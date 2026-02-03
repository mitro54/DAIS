/**
 * @file engine.cpp
 * @brief Core implementation of the DAIS runtime engine.
 * * This file contains the main logic for:
 * 1. Managing the Pseudoterminal (PTY) session.
 * 2. Bi-directional I/O forwarding (User <-> Shell).
 * 3. Embedding and managing the Python interpreter for plugins.
 * 4. Intercepting specific shell commands (like 'ls') to inject custom behavior.
 * 5. Synchronizing state (CWD) between the child shell process and this wrapper.
 */

#include "core/engine.hpp"
#include "core/command_handlers.hpp"
#include "core/help_text.hpp"
#include <cstdio>
#include <thread>
#include <chrono>
#include <array>
#include <string>
#include <iostream> // Needed for std::cout, std::cerr
#include <fstream>  // Needed for std::ofstream, std::ifstream
#include <limits>   // Needed for std::numeric_limits
#include <poll.h>
#include <csignal>
#include <sys/wait.h>
#include <filesystem>
#include <atomic>
#include <mutex>
#include <cerrno>      // errno
#include <sys/ioctl.h> // TIOCGWINSZ
#include <unistd.h>    // STDOUT_FILENO
#include <format>

// --- OS Specific Includes for CWD Sync ---
// We need low-level OS headers to inspect the child process's state directly.
#if defined(__APPLE__)
#include <libproc.h>
#include <sys/proc_info.h>
#endif
// -----------------------------------------

// ==================================================================================
// EMBEDDED MODULE DEFINITION
// ==================================================================================
/**
 * @brief Defines the 'dais' Python module available to scripts.
 * Allows Python extensions to communicate back to the C++ core.
 */
PYBIND11_EMBEDDED_MODULE(dais, m) {
    // Expose a print function so Python can write formatted logs to the DAIS shell
    m.def("log", [](std::string msg) {
        // Uses the dynamic Success color from the Theme
        std::cout << "\r\n[" 
                  << dais::core::handlers::Theme::SUCCESS << "-" 
                  << dais::core::handlers::Theme::RESET << "] " 
                  << msg << "\r\n" << std::flush;
    });
}

namespace dais::core {

    constexpr size_t BUFFER_SIZE = 4096;

    // Helper: Base64 Encoder for binary transfer
    static std::string base64_encode(const unsigned char* data, size_t len) {
        static const char* p = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(4 * ((len + 2) / 3));
        
        for (size_t i = 0; i < len; i += 3) {
            unsigned int v = data[i] << 16;
            if (i + 1 < len) v |= data[i + 1] << 8;
            if (i + 2 < len) v |= data[i + 2];

            out += p[(v >> 18) & 0x3F];
            out += p[(v >> 12) & 0x3F];
            out += (i + 1 < len) ? p[(v >> 6) & 0x3F] : '=';
            out += (i + 2 < len) ? p[v & 0x3F] : '=';
        }
        return out;
    }

    Engine::Engine() {
        // --- SHELL DETECTION ---
        // We detect the shell type from the environment to handle specific quirks:
        // - Zsha: Uses RPROMPT and complicated redraws involving carriage returns (\r).
        // - Fish: Similar to Zsh, plus autosuggestions and often aliased 'ls' commands that break parsing.
        // We group these as "complex shells" for shared logic, while tracking Fish specifically for unique overrides.
        const char* shell_env = std::getenv("SHELL");
        if (shell_env) {
            std::string shell_path(shell_env);
            if (shell_path.find("zsh") != std::string::npos) {
                is_complex_shell_ = true;
            } else if (shell_path.find("fish") != std::string::npos) {
                is_complex_shell_ = true;
                is_fish_ = true;
            }
        }
        
        load_history();  // Load ~/.dais_history on startup

        // --- INITIAL TERMINAL SIZE ---
        struct winsize ws;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
            terminal_cols_ = ws.ws_col;
        }
    }
    
    // Ensure we kill the child shell if the engine is destroyed while running
    Engine::~Engine() { if (running_) kill(pty_.get_child_pid(), SIGTERM); }

    // ==================================================================================
    // EXTENSION & CONFIGURATION MANAGEMENT
    // ==================================================================================

    /**
     * @brief Scans a directory for Python scripts and loads them as modules.
     * Updates sys.path so imports work correctly within the plugins.
     * @param path Absolute or relative path to the scripts folder.
     */
    void Engine::load_extensions(const std::string& path) {
        namespace fs = std::filesystem;
        fs::path p(path);
        
        // Validation
        if (path.empty() || !fs::exists(p) || !fs::is_directory(p)) {
            std::cerr << "[" << handlers::Theme::WARNING << "-" << handlers::Theme::RESET 
                      << "] Warning: Plugin path '" << path << "' invalid. Skipping Python extensions.\n";
            return;
        }

        try {
            // Add the plugin path to Python's sys.path
            py::module_ sys = py::module_::import("sys");
            sys.attr("path").attr("append")(path);

            // Iterate and import .py files
            for (const auto& entry : fs::directory_iterator(path)) {
                if (entry.path().extension() == ".py") {
                    std::string module_name = entry.path().stem().string();
                    
                    // Skip internal python files
                    if (module_name == "__init__" || module_name == "config") continue;
                    
                    // Import and store the module
                    py::module_ plugin = py::module_::import(module_name.c_str());
                    loaded_plugins_.push_back(plugin);
                    
                    std::cout << "[" << handlers::Theme::NOTICE << "-" << handlers::Theme::RESET 
                              << "] Loaded .py extension: " << module_name << "\n";
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[" << handlers::Theme::ERROR << "-" << handlers::Theme::RESET 
                      << "] Error, failed to load extensions: " << e.what() << "\n";
        }
    }

    /**
     * @brief Loads the 'config.py' file to set runtime flags.
     * @param path Directory containing the config file.
     */
    void Engine::load_configuration(const std::string& path) {
        namespace fs = std::filesystem;
        fs::path p(path);
        try {
            py::module_ sys = py::module_::import("sys");
            sys.attr("path").attr("append")(fs::absolute(p).string());
            py::module_ conf_module = py::module_::import("config");

            // --- SETTINGS LOADING ---

            // 1. SHOW_LOGO
            if (py::hasattr(conf_module, "SHOW_LOGO")) {
                config_.show_logo = conf_module.attr("SHOW_LOGO").cast<bool>();
            }

            // 2. SHELL_PROMPTS
            if (py::hasattr(conf_module, "SHELL_PROMPTS")) {
                py::list prompts = conf_module.attr("SHELL_PROMPTS").cast<py::list>();
                if (!prompts.empty()) {
                    config_.shell_prompts.clear();
                    for (auto item : prompts) {
                        config_.shell_prompts.push_back(item.cast<std::string>());
                    }
                }
            }

            if (py::hasattr(conf_module, "LS_PADDING")) {
                config_.ls_padding = conf_module.attr("LS_PADDING").cast<int>();
            }

            // 3. THEME LOADING
            if (py::hasattr(conf_module, "THEME")) {
                py::dict theme = conf_module.attr("THEME").cast<py::dict>();
                
                // Helper lambda to safely get string from dict
                auto load_color = [&](const char* key, std::string& target) {
                    if (theme.contains(key)) {
                        target = theme[key].cast<std::string>();
                    }
                };

                load_color("RESET", handlers::Theme::RESET);
                load_color("STRUCTURE", handlers::Theme::STRUCTURE);
                load_color("UNIT", handlers::Theme::UNIT);
                load_color("VALUE", handlers::Theme::VALUE);
                load_color("ESTIMATE", handlers::Theme::ESTIMATE);
                load_color("TEXT", handlers::Theme::TEXT);
                load_color("SYMLINK", handlers::Theme::SYMLINK);
                load_color("LOGO", handlers::Theme::LOGO);
                load_color("SUCCESS", handlers::Theme::SUCCESS);
                load_color("WARNING", handlers::Theme::WARNING);
                load_color("ERROR", handlers::Theme::ERROR);
                load_color("NOTICE", handlers::Theme::NOTICE);
            }

            // 4. LS FORMAT TEMPLATES
            if (py::hasattr(conf_module, "LS_FORMATS")) {
                py::dict formats = conf_module.attr("LS_FORMATS").cast<py::dict>();
                auto load_fmt = [&](const char* key, std::string& target) {
                    if (formats.contains(key)) {
                        target = formats[key].cast<std::string>();
                    }
                };
                load_fmt("directory", config_.ls_fmt_directory);
                load_fmt("text_file", config_.ls_fmt_text_file);
                load_fmt("data_file", config_.ls_fmt_data_file);
                load_fmt("binary_file", config_.ls_fmt_binary_file);
                load_fmt("error", config_.ls_fmt_error);
            }

            // 5. FILE EXTENSION LISTS
            if (py::hasattr(conf_module, "TEXT_EXTENSIONS")) {
                py::list ext_list = conf_module.attr("TEXT_EXTENSIONS").cast<py::list>();
                dais::utils::FileExtensions::text.clear();
                for (const auto& item : ext_list) {
                    dais::utils::FileExtensions::text.push_back(item.cast<std::string>());
                }
            }
            if (py::hasattr(conf_module, "DATA_EXTENSIONS")) {
                py::list ext_list = conf_module.attr("DATA_EXTENSIONS").cast<py::list>();
                dais::utils::FileExtensions::data.clear();
                for (const auto& item : ext_list) {
                    dais::utils::FileExtensions::data.push_back(item.cast<std::string>());
                }
            }

            // 6. LS SORT OPTIONS
            if (py::hasattr(conf_module, "LS_SORT")) {
                py::dict sort = conf_module.attr("LS_SORT").cast<py::dict>();
                if (sort.contains("by")) config_.ls_sort_by = sort["by"].cast<std::string>();
                if (sort.contains("order")) config_.ls_sort_order = sort["order"].cast<std::string>();
                if (sort.contains("dirs_first")) config_.ls_dirs_first = sort["dirs_first"].cast<bool>();
                if (sort.contains("flow")) config_.ls_flow = sort["flow"].cast<std::string>();
            }

            // 7. DB CONFIGURATION
            if (py::hasattr(conf_module, "DB_TYPE")) {
                config_.db_type = conf_module.attr("DB_TYPE").cast<std::string>();
            }
            if (py::hasattr(conf_module, "DB_SOURCE")) {
                config_.db_source = conf_module.attr("DB_SOURCE").cast<std::string>();
            }

            // Debug Print
            std::cout << "[" << handlers::Theme::NOTICE << "-" << handlers::Theme::RESET 
                      << "] Config loaded successfully.\n";

        } catch (const std::exception& e) {
            // Safe fallback if config is missing
            std::cout << "[" << handlers::Theme::ERROR << "-" << handlers::Theme::RESET 
                      << "] No config.py found (or error reading it). Using defaults.\n";
        }
    }

    /**
     * @brief Triggers a named function in all loaded Python plugins.
     * @param hook_name The function name to call (e.g., "on_command").
     * @param data String data to pass to the hook.
     */
    void Engine::trigger_python_hook(const std::string& hook_name, const std::string& data) {
        for (auto& plugin : loaded_plugins_) {
            if (py::hasattr(plugin, hook_name.c_str())) {
                try {
                    plugin.attr(hook_name.c_str())(data);
                } catch (const std::exception& e) {
                    std::cerr << "Error in plugin: " << e.what() << "\n";
                }
            }
        }
    }

    // ==================================================================================
    // STATE SYNCHRONIZATION
    // ==================================================================================

    /**
     * @brief Synchronizes the Engine's tracked CWD with the actual Shell CWD.
     * * [CRITICAL ARCHITECTURE NOTE]
     * Attempting to track 'cd' commands by parsing user input (stdin) is fragile because:
     * 1. Users use aliases (e.g., '..', 'gohome').
     * 2. Users use TAB completion, which the wrapper doesn't see fully resolved.
     * * Instead, we use OS-specific system calls to inspect the child process directly.
     * This provides almost 100% accuracy regardless of how the directory was changed.
     */
    void Engine::sync_child_cwd() {
        pid_t pid = pty_.get_child_pid();
        if (pid <= 0) return;

#if defined(__APPLE__)
        // macOS: Use libproc to query the vnode path info of the process
        struct proc_vnodepathinfo vpi;
        if (proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vpi, sizeof(vpi)) > 0) {
            shell_cwd_ = std::filesystem::path(vpi.pvi_cdir.vip_path);
        }
#elif defined(__linux__)
        // Linux: Read the magic symlink at /proc/{pid}/cwd
        try {
            auto link_path = std::format("/proc/{}/cwd", pid);
            if (std::filesystem::exists(link_path)) {
                shell_cwd_ = std::filesystem::read_symlink(link_path);
            }
        } catch (...) {
            // Permission denied or process gone; ignore.
        }
#endif
    }

    /**
     * @brief Resolves a partial path to a complete path using aggressive fuzzy matching.
     * 
     * Handles the case where tab completion created a concatenated string like "/mndwin"
     * from "/mnt" + "d" + "wincplusplus". Uses recursive backtracking to try all possible
     * split points and find valid directory matches.
     * 
     * Example: "/mndwin" -> tries "/m" in /, then "ndwin" in /mnt -> finds /mnt/d/wincplusplus
     * 
     * @param partial The incomplete/concatenated path from the accumulator
     * @param cwd Current working directory for relative path resolution
     * @return Resolved path if successful, empty path if resolution failed
     */
    std::filesystem::path Engine::resolve_partial_path(
        const std::string& partial, 
        const std::filesystem::path& cwd
    ) {
        namespace fs = std::filesystem;
        
        if (partial.empty()) return cwd;
        
        // Helper lambda for case-insensitive prefix matching
        auto starts_with_ci = [](const std::string& str, const std::string& prefix) -> bool {
            if (str.size() < prefix.size()) return false;
            for (size_t i = 0; i < prefix.size(); ++i) {
                if (std::tolower(str[i]) != std::tolower(prefix[i])) return false;
            }
            return true;
        };
        
        // Recursive helper to find path from current directory and remaining string
        std::function<fs::path(const fs::path&, const std::string&, int)> find_path;
        find_path = [&](const fs::path& current, const std::string& remaining, int depth) -> fs::path {
            // Base case: nothing left to match
            if (remaining.empty()) {
                return current;
            }
            
            // Depth limit to prevent infinite recursion
            if (depth > 50) return {};
            
            // Must be at a valid directory
            if (!fs::exists(current) || !fs::is_directory(current)) {
                return {};
            }
            
            // Collect directory entries
            std::vector<std::pair<std::string, fs::path>> entries;
            try {
                for (const auto& entry : fs::directory_iterator(current)) {
                    entries.push_back({entry.path().filename().string(), entry.path()});
                }
            } catch (...) {
                return {}; // Permission error
            }
            
            // Try matching increasingly long prefixes of 'remaining' against entries
            // Start with longer prefixes (more specific matches first)
            for (size_t len = std::min(remaining.size(), static_cast<size_t>(256)); len >= 1; --len) {
                std::string prefix = remaining.substr(0, len);
                
                for (const auto& [name, path] : entries) {
                    if (starts_with_ci(name, prefix)) {
                        // Found a potential match - try to resolve the rest
                        std::string rest = remaining.substr(len);
                        
                        // If entry is a directory, recurse into it
                        if (fs::is_directory(path)) {
                            auto result = find_path(path, rest, depth + 1);
                            if (!result.empty()) {
                                return result;
                            }
                        } else if (rest.empty()) {
                            // It's a file and we've consumed all input
                            return path;
                        }
                    }
                }
            }
            
            return {}; // No match found
        };
        
        // Determine starting point and clean the path string
        std::string path_str = partial;
        fs::path start_dir;
        
        if (!path_str.empty() && (path_str[0] == '/' || path_str[0] == '\\')) {
            // Absolute path - start from root
            start_dir = "/";
            path_str = path_str.substr(1); // Remove leading slash
        } else {
            // Relative path - start from CWD
            start_dir = cwd;
        }
        
        // Remove trailing slashes
        while (!path_str.empty() && (path_str.back() == '/' || path_str.back() == '\\')) {
            path_str.pop_back();
        }
        
        return find_path(start_dir, path_str, 0);
    }

    // ==================================================================================
    // MAIN LOOP
    // ==================================================================================

    void Engine::run() {
        if (!pty_.start()) return;

        // We must sync the window size AFTER the PTY has started (so master_fd is valid),
        // but BEFORE we start forwarding output, otherwise text wraps weirdly.
        struct winsize w;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1) {
            pty_.resize(w.ws_row, w.ws_col, config_.show_logo);
        }

        running_ = true;
        
        // Rebranded Startup Message with Configured Theme
        std::cout << "\r[" 
                  << dais::core::handlers::Theme::SUCCESS << "-" 
                  << dais::core::handlers::Theme::RESET << "]" 
                  << " DAIS has been started. Type ':q' or ':exit' to exit.\r\n" << std::flush;

        // Enable Bracketed Paste Mode
        std::cout << "\x1b[?2004h" << std::flush;

        // Spawn the output reader thread (Child -> Screen)
        std::thread output_thread(&Engine::forward_shell_output, this);

        // Run the input processing loop (Keyboard -> Child) in the main thread
        process_user_input();

        // Stop PTY first to unblock threads and signal shell EOF/SIGHUP
        pty_.stop();

        if (output_thread.joinable()) output_thread.join();
        
        // Disable Bracketed Paste Mode
        std::cout << "\x1b[?2004l" << std::flush;
        
        // Wait for child process to truly exit before finishing
        waitpid(pty_.get_child_pid(), nullptr, 0);
        
        std::cout << "\r[" 
                  << dais::core::handlers::Theme::ERROR << "-" 
                  << dais::core::handlers::Theme::RESET << "]" 
                  << " Session ended.\n" << std::flush;
    }

    /**
     * @brief Reads output from the Shell (PTY Master) and writes to Stdout.
     * Handles "Output Interception" where we buffer output (e.g., for 'ls') 
     * to modify it before displaying.
     */
    void Engine::forward_shell_output() {
        std::array<char, BUFFER_SIZE> buffer;
        struct pollfd pfd{};
        pfd.fd = pty_.get_master_fd();
        pfd.events = POLLIN;

        while (running_) {
            int ret = poll(&pfd, 1, 100);

            if (ret < 0) {
                if (errno == EINTR) continue; // Resize signal received, just continue
                break; // Real error, exit loop
            }

            // Poll timeout - no data available, continue polling
            if (ret == 0) continue;

            if (pfd.revents & (POLLERR | POLLHUP)) break;

            if (pfd.revents & POLLIN) {
                ssize_t bytes_read = read(pty_.get_master_fd(), buffer.data(), buffer.size());
                if (bytes_read <= 0) break;

                // --- VISUALIZATION SAFETY ---
                // If the main thread is running a silent command (capture_mode_),
                // we consume the output into a buffer and DO NOT print it.
                if (capture_mode_) {
                    std::lock_guard<std::mutex> lock(capture_mutex_);
                    capture_buffer_.append(buffer.data(), bytes_read);
                    capture_cv_.notify_one();
                    continue; // Skip printing
                }

                // --- PASS-THROUGH MODE ---
                // Forward shell output to terminal with optional logo injection.
                // Uses class members prompt_buffer_ and pass_through_esc_state_ for state.
                
                std::string buffer_str(buffer.data(), bytes_read);

                // --- ALT SCREEN DETECTION (VIM FIX) ---
                // Detect ANSI sequences for entering/exiting alternate screen mode.
                // This prevents DAIS from intercepting keys inside vim/less/htop.
                if (buffer_str.find("\x1b[?1049h") != std::string::npos || buffer_str.find("\x1b[?47h") != std::string::npos) {
                    in_alt_screen_ = true;
                }
                if (buffer_str.find("\x1b[?1049l") != std::string::npos || buffer_str.find("\x1b[?47l") != std::string::npos) {
                    in_alt_screen_ = false;
                }

                // --- LOOK-AHEAD PROMPT DETECTION ---
                // Check if this buffer contains a prompt BEFORE processing characters.
                for (const auto& prompt : config_.shell_prompts) {
                    if (buffer_str.size() >= prompt.size() &&
                        buffer_str.find(prompt) != std::string::npos) {
                        
                        // Logic update: in SSH, shell_state_ can be IDLE if we see a prompt
                        // even if pty_.is_shell_idle() is false. BUT NOT IN ALT SCREEN (Vim).
                        if ((pty_.is_shell_idle() || is_remote_session_) && !in_alt_screen_) {
                            shell_state_ = ShellState::IDLE;
                            
                            // If we were waiting for login to finish, we are now ready!
                            if (is_remote_session_ && pending_remote_deployment_) {
                                ready_to_deploy_ = true;
                                // CLEAN START FIX: Suppress this prompt output so we don't spam.
                                // We break here, effectively swallowing the prompt buffer.
                                // The "Agent Verified" message will print its own newlines,
                                // and the NEXT prompt (after verification) will show up cleanly.
                                goto skip_output_processing;
                            }
                        }
                        break;
                    }
                }
                
                {
                    std::lock_guard<std::recursive_mutex> terminal_lock(terminal_mutex_);
                    for (ssize_t i = 0; i < bytes_read; ++i) {
                        char c = buffer[i];
                        
                        // Shell-Specific Logo Injection Strategy:
                        if (is_complex_shell_ && !is_fish_) {
                            // Zsh: Delayed logo injection with ANSI escape sequence tracking.
                            // State machine: 0=text, 1=ESC, 2=CSI, 3=OSC, 4=Charset
                            if (pass_through_esc_state_ == 1) {
                                if (c == '[') pass_through_esc_state_ = 2;
                                else if (c == ']') pass_through_esc_state_ = 3;
                                else if (c == '(' || c == ')') pass_through_esc_state_ = 4;
                                else pass_through_esc_state_ = 0;
                            } else if (pass_through_esc_state_ == 2) {
                                if (std::isalpha(static_cast<unsigned char>(c))) pass_through_esc_state_ = 0;
                            } else if (pass_through_esc_state_ == 3) {
                                if (c == kBell) pass_through_esc_state_ = 0;
                            } else if (pass_through_esc_state_ == 4) {
                                pass_through_esc_state_ = 0;
                            } else if (c == kEsc) {
                                pass_through_esc_state_ = 1;
                            } else if (at_line_start_ && config_.show_logo && shell_state_ == ShellState::IDLE && 
                                       (pty_.is_shell_idle() || is_remote_session_) && !in_alt_screen_) {
                                // Inject logo at line start when shell is idle (and NOT in vim)
                                if (c >= 33 && c < 127) {
                                    std::string logo_str = handlers::Theme::RESET + "[" + handlers::Theme::LOGO + "-" + handlers::Theme::RESET + "] ";
                                    write(STDOUT_FILENO, logo_str.c_str(), logo_str.size());
                                    at_line_start_ = false;
                                }
                            }
                        } else if (!is_complex_shell_) {
                            // Simple shells: inject immediately
                            if (at_line_start_) {
                                if (c != '\n' && c != '\r' && config_.show_logo && shell_state_ == ShellState::IDLE && 
                                    (pty_.is_shell_idle() || is_remote_session_) && !in_alt_screen_) {
                                    std::string logo_str = handlers::Theme::RESET + "[" + handlers::Theme::LOGO + "-" + handlers::Theme::RESET + "] ";
                                    write(STDOUT_FILENO, logo_str.c_str(), logo_str.size());
                                    at_line_start_ = false;
                                }
                            }
                        }
                        
                        write(STDOUT_FILENO, &c, 1);
                        
                        if (c == '\n') {
                            at_line_start_ = true;
                            in_more_pager_ = false;  // Pager exits on newline (user scrolled)
                            std::lock_guard<std::mutex> lock(prompt_mutex_);
                            prompt_buffer_.clear();
                        } else if (c == '\r') {
                            // For complex shells, \r means "back to line start"
                            // For simple shells, \r often means new prompt line
                            if (!is_complex_shell_) {
                                at_line_start_ = true;
                            }
                        }
                        
                        // ALWAYS capture to prompt_buffer_ (printable AND control chars)
                        if (true) { 
                            std::lock_guard<std::mutex> lock(prompt_mutex_);
                            prompt_buffer_ += c;
                            if (prompt_buffer_.size() > 1024) {
                                prompt_buffer_ = prompt_buffer_.substr(prompt_buffer_.size() - 1024);
                            }
                            
                            if (prompt_buffer_.find("--More--") != std::string::npos) {
                                in_more_pager_ = true;
                            }
                        }
                    }
                }
                
                // --- PROMPT DETECTION: Set state to IDLE ---
                // Check if output ends with a known shell prompt
                {
                    std::lock_guard<std::mutex> lock(prompt_mutex_);
                    for (const auto& prompt : config_.shell_prompts) {
                        if (prompt_buffer_.size() >= prompt.size() &&
                            prompt_buffer_.substr(prompt_buffer_.size() - prompt.size()) == prompt) {
                            
                             // Logic update: in SSH, shell_state_ can be IDLE if we see a prompt
                            // even if pty_.is_shell_idle() is false. BUT NOT IN ALT SCREEN (Vim).
                            if ((pty_.is_shell_idle() || is_remote_session_) && !in_alt_screen_) {
                                shell_state_ = ShellState::IDLE;
                            }
                            break;
                        }
                    }
                }
                
                skip_output_processing:;
            }
        }
    }

    /**
     * @brief Reads User Input (Stdin) and forwards to Shell (PTY Master).
     * Analyzes keystrokes to detect internal commands (:q) or commands 
     * requiring modification (ls).
     */
    void Engine::process_user_input() {
        std::array<char, BUFFER_SIZE> buffer;
        struct pollfd pfd{};
        pfd.fd = STDIN_FILENO;
        pfd.events = POLLIN;

        std::string& cmd_accumulator = input_accumulator_;

        while (running_) {
            int ret = poll(&pfd, 1, 100);

            if (ret < 0) {
                if (errno == EINTR) continue; // Signal interrupted, keep going
                break;
            }

            if (ret == 0) {
                // AUTO-DEPLOYMENT TRIGGER:
                // If the output thread found a prompt while we have a pending deployment, execute it here.
                if (ready_to_deploy_) {
                     ready_to_deploy_ = false;
                     pending_remote_deployment_ = false;
                     deploy_remote_agent();
                     deploy_remote_db_handler();
                }
                continue;
            }

            if (pfd.revents & POLLIN) {
                ssize_t n = read(STDIN_FILENO, buffer.data(), buffer.size());
                if (n <= 0) break;

                std::string data_to_write;
                data_to_write.reserve(n + 8);

                // Process char-by-char to build command string
                for (ssize_t i = 0; i < n; ++i) {
                    char c = buffer[i];

                    // --- BRACKETED PASTE DETECTION ---
                    // \x1b[200~ (Start) and \x1b[201~ (End)
                    if (c == '\x1b' && i + 5 < n && buffer[i+1] == '[' && buffer[i+2] == '2' && buffer[i+3] == '0') {
                        if (buffer[i+4] == '0' && buffer[i+5] == '~') {
                            bracketed_paste_active_ = true;
                            i += 5;
                            continue;
                        } else if (buffer[i+4] == '1' && buffer[i+5] == '~') {
                            i += 5;
                            process_paste_block();
                            continue;
                        }
                    }

                    // --- UNIVERSAL PASTE BUFFERING ---
                    if (bracketed_paste_active_) {
                        paste_accumulator_ += c;
                        continue; // Do NOT forward or process while pasting
                    }

                    // --- STATEFUL OSC SKIPPING ---
                    // If we are in the middle of skipping an OSC sequence (split across reads),
                    // swallow characters until we find the terminator.
                    if (skipping_osc_) {
                        if (c == '\x07') {
                            skipping_osc_ = false;
                        } else if (c == '\x1b' && i + 1 < n && buffer[i + 1] == '\\') {
                             skipping_osc_ = false;
                             i++; // Skip backslash
                        }
                        continue; // Swallow this character
                    }

                    // --- VISUAL MODE ENTRY DETECTION ---
                    bool starts_with_colon = !cmd_accumulator.empty() && cmd_accumulator[0] == ':';
                    bool visual_mode = !in_alt_screen_ && (
                                       (pty_.is_shell_idle() && starts_with_colon) || 
                                       (!pty_.is_shell_idle() && is_remote_session_ && starts_with_colon)
                                       );
                    if (visual_mode) {
                        ensure_visual_mode_init();
                    }

                    // --- ESCAPE SEQUENCE HANDLING ---
                    // Arrow keys navigate DAIS history when shell is IDLE (at prompt).
                    // Uses prompt detection state + debounce to ensure safety.
                    // Falls through to shell if check fails.
                    if (c == '\x1b') {
                        // Check for arrow key interception with debounce
                        if (i + 2 < n && (buffer[i + 1] == '[' || buffer[i + 1] == 'O')) {
                            char arrow = buffer[i + 2];
                            // PAGER TRANSLATION FIX (HIGHEST PRIORITY):
                            // Check if we're in the "more" pager FIRST before any other arrow handling.
                            // Uses in_more_pager_ flag which is set synchronously in forward_shell_output.
                            if ((arrow == 'A' || arrow == 'B') && in_more_pager_) {
                                if (arrow == 'B') { // Down Arrow -> Enter (Scroll)
                                    write(pty_.get_master_fd(), "\n", 1);
                                } 
                                // If Up Arrow (A): Do nothing (Swallow to prevent artifacts)
                                
                                i += 2; // Skip sequence
                                continue; // Don't forward original escape sequence
                            }
                            
                            // DEBOUNCE: Wait 200ms after last command to avoid race with app startup
                            auto now = std::chrono::steady_clock::now();
                            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                now - last_command_time_).count();
                            
                            // Intercept arrows for DAIS history navigation
                            // CASE 1: Local Session (Standard) - always intercept if idle
                            // CASE 2: Remote Session (Internal Command) - stash/restore :db or :commands
                            bool internal_mode = cmd_accumulator.starts_with(":");
                            
                            if ((arrow == 'A' || arrow == 'B') && 
                                (pty_.is_shell_idle() || (is_remote_session_ && internal_mode)) && 
                                elapsed > 200) {
                                // Safe to intercept for DAIS history
                                int direction = (arrow == 'A') ? -1 : 1;
                                navigate_history(direction, cmd_accumulator);
                                i += 2;  // Skip '['/O' and arrow letter
                                continue;  // Don't forward to shell
                            }
                            
                            // CASE 3: Remote Session (Normal Command) - Pass through but CLEAR CACHE
                            // Validate shell history sync by clearing local accumulator so we adopt fresh
                            if ((arrow == 'A' || arrow == 'B') && is_remote_session_ && !internal_mode) {
                                cmd_accumulator.clear();
                                cursor_pos_ = 0;
                                was_visual_mode_ = false;
                                // Fallthrough to forward the key to shell naturally
                            }
                            
                            // --- LEFT/RIGHT ARROW SYNC ---
                            // If user presses Left (D) or Right (C), handle based on mode.
                            if (arrow == 'C' || arrow == 'D') {
                                bool starts_with_colon = !cmd_accumulator.empty() && cmd_accumulator[0] == ':';
                                bool visual_mode = !in_alt_screen_ && (
                                                   (pty_.is_shell_idle() && starts_with_colon) || 
                                                   (!pty_.is_shell_idle() && is_remote_session_ && starts_with_colon)
                                                   );

                                if (visual_mode) {
                                    int old_cursor = cursor_pos_;
                                    if (arrow == 'D') { // Left
                                        if (cursor_pos_ > 0) cursor_pos_--;
                                    } else { // Right
                                        if (cursor_pos_ < cmd_accumulator.size()) cursor_pos_++;
                                    }
                                    visual_move_cursor(old_cursor, cursor_pos_);
                                    i += 2; continue;
                                }

                                // Sync history content to shell before cursor movement
                                sync_history_to_shell(cmd_accumulator);
                            }
                        }
                        
                        // Not intercepted - forward escape sequence to shell
                        data_to_write += c;
                        
                        // Handle CSI sequences (ESC [ ...)
                        if (i + 1 < n && buffer[i + 1] == '[') {
                            data_to_write += buffer[++i]; // '['
                            while (i + 1 < n && !std::isalpha(static_cast<unsigned char>(buffer[i + 1]))) {
                                data_to_write += buffer[++i];
                            }
                            if (i + 1 < n) {
                                data_to_write += buffer[++i]; // terminating letter
                            }
                        }
                        // Handle SS3 sequences (ESC O ...)
                        else if (i + 1 < n && buffer[i + 1] == 'O') {
                            data_to_write += buffer[++i]; // 'O'
                            if (i + 1 < n) {
                                data_to_write += buffer[++i]; // terminating letter
                            }
                        }
                        // Handle OSC sequences (ESC ] ...) - skip entirely
                        else if (i + 1 < n && buffer[i + 1] == ']') {
                            data_to_write.pop_back();  // Remove the ESC we added
                            i++;  // Skip ']'
                            skipping_osc_ = true; // Assume skipping until we find terminator
                            
                            while (i + 1 < n) {
                                if (buffer[i + 1] == '\x07') { 
                                    skipping_osc_ = false; 
                                    i++; 
                                    break; 
                                }
                                if (buffer[i + 1] == '\x1b' && i + 2 < n && buffer[i + 2] == '\\') {
                                    skipping_osc_ = false;
                                    i += 2; 
                                    break;
                                }
                                i++;
                            }
                            // If loop finishes and skipping_osc_ is still true, 
                            // it means we ran out of buffer before finding terminator.
                            // We will continue skipping in the next read() cycle.
                        }
                        continue; // Don't add to accumulator
                    }

                    // --- TAB COMPLETION HANDLING ---
                    // When Tab is pressed, shell does completion which we can't track.
                    // Mark that accumulator is now unreliable for this command.
                    // Only set flag when shell is IDLE (we're actually tracking the command) OR in remote session.
                    if (c == '\t') {
                        if (pty_.is_shell_idle()) {
                            // If user navigated history, shell doesn't have the text yet.
                            // Sync shell with accumulator before sending Tab.
                            if (history_navigated_ && !cmd_accumulator.empty()) {
                                // Erase the visual display first
                                for (size_t i = 0; i < cmd_accumulator.size(); ++i) {
                                    std::cout << "\b \b";
                                }
                                std::cout << std::flush;
                                
                                // Sync: clear shell's empty line and send command text
                                const char kill_line = '\x15';  // Ctrl+U
                                write(pty_.get_master_fd(), &kill_line, 1);
                                write(pty_.get_master_fd(), cmd_accumulator.c_str(), cmd_accumulator.size());
                                history_navigated_ = false;
                            }
                            tab_used_ = true;
                        } 
                        else if (is_remote_session_) {
                            // In remote sessions, the local pty is technically 'running' ssh,
                            // but we still need to track that the user is tabbing.
                            tab_used_ = true;
                        }
                        
                        data_to_write += c;
                        continue;
                    }

                     // --- CTRL+C HANDLING ---
                    // Clears the current line in the shell, so reset our accumulator and flags too.
                    if (c == '\x03') {
                        if (visual_mode) {
                            std::lock_guard<std::recursive_mutex> terminal_lock(terminal_mutex_);
                            visual_move_cursor(cursor_pos_, 0);
                            write(STDOUT_FILENO, "\x1b[J", 3);
                        }
                        cmd_accumulator.clear();
                        cursor_pos_ = 0;
                        was_visual_mode_ = false;
                        tab_used_ = false;
                        data_to_write += c;
                        continue;
                    }

                    // --- SMART INTERCEPTION ---
                    // Only process DAIS commands when at shell prompt (IDLE state)
                    
                    // Check for Enter key (\r or \n) indicating command submission
                    if (c == '\r' || c == '\n') {
                        if (visual_mode) {
                            std::lock_guard<std::recursive_mutex> terminal_lock(terminal_mutex_);
                            visual_move_cursor(cursor_pos_, 0);
                            write(STDOUT_FILENO, "\x1b[J", 3);
                        }
                        cursor_pos_ = 0;
                        was_visual_mode_ = false;
                        
                        // ═══════════════════════════════════════════════════════════════════════════
                        /// @brief REMOTE COMMAND INTERCEPTION
                        /// 
                        /// Remote sessions require special handling because:
                        /// 1. Commands may come from shell history (Up-Arrow), not keyboard input
                        /// 2. The shell echoes commands back asynchronously (race condition)
                        /// 3. Tab completion modifies cmd_accumulator unpredictably
                        ///
                        /// We solve this by:
                        /// - Checking remote session state fresh (avoids stale detection)
                        /// - Recovering the visual command from PTY output if local buffer is unreliable
                        /// - Tracking command source to prevent double-echoing
                        // ═══════════════════════════════════════════════════════════════════════════
                        check_remote_session();
                        
                        std::string clean = cmd_accumulator;
                        bool from_shell_echo = false;

                        if (!pty_.is_shell_idle() && is_remote_session_ && !in_alt_screen_) {
                            // Recover command from shell's visual output (handles history navigation)
                            std::string recovered;
                            {
                                std::lock_guard<std::mutex> lock(prompt_mutex_);
                                CursorRecovery recovery = recover_cmd_from_buffer(prompt_buffer_);
                                recovered = recovery.command;
                            }
                            
                            // Fallback: use local input if shell echo hasn't arrived yet (paste race)
                            std::string local_input;
                            {
                                std::lock_guard<std::mutex> lock(input_mutex_);
                                local_input = input_accumulator_;
                                input_accumulator_.clear(); 
                                cursor_pos_ = 0;
                            }

                            // Choose best available command source
                            if (clean.empty() || clean.find('\t') != std::string::npos || tab_used_) {
                                if (!recovered.empty()) {
                                    clean = recovered;
                                    from_shell_echo = true; // Shell already displayed this command
                                } else if (!local_input.empty() && local_input.find(':') != std::string::npos) {
                                    clean = local_input;
                                }
                            }
                        }

                            // Trim leading/trailing whitespace
                            if (clean.find_first_not_of(" \t\r\n") != std::string::npos) {
                                clean.erase(0, clean.find_first_not_of(" \t\r\n"));
                            }
                            if (clean.find_last_not_of(" \t\r\n") != std::string::npos) {
                                clean.erase(clean.find_last_not_of(" \t\r\n") + 1);
                            }

                            bool intercept = false;
                            
                            // GUARD: Do NOT intercept if in alternate screen (vim/less)
                            if (!in_alt_screen_) {
                                if (clean.starts_with(":")) {
                                    execute_internal_command(clean, from_shell_echo);
                                    intercept = true;
                                }
                            // Check for standard ls (intercept and use agent)
                            // Require shell_state_ to be IDLE (we see a prompt) AND remote session to avoid shadowing Native LS
                            else if ((clean == "ls" || clean.starts_with("ls ")) && shell_state_ == ShellState::IDLE && is_remote_session_) {
                                auto ls_args = handlers::parse_ls_args(clean);
                                if (ls_args.supported) {
                                    handle_remote_ls(ls_args, clean);
                                    intercept = true;
                                }
                            }

                            } // End of !in_alt_screen_ guard
                            
                            if (intercept) {
                                cmd_accumulator.clear();
                                cursor_pos_ = 0;
                                {
                                    std::lock_guard<std::mutex> lock(prompt_mutex_);
                                    // Don't clear prompt_buffer_ here, handled naturally by newlines
                                }
                                // NOTE: Don't send extra newline here - the injected command already has one
                                // Sending another causes double prompts
                                continue; // Skip sending the actual Enter key to remote
                            }

                        // Sync history content to shell before Enter execution
                        sync_history_to_shell(cmd_accumulator);
                        history_navigated_ = false;  // Always reset on Enter
                        
                        // --- STATE TRANSITION: IDLE -> RUNNING ---
                        shell_state_ = ShellState::RUNNING;
                        last_command_time_ = std::chrono::steady_clock::now();  // For debounce
                        
                        // --- THREAD SAFETY: LOCK ---
                        {
                            std::lock_guard<std::mutex> lock(state_mutex_);
                            current_command_ = cmd_accumulator; 
                        }
                        // ---------------------------
                        
                        // Only save to history when shell is idle AND tab wasn't used
                        // (tab makes accumulator unreliable)
                        if (pty_.is_shell_idle()) {
                            // Save to DAIS history file (~/.dais_history)
                            if (!cmd_accumulator.empty()) {
                                save_history_entry(cmd_accumulator);
                                history_index_ = command_history_.size();
                                history_stash_.clear();
                            }
                        }
                        
                        // Process DAIS interceptions when shell is idle
                        // Note: ls interception works even with tab (uses path validation)
                        if (pty_.is_shell_idle() && !in_alt_screen_) {
                            // 1. Detect 'ls' command (with or without arguments)
                            if (cmd_accumulator == "ls" || cmd_accumulator.starts_with("ls ")) {
                                // Check for remote session (SSH)
                                check_remote_session();

                                if (is_remote_session_) {
                                    // --- REMOTE LS ---
                                    if (!remote_agent_deployed_) {
                                        deploy_remote_agent();
                                    }
                                    
                                    // Parse arguments roughly (only -a supported for now)
                                    auto ls_args = handlers::parse_ls_args(cmd_accumulator);
                                    
                                    // Construct Remote Command
                                    std::string agent_cmd;
                                    
                                    // agent args: [-a] [path]
                                    if (ls_args.show_hidden) agent_cmd += " -a";
                                    for (const auto& p : ls_args.paths) {
                                        if (!p.empty()) agent_cmd += " " + p;
                                    }
                                    
                                    // Execute the agent (or python fallback if we had it)
                                    // Note: The agent binary is usually placed at ~/.dais/agent 
                                    // But for this MVP we might assume it's in the PATH or /tmp.
                                    // Implementation Detail: deploy_remote_agent() should detect where it put it.
                                    // For now, let's assume valid PATH or alias.
                                    // Actually, let's run a Mock command if mock agent.
                                    // Or try to run the dropped binary.
                                    
                                    // ACTIVE INTERCEPTION LOGIC:
                                    if (remote_agent_deployed_) {
                                        // Execute
                                        // TODO: The path to agent needs to be stored by deploy_remote_agent
                                        // For MVP we assume it's sitting in /tmp/dais_agent
                                        std::string remote_bin = "/tmp/dais_agent_" + remote_arch_;
                                        std::string json_out = execute_remote_command(remote_bin + agent_cmd, 3000);
                                        
                                        if (!json_out.empty() && json_out.starts_with("[")) {
                                            // Render
                                            handlers::LSFormats formats;
                                            formats.directory = config_.ls_fmt_directory;
                                            formats.text_file = config_.ls_fmt_text_file;
                                            formats.data_file = config_.ls_fmt_data_file;
                                            formats.binary_file = config_.ls_fmt_binary_file;
                                            
                                            handlers::LSSortConfig sort_cfg;
                                            sort_cfg.by = config_.ls_sort_by;
                                            sort_cfg.order = config_.ls_sort_order;
                                            sort_cfg.dirs_first = config_.ls_dirs_first;
                                            sort_cfg.flow = config_.ls_flow;
                                            
                                            std::string rendered = handlers::render_remote_ls(json_out, formats, sort_cfg, config_.ls_padding);
                                            
                                            if (!rendered.empty()) {
                                                // Clear line and print grid
                                                const char* clear_and_prompt = "\x15\n"; 
                                                write(pty_.get_master_fd(), clear_and_prompt, 2);
                                                
                                                write(STDOUT_FILENO, "\r\n", 2);
                                                write(STDOUT_FILENO, rendered.c_str(), rendered.size());
                                                
                                                cmd_accumulator.clear();
                                                cursor_pos_ = 0;
                                                continue; // Done!
                                            }
                                        }
                                    }
                                    
                                    // Tier 4: Fallthrough
                                } 
                                else {
                                    // --- LOCAL NATIVE LS (Existing Logic) ---
                                    // NATIVE LS: Use std::filesystem instead of shell
                                    // Benefits: No shell compatibility issues, faster, more reliable
                                    
                                    sync_child_cwd(); // Get actual child shell CWD
                                    
                                    // Parse arguments
                                    auto ls_args = handlers::parse_ls_args(cmd_accumulator);
                                    ls_args.padding = config_.ls_padding; // Apply user config padding
                                    
                                    // When tab was used, resolve partial paths using fuzzy matching
                                    std::string resolved_cmd = cmd_accumulator;
                                    if (tab_used_ && !ls_args.paths.empty() && ls_args.paths[0] != "") {
                                        auto resolved = resolve_partial_path(ls_args.paths[0], shell_cwd_);
                                        if (!resolved.empty() && std::filesystem::exists(resolved)) {
                                            // Success! Update paths for ls
                                            ls_args.paths[0] = resolved.string();
                                            
                                            // Reconstruct command for history
                                            resolved_cmd = "ls";
                                            if (ls_args.show_hidden) resolved_cmd += " -a";
                                            resolved_cmd += " " + resolved.string();
                                            
                                            // Save resolved command to history
                                            save_history_entry(resolved_cmd);
                                            history_index_ = command_history_.size();
                                            history_stash_.clear();
                                        } else {
                                            // Resolution failed - let shell handle it
                                            // (shell has the correct tab-completed path)
                                            ls_args.supported = false;
                                        }
                                    }
                                
                                    if (ls_args.supported) {
                                    // Build format/sort config from current settings
                                    handlers::LSFormats formats;
                                    formats.directory = config_.ls_fmt_directory;
                                    formats.text_file = config_.ls_fmt_text_file;
                                    formats.data_file = config_.ls_fmt_data_file;
                                    formats.binary_file = config_.ls_fmt_binary_file;
                                    
                                    handlers::LSSortConfig sort_cfg;
                                    sort_cfg.by = config_.ls_sort_by;
                                    sort_cfg.order = config_.ls_sort_order;
                                    sort_cfg.dirs_first = config_.ls_dirs_first;
                                    sort_cfg.flow = config_.ls_flow;
                                    
                                    // Execute native ls
                                    std::string output = handlers::native_ls(
                                        ls_args, shell_cwd_, formats, sort_cfg, thread_pool_
                                    );
                                    
                                    // Write output directly to terminal
                                    write(STDOUT_FILENO, "\r\n", 2);
                                    if (!output.empty()) {
                                        write(STDOUT_FILENO, output.c_str(), output.size());
                                    }
                                    
                                    // Cancel the shell's pending input and trigger new prompt
                                    // The user typed "ls" which was forwarded to shell as they typed.
                                    // Send Ctrl+U (clear line) to cancel it. 
                                    // We do NOT send newline here to avoid double-prompting, as Ctrl+U typically repaints prompt.
                                    char clear_and_prompt[] = { kCtrlU, 0 }; 
                                    write(pty_.get_master_fd(), clear_and_prompt, 1);
                                    
                                    // Clear accumulator and skip writing command to PTY
                                    cmd_accumulator.clear();
                                    cursor_pos_ = 0;
                                    tab_used_ = false;
                                    at_line_start_ = false; // Prompt will handle this
                            }
                        }
                    }

                            // 2. Internal Exit Commands, LS Config, Help, DB, Agent Status
                            // These are handled by the main interception block (Enter Key) now.
                            // We only keep handlers here that are NOT in the main block.

                        }

                        // --- THROTTLED SESSION CHECK ---
                        if (!pty_.is_shell_idle()) {
                            auto now = std::chrono::steady_clock::now();
                            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_session_check_).count() > 500) {
                                check_remote_session();
                                last_session_check_ = now;
                            }
                        }


                        // COMMANDS ALWAYS INTERCEPTED (Typed or History)
                        // Emergency Exit for Remote Sessions
                        if (!pty_.is_shell_idle() && is_remote_session_ && !in_alt_screen_) {
                             if (cmd_accumulator == ":q" || cmd_accumulator == ":exit") {
                                // "Graceful" kill of the whole DAIS session
                                running_ = false;
                                kill(pty_.get_child_pid(), SIGHUP); 
                                return;
                            }
                        }

                        trigger_python_hook("on_command", cmd_accumulator);
                        cmd_accumulator.clear();
                        cursor_pos_ = 0;
                        was_visual_mode_ = false;
                        tab_used_ = false;  // Reset for next command
                        data_to_write += c;
                    }
                    // Handle Backspace
                    else if (c == 127 || c == '\b') {
                        // ADOPTION: If cmd_accumulator is empty, we might be editing a command 
                        // pulled from the shell's native history (Up-Arrow). 
                        // We try to recover it so we can keep edits within DAIS.
                        if (cmd_accumulator.empty()) {
                            CursorRecovery recovery;
                            {
                                std::lock_guard<std::mutex> lock(prompt_mutex_);
                                recovery = recover_cmd_from_buffer(prompt_buffer_);
                            }
                            if (recovery.command.starts_with(":")) {
                                cmd_accumulator = recovery.command;
                                cursor_pos_ = recovery.cursor_idx;
                                ensure_visual_mode_init(cursor_pos_);

                                if (is_remote_session_) {
                                    // Rewind to start of command (handles wrapping)
                                    visual_move_cursor(cursor_pos_, 0); 
                                    // Clear to End of Screen (wipes remote text + wrapped lines)
                                    std::cout << "\x1b[J"; 
                                    // Repaint
                                    std::cout << cmd_accumulator << std::flush;
                                    // Restore cursor
                                    visual_move_cursor(cmd_accumulator.size(), cursor_pos_);
                                }
                            }
                        }

                        // Sync history content to shell before backspace editing
                        sync_history_to_shell(cmd_accumulator);

                        // Check if we are in a DAIS command (: commands stay visual)
                        bool starts_with_colon = !cmd_accumulator.empty() && cmd_accumulator[0] == ':';
                        bool visual_mode = !in_alt_screen_ && (
                                           (pty_.is_shell_idle() && starts_with_colon) || 
                                           (!pty_.is_shell_idle() && is_remote_session_ && starts_with_colon)
                                           );
                        
                        if (!cmd_accumulator.empty() && cursor_pos_ > 0) {
                            int old_cursor = cursor_pos_;
                            std::string tail = cmd_accumulator.substr(cursor_pos_);
                            cmd_accumulator.erase(cursor_pos_ - 1, 1);
                            cursor_pos_--;
                            
                            if (visual_mode) {
                                // Multi-line aware repaint: Move to new pos, print tail + space, then return to cursor_pos_
                                visual_move_cursor(old_cursor, cursor_pos_);
                                std::cout << tail << " " << std::flush;
                                visual_move_cursor(cursor_pos_ + tail.size() + 1, cursor_pos_);
                            } else {
                                data_to_write += c;
                            }
                        } else if (!visual_mode) {
                            // If empty and not in a special DAIS mode, pass through to shell
                            data_to_write += c;
                        }
                    }
                    // Regular character
                    else if (std::isprint(static_cast<unsigned char>(c))) {
                        // ADOPTION: Same as backspace, we try to adopt history commands
                        // before the first new character "leaks" to the shell.
                        if (cmd_accumulator.empty()) {
                            CursorRecovery recovery;
                            {
                                std::lock_guard<std::mutex> lock(prompt_mutex_);
                                recovery = recover_cmd_from_buffer(prompt_buffer_);
                            }
                            if (recovery.command.starts_with(":")) {
                                cmd_accumulator = recovery.command;
                                cursor_pos_ = recovery.cursor_idx;
                                ensure_visual_mode_init(cursor_pos_);

                                if (is_remote_session_) {
                                    std::lock_guard<std::recursive_mutex> terminal_lock(terminal_mutex_);
                                    // Rewind to start of command (handles wrapping)
                                    visual_move_cursor(cursor_pos_, 0); 
                                    // Clear to End of Screen (wipes remote text + wrapped lines)
                                    std::cout << "\x1b[J"; 
                                    // Repaint
                                    std::cout << cmd_accumulator << std::flush;
                                    // Restore cursor
                                    visual_move_cursor(cmd_accumulator.size(), cursor_pos_);
                                }
                            }
                        }

                        // Sync history content to shell before typing
                        sync_history_to_shell(cmd_accumulator);

                        // Track input if shell is idle OR if we are in a remote session 
                        // (needed for :db interception in SSH)
                        bool starts_with_colon = !cmd_accumulator.empty() && cmd_accumulator[0] == ':';
                        if (pty_.is_shell_idle() || is_remote_session_ || c == ':') {
                            if (cursor_pos_ > cmd_accumulator.size()) cursor_pos_ = cmd_accumulator.size();
                            cmd_accumulator.insert(cursor_pos_, 1, c);
                            cursor_pos_++;
                            
                            // Update starts_with_colon after adding char
                            if (cmd_accumulator.size() == 1 && c == ':') starts_with_colon = true;
                        }
                        
                        // Visual-only mode: DAIS commands (:) only
                        // GUARD: Disable visual mode in alternate screen (Vim) so keys pass through logic
                        bool visual_mode = !in_alt_screen_ && (
                                           (pty_.is_shell_idle() && starts_with_colon) || 
                                           (!pty_.is_shell_idle() && is_remote_session_ && starts_with_colon)
                                           );
                        
                        if (visual_mode) {
                            std::lock_guard<std::recursive_mutex> terminal_lock(terminal_mutex_);
                            int old_cursor = cursor_pos_ - 1; // Position before char insertion
                            std::string tail = cmd_accumulator.substr(cursor_pos_);
                            
                            // Reprint from where we were: char + tail, then return to new cursor_pos_
                            visual_move_cursor(old_cursor, old_cursor); 
                            std::cout << c << tail << std::flush;
                            visual_move_cursor(cursor_pos_ + tail.size(), cursor_pos_);
                        } else {
                            data_to_write += c;
                        }
                    }
                    // Non-printable (control chars, etc.) - always pass through
                    else {
                        data_to_write += c;
                    }
                }
                
                // Write to PTY Master (Input to Shell)
                if (!data_to_write.empty()) {
                    write(pty_.get_master_fd(), data_to_write.data(), data_to_write.size());
                }
            }
        }
    }

    /**
     * @brief Helper to identify if a line is a DAIS internal command.
     */
    bool Engine::is_internal_command(const std::string& line) {
        std::string trimmed = line;
        // Trim leading whitespace
        size_t first = trimmed.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return false;
        trimmed = trimmed.substr(first);
        return trimmed.starts_with(":");
    }

    /**
     * @brief Processes a complete block of pasted text.
     * 
     * Atomic handling: Internal commands are marked for interception,
     * native commands are sent directly to the shell.
     */
    void Engine::process_paste_block() {
        if (paste_accumulator_.empty()) {
            bracketed_paste_active_ = false;
            return;
        }

        // We strip the trailing newline to prevent commitment.
        std::string block = paste_accumulator_;
        
        // Remove carriage returns \r
        block.erase(std::remove(block.begin(), block.end(), '\r'), block.end());
        
        // Remove trailing \n to avoid automatic execution
        while (!block.empty() && block.back() == '\n') {
            block.pop_back();
        }

        if (block.empty()) {
            paste_accumulator_.clear();
            bracketed_paste_active_ = false;
            return;
        }

        // Dispatch logic
        if (is_internal_command(block)) {
             // Ensure coordinates are initialized before repainting the paste
             ensure_visual_mode_init();
             
             // For internal commands (:), DAIS manages its own local prompt.
             // We replace remaining \n with ' ' to keep it on one line for easier editing.
             for (char& c : block) if (c == '\n') c = ' ';
             input_accumulator_ += block;
             write(STDOUT_FILENO, block.c_str(), block.size());
        } else {
             // Native commands go to the PTY (the shell).
             // Intermediate newlines in the block WILL trigger shell execution of those lines.
             // This is consistent with standard terminal paste behavior.
             write(pty_.get_master_fd(), block.c_str(), block.size());
             
             // Sync our local command tracker for remote session interception
             if (pty_.is_shell_idle() || is_remote_session_) {
                input_accumulator_ += block;
             }
        }

        paste_accumulator_.clear();
        bracketed_paste_active_ = false;
        cursor_pos_ = input_accumulator_.size();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    /// @brief Execute DAIS internal commands (prefixed with ':')
    /// 
    /// @param clean The cleaned command string (e.g., ":ls", ":db select * from t")
    /// @param from_shell_echo If true, command was recovered from shell's echo output
    ///        (e.g., history recall). Prevents double-echoing of the command.
    ///
    /// Internal commands are intercepted before reaching the shell, allowing DAIS
    /// to provide enhanced functionality like configuration, database queries, and
    /// remote agent management without shell interference.
    // ═══════════════════════════════════════════════════════════════════════════
    void Engine::execute_internal_command(const std::string& clean, bool from_shell_echo) {
        if (clean.empty()) return;
        std::lock_guard<std::recursive_mutex> terminal_lock(terminal_mutex_);

        // Echo command only if user typed it fresh (not from shell history recall)
        if (!from_shell_echo) {
            std::cout << clean << "\r\n" << std::flush;
        } else {
            // Shell already echoed command - just print newline to separate from output
            std::cout << "\r\n" << std::flush;
        }

        // Persist to local history (skip remote sessions and :history itself to avoid loops)
        if (!is_remote_session_ && !clean.starts_with(":history")) {
            save_history_entry(clean);
            history_index_ = command_history_.size();
        }

        // 1. Exit Command (Emergency/Direct)
        // [FAILSAFE]: Allow exit regardless of shell state (except if in alt-screen/vim)
        // to ensure escape from hung remote sessions.
        if (!in_alt_screen_ && (clean == ":q" || clean == ":exit")) {
            running_ = false;
            kill(pty_.get_child_pid(), SIGHUP);
            return;
        }

        // 2. DB Command
        if (clean.starts_with(":db")) {
            std::string query;
            size_t first_space = clean.find(' ');
            if (first_space != std::string::npos) {
                query = clean.substr(first_space + 1);
                size_t first_char = query.find_first_not_of(" ");
                if (first_char != std::string::npos && first_char > 0) {
                    query = query.substr(first_char);
                }
            }
            
            const char kill_line = kCtrlU; 
            write(pty_.get_master_fd(), &kill_line, 1);

            if (is_remote_session_) {
                std::string escaped = clean;
                size_t p = 0;
                while ((p = escaped.find("\"", p)) != std::string::npos) {
                    escaped.replace(p, 1, "\\\"");
                    p += 2;
                }
                std::string inject = "{ history -s \"" + escaped + "\" 2>/dev/null || print -s \"" + escaped + "\" 2>/dev/null; }";
                execute_remote_command(inject, 2000);
            }

            sync_child_cwd();
            handle_db_command(query);
            write(pty_.get_master_fd(), "\n", 1);
        }
        // 3. Help Command
        else if (clean == ":help") {
            const char kill_line = kCtrlU; 
            write(pty_.get_master_fd(), &kill_line, 1);
            std::cout << "\r\n" << get_help_text() << std::flush;

            if (is_remote_session_) {
                std::string inject = "{ history -s \":help\" 2>/dev/null || print -s \":help\" 2>/dev/null; }";
                execute_remote_command(inject, 2000);
            }
            write(pty_.get_master_fd(), "\n", 1);
        }
        // 4. Agent Status
        else if (clean == ":agent-status") {
            const char kill_line = kCtrlU; 
            write(pty_.get_master_fd(), &kill_line, 1);
            
            std::string logo = handlers::Theme::STRUCTURE + "[" + handlers::Theme::NOTICE + "AGENT" + handlers::Theme::STRUCTURE + "]" + handlers::Theme::RESET;
            std::cout << logo << " Status Report:\r\n";
            std::cout << "  Active: " << (is_remote_session_ ? "Yes (Remote)" : "No (Local)") << "\r\n";
            if (is_remote_session_) {
                std::cout << "  Deployed: " << (remote_agent_deployed_ ? (handlers::Theme::SUCCESS + "YES (Binary)" + handlers::Theme::RESET) : (handlers::Theme::WARNING + "NO (Python Fallback)" + handlers::Theme::RESET)) << "\r\n";
                std::cout << "  Arch: " << remote_arch_ << "\r\n";
                if (remote_agent_deployed_) {
                    std::cout << "  Path: ~/.dais/bin/agent_" << remote_arch_ << "\r\n";
                }
            }
            std::cout << std::flush;

            if (is_remote_session_) {
                std::string inject = "{ history -s \":agent-status\" 2>/dev/null || print -s \":agent-status\" 2>/dev/null; }";
                execute_remote_command(inject, 2000);
            }
            write(pty_.get_master_fd(), "\n", 1);
        }
        // 5. LS Customization
        else if (clean.starts_with(":ls")) {
            const char kill_line = kCtrlU; 
            write(pty_.get_master_fd(), &kill_line, 1);

            std::string args;
            size_t first_space = clean.find(' ');
            if (first_space != std::string::npos) {
                args = clean.substr(first_space + 1);
                size_t first_char = args.find_first_not_of(" ");
                if (first_char != std::string::npos && first_char > 0) {
                    args = args.substr(first_char);
                }
            }

            if (args.empty()) {
                std::string msg = handlers::Theme::STRUCTURE + "[" + handlers::Theme::UNIT + "LS Customization" + handlers::Theme::STRUCTURE + "]" + handlers::Theme::RESET + "\r\n";
                msg += "Sort By   " + handlers::Theme::STRUCTURE + ": " + handlers::Theme::VALUE + config_.ls_sort_by + handlers::Theme::RESET + "\r\n";
                msg += "Order     " + handlers::Theme::STRUCTURE + ": " + handlers::Theme::VALUE + config_.ls_sort_order + handlers::Theme::RESET + "\r\n";
                msg += "Dirs 1st  " + handlers::Theme::STRUCTURE + ": " + handlers::Theme::VALUE + (config_.ls_dirs_first ? "true" : "false") + handlers::Theme::RESET + "\r\n";
                msg += "Flow      " + handlers::Theme::STRUCTURE + ": " + handlers::Theme::VALUE + config_.ls_flow + handlers::Theme::RESET + "\r\n";
                
                std::string pipe = handlers::Theme::STRUCTURE + "|" + handlers::Theme::SYMLINK;
                msg += handlers::Theme::STRUCTURE + "[" + handlers::Theme::UNIT + "Usage" + handlers::Theme::STRUCTURE + "] " + handlers::Theme::RESET + ":ls " + 
                       handlers::Theme::STRUCTURE + "[" + handlers::Theme::SYMLINK + "name" + pipe + "size" + pipe + "type" + pipe + "rows" + pipe + "none" + handlers::Theme::STRUCTURE + "] " +
                       handlers::Theme::STRUCTURE + "[" + handlers::Theme::SYMLINK + "asc" + pipe + "desc" + handlers::Theme::STRUCTURE + "] " +
                       handlers::Theme::STRUCTURE + "[" + handlers::Theme::SYMLINK + "true" + pipe + "false" + handlers::Theme::STRUCTURE + "] " +
                       handlers::Theme::STRUCTURE + "[" + handlers::Theme::SYMLINK + "h" + pipe + "v" + handlers::Theme::STRUCTURE + "]\r\n";
                write(STDOUT_FILENO, msg.c_str(), msg.size());
            } else {
                std::stringstream ss(args);
                std::string segment;
                while (ss >> segment) {
                    if (segment == "d" || segment == "default") {
                        config_.ls_sort_by = "type";
                        config_.ls_sort_order = "asc";
                        config_.ls_dirs_first = true;
                        config_.ls_flow = "h";
                    } 
                    else if (segment == "size") config_.ls_sort_by = "size";
                    else if (segment == "name") config_.ls_sort_by = "name";
                    else if (segment == "type") config_.ls_sort_by = "type";
                    else if (segment == "rows") config_.ls_sort_by = "rows";
                    else if (segment == "none") config_.ls_sort_by = "none";
                    else if (segment == "asc") config_.ls_sort_order = "asc";
                    else if (segment == "desc") config_.ls_sort_order = "desc";
                    else if (segment == "true") config_.ls_dirs_first = true;
                    else if (segment == "false") config_.ls_dirs_first = false;
                    else if (segment == "h" || segment == "horizontal") config_.ls_flow = "h";
                    else if (segment == "v" || segment == "vertical") config_.ls_flow = "v";
                }
                
                std::string confirm = handlers::Theme::STRUCTURE + "[" + handlers::Theme::UNIT + "Updated Settings" + handlers::Theme::STRUCTURE + "]" + handlers::Theme::RESET + "\r\n";
                if (segment == "d" || segment == "default") {
                    confirm = handlers::Theme::STRUCTURE + "[" + handlers::Theme::SUCCESS + "-"
                            + handlers::Theme::STRUCTURE + "]" + handlers::Theme::UNIT + " Reset" + handlers::Theme::RESET
                            + " :ls " + handlers::Theme::UNIT + "to defaults" + handlers::Theme::RESET + "\r\n";
                } else {
                    confirm += "Sort By   " + handlers::Theme::STRUCTURE + ": " + handlers::Theme::VALUE + config_.ls_sort_by + handlers::Theme::RESET + "\r\n";
                    confirm += "Order     " + handlers::Theme::STRUCTURE + ": " + handlers::Theme::VALUE + config_.ls_sort_order + handlers::Theme::RESET + "\r\n";
                    confirm += "Dirs 1st  " + handlers::Theme::STRUCTURE + ": " + handlers::Theme::VALUE + (config_.ls_dirs_first ? "true" : "false") + handlers::Theme::RESET + "\r\n";
                    confirm += "Flow      " + handlers::Theme::STRUCTURE + ": " + handlers::Theme::VALUE + config_.ls_flow + handlers::Theme::RESET + "\r\n";
                }
                write(STDOUT_FILENO, confirm.c_str(), confirm.size());
            }

            if (is_remote_session_) {
                // Inject the FULL command with args (e.g. :ls -la)
                // Escape quotes just in case
                std::string escaped = clean;
                size_t p = 0;
                while ((p = escaped.find("\"", p)) != std::string::npos) {
                    escaped.replace(p, 1, "\\\"");
                    p += 2;
                }
                std::string inject = "{ history -s \"" + escaped + "\" 2>/dev/null || print -s \"" + escaped + "\" 2>/dev/null; }";
                execute_remote_command(inject, 2000);
            }
            write(pty_.get_master_fd(), "\n", 1);
        }
        // 6. History
        else if (clean.starts_with(":history")) {
            std::string args;
            size_t first_space = clean.find(' ');
            if (first_space != std::string::npos) {
                args = clean.substr(first_space + 1);
                size_t first_char = args.find_first_not_of(" ");
                if (first_char != std::string::npos && first_char > 0) {
                    args = args.substr(first_char);
                }
            }
            show_history(args);
            write(pty_.get_master_fd(), "\n", 1);
        }
    }

    


    // =========================================================================
    // REMOTE COMMAND EXECUTION (Agent-Based)
    // =========================================================================

    void Engine::handle_remote_ls(const handlers::LSArgs& ls_args, const std::string& original_cmd) {
        std::lock_guard<std::recursive_mutex> terminal_lock(terminal_mutex_);
        // 1. Cancel the user's "ls" characters that are sitting on the remote prompt
        // Ctrl-C (\x03) can be unreliable if the shell is laggy.
        // Safer: Ctrl-A (Start of Line) + Ctrl-K (Kill Line)
        char cancel[] = { kCtrlA, kCtrlK, 0 }; 
        write(pty_.get_master_fd(), cancel, 2);
                
        // 2. Deployment Check
        deploy_remote_agent(); 
        
        std::string json_out;
        
        // 3. Prepare Arguments
        std::string paths_arg;
        for(const auto& p : ls_args.paths) {
            if(!p.empty()) paths_arg += " \"" + p + "\""; // Add quotes for paths with spaces
        }
        if (paths_arg.empty()) paths_arg = " .";


        // 4. Select Execution Method
        // Construct history injection command (Bash: history -s, Zsh: print -s)
        // We assume quotes in original_cmd are balanced or at least simple enough; 
        // proper escaping would require a full shell parser, but basic escaping of " is needed.
        std::string escaped_cmd = original_cmd;
        size_t pos = 0;
        while ((pos = escaped_cmd.find("\"", pos)) != std::string::npos) {
            escaped_cmd.replace(pos, 1, "\\\"");
            pos += 2;
        }
        
        // Polyfill to add to history without executing
        std::string history_inject = "{ history -s \"" + escaped_cmd + "\" 2>/dev/null || print -s \"" + escaped_cmd + "\" 2>/dev/null; }";

        if (remote_agent_deployed_) {
            // A. Binary Agent (Preferred / Fast)
            // \x15 is now handled in execute_remote_command
            std::string agent_cmd = "~/.dais/bin/agent_" + (remote_arch_.empty() ? "x86_64" : remote_arch_);
            agent_cmd += (ls_args.show_hidden ? " -a" : "");
            agent_cmd += paths_arg;
            
            // Chain: History Inject -> Agent
            std::string full_cmd = history_inject + "; " + agent_cmd;
            
            json_out = execute_remote_command(full_cmd, 5000);
        } else {
            // B. Python Fallback (Tier 2 - Slower but Universal)
            // Enhanced with file analysis logic (counts items, rows, cols)
            std::string py_script = 
                "import os,json,stat,sys\n"
                "def A(p,m):\n"
                " if stat.S_ISDIR(m):\n"
                "  try: return 0,0,len(os.listdir(p)),False,False,False\n"
                "  except: return 0,0,0,False,False,False\n"
                " r=0; c=0; t=False; est=False\n"
                " try:\n"
                "  if os.path.getsize(p)==0: return 0,0,0,True,False,False\n"
                "  with open(p,'rb') as f:\n"
                "   h=f.read(1024)\n"
                "   if b'\\0' in h: return 0,0,0,False,False,False\n"
                "   t=True; f.seek(0)\n"
                "   # Limit full scan to 1MB\n"
                "   if os.path.getsize(p)>1048576:\n"
                "    est=True\n"
                "    buf=f.read(32768)\n"
                "    r=buf.count(b'\\n')\n"
                "    if r>0: r=int(r*(os.path.getsize(p)/32768.0))\n"
                "   else:\n"
                "    for l in f:\n"
                "     r+=1\n"
                "     ln=len(l.rstrip(b'\\r\\n'))\n"
                "     if ln>c:c=ln\n"
                " except: pass\n"
                " return r,c,0,t,False,est\n"
                "\n"
                "L=[]\n"
                "paths=sys.argv[1:] or ['.']\n"
                "for P in paths:\n"
                " try:\n"
                "  for f in os.listdir(P):\n"
                "   try:\n"
                "    p=os.path.join(P,f)\n"
                "    s=os.lstat(p)\n"
                "    d=stat.S_ISDIR(s.st_mode)\n"
                "    if not " + std::string(ls_args.show_hidden ? "True" : "False") + " and f.startswith('.'): continue\n"
                "    r,c,cnt,txt,data,est = A(p,s.st_mode)\n"
                "    L.append({"
                "     'name':f,"
                "     'is_dir':d,"
                "     'size':s.st_size,"
                "     'rows':r,'cols':c,'count':cnt,"
                "     'is_text':txt,"
                "     'is_data':data,"
                "     'is_estimated':est"
                "    })\n"
                "   except:pass\n"
                " except:pass\n"
                "print('DAIS_JSON_START')\n" 
                "print(json.dumps(L, separators=(',', ':')))";
                
            // \x15 is now handled in execute_remote_command to ensure it precedes the space
            std::string py_cmd = "python3 -c \"" + py_script + "\" " + paths_arg;
            
            // Chain: History Inject -> Python
            std::string full_cmd = history_inject + "; " + py_cmd;
            
            json_out = execute_remote_command(full_cmd, 5000);
            
            // Robust Extraction
            size_t start_pos = json_out.rfind("DAIS_JSON_START");
            if (start_pos != std::string::npos) {
                size_t nl = json_out.find('\n', start_pos);
                if (nl != std::string::npos) {
                    json_out = json_out.substr(nl + 1);
                }
            }
        }
        
        // 5. Validation Check
        bool valid_json = false;
        if (!json_out.empty()) {
            size_t bracket = json_out.find('[');
            if (bracket != std::string::npos) {
                try {
                    // Pre-validate that it looks somewhat like JSON before passing to Python
                    // This is a weak check, but saves a Python call
                    json_out = json_out.substr(bracket);
                    valid_json = true;
                } catch (...) {
                    valid_json = false;
                }
            }
        }
        
        // 6. Fallback Behavior
        // ... handled below ...
        
        // 7. Render
        if (valid_json) {
            try {
                // Safely parse JSON via Python
                handlers::LSFormats formats;
                formats.directory = config_.ls_fmt_directory;
                formats.text_file = config_.ls_fmt_text_file;
                formats.data_file = config_.ls_fmt_data_file;
                formats.binary_file = config_.ls_fmt_binary_file;
                
                handlers::LSSortConfig sort_cfg;
                sort_cfg.by = config_.ls_sort_by;
                sort_cfg.order = config_.ls_sort_order;
                sort_cfg.dirs_first = config_.ls_dirs_first;
                sort_cfg.flow = config_.ls_flow;
                
                // CRITICAL: This native function call eventually calls Python's json.loads
                // We MUST guard this because agent output errors (e.g. SIGKILL truncating JSON)
                // shouldn't crash the engine.
                std::string output = handlers::render_remote_ls(json_out, formats, sort_cfg, config_.ls_padding);
                
                if (!output.empty()) {
                    write(STDOUT_FILENO, "\r\n", 2);
                    write(STDOUT_FILENO, output.c_str(), output.size());
                } 
            } catch (const std::exception& e) {
                // If parsing fails, fall back to native LS warning
                valid_json = false;
            } catch (...) {
                valid_json = false;
            }
        } 
        
        if (!valid_json || (!remote_agent_deployed_ && !valid_json)) {
             // Logic consolidation:
             // If deployment failed OR parsing failed, output error or fallback.
             if (!remote_agent_deployed_) {
                 write(pty_.get_master_fd(), "ls\n", 3);
                 return;
             }
             
            std::string logo = handlers::Theme::STRUCTURE + "[" + handlers::Theme::WARNING + "-" + handlers::Theme::STRUCTURE + "]" + handlers::Theme::RESET + " ";
            std::string err = "\r\n" + logo + "Remote execution error (invalid output).\r\n";
            write(STDOUT_FILENO, err.c_str(), err.size());
        }

        // 8. Visual Cleanup (CRITICAL)
        // Clear the prompt buffer memory so we don't "recover" the 'ls' we just ran
        {
            std::lock_guard<std::mutex> lock(prompt_mutex_);
            at_line_start_ = true;
        }

        // 9. Force Fresh Prompt
        // Sending a newline to PTY ensures the shell prints a fresh prompt
        // Don't write to local STDOUT - that causes extra blank lines
        write(pty_.get_master_fd(), "\n", 1);
    }

    /**
     * @brief Recovers a clean command string from the prompt buffer by simulating terminal behavior.
     * 
     * Handles ANSI escape codes, cursor movements (backspace, carriage return, CSI C/D),
     * and line clearing (CSI 1K/2K) to reconstruct what is visually present on the line.
     * This is crucial for intercepting commands from shell history where the input
     * comes from the shell's echo rather than user keystrokes.
     * 
     * @param buffer The raw PTY output buffer containing prompts, commands, and ANSI codes.
     * @return A CursorRecovery struct with the command and local cursor index.
     */
    Engine::CursorRecovery Engine::recover_cmd_from_buffer(const std::string& buffer) {
        // 1. Terminal Simulation (Cursor & Overwrite)
        // We reconstruct the line by simulating cursor movements and overwrites.
        std::string clean_line;
        size_t cursor = 0;
        
        // State machine for ANSI skipping
        enum AnsiState { TEXT, ESC, CSI, OSC, OSC_ESC };
        AnsiState state = TEXT;
        std::string csi_seq;
        
        for (char c : buffer) {
            if (state == TEXT) {
                if (c == kEsc) { state = ESC; }
                else if (c == '\b' || c == 0x7f) { 
                    // Handle Backspace (Move cursor left)
                    if (cursor > 0) cursor--;
                }
                else if (c == '\r') {
                    // Handle Carriage Return (Move cursor to start, don't erase)
                    cursor = 0;
                }
                else if (c == kCtrlA) {
                    // Start of Line
                    cursor = 0;
                }
                else if (c == kCtrlK) {
                    // Kill to End of Line
                    if (cursor < clean_line.size()) {
                        clean_line.resize(cursor);
                    }
                }
                else if (c == kCtrlU) {
                    // Clear Line
                    clean_line.clear();
                    cursor = 0;
                }
                else if (c == '\n') {
                    // Handle Line Feed (Wrapping)
                    // If we saw \r (cursor=0) then \n, we should probably append 
                    // rather than overwriting from index 0.
                    cursor = clean_line.size();
                }
                else if (c >= 32) { // Printable (allow spaces)
                    if (cursor < clean_line.size()) {
                        clean_line[cursor] = c; // Overwrite
                    } else {
                        clean_line.push_back(c); // Append
                    }
                    cursor++;
                }
            }
            else if (state == ESC) {
                if (c == '[') { state = CSI; csi_seq.clear(); }
                else if (c == ']') state = OSC;
                else state = TEXT; // Fallback
            }
            else if (state == CSI) {
                if (c >= 0x40 && c <= 0x7E) { 
                    // End of CSI (includes letters, ~, etc.)
                    if (c == 'K') { 
                        // EL - Erase in Line (CSI n K)
                        // 0 (default): Execute clear from cursor to end
                        if (csi_seq.empty() || csi_seq == "0") {
                            if (cursor < clean_line.size()) {
                                clean_line.resize(cursor);
                            }
                        }
                        // 1: Clear from start to cursor
                        else if (csi_seq == "1") {
                             if (cursor < clean_line.size()) {
                                 // Replace 0..cursor with spaces
                                 for (size_t k = 0; k <= cursor && k < clean_line.size(); ++k) clean_line[k] = ' ';
                             }
                        }
                        // 2: Clear entire line
                        else if (csi_seq == "2") {
                            clean_line.clear();
                            if (cursor > 0) clean_line.resize(cursor, ' ');
                        }
                    }
                    else if (c == 'C') {
                        // Cursor Forward (Right)
                        int n = 1;
                        try { if (!csi_seq.empty()) n = std::stoi(csi_seq); } catch(...) {}
                        cursor += n;
                        if (cursor > clean_line.size()) {
                            clean_line.resize(cursor, ' ');
                        }
                    }
                    else if (c == 'D') {
                        // Cursor Back (Left)
                        int n = 1;
                        try { if (!csi_seq.empty()) n = std::stoi(csi_seq); } catch(...) {}
                        if (cursor >= n) cursor -= n;
                        else cursor = 0;
                    }

                    state = TEXT; 
                } else {
                    csi_seq += c;
                }
            }
            else if (state == OSC) {
                if (c == kEsc) state = OSC_ESC;
                else if (c == kBell) state = TEXT; // Bell terminator
            }
            else if (state == OSC_ESC) {
                if (c == '\\') state = TEXT; // ST terminator
                else state = OSC;
            }
        }
        
        // 2. Find the last prompt in clean buffer
        size_t best_pos = std::string::npos;
        size_t prompt_len = 0;
        
        for (const auto& prompt : config_.shell_prompts) {
            size_t pos = clean_line.rfind(prompt);
            // Pick the rightmost prompt found
            if (pos != std::string::npos) {
                if (best_pos == std::string::npos || pos > best_pos) {
                    best_pos = pos;
                    prompt_len = prompt.size();
                }
            }
        }
        
        if (best_pos != std::string::npos) {
            // Found prompt, assume command follows
            std::string recovered = clean_line.substr(best_pos + prompt_len);
            
            // Adjust cursor index to be relative to the start of the command
            int relative_cursor = static_cast<int>(cursor) - static_cast<int>(best_pos + prompt_len);
            if (relative_cursor < 0) relative_cursor = 0;
            if (relative_cursor > recovered.size()) relative_cursor = recovered.size();
            
            // DEEP CLEAN: Strip any remaining non-printable chars
            std::string deep_clean;
            for (char c : recovered) {
                if (std::isprint(static_cast<unsigned char>(c))) {
                    deep_clean += c;
                }
            }
            if (!deep_clean.empty()) recovered = deep_clean;
            if (relative_cursor > recovered.size()) relative_cursor = recovered.size();

            return {recovered, relative_cursor};
        }
        
        return {"", 0};
    }

    void Engine::check_remote_session() {
        std::string fg = pty_.get_foreground_process_name();
        int fg_pid = pty_.get_foreground_process_pid();
        
        bool was = is_remote_session_;
        
        // Simple heuristic: if foreground process contains "ssh", assume remote.
        bool detected_ssh = (fg.find("ssh") != std::string::npos);

        if (detected_ssh) {
            is_remote_session_ = true;
            
            // New Session Logic:
            // If the PID changed, it's a completely new SSH connection.
            // (Even if the user just exited one ssh and started another immediately)
            if (fg_pid != remote_session_pid_) {
                // RESET STATE
                remote_agent_deployed_ = false;
                remote_db_deployed_ = false;
                remote_arch_ = "";
                remote_session_pid_ = fg_pid;
                
                // Signal that we want to deploy as soon as we see the first prompt
                pending_remote_deployment_ = true;
                ready_to_deploy_ = false;
            }
        } else {
            // Not detecting SSH currently.
            // BUT: Don't flip is_remote_session_ to false immediately if the PID is still valid.
            // PTY naming can sometimes flicker (e.g. to "bash" or "grep") during execution.
            // However, get_foreground_process_pid() reflects the process group leader usually.
            
            // Safe Reset: Only verify we actually LEFT the session if the previous PID is gone
            // or if the current foreground PID is explicitly DIFFERENT and NOT ssh.
            
            if (was) {
               // We WERE in a session. Now we see 'fg' (e.g. "bash") and 'fg_pid'.
               // If fg_pid is DIFFERENT than remote_session_pid_, then yes, the SSH process is gone.
               if (fg_pid != remote_session_pid_) {
                   is_remote_session_ = false;
                   remote_session_pid_ = -1;
               } 
               // If fg_pid == remote_session_pid_, we assume it's just a transient state check 
               // (maybe the SSH process is exec'ing something?) or just keep it true for stability.
            } else {
                is_remote_session_ = false;
            }
        }
    }

    std::string Engine::execute_remote_command(const std::string& cmd, int timeout_ms) {
        // Only run if legitimate
        if (!pty_.is_shell_idle() && !is_remote_session_) return "";

        // 1. Prepare Capture
        {
            std::lock_guard<std::mutex> lock(capture_mutex_);
            capture_buffer_.clear();
            capture_mode_ = true;
        }

        // 2. Send Command with Sentinel
        // We use arithmetic expansion to ensure the command echo is totally different from the result
        // Echo: "echo $(( A + B ))"
        // Result: "Sum"
        auto now = std::chrono::system_clock::now().time_since_epoch().count() % 1000000000; // shorter
        long long part_a = now / 2;
        long long part_b = now - part_a;
        
        std::string sentinel = "DAIS_END_" + std::to_string(now);
        
        // Command format: "\x15 cmd; echo DAIS_END_$(( A + B ))\n"
        // 1. \x15 (Ctrl+U): Clears the current line (e.g. "ls path/")
        // 2. " " (Space): Prevents command from being saved to history (HISTCONTROL=ignorespace)
        // 3. Command & Sentinel
        std::string full_cmd;
        full_cmd += kCtrlU;
        full_cmd += " " + cmd + "; echo DAIS_END_$(( " + std::to_string(part_a) + " + " + std::to_string(part_b) + " ))\n";
        
        write(pty_.get_master_fd(), full_cmd.c_str(), full_cmd.size());

        // 3. Wait for Sentinel
        std::unique_lock<std::mutex> lock(capture_mutex_);
        bool finished = capture_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]{
            return capture_buffer_.find(sentinel) != std::string::npos;
        });

        if (finished) {
            /// @brief Prompt-Aware Buffering (Race Condition Fix)
            /// 
            /// SSH/PTY streams fragment data unpredictably. Without this logic, the
            /// shell prompt (e.g., "user@host$ ") might arrive AFTER we disable capture,
            /// leaking it to stdout and causing visual glitches ("ghost prompts").
            ///
            /// Solution: Wait until the buffer definitively ends with a shell prompt
            /// (either user-configured or standard patterns like "$ ").
            capture_cv_.wait_for(lock, std::chrono::milliseconds(1000), [&]{
                if (capture_buffer_.empty()) return false;
                
                // Prompt isn't complete if buffer ends with newline
                char last = capture_buffer_.back();
                if (last == '\n' || last == '\r') return false;

                // Check user-configured prompts first (supports fancy prompts like "➜ ")
                for (const auto& p : config_.shell_prompts) {
                    if (capture_buffer_.size() >= p.size() && 
                        capture_buffer_.compare(capture_buffer_.size() - p.size(), p.size(), p) == 0) {
                        return true; 
                    }
                }

                // Fallback: standard shell prompts ("$ ", "# ", "> ")
                if (capture_buffer_.size() >= 2) {
                    char second_last = capture_buffer_[capture_buffer_.size() - 2];
                    if (last == ' ' && (second_last == '$' || second_last == '#' || second_last == '>')) {
                        return true;
                    }
                }
                
                return false;
            });
        }

        // 4. Disable Capture
        capture_mode_ = false;

        if (!finished) {
            return ""; // Timeout
        }
        
        // 5. Clean Buffer (Strip Echo and Sentinel)
        // Captured buffer looks like: " cmd; echo DAIS_END_...\r\nOUTPUT\r\nDAIS_END_...\r\n"
        // We want just "OUTPUT"
        
        std::string clean = capture_buffer_;
        
        // Remove the Sentinel line at the end
        size_t sent_pos = clean.find(sentinel);
        if (sent_pos != std::string::npos) {
            clean = clean.substr(0, sent_pos);
        }
        
        // Remove the Command Echo at the start
        // The shell might echo the command we sent. 
        // We look for the FIRST newline, assuming the command echo is on the first line.
        // BUT, strictly speaking, we can just look for the last occurrence of the command string?
        // No, that's risky.
        // Better heuristic:
        // Remote commands are sent as " cmd; echo ...".
        // The echo might contain that full string.
        // We also know the *previous* command output ended with a prompt.
        // Actually, we can just look for the first line that is NOT the command echo?
        // Let's just strip the first line if it contains "DAIS_END_".
        // Because the echo OF THE COMMAND contains the sentinel string too (in the echo part)!
        
        size_t first_newline = clean.find('\n');
        if (first_newline != std::string::npos) {
             std::string first_line = clean.substr(0, first_newline);
             if (first_line.find("DAIS_END_") != std::string::npos) {
                 clean = clean.substr(first_newline + 1);
             }
        }
        
        // Trim whitespace
        const char* ws = " \t\n\r\x0b\x0c";
        clean.erase(0, clean.find_first_not_of(ws));
        clean.erase(clean.find_last_not_of(ws) + 1);
        
        // 6. Strip ANSI Escape Codes (Crucial for remote shell hygiene)
        // Simple state machine to remove \x1b[...] and \x1b(...) sequences
        std::string final_clean;
        final_clean.reserve(clean.size());
        bool in_esc = false;
        
        for (size_t i = 0; i < clean.size(); ++i) {
            char c = clean[i];
            if (c == kEsc) {
                in_esc = true;
                // Look ahead for [ or (
                if (i + 1 < clean.size() && (clean[i+1] == '[' || clean[i+1] == '(')) {
                    i++; // Skip the bracket too, let the loop eat the rest
                } else {
                    // Not a CSI sequence we know? just skip ESC
                    in_esc = false; // Actually, solitary ESC might be valid, but here we assume garbage.
                }
                continue;
            }
            
            if (in_esc) {
                // End of ANSI sequence is usually a letter
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
                    in_esc = false;
                }
                // Continue skipping
                continue;
            }
            
            final_clean += c;
        }
        
        return final_clean;
    }

    void Engine::deploy_remote_agent() {
        if (remote_agent_deployed_ || !is_remote_session_) return;
        
        // Only deploy when shell is idle to avoid corrupting user input/output
        // EXCEPTION: If is_remote_session_ is true, the "busy" process IS the SSH client, 
        // which is exactly what we want to talk to.
        if (!is_remote_session_ && !pty_.is_shell_idle()) return;
        
        // 1. Detect Architecture
        std::string out = execute_remote_command("uname -m", 5000);
        
        if (out.empty()) {
            // Try uname -a as fallback if -m returned nothing
            out = execute_remote_command("uname -a", 5000);
        }
        if (out.empty()) return;

        if (out.find("x86_64") != std::string::npos) remote_arch_ = "x86_64";
        else if (out.find("aarch64") != std::string::npos) remote_arch_ = "aarch64";
        else if (out.find("armv7") != std::string::npos) remote_arch_ = "armv7l";
        else if (out.find("armv6") != std::string::npos) {
             remote_arch_ = "armv6";
        }
        else {
             remote_arch_ = "unknown";
             // Only ERROR for completely unknown architectures (where we can't even try Python safely?)
             // Actually, Python fallback works for unknown too.
        }

        if (remote_arch_ == "unknown" && out.empty()) return; // If uname failed completely

        // 2. Get Binary from Bundle
        auto agent = dais::core::agents::get_agent_for_arch(remote_arch_);
        // If no agent (e.g. armv6 or mock), we return.
        // process_user_input will handle the fallback to Python.
        if (agent.data == nullptr) {
             return; 
        }

        std::string target_path = "~/.dais/bin/agent_" + remote_arch_;
        std::string b64 = base64_encode(agent.data, agent.size);
        std::string temp_b64 = target_path + ".b64";

        // --- VERIFICATION STRATEGY ---
        // 1. Check if agent already exists and has correct Hash + Version
        // This avoids expensive re-deployments on every connection.
        bool need_deploy = true;
        
        // Try getting remote hash (sha256sum is standard on most Linuxes)
        // Output format: "hash  filename" -> we just want the first word
        std::string remote_hash_cmd = "sha256sum " + target_path + " 2>/dev/null | cut -d' ' -f1";
        std::string current_hash = execute_remote_command(remote_hash_cmd, 1000);
        
        // Trim whitespace/newlines (both ends to be safe)
        const char* ws = " \t\n\r\x0b\x0c";
        if (current_hash.find_first_not_of(ws) != std::string::npos) {
            current_hash.erase(0, current_hash.find_first_not_of(ws));
            current_hash.erase(current_hash.find_last_not_of(ws) + 1);
        } else {
            current_hash.clear(); // All whitespace
        }
        
        if (!current_hash.empty() && current_hash == agent.hash) {
            // Hash matches! Now check version to be double sure (and handle upgrades if hash colliding?)
            // Actually hash implies version, so hash check is sufficient.
            // But let's run --version just to ensure it's executable and not corrupted
            std::string ver_cmd = target_path + " --version";
            std::string ver = execute_remote_command(ver_cmd, 1000);
            
            if (ver.find("DAIS_AGENT_v1.0") != std::string::npos) {
                // All good
                need_deploy = false;
                remote_agent_deployed_ = true;
                
                 if (config_.show_logo) {
                    std::cout << "\r\n[" << handlers::Theme::SUCCESS << "-" << handlers::Theme::RESET 
                              << "] Agent verified (" << agent.hash.substr(0, 8) << "...).\r\n" << std::flush;
                }
            }
        }

        if (need_deploy) {
            // Ensure directory exists with SECURE permissions (700)
            execute_remote_command("mkdir -p -m 700 ~/.dais/bin", 2000);
            execute_remote_command("rm -f " + temp_b64, 2000); 

            // Disable Echo
            execute_remote_command("stty -echo", 2000);

            // Start Heredoc
            std::string start_heredoc = "cat > " + temp_b64 + " << 'DAIS_EOF'\n";
            write(pty_.get_master_fd(), start_heredoc.c_str(), start_heredoc.size());
            
            // Stream Data
            constexpr size_t PAYLOAD_CHUNK = 4096;
            size_t sent = 0;
            
            while (sent < b64.size()) {
                size_t n = std::min(PAYLOAD_CHUNK, b64.size() - sent);
                write(pty_.get_master_fd(), b64.data() + sent, n);
                sent += n;
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            
            // End Heredoc
            std::string end_heredoc = "\nDAIS_EOF\n";
            write(pty_.get_master_fd(), end_heredoc.c_str(), end_heredoc.size());
            
            std::this_thread::sleep_for(std::chrono::milliseconds(300));

            // Re-enable Echo
            execute_remote_command("stty echo", 2000);

            // Decode and Finalize
            std::string deploy_cmd = 
                "base64 -d " + temp_b64 + " > " + target_path + " && "
                "chmod +x " + target_path + " && "
                "rm " + temp_b64 + " && "
                "echo DAIS_DEPLOY_OK";

            std::string result = execute_remote_command(deploy_cmd, 10000);
            
            if (result.find("DAIS_DEPLOY_OK") != std::string::npos) {
                remote_agent_deployed_ = true;
                
                // POST-DEPLOY VERIFICATION
                // Ensure what we wrote is what we expected
                current_hash = execute_remote_command(remote_hash_cmd, 1000);
                current_hash.erase(current_hash.find_last_not_of(" \n\r\t") + 1);
                
                if (current_hash != agent.hash) {
                     std::cout << "\r[" << handlers::Theme::WARNING << "-" << handlers::Theme::RESET 
                              << "] Integrity Check Failed! Remote hash mismatch.\r\n"
                              << "    Expected: " << agent.hash << "\r\n"
                              << "    Actual:   [" << current_hash << "]\r\n" << std::flush;
                     remote_agent_deployed_ = false; // Mark invalid
                } else {
                     if (config_.show_logo) {
                         std::cout << "\r\n[" << handlers::Theme::SUCCESS << "-" << handlers::Theme::RESET 
                                   << "] Agent deployed (" << agent.hash.substr(0, 8) << "...).\r\n" << std::flush;
                     }
                }

            } else {
                if (config_.show_logo) {
                    std::string logo = handlers::Theme::STRUCTURE + "[" + handlers::Theme::WARNING + "-" + handlers::Theme::STRUCTURE + "]" + handlers::Theme::RESET + " ";
                    std::cout << "\r\n" << logo << "Agent deployment failed. Falling back to Python.\r\n";
                }
            }
        }
    }
    
    /**
     * @brief Loads command history from ~/.dais_history on startup.
     */
    void Engine::load_history() {
        const char* home = getenv("HOME");
        if (!home) return;
        
        history_file_ = std::filesystem::path(home) / ".dais_history";
        
        std::ifstream file(history_file_);
        if (!file.is_open()) return;
        
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                command_history_.push_back(line);
            }
        }
        
        // Trim to MAX_HISTORY if file was larger
        while (command_history_.size() > MAX_HISTORY) {
            command_history_.pop_front();
        }
        
        // Initialize index to end so UP goes to newest first
        history_index_ = command_history_.size();
    }
    
    /**
     * @brief Appends a command to history (in-memory and file).
     * Skips empty commands and duplicates of the last command.
     */
    void Engine::save_history_entry(const std::string& cmd) {
        if (cmd.empty()) return;
        
        // Skip duplicates
        if (!command_history_.empty() && command_history_.back() == cmd) {
            return;
        }
        
        // Add to in-memory buffer
        command_history_.push_back(cmd);
        if (command_history_.size() > MAX_HISTORY) {
            command_history_.pop_front();
        }
        
        // Append to file
        if (!history_file_.empty()) {
            std::ofstream file(history_file_, std::ios::app);
            if (file.is_open()) {
                file << cmd << "\n";
            }
        }
    }
    
    /**
     * @brief Handles :history command.
     * :history       - Show last 20 commands
     * :history N     - Show last N commands
     * :history clear - Clear all history
     */
    void Engine::show_history(const std::string& args) {
        if (args == "clear") {
            command_history_.clear();
            if (!history_file_.empty()) {
                std::ofstream file(history_file_, std::ios::trunc);
            }
            std::cout << "\r\n[" << handlers::Theme::NOTICE << "-" << handlers::Theme::RESET
                      << "] History cleared.\r\n" << std::flush;
            return;
        }
        
        // Parse count (default 20)
        size_t count = 20;
        if (!args.empty()) {
            try {
                count = std::stoul(args);
            } catch (...) {
                count = 20;
            }
        }
        
        if (command_history_.empty()) {
            std::cout << "\r\n[" << handlers::Theme::NOTICE << "-" << handlers::Theme::RESET
                      << "] History is empty.\r\n" << std::flush;
            return;
        }
        
        // Show last N commands
        std::cout << "\r\n";
        size_t start = command_history_.size() > count ? command_history_.size() - count : 0;
        for (size_t i = start; i < command_history_.size(); i++) {
            std::cout << "[" << handlers::Theme::VALUE << (i + 1) << handlers::Theme::RESET
                      << "] " << command_history_[i] << "\r\n";
        }
        std::cout << std::flush;
    }
    
    /**
     * @brief Navigates through DAIS command history via UP/DOWN arrows.
     * 
     * Performs VISUAL-ONLY updates to the terminal using ANSI escape codes.
     * Does NOT send characters to the shell immediately to avoid race conditions.
     * Sets `history_navigated_ = true` so the Enter key handler can sync the shell later.
     * 
     * @param direction -1 for older (up), +1 for newer (down)
     * @param current_line Reference to cmd_accumulator
     */
    void Engine::navigate_history(int direction, std::string& current_line) {
        // SAFETY: Don't write anything if an app is running (vim/nano)
        // This check is belt-and-suspenders with the caller's check
        if (!pty_.is_shell_idle()) return;
        
        if (command_history_.empty()) return;

        // Determine if we are navigating into a visual mode command
        std::string next_content;
        if (direction < 0 && history_index_ > 0) {
            next_content = command_history_[history_index_ - 1];
        } else if (direction > 0 && history_index_ < command_history_.size() - 1) {
            next_content = command_history_[history_index_ + 1];
        } else if (direction > 0 && history_index_ == command_history_.size() - 1) {
            next_content = history_stash_;
        }

        bool into_visual = next_content.starts_with(":");
        if (into_visual) {
            ensure_visual_mode_init(current_line.size());
        }
        
        // Stash current line when first navigating up from the end
        if (history_index_ == command_history_.size() && direction < 0) {
            history_stash_ = current_line;
        }
        
        // Calculate new index with boundary checks
        size_t new_index = history_index_;
        if (direction < 0 && history_index_ > 0) {
            new_index = history_index_ - 1;
        } else if (direction > 0 && history_index_ < command_history_.size()) {
            new_index = history_index_ + 1;
        } else {
            return;  // Already at boundary
        }
        history_index_ = new_index;
        history_navigated_ = true;  // Mark that we've used history navigation
        
        // Determine new content
        std::string new_content;
        if (history_index_ == command_history_.size()) {
            new_content = history_stash_;  // Restore stashed line
        } else {
            new_content = command_history_[history_index_];
        }
        
        // --- VISUAL UPDATE ONLY ---
        // Move back to start of command, clear everything after, print new content
        {
            std::lock_guard<std::recursive_mutex> terminal_lock(terminal_mutex_);
            visual_move_cursor(current_line.size(), 0);
            write(STDOUT_FILENO, "\x1b[J", 3); // J (Erase in Display) with 0 = clear to end of screen
            
            if (!new_content.empty()) {
                write(STDOUT_FILENO, new_content.c_str(), new_content.size());
            }
        }
        
        // Update internal state - shell will see this when Enter is pressed
        current_line = new_content;
        cursor_pos_ = current_line.size();
    }

    /**
     * @brief Syncs visual-only history content to the shell.
     * 
     * When user navigates DAIS history with Up/Down arrows, changes are
     * visual-only (we write to STDOUT, not to the PTY). Before the shell
     * can process edits (left/right arrows, backspace, typing), we must
     * sync the content to the shell's input buffer.
     * 
     * @param accumulator The current command buffer to sync
     * @return true if sync was performed, false if not needed
     */
    bool Engine::sync_history_to_shell(std::string& accumulator) {
        // Only sync if: navigated history + shell idle + non-empty + not internal command
        if (!history_navigated_ || !pty_.is_shell_idle() || 
            accumulator.empty() || accumulator.starts_with(":")) {
            return false;
        }
        
        // 1. Clear visual: move cursor left by command length, then clear to end
        std::cout << "\x1b[" << accumulator.size() << "D\x1b[K" << std::flush;
        
        // 2. Sync to shell: clear line (Ctrl+U) then send accumulated content
        const char kill_line = kCtrlU;
        write(pty_.get_master_fd(), &kill_line, 1);
        write(pty_.get_master_fd(), accumulator.c_str(), accumulator.size());
        
        // 3. Reset flag - shell now has content
        history_navigated_ = false;
        return true;
    }

    /**
     * @brief Handles the execution of the :db command module.
     * 
     * This method acts as a bridge between the C++ engine and the Python
     * 'db_handler' script. It avoids reinventing DB drivers in C++ by
     * leveraging the embedded Python environment.
     * 
     * Rationale for JSON & Pager Strategy:
     * - We return JSON from Python because it is structured and easy to parse
     *   via the same Python interpreter (using json.loads).
     * - For large results, we use a "pager" strategy where Python writes to
     *   a temp file and C++ injects a 'less' command. This keeps DAIS's
     *   render loop simple and leverages the robust, native 'less' pager
     *   for search/scroll functionality, avoiding a complex TUI implementation.
     */
    void Engine::handle_db_command(const std::string& query) {
        std::lock_guard<std::recursive_mutex> terminal_lock(terminal_mutex_);
        if (query.empty()) {
            std::cout << "[" << handlers::Theme::UNIT << "DB Usage" << handlers::Theme::RESET 
                      << "] :db " << handlers::Theme::STRUCTURE << "<" << handlers::Theme::UNIT << "sql_query" << handlers::Theme::STRUCTURE << ">" << handlers::Theme::RESET 
                      << " OR :db " << handlers::Theme::STRUCTURE << "<" << handlers::Theme::UNIT << "saved_query_name" << handlers::Theme::STRUCTURE << ">\r\n" << std::flush;
            return;
        }

        try {
            std::string json_result;

            if (is_remote_session_) {
                // --- REMOTE EXECUTION ---
                check_remote_session(); // Sync state
                deploy_remote_db_handler();

                // Construct remote command
                // Escaping is tricky. We assume basic quoting.
                std::string escaped_query = query;
                // Simple quote escaping
                size_t pos = 0;
                while ((pos = escaped_query.find("\"", pos)) != std::string::npos) {
                    escaped_query.replace(pos, 1, "\\\"");
                    pos += 2;
                }
                std::string remote_cmd = "python3 ~/.dais/bin/db_handler.py \"" + escaped_query + "\"";
                json_result = execute_remote_command(remote_cmd, 10000); // 10s timeout for DB query
            } else {
                // --- LOCAL EXECUTION ---
                // 1. Invoke Python Handler
                // We use the embedded interpreter to import and run the script.
                py::module_ handler = py::module_::import("db_handler");
                
                // Pass CWD to Python so it can find local .env and config files
                std::string cwd_str = shell_cwd_.string();
                json_result = handler.attr("handle_command")(query, cwd_str).cast<std::string>();
            }
            
            // 2. Parse Result
            
            // 2. Parse Result
            py::module_ json = py::module_::import("json");
            py::object result_obj = json.attr("loads")(json_result);
            
            std::string status = result_obj["status"].cast<std::string>();
            
            // --- HANDLING MISSING PACKAGES (Interactive Install) ---
            if (status == "missing_pkg") {
                std::string pkg = result_obj["package"].cast<std::string>();
                
                std::string location = is_remote_session_ ? ("REMOTE: " + pty_.get_foreground_process_name()) : "LOCAL";
                // Heuristic cleanup of process name if it's just "ssh"
                if (is_remote_session_) location = "REMOTE"; 

                std::cout << "\r\n" << handlers::Theme::STRUCTURE << "[" << handlers::Theme::WARNING << "Missing Package" << handlers::Theme::STRUCTURE << "]" << handlers::Theme::RESET 
                          << " Package '" << handlers::Theme::VALUE << pkg << handlers::Theme::RESET << "' on " << handlers::Theme::UNIT << location << handlers::Theme::RESET << ". Install now"
                          << (is_remote_session_ ? " (user-scope)" : "") << "? (y/N) " << std::flush;
                
                // Read single char response (assuming raw mode)
                char c = 0;
                // Wait for input loop
                while (true) {
                    if (read(STDIN_FILENO, &c, 1) > 0) {
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }

                if (c == 'y' || c == 'Y') {
                    std::cout << "Y\r\n"; // Echo
                    std::string cmd;
                    if (is_remote_session_) {
                         // Remote Installation (User Scope Safety)
                         // Warning is already shown by proper UI, but we ensure the command is safe.
                         cmd = "pip install --user " + pkg;
                    } else {
                         // Local Installation
                         cmd = "pip install " + pkg;
                    }
                    
                    // Clear the prompt line to make space for pip output
                    const char* clear_line = "\x15"; 
                    write(pty_.get_master_fd(), clear_line, 1);
                    
                    // Inject command
                    write(pty_.get_master_fd(), cmd.c_str(), cmd.size());
                    write(pty_.get_master_fd(), "\n", 1); 
                } else {
                    std::cout << "N\r\n";
                }
                return;
            }

            if (status == "error") {
                std::string msg = result_obj["message"].cast<std::string>();
                std::cout << handlers::Theme::STRUCTURE << "[" << handlers::Theme::ERROR << "DB Error" << handlers::Theme::STRUCTURE << "] " << handlers::Theme::RESET 
                          << msg << "\r\n" << std::flush;
                return;
            }

            // 3. Handle Actions
            std::string action = result_obj["action"].cast<std::string>();
            std::string data = result_obj["data"].cast<std::string>();
            
            if (action == "print") {
                // ACTION: Print directly to terminal
                std::cout << "\r\n";
                
                std::string formatted = data;
                size_t pos = 0;
                while ((pos = formatted.find("\n", pos)) != std::string::npos) {
                    formatted.replace(pos, 1, "\r\n");
                    pos += 2;
                }
                std::cout << formatted << "\r\n" << std::flush;
                
            } else if (action == "page") {
                // ACTION: Open in Pager (less)
                std::string pager_cmd = "less -S"; 
                if (result_obj.contains("pager")) {
                    pager_cmd = result_obj["pager"].cast<std::string>();
                }
                
                std::string file_arg = "\"" + data + "\"";
                std::string cmd;
                
                // For remote sessions, check if less is available (offers to install if not)
                if (is_remote_session_) {
                    bool has_less = check_and_offer_less_install();
                    if (has_less) {
                        // Use less with cat fallback
                        std::string polyfill = "{ " + pager_cmd + " " + file_arg + " 2>/dev/null || cat " + file_arg + "; }";
                        cmd = polyfill + "; rm -f " + file_arg;
                    } else {
                        // No less, just cat the output
                        cmd = "cat " + file_arg + "; rm -f " + file_arg;
                    }
                } else {
                    // Local session: less should be available
                    std::string polyfill = "{ " + pager_cmd + " " + file_arg + " 2>/dev/null || cat " + file_arg + "; }";
                    cmd = polyfill + "; rm -f " + file_arg;
                }
                
                // === VISUAL SEPARATION ===
                // The user's typed command (:db ...) is visible on screen.
                // We'll use ANSI escape to clear the current line and move cursor up
                // after the shell echoes our command.
                
                // === REMOTE INJECTION ===
                // Use subshell to:
                // 1. Clear the line with ANSI (hides echo of cat command)
                // 2. Run the pager command
                // 3. Leading space prevents history pollution (HISTCONTROL=ignorespace)
                // The \033[2K clears the current line, \033[A moves up one line
                std::string wrapped_cmd = "printf '\\033[A\\033[2K'; " + cmd;
                std::string full_inject = "\x15 " + wrapped_cmd + "\n";
                write(pty_.get_master_fd(), full_inject.c_str(), full_inject.size());
            }
            
        } catch (const std::exception& e) {
            std::cout << handlers::Theme::STRUCTURE << "[" << handlers::Theme::ERROR << "DB Error" << handlers::Theme::STRUCTURE << "] " << handlers::Theme::RESET 
                      << "Python/Engine Error: " << e.what() << "\r\n" << std::flush;
        }
    }

    void Engine::deploy_remote_db_handler() {
        if (remote_db_deployed_ || !is_remote_session_) return;
        // Note: For remote sessions, is_shell_idle() is false (SSH is running).        
        std::string script_content;
        try {
            py::module_ inspect = py::module_::import("inspect");
            py::module_ handler = py::module_::import("db_handler");
            script_content = inspect.attr("getsource")(handler).cast<std::string>();
        } catch (const std::exception& e) {
            return; // Can't deploy if we can't read it
        }

        // 2. Prepare Remote Paths
        std::string b64 = base64_encode((const unsigned char*)script_content.data(), script_content.size());
        
        std::string temp_b64 = "~/.dais/bin/db_handler.py.b64";
        std::string target_path = "~/.dais/bin/db_handler.py";

        // 3. Inject (Silent Streaming)
        // Prevent history pollution by disabling history for this block
        // Also suppress PS2 to prevent '> >' echo artifacts during heredoc
        execute_remote_command("export DAIS_OLD_PS2=\"$PS2\"; export PS2=''; set +o history", 2000); 
        execute_remote_command("mkdir -p -m 700 ~/.dais/bin", 2000);
        execute_remote_command("rm -f " + temp_b64, 2000);
        execute_remote_command("stty -echo", 2000);

        std::string start_heredoc = "cat > " + temp_b64 + " << 'DAIS_EOF'\n";
        write(pty_.get_master_fd(), start_heredoc.c_str(), start_heredoc.size());

        constexpr size_t PAYLOAD_CHUNK = 4096;
        size_t sent = 0;
        while (sent < b64.size()) {
            size_t n = std::min(PAYLOAD_CHUNK, b64.size() - sent);
            write(pty_.get_master_fd(), b64.data() + sent, n);
            sent += n;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        std::string end_heredoc = "\nDAIS_EOF\n";
        write(pty_.get_master_fd(), end_heredoc.c_str(), end_heredoc.size());
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        execute_remote_command("stty echo", 2000);

        // 4. Decode
        std::string deploy_cmd = 
            "base64 -d " + temp_b64 + " > " + target_path + " && "
            "rm " + temp_b64 + " && "
            "export PS2=\"$DAIS_OLD_PS2\"; unset DAIS_OLD_PS2; set -o history && " // Re-enable history & prompts
            "echo DAIS_DEPLOY_OK";

        std::string result = execute_remote_command(deploy_cmd, 5000);
        
        if (result.find("DAIS_DEPLOY_OK") != std::string::npos) {
            remote_db_deployed_ = true;
        }
    }

    bool Engine::check_and_offer_less_install() {
        // Only check once per session
        if (less_checked_) {
            return less_available_;
        }
        less_checked_ = true;

        // Check if less is available
        std::string check_result = execute_remote_command("command -v less >/dev/null 2>&1 && echo LESS_OK || echo LESS_MISSING", 2000);
        
        if (check_result.find("LESS_OK") != std::string::npos) {
            less_available_ = true;
            return true;
        }

        // Less is not available - show one-time info message (non-interactive)
        std::cout << "\r\n[" << handlers::Theme::LOGO << "DB" << handlers::Theme::RESET 
                  << "] 'less' pager not found. Using raw output. Install 'less' for pagination.\r\n" << std::flush;
        
        less_available_ = false;
        return false;
    }

    /**
     * @brief Calculates the visual width of a string by stripping ANSI escape codes.
     */
    int Engine::calculate_visual_length(const std::string& buffer) {
        int length = 0;
        int state = 0; // 0=text, 1=ESC, 2=CSI, 3=OSC
        for (size_t i = 0; i < buffer.size(); ++i) {
            char c = buffer[i];
            if (state == 0) {
                if (c == '\r' || c == '\n') {
                    length = 0;
                } else if (c == '\b') {
                    if (length > 0) length--;
                } else if (c == '\x1b') {
                    state = 1;
                } else if (std::isprint(static_cast<unsigned char>(c))) {
                    length++;
                }
            } else if (state == 1) { // After ESC
                if (c == '[') state = 2; // CSI
                else if (c == ']') state = 3; // OSC
                else state = 0; // 1-char sequence (or unknown)
            } else if (state == 2) { // CSI
                if (c >= 0x40 && c <= 0x7E) state = 0; // Terminator
            } else if (state == 3) { // OSC
                if (c == '\x07' || c == '\x1b') state = 0; // Bell or start of ST
            }
        }
        return length;
    }

    /**
     * @brief Navigates the cursor in 2D space, handling line wraps.
     * Uses CHA (Cursor Horizontal Absolute) and CUU/CUD (Up/Down) sequences.
     */
    void Engine::visual_move_cursor(int old_pos, int new_pos) {
        if (old_pos == new_pos) return;
        std::lock_guard<std::recursive_mutex> terminal_lock(terminal_mutex_);

        int width = terminal_cols_.load();
        if (width <= 0) width = 80;

        // Calculate absolute 1D positions relative to the start of the prompt
        int old_abs = initial_prompt_cols_ + old_pos;
        int new_abs = initial_prompt_cols_ + new_pos;

        int old_row = old_abs / width;
        int new_row = new_abs / width;
        int new_col = new_abs % width;

        // 1. Vertical Movement
        if (new_row < old_row) {
            for (int i = 0; i < (old_row - new_row); ++i) write(STDOUT_FILENO, "\x1b[A", 3);
        } else if (new_row > old_row) {
            for (int i = 0; i < (new_row - old_row); ++i) write(STDOUT_FILENO, "\x1b[B", 3);
        }

        // 2. Horizontal Movement (CHA - Cursor Horizontal Absolute, 1-indexed)
        std::string move_to_col = "\x1b[" + std::to_string(new_col + 1) + "G";
        write(STDOUT_FILENO, move_to_col.c_str(), move_to_col.size());
    }

    /**
     * @brief Consolidates visual mode initialization logic.
     * Captures the visual prompt width once when a command session starts.
     */
    void Engine::ensure_visual_mode_init(int offset_already_in_buffer) {
        if (was_visual_mode_) return;
        std::lock_guard<std::recursive_mutex> terminal_lock(terminal_mutex_);
            std::lock_guard<std::mutex> lock(prompt_mutex_);
            // 1. Calculate the total visual length of the current line (from shell echo)
            int shelf_width = calculate_visual_length(prompt_buffer_);
            
            // 2. Subtract any command characters ALREADY in prompt_buffer_
            initial_prompt_cols_ = shelf_width - offset_already_in_buffer;
            if (initial_prompt_cols_ < 0) initial_prompt_cols_ = 0;

            // Account for Logo if it was visually injected on the current line
            if (!at_line_start_ && config_.show_logo) {
                initial_prompt_cols_ += 4; // Length of "[-] "
            }
            was_visual_mode_ = true;
    }
}

