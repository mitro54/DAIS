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

        // Spawn the output reader thread (Child -> Screen)
        std::thread output_thread(&Engine::forward_shell_output, this);

        // Run the input processing loop (Keyboard -> Child) in the main thread
        process_user_input();

        // Cleanup
        if (output_thread.joinable()) output_thread.join();
        
        waitpid(pty_.get_child_pid(), nullptr, 0);
        pty_.stop();
        
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

        while (true) {
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
                
                // --- LOOK-AHEAD PROMPT DETECTION ---
                // Check if this buffer contains a prompt BEFORE processing characters.
                // This allows shell_state_ to be IDLE when we reach the line start.
                std::string buffer_str(buffer.data(), bytes_read);
                for (const auto& prompt : config_.shell_prompts) {
                    if (buffer_str.size() >= prompt.size() &&
                        buffer_str.find(prompt) != std::string::npos) {
                        // Buffer contains a prompt - mark as IDLE
                        // Also check that shell process is actually foreground
                        if (pty_.is_shell_idle()) {
                            shell_state_ = ShellState::IDLE;
                        }
                        break;
                    }
                }
                
                for (ssize_t i = 0; i < bytes_read; ++i) {
                    char c = buffer[i];
                    
                    // Shell-Specific Logo Injection Strategy:
                    //
                    // Fish: Prompt rendering is too complex (RPROMPT, dynamic redraws).
                    //       Skip pass-through logo injection entirely.
                    //
                    // Zsh: Uses ANSI escape sequences heavily. Use state machine to track
                    //      sequences and only inject when fully outside a sequence.
                    //
                    // Bash/Sh: Simpler prompts. Inject immediately at line start.
                    
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
                        } else if (at_line_start_ && config_.show_logo && shell_state_ == ShellState::IDLE && pty_.is_shell_idle()) {
                            // Inject logo at line start when shell is idle
                            // Note: Don't skip spaces - they may be part of multi-line prompt formatting
                            if (c >= 33 && c < 127) {
                                std::string logo_str = handlers::Theme::RESET + "[" + handlers::Theme::LOGO + "-" + handlers::Theme::RESET + "] ";
                                write(STDOUT_FILENO, logo_str.c_str(), logo_str.size());
                                at_line_start_ = false;
                            }
                        }
                    } else if (!is_complex_shell_) {
                        // Simple shells: inject immediately
                        if (at_line_start_) {
                            if (c != '\n' && c != '\r' && config_.show_logo && shell_state_ == ShellState::IDLE && pty_.is_shell_idle()) {
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
                    // This is critical for the recovery logic to see Esc, Backspace, etc.
                    if (true) { 
                        std::lock_guard<std::mutex> lock(prompt_mutex_);
                        prompt_buffer_ += c;
                        if (prompt_buffer_.size() > 1024) {
                            prompt_buffer_ = prompt_buffer_.substr(prompt_buffer_.size() - 1024);
                        }
                        
                        // PAGER DETECTION: Set flag when "--More--" appears in buffer
                        // This is more reliable than checking in process_user_input
                        // because it's set synchronously as output is processed.
                        if (prompt_buffer_.find("--More--") != std::string::npos) {
                            in_more_pager_ = true;
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
                            shell_state_ = ShellState::IDLE;
                            break;
                        }
                    }
                }
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

        std::string cmd_accumulator;

        while (running_) {
            int ret = poll(&pfd, 1, -1);

            if (ret < 0) {
                if (errno == EINTR) continue; // Signal interrupted, keep going
                break;
            }

            if (pfd.revents & POLLIN) {
                ssize_t n = read(STDIN_FILENO, buffer.data(), buffer.size());
                if (n <= 0) break;

                std::string data_to_write;
                data_to_write.reserve(n + 8);

                // Process char-by-char to build command string
                for (ssize_t i = 0; i < n; ++i) {
                    char c = buffer[i];

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
                            
                            // Intercept arrows for DAIS history navigation ONLY for local sessions
                            // Remote sessions use the shell's own history (forwarded arrows)
                            if ((arrow == 'A' || arrow == 'B') && 
                                pty_.is_shell_idle() && 
                                elapsed > 200) {
                                // Safe to intercept for DAIS history
                                int direction = (arrow == 'A') ? -1 : 1;
                                navigate_history(direction, cmd_accumulator);
                                i += 2;  // Skip '['/O' and arrow letter
                                continue;  // Don't forward to shell
                            }
                            
                            // --- LEFT/RIGHT ARROW SYNC ---
                            // If user presses Left (D) or Right (C) after history navigation,
                            // sync history content to shell first so cursor movement works.
                            if ((arrow == 'C' || arrow == 'D') && 
                                history_navigated_ && pty_.is_shell_idle() && 
                                !cmd_accumulator.empty() && !cmd_accumulator.starts_with(":")) {
                                // Move cursor left by command length, then clear to end (preserves prompt)
                                std::cout << "\x1b[" << cmd_accumulator.size() << "D\x1b[K" << std::flush;
                                
                                // Sync shell: clear line and send accumulated content
                                const char kill_line = kCtrlU;
                                write(pty_.get_master_fd(), &kill_line, 1);
                                write(pty_.get_master_fd(), cmd_accumulator.c_str(), cmd_accumulator.size());
                                
                                // Reset flag - now shell has content and arrow will work
                                history_navigated_ = false;
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
                        cmd_accumulator.clear();
                        tab_used_ = false;
                        data_to_write += c;
                        continue;
                    }

                    // --- SMART INTERCEPTION ---
                    // Only process DAIS commands when at shell prompt (IDLE state)
                    
                    // Check for Enter key (\r or \n) indicating command submission
                    if (c == '\r' || c == '\n') {
                         
                        // --- REMOTE INTERCEPTION AT ENTER ---
                        // For remote sessions, we catch commands here (at Enter key) 
                        // so users can type full arguments before we execute.
                        // SYNC FIX: Always check remote session state before interception
                        // to ensure is_remote_session_ is current (fixes history recall issues).
                        check_remote_session();
                        
                        if (!pty_.is_shell_idle() && is_remote_session_) {
                            // RECOVERY: If cmd_accumulator is empty or contains tab noise,
                            // we try to recover the actual visual line from prompt_buffer_.
                            // This is critical for history navigation (Up-Arrow), where
                            // characters come from the shell, not the keyboard.
                            std::string recovered;
                            {
                                std::lock_guard<std::mutex> lock(prompt_mutex_);
                                recovered = recover_cmd_from_buffer(prompt_buffer_);
                            }
                            
                            // Use recovered if available and:
                            // - cmd_accumulator is empty
                            // - cmd_accumulator contains tab noise
                            // - tab was used (shell has the expanded path, we don't)
                            // NOTE: Don't use is_remote_session_ here - prompt_buffer can be stale
                            std::string clean = cmd_accumulator;
                            if (clean.empty() || clean.find('\t') != std::string::npos || tab_used_) {
                                if (!recovered.empty()) clean = recovered;
                            }

                            // Trim leading/trailing whitespace
                            if (clean.find_first_not_of(" \t\r\n") != std::string::npos) {
                                clean.erase(0, clean.find_first_not_of(" \t\r\n"));
                            }
                            if (clean.find_last_not_of(" \t\r\n") != std::string::npos) {
                                clean.erase(clean.find_last_not_of(" \t\r\n") + 1);
                            }

                            bool intercept = false;
                            
                            // Check for DB command
                            if (clean.starts_with(":db")) {
                                // Save to local history ONLY if local session
                                // For remote sessions, we inject into remote shell history instead
                                if (!is_remote_session_) {
                                    save_history_entry(clean);
                                    history_index_ = command_history_.size();
                                }

                                std::string query = clean.length() > 3 ? clean.substr(4) : "";
                                
                                // CLEAR REMOTE LINE: Send Ctrl+U to remote to wipe the "echo"
                                const char kill_line = kCtrlU; 
                                write(pty_.get_master_fd(), &kill_line, 1);

                                // Inject into remote history so it's 'up-arrowable'
                                // REORDER FIX: We MUST inject history before running the command.
                                // Why? execute_remote_command() enables capture_mode_ (swallows output).
                                // If we run handle_db_command() first, it starts the 'less' process which streams output.
                                // Then execute_remote_command() runs and effectively mutes that output.
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

                                handle_db_command(query);

                                intercept = true;
                            }
                            // Check for Help command
                            else if (clean == ":help") {
                                // Save to local history immediately
                                save_history_entry(clean);
                                history_index_ = command_history_.size();

                                // CLEAR REMOTE LINE
                                const char kill_line = kCtrlU; 
                                write(pty_.get_master_fd(), &kill_line, 1);
                                
                                std::cout << "\r\n" << get_help_text() << std::flush;

                                // Inject into remote history
                                std::string escaped = clean;
                                size_t p = 0;
                                while ((p = escaped.find("\"", p)) != std::string::npos) {
                                    escaped.replace(p, 1, "\\\"");
                                    p += 2;
                                }
                                std::string inject = "{ history -s \"" + escaped + "\" 2>/dev/null || print -s \"" + escaped + "\" 2>/dev/null; }";
                                execute_remote_command(inject, 2000);

                                intercept = true;
                            }
                            // Check for LS customization command
                            else if (clean.starts_with(":ls")) {
                                // Save to local history immediately
                                save_history_entry(clean);
                                history_index_ = command_history_.size();

                                std::string args = clean.length() > 3 ? clean.substr(4) : "";
                                
                                // CLEAR REMOTE LINE
                                const char kill_line = kCtrlU; 
                                write(pty_.get_master_fd(), &kill_line, 1);

                                if (args.empty()) {
                                    std::string msg = "\r\n[LS Customization]\r\n";
                                    msg += "Sort By: " + config_.ls_sort_by + "\r\n";
                                    msg += "Order: " + config_.ls_sort_order + "\r\n";
                                    msg += "Dirs First: " + std::to_string(config_.ls_dirs_first) + "\r\n";
                                    msg += "[USAGE] :ls [name|size|type|rows] [asc|desc]\r\n";
                                    write(STDOUT_FILENO, msg.c_str(), msg.size());
                                } else {
                                    std::stringstream ss(args);
                                    std::string segment;
                                    while (ss >> segment) {
                                        if (segment == "d" || segment == "default") {
                                            config_.ls_sort_by = "type";
                                            config_.ls_sort_order = "asc";
                                            config_.ls_dirs_first = true;
                                        } 
                                        else if (segment == "size") config_.ls_sort_by = "size";
                                        else if (segment == "name") config_.ls_sort_by = "name";
                                        else if (segment == "type") config_.ls_sort_by = "type";
                                        else if (segment == "rows") config_.ls_sort_by = "rows";
                                        else if (segment == "asc") config_.ls_sort_order = "asc";
                                        else if (segment == "desc") config_.ls_sort_order = "desc";
                                    }
                                    
                                    std::string confirm = "\r\nUpdated: Sort=" + config_.ls_sort_by + " Order=" + config_.ls_sort_order + "\r\n";
                                    write(STDOUT_FILENO, confirm.c_str(), confirm.size());
                                }

                                // Inject into remote history
                                std::string escaped = clean;
                                size_t p = 0;
                                while ((p = escaped.find("\"", p)) != std::string::npos) {
                                    escaped.replace(p, 1, "\\\"");
                                    p += 2;
                                }
                                std::string inject = "{ history -s \"" + escaped + "\" 2>/dev/null || print -s \"" + escaped + "\" 2>/dev/null; }";
                                execute_remote_command(inject, 2000);

                                intercept = true;
                            }
                            // Check for standard ls (intercept and use agent)
                            else if (clean == "ls" || clean.starts_with("ls ")) {
                                auto ls_args = handlers::parse_ls_args(clean);
                                if (ls_args.supported) {
                                    handle_remote_ls(ls_args, clean);
                                    intercept = true;
                                }
                                // If not supported (e.g. ls -t), fall through to normal remote execution
                            }

                            if (intercept) {
                                cmd_accumulator.clear();
                                {
                                    std::lock_guard<std::mutex> lock(prompt_mutex_);
                                    // Don't clear prompt_buffer_ here, handled naturally by newlines
                                }
                                // NOTE: Don't send extra newline here - the injected command already has one
                                // Sending another causes double prompts
                                continue; // Skip sending the actual Enter key to remote
                            }
                        }

                        // --- SYNC SHELL WITH VISUAL STATE ---
                        // Only sync when user actually navigated history (changes were visual-only).
                        // Skip for internal commands (:) which are handled separately.
                        if (history_navigated_ && pty_.is_shell_idle() && !cmd_accumulator.empty() && 
                            !cmd_accumulator.starts_with(":")) {
                            // Move cursor left by command length, then clear to end (preserves prompt)
                            std::cout << "\x1b[" << cmd_accumulator.size() << "D\x1b[K" << std::flush;
                            
                            // Sync: clear shell's empty line and send command
                            const char kill_line = kCtrlU;  // Ctrl+U
                            write(pty_.get_master_fd(), &kill_line, 1);
                            write(pty_.get_master_fd(), cmd_accumulator.c_str(), cmd_accumulator.size());
                        }
                        history_navigated_ = false;  // Reset flag
                        
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
                        if (pty_.is_shell_idle()) {
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
                                    // Send Ctrl+U (clear line) to cancel it, then newline for fresh prompt.
                                    char clear_and_prompt[] = { kCtrlU, '\n', 0 }; // Ctrl+U + newline
                                    write(pty_.get_master_fd(), clear_and_prompt, 2);
                                    
                                    // Clear accumulator and skip writing command to PTY
                                    cmd_accumulator.clear();
                                    tab_used_ = false;
                                    at_line_start_ = false; // Prompt will handle this
                                        continue; // Skip the normal PTY write below
                                    }
                                } // End Local Logic
                            }

                            // 2. Internal Exit Commands
                            if (cmd_accumulator == ":q" || cmd_accumulator == ":exit") {
                                running_ = false;
                                kill(pty_.get_child_pid(), SIGHUP);
                                return;
                            }

                            // 3. LS Sort Configuration Commands
                            if (cmd_accumulator.starts_with(":ls")) {
                                std::string args = cmd_accumulator.substr(3);
                                // Trim leading whitespace
                                size_t start = args.find_first_not_of(' ');
                                if (start != std::string::npos) args = args.substr(start);
                                else args.clear();
                                
                                std::string msg;
                                if (args.empty()) {
                                    // Show current settings
                                    msg = "ls: by=" + config_.ls_sort_by + 
                                          ", order=" + config_.ls_sort_order + 
                                          ", dirs_first=" + (config_.ls_dirs_first ? "true" : "false") +
                                          ", flow=" + config_.ls_flow;
                                } else if (args == "d") {
                                    // Reset to defaults
                                    config_.ls_sort_by = "type";
                                    config_.ls_sort_order = "asc";
                                    config_.ls_dirs_first = true;
                                    config_.ls_flow = "h";
                                    msg = "ls: by=type, order=asc, dirs_first=true, flow=h (defaults)";
                                } else {
                                    // Flexible parsing: iterate over all parts and match keywords
                                    std::vector<std::string> parts;
                                    std::string part;
                                    for (char ch : args) {
                                        if (ch == ' ' || ch == ',') {
                                            if (!part.empty()) { parts.push_back(part); part.clear(); }
                                        } else {
                                            part += ch;
                                        }
                                    }
                                    if (!part.empty()) parts.push_back(part);
                                    
                                    for (const auto& p : parts) {
                                        // 1. Sort By
                                        if (p == "name" || p == "size" || p == "type" || p == "rows" || p == "none") {
                                            config_.ls_sort_by = p;
                                        }
                                        // 2. Sort Order
                                        else if (p == "asc" || p == "desc") {
                                            config_.ls_sort_order = p;
                                        }
                                        // 3. Dirs First
                                        else if (p == "true" || p == "1") {
                                            config_.ls_dirs_first = true;
                                        }
                                        else if (p == "false" || p == "0") {
                                            config_.ls_dirs_first = false;
                                        }
                                        // 4. Flow Direction
                                        else if (p == "h" || p == "horizontal") {
                                            config_.ls_flow = "h";
                                        }
                                        else if (p == "v" || p == "vertical") {
                                            config_.ls_flow = "v";
                                        }
                                    }
                                    
                                    msg = "ls: by=" + config_.ls_sort_by + 
                                          ", order=" + config_.ls_sort_order + 
                                          ", dirs_first=" + (config_.ls_dirs_first ? "true" : "false") +
                                          ", flow=" + config_.ls_flow;
                                }
                                
                                // Print feedback and new prompt
                                std::cout << "\r\n[" << handlers::Theme::NOTICE << "-" << handlers::Theme::RESET 
                                          << "] " << msg << "\r\n" << std::flush;
                                
                                cmd_accumulator.clear();
                                // Send just newline to trigger a new prompt
                                write(pty_.get_master_fd(), "\n", 1);
                                continue;
                            }
                            
                            // 4. History Command
                            // :history       - Show last 20 commands
                            // :history N     - Show last N commands
                            // :history clear - Clear all history
                            if (cmd_accumulator.starts_with(":history")) {
                                std::string args = cmd_accumulator.length() > 8 
                                    ? cmd_accumulator.substr(9) : "";
                                // Trim leading space
                                if (!args.empty() && args[0] == ' ') args = args.substr(1);
                                
                                show_history(args);
                                
                                cmd_accumulator.clear();
                                write(pty_.get_master_fd(), "\n", 1);
                                continue;
                            }
                            
                            // 5. Help Command
                            // :help - Show all available DAIS commands
                            if (cmd_accumulator == ":help") {
                                std::cout << "\r\n" << get_help_text() << std::flush;
                                
                                cmd_accumulator.clear();
                                write(pty_.get_master_fd(), "\n", 1);
                                continue;
                            }

                            // 6. DB Command
                            // :db <query> or :db <saved_query_key>
                            if (cmd_accumulator.starts_with(":db")) {
                                std::string query = cmd_accumulator.length() > 3 
                                    ? cmd_accumulator.substr(4) : "";
                                
                                sync_child_cwd(); // Ensure we use the freshly updated CWD
                                handle_db_command(query);
                                
                                cmd_accumulator.clear();
                                write(pty_.get_master_fd(), "\n", 1);
                                continue;
                            }
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
                        if (!pty_.is_shell_idle() && is_remote_session_) {
                            // 2. Internal Exit Commands (Remote Context)
                            // Allows cleanly exiting DAIS even if trapped in SSH
                            if (cmd_accumulator == ":q" || cmd_accumulator == ":exit") {
                                // "Graceful" kill of the whole DAIS session
                                running_ = false;
                                kill(pty_.get_child_pid(), SIGHUP); 
                                return;
                            }
                        }

                        trigger_python_hook("on_command", cmd_accumulator);
                        cmd_accumulator.clear();
                        tab_used_ = false;  // Reset for next command
                        data_to_write += c;
                    }
                    // Handle Backspace
                    else if (c == 127 || c == '\b') {
                        // ADOPTION: If cmd_accumulator is empty, we might be editing a command 
                        // pulled from the shell's native history (Up-Arrow). 
                        // We try to recover it so we can keep edits within DAIS.
                        if (cmd_accumulator.empty()) {
                            std::lock_guard<std::mutex> lock(prompt_mutex_);
                            std::string recovered = recover_cmd_from_buffer(prompt_buffer_);
                            if (recovered.starts_with(":")) {
                                cmd_accumulator = recovered;
                            }
                        }

                        // --- HISTORY EDITING SYNC (same as printable chars) ---
                        // If user starts editing after history navigation (local shell),
                        // sync the history content to shell first, then allow normal editing.
                        if (history_navigated_ && pty_.is_shell_idle() && !cmd_accumulator.empty() &&
                            !cmd_accumulator.starts_with(":")) {
                            // Move cursor left by command length, then clear to end (preserves prompt)
                            std::cout << "\x1b[" << cmd_accumulator.size() << "D\x1b[K" << std::flush;
                            
                            // Sync shell: clear line and send accumulated content
                            const char kill_line = kCtrlU;
                            write(pty_.get_master_fd(), &kill_line, 1);
                            write(pty_.get_master_fd(), cmd_accumulator.c_str(), cmd_accumulator.size());
                            
                            // Reset flag - subsequent edits go directly to shell
                            history_navigated_ = false;
                        }

                        // Check if we are in a DAIS command (: commands stay visual)
                        bool starts_with_colon = !cmd_accumulator.empty() && cmd_accumulator[0] == ':';
                        bool visual_mode = (pty_.is_shell_idle() && starts_with_colon) || 
                                           (!pty_.is_shell_idle() && is_remote_session_ && starts_with_colon);
                        
                        if (!cmd_accumulator.empty()) {
                            cmd_accumulator.pop_back();
                            if (visual_mode) {
                                std::cout << "\b \b" << std::flush;
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
                            std::lock_guard<std::mutex> lock(prompt_mutex_);
                            std::string recovered = recover_cmd_from_buffer(prompt_buffer_);
                            if (recovered.starts_with(":")) {
                                cmd_accumulator = recovered;
                            }
                        }

                        // --- HISTORY EDITING SYNC ---
                        // If user starts typing after history navigation (local shell),
                        // sync the history content to shell first, then allow normal typing.
                        // This enables editing history commands instead of being stuck in visual mode.
                        if (history_navigated_ && pty_.is_shell_idle() && !cmd_accumulator.empty() &&
                            !cmd_accumulator.starts_with(":")) {
                            // Move cursor left by command length, then clear to end (preserves prompt)
                            std::cout << "\x1b[" << cmd_accumulator.size() << "D\x1b[K" << std::flush;
                            
                            // Sync shell: clear line and send accumulated content
                            // Shell will redraw after Ctrl-U
                            const char kill_line = kCtrlU;
                            write(pty_.get_master_fd(), &kill_line, 1);
                            write(pty_.get_master_fd(), cmd_accumulator.c_str(), cmd_accumulator.size());
                            
                            // Reset flag - subsequent chars go directly to shell
                            history_navigated_ = false;
                        }

                        // Track input if shell is idle OR if we are in a remote session 
                        // (needed for :db interception in SSH)
                        bool starts_with_colon = !cmd_accumulator.empty() && cmd_accumulator[0] == ':';
                        if (pty_.is_shell_idle() || is_remote_session_ || c == ':') {
                            cmd_accumulator += c;
                            // Update starts_with_colon after adding char
                            if (cmd_accumulator.size() == 1 && c == ':') starts_with_colon = true;
                        }
                        
                        // Visual-only mode: DAIS commands (:) only
                        // History editing now syncs shell above, so we only stay visual for : commands
                        bool visual_mode = (pty_.is_shell_idle() && starts_with_colon) || 
                                           (!pty_.is_shell_idle() && is_remote_session_ && starts_with_colon);
                        
                        if (visual_mode) {
                            std::cout << c << std::flush;
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
    


    // =========================================================================
    // COMMAND HISTORY (File-Based)
    // =========================================================================

    // COMMAND HISTORY (File-Based)
    // =========================================================================

    void Engine::handle_remote_ls(const handlers::LSArgs& ls_args, const std::string& original_cmd) {
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
            std::string agent_cmd = "./.dais/bin/agent_" + (remote_arch_.empty() ? "x86_64" : remote_arch_);
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
        size_t bracket = json_out.find('[');
        bool valid_json = !json_out.empty() && bracket != std::string::npos;
        
        if (valid_json) {
            json_out = json_out.substr(bracket);
        }
        
        // 6. Fallback Behavior
        if (!remote_agent_deployed_ && !valid_json) {
            // Restore original command to shell (Native LS)
            // No error message, just let standard ls run
            write(pty_.get_master_fd(), "ls\n", 3); // Simple restore
            return; 
        }
        
        // 7. Render
        if (valid_json) {
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
            
            std::string output = handlers::render_remote_ls(json_out, formats, sort_cfg, config_.ls_padding);
            
            if (!output.empty()) {
                write(STDOUT_FILENO, "\r\n", 2);
                write(STDOUT_FILENO, output.c_str(), output.size());
            } 
            // else: Valid JSON but empty content (empty dir or error caught in python). 
            // Be silent like native ls.
        } else {
            std::string logo = handlers::Theme::STRUCTURE + "[" + handlers::Theme::WARNING + "-" + handlers::Theme::STRUCTURE + "]" + handlers::Theme::RESET + " ";
            std::string err = "\r\n" + logo + "Remote execution timed out.\r\n";
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
     * @return The cleaned command string, or empty if prompt not found.
     */
    std::string Engine::recover_cmd_from_buffer(const std::string& buffer) {
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
                if (isalpha(c)) { 
                    // End of CSI
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
                                 for (size_t k = 0; k <= cursor; ++k) clean_line[k] = ' ';
                             }
                        }
                        // 2: Clear entire line
                        else if (csi_seq == "2") {
                            // If cursor > 0, we must preserve 'cursor' position by padding with spaces if we clear?
                            clean_line.clear();
                            if (cursor > 0) clean_line.resize(cursor, ' ');
                        }
                    }
                    else if (c == 'A') {
                        // Cursor Up - ignore for single line simulation? 
                        // Or treating as simple buffer, maybe no-op since we only care about current line content?
                    }
                    else if (c == 'B') {
                        // Cursor Down - ignore
                    }
                    else if (c == 'C') {
                        // Cursor Forward (Right)
                        int n = (csi_seq.empty()) ? 1 : std::stoi(csi_seq);
                        cursor += n;
                        // Pad with spaces if moved beyond current length
                        if (cursor > clean_line.size()) {
                            clean_line.resize(cursor, ' ');
                        }
                    }
                    else if (c == 'D') {
                        // Cursor Back (Left)
                        int n = (csi_seq.empty()) ? 1 : std::stoi(csi_seq);
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
        
        // 3. Extract command
        if (best_pos != std::string::npos) {
            std::string recovered = clean_line.substr(best_pos + prompt_len);
            
            // Trim leading/trailing whitespace
            const char* ws = " \t\r\n";
            recovered.erase(0, recovered.find_first_not_of(ws));
            if (recovered.find_last_not_of(ws) != std::string::npos)
                recovered.erase(recovered.find_last_not_of(ws) + 1);
            
            // DEEP CLEAN: Strip any remaining non-printable chars (e.g. malformed ANSI leftovers)
            // This is critical for SSH history where syntax highlighting might leak through
            std::string deep_clean;
            for (char c : recovered) {
                if (std::isprint(static_cast<unsigned char>(c))) {
                    deep_clean += c;
                }
            }
            if (!deep_clean.empty()) recovered = deep_clean;

            return recovered;
        }

        return "";
    }

    void Engine::check_remote_session() {
        std::string fg = pty_.get_foreground_process_name();
        
        bool was = is_remote_session_;
        
        // Simple heuristic: if foreground process contains "ssh", assume remote.
        // Note: This covers "ssh", "/usr/bin/ssh", etc.
        is_remote_session_ = (fg.find("ssh") != std::string::npos);
        
        if (is_remote_session_ && !was) {
             // New session detected - reset deployment state
             remote_agent_deployed_ = false;
             remote_db_deployed_ = false; // Reset DB handler too
             remote_arch_ = "";
             
             // Trigger auto-deployment immediately if shell is idle
             if (pty_.is_shell_idle()) {
                 deploy_remote_agent();
                 deploy_remote_db_handler();
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
        if (!pty_.is_shell_idle()) return;
        
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

        // 3. Inject Binary (Silent Streaming Upload)
        // 1. Disable Echo (stty -echo) to prevent 1.5MB of base64 from spamming the user's terminal
        // 2. Stream Heredoc
        // 3. Re-enable Echo (stty echo)
        
        std::string b64 = base64_encode(agent.data, agent.size);
        std::string temp_b64 = ".dais/bin/agent_" + remote_arch_ + ".b64";
        std::string target_path = ".dais/bin/agent_" + remote_arch_;
        
        // Ensure directory exists
        execute_remote_command("mkdir -p .dais/bin", 2000);
        execute_remote_command("rm -f " + temp_b64, 2000); 

        // Disable Echo
        execute_remote_command("stty -echo", 2000);

        // Start Heredoc - use single quotes 'DAIS_EOF' to prevent shell expansion
        std::string start_heredoc = "cat > " + temp_b64 + " << 'DAIS_EOF'\n";
        write(pty_.get_master_fd(), start_heredoc.c_str(), start_heredoc.size());
        
        // Stream Data
        constexpr size_t PAYLOAD_CHUNK = 4096;
        size_t sent = 0;
        
        while (sent < b64.size()) {
            size_t n = std::min(PAYLOAD_CHUNK, b64.size() - sent);
            write(pty_.get_master_fd(), b64.data() + sent, n);
            sent += n;
            // Tiny sleep to prevent kernel/remote buffer overflow on fast local systems
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        
        // End Heredoc - ensure it's on a clean new line
        std::string end_heredoc = "\nDAIS_EOF\n";
        write(pty_.get_master_fd(), end_heredoc.c_str(), end_heredoc.size());
        
        // Wait a moment for shell to finalize the file write
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
        } else {
            // Failed
            if (config_.show_logo) {
                std::string logo = handlers::Theme::STRUCTURE + "[" + handlers::Theme::WARNING + "-" + handlers::Theme::STRUCTURE + "]" + handlers::Theme::RESET + " ";
                std::cout << "\r\n" << logo << "Agent deployment failed. Falling back to Python (slower).\r\n";
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
        // DON'T send to shell - just update the display locally.
        // We'll sync with shell when user actually presses Enter.
        // This avoids race conditions with apps like vim.
        
        // Move cursor to start of current input and clear
        // First, move back by current_line length
        if (!current_line.empty()) {
            // Move cursor left by current_line.size()
            std::string move_back = "\x1b[" + std::to_string(current_line.size()) + "D";
            write(STDOUT_FILENO, move_back.c_str(), move_back.size());
            // Clear from cursor to end of line
            write(STDOUT_FILENO, "\x1b[K", 3);
        }
        
        // Write new content
        if (!new_content.empty()) {
            write(STDOUT_FILENO, new_content.c_str(), new_content.size());
        }
        
        // Update internal state - shell will see this when Enter is pressed
        current_line = new_content;
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
        if (query.empty()) {
            std::cout << "\r\n[" << handlers::Theme::WARNING << "-" << handlers::Theme::RESET 
                      << "] Usage: :db <sql_query> OR :db <saved_query_name>\r\n" << std::flush;
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

                std::cout << "\r\n[" << handlers::Theme::WARNING << "-" << handlers::Theme::RESET 
                          << "] Missing package '" << pkg << "' on " << location << ". Install now"
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
                std::cout << "\r\n[" << handlers::Theme::ERROR << "DB" << handlers::Theme::RESET 
                          << "] " << msg << "\r\n" << std::flush;
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
            std::cout << "\r\n[" << handlers::Theme::ERROR << "DB" << handlers::Theme::RESET 
                      << "] Python/Engine Error: " << e.what() << "\r\n" << std::flush;
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
        execute_remote_command("mkdir -p ~/.dais/bin", 2000);
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
}

