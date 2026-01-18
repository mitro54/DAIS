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
#include <thread>
#include <array>
#include <string>
#include <iostream> // Needed for std::cout, std::cerr
#include <fstream>  // Needed for std::ofstream, std::ifstream
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

                // --- PASS-THROUGH MODE ---
                // Forward shell output to terminal with optional logo injection.
                // Uses class members prompt_buffer_ and pass_through_esc_state_ for state.
                
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
                            if (c == '\x07') pass_through_esc_state_ = 0;
                        } else if (pass_through_esc_state_ == 4) {
                            pass_through_esc_state_ = 0;
                        } else if (c == '\x1b') {
                            pass_through_esc_state_ = 1;
                        } else if (at_line_start_ && config_.show_logo && pty_.is_shell_idle()) {
                            // Zsh (and some others) may output a leading space or carriage return 
                            // for alignment purposes, especially with right-prompt setups.
                            // Skipping these ensures our injected logo appears *before* visible content.
                            if (c == ' ') {
                                continue;
                            }
                            if (c >= 33 && c < 127) {
                                std::string logo_str = handlers::Theme::RESET + "[" + handlers::Theme::LOGO + "-" + handlers::Theme::RESET + "] ";
                                write(STDOUT_FILENO, logo_str.c_str(), logo_str.size());
                                at_line_start_ = false;
                            }
                        }
                    } else if (!is_complex_shell_) {
                        // Simple shells: inject immediately
                        if (at_line_start_) {
                            if (c != '\n' && c != '\r' && config_.show_logo && pty_.is_shell_idle()) {
                                std::string logo_str = handlers::Theme::RESET + "[" + handlers::Theme::LOGO + "-" + handlers::Theme::RESET + "] ";
                                write(STDOUT_FILENO, logo_str.c_str(), logo_str.size());
                                at_line_start_ = false;
                            }
                        }
                    }
                    
                    write(STDOUT_FILENO, &c, 1);
                    
                    if (c == '\n') {
                        at_line_start_ = true;
                        prompt_buffer_.clear();
                    } else if (c == '\r') {
                        // For complex shells, \r means "back to line start"
                        // For simple shells, \r often means new prompt line
                        if (!is_complex_shell_) {
                            at_line_start_ = true;
                        }
                    } else if (c >= 32 && c < 127) {
                        // Regular printable char - track for prompt detection
                        if (!is_complex_shell_ || !at_line_start_) {
                            prompt_buffer_ += c;
                            if (prompt_buffer_.size() > 100) {
                                prompt_buffer_ = prompt_buffer_.substr(prompt_buffer_.size() - 100);
                            }
                        }
                    }
                }
                
                // --- PROMPT DETECTION: Set state to IDLE ---
                // Check if output ends with a known shell prompt
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
                            
                            // DEBOUNCE: Wait 200ms after last command to avoid race with app startup
                            auto now = std::chrono::steady_clock::now();
                            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                now - last_command_time_).count();
                            
                            if ((arrow == 'A' || arrow == 'B') && 
                                pty_.is_shell_idle() && 
                                elapsed > 200) {
                                // Safe to intercept for DAIS history
                                int direction = (arrow == 'A') ? -1 : 1;
                                navigate_history(direction, cmd_accumulator);
                                i += 2;  // Skip '['/O' and arrow letter
                                continue;  // Don't forward to shell
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

                    // --- CTRL+C HANDLING ---
                    // Clears the current line in the shell, so reset our accumulator too.
                    if (c == '\x03') {
                        cmd_accumulator.clear();
                        data_to_write += c;
                        continue;
                    }
                    // --- SMART INTERCEPTION ---
                    // Only process DAIS commands when at shell prompt (IDLE state)
                    
                    // Check for Enter key (\r or \n) indicating command submission
                    if (c == '\r' || c == '\n') {
                        // --- SYNC SHELL WITH VISUAL STATE ---
                        // Only sync when user actually navigated history (changes were visual-only).
                        // Skip for internal commands (:) which are handled separately.
                        if (history_navigated_ && pty_.is_shell_idle() && !cmd_accumulator.empty() && 
                            !cmd_accumulator.starts_with(":")) {
                            // First, erase the visual display (we echoed it during navigation)
                            // This prevents double echo since shell will echo the command itself
                            for (size_t i = 0; i < cmd_accumulator.size(); ++i) {
                                std::cout << "\b \b";
                            }
                            std::cout << std::flush;
                            
                            // Now sync: clear shell's empty line and send command
                            const char kill_line = '\x15';  // Ctrl+U
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
                        
                        // Only save to history and process DAIS commands when shell is idle
                        // This prevents vim/nano keystrokes from polluting history
                        if (pty_.is_shell_idle()) {
                            // Save to DAIS history file (~/.dais_history)
                            if (!cmd_accumulator.empty()) {
                                save_history_entry(cmd_accumulator);
                                history_index_ = command_history_.size();
                                history_stash_.clear();
                            }
                            // 1. Detect 'ls' command (with or without arguments)
                            if (cmd_accumulator == "ls" || cmd_accumulator.starts_with("ls ")) {
                                // NATIVE LS: Use std::filesystem instead of shell
                                // Benefits: No shell compatibility issues, faster, more reliable
                                
                                sync_child_cwd(); // Get actual child shell CWD
                                
                                // Parse arguments
                                auto ls_args = handlers::parse_ls_args(cmd_accumulator);
                                
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
                                const char* clear_and_prompt = "\x15\n"; // Ctrl+U + newline
                                write(pty_.get_master_fd(), clear_and_prompt, 2);
                                
                                // Clear accumulator and skip writing command to PTY
                                cmd_accumulator.clear();
                                at_line_start_ = false; // Prompt will handle this
                                    continue; // Skip the normal PTY write below
                                }
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
                                    msg = "ls sort: by=" + config_.ls_sort_by + 
                                          ", order=" + config_.ls_sort_order + 
                                          ", dirs_first=" + (config_.ls_dirs_first ? "true" : "false");
                                } else if (args == "d") {
                                    // Reset to defaults
                                    config_.ls_sort_by = "type";
                                    config_.ls_sort_order = "asc";
                                    config_.ls_dirs_first = true;
                                    msg = "ls sort: by=type, order=asc, dirs_first=true (defaults)";
                                } else {
                                    // Parse space-separated: by [order] [dirs_first]
                                    std::vector<std::string> parts;
                                    std::string part;
                                    for (char ch : args) {
                                        if (ch == ' ') {
                                            if (!part.empty()) { parts.push_back(part); part.clear(); }
                                        } else {
                                            part += ch;
                                        }
                                    }
                                    if (!part.empty()) parts.push_back(part);
                                    
                                    if (parts.size() >= 1) {
                                        const auto& by = parts[0];
                                        if (by == "name" || by == "size" || by == "type" || by == "rows" || by == "none") {
                                            config_.ls_sort_by = by;
                                        }
                                    }
                                    if (parts.size() >= 2) {
                                        const auto& order = parts[1];
                                        if (order == "asc" || order == "desc") {
                                            config_.ls_sort_order = order;
                                        }
                                    }
                                    if (parts.size() >= 3) {
                                        const auto& dirs = parts[2];
                                        if (dirs == "true" || dirs == "1") {
                                            config_.ls_dirs_first = true;
                                        } else if (dirs == "false" || dirs == "0") {
                                            config_.ls_dirs_first = false;
                                        }
                                    }
                                    
                                    msg = "ls sort: by=" + config_.ls_sort_by + 
                                          ", order=" + config_.ls_sort_order + 
                                          ", dirs_first=" + (config_.ls_dirs_first ? "true" : "false");
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
                        }

                        trigger_python_hook("on_command", cmd_accumulator);
                        cmd_accumulator.clear();
                        data_to_write += c;
                    }
                    // Handle Backspace
                    else if (c == 127 || c == '\b') {
                        // When editing a history entry or a DAIS command, handle visually
                        // (shell doesn't know about our visual-only history navigation)
                        bool visual_mode = (pty_.is_shell_idle() && history_navigated_) ||
                                           (pty_.is_shell_idle() && cmd_accumulator.starts_with(":"));
                        
                        if (visual_mode) {
                            if (!cmd_accumulator.empty()) {
                                cmd_accumulator.pop_back();
                                // Erase character visually: backspace, space, backspace
                                std::cout << "\b \b" << std::flush;
                            }
                            // Don't send to shell - we're in visual-only mode
                        } else {
                            if (!cmd_accumulator.empty()) cmd_accumulator.pop_back();
                            data_to_write += c;
                        }
                    }
                    // Regular character
                    else if (std::isprint(static_cast<unsigned char>(c))) {
                        // Only accumulate for DAIS history if shell is IDLE (at prompt)
                        // This prevents app input (e.g. 'n' in nano) from polluting history
                        if (pty_.is_shell_idle()) {
                            cmd_accumulator += c;
                        }
                        
                        // Visual-only mode: DAIS commands (:) or editing history entries
                        // Don't send to shell - we'll sync on Enter
                        bool visual_mode = (pty_.is_shell_idle() && history_navigated_) ||
                                           (pty_.is_shell_idle() && cmd_accumulator.starts_with(":"));
                        
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
}
