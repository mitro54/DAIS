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
#include <cstring> // for std::strlen
#include <thread>
#include <array>
#include <string>
#include <string_view>
#include <iostream> // Needed for std::cout, std::cerr
#include <poll.h>
#include <csignal>
#include <sys/wait.h>
#include <filesystem>
#include <atomic>
#include <iomanip> // for std::boolalpha

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
    std::atomic<bool> running_{false};
    std::atomic<bool> intercepting{false};

    Engine::Engine() {}
    
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
        std::string abs_path = fs::absolute(p).string();

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

            // 2. THEME LOADING
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
                load_color("DIR_NAME", handlers::Theme::DIR_NAME);
                load_color("SYMLINK", handlers::Theme::SYMLINK);
                load_color("LOGO", handlers::Theme::LOGO);
                load_color("SUCCESS", handlers::Theme::SUCCESS);
                load_color("WARNING", handlers::Theme::WARNING);
                load_color("ERROR", handlers::Theme::ERROR);
            }

            // Debug Print
            std::cout << "[" << handlers::Theme::NOTICE << "-" << handlers::Theme::RESET 
                      << "] Config Loaded. SHOW_LOGO = " << std::boolalpha << config_.show_logo << "\n";

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
     * This provides 100% accuracy regardless of how the directory was changed.
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

        running_ = true;
        
        // Rebranded Startup Message with Configured Theme
        std::cout << "\r\n[" 
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
        
        std::cout << "\r\n[" 
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
            // Poll with timeout to allow checking 'running_' flag
            int ret = poll(&pfd, 1, 100);
            if (ret < 0) break; // Error
            if (ret == 0) {
                if (!running_) continue; // Just a timeout check
                continue;
            }

            if (pfd.revents & (POLLERR | POLLHUP)) {
                break; // PTY closed (child exited)
            }

            if (pfd.revents & POLLIN) {
                ssize_t bytes_read = read(
                    pty_.get_master_fd(),
                    buffer.data(),
                    buffer.size()
                );

                if (bytes_read <= 0) break;

                // --- INTERCEPTION MODE ---
                // If the input loop triggered interception (e.g. for 'ls'),
                // we accumulate data until we see a prompt, then process it all at once.
                if (intercepting) {
                    std::string_view chunk(buffer.data(), bytes_read);
                    pending_output_buffer_ += chunk;
                    
                    // Simple heuristic to detect when command output has finished (prompt reappears)
                    if (pending_output_buffer_.find("$ ") != std::string::npos ||
                        pending_output_buffer_.find("> ") != std::string::npos) {
                            
                            std::string modified = process_output(pending_output_buffer_);
                            write(STDOUT_FILENO, modified.c_str(), modified.size());
                            
                            // Reset state
                            intercepting = false;
                            pending_output_buffer_.clear();
                        }
                } 
                // --- PASS-THROUGH MODE ---
                else {
                    for (ssize_t i = 0; i < bytes_read; ++i) {
                        char c = buffer[i];

                        // Logo injection logic at line starts
                        if (at_line_start_) {
                            if (c != '\n' && c != '\r') {
                                if (config_.show_logo) {
                                    // Use dynamic strings from Theme
                                    std::string logo_str = "[" + handlers::Theme::LOGO + "-" + handlers::Theme::RESET + "] ";
                                    write(STDOUT_FILENO, logo_str.c_str(), logo_str.size());
                                    at_line_start_ = false;
                                }
                            }
                        }
                        write(STDOUT_FILENO, &c, 1);
                        if (c == '\n' || c == '\r') at_line_start_ = true;
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
            if (ret < 0) break;

            if (pfd.revents & POLLIN) {
                ssize_t n = read(STDIN_FILENO, buffer.data(), buffer.size());
                if (n <= 0) break;

                std::string data_to_write;
                data_to_write.reserve(n + 8); 

                // Process char-by-char to build command string
                for (ssize_t i = 0; i < n; ++i) {
                    char c = buffer[i];

                    // Check for Enter key (\r or \n) indicating command submission
                    if (c == '\r' || c == '\n') {
                        current_command_ = cmd_accumulator; 
                        
                        // 1. Detect 'ls'
                        if (cmd_accumulator == "ls") {
                            // CWD FIX: Sync OS state before running ls logic
                            sync_child_cwd(); 

                            intercepting = true;
                            // INJECTION: Append ' -1' to force single-column output.
                            // This ensures filenames with spaces are separated by newlines,
                            // allowing the parser to handle them correctly.
                            data_to_write += " -1";
                        }

                        // 2. Internal Exit Commands
                        if (cmd_accumulator == ":q" || cmd_accumulator == ":exit") {
                            running_ = false;
                            kill(pty_.get_child_pid(), SIGHUP);
                            return;
                        }

                        trigger_python_hook("on_command", cmd_accumulator);
                        cmd_accumulator.clear();
                    }
                    // Handle Backspace
                    else if (c == 127 || c == '\b') {
                        if (!cmd_accumulator.empty()) cmd_accumulator.pop_back();
                    }
                    // Accumulate characters
                    else {
                        cmd_accumulator += c;
                    }

                    // Append the actual character to the outgoing stream
                    data_to_write += c;
                }
                
                // Write to PTY Master (Input to Shell)
                if (!data_to_write.empty()) {
                    write(pty_.get_master_fd(), data_to_write.data(), data_to_write.size());
                }
            }
        }
    }
    
    // ==================================================================================
    // OUTPUT PROCESSING
    // ==================================================================================

    /**
     * @brief Processes intercepted output before displaying it.
     * Currently handles 'ls' by handing it off to the command_handlers library.
     */
    std::string Engine::process_output(std::string_view raw_output) {
        std::string final_output;
        final_output.reserve(raw_output.size() * 3);

        // Separate content from the prompt
        size_t last_newline = raw_output.find_last_of("\n");
        if (last_newline == std::string_view::npos) last_newline = raw_output.length(); 

        std::string_view content_payload = raw_output.substr(0, last_newline);
        
        std::string_view prompt_payload = "";
        if (last_newline < raw_output.length()) {
            prompt_payload = raw_output.substr(last_newline);
        }

        // Delegate to handler
        std::string processed_content;
        if (current_command_ == "ls") {
            //  - Handlers transform plain list into grid
            processed_content = handlers::handle_ls(content_payload, shell_cwd_);
        } else {
            processed_content = handlers::handle_generic(content_payload);
        }

        // Reconstruct Output
        if (!processed_content.empty()) {
            final_output += "\r\n"; 
            final_output += processed_content;
        }

        // Re-attach Prompt with Logo
        if (!prompt_payload.empty()) {
            final_output += "\r"; 
            size_t text_start = prompt_payload.find_first_not_of("\r\n");
            
            if (text_start != std::string_view::npos) {
                final_output.append(prompt_payload.substr(0, text_start));
                if (config_.show_logo) {
                    final_output += "[" + handlers::Theme::LOGO + "-" + handlers::Theme::RESET + "] ";
                }
                final_output.append(prompt_payload.substr(text_start));
            } else {
                final_output.append(prompt_payload);
            }
        }

        return final_output;
    }
}