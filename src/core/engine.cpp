/**
 * @file engine.cpp
 * @brief Core implementation of the DASH runtime engine.
 * * This file contains the main logic for:
 * 1. Managing the Pseudoterminal (PTY) session.
 * 2. Bi-directional I/O forwarding (User <-> Shell).
 * 3. Embedding and managing the Python interpreter for plugins.
 * 4. Intercepting specific shell commands (like 'ls') to inject custom behavior.
 * 5. Synchronizing state (CWD) between the child shell process and this wrapper.
 */

#include "core/engine.hpp"
#include "core/command_handlers.hpp"
#include <print>
#include <cstring> // for std::strlen
#include <thread>
#include <array>
#include <string>
#include <string_view>
#include <iostream>
#include <poll.h>
#include <csignal>
#include <sys/wait.h>
#include <filesystem>
#include <atomic>

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
 * @brief Defines the 'dash' Python module available to scripts.
 * Allows Python extensions to communicate back to the C++ core.
 */
PYBIND11_EMBEDDED_MODULE(dash, m) {
    // Expose a print function so Python can write formatted logs to the DASH shell
    m.def("log", [](std::string msg) {
        std::print("\r\n[\x1b[92m-\x1b[0m]: {}\r\n", msg);
    });
}

namespace dash::core {

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
            std::print(stderr, "[\x1b[93m-\x1b[0m] Warning: Plugin path '{}' invalid. Skipping Python extensions.\n", path);
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
                    
                    std::print("[\x1b[92m-\x1b[0m] Loaded .py extension: {}\n", module_name);
                }
            }
        } catch (const std::exception& e) {
            std::print(stderr, "[\x1b[91m-\x1b[0m] Error, failed to load extensions: {}\n", e.what());
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

            // SHOW_LOGO
            if (py::hasattr(conf_module, "SHOW_LOGO")) {
                config_.show_logo = conf_module.attr("SHOW_LOGO").cast<bool>();

                // Debug print for startup (can be removed in prod)
                if (config_.show_logo) std::print("[\x1b[92m-\x1b[0m] SHOW_LOGO = {}\n", config_.show_logo);
                else std::print("[\x1b[91m-\x1b[0m] SHOW_LOGO = {}\n", config_.show_logo);
            }
        } catch (const std::exception& e) {
            // Safe fallback if config is missing
            std::print("[91m-\x1b[0m] No config.py found (or error reading it). Using defaults.\n");
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
                    std::print(stderr, "Error in plugin: {}\n", e.what());
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
        // \r\n is needed because terminal is in RAW mode
        std::print("<DASH> has been started. Type ':q' or ':exit' to exit.\r\n");

        // Spawn the output reader thread (Child -> Screen)
        std::thread output_thread(&Engine::forward_shell_output, this);

        // Run the input processing loop (Keyboard -> Child) in the main thread
        process_user_input();

        // Cleanup
        if (output_thread.joinable()) output_thread.join();
        
        waitpid(pty_.get_child_pid(), nullptr, 0);
        pty_.stop();
        std::print("\r\n<DASH> Session ended.\n");
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
                                    const char* dash = "[\x1b[95m-\x1b[0m] ";
                                    write(STDOUT_FILENO, dash, std::strlen(dash));
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
                    final_output += "[\x1b[95m-\x1b[0m] ";
                }
                final_output.append(prompt_payload.substr(text_start));
            } else {
                final_output.append(prompt_payload);
            }
        }

        return final_output;
    }
}