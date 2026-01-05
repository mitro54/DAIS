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
#if defined(__APPLE__)
#include <libproc.h>
#include <sys/proc_info.h>
#endif
// -----------------------------------------

// EMBEDDED MODULE DEFINITION
// This defines what C++ functions are available to Python
PYBIND11_EMBEDDED_MODULE(dash, m) {
    // Expose a print function so Python can write to the DASH shell
    m.def("log", [](std::string msg) {
        std::print("\r\n[\x1b[92m-\x1b[0m]: {}\r\n", msg);
    });
}

namespace dash::core {

    constexpr size_t BUFFER_SIZE = 4096;
    std::atomic<bool> running_{false};
    std::atomic<bool> intercepting{false};

    Engine::Engine() {}
    Engine::~Engine() { if (running_) kill(pty_.get_child_pid(), SIGTERM); }

    void Engine::load_extensions(const std::string& path) {
        namespace fs = std::filesystem;
        fs::path p(path);
        if (path.empty() || !fs::exists(p) || !fs::is_directory(p)) {
        std::print(stderr, "[\x1b[93m-\x1b[0m] Warning: Plugin path '{}' invalid. Skipping Python extensions.\n", path);
        return;
        }
        std::string abs_path = fs::absolute(p).string();

        try {
            // Add the plugin path to Python's sys.path so it can find files there
            py::module_ sys = py::module_::import("sys");
            sys.attr("path").attr("append")(path);

            for (const auto& entry : fs::directory_iterator(path)) {
                if (entry.path().extension() == ".py") {
                    std::string module_name = entry.path().stem().string();
                    // skip __init__ and config
                    if (module_name == "__init__" || module_name == "config") continue;
                    // Import the file as a module
                    py::module_ plugin = py::module_::import(module_name.c_str());
                    loaded_plugins_.push_back(plugin);
                    
                    std::print("[\x1b[92m-\x1b[0m] Loaded .py extension: {}\n", module_name);
                }
            }
        } catch (const std::exception& e) {
            std::print(stderr, "[\x1b[91m-\x1b[0m] Error, failed to load extensions: {}\n", e.what());
        }
    }

    void Engine::load_configuration(const std::string& path) {
        namespace fs = std::filesystem;
        fs::path p(path);
        try {
            py::module_ sys = py::module_::import("sys");
            sys.attr("path").attr("append")(fs::absolute(p).string());
            py::module_ conf_module = py::module_::import("config");

            // SETTINGS

            // SHOW_LOGO
            if (py::hasattr(conf_module, "SHOW_LOGO")) {
                config_.show_logo = conf_module.attr("SHOW_LOGO").cast<bool>();

                // later modify this to only print if something has changed, or on demand (command for it)
                if (config_.show_logo) std::print("[\x1b[92m-\x1b[0m] SHOW_LOGO = {}\n", config_.show_logo);
                else std::print("[\x1b[91m-\x1b[0m] SHOW_LOGO = {}\n", config_.show_logo);
            }

            // list all the possible settings here in the same way, if hasattr conf module "SETTING_NAME"...


        } catch (const std::exception& e) {
            // if config.py doesnt exist, we just stay with the defaults
            std::print("[91m-\x1b[0m] No config.py found (or error reading it). Using defaults.\n");
        }
    }

    void Engine::trigger_python_hook(const std::string& hook_name, const std::string& data) {
        for (auto& plugin : loaded_plugins_) {
            // Check if the python file has a function with this name
            if (py::hasattr(plugin, hook_name.c_str())) {
                try {
                    plugin.attr(hook_name.c_str())(data);
                } catch (const std::exception& e) {
                    // Python runtime error
                    std::print(stderr, "Error in plugin: {}\n", e.what());
                }
            }
        }
    }

    void Engine::sync_child_cwd() {
        pid_t pid = pty_.get_child_pid();
        if (pid <= 0) return;

#if defined(__APPLE__)
        // macOS Best Practice: Use libproc to get CWD of the child process ID
        struct proc_vnodepathinfo vpi;
        if (proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vpi, sizeof(vpi)) > 0) {
            // vip_path is the absolute path
            shell_cwd_ = std::filesystem::path(vpi.pvi_cdir.vip_path);
        }
#elif defined(__linux__)
        // Linux Best Practice: Read the /proc/{pid}/cwd symlink
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

    void Engine::run() {
        if (!pty_.start()) return;

        running_ = true;
        // \r\n is needed because RAW mode
        std::print("<DASH> has been started. Type ':q' or ':exit' to exit.\r\n");

        std::thread output_thread(&Engine::forward_shell_output, this);

        process_user_input();

        if (output_thread.joinable()) output_thread.join();
        
        // Wait for child to exit gracefully
        waitpid(pty_.get_child_pid(), nullptr, 0);
        pty_.stop();
        std::print("\r\n<DASH> Session ended.\n");
    }

    void Engine::forward_shell_output() {
        std::array<char, BUFFER_SIZE> buffer;
        struct pollfd pfd{};
        pfd.fd = pty_.get_master_fd();
        pfd.events = POLLIN;

        while (true) {
            int ret = poll(&pfd, 1, 100);
            if (ret < 0) break;
            if (ret == 0) {
                if (!running_) continue;
                continue;
            }

            if (pfd.revents & (POLLERR | POLLHUP)) {
                break;
            }

            if (pfd.revents & POLLIN) {
                ssize_t bytes_read = read(
                    pty_.get_master_fd(),
                    buffer.data(),
                    buffer.size()
                );

                if (bytes_read <= 0) break;

                // interception mode
                // modifying the output, look into combining this with the else for loop below later
                if (intercepting) {
                    std::string_view chunk(buffer.data(), bytes_read);
                    pending_output_buffer_ += chunk;
                    if (pending_output_buffer_.find("$ ") != std::string::npos ||
                        pending_output_buffer_.find("> ") != std::string::npos) {
                            std::string modified = process_output(pending_output_buffer_);
                            write(STDOUT_FILENO, modified.c_str(), modified.size());
                            intercepting = false;
                            pending_output_buffer_.clear();
                        }
                } else {
                for (ssize_t i = 0; i < bytes_read; ++i) {
                    char c = buffer[i];

                    if (at_line_start_) {
                        if (c != '\n' && c != '\r') {
                            // check the config
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

    void Engine::process_user_input() {
        // In RAW mode, we read char by char.
        // We accumulate chars to detect commands, but we cannot rely on this 
        // buffer for paths because TAB completion happens in the shell, not here.
        
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

                // Simple check for commands "ls", ":q" & ":exit"
                for (ssize_t i = 0; i < n; ++i) {
                    char c = buffer[i];

                    // Check for Enter key (\r or \n)
                    if (c == '\r' || c == '\n') {
                        current_command_ = cmd_accumulator; 
                        
                        // Check if the accumulated string matches any of our commands
                        if (cmd_accumulator == "ls") {
                            // CWD FIX: Before running LS logic, ensure we know the REAL directory.
                            // This accounts for any previous 'cd' commands that used TAB completion.
                            sync_child_cwd(); 

                            intercepting = true;
                            // INJECTION: Force 'ls' to become 'ls -1' to separate files by newline
                            data_to_write += " -1";
                        }

                        if (cmd_accumulator == ":q" || cmd_accumulator == ":exit") {
                            running_ = false;
                            kill(pty_.get_child_pid(), SIGHUP);
                            return;
                        }

                        // REMOVED MANUAL 'cd' PARSING.
                        // Relying on input parsing for 'cd' is broken by TAB completion.
                        // Instead, we now sync CWD lazily in sync_child_cwd() above.

                        trigger_python_hook("on_command", cmd_accumulator);
                        // Clear buffer for the next command
                        cmd_accumulator.clear();
                    }
                    // Handle Backspace (127 or \b) so we don't watch on deleted chars
                    else if (c == 127 || c == '\b') {
                        if (!cmd_accumulator.empty()) cmd_accumulator.pop_back();
                    }
                    // Accumulate normal characters
                    else {
                        cmd_accumulator += c;
                    }

                    // Append the actual character to the outgoing stream
                    data_to_write += c;
                }
                
                // Writing to master_fd sends keystrokes to Bash
                if (!data_to_write.empty()) {
                    write(pty_.get_master_fd(), data_to_write.data(), data_to_write.size());
                }
            }
        }
    }

    // 'ls' command functionality: (should probably also be configurable later)
    // check each filename with the 'file' cmd to see what type of files they are in the background
    // then process the desired output modification for each file type
    // stitch the newly modified filenames with their new content back to their place
    // show the output
    
    std::string Engine::process_output(std::string_view raw_output) {
        std::string final_output;
        final_output.reserve(raw_output.size() * 3);

        size_t last_newline = raw_output.find_last_of("\n");
        if (last_newline == std::string_view::npos) last_newline = raw_output.length(); 

        std::string_view content_payload = raw_output.substr(0, last_newline);
        
        std::string_view prompt_payload = "";
        if (last_newline < raw_output.length()) {
            prompt_payload = raw_output.substr(last_newline);
        }

        std::string processed_content;
        if (current_command_ == "ls") {
            processed_content = handlers::handle_ls(content_payload, shell_cwd_);
        } else {
            processed_content = handlers::handle_generic(content_payload);
        }

        // 3. Grid Output
        if (!processed_content.empty()) {
            final_output += "\r\n"; 
            final_output += processed_content;
        }

        // 4. Prompt Output
        if (!prompt_payload.empty()) {
            // FIX: Ensure cursor is at column 0 before prompt starts
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