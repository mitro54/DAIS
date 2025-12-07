#include "core/engine.hpp"
#include <print>
#include <thread>
#include <array>
#include <iostream>
#include <poll.h>
#include <csignal>
#include <sys/wait.h>

namespace dash::core {

    constexpr size_t BUFFER_SIZE = 4096;

    Engine::Engine() : running_(false) {}

    Engine::~Engine() {
        if (running_) {
            kill(pty_.get_child_pid(), SIGTERM);
        }
    }

    void Engine::run() {
        if (!pty_.start()) return;

        running_ = true;
        // \r\n is needed because RAW mode
        std::print("[DASH] Started. Type ':quit' or ':exit' to exit.\r\n");

        std::thread output_thread(&Engine::forward_shell_output, this);

        process_user_input();

        if (output_thread.joinable()) output_thread.join();
        
        // Wait for child to exit gracefully
        waitpid(pty_.get_child_pid(), nullptr, 0);
        std::print("\r\n[DASH] Session ended.\n");
    }

    void Engine::forward_shell_output() {
        std::array<char, BUFFER_SIZE> buffer;
        struct pollfd pfd{};
        pfd.fd = pty_.get_master_fd();
        pfd.events = POLLIN;

        while (running_) {
            int ret = poll(&pfd, 1, 100); // 100ms timeout

            if (ret < 0) break; 
            if (ret == 0) continue;

            if (pfd.revents & (POLLERR | POLLHUP)) {
                running_ = false;
                break;
            }

            if (pfd.revents & POLLIN) {
                ssize_t bytes_read = read(pty_.get_master_fd(), buffer.data(), buffer.size());
                if (bytes_read <= 0) break;

                // TODO: Data Interception happens here (Data detection)
                
                // Write to standard out
                write(STDOUT_FILENO, buffer.data(), bytes_read);
            }
        }
    }

    void Engine::process_user_input() {
        // In RAW mode, we read char by char, but for this prototype,
        // we might want to buffer lines or just pass-through.
        // HOWEVER: Since we set RAW mode in Session, std::getline won't work nicely
        // because it expects canonical processing. 
        // For a wrapper, we usually read stdin raw bytes.
        
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

                // Simple check for command ":quit" & ":exit"
                // In a real raw-mode shell, detecting "lines" is harder because
                // you get 'q', then 'u', then 'i', then 't'.
                // For this, we pass everything to bash, unless we detect a pattern.
                for (ssize_t i = 0; i < n; ++i) {
                    char c = buffer[i];

                    // Check for Enter key (\r or \n)
                    if (c == '\r' || c == '\n') {

                        // Check if the accumulated string matches our command
                        if (cmd_accumulator == ":quit" || cmd_accumulator == ":exit") {
                            running_ = false;
                        }
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
                }
                // Writing to master_fd sends keystrokes to Bash
                write(pty_.get_master_fd(), buffer.data(), n);
            }
        }
    }

    void Engine::handle_python_hook(std::string_view code) {
        std::print("[DASH Executing Python]: {}\r\n", code);
        
        // for demo purposes
        std::string cmd = std::format("python3 -c \"{}\"", code);
        system(cmd.c_str());
    }
}