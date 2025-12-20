#pragma once

#include "core/session.hpp"
#include <atomic>
#include <string_view>
#include <string>

namespace dash::core {

    class Engine {
    public:
        Engine();
        ~Engine();

        void run();

    private:
        PTYSession pty_;
        std::atomic<bool> running_;
        std::atomic<bool> at_line_start_{true};

        // modifying output
        std::string pending_output_buffer_;
        bool intercepting = false;
        std::string process_output(std::string_view raw_output);

        // The background thread that reads from Bash -> Screen
        void forward_shell_output();

        // The main loop that reads User Keyboard -> Bash
        void process_user_input();

        // Handlers
        void handle_python_hook(std::string_view code);
        bool is_builtin(std::string_view line);
    };

}