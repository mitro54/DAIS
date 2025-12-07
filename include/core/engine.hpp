#pragma once

#include "core/session.hpp"
#include <atomic>
#include <string_view>

namespace dash::core {

    class Engine {
    public:
        Engine();
        ~Engine();

        void run();

    private:
        PTYSession pty_;
        std::atomic<bool> running_;

        // The background thread that reads from Bash -> Screen
        void forward_shell_output();

        // The main loop that reads User Keyboard -> Bash
        void process_user_input();

        // Handlers
        void handle_python_hook(std::string_view code);
        bool is_builtin(std::string_view line);
    };

}