#pragma once

#include "core/session.hpp"
#include <atomic>
#include <string_view>
#include <string>
#include <vector>
#include <pybind11/embed.h>

namespace py = pybind11;

namespace dash::core {

    class Engine {
    public:
        Engine();
        ~Engine();
        void run();
        void load_extensions(const std::string& path); 
    private:
        PTYSession pty_;
        std::atomic<bool> running_;
        std::atomic<bool> at_line_start_{true};

        // modifying output
        std::string pending_output_buffer_;
        bool intercepting = false;
        std::string process_output(std::string_view raw_output);

        // python state
        py::scoped_interpreter guard{}; 
        std::vector<py::module_> loaded_plugins_;

        // The background thread that reads from Bash -> Screen
        void forward_shell_output();

        // The main loop that reads User Keyboard -> Bash
        void process_user_input();

        void trigger_python_hook(const std::string& hook_name, const std::string& data);
    };

}