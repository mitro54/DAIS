#pragma once
#include "core/session.hpp"
#include <atomic>
#include <string_view>
#include <string>
#include <vector>
#include <filesystem>
#include <pybind11/embed.h>
#include <core/command_handlers.hpp>

namespace py = pybind11;

namespace dash::core {

    struct Config {
        bool show_logo = true;
    };

    class Engine {
    public:
        Engine();
        ~Engine();
        void run();
        void load_extensions(const std::string& path);
        void load_configuration(const std::string& path);
    private:
        PTYSession pty_;
        std::atomic<bool> running_;
        std::atomic<bool> at_line_start_{true};
        Config config_;
        std::filesystem::path shell_cwd_ = std::filesystem::current_path();

        // Track the active command string (e.g., "ls", "git status")
        std::string current_command_;

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

        /** * @brief Queries the OS to get the actual CWD of the child shell process.
         * Essential for handling TAB completion where input buffer doesn't match path.
         */
        void sync_child_cwd();
    };

}