#pragma once

#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <cstdint>
#include <string>

namespace dais::core {

    class PTYSession {
    public:
        PTYSession();
        ~PTYSession();

        // Starts the PTY and forks the child process
        bool start();
        
        // Clean cleanup of file descriptors and processes
        void stop();

        // Updates the PTY size (rows/cols) to match the physical window.
        // Handles "Safe Width" calculation for the logo injection.
        void resize(int rows, int cols, bool show_logo);

        // Getters
        [[nodiscard]] int get_master_fd() const { return master_fd_; }
        [[nodiscard]] pid_t get_child_pid() const { return child_pid_; }
        
        /**
         * @brief Checks if the shell is idle (at prompt, no foreground child).
         * Uses tcgetpgrp to get the foreground process group of the PTY.
         * If it matches the shell's PID, no child (vim, python, etc.) is running.
         * @return true if shell is idle, false if a child process is in foreground
         */
        [[nodiscard]] bool is_shell_idle() const {
            pid_t fg_pgrp = tcgetpgrp(master_fd_);
            // If fg_pgrp matches the shell's process group, shell is idle
            // getpgid(child_pid_) gets the shell's process group
            return fg_pgrp == getpgid(child_pid_);
        }

        /**
         * @brief Retrieves the name of the foreground process (e.g., "vim", "python3", "ssh").
         * Useful for making engine decisions based on what the user is running.
         */
        std::string get_foreground_process_name();

    private:
        int master_fd_;
        pid_t child_pid_;
        struct termios orig_term_; // To restore terminal settings on exit

        void set_raw_mode();
        void restore_term_mode();
    };

}