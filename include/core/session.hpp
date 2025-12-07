#pragma once

#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <cstdint>

namespace dash::core {

    class PTYSession {
    public:
        PTYSession();
        ~PTYSession();

        // Starts the PTY and forks the child process
        bool start();
        
        // Clean cleanup of file descriptors and processes
        void stop();

        // Getters
        [[nodiscard]] int get_master_fd() const { return master_fd_; }
        [[nodiscard]] pid_t get_child_pid() const { return child_pid_; }

        // Resize the virtual terminal
        void resize(int rows, int cols);

    private:
        int master_fd_;
        pid_t child_pid_;
        struct termios orig_term_; // To restore terminal settings on exit

        void set_raw_mode();
        void restore_term_mode();
    };

}