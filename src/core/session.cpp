#include "core/session.hpp"
#include <print>
#include <cstdlib>
#include <cstring>
#include <system_error>

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <util.h>
#else
#include <pty.h>
#endif

namespace dash::core {

    PTYSession::PTYSession() : master_fd_(-1), child_pid_(-1) {}

    PTYSession::~PTYSession() {
        stop();
    }

    bool PTYSession::start() {
        // 1. Save current terminal settings
        if (tcgetattr(STDIN_FILENO, &orig_term_) == -1) {
            std::println(stderr, "Error: Could not save terminal settings.");
            return false;
        }

        // 2. Set Raw Mode (Critical for shells like bash/zsh to work properly)
        // This disables local echo and line buffering in the *wrapper*
        set_raw_mode();

        // 3. Fork and Create PTY
        child_pid_ = forkpty(&master_fd_, nullptr, nullptr, nullptr);

        if (child_pid_ < 0) {
            std::println(stderr, "Error: forkpty failed.");
            return false;
        }

        // --- CHILD PROCESS ---
        if (child_pid_ == 0) {
            // Auto-detect shell
            const char* shell = std::getenv("SHELL");
            if (!shell) shell = "/bin/bash";

            // Replace process with shell
            execlp(shell, shell, "-i", nullptr);
            
            // If we get here, it failed
            std::println(stderr, "Error: Failed to launch shell {}", shell);
            std::exit(1);
        }

        return true;
    }

    void PTYSession::stop() {
        if (master_fd_ != -1) {
            restore_term_mode();
            close(master_fd_);
            master_fd_ = -1;
        }
        // implement waitpid() here later to avoid zombies
    }

    void PTYSession::resize(int rows, int cols) {
        struct winsize ws{};
        ws.ws_row = static_cast<unsigned short>(rows);
        ws.ws_col = static_cast<unsigned short>(cols);
        ioctl(master_fd_, TIOCSWINSZ, &ws);
    }

    void PTYSession::set_raw_mode() {
        struct termios raw = orig_term_;
        cfmakeraw(&raw);
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    }

    void PTYSession::restore_term_mode() {
        tcsetattr(STDIN_FILENO, TCSANOW, &orig_term_);
    }

}