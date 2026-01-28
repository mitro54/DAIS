/**
 * @file session.cpp
 * @brief Implementation of the PTY (Pseudoterminal) Session management.
 * * This file handles the low-level operating system interactions required to:
 * 1. Create a new pseudoterminal pair (master/slave).
 * 2. Fork the current process to create a child process.
 * 3. Configure the terminal environment (Raw mode vs Canonical mode).
 * 4. Launch the user's default shell (bash/zsh) within the child process.
 */

#include "core/session.hpp"
#include <iostream> 
#include <cstdlib>
#include <cstring>
#include <system_error>

// Platform-specific headers for PTY management
#if defined(__APPLE__) || defined(__FreeBSD__)
    #include <util.h>
    #if defined(__APPLE__)
        #include <libproc.h>
    #endif
#elif defined(__linux__)
    #include <pty.h>
    #include <filesystem>
    #include <fstream>
#else
    #include <pty.h>
#endif

namespace dais::core {

    PTYSession::PTYSession() : master_fd_(-1), child_pid_(-1) {}

    PTYSession::~PTYSession() {
        stop();
    }

    /**
     * @brief Initializes the PTY session and spawns the child shell.
     * * The startup sequence is critical and order-sensitive:
     * 1. Save original terminal settings (to restore on exit).
     * 2. Set the parent process's terminal to RAW mode (to pass all input, including Ctrl+C, to the child).
     * 3. Fork the process using `forkpty`, which handles the complex PTY master/slave setup.
     * 4. In the child process:
     * - Detect the user's shell (SHELL env var).
     * - Disable macOS/Apple specific session saving (prevents hangs on exit).
     * - Replace the process image with the shell executable via `execlp`.
     * * @return true if the session started successfully, false otherwise.
     */
    bool PTYSession::start() {
        // 1. Save current terminal settings so we can restore them later
        if (tcgetattr(STDIN_FILENO, &orig_term_) == -1) {
            std::cerr << "Error: Could not save terminal settings." << std::endl;
            return false;
        }

        // 2. Switch to Raw Mode
        // This is essential. Without Raw mode, the parent terminal would intercept 
        // signals (Ctrl+C, Ctrl+Z) and process line editing (Backspace, Enter) locally
        // instead of sending raw keystrokes to the shell.
        set_raw_mode();

        // 3. Fork and Create PTY
        // forkpty() creates a new process and automatically opens the master/slave PTY pair.
        child_pid_ = forkpty(&master_fd_, nullptr, nullptr, nullptr);

        if (child_pid_ < 0) {
            std::cerr << "Error: forkpty failed." << std::endl;
            return false;
        }

        // --- CHILD PROCESS EXECUTION BLOCK ---
        if (child_pid_ == 0) {
            // A. Auto-detect user's preferred shell
            const char* shell = std::getenv("SHELL");
            if (!shell) shell = "/bin/sh";

            // B. macOS/Apple Terminal Fix
            // Apple injects scripts to save session history which requires IPC with Terminal.app.
            // Since we are not Terminal.app, this causes the shell to hang on exit ("Saving session...").
            // Setting this environment variable disables that specific behavior.
            setenv("SHELL_SESSION_HISTORY", "0", 1);

            // C. Execute Shell
            // -i: Interactive mode (sets prompts, job control)
            // -l: Login shell (reads profile scripts, ensures PATH is correct)
            execlp(shell, shell, "-i", "-l", nullptr);
            
            // If execution reaches here, execlp failed (e.g., shell not found).
            std::cerr << "Error: Failed to launch shell " << shell << std::endl;
            std::exit(1);
        }

        return true;
    }

    /**
     * @brief Terminates the PTY session and cleans up resources.
     * Restores the terminal to canonical mode and closes the file descriptor.
     */
    void PTYSession::stop() {
        if (master_fd_ != -1) {
            restore_term_mode();
            close(master_fd_);
            master_fd_ = -1;
        }
        // Note: The Engine class handles waitpid() to reap the child process
        // to prevent zombie processes.
    }

    /**
     * @brief Resizes the virtual window size of the PTY.
     * * [VISUAL COMPENSATION FIX]
     * Since DAIS injects a 4-character logo ("[-] ") at the start of every line,
     * we must tell the inner shell that the window is 4 columns narrower than it 
     * physically is. This ensures the shell wraps text *before* it hits the 
     * physical edge, leaving room for the logo.
     * * @param rows New number of rows (height).
     * @param cols New number of columns (width).
     */
    void PTYSession::resize(int rows, int cols, bool show_logo) {
        struct winsize ws{};
        ws.ws_row = static_cast<unsigned short>(rows);
        
        // Subtract 4 columns to reserve space for the logo.
        // Safety check: ensure we don't underflow if the window is tiny.
        if (show_logo) {
            if (cols > 4) cols -= 4;
            else cols = 1;
        }
        unsigned short safe_cols = cols;
        ws.ws_col = static_cast<unsigned short>(safe_cols);
        
        ioctl(master_fd_, TIOCSWINSZ, &ws);
    }

    /**
     * @brief Configures the standard input for Raw Mode.
     * * Raw mode disables:
     * - ECHO: Characters typed are not printed immediately (the shell handles echo).
     * - ICANON: Input is available byte-by-byte, not line-by-line.
     * - ISIG: Signals like SIGINT (Ctrl+C) are passed as input bytes, not trapped.
     */
    void PTYSession::set_raw_mode() {
        struct termios raw = orig_term_;
        cfmakeraw(&raw);
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    }

    /**
     * @brief Restores the standard input to its original Canonical Mode.
     * Must be called before exiting so the user's terminal behaves normally again.
     */
    void PTYSession::restore_term_mode() {
        tcsetattr(STDIN_FILENO, TCSANOW, &orig_term_);
    }

    std::string PTYSession::get_foreground_process_name() {
        pid_t fg_pgrp = tcgetpgrp(master_fd_);
        if (fg_pgrp < 0) return "";

        // In most shells, the PGID of the foreground job is the PID of the leader process
        pid_t target_pid = fg_pgrp;

#if defined(__APPLE__)
        struct proc_bsdinfo proc;
        if (proc_pidinfo(target_pid, PROC_PIDTBSDINFO, 0, &proc, sizeof(proc)) > 0) {
             return std::string(proc.pbi_name);
        }
#elif defined(__linux__)
        try {
             std::string path = "/proc/" + std::to_string(target_pid) + "/comm";
             std::ifstream pid_file(path);
             if (pid_file.is_open()) {
                 std::string name;
                 std::getline(pid_file, name);
                 // Trim newline
                 if (!name.empty() && name.back() == '\n') name.pop_back();
                 return name;
             }
        } catch (...) {}
#endif
        return "";
    }
}