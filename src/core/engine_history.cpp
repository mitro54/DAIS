/**
 * @file engine_history.cpp
 * @brief Implementation of Engine's command history management.
 * 
 * Handles loading, saving, and navigating the persistent command history.
 * Implements a "visual mode" for history navigation that modifies the 
 * terminal display without immediately committing changes to the shell,
 * preventing race conditions.
 */

#include "core/engine.hpp"
#include "core/command_handlers.hpp"
#include <iostream>
#include <fstream>
#include <unistd.h>

namespace dais::core {

    /**
     * @brief Loads command history from ~/.dais_history on startup.
     * 
     * Reads the history file line by line into the `command_history_` deque.
     * Truncates the history if it exceeds `MAX_HISTORY` to keep memory usage low.
     * Sets `history_index_` to the end, so the first Up Arrow press retrieves the last command.
     */
    void Engine::load_history() {
        const char* home = getenv("HOME");
        if (!home) return;
        
        history_file_ = std::filesystem::path(home) / ".dais_history";
        
        std::ifstream file(history_file_);
        if (!file.is_open()) return;
        
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                command_history_.push_back(line);
            }
        }
        
        while (command_history_.size() > MAX_HISTORY) {
            command_history_.pop_front();
        }
        
        history_index_ = command_history_.size();
    }
    
    /**
     * @brief Appends a command to history (in-memory and file).
     * 
     * - Skips empty commands.
     * - Skips consecutive duplicates to keep history clean.
     * - Appends to the `.dais_history` file immediately for persistence.
     * 
     * @param cmd The command string to save.
     */
    void Engine::save_history_entry(const std::string& cmd) {
        if (cmd.empty()) return;
        
        if (!command_history_.empty() && command_history_.back() == cmd) {
            return;
        }
        
        command_history_.push_back(cmd);
        if (command_history_.size() > MAX_HISTORY) {
            command_history_.pop_front();
        }
        
        if (!history_file_.empty()) {
            std::ofstream file(history_file_, std::ios::app);
            if (file.is_open()) {
                file << cmd << "\n";
            }
        }
    }
    
    /**
     * @brief Handles the internal :history command.
     * 
     * Supports:
     * - `:history` (defaults to last 20 items)
     * - `:history <N>` (show last N items)
     * - `:history clear` (wipes history file and memory)
     * 
     * @param args The arguments passed to the :history command.
     */
    void Engine::show_history(const std::string& args) {
        if (args == "clear") {
            command_history_.clear();
            if (!history_file_.empty()) {
                std::ofstream file(history_file_, std::ios::trunc);
            }
            std::cout << "\r\n[" << handlers::Theme::NOTICE << "-" << handlers::Theme::RESET
                      << "] History cleared.\r\n" << std::flush;
            return;
        }
        
        size_t count = 20;
        if (!args.empty()) {
            try {
                count = std::stoul(args);
            } catch (...) {
                count = 20;
            }
        }
        
        if (command_history_.empty()) {
            std::cout << "\r\n[" << handlers::Theme::NOTICE << "-" << handlers::Theme::RESET
                      << "] History is empty.\r\n" << std::flush;
            return;
        }
        
        std::cout << "\r\n";
        size_t start = command_history_.size() > count ? command_history_.size() - count : 0;
        for (size_t i = start; i < command_history_.size(); i++) {
            std::cout << "[" << handlers::Theme::VALUE << (i + 1) << handlers::Theme::RESET
                      << "] " << command_history_[i] << "\r\n";
        }
        std::cout << std::flush;
    }
    
    /**
     * @brief Navigates through DAIS command history via UP/DOWN arrows.
     * 
     * **Visual Mode Navigation Strategy:**
     * Instead of sending Up/Down codes to the shell (which might fight with
     * the shell's own history or autosuggestions), DAIS handles navigation
     * purely visually:
     * 1. It calculates the visual length of the current line.
     * 2. It moves the cursor back to the start of the command (ignoring prompt).
     * 3. It clears the line and prints the new history item.
     * 
     * Crucially, the shell is *not* notified of this change until:
     * - The user types a character (edits the line).
     * - The user presses Enter (executes the line).
     * 
     * This avoids complex PTY synchronization issues during rapid navigation.
     * 
     * @param direction -1 for older (up), +1 for newer (down)
     * @param current_line Reference to the command accumulator to update.
     */
    void Engine::navigate_history(int direction, std::string& current_line) {
        if (!is_remote_session_ && !pty_.is_shell_idle()) return;
        
        if (command_history_.empty()) return;

        // Preview next state
        std::string next_content;
        if (direction < 0 && history_index_ > 0) {
            next_content = command_history_[history_index_ - 1];
        } else if (direction > 0 && history_index_ < command_history_.size() - 1) {
            next_content = command_history_[history_index_ + 1];
        } else if (direction > 0 && history_index_ == command_history_.size() - 1) {
            next_content = history_stash_;
        }

        // Initialize visual coordinates if we haven't yet
        ensure_visual_mode_init(current_line.size());
        
        // Stash current work when moving away from the "newest" empty line
        if (history_index_ == command_history_.size() && direction < 0) {
            history_stash_ = current_line;
        }
        
        // Update index
        size_t new_index = history_index_;
        if (direction < 0 && history_index_ > 0) {
            new_index = history_index_ - 1;
        } else if (direction > 0 && history_index_ < command_history_.size()) {
            new_index = history_index_ + 1;
        } else {
            return; 
        }
        history_index_ = new_index;
        history_navigated_ = true; 
        synced_with_shell_ = false;
        
        // Retrieve content
        std::string new_content;
        if (history_index_ == command_history_.size()) {
            new_content = history_stash_;
        } else {
            new_content = command_history_[history_index_];
        }
        
        // Perform Visual Update
        {
            std::lock_guard<std::recursive_mutex> terminal_lock(terminal_mutex_);
            visual_move_cursor(current_line.size(), 0);
            write(STDOUT_FILENO, "\x1b[J", 3); // Erase from cursor to end
            
            if (!new_content.empty()) {
                write(STDOUT_FILENO, new_content.c_str(), new_content.size());
            }
        }
        
        // Update Internal State
        current_line = new_content;
        cursor_pos_ = current_line.size();
    }

    /**
     * @brief Syncs the visual-only history content to the actual shell buffer.
     * 
     * Called when the user transitions from "Looking at history" to "Editing/Running".
     * Uses the `kCtrlU` (Kill Line) character to clear the shell's buffer (which
     * might be empty or contain old text) and then injects the current `accumulator` verbatim.
     * 
     * @param accumulator The command string currently visible to the user.
     * @return true if synchronization occurred.
     */
    bool Engine::sync_history_to_shell(std::string& accumulator) {
        if ((synced_with_shell_ && !history_navigated_) || accumulator.empty() || accumulator.starts_with(":")) {
            return false;
        }
        
        // Only require shell idle for local sessions (where it's reliable)
        if (!is_remote_session_ && !pty_.is_shell_idle()) {
            return false;
        }
        
        // Visual Cleanup: Move cursor left to start of command
        // Fish-only: Skip these escape sequences - Fish's prompt repainting conflicts with them
        if (!is_fish_) {
            std::cout << "\x1b[" << accumulator.size() << "D\x1b[K" << std::flush;
        }

        
        // Logical Injection: Kill line -> Send Text
        const char kill_line = kCtrlU;
        write(pty_.get_master_fd(), &kill_line, 1);
        write(pty_.get_master_fd(), accumulator.c_str(), accumulator.size());
        
        // Cursor Sync: If local cursor is not at end, send Left Arrows to match
        if (cursor_pos_ < accumulator.size()) {
            std::string left_arrows;
            for (size_t i = 0; i < accumulator.size() - cursor_pos_; ++i) {
                left_arrows += "\x1b[D";
            }
            write(pty_.get_master_fd(), left_arrows.c_str(), left_arrows.size());
        }

        history_navigated_ = false;
        synced_with_shell_ = true;
        return true;
    }

}
