#pragma once
#include "core/session.hpp"
#include "core/command_handlers.hpp"
#include "core/thread_pool.hpp"
#include <pybind11/embed.h>
#include <atomic>
#include <string_view>
#include <string>
#include <vector>
#include <deque>
#include <filesystem>
#include <mutex>
#include <chrono>

namespace py = pybind11;

namespace dais::core {

    /**
     * @brief Application configuration loaded from config.py at startup.
     * 
     * All fields have sensible defaults and are overwritten if config.py
     * contains corresponding values. Some fields (ls_sort_*) can be
     * modified at runtime via internal commands like :ls.
     */
    struct Config {
        /// Whether to display the [-] logo prefix on each output line.
        bool show_logo = true;
        
        /// Shell prompt patterns used to detect when shell is waiting for input.
        std::vector<std::string> shell_prompts = {"$ ", "% ", "> ", "# ", "➜ ", "❯ "};
        
        // =====================================================================
        // LS FORMAT TEMPLATES
        // =====================================================================
        // Configurable templates for 'ls' output formatting.
        // 
        // Data placeholders: {name}, {size}, {rows}, {cols}, {count}
        // Color placeholders: {RESET}, {STRUCTURE}, {UNIT}, {VALUE}, {ESTIMATE}, {TEXT}, {SYMLINK}
        // 
        // Note: {size} and {rows} include embedded coloring internally.
        
        std::string ls_fmt_directory   = "{TEXT}{name}{STRUCTURE}/ ({VALUE}{count} {UNIT}items{STRUCTURE})";
        std::string ls_fmt_text_file   = "{TEXT}{name} {STRUCTURE}({size}{STRUCTURE}, {rows} {UNIT}R{STRUCTURE}, {VALUE}{cols} {UNIT}C{STRUCTURE})";
        std::string ls_fmt_data_file   = "{TEXT}{name} {STRUCTURE}({size}{STRUCTURE}, {rows} {UNIT}R{STRUCTURE}, {VALUE}{cols} {UNIT}C{STRUCTURE})";
        std::string ls_fmt_binary_file = "{TEXT}{name} {STRUCTURE}({size}{STRUCTURE})";
        std::string ls_fmt_error       = "{TEXT}{name}";
        
        // =====================================================================
        // LS SORT OPTIONS
        // =====================================================================
        // Runtime-modifiable via :ls command:
        //   :ls          - Show current settings
        //   :ls d        - Reset to defaults  
        //   :ls <by> [order] [dirs_first] - e.g., :ls size desc false
        //
        // These are loaded from config.py LS_SORT dictionary at startup.
        
        std::string ls_sort_by = "type";      ///< "name", "size", "type", "rows", "none"
        std::string ls_sort_order = "asc";    ///< "asc" or "desc"
        bool ls_dirs_first = true;            ///< Group directories before files
    };

    class Engine {
    public:
        Engine();
        ~Engine();
        void run();
        void load_extensions(const std::string& path);
        void load_configuration(const std::string& path);
        
        // Helper to allow main.cpp to resize window
        void resize_window(int rows, int cols) {
            pty_.resize(rows, cols, config_.show_logo);
        }

    private:
        PTYSession pty_;
        std::atomic<bool> running_;
        std::atomic<bool> at_line_start_{true};
        Config config_;
        std::filesystem::path shell_cwd_ = std::filesystem::current_path();

        // --- SHELL DETECTION (set once in constructor, read-only after) ---
        // These flags control shell-specific compatibility workarounds.
        // - is_complex_shell_: True for Zsh/Fish. Enables delayed logo injection after escapes.
        // - is_fish_: True for Fish only. Disables pass-through logo injection entirely.
        bool is_complex_shell_ = false;
        bool is_fish_ = false;
        
        // Active command being intercepted (protected by state_mutex_)
        std::string current_command_;
        
        // --- THREAD SAFETY ---
        std::mutex state_mutex_;

        // --- PASS-THROUGH MODE STATE (only accessed from forward_shell_output thread) ---
        std::string prompt_buffer_;            ///< Last ~100 chars for prompt detection
        int pass_through_esc_state_ = 0;       ///< ANSI escape sequence state machine (0=normal)
        
        // Singleton thread pool for parallel file analysis (used by ls handler)
        // Uses more threads than CPU cores because file analysis is I/O-bound (threads wait for disk)
        // Rule: max(hardware_concurrency * 4, 128) gives maximum parallelism for high-speed SSDs
        utils::ThreadPool thread_pool_{std::max(std::thread::hardware_concurrency() * 4, 128u)};

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
        
        // =====================================================================
        // SHELL STATE (Prompt-Based Detection)
        // =====================================================================
        // Track shell state based on events.
        // IDLE = at prompt (matches shell_prompts config), RUNNING = command executing.
        
        enum class ShellState { IDLE, RUNNING };
        std::atomic<ShellState> shell_state_{ShellState::IDLE};
        std::chrono::steady_clock::time_point last_command_time_;  ///< Debounce timer
        
        // =====================================================================
        // COMMAND HISTORY (File-Based + Arrow Navigation)
        // =====================================================================
        // DAIS-managed history persisted to ~/.dais_history.
        // Arrow keys navigate DAIS history when shell is IDLE.
        // Shows original commands (e.g., 'ls' not 'ls -1').
        
        std::deque<std::string> command_history_;   ///< In-memory buffer
        std::filesystem::path history_file_;        ///< ~/.dais_history
        size_t history_index_ = 0;                  ///< Current position in history
        std::string history_stash_;                 ///< Stashes current line when navigating
        bool history_navigated_ = false;            ///< True if arrow navigation was used
        bool skipping_osc_ = false;                 ///< True if we are in the middle of skipping an OSC sequence
        static constexpr size_t MAX_HISTORY = 1000; ///< Max stored commands (like bash)
        
        void load_history();                        ///< Load from file on startup
        void save_history_entry(const std::string& cmd);  ///< Append to file
        void show_history(const std::string& args); ///< Handle :history command
        void navigate_history(int direction, std::string& current_line); ///< Arrow key nav
    };
}