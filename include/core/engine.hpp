#pragma once
#include "core/session.hpp"
#include "core/command_handlers.hpp"
#include "core/thread_pool.hpp"
#include "core/dais_agents.hpp"
#include <pybind11/embed.h>
#include <condition_variable>
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
        std::string ls_flow = "h";            ///< "h" (horizontal) or "v" (vertical)
        int ls_padding = 4;                   ///< Grid padding (spaces between columns)

        // =====================================================================
        // DB CONFIG
        // =====================================================================
        std::string db_type = "sqlite";       ///< "sqlite" or "duckdb"
        std::string db_source = "";           ///< Path to DB file
        // Note: Saved queries are handled in Python to keep C++ simple
    };

    class Engine {
    public:
        // --- Input Tracking for Paste/Fast Type ---
        std::string input_accumulator_;
        std::mutex input_mutex_;
        
        // --- CONSTANTS ---
        static constexpr char kCtrlU = '\x15';     ///< Clear Line
        static constexpr char kCtrlC = '\x03';     ///< Interrupt
        static constexpr char kCtrlA = '\x01';     ///< Start of Line
        static constexpr char kCtrlK = '\x0b';     ///< Kill to End of Line
        static constexpr char kBell  = '\x07';     ///< Bell / Sentinel Marker
        static constexpr char kEsc   = '\x1b';     ///< Escape Character

        /**
         * @brief Constructs the DAIS Engine, detecting the shell environment.
         */
        Engine();

        /**
         * @brief Destructor. Ensures the child PTY process is terminated gracefully.
         */
        ~Engine();

        /**
         * @brief Main execution loop.
         * Blocks until the session ends (user types :q or shell exits).
         */
        void run();

        /**
         * @brief Scans a directory for Python scripts and loads them as modules.
         * @param path Absolute or relative path to the scripts folder.
         */
        void load_extensions(const std::string& path);

        /**
         * @brief Loads runtime configuration from a config.py file.
         * @param path Absolute path to config.py.
         */
        void load_configuration(const std::string& path);
        
        // Helper to allow main.cpp to resize window
        void resize_window(int rows, int cols) {
            terminal_cols_ = cols;
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

        /**
         * @brief Background thread: Reads PTY master -> Writes to Local Stdout.
         * Handles ANSI parsing, state synchronization, and output capture.
         */
        void forward_shell_output();

        /**
         * @brief Main thread: Reads Local Stdin -> Writes to PTY master.
         * Handles user input, command interception (ls, :db), history navigation,
         * and tab completion recovery.
         */
        void process_user_input();
        
        /**
         * @brief Recovers the user's typed command from the raw shell output buffer.
         * 
         * Simulates a robust terminal (handling ANSI color codes, cursor movements, and line clearing)
         * to reconstruct exactly what is visible on the screen.
         * Crucial for intercepting commands from shell history where input is echoed by the shell.
         * 
         * @param raw_buffer The raw PTY output buffer containing prompts, echoes, and control codes.
         * @return std::string The cleaned, reconstructed command string.
         */
        
        /**
         * @brief Execute DAIS internal commands (prefixed with ':')
         * 
         * @param cmd The cleaned command string (e.g., ":ls", ":db select * from t")
         * @param from_shell_echo If true, command was recovered from shell's echo output
         *        (e.g., history recall). Prevents double-echoing of the command.
         */
        void execute_internal_command(const std::string& cmd, bool from_shell_echo = false);

        // --- THREAD SAFETY ---
        std::mutex state_mutex_;
        mutable std::recursive_mutex terminal_mutex_;    ///< Synchronizes all writes to STDOUT_FILENO (Recursive for nested UI calls)

        // --- PASS-THROUGH MODE STATE (only accessed from forward_shell_output thread) ---
        mutable std::mutex prompt_mutex_;      ///< Protects prompt_buffer_
        std::string prompt_buffer_;            ///< Last ~1024 chars for prompt/command detection
        int pass_through_esc_state_ = 0;       ///< ANSI escape sequence state machine (0=normal)
        bool logo_injected_this_prompt_ = false; ///< Prevents multiple logos on the same prompt (e.g. multi-line)
        int expect_prompt_attempts_ = 0;       ///< Force logo injection for N attempts (bypass idle check)
        
        // Singleton thread pool for parallel file analysis (used by ls handler)
        // Uses more threads than CPU cores because file analysis is I/O-bound (threads wait for disk)
        // Rule: max(hardware_concurrency * 4, 128) gives maximum parallelism for high-speed SSDs
        utils::ThreadPool thread_pool_{std::max(std::thread::hardware_concurrency() * 4, 128u)};

        // python state
        py::scoped_interpreter guard{}; 
        std::vector<py::module_> loaded_plugins_;



        void trigger_python_hook(const std::string& hook_name, const std::string& data);

        /** * @brief Queries the OS to get the actual CWD of the child shell process.
         * Essential for handling TAB completion where input buffer doesn't match path.
         */
        void sync_child_cwd();
        
        /** @brief Resolves partial paths using fuzzy component matching.
         * Used to recover tab-completed paths from incomplete accumulator data.
         */
        std::filesystem::path resolve_partial_path(
            const std::string& partial, 
            const std::filesystem::path& cwd
        );
        
        // =====================================================================
        // SHELL STATE (Prompt-Based Detection)
        // =====================================================================
        // Track shell state based on events.
        // IDLE = at prompt (matches shell_prompts config), RUNNING = command executing.
        
        enum class ShellState { IDLE, RUNNING };
        std::atomic<ShellState> shell_state_{ShellState::IDLE};
        std::atomic<bool> synced_with_shell_{true};  ///< True if we are confident in shell state (False forces prompt hunt)
        bool first_prompt_seen_ = false;              ///< Startup logo logic
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
        std::atomic<bool> history_navigated_{false};///< True if arrow navigation was used
        std::atomic<bool> tab_used_{false};         ///< True if Tab was used (accumulator unreliable)
        bool skipping_osc_ = false;                 ///< True if we are in the middle of skipping an OSC sequence
        size_t cursor_pos_ = 0;                     ///< Index in input_accumulator_ for editable prompt
        std::atomic<int> terminal_cols_{80};        ///< Current terminal width
        int initial_prompt_cols_ = 0;              ///< Prompt width when visual mode started
        bool was_visual_mode_ = false;              ///< For detecting entry into visual mode
        bool bracketed_paste_active_ = false;       ///< True if we are inside a \e[200~ ... \e[201~ block
        std::string paste_accumulator_;             ///< Local buffer for pasted text
        std::atomic<bool> in_more_pager_{false};    ///< True when "--More--" is detected (for arrow key translation)
        static constexpr size_t MAX_HISTORY = 1000; ///< Max stored commands (like bash)
        
        bool is_internal_command(const std::string& line); ///< Helper to identify :commands
        void process_paste_block();                 ///< Handles dispatching of buffered paste data
        void visual_move_cursor(int old_pos, int new_pos); ///< Multi-line aware cursor movement
        int calculate_visual_length(const std::string& buffer); ///< Helper to get visual width of string
        void ensure_visual_mode_init(int offset_already_in_buffer = 0); ///< Safeguard for prompt width tracking
        
        void load_history();                        ///< Load from file on startup
        void save_history_entry(const std::string& cmd);  ///< Append to file

        struct CursorRecovery {
            std::string command;
            int cursor_idx;
        };
        CursorRecovery recover_cmd_from_buffer(const std::string& buffer); ///< Helper to recover command and cursor
        void show_history(const std::string& args); ///< Handle :history command
        void navigate_history(int direction, std::string& current_line); ///< Arrow key nav
        
        /**
         * @brief Syncs visual-only history content to the shell.
         * 
         * When user navigates DAIS history (Up/Down), changes are visual-only.
         * Before the shell can process edits (arrows, backspace, typing), we must
         * sync the content. This helper centralizes that logic.
         * 
         * @param accumulator The current command buffer to sync
         * @return true if sync was performed, false if not needed
         */
        bool sync_history_to_shell(std::string& accumulator);

        
        /**
         * @brief Handles the execution of the :db command module.
         * Bridges C++ engine with Python db_handler.
         */
        void handle_db_command(const std::string& query);
        
        // =====================================================================
        // REMOTE SESSION STATE (SSH)
        // =====================================================================
        std::atomic<bool> is_remote_session_{false};       ///< True if foreground is ssh/scp
        bool remote_agent_deployed_ = false;   ///< True if we successfully injected the agent
        std::string remote_arch_ = "";         ///< Detected remote architecture (uname -m)
        std::chrono::steady_clock::time_point last_session_check_; /// Throttle remote checks

        void check_remote_session();           ///< Updates is_remote_session_ based on FG process
        void deploy_remote_agent();            ///< Injects binary if missing

        int remote_session_pid_ = -1;          ///< PID of the current SSH process (for sticky detection)

        // =====================================================================
        // OUTPUT CAPTURING (For Remote Commands)
        // =====================================================================
        // Allows the main thread to capture PTY output temporarily.
        std::atomic<bool> capture_mode_ = false;
        std::string capture_buffer_;
        std::mutex capture_mutex_;
        std::condition_variable capture_cv_;
        
        // --- AUTO-DEPLOYMENT STATE ---
        std::atomic<bool> pending_remote_deployment_{false};
        std::atomic<bool> ready_to_deploy_{false};
        std::atomic<bool> in_alt_screen_{false};
        std::atomic<int> cached_prompt_width_{-1};    ///< Clean prompt width captured at IDLE to prevent cursor jumps from dirty buffers
        bool intentionally_cleared_{false};           ///< Prevents "ghost" history adoption when user explicitly clears the line
        std::string last_remote_prompt_;              ///< Stores the prompt swallowed by execute_remote_command for later restoration
        
        /**
         * @brief Executes a command on the remote shell and captures output.
         * Blocks until the end sentinel is found or timeout.
         */
        std::string execute_remote_command(const std::string& cmd, int timeout_ms = 2000);
        
        /**
         * @brief Handles the complex logic of intercepting and executing 'ls' on a remote host.
         * Incorporates agent deployment, fallback to Python, and output rendering.
         */
        void handle_remote_ls(const handlers::LSArgs& ls_args, const std::string& original_cmd);
        
        bool remote_db_deployed_ = false;       ///< True if db_handler.py is on remote
        void deploy_remote_db_handler();       ///< Injects python script if missing
        
        // =====================================================================
        // LESS PAGER AVAILABILITY (For Remote Sessions)
        // =====================================================================
        bool less_checked_ = false;             ///< True if we've checked for less
        bool less_available_ = true;            ///< True if less is available (default optimistic)
        
        /**
         * @brief Checks if 'less' is available on remote and offers to install if not.
         * @return True if less is available (or was installed), false to use cat fallback.
         */
        bool check_and_offer_less_install();
    };
}