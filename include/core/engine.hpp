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
        std::string recover_cmd_from_buffer(const std::string& raw_buffer);

        // --- THREAD SAFETY ---
        std::mutex state_mutex_;

        // --- PASS-THROUGH MODE STATE (only accessed from forward_shell_output thread) ---
        mutable std::mutex prompt_mutex_;      ///< Protects prompt_buffer_
        std::string prompt_buffer_;            ///< Last ~1024 chars for prompt/command detection
        int pass_through_esc_state_ = 0;       ///< ANSI escape sequence state machine (0=normal)
        
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
        bool tab_used_ = false;                      ///< True if Tab was used (accumulator unreliable)
        bool skipping_osc_ = false;                 ///< True if we are in the middle of skipping an OSC sequence
        std::atomic<bool> in_more_pager_{false};    ///< True when "--More--" is detected (for arrow key translation)
        static constexpr size_t MAX_HISTORY = 1000; ///< Max stored commands (like bash)
        
        void load_history();                        ///< Load from file on startup
        void save_history_entry(const std::string& cmd);  ///< Append to file
        void show_history(const std::string& args); ///< Handle :history command
        void navigate_history(int direction, std::string& current_line); ///< Arrow key nav
        
        /**
         * @brief Handles the execution of the :db command module.
         * Bridges C++ engine with Python db_handler.
         */
        void handle_db_command(const std::string& query);
        
        // =====================================================================
        // REMOTE SESSION STATE (SSH)
        // =====================================================================
        bool is_remote_session_ = false;       ///< True if foreground is ssh/scp
        bool remote_agent_deployed_ = false;   ///< True if we successfully injected the agent
        std::string remote_arch_ = "";         ///< Detected remote architecture (uname -m)
        std::chrono::steady_clock::time_point last_session_check_; /// Throttle remote checks

        void check_remote_session();           ///< Updates is_remote_session_ based on FG process
        void deploy_remote_agent();            ///< Injects binary if missing

        // =====================================================================
        // OUTPUT CAPTURING (For Remote Commands)
        // =====================================================================
        // Allows the main thread to capture PTY output temporarily.
        std::atomic<bool> capture_mode_ = false;
        std::string capture_buffer_;
        std::mutex capture_mutex_;
        std::condition_variable capture_cv_;
        
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