/**
 * @file command_handlers.hpp
 * @brief Output processing and formatting logic for intercepted shell commands.
 * 
 * This module provides the core logic for specialized command handling in DAIS.
 * It currently focuses on the `ls` command, providing a high-performance,
 * parallelized, and visibly pleasing alternative to the standard GNU/BSD ls.
 * 
 * It also defines the global `Theme` structure used throughout the application
 * to ensure consistent coloring and formatting.
 */

#pragma once

#include "core/file_analyzer.hpp"
#include "core/thread_pool.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <unordered_map>

namespace dais::core::handlers {

    // ==================================================================================
    // THEME CONFIGURATION
    // ==================================================================================
    
    /**
     * @brief Centralized color palette using ANSI escape codes.
     * * These values are initialized with defaults but are intended to be overwritten 
     * by the Engine at runtime using values from 'config.py'.
     * Using 'inline static' allows these to serve as mutable global state 
     * without needing an instance passed around everywhere.
     */
    struct Theme {
        // --- Content Styling ---
        inline static std::string RESET     = "\x1b[0m";
        inline static std::string STRUCTURE = "\x1b[38;5;240m"; // Dark Gray (Borders, Parens)
        inline static std::string UNIT      = "\x1b[38;5;109m"; // Sage Blue (KB, MB, DIR label)
        inline static std::string VALUE     = "\x1b[0m";        // Default White (Numbers, Filenames)
        inline static std::string ESTIMATE  = "\x1b[38;5;139m"; // Muted Purple (Tilde ~)
        inline static std::string TEXT      = "\x1b[0m";        // Default White (Directories)
        inline static std::string SYMLINK   = "\x1b[38;5;36m";  // Cyan (Symlinks)
        
        // --- Engine / System Messages ---
        inline static std::string LOGO      = "\x1b[95m";       // Pink (DAIS Logo)
        inline static std::string SUCCESS   = "\x1b[92m";       // Green
        inline static std::string WARNING   = "\x1b[93m";       // Yellow
        inline static std::string ERROR     = "\x1b[91m";       // Red
        inline static std::string NOTICE    = "\x1b[94m";       // Blue
    };

    // ==================================================================================
    // LS FORMAT TEMPLATES & CONFIG
    // ==================================================================================

    /**
     * @brief Templates for rendering individual file entries in the grid.
     * 
     * Supports placeholder substitution (e.g., `{name}`, `{size}`) and
     * embedded color keys (e.g., `{STRUCTURE}`).
     */
    struct LSFormats {
        std::string directory   = "{TEXT}{name}{STRUCTURE}/ ({VALUE}{count} {UNIT}items{STRUCTURE})";
        std::string text_file   = "{TEXT}{name} {STRUCTURE}({VALUE}{size}{STRUCTURE}, {VALUE}{rows} {UNIT}R{STRUCTURE}, {VALUE}{cols} {UNIT}C{STRUCTURE})";
        std::string data_file   = "{TEXT}{name} {STRUCTURE}({VALUE}{size}{STRUCTURE}, {VALUE}{rows} {UNIT}R{STRUCTURE}, {VALUE}{cols} {UNIT}C{STRUCTURE})";
        std::string binary_file = "{TEXT}{name} {STRUCTURE}({VALUE}{size}{STRUCTURE})";
        std::string error       = "{TEXT}{name}";
    };

    /**
     * @brief Configuration for sorting directory listings.
     * Can be modified at runtime via `:ls <sort_by>`.
     */
    struct LSSortConfig {
        std::string by = "type";      ///< Sort key: "name", "size", "type", "rows"
        std::string order = "asc";    ///< "asc" or "desc"
        bool dirs_first = true;       ///< If true, directories always appear before files
        std::string flow = "h";       ///< Grid flow: "h" (horizontal, row-major) or "v" (vertical, column-major)
    };

    /**
     * @brief container for parsed arguments from the `ls` command.
     */
    struct LSArgs {
        bool show_hidden = false;       ///< -a / --all flag
        bool supported = true;          ///< True if no unsupported flags (like -l) were passed
        int padding = 4;                ///< Visual padding between grid columns
        std::vector<std::string> paths; ///< Target paths to list (default: ".")
    };

    // ==================================================================================
    // PUBLIC API
    // ==================================================================================

    /**
     * @brief Parses raw command line arguments into structured LSArgs.
     * 
     * Handles standard flags like `-a`. Detects unsupported flags to fallback
     * to the native shell's `ls`.
     * @param input The full command string (e.g., "ls -a /tmp").
     * @return LSArgs Struct with parsed flags and paths.
     */
    LSArgs parse_ls_args(const std::string& input);

    /**
     * @brief Executes the `ls` logic on the local filesystem.
     * 
     * Uses a thread pool to perform parallel analysis of files (size calculation,
     * content heuristics) for maximum performance on large directories.
     * 
     * @param args Parsed arguments (paths, flags).
     * @param cwd Current working directory of the shell.
     * @param formats Format templates to use.
     * @param sort_cfg Sorting preferences.
     * @param pool Thread pool for parallel execution.
     * @return A fully rendered ANSI string representing the grid.
     */
    std::string native_ls(
        const LSArgs& args,
        const std::filesystem::path& cwd,
        const LSFormats& formats,
        const LSSortConfig& sort_cfg,
        utils::ThreadPool& pool
    );

    /**
     * @brief Renders `ls` results from a remote JSON source.
     * 
     * When running via SSH, the remote agent returns JSON data. This function
     * takes that JSON and renders it using the *local* theme and formatting
     * preferences, ensuring a consistent experience across local and remote sessions.
     * 
     * @param json_output The raw JSON string from the remote agent.
     * @param formats Local format templates.
     * @param sort_cfg Local sort configuration.
     * @param padding padding to use.
     * @return Rendered grid string.
     */
    std::string render_remote_ls(
        const std::string& json_output,
        const LSFormats& formats,
        const LSSortConfig& sort_cfg,
        int padding
    );

    // --- Format Helpers ---
    // Exposed for consistency if other modules need to format sizes/counts
    
    /** @brief Formats bytes into human-readable B/KB/MB/GB string with color. */
    std::string fmt_size(uintmax_t bytes);
    
    /** @brief Formats row counts, adding a tilde for estimates (e.g. "~1.2k"). */
    std::string fmt_rows(size_t rows, bool estimated);

} // namespace dais::core::handlers
