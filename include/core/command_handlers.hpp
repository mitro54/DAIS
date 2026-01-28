/**
 * @file command_handlers.hpp
 * @brief Output processing and formatting logic for intercepted shell commands.
 * * This file contains the logic to parse raw shell output (specifically 'ls'),
 * analyze the files mentioned, and reconstruct the output into a structured,
 * responsive grid with rich metadata (size, row counts, etc.).
 */

#pragma once

#include "core/file_analyzer.hpp"
#include "core/thread_pool.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <format>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cctype>
#include <future> // std::async and std::future
#include <unordered_map>
#include <regex> 

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
    // HELPERS
    // ==================================================================================

    /** * @brief Retrieves the current terminal window width.
     * @return Number of columns (e.g., 80, 120). Defaults to 80 on error.
     */
    inline int get_terminal_width() {
        struct winsize w;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1) return 80;
        return w.ws_col;
    }

    /** * @brief Calculates the visible length of a string, ignoring ANSI escape codes.
     * * Essential for grid layout calculations. If we counted ANSI codes as length,
     * colored strings would be treated as very long, breaking alignment.
     * * @param s The string containing potential color codes.
     * @return The number of printable characters.
     */
    inline size_t get_visible_length(std::string_view s) {
        size_t len = 0;
        bool in_esc_seq = false;
        for (char c : s) {
            if (c == '\x1b') in_esc_seq = true;
            else if (in_esc_seq) {
                // End of standard ANSI (m, K, H) or ST (\)
                if (std::isalpha(c) || c == '\\') in_esc_seq = false;
            } else {
                len++;
            }
        }
        return len;
    }

    /** * @brief Robust ANSI stripper / sanitizing state machine.
     * * Handles complex CSI (\x1b[...m) and basic OSC (\x1b]...) codes.
     * This is critical because shells often emit hidden codes (like window title updates)
     * right before file listings, which can corrupt filename detection if not stripped.
     * * @param s Raw output string from the shell.
     * @return Clean string with only text.
     */
    inline std::string strip_ansi(std::string_view s) {
        std::string result;
        result.reserve(s.size());
        
        enum State { TEXT, ESCAPE, CSI, OSC, CHARSET }; 
        State state = TEXT;

        for (size_t i = 0; i < s.size(); ++i) {
            char c = s[i];
            switch (state) {
                case TEXT:
                    if (c == '\x1b') state = ESCAPE;
                    else result += c;
                    break;
                
                case ESCAPE:
                    if (c == '[') state = CSI;
                    else if (c == ']') state = OSC;
                    else if (c == '(' || c == ')') state = CHARSET; // G0/G1 Charset Selection
                    else state = TEXT; 
                    break;

                case CHARSET:
                    // Charset selection is ESC ( X. Just consume X.
                    // Fish/CMake often use this (e.g., \x1b(B to reset to US ASCII).
                    // If not stripped, it corrupts filenames (e.g., "BCMakeCache.txt").
                    state = TEXT;
                    break;

                case CSI:
                    if (std::isalpha(c)) state = TEXT;
                    break;

                case OSC:
                    // OSC codes end with BEL (\x07) or ST (\x1b\)
                    // ST termination is critical for modern shells like Fish setting window titles.
                    // Without this check, the parser eats the rest of the file content.
                    if (c == '\x07') {
                        state = TEXT; 
                    } else if (c == '\x1b' && i + 1 < s.size() && s[i+1] == '\\') {
                        state = TEXT;
                        i++; // Skip the backslash
                    }
                    break;
            }
        }
        return result;
    }

    /**
     * @brief Cleans a filename of invisible artifacts.
     * Combines ANSI stripping, trimming, and shell quote/escape handling.
     * @param raw The raw line captured from stdout.
     * @return A clean, filesystem-ready filename string.
     */


    // ==================================================================================
    // LS FORMAT TEMPLATES
    // ==================================================================================

    /**
     * @brief Holds format template strings for ls output.
     * Passed to handle_ls() to allow user customization via config.py.
     * 
     * Available placeholders:
     *   {name}  - filename or directory name
     *   {size}  - formatted size (e.g., "10KB")
     *   {rows}  - row count (e.g., "50" or "~1.2k")
     *   {cols}  - max column width
     *   {count} - item count (directories only)
     * 
     * Color placeholders (replaced with Theme values):
     *   {RESET}, {STRUCTURE}, {UNIT}, {VALUE}, {ESTIMATE}, {TEXT}, {SYMLINK}
     */
    struct LSFormats {
        // Default templates
        // Note: {size} includes VALUE/UNIT coloring, {rows} includes ESTIMATE coloring for ~
        std::string directory   = "{TEXT}{name}{STRUCTURE}/ ({VALUE}{count} {UNIT}items{STRUCTURE})";
        std::string text_file   = "{TEXT}{name} {STRUCTURE}({VALUE}{size}{STRUCTURE}, {VALUE}{rows} {UNIT}R{STRUCTURE}, {VALUE}{cols} {UNIT}C{STRUCTURE})";
        std::string data_file   = "{TEXT}{name} {STRUCTURE}({VALUE}{size}{STRUCTURE}, {VALUE}{rows} {UNIT}R{STRUCTURE}, {VALUE}{cols} {UNIT}C{STRUCTURE})";
        std::string binary_file = "{TEXT}{name} {STRUCTURE}({VALUE}{size}{STRUCTURE})";
        std::string error       = "{TEXT}{name}";
    };

    /**
     * @brief Configuration for LS output sorting.
     * 
     * Passed to handle_ls() to control the order of displayed items.
     * Uses std::sort with a custom comparator (introsort) for guaranteed
     * O(n log n) performance, suitable for directories with 10,000+ files.
     * 
     * Modifiable at runtime via :ls command:
     * - :ls          → Show current settings
     * - :ls d        → Reset to defaults
     * - :ls size desc false → Sort by size, descending, dirs mixed with files
     */
    struct LSSortConfig {
        std::string by = "type";     ///< Sort criterion: "name", "size", "type", "rows", "none"
        std::string order = "asc";   ///< Sort direction: "asc" or "desc"
        bool dirs_first = true;      ///< If true, directories always appear before files
        std::string flow = "h";      ///< "h" (horizontal) or "v" (vertical)
    };

    /**
     * @brief Applies placeholder substitution to a format template.
     * Substitutes both data placeholders ({name}, {size}, etc.) and 
     * color placeholders ({STRUCTURE}, {VALUE}, etc.).
     * @param tmpl The template string with {placeholder} syntax.
     * @param vars Map of placeholder names to their replacement values.
     * @return The formatted string with all placeholders substituted.
     */
    inline std::string apply_template(
        const std::string& tmpl,
        const std::unordered_map<std::string, std::string>& vars
    ) {
        std::string result = tmpl;
        
        // First, substitute color placeholders from Theme
        const std::unordered_map<std::string, std::string> colors = {
            {"RESET", Theme::RESET},
            {"STRUCTURE", Theme::STRUCTURE},
            {"UNIT", Theme::UNIT},
            {"VALUE", Theme::VALUE},
            {"ESTIMATE", Theme::ESTIMATE},
            {"TEXT", Theme::TEXT},
            {"SYMLINK", Theme::SYMLINK}
        };
        
        for (const auto& [key, value] : colors) {
            std::string placeholder = "{" + key + "}";
            size_t pos;
            while ((pos = result.find(placeholder)) != std::string::npos) {
                result.replace(pos, placeholder.length(), value);
            }
        }
        
        // Then substitute data placeholders
        for (const auto& [key, value] : vars) {
            std::string placeholder = "{" + key + "}";
            size_t pos;
            while ((pos = result.find(placeholder)) != std::string::npos) {
                result.replace(pos, placeholder.length(), value);
            }
        }
        return result;
    }

    // ==================================================================================
    // FORMATTERS
    // ==================================================================================

    /** 
     * @brief Formats byte counts into human-readable strings (e.g., "10B", "1.5KB", "2.3MB", "1.1GB").
     * Includes Theme::VALUE color for the number and Theme::UNIT color for the suffix.
     */
    inline std::string fmt_size(uintmax_t bytes) {
        if (bytes < 1024) 
            return std::format("{}{}{}B", Theme::VALUE, bytes, Theme::UNIT);
        if (bytes < 1024 * 1024) 
            return std::format("{}{:.1f}{}KB", Theme::VALUE, bytes/1024.0, Theme::UNIT);
        if (bytes < 1024 * 1024 * 1024)
            return std::format("{}{:.1f}{}MB", Theme::VALUE, bytes/(1024.0*1024.0), Theme::UNIT);
        return std::format("{}{:.1f}{}GB", Theme::VALUE, bytes/(1024.0*1024.0*1024.0), Theme::UNIT);
    }

    /** 
     * @brief Formats row counts (e.g., "50", "~1.2k", "~2.5M").
     * Returns raw value without "R" suffix - formatting controlled via templates.
     * Adds colored tilde (~) prefix for estimated values using Theme::ESTIMATE.
     */
    inline std::string fmt_rows(size_t rows, bool estimated) {
        // Compensation for the observed overestimation (~9-10%)
        if (estimated) {
            rows = static_cast<size_t>(rows * 0.92);
        }
        // Tilde is colored with ESTIMATE color for visual distinction
        std::string tilde = estimated ? Theme::ESTIMATE + "~" + Theme::VALUE : "";

        if (rows >= 1000000)
            return std::format("{}{:.1f}M", tilde, rows / 1000000.0);
        if (rows >= 1000)
            return std::format("{}{:.1f}k", tilde, rows / 1000.0);
        return std::format("{}{}", tilde, rows);
    }

    // ==================================================================================
    // NATIVE LS IMPLEMENTATION
    // ==================================================================================
    
    /**
     * @brief Parsed arguments for ls command.
     * 
     * Supports common flags: -a (show hidden), -l (long format - future).
     * Multiple paths can be specified.
     */
    struct LSArgs {
        bool show_hidden = false;   ///< -a or --all flag
        bool supported = true;      ///< If false, flags are too complex for native ls
        int padding = 4;            ///< Grid padding (spaces between columns)
        std::vector<std::string> paths;  ///< Target directories/files
    };
    
    /**
     * @brief Parses ls command arguments from user input.
     * Identifies if the command can be handled natively.
     * Only supports: ls, ls -a, ls --all, and paths.
     * Anything else (e.g., -l, -R, -t) marks supported=false.
     */
    inline LSArgs parse_ls_args(const std::string& input) {
        LSArgs args;
        std::istringstream iss(input);
        std::string token;
        
        iss >> token; // Skip "ls" command itself
        
        while (iss >> token) {
            if (token == "-a" || token == "--all") {
                args.show_hidden = true;
            } else if (token.starts_with("-")) {
                // Any other flag (-l, -R, -t, etc.) is not supported natively.
                // We mark it as unsupported so the engine falls back to the shell.
                args.supported = false;
                return args; 
            } else {
                args.paths.push_back(token);
            }
        }
        
        // Default to current directory if no paths specified
        if (args.paths.empty()) {
            args.paths.push_back("");
        }
        
        return args;
    }
    
    /**
     * @brief Lists directory contents using native std::filesystem APIs.
     * 
     * This replaces the shell-based ls interception with direct filesystem access.
     * Benefits:
     * - No shell compatibility issues (Fish aliases, Zsh colors)
     * - Faster (no process spawn, no PTY I/O)
     * - Robust filename handling (no text parsing)
     * 
     * @param args Parsed ls arguments (paths, flags)
     * @param cwd Current working directory for relative path resolution
     * @param formats Format templates for output styling
     * @param sort_cfg Sorting configuration
     * @param pool Thread pool for parallel file analysis
     * @return Formatted grid string ready for display
     */
    inline std::string native_ls(
        const LSArgs& args,
        const std::filesystem::path& cwd,
        const LSFormats& formats,
        const LSSortConfig& sort_cfg,
        utils::ThreadPool& pool
    ) {
        // GridItem structure for collecting file data
        struct GridItem {
            std::string name;
            dais::utils::FileStats stats;
            std::string display_string;
            size_t visible_len = 0;
        };
        
        std::vector<std::future<GridItem>> futures;
        std::vector<GridItem> grid_items;
        
        // Process each target path
        for (const auto& target : args.paths) {
            std::filesystem::path dir_path = target.empty() ? cwd : cwd / target;
            
            // Handle if target is an absolute path
            if (!target.empty() && std::filesystem::path(target).is_absolute()) {
                dir_path = target;
            }
            
            try {
                // Check if path exists
                if (!std::filesystem::exists(dir_path)) {
                    // Return error message for non-existent path
                    return Theme::ERROR + "ls: cannot access '" + target + "': No such file or directory" + Theme::RESET + "\r\n";
                }
                
                // If it's a file, just analyze that file
                if (!std::filesystem::is_directory(dir_path)) {
                    futures.push_back(pool.enqueue([dir_path]() -> GridItem {
                        auto stats = dais::utils::analyze_path(dir_path.string());
                        return {dir_path.filename().string(), stats, "", 0};
                    }));
                    continue;
                }
                
                // Iterate directory
                for (const auto& entry : std::filesystem::directory_iterator(dir_path)) {
                    std::string name = entry.path().filename().string();
                    
                    // Filter hidden files (starting with .) unless -a flag
                    if (!args.show_hidden && !name.empty() && name[0] == '.') {
                        continue;
                    }
                    
                    // Skip . and .. explicitly
                    if (name == "." || name == "..") {
                        continue;
                    }
                    
                    // Enqueue parallel file analysis
                    std::filesystem::path full_path = entry.path();
                    futures.push_back(pool.enqueue([name, full_path]() -> GridItem {
                        auto stats = dais::utils::analyze_path(full_path.string());
                        return {name, stats, "", 0};
                    }));
                }
            } catch (const std::filesystem::filesystem_error& e) {
                return Theme::ERROR + "ls: " + e.what() + Theme::RESET + "\r\n";
            }
        }
        
        // Collect results from futures
        for (auto& f : futures) {
            try {
                grid_items.push_back(f.get());
            } catch (...) {
                // Ignore failed analysis
            }
        }
        
        if (grid_items.empty()) {
            return ""; // Empty directory
        }
        
        // --- SORTING ---
        // Apply user-configured sorting (same logic as handle_ls)
        auto get_type_priority = [](const GridItem& item) -> int {
            if (item.stats.is_dir) return 0;
            if (item.stats.is_text || item.stats.is_data) return 1;
            return 2; // binary
        };
        
        std::sort(grid_items.begin(), grid_items.end(), 
            [&](const GridItem& a, const GridItem& b) {
                // dirs_first takes priority
                if (sort_cfg.dirs_first) {
                    if (a.stats.is_dir != b.stats.is_dir) {
                        return a.stats.is_dir > b.stats.is_dir;
                    }
                }
                
                int cmp = 0;
                if (sort_cfg.by == "name") {
                    cmp = a.name.compare(b.name);
                } else if (sort_cfg.by == "size") {
                    cmp = (a.stats.size_bytes < b.stats.size_bytes) ? -1 : (a.stats.size_bytes > b.stats.size_bytes ? 1 : 0);
                } else if (sort_cfg.by == "type") {
                    cmp = get_type_priority(a) - get_type_priority(b);
                    if (cmp == 0) cmp = a.name.compare(b.name);
                } else if (sort_cfg.by == "rows") {
                    cmp = (a.stats.rows < b.stats.rows) ? -1 : (a.stats.rows > b.stats.rows ? 1 : 0);
                }
                
                return (sort_cfg.order == "desc") ? (cmp > 0) : (cmp < 0);
            }
        );
        
        // --- FORMAT EACH ITEM ---
        for (auto& item : grid_items) {
            std::unordered_map<std::string, std::string> vars;
            vars["name"] = item.name;
            vars["size"] = fmt_size(item.stats.size_bytes);
            vars["rows"] = fmt_rows(item.stats.rows, item.stats.is_estimated);
            vars["cols"] = std::to_string(item.stats.max_cols);
            vars["count"] = std::to_string(item.stats.item_count);
            
            std::string tmpl;
            if (item.stats.is_dir) {
                tmpl = formats.directory;
            } else if (item.stats.is_text) {
                tmpl = formats.text_file;
            } else if (item.stats.is_data) {
                tmpl = formats.data_file;
            } else {
                tmpl = formats.binary_file;
            }
            
            item.display_string = apply_template(tmpl, vars);
            item.visible_len = get_visible_length(item.display_string);
        }
        
        // --- GRID LAYOUT ---
        int term_width = get_terminal_width();
        size_t max_len = 0;
        for (const auto& item : grid_items) {
            max_len = std::max(max_len, item.visible_len);
        }
        
        /**
         * @brief Grid Column Calculation
         * 
         * Layout strategy:
         * - Each cell includes: "| " (prefix) + Content + Padding + "|" (suffix)
         * - Total width per cell = max_content + padding + 3 (borders/spacing)
         * - Padding is configurable via config.py (LS_PADDING)
         */
        
        // 1. Calculate usable width for content
        // We need 4 chars for row borders ("| " ... " |") + 3 chars per cell overhead
        // Use a 12-char safety margin to be extremely conservative against wrapping
        size_t safety_margin = 12;
        size_t safe_term_width = (static_cast<size_t>(term_width) > safety_margin) ? static_cast<size_t>(term_width) : 80;
        size_t max_possible_padding = 1;
        
        // Ensure even the longest file fits in one column with minimal overhead
        if (safe_term_width > (max_len + safety_margin)) {
            max_possible_padding = safe_term_width - max_len - safety_margin;
        }

        // 2. Clamp padding to valid range [1, max_possible]
        int effective_padding = std::max(1, args.padding);
        effective_padding = std::min(effective_padding, static_cast<int>(max_possible_padding));

        size_t col_width = max_len + effective_padding;     ///< Content width + user-defined padding
        size_t cell_width = col_width + 3;             ///< Total cell width incl. prefix "| " and suffix "|"
        size_t num_cols = std::max(1ul, (safe_term_width - 4) / cell_width);
        
        std::string output;
        
        // Calculate number of rows needed
        size_t total_items = grid_items.size();
        size_t num_rows = (total_items + num_cols - 1) / num_cols;  // Ceiling division
        
        // Helper lambda to render a single cell
        auto render_cell = [&](size_t item_idx) -> std::string {
            std::string cell;
            if (item_idx < grid_items.size()) {
                const auto& item = grid_items[item_idx];
                cell += item.display_string;
                size_t pad = (item.visible_len < col_width) ? (col_width - item.visible_len) : 1;
                cell += std::string(pad, ' ');
            } else {
                // Empty cell for incomplete last row
                cell += std::string(col_width, ' ');
            }
            return cell;
        };
        
        // Build output row by row
        for (size_t row = 0; row < num_rows; ++row) {
            output += Theme::STRUCTURE + "| " + Theme::RESET;
            
            for (size_t col = 0; col < num_cols; ++col) {
                size_t item_idx;
                if (sort_cfg.flow == "v") {
                    // Vertical flow: items go down columns first
                    item_idx = col * num_rows + row;
                } else {
                    // Horizontal flow (default): items go across rows first
                    item_idx = row * num_cols + col;
                }
                
                if (item_idx < total_items) {
                    output += render_cell(item_idx);
                    output += Theme::STRUCTURE + "|" + Theme::RESET;
                    
                    // Add space between cells except at end of row
                    if (col < num_cols - 1 && (row * num_cols + col + 1) < total_items) {
                        output += " ";
                    }
                }
            }
            output += "\r\n";
        }
        
        return output;
    }

    /**
     * @brief Renders the remote LS JSON output into the standard grid format.
     * Uses regex to parse the JSON (since it's a simple flat structure) to avoid JSON deps.
     */
    inline std::string render_remote_ls(
        const std::string& json_output,
        const LSFormats& formats,
        const LSSortConfig& sort_cfg,
        int padding
    ) {
        // GridItem structure 
        struct GridItem {
            std::string name;
            dais::utils::FileStats stats;
            std::string display_string;
            size_t visible_len = 0;
        };
        std::vector<GridItem> grid_items;

        // Simple Regex for: {"name":"foo","is_dir":true,"size":123,...}
        // This is fragile but suffices for our strictly controlled agent output.
        // Group 1: name, 2: is_dir, 3: size, 4: rows, 5: cols, 6: count, 7: text, 8: data, 9: est
        std::regex re(R"(\"name\":\"(.*?)\",\"is_dir\":(true|false),\"size\":(\d+),\"rows\":(\d+),\"cols\":(\d+),\"count\":(\d+),\"is_text\":(true|false),\"is_data\":(true|false),\"is_estimated\":(true|false))");
        
        auto begin = std::sregex_iterator(json_output.begin(), json_output.end(), re);
        auto end = std::sregex_iterator();

        for (std::sregex_iterator i = begin; i != end; ++i) {
            std::smatch match = *i;
            GridItem item;
            item.name = match[1].str();
            
            // Unescape name (basic backslash handling)
            // Note: In a full impl we'd handle \uXXXX, here we trust the agent to be mostly sane
            // or just assume UTF8 pass-through.
            
            item.stats.is_dir = (match[2].str() == "true");
            item.stats.size_bytes = std::stoull(match[3].str());
            item.stats.rows = std::stoull(match[4].str());
            item.stats.max_cols = std::stoull(match[5].str());
            item.stats.item_count = std::stoull(match[6].str());
            item.stats.is_text = (match[7].str() == "true");
            item.stats.is_data = (match[8].str() == "true");
            item.stats.is_estimated = (match[9].str() == "true");
            
            grid_items.push_back(item);
        }

        if (grid_items.empty()) return "";

        // --- SORTING (Copy-Paste from native_ls, can be refactored) ---
        auto get_type_priority = [](const GridItem& item) -> int {
            if (item.stats.is_dir) return 0;
            if (item.stats.is_text || item.stats.is_data) return 1;
            return 2; // binary
        };
        
        std::sort(grid_items.begin(), grid_items.end(), 
            [&](const GridItem& a, const GridItem& b) {
                if (sort_cfg.dirs_first) {
                    if (a.stats.is_dir != b.stats.is_dir) {
                        return a.stats.is_dir > b.stats.is_dir;
                    }
                }
                
                int cmp = 0;
                if (sort_cfg.by == "name") {
                    cmp = a.name.compare(b.name);
                } else if (sort_cfg.by == "size") {
                    cmp = (a.stats.size_bytes < b.stats.size_bytes) ? -1 : (a.stats.size_bytes > b.stats.size_bytes ? 1 : 0);
                } else if (sort_cfg.by == "type") {
                    cmp = get_type_priority(a) - get_type_priority(b);
                    if (cmp == 0) cmp = a.name.compare(b.name);
                } else if (sort_cfg.by == "rows") {
                    cmp = (a.stats.rows < b.stats.rows) ? -1 : (a.stats.rows > b.stats.rows ? 1 : 0);
                }
                
                return (sort_cfg.order == "desc") ? (cmp > 0) : (cmp < 0);
            }
        );

        // --- FORMAT ---
        for (auto& item : grid_items) {
            std::unordered_map<std::string, std::string> vars;
            vars["name"] = item.name;
            vars["size"] = fmt_size(item.stats.size_bytes);
            vars["rows"] = fmt_rows(item.stats.rows, item.stats.is_estimated);
            vars["cols"] = std::to_string(item.stats.max_cols);
            vars["count"] = std::to_string(item.stats.item_count);
            
            std::string tmpl;
            if (item.stats.is_dir) {
                tmpl = formats.directory;
            } else if (item.stats.is_text) {
                tmpl = formats.text_file;
            } else if (item.stats.is_data) {
                tmpl = formats.data_file;
            } else {
                tmpl = formats.binary_file;
            }
            
            item.display_string = apply_template(tmpl, vars);
            item.visible_len = get_visible_length(item.display_string);
        }

        // --- LAYOUT ---
        // (Simplified copy of native_ls layout logic)
        int term_width = get_terminal_width();
        size_t max_len = 0;
        for (const auto& item : grid_items) max_len = std::max(max_len, item.visible_len);
        
        size_t safety_margin = 12;
        size_t safe_term_width = (static_cast<size_t>(term_width) > safety_margin) ? static_cast<size_t>(term_width) : 80;
        size_t max_possible_padding = 1;
        if (safe_term_width > (max_len + safety_margin)) {
            max_possible_padding = safe_term_width - max_len - safety_margin;
        }

        // Use user-configured padding
        int effective_padding = padding; 
        effective_padding = std::min(effective_padding, static_cast<int>(max_possible_padding));
        
        size_t col_width = max_len + effective_padding;
        size_t cell_width = col_width + 3;
        size_t num_cols = std::max(1ul, (safe_term_width - 4) / cell_width);
        
        std::string output;
        size_t total_items = grid_items.size();
        size_t num_rows = (total_items + num_cols - 1) / num_cols;
        
        // Helper lambda to render a single cell
        auto render_cell = [&](size_t item_idx) -> std::string {
            std::string cell;
            if (item_idx < grid_items.size()) {
                const auto& item = grid_items[item_idx];
                cell += item.display_string;
                size_t pad = (item.visible_len < col_width) ? (col_width - item.visible_len) : 1;
                cell += std::string(pad, ' ');
            } else {
                cell += std::string(col_width, ' ');
            }
            return cell;
        };

        for (size_t row = 0; row < num_rows; ++row) {
            output += Theme::STRUCTURE + "| " + Theme::RESET;
            for (size_t col = 0; col < num_cols; ++col) {
                size_t item_idx;
                if (sort_cfg.flow == "v") item_idx = col * num_rows + row;
                else item_idx = row * num_cols + col;
                
                if (item_idx < total_items) {
                    output += render_cell(item_idx);
                    output += Theme::STRUCTURE + "|" + Theme::RESET;
                    if (col < num_cols - 1 && (row * num_cols + col + 1) < total_items) output += " ";
                }
            }
            output += "\r\n";
        }
        return output;
    }
}
