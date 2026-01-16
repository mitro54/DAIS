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
        
        enum State { TEXT, ESCAPE, CSI, OSC }; // CSI: [...], OSC: ]...
        State state = TEXT;

        for (char c : s) {
            switch (state) {
                case TEXT:
                    if (c == '\x1b') state = ESCAPE;
                    else result += c;
                    break;
                
                case ESCAPE:
                    if (c == '[') state = CSI;
                    else if (c == ']') state = OSC;
                    else state = TEXT; // Unknown escape, abort
                    break;

                case CSI:
                    // Standard ANSI codes end with a letter (usually 'm' for color)
                    if (std::isalpha(c)) state = TEXT;
                    break;

                case OSC:
                    // OSC codes usually end with BEL (\x07) or ST (\x1b\)
                    // We treat BEL as the terminator for simplicity here.
                    if (c == '\x07') state = TEXT; 
                    break;
            }
        }
        return result;
    }

    /**
     * @brief Cleans a filename of invisible artifacts.
     * * Combines ANSI stripping with trimming of non-printable characters (whitespace, 
     * carriage returns) from the start and end of the string.
     * * @param raw The raw line captured from stdout.
     * @return A clean, filesystem-ready filename string.
     */
    inline std::string clean_filename(const std::string& raw) {
        std::string clean = strip_ansi(raw);
        
        // Trim non-graphic characters from the start (like \r, \n, \t, etc)
        clean.erase(clean.begin(), std::find_if(clean.begin(), clean.end(), [](unsigned char ch) {
            return std::isgraph(ch); // Keep only visible chars (isgraph includes letters, numbers, punctuation)
        }));

        // Trim from the end
        clean.erase(std::find_if(clean.rbegin(), clean.rend(), [](unsigned char ch) {
            return std::isgraph(ch);
        }).base(), clean.end());

        return clean;
    }

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
    // HANDLERS
    // ==================================================================================

    inline std::string handle_generic(std::string_view raw_output) {
        return std::string(raw_output);
    }

    /**
     * @brief Intercepts 'ls' output and reformats it into a rich data grid.
     * * Logic Flow:
     * 1. Parse Input: Reads the raw string line-by-line (relies on engine injecting 'ls -1').
     * 2. Clean: Removes ANSI codes and whitespace artifacts to get valid filenames.
     * 3. Analyze: Uses 'file_analyzer' to get metadata (size, rows, type).
     * 4. Format: Uses configurable templates to structure output.
     * 5. Layout: Arranges items into a responsive grid that fits the terminal width.
     * * @param raw_output The raw stdout captured from the shell.
     * @param cwd The current working directory (needed to resolve relative filenames).
     * @param formats The format templates loaded from config (or defaults).
     * @return The formatted, colorized grid string.
     */
    inline std::string handle_ls(
        std::string_view raw_output, 
        const std::filesystem::path& cwd,
        const LSFormats& formats
    ) {
        std::stringstream ss{std::string(raw_output)};
        std::string line;
        std::vector<std::string> original_items;
        
        // Use std::getline to parse line-by-line.
        // This works because the Engine injects ' -1' into the 'ls' command.
        while (std::getline(ss, line)) {
            // Remove carriage return if present (common in PTY output)
            if (!line.empty() && line.back() == '\r') line.pop_back();
            original_items.push_back(line);
        }

        if (original_items.empty()) return "";

        struct GridItem {
            std::string display_string;
            size_t visible_len;
        };
        
        // --- THREAD POOL ---
        // Pool is created per-ls call: 64 threads during execution, cleaned up after.
        // This maximizes parallelism for I/O-bound file scanning while avoiding
        // resource waste when idle.
        dais::core::utils::ThreadPool pool(64);

        std::vector<std::future<GridItem>> futures;
        std::vector<GridItem> grid_items;
        bool first_token = true;

        for (const auto& item_raw : original_items) {
            // 1. Clean the filename (remove hidden shell codes)
            std::string clean_name = clean_filename(item_raw);
            
            // 2. Filter out artifacts and special entries
            // NOTE: Filtering must happen synchronously to avoid spawning unnecessary threads
            if (first_token && (clean_name == "ls" || clean_name == "ls -1")) { 
                first_token = false; 
                continue; 
            }
            first_token = false;
            
            if (clean_name.empty() || 
                clean_name == "." || 
                clean_name == ".." || 
                clean_name == "-1") {
                continue;
            }

            // Enqueue Analysis Task to Thread Pool
            futures.push_back(pool.enqueue([clean_name, cwd, formats]() -> GridItem {
                // 3. Analyze File (Thread Safe)
                std::filesystem::path full_path = cwd / clean_name;
                auto stats = dais::utils::analyze_path(full_path.string());

                std::string display;

                // 4. Format based on Type using templates
                if (stats.is_valid) {
                    if (stats.is_dir) {
                        // DIRECTORY: Use directory template
                        display = apply_template(formats.directory, {
                            {"name", clean_name},
                            {"count", std::to_string(stats.item_count)}
                        });
                    } else {
                        // FILE: Use text_file, data_file, or binary_file template
                        std::string size_str = fmt_size(stats.size_bytes);

                        if (stats.is_text) {
                            std::string row_str = fmt_rows(stats.rows, stats.is_estimated);
                            
                            // Use data_file template for CSV/TSV/JSON files
                            if (stats.is_data) {
                                display = apply_template(formats.data_file, {
                                    {"name", clean_name},
                                    {"size", size_str},
                                    {"rows", row_str},
                                    {"cols", std::to_string(stats.max_cols)}
                                });
                            } else {
                                display = apply_template(formats.text_file, {
                                    {"name", clean_name},
                                    {"size", size_str},
                                    {"rows", row_str},
                                    {"cols", std::to_string(stats.max_cols)}
                                });
                            }
                        } else {
                            display = apply_template(formats.binary_file, {
                                {"name", clean_name},
                                {"size", size_str}
                            });
                        }
                    }
                } else {
                    // If analysis failed (e.g. permission error), use error template
                    display = apply_template(formats.error, {
                        {"name", clean_name}
                    });
                }

                // Ensure coloring doesn't bleed
                display += Theme::RESET;
                return {display, get_visible_length(display)};
            }));
        }

        // --- COLLECT RESULTS ---
        // Wait for workers to finish processing. 
        // Order is preserved because we pushed futures in order.
        for (auto& f : futures) {
            try {
                grid_items.push_back(f.get());
            } catch (...) {
                // Fallback in unlikely event of thread error, ignore item to prevent crash
            }
        }

        if (grid_items.empty()) return "";

        // 5. Render Grid
        int term_width = get_terminal_width() - 2; 
        if (term_width < 10) term_width = 10; 

        std::string final_output;
        final_output.reserve(raw_output.size() * 5); 

        int current_line_len = 0;

        for (const auto& item : grid_items) {
            // " | " + Content + " | "
            size_t cell_len = item.visible_len + 4; 
            int gap = (current_line_len > 0) ? 1 : 0;

            // Check if adding this item exceeds terminal width
            if (current_line_len + gap + cell_len > (size_t)term_width) {
                // Wrap to new line
                if (current_line_len > 0) final_output += "\r\n";
                
                final_output += std::format("{}|{} {} {}|{}", Theme::STRUCTURE, Theme::RESET, item.display_string, Theme::STRUCTURE, Theme::RESET);
                current_line_len = cell_len;
            } 
            else {
                // Append to current line
                if (current_line_len > 0) {
                    final_output += " "; 
                    current_line_len += 1;
                }
                final_output += std::format("{}|{} {} {}|{}", Theme::STRUCTURE, Theme::RESET, item.display_string, Theme::STRUCTURE, Theme::RESET);
                current_line_len += cell_len;
            }
        }

        return final_output;
    }
}