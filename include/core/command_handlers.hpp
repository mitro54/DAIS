/**
 * @file command_handlers.hpp
 * @brief Output processing and formatting logic for intercepted shell commands.
 * * This file contains the logic to parse raw shell output (specifically 'ls'),
 * analyze the files mentioned, and reconstruct the output into a structured,
 * responsive grid with rich metadata (size, row counts, etc.).
 */

#pragma once

#include "core/file_analyzer.hpp"
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
        inline static std::string DIR_NAME  = "\x1b[1m\x1b[38;5;39m"; // Bold Blue (Unused on request, kept for config)
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
     * Fixes the "missing pipe |" bug caused by hidden shell control characters.
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
    // FORMATTERS
    // ==================================================================================

    /** @brief Formats byte counts into human-readable strings (B, KB, MB) using Theme colors. */
    inline std::string fmt_size(uintmax_t bytes) {
        if (bytes < 1024) 
            return std::format("{}{}{}{}", Theme::VALUE, bytes, Theme::UNIT, "B");
        if (bytes < 1024 * 1024) 
            return std::format("{}{:.1f}{}{}", Theme::VALUE, bytes/1024.0, Theme::UNIT, "KB");
        return std::format("{}{:.1f}{}{}", Theme::VALUE, bytes/(1024.0*1024.0), Theme::UNIT, "MB");
    }

    /** @brief Formats row counts, adding a tilde (~) and specific color if the count is estimated. */
    inline std::string fmt_rows(size_t rows, bool estimated) {
        // Compensation for the observed overestimation (~9-10%)
        if (estimated) {
            rows = static_cast<size_t>(rows * 0.92);
        }
        std::string tilde = estimated ? std::string(Theme::ESTIMATE) + "~" : "";

        if (rows >= 1000000)
            return std::format("{}{}{:.1f}{}{}", tilde, Theme::VALUE, rows / 1000000.0, Theme::UNIT, "M R");
        if (rows >= 1000)
            return std::format("{}{}{:.1f}{}{}", tilde, Theme::VALUE, rows / 1000.0, Theme::UNIT, "k R");
        return std::format("{}{}{}{}{}", tilde, Theme::VALUE, rows, Theme::UNIT, " R");
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
     * 4. Format: Colors and structures the data based on the Theme.
     * 5. Layout: Arranges items into a responsive grid that fits the terminal width.
     * * @param raw_output The raw stdout captured from the shell.
     * @param cwd The current working directory (needed to resolve relative filenames).
     * @return The formatted, colorized grid string.
     */
    inline std::string handle_ls(std::string_view raw_output, const std::filesystem::path& cwd) {
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
        std::vector<GridItem> grid_items;
        bool first_token = true;

        for (const auto& item_raw : original_items) {
            // 1. Clean the filename (remove hidden shell codes)
            std::string clean_name = clean_filename(item_raw);
            
            // 2. Filter out artifacts and special entries
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

            // 3. Analyze File
            std::filesystem::path full_path = cwd / clean_name;
            auto stats = dais::utils::analyze_path(full_path.string());

            std::string display;

            // 4. Format based on Type
            if (stats.is_valid) {
                if (stats.is_dir) {
                    // DIRECTORY: "Name (DIR: 5 items)".
                    display = std::format("{}{}/ ({}{} {}{}{})", 
                        clean_name,
                        Theme::STRUCTURE, // /
                        Theme::VALUE, stats.item_count, 
                        Theme::UNIT, "items",
                        Theme::STRUCTURE // /
                    );
                } else {
                    // FILE: "Name (10KB, 50R, 80C)"
                    std::string info;
                    std::string size_str = fmt_size(stats.size_bytes);

                    if (stats.is_text) {
                        std::string row_str = fmt_rows(stats.rows, stats.is_estimated);
                        // Construct info string with Themed punctuation
                        info = std::format("{}{}, {}{}, {}{}{}{}", 
                            size_str, Theme::STRUCTURE, row_str, Theme::STRUCTURE,
                            Theme::VALUE, stats.max_cols, Theme::UNIT, " C");
                    } else {
                        info = size_str;
                    }

                    // Wrap info in parentheses
                    display = std::format("{} {}({}{})", 
                        clean_name,
                        Theme::STRUCTURE, info, Theme::STRUCTURE
                    );
                }
            } else {
                // If analysis failed (e.g. permission error), just show the name
                display = clean_name;
            }

            // Ensure coloring doesn't bleed
            display += Theme::RESET;
            grid_items.push_back({display, get_visible_length(display)});
        }

        if (grid_items.empty()) return "";

        // 5. Render Grid (Flex-wrap Layout)
        int term_width = get_terminal_width() - 2; 
        if (term_width < 10) term_width = 10; 

        std::string final_output;
        final_output.reserve(raw_output.size() * 5); 

        int current_line_len = 0;

        for (const auto& item : grid_items) {
            // " | " + Content + " | "
            // We use 4 extra chars for the borders/spacing logic below
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