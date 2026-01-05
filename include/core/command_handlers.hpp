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

namespace dash::core::handlers {

    // ==================================================================================
    // THEME CONFIGURATION
    // ==================================================================================
    
    /**
     * @brief Centralized color palette using ANSI 256-color codes.
     * Designed for a formal, IDE-like appearance (Slate/Sage tones).
     */
    struct Theme {
        static constexpr auto RESET     = "\x1b[0m";
        static constexpr auto STRUCTURE = "\x1b[38;5;240m"; // Dark Gray (Borders, Parentheses, Commas)
        static constexpr auto UNIT      = "\x1b[38;5;109m"; // Sage Blue (Units: KB, MB, DIR)
        static constexpr auto VALUE     = "\x1b[0m";        // Default White (Numerical Data)
        static constexpr auto ESTIMATE  = "\x1b[38;5;139m"; // Muted Purple (Tilde ~ for estimates)
    };

    // ==================================================================================
    // HELPERS
    // ==================================================================================

    /** @brief Returns current terminal width in columns, defaulting to 80 on failure. */
    inline int get_terminal_width() {
        struct winsize w;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1) return 80;
        return w.ws_col;
    }

    /** * @brief Calculates string length excluding invisible ANSI escape codes.
     * Essential for grid layout calculations to prevent misalignment.
     */
    inline size_t get_visible_length(std::string_view s) {
        size_t len = 0;
        bool in_esc_seq = false;
        for (char c : s) {
            if (c == '\x1b') in_esc_seq = true;
            else if (in_esc_seq) {
                if (std::isalpha(c)) in_esc_seq = false; // ANSI codes end with letters (e.g., 'm')
            } else {
                len++;
            }
        }
        return len;
    }

    /** @brief Returns a clean string with all ANSI codes removed. Used for filesystem lookups. */
    inline std::string strip_ansi(std::string_view s) {
        std::string result;
        result.reserve(s.size());
        bool in_esc_seq = false;
        for (char c : s) {
            if (c == '\x1b') in_esc_seq = true;
            else if (in_esc_seq) {
                if (std::isalpha(c)) in_esc_seq = false;
            } else {
                result += c;
            }
        }
        return result;
    }

    // ==================================================================================
    // FORMATTERS
    // ==================================================================================

    /** @brief Formats byte counts into human-readable strings (B, KB, MB) with Theme colors. */
    inline std::string fmt_size(uintmax_t bytes) {
        if (bytes < 1024) 
            return std::format("{}{}{}{}", Theme::VALUE, bytes, Theme::UNIT, "B");
        if (bytes < 1024 * 1024) 
            return std::format("{}{:.1f}{}{}", Theme::VALUE, bytes/1024.0, Theme::UNIT, "KB");
        return std::format("{}{:.1f}{}{}", Theme::VALUE, bytes/(1024.0*1024.0), Theme::UNIT, "MB");
    }

    /** @brief Formats row counts, adding a tilde (~) and specific color if estimated. */
    inline std::string fmt_rows(size_t rows, bool estimated) {
        std::string tilde = estimated ? std::string(Theme::ESTIMATE) + "~" : "";
        if (rows > 1000000) 
            return std::format("{}{}{:.1f}{}{}", tilde, Theme::VALUE, rows/1000000.0, Theme::UNIT, "M R");
        if (rows > 1000) 
            return std::format("{}{}{:.1f}{}{}", tilde, Theme::VALUE, rows/1000.0, Theme::UNIT, "k R");
        return std::format("{}{}{}{}{}", tilde, Theme::VALUE, rows, Theme::UNIT, " R");
    }

    // ==================================================================================
    // HANDLERS
    // ==================================================================================

    inline std::string handle_generic(std::string_view raw_output) {
        return std::string(raw_output);
    }

    /**
     * @brief Transforms 'ls' output into a responsive, rich-text grid.
     * * Pipeline:
     * 1. Tokenize output (splitting by NEWLINE for 'ls -1' compatibility).
     * 2. Clean ANSI codes from tokens to resolve actual file paths.
     * 3. Analyze file stats (size, type, rows).
     * 4. Apply Themed formatting.
     * 5. Render using a "Flex-wrap" layout algorithm to fit terminal width.
     */
    inline std::string handle_ls(std::string_view raw_output, const std::filesystem::path& cwd) {
        std::stringstream ss{std::string(raw_output)};
        std::string line;
        std::vector<std::string> original_items;
        
        // C++23: Use std::getline to respect whitespace in filenames (requires ls -1)
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

        // --- Processing Loop ---
        for (const auto& item_raw : original_items) {
            std::string clean_name = strip_ansi(item_raw);
            
            // Filters: Remove echoed command name and special directories
            // Since we use 'ls -1', the echo might appear as 'ls -1'
            if (first_token && (clean_name == "ls" || clean_name == "ls -1")) { 
                first_token = false; 
                continue; 
            }
            first_token = false;
            
            if (clean_name.empty() || 
                clean_name == "." || 
                clean_name == ".." || 
                clean_name == "ls" || 
                clean_name == "ls -1" || 
                clean_name == "-1" ||
                clean_name == " -1") {
                continue;
            }
            // Resolve Path & Analyze
            std::filesystem::path full_path = cwd / clean_name;
            auto stats = dash::utils::analyze_path(full_path.string());

            std::string display;

            // --- Formatting & Coloring ---
            if (stats.is_valid) {
                if (stats.is_dir) {
                    // DIRECTORY: "Name (DIR: 5 items)"
                    display = std::format("{} {}({}{}: {}{} {}{}{})", 
                        item_raw, 
                        Theme::STRUCTURE, // (
                        Theme::UNIT, "DIR", 
                        Theme::VALUE, stats.item_count, 
                        Theme::UNIT, "items", 
                        Theme::STRUCTURE // )
                    ); 
                } else {
                    // FILE: "Name (10KB, 50R, 80C)"
                    std::string info;
                    std::string size_str = fmt_size(stats.size_bytes);

                    if (stats.is_text) {
                        std::string row_str = fmt_rows(stats.rows, stats.is_estimated);
                        // Construct info string with Themed punctuation
                        info = std::format("{}{}, {}{}, {}{}{}{}", 
                            size_str, 
                            Theme::STRUCTURE, // Comma
                            row_str,
                            Theme::STRUCTURE, // Comma
                            Theme::VALUE, stats.max_cols, Theme::UNIT, " C");
                    } else {
                        info = size_str;
                    }

                    // Wrap info in parentheses
                    display = std::format("{} {}({}{})", 
                        item_raw, 
                        Theme::STRUCTURE, // (
                        info, 
                        Theme::STRUCTURE // )
                    );
                }
            } else {
                display = item_raw;
            }

            display += Theme::RESET; // Prevent color bleed
            size_t vlen = get_visible_length(display);
            grid_items.push_back({display, vlen});
        }

        if (grid_items.empty()) return "";

        // --- Grid Layout Rendering ---
        int term_width = get_terminal_width() - 2; // Safety margin
        if (term_width < 10) term_width = 10; 

        std::string final_output;
        final_output.reserve(raw_output.size() * 5); 

        int current_line_len = 0;

        for (const auto& item : grid_items) {
            size_t cell_len = item.visible_len + 4; // Overhead for "|  |"
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