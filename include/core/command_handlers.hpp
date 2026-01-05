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

    // --- COLORS ---
    constexpr auto C_GRAY  = "\x1b[90m";  
    constexpr auto C_RESET = "\x1b[0m";

    // --- HELPERS ---

    inline int get_terminal_width() {
        struct winsize w;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1) return 80;
        return w.ws_col;
    }

    inline size_t get_visible_length(std::string_view s) {
        size_t len = 0;
        bool in_esc_seq = false;
        for (char c : s) {
            if (c == '\x1b') in_esc_seq = true;
            else if (in_esc_seq) {
                if (std::isalpha(c)) in_esc_seq = false;
            } else {
                len++;
            }
        }
        return len;
    }

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

    // --- HANDLERS ---

    inline std::string handle_generic(std::string_view raw_output) {
        return std::string(raw_output);
    }

    inline std::string handle_ls(std::string_view raw_output, const std::filesystem::path& cwd) {
        std::stringstream ss{std::string(raw_output)};
        std::string token;
        std::vector<std::string> original_items;
        
        while (ss >> token) {
            original_items.push_back(token);
        }

        if (original_items.empty()) return "";

        struct GridItem {
            std::string display_string;
            size_t visible_len;
        };
        std::vector<GridItem> grid_items;

        bool first_token = true;

        for (const auto& item_raw : original_items) {
            std::string clean_name = strip_ansi(item_raw);
            
            if (first_token && clean_name == "ls") {
                first_token = false;
                continue;
            }
            first_token = false;

            if (clean_name.empty()) continue;
            if (clean_name == "." || clean_name == "..") continue;

            std::filesystem::path full_path = cwd / clean_name;
            auto stats = dash::utils::analyze_path(full_path.string());

            std::string final_str;
            if (!stats.info_string.empty()) {
                final_str = std::format("{} ({})", item_raw, stats.info_string);
            } else {
                final_str = item_raw;
            }

            size_t vlen = get_visible_length(final_str);
            grid_items.push_back({final_str, vlen});
        }

        if (grid_items.empty()) return "";

        // Safety margin to prevent hard wrapping
        int term_width = get_terminal_width() - 2; 
        if (term_width < 10) term_width = 10; 

        std::string final_output;
        final_output.reserve(raw_output.size() * 4);

        int current_line_len = 0;

        for (const auto& item : grid_items) {
            size_t cell_len = item.visible_len + 4; 
            int gap = (current_line_len > 0) ? 1 : 0;

            if (current_line_len + gap + cell_len > (size_t)term_width) {
                if (current_line_len > 0) final_output += "\r\n";
                
                final_output += std::format("{}|{} {} {}|{}", C_GRAY, C_RESET, item.display_string, C_GRAY, C_RESET);
                current_line_len = cell_len;
            } 
            else {
                if (current_line_len > 0) {
                    final_output += " "; 
                    current_line_len += 1;
                }
                final_output += std::format("{}|{} {} {}|{}", C_GRAY, C_RESET, item.display_string, C_GRAY, C_RESET);
                current_line_len += cell_len;
            }
        }

        return final_output;
    }
}