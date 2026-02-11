/**
 * @file command_handlers.cpp
 * @brief Implementation of output processing and formatting logic.
 * 
 * Provides the implementation for `native_ls` and `render_remote_ls`.
 * Includes internal helpers for ANSI width calculation, grid layout generation,
 * and templated string formatting.
 */

#include "core/command_handlers.hpp"
#include <algorithm>
#include <iostream>
#include <cmath>
#include <sstream>
#include <regex>
#include <sys/ioctl.h>
#include <unistd.h>

namespace dais::core::handlers {

    // ==================================================================================
    // INTERNAL HELPERS (HIDDEN)
    // ==================================================================================
    namespace {
        
        /**
         * @brief Internal intermediate representation of a file entry.
         * Used to hold data during the Sort -> Format -> Render pipeline.
         */
        struct GridItem {
            std::string name;
            dais::utils::FileStats stats;
            std::string display_string; ///< The fully formatted string (with ANSI codes)
            size_t visible_len = 0;     ///< The visual length of the string (ignoring ANSI)
        };

        // --- ANSI & STRING UTILS ---

        /** @brief queries the terminal window size using ioctl. */
        int get_terminal_width() {
            struct winsize w;
            if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1) return 80;
            return w.ws_col;
        }

        /** @brief Calculates the visual length of a string, ignoring ANSI escape codes. */
        size_t get_visible_length(std::string_view s) {
            size_t len = 0;
            bool in_esc_seq = false;
            for (char c : s) {
                if (c == '\x1b') in_esc_seq = true;
                else if (in_esc_seq) {
                    if (std::isalpha(c) || c == '\\') in_esc_seq = false;
                } else {
                    len++;
                }
            }
            return len;
        }

        // --- SORTING LOGIC ---

        /** @brief Helper to assign sort priority based on file type. */
        int get_type_priority(const GridItem& item, bool dirs_first) {
            if (item.stats.is_dir) return dirs_first ? 0 : 1;
            if (item.stats.is_text || item.stats.is_data) return 1;
            return 2; // binary/other
        }

        /** @brief main sorting routine. Modifies the items vector in-place. */
        void sort_grid_items(std::vector<GridItem>& items, const LSSortConfig& cfg) {
            std::sort(items.begin(), items.end(), [&](const GridItem& a, const GridItem& b) {
                // Priority 1: Directories First
                if (cfg.dirs_first) {
                    if (a.stats.is_dir != b.stats.is_dir) {
                        return a.stats.is_dir > b.stats.is_dir; // true > false (so dir comes first)
                    }
                }
                
                // Priority 2: Primary Sort Key
                int cmp = 0;
                if (cfg.by == "name") {
                    cmp = a.name.compare(b.name);
                } else if (cfg.by == "size") {
                    cmp = (a.stats.size_bytes < b.stats.size_bytes) ? -1 : (a.stats.size_bytes > b.stats.size_bytes ? 1 : 0);
                } else if (cfg.by == "type") {
                    cmp = get_type_priority(a, cfg.dirs_first) - get_type_priority(b, cfg.dirs_first);
                    if (cmp == 0) cmp = a.name.compare(b.name);
                } else if (cfg.by == "rows") {
                    cmp = (a.stats.rows < b.stats.rows) ? -1 : (a.stats.rows > b.stats.rows ? 1 : 0);
                }
                
                // Order: Ascending or Descending
                return (cfg.order == "desc") ? (cmp > 0) : (cmp < 0);
            });
        }

        // --- FORMATTING LOGIC ---

        /** 
         * @brief Applies a format template, substituting placeholders.
         * Replaces {name}, {size}, etc. with actual values, and {COLOR} with ANSI codes.
         */
        std::string apply_template(const std::string& tmpl, const std::unordered_map<std::string, std::string>& vars) {
             std::string result = tmpl;
            
             // Color Placeholders
             static const std::unordered_map<std::string, std::string> colors = {
                 {"RESET", Theme::RESET}, {"STRUCTURE", Theme::STRUCTURE},
                 {"UNIT", Theme::UNIT},   {"VALUE", Theme::VALUE},
                 {"ESTIMATE", Theme::ESTIMATE}, {"TEXT", Theme::TEXT},
                 {"SYMLINK", Theme::SYMLINK}
             };
             
             for (const auto& [key, value] : colors) {
                 std::string placeholder = "{" + key + "}";
                 size_t pos;
                 while ((pos = result.find(placeholder)) != std::string::npos) {
                     result.replace(pos, placeholder.length(), value);
                 }
             }
             
             // Data Placeholders
             for (const auto& [key, value] : vars) {
                 std::string placeholder = "{" + key + "}";
                 size_t pos;
                 while ((pos = result.find(placeholder)) != std::string::npos) {
                     result.replace(pos, placeholder.length(), value);
                 }
             }
             return result;
        }

        /** @brief Applies formatting to all items in the grid. */
        void format_grid_items(std::vector<GridItem>& items, const LSFormats& formats) {
            for (auto& item : items) {
                std::unordered_map<std::string, std::string> vars;
                vars["name"] = item.name;
                vars["size"] = fmt_size(item.stats.size_bytes);
                vars["rows"] = fmt_rows(item.stats.rows, item.stats.is_estimated);
                vars["cols"] = std::to_string(item.stats.max_cols);
                vars["count"] = std::to_string(item.stats.item_count);
                
                std::string tmpl;
                if (item.stats.is_dir)       tmpl = formats.directory;
                else if (item.stats.is_text) tmpl = formats.text_file;
                else if (item.stats.is_data) tmpl = formats.data_file;
                else                         tmpl = formats.binary_file;
                
                item.display_string = apply_template(tmpl, vars);
                item.visible_len = get_visible_length(item.display_string);
            }
        }

        // --- LAYOUT LOGIC ---

        /**
         * @brief Calculates the grid layout and renders the final string.
         * Determines column width based on the longest item, calculates number of columns
         * that fit in the terminal, and renders items in row-major or column-major order.
         */
        std::string render_grid(const std::vector<GridItem>& items, int padding, const std::string& flow_direction) {
            if (items.empty()) return "";

            int term_width = get_terminal_width();
            size_t max_len = 0;
            for (const auto& item : items) max_len = std::max(max_len, item.visible_len);
            
            // Calculate geometry
            const size_t safety_margin = 12;
            size_t safe_term_width = (static_cast<size_t>(term_width) > safety_margin) ? static_cast<size_t>(term_width) : 80;
            size_t max_possible_padding = 1;
            
            if (safe_term_width > (max_len + safety_margin)) {
                max_possible_padding = safe_term_width - max_len - safety_margin;
            }

            int effective_padding = std::max(1, padding);
            effective_padding = std::min(effective_padding, static_cast<int>(max_possible_padding));

            size_t col_width = max_len + effective_padding;
            size_t cell_width = col_width + 3; // "| " + content + padding + "|"
            size_t num_cols = std::max(1ul, (safe_term_width - 4) / cell_width);
            
            size_t total_items = items.size();
            size_t num_rows = (total_items + num_cols - 1) / num_cols;
            
            std::string output;
            
            auto render_cell = [&](size_t idx) -> std::string {
                std::string cell;
                if (idx < items.size()) {
                    const auto& item = items[idx];
                    cell += item.display_string;
                    size_t pad_len = (item.visible_len < col_width) ? (col_width - item.visible_len) : 1;
                    cell += std::string(pad_len, ' ');
                } else {
                    cell += std::string(col_width, ' ');
                }
                return cell;
            };

            for (size_t row = 0; row < num_rows; ++row) {
                output += Theme::STRUCTURE + "| " + Theme::RESET;
                for (size_t col = 0; col < num_cols; ++col) {
                    size_t idx;
                    if (flow_direction == "v") idx = col * num_rows + row;
                    else                       idx = row * num_cols + col;
                    
                    if (idx < total_items) {
                        output += render_cell(idx);
                        output += Theme::STRUCTURE + "|" + Theme::RESET;
                        if (col < num_cols - 1 && (row * num_cols + col + 1) < total_items) {
                            output += " ";
                        }
                    }
                }
                output += "\r\n";
            }
            return output;
        }

    } // namespace anonymous

    // ==================================================================================
    // PUBLIC FORMATTERS
    // ==================================================================================

    std::string fmt_size(uintmax_t bytes) {
        if (bytes < 1024) 
            return std::format("{}{}{}B", Theme::VALUE, bytes, Theme::UNIT);
        if (bytes < 1024 * 1024) 
            return std::format("{}{:.1f}{}KB", Theme::VALUE, bytes/1024.0, Theme::UNIT);
        if (bytes < 1024 * 1024 * 1024)
            return std::format("{}{:.1f}{}MB", Theme::VALUE, bytes/(1024.0*1024.0), Theme::UNIT);
        return std::format("{}{:.1f}{}GB", Theme::VALUE, bytes/(1024.0*1024.0*1024.0), Theme::UNIT);
    }

    std::string fmt_rows(size_t rows, bool estimated) {
        if (estimated) rows = static_cast<size_t>(rows * 0.92);
        std::string tilde = estimated ? Theme::ESTIMATE + "~" + Theme::VALUE : "";
        
        if (rows >= 1000000) return std::format("{}{:.1f}M", tilde, rows / 1000000.0);
        if (rows >= 1000)    return std::format("{}{:.1f}k", tilde, rows / 1000.0);
        return std::format("{}{}", tilde, rows);
    }

    // ==================================================================================
    // ARGUMENT PARSING
    // ==================================================================================

    /**
     * @brief Parses ls arguments with quote-aware tokenization.
     * 
     * Handles single-quoted ('...'), double-quoted ("..."), and
     * backslash-escaped spaces (\ ) so that paths containing spaces
     * are parsed as a single argument rather than being split.
     */
    LSArgs parse_ls_args(const std::string& input) {
        LSArgs args;
        
        // Skip leading "ls" command name
        size_t pos = 0;
        while (pos < input.size() && input[pos] == ' ') pos++;
        // Skip "ls"
        if (pos + 2 <= input.size() && input.substr(pos, 2) == "ls") {
            pos += 2;
        }
        
        // Tokenize remaining input respecting quotes and backslash escapes
        while (pos < input.size()) {
            // Skip whitespace between tokens
            while (pos < input.size() && input[pos] == ' ') pos++;
            if (pos >= input.size()) break;
            
            std::string token;
            char quote_char = 0;
            
            // Check if token starts with a quote
            if (input[pos] == '"' || input[pos] == '\'') {
                quote_char = input[pos];
                pos++; // Skip opening quote
                while (pos < input.size() && input[pos] != quote_char) {
                    token += input[pos];
                    pos++;
                }
                if (pos < input.size()) pos++; // Skip closing quote
            } else {
                // Unquoted token: read until space, handling backslash-escaped spaces
                while (pos < input.size() && input[pos] != ' ') {
                    if (input[pos] == '\\' && pos + 1 < input.size() && input[pos + 1] == ' ') {
                        token += ' ';
                        pos += 2; // Skip backslash and space
                    } else {
                        token += input[pos];
                        pos++;
                    }
                }
            }
            
            if (token.empty()) continue;
            
            if (token == "-a" || token == "--all") {
                args.show_hidden = true;
            } else if (token.starts_with("-")) {
                args.supported = false; // Unknown flag - fall through to native ls
                return args;
            } else {
                args.paths.push_back(token);
            }
        }
        if (args.paths.empty()) args.paths.push_back("");
        return args;
    }

    // ==================================================================================
    // MAIN HANDLERS
    // ==================================================================================

    std::string native_ls(const LSArgs& args, const std::filesystem::path& cwd,
                         const LSFormats& formats, const LSSortConfig& sort_cfg,
                         utils::ThreadPool& pool) {
        
        std::vector<std::future<GridItem>> futures;
        std::vector<GridItem> items;
        
        for (const auto& target : args.paths) {
            // Path Resolution
            std::filesystem::path dir_path = target.empty() ? cwd : cwd / target;
            if (!target.empty() && std::filesystem::path(target).is_absolute()) {
                dir_path = target;
            }
            
            try {
                if (!std::filesystem::exists(dir_path)) {
                    return Theme::ERROR + "ls: cannot access '" + target + "': No such file or directory" + Theme::RESET + "\r\n";
                }
                
                if (!std::filesystem::is_directory(dir_path)) {
                    // Single file Case
                    futures.push_back(pool.enqueue([dir_path]() -> GridItem {
                        auto stats = dais::utils::analyze_path(dir_path.string());
                        return {dir_path.filename().string(), stats, "", 0};
                    }));
                } else {
                    // Directory Iteration
                    for (const auto& entry : std::filesystem::directory_iterator(dir_path)) {
                        std::string name = entry.path().filename().string();
                        if (!args.show_hidden && !name.empty() && name[0] == '.') continue;
                        if (name == "." || name == "..") continue;
                        
                        std::filesystem::path full_path = entry.path();
                        futures.push_back(pool.enqueue([name, full_path]() -> GridItem {
                            auto stats = dais::utils::analyze_path(full_path.string());
                            return {name, stats, "", 0};
                        }));
                    }
                }
            } catch (const std::filesystem::filesystem_error& e) {
                return Theme::ERROR + "ls: " + e.what() + Theme::RESET + "\r\n";
            }
        }
        
        // Collect Results
        for (auto& f : futures) {
            try { items.push_back(f.get()); } catch (...) {}
        }
        
        if (items.empty()) return "";
        
        sort_grid_items(items, sort_cfg);
        format_grid_items(items, formats);
        return render_grid(items, args.padding, sort_cfg.flow);
    }

    std::string render_remote_ls(const std::string& json_output, const LSFormats& formats,
                                const LSSortConfig& sort_cfg, int padding) {
        
        std::vector<GridItem> items;
        // Basic Regex Fallback parsing for the JSON output. 
        // Note: Ideally this should use a proper JSON parser (like nlohmann/json or pybind11::json),
        // but regex is used here to avoid adding a heavy dependency for this specific output format.
        // The Agent output is strictly controlled, so regex is safe enough.
        std::regex re(R"(\"name\":\"(.*?)\",\"is_dir\":(true|false),\"size\":(\d+),\"rows\":(\d+),\"cols\":(\d+),\"count\":(\d+),\"is_text\":(true|false),\"is_data\":(true|false),\"is_estimated\":(true|false))");
        
        auto begin = std::sregex_iterator(json_output.begin(), json_output.end(), re);
        auto end = std::sregex_iterator();

        for (std::sregex_iterator i = begin; i != end; ++i) {
            std::smatch match = *i;
            GridItem item;
            item.name = match[1].str();
            item.stats.is_dir = (match[2].str() == "true");
            item.stats.size_bytes = std::stoull(match[3].str());
            item.stats.rows = std::stoull(match[4].str());
            item.stats.max_cols = std::stoull(match[5].str());
            item.stats.item_count = std::stoull(match[6].str());
            item.stats.is_text = (match[7].str() == "true");
            item.stats.is_data = (match[8].str() == "true");
            item.stats.is_estimated = (match[9].str() == "true");
            items.push_back(item);
        }

        if (items.empty()) return "";

        sort_grid_items(items, sort_cfg);
        format_grid_items(items, formats);
        return render_grid(items, padding, sort_cfg.flow);
    }

} // namespace dais::core::handlers
