#pragma once
#include <string>
#include <filesystem>
#include <fstream>
#include <format>
#include <algorithm>
#include <vector>
#include <cstdint>

namespace dash::utils {
    namespace fs = std::filesystem;

    struct FileStats {
        std::string info_string;
    };

    // Configuration for performance limits
    constexpr size_t MAX_SCAN_BYTES = 32 * 1024; // 32KB Limit
    constexpr size_t MAX_SCAN_LINES = 2000;      // 2000 Lines Limit

    inline std::string format_size(uintmax_t bytes) {
        if (bytes < 1024) return std::format("{}B", bytes);
        if (bytes < 1024 * 1024) return std::format("{:.1f}KB", bytes / 1024.0);
        return std::format("{:.1f}MB", bytes / (1024.0 * 1024.0));
    }

    inline FileStats analyze_path(const std::string& filename) {
        std::error_code ec;
        fs::path p(filename);

        // 1. Check if file exists (non-throwing)
        if (!fs::exists(p, ec)) return { "" }; 

        // 2. Handle Directory
        if (fs::is_directory(p, ec)) {
            size_t item_count = 0;
            // Directory iterator can be slow on network drives, handle with care
            try {
                auto it = fs::directory_iterator(p, fs::directory_options::skip_permission_denied, ec);
                item_count = std::distance(fs::begin(it), fs::end(it));
            } catch (...) { item_count = 0; } // Fallback
            
            return { std::format("DIR: {} items", item_count) };
        }

        // 3. Handle Regular File
        if (fs::is_regular_file(p, ec)) {
            uintmax_t fsize = fs::file_size(p, ec);
            std::string size_str = format_size(fsize);

            // Extension check for likely text files
            std::string ext = p.extension().string();
            // Simple check for common text formats
            bool likely_text = (ext == ".txt" || ext == ".cpp" || ext == ".hpp" || 
                                ext == ".py"  || ext == ".md"  || ext == ".cmake" ||
                                ext == ".json" || ext == ".csv" || ext == ".log");

            if (!likely_text || fsize == 0) {
                return { size_str };
            }

            // 4. Scan Content with Smart Limits
            std::ifstream file(p);
            if (!file.is_open()) return { size_str };

            size_t rows = 0;
            size_t max_cols = 0;
            size_t bytes_read = 0;
            std::string line;
            
            // Loop until we hit line limit OR byte limit
            while (bytes_read < MAX_SCAN_BYTES && rows < MAX_SCAN_LINES && std::getline(file, line)) {
                rows++;
                // Handle Windows \r\n vs Linux \n size differences roughly for byte counting
                size_t line_bytes = line.size() + 1; 
                bytes_read += line_bytes;
                
                // Update max columns found so far
                if (line.size() > max_cols) max_cols = line.size();
            }

            // --- ESTIMATION LOGIC ---
            std::string row_display;
            
            // Did we read the whole file?
            if (bytes_read >= fsize || file.eof()) {
                // Yes, exact count
                row_display = std::format("{}R", rows);
            } else {
                // No, we stopped early. Estimate total rows.
                // Formula: (Total Size / Sample Size) * Sample Rows
                // Use double for calculation to avoid overflow/truncation
                double ratio = (bytes_read > 0) ? (static_cast<double>(fsize) / bytes_read) : 1.0;
                size_t estimated_rows = static_cast<size_t>(rows * ratio);
                
                // Format large numbers cleanly
                if (estimated_rows > 1000000) row_display = std::format("~{:.1f}M R", estimated_rows / 1000000.0);
                else if (estimated_rows > 1000) row_display = std::format("~{:.1f}k R", estimated_rows / 1000.0);
                else row_display = std::format("~{}R", estimated_rows);
            }

            return { std::format("{}, {}, {}C", size_str, row_display, max_cols) };
        }

        return { "Unknown" };
    }
}