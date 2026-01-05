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

    /**
     * @brief container for metadata extracted from a file or directory.
     * Used by the UI handlers to display rich information.
     */
    struct FileStats {
        bool is_dir = false;
        bool is_valid = false;
        
        // --- Directory Specifics ---
        size_t item_count = 0;

        // --- File Specifics ---
        uintmax_t size_bytes = 0;
        size_t rows = 0;
        size_t max_cols = 0;
        bool is_text = false;       // True if extension suggests a text/code file
        bool is_estimated = false;  // True if row count is an extrapolation based on sample size
    };

    // --- Performance Configuration ---
    // Limits to prevent UI freezes when scanning large files on the main thread.
    constexpr size_t MAX_SCAN_BYTES = 32 * 1024; // Scan max 32KB
    constexpr size_t MAX_SCAN_LINES = 2000;      // Scan max 2000 lines

    /**
     * @brief Analyzes a path to extract metadata (size, row count, type).
     * * Uses heuristics to determine if a file is text. Performs a partial scan
     * to estimate row counts for large files to maintain performance.
     * * @param filename Relative or absolute path to the target.
     * @return FileStats Struct containing the analysis results.
     */
    inline FileStats analyze_path(const std::string& filename) {
        std::error_code ec;
        fs::path p(filename);
        FileStats stats;

        // 1. Validation
        if (!fs::exists(p, ec)) return stats; 
        stats.is_valid = true;

        // 2. Directory Analysis
        if (fs::is_directory(p, ec)) {
            stats.is_dir = true;
            try {
                // std::distance is linear time; acceptable for typical dev directories.
                // For huge network drives, this might need future optimization (async).
                auto it = fs::directory_iterator(p, fs::directory_options::skip_permission_denied, ec);
                stats.item_count = std::distance(fs::begin(it), fs::end(it));
            } catch (...) { stats.item_count = 0; }
            return stats;
        }

        // 3. File Analysis
        if (fs::is_regular_file(p, ec)) {
            stats.size_bytes = fs::file_size(p, ec);
            
            // Extension-based text detection
            std::string ext = p.extension().string();
            stats.is_text = (ext == ".txt" || ext == ".cpp" || ext == ".hpp" || 
                             ext == ".py"  || ext == ".md"  || ext == ".cmake" ||
                             ext == ".json" || ext == ".csv" || ext == ".log");

            // Skip heavy scanning if empty or binary
            if (!stats.is_text || stats.size_bytes == 0) return stats;

            // 4. Content Scanning
            std::ifstream file(p);
            if (!file.is_open()) return stats;

            size_t rows = 0;
            size_t bytes_read = 0;
            std::string line;
            
            // Scan loop with safety caps
            while (bytes_read < MAX_SCAN_BYTES && rows < MAX_SCAN_LINES && std::getline(file, line)) {
                rows++;
                size_t line_bytes = line.size() + 1; // +1 for newline approximation
                bytes_read += line_bytes;
                if (line.size() > stats.max_cols) stats.max_cols = line.size();
            }

            // 5. Estimation Logic
            // If we hit the read limit before EOF, extrapolate total rows based on average byte/row ratio.
            if (bytes_read >= stats.size_bytes || file.eof()) {
                stats.rows = rows;
            } else {
                double ratio = (bytes_read > 0) ? (static_cast<double>(stats.size_bytes) / bytes_read) : 1.0;
                stats.rows = static_cast<size_t>(rows * ratio);
                stats.is_estimated = true;
            }
        }
        return stats;
    }
}