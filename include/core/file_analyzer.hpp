#pragma once

#include <string>
#include <filesystem>
#include <format>
#include <algorithm>
#include <vector>
#include <cstdint>
#include <cstdio>  // fopen, fread, fclose

namespace dais::utils {
    namespace fs = std::filesystem;

    /**
     * @brief Container for metadata extracted from a file or directory.
     * Used by the UI handlers to display rich information in the grid layout.
     */
    struct FileStats {
        bool is_dir = false;        ///< True if path is a directory
        bool is_valid = false;      ///< True if path exists and is accessible
        
        // --- Directory Specifics ---
        size_t item_count = 0;      ///< Number of items (files/dirs) immediately inside the directory

        // --- File Specifics ---
        uintmax_t size_bytes = 0;   ///< File size on disk
        size_t rows = 0;            ///< Total number of lines (newlines)
        
        /** * @brief Dual-purpose metric:
         * - For Text/Code: The character width of the longest line.
         * - For CSV/Data: The number of data columns (comma-separated).
         */
        size_t max_cols = 0;        

        bool is_text = false;       ///< True if heuristics suggest a readable text file
        bool is_data = false;       ///< True if file is a data file (.csv, .tsv, .json)
        bool is_estimated = false;  ///< True if row count is extrapolated due to file size limits
    };

    /**
     * @brief Configurable file extension lists for text and data file detection.
     * Loaded from config.py at startup. Uses inline static for global mutable state.
     */
    struct FileExtensions {
        // Text file extensions (code, markup, config files)
        inline static std::vector<std::string> text = {
            ".txt", ".cpp", ".hpp", ".py", ".md", ".cmake",
            ".log", ".sh", ".ini", ".js", ".ts", ".html",
            ".css", ".xml", ".yml", ".conf", ".c", ".h"
        };
        
        // Data file extensions (structured data formats)
        inline static std::vector<std::string> data = {
            ".csv", ".tsv", ".json"
        };
    };

    // --- Performance Configuration ---
    // Limit to prevent UI freezes when scanning large files.
    constexpr size_t MAX_SCAN_BYTES = 32 * 1024; // Scan max 32KB

    /**
     * @brief Analyzes a path to extract metadata (size, row count, type).
     * * Uses extension-based heuristics to determine if a file is text or data.
     * Performs a partial scan to estimate row counts for large files to maintain performance.
     * * @param filename Relative or absolute path to the target.
     * @return FileStats Struct containing the analysis results.
     */
    inline FileStats analyze_path(const std::string& filename) {
        std::error_code ec;
        fs::path p(filename);
        FileStats stats;

        // Single Syscall for metadata
        // fs::status() retrieves type and permissions in one go, avoiding multiple lookups.
        fs::file_status status = fs::status(p, ec);

        // 1. Validation check
        if (ec || !fs::exists(status)) return stats; 
        stats.is_valid = true;

        // 2. Directory Analysis
        if (fs::is_directory(status)) {
            stats.is_dir = true;
            try {
                // std::distance is linear time; acceptable for typical local dev directories.
                // NOTE: For high-latency network drives, this may need async implementation.
                auto it = fs::directory_iterator(p, fs::directory_options::skip_permission_denied, ec);
                stats.item_count = std::distance(fs::begin(it), fs::end(it));
            } catch (...) { stats.item_count = 0; }
            return stats;
        }

        // 3. File Analysis
        if (fs::is_regular_file(status)) {
            stats.size_bytes = fs::file_size(p, ec);
            
            std::string ext = p.extension().string();

            // Detect Data Files using configurable extension list
            stats.is_data = std::find(FileExtensions::data.begin(), 
                                      FileExtensions::data.end(), ext) != FileExtensions::data.end();

            // Detect Text Files using configurable extension list
            stats.is_text = std::find(FileExtensions::text.begin(), 
                                      FileExtensions::text.end(), ext) != FileExtensions::text.end();

            // Skip heavy I/O scanning if empty or binary
            if ((!stats.is_text && !stats.is_data) || stats.size_bytes == 0) return stats;

            // 4. Content Scanning (Optimized Zero-Allocation)
            // and string allocations for every line.
            FILE* f = std::fopen(filename.c_str(), "rb");
            if (!f) return stats;

            // Use stack buffer for speed (no heap allocation)
            char buffer[MAX_SCAN_BYTES];
            size_t bytes_read = std::fread(buffer, 1, MAX_SCAN_BYTES, f);
            std::fclose(f); 

            if (bytes_read == 0) return stats;

            // --- Row & Column Counting Loop (Byte-level) ---
            size_t current_line_len = 0;
            bool first_line_scanned = false;
            char delimiter = (ext == ".tsv") ? '\t' : ',';

            for (size_t i = 0; i < bytes_read; ++i) {
                char c = buffer[i];
                if (c == '\n') {
                    stats.rows++;                 
                    // Logic for the very first line (CSV columns or Text width)
                    if (!first_line_scanned) {
                        // For data files, columns = delimiters + 1. We counted delimiters below, so add 1 now.
                        if (stats.is_data) stats.max_cols++; 
                        // For Text, simply take the length
                        else if (current_line_len > stats.max_cols) stats.max_cols = current_line_len;

                        first_line_scanned = true;
                    } 
                    // Logic for subsequent lines (Text width only)
                    else if (!stats.is_data) {
                        if (current_line_len > stats.max_cols) stats.max_cols = current_line_len;
                    }
                    current_line_len = 0;
                } else {
                    current_line_len++;
                    // If first line of a data file, count delimiters
                    if (!first_line_scanned && stats.is_data && c == delimiter) {
                        stats.max_cols++;
                    }
                }
            }

            // Handle last line if no trailing newline
            if (bytes_read > 0 && buffer[bytes_read - 1] != '\n') stats.rows++;

            // 5. Estimation Logic
            // If we hit the read limit before EOF, extrapolate total rows based on average byte/row ratio.
            if (stats.size_bytes > bytes_read) {
                double ratio = static_cast<double>(stats.size_bytes) / bytes_read;
                stats.rows = static_cast<size_t>(stats.rows * ratio);
                stats.is_estimated = true;
            }
        }
        return stats;
    }
}