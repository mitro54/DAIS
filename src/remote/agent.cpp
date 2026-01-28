/**
 * @file agent.cpp
 * @brief Standalone File Analysis Agent for Remote (SSH) Execution.
 * 
 * * This minimal binary is designed to be statically linked and injected into remote servers.
 * * It performs the exact same high-performance file analysis as the local DAIS engine (using file_analyzer.hpp).
 * * Outputs a compressed JSON stream to stdout for the local DAIS instance to parse and render.
 * 
 * @note This file MUST be compilable on Linux (x86_64, aarch64, armv7) with minimal dependencies (libc/libstdc++).
 */

#include "core/file_analyzer.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <string_view>

/**
 * @brief Escapes a string for valid JSON output.
 * Minimal implementation to avoid heavy JSON library dependencies.
 * @param s Input string
 * @return JSON-safe escaped string
 */
std::string escape_json(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\b') out += "\\b";
        else if (c == '\f') out += "\\f";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (static_cast<unsigned char>(c) < 0x20) {
            char buf[7];
            snprintf(buf, sizeof(buf), "\\u%04x", c);
            out += buf;
        }
        else out += c;
    }
    return out;
}

int main(int argc, char* argv[]) {
    // Pure JSON mode
     
    std::vector<std::string> paths;
    bool show_hidden = false;

    // VERY basic arg parsing
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-a" || arg == "--all") {
            show_hidden = true;
        } else {
            paths.push_back(arg);
        }
    }

    if (paths.empty()) {
        paths.push_back(".");
    }

    std::cout << "["; // Start JSON array

    bool first_item = true;

    for (const auto& target : paths) {
        try {
            std::filesystem::path p(target);
            if (!std::filesystem::exists(p)) continue; // Skip bad paths

            if (std::filesystem::is_directory(p)) {
                for (const auto& entry : std::filesystem::directory_iterator(p)) {
                    std::string name = entry.path().filename().string();
                    if (!show_hidden && name.size() > 0 && name[0] == '.') continue;
                    if (name == "." || name == "..") continue;

                    auto stats = dais::utils::analyze_path(entry.path().string());
                    
                    if (!first_item) std::cout << ",";
                    first_item = false;

                    std::cout << "{"
                              << "\"name\":\"" << escape_json(name) << "\","
                              << "\"is_dir\":" << (stats.is_dir ? "true" : "false") << ","
                              << "\"size\":" << stats.size_bytes << ","
                              << "\"rows\":" << stats.rows << ","
                              << "\"cols\":" << stats.max_cols << ","
                              << "\"count\":" << stats.item_count << ","
                              << "\"is_text\":" << (stats.is_text ? "true" : "false") << ","
                              << "\"is_data\":" << (stats.is_data ? "true" : "false") << "," 
                              << "\"is_estimated\":" << (stats.is_estimated ? "true" : "false")
                              << "}";
                }
            } else {
                // Single file
                auto stats = dais::utils::analyze_path(target);
                if (!first_item) std::cout << ",";
                first_item = false;

                std::cout << "{"
                            << "\"name\":\"" << escape_json(std::filesystem::path(target).filename().string()) << "\","
                            << "\"is_dir\":" << (stats.is_dir ? "true" : "false") << ","
                            << "\"size\":" << stats.size_bytes << ","
                            << "\"rows\":" << stats.rows << ","
                            << "\"cols\":" << stats.max_cols << ","
                            << "\"count\":" << stats.item_count << ","
                            << "\"is_text\":" << (stats.is_text ? "true" : "false") << ","
                            << "\"is_data\":" << (stats.is_data ? "true" : "false") << "," 
                            << "\"is_estimated\":" << (stats.is_estimated ? "true" : "false")
                            << "}";
            }
        } catch (...) {
            // Ignore access errors
        }
    }

    std::cout << "]"; // End JSON array
    std::cout << "\n"; // Clean line termination
    return 0;
}
