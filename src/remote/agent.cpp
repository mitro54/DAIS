/**
 * @file agent.cpp
 * @brief Standalone File Analysis Agent for Remote (SSH) Execution.
 * 
 * * This minimal binary is designed to be statically linked and injected into remote servers.
 * * It performs the exact same high-performance file analysis as the local DAIS engine.
 * * Outputs a compressed JSON stream to stdout for the local DAIS instance to parse.
 * 
 * @note This file MUST be compilable on Linux (x86_64, aarch64, armv7) with minimal dependencies.
 */

#include "core/file_analyzer.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <string_view>
#include <unistd.h> // for nice()

// ==================================================================================
// ROBUST JSON WRITER (Header-Only Implementation)
// ==================================================================================
/**
 * @brief Minimal, safe JSON writer to avoid external dependencies.
 * Handles escaping, comma separation, and structure validation.
 * 
 * DESIGN RATIONALE:
 * - Header-only to keep the agent a single source file.
 * - No dynamic allocations (std::vector ok) for core logic to minimize failure points.
 * - Strict strict escaping guarantees valid JSON even with binary garbage in filenames.
 */
class JsonWriter {
public:
    explicit JsonWriter(std::ostream& out) noexcept : out_(out) {}

    /** @brief Starts a JSON array ([) and manages the FSM stack. */
    void start_array() {
        prepare_value(); // Update Parent
        out_ << "[";
        finish_value(); // Finish Parent's "value expectation" BEFORE pushing child
        
        stack_.push_back({Context::Array, false, true}); // Enter Child
    }


    /** @brief Ends the current JSON array (]) and pops the stack. */
    void end_array() {
        if (!stack_.empty() && stack_.back().ctx != Context::Array) {
             std::cerr << "JSON ERROR: end_array called inside Object\n"; std::exit(1);
        }
        out_ << "]";
        if (!stack_.empty()) stack_.pop_back();
    }

    /** @brief Starts a JSON object ({) and manages the FSM stack. */
    void start_object() {
        prepare_value();
        out_ << "{";
        finish_value();
        stack_.push_back({Context::Object, false, true});
    }

    /** @brief Ends the current JSON object (}) and pops the stack. */
    void end_object() {
        if (!stack_.empty() && stack_.back().ctx != Context::Object) {
             std::cerr << "JSON ERROR: end_object called inside Array\n"; std::exit(1);
        }
        out_ << "}";
        if (!stack_.empty()) stack_.pop_back();
    }

    /** @brief Writes a key string for an object field. */
    void key(std::string_view k) {
        if (stack_.empty() || stack_.back().ctx != Context::Object) {
            std::cerr << "JSON ERROR: key() called outside Object\n"; std::exit(1);
        }
        State& s = stack_.back();
        if (s.expecting_value) {
             std::cerr << "JSON ERROR: key() called while expecting value\n"; std::exit(1);
        }
        
        if (!s.first_element) out_ << ",";
        write_string(k);
        out_ << ":";
        s.expecting_value = true;
    }

    /** @brief Writes a string value and manages commas/FSM state. */
    void value(std::string_view v) {
        prepare_value();
        write_string(v);
        finish_value();
    }

    /** @brief Writes a numeric value and manages commas/FSM state. */
    void value(long long v) {
        prepare_value();
        out_ << v;
        finish_value();
    }

    /** @brief Writes a boolean value and manages commas/FSM state. */
    void value(bool v) {
        prepare_value();
        out_ << (v ? "true" : "false");
        finish_value();
    }

private:
    enum class Context { Array, Object };
    
    struct State {
        Context ctx;
        bool expecting_value; // Only relevant for Object: true if key was just written
        bool first_element;
    };

    std::ostream& out_;
    std::vector<State> stack_;

    void write_string(std::string_view s) {
        if (!out_) return; // Fail silently on broken pipe
        out_ << "\"";
        for (char c : s) {
            // OPTIMIZATION: Check for common printable chars first
            if (c >= 0x20 && c != '"' && c != '\\') {
                 out_ << c;
                 continue;
            }
            switch (c) {
                case '"': out_ << "\\\""; break;
                case '\\': out_ << "\\\\"; break;
                case '\b': out_ << "\\b"; break;
                case '\f': out_ << "\\f"; break;
                case '\n': out_ << "\\n"; break;
                case '\r': out_ << "\\r"; break;
                case '\t': out_ << "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[7];
                        snprintf(buf, sizeof(buf), "\\u%04x", c);
                        out_ << buf;
                    } else {
                        out_ << c;
                    }
            }
        }
        out_ << "\"";
    }

    // Helper to handle comma logic
    void prepare_value() {
        if (stack_.empty()) return; // Root value?

        State& s = stack_.back();
        
        // Validation: Cannot write value in Object unless Key was just written
        if (s.ctx == Context::Object && !s.expecting_value) {
            // ERROR: Attempted to write value in object without key
            // For safety in this environment, we just abort or ignore.
            // Aborting prevents invalid JSON.
            std::cerr << "JSON ERROR: Value without Key\n";
            std::exit(1); 
        }

        if (!s.first_element) {
            // If in Array, we need a comma before this new value
            // If in Object, the comma was handled by key() before the key. 
            // WAIT - logic is:
            // ARRAY: [v1, v2] -> comma before v2
            // OBJECT: {"k1":v1, "k2":v2}
            //   key("k1") -> no comma (first) -> "k1": -> set expecting_value=true
            //   value(v1) -> validation ok -> write v1 -> set expecting_value=false -> set first_element=false
            //   key("k2") -> not first -> comma -> "k2": -> set expecting_value=true
            
            if (s.ctx == Context::Array) {
                out_ << ",";
            }
        }
        
        // If Object, we wrote the key and colon already
    }

    void finish_value() {
        if (stack_.empty()) return;
        State& s = stack_.back();
        if (s.ctx == Context::Object) {
            s.expecting_value = false;
        }
        s.first_element = false;
    }
};

// ==================================================================================
// MAIN EXECUTION
// ==================================================================================

int main(int argc, char* argv[]) {
    // 1. RESOURCE LIMITS
    // Be a good citizen on shared servers.
    // Nice value 10 (base 0) lowers priority significantly.
    // We explicitly cast to void to silence [[nodiscard]] or unused result warnings.
    // Failure to nice is not fatal, so we ignore the return value.
    auto dummy = nice(10);
    (void)dummy;

    // Disable syncing for performance
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    namespace fs = std::filesystem;
    std::vector<std::string> paths;
    bool show_hidden = false;

    // VERY basic arg parsing
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-a" || arg == "--all") {
            show_hidden = true;
        } else if (arg == "--version") {
            std::cout << "DAIS_AGENT_v1.0" << std::endl;
            return 0; 
        } else {
            paths.push_back(arg);
        }
    }

    if (paths.empty()) {
        paths.push_back(".");
    }

    JsonWriter w(std::cout);
    w.start_array();

    for (const auto& target : paths) {
        try {
            fs::path p(target);
            if (!fs::exists(p)) continue;

            if (fs::is_directory(p)) {
                // Use directory_options to skip permission denied errors automatically
                for (const auto& entry : fs::directory_iterator(p, fs::directory_options::skip_permission_denied)) {
                    // Safe access to path string
                    std::string name;
                    try {
                        name = entry.path().filename().string();
                    } catch (...) { continue; }

                    if (!show_hidden && name.size() > 0 && name[0] == '.') continue;
                    if (name == "." || name == "..") continue;

                    try {
                        auto stats = dais::utils::analyze_path(entry.path().string());
                        
                        w.start_object();
                        w.key("name"); w.value(name);
                        w.key("is_dir"); w.value(stats.is_dir);
                        w.key("size"); w.value((long long)stats.size_bytes);
                        w.key("rows"); w.value((long long)stats.rows);
                        w.key("cols"); w.value((long long)stats.max_cols);
                        w.key("count"); w.value((long long)stats.item_count);
                        w.key("is_text"); w.value(stats.is_text);
                        w.key("is_data"); w.value(stats.is_data);
                        w.key("is_estimated"); w.value(stats.is_estimated);
                        w.end_object();
                    } catch (...) {
                        // Skip individual files that fail analysis
                    }
                }
            } else {
                // Single file
                try {
                    auto stats = dais::utils::analyze_path(target);
                    w.start_object();
                    w.key("name"); w.value(fs::path(target).filename().string());
                    w.key("is_dir"); w.value(stats.is_dir);
                    w.key("size"); w.value((long long)stats.size_bytes);
                    w.key("rows"); w.value((long long)stats.rows);
                    w.key("cols"); w.value((long long)stats.max_cols);
                    w.key("count"); w.value((long long)stats.item_count);
                    w.key("is_text"); w.value(stats.is_text);
                    w.key("is_data"); w.value(stats.is_data);
                    w.key("is_estimated"); w.value(stats.is_estimated);
                    w.end_object();
                } catch (...) {}
            }
        } catch (...) {
            // Ignore top-level access errors
        }
    }

    w.end_array();
    
    // Explicitly flush and check for errors
    std::cout << "\n" << std::flush;
    
    if (std::cout.bad()) {
        // If we can't write to stdout (e.g. broken pipe), exit with error
        return 1;
    }
    return 0;
}
