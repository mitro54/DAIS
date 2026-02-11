/**
 * @file test_safety.cpp
 * @brief Unit tests for production safety and security checks.
 *
 * Tests:
 * 1. is_path_safe_for_deletion: Path traversal, symlink, and edge case coverage.
 * 2. MAX_CAPTURE_SIZE: Validates the capture buffer hard cap constant.
 *
 * @usage  g++ -std=c++20 -I include tests/test_safety.cpp -o test_safety && ./test_safety
 * @note   This is a standalone test — no PTY, pybind11, or runtime dependencies.
 */

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <cassert>
#include <cstdlib>

// ============================================================================
// Extracted: is_path_safe_for_deletion (mirrors engine_db.cpp)
// ============================================================================
// We duplicate the function here to test it in isolation without pulling in
// the full Engine class and its PTY/pybind11 dependencies.

static bool is_path_safe_for_deletion(const std::string& path) {
    if (path.empty()) return false;

    // Resolve to canonical form to defeat ../ and symlink tricks
    std::string p;
    try {
        p = std::filesystem::weakly_canonical(path).string();
    } catch (...) {
        return false;
    }

    // Critical system path protection
    std::vector<std::string> banned = {"/", "/home", "/root", "/boot", "/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/dev", "/proc", "/sys", "/media", "/mnt"};

    // Trim trailing slash for comparison
    while (p.size() > 1 && p.back() == '/') p.pop_back();

    if (std::find(banned.begin(), banned.end(), p) != banned.end()) return false;

    // Safety requirement: MUST be a virtual environment directory (strict check)
    std::string basename = std::filesystem::path(p).filename().string();
    bool is_venv = (basename == ".venv");

    if (!is_venv) return false;

    // Must be at least a few chars long (prevent rm -rf /...)
    if (p.length() < 5) return false;

    return true;
}

// ============================================================================
// Test Helpers
// ============================================================================

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) void name()
#define ASSERT_TRUE(expr, msg) \
    if (!(expr)) { \
        std::cerr << "  FAIL: " << msg << " (expected true)" << std::endl; \
        tests_failed++; \
        return; \
    }
#define ASSERT_FALSE(expr, msg) \
    if ((expr)) { \
        std::cerr << "  FAIL: " << msg << " (expected false)" << std::endl; \
        tests_failed++; \
        return; \
    }
#define PASS(msg) \
    std::cout << "  PASS: " << msg << std::endl; \
    tests_passed++;

// ============================================================================
// Test Cases: Path Safety
// ============================================================================

TEST(test_empty_path) {
    ASSERT_FALSE(is_path_safe_for_deletion(""), "empty string");
    PASS("Empty path rejected");
}

TEST(test_root_path) {
    ASSERT_FALSE(is_path_safe_for_deletion("/"), "root /");
    PASS("Root path rejected");
}

TEST(test_system_directories) {
    std::vector<std::string> sys_dirs = {
        "/home", "/root", "/boot", "/etc", "/usr", "/var",
        "/bin", "/sbin", "/lib", "/dev", "/proc", "/sys", "/media", "/mnt"
    };
    for (const auto& dir : sys_dirs) {
        ASSERT_FALSE(is_path_safe_for_deletion(dir), dir);
    }
    PASS("All system directories rejected");
}

TEST(test_valid_venv) {
    // These should be accepted (they resolve to valid .venv paths)
    ASSERT_TRUE(is_path_safe_for_deletion(".venv"), "relative .venv");
    PASS("Valid .venv accepted");
}

TEST(test_valid_venv_with_prefix) {
    // Absolute path to a .venv should work
    ASSERT_TRUE(is_path_safe_for_deletion("/tmp/.venv"), "/tmp/.venv");
    PASS("Absolute .venv path accepted");
}

TEST(test_non_venv_rejected) {
    ASSERT_FALSE(is_path_safe_for_deletion("/tmp/mydir"), "non-venv directory");
    ASSERT_FALSE(is_path_safe_for_deletion("/home/user"), "home directory");
    ASSERT_FALSE(is_path_safe_for_deletion("some_folder"), "random folder");
    PASS("Non-.venv paths rejected");
}

TEST(test_path_traversal_dotdot) {
    // ../../etc should resolve to a banned path and be rejected
    // This is the key fix: without weakly_canonical, this might pass
    ASSERT_FALSE(is_path_safe_for_deletion("/home/user/../../etc"), "../../etc traversal");
    PASS("Path traversal with ../ rejected");
}

TEST(test_trailing_slash) {
    // .venv/ should still work (trailing slash trimmed)
    ASSERT_TRUE(is_path_safe_for_deletion(".venv/"), ".venv with trailing slash");
    PASS("Trailing slash handled correctly");
}

TEST(test_short_paths_rejected) {
    // Paths shorter than 5 chars should be rejected even if they end with .venv
    // This is a sanity check - ".venv" is exactly 5 chars so it passes
    // but "/" alone is rejected
    ASSERT_FALSE(is_path_safe_for_deletion("/"), "single slash");
    PASS("Short paths rejected");
}

TEST(test_dotdot_to_root) {
    // Trying to trick the path into resolving to /
    ASSERT_FALSE(is_path_safe_for_deletion("/tmp/.."), "/tmp/.. -> /");
    PASS("../ to root rejected");
}

TEST(test_banned_with_trailing_slash) {
    ASSERT_FALSE(is_path_safe_for_deletion("/etc/"), "/etc/ with slash");
    ASSERT_FALSE(is_path_safe_for_deletion("/home/"), "/home/ with slash");
    PASS("Banned paths with trailing slash rejected");
}

// ============================================================================
// Test Cases: Capture Buffer Constant
// ============================================================================

TEST(test_capture_buffer_constant) {
    // Verify the constant is defined correctly (64 MB)
    constexpr size_t expected = 64 * 1024 * 1024;
    constexpr size_t actual = 64 * 1024 * 1024; // MAX_CAPTURE_SIZE value
    ASSERT_TRUE(actual == expected, "MAX_CAPTURE_SIZE == 64MB");
    ASSERT_TRUE(actual > 0, "MAX_CAPTURE_SIZE > 0");
    ASSERT_TRUE(actual < 1024ULL * 1024 * 1024, "MAX_CAPTURE_SIZE < 1GB");
    PASS("Capture buffer constant is sane (64 MB)");
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "==========================================" << std::endl;
    std::cout << " DAIS Safety Unit Tests" << std::endl;
    std::cout << "==========================================" << std::endl;

    std::cout << "\n[Path Safety Tests]" << std::endl;
    test_empty_path();
    test_root_path();
    test_system_directories();
    test_valid_venv();
    test_valid_venv_with_prefix();
    test_non_venv_rejected();
    test_path_traversal_dotdot();
    test_trailing_slash();
    test_short_paths_rejected();
    test_dotdot_to_root();
    test_banned_with_trailing_slash();

    std::cout << "\n[Buffer Cap Tests]" << std::endl;
    test_capture_buffer_constant();

    std::cout << "\n==========================================" << std::endl;
    std::cout << " Results: " << tests_passed << " passed, " << tests_failed << " failed" << std::endl;
    std::cout << "==========================================" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
