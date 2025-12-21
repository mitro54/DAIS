#include "core/engine.hpp"
#include <filesystem>
#include <iostream>
#include <vector>

namespace fs = std::filesystem;

// Helper function to find the py_scripts folder
std::string find_plugins_path() {
    std::vector<std::string> candidates = {
        "py_scripts",           // If you run from project root
        "../py_scripts",        // If you run from build/
        "../../py_scripts",     // If you run from build/debug/
        "../src/py_scripts",    // look from src
        //"/usr/local/share/dash/py_scripts" // (Optional) System install path
    };

    for (const auto& path : candidates)
        if (fs::exists(path) && fs::is_directory(path)) return path;
    return ""; // Not found
}

int main() {
    dash::core::Engine engine;
    std::string root_path = find_plugins_path();
    engine.load_configuration(root_path);
    engine.load_extensions(root_path);
    engine.run();
    return 0;
}