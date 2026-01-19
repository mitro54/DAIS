#include "core/engine.hpp"
#include <filesystem>
#include <iostream>
#include <string>
#include <csignal>      // signal()
#include <sys/ioctl.h>  // ioctl()
#include <unistd.h>     // STDOUT_FILENO

namespace fs = std::filesystem;

// Global pointer to allow signal handler to access the engine instance
static dais::core::Engine* global_engine = nullptr;

/**
 * @brief Handles the Window Resize signal (SIGWINCH).
 * Triggered by the OS when the terminal window is resized.
 * Updates the internal PTY size to match the new terminal window size.
 */
void handle_winch(int /*sig*/) {
    if (global_engine) {
        struct winsize w;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1) {
            global_engine->resize_window(w.ws_row, w.ws_col);
        }
    }
}

int main() {
    dais::core::Engine engine;
    global_engine = &engine;

    // 1. Register the resize signal handler
    // This handles updates while the app is running
    signal(SIGWINCH, handle_winch);

    // 2. Path Setup
    // Get the baked-in absolute path to the project root
#ifdef DAIS_ROOT
    fs::path project_root = DAIS_ROOT;
#else
    fs::path project_root = fs::current_path().parent_path();
#endif
    // Construct the path to the scripts folder
    fs::path scripts_path = project_root / "src" / "py_scripts";
    fs::path config_path = project_root / "config";

    // Verify it exists (Sanity check to prevent Segfaults)
    if (!fs::exists(scripts_path)) {
        std::cerr << "[\x1b[93m-\x1b[0m] Warning: Could not find Python scripts at: " << scripts_path << "\n";
    }

    // 3. Load & Run
    engine.load_configuration(config_path);
    engine.load_extensions(scripts_path);

    // The initial window resize will now happen inside run(), 
    // immediately after the PTY starts.
    engine.run();

    return 0;
}