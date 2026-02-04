/**
 * @file config_loader.hpp
 * @brief Definition of the ConfigLoader class.
 * 
 * Provides a static mechanism to load user configuration from a standard
 * Python file (`config.py`). This design allows for rich, scriptable configuration
 * without needing a complex parser in C++.
 */

#pragma once
#include <string>

namespace dais::core {
    struct Config; // Forward declaration

    /**
     * @class ConfigLoader
     * @brief Static helper to bridge C++ configuration with Python scripts.
     */
    class ConfigLoader {
    public:
        /**
         * @brief Loads runtime configuration from a config.py file into the Config struct.
         * 
         * This function initializes the embedded Python interpreter (if needed),
         * adds the target directory to sys.path, and imports the `config` module.
         * It then reflects the Python variables into the C++ Config struct.
         * 
         * @param config The configuration object to populate.
         * @param path Absolute path to the directory containing config.py.
         */
        static void load(Config& config, const std::string& path);
    };
}
