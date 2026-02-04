/**
 * @file config_loader.cpp
 * @brief Implementation of the ConfigLoader with DRY property loading.
 */

#include "core/config_loader.hpp"
#include "core/engine.hpp" // For Config definition
#include "core/command_handlers.hpp" // For Theme
#include "core/file_analyzer.hpp" // For FileExtensions
#include <pybind11/embed.h>
#include <pybind11/stl.h> // For casting vector/map
#include <iostream>
#include <filesystem>

namespace py = pybind11;

namespace dais::core {

    namespace {
        // --- DRY Helper Templates ---

        /** 
         * @brief Safely loads a simple property (int, bool, string) from a python module. 
         */
        template <typename T>
        void load_prop(const py::module_& m, const char* name, T& target) {
            if (py::hasattr(m, name)) {
                try {
                    target = m.attr(name).cast<T>();
                } catch (const std::exception& e) {
                     std::cerr << "[" << handlers::Theme::WARNING << "WARN" << handlers::Theme::RESET 
                               << "] Config Type Mismatch for '" << name << "': " << e.what() << "\n";
                }
            }
        }

        /**
         * @brief Loads a dictionary item into a specific target reference.
         */
        template <typename T>
        void load_dict_item(const py::dict& d, const char* key, T& target) {
            if (d.contains(key)) {
                try {
                    target = d[key].cast<T>();
                } catch (...) {}
            }
        }
    }

    void ConfigLoader::load(Config& config, const std::string& path) {
        namespace fs = std::filesystem;
        fs::path p(path);

        try {
            // Import logic (Assume Python interpreter is already initialized by Engine)
            py::module_ sys = py::module_::import("sys");
            sys.attr("path").attr("append")(fs::absolute(p).string());
            
            // Reload if already imported, or simple import
            py::module_ conf_module = py::module_::import("config");
            try {
                // Force reload in case it changed (optional, but good for dev)
                py::module_ importlib = py::module_::import("importlib");
                conf_module = importlib.attr("reload")(conf_module);
            } catch(...) {}

            // 1. Core Settings
            load_prop(conf_module, "SHOW_LOGO", config.show_logo);
            load_prop(conf_module, "LS_PADDING", config.ls_padding);
            load_prop(conf_module, "DB_TYPE", config.db_type);
            load_prop(conf_module, "DB_SOURCE", config.db_source);

            // 2. Shell Prompts
            if (py::hasattr(conf_module, "SHELL_PROMPTS")) {
                load_prop(conf_module, "SHELL_PROMPTS", config.shell_prompts);
            }

            // 3. Theme
            if (py::hasattr(conf_module, "THEME")) {
                py::dict theme = conf_module.attr("THEME").cast<py::dict>();
                load_dict_item(theme, "RESET", handlers::Theme::RESET);
                load_dict_item(theme, "STRUCTURE", handlers::Theme::STRUCTURE);
                load_dict_item(theme, "UNIT", handlers::Theme::UNIT);
                load_dict_item(theme, "VALUE", handlers::Theme::VALUE);
                load_dict_item(theme, "ESTIMATE", handlers::Theme::ESTIMATE);
                load_dict_item(theme, "TEXT", handlers::Theme::TEXT);
                load_dict_item(theme, "SYMLINK", handlers::Theme::SYMLINK);
                load_dict_item(theme, "LOGO", handlers::Theme::LOGO);
                load_dict_item(theme, "SUCCESS", handlers::Theme::SUCCESS);
                load_dict_item(theme, "WARNING", handlers::Theme::WARNING);
                load_dict_item(theme, "ERROR", handlers::Theme::ERROR);
                load_dict_item(theme, "NOTICE", handlers::Theme::NOTICE);
            }

            // 4. LS Formats
            if (py::hasattr(conf_module, "LS_FORMATS")) {
                py::dict formats = conf_module.attr("LS_FORMATS").cast<py::dict>();
                load_dict_item(formats, "directory", config.ls_fmt_directory);
                load_dict_item(formats, "text_file", config.ls_fmt_text_file);
                load_dict_item(formats, "data_file", config.ls_fmt_data_file);
                load_dict_item(formats, "binary_file", config.ls_fmt_binary_file);
                load_dict_item(formats, "error", config.ls_fmt_error);
            }

            // 5. Extensions (Static utils state)
            if (py::hasattr(conf_module, "TEXT_EXTENSIONS")) {
                load_prop(conf_module, "TEXT_EXTENSIONS", dais::utils::FileExtensions::text);
            }
            if (py::hasattr(conf_module, "DATA_EXTENSIONS")) {
                load_prop(conf_module, "DATA_EXTENSIONS", dais::utils::FileExtensions::data);
            }

            // 6. LS Sort
            if (py::hasattr(conf_module, "LS_SORT")) {
                py::dict sort = conf_module.attr("LS_SORT").cast<py::dict>();
                load_dict_item(sort, "by", config.ls_sort_by);
                load_dict_item(sort, "order", config.ls_sort_order);
                load_dict_item(sort, "dirs_first", config.ls_dirs_first);
                load_dict_item(sort, "flow", config.ls_flow);
            }

            std::cout << "[" << handlers::Theme::NOTICE << "-" << handlers::Theme::RESET 
                      << "] Config loaded successfully.\n";

        } catch (const std::exception& e) {
            std::cout << "[" << handlers::Theme::ERROR << "-" << handlers::Theme::RESET 
                      << "] No config.py found (or error reading it). Using defaults.\n";
        }
    }

} // namespace dais::core
