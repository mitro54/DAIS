#pragma once
/**
 * @file help_text.hpp
 * @brief Centralized help text for DAIS runtime commands.
 * 
 * This file provides the :help command content, keeping documentation
 * separate from logic for maintainability. When adding new commands,
 * update the help text here to keep documentation in sync.
 */

#include <string>
#include "core/command_handlers.hpp"

namespace dais::core {

    /**
     * @brief Returns formatted help text with ANSI colors.
     * 
     * Uses the Theme colors from command_handlers.hpp for consistency
     * with other DAIS output. Uses \r\n for proper PTY terminal formatting.
     * 
     * @return Formatted help string ready for terminal output.
     */
    inline std::string get_help_text() {
        // Use Theme colors for consistency with ls output
        const auto& S = handlers::Theme::STRUCTURE;  // Borders, separators
        const auto& V = handlers::Theme::VALUE;      // Commands (highlighted)
        const auto& U = handlers::Theme::UNIT;       // Labels
        const auto& T = handlers::Theme::TEXT;       // Descriptions
        const auto& N = handlers::Theme::NOTICE;     // Headers
        const auto& R = handlers::Theme::RESET;
        
        std::string h;
        
        // Header
        h += S + "─────────────────────────────────────" + R + "\r\n";
        h += N + " DAIS Commands" + R + "\r\n";
        h += S + "─────────────────────────────────────" + R + "\r\n";
        h += "\r\n";
        
        // LS Commands
        h += U + "File Listing" + R + "\r\n";
        h += S + "  " + V + ":ls" + S + "              " + T + "Show current sort settings" + R + "\r\n";
        h += S + "  " + V + ":ls size desc" + S + "    " + T + "Sort by size, descending" + R + "\r\n";
        h += S + "  " + V + ":ls type asc" + S + "     " + T + "Sort by type, ascending" + R + "\r\n";
        h += S + "  " + V + ":ls true/false" + S + "   " + T + "Dirs first on/off" + R + "\r\n";
        h += S + "  " + V + ":ls d" + S + "            " + T + "Reset to defaults" + R + "\r\n";
        h += "\r\n";
        
        // History & System
        h += U + "History & System" + R + "\r\n";
        h += S + "  " + V + ":history" + S + "         " + T + "Show last 20 commands" + R + "\r\n";
        h += S + "  " + V + ":history N" + S + "       " + T + "Show last N commands" + R + "\r\n";
        h += S + "  " + V + ":history clear" + S + "   " + T + "Clear command history" + R + "\r\n";
        h += S + "  " + V + ":help" + S + "            " + T + "Show this help" + R + "\r\n";
        h += S + "  " + V + ":q / :exit" + S + "       " + T + "Exit DAIS" + R + "\r\n";
        
        return h;
    }

}
