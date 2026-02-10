/**
 * @file engine_db.cpp
 * @brief Implementation of Engine's database command handling (:db).
 * 
 * Provides a unified interface for executing SQL queries and inspecting data
 * from either the local environment or a remote SSH session. Proxies commands
 * to a Python helper script (`db_handler.py`) to leverage Python's rich
 * ecosystem of database drivers (sqlite3, pandas, etc.).
 */

#include "core/engine.hpp"
#include "core/command_handlers.hpp"
#include "core/base64.hpp"
#include <iostream>
#include <thread>
#include <unistd.h>

namespace dais::core {

    /**
     * @brief Evaluates the `:db` command.
     * 
     * Flow:
     * 1. Determines if execution is Local or Remote.
     * 2. **Local**: Imports `db_handler` python module embedded in DAIS.
     * 3. **Remote**: Checks if `db_handler.py` is deployed; deploys if missing.
     *    Then runs `python3 ~/.dais/bin/db_handler.py "QUERY"`.
     * 
     * Output Handling:
     * - Expects a JSON response from the Python script.
     * - Parses JSON to determine actions:
     *   - `print`: Display formatted table directly.
     *   - `page`: Open results in `less` (supports remote pager injection).
     *   - `missing_pkg`: Prompts user to install missing Python libs (e.g. pandas).
     *   - `error`: Displays error message.
     * 
     * @param query The SQL query or saved query name to execute.
     */
    void Engine::handle_db_command(const std::string& query) {
        std::lock_guard<std::recursive_mutex> terminal_lock(terminal_mutex_);
        if (query.empty()) {
            std::cout << "[" << handlers::Theme::UNIT << "DB Usage" << handlers::Theme::RESET 
                      << "] :db " << handlers::Theme::STRUCTURE << "<" << handlers::Theme::UNIT << "sql_query" << handlers::Theme::STRUCTURE << ">" << handlers::Theme::RESET 
                      << " OR :db " << handlers::Theme::STRUCTURE << "<" << handlers::Theme::UNIT << "saved_query_name" << handlers::Theme::STRUCTURE << ">\r\n" << std::flush;
            return;
        }

        try {
            std::string json_result;

            if (is_remote_session_) {
                // --- REMOTE EXECUTION ---
                check_remote_session(); // Sync state
                deploy_remote_db_handler();

                // Construct remote command
                // Escaping is tricky. We assume basic quoting.
                std::string escaped_query = query;
                // Simple quote escaping
                size_t pos = 0;
                while ((pos = escaped_query.find("\"", pos)) != std::string::npos) {
                    escaped_query.replace(pos, 1, "\\\"");
                    pos += 2;
                }
                std::string remote_cmd = "python3 ~/.dais/bin/db_handler.py \"" + escaped_query + "\"";
                json_result = execute_remote_command(remote_cmd, 10000); // 10s timeout for DB query
            } else {
                // --- LOCAL EXECUTION ---
                // 1. Invoke Python Handler
                // We use the embedded interpreter to import and run the script.
                py::module_ handler = py::module_::import("db_handler");
                
                // Pass CWD to Python so it can find local .env and config files
                std::string cwd_str = shell_cwd_.string();
                json_result = handler.attr("handle_command")(query, cwd_str).cast<std::string>();
            }
            
            // 2. Parse Result
            py::module_ json = py::module_::import("json");
            py::object result_obj = json.attr("loads")(json_result);
            
            std::string status = result_obj["status"].cast<std::string>();
            
            // --- HANDLING MISSING PACKAGES (Interactive Install) ---
            if (status == "missing_pkg") {
                std::string pkg = result_obj["package"].cast<std::string>();
                
                std::string location = is_remote_session_ ? ("REMOTE: " + pty_.get_foreground_process_name()) : "LOCAL";
                if (is_remote_session_) location = "REMOTE"; 

                std::cout << "\r\n" << handlers::Theme::STRUCTURE << "[" << handlers::Theme::WARNING << "Missing Package" << handlers::Theme::STRUCTURE << "]" << handlers::Theme::RESET 
                          << " Package '" << handlers::Theme::VALUE << pkg << handlers::Theme::RESET << "' on " << handlers::Theme::UNIT << location << handlers::Theme::RESET << ". Install now"
                          << (is_remote_session_ ? " (user-scope)" : "") << "? (y/N) " << std::flush;
                
                // Read single char response (assuming raw mode)
                char c = 0;
                while (true) {
                    if (read(STDIN_FILENO, &c, 1) > 0) {
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }

                if (c == 'y' || c == 'Y') {
                    std::cout << "Y\r\n"; // Echo
                    std::string cmd;
                    if (is_remote_session_) {
                         cmd = "pip install --user " + pkg;
                    } else {
                         cmd = "pip install " + pkg;
                    }
                    
                    // Inject installation command
                    const char* clear_line = "\x15"; 
                    write(pty_.get_master_fd(), clear_line, 1);
                    write(pty_.get_master_fd(), cmd.c_str(), cmd.size());
                    write(pty_.get_master_fd(), "\n", 1); 
                } else {
                    std::cout << "N\r\n";
                }
                return;
            }

            if (status == "error") {
                std::string msg = result_obj["message"].cast<std::string>();
                std::cout << handlers::Theme::STRUCTURE << "[" << handlers::Theme::ERROR << "DB Error" << handlers::Theme::STRUCTURE << "] " << handlers::Theme::RESET 
                          << msg << "\r\n" << std::flush;
                return;
            }

            // 3. Handle Actions
            std::string action = result_obj["action"].cast<std::string>();
            std::string data = result_obj["data"].cast<std::string>();
            
            if (action == "print") {
                // ACTION: Print directly to terminal
                std::cout << "\r\n";
                
                std::string formatted = data;
                size_t pos = 0;
                while ((pos = formatted.find("\n", pos)) != std::string::npos) {
                    formatted.replace(pos, 1, "\r\n");
                    pos += 2;
                }
                std::cout << formatted << "\r\n" << std::flush;
                
            } else if (action == "page") {
                // ACTION: Open in Pager (less)
                std::string pager_cmd = "less -S"; 
                if (result_obj.contains("pager")) {
                    pager_cmd = result_obj["pager"].cast<std::string>();
                }
                
                std::string file_arg = "\"" + data + "\"";
                std::string cmd;
                
                // Pager Fallback Polyfill
                if (is_remote_session_) {
                    bool has_less = check_and_offer_less_install();
                    if (has_less) {
                        std::string polyfill = "{ " + pager_cmd + " " + file_arg + " 2>/dev/null || cat " + file_arg + "; }";
                        cmd = polyfill + "; rm -f " + file_arg;
                    } else {
                        cmd = "cat " + file_arg + "; rm -f " + file_arg;
                    }
                } else {
                    std::string polyfill = "{ " + pager_cmd + " " + file_arg + " 2>/dev/null || cat " + file_arg + "; }";
                    cmd = polyfill + "; rm -f " + file_arg;
                }
                
                // === REMOTE INJECTION ===
                // 1. Clear the line with ANSI (hides echo of cat command)
                // 2. Run the pager command
                std::string wrapped_cmd = "printf '\\033[A\\033[2K'; " + cmd;
                std::string full_inject = "\x15 " + wrapped_cmd + "\n";
                write(pty_.get_master_fd(), full_inject.c_str(), full_inject.size());
            }
            
        } catch (const std::exception& e) {
            std::cout << handlers::Theme::STRUCTURE << "[" << handlers::Theme::ERROR << "DB Error" << handlers::Theme::STRUCTURE << "] " << handlers::Theme::RESET 
                      << "Python/Engine Error: " << e.what() << "\r\n" << std::flush;
        }
    }

    /**
     * @brief Deploys the Python DB Handler script to the remote host.
     * 
     * Uses introspection (inspect.getsource) to read the local `db_handler.py` source code,
     * encodes it in Base64, and injects it into `~/.dais/bin/db_handler.py` on the remote host.
     * This ensures the remote environment has the exact same logic logic as the local one.
     */
    void Engine::deploy_remote_db_handler() {
        if (remote_db_deployed_ || !is_remote_session_) return;
              
        std::string script_content;
        try {
            py::module_ inspect = py::module_::import("inspect");
            py::module_ handler = py::module_::import("db_handler");
            script_content = inspect.attr("getsource")(handler).cast<std::string>();
        } catch (const std::exception& e) {
            return; 
        }

        // 2. Prepare Remote Paths
        std::string b64 = base64_encode((const unsigned char*)script_content.data(), script_content.size());
        
        std::string temp_b64 = "~/.dais/bin/db_handler.py.b64";
        std::string target_path = "~/.dais/bin/db_handler.py";

        // 3. Inject (Silent Streaming)
        // Temporarily unset PS2 to avoid continuation prompts (> >) appearing during heredoc paste
        execute_remote_command("export DAIS_OLD_PS2=\"$PS2\"; export PS2=''; set +o history", 2000); 
        execute_remote_command("mkdir -p -m 700 ~/.dais/bin", 2000);
        execute_remote_command("rm -f " + temp_b64, 2000);
        execute_remote_command("stty -echo", 2000);

        std::string start_heredoc = "cat > " + temp_b64 + " << 'DAIS_EOF'\n";
        write(pty_.get_master_fd(), start_heredoc.c_str(), start_heredoc.size());

        constexpr size_t PAYLOAD_CHUNK = 4096;
        size_t sent = 0;
        while (sent < b64.size()) {
            size_t n = std::min(PAYLOAD_CHUNK, b64.size() - sent);
            write(pty_.get_master_fd(), b64.data() + sent, n);
            sent += n;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        std::string end_heredoc = "\nDAIS_EOF\n";
        write(pty_.get_master_fd(), end_heredoc.c_str(), end_heredoc.size());
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        execute_remote_command("stty echo", 2000);

        // 4. Decode & Restore Environment
        std::string deploy_cmd = 
            "base64 -d " + temp_b64 + " > " + target_path + " && "
            "rm " + temp_b64 + " && "
            "export PS2=\"$DAIS_OLD_PS2\"; unset DAIS_OLD_PS2; set -o history && " 
            "echo DAIS_DEPLOY_OK";

        std::string result = execute_remote_command(deploy_cmd, 5000);
        
        if (result.find("DAIS_DEPLOY_OK") != std::string::npos) {
            remote_db_deployed_ = true;
        }
    }

    /**
     * @brief Checks if 'less' is available on the remote host.
     * 
     * If not found, informs the user (onc per session) that pagination 
     * is disabled and they should install it for a better experience.
     */
    bool Engine::check_and_offer_less_install() {
        if (less_checked_) {
            return less_available_;
        }
        less_checked_ = true;

        std::string check_result = execute_remote_command("command -v less >/dev/null 2>&1 && echo LESS_OK || echo LESS_MISSING", 2000);
        
        if (check_result.find("LESS_OK") != std::string::npos) {
            less_available_ = true;
            return true;
        }

        std::cout << "\r\n[" << handlers::Theme::LOGO << "DB" << handlers::Theme::RESET 
                  << "] 'less' pager not found. Using raw output. Install 'less' for pagination.\r\n" << std::flush;
        
        less_available_ = false;
        return false;
    }

}
