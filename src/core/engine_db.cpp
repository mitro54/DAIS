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
#include <poll.h>
#include <algorithm>
#include <vector>

namespace dais::core {

    /**
     * @brief Internal helper to verify if a path is safe to 'rm -rf'.
     * Prevents accidental deletion of root, home, or system dirs.
     */
    static bool is_path_safe_for_deletion(const std::string& path) {
        if (path.empty()) return false;
        
        // Critical system path protection
        std::vector<std::string> banned = {"/", "/home", "/root", "/boot", "/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/dev", "/proc", "/sys", "/media", "/mnt"};
        
        std::string p = path;
        // Trim trailing slash for comparison
        while (p.size() > 1 && p.back() == '/') p.pop_back();
        
        if (std::find(banned.begin(), banned.end(), p) != banned.end()) return false;
        
        // Safety requirement: MUST be a virtual environment directory (strict check)
        bool is_venv = (p == ".venv") || 
                       (p.length() >= 6 && p.substr(p.length() - 6) == "/.venv");
        
        if (!is_venv) return false;
        
        // Must be at least a few chars long (prevent rm -rf /...)
        if (p.length() < 5) return false;

        return true;
    }

    /**
     * @brief Translates '\n' to '\r\n' for proper PTY formatting.
     * Prevents the "staircase" effect in raw terminal mode.
     */
    static std::string translate_newlines(const std::string& input) {
        std::string out = input;
        size_t pos = 0;
        while ((pos = out.find("\n", pos)) != std::string::npos) {
            // Check if it's already \r\n
            if (pos > 0 && out[pos-1] == '\r') {
                pos += 1;
                continue;
            }
            out.replace(pos, 1, "\r\n");
            pos += 2;
        }
        return out;
    }

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
            std::string remote_python = "python3";
            std::string anchor_dir = ".";

            if (is_remote_session_) {
                // --- REMOTE EXECUTION ---
                check_remote_session(); // Sync state
                deploy_remote_agent();  // Attempt to deploy agent/establish environment

                // 1. Python Interpreter Detection (Smart Coupled Discovery)
                // Anchors .venv to the nearest .env file (Project Root)
                
                std::string detect_cmd = "( ( d=\".\"; while [ \"$d\" != \"\" ]; do if [ -f \"$d/.env\" ]; then p=\"python3\"; [ -x \"$d/.venv/bin/python\" ] && \"$d/.venv/bin/python\" -m pip --version >/dev/null 2>&1 && p=\"$d/.venv/bin/python\"; echo \"DAIS_DET:$p|$d\"; exit; fi; case \"$d\" in .) d=\"..\" ;; /*) [ \"$d\" = \"/\" ] && d=\"\" || d=\"$(dirname \"$d\")\" ;; *) d=\"\" ;; esac; [ \"$d\" = \"$HOME\" ] && break; done; p=\"python3\"; [ -x \"./.venv/bin/python\" ] && \"./.venv/bin/python\" -m pip --version >/dev/null 2>&1 && p=\"./.venv/bin/python\"; echo \"DAIS_DET:$p|.\"; ) )";
                std::string detect_res = execute_remote_command(detect_cmd, 3000);
                
                size_t start = detect_res.find("DAIS_DET:");
                if (start != std::string::npos) {
                    std::string line = detect_res.substr(start + 9);
                    size_t end = line.find_first_of("\r\n");
                    if (end != std::string::npos) line = line.substr(0, end);
                    
                    size_t sep = line.find('|');
                    if (sep != std::string::npos) {
                        remote_python = line.substr(0, sep);
                        anchor_dir = line.substr(sep + 1);
                        
                        // Robust trim
                        auto trim = [](std::string& s) {
                            s.erase(0, s.find_first_not_of(" \t\n\r"));
                            s.erase(s.find_last_not_of(" \t\n\r") + 1);
                        };
                        trim(remote_python);
                        trim(anchor_dir);
                    }
                }

                // 2. Base64 Encode Query (Mitigate Shell Injection)
                std::string b64_query = base64_encode((const unsigned char*)query.data(), query.size());

                std::string remote_cmd;
                
                if (remote_agent_deployed_) {
                    // OPTION A: Standard File-Based (Faster, Persistent)
                    deploy_remote_db_handler();

                    // Use the same base directory as the agent if possible, or fallback
                    std::string db_script_path = remote_bin_path_;
                    size_t last_slash = db_script_path.find_last_of('/');
                    if (last_slash != std::string::npos) {
                        db_script_path = db_script_path.substr(0, last_slash);
                    } else {
                        db_script_path = "~/.dais/bin"; // Default fallback
                    }
                    db_script_path += "/db_handler.py";

                    remote_cmd = remote_python + " " + db_script_path + " --b64-query \"" + b64_query + "\"";
                } else {
                    // OPTION B: Stealth/Fallback (Pipe into memory)
                    // Used when file system is read-only or blocked (Case C)
                    
                    std::string script_content;
                    try {
                        py::module_ inspect = py::module_::import("inspect");
                        py::module_ handler = py::module_::import("db_handler");
                        script_content = inspect.attr("getsource")(handler).cast<std::string>();
                    } catch (const std::exception& e) {
                        throw std::runtime_error("Failed to load local db_handler for stealth injection");
                    }

                    std::string script_b64 = base64_encode((const unsigned char*)script_content.data(), script_content.size());
                    
                    // Command: echo "B64" | base64 -d | python3 - --b64-query "B64_QUERY"
                    remote_cmd = "echo \"" + script_b64 + "\" | base64 -d | " + remote_python + " - --b64-query \"" + b64_query + "\"";
                }
                
                json_result = execute_remote_command(remote_cmd, 15000); // 15s timeout

                // Safety: Check if result is empty or garbage (pollution from remote shell)
                auto is_mostly_whitespace = [](const std::string& s) {
                    return s.empty() || std::all_of(s.begin(), s.end(), [](unsigned char c){ return std::isspace(c); });
                };

                if (is_mostly_whitespace(json_result) || (json_result.find("{") == std::string::npos && json_result.find("[") == std::string::npos)) {
                    std::cout << "\r\n" << handlers::Theme::STRUCTURE << "[" << handlers::Theme::ERROR << "DB Error" << handlers::Theme::STRUCTURE << "] " << handlers::Theme::RESET 
                              << "Remote command returned invalid response.\r\n";
                    if (json_result.empty()) {
                        std::cout << handlers::Theme::WARNING << "[Tip] " << handlers::Theme::RESET << "Command returned no output. Check if " << handlers::Theme::VALUE << remote_python << handlers::Theme::RESET << " is working on remote.\r\n";
                    } else {
                        // Use translate_newlines for raw response too
                        std::cout << handlers::Theme::STRUCTURE << "--- [Raw Response] ---" << handlers::Theme::RESET << "\r\n" 
                                  << translate_newlines(json_result) << "\r\n" 
                                  << handlers::Theme::STRUCTURE << "----------------------" << handlers::Theme::RESET << "\r\n";
                    }
                    return;
                }
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
            
            // --- HANDLING MISSING PACKAGES (Venv approach) ---
            if (status == "missing_pkg") {
                std::string pkg = result_obj["package"].cast<std::string>();
                std::string location = is_remote_session_ ? "REMOTE" : "LOCAL";

                if (is_remote_session_) {
                    // 1. Remote Venv Logic (Coupled to configuration)
                    // We reuse the anchor_dir detected earlier
                    std::string venv_bin_path = (anchor_dir == "." ? "./.venv/bin/python" : anchor_dir + "/.venv/bin/python");
                    std::string venv_check = execute_remote_command("test -x " + venv_bin_path + " && " + venv_bin_path + " -m pip --version >/dev/null 2>&1 && echo YES", 2000);
                    bool has_venv = (venv_check.find("YES") != std::string::npos);

                    if (has_venv) {
                        // Scenario A: Venv exists, but package missing
                        std::cout << "\r\n" << handlers::Theme::STRUCTURE << "[" << handlers::Theme::WARNING << "Missing Package" << handlers::Theme::STRUCTURE << "]" << handlers::Theme::RESET 
                                  << " Package '" << handlers::Theme::VALUE << pkg << handlers::Theme::RESET << "' is required for SQL connectivity but missing in your environment.\r\n"
                                  << "Install it into " << handlers::Theme::UNIT << venv_bin_path << handlers::Theme::RESET << " now? (y/N) " << std::flush;
                    } else {
                        // Scenario B: No venv
                        std::string target_venv = (anchor_dir == "." ? ".venv" : anchor_dir + "/.venv");
                        std::cout << "\r\n" << handlers::Theme::STRUCTURE << "[" << handlers::Theme::WARNING << "Missing Package" << handlers::Theme::STRUCTURE << "]" << handlers::Theme::RESET 
                                  << " Package '" << handlers::Theme::VALUE << pkg << handlers::Theme::RESET << "' is required for SQL connectivity on " << handlers::Theme::UNIT << "REMOTE" << handlers::Theme::RESET << ".\r\n"
                                  << "Create a private virtual environment (" << handlers::Theme::VALUE << target_venv << handlers::Theme::RESET << ") and install? (y/N) " << std::flush;
                    }

                    char c = 0;
                    struct pollfd fds[1];
                    fds[0].fd = STDIN_FILENO;
                    fds[0].events = POLLIN;

                    // Non-blocking wait with poll (max 30s timeout total)
                    int ret = poll(fds, 1, 30000); 
                    if (ret > 0 && (fds[0].revents & POLLIN)) {
                        read(STDIN_FILENO, &c, 1);
                    } else if (ret == 0) {
                        std::cout << " (Timeout)\r\n";
                        return;
                    }

                    if (c == 'y' || c == 'Y') {
                        std::cout << "Y\r\n";
                        tcflush(STDIN_FILENO, TCIFLUSH);

                        std::string venv_path = (anchor_dir == "." ? ".venv" : anchor_dir + "/.venv");
                        std::string py_bin = (anchor_dir == "." ? "./.venv/bin/python" : anchor_dir + "/.venv/bin/python");

                        // Safety Check for deletion
                        std::string purge_cmd = "";
                        if (is_path_safe_for_deletion(venv_path)) {
                            purge_cmd = "rm -rf \"" + venv_path + "\" && ";
                        }

                        std::string setup_cmd;
                        if (!has_venv) {
                            // High Reliability Creation: Purge -> Create -> Ensure Pip -> Install
                            setup_cmd = "set +o history && " + purge_cmd + "python3 -m venv " + venv_path + " && (" + py_bin + " -m ensurepip --default-pip || true) && " + py_bin + " -m pip install " + pkg + " && echo INSTALL_DONE && set -o history";
                        } else {
                            setup_cmd = "set +o history && " + py_bin + " -m pip install " + pkg + " && echo INSTALL_DONE && set -o history";
                        }

                        // Inform user of the exact command being run for transparency
                        std::string display_cmd = (has_venv ? "" : "python3 -m venv " + venv_path + " && ") + py_bin + " -m pip install " + pkg;
                        std::cout << handlers::Theme::STRUCTURE << "[" << handlers::Theme::NOTICE << "Running" << handlers::Theme::STRUCTURE << "] " << handlers::Theme::RESET 
                                  << handlers::Theme::VALUE << translate_newlines(display_cmd) << handlers::Theme::RESET << "\r\n";

                        std::string output = execute_remote_command(setup_cmd, 120000); // 2 min timeout

                        if (output.find("INSTALL_DONE") == std::string::npos) {
                             // Failure! Attempt to diagnose
                             std::cout << "\r\n" << handlers::Theme::STRUCTURE << "[" << handlers::Theme::ERROR << "Install Failed" << handlers::Theme::STRUCTURE << "] " << handlers::Theme::RESET 
                                       << "Installation command did not complete successfully.\r\n";

                             if (output.find("python3-venv") != std::string::npos) {
                                 std::cout << handlers::Theme::WARNING << "[Tip] " << handlers::Theme::RESET << "The 'python3-venv' package is missing on the remote host.\r\n"
                                           << "Please run 'sudo apt install python3-venv' on the server manually.\r\n";
                             } else if (output.find("No module named pip") != std::string::npos) {
                                 std::cout << handlers::Theme::WARNING << "[Tip] " << handlers::Theme::RESET << "The venv was created without 'pip'.\r\n"
                                           << "Please run 'sudo apt install python3-pip-whl python3-setuptools-whl' on the host to fix venv provisioning.\r\n";
                             } else if (!has_venv && execute_remote_command("test -x .venv/bin/python || echo MISSING", 1000).find("MISSING") != std::string::npos) {
                                 std::cout << handlers::Theme::WARNING << "[Tip] " << handlers::Theme::RESET << "Virtual environment creation failed (structure incomplete).\r\n"
                                           << "Ensure you have enough disk space and permissions in the current directory.\r\n";
                             } else {
                                 // Show raw output (last few lines)
                                 std::cout << handlers::Theme::STRUCTURE << "--- [Remote Output] ---" << handlers::Theme::RESET << "\r\n" << output << "\r\n" << handlers::Theme::STRUCTURE << "-----------------------" << handlers::Theme::RESET << "\r\n";
                             }
                             return;
                        }

                        std::cout << handlers::Theme::STRUCTURE << "[" << handlers::Theme::SUCCESS << "Success" << handlers::Theme::STRUCTURE << "] " << handlers::Theme::RESET 
                                  << "Environment ready. Retrying query...\r\n";
                        
                        handle_db_command(query); // Retry
                    } else {
                        std::cout << "N\r\n";
                    }
                    return;
                } else {
                    // LOCAL: Legacy behavior
                    std::cout << "\r\n" << handlers::Theme::STRUCTURE << "[" << handlers::Theme::WARNING << "Missing Package" << handlers::Theme::STRUCTURE << "]" << handlers::Theme::RESET 
                              << " Package '" << handlers::Theme::VALUE << pkg << handlers::Theme::RESET << "' on " << handlers::Theme::UNIT << location << handlers::Theme::RESET << ". Install now? (y/N) " << std::flush;
                    
                    char c = 0;
                    while (read(STDIN_FILENO, &c, 1) <= 0) std::this_thread::sleep_for(std::chrono::milliseconds(10));

                    if (c == 'y' || c == 'Y') {
                        std::cout << "Y\r\n";
                        tcflush(STDIN_FILENO, TCIFLUSH);
                        std::string cmd = "pip install " + pkg;
                        const char* clear_line = "\x15"; 
                        write(pty_.get_master_fd(), clear_line, 1);
                        write(pty_.get_master_fd(), cmd.c_str(), cmd.size());
                        write(pty_.get_master_fd(), "\n", 1); 
                    } else {
                        std::cout << "N\r\n";
                    }
                    return;
                }
            }

            if (status == "error") {
                std::string msg = result_obj["message"].cast<std::string>();
                std::cout << handlers::Theme::STRUCTURE << "[" << handlers::Theme::ERROR << "DB Error" << handlers::Theme::STRUCTURE << "] " << handlers::Theme::RESET 
                          << translate_newlines(msg) << "\r\n" << std::flush;
                return;
            }

            // 3. Handle Actions
            std::string action = result_obj["action"].cast<std::string>();
            std::string data = result_obj["data"].cast<std::string>();
            
            if (action == "print") {
                // ACTION: Print directly to terminal
                std::cout << "\r\n" << translate_newlines(data) << "\r\n" << std::flush;
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
                        // No '|| cat' fallback: less is confirmed installed.
                        // Using fallback would dump the entire table if user Ctrl+Z's out of less.
                        // Prepend ~/.dais/bin to PATH so locally-installed less is found.
                        cmd = "export PATH=\"$HOME/.dais/bin:$PATH\"; " + pager_cmd + " " + file_arg + "; rm -f " + file_arg;
                    } else {
                        cmd = "cat " + file_arg + "; rm -f " + file_arg;
                    }
                } else {
                    std::string polyfill = "{ " + pager_cmd + " " + file_arg + " 2>/dev/null || cat " + file_arg + "; }";
                    cmd = polyfill + "; rm -f " + file_arg;
                }
                
                // === CLEAN PAGER INJECTION ===
                // Phase 1: Suppress terminal echo (hides command text from user)
                {
                    ScopedSuppression suppression(suppress_output_);
                    std::string echo_off = "\x15 set +o history 2>/dev/null; stty -echo; set -o history 2>/dev/null\n";
                    write(pty_.get_master_fd(), echo_off.c_str(), echo_off.size());
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }

                // Phase 2: Inject pager command (no echo, no history, clean restore)
                // IMPORTANT: 'stty echo' is placed at the START so terminal is restored before
                // the pager takes over. If the user Ctrl+Z's out of less, the terminal remains
                // usable because echo was already re-enabled.
                std::string full_inject = "\x15 set +o history 2>/dev/null; stty echo; " + cmd + "; set -o history 2>/dev/null\n";
                write(pty_.get_master_fd(), full_inject.c_str(), full_inject.size());
            }
            
        } catch (const std::exception& e) {
            std::cout << handlers::Theme::STRUCTURE << "[" << handlers::Theme::ERROR << "DB Error" << handlers::Theme::STRUCTURE << "] " << handlers::Theme::RESET 
                      << translate_newlines(std::string("Python/Engine Error: ") + e.what()) << "\r\n" << std::flush;
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
        
        // Silence all PTY output during deployment (RAII — clears on any exit)
        ScopedSuppression suppression(suppress_output_);
              
        std::string script_content;
        try {
            py::module_ inspect = py::module_::import("inspect");
            py::module_ handler = py::module_::import("db_handler");
            script_content = inspect.attr("getsource")(handler).cast<std::string>();
        } catch (const std::exception& e) {
            return; 
        }

        std::string b64 = base64_encode((const unsigned char*)script_content.data(), script_content.size());
        
        // Use the same folder where the agent lives (remote_bin_path_)
        // If agent isn't deployed (e.g. pure python mode?), we need to find a place.
        // But usually agent deployment runs first.
        
        std::string base_dir;
        if (!remote_bin_path_.empty()) {
            size_t last_slash = remote_bin_path_.find_last_of('/');
            if (last_slash != std::string::npos) {
                base_dir = remote_bin_path_.substr(0, last_slash);
            } else {
                base_dir = "~/.dais/bin";
            }
        } else {
             // Fallback if agent failed or not deployed yet (shouldn't happen for DB but safe to have)
             base_dir = "~/.dais/bin";
        }

        std::string target_path = base_dir + "/db_handler.py";
        std::string temp_b64 = target_path + ".b64";

        // 3. Inject (Silent Streaming)
        // Temporarily unset PS2 to avoid continuation prompts (> >) appearing during heredoc paste
        execute_remote_command("export DAIS_OLD_PS2=\"$PS2\"; export PS2=''; set +o history", 2000); 
        
        // Create dir if needed (agent might have done it, but idempotency is good)
        execute_remote_command("mkdir -p -m 700 " + base_dir, 2000);
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
     * If not found, informs the user (once per session) that pagination 
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

        // Offer to install less (following the same pattern as missing Python packages)
        std::cout << "\r\n" << handlers::Theme::STRUCTURE << "[" << handlers::Theme::WARNING << "Missing Tool" << handlers::Theme::STRUCTURE << "]" << handlers::Theme::RESET 
                  << " '" << handlers::Theme::VALUE << "less" << handlers::Theme::RESET << "' pager not found. Install for table pagination?\r\n"
                  << handlers::Theme::STRUCTURE << "[" << handlers::Theme::WARNING << "Note" << handlers::Theme::STRUCTURE << "]" << handlers::Theme::RESET << " May require sudo/root privileges.\r\n"
                  << "Proceed? (y/N) " << std::flush;
        
        char c = 0;
        struct pollfd fds[1];
        fds[0].fd = STDIN_FILENO;
        fds[0].events = POLLIN;

        // Non-blocking wait with poll (max 15s timeout)
        int ret = poll(fds, 1, 15000); 
        if (ret > 0 && (fds[0].revents & POLLIN)) {
            read(STDIN_FILENO, &c, 1);
        } else if (ret == 0) {
            std::cout << " (Timeout)\r\n";
            less_available_ = false;
            return false;
        }

        if (c == 'y' || c == 'Y') {
            std::cout << "Y\r\n";
            tcflush(STDIN_FILENO, TCIFLUSH);

            // Cross-distro installation logic (tries without sudo first, escalates only if needed)
            // CRITICAL: Use 'sudo -n' (non-interactive) — if a password is required, sudo exits
            // immediately instead of prompting. A hanging sudo prompt would hijack the PTY
            // and corrupt all subsequent commands.
            std::string install_cmd = 
                "( apt-get install -y less 2>/dev/null "
                "|| yum install -y less 2>/dev/null "
                "|| apk add less 2>/dev/null "
                "|| sudo -n apt-get install -y less 2>/dev/null "
                "|| sudo -n yum install -y less 2>/dev/null "
                // User-space fallback: download .deb and extract binary to ~/.dais/bin/ (no root)
                "|| ( mkdir -p ~/.dais/bin && cd /tmp && apt-get download less 2>/dev/null "
                "&& dpkg-deb -x less_*.deb /tmp/.dais_less_extract 2>/dev/null "
                "&& cp /tmp/.dais_less_extract/usr/bin/less ~/.dais/bin/less "
                "&& chmod +x ~/.dais/bin/less "
                "&& rm -rf /tmp/.dais_less_extract /tmp/less_*.deb ) 2>/dev/null "
                ") && ( command -v less >/dev/null 2>&1 || test -x ~/.dais/bin/less ) && echo LESS_INSTALLED";

            std::cout << handlers::Theme::STRUCTURE << "[" << handlers::Theme::NOTICE << "Installing" << handlers::Theme::STRUCTURE << "] " << handlers::Theme::RESET 
                      << "Attempting to install 'less'...\r\n" << std::flush;

            std::string result = execute_remote_command(install_cmd, 30000);
            
            if (result.find("LESS_INSTALLED") != std::string::npos) {
                std::cout << handlers::Theme::STRUCTURE << "[" << handlers::Theme::SUCCESS << "Success" << handlers::Theme::STRUCTURE << "] " << handlers::Theme::RESET 
                          << "'less' installed successfully.\r\n" << std::flush;
                less_available_ = true;
                return true;
            } else {
                std::cout << handlers::Theme::STRUCTURE << "[" << handlers::Theme::WARNING << "Failed" << handlers::Theme::STRUCTURE << "] " << handlers::Theme::RESET 
                          << "Could not install 'less'. Using raw output.\r\n"
                          << handlers::Theme::STRUCTURE << "[" << handlers::Theme::WARNING << "Tip" << handlers::Theme::STRUCTURE << "] " << handlers::Theme::RESET << "Try manually: sudo apt install less\r\n" << std::flush;
                // Brief pause so the user can read the message before table output floods the screen
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
        } else {
            std::cout << "N\r\n";
        }
        
        less_available_ = false;
        return false;
    }

}
