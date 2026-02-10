/**
 * @file engine_remote.cpp
 * @brief Implementation of Engine's remote session management (SSH/Docker).
 * 
 * This module handles:
 * - Detection of remote SSH sessions via process tree analysis.
 * - Secure execution of commands on remote hosts using a hidden Sentinel logic.
 * - Deployment of the DAIS agent binary to remote hosts for structured output (ls --json).
 * - Architecture detection and integrity verification of remote agents.
 */

#include "core/engine.hpp"
#include "core/command_handlers.hpp"
#include "core/dais_agents.hpp"
#include "core/base64.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <unistd.h> // for write

namespace dais::core {

    /**
     * @brief Checks if the current foreground process indicates a remote session (SSH).
     * 
     * Uses a heuristic based on the process name (containing "ssh").
     * Monitors the foreground process PID to detect:
     * 1. New SSH sessions (PID changed while name is still ssh).
     * 2. Exited SSH sessions (PID changed and name is no longer ssh).
     * 
     * When a new session is detected, it resets the remote state (agent deployed,
     * architecture, etc.) to ensure a fresh environment scan.
     */
    void Engine::check_remote_session() {
        std::string fg = pty_.get_foreground_process_name();
        int fg_pid = pty_.get_foreground_process_pid();
        
        bool was = is_remote_session_;
        
        // Refined heuristic: prevent matching ssh-keygen, ssh-agent, etc.
        // We look for "ssh" exactly, or ending with "/ssh" (e.g. /usr/bin/ssh)
        bool detected_ssh = false;
        if (fg == "ssh") {
            detected_ssh = true;
        } else if (fg.size() >= 4 && fg.substr(fg.size() - 4) == "/ssh") {
            detected_ssh = true;
        }

        if (detected_ssh) {
            is_remote_session_ = true;
            
            // New Session Logic:
            // If the PID changed, it's a completely new SSH connection.
            // (Even if the user just exited one ssh and started another immediately)
            if (fg_pid != remote_session_pid_) {
                // RESET STATE
                remote_agent_deployed_ = false;
                remote_db_deployed_ = false;
                remote_bin_path_ = "";
                remote_arch_ = "";
                remote_session_pid_ = fg_pid;
                
                // Signal that we want to deploy as soon as we see the first prompt
                pending_remote_deployment_ = true;
                ready_to_deploy_ = false;
            }
        } else {
            // Not detecting SSH currently.
            // Safe Reset: Only verify we actually LEFT the session if the previous PID is gone
            // or if the current foreground PID is explicitly DIFFERENT and NOT ssh.
            if (was) {
               if (fg_pid != remote_session_pid_) {
                   is_remote_session_ = false;
                   remote_session_pid_ = -1;
               } 
            } else {
                is_remote_session_ = false;
            }
        }
    }

    /**
     * @brief Executes a command on the remote host and captures its output.
     * 
     * Strategy:
     * 1. Appends a unique "Sentinel" echo to the command: `cmd; echo DAIS_END_<timestamp>`
     * 2. This ensures we can distinguish command output from the command echo itself.
     * 3. Uses arithmetic expansion `$(( A + B ))` for the sentinel to prevent
     *    false positives where the shell simply echoes the typed command string.
     * 
     * Capture Logic:
     * - The PTY output is buffered until the Sentinel string is found.
     * - A race condition exists where the prompt appears *after* the sentinel.
     *   We wait for a shell prompt ($, #, >) or user-defined prompts to appear
     *   before finishing capture, ensuring the UI remains clean.
     * 
     * @param cmd The command to execute (e.g., "ls -la", "uname -m")
     * @param timeout_ms Max time to wait for the sentinel.
     * @return The clean stdout of the command, with ANSI codes and echoes stripped.
     */
    std::string Engine::execute_remote_command(const std::string& cmd, int timeout_ms) {
        // Only run if legitimate
        if (!pty_.is_shell_idle() && !is_remote_session_) return "";

        last_remote_prompt_.clear(); 
        
        // 1. Prepare Capture
        {
            std::lock_guard<std::mutex> lock(capture_mutex_);
            capture_buffer_.clear();
            capture_mode_ = true;
        }

        // 2. Send Command with Sentinel
        auto now = std::chrono::system_clock::now().time_since_epoch().count() % 1000000000;
        long long part_a = now / 2;
        long long part_b = now - part_a;
        
        std::string sentinel = "DAIS_END_" + std::to_string(now);
        
        // Command format: "\x15 cmd; echo DAIS_END_$(( A + B ))\n"
        // \x15 (Ctrl+U) clears any existing junk on the line.
        // Leading space prevents history pollution (if HISTCONTROL=ignorespace).
        std::string full_cmd;
        full_cmd += kCtrlU;
        full_cmd += " " + cmd + "; echo DAIS_END_$(( " + std::to_string(part_a) + " + " + std::to_string(part_b) + " ))\n";
        
        write(pty_.get_master_fd(), full_cmd.c_str(), full_cmd.size());

        // 3. Wait for Sentinel
        std::unique_lock<std::mutex> lock(capture_mutex_);
        bool finished = capture_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]{
            return capture_buffer_.find(sentinel) != std::string::npos;
        });

        if (finished) {
            // Prompt-Aware Buffering: Wait for the shell prompt to appear after the sentinel.
            // We use a short timeout (50ms) because for local/fast connections the prompt 
            // usually arrives immediately after the command output. 
            // Should not wait 1s as it creates noticeable lag if the prompt detection fails.
            capture_cv_.wait_for(lock, std::chrono::milliseconds(10), [&]{
                if (capture_buffer_.empty()) return false;
                char last = capture_buffer_.back();
                if (last == '\n' || last == '\r') return false;

                // Check user-configured prompts
                for (const auto& p : config_.shell_prompts) {
                    if (capture_buffer_.size() >= p.size() && 
                        capture_buffer_.compare(capture_buffer_.size() - p.size(), p.size(), p) == 0) {
                        return true; 
                    }
                }
                // Fallback heuristic prompts
                if (capture_buffer_.size() >= 2) {
                    char second_last = capture_buffer_[capture_buffer_.size() - 2];
                    if (last == ' ' && (second_last == '$' || second_last == '#' || second_last == '>')) {
                        return true;
                    }
                }
                return false;
            });
        }

        // 4. Disable Capture
        capture_mode_ = false;

        // Restore prompt to visual state if we swallowed it
        if (finished && !capture_buffer_.empty()) {
            size_t sent_pos = capture_buffer_.rfind(sentinel);
            if (sent_pos != std::string::npos) {
                size_t after_sentinel = sent_pos + sentinel.size();
                if (after_sentinel < capture_buffer_.size()) {
                    std::string prompt_part = capture_buffer_.substr(after_sentinel);
                    if (!prompt_part.empty()) {
                        last_remote_prompt_ = prompt_part;
                        
                        std::lock_guard<std::mutex> prompt_lock(prompt_mutex_);
                        prompt_buffer_ += prompt_part;
                        // Check for idle state based on this new prompt
                        for (const auto& p : config_.shell_prompts) {
                            if (prompt_buffer_.size() >= p.size() && 
                                prompt_buffer_.compare(prompt_buffer_.size() - p.size(), p.size(), p) == 0) {
                                shell_state_ = ShellState::IDLE;
                                // Need to recalculate visual width for correct cursor handling
                                // We call calculate_visual_length via Engine instance method? 
                                // Actually calculate_visual_length is removed from this file.
                                // We rely on Engine::ensure_visual_mode_init logic later or 
                                // we need the helper back if we want to fetch it here.
                                // NOTE: In decomposition, prompt_buffer_ update is enough for Engine::ensure_visual_mode_init 
                                // to pick it up later.
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (!finished) return ""; 

        // 5. Clean Buffer
        std::string clean = capture_buffer_;
        size_t sent_pos = clean.find(sentinel);
        if (sent_pos != std::string::npos) clean = clean.substr(0, sent_pos);
        
        // Remove Command Echo (first line usually)
        size_t first_newline = clean.find('\n');
        if (first_newline != std::string::npos) {
             std::string first_line = clean.substr(0, first_newline);
             if (first_line.find("DAIS_END_") != std::string::npos) {
                 clean = clean.substr(first_newline + 1);
             }
        }
        
        const char* ws = " \t\n\r\x0b\x0c";
        clean.erase(0, clean.find_first_not_of(ws));
        clean.erase(clean.find_last_not_of(ws) + 1);
        
        // 6. Strip ANSI Escape Codes
        std::string final_clean;
        final_clean.reserve(clean.size());
        bool in_esc = false;
        
        for (size_t i = 0; i < clean.size(); ++i) {
            char c = clean[i];
            if (c == kEsc) {
                in_esc = true;
                if (i + 1 < clean.size() && (clean[i+1] == '[' || clean[i+1] == '(')) i++;
                continue;
            }
            if (in_esc) {
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) in_esc = false;
                continue;
            }
            final_clean += c;
        }
        return final_clean;
    }

    /**
     * @brief Deploys the native DAIS helper agent to the remote host.
     * 
     * Steps:
     * 1. Identifies remote architecture (`uname -m`).
     * 2. Selects the appropriate pre-compiled binary blob.
     * 3. Checks existing installation hash to skip redundant deploys.
     * 4. Uploads binary via "streaming heredoc" (avoids transferring files).
     * 5. `stty -echo` is used to prevent the binary data from being echoed back, 
     *    which speeds up transfer and prevents terminal corruption.
     * 6. Verifies integrity (sha256sum) after deployment.
     */
    void Engine::deploy_remote_agent() {
        if (remote_agent_deployed_ || !is_remote_session_ || agent_deployment_failed_) return;
        if (!is_remote_session_ && !pty_.is_shell_idle()) return;
        
        // 1. Detect Architecture
        std::string out = execute_remote_command("uname -m", 5000);
        if (out.empty()) out = execute_remote_command("uname -a", 5000);
        if (out.empty()) return;

        if (out.find("x86_64") != std::string::npos) remote_arch_ = "x86_64";
        else if (out.find("aarch64") != std::string::npos) remote_arch_ = "aarch64";
        else if (out.find("armv7") != std::string::npos) remote_arch_ = "armv7l";
        else if (out.find("armv6") != std::string::npos) remote_arch_ = "armv6";
        else remote_arch_ = "unknown";

        if (remote_arch_ == "unknown" && out.empty()) return;

        // 2. Get Binary from Bundle
        auto agent = dais::core::agents::get_agent_for_arch(remote_arch_);
        if (agent.data == nullptr || agent.size == 0) {
            if (config_.show_logo) {
                 std::cout << "\r\n[" << handlers::Theme::WARNING << "-" << handlers::Theme::RESET 
                           << "] Agent binary for " << remote_arch_ << " is missing or empty. Skipping native deployment.\r\n";
            }
            return; 
        }

        // 3. Dynamic Location Search
        // Candidates for deployment (in order of preference)
        // 1. ~/.dais/bin (Standard persistence)
        // 2. $XDG_RUNTIME_DIR/dais (Modern Linux temp, often noexec-safe)
        // 3. /tmp/dais-<uid> (Fallback temp)
        std::vector<std::string> base_dirs = {
            "~/.dais/bin",
            "${XDG_RUNTIME_DIR:-/tmp}/dais", 
            "/tmp/dais-$(id -u)"
        };

        for (const auto& base_dir : base_dirs) {
            // A. Check Writability AND Tools (base64)
            // We use 'echo OK' to confirm success because exit codes are harder to trap cleanly in all shells
            // Also check for base64 availability
            std::string check_cmd = "command -v base64 >/dev/null 2>&1 && mkdir -p -m 700 " + base_dir + " >/dev/null 2>&1 && touch " + base_dir + "/.perm_check >/dev/null 2>&1 && rm " + base_dir + "/.perm_check >/dev/null 2>&1 && echo DAIS_OK";
            std::string check_res = execute_remote_command(check_cmd, 2000);
            
            if (check_res.find("DAIS_OK") == std::string::npos) {
                // If failed, it might be permissions OR missing base64.
                // We'll skip silently to next dir, but if it ends up failing all, the final error captures it.
                continue; 
            }

            // B. Define Target Path (Deterministic Naming)
            // dais-agent-<arch> (Transparent naming)
            std::string filename = "dais-agent-" + remote_arch_;
            std::string target_path = base_dir + "/" + filename;
            
            // Clean up path double slashes if any (though shells usually handle it)
            // We'll trust the shell to handle `//`
            
            bool need_deploy = true;
            std::string remote_hash_cmd = "sha256sum " + target_path + " 2>/dev/null | cut -d' ' -f1";
            std::string current_hash = execute_remote_command(remote_hash_cmd, 1000);
            
            const char* ws = " \t\n\r\x0b\x0c";
            if (current_hash.find_first_not_of(ws) != std::string::npos) {
                current_hash.erase(0, current_hash.find_first_not_of(ws));
                current_hash.erase(current_hash.find_last_not_of(ws) + 1);
            } else {
                current_hash.clear();
            }

            // C. Integrity Check
            // We search for the hash because 'execute_remote_command' might capture 
            // the command echo (e.g. "sha256sum ...") depending on shell behavior, 
            // making strict equality fail.
            if (!current_hash.empty() && current_hash.find(agent.hash) != std::string::npos) {
                // Bin exists and matches hash. Check if executable.
                // We'll just try running version check immediately.
                need_deploy = false;
            }

            // D. Deploy (if needed)
            if (need_deploy) {
                if (config_.show_logo) {
                    std::cout << "\r\n[" << handlers::Theme::NOTICE << "-" << handlers::Theme::RESET 
                              << "] Attempting to inject remote agent (" << target_path << ")..." << std::flush;
                }

                // Encode
                std::string b64 = base64_encode(agent.data, agent.size);
                std::string temp_b64 = target_path + ".b64";

                // Transfer
                execute_remote_command("rm -f " + temp_b64, 2000); 
                
                // Prevent history pollution & echo & prompts
                execute_remote_command("set +o history", 1000); 
                execute_remote_command("stty -echo", 2000);
                // Disable PS2 prompt (continuation prompt) to prevent '> > >' spam
                execute_remote_command("export PS2=''", 1000);

                // Add leading space to 'cat' for history safety (ignorespace)
                std::string start_heredoc = " cat > " + temp_b64 + " << 'DAIS_EOF'\n";
                write(pty_.get_master_fd(), start_heredoc.c_str(), start_heredoc.size());
                
                // BACKGROUND DRAINER
                // Start a thread to drain the PTY output (echoes, PS2 prompts) while we write.
                // If we don't drain, the PTY buffer can fill up, causing 'write' to block 
                // or the remote shell to block on output, leading to severe slowdowns.
                std::atomic<bool> draining{true};
                std::thread drainer([&]() {
                    char buf[4096];
                    while (draining) {
                        // Non-blocking read? No, we can't easily set non-blocking on the same FD 
                        // without affecting the main thread if not careful. 
                        // Use select/poll with timeout to avoid blocking forever.
                        fd_set set;
                        FD_ZERO(&set);
                        FD_SET(pty_.get_master_fd(), &set);
                        struct timeval timeout = {0, 10000}; // 10ms
                        if (select(pty_.get_master_fd() + 1, &set, nullptr, nullptr, &timeout) > 0) {
                            read(pty_.get_master_fd(), buf, sizeof(buf));
                        } else {
                            // Check quit condition even if no data
                            std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        }
                    }
                });

                // CHUNKED TRANSMISSION WITH LINE WRAPPING (76 chars)
                size_t sent = 0;
                size_t line_len = 0;
                constexpr size_t MAX_LINE = 76;
                // Write larger chunks to kernel (4KB) but ensure we insert newlines
                // We construct a local buffer to minimize write() syscalls
                std::string write_buffer; 
                write_buffer.reserve(4096 + 128); 

                while (sent < b64.size()) {
                    char c = b64[sent++];
                    write_buffer += c;
                    line_len++;

                    if (line_len >= MAX_LINE) {
                        write_buffer += "\n"; // Explicit newline for shell
                        line_len = 0;
                    }
                    
                    // Flush buffer when full or done
                    if (write_buffer.size() >= 4096 || sent == b64.size()) {
                        write(pty_.get_master_fd(), write_buffer.c_str(), write_buffer.size());
                        write_buffer.clear();
                        // Minimal sleep to yield to shell/drainer, avoiding CPU hogging
                        // but substantially faster than per-line sleep.
                        std::this_thread::sleep_for(std::chrono::microseconds(100)); 
                    }
                }
                
                if (line_len > 0) write(pty_.get_master_fd(), "\n", 1); 

                // Use explicit CRLF for EOF
                std::string end_heredoc = "\r\nDAIS_EOF\r\n";
                write(pty_.get_master_fd(), end_heredoc.c_str(), end_heredoc.size());
                
                // Allow drainer to finish clearing up any trailing echoes
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                draining = false;
                if (drainer.joinable()) drainer.join();

                execute_remote_command("stty echo", 2000);
                execute_remote_command("set -o history", 1000); // Restore history

                std::string deploy_cmd = 
                    " base64 -d " + temp_b64 + " > " + target_path + " && "
                    "chmod +x " + target_path + " && "
                    "rm " + temp_b64 + " && "
                    "echo DAIS_DEPLOY_OK";

                std::string result = execute_remote_command(deploy_cmd, 10000);
                if (result.find("DAIS_DEPLOY_OK") == std::string::npos) {
                    if (config_.show_logo) {
                        std::cout << " [FAILED]\r\n    Error output: " << result << "\r\n";
                    }
                    continue; // Deployment failed (maybe disk full?), try next path
                }
            }

            // E. Final Verification (Execution & NOEXEC Check)
            // This runs the agent. If it fails (126 Permission Denied), we know we hit noexec.
            std::string ver_cmd = target_path + " --version";
            std::string ver = execute_remote_command(ver_cmd, 1000);
            
            if (ver.find("DAIS_AGENT") != std::string::npos) {
                // SUCCESS!
                remote_agent_deployed_ = true;
                remote_bin_path_ = target_path;
                
                if (config_.show_logo) {
                    std::cout << "\r\n[" << handlers::Theme::SUCCESS << "-" << handlers::Theme::RESET 
                              << "] Agent active at " << target_path << "\r\n" << std::flush;
                }
                return; // Done
            }
            
            // F. Cleanup on failure (best effort)
            // If we deployed but couldn't run, delete it so we don't leave trash in noexec mount
            if (need_deploy) {
                execute_remote_command("rm " + target_path, 1000);
            }
        }

        // 4. Fallback Failure
        // 4. Fallback Failure
        agent_deployment_failed_ = true; // Mark as failed to prevent retry spam
        if (config_.show_logo) {
            std::cout << "\r\n" << handlers::Theme::STRUCTURE << "[" << handlers::Theme::WARNING << "-" << handlers::Theme::STRUCTURE << "]" << handlers::Theme::RESET 
                      << " Agent deployment failed (No writable/executable path found). Falling back to Python.\r\n";
        }
    }
}
