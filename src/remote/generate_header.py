"""
Script to generate C++ headers from binary files.
Used to embed the remote agent binaries directly into the DAIS engine execution.

This script reads binary files from a specified directory, computes their SHA256 hashes,
and generates a C++ header file containing the data as byte arrays. It ensures that
the DAIS engine has compile-time access to the correct agent binaries for remote deployment.
It uses streaming I/O to maintain constant memory usage regardless of binary size.

Usage:
    python3 generate_header.py <binary_dir> <output_header> [--permissive]
"""

import sys
import os
import hashlib
import argparse
from typing import List, Tuple, TextIO

# Constants for binary names and their corresponding C++ variable names
BINARIES: List[Tuple[str, str]] = [
    ("agent_x86_64", "AGENT_LINUX_AMD64"),
    ("agent_aarch64", "AGENT_LINUX_ARM64"),
    ("agent_armv7", "AGENT_LINUX_ARMV7")
]

def write_binary_to_header(f_out: TextIO, path: str, var_name: str, permissive: bool = False) -> None:
    """
    Reads a binary file in chunks and streams C++ code + hash to the output file.
    
    Args:
        f_out (TextIO): Open file handle to write the C++ code to.
        path (str): Path to the binary file.
        var_name (str): Name of the C++ variable to generate.
        permissive (bool): If True, missing files generate empty placeholders.
        
    Raises:
        FileNotFoundError: If the file does not exist and permissive is False.
        IOError: If reading the file fails.
    """
    if not os.path.exists(path):
        if permissive:
            print(f"Warning: {path} not found. Using empty placeholder.")
            f_out.write(f"    // Placeholder for missing binary: {os.path.basename(path)}\n")
            f_out.write(f"    inline const unsigned char {var_name}[] = {{ 0x00 }};\n")
            f_out.write(f"    inline const size_t SIZE_{var_name.replace('AGENT_', '')} = 0;\n")
            f_out.write(f"    inline const std::string HASH_{var_name.replace('AGENT_', '')} = \"\";\n")
            return
        else:
            raise FileNotFoundError(f"Critical Error: Agent binary not found at {path}. Build aborted.")

    f_out.write(f"    /** @brief Embedded binary data for {var_name} */\n")
    f_out.write(f"    inline const unsigned char {var_name}[] = {{ ")
    
    sha256 = hashlib.sha256()
    total_size = 0
    
    try:
        with open(path, 'rb') as f_in:
            while True:
                chunk = f_in.read(65536) # Read in 64KB chunks
                if not chunk:
                    break
                
                sha256.update(chunk)
                total_size += len(chunk)
                
                # Convert chunk to hex output
                # We append a trailing comma to every chunk. 
                # C++11 allows trailing commas in initializer lists (e.g., { 0x01, 0x02, }).
                # This avoids complex logic or race conditions checking file size.
                hex_chunk = ", ".join(f"0x{b:02x}" for b in chunk)
                f_out.write(hex_chunk)
                f_out.write(", ")
                
    except IOError as e:
        raise IOError(f"Failed to read file {path}: {e}")

    # Handle empty files: C++ arrays cannot be empty 'elem[] = {}'.
    # We must provide at least one byte even if size is 0, or just use 0x00.
    if total_size == 0:
        f_out.write("0x00")
    
    f_out.write(" };\n")
    f_out.write(f"    /** @brief Size of {var_name} in bytes */\n")
    f_out.write(f"    inline const size_t SIZE_{var_name.replace('AGENT_', '')} = {total_size};\n")
    f_out.write(f"    /** @brief SHA256 hash of {var_name} */\n")
    f_out.write(f"    inline const std::string HASH_{var_name.replace('AGENT_', '')} = \"{sha256.hexdigest()}\";\n")


def generate_header(binary_dir: str, output_path: str, permissive: bool = False) -> None:
    """
    Generates the C++ header file containing embedded binaries using streaming.

    Args:
        binary_dir (str): Directory containing the binary files.
        output_path (str): Path where the generated header should be written.
        permissive (bool): If True, allows missing binaries.
    """
    # Safety: Ensure output directory exists to avoid FileNotFoundError
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    try:
        # Atomic Write Strategy:
        # 1. Write to a temporary file in the same directory (to ensure atomic rename works across filesystems).
        # 2. Flush and fsync to guarantee data is on disk.
        # 3. Rename temp file to output_path.
        
        temp_output_path = output_path + ".tmp"
        
        try:
            # Use UTF-8 explicitly for reproducible builds across platforms
            with open(temp_output_path, 'w', encoding='utf-8') as f:
                f.write("#pragma once\n\n")
                f.write("#include <vector>\n")
                f.write("#include <string>\n")
                f.write("#include <map>\n\n")
                f.write("/**\n")
                f.write(" * @namespace dais::core::agents\n")
                f.write(" * @brief Contains embedded agent binaries for remote deployment.\n")
                f.write(" */\n")
                f.write("namespace dais::core::agents {\n\n")
                f.write("    /**\n")
                f.write("     * @struct AgentBinary\n")
                f.write("     * @brief Represents a compiled agent binary for a specific architecture.\n")
                f.write("     */\n")
                f.write("    struct AgentBinary {\n")
                f.write("        const unsigned char* data; ///< Pointer to raw binary data\n")
                f.write("        size_t size;               ///< Size of the binary in bytes\n")
                f.write("        std::string arch;          ///< Architecture string (e.g., \"x86_64\")\n")
                f.write("        std::string hash;          ///< SHA256 integrity hash\n")
                f.write("    };\n\n")

                print(f"Scanning directory: {binary_dir}")
                
                for filename, varname in BINARIES:
                    full_path = os.path.join(binary_dir, filename)
                    try:
                        write_binary_to_header(f, full_path, varname, permissive)
                        f.write("\n")
                    except Exception as e:
                        # Cleanup temp file on failure
                        # f is closed by context manager
                        if os.path.exists(temp_output_path):
                            os.remove(temp_output_path)
                        print(str(e), file=sys.stderr)
                        sys.exit(1)

                f.write("    /**\n")
                f.write("     * @brief Retrieves the correct agent binary for a given architecture.\n")
                f.write("     * @param arch The target architecture (e.g., \"x86_64\", \"aarch64\").\n")
                f.write("     * @return AgentBinary struct containing the data and metadata. Returns empty struct if not found.\n")
                f.write("     */\n")
                f.write("    inline AgentBinary get_agent_for_arch(const std::string& arch) {\n")
                f.write("        if (arch == \"x86_64\") return {AGENT_LINUX_AMD64, SIZE_LINUX_AMD64, \"x86_64\", HASH_LINUX_AMD64};\n")
                f.write("        if (arch == \"aarch64\") return {AGENT_LINUX_ARM64, SIZE_LINUX_ARM64, \"aarch64\", HASH_LINUX_ARM64};\n")
                f.write("        if (arch == \"armv7l\") return {AGENT_LINUX_ARMV7, SIZE_LINUX_ARMV7, \"armv7l\", HASH_LINUX_ARMV7};\n")
                f.write("        return {nullptr, 0, \"\", \"\"};\n")
                f.write("    }\n")
                f.write("}\n")
                
                f.flush()
                os.fsync(f.fileno())

            # Atomic rename
            os.replace(temp_output_path, output_path)
            print(f"Successfully generated: {output_path}")

        except IOError as e:
            if os.path.exists(temp_output_path):
                 try: os.remove(temp_output_path)
                 except: pass
            print(f"Error writing to {output_path}: {e}", file=sys.stderr)
            sys.exit(1)
            
    except IOError as e:
        # Fallback error handler for the outer block if needed.

        
        if os.path.exists(temp_output_path):
             try: os.remove(temp_output_path)
             except: pass
        print(f"Error writing to {output_path}: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Generate C++ header from agent binaries.")
    parser.add_argument("binary_dir", help="Directory containing the compiled agent binaries")
    parser.add_argument("output_header", help="Path to the output C++ header file")
    parser.add_argument("--permissive", action="store_true", help="Do not fail if binaries are missing (generates placeholders)")
    
    args = parser.parse_args()
    
    generate_header(args.binary_dir, args.output_header, args.permissive)

if __name__ == "__main__":
    main()
