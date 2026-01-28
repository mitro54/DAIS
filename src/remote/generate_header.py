"""
Script to generate C++ headers from binary files.
Used to embed the remote agent binaries directly into the DAIS engine execution.
"""
import sys
import os

def file_to_hex(path, var_name):
    """
    Reads a binary file and converts it into a C++ byte array definition.
    
    Args:
        path (str): Path to the binary file.
        var_name (str): Name of the C++ variable to generate.
        
    Returns:
        str: A string containing the C++ code for the byte array and its size.
    """
    if not os.path.exists(path):
        print(f"Warning: {path} not found. Using empty placeholder.")
        return f"    inline const unsigned char {var_name}[] = {{ 0x00 }};\n    inline const size_t SIZE_{var_name.replace('AGENT_', '')} = 0;"
    
    with open(path, 'rb') as f:
        data = f.read()
    
    hex_str = ", ".join(f"0x{b:02x}" for b in data)
    return f"    inline const unsigned char {var_name}[] = {{ {hex_str} }};\n    inline const size_t SIZE_{var_name.replace('AGENT_', '')} = {len(data)};"

def generate_header(output_path, binary_dir):
    header = """#pragma once

#include <vector>
#include <string>
#include <map>

namespace dais::core::agents {

    // Helper struct for agent binaries
    struct AgentBinary {
        const unsigned char* data;
        size_t size;
        std::string arch;
    };

"""
    # Define mappings (Binary Name -> C++ Var Name)
    binaries = [
        ("agent_x86_64", "AGENT_LINUX_AMD64"),
        ("agent_aarch64", "AGENT_LINUX_ARM64"),
        ("agent_armv7", "AGENT_LINUX_ARMV7")
    ]

    for filename, varname in binaries:
        full_path = os.path.join(binary_dir, filename)
        header += file_to_hex(full_path, varname) + "\n\n"

    header += """    // Helper to get agent by architecture
    inline AgentBinary get_agent_for_arch(const std::string& arch) {
        if (arch == "x86_64") return {AGENT_LINUX_AMD64, SIZE_LINUX_AMD64, "x86_64"};
        if (arch == "aarch64") return {AGENT_LINUX_ARM64, SIZE_LINUX_ARM64, "aarch64"};
        if (arch == "armv7l") return {AGENT_LINUX_ARMV7, SIZE_LINUX_ARMV7, "armv7l"};
        return {nullptr, 0, ""};
    }
}
"""
    with open(output_path, 'w') as f:
        f.write(header)
    print(f"Generated {output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 generate_header.py <binary_dir> <output_header>")
        sys.exit(1)
    
    generate_header(sys.argv[2], sys.argv[1])
