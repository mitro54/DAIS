/**
 * @file base64.hpp
 * @brief Simple Base64 encoding utility.
 */

#pragma once
#include <string>
#include <vector>

namespace dais::core {

    /**
     * @brief Encodes binary data into a Base64 string.
     * Used for transferring binary agents and scripts to remote hosts via PTY.
     */
    inline std::string base64_encode(const unsigned char* data, size_t len) {
        static const char* p = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(4 * ((len + 2) / 3));
        
        for (size_t i = 0; i < len; i += 3) {
            unsigned int v = data[i] << 16;
            if (i + 1 < len) v |= data[i + 1] << 8;
            if (i + 2 < len) v |= data[i + 2];

            out += p[(v >> 18) & 0x3F];
            out += p[(v >> 12) & 0x3F];
            out += (i + 1 < len) ? p[(v >> 6) & 0x3F] : '=';
            out += (i + 2 < len) ? p[v & 0x3F] : '=';
        }
        return out;
    }

}
