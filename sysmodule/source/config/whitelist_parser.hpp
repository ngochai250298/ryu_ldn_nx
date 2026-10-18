/**
 * @file whitelist_parser.hpp
 * @brief Pure line scanner for gamelist.txt (no fs, host-testable)
 *
 * Feed it the file in chunks; it calls emit(id) once per valid line.
 * Skips a leading UTF-8 BOM and leading whitespace, accepts LF, CR and CRLF,
 * with or without a "0x" prefix. Used twice by the loader: once to count
 * entries (exact allocation), once to store them.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace ryu_ldn::config {

/// Parse "0x0100152000022000" (prefix optional) up to the first non-hex char.
inline uint64_t ParseHexId(const char* str, size_t len) {
    if (!str || len == 0) return 0;
    size_t i = 0;
    if (len >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) i = 2;

    uint64_t result = 0;
    while (i < len) {
        char c = str[i++];
        uint64_t digit;
        if (c >= '0' && c <= '9')      digit = static_cast<uint64_t>(c - '0');
        else if (c >= 'a' && c <= 'f') digit = static_cast<uint64_t>(10 + (c - 'a'));
        else if (c >= 'A' && c <= 'F') digit = static_cast<uint64_t>(10 + (c - 'A'));
        else break;
        result = (result << 4) | digit;
    }
    return result;
}

class WhitelistScanner {
public:
    template <typename Emit>
    void Feed(const char* data, size_t size, Emit&& emit) {
        for (size_t i = 0; i < size; i++) {
            char c = data[i];
            if (m_pos < 3) {  // UTF-8 BOM EF BB BF
                static constexpr unsigned char BOM[3] = {0xEF, 0xBB, 0xBF};
                if (static_cast<unsigned char>(c) == BOM[m_pos]) { m_pos++; continue; }
                m_pos = 3;  // not a BOM, treat as content
            }
            if (c == '\n' || c == '\r') {
                EndLine(emit);
            } else if (m_len == 0 && (c == ' ' || c == '\t')) {
                // leading whitespace
            } else if (m_len < sizeof(m_line)) {
                m_line[m_len++] = c;
            }
        }
    }

    /// Call after the last chunk (file without trailing newline).
    template <typename Emit>
    void Finish(Emit&& emit) { EndLine(emit); }

private:
    template <typename Emit>
    void EndLine(Emit& emit) {
        if (m_len > 0) {
            uint64_t id = ParseHexId(m_line, m_len);
            if (id != 0) emit(id);
            m_len = 0;
        }
    }

    char m_line[24];
    size_t m_len = 0;
    size_t m_pos = 0;
};

}  // namespace ryu_ldn::config
