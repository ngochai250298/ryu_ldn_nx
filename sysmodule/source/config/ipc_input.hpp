/**
 * @file ipc_input.hpp
 * @brief Bounded, validated copy of fixed-size IPC strings (host-testable)
 *
 * IPC strings arrive in fixed char arrays that a client may leave without a
 * NUL. They end up in config.ini, so a newline or control character would let
 * a client inject extra keys into the file.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#pragma once

#include <cstddef>

namespace ryu_ldn::config {

/**
 * @brief Copy a NUL-terminated string out of a src_size-byte IPC array
 *
 * Never reads past src_size. Returns false (dest untouched) if the array has
 * no NUL, the string does not fit in dest_cap-1 chars, or it contains a
 * control character (< 0x20 or 0x7F), which covers CR/LF.
 */
inline bool copy_ipc_string(char* dest, size_t dest_cap, const char* src, size_t src_size) {
    size_t len = 0;
    while (len < src_size && src[len] != '\0') {
        unsigned char c = static_cast<unsigned char>(src[len]);
        if (c < 0x20 || c == 0x7F) return false;
        len++;
    }
    if (len == src_size || len >= dest_cap) return false;
    for (size_t i = 0; i < len; i++) dest[i] = src[i];
    dest[len] = '\0';
    return true;
}

}  // namespace ryu_ldn::config
