/**
 * @file packet_ring.hpp
 * @brief Fixed-size FIFO of variable-length datagrams
 *
 * Datagrams are stored back to back as [Header][u16 length][payload] in one
 * byte buffer that wraps around, so a 100-byte keepalive costs ~120 bytes
 * instead of a whole MTU-sized slot. When a new datagram doesn't fit, the
 * oldest ones are dropped (UDP behaviour). No allocation after construction.
 *
 * Not thread-safe; the owner holds its own lock.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <algorithm>

namespace ams::mitm::bsd {

template<typename Header, size_t Capacity>
class PacketRing {
public:
    /// Bytes one datagram of len payload bytes takes in the ring.
    static constexpr size_t RecordSize(size_t len) { return sizeof(Header) + sizeof(uint16_t) + len; }

    /**
     * @brief Append a datagram, dropping the oldest ones to make room
     * @return false (and nothing stored) if it could never fit
     */
    bool Push(const Header& header, const void* data, size_t len) {
        const size_t need = RecordSize(len);
        if (need > Capacity || len > UINT16_MAX) {
            return false;
        }
        while (Capacity - m_used < need) {
            Pop();
        }
        const uint16_t len16 = static_cast<uint16_t>(len);
        const size_t tail = (m_head + m_used) % Capacity;
        Copy(tail, &header, sizeof(header));
        Copy((tail + sizeof(header)) % Capacity, &len16, sizeof(len16));
        if (len > 0) {
            Copy((tail + sizeof(header) + sizeof(len16)) % Capacity, data, len);
        }
        m_used += need;
        m_payload_bytes += len;
        m_count++;
        return true;
    }

    /**
     * @brief Copy out the oldest datagram without removing it
     * @param out_header Receives the header (may be nullptr)
     * @param out Receives up to out_size payload bytes
     * @return The datagram's full payload length; 0 if empty
     */
    size_t Front(Header* out_header, void* out, size_t out_size) const {
        if (m_count == 0) {
            return 0;
        }
        Header header;
        uint16_t len;
        Read(m_head, &header, sizeof(header));
        Read((m_head + sizeof(header)) % Capacity, &len, sizeof(len));
        if (out_header != nullptr) {
            *out_header = header;
        }
        const size_t n = std::min(out_size, static_cast<size_t>(len));
        if (n > 0) {
            Read((m_head + sizeof(header) + sizeof(len)) % Capacity, out, n);
        }
        return len;
    }

    /// Remove the oldest datagram.
    void Pop() {
        if (m_count == 0) {
            return;
        }
        uint16_t len;
        Read((m_head + sizeof(Header)) % Capacity, &len, sizeof(len));
        const size_t size = RecordSize(len);
        m_head = (m_head + size) % Capacity;
        m_used -= size;
        m_payload_bytes -= len;
        m_count--;
    }

    void Clear() {
        m_head = 0;
        m_used = 0;
        m_payload_bytes = 0;
        m_count = 0;
    }

    bool Empty() const { return m_count == 0; }
    size_t Count() const { return m_count; }
    size_t PayloadBytes() const { return m_payload_bytes; }

private:
    void Copy(size_t pos, const void* src, size_t n) {
        const size_t first = std::min(n, Capacity - pos);
        std::memcpy(m_buffer + pos, src, first);
        std::memcpy(m_buffer, static_cast<const uint8_t*>(src) + first, n - first);
    }

    void Read(size_t pos, void* dst, size_t n) const {
        const size_t first = std::min(n, Capacity - pos);
        std::memcpy(dst, m_buffer + pos, first);
        std::memcpy(static_cast<uint8_t*>(dst) + first, m_buffer, n - first);
    }

    uint8_t m_buffer[Capacity];
    size_t m_head = 0;           ///< Offset of the oldest record
    size_t m_used = 0;           ///< Bytes in use
    size_t m_payload_bytes = 0;  ///< Sum of payload lengths (FIONREAD)
    size_t m_count = 0;          ///< Records stored
};

} // namespace ams::mitm::bsd
