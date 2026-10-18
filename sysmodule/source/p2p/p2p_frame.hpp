/**
 * @file p2p_frame.hpp
 * @brief Wire-frame limits shared by P2pProxyServer and P2pProxyClient
 *
 * Header-only and free of stratosphere so host unit tests can include it.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#pragma once

#include "../protocol/types.hpp"
#include "../protocol/ryu_protocol.hpp"
#include <cstddef>
#include <cstring>

namespace ams::mitm::p2p {

/**
 * @brief Largest P2P frame (LdnHeader + payload) we encode or buffer.
 *
 * The biggest real frame is ProxyData: 12 B LdnHeader + 20 B ProxyDataHeader
 * + one game datagram, and the BSD MITM caps datagrams at
 * PROXY_SOCKET_MAX_PAYLOAD (2000 B), so 2032 B. 2 KB is also the master
 * link's send buffer (network/tcp_client.hpp), so relay and P2P carry the
 * same maximum.
 */
constexpr size_t P2P_MAX_FRAME_SIZE = 2048;

/// Largest ProxyData payload that fits in one P2P frame (2016 B).
constexpr size_t P2P_MAX_PROXY_PAYLOAD = P2P_MAX_FRAME_SIZE
    - sizeof(ryu_ldn::protocol::LdnHeader)
    - sizeof(ryu_ldn::protocol::ProxyDataHeader);

enum class FrameStatus {
    Ok,       ///< All complete frames handled; any tail is a partial frame
    Invalid,  ///< Bad magic/version, or data_size < 0 or > MAX_PACKET_SIZE: disconnect
    Oversized,///< FrameAssembler only: a valid frame too big to buffer is being dropped
};

/**
 * @brief Walk the complete frames in data[0, size).
 *
 * Every header is validated (magic, version, 0 <= data_size <=
 * MAX_PACKET_SIZE) before its length is used, and a frame is dispatched
 * only once all of its bytes are present. A zero-length frame advances by
 * the 12-byte header, so the walk always terminates.
 *
 * @param[out] consumed Bytes of complete frames walked (frames already
 *             handed to @p on_frame, including the one that stopped the walk)
 * @param on_frame bool(const LdnHeader&, const uint8_t* payload, size_t len);
 *        return false to stop (for example after the handler disconnected).
 */
template <typename OnFrame>
inline FrameStatus ForEachFrame(const uint8_t* data, size_t size, size_t& consumed,
                                OnFrame&& on_frame) {
    using namespace ryu_ldn::protocol;
    consumed = 0;
    while (consumed < size) {
        size_t frame_size = 0;
        switch (check_complete_packet(data + consumed, size - consumed, frame_size)) {
            case DecodeResult::Success:
                break;
            case DecodeResult::BufferTooSmall:
            case DecodeResult::IncompletePacket:
                return FrameStatus::Ok;
            default:
                return FrameStatus::Invalid;
        }
        LdnHeader header;
        std::memcpy(&header, data + consumed, sizeof(header));
        const uint8_t* payload = data + consumed + sizeof(LdnHeader);
        consumed += frame_size;
        if (!on_frame(header, payload, frame_size - sizeof(LdnHeader))) {
            break;
        }
    }
    return FrameStatus::Ok;
}

/**
 * @brief Reassembles P2P frames from a TCP byte stream.
 *
 * recv() straight into WritePtr()/Writable(), then Commit() the byte count.
 * Complete frames are handed to the callback in order; a partial frame is
 * kept (moved to the front of the buffer) until the rest arrives. Writable()
 * is never 0 between calls.
 *
 * A frame with a valid header that is larger than Capacity (legal up to
 * MAX_PACKET_SIZE, but more than any game sends) is discarded byte by byte
 * as it arrives, so it cannot wedge the stream; Commit() reports Oversized
 * when that starts.
 */
template <size_t Capacity>
class FrameAssembler {
    static_assert(Capacity > sizeof(ryu_ldn::protocol::LdnHeader), "Capacity too small");

public:
    uint8_t* WritePtr() { return m_buf + m_len; }
    size_t Writable() const { return Capacity - m_len; }
    size_t Buffered() const { return m_len; }
    void Reset() { m_len = 0; m_skip = 0; }

    /**
     * @brief Account for @p n bytes written at WritePtr() and dispatch frames.
     * @param on_frame Same contract as ForEachFrame.
     * @return Invalid: the stream is corrupt, disconnect (buffer is reset).
     */
    template <typename OnFrame>
    FrameStatus Commit(size_t n, OnFrame&& on_frame) {
        using namespace ryu_ldn::protocol;

        m_len += (n < Writable()) ? n : Writable();

        if (m_skip > 0) {
            const size_t drop = (m_skip < m_len) ? m_skip : m_len;
            Consume(drop);
            m_skip -= drop;
            if (m_skip > 0) {
                return FrameStatus::Ok;
            }
        }

        size_t consumed = 0;
        if (ForEachFrame(m_buf, m_len, consumed, on_frame) == FrameStatus::Invalid) {
            Reset();
            return FrameStatus::Invalid;
        }
        Consume(consumed);

        // What is left is a partial frame whose header (if complete) is
        // valid. If the whole frame can never fit, start discarding it.
        size_t frame_size = 0;
        if (check_complete_packet(m_buf, m_len, frame_size) == DecodeResult::IncompletePacket &&
            frame_size > Capacity) {
            m_skip = frame_size - m_len;
            m_len = 0;
            return FrameStatus::Oversized;
        }
        return FrameStatus::Ok;
    }

private:
    void Consume(size_t n) {
        std::memmove(m_buf, m_buf + n, m_len - n);
        m_len -= n;
    }

    alignas(8) uint8_t m_buf[Capacity];
    size_t m_len = 0;
    size_t m_skip = 0;  ///< Bytes of an oversized frame still to discard
};

} // namespace ams::mitm::p2p
