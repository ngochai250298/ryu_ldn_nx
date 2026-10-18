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

} // namespace ams::mitm::p2p
