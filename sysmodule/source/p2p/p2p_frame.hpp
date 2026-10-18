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
#include <cstddef>

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

} // namespace ams::mitm::p2p
