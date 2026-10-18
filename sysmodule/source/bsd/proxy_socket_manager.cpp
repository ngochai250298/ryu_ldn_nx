/**
 * @file proxy_socket_manager.cpp
 * @brief Implementation of the Proxy Socket Manager
 *
 * This file implements the central registry for proxy sockets.
 * See proxy_socket_manager.hpp for design documentation.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include "proxy_socket_manager.hpp"
#include "../debug/log.hpp"

namespace ams::mitm::bsd {

// =============================================================================
// Singleton
// =============================================================================

ProxySocketManager& ProxySocketManager::GetInstance() {
    static ProxySocketManager instance;
    return instance;
}

// =============================================================================
// Socket Management
// =============================================================================

std::shared_ptr<ProxySocket> ProxySocketManager::CreateProxySocket(u64 key, ryu_ldn::bsd::SocketType type,
                                                                    ryu_ldn::bsd::ProtocolType protocol) {
    std::scoped_lock lock(m_mutex);

    // Already exists - return existing
    auto it = m_sockets.find(key);
    if (it != m_sockets.end()) {
        return it->second;
    }

    // Check limit
    if (m_sockets.size() >= MAX_PROXY_SOCKETS) {
        return nullptr;
    }

    // nothrow: a failed allocation becomes ENOMEM for the game, not a
    // constructor running at address 0.
    ProxySocket* raw = new (std::nothrow) ProxySocket(type, protocol);
    if (raw == nullptr) {
        LOG_WARN("ProxySocketManager: out of memory creating proxy for key=0x%lx", static_cast<unsigned long>(key));
        return nullptr;
    }
    std::shared_ptr<ProxySocket> socket(raw);
    m_sockets[key] = socket;
    return socket;
}

std::shared_ptr<ProxySocket> ProxySocketManager::GetProxySocket(u64 key) {
    std::scoped_lock lock(m_mutex);

    auto it = m_sockets.find(key);
    if (it != m_sockets.end()) {
        return it->second;
    }

    return nullptr;
}

bool ProxySocketManager::IsProxySocket(u64 key) const {
    std::scoped_lock lock(m_mutex);
    return m_sockets.find(key) != m_sockets.end();
}

// Sockets are taken out of the registry under m_mutex and closed after it is
// released: Close() wakes waiters and, for TCP, calls SendProxyDisconnect,
// which takes m_mutex itself. Handlers still holding a reference keep the
// object alive and see it Closed.

bool ProxySocketManager::CloseProxySocket(u64 key) {
    std::shared_ptr<ProxySocket> socket;
    {
        std::scoped_lock lock(m_mutex);

        auto it = m_sockets.find(key);
        if (it == m_sockets.end()) {
            return false;
        }
        socket = std::move(it->second);
        m_sockets.erase(it);

        if (socket != nullptr && socket->GetLocalAddr().GetPort() != 0) {
            m_port_pool.ReleasePort(socket->GetLocalAddr().GetPort(), socket->GetProtocol());
        }
    }

    if (socket != nullptr) {
        socket->Close();
    }
    return true;
}

void ProxySocketManager::CloseAllProxySockets() {
    decltype(m_sockets) closing;
    {
        std::scoped_lock lock(m_mutex);
        closing.swap(m_sockets);
        m_port_pool.ReleaseAll();
    }

    for (auto& [fd, socket] : closing) {
        if (socket != nullptr) {
            socket->Close();
        }
    }
}

void ProxySocketManager::Reset() {
    // Close first, while the disconnect callback is still set.
    CloseAllProxySockets();

    std::scoped_lock lock(m_mutex);

    // Clear pending packets ring (no dealloc — just reset indices)
    m_pending.Clear();

    // Reset local IP
    m_local_ip = 0;

    // Clear callbacks
    m_send_callback = nullptr;
    m_proxy_connect_callback = nullptr;
    m_proxy_connect_reply_callback = nullptr;
    m_proxy_disconnect_callback = nullptr;
}

// =============================================================================
// Port Management
// =============================================================================

uint16_t ProxySocketManager::AllocatePort(ryu_ldn::bsd::ProtocolType protocol) {
    return m_port_pool.AllocatePort(protocol);
}

bool ProxySocketManager::ReservePort(uint16_t port, ryu_ldn::bsd::ProtocolType protocol) {
    return m_port_pool.AllocateSpecificPort(port, protocol);
}

void ProxySocketManager::ReleasePort(uint16_t port, ryu_ldn::bsd::ProtocolType protocol) {
    m_port_pool.ReleasePort(port, protocol);
}

// =============================================================================
// Outgoing Data
// =============================================================================

void ProxySocketManager::SetSendCallback(SendProxyDataCallback callback) {
    std::scoped_lock lock(m_mutex);
    m_send_callback = callback;
}

bool ProxySocketManager::SendProxyData(uint32_t source_ip, uint16_t source_port,
                                        uint32_t dest_ip, uint16_t dest_port,
                                        ryu_ldn::bsd::ProtocolType protocol,
                                        const void* data, size_t data_len) {
    SendProxyDataCallback callback;
    {
        std::scoped_lock lock(m_mutex);
        callback = m_send_callback;
    }

    if (callback == nullptr) {
        LOG_WARN("ProxySocketManager::SendProxyData: m_send_callback=nullptr (src=0x%08X:%u dst=0x%08X:%u)",
                 source_ip, source_port, dest_ip, dest_port);
        return false;
    }

    bool ok = callback(source_ip, source_port, dest_ip, dest_port, protocol, data, data_len);
    if (!ok) {
        LOG_WARN("ProxySocketManager::SendProxyData: callback returned false (src=0x%08X:%u dst=0x%08X:%u len=%zu)",
                 source_ip, source_port, dest_ip, dest_port, data_len);
    }
    return ok;
}

void ProxySocketManager::SetProxyConnectCallback(SendProxyConnectCallback callback) {
    std::scoped_lock lock(m_mutex);
    m_proxy_connect_callback = callback;
}

bool ProxySocketManager::SendProxyConnect(uint32_t source_ip, uint16_t source_port,
                                           uint32_t dest_ip, uint16_t dest_port,
                                           ryu_ldn::bsd::ProtocolType protocol) {
    SendProxyConnectCallback callback;
    {
        std::scoped_lock lock(m_mutex);
        callback = m_proxy_connect_callback;
    }

    if (callback == nullptr) {
        return false;
    }

    return callback(source_ip, source_port, dest_ip, dest_port, protocol);
}

void ProxySocketManager::SetProxyConnectReplyCallback(SendProxyConnectReplyCallback callback) {
    std::scoped_lock lock(m_mutex);
    m_proxy_connect_reply_callback = callback;
}

bool ProxySocketManager::SendProxyConnectReply(uint32_t source_ip, uint16_t source_port,
                                                uint32_t dest_ip, uint16_t dest_port,
                                                ryu_ldn::bsd::ProtocolType protocol) {
    SendProxyConnectReplyCallback callback;
    {
        std::scoped_lock lock(m_mutex);
        callback = m_proxy_connect_reply_callback;
    }

    if (callback == nullptr) {
        return false;
    }

    return callback(source_ip, source_port, dest_ip, dest_port, protocol);
}

void ProxySocketManager::SetProxyDisconnectCallback(SendProxyDisconnectCallback callback) {
    std::scoped_lock lock(m_mutex);
    m_proxy_disconnect_callback = callback;
}

bool ProxySocketManager::SendProxyDisconnect(uint32_t source_ip, uint16_t source_port,
                                              uint32_t dest_ip, uint16_t dest_port,
                                              ryu_ldn::bsd::ProtocolType protocol) {
    SendProxyDisconnectCallback callback;
    {
        std::scoped_lock lock(m_mutex);
        callback = m_proxy_disconnect_callback;
    }

    if (callback == nullptr) {
        return false;
    }

    return callback(source_ip, source_port, dest_ip, dest_port, protocol);
}

bool ProxySocketManager::RouteConnectResponse(const ryu_ldn::protocol::ProxyConnectResponse& response) {
    std::scoped_lock lock(m_mutex);

    // Find socket in Connecting state that matches the destination
    uint32_t dest_ip = response.info.source_ipv4;  // Response comes back to our source
    uint16_t dest_port = response.info.source_port;

    for (auto& [fd, socket] : m_sockets) {
        if (socket == nullptr) {
            continue;
        }

        // Check if socket is connecting
        if (socket->GetState() != ProxySocketState::Connecting) {
            continue;
        }

        // Check local address matches
        const auto& local_addr = socket->GetLocalAddr();
        if (local_addr.GetAddr() != dest_ip || local_addr.GetPort() != dest_port) {
            continue;
        }

        // Found matching socket - deliver response
        socket->HandleConnectResponse(response);
        return true;
    }

    return false;
}

bool ProxySocketManager::RouteConnectRequest(const ryu_ldn::protocol::ProxyConnectRequest& request) {
    // Find listening socket that matches the destination
    uint32_t dest_ip = request.info.dest_ipv4;
    uint16_t dest_port = request.info.dest_port;

    std::shared_ptr<ProxySocket> listener;
    {
        std::scoped_lock lock(m_mutex);

        for (auto& [fd, socket] : m_sockets) {
            if (socket == nullptr ||
                socket->GetState() != ProxySocketState::Listening ||
                socket->GetProtocol() != ryu_ldn::bsd::ProtocolType::Tcp) {
                continue;
            }

            // Port must match; IP can be exact match or INADDR_ANY
            const auto& local_addr = socket->GetLocalAddr();
            const uint32_t local_ip = local_addr.GetAddr();
            if (local_addr.GetPort() != dest_port || (local_ip != 0 && local_ip != dest_ip)) {
                continue;
            }

            listener = socket;
            break;
        }
    }

    if (listener == nullptr) {
        return false;
    }

    // Outside m_mutex: IncomingConnection replies through SendProxyConnectReply.
    listener->IncomingConnection(request);
    return true;
}

// =============================================================================
// Data Routing
// =============================================================================

bool ProxySocketManager::RouteIncomingData(uint32_t source_ip, uint16_t source_port,
                                            uint32_t dest_ip, uint16_t dest_port,
                                            ryu_ldn::bsd::ProtocolType protocol,
                                            const void* data, size_t data_len) {
    std::scoped_lock lock(m_mutex);

    // For broadcast/multicast packets, deliver to ALL matching sockets.
    // PIA mesh discovery relies on broadcast UDP reaching every listener
    // on the same port. For unicast, only one socket matches.
    constexpr size_t kMaxSockets = 8;
    ProxySocket* targets[kMaxSockets];
    size_t match_count = FindAllSocketsByDestination(dest_ip, dest_port, protocol,
                                                      targets, kMaxSockets);

    if (match_count == 0) {
        // No matching socket — buffer for post-bind delivery. Oversize
        // datagrams are dropped, never stored cut short.
        if (data_len <= PROXY_SOCKET_MAX_PAYLOAD && (data != nullptr || data_len == 0)) {
            m_pending.Push(PendingHeader{source_ip, dest_ip, source_port, dest_port, protocol}, data, data_len);
        }
        return false;
    }

    // Build source address for RecvFrom
    // Note: Nintendo Switch uses BSD-style sockaddr with sin_len field
    // sin_len must be sizeof(SockAddrIn) = 16 for the game to accept the address
    //
    // CRITICAL: Ryujinx stores IPs as uint in "big-endian read" format:
    // For 10.114.0.1, Ryujinx stores 0x0A720001.
    // BUT in BsdSockAddr, sin_addr must be in NETWORK BYTE ORDER (standard BSD).
    // Ryujinx does Array.Reverse() when converting ProxyInfo.SourceIpV4 to IPEndPoint,
    // then copies bytes directly to sin_addr, resulting in network byte order.
    // So we must bswap32 to convert Ryujinx format -> network byte order.
    // For 10.114.0.1: 0x0A720001 -> bswap32 -> 0x0100720A (network order)
    ryu_ldn::bsd::SockAddrIn from_addr{};
    from_addr.sin_len = sizeof(ryu_ldn::bsd::SockAddrIn);
    from_addr.sin_family = static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet);
    from_addr.sin_port = __builtin_bswap16(source_port);
    from_addr.sin_addr = __builtin_bswap32(source_ip);  // Convert Ryujinx format to network byte order

    // Deliver to all matching sockets (critical for broadcast UDP)
    for (size_t i = 0; i < match_count; i++) {
        targets[i]->IncomingData(data, data_len, from_addr);
    }

    return true;
}

size_t ProxySocketManager::FindAllSocketsByDestination(uint32_t dest_ip, uint16_t dest_port,
                                                          ryu_ldn::bsd::ProtocolType protocol,
                                                          ProxySocket* out_sockets[], size_t max_sockets) {
    // Caller must hold m_mutex

    bool is_broadcast = ((dest_ip & 0x000000FF) == 0x000000FF) ||
                        ((dest_ip & 0x0000FFFF) == 0x0000FFFF);

    size_t count = 0;

    for (auto& [fd, socket] : m_sockets) {
        if (socket == nullptr) {
            continue;
        }
        if (count >= max_sockets) {
            break;
        }

        if (socket->GetProtocol() != protocol) {
            continue;
        }

        const auto& local_addr = socket->GetLocalAddr();

        if (local_addr.GetPort() != dest_port) {
            continue;
        }

        uint32_t local_ip = local_addr.GetAddr();  // Ryujinx format, like dest_ip

        if (local_ip == 0) {
            out_sockets[count++] = socket.get();
            continue;
        }
        if (local_ip == dest_ip) {
            out_sockets[count++] = socket.get();
            continue;
        }
        if (is_broadcast) {
            if ((local_ip & 0xFFFF0000) == (dest_ip & 0xFFFF0000)) {
                out_sockets[count++] = socket.get();
                continue;
            }
        }
    }

    return count;
}

// =============================================================================
// LDN Network Configuration
// =============================================================================

void ProxySocketManager::SetLocalIp(uint32_t ip) {
    std::scoped_lock lock(m_mutex);
    m_local_ip = ip;
}

uint32_t ProxySocketManager::GetLocalIp() const {
    std::scoped_lock lock(m_mutex);
    return m_local_ip;
}

// =============================================================================
// Statistics
// =============================================================================

size_t ProxySocketManager::GetActiveSocketCount() const {
    std::scoped_lock lock(m_mutex);
    return m_sockets.size();
}

size_t ProxySocketManager::GetAvailablePortCount(ryu_ldn::bsd::ProtocolType protocol) const {
    return m_port_pool.GetAvailableCount(protocol);
}

// =============================================================================
// Pending Packet Delivery
// =============================================================================

void ProxySocketManager::DeliverPendingPackets(ProxySocket* socket, uint16_t port,
                                                ryu_ldn::bsd::ProtocolType protocol) {
    // Called after bind - deliver any buffered packets matching this socket
    // Caller must NOT hold m_mutex (we take it here)
    std::scoped_lock lock(m_mutex);

    if (socket == nullptr) {
        return;
    }

    // Take each datagram off the front once; deliver matches, re-queue the
    // rest at the back so their order is kept.
    uint8_t payload[PROXY_SOCKET_MAX_PAYLOAD];
    for (size_t n = m_pending.Count(); n > 0; n--) {
        PendingHeader pkt;
        const size_t len = m_pending.Front(&pkt, payload, sizeof(payload));
        m_pending.Pop();

        if (pkt.protocol == protocol && pkt.dest_port == port) {
            ryu_ldn::bsd::SockAddrIn from_addr{};
            from_addr.sin_len = sizeof(ryu_ldn::bsd::SockAddrIn);
            from_addr.sin_family = static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet);
            from_addr.sin_port = __builtin_bswap16(pkt.source_port);
            from_addr.sin_addr = __builtin_bswap32(pkt.source_ip);  // Ryujinx -> network byte order
            socket->IncomingData(payload, len, from_addr);
        } else {
            m_pending.Push(pkt, payload, len);
        }
    }
}

} // namespace ams::mitm::bsd
