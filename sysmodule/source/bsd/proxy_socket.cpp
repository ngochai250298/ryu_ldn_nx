/**
 * @file proxy_socket.cpp
 * @brief Implementation of the Proxy Socket for LDN Traffic Routing
 *
 * This file implements the ProxySocket class. Data transfer operations
 * (Send/Recv) interact with the ProxySocketManager to encode/decode
 * ProxyData packets.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include "proxy_socket.hpp"
#include "proxy_socket_manager.hpp"
#include "../debug/log.hpp"

namespace ams::mitm::bsd {

// =============================================================================
// BSD Error Codes (from bsd_types.hpp)
// =============================================================================

using Errno = ryu_ldn::bsd::BsdErrno;

// =============================================================================
// Construction / Destruction
// =============================================================================

ProxySocket::ProxySocket(ryu_ldn::bsd::SocketType type, ryu_ldn::bsd::ProtocolType protocol)
    : m_type(type)
    , m_protocol(protocol)
    , m_state(ProxySocketState::Created)
    , m_non_blocking(false)
    , m_shutdown_read(false)
    , m_shutdown_write(false)
{
    // Initialize addresses to zero
    std::memset(&m_local_addr, 0, sizeof(m_local_addr));
    std::memset(&m_remote_addr, 0, sizeof(m_remote_addr));

    // Set address family
    m_local_addr.sin_family = static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet);
    m_local_addr.sin_len = sizeof(ryu_ldn::bsd::SockAddrIn);
    m_remote_addr.sin_family = static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet);
    m_remote_addr.sin_len = sizeof(ryu_ldn::bsd::SockAddrIn);
}

ProxySocket::~ProxySocket() {
    // Just cleanup, don't send disconnect (should have called Close())
    m_state = ProxySocketState::Closed;
}

// =============================================================================
// Address Management
// =============================================================================

Result ProxySocket::Bind(const ryu_ldn::bsd::SockAddrIn& addr) {
    // Check state
    if (m_state != ProxySocketState::Created) {
        // Already bound or in invalid state
        R_THROW(static_cast<s32>(Errno::Inval));
    }

    // Validate address family
    if (addr.sin_family != static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet)) {
        R_THROW(static_cast<s32>(Errno::AfNoSupport));
    }

    // Store local address
    m_local_addr = addr;
    m_state = ProxySocketState::Bound;

    R_SUCCEED();
}

Result ProxySocket::Connect(const ryu_ldn::bsd::SockAddrIn& addr) {
    // Check state - must be at least created (can connect unbound socket)
    if (m_state == ProxySocketState::Closed) {
        R_THROW(static_cast<s32>(Errno::BadF));
    }

    // If not bound yet, auto-bind will happen with ephemeral port
    // (caller should have done this before calling Connect)

    // Validate address family
    if (addr.sin_family != static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet)) {
        R_THROW(static_cast<s32>(Errno::AfNoSupport));
    }

    // Store remote address
    m_remote_addr = addr;

    // For TCP, perform connect handshake
    if (m_type == ryu_ldn::bsd::SocketType::Stream) {
        m_state = ProxySocketState::Connecting;
        m_connect_response_received = false;
        m_connect_event.Clear();

        // Send ProxyConnect via ProxySocketManager
        auto& manager = ProxySocketManager::GetInstance();
        bool sent = manager.SendProxyConnect(
            m_local_addr.GetAddr(), m_local_addr.GetPort(),
            addr.GetAddr(), addr.GetPort(),
            m_protocol
        );

        if (!sent) {
            m_state = ProxySocketState::Bound;
            R_THROW(static_cast<s32>(Errno::NetUnreach));
        }

        // Wait for ProxyConnectReply (with timeout)
        if (!m_non_blocking) {
            // Blocking connect - wait up to 4 seconds (like Ryujinx)
            bool got_response = m_connect_event.TimedWait(TimeSpan::FromSeconds(4));

            if (m_state == ProxySocketState::Closed) {
                R_THROW(static_cast<s32>(Errno::BadF));
            }
            if (!got_response || !m_connect_response_received) {
                m_state = ProxySocketState::Bound;
                R_THROW(static_cast<s32>(Errno::TimedOut));
            }

            // Check if connection was refused (protocol != Unspecified means error)
            if (m_connect_response.info.protocol != ryu_ldn::protocol::ProtocolType::Unspecified) {
                m_state = ProxySocketState::Bound;
                R_THROW(static_cast<s32>(Errno::ConnRefused));
            }

            m_state = ProxySocketState::Connected;
        } else {
            // Non-blocking connect - return EINPROGRESS
            // The connect will complete asynchronously
            R_THROW(static_cast<s32>(Errno::InProgress));
        }
    } else {
        // For UDP, just store the default destination
        m_state = ProxySocketState::Connected;
    }

    R_SUCCEED();
}

Result ProxySocket::GetSockName(ryu_ldn::bsd::SockAddrIn* out_addr) const {
    if (out_addr == nullptr) {
        R_THROW(static_cast<s32>(Errno::Fault));
    }

    if (m_state == ProxySocketState::Created) {
        // Not bound yet, return zeroed address
        std::memset(out_addr, 0, sizeof(*out_addr));
        out_addr->sin_family = static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet);
        out_addr->sin_len = sizeof(ryu_ldn::bsd::SockAddrIn);
    } else {
        *out_addr = m_local_addr;
    }

    R_SUCCEED();
}

Result ProxySocket::GetPeerName(ryu_ldn::bsd::SockAddrIn* out_addr) const {
    if (out_addr == nullptr) {
        R_THROW(static_cast<s32>(Errno::Fault));
    }

    if (m_state != ProxySocketState::Connected) {
        R_THROW(static_cast<s32>(Errno::NotConn));
    }

    *out_addr = m_remote_addr;
    R_SUCCEED();
}

// =============================================================================
// Data Transfer
// =============================================================================

s32 ProxySocket::Send(const void* data, size_t len, s32 flags) {
    // Must be connected for Send()
    if (m_state != ProxySocketState::Connected) {
        return -static_cast<s32>(Errno::NotConn);
    }

    // Use SendTo with connected remote address
    return SendTo(data, len, flags, m_remote_addr);
}

s32 ProxySocket::SendTo(const void* data, size_t len, s32 flags, const ryu_ldn::bsd::SockAddrIn& dest) {
    AMS_UNUSED(flags);

    // Check write shutdown
    if (m_shutdown_write) {
        return -static_cast<s32>(Errno::Inval);
    }

    // Check socket state
    if (m_state == ProxySocketState::Closed) {
        return -static_cast<s32>(Errno::BadF);
    }

    // Must be at least bound to send
    if (m_state == ProxySocketState::Created) {
        return -static_cast<s32>(Errno::DestAddrReq);
    }

    // Validate data
    if (data == nullptr && len > 0) {
        return -static_cast<s32>(Errno::Fault);
    }

    // Check max payload size
    if (len > PROXY_SOCKET_MAX_PAYLOAD) {
        return -static_cast<s32>(Errno::MsgSize);
    }

    // Send via ProxySocketManager which routes to LDN server.
    // m_local_addr.sin_addr is stored in Ryujinx format (no bswap was applied in Bind),
    // so read it directly. dest comes from the game in network byte order, so GetAddr()
    // bswaps it into Ryujinx format — which is what the server expects on the wire.
    uint32_t source_ip = m_local_addr.sin_addr;
    uint16_t source_port = m_local_addr.GetPort();
    uint32_t dest_ip = dest.GetAddr();
    uint16_t dest_port = dest.GetPort();

    auto& manager = ProxySocketManager::GetInstance();
    bool sent = manager.SendProxyData(source_ip, source_port, dest_ip, dest_port,
                                       m_protocol, data, len);

    if (!sent) {
        // No send callback registered or send failed
        // Return ENETUNREACH to indicate network is unreachable
        return -static_cast<s32>(Errno::NetUnreach);
    }

    return static_cast<s32>(len);
}

s32 ProxySocket::Recv(void* buffer, size_t len, s32 flags) {
    // For connected sockets, use RecvFrom and discard the address
    if (m_state == ProxySocketState::Connected) {
        return RecvFrom(buffer, len, flags, nullptr);
    }

    // For unconnected sockets, Recv requires a default peer (connected state)
    return -static_cast<s32>(Errno::NotConn);
}

TimeSpan ProxySocket::BlockingWaitLimit() const {
    const s64 cap_ns = TimeSpan::FromMilliSeconds(PROXY_SOCKET_MAX_BLOCK_MS).GetNanoSeconds();
    const s64 rcv_ns = m_rcv_timeout_ns;
    return TimeSpan::FromNanoSeconds((rcv_ns > 0 && rcv_ns < cap_ns) ? rcv_ns : cap_ns);
}

s32 ProxySocket::RecvFrom(void* buffer, size_t len, s32 flags, ryu_ldn::bsd::SockAddrIn* from) {
    // Validate buffer
    if (buffer == nullptr && len > 0) {
        return -static_cast<s32>(Errno::Fault);
    }

    const bool peek = (flags & ryu_ldn::bsd::MSG_FLAG_PEEK) != 0;
    const bool dontwait = (flags & ryu_ldn::bsd::MSG_FLAG_DONTWAIT) != 0 || m_non_blocking;
    const TimeSpan deadline = os::GetSystemTick().ToTimeSpan() + BlockingWaitLimit();

    while (true) {
        {
            std::scoped_lock lock(m_queue_mutex);

            if (m_state == ProxySocketState::Closed) {
                return -static_cast<s32>(Errno::BadF);
            }
            if (m_shutdown_read) {
                return 0; // EOF
            }

            if (!m_rx_ring.Empty()) {
                // A datagram larger than the buffer is truncated, the rest discarded.
                const size_t full_len = m_rx_ring.Front(from, buffer, len);
                if (!peek) {
                    m_rx_ring.Pop();
                }
                if (m_rx_ring.Empty()) {
                    m_receive_event.Clear();
                }
                return static_cast<s32>(std::min(len, full_len));
            }

            if (dontwait) {
                return -static_cast<s32>(Errno::Again);
            }

            // Queue is empty. IncomingData/Shutdown/Close signal under this
            // lock, so clearing here can't lose a wakeup.
            m_receive_event.Clear();
        }

        const TimeSpan now = os::GetSystemTick().ToTimeSpan();
        if (now >= deadline) {
            return -static_cast<s32>(Errno::Again);
        }
        m_receive_event.TimedWait(deadline - now);
    }
}

void ProxySocket::IncomingData(const void* data, size_t len, const ryu_ldn::bsd::SockAddrIn& from) {
    // Hex-dump first 32 bytes — only format and log at VERBOSE level, since this
    // fires on every incoming packet and the snprintf loop is non-trivial under
    // load (~100+ packets/sec during gameplay).
    if (len > 0 && data != nullptr &&
        ryu_ldn::debug::g_logger.should_log(ryu_ldn::debug::LogLevel::Verbose)) {
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        size_t log_len = std::min(len, size_t(32));
        char hex_buf[128];
        char* p = hex_buf;
        for (size_t i = 0; i < log_len && (p - hex_buf) < 120; i++) {
            p += std::snprintf(p, 4, "%02X ", bytes[i]);
        }
        LOG_VERBOSE("ProxySocket IncomingData: %zu bytes, first %zu: %s", len, log_len, hex_buf);
    }

    // NOTE: Broadcast filtering is intentionally incomplete. When this socket
    // is bound to INADDR_ANY (local_ip == 0), we cannot determine the
    // original destination IP of an incoming packet, so filtering based on
    // SO_BROADCAST is not feasible. Since ProxySocketManager::RouteIncomingData
    // already delivers broadcast UDP to all matching sockets, and PIA mesh
    // discovery requires that broadcast reach every listener, skipping the
    // filter here is correct behaviour. The if-block is kept as a structural
    // anchor for a future destination-aware implementation if the proxy
    // protocol ever carries the destination address.

    // A datagram larger than any game frame is dropped rather than cut short
    // and delivered as if complete.
    if (len > PROXY_SOCKET_MAX_PAYLOAD || (data == nullptr && len > 0)) {
        LOG_WARN("ProxySocket IncomingData: dropping %zu-byte datagram (max %zu)", len, PROXY_SOCKET_MAX_PAYLOAD);
        return;
    }

    std::scoped_lock lock(m_queue_mutex);

    // Drops the oldest datagrams if full (UDP behavior); no allocation.
    m_rx_ring.Push(from, data, len);

    m_receive_event.Signal();
}

// =============================================================================
// Socket Options
// =============================================================================

Result ProxySocket::SetSockOpt(s32 level, s32 optname, const void* optval, size_t optlen) {
    // Handle SOL_SOCKET level options
    if (level == static_cast<s32>(ryu_ldn::bsd::SocketOptionLevel::Socket)) {
        switch (static_cast<ryu_ldn::bsd::SocketOption>(optname)) {
            case ryu_ldn::bsd::SocketOption::Broadcast:
                // SO_BROADCAST - enable/disable broadcast reception
                if (optval != nullptr && optlen >= sizeof(s32)) {
                    s32 value = *reinterpret_cast<const s32*>(optval);
                    m_broadcast = (value != 0);
                    R_SUCCEED();
                }
                R_THROW(static_cast<s32>(Errno::Inval));

            case ryu_ldn::bsd::SocketOption::ReuseAddr:
            case ryu_ldn::bsd::SocketOption::KeepAlive:
            case ryu_ldn::bsd::SocketOption::DontRoute:
            case ryu_ldn::bsd::SocketOption::Linger:
            case ryu_ldn::bsd::SocketOption::OobInline:
            case ryu_ldn::bsd::SocketOption::ReusePort:
            case ryu_ldn::bsd::SocketOption::SndBuf:
            case ryu_ldn::bsd::SocketOption::RcvBuf:
            case ryu_ldn::bsd::SocketOption::SndLoWat:
            case ryu_ldn::bsd::SocketOption::RcvLoWat:
            case ryu_ldn::bsd::SocketOption::RcvTimeo:
                if (optval != nullptr && optlen >= sizeof(ryu_ldn::bsd::Timeval)) {
                    ryu_ldn::bsd::Timeval tv;
                    std::memcpy(&tv, optval, sizeof(tv));
                    m_rcv_timeout_ns = ryu_ldn::bsd::TimevalToNanoseconds(tv);
                    R_SUCCEED();
                }
                R_THROW(static_cast<s32>(Errno::Inval));

            case ryu_ldn::bsd::SocketOption::SndTimeo:
                // Accept but ignore these common options
                R_SUCCEED();

            default:
                break;
        }
    }

    // Accept but ignore unknown options (compatibility)
    AMS_UNUSED(level, optname, optval, optlen);
    R_SUCCEED();
}

Result ProxySocket::GetSockOpt(s32 level, s32 optname, void* optval, size_t* optlen) const {
    if (optval == nullptr || optlen == nullptr) {
        R_THROW(static_cast<s32>(Errno::Fault));
    }

    // Handle specific options
    if (level == static_cast<s32>(ryu_ldn::bsd::SocketOptionLevel::Socket)) {
        switch (static_cast<ryu_ldn::bsd::SocketOption>(optname)) {
            case ryu_ldn::bsd::SocketOption::Type:
                // SO_TYPE - return socket type
                if (*optlen >= sizeof(s32)) {
                    *reinterpret_cast<s32*>(optval) = static_cast<s32>(m_type);
                    *optlen = sizeof(s32);
                    R_SUCCEED();
                }
                break;

            case ryu_ldn::bsd::SocketOption::Error:
                // SO_ERROR - return 0 (no error)
                if (*optlen >= sizeof(s32)) {
                    *reinterpret_cast<s32*>(optval) = 0;
                    *optlen = sizeof(s32);
                    R_SUCCEED();
                }
                break;

            case ryu_ldn::bsd::SocketOption::Broadcast:
                // SO_BROADCAST - return broadcast flag
                if (*optlen >= sizeof(s32)) {
                    *reinterpret_cast<s32*>(optval) = m_broadcast ? 1 : 0;
                    *optlen = sizeof(s32);
                    R_SUCCEED();
                }
                break;

            default:
                break;
        }
    }

    // Unknown option - return not supported
    R_THROW(static_cast<s32>(Errno::NoProtoOpt));
}

// =============================================================================
// TCP-specific Operations
// =============================================================================

Result ProxySocket::Listen(s32 backlog) {
    AMS_UNUSED(backlog);

    // Must be TCP
    if (m_type != ryu_ldn::bsd::SocketType::Stream) {
        R_THROW(static_cast<s32>(Errno::OpNotSupp));
    }

    // Must be bound
    if (m_state == ProxySocketState::Created) {
        R_THROW(static_cast<s32>(Errno::Inval));
    }

    m_state = ProxySocketState::Listening;
    R_SUCCEED();
}

std::unique_ptr<ProxySocket> ProxySocket::Accept(ryu_ldn::bsd::SockAddrIn* out_addr) {
    const TimeSpan deadline = os::GetSystemTick().ToTimeSpan() + BlockingWaitLimit();

    while (true) {
        {
            std::scoped_lock lock(m_queue_mutex);

            // Must be listening (Close moves the state to Closed)
            if (m_state != ProxySocketState::Listening) {
                return nullptr;
            }

            if (!m_accept_queue.empty()) {
                auto accepted = std::move(m_accept_queue.front());
                m_accept_queue.pop_front();

                if (m_accept_queue.empty()) {
                    m_accept_event.Clear();
                }

                if (out_addr != nullptr) {
                    *out_addr = accepted->GetRemoteAddr();
                }

                return accepted;
            }

            if (m_non_blocking) {
                return nullptr; // EWOULDBLOCK
            }

            m_accept_event.Clear();
        }

        const TimeSpan now = os::GetSystemTick().ToTimeSpan();
        if (now >= deadline) {
            return nullptr;
        }
        m_accept_event.TimedWait(deadline - now);
    }
}

void ProxySocket::IncomingConnection(const ryu_ldn::protocol::ProxyConnectRequest& request) {
    // Only accept on listening sockets
    if (m_state != ProxySocketState::Listening) {
        return;
    }

    // Create a new socket for the accepted connection
    std::unique_ptr<ProxySocket> accepted(new (std::nothrow) ProxySocket(m_type, m_protocol));
    if (accepted == nullptr) {
        LOG_WARN("ProxySocket IncomingConnection: out of memory, connection dropped");
        return;
    }

    // Set local address (same as listening socket)
    accepted->m_local_addr = m_local_addr;

    // Set remote address from request
    // CRITICAL: Do NOT bswap32 the IP - must match Ryujinx/NetworkInfo format
    accepted->m_remote_addr.sin_family = static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet);
    accepted->m_remote_addr.sin_len = sizeof(ryu_ldn::bsd::SockAddrIn);
    accepted->m_remote_addr.sin_addr = request.info.source_ipv4;  // NO bswap32 - Ryujinx format
    accepted->m_remote_addr.sin_port = __builtin_bswap16(request.info.source_port);

    // Mark as connected
    accepted->m_state = ProxySocketState::Connected;

    {
        std::scoped_lock lock(m_queue_mutex);
        m_accept_queue.push_back(std::move(accepted));
        m_accept_event.Signal();
    }

    // Send ProxyConnectReply back to the peer via ProxySocketManager, after
    // releasing m_queue_mutex: the manager lock is always taken first.
    auto& manager = ProxySocketManager::GetInstance();
    uint32_t local_ip = m_local_addr.GetAddr();
    uint16_t local_port = m_local_addr.GetPort();
    uint32_t remote_ip = request.info.source_ipv4;
    uint16_t remote_port = request.info.source_port;

    manager.SendProxyConnectReply(local_ip, local_port, remote_ip, remote_port,
                                   ryu_ldn::bsd::ProtocolType::Tcp);
}

void ProxySocket::HandleConnectResponse(const ryu_ldn::protocol::ProxyConnectResponse& response) {
    // Store the response
    m_connect_response = response;
    m_connect_response_received = true;

    // Signal that connect response arrived
    m_connect_event.Signal();
}

bool ProxySocket::HasPendingConnections() const {
    std::scoped_lock lock(m_queue_mutex);
    return !m_accept_queue.empty();
}

// =============================================================================
// Shutdown and Close
// =============================================================================

Result ProxySocket::Shutdown(ryu_ldn::bsd::ShutdownHow how) {
    std::scoped_lock lock(m_queue_mutex);

    switch (how) {
        case ryu_ldn::bsd::ShutdownHow::Read:
            m_shutdown_read = true;
            break;
        case ryu_ldn::bsd::ShutdownHow::Write:
            m_shutdown_write = true;
            break;
        case ryu_ldn::bsd::ShutdownHow::Both:
            m_shutdown_read = true;
            m_shutdown_write = true;
            break;
        default:
            R_THROW(static_cast<s32>(Errno::Inval));
    }

    // Wake any blocked receiver; it sees the shutdown and returns EOF.
    m_receive_event.Signal();

    R_SUCCEED();
}

Result ProxySocket::Close() {
    {
        std::scoped_lock lock(m_queue_mutex);
        m_state = ProxySocketState::Closed;
        m_shutdown_read = true;
        m_shutdown_write = true;

        // Clear ring queue (no deallocation — just reset indices)
        m_rx_ring.Clear();

        // Wake every waiter; each one sees Closed and returns.
        m_receive_event.Signal();
        m_accept_event.Signal();
        m_connect_event.Signal();
    }

    // For TCP, send ProxyDisconnect to notify the peer
    if (m_protocol == ryu_ldn::bsd::ProtocolType::Tcp && m_remote_addr.GetPort() != 0) {
        auto& manager = ProxySocketManager::GetInstance();
        uint32_t local_ip = m_local_addr.GetAddr();
        uint16_t local_port = m_local_addr.GetPort();
        uint32_t remote_ip = m_remote_addr.GetAddr();
        uint16_t remote_port = m_remote_addr.GetPort();

        manager.SendProxyDisconnect(local_ip, local_port, remote_ip, remote_port,
                                     ryu_ldn::bsd::ProtocolType::Tcp);
    }

    R_SUCCEED();
}

// =============================================================================
// Event Handling
// =============================================================================

bool ProxySocket::HasPendingData() const {
    std::scoped_lock lock(m_queue_mutex);
    return !m_rx_ring.Empty();
}

size_t ProxySocket::GetPendingDataSize() const {
    std::scoped_lock lock(m_queue_mutex);
    return m_rx_ring.PayloadBytes();
}

} // namespace ams::mitm::bsd
