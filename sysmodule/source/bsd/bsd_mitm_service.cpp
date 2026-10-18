/**
 * @file bsd_mitm_service.cpp
 * @brief BSD MITM Service implementation - Socket interception for LDN proxy
 *
 * ## Overview
 *
 * This file implements all BSD socket service commands with full forwarding
 * to the real bsd:u service. The MITM service intercepts all IPC calls and
 * transparently forwards them.
 *
 * ## Forwarding Architecture
 *
 * This MITM uses Atmosphere's `serviceMitmDispatch*` macros to forward
 * IPC calls to the real bsd:u service. The macros handle:
 *
 * - Buffer marshalling (InBuffer, OutBuffer, AutoSelectBuffer)
 * - Handle forwarding (CopyHandle, MoveHandle)
 * - PID override with MITM tag (0xFFFE prefix)
 * - Response parsing and error propagation
 *
 * ## Forward Service Access
 *
 * The `m_forward_service` member (inherited from MitmServiceImplBase) holds
 * a session to the real bsd:u service. All forwarding calls use this session.
 *
 * ## Buffer Attributes (from switchbrew)
 *
 * BSD service uses specific buffer types defined by SfBufferAttr:
 * - SfBufferAttr_HipcMapAlias: Type-A (0x5) or Type-B (0x6) buffer
 * - SfBufferAttr_HipcAutoSelect: Type-0x21 (in) or Type-0x22 (out) auto-select
 * - SfBufferAttr_In: Input buffer
 * - SfBufferAttr_Out: Output buffer
 *
 * ## Command Reference
 *
 * https://switchbrew.org/wiki/Sockets_services#bsd:u.2C_bsd:s
 *
 * ## LDN Interception Strategy (Future Stories)
 *
 * In Story 8.4+, we will add:
 * 1. Socket tracking table to monitor all created sockets
 * 2. LDN address detection in Bind/Connect (10.114.x.x)
 * 3. ProxyData packet routing for LDN sockets
 * 4. Virtual socket emulation for LDN traffic
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include "bsd_mitm_service.hpp"
#include "proxy_socket_manager.hpp"
#include "bsd_types.hpp"
#include "../debug/log.hpp"
#include "../ldn/ldn_shared_state.hpp"
#include "../config/game_whitelist.hpp"
#include "../config/config_ipc_service.hpp"

// Atmosphere MITM dispatch macros for IPC forwarding
#include <stratosphere/sf/sf_mitm_dispatch.h>

extern "C" {
#include <switch/services/bsd.h>
}

namespace ams::mitm::bsd {

// =============================================================================
// Socket Type/Protocol Tracking
// =============================================================================

/**
 * @brief Info stored for each socket created via Socket()
 *
 * We need to track this because when Bind/Connect is called later,
 * we need to know the socket type and protocol to create the ProxySocket.
 */
struct SocketInfo {
    ryu_ldn::bsd::SocketType type;
    ryu_ldn::bsd::ProtocolType protocol;
    bool is_proxy;  // True if this socket is an LDN proxy socket
    bool broadcast; // SO_BROADCAST option (tracked before proxy creation)
    bool non_blocking; // O_NONBLOCK / FIONBIO / SOCK_NONBLOCK (tracked before proxy creation)
    s64 rcv_timeout_ns; // SO_RCVTIMEO, 0 for none (tracked before proxy creation)
    u32 session_id; // Session ID that owns this socket (for cleanup on session close)
};

/**
 * @brief Socket info tracking table
 *
 * Maps file descriptor to socket info. This is needed because Socket()
 * creates the fd but Bind/Connect happens later, and we need the socket
 * type/protocol to create the ProxySocket.
 *
 * NOTE: This is a global static shared across all MITM clients. Access
 * must be protected by g_socket_info_mutex. Different client processes
 * may have the same fd values, but since we're in the sysmodule context,
 * fd collisions are handled by the fact that each BsdMitmService instance
 * forwards to a different real service session.
 */
static std::unordered_map<u64, SocketInfo> g_socket_info;

/**
 * @brief Mutex protecting g_socket_info
 *
 * Must be held when reading or modifying g_socket_info.
 */
static os::Mutex g_socket_info_mutex{false};

/**
 * @brief Map of PIDs to session count for BSD MITM
 *
 * Tracks how many BSD sessions have been intercepted per process.
 * We intercept ALL BSD sessions from whitelisted games because some games
 * (like Mario Kart 8) may use multiple sessions for different operations.
 * Value: number of BSD sessions intercepted for this PID.
 */
static std::unordered_map<u64, u32> g_mitm_pid_count;
static os::Mutex g_mitm_pids_mutex{false};

/**
 * @brief List of abandoned forward services (sessions that never got RegisterClient)
 *
 * When a BSD MITM session is closed without ever receiving RegisterClient,
 * we move its forward_service here instead of closing it. This prevents
 * a system freeze that occurs when closing an unregistered bsd:u session.
 *
 * These services will be cleaned up when the game process exits or when
 * we explicitly clean them (e.g., on LDN disconnect).
 */
static std::vector<std::shared_ptr<::Service>> g_abandoned_forward_services;
static os::Mutex g_abandoned_services_mutex{false};

// =============================================================================
// Constructor / Destructor
// =============================================================================

/**
 * @brief Construct BSD MITM service for a client process
 *
 * Called by Atmosphere's server manager when a process opens bsd:u
 * and ShouldMitm() returns true.
 *
 * ## Forward Service
 *
 * The `s` parameter is a shared_ptr to a Service structure that represents
 * an open session to the real bsd:u service. This is stored in the inherited
 * `m_forward_service` member and used for all forwarding calls via
 * `serviceMitmDispatch*` macros.
 *
 * ## Client Tracking
 *
 * We store the client's PID for logging and future socket tracking.
 * Each client process gets its own BsdMitmService instance with its own
 * forward service session.
 *
 * @param s Shared pointer to the original bsd:u service session
 * @param c Process information for the client (PID, program ID, etc.)
 */
BsdMitmService::BsdMitmService(std::shared_ptr<::Service>&& s, const sm::MitmProcessInfo& c)
    : MitmServiceImplBase(std::forward<std::shared_ptr<::Service>>(s), c)
    , m_client_pid(c.process_id.value)
    , m_session_id(++s_next_session_id)
{
    // Get more info about the forward service
    ::Service* fwd = m_forward_service.get();
    Handle session_handle = fwd ? fwd->session : INVALID_HANDLE;
    bool is_domain = fwd ? serviceIsDomain(fwd) : false;
    u32 object_id = fwd ? fwd->object_id : 0;

    LOG_INFO("[BSD#%u] CONSTRUCTOR: program_id=0x%016lx, pid=%lu, fwd_srv=%p (handle=0x%x, domain=%d, object_id=%u)",
             m_session_id, c.program_id.value, m_client_pid, fwd, session_handle, is_domain, object_id);
    // FIX v6-v7 (#44): Count active IPC sessions to detect game exit.
    // Each BsdMitmService instance is one bsd:u session.
    ams::mitm::ldn::SharedState::GetInstance().IncrementSessionCount();
}

/**
 * @brief Destroy BSD MITM service
 *
 * Called when the client process closes its bsd:u session or terminates.
 * The forward_service session is automatically closed by the shared_ptr.
 *
 * ## Future Cleanup (Story 8.4)
 *
 * When socket tracking is implemented, this destructor will cleanup
 * all tracked sockets for this client to prevent resource leaks.
 */
BsdMitmService::~BsdMitmService() {
    // Clean up all socket info entries belonging to this session
    // This prevents memory leaks when games crash or exit without closing sockets
    //
    // IMPORTANT: We must NOT hold g_socket_info_mutex while calling CloseProxySocket
    // because CloseProxySocket acquires ProxySocketManager::m_mutex, which could
    // cause a deadlock if the mutex order is reversed elsewhere.
    std::vector<u64> proxy_keys_to_close;
    {
        std::scoped_lock lock(g_socket_info_mutex);
        size_t cleaned = 0;
        for (auto it = g_socket_info.begin(); it != g_socket_info.end(); ) {
            if (it->second.session_id == m_session_id) {
                // Collect proxy sockets to close after releasing the lock
                if (it->second.is_proxy) {
                    proxy_keys_to_close.push_back(it->first);
                }
                it = g_socket_info.erase(it);
                cleaned++;
            } else {
                ++it;
            }
        }
        if (cleaned > 0) {
            LOG_INFO("[BSD#%u] DESTRUCTOR: cleaned up %zu orphaned socket entries", m_session_id, cleaned);
        }
    }

    // Now close proxy sockets without holding g_socket_info_mutex
    if (!proxy_keys_to_close.empty()) {
        auto& manager = ProxySocketManager::GetInstance();
        for (u64 key : proxy_keys_to_close) {
            manager.CloseProxySocket(key);
        }
    }

    // Decrement the session count for this PID
    bool was_last_session = false;
    {
        std::scoped_lock lock(g_mitm_pids_mutex);
        auto it = g_mitm_pid_count.find(m_client_pid);
        if (it != g_mitm_pid_count.end()) {
            if (it->second > 0) {
                it->second--;
            }
            if (it->second == 0) {
                g_mitm_pid_count.erase(it);
                was_last_session = true;
            }
        }
    }

    // FIX v3 (#44): If this was the last BSD session for this process,
    // clean up abandoned forward services immediately.
    // Previously we relied on CleanupAbandonedServices() being called
    // from ~ICommunicationService() / DisconnectFromServer(), but if
    // the game crashes before opening ldn:u (or never opens it), those
    // paths are never hit. Abandoned bsd:u handles accumulate and can
    // exhaust the global bsd:u session pool, causing the next game's
    // nn::socket::Initialize (and CreateTransferMemory) to fail.
    if (was_last_session) {
        LOG_INFO("[BSD#%u] Last BSD session for pid=%lu — cleaning up abandoned services",
                 m_session_id, m_client_pid);
        CleanupAbandonedServices();
    }

    // FIX v6-v7 (#44): Count active IPC sessions to detect game exit.
    // When the game dies, Atmosphere closes all ldn:u/bsd:u sessions.
    // The destructor runs for each session, decrementing the counter.
    // When it hits zero, no more sessions exist → the game is gone.
    auto& shared_state = ams::mitm::ldn::SharedState::GetInstance();
    u32 remaining = shared_state.DecrementSessionCount();
    LOG_INFO("[BSD#%u] Destructor: active sessions remaining = %u", m_session_id, remaining);

    if (remaining == 0) {
        LOG_INFO("[BSD#%u] Destructor: no active sessions — game closed, terminating sysmodule", m_session_id);
        (void)sm::mitm::UninstallMitm(sm::ServiceName::Encode("ldn:u"));
        (void)sm::mitm::UninstallMitm(sm::ServiceName::Encode("bsd:u"));
        ryu_ldn::debug::g_logger.flush();
        svc::ExitProcess();
    }
    ::Service* fwd = m_forward_service.get();
    Handle session_handle = fwd ? fwd->session : INVALID_HANDLE;
    LOG_INFO("[BSD#%u] DESTRUCTOR: pid=%lu, fwd_srv=%p (handle=0x%x), commands=%u, registered=%d",
             m_session_id, m_client_pid, fwd, session_handle, m_command_count, m_registered);

    // LAZY FORWARD SERVICE HANDLING:
    // If this session was never registered (never received RegisterClient),
    // we must NOT close the forward_service. Closing an unregistered bsd:u
    // session causes a system freeze. Instead, we move it to an "abandoned"
    // list where it stays alive until the game process exits.
    if (!m_registered) {
        if (m_forward_service) {
            LOG_WARN("[BSD#%u] Session never registered - moving forward_service to abandoned list to prevent freeze",
                     m_session_id);
            std::scoped_lock lock(g_abandoned_services_mutex);
            g_abandoned_forward_services.push_back(std::move(m_forward_service));
            LOG_INFO("[BSD#%u] Abandoned services count: %zu", m_session_id, g_abandoned_forward_services.size());
        }
    }
    // For registered sessions, m_forward_service will be closed normally
    // when the base class destructor runs (shared_ptr goes out of scope)
}

/**
 * @brief Determine if we should MITM a process's BSD calls
 *
 * Atmosphere calls this for each process that opens bsd:u.
 * If we return true, our MITM service handles all their BSD calls.
 *
 * ## Strategy
 *
 * We intercept BSD sessions from applications that are in the LDN
 * game whitelist (fetched from Ryujinx server at startup), while
 * [ldn] enabled is set. System processes are never intercepted.
 *
 * @param client_info Process information (PID, program ID, etc.)
 * @return true For games in the whitelist when LDN is enabled, false otherwise
 */
bool BsdMitmService::ShouldMitm(const sm::MitmProcessInfo& client_info) {
    // Static counter to track all ShouldMitm calls for debugging
    static u32 s_call_count = 0;
    u32 call_id = ++s_call_count;

    LOG_INFO("BSD ShouldMitm #%u: ENTER pid=%lu, program_id=0x%016lx",
             call_id, client_info.process_id.value, client_info.program_id.value);

    // Our sysmodule's program_id - do not intercept ourselves
    constexpr u64 OUR_PROGRAM_ID = 0x4200000000000010ULL;

    // Skip our own sysmodule to avoid infinite recursion
    if (client_info.program_id.value == OUR_PROGRAM_ID) {
        LOG_INFO("BSD ShouldMitm #%u: SKIP (our sysmodule)", call_id);
        return false;
    }

    u64 program_id = client_info.program_id.value;

    // Skip non-applications (system services, applets, etc.).
    // System modules live at 0x0100000000000000-0x01000000000007FF and applets
    // at 0x0100000000001000+, all below ncm::ApplicationId::Start.
    if (!ncm::IsApplicationId(client_info.program_id)) {
        LOG_INFO("BSD ShouldMitm #%u: SKIP (system 0x%016lx)", call_id, program_id);
        return false;
    }

    // LDN emulation disabled: leave the game's sockets untouched
    if (!ryu_ldn::ipc::IsLdnEnabled()) {
        LOG_INFO("BSD ShouldMitm #%u: SKIP (LDN disabled)", call_id);
        return false;
    }

    // Is this game in the LDN whitelist?
    LOG_INFO("BSD ShouldMitm #%u: checking whitelist for 0x%016lx...", call_id, program_id);
    bool is_whitelisted = ryu_ldn::config::IsGameInWhitelist(program_id);
    LOG_INFO("BSD ShouldMitm #%u: whitelist result=%s", call_id, is_whitelisted ? "YES" : "NO");

    if (!is_whitelisted) {
        return false;
    }

    // Track session count and decide whether to intercept
    {
        std::scoped_lock lock(g_mitm_pids_mutex);
        u32& count = g_mitm_pid_count[client_info.process_id.value];
        count++;

        // Skip the first BSD session from each game process.
        // Games typically open a "dummy" first session that is never used
        // (no RegisterClient is ever called on it). Intercepting this session
        // causes system instability/crashes even if we try to handle it gracefully.
        // The actual networking happens on session #2+.
        if (count == 1) {
            LOG_INFO("BSD ShouldMitm #%u: SKIP first session for pid=%lu (dummy session)",
                     call_id, client_info.process_id.value);
            return false;
        }

        LOG_INFO("BSD ShouldMitm #%u: INTERCEPTING session #%u for pid=%lu",
                 call_id, count, client_info.process_id.value);
    }

    return true;
}

/**
 * @brief Clean up abandoned forward services
 *
 * Sessions that never received RegisterClient have their forward_service
 * moved to an abandoned list to prevent system freeze. This function
 * cleans up those services by closing them safely.
 *
 * Should be called when LDN disconnects or when the game process exits.
 */
void BsdMitmService::CleanupAbandonedServices() {
    std::scoped_lock lock(g_abandoned_services_mutex);

    if (g_abandoned_forward_services.empty()) {
        return;
    }

    LOG_INFO("BSD CleanupAbandonedServices: cleaning up %zu abandoned services",
             g_abandoned_forward_services.size());

    // Clear the vector - this will call serviceClose() on each service
    // We do this here (during LDN disconnect) rather than during session
    // destruction because it's safer to close these sessions when the
    // game is no longer actively using BSD.
    g_abandoned_forward_services.clear();

    LOG_INFO("BSD CleanupAbandonedServices: cleanup complete");
}

// =============================================================================
// Session Management Commands
// =============================================================================

/**
 * @brief Initialize BSD socket library for a client (Command 0)
 *
 * First command called by games to initialize the socket library.
 * This sets up buffer sizes and transfer memory for socket operations.
 *
 * ## IPC Interface (from switchbrew)
 *
 * ```
 * Input:
 *   [4] u32 config_size (should be 0x20 for LibraryConfigData)
 *   [0x21] Type-0x21 buffer (config data, auto-select)
 *   [0xA] Copy handle (transfer memory)
 *   ClientProcessId
 *
 * Output:
 *   [4] s32 errno (0 = success)
 * ```
 *
 * ## Transfer Memory
 *
 * The transfer_memory handle is a shared memory region used for socket
 * buffers. We must forward it to the real service as a copy handle.
 *
 * @param[out] out_errno BSD errno on failure (0 on success)
 * @param[in] config_size Size of config buffer (0x20 for LibraryConfigData)
 * @param[in] config LibraryConfigData with socket buffer settings
 * @param[in] client_pid Client's process ID
 * @param[in] transfer_memory Handle to transfer memory for buffers
 *
 * @return Result code from forwarding to real service
 */
Result BsdMitmService::RegisterClient(
    sf::Out<u64> out_result,
    const ryu_ldn::bsd::LibraryConfigData& config,
    const sf::ClientProcessId& client_pid,
    u64 tmem_size,
    sf::CopyHandle&& transfer_memory)
{
    m_command_count++;

    Handle tmem_handle = transfer_memory.GetOsHandle();
    LOG_INFO("[BSD#%u] RegisterClient ENTRY: cmd_count=%u, client_pid=%lu, tmem_size=%lu, tmem_handle=0x%x",
             m_session_id, m_command_count, client_pid.GetValue().value, tmem_size, tmem_handle);

    if (tmem_handle == INVALID_HANDLE) {
        LOG_ERROR("BSD RegisterClient: INVALID transfer memory handle!");
    }

    LOG_VERBOSE("BSD RegisterClient config: version=%u, tcp_tx=%u, tcp_rx=%u, udp_tx=%u, udp_rx=%u, sb_eff=%u",
                config.version, config.tcp_tx_buf_size, config.tcp_rx_buf_size,
                config.udp_tx_buf_size, config.udp_rx_buf_size, config.sb_efficiency);

    // According to libnx source (_bsdRegisterClient in bsd.c), format is:
    // - InRaw: [config 32 bytes][pid_placeholder 8 bytes = 0][tmem_sz 8 bytes] = 48 bytes
    // - CopyHandle: transfer_memory
    // - send_pid: true
    // - Output: u64 pid_out (not errno!)

    const struct {
        ryu_ldn::bsd::LibraryConfigData config;
        u64 pid_placeholder;  // Always 0
        u64 tmem_size;
    } forward_input = { config, 0, tmem_size };

    u64 pid_out = 0;

    Result rc = serviceMitmDispatchInOut(
        m_forward_service.get(), 0, forward_input, pid_out,
        .in_send_pid = true,
        .in_num_handles = 1,
        .in_handles = { tmem_handle },
        .override_pid = m_client_pid,
    );

    LOG_INFO("[BSD#%u] RegisterClient: forward returned rc=0x%x, pid_out=0x%lx",
             m_session_id, rc.GetValue(), pid_out);

    // Do not Detach() transfer_memory. The kernel gave this process its own
    // copy of the client's handle and the forward above copied it again into
    // the real bsd:u, so our copy must be closed; the managed sf::CopyHandle
    // does that when it goes out of scope. Keeping it open pins the client's
    // transfer memory, and with it the dead process, so the next application
    // launch blocks forever. Atmosphere-libs f32c8c5d fixes the same leak in
    // the automatic mitm forward path.

    // Mark this session as registered
    if (R_SUCCEEDED(rc)) {
        m_registered = true;
    }

    // Return the pid_out value from real service
    out_result.SetValue(pid_out);
    LOG_INFO("[BSD#%u] RegisterClient EXIT: returning rc=0x%x, pid_out=0x%lx, registered=%d", m_session_id, rc.GetValue(), pid_out, m_registered);
    R_RETURN(rc);
}

// =============================================================================
// Reply and Buffer Helpers
// =============================================================================

namespace {

namespace rb = ryu_ldn::bsd;

/// Fills the {ret, errno_} reply words from a result that is >= 0 or -errno.
Result Reply(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 result) {
    const rb::BsdReply reply = rb::MakeReply(result);
    out_ret.SetValue(reply.ret);
    out_errno.SetValue(reply.errno_);
    R_SUCCEED();
}

/// ProxySocket methods that return Result carry the errno as the value.
s32 ErrnoResult(Result rc) {
    return R_SUCCEEDED(rc) ? 0 : -static_cast<s32>(rc.GetValue());
}

/// Hands the untouched request to the real service (Atmosphere replays it).
Result ForwardToRealService() {
    R_THROW(sm::mitm::ResultShouldForwardToSession());
}

/// Copies an IPv4 sockaddr out of an IPC buffer. The buffer may be
/// misaligned, so the address is always read through an aligned copy.
bool ReadSockAddrIn(const sf::InAutoSelectBuffer& buf, rb::SockAddrIn* out) {
    if (buf.GetPointer() == nullptr || buf.GetSize() < sizeof(*out)) {
        return false;
    }
    std::memcpy(out, buf.GetPointer(), sizeof(*out));
    return out->sin_family == static_cast<u8>(rb::AddressFamily::Inet);
}

/// Writes an address to the game's buffer and returns the length to report.
u32 WriteSockAddrIn(sf::OutAutoSelectBuffer& buf, const rb::SockAddrIn& addr) {
    const size_t n = std::min(buf.GetSize(), sizeof(addr));
    if (n > 0) {
        std::memcpy(buf.GetPointer(), &addr, n);
    }
    return sizeof(addr);
}

bool IsProxyFd(u64 key) {
    std::scoped_lock lock(g_socket_info_mutex);
    auto it = g_socket_info.find(key);
    return it != g_socket_info.end() && it->second.is_proxy;
}

void MarkProxy(u64 key) {
    std::scoped_lock lock(g_socket_info_mutex);
    auto it = g_socket_info.find(key);
    if (it != g_socket_info.end()) {
        it->second.is_proxy = true;
    }
}

/// Applies a change to the tracked info of fd, if it is tracked.
template<typename F>
void UpdateSocketInfo(u64 key, F update) {
    std::scoped_lock lock(g_socket_info_mutex);
    auto it = g_socket_info.find(key);
    if (it != g_socket_info.end()) {
        update(it->second);
    }
}

bool GetSocketInfo(u64 key, SocketInfo* out) {
    std::scoped_lock lock(g_socket_info_mutex);
    auto it = g_socket_info.find(key);
    if (it == g_socket_info.end()) {
        return false;
    }
    *out = it->second;
    return true;
}

/// Creates the proxy for fd and carries over the options the game set on the
/// socket before it became a proxy (fcntl/ioctl/setsockopt arrive first).
std::shared_ptr<ProxySocket> CreateProxy(ProxySocketManager& manager, u64 key, const SocketInfo& info) {
    auto proxy = manager.CreateProxySocket(key, info.type, info.protocol);
    if (proxy != nullptr) {
        proxy->SetBroadcastEnabled(info.broadcast);
        proxy->SetNonBlocking(info.non_blocking);
        proxy->SetRecvTimeout(info.rcv_timeout_ns);
    }
    return proxy;
}

/// Creates key's proxy bound to addr (port 0 picks an ephemeral port) and
/// marks the fd as a proxy. On failure nothing is left behind: the proxy is
/// closed and its port released. Returns 0 or -errno.
s32 CreateBoundProxy(ProxySocketManager& manager, u64 key, const SocketInfo& info,
                     rb::SockAddrIn addr, std::shared_ptr<ProxySocket>* out) {
    if (manager.GetProxySocket(key) != nullptr) {
        return -static_cast<s32>(rb::BsdErrno::Inval);  // already bound
    }
    auto proxy = CreateProxy(manager, key, info);
    if (proxy == nullptr) {
        return -static_cast<s32>(rb::BsdErrno::NoMem);
    }

    uint16_t port = addr.GetPort();
    if (port == 0) {
        port = manager.AllocatePort(info.protocol);
        if (port == 0) {
            manager.CloseProxySocket(key);
            return -static_cast<s32>(rb::BsdErrno::AddrInUse);
        }
        addr.sin_port = __builtin_bswap16(port);
    } else if (!manager.ReservePort(port, info.protocol)) {
        manager.CloseProxySocket(key);
        return -static_cast<s32>(rb::BsdErrno::AddrInUse);
    }

    const s32 result = ErrnoResult(proxy->Bind(addr));
    if (result < 0) {
        manager.ReleasePort(port, info.protocol);  // unbound, so Close won't
        manager.CloseProxySocket(key);
        return result;
    }

    MarkProxy(key);
    *out = std::move(proxy);
    return 0;
}

/// The address an implicit bind (connect/sendto on an unbound fd) uses.
rb::SockAddrIn SessionAddr(ProxySocketManager& manager) {
    rb::SockAddrIn addr{};
    addr.sin_len = sizeof(addr);
    addr.sin_family = static_cast<u8>(rb::AddressFamily::Inet);
    addr.sin_addr = __builtin_bswap32(manager.GetLocalIp());  // network order
    return addr;
}

rb::ProtocolType DefaultProtocol(s32 type, s32 protocol) {
    if (protocol != 0) {
        return static_cast<rb::ProtocolType>(protocol);
    }
    if (type == static_cast<s32>(rb::SocketType::Stream)) {
        return rb::ProtocolType::Tcp;
    }
    if (type == static_cast<s32>(rb::SocketType::Dgram)) {
        return rb::ProtocolType::Udp;
    }
    return rb::ProtocolType::Unspecified;
}

/// Forwards Socket/SocketExempt by hand so the new fd can be tracked.
Result ForwardSocketCreate(::Service* srv, u32 cmd_id, u32 session_id,
                           sf::Out<s32> out_ret, sf::Out<s32> out_errno,
                           s32 domain, s32 type, s32 protocol) {
    const struct { s32 domain; s32 type; s32 protocol; } in = { domain, type, protocol };
    rb::BsdReply out{};
    R_TRY(serviceMitmDispatchInOut(srv, cmd_id, in, out));

    out_ret.SetValue(out.ret);
    out_errno.SetValue(out.errno_);
    LOG_INFO("[BSD#%u] Socket(cmd %u): fd=%d errno=%d", session_id, cmd_id, out.ret, out.ret < 0 ? out.errno_ : 0);

    if (out.ret >= 0) {
        std::scoped_lock lock(g_socket_info_mutex);
        const s32 base_type = type & rb::SOCK_TYPE_MASK;
        g_socket_info[rb::SocketKey(session_id, out.ret)] = SocketInfo{
            .type = static_cast<rb::SocketType>(base_type),
            .protocol = DefaultProtocol(base_type, protocol),
            .is_proxy = false,
            .broadcast = false,
            .non_blocking = (type & rb::SOCK_FLAG_NONBLOCK) != 0,
            .rcv_timeout_ns = 0,
            .session_id = session_id,
        };
    }
    R_SUCCEED();
}

} // namespace

// =============================================================================
// Socket Lifecycle Commands
// =============================================================================

Result BsdMitmService::Socket(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 domain, s32 type, s32 protocol) {
    m_command_count++;
    R_RETURN(ForwardSocketCreate(m_forward_service.get(), 2, m_session_id, out_ret, out_errno, domain, type, protocol));
}

Result BsdMitmService::SocketExempt(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 domain, s32 type, s32 protocol) {
    m_command_count++;
    R_RETURN(ForwardSocketCreate(m_forward_service.get(), 3, m_session_id, out_ret, out_errno, domain, type, protocol));
}

Result BsdMitmService::Close(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd) {
    AMS_UNUSED(out_ret, out_errno);
    m_command_count++;

    {
        std::scoped_lock lock(g_socket_info_mutex);
        g_socket_info.erase(Key(fd));
    }
    if (ProxySocketManager::GetInstance().CloseProxySocket(Key(fd))) {
        LOG_INFO("[BSD#%u] Close fd=%d closed LDN proxy socket", m_session_id, fd);
    }

    // The real fd exists too; close it there.
    R_RETURN(ForwardToRealService());
}

// =============================================================================
// Address Operations (LDN Detection Points)
// =============================================================================

Result BsdMitmService::Bind(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer& addr) {
    m_command_count++;

    rb::SockAddrIn sock_addr;
    if (!ReadSockAddrIn(addr, &sock_addr)) {
        R_RETURN(ForwardToRealService());
    }

    LOG_INFO("[BSD#%u] Bind fd=%d addr=%u.%u.%u.%u:%u", m_session_id, fd,
             (sock_addr.sin_addr >> 0) & 0xFF, (sock_addr.sin_addr >> 8) & 0xFF,
             (sock_addr.sin_addr >> 16) & 0xFF, (sock_addr.sin_addr >> 24) & 0xFF,
             sock_addr.GetPort());

    auto& manager = ProxySocketManager::GetInstance();
    const bool is_inaddr_any = (sock_addr.sin_addr == 0);
    SocketInfo socket_info;
    if (!rb::IsProxyBind(sock_addr.GetAddr(), manager.GetLocalIp() != 0) || !GetSocketInfo(Key(fd), &socket_info)) {
        R_RETURN(ForwardToRealService());
    }

    rb::SockAddrIn bind_addr = sock_addr;
    if (is_inaddr_any) {
        // sin_addr is network order; the manager keeps the Ryujinx format.
        bind_addr.sin_addr = __builtin_bswap32(manager.GetLocalIp());
    }

    std::shared_ptr<ProxySocket> proxy;
    const s32 bind_result = CreateBoundProxy(manager, Key(fd), socket_info, bind_addr, &proxy);
    if (bind_result < 0) {
        LOG_ERROR("[BSD#%u] Bind fd=%d proxy bind failed: errno=%d", m_session_id, fd, -bind_result);
        R_RETURN(Reply(out_ret, out_errno, bind_result));
    }

    LOG_INFO("[BSD#%u] Bind fd=%d bound to LDN proxy port %u", m_session_id, fd, proxy->GetLocalAddr().GetPort());
    manager.DeliverPendingPackets(proxy.get(), proxy->GetLocalAddr().GetPort(), socket_info.protocol);

    // INADDR_ANY binds also bind the real socket so non-LDN traffic still works.
    if (is_inaddr_any) {
        rb::BsdReply real{};
        const Result real_rc = serviceMitmDispatchInOut(
            m_forward_service.get(), 13, fd, real,
            .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcAutoSelect },
            .buffers = { { addr.GetPointer(), addr.GetSize() } },
        );
        if (R_FAILED(real_rc) || real.ret < 0) {
            LOG_WARN("[BSD#%u] Bind fd=%d real bind failed (rc=0x%x, errno=%d), proxy-only",
                     m_session_id, fd, real_rc.GetValue(), real.errno_);
        }
    }

    R_RETURN(Reply(out_ret, out_errno, 0));
}

Result BsdMitmService::Connect(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer& addr) {
    m_command_count++;

    rb::SockAddrIn sock_addr;
    SocketInfo socket_info;
    if (!ReadSockAddrIn(addr, &sock_addr) || !sock_addr.IsLdnAddress() || !GetSocketInfo(Key(fd), &socket_info)) {
        R_RETURN(ForwardToRealService());
    }

    LOG_INFO("[BSD#%u] Connect fd=%d to LDN port %u", m_session_id, fd, sock_addr.GetPort());

    auto& manager = ProxySocketManager::GetInstance();
    auto proxy = manager.GetProxySocket(Key(fd));
    const bool created = (proxy == nullptr);
    if (created) {
        const s32 bind_result = CreateBoundProxy(manager, Key(fd), socket_info, SessionAddr(manager), &proxy);
        if (bind_result < 0) {
            R_RETURN(Reply(out_ret, out_errno, bind_result));
        }
    }

    const s32 connect_result = ErrnoResult(proxy->Connect(sock_addr));
    if (connect_result < 0) {
        LOG_ERROR("[BSD#%u] Connect fd=%d proxy connect failed: errno=%d", m_session_id, fd, -connect_result);
        if (created) {
            // Leave the fd as it was before connect().
            UpdateSocketInfo(Key(fd), [](SocketInfo& info) { info.is_proxy = false; });
            manager.CloseProxySocket(Key(fd));
        }
        R_RETURN(Reply(out_ret, out_errno, connect_result));
    }

    MarkProxy(Key(fd));
    R_RETURN(Reply(out_ret, out_errno, 0));
}

Result BsdMitmService::Accept(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_addrlen, s32 fd, sf::OutAutoSelectBuffer addr_out) {
    AMS_UNUSED(out_ret, out_errno, out_addrlen, fd, addr_out);
    m_command_count++;
    R_RETURN(ForwardToRealService());
}

Result BsdMitmService::Listen(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 backlog) {
    AMS_UNUSED(out_ret, out_errno, fd, backlog);
    m_command_count++;
    R_RETURN(ForwardToRealService());
}

Result BsdMitmService::GetPeerName(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_addrlen, s32 fd, sf::OutAutoSelectBuffer addr_out) {
    m_command_count++;

    auto proxy = ProxySocketManager::GetInstance().GetProxySocket(Key(fd));
    if (proxy == nullptr) {
        R_RETURN(ForwardToRealService());
    }

    rb::SockAddrIn peer;
    const s32 result = ErrnoResult(proxy->GetPeerName(&peer));
    out_addrlen.SetValue(result < 0 ? 0 : WriteSockAddrIn(addr_out, peer));
    R_RETURN(Reply(out_ret, out_errno, result));
}

Result BsdMitmService::GetSockName(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_addrlen, s32 fd, sf::OutAutoSelectBuffer addr_out) {
    m_command_count++;

    auto proxy = ProxySocketManager::GetInstance().GetProxySocket(Key(fd));
    if (proxy == nullptr) {
        R_RETURN(ForwardToRealService());
    }

    rb::SockAddrIn local;
    const s32 result = ErrnoResult(proxy->GetSockName(&local));
    out_addrlen.SetValue(result < 0 ? 0 : WriteSockAddrIn(addr_out, local));
    R_RETURN(Reply(out_ret, out_errno, result));
}

// =============================================================================
// Data Transfer Commands (LDN Proxy Points)
// =============================================================================

Result BsdMitmService::Send(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 flags, const sf::InAutoSelectBuffer& buffer) {
    m_command_count++;

    auto proxy = IsProxyFd(Key(fd)) ? ProxySocketManager::GetInstance().GetProxySocket(Key(fd)) : nullptr;
    if (proxy == nullptr) {
        R_RETURN(ForwardToRealService());
    }
    R_RETURN(Reply(out_ret, out_errno, proxy->Send(buffer.GetPointer(), buffer.GetSize(), flags)));
}

Result BsdMitmService::Write(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer& buffer) {
    m_command_count++;

    auto proxy = IsProxyFd(Key(fd)) ? ProxySocketManager::GetInstance().GetProxySocket(Key(fd)) : nullptr;
    if (proxy == nullptr) {
        R_RETURN(ForwardToRealService());
    }
    R_RETURN(Reply(out_ret, out_errno, proxy->Send(buffer.GetPointer(), buffer.GetSize(), 0)));
}

Result BsdMitmService::SendTo(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 flags,
                              const sf::InAutoSelectBuffer& buffer, const sf::InAutoSelectBuffer& addr) {
    m_command_count++;

    rb::SockAddrIn dest;
    const bool has_dest = ReadSockAddrIn(addr, &dest);
    SocketInfo socket_info;
    const bool found = GetSocketInfo(Key(fd), &socket_info);
    bool is_proxy = found && socket_info.is_proxy;
    auto& manager = ProxySocketManager::GetInstance();

    // First send to an LDN address from an unbound socket: auto-bind a proxy.
    if (has_dest && dest.IsLdnAddress() && found && !socket_info.is_proxy) {
        std::shared_ptr<ProxySocket> created;
        const s32 bind_result = CreateBoundProxy(manager, Key(fd), socket_info, SessionAddr(manager), &created);
        if (bind_result < 0) {
            R_RETURN(Reply(out_ret, out_errno, bind_result));
        }
        is_proxy = true;
    }

    // Internet destinations use the real socket even on a proxied fd (an
    // INADDR_ANY proxy is bound on the real side too).
    if (!is_proxy || (has_dest && !rb::IsProxyDestination(dest.GetAddr()))) {
        R_RETURN(ForwardToRealService());
    }

    auto proxy = manager.GetProxySocket(Key(fd));
    if (proxy == nullptr) {
        // The real socket can't reach LDN addresses.
        R_RETURN(Reply(out_ret, out_errno, -static_cast<s32>(rb::BsdErrno::NetUnreach)));
    }
    if (!has_dest) {
        // sendto() without an address on a connected socket is send().
        R_RETURN(Reply(out_ret, out_errno, proxy->Send(buffer.GetPointer(), buffer.GetSize(), flags)));
    }
    R_RETURN(Reply(out_ret, out_errno, proxy->SendTo(buffer.GetPointer(), buffer.GetSize(), flags, dest)));
}

Result BsdMitmService::Recv(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 flags, sf::OutAutoSelectBuffer buffer) {
    m_command_count++;

    auto proxy = IsProxyFd(Key(fd)) ? ProxySocketManager::GetInstance().GetProxySocket(Key(fd)) : nullptr;
    if (proxy == nullptr) {
        R_RETURN(ForwardToRealService());
    }
    R_RETURN(Reply(out_ret, out_errno, proxy->Recv(buffer.GetPointer(), buffer.GetSize(), flags)));
}

Result BsdMitmService::Read(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, sf::OutAutoSelectBuffer buffer) {
    m_command_count++;

    auto proxy = IsProxyFd(Key(fd)) ? ProxySocketManager::GetInstance().GetProxySocket(Key(fd)) : nullptr;
    if (proxy == nullptr) {
        R_RETURN(ForwardToRealService());
    }
    R_RETURN(Reply(out_ret, out_errno, proxy->Recv(buffer.GetPointer(), buffer.GetSize(), 0)));
}

Result BsdMitmService::RecvFrom(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_addrlen,
                                s32 fd, s32 flags, sf::OutAutoSelectBuffer buffer, sf::OutAutoSelectBuffer addr_out) {
    m_command_count++;

    auto proxy = IsProxyFd(Key(fd)) ? ProxySocketManager::GetInstance().GetProxySocket(Key(fd)) : nullptr;
    if (proxy == nullptr) {
        R_RETURN(ForwardToRealService());
    }

    rb::SockAddrIn from{};
    const s32 result = proxy->RecvFrom(buffer.GetPointer(), buffer.GetSize(), flags, &from);
    out_addrlen.SetValue(result < 0 ? 0 : WriteSockAddrIn(addr_out, from));
    R_RETURN(Reply(out_ret, out_errno, result));
}

// =============================================================================
// Readiness (Select / Poll)
// =============================================================================

namespace {

bool FdIsSet(s32 fd, const void* fds, size_t size) {
    const size_t byte = static_cast<size_t>(fd) / 8;
    return fds != nullptr && fd >= 0 && byte < size &&
           (static_cast<const u8*>(fds)[byte] & (1u << (fd % 8))) != 0;
}

void FdSet(s32 fd, void* fds, size_t size) {
    const size_t byte = static_cast<size_t>(fd) / 8;
    if (fds != nullptr && fd >= 0 && byte < size) {
        static_cast<u8*>(fds)[byte] |= static_cast<u8>(1u << (fd % 8));
    }
}

/// Proxy readiness for select(); returns the number of bits set.
s32 SelectProxies(u32 session_id, s32 nfds,
                  const sf::InAutoSelectBuffer& rd_in, const sf::InAutoSelectBuffer& wr_in, const sf::InAutoSelectBuffer& er_in,
                  sf::OutAutoSelectBuffer& rd_out, sf::OutAutoSelectBuffer& wr_out, sf::OutAutoSelectBuffer& er_out,
                  bool* has_proxy, bool* has_real) {
    auto& manager = ProxySocketManager::GetInstance();
    s32 ready = 0;
    for (s32 fd = 0; fd < nfds; fd++) {
        const bool r = FdIsSet(fd, rd_in.GetPointer(), rd_in.GetSize());
        const bool w = FdIsSet(fd, wr_in.GetPointer(), wr_in.GetSize());
        const bool e = FdIsSet(fd, er_in.GetPointer(), er_in.GetSize());
        if (!r && !w && !e) {
            continue;
        }
        auto proxy = manager.GetProxySocket(rb::SocketKey(session_id, fd));
        if (proxy == nullptr) {
            *has_real = true;
            continue;
        }
        *has_proxy = true;
        if (r && proxy->HasPendingData()) {
            FdSet(fd, rd_out.GetPointer(), rd_out.GetSize());
            ready++;
        }
        if (w) {
            FdSet(fd, wr_out.GetPointer(), wr_out.GetSize());
            ready++;
        }
        if (e && proxy->GetState() == ProxySocketState::Closed) {
            FdSet(fd, er_out.GetPointer(), er_out.GetSize());
            ready++;
        }
    }
    return ready;
}

/// Proxy readiness for poll(); sets revents and returns the number of ready entries.
s32 PollProxies(u32 session_id, rb::PollFd* fds, size_t count, bool* has_proxy, bool* has_real) {
    auto& manager = ProxySocketManager::GetInstance();
    s32 ready = 0;
    for (size_t i = 0; i < count; i++) {
        auto proxy = manager.GetProxySocket(rb::SocketKey(session_id, fds[i].fd));
        if (proxy == nullptr) {
            *has_real = true;
            continue;
        }
        *has_proxy = true;
        s16 revents = 0;
        if ((fds[i].events & static_cast<s16>(rb::PollEvents::In)) && proxy->HasPendingData()) {
            revents |= static_cast<s16>(rb::PollEvents::In);
        }
        if (fds[i].events & static_cast<s16>(rb::PollEvents::Out)) {
            revents |= static_cast<s16>(rb::PollEvents::Out);
        }
        if (proxy->GetState() == ProxySocketState::Closed) {
            revents |= static_cast<s16>(rb::PollEvents::Hup);
        }
        fds[i].revents = revents;
        if (revents != 0) {
            ready++;
        }
    }
    return ready;
}

} // namespace

Result BsdMitmService::Select(sf::Out<s32> out_ret, sf::Out<s32> out_errno,
                              s32 nfds, const rb::SelectTimeval& timeout,
                              const sf::InAutoSelectBuffer& readfds_in,
                              const sf::InAutoSelectBuffer& writefds_in,
                              const sf::InAutoSelectBuffer& errorfds_in,
                              sf::OutAutoSelectBuffer readfds_out,
                              sf::OutAutoSelectBuffer writefds_out,
                              sf::OutAutoSelectBuffer errorfds_out) {
    m_command_count++;

    for (auto* out : { &readfds_out, &writefds_out, &errorfds_out }) {
        if (out->GetSize() > 0) {
            std::memset(out->GetPointer(), 0, out->GetSize());
        }
    }

    bool has_proxy = false;
    bool has_real = false;
    const s32 ready = SelectProxies(m_session_id, nfds, readfds_in, writefds_in, errorfds_in,
                                    readfds_out, writefds_out, errorfds_out, &has_proxy, &has_real);
    if (!has_proxy) {
        R_RETURN(ForwardToRealService());
    }
    if (!has_real || ready > 0) {
        R_RETURN(Reply(out_ret, out_errno, ready));
    }

    const struct { s32 nfds; u32 pad; rb::SelectTimeval timeout; } in = { nfds, 0, timeout };
    rb::BsdReply out{};
    R_TRY(serviceMitmDispatchInOut(
        m_forward_service.get(), 5, in, out,
        .buffer_attrs = {
            SfBufferAttr_In | SfBufferAttr_HipcAutoSelect,
            SfBufferAttr_In | SfBufferAttr_HipcAutoSelect,
            SfBufferAttr_In | SfBufferAttr_HipcAutoSelect,
            SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect,
            SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect,
            SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect,
        },
        .buffers = {
            { readfds_in.GetPointer(), readfds_in.GetSize() },
            { writefds_in.GetPointer(), writefds_in.GetSize() },
            { errorfds_in.GetPointer(), errorfds_in.GetSize() },
            { readfds_out.GetPointer(), readfds_out.GetSize() },
            { writefds_out.GetPointer(), writefds_out.GetSize() },
            { errorfds_out.GetPointer(), errorfds_out.GetSize() },
        },
    ));
    if (out.ret < 0) {
        out_ret.SetValue(out.ret);
        out_errno.SetValue(out.errno_);
        R_SUCCEED();
    }
    has_proxy = has_real = false;
    const s32 proxy_ready = SelectProxies(m_session_id, nfds, readfds_in, writefds_in, errorfds_in,
                                          readfds_out, writefds_out, errorfds_out, &has_proxy, &has_real);
    R_RETURN(Reply(out_ret, out_errno, out.ret + proxy_ready));
}

Result BsdMitmService::Poll(sf::Out<s32> out_ret, sf::Out<s32> out_errno,
                            const sf::InAutoSelectBuffer& fds_in, sf::OutAutoSelectBuffer fds_out,
                            s32 nfds, s32 timeout) {
    m_command_count++;

    const size_t count = std::min({ static_cast<size_t>(std::max(nfds, 0)),
                                    fds_in.GetSize() / sizeof(rb::PollFd),
                                    fds_out.GetSize() / sizeof(rb::PollFd) });
    if (count > 0) {
        std::memcpy(fds_out.GetPointer(), fds_in.GetPointer(), count * sizeof(rb::PollFd));
    }
    auto* poll_fds = reinterpret_cast<rb::PollFd*>(fds_out.GetPointer());

    bool has_proxy = false;
    bool has_real = false;
    const s32 ready = PollProxies(m_session_id, poll_fds, count, &has_proxy, &has_real);
    if (!has_proxy) {
        R_RETURN(ForwardToRealService());
    }
    if (!has_real || ready > 0) {
        R_RETURN(Reply(out_ret, out_errno, ready));
    }

    const struct { s32 nfds; s32 timeout; } in = { nfds, timeout };
    rb::BsdReply out{};
    R_TRY(serviceMitmDispatchInOut(
        m_forward_service.get(), 6, in, out,
        .buffer_attrs = {
            SfBufferAttr_In | SfBufferAttr_HipcAutoSelect,
            SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect,
        },
        .buffers = {
            { fds_in.GetPointer(), fds_in.GetSize() },
            { fds_out.GetPointer(), fds_out.GetSize() },
        },
    ));
    if (out.ret < 0) {
        out_ret.SetValue(out.ret);
        out_errno.SetValue(out.errno_);
        R_SUCCEED();
    }
    has_proxy = has_real = false;
    const s32 proxy_ready = PollProxies(m_session_id, poll_fds, count, &has_proxy, &has_real);
    R_RETURN(Reply(out_ret, out_errno, out.ret + proxy_ready));
}

// =============================================================================
// Socket Control Commands
// =============================================================================

Result BsdMitmService::Ioctl(sf::Out<s32> out_ret, sf::Out<s32> out_errno,
                             s32 fd, u32 request, u32 bufcount,
                             const sf::InAutoSelectBuffer& in1, const sf::InAutoSelectBuffer& in2,
                             const sf::InAutoSelectBuffer& in3, const sf::InAutoSelectBuffer& in4,
                             sf::OutAutoSelectBuffer out1, sf::OutAutoSelectBuffer out2,
                             sf::OutAutoSelectBuffer out3, sf::OutAutoSelectBuffer out4) {
    AMS_UNUSED(bufcount, in2, in3, in4, out2, out3, out4);
    m_command_count++;

    auto proxy = ProxySocketManager::GetInstance().GetProxySocket(Key(fd));

    if (request == static_cast<u32>(rb::IoctlRequest::FioNbio) && in1.GetSize() >= sizeof(s32)) {
        // Record it for a proxy created later, then let the real fd see it too.
        s32 value;
        std::memcpy(&value, in1.GetPointer(), sizeof(value));
        UpdateSocketInfo(Key(fd), [&](SocketInfo& info) { info.non_blocking = (value != 0); });
        if (proxy != nullptr) {
            proxy->SetNonBlocking(value != 0);
        }
        R_RETURN(ForwardToRealService());
    }

    if (proxy != nullptr && request == static_cast<u32>(rb::IoctlRequest::FioNread)) {
        const s32 pending = static_cast<s32>(proxy->GetPendingDataSize());
        if (out1.GetSize() >= sizeof(s32)) {
            std::memcpy(out1.GetPointer(), &pending, sizeof(pending));
        }
        R_RETURN(Reply(out_ret, out_errno, 0));
    }
    R_RETURN(ForwardToRealService());
}

Result BsdMitmService::Fcntl(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 cmd, s32 arg) {
    AMS_UNUSED(out_ret, out_errno);
    m_command_count++;

    // F_SETFL is recorded (for a proxy created later) and applied to an
    // existing proxy, then forwarded so the real fd keeps the same flags and
    // F_GETFL can always be answered by the real service.
    if (cmd == static_cast<s32>(rb::FcntlCommand::SetFl)) {
        const bool non_blocking = (arg & static_cast<s32>(rb::FileStatusFlags::NonBlock)) != 0;
        UpdateSocketInfo(Key(fd), [&](SocketInfo& info) { info.non_blocking = non_blocking; });
        if (auto proxy = ProxySocketManager::GetInstance().GetProxySocket(Key(fd)); proxy != nullptr) {
            proxy->SetNonBlocking(non_blocking);
        }
    }
    R_RETURN(ForwardToRealService());
}

Result BsdMitmService::GetSockOpt(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_optlen,
                                  s32 fd, s32 level, s32 optname, sf::OutAutoSelectBuffer optval) {
    m_command_count++;

    auto proxy = ProxySocketManager::GetInstance().GetProxySocket(Key(fd));
    if (proxy == nullptr) {
        R_RETURN(ForwardToRealService());
    }

    size_t optlen = optval.GetSize();
    const s32 result = ErrnoResult(proxy->GetSockOpt(level, optname, optval.GetPointer(), &optlen));
    out_optlen.SetValue(result < 0 ? 0 : static_cast<u32>(optlen));
    R_RETURN(Reply(out_ret, out_errno, result));
}

Result BsdMitmService::SetSockOpt(sf::Out<s32> out_ret, sf::Out<s32> out_errno,
                                  s32 fd, s32 level, s32 optname, const sf::InAutoSelectBuffer& optval) {
    m_command_count++;

    // Remember SO_BROADCAST and SO_RCVTIMEO for a proxy created later by
    // Bind/Connect/SendTo.
    if (level == static_cast<s32>(rb::SocketOptionLevel::Socket)) {
        if (optname == static_cast<s32>(rb::SocketOption::Broadcast) && optval.GetSize() >= sizeof(s32)) {
            s32 value;
            std::memcpy(&value, optval.GetPointer(), sizeof(value));
            UpdateSocketInfo(Key(fd), [&](SocketInfo& info) { info.broadcast = (value != 0); });
        } else if (optname == static_cast<s32>(rb::SocketOption::RcvTimeo) && optval.GetSize() >= sizeof(rb::Timeval)) {
            rb::Timeval tv;
            std::memcpy(&tv, optval.GetPointer(), sizeof(tv));
            UpdateSocketInfo(Key(fd), [&](SocketInfo& info) { info.rcv_timeout_ns = rb::TimevalToNanoseconds(tv); });
        }
    }

    auto proxy = ProxySocketManager::GetInstance().GetProxySocket(Key(fd));
    if (proxy != nullptr) {
        R_RETURN(Reply(out_ret, out_errno, ErrnoResult(proxy->SetSockOpt(level, optname, optval.GetPointer(), optval.GetSize()))));
    }
    R_RETURN(ForwardToRealService());
}

Result BsdMitmService::Shutdown(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 how) {
    m_command_count++;

    // shutdown() is how a game unblocks a receiver, so it must reach the proxy.
    auto proxy = ProxySocketManager::GetInstance().GetProxySocket(Key(fd));
    if (proxy == nullptr) {
        R_RETURN(ForwardToRealService());
    }
    R_RETURN(Reply(out_ret, out_errno, ErrnoResult(proxy->Shutdown(static_cast<rb::ShutdownHow>(how)))));
}

/**
 * @brief Initialize BSD socket library (shared memory variant) (Command 33)
 *
 * Same as RegisterClient but the work-buffer is allocated in the sysmodule's
 * memory instead of using TransferMemory from the client. Available from 10.0.0+.
 *
 * ## IPC Interface (from switchbrew)
 *
 * Same input/output as RegisterClient except this doesn't take an input handle.
 * Output: s32 bsd_errno (0 on success)
 *
 * @param[out] out_errno BSD errno on failure (0 on success)
 * @param[in] config LibraryConfigData with socket buffer settings
 * @param[in] client_pid Client's process ID
 * @param[in] tmem_size Size for work buffer
 *
 * @return Result code from forwarding to real service
 */
Result BsdMitmService::RegisterClientShared(
    sf::Out<u64> out_result,
    const ryu_ldn::bsd::LibraryConfigData& config,
    const sf::ClientProcessId& client_pid,
    u64 tmem_size)
{
    m_command_count++;

    LOG_INFO("[BSD#%u] RegisterClientShared ENTRY: cmd_count=%u, client_pid=%lu, tmem_size=%lu",
             m_session_id, m_command_count, client_pid.GetValue().value, tmem_size);

    LOG_VERBOSE("BSD RegisterClientShared config: version=%u, tcp_tx=%u, tcp_rx=%u, udp_tx=%u, udp_rx=%u, sb_eff=%u",
                config.version, config.tcp_tx_buf_size, config.tcp_rx_buf_size,
                config.udp_tx_buf_size, config.udp_rx_buf_size, config.sb_efficiency);

    // Same format as RegisterClient but without the CopyHandle.
    // InRaw: [config 32 bytes][pid_placeholder 8 bytes = 0][tmem_size 8 bytes] = 48 bytes
    const struct {
        ryu_ldn::bsd::LibraryConfigData config;
        u64 pid_placeholder;
        u64 tmem_size;
    } forward_input = { config, 0, tmem_size };

    u64 pid_out = 0;

    Result rc = serviceMitmDispatchInOut(
        m_forward_service.get(), 33, forward_input, pid_out,
        .in_send_pid = true,
        .override_pid = m_client_pid,
    );

    LOG_INFO("[BSD#%u] RegisterClientShared: forward returned rc=0x%x, pid_out=0x%lx",
             m_session_id, rc.GetValue(), pid_out);

    // Mark this session as registered
    if (R_SUCCEEDED(rc)) {
        m_registered = true;
    }

    out_result.SetValue(pid_out);
    R_RETURN(rc);
}


} // namespace ams::mitm::bsd
