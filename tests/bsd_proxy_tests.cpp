/**
 * @file bsd_proxy_tests.cpp
 * @brief Unit tests for the bsd:u intercept: reply layout and proxy sockets
 *
 * Everything here calls the real sysmodule code. bsd_types.hpp is a plain
 * header; the proxy sources build on the host against the small
 * <stratosphere.hpp> stand-in in tests/host_shim/.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <chrono>
#include <thread>
#include <cstring>
#include <atomic>
#include <unistd.h>

#include "bsd/bsd_types.hpp"
#include "bsd/proxy_socket.hpp"
#include "bsd/proxy_socket_manager.hpp"
#include "bsd/packet_ring.hpp"

// ============================================================================
// Test Framework (minimal)
// ============================================================================

static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST(name) \
    static void test_##name(); \
    static struct test_##name##_register { \
        test_##name##_register() { \
            printf("  [TEST] %s... ", #name); \
            fflush(stdout); \
            int failed_before = g_tests_failed; \
            test_##name(); \
            if (g_tests_failed == failed_before) { \
                printf("PASS\n"); \
                g_tests_passed++; \
            } \
        } \
    } test_##name##_instance; \
    static void test_##name()

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            printf("FAIL\n    Assertion failed: %s\n    at %s:%d\n", #cond, __FILE__, __LINE__); \
            g_tests_failed++; \
            return; \
        } \
    } while(0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))
#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))

namespace rb = ryu_ldn::bsd;
using ams::mitm::bsd::ProxySocket;
using ams::mitm::bsd::ProxySocketManager;

namespace {

constexpr int32_t kEAgain = static_cast<int32_t>(rb::BsdErrno::Again);
constexpr int32_t kEBadF = static_cast<int32_t>(rb::BsdErrno::BadF);

/// A sockaddr as the game passes it: port and address in network order.
rb::SockAddrIn Addr(uint32_t ip, uint16_t port) {
    rb::SockAddrIn a{};
    a.sin_len = sizeof(a);
    a.sin_family = static_cast<uint8_t>(rb::AddressFamily::Inet);
    a.sin_port = __builtin_bswap16(port);
    a.sin_addr = __builtin_bswap32(ip);
    return a;
}

rb::SockAddrIn LdnAddr(uint16_t port) { return Addr(0x0A720001, port); }

/// A bound UDP proxy socket, as Bind leaves it.
std::unique_ptr<ProxySocket> BoundUdp() {
    auto s = std::make_unique<ProxySocket>(rb::SocketType::Dgram, rb::ProtocolType::Udp);
    s->Bind(LdnAddr(12345));
    return s;
}

void SetRecvTimeoutMs(ProxySocket& s, int64_t ms) {
    const rb::Timeval tv{ ms / 1000, (ms % 1000) * 1000 };
    s.SetSockOpt(static_cast<int32_t>(rb::SocketOptionLevel::Socket),
                 static_cast<int32_t>(rb::SocketOption::RcvTimeo), &tv, sizeof(tv));
}

int64_t ElapsedMs(std::chrono::steady_clock::time_point start) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
}

/// Runs RecvFrom on another thread; returns its result once it finishes.
struct BlockedReceiver {
    ProxySocket& socket;
    int32_t result = 1;
    std::thread thread;
    explicit BlockedReceiver(ProxySocket& s) : socket(s), thread([this] {
        char buf[64];
        result = socket.RecvFrom(buf, sizeof(buf), 0, nullptr);
    }) {}
    void Join() { thread.join(); }
};

std::atomic<int> g_disconnects{0};
bool CountDisconnect(uint32_t, uint16_t, uint32_t, uint16_t, rb::ProtocolType) { g_disconnects++; return true; }
bool AcceptConnect(uint32_t, uint16_t, uint32_t, uint16_t, rb::ProtocolType) { return true; }

/// Runs fn on a thread; fails the process if it hasn't finished in 2 s (deadlock).
template<typename F>
bool FinishesInTime(F fn) {
    std::atomic<bool> done{false};
    std::thread t([&] { fn(); done = true; });
    for (int i = 0; i < 200 && !done; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!done) {
        printf("FAIL\n    deadlock: call did not return within 2 s\n");
        fflush(stdout);
        _exit(1);
    }
    t.join();
    return true;
}

/// A TCP proxy socket registered as fd, with a remote peer set so Close
/// sends ProxyDisconnect through the manager.
std::shared_ptr<ProxySocket> ConnectedTcp(s32 fd) {
    auto& m = ProxySocketManager::GetInstance();
    m.SetProxyConnectCallback(AcceptConnect);
    m.SetProxyDisconnectCallback(CountDisconnect);
    auto s = m.CreateProxySocket(fd, rb::SocketType::Stream, rb::ProtocolType::Tcp);
    s->Bind(LdnAddr(4000));
    s->SetNonBlocking(true);
    s->Connect(LdnAddr(5000));  // EINPROGRESS, but the peer is recorded
    return s;
}

} // namespace

// ============================================================================
// Reply layout (libnx bsd.c _bsdDispatchImpl: { int ret; int errno_; })
// ============================================================================

TEST(reply_success_puts_result_in_ret) {
    const rb::BsdReply r = rb::MakeReply(5);
    ASSERT_EQ(r.ret, 5);
    ASSERT_EQ(r.errno_, 0);
}

TEST(reply_new_fd_zero_is_success) {
    const rb::BsdReply r = rb::MakeReply(0);
    ASSERT_EQ(r.ret, 0);
    ASSERT_EQ(r.errno_, 0);
}

TEST(reply_failure_is_minus_one_and_errno) {
    const rb::BsdReply r = rb::MakeReply(-static_cast<int32_t>(rb::BsdErrno::Again));
    ASSERT_EQ(r.ret, -1);
    ASSERT_EQ(r.errno_, static_cast<int32_t>(rb::BsdErrno::Again));
}

TEST(reply_words_are_ret_then_errno) {
    ASSERT_EQ(offsetof(rb::BsdReply, ret), 0u);
    ASSERT_EQ(offsetof(rb::BsdReply, errno_), 4u);
    ASSERT_EQ(sizeof(rb::BsdReply), 8u);
}

TEST(select_timeout_matches_libnx_request) {
    // { int nfds; BsdSelectTimeval timeout; } puts the timeout at offset 8.
    struct Request { int32_t nfds; rb::SelectTimeval timeout; };
    ASSERT_EQ(sizeof(rb::SelectTimeval), 24u);
    ASSERT_EQ(alignof(rb::SelectTimeval), 8u);
    ASSERT_EQ(offsetof(Request, timeout), 8u);
    ASSERT_EQ(offsetof(rb::SelectTimeval, is_null), 16u);
}

// ============================================================================
// Bounded blocking waits (relaunch freeze)
// ============================================================================

TEST(nonblocking_recv_returns_eagain_at_once) {
    auto s = BoundUdp();
    s->SetNonBlocking(true);
    char buf[16];
    const auto start = std::chrono::steady_clock::now();
    ASSERT_EQ(s->RecvFrom(buf, sizeof(buf), 0, nullptr), -kEAgain);
    ASSERT_TRUE(ElapsedMs(start) < 50);
}

TEST(msg_dontwait_returns_eagain_at_once) {
    auto s = BoundUdp();
    char buf[16];
    const auto start = std::chrono::steady_clock::now();
    ASSERT_EQ(s->RecvFrom(buf, sizeof(buf), rb::MSG_FLAG_DONTWAIT, nullptr), -kEAgain);
    ASSERT_TRUE(ElapsedMs(start) < 50);
}

TEST(blocking_recv_honours_so_rcvtimeo) {
    auto s = BoundUdp();
    SetRecvTimeoutMs(*s, 60);
    char buf[16];
    const auto start = std::chrono::steady_clock::now();
    ASSERT_EQ(s->RecvFrom(buf, sizeof(buf), 0, nullptr), -kEAgain);
    const int64_t ms = ElapsedMs(start);
    ASSERT_TRUE(ms >= 50);
    ASSERT_TRUE(ms < 500);
}

TEST(blocking_recv_without_timeout_is_capped) {
    auto s = BoundUdp();
    char buf[16];
    const auto start = std::chrono::steady_clock::now();
    ASSERT_EQ(s->RecvFrom(buf, sizeof(buf), 0, nullptr), -kEAgain);
    const int64_t ms = ElapsedMs(start);
    ASSERT_TRUE(ms >= ams::mitm::bsd::PROXY_SOCKET_MAX_BLOCK_MS - 10);
    ASSERT_TRUE(ms < ams::mitm::bsd::PROXY_SOCKET_MAX_BLOCK_MS + 500);
}

TEST(incoming_data_wakes_blocked_receiver) {
    auto s = BoundUdp();
    BlockedReceiver r(*s);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const auto start = std::chrono::steady_clock::now();
    s->IncomingData("hello", 5, LdnAddr(1));
    r.Join();
    ASSERT_EQ(r.result, 5);
    ASSERT_TRUE(ElapsedMs(start) < 300);
}

TEST(close_wakes_blocked_receiver_with_ebadf) {
    auto s = BoundUdp();
    BlockedReceiver r(*s);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const auto start = std::chrono::steady_clock::now();
    s->Close();
    r.Join();
    ASSERT_EQ(r.result, -kEBadF);
    ASSERT_TRUE(ElapsedMs(start) < 300);
}

TEST(shutdown_read_wakes_blocked_receiver_with_eof) {
    auto s = BoundUdp();
    BlockedReceiver r(*s);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const auto start = std::chrono::steady_clock::now();
    s->Shutdown(rb::ShutdownHow::Read);
    r.Join();
    ASSERT_EQ(r.result, 0);
    ASSERT_TRUE(ElapsedMs(start) < 300);
}

TEST(shutdown_write_does_not_spin_blocked_receiver) {
    // A signalled-but-empty queue must not turn the wait into a busy loop
    // or an early return: the receiver still waits out its timeout.
    auto s = BoundUdp();
    SetRecvTimeoutMs(*s, 150);
    BlockedReceiver r(*s);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    s->Shutdown(rb::ShutdownHow::Write);
    const auto start = std::chrono::steady_clock::now();
    r.Join();
    ASSERT_EQ(r.result, -kEAgain);
    ASSERT_TRUE(ElapsedMs(start) >= 80);
}

// ============================================================================
// Proxy socket lifetime (close while another thread is inside the socket)
// ============================================================================

TEST(close_proxy_socket_wakes_waiter_without_freeing_it) {
    auto& m = ProxySocketManager::GetInstance();
    m.Reset();
    auto created = m.CreateProxySocket(7, rb::SocketType::Dgram, rb::ProtocolType::Udp);
    created->Bind(LdnAddr(6000));
    created.reset();

    // As an IPC handler would: look up, then block inside the socket.
    auto held = m.GetProxySocket(7);
    BlockedReceiver r(*held);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    ASSERT_TRUE(m.CloseProxySocket(7));
    r.Join();
    ASSERT_EQ(r.result, -kEBadF);
    ASSERT_TRUE(m.GetProxySocket(7) == nullptr);
    ASSERT_TRUE(held->GetState() == ams::mitm::bsd::ProxySocketState::Closed);
}

TEST(reset_wakes_waiter_without_freeing_it) {
    auto& m = ProxySocketManager::GetInstance();
    m.Reset();
    auto held = m.CreateProxySocket(8, rb::SocketType::Dgram, rb::ProtocolType::Udp);
    held->Bind(LdnAddr(6001));
    BlockedReceiver r(*held);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    m.Reset();
    r.Join();
    ASSERT_EQ(r.result, -kEBadF);
    ASSERT_EQ(m.GetActiveSocketCount(), 0u);
}

TEST(close_tcp_proxy_sends_disconnect_without_deadlock) {
    auto& m = ProxySocketManager::GetInstance();
    m.Reset();
    ConnectedTcp(9);
    g_disconnects = 0;
    FinishesInTime([&] { m.CloseProxySocket(9); });
    ASSERT_EQ(g_disconnects.load(), 1);
}

TEST(reset_sends_tcp_disconnect_before_clearing_callbacks) {
    auto& m = ProxySocketManager::GetInstance();
    m.Reset();
    ConnectedTcp(10);
    g_disconnects = 0;
    FinishesInTime([&] { m.Reset(); });
    ASSERT_EQ(g_disconnects.load(), 1);
}

// ============================================================================
// Receive buffers (heap size, oversize datagrams)
// ============================================================================

using SmallRing = ams::mitm::bsd::PacketRing<uint32_t, 64>;

TEST(packet_ring_keeps_variable_sized_datagrams_in_order) {
    SmallRing ring;
    ASSERT_TRUE(ring.Push(1, "ab", 2));
    ASSERT_TRUE(ring.Push(2, "cdef", 4));
    ASSERT_EQ(ring.Count(), 2u);
    ASSERT_EQ(ring.PayloadBytes(), 6u);
    uint32_t h = 0;
    char buf[8] = {};
    ASSERT_EQ(ring.Front(&h, buf, sizeof(buf)), 2u);
    ASSERT_EQ(h, 1u);
    ASSERT_TRUE(std::memcmp(buf, "ab", 2) == 0);
    ring.Pop();
    ASSERT_EQ(ring.Front(&h, buf, sizeof(buf)), 4u);
    ASSERT_EQ(h, 2u);
    ASSERT_TRUE(std::memcmp(buf, "cdef", 4) == 0);
}

TEST(packet_ring_wraps_and_drops_oldest_when_full) {
    SmallRing ring;  // 15-byte records (4 + 2 + 9) don't divide 64, so they straddle the end
    char payload[20];
    for (int i = 0; i < 20; i++) payload[i] = static_cast<char>('a' + i);
    for (uint32_t i = 0; i < 10; i++) {
        ASSERT_TRUE(ring.Push(i, payload + i, 9));
    }
    // 64 bytes hold four records: the newest four survive, in order.
    ASSERT_EQ(ring.Count(), 4u);
    char buf[16];
    for (uint32_t i = 6; i < 10; i++) {
        uint32_t h = 0;
        ASSERT_EQ(ring.Front(&h, buf, sizeof(buf)), 9u);
        ASSERT_EQ(h, i);
        ASSERT_TRUE(std::memcmp(buf, payload + i, 9) == 0);
        ring.Pop();
    }
    ASSERT_TRUE(ring.Empty());
    ASSERT_EQ(ring.PayloadBytes(), 0u);
}

TEST(packet_ring_rejects_record_larger_than_buffer) {
    SmallRing ring;
    char big[64] = {};
    ASSERT_TRUE(ring.Push(1, "x", 1));
    ASSERT_FALSE(ring.Push(2, big, sizeof(big)));
    ASSERT_EQ(ring.Count(), 1u);  // nothing evicted for a record that can't fit
}

TEST(proxy_socket_is_about_16_kb) {
    // It was ~65 KB with 32 fixed 2 KB slots; the heap is 384 KB.
    ASSERT_TRUE(sizeof(ProxySocket) < 20 * 1024);
}

TEST(oversize_datagram_is_dropped_not_truncated) {
    auto s = BoundUdp();
    static char big[ams::mitm::bsd::PROXY_SOCKET_MAX_PAYLOAD + 1];
    s->IncomingData(big, sizeof(big), LdnAddr(1));
    ASSERT_FALSE(s->HasPendingData());
}

TEST(short_recv_buffer_truncates_and_discards_rest) {
    auto s = BoundUdp();
    s->IncomingData("abcdef", 6, LdnAddr(1));
    s->IncomingData("xy", 2, LdnAddr(1));
    char buf[4];
    ASSERT_EQ(s->RecvFrom(buf, 3, rb::MSG_FLAG_DONTWAIT, nullptr), 3);
    ASSERT_EQ(s->RecvFrom(buf, sizeof(buf), rb::MSG_FLAG_DONTWAIT, nullptr), 2);
    ASSERT_TRUE(std::memcmp(buf, "xy", 2) == 0);
}

TEST(fionread_counts_queued_payload_bytes) {
    auto s = BoundUdp();
    s->IncomingData("abc", 3, LdnAddr(1));
    s->IncomingData("de", 2, LdnAddr(1));
    ASSERT_EQ(s->GetPendingDataSize(), 5u);
}

TEST(pending_datagrams_reach_the_socket_that_binds_later) {
    auto& m = ProxySocketManager::GetInstance();
    m.Reset();
    static char big[ams::mitm::bsd::PROXY_SOCKET_MAX_PAYLOAD + 1];
    // Arrive before anything is bound on 7000 (and one for another port).
    m.RouteIncomingData(0x0A720002, 1, 0x0A720001, 7000, rb::ProtocolType::Udp, "one", 3);
    m.RouteIncomingData(0x0A720002, 1, 0x0A720001, 7001, rb::ProtocolType::Udp, "other", 5);
    m.RouteIncomingData(0x0A720002, 1, 0x0A720001, 7000, rb::ProtocolType::Udp, big, sizeof(big));
    m.RouteIncomingData(0x0A720002, 1, 0x0A720001, 7000, rb::ProtocolType::Udp, "two", 3);

    auto s = m.CreateProxySocket(11, rb::SocketType::Dgram, rb::ProtocolType::Udp);
    s->Bind(LdnAddr(7000));
    m.DeliverPendingPackets(s.get(), 7000, rb::ProtocolType::Udp);

    char buf[8];
    ASSERT_EQ(s->RecvFrom(buf, sizeof(buf), rb::MSG_FLAG_DONTWAIT, nullptr), 3);
    ASSERT_TRUE(std::memcmp(buf, "one", 3) == 0);
    ASSERT_EQ(s->RecvFrom(buf, sizeof(buf), rb::MSG_FLAG_DONTWAIT, nullptr), 3);
    ASSERT_TRUE(std::memcmp(buf, "two", 3) == 0);
    ASSERT_EQ(s->RecvFrom(buf, sizeof(buf), rb::MSG_FLAG_DONTWAIT, nullptr), -kEAgain);

    // The datagram for the other port is still pending.
    auto other = m.CreateProxySocket(12, rb::SocketType::Dgram, rb::ProtocolType::Udp);
    other->Bind(LdnAddr(7001));
    m.DeliverPendingPackets(other.get(), 7001, rb::ProtocolType::Udp);
    ASSERT_EQ(other->RecvFrom(buf, sizeof(buf), rb::MSG_FLAG_DONTWAIT, nullptr), 5);
}

TEST(proxy_count_is_capped) {
    auto& m = ProxySocketManager::GetInstance();
    m.Reset();
    for (s32 fd = 0; fd < static_cast<s32>(ams::mitm::bsd::MAX_PROXY_SOCKETS); fd++) {
        ASSERT_TRUE(m.CreateProxySocket(100 + fd, rb::SocketType::Dgram, rb::ProtocolType::Udp) != nullptr);
    }
    ASSERT_TRUE(m.CreateProxySocket(999, rb::SocketType::Dgram, rb::ProtocolType::Udp) == nullptr);
    m.Reset();
}

// The bind/connect/sendto error paths undo a half-made proxy with
// CloseProxySocket; it must free the slot and leave other ports reserved.
TEST(closing_unbound_proxy_frees_slot_and_keeps_other_ports) {
    auto& m = ProxySocketManager::GetInstance();
    m.Reset();
    auto bound = m.CreateProxySocket(100, rb::SocketType::Dgram, rb::ProtocolType::Udp);
    ASSERT_TRUE(m.ReservePort(50000, rb::ProtocolType::Udp));
    ASSERT_TRUE(R_SUCCEEDED(bound->Bind(LdnAddr(50000))));
    for (s32 fd = 1; fd < static_cast<s32>(ams::mitm::bsd::MAX_PROXY_SOCKETS); fd++) {
        ASSERT_TRUE(m.CreateProxySocket(100 + fd, rb::SocketType::Dgram, rb::ProtocolType::Udp) != nullptr);
    }
    ASSERT_TRUE(m.CloseProxySocket(101));  // never bound
    ASSERT_TRUE(m.CreateProxySocket(999, rb::SocketType::Dgram, rb::ProtocolType::Udp) != nullptr);
    ASSERT_FALSE(m.ReservePort(50000, rb::ProtocolType::Udp));  // still the bound socket's
    m.Reset();
    ASSERT_TRUE(m.ReservePort(50000, rb::ProtocolType::Udp));   // released by Reset
    m.ReleasePort(50000, rb::ProtocolType::Udp);
}

// ============================================================================
// Which sockets and datagrams are proxied (online play must keep working)
// ============================================================================

TEST(inaddr_any_bind_is_proxied_only_during_ldn_session) {
    ASSERT_FALSE(rb::IsProxyBind(0, false));
    ASSERT_TRUE(rb::IsProxyBind(0, true));
}

TEST(ldn_bind_is_always_proxied_other_binds_never) {
    ASSERT_TRUE(rb::IsProxyBind(0x0A720002, false));
    ASSERT_TRUE(rb::IsProxyBind(0x0A720002, true));
    ASSERT_FALSE(rb::IsProxyBind(0xC0A80105, true));   // 192.168.1.5
    ASSERT_FALSE(rb::IsProxyBind(0x7F000001, true));   // 127.0.0.1
}

TEST(internet_destinations_leave_the_proxy) {
    ASSERT_TRUE(rb::IsProxyDestination(0x0A720001));   // 10.114.0.1
    ASSERT_TRUE(rb::IsProxyDestination(0x0A72FFFF));   // 10.114.255.255
    ASSERT_TRUE(rb::IsProxyDestination(0xFFFFFFFF));   // limited broadcast
    ASSERT_TRUE(rb::IsProxyDestination(0xC0A800FF));   // legacy 192.168.0.255
    ASSERT_FALSE(rb::IsProxyDestination(0x08080808));  // 8.8.8.8
    ASSERT_FALSE(rb::IsProxyDestination(0x0A000001));  // 10.0.0.1 (LAN, not LDN)
}

// ============================================================================
// Address byte order (sin_addr is network order on every path)
// ============================================================================

struct SentPacket { uint32_t src; uint16_t sport; uint32_t dst; uint16_t dport; };
SentPacket g_sent{};
bool CaptureSend(uint32_t src, uint16_t sport, uint32_t dst, uint16_t dport, rb::ProtocolType, const void*, size_t) {
    g_sent = {src, sport, dst, dport};
    return true;
}

TEST(explicit_ldn_bind_sends_with_its_own_ip) {
    auto& m = ProxySocketManager::GetInstance();
    m.Reset();
    m.SetSendCallback(CaptureSend);
    auto s = m.CreateProxySocket(20, rb::SocketType::Dgram, rb::ProtocolType::Udp);
    s->Bind(Addr(0x0A720002, 8000));
    ASSERT_EQ(s->SendTo("x", 1, 0, Addr(0x0A720003, 9000)), 1);
    ASSERT_EQ(g_sent.src, 0x0A720002u);   // 10.114.0.2, not 2.0.114.10
    ASSERT_EQ(g_sent.sport, 8000);
    ASSERT_EQ(g_sent.dst, 0x0A720003u);
    ASSERT_EQ(g_sent.dport, 9000);
}

TEST(socket_bound_without_ip_sends_with_session_ip) {
    auto& m = ProxySocketManager::GetInstance();
    m.Reset();
    m.SetSendCallback(CaptureSend);
    m.SetLocalIp(0x0A720005);
    auto s = m.CreateProxySocket(21, rb::SocketType::Dgram, rb::ProtocolType::Udp);
    s->Bind(Addr(0, 8001));
    ASSERT_EQ(s->SendTo("x", 1, 0, Addr(0x0A72FFFF, 9000)), 1);
    ASSERT_EQ(g_sent.src, 0x0A720005u);
}

TEST(explicit_ldn_bind_receives_unicast_and_broadcast) {
    auto& m = ProxySocketManager::GetInstance();
    m.Reset();
    auto s = m.CreateProxySocket(22, rb::SocketType::Dgram, rb::ProtocolType::Udp);
    s->Bind(Addr(0x0A720002, 8002));
    ASSERT_TRUE(m.RouteIncomingData(0x0A720001, 1, 0x0A720002, 8002, rb::ProtocolType::Udp, "u", 1));
    ASSERT_TRUE(m.RouteIncomingData(0x0A720001, 1, 0x0A72FFFF, 8002, rb::ProtocolType::Udp, "b", 1));
    ASSERT_FALSE(m.RouteIncomingData(0x0A720001, 1, 0x0A720009, 8002, rb::ProtocolType::Udp, "o", 1));
    rb::SockAddrIn from{};
    char c;
    ASSERT_EQ(s->RecvFrom(&c, 1, rb::MSG_FLAG_DONTWAIT, &from), 1);
    ASSERT_EQ(c, 'u');
    ASSERT_EQ(from.GetAddr(), 0x0A720001u);  // network order for the game
    ASSERT_EQ(s->RecvFrom(&c, 1, rb::MSG_FLAG_DONTWAIT, nullptr), 1);
    ASSERT_EQ(c, 'b');
    m.Reset();
}

TEST(getsockname_returns_network_order) {
    auto s = BoundUdp();
    rb::SockAddrIn out{};
    ASSERT_TRUE(R_SUCCEEDED(s->GetSockName(&out)));
    ASSERT_EQ(out.GetAddr(), 0x0A720001u);
    ASSERT_EQ(out.GetPort(), 12345);
}

// ============================================================================
// Socket keys (fd numbering is per bsd:u client)
// ============================================================================

TEST(same_fd_in_two_sessions_has_two_keys) {
    ASSERT_TRUE(rb::SocketKey(1, 0) != rb::SocketKey(2, 0));
    ASSERT_EQ(rb::SocketKey(1, 5) & 0xFFFFFFFFu, 5u);
}

TEST(same_fd_in_two_sessions_gets_two_proxies) {
    auto& m = ProxySocketManager::GetInstance();
    m.Reset();
    auto a = m.CreateProxySocket(rb::SocketKey(1, 0), rb::SocketType::Dgram, rb::ProtocolType::Udp);
    auto b = m.CreateProxySocket(rb::SocketKey(2, 0), rb::SocketType::Dgram, rb::ProtocolType::Udp);
    ASSERT_TRUE(a != nullptr && b != nullptr && a != b);
    ASSERT_TRUE(m.CloseProxySocket(rb::SocketKey(2, 0)));
    ASSERT_TRUE(m.GetProxySocket(rb::SocketKey(1, 0)) == a);
    m.Reset();
}

TEST(timeval_to_nanoseconds) {
    ASSERT_EQ(rb::TimevalToNanoseconds({1, 500000}), 1500000000LL);
    ASSERT_EQ(rb::TimevalToNanoseconds({0, 0}), 0LL);
    ASSERT_EQ(rb::TimevalToNanoseconds({-1, 0}), 0LL);
}

// ============================================================================
// Poll/Select wake-up (finding: proxy-only poll ignored its timeout)
// ============================================================================

namespace {
s64 MsSince(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
}
}

TEST(poll_wait_times_out_without_activity) {
    const auto seq = ams::mitm::bsd::ProxyActivitySeq();
    const auto t0 = std::chrono::steady_clock::now();
    ams::mitm::bsd::WaitProxyActivity(seq, ams::TimeSpan::FromMilliSeconds(50));
    const s64 ms = MsSince(t0);
    ASSERT_TRUE(ms >= 45 && ms < 1000);
}

TEST(poll_wait_wakes_on_incoming_data) {
    auto s = BoundUdp();
    const auto seq = ams::mitm::bsd::ProxyActivitySeq();
    std::thread sender([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        s->IncomingData("x", 1, LdnAddr(1));
    });
    const auto t0 = std::chrono::steady_clock::now();
    ams::mitm::bsd::WaitProxyActivity(seq, ams::TimeSpan::FromSeconds(2));
    sender.join();
    ASSERT_TRUE(MsSince(t0) < 1000);
    ASSERT_TRUE(s->HasPendingData());
}

TEST(poll_wait_does_not_miss_activity_before_it_starts) {
    auto s = BoundUdp();
    const auto seq = ams::mitm::bsd::ProxyActivitySeq();
    s->IncomingData("x", 1, LdnAddr(1));  // lands between the check and the wait
    const auto t0 = std::chrono::steady_clock::now();
    ams::mitm::bsd::WaitProxyActivity(seq, ams::TimeSpan::FromSeconds(2));
    ASSERT_TRUE(MsSince(t0) < 100);
}

TEST(poll_wait_wakes_on_close) {
    auto s = BoundUdp();
    const auto seq = ams::mitm::bsd::ProxyActivitySeq();
    std::thread closer([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        static_cast<void>(s->Close());
    });
    const auto t0 = std::chrono::steady_clock::now();
    ams::mitm::bsd::WaitProxyActivity(seq, ams::TimeSpan::FromSeconds(2));
    closer.join();
    ASSERT_TRUE(MsSince(t0) < 1000);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("\n========================================\n");
    printf("  BSD Proxy Tests - ryu_ldn_nx\n");
    printf("========================================\n\n");

    // Tests run automatically via static initializers

    printf("\n========================================\n");
    printf("  Results: %d/%d passed\n", g_tests_passed, g_tests_passed + g_tests_failed);
    printf("========================================\n\n");

    return g_tests_failed > 0 ? 1 : 0;
}
