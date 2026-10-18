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

#include "bsd/bsd_types.hpp"
#include "bsd/proxy_socket.hpp"
#include "bsd/proxy_socket_manager.hpp"

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

namespace {

constexpr int32_t kEAgain = static_cast<int32_t>(rb::BsdErrno::Again);
constexpr int32_t kEBadF = static_cast<int32_t>(rb::BsdErrno::BadF);

rb::SockAddrIn LdnAddr(uint16_t port) {
    rb::SockAddrIn a{};
    a.sin_len = sizeof(a);
    a.sin_family = static_cast<uint8_t>(rb::AddressFamily::Inet);
    a.sin_port = __builtin_bswap16(port);
    a.sin_addr = 0x0A720001;
    return a;
}

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

TEST(timeval_to_nanoseconds) {
    ASSERT_EQ(rb::TimevalToNanoseconds({1, 500000}), 1500000000LL);
    ASSERT_EQ(rb::TimevalToNanoseconds({0, 0}), 0LL);
    ASSERT_EQ(rb::TimevalToNanoseconds({-1, 0}), 0LL);
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
