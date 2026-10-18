/**
 * @file ldn_service_tests.cpp
 * @brief Regression tests for the ldn:u service fixes
 *
 * These compile the real ldn/ sources that have no Switch dependency
 * (ldn_network_timeout.cpp via tests/shim/stratosphere.hpp). Anything that
 * lives inside ICommunicationService cannot be built on the host; where a
 * test mirrors logic instead of calling it, the test says so.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <thread>
#include <unistd.h>

#include "ldn/ldn_network_timeout.hpp"
#include "ldn/ldn_helpers.hpp"

using ams::mitm::ldn::NetworkTimeout;

// ============================================================================
// Test Framework (minimal; explicit calls from main so the logger global is
// constructed before any LOG_* in the code under test runs)
// ============================================================================

static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            printf("FAIL\n    Assertion failed: %s\n    at %s:%d\n", #cond, __FILE__, __LINE__); \
            g_tests_failed++; \
            return; \
        } \
    } while (0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))

#define RUN(fn) \
    do { \
        printf("  [TEST] %s... ", #fn); \
        fflush(stdout); \
        int failed_before = g_tests_failed; \
        fn(); \
        if (g_tests_failed == failed_before) { \
            printf("PASS\n"); \
            g_tests_passed++; \
        } \
    } while (0)

/// Run fn on its own thread; a hang is a failure, not a hung test run.
/// A deadlocked thread cannot be joined, so on timeout the process exits.
template <typename Fn>
static bool CompletesWithin(std::chrono::milliseconds limit, Fn fn) {
    std::packaged_task<void()> task(fn);
    auto done = task.get_future();
    std::thread worker(std::move(task));
    if (done.wait_for(limit) != std::future_status::ready) {
        printf("FAIL\n    deadlock: did not finish within %lld ms\n",
               static_cast<long long>(limit.count()));
        fflush(stdout);
        _exit(1);
    }
    worker.join();
    return true;
}

static uint64_t NowMs() {
    return static_cast<uint64_t>(ams::os::ConvertToTimeSpan(ams::os::GetSystemTick()).GetMilliSeconds());
}

// ============================================================================
// Finding 1: inactivity timeout self-deadlock
// ============================================================================

static NetworkTimeout* g_reentrant_timeout = nullptr;
static int g_callback_calls = 0;

// Touches the timeout from inside its own callback. The old CheckTimeout held
// its non-recursive mutex across the callback, so this hung forever, the same
// way OnInactivityTimeout hung re-taking g_active_service_mutex.
static void ReentrantCallback() {
    g_callback_calls++;
    (void)g_reentrant_timeout->IsActive();
    g_reentrant_timeout->DisableTimeout();
}

static void timeout_callback_runs_without_lock_held() {
    NetworkTimeout timeout(NetworkTimeout::DEFAULT_IDLE_TIMEOUT_MS, &ReentrantCallback);
    g_reentrant_timeout = &timeout;
    g_callback_calls = 0;

    timeout.RefreshTimeout();
    bool fired = false;
    CompletesWithin(std::chrono::milliseconds(2000), [&] {
        fired = timeout.CheckTimeout(NowMs() + NetworkTimeout::DEFAULT_IDLE_TIMEOUT_MS + 1);
    });

    ASSERT_TRUE(fired);
    ASSERT_TRUE(g_callback_calls == 1);
    g_reentrant_timeout = nullptr;
}

// The receive loop now acts on CheckTimeout's return value (no callback), so
// expiry must be reported even without one, and only once per arm.
static void timeout_reports_expiry_once_without_callback() {
    NetworkTimeout timeout(NetworkTimeout::DEFAULT_IDLE_TIMEOUT_MS, nullptr);
    timeout.RefreshTimeout();
    const uint64_t later = NowMs() + NetworkTimeout::DEFAULT_IDLE_TIMEOUT_MS + 1;

    ASSERT_TRUE(timeout.CheckTimeout(later));
    ASSERT_FALSE(timeout.CheckTimeout(later));
    ASSERT_FALSE(timeout.IsActive());
}

static void timeout_not_expired_or_disabled_does_not_fire() {
    NetworkTimeout timeout(NetworkTimeout::DEFAULT_IDLE_TIMEOUT_MS, nullptr);

    ASSERT_FALSE(timeout.CheckTimeout(NowMs() + 100000));  // never armed

    timeout.RefreshTimeout();
    ASSERT_FALSE(timeout.CheckTimeout(NowMs()));            // armed, not yet due
    ASSERT_TRUE(timeout.IsActive());

    timeout.DisableTimeout();                               // CreateNetwork/Connect
    ASSERT_FALSE(timeout.CheckTimeout(NowMs() + 100000));
}

// ============================================================================
// Finding 3 / finding 2 readiness: the server's Disconnect packet
// ============================================================================

// Same names and values as ams::mitm::ldn::DisconnectReason (ldn_types.hpp
// pulls in <stratosphere.hpp>); the helper under test is the real one.
enum class Reason : uint32_t {
    None = 0, User = 1, SystemRequest = 2, DestroyedByUser = 3,
    DestroyedBySystem = 4, Rejected = 5, SignalLost = 6,
};

static void server_disconnect_reason_matches_ryujinx() {
    using ams::mitm::ldn::helpers::ServerDisconnectReason;
    // Station dropped because the host left: DestroyedByUser (Station.cs).
    ASSERT_TRUE(ServerDisconnectReason(Reason::None, false) == Reason::DestroyedByUser);
    // Host whose room the server closed: DestroyedBySystem (AccessPoint.cs).
    ASSERT_TRUE(ServerDisconnectReason(Reason::None, true) == Reason::DestroyedBySystem);
    // A Reject that preceded the Disconnect wins (HandleReject).
    ASSERT_TRUE(ServerDisconnectReason(Reason::Rejected, false) == Reason::Rejected);
    ASSERT_TRUE(ServerDisconnectReason(Reason::SignalLost, true) == Reason::SignalLost);
}

// ============================================================================
// Finding 4: one receive-thread stack per live instance
// ============================================================================

static void receive_stack_pool_gives_each_instance_its_own_stack() {
    // Same template and parameters as g_recv_stacks in ldn_icommunication.cpp.
    static ams::mitm::ldn::helpers::StackPool<2, 0x4000, 0x1000> pool;

    const int a = pool.Claim();   // game A's instance
    const int b = pool.Claim();   // game B opens ldn:u before A is torn down
    ASSERT_TRUE(a >= 0 && b >= 0 && a != b);
    ASSERT_TRUE(pool.Stack(a) != pool.Stack(b));
    ASSERT_TRUE(reinterpret_cast<uintptr_t>(pool.Stack(a)) % 0x1000 == 0);
    ASSERT_TRUE(reinterpret_cast<uintptr_t>(pool.Stack(b)) % 0x1000 == 0);

    ASSERT_TRUE(pool.Claim() == -1);  // third concurrent session is refused

    pool.Release(a);                  // A's destructor joined its thread
    ASSERT_TRUE(pool.Claim() == a);
}

int main() {
    printf("\n========================================\n");
    printf("  LDN Service Tests - ryu_ldn_nx\n");
    printf("========================================\n\n");

    RUN(timeout_callback_runs_without_lock_held);
    RUN(timeout_reports_expiry_once_without_callback);
    RUN(timeout_not_expired_or_disabled_does_not_fire);
    RUN(server_disconnect_reason_matches_ryujinx);
    RUN(receive_stack_pool_gives_each_instance_its_own_stack);

    printf("\n========================================\n");
    printf("  Results: %d/%d passed\n", g_tests_passed, g_tests_passed + g_tests_failed);
    printf("========================================\n");
    return g_tests_failed == 0 ? 0 : 1;
}
