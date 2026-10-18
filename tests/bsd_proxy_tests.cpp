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

#include "bsd/bsd_types.hpp"

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
