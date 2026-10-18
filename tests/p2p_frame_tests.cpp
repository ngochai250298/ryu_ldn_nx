/**
 * @file p2p_frame_tests.cpp
 * @brief Tests for the P2P wire-frame parser (sysmodule/source/p2p/p2p_frame.hpp)
 *
 * Unlike the other p2p_* suites, these call the real parsing code that
 * P2pProxySession and P2pProxyClient run on bytes from the network. Peers
 * are untrusted, so every length here is treated as hostile.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include "p2p/p2p_frame.hpp"
#include "protocol/ryu_protocol.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace ryu_ldn::protocol;
using namespace ams::mitm::p2p;

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

// ============================================================================
// Helpers
// ============================================================================

struct Seen {
    uint8_t type;
    std::vector<uint8_t> payload;
};

// Raw header with an arbitrary (possibly hostile) data_size.
static std::vector<uint8_t> raw_header(uint8_t type, int32_t data_size) {
    std::vector<uint8_t> out(sizeof(LdnHeader));
    encode_header(out.data(), static_cast<PacketId>(type), data_size);
    return out;
}

// Well-formed frame of @p len payload bytes, each byte = @p fill.
static std::vector<uint8_t> frame(uint8_t type, size_t len, uint8_t fill) {
    std::vector<uint8_t> out = raw_header(type, static_cast<int32_t>(len));
    out.insert(out.end(), len, fill);
    return out;
}

static void append(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

static FrameStatus walk(const std::vector<uint8_t>& bytes, size_t& consumed,
                        std::vector<Seen>& seen) {
    return ForEachFrame(bytes.data(), bytes.size(), consumed,
        [&](const LdnHeader& h, const uint8_t* p, size_t n) {
            seen.push_back({h.type, std::vector<uint8_t>(p, p + n)});
            return true;
        });
}

// ============================================================================
// ForEachFrame: hostile lengths (audit finding 2)
// ============================================================================

TEST(negative_size_minus_12_is_invalid_not_a_hang) {
    // data_size = -12 used to wrap packet_size to 0 and spin forever.
    auto bytes = raw_header(0xEE, -12);
    size_t consumed = 99;
    std::vector<Seen> seen;
    ASSERT_EQ(walk(bytes, consumed, seen), FrameStatus::Invalid);
    ASSERT_TRUE(seen.empty());
    ASSERT_EQ(consumed, 0u);
}

TEST(negative_size_minus_1_is_invalid_not_oob) {
    // data_size = -1 used to pass the bounds check and yield a ~2^64 payload length.
    auto bytes = raw_header(static_cast<uint8_t>(PacketId::ProxyData), -1);
    bytes.resize(64, 0);
    size_t consumed = 0;
    std::vector<Seen> seen;
    ASSERT_EQ(walk(bytes, consumed, seen), FrameStatus::Invalid);
    ASSERT_TRUE(seen.empty());
}

TEST(int_min_size_is_invalid) {
    auto bytes = raw_header(static_cast<uint8_t>(PacketId::ProxyData), INT32_MIN);
    size_t consumed = 0;
    std::vector<Seen> seen;
    ASSERT_EQ(walk(bytes, consumed, seen), FrameStatus::Invalid);
}

TEST(size_above_protocol_max_is_invalid) {
    auto bytes = raw_header(static_cast<uint8_t>(PacketId::ProxyData),
                            static_cast<int32_t>(MAX_PACKET_SIZE + 1));
    size_t consumed = 0;
    std::vector<Seen> seen;
    ASSERT_EQ(walk(bytes, consumed, seen), FrameStatus::Invalid);
}

TEST(bad_magic_is_invalid) {
    auto bytes = frame(static_cast<uint8_t>(PacketId::ProxyConfig), 8, 0);
    bytes[0] ^= 0xFF;
    size_t consumed = 0;
    std::vector<Seen> seen;
    ASSERT_EQ(walk(bytes, consumed, seen), FrameStatus::Invalid);
}

TEST(bad_version_is_invalid) {
    auto bytes = frame(static_cast<uint8_t>(PacketId::ProxyConfig), 8, 0);
    bytes[5] = PROTOCOL_VERSION + 1;
    size_t consumed = 0;
    std::vector<Seen> seen;
    ASSERT_EQ(walk(bytes, consumed, seen), FrameStatus::Invalid);
}

TEST(zero_size_frames_make_progress) {
    // A run of header-only frames must each advance by 12 bytes and end.
    std::vector<uint8_t> bytes;
    for (int i = 0; i < 100; i++) append(bytes, frame(0xEE, 0, 0));
    size_t consumed = 0;
    std::vector<Seen> seen;
    ASSERT_EQ(walk(bytes, consumed, seen), FrameStatus::Ok);
    ASSERT_EQ(seen.size(), 100u);
    ASSERT_EQ(consumed, bytes.size());
}

TEST(size_beyond_received_bytes_is_not_dispatched) {
    // Header claims 100 bytes, only 10 arrived: nothing dispatched, nothing consumed.
    auto bytes = raw_header(static_cast<uint8_t>(PacketId::ProxyData), 100);
    bytes.insert(bytes.end(), 10, 0xAB);
    size_t consumed = 0;
    std::vector<Seen> seen;
    ASSERT_EQ(walk(bytes, consumed, seen), FrameStatus::Ok);
    ASSERT_TRUE(seen.empty());
    ASSERT_EQ(consumed, 0u);
}

TEST(truncated_header_is_not_dispatched) {
    auto bytes = raw_header(static_cast<uint8_t>(PacketId::ProxyData), 4);
    bytes.resize(7);
    size_t consumed = 0;
    std::vector<Seen> seen;
    ASSERT_EQ(walk(bytes, consumed, seen), FrameStatus::Ok);
    ASSERT_TRUE(seen.empty());
    ASSERT_EQ(consumed, 0u);
}

TEST(complete_frames_then_partial_tail) {
    std::vector<uint8_t> bytes;
    append(bytes, frame(1, 8, 0x11));
    append(bytes, frame(2, 20, 0x22));
    auto tail = frame(3, 30, 0x33);
    bytes.insert(bytes.end(), tail.begin(), tail.begin() + 15);
    size_t consumed = 0;
    std::vector<Seen> seen;
    ASSERT_EQ(walk(bytes, consumed, seen), FrameStatus::Ok);
    ASSERT_EQ(seen.size(), 2u);
    ASSERT_EQ(seen[0].type, 1);
    ASSERT_EQ(seen[0].payload, std::vector<uint8_t>(8, 0x11));
    ASSERT_EQ(seen[1].payload, std::vector<uint8_t>(20, 0x22));
    ASSERT_EQ(consumed, 12u + 8 + 12 + 20);
}

TEST(invalid_frame_after_valid_ones_stops_at_it) {
    std::vector<uint8_t> bytes;
    append(bytes, frame(1, 4, 0x11));
    append(bytes, raw_header(2, -5));
    size_t consumed = 0;
    std::vector<Seen> seen;
    ASSERT_EQ(walk(bytes, consumed, seen), FrameStatus::Invalid);
    ASSERT_EQ(seen.size(), 1u);
}

TEST(callback_can_stop_the_walk) {
    std::vector<uint8_t> bytes;
    for (int i = 0; i < 5; i++) append(bytes, frame(1, 4, 0));
    size_t consumed = 0;
    int calls = 0;
    auto st = ForEachFrame(bytes.data(), bytes.size(), consumed,
        [&](const LdnHeader&, const uint8_t*, size_t) { return ++calls < 2; });
    ASSERT_EQ(st, FrameStatus::Ok);
    ASSERT_EQ(calls, 2);
}

TEST(empty_input) {
    size_t consumed = 5;
    int calls = 0;
    auto st = ForEachFrame(nullptr, 0, consumed,
        [&](const LdnHeader&, const uint8_t*, size_t) { calls++; return true; });
    ASSERT_EQ(st, FrameStatus::Ok);
    ASSERT_EQ(calls, 0);
    ASSERT_EQ(consumed, 0u);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    // Tests run from static constructors above.
    printf("\n  Results: %d/%d passed\n", g_tests_passed, g_tests_passed + g_tests_failed);
    return g_tests_failed == 0 ? 0 : 1;
}
