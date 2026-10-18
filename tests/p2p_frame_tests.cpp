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
#include <algorithm>
#include <random>
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
// FrameAssembler: TCP stream reassembly (audit finding 4)
// ============================================================================

using Assembler = FrameAssembler<P2P_MAX_FRAME_SIZE>;

struct FeedResult {
    std::vector<Seen> seen;
    int invalid = 0;
    int oversized = 0;
};

// Feed @p bytes the way ReceiveLoop does: each "recv" delivers at most
// @p chunk bytes and never more than Writable().
static void feed(Assembler& a, const std::vector<uint8_t>& bytes, size_t chunk, FeedResult& r) {
    size_t pos = 0;
    while (pos < bytes.size()) {
        if (a.Writable() == 0) {  // would make recv() return 0 = "closed"
            r.invalid = -1000;
            return;
        }
        size_t n = std::min({chunk, a.Writable(), bytes.size() - pos});
        std::memcpy(a.WritePtr(), bytes.data() + pos, n);
        pos += n;
        FrameStatus st = a.Commit(n, [&](const LdnHeader& h, const uint8_t* p, size_t len) {
            r.seen.push_back({h.type, std::vector<uint8_t>(p, p + len)});
            return true;
        });
        if (st == FrameStatus::Invalid) r.invalid++;
        if (st == FrameStatus::Oversized) r.oversized++;
    }
}

static std::vector<uint8_t> three_frames() {
    std::vector<uint8_t> bytes;
    append(bytes, frame(1, 8, 0x11));
    append(bytes, frame(2, 0, 0));
    append(bytes, frame(3, 1500, 0x33));
    return bytes;
}

TEST(assembler_one_byte_at_a_time) {
    Assembler a;
    FeedResult r;
    feed(a, three_frames(), 1, r);
    ASSERT_EQ(r.invalid, 0);
    ASSERT_EQ(r.seen.size(), 3u);
    ASSERT_EQ(r.seen[0].payload, std::vector<uint8_t>(8, 0x11));
    ASSERT_EQ(r.seen[1].payload.size(), 0u);
    ASSERT_EQ(r.seen[2].type, 3);
    ASSERT_EQ(r.seen[2].payload, std::vector<uint8_t>(1500, 0x33));
    ASSERT_EQ(a.Buffered(), 0u);
}

TEST(assembler_every_split_point) {
    // Two recv()s, split at every possible offset: same frames every time.
    const auto bytes = three_frames();
    for (size_t cut = 1; cut < bytes.size(); cut++) {
        Assembler a;
        FeedResult r;
        feed(a, std::vector<uint8_t>(bytes.begin(), bytes.begin() + cut), SIZE_MAX, r);
        feed(a, std::vector<uint8_t>(bytes.begin() + cut, bytes.end()), SIZE_MAX, r);
        ASSERT_EQ(r.invalid, 0);
        ASSERT_EQ(r.seen.size(), 3u);
        ASSERT_EQ(r.seen[2].payload, std::vector<uint8_t>(1500, 0x33));
    }
}

TEST(assembler_max_size_frame_fits) {
    Assembler a;
    FeedResult r;
    const size_t payload = P2P_MAX_FRAME_SIZE - sizeof(LdnHeader);
    feed(a, frame(static_cast<uint8_t>(PacketId::ProxyData), payload, 0x5A), 700, r);
    ASSERT_EQ(r.seen.size(), 1u);
    ASSERT_EQ(r.seen[0].payload.size(), payload);
    ASSERT_EQ(r.oversized, 0);
}

TEST(assembler_proxy_data_with_max_payload_fits) {
    // 12 + 20 + P2P_MAX_PROXY_PAYLOAD must fit, and cover the BSD 2000 B datagram cap.
    ASSERT_TRUE(P2P_MAX_PROXY_PAYLOAD >= 2000u);
    Assembler a;
    FeedResult r;
    feed(a, frame(static_cast<uint8_t>(PacketId::ProxyData),
                  sizeof(ProxyDataHeader) + P2P_MAX_PROXY_PAYLOAD, 0x01), 1460, r);
    ASSERT_EQ(r.seen.size(), 1u);
}

TEST(assembler_oversized_frame_is_skipped_not_fatal) {
    // Legal (<= MAX_PACKET_SIZE) but larger than we buffer: dropped, and the
    // next frame still arrives intact.
    std::vector<uint8_t> bytes;
    append(bytes, frame(1, 4, 0x11));
    append(bytes, frame(2, 5000, 0x22));
    append(bytes, frame(3, 6, 0x33));
    for (size_t chunk : {size_t(1), size_t(13), size_t(1460), size_t(4096)}) {
        Assembler a;
        FeedResult r;
        feed(a, bytes, chunk, r);
        ASSERT_EQ(r.invalid, 0);
        ASSERT_EQ(r.oversized, 1);
        ASSERT_EQ(r.seen.size(), 2u);
        ASSERT_EQ(r.seen[0].type, 1);
        ASSERT_EQ(r.seen[1].type, 3);
        ASSERT_EQ(r.seen[1].payload, std::vector<uint8_t>(6, 0x33));
        ASSERT_EQ(a.Buffered(), 0u);
    }
}

TEST(assembler_protocol_max_frame_is_skipped) {
    std::vector<uint8_t> bytes = frame(2, MAX_PACKET_SIZE, 0x22);
    append(bytes, frame(3, 1, 0x33));
    Assembler a;
    FeedResult r;
    feed(a, bytes, 1460, r);
    ASSERT_EQ(r.invalid, 0);
    ASSERT_EQ(r.seen.size(), 1u);
    ASSERT_EQ(r.seen[0].type, 3);
}

TEST(assembler_hostile_header_after_split_is_invalid) {
    std::vector<uint8_t> bytes = frame(1, 4, 0x11);
    append(bytes, raw_header(2, -12));
    Assembler a;
    FeedResult r;
    feed(a, bytes, 5, r);
    ASSERT_EQ(r.seen.size(), 1u);
    ASSERT_EQ(r.invalid, 1);
    ASSERT_EQ(a.Buffered(), 0u);
}

TEST(assembler_truncated_stream_keeps_tail_and_never_fills) {
    // A peer that stops mid-frame leaves the tail buffered with room to spare.
    auto bytes = frame(1, 1000, 0x11);
    bytes.resize(600);
    Assembler a;
    FeedResult r;
    feed(a, bytes, 128, r);
    ASSERT_TRUE(r.seen.empty());
    ASSERT_EQ(a.Buffered(), 600u);
    ASSERT_TRUE(a.Writable() > 0);
}

// ============================================================================
// Fuzz: random frames, random chunking, random corruption
// ============================================================================

TEST(fuzz_valid_streams_any_chunking) {
    std::mt19937 rng(0xC0FFEE);
    for (int iter = 0; iter < 300; iter++) {
        std::vector<uint8_t> bytes;
        std::vector<Seen> expected;
        int expected_oversized = 0;
        const int frames = 1 + static_cast<int>(rng() % 20);
        for (int i = 0; i < frames; i++) {
            size_t len = (rng() % 8 == 0) ? 2000 + rng() % 4000 : rng() % 1600;
            uint8_t type = static_cast<uint8_t>(rng());
            uint8_t fill = static_cast<uint8_t>(rng());
            append(bytes, frame(type, len, fill));
            if (sizeof(LdnHeader) + len <= P2P_MAX_FRAME_SIZE) {
                expected.push_back({type, std::vector<uint8_t>(len, fill)});
            } else {
                expected_oversized++;
            }
        }
        Assembler a;
        FeedResult r;
        feed(a, bytes, 1 + rng() % 3000, r);
        ASSERT_EQ(r.invalid, 0);
        ASSERT_EQ(r.oversized, expected_oversized);
        ASSERT_EQ(r.seen.size(), expected.size());
        for (size_t i = 0; i < expected.size(); i++) {
            ASSERT_EQ(r.seen[i].type, expected[i].type);
            ASSERT_EQ(r.seen[i].payload, expected[i].payload);
        }
        ASSERT_EQ(a.Buffered(), 0u);
    }
}

TEST(fuzz_random_and_corrupted_bytes) {
    // Garbage, valid frames with flipped bytes, and hostile sizes. Nothing
    // may crash, dispatched lengths must stay within the buffer, and the
    // assembler must always leave room for the next recv().
    std::mt19937 rng(1234);
    for (int iter = 0; iter < 2000; iter++) {
        std::vector<uint8_t> bytes;
        const int parts = 1 + static_cast<int>(rng() % 6);
        for (int i = 0; i < parts; i++) {
            switch (rng() % 4) {
                case 0: {  // pure noise
                    size_t n = rng() % 64;
                    for (size_t k = 0; k < n; k++) bytes.push_back(static_cast<uint8_t>(rng()));
                    break;
                }
                case 1: {  // valid header, hostile size, short body
                    static const int32_t sizes[] = {-1, -12, INT32_MIN, INT32_MAX, 0,
                                                    static_cast<int32_t>(MAX_PACKET_SIZE),
                                                    static_cast<int32_t>(MAX_PACKET_SIZE + 1)};
                    append(bytes, raw_header(static_cast<uint8_t>(rng()), sizes[rng() % 7]));
                    bytes.insert(bytes.end(), rng() % 32, 0);
                    break;
                }
                case 2: {  // valid frame with one corrupted byte
                    auto f = frame(static_cast<uint8_t>(rng()), rng() % 300, 0x5A);
                    f[rng() % f.size()] ^= static_cast<uint8_t>(1 + rng() % 255);
                    append(bytes, f);
                    break;
                }
                default:   // valid frame, truncated
                    auto f = frame(static_cast<uint8_t>(rng()), rng() % 300, 0x5A);
                    f.resize(rng() % (f.size() + 1));
                    append(bytes, f);
                    break;
            }
        }
        Assembler a;
        size_t pos = 0;
        while (pos < bytes.size()) {
            ASSERT_TRUE(a.Writable() > 0);
            size_t n = std::min({static_cast<size_t>(1 + rng() % 200), a.Writable(), bytes.size() - pos});
            std::memcpy(a.WritePtr(), bytes.data() + pos, n);
            pos += n;
            bool bad_len = false;
            FrameStatus st = a.Commit(n, [&](const LdnHeader& h, const uint8_t*, size_t len) {
                if (h.data_size < 0 || static_cast<size_t>(h.data_size) != len ||
                    len > P2P_MAX_FRAME_SIZE - sizeof(LdnHeader)) {
                    bad_len = true;
                }
                return true;
            });
            ASSERT_FALSE(bad_len);
            if (st == FrameStatus::Invalid) {
                ASSERT_EQ(a.Buffered(), 0u);  // caller disconnects; buffer reset
            }
        }
    }
}

// ============================================================================
// Main
// ============================================================================

int main() {
    // Tests run from static constructors above.
    printf("\n  Results: %d/%d passed\n", g_tests_passed, g_tests_passed + g_tests_failed);
    return g_tests_failed == 0 ? 0 : 1;
}
