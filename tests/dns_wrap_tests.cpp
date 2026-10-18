/**
 * @file dns_wrap_tests.cpp
 * @brief Unit tests for the UDP DNS resolver behind __wrap_getaddrinfo
 *
 * Includes dns_wrap.cpp directly so its internal functions
 * (QueryDnsServer, ResolveWithServers, GetDnsServers) are tested as
 * shipped, not copied. A fake DNS server on 127.0.0.1 answers each query.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include "../sysmodule/source/network/dns_wrap.cpp"

#include <atomic>
#include <chrono>
#include <thread>

static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            printf("    FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            return false; \
        } \
    } while (0)

#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))

#define RUN_TEST(test_func) \
    do { \
        printf("  [TEST] %s... ", #test_func); \
        fflush(stdout); \
        if (test_func()) { \
            printf("PASS\n"); \
            g_tests_passed++; \
        } else { \
            g_tests_failed++; \
        } \
    } while (0)

namespace {

/// A UDP socket bound to 127.0.0.1 on a free port
struct UdpSocket {
    int fd = -1;
    uint16_t port = 0;

    UdpSocket() {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        socklen_t len = sizeof(addr);
        getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &len);
        port = ntohs(addr.sin_port);
    }
    ~UdpSocket() { close(fd); }
};

/// Build a one-answer A-record reply for a received query
size_t BuildReply(const uint8_t* query, size_t query_len, uint16_t id,
                  const uint8_t ip[4], uint8_t* out) {
    std::memcpy(out, query, query_len);
    out[0] = static_cast<uint8_t>(id >> 8);
    out[1] = static_cast<uint8_t>(id);
    out[2] = 0x81;  // QR=1, RD=1
    out[3] = 0x80;  // RA=1, RCODE=0
    out[7] = 1;     // ANCOUNT=1
    size_t pos = query_len;
    const uint8_t answer[] = {
        0xC0, 0x0C,              // name: pointer to the question
        0x00, 0x01, 0x00, 0x01,  // TYPE A, CLASS IN
        0x00, 0x00, 0x00, 0x3C,  // TTL
        0x00, 0x04,              // RDLENGTH
    };
    std::memcpy(out + pos, answer, sizeof(answer));
    pos += sizeof(answer);
    std::memcpy(out + pos, ip, 4);
    return pos + 4;
}

/**
 * @brief Fake server: answers the first query with a wrong-ID reply, a
 *        reply from another port, then (if `answer`) the genuine one
 */
void FakeServer(UdpSocket* server, bool answer) {
    uint8_t query[512];
    struct sockaddr_in client{};
    socklen_t len = sizeof(client);
    ssize_t n = recvfrom(server->fd, query, sizeof(query), 0,
                         reinterpret_cast<struct sockaddr*>(&client), &len);
    if (n < 12) return;
    const uint16_t id = static_cast<uint16_t>((query[0] << 8) | query[1]);
    uint8_t reply[600];

    const uint8_t forged_ip[4] = {6, 6, 6, 6};
    size_t r = BuildReply(query, static_cast<size_t>(n), static_cast<uint16_t>(id + 1), forged_ip, reply);
    sendto(server->fd, reply, r, 0, reinterpret_cast<struct sockaddr*>(&client), len);

    UdpSocket other;  // right ID, wrong source port
    r = BuildReply(query, static_cast<size_t>(n), id, forged_ip, reply);
    sendto(other.fd, reply, r, 0, reinterpret_cast<struct sockaddr*>(&client), len);

    if (answer) {
        const uint8_t real_ip[4] = {203, 0, 113, 7};
        r = BuildReply(query, static_cast<size_t>(n), id, real_ip, reply);
        sendto(server->fd, reply, r, 0, reinterpret_cast<struct sockaddr*>(&client), len);
    }
}

const uint32_t kLoopback = htonl(INADDR_LOOPBACK);

} // namespace

/**
 * @brief Replies with the wrong ID or source port are ignored
 *
 * The old resolver took the first datagram, which here is the forged
 * 6.6.6.6 answer.
 */
bool test_query_ignores_wrong_id_and_port() {
    UdpSocket server;
    std::thread t(FakeServer, &server, true);
    uint32_t ips[8];
    int n = QueryDnsServer("relay.example.com", kLoopback, server.port, 2000, ips, 8);
    t.join();
    ASSERT_EQ(n, 1);
    ASSERT_EQ(ips[0], 0xCB007107u);  // 203.0.113.7
    return true;
}

/**
 * @brief Only forged replies: the query waits out its deadline and fails
 */
bool test_query_times_out_without_genuine_reply() {
    UdpSocket server;
    std::thread t(FakeServer, &server, false);
    uint32_t ips[8];
    auto start = std::chrono::steady_clock::now();
    int n = QueryDnsServer("relay.example.com", kLoopback, server.port, 300, ips, 8);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    t.join();
    ASSERT_EQ(n, DnsErr(EAI_AGAIN));
    ASSERT_TRUE(ms >= 250 && ms < 2000);
    return true;
}

/**
 * @brief A silent first server falls through to the next one
 */
bool test_resolve_falls_back_to_next_server() {
    UdpSocket server;
    std::thread t(FakeServer, &server, true);
    // 127.0.0.2 is loopback too, but nothing listens on it
    const uint32_t servers[2] = {htonl(0x7F000002), kLoopback};
    uint32_t ips[8];
    int n = ResolveWithServers("relay.example.com", servers, 2, server.port, 300, ips, 8);
    t.join();
    ASSERT_EQ(n, 1);
    ASSERT_EQ(ips[0], 0xCB007107u);
    return true;
}

/**
 * @brief With one server, every attempt goes to it (3 attempts)
 */
bool test_resolve_retries_single_server() {
    UdpSocket server;
    std::atomic<int> queries{0};
    std::thread t([&] {
        // Drop the first two queries, answer the third
        uint8_t buf[512];
        for (int i = 0; i < 2; i++) {
            if (recv(server.fd, buf, sizeof(buf), 0) > 0) queries++;
        }
        FakeServer(&server, true);
        queries++;
    });
    uint32_t ips[8];
    int n = ResolveWithServers("relay.example.com", &kLoopback, 1, server.port, 300, ips, 8);
    t.join();
    ASSERT_EQ(n, 1);
    ASSERT_EQ(queries.load(), 3);
    return true;
}

/**
 * @brief On the host there is no nifm: the list is just 8.8.8.8
 */
bool test_dns_server_list_fallback() {
    uint32_t servers[3];
    ASSERT_EQ(GetDnsServers(servers), 1);
    ASSERT_EQ(servers[0], 0x08080808u);
    return true;
}

int main() {
    printf("\n========================================\n");
    printf("  DNS Wrapper Tests - ryu_ldn_nx\n");
    printf("========================================\n\n");

    RUN_TEST(test_query_ignores_wrong_id_and_port);
    RUN_TEST(test_query_times_out_without_genuine_reply);
    RUN_TEST(test_resolve_falls_back_to_next_server);
    RUN_TEST(test_resolve_retries_single_server);
    RUN_TEST(test_dns_server_list_fallback);

    printf("\n========================================\n");
    printf("  Results: %d/%d passed\n", g_tests_passed, g_tests_passed + g_tests_failed);
    printf("========================================\n\n");
    return g_tests_failed > 0 ? 1 : 0;
}
