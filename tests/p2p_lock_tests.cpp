/**
 * @file p2p_lock_tests.cpp
 * @brief Real P2P proxy sources: blocking network I/O never holds a lock
 *        that teardown or other threads need
 *
 * Builds p2p/p2p_proxy_client.cpp and p2p/p2p_proxy_server.cpp against
 * tests/host_shim. Each test fails (by timed join) on the code before its
 * fix instead of hanging the suite.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

#include "p2p/p2p_proxy_client.hpp"
#include "p2p/p2p_proxy_server.hpp"
#include "p2p/upnp_port_mapper.hpp"

using ams::mitm::p2p::P2pProxyClient;
using ams::mitm::p2p::P2pProxyServer;
using namespace std::chrono_literals;

// The server only reaches UPnP from NatPunch, which these tests never call.
namespace ams::mitm::p2p {
UpnpPortMapper& UpnpPortMapper::GetInstance() { std::abort(); }
bool UpnpPortMapper::Discover() { std::abort(); }
bool UpnpPortMapper::AddPortMapping(uint16_t, uint16_t, const char*, int) { std::abort(); }
bool UpnpPortMapper::DeletePortMapping(uint16_t) { std::abort(); }
bool UpnpPortMapper::RefreshPortMapping(uint16_t, uint16_t, const char*) { std::abort(); }
bool UpnpPortMapper::GetExternalIPAddress(char*, size_t) { std::abort(); }
}

template<typename Pred>
static bool WaitFor(Pred pred, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(10ms);
    }
    return true;
}

/**
 * P2pProxyClient sends under its mutex. Before SO_SNDTIMEO a send() blocked
 * on a host that stopped reading held it forever, and Disconnect() (which
 * needs it) never returned.
 */
static bool test_disconnect_while_send_blocked_on_stalled_host() {
    // A host that accepts the connection and never reads from it
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int rcvbuf = 4096;
    setsockopt(listen_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t addr_len = sizeof(addr);
    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        listen(listen_fd, 1) != 0 ||
        getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &addr_len) != 0) {
        printf("FAIL\n    listener setup\n");
        return false;
    }

    auto* client = new P2pProxyClient();
    if (!client->Connect("127.0.0.1", ntohs(addr.sin_port))) {
        printf("FAIL\n    connect\n");
        return false;
    }
    int host_fd = accept(listen_fd, nullptr, nullptr);

    std::atomic<int> finished{0};
    std::atomic<bool> send_failed{false};
    std::thread sender([&] {
        static char buf[16 * 1024];
        while (client->Send(buf, sizeof(buf))) {}
        send_failed = true;
        finished++;
    });
    std::thread teardown([&] {
        std::this_thread::sleep_for(200ms);  // sender is blocked by now
        client->Disconnect();
        finished++;
    });

    if (!WaitFor([&] { return finished == 2; },
                 std::chrono::milliseconds(P2pProxyClient::SEND_TIMEOUT_MS + 10000))) {
        printf("FAIL\n    send/Disconnect did not finish (deadlock)\n");
        fflush(stdout);
        std::_Exit(1);  // Cannot join or destroy the client safely
    }
    sender.join();
    teardown.join();
    delete client;
    close(host_fd);
    close(listen_fd);
    return send_failed;
}

// A joiner that authenticates against a running server
static bool AuthenticateJoiner(P2pProxyServer& server, P2pProxyClient& client,
                               uint32_t virtual_ip) {
    ryu_ldn::protocol::ExternalProxyToken token{};
    token.virtual_ip = virtual_ip;
    std::memset(token.token, 0xAB, sizeof(token.token));
    token.address_family = 2;
    server.AddWaitingToken(token);

    ryu_ldn::protocol::ExternalProxyConfig config{};
    std::memcpy(config.token, token.token, sizeof(config.token));
    config.address_family = 2;
    return client.Connect("127.0.0.1", server.GetPrivatePort()) &&
           client.PerformAuth(config) && client.EnsureProxyReady(4000);
}

/**
 * A retired session sits in m_zombie_sessions until it is reaped.
 * ReapZombieSessions copied each pointer out with get(), so the slot resets
 * after it deleted the session before its thread was joined, and the
 * reaper then deleted it again.
 */
static bool test_reap_joins_before_delete() {
    P2pProxyServer server;
    if (!server.Start()) {
        printf("FAIL\n    server start\n");
        return false;
    }
    P2pProxyClient client;
    if (!AuthenticateJoiner(server, client, 0x0A720002)) {
        printf("FAIL\n    joiner did not authenticate\n");
        return false;
    }
    client.Disconnect();
    std::this_thread::sleep_for(300ms);  // the session retires itself
    server.Stop();                       // reaps it
    return true;
}

int main() {
    printf("\n=== P2P Lock Tests ===\n");
    signal(SIGPIPE, SIG_IGN);

    int passed = 0, total = 0;
    auto run = [&](const char* name, bool (*fn)()) {
        printf("  [TEST] %s... ", name);
        fflush(stdout);
        total++;
        if (fn()) {
            printf("PASS\n");
            passed++;
        }
    };
    run("disconnect_while_send_blocked_on_stalled_host",
        test_disconnect_while_send_blocked_on_stalled_host);
    run("reap_joins_before_delete", test_reap_joins_before_delete);

    printf("  Results: %d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
