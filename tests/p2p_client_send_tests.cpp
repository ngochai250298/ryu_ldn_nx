/**
 * @file p2p_client_send_tests.cpp
 * @brief Real P2pProxyClient: a host that stops reading cannot wedge teardown
 *
 * Builds p2p/p2p_proxy_client.cpp against tests/host_shim. Sends run under
 * the client mutex, so before SO_SNDTIMEO a send() blocked on a full socket
 * held it forever and Disconnect() (which needs it) never returned.
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
#include <thread>

#include "p2p/p2p_proxy_client.hpp"

using ams::mitm::p2p::P2pProxyClient;

int main() {
    printf("\n=== P2P Client Send Tests ===\n");
    signal(SIGPIPE, SIG_IGN);

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
        printf("  FAIL: listener setup\n");
        return 1;
    }

    auto* client = new P2pProxyClient();
    if (!client->Connect("127.0.0.1", ntohs(addr.sin_port))) {
        printf("  FAIL: connect\n");
        return 1;
    }
    int host_fd = accept(listen_fd, nullptr, nullptr);

    printf("  [TEST] disconnect_while_send_blocked_on_stalled_host... ");
    fflush(stdout);
    std::atomic<int> finished{0};
    std::atomic<bool> send_failed{false};
    std::thread sender([&] {
        static char buf[16 * 1024];
        while (client->Send(buf, sizeof(buf))) {}
        send_failed = true;
        finished++;
    });
    std::thread teardown([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));  // sender is blocked by now
        client->Disconnect();
        finished++;
    });

    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(P2pProxyClient::SEND_TIMEOUT_MS + 10000);
    while (finished < 2 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (finished < 2) {
        printf("FAIL\n    send/Disconnect did not finish (deadlock)\n");
        fflush(stdout);
        std::_Exit(1);  // Cannot join or destroy the client safely
    }
    sender.join();
    teardown.join();
    delete client;
    close(host_fd);
    close(listen_fd);

    if (!send_failed) {
        printf("FAIL\n");
        return 1;
    }
    printf("PASS\n  Results: 1/1 passed\n");
    return 0;
}
