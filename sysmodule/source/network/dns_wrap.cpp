/**
 * @file dns_wrap.cpp
 * @brief Linker wrappers for resolver functions that crash in our sysmodule
 *
 * libnx's getaddrinfo() / gethostbyname() / getnameinfo() route to the
 * `sfdnsres` system service. From the boot2 sysmodule context (TitleID
 * 0x4200000000000010) those calls reliably DABRT — likely because of a
 * resource-limit / capability mismatch around the way the service hands
 * out a TransferMemory-backed buffer. Diagnosed in upnp_port_mapper's
 * BSD pre-flight test where `getaddrinfo("239.255.255.250","1900",AF_INET)`
 * never returned and never logged a result line — the syscall chain
 * panics inside libnx before getting back to us.
 *
 * This compilation unit defines `__wrap_*` versions and the Makefile
 * adds `-Wl,--wrap=getaddrinfo,--wrap=freeaddrinfo,--wrap=getnameinfo,--wrap=gai_strerror`.
 * The linker redirects every call (including those baked into
 * `libminiupnpc.a`) to these implementations, so miniupnpc's SSDP
 * discovery + HTTP control flow can run without ever touching sfdnsres.
 *
 * **Scope of substitution**: IPv4 numeric literals are resolved via
 * `inet_pton`. Hostname resolution is performed via direct UDP DNS
 * queries to the configured (or fallback) DNS server, bypassing
 * sfdnsres entirely. This allows both IP-literal and hostname-based
 * lookups to work from the boot2 sysmodule context.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include "../debug/log.hpp"

#ifdef __SWITCH__
/**
 * Declare nifmGetCurrentIpConfigInfo with C linkage to match the
 * symbol exported by libnx. The <switch/services/nifm.h> header is
 * intentionally NOT included because it pulls in the Stratosphere
 * Result type (ams::Result), which conflicts with this compilation
 * unit's minimal dependency set. We declare the function with plain
 * C types (uint32_t*) and check the return value against 0 (success).
 */
extern "C" uint32_t nifmGetCurrentIpConfigInfo(uint32_t* out_addr,
                                                uint32_t* out_subnet,
                                                uint32_t* out_gw,
                                                uint32_t* out_dns1,
                                                uint32_t* out_dns2);
/// libnx <switch/kernel/random.h>, declared here for the same reason
extern "C" void randomGet(void* buf, size_t len);
#else
#include <random>
#endif

#include <poll.h>
#include <chrono>

#include <unistd.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

// Forward declaration needed for EAI_MEMORY cleanup in __wrap_getaddrinfo
extern "C" void __wrap_freeaddrinfo(struct addrinfo* res);

/**
 * @brief Storage struct for contiguous addrinfo + sockaddr_in allocation.
 *
 * addrinfo and sockaddr_in are allocated together to keep the ai_addr
 * pointer valid after a single malloc/free. Using a struct (not union)
 * ensures ai_family and sa.sin_addr.s_addr occupy separate memory,
 * preventing the overlap bug where assigning ai_family = AF_INET (2)
 * corrupted the resolved IP address on ARM64.
 */
struct AddrinfoStorage {
    struct addrinfo ai;
    struct sockaddr_in sa;
};

namespace {

/**
 * @brief An EAI_* code as an always-negative internal error
 *
 * Internal functions return an IP count (>0) or a negative error.
 * newlib's EAI_* values are positive, glibc's (host tests) negative, so
 * a plain -EAI_AGAIN would read as "3 IPs" on the host.
 */
constexpr int DnsErr(int eai) {
    return eai > 0 ? -eai : eai;
}

/**
 * @brief Encode a hostname into DNS wire-format label sequence.
 * @param hostname  Null-terminated hostname string (e.g. "www.example.com").
 * @param buf       Output buffer for the encoded name.
 * @param buf_size  Size of the output buffer.
 * @return Number of bytes written to buf, or 0 if the encoded name exceeds buf_size.
 *
 * Labels are length-prefixed; the sequence is terminated by a zero-length label.
 * "www.example.com" becomes "\x03www\x07example\x03com\x00".
 */
size_t EncodeDnsName(const char* hostname, uint8_t* buf, size_t buf_size) {
    if (!hostname || !buf || buf_size == 0) {
        return 0;
    }

    size_t pos = 0;
    const char* src = hostname;

    while (*src) {
        // Find the next dot (or end of string)
        const char* dot = std::strchr(src, '.');
        size_t label_len = dot ? static_cast<size_t>(dot - src) : std::strlen(src);

        // DNS labels must be 1..63 bytes
        if (label_len == 0 || label_len > 63) {
            return 0;
        }

        // Need space for: 1 byte length + label_len bytes + at least 1 byte terminator
        if (pos + 1 + label_len + 1 > buf_size) {
            return 0;
        }

        buf[pos++] = static_cast<uint8_t>(label_len);
        std::memcpy(buf + pos, src, label_len);
        pos += label_len;

        if (dot) {
            src = dot + 1;  // Skip the dot
        } else {
            break;
        }
    }

    // Zero-length label (root terminator)
    if (pos + 1 > buf_size) {
        return 0;
    }
    buf[pos++] = 0x00;

    return pos;
}

/**
 * @brief Build a DNS query packet for an A record.
 * @param hostname     The hostname to resolve.
 * @param query_id     The query ID to embed in the DNS header.
 * @param packet       Output buffer for the DNS query packet.
 * @param packet_size  Size of the output buffer.
 * @return Size of the built packet in bytes, or -1 on error.
 *
 * The query requests an A record (QTYPE=1) in the IN class (QCLASS=1)
 * with the recursion-desired flag set.
 */
ssize_t BuildDnsQuery(const char* hostname, uint16_t query_id,
                      uint8_t* packet, size_t packet_size) {
    if (!hostname || hostname[0] == '\0' || !packet) {
        return -1;
    }

    // Encode the name first to determine its length
    uint8_t name_buf[256];
    size_t name_len = EncodeDnsName(hostname, name_buf, sizeof(name_buf));
    if (name_len == 0) {
        return -1;
    }

    // Total packet size: 12 (header) + name_len + 4 (QTYPE + QCLASS)
    size_t total_size = 12 + name_len + 4;
    if (total_size > packet_size) {
        return -1;
    }

    size_t pos = 0;

    // DNS Header (12 bytes)
    packet[pos++] = static_cast<uint8_t>((query_id >> 8) & 0xFF);
    packet[pos++] = static_cast<uint8_t>(query_id & 0xFF);
    packet[pos++] = 0x01;  // Flags: RD=1 (recursion desired) → 0x0100
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;  // QDCOUNT = 1
    packet[pos++] = 0x01;
    packet[pos++] = 0x00;  // ANCOUNT = 0
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;  // NSCOUNT = 0
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;  // ARCOUNT = 0
    packet[pos++] = 0x00;

    // Question section: encoded name + QTYPE + QCLASS
    std::memcpy(packet + pos, name_buf, name_len);
    pos += name_len;

    // QTYPE = A (1) in big-endian
    packet[pos++] = 0x00;
    packet[pos++] = 0x01;

    // QCLASS = IN (1) in big-endian
    packet[pos++] = 0x00;
    packet[pos++] = 0x01;

    return static_cast<ssize_t>(pos);
}

/// Google DNS, the last resort (0x08080808 is the same in either byte order)
constexpr uint32_t kFallbackDnsIp = 0x08080808;

/// Attempts per lookup, and the reply wait for each one
constexpr int kDnsAttempts = 3;
constexpr uint32_t kDnsAttemptTimeoutMs = 1500;

/**
 * @brief List the DNS servers to try, in order
 * @param out  Receives up to 3 IPv4 addresses in network byte order.
 * @return Number of servers written (at least 1).
 *
 * The nifm primary, the nifm secondary, then 8.8.8.8, without
 * duplicates. The nifm values are already in network byte order.
 */
static int GetDnsServers(uint32_t (&out)[3]) {
    int n = 0;
    auto add = [&](uint32_t ip) {
        if (ip == 0) return;
        for (int i = 0; i < n; i++) {
            if (out[i] == ip) return;
        }
        out[n++] = ip;
    };
#ifdef __SWITCH__
    uint32_t out_addr = 0, out_subnet = 0, out_gw = 0;
    uint32_t out_dns1 = 0, out_dns2 = 0;
    if (nifmGetCurrentIpConfigInfo(&out_addr, &out_subnet, &out_gw, &out_dns1, &out_dns2) == 0) {
        add(out_dns1);
        add(out_dns2);
    }
#endif
    add(kFallbackDnsIp);
    return n;
}

/**
 * @brief A fresh, unpredictable 16-bit query ID
 */
static uint16_t NewQueryId() {
    uint16_t id = 0;
#ifdef __SWITCH__
    randomGet(&id, sizeof(id));
#else
    std::random_device rd;
    id = static_cast<uint16_t>(rd());
#endif
    return id;
}

/**
 * @brief Skip over a DNS name in a response packet (handles labels and pointers).
 * @param p     Current position in the response buffer.
 * @param end   End of the response buffer (one past last valid byte).
 * @return Pointer to the byte after the name, or nullptr if the name overflows the buffer.
 *
 * DNS names use label sequences (length-prefixed) and may contain compression
 * pointers (2-byte entries starting with 0xC0). This function advances past
 * the name without following pointers, since we only need to skip over it.
 */
static const uint8_t* SkipDnsName(const uint8_t* p, const uint8_t* end) {
    if (!p || !end) {
        return nullptr;
    }

    while (p < end) {
        uint8_t label_len = *p;

        // Compression pointer: top 2 bits = 11
        if ((label_len & 0xC0) == 0xC0) {
            // Pointer is 2 bytes — advance past it
            if (p + 2 > end) {
                return nullptr;
            }
            return p + 2;
        }

        // Zero-length label: end of name
        if (label_len == 0) {
            return p + 1;
        }

        // Regular label: skip length byte + label data
        if (p + 1 + label_len > end) {
            return nullptr;
        }
        p += 1 + label_len;
    }

    // Ran past the end without terminating
    return nullptr;
}

/**
 * @brief Parse a DNS response packet and extract IPv4 addresses from A records.
 * @param response  Raw DNS response bytes.
 * @param resp_len  Length of the response in bytes.
 * @param out_ips   Output array for resolved IPv4 addresses (network byte order).
 * @param max_ips   Maximum number of IPs the output array can hold.
 * @return Number of IPs extracted (>=1 on success), or negative EAI_* error code.
 *
 * Validates the DNS header (QR=1, RCODE=0, ANCOUNT>0), skips the question
 * section, and iterates over answer records extracting A records (TYPE=1,
 * CLASS=1, RDLENGTH=4). Returns EAI_NONAME for NXDOMAIN, EAI_FAIL for
 * SERVFAIL/REFUSED, EAI_AGAIN for truncated responses.
 */
static int ParseDnsResponse(const uint8_t* response, size_t resp_len,
                             uint32_t* out_ips, int max_ips) {
    if (!response || resp_len < 12 || !out_ips || max_ips <= 0) {
        return -1;
    }

    // Parse header
    uint16_t flags = (static_cast<uint16_t>(response[2]) << 8) | response[3];
    uint16_t rcode = flags & 0x000F;

    // QR bit must be 1 (response)
    if (!(flags & 0x8000)) {
        return -1;
    }

    // TC (truncated) bit
    if (flags & 0x0200) {
        return DnsErr(EAI_AGAIN);
    }

    // RCODE
    if (rcode == 3) {
        return DnsErr(EAI_NONAME);  // NXDOMAIN
    }
    if (rcode == 2 || rcode == 5) {
        return DnsErr(EAI_FAIL);  // SERVFAIL or REFUSED
    }
    if (rcode != 0) {
        return DnsErr(EAI_FAIL);  // Other errors
    }

    uint16_t ancount = (static_cast<uint16_t>(response[6]) << 8) | response[7];
    if (ancount == 0) {
        return DnsErr(EAI_NONAME);
    }

    uint16_t qdcount = (static_cast<uint16_t>(response[4]) << 8) | response[5];
    const uint8_t* p = response + 12;
    const uint8_t* end = response + resp_len;

    // Skip all question sections (name + QTYPE + QCLASS each)
    for (uint16_t q = 0; q < qdcount; ++q) {
        p = SkipDnsName(p, end);
        if (!p || p + 4 > end) {
            return -1;
        }
        p += 4;  // Skip QTYPE and QCLASS (4 bytes)
    }

    // Parse answer records
    int ip_count = 0;
    for (uint16_t i = 0; i < ancount && ip_count < max_ips; ++i) {
        // Skip the name
        p = SkipDnsName(p, end);
        if (!p || p + 10 > end) {
            return -1;
        }

        // TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        uint16_t rtype = (static_cast<uint16_t>(p[0]) << 8) | p[1];
        uint16_t rclass = (static_cast<uint16_t>(p[2]) << 8) | p[3];
        uint32_t rttl = (static_cast<uint32_t>(p[4]) << 24) | (static_cast<uint32_t>(p[5]) << 16) |
                        (static_cast<uint32_t>(p[6]) << 8)  | p[7];
        uint16_t rdlength = (static_cast<uint16_t>(p[8]) << 8) | p[9];
        LOG_INFO("DNS answer[%u]: type=%u class=%u ttl=%u rdlen=%u offset=%td",
                 i, rtype, rclass, rttl, rdlength, p - response);
        p += 10;

        if (p + rdlength > end) {
            return -1;
        }

        // A record: TYPE=1, CLASS=1, RDLENGTH=4
        if (rtype == 1 && rclass == 1 && rdlength == 4) {
            if (ip_count < max_ips) {
                uint32_t ip = (static_cast<uint32_t>(p[0]) << 24) |
                              (static_cast<uint32_t>(p[1]) << 16) |
                              (static_cast<uint32_t>(p[2]) << 8)  |
                              static_cast<uint32_t>(p[3]);
                LOG_INFO("DNS A record: raw_ip=0x%08X -> %u.%u.%u.%u",
                         ip, p[0], p[1], p[2], p[3]);
                out_ips[ip_count++] = ip;
            }
        }

        p += rdlength;
    }

    return ip_count > 0 ? ip_count : DnsErr(EAI_NONAME);
}

/**
 * @brief One DNS query to one server, waiting for its genuine answer
 * @param hostname    Null-terminated hostname to resolve.
 * @param server_ip   DNS server IPv4 address, network byte order.
 * @param port        DNS server port (53; tests use their own).
 * @param timeout_ms  How long to wait for a matching reply.
 * @param out_ips     Output array for resolved IPv4 addresses (host byte order).
 * @param max_ips     Maximum number of IPs the output array can hold.
 * @return Number of resolved IPs (>=1 on success), or negative EAI_* error code
 *         (DnsErr(EAI_AGAIN) when no matching reply arrived in time).
 *
 * A reply counts only if it comes from server_ip:port and carries this
 * query's random ID. Anything else (a stale reply, or one forged by an
 * off-path host on the LAN) is dropped and the wait continues until the
 * deadline.
 */
static int QueryDnsServer(const char* hostname, uint32_t server_ip, uint16_t port,
                          uint32_t timeout_ms, uint32_t* out_ips, int max_ips) {
    if (!hostname || !out_ips || max_ips <= 0) {
        return DnsErr(EAI_FAIL);
    }

    const uint16_t query_id = NewQueryId();
    uint8_t query_buf[512];
    ssize_t query_len = BuildDnsQuery(hostname, query_id, query_buf, sizeof(query_buf));
    if (query_len < 0) {
        return DnsErr(EAI_FAIL);
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return DnsErr(EAI_FAIL);
    }

    struct sockaddr_in dns_addr{};
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(port);
    dns_addr.sin_addr.s_addr = server_ip;

    LOG_VERBOSE("DNS query for '%s': sending %zd bytes to %s", hostname, query_len,
                inet_ntoa(dns_addr.sin_addr));

    ssize_t sent = sendto(sock, query_buf, static_cast<size_t>(query_len), 0,
                           reinterpret_cast<struct sockaddr*>(&dns_addr),
                           sizeof(dns_addr));
    if (sent < 0) {
        close(sock);
        return DnsErr(EAI_AGAIN);
    }

    using Clock = std::chrono::steady_clock;
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    uint8_t resp_buf[512];
    ssize_t recv_len = -1;
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        if (left <= 0) {
            break;
        }
        struct pollfd pfd = {sock, POLLIN, 0};
        int pr = poll(&pfd, 1, static_cast<int>(left));
        if (pr < 0 && errno == EINTR) {
            continue;
        }
        if (pr <= 0) {
            break;
        }

        struct sockaddr_in from_addr{};
        socklen_t from_len = sizeof(from_addr);
        ssize_t n = recvfrom(sock, resp_buf, sizeof(resp_buf), 0,
                             reinterpret_cast<struct sockaddr*>(&from_addr), &from_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            break;
        }
        const uint16_t resp_id = n >= 2 ? static_cast<uint16_t>((resp_buf[0] << 8) | resp_buf[1]) : 0;
        if (n < 12 || from_addr.sin_addr.s_addr != server_ip ||
            from_addr.sin_port != htons(port) || resp_id != query_id) {
            LOG_WARN("DNS: ignoring %zd-byte reply from %s:%u id=0x%04X (expected id 0x%04X)",
                     n, inet_ntoa(from_addr.sin_addr), ntohs(from_addr.sin_port), resp_id, query_id);
            continue;
        }
        recv_len = n;
        break;
    }

    close(sock);

    if (recv_len < 12) {
        return DnsErr(EAI_AGAIN);
    }

    {
        uint16_t resp_fl  = (static_cast<uint16_t>(resp_buf[2]) << 8) | resp_buf[3];
        uint16_t resp_qd  = (static_cast<uint16_t>(resp_buf[4]) << 8) | resp_buf[5];
        uint16_t resp_an  = (static_cast<uint16_t>(resp_buf[6]) << 8) | resp_buf[7];
        uint16_t resp_ns  = (static_cast<uint16_t>(resp_buf[8]) << 8) | resp_buf[9];
        uint16_t resp_ar  = (static_cast<uint16_t>(resp_buf[10]) << 8) | resp_buf[11];
        LOG_INFO("DNS response: %zd bytes, id=0x%04X flags=0x%04X QD=%u AN=%u NS=%u AR=%u",
                 recv_len, query_id, resp_fl, resp_qd, resp_an, resp_ns, resp_ar);
    }

    // Hex dump of DNS response — one LOG_INFO per 16-byte line
    {
        size_t dump_len = (recv_len < 64) ? static_cast<size_t>(recv_len) : 64;
        for (size_t i = 0; i < dump_len; i += 16) {
            LOG_INFO("DNS hex %04zx: %02x %02x %02x %02x %02x %02x %02x %02x  "
                     "%02x %02x %02x %02x %02x %02x %02x %02x",
                     i,
                     (i+0 < dump_len) ? resp_buf[i+0] : 0,
                     (i+1 < dump_len) ? resp_buf[i+1] : 0,
                     (i+2 < dump_len) ? resp_buf[i+2] : 0,
                     (i+3 < dump_len) ? resp_buf[i+3] : 0,
                     (i+4 < dump_len) ? resp_buf[i+4] : 0,
                     (i+5 < dump_len) ? resp_buf[i+5] : 0,
                     (i+6 < dump_len) ? resp_buf[i+6] : 0,
                     (i+7 < dump_len) ? resp_buf[i+7] : 0,
                     (i+8 < dump_len) ? resp_buf[i+8] : 0,
                     (i+9 < dump_len) ? resp_buf[i+9] : 0,
                     (i+10 < dump_len) ? resp_buf[i+10] : 0,
                     (i+11 < dump_len) ? resp_buf[i+11] : 0,
                     (i+12 < dump_len) ? resp_buf[i+12] : 0,
                     (i+13 < dump_len) ? resp_buf[i+13] : 0,
                     (i+14 < dump_len) ? resp_buf[i+14] : 0,
                     (i+15 < dump_len) ? resp_buf[i+15] : 0);
        }
    }

    return ParseDnsResponse(resp_buf, static_cast<size_t>(recv_len), out_ips, max_ips);
}

/**
 * @brief Resolve over a list of servers, one attempt each in turn
 *
 * Makes kDnsAttempts attempts, moving down the list (the last server
 * takes the remaining attempts). Stops at the first answer, or at
 * NXDOMAIN, which is authoritative.
 */
static int ResolveWithServers(const char* hostname, const uint32_t* servers, int server_count,
                              uint16_t port, uint32_t attempt_timeout_ms,
                              uint32_t* out_ips, int max_ips) {
    int result = DnsErr(EAI_AGAIN);
    for (int attempt = 0; attempt < kDnsAttempts && server_count > 0; attempt++) {
        const uint32_t server = servers[attempt < server_count ? attempt : server_count - 1];
        result = QueryDnsServer(hostname, server, port, attempt_timeout_ms, out_ips, max_ips);
        if (result > 0) {
            LOG_INFO("DNS resolved '%s' to %d IP(s) (attempt %d)", hostname, result, attempt + 1);
            return result;
        }
        if (result == DnsErr(EAI_NONAME)) {
            break;
        }
        LOG_WARN("DNS attempt %d for '%s' failed: result=%d", attempt + 1, hostname, result);
    }
    LOG_WARN("DNS resolve '%s' failed: result=%d", hostname, result);
    return result;
}

/**
 * @brief Resolve a hostname with direct UDP DNS queries
 * @return Number of resolved IPs (>=1 on success), or negative EAI_* error code.
 *
 * Up to 3 attempts of 1.5 s: the nifm primary DNS, the secondary, then
 * 8.8.8.8. Only A records (IPv4); truncated responses (TC bit) return
 * EAI_AGAIN since TCP fallback is not implemented.
 */
static int ResolveHostnameDns(const char* hostname, uint32_t* out_ips, int max_ips) {
    uint32_t servers[3];
    const int count = GetDnsServers(servers);
    return ResolveWithServers(hostname, servers, count, 53, kDnsAttemptTimeoutMs, out_ips, max_ips);
}

} // anonymous namespace

extern "C" {

int __wrap_getaddrinfo(const char* node, const char* service,
                       const struct addrinfo* hints,
                       struct addrinfo** res) {
    if (!res) {
        errno = EINVAL;
        return EAI_SYSTEM;
    }
    *res = nullptr;

    if (!node && !service) {
        return EAI_NONAME;
    }

    int family = hints ? hints->ai_family : AF_UNSPEC;
    if (family != AF_UNSPEC && family != AF_INET) {
        return EAI_FAMILY;
    }

    uint16_t port = 0;
    if (service) {
        port = static_cast<uint16_t>(std::atoi(service));
    }

    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    if (node) {
        if (::inet_pton(AF_INET, node, &sa.sin_addr) != 1) {
            // Not an IP literal — attempt DNS resolution
            uint32_t resolved_ips[8];
            int num_ips = ResolveHostnameDns(node, resolved_ips, 8);

            if (num_ips <= 0) {
                if (num_ips == 0) return EAI_NONAME;
                // Map negative EAI codes back to positive for getaddrinfo
                if (num_ips == DnsErr(EAI_AGAIN)) return EAI_AGAIN;
                if (num_ips == DnsErr(EAI_NONAME)) return EAI_NONAME;
                if (num_ips == DnsErr(EAI_FAIL))   return EAI_FAIL;
                return EAI_AGAIN;  // unknown error → retryable
            }

            // Build addrinfo linked list from resolved IPs
            struct addrinfo* head = nullptr;
            struct addrinfo* tail = nullptr;

            for (int i = 0; i < num_ips; ++i) {
                struct sockaddr_in ip_sa{};
                ip_sa.sin_family = AF_INET;
                ip_sa.sin_port = htons(port);
                ip_sa.sin_addr.s_addr = htonl(resolved_ips[i]);

                // codeql[cpp/suspicious-allocation-size] — AddrinfoStorage is a struct
                // containing addrinfo + sockaddr_in, not an array of addrinfo.
                auto* storage = static_cast<AddrinfoStorage*>(
                    std::malloc(sizeof(AddrinfoStorage)));
                if (!storage) {
                    if (head) __wrap_freeaddrinfo(head);
                    return EAI_MEMORY;
                }

                std::memset(&storage->ai, 0, sizeof(struct addrinfo));
                storage->sa = ip_sa;
                storage->ai.ai_family   = AF_INET;
                storage->ai.ai_socktype = hints ? hints->ai_socktype : 0;
                storage->ai.ai_protocol = hints ? hints->ai_protocol : 0;
                storage->ai.ai_addrlen  = sizeof(struct sockaddr_in);
                storage->ai.ai_addr     = reinterpret_cast<struct sockaddr*>(&storage->sa);
                storage->ai.ai_canonname = nullptr;
                storage->ai.ai_next      = nullptr;

                auto* ai = &storage->ai;
                if (!head) {
                    head = ai;
                } else {
                    tail->ai_next = ai;
                }
                tail = ai;
            }

            *res = head;
            return 0;
        }
    } else {
        const bool passive = hints && (hints->ai_flags & AI_PASSIVE);
        sa.sin_addr.s_addr = htonl(passive ? INADDR_ANY : INADDR_LOOPBACK);
    }

    // codeql[cpp/suspicious-allocation-size] — AddrinfoStorage is a struct
    // containing addrinfo + sockaddr_in, not an array of addrinfo.
    auto* storage = static_cast<AddrinfoStorage*>(
        std::malloc(sizeof(AddrinfoStorage)));
    if (!storage) return EAI_MEMORY;

    std::memset(&storage->ai, 0, sizeof(struct addrinfo));
    storage->sa = sa;
    storage->ai.ai_family   = AF_INET;
    storage->ai.ai_socktype = hints ? hints->ai_socktype : 0;
    storage->ai.ai_protocol = hints ? hints->ai_protocol : 0;
    storage->ai.ai_addrlen  = sizeof(struct sockaddr_in);
    storage->ai.ai_addr     = reinterpret_cast<struct sockaddr*>(&storage->sa);
    storage->ai.ai_canonname = nullptr;
    storage->ai.ai_next      = nullptr;

    *res = &storage->ai;
    return 0;
}

void __wrap_freeaddrinfo(struct addrinfo* res) {
    while (res) {
        struct addrinfo* next = res->ai_next;
        std::free(res);   // ai_addr is inside the same allocation block
        res = next;
    }
}

int __wrap_getnameinfo(const struct sockaddr* sa, socklen_t salen,
                       char* host, socklen_t hostlen,
                       char* serv, socklen_t servlen, int /*flags*/) {
    if (!sa || salen < static_cast<socklen_t>(sizeof(struct sockaddr_in))) {
        return EAI_FAMILY;
    }
    if (sa->sa_family != AF_INET) {
        return EAI_FAMILY;
    }

    const auto* sin = reinterpret_cast<const struct sockaddr_in*>(sa);

    if (host && hostlen > 0) {
        if (::inet_ntop(AF_INET, &sin->sin_addr, host, hostlen) == nullptr) {
            return EAI_OVERFLOW;
        }
    }
    if (serv && servlen > 0) {
        std::snprintf(serv, servlen, "%u", ntohs(sin->sin_port));
    }
    return 0;
}

const char* __wrap_gai_strerror(int /*ecode*/) {
    return "dns error";
}

} // extern "C"
