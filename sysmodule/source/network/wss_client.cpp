/**
 * @file wss_client.cpp
 * @brief Secure WebSocket transport implementation
 *
 * ## Implementation Notes
 *
 * ### Locking
 * mbedTLS contexts are not safe for concurrent read and write, and a read
 * may itself write (alerts, or our pong). Every mbedTLS call therefore runs
 * under m_tls_mutex. The receive thread waits for readability with poll()
 * *outside* that lock, so a long receive timeout never blocks game sends,
 * the same property TcpClient gets from its separate send/recv mutexes.
 *
 * ### Receive path
 * Decrypted bytes are fed through a streaming frame decoder. Payload bytes
 * of binary/continuation frames go straight into TcpClient's PacketBuffer,
 * so fragmented messages need no extra buffer and the inherited
 * receive_packet() reassembles RyuLdn packets exactly as it does for TCP.
 *
 * ### BIO
 * Sends block (Socket::send_all). Reads use the handshake timeout during
 * connect and are non-blocking afterwards (we only read after poll()).
 *
 * @see wss_client.hpp for the public interface
 */

#include "wss_client.hpp"
#include "../debug/log.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <strings.h>

#include <mbedtls/base64.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha1.h>

namespace ryu_ldn::network {

// =============================================================================
// WebSocket framing helpers
// =============================================================================

namespace ws {

size_t encode_header(uint8_t* out, uint8_t opcode, size_t payload_size, const uint8_t* mask_key) {
    size_t offset = 0;
    out[offset++] = static_cast<uint8_t>(0x80 | (opcode & 0x0F));  // FIN

    const uint8_t mask_bit = mask_key ? 0x80 : 0x00;
    if (payload_size < 126) {
        out[offset++] = static_cast<uint8_t>(mask_bit | payload_size);
    } else if (payload_size <= 0xFFFF) {
        out[offset++] = static_cast<uint8_t>(mask_bit | 126);
        out[offset++] = static_cast<uint8_t>(payload_size >> 8);
        out[offset++] = static_cast<uint8_t>(payload_size);
    } else {
        out[offset++] = static_cast<uint8_t>(mask_bit | 127);
        for (int shift = 56; shift >= 0; shift -= 8) {
            out[offset++] = static_cast<uint8_t>(static_cast<uint64_t>(payload_size) >> shift);
        }
    }

    if (mask_key) {
        std::memcpy(out + offset, mask_key, 4);
        offset += 4;
    }
    return offset;
}

void apply_mask(uint8_t* data, size_t size, const uint8_t* mask_key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= mask_key[i & 3];
    }
}

bool compute_accept(const char* key, char* out, size_t out_size) {
    static constexpr const char* WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    char concat[128];
    int len = std::snprintf(concat, sizeof(concat), "%s%s", key, WS_GUID);
    if (len <= 0 || static_cast<size_t>(len) >= sizeof(concat)) {
        return false;
    }

    unsigned char digest[20];
    if (mbedtls_sha1_ret(reinterpret_cast<const unsigned char*>(concat), static_cast<size_t>(len), digest) != 0) {
        return false;
    }

    size_t written = 0;
    if (mbedtls_base64_encode(reinterpret_cast<unsigned char*>(out), out_size, &written, digest, sizeof(digest)) != 0) {
        return false;
    }
    return true;
}

namespace {

/**
 * @brief Find a header value (case-insensitive name) in a header block
 *
 * @return Pointer to the first non-space value character, or nullptr.
 *         The value ends at the next CR.
 */
const char* find_header(const char* response, const char* name) {
    const size_t name_len = std::strlen(name);
    const char* line = std::strstr(response, "\r\n");
    while (line != nullptr && line[2] != '\0') {
        line += 2;
        if (strncasecmp(line, name, name_len) == 0 && line[name_len] == ':') {
            const char* value = line + name_len + 1;
            while (*value == ' ' || *value == '\t') {
                value++;
            }
            return value;
        }
        line = std::strstr(line, "\r\n");
    }
    return nullptr;
}

/**
 * @brief Compare a header value (terminated by CR or spaces) with a string
 */
bool header_equals(const char* value, const char* expected, bool ignore_case) {
    const size_t expected_len = std::strlen(expected);
    const int cmp = ignore_case ? strncasecmp(value, expected, expected_len)
                                : std::strncmp(value, expected, expected_len);
    if (cmp != 0) {
        return false;
    }
    const char end = value[expected_len];
    return end == '\r' || end == ' ' || end == '\t' || end == '\0';
}

} // anonymous namespace

UpgradeResult check_upgrade_response(const char* response, const char* expected_accept, int& status_code) {
    status_code = 0;
    if (std::strncmp(response, "HTTP/1.1 ", 9) != 0) {
        return UpgradeResult::Malformed;
    }
    status_code = std::atoi(response + 9);
    if (status_code != 101) {
        return UpgradeResult::NotSwitching;
    }

    const char* upgrade = find_header(response, "Upgrade");
    if (upgrade == nullptr || !header_equals(upgrade, "websocket", true)) {
        return UpgradeResult::BadUpgrade;
    }

    const char* accept = find_header(response, "Sec-WebSocket-Accept");
    if (accept == nullptr || !header_equals(accept, expected_accept, false)) {
        return UpgradeResult::BadAccept;
    }
    return UpgradeResult::Ok;
}

} // namespace ws

// =============================================================================
// Transport status
// =============================================================================

namespace {

::ams::os::Mutex g_status_mutex{false};
char g_status[TRANSPORT_STATUS_SIZE] = "Not connected";

/**
 * @brief Largest CA bundle we will load
 *
 * Parsing costs ~1.7x the PEM size plus the PEM itself at peak, all in the
 * 1 MB malloc arena: the 189 KB Mozilla bundle peaks at ~518 KB. Ship only
 * the roots Cloudflare chains to (ISRG X1/X2, GTS R1-R4, SSL.com: ~12 KB,
 * ~35 KB peak); a full bundle fails closed with a clear status instead.
 */
constexpr size_t MAX_CA_FILE_SIZE = 64 * 1024;

/** @brief Largest HTTP upgrade response we accept */
constexpr size_t MAX_UPGRADE_RESPONSE = 1024;

/**
 * @brief Format an mbedTLS error into the transport status
 */
void set_tls_error_status(const char* what, int ret) {
    char status[TRANSPORT_STATUS_SIZE];
    std::snprintf(status, sizeof(status), "%s (-0x%04X)", what, static_cast<unsigned>(-ret));
    set_transport_status(status);
}

} // anonymous namespace

void set_transport_status(const char* status) {
    std::scoped_lock lk(g_status_mutex);
    std::snprintf(g_status, sizeof(g_status), "%s", status);
}

void get_transport_status(char* out, size_t out_size) {
    std::scoped_lock lk(g_status_mutex);
    std::snprintf(out, out_size, "%s", g_status);
}

// =============================================================================
// Construction / Initialization
// =============================================================================

WssClient::WssClient(const config::ServerConfig& server)
    : TcpClient()
    , m_server(server)
{
    mbedtls_entropy_init(&m_entropy);
    mbedtls_ctr_drbg_init(&m_drbg);
    mbedtls_ssl_config_init(&m_ssl_config);
    mbedtls_ssl_init(&m_ssl);
    mbedtls_x509_crt_init(&m_ca);
}

WssClient::~WssClient() {
    // TcpClient's destructor would only run its own disconnect()
    disconnect();
    mbedtls_ssl_free(&m_ssl);
    mbedtls_ssl_config_free(&m_ssl_config);
    mbedtls_ctr_drbg_free(&m_drbg);
    mbedtls_entropy_free(&m_entropy);
    mbedtls_x509_crt_free(&m_ca);
    mbedtls_platform_zeroize(m_server.token, sizeof(m_server.token));
}

bool WssClient::initialize() {
    if (!TcpClient::initialize()) {
        return false;
    }
    if (m_tls_initialized) {
        return true;
    }

#ifdef __SWITCH__
    // mbedtls_hardware_poll (the only entropy source in the portlib build)
    // reads csrng; certificate validity checks need the time service.
    if (R_FAILED(csrngInitialize())) {
        LOG_ERROR("WssClient: csrngInitialize failed");
        return false;
    }
    if (R_FAILED(::ams::time::InitializeForSystem())) {
        LOG_ERROR("WssClient: time service init failed");
        return false;
    }
#endif

    static constexpr const char* PERSONALIZATION = "ryu_ldn_nx wss";
    int ret = mbedtls_ctr_drbg_seed(&m_drbg, mbedtls_entropy_func, &m_entropy,
                                    reinterpret_cast<const unsigned char*>(PERSONALIZATION),
                                    std::strlen(PERSONALIZATION));
    if (ret != 0) {
        LOG_ERROR("WssClient: DRBG seed failed (-0x%04X)", static_cast<unsigned>(-ret));
        return false;
    }

    ret = mbedtls_ssl_config_defaults(&m_ssl_config, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        LOG_ERROR("WssClient: ssl_config_defaults failed (-0x%04X)", static_cast<unsigned>(-ret));
        return false;
    }
    mbedtls_ssl_conf_min_version(&m_ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_authmode(&m_ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&m_ssl_config, &m_ca, nullptr);
    mbedtls_ssl_conf_rng(&m_ssl_config, mbedtls_ctr_drbg_random, &m_drbg);

    m_tls_initialized = true;
    return true;
}

// =============================================================================
// Connection Management
// =============================================================================

ClientResult WssClient::connect(const char* host, uint16_t port, uint32_t timeout_ms) {
    if (m_socket.is_connected()) {
        LOG_WARN("WssClient already connected");
        return ClientResult::AlreadyConnected;
    }
    if (!m_tls_initialized) {
        return ClientResult::NotInitialized;
    }

    if (host == nullptr || host[0] == '\0' || m_server.console_id[0] == '\0' || m_server.token[0] == '\0') {
        LOG_WARN("WssClient: refusing to connect, [server] host/console_id/token not configured or invalid");
        set_transport_status("Not configured (host, console_id, token)");
        return ClientResult::ConnectionFailed;
    }

    LOG_INFO("WssClient::connect(%s, %u, path=%s, console_id=%s)", host, port, m_server.path, m_server.console_id);
    set_transport_status("Connecting");

    {
        // A receive thread may still be inside receive_packet()
        std::scoped_lock recv_lock(m_recv_mutex);
        m_recv_buffer.reset();
        reset_decoder();
        m_lost = false;
    }

    // No trust anchor, no connection
    if (!load_ca(m_server.ca_file)) {
        return ClientResult::TlsFailed;
    }

    SocketResult socket_result = m_socket.connect(host, port, timeout_ms);
    if (socket_result != SocketResult::Success) {
        mbedtls_x509_crt_free(&m_ca);
        LOG_WARN("WssClient: TCP connect failed: %s", socket_result_to_string(socket_result));
        set_transport_status("TCP connect failed");
        return socket_to_client_result(socket_result);
    }
    m_socket.set_nodelay(true);
    // Non-blocking fd: sends stall at most send_all's 5 s writable wait
    // instead of blocking under the TLS lock, and Socket::recv never has to
    // flip O_NONBLOCK on a descriptor another thread is writing to.
    m_socket.set_non_blocking(true);

    ClientResult result = handshake(host, timeout_ms);
    // Only the handshake needs the trust anchors (renegotiation is off)
    mbedtls_x509_crt_free(&m_ca);
    mbedtls_x509_crt_init(&m_ca);

    if (result == ClientResult::Success) {
        result = upgrade(host, port);
    }
    if (result != ClientResult::Success) {
        close_transport(false);
        return result;
    }
    return ClientResult::Success;
}

void WssClient::disconnect() {
    // The reassembly buffer is left alone (a reader may hold it); connect()
    // resets it under the receive lock, and nothing is delivered meanwhile
    // because receive_packet() checks the connection first.
    close_transport(true);
    // The teardown only shut the socket down, which wakes a reader polling
    // it. Close once that reader is out (it holds m_recv_mutex across the
    // poll), so its fd number is never freed under it.
    std::scoped_lock recv_lock(m_recv_mutex);
    m_socket.close();
}

bool WssClient::is_connected() const {
    return m_ws_ready && m_socket.is_connected();
}

/**
 * @brief Parse the CA bundle into m_ca
 *
 * The file is read into a temporary malloc buffer (not the 384 KB ExpHeap)
 * and parsed with mbedtls_x509_crt_parse. On Switch it is read with ams::fs,
 * since newlib stdio has no sdmc device in a stratosphere sysmodule.
 */
bool WssClient::load_ca(const char* path) {
    mbedtls_x509_crt_free(&m_ca);
    mbedtls_x509_crt_init(&m_ca);

    size_t file_size = 0;
    unsigned char* pem = nullptr;
    bool too_large = false;
#ifdef __SWITCH__
    ams::fs::FileHandle file;
    if (R_SUCCEEDED(ams::fs::OpenFile(&file, path, ams::fs::OpenMode_Read))) {
        s64 size = 0;
        if (R_SUCCEEDED(ams::fs::GetFileSize(&size, file)) && size > 0) {
            too_large = static_cast<size_t>(size) > MAX_CA_FILE_SIZE;
            pem = too_large ? nullptr : static_cast<unsigned char*>(std::malloc(static_cast<size_t>(size) + 1));
            if (pem != nullptr && R_FAILED(ams::fs::ReadFile(&file_size, file, 0, pem, static_cast<size_t>(size)))) {
                file_size = 0;
            }
        }
        ams::fs::CloseFile(file);
    }
#else
    if (FILE* file = std::fopen(path, "rb")) {
        std::fseek(file, 0, SEEK_END);
        const long size = std::ftell(file);
        std::fseek(file, 0, SEEK_SET);
        if (size > 0) {
            too_large = static_cast<size_t>(size) > MAX_CA_FILE_SIZE;
            pem = too_large ? nullptr : static_cast<unsigned char*>(std::malloc(static_cast<size_t>(size) + 1));
            if (pem != nullptr) {
                file_size = std::fread(pem, 1, static_cast<size_t>(size), file);
            }
        }
        std::fclose(file);
    }
#endif

    int ret = -1;
    if (pem != nullptr && file_size > 0) {
        pem[file_size] = '\0';  // PEM parsing needs the terminator in the length
        ret = mbedtls_x509_crt_parse(&m_ca, pem, file_size + 1);
    }
    std::free(pem);

    // A positive return means some certificates were skipped; usable as
    // long as at least one parsed.
    if (ret < 0 || m_ca.version == 0) {
        if (too_large) {
            LOG_WARN("WssClient: %s is over %zu bytes; ship only the relay's root CAs", path, MAX_CA_FILE_SIZE);
            set_transport_status("TLS: ca_file over 64 KB (trim it)");
        } else {
            LOG_WARN("WssClient: no usable CA certificate in %s", path);
            set_transport_status("TLS: CA file missing or invalid");
        }
        mbedtls_x509_crt_free(&m_ca);
        mbedtls_x509_crt_init(&m_ca);
        return false;
    }
    return true;
}

/**
 * @brief TLS handshake with chain + hostname verification
 */
ClientResult WssClient::handshake(const char* host, uint32_t timeout_ms) {
    int ret = mbedtls_ssl_setup(&m_ssl, &m_ssl_config);
    if (ret == 0) {
        // Sets SNI and the name checked against SAN/CN
        ret = mbedtls_ssl_set_hostname(&m_ssl, host);
    }
    if (ret != 0) {
        set_tls_error_status("TLS: setup failed", ret);
        return ClientResult::TlsFailed;
    }
    // Per-read bound; the fd is non-blocking, so never wait forever
    m_io_timeout_ms = timeout_ms > 0 ? static_cast<int32_t>(timeout_ms) : 5000;
    mbedtls_ssl_set_bio(&m_ssl, this, bio_send, bio_recv, nullptr);

    while ((ret = mbedtls_ssl_handshake(&m_ssl)) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        const uint32_t flags = mbedtls_ssl_get_verify_result(&m_ssl);
        if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED && flags != 0) {
            if (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) {
                set_transport_status("TLS: certificate does not match host");
            } else if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) {
                set_transport_status("TLS: certificate not trusted (ca_file)");
            } else if (flags & (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE)) {
                set_transport_status("TLS: certificate expired or clock wrong");
            } else {
                set_transport_status("TLS: certificate rejected");
            }
            LOG_WARN("WssClient: certificate verification failed (flags=0x%08X)", flags);
        } else if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
            set_transport_status("TLS: handshake timed out");
            LOG_WARN("WssClient: TLS handshake timed out");
            return ClientResult::Timeout;
        } else {
            set_tls_error_status("TLS: handshake failed", ret);
            LOG_WARN("WssClient: TLS handshake failed (-0x%04X)", static_cast<unsigned>(-ret));
        }
        return ClientResult::TlsFailed;
    }

    LOG_INFO("WssClient: TLS established (%s, %s)",
             mbedtls_ssl_get_version(&m_ssl), mbedtls_ssl_get_ciphersuite(&m_ssl));
    return ClientResult::Success;
}

/**
 * @brief Send the HTTP upgrade and validate the 101 response
 *
 * The request buffer holds the token and is wiped before returning.
 */
ClientResult WssClient::upgrade(const char* host, uint16_t port) {
    unsigned char nonce[16];
    char key[32];
    char expected_accept[32];
    size_t key_len = 0;
    if (mbedtls_ctr_drbg_random(&m_drbg, nonce, sizeof(nonce)) != 0 ||
        mbedtls_base64_encode(reinterpret_cast<unsigned char*>(key), sizeof(key), &key_len, nonce, sizeof(nonce)) != 0 ||
        !ws::compute_accept(key, expected_accept, sizeof(expected_accept))) {
        set_transport_status("WebSocket: key generation failed");
        return ClientResult::InternalError;
    }

    char host_header[config::MAX_HOST_LENGTH + 8];
    if (port == 443) {
        std::snprintf(host_header, sizeof(host_header), "%s", host);
    } else {
        std::snprintf(host_header, sizeof(host_header), "%s:%u", host, port);
    }

    char request[640];
    const int request_len = std::snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "X-Console-Id: %s\r\n"
        "Authorization: Bearer %s\r\n"
        "\r\n",
        m_server.path[0] != '\0' ? m_server.path : "/", host_header, key,
        m_server.console_id, m_server.token);

    SocketResult write_result = SocketResult::SocketError;
    if (request_len > 0 && static_cast<size_t>(request_len) < sizeof(request)) {
        write_result = write_all_locked(reinterpret_cast<const uint8_t*>(request), static_cast<size_t>(request_len));
    }
    mbedtls_platform_zeroize(request, sizeof(request));
    if (write_result != SocketResult::Success) {
        set_transport_status("WebSocket: upgrade request failed");
        return ClientResult::ConnectionFailed;
    }

    // Read until the end of the header block; anything after it is
    // already WebSocket frame data.
    char response[MAX_UPGRADE_RESPONSE + 1];
    size_t response_len = 0;
    const char* header_end = nullptr;
    while (header_end == nullptr) {
        if (response_len >= MAX_UPGRADE_RESPONSE) {
            set_transport_status("WebSocket: upgrade response too large");
            return ClientResult::ConnectionFailed;
        }
        int ret = mbedtls_ssl_read(&m_ssl, reinterpret_cast<unsigned char*>(response + response_len),
                                   MAX_UPGRADE_RESPONSE - response_len);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret <= 0) {
            if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
                set_transport_status("WebSocket: no upgrade response");
                return ClientResult::Timeout;
            }
            set_tls_error_status("WebSocket: closed during upgrade", ret);
            return ClientResult::ConnectionFailed;
        }
        response_len += static_cast<size_t>(ret);
        response[response_len] = '\0';
        header_end = std::strstr(response, "\r\n\r\n");
    }

    const size_t header_len = static_cast<size_t>(header_end - response) + 4;
    const char saved = response[header_len];
    response[header_len] = '\0';

    int status_code = 0;
    ws::UpgradeResult upgrade_result = ws::check_upgrade_response(response, expected_accept, status_code);
    response[header_len] = saved;

    switch (upgrade_result) {
        case ws::UpgradeResult::Ok:
            break;
        case ws::UpgradeResult::NotSwitching: {
            char status[TRANSPORT_STATUS_SIZE];
            std::snprintf(status, sizeof(status), "Relay rejected this console (HTTP %d)", status_code);
            set_transport_status(status);
            // The relay answers any auth failure with a plain 404
            LOG_WARN("WssClient: upgrade refused with HTTP %d (check console_id/token/path)", status_code);
            return ClientResult::Rejected;
        }
        case ws::UpgradeResult::BadAccept:
            set_transport_status("WebSocket: bad Sec-WebSocket-Accept");
            LOG_WARN("WssClient: Sec-WebSocket-Accept mismatch");
            return ClientResult::ConnectionFailed;
        default:
            set_transport_status("WebSocket: invalid upgrade response");
            LOG_WARN("WssClient: invalid upgrade response");
            return ClientResult::ConnectionFailed;
    }

    // From here on reads only follow a poll(), so the BIO never blocks
    m_io_timeout_ms = 0;
    {
        // The relay may send frames right after the 101; hold the receive
        // lock so the receive thread cannot decode concurrently.
        std::scoped_lock recv_lock(m_recv_mutex);
        m_ws_ready = true;
        if (response_len > header_len) {
            ClientResult leftover = consume_stream(reinterpret_cast<const uint8_t*>(response) + header_len,
                                                   response_len - header_len);
            if (leftover != ClientResult::Success) {
                return leftover;
            }
        }
    }

    char status[TRANSPORT_STATUS_SIZE];
    std::snprintf(status, sizeof(status), "Secure (%s)", mbedtls_ssl_get_version(&m_ssl));
    set_transport_status(status);
    LOG_INFO("WssClient: WebSocket upgrade complete");
    return ClientResult::Success;
}

/**
 * @brief Tear down the TLS session and the socket
 *
 * Frees the session so its ~33 KB record buffers go back to the malloc
 * arena while disconnected. Safe to call repeatedly and from the receive
 * thread (it does not touch the reassembly buffer).
 */
void WssClient::close_transport(bool send_close) {
    std::scoped_lock lk(m_tls_mutex);
    if (m_ws_ready && send_close) {
        // 1000 = normal closure
        const uint8_t code[2] = {0x03, 0xE8};
        write_frame_locked(ws::OPCODE_CLOSE, code, sizeof(code));
        if (m_ws_ready) {
            mbedtls_ssl_close_notify(&m_ssl);
        }
    }
    teardown_locked(!send_close);
}

/**
 * @brief Free the TLS session and shut the socket down (m_tls_mutex held)
 *
 * Every mbedTLS call runs under m_tls_mutex and re-checks m_ws_ready, so
 * a reader or writer on another thread can never touch a freed context.
 * The socket is shut down, not closed: the receive thread polls it
 * without m_tls_mutex, and a sender can get here from a failed write.
 * disconnect() or the next connect() closes it.
 *
 * @param lost true when an error ended the connection: receive_packet()
 *             then reports ConnectionLost until the next connect
 */
void WssClient::teardown_locked(bool lost) {
    if (lost && m_ws_ready) {
        m_lost = true;
    }
    m_ws_ready = false;
    mbedtls_ssl_free(&m_ssl);
    mbedtls_ssl_init(&m_ssl);
    m_socket.shutdown();
}

/**
 * @brief Tear down after a fatal receive-side error
 */
ClientResult WssClient::fail(const char* status) {
    set_transport_status(status);
    close_transport(false);
    return ClientResult::ConnectionLost;
}

// =============================================================================
// Send
// =============================================================================

SocketResult WssClient::send_bytes(const uint8_t* data, size_t size) {
    std::scoped_lock lk(m_tls_mutex);
    if (!m_ws_ready) {
        return SocketResult::NotConnected;
    }
    return write_frame_locked(ws::OPCODE_BINARY, data, size);
}

/**
 * @brief Build one masked FIN frame in m_frame and write it (lock held)
 */
SocketResult WssClient::write_frame_locked(uint8_t opcode, const uint8_t* data, size_t size) {
    if (size > sizeof(m_frame) - 8) {
        LOG_WARN("WssClient: %zu-byte frame exceeds the send buffer", size);
        return SocketResult::SocketError;
    }

    uint8_t mask[4];
    if (mbedtls_ctr_drbg_random(&m_drbg, mask, sizeof(mask)) != 0) {
        return SocketResult::SocketError;
    }
    const size_t header_size = ws::encode_header(m_frame, opcode, size, mask);
    if (size > 0) {
        std::memcpy(m_frame + header_size, data, size);
        ws::apply_mask(m_frame + header_size, size, mask);
    }
    return write_all_locked(m_frame, header_size + size);
}

SocketResult WssClient::write_all_locked(const uint8_t* data, size_t size) {
    size_t written = 0;
    while (written < size) {
        int ret = mbedtls_ssl_write(&m_ssl, data + written, size - written);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret <= 0) {
            // Includes a send stalled past send_all's 5 s writable wait
            LOG_WARN("WssClient: TLS write failed (-0x%04X)", static_cast<unsigned>(-ret));
            set_tls_error_status("TLS: write failed", ret);
            teardown_locked(true);
            return SocketResult::ConnectionReset;  // -> ClientResult::ConnectionLost
        }
        written += static_cast<size_t>(ret);
    }
    return SocketResult::Success;
}

// =============================================================================
// Receive
// =============================================================================

ClientResult WssClient::receive_packet(protocol::PacketId& type,
                                       void* payload, size_t payload_buffer_size,
                                       size_t& payload_size,
                                       int32_t timeout_ms) {
    payload_size = 0;
    {
        std::scoped_lock recv_lock(m_recv_mutex);
        if (!m_ws_ready) {
            return m_lost ? ClientResult::ConnectionLost : ClientResult::NotConnected;
        }
        // One poll per call: a trickling peer cannot hold the caller for
        // N x timeout_ms, and partial data simply waits for the next call.
        if (!m_recv_buffer.has_complete_packet()) {
            ClientResult result = receive_into_buffer(timeout_ms);
            if (result != ClientResult::Success) {
                return result;
            }
            if (!m_recv_buffer.has_complete_packet()) {
                return ClientResult::Timeout;
            }
        }
    }

    // A complete packet is buffered, so this does no I/O
    ClientResult result = TcpClient::receive_packet(type, payload, payload_buffer_size, payload_size, 0);
    if (result == ClientResult::BufferTooSmall) {
        // Drop it rather than leave it at the head of the stream
        std::scoped_lock recv_lock(m_recv_mutex);
        m_recv_buffer.consume(sizeof(protocol::LdnHeader) + payload_size);
        LOG_WARN("WssClient: dropped %zu-byte packet (caller buffer %zu)", payload_size, payload_buffer_size);
    }
    return result;
}

ClientResult WssClient::receive_into_buffer(int32_t timeout_ms) {
    if (!m_ws_ready) {
        return m_lost ? ClientResult::ConnectionLost : ClientResult::NotConnected;
    }

    // Validate the packet at the head before reading more. The relay sends
    // one valid packet per message, so a bad header is a fatal protocol
    // error; a packet larger than the reassembly buffer is skipped.
    if (m_recv_buffer.size() >= sizeof(protocol::LdnHeader)) {
        protocol::LdnHeader header;
        if (protocol::decode_header(m_recv_buffer.data(), m_recv_buffer.size(), header) != protocol::DecodeResult::Success) {
            LOG_WARN("WssClient: invalid RyuLdn header from relay");
            return fail("Relay sent an invalid packet");
        }
        const size_t packet_size = sizeof(header) + static_cast<size_t>(header.data_size);
        if (packet_size > m_recv_buffer.capacity()) {
            // Head is incomplete, so every buffered byte belongs to it
            LOG_WARN("WssClient: skipping %zu-byte packet (type %u), larger than the receive buffer",
                     packet_size, header.type);
            m_skip_remaining = packet_size - m_recv_buffer.size();
            m_recv_buffer.reset();
        }
    }

    bool pending;
    {
        std::scoped_lock lk(m_tls_mutex);
        pending = mbedtls_ssl_get_bytes_avail(&m_ssl) > 0 || mbedtls_ssl_check_pending(&m_ssl) != 0;
    }
    if (!pending) {
        // Wait without the TLS lock so sends are not blocked.
        // UINT32_MAX becomes -1 in poll(): wait forever.
        const uint32_t wait_ms = timeout_ms < 0 ? UINT32_MAX : static_cast<uint32_t>(timeout_ms);
        SocketResult wait_result = m_socket.wait_ready(wait_ms, false);
        if (wait_result == SocketResult::Timeout) {
            return ClientResult::Timeout;
        }
        if (wait_result != SocketResult::Success) {
            if (!m_ws_ready) {
                // disconnect() from another thread closed the socket under us
                return m_lost ? ClientResult::ConnectionLost : ClientResult::NotConnected;
            }
            LOG_INFO("WssClient: socket error while waiting (%s)", socket_result_to_string(wait_result));
            return fail("Connection lost");
        }
    }

    // Frame headers are dropped, so reading no more than the free space
    // guarantees the payload fits the reassembly buffer.
    uint8_t buffer[2048];
    const size_t read_size = m_recv_buffer.available() < sizeof(buffer) ? m_recv_buffer.available() : sizeof(buffer);
    if (read_size == 0) {
        // Unreachable: oversized packets are skipped above
        LOG_WARN("WssClient: reassembly buffer full without a complete packet");
        return fail("WebSocket: receive buffer overflow");
    }

    int ret;
    {
        std::scoped_lock lk(m_tls_mutex);
        if (!m_ws_ready) {
            return m_lost ? ClientResult::ConnectionLost : ClientResult::NotConnected;
        }
        ret = mbedtls_ssl_read(&m_ssl, buffer, read_size);
    }

    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return ClientResult::Success;  // Partial record; caller loops
    }
    if (ret <= 0) {
        if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            LOG_INFO("WssClient: relay closed the TLS session");
            set_transport_status("Closed by relay");
        } else {
            LOG_WARN("WssClient: TLS read failed (-0x%04X)", static_cast<unsigned>(-ret));
            set_tls_error_status("TLS: read failed", ret);
        }
        close_transport(false);
        return ClientResult::ConnectionLost;
    }

    return consume_stream(buffer, static_cast<size_t>(ret));
}

void WssClient::reset_decoder() {
    m_frame_active = false;
    m_frame_header_size = 0;
    m_frame_remaining = 0;
    m_frame_opcode = 0;
    m_in_message = false;
    m_control_size = 0;
    m_skip_remaining = 0;
}

/**
 * @brief Streaming frame decoder
 *
 * Handles arbitrary splits of headers and payloads across TLS reads.
 * Data payloads are appended to m_recv_buffer; control payloads are
 * collected in m_control and acted on when complete.
 */
ClientResult WssClient::consume_stream(const uint8_t* data, size_t size) {
    while (size > 0) {
        if (!m_frame_active) {
            // Header: 2 bytes, then a 2- or 8-byte extended length
            m_frame_header[m_frame_header_size++] = *data++;
            size--;
            if (m_frame_header_size < 2) {
                continue;
            }
            const uint8_t len7 = m_frame_header[1] & 0x7F;
            const size_t header_needed = 2 + (len7 == 126 ? 2 : (len7 == 127 ? 8 : 0));
            if (m_frame_header_size < header_needed) {
                continue;
            }
            if (!begin_frame()) {
                return fail("WebSocket: protocol error");
            }
        } else {
            const size_t chunk = static_cast<size_t>(m_frame_remaining < size ? m_frame_remaining : size);
            if (m_frame_opcode >= ws::OPCODE_CLOSE) {
                std::memcpy(m_control + m_control_size, data, chunk);
                m_control_size += chunk;
            } else {
                const size_t skip = m_skip_remaining < chunk ? m_skip_remaining : chunk;
                m_skip_remaining -= skip;
                // Reads are capped to the free space, so this is a bug guard
                if (m_recv_buffer.append(data + skip, chunk - skip) != protocol::BufferResult::Success) {
                    LOG_WARN("WssClient: reassembly buffer overflow (%zu bytes)", chunk - skip);
                    return fail("WebSocket: receive buffer overflow");
                }
            }
            data += chunk;
            size -= chunk;
            m_frame_remaining -= chunk;
        }

        if (m_frame_active && m_frame_remaining == 0) {
            m_frame_active = false;
            m_frame_header_size = 0;
            if (m_frame_opcode >= ws::OPCODE_CLOSE) {
                ClientResult control_result = finish_control_frame();
                if (control_result != ClientResult::Success) {
                    return control_result;
                }
            }
        }
    }
    return ClientResult::Success;
}

/**
 * @brief Validate a complete frame header and start its payload
 *
 * @return false on a protocol violation (the caller drops the connection)
 */
bool WssClient::begin_frame() {
    const uint8_t b0 = m_frame_header[0];
    const uint8_t b1 = m_frame_header[1];
    const uint8_t len7 = b1 & 0x7F;

    // No extensions are negotiated, and servers must not mask
    if ((b0 & 0x70) != 0 || (b1 & 0x80) != 0) {
        LOG_WARN("WssClient: invalid frame header 0x%02X 0x%02X", b0, b1);
        return false;
    }

    uint64_t length = len7;
    if (len7 == 126) {
        length = (static_cast<uint64_t>(m_frame_header[2]) << 8) | m_frame_header[3];
    } else if (len7 == 127) {
        length = 0;
        for (int i = 0; i < 8; i++) {
            length = (length << 8) | m_frame_header[2 + i];
        }
    }

    const uint8_t opcode = b0 & 0x0F;
    const bool fin = (b0 & 0x80) != 0;

    bool valid;
    if (opcode >= ws::OPCODE_CLOSE) {
        // Control frames may arrive between fragments of a message
        valid = opcode <= ws::OPCODE_PONG && fin && length <= ws::MAX_CONTROL_PAYLOAD;
        m_control_size = 0;
    } else if (opcode == ws::OPCODE_BINARY) {
        valid = !m_in_message;
        m_in_message = !fin;
    } else if (opcode == ws::OPCODE_CONTINUATION) {
        valid = m_in_message;
        m_in_message = !fin;
    } else {
        valid = false;  // Text and reserved opcodes break the contract
    }
    if (!valid) {
        LOG_WARN("WssClient: unexpected frame (opcode=%u, fin=%d, len=%llu)",
                 opcode, fin ? 1 : 0, static_cast<unsigned long long>(length));
        return false;
    }

    m_frame_opcode = opcode;
    m_frame_remaining = length;
    m_frame_active = true;
    return true;
}

/**
 * @brief Act on a complete control frame
 */
ClientResult WssClient::finish_control_frame() {
    switch (m_frame_opcode) {
        case ws::OPCODE_PING: {
            std::scoped_lock lk(m_tls_mutex);
            if (m_ws_ready) {
                write_frame_locked(ws::OPCODE_PONG, m_control, m_control_size);
            }
            return ClientResult::Success;
        }
        case ws::OPCODE_PONG:
            return ClientResult::Success;
        default: {
            // Close: echo the code back, then drop the connection
            const unsigned code = m_control_size >= 2 ? ((m_control[0] << 8) | m_control[1]) : 1005;
            LOG_INFO("WssClient: relay sent close (code %u)", code);
            char status[TRANSPORT_STATUS_SIZE];
            std::snprintf(status, sizeof(status), "Closed by relay (code %u)", code);
            set_transport_status(status);
            {
                std::scoped_lock lk(m_tls_mutex);
                if (m_ws_ready) {
                    write_frame_locked(ws::OPCODE_CLOSE, m_control, m_control_size >= 2 ? 2 : 0);
                }
            }
            close_transport(false);
            return ClientResult::ConnectionLost;
        }
    }
}

// =============================================================================
// BIO callbacks
// =============================================================================

int WssClient::bio_send(void* ctx, const unsigned char* buf, size_t len) {
    auto* self = static_cast<WssClient*>(ctx);
    SocketResult result = self->m_socket.send_all(buf, len);
    return result == SocketResult::Success ? static_cast<int>(len) : MBEDTLS_ERR_NET_SEND_FAILED;
}

int WssClient::bio_recv(void* ctx, unsigned char* buf, size_t len) {
    auto* self = static_cast<WssClient*>(ctx);
    size_t received = 0;
    switch (self->m_socket.recv(buf, len, received, self->m_io_timeout_ms)) {
        case SocketResult::Success:    return static_cast<int>(received);
        case SocketResult::WouldBlock: return MBEDTLS_ERR_SSL_WANT_READ;
        case SocketResult::Timeout:    return MBEDTLS_ERR_SSL_TIMEOUT;
        case SocketResult::Closed:     return 0;
        default:                       return MBEDTLS_ERR_NET_RECV_FAILED;
    }
}

} // namespace ryu_ldn::network
