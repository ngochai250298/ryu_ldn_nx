/**
 * @file wss_client.hpp
 * @brief Secure WebSocket (wss://) transport for the RyuLdn protocol
 *
 * WssClient carries the unchanged RyuLdn byte stream inside a TLS 1.2+
 * WebSocket, so the sysmodule can reach a relay that only accepts HTTPS
 * on port 443 (e.g. a Cloudflare Worker).
 *
 * ## Layering
 *
 * ```
 * +----------------+     +---------------------+     +-------------+
 * |   TcpClient    | --> | WssClient overrides | --> |   Socket    |
 * | encode/reassem.|     | WS frame + mbedTLS  |     |  (TCP/IP)   |
 * +----------------+     +---------------------+     +-------------+
 * ```
 *
 * WssClient derives from TcpClient and only replaces the byte transport
 * (connect, send_bytes, receive_into_buffer). Packet encoding and stream
 * reassembly are inherited, so every packet the game logic sends is
 * byte-identical to the plain TCP client.
 *
 * ## Wire contract
 *
 * - `GET <path>` upgrade with `X-Console-Id` and `Authorization: Bearer <token>`;
 *   anything but `101` with a valid `Sec-WebSocket-Accept` fails the connect.
 * - One RyuLdn packet (LdnHeader + payload) per masked binary message.
 * - Server frames may be fragmented; payloads of binary and continuation
 *   frames are appended to the reassembly buffer in order.
 * - Ping is answered with pong; close ends the connection (ConnectionLost).
 *
 * ## Security
 *
 * Fail closed: the relay certificate chain is verified against `ca_file`
 * and the hostname (SNI + SAN/CN). There is no plaintext fallback and no
 * option to skip verification. The token is never logged.
 *
 * ## Memory
 *
 * mbedTLS allocates through calloc/free, which in the sysmodule resolve to
 * the 1 MB stratosphere malloc arena (g_malloc_buffer), not the 384 KB
 * ExpHeap behind operator new. The record buffers (~33 KB) live only while
 * connected; the CA chain is parsed per connect and freed right after the
 * handshake.
 *
 * @see tcp_client.hpp for the packet encoding this class inherits
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <cstddef>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include "tcp_client.hpp"
#include "../config/config.hpp"

namespace ryu_ldn::network {

// =============================================================================
// WebSocket framing helpers (RFC 6455)
// =============================================================================

namespace ws {

constexpr uint8_t OPCODE_CONTINUATION = 0x0;  ///< Continuation of a fragmented message
constexpr uint8_t OPCODE_TEXT         = 0x1;  ///< Text message (rejected by the relay contract)
constexpr uint8_t OPCODE_BINARY       = 0x2;  ///< Binary message (one RyuLdn packet)
constexpr uint8_t OPCODE_CLOSE        = 0x8;  ///< Close control frame
constexpr uint8_t OPCODE_PING         = 0x9;  ///< Ping control frame
constexpr uint8_t OPCODE_PONG         = 0xA;  ///< Pong control frame

/** @brief Largest frame header: 2 bytes + 8-byte length + 4-byte mask */
constexpr size_t MAX_HEADER_SIZE = 14;

/** @brief Largest control frame payload allowed by RFC 6455 */
constexpr size_t MAX_CONTROL_PAYLOAD = 125;

/**
 * @brief Encode a single FIN frame header
 *
 * @param[out] out Buffer of at least MAX_HEADER_SIZE bytes
 * @param opcode Frame opcode
 * @param payload_size Payload length
 * @param mask_key 4-byte masking key, or nullptr for an unmasked (server) frame
 * @return Number of header bytes written
 */
size_t encode_header(uint8_t* out, uint8_t opcode, size_t payload_size, const uint8_t* mask_key);

/**
 * @brief XOR data with the 4-byte masking key (masking and unmasking are the same)
 */
void apply_mask(uint8_t* data, size_t size, const uint8_t* mask_key);

/**
 * @brief Compute Sec-WebSocket-Accept for a Sec-WebSocket-Key
 *
 * @param key Base64 key sent by the client
 * @param[out] out Buffer for the base64 result (at least 29 bytes)
 * @param out_size Size of out
 * @return true on success
 */
bool compute_accept(const char* key, char* out, size_t out_size);

/**
 * @brief Outcome of checking the HTTP upgrade response
 */
enum class UpgradeResult {
    Ok,             ///< 101 with matching Upgrade and Sec-WebSocket-Accept
    Malformed,      ///< Not an HTTP/1.1 status line
    NotSwitching,   ///< Status was not 101 (e.g. 404 for a bad token)
    BadUpgrade,     ///< Missing or wrong Upgrade header
    BadAccept       ///< Missing or wrong Sec-WebSocket-Accept
};

/**
 * @brief Validate an HTTP upgrade response header block
 *
 * @param response NUL-terminated response headers
 * @param expected_accept Expected Sec-WebSocket-Accept value
 * @param[out] status_code Parsed HTTP status code (0 if malformed)
 * @return UpgradeResult
 */
UpgradeResult check_upgrade_response(const char* response, const char* expected_accept, int& status_code);

} // namespace ws

// =============================================================================
// Transport status (for the overlay)
// =============================================================================

/**
 * @brief Maximum length of the transport status string (including NUL)
 */
constexpr size_t TRANSPORT_STATUS_SIZE = 64;

/**
 * @brief Set the human-readable transport status shown by the overlay
 *
 * Status strings are fixed text plus error codes; they never contain
 * the token or any request header.
 */
void set_transport_status(const char* status);

/**
 * @brief Copy the current transport status (thread-safe)
 */
void get_transport_status(char* out, size_t out_size);

// =============================================================================
// WssClient Class
// =============================================================================

/**
 * @brief RyuLdn client over a TLS WebSocket
 *
 * Construct with the [server] config; RyuLdnClient creates it when
 * `transport = wss`. Not copyable or movable (mbedTLS contexts hold
 * pointers back into the object).
 */
class WssClient : public TcpClient {
public:
    /**
     * @brief Create a disconnected client
     *
     * @param server Server config (path, console_id, token, ca_file are copied)
     */
    explicit WssClient(const config::ServerConfig& server);

    /**
     * @brief Destructor - closes the connection and frees mbedTLS state
     */
    ~WssClient() override;

    WssClient(const WssClient&) = delete;
    WssClient& operator=(const WssClient&) = delete;
    WssClient(WssClient&&) = delete;
    WssClient& operator=(WssClient&&) = delete;

    /**
     * @brief Initialize sockets, the hardware RNG and the TLS configuration
     *
     * On Switch this also starts csrng (entropy for mbedTLS) and the time
     * service (certificate validity checks).
     */
    bool initialize() override;

    /**
     * @brief TCP connect, TLS handshake, then WebSocket upgrade
     *
     * @return ClientResult::Success once the upgrade returned 101
     * @return ClientResult::TlsFailed on a CA file, certificate or handshake failure
     * @return ClientResult::Rejected if the upgrade got anything but 101 (the relay sends 404 on bad auth)
     * @return ClientResult::Timeout if the TCP connect or TLS handshake timed out
     * @return ClientResult::ConnectionFailed on missing config, a refused TCP connect or a bad 101
     */
    /// @gdb{tag="NETWORK:TCP", msg="WssClient::connect"}
    ClientResult connect(const char* host, uint16_t port, uint32_t timeout_ms = 5000) override;

    /**
     * @brief Send a close frame (best effort), close TLS and the socket
     */
    /// @gdb{tag="NETWORK:TCP", msg="WssClient::disconnect"}
    void disconnect() override;

    /**
     * @brief True only once the WebSocket upgrade has completed
     */
    bool is_connected() const override;

    /**
     * @brief Receive one RyuLdn packet, waiting at most one poll of timeout_ms
     *
     * Unlike TcpClient this never wedges the stream:
     * - a packet larger than payload_buffer_size is consumed and reported
     *   as BufferTooSmall (payload_size = its size);
     * - a packet larger than the reassembly buffer is skipped;
     * - a bad header, TLS error, close frame or socket error tears the
     *   connection down and returns ConnectionLost (sticky until the next
     *   connect, so a reader never sees a silent NotConnected).
     *
     * @return ClientResult::Timeout if no complete packet arrived in time
     */
    ClientResult receive_packet(protocol::PacketId& type,
                                void* payload, size_t payload_buffer_size,
                                size_t& payload_size,
                                int32_t timeout_ms = -1) override;

protected:
    ClientResult receive_into_buffer(int32_t timeout_ms) override;
    SocketResult send_bytes(const uint8_t* data, size_t size) override;

private:
    config::ServerConfig m_server;           ///< Copy of [server] (holds the token)

    mbedtls_entropy_context m_entropy;       ///< Entropy pool (csrng on Switch)
    mbedtls_ctr_drbg_context m_drbg;         ///< DRBG for TLS and frame masks
    mbedtls_ssl_config m_ssl_config;         ///< Client config: TLS 1.2+, verify required
    mbedtls_ssl_context m_ssl;               ///< Session (record buffers allocated per connect)
    mbedtls_x509_crt m_ca;                   ///< Trust anchors, only populated during connect
    bool m_tls_initialized = false;          ///< initialize() completed

    std::atomic<bool> m_ws_ready{false};     ///< Upgrade done, frames may flow
    std::atomic<bool> m_lost{false};         ///< Torn down by an error (not disconnect())
    int32_t m_io_timeout_ms = 0;             ///< Read timeout used by the BIO (handshake only)

    // Frame decoder state (receive side, guarded by TcpClient::m_recv_mutex)
    uint8_t m_frame_header[ws::MAX_HEADER_SIZE];
    size_t m_frame_header_size = 0;
    uint64_t m_frame_remaining = 0;
    uint8_t m_frame_opcode = 0;
    bool m_frame_active = false;             ///< Header parsed, payload in progress
    bool m_in_message = false;
    size_t m_skip_remaining = 0;             ///< Bytes left of an oversized packet being dropped
    uint8_t m_control[ws::MAX_CONTROL_PAYLOAD];
    size_t m_control_size = 0;

    // Send side: one masked frame is built here (guarded by m_tls_mutex)
    uint8_t m_frame[8 + sizeof(m_send_buffer)];

    // Serialises every mbedTLS call: a read can emit records (alerts),
    // and a pong is written from the receive thread.
    mutable ::ams::os::Mutex m_tls_mutex{false};

    bool load_ca(const char* path);
    ClientResult handshake(const char* host, uint32_t timeout_ms);
    ClientResult upgrade(const char* host, uint16_t port);
    ClientResult consume_stream(const uint8_t* data, size_t size);
    bool begin_frame();
    ClientResult finish_control_frame();
    SocketResult write_frame_locked(uint8_t opcode, const uint8_t* data, size_t size);
    SocketResult write_all_locked(const uint8_t* data, size_t size);
    void close_transport(bool send_close);
    void teardown_locked(bool lost);
    ClientResult fail(const char* status);
    void reset_decoder();

    static int bio_send(void* ctx, const unsigned char* buf, size_t len);
    static int bio_recv(void* ctx, unsigned char* buf, size_t len);
};

} // namespace ryu_ldn::network
