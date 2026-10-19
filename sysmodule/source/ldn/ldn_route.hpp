/**
 * @file ldn_route.hpp
 * @brief Relay or real Local Wireless, and what the game sees on failure
 *
 * Pure functions (no Atmosphere dependencies) so host tests cover them.
 *
 * ## Route
 *
 * A Local Wireless session goes to the relay unless one of these holds:
 * - `[ldn] enabled = 0`
 * - the console has no IP address (offline: the relay cannot work)
 * - every button of `[ldn] real_wireless_button` (default ZR) was held
 *   while the game was launched
 *
 * In those cases the game gets Nintendo's real ldn:u service (the radio).
 * The launch button comes from Atmosphere's override status, which the
 * loader samples from every controller when it creates the process and
 * sm hands to each MITM in sm::MitmProcessInfo.
 *
 * ## Errors shown to the game
 *
 * OpenAccessPoint/OpenStation never fail on the network. When the relay
 * cannot be reached, the next call that needs it (Scan, CreateNetwork,
 * Connect and their Private variants) fails with a cause-specific result,
 * module 0x10, which the system error screen shows as 2016-01xx.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#pragma once

#include <cstdint>
#include "../network/itcp_client.hpp"

namespace ryu_ldn::ldn {

/**
 * @brief True if every button in @p button_mask was held when the game was launched
 *
 * @param button_mask `[ldn] real_wireless_button` (HidNpadButton bits); 0 (`none`) never matches
 * @param keys_held_at_launch Atmosphere override status keys
 */
constexpr bool HeldRealWirelessButton(uint64_t button_mask, uint64_t keys_held_at_launch) {
    return button_mask != 0 && (keys_held_at_launch & button_mask) == button_mask;
}

/// True to serve the session from the relay, false for the real ldn:u service
constexpr bool UseRelay(bool ldn_enabled, bool online, uint64_t button_mask, uint64_t keys_held_at_launch) {
    return ldn_enabled && online && !HeldRealWirelessButton(button_mask, keys_held_at_launch);
}

/// Result descriptions for relay failures (shown as 2016-0101 .. 2016-0104)
constexpr uint32_t ResultDescRelayUnreachable = 101;  ///< DNS, TCP refused, timeout
constexpr uint32_t ResultDescRelayTls         = 102;  ///< TLS handshake or certificate
constexpr uint32_t ResultDescRelayRejected    = 103;  ///< Bad token or path
constexpr uint32_t ResultDescRelayHandshake   = 104;  ///< LDN handshake failed or timed out

/// Result description for a failed transport connect()
constexpr uint32_t RelayConnectFailureDesc(network::ClientResult result) {
    switch (result) {
        case network::ClientResult::TlsFailed: return ResultDescRelayTls;
        case network::ClientResult::Rejected:  return ResultDescRelayRejected;
        default:                               return ResultDescRelayUnreachable;
    }
}

} // namespace ryu_ldn::ldn
