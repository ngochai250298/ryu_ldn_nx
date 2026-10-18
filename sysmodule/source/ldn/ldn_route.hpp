/**
 * @file ldn_route.hpp
 * @brief Relay or real Local Wireless for a game's Local Wireless session
 *
 * Pure functions (no Atmosphere dependencies) so host tests cover them.
 *
 * ## Route
 *
 * A Local Wireless session goes to the relay unless one of these holds:
 * - `[ldn] enabled = 0`
 * - the console has no IP address (offline: the relay cannot work)
 * - RealWirelessKey was held while the game was launched
 *
 * In those cases the game gets Nintendo's real ldn:u service (the radio).
 * The launch button comes from Atmosphere's override status, which the
 * loader samples from every controller when it creates the process and
 * sm hands to each MITM in sm::MitmProcessInfo.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#pragma once

#include <cstdint>

namespace ryu_ldn::ldn {

/// Hold while launching a game to give that launch real Local Wireless (HidNpadButton_ZR)
constexpr uint64_t RealWirelessKey = 1ULL << 9;

/// True if RealWirelessKey was held when the game was launched
constexpr bool HeldRealWirelessKey(uint64_t keys_held_at_launch) {
    return (keys_held_at_launch & RealWirelessKey) != 0;
}

/// True to serve the session from the relay, false for the real ldn:u service
constexpr bool UseRelay(bool ldn_enabled, bool online, uint64_t keys_held_at_launch) {
    return ldn_enabled && online && !HeldRealWirelessKey(keys_held_at_launch);
}

} // namespace ryu_ldn::ldn
