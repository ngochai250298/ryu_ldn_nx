/**
 * @file ldn_helpers.hpp
 * @brief Pure decision helpers used by ICommunicationService
 *
 * No Switch headers: the host tests in tests/ldn_service_tests.cpp include
 * this file and exercise the same code the sysmodule runs. Enum-typed
 * helpers are templates so this header needs nothing from ldn_types.hpp.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#pragma once

namespace ams::mitm::ldn::helpers {

/**
 * @brief Disconnect reason to report when the server drops us from a room
 *
 * Ryujinx: the reason from a preceding Reject wins; otherwise
 * DisconnectReasonOrDefault(DestroyedBySystem) for an access point and
 * DisconnectReasonOrDefault(DestroyedByUser) for a station.
 */
template <typename Reason>
constexpr Reason ServerDisconnectReason(Reason pending_reject, bool is_host) {
    if (pending_reject != Reason::None) {
        return pending_reject;
    }
    return is_host ? Reason::DestroyedBySystem : Reason::DestroyedByUser;
}

} // namespace ams::mitm::ldn::helpers
