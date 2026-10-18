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

#include <atomic>
#include <cstddef>
#include <cstdint>

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

/**
 * @brief Fixed set of thread stacks handed out one per live owner
 *
 * Lives in static storage. Claim() is lock-free and safe from any IPC
 * thread; a slot stays owned until Release(), which the owner calls only
 * after its thread has been joined.
 */
template <size_t Slots, size_t Size, size_t Align>
class StackPool {
public:
    static constexpr size_t StackSize = Size;

    /// @return a free slot index, or -1 when every slot is in use
    int Claim() {
        for (size_t i = 0; i < Slots; i++) {
            bool expected = false;
            if (m_in_use[i].compare_exchange_strong(expected, true)) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

    void Release(int slot) { m_in_use[slot].store(false); }

    void* Stack(int slot) { return m_stacks[slot]; }

private:
    alignas(Align) uint8_t m_stacks[Slots][Size];
    std::atomic<bool> m_in_use[Slots] = {};
};

} // namespace ams::mitm::ldn::helpers
