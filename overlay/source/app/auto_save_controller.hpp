/**
 * @file auto_save_controller.hpp
 * @brief Auto-save logic extracted from the main dashboard.
 *
 * Manages:
 * - m_backoff (SaveBackoff): triggers a save after 60 dirty frames and backs
 *   off for ~10 s after a failed save.
 * - m_saveConfirmCounter: counts frames after successful save to show
 *   "Saved!" indicator for ConfirmDurationFrames (120 frames ~ 2 s).
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */
#pragma once

#include <string>

#include <switch.h>

#include "ryu_ldn_ipc.h"
#include "app/config_actions.hpp"
#include "app/overlay_state.hpp"
#include "app/save_backoff.hpp"

class AutoSaveController {
public:
    /** @brief Call once per frame. Marks OverlayState as saved if auto-save fires. */
    void Update(bool isDirty) {
        if (m_backoff.Due(isDirty)) {
            // Skip mid-session auto-save while a game uses LDN; the exit and
            // page-leave saves still run. IPC only when a save is actually due.
            if (!IsLdnSessionActive()) {
                if (DoSaveConfig()) {
                    m_saveConfirmCounter = ConfirmDurationFrames;
                } else {
                    m_backoff.Failed();
                }
            }
        }
        if (m_saveConfirmCounter > 0) {
            m_saveConfirmCounter--;
        }
    }

    /** @brief Force an immediate save attempt. */
    void ForceSave() {
        if (DoSaveConfig()) {
            m_saveConfirmCounter = ConfirmDurationFrames;
        } else {
            m_backoff.Failed();
        }
    }

    /** @brief Reset confirm counter (e.g. after reload). */
    void ResetConfirm() {
        m_saveConfirmCounter = 0;
    }

    /** @brief Whether the "Saved!" flash indicator should be visible. */
    bool IsConfirmVisible() const {
        return m_saveConfirmCounter > 0;
    }

    /** @brief Get the text for the config dirty indicator. */
    std::string GetIndicatorText() const {
        bool isDirty = OverlayState::Instance().IsDirty();
        if (m_saveConfirmCounter > 0) {
            return "Saved!";
        }
        return isDirty ? "\u26A0 Unsaved changes" : "Saved";
    }

private:
    /** @brief Check if an LDN session is currently active. */
    bool IsLdnSessionActive() const {
        RyuLdnConfigService* svc = ryuLdnGetService();
        if (!svc) return false;
        u32 gameActive;
        if (R_FAILED(ryuLdnIsGameActive(svc, &gameActive))) return false;
        return gameActive != 0;
    }
    SaveBackoff m_backoff;
    u32 m_saveConfirmCounter = 0;
    static constexpr u32 ConfirmDurationFrames = 120;
};
