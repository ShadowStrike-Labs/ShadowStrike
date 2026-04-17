/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - SYSTEM TRAY MODULE
 * ============================================================================
 *
 * @file SystemTray.hpp
 * @brief Enterprise-grade system tray integration with real-time icon state,
 *        context menu, and engine event forwarding.
 *
 * The SystemTray module owns the notification area (tray) icon and serves as
 * the primary lightweight user interface for the protection service.  It
 * delegates balloon/toast display to NotificationManager and communicates
 * with the engine via direct singleton access (in-process) or named-pipe
 * IPC (out-of-process).
 *
 * SYSTEM TRAY CAPABILITIES:
 * =========================
 *
 * 1. TRAY ICON LIFECYCLE
 *    - Shell_NotifyIconW with GUID-based identification
 *    - DPI-aware icon rendering (per-monitor v2)
 *    - Graceful recreation after explorer.exe restart
 *
 * 2. ICON STATE MACHINE
 *    - Protected   (green shield)   — engine active, all OK
 *    - Scanning    (blue shield)    — scan in progress
 *    - Paused      (yellow shield)  — protection temporarily paused
 *    - Degraded    (orange shield)  — partial functionality
 *    - Stopped     (red shield)     — protection disabled / error
 *    - Updating    (cyan shield)    — signature / engine update
 *    - Uninitialized (gray shield)  — startup phase
 *
 * 3. CONTEXT MENU
 *    - Open Dashboard (default, bold)
 *    - Quick Scan / Full Scan
 *    - Pause Protection (submenu: 15 min, 1 hr, Until restart, Resume)
 *    - Quarantine Viewer
 *    - Check for Updates
 *    - Settings
 *    - About ShadowStrike
 *    - Exit
 *
 * 4. ENGINE INTEGRATION
 *    - RealTimeProtection state-change callback
 *    - ScanEngine detection + completion callbacks
 *    - AlertSystem alert callback
 *    - NotificationManager forwarding
 *
 * 5. ROBUSTNESS
 *    - Survives explorer.exe crash via TaskbarCreated re-registration
 *    - Thread-safe: own message-pump thread with PostMessage bridge
 *    - No raw new/delete — full RAII
 *
 * @note Thread-safe Meyers' Singleton with PIMPL.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: GNU Affero General Public License v3.0
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <string>
#include <string_view>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  include <shellapi.h>
#endif

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::UI {
    class SystemTrayImpl;
}

namespace ShadowStrike {
namespace UI {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace TrayConstants {

    inline constexpr uint32_t VERSION_MAJOR = 1;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default dashboard URL (localhost Community edition)
    inline constexpr const wchar_t* DEFAULT_DASHBOARD_URL = L"http://127.0.0.1:9443";

    /// @brief Tooltip prefix
    inline constexpr const wchar_t* TOOLTIP_PREFIX = L"ShadowStrike";

    /// @brief Icon status poll interval (ms)
    inline constexpr uint32_t STATUS_POLL_INTERVAL_MS = 5000;

    /// @brief WM_APP range for tray messages
    inline constexpr UINT WM_TRAY_CALLBACK = WM_APP + 0x100;

    /// @brief Timer IDs
    inline constexpr UINT_PTR TIMER_STATUS_POLL = 1;
    inline constexpr UINT_PTR TIMER_ANIMATION   = 2;

    /// @brief Animation frame interval (ms)
    inline constexpr uint32_t ANIMATION_INTERVAL_MS = 400;

    /// @brief Maximum tooltip length (Windows limit is 128 wchar_t)
    inline constexpr size_t MAX_TOOLTIP_LENGTH = 127;

}  // namespace TrayConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Visual state of the tray icon.
 *
 * Drives the icon color and tooltip text.
 */
enum class TrayIconState : uint8_t {
    Uninitialized = 0,  ///< Gray shield — startup phase
    Protected     = 1,  ///< Green shield — all protection active
    Scanning      = 2,  ///< Blue shield  — scan in progress
    Paused        = 3,  ///< Yellow shield — user-paused
    Degraded      = 4,  ///< Orange shield — partial functionality
    Stopped       = 5,  ///< Red shield   — protection off / error
    Updating      = 6   ///< Cyan shield  — updating signatures
};

/**
 * @brief Context menu actions the user can trigger.
 */
enum class TrayMenuAction : uint16_t {
    OpenDashboard       = 1001,
    QuickScan           = 1002,
    FullScan            = 1003,
    PauseProtection15m  = 1004,
    PauseProtection1h   = 1005,
    PauseProtectionRestart = 1006,
    ResumeProtection    = 1007,
    OpenQuarantine      = 1008,
    CheckUpdates        = 1009,
    OpenSettings        = 1010,
    About               = 1011,
    Exit                = 1012
};

/**
 * @brief Module status
 */
enum class SystemTrayStatus : uint8_t {
    Uninitialized = 0,
    Initializing  = 1,
    Running       = 2,
    Stopping      = 3,
    Stopped       = 4,
    Error         = 5
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Configuration for the system tray module.
 */
struct SystemTrayConfig {
    /// @brief Enable the system tray icon
    bool enabled = true;

    /// @brief Dashboard URL to open on double-click
    std::wstring dashboardUrl{TrayConstants::DEFAULT_DASHBOARD_URL};

    /// @brief Show balloon on threat detection
    bool showThreatBalloons = true;

    /// @brief Show balloon on scan completion
    bool showScanCompleteBalloons = true;

    /// @brief Show balloon on state changes
    bool showStateChangeBalloons = true;

    /// @brief Enable animated icon during scan
    bool enableScanAnimation = true;

    /// @brief Status poll interval (ms, 0 = disable polling)
    uint32_t statusPollIntervalMs = TrayConstants::STATUS_POLL_INTERVAL_MS;

    /// @brief Auto-register engine callbacks on Initialize
    bool autoRegisterCallbacks = true;

    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Statistics snapshot for the system tray module.
 */
struct SystemTrayStatistics {
    uint64_t menusShown           = 0;
    uint64_t dashboardLaunches    = 0;
    uint64_t scansRequested       = 0;
    uint64_t pauseRequests        = 0;
    uint64_t resumeRequests       = 0;
    uint64_t iconStateChanges     = 0;
    uint64_t explorerRestarts     = 0;
    uint64_t balloonsSent         = 0;
    int64_t  uptimeSeconds        = 0;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Called when the user selects a menu item.
using TrayActionCallback = std::function<void(TrayMenuAction action)>;

/// @brief Called when the user clicks the tray icon (left-click).
using TrayClickCallback = std::function<void()>;

/// @brief Called when exit is confirmed.
using TrayExitCallback = std::function<bool()>;

// ============================================================================
// SYSTEM TRAY CLASS
// ============================================================================

/**
 * @class SystemTray
 * @brief Meyers' Singleton that manages the notification-area (tray) icon.
 *
 * Runs its own message-pump thread so it works in both service and
 * GUI host processes.  All public methods are thread-safe.
 */
class SystemTray final {
public:
    // ========================================================================
    // SINGLETON
    // ========================================================================

    [[nodiscard]] static SystemTray& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;

    SystemTray(const SystemTray&)            = delete;
    SystemTray& operator=(const SystemTray&) = delete;
    SystemTray(SystemTray&&)                 = delete;
    SystemTray& operator=(SystemTray&&)      = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    /// @brief Initialize the tray icon and start the message-pump thread.
    [[nodiscard]] bool Initialize(const SystemTrayConfig& config = {});

    /// @brief Gracefully remove the icon and stop the thread.
    void Shutdown();

    /// @brief Is the module initialized and running?
    [[nodiscard]] bool IsInitialized() const noexcept;

    /// @brief Current module status.
    [[nodiscard]] SystemTrayStatus GetStatus() const noexcept;

    /// @brief Update configuration at runtime.
    [[nodiscard]] bool UpdateConfiguration(const SystemTrayConfig& config);

    /// @brief Get current configuration.
    [[nodiscard]] SystemTrayConfig GetConfiguration() const;

    // ========================================================================
    // ICON STATE
    // ========================================================================

    /// @brief Set the visual state of the tray icon.
    void SetIconState(TrayIconState state);

    /// @brief Get the current visual state.
    [[nodiscard]] TrayIconState GetIconState() const noexcept;

    /// @brief Override the tooltip text (empty = auto-generate from state).
    void SetTooltip(std::wstring_view tooltip);

    /// @brief Get the current tooltip text.
    [[nodiscard]] std::wstring GetTooltip() const;

    // ========================================================================
    // NOTIFICATIONS
    // ========================================================================

    /// @brief Show a balloon notification via the tray icon.
    void ShowBalloon(
        std::wstring_view title,
        std::wstring_view message,
        DWORD flags = NIIF_INFO,
        uint32_t timeoutMs = 5000);

    // ========================================================================
    // ENGINE INTEGRATION
    // ========================================================================

    /// @brief Register callbacks with RTP, ScanEngine, AlertSystem.
    /// Called automatically if config.autoRegisterCallbacks is true.
    void RegisterEngineCallbacks();

    /// @brief Unregister previously registered engine callbacks.
    void UnregisterEngineCallbacks();

    /// @brief Manually synchronize icon state from current engine state.
    void SyncStateFromEngine();

    // ========================================================================
    // USER CALLBACKS
    // ========================================================================

    /// @brief Register a callback for menu actions.
    void RegisterActionCallback(TrayActionCallback callback);

    /// @brief Register a callback for left-click on the icon.
    void RegisterClickCallback(TrayClickCallback callback);

    /// @brief Register a callback for exit confirmation.
    /// Return false from the callback to cancel exit.
    void RegisterExitCallback(TrayExitCallback callback);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] SystemTrayStatistics GetStatistics() const;
    void ResetStatistics();

    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    SystemTray();
    ~SystemTray();

    std::unique_ptr<SystemTrayImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetTrayIconStateName(TrayIconState state) noexcept;
[[nodiscard]] std::wstring     GetTrayIconStateTooltip(TrayIconState state);
[[nodiscard]] std::string_view GetTrayMenuActionName(TrayMenuAction action) noexcept;
[[nodiscard]] std::string_view GetSystemTrayStatusName(SystemTrayStatus status) noexcept;

}  // namespace UI
}  // namespace ShadowStrike
