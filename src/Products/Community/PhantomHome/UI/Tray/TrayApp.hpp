/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * TrayApp.hpp — Public interface for the Phantom system-tray process.
 *
 * Sole responsibility: NOTIFYICONDATA lifecycle, single-instance enforcement,
 * icon/tooltip state management, and the Win32 message loop.
 *
 * Extension points for future todos:
 *   - ShowContextMenu : tray-menu todo provides population logic.
 *   - SetState        : tray-ipc todo drives state changes via IPC.
 *   - Autorun install : tray-autorun todo wires HKCU\Run entry.
 */
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>

#include <cstdint>
#include <memory>

namespace ShadowStrike::PhantomHome::Tray {

// ---------------------------------------------------------------------------
// TrayState
//   Reflects the global protection surface as visible in the tray icon
//   and tooltip.  The numeric values are stable — do not reorder them.
// ---------------------------------------------------------------------------
enum class TrayState : std::uint8_t {
    Unknown  = 0,  ///< State not yet known (startup)
    Healthy  = 1,  ///< All engines active, no threats
    AtRisk   = 2,  ///< Degraded protection or deferred action required
    Critical = 3,  ///< Active threat detected or engine failed
    Paused   = 4,  ///< User-initiated pause
    Offline  = 5,  ///< Phantom service unreachable
};

// ---------------------------------------------------------------------------
// TrayApp
//   Meyers-singleton entry point for the tray process.
//   PIMPL: ABI is stable; Impl details are hidden in TrayApp.cpp.
// ---------------------------------------------------------------------------
class [[nodiscard]] TrayApp final {
public:
    TrayApp(const TrayApp&)            = delete;
    TrayApp& operator=(const TrayApp&) = delete;
    TrayApp(TrayApp&&)                 = delete;
    TrayApp& operator=(TrayApp&&)      = delete;

    // Returns the process-singleton instance.
    [[nodiscard]] static TrayApp& Instance();

    // Main entry point called from wWinMain.  Runs the message loop and
    // returns the process exit code when WM_QUIT is received.
    [[nodiscard]] int Run(HINSTANCE hInstance);

    // Thread-safe tray-state update.
    // Posts WM_USER+0x2002 to the message window so icon/tooltip are updated
    // on the UI thread.  Safe to call from any thread (tray-ipc todo).
    void SetState(TrayState state) noexcept;

    // Returns the last state set via SetState (or TrayState::Unknown on
    // startup).  Guaranteed sequentially consistent with SetState.
    [[nodiscard]] TrayState CurrentState() const noexcept;

    // Show the tray context menu at the current cursor position.
    // Extension point: menu population is provided by the tray-menu todo.
    // Until that todo lands this method logs a stub message and returns.
    void ShowContextMenu(HWND owner);

    // Post WM_QUIT to the message window; safe to call from any thread.
    void RequestQuit() noexcept;

    // Resolves ShadowStrikePhantomUI.exe relative to the current tray exe
    // and launches it via ShellExecuteW.  `args` is an optional command-line
    // argument string (e.g. L"--open=dashboard"); pass nullptr for no args.
    // Thread-safe.  Logs success or failure; never throws.
    static void LaunchMainUI(LPCWSTR args = nullptr) noexcept;

private:
    TrayApp();
    ~TrayApp();

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::PhantomHome::Tray
