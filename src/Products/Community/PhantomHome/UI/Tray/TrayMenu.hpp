/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * TrayMenu.hpp — Context-menu population and command dispatch for the
 *                Phantom system-tray process.
 *
 * Lifecycle:
 *   TrayApp::ShowContextMenu() → ShowTrayContextMenu() → HandleTrayMenuCmd()
 */
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>

#include "TrayApp.hpp"  // for TrayState

namespace ShadowStrike::PhantomHome::Tray {

// ---------------------------------------------------------------------------
// TrayMenuCmd
//   Stable command IDs for the tray context menu.  Values are never
//   persisted but stability aids diagnostics and log correlation.
// ---------------------------------------------------------------------------
enum class TrayMenuCmd : UINT {
    None            = 0,
    OpenDashboard   = 0xA001,
    QuickScan       = 0xA002,
    FullScan        = 0xA003,
    PauseProtection = 0xA010,
    ResumeProtection= 0xA011,
    OpenSettings    = 0xA020,
    OpenReports     = 0xA021,
    OpenQuarantine  = 0xA022,
    CheckForUpdates = 0xA030,
    About           = 0xA040,
    Exit            = 0xA0FF,
};

// Show the context menu at the current cursor position.
// `owner` must be the tray's message-only HWND so that clicks outside the
// menu dismiss it correctly (per MSDN SetForegroundWindow guidance).
//
// Returns the command the user chose, or TrayMenuCmd::None if dismissed.
[[nodiscard]] TrayMenuCmd ShowTrayContextMenu(HWND owner, TrayState currentState);

// Dispatch the chosen command.  Called by TrayApp after ShowTrayContextMenu
// returns a non-None result.  May launch the UI process, show a dialog, or
// post WM_QUIT depending on the command.
void HandleTrayMenuCmd(TrayMenuCmd cmd);

} // namespace ShadowStrike::PhantomHome::Tray
