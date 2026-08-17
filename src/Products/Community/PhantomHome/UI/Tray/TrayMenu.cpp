/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * TrayMenu.cpp — Context-menu population and command dispatch.
 *
 * Menu layout:
 *   Open ShadowStrike Phantom   (bold / default)
 *   ──────────────────────────
 *   Quick Scan
 *   Full Scan
 *   ──────────────────────────
 *   Pause Protection  [or Resume Protection when paused]
 *   ──────────────────────────
 *   Settings
 *   Reports
 *   Quarantine
 *   ──────────────────────────
 *   Check for Updates
 *   About
 *   ──────────────────────────
 *   Exit
 *
 * Disabled items (TrayState::Offline):
 *   QuickScan, FullScan, Pause/Resume, Settings, Reports, Quarantine,
 *   CheckForUpdates.  OpenDashboard, About, and Exit remain enabled.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>

#include <string>

#include "TrayMenu.hpp"
#include "TrayApp.hpp"
#include "TrayIpc.hpp"
#include "Version.hpp"
#include "Products/Community/PhantomHome/UI/Shared/TrayUiArgs.hpp"
#include "PhantomCore/Utils/Logger.hpp"

namespace ShadowStrike::PhantomHome::Tray {

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

static constexpr wchar_t kLogCategory[] = L"TrayMenu";
static constexpr wchar_t kUiExeName[]   = L"ShadowStrikePhantomUI.exe";

// ---------------------------------------------------------------------------
// RAII HMENU guard — destroys the menu on scope exit unless released.
// ---------------------------------------------------------------------------

struct MenuGuard final {
    HMENU h{nullptr};

    explicit MenuGuard(HMENU m) noexcept : h(m) {}
    ~MenuGuard() noexcept { if (h) { DestroyMenu(h); h = nullptr; } }

    MenuGuard(const MenuGuard&)            = delete;
    MenuGuard& operator=(const MenuGuard&) = delete;

    [[nodiscard]] HMENU get()   const noexcept { return h; }
    [[nodiscard]] bool  valid() const noexcept { return h != nullptr; }
};

// ---------------------------------------------------------------------------
// SpawnUiWithArg
//   Resolves the UI executable path relative to the current tray exe and
//   launches it via ShellExecuteW with the provided command-line argument.
//   Logs success or failure; never throws.
// ---------------------------------------------------------------------------

static void SpawnUiWithArg(LPCWSTR arg) noexcept {
    // Resolve the UI exe path from the tray exe location.
    wchar_t buf[MAX_PATH + 1]{};
    if (!GetModuleFileNameW(nullptr, buf, MAX_PATH)) {
        SS_LOG_LAST_ERROR(kLogCategory,
            L"GetModuleFileNameW failed; cannot resolve UI executable path");
        return;
    }

    std::wstring uiPath(buf);
    const auto slash = uiPath.find_last_of(L'\\');
    if (slash == std::wstring::npos) {
        SS_LOG_ERROR(kLogCategory,
            L"Unexpected module path format (no backslash): '%ls'", uiPath.c_str());
        return;
    }
    uiPath.resize(slash + 1);
    uiPath += kUiExeName;

    SS_LOG_INFO(kLogCategory,
        L"Spawning UI '%ls' with arg '%ls'", uiPath.c_str(), arg ? arg : L"(none)");

    const HINSTANCE rc = ShellExecuteW(
        nullptr, L"open", uiPath.c_str(), arg, nullptr, SW_SHOWNORMAL);

    if (reinterpret_cast<INT_PTR>(rc) <= 32) {
        SS_LOG_ERROR(kLogCategory,
            L"ShellExecuteW('%ls', arg='%ls') failed (code=%td)",
            uiPath.c_str(), arg ? arg : L"(none)",
            reinterpret_cast<INT_PTR>(rc));
    }
}

// ---------------------------------------------------------------------------
// ShowTrayContextMenu
// ---------------------------------------------------------------------------

TrayMenuCmd ShowTrayContextMenu(HWND owner, TrayState currentState) {
    MenuGuard mg(CreatePopupMenu());
    if (!mg.valid()) {
        SS_LOG_LAST_ERROR(kLogCategory, L"CreatePopupMenu() failed");
        return TrayMenuCmd::None;
    }

    const bool offline = (currentState == TrayState::Offline);
    const bool paused  = (currentState == TrayState::Paused);

    // Helper: append a string item, optionally greyed out.
    auto append = [&](TrayMenuCmd cmd, const wchar_t* text, bool disabled = false) noexcept {
        const UINT flags = MF_STRING | (disabled ? (MF_DISABLED | MF_GRAYED) : MF_ENABLED);
        if (!AppendMenuW(mg.get(), flags, static_cast<UINT_PTR>(cmd), text)) {
            SS_LOG_WARN(kLogCategory,
                L"AppendMenuW cmd=0x%04X failed (GLE=%lu)",
                static_cast<UINT>(cmd), GetLastError());
        }
    };

    auto sep = [&]() noexcept {
        AppendMenuW(mg.get(), MF_SEPARATOR, 0, nullptr);
    };

    // --- Open Dashboard (always enabled) ------------------------------------
    append(TrayMenuCmd::OpenDashboard, L"Open ShadowStrike Phantom");
    sep();

    // --- Scan actions -------------------------------------------------------
    append(TrayMenuCmd::QuickScan, L"Quick Scan", offline);
    append(TrayMenuCmd::FullScan,  L"Full Scan",  offline);
    sep();

    // --- Pause / Resume (mutually exclusive display) ------------------------
    if (paused) {
        append(TrayMenuCmd::ResumeProtection, L"Resume Protection", false);
    } else {
        append(TrayMenuCmd::PauseProtection, L"Pause Protection", offline);
    }
    sep();

    // --- Management views ---------------------------------------------------
    append(TrayMenuCmd::OpenSettings,   L"Settings",   offline);
    append(TrayMenuCmd::OpenReports,    L"Reports",    offline);
    append(TrayMenuCmd::OpenQuarantine, L"Quarantine", offline);
    sep();

    // --- Updates & About ----------------------------------------------------
    append(TrayMenuCmd::CheckForUpdates, L"Check for Updates", offline);
    append(TrayMenuCmd::About, L"About");
    sep();

    // --- Exit ---------------------------------------------------------------
    append(TrayMenuCmd::Exit, L"Exit");

    // Bold the OpenDashboard item (default action, double-click equivalent).
    if (!SetMenuDefaultItem(mg.get(),
            static_cast<UINT>(TrayMenuCmd::OpenDashboard), FALSE)) {
        SS_LOG_WARN(kLogCategory,
            L"SetMenuDefaultItem failed (GLE=%lu)", GetLastError());
    }

    // MSDN guidance: call SetForegroundWindow before TrackPopupMenuEx so the
    // menu is properly dismissed when the user clicks outside it.
    SetForegroundWindow(owner);

    POINT pt{};
    if (!GetCursorPos(&pt)) {
        SS_LOG_WARN(kLogCategory,
            L"GetCursorPos failed (GLE=%lu); using (0,0)", GetLastError());
        pt = {0, 0};
    }

    const UINT chosen = TrackPopupMenuEx(
        mg.get(),
        TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
        pt.x, pt.y,
        owner,
        nullptr);

    // MSDN guidance: post WM_NULL after TrackPopupMenuEx to ensure the menu
    // is fully dismissed before any subsequent message processing.
    PostMessageW(owner, WM_NULL, 0, 0);

    return (chosen == 0) ? TrayMenuCmd::None
                         : static_cast<TrayMenuCmd>(chosen);
}

// ---------------------------------------------------------------------------
// HandleTrayMenuCmd
// ---------------------------------------------------------------------------

void HandleTrayMenuCmd(TrayMenuCmd cmd) {
    switch (cmd) {

    case TrayMenuCmd::OpenDashboard:
        // Use TrayApp::LaunchMainUI to avoid duplicating path-resolution logic.
        TrayApp::LaunchMainUI(UI::TrayArgs::kOpenDashboard);
        break;

    case TrayMenuCmd::QuickScan:
        IPC::TrayIpc::Instance().StartFastScan();
        SpawnUiWithArg(UI::TrayArgs::kQuickScan);
        break;

    case TrayMenuCmd::FullScan:
        SpawnUiWithArg(UI::TrayArgs::kFullScan);
        break;

    case TrayMenuCmd::PauseProtection:
        IPC::TrayIpc::Instance().PauseProtection(0);
        SpawnUiWithArg(UI::TrayArgs::kPauseProtection);
        break;

    case TrayMenuCmd::ResumeProtection:
        IPC::TrayIpc::Instance().ResumeProtection();
        SpawnUiWithArg(UI::TrayArgs::kResumeProtection);
        break;

    case TrayMenuCmd::OpenSettings:
        SpawnUiWithArg(UI::TrayArgs::kOpenSettings);
        break;

    case TrayMenuCmd::OpenReports:
        SpawnUiWithArg(UI::TrayArgs::kOpenReports);
        break;

    case TrayMenuCmd::OpenQuarantine:
        SpawnUiWithArg(UI::TrayArgs::kOpenQuarantine);
        break;

    case TrayMenuCmd::CheckForUpdates:
        SpawnUiWithArg(UI::TrayArgs::kCheckForUpdates);
        break;

    case TrayMenuCmd::About: {
        std::wstring text =
            L"ShadowStrike Phantom\n"
            L"Version: ";
        text += Version::kVersion;
        text +=
            L"\n\n"
            L"Enterprise Next-Generation Antivirus Platform\n"
            L"\u00A9 2026 ShadowStrike Security. All rights reserved.";

        MessageBoxW(nullptr,
            text.c_str(),
            L"About ShadowStrike Phantom",
            MB_OK | MB_ICONINFORMATION);
        break;
    }

    case TrayMenuCmd::Exit: {
        const TrayState s = TrayApp::Instance().CurrentState();
        const bool protectionActive =
            (s != TrayState::Offline && s != TrayState::Paused);

        if (protectionActive) {
            const int confirm = MessageBoxW(
                nullptr,
                L"Exit the tray? Real-time protection will continue in the background.",
                L"Confirm Exit",
                MB_YESNO | MB_ICONQUESTION);
            if (confirm != IDYES) {
                SS_LOG_INFO(kLogCategory, L"Exit cancelled by user");
                return;
            }
        }

        SS_LOG_INFO(kLogCategory, L"User requested tray exit");
        TrayApp::Instance().RequestQuit();
        break;
    }

    case TrayMenuCmd::None:
        // Dismissed — nothing to do.
        break;

    default:
        SS_LOG_WARN(kLogCategory,
            L"Unknown TrayMenuCmd value: 0x%04X", static_cast<UINT>(cmd));
        break;
    }
}

} // namespace ShadowStrike::PhantomHome::Tray
