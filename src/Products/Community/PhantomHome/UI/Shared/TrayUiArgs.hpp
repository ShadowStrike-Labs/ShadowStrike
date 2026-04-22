/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * TrayUiArgs.hpp — Command-line argument constants passed from the tray
 *                  process to ShadowStrikePhantomUI.exe.
 *
 * Both the tray and the UI must agree on these strings. The tray passes them
 * as ShellExecuteW arguments; the UI parses them on startup to route the user
 * to the correct view or trigger the appropriate action.
 */
#pragma once

namespace ShadowStrike::PhantomHome::UI::TrayArgs {

inline constexpr wchar_t kOpenDashboard[]   = L"--open=dashboard";
inline constexpr wchar_t kQuickScan[]       = L"--scan=quick";
inline constexpr wchar_t kFullScan[]        = L"--scan=full";
inline constexpr wchar_t kPauseProtection[] = L"--protection=pause";
inline constexpr wchar_t kResumeProtection[]= L"--protection=resume";
inline constexpr wchar_t kOpenSettings[]    = L"--open=settings";
inline constexpr wchar_t kOpenReports[]     = L"--open=reports";
inline constexpr wchar_t kOpenQuarantine[]  = L"--open=quarantine";
inline constexpr wchar_t kCheckForUpdates[] = L"--action=check-updates";

} // namespace ShadowStrike::PhantomHome::UI::TrayArgs
