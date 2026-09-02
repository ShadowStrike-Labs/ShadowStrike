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

// ---------------------------------------------------------------------------
// VALUE-CARRYING ARGUMENT - MATCH WITH A PREFIX TEST, NEVER WITH ==.
//
// Every constant above is a COMPLETE argument and the UI compares them with
// operator==.  This one is different: the scan target follows it, so the whole
// argument is "--scan-path=<path>" and only the prefix is fixed.  Comparing it
// with == would simply never fire, which would leave the Explorer entry present
// in the menu and inert - precisely the failure this comment exists to prevent.
//
// PRODUCER: the Explorer shell verb registered by the installer (component
// CmpShellIntegration in packaging/installer/Components.wxs), whose command is
//     "<installdir>\ShadowStrikePhantomUI.exe" --scan-path="%1"
// Both sides therefore share this one literal, and a contract test pins that
// the registered command really does contain it - two places spelling the same
// argument differently is how a menu entry becomes silently inert.
//
// MAY APPEAR MORE THAN ONCE in a single command line.  Every occurrence adds
// one target to ONE custom scan rather than starting a separate scan, because
// the service models a custom scan as a set of paths.
// ---------------------------------------------------------------------------
inline constexpr wchar_t kScanPathPrefix[] = L"--scan-path=";

} // namespace ShadowStrike::PhantomHome::UI::TrayArgs
