/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AutoRun.hpp — HKCU\Run self-healing registration for the Phantom tray.
 *
 * All functions are idempotent and thread-safe.  Failures are logged via
 * SS_LOG_* and reported through the return value; they never throw.
 */
#pragma once

#include <string>

namespace ShadowStrike::PhantomHome::Tray {

// Registry value name used under HKCU\Software\Microsoft\Windows\CurrentVersion\Run.
inline constexpr wchar_t kAutoRunValueName[] = L"ShadowStrikePhantomTray";

// Ensures the HKCU Run entry exists and points at the current tray executable
// (quoted path + " --autorun").  Rewrites stale or mismatched values.
// Fails safe: logs the error and returns false if the registry is not writable.
// Idempotent — no write is performed when the value is already correct.
// Thread-safe.
[[nodiscard]] bool EnsureAutoRun();

// Removes the HKCU Run entry.  Used by the uninstaller or user-initiated
// opt-out.  Returns true if the value was removed or was already absent.
[[nodiscard]] bool RemoveAutoRun();

// Reads the current registered autorun command string, if any.
// Returns an empty wstring if the value is absent or unreadable.
[[nodiscard]] std::wstring CurrentAutoRunValue();

} // namespace ShadowStrike::PhantomHome::Tray
