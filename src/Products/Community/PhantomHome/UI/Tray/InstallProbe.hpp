/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * InstallProbe.hpp - Tray-side checks that verify the Phantom product is
 * actually installed (MSI install anchor + SCM service entry) before the
 * tray paints an icon or self-heals any autostart entry.
 *
 * Rationale: a stale HKCU\Run entry, a hand-copied tray binary in
 * vm_shrd\..., or a broken uninstaller can leave the tray executable
 * runnable while the service and MSI are gone. In that state the tray
 * must NOT pretend to be a healthy product surface.
 */
#pragma once

#include <string>

namespace ShadowStrike::PhantomHome::Tray {

// Result of the install probe.  Mutually exclusive states.
enum class InstallState {
    Installed,        // MSI anchor present AND service is registered in SCM.
    Orphaned,         // Tray binary is running but MSI/service are gone.
    InstalledNoSvc,   // MSI anchor present but service entry missing.
};

struct InstallProbeResult {
    InstallState    state{InstallState::Orphaned};
    std::wstring    installFolder;   // HKLM\SOFTWARE\ShadowStrike\PhantomHome\Install\InstallFolder
    std::wstring    runningExePath;  // GetModuleFileNameW(nullptr)
    bool            serviceRegistered{false};
};

// Performs the full probe.  Never throws.  All failures are logged via SS_LOG_*.
[[nodiscard]] InstallProbeResult ProbeInstall() noexcept;

// True iff the tray executable resides under the directory recorded in the
// MSI install anchor (case-insensitive prefix match, with path normalization).
[[nodiscard]] bool IsTrayUnderInstallFolder(const InstallProbeResult& r) noexcept;

} // namespace ShadowStrike::PhantomHome::Tray
