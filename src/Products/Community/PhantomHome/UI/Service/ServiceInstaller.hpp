/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

#pragma once

#include <string>

namespace ShadowStrike::PhantomHome::UI::Service {

// Register / unregister the ShadowStrikePhantomService with the SCM.
// `image_path` must be an absolute, unquoted path to the service EXE.
[[nodiscard]] bool InstallService(const std::wstring& image_path);
[[nodiscard]] bool UninstallService();

// Register / unregister a machine-wide logon autostart entry for the Tray
// under HKLM\Software\Microsoft\Windows\CurrentVersion\Run. The service runs
// as LocalSystem and is not user-facing; the tray is the only component that
// must launch in the interactive session, and it ships as a sibling exe next
// to the service binary.
//
// `tray_path` must be an absolute, unquoted path to the tray EXE. The callee
// writes a correctly quoted REG_SZ value that cmd/explorer will parse safely.
[[nodiscard]] bool InstallTrayAutostart(const std::wstring& tray_path);
[[nodiscard]] bool UninstallTrayAutostart();

}  // namespace ShadowStrike::PhantomHome::UI::Service
