/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomCore - SCRIPT-SCANNER SUBSYSTEM WIRING
 * ============================================================================
 *
 * @file  ScriptsWiring.hpp
 * @brief Brings up the four dormant script scanners (JavaScript, VBScript,
 *        Python, Office Macros) as a coherent subsystem. AMSIIntegration and
 *        PowerShellScanner are already wired from AntivirusService and are
 *        deliberately NOT re-initialized here.
 *
 * The four scanners are independent of each other; initialization order is
 * not meaningful, but the subsystem uses a uniform try/catch shield so one
 * broken scanner cannot take the rest down. Shutdown is reverse-order for
 * symmetry.
 * ============================================================================
 */

#pragma once

namespace ShadowStrike::Scripts::Wiring {

[[nodiscard]] bool InitializeScriptsSubsystem() noexcept;
void ShutdownScriptsSubsystem() noexcept;

}  // namespace ShadowStrike::Scripts::Wiring
