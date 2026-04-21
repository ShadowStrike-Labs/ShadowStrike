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

#include <cstdint>
#include <string>

namespace ShadowStrike::Scripts::Wiring {

[[nodiscard]] bool InitializeScriptsSubsystem() noexcept;
void ShutdownScriptsSubsystem() noexcept;

// ============================================================================
// KERNEL EVENT DISPATCH
//
// Routes file-scan events from the kernel minifilter into the correct
// script scanner based on file extension. Returns `true` if ANY scanner
// flagged the file as malicious, so the caller can turn that into a Block
// verdict before the kernel lets the operation complete.
//
// Extensions handled:
//   .js / .jse / .mjs / .cjs                 -> JavaScriptScanner
//   .vbs / .vbe / .wsf / .wsh / .hta         -> VBScriptScanner
//   .py / .pyw / .pyc / .pyo / .pyz          -> PythonScriptScanner
//   .doc / .docm / .xls / .xlsm / .ppt /
//   .pptm / .docx / .xlsx / .pptx / .rtf     -> MacroDetector
//
// Unknown extensions are ignored and return false.
// ============================================================================

/**
 * @brief Scan a file that was just written/closed by @p pid. Returns
 *        @c true if a scanner returned a malicious verdict.
 */
[[nodiscard]] bool DispatchFileScan(std::uint32_t pid,
                                    const std::wstring& filePath) noexcept;

}  // namespace ShadowStrike::Scripts::Wiring
