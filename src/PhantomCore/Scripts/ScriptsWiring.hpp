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

#include <cstddef>
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
//   .py / .pyw / .pyc / .pyo / .pyz /
//   .whl / .egg / .pyd                       -> PythonScriptScanner
//   .doc / .docm / .xls / .xlsm / .ppt /
//   .pptm / .docx / .xlsx / .pptx / .rtf     -> MacroDetector
//
// Unknown extensions are ignored and return false.
// ============================================================================

/**
 * @brief Scan a file that was just written/closed by @p pid.
 * @param pid Originating process identifier from kernel/service dispatch. Forwarded to
 *        the JavaScript scanner, whose result, alert and telemetry carry it. The VBScript,
 *        Python and macro scanners have no process-aware scan entry yet (task 180).
 * @param filePath Absolute or normalized path. Empty paths, embedded NULs,
 *        control characters, and paths longer than 32767 UTF-16 code units
 *        are rejected before scanner dispatch.
 * @return @c true if a scanner returned a malicious verdict; @c false for
 *         clean, unsupported, invalid, or scanner-error outcomes.
 * @thread_safety Thread-safe; per-scanner implementations own their locks.
 */
[[nodiscard]] bool DispatchFileScan(std::uint32_t pid,
                                    const std::wstring& filePath) noexcept;

// ============================================================================
// PROCESS-NOTIFY AND IMAGE-LOAD FAN-OUT (task 177)
//
// The six script modules each implement OnKernelProcessNotify and
// OnKernelImageLoad, and until now nothing called them. These two aggregators
// fan a kernel process create/exit (resp. image load) out to every module.
//
// DETECTION AND TELEMETRY ONLY, NOT ENFORCEMENT, and the wording is deliberate.
// A module that convicts (e.g. PowerShell on an encoded command line) asks the
// kernel to block through RequestKernelProcessBlock, but that transport is the
// broken, headerless wire struct of tasks 158/175 and the kernel discards it -
// verified by reading requestKernelProcessBlockImpl. So wiring these restores
// what they SEE and REPORT; it does not make them able to stop anything, and
// this must not be over-claimed.
//
// The process-notify fan-out runs OFF the kernel-blocking thread, on
// RealTimeProtection's ProcessNotifyFanOutLoop (task 186). The image-load
// fan-out runs inline on the image-load handler, which is notification-only and
// does not block the kernel on a reply.
// ============================================================================

namespace Detail {

/// Stable identity for each script module in the fan-out tables. The tables in
/// ScriptsWiring.cpp tag every entry with one of these and static_assert their
/// size against kScriptFanOutModuleCount; the coverage accessors below let a
/// test confirm all six are present with none duplicated or dropped.
enum class ScriptModule : std::uint8_t {
    PowerShell = 0,
    JavaScript,
    Macro,
    Amsi,
    Python,
    VBScript,
    Count
};

inline constexpr std::size_t kScriptFanOutModuleCount =
    static_cast<std::size_t>(ScriptModule::Count);  // 6

/// Bitmask with one bit set per module; a complete fan-out covers exactly this.
inline constexpr std::uint32_t kScriptFanOutCoverageAll =
    (std::uint32_t{1} << kScriptFanOutModuleCount) - 1u;

}  // namespace Detail

/// @brief Fan a kernel process create/exit out to every script module.
/// @param pid, parentPid, imagePath, commandLine, isCreation  Kernel event, as
///        delivered to RealTimeProtection::OnKernelProcessNotify. Modules that
///        do not consult a given field (Python/VBScript ignore the command line)
///        simply do not read it.
/// @note  Detection and telemetry only - see the header comment. noexcept: each
///        module call is shielded in its own <Module>Wire.cpp free function, so
///        one misbehaving module cannot stop the others or take down the worker.
void DispatchProcessNotify(std::uint32_t pid,
                           std::uint32_t parentPid,
                           const std::wstring& imagePath,
                           const std::wstring& commandLine,
                           bool isCreation) noexcept;

/// @brief Fan a kernel image (DLL/exe) load out to every script module.
/// @note  Detection and telemetry only; runs inline on the notification-only
///        image-load handler.
void DispatchImageLoad(std::uint32_t pid,
                       const std::wstring& imagePath,
                       std::uintptr_t imageBase,
                       std::size_t imageSize) noexcept;

/// @brief Bitmask of the modules the process-notify / image-load fan-out covers,
///        built by reading the actual dispatch tables. Equals
///        Detail::kScriptFanOutCoverageAll when every module is wired exactly
///        once. Exposed so a unit test can prove a module was not silently
///        dropped or duplicated (the size static_assert catches only count).
[[nodiscard]] std::uint32_t ProcessNotifyFanOutCoverage() noexcept;
[[nodiscard]] std::uint32_t ImageLoadFanOutCoverage() noexcept;

}  // namespace ShadowStrike::Scripts::Wiring
