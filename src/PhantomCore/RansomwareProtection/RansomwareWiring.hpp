/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomCore - RANSOMWARE SUBSYSTEM WIRING
 * ============================================================================
 *
 * @file  RansomwareWiring.hpp
 * @brief Single entry point that brings up / tears down the full ransomware
 *        protection stack (9 singleton modules) as one coherent subsystem.
 *
 * The ransomware stack is composed of two logical layers:
 *
 *   1. PROTECTIVE layer  - must initialize first, so detectors can attach
 *                          callbacks into their pre-write / pre-delete hooks:
 *        - FileBackupManager        (shadow copies of target files)
 *        - HoneypotManager          (decoy file tripwires)
 *        - ShadowCopyProtector      (VSS hardening / vssadmin blocking)
 *        - BackupProtector          (well-known backup path guard)
 *        - VolumeSnapshotService    (emergency snapshot creation)
 *
 *   2. DETECTOR / RESPONDER layer:
 *        - RansomwareDetector       (behavioral write/rename analyzer)
 *        - LockyDetector            (family-specific IOC detector)
 *        - WannaCryDetector         (family-specific IOC detector)
 *        - RansomwareDecryptor      (known-key recovery engine)
 *
 * Shutdown happens in strict reverse order so no detector callback outlives
 * the protector it references.
 *
 * Failure policy:
 *   - Initialize failures on individual modules are logged and isolated.
 *     The remainder of the subsystem still comes up; a single broken
 *     component must not take down ransomware protection entirely.
 *   - This file throws no exceptions; every entry point is ``noexcept``.
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace ShadowStrike::Ransomware::Wiring {

/**
 * @brief Initialize every ransomware-protection singleton with its default
 *        configuration. Safe to call multiple times (each Initialize is
 *        idempotent inside its own module).
 *
 * @return `true` if the subsystem as a whole came up (at least one module
 *         initialized successfully), `false` if every module failed -
 *         which indicates a systemic problem the caller should surface.
 */
[[nodiscard]] bool InitializeRansomwareSubsystem() noexcept;

/**
 * @brief Tear down every ransomware-protection singleton in reverse
 *        initialization order. Always succeeds; exceptions from individual
 *        modules are swallowed and logged.
 */
void ShutdownRansomwareSubsystem() noexcept;

// ============================================================================
// KERNEL EVENT DISPATCH  (called from RealTimeProtection's kernel handlers)
//
// Each dispatch routes a single kernel-observed event into every ransomware
// module that has a matching entry point. Signatures use only primitive
// types and std::wstring so the header can be included from TUs that must
// not pull in any module header (ODR isolation).
//
// All dispatches are noexcept; individual module failures are swallowed and
// logged. None of them block the caller.
// ============================================================================

/**
 * @brief A process just wrote to @p filePath. Runs the behavioral write
 *        analysis (RansomwareDetector::AnalyzeWrite), the family-specific
 *        detectors (LockyDetector::OnFileWrite), and the honeypot tripwire
 *        (HoneypotManager::OnHoneypotAccessed when @p filePath matches a
 *        registered decoy).
 */
void DispatchFileWrite(std::uint32_t pid,
                       const std::wstring& filePath,
                       const std::wstring& processName) noexcept;

/// Process @p pid renamed @p oldPath to @p newPath.
void DispatchFileRename(std::uint32_t pid,
                        const std::wstring& oldPath,
                        const std::wstring& newPath) noexcept;

/// Process @p pid deleted @p filePath.
void DispatchFileDelete(std::uint32_t pid,
                        const std::wstring& filePath) noexcept;

/// Kernel reported a process creation / termination event.
void DispatchProcessNotify(std::uint32_t pid,
                           std::uint32_t parentPid,
                           const std::wstring& imagePath,
                           const std::wstring& commandLine,
                           bool isCreation) noexcept;

/// Kernel reported an image (DLL / driver / exe) load.
void DispatchImageLoad(std::uint32_t pid,
                       const std::wstring& imagePath,
                       std::uintptr_t imageBase,
                       std::size_t imageSize) noexcept;

}  // namespace ShadowStrike::Ransomware::Wiring
