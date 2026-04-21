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

}  // namespace ShadowStrike::Ransomware::Wiring
