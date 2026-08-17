/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for ShadowCopyProtector. Isolated in its own TU because the
 * RansomwareProtection module headers pair-wise redefine the same enums in
 * the ShadowStrike::Ransomware namespace, so only one may be included per TU.
 */
#include "pch.h"
#include "ShadowCopyProtector.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Ransomware::Wiring::Internal {

bool ShadowCopyProtector_Init() noexcept {
    try {
        if (ShadowCopyProtector::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("RansomwareWiring: ShadowCopyProtector::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: ShadowCopyProtector init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: ShadowCopyProtector init unknown exception");
    }
    return false;
}

void ShadowCopyProtector_Shutdown() noexcept {
    try {
        ShadowCopyProtector::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: ShadowCopyProtector shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: ShadowCopyProtector shutdown unknown exception");
    }
}

// ---------------------------------------------------------------------------
// Kernel event dispatch for ShadowCopyProtector.
//
// WHY THIS EXISTS: ShadowCopyProtector was the only module of the nine in this
// subsystem whose wiring shim carried lifecycle calls and no event hook, while
// still implementing a full process-creation analyzer. MEASURED before adding
// it: ShadowCopyProtector::OnKernelProcessNotify had zero callers anywhere in
// the repository, so OnProcessCreation had never executed in production and
// every capability behind it was inert - VSS attack-type classification, the
// whitelist, the decision callback, the attack-event history, the per-type
// counters, the T1490 telemetry record and the Critical alert.
//
// WHAT WAS AND WAS NOT LOST, stated precisely because BackupProtector's shim
// below covers overlapping commands: the command patterns themselves are NOT
// unique to this module - BackupProtector is wired and matches
// vssadmin_delete_shadows, vssadmin_resize_shadowstorage,
// wmic_shadowcopy_delete and powershell_wmi_shadow_delete.
//
// CORRECTED BY MEASUREMENT. This block used to continue "But its handler does
// exactly one thing on a hit, SS_LOG_WARN, so before this hook existed a T1490
// Inhibit-System-Recovery attempt produced a single warning log line and
// nothing an operator, the alert pipeline or the SOC could see." That was
// written from reading BackupProtector's handler and not the function it calls,
// and it is wrong. AnalyzeProcess consults QueryDecision, moves three counters,
// raises its own alert, records backup_threat_blocked telemetry, and calls
// ExecuteTermination when the action resolves to BlockKill. A T1490 attempt was
// therefore already alerted, counted, telemetered and conditionally enforced
// before this hook existed.
//
// WHAT THIS HOOK GENUINELY RESTORES, stated without the overclaim: the
// VSS-specific attack taxonomy, command coverage BackupProtector does not have
// (diskshadow, Get-CimInstance, Remove-WmiObject, recursive base64 decoding),
// snapshot-count correlation, and the removal of a module that ran its Init and
// Shutdown and reported itself online while its analyzer had no feed at all.
//
// NO ENFORCEMENT IS NEWLY ENABLED. DispatchProcessNotify is void and
// RealTimeProtection returns Allow immediately after calling it, so the Block
// verdict OnProcessCreation computes is still discarded; the module already
// reports that honestly as "DETECTED BUT NOT BLOCKED" and charges it to
// blockRequestedNotPerformed. That counter is now the measure-before-enabling
// number for the transport work.
//
// COST ON THE VERDICT THREAD: this runs on the process-creation callback,
// which owes the kernel an answer inside the fan-out budget. OnProcessCreation
// is bounded string work - filename extraction, a whitelist lookup, three
// small name-compare loops, then AnalyzeCommandInternal, which is
// normalization plus WideIContains checks with no I/O, no syscall and no lock.
// The locking and alerting paths are reached only on an actual detection.
//
// Termination events are dropped: this module keeps no per-process state.
// ---------------------------------------------------------------------------
void ShadowCopyProtector_OnProcessNotify(std::uint32_t pid,
                                         std::uint32_t parentPid,
                                         const std::wstring& imagePath,
                                         const std::wstring& commandLine,
                                         bool isCreation) noexcept {
    if (!isCreation) return;

    // A command line is required, not optional: the VSS destruction intent is
    // carried entirely by the arguments. An image name alone cannot classify an
    // attack here, because vssadmin.exe and wmic.exe have legitimate uses that
    // AnalyzeCommandInternal deliberately allows.
    if (imagePath.empty() || commandLine.empty()) return;

    try {
        ShadowCopyProtector::Instance().OnKernelProcessNotify(
            pid,
            parentPid,
            std::wstring_view{imagePath},
            std::wstring_view{commandLine},
            /*isCreate=*/true);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: ShadowCopyProtector OnKernelProcessNotify exception: {}",
                            e.what());
    } catch (...) {
        Utils::Logger::Warn("RansomwareWiring: ShadowCopyProtector OnKernelProcessNotify unknown exception");
    }
}

}  // namespace ShadowStrike::Ransomware::Wiring::Internal
