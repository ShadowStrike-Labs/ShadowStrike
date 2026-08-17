/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "pch.h"
/**
 * @file  RansomwareWiring.cpp
 * @brief Aggregator TU for the ransomware-protection subsystem.
 *
 * This file MUST NOT include any individual module header from the
 * RansomwareProtection directory. The per-module headers pair-wise redefine
 * `RansomwareFamily`, `DetectionConfidence`, `BlockCallback`, and
 * `DecisionCallback` in the same `ShadowStrike::Ransomware` namespace, so
 * only one module header may live in a single TU at a time.
 *
 * The actual module calls are delegated to `<Module>Wire.cpp` files through
 * forward-declared free functions under
 * `ShadowStrike::Ransomware::Wiring::Internal`.
 */

#include "RansomwareWiring.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Ransomware::Wiring::Internal {

bool BackupProtector_Init() noexcept;
void BackupProtector_Shutdown() noexcept;
bool FileBackupManager_Init() noexcept;
void FileBackupManager_Shutdown() noexcept;
bool HoneypotManager_Init() noexcept;
void HoneypotManager_Shutdown() noexcept;
bool LockyDetector_Init() noexcept;
void LockyDetector_Shutdown() noexcept;
bool RansomwareDecryptor_Init() noexcept;
void RansomwareDecryptor_Shutdown() noexcept;
bool RansomwareDetector_Init() noexcept;
void RansomwareDetector_Shutdown() noexcept;
bool ShadowCopyProtector_Init() noexcept;
void ShadowCopyProtector_Shutdown() noexcept;
bool VolumeSnapshotService_Init() noexcept;
void VolumeSnapshotService_Shutdown() noexcept;
bool WannaCryDetector_Init() noexcept;
void WannaCryDetector_Shutdown() noexcept;

// Kernel event dispatch — one free function per (module, event). The
// aggregator's public Dispatch* functions fan out to these.
bool RansomwareDetector_OnFileWrite(std::uint32_t pid,
                                    const std::wstring& filePath) noexcept;
bool RansomwareDetector_OnFileRename(std::uint32_t pid,
                                     const std::wstring& oldPath,
                                     const std::wstring& newPath) noexcept;
bool RansomwareDetector_OnFileDelete(std::uint32_t pid,
                                     const std::wstring& filePath) noexcept;
void RansomwareDetector_OnProcessNotify(std::uint32_t pid,
                                        const std::wstring& imagePath,
                                        const std::wstring& commandLine,
                                        bool isCreation) noexcept;
void RansomwareDetector_OnImageLoad(std::uint32_t pid,
                                    const std::wstring& imagePath,
                                    std::uintptr_t imageBase,
                                    std::size_t imageSize) noexcept;
bool RansomwareDetector_IsHoneypotPath(const std::wstring& filePath) noexcept;
void RansomwareDetector_OnHoneypotTouched(std::uint32_t pid,
                                          const std::wstring& filePath) noexcept;

void LockyDetector_OnFileWrite(std::uint32_t pid,
                               const std::wstring& filePath,
                               std::size_t dataSize) noexcept;
void LockyDetector_OnFileRename(std::uint32_t pid,
                                const std::wstring& oldPath,
                                const std::wstring& newPath) noexcept;
void LockyDetector_OnProcessNotify(std::uint32_t pid,
                                   std::uint32_t parentPid,
                                   const std::wstring& imagePath,
                                   bool isCreation) noexcept;
void LockyDetector_OnImageLoad(std::uint32_t pid,
                               const std::wstring& imagePath,
                               std::uintptr_t imageBase) noexcept;

void WannaCryDetector_OnProcessCreated(std::uint32_t pid,
                                       const std::wstring& imagePath,
                                       const std::wstring& commandLine) noexcept;

bool HoneypotManager_OnKernelNotification(const std::wstring& filePath,
                                          std::uint32_t pid,
                                          std::uint32_t threadId,
                                          std::uint8_t accessTypeRaw) noexcept;
void HoneypotManager_OnProcessNotify(std::uint32_t pid,
                                     std::uint32_t parentPid,
                                     const std::wstring& imagePath,
                                     bool isCreation) noexcept;
void HoneypotManager_OnImageLoad(std::uint32_t pid,
                                 const std::wstring& imagePath,
                                 std::uintptr_t imageBase) noexcept;

void BackupProtector_OnProcessNotify(std::uint32_t pid,
                                     const std::wstring& imagePath,
                                     const std::wstring& commandLine,
                                     bool isCreation) noexcept;

void ShadowCopyProtector_OnProcessNotify(std::uint32_t pid,
                                         std::uint32_t parentPid,
                                         const std::wstring& imagePath,
                                         const std::wstring& commandLine,
                                         bool isCreation) noexcept;

void FileBackupManager_OnProcessNotify(std::uint32_t pid,
                                       std::uint32_t parentPid,
                                       const std::wstring& imagePath,
                                       bool isCreation) noexcept;

}  // namespace ShadowStrike::Ransomware::Wiring::Internal

namespace ShadowStrike::Ransomware::Wiring {

bool InitializeRansomwareSubsystem() noexcept {
    using namespace Internal;

    Utils::Logger::Info("RansomwareWiring: initializing subsystem");

    // Protective layer first so detectors can attach into their hooks.
    const bool fbm  = FileBackupManager_Init();
    const bool hpm  = HoneypotManager_Init();
    const bool scp  = ShadowCopyProtector_Init();
    const bool bp   = BackupProtector_Init();
    const bool vss  = VolumeSnapshotService_Init();

    // Detector / responder layer.
    const bool rd   = RansomwareDetector_Init();
    const bool locky = LockyDetector_Init();
    const bool wcry  = WannaCryDetector_Init();
    const bool dec   = RansomwareDecryptor_Init();

    const int ok = (fbm ? 1 : 0) + (hpm ? 1 : 0) + (scp ? 1 : 0) + (bp ? 1 : 0)
                 + (vss ? 1 : 0) + (rd ? 1 : 0) + (locky ? 1 : 0) + (wcry ? 1 : 0)
                 + (dec ? 1 : 0);

    Utils::Logger::Info("RansomwareWiring: subsystem online ({}/9 modules ready)",
                        ok);
    return ok > 0;
}

void ShutdownRansomwareSubsystem() noexcept {
    using namespace Internal;

    Utils::Logger::Info("RansomwareWiring: shutting down subsystem");

    // Strict reverse order of Initialize so detectors release their
    // callbacks before the protectors they reference go away.
    RansomwareDecryptor_Shutdown();
    WannaCryDetector_Shutdown();
    LockyDetector_Shutdown();
    RansomwareDetector_Shutdown();
    VolumeSnapshotService_Shutdown();
    BackupProtector_Shutdown();
    ShadowCopyProtector_Shutdown();
    HoneypotManager_Shutdown();
    FileBackupManager_Shutdown();

    Utils::Logger::Info("RansomwareWiring: subsystem stopped");
}

// ===========================================================================
// PUBLIC DISPATCH API
// ===========================================================================
//
// Every kernel event the user-mode service receives from PhantomSensor is
// routed through exactly one of these Dispatch* functions, which fan out to
// each module that has a handler for that event. They are noexcept and
// resilient: a single misbehaving module cannot take the IPC loop down.

void DispatchFileWrite(std::uint32_t pid,
                       const std::wstring& filePath,
                       const std::wstring& /*processName*/) noexcept {
    using namespace Internal;
    if (filePath.empty()) return;

    // Honeypot first — a decoy touch is an immediate high-confidence signal.
    // OnHoneypotTouched runs the full response pipeline (terminate, backup,
    // snapshot, lockdown), so we short-circuit the regular AnalyzeWrite
    // path to avoid double-triggering on the same kernel event. The Locky
    // sub-detector is also skipped because the process is being torn down.
    if (RansomwareDetector_IsHoneypotPath(filePath)) {
        RansomwareDetector_OnHoneypotTouched(pid, filePath);
        (void)HoneypotManager_OnKernelNotification(
            filePath, pid, /*threadId*/ 0,
            /*accessTypeRaw = Write*/ 2);
        return;
    }

    // Behavioral write analysis + Locky-family scoring.
    (void)RansomwareDetector_OnFileWrite(pid, filePath);
    LockyDetector_OnFileWrite(pid, filePath, /*dataSize*/ 0);
}

void DispatchFileRename(std::uint32_t pid,
                        const std::wstring& oldPath,
                        const std::wstring& newPath) noexcept {
    using namespace Internal;
    if (oldPath.empty() && newPath.empty()) return;

    if (RansomwareDetector_IsHoneypotPath(oldPath) ||
        RansomwareDetector_IsHoneypotPath(newPath)) {
        (void)HoneypotManager_OnKernelNotification(
            oldPath.empty() ? newPath : oldPath, pid, 0,
            /*accessTypeRaw = Rename*/ 4);
    }

    (void)RansomwareDetector_OnFileRename(pid, oldPath, newPath);
    LockyDetector_OnFileRename(pid, oldPath, newPath);
}

void DispatchFileDelete(std::uint32_t pid,
                        const std::wstring& filePath) noexcept {
    using namespace Internal;
    if (filePath.empty()) return;

    if (RansomwareDetector_IsHoneypotPath(filePath)) {
        (void)HoneypotManager_OnKernelNotification(
            filePath, pid, 0, /*accessTypeRaw = Delete*/ 3);
    }

    (void)RansomwareDetector_OnFileDelete(pid, filePath);
}

void DispatchProcessNotify(std::uint32_t pid,
                           std::uint32_t parentPid,
                           const std::wstring& imagePath,
                           const std::wstring& commandLine,
                           bool isCreation) noexcept {
    using namespace Internal;

    RansomwareDetector_OnProcessNotify(pid, imagePath, commandLine, isCreation);
    LockyDetector_OnProcessNotify(pid, parentPid, imagePath, isCreation);
    HoneypotManager_OnProcessNotify(pid, parentPid, imagePath, isCreation);

    // BackupProtector intercepts destructive backup-removal commands
    // (vssadmin delete shadows, wbadmin delete, etc.) at process creation.
    BackupProtector_OnProcessNotify(pid, imagePath, commandLine, isCreation);

    // ShadowCopyProtector is the module that classifies a VSS destruction
    // attempt by type, records it, attributes it to MITRE T1490 and raises the
    // Critical alert. It was absent from this fan-out while its Init and
    // Shutdown were both called, so it reported itself as an online module
    // with no feed.
    //
    // CORRECTED BY MEASUREMENT. This comment used to say that BackupProtector
    // "only writes a warning line on a hit" and that without this call a T1490
    // attempt "was visible nowhere but that one log line". Both are false. The
    // 6287c7fc commit message corrected the claim and left the wrong text here,
    // which is worse than never having written it: this is the comment a reader
    // consults to decide whether one of the two entries is redundant.
    //
    // What BackupProtector_OnProcessNotify above actually reaches is
    // AnalyzeProcess, which consults QueryDecision, moves attemptsBlocked,
    // byThreatType and vssDeletesBlocked, raises its own alert, records
    // backup_threat_blocked telemetry, and calls ExecuteTermination when the
    // action resolves to BlockKill. Its patterns already cover
    // vssadmin_delete_shadows, vssadmin_resize_shadowstorage,
    // wmic_shadowcopy_delete and powershell_wmi_shadow_delete.
    //
    // So what THIS entry adds is not the only visibility. It adds the
    // VSS-specific taxonomy (VSSAttackType rather than BackupThreatType),
    // broader command coverage (diskshadow, Get-CimInstance, Remove-WmiObject,
    // and base64 -EncodedCommand payloads decoded recursively), snapshot-count
    // correlation, and it stops a module reporting itself online with no feed.
    // Do NOT delete either entry on the assumption that the other covers it;
    // the ownership boundary between them is task 169's decision, not an
    // inference to be drawn from this comment.
    ShadowCopyProtector_OnProcessNotify(pid, parentPid, imagePath, commandLine, isCreation);

    // FileBackupManager commits any pending JIT backups when the source
    // process exits — must run on both creation and termination events so
    // dead-PID entries are not left behind to leak memory and starve the
    // eviction logic of room for still-running processes.
    FileBackupManager_OnProcessNotify(pid, parentPid, imagePath, isCreation);

    // WannaCry only cares about process creation events (service/mutex
    // indicators are checked in the creation hot path).
    if (isCreation) {
        WannaCryDetector_OnProcessCreated(pid, imagePath, commandLine);
    }
}

void DispatchImageLoad(std::uint32_t pid,
                       const std::wstring& imagePath,
                       std::uintptr_t imageBase,
                       std::size_t imageSize) noexcept {
    using namespace Internal;
    RansomwareDetector_OnImageLoad(pid, imagePath, imageBase, imageSize);
    LockyDetector_OnImageLoad(pid, imagePath, imageBase);
    HoneypotManager_OnImageLoad(pid, imagePath, imageBase);
}

}  // namespace ShadowStrike::Ransomware::Wiring
