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

}  // namespace ShadowStrike::Ransomware::Wiring
