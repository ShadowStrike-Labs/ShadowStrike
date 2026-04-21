/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for VolumeSnapshotService. Isolated in its own TU because the
 * RansomwareProtection module headers pair-wise redefine the same enums in
 * the ShadowStrike::Ransomware namespace, so only one may be included per TU.
 */
#include "pch.h"
#include "VolumeSnapshotService.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Ransomware::Wiring::Internal {

bool VolumeSnapshotService_Init() noexcept {
    try {
        if (VolumeSnapshotService::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("RansomwareWiring: VolumeSnapshotService::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: VolumeSnapshotService init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: VolumeSnapshotService init unknown exception");
    }
    return false;
}

void VolumeSnapshotService_Shutdown() noexcept {
    try {
        VolumeSnapshotService::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: VolumeSnapshotService shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: VolumeSnapshotService shutdown unknown exception");
    }
}

}  // namespace ShadowStrike::Ransomware::Wiring::Internal
