/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for BackupProtector. Isolated in its own TU because the
 * RansomwareProtection module headers pair-wise redefine the same enums in
 * the ShadowStrike::Ransomware namespace, so only one may be included per TU.
 */
#include "pch.h"
#include "BackupProtector.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Ransomware::Wiring::Internal {

bool BackupProtector_Init() noexcept {
    try {
        if (BackupProtector::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("RansomwareWiring: BackupProtector::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: BackupProtector init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: BackupProtector init unknown exception");
    }
    return false;
}

void BackupProtector_Shutdown() noexcept {
    try {
        BackupProtector::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: BackupProtector shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: BackupProtector shutdown unknown exception");
    }
}

}  // namespace ShadowStrike::Ransomware::Wiring::Internal
