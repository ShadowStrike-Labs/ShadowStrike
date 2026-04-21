/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Per-module wiring shim for FileBackupManager. Isolated in its own TU because the
 * RansomwareProtection module headers pair-wise redefine the same enums in
 * the ShadowStrike::Ransomware namespace, so only one may be included per TU.
 */
#include "pch.h"
#include "FileBackupManager.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike::Ransomware::Wiring::Internal {

bool FileBackupManager_Init() noexcept {
    try {
        if (FileBackupManager::Instance().Initialize()) {
            return true;
        }
        Utils::Logger::Warn("RansomwareWiring: FileBackupManager::Initialize returned false");
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: FileBackupManager init exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: FileBackupManager init unknown exception");
    }
    return false;
}

void FileBackupManager_Shutdown() noexcept {
    try {
        FileBackupManager::Instance().Shutdown();
    } catch (const std::exception& e) {
        Utils::Logger::Error("RansomwareWiring: FileBackupManager shutdown exception: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("RansomwareWiring: FileBackupManager shutdown unknown exception");
    }
}

}  // namespace ShadowStrike::Ransomware::Wiring::Internal
