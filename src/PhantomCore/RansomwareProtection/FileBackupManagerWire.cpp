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

// ---------------------------------------------------------------------------
// Kernel event dispatch for FileBackupManager.
//
// FileBackupManager::OnKernelProcessNotify is responsible for committing any
// JIT backups created on behalf of a process when that process exits — if
// the process exits cleanly the assumption is that its file modifications
// were legitimate, so the rollback data can be reclaimed.  Without this
// hook backups accumulate indefinitely against terminated PIDs (memory and
// disk leak) and the RAM/disk eviction logic ends up evicting *good*
// snapshots from still-running processes before the dead-PID entries.
//
// Exceptions are swallowed so a single bad notify cannot take down the
// IPC dispatcher.
// ---------------------------------------------------------------------------
void FileBackupManager_OnProcessNotify(std::uint32_t pid,
                                       std::uint32_t parentPid,
                                       const std::wstring& imagePath,
                                       bool isCreation) noexcept {
    (void)parentPid;
    try {
        FileBackupManager::Instance().OnKernelProcessNotify(
            pid, parentPid, std::wstring_view{imagePath}, isCreation);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: FileBackupManager OnKernelProcessNotify exception: {}",
                            e.what());
    } catch (...) {
        Utils::Logger::Warn("RansomwareWiring: FileBackupManager OnKernelProcessNotify unknown exception");
    }
}

}  // namespace ShadowStrike::Ransomware::Wiring::Internal
