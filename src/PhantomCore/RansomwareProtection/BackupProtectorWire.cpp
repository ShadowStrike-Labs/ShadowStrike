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

// ---------------------------------------------------------------------------
// Kernel event dispatch for BackupProtector.
//
// BackupProtector exists to intercept destructive backup-removal commands
// (vssadmin delete shadows, wbadmin delete, wmic shadowcopy delete, bcdedit
// recoveryenabled no, etc.) at process-creation time. Without this hook the
// module's pattern store, whitelist, and AnalyzeProcess pipeline would never
// run and the protection would be a no-op.
//
// We only invoke the handler on creation events; process-exit notifications
// are uninteresting to BackupProtector. We swallow exceptions so a single
// misbehaving call cannot take the IPC dispatcher down.
// ---------------------------------------------------------------------------
void BackupProtector_OnProcessNotify(std::uint32_t pid,
                                     const std::wstring& imagePath,
                                     const std::wstring& commandLine,
                                     bool isCreation) noexcept {
    if (!isCreation) return;
    if (imagePath.empty() || commandLine.empty()) return;

    try {
        BackupProtector::Instance().OnKernelProcessNotify(
            pid,
            std::wstring_view{imagePath},
            std::wstring_view{commandLine},
            /*isCreate=*/true);
    } catch (const std::exception& e) {
        Utils::Logger::Warn("RansomwareWiring: BackupProtector OnKernelProcessNotify exception: {}",
                            e.what());
    } catch (...) {
        Utils::Logger::Warn("RansomwareWiring: BackupProtector OnKernelProcessNotify unknown exception");
    }
}

}  // namespace ShadowStrike::Ransomware::Wiring::Internal
