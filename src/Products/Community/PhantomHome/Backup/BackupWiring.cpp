/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - BACKUP MODULE WIRING
 * ============================================================================
 *
 * @file BackupWiring.cpp
 * @brief Registers the Backup subsystem with the HomeProductOrchestrator via
 *        a static initializer.
 *
 * BackupManager is the single facade registered here.  It owns and sequences
 * the vault lifecycle, the incremental-transfer engine, and the restore
 * pipeline through its Initialize() / Shutdown() calls.
 *
 * A single RegisterModule() call is the correct design choice for three
 * independent reasons:
 *
 *   1. Facade pattern.  BackupManager::Initialize() brings BackupScheduler,
 *      RestoreManager, and IncrementalBackup up in the correct dependency
 *      order.  Wiring them separately would duplicate lifecycle management
 *      and bypass BackupManager's internal sequencing.
 *
 *   2. Header ODR constraint.  BackupScheduler.hpp, BackupManager.hpp, and
 *      IncrementalBackup.hpp each independently declare
 *      ShadowStrike::Backup::ModuleStatus.  Including more than one of these
 *      headers in the same translation unit triggers a C2011 redefinition
 *      error.  The upstream headers rely on the project PCH to absorb
 *      duplicates; a standalone wiring TU cannot use that mechanism.
 *
 *   3. Startup ordering.  BackupManager is the natural start boundary:
 *      nothing in the Backup subsystem is independently useful without a
 *      vault being open.
 *
 * Config gate : "Home/Backup/Enabled"
 * Phase       : ModulePhase::Background (long-lived snapshot threads)
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "pch.h"

#include "../HomeProductOrchestrator.hpp"
#include "BackupManager.hpp"

#include "../../../../PhantomCore/Utils/Logger.hpp"

#include <ShlObj.h>   // SHGetKnownFolderPath, FOLDERID_LocalAppData
#include <filesystem>

namespace {

constexpr const wchar_t* kLogCategory = L"BackupWiring";

/// @brief Resolve a default vault path under %LOCALAPPDATA%\ShadowStrike.
/// Falls back to a temp-based path if SHGetKnownFolderPath fails.
[[nodiscard]] std::filesystem::path ResolveDefaultVaultPath() noexcept {
    try {
        PWSTR appDataRaw = nullptr;
        HRESULT hr = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &appDataRaw);
        if (SUCCEEDED(hr) && appDataRaw) {
            std::filesystem::path vaultPath =
                std::filesystem::path(appDataRaw) / L"ShadowStrike" / L".ShadowStrikeVault";
            CoTaskMemFree(appDataRaw);
            return vaultPath;
        }
        if (appDataRaw) CoTaskMemFree(appDataRaw);
    } catch (...) { /* fall through */ }

    // Fallback: use temp directory
    std::error_code ec;
    auto tmp = std::filesystem::temp_directory_path(ec);
    if (!ec) {
        return tmp / L"ShadowStrike" / L".ShadowStrikeVault";
    }
    return L"C:\\ProgramData\\ShadowStrike\\.ShadowStrikeVault";
}

struct BackupWiringRegistrar final {
    BackupWiringRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Backup::BackupManager;
            using ::ShadowStrike::Backup::BackupConfiguration;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "BackupManager",
                .enabledConfigKey = "Home/Backup/Enabled",
                .phase            = ModulePhase::Background,

                .initialize = []() -> bool {
                    try {
                        // Build a valid BackupConfiguration with a default vault
                        // path.  BackupConfiguration{} would have an empty
                        // vaultPath and fail IsValid().
                        BackupConfiguration config;
                        config.defaultVault.vaultPath = ResolveDefaultVaultPath();
                        config.defaultVault.encryption = ::ShadowStrike::Backup::EncryptionMode::AES256;
                        config.defaultVault.compression = ::ShadowStrike::Backup::CompressionLevel::Normal;
                        config.defaultVault.hideVault = true;

                        if (!BackupManager::Instance().Initialize(config)) {
                            SS_LOG_ERROR(kLogCategory,
                                L"BackupManager::Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BackupManager: initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BackupManager: initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    // BackupManager has no separate Start() method; the module
                    // is fully operational (vault open, scheduler armed) once
                    // Initialize() returns true.
                    try {
                        if (!BackupManager::Instance().IsInitialized()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"BackupManager: start() called but module is not "
                                L"initialized");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BackupManager: start() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BackupManager: start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        BackupManager::Instance().Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BackupManager: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BackupManager: Shutdown() threw unknown exception");
                    }
                }
            });
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

// Namespace-scope object — constructed before main(), exactly once per
// PhantomHome binary (unnamed namespace prevents ODR issues in other TUs).
const BackupWiringRegistrar g_backupWiringRegistrar{};

}  // namespace
