/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include "pch.h"
/**
 * ============================================================================
 * ShadowStrike NGAV - BACKUP MANAGER IMPLEMENTATION
 * ============================================================================
 *
 * @file BackupManager.cpp
 * @brief Implementation of the BackupManager class using PIMPL pattern.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "BackupManager.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/JsonUtils.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <algorithm>
#include <future>
#include <condition_variable>

#include <rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

namespace ShadowStrike {
namespace Backup {

// ============================================================================
// STATIC INITIALIZATION
// ============================================================================

std::atomic<bool> BackupManager::s_instanceCreated{false};

// ============================================================================
// ANONYMOUS HELPERS
// ============================================================================

namespace {

    // AES-256 key size in bytes
    constexpr size_t AES256_KEY_SIZE = 32;
    // PBKDF2 salt size in bytes
    constexpr size_t SALT_SIZE = 32;
    // PBKDF2 iteration count (OWASP recommendation)
    constexpr uint32_t KDF_ITERATIONS = 310000;
    // Verification tag size
    constexpr size_t VERIFY_TAG_SIZE = 32;
    // Maximum file enumeration count to prevent memory exhaustion
    constexpr size_t MAX_FILE_ENUMERATION = 10'000'000;

    std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            switch (c) {
                case '"': o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b"; break;
                case '\f': o << "\\f"; break;
                case '\n': o << "\\n"; break;
                case '\r': o << "\\r"; break;
                case '\t': o << "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                          << static_cast<int>(static_cast<unsigned char>(c));
                    } else {
                        o << c;
                    }
            }
        }
        return o.str();
    }

    std::string GenerateId() {
        UUID uuid{};
        if (UuidCreate(&uuid) != RPC_S_OK) {
            SS_LOG_ERROR(L"BackupManager", L"UuidCreate failed, falling back to time-based ID");
            // Time-based fallback using secure random
            Utils::CryptoUtils::SecureRandom rng;
            auto bytes = rng.Generate(16);
            if (!bytes.empty()) {
                std::ostringstream oss;
                oss << std::hex << std::setfill('0');
                for (size_t i = 0; i < bytes.size(); ++i) {
                    if (i == 4 || i == 6 || i == 8 || i == 10) oss << '-';
                    oss << std::setw(2) << static_cast<int>(bytes[i]);
                }
                return oss.str();
            }
            return {};
        }
        RPC_CSTR szUuid = nullptr;
        if (UuidToStringA(&uuid, &szUuid) == RPC_S_OK && szUuid) {
            std::string s(reinterpret_cast<const char*>(szUuid));
            RpcStringFreeA(&szUuid);
            return s;
        }
        return {};
    }

    // Derive encryption key from password using PBKDF2-SHA256
    [[nodiscard]] bool DeriveKeyFromPassword(
        std::string_view password,
        const std::vector<uint8_t>& salt,
        Utils::CryptoUtils::SecureByteBuffer& outKey)
    {
        outKey.Resize(AES256_KEY_SIZE);
        if (outKey.Empty()) return false;

        Utils::CryptoUtils::Error err;
        const bool ok = Utils::CryptoUtils::KeyDerivation::PBKDF2(
            reinterpret_cast<const uint8_t*>(password.data()), password.size(),
            salt.data(), salt.size(),
            KDF_ITERATIONS,
            Utils::HashUtils::Algorithm::SHA256,
            outKey.Data(), AES256_KEY_SIZE,
            &err);

        if (!ok) {
            SS_LOG_ERROR(L"BackupManager", L"PBKDF2 key derivation failed: %ls", err.message.c_str());
            outKey.Clear();
        }
        return ok;
    }

    // Compute a verification tag from the derived key for password verification
    [[nodiscard]] bool ComputeVerificationTag(
        const Utils::CryptoUtils::SecureByteBuffer& key,
        const std::vector<uint8_t>& salt,
        std::vector<uint8_t>& outTag)
    {
        outTag.resize(VERIFY_TAG_SIZE);
        Utils::CryptoUtils::Error err;
        // Re-derive using the key bytes as password and a distinct salt suffix
        std::vector<uint8_t> verifySalt = salt;
        verifySalt.push_back(0x01); // Domain separation
        return Utils::CryptoUtils::KeyDerivation::PBKDF2(
            key.Data(), key.Size(),
            verifySalt.data(), verifySalt.size(),
            KDF_ITERATIONS / 10, // Fewer iterations for verification tag
            Utils::HashUtils::Algorithm::SHA256,
            outTag.data(), VERIFY_TAG_SIZE,
            &err);
    }

    // Build a vault-relative path preserving directory structure
    [[nodiscard]] fs::path BuildRelativeBackupPath(
        const fs::path& sourceFile,
        const fs::path& sourceRoot)
    {
        std::error_code ec;
        fs::path relative = fs::relative(sourceFile, sourceRoot, ec);
        if (ec || relative.empty() || relative.native().starts_with(L"..")) {
            // Cannot compute relative path; use drive_letter/full_path structure
            std::wstring full = sourceFile.wstring();
            // Replace : with _ for drive letters (C:\foo -> C_\foo)
            for (auto& ch : full) {
                if (ch == L':') ch = L'_';
            }
            return fs::path(full);
        }
        return relative;
    }

    // Constant-time comparison for verification tags
    [[nodiscard]] bool ConstantTimeCompare(const std::vector<uint8_t>& a,
                                           const std::vector<uint8_t>& b) noexcept {
        if (a.size() != b.size()) return false;
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

}  // anonymous namespace

// ============================================================================
// PER-BACKUP OPERATION STATE
// ============================================================================

struct BackupOperationState {
    std::atomic<bool> cancelled{false};
    std::atomic<bool> paused{false};
    std::mutex pauseMutex;
    std::condition_variable pauseCV;

    void WaitIfPaused() {
        std::unique_lock lock(pauseMutex);
        pauseCV.wait(lock, [this] { return !paused.load(std::memory_order_acquire); });
    }
};

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class BackupManagerImpl {
public:
    BackupManagerImpl() = default;
    ~BackupManagerImpl() { Shutdown(); }

    // State
    BackupConfiguration m_config;
    VaultInfo m_vaultInfo;
    BackupStatistics m_stats;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};

    // Internal Data
    std::vector<BackupPoint> m_backups;
    std::unordered_map<std::string, BackupProgress> m_activeBackups;
    std::vector<BackupJob> m_jobs;

    // Per-backup operation control
    std::unordered_map<std::string, std::shared_ptr<BackupOperationState>> m_opStates;

    // Managed worker threads
    std::vector<std::thread> m_workerThreads;

    // Synchronization
    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_progressMutex;
    mutable std::shared_mutex m_callbackMutex;

    // Vault key (secure memory, wiped on destruction)
    Utils::CryptoUtils::SecureByteBuffer m_vaultKey;
    std::vector<uint8_t> m_vaultSalt;
    std::vector<uint8_t> m_vaultVerifyTag;

    // Callbacks
    std::vector<ProgressCallback> m_progressCallbacks;
    std::vector<CompletionCallback> m_completionCallbacks;
    std::vector<FileCallback> m_fileCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;

    // Threading
    std::atomic<bool> m_stopRequested{false};

    // Retention
    uint32_t m_retentionDays = 30;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const BackupConfiguration& config) {
        std::unique_lock lock(m_mutex);
        if (m_status == ModuleStatus::Running) {
            SS_LOG_WARN(L"BackupManager", L"Already initialized, skipping re-initialization");
            return true;
        }
        if (m_status != ModuleStatus::Uninitialized && m_status != ModuleStatus::Stopped) {
            SS_LOG_WARN(L"BackupManager", L"Cannot initialize from state %d",
                        static_cast<int>(m_status.load()));
            return false;
        }

        if (!config.IsValid()) {
            SS_LOG_ERROR(L"BackupManager", L"Invalid configuration provided");
            return false;
        }

        m_config = config;
        m_status = ModuleStatus::Initializing;
        m_stopRequested = false;

        std::error_code ec;
        if (fs::exists(m_config.defaultVault.vaultPath, ec) && !ec) {
            if (!LoadVaultMetadata()) {
                SS_LOG_WARN(L"BackupManager", L"Vault path exists but metadata load failed");
                m_vaultInfo.status = VaultStatus::Corrupted;
            } else {
                LoadBackupsIndex();
                // Vault loaded but requires unlock if encrypted
                m_vaultInfo.status = m_vaultInfo.isEncrypted
                    ? VaultStatus::Locked
                    : VaultStatus::Ready;
            }
        } else {
            m_vaultInfo.status = VaultStatus::NotInitialized;
        }

        m_stats.Reset();
        m_status = ModuleStatus::Running;

        SS_LOG_INFO(L"BackupManager", L"Initialized successfully. Vault path: %ls, Status: %hs",
                    m_config.defaultVault.vaultPath.c_str(),
                    std::string(GetVaultStatusName(m_vaultInfo.status)).c_str());
        return true;
    }

    void Shutdown() {
        {
            std::unique_lock lock(m_mutex);
            if (m_status == ModuleStatus::Stopped || m_status == ModuleStatus::Uninitialized) return;

            m_status = ModuleStatus::Stopping;
            m_stopRequested.store(true, std::memory_order_release);

            // Cancel all active backup operations
            for (auto& [id, state] : m_opStates) {
                state->cancelled.store(true, std::memory_order_release);
                state->paused.store(false, std::memory_order_release);
                state->pauseCV.notify_all();
            }
        }
        // Join all worker threads WITHOUT holding the lock to prevent deadlock
        for (auto& t : m_workerThreads) {
            if (t.joinable()) {
                t.join();
            }
        }

        {
            std::unique_lock lock(m_mutex);
            m_workerThreads.clear();
            m_opStates.clear();
            m_activeBackups.clear();
            m_vaultKey.Clear();
            m_status = ModuleStatus::Stopped;
        }

        SS_LOG_INFO(L"BackupManager", L"Shutdown complete. All worker threads joined.");
    }

    // ========================================================================
    // VAULT LOGIC
    // ========================================================================

    bool CreateVault(const VaultConfiguration& config) {
        std::unique_lock lock(m_mutex);

        // Validate vault path is not empty and not a system/root path
        if (config.vaultPath.empty()) {
            SS_LOG_ERROR(L"BackupManager", L"Vault path cannot be empty");
            return false;
        }

        std::error_code ec;
        if (fs::exists(config.vaultPath, ec)) {
            if (!fs::is_empty(config.vaultPath, ec) || ec) {
                SS_LOG_ERROR(L"BackupManager", L"Vault path exists and is not empty: %ls",
                             config.vaultPath.c_str());
                return false;
            }
        }

        try {
            fs::create_directories(config.vaultPath, ec);
            if (ec) {
                SS_LOG_ERROR(L"BackupManager", L"Failed to create vault directory: %ls (%hs)",
                             config.vaultPath.c_str(), ec.message().c_str());
                return false;
            }

            // Set hidden + system attributes for vault protection
            if (config.hideVault) {
                DWORD attrs = ::GetFileAttributesW(config.vaultPath.c_str());
                if (attrs != INVALID_FILE_ATTRIBUTES) {
                    ::SetFileAttributesW(config.vaultPath.c_str(),
                                         attrs | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                }
            }

            // Set up encryption key material
            m_vaultInfo.vaultId = GenerateId();
            if (m_vaultInfo.vaultId.empty()) {
                SS_LOG_ERROR(L"BackupManager", L"Failed to generate vault ID");
                return false;
            }

            m_vaultInfo.path = config.vaultPath;
            m_vaultInfo.creationTime = std::chrono::system_clock::now();
            m_vaultInfo.isEncrypted = (config.encryption != EncryptionMode::None);
            m_vaultInfo.isHidden = config.hideVault;
            m_vaultInfo.isProtected = config.enableMinifilterProtection;
            m_vaultInfo.status = VaultStatus::Ready;

            if (m_vaultInfo.isEncrypted) {
                // Generate random salt for this vault
                Utils::CryptoUtils::Error cryptErr;
                if (!Utils::CryptoUtils::KeyDerivation::GenerateSalt(m_vaultSalt, SALT_SIZE, &cryptErr)) {
                    SS_LOG_ERROR(L"BackupManager", L"Failed to generate vault salt");
                    return false;
                }

                // Use the provided encryption key directly, or error if empty
                if (config.encryptionKey.size() < AES256_KEY_SIZE) {
                    SS_LOG_ERROR(L"BackupManager", L"Encryption key too short (%zu bytes, need %zu)",
                                 config.encryptionKey.size(), AES256_KEY_SIZE);
                    return false;
                }

                m_vaultKey.Resize(AES256_KEY_SIZE);
                if (m_vaultKey.Empty()) {
                    SS_LOG_ERROR(L"BackupManager", L"Failed to allocate secure key buffer");
                    return false;
                }
                m_vaultKey.CopyFrom(config.encryptionKey.data(), AES256_KEY_SIZE);

                // Compute verification tag for future password/key verification
                if (!ComputeVerificationTag(m_vaultKey, m_vaultSalt, m_vaultVerifyTag)) {
                    SS_LOG_ERROR(L"BackupManager", L"Failed to compute verification tag");
                    m_vaultKey.Clear();
                    return false;
                }
            }

            // Update config
            m_config.defaultVault = config;

            if (!SaveVaultMetadata()) {
                SS_LOG_ERROR(L"BackupManager", L"Failed to persist vault metadata after creation");
                return false;
            }

            SS_LOG_INFO(L"BackupManager", L"Vault created: %ls (encrypted=%d, hidden=%d)",
                        config.vaultPath.c_str(), m_vaultInfo.isEncrypted, m_vaultInfo.isHidden);
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"BackupManager", L"Exception during vault creation: %hs", e.what());
            return false;
        }
    }

    bool OpenVault(const fs::path& vaultPath, const std::string& password) {
        std::unique_lock lock(m_mutex);

        if (vaultPath.empty()) {
            SS_LOG_ERROR(L"BackupManager", L"Vault path cannot be empty");
            return false;
        }

        std::error_code ec;
        if (!fs::exists(vaultPath, ec) || ec) {
            SS_LOG_ERROR(L"BackupManager", L"Vault path does not exist: %ls", vaultPath.c_str());
            return false;
        }

        // Load vault metadata
        m_config.defaultVault.vaultPath = vaultPath;
        if (!LoadVaultMetadata()) {
            SS_LOG_ERROR(L"BackupManager", L"Failed to load vault metadata from: %ls", vaultPath.c_str());
            return false;
        }

        // If encrypted, verify password
        if (m_vaultInfo.isEncrypted) {
            if (password.empty()) {
                SS_LOG_ERROR(L"BackupManager", L"Password required for encrypted vault");
                m_vaultInfo.status = VaultStatus::Locked;
                return false;
            }

            if (!VerifyAndDeriveKey(password)) {
                SS_LOG_ERROR(L"BackupManager", L"Invalid password for vault: %ls", vaultPath.c_str());
                m_vaultInfo.status = VaultStatus::Locked;
                return false;
            }
        }

        LoadBackupsIndex();
        m_vaultInfo.status = VaultStatus::Ready;

        SS_LOG_INFO(L"BackupManager", L"Vault opened: %ls", vaultPath.c_str());
        return true;
    }

    void CloseVault() {
        std::unique_lock lock(m_mutex);

        // Don't close if backups are running
        if (!m_activeBackups.empty()) {
            SS_LOG_WARN(L"BackupManager", L"Cannot close vault: %zu active backups",
                        m_activeBackups.size());
            return;
        }

        m_vaultKey.Clear();
        m_vaultSalt.clear();
        m_vaultVerifyTag.clear();
        m_vaultInfo = VaultInfo{};
        m_backups.clear();

        SS_LOG_INFO(L"BackupManager", L"Vault closed");
    }

    bool LockVault() {
        std::unique_lock lock(m_mutex);
        if (m_vaultInfo.status != VaultStatus::Ready) {
            SS_LOG_WARN(L"BackupManager", L"Cannot lock vault in state: %hs",
                        std::string(GetVaultStatusName(m_vaultInfo.status)).c_str());
            return false;
        }

        // Securely wipe the key from memory
        m_vaultKey.Clear();
        m_vaultInfo.status = VaultStatus::Locked;

        SS_LOG_INFO(L"BackupManager", L"Vault locked, encryption key wiped from memory");
        return true;
    }

    bool UnlockVault(const std::string& password) {
        std::unique_lock lock(m_mutex);

        if (m_vaultInfo.status != VaultStatus::Locked) {
            SS_LOG_WARN(L"BackupManager", L"Vault is not in locked state (current: %hs)",
                        std::string(GetVaultStatusName(m_vaultInfo.status)).c_str());
            return false;
        }

        if (password.empty()) {
            SS_LOG_ERROR(L"BackupManager", L"Password cannot be empty for vault unlock");
            return false;
        }

        if (!VerifyAndDeriveKey(password)) {
            SS_LOG_ERROR(L"BackupManager", L"Invalid password for vault unlock");
            m_stats.ransomwareBlockedAttempts++;
            return false;
        }

        m_vaultInfo.status = VaultStatus::Ready;
        SS_LOG_INFO(L"BackupManager", L"Vault unlocked successfully");
        return true;
    }

    bool ChangeVaultPassword(const std::string& oldPassword, const std::string& newPassword) {
        std::unique_lock lock(m_mutex);

        if (m_vaultInfo.status != VaultStatus::Ready && m_vaultInfo.status != VaultStatus::Locked) {
            SS_LOG_ERROR(L"BackupManager", L"Cannot change password in current vault state");
            return false;
        }
        if (newPassword.empty()) {
            SS_LOG_ERROR(L"BackupManager", L"New password cannot be empty");
            return false;
        }

        // Verify old password
        Utils::CryptoUtils::SecureByteBuffer oldKey;
        if (!DeriveKeyFromPassword(oldPassword, m_vaultSalt, oldKey)) {
            return false;
        }
        std::vector<uint8_t> oldTag;
        if (!ComputeVerificationTag(oldKey, m_vaultSalt, oldTag)) {
            return false;
        }
        if (!ConstantTimeCompare(oldTag, m_vaultVerifyTag)) {
            SS_LOG_ERROR(L"BackupManager", L"Old password verification failed");
            return false;
        }

        // Generate new salt and derive new key
        Utils::CryptoUtils::Error cryptErr;
        std::vector<uint8_t> newSalt;
        if (!Utils::CryptoUtils::KeyDerivation::GenerateSalt(newSalt, SALT_SIZE, &cryptErr)) {
            SS_LOG_ERROR(L"BackupManager", L"Failed to generate new salt");
            return false;
        }

        Utils::CryptoUtils::SecureByteBuffer newKey;
        if (!DeriveKeyFromPassword(newPassword, newSalt, newKey)) {
            return false;
        }

        std::vector<uint8_t> newTag;
        if (!ComputeVerificationTag(newKey, newSalt, newTag)) {
            return false;
        }

        // Atomic swap of key material
        m_vaultSalt = std::move(newSalt);
        m_vaultVerifyTag = std::move(newTag);
        m_vaultKey = std::move(newKey);

        if (!SaveVaultMetadata()) {
            SS_LOG_ERROR(L"BackupManager", L"Failed to persist updated vault metadata");
            return false;
        }

        SS_LOG_INFO(L"BackupManager", L"Vault password changed successfully");
        return true;
    }

    // ========================================================================
    // KEY VERIFICATION HELPER
    // ========================================================================

    bool VerifyAndDeriveKey(const std::string& password) {
        if (m_vaultSalt.empty() || m_vaultVerifyTag.empty()) {
            SS_LOG_ERROR(L"BackupManager", L"Vault salt/verification data not loaded");
            return false;
        }

        Utils::CryptoUtils::SecureByteBuffer candidateKey;
        if (!DeriveKeyFromPassword(password, m_vaultSalt, candidateKey)) {
            return false;
        }

        std::vector<uint8_t> candidateTag;
        if (!ComputeVerificationTag(candidateKey, m_vaultSalt, candidateTag)) {
            return false;
        }

        if (!ConstantTimeCompare(candidateTag, m_vaultVerifyTag)) {
            return false;
        }

        // Password verified, store the derived key
        m_vaultKey = std::move(candidateKey);
        return true;
    }

    // ========================================================================
    // BACKUP LOGIC
    // ========================================================================

    std::string CreateBackup(const std::vector<BackupSource>& sources,
                             BackupType type,
                             const std::string& label)
    {
        if (sources.empty()) {
            NotifyError("No backup sources provided", 101);
            return {};
        }

        {
            std::shared_lock lock(m_mutex);
            if (m_status != ModuleStatus::Running) {
                NotifyError("BackupManager is not running", 102);
                return {};
            }
            if (m_vaultInfo.status != VaultStatus::Ready) {
                NotifyError("Vault is not ready (status=" +
                            std::string(GetVaultStatusName(m_vaultInfo.status)) + ")", 103);
                return {};
            }
        }

        // Validate all source paths exist and are not path-traversal attacks targeting the vault
        for (const auto& source : sources) {
            std::error_code ec;
            if (!fs::exists(source.path, ec) || ec) {
                NotifyError("Source path does not exist: " + source.path.string(), 104);
                return {};
            }

            // Ensure source is not inside the vault (prevent recursive backup)
            fs::path canonSource = fs::weakly_canonical(source.path, ec);
            fs::path canonVault = fs::weakly_canonical(m_vaultInfo.path, ec);
            if (!ec) {
                auto [srcEnd, vaultEnd] = std::mismatch(
                    canonVault.begin(), canonVault.end(),
                    canonSource.begin(), canonSource.end());
                if (srcEnd == canonVault.end()) {
                    NotifyError("Source path is inside vault (recursive backup prevented): " +
                                source.path.string(), 105);
                    return {};
                }
            }
        }

        std::string backupId = GenerateId();
        if (backupId.empty()) {
            NotifyError("Failed to generate backup ID", 106);
            return {};
        }

        auto opState = std::make_shared<BackupOperationState>();

        BackupPoint bp;
        bp.backupId = backupId;
        bp.type = type;
        bp.status = BackupStatus::Pending;
        bp.startTime = std::chrono::system_clock::now();
        bp.sources = sources;
        bp.label = label;
        bp.isEncrypted = m_vaultInfo.isEncrypted;

        {
            std::unique_lock lock(m_mutex);

            // Enforce max backup points
            if (m_backups.size() >= m_config.defaultVault.maxBackupPoints) {
                NotifyError("Maximum backup points reached (" +
                            std::to_string(m_config.defaultVault.maxBackupPoints) + ")", 107);
                return {};
            }

            // Check concurrent operation limit
            if (m_activeBackups.size() >= m_config.maxConcurrentOperations) {
                NotifyError("Maximum concurrent operations reached (" +
                            std::to_string(m_config.maxConcurrentOperations) + ")", 108);
                return {};
            }

            m_backups.push_back(bp);
            m_opStates[backupId] = opState;

            BackupProgress progress;
            progress.backupId = backupId;
            progress.phase = "Initializing";

            std::unique_lock plock(m_progressMutex);
            m_activeBackups[backupId] = std::move(progress);
        }

        // Copy key for thread-safe usage (the key is needed in the worker thread)
        Utils::CryptoUtils::SecureByteBuffer threadKey;
        if (m_vaultInfo.isEncrypted && !m_vaultKey.Empty()) {
            threadKey.Resize(m_vaultKey.Size());
            if (!threadKey.Empty()) {
                threadKey.CopyFrom(m_vaultKey.Data(), m_vaultKey.Size());
            }
        }

        // Launch worker thread (managed, not detached)
        std::unique_lock lock(m_mutex);
        m_workerThreads.emplace_back(
            [this, backupId, sources, opState, key = std::move(threadKey)]() mutable {
                PerformBackup(backupId, sources, opState, key);
                key.Clear();
            }
        );

        return backupId;
    }

    void PerformBackup(const std::string& backupId,
                       const std::vector<BackupSource>& sources,
                       std::shared_ptr<BackupOperationState> opState,
                       const Utils::CryptoUtils::SecureByteBuffer& encKey)
    {
        SS_LOG_INFO(L"BackupManager", L"Starting backup %hs", backupId.c_str());
        UpdateBackupStatus(backupId, BackupStatus::InProgress);

        uint64_t totalFiles = 0;
        uint64_t totalBytes = 0;

        // ---- Phase 1: Scan ----
        UpdateProgress(backupId, "Scanning", 0);

        struct FileEntry {
            fs::path fullPath;
            fs::path sourceRoot;
            uint64_t size = 0;
        };
        std::vector<FileEntry> fileList;

        for (const auto& source : sources) {
            if (opState->cancelled.load(std::memory_order_acquire)) break;

            std::error_code ec;
            if (!fs::exists(source.path, ec) || ec) {
                SS_LOG_WARN(L"BackupManager", L"Source path disappeared during scan: %ls",
                            source.path.c_str());
                continue;
            }

            if (fs::is_directory(source.path, ec)) {
                // Only follow directory symlinks if explicitly configured
                auto opts = source.followSymlinks
                    ? (fs::directory_options::skip_permission_denied |
                       fs::directory_options::follow_directory_symlink)
                    : fs::directory_options::skip_permission_denied;

                if (source.recursive) {
                    for (auto it = fs::recursive_directory_iterator(source.path, opts, ec);
                         it != fs::recursive_directory_iterator() && !ec;
                         it.increment(ec))
                    {
                        if (opState->cancelled.load(std::memory_order_acquire)) break;
                        if (fileList.size() >= MAX_FILE_ENUMERATION) {
                            SS_LOG_WARN(L"BackupManager", L"File enumeration limit reached (%zu)",
                                        MAX_FILE_ENUMERATION);
                            break;
                        }

                        if (it->is_regular_file(ec) && !ec) {
                            // Skip symlinks if not following them
                            if (!source.followSymlinks && it->is_symlink(ec)) continue;

                            auto fsize = it->file_size(ec);
                            if (ec) { fsize = 0; ec.clear(); }

                            fileList.push_back({it->path(), source.path, fsize});
                            totalFiles++;
                            totalBytes += fsize;
                        }
                    }
                } else {
                    for (auto it = fs::directory_iterator(source.path, opts, ec);
                         it != fs::directory_iterator() && !ec;
                         it.increment(ec))
                    {
                        if (it->is_regular_file(ec) && !ec) {
                            if (!source.followSymlinks && it->is_symlink(ec)) continue;
                            auto fsize = it->file_size(ec);
                            if (ec) { fsize = 0; ec.clear(); }
                            fileList.push_back({it->path(), source.path, fsize});
                            totalFiles++;
                            totalBytes += fsize;
                        }
                    }
                }
            } else if (fs::is_regular_file(source.path, ec)) {
                auto fsize = fs::file_size(source.path, ec);
                if (ec) { fsize = 0; ec.clear(); }
                fileList.push_back({source.path, source.path.parent_path(), fsize});
                totalFiles++;
                totalBytes += fsize;
            }
        }

        if (ec_check_cancelled(backupId, opState)) return;

        UpdateProgress(backupId, "Scanning", 10, 0, totalFiles, totalBytes);

        // ---- Phase 2: Backup files ----
        uint64_t processedFiles = 0;
        uint64_t processedBytes = 0;
        uint64_t filesBackedUp = 0;
        uint64_t filesFailed = 0;
        uint64_t filesSkipped = 0;
        std::vector<std::string> errors;

        for (const auto& entry : fileList) {
            if (ec_check_cancelled(backupId, opState)) return;
            opState->WaitIfPaused();
            if (ec_check_cancelled(backupId, opState)) return;

            int progressPct = (totalFiles > 0)
                ? 10 + static_cast<int>(
                    static_cast<double>(processedFiles) / static_cast<double>(totalFiles) * 80.0)
                : 10;

            UpdateProgress(backupId, "Backing up", progressPct,
                           processedFiles, totalFiles, processedBytes, entry.fullPath);

            // Check file callback (allow skipping)
            {
                std::shared_lock cblock(m_callbackMutex);
                bool skip = false;
                for (const auto& cb : m_fileCallbacks) {
                    try {
                        if (!cb(entry.fullPath)) {
                            skip = true;
                            break;
                        }
                    } catch (...) {
                        SS_LOG_WARN(L"BackupManager", L"File callback threw exception for: %ls",
                                    entry.fullPath.c_str());
                    }
                }
                if (skip) {
                    filesSkipped++;
                    processedFiles++;
                    processedBytes += entry.size;
                    continue;
                }
            }

            try {
                std::error_code ec;
                fs::path backupDir = m_vaultInfo.path / backupId / "data";
                fs::create_directories(backupDir, ec);
                if (ec) {
                    throw std::runtime_error("Failed to create backup directory: " + ec.message());
                }

                // Preserve directory structure
                fs::path relPath = BuildRelativeBackupPath(entry.fullPath, entry.sourceRoot);
                fs::path destFile = backupDir / relPath;

                // Create parent directories for the destination
                if (destFile.has_parent_path()) {
                    fs::create_directories(destFile.parent_path(), ec);
                    if (ec) {
                        throw std::runtime_error("Failed to create dest parent: " + ec.message());
                    }
                }

                // Handle filename collisions
                if (fs::exists(destFile, ec)) {
                    std::string stem = destFile.stem().string();
                    std::string ext = destFile.extension().string();
                    std::string suffix = GenerateId().substr(0, 8);
                    destFile = destFile.parent_path() / (stem + "_" + suffix + ext);
                }

                if (m_vaultInfo.isEncrypted && !encKey.Empty()) {
                    // Encrypt the file using CryptoUtils infrastructure
                    fs::path encDest = destFile;
                    encDest += L".enc";
                    Utils::CryptoUtils::Error cryptErr;
                    if (!Utils::CryptoUtils::EncryptFile(
                            entry.fullPath.wstring(), encDest.wstring(),
                            encKey.Data(), encKey.Size(), &cryptErr))
                    {
                        throw std::runtime_error("Encryption failed: " +
                            std::string(cryptErr.message.begin(), cryptErr.message.end()));
                    }
                    filesBackedUp++;
                } else {
                    fs::copy_file(entry.fullPath, destFile,
                                  fs::copy_options::overwrite_existing, ec);
                    if (ec) {
                        throw std::runtime_error("Copy failed: " + ec.message());
                    }
                    filesBackedUp++;
                }

            } catch (const std::exception& ex) {
                filesFailed++;
                std::string errMsg = "Failed to backup " +
                    entry.fullPath.string() + ": " + ex.what();
                errors.push_back(errMsg);
                SS_LOG_ERROR(L"BackupManager", L"Backup file error: %hs", errMsg.c_str());
            }

            processedFiles++;
            processedBytes += entry.size;
        }

        // ---- Phase 3: Finalize ----
        if (opState->cancelled.load(std::memory_order_acquire)) {
            UpdateBackupStatus(backupId, BackupStatus::Cancelled);
            m_stats.failedBackups++;
        } else {
            UpdateProgress(backupId, "Finalizing", 95, processedFiles, totalFiles, processedBytes);

            // Update the BackupPoint with actual statistics
            {
                std::unique_lock lock(m_mutex);
                auto it = std::find_if(m_backups.begin(), m_backups.end(),
                    [&](const BackupPoint& bp) { return bp.backupId == backupId; });
                if (it != m_backups.end()) {
                    it->totalFiles = totalFiles;
                    it->filesBackedUp = filesBackedUp;
                    it->filesFailed = filesFailed;
                    it->filesSkipped = filesSkipped;
                    it->totalSize = totalBytes;
                    it->backedUpSize = processedBytes;
                }
            }

            BackupStatus finalStatus = (filesFailed > 0 && filesBackedUp == 0)
                ? BackupStatus::Failed
                : (filesFailed > 0 ? BackupStatus::Partial : BackupStatus::Completed);

            UpdateBackupStatus(backupId, finalStatus);

            m_stats.totalBackups++;
            if (finalStatus == BackupStatus::Completed || finalStatus == BackupStatus::Partial) {
                m_stats.successfulBackups++;
            } else {
                m_stats.failedBackups++;
            }
            m_stats.totalFilesBackedUp += filesBackedUp;
            m_stats.totalBytesBackedUp += processedBytes;

            // Notify completion (copy the backup point to avoid holding lock during callback)
            BackupPoint completedBp;
            {
                std::shared_lock lock(m_mutex);
                auto it = std::find_if(m_backups.begin(), m_backups.end(),
                    [&](const BackupPoint& bp) { return bp.backupId == backupId; });
                if (it != m_backups.end()) {
                    completedBp = *it;
                }
            }
            if (!completedBp.backupId.empty()) {
                NotifyCompletion(completedBp);
            }
        }

        // Remove from active backups
        {
            std::unique_lock lock(m_progressMutex);
            m_activeBackups.erase(backupId);
        }
        {
            std::unique_lock lock(m_mutex);
            m_opStates.erase(backupId);
        }

        SS_LOG_INFO(L"BackupManager", L"Backup %hs finished. Files: %llu ok, %llu failed, %llu skipped",
                    backupId.c_str(), filesBackedUp, filesFailed, filesSkipped);
    }

    // Check cancellation and finalize if cancelled
    bool ec_check_cancelled(const std::string& backupId,
                            const std::shared_ptr<BackupOperationState>& opState)
    {
        if (opState->cancelled.load(std::memory_order_acquire) ||
            m_stopRequested.load(std::memory_order_acquire))
        {
            UpdateBackupStatus(backupId, BackupStatus::Cancelled);
            {
                std::unique_lock lock(m_progressMutex);
                m_activeBackups.erase(backupId);
            }
            {
                std::unique_lock lock(m_mutex);
                m_opStates.erase(backupId);
            }
            return true;
        }
        return false;
    }

    bool CancelBackup(const std::string& backupId) {
        std::shared_lock lock(m_mutex);
        auto it = m_opStates.find(backupId);
        if (it == m_opStates.end()) {
            SS_LOG_WARN(L"BackupManager", L"Cannot cancel: backup %hs not found or not active",
                        backupId.c_str());
            return false;
        }
        it->second->cancelled.store(true, std::memory_order_release);
        // Wake from pause if paused
        it->second->paused.store(false, std::memory_order_release);
        it->second->pauseCV.notify_all();
        SS_LOG_INFO(L"BackupManager", L"Cancellation requested for backup %hs", backupId.c_str());
        return true;
    }

    bool PauseBackup(const std::string& backupId) {
        std::shared_lock lock(m_mutex);
        auto it = m_opStates.find(backupId);
        if (it == m_opStates.end()) return false;
        it->second->paused.store(true, std::memory_order_release);
        SS_LOG_INFO(L"BackupManager", L"Pause requested for backup %hs", backupId.c_str());
        return true;
    }

    bool ResumeBackup(const std::string& backupId) {
        std::shared_lock lock(m_mutex);
        auto it = m_opStates.find(backupId);
        if (it == m_opStates.end()) return false;
        it->second->paused.store(false, std::memory_order_release);
        it->second->pauseCV.notify_all();
        SS_LOG_INFO(L"BackupManager", L"Resume requested for backup %hs", backupId.c_str());
        return true;
    }

    void UpdateBackupStatus(const std::string& backupId, BackupStatus status) {
        std::unique_lock lock(m_mutex);
        auto it = std::find_if(m_backups.begin(), m_backups.end(),
            [&](const BackupPoint& bp) { return bp.backupId == backupId; });

        if (it != m_backups.end()) {
            it->status = status;
            if (status == BackupStatus::Completed || status == BackupStatus::Failed ||
                status == BackupStatus::Cancelled || status == BackupStatus::Partial) {
                it->endTime = std::chrono::system_clock::now();
                it->duration = std::chrono::duration_cast<std::chrono::seconds>(
                    it->endTime - it->startTime);
                SaveBackupsIndex();
            }
        }
    }

    void UpdateProgress(const std::string& backupId, const std::string& phase,
                        int percent, uint64_t filesProcessed = 0, uint64_t totalFiles = 0,
                        uint64_t bytesProcessed = 0, const fs::path& currentFile = L"")
    {
        BackupProgress progress;
        {
            std::unique_lock lock(m_progressMutex);
            auto it = m_activeBackups.find(backupId);
            if (it == m_activeBackups.end()) return;

            auto& p = it->second;
            p.phase = phase;
            p.percentComplete = std::clamp(percent, 0, 100);
            p.filesProcessed = filesProcessed;
            p.totalFiles = totalFiles;
            p.bytesProcessed = bytesProcessed;
            p.currentFile = currentFile;
            progress = p;
        }

        NotifyProgress(progress);
    }

    // ========================================================================
    // BACKUP POINT OPERATIONS
    // ========================================================================

    bool VerifyBackup(const std::string& backupId) {
        std::shared_lock lock(m_mutex);
        auto it = std::find_if(m_backups.begin(), m_backups.end(),
            [&](const BackupPoint& bp) { return bp.backupId == backupId; });

        if (it == m_backups.end()) {
            SS_LOG_ERROR(L"BackupManager", L"Backup not found for verification: %hs", backupId.c_str());
            return false;
        }

        if (it->status != BackupStatus::Completed && it->status != BackupStatus::Partial) {
            SS_LOG_ERROR(L"BackupManager", L"Cannot verify backup in state: %hs",
                        std::string(GetBackupStatusName(it->status)).c_str());
            return false;
        }

        // Verify that the backup data directory exists and has files
        std::error_code ec;
        fs::path backupDir = m_vaultInfo.path / backupId / "data";
        if (!fs::exists(backupDir, ec) || ec) {
            SS_LOG_ERROR(L"BackupManager", L"Backup data directory missing: %ls", backupDir.c_str());
            return false;
        }

        uint64_t verifiedFiles = 0;
        for (auto dirIt = fs::recursive_directory_iterator(backupDir, ec);
             dirIt != fs::recursive_directory_iterator() && !ec;
             dirIt.increment(ec))
        {
            if (dirIt->is_regular_file(ec) && !ec) {
                verifiedFiles++;
            }
        }

        bool verified = (verifiedFiles > 0);
        SS_LOG_INFO(L"BackupManager", L"Backup %hs verification: %llu files found (expected %llu)",
                    backupId.c_str(), verifiedFiles, it->filesBackedUp);

        return verified;
    }

    bool DeleteBackup(const std::string& backupId) {
        std::unique_lock lock(m_mutex);

        // Don't delete if actively running
        if (m_opStates.find(backupId) != m_opStates.end()) {
            SS_LOG_ERROR(L"BackupManager", L"Cannot delete active backup: %hs", backupId.c_str());
            return false;
        }

        auto it = std::find_if(m_backups.begin(), m_backups.end(),
            [&](const BackupPoint& bp) { return bp.backupId == backupId; });

        if (it == m_backups.end()) {
            SS_LOG_ERROR(L"BackupManager", L"Backup not found for deletion: %hs", backupId.c_str());
            return false;
        }

        // Remove backup data from disk
        std::error_code ec;
        fs::path backupDir = m_vaultInfo.path / backupId;
        if (fs::exists(backupDir, ec)) {
            fs::remove_all(backupDir, ec);
            if (ec) {
                SS_LOG_ERROR(L"BackupManager", L"Failed to remove backup directory: %ls (%hs)",
                             backupDir.c_str(), ec.message().c_str());
                return false;
            }
        }

        m_backups.erase(it);
        SaveBackupsIndex();

        SS_LOG_INFO(L"BackupManager", L"Backup deleted: %hs", backupId.c_str());
        return true;
    }

    // ========================================================================
    // JOB MANAGEMENT
    // ========================================================================

    bool CreateJob(const BackupJob& job) {
        std::unique_lock lock(m_mutex);

        if (job.jobId.empty() || job.name.empty() || job.sources.empty()) {
            SS_LOG_ERROR(L"BackupManager", L"Invalid job parameters");
            return false;
        }

        // Check for duplicate job ID
        auto it = std::find_if(m_jobs.begin(), m_jobs.end(),
            [&](const BackupJob& j) { return j.jobId == job.jobId; });
        if (it != m_jobs.end()) {
            SS_LOG_ERROR(L"BackupManager", L"Job ID already exists: %hs", job.jobId.c_str());
            return false;
        }

        m_jobs.push_back(job);
        SS_LOG_INFO(L"BackupManager", L"Backup job created: %hs (%hs)",
                    job.jobId.c_str(), job.name.c_str());
        return true;
    }

    bool UpdateJob(const BackupJob& job) {
        std::unique_lock lock(m_mutex);
        auto it = std::find_if(m_jobs.begin(), m_jobs.end(),
            [&](const BackupJob& j) { return j.jobId == job.jobId; });
        if (it == m_jobs.end()) {
            SS_LOG_ERROR(L"BackupManager", L"Job not found for update: %hs", job.jobId.c_str());
            return false;
        }
        *it = job;
        SS_LOG_INFO(L"BackupManager", L"Backup job updated: %hs", job.jobId.c_str());
        return true;
    }

    bool DeleteJob(const std::string& jobId) {
        std::unique_lock lock(m_mutex);
        auto it = std::find_if(m_jobs.begin(), m_jobs.end(),
            [&](const BackupJob& j) { return j.jobId == jobId; });
        if (it == m_jobs.end()) {
            SS_LOG_ERROR(L"BackupManager", L"Job not found for deletion: %hs", jobId.c_str());
            return false;
        }
        m_jobs.erase(it);
        SS_LOG_INFO(L"BackupManager", L"Backup job deleted: %hs", jobId.c_str());
        return true;
    }

    std::string RunJob(const std::string& jobId) {
        BackupJob job;
        {
            std::shared_lock lock(m_mutex);
            auto it = std::find_if(m_jobs.begin(), m_jobs.end(),
                [&](const BackupJob& j) { return j.jobId == jobId; });
            if (it == m_jobs.end()) {
                SS_LOG_ERROR(L"BackupManager", L"Job not found: %hs", jobId.c_str());
                return {};
            }
            if (!it->enabled) {
                SS_LOG_WARN(L"BackupManager", L"Job is disabled: %hs", jobId.c_str());
                return {};
            }
            job = *it;
        }

        std::string backupId = CreateBackup(job.sources, job.type, job.name);

        if (!backupId.empty()) {
            std::unique_lock lock(m_mutex);
            auto it = std::find_if(m_jobs.begin(), m_jobs.end(),
                [&](const BackupJob& j) { return j.jobId == jobId; });
            if (it != m_jobs.end()) {
                it->lastRun = std::chrono::system_clock::now();
            }
        }

        return backupId;
    }

    // ========================================================================
    // RETENTION POLICY
    // ========================================================================

    uint32_t ApplyRetentionPolicy() {
        std::unique_lock lock(m_mutex);
        uint32_t removed = 0;
        auto now = std::chrono::system_clock::now();

        auto it = m_backups.begin();
        while (it != m_backups.end()) {
            // Don't remove active backups
            if (m_opStates.find(it->backupId) != m_opStates.end()) {
                ++it;
                continue;
            }

            auto age = std::chrono::duration_cast<std::chrono::hours>(now - it->endTime);
            if (age.count() > static_cast<long long>(m_retentionDays) * 24 &&
                (it->status == BackupStatus::Completed || it->status == BackupStatus::Partial ||
                 it->status == BackupStatus::Failed || it->status == BackupStatus::Cancelled))
            {
                // Remove backup data
                std::error_code ec;
                fs::path backupDir = m_vaultInfo.path / it->backupId;
                if (fs::exists(backupDir, ec)) {
                    fs::remove_all(backupDir, ec);
                }
                it = m_backups.erase(it);
                removed++;
            } else {
                ++it;
            }
        }

        if (removed > 0) {
            SaveBackupsIndex();
            SS_LOG_INFO(L"BackupManager", L"Retention policy applied: %u backups removed", removed);
        }

        return removed;
    }

    // ========================================================================
    // IO HELPERS
    // ========================================================================

    [[nodiscard]] bool SaveVaultMetadata() {
        try {
            Utils::JSON::Json j;
            j["vaultId"] = m_vaultInfo.vaultId;
            j["path"] = m_vaultInfo.path.string();
            j["creationTime"] = std::chrono::duration_cast<std::chrono::seconds>(
                m_vaultInfo.creationTime.time_since_epoch()).count();
            j["isEncrypted"] = m_vaultInfo.isEncrypted;
            j["isHidden"] = m_vaultInfo.isHidden;
            j["isProtected"] = m_vaultInfo.isProtected;
            j["totalSize"] = m_vaultInfo.totalSize;
            j["usedSize"] = m_vaultInfo.usedSize;
            j["status"] = static_cast<int>(m_vaultInfo.status);
            j["backupCount"] = m_vaultInfo.backupCount;

            // Store crypto material for encrypted vaults
            if (m_vaultInfo.isEncrypted && !m_vaultSalt.empty()) {
                // Encode salt and verify tag as hex
                std::ostringstream saltHex;
                saltHex << std::hex << std::setfill('0');
                for (uint8_t b : m_vaultSalt) saltHex << std::setw(2) << static_cast<int>(b);
                j["salt"] = saltHex.str();

                std::ostringstream tagHex;
                tagHex << std::hex << std::setfill('0');
                for (uint8_t b : m_vaultVerifyTag) tagHex << std::setw(2) << static_cast<int>(b);
                j["verifyTag"] = tagHex.str();
            }

            fs::path metaPath = m_vaultInfo.path / "vault.json";
            Utils::JSON::Error jsonErr;
            if (!Utils::JSON::SaveToFile(metaPath, j, &jsonErr)) {
                SS_LOG_ERROR(L"BackupManager", L"Failed to write vault.json: %hs",
                             jsonErr.message.c_str());
                return false;
            }
            return true;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"BackupManager", L"Exception saving vault metadata: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool LoadVaultMetadata() {
        try {
            fs::path metaPath = m_config.defaultVault.vaultPath / "vault.json";
            std::error_code ec;
            if (!fs::exists(metaPath, ec) || ec) return false;

            Utils::JSON::Json j;
            Utils::JSON::Error jsonErr;
            if (!Utils::JSON::LoadFromFile(metaPath, j, &jsonErr)) {
                SS_LOG_ERROR(L"BackupManager", L"Failed to parse vault.json: %hs",
                             jsonErr.message.c_str());
                return false;
            }

            m_vaultInfo.vaultId = j.value("vaultId", "");
            m_vaultInfo.path = j.value("path", "");
            auto timeVal = j.value("creationTime", 0LL);
            m_vaultInfo.creationTime = std::chrono::system_clock::time_point(
                std::chrono::seconds(timeVal));
            m_vaultInfo.isEncrypted = j.value("isEncrypted", false);
            m_vaultInfo.isHidden = j.value("isHidden", false);
            m_vaultInfo.isProtected = j.value("isProtected", false);
            m_vaultInfo.totalSize = j.value("totalSize", 0ULL);
            m_vaultInfo.usedSize = j.value("usedSize", 0ULL);
            m_vaultInfo.status = static_cast<VaultStatus>(
                j.value("status", static_cast<int>(VaultStatus::Ready)));
            m_vaultInfo.backupCount = j.value("backupCount", 0U);

            // Load crypto material
            if (m_vaultInfo.isEncrypted) {
                std::string saltHex = j.value("salt", "");
                std::string tagHex = j.value("verifyTag", "");

                if (saltHex.empty() || tagHex.empty()) {
                    SS_LOG_ERROR(L"BackupManager", L"Encrypted vault missing salt/verifyTag");
                    return false;
                }

                // Hex decode salt
                m_vaultSalt.clear();
                m_vaultSalt.reserve(saltHex.size() / 2);
                for (size_t i = 0; i + 1 < saltHex.size(); i += 2) {
                    auto byte = static_cast<uint8_t>(
                        std::stoul(saltHex.substr(i, 2), nullptr, 16));
                    m_vaultSalt.push_back(byte);
                }

                // Hex decode verify tag
                m_vaultVerifyTag.clear();
                m_vaultVerifyTag.reserve(tagHex.size() / 2);
                for (size_t i = 0; i + 1 < tagHex.size(); i += 2) {
                    auto byte = static_cast<uint8_t>(
                        std::stoul(tagHex.substr(i, 2), nullptr, 16));
                    m_vaultVerifyTag.push_back(byte);
                }
            }

            return true;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"BackupManager", L"Exception loading vault metadata: %hs", e.what());
            return false;
        }
    }

    void SaveBackupsIndex() {
        try {
            Utils::JSON::Json jArray = Utils::JSON::Json::array();
            for (const auto& bp : m_backups) {
                Utils::JSON::Json jBp;
                jBp["backupId"] = bp.backupId;
                jBp["parentBackupId"] = bp.parentBackupId;
                jBp["type"] = static_cast<int>(bp.type);
                jBp["status"] = static_cast<int>(bp.status);
                jBp["startTime"] = std::chrono::duration_cast<std::chrono::seconds>(
                    bp.startTime.time_since_epoch()).count();
                jBp["endTime"] = std::chrono::duration_cast<std::chrono::seconds>(
                    bp.endTime.time_since_epoch()).count();
                jBp["totalFiles"] = bp.totalFiles;
                jBp["totalSize"] = bp.totalSize;
                jBp["backedUpSize"] = bp.backedUpSize;
                jBp["filesBackedUp"] = bp.filesBackedUp;
                jBp["filesSkipped"] = bp.filesSkipped;
                jBp["filesFailed"] = bp.filesFailed;
                jBp["isEncrypted"] = bp.isEncrypted;
                jBp["isVerified"] = bp.isVerified;
                jBp["label"] = bp.label;
                jBp["notes"] = bp.notes;
                jArray.push_back(jBp);
            }

            fs::path indexPath = m_vaultInfo.path / "index.json";
            Utils::JSON::Error jsonErr;
            if (!Utils::JSON::SaveToFile(indexPath, jArray, &jsonErr)) {
                SS_LOG_ERROR(L"BackupManager", L"Failed to write index.json: %hs",
                             jsonErr.message.c_str());
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"BackupManager", L"Exception saving backups index: %hs", e.what());
        }
    }

    void LoadBackupsIndex() {
        try {
            fs::path indexPath = m_config.defaultVault.vaultPath / "index.json";
            std::error_code ec;
            if (!fs::exists(indexPath, ec) || ec) return;

            Utils::JSON::Json jArray;
            Utils::JSON::Error jsonErr;
            if (!Utils::JSON::LoadFromFile(indexPath, jArray, &jsonErr) || !jArray.is_array()) {
                SS_LOG_ERROR(L"BackupManager", L"Failed to parse index.json: %hs",
                             jsonErr.message.c_str());
                return;
            }

            m_backups.clear();
            m_backups.reserve(std::min(jArray.size(), BackupConstants::MAX_BACKUP_POINTS));

            for (const auto& jBp : jArray) {
                if (m_backups.size() >= BackupConstants::MAX_BACKUP_POINTS) break;

                BackupPoint bp;
                bp.backupId = jBp.value("backupId", "");
                if (bp.backupId.empty()) continue; // Skip entries without ID

                bp.parentBackupId = jBp.value("parentBackupId", "");
                bp.type = static_cast<BackupType>(
                    jBp.value("type", static_cast<int>(BackupType::Full)));
                bp.status = static_cast<BackupStatus>(
                    jBp.value("status", static_cast<int>(BackupStatus::Completed)));

                auto startVal = jBp.value("startTime", 0LL);
                bp.startTime = std::chrono::system_clock::time_point(
                    std::chrono::seconds(startVal));
                auto endVal = jBp.value("endTime", 0LL);
                bp.endTime = std::chrono::system_clock::time_point(
                    std::chrono::seconds(endVal));

                bp.totalFiles = jBp.value("totalFiles", 0ULL);
                bp.totalSize = jBp.value("totalSize", 0ULL);
                bp.backedUpSize = jBp.value("backedUpSize", 0ULL);
                bp.filesBackedUp = jBp.value("filesBackedUp", 0ULL);
                bp.filesSkipped = jBp.value("filesSkipped", 0ULL);
                bp.filesFailed = jBp.value("filesFailed", 0ULL);
                bp.isEncrypted = jBp.value("isEncrypted", false);
                bp.isVerified = jBp.value("isVerified", false);
                bp.label = jBp.value("label", "");
                bp.notes = jBp.value("notes", "");

                if (startVal != 0 && endVal != 0) {
                    bp.duration = std::chrono::duration_cast<std::chrono::seconds>(
                        bp.endTime - bp.startTime);
                }

                m_backups.push_back(std::move(bp));
            }

            SS_LOG_INFO(L"BackupManager", L"Loaded %zu backup points from index",
                        m_backups.size());
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"BackupManager", L"Exception loading backups index: %hs", e.what());
        }
    }

    // ========================================================================
    // NOTIFICATIONS
    // ========================================================================

    void NotifyProgress(const BackupProgress& progress) {
        // Copy callbacks to invoke outside the lock
        std::vector<ProgressCallback> cbs;
        {
            std::shared_lock lock(m_callbackMutex);
            cbs = m_progressCallbacks;
        }
        for (const auto& cb : cbs) {
            try { cb(progress); }
            catch (const std::exception& e) {
                SS_LOG_WARN(L"BackupManager", L"Progress callback threw: %hs", e.what());
            }
        }
    }

    void NotifyCompletion(const BackupPoint& bp) {
        std::vector<CompletionCallback> cbs;
        {
            std::shared_lock lock(m_callbackMutex);
            cbs = m_completionCallbacks;
        }
        for (const auto& cb : cbs) {
            try { cb(bp); }
            catch (const std::exception& e) {
                SS_LOG_WARN(L"BackupManager", L"Completion callback threw: %hs", e.what());
            }
        }
    }

    void NotifyError(const std::string& msg, int code) {
        SS_LOG_ERROR(L"BackupManager", L"Error [%d]: %hs", code, msg.c_str());
        std::vector<ErrorCallback> cbs;
        {
            std::shared_lock lock(m_callbackMutex);
            cbs = m_errorCallbacks;
        }
        for (const auto& cb : cbs) {
            try { cb(msg, code); }
            catch (const std::exception& e) {
                SS_LOG_WARN(L"BackupManager", L"Error callback threw: %hs", e.what());
            }
        }
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    bool UpdateConfiguration(const BackupConfiguration& config) {
        if (!config.IsValid()) {
            SS_LOG_ERROR(L"BackupManager", L"Invalid configuration");
            return false;
        }
        std::unique_lock lock(m_mutex);
        m_config = config;
        m_retentionDays = 30; // Reset to default; jobs carry their own retention
        SS_LOG_INFO(L"BackupManager", L"Configuration updated");
        return true;
    }

    // ========================================================================
    // SELF-TEST
    // ========================================================================

    bool SelfTest() {
        SS_LOG_INFO(L"BackupManager", L"Running self-test...");

        // Test 1: UUID generation
        std::string testId = GenerateId();
        if (testId.empty()) {
            SS_LOG_ERROR(L"BackupManager", L"Self-test FAILED: UUID generation");
            return false;
        }

        // Test 2: Vault metadata path construction
        if (m_config.defaultVault.vaultPath.empty()) {
            SS_LOG_WARN(L"BackupManager", L"Self-test: No vault path configured (non-fatal)");
        }

        // Test 3: Crypto subsystem (if encryption enabled)
        if (m_vaultInfo.isEncrypted) {
            Utils::CryptoUtils::SecureRandom rng;
            auto testBytes = rng.Generate(32);
            if (testBytes.empty()) {
                SS_LOG_ERROR(L"BackupManager", L"Self-test FAILED: Secure random generation");
                return false;
            }
        }

        SS_LOG_INFO(L"BackupManager", L"Self-test PASSED");
        return true;
    }

};

// ============================================================================
// BACKUP MANAGER PUBLIC API
// ============================================================================

BackupManager& BackupManager::Instance() noexcept {
    static BackupManager instance;
    return instance;
}

bool BackupManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

BackupManager::BackupManager() : m_impl(std::make_unique<BackupManagerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

BackupManager::~BackupManager() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    s_instanceCreated.store(false, std::memory_order_release);
}

bool BackupManager::Initialize(const std::wstring& vaultPath) {
    BackupConfiguration config;
    config.defaultVault.vaultPath = vaultPath;
    return Initialize(config);
}

bool BackupManager::Initialize(const BackupConfiguration& config) {
    return m_impl->Initialize(config);
}

void BackupManager::Shutdown() {
    m_impl->Shutdown();
}

bool BackupManager::IsInitialized() const noexcept {
    return m_impl->m_status == ModuleStatus::Running;
}

ModuleStatus BackupManager::GetStatus() const noexcept {
    return m_impl->m_status;
}

bool BackupManager::UpdateConfiguration(const BackupConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

BackupConfiguration BackupManager::GetConfiguration() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// VAULT MANAGEMENT
// ============================================================================

bool BackupManager::CreateVault(const VaultConfiguration& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(L"BackupManager", L"Invalid vault configuration");
        return false;
    }
    return m_impl->CreateVault(config);
}

bool BackupManager::OpenVault(const fs::path& vaultPath, const std::string& password) {
    return m_impl->OpenVault(vaultPath, password);
}

void BackupManager::CloseVault() {
    m_impl->CloseVault();
}

bool BackupManager::LockVault() {
    return m_impl->LockVault();
}

bool BackupManager::UnlockVault(const std::string& password) {
    return m_impl->UnlockVault(password);
}

bool BackupManager::ChangeVaultPassword(const std::string& oldPassword,
                                         const std::string& newPassword) {
    return m_impl->ChangeVaultPassword(oldPassword, newPassword);
}

VaultInfo BackupManager::GetVaultInfo() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_vaultInfo;
}

bool BackupManager::IsVaultOpen() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_vaultInfo.status == VaultStatus::Ready ||
           m_impl->m_vaultInfo.status == VaultStatus::Unlocked;
}

bool BackupManager::IsVaultLocked() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_vaultInfo.status == VaultStatus::Locked;
}

// ============================================================================
// BACKUP OPERATIONS
// ============================================================================

bool BackupManager::CreateBackup(const std::wstring& sourcePath) {
    BackupSource source;
    source.path = sourcePath;
    std::error_code ec;
    source.isDirectory = fs::is_directory(sourcePath, ec);
    return !CreateBackup({source}, BackupType::Full, "Quick Backup").empty();
}

std::string BackupManager::CreateBackup(const std::vector<BackupSource>& sources,
                                         BackupType type,
                                         const std::string& label) {
    return m_impl->CreateBackup(sources, type, label);
}

bool BackupManager::CancelBackup(const std::string& backupId) {
    return m_impl->CancelBackup(backupId);
}

bool BackupManager::PauseBackup(const std::string& backupId) {
    return m_impl->PauseBackup(backupId);
}

bool BackupManager::ResumeBackup(const std::string& backupId) {
    return m_impl->ResumeBackup(backupId);
}

bool BackupManager::VerifyBackup(const std::string& backupId) {
    return m_impl->VerifyBackup(backupId);
}

bool BackupManager::DeleteBackup(const std::string& backupId) {
    return m_impl->DeleteBackup(backupId);
}

// ============================================================================
// BACKUP POINTS
// ============================================================================

std::vector<std::wstring> BackupManager::GetBackupPoints() {
    std::shared_lock lock(m_impl->m_mutex);
    std::vector<std::wstring> ids;
    ids.reserve(m_impl->m_backups.size());
    for (const auto& bp : m_impl->m_backups) {
        ids.push_back(std::wstring(bp.backupId.begin(), bp.backupId.end()));
    }
    return ids;
}

std::vector<BackupPoint> BackupManager::GetBackupPointsDetailed() {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_backups;
}

std::optional<BackupPoint> BackupManager::GetBackupPoint(const std::string& backupId) {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = std::find_if(m_impl->m_backups.begin(), m_impl->m_backups.end(),
        [&](const BackupPoint& bp) { return bp.backupId == backupId; });
    if (it != m_impl->m_backups.end()) {
        return *it;
    }
    return std::nullopt;
}

std::optional<BackupPoint> BackupManager::GetLatestBackupPoint() {
    std::shared_lock lock(m_impl->m_mutex);
    if (m_impl->m_backups.empty()) return std::nullopt;

    auto it = std::max_element(m_impl->m_backups.begin(), m_impl->m_backups.end(),
        [](const BackupPoint& a, const BackupPoint& b) {
            return a.startTime < b.startTime;
        });
    return *it;
}

std::optional<BackupProgress> BackupManager::GetBackupProgress(const std::string& backupId) {
    std::shared_lock lock(m_impl->m_progressMutex);
    auto it = m_impl->m_activeBackups.find(backupId);
    if (it != m_impl->m_activeBackups.end()) {
        return it->second;
    }
    return std::nullopt;
}

// ============================================================================
// JOB MANAGEMENT
// ============================================================================

bool BackupManager::CreateJob(const BackupJob& job) {
    return m_impl->CreateJob(job);
}

bool BackupManager::UpdateJob(const BackupJob& job) {
    return m_impl->UpdateJob(job);
}

bool BackupManager::DeleteJob(const std::string& jobId) {
    return m_impl->DeleteJob(jobId);
}

std::vector<BackupJob> BackupManager::GetJobs() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_jobs;
}

std::string BackupManager::RunJob(const std::string& jobId) {
    return m_impl->RunJob(jobId);
}

// ============================================================================
// VSS INTEGRATION
// ============================================================================

bool BackupManager::CreateVSSSnapshot(const std::wstring& volumePath) {
    if (volumePath.empty()) {
        SS_LOG_ERROR(L"BackupManager", L"VSS: Volume path cannot be empty");
        return false;
    }
    // VSS snapshot creation requires COM initialization and IVssBackupComponents.
    // This should delegate to the VolumeSnapshotService module when fully integrated.
    SS_LOG_WARN(L"BackupManager", L"VSS snapshot creation requires VolumeSnapshotService integration");
    m_impl->m_stats.vssSnapshotsCreated++;
    return false;
}

bool BackupManager::DeleteVSSSnapshot(const std::string& snapshotId) {
    if (snapshotId.empty()) {
        SS_LOG_ERROR(L"BackupManager", L"VSS: Snapshot ID cannot be empty");
        return false;
    }
    SS_LOG_WARN(L"BackupManager", L"VSS snapshot deletion requires VolumeSnapshotService integration");
    return false;
}

std::vector<std::string> BackupManager::GetVSSSnapshots(const std::wstring& volumePath) {
    if (volumePath.empty()) return {};
    SS_LOG_WARN(L"BackupManager", L"VSS enumeration requires VolumeSnapshotService integration");
    return {};
}

// ============================================================================
// RETENTION
// ============================================================================

uint32_t BackupManager::ApplyRetentionPolicy() {
    return m_impl->ApplyRetentionPolicy();
}

void BackupManager::SetRetentionDays(uint32_t days) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_retentionDays = (days > 0) ? days : 1; // Minimum 1 day
    SS_LOG_INFO(L"BackupManager", L"Retention days set to %u", m_impl->m_retentionDays);
}

uint32_t BackupManager::GetRetentionDays() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_retentionDays;
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

void BackupManager::RegisterProgressCallback(ProgressCallback callback) {
    if (!callback) return;
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_progressCallbacks.push_back(std::move(callback));
}

void BackupManager::RegisterCompletionCallback(CompletionCallback callback) {
    if (!callback) return;
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_completionCallbacks.push_back(std::move(callback));
}

void BackupManager::RegisterFileCallback(FileCallback callback) {
    if (!callback) return;
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_fileCallbacks.push_back(std::move(callback));
}

void BackupManager::RegisterErrorCallback(ErrorCallback callback) {
    if (!callback) return;
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallbacks.push_back(std::move(callback));
}

void BackupManager::UnregisterCallbacks() {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_progressCallbacks.clear();
    m_impl->m_completionCallbacks.clear();
    m_impl->m_fileCallbacks.clear();
    m_impl->m_errorCallbacks.clear();
}

// ============================================================================
// STATISTICS
// ============================================================================

BackupStatistics BackupManager::GetStatistics() const {
    BackupStatistics s;
    s.totalBackups = m_impl->m_stats.totalBackups.load(std::memory_order_relaxed);
    s.successfulBackups = m_impl->m_stats.successfulBackups.load(std::memory_order_relaxed);
    s.failedBackups = m_impl->m_stats.failedBackups.load(std::memory_order_relaxed);
    s.totalFilesBackedUp = m_impl->m_stats.totalFilesBackedUp.load(std::memory_order_relaxed);
    s.totalBytesBackedUp = m_impl->m_stats.totalBytesBackedUp.load(std::memory_order_relaxed);
    s.totalRestores = m_impl->m_stats.totalRestores.load(std::memory_order_relaxed);
    s.successfulRestores = m_impl->m_stats.successfulRestores.load(std::memory_order_relaxed);
    s.bytesSavedByDedup = m_impl->m_stats.bytesSavedByDedup.load(std::memory_order_relaxed);
    s.bytesSavedByCompression = m_impl->m_stats.bytesSavedByCompression.load(std::memory_order_relaxed);
    s.vssSnapshotsCreated = m_impl->m_stats.vssSnapshotsCreated.load(std::memory_order_relaxed);
    s.ransomwareBlockedAttempts = m_impl->m_stats.ransomwareBlockedAttempts.load(std::memory_order_relaxed);
    s.startTime = m_impl->m_stats.startTime;
    return s;
}

void BackupManager::ResetStatistics() {
    m_impl->m_stats.Reset();
}

bool BackupManager::SelfTest() {
    return m_impl->SelfTest();
}

std::string BackupManager::GetVersionString() noexcept {
    return std::to_string(BackupConstants::VERSION_MAJOR) + "." +
           std::to_string(BackupConstants::VERSION_MINOR) + "." +
           std::to_string(BackupConstants::VERSION_PATCH);
}

// ============================================================================
// JSON SERIALIZATION
// ============================================================================

std::string VaultInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"vaultId\":\"" << EscapeJson(vaultId) << "\","
        << "\"path\":\"" << EscapeJson(path.string()) << "\","
        << "\"status\":\"" << GetVaultStatusName(status) << "\","
        << "\"totalSize\":" << totalSize << ","
        << "\"usedSize\":" << usedSize << ","
        << "\"availableSize\":" << availableSize << ","
        << "\"backupCount\":" << backupCount << ","
        << "\"isEncrypted\":" << (isEncrypted ? "true" : "false") << ","
        << "\"isProtected\":" << (isProtected ? "true" : "false") << ","
        << "\"isHidden\":" << (isHidden ? "true" : "false")
        << "}";
    return oss.str();
}

std::string BackupPoint::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"backupId\":\"" << EscapeJson(backupId) << "\","
        << "\"parentBackupId\":\"" << EscapeJson(parentBackupId) << "\","
        << "\"type\":\"" << GetBackupTypeName(type) << "\","
        << "\"status\":\"" << GetBackupStatusName(status) << "\","
        << "\"totalFiles\":" << totalFiles << ","
        << "\"totalSize\":" << totalSize << ","
        << "\"backedUpSize\":" << backedUpSize << ","
        << "\"filesBackedUp\":" << filesBackedUp << ","
        << "\"filesSkipped\":" << filesSkipped << ","
        << "\"filesFailed\":" << filesFailed << ","
        << "\"compressionRatio\":" << std::fixed << std::setprecision(2) << compressionRatio << ","
        << "\"isEncrypted\":" << (isEncrypted ? "true" : "false") << ","
        << "\"isVerified\":" << (isVerified ? "true" : "false") << ","
        << "\"label\":\"" << EscapeJson(label) << "\","
        << "\"notes\":\"" << EscapeJson(notes) << "\","
        << "\"duration\":" << duration.count()
        << "}";
    return oss.str();
}

std::string BackupProgress::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"backupId\":\"" << EscapeJson(backupId) << "\","
        << "\"phase\":\"" << EscapeJson(phase) << "\","
        << "\"percentComplete\":" << percentComplete << ","
        << "\"filesProcessed\":" << filesProcessed << ","
        << "\"totalFiles\":" << totalFiles << ","
        << "\"bytesProcessed\":" << bytesProcessed << ","
        << "\"totalBytes\":" << totalBytes << ","
        << "\"transferRate\":" << transferRate << ","
        << "\"estimatedTimeRemaining\":" << estimatedTimeRemaining << ","
        << "\"currentFile\":\"" << EscapeJson(currentFile.string()) << "\","
        << "\"errorCount\":" << errors.size()
        << "}";
    return oss.str();
}

std::string BackupSource::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"path\":\"" << EscapeJson(path.string()) << "\","
        << "\"isDirectory\":" << (isDirectory ? "true" : "false") << ","
        << "\"recursive\":" << (recursive ? "true" : "false") << ","
        << "\"followSymlinks\":" << (followSymlinks ? "true" : "false") << ","
        << "\"useVSS\":" << (useVSS ? "true" : "false")
        << "}";
    return oss.str();
}

std::string BackupJob::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"jobId\":\"" << EscapeJson(jobId) << "\","
        << "\"name\":\"" << EscapeJson(name) << "\","
        << "\"type\":\"" << GetBackupTypeName(type) << "\","
        << "\"vaultId\":\"" << EscapeJson(vaultId) << "\","
        << "\"enabled\":" << (enabled ? "true" : "false") << ","
        << "\"retentionDays\":" << retentionDays << ","
        << "\"maxVersions\":" << maxVersions << ","
        << "\"sourceCount\":" << sources.size()
        << "}";
    return oss.str();
}

std::string BackupStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"totalBackups\":" << totalBackups.load(std::memory_order_relaxed) << ","
        << "\"successfulBackups\":" << successfulBackups.load(std::memory_order_relaxed) << ","
        << "\"failedBackups\":" << failedBackups.load(std::memory_order_relaxed) << ","
        << "\"totalBytesBackedUp\":" << totalBytesBackedUp.load(std::memory_order_relaxed) << ","
        << "\"totalFilesBackedUp\":" << totalFilesBackedUp.load(std::memory_order_relaxed) << ","
        << "\"totalRestores\":" << totalRestores.load(std::memory_order_relaxed) << ","
        << "\"bytesSavedByDedup\":" << bytesSavedByDedup.load(std::memory_order_relaxed) << ","
        << "\"bytesSavedByCompression\":" << bytesSavedByCompression.load(std::memory_order_relaxed) << ","
        << "\"vssSnapshotsCreated\":" << vssSnapshotsCreated.load(std::memory_order_relaxed) << ","
        << "\"ransomwareBlockedAttempts\":" << ransomwareBlockedAttempts.load(std::memory_order_relaxed)
        << "}";
    return oss.str();
}

void BackupStatistics::Reset() noexcept {
    totalBackups = 0;
    successfulBackups = 0;
    failedBackups = 0;
    totalBytesBackedUp = 0;
    totalFilesBackedUp = 0;
    totalRestores = 0;
    successfulRestores = 0;
    bytesSavedByDedup = 0;
    bytesSavedByCompression = 0;
    vssSnapshotsCreated = 0;
    ransomwareBlockedAttempts = 0;
    startTime = Clock::now();
}

// ============================================================================
// VALIDATION
// ============================================================================

bool VaultConfiguration::IsValid() const noexcept {
    if (vaultPath.empty()) return false;
    // Reject suspiciously short or root-only paths
    if (vaultPath.native().size() < 4) return false;
    // If encryption is enabled, key must be adequate (for CreateVault path)
    // Note: For password-based open/unlock, key may be empty at this point
    return true;
}

bool BackupConfiguration::IsValid() const noexcept {
    if (!defaultVault.IsValid()) return false;
    if (blockSize == 0 || blockSize > 64 * 1024 * 1024) return false; // Max 64MB block
    if (maxConcurrentOperations == 0 || maxConcurrentOperations > 32) return false;
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetBackupTypeName(BackupType type) noexcept {
    switch (type) {
        case BackupType::Full:        return "Full";
        case BackupType::Incremental: return "Incremental";
        case BackupType::Differential:return "Differential";
        case BackupType::Mirror:      return "Mirror";
        case BackupType::CDP:         return "CDP";
        case BackupType::Snapshot:    return "Snapshot";
        default:                      return "Unknown";
    }
}

std::string_view GetStorageTypeName(StorageType type) noexcept {
    switch (type) {
        case StorageType::LocalDisk:    return "LocalDisk";
        case StorageType::NetworkShare: return "NetworkShare";
        case StorageType::CloudS3:      return "CloudS3";
        case StorageType::CloudAzure:   return "CloudAzure";
        case StorageType::CloudGCS:     return "CloudGCS";
        case StorageType::USB:          return "USB";
        case StorageType::NAS:          return "NAS";
        default:                        return "Unknown";
    }
}

std::string_view GetBackupStatusName(BackupStatus status) noexcept {
    switch (status) {
        case BackupStatus::Pending:    return "Pending";
        case BackupStatus::InProgress: return "InProgress";
        case BackupStatus::Completed:  return "Completed";
        case BackupStatus::Failed:     return "Failed";
        case BackupStatus::Cancelled:  return "Cancelled";
        case BackupStatus::Partial:    return "Partial";
        case BackupStatus::Verifying:  return "Verifying";
        case BackupStatus::Verified:   return "Verified";
        default:                       return "Unknown";
    }
}

std::string_view GetVaultStatusName(VaultStatus status) noexcept {
    switch (status) {
        case VaultStatus::NotInitialized: return "NotInitialized";
        case VaultStatus::Initializing:   return "Initializing";
        case VaultStatus::Ready:          return "Ready";
        case VaultStatus::Locked:         return "Locked";
        case VaultStatus::Unlocked:       return "Unlocked";
        case VaultStatus::Corrupted:      return "Corrupted";
        case VaultStatus::Full:           return "Full";
        case VaultStatus::Error:          return "Error";
        default:                          return "Unknown";
    }
}

std::string_view GetCompressionLevelName(CompressionLevel level) noexcept {
    switch (level) {
        case CompressionLevel::None:    return "None";
        case CompressionLevel::Fast:    return "Fast";
        case CompressionLevel::Normal:  return "Normal";
        case CompressionLevel::Maximum: return "Maximum";
        default:                        return "Unknown";
    }
}

std::string_view GetEncryptionModeName(EncryptionMode mode) noexcept {
    switch (mode) {
        case EncryptionMode::None:     return "None";
        case EncryptionMode::AES128:   return "AES128";
        case EncryptionMode::AES256:   return "AES256";
        case EncryptionMode::ChaCha20: return "ChaCha20";
        default:                       return "Unknown";
    }
}

std::string GenerateBackupId() {
    return GenerateId();
}

uint64_t EstimateBackupSize(const std::vector<BackupSource>& sources) {
    uint64_t total = 0;
    for (const auto& source : sources) {
        std::error_code ec;
        if (!fs::exists(source.path, ec) || ec) continue;

        if (fs::is_directory(source.path, ec)) {
            if (source.recursive) {
                for (auto it = fs::recursive_directory_iterator(
                         source.path, fs::directory_options::skip_permission_denied, ec);
                     it != fs::recursive_directory_iterator() && !ec;
                     it.increment(ec))
                {
                    if (it->is_regular_file(ec) && !ec) {
                        auto fsize = it->file_size(ec);
                        if (!ec) total += fsize;
                        ec.clear();
                    }
                }
            } else {
                for (auto it = fs::directory_iterator(
                         source.path, fs::directory_options::skip_permission_denied, ec);
                     it != fs::directory_iterator() && !ec;
                     it.increment(ec))
                {
                    if (it->is_regular_file(ec) && !ec) {
                        auto fsize = it->file_size(ec);
                        if (!ec) total += fsize;
                        ec.clear();
                    }
                }
            }
        } else if (fs::is_regular_file(source.path, ec)) {
            auto fsize = fs::file_size(source.path, ec);
            if (!ec) total += fsize;
        }
    }
    return total;
}

std::string FormatBytes(uint64_t bytes) {
    constexpr uint64_t KB = 1024ULL;
    constexpr uint64_t MB = KB * 1024;
    constexpr uint64_t GB = MB * 1024;
    constexpr uint64_t TB = GB * 1024;

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    if (bytes >= TB) {
        oss << static_cast<double>(bytes) / static_cast<double>(TB) << " TB";
    } else if (bytes >= GB) {
        oss << static_cast<double>(bytes) / static_cast<double>(GB) << " GB";
    } else if (bytes >= MB) {
        oss << static_cast<double>(bytes) / static_cast<double>(MB) << " MB";
    } else if (bytes >= KB) {
        oss << static_cast<double>(bytes) / static_cast<double>(KB) << " KB";
    } else {
        oss << bytes << " B";
    }
    return oss.str();
}

}  // namespace Backup
}  // namespace ShadowStrike
