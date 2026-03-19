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
/**
 * @file QuarantineManager.cpp
 * @brief Enterprise implementation of threat isolation and remediation engine.
 *
 * The Jailer of ShadowStrike NGAV - safely isolates malicious files from
 * production systems with encryption, process termination, and full rollback.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "QuarantineManager.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/RegistryUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/ThreadPool.hpp"
#include "../../Database/QuarantineDB.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <random>

// ============================================================================
// WINDOWS SPECIFIC INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <RestartManager.h>
#  pragma comment(lib, "Rstrtmgr.lib")
#endif

namespace ShadowStrike {
namespace Core {
namespace Engine {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] constexpr const char* QuarantineStatusToString(QuarantineStatus status) noexcept {
    switch (status) {
        case QuarantineStatus::Success: return "Success";
        case QuarantineStatus::FileNotFound: return "FileNotFound";
        case QuarantineStatus::AccessDenied: return "AccessDenied";
        case QuarantineStatus::FileInUse: return "FileInUse";
        case QuarantineStatus::FileTooLarge: return "FileTooLarge";
        case QuarantineStatus::SystemFileProtected: return "SystemFileProtected";
        case QuarantineStatus::WhitelistMatch: return "WhitelistMatch";
        case QuarantineStatus::EncryptionFailed: return "EncryptionFailed";
        case QuarantineStatus::StorageFull: return "StorageFull";
        case QuarantineStatus::DatabaseError: return "DatabaseError";
        case QuarantineStatus::ProcessKillFailed: return "ProcessKillFailed";
        case QuarantineStatus::AlreadyQuarantined: return "AlreadyQuarantined";
        case QuarantineStatus::EntryNotFound: return "EntryNotFound";
        case QuarantineStatus::DecryptionFailed: return "DecryptionFailed";
        case QuarantineStatus::IntegrityFailed: return "IntegrityFailed";
        case QuarantineStatus::RebootRequired: return "RebootRequired";
        case QuarantineStatus::Cancelled: return "Cancelled";
        case QuarantineStatus::Timeout: return "Timeout";
        default: return "UnknownError";
    }
}

[[nodiscard]] constexpr const char* QuarantineStateToString(QuarantineState state) noexcept {
    switch (state) {
        case QuarantineState::Active: return "Active";
        case QuarantineState::Restored: return "Restored";
        case QuarantineState::Deleted: return "Deleted";
        case QuarantineState::Pending: return "Pending";
        case QuarantineState::Failed: return "Failed";
        case QuarantineState::Submitted: return "Submitted";
        case QuarantineState::PendingReboot: return "PendingReboot";
        default: return "Unknown";
    }
}

[[nodiscard]] bool IsValidQuarantinePath(const std::wstring& path) noexcept {
    if (path.empty() || path.length() > 32767) return false;

    try {
        fs::path p(path);
        return !p.empty();
    } catch (...) {
        return false;
    }
}

[[nodiscard]] uint64_t GetFileSizeSafe(const std::wstring& path) noexcept {
    try {
        std::error_code ec;
        auto size = fs::file_size(path, ec);
        return ec ? 0 : size;
    } catch (...) {
        return 0;
    }
}

[[nodiscard]] std::wstring GenerateQuarantineFileName(
    const std::string& hash,
    const std::wstring& originalExtension
) noexcept {
    try {
        auto hashW = StringUtils::ToWideString(hash.substr(0, 16));
        return hashW + QuarantineConstants::QUARANTINE_EXTENSION;
    } catch (...) {
        return L"unknown.ssqf";
    }
}

[[nodiscard]] bool CanTerminateProcess(uint32_t processId) noexcept {
    if (processId == 0 || processId == 4) return false; // System/Idle

    try {
        return !ProcessUtils::IsSystemProcess(processId);
    } catch (...) {
        return false;
    }
}

[[nodiscard]] std::wstring GetProcessImagePath(uint32_t processId) noexcept {
    try {
        return ProcessUtils::GetProcessImagePath(processId);
    } catch (...) {
        return L"";
    }
}

[[nodiscard]] bool IsFileLocked(const std::wstring& path) noexcept {
    try {
        std::error_code ec;
        if (!fs::exists(path, ec)) return false;

        // Try to open with exclusive access
        std::ofstream file(path, std::ios::binary | std::ios::app);
        return !file.is_open();
    } catch (...) {
        return true;
    }
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for QuarantineManager.
 */
class QuarantineManager::Impl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_entriesMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::mutex m_operationMutex;

    // Initialization state
    std::atomic<bool> m_initialized{false};

    // Configuration
    QuarantineManagerConfig m_config{};

    // Thread pool for async operations
    std::shared_ptr<ThreadPool> m_threadPool;

    // Database
    std::unique_ptr<Database::QuarantineDB> m_database;

    // Master encryption key (AES-256)
    std::array<uint8_t, QuarantineConstants::AES_KEY_SIZE> m_masterKey{};

    // Entry cache (LRU with size limit)
    std::unordered_map<uint64_t, QuarantineEntry> m_entryCache;
    static constexpr size_t MAX_CACHE_SIZE = 1000;

    // Callbacks
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::unordered_map<uint64_t, QuarantineCallback> m_quarantineCallbacks;
    std::unordered_map<uint64_t, RestoreCallback> m_restoreCallbacks;
    std::unordered_map<uint64_t, RemediationCallback> m_remediationCallbacks;

    // Statistics
    QuarantineManagerStats m_stats{};

    // Entry ID counter
    std::atomic<uint64_t> m_nextEntryId{1};

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    Impl() = default;
    ~Impl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(
        std::shared_ptr<ThreadPool> threadPool,
        const QuarantineManagerConfig& config
    ) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("QuarantineManager::Impl already initialized");
            return true;
        }

        try {
            Logger::Info("QuarantineManager::Impl: Initializing");

            // Store configuration
            m_config = config;
            m_threadPool = threadPool;

            // Create vault directory if needed
            if (!m_config.vaultPath.empty()) {
                std::error_code ec;
                if (!fs::exists(m_config.vaultPath, ec)) {
                    fs::create_directories(m_config.vaultPath, ec);
                    if (ec) {
                        Logger::Error("QuarantineManager: Failed to create vault: {}", ec.message());
                        return false;
                    }
                }

                Logger::Info("QuarantineManager: Vault path: {}",
                    StringUtils::ToNarrowString(m_config.vaultPath));
            }

            // Initialize database
            m_database = std::make_unique<Database::QuarantineDB>();
            auto dbPath = m_config.vaultPath / L"quarantine.db";

            if (!m_database->Initialize(dbPath)) {
                Logger::Error("QuarantineManager: Database initialization failed");
                return false;
            }

            Logger::Info("QuarantineManager: Database initialized");

            // Derive master encryption key
            if (m_config.encryptFiles) {
                DeriveEncryptionKey();
                Logger::Info("QuarantineManager: Encryption key derived");
            }

            // Load entry count
            m_stats.activeEntries.store(
                m_database->GetEntryCount(QuarantineState::Active),
                std::memory_order_relaxed
            );

            m_initialized.store(true, std::memory_order_release);
            Logger::Info("QuarantineManager::Impl: Initialization complete");

            return true;

        } catch (const std::exception& e) {
            Logger::Error("QuarantineManager::Impl: Initialization exception: {}", e.what());
            return false;
        }
    }

    void Shutdown() {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("QuarantineManager::Impl: Shutting down");

        // Shutdown database
        if (m_database) {
            m_database->Shutdown();
            m_database.reset();
        }

        // Clear cache
        {
            std::unique_lock entriesLock(m_entriesMutex);
            m_entryCache.clear();
        }

        // Clear callbacks
        {
            std::unique_lock cbLock(m_callbackMutex);
            m_quarantineCallbacks.clear();
            m_restoreCallbacks.clear();
            m_remediationCallbacks.clear();
        }

        // Zero encryption key
        m_masterKey.fill(0);

        m_initialized.store(false, std::memory_order_release);
        Logger::Info("QuarantineManager::Impl: Shutdown complete");
    }

    // ========================================================================
    // ENCRYPTION KEY MANAGEMENT
    // ========================================================================

    void DeriveEncryptionKey() {
        try {
            // Use machine-specific entropy
            auto machineGuid = SystemUtils::GetMachineGuid();
            auto userSid = SystemUtils::GetCurrentUserSid();

            std::string keyMaterial = machineGuid + userSid + "ShadowStrike-Quarantine-Key-v2";

            // Salt (fixed for reproducibility on same machine)
            std::vector<uint8_t> salt(32, 0x53); // 'S' repeated

            // PBKDF2 with 100,000 iterations
            CryptoUtils::DeriveKey(
                reinterpret_cast<const uint8_t*>(keyMaterial.data()),
                keyMaterial.size(),
                salt.data(),
                salt.size(),
                100000, // iterations
                m_masterKey.data(),
                m_masterKey.size()
            );

            Logger::Debug("QuarantineManager: Master key derived (PBKDF2, 100k iterations)");

        } catch (const std::exception& e) {
            Logger::Error("QuarantineManager: Key derivation failed: {}", e.what());
            throw;
        }
    }

    // ========================================================================
    // METADATA COLLECTION
    // ========================================================================

    [[nodiscard]] FileMetadata CollectMetadata(const std::wstring& filePath) {
        FileMetadata metadata{};

        try {
            metadata.originalPath = filePath;

            fs::path p(filePath);
            metadata.fileName = p.filename().wstring();
            metadata.extension = p.extension().wstring();

            std::error_code ec;
            metadata.fileSize = fs::file_size(filePath, ec);

            // File times
            auto ftime = fs::last_write_time(filePath, ec);
            if (!ec) {
                auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
                );
                metadata.modificationTime = sctp;
            }

            // Windows-specific attributes
#ifdef _WIN32
            DWORD attrs = GetFileAttributesW(filePath.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES) {
                metadata.attributes = attrs;
                metadata.isReadOnly = (attrs & FILE_ATTRIBUTE_READONLY) != 0;
                metadata.isHidden = (attrs & FILE_ATTRIBUTE_HIDDEN) != 0;
                metadata.isSystem = (attrs & FILE_ATTRIBUTE_SYSTEM) != 0;
            }

            // Check if executable
            auto ext = StringUtils::ToLower(metadata.extension);
            metadata.isExecutable = (ext == L".exe" || ext == L".dll" ||
                                    ext == L".sys" || ext == L".scr");
#endif

            // Owner information
            metadata.ownerSid = SystemUtils::GetFileOwnerSid(filePath);

            Logger::Debug("QuarantineManager: Metadata collected for {}",
                StringUtils::ToNarrowString(metadata.fileName));

        } catch (const std::exception& e) {
            Logger::Error("QuarantineManager: Metadata collection failed: {}", e.what());
        }

        return metadata;
    }

    // ========================================================================
    // HASH CALCULATION
    // ========================================================================

    [[nodiscard]] QuarantineHashes CalculateHashes(const std::wstring& filePath) {
        QuarantineHashes hashes{};

        try {
            std::vector<uint8_t> hashBytes;
            HashUtils::Error hashErr;

            // SHA-256
            if (HashUtils::ComputeFile(HashUtils::Algorithm::SHA256,
                                      filePath, hashBytes, &hashErr)) {
                hashes.sha256 = HashUtils::ToHexLower(hashBytes);
            }

            // MD5
            if (HashUtils::ComputeFile(HashUtils::Algorithm::MD5,
                                      filePath, hashBytes, &hashErr)) {
                hashes.md5 = HashUtils::ToHexLower(hashBytes);
            }

            // SHA-1
            if (HashUtils::ComputeFile(HashUtils::Algorithm::SHA1,
                                      filePath, hashBytes, &hashErr)) {
                hashes.sha1 = HashUtils::ToHexLower(hashBytes);
            }

            Logger::Debug("QuarantineManager: Hashes calculated - SHA256: {}",
                hashes.sha256.substr(0, 16));

        } catch (const std::exception& e) {
            Logger::Error("QuarantineManager: Hash calculation failed: {}", e.what());
        }

        return hashes;
    }

    // ========================================================================
    // ENCRYPTION / DECRYPTION
    // ========================================================================

    [[nodiscard]] std::vector<uint8_t> EncryptContent(
        std::span<const uint8_t> data,
        std::array<uint8_t, QuarantineConstants::GCM_IV_SIZE>& iv
    ) {
        try {
            // Generate random IV
            std::random_device rd;
            std::mt19937_64 gen(rd());
            std::uniform_int_distribution<uint8_t> dist(0, 255);

            for (auto& byte : iv) {
                byte = dist(gen);
            }

            // Encrypt with AES-256-GCM
            std::vector<uint8_t> encrypted;
            std::vector<uint8_t> tag(QuarantineConstants::GCM_TAG_SIZE);

            bool success = CryptoUtils::EncryptAES256GCM(
                data.data(), data.size(),
                m_masterKey.data(), m_masterKey.size(),
                iv.data(), iv.size(),
                encrypted,
                tag
            );

            if (!success) {
                throw std::runtime_error("AES-256-GCM encryption failed");
            }

            // Append authentication tag
            encrypted.insert(encrypted.end(), tag.begin(), tag.end());

            Logger::Debug("QuarantineManager: Content encrypted ({} bytes -> {} bytes)",
                data.size(), encrypted.size());

            return encrypted;

        } catch (const std::exception& e) {
            Logger::Error("QuarantineManager: Encryption failed: {}", e.what());
            throw;
        }
    }

    [[nodiscard]] std::vector<uint8_t> DecryptContent(
        std::span<const uint8_t> data,
        const std::array<uint8_t, QuarantineConstants::GCM_IV_SIZE>& iv
    ) {
        try {
            if (data.size() < QuarantineConstants::GCM_TAG_SIZE) {
                throw std::runtime_error("Invalid encrypted data size");
            }

            // Extract authentication tag
            size_t ciphertextSize = data.size() - QuarantineConstants::GCM_TAG_SIZE;
            std::vector<uint8_t> tag(
                data.begin() + ciphertextSize,
                data.end()
            );

            // Decrypt with AES-256-GCM
            std::vector<uint8_t> decrypted;

            bool success = CryptoUtils::DecryptAES256GCM(
                data.data(), ciphertextSize,
                m_masterKey.data(), m_masterKey.size(),
                iv.data(), iv.size(),
                tag.data(), tag.size(),
                decrypted
            );

            if (!success) {
                throw std::runtime_error("AES-256-GCM decryption failed (authentication tag mismatch)");
            }

            Logger::Debug("QuarantineManager: Content decrypted ({} bytes -> {} bytes)",
                data.size(), decrypted.size());

            return decrypted;

        } catch (const std::exception& e) {
            Logger::Error("QuarantineManager: Decryption failed: {}", e.what());
            throw;
        }
    }

    // ========================================================================
    // PROCESS MANAGEMENT
    // ========================================================================

    [[nodiscard]] std::vector<LockingProcess> GetLockingProcessesImpl(
        const std::wstring& filePath
    ) const {
        std::vector<LockingProcess> processes;

#ifdef _WIN32
        try {
            DWORD dwSession;
            WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1] = {0};

            DWORD dwError = RmStartSession(&dwSession, 0, szSessionKey);
            if (dwError != ERROR_SUCCESS) {
                Logger::Warn("QuarantineManager: RmStartSession failed: {}", dwError);
                return processes;
            }

            // Register resource
            LPCWSTR pszFile = filePath.c_str();
            dwError = RmRegisterResources(dwSession, 1, &pszFile, 0, nullptr, 0, nullptr);

            if (dwError == ERROR_SUCCESS) {
                UINT nProcInfoNeeded = 0;
                UINT nProcInfo = 10;
                DWORD dwReason = 0;
                RM_PROCESS_INFO rgpi[10];

                dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo,
                                   rgpi, &dwReason);

                if (dwError == ERROR_SUCCESS || dwError == ERROR_MORE_DATA) {
                    for (UINT i = 0; i < nProcInfo; i++) {
                        LockingProcess proc{};
                        proc.processId = rgpi[i].Process.dwProcessId;
                        proc.processName = rgpi[i].strAppName;
                        proc.processPath = GetProcessImagePath(proc.processId);
                        proc.isSystemProcess = ProcessUtils::IsSystemProcess(proc.processId);
                        proc.canTerminate = CanTerminateProcess(proc.processId);

                        processes.push_back(proc);
                    }

                    Logger::Info("QuarantineManager: Found {} locking processes",
                        processes.size());
                }
            }

            RmEndSession(dwSession);

        } catch (const std::exception& e) {
            Logger::Error("QuarantineManager: GetLockingProcesses failed: {}", e.what());
        }
#endif

        return processes;
    }

    [[nodiscard]] std::vector<LockingProcess> TerminateLockingProcessesImpl(
        const std::wstring& filePath
    ) {
        std::vector<LockingProcess> terminated;

        try {
            auto processes = GetLockingProcessesImpl(filePath);

            for (auto& proc : processes) {
                if (!proc.canTerminate) {
                    Logger::Warn("QuarantineManager: Cannot terminate system process: {} (PID {})",
                        StringUtils::ToNarrowString(proc.processName), proc.processId);
                    continue;
                }

                if (!m_config.autoTerminateProcesses) {
                    Logger::Info("QuarantineManager: Auto-terminate disabled, skipping PID {}",
                        proc.processId);
                    continue;
                }

                // Attempt graceful termination
                bool success = ProcessUtils::TerminateProcess(
                    proc.processId,
                    m_config.processKillTimeoutMs
                );

                if (success) {
                    proc.wasTerminated = true;
                    terminated.push_back(proc);
                    m_stats.processesTerminated.fetch_add(1, std::memory_order_relaxed);

                    Logger::Info("QuarantineManager: Terminated process: {} (PID {})",
                        StringUtils::ToNarrowString(proc.processName), proc.processId);
                } else {
                    Logger::Warn("QuarantineManager: Failed to terminate process: {} (PID {})",
                        StringUtils::ToNarrowString(proc.processName), proc.processId);
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("QuarantineManager: TerminateLockingProcesses failed: {}", e.what());
        }

        return terminated;
    }

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    void UpdateCache(const QuarantineEntry& entry) {
        std::unique_lock lock(m_entriesMutex);

        // LRU eviction if cache is full
        if (m_entryCache.size() >= MAX_CACHE_SIZE) {
            // Remove oldest entry (simple eviction - can be improved with LRU list)
            auto it = m_entryCache.begin();
            m_entryCache.erase(it);
        }

        m_entryCache[entry.entryId] = entry;
    }

    [[nodiscard]] std::optional<QuarantineEntry> GetFromCache(uint64_t entryId) const {
        std::shared_lock lock(m_entriesMutex);

        auto it = m_entryCache.find(entryId);
        if (it != m_entryCache.end()) {
            return it->second;
        }

        return std::nullopt;
    }

    void RemoveFromCache(uint64_t entryId) {
        std::unique_lock lock(m_entriesMutex);
        m_entryCache.erase(entryId);
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeQuarantineCallbacks(const QuarantineResult& result) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_quarantineCallbacks) {
            try {
                callback(result);
            } catch (const std::exception& e) {
                Logger::Error("QuarantineManager: Quarantine callback exception: {}", e.what());
            }
        }
    }

    void InvokeRestoreCallbacks(const RestoreResult& result) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_restoreCallbacks) {
            try {
                callback(result);
            } catch (const std::exception& e) {
                Logger::Error("QuarantineManager: Restore callback exception: {}", e.what());
            }
        }
    }

    void InvokeRemediationCallbacks(const RemediationAction& action) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_remediationCallbacks) {
            try {
                callback(action);
            } catch (const std::exception& e) {
                Logger::Error("QuarantineManager: Remediation callback exception: {}", e.what());
            }
        }
    }

    // ========================================================================
    // VALIDATION
    // ========================================================================

    [[nodiscard]] bool IsSystemCriticalFile(const std::wstring& filePath) const {
        try {
            auto pathLower = StringUtils::ToLower(filePath);

            // Check for Windows system directories
            static const std::vector<std::wstring> criticalPaths = {
                L"\\windows\\system32\\",
                L"\\windows\\syswow64\\",
                L"\\windows\\winsxs\\",
                L"\\program files\\windows defender\\",
            };

            for (const auto& critical : criticalPaths) {
                if (pathLower.find(critical) != std::wstring::npos) {
                    return true;
                }
            }

            // Check for critical system files
            fs::path p(filePath);
            auto filename = StringUtils::ToLower(p.filename().wstring());

            static const std::vector<std::wstring> criticalFiles = {
                L"ntoskrnl.exe", L"hal.dll", L"ntdll.dll",
                L"kernel32.dll", L"advapi32.dll", L"explorer.exe"
            };

            return std::find(criticalFiles.begin(), criticalFiles.end(), filename)
                != criticalFiles.end();

        } catch (...) {
            return false;
        }
    }

    [[nodiscard]] std::wstring GenerateQuarantinePath(const std::wstring& originalPath) {
        try {
            // Generate unique filename based on hash + timestamp
            auto timestamp = system_clock::now().time_since_epoch().count();
            auto filename = std::format(L"Q{:016X}.ssqf", timestamp);

            return m_config.vaultPath / filename;

        } catch (const std::exception& e) {
            Logger::Error("QuarantineManager: GenerateQuarantinePath failed: {}", e.what());
            return m_config.vaultPath / L"unknown.ssqf";
        }
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

QuarantineManager& QuarantineManager::Instance() {
    static QuarantineManager instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

QuarantineManager::QuarantineManager()
    : m_impl(std::make_unique<Impl>())
{
    Logger::Info("QuarantineManager: Constructor called");
}

QuarantineManager::~QuarantineManager() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("QuarantineManager: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool QuarantineManager::Initialize() {
    auto config = QuarantineManagerConfig::CreateDefault();
    config.vaultPath = L"C:\\ProgramData\\ShadowStrike\\Quarantine";

    return Initialize(nullptr, config);
}

bool QuarantineManager::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool) {
    auto config = QuarantineManagerConfig::CreateDefault();
    config.vaultPath = L"C:\\ProgramData\\ShadowStrike\\Quarantine";

    return Initialize(threadPool, config);
}

bool QuarantineManager::Initialize(
    std::shared_ptr<Utils::ThreadPool> threadPool,
    const QuarantineManagerConfig& config
) {
    if (!m_impl) {
        Logger::Critical("QuarantineManager: Implementation is null");
        return false;
    }

    return m_impl->Initialize(threadPool, config);
}

void QuarantineManager::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool QuarantineManager::IsInitialized() const noexcept {
    return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
}

void QuarantineManager::UpdateConfig(const QuarantineManagerConfig& config) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = config;

    Logger::Info("QuarantineManager: Configuration updated");
}

QuarantineManagerConfig QuarantineManager::GetConfig() const {
    if (!m_impl) return QuarantineManagerConfig{};

    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}

// ============================================================================
// QUARANTINE OPERATIONS
// ============================================================================

QuarantineResult QuarantineManager::QuarantineFile(const QuarantineRequest& request) {
    QuarantineResult result{};
    const auto opStart = steady_clock::now();

    if (!IsInitialized()) {
        Logger::Error("QuarantineManager: Not initialized");
        result.status = QuarantineStatus::DatabaseError;
        result.message = L"Manager not initialized";
        return result;
    }

    try {
        // Lock for quarantine operation
        std::lock_guard opLock(m_impl->m_operationMutex);

        Logger::Info("QuarantineManager: Quarantine request for: {}",
            StringUtils::ToNarrowString(request.filePath));

        result.originalPath = request.filePath;

        // ====================================================================
        // STAGE 1: VALIDATION
        // ====================================================================

        // Validate path
        if (!IsValidQuarantinePath(request.filePath)) {
            Logger::Error("QuarantineManager: Invalid file path");
            result.status = QuarantineStatus::FileNotFound;
            result.message = L"Invalid file path";
            return result;
        }

        // Check file existence
        std::error_code ec;
        if (!fs::exists(request.filePath, ec)) {
            Logger::Error("QuarantineManager: File not found");
            result.status = QuarantineStatus::FileNotFound;
            result.message = L"File not found";
            return result;
        }

        // Check file size
        uint64_t fileSize = GetFileSizeSafe(request.filePath);
        if (fileSize > m_impl->m_config.maxFileSize) {
            Logger::Error("QuarantineManager: File too large: {} bytes", fileSize);
            result.status = QuarantineStatus::FileTooLarge;
            result.message = L"File exceeds maximum size";
            return result;
        }

        // Check system critical files
        if (!request.force && m_impl->IsSystemCriticalFile(request.filePath)) {
            Logger::Error("QuarantineManager: System critical file protected");
            result.status = QuarantineStatus::SystemFileProtected;
            result.message = L"System critical file cannot be quarantined";
            return result;
        }

        // ====================================================================
        // STAGE 2: METADATA COLLECTION
        // ====================================================================

        auto metadata = m_impl->CollectMetadata(request.filePath);
        auto hashes = m_impl->CalculateHashes(request.filePath);

        // Check if already quarantined
        if (!hashes.sha256.empty() && IsQuarantined(hashes.sha256)) {
            Logger::Warn("QuarantineManager: File already quarantined");
            result.status = QuarantineStatus::AlreadyQuarantined;
            result.message = L"File already in quarantine";
            return result;
        }

        // ====================================================================
        // STAGE 3: PROCESS NEUTRALIZATION
        // ====================================================================

        auto lockingProcesses = m_impl->GetLockingProcessesImpl(request.filePath);

        if (!lockingProcesses.empty()) {
            Logger::Info("QuarantineManager: File locked by {} processes",
                lockingProcesses.size());

            if (m_impl->m_config.autoTerminateProcesses) {
                auto terminated = m_impl->TerminateLockingProcessesImpl(request.filePath);
                result.processesTerminated = terminated;

                if (terminated.size() < lockingProcesses.size()) {
                    Logger::Warn("QuarantineManager: Not all processes terminated");
                    result.status = QuarantineStatus::ProcessKillFailed;
                    result.message = L"Failed to terminate all locking processes";
                    result.rebootRequired = true;
                    return result;
                }
            } else {
                Logger::Error("QuarantineManager: File in use, auto-terminate disabled");
                result.status = QuarantineStatus::FileInUse;
                result.message = L"File is in use";
                result.rebootRequired = true;
                return result;
            }
        }

        // ====================================================================
        // STAGE 4: FILE READ
        // ====================================================================

        std::vector<uint8_t> fileContent;
        try {
            std::ifstream file(request.filePath, std::ios::binary);
            if (!file) {
                Logger::Error("QuarantineManager: Cannot open file for reading");
                result.status = QuarantineStatus::AccessDenied;
                result.message = L"Cannot open file";
                return result;
            }

            file.seekg(0, std::ios::end);
            size_t size = file.tellg();
            file.seekg(0, std::ios::beg);

            fileContent.resize(size);
            file.read(reinterpret_cast<char*>(fileContent.data()), size);

        } catch (const std::exception& e) {
            Logger::Error("QuarantineManager: File read failed: {}", e.what());
            result.status = QuarantineStatus::AccessDenied;
            result.message = L"Failed to read file";
            return result;
        }

        // ====================================================================
        // STAGE 5: ENCRYPTION
        // ====================================================================

        std::vector<uint8_t> encryptedContent = fileContent; // Copy for non-encrypted mode
        std::array<uint8_t, QuarantineConstants::GCM_IV_SIZE> iv{};

        if (m_impl->m_config.encryptFiles) {
            try {
                encryptedContent = m_impl->EncryptContent(fileContent, iv);
            } catch (const std::exception& e) {
                Logger::Error("QuarantineManager: Encryption failed: {}", e.what());
                result.status = QuarantineStatus::EncryptionFailed;
                result.message = L"Encryption failed";
                return result;
            }
        }

        // ====================================================================
        // STAGE 6: VAULT STORAGE
        // ====================================================================

        auto quarantinePath = m_impl->GenerateQuarantinePath(request.filePath);
        result.quarantinePath = quarantinePath;

        try {
            std::ofstream outFile(quarantinePath, std::ios::binary);
            if (!outFile) {
                Logger::Error("QuarantineManager: Cannot create quarantine file");
                result.status = QuarantineStatus::StorageFull;
                result.message = L"Cannot create quarantine file";
                return result;
            }

            // Write file format header
            uint32_t magic = QuarantineConstants::QUARANTINE_MAGIC;
            uint16_t version = QuarantineConstants::QUARANTINE_VERSION;
            uint16_t flags = static_cast<uint16_t>(QuarantineFlags::Encrypted);
            uint64_t originalSize = fileContent.size();

            outFile.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
            outFile.write(reinterpret_cast<const char*>(&version), sizeof(version));
            outFile.write(reinterpret_cast<const char*>(&flags), sizeof(flags));
            outFile.write(reinterpret_cast<const char*>(&originalSize), sizeof(originalSize));

            // Write IV
            outFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());

            // Write encrypted content
            outFile.write(reinterpret_cast<const char*>(encryptedContent.data()),
                         encryptedContent.size());

            outFile.close();

            Logger::Info("QuarantineManager: File written to vault: {}",
                StringUtils::ToNarrowString(quarantinePath));

        } catch (const std::exception& e) {
            Logger::Error("QuarantineManager: Vault write failed: {}", e.what());
            result.status = QuarantineStatus::StorageFull;
            result.message = L"Failed to write quarantine file";
            return result;
        }

        // ====================================================================
        // STAGE 7: ORIGINAL DELETION
        // ====================================================================

        try {
            if (m_impl->m_config.secureWipeOriginal) {
                // TODO: Implement DoD 5220.22-M secure wipe
                Logger::Info("QuarantineManager: Secure wipe not implemented, using standard delete");
            }

            fs::remove(request.filePath, ec);
            if (ec) {
                Logger::Error("QuarantineManager: Failed to delete original: {}", ec.message());
                result.rebootRequired = true;
            } else {
                Logger::Info("QuarantineManager: Original file deleted");
            }

        } catch (const std::exception& e) {
            Logger::Error("QuarantineManager: Delete failed: {}", e.what());
            result.rebootRequired = true;
        }

        // ====================================================================
        // STAGE 8: DATABASE STORAGE
        // ====================================================================

        QuarantineEntry entry{};
        entry.entryId = m_impl->m_nextEntryId.fetch_add(1, std::memory_order_relaxed);
        entry.quarantinePath = quarantinePath;
        entry.state = QuarantineState::Active;
        entry.itemType = QuarantineItemType::File;
        entry.flags = QuarantineFlags::Encrypted;
        entry.originalPath = request.filePath;
        entry.fileName = metadata.fileName;
        entry.originalSize = fileContent.size();
        entry.metadata = metadata;
        entry.hashes = hashes;
        entry.threatName = request.threatName;
        entry.threatFamily = request.threatFamily;
        entry.detectionSource = request.detectionSource;
        entry.threatScore = request.threatScore;
        entry.priority = request.priority;
        entry.mitreTechniques = request.mitreTechniques;
        entry.detectionProcessId = request.relatedProcessId;
        entry.userName = SystemUtils::GetCurrentUserName();
        entry.machineName = SystemUtils::GetComputerName();
        entry.detectionTime = system_clock::now();
        entry.quarantineTime = system_clock::now();
        entry.expirationTime = entry.quarantineTime +
            std::chrono::hours(24 * m_impl->m_config.defaultRetentionDays);
        entry.terminatedProcesses = result.processesTerminated;
        entry.userNotes = request.userNotes;

        // Store in database
        if (!m_impl->m_database->AddEntry(entry)) {
            Logger::Error("QuarantineManager: Database storage failed");
            result.status = QuarantineStatus::DatabaseError;
            result.message = L"Failed to store entry in database";
            return result;
        }

        result.entryId = entry.entryId;

        // Update cache
        m_impl->UpdateCache(entry);

        // ====================================================================
        // STAGE 9: STATISTICS UPDATE
        // ====================================================================

        m_impl->m_stats.totalQuarantined.fetch_add(1, std::memory_order_relaxed);
        m_impl->m_stats.activeEntries.fetch_add(1, std::memory_order_relaxed);
        m_impl->m_stats.currentVaultSize.fetch_add(
            encryptedContent.size(), std::memory_order_relaxed
        );

        // ====================================================================
        // SUCCESS
        // ====================================================================

        result.status = QuarantineStatus::Success;
        result.message = L"File quarantined successfully";
        result.duration = duration_cast<milliseconds>(steady_clock::now() - opStart);

        Logger::Info("QuarantineManager: Quarantine complete - Entry ID: {}, Duration: {} ms",
            entry.entryId, result.duration.count());

        // Invoke callbacks
        m_impl->InvokeQuarantineCallbacks(result);

        return result;

    } catch (const std::exception& e) {
        Logger::Error("QuarantineManager: Quarantine exception: {}", e.what());
        m_impl->m_stats.quarantineFailures.fetch_add(1, std::memory_order_relaxed);

        result.status = QuarantineStatus::UnknownError;
        result.message = StringUtils::ToWideString(
            std::format("Exception: {}", e.what())
        );
        return result;
    }
}

QuarantineResult QuarantineManager::QuarantineFile(
    const std::wstring& filePath,
    const std::wstring& threatName,
    uint32_t relatedPid
) {
    QuarantineRequest request{};
    request.filePath = filePath;
    request.threatName = threatName;
    request.relatedProcessId = relatedPid;
    request.autoRemediate = m_impl->m_config.autoRemediate;

    return QuarantineFile(request);
}

std::future<QuarantineResult> QuarantineManager::QuarantineFileAsync(
    const QuarantineRequest& request,
    QuarantineCallback callback
) {
    return std::async(std::launch::async, [this, request, callback]() {
        auto result = QuarantineFile(request);

        if (callback) {
            try {
                callback(result);
            } catch (const std::exception& e) {
                Logger::Error("QuarantineManager: Async callback exception: {}", e.what());
            }
        }

        return result;
    });
}

std::vector<QuarantineResult> QuarantineManager::QuarantineFiles(
    const std::vector<QuarantineRequest>& requests
) {
    std::vector<QuarantineResult> results;
    results.reserve(requests.size());

    for (const auto& request : requests) {
        results.push_back(QuarantineFile(request));
    }

    return results;
}

// ============================================================================
// RESTORE OPERATIONS
// ============================================================================

RestoreResult QuarantineManager::RestoreFile(const RestoreRequest& request) {
    RestoreResult result{};

    if (!IsInitialized()) {
        Logger::Error("QuarantineManager: Not initialized");
        result.status = QuarantineStatus::DatabaseError;
        result.message = L"Manager not initialized";
        return result;
    }

    try {
        Logger::Info("QuarantineManager: Restore request for entry ID: {}", request.entryId);

        result.entryId = request.entryId;

        // ====================================================================
        // STAGE 1: ENTRY LOOKUP
        // ====================================================================

        auto entryOpt = GetEntry(request.entryId);
        if (!entryOpt) {
            Logger::Error("QuarantineManager: Entry not found");
            result.status = QuarantineStatus::EntryNotFound;
            result.message = L"Entry not found";
            return result;
        }

        auto entry = *entryOpt;

        // Validate state
        if (entry.state != QuarantineState::Active) {
            Logger::Error("QuarantineManager: Entry not in active state");
            result.status = QuarantineStatus::UnknownError;
            result.message = L"Entry not active";
            return result;
        }

        // ====================================================================
        // STAGE 2: READ QUARANTINE FILE
        // ====================================================================

        std::vector<uint8_t> fileContent;

        try {
            std::ifstream inFile(entry.quarantinePath, std::ios::binary);
            if (!inFile) {
                Logger::Error("QuarantineManager: Cannot open quarantine file");
                result.status = QuarantineStatus::EntryNotFound;
                result.message = L"Quarantine file not found";
                return result;
            }

            // Read header
            uint32_t magic = 0;
            uint16_t version = 0;
            uint16_t flags = 0;
            uint64_t originalSize = 0;
            std::array<uint8_t, QuarantineConstants::GCM_IV_SIZE> iv{};

            inFile.read(reinterpret_cast<char*>(&magic), sizeof(magic));
            inFile.read(reinterpret_cast<char*>(&version), sizeof(version));
            inFile.read(reinterpret_cast<char*>(&flags), sizeof(flags));
            inFile.read(reinterpret_cast<char*>(&originalSize), sizeof(originalSize));
            inFile.read(reinterpret_cast<char*>(iv.data()), iv.size());

            // Verify magic number
            if (magic != QuarantineConstants::QUARANTINE_MAGIC) {
                Logger::Error("QuarantineManager: Invalid quarantine file format");
                result.status = QuarantineStatus::IntegrityFailed;
                result.message = L"Invalid file format";
                return result;
            }

            // Read encrypted content
            std::vector<uint8_t> encryptedContent;
            inFile.seekg(0, std::ios::end);
            size_t totalSize = inFile.tellg();
            size_t headerSize = sizeof(magic) + sizeof(version) + sizeof(flags) +
                               sizeof(originalSize) + iv.size();
            size_t encryptedSize = totalSize - headerSize;

            inFile.seekg(headerSize, std::ios::beg);
            encryptedContent.resize(encryptedSize);
            inFile.read(reinterpret_cast<char*>(encryptedContent.data()), encryptedSize);

            // Decrypt
            if (m_impl->m_config.encryptFiles) {
                fileContent = m_impl->DecryptContent(encryptedContent, iv);
            } else {
                fileContent = encryptedContent;
            }

            Logger::Info("QuarantineManager: File decrypted, size: {}", fileContent.size());

        } catch (const std::exception& e) {
            Logger::Error("QuarantineManager: Read/decrypt failed: {}", e.what());
            m_impl->m_stats.restoreFailures.fetch_add(1, std::memory_order_relaxed);
            result.status = QuarantineStatus::DecryptionFailed;
            result.message = L"Decryption failed";
            return result;
        }

        // ====================================================================
        // STAGE 3: INTEGRITY VERIFICATION
        // ====================================================================

        if (request.verifyIntegrity && !entry.hashes.sha256.empty()) {
            std::vector<uint8_t> hashBytes;
            HashUtils::Compute(HashUtils::Algorithm::SHA256,
                             fileContent.data(), fileContent.size(), hashBytes);
            auto restoredHash = HashUtils::ToHexLower(hashBytes);

            if (restoredHash != entry.hashes.sha256) {
                Logger::Error("QuarantineManager: Integrity check failed");
                Logger::Error("Expected: {}, Got: {}",
                    entry.hashes.sha256, restoredHash);
                result.status = QuarantineStatus::IntegrityFailed;
                result.message = L"Hash mismatch - file corrupted";
                return result;
            }

            result.integrityVerified = true;
            result.restoredHash = restoredHash;
            Logger::Info("QuarantineManager: Integrity verified");
        }

        // ====================================================================
        // STAGE 4: FILE WRITE
        // ====================================================================

        std::wstring restorePath = request.customPath.empty()
            ? entry.originalPath
            : request.customPath;

        result.restoredPath = restorePath;

        try {
            // Check if file exists
            std::error_code ec;
            if (fs::exists(restorePath, ec) && !request.overrideExisting) {
                Logger::Error("QuarantineManager: File already exists");
                result.status = QuarantineStatus::UnknownError;
                result.message = L"File already exists";
                return result;
            }

            // Write file
            std::ofstream outFile(restorePath, std::ios::binary);
            if (!outFile) {
                Logger::Error("QuarantineManager: Cannot create restored file");
                result.status = QuarantineStatus::AccessDenied;
                result.message = L"Cannot create file";
                return result;
            }

            outFile.write(reinterpret_cast<const char*>(fileContent.data()),
                         fileContent.size());
            outFile.close();

            Logger::Info("QuarantineManager: File restored to: {}",
                StringUtils::ToNarrowString(restorePath));

        } catch (const std::exception& e) {
            Logger::Error("QuarantineManager: Restore write failed: {}", e.what());
            m_impl->m_stats.restoreFailures.fetch_add(1, std::memory_order_relaxed);
            result.status = QuarantineStatus::AccessDenied;
            result.message = L"Failed to write restored file";
            return result;
        }

        // ====================================================================
        // STAGE 5: DATABASE UPDATE
        // ====================================================================

        entry.state = QuarantineState::Restored;
        entry.restoreTime = system_clock::now();

        if (!m_impl->m_database->UpdateEntry(entry)) {
            Logger::Warn("QuarantineManager: Database update failed (non-fatal)");
        }

        m_impl->UpdateCache(entry);

        // ====================================================================
        // STAGE 6: STATISTICS
        // ====================================================================

        m_impl->m_stats.totalRestored.fetch_add(1, std::memory_order_relaxed);
        m_impl->m_stats.activeEntries.fetch_sub(1, std::memory_order_relaxed);

        // ====================================================================
        // SUCCESS
        // ====================================================================

        result.status = QuarantineStatus::Success;
        result.message = L"File restored successfully";

        Logger::Info("QuarantineManager: Restore complete - Entry ID: {}", entry.entryId);

        // Invoke callbacks
        m_impl->InvokeRestoreCallbacks(result);

        return result;

    } catch (const std::exception& e) {
        Logger::Error("QuarantineManager: Restore exception: {}", e.what());
        m_impl->m_stats.restoreFailures.fetch_add(1, std::memory_order_relaxed);

        result.status = QuarantineStatus::UnknownError;
        result.message = StringUtils::ToWideString(
            std::format("Exception: {}", e.what())
        );
        return result;
    }
}

RestoreResult QuarantineManager::RestoreFile(
    uint64_t entryId,
    const std::wstring& restorePath
) {
    RestoreRequest request{};
    request.entryId = entryId;
    request.customPath = restorePath;
    request.verifyIntegrity = m_impl->m_config.verifyIntegrityOnRestore;

    return RestoreFile(request);
}

std::future<RestoreResult> QuarantineManager::RestoreFileAsync(
    const RestoreRequest& request,
    RestoreCallback callback
) {
    return std::async(std::launch::async, [this, request, callback]() {
        auto result = RestoreFile(request);

        if (callback) {
            try {
                callback(result);
            } catch (const std::exception& e) {
                Logger::Error("QuarantineManager: Async callback exception: {}", e.what());
            }
        }

        return result;
    });
}

// ============================================================================
// DELETE OPERATIONS
// ============================================================================

bool QuarantineManager::DeleteFile(uint64_t entryId, bool secureWipe) {
    if (!IsInitialized()) {
        Logger::Error("QuarantineManager: Not initialized");
        return false;
    }

    try {
        auto entryOpt = GetEntry(entryId);
        if (!entryOpt) {
            Logger::Error("QuarantineManager: Entry not found");
            return false;
        }

        auto entry = *entryOpt;

        // Delete quarantine file
        std::error_code ec;
        if (fs::exists(entry.quarantinePath, ec)) {
            if (secureWipe) {
                // TODO: Implement secure wipe
                Logger::Info("QuarantineManager: Secure wipe not implemented");
            }

            fs::remove(entry.quarantinePath, ec);
            if (ec) {
                Logger::Error("QuarantineManager: Failed to delete quarantine file: {}",
                    ec.message());
                return false;
            }
        }

        // Update database
        entry.state = QuarantineState::Deleted;
        entry.deletionTime = system_clock::now();

        if (!m_impl->m_database->UpdateEntry(entry)) {
            Logger::Warn("QuarantineManager: Database update failed");
        }

        // Update cache
        m_impl->RemoveFromCache(entryId);

        // Update statistics
        m_impl->m_stats.totalDeleted.fetch_add(1, std::memory_order_relaxed);
        if (entry.state == QuarantineState::Active) {
            m_impl->m_stats.activeEntries.fetch_sub(1, std::memory_order_relaxed);
        }

        Logger::Info("QuarantineManager: Entry deleted: {}", entryId);
        return true;

    } catch (const std::exception& e) {
        Logger::Error("QuarantineManager: Delete exception: {}", e.what());
        return false;
    }
}

size_t QuarantineManager::DeleteFiles(const std::vector<uint64_t>& entryIds) {
    size_t deleted = 0;

    for (auto entryId : entryIds) {
        if (DeleteFile(entryId, false)) {
            deleted++;
        }
    }

    return deleted;
}

size_t QuarantineManager::DeleteExpiredEntries() {
    if (!IsInitialized()) return 0;

    try {
        auto now = system_clock::now();
        auto entries = GetActiveEntries();

        size_t deleted = 0;
        for (const auto& entry : entries) {
            if (entry.IsExpired()) {
                if (DeleteFile(entry.entryId, false)) {
                    deleted++;
                }
            }
        }

        m_impl->m_stats.expiredDeleted.fetch_add(deleted, std::memory_order_relaxed);
        Logger::Info("QuarantineManager: Deleted {} expired entries", deleted);

        return deleted;

    } catch (const std::exception& e) {
        Logger::Error("QuarantineManager: DeleteExpiredEntries exception: {}", e.what());
        return 0;
    }
}

size_t QuarantineManager::DeleteAllEntries() {
    if (!IsInitialized()) return 0;

    try {
        auto entries = GetActiveEntries();
        size_t deleted = 0;

        for (const auto& entry : entries) {
            if (DeleteFile(entry.entryId, false)) {
                deleted++;
            }
        }

        Logger::Info("QuarantineManager: Deleted {} entries", deleted);
        return deleted;

    } catch (const std::exception& e) {
        Logger::Error("QuarantineManager: DeleteAllEntries exception: {}", e.what());
        return 0;
    }
}

// ============================================================================
// QUERY OPERATIONS
// ============================================================================

std::optional<QuarantineEntry> QuarantineManager::GetEntry(uint64_t entryId) const {
    if (!IsInitialized()) return std::nullopt;

    try {
        // Check cache first
        if (auto cached = m_impl->GetFromCache(entryId)) {
            return cached;
        }

        // Query database
        auto entry = m_impl->m_database->GetEntry(entryId);
        if (entry) {
            // Update cache
            const_cast<Impl*>(m_impl.get())->UpdateCache(*entry);
        }

        return entry;

    } catch (const std::exception& e) {
        Logger::Error("QuarantineManager: GetEntry exception: {}", e.what());
        return std::nullopt;
    }
}

std::optional<QuarantineEntry> QuarantineManager::GetEntryByHash(
    const std::string& hash
) const {
    if (!IsInitialized()) return std::nullopt;

    try {
        return m_impl->m_database->GetEntryByHash(hash);
    } catch (const std::exception& e) {
        Logger::Error("QuarantineManager: GetEntryByHash exception: {}", e.what());
        return std::nullopt;
    }
}

std::vector<QuarantineEntry> QuarantineManager::QueryEntries(
    const QuarantineQuery& query
) const {
    if (!IsInitialized()) return {};

    try {
        return m_impl->m_database->QueryEntries(query);
    } catch (const std::exception& e) {
        Logger::Error("QuarantineManager: QueryEntries exception: {}", e.what());
        return {};
    }
}

std::vector<QuarantineEntry> QuarantineManager::GetActiveEntries() const {
    QuarantineQuery query{};
    query.state = QuarantineState::Active;
    return QueryEntries(query);
}

size_t QuarantineManager::GetEntryCount(std::optional<QuarantineState> state) const {
    if (!IsInitialized()) return 0;

    try {
        return m_impl->m_database->GetEntryCount(state);
    } catch (const std::exception& e) {
        Logger::Error("QuarantineManager: GetEntryCount exception: {}", e.what());
        return 0;
    }
}

bool QuarantineManager::IsQuarantined(const std::string& hash) const {
    return GetEntryByHash(hash).has_value();
}

// ============================================================================
// PROCESS MANAGEMENT
// ============================================================================

std::vector<LockingProcess> QuarantineManager::TerminateLockingProcesses(
    const std::wstring& filePath
) {
    if (!IsInitialized()) return {};
    return m_impl->TerminateLockingProcessesImpl(filePath);
}

std::vector<LockingProcess> QuarantineManager::GetLockingProcesses(
    const std::wstring& filePath
) const {
    if (!IsInitialized()) return {};
    return m_impl->GetLockingProcessesImpl(filePath);
}

// ============================================================================
// REMEDIATION (TODO)
// ============================================================================

std::vector<RemediationAction> QuarantineManager::RemediateArtifacts(uint64_t entryId) {
    // TODO: Implement registry/service/task cleanup
    Logger::Warn("QuarantineManager: RemediateArtifacts not yet implemented");
    return {};
}

bool QuarantineManager::RollbackRemediation(uint64_t entryId) {
    // TODO: Implement remediation rollback
    Logger::Warn("QuarantineManager: RollbackRemediation not yet implemented");
    return false;
}

bool QuarantineManager::AddRemediationAction(
    uint64_t entryId,
    const RemediationAction& action
) {
    // TODO: Store remediation action in database
    Logger::Warn("QuarantineManager: AddRemediationAction not yet implemented");
    return false;
}

// ============================================================================
// FORENSICS (TODO)
// ============================================================================

bool QuarantineManager::ExtractForAnalysis(
    uint64_t entryId,
    const std::wstring& destPath
) {
    // TODO: Extract quarantined file for forensic analysis
    Logger::Warn("QuarantineManager: ExtractForAnalysis not yet implemented");
    return false;
}

std::string QuarantineManager::SubmitSample(uint64_t entryId) {
    // TODO: Submit to cloud/sandbox for analysis
    Logger::Warn("QuarantineManager: SubmitSample not yet implemented");
    return "";
}

std::wstring QuarantineManager::PreserveEvidence(uint64_t entryId) {
    // TODO: Create forensics archive
    Logger::Warn("QuarantineManager: PreserveEvidence not yet implemented");
    return L"";
}

// ============================================================================
// EXPORT/IMPORT (TODO)
// ============================================================================

bool QuarantineManager::ExportDatabase(const std::wstring& filePath) const {
    // TODO: Export quarantine database to JSON/XML
    Logger::Warn("QuarantineManager: ExportDatabase not yet implemented");
    return false;
}

size_t QuarantineManager::ImportDatabase(const std::wstring& filePath) {
    // TODO: Import quarantine database
    Logger::Warn("QuarantineManager: ImportDatabase not yet implemented");
    return 0;
}

// ============================================================================
// MAINTENANCE
// ============================================================================

void QuarantineManager::RunMaintenance() {
    if (!IsInitialized()) return;

    try {
        Logger::Info("QuarantineManager: Running maintenance");

        // Delete expired entries
        if (m_impl->m_config.autoDeleteExpired) {
            DeleteExpiredEntries();
        }

        // Verify vault integrity
        VerifyVaultIntegrity();

        Logger::Info("QuarantineManager: Maintenance complete");

    } catch (const std::exception& e) {
        Logger::Error("QuarantineManager: Maintenance exception: {}", e.what());
    }
}

size_t QuarantineManager::VerifyVaultIntegrity() {
    if (!IsInitialized()) return 0;

    size_t corrupted = 0;

    try {
        auto entries = GetActiveEntries();

        for (const auto& entry : entries) {
            std::error_code ec;
            if (!fs::exists(entry.quarantinePath, ec)) {
                Logger::Warn("QuarantineManager: Quarantine file missing: {}",
                    StringUtils::ToNarrowString(entry.quarantinePath));
                corrupted++;
            }
        }

        Logger::Info("QuarantineManager: Integrity check - {} corrupted entries", corrupted);
        return corrupted;

    } catch (const std::exception& e) {
        Logger::Error("QuarantineManager: VerifyVaultIntegrity exception: {}", e.what());
        return 0;
    }
}

uint64_t QuarantineManager::CompactVault() {
    // TODO: Implement vault compaction
    Logger::Warn("QuarantineManager: CompactVault not yet implemented");
    return 0;
}

std::wstring QuarantineManager::GetVaultPath() const {
    if (!m_impl) return L"";

    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config.vaultPath;
}

uint64_t QuarantineManager::GetVaultSize() const {
    return m_impl ? m_impl->m_stats.currentVaultSize.load(std::memory_order_relaxed) : 0;
}

uint64_t QuarantineManager::GetAvailableSpace() const {
    // TODO: Get available disk space
    return 0;
}

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t QuarantineManager::RegisterQuarantineCallback(QuarantineCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_quarantineCallbacks[id] = std::move(callback);

    Logger::Debug("QuarantineManager: Registered quarantine callback {}", id);
    return id;
}

bool QuarantineManager::UnregisterQuarantineCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_callbackMutex);
    return m_impl->m_quarantineCallbacks.erase(callbackId) > 0;
}

uint64_t QuarantineManager::RegisterRestoreCallback(RestoreCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_restoreCallbacks[id] = std::move(callback);

    Logger::Debug("QuarantineManager: Registered restore callback {}", id);
    return id;
}

bool QuarantineManager::UnregisterRestoreCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_callbackMutex);
    return m_impl->m_restoreCallbacks.erase(callbackId) > 0;
}

uint64_t QuarantineManager::RegisterRemediationCallback(RemediationCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_remediationCallbacks[id] = std::move(callback);

    Logger::Debug("QuarantineManager: Registered remediation callback {}", id);
    return id;
}

bool QuarantineManager::UnregisterRemediationCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_callbackMutex);
    return m_impl->m_remediationCallbacks.erase(callbackId) > 0;
}

// ============================================================================
// STATISTICS
// ============================================================================

QuarantineManagerStats QuarantineManager::GetStats() const {
    return m_impl ? m_impl->m_stats : QuarantineManagerStats{};
}

void QuarantineManager::ResetStats() {
    if (m_impl) {
        m_impl->m_stats.Reset();
        Logger::Info("QuarantineManager: Statistics reset");
    }
}

// ============================================================================
// EXTERNAL INTEGRATION
// ============================================================================

void QuarantineManager::SetQuarantineDB(Database::QuarantineDB* db) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_database.reset(db);

    Logger::Info("QuarantineManager: External database set");
}

} // namespace Engine
} // namespace Core
} // namespace ShadowStrike
