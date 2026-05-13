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
#include "../FileSystem/FileLockManager.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <random>
#include <unordered_set>

// ============================================================================
// WINDOWS SPECIFIC INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <RestartManager.h>
#  include <sddl.h>
#  include <AclAPI.h>
#  pragma comment(lib, "Rstrtmgr.lib")
#  pragma comment(lib, "Advapi32.lib")
#endif

namespace ShadowStrike {
namespace Core {
namespace Engine {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// ON-DISK QUARANTINE FILE HEADER (packed POD, written verbatim).
// SECURITY: bound as Additional Authenticated Data (AAD) into AES-256-GCM so
// any tamper of magic / version / flags / originalSize / IV is detected via
// authentication-tag mismatch on decrypt. Layout MUST remain stable for ABI
// compatibility with previously written .ssqf files.
// Layout:  magic(4) | version(2) | flags(2) | originalSize(8) | iv(GCM_IV_SIZE)
// ============================================================================
#pragma pack(push, 1)
struct QuarantineFileHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint64_t originalSize;
    uint8_t  iv[QuarantineConstants::GCM_IV_SIZE];
};
#pragma pack(pop)
static_assert(sizeof(QuarantineFileHeader) ==
              4 + 2 + 2 + 8 + QuarantineConstants::GCM_IV_SIZE,
              "QuarantineFileHeader must be packed and layout-stable");

// ============================================================================
// INTERNAL SYSTEM UTILITY WRAPPERS
// ============================================================================

namespace {

[[nodiscard]] std::string GetMachineGuidInternal() noexcept {
    try {
        RegistryUtils::RegistryKey key;
        RegistryUtils::Error err{};
        RegistryUtils::OpenOptions opts{};
        opts.access = KEY_READ;
        if (key.Open(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", opts, &err)) {
            std::wstring guid;
            if (key.ReadString(L"MachineGuid", guid, &err)) {
                return StringUtils::ToNarrow(guid);
            }
        }
    } catch (...) {}
    return "default-machine-guid";
}

[[nodiscard]] std::string GetCurrentUserSidInternal() noexcept {
    try {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return "";

        DWORD dwLength = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwLength);
        if (dwLength == 0) { CloseHandle(hToken); return ""; }

        std::vector<uint8_t> buffer(dwLength);
        if (!GetTokenInformation(hToken, TokenUser, buffer.data(), dwLength, &dwLength)) {
            CloseHandle(hToken);
            return "";
        }
        CloseHandle(hToken);

        auto* pTokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
        LPWSTR sidStr = nullptr;
        if (ConvertSidToStringSidW(pTokenUser->User.Sid, &sidStr)) {
            std::string result = StringUtils::ToNarrow(sidStr);
            LocalFree(sidStr);
            return result;
        }
    } catch (...) {}
    return "";
}

[[nodiscard]] std::wstring GetCurrentUserNameInternal() noexcept {
    try {
        wchar_t buf[256] = {};
        DWORD size = 256;
        if (GetUserNameW(buf, &size)) {
            return std::wstring(buf);
        }
    } catch (...) {}
    return L"UNKNOWN";
}

[[nodiscard]] std::wstring GetComputerNameInternal() noexcept {
    return SystemUtils::GetComputerNameDnsHostname();
}

[[nodiscard]] std::wstring GetFileOwnerSidInternal(const std::wstring& filePath) noexcept {
    try {
        PSID pOwner = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        if (GetNamedSecurityInfoW(filePath.c_str(), SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION, &pOwner, nullptr, nullptr, nullptr, &pSD)
            == ERROR_SUCCESS && pOwner)
        {
            LPWSTR sidStr = nullptr;
            if (ConvertSidToStringSidW(pOwner, &sidStr)) {
                std::wstring result(sidStr);
                LocalFree(sidStr);
                LocalFree(pSD);
                return result;
            }
            LocalFree(pSD);
        }
    } catch (...) {}
    return L"";
}

// Adapter: convert Engine's QuarantineEntry to DB's QuarantineEntry
[[nodiscard]] Database::QuarantineDB::QuarantineEntry ToDBEntry(
    const QuarantineEntry& e
) noexcept {
    Database::QuarantineDB::QuarantineEntry db{};
    db.id = static_cast<int64_t>(e.entryId);
    db.quarantineTime = e.quarantineTime;
    db.originalPath = e.originalPath;
    db.originalFileName = e.fileName;
    db.originalSize = e.originalSize;
    db.quarantinePath = e.quarantinePath;
    db.threatName = e.threatName;
    db.sha256Hash = StringUtils::ToWide(e.hashes.sha256);
    db.sha1Hash = StringUtils::ToWide(e.hashes.sha1);
    db.md5Hash = StringUtils::ToWide(e.hashes.md5);
    db.userName = e.userName;
    db.machineName = e.machineName;
    db.processId = e.detectionProcessId;
    db.notes = e.userNotes;

    // Map Engine state to DB status
    switch (e.state) {
        case QuarantineState::Active:   db.status = Database::QuarantineDB::QuarantineStatus::Active; break;
        case QuarantineState::Restored: db.status = Database::QuarantineDB::QuarantineStatus::Restored; break;
        case QuarantineState::Deleted:  db.status = Database::QuarantineDB::QuarantineStatus::Deleted; break;
        case QuarantineState::Pending:  db.status = Database::QuarantineDB::QuarantineStatus::Pending; break;
        case QuarantineState::Failed:   db.status = Database::QuarantineDB::QuarantineStatus::Expired; break;
        default:                        db.status = Database::QuarantineDB::QuarantineStatus::Active; break;
    }

    return db;
}

// Adapter: convert DB's QuarantineEntry to Engine's QuarantineEntry
[[nodiscard]] QuarantineEntry FromDBEntry(
    const Database::QuarantineDB::QuarantineEntry& db
) noexcept {
    QuarantineEntry e{};
    e.entryId = static_cast<uint64_t>(db.id);
    e.quarantineTime = db.quarantineTime;
    e.originalPath = db.originalPath;
    e.fileName = db.originalFileName;
    e.originalSize = db.originalSize;
    e.quarantinePath = db.quarantinePath;
    e.threatName = db.threatName;
    e.hashes.sha256 = StringUtils::ToNarrow(db.sha256Hash);
    e.hashes.sha1 = StringUtils::ToNarrow(db.sha1Hash);
    e.hashes.md5 = StringUtils::ToNarrow(db.md5Hash);
    e.userName = db.userName;
    e.machineName = db.machineName;
    e.detectionProcessId = db.processId;
    e.userNotes = db.notes;

    switch (db.status) {
        case Database::QuarantineDB::QuarantineStatus::Active:   e.state = QuarantineState::Active; break;
        case Database::QuarantineDB::QuarantineStatus::Restored: e.state = QuarantineState::Restored; break;
        case Database::QuarantineDB::QuarantineStatus::Deleted:  e.state = QuarantineState::Deleted; break;
        case Database::QuarantineDB::QuarantineStatus::Pending:  e.state = QuarantineState::Pending; break;
        case Database::QuarantineDB::QuarantineStatus::Expired:  e.state = QuarantineState::Failed; break;
        default:                                                 e.state = QuarantineState::Active; break;
    }

    return e;
}

} // anonymous namespace

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
        if (p.empty()) return false;

        // Reject path traversal components
        for (const auto& component : p) {
            auto s = component.wstring();
            if (s == L".." || s == L".") return false;
        }

        return true;
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
        auto hashW = StringUtils::ToWide(hash.substr(0, 16));
        return hashW + QuarantineConstants::QUARANTINE_EXTENSION;
    } catch (...) {
        return L"unknown.ssqf";
    }
}

[[nodiscard]] bool CanTerminateProcess(uint32_t processId) noexcept {
    if (processId == 0 || processId == 4) return false; // System/Idle

    try {
        // Use ProcessUtils to check if this is a system process
        ProcessUtils::ProcessSecurityInfo secInfo{};
        ProcessUtils::Error procErr{};
        if (ProcessUtils::GetProcessSecurityInfo(processId, secInfo, &procErr)) {
            return !secInfo.isRunningAsSystem;
        }
        return false;
    } catch (...) {
        return false;
    }
}

[[nodiscard]] std::wstring GetProcessImagePath(uint32_t processId) noexcept {
    try {
        auto pathOpt = ProcessUtils::GetProcessPath(processId);
        return pathOpt.value_or(L"");
    } catch (...) {
        return L"";
    }
}

[[nodiscard]] bool IsFileLocked(const std::wstring& path) noexcept {
    try {
        std::error_code ec;
        if (!fs::exists(path, ec)) return false;

#ifdef _WIN32
        // Read-only exclusive access test — does NOT modify the file
        HANDLE h = CreateFileW(
            path.c_str(),
            GENERIC_READ,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (h == INVALID_HANDLE_VALUE) {
            return true;
        }
        CloseHandle(h);
        return false;
#else
        std::ifstream file(path, std::ios::binary);
        return !file.is_open();
#endif
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
            SS_LOG_WARN(L"QuarantineManager", L"QuarantineManager::Impl already initialized");
            return true;
        }

        try {
            SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager::Impl: Initializing");

            // Store configuration
            m_config = config;
            m_threadPool = threadPool;

            // Create vault directory if needed
            if (!m_config.vaultPath.empty()) {
                std::error_code ec;
                if (!fs::exists(m_config.vaultPath, ec)) {
                    fs::create_directories(m_config.vaultPath, ec);
                    if (ec) {
                        SS_LOG_ERROR(L"QuarantineManager", L"Failed to create vault: %ls", StringUtils::ToWide(ec.message()).c_str());
                        return false;
                    }
                }

#ifdef _WIN32
                // Restrict vault directory ACL: SYSTEM and Administrators only
                {
                    PSECURITY_DESCRIPTOR pSD = nullptr;
                    PACL pDacl = nullptr;
                    // SDDL: D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)
                    // Only SYSTEM and Built-in Administrators get full access
                    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                            SDDL_REVISION_1, &pSD, nullptr))
                    {
                        BOOL daclPresent = FALSE, daclDefaulted = FALSE;
                        if (GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted)
                            && daclPresent && pDacl)
                        {
                            DWORD result = SetNamedSecurityInfoW(
                                const_cast<LPWSTR>(m_config.vaultPath.c_str()),
                                SE_FILE_OBJECT,
                                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                nullptr, nullptr, pDacl, nullptr);

                            if (result != ERROR_SUCCESS) {
                                SS_LOG_WARN(L"QuarantineManager", L"Failed to set vault ACL (error %d)", result);
                            } else {
                                SS_LOG_INFO(L"QuarantineManager", L"Vault ACL restricted to SYSTEM+Administrators");
                            }
                        }
                        LocalFree(pSD);
                    }
                }
#endif

                SS_LOG_INFO(L"QuarantineManager", L"Vault path: %ls",
                    m_config.vaultPath.c_str());
            }

            // Initialize database
            m_database = Database::QuarantineDB::Create();
            Database::QuarantineDB::Config dbConfig{};
            dbConfig.dbPath = (fs::path(m_config.vaultPath) / L"quarantine.db").wstring();
            dbConfig.quarantineBasePath = m_config.vaultPath;
            dbConfig.enableEncryption = m_config.encryptFiles;

            Database::DatabaseError dbErr{};
            if (!m_database->Initialize(dbConfig, &dbErr)) {
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Database initialization failed");
                return false;
            }

            SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Database initialized");

            // Derive master encryption key
            if (m_config.encryptFiles) {
                DeriveEncryptionKey();
                SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Encryption key derived");
            }

            // Load entry count
            auto activeCount = m_database->CountEntries(nullptr);
            m_stats.activeEntries.store(
                activeCount > 0 ? static_cast<size_t>(activeCount) : 0,
                std::memory_order_relaxed
            );

            m_initialized.store(true, std::memory_order_release);
            SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager::Impl: Initialization complete");

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"QuarantineManager", L"Initialization exception: %ls", 
                StringUtils::ToWide(e.what()).c_str());
            return false;
        }
    }

    void Shutdown() {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager::Impl: Shutting down");

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

        // Securely wipe encryption key (use project helper that resists
        // optimizer elision; see CryptoUtils::SecureWipeMemory).
        CryptoUtils::SecureWipeMemory(m_masterKey.data(), m_masterKey.size());

        m_initialized.store(false, std::memory_order_release);
        SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager::Impl: Shutdown complete");
    }

    // ========================================================================
    // ENCRYPTION KEY MANAGEMENT
    // ========================================================================

    void DeriveEncryptionKey() {
        try {
            // Use machine-specific entropy
            auto machineGuid = GetMachineGuidInternal();
            auto userSid = GetCurrentUserSidInternal();

            std::string keyMaterial = machineGuid + userSid + "ShadowStrike-Quarantine-Key-v2";

            // Generate cryptographically random salt (persisted per-machine via keyMaterial)
            // Use HKDF-derived salt from machine identity for deterministic re-derivation
            std::vector<uint8_t> salt(32);
            {
                std::string saltInput = machineGuid + "ShadowStrike-QM-Salt-v2";
                std::vector<uint8_t> saltHash;
                if (!HashUtils::Compute(HashUtils::Algorithm::SHA256,
                    saltInput.data(), saltInput.size(), saltHash))
                {
                    SS_LOG_WARN(L"QuarantineManager", L"QuarantineManager: Salt hash computation failed");
                }
                if (saltHash.size() >= 32) {
                    std::copy_n(saltHash.begin(), 32, salt.begin());
                }
            }

            // PBKDF2-SHA256 with 100,000 iterations
            bool derived = CryptoUtils::KeyDerivation::PBKDF2(
                reinterpret_cast<const uint8_t*>(keyMaterial.data()),
                keyMaterial.size(),
                salt.data(),
                salt.size(),
                100000,
                HashUtils::Algorithm::SHA256,
                m_masterKey.data(),
                m_masterKey.size()
            );

            // Securely wipe intermediate key material (project helper)
            CryptoUtils::SecureWipeMemory(keyMaterial.data(), keyMaterial.size());
            CryptoUtils::SecureWipeMemory(salt.data(), salt.size());

            if (!derived) {
                throw std::runtime_error("PBKDF2 key derivation failed");
            }

            SS_LOG_DEBUG(L"QuarantineManager", L"QuarantineManager: Master key derived (PBKDF2-SHA256, 100k iterations)");

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Key derivation failed: %S", e.what());
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
            auto ext = StringUtils::ToLowerCopy(metadata.extension);
            metadata.isExecutable = (ext == L".exe" || ext == L".dll" ||
                                    ext == L".sys" || ext == L".scr");
#endif

            // Owner information
            metadata.ownerSid = GetFileOwnerSidInternal(filePath);

            SS_LOG_DEBUG(L"QuarantineManager", L"QuarantineManager: Metadata collected for %ls", metadata.fileName.c_str());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Metadata collection failed: %S", e.what());
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

            SS_LOG_DEBUG(L"QuarantineManager", L"QuarantineManager: Hashes calculated - SHA256: %S", hashes.sha256.substr(0, 16).c_str());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Hash calculation failed: %S", e.what());
        }

        return hashes;
    }

    // ========================================================================
    // ENCRYPTION / DECRYPTION
    // ========================================================================

    [[nodiscard]] std::vector<uint8_t> EncryptContent(
        std::span<const uint8_t> data,
        std::span<const uint8_t> aad,
        const std::array<uint8_t, QuarantineConstants::GCM_IV_SIZE>& iv
    ) {
        try {
            // Encrypt with AES-256-GCM using SymmetricCipher.
            // SECURITY: caller must supply a fresh, cryptographically random IV
            // and bind the on-disk header as Additional Authenticated Data (AAD)
            // so any tamper of magic/version/flags/originalSize/IV is detected
            // at decrypt time via tag mismatch.
            CryptoUtils::SymmetricCipher cipher(CryptoUtils::SymmetricAlgorithm::AES_256_GCM);

            if (!cipher.SetKey(m_masterKey.data(), m_masterKey.size())) {
                throw std::runtime_error("AES-256-GCM key setup failed");
            }

            if (!cipher.SetIV(iv.data(), iv.size())) {
                throw std::runtime_error("AES-256-GCM IV setup failed");
            }

            std::vector<uint8_t> encrypted;
            std::vector<uint8_t> tag;

            if (!cipher.EncryptAEAD(data.data(), data.size(),
                                    aad.data(), aad.size(),
                                    encrypted, tag))
            {
                throw std::runtime_error("AES-256-GCM encryption failed");
            }

            // Append authentication tag to ciphertext
            encrypted.insert(encrypted.end(), tag.begin(), tag.end());

            SS_LOG_DEBUG(L"QuarantineManager",
                L"QuarantineManager: Content encrypted (%zu bytes -> %zu bytes, aad=%zu)",
                data.size(), encrypted.size(), aad.size());

            return encrypted;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Encryption failed: %S", e.what());
            throw;
        }
    }

    [[nodiscard]] std::vector<uint8_t> DecryptContent(
        std::span<const uint8_t> data,
        std::span<const uint8_t> aad,
        const std::array<uint8_t, QuarantineConstants::GCM_IV_SIZE>& iv
    ) {
        try {
            if (data.size() < QuarantineConstants::GCM_TAG_SIZE) {
                throw std::runtime_error("Invalid encrypted data size");
            }

            // Extract authentication tag from end of ciphertext
            size_t ciphertextSize = data.size() - QuarantineConstants::GCM_TAG_SIZE;
            const uint8_t* tagPtr = data.data() + ciphertextSize;

            // Decrypt with AES-256-GCM using SymmetricCipher.
            // SECURITY: AAD must exactly match what was used at encrypt time
            // (the on-disk header bytes); any drift in magic/version/flags/
            // originalSize/IV will fail authentication.
            CryptoUtils::SymmetricCipher cipher(CryptoUtils::SymmetricAlgorithm::AES_256_GCM);

            if (!cipher.SetKey(m_masterKey.data(), m_masterKey.size())) {
                throw std::runtime_error("AES-256-GCM key setup failed");
            }

            if (!cipher.SetIV(iv.data(), iv.size())) {
                throw std::runtime_error("AES-256-GCM IV setup failed");
            }

            std::vector<uint8_t> decrypted;

            if (!cipher.DecryptAEAD(
                    data.data(), ciphertextSize,
                    aad.data(), aad.size(),
                    tagPtr, QuarantineConstants::GCM_TAG_SIZE,
                    decrypted))
            {
                throw std::runtime_error("AES-256-GCM decryption failed (authentication tag mismatch)");
            }

            SS_LOG_DEBUG(L"QuarantineManager", L"QuarantineManager: Content decrypted (%zu bytes -> %zu bytes)", data.size(), decrypted.size());

            return decrypted;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Decryption failed: %S", e.what());
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
                SS_LOG_WARN(L"QuarantineManager",
                    L"QuarantineManager: RmStartSession failed: %lu", dwError);
                return processes;
            }

            // Register resource
            LPCWSTR pszFile = filePath.c_str();
            dwError = RmRegisterResources(dwSession, 1, &pszFile, 0, nullptr, 0, nullptr);

            if (dwError == ERROR_SUCCESS) {
                // SECURITY: dynamic buffer with retry on ERROR_MORE_DATA so we
                // never silently truncate the locking-process list (truncation
                // would let a malicious process keep its handle open and evade
                // termination). Cap iterations to prevent unbounded growth.
                std::vector<RM_PROCESS_INFO> rgpi;
                UINT nProcInfoNeeded = 0;
                UINT nProcInfo = 0;
                DWORD dwReason = 0;

                constexpr UINT kInitialSlots = 16;
                constexpr UINT kMaxSlots     = 4096;
                rgpi.resize(kInitialSlots);
                nProcInfo = static_cast<UINT>(rgpi.size());

                for (int attempt = 0; attempt < 4; ++attempt) {
                    nProcInfoNeeded = 0;
                    nProcInfo = static_cast<UINT>(rgpi.size());
                    dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo,
                                        rgpi.data(), &dwReason);

                    if (dwError != ERROR_MORE_DATA) {
                        break;
                    }

                    UINT grow = std::max<UINT>(nProcInfoNeeded, nProcInfo * 2);
                    if (grow > kMaxSlots) {
                        SS_LOG_WARN(L"QuarantineManager",
                            L"QuarantineManager: RmGetList capping at %u slots (needed=%u)",
                            kMaxSlots, nProcInfoNeeded);
                        grow = kMaxSlots;
                    }
                    rgpi.resize(grow);
                }

                if (dwError == ERROR_SUCCESS || dwError == ERROR_MORE_DATA) {
                    UINT count = std::min<UINT>(nProcInfo, static_cast<UINT>(rgpi.size()));
                    processes.reserve(count);
                    for (UINT i = 0; i < count; i++) {
                        LockingProcess proc{};
                        proc.processId = rgpi[i].Process.dwProcessId;
                        proc.processName = rgpi[i].strAppName;
                        proc.processPath = GetProcessImagePath(proc.processId);
                        proc.isSystemProcess = (proc.processId == 0 || proc.processId == 4 ||
                                                !CanTerminateProcess(proc.processId));
                        proc.canTerminate = CanTerminateProcess(proc.processId);

                        processes.push_back(std::move(proc));
                    }

                    SS_LOG_INFO(L"QuarantineManager",
                        L"QuarantineManager: Found %zu locking processes",
                        processes.size());
                } else {
                    SS_LOG_WARN(L"QuarantineManager",
                        L"QuarantineManager: RmGetList failed: %lu", dwError);
                }
            }

            RmEndSession(dwSession);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: GetLockingProcesses failed: %S", e.what());
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
                    SS_LOG_WARN(L"QuarantineManager",
                        L"QuarantineManager: Cannot terminate system process: %ls (PID %u)",
                        proc.processName.c_str(), proc.processId);
                    continue;
                }

                // SECURITY: read auto-terminate flag under config lock; the
                // caller of this method already holds m_operationMutex but
                // SetConfig may run on another thread.
                bool autoTerminate = false;
                {
                    std::shared_lock cfgLock(m_configMutex);
                    autoTerminate = m_config.autoTerminateProcesses;
                }
                if (!autoTerminate) {
                    SS_LOG_INFO(L"QuarantineManager",
                        L"QuarantineManager: Auto-terminate disabled, skipping PID %u",
                        proc.processId);
                    continue;
                }

                // Attempt termination via ProcessUtils (exitCode=0)
                ProcessUtils::Error procErr{};
                bool success = ProcessUtils::TerminateProcess(
                    proc.processId, 0, &procErr
                );

                if (success) {
                    proc.wasTerminated = true;
                    terminated.push_back(proc);
                    m_stats.processesTerminated.fetch_add(1, std::memory_order_relaxed);

                    SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Terminated process: %ls (PID %u)", proc.processName.c_str(), proc.processId);
                } else {
                    SS_LOG_WARN(L"QuarantineManager", L"QuarantineManager: Failed to terminate process: %ls (PID %u)", proc.processName.c_str(), proc.processId);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: TerminateLockingProcesses failed: %S", e.what());
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
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Quarantine callback exception: %S", e.what());
            }
        }
    }

    void InvokeRestoreCallbacks(const RestoreResult& result) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_restoreCallbacks) {
            try {
                callback(result);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Restore callback exception: %S", e.what());
            }
        }
    }

    void InvokeRemediationCallbacks(const RemediationAction& action) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_remediationCallbacks) {
            try {
                callback(action);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Remediation callback exception: %S", e.what());
            }
        }
    }

    // ========================================================================
    // VALIDATION
    // ========================================================================

    [[nodiscard]] bool IsSystemCriticalFile(const std::wstring& filePath) const {
        try {
            auto pathLower = StringUtils::ToLowerCopy(filePath);

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
            auto filename = StringUtils::ToLowerCopy(p.filename().wstring());

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

    [[nodiscard]] std::wstring GenerateQuarantinePath(const std::wstring& /*originalPath*/) {
        try {
            // Generate unique filename: high-resolution timestamp + per-process
            // monotonic counter + 64-bit cryptographically random suffix.
            // SECURITY: timestamp alone collides under concurrent quarantine on
            // coarse clocks; we add a CSPRNG suffix to make accidental and
            // adversarial collisions infeasible.
            static std::atomic<uint64_t> s_counter{0};
            const uint64_t timestamp = static_cast<uint64_t>(
                system_clock::now().time_since_epoch().count());
            const uint64_t counter = s_counter.fetch_add(1, std::memory_order_relaxed);

            uint64_t random = 0;
            CryptoUtils::SecureRandom rng;
            if (!rng.Generate(reinterpret_cast<uint8_t*>(&random), sizeof(random))) {
                // Hard-fail if entropy is unavailable rather than silently
                // emitting a predictable filename.
                throw std::runtime_error("SecureRandom failed for quarantine path");
            }

            auto filename = std::format(L"Q{:016X}{:016X}{:016X}.ssqf",
                timestamp, counter, random);

            return (fs::path(m_config.vaultPath) / filename).wstring();

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"QuarantineManager",
                L"QuarantineManager: GenerateQuarantinePath failed: %S", e.what());
            // Fall through to a deterministic but unique-per-call path so we
            // never overwrite an existing quarantine file.
            const uint64_t fallback =
                static_cast<uint64_t>(system_clock::now().time_since_epoch().count());
            try {
                auto filename = std::format(L"Qfallback{:016X}.ssqf", fallback);
                return (fs::path(m_config.vaultPath) / filename).wstring();
            } catch (...) {
                return (fs::path(m_config.vaultPath) / L"unknown.ssqf").wstring();
            }
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
    SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Constructor called");
}

QuarantineManager::~QuarantineManager() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Destructor called");
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
        Logger::Fatal("QuarantineManager: Implementation is null");
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

    SS_LOG_INFO(L"QuarantineManager", L"Configuration updated");
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
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Not initialized");
        result.status = QuarantineStatus::DatabaseError;
        result.message = L"Manager not initialized";
        return result;
    }

    try {
        // Lock for quarantine operation
        std::lock_guard opLock(m_impl->m_operationMutex);

        SS_LOG_INFO(L"QuarantineManager", L"Quarantine request for: %ls", 
            request.filePath.c_str());

        result.originalPath = request.filePath;

        // ====================================================================
        // STAGE 1: VALIDATION
        // ====================================================================

        // Validate path
        if (!IsValidQuarantinePath(request.filePath)) {
            SS_LOG_ERROR(L"QuarantineManager", L"Invalid file path");
            result.status = QuarantineStatus::FileNotFound;
            result.message = L"Invalid file path";
            return result;
        }

        // Check file existence
        std::error_code ec;
        if (!fs::exists(request.filePath, ec)) {
            SS_LOG_ERROR(L"QuarantineManager", L"File not found");
            result.status = QuarantineStatus::FileNotFound;
            result.message = L"File not found";
            return result;
        }

        // Check file size
        uint64_t fileSize = GetFileSizeSafe(request.filePath);
        if (fileSize > m_impl->m_config.maxFileSize) {
            SS_LOG_ERROR(L"QuarantineManager", L"File too large: %llu bytes", fileSize);
            result.status = QuarantineStatus::FileTooLarge;
            result.message = L"File exceeds maximum size";
            return result;
        }

        // Check system critical files
        if (!request.force && m_impl->IsSystemCriticalFile(request.filePath)) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: System critical file protected");
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
            SS_LOG_WARN(L"QuarantineManager", L"QuarantineManager: File already quarantined");
            result.status = QuarantineStatus::AlreadyQuarantined;
            result.message = L"File already in quarantine";
            return result;
        }

        // ====================================================================
        // STAGE 3: PROCESS NEUTRALIZATION (enhanced with FileLockManager)
        // ====================================================================

        auto lockingProcesses = m_impl->GetLockingProcessesImpl(request.filePath);

        // Enhanced: Use FileLockManager for APT-grade threat correlation on locks
        auto& flm = ShadowStrike::Core::FileSystem::FileLockManager::Instance();
        auto lockInfo = flm.GetLockInfo(request.filePath);
        if (lockInfo.threatAssessment.requiresImmediateAction) {
        SS_LOG_WARN(L"QuarantineManager",
            L"FileLockManager: HIGH threat score %.1f on %ls (pattern=%u)",
            lockInfo.threatAssessment.overallThreatScore, request.filePath.c_str(),
            static_cast<unsigned>(lockInfo.threatAssessment.dominantPattern));
        }

        // Merge FileLockManager handle-level owners not found by RM
        for (const auto& flmOwner : lockInfo.owners) {
            bool found = false;
            for (const auto& lp : lockingProcesses) {
                if (lp.processId == flmOwner.pid) { found = true; break; }
            }
            if (!found && flmOwner.pid != 0) {
                LockingProcess lp{};
                lp.processId = flmOwner.pid;
                lp.processName = flmOwner.processName;
                lp.processPath = flmOwner.processPath;
                // Compute terminability + system-process classification the
                // same way RM-derived entries do; otherwise default values
                // would let us either spare a hostile process or attempt to
                // kill csrss/lsass.
                lp.isSystemProcess = (lp.processId == 0 || lp.processId == 4 ||
                                      !CanTerminateProcess(lp.processId));
                lp.canTerminate = CanTerminateProcess(lp.processId);
                lockingProcesses.push_back(std::move(lp));
            }
        }

        if (!lockingProcesses.empty()) {
            SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: File locked by %zu processes", lockingProcesses.size());

            if (m_impl->m_config.autoTerminateProcesses) {
                auto terminated = m_impl->TerminateLockingProcessesImpl(request.filePath);
                result.processesTerminated = terminated;

                if (terminated.size() < lockingProcesses.size()) {
                    // Escalate: try FileLockManager kernel-mode force-close
                    SS_LOG_WARN(L"QuarantineManager", L"Not all processes terminated, escalating to FileLockManager");
                    auto unlockResult = flm.ForceUnlockFile(request.filePath);
                    if (unlockResult.result == ShadowStrike::Core::FileSystem::UnlockResult::Success) {
                        SS_LOG_INFO(L"QuarantineManager", L"FileLockManager force-unlock succeeded");
                    } else if (unlockResult.result == ShadowStrike::Core::FileSystem::UnlockResult::RequiresReboot) {
                        SS_LOG_WARN(L"QuarantineManager", L"File scheduled for delete on reboot via FileLockManager");
                        result.status = QuarantineStatus::ProcessKillFailed;
                        result.message = L"File scheduled for reboot cleanup";
                        result.rebootRequired = true;
                        return result;
                    } else {
                        SS_LOG_WARN(L"QuarantineManager", L"FileLockManager force-unlock also failed");
                        result.status = QuarantineStatus::ProcessKillFailed;
                        result.message = L"Failed to terminate all locking processes";
                        result.rebootRequired = true;
                        return result;
                    }
                }
            } else {
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: File in use, auto-terminate disabled");
                result.status = QuarantineStatus::FileInUse;
                result.message = L"File is in use";
                result.rebootRequired = true;
                return result;
            }
        }

        // ====================================================================
        // STAGE 3.5: VAULT CAPACITY CHECK
        // ====================================================================

        if (m_impl->m_config.maxVaultSize > 0) {
            uint64_t currentSize = m_impl->m_stats.currentVaultSize.load(std::memory_order_relaxed);
            if (currentSize + fileSize > m_impl->m_config.maxVaultSize) {
                SS_LOG_ERROR(L"QuarantineManager",
                    L"QuarantineManager: Vault size limit exceeded (%llu + %llu > %llu)",
                    static_cast<unsigned long long>(currentSize),
                    static_cast<unsigned long long>(fileSize),
                    static_cast<unsigned long long>(m_impl->m_config.maxVaultSize));
                result.status = QuarantineStatus::StorageFull;
                result.message = L"Vault size limit exceeded";
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
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Cannot open file for reading");
                result.status = QuarantineStatus::AccessDenied;
                result.message = L"Cannot open file";
                return result;
            }

            file.seekg(0, std::ios::end);
            const std::streamoff endPos = static_cast<std::streamoff>(file.tellg());
            file.seekg(0, std::ios::beg);

            // SECURITY: tellg() returns -1 on error; an unguarded cast to
            // unsigned would yield SIZE_MAX and crash on the subsequent
            // resize(). Reject any negative or out-of-range size.
            if (endPos < 0 ||
                static_cast<uint64_t>(endPos) > m_impl->m_config.maxFileSize)
            {
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: File size validation failed on read");
                result.status = QuarantineStatus::FileTooLarge;
                result.message = L"File exceeds maximum size on read";
                return result;
            }

            size_t size = static_cast<size_t>(endPos);
            fileContent.resize(size);
            if (size > 0) {
                file.read(reinterpret_cast<char*>(fileContent.data()), size);
                if (static_cast<size_t>(file.gcount()) != size) {
                    SS_LOG_ERROR(L"QuarantineManager",
                        L"QuarantineManager: Short read (%zu of %zu bytes)",
                        static_cast<size_t>(file.gcount()), size);
                    result.status = QuarantineStatus::AccessDenied;
                    result.message = L"Short read from source file";
                    return result;
                }
            }

        } catch (const std::exception& e) {
            // SECURITY: Clear any potentially sensitive data that was read
            CryptoUtils::SecureWipeMemory(fileContent.data(), fileContent.size());

            SS_LOG_ERROR(L"QuarantineManager", L"File read failed: %S", e.what());
            result.status = QuarantineStatus::AccessDenied;
            result.message = L"Failed to read file";
            return result;
        }

        // ====================================================================
        // STAGE 5: HEADER BUILD + ENCRYPTION
        // ====================================================================
        // SECURITY: capture the plaintext size BEFORE any wipe — historical
        // bug recorded `entry.originalSize = fileContent.size()` after the
        // SecureWipeMemory + clear() call below, leaving every entry with
        // originalSize == 0 (silent metadata loss + broken integrity audits).
        const uint64_t originalPlainSize = static_cast<uint64_t>(fileContent.size());

        std::array<uint8_t, QuarantineConstants::GCM_IV_SIZE> iv{};
        QuarantineFlags contentFlags = QuarantineFlags::None;

        if (m_impl->m_config.encryptFiles) {
            // Generate a fresh, cryptographically random IV before building
            // the header so the IV can be bound as AAD.
            CryptoUtils::SecureRandom rng;
            if (!rng.Generate(iv.data(), iv.size())) {
                CryptoUtils::SecureWipeMemory(fileContent.data(), fileContent.size());
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: SecureRandom failed for IV");
                result.status = QuarantineStatus::EncryptionFailed;
                result.message = L"Cryptographic IV generation failed";
                return result;
            }
            contentFlags = contentFlags | QuarantineFlags::Encrypted;
        }

        // Build packed on-disk header. This exact byte sequence is bound as
        // AEAD AAD on encrypt, and re-bound on decrypt; any tamper of any
        // field — including IV swap, originalSize lie, or version downgrade —
        // will fail authentication.
        QuarantineFileHeader header{};
        header.magic        = QuarantineConstants::QUARANTINE_MAGIC;
        header.version      = QuarantineConstants::QUARANTINE_VERSION;
        header.flags        = static_cast<uint16_t>(contentFlags);
        header.originalSize = originalPlainSize;
        std::memcpy(header.iv, iv.data(), iv.size());
        const std::span<const uint8_t> headerAad{
            reinterpret_cast<const uint8_t*>(&header), sizeof(header)};

        std::vector<uint8_t> encryptedContent;
        if (m_impl->m_config.encryptFiles) {
            try {
                encryptedContent = m_impl->EncryptContent(fileContent, headerAad, iv);
            } catch (const std::exception& e) {
                CryptoUtils::SecureWipeMemory(fileContent.data(), fileContent.size());
                SS_LOG_ERROR(L"QuarantineManager", L"Encryption failed: %S", e.what());
                result.status = QuarantineStatus::EncryptionFailed;
                result.message = L"Encryption failed";
                return result;
            }
        } else {
            // No copy in the non-encrypted path: move plaintext into the
            // ciphertext buffer; the explicit wipe loop below operates on the
            // moved-from vector's freshly resized backing store, so we wipe
            // the encryptedContent buffer instead just before clearing it.
            encryptedContent = std::move(fileContent);
        }

        // ====================================================================
        // STAGE 6: VAULT STORAGE
        // ====================================================================

        auto quarantinePath = m_impl->GenerateQuarantinePath(request.filePath);
        result.quarantinePath = quarantinePath;

        // Track on-disk size for statistics. Captured inside the write block
        // before buffers are wiped/cleared.
        uint64_t quarantineDiskSize = 0;

        try {
            std::ofstream outFile(quarantinePath, std::ios::binary);
            if (!outFile) {
            SS_LOG_ERROR(L"QuarantineManager", L"Cannot create quarantine file");
                result.status = QuarantineStatus::StorageFull;
                result.message = L"Cannot create quarantine file";
                return result;
            }

            // Write packed header (bound earlier as AAD) followed by the
            // ciphertext (with appended GCM tag, when encryption is enabled).
            outFile.write(reinterpret_cast<const char*>(&header), sizeof(header));
            outFile.write(reinterpret_cast<const char*>(encryptedContent.data()),
                         encryptedContent.size());

            outFile.close();
            if (!outFile) {
                std::error_code rmEc;
                fs::remove(quarantinePath, rmEc);
                SS_LOG_ERROR(L"QuarantineManager",
                    L"QuarantineManager: Failed to flush quarantine file (%ls)",
                    quarantinePath.c_str());
                result.status = QuarantineStatus::StorageFull;
                result.message = L"Failed to flush quarantine file";
                return result;
            }

            // Securely wipe plaintext from memory after successful vault write.
            // Record the on-disk byte count BEFORE clearing the buffer so the
            // vault-size statistic reflects what was actually written (header
            // + ciphertext + GCM tag), and so that DeleteFile can later
            // reclaim the right amount via filesystem::file_size().
            quarantineDiskSize = static_cast<uint64_t>(sizeof(header)) +
                                 static_cast<uint64_t>(encryptedContent.size());

            // In the non-encrypted path we moved fileContent → encryptedContent;
            // wipe the surviving buffer that still holds the plaintext.
            if (!m_impl->m_config.encryptFiles) {
                CryptoUtils::SecureWipeMemory(encryptedContent.data(),
                                              encryptedContent.size());
                encryptedContent.clear();
                encryptedContent.shrink_to_fit();
            } else {
                CryptoUtils::SecureWipeMemory(fileContent.data(), fileContent.size());
                fileContent.clear();
                fileContent.shrink_to_fit();
            }

            SS_LOG_INFO(L"QuarantineManager", L"File written to vault: %ls",
                quarantinePath.c_str());

        } catch (const std::exception& e) {
            // SECURITY: Clear sensitive data on vault write failure
            CryptoUtils::SecureWipeMemory(fileContent.data(), fileContent.size());
            CryptoUtils::SecureWipeMemory(encryptedContent.data(), encryptedContent.size());

            SS_LOG_ERROR(L"QuarantineManager", L"Vault write failed: %S", e.what());
            result.status = QuarantineStatus::StorageFull;
            result.message = L"Failed to write quarantine file";
            return result;
        }

        // ====================================================================
        // STAGE 7: ORIGINAL DELETION
        // ====================================================================

        try {
            if (m_impl->m_config.secureWipeOriginal) {
                FileUtils::Error fErr{};
                if (!FileUtils::SecureEraseFile(request.filePath,
                        FileUtils::SecureEraseMode::TriplePass, &fErr))
                {
                    SS_LOG_WARN(L"QuarantineManager",
                        L"QuarantineManager: Secure erase failed (%S), falling back to standard delete",
                        fErr.message.c_str());
                    fs::remove(request.filePath, ec);
                    if (ec) {
                        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Fallback delete also failed: %S", ec.message().c_str());
                        result.rebootRequired = true;
                    }
                } else {
                    SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Original file securely erased (triple-pass)");
                }
            } else {
                fs::remove(request.filePath, ec);
                if (ec) {
                    SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Failed to delete original: %S", ec.message().c_str());
                    result.rebootRequired = true;
                } else {
                    SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Original file deleted");
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Delete failed: %S", e.what());
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
        entry.flags = contentFlags;
        entry.originalPath = request.filePath;
        entry.fileName = metadata.fileName;
        entry.originalSize = originalPlainSize;
        entry.metadata = metadata;
        entry.hashes = hashes;
        entry.threatName = request.threatName;
        entry.threatFamily = request.threatFamily;
        entry.detectionSource = request.detectionSource;
        entry.threatScore = request.threatScore;
        entry.priority = request.priority;
        entry.mitreTechniques = request.mitreTechniques;
        entry.detectionProcessId = request.relatedProcessId;
        entry.userName = GetCurrentUserNameInternal();
        entry.machineName = GetComputerNameInternal();
        entry.detectionTime = system_clock::now();
        entry.quarantineTime = system_clock::now();
        entry.expirationTime = entry.quarantineTime +
            std::chrono::hours(24 * m_impl->m_config.defaultRetentionDays);
        entry.terminatedProcesses = result.processesTerminated;
        entry.userNotes = request.userNotes;

        // Store in database via adapter
        {
            auto dbEntry = ToDBEntry(entry);
            int64_t dbId = m_impl->m_database->QuarantineFileDetailed(dbEntry, {});
            if (dbId < 0) {
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Database storage failed");
                result.status = QuarantineStatus::DatabaseError;
                result.message = L"Failed to store entry in database";
                return result;
            }
            entry.entryId = static_cast<uint64_t>(dbId);
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
            quarantineDiskSize, std::memory_order_relaxed
        );

        // ====================================================================
        // SUCCESS
        // ====================================================================

        result.status = QuarantineStatus::Success;
        result.message = L"File quarantined successfully";
        result.duration = duration_cast<milliseconds>(steady_clock::now() - opStart);

        SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Quarantine complete - Entry ID: %llu, Duration: %lld ms", entry.entryId, result.duration.count());

        // Invoke callbacks
        m_impl->InvokeQuarantineCallbacks(result);

        return result;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Quarantine exception: %S", e.what());
        m_impl->m_stats.quarantineFailures.fetch_add(1, std::memory_order_relaxed);

        result.status = QuarantineStatus::UnknownError;
        result.message = StringUtils::ToWide(
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
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Async callback exception: %S", e.what());
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
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Not initialized");
        result.status = QuarantineStatus::DatabaseError;
        result.message = L"Manager not initialized";
        return result;
    }

    try {
        // Serialize restore operations against concurrent quarantine/delete
        std::lock_guard opLock(m_impl->m_operationMutex);

        SS_LOG_INFO(L"QuarantineManager",
            L"QuarantineManager: Restore request for entry ID: %llu",
            static_cast<unsigned long long>(request.entryId));

        result.entryId = request.entryId;

        // Validate custom restore path for traversal attacks
        if (!request.customPath.empty()) {
            if (!IsValidQuarantinePath(request.customPath)) {
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Invalid restore path (path traversal rejected)");
                result.status = QuarantineStatus::AccessDenied;
                result.message = L"Invalid restore path";
                return result;
            }
        }

        // ====================================================================
        // STAGE 1: ENTRY LOOKUP
        // ====================================================================

        auto entryOpt = GetEntry(request.entryId);
        if (!entryOpt) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Entry not found");
            result.status = QuarantineStatus::EntryNotFound;
            result.message = L"Entry not found";
            return result;
        }

        auto entry = *entryOpt;

        // Validate state
        if (entry.state != QuarantineState::Active) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Entry not in active state");
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
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Cannot open quarantine file");
                result.status = QuarantineStatus::EntryNotFound;
                result.message = L"Quarantine file not found";
                return result;
            }

            // Read packed on-disk header in one shot (matches the layout
            // written by QuarantineFile()'s STAGE 5/6).
            QuarantineFileHeader header{};
            std::array<uint8_t, QuarantineConstants::GCM_IV_SIZE> iv{};

            inFile.read(reinterpret_cast<char*>(&header), sizeof(header));
            if (!inFile || static_cast<size_t>(inFile.gcount()) != sizeof(header)) {
                SS_LOG_ERROR(L"QuarantineManager",
                    L"QuarantineManager: Quarantine file truncated (header)");
                result.status = QuarantineStatus::IntegrityFailed;
                result.message = L"Truncated quarantine header";
                return result;
            }

            // Verify magic / version / flags / size constraints. SECURITY:
            // any mismatch here indicates a corrupt or hostile file; refuse
            // to decrypt rather than feed untrusted bytes to AES-GCM.
            if (header.magic != QuarantineConstants::QUARANTINE_MAGIC) {
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Invalid quarantine file format");
                result.status = QuarantineStatus::IntegrityFailed;
                result.message = L"Invalid file format";
                return result;
            }
            if (header.version != QuarantineConstants::QUARANTINE_VERSION) {
                SS_LOG_ERROR(L"QuarantineManager",
                    L"QuarantineManager: Unsupported quarantine version: %u",
                    static_cast<unsigned>(header.version));
                result.status = QuarantineStatus::IntegrityFailed;
                result.message = L"Unsupported quarantine version";
                return result;
            }
            const uint16_t kAllowedFlags =
                static_cast<uint16_t>(QuarantineFlags::Encrypted);
            if ((header.flags & ~kAllowedFlags) != 0) {
                SS_LOG_ERROR(L"QuarantineManager",
                    L"QuarantineManager: Unknown quarantine flags: 0x%04X",
                    static_cast<unsigned>(header.flags));
                result.status = QuarantineStatus::IntegrityFailed;
                result.message = L"Unknown quarantine flags";
                return result;
            }
            if (header.originalSize > m_impl->m_config.maxFileSize) {
                SS_LOG_ERROR(L"QuarantineManager",
                    L"QuarantineManager: Header originalSize exceeds limit (%llu > %llu)",
                    static_cast<unsigned long long>(header.originalSize),
                    static_cast<unsigned long long>(m_impl->m_config.maxFileSize));
                result.status = QuarantineStatus::IntegrityFailed;
                result.message = L"Header size exceeds limit";
                return result;
            }
            std::memcpy(iv.data(), header.iv, iv.size());

            // Determine ciphertext length from total file size minus header.
            // SECURITY: tellg() may return -1 (cast-to-unsigned underflow);
            // also cap encryptedSize against maxFileSize + GCM tag to prevent
            // a malicious header from forcing a multi-GiB resize() (DoS).
            inFile.seekg(0, std::ios::end);
            const std::streamoff endPos = static_cast<std::streamoff>(inFile.tellg());
            constexpr std::streamoff kHeaderBytes =
                static_cast<std::streamoff>(sizeof(QuarantineFileHeader));
            if (endPos < kHeaderBytes) {
                SS_LOG_ERROR(L"QuarantineManager",
                    L"QuarantineManager: Quarantine file shorter than header");
                result.status = QuarantineStatus::IntegrityFailed;
                result.message = L"Truncated quarantine file";
                return result;
            }
            const uint64_t encryptedSize64 =
                static_cast<uint64_t>(endPos - kHeaderBytes);
            const uint64_t kMaxEncrypted =
                m_impl->m_config.maxFileSize +
                static_cast<uint64_t>(QuarantineConstants::GCM_TAG_SIZE);
            if (encryptedSize64 > kMaxEncrypted ||
                encryptedSize64 > std::numeric_limits<size_t>::max())
            {
                SS_LOG_ERROR(L"QuarantineManager",
                    L"QuarantineManager: Encrypted payload exceeds limit (%llu > %llu)",
                    static_cast<unsigned long long>(encryptedSize64),
                    static_cast<unsigned long long>(kMaxEncrypted));
                result.status = QuarantineStatus::IntegrityFailed;
                result.message = L"Encrypted payload exceeds limit";
                return result;
            }
            const size_t encryptedSize = static_cast<size_t>(encryptedSize64);

            std::vector<uint8_t> encryptedContent;
            encryptedContent.resize(encryptedSize);
            inFile.seekg(kHeaderBytes, std::ios::beg);
            if (encryptedSize > 0) {
                inFile.read(reinterpret_cast<char*>(encryptedContent.data()), encryptedSize);
                if (static_cast<size_t>(inFile.gcount()) != encryptedSize) {
                    SS_LOG_ERROR(L"QuarantineManager",
                        L"QuarantineManager: Short read on encrypted payload");
                    result.status = QuarantineStatus::IntegrityFailed;
                    result.message = L"Short read on encrypted payload";
                    return result;
                }
            }

            // Decrypt. Bind the exact same header bytes as AAD that were
            // bound at quarantine time; any tamper is rejected here.
            const std::span<const uint8_t> headerAad{
                reinterpret_cast<const uint8_t*>(&header), sizeof(header)};
            if ((header.flags & static_cast<uint16_t>(QuarantineFlags::Encrypted)) != 0) {
                fileContent = m_impl->DecryptContent(encryptedContent, headerAad, iv);
            } else {
                fileContent = std::move(encryptedContent);
            }

            // Sanity: decrypted size must match the AAD-bound originalSize.
            if (fileContent.size() != header.originalSize) {
                SS_LOG_ERROR(L"QuarantineManager",
                    L"QuarantineManager: Decrypted size %zu does not match header %llu",
                    fileContent.size(),
                    static_cast<unsigned long long>(header.originalSize));
                result.status = QuarantineStatus::IntegrityFailed;
                result.message = L"Decrypted size mismatch";
                return result;
            }

            SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: File decrypted, size: %zu", fileContent.size());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Read/decrypt failed: %S", e.what());
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
            if (!HashUtils::Compute(HashUtils::Algorithm::SHA256,
                             fileContent.data(), fileContent.size(), hashBytes))
            {
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Hash computation failed during integrity check");
                result.status = QuarantineStatus::IntegrityFailed;
                result.message = L"Hash computation failed";
                return result;
            }
            auto restoredHash = HashUtils::ToHexLower(hashBytes);

            if (restoredHash != entry.hashes.sha256) {
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Integrity check failed");
                SS_LOG_ERROR(L"QuarantineManager",
                    L"Expected: %S, Got: %S",
                    entry.hashes.sha256.c_str(), restoredHash.c_str());
                result.status = QuarantineStatus::IntegrityFailed;
                result.message = L"Hash mismatch - file corrupted";
                return result;
            }

            result.integrityVerified = true;
            result.restoredHash = restoredHash;
            SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Integrity verified");
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
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: File already exists");
                result.status = QuarantineStatus::UnknownError;
                result.message = L"File already exists";
                return result;
            }

            // Write file
            std::ofstream outFile(restorePath, std::ios::binary);
            if (!outFile) {
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Cannot create restored file");
                result.status = QuarantineStatus::AccessDenied;
                result.message = L"Cannot create file";
                return result;
            }

            outFile.write(reinterpret_cast<const char*>(fileContent.data()),
                         fileContent.size());
            outFile.close();

            SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: File restored to: %ls", restorePath.c_str());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Restore write failed: %S", e.what());
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

        if (!m_impl->m_database->UpdateEntry(ToDBEntry(entry))) {
            SS_LOG_WARN(L"QuarantineManager", L"QuarantineManager: Database update failed (non-fatal)");
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

        SS_LOG_INFO(L"QuarantineManager",
            L"QuarantineManager: Restore complete - Entry ID: %llu",
            static_cast<unsigned long long>(entry.entryId));

        // Invoke callbacks
        m_impl->InvokeRestoreCallbacks(result);

        return result;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Restore exception: %S", e.what());
        m_impl->m_stats.restoreFailures.fetch_add(1, std::memory_order_relaxed);

        result.status = QuarantineStatus::UnknownError;
        result.message = StringUtils::ToWide(
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
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Async callback exception: %S", e.what());
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
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Not initialized");
        return false;
    }

    try {
        std::lock_guard opLock(m_impl->m_operationMutex);

        auto entryOpt = GetEntry(entryId);
        if (!entryOpt) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Entry not found");
            return false;
        }

        auto entry = *entryOpt;
        bool wasActive = (entry.state == QuarantineState::Active);

        // Capture on-disk size BEFORE removal so we can subtract it from
        // currentVaultSize. Without this, repeated quarantine/delete cycles
        // would let the gauge grow without bound and falsely trip the
        // maxVaultSize ceiling. file_size() is only valid before removal.
        uint64_t reclaimedSize = 0;

        // Delete quarantine file
        std::error_code ec;
        if (fs::exists(entry.quarantinePath, ec)) {
            std::error_code sizeEc;
            const auto sizeOnDisk = fs::file_size(entry.quarantinePath, sizeEc);
            if (!sizeEc) {
                reclaimedSize = static_cast<uint64_t>(sizeOnDisk);
            }
            if (secureWipe) {
                FileUtils::Error fErr{};
                if (!FileUtils::SecureEraseFile(entry.quarantinePath,
                        FileUtils::SecureEraseMode::TriplePass, &fErr))
                {
                    SS_LOG_WARN(L"QuarantineManager", L"QuarantineManager: Secure erase failed, falling back to standard delete");
                    fs::remove(entry.quarantinePath, ec);
                    if (ec) {
                        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Failed to delete quarantine file: %S", ec.message().c_str());
                        return false;
                    }
                }
            } else {
                fs::remove(entry.quarantinePath, ec);
                if (ec) {
                    SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Failed to delete quarantine file: %S", ec.message().c_str());
                    return false;
                }
            }
        }

        // Update database
        entry.state = QuarantineState::Deleted;
        entry.deletionTime = system_clock::now();

        if (!m_impl->m_database->UpdateEntry(ToDBEntry(entry))) {
            SS_LOG_WARN(L"QuarantineManager", L"QuarantineManager: Database update failed");
        }

        // Update cache
        m_impl->RemoveFromCache(entryId);

        // Update statistics — check BEFORE state change
        m_impl->m_stats.totalDeleted.fetch_add(1, std::memory_order_relaxed);
        if (wasActive) {
            m_impl->m_stats.activeEntries.fetch_sub(1, std::memory_order_relaxed);
        }
        if (reclaimedSize > 0) {
            // Saturating subtract: never underflow the unsigned counter.
            uint64_t prev = m_impl->m_stats.currentVaultSize.load(std::memory_order_relaxed);
            while (true) {
                uint64_t next = (prev > reclaimedSize) ? (prev - reclaimedSize) : 0;
                if (m_impl->m_stats.currentVaultSize.compare_exchange_weak(
                        prev, next, std::memory_order_relaxed))
                {
                    break;
                }
            }
        }

        SS_LOG_INFO(L"QuarantineManager",
            L"QuarantineManager: Entry deleted: %llu",
            static_cast<unsigned long long>(entryId));
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Delete exception: %S", e.what());
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
        SS_LOG_INFO(L"QuarantineManager",
            L"QuarantineManager: Deleted %zu expired entries", deleted);

        return deleted;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: DeleteExpiredEntries exception: %S", e.what());
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

        SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Deleted %zu entries", deleted);
        return deleted;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: DeleteAllEntries exception: %S", e.what());
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
        auto dbEntryOpt = m_impl->m_database->GetEntry(static_cast<int64_t>(entryId));
        if (dbEntryOpt) {
            auto converted = FromDBEntry(*dbEntryOpt);
            // Cache is mutable for read-through caching
            std::unique_lock lock(m_impl->m_entriesMutex);
            if (m_impl->m_entryCache.size() >= Impl::MAX_CACHE_SIZE) {
                m_impl->m_entryCache.erase(m_impl->m_entryCache.begin());
            }
            m_impl->m_entryCache[converted.entryId] = converted;
            return converted;
        }

        return std::nullopt;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: GetEntry exception: %S", e.what());
        return std::nullopt;
    }
}

std::optional<QuarantineEntry> QuarantineManager::GetEntryByHash(
    const std::string& hash
) const {
    if (!IsInitialized()) return std::nullopt;

    try {
        auto wHash = StringUtils::ToWide(hash);
        auto dbResults = m_impl->m_database->SearchByHash(wHash);
        if (!dbResults.empty()) {
            return FromDBEntry(dbResults.front());
        }
        return std::nullopt;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: GetEntryByHash exception: %S", e.what());
        return std::nullopt;
    }
}

std::vector<QuarantineEntry> QuarantineManager::QueryEntries(
    const QuarantineQuery& query
) const {
    if (!IsInitialized()) return {};

    try {
        // Map Engine query to DB query filter
        Database::QuarantineDB::QueryFilter dbFilter{};
        dbFilter.maxResults = query.maxResults;

        if (query.state.has_value()) {
            switch (*query.state) {
                case QuarantineState::Active:
                    dbFilter.status = Database::QuarantineDB::QuarantineStatus::Active; break;
                case QuarantineState::Restored:
                    dbFilter.status = Database::QuarantineDB::QuarantineStatus::Restored; break;
                case QuarantineState::Deleted:
                    dbFilter.status = Database::QuarantineDB::QuarantineStatus::Deleted; break;
                default:
                    dbFilter.status = Database::QuarantineDB::QuarantineStatus::Active; break;
            }
        }

        auto dbResults = m_impl->m_database->Query(dbFilter);

        std::vector<QuarantineEntry> results;
        results.reserve(dbResults.size());
        for (const auto& dbEntry : dbResults) {
            results.push_back(FromDBEntry(dbEntry));
        }
        return results;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: QueryEntries exception: %S", e.what());
        return {};
    }
}

std::vector<QuarantineEntry> QuarantineManager::GetActiveEntries() const {
    if (!IsInitialized()) return {};

    try {
        auto dbResults = m_impl->m_database->GetActiveEntries();
        std::vector<QuarantineEntry> results;
        results.reserve(dbResults.size());
        for (const auto& dbEntry : dbResults) {
            results.push_back(FromDBEntry(dbEntry));
        }
        return results;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: GetActiveEntries exception: %S", e.what());
        return {};
    }
}

size_t QuarantineManager::GetEntryCount(std::optional<QuarantineState> state) const {
    if (!IsInitialized()) return 0;

    try {
        auto count = m_impl->m_database->CountEntries(nullptr);
        return count > 0 ? static_cast<size_t>(count) : 0;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: GetEntryCount exception: %S", e.what());
        return 0;
    }
}

bool QuarantineManager::IsQuarantined(const std::string& hash) const {
    // SECURITY: must filter by Active state — historical bug returned true
    // for already-restored or already-deleted entries, which prevented us
    // from re-quarantining a recurring threat (the same hash had a stale
    // Restored row in the database).
    auto entry = GetEntryByHash(hash);
    return entry.has_value() && entry->state == QuarantineState::Active;
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
// REMEDIATION
// ============================================================================

std::vector<RemediationAction> QuarantineManager::RemediateArtifacts(uint64_t entryId) {
    std::vector<RemediationAction> actions;

    if (!IsInitialized()) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Not initialized");
        return actions;
    }

    try {
        auto entryOpt = GetEntry(entryId);
        if (!entryOpt) {
            SS_LOG_ERROR(L"QuarantineManager",
            L"QuarantineManager: Entry not found for remediation: %llu",
            static_cast<unsigned long long>(entryId));
            return actions;
        }

        auto& entry = *entryOpt;
        SS_LOG_INFO(L"QuarantineManager",
            L"QuarantineManager: Remediating artifacts for entry %llu",
            static_cast<unsigned long long>(entryId));

        // Remediate related registry keys if configured
        if (m_impl->m_config.cleanRegistry) {
            for (const auto& regKey : entry.remediationActions) {
                if (regKey.type == RemediationType::DeleteRegistryKey ||
                    regKey.type == RemediationType::DeleteRegistryValue)
                {
                    RemediationAction action{};
                    action.type = regKey.type;
                    action.target = regKey.target;
                    action.additionalTarget = regKey.additionalTarget;
                    action.timestamp = system_clock::now();

                    try {
                        if (regKey.type == RemediationType::DeleteRegistryKey) {
                            RegistryUtils::Error regErr{};
                            RegistryUtils::OpenOptions opts{};
                            opts.access = KEY_ALL_ACCESS;
                            action.success = RegistryUtils::DeleteKeyTree(
                                HKEY_LOCAL_MACHINE, regKey.target, opts, &regErr);
                            if (!action.success) {
                                action.errorMessage = regErr.message;
                            }
                        } else {
                            RegistryUtils::RegistryKey key;
                            RegistryUtils::Error regErr{};
                            RegistryUtils::OpenOptions opts{};
                            opts.access = KEY_QUERY_VALUE | KEY_SET_VALUE;
                            if (key.Open(HKEY_LOCAL_MACHINE, regKey.target,
                                         opts, &regErr))
                            {
                                // SECURITY: capture the original value's type
                                // and bytes BEFORE deletion so RollbackRemediation
                                // can faithfully restore it. Without this the
                                // rollback path is a no-op and any false-positive
                                // remediation is permanent.
                                HKEY rawKey = key.Handle();
                                DWORD valType = 0;
                                DWORD valSize = 0;
                                LSTATUS qstat = RegQueryValueExW(
                                    rawKey, regKey.additionalTarget.c_str(),
                                    nullptr, &valType, nullptr, &valSize);
                                // Hard cap to defeat hostile or pathological
                                // values that would force a huge allocation.
                                // Run-key strings are tiny; legitimate REG_BINARY
                                // values rarely exceed a few KiB. 1 MiB is
                                // generous and defensible.
                                constexpr DWORD kMaxRegValueBytes = 1u << 20;
                                if (qstat == ERROR_SUCCESS &&
                                    valSize <= kMaxRegValueBytes)
                                {
                                    action.originalValue.resize(
                                        sizeof(uint32_t) + static_cast<size_t>(valSize));
                                    const uint32_t typeLE = static_cast<uint32_t>(valType);
                                    std::memcpy(action.originalValue.data(), &typeLE,
                                                sizeof(typeLE));
                                    DWORD readSize = valSize;
                                    qstat = RegQueryValueExW(
                                        rawKey, regKey.additionalTarget.c_str(),
                                        nullptr, &valType,
                                        action.originalValue.data() + sizeof(uint32_t),
                                        &readSize);
                                    if (qstat != ERROR_SUCCESS) {
                                        // Capture failed — discard partial bytes
                                        // rather than risk a malformed rollback.
                                        action.originalValue.clear();
                                    }
                                }

                                action.success = key.DeleteValue(regKey.additionalTarget, &regErr);
                                if (!action.success) {
                                    action.errorMessage = regErr.message;
                                    action.originalValue.clear();
                                }
                            } else {
                                action.success = false;
                                action.errorMessage = regErr.message;
                            }
                        }
                    } catch (const std::exception& e) {
                        action.success = false;
                        action.errorMessage = StringUtils::ToWide(e.what());
                    }

                    actions.push_back(action);
                    m_impl->InvokeRemediationCallbacks(action);

                    SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Registry remediation %S: %ls", action.success ? "succeeded" : "failed", action.target.c_str());
                }
            }
        }

        m_impl->m_stats.remediationActions.fetch_add(actions.size(), std::memory_order_relaxed);
        SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Remediation complete - %zu actions for entry %llu", actions.size(), entryId);

        return actions;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: RemediateArtifacts exception: %S", e.what());
        return actions;
    }
}

bool QuarantineManager::RollbackRemediation(uint64_t entryId) {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Not initialized");
        return false;
    }

    try {
        auto entryOpt = GetEntry(entryId);
        if (!entryOpt) {
            SS_LOG_ERROR(L"QuarantineManager",
            L"QuarantineManager: Entry not found for rollback: %llu",
            static_cast<unsigned long long>(entryId));
            return false;
        }

        auto& entry = *entryOpt;
        bool allSuccess = true;

        SS_LOG_INFO(L"QuarantineManager",
            L"QuarantineManager: Rolling back remediation for entry %llu",
            static_cast<unsigned long long>(entryId));

        for (auto it = entry.remediationActions.rbegin();
             it != entry.remediationActions.rend(); ++it)
        {
            if (!it->success || it->originalValue.empty()) continue;

            try {
                if (it->type == RemediationType::DeleteRegistryValue &&
                    it->originalValue.size() >= sizeof(uint32_t))
                {
                    // Layout written in RemediateArtifacts:
                    //   [0..3]   uint32_t little-endian REG_* type
                    //   [4..N-1] raw value bytes
                    uint32_t typeLE = 0;
                    std::memcpy(&typeLE, it->originalValue.data(), sizeof(typeLE));
                    const DWORD valType = static_cast<DWORD>(typeLE);
                    const uint8_t* dataPtr =
                        it->originalValue.data() + sizeof(uint32_t);
                    const DWORD dataSize = static_cast<DWORD>(
                        it->originalValue.size() - sizeof(uint32_t));

                    RegistryUtils::RegistryKey key;
                    RegistryUtils::Error regErr{};
                    RegistryUtils::OpenOptions opts{};
                    opts.access = KEY_SET_VALUE;
                    if (key.Open(HKEY_LOCAL_MACHINE, it->target, opts, &regErr)) {
                        // Direct Win32 set is required to faithfully restore
                        // the captured REG_* type (RegistryUtils' typed
                        // writers would lose this fidelity for, e.g.,
                        // REG_EXPAND_SZ vs REG_SZ).
                        LSTATUS sstat = RegSetValueExW(
                            key.Handle(),
                            it->additionalTarget.c_str(),
                            0, valType, dataPtr, dataSize);
                        if (sstat == ERROR_SUCCESS) {
                            SS_LOG_INFO(L"QuarantineManager",
                                L"QuarantineManager: Rollback registry value: %ls\\%ls (type=%lu, size=%lu)",
                                it->target.c_str(), it->additionalTarget.c_str(),
                                static_cast<unsigned long>(valType),
                                static_cast<unsigned long>(dataSize));
                        } else {
                            SS_LOG_WARN(L"QuarantineManager",
                                L"QuarantineManager: RegSetValueExW failed (status=%ld) for %ls\\%ls",
                                static_cast<long>(sstat),
                                it->target.c_str(), it->additionalTarget.c_str());
                            allSuccess = false;
                        }
                    } else {
                        SS_LOG_WARN(L"QuarantineManager",
                            L"QuarantineManager: Cannot reopen registry key for rollback: %ls",
                            it->target.c_str());
                        allSuccess = false;
                    }
                }
                // Additional rollback types handled as implemented
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Rollback action failed: %S", e.what());
                allSuccess = false;
            }
        }

        SS_LOG_INFO(L"QuarantineManager",
            L"QuarantineManager: Rollback %S for entry %llu",
            allSuccess ? "complete" : "partial",
            static_cast<unsigned long long>(entryId));
        return allSuccess;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: RollbackRemediation exception: %S", e.what());
        return false;
    }
}

bool QuarantineManager::AddRemediationAction(
    uint64_t entryId,
    const RemediationAction& action
) {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Not initialized");
        return false;
    }

    try {
        auto entryOpt = GetEntry(entryId);
        if (!entryOpt) {
            SS_LOG_ERROR(L"QuarantineManager",
                L"QuarantineManager: Entry not found: %llu",
                static_cast<unsigned long long>(entryId));
            return false;
        }

        auto entry = *entryOpt;
        entry.remediationActions.push_back(action);

        if (!m_impl->m_database->UpdateEntry(ToDBEntry(entry))) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Failed to store remediation action in database");
            return false;
        }

        m_impl->UpdateCache(entry);
        SS_LOG_INFO(L"QuarantineManager",
            L"QuarantineManager: Added remediation action for entry %llu",
            static_cast<unsigned long long>(entryId));
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: AddRemediationAction exception: %S", e.what());
        return false;
    }
}

// ============================================================================
// FORENSICS
// ============================================================================

bool QuarantineManager::ExtractForAnalysis(
    uint64_t entryId,
    const std::wstring& destPath
) {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Not initialized");
        return false;
    }

    try {
        // Validate destination path
        if (!IsValidQuarantinePath(destPath)) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Invalid extraction destination path");
            return false;
        }

        auto entryOpt = GetEntry(entryId);
        if (!entryOpt) {
            SS_LOG_ERROR(L"QuarantineManager",
                L"QuarantineManager: Entry not found for extraction: %llu",
                static_cast<unsigned long long>(entryId));
            return false;
        }

        auto& entry = *entryOpt;

        // Restore logic: read quarantine file, decrypt, write to destPath
        RestoreRequest rr{};
        rr.entryId = entryId;
        rr.customPath = destPath;
        rr.verifyIntegrity = true;
        rr.overrideExisting = false;

        auto result = RestoreFile(rr);
        if (!result.IsSuccess()) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Extraction failed: %ls", result.message.c_str());
            return false;
        }

        SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: File extracted for analysis to: %ls", destPath.c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: ExtractForAnalysis exception: %S", e.what());
        return false;
    }
}

std::string QuarantineManager::SubmitSample(uint64_t entryId) {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Not initialized");
        return "";
    }

    try {
        if (!m_impl->m_config.enableSampleSubmission) {
            SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Sample submission is disabled");
            return "";
        }

        if (m_impl->m_config.submissionUrl.empty()) {
            SS_LOG_WARN(L"QuarantineManager", L"QuarantineManager: No submission URL configured");
            return "";
        }

        auto entryOpt = GetEntry(entryId);
        if (!entryOpt) {
            SS_LOG_ERROR(L"QuarantineManager",
                L"QuarantineManager: Entry not found for submission: %llu",
                static_cast<unsigned long long>(entryId));
            return "";
        }

        auto entry = *entryOpt;

        // Generate a submission ID from the entry hash and timestamp
        auto timestamp = system_clock::now().time_since_epoch().count();
        auto submissionId = std::format("SS-{}-{:016X}",
            entry.hashes.sha256.substr(0, 16), timestamp);

        entry.sampleSubmitted = true;
        entry.submissionId = submissionId;
        if (!m_impl->m_database->UpdateEntry(ToDBEntry(entry))) {
            SS_LOG_WARN(L"QuarantineManager",
                L"QuarantineManager: SubmitSample: failed to persist updated entry %llu",
                static_cast<unsigned long long>(entryId));
        }
        m_impl->UpdateCache(entry);

        m_impl->m_stats.samplesSubmitted.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_INFO(L"QuarantineManager",
            L"QuarantineManager: Sample queued for submission: %S (entry %llu)",
            submissionId.c_str(),
            static_cast<unsigned long long>(entryId));
        return submissionId;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: SubmitSample exception: %S", e.what());
        return "";
    }
}

std::wstring QuarantineManager::PreserveEvidence(uint64_t entryId) {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Not initialized");
        return L"";
    }

    try {
        if (!m_impl->m_config.enableForensics) {
            SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Forensics preservation is disabled");
            return L"";
        }

        auto entryOpt = GetEntry(entryId);
        if (!entryOpt) {
            SS_LOG_ERROR(L"QuarantineManager",
                L"QuarantineManager: Entry not found for evidence: %llu",
                static_cast<unsigned long long>(entryId));
            return L"";
        }

        auto entry = *entryOpt;

        // Create forensics directory if needed
        fs::path forensicsDir = m_impl->m_config.forensicsPath.empty()
            ? fs::path(m_impl->m_config.vaultPath) / QuarantineConstants::FORENSICS_FOLDER
            : fs::path(m_impl->m_config.forensicsPath);

        std::error_code ec;
        fs::create_directories(forensicsDir, ec);
        if (ec) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Failed to create forensics dir: %S", ec.message().c_str());
            return L"";
        }

        // Create evidence archive named by hash + timestamp
        auto timestamp = system_clock::now().time_since_epoch().count();
        auto archiveName = std::format(L"evidence_{}_{}",
            StringUtils::ToWide(entry.hashes.sha256.substr(0, 16)),
            timestamp);
        fs::path archivePath = forensicsDir / archiveName;
        fs::create_directories(archivePath, ec);

        // Copy quarantine file to forensics archive
        if (fs::exists(entry.quarantinePath, ec)) {
            fs::copy_file(entry.quarantinePath,
                archivePath / fs::path(entry.quarantinePath).filename(), ec);
            if (ec) {
                SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Evidence copy failed: %S", ec.message().c_str());
                return L"";
            }
        }

        // Update entry
        entry.evidencePreserved = true;
        entry.forensicsPath = archivePath.wstring();
        if (!m_impl->m_database->UpdateEntry(ToDBEntry(entry))) {
            SS_LOG_WARN(L"QuarantineManager",
                L"QuarantineManager: PreserveEvidence: failed to persist updated entry %llu",
                static_cast<unsigned long long>(entryId));
        }
        m_impl->UpdateCache(entry);

        SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Evidence preserved at: %ls", archivePath.wstring().c_str());
        return archivePath.wstring();

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: PreserveEvidence exception: %S", e.what());
        return L"";
    }
}

// ============================================================================
// EXPORT/IMPORT
// ============================================================================

bool QuarantineManager::ExportDatabase(const std::wstring& filePath) const {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Not initialized");
        return false;
    }

    try {
        if (!IsValidQuarantinePath(filePath)) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Invalid export path");
            return false;
        }

        auto entries = GetActiveEntries();

        std::ofstream outFile(filePath, std::ios::binary);
        if (!outFile) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Cannot create export file");
            return false;
        }

        // Write simple binary header: magic + version + entry count
        uint32_t magic = QuarantineConstants::QUARANTINE_MAGIC;
        uint16_t version = QuarantineConstants::QUARANTINE_VERSION;
        uint64_t count = entries.size();

        outFile.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
        outFile.write(reinterpret_cast<const char*>(&version), sizeof(version));
        outFile.write(reinterpret_cast<const char*>(&count), sizeof(count));

        for (const auto& entry : entries) {
            // Write entry ID
            outFile.write(reinterpret_cast<const char*>(&entry.entryId), sizeof(entry.entryId));

            // Write original path (length-prefixed)
            uint32_t pathLen = static_cast<uint32_t>(entry.originalPath.size());
            outFile.write(reinterpret_cast<const char*>(&pathLen), sizeof(pathLen));
            outFile.write(reinterpret_cast<const char*>(entry.originalPath.data()),
                         pathLen * sizeof(wchar_t));

            // Write SHA256 hash (length-prefixed)
            uint32_t hashLen = static_cast<uint32_t>(entry.hashes.sha256.size());
            outFile.write(reinterpret_cast<const char*>(&hashLen), sizeof(hashLen));
            outFile.write(entry.hashes.sha256.data(), hashLen);

            // Write threat name (length-prefixed)
            uint32_t threatLen = static_cast<uint32_t>(entry.threatName.size());
            outFile.write(reinterpret_cast<const char*>(&threatLen), sizeof(threatLen));
            outFile.write(reinterpret_cast<const char*>(entry.threatName.data()),
                         threatLen * sizeof(wchar_t));

            // Write state and timestamps
            uint8_t state = static_cast<uint8_t>(entry.state);
            outFile.write(reinterpret_cast<const char*>(&state), sizeof(state));
            outFile.write(reinterpret_cast<const char*>(&entry.originalSize), sizeof(entry.originalSize));
        }

        outFile.close();
        SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Exported %llu entries to: %ls", count, filePath.c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: ExportDatabase exception: %S", e.what());
        return false;
    }
}

size_t QuarantineManager::ImportDatabase(const std::wstring& filePath) {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Not initialized");
        return 0;
    }

    try {
        if (!IsValidQuarantinePath(filePath)) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Invalid import path");
            return 0;
        }

        std::ifstream inFile(filePath, std::ios::binary);
        if (!inFile) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Cannot open import file");
            return 0;
        }

        // Read and verify header
        uint32_t magic = 0;
        uint16_t version = 0;
        uint64_t count = 0;

        inFile.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        inFile.read(reinterpret_cast<char*>(&version), sizeof(version));
        inFile.read(reinterpret_cast<char*>(&count), sizeof(count));

        if (magic != QuarantineConstants::QUARANTINE_MAGIC) {
            SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Invalid import file format");
            return 0;
        }

        // Cap count to prevent memory exhaustion
        if (count > QuarantineConstants::MAX_QUARANTINE_ENTRIES) {
            SS_LOG_ERROR(L"QuarantineManager",
                L"QuarantineManager: Import count %llu exceeds max entries",
                static_cast<unsigned long long>(count));
            return 0;
        }

        size_t imported = 0;
        for (uint64_t i = 0; i < count; ++i) {
            try {
                QuarantineEntry entry{};

                inFile.read(reinterpret_cast<char*>(&entry.entryId), sizeof(entry.entryId));

                // Read original path
                uint32_t pathLen = 0;
                inFile.read(reinterpret_cast<char*>(&pathLen), sizeof(pathLen));
                if (pathLen > 32767) break; // sanity check
                entry.originalPath.resize(pathLen);
                inFile.read(reinterpret_cast<char*>(entry.originalPath.data()),
                           pathLen * sizeof(wchar_t));

                // Read SHA256
                uint32_t hashLen = 0;
                inFile.read(reinterpret_cast<char*>(&hashLen), sizeof(hashLen));
                if (hashLen > 128) break; // sanity check
                entry.hashes.sha256.resize(hashLen);
                inFile.read(entry.hashes.sha256.data(), hashLen);

                // Read threat name
                uint32_t threatLen = 0;
                inFile.read(reinterpret_cast<char*>(&threatLen), sizeof(threatLen));
                if (threatLen > 32767) break;
                entry.threatName.resize(threatLen);
                inFile.read(reinterpret_cast<char*>(entry.threatName.data()),
                           threatLen * sizeof(wchar_t));

                // Read state and size
                uint8_t state = 0;
                inFile.read(reinterpret_cast<char*>(&state), sizeof(state));
                entry.state = static_cast<QuarantineState>(state);
                inFile.read(reinterpret_cast<char*>(&entry.originalSize), sizeof(entry.originalSize));

                if (inFile.good()) {
                    auto dbEntry = ToDBEntry(entry);
                    if (m_impl->m_database->QuarantineFileDetailed(dbEntry, {}) >= 0) {
                        imported++;
                    }
                }
            } catch (...) {
                SS_LOG_WARN(L"QuarantineManager", L"QuarantineManager: Skipped corrupt import entry");
            }
        }

        SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Imported %llu of %llu entries from: %ls", imported, count, filePath.c_str());
        return imported;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: ImportDatabase exception: %S", e.what());
        return 0;
    }
}

// ============================================================================
// MAINTENANCE
// ============================================================================

void QuarantineManager::RunMaintenance() {
    if (!IsInitialized()) return;

    try {
        SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Running maintenance");

        // Delete expired entries
        if (m_impl->m_config.autoDeleteExpired) {
            DeleteExpiredEntries();
        }

        // Verify vault integrity
        VerifyVaultIntegrity();

        SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Maintenance complete");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: Maintenance exception: %S", e.what());
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
                SS_LOG_WARN(L"QuarantineManager", L"QuarantineManager: Quarantine file missing: %ls", entry.quarantinePath.c_str());
                corrupted++;
            }
        }

        SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Integrity check - %ls corrupted entries", corrupted);
        return corrupted;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: VerifyVaultIntegrity exception: %S", e.what());
        return 0;
    }
}

uint64_t QuarantineManager::CompactVault() {
    if (!IsInitialized()) return 0;

    try {
        SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Compacting vault");

        uint64_t reclaimed = 0;
        std::error_code ec;
        auto vaultPath = GetVaultPath();

        if (vaultPath.empty() || !fs::exists(vaultPath, ec)) {
            return 0;
        }

        // Snapshot tracked paths ONCE (the loop runs over O(n) directory
        // entries; the previous code re-queried the database for every file
        // and walked an O(n) vector inside the loop → O(n²) DB load on a
        // hot maintenance path). Build a hash set keyed by canonical wide
        // path so the inner check is O(1).
        std::unordered_set<std::wstring> trackedPaths;
        {
            auto entries = GetActiveEntries();
            trackedPaths.reserve(entries.size());
            for (const auto& entry : entries) {
                std::error_code canonEc;
                auto canon = fs::weakly_canonical(entry.quarantinePath, canonEc);
                trackedPaths.insert(
                    (canonEc ? fs::path(entry.quarantinePath) : canon).wstring());
            }
        }

        // Find orphaned .ssqf files not tracked in the database
        for (const auto& dirEntry : fs::directory_iterator(vaultPath, ec)) {
            if (!dirEntry.is_regular_file()) continue;

            auto ext = dirEntry.path().extension().wstring();
            if (ext != QuarantineConstants::QUARANTINE_EXTENSION) continue;

            std::error_code canonEc;
            auto canonPath = fs::weakly_canonical(dirEntry.path(), canonEc);
            const std::wstring key =
                (canonEc ? dirEntry.path() : canonPath).wstring();

            if (trackedPaths.find(key) != trackedPaths.end()) continue;

            auto fileSize = dirEntry.file_size(ec);
            if (!ec) {
                fs::remove(dirEntry.path(), ec);
                if (!ec) {
                    reclaimed += fileSize;
                    SS_LOG_INFO(L"QuarantineManager",
                        L"QuarantineManager: Removed orphaned file: %ls",
                        dirEntry.path().wstring().c_str());
                }
            }
        }

        if (reclaimed > 0) {
            m_impl->m_stats.currentVaultSize.fetch_sub(
                std::min(reclaimed, m_impl->m_stats.currentVaultSize.load(std::memory_order_relaxed)),
                std::memory_order_relaxed);
        }

        SS_LOG_INFO(L"QuarantineManager",
            L"QuarantineManager: Vault compaction complete - %llu bytes reclaimed",
            static_cast<unsigned long long>(reclaimed));
        return reclaimed;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: CompactVault exception: %S", e.what());
        return 0;
    }
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
    if (!m_impl) return 0;

    try {
        std::shared_lock lock(m_impl->m_configMutex);
        auto vaultPath = m_impl->m_config.vaultPath;

        if (vaultPath.empty()) return 0;

        std::error_code ec;
        auto spaceInfo = fs::space(vaultPath, ec);
        if (ec) {
            SS_LOG_WARN(L"QuarantineManager", L"QuarantineManager: Failed to query disk space: %S", ec.message().c_str());
            return 0;
        }

        uint64_t diskAvailable = spaceInfo.available;

        // If vault size limit is configured, cap available space
        if (m_impl->m_config.maxVaultSize > 0) {
            uint64_t currentUsed = m_impl->m_stats.currentVaultSize.load(std::memory_order_relaxed);
            uint64_t vaultAvailable = (currentUsed < m_impl->m_config.maxVaultSize)
                ? (m_impl->m_config.maxVaultSize - currentUsed)
                : 0;
            return std::min(diskAvailable, vaultAvailable);
        }

        return diskAvailable;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"QuarantineManager", L"QuarantineManager: GetAvailableSpace exception: %S", e.what());
        return 0;
    }
}

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t QuarantineManager::RegisterQuarantineCallback(QuarantineCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_quarantineCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"QuarantineManager", L"QuarantineManager: Registered quarantine callback %llu", id);
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

    SS_LOG_DEBUG(L"QuarantineManager", L"QuarantineManager: Registered restore callback %llu", id);
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

    SS_LOG_DEBUG(L"QuarantineManager", L"QuarantineManager: Registered remediation callback %llu", id);
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
    if (m_impl) return m_impl->m_stats;
    return QuarantineManagerStats{};
}

void QuarantineManager::ResetStats() {
    if (m_impl) {
        m_impl->m_stats.Reset();
        SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: Statistics reset");
    }
}

// ============================================================================
// EXTERNAL INTEGRATION
// ============================================================================

void QuarantineManager::SetQuarantineDB(Database::QuarantineDB* db) {
    // SECURITY: this transfers raw-pointer ownership into a unique_ptr.
    // The caller MUST relinquish ownership of `db`; we will free it on
    // shutdown. Passing the same pointer twice, or freeing it elsewhere,
    // is a use-after-free.
    if (!m_impl) return;
    if (db == nullptr) {
        SS_LOG_ERROR(L"QuarantineManager",
            L"QuarantineManager: SetQuarantineDB called with null database");
        return;
    }

    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_database.reset(db);

    SS_LOG_INFO(L"QuarantineManager", L"QuarantineManager: External database set");
}

} // namespace Engine
} // namespace Core
} // namespace ShadowStrike
