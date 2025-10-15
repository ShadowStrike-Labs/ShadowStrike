#include "QuarantineDB.hpp"
#include"../Utils/CompressionUtils.hpp"
#include"../Utils/HashUtils.hpp"
#include"../Utils/JSONUtils.hpp"
#include"../Utils/Base64Utils.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <fstream>

#ifdef _WIN32
#include <Windows.h>
#include <Lmcons.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace ShadowStrike {
    namespace Database {

        namespace {
            // Database schema version
            constexpr int QUARANTINE_SCHEMA_VERSION = 1;

            // SQL statements
            constexpr const char* SQL_CREATE_QUARANTINE_TABLE = R"(
                CREATE TABLE IF NOT EXISTS quarantine_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    quarantine_time TEXT NOT NULL,
                    last_access_time TEXT NOT NULL,
                    original_path TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    original_directory TEXT NOT NULL,
                    original_size INTEGER NOT NULL,
                    original_creation_time TEXT,
                    original_modification_time TEXT,
                    quarantine_path TEXT NOT NULL UNIQUE,
                    quarantine_filename TEXT NOT NULL,
                    quarantine_size INTEGER NOT NULL,
                    threat_type INTEGER NOT NULL,
                    severity INTEGER NOT NULL,
                    threat_name TEXT NOT NULL,
                    threat_signature TEXT,
                    scan_engine TEXT,
                    scan_engine_version TEXT,
                    md5_hash TEXT,
                    sha1_hash TEXT,
                    sha256_hash TEXT NOT NULL,
                    status INTEGER NOT NULL DEFAULT 0,
                    user_name TEXT,
                    machine_name TEXT,
                    process_id INTEGER,
                    process_name TEXT,
                    is_encrypted INTEGER NOT NULL DEFAULT 1,
                    encryption_method TEXT,
                    notes TEXT,
                    detection_reason TEXT,
                    restoration_time TEXT,
                    restored_by TEXT,
                    restoration_reason TEXT,
                    can_restore INTEGER NOT NULL DEFAULT 1,
                    can_delete INTEGER NOT NULL DEFAULT 1,
                    requires_password INTEGER NOT NULL DEFAULT 0
                );
            )";

            constexpr const char* SQL_CREATE_INDICES = R"(
                CREATE INDEX IF NOT EXISTS idx_quar_time ON quarantine_entries(quarantine_time DESC);
                CREATE INDEX IF NOT EXISTS idx_quar_status ON quarantine_entries(status);
                CREATE INDEX IF NOT EXISTS idx_quar_threat_type ON quarantine_entries(threat_type);
                CREATE INDEX IF NOT EXISTS idx_quar_severity ON quarantine_entries(severity);
                CREATE INDEX IF NOT EXISTS idx_quar_original_path ON quarantine_entries(original_path);
                CREATE INDEX IF NOT EXISTS idx_quar_sha256 ON quarantine_entries(sha256_hash);
                CREATE INDEX IF NOT EXISTS idx_quar_user ON quarantine_entries(user_name);
                CREATE INDEX IF NOT EXISTS idx_quar_composite ON quarantine_entries(status, threat_type, quarantine_time DESC);
            )";

            constexpr const char* SQL_CREATE_AUDIT_TABLE = R"(
                CREATE TABLE IF NOT EXISTS quarantine_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    entry_id INTEGER NOT NULL,
                    action INTEGER NOT NULL,
                    user_name TEXT,
                    machine_name TEXT,
                    details TEXT,
                    success INTEGER NOT NULL DEFAULT 1
                );
            )";

            constexpr const char* SQL_CREATE_METADATA_TABLE = R"(
                CREATE TABLE IF NOT EXISTS quarantine_metadata (
                    entry_id INTEGER NOT NULL,
                    metadata_key TEXT NOT NULL,
                    metadata_value TEXT,
                    PRIMARY KEY (entry_id, metadata_key),
                    FOREIGN KEY (entry_id) REFERENCES quarantine_entries(id) ON DELETE CASCADE
                ) WITHOUT ROWID;
            )";

            constexpr const char* SQL_INSERT_ENTRY = R"(
                INSERT INTO quarantine_entries (
                    quarantine_time, last_access_time, original_path, original_filename,
                    original_directory, original_size, original_creation_time, original_modification_time,
                    quarantine_path, quarantine_filename, quarantine_size,
                    threat_type, severity, threat_name, threat_signature,
                    scan_engine, scan_engine_version,
                    md5_hash, sha1_hash, sha256_hash,
                    status, user_name, machine_name, process_id, process_name,
                    is_encrypted, encryption_method, notes, detection_reason,
                    can_restore, can_delete, requires_password
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            )";

            constexpr const char* SQL_UPDATE_ENTRY = R"(
                UPDATE quarantine_entries SET
                    last_access_time = ?,
                    status = ?,
                    restoration_time = ?,
                    restored_by = ?,
                    restoration_reason = ?,
                    notes = ?
                WHERE id = ?
            )";

            constexpr const char* SQL_SELECT_ENTRY = R"(
                SELECT * FROM quarantine_entries WHERE id = ?
            )";

            constexpr const char* SQL_DELETE_ENTRY = R"(
                DELETE FROM quarantine_entries WHERE id = ?
            )";

            constexpr const char* SQL_COUNT_ALL = R"(
                SELECT COUNT(*) FROM quarantine_entries
            )";

            constexpr const char* SQL_GET_OLDEST = R"(
                SELECT quarantine_time FROM quarantine_entries ORDER BY quarantine_time ASC LIMIT 1
            )";

            constexpr const char* SQL_GET_NEWEST = R"(
                SELECT quarantine_time FROM quarantine_entries ORDER BY quarantine_time DESC LIMIT 1
            )";

            constexpr const char* SQL_INSERT_AUDIT = R"(
                INSERT INTO quarantine_audit_log (timestamp, entry_id, action, user_name, machine_name, details, success)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            )";

            // UTF-8 conversion helpers
            std::string ToUTF8(std::wstring_view wstr) {
                if (wstr.empty()) return std::string();
                
                int size = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), 
                    static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
                if (size == 0) return std::string();
                
                std::string result(size, '\0');
                WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), 
                    &result[0], size, nullptr, nullptr);
                return result;
            }

            std::wstring ToWide(std::string_view str) {
                if (str.empty()) return std::wstring();
                
                int size = MultiByteToWideChar(CP_UTF8, 0, str.data(), 
                    static_cast<int>(str.size()), nullptr, 0);
                if (size == 0) return std::wstring();
                
                std::wstring result(size, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), 
                    &result[0], size);
                return result;
            }

            // Get current system information
            std::wstring GetMachineName() {
                wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
                DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
                if (GetComputerNameW(buf, &size)) {
                    return std::wstring(buf);
                }
                return L"Unknown";
            }

            std::wstring GetCurrentUserName() {
                wchar_t buf[UNLEN + 1] = {};
                DWORD size = UNLEN + 1;
                if (::GetUserNameW(buf, &size)) {
                    return std::wstring(buf);
                }
                return L"Unknown";
            }

            // Hex conversion helper
            std::wstring ToHex(const std::vector<uint8_t>& data) {
                static const wchar_t* hexChars = L"0123456789abcdef";
                std::wstring result;
                result.reserve(data.size() * 2);
                for (uint8_t byte : data) {
                    result.push_back(hexChars[(byte >> 4) & 0xF]);
                    result.push_back(hexChars[byte & 0xF]);
                }
                return result;
            }

            std::vector<uint8_t> FromHex(std::wstring_view hex) {
                std::vector<uint8_t> result;
                result.reserve(hex.size() / 2);
                for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                    wchar_t high = hex[i];
                    wchar_t low = hex[i + 1];
                    
                    uint8_t highNibble = (high >= L'0' && high <= L'9') ? (high - L'0') :
                                        (high >= L'a' && high <= L'f') ? (high - L'a' + 10) :
                                        (high >= L'A' && high <= L'F') ? (high - L'A' + 10) : 0;
                    uint8_t lowNibble = (low >= L'0' && low <= L'9') ? (low - L'0') :
                                       (low >= L'a' && low <= L'f') ? (low - L'a' + 10) :
                                       (low >= L'A' && low <= L'F') ? (low - L'A' + 10) : 0;
                    
                    result.push_back((highNibble << 4) | lowNibble);
                }
                return result;
            }
        }

        // =========================================================================
        // QuarantineDB Implementation
        // ========================================================================

        QuarantineDB& QuarantineDB::Instance() {
            static QuarantineDB instance;
            return instance;
        }

        QuarantineDB::QuarantineDB() {
            m_machineName = GetMachineName();
            m_userName = GetCurrentUserName();
        }

        QuarantineDB::~QuarantineDB() {
            Shutdown();
        }

        bool QuarantineDB::Initialize(const Config& config, DatabaseError* err) {
            if (m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"QuarantineDB", L"Already initialized");
                return true;
            }

            SS_LOG_INFO(L"QuarantineDB", L"Initializing QuarantineDB...");

            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config = config;

            // Initialize DatabaseManager
            DatabaseConfig dbConfig;
            dbConfig.databasePath = m_config.dbPath;
            dbConfig.enableWAL = m_config.enableWAL;
            dbConfig.cacheSizeKB = m_config.dbCacheSizeKB;
            dbConfig.maxConnections = m_config.maxConnections;
            dbConfig.minConnections = 2;

            if (!DatabaseManager::Instance().Initialize(dbConfig, err)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to initialize DatabaseManager");
                return false;
            }

            // Create schema
            if (!createSchema(err)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to create schema");
                DatabaseManager::Instance().Shutdown();
                return false;
            }

            // Ensure quarantine directory exists
            if (!ensureQuarantineDirectory(err)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to create quarantine directory");
                return false;
            }

            // Generate master encryption key
            {
                std::lock_guard<std::mutex> keyLock(m_keyMutex);
                m_masterKey = deriveEncryptionKey();
            }

            // Start background cleanup thread if enabled
            if (m_config.enableAutoCleanup) {
                m_shutdownCleanup.store(false, std::memory_order_release);
                m_cleanupThread = std::thread(&QuarantineDB::backgroundCleanupThread, this);
            }

            // Initialize statistics
            recalculateStatistics(err);

            m_initialized.store(true, std::memory_order_release);

            SS_LOG_INFO(L"QuarantineDB", L"QuarantineDB initialized successfully");
            
            // Log initialization
            logAuditEvent(QuarantineAction::Quarantined, 0, L"QuarantineDB initialized");

            return true;
        }

        void QuarantineDB::Shutdown() {
            if (!m_initialized.load(std::memory_order_acquire)) {
                return;
            }

            SS_LOG_INFO(L"QuarantineDB", L"Shutting down QuarantineDB...");

            // Log shutdown
            logAuditEvent(QuarantineAction::Quarantined, 0, L"QuarantineDB shutting down");

            // Stop cleanup thread
            m_shutdownCleanup.store(true, std::memory_order_release);
            m_cleanupCV.notify_all();

            if (m_cleanupThread.joinable()) {
                m_cleanupThread.join();
            }

            // Clear encryption key from memory
            {
                std::lock_guard<std::mutex> lock(m_keyMutex);
                std::fill(m_masterKey.begin(), m_masterKey.end(), 0);
                m_masterKey.clear();
            }

            // Shutdown database manager
            DatabaseManager::Instance().Shutdown();

            m_initialized.store(false, std::memory_order_release);

            SS_LOG_INFO(L"QuarantineDB", L"QuarantineDB shut down");
        }

        // =========================================================================
        // Quarantine Operations
        // ========================================================================

       
            int64_t QuarantineDB::QuarantineFile(std::wstring_view originalPath,
                ThreatType threatType,
                ThreatSeverity severity,
                std::wstring_view threatName,
                std::wstring_view detectionReason,
                DatabaseError* err)
        {
            SS_LOG_INFO(L"QuarantineDB", L"Quarantining file: %ls", originalPath.data());

            // Read original file
            Utils::FileUtils::Error fileErr;
            std::vector<std::byte> fileData;

            if (!Utils::FileUtils::ReadAllBytes(originalPath, fileData, &fileErr)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to read original file";
                }
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to read file: %ls", originalPath.data());
                return -1;
            }

            // Create entry
            QuarantineEntry entry;
            entry.quarantineTime = std::chrono::system_clock::now();
            entry.lastAccessTime = entry.quarantineTime;
            entry.originalPath = originalPath;

            // Extract file information
            std::filesystem::path path(originalPath);
            entry.originalFileName = path.filename().wstring();
            entry.originalDirectory = path.parent_path().wstring();
            entry.originalSize = fileData.size();

            // Get file times
            Utils::FileUtils::FileStat stat;
            if (Utils::FileUtils::Stat(originalPath, stat, &fileErr)) {
                // Convert FILETIME to system_clock::time_point
                ULARGE_INTEGER uli;
                uli.LowPart = stat.creation.dwLowDateTime;
                uli.HighPart = stat.creation.dwHighDateTime;
                entry.originalCreationTime = std::chrono::system_clock::from_time_t(
                    (uli.QuadPart - 116444736000000000ULL) / 10000000ULL);

                uli.LowPart = stat.lastWrite.dwLowDateTime;
                uli.HighPart = stat.lastWrite.dwHighDateTime;
                entry.originalModificationTime = std::chrono::system_clock::from_time_t(
                    (uli.QuadPart - 116444736000000000ULL) / 10000000ULL);
            }

            // Set threat information
            entry.threatType = threatType;
            entry.severity = severity;
            entry.threatName = threatName;
            entry.detectionReason = detectionReason;
            entry.scanEngine = L"ShadowStrike";
            entry.scanEngineVersion = L"1.0.0";

            // Set system information
            entry.userName = m_userName;
            entry.machineName = m_machineName;
            entry.processId = GetCurrentProcessId();

            // Get process name
            wchar_t processPath[MAX_PATH];
            if (GetModuleFileNameW(nullptr, processPath, MAX_PATH) > 0) {
                std::filesystem::path pPath(processPath);
                entry.processName = pPath.filename().wstring();
            }

            // Calculate hashes
            // std::byte -> uint8_t dönüþümü açýk cast gerektirir; doðrudan iterator ctor çalýþmaz.
            std::vector<uint8_t> rawData;
            rawData.resize(fileData.size());
            std::transform(fileData.begin(), fileData.end(), rawData.begin(),
                [](std::byte b) { return static_cast<uint8_t>(b); });

            if (!calculateHashes(rawData, entry.md5Hash, entry.sha1Hash, entry.sha256Hash)) {
                SS_LOG_WARN(L"QuarantineDB", L"Failed to calculate file hashes");
            }

            // Set encryption info
            entry.isEncrypted = m_config.enableEncryption;
            entry.encryptionMethod = m_config.encryptionAlgorithm;

            entry.status = QuarantineStatus::Active;
            entry.canRestore = true;
            entry.canDelete = true;
            entry.requiresPasswordForRestore = m_config.requirePasswordForRestore;

            // Quarantine with full details
            return QuarantineFileDetailed(entry, rawData, err);
        }

        int64_t QuarantineDB::QuarantineFileDetailed(const QuarantineEntry& entry,
                                                     const std::vector<uint8_t>& fileData,
                                                     DatabaseError* err)
        {
            // Insert entry to get ID
            int64_t entryId = dbInsertEntry(entry, err);
            if (entryId < 0) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to insert quarantine entry");
                return -1;
            }

            // Generate quarantine path
            std::wstring quarantinePath = generateQuarantinePath(entryId);

            // Encrypt and store file
            if (!encryptAndStoreFile(fileData, quarantinePath, err)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to encrypt and store file");
                // Rollback: delete entry
                dbDeleteEntry(entryId, nullptr);
                return -1;
            }

            // Update entry with quarantine path and size
            QuarantineEntry updatedEntry = entry;
            updatedEntry.id = entryId;
            updatedEntry.quarantinePath = quarantinePath;
            updatedEntry.quarantineFileName = std::filesystem::path(quarantinePath).filename().wstring();
            
            // Get encrypted file size
            Utils::FileUtils::Error fileErr;
            Utils::FileUtils::FileStat fileStat;
            if (Utils::FileUtils::Stat(quarantinePath, fileStat, &fileErr)) {
                updatedEntry.quarantineSize = fileStat.size;
            } else {
                updatedEntry.quarantineSize = fileData.size();
            }

            if (!dbUpdateEntry(updatedEntry, err)) {
                SS_LOG_WARN(L"QuarantineDB", L"Failed to update entry with quarantine info");
            }

            // Log audit event
            logAuditEvent(QuarantineAction::Quarantined, entryId, 
                         L"File quarantined: " + entry.originalPath);

            // Update statistics
            updateStatistics(updatedEntry, QuarantineAction::Quarantined);

            SS_LOG_INFO(L"QuarantineDB", L"File quarantined successfully. Entry ID: %lld", entryId);
            return entryId;
        }

        bool QuarantineDB::RestoreFile(int64_t entryId,
                                       std::wstring_view restorePath,
                                       std::wstring_view restoredBy,
                                       std::wstring_view reason,
                                       DatabaseError* err)
        {
            SS_LOG_INFO(L"QuarantineDB", L"Restoring file from quarantine. Entry ID: %lld", entryId);

            // Get entry
            auto entryOpt = GetEntry(entryId, err);
            if (!entryOpt) {
                if (err) {
                    err->message = L"Entry not found";
                }
                return false;
            }

            QuarantineEntry entry = *entryOpt;

            // Check if restoration is allowed
            if (!entry.canRestore) {
                if (err) {
                    err->sqliteCode = SQLITE_AUTH;
                    err->message = L"Restoration not allowed for this entry";
                }
                SS_LOG_WARN(L"QuarantineDB", L"Restoration not allowed for entry: %lld", entryId);
                return false;
            }

            // Check status
            if (entry.status != QuarantineStatus::Active) {
                if (err) {
                    err->message = L"Entry is not in active state";
                }
                return false;
            }

            // Determine restore path
            std::wstring targetPath = restorePath.empty() ? entry.originalPath : std::wstring(restorePath);

            // Extract and decrypt file data
            std::vector<uint8_t> fileData;
            if (!decryptAndLoadFile(entry.quarantinePath, fileData, err)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to decrypt quarantined file");
                
                // Mark as corrupted
                entry.status = QuarantineStatus::Corrupted;
                dbUpdateEntry(entry, nullptr);
                
                logAuditEvent(QuarantineAction::Failed, entryId, L"Decryption failed during restoration");
                return false;
            }

            // Verify integrity
            std::wstring md5, sha1, sha256;
            if (m_config.enableIntegrityChecks) {
                if (!calculateHashes(fileData, md5, sha1, sha256)) {
                    SS_LOG_WARN(L"QuarantineDB", L"Failed to calculate hashes for verification");
                } else if (sha256 != entry.sha256Hash) {
                    if (err) {
                        err->sqliteCode = SQLITE_CORRUPT;
                        err->message = L"File integrity check failed";
                    }
                    SS_LOG_ERROR(L"QuarantineDB", L"File integrity check failed for entry: %lld", entryId);
                    
                    // Mark as corrupted
                    entry.status = QuarantineStatus::Corrupted;
                    dbUpdateEntry(entry, nullptr);
                    
                    logAuditEvent(QuarantineAction::Failed, entryId, L"Integrity check failed");
                    return false;
                }
            }

            // Create target directory if needed
            std::filesystem::path targetFilePath(targetPath);
            Utils::FileUtils::Error fileErr2;
            if (!Utils::FileUtils::CreateDirectories(targetFilePath.parent_path().wstring(), &fileErr2)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to create target directory";
                }
                return false;
            }

            // Write restored file
            if (!Utils::FileUtils::WriteAllBytesAtomic(targetPath, 
                reinterpret_cast<const std::byte*>(fileData.data()), 
                fileData.size(), &fileErr2)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to write restored file";
                }
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to write restored file");
                return false;
            }

            // Update entry status
            entry.status = QuarantineStatus::Restored;
            entry.restorationTime = std::chrono::system_clock::now();
            entry.restoredBy = restoredBy.empty() ? m_userName : std::wstring(restoredBy);
            entry.restorationReason = reason;
            entry.lastAccessTime = entry.restorationTime;

            if (!dbUpdateEntry(entry, err)) {
                SS_LOG_WARN(L"QuarantineDB", L"Failed to update entry after restoration");
            }

            // Log audit event
            std::wstring auditDetails = L"File restored to: " + targetPath;
            logAuditEvent(QuarantineAction::Restored, entryId, auditDetails);

            // Update statistics
            updateStatistics(entry, QuarantineAction::Restored);

            SS_LOG_INFO(L"QuarantineDB", L"File restored successfully. Entry ID: %lld", entryId);
            return true;
        }

        bool QuarantineDB::DeleteQuarantinedFile(int64_t entryId,
                                                std::wstring_view deletedBy,
                                                std::wstring_view reason,
                                                DatabaseError* err)
        {
            SS_LOG_INFO(L"QuarantineDB", L"Deleting quarantined file. Entry ID: %lld", entryId);

            // Get entry
            auto entryOpt = GetEntry(entryId, err);
            if (!entryOpt) {
                if (err) {
                    err->message = L"Entry not found";
                }
                return false;
            }

            QuarantineEntry entry = *entryOpt;

            // Check if deletion is allowed
            if (!entry.canDelete) {
                if (err) {
                    err->sqliteCode = SQLITE_AUTH;
                    err->message = L"Deletion not allowed for this entry";
                }
                SS_LOG_WARN(L"QuarantineDB", L"Deletion not allowed for entry: %lld", entryId);
                return false;
            }

            // Delete physical file
            Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::RemoveFile(entry.quarantinePath, &fileErr)) {
                SS_LOG_WARN(L"QuarantineDB", L"Failed to delete physical file: %ls", 
                           entry.quarantinePath.c_str());
                // Continue anyway to remove database entry
            }

            // Update entry status (mark as deleted instead of removing)
            entry.status = QuarantineStatus::Deleted;
            entry.lastAccessTime = std::chrono::system_clock::now();
            
            std::wstring deletedByUser = deletedBy.empty() ? m_userName : std::wstring(deletedBy);
            entry.notes += L"\nDeleted by: " + deletedByUser;
            if (!reason.empty()) {
                entry.notes += L"\nReason: " + std::wstring(reason);
            }

            if (!dbUpdateEntry(entry, err)) {
                SS_LOG_WARN(L"QuarantineDB", L"Failed to update entry after deletion");
            }

            // Log audit event
            std::wstring auditDetails = L"File deleted. Reason: " + std::wstring(reason);
            logAuditEvent(QuarantineAction::Deleted, entryId, auditDetails);

            // Update statistics
            updateStatistics(entry, QuarantineAction::Deleted);

            SS_LOG_INFO(L"QuarantineDB", L"Quarantined file deleted successfully. Entry ID: %lld", entryId);
            return true;
        }

        // =========================================================================
        // Batch Operations
        // ========================================================================

        bool QuarantineDB::QuarantineBatch(const std::vector<std::wstring>& filePaths,
                                          ThreatType threatType,
                                          ThreatSeverity severity,
                                          std::wstring_view threatName,
                                          DatabaseError* err)
        {
            if (filePaths.empty()) return true;

            SS_LOG_INFO(L"QuarantineDB", L"Batch quarantine: %zu files", filePaths.size());

            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);
            
            if (!trans || !trans->IsActive()) {
                return false;
            }

            size_t successCount = 0;
            for (const auto& path : filePaths) {
                if (QuarantineFile(path, threatType, severity, threatName, L"", err) > 0) {
                    successCount++;
                } else {
                    SS_LOG_WARN(L"QuarantineDB", L"Failed to quarantine file: %ls", path.c_str());
                }
            }

            if (!trans->Commit(err)) {
                return false;
            }

            SS_LOG_INFO(L"QuarantineDB", L"Batch quarantine completed: %zu/%zu successful", 
                       successCount, filePaths.size());
            return successCount > 0;
        }

        bool QuarantineDB::RestoreBatch(const std::vector<int64_t>& entryIds,
                                       std::wstring_view restoredBy,
                                       DatabaseError* err)
        {
            if (entryIds.empty()) return true;

            SS_LOG_INFO(L"QuarantineDB", L"Batch restore: %zu entries", entryIds.size());

            size_t successCount = 0;
            for (int64_t id : entryIds) {
                if (RestoreFile(id, L"", restoredBy, L"Batch restoration", err)) {
                    successCount++;
                } else {
                    SS_LOG_WARN(L"QuarantineDB", L"Failed to restore entry: %lld", id);
                }
            }

            SS_LOG_INFO(L"QuarantineDB", L"Batch restore completed: %zu/%zu successful", 
                       successCount, entryIds.size());
            return successCount > 0;
        }

        bool QuarantineDB::DeleteBatch(const std::vector<int64_t>& entryIds,
                                      std::wstring_view deletedBy,
                                      DatabaseError* err)
        {
            if (entryIds.empty()) return true;

            SS_LOG_INFO(L"QuarantineDB", L"Batch delete: %zu entries", entryIds.size());

            size_t successCount = 0;
            for (int64_t id : entryIds) {
                if (DeleteQuarantinedFile(id, deletedBy, L"Batch deletion", err)) {
                    successCount++;
                } else {
                    SS_LOG_WARN(L"QuarantineDB", L"Failed to delete entry: %lld", id);
                }
            }

            SS_LOG_INFO(L"QuarantineDB", L"Batch delete completed: %zu/%zu successful", 
                       successCount, entryIds.size());
            return successCount > 0;
        }

        // =========================================================================
        // Query Operations (NEW)
        // ========================================================================

        std::optional<QuarantineDB::QuarantineEntry> QuarantineDB::GetEntry(int64_t id, DatabaseError* err) {
            return dbSelectEntry(id, err);
        }

        std::vector<QuarantineDB::QuarantineEntry> QuarantineDB::Query(const QueryFilter& filter,
                                                                       DatabaseError* err)
        {
            std::vector<std::string> params;
            std::string sql = buildQuerySQL(filter, params);

            return dbSelectEntries(sql, params, err);
        }

        std::vector<QuarantineDB::QuarantineEntry> QuarantineDB::GetByThreatType(ThreatType type,
                                                                                 size_t maxCount,
                                                                                 DatabaseError* err)
        {
            QueryFilter filter;
            filter.threatType = type;
            filter.maxResults = maxCount;
            filter.sortDescending = true;

            return Query(filter, err);
        }

        std::vector<QuarantineDB::QuarantineEntry> QuarantineDB::GetBySeverity(ThreatSeverity severity,
                                                                               size_t maxCount,
                                                                               DatabaseError* err)
        {
            QueryFilter filter;
            filter.minSeverity = severity;
            filter.maxSeverity = severity;
            filter.maxResults = maxCount;
            filter.sortDescending = true;

            return Query(filter, err);
        }

        std::vector<QuarantineDB::QuarantineEntry> QuarantineDB::GetByStatus(QuarantineStatus status,
                                                                             size_t maxCount,
                                                                             DatabaseError* err)
        {
            QueryFilter filter;
            filter.status = status;
            filter.maxResults = maxCount;
            filter.sortDescending = true;

            return Query(filter, err);
        }

        std::vector<QuarantineDB::QuarantineEntry> QuarantineDB::GetActiveEntries(size_t maxCount,
                                                                                  DatabaseError* err)
        {
            return GetByStatus(QuarantineStatus::Active, maxCount, err);
        }

        std::vector<QuarantineDB::QuarantineEntry> QuarantineDB::GetRecent(size_t count,
                                                                           DatabaseError* err)
        {
            QueryFilter filter;
            filter.maxResults = count;
            filter.sortDescending = true;

            return Query(filter, err);
        }

        std::vector<QuarantineDB::QuarantineEntry> QuarantineDB::SearchByHash(std::wstring_view hash,
                                                                              DatabaseError* err)
        {
            QueryFilter filter;
            filter.fileHashPattern = hash;
            filter.maxResults = 100;

            return Query(filter, err);
        }

        std::vector<QuarantineDB::QuarantineEntry> QuarantineDB::SearchByFileName(std::wstring_view fileName,
                                                                                  size_t maxCount,
                                                                                  DatabaseError* err)
        {
            QueryFilter filter;
            std::wstring pattern = L"%";
            pattern += fileName;
            pattern += L"%";
            filter.originalPathPattern = pattern;
            filter.maxResults = maxCount;

            return Query(filter, err);
        }

        int64_t QuarantineDB::CountEntries(const QueryFilter* filter, DatabaseError* err) {
            std::vector<std::string> params;
            std::string sql;
            
            if (filter) {
                sql = buildCountSQL(*filter, params);
            } else {
                sql = SQL_COUNT_ALL;
            }

            auto result = DatabaseManager::Instance().Query(sql, err);
            
            if (result.Next()) {
                return result.GetInt64(0);
            }

            return -1;
        }

        // =========================================================================
        // File Operations (implementation continues...)
        // ========================================================================

        bool QuarantineDB::ExtractFileData(int64_t entryId,
                                          std::vector<uint8_t>& outData,
                                          DatabaseError* err)
        {
            auto entryOpt = GetEntry(entryId, err);
            if (!entryOpt) {
                return false;
            }

            return decryptAndLoadFile(entryOpt->quarantinePath, outData, err);
        }

        bool QuarantineDB::GetFileHash(int64_t entryId,
                                      std::wstring& md5,
                                      std::wstring& sha1,
                                      std::wstring& sha256,
                                      DatabaseError* err)
        {
            auto entryOpt = GetEntry(entryId, err);
            if (!entryOpt) {
                return false;
            }

            md5 = entryOpt->md5Hash;
            sha1 = entryOpt->sha1Hash;
            sha256 = entryOpt->sha256Hash;

            return true;
        }

        bool QuarantineDB::VerifyIntegrity(int64_t entryId, DatabaseError* err) {
            SS_LOG_DEBUG(L"QuarantineDB", L"Verifying integrity for entry: %lld", entryId);

            auto entryOpt = GetEntry(entryId, err);
            if (!entryOpt) {
                return false;
            }

            QuarantineEntry& entry = *entryOpt;

            // Extract file data
            std::vector<uint8_t> fileData;
            if (!decryptAndLoadFile(entry.quarantinePath, fileData, err)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to decrypt file for integrity check");
                
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.integrityChecksFailed++;
                
                return false;
            }

            // Calculate current hashes
            std::wstring md5, sha1, sha256;
            if (!calculateHashes(fileData, md5, sha1, sha256)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to calculate hashes for integrity check");
                return false;
            }

            // Verify
            bool isValid = (sha256 == entry.sha256Hash);

            if (isValid) {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.integrityChecksPassed++;
                SS_LOG_DEBUG(L"QuarantineDB", L"Integrity check passed for entry: %lld", entryId);
            } else {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.integrityChecksFailed++;
                SS_LOG_ERROR(L"QuarantineDB", L"Integrity check FAILED for entry: %lld", entryId);
                
                // Mark as corrupted
                entry.status = QuarantineStatus::Corrupted;
                dbUpdateEntry(entry, nullptr);
            }

            return isValid;
        }

        bool QuarantineDB::UpdateEntry(const QuarantineEntry& entry, DatabaseError* err) {
            return dbUpdateEntry(entry, err);
        }

        bool QuarantineDB::AddNotes(int64_t entryId,
                                   std::wstring_view notes,
                                   DatabaseError* err)
        {
            auto entryOpt = GetEntry(entryId, err);
            if (!entryOpt) {
                return false;
            }

            QuarantineEntry entry = *entryOpt;
            if (!entry.notes.empty()) {
                entry.notes += L"\n";
            }
            entry.notes += notes;
            entry.lastAccessTime = std::chrono::system_clock::now();

            return dbUpdateEntry(entry, err);
        }

        

        // =========================================================================
        // Internal Helper Implementations
        // ========================================================================

        bool QuarantineDB::createSchema(DatabaseError* err) {
            // Create main table
            if (!DatabaseManager::Instance().Execute(SQL_CREATE_QUARANTINE_TABLE, err)) {
                return false;
            }

            // Create indices
            if (!DatabaseManager::Instance().Execute(SQL_CREATE_INDICES, err)) {
                return false;
            }

            // Create audit log table
            if (!DatabaseManager::Instance().Execute(SQL_CREATE_AUDIT_TABLE, err)) {
                return false;
            }

            // Create metadata table
            if (!DatabaseManager::Instance().Execute(SQL_CREATE_METADATA_TABLE, err)) {
                return false;
            }

            SS_LOG_INFO(L"QuarantineDB", L"Schema created successfully");
            return true;
        }

        // =========================================================================
        // Remaining Critical Implementations
        // ============================================================================

        bool QuarantineDB::upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err) {
            // Future schema migrations
            return true;
        }

        int64_t QuarantineDB::dbInsertEntry(const QuarantineEntry& entry, DatabaseError* err) {
            std::string quarantineTime = timePointToString(entry.quarantineTime);
            std::string lastAccessTime = timePointToString(entry.lastAccessTime);
            std::string originalCreationTime = timePointToString(entry.originalCreationTime);
            std::string originalModificationTime = timePointToString(entry.originalModificationTime);

            // Note: quarantine_path and quarantine_filename will be updated later
            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_INSERT_ENTRY,
                err,
                quarantineTime,
                lastAccessTime,
                ToUTF8(entry.originalPath),
                ToUTF8(entry.originalFileName),
                ToUTF8(entry.originalDirectory),
                static_cast<int64_t>(entry.originalSize),
                originalCreationTime,
                originalModificationTime,
                ToUTF8(entry.quarantinePath.empty() ? L"pending" : entry.quarantinePath),
                ToUTF8(entry.quarantineFileName.empty() ? L"pending" : entry.quarantineFileName),
                static_cast<int64_t>(entry.quarantineSize),
                static_cast<int>(entry.threatType),
                static_cast<int>(entry.severity),
                ToUTF8(entry.threatName),
                ToUTF8(entry.threatSignature),
                ToUTF8(entry.scanEngine),
                ToUTF8(entry.scanEngineVersion),
                ToUTF8(entry.md5Hash),
                ToUTF8(entry.sha1Hash),
                ToUTF8(entry.sha256Hash),
                static_cast<int>(entry.status),
                ToUTF8(entry.userName),
                ToUTF8(entry.machineName),
                static_cast<int>(entry.processId),
                ToUTF8(entry.processName),
                entry.isEncrypted ? 1 : 0,
                ToUTF8(entry.encryptionMethod),
                ToUTF8(entry.notes),
                ToUTF8(entry.detectionReason),
                entry.canRestore ? 1 : 0,
                entry.canDelete ? 1 : 0,
                entry.requiresPasswordForRestore ? 1 : 0
            );

            if (success) {
                int64_t id = DatabaseManager::Instance().LastInsertRowId();
                
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalQuarantines++;
                
                return id;
            }

            return -1;
        }

        bool QuarantineDB::dbUpdateEntry(const QuarantineEntry& entry, DatabaseError* err) {
            if (entry.id <= 0) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Invalid entry ID for update";
                }
                return false;
            }

            std::string lastAccessTime = timePointToString(entry.lastAccessTime);
            std::string restorationTime = entry.status == QuarantineStatus::Restored ?
                timePointToString(entry.restorationTime) : "";

            return DatabaseManager::Instance().ExecuteWithParams(
                SQL_UPDATE_ENTRY,
                err,
                lastAccessTime,
                static_cast<int>(entry.status),
                restorationTime,
                ToUTF8(entry.restoredBy),
                ToUTF8(entry.restorationReason),
                ToUTF8(entry.notes),
                entry.id
            );
        }

        bool QuarantineDB::dbDeleteEntry(int64_t id, DatabaseError* err) {
            if (id <= 0) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Invalid entry ID for deletion";
                }
                return false;
            }

            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_DELETE_ENTRY, err, id);

            if (success) {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalDeletions++;
            }

            return success;
        }

        std::optional<QuarantineDB::QuarantineEntry> QuarantineDB::dbSelectEntry(int64_t id, DatabaseError* err) {
            auto result = DatabaseManager::Instance().QueryWithParams(
                SQL_SELECT_ENTRY, err, id);

            if (result.Next()) {
                return rowToQuarantineEntry(result);
            }

            return std::nullopt;
        }

        std::vector<QuarantineDB::QuarantineEntry> QuarantineDB::dbSelectEntries(
            std::string_view sql,
            const std::vector<std::string>& params,
            DatabaseError* err)
        {
            std::vector<QuarantineEntry> entries;

            auto result = DatabaseManager::Instance().Query(sql, err);

            while (result.Next()) {
                entries.push_back(rowToQuarantineEntry(result));
            }

            return entries;
        }

        std::string QuarantineDB::buildQuerySQL(const QueryFilter& filter, std::vector<std::string>& outParams) {
            std::ostringstream sql;
            sql << "SELECT * FROM quarantine_entries WHERE 1=1";

            if (filter.threatType) {
                sql << " AND threat_type = ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.threatType)));
            }

            if (filter.minSeverity) {
                sql << " AND severity >= ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.minSeverity)));
            }

            if (filter.maxSeverity) {
                sql << " AND severity <= ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.maxSeverity)));
            }

            if (filter.status) {
                sql << " AND status = ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.status)));
            }

            if (filter.startTime) {
                sql << " AND quarantine_time >= ?";
                outParams.push_back(timePointToString(*filter.startTime));
            }

            if (filter.endTime) {
                sql << " AND quarantine_time <= ?";
                outParams.push_back(timePointToString(*filter.endTime));
            }

            if (filter.originalPathPattern) {
                sql << " AND original_path LIKE ?";
                outParams.push_back(ToUTF8(*filter.originalPathPattern));
            }

            if (filter.threatNamePattern) {
                sql << " AND threat_name LIKE ?";
                outParams.push_back(ToUTF8(*filter.threatNamePattern));
            }

            if (filter.fileHashPattern) {
                sql << " AND (md5_hash LIKE ? OR sha1_hash LIKE ? OR sha256_hash LIKE ?)";
                std::string hashPattern = ToUTF8(*filter.fileHashPattern);
                outParams.push_back(hashPattern);
                outParams.push_back(hashPattern);
                outParams.push_back(hashPattern);
            }

            if (filter.userNamePattern) {
                sql << " AND user_name LIKE ?";
                outParams.push_back(ToUTF8(*filter.userNamePattern));
            }

            if (filter.machineNamePattern) {
                sql << " AND machine_name LIKE ?";
                outParams.push_back(ToUTF8(*filter.machineNamePattern));
            }

            // Order and limit
            if (filter.sortDescending) {
                sql << " ORDER BY quarantine_time DESC";
            } else {
                sql << " ORDER BY quarantine_time ASC";
            }

            sql << " LIMIT " << filter.maxResults;

            return sql.str();
        }

        std::string QuarantineDB::buildCountSQL(const QueryFilter& filter, std::vector<std::string>& outParams) {
            std::ostringstream sql;
            sql << "SELECT COUNT(*) FROM quarantine_entries WHERE 1=1";

            // Apply same filters as buildQuerySQL (simplified version)
            if (filter.threatType) {
                sql << " AND threat_type = ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.threatType)));
            }

            if (filter.status) {
                sql << " AND status = ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.status)));
            }

            return sql.str();
        }

        QuarantineDB::QuarantineEntry QuarantineDB::rowToQuarantineEntry(QueryResult& result) {
            QuarantineEntry entry;
            
            entry.id = result.GetInt64(0);
            entry.quarantineTime = stringToTimePoint(result.GetString(1));
            entry.lastAccessTime = stringToTimePoint(result.GetString(2));
            entry.originalPath = ToWide(result.GetString(3));
            entry.originalFileName = ToWide(result.GetString(4));
            entry.originalDirectory = ToWide(result.GetString(5));
            entry.originalSize = result.GetInt64(6);
            entry.originalCreationTime = stringToTimePoint(result.GetString(7));
            entry.originalModificationTime = stringToTimePoint(result.GetString(8));
            entry.quarantinePath = ToWide(result.GetString(9));
            entry.quarantineFileName = ToWide(result.GetString(10));
            entry.quarantineSize = result.GetInt64(11);
            entry.threatType = static_cast<ThreatType>(result.GetInt(12));
            entry.severity = static_cast<ThreatSeverity>(result.GetInt(13));
            entry.threatName = ToWide(result.GetString(14));
            entry.threatSignature = ToWide(result.GetString(15));
            entry.scanEngine = ToWide(result.GetString(16));
            entry.scanEngineVersion = ToWide(result.GetString(17));
            entry.md5Hash = ToWide(result.GetString(18));
            entry.sha1Hash = ToWide(result.GetString(19));
            entry.sha256Hash = ToWide(result.GetString(20));
            entry.status = static_cast<QuarantineStatus>(result.GetInt(21));
            entry.userName = ToWide(result.GetString(22));
            entry.machineName = ToWide(result.GetString(23));
            entry.processId = result.GetInt(24);
            entry.processName = ToWide(result.GetString(25));
            entry.isEncrypted = result.GetInt(26) != 0;
            entry.encryptionMethod = ToWide(result.GetString(27));
            entry.notes = ToWide(result.GetString(28));
            entry.detectionReason = ToWide(result.GetString(29));
            
            if (!result.IsNull(30)) {
                entry.restorationTime = stringToTimePoint(result.GetString(30));
            }
            entry.restoredBy = ToWide(result.GetString(31));
            entry.restorationReason = ToWide(result.GetString(32));
            entry.canRestore = result.GetInt(33) != 0;
            entry.canDelete = result.GetInt(34) != 0;
            entry.requiresPasswordForRestore = result.GetInt(35) != 0;

            return entry;
        }

        std::string QuarantineDB::timePointToString(std::chrono::system_clock::time_point tp) {
            auto time_t = std::chrono::system_clock::to_time_t(tp);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                tp.time_since_epoch()) % 1000;

            std::tm tm;
            gmtime_s(&tm, &time_t);

            std::ostringstream oss;
            oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
            oss << '.' << std::setfill('0') << std::setw(3) << ms.count();

            return oss.str();
        }

        std::chrono::system_clock::time_point QuarantineDB::stringToTimePoint(std::string_view str) {
            if (str.empty()) {
                return std::chrono::system_clock::time_point{};
            }

            std::tm tm = {};
            int year, month, day, hour, minute, second;
            if (sscanf_s(str.data(), "%d-%d-%d %d:%d:%d", 
                        &year, &month, &day, &hour, &minute, &second) != 6) {
                return std::chrono::system_clock::time_point{};
            }

            tm.tm_year = year - 1900;
            tm.tm_mon = month - 1;
            tm.tm_mday = day;
            tm.tm_hour = hour;
            tm.tm_min = minute;
            tm.tm_sec = second;

            auto tp = std::chrono::system_clock::from_time_t(_mkgmtime(&tm));

            // Parse milliseconds if present
            auto dotPos = str.find('.');
            if (dotPos != std::string_view::npos && dotPos + 1 < str.size()) {
                try {
                    int ms = std::stoi(std::string(str.substr(dotPos + 1, 3)));
                    tp += std::chrono::milliseconds(ms);
                }
                catch (...) {
                    // Ignore
                }
            }

            return tp;
        }

        // ============================================================================
        // Encryption & Hashing Implementations
        // ============================================================================

        bool QuarantineDB::encryptAndStoreFile(const std::vector<uint8_t>& fileData,
                                              std::wstring_view quarantinePath,
                                              DatabaseError* err)
        {
            std::vector<uint8_t> dataToStore = fileData;

            // Compress if enabled
            if (m_config.enableCompression) {
                std::vector<uint8_t> compressedData;
                if (compressData(fileData, compressedData)) {
                    dataToStore = std::move(compressedData);
                    SS_LOG_DEBUG(L"QuarantineDB", L"File compressed: %zu -> %zu bytes", 
                               fileData.size(), dataToStore.size());
                }
            }

            // Encrypt if enabled
            if (m_config.enableEncryption) {
                // Simple XOR encryption for demonstration
                // In production, use proper AES-256-GCM via BCrypt API
                std::lock_guard<std::mutex> lock(m_keyMutex);
                for (size_t i = 0; i < dataToStore.size(); ++i) {
                    dataToStore[i] ^= m_masterKey[i % m_masterKey.size()];
                }
            }

            // Write to file
            Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::WriteAllBytesAtomic(quarantinePath,
                reinterpret_cast<const std::byte*>(dataToStore.data()),
                dataToStore.size(), &fileErr)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to write quarantine file";
                }
                return false;
            }

            return true;
        }

        
            bool QuarantineDB::decryptAndLoadFile(std::wstring_view quarantinePath,
                std::vector<uint8_t>& outData,
                DatabaseError* err)
        {
            // Read encrypted file
            Utils::FileUtils::Error fileErr;
            std::vector<std::byte> encryptedData;

            if (!Utils::FileUtils::ReadAllBytes(quarantinePath, encryptedData, &fileErr)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to read quarantine file";
                }
                return false;
            }

            // Explicitly convert std::byte -> uint8_t (iterator ctor fails because conversion is explicit)
            std::vector<uint8_t> data;
            data.resize(encryptedData.size());
            std::transform(encryptedData.begin(), encryptedData.end(), data.begin(),
                [](std::byte b) { return static_cast<uint8_t>(b); });

            // Decrypt if encrypted
            if (m_config.enableEncryption) {
                std::lock_guard<std::mutex> lock(m_keyMutex);
                for (size_t i = 0; i < data.size(); ++i) {
                    data[i] ^= m_masterKey[i % m_masterKey.size()];
                }
            }

            // Decompress if needed
            if (m_config.enableCompression) {
                std::vector<uint8_t> decompressedData;
                if (decompressData(data, decompressedData)) {
                    outData = std::move(decompressedData);
                    return true;
                }
            }

            outData = std::move(data);
            return true;
        }

        bool QuarantineDB::compressData(const std::vector<uint8_t>& input,
                                       std::vector<uint8_t>& output)
        {
            // Quick check: nothing to do for empty input
            output.clear();
            if (input.empty()) return true;

            using namespace ShadowStrike::Utils::CompressionUtils;

            // check API availability
            if (!IsCompressionApiAvailable()) {
                SS_LOG_WARN(L"QuarantineDB", L"Windows Compression API not available");
                return false;
            }

            Compressor compressor;
            if (!compressor.open(Algorithm::Xpress)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to open compressor (Algorithm::Xpress)");
                return false;
            }

            const void* src = static_cast<const void*>(input.data());
            size_t size = input.size(); // byte count (uint8_t => 1 byte)

            bool ok = compressor.compress(src, size, output);
            if (!ok) {
                SS_LOG_ERROR(L"QuarantineDB", L"Compression failed");
                compressor.close();
                return false;
            }

            compressor.close();
            return true;
        }

        bool QuarantineDB::decompressData(const std::vector<uint8_t>& input,
                                         std::vector<uint8_t>& output)
        {
            output.clear();
            if (input.empty()) return true;

            using namespace ShadowStrike::Utils::CompressionUtils;

            if (!IsCompressionApiAvailable()) {
                SS_LOG_WARN(L"QuarantineDB", L"Windows Compression API not available");
                return false;
            }

            Decompressor decompressor;
            if (!decompressor.open(Algorithm::Xpress)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to open decompressor (Algorithm::Xpress)");
                return false;
            }

            const void* src = static_cast<const void*>(input.data());
            size_t size = input.size();

            // If you know the expected uncompressed size (e.g. from DB), pass it here to avoid decompression bombs.
            size_t expectedUncompressedSize = 0; // 0 = unknown
            bool ok = decompressor.decompress(src, size, output, expectedUncompressedSize);
            if (!ok) {
                SS_LOG_ERROR(L"QuarantineDB", L"Decompression failed");
                decompressor.close();
                return false;
            }

            decompressor.close();
            return true;
        }

        bool QuarantineDB::calculateHashes(const std::vector<uint8_t>& data,
                                          std::wstring& md5,
                                          std::wstring& sha1,
                                          std::wstring& sha256)
        {
            md5 = calculateMD5(data);
            sha1 = calculateSHA1(data);
            sha256 = calculateSHA256(data);

            return !sha256.empty();
        }

        std::wstring QuarantineDB::calculateMD5(const std::vector<uint8_t>& data) {
           
            if (data.empty()) return std::wstring();
            
            std::string hex;
            ShadowStrike::Utils::HashUtils::Error Herr{};
                
            if (!ShadowStrike::Utils::HashUtils::ComputeHex(ShadowStrike::Utils::HashUtils::Algorithm::MD5, data.data(), data.size(), hex,/*upper*/false, &Herr)) {
                SS_LOG_ERROR(L"QuarantineDB", L"calculateMD5: ComputeHex failed (nt=0x%08X, win32=%lu)", Herr.ntstatus, Herr.win32);
                return std::wstring();
            }

            return ToWide(hex);
        }

        std::wstring QuarantineDB::calculateSHA1(const std::vector<uint8_t>& data) {
           
            if (data.empty()) return std::wstring();

            std::string hex;
            ShadowStrike::Utils::HashUtils::Error Herr{};

            if (!ShadowStrike::Utils::HashUtils::ComputeHex(ShadowStrike::Utils::HashUtils::Algorithm::SHA1, data.data(), data.size(), hex,/*upper*/false, &Herr)) {
                SS_LOG_ERROR(L"QuarantineDB", L"calculateSHA1: ComputeHex failed (nt=0x%08X, win32=%lu)", Herr.ntstatus, Herr.win32);
                return std::wstring();
            }

            return ToWide(hex);
        }

        std::wstring QuarantineDB::calculateSHA256(const std::vector<uint8_t>& data) {
            
            if (data.empty()) return std::wstring();

            std::string hex;
            ShadowStrike::Utils::HashUtils::Error Herr{};

            if (!ShadowStrike::Utils::HashUtils::ComputeHex(ShadowStrike::Utils::HashUtils::Algorithm::SHA256, data.data(), data.size(), hex,/*upper*/false, &Herr)) {
                SS_LOG_ERROR(L"QuarantineDB", L"calculateSHA256: ComputeHex failed (nt=0x%08X, win32=%lu)", Herr.ntstatus, Herr.win32);
                return std::wstring();
            }

            return ToWide(hex);
        }

        // =========================================================================
        // Background Cleanup Implementation
        // ========================================================================

        void QuarantineDB::backgroundCleanupThread() {
            SS_LOG_INFO(L"QuarantineDB", L"Background cleanup thread started");

            while (!m_shutdownCleanup.load(std::memory_order_acquire)) {
                std::unique_lock<std::mutex> lock(m_cleanupMutex);

                m_cleanupCV.wait_for(lock, std::chrono::hours(1), [this]() {
                    return m_shutdownCleanup.load(std::memory_order_acquire);
                });

                if (m_shutdownCleanup.load(std::memory_order_acquire)) {
                    break;
                }

                // Perform cleanup
                DatabaseError err;
                cleanupOldEntries(&err);
                cleanupCorruptedEntries(&err);
            }

            SS_LOG_INFO(L"QuarantineDB", L"Background cleanup thread stopped");
        }

        bool QuarantineDB::cleanupOldEntries(DatabaseError* err) {
            auto cutoffTime = std::chrono::system_clock::now() - m_config.maxRetentionDays;
            
            QueryFilter filter;
            filter.endTime = cutoffTime;
            filter.status = QuarantineStatus::Active;
            filter.maxResults = 1000;

            auto entries = Query(filter, err);
            
            for (const auto& entry : entries) {
                DeleteQuarantinedFile(entry.id, L"System", L"Automatic cleanup - retention expired", nullptr);
            }

            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.lastCleanup = std::chrono::system_clock::now();
            m_stats.cleanupCount++;

            SS_LOG_INFO(L"QuarantineDB", L"Cleanup: removed %zu expired entries", entries.size());
            return true;
        }

        bool QuarantineDB::cleanupCorruptedEntries(DatabaseError* err) {
            auto entries = GetByStatus(QuarantineStatus::Corrupted, 100, err);
            
            for (const auto& entry : entries) {
                dbDeleteEntry(entry.id, nullptr);
            }

            return true;
        }

        std::wstring QuarantineDB::generateQuarantinePath(int64_t entryId) {
            std::wostringstream oss;
            oss << m_config.quarantineBasePath;
            if (!m_config.quarantineBasePath.empty() && 
                m_config.quarantineBasePath.back() != L'\\') {
                oss << L"\\";
            }
            oss << L"quar_" << std::setfill(L'0') << std::setw(10) << entryId << L".dat";
            return oss.str();
        }

        bool QuarantineDB::ensureQuarantineDirectory(DatabaseError* err) {
            Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::CreateDirectories(m_config.quarantineBasePath, &fileErr)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to create quarantine directory";
                }
                return false;
            }
            return true;
        }

        std::vector<uint8_t> QuarantineDB::deriveEncryptionKey() {
            // Generate a simple key (in production, use proper key derivation)
            std::vector<uint8_t> key(32);
            for (size_t i = 0; i < key.size(); ++i) {
                key[i] = static_cast<uint8_t>((i * 7 + 13) ^ 0xAA);
            }
            return key;
        }

        std::vector<uint8_t> QuarantineDB::generateSalt() {
            std::vector<uint8_t> salt(16);
            // In production, use cryptographically secure random
            for (size_t i = 0; i < salt.size(); ++i) {
                salt[i] = static_cast<uint8_t>(rand() % 256);
            }
            return salt;
        }

        void QuarantineDB::updateStatistics(const QuarantineEntry& entry, QuarantineAction action) {
            std::lock_guard<std::mutex> lock(m_statsMutex);

            m_stats.totalEntries++;
            
            switch (action) {
                case QuarantineAction::Quarantined:
                    m_stats.activeEntries++;
                    m_stats.entriesByType[static_cast<size_t>(entry.threatType)]++;
                    m_stats.entriesBySeverity[static_cast<size_t>(entry.severity)]++;
                    m_stats.totalQuarantineSize += entry.originalSize;
                    break;
                case QuarantineAction::Restored:
                    if (m_stats.activeEntries > 0) m_stats.activeEntries--;
                    m_stats.restoredEntries++;
                    m_stats.totalRestorations++;
                    break;
                case QuarantineAction::Deleted:
                    if (m_stats.activeEntries > 0) m_stats.activeEntries--;
                    m_stats.deletedEntries++;
                    m_stats.totalDeletions++;
                    break;
                default:
                    break;
            }

            m_stats.entriesByStatus[static_cast<size_t>(entry.status)]++;

            if (m_stats.oldestEntry == std::chrono::system_clock::time_point{} ||
                entry.quarantineTime < m_stats.oldestEntry) {
                m_stats.oldestEntry = entry.quarantineTime;
            }

            if (entry.quarantineTime > m_stats.newestEntry) {
                m_stats.newestEntry = entry.quarantineTime;
            }
        }

        void QuarantineDB::recalculateStatistics(DatabaseError* err) {
            std::lock_guard<std::mutex> lock(m_statsMutex);

            m_stats = Statistics{};

            auto result = DatabaseManager::Instance().Query(SQL_COUNT_ALL, err);
            if (result.Next()) {
                m_stats.totalEntries = result.GetInt64(0);
            }

            // Get oldest
            result = DatabaseManager::Instance().Query(SQL_GET_OLDEST, err);
            if (result.Next()) {
                m_stats.oldestEntry = stringToTimePoint(result.GetString(0));
            }

            // Get newest
            result = DatabaseManager::Instance().Query(SQL_GET_NEWEST, err);
            if (result.Next()) {
                m_stats.newestEntry = stringToTimePoint(result.GetString(0));
            }
        }

        void QuarantineDB::logAuditEvent(QuarantineAction action,
                                        int64_t entryId,
                                        std::wstring_view details)
        {
            if (!m_config.enableAuditLog) {
                return;
            }

            std::string timestamp = timePointToString(std::chrono::system_clock::now());

            DatabaseManager::Instance().ExecuteWithParams(
                SQL_INSERT_AUDIT,
                nullptr,
                timestamp,
                entryId,
                static_cast<int>(action),
                ToUTF8(m_userName),
                ToUTF8(m_machineName),
                ToUTF8(details),
                1  // success
            );
        }

        // ============================================================================
        // Utility String Conversions
        // ============================================================================

        std::wstring QuarantineDB::ThreatTypeToString(ThreatType type) {
            switch (type) {
                case ThreatType::Virus: return L"Virus";
                case ThreatType::Trojan: return L"Trojan";
                case ThreatType::Worm: return L"Worm";
                case ThreatType::Ransomware: return L"Ransomware";
                case ThreatType::Spyware: return L"Spyware";
                case ThreatType::Adware: return L"Adware";
                case ThreatType::Rootkit: return L"Rootkit";
                case ThreatType::Backdoor: return L"Backdoor";
                case ThreatType::PUA: return L"PUA";
                case ThreatType::Exploit: return L"Exploit";
                case ThreatType::Script: return L"Script";
                case ThreatType::Macro: return L"Macro";
                case ThreatType::Phishing: return L"Phishing";
                case ThreatType::Suspicious: return L"Suspicious";
                case ThreatType::Custom: return L"Custom";
                default: return L"Unknown";
            }
        }

        QuarantineDB::ThreatType QuarantineDB::StringToThreatType(std::wstring_view str) {
            if (str == L"Virus") return ThreatType::Virus;
            if (str == L"Trojan") return ThreatType::Trojan;
            if (str == L"Worm") return ThreatType::Worm;
            if (str == L"Ransomware") return ThreatType::Ransomware;
            if (str == L"Spyware") return ThreatType::Spyware;
            if (str == L"Adware") return ThreatType::Adware;
            if (str == L"Rootkit") return ThreatType::Rootkit;
            if (str == L"Backdoor") return ThreatType::Backdoor;
            if (str == L"PUA") return ThreatType::PUA;
            if (str == L"Exploit") return ThreatType::Exploit;
            if (str == L"Script") return ThreatType::Script;
            if (str == L"Macro") return ThreatType::Macro;
            if (str == L"Phishing") return ThreatType::Phishing;
            if (str == L"Suspicious") return ThreatType::Suspicious;
            if (str == L"Custom") return ThreatType::Custom;
            return ThreatType::Unknown;
        }

        std::wstring QuarantineDB::ThreatSeverityToString(ThreatSeverity severity) {
            switch (severity) {
                case ThreatSeverity::Info: return L"Info";
                case ThreatSeverity::Low: return L"Low";
                case ThreatSeverity::Medium: return L"Medium";
                case ThreatSeverity::High: return L"High";
                case ThreatSeverity::Critical: return L"Critical";
                default: return L"Unknown";
            }
        }

        QuarantineDB::ThreatSeverity QuarantineDB::StringToThreatSeverity(std::wstring_view str) {
            if (str == L"Info") return ThreatSeverity::Info;
            if (str == L"Low") return ThreatSeverity::Low;
            if (str == L"Medium") return ThreatSeverity::Medium;
            if (str == L"High") return ThreatSeverity::High;
            if (str == L"Critical") return ThreatSeverity::Critical;
            return ThreatSeverity::Medium;
        }

        std::wstring QuarantineDB::QuarantineStatusToString(QuarantineStatus status) {
            switch (status) {
                case QuarantineStatus::Active: return L"Active";
                case QuarantineStatus::Restored: return L"Restored";
                case QuarantineStatus::Deleted: return L"Deleted";
                case QuarantineStatus::Expired: return L"Expired";
                case QuarantineStatus::Corrupted: return L"Corrupted";
                case QuarantineStatus::Pending: return L"Pending";
                default: return L"Unknown";
            }
        }

        QuarantineDB::QuarantineStatus QuarantineDB::StringToQuarantineStatus(std::wstring_view str) {
            if (str == L"Active") return QuarantineStatus::Active;
            if (str == L"Restored") return QuarantineStatus::Restored;
            if (str == L"Deleted") return QuarantineStatus::Deleted;
            if (str == L"Expired") return QuarantineStatus::Expired;
            if (str == L"Corrupted") return QuarantineStatus::Corrupted;
            if (str == L"Pending") return QuarantineStatus::Pending;
            return QuarantineStatus::Active;
        }

        std::wstring QuarantineDB::QuarantineActionToString(QuarantineAction action) {
            switch (action) {
                case QuarantineAction::Quarantined: return L"Quarantined";
                case QuarantineAction::Restored: return L"Restored";
                case QuarantineAction::Deleted: return L"Deleted";
                case QuarantineAction::Submitted: return L"Submitted";
                case QuarantineAction::Whitelisted: return L"Whitelisted";
                case QuarantineAction::Failed: return L"Failed";
                default: return L"Unknown";
            }
        }

        // Remaining simple functions (GetStatistics, GetConfig, etc.)
        QuarantineDB::Statistics QuarantineDB::GetStatistics(DatabaseError* err) {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            return m_stats;
        }

        void QuarantineDB::ResetStatistics() {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats = Statistics{};
        }

        QuarantineDB::Config QuarantineDB::GetConfig() const {
            std::shared_lock<std::shared_mutex> lock(m_configMutex);
            return m_config;
        }

        void QuarantineDB::SetMaxRetentionDays(std::chrono::hours days) {
            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config.maxRetentionDays = days;
        }

        void QuarantineDB::SetMaxQuarantineSize(size_t sizeBytes) {
            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config.maxQuarantineSize = sizeBytes;
        }

        bool QuarantineDB::Vacuum(DatabaseError* err) {
            SS_LOG_INFO(L"QuarantineDB", L"Running VACUUM...");
            return DatabaseManager::Instance().Vacuum(err);
        }

        bool QuarantineDB::CheckIntegrity(DatabaseError* err) {
            SS_LOG_INFO(L"QuarantineDB", L"Checking integrity...");
            std::vector<std::wstring> issues;
            return DatabaseManager::Instance().CheckIntegrity(issues, err);
        }

        bool QuarantineDB::Optimize(DatabaseError* err) {
            SS_LOG_INFO(L"QuarantineDB", L"Optimizing database...");
            return DatabaseManager::Instance().Optimize(err);
        }

        bool QuarantineDB::RebuildIndices(DatabaseError* err) {
            SS_LOG_INFO(L"QuarantineDB", L"Rebuilding indices...");
            return DatabaseManager::Instance().Execute(SQL_CREATE_INDICES, err);
        }

        
        bool QuarantineDB::CleanupExpired(DatabaseError* err) {
            return cleanupOldEntries(err);
        }

        bool QuarantineDB::CleanupBySize(size_t targetSize, DatabaseError* err) {
            SS_LOG_INFO(L"QuarantineDB", L"Running size-based cleanup. Target size: %zu bytes", targetSize);

            std::lock_guard<std::mutex> lock(m_statsMutex);

            // Check current size
            if (m_stats.totalQuarantineSize <= targetSize) {
                SS_LOG_INFO(L"QuarantineDB", L"Current size (%zu) is already below target", 
                           m_stats.totalQuarantineSize);
                return true;
            }

            // Get all active entries sorted by age (oldest first)
            QueryFilter filter;
            filter.status = QuarantineStatus::Active;
            filter.sortDescending = false;  // oldest first
            filter.maxResults = 10000;

            auto entries = Query(filter, err);
            if (entries.empty()) {
                return true;
            }

            size_t currentSize = m_stats.totalQuarantineSize;
            size_t deletedCount = 0;

            // Delete oldest entries until we reach target
            for (const auto& entry : entries) {
                if (currentSize <= targetSize) {
                    break;
                }

                if (DeleteQuarantinedFile(entry.id, L"System", L"Automatic cleanup - size limit", nullptr)) {
                    currentSize -= entry.originalSize;
                    deletedCount++;
                }
            }

            SS_LOG_INFO(L"QuarantineDB", L"Cleanup completed. Deleted %zu entries. New size: %zu bytes", 
                       deletedCount, currentSize);

            m_stats.cleanupCount++;
            m_stats.lastCleanup = std::chrono::system_clock::now();

            return true;
        }

        bool QuarantineDB::DeleteAll(bool confirmed, DatabaseError* err) {
            if (!confirmed) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Deletion not confirmed. Set confirmed=true to proceed.";
                }
                SS_LOG_WARN(L"QuarantineDB", L"DeleteAll called without confirmation");
                return false;
            }

            SS_LOG_WARN(L"QuarantineDB", L"Deleting ALL quarantine entries - DESTRUCTIVE OPERATION");

            // Get all entries
            auto entries = GetActiveEntries(100000, err);

            // Delete physical files first
            size_t deletedFiles = 0;
            for (const auto& entry : entries) {
                Utils::FileUtils::Error fileErr;
                if (Utils::FileUtils::RemoveFile(entry.quarantinePath, &fileErr)) {
                    deletedFiles++;
                }
            }

            // Delete from database
            if (!DatabaseManager::Instance().Execute("DELETE FROM quarantine_entries", err)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to delete entries from database");
                return false;
            }

            // Also clean up audit log
            DatabaseManager::Instance().Execute("DELETE FROM quarantine_audit_log", nullptr);
            DatabaseManager::Instance().Execute("DELETE FROM quarantine_metadata", nullptr);

            // Reset statistics
            ResetStatistics();

            // Log audit event
            logAuditEvent(QuarantineAction::Deleted, 0, 
                         L"All quarantine entries deleted. Physical files: " + std::to_wstring(deletedFiles));

            SS_LOG_INFO(L"QuarantineDB", L"DeleteAll completed. Removed %zu files and all database entries", 
                       deletedFiles);

            return true;
        }

        bool QuarantineDB::ExportEntry(int64_t entryId, std::wstring_view exportPath,
            bool includeMetadata, DatabaseError* err)
        {
            SS_LOG_INFO(L"QuarantineDB", L"Exporting quarantine entry %lld to: %ls", entryId, exportPath.data());

            // Get entry
            auto entryOpt = GetEntry(entryId, err);
            if (!entryOpt) {
                if (err && err->message.empty()) {
                    err->message = L"Entry not found";
                }
                return false;
            }

            const QuarantineEntry& entry = *entryOpt;

            // Extract file data
            std::vector<uint8_t> fileData;
            if (!ExtractFileData(entryId, fileData, err)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to extract file data for export");
                return false;
            }

            // Create export package using JSON format
            using namespace ShadowStrike::Utils::JSON;
            Json exportPackage;

            // File metadata
            exportPackage["format_version"] = "1.0";
            exportPackage["export_time"] = timePointToString(std::chrono::system_clock::now());
            exportPackage["entry_id"] = entry.id;

            // Original file info
            exportPackage["original"]["path"] = ToUTF8(entry.originalPath);
            exportPackage["original"]["filename"] = ToUTF8(entry.originalFileName);
            exportPackage["original"]["directory"] = ToUTF8(entry.originalDirectory);
            exportPackage["original"]["size"] = entry.originalSize;
            exportPackage["original"]["creation_time"] = timePointToString(entry.originalCreationTime);
            exportPackage["original"]["modification_time"] = timePointToString(entry.originalModificationTime);

            // Threat info
            exportPackage["threat"]["type"] = ToUTF8(ThreatTypeToString(entry.threatType));
            exportPackage["threat"]["severity"] = ToUTF8(ThreatSeverityToString(entry.severity));
            exportPackage["threat"]["name"] = ToUTF8(entry.threatName);
            exportPackage["threat"]["signature"] = ToUTF8(entry.threatSignature);
            exportPackage["threat"]["detection_reason"] = ToUTF8(entry.detectionReason);

            // Scan info
            exportPackage["scan"]["engine"] = ToUTF8(entry.scanEngine);
            exportPackage["scan"]["engine_version"] = ToUTF8(entry.scanEngineVersion);

            // Hashes
            exportPackage["hashes"]["md5"] = ToUTF8(entry.md5Hash);
            exportPackage["hashes"]["sha1"] = ToUTF8(entry.sha1Hash);
            exportPackage["hashes"]["sha256"] = ToUTF8(entry.sha256Hash);

            // System info
            exportPackage["system"]["user_name"] = ToUTF8(entry.userName);
            exportPackage["system"]["machine_name"] = ToUTF8(entry.machineName);
            exportPackage["system"]["process_id"] = entry.processId;
            exportPackage["system"]["process_name"] = ToUTF8(entry.processName);

            // Quarantine info
            exportPackage["quarantine"]["time"] = timePointToString(entry.quarantineTime);
            exportPackage["quarantine"]["status"] = ToUTF8(QuarantineStatusToString(entry.status));
            exportPackage["quarantine"]["notes"] = ToUTF8(entry.notes);

            // Encode file data as Base64
            std::string base64Data;
            Utils::Base64EncodeOptions b64opts;
            if (!Utils::Base64Encode(fileData.data(), fileData.size(), base64Data, b64opts)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to encode file data";
                }
                return false;
            }
            exportPackage["file_data"] = base64Data;

            // Write to file
            std::filesystem::path exportFilePath(exportPath);
            
            // Create export directory if needed
            Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::CreateDirectories(exportFilePath.parent_path().wstring(), &fileErr)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to create export directory";
                }
                return false;
            }

            // Save JSON
            Error jsonErr;
            SaveOptions saveOpts;
            saveOpts.pretty = true;
            saveOpts.indentSpaces = 2;
            saveOpts.atomicReplace = true;

            if (!SaveToFile(exportFilePath, exportPackage, &jsonErr, saveOpts)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to save export file: " + ToWide(jsonErr.message);
                }
                return false;
            }

            // Log audit event
            logAuditEvent(QuarantineAction::Submitted, entryId, 
                         L"Entry exported to: " + std::wstring(exportPath));

            SS_LOG_INFO(L"QuarantineDB", L"Entry exported successfully: %lld", entryId);
            return true;
        }

        int64_t QuarantineDB::ImportEntry(std::wstring_view importPath, DatabaseError* err) {
            SS_LOG_INFO(L"QuarantineDB", L"Importing quarantine entry from: %ls", importPath.data());

            // Load JSON file
            using namespace ShadowStrike::Utils::JSON;
            Json importPackage;
            Error jsonErr;
            ParseOptions parseOpts;

            if (!LoadFromFile(std::filesystem::path(importPath), importPackage, &jsonErr, parseOpts)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to load import file: " + ToWide(jsonErr.message);
                }
                return -1;
            }

            // Validate format
            if (!importPackage.contains("format_version") || !importPackage.contains("file_data")) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Invalid import file format";
                }
                return -1;
            }

            // Parse entry data
            QuarantineEntry entry;

            // Original file info
            entry.originalPath = ToWide(importPackage["original"]["path"].get<std::string>());
            entry.originalFileName = ToWide(importPackage["original"]["filename"].get<std::string>());
            entry.originalDirectory = ToWide(importPackage["original"]["directory"].get<std::string>());
            entry.originalSize = importPackage["original"]["size"].get<uint64_t>();
            entry.originalCreationTime = stringToTimePoint(importPackage["original"]["creation_time"].get<std::string>());
            entry.originalModificationTime = stringToTimePoint(importPackage["original"]["modification_time"].get<std::string>());

            // Threat info
            entry.threatType = StringToThreatType(ToWide(importPackage["threat"]["type"].get<std::string>()));
            entry.severity = StringToThreatSeverity(ToWide(importPackage["threat"]["severity"].get<std::string>()));
            entry.threatName = ToWide(importPackage["threat"]["name"].get<std::string>());
            entry.threatSignature = ToWide(importPackage["threat"]["signature"].get<std::string>());
            entry.detectionReason = ToWide(importPackage["threat"]["detection_reason"].get<std::string>());

            // Scan info
            entry.scanEngine = ToWide(importPackage["scan"]["engine"].get<std::string>());
            entry.scanEngineVersion = ToWide(importPackage["scan"]["engine_version"].get<std::string>());

            // Hashes
            entry.md5Hash = ToWide(importPackage["hashes"]["md5"].get<std::string>());
            entry.sha1Hash = ToWide(importPackage["hashes"]["sha1"].get<std::string>());
            entry.sha256Hash = ToWide(importPackage["hashes"]["sha256"].get<std::string>());

            // System info
            entry.userName = ToWide(importPackage["system"]["user_name"].get<std::string>());
            entry.machineName = ToWide(importPackage["system"]["machine_name"].get<std::string>());
            entry.processId = importPackage["system"]["process_id"].get<uint32_t>();
            entry.processName = ToWide(importPackage["system"]["process_name"].get<std::string>());

            // Quarantine info
            entry.quarantineTime = std::chrono::system_clock::now(); // Use current time for import
            entry.lastAccessTime = entry.quarantineTime;
            entry.status = QuarantineStatus::Active;
            entry.notes = ToWide(importPackage["quarantine"]["notes"].get<std::string>());
            entry.notes += L"\n[Imported from: " + std::wstring(importPath) + L"]";

            // Decode file data from Base64
            std::string base64Data = importPackage["file_data"].get<std::string>();
            std::vector<uint8_t> fileData;
            Utils::Base64DecodeError decErr = Utils::Base64DecodeError::None;
            Utils::Base64DecodeOptions b64opts;
            if (!Utils::Base64Decode(base64Data, fileData, decErr, b64opts)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to decode file data";
                }
                return -1;
            }

            // Verify hashes
            std::wstring md5, sha1, sha256;
            if (!calculateHashes(fileData, md5, sha1, sha256)) {
                SS_LOG_WARN(L"QuarantineDB", L"Failed to calculate hashes for imported file");
            } else if (sha256 != entry.sha256Hash) {
                if (err) {
                    err->sqliteCode = SQLITE_CORRUPT;
                    err->message = L"File integrity check failed - hash mismatch";
                }
                SS_LOG_ERROR(L"QuarantineDB", L"Imported file hash mismatch");
                return -1;
            }

            // Set encryption info
            entry.isEncrypted = m_config.enableEncryption;
            entry.encryptionMethod = m_config.encryptionAlgorithm;
            entry.canRestore = true;
            entry.canDelete = true;

            // Import the file
            int64_t entryId = QuarantineFileDetailed(entry, fileData, err);

            if (entryId > 0) {
                logAuditEvent(QuarantineAction::Quarantined, entryId, 
                             L"Entry imported from: " + std::wstring(importPath));
                SS_LOG_INFO(L"QuarantineDB", L"Entry imported successfully. ID: %lld", entryId);
            }

            return entryId;
        }

        bool QuarantineDB::SubmitForAnalysis(int64_t entryId, std::wstring_view submissionEndpoint,
            DatabaseError* err)
        {
            SS_LOG_INFO(L"QuarantineDB", L"Submitting entry %lld for analysis to: %ls", 
                       entryId, submissionEndpoint.data());

            // Get entry
            auto entryOpt = GetEntry(entryId, err);
            if (!entryOpt) {
                return false;
            }

            QuarantineEntry entry = *entryOpt;

            // Export to temporary file
            std::wstring tempPath = m_config.quarantineBasePath + L"\\temp_submit_" + 
                                   std::to_wstring(entryId) + L".json";

            if (!ExportEntry(entryId, tempPath, true, err)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to export entry for submission");
                return false;
            }

            // Update entry status
            entry.status = QuarantineStatus::Pending;
            std::wstring timestampStr = ToWide(timePointToString(std::chrono::system_clock::now()));
            entry.notes += L"\n[Submitted for analysis at: " + timestampStr + L"]";
            entry.lastAccessTime = std::chrono::system_clock::now();

            if (!dbUpdateEntry(entry, err)) {
                SS_LOG_WARN(L"QuarantineDB", L"Failed to update entry status after submission");
            }

            // Log audit event
            logAuditEvent(QuarantineAction::Submitted, entryId, 
                         L"Submitted to: " + std::wstring(submissionEndpoint));

            // Clean up temp file
            Utils::FileUtils::Error fileErr;
            Utils::FileUtils::RemoveFile(tempPath, &fileErr);

            SS_LOG_INFO(L"QuarantineDB", L"Entry submitted successfully: %lld", entryId);

            // NOTE: Actual HTTP/network submission would be implemented here
            // For production, integrate with your cloud analysis platform
            return true;
        }

        std::wstring QuarantineDB::GenerateReport(const QueryFilter* filter) {
            SS_LOG_INFO(L"QuarantineDB", L"Generating quarantine report");

            std::wostringstream report;

            // Header
            report << L"==============================================\n";
            report << L"     SHADOWSTRIKE QUARANTINE REPORT\n";
            report << L"==============================================\n\n";

            // Generation time
            auto now = std::chrono::system_clock::now();
            report << L"Generated: " << ToWide(timePointToString(now)) << L"\n";
            report << L"System: " << m_machineName << L"\n";
            report << L"User: " << m_userName << L"\n\n";

            // Statistics
            Statistics stats = GetStatistics(nullptr);

            report << L"----------------------------------------------\n";
            report << L"SUMMARY STATISTICS\n";
            report << L"----------------------------------------------\n";
            report << L"Total Entries: " << stats.totalEntries << L"\n";
            report << L"Active Entries: " << stats.activeEntries << L"\n";
            report << L"Restored Entries: " << stats.restoredEntries << L"\n";
            report << L"Deleted Entries: " << stats.deletedEntries << L"\n";
            report << L"Total Quarantines: " << stats.totalQuarantines << L"\n";
            report << L"Total Restorations: " << stats.totalRestorations << L"\n";
            report << L"Total Deletions: " << stats.totalDeletions << L"\n";
            report << L"Failed Operations: " << stats.failedOperations << L"\n\n";

            report << L"Total Quarantine Size: " << (stats.totalQuarantineSize / 1024.0 / 1024.0) << L" MB\n";
            report << L"Average File Size: " << (stats.averageFileSize / 1024.0) << L" KB\n";
            report << L"Largest File Size: " << (stats.largestFileSize / 1024.0 / 1024.0) << L" MB\n\n";

            report << L"Integrity Checks Passed: " << stats.integrityChecksPassed << L"\n";
            report << L"Integrity Checks Failed: " << stats.integrityChecksFailed << L"\n\n";

            // Threat breakdown
            report << L"----------------------------------------------\n";
            report << L"THREAT TYPE BREAKDOWN\n";
            report << L"----------------------------------------------\n";
            for (int i = 0; i < 256; i++) {
                if (stats.entriesByType[i] > 0) {
                    ThreatType type = static_cast<ThreatType>(i);
                    report << ThreatTypeToString(type) << L": " << stats.entriesByType[i] << L"\n";
                }
            }
            report << L"\n";

            // Severity breakdown
            report << L"----------------------------------------------\n";
            report << L"SEVERITY BREAKDOWN\n";
            report << L"----------------------------------------------\n";
            for (int i = 0; i < 5; i++) {
                if (stats.entriesBySeverity[i] > 0) {
                    ThreatSeverity sev = static_cast<ThreatSeverity>(i);
                    report << ThreatSeverityToString(sev) << L": " << stats.entriesBySeverity[i] << L"\n";
                }
            }
            report << L"\n";

            // Recent entries
            auto entries = filter ? Query(*filter, nullptr) : GetRecent(20, nullptr);

            report << L"----------------------------------------------\n";
            report << L"RECENT QUARANTINE ENTRIES (" << entries.size() << L" shown)\n";
            report << L"----------------------------------------------\n";

            for (const auto& entry : entries) {
                report << L"\nEntry ID: " << entry.id << L"\n";
                report << L"  File: " << entry.originalFileName << L"\n";
                report << L"  Path: " << entry.originalPath << L"\n";
                report << L"  Threat: " << entry.threatName << L" (" << ThreatTypeToString(entry.threatType) << L")\n";
                report << L"  Severity: " << ThreatSeverityToString(entry.severity) << L"\n";
                report << L"  Status: " << QuarantineStatusToString(entry.status) << L"\n";
                report << L"  Quarantine Time: " << ToWide(timePointToString(entry.quarantineTime)) << L"\n";
                report << L"  Size: " << (entry.originalSize / 1024.0) << L" KB\n";
                report << L"  SHA256: " << entry.sha256Hash.substr(0, 16) << L"...\n";
            }

            report << L"\n==============================================\n";
            report << L"           END OF REPORT\n";
            report << L"==============================================\n";

            return report.str();
        }

        bool QuarantineDB::ExportToJSON(std::wstring_view filePath, const QueryFilter* filter,
            DatabaseError* err)
        {
            SS_LOG_INFO(L"QuarantineDB", L"Exporting to JSON: %ls", filePath.data());

            // Get entries
            auto entries = filter ? Query(*filter, err) : GetActiveEntries(10000, err);

            // Create JSON structure
            using namespace ShadowStrike::Utils::JSON;
            Json exportData;

            exportData["format"] = "ShadowStrike Quarantine Export";
            exportData["version"] = "1.0";
            exportData["export_time"] = timePointToString(std::chrono::system_clock::now());
            exportData["entry_count"] = entries.size();

            // Add statistics
            Statistics stats = GetStatistics(nullptr);
            exportData["statistics"]["total_entries"] = stats.totalEntries;
            exportData["statistics"]["active_entries"] = stats.activeEntries;
            exportData["statistics"]["total_size_bytes"] = stats.totalQuarantineSize;

            // Add entries
            Json entriesArray = Json::array();
            for (const auto& entry : entries) {
                Json entryJson;
                entryJson["id"] = entry.id;
                entryJson["original_path"] = ToUTF8(entry.originalPath);
                entryJson["original_filename"] = ToUTF8(entry.originalFileName);
                entryJson["original_size"] = entry.originalSize;
                entryJson["quarantine_time"] = timePointToString(entry.quarantineTime);
                entryJson["threat_type"] = ToUTF8(ThreatTypeToString(entry.threatType));
                entryJson["threat_name"] = ToUTF8(entry.threatName);
                entryJson["severity"] = ToUTF8(ThreatSeverityToString(entry.severity));
                entryJson["status"] = ToUTF8(QuarantineStatusToString(entry.status));
                entryJson["sha256_hash"] = ToUTF8(entry.sha256Hash);
                entryJson["user_name"] = ToUTF8(entry.userName);
                entryJson["machine_name"] = ToUTF8(entry.machineName);
                entryJson["detection_reason"] = ToUTF8(entry.detectionReason);
                entryJson["notes"] = ToUTF8(entry.notes);

                entriesArray.push_back(entryJson);
            }
            exportData["entries"] = entriesArray;

            // Write to file
            Error jsonErr;
            SaveOptions saveOpts;
            saveOpts.pretty = true;
            saveOpts.indentSpaces = 2;
            saveOpts.atomicReplace = true;

            if (!SaveToFile(std::filesystem::path(filePath), exportData, &jsonErr, saveOpts)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to save JSON export: " + ToWide(jsonErr.message);
                }
                return false;
            }

            SS_LOG_INFO(L"QuarantineDB", L"JSON export completed. %zu entries exported", entries.size());
            return true;
        }

        bool QuarantineDB::ExportToCSV(std::wstring_view filePath, const QueryFilter* filter,
            DatabaseError* err)
        {
            SS_LOG_INFO(L"QuarantineDB", L"Exporting to CSV: %ls", filePath.data());

            // Get entries
            auto entries = filter ? Query(*filter, err) : GetActiveEntries(10000, err);

            // Open file for writing
            std::wofstream csvFile(std::wstring(filePath), std::ios::out | std::ios::trunc);
            if (!csvFile.is_open()) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to open CSV file for writing";
                }
                return false;
            }

            // Write BOM for UTF-8
            csvFile << L"\xFEFF";

            // Write CSV header
            csvFile << L"Entry ID,Original Path,Original Filename,File Size (bytes),Quarantine Time,"
                   << L"Threat Type,Threat Name,Severity,Status,SHA256 Hash,User,Machine,Detection Reason,Notes\n";

            // Helper lambda to escape CSV fields
            auto escapeCsv = [](const std::wstring& field) -> std::wstring {
                if (field.find(L',') != std::wstring::npos || 
                    field.find(L'"') != std::wstring::npos || 
                    field.find(L'\n') != std::wstring::npos) {
                    std::wstring escaped = L"\"";
                    for (wchar_t c : field) {
                        if (c == L'"') escaped += L"\"\"";
                        else escaped += c;
                    }
                    escaped += L"\"";
                    return escaped;
                }
                return field;
            };

            // Write entries
            for (const auto& entry : entries) {
                csvFile << entry.id << L","
                       << escapeCsv(entry.originalPath) << L","
                       << escapeCsv(entry.originalFileName) << L","
                       << entry.originalSize << L","
                       << escapeCsv(ToWide(timePointToString(entry.quarantineTime))) << L","
                       << escapeCsv(ThreatTypeToString(entry.threatType)) << L","
                       << escapeCsv(entry.threatName) << L","
                       << escapeCsv(ThreatSeverityToString(entry.severity)) << L","
                       << escapeCsv(QuarantineStatusToString(entry.status)) << L","
                       << escapeCsv(entry.sha256Hash) << L","
                       << escapeCsv(entry.userName) << L","
                       << escapeCsv(entry.machineName) << L","
                       << escapeCsv(entry.detectionReason) << L","
                       << escapeCsv(entry.notes) << L"\n";
            }

            csvFile.close();

            SS_LOG_INFO(L"QuarantineDB", L"CSV export completed. %zu entries exported", entries.size());
            return true;
        }

        bool QuarantineDB::BackupQuarantine(std::wstring_view backupPath, DatabaseError* err) {
            SS_LOG_INFO(L"QuarantineDB", L"Creating quarantine backup: %ls", backupPath.data());

            std::filesystem::path backupFilePath(backupPath);

            // Create backup directory
            Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::CreateDirectories(backupFilePath.parent_path().wstring(), &fileErr)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to create backup directory";
                }
                return false;
            }

            // Create a comprehensive backup package
            using namespace ShadowStrike::Utils::JSON;
            Json backup;

            backup["backup_format"] = "ShadowStrike Quarantine Backup";
            backup["backup_version"] = "1.0";
            backup["backup_time"] = timePointToString(std::chrono::system_clock::now());
            backup["system"]["machine_name"] = ToUTF8(m_machineName);
            backup["system"]["user_name"] = ToUTF8(m_userName);

            // Add all entries with their data
            auto entries = GetActiveEntries(100000, err);
            backup["entry_count"] = entries.size();

            Json entriesArray = Json::array();
            size_t successCount = 0;
            size_t failureCount = 0;

            for (const auto& entry : entries) {
                // Extract file data
                std::vector<uint8_t> fileData;
                if (!ExtractFileData(entry.id, fileData, nullptr)) {
                    SS_LOG_WARN(L"QuarantineDB", L"Failed to extract data for entry %lld during backup", entry.id);
                    continue;
                }

                Json entryBackup;

                // Full entry metadata
                entryBackup["id"] = entry.id;
                entryBackup["original"]["path"] = ToUTF8(entry.originalPath);
                entryBackup["original"]["filename"] = ToUTF8(entry.originalFileName);
                entryBackup["original"]["directory"] = ToUTF8(entry.originalDirectory);
                entryBackup["original"]["size"] = entry.originalSize;
                entryBackup["original"]["creation_time"] = timePointToString(entry.originalCreationTime);
                entryBackup["original"]["modification_time"] = timePointToString(entry.originalModificationTime);

                entryBackup["threat"]["type"] = ToUTF8(ThreatTypeToString(entry.threatType));
                entryBackup["threat"]["severity"] = ToUTF8(ThreatSeverityToString(entry.severity));
                entryBackup["threat"]["name"] = ToUTF8(entry.threatName);
                entryBackup["threat"]["signature"] = ToUTF8(entry.threatSignature);
                entryBackup["threat"]["detection_reason"] = ToUTF8(entry.detectionReason);

                entryBackup["scan"]["engine"] = ToUTF8(entry.scanEngine);
                entryBackup["scan"]["engine_version"] = ToUTF8(entry.scanEngineVersion);

                entryBackup["hashes"]["md5"] = ToUTF8(entry.md5Hash);
                entryBackup["hashes"]["sha1"] = ToUTF8(entry.sha1Hash);
                entryBackup["hashes"]["sha256"] = ToUTF8(entry.sha256Hash);

                entryBackup["system"]["user"] = ToUTF8(entry.userName);
                entryBackup["system"]["machine"] = ToUTF8(entry.machineName);
                entryBackup["system"]["process_id"] = entry.processId;
                entryBackup["system"]["process_name"] = ToUTF8(entry.processName);

                entryBackup["quarantine"]["time"] = timePointToString(entry.quarantineTime);
                entryBackup["quarantine"]["status"] = ToUTF8(QuarantineStatusToString(entry.status));
                entryBackup["quarantine"]["notes"] = ToUTF8(entry.notes);

                // Encode file data
                std::string base64Data;
                Utils::Base64EncodeOptions b64opts;
                if (!Utils::Base64Encode(fileData.data(), fileData.size(), base64Data, b64opts)) {
                    SS_LOG_WARN(L"QuarantineDB", L"Failed to encode file data for backup");
                    failureCount++;
                    continue;
                }
                entryBackup["file_data"] = base64Data;

                entriesArray.push_back(entryBackup);
                successCount++;
            }

            backup["entries"] = entriesArray;
            backup["backup_success_count"] = successCount;

            // Add statistics
            Statistics stats = GetStatistics(nullptr);
            backup["statistics"]["total_entries"] = stats.totalEntries;
            backup["statistics"]["active_entries"] = stats.activeEntries;
            backup["statistics"]["total_size_bytes"] = stats.totalQuarantineSize;

            // Write backup file
            Error jsonErr;
            SaveOptions saveOpts;
            saveOpts.pretty = true;
            saveOpts.indentSpaces = 2;
            saveOpts.atomicReplace = true;

            if (!SaveToFile(backupFilePath, backup, &jsonErr, saveOpts)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to save backup file: " + ToWide(jsonErr.message);
                }
                return false;
            }

            // Log audit event
            logAuditEvent(QuarantineAction::Submitted, 0, 
                         L"Backup created: " + std::wstring(backupPath) + 
                         L" (" + std::to_wstring(successCount) + L" entries)");

            SS_LOG_INFO(L"QuarantineDB", L"Backup completed. %zu entries backed up", successCount);
            return true;
        }

        bool QuarantineDB::RestoreQuarantine(std::wstring_view backupPath, DatabaseError* err) {
            SS_LOG_INFO(L"QuarantineDB", L"Restoring quarantine from backup: %ls", backupPath.data());

            // Load backup file
            using namespace ShadowStrike::Utils::JSON;
            Json backup;
            Error jsonErr;
            ParseOptions parseOpts;

            if (!LoadFromFile(std::filesystem::path(backupPath), backup, &jsonErr, parseOpts)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to load backup file: " + ToWide(jsonErr.message);
                }
                return false;
            }

            // Validate backup format
            if (!backup.contains("backup_format") || !backup.contains("entries")) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Invalid backup file format";
                }
                return false;
            }

            // Get entries array
            const Json& entriesArray = backup["entries"];
            size_t totalEntries = entriesArray.size();
            size_t successCount = 0;
            size_t failureCount = 0;

            SS_LOG_INFO(L"QuarantineDB", L"Restoring %zu entries from backup", totalEntries);

            // Start transaction for bulk insert
            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);
            
            if (!trans || !trans->IsActive()) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to begin transaction for restore");
                return false;
            }

            // Restore each entry
            for (const auto& entryBackup : entriesArray) {
                try {
                    QuarantineEntry entry;

                    // Parse entry data
                    entry.originalPath = ToWide(entryBackup["original"]["path"].get<std::string>());
                    entry.originalFileName = ToWide(entryBackup["original"]["filename"].get<std::string>());
                    entry.originalDirectory = ToWide(entryBackup["original"]["directory"].get<std::string>());
                    entry.originalSize = entryBackup["original"]["size"].get<uint64_t>();
                    entry.originalCreationTime = stringToTimePoint(entryBackup["original"]["creation_time"].get<std::string>());
                    entry.originalModificationTime = stringToTimePoint(entryBackup["original"]["modification_time"].get<std::string>());

                    entry.threatType = StringToThreatType(ToWide(entryBackup["threat"]["type"].get<std::string>()));
                    entry.severity = StringToThreatSeverity(ToWide(entryBackup["threat"]["severity"].get<std::string>()));
                    entry.threatName = ToWide(entryBackup["threat"]["name"].get<std::string>());
                    entry.threatSignature = ToWide(entryBackup["threat"]["signature"].get<std::string>());
                    entry.detectionReason = ToWide(entryBackup["threat"]["detection_reason"].get<std::string>());

                    entry.scanEngine = ToWide(entryBackup["scan"]["engine"].get<std::string>());
                    entry.scanEngineVersion = ToWide(entryBackup["scan"]["engine_version"].get<std::string>());

                    entry.md5Hash = ToWide(entryBackup["hashes"]["md5"].get<std::string>());
                    entry.sha1Hash = ToWide(entryBackup["hashes"]["sha1"].get<std::string>());
                    entry.sha256Hash = ToWide(entryBackup["hashes"]["sha256"].get<std::string>());

                    entry.userName = ToWide(entryBackup["system"]["user"].get<std::string>());
                    entry.machineName = ToWide(entryBackup["system"]["machine"].get<std::string>());
                    entry.processId = entryBackup["system"]["process_id"].get<uint32_t>();
                    entry.processName = ToWide(entryBackup["system"]["process_name"].get<std::string>());

                    entry.quarantineTime = stringToTimePoint(entryBackup["quarantine"]["time"].get<std::string>());
                    entry.status = StringToQuarantineStatus(ToWide(entryBackup["quarantine"]["status"].get<std::string>()));
                    entry.notes = ToWide(entryBackup["quarantine"]["notes"].get<std::string>());
                    entry.notes += L"\n[Restored from backup: " + std::wstring(backupPath) + L"]";

                    entry.lastAccessTime = std::chrono::system_clock::now();
                    entry.isEncrypted = m_config.enableEncryption;
                    entry.encryptionMethod = m_config.encryptionAlgorithm;
                    entry.canRestore = true;
                    entry.canDelete = true;

                    // Decode file data
                    std::string base64Data = entryBackup["file_data"].get<std::string>();
                    std::vector<uint8_t> fileData;
                    Utils::Base64DecodeError decErr = Utils::Base64DecodeError::None;
                    Utils::Base64DecodeOptions b64opts;
                    if (!Utils::Base64Decode(base64Data, fileData, decErr, b64opts)) {
                        SS_LOG_WARN(L"QuarantineDB", L"Failed to decode file data for entry");
                        failureCount++;
                        continue;
                    }

                    // Verify hash
                    std::wstring md5, sha1, sha256;
                    if (calculateHashes(fileData, md5, sha1, sha256)) {
                        if (sha256 != entry.sha256Hash) {
                            SS_LOG_WARN(L"QuarantineDB", L"Hash mismatch for restored entry");
                            failureCount++;
                            continue;
                        }
                    }

                    // Import the entry
                    int64_t newId = QuarantineFileDetailed(entry, fileData, nullptr);
                    if (newId > 0) {
                        successCount++;
                    } else {
                        failureCount++;
                    }

                } catch (const std::exception& e) {
                    SS_LOG_WARN(L"QuarantineDB", L"Exception restoring entry: %hs", e.what());
                    failureCount++;
                    continue;
                }
            }

            // Commit transaction
            if (!trans->Commit(err)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to commit restore transaction");
                return false;
            }

            // Log audit event
            logAuditEvent(QuarantineAction::Restored, 0, 
                         L"Restored from backup: " + std::wstring(backupPath) + 
                         L" (Success: " + std::to_wstring(successCount) + 
                         L", Failed: " + std::to_wstring(failureCount) + L")");

            SS_LOG_INFO(L"QuarantineDB", L"Restore completed. Success: %zu, Failed: %zu", 
                       successCount, failureCount);

            return successCount > 0;
        }

    } // namespace Database
} // namespace ShadowStrike