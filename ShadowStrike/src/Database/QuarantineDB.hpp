#pragma once

#include "DatabaseManager.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <map>

namespace ShadowStrike {
    namespace Database {

        // ============================================================================
        // QuarantineDB - Secure Quarantine Management System
        // ============================================================================

        /**
         * @brief Secure quarantine database for isolated file management.
         * 
         * Features:
         * - Encrypted file storage with AES-256
         * - Detailed threat metadata tracking
         * - Secure file restoration with validation
         * - Automatic cleanup and retention policies
         * - Audit logging for all operations
         * - Thread-safe concurrent access
         * - Integrity verification
         */
        class QuarantineDB {
        public:
            // ============================================================================
            // Types & Enums
            // ============================================================================

            enum class ThreatType : uint8_t {
                Unknown = 0,
                Virus = 1,
                Trojan = 2,
                Worm = 3,
                Ransomware = 4,
                Spyware = 5,
                Adware = 6,
                Rootkit = 7,
                Backdoor = 8,
                PUA = 9,              // Potentially Unwanted Application
                Exploit = 10,
                Script = 11,
                Macro = 12,
                Phishing = 13,
                Suspicious = 14,
                Custom = 255
            };

            enum class ThreatSeverity : uint8_t {
                Info = 0,
                Low = 1,
                Medium = 2,
                High = 3,
                Critical = 4
            };

            enum class QuarantineAction : uint8_t {
                Quarantined = 0,
                Restored = 1,
                Deleted = 2,
                Submitted = 3,        // Submitted for analysis
                Whitelisted = 4,
                Failed = 5
            };

            enum class QuarantineStatus : uint8_t {
                Active = 0,
                Restored = 1,
                Deleted = 2,
                Expired = 3,
                Corrupted = 4,
                Pending = 5
            };

            struct QuarantineEntry {
                int64_t id = 0;
                std::chrono::system_clock::time_point quarantineTime;
                std::chrono::system_clock::time_point lastAccessTime;
                
                // Original file information
                std::wstring originalPath;
                std::wstring originalFileName;
                std::wstring originalDirectory;
                uint64_t originalSize = 0;
                std::chrono::system_clock::time_point originalCreationTime;
                std::chrono::system_clock::time_point originalModificationTime;
                
                // Quarantine file information
                std::wstring quarantinePath;
                std::wstring quarantineFileName;
                uint64_t quarantineSize = 0;
                
                // Threat information
                ThreatType threatType = ThreatType::Unknown;
                ThreatSeverity severity = ThreatSeverity::Medium;
                std::wstring threatName;
                std::wstring threatSignature;
                std::wstring scanEngine;
                std::wstring scanEngineVersion;
                
                // File hashes
                std::wstring md5Hash;
                std::wstring sha1Hash;
                std::wstring sha256Hash;
                
                // Metadata
                QuarantineStatus status = QuarantineStatus::Active;
                std::wstring userName;
                std::wstring machineName;
                uint32_t processId = 0;
                std::wstring processName;
                
                // Encryption information
                bool isEncrypted = true;
                std::wstring encryptionMethod;
                
                // Additional information
                std::wstring notes;
                std::wstring detectionReason;
                std::map<std::wstring, std::wstring> customMetadata;
                
                // Restoration information
                std::chrono::system_clock::time_point restorationTime;
                std::wstring restoredBy;
                std::wstring restorationReason;
                
                // Access control
                bool canRestore = true;
                bool canDelete = true;
                bool requiresPasswordForRestore = false;
            };

            // ============================================================================
            // Configuration
            // ============================================================================

            struct Config {
                std::wstring dbPath = L"C:\\ProgramData\\ShadowStrike\\quarantine.db";
                std::wstring quarantineBasePath = L"C:\\ProgramData\\ShadowStrike\\Quarantine";
                
                // Database settings
                bool enableWAL = true;
                size_t dbCacheSizeKB = 10240;     // 10MB
                size_t maxConnections = 5;
                
                // Security settings
                bool enableEncryption = true;
                std::wstring encryptionAlgorithm = L"AES-256-GCM";
                bool requirePasswordForRestore = false;
                bool enableIntegrityChecks = true;
                
                // Retention settings
                bool enableAutoCleanup = true;
                std::chrono::hours maxRetentionDays = std::chrono::hours(24 * 90);  // 90 days
                size_t maxQuarantineSize = 1024ULL * 1024 * 1024;  // 1GB
                size_t maxEntriesCount = 10000;
                
                // Compression settings
                bool enableCompression = true;
                std::wstring compressionAlgorithm = L"LZMA";
                
                // Logging settings
                bool enableAuditLog = true;
                bool logAllOperations = true;
                
                // Performance settings
                size_t batchOperationSize = 100;
                
                // Backup settings
                bool enableAutoBackup = true;
                std::chrono::hours backupInterval = std::chrono::hours(24);
                size_t maxBackupCount = 7;
            };

            struct QueryFilter {
                std::optional<ThreatType> threatType;
                std::optional<ThreatSeverity> minSeverity;
                std::optional<ThreatSeverity> maxSeverity;
                std::optional<QuarantineStatus> status;
                std::optional<std::chrono::system_clock::time_point> startTime;
                std::optional<std::chrono::system_clock::time_point> endTime;
                std::optional<std::wstring> originalPathPattern;
                std::optional<std::wstring> threatNamePattern;
                std::optional<std::wstring> fileHashPattern;
                std::optional<std::wstring> userNamePattern;
                std::optional<std::wstring> machineNamePattern;
                size_t maxResults = 1000;
                bool sortDescending = true;
            };

            struct Statistics {
                uint64_t totalEntries = 0;
                uint64_t activeEntries = 0;
                uint64_t restoredEntries = 0;
                uint64_t deletedEntries = 0;
                
                uint64_t entriesByType[256] = {};        // Per ThreatType
                uint64_t entriesBySeverity[5] = {};      // Per ThreatSeverity
                uint64_t entriesByStatus[6] = {};        // Per QuarantineStatus
                
                uint64_t totalQuarantines = 0;
                uint64_t totalRestorations = 0;
                uint64_t totalDeletions = 0;
                uint64_t failedOperations = 0;
                
                size_t totalQuarantineSize = 0;
                size_t averageFileSize = 0;
                size_t largestFileSize = 0;
                
                std::chrono::system_clock::time_point oldestEntry;
                std::chrono::system_clock::time_point newestEntry;
                std::chrono::system_clock::time_point lastCleanup;
                
                uint64_t cleanupCount = 0;
                uint64_t integrityChecksPassed = 0;
                uint64_t integrityChecksFailed = 0;
            };

            // ============================================================================
            // Lifecycle
            // ============================================================================

            static QuarantineDB& Instance();

            bool Initialize(const Config& config, DatabaseError* err = nullptr);
            void Shutdown();
            bool IsInitialized() const noexcept { return m_initialized.load(); }

            // ============================================================================
            // Quarantine Operations
            // ============================================================================

            // Quarantine a file
            int64_t QuarantineFile(std::wstring_view originalPath,
                                  ThreatType threatType,
                                  ThreatSeverity severity,
                                  std::wstring_view threatName,
                                  std::wstring_view detectionReason = L"",
                                  DatabaseError* err = nullptr);

            // Quarantine with full metadata
            int64_t QuarantineFileDetailed(const QuarantineEntry& entry,
                                          const std::vector<uint8_t>& fileData,
                                          DatabaseError* err = nullptr);

            // Restore quarantined file
            bool RestoreFile(int64_t entryId,
                           std::wstring_view restorePath = L"",
                           std::wstring_view restoredBy = L"",
                           std::wstring_view reason = L"",
                           DatabaseError* err = nullptr);

            // Delete quarantined file permanently
            bool DeleteQuarantinedFile(int64_t entryId,
                                      std::wstring_view deletedBy = L"",
                                      std::wstring_view reason = L"",
                                      DatabaseError* err = nullptr);

            // Batch operations
            bool QuarantineBatch(const std::vector<std::wstring>& filePaths,
                               ThreatType threatType,
                               ThreatSeverity severity,
                               std::wstring_view threatName,
                               DatabaseError* err = nullptr);

            bool RestoreBatch(const std::vector<int64_t>& entryIds,
                            std::wstring_view restoredBy = L"",
                            DatabaseError* err = nullptr);

            bool DeleteBatch(const std::vector<int64_t>& entryIds,
                           std::wstring_view deletedBy = L"",
                           DatabaseError* err = nullptr);

            // ============================================================================
            // Query Operations
            // ============================================================================

            // Get entry by ID
            std::optional<QuarantineEntry> GetEntry(int64_t id, DatabaseError* err = nullptr);

            // Query with filters
            std::vector<QuarantineEntry> Query(const QueryFilter& filter,
                                              DatabaseError* err = nullptr);

            // Get by threat type
            std::vector<QuarantineEntry> GetByThreatType(ThreatType type,
                                                         size_t maxCount = 1000,
                                                         DatabaseError* err = nullptr);

            // Get by severity
            std::vector<QuarantineEntry> GetBySeverity(ThreatSeverity severity,
                                                      size_t maxCount = 1000,
                                                      DatabaseError* err = nullptr);

            // Get by status
            std::vector<QuarantineEntry> GetByStatus(QuarantineStatus status,
                                                    size_t maxCount = 1000,
                                                    DatabaseError* err = nullptr);

            // Get active entries
            std::vector<QuarantineEntry> GetActiveEntries(size_t maxCount = 1000,
                                                         DatabaseError* err = nullptr);

            // Get recent entries
            std::vector<QuarantineEntry> GetRecent(size_t count = 100,
                                                  DatabaseError* err = nullptr);

            // Search by file hash
            std::vector<QuarantineEntry> SearchByHash(std::wstring_view hash,
                                                     DatabaseError* err = nullptr);

            // Search by file name
            std::vector<QuarantineEntry> SearchByFileName(std::wstring_view fileName,
                                                         size_t maxCount = 1000,
                                                         DatabaseError* err = nullptr);

            // Count entries
            int64_t CountEntries(const QueryFilter* filter = nullptr,
                               DatabaseError* err = nullptr);

            // ============================================================================
            // File Operations
            // ============================================================================

            // Extract quarantined file data (decrypted)
            bool ExtractFileData(int64_t entryId,
                               std::vector<uint8_t>& outData,
                               DatabaseError* err = nullptr);

            // Get file hash without extraction
            bool GetFileHash(int64_t entryId,
                           std::wstring& md5,
                           std::wstring& sha1,
                           std::wstring& sha256,
                           DatabaseError* err = nullptr);

            // Verify file integrity
            bool VerifyIntegrity(int64_t entryId, DatabaseError* err = nullptr);

            // Update entry metadata
            bool UpdateEntry(const QuarantineEntry& entry, DatabaseError* err = nullptr);

            // Add notes to entry
            bool AddNotes(int64_t entryId,
                        std::wstring_view notes,
                        DatabaseError* err = nullptr);

            // ============================================================================
            // Management Operations
            // ============================================================================

            // Cleanup expired entries
            bool CleanupExpired(DatabaseError* err = nullptr);

            // Force cleanup to meet size limits
            bool CleanupBySize(size_t targetSize, DatabaseError* err = nullptr);

            // Delete all entries (with confirmation)
            bool DeleteAll(bool confirmed, DatabaseError* err = nullptr);

            // Export quarantine data
            bool ExportEntry(int64_t entryId,
                           std::wstring_view exportPath,
                           bool includeMetadata = true,
                           DatabaseError* err = nullptr);

            // Import quarantine data
            int64_t ImportEntry(std::wstring_view importPath,
                              DatabaseError* err = nullptr);

            // Submit to cloud analysis
            bool SubmitForAnalysis(int64_t entryId,
                                 std::wstring_view submissionEndpoint,
                                 DatabaseError* err = nullptr);

            // ============================================================================
            // Statistics & Reporting
            // ============================================================================

            Statistics GetStatistics(DatabaseError* err = nullptr);
            void ResetStatistics();

            Config GetConfig() const;
            void SetMaxRetentionDays(std::chrono::hours days);
            void SetMaxQuarantineSize(size_t sizeBytes);

            // Generate report
            std::wstring GenerateReport(const QueryFilter* filter = nullptr);

            // Export to file formats
            bool ExportToJSON(std::wstring_view filePath,
                            const QueryFilter* filter = nullptr,
                            DatabaseError* err = nullptr);

            bool ExportToCSV(std::wstring_view filePath,
                           const QueryFilter* filter = nullptr,
                           DatabaseError* err = nullptr);

            // ============================================================================
            // Utility Functions
            // ============================================================================

            static std::wstring ThreatTypeToString(ThreatType type);
            static ThreatType StringToThreatType(std::wstring_view str);

            static std::wstring ThreatSeverityToString(ThreatSeverity severity);
            static ThreatSeverity StringToThreatSeverity(std::wstring_view str);

            static std::wstring QuarantineStatusToString(QuarantineStatus status);
            static QuarantineStatus StringToQuarantineStatus(std::wstring_view str);

            static std::wstring QuarantineActionToString(QuarantineAction action);

            // ============================================================================
            // Maintenance Operations
            // ============================================================================

            bool Vacuum(DatabaseError* err = nullptr);
            bool CheckIntegrity(DatabaseError* err = nullptr);
            bool Optimize(DatabaseError* err = nullptr);
            bool RebuildIndices(DatabaseError* err = nullptr);

            // Backup operations
            bool BackupQuarantine(std::wstring_view backupPath, DatabaseError* err = nullptr);
            bool RestoreQuarantine(std::wstring_view backupPath, DatabaseError* err = nullptr);

        private:
            QuarantineDB();
            ~QuarantineDB();

            QuarantineDB(const QuarantineDB&) = delete;
            QuarantineDB& operator=(const QuarantineDB&) = delete;

            // ============================================================================
            // Internal Operations
            // ============================================================================

            // Schema management
            bool createSchema(DatabaseError* err);
            bool upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err);

            // Database operations
            int64_t dbInsertEntry(const QuarantineEntry& entry, DatabaseError* err);
            bool dbUpdateEntry(const QuarantineEntry& entry, DatabaseError* err);
            bool dbDeleteEntry(int64_t id, DatabaseError* err);
            std::optional<QuarantineEntry> dbSelectEntry(int64_t id, DatabaseError* err);
            std::vector<QuarantineEntry> dbSelectEntries(std::string_view sql,
                                                        const std::vector<std::string>& params,
                                                        DatabaseError* err);

            // Query builders
            std::string buildQuerySQL(const QueryFilter& filter, std::vector<std::string>& outParams);
            std::string buildCountSQL(const QueryFilter& filter, std::vector<std::string>& outParams);

            // File operations
            bool encryptAndStoreFile(const std::vector<uint8_t>& fileData,
                                   std::wstring_view quarantinePath,
                                   DatabaseError* err);

            bool decryptAndLoadFile(std::wstring_view quarantinePath,
                                  std::vector<uint8_t>& outData,
                                  DatabaseError* err);

            bool compressData(const std::vector<uint8_t>& input,
                            std::vector<uint8_t>& output);

            bool decompressData(const std::vector<uint8_t>& input,
                              std::vector<uint8_t>& output);

            // Hash calculation
            bool calculateHashes(const std::vector<uint8_t>& data,
                               std::wstring& md5,
                               std::wstring& sha1,
                               std::wstring& sha256);

            std::wstring calculateMD5(const std::vector<uint8_t>& data);
            std::wstring calculateSHA1(const std::vector<uint8_t>& data);
            std::wstring calculateSHA256(const std::vector<uint8_t>& data);

            // Path management
            std::wstring generateQuarantinePath(int64_t entryId);
            bool ensureQuarantineDirectory(DatabaseError* err);

            // Cleanup helpers
            bool cleanupOldEntries(DatabaseError* err);
            bool cleanupCorruptedEntries(DatabaseError* err);
            void backgroundCleanupThread();

            // Statistics helpers
            void updateStatistics(const QuarantineEntry& entry, QuarantineAction action);
            void recalculateStatistics(DatabaseError* err);

            // Audit logging
            void logAuditEvent(QuarantineAction action,
                             int64_t entryId,
                             std::wstring_view details);

            // Utility helpers
            QuarantineEntry rowToQuarantineEntry(QueryResult& result);
            static std::string timePointToString(std::chrono::system_clock::time_point tp);
            static std::chrono::system_clock::time_point stringToTimePoint(std::string_view str);

            // Encryption key management
            std::vector<uint8_t> deriveEncryptionKey();
            std::vector<uint8_t> generateSalt();

            // ============================================================================
            // State
            // ============================================================================

            std::atomic<bool> m_initialized{ false };
            Config m_config;
            mutable std::shared_mutex m_configMutex;

            // Background cleanup
            std::thread m_cleanupThread;
            std::atomic<bool> m_shutdownCleanup{ false };
            std::condition_variable m_cleanupCV;
            std::mutex m_cleanupMutex;
            std::chrono::steady_clock::time_point m_lastCleanup;

            // Statistics
            mutable std::mutex m_statsMutex;
            Statistics m_stats;

            // System information (cached)
            std::wstring m_machineName;
            std::wstring m_userName;

            // Encryption key (in-memory only)
            mutable std::mutex m_keyMutex;
            std::vector<uint8_t> m_masterKey;
        };

    } // namespace Database
} // namespace ShadowStrike