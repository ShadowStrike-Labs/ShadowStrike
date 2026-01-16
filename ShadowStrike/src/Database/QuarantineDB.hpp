/**
 * @file QuarantineDB.hpp
 * @brief Enterprise-grade secure quarantine management system for malware isolation.
 * 
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @date 2025
 * @copyright ShadowStrike Project - All Rights Reserved
 * 
 * @details
 * QuarantineDB provides a comprehensive secure vault for isolating detected malware
 * and suspicious files. It integrates AES-256 encryption, LZMA compression, hash
 * verification, and complete audit logging for enterprise compliance.
 * 
 * Architecture Overview:
 * ```
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                           APPLICATION LAYER                                  │
 * │  (Scan Engine, Threat Detection, User Interface, API Endpoints)             │
 * └─────────────────────────────────────────────┬───────────────────────────────┘
 *                                               │
 *                                               ▼
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                          QUARANTINEDB SINGLETON                             │
 * │ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐                │
 * │ │  Quarantine Ops │ │  Query Engine   │ │ Management Ops  │                │
 * │ │ ───────────────│ │ ───────────────│ │ ───────────────│                │
 * │ │ QuarantineFile  │ │ GetEntry        │ │ CleanupExpired  │                │
 * │ │ RestoreFile     │ │ Query           │ │ CleanupBySize   │                │
 * │ │ DeleteFile      │ │ SearchByHash    │ │ DeleteAll       │                │
 * │ │ BatchOps        │ │ GetBy*          │ │ Export/Import   │                │
 * │ └─────────────────┘ └─────────────────┘ └─────────────────┘                │
 * └─────────────────────────────────────────────┬───────────────────────────────┘
 *                                               │
 *                                               ▼
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                         SECURITY & ENCRYPTION LAYER                         │
 * │ ┌──────────────────────────┐  ┌──────────────────────────┐                 │
 * │ │    AES-256-GCM Engine    │  │    Hash Verification     │                 │
 * │ │ ────────────────────────│  │ ────────────────────────│                 │
 * │ │ encryptAndStoreFile()    │  │ MD5 / SHA1 / SHA256      │                 │
 * │ │ decryptAndLoadFile()     │  │ calculateHashes()        │                 │
 * │ │ deriveEncryptionKey()    │  │ VerifyIntegrity()        │                 │
 * │ └──────────────────────────┘  └──────────────────────────┘                 │
 * └─────────────────────────────────────────────┬───────────────────────────────┘
 *                                               │
 *                                               ▼
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                            STORAGE LAYER                                    │
 * │ ┌──────────────────────────┐  ┌──────────────────────────┐                 │
 * │ │    SQLite Database       │  │    Quarantine Vault      │                 │
 * │ │ ────────────────────────│  │ ────────────────────────│                 │
 * │ │ quarantine_entries       │  │ Encrypted File Storage   │                 │
 * │ │ quarantine_audit_log     │  │ LZMA Compressed Blobs    │                 │
 * │ │ quarantine_metadata      │  │ Directory Structure      │                 │
 * │ │ 8 Performance Indices    │  │ Path: {base}/{id}.qf     │                 │
 * │ └──────────────────────────┘  └──────────────────────────┘                 │
 * └─────────────────────────────────────────────┬───────────────────────────────┘
 *                                               │
 *                                               ▼
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                         BACKGROUND SERVICES                                 │
 * │ ┌──────────────────────────┐  ┌──────────────────────────┐                 │
 * │ │    Cleanup Thread        │  │    Audit Logger          │                 │
 * │ │ ────────────────────────│  │ ────────────────────────│                 │
 * │ │ Hourly maintenance       │  │ All operations tracked   │                 │
 * │ │ Retention enforcement    │  │ User/machine attribution │                 │
 * │ │ Size limit management    │  │ Timestamp logging        │                 │
 * │ │ Integrity verification   │  │ Compliance support       │                 │
 * │ └──────────────────────────┘  └──────────────────────────┘                 │
 * └─────────────────────────────────────────────────────────────────────────────┘
 * ```
 * 
 * Key Features:
 * - **Secure Isolation**: Files encrypted with AES-256-GCM before storage
 * - **Integrity Verification**: Triple-hash (MD5/SHA1/SHA256) for validation
 * - **Compression**: LZMA compression reduces storage requirements
 * - **16 Threat Types**: Virus, Trojan, Worm, Ransomware, Spyware, etc.
 * - **5 Severity Levels**: Info, Low, Medium, High, Critical
 * - **Full Audit Trail**: Every operation logged for compliance
 * - **Automatic Cleanup**: Retention and size-based purging
 * - **Batch Operations**: High-performance bulk quarantine/restore/delete
 * - **Export/Import**: JSON, CSV, full backup formats
 * 
 * Thread Safety:
 * - Singleton pattern with thread-safe initialization
 * - shared_mutex for configuration access
 * - mutex for statistics and encryption key
 * - Atomic flags for initialization state
 * - Background cleanup with condition variable
 * 
 * Usage Example:
 * @code{.cpp}
 * // Initialize quarantine system
 * QuarantineDB::Config config;
 * config.quarantineBasePath = L"C:\\ProgramData\\ShadowStrike\\Quarantine";
 * config.enableEncryption = true;
 * config.maxRetentionDays = std::chrono::hours(24 * 90); // 90 days
 * 
 * if (!QuarantineDB::Instance().Initialize(config, &error)) {
 *     // Handle initialization error
 * }
 * 
 * // Quarantine a detected malware file
 * int64_t entryId = QuarantineDB::Instance().QuarantineFile(
 *     L"C:\\Users\\victim\\malware.exe",
 *     ThreatType::Trojan,
 *     ThreatSeverity::High,
 *     L"Trojan.GenericKD.12345",
 *     L"Detected by signature scan"
 * );
 * 
 * // Query quarantined files
 * QueryFilter filter;
 * filter.threatType = ThreatType::Trojan;
 * filter.minSeverity = ThreatSeverity::High;
 * auto results = QuarantineDB::Instance().Query(filter);
 * 
 * // Restore if false positive
 * QuarantineDB::Instance().RestoreFile(entryId, L"", L"SecurityAdmin", L"False positive");
 * @endcode
 * 
 * @see DatabaseManager For underlying database operations
 * @see HashUtils For hash calculation utilities
 * @see CompressionUtils For LZMA compression
 */

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
        //                  QUARANTINEDB - SECURE QUARANTINE MANAGEMENT
        // ============================================================================

        /**
         * @class QuarantineDB
         * @brief Singleton class providing secure quarantine database operations.
         * 
         * @details QuarantineDB manages the complete lifecycle of quarantined files
         * including secure storage, metadata tracking, integrity verification,
         * restoration, and permanent deletion with full audit logging.
         * 
         * Design Patterns:
         * - **Singleton**: Single instance for centralized quarantine management
         * - **RAII**: Background cleanup thread managed by destructor
         * - **Command**: Audit log records all state-changing operations
         * 
         * @invariant Once initialized, database connection remains valid until Shutdown
         * @invariant Encryption key remains in memory only, never persisted
         * @invariant All file operations are atomic (success or rollback)
         */
        class QuarantineDB {
        public:

            // ============================================================================
            //                          TYPES & ENUMERATIONS
            // ============================================================================
            
            /** @name Threat Classification Enums
             *  Enumerations for categorizing detected threats.
             *  @{
             */

            /**
             * @enum ThreatType
             * @brief Classification of detected threat/malware type.
             * 
             * @details 16 threat categories covering the full malware taxonomy.
             * Used for reporting, filtering, and severity assessment.
             */
            enum class ThreatType : uint8_t {
                Unknown = 0,        ///< Unclassified or unrecognized threat
                Virus = 1,          ///< Self-replicating code that infects files
                Trojan = 2,         ///< Malware disguised as legitimate software
                Worm = 3,           ///< Self-propagating network malware
                Ransomware = 4,     ///< Encrypts files for ransom demands
                Spyware = 5,        ///< Covertly collects user information
                Adware = 6,         ///< Displays unwanted advertisements
                Rootkit = 7,        ///< Hides malware presence from system
                Backdoor = 8,       ///< Provides unauthorized remote access
                PUA = 9,            ///< Potentially Unwanted Application
                Exploit = 10,       ///< Code exploiting system vulnerabilities
                Script = 11,        ///< Malicious scripts (JS, VBS, PowerShell)
                Macro = 12,         ///< Office document macro malware
                Phishing = 13,      ///< Credential-stealing deception
                Suspicious = 14,    ///< Behavioral detection, unconfirmed type
                Custom = 255        ///< User-defined custom threat type
            };

            /**
             * @enum ThreatSeverity
             * @brief Risk level classification for detected threats.
             * 
             * @details 5-level severity scale for prioritizing response actions.
             * Higher severity indicates greater potential damage.
             */
            enum class ThreatSeverity : uint8_t {
                Info = 0,       ///< Informational only, no action required
                Low = 1,        ///< Minor risk, limited impact potential
                Medium = 2,     ///< Moderate risk, should be addressed
                High = 3,       ///< Significant risk, immediate attention needed
                Critical = 4    ///< Severe risk, system compromise likely
            };

            /**
             * @enum QuarantineAction
             * @brief Actions that can be performed on quarantined entries.
             * 
             * @details Used for audit logging to track what operations
             * were performed on quarantine entries.
             */
            enum class QuarantineAction : uint8_t {
                Quarantined = 0,    ///< File was quarantined (isolated)
                Restored = 1,       ///< File was restored to original location
                Deleted = 2,        ///< File was permanently deleted
                Submitted = 3,      ///< File was submitted for cloud analysis
                Whitelisted = 4,    ///< File was marked as safe (false positive)
                Failed = 5          ///< Operation failed
            };

            /**
             * @enum QuarantineStatus
             * @brief Current state of a quarantine entry.
             * 
             * @details Tracks the lifecycle state of quarantined files.
             */
            enum class QuarantineStatus : uint8_t {
                Active = 0,     ///< File is actively quarantined
                Restored = 1,   ///< File has been restored to filesystem
                Deleted = 2,    ///< File has been permanently deleted
                Expired = 3,    ///< File exceeded retention period
                Corrupted = 4,  ///< File integrity check failed
                Pending = 5     ///< Awaiting analysis or decision
            };

            /** @} */ // end of Threat Classification Enums

            // ============================================================================
            //                          DATA STRUCTURES
            // ============================================================================

            /** @name Quarantine Data Structures
             *  Structures for quarantine entries, configuration, and queries.
             *  @{
             */

            /**
             * @struct QuarantineEntry
             * @brief Complete metadata for a quarantined file.
             * 
             * @details Contains 30+ fields capturing:
             * - Original file information (path, size, timestamps)
             * - Quarantine file information (encrypted path, size)
             * - Threat classification (type, severity, signature)
             * - Hash verification (MD5, SHA1, SHA256)
             * - System context (user, machine, process)
             * - Encryption state and method
             * - Restoration tracking
             * - Access control flags
             */
            struct QuarantineEntry {
                // === Identity ===
                int64_t id = 0;                                             ///< Unique entry ID (auto-generated)
                std::chrono::system_clock::time_point quarantineTime;       ///< When file was quarantined
                std::chrono::system_clock::time_point lastAccessTime;       ///< Last access to this entry
                
                // === Original File Information ===
                std::wstring originalPath;                                  ///< Full path before quarantine
                std::wstring originalFileName;                              ///< Filename before quarantine
                std::wstring originalDirectory;                             ///< Directory before quarantine
                uint64_t originalSize = 0;                                  ///< File size in bytes
                std::chrono::system_clock::time_point originalCreationTime; ///< Original file creation time
                std::chrono::system_clock::time_point originalModificationTime; ///< Original last modified time
                
                // === Quarantine File Information ===
                std::wstring quarantinePath;                                ///< Path in quarantine vault
                std::wstring quarantineFileName;                            ///< Filename in quarantine vault
                uint64_t quarantineSize = 0;                                ///< Size after compression/encryption
                
                // === Threat Information ===
                ThreatType threatType = ThreatType::Unknown;                ///< Classification of threat
                ThreatSeverity severity = ThreatSeverity::Medium;           ///< Risk level
                std::wstring threatName;                                    ///< Detection name (e.g., "Trojan.Gen.2")
                std::wstring threatSignature;                               ///< Signature ID that detected it
                std::wstring scanEngine;                                    ///< Engine that detected threat
                std::wstring scanEngineVersion;                             ///< Engine version at detection
                
                // === File Hashes ===
                std::wstring md5Hash;                                       ///< MD5 hash (32 hex chars)
                std::wstring sha1Hash;                                      ///< SHA-1 hash (40 hex chars)
                std::wstring sha256Hash;                                    ///< SHA-256 hash (64 hex chars)
                
                // === System Context ===
                QuarantineStatus status = QuarantineStatus::Active;         ///< Current entry state
                std::wstring userName;                                      ///< User who triggered quarantine
                std::wstring machineName;                                   ///< Machine where detected
                uint32_t processId = 0;                                     ///< Process ID that accessed file
                std::wstring processName;                                   ///< Process name that accessed file
                
                // === Encryption Information ===
                bool isEncrypted = true;                                    ///< Whether file is encrypted
                std::wstring encryptionMethod;                              ///< Encryption algorithm used
                
                // === Additional Information ===
                std::wstring notes;                                         ///< User/system notes
                std::wstring detectionReason;                               ///< Why file was flagged
                std::map<std::wstring, std::wstring> customMetadata;        ///< Extensible metadata
                
                // === Restoration Information ===
                std::chrono::system_clock::time_point restorationTime;      ///< When restored (if applicable)
                std::wstring restoredBy;                                    ///< User who restored file
                std::wstring restorationReason;                             ///< Reason for restoration
                
                // === Access Control ===
                bool canRestore = true;                                     ///< Whether restoration is allowed
                bool canDelete = true;                                      ///< Whether deletion is allowed
                bool requiresPasswordForRestore = false;                    ///< Password protection flag
            };

            // ============================================================================
            //                          CONFIGURATION
            // ============================================================================

            /**
             * @struct Config
             * @brief Configuration settings for QuarantineDB initialization.
             * 
             * @details Comprehensive configuration covering:
             * - Database paths and connection settings
             * - Security options (encryption, passwords)
             * - Retention policies (time-based, size-based)
             * - Compression settings
             * - Audit logging options
             * - Performance tuning
             * - Backup scheduling
             */
            struct Config {
                // === Path Settings ===
                std::wstring dbPath = L"C:\\ProgramData\\ShadowStrike\\quarantine.db";  ///< SQLite database file path
                std::wstring quarantineBasePath = L"C:\\ProgramData\\ShadowStrike\\Quarantine"; ///< Base directory for encrypted files
                
                // === Database Settings ===
                bool enableWAL = true;              ///< Enable Write-Ahead Logging for performance
                size_t dbCacheSizeKB = 10240;       ///< Database cache size (default 10MB)
                size_t maxConnections = 5;          ///< Maximum concurrent database connections
                
                // === Security Settings ===
                bool enableEncryption = true;       ///< Encrypt quarantined files (strongly recommended)
                std::wstring encryptionAlgorithm = L"AES-256-GCM"; ///< Encryption algorithm to use
                bool requirePasswordForRestore = false; ///< Require password to restore files
                bool enableIntegrityChecks = true;  ///< Verify file integrity on access
                
                // === Retention Settings ===
                bool enableAutoCleanup = true;      ///< Enable automatic cleanup of old entries
                std::chrono::hours maxRetentionDays = std::chrono::hours(24 * 90);  ///< Maximum retention (default 90 days)
                size_t maxQuarantineSize = 1024ULL * 1024 * 1024;  ///< Maximum vault size (default 1GB)
                size_t maxEntriesCount = 10000;     ///< Maximum number of entries
                
                // === Compression Settings ===
                bool enableCompression = true;      ///< Compress files before encryption
                std::wstring compressionAlgorithm = L"LZMA"; ///< Compression algorithm (LZMA/Xpress)
                
                // === Logging Settings ===
                bool enableAuditLog = true;         ///< Enable audit trail for compliance
                bool logAllOperations = true;       ///< Log all operations (not just modifications)
                
                // === Performance Settings ===
                size_t batchOperationSize = 100;    ///< Batch size for bulk operations
                
                // === Backup Settings ===
                bool enableAutoBackup = true;       ///< Enable automatic backups
                std::chrono::hours backupInterval = std::chrono::hours(24); ///< Backup frequency
                size_t maxBackupCount = 7;          ///< Maximum backup files to retain
            };

            /**
             * @struct QueryFilter
             * @brief Filter criteria for querying quarantine entries.
             * 
             * @details Supports filtering by:
             * - Threat type and severity range
             * - Status and time range
             * - Path, name, and hash patterns
             * - User and machine filters
             * - Result limiting and sorting
             */
            struct QueryFilter {
                std::optional<ThreatType> threatType;           ///< Filter by specific threat type
                std::optional<ThreatSeverity> minSeverity;      ///< Minimum severity (inclusive)
                std::optional<ThreatSeverity> maxSeverity;      ///< Maximum severity (inclusive)
                std::optional<QuarantineStatus> status;         ///< Filter by status
                std::optional<std::chrono::system_clock::time_point> startTime; ///< Quarantine time >= startTime
                std::optional<std::chrono::system_clock::time_point> endTime;   ///< Quarantine time <= endTime
                std::optional<std::wstring> originalPathPattern;  ///< LIKE pattern for original path
                std::optional<std::wstring> threatNamePattern;    ///< LIKE pattern for threat name
                std::optional<std::wstring> fileHashPattern;      ///< Exact or partial hash match
                std::optional<std::wstring> userNamePattern;      ///< LIKE pattern for user name
                std::optional<std::wstring> machineNamePattern;   ///< LIKE pattern for machine name
                size_t maxResults = 1000;                         ///< Maximum results to return
                bool sortDescending = true;                       ///< Sort by quarantine time descending
            };

            /**
             * @struct Statistics
             * @brief Quarantine system statistics and metrics.
             * 
             * @details Provides comprehensive metrics for:
             * - Entry counts by status
             * - Breakdown by threat type and severity
             * - Operation counters (quarantine, restore, delete)
             * - Storage utilization
             * - Integrity check results
             * - Timestamps for oldest/newest entries
             */
            struct Statistics {
                // === Entry Counts ===
                uint64_t totalEntries = 0;          ///< Total entries ever created
                uint64_t activeEntries = 0;         ///< Currently active quarantine entries
                uint64_t restoredEntries = 0;       ///< Files that have been restored
                uint64_t deletedEntries = 0;        ///< Files permanently deleted
                
                // === Breakdown by Classification ===
                uint64_t entriesByType[256] = {};       ///< Count per ThreatType value
                uint64_t entriesBySeverity[5] = {};     ///< Count per ThreatSeverity value
                uint64_t entriesByStatus[6] = {};       ///< Count per QuarantineStatus value
                
                // === Operation Counters ===
                uint64_t totalQuarantines = 0;      ///< Total quarantine operations performed
                uint64_t totalRestorations = 0;     ///< Total restore operations performed
                uint64_t totalDeletions = 0;        ///< Total delete operations performed
                uint64_t failedOperations = 0;      ///< Total failed operations
                
                // === Storage Metrics ===
                size_t totalQuarantineSize = 0;     ///< Total bytes in quarantine vault
                size_t averageFileSize = 0;         ///< Average file size
                size_t largestFileSize = 0;         ///< Largest single file size
                
                // === Timestamps ===
                std::chrono::system_clock::time_point oldestEntry; ///< Oldest active entry
                std::chrono::system_clock::time_point newestEntry; ///< Most recent entry
                std::chrono::system_clock::time_point lastCleanup; ///< Last cleanup operation
                
                // === Integrity Metrics ===
                uint64_t cleanupCount = 0;          ///< Number of cleanup operations run
                uint64_t integrityChecksPassed = 0; ///< Successful integrity verifications
                uint64_t integrityChecksFailed = 0; ///< Failed integrity verifications
            };

            /** @} */ // end of Quarantine Data Structures

            // ============================================================================
            //                          LIFECYCLE MANAGEMENT
            // ============================================================================

            /** @name Lifecycle Methods
             *  Singleton access and initialization/shutdown operations.
             *  @{
             */

            /**
             * @brief Returns the singleton instance of QuarantineDB.
             * @return Reference to the global QuarantineDB instance.
             * @note Thread-safe via static initialization (C++11 guarantee).
             */
            static QuarantineDB& Instance();

            /**
             * @brief Initializes the quarantine system with provided configuration.
             * 
             * @param config Configuration settings for quarantine operations.
             * @param err Optional error output parameter.
             * @return true if initialization succeeded, false otherwise.
             * 
             * @details Initialization sequence:
             * 1. Validates configuration parameters
             * 2. Creates quarantine directory structure
             * 3. Opens/creates SQLite database
             * 4. Creates/upgrades schema if needed
             * 5. Derives encryption key from system parameters
             * 6. Loads existing statistics
             * 7. Starts background cleanup thread
             * 
             * @pre Database not already initialized
             * @post m_initialized is true on success
             * @warning Must be called before any quarantine operations
             */
            bool Initialize(const Config& config, DatabaseError* err = nullptr);

            /**
             * @brief Shuts down the quarantine system gracefully.
             * 
             * @details Shutdown sequence:
             * 1. Signals background cleanup thread to stop
             * 2. Waits for cleanup thread to finish
             * 3. Persists final statistics
             * 4. Clears encryption key from memory
             * 5. Closes database connection
             * 6. Resets initialization flag
             * 
             * @post m_initialized is false
             * @note Safe to call multiple times
             */
            void Shutdown();

            /**
             * @brief Checks if the quarantine system is initialized.
             * @return true if Initialize() succeeded and Shutdown() not called.
             * @note Thread-safe via atomic flag.
             */
            bool IsInitialized() const noexcept { return m_initialized.load(); }

            /** @} */ // end of Lifecycle Methods

            // ============================================================================
            //                       QUARANTINE OPERATIONS
            // ============================================================================

            /** @name Quarantine Operations
             *  Methods for quarantining, restoring, and deleting files.
             *  @{
             */

            /**
             * @brief Quarantines a file with basic threat information.
             * 
             * @param originalPath Full path to the file to quarantine.
             * @param threatType Classification of the detected threat.
             * @param severity Risk level of the threat.
             * @param threatName Detection name (e.g., "Trojan.GenericKD.12345").
             * @param detectionReason Why the file was flagged (optional).
             * @param err Optional error output parameter.
             * @return New entry ID on success, -1 on failure.
             * 
             * @details Process:
             * 1. Reads file content into memory
             * 2. Calculates MD5/SHA1/SHA256 hashes
             * 3. Compresses file content (if enabled)
             * 4. Encrypts compressed data (if enabled)
             * 5. Writes to quarantine vault
             * 6. Deletes original file
             * 7. Inserts metadata into database
             * 8. Logs audit event
             * 
             * @warning Original file is deleted on successful quarantine
             */
            int64_t QuarantineFile(std::wstring_view originalPath,
                                  ThreatType threatType,
                                  ThreatSeverity severity,
                                  std::wstring_view threatName,
                                  std::wstring_view detectionReason = L"",
                                  DatabaseError* err = nullptr);

            /**
             * @brief Quarantines with complete metadata and pre-read file data.
             * 
             * @param entry Complete QuarantineEntry with all metadata filled.
             * @param fileData Pre-read file content as byte vector.
             * @param err Optional error output parameter.
             * @return New entry ID on success, -1 on failure.
             * 
             * @details Use this when file content is already in memory
             * (e.g., from a previous scan operation). Skips file I/O.
             */
            int64_t QuarantineFileDetailed(const QuarantineEntry& entry,
                                          const std::vector<uint8_t>& fileData,
                                          DatabaseError* err = nullptr);

            /**
             * @brief Restores a quarantined file to the filesystem.
             * 
             * @param entryId ID of the quarantine entry to restore.
             * @param restorePath Destination path (empty = original location).
             * @param restoredBy User performing restoration (audit trail).
             * @param reason Reason for restoration (audit trail).
             * @param err Optional error output parameter.
             * @return true if restoration succeeded.
             * 
             * @details Process:
             * 1. Retrieves entry metadata
             * 2. Reads encrypted file from vault
             * 3. Decrypts file content
             * 4. Decompresses if needed
             * 5. Verifies hash integrity
             * 6. Writes to restore destination
             * 7. Updates entry status to Restored
             * 8. Logs audit event
             * 
             * @note Does NOT delete the quarantine copy
             * @warning Restored file may still be malicious - use with caution
             */
            bool RestoreFile(int64_t entryId,
                           std::wstring_view restorePath = L"",
                           std::wstring_view restoredBy = L"",
                           std::wstring_view reason = L"",
                           DatabaseError* err = nullptr);

            /**
             * @brief Permanently deletes a quarantined file.
             * 
             * @param entryId ID of the quarantine entry to delete.
             * @param deletedBy User performing deletion (audit trail).
             * @param reason Reason for deletion (audit trail).
             * @param err Optional error output parameter.
             * @return true if deletion succeeded.
             * 
             * @details Process:
             * 1. Retrieves entry metadata
             * 2. Deletes encrypted file from vault
             * 3. Updates entry status to Deleted
             * 4. Logs audit event
             * 
             * @warning This operation is irreversible
             */
            bool DeleteQuarantinedFile(int64_t entryId,
                                      std::wstring_view deletedBy = L"",
                                      std::wstring_view reason = L"",
                                      DatabaseError* err = nullptr);

            /**
             * @brief Quarantines multiple files in a single batch operation.
             * 
             * @param filePaths Vector of file paths to quarantine.
             * @param threatType Common threat type for all files.
             * @param severity Common severity for all files.
             * @param threatName Common threat name for all files.
             * @param err Optional error output parameter.
             * @return true if all files quarantined successfully.
             */
            bool QuarantineBatch(const std::vector<std::wstring>& filePaths,
                               ThreatType threatType,
                               ThreatSeverity severity,
                               std::wstring_view threatName,
                               DatabaseError* err = nullptr);

            /**
             * @brief Restores multiple quarantined files.
             * @param entryIds Vector of entry IDs to restore.
             * @param restoredBy User performing restoration.
             * @param err Optional error output parameter.
             * @return true if all restorations succeeded.
             */
            bool RestoreBatch(const std::vector<int64_t>& entryIds,
                            std::wstring_view restoredBy = L"",
                            DatabaseError* err = nullptr);

            /**
             * @brief Deletes multiple quarantined files.
             * @param entryIds Vector of entry IDs to delete.
             * @param deletedBy User performing deletion.
             * @param err Optional error output parameter.
             * @return true if all deletions succeeded.
             */
            bool DeleteBatch(const std::vector<int64_t>& entryIds,
                           std::wstring_view deletedBy = L"",
                           DatabaseError* err = nullptr);

            /** @} */ // end of Quarantine Operations

            // ============================================================================
            //                          QUERY OPERATIONS
            // ============================================================================

            /** @name Query Operations
             *  Methods for searching and retrieving quarantine entries.
             *  @{
             */

            /**
             * @brief Retrieves a single quarantine entry by ID.
             * @param id Unique entry identifier.
             * @param err Optional error output parameter.
             * @return QuarantineEntry if found, std::nullopt otherwise.
             */
            std::optional<QuarantineEntry> GetEntry(int64_t id, DatabaseError* err = nullptr);

            /**
             * @brief Queries quarantine entries with complex filtering.
             * 
             * @param filter QueryFilter specifying search criteria.
             * @param err Optional error output parameter.
             * @return Vector of matching QuarantineEntry objects.
             * 
             * @details Supports filtering by threat type, severity range, status,
             * time range, path patterns, hash patterns, and user/machine filters.
             */
            std::vector<QuarantineEntry> Query(const QueryFilter& filter,
                                              DatabaseError* err = nullptr);

            /**
             * @brief Retrieves entries of a specific threat type.
             * @param type ThreatType to filter by.
             * @param maxCount Maximum entries to return.
             * @param err Optional error output parameter.
             * @return Vector of matching entries.
             */
            std::vector<QuarantineEntry> GetByThreatType(ThreatType type,
                                                         size_t maxCount = 1000,
                                                         DatabaseError* err = nullptr);

            /**
             * @brief Retrieves entries of a specific severity level.
             * @param severity ThreatSeverity to filter by.
             * @param maxCount Maximum entries to return.
             * @param err Optional error output parameter.
             * @return Vector of matching entries.
             */
            std::vector<QuarantineEntry> GetBySeverity(ThreatSeverity severity,
                                                      size_t maxCount = 1000,
                                                      DatabaseError* err = nullptr);

            /**
             * @brief Retrieves entries with a specific status.
             * @param status QuarantineStatus to filter by.
             * @param maxCount Maximum entries to return.
             * @param err Optional error output parameter.
             * @return Vector of matching entries.
             */
            std::vector<QuarantineEntry> GetByStatus(QuarantineStatus status,
                                                    size_t maxCount = 1000,
                                                    DatabaseError* err = nullptr);

            /**
             * @brief Retrieves all active (not restored/deleted) entries.
             * @param maxCount Maximum entries to return.
             * @param err Optional error output parameter.
             * @return Vector of active quarantine entries.
             */
            std::vector<QuarantineEntry> GetActiveEntries(size_t maxCount = 1000,
                                                         DatabaseError* err = nullptr);

            /**
             * @brief Retrieves most recently quarantined entries.
             * @param count Number of entries to retrieve.
             * @param err Optional error output parameter.
             * @return Vector of entries sorted by quarantine time (newest first).
             */
            std::vector<QuarantineEntry> GetRecent(size_t count = 100,
                                                  DatabaseError* err = nullptr);

            /**
             * @brief Searches for entries by file hash.
             * 
             * @param hash Hash value to search (MD5, SHA1, or SHA256).
             * @param err Optional error output parameter.
             * @return Vector of entries matching the hash.
             * 
             * @details Searches across all three hash fields.
             */
            std::vector<QuarantineEntry> SearchByHash(std::wstring_view hash,
                                                     DatabaseError* err = nullptr);

            /**
             * @brief Searches for entries by original filename.
             * 
             * @param fileName Filename or pattern to search.
             * @param maxCount Maximum entries to return.
             * @param err Optional error output parameter.
             * @return Vector of entries with matching filenames.
             */
            std::vector<QuarantineEntry> SearchByFileName(std::wstring_view fileName,
                                                         size_t maxCount = 1000,
                                                         DatabaseError* err = nullptr);

            /**
             * @brief Counts entries matching optional filter criteria.
             * @param filter Optional filter (nullptr = count all entries).
             * @param err Optional error output parameter.
             * @return Number of matching entries, -1 on error.
             */
            int64_t CountEntries(const QueryFilter* filter = nullptr,
                               DatabaseError* err = nullptr);

            /** @} */ // end of Query Operations

            // ============================================================================
            //                          FILE OPERATIONS
            // ============================================================================

            /** @name File Operations
             *  Methods for file data extraction and integrity verification.
             *  @{
             */

            /**
             * @brief Extracts decrypted file content from quarantine.
             * 
             * @param entryId ID of the quarantine entry.
             * @param outData Output vector for decrypted file content.
             * @param err Optional error output parameter.
             * @return true if extraction succeeded.
             * 
             * @details Reads encrypted file, decrypts, decompresses, and
             * returns original file content. Does NOT restore the file.
             */
            bool ExtractFileData(int64_t entryId,
                               std::vector<uint8_t>& outData,
                               DatabaseError* err = nullptr);

            /**
             * @brief Retrieves stored hashes without file extraction.
             * 
             * @param entryId ID of the quarantine entry.
             * @param md5 Output for MD5 hash (32 hex characters).
             * @param sha1 Output for SHA-1 hash (40 hex characters).
             * @param sha256 Output for SHA-256 hash (64 hex characters).
             * @param err Optional error output parameter.
             * @return true if hashes retrieved successfully.
             */
            bool GetFileHash(int64_t entryId,
                           std::wstring& md5,
                           std::wstring& sha1,
                           std::wstring& sha256,
                           DatabaseError* err = nullptr);

            /**
             * @brief Verifies integrity of a quarantined file.
             * 
             * @param entryId ID of the quarantine entry to verify.
             * @param err Optional error output parameter.
             * @return true if file integrity is valid.
             * 
             * @details Extracts file, recalculates SHA256, and compares
             * against stored hash. Updates statistics accordingly.
             */
            bool VerifyIntegrity(int64_t entryId, DatabaseError* err = nullptr);

            /**
             * @brief Updates metadata for an existing quarantine entry.
             * @param entry QuarantineEntry with updated fields.
             * @param err Optional error output parameter.
             * @return true if update succeeded.
             */
            bool UpdateEntry(const QuarantineEntry& entry, DatabaseError* err = nullptr);

            /**
             * @brief Appends notes to an existing quarantine entry.
             * @param entryId ID of the entry to update.
             * @param notes Additional notes to append.
             * @param err Optional error output parameter.
             * @return true if notes added successfully.
             */
            bool AddNotes(int64_t entryId,
                        std::wstring_view notes,
                        DatabaseError* err = nullptr);

            /** @} */ // end of File Operations

            // ============================================================================
            //                       MANAGEMENT OPERATIONS
            // ============================================================================

            /** @name Management Operations
             *  Methods for cleanup, export, import, and analysis submission.
             *  @{
             */

            /**
             * @brief Removes entries that exceed the retention period.
             * @param err Optional error output parameter.
             * @return true if cleanup completed (even if no entries removed).
             */
            bool CleanupExpired(DatabaseError* err = nullptr);

            /**
             * @brief Removes oldest entries until vault is under target size.
             * @param targetSize Target vault size in bytes.
             * @param err Optional error output parameter.
             * @return true if cleanup completed successfully.
             */
            bool CleanupBySize(size_t targetSize, DatabaseError* err = nullptr);

            /**
             * @brief Permanently deletes all quarantine entries.
             * 
             * @param confirmed Must be true to proceed (safety check).
             * @param err Optional error output parameter.
             * @return true if all entries deleted.
             * 
             * @warning Irreversible operation - requires confirmation flag
             */
            bool DeleteAll(bool confirmed, DatabaseError* err = nullptr);

            /**
             * @brief Exports a single quarantine entry to a JSON file.
             * 
             * @param entryId ID of the entry to export.
             * @param exportPath Destination file path.
             * @param includeMetadata Whether to include full metadata.
             * @param err Optional error output parameter.
             * @return true if export succeeded.
             * 
             * @details Exports include Base64-encoded file content for portability.
             */
            bool ExportEntry(int64_t entryId,
                           std::wstring_view exportPath,
                           bool includeMetadata = true,
                           DatabaseError* err = nullptr);

            /**
             * @brief Imports a quarantine entry from a JSON export file.
             * 
             * @param importPath Path to the JSON export file.
             * @param err Optional error output parameter.
             * @return New entry ID on success, -1 on failure.
             * 
             * @details Validates hash integrity during import.
             */
            int64_t ImportEntry(std::wstring_view importPath,
                              DatabaseError* err = nullptr);

            /**
             * @brief Prepares a quarantined file for cloud analysis submission.
             * 
             * @param entryId ID of the entry to submit.
             * @param submissionEndpoint API endpoint URL for tracking.
             * @param err Optional error output parameter.
             * @return true if submission was prepared and status updated.
             * 
             * @details Validates entry state, creates export preparation,
             * updates status to Pending, and logs audit event. Actual network
             * transmission should be handled by ThreatIntel module integration.
             * 
             * @pre Entry must be in Active or Pending status
             * @post Entry status changed to Pending with submission notes
             */
            bool SubmitForAnalysis(int64_t entryId,
                                 std::wstring_view submissionEndpoint,
                                 DatabaseError* err = nullptr);

            /** @} */ // end of Management Operations

            // ============================================================================
            //                      STATISTICS & REPORTING
            // ============================================================================

            /** @name Statistics & Reporting
             *  Methods for retrieving metrics and generating reports.
             *  @{
             */

            /**
             * @brief Retrieves current quarantine statistics.
             * @param err Optional error output parameter (unused).
             * @return Copy of current Statistics structure.
             */
            Statistics GetStatistics(DatabaseError* err = nullptr);

            /**
             * @brief Resets all statistics counters to zero.
             */
            void ResetStatistics();

            /**
             * @brief Retrieves current configuration.
             * @return Copy of current Config structure.
             */
            Config GetConfig() const;

            /**
             * @brief Updates the maximum retention period.
             * @param days New retention period.
             */
            void SetMaxRetentionDays(std::chrono::hours days);

            /**
             * @brief Updates the maximum quarantine vault size.
             * @param sizeBytes New maximum size in bytes.
             */
            void SetMaxQuarantineSize(size_t sizeBytes);

            /**
             * @brief Generates a comprehensive text-based report.
             * 
             * @param filter Optional filter for entries to include.
             * @return Formatted wide string report.
             * 
             * @details Report includes header, statistics, threat breakdown,
             * severity breakdown, and list of recent/filtered entries.
             */
            std::wstring GenerateReport(const QueryFilter* filter = nullptr);

            /**
             * @brief Exports quarantine metadata to a JSON file.
             * 
             * @param filePath Destination file path.
             * @param filter Optional filter for which entries to export.
             * @param err Optional error output parameter.
             * @return true if export succeeded.
             * 
             * @note Exports metadata only, not file content
             */
            bool ExportToJSON(std::wstring_view filePath,
                            const QueryFilter* filter = nullptr,
                            DatabaseError* err = nullptr);

            /**
             * @brief Exports quarantine metadata to a CSV file.
             * 
             * @param filePath Destination file path.
             * @param filter Optional filter for which entries to export.
             * @param err Optional error output parameter.
             * @return true if export succeeded.
             * 
             * @details UTF-8 encoded with BOM, proper field escaping.
             */
            bool ExportToCSV(std::wstring_view filePath,
                           const QueryFilter* filter = nullptr,
                           DatabaseError* err = nullptr);

            /** @} */ // end of Statistics & Reporting

            // ============================================================================
            //                       UTILITY FUNCTIONS
            // ============================================================================

            /** @name Utility Functions
             *  Static conversion methods for enums and strings.
             *  @{
             */

            /** @brief Converts ThreatType to human-readable string. */
            static std::wstring ThreatTypeToString(ThreatType type);
            /** @brief Parses string to ThreatType enum. */
            static ThreatType StringToThreatType(std::wstring_view str);

            /** @brief Converts ThreatSeverity to human-readable string. */
            static std::wstring ThreatSeverityToString(ThreatSeverity severity);
            /** @brief Parses string to ThreatSeverity enum. */
            static ThreatSeverity StringToThreatSeverity(std::wstring_view str);

            /** @brief Converts QuarantineStatus to human-readable string. */
            static std::wstring QuarantineStatusToString(QuarantineStatus status);
            /** @brief Parses string to QuarantineStatus enum. */
            static QuarantineStatus StringToQuarantineStatus(std::wstring_view str);

            /** @brief Converts QuarantineAction to human-readable string. */
            static std::wstring QuarantineActionToString(QuarantineAction action);

            /** @} */ // end of Utility Functions

            // ============================================================================
            //                      MAINTENANCE OPERATIONS
            // ============================================================================

            /** @name Maintenance Operations
             *  Database maintenance, optimization, and backup methods.
             *  @{
             */

            /**
             * @brief Reclaims unused database space.
             * @param err Optional error output parameter.
             * @return true if vacuum succeeded.
             */
            bool Vacuum(DatabaseError* err = nullptr);

            /**
             * @brief Verifies database integrity.
             * @param err Optional error output parameter.
             * @return true if database is intact.
             */
            bool CheckIntegrity(DatabaseError* err = nullptr);

            /**
             * @brief Optimizes database for performance.
             * @param err Optional error output parameter.
             * @return true if optimization succeeded.
             */
            bool Optimize(DatabaseError* err = nullptr);

            /**
             * @brief Rebuilds all database indices.
             * @param err Optional error output parameter.
             * @return true if rebuild succeeded.
             */
            bool RebuildIndices(DatabaseError* err = nullptr);

            /**
             * @brief Creates a full backup of the quarantine vault.
             * 
             * @param backupPath Destination file path.
             * @param err Optional error output parameter.
             * @return true if backup succeeded.
             * 
             * @details Includes all entries with encrypted file content.
             * @warning Backup files can be very large.
             */
            bool BackupQuarantine(std::wstring_view backupPath, DatabaseError* err = nullptr);

            /**
             * @brief Restores quarantine from a backup file.
             * 
             * @param backupPath Path to backup file.
             * @param err Optional error output parameter.
             * @return true if at least one entry restored.
             * 
             * @details Validates hash integrity during restore.
             * @note Creates new entry IDs, does not preserve originals.
             */
            bool RestoreQuarantine(std::wstring_view backupPath, DatabaseError* err = nullptr);

            /**
             * @brief Logs an audit event for compliance tracking.
             * 
             * @param action The action that was performed.
             * @param entryId ID of the affected entry (0 for bulk operations).
             * @param details Additional details about the action.
             */
            void logAuditEvent(QuarantineAction action,
                int64_t entryId,
                std::wstring_view details);

            /** @} */ // end of Maintenance Operations

        private:
            // ============================================================================
            //                      PRIVATE CONSTRUCTORS
            // ============================================================================

            /** @brief Private constructor for singleton pattern. */
            QuarantineDB();
            
            /** @brief Destructor - calls Shutdown() if still initialized. */
            ~QuarantineDB();

            /** @brief Deleted copy constructor (singleton). */
            QuarantineDB(const QuarantineDB&) = delete;
            
            /** @brief Deleted copy assignment (singleton). */
            QuarantineDB& operator=(const QuarantineDB&) = delete;

            // ============================================================================
            //                      INTERNAL OPERATIONS
            // ============================================================================

            /** @name Schema Management
             *  Internal methods for database schema creation and upgrades.
             *  @{
             */

            /**
             * @brief Creates the initial database schema.
             * @param err Optional error output parameter.
             * @return true if schema created successfully.
             */
            bool createSchema(DatabaseError* err);

            /**
             * @brief Upgrades database schema from one version to another.
             * @param currentVersion Current schema version.
             * @param targetVersion Target schema version.
             * @param err Optional error output parameter.
             * @return true if upgrade succeeded.
             */
            bool upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err);

            /** @} */

            /** @name Database Operations
             *  Internal CRUD operations for quarantine entries.
             *  @{
             */

            /**
             * @brief Inserts a new quarantine entry into the database.
             * @param entry Entry to insert (id field ignored).
             * @param err Optional error output parameter.
             * @return New entry ID, or -1 on failure.
             */
            int64_t dbInsertEntry(const QuarantineEntry& entry, DatabaseError* err);

            /**
             * @brief Updates an existing quarantine entry.
             * @param entry Entry with updated fields.
             * @param err Optional error output parameter.
             * @return true if update succeeded.
             */
            bool dbUpdateEntry(const QuarantineEntry& entry, DatabaseError* err);

            /**
             * @brief Deletes a quarantine entry from the database.
             * @param id Entry ID to delete.
             * @param err Optional error output parameter.
             * @return true if deletion succeeded.
             */
            bool dbDeleteEntry(int64_t id, DatabaseError* err);

            /**
             * @brief Retrieves a single entry by ID.
             * @param id Entry ID to retrieve.
             * @param err Optional error output parameter.
             * @return Entry if found, nullopt otherwise.
             */
            std::optional<QuarantineEntry> dbSelectEntry(int64_t id, DatabaseError* err);

            /**
             * @brief Executes a SELECT query and returns multiple entries.
             * @param sql SQL query string.
             * @param params Query parameters.
             * @param err Optional error output parameter.
             * @return Vector of matching entries.
             */
            std::vector<QuarantineEntry> dbSelectEntries(std::string_view sql,
                                                        const std::vector<std::string>& params,
                                                        DatabaseError* err);

            /** @} */

            /** @name Query Builders
             *  Internal methods for constructing SQL queries from filters.
             *  @{
             */

            /**
             * @brief Builds a SELECT SQL statement from QueryFilter.
             * @param filter Query filter criteria.
             * @param outParams Output vector for query parameters.
             * @return SQL query string.
             */
            std::string buildQuerySQL(const QueryFilter& filter, std::vector<std::string>& outParams);

            /**
             * @brief Builds a COUNT SQL statement from QueryFilter.
             * @param filter Query filter criteria.
             * @param outParams Output vector for query parameters.
             * @return SQL count query string.
             */
            std::string buildCountSQL(const QueryFilter& filter, std::vector<std::string>& outParams);

            /** @} */

            /** @name File Operations
             *  Internal encryption, decryption, and compression methods.
             *  @{
             */

            /**
             * @brief Encrypts and stores file data to the quarantine vault.
             * @param fileData Raw file content to encrypt.
             * @param quarantinePath Destination path in vault.
             * @param err Optional error output parameter.
             * @return true if operation succeeded.
             */
            bool encryptAndStoreFile(const std::vector<uint8_t>& fileData,
                                   std::wstring_view quarantinePath,
                                   DatabaseError* err);

            /**
             * @brief Decrypts and loads file data from the quarantine vault.
             * @param quarantinePath Source path in vault.
             * @param outData Output vector for decrypted content.
             * @param err Optional error output parameter.
             * @return true if operation succeeded.
             */
            bool decryptAndLoadFile(std::wstring_view quarantinePath,
                                  std::vector<uint8_t>& outData,
                                  DatabaseError* err);

            /**
             * @brief Compresses data using configured algorithm.
             * @param input Raw data to compress.
             * @param output Compressed data output.
             * @return true if compression succeeded.
             */
            bool compressData(const std::vector<uint8_t>& input,
                            std::vector<uint8_t>& output);

            /**
             * @brief Decompresses data using configured algorithm.
             * @param input Compressed data.
             * @param output Decompressed data output.
             * @return true if decompression succeeded.
             */
            bool decompressData(const std::vector<uint8_t>& input,
                              std::vector<uint8_t>& output);

            /** @} */

            /** @name Hash Calculation
             *  Internal methods for computing file hashes.
             *  @{
             */

            /**
             * @brief Calculates MD5, SHA-1, and SHA-256 hashes.
             * @param data File content to hash.
             * @param md5 Output MD5 hash.
             * @param sha1 Output SHA-1 hash.
             * @param sha256 Output SHA-256 hash.
             * @return true if all hashes calculated successfully.
             */
            bool calculateHashes(const std::vector<uint8_t>& data,
                               std::wstring& md5,
                               std::wstring& sha1,
                               std::wstring& sha256);

            /** @brief Calculates MD5 hash of data. */
            std::wstring calculateMD5(const std::vector<uint8_t>& data);
            
            /** @brief Calculates SHA-1 hash of data. */
            std::wstring calculateSHA1(const std::vector<uint8_t>& data);
            
            /** @brief Calculates SHA-256 hash of data. */
            std::wstring calculateSHA256(const std::vector<uint8_t>& data);

            /** @} */

            /** @name Path Management
             *  Internal methods for quarantine path handling.
             *  @{
             */

            /**
             * @brief Generates unique quarantine file path for an entry.
             * @param entryId Entry ID to generate path for.
             * @return Full path to quarantine file.
             */
            std::wstring generateQuarantinePath(int64_t entryId);

            /**
             * @brief Ensures quarantine directory structure exists.
             * @param err Optional error output parameter.
             * @return true if directory exists or was created.
             */
            bool ensureQuarantineDirectory(DatabaseError* err);

            /** @} */

            /** @name Cleanup Helpers
             *  Internal methods for background cleanup operations.
             *  @{
             */

            /**
             * @brief Removes entries exceeding retention period.
             * @param err Optional error output parameter.
             * @return true if cleanup completed.
             */
            bool cleanupOldEntries(DatabaseError* err);

            /**
             * @brief Removes entries with corrupted files.
             * @param err Optional error output parameter.
             * @return true if cleanup completed.
             */
            bool cleanupCorruptedEntries(DatabaseError* err);

            /**
             * @brief Background thread function for periodic cleanup.
             * @details Runs hourly cleanup cycle, checking retention
             * and size limits. Wakes on shutdown signal.
             */
            void backgroundCleanupThread();

            /** @} */

            /** @name Statistics Helpers
             *  Internal methods for statistics management.
             *  @{
             */

            /**
             * @brief Updates statistics after an operation.
             * @param entry Entry involved in the operation.
             * @param action Action that was performed.
             */
            void updateStatistics(const QuarantineEntry& entry, QuarantineAction action);

            /**
             * @brief Recalculates all statistics from database.
             * @param err Optional error output parameter.
             */
            void recalculateStatistics(DatabaseError* err);

            /** @} */

            /** @name Utility Helpers
             *  Internal utility methods for data conversion.
             *  @{
             */

            /**
             * @brief Converts database row to QuarantineEntry.
             * @param result Query result positioned at current row.
             * @return Populated QuarantineEntry.
             */
            QuarantineEntry rowToQuarantineEntry(QueryResult& result);

            /**
             * @brief Converts time_point to ISO 8601 string.
             * @param tp Time point to convert.
             * @return ISO 8601 formatted string.
             */
            static std::string timePointToString(std::chrono::system_clock::time_point tp);

            /**
             * @brief Parses ISO 8601 string to time_point.
             * @param str ISO 8601 formatted string.
             * @return Parsed time point.
             */
            static std::chrono::system_clock::time_point stringToTimePoint(std::string_view str);

            /** @} */

            /** @name Encryption Key Management
             *  Internal methods for encryption key handling.
             *  @{
             */

            /**
             * @brief Derives encryption key from system parameters.
             * @return Derived encryption key bytes.
             */
            std::vector<uint8_t> deriveEncryptionKey();

            /**
             * @brief Generates random salt for key derivation.
             * @return Random salt bytes.
             */
            std::vector<uint8_t> generateSalt();

            /** @} */

            // ============================================================================
            //                          STATE MEMBERS
            // ============================================================================

            /** @name Initialization State
             *  @{
             */
            std::atomic<bool> m_initialized{ false };   ///< Initialization flag (atomic for thread safety)
            Config m_config;                            ///< Current configuration
            mutable std::shared_mutex m_configMutex;    ///< Mutex protecting config access
            /** @} */

            /** @name Background Cleanup State
             *  @{
             */
            std::thread m_cleanupThread;                ///< Background cleanup thread handle
            std::atomic<bool> m_shutdownCleanup{ false }; ///< Shutdown signal for cleanup thread
            std::condition_variable m_cleanupCV;        ///< Condition variable for cleanup timing
            std::mutex m_cleanupMutex;                  ///< Mutex for cleanup condition variable
            std::chrono::steady_clock::time_point m_lastCleanup; ///< Last cleanup timestamp
            /** @} */

            /** @name Statistics State
             *  @{
             */
            mutable std::mutex m_statsMutex;            ///< Mutex protecting statistics access
            Statistics m_stats;                         ///< Current statistics snapshot
            /** @} */

            /** @name System Information
             *  @{
             */
            std::wstring m_machineName;                 ///< Cached machine name
            std::wstring m_userName;                    ///< Cached user name
            /** @} */

            /** @name Encryption Key State
             *  @{
             */
            mutable std::mutex m_keyMutex;              ///< Mutex protecting encryption key
            std::vector<uint8_t> m_masterKey;           ///< Master encryption key (memory-only)
            /** @} */
        };

    } // namespace Database
} // namespace ShadowStrike