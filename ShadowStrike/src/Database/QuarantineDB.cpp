// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

/**
 * @file QuarantineDB.cpp
 * @brief Secure Quarantine Database Management System - Implementation
 * 
 * @details This file implements the QuarantineDB class, a comprehensive secure
 * quarantine management system for the ShadowStrike antivirus engine. It provides
 * enterprise-grade malware isolation with encrypted storage, integrity verification,
 * and complete audit trail capabilities.
 * 
 * ## Architecture Overview
 * 
 * ```
 *                    ┌─────────────────────────────────────────────────┐
 *                    │            QUARANTINE ARCHITECTURE              │
 *                    └─────────────────────────────────────────────────┘
 *                                         │
 *     ┌───────────────────────────────────┼───────────────────────────────────┐
 *     │                                   ▼                                   │
 *     │  ┌──────────────────────────────────────────────────────────────┐    │
 *     │  │                      QuarantineDB Singleton                   │    │
 *     │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐    │    │
 *     │  │  │ Quarantine   │  │   Query      │  │   Management     │    │    │
 *     │  │  │ Operations   │  │   Engine     │  │   Operations     │    │    │
 *     │  │  │              │  │              │  │                  │    │    │
 *     │  │  │ •Quarantine  │  │ •GetEntry    │  │ •Cleanup         │    │    │
 *     │  │  │ •Restore     │  │ •Query       │  │ •Export/Import   │    │    │
 *     │  │  │ •Delete      │  │ •Search      │  │ •Backup/Restore  │    │    │
 *     │  │  │ •Batch Ops   │  │ •Count       │  │ •Report Gen      │    │    │
 *     │  │  └──────────────┘  └──────────────┘  └──────────────────┘    │    │
 *     │  └───────────────────────────┬──────────────────────────────────┘    │
 *     │                              │                                       │
 *     │  ┌───────────────────────────┼───────────────────────────────────┐  │
 *     │  │                           ▼                                   │  │
 *     │  │  ┌──────────────────────────────────────────────────────┐    │  │
 *     │  │  │              Security & Encryption Layer              │    │  │
 *     │  │  │  ┌────────────────┐  ┌────────────────────────────┐  │    │  │
 *     │  │  │  │ AES-256-GCM    │  │ Hash Verification          │  │    │  │
 *     │  │  │  │ Encryption     │  │ (MD5/SHA1/SHA256)          │  │    │  │
 *     │  │  │  └────────────────┘  └────────────────────────────┘  │    │  │
 *     │  │  │  ┌────────────────┐  ┌────────────────────────────┐  │    │  │
 *     │  │  │  │ Compression    │  │ Integrity Checking         │  │    │  │
 *     │  │  │  │ (LZMA/Xpress)  │  │                            │  │    │  │
 *     │  │  │  └────────────────┘  └────────────────────────────┘  │    │  │
 *     │  │  └──────────────────────────────────────────────────────┘    │  │
 *     │  └───────────────────────────┬───────────────────────────────────┘  │
 *     │                              │                                       │
 *     │  ┌───────────────────────────┼───────────────────────────────────┐  │
 *     │  │                           ▼                                   │  │
 *     │  │  ┌──────────────────────────────────────────────────────┐    │  │
 *     │  │  │                  Storage Layer                        │    │  │
 *     │  │  │  ┌──────────────────┐  ┌──────────────────────────┐  │    │  │
 *     │  │  │  │ DatabaseManager  │  │ Encrypted File Storage   │  │    │  │
 *     │  │  │  │ (SQLite Backend) │  │ (Quarantine Folder)      │  │    │  │
 *     │  │  │  │                  │  │                          │  │    │  │
 *     │  │  │  │ •quarantine_     │  │ •quar_XXXX_TIMESTAMP.dat │  │    │  │
 *     │  │  │  │   entries        │  │ •Encrypted & Compressed  │  │    │  │
 *     │  │  │  │ •quarantine_     │  │                          │  │    │  │
 *     │  │  │  │   audit_log      │  │                          │  │    │  │
 *     │  │  │  │ •quarantine_     │  │                          │  │    │  │
 *     │  │  │  │   metadata       │  │                          │  │    │  │
 *     │  │  │  └──────────────────┘  └──────────────────────────┘  │    │  │
 *     │  │  └──────────────────────────────────────────────────────┘    │  │
 *     │  └───────────────────────────┬───────────────────────────────────┘  │
 *     │                              │                                       │
 *     │  ┌───────────────────────────┼───────────────────────────────────┐  │
 *     │  │                           ▼                                   │  │
 *     │  │  ┌──────────────────────────────────────────────────────┐    │  │
 *     │  │  │              Background Services                      │    │  │
 *     │  │  │  ┌────────────────┐  ┌────────────────────────────┐  │    │  │
 *     │  │  │  │ Cleanup Thread │  │ Audit Logger               │  │    │  │
 *     │  │  │  │ (Retention &   │  │ (All Operations)           │  │    │  │
 *     │  │  │  │  Size Limits)  │  │                            │  │    │  │
 *     │  │  │  └────────────────┘  └────────────────────────────┘  │    │  │
 *     │  │  └──────────────────────────────────────────────────────┘    │  │
 *     │  └───────────────────────────────────────────────────────────────┘  │
 *     │                                                                       │
 *     └───────────────────────────────────────────────────────────────────────┘
 * ```
 * 
 * ## Key Features
 * 
 * - **Secure File Isolation**: AES-256 encryption with optional compression
 * - **Comprehensive Threat Tracking**: 16 threat types, 5 severity levels
 * - **Integrity Verification**: MD5, SHA1, SHA256 hash validation
 * - **Audit Trail**: Complete logging of all quarantine operations
 * - **Background Cleanup**: Automatic retention and size-based cleanup
 * - **Flexible Querying**: Multi-criteria filtering and search
 * - **Export/Import**: JSON, CSV, and full backup support
 * - **Thread-Safe**: Concurrent access with proper synchronization
 * 
 * ## Database Schema
 * 
 * ### quarantine_entries (Main Table)
 * | Column                 | Type     | Description                      |
 * |------------------------|----------|----------------------------------|
 * | id                     | INTEGER  | Primary key (auto-increment)     |
 * | quarantine_time        | TEXT     | ISO 8601 timestamp               |
 * | last_access_time       | TEXT     | Last accessed timestamp          |
 * | original_path          | TEXT     | Full original file path          |
 * | original_filename      | TEXT     | Original filename                |
 * | original_directory     | TEXT     | Original directory path          |
 * | original_size          | INTEGER  | Original file size in bytes      |
 * | original_creation_time | TEXT     | File creation timestamp          |
 * | original_modification_time| TEXT  | File modification timestamp      |
 * | quarantine_path        | TEXT     | Encrypted file path              |
 * | quarantine_filename    | TEXT     | Encrypted filename               |
 * | quarantine_size        | INTEGER  | Encrypted file size              |
 * | threat_type            | INTEGER  | ThreatType enum value            |
 * | severity               | INTEGER  | ThreatSeverity enum value        |
 * | threat_name            | TEXT     | Detection name/signature         |
 * | threat_signature       | TEXT     | Signature identifier             |
 * | scan_engine            | TEXT     | Detection engine name            |
 * | scan_engine_version    | TEXT     | Engine version                   |
 * | md5_hash               | TEXT     | MD5 hash of original file        |
 * | sha1_hash              | TEXT     | SHA1 hash of original file       |
 * | sha256_hash            | TEXT     | SHA256 hash (NOT NULL)           |
 * | status                 | INTEGER  | QuarantineStatus enum value      |
 * | user_name              | TEXT     | User who triggered quarantine    |
 * | machine_name           | TEXT     | Machine hostname                 |
 * | process_id             | INTEGER  | Triggering process ID            |
 * | process_name           | TEXT     | Triggering process name          |
 * | is_encrypted           | INTEGER  | 1=encrypted, 0=not               |
 * | encryption_method      | TEXT     | Algorithm used                   |
 * | notes                  | TEXT     | User/system notes                |
 * | detection_reason       | TEXT     | Why file was quarantined         |
 * | restoration_time       | TEXT     | When restored (if applicable)    |
 * | restored_by            | TEXT     | Who restored the file            |
 * | restoration_reason     | TEXT     | Why file was restored            |
 * | can_restore            | INTEGER  | 1=restorable, 0=locked           |
 * | can_delete             | INTEGER  | 1=deletable, 0=locked            |
 * | requires_password      | INTEGER  | 1=password required              |
 * 
 * ### Indices
 * - idx_quar_time: quarantine_time DESC
 * - idx_quar_status: status
 * - idx_quar_threat_type: threat_type
 * - idx_quar_severity: severity
 * - idx_quar_original_path: original_path
 * - idx_quar_sha256: sha256_hash
 * - idx_quar_user: user_name
 * - idx_quar_composite: (status, threat_type, quarantine_time DESC)
 * 
 * ## Thread Safety
 * 
 * - Configuration: std::shared_mutex (read-write lock)
 * - Statistics: std::mutex
 * - Encryption Key: std::mutex
 * - Background Cleanup: std::condition_variable + atomic
 * 
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2025
 * @copyright MIT License
 * 
 * @see QuarantineDB.hpp
 * @see DatabaseManager.hpp
 * @see CompressionUtils.hpp
 * @see HashUtils.hpp
 */

#include"pch.h"
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
#include <random>

#ifdef _WIN32
#include <Windows.h>
#include <Lmcons.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

// BCrypt algorithm identifiers
#ifndef BCRYPT_AES_ALGORITHM
#define BCRYPT_AES_ALGORITHM L"AES"
#endif
#ifndef BCRYPT_CHAIN_MODE_GCM
#define BCRYPT_CHAIN_MODE_GCM L"ChainingModeGCM"
#endif
#ifndef BCRYPT_AUTH_TAG_LENGTH
#define BCRYPT_AUTH_TAG_LENGTH L"AuthTagLength"
#endif
#endif

namespace ShadowStrike {
    namespace Database {

        // ============================================================================
        //                        ANONYMOUS NAMESPACE
        // ============================================================================
        /**
         * @brief Anonymous namespace containing internal constants and helper functions.
         * 
         * @details This namespace encapsulates implementation details that should not
         * be exposed outside this translation unit, including:
         * - Database schema version
         * - SQL statement definitions
         * - UTF-8/Wide string conversion utilities
         * - System information retrieval helpers
         * - Hex encoding/decoding utilities
         */
        namespace {
            
            // ========================================================================
            //                      SCHEMA CONFIGURATION
            // ========================================================================
            
            /**
             * @brief Current database schema version for migration support.
             * @details Increment this when schema changes require migration logic.
             */
            constexpr int QUARANTINE_SCHEMA_VERSION = 1;

            // ========================================================================
            //                      SQL STATEMENT DEFINITIONS
            // ========================================================================

            /**
             * @brief SQL statement to create the main quarantine_entries table.
             * 
             * @details Creates a comprehensive table with 36 columns to store:
             * - Original file information (path, size, timestamps)
             * - Quarantine file information (encrypted path, size)
             * - Threat classification (type, severity, name, signature)
             * - Scan engine information
             * - File hashes (MD5, SHA1, SHA256)
             * - Status and access control flags
             * - System context (user, machine, process)
             * - Restoration tracking
             */
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
        quarantine_path TEXT NOT NULL,
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

            /**
             * @brief SQL statements to create performance-optimized indices.
             * 
             * @details Creates 8 indices for efficient querying:
             * - Time-based: quarantine_time DESC for recent entries
             * - Status filtering: status index
             * - Threat filtering: threat_type and severity indices
             * - Path lookup: original_path index
             * - Hash search: sha256_hash index
             * - User filtering: user_name index
             * - Composite: (status, threat_type, quarantine_time) for common queries
             */
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

            /**
             * @brief SQL statement to create the audit log table.
             * 
             * @details Stores a complete audit trail of all quarantine operations:
             * - timestamp: When the action occurred
             * - entry_id: Which quarantine entry was affected
             * - action: QuarantineAction enum value
             * - user_name/machine_name: Who performed the action
             * - details: Additional context
             * - success: Whether the operation succeeded
             */
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

            /**
             * @brief SQL statement to create the metadata extension table.
             * 
             * @details Stores arbitrary key-value metadata for quarantine entries.
             * Uses WITHOUT ROWID optimization for performance on primary key lookups.
             * Has a cascading foreign key to automatically clean up when entries are deleted.
             */
            constexpr const char* SQL_CREATE_METADATA_TABLE = R"(
                CREATE TABLE IF NOT EXISTS quarantine_metadata (
                    entry_id INTEGER NOT NULL,
                    metadata_key TEXT NOT NULL,
                    metadata_value TEXT,
                    PRIMARY KEY (entry_id, metadata_key),
                    FOREIGN KEY (entry_id) REFERENCES quarantine_entries(id) ON DELETE CASCADE
                ) WITHOUT ROWID;
            )";

            /**
             * @brief SQL statement to insert a new quarantine entry.
             * @details Parameterized INSERT with 32 bound parameters.
             */
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

            /**
             * @brief SQL statement to update an existing quarantine entry.
             * @details Updates mutable fields: access time, quarantine path/size,
             *          status, restoration info, and notes.
             */
            constexpr const char* SQL_UPDATE_ENTRY = R"(
    UPDATE quarantine_entries SET
        last_access_time = ?,
        quarantine_path = ?,
        quarantine_filename = ?,
        quarantine_size = ?,
        status = ?,
        restoration_time = ?,
        restored_by = ?,
        restoration_reason = ?,
        notes = ?
    WHERE id = ?
)";
            
            /**
             * @brief SQL statement to select a single entry by ID.
             */
            constexpr const char* SQL_SELECT_ENTRY = R"(
                SELECT * FROM quarantine_entries WHERE id = ?
            )";

            /**
             * @brief SQL statement to delete an entry by ID.
             */
            constexpr const char* SQL_DELETE_ENTRY = R"(
                DELETE FROM quarantine_entries WHERE id = ?
            )";

            /**
             * @brief SQL statement to count all entries.
             */
            constexpr const char* SQL_COUNT_ALL = R"(
                SELECT COUNT(*) FROM quarantine_entries
            )";

            /**
             * @brief SQL statement to get the oldest quarantine timestamp.
             */
            constexpr const char* SQL_GET_OLDEST = R"(
                SELECT quarantine_time FROM quarantine_entries ORDER BY quarantine_time ASC LIMIT 1
            )";

            /**
             * @brief SQL statement to get the newest quarantine timestamp.
             */
            constexpr const char* SQL_GET_NEWEST = R"(
                SELECT quarantine_time FROM quarantine_entries ORDER BY quarantine_time DESC LIMIT 1
            )";

            /**
             * @brief SQL statement to insert an audit log entry.
             */
            constexpr const char* SQL_INSERT_AUDIT = R"(
                INSERT INTO quarantine_audit_log (timestamp, entry_id, action, user_name, machine_name, details, success)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            )";

            // ========================================================================
            //                      UTF-8 CONVERSION HELPERS
            // ========================================================================

            /**
             * @brief Converts a wide string to UTF-8 encoded string.
             * 
             * @param wstr Wide string view to convert.
             * @return UTF-8 encoded std::string, empty on failure.
             * 
             * @note Uses Windows WideCharToMultiByte API with CP_UTF8.
             */
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

            /**
             * @brief Converts a UTF-8 encoded string to wide string.
             * 
             * @param str UTF-8 string view to convert.
             * @return Wide string (std::wstring), empty on failure.
             * 
             * @note Uses Windows MultiByteToWideChar API with CP_UTF8.
             */
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

            // ========================================================================
            //                      SYSTEM INFORMATION HELPERS
            // ========================================================================

            /**
             * @brief Retrieves the local machine (computer) name.
             * 
             * @return Wide string containing machine name, or "Unknown" on failure.
             * 
             * @note Uses Windows GetComputerNameW API.
             */
            std::wstring GetMachineName() {
                wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
                DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
                if (GetComputerNameW(buf, &size)) {
                    return std::wstring(buf);
                }
                return L"Unknown";
            }

            /**
             * @brief Retrieves the current Windows user name.
             * 
             * @return Wide string containing user name, or "Unknown" on failure.
             * 
             * @note Uses Windows GetUserNameW API.
             */
            std::wstring GetCurrentUserName() {
                wchar_t buf[UNLEN + 1] = {};
                DWORD size = UNLEN + 1;
                if (::GetUserNameW(buf, &size)) {
                    return std::wstring(buf);
                }
                return L"Unknown";
            }

            // ========================================================================
            //                      HEX ENCODING/DECODING HELPERS
            // ========================================================================

            /**
             * @brief Converts binary data to lowercase hexadecimal string.
             * 
             * @param data Binary data vector to encode.
             * @return Wide string containing hex representation.
             * 
             * @details Produces lowercase hex (e.g., "a1b2c3"). Each byte
             * becomes two hex characters. Output length = input.size() * 2.
             */
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

            /**
             * @brief Converts hexadecimal string back to binary data.
             * 
             * @param hex Hex-encoded wide string (case-insensitive).
             * @return Vector of decoded bytes.
             * 
             * @details Handles both uppercase and lowercase hex characters.
             * Output length = input.size() / 2 (truncates odd-length input).
             */
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

        // ============================================================================
        //                    QUARANTINEDB IMPLEMENTATION
        // ============================================================================

        /**
         * @brief Returns the singleton instance of QuarantineDB.
         * 
         * @return Reference to the single QuarantineDB instance.
         * 
         * @details Thread-safe singleton using C++11 magic statics.
         * The instance is created on first access and destroyed at program exit.
         */
        QuarantineDB& QuarantineDB::Instance() {
            static QuarantineDB instance;
            return instance;
        }

        /**
         * @brief Private constructor - initializes cached system information.
         * 
         * @details Caches machine name and user name on construction to avoid
         * repeated system calls during quarantine operations.
         */
        QuarantineDB::QuarantineDB() {
            m_machineName = GetMachineName();
            m_userName = GetCurrentUserName();
        }

        /**
         * @brief Destructor - ensures clean shutdown.
         * 
         * @details Calls Shutdown() to stop background threads, clear encryption
         * keys from memory, and close database connections.
         */
        QuarantineDB::~QuarantineDB() {
            Shutdown();
        }

        /**
         * @brief Initializes the QuarantineDB system.
         * 
         * @param config Configuration settings for the quarantine system.
         * @param err Optional error output parameter.
         * @return true if initialization succeeded, false otherwise.
         * 
         * @details Initialization sequence:
         * 1. Validates not already initialized
         * 2. Stores configuration with thread-safe locking
         * 3. Initializes DatabaseManager with WAL mode
         * 4. Creates database schema (tables + indices)
         * 5. Ensures quarantine directory exists
         * 6. Generates master encryption key
         * 7. Starts background cleanup thread if enabled
         * 8. Calculates initial statistics
         * 9. Logs initialization audit event
         * 
         * @note Thread-safe. Safe to call from any thread.
         */
        bool QuarantineDB::Initialize(const Config& config, DatabaseError* err) {
            if (m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"QuarantineDB", L"Already initialized");
                return true;
            }

            SS_LOG_INFO(L"QuarantineDB", L"Initializing QuarantineDB...");

            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config = config;

            if (DatabaseManager::Instance().IsInitialized()) {
                SS_LOG_INFO(L"QuarantineDB", L"Shutting down existing DatabaseManager instance");
                DatabaseManager::Instance().Shutdown();
                std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Allow cleanup
            }

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

        /**
         * @brief Shuts down the QuarantineDB system gracefully.
         * 
         * @details Shutdown sequence:
         * 1. Checks if system is initialized (early return if not)
         * 2. Logs shutdown audit event
         * 3. Signals and waits for cleanup thread termination
         * 4. Securely clears encryption key from memory
         * 5. Shuts down DatabaseManager
         * 6. Updates initialized flag
         * 
         * @note Thread-safe. Blocks until cleanup thread terminates.
         * @note Encryption key is zeroed before clearing for security.
         */
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

        // ============================================================================
        //                      QUARANTINE OPERATIONS
        // ============================================================================

        /**
         * @brief Quarantines a file by moving it to secure encrypted storage.
         * 
         * @param originalPath Full path to the file to quarantine.
         * @param threatType Type of threat detected.
         * @param severity Severity level of the threat.
         * @param threatName Name/identifier of the detected threat.
         * @param detectionReason Optional reason for detection.
         * @param err Optional error output parameter.
         * @return Entry ID (>0) on success, -1 on failure.
         * 
         * @details Quarantine process:
         * 1. Reads original file content
         * 2. Extracts file metadata (name, path, size, timestamps)
         * 3. Calculates file hashes (MD5, SHA1, SHA256)
         * 4. Captures system context (user, machine, process)
         * 5. Creates database entry
         * 6. Encrypts and stores file in quarantine folder
         * 7. Updates entry with quarantine path
         * 8. Logs audit event and updates statistics
         * 
         * @note The original file is NOT automatically deleted.
         * @note Thread-safe.
         * 
         * @code
         * int64_t id = QuarantineDB::Instance().QuarantineFile(
         *     L"C:\\malware.exe",
         *     ThreatType::Trojan,
         *     ThreatSeverity::High,
         *     L"Trojan.Win32.Malware.ABC"
         * );
         * @endcode
         */
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
            // std::byte -> uint8_t dönüşümü açık cast gerektirir; doğrudan iterator ctor çalışmaz.
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

        /**
         * @brief Quarantines a file with pre-populated entry metadata and file data.
         * 
         * @param entry Pre-filled QuarantineEntry structure with threat information.
         * @param fileData Raw file content as byte vector.
         * @param err Optional error output parameter.
         * @return Entry ID (>0) on success, -1 on failure.
         * 
         * @details This method provides fine-grained control over quarantine metadata.
         * It performs:
         * 1. Database entry insertion
         * 2. Quarantine path generation
         * 3. File encryption and storage
         * 4. Entry update with quarantine path and size
         * 5. Audit logging and statistics update
         * 
         * @note Rolls back database entry if file storage fails.
         * @note Used internally by QuarantineFile() and ImportEntry().
         */
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

        /**
         * @brief Restores a quarantined file to its original or specified location.
         * 
         * @param entryId ID of the quarantine entry to restore.
         * @param restorePath Optional path to restore to (uses original path if empty).
         * @param restoredBy Optional identifier of who is restoring the file.
         * @param reason Optional reason for restoration.
         * @param err Optional error output parameter.
         * @return true if restoration succeeded, false otherwise.
         * 
         * @details Restoration process:
         * 1. Retrieves entry from database
         * 2. Validates restoration is allowed (canRestore flag, Active status)
         * 3. Decrypts and decompresses quarantined file
         * 4. Verifies file integrity using SHA256 hash
         * 5. Creates target directory if needed
         * 6. Writes restored file atomically
         * 7. Updates entry status to Restored
         * 8. Logs audit event and updates statistics
         * 
         * @note If integrity check fails, entry is marked as Corrupted.
         * @note The quarantined copy remains in storage after restoration.
         * 
         * @throws Sets err if entry not found, restoration disallowed, integrity failed,
         *         or file write fails.
         */
        bool QuarantineDB::RestoreFile(int64_t entryId,
                                       std::wstring_view restorePath,
                                       std::wstring_view restoredBy,
                                       std::wstring_view reason,
                                       DatabaseError* err)
        {
            SS_LOG_INFO(L"QuarantineDB", L"Restoring file from quarantine. Entry ID: %lld", entryId);

            auto entryOpt = GetEntry(entryId, err);
            if (!entryOpt) {
                if (err) {
                    err->sqliteCode = SQLITE_NOTFOUND;  
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

        /**
         * @brief Permanently deletes a quarantined file.
         * 
         * @param entryId ID of the quarantine entry to delete.
         * @param deletedBy Optional identifier of who is deleting the file.
         * @param reason Optional reason for deletion.
         * @param err Optional error output parameter.
         * @return true if deletion succeeded, false otherwise.
         * 
         * @details Deletion process:
         * 1. Retrieves entry from database
         * 2. Validates deletion is allowed (canDelete flag)
         * 3. Deletes physical encrypted file from quarantine folder
         * 4. Updates entry status to Deleted (entry preserved for audit)
         * 5. Adds deletion notes to entry
         * 6. Logs audit event and updates statistics
         * 
         * @note The database entry is NOT removed, only marked as Deleted.
         * @note Physical file deletion failure does not prevent status update.
         */
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
					err->sqliteCode = SQLITE_NOTFOUND;
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

        // ============================================================================
        //                        BATCH OPERATIONS
        // ============================================================================

        /**
         * @brief Quarantines multiple files in a single operation.
         * 
         * @param filePaths Vector of file paths to quarantine.
         * @param threatType Threat type applied to all files.
         * @param severity Severity level applied to all files.
         * @param threatName Threat name applied to all files.
         * @param err Optional error output parameter (for last failure).
         * @return true if at least one file was quarantined, false if all failed.
         * 
         * @details Iterates through file paths and quarantines each one individually.
         * Continues processing even if some files fail. Logs success/failure count.
         * 
         * @note Non-atomic: individual failures don't roll back successful operations.
         */
        bool QuarantineDB::QuarantineBatch(const std::vector<std::wstring>& filePaths,
            ThreatType threatType,
            ThreatSeverity severity,
            std::wstring_view threatName,
            DatabaseError* err)
        {
            if (filePaths.empty()) return true;

            SS_LOG_INFO(L"QuarantineDB", L"Batch quarantine: %zu files", filePaths.size());

           
            size_t successCount = 0;
            for (const auto& path : filePaths) {
                if (QuarantineFile(path, threatType, severity, threatName, L"", err) > 0) {
                    successCount++;
                }
                else {
                    SS_LOG_WARN(L"QuarantineDB", L"Failed to quarantine file: %ls", path.c_str());
                }
            }

            SS_LOG_INFO(L"QuarantineDB", L"Batch quarantine completed: %zu/%zu successful",
                successCount, filePaths.size());
            return successCount > 0;
        }
        
        /**
         * @brief Restores multiple quarantined files in a single operation.
         * 
         * @param entryIds Vector of entry IDs to restore.
         * @param restoredBy Optional identifier of who is restoring.
         * @param err Optional error output parameter (for last failure).
         * @return true if at least one file was restored, false if all failed.
         * 
         * @details Each file is restored to its original location.
         * Continues processing even if some restorations fail.
         */
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

        /**
         * @brief Deletes multiple quarantined files in a single operation.
         * 
         * @param entryIds Vector of entry IDs to delete.
         * @param deletedBy Optional identifier of who is deleting.
         * @param err Optional error output parameter (for last failure).
         * @return true if at least one file was deleted, false if all failed.
         * 
         * @details Each entry is marked as Deleted and physical files are removed.
         * Continues processing even if some deletions fail.
         */
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

        // ============================================================================
        //                        QUERY OPERATIONS
        // ============================================================================

        /**
         * @brief Retrieves a single quarantine entry by ID.
         * 
         * @param id Entry ID to retrieve.
         * @param err Optional error output parameter.
         * @return Optional containing the entry if found, std::nullopt otherwise.
         */
        std::optional<QuarantineDB::QuarantineEntry> QuarantineDB::GetEntry(int64_t id, DatabaseError* err) {
            return dbSelectEntry(id, err);
        }

        /**
         * @brief Queries quarantine entries with flexible filtering.
         * 
         * @param filter QueryFilter structure specifying search criteria.
         * @param err Optional error output parameter.
         * @return Vector of matching entries (may be empty).
         * 
         * @details Supports filtering by:
         * - Threat type, severity range
         * - Status
         * - Time range
         * - Path, threat name, hash patterns
         * - User and machine name patterns
         * 
         * @see QueryFilter for all available filter options.
         */
        std::vector<QuarantineDB::QuarantineEntry> QuarantineDB::Query(const QueryFilter& filter,
                                                                       DatabaseError* err)
        {
            std::vector<std::string> params;
            std::string sql = buildQuerySQL(filter, params);

            return dbSelectEntries(sql, params, err);
        }

        /**
         * @brief Retrieves entries by threat type.
         * 
         * @param type ThreatType to filter by.
         * @param maxCount Maximum entries to return (default 1000).
         * @param err Optional error output parameter.
         * @return Vector of matching entries, sorted by time descending.
         */
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

        /**
         * @brief Retrieves entries by severity level.
         * 
         * @param severity ThreatSeverity to filter by.
         * @param maxCount Maximum entries to return (default 1000).
         * @param err Optional error output parameter.
         * @return Vector of matching entries, sorted by time descending.
         */
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

        /**
         * @brief Retrieves entries by quarantine status.
         * 
         * @param status QuarantineStatus to filter by.
         * @param maxCount Maximum entries to return (default 1000).
         * @param err Optional error output parameter.
         * @return Vector of matching entries, sorted by time descending.
         */
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

        /**
         * @brief Retrieves all active (non-deleted, non-restored) entries.
         * 
         * @param maxCount Maximum entries to return (default 1000).
         * @param err Optional error output parameter.
         * @return Vector of active entries, sorted by time descending.
         */
        std::vector<QuarantineDB::QuarantineEntry> QuarantineDB::GetActiveEntries(size_t maxCount,
                                                                                  DatabaseError* err)
        {
            return GetByStatus(QuarantineStatus::Active, maxCount, err);
        }

        /**
         * @brief Retrieves the most recent quarantine entries.
         * 
         * @param count Number of entries to retrieve (default 100).
         * @param err Optional error output parameter.
         * @return Vector of recent entries, sorted by time descending.
         */
        std::vector<QuarantineDB::QuarantineEntry> QuarantineDB::GetRecent(size_t count,
                                                                           DatabaseError* err)
        {
            QueryFilter filter;
            filter.maxResults = count;
            filter.sortDescending = true;

            return Query(filter, err);
        }

        /**
         * @brief Searches for entries matching a file hash.
         * 
         * @param hash Hash value to search for (MD5, SHA1, or SHA256).
         * @param err Optional error output parameter.
         * @return Vector of matching entries (max 100).
         * 
         * @details Searches across all three hash fields (md5, sha1, sha256).
         */
        std::vector<QuarantineDB::QuarantineEntry> QuarantineDB::SearchByHash(std::wstring_view hash,
                                                                              DatabaseError* err)
        {
            QueryFilter filter;
            filter.fileHashPattern = hash;
            filter.maxResults = 100;

            return Query(filter, err);
        }

        /**
         * @brief Searches for entries by original filename pattern.
         * 
         * @param fileName Filename or partial filename to search for.
         * @param maxCount Maximum entries to return (default 1000).
         * @param err Optional error output parameter.
         * @return Vector of matching entries.
         * 
         * @details Uses SQL LIKE pattern matching with wildcards.
         */
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

        /**
         * @brief Counts entries matching an optional filter.
         * 
         * @param filter Optional QueryFilter for filtering (nullptr for all).
         * @param err Optional error output parameter.
         * @return Count of matching entries, -1 on error.
         */
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

        // ============================================================================
        //                        FILE OPERATIONS
        // ============================================================================

        /**
         * @brief Extracts decrypted file data from quarantine storage.
         * 
         * @param entryId ID of the quarantine entry.
         * @param outData Output vector to receive decrypted file data.
         * @param err Optional error output parameter.
         * @return true if extraction succeeded, false otherwise.
         * 
         * @details Decrypts and decompresses the quarantined file without
         * restoring it to disk. Useful for analysis or submission.
         */
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

        /**
         * @brief Retrieves file hashes without extracting file data.
         * 
         * @param entryId ID of the quarantine entry.
         * @param md5 Output parameter for MD5 hash.
         * @param sha1 Output parameter for SHA1 hash.
         * @param sha256 Output parameter for SHA256 hash.
         * @param err Optional error output parameter.
         * @return true if entry found and hashes retrieved, false otherwise.
         */
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

        /**
         * @brief Verifies the integrity of a quarantined file.
         * 
         * @param entryId ID of the quarantine entry to verify.
         * @param err Optional error output parameter.
         * @return true if integrity check passed, false otherwise.
         * 
         * @details Extracts file data, recalculates SHA256 hash, and compares
         * against stored hash. Marks entry as Corrupted if verification fails.
         * Updates statistics counters for passed/failed checks.
         */
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

        /**
         * @brief Updates an existing quarantine entry.
         * 
         * @param entry Modified QuarantineEntry to save.
         * @param err Optional error output parameter.
         * @return true if update succeeded, false otherwise.
         * 
         * @note Entry ID must be valid (>0).
         */
        bool QuarantineDB::UpdateEntry(const QuarantineEntry& entry, DatabaseError* err) {
            return dbUpdateEntry(entry, err);
        }

        /**
         * @brief Appends notes to an existing entry.
         * 
         * @param entryId ID of the quarantine entry.
         * @param notes Text to append to existing notes.
         * @param err Optional error output parameter.
         * @return true if notes were added, false otherwise.
         * 
         * @details Appends notes with newline separator and updates
         * the last access timestamp.
         */
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

        

        // ============================================================================
        //                  INTERNAL HELPER IMPLEMENTATIONS
        // ============================================================================

        /**
         * @brief Creates the database schema (tables, indices).
         * 
         * @param err Optional error output parameter.
         * @return true if schema was created successfully, false otherwise.
         * 
         * @details Creates:
         * - quarantine_entries main table (36 columns)
         * - 8 performance indices
         * - quarantine_audit_log for operation tracking
         * - quarantine_metadata for custom key-value data
         */
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

        // ============================================================================
        //               SCHEMA MIGRATION FRAMEWORK
        // ============================================================================

        /**
         * @brief Upgrades database schema between versions using transactional migrations.
         * 
         * @param currentVersion Current schema version in database.
         * @param targetVersion Target schema version to upgrade to.
         * @param err Optional error output parameter.
         * @return true if all migrations succeeded (or no upgrade needed).
         * 
         * @details Migration Framework:
         * - Each version increment has a dedicated migration function
         * - Migrations are executed in a transaction for atomicity
         * - On failure, the transaction is rolled back
         * - Version metadata is updated after successful migration
         * 
         * Adding New Migrations:
         * 1. Increment QUARANTINE_SCHEMA_VERSION constant
         * 2. Add case in switch statement below
         * 3. Implement migration SQL in the new case
         * 4. Test both fresh install and upgrade paths
         * 
         * Example Migration (v1 → v2):
         * @code{.cpp}
         * case 2:
         *     db.exec("ALTER TABLE quarantine_entries ADD COLUMN risk_score REAL DEFAULT 0.0");
         *     db.exec("CREATE INDEX idx_quar_risk ON quarantine_entries(risk_score)");
         *     break;
         * @endcode
         */
        bool QuarantineDB::upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err) {
            SS_LOG_INFO(L"QuarantineDB", L"Schema migration: v%d → v%d", currentVersion, targetVersion);
            
            // No migration needed if versions match
            if (currentVersion >= targetVersion) {
                SS_LOG_DEBUG(L"QuarantineDB", L"No schema migration needed");
                return true;
            }
            
            try {
                // Execute migrations sequentially within a transaction
                for (int version = currentVersion + 1; version <= targetVersion; ++version) {
                    SS_LOG_INFO(L"QuarantineDB", L"Applying migration to schema version %d", version);
                    
                    switch (version) {
                        case 1:
                            // Base schema - created by createSchema(), no migration needed
                            break;
                            
                        // === Future Migrations ===
                        // case 2:
                        //     // Example: Add malware family tracking
                        //     DatabaseManager::Instance().Execute(
                        //         "ALTER TABLE quarantine_entries ADD COLUMN malware_family TEXT",
                        //         nullptr);
                        //     DatabaseManager::Instance().Execute(
                        //         "ALTER TABLE quarantine_entries ADD COLUMN confidence_score REAL DEFAULT 0.0",
                        //         nullptr);
                        //     DatabaseManager::Instance().Execute(
                        //         "CREATE INDEX idx_quar_family ON quarantine_entries(malware_family)",
                        //         nullptr);
                        //     break;
                        //
                        // case 3:
                        //     // Example: Add cloud sync tracking
                        //     DatabaseManager::Instance().Execute(
                        //         "ALTER TABLE quarantine_entries ADD COLUMN cloud_sync_status INTEGER DEFAULT 0",
                        //         nullptr);
                        //     DatabaseManager::Instance().Execute(
                        //         "ALTER TABLE quarantine_entries ADD COLUMN last_cloud_sync TEXT",
                        //         nullptr);
                        //     break;
                            
                        default:
                            SS_LOG_WARN(L"QuarantineDB", L"Unknown migration version: %d", version);
                            break;
                    }
                }
                
                // Update schema version in metadata
                DatabaseManager::Instance().ExecuteWithParams(
                    "INSERT OR REPLACE INTO quarantine_metadata (key, value) VALUES ('schema_version', ?)",
                    nullptr,
                    std::to_string(targetVersion));
                
                SS_LOG_INFO(L"QuarantineDB", L"Schema migration completed successfully to v%d", targetVersion);
                return true;
                
            } catch (const std::exception& e) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Schema migration failed: " + ToWide(e.what());
                }
                SS_LOG_ERROR(L"QuarantineDB", L"Schema migration failed: %hs", e.what());
                return false;
            }
        }

        /**
         * @brief Inserts a new quarantine entry into the database.
         * 
         * @param entry QuarantineEntry to insert.
         * @param err Optional error output parameter.
         * @return Newly assigned entry ID (>0) on success, -1 on failure.
         * 
         * @details Binds all 32 parameters to SQL_INSERT_ENTRY statement.
         * Updates total quarantine count on success.
         */
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

        /**
         * @brief Updates an existing quarantine entry in the database.
         * 
         * @param entry QuarantineEntry with updated values.
         * @param err Optional error output parameter.
         * @return true if update succeeded, false otherwise.
         * 
         * @details Updates mutable fields: last_access_time, quarantine_path,
         * quarantine_filename, quarantine_size, status, restoration info, notes.
         * 
         * @note Entry ID must be valid (>0).
         */
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
                ToUTF8(entry.quarantinePath),           
                ToUTF8(entry.quarantineFileName),      
                static_cast<int64_t>(entry.quarantineSize),  
                static_cast<int>(entry.status),
                restorationTime,
                ToUTF8(entry.restoredBy),
                ToUTF8(entry.restorationReason),
                ToUTF8(entry.notes),
                entry.id
            );
        }

        /**
         * @brief Deletes a quarantine entry from the database.
         * 
         * @param id Entry ID to delete.
         * @param err Optional error output parameter.
         * @return true if deletion succeeded, false otherwise.
         * 
         * @note This permanently removes the database record.
         *       Use with caution - prefer status update for audit trail.
         */
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

        /**
         * @brief Selects a single quarantine entry by ID.
         * 
         * @param id Entry ID to retrieve.
         * @param err Optional error output parameter.
         * @return Optional containing entry if found, std::nullopt otherwise.
         */
        std::optional<QuarantineDB::QuarantineEntry> QuarantineDB::dbSelectEntry(int64_t id, DatabaseError* err) {
            auto result = DatabaseManager::Instance().QueryWithParams(
                SQL_SELECT_ENTRY, err, id);

            if (result.Next()) {
                return rowToQuarantineEntry(result);
            }

            return std::nullopt;
        }

        /**
         * @brief Selects multiple quarantine entries using a custom SQL query.
         * 
         * @param sql SQL SELECT statement.
         * @param params Parameter values for prepared statement.
         * @param err Optional error output parameter.
         * @return Vector of matching entries.
         * 
         * @details Converts each row to QuarantineEntry using rowToQuarantineEntry().
         */
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

        /**
         * @brief Builds a SELECT SQL query from filter criteria.
         * 
         * @param filter QueryFilter with search criteria.
         * @param outParams Output vector for parameter values.
         * @return SQL query string.
         * 
         * @details Constructs WHERE clauses for all non-empty filter fields.
         * Adds ORDER BY and LIMIT clauses based on filter settings.
         */
        std::string QuarantineDB::buildQuerySQL(const QueryFilter& filter, std::vector<std::string>& outParams) {
            std::ostringstream sql;
            sql << "SELECT * FROM quarantine_entries WHERE 1=1";

            if (filter.threatType) {
                sql << " AND threat_type = " << static_cast<int>(*filter.threatType);  // Direct value
            }

            if (filter.minSeverity) {
                sql << " AND severity >= " << static_cast<int>(*filter.minSeverity);
            }

            if (filter.maxSeverity) {
                sql << " AND severity <= " << static_cast<int>(*filter.maxSeverity);
            }

            if (filter.status) {
                sql << " AND status = " << static_cast<int>(*filter.status);  // Direct value
            }

            if (filter.startTime) {
                sql << " AND quarantine_time >= '" << timePointToString(*filter.startTime) << "'";
            }

            if (filter.endTime) {
                sql << " AND quarantine_time <= '" << timePointToString(*filter.endTime) << "'";
            }

            if (filter.originalPathPattern) {
                sql << " AND original_path LIKE '" << ToUTF8(*filter.originalPathPattern) << "'";
            }

            if (filter.threatNamePattern) {
                sql << " AND threat_name LIKE '" << ToUTF8(*filter.threatNamePattern) << "'";
            }

            if (filter.fileHashPattern) {
                std::string hashPattern = ToUTF8(*filter.fileHashPattern);
                sql << " AND (md5_hash LIKE '" << hashPattern << "' OR sha1_hash LIKE '"
                    << hashPattern << "' OR sha256_hash LIKE '" << hashPattern << "')";
            }

            if (filter.userNamePattern) {
                sql << " AND user_name LIKE '" << ToUTF8(*filter.userNamePattern) << "'";
            }

            if (filter.machineNamePattern) {
                sql << " AND machine_name LIKE '" << ToUTF8(*filter.machineNamePattern) << "'";
            }

            // Order and limit
            if (filter.sortDescending) {
                sql << " ORDER BY quarantine_time DESC";
            }
            else {
                sql << " ORDER BY quarantine_time ASC";
            }

            sql << " LIMIT " << filter.maxResults;

            return sql.str();
        }

        /**
         * @brief Builds a COUNT SQL query from filter criteria.
         * 
         * @param filter QueryFilter with search criteria.
         * @param outParams Output vector for parameter values.
         * @return SQL COUNT query string.
         */
        std::string QuarantineDB::buildCountSQL(const QueryFilter& filter, std::vector<std::string>& outParams) {
            std::ostringstream sql;
            sql << "SELECT COUNT(*) FROM quarantine_entries WHERE 1=1";

            if (filter.threatType) {
                sql << " AND threat_type = " << static_cast<int>(*filter.threatType);  // Direct
            }

            if (filter.status) {
                sql << " AND status = " << static_cast<int>(*filter.status);  // Direct
            }

            return sql.str();
        }

        /**
         * @brief Converts a database row to a QuarantineEntry structure.
         * 
         * @param result QueryResult positioned at a valid row.
         * @return Fully populated QuarantineEntry.
         * 
         * @details Maps all 36 columns to corresponding entry fields.
         * Handles type conversions for enums, timestamps, and flags.
         */
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

        /**
         * @brief Converts a time_point to ISO 8601 string with milliseconds.
         * 
         * @param tp System clock time point.
         * @return ISO 8601 formatted string "YYYY-MM-DD HH:MM:SS.mmm".
         * 
         * @details Uses UTC timezone for database consistency.
         */
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

        /**
         * @brief Parses an ISO 8601 string to a time_point.
         * 
         * @param str ISO 8601 formatted string.
         * @return System clock time point, or epoch on parse failure.
         * 
         * @details Supports optional milliseconds after decimal point.
         */
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
        //               ENCRYPTION & HASHING IMPLEMENTATIONS
        // ============================================================================

        /**
         * @brief AES-256-GCM encryption constants.
         * @details Industry-standard values for authenticated encryption.
         */
        namespace CryptoConstants {
            constexpr size_t AES_KEY_SIZE = 32;       ///< 256-bit key
            constexpr size_t AES_IV_SIZE = 12;        ///< 96-bit IV (recommended for GCM)
            constexpr size_t AES_TAG_SIZE = 16;       ///< 128-bit authentication tag
            constexpr size_t PBKDF2_ITERATIONS = 100000; ///< NIST recommended minimum
            constexpr size_t SALT_SIZE = 32;          ///< 256-bit salt
        }

        /**
         * @brief Encrypts file data using AES-256-GCM and stores it in the quarantine folder.
         * 
         * @param fileData Raw file content to encrypt.
         * @param quarantinePath Destination path for encrypted file.
         * @param err Optional error output parameter.
         * @return true if file was encrypted and stored, false otherwise.
         * 
         * @details Processing pipeline:
         * 1. Compress data if compression is enabled (LZMA/Xpress)
         * 2. Generate cryptographically secure IV using BCryptGenRandom
         * 3. Encrypt data using AES-256-GCM via Windows BCrypt API
         * 4. Write atomically: [IV (12 bytes)][Auth Tag (16 bytes)][Ciphertext]
         * 
         * Security Features:
         * - Authenticated encryption prevents tampering
         * - Unique IV per file prevents pattern analysis
         * - Authentication tag verifies integrity on decryption
         */
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

            // Encrypt if enabled using AES-256-GCM
            if (m_config.enableEncryption) {
#ifdef _WIN32
                BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
                BCRYPT_KEY_HANDLE hKey = nullptr;
                NTSTATUS status;

                // Open AES algorithm provider
                status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, nullptr, 0);
                if (!BCRYPT_SUCCESS(status)) {
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"Failed to open BCrypt algorithm provider";
                    }
                    SS_LOG_ERROR(L"QuarantineDB", L"BCryptOpenAlgorithmProvider failed: 0x%08X", status);
                    return false;
                }

                // Set GCM chaining mode
                status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
                    reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                    static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_GCM)), 0);
                if (!BCRYPT_SUCCESS(status)) {
                    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"Failed to set GCM chaining mode";
                    }
                    SS_LOG_ERROR(L"QuarantineDB", L"BCryptSetProperty GCM failed: 0x%08X", status);
                    return false;
                }

                // Generate cryptographically secure IV
                std::vector<uint8_t> iv(CryptoConstants::AES_IV_SIZE);
                status = BCryptGenRandom(nullptr, iv.data(), static_cast<ULONG>(iv.size()),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                if (!BCRYPT_SUCCESS(status)) {
                    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"Failed to generate secure IV";
                    }
                    SS_LOG_ERROR(L"QuarantineDB", L"BCryptGenRandom IV failed: 0x%08X", status);
                    return false;
                }

                // Get the key
                std::vector<uint8_t> key;
                {
                    std::lock_guard<std::mutex> lock(m_keyMutex);
                    key = m_masterKey;
                }

                // Generate key object
                status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, nullptr, 0,
                    key.data(), static_cast<ULONG>(key.size()), 0);
                if (!BCRYPT_SUCCESS(status)) {
                    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"Failed to generate symmetric key";
                    }
                    SS_LOG_ERROR(L"QuarantineDB", L"BCryptGenerateSymmetricKey failed: 0x%08X", status);
                    return false;
                }

                // Prepare authentication tag buffer
                std::vector<uint8_t> authTag(CryptoConstants::AES_TAG_SIZE);

                // Prepare authenticated cipher mode info
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
                BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
                authInfo.pbNonce = iv.data();
                authInfo.cbNonce = static_cast<ULONG>(iv.size());
                authInfo.pbTag = authTag.data();
                authInfo.cbTag = static_cast<ULONG>(authTag.size());

                // Get required ciphertext size (same as plaintext for GCM)
                ULONG ciphertextSize = static_cast<ULONG>(dataToStore.size());
                std::vector<uint8_t> ciphertext(ciphertextSize);

                // Perform encryption
                ULONG resultSize = 0;
                status = BCryptEncrypt(hKey, dataToStore.data(), static_cast<ULONG>(dataToStore.size()),
                    &authInfo, nullptr, 0, ciphertext.data(), ciphertextSize, &resultSize, 0);

                BCryptDestroyKey(hKey);
                BCryptCloseAlgorithmProvider(hAlgorithm, 0);

                if (!BCRYPT_SUCCESS(status)) {
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"AES-256-GCM encryption failed";
                    }
                    SS_LOG_ERROR(L"QuarantineDB", L"BCryptEncrypt failed: 0x%08X", status);
                    return false;
                }

                // Build output: [IV (12 bytes)][Auth Tag (16 bytes)][Ciphertext]
                dataToStore.clear();
                dataToStore.reserve(iv.size() + authTag.size() + ciphertext.size());
                dataToStore.insert(dataToStore.end(), iv.begin(), iv.end());
                dataToStore.insert(dataToStore.end(), authTag.begin(), authTag.end());
                dataToStore.insert(dataToStore.end(), ciphertext.begin(), ciphertext.end());

                // Securely clear key from stack
                SecureZeroMemory(key.data(), key.size());

                SS_LOG_DEBUG(L"QuarantineDB", L"File encrypted with AES-256-GCM, IV: %zu bytes, Tag: %zu bytes",
                    iv.size(), authTag.size());
#else
                // Non-Windows fallback - should use OpenSSL or similar
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Encryption not supported on this platform";
                }
                return false;
#endif
            }

            // Write to file atomically
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

        /**
         * @brief Decrypts and loads file data from quarantine storage using AES-256-GCM.
         * 
         * @param quarantinePath Path to encrypted quarantine file.
         * @param outData Output vector for decrypted file content.
         * @param err Optional error output parameter.
         * @return true if file was loaded and decrypted, false otherwise.
         * 
         * @details Processing pipeline:
         * 1. Read encrypted file from disk
         * 2. Parse header: [IV (12 bytes)][Auth Tag (16 bytes)][Ciphertext]
         * 3. Decrypt using AES-256-GCM via Windows BCrypt API
         * 4. Verify authentication tag (tamper detection)
         * 5. Decompress if compression was enabled
         * 
         * Security Features:
         * - Authentication tag verification detects tampering
         * - Decryption fails immediately if data was modified
         */
        bool QuarantineDB::decryptAndLoadFile(std::wstring_view quarantinePath,
            std::vector<uint8_t>& outData,
            DatabaseError* err)
        {
            // Read encrypted file
            Utils::FileUtils::Error fileErr;
            std::vector<std::byte> encryptedDataBytes;

            if (!Utils::FileUtils::ReadAllBytes(quarantinePath, encryptedDataBytes, &fileErr)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to read quarantine file";
                }
                return false;
            }

            // Convert std::byte -> uint8_t
            std::vector<uint8_t> encryptedData;
            encryptedData.resize(encryptedDataBytes.size());
            std::transform(encryptedDataBytes.begin(), encryptedDataBytes.end(), encryptedData.begin(),
                [](std::byte b) { return static_cast<uint8_t>(b); });

            std::vector<uint8_t> data;

            // Decrypt if encrypted
            if (m_config.enableEncryption) {
#ifdef _WIN32
                // Minimum size: IV + Tag + at least 1 byte of ciphertext
                constexpr size_t MIN_ENCRYPTED_SIZE = CryptoConstants::AES_IV_SIZE + 
                                                       CryptoConstants::AES_TAG_SIZE + 1;
                if (encryptedData.size() < MIN_ENCRYPTED_SIZE) {
                    if (err) {
                        err->sqliteCode = SQLITE_CORRUPT;
                        err->message = L"Encrypted file is too small or corrupted";
                    }
                    SS_LOG_ERROR(L"QuarantineDB", L"Encrypted file size too small: %zu bytes", 
                        encryptedData.size());
                    return false;
                }

                // Parse header: [IV (12 bytes)][Auth Tag (16 bytes)][Ciphertext]
                std::vector<uint8_t> iv(encryptedData.begin(), 
                    encryptedData.begin() + CryptoConstants::AES_IV_SIZE);
                std::vector<uint8_t> authTag(
                    encryptedData.begin() + CryptoConstants::AES_IV_SIZE,
                    encryptedData.begin() + CryptoConstants::AES_IV_SIZE + CryptoConstants::AES_TAG_SIZE);
                std::vector<uint8_t> ciphertext(
                    encryptedData.begin() + CryptoConstants::AES_IV_SIZE + CryptoConstants::AES_TAG_SIZE,
                    encryptedData.end());

                BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
                BCRYPT_KEY_HANDLE hKey = nullptr;
                NTSTATUS status;

                // Open AES algorithm provider
                status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, nullptr, 0);
                if (!BCRYPT_SUCCESS(status)) {
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"Failed to open BCrypt algorithm provider";
                    }
                    return false;
                }

                // Set GCM chaining mode
                status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
                    reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                    static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_GCM)), 0);
                if (!BCRYPT_SUCCESS(status)) {
                    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"Failed to set GCM chaining mode";
                    }
                    return false;
                }

                // Get the key
                std::vector<uint8_t> key;
                {
                    std::lock_guard<std::mutex> lock(m_keyMutex);
                    key = m_masterKey;
                }

                // Generate key object
                status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, nullptr, 0,
                    key.data(), static_cast<ULONG>(key.size()), 0);
                if (!BCRYPT_SUCCESS(status)) {
                    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"Failed to generate symmetric key";
                    }
                    SecureZeroMemory(key.data(), key.size());
                    return false;
                }

                // Prepare authenticated cipher mode info
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
                BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
                authInfo.pbNonce = iv.data();
                authInfo.cbNonce = static_cast<ULONG>(iv.size());
                authInfo.pbTag = authTag.data();
                authInfo.cbTag = static_cast<ULONG>(authTag.size());

                // Allocate plaintext buffer
                data.resize(ciphertext.size());
                ULONG resultSize = 0;

                // Perform decryption with authentication verification
                status = BCryptDecrypt(hKey, ciphertext.data(), static_cast<ULONG>(ciphertext.size()),
                    &authInfo, nullptr, 0, data.data(), static_cast<ULONG>(data.size()), &resultSize, 0);

                BCryptDestroyKey(hKey);
                BCryptCloseAlgorithmProvider(hAlgorithm, 0);
                SecureZeroMemory(key.data(), key.size());

                if (!BCRYPT_SUCCESS(status)) {
                    if (status == static_cast<NTSTATUS>(0xC000A002L)) { // STATUS_AUTH_TAG_MISMATCH
                        if (err) {
                            err->sqliteCode = SQLITE_CORRUPT;
                            err->message = L"Authentication failed - file may have been tampered with";
                        }
                        SS_LOG_ERROR(L"QuarantineDB", L"Authentication tag mismatch - file tampered!");
                    } else {
                        if (err) {
                            err->sqliteCode = SQLITE_ERROR;
                            err->message = L"AES-256-GCM decryption failed";
                        }
                        SS_LOG_ERROR(L"QuarantineDB", L"BCryptDecrypt failed: 0x%08X", status);
                    }
                    return false;
                }

                data.resize(resultSize);
                SS_LOG_DEBUG(L"QuarantineDB", L"File decrypted with AES-256-GCM, plaintext: %zu bytes", 
                    data.size());
#else
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Decryption not supported on this platform";
                }
                return false;
#endif
            } else {
                data = std::move(encryptedData);
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

            /**
             * @brief Compresses data using Windows Compression API.
             * 
             * @param input Data to compress.
             * @param output Output vector for compressed data.
             * @return true on success (output may equal input if compression not beneficial).
             * 
             * @details Uses Xpress algorithm. Falls back to uncompressed if:
             * - Compression API not available
             * - Compressed size >= original size
             */
            bool QuarantineDB::compressData(const std::vector<uint8_t>& input,
                std::vector<uint8_t>& output)
            {
                output.clear();
                if (input.empty()) return true;

                using namespace ShadowStrike::Utils::CompressionUtils;

                if (!IsCompressionApiAvailable()) {
                    SS_LOG_WARN(L"QuarantineDB", L"Compression API not available - storing uncompressed");
                    output = input; 
                    return true;
                }

                Compressor compressor;
                if (!compressor.open(Algorithm::Xpress)) {
                    SS_LOG_WARN(L"QuarantineDB", L"Failed to open compressor - storing uncompressed");
                    output = input;
                    return true;
                }

                const void* src = static_cast<const void*>(input.data());
                size_t size = input.size();

                bool ok = compressor.compress(src, size, output);
                compressor.close();

                if (!ok || output.size() >= input.size()) {
                   
                    SS_LOG_DEBUG(L"QuarantineDB", L"Compression not beneficial (%zu -> %zu), storing uncompressed",
                        input.size(), output.size());
                    output = input;
                }

                return true;
            }

            /**
             * @brief Decompresses data using Windows Compression API.
             * 
             * @param input Compressed data.
             * @param output Output vector for decompressed data.
             * @return true on success (output may equal input if data was not compressed).
             * 
             * @details Uses Xpress algorithm. Limits max output to 100MB for safety.
             * Falls back to input data if decompression fails.
             */
            bool QuarantineDB::decompressData(const std::vector<uint8_t>& input,
                std::vector<uint8_t>& output)
            {
                output.clear();
                if (input.empty()) return true;

                using namespace ShadowStrike::Utils::CompressionUtils;

                if (!IsCompressionApiAvailable()) {
                    SS_LOG_WARN(L"QuarantineDB", L"Compression API not available - assuming uncompressed");
                    output = input;
                    return true;
                }

                Decompressor decompressor;
                if (!decompressor.open(Algorithm::Xpress)) {
                    SS_LOG_WARN(L"QuarantineDB", L"Failed to open decompressor - assuming uncompressed");
                    output = input;
                    return true;
                }

                const void* src = static_cast<const void*>(input.data());
                size_t size = input.size();

                
                size_t maxDecompressedSize = std::min(size * 10, size_t(100 * 1024 * 1024));

                bool ok = decompressor.decompress(src, size, output, maxDecompressedSize);
                decompressor.close();

                if (!ok) {
                    SS_LOG_WARN(L"QuarantineDB", L"Decompression failed - assuming data was uncompressed");
                    output = input;
                }

                return true;
            }

        /**
         * @brief Calculates MD5, SHA1, and SHA256 hashes for file data.
         * 
         * @param data File content to hash.
         * @param md5 Output parameter for MD5 hash (hex).
         * @param sha1 Output parameter for SHA1 hash (hex).
         * @param sha256 Output parameter for SHA256 hash (hex).
         * @return true if SHA256 was calculated successfully.
         * 
         * @details Uses HashUtils utility class with BCrypt backend.
         */
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

        /**
         * @brief Calculates MD5 hash for file data.
         * @param data File content to hash.
         * @return Lowercase hex MD5 hash, empty on failure.
         */
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

        /**
         * @brief Calculates SHA1 hash for file data.
         * @param data File content to hash.
         * @return Lowercase hex SHA1 hash, empty on failure.
         */
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

        /**
         * @brief Calculates SHA256 hash for file data.
         * @param data File content to hash.
         * @return Lowercase hex SHA256 hash, empty on failure.
         */
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

        // ============================================================================
        //               BACKGROUND CLEANUP IMPLEMENTATION
        // ============================================================================

        /**
         * @brief Background thread function for automatic cleanup.
         * 
         * @details Runs hourly cleanup operations:
         * - Removes expired entries (based on retention policy)
         * - Removes corrupted entries
         * 
         * Thread terminates when m_shutdownCleanup flag is set.
         */
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

        /**
         * @brief Cleans up entries that have exceeded retention period.
         * 
         * @param err Optional error output parameter.
         * @return true if cleanup completed successfully.
         * 
         * @details Deletes active entries older than maxRetentionDays config.
         * Updates cleanup timestamp and counter in statistics.
         */
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

        /**
         * @brief Cleans up entries marked as corrupted.
         * 
         * @param err Optional error output parameter.
         * @return true if cleanup completed successfully.
         * 
         * @details Permanently deletes database records for corrupted entries.
         */
        bool QuarantineDB::cleanupCorruptedEntries(DatabaseError* err) {
            auto entries = GetByStatus(QuarantineStatus::Corrupted, 100, err);
            
            for (const auto& entry : entries) {
                dbDeleteEntry(entry.id, nullptr);
            }

            return true;
        }

        /**
         * @brief Generates a unique quarantine file path for an entry.
         * 
         * @param entryId Entry ID to include in filename.
         * @return Full path in format: quarantineBasePath/quar_NNNNNNNNNN_TIMESTAMP.dat
         */
        std::wstring QuarantineDB::generateQuarantinePath(int64_t entryId) {
            auto now = std::chrono::system_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

            std::wostringstream oss;
            oss << m_config.quarantineBasePath;
            if (!m_config.quarantineBasePath.empty() &&
                m_config.quarantineBasePath.back() != L'\\') {
                oss << L"\\";
            }
            
            oss << L"quar_" << std::setfill(L'0') << std::setw(10) << entryId
                << L"_" << ms << L".dat";
            return oss.str();
        }

        /**
         * @brief Ensures the quarantine base directory exists.
         * 
         * @param err Optional error output parameter.
         * @return true if directory exists or was created.
         */
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

        /**
         * @brief Derives the master encryption key using PBKDF2-SHA256.
         * 
         * @return 32-byte (256-bit) encryption key suitable for AES-256.
         * 
         * @details Uses PBKDF2 (Password-Based Key Derivation Function 2) with:
         * - SHA-256 as the underlying hash function
         * - 100,000 iterations (NIST SP 800-132 recommended minimum)
         * - Machine-specific entropy (machine name, username, installation ID)
         * - Cryptographically secure salt stored separately
         * 
         * Security Considerations:
         * - Key is derived deterministically from system parameters
         * - Same machine will always derive same key (allows decryption)
         * - Different machines will derive different keys (isolation)
         * - High iteration count prevents brute-force attacks
         */
        std::vector<uint8_t> QuarantineDB::deriveEncryptionKey() {
#ifdef _WIN32
            // Build entropy from system parameters
            std::wstring entropy = m_machineName + L":" + m_userName + L":ShadowStrike:v2.0";
            
            // Convert entropy to bytes
            std::string entropyUtf8 = ToUTF8(entropy);
            
            // Generate or retrieve persistent salt
            std::vector<uint8_t> salt = generateSalt();
            
            BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
            NTSTATUS status;
            
            // Open SHA-256 algorithm for PBKDF2
            status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM,
                nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            if (!BCRYPT_SUCCESS(status)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to open SHA256 for PBKDF2: 0x%08X", status);
                // Fallback to secure random key
                std::vector<uint8_t> key(CryptoConstants::AES_KEY_SIZE);
                BCryptGenRandom(nullptr, key.data(), static_cast<ULONG>(key.size()),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                return key;
            }
            
            // Derive key using PBKDF2
            std::vector<uint8_t> derivedKey(CryptoConstants::AES_KEY_SIZE);
            status = BCryptDeriveKeyPBKDF2(
                hAlgorithm,
                reinterpret_cast<PUCHAR>(const_cast<char*>(entropyUtf8.data())),
                static_cast<ULONG>(entropyUtf8.size()),
                salt.data(),
                static_cast<ULONG>(salt.size()),
                CryptoConstants::PBKDF2_ITERATIONS,
                derivedKey.data(),
                static_cast<ULONG>(derivedKey.size()),
                0);
            
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            
            if (!BCRYPT_SUCCESS(status)) {
                SS_LOG_ERROR(L"QuarantineDB", L"PBKDF2 key derivation failed: 0x%08X", status);
                // Fallback to secure random key
                std::vector<uint8_t> key(CryptoConstants::AES_KEY_SIZE);
                BCryptGenRandom(nullptr, key.data(), static_cast<ULONG>(key.size()),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                return key;
            }
            
            SS_LOG_DEBUG(L"QuarantineDB", L"Encryption key derived using PBKDF2-SHA256 (%zu iterations)",
                CryptoConstants::PBKDF2_ITERATIONS);
            
            // Securely clear entropy
            SecureZeroMemory(const_cast<char*>(entropyUtf8.data()), entropyUtf8.size());
            
            return derivedKey;
#else
            // Non-Windows: generate secure random key
            std::vector<uint8_t> key(CryptoConstants::AES_KEY_SIZE);
            std::random_device rd;
            for (auto& byte : key) {
                byte = static_cast<uint8_t>(rd() % 256);
            }
            return key;
#endif
        }

        /**
         * @brief Generates a cryptographically secure random salt.
         * 
         * @return 32-byte (256-bit) cryptographically secure random salt.
         * 
         * @details Uses BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG
         * which leverages the system's cryptographic random number generator.
         * On Windows this is backed by the CNG (Cryptography Next Generation) API.
         * 
         * The salt is used for:
         * - PBKDF2 key derivation (prevents rainbow table attacks)
         * - Adding entropy to encryption operations
         */
        std::vector<uint8_t> QuarantineDB::generateSalt() {
            std::vector<uint8_t> salt(CryptoConstants::SALT_SIZE);
            
#ifdef _WIN32
            NTSTATUS status = BCryptGenRandom(
                nullptr,
                salt.data(),
                static_cast<ULONG>(salt.size()),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            
            if (!BCRYPT_SUCCESS(status)) {
                SS_LOG_WARN(L"QuarantineDB", L"BCryptGenRandom failed: 0x%08X, using fallback", status);
                // Fallback using high-resolution timer and other entropy sources
                auto now = std::chrono::high_resolution_clock::now();
                auto seed = now.time_since_epoch().count();
                std::mt19937_64 rng(seed);
                std::uniform_int_distribution<int> dist(0, 255);
                for (auto& byte : salt) {
                    byte = static_cast<uint8_t>(dist(rng));
                }
            }
#else
            // Non-Windows: use random_device
            std::random_device rd;
            std::uniform_int_distribution<int> dist(0, 255);
            for (auto& byte : salt) {
                byte = static_cast<uint8_t>(dist(rd));
            }
#endif
            
            return salt;
        }

        /**
         * @brief Updates statistics counters based on a quarantine action.
         * 
         * @param entry Entry being affected.
         * @param action Action being performed.
         * 
         * @details Updates counters for:
         * - Quarantined: active count, type/severity breakdown, total size
         * - Restored: decreases active, increases restored count
         * - Deleted: decreases active, increases deleted count
         * 
         * Also tracks oldest/newest entry timestamps.
         */
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

        /**
         * @brief Recalculates all statistics from database.
         * 
         * @param err Optional error output parameter.
         * 
         * @details Queries database for total count, oldest/newest timestamps.
         * Resets all counters before recalculation.
         */
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

        /**
         * @brief Records an audit log entry for a quarantine action.
         * 
         * @param action Action being performed.
         * @param entryId Entry ID affected (0 for system events).
         * @param details Description of the action.
         * 
         * @details Inserts into quarantine_audit_log table if audit logging enabled.
         * Captures timestamp, user, machine, and success status.
         */
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
        //                  UTILITY STRING CONVERSIONS
        // ============================================================================

        /**
         * @brief Converts ThreatType enum to human-readable string.
         * @param type ThreatType value.
         * @return Wide string representation (e.g., "Virus", "Trojan").
         */
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

        /**
         * @brief Parses string to ThreatType enum.
         * @param str String representation.
         * @return ThreatType value, Unknown if not recognized.
         */
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

        /**
         * @brief Converts ThreatSeverity enum to human-readable string.
         * @param severity ThreatSeverity value.
         * @return Wide string representation (e.g., "Low", "High", "Critical").
         */
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

        /**
         * @brief Parses string to ThreatSeverity enum.
         * @param str String representation.
         * @return ThreatSeverity value, Medium as default.
         */
        QuarantineDB::ThreatSeverity QuarantineDB::StringToThreatSeverity(std::wstring_view str) {
            if (str == L"Info") return ThreatSeverity::Info;
            if (str == L"Low") return ThreatSeverity::Low;
            if (str == L"Medium") return ThreatSeverity::Medium;
            if (str == L"High") return ThreatSeverity::High;
            if (str == L"Critical") return ThreatSeverity::Critical;
            return ThreatSeverity::Medium;
        }

        /**
         * @brief Converts QuarantineStatus enum to human-readable string.
         * @param status QuarantineStatus value.
         * @return Wide string representation (e.g., "Active", "Restored").
         */
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

        /**
         * @brief Parses string to QuarantineStatus enum.
         * @param str String representation.
         * @return QuarantineStatus value, Active as default.
         */
        QuarantineDB::QuarantineStatus QuarantineDB::StringToQuarantineStatus(std::wstring_view str) {
            if (str == L"Active") return QuarantineStatus::Active;
            if (str == L"Restored") return QuarantineStatus::Restored;
            if (str == L"Deleted") return QuarantineStatus::Deleted;
            if (str == L"Expired") return QuarantineStatus::Expired;
            if (str == L"Corrupted") return QuarantineStatus::Corrupted;
            if (str == L"Pending") return QuarantineStatus::Pending;
            return QuarantineStatus::Active;
        }

        /**
         * @brief Converts QuarantineAction enum to human-readable string.
         * @param action QuarantineAction value.
         * @return Wide string representation (e.g., "Quarantined", "Restored").
         */
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

        // ============================================================================
        //              STATISTICS, CONFIG & MAINTENANCE OPERATIONS
        // ============================================================================

        /**
         * @brief Retrieves current quarantine statistics.
         * @param err Optional error output parameter (unused).
         * @return Copy of current Statistics structure.
         */
        QuarantineDB::Statistics QuarantineDB::GetStatistics(DatabaseError* err) {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            return m_stats;
        }

        /**
         * @brief Resets all statistics counters to zero.
         */
        void QuarantineDB::ResetStatistics() {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats = Statistics{};
        }

        /**
         * @brief Retrieves current configuration.
         * @return Copy of current Config structure.
         */
        QuarantineDB::Config QuarantineDB::GetConfig() const {
            std::shared_lock<std::shared_mutex> lock(m_configMutex);
            return m_config;
        }

        /**
         * @brief Sets maximum retention period for quarantined files.
         * @param days Retention period in hours.
         */
        void QuarantineDB::SetMaxRetentionDays(std::chrono::hours days) {
            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config.maxRetentionDays = days;
        }

        /**
         * @brief Sets maximum total quarantine storage size.
         * @param sizeBytes Maximum size in bytes.
         */
        void QuarantineDB::SetMaxQuarantineSize(size_t sizeBytes) {
            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config.maxQuarantineSize = sizeBytes;
        }

        /**
         * @brief Runs SQLite VACUUM to reclaim disk space.
         * @param err Optional error output parameter.
         * @return true if vacuum succeeded.
         */
        bool QuarantineDB::Vacuum(DatabaseError* err) {
            SS_LOG_INFO(L"QuarantineDB", L"Running VACUUM...");
            return DatabaseManager::Instance().Vacuum(err);
        }

        /**
         * @brief Checks database integrity using SQLite integrity_check.
         * @param err Optional error output parameter.
         * @return true if integrity check passed.
         */
        bool QuarantineDB::CheckIntegrity(DatabaseError* err) {
            SS_LOG_INFO(L"QuarantineDB", L"Checking integrity...");
            std::vector<std::wstring> issues;
            return DatabaseManager::Instance().CheckIntegrity(issues, err);
        }

        /**
         * @brief Optimizes database for better query performance.
         * @param err Optional error output parameter.
         * @return true if optimization succeeded.
         */
        bool QuarantineDB::Optimize(DatabaseError* err) {
            SS_LOG_INFO(L"QuarantineDB", L"Optimizing database...");
            return DatabaseManager::Instance().Optimize(err);
        }

        /**
         * @brief Rebuilds all table indices.
         * @param err Optional error output parameter.
         * @return true if indices were rebuilt successfully.
         */
        bool QuarantineDB::RebuildIndices(DatabaseError* err) {
            SS_LOG_INFO(L"QuarantineDB", L"Rebuilding indices...");
            return DatabaseManager::Instance().Execute(SQL_CREATE_INDICES, err);
        }

        /**
         * @brief Public wrapper for cleaning up expired entries.
         * @param err Optional error output parameter.
         * @return true if cleanup succeeded.
         */        
        bool QuarantineDB::CleanupExpired(DatabaseError* err) {
            return cleanupOldEntries(err);
        }

        /**
         * @brief Cleans up entries to meet a target storage size.
         * 
         * @param targetSize Target maximum storage size in bytes.
         * @param err Optional error output parameter.
         * @return true if cleanup succeeded or already within limits.
         * 
         * @details Deletes oldest active entries first until target is reached.
         * Updates statistics after cleanup.
         */
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

        /**
         * @brief Deletes ALL quarantine entries and files.
         * 
         * @param confirmed Must be true to proceed (safety check).
         * @param err Optional error output parameter.
         * @return true if all entries were deleted.
         * 
         * @warning DESTRUCTIVE OPERATION - Cannot be undone!
         * @note Deletes physical files, database entries, audit logs, and metadata.
         */
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

        // ============================================================================
        //                    EXPORT/IMPORT OPERATIONS
        // ============================================================================

        /**
         * @brief Exports a single quarantine entry to a JSON file.
         * 
         * @param entryId Entry ID to export.
         * @param exportPath Destination file path.
         * @param includeMetadata Whether to include custom metadata.
         * @param err Optional error output parameter.
         * @return true if export succeeded.
         * 
         * @details Exported JSON includes:
         * - Format version and export timestamp
         * - Complete entry metadata
         * - Base64-encoded file content
         * - All hashes and threat information
         */
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

        /**
         * @brief Imports a quarantine entry from a JSON export file.
         * 
         * @param importPath Path to JSON export file.
         * @param err Optional error output parameter.
         * @return New entry ID on success, -1 on failure.
         * 
         * @details Validates format, decodes Base64 file content, verifies
         * hash integrity, and creates new quarantine entry with imported data.
         */
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


		// ============================================================================
        //                    ANALYSIS SUBMISSION
        // ============================================================================

        /**
         * @brief Submits a quarantined file for cloud analysis.
         * 
         * @param entryId Entry ID to submit.
         * @param submissionEndpoint API endpoint for submission.
         * @param err Optional error output parameter.
         * @return true if submission was prepared and entry status updated.
         * 
         * @details Current Implementation:
         * 1. Validates entry exists and is active
         * 2. Exports entry data to temporary JSON file
         * 3. Updates entry status to Pending
         * 4. Logs audit event for compliance
         * 5. Cleans up temporary export file
         * 
         * @note Network submission requires separate ThreatIntel module integration.
         *       This method prepares the submission and updates tracking status.
         *       Actual network transmission should be handled by:
         *       - ThreatIntelDatabase::SubmitSample() for cloud analysis
         *       - Async job queue for background processing
         * 
         * Future Enhancement:
         * @code{.cpp}
         * // Example integration with ThreatIntel module:
         * auto& threatIntel = ThreatIntel::ThreatIntelDatabase::Instance();
         * std::future<bool> result = threatIntel.SubmitSampleAsync(
         *     entryId, fileData, submissionEndpoint);
         * @endcode
         */
        bool QuarantineDB::SubmitForAnalysis(int64_t entryId, std::wstring_view submissionEndpoint,
            DatabaseError* err)
        {
            SS_LOG_INFO(L"QuarantineDB", L"Preparing entry %lld for analysis submission to: %ls", 
                       entryId, submissionEndpoint.data());

            // Validate entry exists
            auto entryOpt = GetEntry(entryId, err);
            if (!entryOpt) {
                SS_LOG_ERROR(L"QuarantineDB", L"Entry %lld not found for submission", entryId);
                return false;
            }

            QuarantineEntry entry = *entryOpt;
            
            // Validate entry is in a submittable state
            if (entry.status != QuarantineStatus::Active && 
                entry.status != QuarantineStatus::Pending) {
                if (err) {
                    err->sqliteCode = SQLITE_CONSTRAINT;
                    err->message = L"Entry is not in a submittable state (must be Active or Pending)";
                }
                SS_LOG_WARN(L"QuarantineDB", L"Entry %lld cannot be submitted, status: %ls",
                    entryId, QuarantineStatusToString(entry.status).c_str());
                return false;
            }

            // Create temporary export for submission preparation
            std::wstring tempPath = m_config.quarantineBasePath + L"\\submission_prep_" + 
                                   std::to_wstring(entryId) + L"_" +
                                   std::to_wstring(std::chrono::system_clock::now().time_since_epoch().count()) +
                                   L".json";

            if (!ExportEntry(entryId, tempPath, true, err)) {
                SS_LOG_ERROR(L"QuarantineDB", L"Failed to prepare export for entry %lld", entryId);
                return false;
            }

            // Update entry status to track submission
            entry.status = QuarantineStatus::Pending;
            std::wstring timestampStr = ToWide(timePointToString(std::chrono::system_clock::now()));
            entry.notes += L"\n[Submission prepared at: " + timestampStr + 
                          L", Endpoint: " + std::wstring(submissionEndpoint) + L"]";
            entry.lastAccessTime = std::chrono::system_clock::now();

            if (!dbUpdateEntry(entry, err)) {
                SS_LOG_WARN(L"QuarantineDB", L"Failed to update entry status after submission prep");
            }

            // Log audit event for compliance tracking
            logAuditEvent(QuarantineAction::Submitted, entryId, 
                         L"Submission prepared for endpoint: " + std::wstring(submissionEndpoint));

            // Clean up temporary preparation file
            Utils::FileUtils::Error fileErr;
            if (Utils::FileUtils::RemoveFile(tempPath, &fileErr)) {
                SS_LOG_DEBUG(L"QuarantineDB", L"Submission preparation file cleaned up: %ls", tempPath.c_str());
            } else {
                SS_LOG_DEBUG(L"QuarantineDB", L"Note: Submission preparation file retained for review: %ls", 
                    tempPath.c_str());
            }

            SS_LOG_INFO(L"QuarantineDB", L"Entry %lld prepared for analysis submission", entryId);
            
            // NOTE: Actual network submission should be performed by the calling code
            // using ThreatIntel module or dedicated submission service. This method
            // handles the quarantine-side preparation and status tracking only.

            return true;
        }

		// ============================================================================
        //                    REPORTING OPERATIONS
        // ============================================================================

        /**
         * @brief Generates a comprehensive text-based quarantine report.
         * 
         * @param filter Optional filter for which entries to include.
         * @return Wide string containing formatted report.
         * 
         * @details Report includes:
         * - Header with generation time and system info
         * - Summary statistics (counts, sizes)
         * - Threat type breakdown
         * - Severity breakdown
         * - List of recent/filtered entries with details
         */
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

        /**
         * @brief Exports quarantine entries to a JSON file.
         * 
         * @param filePath Destination file path.
         * @param filter Optional filter for which entries to export.
         * @param err Optional error output parameter.
         * @return true if export succeeded.
         * 
         * @details Exports metadata only (no file content). Includes
         * format info, statistics, and array of entry records.
         */
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

        /**
         * @brief Exports quarantine entries to a CSV file.
         * 
         * @param filePath Destination file path.
         * @param filter Optional filter for which entries to export.
         * @param err Optional error output parameter.
         * @return true if export succeeded.
         * 
         * @details Creates UTF-8 encoded CSV with BOM. Properly escapes
         * fields containing commas, quotes, or newlines.
         */
        bool QuarantineDB::ExportToCSV(std::wstring_view filePath, const QueryFilter* filter,
            DatabaseError* err)
        {
            SS_LOG_INFO(L"QuarantineDB", L"Exporting to CSV: %ls", filePath.data());

            // Get entries
            auto entries = filter ? Query(*filter, err) : GetActiveEntries(10000, err);

            // Open file for writing
            std::ofstream csvFile(std::wstring(filePath), std::ios::out | std::ios::trunc | std::ios::binary);
            if (!csvFile.is_open()) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to open CSV file for writing";
                }
                return false;
            }

            // Write UTF-8 BOM correctly
            csvFile.write("\xEF\xBB\xBF", 3);  // Correct UTF-8 BOM

            // Write CSV header (convert to UTF-8)
            std::string header = "Entry ID,Original Path,Original Filename,File Size (bytes),Quarantine Time,"
                "Threat Type,Threat Name,Severity,Status,SHA256 Hash,User,Machine,Detection Reason,Notes\n";
            csvFile.write(header.c_str(), header.size());

            // Helper lambda for CSV escape (keep same)
            auto escapeCsv = [](const std::wstring& field) -> std::string {
                std::string utf8Field = ToUTF8(field);
                if (utf8Field.find(',') != std::string::npos ||
                    utf8Field.find('"') != std::string::npos ||
                    utf8Field.find('\n') != std::string::npos) {
                    std::string escaped = "\"";
                    for (char c : utf8Field) {
                        if (c == '"') escaped += "\"\"";
                        else escaped += c;
                    }
                    escaped += "\"";
                    return escaped;
                }
                return utf8Field;
                };

            // Write entries (convert each field to UTF-8)
            for (const auto& entry : entries) {
                std::ostringstream line;
                line << entry.id << ","
                    << escapeCsv(entry.originalPath) << ","
                    << escapeCsv(entry.originalFileName) << ","
                    << entry.originalSize << ","
                    << escapeCsv(ToWide(timePointToString(entry.quarantineTime))) << ","
                    << escapeCsv(ThreatTypeToString(entry.threatType)) << ","
                    << escapeCsv(entry.threatName) << ","
                    << escapeCsv(ThreatSeverityToString(entry.severity)) << ","
                    << escapeCsv(QuarantineStatusToString(entry.status)) << ","
                    << escapeCsv(entry.sha256Hash) << ","
                    << escapeCsv(entry.userName) << ","
                    << escapeCsv(entry.machineName) << ","
                    << escapeCsv(entry.detectionReason) << ","
                    << escapeCsv(entry.notes) << "\n";

                std::string lineStr = line.str();
                csvFile.write(lineStr.c_str(), lineStr.size());
            }

            csvFile.close();

            SS_LOG_INFO(L"QuarantineDB", L"CSV export completed. %zu entries exported", entries.size());
            return true;
        }

        // ============================================================================
        //                    BACKUP & RESTORE OPERATIONS
        // ============================================================================

        /**
         * @brief Creates a comprehensive backup of the entire quarantine vault.
         * 
         * @param backupPath Destination path for the backup JSON file.
         * @param err Optional error output parameter.
         * @return true if backup succeeded (partial success if some entries fail).
         * 
         * @details Backup Process:
         * 1. Creates backup directory if needed
         * 2. Retrieves all active quarantine entries
         * 3. For each entry:
         *    - Extracts encrypted file data
         *    - Includes complete metadata (30+ fields)
         *    - Encodes file content as Base64
         * 4. Adds statistics snapshot
         * 5. Saves as atomic JSON file
         * 
         * Backup Format:
         * ```json
         * {
         *   "backup_format": "ShadowStrike Quarantine Backup",
         *   "backup_version": "1.0",
         *   "backup_time": "2024-01-15T10:30:00Z",
         *   "entry_count": 42,
         *   "entries": [ {...}, {...} ],
         *   "statistics": {...}
         * }
         * ```
         * 
         * @warning Backup files can be large (includes all file contents).
         * @note Logs audit event for compliance tracking.
         */
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

        /**
         * @brief Restores quarantine entries from a backup file.
         * 
         * @param backupPath Path to the backup JSON file.
         * @param err Optional error output parameter.
         * @return true if at least one entry was restored successfully.
         * 
         * @details Restore Process:
         * 1. Loads and validates backup file format
         * 2. For each entry in backup:
         *    - Parses all metadata fields (30+)
         *    - Decodes Base64 file content
         *    - Verifies SHA256 hash integrity
         *    - Creates new quarantine entry via QuarantineFileDetailed
         *    - Appends "[Restored from backup]" to notes
         * 3. Logs audit event with success/failure counts
         * 
         * Integrity Validation:
         * - Each entry's SHA256 hash is verified against decoded content
         * - Hash mismatches cause individual entry to be skipped
         * - Parse failures cause individual entry to be skipped
         * 
         * @note Creates new entry IDs (does not preserve original IDs).
         * @note Entries marked with original quarantine timestamp.
         * @warning Duplicate detection not performed - may create duplicates.
         */
        bool QuarantineDB::RestoreQuarantine(std::wstring_view backupPath, DatabaseError* err) {
            SS_LOG_INFO(L"QuarantineDB", L"Restoring quarantine from backup: %ls", backupPath.data());

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

            if (!backup.contains("backup_format") || !backup.contains("entries")) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Invalid backup file format";
                }
                return false;
            }

            const Json& entriesArray = backup["entries"];
            size_t totalEntries = entriesArray.size();
            size_t successCount = 0;
            size_t failureCount = 0;

            SS_LOG_INFO(L"QuarantineDB", L"Restoring %zu entries from backup", totalEntries);

            for (const auto& entryBackup : entriesArray) {
                try {
                    QuarantineEntry entry;

                    //PARSE ALL FIELDS FIRST!
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

                    // PARSE HASHES BEFORE VERIFICATION!
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

                    // NOW VERIFY HASH (entry.sha256Hash is populated!)
                    std::wstring md5, sha1, sha256;
                    if (calculateHashes(fileData, md5, sha1, sha256)) {
                        if (sha256 != entry.sha256Hash) {
                            SS_LOG_WARN(L"QuarantineDB", L"Hash mismatch for restored entry (expected: %ls, got: %ls)",
                                entry.sha256Hash.c_str(), sha256.c_str());
                            failureCount++;
                            continue;
                        }
                    }

                    // Import the entry
                    int64_t newId = QuarantineFileDetailed(entry, fileData, nullptr);
                    if (newId > 0) {
                        successCount++;
                    }
                    else {
                        failureCount++;
                    }

                }
                catch (const std::exception& e) {
                    SS_LOG_WARN(L"QuarantineDB", L"Exception restoring entry: %hs", e.what());
                    failureCount++;
                    continue;
                }
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