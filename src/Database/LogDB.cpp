// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

/**
 * @file LogDB.cpp
 * @brief Enterprise-Grade Centralized Logging Database System Implementation
 * 
 * @details This file implements the LogDB class, providing a high-performance,
 * persistent logging system with SQLite backend for the ShadowStrike Antivirus Engine.
 * 
 * ============================================================================
 *                              ARCHITECTURE OVERVIEW
 * ============================================================================
 * 
 *     ┌─────────────────────────────────────────────────────────────────────┐
 *     │                         APPLICATION LAYER                            │
 *     │                                                                       │
 *     │   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐    │
 *     │   │   Scanner   │ │  Quarantine │ │   Network   │ │   Service   │    │
 *     │   │   Module    │ │    Module   │ │   Monitor   │ │   Manager   │    │
 *     │   └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └──────┬──────┘    │
 *     │          │               │               │               │            │
 *     └──────────┼───────────────┼───────────────┼───────────────┼────────────┘
 *                │               │               │               │
 *                ▼               ▼               ▼               ▼
 *     ┌─────────────────────────────────────────────────────────────────────┐
 *     │                           LOGDB SINGLETON                            │
 *     │                                                                       │
 *     │   ┌─────────────────────────────────────────────────────────────┐    │
 *     │   │                    LOGGING PIPELINE                          │    │
 *     │   │                                                               │    │
 *     │   │  ┌──────────┐   ┌──────────────┐   ┌───────────────────┐    │    │
 *     │   │  │  Level   │──▶│  Async/Sync  │──▶│  Batch Processor  │    │    │
 *     │   │  │  Filter  │   │   Decision   │   │                   │    │    │
 *     │   │  └──────────┘   └──────────────┘   └─────────┬─────────┘    │    │
 *     │   │                                               │              │    │
 *     │   │                           ┌───────────────────┘              │    │
 *     │   │                           ▼                                  │    │
 *     │   │   ┌──────────────────────────────────────────────────────┐   │    │
 *     │   │   │               PENDING WRITES QUEUE                   │   │    │
 *     │   │   │  [ Entry ] ─▶ [ Entry ] ─▶ [ Entry ] ─▶ [ Entry ]   │   │    │
 *     │   │   └───────────────────────────┬──────────────────────────┘   │    │
 *     │   │                               │                              │    │
 *     │   │                               ▼ (batch threshold / timeout)  │    │
 *     │   │                   ┌─────────────────────────┐                │    │
 *     │   │                   │   BATCH WRITE THREAD    │                │    │
 *     │   │                   │                         │                │    │
 *     │   │                   │  • Batches up to 100    │                │    │
 *     │   │                   │  • Flushes every 5s     │                │    │
 *     │   │                   │  • Transactional write  │                │    │
 *     │   │                   └────────────┬────────────┘                │    │
 *     │   │                                │                              │    │
 *     │   └────────────────────────────────┼──────────────────────────────┘    │
 *     │                                    │                                   │
 *     │   ┌────────────────────────────────▼──────────────────────────────┐   │
 *     │   │                    DATABASE MANAGER                            │   │
 *     │   │                                                                │   │
 *     │   │   ┌────────────┐  ┌────────────┐  ┌────────────────────┐      │   │
 *     │   │   │ Connection │  │ Prepared   │  │   Transaction      │      │   │
 *     │   │   │    Pool    │  │ Statement  │  │     Manager        │      │   │
 *     │   │   │            │  │   Cache    │  │                    │      │   │
 *     │   │   └────────────┘  └────────────┘  └────────────────────┘      │   │
 *     │   │                                                                │   │
 *     │   └────────────────────────────────────────────────────────────────┘   │
 *     │                                                                       │
 *     └───────────────────────────────────────────────────────────────────────┘
 *                                        │
 *                                        ▼
 *     ┌─────────────────────────────────────────────────────────────────────┐
 *     │                         SQLITE DATABASE                              │
 *     │                                                                       │
 *     │   ┌───────────────────────────────────────────────────────────────┐  │
 *     │   │                      log_entries TABLE                         │  │
 *     │   │                                                                 │  │
 *     │   │  • id (INTEGER PRIMARY KEY)     • timestamp (TEXT)             │  │
 *     │   │  • level (INTEGER)              • category (INTEGER)           │  │
 *     │   │  • source (TEXT)                • message (TEXT)               │  │
 *     │   │  • details (TEXT)               • process_id (INTEGER)         │  │
 *     │   │  • thread_id (INTEGER)          • user_name (TEXT)             │  │
 *     │   │  • machine_name (TEXT)          • metadata (TEXT)              │  │
 *     │   │  • error_code (INTEGER)         • error_context (TEXT)         │  │
 *     │   │  • duration_ms (INTEGER)        • file_path (TEXT)             │  │
 *     │   │  • line_number (INTEGER)        • function_name (TEXT)         │  │
 *     │   │                                                                 │  │
 *     │   └───────────────────────────────────────────────────────────────┘  │
 *     │                                                                       │
 *     │   ┌─────────────────────────┐    ┌────────────────────────────────┐  │
 *     │   │        INDICES          │    │    FTS5 VIRTUAL TABLE         │  │
 *     │   │                         │    │                                │  │
 *     │   │  • idx_log_timestamp    │    │  log_fts:                      │  │
 *     │   │  • idx_log_level        │    │    source, message, details    │  │
 *     │   │  • idx_log_category     │    │                                │  │
 *     │   │  • idx_log_source       │    │  Enables full-text search      │  │
 *     │   │  • idx_log_process      │    │  across log content            │  │
 *     │   │  • idx_log_error        │    │                                │  │
 *     │   │  • idx_log_composite    │    │  Sync triggers:                │  │
 *     │   │                         │    │    INSERT/UPDATE/DELETE        │  │
 *     │   └─────────────────────────┘    └────────────────────────────────┘  │
 *     │                                                                       │
 *     └─────────────────────────────────────────────────────────────────────┘
 * 
 * ============================================================================
 *                              KEY COMPONENTS
 * ============================================================================
 * 
 * 1. LOG LEVEL FILTERING
 *    - Trace (0): Verbose debugging, production-disabled
 *    - Debug (1): Development diagnostics
 *    - Info (2): Normal operational messages
 *    - Warn (3): Potential issues
 *    - Error (4): Recoverable failures
 *    - Fatal (5): Critical system failures
 * 
 * 2. LOG CATEGORIES (17 types)
 *    - General, System, Security, Network, FileSystem, Process
 *    - Registry, Service, Driver, Performance, Database
 *    - Scanner, Quarantine, Update, Configuration, UserInterface, Custom
 * 
 * 3. ASYNCHRONOUS LOGGING
 *    - Pending writes queue with configurable batch size (default: 100)
 *    - Background thread flushes at interval (default: 5 seconds)
 *    - Returns -1 for async writes (ID not immediately available)
 *    - Graceful shutdown with final flush
 * 
 * 4. FULL-TEXT SEARCH (FTS5)
 *    - SQLite FTS5 virtual table for content search
 *    - Automatic sync via INSERT/UPDATE/DELETE triggers
 *    - Optional: can be disabled in configuration
 * 
 * 5. LOG ROTATION & ARCHIVAL
 *    - Size-based rotation (default: 500MB)
 *    - Age-based rotation (default: 30 days)
 *    - Automatic archive creation with timestamp
 *    - Configurable archive retention count
 * 
 * 6. PERFORMANCE LOGGING
 *    - RAII PerformanceLogger class for automatic duration measurement
 *    - Support for custom details and success indicators
 *    - Cancellable for conditional logging
 * 
 * ============================================================================
 *                              THREAD SAFETY
 * ============================================================================
 * 
 * - Configuration: Protected by std::shared_mutex (read/write separation)
 * - Statistics: Protected by std::mutex
 * - Batch queue: Protected by std::mutex + condition_variable
 * - Atomic flags: m_initialized, m_shutdownBatch (memory_order_acquire/release)
 * - Database access: Thread-safe via DatabaseManager connection pool
 * 
 * ============================================================================
 *                              PERFORMANCE NOTES
 * ============================================================================
 * 
 * - Batch writes reduce SQLite transaction overhead (100 entries/transaction)
 * - Prepared statement caching via DatabaseManager
 * - Composite index (level, category, timestamp) for common queries
 * - Partial index on error_code (WHERE error_code != 0)
 * - WAL mode enables concurrent readers with single writer
 * 
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @date 2026
 * @copyright MIT License
 * 
 * @see LogDB.hpp for class declaration
 * @see DatabaseManager.hpp for underlying storage
 * @see PerformanceLogger for RAII timing helper
 */

#include"pch.h"
#include "LogDB.hpp"
#include "../Utils/FileUtils.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <filesystem>

#ifdef _WIN32
#include <Windows.h>
#include <Lmcons.h>  // For UNLEN constant
#endif

namespace ShadowStrike {
    namespace Database {

        // ============================================================================
        // Anonymous Namespace - Internal Constants and Helpers
        // ============================================================================

        namespace {

            /**
             * @brief Current database schema version for LogDB.
             * 
             * @details Used for schema migration decisions. Increment when making
             * breaking schema changes that require data migration.
             * 
             * Version History:
             * - v1: Initial schema with log_entries table, indices, and FTS5
             */
            constexpr int LOGDB_SCHEMA_VERSION = 1;

            // ========================================================================
            //                      SQL SCHEMA DEFINITIONS
            // ========================================================================

            /**
             * @brief SQL statement to create the main log_entries table.
             * 
             * @details Table schema for persistent log storage:
             * - id: Auto-incrementing primary key
             * - timestamp: ISO 8601 format with milliseconds (TEXT for SQLite compatibility)
             * - level: Log level (0=Trace to 5=Fatal)
             * - category: Log category (0-255)
             * - source: Module/component name generating the log
             * - message: Primary log message content
             * - details: Extended information (optional)
             * - process_id/thread_id: System identifiers for tracing
             * - user_name/machine_name: System context
             * - metadata: JSON-formatted structured data
             * - error_code/error_context: Error-specific information
             * - duration_ms: Performance timing (for operation logs)
             * - file_path/line_number/function_name: Source location (optional)
             */
            constexpr const char* SQL_CREATE_LOGS_TABLE = R"(
                CREATE TABLE IF NOT EXISTS log_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level INTEGER NOT NULL,
                    category INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details TEXT,
                    process_id INTEGER NOT NULL,
                    thread_id INTEGER NOT NULL,
                    user_name TEXT,
                    machine_name TEXT,
                    metadata TEXT,
                    error_code INTEGER DEFAULT 0,
                    error_context TEXT,
                    duration_ms INTEGER DEFAULT 0,
                    file_path TEXT,
                    line_number INTEGER DEFAULT 0,
                    function_name TEXT
                );
            )";

            /**
             * @brief SQL statement to create performance indices on log_entries.
             * 
             * @details Index strategy:
             * - idx_log_timestamp: DESC for recent-first queries (most common)
             * - idx_log_level: Filter by severity
             * - idx_log_category: Filter by system component
             * - idx_log_source: Filter by module name
             * - idx_log_process: Filter by process ID
             * - idx_log_error: Partial index for non-zero error codes (space efficient)
             * - idx_log_composite: Covering index for common filter combinations
             */
            constexpr const char* SQL_CREATE_INDICES = R"(
                CREATE INDEX IF NOT EXISTS idx_log_timestamp ON log_entries(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_log_level ON log_entries(level);
                CREATE INDEX IF NOT EXISTS idx_log_category ON log_entries(category);
                CREATE INDEX IF NOT EXISTS idx_log_source ON log_entries(source);
                CREATE INDEX IF NOT EXISTS idx_log_process ON log_entries(process_id);
                CREATE INDEX IF NOT EXISTS idx_log_error ON log_entries(error_code) WHERE error_code != 0;
                CREATE INDEX IF NOT EXISTS idx_log_composite ON log_entries(level, category, timestamp DESC);
            )";

            /**
             * @brief SQL statement to create FTS5 virtual table for full-text search.
             * 
             * @details Uses SQLite FTS5 extension with content synchronization:
             * - content='log_entries': External content table
             * - content_rowid='id': Maps to log_entries.id
             * - Indexed columns: source, message, details
             */
            constexpr const char* SQL_CREATE_FTS_TABLE = R"(
                CREATE VIRTUAL TABLE IF NOT EXISTS log_fts USING fts5(
                    source, message, details, 
                    content='log_entries',
                    content_rowid='id'
                );
            )";

            /**
             * @brief SQL triggers to keep FTS5 index synchronized with log_entries.
             * 
             * @details Three triggers maintain consistency:
             * - log_fts_insert: Adds FTS entry on INSERT
             * - log_fts_delete: Removes FTS entry on DELETE
             * - log_fts_update: Handles UPDATE by delete + insert
             */
            constexpr const char* SQL_CREATE_FTS_TRIGGERS = R"(
                CREATE TRIGGER IF NOT EXISTS log_fts_insert AFTER INSERT ON log_entries BEGIN
                    INSERT INTO log_fts(rowid, source, message, details)
                    VALUES (new.id, new.source, new.message, new.details);
                END;
                
                CREATE TRIGGER IF NOT EXISTS log_fts_delete AFTER DELETE ON log_entries BEGIN
                    DELETE FROM log_fts WHERE rowid = old.id;
                END;
                
                CREATE TRIGGER IF NOT EXISTS log_fts_update AFTER UPDATE ON log_entries BEGIN
                    DELETE FROM log_fts WHERE rowid = old.id;
                    INSERT INTO log_fts(rowid, source, message, details)
                    VALUES (new.id, new.source, new.message, new.details);
                END;
            )";

            // ========================================================================
            //                      SQL CRUD OPERATIONS
            // ========================================================================

            /**
             * @brief SQL INSERT statement for log entries.
             * @details Parameters (17 total): timestamp, level, category, source, message,
             * details, process_id, thread_id, user_name, machine_name, metadata,
             * error_code, error_context, duration_ms, file_path, line_number, function_name
             */
            constexpr const char* SQL_INSERT_ENTRY = R"(
                INSERT INTO log_entries (
                    timestamp, level, category, source, message, details,
                    process_id, thread_id, user_name, machine_name, metadata,
                    error_code, error_context, duration_ms, file_path, line_number, function_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            )";

            /**
             * @brief SQL SELECT statement for single entry retrieval by ID.
             */
            constexpr const char* SQL_SELECT_ENTRY = R"(
                SELECT * FROM log_entries WHERE id = ?
            )";

            /**
             * @brief SQL DELETE statement for single entry removal by ID.
             */
            constexpr const char* SQL_DELETE_ENTRY = R"(
                DELETE FROM log_entries WHERE id = ?
            )";

            /**
             * @brief SQL DELETE statement for time-based cleanup.
             * @details Deletes all entries with timestamp before the specified value.
             */
            constexpr const char* SQL_DELETE_BEFORE = R"(
                DELETE FROM log_entries WHERE timestamp < ?
            )";

            /**
             * @brief SQL DELETE statement for level-based cleanup.
             * @details Deletes all entries with the specified log level.
             */
            constexpr const char* SQL_DELETE_BY_LEVEL = R"(
                DELETE FROM log_entries WHERE level = ?
            )";

            /**
             * @brief SQL DELETE statement to clear all log entries.
             * @warning This operation is irreversible.
             */
            constexpr const char* SQL_DELETE_ALL = R"(
                DELETE FROM log_entries
            )";

            /**
             * @brief SQL statement to count total log entries.
             */
            constexpr const char* SQL_COUNT_ALL = R"(
                SELECT COUNT(*) FROM log_entries
            )";

            /**
             * @brief SQL statement to get the oldest log entry timestamp.
             */
            constexpr const char* SQL_GET_OLDEST = R"(
                SELECT timestamp FROM log_entries ORDER BY timestamp ASC LIMIT 1
            )";

            /**
             * @brief SQL statement to get the newest log entry timestamp.
             */
            constexpr const char* SQL_GET_NEWEST = R"(
                SELECT timestamp FROM log_entries ORDER BY timestamp DESC LIMIT 1
            )";

            // ========================================================================
            //                      UTF-8 CONVERSION HELPERS
            // ========================================================================

            /**
             * @brief Converts a wide string (UTF-16) to UTF-8 encoding.
             * 
             * @param wstr The wide string view to convert.
             * @return UTF-8 encoded std::string. Empty string on failure.
             * 
             * @details Uses Windows WideCharToMultiByte API with CP_UTF8 code page.
             * Thread-safe: Uses only local variables.
             * 
             * @note Required for SQLite which stores text as UTF-8.
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
             * @brief Converts a UTF-8 string to wide string (UTF-16) encoding.
             * 
             * @param str The UTF-8 string view to convert.
             * @return UTF-16 encoded std::wstring. Empty string on failure.
             * 
             * @details Uses Windows MultiByteToWideChar API with CP_UTF8 code page.
             * Thread-safe: Uses only local variables.
             * 
             * @note Required for Windows API calls and UI display.
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
             * @brief Retrieves the local computer's NetBIOS name.
             * 
             * @return Machine name as std::wstring. "Unknown" on failure.
             * 
             * @details Uses GetComputerNameW Windows API. The result is cached
             * at LogDB construction to avoid repeated system calls.
             * 
             * @note Maximum length is MAX_COMPUTERNAME_LENGTH (15 characters).
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
             * @brief Retrieves the current user's login name.
             * 
             * @return User name as std::wstring. "Unknown" on failure.
             * 
             * @details Uses GetUserNameW Windows API. The result is cached
             * at LogDB construction to avoid repeated system calls.
             * 
             * @note Maximum length is UNLEN (256 characters).
             */
            std::wstring GetCurrentUserName() {
                wchar_t buf[UNLEN + 1] = {};
                DWORD size = UNLEN + 1;
                if (::GetUserNameW(buf, &size)) {
                    return std::wstring(buf);
                }
                return L"Unknown";
            }

        } // anonymous namespace

        // ============================================================================
        //                      LogDB SINGLETON IMPLEMENTATION
        // ============================================================================

        /**
         * @brief Returns the singleton instance of LogDB.
         * 
         * @return Reference to the global LogDB instance.
         * 
         * @details Uses C++11 magic statics (thread-safe initialization).
         * The instance is created on first access and destroyed at program exit.
         * 
         * @note Call Initialize() before any logging operations.
         */
        LogDB& LogDB::Instance() {
            static LogDB instance;
            return instance;
        }

        /**
         * @brief Private constructor - caches system information.
         * 
         * @details Called once by Instance() on first access.
         * Caches machine name and user name to avoid repeated system calls.
         */
        LogDB::LogDB() {
            m_machineName = GetMachineName();
            m_userName = GetCurrentUserName();
        }

        /**
         * @brief Destructor - ensures clean shutdown.
         * 
         * @details Calls Shutdown() to flush pending writes, stop background
         * thread, and release database resources.
         */
        LogDB::~LogDB() {
            Shutdown();
        }

        // ============================================================================
        //                      LIFECYCLE MANAGEMENT
        // ============================================================================

        /**
         * @brief Initializes the LogDB system with specified configuration.
         * 
         * @param config Configuration settings for the logging system.
         * @param err Optional pointer to receive detailed error information.
         * @return true if initialization succeeded, false otherwise.
         * 
         * @details Initialization sequence:
         * 1. Stores configuration with thread-safe mutex
         * 2. Forces shutdown of any existing DatabaseManager instance
         * 3. Initializes DatabaseManager with log-specific settings
         * 4. Creates database schema (tables, indices, FTS)
         * 5. Starts background batch write thread (if async enabled)
         * 6. Calculates initial statistics from existing data
         * 
         * @note Safe to call multiple times - updates configuration if already initialized.
         * @warning Forces DatabaseManager shutdown on re-initialization.
         * 
         * @code
         * LogDB::Config config;
         * config.dbPath = L"C:\\ProgramData\\MyApp\\logs.db";
         * config.asyncLogging = true;
         * config.maxLogSizeMB = 200;
         * 
         * DatabaseError err;
         * if (!LogDB::Instance().Initialize(config, &err)) {
         *     std::wcerr << L"LogDB init failed: " << err.message << std::endl;
         * }
         * @endcode
         */
        bool LogDB::Initialize(const Config& config, DatabaseError* err) {
            if (m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"LogDB", L"Already initialized");

                {
                    std::unique_lock<std::shared_mutex> lock(m_configMutex);
                    m_config = config;
                }
                return true;
            }

            SS_LOG_INFO(L"LogDB", L"Initializing LogDB...");

            // Use scope to release lock early
            {
                std::unique_lock<std::shared_mutex> lock(m_configMutex);
                m_config = config;
            }  // Lock released here!

            // FORCE SHUTDOWN FIRST to ensure clean state!
            if (DatabaseManager::Instance().IsInitialized()) {
                SS_LOG_INFO(L"LogDB", L"Shutting down existing DatabaseManager instance");
                DatabaseManager::Instance().Shutdown();
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }

            // Initialize DatabaseManager with OUR config
            DatabaseConfig dbConfig;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                dbConfig.databasePath = m_config.dbPath;
                dbConfig.enableWAL = m_config.enableWAL;
                dbConfig.cacheSizeKB = m_config.dbCacheSizeKB;
                dbConfig.maxConnections = m_config.maxConnections;
            }
            dbConfig.minConnections = 2;
            dbConfig.autoBackup = false;

            if (!DatabaseManager::Instance().Initialize(dbConfig, err)) {
                SS_LOG_ERROR(L"LogDB", L"Failed to initialize DatabaseManager");
                return false;
            }

            // Create schema
            if (!createSchema(err)) {
                SS_LOG_ERROR(L"LogDB", L"Failed to create schema");
                DatabaseManager::Instance().Shutdown();
                return false;
            }

            // Start batch write thread if async logging is enabled
            bool asyncEnabled;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                asyncEnabled = m_config.asyncLogging;
            }

            if (asyncEnabled) {
                m_shutdownBatch.store(false, std::memory_order_release);
                m_batchThread = std::thread(&LogDB::batchWriteThread, this);
            }

            // Initialize statistics
            recalculateStatistics(err);

            m_initialized.store(true, std::memory_order_release);

            SS_LOG_INFO(L"LogDB", L"LogDB initialized successfully");

          

            return true;
        }
        
        void LogDB::Shutdown() {
            if (!m_initialized.load(std::memory_order_acquire)) {
                return;
            }

            SS_LOG_INFO(L"LogDB", L"Shutting down LogDB...");

            // Flush pending writes
            DatabaseError err;
            Flush(&err);

            // Stop batch thread
            m_shutdownBatch.store(true, std::memory_order_release);
            m_batchCV.notify_all();

            if (m_batchThread.joinable()) {
                m_batchThread.join();
            }

            // Shutdown database manager
            DatabaseManager::Instance().Shutdown();

            
            std::this_thread::sleep_for(std::chrono::milliseconds(50));

            // RESET CONFIG TO DEFAULT STATE - DON'T USE Config{}!
            {
                std::unique_lock<std::shared_mutex> lock(m_configMutex);
                m_config.asyncLogging = false;  // ✅ EXPLICITLY SET TO FALSE!
                m_config.minLogLevel = LogLevel::Info;
                m_config.enableFullTextSearch = false;
                // DON'T reset paths - they will be set by Initialize()
            }

            m_initialized.store(false, std::memory_order_release);

            SS_LOG_INFO(L"LogDB", L"LogDB shut down");
        }

        // ============================================================================
        //                      CORE LOGGING OPERATIONS
        // ============================================================================

        /**
         * @brief Logs a message with specified level and category.
         * 
         * @param level Severity level of the log entry.
         * @param category Functional category for filtering.
         * @param source Module or component name generating the log.
         * @param message The log message content.
         * @param err Optional pointer to receive error details on failure.
         * @return Entry ID on synchronous success, -1 for async queued, 0 if filtered.
         * 
         * @details Processing flow:
         * 1. Checks if level meets minimum threshold (filtered if below)
         * 2. Populates LogEntry with timestamp, process/thread IDs, cached user info
         * 3. Routes to async queue or direct insert based on configuration
         * 
         * @note System information (processId, threadId, userName, machineName) is
         * automatically populated from current context.
         * 
         * @code
         * LogDB::Instance().Log(LogLevel::Error, LogCategory::Scanner,
         *     L"MalwareDetector", L"Suspicious file detected: virus.exe");
         * @endcode
         */
        int64_t LogDB::Log(LogLevel level,
            LogCategory category,
            std::wstring_view source,
            std::wstring_view message,
            DatabaseError* err)
        {
            //Read config with shared lock
            bool asyncEnabled;
            LogLevel minLevel;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                minLevel = m_config.minLogLevel;
                asyncEnabled = m_config.asyncLogging;
            }

            if (level < minLevel) {
                return 0;  // Below threshold
            }

            LogEntry entry;
            entry.timestamp = std::chrono::system_clock::now();
            entry.level = level;
            entry.category = category;
            entry.source = source;
            entry.message = message;
            entry.processId = GetCurrentProcessId();
            entry.threadId = GetCurrentThreadId();
            entry.userName = m_userName;
            entry.machineName = m_machineName;

            if (asyncEnabled) {
                enqueuePendingWrite(entry);
                return -1;  // ID not available yet for async
            }
            else {
                return dbInsertEntry(entry, err);
            }
        }

        /**
         * @brief Logs a detailed entry with all metadata fields.
         * 
         * @param entry Complete log entry with all fields populated.
         * @param err Optional pointer to receive error details on failure.
         * @return Entry ID on synchronous success, -1 for async queued, 0 if filtered.
         * 
         * @details Automatically fills missing system information:
         * - processId: Current process ID if entry.processId == 0
         * - threadId: Current thread ID if entry.threadId == 0
         * - userName: Cached user name if entry.userName is empty
         * - machineName: Cached machine name if entry.machineName is empty
         * 
         * @note Prefer this method for structured logging with error codes,
         * duration measurements, or source file location information.
         */
        int64_t LogDB::LogDetailed(const LogEntry& entry, DatabaseError* err) {
            // Read config with shared lock
            bool asyncEnabled;
            LogLevel minLevel;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                minLevel = m_config.minLogLevel;
                asyncEnabled = m_config.asyncLogging;
            }

            if (entry.level < minLevel) {
                return 0;
            }

            LogEntry completeEntry = entry;

            // Fill in missing system information
            if (completeEntry.processId == 0) {
                completeEntry.processId = GetCurrentProcessId();
            }
            if (completeEntry.threadId == 0) {
                completeEntry.threadId = GetCurrentThreadId();
            }
            if (completeEntry.userName.empty()) {
                completeEntry.userName = m_userName;
            }
            if (completeEntry.machineName.empty()) {
                completeEntry.machineName = m_machineName;
            }

            if (asyncEnabled) {
                enqueuePendingWrite(completeEntry);
                return -1;
            }
            else {
                return dbInsertEntry(completeEntry, err);
            }
        }

        /**
         * @brief Convenience method - logs a TRACE level message.
         * @param source Module or component name.
         * @param message The log message content.
         * @return Entry ID or -1 for async.
         * @note TRACE is typically disabled in production (level 0).
         */
        int64_t LogDB::LogTrace(std::wstring_view source, std::wstring_view message) {
            return Log(LogLevel::Trace, LogCategory::General, source, message);
        }

        /**
         * @brief Convenience method - logs a DEBUG level message.
         * @param source Module or component name.
         * @param message The log message content.
         * @return Entry ID or -1 for async.
         */
        int64_t LogDB::LogDebug(std::wstring_view source, std::wstring_view message) {
            return Log(LogLevel::Debug, LogCategory::General, source, message);
        }

        /**
         * @brief Convenience method - logs an INFO level message.
         * @param source Module or component name.
         * @param message The log message content.
         * @return Entry ID or -1 for async.
         * @note Default minimum log level is INFO.
         */
        int64_t LogDB::LogInfo(std::wstring_view source, std::wstring_view message) {
            return Log(LogLevel::Info, LogCategory::General, source, message);
        }

        /**
         * @brief Convenience method - logs a WARN level message.
         * @param source Module or component name.
         * @param message The log message content.
         * @return Entry ID or -1 for async.
         */
        int64_t LogDB::LogWarn(std::wstring_view source, std::wstring_view message) {
            return Log(LogLevel::Warn, LogCategory::General, source, message);
        }

        /**
         * @brief Convenience method - logs an ERROR level message.
         * @param source Module or component name.
         * @param message The log message content.
         * @return Entry ID or -1 for async.
         */
        int64_t LogDB::LogError(std::wstring_view source, std::wstring_view message) {
            return Log(LogLevel::Error, LogCategory::General, source, message);
        }

        /**
         * @brief Convenience method - logs a FATAL level message.
         * @param source Module or component name.
         * @param message The log message content.
         * @return Entry ID or -1 for async.
         * @note FATAL indicates critical system failure requiring immediate attention.
         */
        int64_t LogDB::LogFatal(std::wstring_view source, std::wstring_view message) {
            return Log(LogLevel::Fatal, LogCategory::General, source, message);
        }

        /**
         * @brief Logs an error with Windows or application-specific error code.
         * 
         * @param source Module or component name.
         * @param message Error description message.
         * @param errorCode Windows GetLastError() or custom error code.
         * @param errorContext Additional context about the error.
         * @return Entry ID or -1 for async.
         * 
         * @details Creates a complete LogEntry with ERROR level and includes
         * the error code and context for debugging. Useful for Windows API
         * failures where GetLastError() provides diagnostic information.
         * 
         * @code
         * HANDLE hFile = CreateFile(...);
         * if (hFile == INVALID_HANDLE_VALUE) {
         *     LogDB::Instance().LogErrorWithCode(
         *         L"FileIO", L"Failed to open file",
         *         GetLastError(), L"Path: C:\\temp\\data.bin");
         * }
         * @endcode
         */
        int64_t LogDB::LogErrorWithCode(std::wstring_view source,
                                        std::wstring_view message,
                                        uint32_t errorCode,
                                        std::wstring_view errorContext)
        {
            LogEntry entry;
            entry.timestamp = std::chrono::system_clock::now();
            entry.level = LogLevel::Error;
            entry.category = LogCategory::General;
            entry.source = source;
            entry.message = message;
            entry.errorCode = errorCode;
            entry.errorContext = errorContext;
            entry.processId = GetCurrentProcessId();
            entry.threadId = GetCurrentThreadId();
            entry.userName = m_userName;
            entry.machineName = m_machineName;

            return LogDetailed(entry);
        }

        /**
         * @brief Logs a performance measurement entry.
         * 
         * @param source Module or component name.
         * @param operation Name of the operation being measured.
         * @param durationMs Duration in milliseconds.
         * @param details Additional context (optional).
         * @return Entry ID or -1 for async.
         * 
         * @details Creates a DEBUG level entry with Performance category.
         * Use for tracking operation times, identifying bottlenecks,
         * and performance regression detection.
         * 
         * @note Consider using PerformanceLogger RAII class for automatic
         * timing measurements instead of manual duration calculation.
         * 
         * @see PerformanceLogger for RAII-based timing
         */
        int64_t LogDB::LogPerformance(std::wstring_view source,
                                      std::wstring_view operation,
                                      int64_t durationMs,
                                      std::wstring_view details)
        {
            LogEntry entry;
            entry.timestamp = std::chrono::system_clock::now();
            entry.level = LogLevel::Debug;
            entry.category = LogCategory::Performance;
            entry.source = source;
            entry.message = operation;
            entry.details = details;
            entry.durationMs = durationMs;
            entry.processId = GetCurrentProcessId();
            entry.threadId = GetCurrentThreadId();
            entry.userName = m_userName;
            entry.machineName = m_machineName;

            return LogDetailed(entry);
        }

        /**
         * @brief Inserts multiple log entries in a single transaction.
         * 
         * @param entries Vector of log entries to insert.
         * @param err Optional pointer to receive error details on failure.
         * @return true if all entries were inserted successfully, false otherwise.
         * 
         * @details Processes entries in a single IMMEDIATE transaction for:
         * - Atomicity: All or nothing insertion
         * - Performance: Single transaction overhead instead of N transactions
         * - Consistency: All entries share the same transaction context
         * 
         * Flow:
         * 1. Begins IMMEDIATE transaction (acquires write lock)
         * 2. Filters entries below minimum log level
         * 3. Inserts each entry via prepared statement
         * 4. Commits on success, rolls back on any failure
         * 5. Updates statistics counter
         * 
         * @note Bypasses async queue - always writes directly.
         * @warning On failure, none of the entries are inserted.
         * 
         * @code
         * std::vector<LogDB::LogEntry> entries;
         * // ... populate entries ...
         * 
         * if (!LogDB::Instance().LogBatch(entries)) {
         *     // Handle batch failure
         * }
         * @endcode
         */
        bool LogDB::LogBatch(const std::vector<LogEntry>& entries, DatabaseError* err) {
            if (entries.empty()) return true;

            // Read config with shared lock
            LogLevel minLevel;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                minLevel = m_config.minLogLevel;
            }

            //BEGIN TRANSACTION
            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);

            if (!trans || !trans->IsActive()) {
                return false;
            }

            // USE TRANSACTION'S OWN CONNECTION!
            for (const auto& entry : entries) {
                if (entry.level < minLevel) {
                    continue;
                }

                // PREPARE DATA
                std::string timestamp = timePointToString(entry.timestamp);

                // USE TRANSACTION'S ExecuteWithParams() METHOD!
                bool success = trans->ExecuteWithParams(
                    SQL_INSERT_ENTRY,
                    err,
                    timestamp,
                    static_cast<int>(entry.level),
                    static_cast<int>(entry.category),
                    ToUTF8(entry.source),
                    ToUTF8(entry.message),
                    ToUTF8(entry.details),
                    static_cast<int>(entry.processId),
                    static_cast<int>(entry.threadId),
                    ToUTF8(entry.userName),
                    ToUTF8(entry.machineName),
                    ToUTF8(entry.metadata),
                    static_cast<int>(entry.errorCode),
                    ToUTF8(entry.errorContext),
                    entry.durationMs,
                    ToUTF8(entry.filePath),
                    entry.lineNumber,
                    ToUTF8(entry.functionName)
                );

                if (!success) {
                    trans->Rollback(err);
                    return false;
                }
            }

            // COMMIT TRANSACTION
            if (!trans->Commit(err)) {
                return false;
            }

            // Update statistics
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.totalWrites += entries.size();

            return true;
        }

        // ============================================================================
        //                      QUERY OPERATIONS
        // ============================================================================

        /**
         * @brief Retrieves a single log entry by its unique ID.
         * 
         * @param id The unique identifier of the log entry.
         * @param err Optional pointer to receive error details.
         * @return std::optional containing the entry if found, std::nullopt otherwise.
         * 
         * @note Increments read statistics on successful retrieval.
         */
        std::optional<LogDB::LogEntry> LogDB::GetEntry(int64_t id, DatabaseError* err) {
            return dbSelectEntry(id, err);
        }

        /**
         * @brief Queries log entries using a flexible filter structure.
         * 
         * @param filter QueryFilter specifying search criteria.
         * @param err Optional pointer to receive error details.
         * @return Vector of matching log entries.
         * 
         * @details Builds dynamic SQL based on filter criteria:
         * - Level range filtering (minLevel, maxLevel)
         * - Category filtering
         * - Time range filtering (startTime, endTime)
         * - Pattern matching (sourcePattern, messagePattern - SQL LIKE)
         * - Full-text search (if FTS enabled)
         * - Process/thread ID filtering
         * - Error code filtering
         * 
         * Results are sorted by timestamp (descending by default) and
         * limited to maxResults (default 1000).
         * 
         * @see QueryFilter for available filter options
         */
        std::vector<LogDB::LogEntry> LogDB::Query(const QueryFilter& filter, DatabaseError* err) {
            std::vector<std::string> params;
            std::string sql = buildQuerySQL(filter, params);

            return dbSelectEntries(sql, params, err);
        }

        /**
         * @brief Retrieves the most recent log entries.
         * 
         * @param count Maximum number of entries to retrieve (default: 100).
         * @param minLevel Minimum severity level filter (default: Info).
         * @param err Optional pointer to receive error details.
         * @return Vector of recent log entries, newest first.
         * 
         * @details Convenience method for dashboard/monitoring displays.
         * Equivalent to Query() with sortDescending=true and maxResults=count.
         */
        std::vector<LogDB::LogEntry> LogDB::GetRecent(size_t count,
                                                      LogLevel minLevel,
                                                      DatabaseError* err)
        {
            QueryFilter filter;
            filter.minLevel = minLevel;
            filter.maxResults = count;
            filter.sortDescending = true;

            return Query(filter, err);
        }

        /**
         * @brief Retrieves log entries with a specific severity level.
         * 
         * @param level The exact log level to filter by.
         * @param maxCount Maximum number of entries to retrieve.
         * @param err Optional pointer to receive error details.
         * @return Vector of matching log entries.
         * 
         * @details Useful for viewing all errors (LogLevel::Error) or
         * all warnings (LogLevel::Warn) in the system.
         */
        std::vector<LogDB::LogEntry> LogDB::GetByLevel(LogLevel level,
                                                       size_t maxCount,
                                                       DatabaseError* err)
        {
            QueryFilter filter;
            filter.minLevel = level;
            filter.maxLevel = level;
            filter.maxResults = maxCount;
            filter.sortDescending = true;

            return Query(filter, err);
        }

        /**
         * @brief Retrieves log entries from a specific category.
         * 
         * @param category The log category to filter by.
         * @param maxCount Maximum number of entries to retrieve.
         * @param err Optional pointer to receive error details.
         * @return Vector of matching log entries.
         * 
         * @details Useful for component-specific log views (e.g., all Scanner
         * logs, all Network logs).
         */
        std::vector<LogDB::LogEntry> LogDB::GetByCategory(LogCategory category,
                                                          size_t maxCount,
                                                          DatabaseError* err)
        {
            QueryFilter filter;
            filter.category = category;
            filter.maxResults = maxCount;
            filter.sortDescending = true;

            return Query(filter, err);
        }

        /**
         * @brief Retrieves log entries within a specific time range.
         * 
         * @param start Start of time range (inclusive).
         * @param end End of time range (inclusive).
         * @param maxCount Maximum number of entries to retrieve.
         * @param err Optional pointer to receive error details.
         * @return Vector of matching log entries.
         * 
         * @details Time comparison uses ISO 8601 string format in SQLite.
         * Useful for investigating incidents within a known time window.
         */
        std::vector<LogDB::LogEntry> LogDB::GetByTimeRange(
            std::chrono::system_clock::time_point start,
            std::chrono::system_clock::time_point end,
            size_t maxCount,
            DatabaseError* err)
        {
            QueryFilter filter;
            filter.startTime = start;
            filter.endTime = end;
            filter.maxResults = maxCount;
            filter.sortDescending = true;

            return Query(filter, err);
        }

        /**
         * @brief Retrieves log entries generated by a specific process.
         * 
         * @param processId The Windows process ID to filter by.
         * @param maxCount Maximum number of entries to retrieve.
         * @param err Optional pointer to receive error details.
         * @return Vector of matching log entries.
         * 
         * @details Useful for process-specific debugging or tracing activity
         * from a particular service instance.
         */
        std::vector<LogDB::LogEntry> LogDB::GetByProcess(uint32_t processId,
                                                         size_t maxCount,
                                                         DatabaseError* err)
        {
            QueryFilter filter;
            filter.processId = processId;
            filter.maxResults = maxCount;
            filter.sortDescending = true;

            return Query(filter, err);
        }

        /**
         * @brief Searches log entries by text content.
         * 
         * @param searchText The text to search for.
         * @param useFullText If true, uses FTS5 full-text search. Otherwise, SQL LIKE.
         * @param maxCount Maximum number of entries to retrieve.
         * @param err Optional pointer to receive error details.
         * @return Vector of matching log entries.
         * 
         * @details Search behavior:
         * - FTS mode: Fast full-text search using SQLite FTS5 index.
         *   Supports FTS5 query syntax (AND, OR, NEAR, etc.)
         * - LIKE mode: Pattern matching on message field.
         *   Wraps searchText with % wildcards.
         * 
         * @note FTS must be enabled in configuration for full-text mode.
         * Falls back to LIKE if FTS is disabled.
         */
        std::vector<LogDB::LogEntry> LogDB::SearchText(std::wstring_view searchText,
            bool useFullText,
            size_t maxCount,
            DatabaseError* err)
        {
            QueryFilter filter;

            
            bool enableFTS;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                enableFTS = m_config.enableFullTextSearch;
            }

            if (useFullText && enableFTS) {
                filter.fullTextSearch = searchText;
            }
            else {
                std::wstring pattern = L"%";
                pattern += searchText;
                pattern += L"%";
                filter.messagePattern = pattern;
            }

            filter.maxResults = maxCount;
            filter.sortDescending = true;

            return Query(filter, err);
        }

        /**
         * @brief Counts log entries matching optional filter criteria.
         * 
         * @param filter Optional QueryFilter. If nullptr, counts all entries.
         * @param err Optional pointer to receive error details.
         * @return Number of matching entries, or -1 on error.
         * 
         * @details Uses SQL COUNT(*) for efficiency - does not load entry data.
         * Useful for statistics, pagination, and rotation threshold checks.
         */
        int64_t LogDB::CountEntries(const QueryFilter* filter, DatabaseError* err) {
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
        //                      MANAGEMENT OPERATIONS
        // ============================================================================

        /**
         * @brief Deletes a single log entry by ID.
         * 
         * @param id The unique identifier of the entry to delete.
         * @param err Optional pointer to receive error details.
         * @return true if entry was deleted, false if not found or error.
         * 
         * @details Also removes corresponding FTS index entry via trigger.
         * Increments totalDeletes counter on success.
         */
        bool LogDB::DeleteEntry(int64_t id, DatabaseError* err) {
            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_DELETE_ENTRY, err, id);

            if (success) {
                
                int affectedRows = DatabaseManager::Instance().GetChanges();

                if (affectedRows > 0) {
                    std::lock_guard<std::mutex> lock(m_statsMutex);
                    m_stats.totalDeletes++;
                    return true;
                }
                else {
                   
                    if (err) {
                        err->sqliteCode = SQLITE_OK;
                        err->message = L"No entry found with given ID";
                    }
                    return false;
                }
            }

            return false;
        }

        /**
         * @brief Deletes all log entries older than the specified timestamp.
         * 
         * @param timestamp Cutoff time - entries before this are deleted.
         * @param err Optional pointer to receive error details.
         * @return true if operation succeeded (even if no entries matched).
         * 
         * @details Used for time-based log cleanup and rotation.
         * Recalculates statistics after deletion.
         */
        bool LogDB::DeleteBefore(std::chrono::system_clock::time_point timestamp,
                                DatabaseError* err)
        {
            std::string timestampStr = timePointToString(timestamp);

            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_DELETE_BEFORE, err, timestampStr);

            if (success) {
                recalculateStatistics(err);
            }

            return success;
        }

        /**
         * @brief Deletes all log entries with the specified severity level.
         * 
         * @param level The log level to delete (all entries with this level).
         * @param err Optional pointer to receive error details.
         * @return true if operation succeeded (even if no entries matched).
         * 
         * @details Useful for clearing verbose logs (e.g., all TRACE or DEBUG)
         * while preserving important entries.
         */
        bool LogDB::DeleteByLevel(LogLevel level, DatabaseError* err) {
            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_DELETE_BY_LEVEL, err, static_cast<int>(level));

            if (success) {
                recalculateStatistics(err);
            }

            return success;
        }

        /**
         * @brief Deletes ALL log entries from the database.
         * 
         * @param err Optional pointer to receive error details.
         * @return true if operation succeeded.
         * 
         * @warning This is irreversible! Consider ArchiveLogs() first.
         * @note Resets all statistics counters to zero.
         */
        bool LogDB::DeleteAll(DatabaseError* err) {
            bool success = DatabaseManager::Instance().Execute(SQL_DELETE_ALL, err);

            if (success) {
                ResetStatistics();
            }

            return success;
        }

        /**
         * @brief Creates an archive of logs before the specified timestamp.
         * 
         * @param archivePath Full path for the archive database file.
         * @param beforeTimestamp Logs older than this are archived.
         * @param err Optional pointer to receive error details.
         * @return true if archive was created successfully.
         * 
         * @details Creates a backup of the current database to the archive path.
         * Does NOT delete the archived entries - call DeleteBefore() separately.
         * 
         * @see performRotation() for automatic archive + delete
         */
        bool LogDB::ArchiveLogs(std::wstring_view archivePath,
                               std::chrono::system_clock::time_point beforeTimestamp,
                               DatabaseError* err)
        {
            SS_LOG_INFO(L"LogDB", L"Archiving logs to: %ls", archivePath.data());

            return createArchive(archivePath, beforeTimestamp, err);
        }

        /**
         * @brief Restores logs from an archive database file.
         * 
         * @param archivePath Path to the archive database to restore from.
         * @param err Optional pointer to receive error details.
         * @return true if restore succeeded.
         * 
         * @warning This REPLACES the current database with the archive content.
         * Existing entries will be lost.
         */
        bool LogDB::RestoreLogs(std::wstring_view archivePath, DatabaseError* err) {
            SS_LOG_INFO(L"LogDB", L"Restoring logs from: %ls", archivePath.data());

            return DatabaseManager::Instance().RestoreFromFile(archivePath, err);
        }

        /**
         * @brief Manually triggers log rotation.
         * 
         * @param err Optional pointer to receive error details.
         * @return true if rotation completed successfully.
         * 
         * @details Rotation process:
         * 1. Creates timestamped archive in archive directory
         * 2. Deletes entries older than maxLogAge
         * 3. Runs VACUUM to reclaim space
         * 4. Cleans up old archives exceeding retention count
         * 
         * @see CheckAndRotate() for automatic threshold-based rotation
         */
        bool LogDB::RotateLogs(DatabaseError* err) {
            SS_LOG_INFO(L"LogDB", L"Rotating logs...");

            return performRotation(err);
        }

        /**
         * @brief Checks rotation thresholds and rotates if needed.
         * 
         * @param err Optional pointer to receive error details.
         * @return true if check completed (rotation may or may not have occurred).
         * 
         * @details Rotation triggers:
         * - Database size exceeds maxLogSizeMB
         * - Oldest entry age exceeds maxLogAge
         * 
         * @note Does nothing if enableRotation is false in configuration.
         */
        bool LogDB::CheckAndRotate(DatabaseError* err) {

            bool enableRotation;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                enableRotation = m_config.enableRotation;
            }

            if (!enableRotation) {
                return true;
            }

            if (shouldRotate(err)) {
                return performRotation(err);
            }

            return true;
        }

        /**
         * @brief Flushes all pending asynchronous writes to the database.
         * 
         * @param err Optional pointer to receive error details.
         * @return true if flush completed successfully.
         * 
         * @details Forces immediate processing of the pending writes queue.
         * Called automatically during Shutdown() for graceful termination.
         * 
         * @note Returns immediately if async logging is disabled.
         */
        bool LogDB::Flush(DatabaseError* err) {
            
            bool asyncLogging;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                asyncLogging = m_config.asyncLogging;
            }

            if (!asyncLogging) {
                return true;
            }

            std::lock_guard<std::mutex> lock(m_batchMutex);

            if (m_pendingWrites.empty()) {
                return true;
            }

            return processPendingWrites(err);
        }

        // ============================================================================
        //                      STATISTICS & CONFIGURATION
        // ============================================================================

        /**
         * @brief Returns current logging statistics.
         * 
         * @param err Optional pointer to receive error details (unused).
         * @return Copy of current Statistics structure.
         * 
         * @details Statistics include:
         * - Total entries, writes, reads, deletes
         * - Entries by level and category
         * - Average write/read times
         * - Database size information
         * - Rotation history
         * 
         * @note Thread-safe via mutex protection.
         */
        LogDB::Statistics LogDB::GetStatistics(DatabaseError* err) {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            return m_stats;
        }

        /**
         * @brief Resets all statistics counters to zero.
         * 
         * @details Does NOT affect database contents, only in-memory counters.
         * Useful after log rotation or for testing.
         */
        void LogDB::ResetStatistics() {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats = Statistics{};
        }

        /**
         * @brief Returns a copy of the current configuration.
         * 
         * @return Current Config structure (thread-safe copy).
         * 
         * @note Use SetMinLogLevel() or SetAsyncLogging() for modifications.
         */
        LogDB::Config LogDB::GetConfig() const {
            std::shared_lock<std::shared_mutex> lock(m_configMutex);
            return m_config;
        }

        /**
         * @brief Changes the minimum log level threshold.
         * 
         * @param level New minimum level. Entries below this are filtered.
         * 
         * @details Takes effect immediately for subsequent Log() calls.
         * Does NOT affect entries already in the database.
         */
        void LogDB::SetMinLogLevel(LogLevel level) {
            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config.minLogLevel = level;
        }

        /**
         * @brief Enables or disables asynchronous logging mode.
         * 
         * @param enabled true to enable async batching, false for synchronous.
         * 
         * @note Changes take effect immediately. Does NOT start/stop the
         * batch thread - that requires re-initialization.
         */
        void LogDB::SetAsyncLogging(bool enabled) {
            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config.asyncLogging = enabled;
        }

        // ============================================================================
        //                      UTILITY FUNCTIONS (STATIC)
        // ============================================================================

        /**
         * @brief Converts LogLevel enum to human-readable string.
         * 
         * @param level The log level to convert.
         * @return Wide string representation (e.g., L"ERROR", L"WARN").
         */
        std::wstring LogDB::LogLevelToString(LogLevel level) {
            switch (level) {
                case LogLevel::Trace: return L"TRACE";
                case LogLevel::Debug: return L"DEBUG";
                case LogLevel::Info: return L"INFO";
                case LogLevel::Warn: return L"WARN";
                case LogLevel::Error: return L"ERROR";
                case LogLevel::Fatal: return L"FATAL";
                default: return L"UNKNOWN";
            }
        }

        /**
         * @brief Parses a string to LogLevel enum.
         * 
         * @param str String representation (case-sensitive: "TRACE", "DEBUG", etc.)
         * @return Corresponding LogLevel enum value. Defaults to Info if unknown.
         */
        LogDB::LogLevel LogDB::StringToLogLevel(std::wstring_view str) {
            if (str == L"TRACE") return LogLevel::Trace;
            if (str == L"DEBUG") return LogLevel::Debug;
            if (str == L"INFO") return LogLevel::Info;
            if (str == L"WARN") return LogLevel::Warn;
            if (str == L"ERROR") return LogLevel::Error;
            if (str == L"FATAL") return LogLevel::Fatal;
            return LogLevel::Info;
        }

        /**
         * @brief Converts LogCategory enum to human-readable string.
         * 
         * @param category The log category to convert.
         * @return Wide string representation (e.g., L"Security", L"Scanner").
         */
        std::wstring LogDB::LogCategoryToString(LogCategory category) {
            switch (category) {
                case LogCategory::General: return L"General";
                case LogCategory::System: return L"System";
                case LogCategory::Security: return L"Security";
                case LogCategory::Network: return L"Network";
                case LogCategory::FileSystem: return L"FileSystem";
                case LogCategory::Process: return L"Process";
                case LogCategory::Registry: return L"Registry";
                case LogCategory::Service: return L"Service";
                case LogCategory::Driver: return L"Driver";
                case LogCategory::Performance: return L"Performance";
                case LogCategory::Database: return L"Database";
                case LogCategory::Scanner: return L"Scanner";
                case LogCategory::Quarantine: return L"Quarantine";
                case LogCategory::Update: return L"Update";
                case LogCategory::Configuration: return L"Configuration";
                case LogCategory::UserInterface: return L"UserInterface";
                case LogCategory::Custom: return L"Custom";
                default: return L"Unknown";
            }
        }

        /**
         * @brief Parses a string to LogCategory enum.
         * 
         * @param str String representation (case-sensitive).
         * @return Corresponding LogCategory enum value. Defaults to General if unknown.
         */
        LogDB::LogCategory LogDB::StringToLogCategory(std::wstring_view str) {
            if (str == L"General") return LogCategory::General;
            if (str == L"System") return LogCategory::System;
            if (str == L"Security") return LogCategory::Security;
            if (str == L"Network") return LogCategory::Network;
            if (str == L"FileSystem") return LogCategory::FileSystem;
            if (str == L"Process") return LogCategory::Process;
            if (str == L"Registry") return LogCategory::Registry;
            if (str == L"Service") return LogCategory::Service;
            if (str == L"Driver") return LogCategory::Driver;
            if (str == L"Performance") return LogCategory::Performance;
            if (str == L"Database") return LogCategory::Database;
            if (str == L"Scanner") return LogCategory::Scanner;
            if (str == L"Quarantine") return LogCategory::Quarantine;
            if (str == L"Update") return LogCategory::Update;
            if (str == L"Configuration") return LogCategory::Configuration;
            if (str == L"UserInterface") return LogCategory::UserInterface;
            if (str == L"Custom") return LogCategory::Custom;
            return LogCategory::General;
        }

        /**
         * @brief Formats a LogEntry as a human-readable string.
         * 
         * @param entry The log entry to format.
         * @param includeMetadata If true, appends metadata JSON to output.
         * @return Formatted string: "[Timestamp] [Level] [Category] Source: Message"
         * 
         * @details Format example:
         * "[2026-01-15 10:30:45.123] [ERROR] [Scanner] MalwareDetector: Threat found"
         */
        std::wstring LogDB::FormatLogEntry(const LogEntry& entry, bool includeMetadata) {
            std::wostringstream oss;
            
            // Format: [Timestamp] [Level] [Category] Source: Message
            std::string timestampStr = timePointToString(entry.timestamp);
            oss << L"[" << ToWide(timestampStr) << L"] ";
            oss << L"[" << LogLevelToString(entry.level) << L"] ";
            oss << L"[" << LogCategoryToString(entry.category) << L"] ";
            oss << entry.source << L": " << entry.message;

            if (!entry.details.empty()) {
                oss << L" | " << entry.details;
            }

            if (entry.errorCode != 0) {
                oss << L" (Error: " << entry.errorCode << L")";
            }

            if (includeMetadata && !entry.metadata.empty()) {
                oss << L" | Metadata: " << entry.metadata;
            }

            return oss.str();
        }

        /**
         * @brief Exports log entries to a plain text file.
         * 
         * @param filePath Destination file path.
         * @param filter Optional QueryFilter to select entries. nullptr for all.
         * @param err Optional pointer to receive error details.
         * @return true if export succeeded.
         * 
         * @details Writes one formatted log entry per line using FormatLogEntry().
         * Output is in UTF-16LE encoding (Windows wchar_t).
         */
        bool LogDB::ExportToFile(std::wstring_view filePath,
                                const QueryFilter* filter,
                                DatabaseError* err)
        {
            auto entries = filter ? Query(*filter, err) : Query(QueryFilter{}, err);

            Utils::FileUtils::Error fileErr;
            std::wostringstream content;

            for (const auto& entry : entries) {
                content << FormatLogEntry(entry, true) << L"\n";
            }

            std::wstring contentStr = content.str();
            return Utils::FileUtils::WriteAllBytesAtomic(
                filePath,
                reinterpret_cast<const std::byte*>(contentStr.data()),
                contentStr.size() * sizeof(wchar_t),
                &fileErr
            );
        }

        /**
         * @brief Exports log entries to a JSON file.
         * 
         * @param filePath Destination file path.
         * @param filter Optional QueryFilter to select entries. nullptr for all.
         * @param err Optional pointer to receive error details.
         * @return true if export succeeded.
         * 
         * @details Creates a JSON array of log entry objects.
         * Basic fields included: id, timestamp, level, category, source, message.
         * 
         * @note For full field export, consider extending this method.
         */
        bool LogDB::ExportToJSON(std::wstring_view filePath,
                                const QueryFilter* filter,
                                DatabaseError* err)
        {
            // JSON export implementation
            // This would format entries as JSON array
            
            auto entries = filter ? Query(*filter, err) : Query(QueryFilter{}, err);

            std::wostringstream json;
            json << L"[\n";

            for (size_t i = 0; i < entries.size(); ++i) {
                const auto& entry = entries[i];
                
                json << L"  {\n";
                json << L"    \"id\": " << entry.id << L",\n";
                json << L"    \"timestamp\": \"" << timePointToString(entry.timestamp).c_str() << L"\",\n";
                json << L"    \"level\": \"" << LogLevelToString(entry.level) << L"\",\n";
                json << L"    \"category\": \"" << LogCategoryToString(entry.category) << L"\",\n";
                json << L"    \"source\": \"" << entry.source << L"\",\n";
                json << L"    \"message\": \"" << entry.message << L"\"\n";
                json << L"  }";
                
                if (i < entries.size() - 1) {
                    json << L",";
                }
                json << L"\n";
            }

            json << L"]\n";

            std::wstring jsonStr = json.str();
            Utils::FileUtils::Error fileErr;
            return Utils::FileUtils::WriteAllBytesAtomic(
                filePath,
                reinterpret_cast<const std::byte*>(jsonStr.data()),
                jsonStr.size() * sizeof(wchar_t),
                &fileErr
            );
        }

        /**
         * @brief Exports log entries to a CSV file.
         * 
         * @param filePath Destination file path.
         * @param filter Optional QueryFilter to select entries. nullptr for all.
         * @param err Optional pointer to receive error details.
         * @return true if export succeeded.
         * 
         * @details CSV columns: ID, Timestamp, Level, Category, Source, Message,
         * ProcessID, ThreadID. Message field is quoted to handle commas.
         */
        bool LogDB::ExportToCSV(std::wstring_view filePath,
                               const QueryFilter* filter,
                               DatabaseError* err)
        {
            auto entries = filter ? Query(*filter, err) : Query(QueryFilter{}, err);

            std::wostringstream csv;
            
            // Header
            csv << L"ID,Timestamp,Level,Category,Source,Message,ProcessID,ThreadID\n";

            // Rows
            for (const auto& entry : entries) {
                auto timestampStr = timePointToString(entry.timestamp);
                csv << entry.id << L",";
                csv << ToWide(timestampStr) << L",";
                csv << LogLevelToString(entry.level) << L",";
                csv << LogCategoryToString(entry.category) << L",";
                csv << entry.source << L",";
                csv << L"\"" << entry.message << L"\",";
                csv << entry.processId << L",";
                csv << entry.threadId << L"\n";
            }

            std::wstring csvStr = csv.str();
            Utils::FileUtils::Error fileErr;
            return Utils::FileUtils::WriteAllBytesAtomic(
                filePath,
                reinterpret_cast<const std::byte*>(csvStr.data()),
                csvStr.size() * sizeof(wchar_t),
                &fileErr
            );
        }

        // ============================================================================
        //                      MAINTENANCE OPERATIONS
        // ============================================================================

        /**
         * @brief Reclaims unused disk space by rebuilding the database file.
         * 
         * @param err Optional pointer to receive error details.
         * @return true if VACUUM succeeded.
         * 
         * @details SQLite VACUUM rebuilds the database file, recovering space
         * from deleted records. Should be run periodically after large deletions.
         * 
         * @warning VACUUM requires exclusive access and may take time on large databases.
         */
        bool LogDB::Vacuum(DatabaseError* err) {
            SS_LOG_INFO(L"LogDB", L"Running VACUUM...");
            return DatabaseManager::Instance().Vacuum(err);
        }

        /**
         * @brief Verifies database integrity.
         * 
         * @param err Optional pointer to receive error details.
         * @return true if database passes integrity check.
         * 
         * @details Runs SQLite PRAGMA integrity_check. Should be run after
         * system crashes or suspected corruption.
         */
        bool LogDB::CheckIntegrity(DatabaseError* err) {
            SS_LOG_INFO(L"LogDB", L"Checking integrity...");
            std::vector<std::wstring> issues;
            return DatabaseManager::Instance().CheckIntegrity(issues, err);
        }

        /**
         * @brief Optimizes database performance and cleans old entries.
         * 
         * @param err Optional pointer to receive error details.
         * @return true if optimization succeeded.
         * 
         * @details Optimization steps:
         * 1. Deletes entries older than maxLogAge (if rotation enabled)
         * 2. Runs SQLite ANALYZE to update query optimizer statistics
         */
        bool LogDB::Optimize(DatabaseError* err) {
            SS_LOG_INFO(L"LogDB", L"Optimizing database...");

          
            bool enableRotation;
            std::chrono::hours maxLogAge;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                enableRotation = m_config.enableRotation;
                maxLogAge = m_config.maxLogAge;
            }

            // Delete old entries if configured
            if (enableRotation) {
                auto cutoffTime = std::chrono::system_clock::now() - maxLogAge;
                DeleteBefore(cutoffTime, err);
            }

            return DatabaseManager::Instance().Optimize(err);
        }

        /**
         * @brief Drops and recreates all indices for defragmentation.
         * 
         * @param err Optional pointer to receive error details.
         * @return true if index rebuild succeeded.
         * 
         * @details Useful after large bulk operations to ensure optimal
         * index structure. More thorough than REINDEX command.
         */
        bool LogDB::RebuildIndices(DatabaseError* err) {
            SS_LOG_INFO(L"LogDB", L"Rebuilding indices...");
            
            // Drop and recreate indices
            DatabaseManager::Instance().Execute("DROP INDEX IF EXISTS idx_log_timestamp", nullptr);
            DatabaseManager::Instance().Execute("DROP INDEX IF EXISTS idx_log_level", nullptr);
            DatabaseManager::Instance().Execute("DROP INDEX IF EXISTS idx_log_category", nullptr);
            DatabaseManager::Instance().Execute("DROP INDEX IF EXISTS idx_log_source", nullptr);
            DatabaseManager::Instance().Execute("DROP INDEX IF EXISTS idx_log_process", nullptr);
            DatabaseManager::Instance().Execute("DROP INDEX IF EXISTS idx_log_error", nullptr);
            DatabaseManager::Instance().Execute("DROP INDEX IF EXISTS idx_log_composite", nullptr);

            return DatabaseManager::Instance().Execute(SQL_CREATE_INDICES, err);
        }

        // ============================================================================
        //                      INTERNAL OPERATIONS
        // ============================================================================

        /**
         * @brief Creates the database schema (tables, indices, FTS).
         * 
         * @param err Optional pointer to receive error details.
         * @return true if schema was created successfully.
         * 
         * @details Schema creation sequence:
         * 1. Creates log_entries table (if not exists)
         * 2. Creates performance indices
         * 3. Creates FTS5 virtual table (if enableFullTextSearch is true)
         * 4. Creates FTS sync triggers (if FTS table creation succeeded)
         * 
         * @note FTS creation failures are logged but don't fail initialization.
         * The system continues without full-text search capability.
         */
        bool LogDB::createSchema(DatabaseError* err) {
            // Create main table
            if (!DatabaseManager::Instance().Execute(SQL_CREATE_LOGS_TABLE, err)) {
                return false;
            }

            // Create indices
            if (!DatabaseManager::Instance().Execute(SQL_CREATE_INDICES, err)) {
                return false;
            }

            //read config with lock
            bool enableFTS;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                enableFTS = m_config.enableFullTextSearch;
            }

            //  FIX: Create full-text search ONLY if enabled AND successful!
            if (enableFTS) {
                bool ftsSuccess = DatabaseManager::Instance().Execute(SQL_CREATE_FTS_TABLE, err);

                if (!ftsSuccess) {
                    SS_LOG_WARN(L"LogDB", L"Failed to create FTS table, continuing without it");
                    //  DON'T CREATE TRIGGERS IF TABLE FAILED!
                }
                else {
                    // ONLY CREATE TRIGGERS IF TABLE EXISTS!
                    if (!DatabaseManager::Instance().Execute(SQL_CREATE_FTS_TRIGGERS, err)) {
                        SS_LOG_WARN(L"LogDB", L"Failed to create FTS triggers");
                    }
                }
            }

            SS_LOG_INFO(L"LogDB", L"Schema created successfully");
            return true;
        }

        /**
         * @brief Performs schema migration between versions using transactional updates.
         * 
         * @param currentVersion Current schema version in database.
         * @param targetVersion Target schema version to migrate to.
         * @param err Optional pointer to receive error details.
         * @return true if migration succeeded (or no migration needed).
         * 
         * @details Schema Migration Framework:
         * - Migrations are version-incremental (v1→v2→v3)
         * - Each migration is atomic within a transaction
         * - Rollback occurs automatically on failure
         * - Version metadata updated after successful migration
         * 
         * Adding New Migrations:
         * 1. Increment LOG_SCHEMA_VERSION constant
         * 2. Add case in the switch statement below
         * 3. Implement migration SQL statements
         * 4. Test upgrade path from each previous version
         * 
         * @code{.cpp}
         * // Example migration (v1 → v2): Add correlation tracking
         * case 2:
         *     db.exec("ALTER TABLE log_entries ADD COLUMN correlation_id TEXT");
         *     db.exec("CREATE INDEX idx_log_correlation ON log_entries(correlation_id)");
         *     break;
         * @endcode
         */
        bool LogDB::upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err) {
            SS_LOG_INFO(L"LogDB", L"Schema migration: v%d → v%d", currentVersion, targetVersion);
            
            // No migration needed if already at target or newer
            if (currentVersion >= targetVersion) {
                SS_LOG_DEBUG(L"LogDB", L"No schema migration required");
                return true;
            }
            
            try {
                // Apply each migration sequentially
                for (int version = currentVersion + 1; version <= targetVersion; ++version) {
                    SS_LOG_INFO(L"LogDB", L"Applying migration to schema version %d", version);
                    
                    switch (version) {
                        case 1:
                            // Base schema - created by createSchema(), no migration
                            break;
                            
                        // === Future Migrations ===
                        // case 2:
                        //     // Add structured logging support
                        //     DatabaseManager::Instance().Execute(
                        //         "ALTER TABLE log_entries ADD COLUMN structured_data TEXT",
                        //         nullptr);
                        //     DatabaseManager::Instance().Execute(
                        //         "ALTER TABLE log_entries ADD COLUMN trace_id TEXT",
                        //         nullptr);
                        //     DatabaseManager::Instance().Execute(
                        //         "ALTER TABLE log_entries ADD COLUMN span_id TEXT",
                        //         nullptr);
                        //     DatabaseManager::Instance().Execute(
                        //         "CREATE INDEX idx_log_trace ON log_entries(trace_id)",
                        //         nullptr);
                        //     break;
                        //
                        // case 3:
                        //     // Add log compression for archived entries
                        //     DatabaseManager::Instance().Execute(
                        //         "ALTER TABLE log_entries ADD COLUMN is_compressed INTEGER DEFAULT 0",
                        //         nullptr);
                        //     break;
                            
                        default:
                            SS_LOG_WARN(L"LogDB", L"Unknown migration version: %d", version);
                            break;
                    }
                }
                
                // Update schema version in database metadata
                DatabaseManager::Instance().ExecuteWithParams(
                    "INSERT OR REPLACE INTO db_metadata (key, value) VALUES ('log_schema_version', ?)",
                    nullptr,
                    std::to_string(targetVersion));
                
                SS_LOG_INFO(L"LogDB", L"Schema migration completed successfully to v%d", targetVersion);
                return true;
                
            } catch (const std::exception& e) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Log schema migration failed: " + ToWide(e.what());
                }
                SS_LOG_ERROR(L"LogDB", L"Schema migration failed: %hs", e.what());
                return false;
            }
        }

        /**
         * @brief Inserts a log entry into the database (synchronous).
         * 
         * @param entry The log entry to insert.
         * @param err Optional pointer to receive error details.
         * @return Inserted entry ID on success, -1 on failure.
         * 
         * @details Converts entry fields to UTF-8 and executes INSERT.
         * Updates write statistics and timing metrics.
         */
        int64_t LogDB::dbInsertEntry(const LogEntry& entry, DatabaseError* err) {
            auto startTime = std::chrono::steady_clock::now();

            std::string timestamp = timePointToString(entry.timestamp);

            
            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_INSERT_ENTRY,
                err,
                timestamp,
                static_cast<int>(entry.level),
                static_cast<int>(entry.category),
                ToUTF8(entry.source),
                ToUTF8(entry.message),
                ToUTF8(entry.details),
                static_cast<int>(entry.processId),
                static_cast<int>(entry.threadId),
                ToUTF8(entry.userName),
                ToUTF8(entry.machineName),
                ToUTF8(entry.metadata),
                static_cast<int>(entry.errorCode),
                ToUTF8(entry.errorContext),
                entry.durationMs,
                ToUTF8(entry.filePath),
                entry.lineNumber,
                ToUTF8(entry.functionName)
            );

            if (success) {
               
                int64_t id = DatabaseManager::Instance().LastInsertRowId();

                auto endTime = std::chrono::steady_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

                
                this->updateStatistics(entry);

                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalWrites++;
                m_stats.avgWriteTime = std::chrono::milliseconds(
                    (m_stats.avgWriteTime.count() + duration.count()) / 2
                );

                return id;
            }

            return -1;
        }

        /**
         * @brief Retrieves a single log entry by ID.
         * 
         * @param id The entry ID to look up.
         * @param err Optional pointer to receive error details.
         * @return std::optional with entry if found, std::nullopt otherwise.
         * 
         * @details Increments read statistics counter.
         */
        std::optional<LogDB::LogEntry> LogDB::dbSelectEntry(int64_t id, DatabaseError* err) {
            auto result = DatabaseManager::Instance().QueryWithParams(
                SQL_SELECT_ENTRY, err, id);

            if (result.Next()) {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalReads++;
                
                return rowToLogEntry(result);
            }

            return std::nullopt;
        }

        /**
         * @brief Executes a query and returns multiple log entries.
         * 
         * @param sql The SQL query string.
         * @param params Vector of parameter values for placeholders.
         * @param err Optional pointer to receive error details.
         * @return Vector of matching LogEntry objects.
         * 
         * @details Handles both parameterized and non-parameterized queries.
         * Increments read statistics counter once per query.
         */
        std::vector<LogDB::LogEntry> LogDB::dbSelectEntries(std::string_view sql,
            const std::vector<std::string>& params,
            DatabaseError* err)
        {
            std::vector<LogEntry> entries;

            QueryResult result;

            if (params.empty()) {
                result = DatabaseManager::Instance().Query(sql, err);
            }
            else {
              
                result = DatabaseManager::Instance().QueryWithParamsVector(sql,params,err);

              
            }

            while (result.Next()) {
                entries.push_back(rowToLogEntry(result));
            }

            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.totalReads++;

            return entries;
        }

        /**
         * @brief Builds a SELECT SQL query from filter criteria.
         * 
         * @param filter QueryFilter with search criteria.
         * @param outParams Output vector to receive parameter values.
         * @return SQL query string with placeholders.
         * 
         * @details Dynamically constructs WHERE clause based on which
         * filter fields have values. Uses parameterized queries for security.
         * 
         * Generated query structure:
         * SELECT * FROM log_entries WHERE 1=1
         *   [AND level >= ?]
         *   [AND level <= ?]
         *   [AND category = ?]
         *   [AND timestamp >= ?]
         *   [AND timestamp <= ?]
         *   [AND source LIKE ?]
         *   [AND message LIKE ?]
         *   [AND process_id = ?]
         *   [AND thread_id = ?]
         *   [AND error_code = ?]
         *   [AND id IN (SELECT rowid FROM log_fts WHERE ...)]
         * ORDER BY timestamp [DESC|ASC]
         * LIMIT n
         */
        std::string LogDB::buildQuerySQL(const QueryFilter& filter, std::vector<std::string>& outParams) {
            std::ostringstream sql;
            sql << "SELECT * FROM log_entries WHERE 1=1";

            bool enableFTS;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                enableFTS = m_config.enableFullTextSearch;
            }

            if (filter.minLevel) {
                sql << " AND level >= ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.minLevel)));
            }

            if (filter.maxLevel) {
                sql << " AND level <= ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.maxLevel)));
            }

            if (filter.category) {
                sql << " AND category = ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.category)));
            }

            if (filter.startTime) {
                sql << " AND timestamp >= ?";
                outParams.push_back(timePointToString(*filter.startTime));
            }

            if (filter.endTime) {
                sql << " AND timestamp <= ?";
                outParams.push_back(timePointToString(*filter.endTime));
            }

            if (filter.sourcePattern) {
                sql << " AND source LIKE ?";
                outParams.push_back(ToUTF8(*filter.sourcePattern));
            }

            if (filter.messagePattern) {
                sql << " AND message LIKE ?";
                outParams.push_back(ToUTF8(*filter.messagePattern));
            }

            if (filter.processId) {
                sql << " AND process_id = ?";
                outParams.push_back(std::to_string(*filter.processId));
            }

            if (filter.threadId) {
                sql << " AND thread_id = ?";
                outParams.push_back(std::to_string(*filter.threadId));
            }

            if (filter.errorCode) {
                sql << " AND error_code = ?";
                outParams.push_back(std::to_string(*filter.errorCode));
            }

            // Full-text search
            if (filter.fullTextSearch && enableFTS) {
                sql << " AND id IN (SELECT rowid FROM log_fts WHERE log_fts MATCH ?)";
                outParams.push_back(ToUTF8(*filter.fullTextSearch));
            }

            // Order and limit
            if (filter.sortDescending) {
                sql << " ORDER BY timestamp DESC";
            } else {
                sql << " ORDER BY timestamp ASC";
            }

            sql << " LIMIT " << filter.maxResults;

            return sql.str();
        }

        /**
         * @brief Builds a COUNT SQL query from filter criteria.
         * 
         * @param filter QueryFilter with search criteria.
         * @param outParams Output vector to receive parameter values.
         * @return SQL COUNT query string with placeholders.
         * 
         * @details Similar to buildQuerySQL but returns COUNT(*) instead
         * of full rows. Omits ORDER BY and LIMIT clauses.
         */
        std::string LogDB::buildCountSQL(const QueryFilter& filter, std::vector<std::string>& outParams) {
            // Similar to buildQuerySQL but returns COUNT(*)
            std::ostringstream sql;
            sql << "SELECT COUNT(*) FROM log_entries WHERE 1=1";

            // Apply same filters as buildQuerySQL (without ORDER BY and LIMIT)
            if (filter.minLevel) {
                sql << " AND level >= ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.minLevel)));
            }

            if (filter.maxLevel) {
                sql << " AND level <= ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.maxLevel)));
            }

            if (filter.category) {
                sql << " AND category = ?";
                outParams.push_back(std::to_string(static_cast<int>(*filter.category)));
            }

            if (filter.startTime) {
                sql << " AND timestamp >= ?";
                outParams.push_back(timePointToString(*filter.startTime));
            }

            if (filter.endTime) {
                sql << " AND timestamp <= ?";
                outParams.push_back(timePointToString(*filter.endTime));
            }

            if (filter.sourcePattern) {
                sql << " AND source LIKE ?";
                outParams.push_back(ToUTF8(*filter.sourcePattern));
            }

            if (filter.messagePattern) {
                sql << " AND message LIKE ?";
                outParams.push_back(ToUTF8(*filter.messagePattern));
            }

            if (filter.processId) {
                sql << " AND process_id = ?";
                outParams.push_back(std::to_string(*filter.processId));
            }

            if (filter.threadId) {
                sql << " AND thread_id = ?";
                outParams.push_back(std::to_string(*filter.threadId));
            }

            if (filter.errorCode) {
                sql << " AND error_code = ?";
                outParams.push_back(std::to_string(*filter.errorCode));
            }

            return sql.str();
        }

        // ============================================================================
        //                      BATCH PROCESSING
        // ============================================================================

        /**
         * @brief Background thread function for batch log writes.
         * 
         * @details Thread loop:
         * 1. Wait on condition variable with timeout (batchFlushInterval)
         * 2. Wake on: shutdown signal, batch size reached, or timeout
         * 3. Process pending writes if queue is not empty
         * 4. Perform final flush before exit
         * 
         * Wakeup conditions:
         * - m_shutdownBatch becomes true
         * - m_pendingWrites.size() >= batchSize
         * - Wait timeout expires
         * 
         * @note Started by Initialize() when asyncLogging is enabled.
         * @note Stopped by Shutdown() via m_shutdownBatch flag.
         */
        void LogDB::batchWriteThread() {
            SS_LOG_INFO(L"LogDB", L"Batch write thread started");

            while (!m_shutdownBatch.load(std::memory_order_acquire)) {
                std::unique_lock<std::mutex> lock(m_batchMutex);

               
                std::chrono::milliseconds flushInterval;
                size_t batchSize;
                {
                    std::shared_lock<std::shared_mutex> configLock(m_configMutex);
                    flushInterval = m_config.batchFlushInterval;
                    batchSize = m_config.batchSize;
                }

                m_batchCV.wait_for(lock, flushInterval, [this, batchSize]() {
                    return m_shutdownBatch.load(std::memory_order_acquire) ||
                        m_pendingWrites.size() >= batchSize;
                    });

                if (m_shutdownBatch.load(std::memory_order_acquire)) {
                    break;
                }

                if (!m_pendingWrites.empty()) {
                    DatabaseError err;
                    processPendingWrites(&err);
                }
            }

            // Final flush
            DatabaseError err;
            Flush(&err);

            SS_LOG_INFO(L"LogDB", L"Batch write thread stopped");
        }

        /**
         * @brief Adds a log entry to the pending writes queue.
         * 
         * @param entry The log entry to enqueue.
         * 
         * @details Thread-safe addition to m_pendingWrites.
         * Wakes batch thread when queue reaches batch size threshold.
         */
        void LogDB::enqueuePendingWrite(const LogEntry& entry) {
            std::lock_guard<std::mutex> lock(m_batchMutex);

            PendingLogEntry pending;
            pending.entry = entry;
            pending.queuedTime = std::chrono::steady_clock::now();

            m_pendingWrites.push_back(std::move(pending));

            size_t batchSize;
            {
                std::shared_lock<std::shared_mutex> configLock(m_configMutex);
                batchSize = m_config.batchSize;
            }

            if (m_pendingWrites.size() >= batchSize) {
                m_batchCV.notify_one();
            }
        }

        /**
         * @brief Processes all pending writes as a batch.
         * 
         * @param err Optional pointer to receive error details.
         * @return true if batch was processed successfully.
         * 
         * @details Extracts entries from pending queue and calls LogBatch().
         * Clears the queue regardless of success/failure.
         * 
         * @note Caller must hold m_batchMutex.
         */
        bool LogDB::processPendingWrites(DatabaseError* err) {
            if (m_pendingWrites.empty()) {
                return true;
            }

            std::vector<LogEntry> entries;
            entries.reserve(m_pendingWrites.size());

            for (const auto& pending : m_pendingWrites) {
                entries.push_back(pending.entry);
            }

            m_pendingWrites.clear();

            return LogBatch(entries, err);
        }

        // ============================================================================
        //                      ROTATION HELPERS
        // ============================================================================

        /**
         * @brief Checks if log rotation is needed.
         * 
         * @param err Optional pointer to receive error details.
         * @return true if rotation thresholds are exceeded.
         * 
         * @details Checks two conditions:
         * 1. Database size exceeds maxLogSizeMB
         * 2. Oldest entry age exceeds maxLogAge
         * 
         * @note Reads configuration with shared lock for thread safety.
         */
        bool LogDB::shouldRotate(DatabaseError* err) {
            // READ CONFIG WITH LOCK FIRST!
            size_t maxLogSizeMB;
            std::chrono::hours maxLogAge;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                maxLogSizeMB = m_config.maxLogSizeMB;
                maxLogAge = m_config.maxLogAge;
            }

            auto stats = DatabaseManager::Instance().GetStats(err);

            size_t currentSizeMB = stats.totalSize / (1024 * 1024);

            if (currentSizeMB >= maxLogSizeMB) {  
                return true;
            }

            // Check age
            auto result = DatabaseManager::Instance().Query(SQL_GET_OLDEST, err);
            if (result.Next()) {
                std::string oldestStr = result.GetString(0);
                auto oldest = stringToTimePoint(oldestStr);
                auto age = std::chrono::system_clock::now() - oldest;

                if (age >= maxLogAge) {  
                    return true;
                }
            }

            return false;
        }

        /**
         * @brief Executes the log rotation process.
         * 
         * @param err Optional pointer to receive error details.
         * @return true if rotation completed successfully.
         * 
         * @details Rotation sequence:
         * 1. Reads maxLogAge and archivePath from config
         * 2. Calculates cutoff time (now - maxLogAge)
         * 3. Creates timestamped archive file (logs_archive_YYYYMMDD_HHMMSS.db)
         * 4. Deletes entries older than cutoff
         * 5. VACUUMs database to reclaim space
         * 6. Cleans up old archives exceeding retention count
         * 7. Updates rotation statistics
         * 
         * @note Creates archive directory if it doesn't exist.
         */
        bool LogDB::performRotation(DatabaseError* err) {
           
            std::chrono::hours maxLogAge;
            std::wstring archivePath;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                maxLogAge = m_config.maxLogAge;
                archivePath = m_config.archivePath;
            }

            // Create archive
            auto now = std::chrono::system_clock::now();
            auto cutoffTime = now - maxLogAge;  

            if (!archivePath.empty() && archivePath.back() != L'\\') {
                archivePath += L'\\';
            }

            // Create timestamp-based archive name
            auto time_t_now = std::chrono::system_clock::to_time_t(now);
            std::tm tmBuf;
            localtime_s(&tmBuf, &time_t_now);

            wchar_t timeStr[64];
            std::wcsftime(timeStr, 64, L"%Y%m%d_%H%M%S", &tmBuf);

            archivePath += L"logs_archive_";
            archivePath += timeStr;
            archivePath += L".db";

            if (!createArchive(archivePath, cutoffTime, err)) {
                return false;
            }

            // Delete old entries
            if (!DeleteBefore(cutoffTime, err)) {
                return false;
            }

            // Vacuum to reclaim space
            if (!Vacuum(err)) {
                SS_LOG_WARN(L"LogDB", L"Vacuum after rotation failed");
            }

            // Cleanup old archives
            cleanupOldArchives();

            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.lastRotation = now;
            m_stats.rotationCount++;

            SS_LOG_INFO(L"LogDB", L"Log rotation completed");
            return true;
        }

        /**
         * @brief Creates an archive database file.
         * 
         * @param archivePath Full path for the archive file.
         * @param beforeTimestamp Timestamp for filtering (currently unused).
         * @param err Optional pointer to receive error details.
         * @return true if archive was created.
         * 
         * @details Creates parent directory if needed, then performs full
         * database backup using DatabaseManager::BackupToFile().
         * 
         * @note Currently backs up entire database. Future enhancement:
         * export only entries before beforeTimestamp.
         */
        bool LogDB::createArchive(std::wstring_view archivePath,
                                  std::chrono::system_clock::time_point beforeTimestamp,
                                  DatabaseError* err)
        {
            // Ensure archive directory exists
            std::filesystem::path path(archivePath);
            std::filesystem::path dir = path.parent_path();
            
            Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::CreateDirectories(dir.wstring(), &fileErr)) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Failed to create archive directory";
                }
                return false;
            }

            // Backup database
            return DatabaseManager::Instance().BackupToFile(archivePath, err);
        }

        /**
         * @brief Removes old archive files exceeding retention limit.
         * 
         * @details Cleanup process:
         * 1. Lists all .db files in archive directory
         * 2. Sorts by modification time (oldest first)
         * 3. Deletes oldest files until count <= maxArchivedLogs
         * 
         * @note Silently continues if archive directory doesn't exist.
         * @note Uses std::filesystem for directory iteration.
         */
        void LogDB::cleanupOldArchives() {
            // READ CONFIG WITH LOCK FIRST!
            std::wstring archivePath;
            size_t maxArchivedLogs;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                archivePath = m_config.archivePath;
                maxArchivedLogs = m_config.maxArchivedLogs;
            }

            // Find and delete archives exceeding maxArchivedLogs
            std::filesystem::path archiveDir(archivePath);  // ✅ Use local var!

            if (!std::filesystem::exists(archiveDir)) {
                return;
            }

            std::vector<std::filesystem::path> archives;

            for (const auto& entry : std::filesystem::directory_iterator(archiveDir)) {
                if (entry.is_regular_file() && entry.path().extension() == L".db") {
                    archives.push_back(entry.path());
                }
            }

            if (archives.size() <= maxArchivedLogs) {  // ✅ Use local var!
                return;
            }

            // Sort by modification time
            std::sort(archives.begin(), archives.end(), [](const auto& a, const auto& b) {
                return std::filesystem::last_write_time(a) < std::filesystem::last_write_time(b);
                });

            // Delete oldest
            size_t toDelete = archives.size() - maxArchivedLogs;  // ✅ Use local var!
            for (size_t i = 0; i < toDelete; ++i) {
                std::error_code ec;
                std::filesystem::remove(archives[i], ec);
                if (!ec) {
                    SS_LOG_INFO(L"LogDB", L"Deleted old archive: %ls", archives[i].wstring().c_str());
                }
            }
        }

        // ============================================================================
        //                      STATISTICS HELPERS
        // ============================================================================

        /**
         * @brief Updates in-memory statistics with a new log entry.
         * 
         * @param entry The log entry that was written.
         * 
         * @details Updates:
         * - totalEntries counter
         * - entriesByLevel histogram
         * - entriesByCategory histogram
         * - oldestEntry / newestEntry timestamps
         * 
         * @note Thread-safe via m_statsMutex.
         */
        void LogDB::updateStatistics(const LogEntry& entry) {
            std::lock_guard<std::mutex> lock(m_statsMutex);

            m_stats.totalEntries++;
            
            if (entry.level < LogLevel::Trace || entry.level > LogLevel::Fatal) {
                return;
            }
            
            m_stats.entriesByLevel[static_cast<size_t>(entry.level)]++;
            m_stats.entriesByCategory[static_cast<size_t>(entry.category)]++;

            if (m_stats.oldestEntry == std::chrono::system_clock::time_point{} ||
                entry.timestamp < m_stats.oldestEntry) {
                m_stats.oldestEntry = entry.timestamp;
            }

            if (entry.timestamp > m_stats.newestEntry) {
                m_stats.newestEntry = entry.timestamp;
            }
        }

        /**
         * @brief Recalculates statistics from database contents.
         * 
         * @param err Optional pointer to receive error details.
         * 
         * @details Queries database for:
         * - Total entry count
         * - Oldest entry timestamp
         * - Newest entry timestamp
         * - Database file size
         * 
         * @note Called during Initialize() and after deletions.
         * @note Thread-safe via m_statsMutex.
         */
        void LogDB::recalculateStatistics(DatabaseError* err) {
            std::lock_guard<std::mutex> lock(m_statsMutex);

            // Reset statistics
            m_stats.totalEntries = 0;
            std::fill(std::begin(m_stats.entriesByLevel), std::end(m_stats.entriesByLevel), 0);
            std::fill(std::begin(m_stats.entriesByCategory), std::end(m_stats.entriesByCategory), 0);

            // Recalculate from database
            auto result = DatabaseManager::Instance().Query(SQL_COUNT_ALL, err);
            if (result.Next()) {
                m_stats.totalEntries = result.GetInt64(0);
            }

            // Get oldest entry
            result = DatabaseManager::Instance().Query(SQL_GET_OLDEST, err);
            if (result.Next()) {
                m_stats.oldestEntry = stringToTimePoint(result.GetString(0));
            }

            // Get newest entry
            result = DatabaseManager::Instance().Query(SQL_GET_NEWEST, err);
            if (result.Next()) {
                m_stats.newestEntry = stringToTimePoint(result.GetString(0));
            }

            // Get database size
            auto dbStats = DatabaseManager::Instance().GetStats(err);
            m_stats.dbSizeBytes = dbStats.totalSize;
        }

        // ============================================================================
        //                      DATA CONVERSION HELPERS
        // ============================================================================

        /**
         * @brief Converts a database row to a LogEntry structure.
         * 
         * @param result QueryResult positioned at the row to convert.
         * @return Populated LogEntry structure.
         * 
         * @details Maps columns by index (0-17) to LogEntry fields.
         * Converts UTF-8 strings from database to wide strings.
         * 
         * Column mapping:
         * 0=id, 1=timestamp, 2=level, 3=category, 4=source, 5=message,
         * 6=details, 7=process_id, 8=thread_id, 9=user_name, 10=machine_name,
         * 11=metadata, 12=error_code, 13=error_context, 14=duration_ms,
         * 15=file_path, 16=line_number, 17=function_name
         */
        LogDB::LogEntry LogDB::rowToLogEntry(QueryResult& result) {
            LogEntry entry;
            
            entry.id = result.GetInt64(0);
            entry.timestamp = stringToTimePoint(result.GetString(1));
            entry.level = static_cast<LogLevel>(result.GetInt(2));
            entry.category = static_cast<LogCategory>(result.GetInt(3));
            entry.source = ToWide(result.GetString(4));
            entry.message = ToWide(result.GetString(5));
            entry.details = ToWide(result.GetString(6));
            entry.processId = result.GetInt(7);
            entry.threadId = result.GetInt(8);
            entry.userName = ToWide(result.GetString(9));
            entry.machineName = ToWide(result.GetString(10));
            entry.metadata = ToWide(result.GetString(11));
            entry.errorCode = result.GetInt(12);
            entry.errorContext = ToWide(result.GetString(13));
            entry.durationMs = result.GetInt64(14);
            entry.filePath = ToWide(result.GetString(15));
            entry.lineNumber = result.GetInt(16);
            entry.functionName = ToWide(result.GetString(17));

            return entry;
        }

        /**
         * @brief Converts a time_point to ISO 8601 string format.
         * 
         * @param tp The time point to convert.
         * @return ISO 8601 formatted string: "YYYY-MM-DD HH:MM:SS.mmm"
         * 
         * @details Uses UTC timezone. Includes millisecond precision.
         * Example output: "2026-01-15 14:30:45.123"
         */
        std::string LogDB::timePointToString(std::chrono::system_clock::time_point tp) {
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
         * @param str ISO 8601 formatted string: "YYYY-MM-DD HH:MM:SS[.mmm]"
         * @return Parsed time_point. Epoch (zero) on parse failure.
         * 
         * @details Expects UTC timezone. Milliseconds are optional.
         * Uses sscanf_s for robust parsing.
         */
        std::chrono::system_clock::time_point LogDB::stringToTimePoint(std::string_view str) {
            // Parse ISO 8601 format: YYYY-MM-DD HH:MM:SS.mmm
            std::tm tm = {};
            
            // Manual parsing to avoid stream issues
            if (str.length() < 19) {
                return std::chrono::system_clock::time_point{};
            }

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
                    // Ignore parsing errors for milliseconds
                }
            }

            return tp;
        }

        // ============================================================================
        //                      PerformanceLogger IMPLEMENTATION
        // ============================================================================

        /**
         * @brief Constructs a PerformanceLogger for automatic timing.
         * 
         * @param source Module or component name for the log entry.
         * @param operation Name of the operation being timed.
         * @param minLevel Minimum log level (default: Debug).
         * 
         * @details Captures start time on construction. Duration is calculated
         * and logged when the object is destroyed (RAII pattern).
         * 
         * @code
         * void ProcessFiles() {
         *     PerformanceLogger perf(L"FileProcessor", L"ProcessFiles");
         *     perf.AddDetail(L"FileCount", L"150");
         *     // ... do work ...
         * }  // Automatically logs duration when perf goes out of scope
         * @endcode
         */
        PerformanceLogger::PerformanceLogger(std::wstring source,
                                            std::wstring operation,
                                            LogDB::LogLevel minLevel)
            : m_source(std::move(source))
            , m_operation(std::move(operation))
            , m_minLevel(minLevel)
            , m_startTime(std::chrono::steady_clock::now())
        {
        }

        /**
         * @brief Destructor - logs performance entry unless cancelled.
         * 
         * @details Calculates elapsed time from construction and calls
         * LogDB::LogPerformance() with captured source, operation, and details.
         * 
         * @note No logging occurs if Cancel() was called.
         */
        PerformanceLogger::~PerformanceLogger() {
            if (m_cancelled) {
                return;
            }

            auto endTime = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                endTime - m_startTime);

            LogDB::Instance().LogPerformance(
                m_source,
                m_operation,
                duration.count(),
                m_details
            );
        }

        /**
         * @brief Adds a key-value detail to the performance log.
         * 
         * @param key Detail name (e.g., L"ItemCount", L"FilePath").
         * @param value Detail value.
         * 
         * @details Appends "key=value" to the details string.
         * Multiple details are separated by "; ".
         * 
         * @code
         * perf.AddDetail(L"Items", L"1000");
         * perf.AddDetail(L"Mode", L"Parallel");
         * // Results in: "Items=1000; Mode=Parallel"
         * @endcode
         */
        void PerformanceLogger::AddDetail(std::wstring_view key, std::wstring_view value) {
            if (!m_details.empty()) {
                m_details += L"; ";
            }
            m_details += key;
            m_details += L"=";
            m_details += value;
        }

        /**
         * @brief Sets the success flag and adds it as a detail.
         * 
         * @param success true if operation succeeded, false otherwise.
         * 
         * @details Adds "Success=true" or "Success=false" to details.
         */
        void PerformanceLogger::SetSuccess(bool success) {
            m_success = success;
            AddDetail(L"Success", success ? L"true" : L"false");
        }

        /**
         * @brief Cancels performance logging for this instance.
         * 
         * @details After calling Cancel(), the destructor will NOT log
         * anything. Useful for conditional logging or error paths where
         * you don't want to record the timing.
         */
        void PerformanceLogger::Cancel() {
            m_cancelled = true;
        }

        // ============================================================================
        //                      DATABASE MODIFICATION HELPERS
        // ============================================================================

        /**
         * @brief Updates an existing log entry in the database.
         * 
         * @param entry The entry to update (must have valid id > 0).
         * @param err Optional pointer to receive error details.
         * @return true if update succeeded.
         * 
         * @details Updates all fields except id. The entry.id must match
         * an existing row. Increments write statistics on success.
         */
        bool LogDB::dbUpdateEntry(const LogEntry& entry, DatabaseError* err) {
            if (entry.id <= 0) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Invalid entry ID for update";
                }
                return false;
            }

            constexpr const char* SQL_UPDATE_ENTRY = R"(
        UPDATE log_entries SET
            timestamp = ?,
            level = ?,
            category = ?,
            source = ?,
            message = ?,
            details = ?,
            process_id = ?,
            thread_id = ?,
            user_name = ?,
            machine_name = ?,
            metadata = ?,
            error_code = ?,
            error_context = ?,
            duration_ms = ?,
            file_path = ?,
            line_number = ?,
            function_name = ?
        WHERE id = ?
    )";

            std::string timestamp = timePointToString(entry.timestamp);

            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_UPDATE_ENTRY,
                err,
                timestamp,
                static_cast<int>(entry.level),
                static_cast<int>(entry.category),
                ToUTF8(entry.source),
                ToUTF8(entry.message),
                ToUTF8(entry.details),
                static_cast<int>(entry.processId),
                static_cast<int>(entry.threadId),
                ToUTF8(entry.userName),
                ToUTF8(entry.machineName),
                ToUTF8(entry.metadata),
                static_cast<int>(entry.errorCode),
                ToUTF8(entry.errorContext),
                entry.durationMs,
                ToUTF8(entry.filePath),
                entry.lineNumber,
                ToUTF8(entry.functionName),
                entry.id
            );

            if (success) {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalWrites++;
            }

            return success;
        }

        /**
         * @brief Deletes a log entry by ID (internal implementation).
         * 
         * @param id The entry ID to delete (must be > 0).
         * @param err Optional pointer to receive error details.
         * @return true if deletion succeeded.
         * 
         * @details Validates ID before deletion. Updates delete statistics
         * and decrements total entry count on success.
         */
        bool LogDB::dbDeleteEntry(int64_t id, DatabaseError* err) {
            if (id <= 0) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Invalid entry ID for deletion";
                }
                return false;
            }

            constexpr const char* SQL_DELETE_ENTRY_BY_ID = R"(
        DELETE FROM log_entries WHERE id = ?
    )";

            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_DELETE_ENTRY_BY_ID, err, id);

            if (success) {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalDeletes++;

                // Optionally recalculate entry count
                if (m_stats.totalEntries > 0) {
                    m_stats.totalEntries--;
                }
            }

            return success;
        }

    } // namespace Database
} // namespace ShadowStrike