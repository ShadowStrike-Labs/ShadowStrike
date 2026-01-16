#pragma once

/**
 * @file LogDB.hpp
 * @brief Enterprise-Grade Centralized Logging Database System
 * 
 * @details Provides a high-performance, persistent logging system with SQLite
 * backend for the ShadowStrike Antivirus Engine. Designed for enterprise
 * security applications requiring comprehensive audit trails and diagnostics.
 * 
 * ============================================================================
 *                              ARCHITECTURE OVERVIEW
 * ============================================================================
 * 
 *     ┌─────────────────────────────────────────────────────────────────────┐
 *     │                         APPLICATION LAYER                            │
 *     │                                                                       │
 *     │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
 *     │   │   Scanner   │  │  Quarantine │  │   Network   │  │   Service   │ │
 *     │   │   Module    │  │    Module   │  │   Monitor   │  │   Manager   │ │
 *     │   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘ │
 *     └──────────┼────────────────┼────────────────┼────────────────┼────────┘
 *                │                │                │                │
 *                └───────────────┬┴────────────────┴────────────────┘
 *                                │
 *                                ▼
 *     ┌─────────────────────────────────────────────────────────────────────┐
 *     │                         LogDB SINGLETON                              │
 *     │                                                                       │
 *     │  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐  ┌────────────┐  │
 *     │  │   Level     │  │   Async      │  │   Query     │  │  Rotation  │  │
 *     │  │  Filtering  │──│   Batching   │──│   Engine    │──│  Manager   │  │
 *     │  └─────────────┘  └──────────────┘  └─────────────┘  └────────────┘  │
 *     │                          │                                           │
 *     │                          ▼                                           │
 *     │            ┌──────────────────────────────┐                          │
 *     │            │    BACKGROUND BATCH THREAD   │                          │
 *     │            │  • Configurable batch size   │                          │
 *     │            │  • Timed flush interval      │                          │
 *     │            │  • Transactional writes      │                          │
 *     │            └──────────────────────────────┘                          │
 *     └─────────────────────────────────────────────────────────────────────┘
 *                                │
 *                                ▼
 *     ┌─────────────────────────────────────────────────────────────────────┐
 *     │                      DATABASE MANAGER                                │
 *     │         Connection Pool │ Statement Cache │ Transactions             │
 *     └─────────────────────────────────────────────────────────────────────┘
 *                                │
 *                                ▼
 *     ┌─────────────────────────────────────────────────────────────────────┐
 *     │                         SQLITE DATABASE                              │
 *     │    log_entries TABLE │ Performance Indices │ FTS5 Full-Text Search   │
 *     └─────────────────────────────────────────────────────────────────────┘
 * 
 * ============================================================================
 *                              KEY FEATURES
 * ============================================================================
 * 
 * 1. MULTI-LEVEL LOGGING
 *    - Trace (0): Verbose debugging information
 *    - Debug (1): Development diagnostic messages
 *    - Info (2): Normal operational messages (default threshold)
 *    - Warn (3): Warning conditions
 *    - Error (4): Error conditions
 *    - Fatal (5): Critical failures
 * 
 * 2. CATEGORIZED LOGGING (17 categories)
 *    General, System, Security, Network, FileSystem, Process, Registry,
 *    Service, Driver, Performance, Database, Scanner, Quarantine, Update,
 *    Configuration, UserInterface, Custom
 * 
 * 3. ASYNCHRONOUS LOGGING
 *    - Background thread for non-blocking writes
 *    - Configurable batch size (default: 100 entries)
 *    - Automatic flush interval (default: 5 seconds)
 *    - Graceful shutdown with final flush
 * 
 * 4. FULL-TEXT SEARCH (FTS5)
 *    - Optional SQLite FTS5 integration
 *    - Searchable: source, message, details fields
 *    - Automatic index synchronization via triggers
 * 
 * 5. LOG ROTATION & ARCHIVAL
 *    - Size-based rotation (default: 500MB)
 *    - Age-based rotation (default: 30 days)
 *    - Automatic archive creation with retention management
 * 
 * ============================================================================
 *                              USAGE EXAMPLE
 * ============================================================================
 * 
 * @code
 * #include "LogDB.hpp"
 * using namespace ShadowStrike::Database;
 * 
 * // Initialize logging system
 * LogDB::Config config;
 * config.dbPath = L"C:\\ProgramData\\ShadowStrike\\logs.db";
 * config.asyncLogging = true;
 * config.maxLogSizeMB = 200;
 * 
 * DatabaseError err;
 * if (!LogDB::Instance().Initialize(config, &err)) {
 *     // Handle initialization failure
 * }
 * 
 * // Basic logging
 * LogDB::Instance().LogInfo(L"MainModule", L"Application started");
 * LogDB::Instance().LogError(L"Scanner", L"Malware detected in file.exe");
 * 
 * // Error logging with code
 * LogDB::Instance().LogErrorWithCode(L"FileIO", L"Failed to open file",
 *     GetLastError(), L"Path: C:\\temp\\data.bin");
 * 
 * // Performance logging with RAII
 * {
 *     PerformanceLogger perf(L"Scanner", L"ScanDirectory");
 *     perf.AddDetail(L"Files", L"1500");
 *     // ... scan operation ...
 * }  // Automatically logs duration
 * 
 * // Query logs
 * auto errors = LogDB::Instance().GetByLevel(LogDB::LogLevel::Error, 100);
 * auto recent = LogDB::Instance().GetRecent(50);
 * 
 * // Full-text search
 * auto results = LogDB::Instance().SearchText(L"malware", true);
 * 
 * // Shutdown
 * LogDB::Instance().Shutdown();
 * @endcode
 * 
 * ============================================================================
 *                              THREAD SAFETY
 * ============================================================================
 * 
 * - All public methods are thread-safe
 * - Configuration protected by std::shared_mutex
 * - Statistics protected by std::mutex
 * - Batch queue protected by std::mutex + condition_variable
 * - Atomic flags for initialization and shutdown states
 * 
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @date 2026
 * @copyright MIT License
 * 
 * @see LogDB.cpp for implementation details
 * @see DatabaseManager.hpp for underlying storage
 */

#include "DatabaseManager.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/SystemUtils.hpp"

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

namespace ShadowStrike {
    namespace Database {

        // ============================================================================
        //                      LogDB CLASS DECLARATION
        // ============================================================================

        /**
         * @class LogDB
         * @brief Singleton persistent logging system with database storage.
         * 
         * @details Provides centralized logging with:
         * - Multi-level severity filtering (Trace to Fatal)
         * - Categorized logging for component separation
         * - Asynchronous batch writes for performance
         * - Full-text search capabilities (optional FTS5)
         * - Automatic log rotation and archival
         * - Comprehensive query API
         * - Statistics and analytics
         * 
         * @note Thread-safe: All public methods can be called from any thread.
         * @note Singleton: Access via LogDB::Instance()
         * 
         * @see Initialize() for startup
         * @see Shutdown() for cleanup
         */
        class LogDB {
        public:
            // ========================================================================
            //                      ENUMERATIONS
            // ========================================================================

            /**
             * @enum LogLevel
             * @brief Severity level for log entries.
             * 
             * @details Levels are ordered by severity (0=lowest, 5=highest).
             * The minimum log level can be configured to filter out verbose entries.
             * 
             * Typical usage:
             * - Trace: Loop iterations, variable dumps (production disabled)
             * - Debug: Function entry/exit, state changes
             * - Info: Normal operations, milestones
             * - Warn: Recoverable issues, deprecation warnings
             * - Error: Failures requiring attention
             * - Fatal: Critical failures, application termination
             */
            enum class LogLevel : uint8_t {
                Trace = 0,      ///< Verbose tracing (production disabled)
                Debug = 1,      ///< Debugging information
                Info = 2,       ///< Normal operational messages
                Warn = 3,       ///< Warning conditions
                Error = 4,      ///< Error conditions
                Fatal = 5       ///< Critical failures
            };

            /**
             * @enum LogCategory
             * @brief Functional category for log entries.
             * 
             * @details Categories enable filtering by system component.
             * Use the appropriate category to make logs easier to analyze.
             */
            enum class LogCategory : uint8_t {
                General = 0,        ///< General purpose logs
                System = 1,         ///< Operating system interactions
                Security = 2,       ///< Security-related events
                Network = 3,        ///< Network operations
                FileSystem = 4,     ///< File system operations
                Process = 5,        ///< Process management
                Registry = 6,       ///< Windows Registry operations
                Service = 7,        ///< Windows Service management
                Driver = 8,         ///< Kernel driver interactions
                Performance = 9,    ///< Performance measurements
                Database = 10,      ///< Database operations
                Scanner = 11,       ///< Malware scanner events
                Quarantine = 12,    ///< Quarantine operations
                Update = 13,        ///< Update/patch operations
                Configuration = 14, ///< Configuration changes
                UserInterface = 15, ///< UI-related events
                Custom = 255        ///< User-defined category
            };

            // ========================================================================
            //                      DATA STRUCTURES
            // ========================================================================

            /**
             * @struct LogEntry
             * @brief Complete log entry with all metadata fields.
             * 
             * @details Represents a single log record in the database.
             * Most fields are optional and will be auto-populated if empty.
             */
            struct LogEntry {
                int64_t id = 0;                                    ///< Database row ID (auto-assigned)
                std::chrono::system_clock::time_point timestamp;   ///< Entry timestamp (UTC)
                LogLevel level = LogLevel::Info;                   ///< Severity level
                LogCategory category = LogCategory::General;       ///< Functional category
                
                std::wstring source;            ///< Component/module name generating the log
                std::wstring message;           ///< Primary log message
                std::wstring details;           ///< Extended details (optional)
                
                uint32_t processId = 0;         ///< Windows Process ID (0 = auto-fill)
                uint32_t threadId = 0;          ///< Windows Thread ID (0 = auto-fill)
                std::wstring userName;          ///< User name (empty = auto-fill)
                std::wstring machineName;       ///< Machine name (empty = auto-fill)
                
                std::wstring metadata;          ///< Structured metadata (JSON format)
                
                uint32_t errorCode = 0;         ///< Windows/application error code
                std::wstring errorContext;      ///< Additional error context
                
                int64_t durationMs = 0;         ///< Operation duration (performance logs)
                
                std::wstring filePath;          ///< Source file path (optional)
                int lineNumber = 0;             ///< Source line number (optional)
                std::wstring functionName;      ///< Source function name (optional)
            };

            // ========================================================================
            //                      CONFIGURATION STRUCTURES
            // ========================================================================

            /**
             * @struct Config
             * @brief Configuration settings for LogDB initialization.
             * 
             * @details Controls all aspects of logging behavior including:
             * - Database location and settings
             * - Logging thresholds and modes
             * - Rotation and archival policies
             * - Performance tuning
             * 
             * @note All paths should use absolute paths.
             * @note Changes require re-initialization to take effect.
             */
            struct Config {
                /// @name Database Settings
                /// @{
                std::wstring dbPath = L"C:\\ProgramData\\ShadowStrike\\logs.db";  ///< Database file path
                bool enableWAL = true;              ///< Enable Write-Ahead Logging (recommended)
                size_t dbCacheSizeKB = 20480;       ///< SQLite cache size (20MB default)
                size_t maxConnections = 5;          ///< Max pool connections
                /// @}
                
                /// @name Logging Behavior
                /// @{
                LogLevel minLogLevel = LogLevel::Info;  ///< Minimum level to record
                bool logToConsole = false;          ///< Echo logs to console (debug)
                bool logToFile = true;              ///< Write to database
                bool asyncLogging = true;           ///< Use background batch thread
                /// @}
                
                /// @name Rotation Settings
                /// @{
                bool enableRotation = true;         ///< Enable automatic rotation
                size_t maxLogSizeMB = 500;          ///< Size threshold for rotation
                std::chrono::hours maxLogAge = std::chrono::hours(24 * 30);  ///< Age threshold (30 days)
                size_t maxArchivedLogs = 10;        ///< Max archives to retain
                std::wstring archivePath = L"C:\\ProgramData\\ShadowStrike\\LogArchive";  ///< Archive directory
                /// @}
                
                /// @name Performance Tuning
                /// @{
                size_t batchSize = 100;             ///< Entries per batch write
                std::chrono::milliseconds batchFlushInterval = std::chrono::seconds(5);  ///< Max wait before flush
                /// @}
                
                /// @name Features
                /// @{
                bool enableFullTextSearch = true;   ///< Create FTS5 index
                bool enableStatistics = true;       ///< Track statistics
                /// @}
            };

            /**
             * @struct QueryFilter
             * @brief Filter criteria for log queries.
             * 
             * @details Optional fields allow flexible query construction.
             * Unset (std::nullopt) fields are not included in the WHERE clause.
             * 
             * Pattern fields use SQL LIKE syntax (% for wildcard).
             * Full-text search uses FTS5 query syntax.
             */
            struct QueryFilter {
                std::optional<LogLevel> minLevel;       ///< Minimum severity level
                std::optional<LogLevel> maxLevel;       ///< Maximum severity level
                std::optional<LogCategory> category;    ///< Filter by category
                std::optional<std::chrono::system_clock::time_point> startTime;  ///< Time range start
                std::optional<std::chrono::system_clock::time_point> endTime;    ///< Time range end
                std::optional<std::wstring> sourcePattern;      ///< Source LIKE pattern
                std::optional<std::wstring> messagePattern;     ///< Message LIKE pattern
                std::optional<std::wstring> fullTextSearch;     ///< FTS5 query string
                std::optional<uint32_t> processId;      ///< Filter by process ID
                std::optional<uint32_t> threadId;       ///< Filter by thread ID
                std::optional<uint32_t> errorCode;      ///< Filter by error code
                size_t maxResults = 1000;               ///< Max entries to return
                bool sortDescending = true;             ///< true = newest first
            };

            /**
             * @struct Statistics
             * @brief Runtime statistics for logging operations.
             * 
             * @details Tracks operational metrics for monitoring and debugging.
             * Updated automatically during logging operations.
             */
            struct Statistics {
                uint64_t totalEntries = 0;              ///< Total entries in database
                uint64_t entriesByLevel[6] = {};        ///< Histogram by LogLevel
                uint64_t entriesByCategory[256] = {};   ///< Histogram by LogCategory
                
                uint64_t totalWrites = 0;               ///< Total insert operations
                uint64_t totalReads = 0;                ///< Total query operations
                uint64_t totalDeletes = 0;              ///< Total delete operations
                
                std::chrono::milliseconds avgWriteTime{};   ///< Average write latency
                std::chrono::milliseconds avgReadTime{};    ///< Average read latency
                
                size_t dbSizeBytes = 0;                     ///< Current database file size
                size_t indexSizeBytes = 0;                  ///< Index storage size
                
                std::chrono::system_clock::time_point oldestEntry;  ///< Oldest entry timestamp
                std::chrono::system_clock::time_point newestEntry;  ///< Newest entry timestamp
                std::chrono::system_clock::time_point lastRotation; ///< Last rotation time
                
                uint64_t rotationCount = 0;                 ///< Number of rotations performed
                uint64_t archivedLogCount = 0;              ///< Number of archives created
            };

            // ========================================================================
            //                      LIFECYCLE MANAGEMENT
            // ========================================================================

            /**
             * @brief Returns the singleton instance of LogDB.
             * @return Reference to the global LogDB instance.
             * @note Thread-safe via C++11 magic statics.
             */
            static LogDB& Instance();

            /**
             * @brief Initializes the logging system with specified configuration.
             * @param config Configuration settings.
             * @param err Optional pointer for detailed error information.
             * @return true if initialization succeeded.
             * @see Config for available options.
             */
            bool Initialize(const Config& config, DatabaseError* err = nullptr);
            
            /**
             * @brief Shuts down the logging system gracefully.
             * @details Flushes pending writes and stops background thread.
             */
            void Shutdown();
            
            /**
             * @brief Checks if the logging system is initialized.
             * @return true if Initialize() completed successfully.
             */
            bool IsInitialized() const noexcept { return m_initialized.load(); }

            // ========================================================================
            //                      LOGGING OPERATIONS
            // ========================================================================

            /**
             * @brief Logs a message with specified level and category.
             * @param level Severity level.
             * @param category Functional category.
             * @param source Module/component name.
             * @param message Log message content.
             * @param err Optional error output.
             * @return Entry ID (sync), -1 (async queued), 0 (filtered).
             */
            int64_t Log(LogLevel level,
                       LogCategory category,
                       std::wstring_view source,
                       std::wstring_view message,
                       DatabaseError* err = nullptr);

            /**
             * @brief Logs a complete entry with all metadata fields.
             * @param entry Full log entry structure.
             * @param err Optional error output.
             * @return Entry ID (sync), -1 (async queued), 0 (filtered).
             */
            int64_t LogDetailed(const LogEntry& entry, DatabaseError* err = nullptr);

            /// @name Convenience Logging Methods
            /// @brief Quick logging at specific levels with General category.
            /// @{
            int64_t LogTrace(std::wstring_view source, std::wstring_view message);  ///< Log at TRACE level
            int64_t LogDebug(std::wstring_view source, std::wstring_view message);  ///< Log at DEBUG level
            int64_t LogInfo(std::wstring_view source, std::wstring_view message);   ///< Log at INFO level
            int64_t LogWarn(std::wstring_view source, std::wstring_view message);   ///< Log at WARN level
            int64_t LogError(std::wstring_view source, std::wstring_view message);  ///< Log at ERROR level
            int64_t LogFatal(std::wstring_view source, std::wstring_view message);  ///< Log at FATAL level
            /// @}

            /**
             * @brief Logs an error with Windows/application error code.
             * @param source Module/component name.
             * @param message Error description.
             * @param errorCode GetLastError() or custom error code.
             * @param errorContext Additional context about the failure.
             * @return Entry ID or -1 for async.
             */
            int64_t LogErrorWithCode(std::wstring_view source,
                                    std::wstring_view message,
                                    uint32_t errorCode,
                                    std::wstring_view errorContext = L"");

            /**
             * @brief Logs a performance measurement.
             * @param source Module/component name.
             * @param operation Name of the timed operation.
             * @param durationMs Duration in milliseconds.
             * @param details Additional context.
             * @return Entry ID or -1 for async.
             * @see PerformanceLogger for automatic timing.
             */
            int64_t LogPerformance(std::wstring_view source,
                                  std::wstring_view operation,
                                  int64_t durationMs,
                                  std::wstring_view details = L"");

            /**
             * @brief Inserts multiple entries in a single transaction.
             * @param entries Vector of entries to insert.
             * @param err Optional error output.
             * @return true if all entries were inserted.
             */
            bool LogBatch(const std::vector<LogEntry>& entries, DatabaseError* err = nullptr);

            // ========================================================================
            //                      QUERY OPERATIONS
            // ========================================================================

            /**
             * @brief Retrieves a single log entry by ID.
             * @param id Entry ID to look up.
             * @param err Optional error output.
             * @return Entry if found, std::nullopt otherwise.
             */
            std::optional<LogEntry> GetEntry(int64_t id, DatabaseError* err = nullptr);

            /**
             * @brief Queries entries with flexible filter criteria.
             * @param filter QueryFilter specifying search criteria.
             * @param err Optional error output.
             * @return Vector of matching entries.
             * @see QueryFilter for available filter options.
             */
            std::vector<LogEntry> Query(const QueryFilter& filter, DatabaseError* err = nullptr);

            /**
             * @brief Gets the most recent log entries.
             * @param count Max entries to return (default: 100).
             * @param minLevel Minimum severity filter (default: Info).
             * @param err Optional error output.
             * @return Vector of recent entries, newest first.
             */
            std::vector<LogEntry> GetRecent(size_t count = 100,
                                           LogLevel minLevel = LogLevel::Info,
                                           DatabaseError* err = nullptr);

            /**
             * @brief Gets entries with a specific severity level.
             * @param level Exact level to filter by.
             * @param maxCount Max entries to return.
             * @param err Optional error output.
             * @return Vector of matching entries.
             */
            std::vector<LogEntry> GetByLevel(LogLevel level,
                                            size_t maxCount = 1000,
                                            DatabaseError* err = nullptr);

            /**
             * @brief Gets entries from a specific category.
             * @param category Category to filter by.
             * @param maxCount Max entries to return.
             * @param err Optional error output.
             * @return Vector of matching entries.
             */
            std::vector<LogEntry> GetByCategory(LogCategory category,
                                               size_t maxCount = 1000,
                                               DatabaseError* err = nullptr);

            /**
             * @brief Gets entries within a time range.
             * @param start Range start (inclusive).
             * @param end Range end (inclusive).
             * @param maxCount Max entries to return.
             * @param err Optional error output.
             * @return Vector of matching entries.
             */
            std::vector<LogEntry> GetByTimeRange(
                std::chrono::system_clock::time_point start,
                std::chrono::system_clock::time_point end,
                size_t maxCount = 1000,
                DatabaseError* err = nullptr);

            /**
             * @brief Gets entries from a specific process.
             * @param processId Windows process ID.
             * @param maxCount Max entries to return.
             * @param err Optional error output.
             * @return Vector of matching entries.
             */
            std::vector<LogEntry> GetByProcess(uint32_t processId,
                                              size_t maxCount = 1000,
                                              DatabaseError* err = nullptr);

            /**
             * @brief Searches entries by text content.
             * @param searchText Text to search for.
             * @param useFullText true = FTS5 search, false = LIKE pattern.
             * @param maxCount Max entries to return.
             * @param err Optional error output.
             * @return Vector of matching entries.
             */
            std::vector<LogEntry> SearchText(std::wstring_view searchText,
                                            bool useFullText = false,
                                            size_t maxCount = 1000,
                                            DatabaseError* err = nullptr);

            /**
             * @brief Counts entries matching optional filter.
             * @param filter Optional filter criteria (nullptr = count all).
             * @param err Optional error output.
             * @return Entry count, or -1 on error.
             */
            int64_t CountEntries(const QueryFilter* filter = nullptr, DatabaseError* err = nullptr);

            // ========================================================================
            //                      MANAGEMENT OPERATIONS
            // ========================================================================

            /// @name Deletion Operations
            /// @{
            
            /** @brief Deletes a single entry by ID. */
            bool DeleteEntry(int64_t id, DatabaseError* err = nullptr);
            
            /** @brief Deletes entries older than specified timestamp. */
            bool DeleteBefore(std::chrono::system_clock::time_point timestamp,
                            DatabaseError* err = nullptr);
            
            /** @brief Deletes all entries with specified level. */
            bool DeleteByLevel(LogLevel level, DatabaseError* err = nullptr);
            
            /** @brief Deletes ALL entries. @warning Irreversible! */
            bool DeleteAll(DatabaseError* err = nullptr);
            /// @}

            /// @name Archive Operations
            /// @{
            
            /**
             * @brief Creates an archive of logs before timestamp.
             * @param archivePath Full path for archive file.
             * @param beforeTimestamp Archive entries older than this.
             * @param err Optional error output.
             * @return true if archive was created.
             */
            bool ArchiveLogs(std::wstring_view archivePath,
                           std::chrono::system_clock::time_point beforeTimestamp,
                           DatabaseError* err = nullptr);

            /**
             * @brief Restores logs from archive (replaces current).
             * @param archivePath Path to archive file.
             * @param err Optional error output.
             * @return true if restore succeeded.
             * @warning Replaces current database!
             */
            bool RestoreLogs(std::wstring_view archivePath, DatabaseError* err = nullptr);
            /// @}

            /// @name Rotation Operations
            /// @{
            
            /** @brief Manually triggers log rotation. */
            bool RotateLogs(DatabaseError* err = nullptr);
            
            /** @brief Checks thresholds and rotates if needed. */
            bool CheckAndRotate(DatabaseError* err = nullptr);
            
            /** @brief Flushes all pending async writes. */
            bool Flush(DatabaseError* err = nullptr);
            /// @}

            // ========================================================================
            //                      CONFIGURATION & STATISTICS
            // ========================================================================

            /** @brief Returns current runtime statistics. */
            Statistics GetStatistics(DatabaseError* err = nullptr);
            
            /** @brief Resets statistics counters to zero. */
            void ResetStatistics();

            /** @brief Returns a copy of current configuration. */
            Config GetConfig() const;
            
            /** @brief Changes minimum log level threshold. */
            void SetMinLogLevel(LogLevel level);
            
            /** @brief Enables or disables async logging mode. */
            void SetAsyncLogging(bool enabled);

            // ========================================================================
            //                      UTILITY FUNCTIONS
            // ========================================================================

            /// @name Enum Conversion Utilities
            /// @{
            
            /** @brief Converts LogLevel to string (e.g., "ERROR"). */
            static std::wstring LogLevelToString(LogLevel level);
            
            /** @brief Parses string to LogLevel. */
            static LogLevel StringToLogLevel(std::wstring_view str);

            /** @brief Converts LogCategory to string (e.g., "Scanner"). */
            static std::wstring LogCategoryToString(LogCategory category);
            
            /** @brief Parses string to LogCategory. */
            static LogCategory StringToLogCategory(std::wstring_view str);
            /// @}

            /**
             * @brief Formats a log entry as human-readable string.
             * @param entry Entry to format.
             * @param includeMetadata Include metadata JSON in output.
             * @return Formatted string: "[Time] [Level] [Category] Source: Message"
             */
            static std::wstring FormatLogEntry(const LogEntry& entry, bool includeMetadata = false);

            /// @name Export Functions
            /// @{
            
            /** @brief Exports logs to plain text file. */
            bool ExportToFile(std::wstring_view filePath,
                            const QueryFilter* filter = nullptr,
                            DatabaseError* err = nullptr);

            /** @brief Exports logs to JSON format. */
            bool ExportToJSON(std::wstring_view filePath,
                            const QueryFilter* filter = nullptr,
                            DatabaseError* err = nullptr);

            /** @brief Exports logs to CSV format. */
            bool ExportToCSV(std::wstring_view filePath,
                           const QueryFilter* filter = nullptr,
                           DatabaseError* err = nullptr);
            /// @}

            // ========================================================================
            //                      MAINTENANCE OPERATIONS
            // ========================================================================

            /** @brief Reclaims disk space (SQLite VACUUM). */
            bool Vacuum(DatabaseError* err = nullptr);
            
            /** @brief Verifies database integrity. */
            bool CheckIntegrity(DatabaseError* err = nullptr);
            
            /** @brief Optimizes database performance (ANALYZE + cleanup). */
            bool Optimize(DatabaseError* err = nullptr);
            
            /** @brief Drops and recreates all indices. */
            bool RebuildIndices(DatabaseError* err = nullptr);

        private:
            // ========================================================================
            //                      PRIVATE MEMBERS
            // ========================================================================

            LogDB();   ///< Private constructor (singleton)
            ~LogDB();  ///< Private destructor

            LogDB(const LogDB&) = delete;             ///< No copy
            LogDB& operator=(const LogDB&) = delete;  ///< No copy assignment

            // ========================================================================
            //                      INTERNAL OPERATIONS
            // ========================================================================

            /// @name Schema Management
            /// @{
            bool createSchema(DatabaseError* err);      ///< Creates tables and indices
            bool upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err);  ///< Schema migration
            /// @}

            /// @name Database Operations
            /// @{
            int64_t dbInsertEntry(const LogEntry& entry, DatabaseError* err);       ///< Insert single entry
            bool dbUpdateEntry(const LogEntry& entry, DatabaseError* err);          ///< Update existing entry
            bool dbDeleteEntry(int64_t id, DatabaseError* err);                     ///< Delete by ID
            std::optional<LogEntry> dbSelectEntry(int64_t id, DatabaseError* err);  ///< Select by ID
            std::vector<LogEntry> dbSelectEntries(std::string_view sql,             ///< Execute query
                                                 const std::vector<std::string>& params,
                                                 DatabaseError* err);
            /// @}

            /// @name Query Builders
            /// @{
            std::string buildQuerySQL(const QueryFilter& filter, std::vector<std::string>& outParams);   ///< Build SELECT
            std::string buildCountSQL(const QueryFilter& filter, std::vector<std::string>& outParams);   ///< Build COUNT
            /// @}

            /// @name Batch Processing
            /// @{
            void batchWriteThread();                                ///< Background thread function
            void enqueuePendingWrite(const LogEntry& entry);        ///< Add to async queue
            bool processPendingWrites(DatabaseError* err);          ///< Process queue batch
            /// @}

            /// @name Rotation Helpers
            /// @{
            bool shouldRotate(DatabaseError* err);                  ///< Check rotation thresholds
            bool performRotation(DatabaseError* err);               ///< Execute rotation
            bool createArchive(std::wstring_view archivePath,       ///< Create archive file
                             std::chrono::system_clock::time_point beforeTimestamp,
                             DatabaseError* err);
            void cleanupOldArchives();                              ///< Remove excess archives
            /// @}

            /// @name Statistics Helpers
            /// @{
            void updateStatistics(const LogEntry& entry);           ///< Incremental update
            void recalculateStatistics(DatabaseError* err);         ///< Full recalculation
            /// @}

            /// @name Utility Helpers
            /// @{
            LogEntry rowToLogEntry(QueryResult& result);            ///< Row to struct conversion
            static std::string timePointToString(std::chrono::system_clock::time_point tp);    ///< Time to ISO 8601
            static std::chrono::system_clock::time_point stringToTimePoint(std::string_view str);  ///< ISO 8601 to time
            /// @}

            // ========================================================================
            //                      STATE MEMBERS
            // ========================================================================

            std::atomic<bool> m_initialized{ false };   ///< Initialization flag
            Config m_config;
            mutable std::shared_mutex m_configMutex;   ///< Config read/write mutex

            /// @name Batch Writing State
            /// @{
            
            /**
             * @struct PendingLogEntry
             * @brief Entry queued for async batch write.
             */
            struct PendingLogEntry {
                LogEntry entry;                                    ///< The log entry data
                std::chrono::steady_clock::time_point queuedTime;  ///< When entry was queued
            };

            std::mutex m_batchMutex;                    ///< Protects pending queue
            std::condition_variable m_batchCV;          ///< Batch thread signal
            std::vector<PendingLogEntry> m_pendingWrites;  ///< Pending write queue
            std::thread m_batchThread;                  ///< Background batch thread
            std::atomic<bool> m_shutdownBatch{ false }; ///< Shutdown signal
            /// @}

            /// @name Statistics State
            /// @{
            mutable std::mutex m_statsMutex;    ///< Protects statistics
            Statistics m_stats;                  ///< Runtime statistics
            /// @}

            /// @name Cached System Information
            /// @{
            std::wstring m_machineName;         ///< Local machine name
            std::wstring m_userName;            ///< Current user name
            /// @}
        };

        // ============================================================================
        //                      PerformanceLogger CLASS
        // ============================================================================

        /**
         * @class PerformanceLogger
         * @brief RAII helper for automatic performance logging.
         * 
         * @details Measures elapsed time from construction to destruction
         * and logs the result via LogDB::LogPerformance(). Ideal for
         * timing function calls, operations, or code blocks.
         * 
         * Features:
         * - Automatic start time capture on construction
         * - Automatic duration calculation and logging on destruction
         * - Support for custom key-value details
         * - Success/failure tracking
         * - Cancellable (no log on destruction if cancelled)
         * 
         * @code
         * void ProcessFiles(const std::vector<std::wstring>& files) {
         *     PerformanceLogger perf(L"FileProcessor", L"ProcessFiles");
         *     perf.AddDetail(L"FileCount", std::to_wstring(files.size()));
         *     
         *     try {
         *         for (const auto& file : files) {
         *             // process each file...
         *         }
         *         perf.SetSuccess(true);
         *     }
         *     catch (...) {
         *         perf.SetSuccess(false);
         *         throw;
         *     }
         * }  // Logs: "ProcessFiles - 1234ms | FileCount=150; Success=true"
         * @endcode
         * 
         * @note Non-copyable to prevent duplicate timing logs.
         */
        class PerformanceLogger {
        public:
            /**
             * @brief Constructs a PerformanceLogger and starts timing.
             * @param source Module/component name.
             * @param operation Name of the operation being timed.
             * @param minLevel Minimum level to actually log (default: Debug).
             */
            explicit PerformanceLogger(std::wstring source,
                                      std::wstring operation,
                                      LogDB::LogLevel minLevel = LogDB::LogLevel::Debug);
            
            /**
             * @brief Destructor - logs the performance entry (unless cancelled).
             */
            ~PerformanceLogger();

            PerformanceLogger(const PerformanceLogger&) = delete;             ///< No copy
            PerformanceLogger& operator=(const PerformanceLogger&) = delete;  ///< No copy assignment

            /**
             * @brief Adds a key-value detail to the log.
             * @param key Detail name.
             * @param value Detail value.
             */
            void AddDetail(std::wstring_view key, std::wstring_view value);
            
            /**
             * @brief Sets the success flag and adds it as a detail.
             * @param success true if operation succeeded.
             */
            void SetSuccess(bool success);
            
            /**
             * @brief Cancels logging - destructor will not log anything.
             */
            void Cancel();

        private:
            std::wstring m_source;                               ///< Source component
            std::wstring m_operation;                            ///< Operation name
            LogDB::LogLevel m_minLevel;                          ///< Minimum level threshold
            std::chrono::steady_clock::time_point m_startTime;   ///< Start timestamp
            std::wstring m_details;                              ///< Accumulated details
            bool m_cancelled = false;                            ///< Cancellation flag
            bool m_success = true;                               ///< Success flag
        };

    } // namespace Database
} // namespace ShadowStrike