#pragma once

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
        // LogDB - Centralized Logging Database System
        // ============================================================================

        /**
         * @brief Persistent logging system with database storage and efficient querying.
         * 
         * Features:
         * - Multi-level logging (Trace, Debug, Info, Warn, Error, Fatal)
         * - Structured log entries with metadata
         * - Advanced filtering and search capabilities
         * - Log rotation and archival
         * - Performance-optimized batch writes
         * - Real-time log streaming
         * - Statistics and analytics
         * - Thread-safe operations
         */
        class LogDB {
        public:
            // ============================================================================
            // Types & Enums
            // ============================================================================

            enum class LogLevel : uint8_t {
                Trace = 0,
                Debug = 1,
                Info = 2,
                Warn = 3,
                Error = 4,
                Fatal = 5
            };

            enum class LogCategory : uint8_t {
                General = 0,
                System = 1,
                Security = 2,
                Network = 3,
                FileSystem = 4,
                Process = 5,
                Registry = 6,
                Service = 7,
                Driver = 8,
                Performance = 9,
                Database = 10,
                Scanner = 11,
                Quarantine = 12,
                Update = 13,
                Configuration = 14,
                UserInterface = 15,
                Custom = 255
            };

            struct LogEntry {
                int64_t id = 0;
                std::chrono::system_clock::time_point timestamp;
                LogLevel level = LogLevel::Info;
                LogCategory category = LogCategory::General;
                
                std::wstring source;            // Component/module name
                std::wstring message;           // Log message
                std::wstring details;           // Extended details (optional)
                
                uint32_t processId = 0;
                uint32_t threadId = 0;
                std::wstring userName;
                std::wstring machineName;
                
                // Structured metadata (JSON format)
                std::wstring metadata;
                
                // Error information
                uint32_t errorCode = 0;
                std::wstring errorContext;
                
                // Performance metrics
                int64_t durationMs = 0;         // Operation duration (if applicable)
                
                // File/location information
                std::wstring filePath;
                int lineNumber = 0;
                std::wstring functionName;
            };

            // ============================================================================
            // Configuration
            // ============================================================================

            struct Config {
                std::wstring dbPath = L"C:\\ProgramData\\ShadowStrike\\logs.db";
                
                // Database settings
                bool enableWAL = true;
                size_t dbCacheSizeKB = 20480;       // 20MB
                size_t maxConnections = 5;
                
                // Logging settings
                LogLevel minLogLevel = LogLevel::Info;
                bool logToConsole = false;
                bool logToFile = true;
                bool asyncLogging = true;
                
                // Rotation settings
                bool enableRotation = true;
                size_t maxLogSizeMB = 500;          // Rotate when DB exceeds this
                std::chrono::hours maxLogAge = std::chrono::hours(24 * 30);  // 30 days
                size_t maxArchivedLogs = 10;
                std::wstring archivePath = L"C:\\ProgramData\\ShadowStrike\\LogArchive";
                
                // Performance settings
                size_t batchSize = 100;             // Batch insert size
                std::chrono::milliseconds batchFlushInterval = std::chrono::seconds(5);
                
                // Indexing
                bool enableFullTextSearch = true;
                
                // Statistics
                bool enableStatistics = true;
            };

            struct QueryFilter {
                std::optional<LogLevel> minLevel;
                std::optional<LogLevel> maxLevel;
                std::optional<LogCategory> category;
                std::optional<std::chrono::system_clock::time_point> startTime;
                std::optional<std::chrono::system_clock::time_point> endTime;
                std::optional<std::wstring> sourcePattern;      // SQL LIKE pattern
                std::optional<std::wstring> messagePattern;     // SQL LIKE pattern
                std::optional<std::wstring> fullTextSearch;     // Full-text search query
                std::optional<uint32_t> processId;
                std::optional<uint32_t> threadId;
                std::optional<uint32_t> errorCode;
                size_t maxResults = 1000;
                bool sortDescending = true;                     // Newest first
            };

            struct Statistics {
                uint64_t totalEntries = 0;
                uint64_t entriesByLevel[6] = {};               // Per LogLevel
                uint64_t entriesByCategory[256] = {};          // Per LogCategory
                
                uint64_t totalWrites = 0;
                uint64_t totalReads = 0;
                uint64_t totalDeletes = 0;
                
                std::chrono::milliseconds avgWriteTime{};
                std::chrono::milliseconds avgReadTime{};
                
                size_t dbSizeBytes = 0;
                size_t indexSizeBytes = 0;
                
                std::chrono::system_clock::time_point oldestEntry;
                std::chrono::system_clock::time_point newestEntry;
                std::chrono::system_clock::time_point lastRotation;
                
                uint64_t rotationCount = 0;
                uint64_t archivedLogCount = 0;
            };

            // ============================================================================
            // Lifecycle
            // ============================================================================

            static LogDB& Instance();

            bool Initialize(const Config& config, DatabaseError* err = nullptr);
            void Shutdown();
            bool IsInitialized() const noexcept { return m_initialized.load(); }

            // ============================================================================
            // Logging Operations
            // ============================================================================

            // Basic logging
            int64_t Log(LogLevel level,
                       LogCategory category,
                       std::wstring_view source,
                       std::wstring_view message,
                       DatabaseError* err = nullptr);

            // Detailed logging
            int64_t LogDetailed(const LogEntry& entry, DatabaseError* err = nullptr);

            // Convenience methods
            int64_t LogTrace(std::wstring_view source, std::wstring_view message);
            int64_t LogDebug(std::wstring_view source, std::wstring_view message);
            int64_t LogInfo(std::wstring_view source, std::wstring_view message);
            int64_t LogWarn(std::wstring_view source, std::wstring_view message);
            int64_t LogError(std::wstring_view source, std::wstring_view message);
            int64_t LogFatal(std::wstring_view source, std::wstring_view message);

            // Error logging with code
            int64_t LogErrorWithCode(std::wstring_view source,
                                    std::wstring_view message,
                                    uint32_t errorCode,
                                    std::wstring_view errorContext = L"");

            // Performance logging
            int64_t LogPerformance(std::wstring_view source,
                                  std::wstring_view operation,
                                  int64_t durationMs,
                                  std::wstring_view details = L"");

            // Batch logging
            bool LogBatch(const std::vector<LogEntry>& entries, DatabaseError* err = nullptr);

            // ============================================================================
            // Query Operations
            // ============================================================================

            // Get single entry by ID
            std::optional<LogEntry> GetEntry(int64_t id, DatabaseError* err = nullptr);

            // Query with filters
            std::vector<LogEntry> Query(const QueryFilter& filter, DatabaseError* err = nullptr);

            // Get recent entries
            std::vector<LogEntry> GetRecent(size_t count = 100,
                                           LogLevel minLevel = LogLevel::Info,
                                           DatabaseError* err = nullptr);

            // Get entries by level
            std::vector<LogEntry> GetByLevel(LogLevel level,
                                            size_t maxCount = 1000,
                                            DatabaseError* err = nullptr);

            // Get entries by category
            std::vector<LogEntry> GetByCategory(LogCategory category,
                                               size_t maxCount = 1000,
                                               DatabaseError* err = nullptr);

            // Get entries by time range
            std::vector<LogEntry> GetByTimeRange(
                std::chrono::system_clock::time_point start,
                std::chrono::system_clock::time_point end,
                size_t maxCount = 1000,
                DatabaseError* err = nullptr);

            // Get entries by process
            std::vector<LogEntry> GetByProcess(uint32_t processId,
                                              size_t maxCount = 1000,
                                              DatabaseError* err = nullptr);

            // Search by text
            std::vector<LogEntry> SearchText(std::wstring_view searchText,
                                            bool useFullText = false,
                                            size_t maxCount = 1000,
                                            DatabaseError* err = nullptr);

            // Count entries
            int64_t CountEntries(const QueryFilter* filter = nullptr, DatabaseError* err = nullptr);

            // ============================================================================
            // Management Operations
            // ============================================================================

            // Delete entries
            bool DeleteEntry(int64_t id, DatabaseError* err = nullptr);
            bool DeleteBefore(std::chrono::system_clock::time_point timestamp,
                            DatabaseError* err = nullptr);
            bool DeleteByLevel(LogLevel level, DatabaseError* err = nullptr);
            bool DeleteAll(DatabaseError* err = nullptr);

            // Archive operations
            bool ArchiveLogs(std::wstring_view archivePath,
                           std::chrono::system_clock::time_point beforeTimestamp,
                           DatabaseError* err = nullptr);

            bool RestoreLogs(std::wstring_view archivePath, DatabaseError* err = nullptr);

            // Rotation
            bool RotateLogs(DatabaseError* err = nullptr);
            bool CheckAndRotate(DatabaseError* err = nullptr);

            // Flush pending writes
            bool Flush(DatabaseError* err = nullptr);

            // ============================================================================
            // Configuration & Statistics
            // ============================================================================

            Statistics GetStatistics(DatabaseError* err = nullptr);
            void ResetStatistics();

            Config GetConfig() const;
            void SetMinLogLevel(LogLevel level);
            void SetAsyncLogging(bool enabled);

            // ============================================================================
            // Utility Functions
            // ============================================================================

            static std::wstring LogLevelToString(LogLevel level);
            static LogLevel StringToLogLevel(std::wstring_view str);

            static std::wstring LogCategoryToString(LogCategory category);
            static LogCategory StringToLogCategory(std::wstring_view str);

            static std::wstring FormatLogEntry(const LogEntry& entry, bool includeMetadata = false);

            // Export logs
            bool ExportToFile(std::wstring_view filePath,
                            const QueryFilter* filter = nullptr,
                            DatabaseError* err = nullptr);

            bool ExportToJSON(std::wstring_view filePath,
                            const QueryFilter* filter = nullptr,
                            DatabaseError* err = nullptr);

            bool ExportToCSV(std::wstring_view filePath,
                           const QueryFilter* filter = nullptr,
                           DatabaseError* err = nullptr);

            // ============================================================================
            // Maintenance
            // ============================================================================

            bool Vacuum(DatabaseError* err = nullptr);
            bool CheckIntegrity(DatabaseError* err = nullptr);
            bool Optimize(DatabaseError* err = nullptr);
            bool RebuildIndices(DatabaseError* err = nullptr);

        private:
            LogDB();
            ~LogDB();

            LogDB(const LogDB&) = delete;
            LogDB& operator=(const LogDB&) = delete;

            // ============================================================================
            // Internal Operations
            // ============================================================================

            // Schema management
            bool createSchema(DatabaseError* err);
            bool upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err);

            // Database operations
            int64_t dbInsertEntry(const LogEntry& entry, DatabaseError* err);
            bool dbUpdateEntry(const LogEntry& entry, DatabaseError* err);
            bool dbDeleteEntry(int64_t id, DatabaseError* err);
            std::optional<LogEntry> dbSelectEntry(int64_t id, DatabaseError* err);
            std::vector<LogEntry> dbSelectEntries(std::string_view sql,
                                                 const std::vector<std::string>& params,
                                                 DatabaseError* err);

            // Query builders
            std::string buildQuerySQL(const QueryFilter& filter, std::vector<std::string>& outParams);
            std::string buildCountSQL(const QueryFilter& filter, std::vector<std::string>& outParams);

            // Batch processing
            void batchWriteThread();
            void enqueuePendingWrite(const LogEntry& entry);
            bool processPendingWrites(DatabaseError* err);

            // Rotation helpers
            bool shouldRotate(DatabaseError* err);
            bool performRotation(DatabaseError* err);
            bool createArchive(std::wstring_view archivePath,
                             std::chrono::system_clock::time_point beforeTimestamp,
                             DatabaseError* err);
            void cleanupOldArchives();

            // Statistics helpers
            void updateStatistics(const LogEntry& entry);
            void recalculateStatistics(DatabaseError* err);

            // Utility helpers
            LogEntry rowToLogEntry(QueryResult& result);
            static std::string timePointToString(std::chrono::system_clock::time_point tp);
            static std::chrono::system_clock::time_point stringToTimePoint(std::string_view str);

            // ============================================================================
            // State
            // ============================================================================

            std::atomic<bool> m_initialized{ false };
            Config m_config;
            mutable std::shared_mutex m_configMutex;

            // Batch writing
            struct PendingLogEntry {
                LogEntry entry;
                std::chrono::steady_clock::time_point queuedTime;
            };

            std::mutex m_batchMutex;
            std::condition_variable m_batchCV;
            std::vector<PendingLogEntry> m_pendingWrites;
            std::thread m_batchThread;
            std::atomic<bool> m_shutdownBatch{ false };

            // Statistics
            mutable std::mutex m_statsMutex;
            Statistics m_stats;

            // System information (cached)
            std::wstring m_machineName;
            std::wstring m_userName;
        };

        // ============================================================================
        // RAII Helper for Performance Logging
        // ============================================================================

        class PerformanceLogger {
        public:
            explicit PerformanceLogger(std::wstring source,
                                      std::wstring operation,
                                      LogDB::LogLevel minLevel = LogDB::LogLevel::Debug);
            ~PerformanceLogger();

            PerformanceLogger(const PerformanceLogger&) = delete;
            PerformanceLogger& operator=(const PerformanceLogger&) = delete;

            void AddDetail(std::wstring_view key, std::wstring_view value);
            void SetSuccess(bool success);
            void Cancel();

        private:
            std::wstring m_source;
            std::wstring m_operation;
            LogDB::LogLevel m_minLevel;
            std::chrono::steady_clock::time_point m_startTime;
            std::wstring m_details;
            bool m_cancelled = false;
            bool m_success = true;
        };

    } // namespace Database
} // namespace ShadowStrike