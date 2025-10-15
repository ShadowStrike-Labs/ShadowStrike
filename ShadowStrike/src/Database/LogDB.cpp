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

        namespace {
            // Database schema version
            constexpr int LOGDB_SCHEMA_VERSION = 1;

            // SQL statements
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

            constexpr const char* SQL_CREATE_INDICES = R"(
                CREATE INDEX IF NOT EXISTS idx_log_timestamp ON log_entries(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_log_level ON log_entries(level);
                CREATE INDEX IF NOT EXISTS idx_log_category ON log_entries(category);
                CREATE INDEX IF NOT EXISTS idx_log_source ON log_entries(source);
                CREATE INDEX IF NOT EXISTS idx_log_process ON log_entries(process_id);
                CREATE INDEX IF NOT EXISTS idx_log_error ON log_entries(error_code) WHERE error_code != 0;
                CREATE INDEX IF NOT EXISTS idx_log_composite ON log_entries(level, category, timestamp DESC);
            )";

            constexpr const char* SQL_CREATE_FTS_TABLE = R"(
                CREATE VIRTUAL TABLE IF NOT EXISTS log_fts USING fts5(
                    source, message, details, 
                    content='log_entries',
                    content_rowid='id'
                );
            )";

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

            constexpr const char* SQL_INSERT_ENTRY = R"(
                INSERT INTO log_entries (
                    timestamp, level, category, source, message, details,
                    process_id, thread_id, user_name, machine_name, metadata,
                    error_code, error_context, duration_ms, file_path, line_number, function_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            )";

            constexpr const char* SQL_SELECT_ENTRY = R"(
                SELECT * FROM log_entries WHERE id = ?
            )";

            constexpr const char* SQL_DELETE_ENTRY = R"(
                DELETE FROM log_entries WHERE id = ?
            )";

            constexpr const char* SQL_DELETE_BEFORE = R"(
                DELETE FROM log_entries WHERE timestamp < ?
            )";

            constexpr const char* SQL_DELETE_BY_LEVEL = R"(
                DELETE FROM log_entries WHERE level = ?
            )";

            constexpr const char* SQL_DELETE_ALL = R"(
                DELETE FROM log_entries
            )";

            constexpr const char* SQL_COUNT_ALL = R"(
                SELECT COUNT(*) FROM log_entries
            )";

            constexpr const char* SQL_GET_OLDEST = R"(
                SELECT timestamp FROM log_entries ORDER BY timestamp ASC LIMIT 1
            )";

            constexpr const char* SQL_GET_NEWEST = R"(
                SELECT timestamp FROM log_entries ORDER BY timestamp DESC LIMIT 1
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
        }

        // ============================================================================
        // LogDB Implementation
        // ============================================================================

        LogDB& LogDB::Instance() {
            static LogDB instance;
            return instance;
        }

        LogDB::LogDB() {
            m_machineName = GetMachineName();
            m_userName = GetCurrentUserName();
        }

        LogDB::~LogDB() {
            Shutdown();
        }

        bool LogDB::Initialize(const Config& config, DatabaseError* err) {
            if (m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"LogDB", L"Already initialized");
                return true;
            }

            SS_LOG_INFO(L"LogDB", L"Initializing LogDB...");

            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config = config;

            // Initialize DatabaseManager
            DatabaseConfig dbConfig;
            dbConfig.databasePath = m_config.dbPath;
            dbConfig.enableWAL = m_config.enableWAL;
            dbConfig.cacheSizeKB = m_config.dbCacheSizeKB;
            dbConfig.maxConnections = m_config.maxConnections;
            dbConfig.minConnections = 2;
            dbConfig.autoBackup = false;  // We handle rotation manually

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
            if (m_config.asyncLogging) {
                m_shutdownBatch.store(false, std::memory_order_release);
                m_batchThread = std::thread(&LogDB::batchWriteThread, this);
            }

            // Initialize statistics
            recalculateStatistics(err);

            m_initialized.store(true, std::memory_order_release);

            SS_LOG_INFO(L"LogDB", L"LogDB initialized successfully");
            
            // Log initialization event
            LogInfo(L"LogDB", L"Database logging system initialized");

            return true;
        }

        void LogDB::Shutdown() {
            if (!m_initialized.load(std::memory_order_acquire)) {
                return;
            }

            SS_LOG_INFO(L"LogDB", L"Shutting down LogDB...");

            // Log shutdown event
            LogInfo(L"LogDB", L"Database logging system shutting down");

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

            m_initialized.store(false, std::memory_order_release);

            SS_LOG_INFO(L"LogDB", L"LogDB shut down");
        }

        // ============================================================================
        // Logging Operations
        // ============================================================================

        int64_t LogDB::Log(LogLevel level,
                          LogCategory category,
                          std::wstring_view source,
                          std::wstring_view message,
                          DatabaseError* err)
        {
            if (level < m_config.minLogLevel) {
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

            if (m_config.asyncLogging) {
                enqueuePendingWrite(entry);
                return -1;  // ID not available yet for async
            } else {
                return dbInsertEntry(entry, err);
            }
        }

        int64_t LogDB::LogDetailed(const LogEntry& entry, DatabaseError* err) {
            if (entry.level < m_config.minLogLevel) {
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

            if (m_config.asyncLogging) {
                enqueuePendingWrite(completeEntry);
                return -1;
            } else {
                return dbInsertEntry(completeEntry, err);
            }
        }

        int64_t LogDB::LogTrace(std::wstring_view source, std::wstring_view message) {
            return Log(LogLevel::Trace, LogCategory::General, source, message);
        }

        int64_t LogDB::LogDebug(std::wstring_view source, std::wstring_view message) {
            return Log(LogLevel::Debug, LogCategory::General, source, message);
        }

        int64_t LogDB::LogInfo(std::wstring_view source, std::wstring_view message) {
            return Log(LogLevel::Info, LogCategory::General, source, message);
        }

        int64_t LogDB::LogWarn(std::wstring_view source, std::wstring_view message) {
            return Log(LogLevel::Warn, LogCategory::General, source, message);
        }

        int64_t LogDB::LogError(std::wstring_view source, std::wstring_view message) {
            return Log(LogLevel::Error, LogCategory::General, source, message);
        }

        int64_t LogDB::LogFatal(std::wstring_view source, std::wstring_view message) {
            return Log(LogLevel::Fatal, LogCategory::General, source, message);
        }

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

        bool LogDB::LogBatch(const std::vector<LogEntry>& entries, DatabaseError* err) {
            if (entries.empty()) return true;

            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);
            
            if (!trans || !trans->IsActive()) {
                return false;
            }

            for (const auto& entry : entries) {
                if (entry.level < m_config.minLogLevel) {
                    continue;
                }

                if (dbInsertEntry(entry, err) < 0) {
                    trans->Rollback(err);
                    return false;
                }
            }

            if (!trans->Commit(err)) {
                return false;
            }

            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.totalWrites += entries.size();

            return true;
        }

        // ============================================================================
        // Query Operations
        // ============================================================================

        std::optional<LogDB::LogEntry> LogDB::GetEntry(int64_t id, DatabaseError* err) {
            return dbSelectEntry(id, err);
        }

        std::vector<LogDB::LogEntry> LogDB::Query(const QueryFilter& filter, DatabaseError* err) {
            std::vector<std::string> params;
            std::string sql = buildQuerySQL(filter, params);

            return dbSelectEntries(sql, params, err);
        }

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

        std::vector<LogDB::LogEntry> LogDB::SearchText(std::wstring_view searchText,
                                                       bool useFullText,
                                                       size_t maxCount,
                                                       DatabaseError* err)
        {
            QueryFilter filter;
            
            if (useFullText && m_config.enableFullTextSearch) {
                filter.fullTextSearch = searchText;
            } else {
                std::wstring pattern = L"%";
                pattern += searchText;
                pattern += L"%";
                filter.messagePattern = pattern;
            }
            
            filter.maxResults = maxCount;
            filter.sortDescending = true;

            return Query(filter, err);
        }

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
        // Management Operations
        // ============================================================================

        bool LogDB::DeleteEntry(int64_t id, DatabaseError* err) {
            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_DELETE_ENTRY, err, id);

            if (success) {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalDeletes++;
            }

            return success;
        }

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

        bool LogDB::DeleteByLevel(LogLevel level, DatabaseError* err) {
            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_DELETE_BY_LEVEL, err, static_cast<int>(level));

            if (success) {
                recalculateStatistics(err);
            }

            return success;
        }

        bool LogDB::DeleteAll(DatabaseError* err) {
            bool success = DatabaseManager::Instance().Execute(SQL_DELETE_ALL, err);

            if (success) {
                ResetStatistics();
            }

            return success;
        }

        bool LogDB::ArchiveLogs(std::wstring_view archivePath,
                               std::chrono::system_clock::time_point beforeTimestamp,
                               DatabaseError* err)
        {
            SS_LOG_INFO(L"LogDB", L"Archiving logs to: %ls", archivePath.data());

            return createArchive(archivePath, beforeTimestamp, err);
        }

        bool LogDB::RestoreLogs(std::wstring_view archivePath, DatabaseError* err) {
            SS_LOG_INFO(L"LogDB", L"Restoring logs from: %ls", archivePath.data());

            return DatabaseManager::Instance().RestoreFromFile(archivePath, err);
        }

        bool LogDB::RotateLogs(DatabaseError* err) {
            SS_LOG_INFO(L"LogDB", L"Rotating logs...");

            return performRotation(err);
        }

        bool LogDB::CheckAndRotate(DatabaseError* err) {
            if (!m_config.enableRotation) {
                return true;
            }

            if (shouldRotate(err)) {
                return performRotation(err);
            }

            return true;
        }

        bool LogDB::Flush(DatabaseError* err) {
            if (!m_config.asyncLogging) {
                return true;
            }

            std::lock_guard<std::mutex> lock(m_batchMutex);

            if (m_pendingWrites.empty()) {
                return true;
            }

            return processPendingWrites(err);
        }

        // ============================================================================
        // Statistics & Configuration
        // ============================================================================

        LogDB::Statistics LogDB::GetStatistics(DatabaseError* err) {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            return m_stats;
        }

        void LogDB::ResetStatistics() {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats = Statistics{};
        }

        LogDB::Config LogDB::GetConfig() const {
            std::shared_lock<std::shared_mutex> lock(m_configMutex);
            return m_config;
        }

        void LogDB::SetMinLogLevel(LogLevel level) {
            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config.minLogLevel = level;
        }

        void LogDB::SetAsyncLogging(bool enabled) {
            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config.asyncLogging = enabled;
        }

        // ============================================================================
        // Utility Functions (Static)
        // ============================================================================

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

        LogDB::LogLevel LogDB::StringToLogLevel(std::wstring_view str) {
            if (str == L"TRACE") return LogLevel::Trace;
            if (str == L"DEBUG") return LogLevel::Debug;
            if (str == L"INFO") return LogLevel::Info;
            if (str == L"WARN") return LogLevel::Warn;
            if (str == L"ERROR") return LogLevel::Error;
            if (str == L"FATAL") return LogLevel::Fatal;
            return LogLevel::Info;
        }

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
        // Maintenance Operations
        // ============================================================================

        bool LogDB::Vacuum(DatabaseError* err) {
            SS_LOG_INFO(L"LogDB", L"Running VACUUM...");
            return DatabaseManager::Instance().Vacuum(err);
        }

        bool LogDB::CheckIntegrity(DatabaseError* err) {
            SS_LOG_INFO(L"LogDB", L"Checking integrity...");
            std::vector<std::wstring> issues;
            return DatabaseManager::Instance().CheckIntegrity(issues, err);
        }

        bool LogDB::Optimize(DatabaseError* err) {
            SS_LOG_INFO(L"LogDB", L"Optimizing database...");
            
            // Delete old entries if configured
            if (m_config.enableRotation) {
                auto cutoffTime = std::chrono::system_clock::now() - m_config.maxLogAge;
                DeleteBefore(cutoffTime, err);
            }

            return DatabaseManager::Instance().Optimize(err);
        }

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
        // Internal Operations(NEW)
        // ============================================================================

        bool LogDB::createSchema(DatabaseError* err) {
            // Create main table
            if (!DatabaseManager::Instance().Execute(SQL_CREATE_LOGS_TABLE, err)) {
                return false;
            }

            // Create indices
            if (!DatabaseManager::Instance().Execute(SQL_CREATE_INDICES, err)) {
                return false;
            }

            // Create full-text search if enabled
            if (m_config.enableFullTextSearch) {
                if (!DatabaseManager::Instance().Execute(SQL_CREATE_FTS_TABLE, err)) {
                    SS_LOG_WARN(L"LogDB", L"Failed to create FTS table, continuing without it");
                }
                
                if (!DatabaseManager::Instance().Execute(SQL_CREATE_FTS_TRIGGERS, err)) {
                    SS_LOG_WARN(L"LogDB", L"Failed to create FTS triggers");
                }
            }

            SS_LOG_INFO(L"LogDB", L"Schema created successfully");
            return true;
        }

        bool LogDB::upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err) {
            // Future schema migrations
            return true;
        }

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

                updateStatistics(entry);

                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalWrites++;
                m_stats.avgWriteTime = std::chrono::milliseconds(
                    (m_stats.avgWriteTime.count() + duration.count()) / 2
                );

                return id;
            }

            return -1;
        }

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

        std::vector<LogDB::LogEntry> LogDB::dbSelectEntries(std::string_view sql,
                                                            const std::vector<std::string>& params,
                                                            DatabaseError* err)
        {
            std::vector<LogEntry> entries;

            // This is simplified - in reality you'd need a variadic approach
            // or build a prepared statement dynamically
            auto result = DatabaseManager::Instance().Query(sql, err);

            while (result.Next()) {
                entries.push_back(rowToLogEntry(result));
            }

            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.totalReads++;

            return entries;
        }

        std::string LogDB::buildQuerySQL(const QueryFilter& filter, std::vector<std::string>& outParams) {
            std::ostringstream sql;
            sql << "SELECT * FROM log_entries WHERE 1=1";

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
            if (filter.fullTextSearch && m_config.enableFullTextSearch) {
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

        void LogDB::batchWriteThread() {
            SS_LOG_INFO(L"LogDB", L"Batch write thread started");

            while (!m_shutdownBatch.load(std::memory_order_acquire)) {
                std::unique_lock<std::mutex> lock(m_batchMutex);

                m_batchCV.wait_for(lock, m_config.batchFlushInterval, [this]() {
                    return m_shutdownBatch.load(std::memory_order_acquire) ||
                           m_pendingWrites.size() >= m_config.batchSize;
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

        void LogDB::enqueuePendingWrite(const LogEntry& entry) {
            std::lock_guard<std::mutex> lock(m_batchMutex);

            PendingLogEntry pending;
            pending.entry = entry;
            pending.queuedTime = std::chrono::steady_clock::now();

            m_pendingWrites.push_back(std::move(pending));

            if (m_pendingWrites.size() >= m_config.batchSize) {
                m_batchCV.notify_one();
            }
        }

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

        bool LogDB::shouldRotate(DatabaseError* err) {
            auto stats = DatabaseManager::Instance().GetStats(err);
            
            size_t currentSizeMB = stats.totalSize / (1024 * 1024);
            
            if (currentSizeMB >= m_config.maxLogSizeMB) {
                return true;
            }

            // Check age
            auto result = DatabaseManager::Instance().Query(SQL_GET_OLDEST, err);
            if (result.Next()) {
                std::string oldestStr = result.GetString(0);
                auto oldest = stringToTimePoint(oldestStr);
                auto age = std::chrono::system_clock::now() - oldest;
                
                if (age >= m_config.maxLogAge) {
                    return true;
                }
            }

            return false;
        }

        bool LogDB::performRotation(DatabaseError* err) {
            // Create archive
            auto now = std::chrono::system_clock::now();
            auto cutoffTime = now - m_config.maxLogAge;

            std::wstring archivePath = m_config.archivePath;
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

        void LogDB::cleanupOldArchives() {
            // Find and delete archives exceeding maxArchivedLogs
            std::filesystem::path archiveDir(m_config.archivePath);
            
            if (!std::filesystem::exists(archiveDir)) {
                return;
            }

            std::vector<std::filesystem::path> archives;
            
            for (const auto& entry : std::filesystem::directory_iterator(archiveDir)) {
                if (entry.is_regular_file() && entry.path().extension() == L".db") {
                    archives.push_back(entry.path());
                }
            }

            if (archives.size() <= m_config.maxArchivedLogs) {
                return;
            }

            // Sort by modification time
            std::sort(archives.begin(), archives.end(), [](const auto& a, const auto& b) {
                return std::filesystem::last_write_time(a) < std::filesystem::last_write_time(b);
            });

            // Delete oldest
            size_t toDelete = archives.size() - m_config.maxArchivedLogs;
            for (size_t i = 0; i < toDelete; ++i) {
                std::error_code ec;
                std::filesystem::remove(archives[i], ec);
                if (!ec) {
                    SS_LOG_INFO(L"LogDB", L"Deleted old archive: %ls", archives[i].wstring().c_str());
                }
            }
        }

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
        // PerformanceLogger Implementation
        // ============================================================================

        PerformanceLogger::PerformanceLogger(std::wstring source,
                                            std::wstring operation,
                                            LogDB::LogLevel minLevel)
            : m_source(std::move(source))
            , m_operation(std::move(operation))
            , m_minLevel(minLevel)
            , m_startTime(std::chrono::steady_clock::now())
        {
        }

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

        void PerformanceLogger::AddDetail(std::wstring_view key, std::wstring_view value) {
            if (!m_details.empty()) {
                m_details += L"; ";
            }
            m_details += key;
            m_details += L"=";
            m_details += value;
        }

        void PerformanceLogger::SetSuccess(bool success) {
            m_success = success;
            AddDetail(L"Success", success ? L"true" : L"false");
        }

        void PerformanceLogger::Cancel() {
            m_cancelled = true;
        }

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