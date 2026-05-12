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
 * @copyright (C) 2026 ShadowStrike Security
 * 
 * @see LogDB.hpp for class declaration
 * @see DatabaseManager.hpp for underlying storage
 * @see PerformanceLogger for RAII timing helper
 */

#include "pch.h"
#include "LogDB.hpp"
#include "../Utils/FileUtils.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <regex>
#include <cstring>

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

            // ========================================================================
            //                      JSON SECURITY HELPERS
            // ========================================================================

            /**
             * @brief Escapes special characters in a wide string for safe JSON string output.
             * 
             * @param input The wide string to escape.
             * @return Escaped wide string safe for JSON string literals.
             * 
             * @details Escapes the following characters per RFC 8259:
             * - Backslash (\) -> \\
             * - Double quote (") -> \"
             * - Backspace (0x08) -> \b
             * - Form feed (0x0C) -> \f
             * - Newline (0x0A) -> \n
             * - Carriage return (0x0D) -> \r
             * - Tab (0x09) -> \t
             * - Other control characters (0x00-0x1F) -> \uXXXX
             * 
             * @security Prevents JSON injection by properly escaping all special characters.
             */
            [[nodiscard]] std::wstring EscapeJsonString(std::wstring_view input) noexcept {
                std::wstring result;
                result.reserve(input.size() + input.size() / 8);  // Extra space for escapes
                
                for (const wchar_t c : input) {
                    switch (c) {
                        case L'\\': result += L"\\\\"; break;
                        case L'"':  result += L"\\\""; break;
                        case L'\b': result += L"\\b";  break;
                        case L'\f': result += L"\\f";  break;
                        case L'\n': result += L"\\n";  break;
                        case L'\r': result += L"\\r";  break;
                        case L'\t': result += L"\\t";  break;
                        default:
                            if (c < 0x20) {
                                // Escape control characters as Unicode escape sequence
                                wchar_t buf[7];
                                _snwprintf_s(buf, _TRUNCATE, L"\\u%04x", static_cast<unsigned int>(c));
                                result += buf;
                            }
                            else {
                                result += c;
                            }
                            break;
                    }
                }
                return result;
            }

            // ========================================================================
            //                      CSV SECURITY HELPERS
            // ========================================================================

            /**
             * @brief Sanitizes a wide string field for CSV export to prevent formula injection.
             * 
             * @param field The field value to sanitize.
             * @return Sanitized wide string safe for CSV export.
             * 
             * @details CSV Formula Injection occurs when a field begins with characters
             * that spreadsheet applications interpret as formula indicators.
             * 
             * Trigger characters: =, @, +, -, tab (\t), carriage return (\r)
             * 
             * Prevention: Prepends a single quote (') to force text interpretation.
             * 
             * @see https://owasp.org/www-community/attacks/CSV_Injection
             */
            [[nodiscard]] std::wstring SanitizeCsvFieldW(std::wstring_view field) noexcept {
                if (field.empty()) {
                    return std::wstring();
                }
                
                const wchar_t firstChar = field.front();
                const bool needsSanitization = (firstChar == L'=' || 
                                                 firstChar == L'@' || 
                                                 firstChar == L'+' || 
                                                 firstChar == L'-' ||
                                                 firstChar == L'\t' ||
                                                 firstChar == L'\r');
                
                if (needsSanitization) {
                    std::wstring result;
                    result.reserve(field.size() + 1);
                    result += L'\'';
                    result += field;
                    return result;
                }
                
                return std::wstring(field);
            }

            // ========================================================================
            //                      HARDENING CONSTANTS & HELPERS
            // ========================================================================

            /**
             * @brief Per-field maximum length (UTF-16 code units) accepted at insert.
             *
             * @details Caps DoS-via-large-string attacks and bounds storage cost.
             * Fields exceeding the cap are truncated with an ellipsis marker.
             */
            constexpr size_t LOGDB_MAX_SOURCE_LEN     = 256;
            constexpr size_t LOGDB_MAX_MESSAGE_LEN    = 8192;
            constexpr size_t LOGDB_MAX_DETAILS_LEN    = 16384;
            constexpr size_t LOGDB_MAX_METADATA_LEN   = 16384;
            constexpr size_t LOGDB_MAX_CONTEXT_LEN    = 4096;
            constexpr size_t LOGDB_MAX_PATH_LEN       = 1024;
            constexpr size_t LOGDB_MAX_FUNCNAME_LEN   = 512;
            constexpr size_t LOGDB_MAX_FTS_QUERY_LEN  = 1024;

            /// Hard caps for query and async queue sizing.
            constexpr size_t LOGDB_MAX_QUERY_RESULTS  = 100000;
            constexpr size_t LOGDB_MAX_PENDING_WRITES = 100000;
            constexpr size_t LOGDB_MAX_EXPORT_ENTRIES = 1000000;

            /// Archive filename prefix used by performRotation; cleanup is gated to this prefix.
            constexpr const wchar_t* LOGDB_ARCHIVE_PREFIX = L"logs_archive_";

            /**
             * @brief Clamps a wide string to a maximum length, appending an ellipsis marker.
             *
             * @param s Input string.
             * @param maxLen Maximum length in wide code units (must be >= 4).
             * @return Possibly-truncated copy of @p s.
             *
             * @security Bounds memory consumption of attacker-controllable log fields.
             */
            [[nodiscard]] std::wstring ClampField(std::wstring_view s, size_t maxLen) {
                if (s.size() <= maxLen) {
                    return std::wstring(s);
                }
                if (maxLen <= 4) {
                    return std::wstring(s.substr(0, maxLen));
                }
                std::wstring out;
                out.reserve(maxLen);
                out.assign(s.data(), maxLen - 4);
                out.append(L"...");
                return out;
            }

            /**
             * @brief Strips control characters (CR/LF/ESC/etc.) from a wide string for
             *        safe rendering on log-export and text/UI surfaces.
             *
             * @details Replaces every code unit in U+0000..U+001F (except TAB) and U+007F
             * with a single space. The DB still stores the raw text; sanitization happens
             * only on outbound rendering paths to prevent log-injection (CRLF forgery,
             * ANSI escape smuggling) of attacker-controllable fields.
             *
             * @security Mitigates CWE-117 (Improper Output Neutralization for Logs).
             */
            [[nodiscard]] std::wstring SanitizeForRender(std::wstring_view s) {
                std::wstring out;
                out.reserve(s.size());
                for (wchar_t c : s) {
                    if (c == L'\t') { out.push_back(c); continue; }
                    if (c < 0x20 || c == 0x7F) {
                        out.push_back(L' ');
                    } else {
                        out.push_back(c);
                    }
                }
                return out;
            }

            /**
             * @brief Redacts well-known secret patterns from arbitrary text on export.
             *
             * @details Pattern-based, conservative pass that masks the value half of
             * common credential constructions (password=, api_key=, Bearer <token>,
             * AWS access keys, JWTs). Forensic evidence remains untouched in the DB;
             * only export-side artifacts (text/JSON/CSV) are scrubbed.
             *
             * @security Mitigates inadvertent secret exfiltration via log exports.
             */
            [[nodiscard]] std::wstring RedactSecrets(std::wstring_view input) {
                // Operate on a mutable copy; std::regex over wide strings is supported.
                std::wstring text(input);
                try {
                    static const std::wregex kvSecret(
                        LR"((?:password|passwd|pwd|api[_-]?key|secret|token|authorization)\s*[:=]\s*\S+)",
                        std::regex::icase);
                    static const std::wregex bearer(LR"(Bearer\s+[A-Za-z0-9._\-]+)",
                        std::regex::icase);
                    static const std::wregex awsKey(LR"(AKIA[0-9A-Z]{16})");
                    static const std::wregex jwt(LR"(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})");
                    text = std::regex_replace(text, kvSecret, std::wstring(L"[REDACTED]"));
                    text = std::regex_replace(text, bearer,   std::wstring(L"Bearer [REDACTED]"));
                    text = std::regex_replace(text, awsKey,   std::wstring(L"[REDACTED_AWS_KEY]"));
                    text = std::regex_replace(text, jwt,      std::wstring(L"[REDACTED_JWT]"));
                } catch (...) {
                    // Regex catastrophic-backtrack guard: on any failure, return clamped raw.
                    return ClampField(input, LOGDB_MAX_DETAILS_LEN);
                }
                return text;
            }

            /**
             * @brief Validates an absolute filesystem path for export/archive use.
             *
             * @param path Path under inspection (Windows wide).
             * @return true if @p path is absolute, NUL-free, and free of '..' segments.
             *
             * @security Mitigates path traversal (CWE-22) on attacker-influenced paths.
             */
            [[nodiscard]] bool IsSafePath(std::wstring_view path) noexcept {
                if (path.empty() || path.size() > 32767) return false;
                for (wchar_t c : path) {
                    if (c == L'\0') return false;
                }
                std::filesystem::path p(path);
                if (!p.is_absolute()) return false;
                for (const auto& part : p) {
                    if (part == L"..") return false;
                }
                return true;
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
            // Serialize concurrent Initialize() / Shutdown() invocations.
            std::lock_guard<std::mutex> initLock(m_initMutex);

            if (m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"LogDB", L"Already initialized; applying configuration update");

                bool wantAsync = false;
                bool wasAsync = false;
                {
                    std::unique_lock<std::shared_mutex> lock(m_configMutex);
                    wasAsync = m_config.asyncLogging;
                    m_config = config;
                    wantAsync = m_config.asyncLogging;
                }

                // Reconcile batch thread with new config (start or stop as needed).
                if (wantAsync && !wasAsync) {
                    m_shutdownBatch.store(false, std::memory_order_release);
                    if (!m_batchThread.joinable()) {
                        m_batchThread = std::thread(&LogDB::batchWriteThread, this);
                    }
                } else if (!wantAsync && wasAsync) {
                    m_shutdownBatch.store(true, std::memory_order_release);
                    m_batchCV.notify_all();
                    if (m_batchThread.joinable()) {
                        m_batchThread.join();
                    }
                }
                return true;
            }

            SS_LOG_INFO(L"LogDB", L"Initializing LogDB...");

            {
                std::unique_lock<std::shared_mutex> lock(m_configMutex);
                m_config = config;
            }

            // [ARCH-BLOCKER] DatabaseManager is a process-wide singleton shared
            // with ConfigurationDB / QuarantineDB. Force-shutdown here mirrors the
            // sibling DB modules' convention (see QuarantineDB.cpp ~line 786) and
            // is preserved to keep behavior consistent. Resolving the multi-DB
            // sharing pattern is a cross-cutting architecture change.
            if (DatabaseManager::Instance().IsInitialized()) {
                SS_LOG_INFO(L"LogDB", L"Shutting down existing DatabaseManager instance");
                DatabaseManager::Instance().Shutdown();
            }

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
            // Security audit logs require durability across crashes.
            dbConfig.synchronousMode = L"NORMAL";

            if (!DatabaseManager::Instance().Initialize(dbConfig, err)) {
                SS_LOG_ERROR(L"LogDB", L"Failed to initialize DatabaseManager");
                return false;
            }

            if (!createSchema(err)) {
                SS_LOG_ERROR(L"LogDB", L"Failed to create schema");
                DatabaseManager::Instance().Shutdown();
                return false;
            }

            bool asyncEnabled = false;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                asyncEnabled = m_config.asyncLogging;
            }

            if (asyncEnabled) {
                m_shutdownBatch.store(false, std::memory_order_release);
                m_batchThread = std::thread(&LogDB::batchWriteThread, this);
            }

            recalculateStatistics(err);

            m_initialized.store(true, std::memory_order_release);

            SS_LOG_INFO(L"LogDB", L"LogDB initialized successfully");
            return true;
        }
        
        void LogDB::Shutdown() {
            std::lock_guard<std::mutex> initLock(m_initMutex);

            if (!m_initialized.load(std::memory_order_acquire)) {
                return;
            }

            SS_LOG_INFO(L"LogDB", L"Shutting down LogDB...");

            // Drain any queued async writes before tearing down the batch thread.
            DatabaseError err;
            Flush(&err);

            m_shutdownBatch.store(true, std::memory_order_release);
            m_batchCV.notify_all();

            if (m_batchThread.joinable()) {
                m_batchThread.join();
            }

            // [ARCH-BLOCKER] See note in Initialize() about shared DatabaseManager.
            DatabaseManager::Instance().Shutdown();

            // Preserve user-supplied configuration (paths, levels, async flag) so a
            // subsequent Initialize() without an explicit config will not silently
            // downgrade settings. Only transient/runtime state is cleared.
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

            LogLevel minLevel;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                minLevel = m_config.minLogLevel;
            }

            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);

            if (!trans || !trans->IsActive()) {
                return false;
            }

            uint64_t inserted = 0;
            uint64_t filtered = 0;
            for (const auto& entry : entries) {
                if (entry.level < minLevel) {
                    ++filtered;
                    continue;
                }

                // Bound field lengths defensively at the batch path too.
                LogEntry clamped = entry;
                clamped.source       = ClampField(clamped.source,       LOGDB_MAX_SOURCE_LEN);
                clamped.message      = ClampField(clamped.message,      LOGDB_MAX_MESSAGE_LEN);
                clamped.details      = ClampField(clamped.details,      LOGDB_MAX_DETAILS_LEN);
                clamped.metadata     = ClampField(clamped.metadata,     LOGDB_MAX_METADATA_LEN);
                clamped.errorContext = ClampField(clamped.errorContext, LOGDB_MAX_CONTEXT_LEN);
                clamped.filePath     = ClampField(clamped.filePath,     LOGDB_MAX_PATH_LEN);
                clamped.functionName = ClampField(clamped.functionName, LOGDB_MAX_FUNCNAME_LEN);

                const std::string timestamp = timePointToString(clamped.timestamp);

                bool success = trans->ExecuteWithParams(
                    SQL_INSERT_ENTRY,
                    err,
                    timestamp,
                    static_cast<int>(clamped.level),
                    static_cast<int>(clamped.category),
                    ToUTF8(clamped.source),
                    ToUTF8(clamped.message),
                    ToUTF8(clamped.details),
                    static_cast<int>(clamped.processId),
                    static_cast<int>(clamped.threadId),
                    ToUTF8(clamped.userName),
                    ToUTF8(clamped.machineName),
                    ToUTF8(clamped.metadata),
                    static_cast<int>(clamped.errorCode),
                    ToUTF8(clamped.errorContext),
                    clamped.durationMs,
                    ToUTF8(clamped.filePath),
                    clamped.lineNumber,
                    ToUTF8(clamped.functionName)
                );

                if (!success) {
                    if (err) {
                        SS_LOG_ERROR(L"LogDB", L"LogBatch: insert failed after %llu entries: %ls",
                            static_cast<unsigned long long>(inserted), err->message.c_str());
                    }
                    trans->Rollback(err);
                    return false;
                }
                ++inserted;
            }

            if (!trans->Commit(err)) {
                return false;
            }

            // BUGFIX: previously incremented totalWrites by entries.size() even
            // for entries filtered out by minLevel. Count only what was inserted.
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.totalWrites    += inserted;
            m_stats.filteredWrites += filtered;

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
                std::wstring q(searchText);
                if (q.size() > LOGDB_MAX_FTS_QUERY_LEN) {
                    q.resize(LOGDB_MAX_FTS_QUERY_LEN);
                }
                filter.fullTextSearch = std::move(q);
            }
            else {
                if (useFullText && !enableFTS) {
                    SS_LOG_WARN(L"LogDB",
                        L"SearchText: FTS requested but disabled; falling back to LIKE");
                }
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

            // BUGFIX: previously called Query() which silently dropped bound params,
            // returning the unfiltered total. Use the parameter-binding overload
            // whenever the filter contributed placeholders.
            QueryResult result = params.empty()
                ? DatabaseManager::Instance().Query(sql, err)
                : DatabaseManager::Instance().QueryWithParamsVector(sql, params, err);

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
            if (id <= 0) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"DeleteEntry: invalid id";
                }
                return false;
            }

            // Wrap statement + change-count read in a single transaction so the
            // change counter is read from the same connection that executed the
            // DELETE. Without this, the pooled connection may differ and the
            // returned change count is unreliable.
            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);
            if (!trans || !trans->IsActive()) {
                return false;
            }

            if (!trans->ExecuteWithParams(SQL_DELETE_ENTRY, err, id)) {
                trans->Rollback(err);
                return false;
            }

            const int affectedRows = DatabaseManager::Instance().GetChangedRowCount();

            if (!trans->Commit(err)) {
                return false;
            }

            if (affectedRows > 0) {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalDeletes++;
                if (m_stats.totalEntries > 0) {
                    m_stats.totalEntries--;
                }
                return true;
            }

            if (err) {
                err->sqliteCode = SQLITE_OK;
                err->message = L"No entry found with given ID";
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
            if (!IsSafePath(archivePath)) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"ArchiveLogs: rejected unsafe archive path";
                }
                SS_LOG_ERROR(L"LogDB", L"ArchiveLogs: rejected unsafe archive path");
                return false;
            }
            const std::wstring safePath(archivePath);
            SS_LOG_INFO(L"LogDB", L"Archiving logs to: %ls", safePath.c_str());

            // Drain pending async writes so the archive captures all queued entries.
            DatabaseError flushErr;
            Flush(&flushErr);

            return createArchive(safePath, beforeTimestamp, err);
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
            if (!IsSafePath(archivePath)) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"RestoreLogs: rejected unsafe archive path";
                }
                SS_LOG_ERROR(L"LogDB", L"RestoreLogs: rejected unsafe archive path");
                return false;
            }
            std::error_code ec;
            if (!std::filesystem::exists(std::filesystem::path(archivePath), ec) || ec) {
                if (err) {
                    err->sqliteCode = SQLITE_CANTOPEN;
                    err->message = L"RestoreLogs: archive file does not exist";
                }
                return false;
            }
            const std::wstring safePath(archivePath);
            SS_LOG_INFO(L"LogDB", L"Restoring logs from: %ls", safePath.c_str());

            if (!DatabaseManager::Instance().RestoreFromFile(safePath, err)) {
                return false;
            }

            // Post-restore: verify integrity of the now-replaced database.
            std::vector<std::wstring> issues;
            if (!DatabaseManager::Instance().CheckIntegrity(issues, err)) {
                SS_LOG_ERROR(L"LogDB", L"RestoreLogs: post-restore integrity check failed");
                return false;
            }
            return true;
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
            // Always attempt to drain the pending queue. If a caller toggled
            // asyncLogging off after entries were already queued, we still need
            // to flush them — checking the current flag would leak data.
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
            bool wasEnabled = false;
            {
                std::unique_lock<std::shared_mutex> lock(m_configMutex);
                wasEnabled = m_config.asyncLogging;
                m_config.asyncLogging = enabled;
            }

            if (!m_initialized.load(std::memory_order_acquire)) {
                return;
            }

            // BUGFIX: previously a silent runtime toggle that left the batch
            // thread in a desynchronized state. Now we actually start/stop the
            // background writer to honor the new mode.
            if (enabled && !wasEnabled) {
                m_shutdownBatch.store(false, std::memory_order_release);
                if (!m_batchThread.joinable()) {
                    m_batchThread = std::thread(&LogDB::batchWriteThread, this);
                }
                SS_LOG_INFO(L"LogDB", L"Async logging enabled; batch thread started");
            } else if (!enabled && wasEnabled) {
                DatabaseError err;
                Flush(&err);
                m_shutdownBatch.store(true, std::memory_order_release);
                m_batchCV.notify_all();
                if (m_batchThread.joinable()) {
                    m_batchThread.join();
                }
                SS_LOG_INFO(L"LogDB", L"Async logging disabled; batch thread stopped");
            }
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

            // SECURITY: strip control characters on render so a hostile message
            // cannot inject newlines/ANSI/escape sequences into logs/consoles.
            const std::wstring src     = SanitizeForRender(entry.source);
            const std::wstring msg     = SanitizeForRender(entry.message);
            const std::wstring details = SanitizeForRender(entry.details);
            const std::wstring meta    = SanitizeForRender(entry.metadata);

            std::string timestampStr = timePointToString(entry.timestamp);
            oss << L"[" << ToWide(timestampStr) << L"] ";
            oss << L"[" << LogLevelToString(entry.level) << L"] ";
            oss << L"[" << LogCategoryToString(entry.category) << L"] ";
            oss << src << L": " << msg;

            if (!details.empty()) {
                oss << L" | " << details;
            }

            if (entry.errorCode != 0) {
                oss << L" (Error: " << entry.errorCode << L")";
            }

            if (includeMetadata && !meta.empty()) {
                oss << L" | Metadata: " << meta;
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
            if (!IsSafePath(filePath)) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"ExportToFile: rejected unsafe destination path";
                }
                return false;
            }

            // Drain async queue so the export reflects all entries up to this call.
            DatabaseError flushErr;
            Flush(&flushErr);

            // Bound entry count regardless of caller-supplied filter.
            QueryFilter effective = filter ? *filter : QueryFilter{};
            if (effective.maxResults == 0 || effective.maxResults > LOGDB_MAX_EXPORT_ENTRIES) {
                effective.maxResults = LOGDB_MAX_EXPORT_ENTRIES;
            }
            auto entries = Query(effective, err);

            std::wostringstream content;
            for (const auto& entry : entries) {
                LogEntry sanitized = entry;
                // SECURITY: strip control characters and redact secrets on the
                // outbound rendering surface. DB retains raw forensic data.
                sanitized.source       = SanitizeForRender(sanitized.source);
                sanitized.message      = RedactSecrets(SanitizeForRender(sanitized.message));
                sanitized.details      = RedactSecrets(SanitizeForRender(sanitized.details));
                sanitized.metadata     = RedactSecrets(SanitizeForRender(sanitized.metadata));
                sanitized.errorContext = RedactSecrets(SanitizeForRender(sanitized.errorContext));
                content << FormatLogEntry(sanitized, true) << L"\r\n";
            }

            // Emit UTF-8 for SIEM/tooling compatibility (DB is UTF-8 too).
            const std::string utf8 = ToUTF8(content.str());
            Utils::FileUtils::Error fileErr;
            return Utils::FileUtils::WriteAllBytesAtomic(
                filePath,
                reinterpret_cast<const std::byte*>(utf8.data()),
                utf8.size(),
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
            if (!IsSafePath(filePath)) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"ExportToJSON: rejected unsafe destination path";
                }
                return false;
            }

            DatabaseError flushErr;
            Flush(&flushErr);

            QueryFilter effective = filter ? *filter : QueryFilter{};
            if (effective.maxResults == 0 || effective.maxResults > LOGDB_MAX_EXPORT_ENTRIES) {
                effective.maxResults = LOGDB_MAX_EXPORT_ENTRIES;
            }
            auto entries = Query(effective, err);

            std::wostringstream json;
            json << L"[\n";

            for (size_t i = 0; i < entries.size(); ++i) {
                const auto& entry = entries[i];

                // SECURITY: sanitize + redact attacker-influenced fields on render.
                const std::wstring src     = RedactSecrets(SanitizeForRender(entry.source));
                const std::wstring msg     = RedactSecrets(SanitizeForRender(entry.message));
                const std::wstring details = RedactSecrets(SanitizeForRender(entry.details));
                const std::wstring meta    = RedactSecrets(SanitizeForRender(entry.metadata));
                const std::wstring ectx    = RedactSecrets(SanitizeForRender(entry.errorContext));
                const std::wstring fpath   = SanitizeForRender(entry.filePath);
                const std::wstring fname   = SanitizeForRender(entry.functionName);
                const std::wstring user    = SanitizeForRender(entry.userName);
                const std::wstring host    = SanitizeForRender(entry.machineName);

                json << L"  {\n";
                json << L"    \"id\": " << entry.id << L",\n";
                json << L"    \"timestamp\": \"" << EscapeJsonString(ToWide(timePointToString(entry.timestamp))) << L"\",\n";
                json << L"    \"level\": \""    << EscapeJsonString(LogLevelToString(entry.level))    << L"\",\n";
                json << L"    \"category\": \"" << EscapeJsonString(LogCategoryToString(entry.category)) << L"\",\n";
                json << L"    \"source\": \""   << EscapeJsonString(src)     << L"\",\n";
                json << L"    \"message\": \""  << EscapeJsonString(msg)     << L"\",\n";
                json << L"    \"details\": \""  << EscapeJsonString(details) << L"\",\n";
                json << L"    \"processId\": "  << entry.processId  << L",\n";
                json << L"    \"threadId\": "   << entry.threadId   << L",\n";
                json << L"    \"userName\": \"" << EscapeJsonString(user) << L"\",\n";
                json << L"    \"machineName\": \"" << EscapeJsonString(host) << L"\",\n";
                json << L"    \"metadata\": \"" << EscapeJsonString(meta) << L"\",\n";
                json << L"    \"errorCode\": "  << entry.errorCode  << L",\n";
                json << L"    \"errorContext\": \"" << EscapeJsonString(ectx) << L"\",\n";
                json << L"    \"durationMs\": " << entry.durationMs << L",\n";
                json << L"    \"filePath\": \"" << EscapeJsonString(fpath) << L"\",\n";
                json << L"    \"lineNumber\": " << entry.lineNumber << L",\n";
                json << L"    \"functionName\": \"" << EscapeJsonString(fname) << L"\"\n";
                json << L"  }";

                if (i < entries.size() - 1) {
                    json << L",";
                }
                json << L"\n";
            }

            json << L"]\n";

            const std::string utf8 = ToUTF8(json.str());
            Utils::FileUtils::Error fileErr;
            return Utils::FileUtils::WriteAllBytesAtomic(
                filePath,
                reinterpret_cast<const std::byte*>(utf8.data()),
                utf8.size(),
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
         * 
         * @security Uses SanitizeCsvFieldW to prevent CSV formula injection attacks.
         * Fields starting with =, @, +, - are prefixed with a single quote.
         */
        bool LogDB::ExportToCSV(std::wstring_view filePath,
                               const QueryFilter* filter,
                               DatabaseError* err)
        {
            if (!IsSafePath(filePath)) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"ExportToCSV: rejected unsafe destination path";
                }
                return false;
            }

            DatabaseError flushErr;
            Flush(&flushErr);

            QueryFilter effective = filter ? *filter : QueryFilter{};
            if (effective.maxResults == 0 || effective.maxResults > LOGDB_MAX_EXPORT_ENTRIES) {
                effective.maxResults = LOGDB_MAX_EXPORT_ENTRIES;
            }
            auto entries = Query(effective, err);

            // Helper lambda for CSV escape with formula injection prevention
            auto escapeCsvField = [](std::wstring_view field) -> std::wstring {
                std::wstring sanitized = SanitizeCsvFieldW(field);

                if (sanitized.find(L',') != std::wstring::npos ||
                    sanitized.find(L'"') != std::wstring::npos ||
                    sanitized.find(L'\n') != std::wstring::npos ||
                    sanitized.find(L'\r') != std::wstring::npos) {
                    std::wstring escaped = L"\"";
                    for (wchar_t c : sanitized) {
                        if (c == L'"') escaped += L"\"\"";
                        else escaped += c;
                    }
                    escaped += L"\"";
                    return escaped;
                }
                return sanitized;
            };

            std::wostringstream csv;
            csv << L"ID,Timestamp,Level,Category,Source,Message,ProcessID,ThreadID\r\n";

            for (const auto& entry : entries) {
                const std::wstring src = RedactSecrets(SanitizeForRender(entry.source));
                const std::wstring msg = RedactSecrets(SanitizeForRender(entry.message));
                auto timestampStr = timePointToString(entry.timestamp);
                csv << entry.id << L",";
                csv << ToWide(timestampStr) << L",";
                csv << LogLevelToString(entry.level) << L",";
                csv << LogCategoryToString(entry.category) << L",";
                csv << escapeCsvField(src) << L",";
                csv << escapeCsvField(msg) << L",";
                csv << entry.processId << L",";
                csv << entry.threadId << L"\r\n";
            }

            // UTF-8 with BOM for Excel-friendly CSV consumption.
            std::string utf8 = ToUTF8(csv.str());
            std::string out;
            out.reserve(3 + utf8.size());
            out.push_back(static_cast<char>(0xEF));
            out.push_back(static_cast<char>(0xBB));
            out.push_back(static_cast<char>(0xBF));
            out.append(utf8);

            Utils::FileUtils::Error fileErr;
            return Utils::FileUtils::WriteAllBytesAtomic(
                filePath,
                reinterpret_cast<const std::byte*>(out.data()),
                out.size(),
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

            // Atomically drop + recreate to ensure readers never observe a
            // missing-index window during reconciliation.
            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);
            if (!trans || !trans->IsActive()) {
                return false;
            }

            const char* dropStmts[] = {
                "DROP INDEX IF EXISTS idx_log_timestamp",
                "DROP INDEX IF EXISTS idx_log_level",
                "DROP INDEX IF EXISTS idx_log_category",
                "DROP INDEX IF EXISTS idx_log_source",
                "DROP INDEX IF EXISTS idx_log_process",
                "DROP INDEX IF EXISTS idx_log_error",
                "DROP INDEX IF EXISTS idx_log_composite",
            };
            for (const char* stmt : dropStmts) {
                if (!trans->Execute(stmt, err)) {
                    trans->Rollback(err);
                    return false;
                }
            }
            if (!trans->Execute(SQL_CREATE_INDICES, err)) {
                trans->Rollback(err);
                return false;
            }
            return trans->Commit(err);
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
                
                // Persist schema version in the DatabaseManager-owned `_metadata`
                // table (LogDB does not create its own metadata table; the legacy
                // `db_metadata` reference would silently fail at runtime).
                DatabaseManager::Instance().ExecuteWithParams(
                    "INSERT OR REPLACE INTO _metadata (key, value) VALUES ('log_schema_version', ?)",
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

            // Bound attacker-controllable field lengths before serialization.
            LogEntry clamped = entry;
            clamped.source        = ClampField(clamped.source,        LOGDB_MAX_SOURCE_LEN);
            clamped.message       = ClampField(clamped.message,       LOGDB_MAX_MESSAGE_LEN);
            clamped.details       = ClampField(clamped.details,       LOGDB_MAX_DETAILS_LEN);
            clamped.metadata      = ClampField(clamped.metadata,      LOGDB_MAX_METADATA_LEN);
            clamped.errorContext  = ClampField(clamped.errorContext,  LOGDB_MAX_CONTEXT_LEN);
            clamped.filePath      = ClampField(clamped.filePath,      LOGDB_MAX_PATH_LEN);
            clamped.functionName  = ClampField(clamped.functionName,  LOGDB_MAX_FUNCNAME_LEN);

            const std::string timestamp = timePointToString(clamped.timestamp);

            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_INSERT_ENTRY,
                err,
                timestamp,
                static_cast<int>(clamped.level),
                static_cast<int>(clamped.category),
                ToUTF8(clamped.source),
                ToUTF8(clamped.message),
                ToUTF8(clamped.details),
                static_cast<int>(clamped.processId),
                static_cast<int>(clamped.threadId),
                ToUTF8(clamped.userName),
                ToUTF8(clamped.machineName),
                ToUTF8(clamped.metadata),
                static_cast<int>(clamped.errorCode),
                ToUTF8(clamped.errorContext),
                clamped.durationMs,
                ToUTF8(clamped.filePath),
                clamped.lineNumber,
                ToUTF8(clamped.functionName)
            );

            if (!success) {
                return -1;
            }

            const int64_t id = DatabaseManager::Instance().LastInsertRowId();

            const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime);

            // BUGFIX: previous implementation re-locked m_statsMutex after
            // updateStatistics() had already acquired it — std::mutex is NOT
            // recursive, which was a guaranteed deadlock on every sync write.
            // Merge stats updates under a single lock and compute avgWriteTime
            // as a proper running mean instead of an exponentially-biased average.
            {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalEntries++;
                if (clamped.level >= LogLevel::Trace && clamped.level <= LogLevel::Fatal) {
                    m_stats.entriesByLevel[static_cast<size_t>(clamped.level)]++;
                }
                m_stats.entriesByCategory[static_cast<size_t>(clamped.category)]++;
                if (m_stats.oldestEntry == std::chrono::system_clock::time_point{} ||
                    clamped.timestamp < m_stats.oldestEntry) {
                    m_stats.oldestEntry = clamped.timestamp;
                }
                if (clamped.timestamp > m_stats.newestEntry) {
                    m_stats.newestEntry = clamped.timestamp;
                }

                const uint64_t prevWrites = m_stats.totalWrites;
                m_stats.totalWrites = prevWrites + 1;
                // running mean: avg_n = avg_{n-1} + (sample - avg_{n-1}) / n
                const int64_t avgPrev = m_stats.avgWriteTime.count();
                const int64_t sample  = duration.count();
                const int64_t newAvg  = avgPrev + (sample - avgPrev) / static_cast<int64_t>(prevWrites + 1);
                m_stats.avgWriteTime = std::chrono::milliseconds(newAvg);
            }

            return id;
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
                std::wstring ftsQuery = *filter.fullTextSearch;
                if (ftsQuery.size() > LOGDB_MAX_FTS_QUERY_LEN) {
                    ftsQuery.resize(LOGDB_MAX_FTS_QUERY_LEN);
                }
                sql << " AND id IN (SELECT rowid FROM log_fts WHERE log_fts MATCH ?)";
                outParams.push_back(ToUTF8(ftsQuery));
            }

            // Order and limit
            if (filter.sortDescending) {
                sql << " ORDER BY timestamp DESC";
            } else {
                sql << " ORDER BY timestamp ASC";
            }

            // SECURITY: clamp result count to bound memory/CPU on attacker-influenced filters.
            const size_t cappedResults = (filter.maxResults == 0 || filter.maxResults > LOGDB_MAX_QUERY_RESULTS)
                ? LOGDB_MAX_QUERY_RESULTS
                : filter.maxResults;
            sql << " LIMIT " << cappedResults;

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

            // SECURITY: cap the queue to bound memory under a stalled DB or a
            // logging storm. Dropping the new entry (rather than evicting older
            // ones) preserves forensic ordering and is reported via statistics.
            if (m_pendingWrites.size() >= LOGDB_MAX_PENDING_WRITES) {
                {
                    std::lock_guard<std::mutex> statsLock(m_statsMutex);
                    m_stats.droppedAsyncWrites++;
                }
                m_batchCV.notify_one();
                return;
            }

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
                SS_LOG_ERROR(L"LogDB", L"performRotation: archive creation failed at %ls",
                    archivePath.c_str());
                return false;
            }

            // Delete old entries — surface failure with archive path so operators
            // can correlate with the archive that was just emitted.
            DatabaseError delErr;
            if (!DeleteBefore(cutoffTime, &delErr)) {
                SS_LOG_ERROR(L"LogDB",
                    L"performRotation: DeleteBefore failed after archive %ls (sqlite=%d, %ls)",
                    archivePath.c_str(),
                    delErr.sqliteCode,
                    delErr.message.c_str());
                if (err) {
                    *err = delErr;
                }
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
            std::wstring archivePath;
            size_t maxArchivedLogs;
            {
                std::shared_lock<std::shared_mutex> lock(m_configMutex);
                archivePath = m_config.archivePath;
                maxArchivedLogs = m_config.maxArchivedLogs;
            }

            std::error_code ec;
            std::filesystem::path archiveDir(archivePath);
            if (!std::filesystem::exists(archiveDir, ec) || ec) {
                return;
            }

            struct ArchiveFile {
                std::filesystem::path path;
                std::filesystem::file_time_type mtime;
            };
            std::vector<ArchiveFile> archives;

            try {
                for (const auto& entry : std::filesystem::directory_iterator(
                        archiveDir, std::filesystem::directory_options::skip_permission_denied, ec))
                {
                    if (ec) break;
                    if (!entry.is_regular_file(ec) || ec) { ec.clear(); continue; }
                    const auto& p = entry.path();
                    if (p.extension() != L".db") continue;
                    // SECURITY: gate cleanup strictly to our own archive filename pattern
                    // so a misconfigured archivePath cannot wipe unrelated .db files.
                    const std::wstring stem = p.stem().wstring();
                    if (stem.rfind(LOGDB_ARCHIVE_PREFIX, 0) != 0) continue;
                    auto mt = std::filesystem::last_write_time(p, ec);
                    if (ec) { ec.clear(); continue; }
                    archives.push_back({ p, mt });
                }
            } catch (const std::filesystem::filesystem_error& e) {
                SS_LOG_WARN(L"LogDB", L"cleanupOldArchives: enumeration failed: %hs", e.what());
                return;
            }

            if (archives.size() <= maxArchivedLogs) {
                return;
            }

            std::sort(archives.begin(), archives.end(),
                [](const ArchiveFile& a, const ArchiveFile& b) {
                    return a.mtime < b.mtime;
                });

            const size_t toDelete = archives.size() - maxArchivedLogs;
            for (size_t i = 0; i < toDelete; ++i) {
                std::error_code rmEc;
                std::filesystem::remove(archives[i].path, rmEc);
                if (!rmEc) {
                    SS_LOG_INFO(L"LogDB", L"Deleted old archive: %ls",
                        archives[i].path.wstring().c_str());
                } else {
                    SS_LOG_WARN(L"LogDB", L"Failed to delete archive: %ls (%hs)",
                        archives[i].path.wstring().c_str(), rmEc.message().c_str());
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

            // BUGFIX: previous gate `entry.level < LogLevel::Trace` is
            // tautologically false because LogLevel is uint8_t starting at 0.
            // Use a proper range check that gates both ends.
            if (entry.level >= LogLevel::Trace && entry.level <= LogLevel::Fatal) {
                m_stats.entriesByLevel[static_cast<size_t>(entry.level)]++;
            }
            // LogCategory is uint8_t, so the [256] histogram cannot overflow,
            // but we still bound defensively in case the underlying type ever
            // changes width.
            const size_t catIdx = static_cast<size_t>(entry.category);
            if (catIdx < (sizeof(m_stats.entriesByCategory) / sizeof(m_stats.entriesByCategory[0]))) {
                m_stats.entriesByCategory[catIdx]++;
            }

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
            if (str.length() < 19) {
                return std::chrono::system_clock::time_point{};
            }

            // sscanf_s expects a null-terminated buffer; std::string_view may
            // not be terminated, so copy into a bounded local buffer.
            char buf[64];
            const size_t copyLen = std::min<size_t>(str.size(), sizeof(buf) - 1);
            std::memcpy(buf, str.data(), copyLen);
            buf[copyLen] = '\0';

            int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
            if (sscanf_s(buf, "%d-%d-%d %d:%d:%d",
                         &year, &month, &day, &hour, &minute, &second) != 6) {
                return std::chrono::system_clock::time_point{};
            }

            // SECURITY: validate ranges before handing to _mkgmtime to avoid
            // undefined behavior on out-of-range struct tm fields.
            if (year < 1970 || year > 9999 ||
                month < 1 || month > 12 ||
                day < 1   || day > 31 ||
                hour < 0  || hour > 23 ||
                minute < 0 || minute > 59 ||
                second < 0 || second > 60) {
                return std::chrono::system_clock::time_point{};
            }

            std::tm tm = {};
            tm.tm_year = year - 1900;
            tm.tm_mon  = month - 1;
            tm.tm_mday = day;
            tm.tm_hour = hour;
            tm.tm_min  = minute;
            tm.tm_sec  = second;

            const time_t t = _mkgmtime(&tm);
            if (t == static_cast<time_t>(-1)) {
                return std::chrono::system_clock::time_point{};
            }
            auto tp = std::chrono::system_clock::from_time_t(t);

            const size_t dotPos = std::string_view(buf, copyLen).find('.');
            if (dotPos != std::string_view::npos && dotPos + 1 < copyLen) {
                try {
                    const std::string fragment(buf + dotPos + 1,
                        std::min<size_t>(3, copyLen - dotPos - 1));
                    int ms = std::stoi(fragment);
                    if (ms >= 0 && ms < 1000) {
                        tp += std::chrono::milliseconds(ms);
                    }
                } catch (...) {
                    // Ignore: sub-second precision is best-effort.
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
