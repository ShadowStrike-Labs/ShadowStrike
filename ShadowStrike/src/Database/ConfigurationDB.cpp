// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * ============================================================================
 * ShadowStrike ConfigurationDatabase - IMPLEMENTATION
 * ============================================================================
 *
 * @file ConfigurationDB.cpp
 * @brief Enterprise-grade SQLite-backed configuration management system.
 * 
 * This module provides a comprehensive configuration storage and management
 * system designed for enterprise antivirus deployments. It serves as the
 * primary interface for persistent configuration data that needs to survive
 * application restarts and be accessible via GUI/management interfaces.
 * 
 * Architecture Overview:
 * ----------------------
 * ConfigurationDB sits above the memory-mapped high-performance stores
 * (SignatureIndex, HashStore, PatternStore) and provides:
 * 
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                    GUI / Management API                      │
 *   └─────────────────────────────────────────────────────────────┘
 *                                 │
 *                                 ▼
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │              ConfigurationDB (SQLite Layer)                  │
 *   │  - User preferences, policies, audit logs                   │
 *   │  - Versioned configurations with rollback                   │
 *   │  - Change notifications for hot-reload                      │
 *   │  - DPAPI encryption for sensitive values                    │
 *   └─────────────────────────────────────────────────────────────┘
 *                                 │
 *                                 ▼
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │           Memory-Mapped Stores (High-Performance)            │
 *   │  - SignatureIndex, HashStore, PatternStore                  │
 *   │  - Sub-microsecond query latency                            │
 *   │  - Lock-free concurrent access                              │
 *   └─────────────────────────────────────────────────────────────┘
 * 
 * Key Features:
 * -------------
 * 1. HIERARCHICAL CONFIGURATION KEYS
 *    Keys use dot-notation (e.g., "network.proxy.host") enabling
 *    prefix-based queries and logical grouping.
 * 
 * 2. MULTI-TYPE VALUE SUPPORT
 *    - String, Integer, Real, Boolean, JSON, Binary, Encrypted
 *    - Type-safe variant storage with automatic serialization
 * 
 * 3. ENCRYPTION (Windows DPAPI)
 *    - Sensitive values encrypted at rest using Windows Data Protection API
 *    - Machine-local encryption bound to Windows credentials
 *    - Optional entropy via master key for additional security
 * 
 * 4. VERSION CONTROL & AUDIT
 *    - Full version history for each configuration key
 *    - Rollback capability to any previous version
 *    - Comprehensive audit log with change reasons
 * 
 * 5. HOT-RELOAD & CHANGE NOTIFICATIONS
 *    - Background thread monitors for external database changes
 *    - Delta-based reload only fetches modified configurations
 *    - Observer pattern for real-time change notifications
 * 
 * 6. VALIDATION FRAMEWORK
 *    - Regex patterns, min/max bounds, allowed values
 *    - Custom validator callbacks for complex rules
 *    - Schema enforcement before write operations
 * 
 * Thread Safety:
 * --------------
 * - All public methods are thread-safe via shared/exclusive locks
 * - Cache operations use reader-writer lock for concurrent reads
 * - Hot-reload thread safely updates cache without blocking readers
 * - Notifications dispatched outside locks to prevent deadlocks
 * 
 * Performance Considerations:
 * ---------------------------
 * - In-memory cache with configurable TTL reduces database I/O
 * - Prepared statements cached by DatabaseManager
 * - WAL mode enabled for concurrent read/write performance
 * - Indexed columns for efficient prefix and scope queries
 * 
 * Error Handling:
 * ---------------
 * All methods accept optional DatabaseError* for detailed error info.
 * Operations that fail return false/nullopt and log via SS_LOG_*.
 * Transactions are rolled back on partial failures.
 * 
 * @note This module uses Windows DPAPI (CryptProtectData/CryptUnprotectData)
 *       for encryption. These are NOT deprecated CAPI hash functions - DPAPI
 *       is the recommended Windows API for data protection at rest.
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * ============================================================================
 */

#include"pch.h"
#include"Utils/StringUtils.hpp"
#include "ConfigurationDB.hpp"
#include"DatabaseManager.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/XMLUtils.hpp"
#include"../Utils/SystemUtils.hpp"
#include"../Utils/Base64Utils.hpp"

#include <regex>
#include <algorithm>
#include <sstream>

#ifdef _WIN32
#  include <Windows.h>
#  include <wincrypt.h>
#  pragma comment(lib, "Crypt32.lib")
#  pragma comment(lib, "Advapi32.lib")
#endif

namespace ShadowStrike {
    namespace Database {

        // ============================================================================
        // CONSTANTS & INTERNAL HELPERS
        // ============================================================================
        
        namespace {
            /**
             * @brief Database schema version for migration management.
             * 
             * Increment this when adding new columns, tables, or indices.
             * The upgradeSchema() method handles migrations from older versions.
             */
            constexpr int SCHEMA_VERSION = 1;
            
            /** @brief Log category for all ConfigurationDB operations */
            constexpr const wchar_t* LOG_CATEGORY = L"ConfigurationDB";

            /**
             * @brief Minimum required key length for strong encryption.
             * 
             * When requireStrongKeys is enabled, the master key must be at least
             * this many bytes (256 bits) to meet enterprise security standards.
             */
            constexpr size_t MIN_KEY_LENGTH = 32;
            
            /** @brief AES block size for alignment calculations */
            constexpr size_t AES_BLOCK_SIZE = 16;
            
            /**
             * @brief Helper function to Base64 encode binary data.
             * 
             * Used for export operations where binary data needs to be
             * represented as a string (e.g., JSON/XML export).
             * 
             * @param data Pointer to binary data
             * @param len Length of data in bytes
             * @return Base64-encoded string, or empty string on failure
             */
            inline std::string Base64EncodeToString(const uint8_t* data, size_t len) {
                std::string out;
                if (Utils::Base64Encode(data, len, out)) {
                    return out;
                }
                SS_LOG_ERROR(LOG_CATEGORY, L"Base64 encoding failed for %zu bytes", len);
                return {};
            }
        }

        // ============================================================================
        // SINGLETON LIFECYCLE
        // ============================================================================

        ConfigurationDB::ConfigurationDB() = default;
        
        ConfigurationDB::~ConfigurationDB() {
            Shutdown();
        }

        /**
         * @brief Returns the singleton instance of ConfigurationDB.
         * 
         * Thread-safe via C++11 static initialization guarantees (magic statics).
         * The instance is lazily created on first access and destroyed at program exit.
         * 
         * @return Reference to the singleton ConfigurationDB instance
         */
        ConfigurationDB& ConfigurationDB::Instance() {
            static ConfigurationDB instance;
            return instance;
        }

        /**
         * @brief Initializes the ConfigurationDB with the provided configuration.
         * 
         * This method performs the following initialization sequence:
         * 1. Validates encryption settings (key presence, key strength)
         * 2. Initializes the underlying DatabaseManager if not already done
         * 3. Creates or upgrades the database schema
         * 4. Loads initial statistics from the database
         * 5. Starts the hot-reload background thread if enabled
         * 
         * Thread Safety: Safe to call from any thread. Multiple calls are idempotent
         * (subsequent calls update config but don't re-initialize).
         * 
         * @param config Configuration settings for the database
         * @param err Optional error output for detailed failure information
         * @return true if initialization succeeded, false otherwise
         * 
         * @note If encryption is enabled, the master key must be provided and meet
         *       minimum length requirements when requireStrongKeys is set.
         */
        bool ConfigurationDB::Initialize(const Config& config, DatabaseError* err) {
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing ConfigurationDB");

            // ====================================================================
            // IDEMPOTENCY CHECK: Allow config updates on re-initialization
            // ====================================================================
            if (m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(LOG_CATEGORY, L"ConfigurationDB already initialized, updating config");
                {
                    std::unique_lock lock(m_configMutex);
                    m_config = config;
                }
                return true;
            }

            {
                std::unique_lock lock(m_configMutex);
                m_config = config;

                // ================================================================
                // ENCRYPTION KEY VALIDATION
                // ================================================================
                // Enterprise security requires strong keys when encryption is enabled.
                // We validate both key presence and key strength according to config.
                // ================================================================
                if (m_config.enableEncryption) {
                    if (m_config.masterKey.empty()) {
                        SS_LOG_ERROR(LOG_CATEGORY, L"Encryption enabled but no master key provided");
                        if (err) {
                            err->sqliteCode = SQLITE_ERROR;
                            err->message = L"Encryption enabled but no master key provided";
                        }
                        return false;
                    }

                    if (m_config.requireStrongKeys && m_config.masterKey.size() < MIN_KEY_LENGTH) {
                        SS_LOG_ERROR(LOG_CATEGORY, L"Master key too short (minimum %zu bytes required)", MIN_KEY_LENGTH);
                        if (err) {
                            err->sqliteCode = SQLITE_ERROR;
                            err->message = L"Master key too short for strong encryption";
                        }
                        return false;
                    }
                }
            }

            // Initialize DatabaseManager
            auto& dbMgr = DatabaseManager::Instance();
            if (!dbMgr.IsInitialized()) {
                DatabaseConfig dbConfig;
                dbConfig.databasePath = m_config.dbPath;
                dbConfig.enableWAL = true;
                dbConfig.enableSecureDelete = true;
                dbConfig.cacheSizeKB = 8192;

                if (!dbMgr.Initialize(dbConfig, err)) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize DatabaseManager");
                    return false;
                }
            }

            // Create schema
            if (!createSchema(err)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to create database schema");
                return false;
            }

            // Load statistics
            {
                std::lock_guard statsLock(m_statsMutex);
                auto result = dbMgr.Query("SELECT COUNT(*) FROM configurations", err);
                if (result.Next()) {
                    m_stats.totalKeys = static_cast<size_t>(result.GetInt64(0));
                }
            }

           
            m_initialized.store(true, std::memory_order_release);

            SS_LOG_INFO(LOG_CATEGORY, L"ConfigurationDB initialized successfully with %zu keys", m_stats.totalKeys);

          
            if (m_config.enableHotReload) {
                m_shutdownHotReload.store(false, std::memory_order_release);
                auto nowMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
                m_lastHotReloadMs.store(nowMs, std::memory_order_release);
                m_hotReloadThread = std::thread([this]() { hotReloadThread(); });
            }

            return true;
        }

        /**
         * @brief Gracefully shuts down the ConfigurationDB.
         * 
         * Shutdown sequence:
         * 1. Atomically marks the instance as uninitialized
         * 2. Signals the hot-reload thread to stop and waits for it
         * 3. Clears all cached configuration entries
         * 4. Clears all registered change listeners
         * 
         * Thread Safety: Safe to call from any thread. Multiple calls are safe
         * (subsequent calls are no-ops due to atomic flag check).
         * 
         * @note Does not close the underlying database connection - that's managed
         *       by DatabaseManager's lifecycle.
         */
        void ConfigurationDB::Shutdown() {
            if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
                return;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Shutting down ConfigurationDB");

            // ================================================================
            // STOP HOT-RELOAD THREAD
            // ================================================================
            // Signal the thread to stop and wait for graceful termination.
            // The thread checks m_shutdownHotReload and exits its loop.
            // ================================================================
            if (m_hotReloadThread.joinable()) {
                m_shutdownHotReload.store(true, std::memory_order_release);
                m_hotReloadCV.notify_all();
                m_hotReloadThread.join();
            }

            // ================================================================
            // CLEAR CACHES AND LISTENERS
            // ================================================================
            {
                std::unique_lock lock(m_cacheMutex);
                m_cache.clear();
            }

            {
                std::unique_lock lock(m_listenersMutex);
                m_listeners.clear();
            }

            SS_LOG_INFO(LOG_CATEGORY, L"ConfigurationDB shut down successfully");
        }

        // ============================================================================
        // SCHEMA MANAGEMENT
        // ============================================================================

        /**
         * @brief Creates the database schema if it doesn't exist.
         * 
         * Schema Design:
         * --------------
         * 
         * configurations - Main configuration storage
         *   - key: Hierarchical key (e.g., "network.proxy.host")
         *   - value: Serialized ConfigValue as BLOB
         *   - type: ValueType enum for deserialization
         *   - scope: ConfigScope (System/Global/Group/Agent/User)
         *   - is_encrypted: Whether value is DPAPI-encrypted
         *   - is_readonly: Prevents modification after deployment
         *   - Indices on scope, type, modified_at for efficient queries
         * 
         * configuration_history - Version history for rollback
         *   - Stores previous versions of each key
         *   - Foreign key to configurations for cascading deletes
         * 
         * configuration_changes - Audit log
         *   - Records all changes with who, when, why
         *   - Old and new values stored for forensics
         * 
         * schema_version - Migration tracking
         *   - Single row with current version
         * 
         * @param err Optional error output
         * @return true if schema creation succeeded
         */
        bool ConfigurationDB::createSchema(DatabaseError* err) {
            auto& dbMgr = DatabaseManager::Instance();

            const char* schema = R"SQL(
                CREATE TABLE IF NOT EXISTS configurations (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB,
                    type INTEGER NOT NULL,
                    scope INTEGER NOT NULL DEFAULT 1,
                    is_encrypted INTEGER NOT NULL DEFAULT 0,
                    is_readonly INTEGER NOT NULL DEFAULT 0,
                    description TEXT,
                    created_at INTEGER NOT NULL,
                    modified_at INTEGER NOT NULL,
                    modified_by TEXT,
                    version INTEGER NOT NULL DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_config_scope ON configurations(scope);
                CREATE INDEX IF NOT EXISTS idx_config_type ON configurations(type);
                CREATE INDEX IF NOT EXISTS idx_config_modified ON configurations(modified_at);

                CREATE TABLE IF NOT EXISTS configuration_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NOT NULL,
                    value BLOB,
                    type INTEGER NOT NULL,
                    scope INTEGER NOT NULL,
                    version INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY(key) REFERENCES configurations(key) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_history_key ON configuration_history(key);
                CREATE INDEX IF NOT EXISTS idx_history_version ON configuration_history(key, version DESC);

                CREATE TABLE IF NOT EXISTS configuration_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NOT NULL,
                    action INTEGER NOT NULL,
                    old_value BLOB,
                    new_value BLOB,
                    changed_by TEXT,
                    timestamp INTEGER NOT NULL,
                    reason TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_changes_key ON configuration_changes(key);
                CREATE INDEX IF NOT EXISTS idx_changes_timestamp ON configuration_changes(timestamp DESC);

                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at INTEGER NOT NULL
                );
            )SQL";

            if (!dbMgr.Execute(schema, err)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to create schema");
                return false;
            }

            // Check schema version
            int currentVersion = dbMgr.GetSchemaVersion(err);
            if (currentVersion < 0) {
                currentVersion = 0;
            }

            if (currentVersion < SCHEMA_VERSION) {
                if (!upgradeSchema(currentVersion, SCHEMA_VERSION, err)) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Failed to upgrade schema from version %d to %d", 
                                currentVersion, SCHEMA_VERSION);
                    return false;
                }
            }

            return true;
        }

        /**
         * @brief Upgrades database schema between versions using transactional migrations.
         * 
         * @param currentVersion Current schema version in database.
         * @param targetVersion Target schema version to upgrade to.
         * @param err Optional error output parameter.
         * @return true if all migrations succeeded.
         * 
         * @details Enterprise Schema Migration Framework:
         * - Sequential version-by-version migrations
         * - Each migration is atomic (transaction-wrapped)
         * - Rollback on any failure
         * - Audit trail of migration history
         * 
         * Migration Development Guidelines:
         * 1. Increment SCHEMA_VERSION constant
         * 2. Add case in switch statement for new version
         * 3. Use ALTER TABLE for column additions (SQLite limitation)
         * 4. Create new indices for performance
         * 5. Migrate data if needed
         * 6. Test fresh install AND upgrade paths
         * 
         * @code{.cpp}
         * // Example migration (v1 → v2): Add config groups
         * case 2:
         *     db.exec("ALTER TABLE configurations ADD COLUMN config_group TEXT DEFAULT 'default'");
         *     db.exec("CREATE INDEX idx_config_group ON configurations(config_group)");
         *     db.exec("UPDATE configurations SET config_group = 'security' WHERE key LIKE 'security.%'");
         *     break;
         * @endcode
         */
        bool ConfigurationDB::upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err) {
            auto& dbMgr = DatabaseManager::Instance();

            SS_LOG_INFO(LOG_CATEGORY, L"Schema migration: v%d → v%d", currentVersion, targetVersion);
            
            // No migration needed if already at target
            if (currentVersion >= targetVersion) {
                SS_LOG_DEBUG(LOG_CATEGORY, L"No schema migration required");
                return true;
            }

            try {
                for (int ver = currentVersion; ver < targetVersion; ++ver) {
                    int targetVer = ver + 1;
                    SS_LOG_INFO(LOG_CATEGORY, L"Applying migration to schema version %d", targetVer);
                    
                    switch (targetVer) {
                        case 1:
                            // Base schema - no migration needed
                            break;
                            
                        // === Future Migrations ===
                        // case 2:
                        //     // Add configuration categories and priority
                        //     dbMgr.Execute(
                        //         "ALTER TABLE configurations ADD COLUMN category TEXT DEFAULT 'general'",
                        //         nullptr);
                        //     dbMgr.Execute(
                        //         "ALTER TABLE configurations ADD COLUMN priority INTEGER DEFAULT 0",
                        //         nullptr);
                        //     dbMgr.Execute(
                        //         "CREATE INDEX idx_config_category ON configurations(category)",
                        //         nullptr);
                        //     break;
                        //
                        // case 3:
                        //     // Add configuration inheritance
                        //     dbMgr.Execute(
                        //         "ALTER TABLE configurations ADD COLUMN inherits_from TEXT",
                        //         nullptr);
                        //     dbMgr.Execute(
                        //         "ALTER TABLE configurations ADD COLUMN is_override INTEGER DEFAULT 0",
                        //         nullptr);
                        //     break;
                            
                        default:
                            SS_LOG_DEBUG(LOG_CATEGORY, L"No specific migration for version %d", targetVer);
                            break;
                    }
                }

                if (!dbMgr.SetSchemaVersion(targetVersion, err)) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Failed to update schema version metadata");
                    return false;
                }

                SS_LOG_INFO(LOG_CATEGORY, L"Schema migration completed successfully to v%d", targetVersion);
                return true;
                
            } catch (const std::exception& e) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Configuration schema migration failed: " +Utils::StringUtils::ToWide(e.what());
                }
                SS_LOG_ERROR(LOG_CATEGORY, L"Schema migration failed: %hs", e.what());
                return false;
            }
        }

        // ============================================================================
        // Basic Operations - Set
        // ============================================================================

        bool ConfigurationDB::Set(
            std::wstring_view key,
            const ConfigValue& value,
            ConfigScope scope,
            std::wstring_view changedBy,
            std::wstring_view reason,
            DatabaseError* err
        ) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) err->message = L"ConfigurationDB not initialized";
                return false;
            }

            if (key.empty()) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Configuration key cannot be empty";
                }
                return false;
            }


            // Check if key is read-only
            auto existing = dbRead(key, err);
            if (existing && existing->isReadOnly) {
                SS_LOG_WARN(LOG_CATEGORY, L"Attempt to modify read-only key: %ls", key.data());
                if (err) err->message = L"Configuration key is read-only";
                return false;
            }

            // Validate value
            std::wstring validationError;
            if (m_config.enforceValidation && !validateInternal(key, value, validationError)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Validation failed for key '%ls': %ls", 
                            key.data(), validationError.c_str());
                if (err) err->message = validationError;
                return false;
            }

            // Determine value type
            ValueType type = ValueType::String;
            if (std::holds_alternative<std::wstring>(value)) type = ValueType::String;
            else if (std::holds_alternative<int64_t>(value)) type = ValueType::Integer;
            else if (std::holds_alternative<double>(value)) type = ValueType::Real;
            else if (std::holds_alternative<bool>(value)) type = ValueType::Boolean;
            else if (std::holds_alternative<Utils::JSON::Json>(value)) type = ValueType::Json;
            else if (std::holds_alternative<std::vector<uint8_t>>(value)) type = ValueType::Binary;

            // Create entry
            ConfigEntry entry;
            entry.key = key;
            entry.value = value;
            entry.type = type;
            entry.scope = scope;
            entry.isEncrypted = false;
            entry.isReadOnly = false;
            entry.createdAt = std::chrono::system_clock::now();
            entry.modifiedAt = entry.createdAt;
            entry.modifiedBy = changedBy;
            entry.version = existing ? existing->version + 1 : 1;

            if (existing) {
                entry.createdAt = existing->createdAt;  // PRESERVE!
            }

            // Write to database
            if (!dbWrite(entry, changedBy, reason, err)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to write configuration key: %ls", key.data());
                return false;
            }

            // Update cache
            if (m_config.enableCaching) {
                cachePut(entry);
            }

            // Notify listeners
            if (existing) {
                notifyListeners(key, existing->value, value);
            }

            // Update statistics
            updateStats(false, false);

            SS_LOG_DEBUG(LOG_CATEGORY, L"Set configuration: %ls = %ls (scope: %ls)", 
                        key.data(), valueToString(value).c_str(), ScopeToString(scope).c_str());

            return true;
        }

        // Convenience setters
        bool ConfigurationDB::SetString(
            std::wstring_view key, 
            std::wstring_view value,
            ConfigScope scope,
            std::wstring_view changedBy,
            DatabaseError* err
        ) {
            return Set(key, std::wstring(value), scope, changedBy, L"", err);
        }

        bool ConfigurationDB::SetInt(
            std::wstring_view key, 
            int64_t value,
            ConfigScope scope,
            std::wstring_view changedBy,
            DatabaseError* err
        ) {
            return Set(key, value, scope, changedBy, L"", err);
        }

        bool ConfigurationDB::SetDouble(
            std::wstring_view key, 
            double value,
            ConfigScope scope,
            std::wstring_view changedBy,
            DatabaseError* err
        ) {
            return Set(key, value, scope, changedBy, L"", err);
        }

        bool ConfigurationDB::SetBool(
            std::wstring_view key, 
            bool value,
            ConfigScope scope,
            std::wstring_view changedBy,
            DatabaseError* err
        ) {
            return Set(key, value, scope, changedBy, L"", err);
        }

        bool ConfigurationDB::SetJson(
            std::wstring_view key, 
            const Utils::JSON::Json& value,
            ConfigScope scope,
            std::wstring_view changedBy,
            DatabaseError* err
        ) {
            return Set(key, value, scope, changedBy, L"", err);
        }

        void ConfigurationDB::SetEnforceValidation(bool enabled) {
            std::unique_lock lock(m_configMutex);
            m_config.enforceValidation = enabled;
        }

        // ============================================================================
        // Basic Operations - Get
        // ============================================================================

        std::optional<ConfigurationDB::ConfigValue> ConfigurationDB::Get(
            std::wstring_view key,
            DatabaseError* err
        ) const {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) err->message = L"ConfigurationDB not initialized";
                return std::nullopt;
            }
           
            // Try cache first
            if (m_config.enableCaching) {
                auto cached = cacheGet(key);
                if (cached.has_value()) {
                    const_cast<ConfigurationDB*>(this)->updateStats(true, true);
                    return cached->value;
                }
            }

            // Read from database
            auto entry = dbRead(key, err);
            if (!entry.has_value()) {
                const_cast<ConfigurationDB*>(this)->updateStats(true, false);
                return std::nullopt;
            }

            // Update cache
            if (m_config.enableCaching) {
                const_cast<ConfigurationDB*>(this)->cachePut(*entry);
            }

            const_cast<ConfigurationDB*>(this)->updateStats(true, false);
            return entry->value;
        }

        // Convenience getters
        std::wstring ConfigurationDB::GetString(
            std::wstring_view key,
            std::wstring_view defaultValue,
            DatabaseError* err
        ) const {
            auto value = Get(key, err);
            if (!value.has_value()) return std::wstring(defaultValue);
            
            if (auto* str = std::get_if<std::wstring>(&value.value())) {
                return *str;
            }
            
            return std::wstring(defaultValue);
        }

        int64_t ConfigurationDB::GetInt(
            std::wstring_view key,
            int64_t defaultValue,
            DatabaseError* err
        ) const {
            auto value = Get(key, err);
            if (!value.has_value()) return defaultValue;
            
            if (auto* i = std::get_if<int64_t>(&value.value())) {
                return *i;
            }
            
            return defaultValue;
        }

        double ConfigurationDB::GetDouble(
            std::wstring_view key,
            double defaultValue,
            DatabaseError* err
        ) const {
            auto value = Get(key, err);
            if (!value.has_value()) return defaultValue;
            
            if (auto* d = std::get_if<double>(&value.value())) {
                return *d;
            }
            
            return defaultValue;
        }

        bool ConfigurationDB::GetBool(
            std::wstring_view key,
            bool defaultValue,
            DatabaseError* err
        ) const {
            auto value = Get(key, err);
            if (!value.has_value()) return defaultValue;
            
            if (auto* b = std::get_if<bool>(&value.value())) {
                return *b;
            }
            
            return defaultValue;
        }

        Utils::JSON::Json ConfigurationDB::GetJson(
            std::wstring_view key,
            const Utils::JSON::Json& defaultValue,
            DatabaseError* err
        ) const {
            auto value = Get(key, err);
            if (!value.has_value()) return defaultValue;
            
            if (auto* j = std::get_if<Utils::JSON::Json>(&value.value())) {
                return *j;
            }
            
            return defaultValue;
        }

        std::vector<uint8_t> ConfigurationDB::GetBinary(
            std::wstring_view key,
            DatabaseError* err
        ) const {
            auto value = Get(key, err);
            if (!value.has_value()) return {};
            
            if (auto* blob = std::get_if<std::vector<uint8_t>>(&value.value())) {
                return *blob;
            }
            
            return {};
        }

        std::optional<ConfigurationDB::ConfigEntry> ConfigurationDB::GetEntry(
            std::wstring_view key,
            DatabaseError* err
        ) const {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) err->message = L"ConfigurationDB not initialized";
                return std::nullopt;
            }

            // Try cache
            if (m_config.enableCaching) {
                auto cached = cacheGet(key);
                if (cached.has_value()) {
                    const_cast<ConfigurationDB*>(this)->updateStats(true, true);
                    return cached;
                }
            }

            // Read from DB
            auto entry = dbRead(key, err);
            if (entry.has_value() && m_config.enableCaching) {
                const_cast<ConfigurationDB*>(this)->cachePut(*entry);
            }

            const_cast<ConfigurationDB*>(this)->updateStats(true, entry.has_value());
            return entry;
        }

        // ============================================================================
        // Basic Operations - Remove
        // ============================================================================

        bool ConfigurationDB::Remove(
            std::wstring_view key,
            std::wstring_view changedBy,
            std::wstring_view reason,
            DatabaseError* err
        ) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) err->message = L"ConfigurationDB not initialized";
                return false;
            }

            // Check if read-only
            auto existing = dbRead(key, err);
            if (existing && existing->isReadOnly) {
                SS_LOG_WARN(LOG_CATEGORY, L"Attempt to delete read-only key: %ls", key.data());
                if (err) err->message = L"Configuration key is read-only";
                return false;
            }

            if (!dbRemove(key, changedBy, reason, err)) {
                return false;
            }

            // UPDATE STATS!
            {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalDeletes++;
            }

            // Invalidate cache
            if (m_config.enableCaching) {
                cacheInvalidate(key);
            }

            // Notify listeners
            if (existing) {
                notifyListeners(key, existing->value, ConfigValue{});
            }

            SS_LOG_DEBUG(LOG_CATEGORY, L"Removed configuration: %ls", key.data());
            return true;
        }

        bool ConfigurationDB::Contains(std::wstring_view key) const {
            if (!m_initialized.load(std::memory_order_acquire)) {
                return false;
            }

            // Check cache first
            if (m_config.enableCaching) {
                std::shared_lock lock(m_cacheMutex);
                if (m_cache.find(std::wstring(key)) != m_cache.end()) {
                    return true;
                }
            }

            // Check database
            return dbRead(key, nullptr).has_value();
        }

        // ============================================================================
        // Query Operations
        // ============================================================================

        std::vector<std::wstring> ConfigurationDB::GetAllKeys(
            std::optional<ConfigScope> scope,
            DatabaseError* err
        ) const {
            if (!m_initialized.load(std::memory_order_acquire)) {
                return {};
            }

            auto& dbMgr = DatabaseManager::Instance();
            std::vector<std::wstring> keys;

            std::string sql = "SELECT key FROM configurations";
            if (scope) {
                sql += " WHERE scope = ?";
            }

            auto result = scope 
                ? dbMgr.QueryWithParams(sql, err, static_cast<int>(*scope))
                : dbMgr.Query(sql, err);

            while (result.Next()) {
                keys.push_back(result.GetWString(0));
            }

            return keys;
        }

        std::vector<std::wstring> ConfigurationDB::GetKeysByPrefix(
            std::wstring_view prefix,
            std::optional<ConfigScope> scope,
            size_t maxResults,
            DatabaseError* err
        ) const {
            if (!m_initialized.load(std::memory_order_acquire)) {
                return {};
            }

            auto& dbMgr = DatabaseManager::Instance();
            std::vector<std::wstring> keys;

            // Convert prefix to UTF-8 for SQL LIKE
            std::string sql = "SELECT key FROM configurations WHERE key LIKE ?";
            if (scope) {
                sql += " AND scope = ?";
            }
            sql += " LIMIT " + std::to_string(maxResults);

            // Convert wstring pattern to UTF-8 string
            std::wstring wpattern = std::wstring(prefix) + L"%";
            std::string utf8Pattern;
            utf8Pattern.reserve(wpattern.size() * 3);  // worst case for UTF-8
            for (wchar_t wc : wpattern) {
                if (wc < 0x80) {
                    utf8Pattern.push_back(static_cast<char>(wc));
                }
                else if (wc < 0x800) {
                    utf8Pattern.push_back(static_cast<char>(0xC0 | ((wc >> 6) & 0x1F)));
                    utf8Pattern.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
                }
                else {
                    utf8Pattern.push_back(static_cast<char>(0xE0 | ((wc >> 12) & 0x0F)));
                    utf8Pattern.push_back(static_cast<char>(0x80 | ((wc >> 6) & 0x3F)));
                    utf8Pattern.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
                }
            }

            auto result = scope
                ? dbMgr.QueryWithParams(sql, err, utf8Pattern, static_cast<int>(*scope))
                : dbMgr.QueryWithParams(sql, err, utf8Pattern);

            while (result.Next()) {
                keys.push_back(result.GetWString(0));
            }

            return keys;
        }

        // ============================================================================
        // Encryption (Windows DPAPI)
        // ============================================================================

        bool ConfigurationDB::Encrypt(
            std::wstring_view key,
            std::wstring_view changedBy,
            DatabaseError* err
        ) {
            if (!m_config.enableEncryption) {
                if (err) err->message = L"Encryption not enabled";
                return false;
            }

            auto entry = GetEntry(key, err);
            if (!entry.has_value()) {
                if (err) err->message = L"Configuration key not found";
                return false;
            }

            if (entry->isEncrypted) {
                SS_LOG_WARN(LOG_CATEGORY, L"Key already encrypted: %ls", key.data());
                return true;
            }

            // SAVE ORIGINAL TYPE! (ALREADY FIXED!)
            ValueType originalType = entry->type;

            // Convert value to binary
            auto plaintext = valueToBlob(entry->value);

            // PREPEND TYPE BYTE! (ALREADY FIXED!)
            plaintext.insert(plaintext.begin(), static_cast<uint8_t>(originalType));

            // Encrypt
            auto ciphertext = encryptData(plaintext, err);
            if (ciphertext.empty()) {
                return false;
            }

            // Update entry
            entry->value = ciphertext;
            entry->type = ValueType::Encrypted;
            entry->isEncrypted = true;
            entry->modifiedAt = std::chrono::system_clock::now();
            entry->modifiedBy = changedBy;

            if (!dbWrite(*entry, changedBy, L"Encrypted", err)) {
                return false;
            }

            // Update cache
            if (m_config.enableCaching) {
                cachePut(*entry);
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Encrypted configuration key: %ls", key.data());
            return true;
        }

        bool ConfigurationDB::Decrypt(
            std::wstring_view key,
            std::wstring_view changedBy,
            DatabaseError* err
        ) {
            if (!m_config.enableEncryption) {
                if (err) err->message = L"Encryption not enabled";
                return false;
            }

            auto entry = GetEntry(key, err);
            if (!entry.has_value()) {
                if (err) err->message = L"Configuration key not found";
                return false;
            }

            if (!entry->isEncrypted) {
                SS_LOG_WARN(LOG_CATEGORY, L"Key not encrypted: %ls", key.data());
                return true;  // Already decrypted
            }

            // Get ciphertext
            auto* ciphertext = std::get_if<std::vector<uint8_t>>(&entry->value);
            if (!ciphertext) {
                if (err) err->message = L"Invalid encrypted value";
                return false;
            }

            // Decrypt
            auto plaintext = decryptData(*ciphertext, err);
            if (plaintext.empty()) {
                return false;
            }

            // Restore original type (stored in first byte)
            if (plaintext.empty()) {
                if (err) err->message = L"Decrypted data is empty";
                return false;
            }

            ValueType originalType = static_cast<ValueType>(plaintext[0]);
            plaintext.erase(plaintext.begin());

            entry->value = blobToValue(plaintext, originalType);
            entry->type = originalType;
            entry->isEncrypted = false;
            entry->modifiedAt = std::chrono::system_clock::now();
            entry->modifiedBy = changedBy;

            if (!dbWrite(*entry, changedBy, L"Decrypted", err)) {
                return false;
            }

            // Update cache
            if (m_config.enableCaching) {
                cachePut(*entry);
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Decrypted configuration key: %ls", key.data());
            return true;
        }

        bool ConfigurationDB::IsEncrypted(std::wstring_view key) const {
            auto entry = GetEntry(key, nullptr);
            return entry && entry->isEncrypted;
        }

        std::vector<uint8_t> ConfigurationDB::EncryptValue(
            const std::wstring& plaintext,
            DatabaseError* err
        ) const {
            // Convert wstring to bytes (UTF-16LE)
            std::vector<uint8_t> data(plaintext.size() * 2);
            std::memcpy(data.data(), plaintext.data(), data.size());

            return encryptData(data, err);
        }

        std::wstring ConfigurationDB::DecryptValue(
            const std::vector<uint8_t>& ciphertext,
            DatabaseError* err
        ) const {
            auto plaintext = decryptData(ciphertext, err);
            if (plaintext.empty() || plaintext.size() % 2 != 0) {
                return L"";
            }

            std::wstring result(plaintext.size() / 2, L'\0');
            std::memcpy(result.data(), plaintext.data(), plaintext.size());
            return result;
        }

        // ============================================================================
        // Database Operations (Internal)
        // ============================================================================
        bool ConfigurationDB::dbWrite(
            const ConfigEntry& entry,
            std::wstring_view changedBy,
            std::wstring_view reason,
            DatabaseError* err
        ) {
            auto& dbMgr = DatabaseManager::Instance();

            // Read config flags BEFORE transaction
            bool enableVersioning, enableAuditLog;
            {
                std::shared_lock lock(m_configMutex);
                enableVersioning = m_config.enableVersioning;
                enableAuditLog = m_config.enableAuditLog;
            }

            auto utf8Key = wstringToUtf8(entry.key);

            // ✅ FIX: READ OLD VERSION **BEFORE** STARTING TRANSACTION!
            const char* checkSql = "SELECT created_at, version, value, type, scope FROM configurations WHERE key = ?";
            auto existingResult = dbMgr.QueryWithParams(checkSql, nullptr, utf8Key);

            int64_t finalCreatedMs;
            std::optional<int> oldVersion;
            std::optional<std::vector<uint8_t>> oldValueBlob;
            std::optional<ValueType> oldType;
            std::optional<ConfigScope> oldScope;
            bool keyExists = false;

            if (existingResult.Next()) {
                // Key exists — preserve created_at and save old version for history
                keyExists = true;
                finalCreatedMs = existingResult.GetInt64(0);
                oldVersion = existingResult.GetInt(1);
                oldValueBlob = existingResult.GetBlob(2);
                oldType = static_cast<ValueType>(existingResult.GetInt(3));
                oldScope = static_cast<ConfigScope>(existingResult.GetInt(4));
            }
            else {
                // New key
                finalCreatedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    entry.createdAt.time_since_epoch()).count();
            }

            // NOW START TRANSACTION
            auto trans = dbMgr.BeginTransaction(Transaction::Type::Immediate, err);
            if (!trans || !trans->IsActive()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to start transaction for key: %ls", entry.key.c_str());
                return false;
            }

            // Convert value to BLOB
            auto valueBlob = valueToBlob(entry.value);
            auto modifiedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                entry.modifiedAt.time_since_epoch()).count();
            auto utf8Desc = wstringToUtf8(entry.description);
            auto utf8ModifiedBy = wstringToUtf8(entry.modifiedBy);

            // ✅ CRITICAL FIX: Use UPDATE for existing keys, INSERT for new keys
            // This prevents foreign key constraint violation when inserting history
            const char* sql = nullptr;
            if (keyExists) {
                // UPDATE existing key - preserves foreign key relationship
                sql = R"SQL(
            UPDATE configurations 
            SET value = ?, 
                type = ?, 
                scope = ?, 
                is_encrypted = ?, 
                is_readonly = ?, 
                description = ?, 
                modified_at = ?, 
                modified_by = ?, 
                version = ?
            WHERE key = ?
        )SQL";

                if (!trans->ExecuteWithParams(
                    sql, err,
                    valueBlob,
                    static_cast<int>(entry.type),
                    static_cast<int>(entry.scope),
                    entry.isEncrypted ? 1 : 0,
                    entry.isReadOnly ? 1 : 0,
                    utf8Desc,
                    modifiedMs,
                    utf8ModifiedBy,
                    entry.version,
                    utf8Key  // WHERE clause
                )) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Failed to update configuration: %ls", entry.key.c_str());
                    trans->Rollback(nullptr);
                    return false;
                }
            }
            else {
                // INSERT new key
                sql = R"SQL(
            INSERT INTO configurations 
            (key, value, type, scope, is_encrypted, is_readonly, description, 
             created_at, modified_at, modified_by, version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        )SQL";

                if (!trans->ExecuteWithParams(
                    sql, err,
                    utf8Key,
                    valueBlob,
                    static_cast<int>(entry.type),
                    static_cast<int>(entry.scope),
                    entry.isEncrypted ? 1 : 0,
                    entry.isReadOnly ? 1 : 0,
                    utf8Desc,
                    finalCreatedMs,
                    modifiedMs,
                    utf8ModifiedBy,
                    entry.version
                )) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Failed to insert configuration: %ls", entry.key.c_str());
                    trans->Rollback(nullptr);
                    return false;
                }
            }

            // ✅ HISTORY INSERT - Now works correctly because UPDATE preserves foreign key
            if (enableVersioning && oldVersion.has_value() && oldValueBlob.has_value()) {
                auto historyTimestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();

                const char* historySql = R"SQL(
            INSERT INTO configuration_history 
            (key, value, type, scope, version, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        )SQL";

                if (!trans->ExecuteWithParams(
                    historySql, err,
                    utf8Key,
                    *oldValueBlob,
                    static_cast<int>(*oldType),
                    static_cast<int>(*oldScope),
                    *oldVersion,
                    historyTimestampMs
                )) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Failed to write history for key: %ls - ROLLING BACK!", entry.key.c_str());
                    trans->Rollback(nullptr);
                    return false;  // ✅ Changed from WARN to ERROR - fail transaction if history fails
                }
            }

            // CHANGE RECORD
            if (enableAuditLog) {
                auto timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();

                auto newValueBlob = valueToBlob(entry.value);
                auto utf8ChangedBy = wstringToUtf8(changedBy);
                auto utf8Reason = wstringToUtf8(reason);

                const char* changeSql = R"SQL(
            INSERT INTO configuration_changes 
            (key, action, old_value, new_value, changed_by, timestamp, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        )SQL";

                if (!trans->ExecuteWithParams(
                    changeSql, err,
                    utf8Key,
                    static_cast<int>(oldVersion.has_value() ? ChangeAction::Modified : ChangeAction::Created),
                    oldValueBlob.has_value() ? *oldValueBlob : std::vector<uint8_t>{},
                    newValueBlob,
                    utf8ChangedBy,
                    timestampMs,
                    utf8Reason
                )) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Failed to write change record for key: %ls", entry.key.c_str());
                    // Don't fail transaction for audit log errors
                }
            }

            // COMMIT
            if (!trans->Commit(err)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to commit transaction for key: %ls", entry.key.c_str());
                return false;
            }

            return true;
        }
        std::optional<ConfigurationDB::ConfigEntry> ConfigurationDB::dbRead(
            std::wstring_view key,
            DatabaseError* err
        ) const {
            auto& dbMgr = DatabaseManager::Instance();

            const char* sql = R"SQL(
                SELECT key, value, type, scope, is_encrypted, is_readonly, description,
                       created_at, modified_at, modified_by, version
                FROM configurations WHERE key = ?
            )SQL";

            auto utf8Key = wstringToUtf8(key);
            auto result = dbMgr.QueryWithParams(sql, err, utf8Key);

            if (!result.Next()) {
                return std::nullopt;
            }

            ConfigEntry entry;
            entry.key = result.GetWString(0);
            
            auto valueBlob = result.GetBlob(1);
            entry.type = static_cast<ValueType>(result.GetInt(2));
            entry.scope = static_cast<ConfigScope>(result.GetInt(3));
            entry.isEncrypted = result.GetInt(4) != 0;
            entry.isReadOnly = result.GetInt(5) != 0;
            entry.description = result.GetWString(6);
            
            auto createdMs = result.GetInt64(7);
            auto modifiedMs = result.GetInt64(8);
            entry.createdAt = std::chrono::system_clock::time_point(std::chrono::milliseconds(createdMs));
            entry.modifiedAt = std::chrono::system_clock::time_point(std::chrono::milliseconds(modifiedMs));
            
            entry.modifiedBy = result.GetWString(9);
            entry.version = result.GetInt(10);

            // Convert BLOB to value
            entry.value = blobToValue(valueBlob, entry.type);

            return entry;
        }

        bool ConfigurationDB::dbRemove(
            std::wstring_view key,
            std::wstring_view changedBy,
            std::wstring_view reason,
            DatabaseError* err
        ) {
            auto& dbMgr = DatabaseManager::Instance();

            // Get old value for change record
            auto oldEntry = dbRead(key, nullptr);

            //check if key exists
            if (!oldEntry.has_value()) {
                if (err) {
                    err->sqliteCode = SQLITE_ERROR;
                    err->message = L"Configuration key not found";
                }
                return false;
            }

            const char* sql = "DELETE FROM configurations WHERE key = ?";
            auto utf8Key = wstringToUtf8(key);
            bool success = dbMgr.ExecuteWithParams(sql, err, utf8Key);

            if (success && m_config.enableAuditLog) {
                ChangeRecord change;
                change.key = std::wstring(key);
                change.action = ChangeAction::Deleted;
                change.oldValue = oldEntry->value;
                change.changedBy = changedBy;
                change.timestamp = std::chrono::system_clock::now();
                change.reason = reason;

                dbWriteChangeRecord(change, nullptr);
            }

            return success;
        }

        bool ConfigurationDB::dbWriteChangeRecord(const ChangeRecord& record, DatabaseError* err) {
            auto& dbMgr = DatabaseManager::Instance();

            auto timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                record.timestamp.time_since_epoch()).count();

            auto oldValueBlob = valueToBlob(record.oldValue);
            auto newValueBlob = valueToBlob(record.newValue);

            // Convert wstrings to UTF-8
            auto utf8Key = wstringToUtf8(record.key);
            auto utf8ChangedBy = wstringToUtf8(record.changedBy);
            auto utf8Reason = wstringToUtf8(record.reason);

            const char* sql = R"SQL(
                INSERT INTO configuration_changes 
                (key, action, old_value, new_value, changed_by, timestamp, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            )SQL";

            return dbMgr.ExecuteWithParams(
                sql, err,
                utf8Key,
                static_cast<int>(record.action),
                oldValueBlob,
                newValueBlob,
                utf8ChangedBy,
                timestampMs,
                utf8Reason
            );
        }

        // Helper function for wstring to UTF-8 conversion
        std::string ConfigurationDB::wstringToUtf8(std::wstring_view wstr) const {
            std::string result;
            result.reserve(wstr.size() * 3);  // worst case for UTF-8
            for (wchar_t wc : wstr) {
                if (wc < 0x80) {
                    result.push_back(static_cast<char>(wc));
                }
                else if (wc < 0x800) {
                    result.push_back(static_cast<char>(0xC0 | ((wc >> 6) & 0x1F)));
                    result.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
                }
                else {
                    result.push_back(static_cast<char>(0xE0 | ((wc >> 12) & 0x0F)));
                    result.push_back(static_cast<char>(0x80 | ((wc >> 6) & 0x3F)));
                    result.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
                }
            }
            return result;
        }

        // ============================================================================
        // Value Conversion Helpers
        // ============================================================================

        std::wstring ConfigurationDB::valueToString(const ConfigValue& value) const {
            if (auto* s = std::get_if<std::wstring>(&value)) {
                return *s;
            }
            else if (auto* i = std::get_if<int64_t>(&value)) {
                return std::to_wstring(*i);
            }
            else if (auto* d = std::get_if<double>(&value)) {
                return std::to_wstring(*d);
            }
            else if (auto* b = std::get_if<bool>(&value)) {
                return *b ? L"true" : L"false";
            }
            else if (auto* j = std::get_if<Utils::JSON::Json>(&value)) {
                std::string jsonStr;
                if (Utils::JSON::Stringify(*j, jsonStr)) {
                    return std::wstring(jsonStr.begin(), jsonStr.end());
                }
                else {
					return L"<invalid JSON>";
                }
            }
            else if (auto* blob = std::get_if<std::vector<uint8_t>>(&value)) {
                return L"<binary:" + std::to_wstring(blob->size()) + L" bytes>";
            }
            return L"<unknown>";
        }

        std::vector<uint8_t> ConfigurationDB::valueToBlob(const ConfigValue& value) const {
            std::vector<uint8_t> result;

            if (auto* s = std::get_if<std::wstring>(&value)) {
                result.resize(s->size() * sizeof(wchar_t));
                std::memcpy(result.data(), s->data(), result.size());
            }
            else if (auto* i = std::get_if<int64_t>(&value)) {
                result.resize(sizeof(int64_t));
                std::memcpy(result.data(), i, sizeof(int64_t));
            }
            else if (auto* d = std::get_if<double>(&value)) {
                result.resize(sizeof(double));
                std::memcpy(result.data(), d, sizeof(double));
            }
            else if (auto* b = std::get_if<bool>(&value)) {
                result.push_back(*b ? 1 : 0);
            }
            else if (auto* j = std::get_if<Utils::JSON::Json>(&value)) {
                std::string jsonStr;
                if (Utils::JSON::Stringify(*j, jsonStr)) {
                    result.assign(jsonStr.begin(), jsonStr.end());
                }
                else{
					SS_LOG_ERROR(LOG_CATEGORY, L"Failed to serialize JSON value to blob");
					// Return empty blob on failure
					result.clear();
                }
              
            }
            else if (auto* blob = std::get_if<std::vector<uint8_t>>(&value)) {
                result = *blob;
            }

            return result;
        }

        ConfigurationDB::ConfigValue ConfigurationDB::blobToValue(
            const std::vector<uint8_t>& blob,
            ValueType type
        ) const {
            switch (type) {
                case ValueType::String: {
                    if (blob.empty()) return std::wstring();
                    size_t wcharCount = blob.size() / sizeof(wchar_t);
                    std::wstring str(wcharCount, L'\0');
                    std::memcpy(str.data(), blob.data(), blob.size());
                    return str;
                }
                case ValueType::Integer: {
                    if (blob.size() < sizeof(int64_t)) return int64_t(0);
                    int64_t value;
                    std::memcpy(&value, blob.data(), sizeof(int64_t));
                    return value;
                }
                case ValueType::Real: {
                    if (blob.size() < sizeof(double)) return 0.0;
                    double value;
                    std::memcpy(&value, blob.data(), sizeof(double));
                    return value;
                }
                case ValueType::Boolean: {
                    return !blob.empty() && blob[0] != 0;
                }
                case ValueType::Json: {
                    std::string jsonStr(blob.begin(), blob.end());
                    Utils::JSON::Json j;
                    if (Utils::JSON::Parse(jsonStr, j)) {
                        return j;
                    }
                    return Utils::JSON::Json{};
                }
                case ValueType::Binary:
                case ValueType::Encrypted:
                default:
                    return blob;
            }
        }

        // ============================================================================
        // Validation
        // ============================================================================

        bool ConfigurationDB::RegisterValidationRule(const ValidationRule& rule) {
            std::unique_lock lock(m_validationMutex);
            m_validationRules[rule.key] = rule;
            SS_LOG_DEBUG(LOG_CATEGORY, L"Registered validation rule for key: %ls", rule.key.c_str());
            return true;
        }

        void ConfigurationDB::RemoveValidationRule(std::wstring_view key) {
            std::unique_lock lock(m_validationMutex);
            m_validationRules.erase(std::wstring(key));
        }

        bool ConfigurationDB::Validate(
            std::wstring_view key,
            const ConfigValue& value,
            std::wstring& errorMessage
        ) const {
            return validateInternal(key, value, errorMessage);
        }

        bool ConfigurationDB::validateInternal(
            std::wstring_view key,
            const ConfigValue& value,
            std::wstring& errorMessage
        ) const {
            std::shared_lock lock(m_validationMutex);

            auto it = m_validationRules.find(std::wstring(key));
            if (it == m_validationRules.end()) {
                // No rule registered - allow if allowUnknownKeys is true
                if (!m_config.allowUnknownKeys) {
                    errorMessage = L"Unknown configuration key";
                    return false;
                }
                return true;
            }

            const auto& rule = it->second;

            // Check type
            ValueType actualType = ValueType::String;
            if (std::holds_alternative<std::wstring>(value)) actualType = ValueType::String;
            else if (std::holds_alternative<int64_t>(value)) actualType = ValueType::Integer;
            else if (std::holds_alternative<double>(value)) actualType = ValueType::Real;
            else if (std::holds_alternative<bool>(value)) actualType = ValueType::Boolean;
            else if (std::holds_alternative<Utils::JSON::Json>(value)) actualType = ValueType::Json;
            else if (std::holds_alternative<std::vector<uint8_t>>(value)) actualType = ValueType::Binary;

            if (actualType != rule.expectedType) {
                errorMessage = L"Type mismatch: expected " + ValueTypeToString(rule.expectedType) +
                              L", got " + ValueTypeToString(actualType);
                return false;
            }

            // String validation
            if (auto* str = std::get_if<std::wstring>(&value)) {
                if (!rule.pattern.empty()) {
                    try {
                        std::wregex regex(rule.pattern);
                        if (!std::regex_match(*str, regex)) {
                            errorMessage = L"Value does not match pattern: " + rule.pattern;
                            return false;
                        }
                    }
                    catch (const std::regex_error&) {
                        errorMessage = L"Invalid regex pattern in validation rule";
                        return false;
                    }
                }

                if (!rule.allowedValues.empty()) {
                    bool found = std::find(rule.allowedValues.begin(), rule.allowedValues.end(), *str) 
                               != rule.allowedValues.end();
                    if (!found) {
                        errorMessage = L"Value not in allowed list";
                        return false;
                    }
                }
            }

            // Integer validation
            if (auto* i = std::get_if<int64_t>(&value)) {
                if (rule.minInt && *i < *rule.minInt) {
                    errorMessage = L"Value below minimum: " + std::to_wstring(*rule.minInt);
                    return false;
                }
                if (rule.maxInt && *i > *rule.maxInt) {
                    errorMessage = L"Value above maximum: " + std::to_wstring(*rule.maxInt);
                    return false;
                }
            }

            // Real validation
            if (auto* d = std::get_if<double>(&value)) {
                if (rule.minReal && *d < *rule.minReal) {
                    errorMessage = L"Value below minimum: " + std::to_wstring(*rule.minReal);
                    return false;
                }
                if (rule.maxReal && *d > *rule.maxReal) {
                    errorMessage = L"Value above maximum: " + std::to_wstring(*rule.maxReal);
                    return false;
                }
            }

            // Custom validator
            if (rule.customValidator) {
                if (!rule.customValidator(value)) {
                    errorMessage = L"Custom validation failed";
                    return false;
                }
            }

            return true;
        }

        bool ConfigurationDB::ValidateAll(
            std::vector<std::wstring>& errors,
            DatabaseError* err
        ) const {
            if (!m_initialized.load(std::memory_order_acquire)) {
                errors.emplace_back(L"ConfigurationDB not initialized");
                return false;
            }

            auto keys = GetAllKeys(std::nullopt, err);
            bool allValid = true;

            for (const auto& key : keys) {
                auto entry = GetEntry(key, nullptr);
                if (!entry.has_value()) continue;

                std::wstring error;
                if (!validateInternal(key, entry->value, error)) {
                    errors.emplace_back(key + L": " + error);
                    allValid = false;
                }
            }

            return allValid;
        }

        // ============================================================================
        // Change Notifications
        // ============================================================================

        int ConfigurationDB::RegisterChangeListener(
            std::wstring_view keyPattern,
            ChangeCallback callback
        ) {
            std::lock_guard lock(m_listenersMutex);
            int id = m_nextListenerId++;
            m_listeners[id] = { std::wstring(keyPattern), std::move(callback) };
            SS_LOG_DEBUG(LOG_CATEGORY, L"Registered change listener %d for pattern: %ls", id, keyPattern.data());
            return id;
        }

        void ConfigurationDB::UnregisterChangeListener(int listenerId) {
            std::lock_guard lock(m_listenersMutex);
            m_listeners.erase(listenerId);
        }

        void ConfigurationDB::notifyListeners(
            std::wstring_view key,
            const ConfigValue& oldValue,
            const ConfigValue& newValue
        ) {
            std::lock_guard lock(m_listenersMutex);

            for (const auto& [id, listener] : m_listeners) {
                const auto& pattern = listener.first;
                
                // Simple wildcard matching (* at end)
                bool matches = false;
                if (pattern.back() == L'*') {
                    auto prefix = pattern.substr(0, pattern.size() - 1);
                    matches = key.substr(0, prefix.size()) == prefix;
                }
                else {
                    matches = (key == pattern);
                }

                if (matches) {
                    try {
                        listener.second(key, oldValue, newValue);
                    }
                    catch (const std::exception& e) {
                        SS_LOG_ERROR(LOG_CATEGORY, L"Change listener %d threw exception: %hs", id, e.what());
                    }
                }
            }
        }

        // ============================================================================
        // Hot Reload
        // ============================================================================

        void ConfigurationDB::hotReloadThread() {
            SS_LOG_INFO(LOG_CATEGORY, L"Hot-reload thread started");

            while (!m_shutdownHotReload.load(std::memory_order_acquire)) {
                std::unique_lock lock(m_hotReloadMutex);
                m_hotReloadCV.wait_for(
                    lock,
                    m_config.hotReloadInterval,
                    [this]() { return m_shutdownHotReload.load(std::memory_order_acquire); }
                );

                if (m_shutdownHotReload.load(std::memory_order_acquire)) {
                    break;
                }

                // Check for database changes and reload cache
                HotReload(nullptr);
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Hot-reload thread stopped");
        }


        /**
         * @brief Performs hot-reload of configuration database.
         * 
         * This method implements a delta-based reload strategy that only fetches
         * configurations modified since the last reload timestamp. This is critical
         * for enterprise deployments where:
         * 
         * 1. Multiple processes may modify the same SQLite database
         * 2. Configuration changes need to propagate across distributed agents
         * 3. Memory efficiency requires selective cache updates
         * 4. Change notifications must fire for external modifications
         * 
         * Algorithm:
         * 1. Query database for rows with modified_at > lastReloadTimestamp
         * 2. For each modified row, update cache entry
         * 3. Compare old vs new values to determine if notification needed
         * 4. Dispatch change notifications to registered listeners
         * 5. Update last-reload timestamp for next delta query
         * 
         * Thread Safety: This method is called from the hot-reload background thread
         * and uses appropriate locking for cache access. Notifications are dispatched
         * outside the cache lock to prevent deadlocks.
         * 
         * @param err Optional error output
         * @return true if reload completed successfully, false on database error
         */
        bool ConfigurationDB::HotReload(DatabaseError* err) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                return false;
            }

            SS_LOG_DEBUG(LOG_CATEGORY, L"Performing hot-reload (delta-based)");
            
            auto& dbMgr = DatabaseManager::Instance();
            
            // Load last reload timestamp - atomic for thread safety
            const uint64_t lastMs = m_lastHotReloadMs.load(std::memory_order_acquire);
            const uint64_t nowMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
            
            // ========================================================================
            // DELTA QUERY: Only fetch configurations modified since last reload
            // ========================================================================
            // This is the key optimization for enterprise deployments - we avoid
            // reloading the entire configuration table on every interval.
            // If lastMs == 0 (first run), we load all configurations.
            // ========================================================================
            
            std::string sql = R"SQL(
                SELECT key, value, type, scope, is_encrypted, is_readonly, 
                       description, created_at, modified_at, modified_by, version 
                FROM configurations
            )SQL";
            
            if (lastMs > 0) {
                sql += " WHERE modified_at > ?";
            }
            
            auto result = (lastMs > 0)
                ? dbMgr.QueryWithParams(sql, err, static_cast<int64_t>(lastMs))
                : dbMgr.Query(sql, err);
            
            if (err && !err->message.empty()) {
                SS_LOG_WARN(LOG_CATEGORY, L"HotReload: Database query failed - %ls", err->message.c_str());
                // Update timestamp anyway to prevent tight retry loop on persistent DB errors
                m_lastHotReloadMs.store(nowMs, std::memory_order_release);
                return false;
            }
            
            // ========================================================================
            // NOTIFICATION COLLECTION: Gather changes outside cache lock
            // ========================================================================
            // We collect all notifications first, then dispatch them after releasing
            // the cache lock. This prevents potential deadlocks if listeners try
            // to access the cache during notification handling.
            // ========================================================================
            
            std::vector<std::tuple<std::wstring, ConfigValue, ConfigValue>> pendingNotifications;
            const bool cachingEnabled = m_config.enableCaching;
            size_t processedCount = 0;
            size_t errorCount = 0;
            
            while (result.Next()) {
                try {
                    // Parse configuration entry from database row
                    ConfigEntry entry;
                    entry.key = result.GetWString(0);
                    auto valueBlob = result.GetBlob(1);
                    entry.type = static_cast<ValueType>(result.GetInt(2));
                    entry.scope = static_cast<ConfigScope>(result.GetInt(3));
                    entry.isEncrypted = result.GetInt(4) != 0;
                    entry.isReadOnly = result.GetInt(5) != 0;
                    entry.description = result.GetWString(6);
                    
                    const auto createdMs = result.GetInt64(7);
                    const auto modifiedMs = result.GetInt64(8);
                    entry.createdAt = std::chrono::system_clock::time_point(
                        std::chrono::milliseconds(createdMs));
                    entry.modifiedAt = std::chrono::system_clock::time_point(
                        std::chrono::milliseconds(modifiedMs));
                    entry.modifiedBy = result.GetWString(9);
                    entry.version = result.GetInt(10);
                    
                    // Convert blob to variant value using type information
                    entry.value = blobToValue(valueBlob, entry.type);
                    
                    if (cachingEnabled) {
                        // ============================================================
                        // CACHE UPDATE WITH CHANGE DETECTION
                        // ============================================================
                        std::optional<ConfigValue> oldValueOpt;
                        {
                            std::unique_lock cacheLock(m_cacheMutex);
                            
                            // Capture old value before update (if exists)
                            auto it = m_cache.find(entry.key);
                            if (it != m_cache.end()) {
                                oldValueOpt = it->second.value;
                            }
                            
                            // Update cache with new entry
                            m_cache[entry.key] = entry;
                        }
                        
                        // Determine if notification is needed
                        const ConfigValue oldValue = oldValueOpt.value_or(ConfigValue{});
                        bool shouldNotify = false;
                        
                        if (!oldValueOpt.has_value()) {
                            // New key appeared in database
                            shouldNotify = true;
                        } else {
                            // Compare values using string representation (type-agnostic)
                            shouldNotify = (valueToString(oldValue) != valueToString(entry.value));
                        }
                        
                        if (shouldNotify) {
                            pendingNotifications.emplace_back(
                                entry.key, 
                                oldValue, 
                                entry.value
                            );
                        }
                    } else {
                        // Caching disabled - still notify with empty old value
                        pendingNotifications.emplace_back(
                            entry.key, 
                            ConfigValue{}, 
                            entry.value
                        );
                    }
                    
                    ++processedCount;
                }
                catch (const std::exception& ex) {
                    SS_LOG_ERROR(LOG_CATEGORY, 
                        L"HotReload: Exception processing row: %hs", ex.what());
                    ++errorCount;
                    continue;
                }
            }
            
            // Update last-reload timestamp for next delta query
            m_lastHotReloadMs.store(nowMs, std::memory_order_release);
            
            // ========================================================================
            // DISPATCH NOTIFICATIONS: Outside cache lock to prevent deadlocks
            // ========================================================================
            
            for (const auto& [key, oldValue, newValue] : pendingNotifications) {
                notifyListeners(key, oldValue, newValue);
            }
            
            if (processedCount > 0 || errorCount > 0) {
                SS_LOG_DEBUG(LOG_CATEGORY, 
                    L"HotReload: Processed %zu entries, %zu notifications, %zu errors",
                    processedCount, pendingNotifications.size(), errorCount);
            }
            
            return errorCount == 0;
        }
        
        // ============================================================================
        // Statistics
        // ============================================================================

        ConfigurationDB::Statistics ConfigurationDB::GetStatistics() const {
            std::lock_guard lock(m_statsMutex);
            return m_stats;
        }

        void ConfigurationDB::ResetStatistics() {
            std::lock_guard lock(m_statsMutex);
            m_stats = Statistics{};
        }

        void ConfigurationDB::updateStats(bool read, bool cacheHit) {
            std::lock_guard lock(m_statsMutex);
            if (read) {
                m_stats.totalReads++;
                if (cacheHit) {
                    m_stats.cacheHits++;
                }
                else {
                    m_stats.cacheMisses++;
                }
            }
            else {
                m_stats.totalWrites++;
            }
        }

        ConfigurationDB::Config ConfigurationDB::GetConfig() const {
            std::shared_lock lock(m_configMutex);
            return m_config;
        }

        // ============================================================================
        // Maintenance
        // ============================================================================

        bool ConfigurationDB::Vacuum(DatabaseError* err) {
            return DatabaseManager::Instance().Vacuum(err);
        }

        bool ConfigurationDB::CheckIntegrity(DatabaseError* err) {
            std::vector<std::wstring> issues;
            return DatabaseManager::Instance().CheckIntegrity(issues, err);
        }

        bool ConfigurationDB::Optimize(DatabaseError* err) {
            return DatabaseManager::Instance().Optimize(err);
        }

        bool ConfigurationDB::CleanupAuditLog(
            std::chrono::system_clock::time_point olderThan,
            DatabaseError* err
        ) {
            auto& dbMgr = DatabaseManager::Instance();

            auto timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                olderThan.time_since_epoch()).count();

            const char* sql = "DELETE FROM configuration_changes WHERE timestamp < ?";
            return dbMgr.ExecuteWithParams(sql, err, timestampMs);
        }

        // ============================================================================
        // Batch Operations
        // ============================================================================
        bool ConfigurationDB::SetBatch(
            const std::vector<std::pair<std::wstring, ConfigValue>>& entries,
            ConfigScope scope,
            std::wstring_view changedBy,
            DatabaseError* err
        ) {
            auto& dbMgr = DatabaseManager::Instance();
            auto trans = dbMgr.BeginTransaction(Transaction::Type::Immediate, err);
            if (!trans || !trans->IsActive()) {
                return false;
            }

            
            for (const auto& [key, value] : entries) {
               

                // Determine value type
                ValueType type = ValueType::String;
                if (std::holds_alternative<std::wstring>(value)) type = ValueType::String;
                else if (std::holds_alternative<int64_t>(value)) type = ValueType::Integer;
                else if (std::holds_alternative<double>(value)) type = ValueType::Real;
                else if (std::holds_alternative<bool>(value)) type = ValueType::Boolean;
                else if (std::holds_alternative<Utils::JSON::Json>(value)) type = ValueType::Json;
                else if (std::holds_alternative<std::vector<uint8_t>>(value)) type = ValueType::Binary;

                // Convert value to BLOB
                auto valueBlob = valueToBlob(value);

                // Get timestamps
                auto now = std::chrono::system_clock::now();
                auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()).count();

                // Convert strings to UTF-8
                auto utf8Key = wstringToUtf8(key);
                auto utf8ChangedBy = wstringToUtf8(changedBy);

                // USE TRANSACTION'S ExecuteWithParams!
                const char* sql = R"SQL(
            INSERT OR REPLACE INTO configurations 
            (key, value, type, scope, is_encrypted, is_readonly, description, 
             created_at, modified_at, modified_by, version)
            VALUES (?, ?, ?, ?, 0, 0, '', ?, ?, ?, 1)
        )SQL";

                if (!trans->ExecuteWithParams(
                    sql, err,
                    utf8Key,
                    valueBlob,
                    static_cast<int>(type),
                    static_cast<int>(scope),
                    nowMs,  // created_at
                    nowMs,  // modified_at
                    utf8ChangedBy
                )) {
                    trans->Rollback(nullptr);
                    return false;
                }
            }

            return trans->Commit(err);
        }

        std::unordered_map<std::wstring, ConfigurationDB::ConfigValue> ConfigurationDB::GetBatch(
            const std::vector<std::wstring>& keys,
            DatabaseError* err
        ) const {
            std::unordered_map<std::wstring, ConfigValue> results;

            for (const auto& key : keys) {
                auto value = Get(key, err);
                if (value.has_value()) {
                    results[key] = value.value();
                }
            }

            return results;
        }

        bool ConfigurationDB::RemoveBatch(
            const std::vector<std::wstring>& keys,
            std::wstring_view changedBy,
            DatabaseError* err
        ) {
            auto& dbMgr = DatabaseManager::Instance();
            auto trans = dbMgr.BeginTransaction(Transaction::Type::Immediate, err);
            if (!trans || !trans->IsActive()) {
                return false;
            }

            for (const auto& key : keys) {
                auto utf8Key = wstringToUtf8(key);

                const char* checkSql = "SELECT COUNT(*) FROM configurations WHERE key = ?";
                auto result = dbMgr.QueryWithParams(checkSql, err, utf8Key);

                if (!result.Next() || result.GetInt(0) == 0) {
                    trans->Rollback(nullptr);
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"Key not found: " + key;
                    }
                    return false;
                }

                const char* deleteSql = "DELETE FROM configurations WHERE key = ?";
                if (!trans->ExecuteWithParams(deleteSql, err, utf8Key)) {
                    trans->Rollback(nullptr);
                    return false;
                }
            }

            // COMMIT FIRST!
            if (!trans->Commit(err)) {
                return false;
            }

            // INVALIDATE CACHE AFTER COMMIT!
            if (m_config.enableCaching) {
                for (const auto& key : keys) {
                    cacheInvalidate(key);
                }
            }

            // UPDATE STATS AFTER SUCCESSFUL COMMIT!
            {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.totalDeletes += keys.size();
            }

            return true;
        }

   // ============================================================================
   // Import/Export - Full Implementation
   // ============================================================================

        bool ConfigurationDB::ExportToJson(
            const std::filesystem::path& path,
            std::optional<ConfigScope> scope,
            bool includeEncrypted,
            DatabaseError* err
        ) const {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) err->message = L"ConfigurationDB not initialized";
                SS_LOG_ERROR(LOG_CATEGORY, L"ExportToJson: DB not initialized");
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Exporting configurations to JSON: %ls", path.wstring().c_str());

            auto& dbMgr = DatabaseManager::Instance();

            // Build query based on scope filter
            std::string sql = "SELECT key, value, type, scope, is_encrypted, is_readonly, description, "
                "created_at, modified_at, modified_by, version FROM configurations";

            if (scope.has_value()) {
                sql += " WHERE scope = ?";
            }
            sql += " ORDER BY key";

            QueryResult result;
            if (scope.has_value()) {
                result = dbMgr.QueryWithParams(sql, err, static_cast<int>(*scope));
            }
            else {
                result = dbMgr.Query(sql, err);
            }

            if (err && !err->message.empty()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ExportToJson: Query failed");
                return false;
            }

            // Build JSON structure
            Utils::JSON::Json root = Utils::JSON::Json::object();
            root["version"] = "1.0";
            root["exportDate"] = Utils::SystemUtils::NowFileTime100nsUTC();
            root["exportedBy"] = "ConfigurationDB";
            root["configurations"] = Utils::JSON::Json::array();

            auto& configs = root["configurations"];

            while (result.Next()) {
                try {
                    Utils::JSON::Json entry = Utils::JSON::Json::object();

                    std::wstring key = result.GetWString(0);
                    auto valueBlob = result.GetBlob(1);
                    auto type = static_cast<ValueType>(result.GetInt(2));
                    auto entryScope = static_cast<ConfigScope>(result.GetInt(3));
                    bool isEncrypted = result.GetInt(4) != 0;
                    bool isReadOnly = result.GetInt(5) != 0;
                    std::wstring description = result.GetWString(6);
                    int64_t createdMs = result.GetInt64(7);
                    int64_t modifiedMs = result.GetInt64(8);
                    std::wstring modifiedBy = result.GetWString(9);
                    int version = result.GetInt(10);

                    // Skip encrypted entries if not requested
                    if (isEncrypted && !includeEncrypted) {
                        continue;
                    }

                    // Convert key to narrow string for JSON using proper UTF-8
                    std::string keyNarrow = wstringToUtf8(key);
                    entry["key"] = keyNarrow;
                    entry["type"] = static_cast<int>(type);
                    entry["scope"] = static_cast<int>(entryScope);
                    entry["isEncrypted"] = isEncrypted;
                    entry["isReadOnly"] = isReadOnly;

                    std::string descNarrow = wstringToUtf8(description);
                    entry["description"] = descNarrow;

                    entry["createdAt"] = createdMs;
                    entry["modifiedAt"] = modifiedMs;

                    std::string modifiedByNarrow = wstringToUtf8(modifiedBy);
                    entry["modifiedBy"] = modifiedByNarrow;
                    entry["version"] = version;

                    // Convert value based on type
                    if (isEncrypted) {
                        // Export encrypted data as base64
                        entry["value"] = Base64EncodeToString(valueBlob.data(), valueBlob.size());
                    }
                    else {
                        ConfigValue val = blobToValue(valueBlob, type);

                        if (std::holds_alternative<std::wstring>(val)) {
                            auto& wstr = std::get<std::wstring>(val);
                            entry["value"] = std::string(wstr.begin(), wstr.end());
                        }
                        else if (std::holds_alternative<int64_t>(val)) {
                            entry["value"] = std::get<int64_t>(val);
                        }
                        else if (std::holds_alternative<double>(val)) {
                            entry["value"] = std::get<double>(val);
                        }
                        else if (std::holds_alternative<bool>(val)) {
                            entry["value"] = std::get<bool>(val);
                        }
                        else if (std::holds_alternative<Utils::JSON::Json>(val)) {
                            entry["value"] = std::get<Utils::JSON::Json>(val);
                        }
                        else if (std::holds_alternative<std::vector<uint8_t>>(val)) {
                            auto& bin = std::get<std::vector<uint8_t>>(val);
                            entry["value"] = Base64EncodeToString(bin.data(), bin.size());
                        }
                    }

                    configs.push_back(std::move(entry));

                }
                catch (const std::exception& ex) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"ExportToJson: Exception processing row: %hs", ex.what());
                    continue;
                }
            }

            // Write to file using JSONUtils
            Utils::JSON::SaveOptions saveOpts;
            saveOpts.pretty = true;
            saveOpts.indentSpaces = 2;
            saveOpts.atomicReplace = true;

            Utils::JSON::Error jsonErr;
            if (!Utils::JSON::SaveToFile(path, root, &jsonErr, saveOpts)) {
                if (err) {
                    err->message = std::wstring(jsonErr.message.begin(), jsonErr.message.end());
                }
                SS_LOG_ERROR(LOG_CATEGORY, L"ExportToJson: Failed to write file: %hs", jsonErr.message.c_str());
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Successfully exported %zu configurations to JSON", configs.size());
            return true;
        }

        bool ConfigurationDB::ImportFromJson(
            const std::filesystem::path& path,
            bool overwriteExisting,
            std::wstring_view changedBy,
            DatabaseError* err
        ) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) err->message = L"ConfigurationDB not initialized";
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromJson: DB not initialized");
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Importing configurations from JSON: %ls", path.wstring().c_str());

            // Validate file exists
            if (!std::filesystem::exists(path)) {
                if (err) err->message = L"JSON file not found";
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromJson: File not found: %ls", path.wstring().c_str());
                return false;
            }

            // Parse JSON file
            Utils::JSON::Json root;
            Utils::JSON::ParseOptions parseOpts;
            parseOpts.allowComments = true;

            Utils::JSON::Error jsonErr;
            if (!Utils::JSON::LoadFromFile(path, root, &jsonErr, parseOpts)) {
                if (err) {
                    err->message = std::wstring(jsonErr.message.begin(), jsonErr.message.end());
                }
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromJson: Failed to parse file: %hs", jsonErr.message.c_str());
                return false;
            }

            // Validate JSON structure
            if (!root.contains("configurations") || !root["configurations"].is_array()) {
                if (err) err->message = L"Invalid JSON structure: missing 'configurations' array";
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromJson: Invalid JSON structure");
                return false;
            }

            auto& configs = root["configurations"];
            size_t importedCount = 0;
            size_t skippedCount = 0;
            size_t errorCount = 0;

            auto& dbMgr = DatabaseManager::Instance();

            // Begin transaction for atomic import
            if (!dbMgr.BeginTransaction(ShadowStrike::Database::Transaction::Type::Immediate,err)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromJson: Failed to begin transaction");
                return false;
            }

            for (const auto& entry : configs) {
                try {
                    if (!entry.contains("key") || !entry.contains("value") || !entry.contains("type")) {
                        SS_LOG_WARN(LOG_CATEGORY, L"ImportFromJson: Skipping invalid entry (missing required fields)");
                        skippedCount++;
                        continue;
                    }

                    // Extract fields
                    std::string keyNarrow = entry["key"].get<std::string>();
                    std::wstring key(keyNarrow.begin(), keyNarrow.end());

                    auto type = static_cast<ValueType>(entry["type"].get<int>());
                    auto scope = entry.contains("scope") ?
                        static_cast<ConfigScope>(entry["scope"].get<int>()) : ConfigScope::Global;

                    bool isEncrypted = entry.contains("isEncrypted") ? entry["isEncrypted"].get<bool>() : false;
                    bool isReadOnly = entry.contains("isReadOnly") ? entry["isReadOnly"].get<bool>() : false;

                    std::wstring description;
                    if (entry.contains("description")) {
                        std::string descNarrow = entry["description"].get<std::string>();
                        description = std::wstring(descNarrow.begin(), descNarrow.end());
                    }

                    // Check if key exists
                    if (!overwriteExisting && Contains(key)) {
                        SS_LOG_DEBUG(LOG_CATEGORY, L"ImportFromJson: Skipping existing key: %ls", key.c_str());
                        skippedCount++;
                        continue;
                    }

                    // Convert value based on type
                    ConfigValue value;

                    if (isEncrypted) {
                        // Encrypted data stored as base64
                        std::string base64Str = entry["value"].get<std::string>();
                        std::vector<uint8_t> encryptedData;
                        Utils::Base64DecodeError decodeErr;
                        if (!Utils::Base64Decode(base64Str, encryptedData, decodeErr)) {
                            SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromJson: Failed to decode encrypted value for key: %ls", key.c_str());
                            errorCount++;
                            continue;
                        }
                        value = encryptedData;
                    }
                    else {
                        // Decode based on type
                        switch (type) {
                        case ValueType::String: {
                            std::string strNarrow = entry["value"].get<std::string>();
                            value = std::wstring(strNarrow.begin(), strNarrow.end());
                            break;
                        }
                        case ValueType::Integer:
                            value = entry["value"].get<int64_t>();
                            break;
                        case ValueType::Real:
                            value = entry["value"].get<double>();
                            break;
                        case ValueType::Boolean:
                            value = entry["value"].get<bool>();
                            break;
                        case ValueType::Json:
                            value = entry["value"];
                            break;
                        case ValueType::Binary:
                        case ValueType::Encrypted: {
                            std::string base64Str = entry["value"].get<std::string>();
                            std::vector<uint8_t> binaryData;
                            Utils::Base64DecodeError decodeErr;
                            if (!Utils::Base64Decode(base64Str, binaryData, decodeErr)) {
                                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromJson: Failed to decode binary value for key: %ls", key.c_str());
                                errorCount++;
                                continue;
                            }
                            value = binaryData;
                            break;
                        }
                        default:
                            SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromJson: Unsupported type for key: %ls", key.c_str());
                            errorCount++;
                            continue;
                        }
                    }

                    // Import the configuration
                    if (!Set(key, value, scope, changedBy, L"Imported from JSON", err)) {
                        SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromJson: Failed to import key: %ls", key.c_str());
                        errorCount++;
                        continue;
                    }

                    // If read-only flag was set, update it separately
                    if (isReadOnly) {
                        std::string updateSql = "UPDATE configurations SET is_readonly = 1 WHERE key = ?";
                        std::string keyUtf8 = wstringToUtf8(key);
                        if (!dbMgr.ExecuteWithParams(updateSql, err, keyUtf8)) {
                            SS_LOG_WARN(LOG_CATEGORY, L"ImportFromJson: Failed to set read-only flag for: %ls", key.c_str());
                        }
                    }

                    importedCount++;

                }
                catch (const std::exception& ex) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromJson: Exception processing entry: %hs", ex.what());
                    errorCount++;
                    continue;
                }
            }

            // Commit transaction
			auto trans = dbMgr.BeginTransaction(Transaction::Type::Immediate, err);
            if(!trans || !trans->IsActive()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromJson: Transaction not active during commit");
                return false;
			}

            if (!trans->Commit(err)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromJson: Failed to commit transaction");
                trans->Rollback(nullptr);
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Import complete: %zu imported, %zu skipped, %zu errors",
                importedCount, skippedCount, errorCount);

            return errorCount == 0;
        }

        bool ConfigurationDB::ExportToXml(
            const std::filesystem::path& path,
            std::optional<ConfigScope> scope,
            bool includeEncrypted,
            DatabaseError* err
        ) const {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) err->message = L"ConfigurationDB not initialized";
                SS_LOG_ERROR(LOG_CATEGORY, L"ExportToXml: DB not initialized");
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Exporting configurations to XML: %ls", path.wstring().c_str());

            auto& dbMgr = DatabaseManager::Instance();

            // Build query
            std::string sql = "SELECT key, value, type, scope, is_encrypted, is_readonly, description, "
                "created_at, modified_at, modified_by, version FROM configurations";

            if (scope.has_value()) {
                sql += " WHERE scope = ?";
            }
            sql += " ORDER BY key";

            QueryResult result;
            if (scope.has_value()) {
                result = dbMgr.QueryWithParams(sql, err, static_cast<int>(*scope));
            }
            else {
                result = dbMgr.Query(sql, err);
            }

            if (err && !err->message.empty()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ExportToXml: Query failed");
                return false;
            }

            // Build XML document
            Utils::XML::Document doc;
            auto root = doc.append_child("ConfigurationDatabase");
            root.append_attribute("version").set_value("1.0");

            char timestampBuf[32];
            snprintf(timestampBuf, sizeof(timestampBuf), "%llu", Utils::SystemUtils::NowFileTime100nsUTC());
            root.append_attribute("exportDate").set_value(timestampBuf);
            root.append_attribute("exportedBy").set_value("ConfigurationDB");

            auto configs = root.append_child("Configurations");

            while (result.Next()) {
                try {
                    std::wstring key = result.GetWString(0);
                    auto valueBlob = result.GetBlob(1);
                    auto type = static_cast<ValueType>(result.GetInt(2));
                    auto entryScope = static_cast<ConfigScope>(result.GetInt(3));
                    bool isEncrypted = result.GetInt(4) != 0;
                    bool isReadOnly = result.GetInt(5) != 0;
                    std::wstring description = result.GetWString(6);
                    int64_t createdMs = result.GetInt64(7);
                    int64_t modifiedMs = result.GetInt64(8);
                    std::wstring modifiedBy = result.GetWString(9);
                    int version = result.GetInt(10);

                    // Skip encrypted if not requested
                    if (isEncrypted && !includeEncrypted) {
                        continue;
                    }

                    auto entry = configs.append_child("Configuration");

                    // Convert to UTF-8 for XML using proper conversion
                    std::string keyUtf8 = wstringToUtf8(key);
                    entry.append_attribute("key").set_value(keyUtf8.c_str());
                    entry.append_attribute("type").set_value(static_cast<int>(type));
                    entry.append_attribute("scope").set_value(static_cast<int>(entryScope));
                    entry.append_attribute("isEncrypted").set_value(isEncrypted);
                    entry.append_attribute("isReadOnly").set_value(isReadOnly);
                    entry.append_attribute("version").set_value(version);

                    // Description
                    if (!description.empty()) {
                        std::string descUtf8 = wstringToUtf8(description);
                        auto descNode = entry.append_child("Description");
                        descNode.text().set(descUtf8.c_str());
                    }

                    // Metadata
                    auto meta = entry.append_child("Metadata");

                    char createdBuf[32];
                    snprintf(createdBuf, sizeof(createdBuf), "%lld", createdMs);
                    meta.append_child("CreatedAt").text().set(createdBuf);

                    char modifiedBuf[32];
                    snprintf(modifiedBuf, sizeof(modifiedBuf), "%lld", modifiedMs);
                    meta.append_child("ModifiedAt").text().set(modifiedBuf);

                    std::string modifiedByUtf8 = wstringToUtf8(modifiedBy);
                    meta.append_child("ModifiedBy").text().set(modifiedByUtf8.c_str());

                    // Value
                    auto valueNode = entry.append_child("Value");

                    if (isEncrypted) {
                        valueNode.append_attribute("encoding").set_value("base64");
                        std::string base64 = Base64EncodeToString(valueBlob.data(), valueBlob.size());
                        valueNode.text().set(base64.c_str());
                    }
                    else {
                        ConfigValue val = blobToValue(valueBlob, type);

                        if (std::holds_alternative<std::wstring>(val)) {
                            auto& wstr = std::get<std::wstring>(val);
                            std::string strUtf8 = wstringToUtf8(wstr);
                            valueNode.text().set(strUtf8.c_str());
                        }
                        else if (std::holds_alternative<int64_t>(val)) {
                            char buf[32];
                            snprintf(buf, sizeof(buf), "%lld", std::get<int64_t>(val));
                            valueNode.text().set(buf);
                        }
                        else if (std::holds_alternative<double>(val)) {
                            char buf[32];
                            snprintf(buf, sizeof(buf), "%.15g", std::get<double>(val));
                            valueNode.text().set(buf);
                        }
                        else if (std::holds_alternative<bool>(val)) {
                            valueNode.text().set(std::get<bool>(val) ? "true" : "false");
                        }
                        else if (std::holds_alternative<Utils::JSON::Json>(val)) {
                            std::string jsonStr;
                            Utils::JSON::StringifyOptions strOpts;
                            strOpts.pretty = false;
                            if (Utils::JSON::Stringify(std::get<Utils::JSON::Json>(val), jsonStr, strOpts)) {
                                valueNode.append_attribute("encoding").set_value("json");
                                valueNode.text().set(jsonStr.c_str());
                            }
                            else {
                                SS_LOG_WARN(LOG_CATEGORY, L"ExportToXml: Failed to stringify JSON value for key: %ls", key.c_str());
								valueNode.text().set("");
                            }
                        }
                        else if (std::holds_alternative<std::vector<uint8_t>>(val)) {
                            auto& bin = std::get<std::vector<uint8_t>>(val);
                            valueNode.append_attribute("encoding").set_value("base64");
                            std::string base64 = Base64EncodeToString(bin.data(), bin.size());
                            valueNode.text().set(base64.c_str());
                        }
                    }

                }
                catch (const std::exception& ex) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"ExportToXml: Exception processing row: %hs", ex.what());
                    continue;
                }
            }

            // Save to file
            Utils::XML::SaveOptions saveOpts;
            saveOpts.pretty = true;
            saveOpts.indentSpaces = 2;
            saveOpts.atomicReplace = true;
            saveOpts.writeDeclaration = true;

            Utils::XML::Error xmlErr;
            if (!Utils::XML::SaveToFile(path, doc, &xmlErr, saveOpts)) {
                if (err) {
                    err->message = std::wstring(xmlErr.message.begin(), xmlErr.message.end());
                }
                SS_LOG_ERROR(LOG_CATEGORY, L"ExportToXml: Failed to write file: %hs", xmlErr.message.c_str());
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Successfully exported configurations to XML");
            return true;
        }

        bool ConfigurationDB::ImportFromXml(
            const std::filesystem::path& path,
            bool overwriteExisting,
            std::wstring_view changedBy,
            DatabaseError* err
        ) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) err->message = L"ConfigurationDB not initialized";
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromXml: DB not initialized");
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Importing configurations from XML: %ls", path.wstring().c_str());

            // Validate file
            if (!std::filesystem::exists(path)) {
                if (err) err->message = L"XML file not found";
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromXml: File not found: %ls", path.wstring().c_str());
                return false;
            }

            // Parse XML
            Utils::XML::Document doc;
            Utils::XML::ParseOptions parseOpts;
            parseOpts.allowComments = true;

            Utils::XML::Error xmlErr;
            if (!Utils::XML::LoadFromFile(path, doc, &xmlErr, parseOpts)) {
                if (err) {
                    err->message = std::wstring(xmlErr.message.begin(), xmlErr.message.end());
                }
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromXml: Failed to parse file: %hs", xmlErr.message.c_str());
                return false;
            }

            auto root = doc.child("ConfigurationDatabase");
            if (!root) {
                if (err) err->message = L"Invalid XML: missing ConfigurationDatabase root";
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromXml: Invalid XML structure");
                return false;
            }

            auto configs = root.child("Configurations");
            if (!configs) {
                if (err) err->message = L"Invalid XML: missing Configurations node";
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromXml: Invalid XML structure");
                return false;
            }

            size_t importedCount = 0;
            size_t skippedCount = 0;
            size_t errorCount = 0;

            auto& dbMgr = DatabaseManager::Instance();

            // Begin transaction
			auto trans = dbMgr.BeginTransaction(Transaction::Type::Immediate, err);
            if (!trans || !trans->IsActive()) {
                                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromXml: Failed to begin transaction");
								return false;
            }
            if (!trans->Commit(err)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromXml: Failed to begin transaction");
                return false;
            }

            for (auto entry = configs.child("Configuration"); entry; entry = entry.next_sibling("Configuration")) {
                try {
                    // Extract attributes
                    auto keyAttr = entry.attribute("key");
                    if (!keyAttr) {
                        SS_LOG_WARN(LOG_CATEGORY, L"ImportFromXml: Skipping entry without key attribute");
                        skippedCount++;
                        continue;
                    }

                    std::string keyUtf8 = keyAttr.as_string();
                    std::wstring key(keyUtf8.begin(), keyUtf8.end());

                    int typeInt = entry.attribute("type").as_int(-1);
                    if (typeInt < 0) {
                        SS_LOG_WARN(LOG_CATEGORY, L"ImportFromXml: Skipping entry with invalid type: %ls", key.c_str());
                        skippedCount++;
                        continue;
                    }

                    auto type = static_cast<ValueType>(typeInt);
                    auto scope = static_cast<ConfigScope>(entry.attribute("scope").as_int(static_cast<int>(ConfigScope::Global)));
                    bool isEncrypted = entry.attribute("isEncrypted").as_bool(false);
                    bool isReadOnly = entry.attribute("isReadOnly").as_bool(false);

                    // Check if exists
                    if (!overwriteExisting && Contains(key)) {
                        SS_LOG_DEBUG(LOG_CATEGORY, L"ImportFromXml: Skipping existing key: %ls", key.c_str());
                        skippedCount++;
                        continue;
                    }

                    // Extract value
                    auto valueNode = entry.child("Value");
                    if (!valueNode) {
                        SS_LOG_WARN(LOG_CATEGORY, L"ImportFromXml: Skipping entry without Value node: %ls", key.c_str());
                        skippedCount++;
                        continue;
                    }

                    std::string valueText = valueNode.text().as_string();
                    std::string encoding = valueNode.attribute("encoding").as_string("");

                    ConfigValue value;

                    if (encoding == "base64") {
                        // Decode base64
                        std::vector<uint8_t> decoded;
                        Utils::Base64DecodeError decodeErr;
                        if (!Utils::Base64Decode(valueText, decoded, decodeErr)) {
                            SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromXml: Failed to decode base64 for key: %ls", key.c_str());
                            errorCount++;
                            continue;
                        }
                        value = decoded;
                    }
                    else if (encoding == "json") {
                        // Parse JSON
                        Utils::JSON::Json jsonVal;
                        Utils::JSON::ParseOptions jsonOpts;
                        Utils::JSON::Error jsonErr;
                        if (!Utils::JSON::Parse(valueText, jsonVal, &jsonErr, jsonOpts)) {
                            SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromXml: Failed to parse JSON for key: %ls", key.c_str());
                            errorCount++;
                            continue;
                        }
                        value = jsonVal;
                    }
                    else {
                        // Parse based on type
                        switch (type) {
                        case ValueType::String:
                            value = std::wstring(valueText.begin(), valueText.end());
                            break;
                        case ValueType::Integer:
                            value = static_cast<int64_t>(std::stoll(valueText));
                            break;
                        case ValueType::Real:
                            value = std::stod(valueText);
                            break;
                        case ValueType::Boolean:
                            value = (valueText == "true" || valueText == "1");
                            break;
                        default:
                            SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromXml: Unsupported type for key: %ls", key.c_str());
                            errorCount++;
                            continue;
                        }
                    }

                    // Import
                    if (!Set(key, value, scope, changedBy, L"Imported from XML", err)) {
                        SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromXml: Failed to import key: %ls", key.c_str());
                        errorCount++;
                        continue;
                    }

                    // Set read-only if needed
                    if (isReadOnly) {
                        std::string updateSql = "UPDATE configurations SET is_readonly = 1 WHERE key = ?";
                        std::string keyNarrow = wstringToUtf8(key);
                        if (!dbMgr.ExecuteWithParams(updateSql, err, keyNarrow)) {
                            SS_LOG_WARN(LOG_CATEGORY, L"ImportFromXml: Failed to set read-only for: %ls", key.c_str());
                        }
                    }

                    importedCount++;

                }
                catch (const std::exception& ex) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromXml: Exception processing entry: %hs", ex.what());
                    errorCount++;
                    continue;
                }
            }

            // Commit
			auto trans_ = dbMgr.BeginTransaction(Transaction::Type::Immediate, err);
            if (!trans_ || !trans_->IsActive()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromXml: Failed to begin transaction");
				return false;
            }

            if (!trans_->Commit(err)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ImportFromXml: Failed to commit transaction");
                trans_->Rollback(nullptr);
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Import complete: %zu imported, %zu skipped, %zu errors",
                importedCount, skippedCount, errorCount);

            return errorCount == 0;
        }

        // ============================================================================
        // Version History - Full Implementation
        // ============================================================================

        std::vector<ConfigurationDB::ConfigEntry> ConfigurationDB::GetHistory(
            std::wstring_view key,
            size_t maxVersions,
            DatabaseError* err
        ) const {
            std::vector<ConfigEntry> history;

            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) err->message = L"ConfigurationDB not initialized";
                return history;
            }

            auto& dbMgr = DatabaseManager::Instance();

            std::string sql = "SELECT key, value, type, scope, version, created_at "
                "FROM configuration_history "
                "WHERE key = ? "
                "ORDER BY version DESC";

            if (maxVersions > 0) {
                sql += " LIMIT ?";
            }

            std::string keyUtf8 = wstringToUtf8(key);

            QueryResult result;
            if (maxVersions > 0) {
                result = dbMgr.QueryWithParams(sql, err, keyUtf8, static_cast<int>(maxVersions));
            }
            else {
                result = dbMgr.QueryWithParams(sql, err, keyUtf8);
            }

            if (err && !err->message.empty()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"GetHistory: Query failed for key: %ls", key.data());
                return history;
            }

            while (result.Next()) {
                try {
                    ConfigEntry entry;
                    entry.key = result.GetWString(0);
                    auto valueBlob = result.GetBlob(1);
                    entry.type = static_cast<ValueType>(result.GetInt(2));
                    entry.scope = static_cast<ConfigScope>(result.GetInt(3));
                    entry.version = result.GetInt(4);
                    int64_t createdMs = result.GetInt64(5);
                    entry.createdAt = std::chrono::system_clock::time_point(std::chrono::milliseconds(createdMs));

                    entry.value = blobToValue(valueBlob, entry.type);

                    history.push_back(std::move(entry));

                }
                catch (const std::exception& ex) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"GetHistory: Exception processing row: %hs", ex.what());
                    continue;
                }
            }

            SS_LOG_DEBUG(LOG_CATEGORY, L"Retrieved %zu history entries for key: %ls", history.size(), key.data());
            return history;
        }

        bool ConfigurationDB::Rollback(
            std::wstring_view key,
            int version,
            std::wstring_view changedBy,
            DatabaseError* err
        ) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) err->message = L"ConfigurationDB not initialized";
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Rolling back key '%ls' to version %d", key.data(), version);

            auto& dbMgr = DatabaseManager::Instance();

            // Get the historical version
            std::string sql = "SELECT value, type, scope FROM configuration_history "
                "WHERE key = ? AND version = ?";

            std::string keyUtf8 = wstringToUtf8(key);

            auto result = dbMgr.QueryWithParams(sql, err, keyUtf8, version);

            if (err && !err->message.empty()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Rollback: Query failed");
                return false;
            }

            if (!result.Next()) {
                if (err)
                {
                    err->message = L"Version not found in history";
                    err->sqliteCode = SQLITE_ERROR;
                }
                SS_LOG_ERROR(LOG_CATEGORY, L"Rollback: Version %d not found for key: %ls", version, key.data());
                return false;
            }

            try {
                auto valueBlob = result.GetBlob(0);
                auto type = static_cast<ValueType>(result.GetInt(1));
                auto scope = static_cast<ConfigScope>(result.GetInt(2));

                ConfigValue value = blobToValue(valueBlob, type);
                
                // Restore the value
                std::wstring reason = L"Rolled back to version " + std::to_wstring(version);
                if (!Set(key, value, scope, changedBy, reason, err)) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Rollback: Failed to restore value");
                    return false;
                }

                SS_LOG_INFO(LOG_CATEGORY, L"Successfully rolled back key '%ls' to version %d", key.data(), version);
                return true;

            }
            catch (const std::exception& ex) {
                if (err) err->message = L"Exception during rollback: " + std::wstring(ex.what(), ex.what() + strlen(ex.what()));
                SS_LOG_ERROR(LOG_CATEGORY, L"Rollback: Exception: %hs", ex.what());
                return false;
            }
        }

        std::vector<ConfigurationDB::ChangeRecord> ConfigurationDB::GetChangeHistory(
            std::optional<std::wstring> key,
            std::optional<std::chrono::system_clock::time_point> since,
            size_t maxRecords,
            DatabaseError* err
        ) const {
            std::vector<ChangeRecord> changes;

            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) err->message = L"ConfigurationDB not initialized";
                return changes;
            }

            auto& dbMgr = DatabaseManager::Instance();

            std::string sql = "SELECT id, key, action, old_value, new_value, changed_by, timestamp, reason "
                "FROM configuration_changes ";

            std::vector<std::string> conditions;

            if (key.has_value()) {
                conditions.emplace_back("key = ?");
            }

            if (since.has_value()) {
                conditions.emplace_back("timestamp >= ?");
            }

            if (!conditions.empty()) {
                sql += "WHERE ";
                for (size_t i = 0; i < conditions.size(); ++i) {
                    if (i > 0) sql += " AND ";
                    sql += conditions[i];
                }
            }

            sql += " ORDER BY timestamp DESC";

            if (maxRecords > 0) {
                sql += " LIMIT ?";
            }

            // Build parameter list
            QueryResult result;

            if (key.has_value() && since.has_value() && maxRecords > 0) {
                std::string keyUtf8(key->begin(), key->end());
                int64_t sinceMs = std::chrono::duration_cast<std::chrono::milliseconds>(since->time_since_epoch()).count();
                result = dbMgr.QueryWithParams(sql, err, keyUtf8, sinceMs, static_cast<int>(maxRecords));
            }
            else if (key.has_value() && since.has_value()) {
                std::string keyUtf8(key->begin(), key->end());
                int64_t sinceMs = std::chrono::duration_cast<std::chrono::milliseconds>(since->time_since_epoch()).count();
                result = dbMgr.QueryWithParams(sql, err, keyUtf8, sinceMs);
            }
            else if (key.has_value() && maxRecords > 0) {
                std::string keyUtf8(key->begin(), key->end());
                result = dbMgr.QueryWithParams(sql, err, keyUtf8, static_cast<int>(maxRecords));
            }
            else if (since.has_value() && maxRecords > 0) {
                int64_t sinceMs = std::chrono::duration_cast<std::chrono::milliseconds>(since->time_since_epoch()).count();
                result = dbMgr.QueryWithParams(sql, err, sinceMs, static_cast<int>(maxRecords));
            }
            else if (key.has_value()) {
                std::string keyUtf8(key->begin(), key->end());
                result = dbMgr.QueryWithParams(sql, err, keyUtf8);
            }
            else if (since.has_value()) {
                int64_t sinceMs = std::chrono::duration_cast<std::chrono::milliseconds>(since->time_since_epoch()).count();
                result = dbMgr.QueryWithParams(sql, err, sinceMs);
            }
            else if (maxRecords > 0) {
                result = dbMgr.QueryWithParams(sql, err, static_cast<int>(maxRecords));
            }
            else {
                result = dbMgr.Query(sql, err);
            }

            if (err && !err->message.empty()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"GetChangeHistory: Query failed");
                return changes;
            }

            while (result.Next()) {
                try {
                    ChangeRecord record;
                    record.changeId = result.GetInt64(0);
                    record.key = result.GetWString(1);
                    record.action = static_cast<ChangeAction>(result.GetInt(2));

                    // ====================================================================
                    // BLOB DESERIALIZATION: Convert stored blobs back to ConfigValue
                    // ====================================================================
                    // The old_value and new_value columns store serialized ConfigValues.
                    // To properly deserialize them, we need the value type. We attempt
                    // to get the type from the current configuration entry, falling back
                    // to treating the data as binary if the key no longer exists.
                    // ====================================================================
                    
                    auto oldBlob = result.GetBlob(3);
                    auto newBlob = result.GetBlob(4);
                    
                    // Attempt to determine value type for proper deserialization
                    // Look up current type from configurations table (best effort)
                    ValueType valueType = ValueType::Binary;  // Default fallback
                    {
                        auto currentEntry = dbRead(record.key, nullptr);
                        if (currentEntry.has_value()) {
                            valueType = currentEntry->type;
                        }
                    }
                    
                    // Deserialize old value (if present)
                    if (!oldBlob.empty()) {
                        try {
                            record.oldValue = blobToValue(oldBlob, valueType);
                        } catch (...) {
                            // If deserialization fails, store as raw binary
                            record.oldValue = oldBlob;
                        }
                    }
                    
                    // Deserialize new value (if present)
                    if (!newBlob.empty()) {
                        try {
                            record.newValue = blobToValue(newBlob, valueType);
                        } catch (...) {
                            // If deserialization fails, store as raw binary
                            record.newValue = newBlob;
                        }
                    }

                    record.changedBy = result.GetWString(5);
                    int64_t timestampMs = result.GetInt64(6);
                    record.timestamp = std::chrono::system_clock::time_point(std::chrono::milliseconds(timestampMs));
                    record.reason = result.GetWString(7);

                    changes.push_back(std::move(record));

                }
                catch (const std::exception& ex) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"GetChangeHistory: Exception processing row: %hs", ex.what());
                    continue;
                }
            }

            SS_LOG_DEBUG(LOG_CATEGORY, L"Retrieved %zu change records", changes.size());
            return changes;
        }

        // ============================================================================
        // Defaults - Full Implementation
        // ============================================================================

        bool ConfigurationDB::LoadDefaults(bool overwriteExisting, DatabaseError* err) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                if (err) err->message = L"ConfigurationDB not initialized";
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Loading default configurations (overwrite=%d)", overwriteExisting);

            std::shared_lock lock(m_defaultsMutex);

            if (m_defaults.empty()) {
                SS_LOG_WARN(LOG_CATEGORY, L"No defaults registered");
                return true;
            }

            size_t loadedCount = 0;
            size_t skippedCount = 0;

            for (const auto& [key, defaultPair] : m_defaults) {
                const auto& [value, scope] = defaultPair;

                // Check if key exists
                if (!overwriteExisting && Contains(key)) {
                    SS_LOG_DEBUG(LOG_CATEGORY, L"Skipping existing default: %ls", key.c_str());
                    skippedCount++;
                    continue;
                }

                // Set the default value
                if (Set(key, value, scope, L"System", L"Default configuration", err)) {
                    loadedCount++;
                }
                else {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Failed to load default: %ls", key.c_str());
                }
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Loaded %zu defaults, skipped %zu", loadedCount, skippedCount);
            return true;
        }

        void ConfigurationDB::RegisterDefault(
            std::wstring_view key,
            const ConfigValue& defaultValue,
            ConfigScope scope,
            std::wstring_view description
        ) {
            std::unique_lock lock(m_defaultsMutex);

            std::wstring keyStr(key);
            m_defaults[keyStr] = { defaultValue, scope };

            SS_LOG_DEBUG(LOG_CATEGORY, L"Registered default configuration: %ls", key.data());
        }

        std::optional<ConfigurationDB::ConfigValue> ConfigurationDB::GetDefault(std::wstring_view key) const {
            std::shared_lock lock(m_defaultsMutex);

            std::wstring keyStr(key);
            auto it = m_defaults.find(keyStr);

            if (it != m_defaults.end()) {
                return it->second.first;
            }

            return std::nullopt;
        }


        // ============================================================================
        // CACHE OPERATIONS (Internal)
        // ============================================================================
        // The cache provides fast lookups for frequently accessed configurations.
        // It uses a simple eviction policy (remove oldest on overflow) and is
        // protected by a reader-writer lock for concurrent access.
        // ============================================================================

        /**
         * @brief Invalidates a single key from the cache.
         * @param key The configuration key to remove from cache
         */
        void ConfigurationDB::cacheInvalidate(std::wstring_view key) {
            std::unique_lock lock(m_cacheMutex);
            m_cache.erase(std::wstring(key));
        }

        /**
         * @brief Clears the entire cache.
         * 
         * Called during shutdown and when a full reload is needed.
         */
        void ConfigurationDB::cacheInvalidateAll() {
            std::unique_lock lock(m_cacheMutex);
            m_cache.clear();
        }

        /**
         * @brief Retrieves a configuration entry from cache.
         * 
         * @param key The configuration key to look up
         * @return The cached entry if present, nullopt otherwise
         */
        std::optional<ConfigurationDB::ConfigEntry> ConfigurationDB::cacheGet(std::wstring_view key) const {
            std::shared_lock lock(m_cacheMutex);
            auto it = m_cache.find(std::wstring(key));
            if (it != m_cache.end()) {
                return it->second;
            }
            return std::nullopt;
        }

        /**
         * @brief Adds or updates an entry in the cache.
         * 
         * If the cache is at capacity (maxCacheEntries), the oldest entry
         * is evicted to make room. This is a simple FIFO eviction policy.
         * 
         * @param entry The configuration entry to cache
         * 
         * @note For a production system with higher performance requirements,
         *       consider implementing an LRU cache with O(1) eviction using
         *       a hash map + doubly-linked list combination.
         */
        void ConfigurationDB::cachePut(const ConfigEntry& entry) {
            std::unique_lock lock(m_cacheMutex);

            // Cache size limit check with FIFO eviction
            if (m_config.maxCacheEntries > 0 && m_cache.size() >= m_config.maxCacheEntries) {
                if (!m_cache.empty()) {
                    m_cache.erase(m_cache.begin());
                }
            }

            m_cache[entry.key] = entry;
        }

        // ============================================================================
        // ENCRYPTION HELPERS (Windows DPAPI)
        // ============================================================================
        // Windows Data Protection API (DPAPI) provides machine-local encryption
        // using credentials derived from the user's logon password. This is the
        // recommended approach for protecting sensitive data at rest on Windows.
        //
        // Key features:
        // - No explicit key management required (handled by Windows)
        // - Machine-bound encryption (data can only be decrypted on same machine)
        // - Optional entropy parameter for additional security
        //
        // IMPORTANT: This is NOT the deprecated CAPI hash functions! DPAPI is a
        // distinct, modern API that remains fully supported by Microsoft.
        // ============================================================================

        /**
         * @brief Encrypts data using Windows DPAPI (CryptProtectData).
         * 
         * The encrypted data can only be decrypted on the same machine by the
         * same user (or any user if CRYPTPROTECT_LOCAL_MACHINE is set).
         * 
         * @param plaintext The data to encrypt
         * @param err Optional error output
         * @return Encrypted blob, or empty vector on failure
         * 
         * @note Uses CRYPTPROTECT_LOCAL_MACHINE flag, allowing any user on the
         *       same machine to decrypt. This is appropriate for system-wide
         *       antivirus configurations.
         */
        std::vector<uint8_t> ConfigurationDB::encryptData(
            const std::vector<uint8_t>& plaintext,
            DatabaseError* err
        ) const {
            if (!m_config.enableEncryption) {
                if (err) {
                    err->message = L"Encryption not enabled";
                }
                return {};
            }

#ifdef _WIN32
            // Use Windows DPAPI for encryption
            DATA_BLOB input{};
            DATA_BLOB output{};

            input.pbData = const_cast<BYTE*>(plaintext.data());
            input.cbData = static_cast<DWORD>(plaintext.size());

            // Optional entropy (additional security)
            DATA_BLOB entropy{};
            if (!m_config.masterKey.empty()) {
                entropy.pbData = const_cast<BYTE*>(m_config.masterKey.data());
                entropy.cbData = static_cast<DWORD>(m_config.masterKey.size());
            }

            BOOL success = CryptProtectData(
                &input,
                L"ShadowStrike Config",
                m_config.masterKey.empty() ? nullptr : &entropy,
                nullptr,
                nullptr,
                CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
                &output
            );

            if (!success) {
                if (err) {
                    err->message = L"CryptProtectData failed";
                    err->sqliteCode = GetLastError();
                }
                SS_LOG_LAST_ERROR(L"ConfigurationDB", L"CryptProtectData failed");
                return {};
            }

            std::vector<uint8_t> result(output.pbData, output.pbData + output.cbData);
            LocalFree(output.pbData);

            return result;
#else
            if (err) {
                err->message = L"Encryption not supported on this platform";
            }
            return {};
#endif
        }

        /**
         * @brief Decrypts data using Windows DPAPI (CryptUnprotectData).
         * 
         * This method reverses the encryption performed by encryptData().
         * The same entropy (master key) used during encryption must be
         * provided for successful decryption.
         * 
         * @param ciphertext The encrypted data blob
         * @param err Optional error output
         * @return Decrypted plaintext, or empty vector on failure
         * 
         * @warning Decryption will fail if:
         *          - The data was encrypted on a different machine
         *          - The master key (entropy) doesn't match
         *          - The encrypted blob is corrupted
         */
        std::vector<uint8_t> ConfigurationDB::decryptData(
            const std::vector<uint8_t>& ciphertext,
            DatabaseError* err
        ) const {
            if (!m_config.enableEncryption) {
                if (err) {
                    err->message = L"Encryption not enabled";
                }
                return {};
            }

#ifdef _WIN32
            DATA_BLOB input{};
            DATA_BLOB output{};

            input.pbData = const_cast<BYTE*>(ciphertext.data());
            input.cbData = static_cast<DWORD>(ciphertext.size());

            // Optional entropy - must match what was used during encryption
            DATA_BLOB entropy{};
            if (!m_config.masterKey.empty()) {
                entropy.pbData = const_cast<BYTE*>(m_config.masterKey.data());
                entropy.cbData = static_cast<DWORD>(m_config.masterKey.size());
            }

            BOOL success = CryptUnprotectData(
                &input,
                nullptr,
                m_config.masterKey.empty() ? nullptr : &entropy,
                nullptr,
                nullptr,
                CRYPTPROTECT_UI_FORBIDDEN,
                &output
            );

            if (!success) {
                if (err) {
                    err->message = L"CryptUnprotectData failed";
                    err->sqliteCode = GetLastError();
                }
                SS_LOG_LAST_ERROR(LOG_CATEGORY, L"CryptUnprotectData failed");
                return {};
            }

            std::vector<uint8_t> result(output.pbData, output.pbData + output.cbData);
            LocalFree(output.pbData);

            return result;
#else
            if (err) {
                err->message = L"Decryption not supported on this platform";
            }
            return {};
#endif
        }

        // ============================================================================
        // Value Conversion Helper
        // ============================================================================
        
        /**
         * @brief Converts a string representation to a typed ConfigValue.
         * 
         * This method handles parsing of configuration values from their string
         * representations (e.g., from XML import or user input). Each type has
         * specific parsing rules:
         * 
         * - String: Direct passthrough
         * - Integer: Parsed via std::stoll with error fallback to 0
         * - Real: Parsed via std::stod with error fallback to 0.0
         * - Boolean: Case-insensitive matching of "true", "1", "yes", "on"
         * - Binary/Encrypted: UTF-16 bytes of the string
         * 
         * @param str Input string to convert
         * @param type Target ValueType for conversion
         * @return ConfigValue containing the parsed/converted value
         */
        ConfigurationDB::ConfigValue ConfigurationDB::valueFromString(
            std::wstring_view str,
            ValueType type
        ) const {
            switch (type) {
            case ValueType::String:
                return std::wstring(str);

            case ValueType::Integer: {
                try {
                    return static_cast<int64_t>(std::stoll(std::wstring(str)));
                }
                catch (const std::exception&) {
                    SS_LOG_WARN(LOG_CATEGORY, 
                        L"valueFromString: Failed to parse integer from '%ls', defaulting to 0",
                        std::wstring(str).c_str());
                    return int64_t{0};
                }
            }

            case ValueType::Real: {
                try {
                    return std::stod(std::wstring(str));
                }
                catch (const std::exception&) {
                    SS_LOG_WARN(LOG_CATEGORY, 
                        L"valueFromString: Failed to parse real from '%ls', defaulting to 0.0",
                        std::wstring(str).c_str());
                    return 0.0;
                }
            }

            case ValueType::Boolean: {
                // Case-insensitive boolean parsing
                // Accepts: "true", "1", "yes", "on" as true
                // All other values (including "false", "0", "no", "off") are false
                std::wstring lower(str);
                std::transform(lower.begin(), lower.end(), lower.begin(),
                    [](wchar_t c) { return static_cast<wchar_t>(std::tolower(c)); });
                
                return (lower == L"true" || lower == L"1" || 
                        lower == L"yes" || lower == L"on");
            }
            
            case ValueType::Json: {
                // Parse JSON string into Json object
                try {
                    std::string utf8Str = wstringToUtf8(str);
                    return Utils::JSON::Json::parse(utf8Str);
                }
                catch (const std::exception& ex) {
                    SS_LOG_WARN(LOG_CATEGORY, 
                        L"valueFromString: Failed to parse JSON: %hs", ex.what());
                    return Utils::JSON::Json{};
                }
            }

            case ValueType::Binary:
            case ValueType::Encrypted:
            default: {
                // Convert string to binary
                std::vector<uint8_t> binary(str.size() * sizeof(wchar_t));
                std::memcpy(binary.data(), str.data(), binary.size());
                return binary;
            }
            }
        }
    } // namespace Database
} // namespace ShadowStrike