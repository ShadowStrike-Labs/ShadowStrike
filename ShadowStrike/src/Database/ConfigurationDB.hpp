/**
 * ============================================================================
 * ShadowStrike ConfigurationDB - HEADER
 * ============================================================================
 *
 * @file ConfigurationDB.hpp
 * @brief Enterprise-grade SQLite-backed configuration management system.
 *
 * This module provides a comprehensive configuration storage and management
 * system designed for enterprise antivirus deployments. It serves as the
 * persistence layer for user preferences, policies, and system settings.
 *
 * Architecture Position:
 * ----------------------
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                    GUI / Management API                      │
 *   └─────────────────────────────────────────────────────────────┘
 *                                 │
 *                                 ▼
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │              ConfigurationDB (SQLite Layer)                  │ ◄── YOU ARE HERE
 *   │  - User preferences, policies, audit logs                    │
 *   │  - Versioned configurations with rollback                    │
 *   │  - Change notifications for hot-reload                       │
 *   │  - DPAPI encryption for sensitive values                     │
 *   └─────────────────────────────────────────────────────────────┘
 *                                 │
 *                                 ▼
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │           Memory-Mapped Stores (High-Performance)            │
 *   │  - SignatureIndex, HashStore, PatternStore                   │
 *   │  - Sub-microsecond query latency                             │
 *   │  - Lock-free concurrent access                               │
 *   └─────────────────────────────────────────────────────────────┘
 *
 * Key Features:
 * -------------
 * - HIERARCHICAL KEYS: Dot-notation (e.g., "network.proxy.host")
 * - MULTI-TYPE VALUES: String, Integer, Real, Boolean, JSON, Binary
 * - ENCRYPTION: Windows DPAPI for sensitive values
 * - VERSION CONTROL: Full history with rollback capability
 * - AUDIT LOG: Complete change tracking with reasons
 * - HOT-RELOAD: Background delta-sync with change notifications
 * - VALIDATION: Regex, bounds, custom validators
 * - IMPORT/EXPORT: JSON and XML support
 *
 * Thread Safety:
 * --------------
 * All public methods are thread-safe. The class uses reader-writer locks
 * for cache access and mutex protection for state modifications.
 *
 * Usage Example:
 * --------------
 * @code
 * // Initialize
 * ConfigurationDB::Config cfg;
 * cfg.dbPath = L"C:\\ProgramData\\ShadowStrike\\config.db";
 * cfg.enableEncryption = true;
 * cfg.masterKey = generateSecureKey();
 * 
 * auto& db = ConfigurationDB::Instance();
 * db.Initialize(cfg);
 * 
 * // Set configuration values
 * db.SetString(L"network.proxy.host", L"proxy.example.com");
 * db.SetInt(L"scan.max_threads", 8);
 * db.SetBool(L"ui.dark_mode", true);
 * 
 * // Get with defaults
 * auto host = db.GetString(L"network.proxy.host", L"localhost");
 * auto threads = db.GetInt(L"scan.max_threads", 4);
 * 
 * // Register for change notifications
 * db.RegisterChangeListener(L"scan.*", [](auto key, auto oldVal, auto newVal) {
 *     // Handle scan configuration changes
 * });
 * @endcode
 *
 * @author ShadowStrike Security Team
 * @copyright 2026 ShadowStrike Security Suite
 * @version 1.0.0
 *
 * ============================================================================
 */

#pragma once

#include "DatabaseManager.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/JSONUtils.hpp"

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <any>
#include <variant>

namespace ShadowStrike {
    namespace Database {

        // ============================================================================
        // ConfigurationDB - ENTERPRISE CONFIGURATION MANAGEMENT
        // ============================================================================

        /**
         * @class ConfigurationDB
         * @brief Thread-safe singleton for enterprise configuration management.
         * 
         * Provides a complete configuration management solution with support for:
         * 
         * @par Hierarchical Key Organization
         * Keys use dot-notation for logical grouping:
         * - `network.proxy.host` - Network proxy hostname
         * - `network.proxy.port` - Network proxy port
         * - `scan.realtime.enabled` - Real-time scanning toggle
         * 
         * @par Multi-Type Value Storage
         * Values are stored as a variant supporting:
         * - String (std::wstring)
         * - Integer (int64_t)
         * - Real (double)
         * - Boolean (bool)
         * - JSON (nlohmann::json)
         * - Binary (std::vector<uint8_t>)
         * 
         * @par Scope-Based Access Control
         * - System: Read-only after deployment
         * - Global: Admin-modifiable settings
         * - Group: Team/department specific
         * - Agent: Per-machine settings
         * - User: User preferences
         * 
         * @par Security Features
         * - DPAPI encryption for sensitive values
         * - Read-only protection for system configs
         * - Validation rules with custom validators
         * - Complete audit trail
         * 
         * @note This class is a singleton. Use Instance() to access.
         * @see Initialize() for setup requirements
         * @see Shutdown() for cleanup
         */
        class ConfigurationDB {
        public:
            // ============================================================================
            // TYPE DEFINITIONS
            // ============================================================================

            /**
             * @enum ValueType
             * @brief Identifies the type of a configuration value for serialization.
             */
            enum class ValueType : uint8_t {
                String,     ///< UTF-16 string (std::wstring)
                Integer,    ///< 64-bit signed integer
                Real,       ///< Double-precision floating point
                Boolean,    ///< Boolean value
                Json,       ///< JSON object (nlohmann::json)
                Binary,     ///< Raw binary data
                Encrypted   ///< DPAPI-encrypted binary data
            };

            /**
             * @enum ConfigScope
             * @brief Defines the access scope and override priority of a configuration.
             * 
             * Scopes form a hierarchy where more specific scopes can override
             * more general ones (User > Agent > Group > Global > System).
             */
            enum class ConfigScope : uint8_t {
                System,     ///< System-wide, read-only after deployment
                Global,     ///< Global settings (admin-modifiable)
                Group,      ///< Group-specific settings
                Agent,      ///< Agent-specific settings
                User        ///< User-specific settings (highest priority)
            };

            /**
             * @enum ChangeAction
             * @brief Types of changes recorded in the audit log.
             */
            enum class ChangeAction : uint8_t {
                Created,    ///< New configuration key created
                Modified,   ///< Existing value changed
                Deleted,    ///< Configuration key removed
                Encrypted,  ///< Value was encrypted
                Decrypted   ///< Value was decrypted
            };

            /**
             * @typedef ConfigValue
             * @brief Type-safe variant for configuration values.
             * 
             * Supports all value types that can be stored in the configuration
             * database. Use std::get_if<T> or std::holds_alternative<T> to
             * access the underlying value.
             */
            using ConfigValue = std::variant<
                std::wstring,           ///< String values
                int64_t,                ///< Integer values
                double,                 ///< Real (floating point) values
                bool,                   ///< Boolean values
                Utils::JSON::Json,      ///< JSON objects
                std::vector<uint8_t>    ///< Binary/Encrypted data
            >;

            /**
             * @struct ConfigEntry
             * @brief Complete configuration entry with metadata.
             * 
             * Contains the configuration value along with all associated
             * metadata including type, scope, encryption status, timestamps,
             * and version information.
             */
            struct ConfigEntry {
                std::wstring key;                               ///< Hierarchical key (dot-notation)
                ConfigValue value;                              ///< The configuration value
                ValueType type;                                 ///< Value type for serialization
                ConfigScope scope;                              ///< Access scope
                bool isEncrypted = false;                       ///< Whether value is DPAPI-encrypted
                bool isReadOnly = false;                        ///< Prevents modification
                std::wstring description;                       ///< Human-readable description
                std::chrono::system_clock::time_point createdAt;   ///< Creation timestamp
                std::chrono::system_clock::time_point modifiedAt;  ///< Last modification timestamp
                std::wstring modifiedBy;                        ///< User/system that made last change
                int version = 1;                                ///< Version number for history
            };

            /**
             * @struct ChangeRecord
             * @brief Audit log entry for a configuration change.
             */
            struct ChangeRecord {
                int64_t changeId = 0;
                std::wstring key;
                ChangeAction action;
                ConfigValue oldValue;
                ConfigValue newValue;                               ///< Value after change
                std::wstring changedBy;                             ///< Who made the change
                std::chrono::system_clock::time_point timestamp;    ///< When the change occurred
                std::wstring reason;                                ///< Optional reason for the change
            };

            /**
             * @struct ValidationRule
             * @brief Defines validation constraints for a configuration key.
             * 
             * Validation rules can enforce:
             * - Expected data type
             * - Required presence
             * - String patterns (regex)
             * - Numeric bounds (min/max)
             * - Allowed value lists
             * - Custom validation logic
             */
            struct ValidationRule {
                std::wstring key;                               ///< Key to validate
                ValueType expectedType;                         ///< Required value type
                bool required = false;                          ///< Whether key must exist
                std::wstring pattern;                           ///< Regex pattern for string validation
                std::optional<int64_t> minInt;                  ///< Minimum value for integers
                std::optional<int64_t> maxInt;                  ///< Maximum value for integers
                std::optional<double> minReal;                  ///< Minimum value for reals
                std::optional<double> maxReal;                  ///< Maximum value for reals
                std::vector<std::wstring> allowedValues;        ///< List of permitted string values
                std::function<bool(const ConfigValue&)> customValidator; ///< Custom validation function
            };

            /**
             * @struct Config
             * @brief Configuration settings for the ConfigurationDB instance.
             * 
             * These settings control security, performance, and behavior
             * of the configuration database system.
             */
            struct Config {
                /// @name Database Location
                /// @{
                std::wstring dbPath = L"C:\\ProgramData\\ShadowStrike\\config.db";
                /// @}
                
                /// @name Security Settings
                /// @{
                bool enableEncryption = true;           ///< Enable DPAPI encryption
                std::vector<uint8_t> masterKey;         ///< Entropy for DPAPI (256-bit recommended)
                bool requireStrongKeys = true;          ///< Enforce minimum key length (32 bytes)
                /// @}
                
                /// @name Audit Settings
                /// @{
                bool enableAuditLog = true;             ///< Track all configuration changes
                bool trackAllChanges = true;            ///< Include old/new values in audit log
                size_t maxAuditRecords = 100000;        ///< Maximum audit records to retain
                /// @}
                
                /// @name Versioning Settings
                /// @{
                bool enableVersioning = true;           ///< Keep version history
                size_t maxVersionsPerKey = 10;          ///< Maximum versions to retain per key
                /// @}
                
                /// @name Validation Settings
                /// @{
                bool enforceValidation = true;          ///< Validate values before writing
                bool allowUnknownKeys = false;          ///< Allow keys without validation rules
                /// @}
                
                /// @name Performance Settings
                /// @{
                bool enableCaching = true;              ///< Enable in-memory cache
                size_t maxCacheEntries = 10000;         ///< Maximum cached entries
                std::chrono::milliseconds cacheRefreshInterval = std::chrono::minutes(5);
                /// @}
                
                /// @name Hot-Reload Settings
                /// @{
                bool enableHotReload = true;            ///< Enable background sync
                std::chrono::milliseconds hotReloadInterval = std::chrono::seconds(30);
                /// @}
            };

            /**
             * @struct Statistics
             * @brief Runtime statistics for monitoring and diagnostics.
             * 
             * Provides insight into database usage patterns and cache
             * performance for capacity planning and optimization.
             */
            struct Statistics {
                /// @name Key Counts
                /// @{
                size_t totalKeys = 0;                   ///< Total configuration keys
                size_t systemKeys = 0;                  ///< System-scope keys
                size_t globalKeys = 0;                  ///< Global-scope keys
                size_t groupKeys = 0;                   ///< Group-scope keys
                size_t agentKeys = 0;                   ///< Agent-scope keys
                size_t encryptedKeys = 0;               ///< Keys with encrypted values
                size_t readOnlyKeys = 0;                ///< Read-only keys
                /// @}
                
                /// @name Operation Counters
                /// @{
                uint64_t totalReads = 0;                ///< Total read operations
                uint64_t totalWrites = 0;               ///< Total write operations
                uint64_t totalDeletes = 0;              ///< Total delete operations
                /// @}
                
                /// @name Cache Statistics
                /// @{
                uint64_t cacheHits = 0;                 ///< Cache hit count
                uint64_t cacheMisses = 0;               ///< Cache miss count
                /// @}
                
                /// @name Change Tracking
                /// @{
                size_t totalChanges = 0;                ///< Total changes recorded
                std::chrono::system_clock::time_point lastChange; ///< Time of last change
                /// @}
            };

            // ============================================================================
            // LIFECYCLE MANAGEMENT
            // ============================================================================

            /**
             * @brief Returns the singleton instance.
             * @return Reference to the ConfigurationDB singleton
             */
            static ConfigurationDB& Instance();

            /**
             * @brief Initializes the configuration database.
             * @param config Configuration settings
             * @param err Optional error output
             * @return true if initialization succeeded
             */
            bool Initialize(const Config& config, DatabaseError* err = nullptr);
            
            /**
             * @brief Gracefully shuts down the database.
             */
            void Shutdown();
            
            /**
             * @brief Checks if the database is initialized.
             * @return true if Initialize() was called successfully
             */
            bool IsInitialized() const noexcept { return m_initialized.load(); }

            // ============================================================================
            // BASIC OPERATIONS
            // ============================================================================

            /**
             * @brief Sets a configuration value.
             * @param key Hierarchical key (dot-notation)
             * @param value The value to store
             * @param scope Access scope for the key
             * @param changedBy Identifier for audit log
             * @param reason Optional reason for the change
             * @param err Optional error output
             * @return true if the value was set successfully
             */
            bool Set(std::wstring_view key,
                    const ConfigValue& value,
                    ConfigScope scope = ConfigScope::Global,
                    std::wstring_view changedBy = L"System",
                    std::wstring_view reason = L"",
                    DatabaseError* err = nullptr);

            // Convenience setters
            bool SetString(std::wstring_view key, std::wstring_view value,
                          ConfigScope scope = ConfigScope::Global,
                          std::wstring_view changedBy = L"System",
                          DatabaseError* err = nullptr);

            bool SetInt(std::wstring_view key, int64_t value,
                       ConfigScope scope = ConfigScope::Global,
                       std::wstring_view changedBy = L"System",
                       DatabaseError* err = nullptr);

            bool SetDouble(std::wstring_view key, double value,
                          ConfigScope scope = ConfigScope::Global,
                          std::wstring_view changedBy = L"System",
                          DatabaseError* err = nullptr);

            bool SetBool(std::wstring_view key, bool value,
                        ConfigScope scope = ConfigScope::Global,
                        std::wstring_view changedBy = L"System",
                        DatabaseError* err = nullptr);

            bool SetJson(std::wstring_view key, const Utils::JSON::Json& value,
                        ConfigScope scope = ConfigScope::Global,
                        std::wstring_view changedBy = L"System",
                        DatabaseError* err = nullptr);


            // Get configuration value
            std::optional<ConfigValue> Get(std::wstring_view key,
                                          DatabaseError* err = nullptr) const;

            // Convenience getters with defaults
            std::wstring GetString(std::wstring_view key,
                                  std::wstring_view defaultValue = L"",
                                  DatabaseError* err = nullptr) const;

            int64_t GetInt(std::wstring_view key,
                          int64_t defaultValue = 0,
                          DatabaseError* err = nullptr) const;

            double GetDouble(std::wstring_view key,
                           double defaultValue = 0.0,
                           DatabaseError* err = nullptr) const;

            bool GetBool(std::wstring_view key,
                        bool defaultValue = false,
                        DatabaseError* err = nullptr) const;

            Utils::JSON::Json GetJson(std::wstring_view key,
                                     const Utils::JSON::Json& defaultValue = {},
                                     DatabaseError* err = nullptr) const;

            std::vector<uint8_t> GetBinary(std::wstring_view key,
                                          DatabaseError* err = nullptr) const;

            // Get full entry with metadata
            std::optional<ConfigEntry> GetEntry(std::wstring_view key,
                                               DatabaseError* err = nullptr) const;

            // Remove configuration
            bool Remove(std::wstring_view key,
                       std::wstring_view changedBy = L"System",
                       std::wstring_view reason = L"",
                       DatabaseError* err = nullptr);

            // Check existence
            bool Contains(std::wstring_view key) const;

            // Get all keys (optionally filtered by scope)
            std::vector<std::wstring> GetAllKeys(
                std::optional<ConfigScope> scope = std::nullopt,
                DatabaseError* err = nullptr) const;

            // Get keys by prefix (hierarchical query)
            std::vector<std::wstring> GetKeysByPrefix(
                std::wstring_view prefix,
                std::optional<ConfigScope> scope = std::nullopt,
                size_t maxResults = 1000,
                DatabaseError* err = nullptr) const;

            // ============================================================================
            // Encryption
            // ============================================================================

            // Encrypt a configuration value
            bool Encrypt(std::wstring_view key,
                        std::wstring_view changedBy = L"System",
                        DatabaseError* err = nullptr);

            // Decrypt a configuration value
            bool Decrypt(std::wstring_view key,
                        std::wstring_view changedBy = L"System",
                        DatabaseError* err = nullptr);

            // Check if key is encrypted
            bool IsEncrypted(std::wstring_view key) const;

            // Encrypt sensitive value before storing
            std::vector<uint8_t> EncryptValue(const std::wstring& plaintext,
                                             DatabaseError* err = nullptr) const;

            // Decrypt encrypted value
            std::wstring DecryptValue(const std::vector<uint8_t>& ciphertext,
                                     DatabaseError* err = nullptr) const;

            // ============================================================================
            // Versioning & History
            // ============================================================================

            // Get version history for a key
            std::vector<ConfigEntry> GetHistory(std::wstring_view key,
                                               size_t maxVersions = 10,
                                               DatabaseError* err = nullptr) const;

            // Rollback to a previous version
            bool Rollback(std::wstring_view key,
                         int version,
                         std::wstring_view changedBy = L"System",
                         DatabaseError* err = nullptr);

            // Get change history
            std::vector<ChangeRecord> GetChangeHistory(
                std::optional<std::wstring> key = std::nullopt,
                std::optional<std::chrono::system_clock::time_point> since = std::nullopt,
                size_t maxRecords = 100,
                DatabaseError* err = nullptr) const;

            // ============================================================================
            // Validation
            // ============================================================================

            // Register validation rule
            bool RegisterValidationRule(const ValidationRule& rule);

            // Remove validation rule
            void RemoveValidationRule(std::wstring_view key);

            void SetEnforceValidation(bool enabled);

            // Validate a value against registered rules
            bool Validate(std::wstring_view key,
                         const ConfigValue& value,
                         std::wstring& errorMessage) const;

            // Validate all configurations
            bool ValidateAll(std::vector<std::wstring>& errors,
                           DatabaseError* err = nullptr) const;

            // ============================================================================
            // Batch Operations
            // ============================================================================

            // Set multiple values in a transaction
            bool SetBatch(const std::vector<std::pair<std::wstring, ConfigValue>>& entries,
                         ConfigScope scope = ConfigScope::Global,
                         std::wstring_view changedBy = L"System",
                         DatabaseError* err = nullptr);

            // Get multiple values
            std::unordered_map<std::wstring, ConfigValue> GetBatch(
                const std::vector<std::wstring>& keys,
                DatabaseError* err = nullptr) const;

            // Remove multiple keys
            bool RemoveBatch(const std::vector<std::wstring>& keys,
                           std::wstring_view changedBy = L"System",
                           DatabaseError* err = nullptr);

            // ============================================================================
            // Import / Export
            // ============================================================================

            // Export to JSON
            bool ExportToJson(const std::filesystem::path& path,
                            std::optional<ConfigScope> scope = std::nullopt,
                            bool includeEncrypted = false,
                            DatabaseError* err = nullptr) const;

            // Import from JSON
            bool ImportFromJson(const std::filesystem::path& path,
                              bool overwriteExisting = false,
                              std::wstring_view changedBy = L"Import",
                              DatabaseError* err = nullptr);

            // Export to XML (for compatibility)
            bool ExportToXml(const std::filesystem::path& path,
                           std::optional<ConfigScope> scope = std::nullopt,
                           bool includeEncrypted = false,
                           DatabaseError* err = nullptr) const;

            // Import from XML
            bool ImportFromXml(const std::filesystem::path& path,
                             bool overwriteExisting = false,
                             std::wstring_view changedBy = L"Import",
                             DatabaseError* err = nullptr);

            // ============================================================================
            // Change Notifications (Observer Pattern)
            // ============================================================================

            using ChangeCallback = std::function<void(
                std::wstring_view key,
                const ConfigValue& oldValue,
                const ConfigValue& newValue
            )>;

            // Register callback for key changes
            int RegisterChangeListener(std::wstring_view keyPattern,
                                      ChangeCallback callback);

            // Unregister callback
            void UnregisterChangeListener(int listenerId);

            // Trigger hot-reload (check for external DB changes)
            bool HotReload(DatabaseError* err = nullptr);

            // ============================================================================
            // Default Configurations
            // ============================================================================

            // Load default system configurations
            bool LoadDefaults(bool overwriteExisting = false,
                            DatabaseError* err = nullptr);

            // Register a default value
            void RegisterDefault(std::wstring_view key,
                                const ConfigValue& defaultValue,
                                ConfigScope scope,
                                std::wstring_view description = L"");

            // Get default value
            std::optional<ConfigValue> GetDefault(std::wstring_view key) const;

            // ============================================================================
            // Statistics & Maintenance
            // ============================================================================

            Statistics GetStatistics() const;
            void ResetStatistics();

            Config GetConfig() const;

            // Vacuum database
            bool Vacuum(DatabaseError* err = nullptr);

            // Check integrity
            bool CheckIntegrity(DatabaseError* err = nullptr);

            // Optimize database
            bool Optimize(DatabaseError* err = nullptr);

            // Cleanup old change records
            bool CleanupAuditLog(std::chrono::system_clock::time_point olderThan,
                               DatabaseError* err = nullptr);

        private:
            ConfigurationDB();
            ~ConfigurationDB();

            ConfigurationDB(const ConfigurationDB&) = delete;
            ConfigurationDB& operator=(const ConfigurationDB&) = delete;

            // ============================================================================
            // Internal Operations
            // ============================================================================

            // Schema management
            bool createSchema(DatabaseError* err);
            bool upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err);

            // Database operations
            bool dbWrite(const ConfigEntry& entry,
                        std::wstring_view changedBy,
                        std::wstring_view reason,
                        DatabaseError* err);

            std::optional<ConfigEntry> dbRead(std::wstring_view key,
                                             DatabaseError* err) const;

            bool dbRemove(std::wstring_view key,
                         std::wstring_view changedBy,
                         std::wstring_view reason,
                         DatabaseError* err);

            bool dbWriteChangeRecord(const ChangeRecord& record, DatabaseError* err);

            // Cache operations
            void cacheInvalidate(std::wstring_view key);
            void cacheInvalidateAll();
            std::optional<ConfigEntry> cacheGet(std::wstring_view key) const;
            void cachePut(const ConfigEntry& entry);

            // Encryption helpers (using Windows DPAPI or custom crypto)
            std::vector<uint8_t> encryptData(const std::vector<uint8_t>& plaintext,
                                           DatabaseError* err) const;
            std::vector<uint8_t> decryptData(const std::vector<uint8_t>& ciphertext,
                                           DatabaseError* err) const;

            // Value conversion
            ConfigValue valueFromString(std::wstring_view str, ValueType type) const;
            std::wstring valueToString(const ConfigValue& value) const;
            std::vector<uint8_t> valueToBlob(const ConfigValue& value) const;
            ConfigValue blobToValue(const std::vector<uint8_t>& blob, ValueType type) const;

            // Helper for UTF-8 conversion
            std::string wstringToUtf8(std::wstring_view wstr) const;

            // Validation helpers
            bool validateInternal(std::wstring_view key,
                                 const ConfigValue& value,
                                 std::wstring& errorMessage) const;

            // Change notification
            void notifyListeners(std::wstring_view key,
                               const ConfigValue& oldValue,
                               const ConfigValue& newValue);

            // Hot-reload thread
            void hotReloadThread();

            // Statistics update
            void updateStats(bool read, bool cacheHit);

            // ============================================================================
            // State
            // ============================================================================

            std::atomic<bool> m_initialized{ false };
            Config m_config;
            mutable std::shared_mutex m_configMutex;

            // Cache (key -> ConfigEntry)
            mutable std::shared_mutex m_cacheMutex;
            mutable std::unordered_map<std::wstring, ConfigEntry> m_cache;

            // Validation rules
            mutable std::shared_mutex m_validationMutex;
            std::unordered_map<std::wstring, ValidationRule> m_validationRules;

            // Default values
            mutable std::shared_mutex m_defaultsMutex;
            std::unordered_map<std::wstring, std::pair<ConfigValue, ConfigScope>> m_defaults;

            // Change listeners
            mutable std::mutex m_listenersMutex;
            int m_nextListenerId = 1;
            std::unordered_map<int, std::pair<std::wstring, ChangeCallback>> m_listeners;

            // Hot-reload thread
            std::thread m_hotReloadThread;
            std::atomic<bool> m_shutdownHotReload{ false };
            std::condition_variable m_hotReloadCV;
            std::mutex m_hotReloadMutex;
			std::atomic<uint64_t> m_lastHotReloadMs{ 0 };

            // Statistics
            mutable std::mutex m_statsMutex;
            Statistics m_stats;
        };

        // ============================================================================
        // Helper Functions
        // ============================================================================

        // Convert scope to string
        inline std::wstring ScopeToString(ConfigurationDB::ConfigScope scope) {
            switch (scope) {
                case ConfigurationDB::ConfigScope::System: return L"System";
                case ConfigurationDB::ConfigScope::Global: return L"Global";
                case ConfigurationDB::ConfigScope::Group:  return L"Group";
                case ConfigurationDB::ConfigScope::Agent:  return L"Agent";
                case ConfigurationDB::ConfigScope::User:   return L"User";
                default: return L"Unknown";
            }
        }

        // Convert string to scope
        inline std::optional<ConfigurationDB::ConfigScope> StringToScope(std::wstring_view str) {
            if (str == L"System") return ConfigurationDB::ConfigScope::System;
            if (str == L"Global") return ConfigurationDB::ConfigScope::Global;
            if (str == L"Group")  return ConfigurationDB::ConfigScope::Group;
            if (str == L"Agent")  return ConfigurationDB::ConfigScope::Agent;
            if (str == L"User")   return ConfigurationDB::ConfigScope::User;
            return std::nullopt;
        }

        // Convert ValueType to string
        inline std::wstring ValueTypeToString(ConfigurationDB::ValueType type) {
            switch (type) {
                case ConfigurationDB::ValueType::String:    return L"String";
                case ConfigurationDB::ValueType::Integer:   return L"Integer";
                case ConfigurationDB::ValueType::Real:      return L"Real";
                case ConfigurationDB::ValueType::Boolean:   return L"Boolean";
                case ConfigurationDB::ValueType::Json:      return L"Json";
                case ConfigurationDB::ValueType::Binary:    return L"Binary";
                case ConfigurationDB::ValueType::Encrypted: return L"Encrypted";
                default: return L"Unknown";
            }
        }

        // Convert string to ValueType
        inline std::optional<ConfigurationDB::ValueType> StringToValueType(std::wstring_view str) {
            if (str == L"String")    return ConfigurationDB::ValueType::String;
            if (str == L"Integer")   return ConfigurationDB::ValueType::Integer;
            if (str == L"Real")      return ConfigurationDB::ValueType::Real;
            if (str == L"Boolean")   return ConfigurationDB::ValueType::Boolean;
            if (str == L"Json")      return ConfigurationDB::ValueType::Json;
            if (str == L"Binary")    return ConfigurationDB::ValueType::Binary;
            if (str == L"Encrypted") return ConfigurationDB::ValueType::Encrypted;
            return std::nullopt;
        }

    } // namespace Database
} // namespace ShadowStrike
