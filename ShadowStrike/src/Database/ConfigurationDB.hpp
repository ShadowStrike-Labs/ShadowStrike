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
        // ConfigurationDB - Secure Configuration Management System
        // ============================================================================

        /**
         * @brief Enterprise-grade configuration management with encryption, validation,
         *        versioning, change tracking, and centralized policy management.
         * 
         * Features:
         * - Hierarchical configuration keys (e.g., "network.proxy.host")
         * - Multiple data types (string, int, double, bool, JSON, binary)
         * - Encryption for sensitive values (passwords, keys, tokens)
         * - Configuration versioning and rollback
         * - Change tracking and audit trail
         * - Configuration validation and schema enforcement
         * - Hot-reload and change notifications
         * - Import/Export (JSON, XML)
         * - Group-based configurations (per-agent, per-group, global)
         * - Read-only system configs vs user-modifiable configs
         */
        class ConfigurationDB {
        public:
            // ============================================================================
            // Types & Structures
            // ============================================================================

            enum class ValueType : uint8_t {
                String,
                Integer,
                Real,
                Boolean,
                Json,
                Binary,
                Encrypted
            };

            enum class ConfigScope : uint8_t {
                System,     // System-wide, read-only after deployment
                Global,     // Global settings (admin-modifiable)
                Group,      // Group-specific settings
                Agent,      // Agent-specific settings
                User        // User-specific settings
            };

            enum class ChangeAction : uint8_t {
                Created,
                Modified,
                Deleted,
                Encrypted,
                Decrypted
            };

            // Configuration value (variant)
            using ConfigValue = std::variant<
                std::wstring,           // String
                int64_t,                // Integer
                double,                 // Real
                bool,                   // Boolean
                Utils::JSON::Json,      // JSON object
                std::vector<uint8_t>    // Binary/Encrypted
            >;

            struct ConfigEntry {
                std::wstring key;
                ConfigValue value;
                ValueType type;
                ConfigScope scope;
                bool isEncrypted = false;
                bool isReadOnly = false;
                std::wstring description;
                std::chrono::system_clock::time_point createdAt;
                std::chrono::system_clock::time_point modifiedAt;
                std::wstring modifiedBy;
                int version = 1;
            };

            struct ChangeRecord {
                int64_t changeId = 0;
                std::wstring key;
                ChangeAction action;
                ConfigValue oldValue;
                ConfigValue newValue;
                std::wstring changedBy;
                std::chrono::system_clock::time_point timestamp;
                std::wstring reason;
            };

            struct ValidationRule {
                std::wstring key;
                ValueType expectedType;
                bool required = false;
                std::wstring pattern;           // Regex for string validation
                std::optional<int64_t> minInt;
                std::optional<int64_t> maxInt;
                std::optional<double> minReal;
                std::optional<double> maxReal;
                std::vector<std::wstring> allowedValues;
                std::function<bool(const ConfigValue&)> customValidator;
            };

            struct Config {
                std::wstring dbPath = L"C:\\ProgramData\\Bitdefender\\ShadowStrike\\config.db";
                
                // Security
                bool enableEncryption = true;
                std::vector<uint8_t> masterKey;     // AES-256 key for encryption
                bool requireStrongKeys = true;       // Enforce key strength
                
                // Audit
                bool enableAuditLog = true;
                bool trackAllChanges = true;
                size_t maxAuditRecords = 100000;
                
                // Versioning
                bool enableVersioning = true;
                size_t maxVersionsPerKey = 10;
                
                // Validation
                bool enforceValidation = true;
                bool allowUnknownKeys = false;
                
                // Performance
                bool enableCaching = true;
                size_t maxCacheEntries = 10000;
                std::chrono::milliseconds cacheRefreshInterval = std::chrono::minutes(5);
                
                // Hot-reload
                bool enableHotReload = true;
                std::chrono::milliseconds hotReloadInterval = std::chrono::seconds(30);
            };

            struct Statistics {
                size_t totalKeys = 0;
                size_t systemKeys = 0;
                size_t globalKeys = 0;
                size_t groupKeys = 0;
                size_t agentKeys = 0;
                size_t encryptedKeys = 0;
                size_t readOnlyKeys = 0;
                
                uint64_t totalReads = 0;
                uint64_t totalWrites = 0;
                uint64_t totalDeletes = 0;
                uint64_t cacheHits = 0;
                uint64_t cacheMisses = 0;
                
                size_t totalChanges = 0;
                std::chrono::system_clock::time_point lastChange;
            };

            // ============================================================================
            // Lifecycle
            // ============================================================================

            static ConfigurationDB& Instance();

            bool Initialize(const Config& config, DatabaseError* err = nullptr);
            void Shutdown();
            bool IsInitialized() const noexcept { return m_initialized.load(); }

            // ============================================================================
            // Basic Operations
            // ============================================================================

            // Set configuration value
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
