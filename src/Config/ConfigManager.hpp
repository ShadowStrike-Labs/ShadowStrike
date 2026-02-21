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
 * ============================================================================
 * ShadowStrike NGAV - CONFIGURATION MANAGER MODULE
 * ============================================================================
 *
 * @file ConfigManager.hpp
 * @brief Enterprise-grade unified configuration management system with layered
 *        configuration, hot-reloading, validation, and encryption support.
 *
 * Central hub for all application settings with type-safe access, change
 * notifications, and enterprise policy integration.
 *
 * CONFIGURATION ARCHITECTURE:
 * ===========================
 *
 * 1. LAYERED CONFIGURATION
 *    - Factory defaults
 *    - System-wide settings
 *    - Enterprise policies (immutable)
 *    - User preferences
 *    - Session overrides
 *
 * 2. TYPE-SAFE ACCESS
 *    - Strongly-typed getters/setters
 *    - Compile-time validation
 *    - Default value fallbacks
 *    - Type conversion utilities
 *
 * 3. HOT-RELOADING
 *    - File change detection
 *    - Automatic refresh
 *    - Change notifications
 *    - Atomic updates
 *
 * 4. VALIDATION
 *    - Schema validation
 *    - Range checking
 *    - Dependency validation
 *    - Constraint enforcement
 *
 * 5. SECURITY
 *    - Sensitive field encryption
 *    - Access control
 *    - Audit logging
 *    - Tamper detection
 *
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <unordered_map>
#include <optional>
#include <variant>
#include <any>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>
#include <span>
#include <type_traits>
#include <typeindex>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Database/ConfigurationDB.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Config {
    class ConfigManagerImpl;
}

namespace ShadowStrike {
namespace Config {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace ConfigConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum key length
    inline constexpr size_t MAX_KEY_LENGTH = 256;
    
    /// @brief Maximum value length
    inline constexpr size_t MAX_VALUE_LENGTH = 65536;
    
    /// @brief Maximum array elements
    inline constexpr size_t MAX_ARRAY_ELEMENTS = 1024;
    
    /// @brief Hot-reload interval (milliseconds)
    inline constexpr uint32_t HOT_RELOAD_INTERVAL_MS = 1000;
    
    /// @brief Maximum layers
    inline constexpr uint32_t MAX_CONFIG_LAYERS = 16;

}  // namespace ConfigConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

/// @brief Configuration value variant
using ConfigValue = std::variant<
    std::monostate,
    bool,
    int32_t,
    int64_t,
    uint32_t,
    uint64_t,
    double,
    std::string,
    std::wstring,
    std::vector<std::string>,
    std::vector<int64_t>,
    std::map<std::string, std::string>
>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Configuration layer priority
 */
enum class ConfigLayer : uint8_t {
    Default         = 0,    ///< Factory defaults (lowest priority)
    System          = 1,    ///< System-wide settings
    Enterprise      = 2,    ///< Enterprise policy (from management console)
    Policy          = 3,    ///< Group policy settings
    User            = 4,    ///< User preferences
    Session         = 5,    ///< Temporary session overrides
    Override        = 6     ///< Runtime overrides (highest priority)
};

/**
 * @brief Value type
 */
enum class ValueType : uint8_t {
    Null        = 0,
    Boolean     = 1,
    Integer     = 2,
    UInteger    = 3,
    Float       = 4,
    String      = 5,
    WString     = 6,
    StringList  = 7,
    IntList     = 8,
    Map         = 9,
    Binary      = 10,
    Unknown     = 11
};

/**
 * @brief Change reason
 */
enum class ChangeReason : uint8_t {
    Initialization      = 0,
    UserModification    = 1,
    PolicyUpdate        = 2,
    HotReload           = 3,
    Import              = 4,
    Reset               = 5,
    Migration           = 6,
    Rollback            = 7
};

/**
 * @brief Validation result
 */
enum class ValidationResult : uint8_t {
    Valid               = 0,
    InvalidType         = 1,
    OutOfRange          = 2,
    InvalidFormat       = 3,
    DependencyFailed    = 4,
    ReadOnly            = 5,
    PolicyLocked        = 6,
    Deprecated          = 7,
    Unknown             = 8
};

/**
 * @brief Manager status
 */
enum class ConfigStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Reloading       = 3,
    Migrating       = 4,
    Error           = 5,
    Stopping        = 6,
    Stopped         = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Configuration key metadata
 */
struct ConfigKeyMetadata {
    /// @brief Key name
    std::string key;
    
    /// @brief Display name
    std::string displayName;
    
    /// @brief Description
    std::string description;
    
    /// @brief Category
    std::string category;
    
    /// @brief Value type
    ValueType valueType = ValueType::Unknown;
    
    /// @brief Default value
    ConfigValue defaultValue;
    
    /// @brief Minimum value (for numeric types)
    std::optional<double> minValue;
    
    /// @brief Maximum value (for numeric types)
    std::optional<double> maxValue;
    
    /// @brief Allowed values (for enum-like strings)
    std::vector<std::string> allowedValues;
    
    /// @brief Is sensitive (requires encryption)
    bool isSensitive = false;
    
    /// @brief Is read-only
    bool isReadOnly = false;
    
    /// @brief Is deprecated
    bool isDeprecated = false;
    
    /// @brief Requires restart
    bool requiresRestart = false;
    
    /// @brief Dependencies (keys that must be set first)
    std::vector<std::string> dependencies;
    
    /// @brief Version added
    std::string versionAdded;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration change event
 */
struct ConfigChangeEvent {
    /// @brief Key that changed
    std::string key;
    
    /// @brief Old value
    ConfigValue oldValue;
    
    /// @brief New value
    ConfigValue newValue;
    
    /// @brief Layer that changed
    ConfigLayer layer = ConfigLayer::Default;
    
    /// @brief Reason for change
    ChangeReason reason = ChangeReason::UserModification;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief User/source that made the change
    std::string source;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration snapshot
 */
struct ConfigSnapshot {
    /// @brief Snapshot ID
    uint64_t snapshotId = 0;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Configuration data
    std::map<std::string, ConfigValue> values;
    
    /// @brief Layer
    ConfigLayer layer = ConfigLayer::User;
    
    /// @brief Description
    std::string description;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration validation error
 */
struct ConfigValidationError {
    /// @brief Key with error
    std::string key;
    
    /// @brief Error result
    ValidationResult result = ValidationResult::Unknown;
    
    /// @brief Error message
    std::string message;
    
    /// @brief Suggested fix
    std::optional<std::string> suggestedFix;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Import/export options
 */
struct ConfigIOOptions {
    /// @brief Include defaults
    bool includeDefaults = false;
    
    /// @brief Include sensitive values
    bool includeSensitive = false;
    
    /// @brief Include metadata
    bool includeMetadata = true;
    
    /// @brief Encrypt sensitive values
    bool encryptSensitive = true;
    
    /// @brief Layers to include
    std::set<ConfigLayer> layers = {ConfigLayer::User};
    
    /// @brief Categories to include (empty = all)
    std::set<std::string> categories;
};

/**
 * @brief Statistics
 */
struct ConfigStatistics {
    std::atomic<uint64_t> totalReads{0};
    std::atomic<uint64_t> totalWrites{0};
    std::atomic<uint64_t> cacheHits{0};
    std::atomic<uint64_t> cacheMisses{0};
    std::atomic<uint64_t> validationErrors{0};
    std::atomic<uint64_t> hotReloads{0};
    std::atomic<uint64_t> policyUpdates{0};
    std::atomic<uint64_t> snapshotsTaken{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct ConfigManagerConfiguration {
    /// @brief Database path
    fs::path databasePath;
    
    /// @brief Enable hot-reloading
    bool enableHotReload = true;
    
    /// @brief Hot-reload interval (milliseconds)
    uint32_t hotReloadIntervalMs = ConfigConstants::HOT_RELOAD_INTERVAL_MS;
    
    /// @brief Enable caching
    bool enableCaching = true;
    
    /// @brief Cache TTL (seconds)
    uint32_t cacheTtlSeconds = 300;
    
    /// @brief Enable encryption for sensitive values
    bool encryptSensitiveValues = true;
    
    /// @brief Enable change auditing
    bool enableAuditing = true;
    
    /// @brief Maximum snapshots to retain
    uint32_t maxSnapshots = 100;
    
    /// @brief Validate on load
    bool validateOnLoad = true;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ChangeCallback = std::function<void(const ConfigChangeEvent&)>;
using ValidationCallback = std::function<ValidationResult(const std::string& key, const ConfigValue& value)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// CONFIG MANAGER CLASS
// ============================================================================

/**
 * @class ConfigManager
 * @brief Enterprise configuration management
 */
class ConfigManager final {
public:
    [[nodiscard]] static ConfigManager& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    ConfigManager(ConfigManager&&) = delete;
    ConfigManager& operator=(ConfigManager&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const ConfigManagerConfiguration& config = {});
    [[nodiscard]] bool Initialize(const std::wstring& dbPath);
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ConfigStatus GetStatus() const noexcept;

    // ========================================================================
    // TYPE-SAFE GETTERS
    // ========================================================================
    
    /// @brief Get value with type and default
    template<typename T>
    [[nodiscard]] T GetValue(const std::string& key, const T& defaultValue) const;
    
    /// @brief Get value with type and default (wide key)
    template<typename T>
    [[nodiscard]] T GetValue(const std::wstring& key, const T& defaultValue) const;
    
    /// @brief Get optional value
    template<typename T>
    [[nodiscard]] std::optional<T> GetOptionalValue(const std::string& key) const;
    
    /// @brief Get value from specific layer
    template<typename T>
    [[nodiscard]] std::optional<T> GetValueFromLayer(const std::string& key, ConfigLayer layer) const;

    // ========================================================================
    // TYPE-SAFE SETTERS
    // ========================================================================
    
    /// @brief Set value with type
    template<typename T>
    [[nodiscard]] bool SetValue(const std::string& key, const T& value, ConfigLayer layer = ConfigLayer::User);
    
    /// @brief Set value (wide key)
    template<typename T>
    [[nodiscard]] bool SetValue(const std::wstring& key, const T& value, ConfigLayer layer = ConfigLayer::User);
    
    /// @brief Set value with validation
    template<typename T>
    [[nodiscard]] std::pair<bool, std::string> SetValueValidated(
        const std::string& key, const T& value, ConfigLayer layer = ConfigLayer::User);

    // ========================================================================
    // GENERIC VALUE OPERATIONS
    // ========================================================================
    
    /// @brief Get raw value
    [[nodiscard]] ConfigValue GetRawValue(const std::string& key) const;
    
    /// @brief Set raw value
    [[nodiscard]] bool SetRawValue(const std::string& key, const ConfigValue& value, ConfigLayer layer = ConfigLayer::User);
    
    /// @brief Check if key exists
    [[nodiscard]] bool HasKey(const std::string& key) const;
    
    /// @brief Get value type
    [[nodiscard]] ValueType GetValueType(const std::string& key) const;
    
    /// @brief Delete value
    [[nodiscard]] bool DeleteValue(const std::string& key, ConfigLayer layer = ConfigLayer::User);
    
    /// @brief Get effective layer for key
    [[nodiscard]] ConfigLayer GetEffectiveLayer(const std::string& key) const;

    // ========================================================================
    // BULK OPERATIONS
    // ========================================================================
    
    /// @brief Get all keys
    [[nodiscard]] std::vector<std::string> GetAllKeys() const;
    
    /// @brief Get keys by category
    [[nodiscard]] std::vector<std::string> GetKeysByCategory(const std::string& category) const;
    
    /// @brief Get all values as map
    [[nodiscard]] std::map<std::string, ConfigValue> GetAllValues(ConfigLayer layer = ConfigLayer::User) const;
    
    /// @brief Set multiple values
    [[nodiscard]] bool SetMultipleValues(
        const std::map<std::string, ConfigValue>& values,
        ConfigLayer layer = ConfigLayer::User);

    // ========================================================================
    // METADATA
    // ========================================================================
    
    /// @brief Register key metadata
    [[nodiscard]] bool RegisterKeyMetadata(const ConfigKeyMetadata& metadata);
    
    /// @brief Get key metadata
    [[nodiscard]] std::optional<ConfigKeyMetadata> GetKeyMetadata(const std::string& key) const;
    
    /// @brief Get all categories
    [[nodiscard]] std::vector<std::string> GetCategories() const;

    // ========================================================================
    // HOT-RELOADING
    // ========================================================================
    
    /// @brief Trigger manual reload
    void Reload();
    
    /// @brief Force reload from disk
    void ForceReload();
    
    /// @brief Enable/disable hot-reload
    void SetHotReloadEnabled(bool enabled);
    
    /// @brief Is hot-reload enabled
    [[nodiscard]] bool IsHotReloadEnabled() const noexcept;

    // ========================================================================
    // VALIDATION
    // ========================================================================
    
    /// @brief Validate single value
    [[nodiscard]] ValidationResult ValidateValue(const std::string& key, const ConfigValue& value) const;
    
    /// @brief Validate all configuration
    [[nodiscard]] std::vector<ConfigValidationError> ValidateAll() const;
    
    /// @brief Register custom validator
    void RegisterValidator(const std::string& key, ValidationCallback validator);

    // ========================================================================
    // SNAPSHOTS
    // ========================================================================
    
    /// @brief Create snapshot
    [[nodiscard]] uint64_t CreateSnapshot(const std::string& description = "");
    
    /// @brief Restore from snapshot
    [[nodiscard]] bool RestoreSnapshot(uint64_t snapshotId);
    
    /// @brief List snapshots
    [[nodiscard]] std::vector<ConfigSnapshot> ListSnapshots() const;
    
    /// @brief Delete snapshot
    [[nodiscard]] bool DeleteSnapshot(uint64_t snapshotId);

    // ========================================================================
    // IMPORT/EXPORT
    // ========================================================================
    
    /// @brief Export to file
    [[nodiscard]] bool ExportToFile(const fs::path& filePath, const ConfigIOOptions& options = {}) const;
    
    /// @brief Import from file
    [[nodiscard]] bool ImportFromFile(const fs::path& filePath, ConfigLayer targetLayer = ConfigLayer::User);
    
    /// @brief Export to JSON string
    [[nodiscard]] std::string ExportToJson(const ConfigIOOptions& options = {}) const;
    
    /// @brief Import from JSON string
    [[nodiscard]] bool ImportFromJson(const std::string& json, ConfigLayer targetLayer = ConfigLayer::User);

    // ========================================================================
    // DEFAULTS
    // ========================================================================
    
    /// @brief Reset to defaults
    void ResetToDefaults(ConfigLayer layer = ConfigLayer::User);
    
    /// @brief Reset single key to default
    [[nodiscard]] bool ResetKeyToDefault(const std::string& key);
    
    /// @brief Load factory defaults
    void LoadFactoryDefaults();

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /// @brief Register change callback
    uint64_t RegisterChangeCallback(ChangeCallback callback);
    
    /// @brief Register callback for specific key
    uint64_t RegisterKeyChangeCallback(const std::string& key, ChangeCallback callback);
    
    /// @brief Unregister callback
    void UnregisterCallback(uint64_t callbackId);
    
    /// @brief Register error callback
    void RegisterErrorCallback(ErrorCallback callback);

    // ========================================================================
    // STATISTICS & DIAGNOSTICS
    // ========================================================================
    
    [[nodiscard]] ConfigStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    ConfigManager();
    ~ConfigManager();
    
    std::unique_ptr<ConfigManagerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetConfigLayerName(ConfigLayer layer) noexcept;
[[nodiscard]] std::string_view GetValueTypeName(ValueType type) noexcept;
[[nodiscard]] std::string_view GetChangeReasonName(ChangeReason reason) noexcept;
[[nodiscard]] std::string_view GetValidationResultName(ValidationResult result) noexcept;

/// @brief Convert ConfigValue to string
[[nodiscard]] std::string ConfigValueToString(const ConfigValue& value);

/// @brief Parse string to ConfigValue
[[nodiscard]] ConfigValue ParseConfigValue(const std::string& str, ValueType expectedType);

/// @brief Get type of ConfigValue
[[nodiscard]] ValueType GetConfigValueType(const ConfigValue& value);

}  // namespace Config
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_CONFIG_GET(key, default) \
    ::ShadowStrike::Config::ConfigManager::Instance().GetValue(key, default)

#define SS_CONFIG_SET(key, value) \
    ::ShadowStrike::Config::ConfigManager::Instance().SetValue(key, value)

#define SS_CONFIG_HAS(key) \
    ::ShadowStrike::Config::ConfigManager::Instance().HasKey(key)
