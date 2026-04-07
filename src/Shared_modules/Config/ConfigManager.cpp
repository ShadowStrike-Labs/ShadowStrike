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
#include "pch.h"
#include "ConfigManager.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../SelfProtection/CryptoManager.hpp"
#include "../Database/ConfigurationDB.hpp"

#include <sstream>
#include <thread>
#include <charconv>
#include <cstring>
#include <limits>

namespace ShadowStrike {
namespace Config {

// ============================================================================
// STRING CONVERSION HELPERS (narrow <-> wide)
// ============================================================================

namespace {

[[nodiscard]] std::wstring NarrowToWide(const std::string& narrow) noexcept {
    if (narrow.empty()) return {};
    const int needed = ::MultiByteToWideChar(
        CP_UTF8, 0, narrow.data(), static_cast<int>(narrow.size()), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring wide(static_cast<size_t>(needed), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, narrow.data(),
        static_cast<int>(narrow.size()), wide.data(), needed);
    return wide;
}

[[nodiscard]] std::string WideToNarrow(const std::wstring& wide) noexcept {
    if (wide.empty()) return {};
    const int needed = ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
        nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string narrow(static_cast<size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, wide.data(),
        static_cast<int>(wide.size()), narrow.data(), needed,
        nullptr, nullptr);
    return narrow;
}

// Convert Config::ConfigValue -> Database::ConfigurationDB::ConfigValue for DB persistence
[[nodiscard]] std::optional<Database::ConfigurationDB::ConfigValue>
ConfigValueToDbValue(const ConfigValue& cv) noexcept {
    try {
        if (std::holds_alternative<std::monostate>(cv)) {
            return std::nullopt;
        }
        if (const auto* v = std::get_if<bool>(&cv)) {
            return Database::ConfigurationDB::ConfigValue{*v};
        }
        if (const auto* v = std::get_if<int32_t>(&cv)) {
            return Database::ConfigurationDB::ConfigValue{static_cast<int64_t>(*v)};
        }
        if (const auto* v = std::get_if<int64_t>(&cv)) {
            return Database::ConfigurationDB::ConfigValue{*v};
        }
        if (const auto* v = std::get_if<uint32_t>(&cv)) {
            return Database::ConfigurationDB::ConfigValue{static_cast<int64_t>(*v)};
        }
        if (const auto* v = std::get_if<uint64_t>(&cv)) {
            if (*v > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
                SS_LOG_WARN(L"Config",
                    L"uint64_t value %llu exceeds int64_t range — storing as double",
                    *v);
                return Database::ConfigurationDB::ConfigValue{static_cast<double>(*v)};
            }
            return Database::ConfigurationDB::ConfigValue{static_cast<int64_t>(*v)};
        }
        if (const auto* v = std::get_if<double>(&cv)) {
            return Database::ConfigurationDB::ConfigValue{*v};
        }
        if (const auto* v = std::get_if<std::string>(&cv)) {
            return Database::ConfigurationDB::ConfigValue{NarrowToWide(*v)};
        }
        if (const auto* v = std::get_if<std::wstring>(&cv)) {
            return Database::ConfigurationDB::ConfigValue{*v};
        }
        // Complex types -> JSON string in DB
        if (const auto* v = std::get_if<std::vector<std::string>>(&cv)) {
            Utils::JSON::Json arr = Utils::JSON::Json::array();
            for (const auto& s : *v) arr.push_back(s);
            return Database::ConfigurationDB::ConfigValue{NarrowToWide(arr.dump())};
        }
        if (const auto* v = std::get_if<std::vector<int64_t>>(&cv)) {
            Utils::JSON::Json arr = Utils::JSON::Json::array();
            for (const auto& i : *v) arr.push_back(i);
            return Database::ConfigurationDB::ConfigValue{NarrowToWide(arr.dump())};
        }
        if (const auto* v = std::get_if<std::map<std::string, std::string>>(&cv)) {
            Utils::JSON::Json obj = Utils::JSON::Json::object();
            for (const auto& [k, val] : *v) obj[k] = val;
            return Database::ConfigurationDB::ConfigValue{NarrowToWide(obj.dump())};
        }
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"Config", L"Exception in ConfigValueToDbValue: %hs", ex.what());
    } catch (...) {
        SS_LOG_ERROR(L"Config", L"Unknown exception in ConfigValueToDbValue");
    }
    return std::nullopt;
}

// Convert Database::ConfigurationDB::ConfigValue -> Config::ConfigValue
[[nodiscard]] ConfigValue DbValueToConfigValue(
    const Database::ConfigurationDB::ConfigValue& dbv) noexcept {
    try {
        if (const auto* v = std::get_if<bool>(&dbv)) {
            return ConfigValue{*v};
        }
        if (const auto* v = std::get_if<int64_t>(&dbv)) {
            return ConfigValue{*v};
        }
        if (const auto* v = std::get_if<double>(&dbv)) {
            return ConfigValue{*v};
        }
        if (const auto* v = std::get_if<std::wstring>(&dbv)) {
            return ConfigValue{WideToNarrow(*v)};
        }
        // JSON -> try to parse as string
        if (const auto* v = std::get_if<Utils::JSON::Json>(&dbv)) {
            if (v->is_string()) {
                return ConfigValue{v->get<std::string>()};
            }
            return ConfigValue{v->dump()};
        }
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"Config", L"Exception in DbValueToConfigValue: %hs", ex.what());
    } catch (...) {
        SS_LOG_ERROR(L"Config", L"Unknown exception in DbValueToConfigValue");
    }
    return ConfigValue{std::monostate{}};
}

} // anonymous namespace

// ============================================================================
// CONFIGMANAGERIMPL - PIMPL INTERNALS
// ============================================================================

class ConfigManagerImpl {
public:
    ConfigManagerConfiguration m_config;
    std::atomic<ConfigStatus> m_status{ConfigStatus::Uninitialized};
    std::array<std::map<std::string, ConfigValue>, 7> m_layers;
    std::unordered_map<std::string, ConfigKeyMetadata> m_metadata;
    std::unordered_map<std::string, ValidationCallback> m_validators;
    std::unordered_map<uint64_t, ChangeCallback> m_globalCallbacks;
    std::unordered_map<std::string, std::unordered_map<uint64_t, ChangeCallback>> m_keyCallbacks;
    ErrorCallback m_errorCallback;
    uint64_t m_nextCallbackId{1};
    std::map<uint64_t, ConfigSnapshot> m_snapshots;
    uint64_t m_nextSnapshotId{1};
    ConfigStatistics m_stats;
    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_hotReloadEnabled{true};
    std::atomic<bool> m_shutdownRequested{false};
    std::jthread m_hotReloadThread;

    // ========================================================================
    // Layer Resolution
    // ========================================================================

    [[nodiscard]] ConfigValue ResolveValue(const std::string& key) const {
        // Check layers from highest (Override=6) to lowest (Default=0)
        for (int i = 6; i >= 0; --i) {
            auto it = m_layers[static_cast<size_t>(i)].find(key);
            if (it != m_layers[static_cast<size_t>(i)].end()) {
                if (!std::holds_alternative<std::monostate>(it->second)) {
                    return it->second;
                }
            }
        }
        return ConfigValue{std::monostate{}};
    }

    [[nodiscard]] ConfigLayer ResolveEffectiveLayer(const std::string& key) const {
        for (int i = 6; i >= 0; --i) {
            auto it = m_layers[static_cast<size_t>(i)].find(key);
            if (it != m_layers[static_cast<size_t>(i)].end()) {
                if (!std::holds_alternative<std::monostate>(it->second)) {
                    return static_cast<ConfigLayer>(i);
                }
            }
        }
        return ConfigLayer::Default;
    }

    // ========================================================================
    // Deferred Callback Invocation (avoids deadlock from firing under lock)
    // ========================================================================

    struct PendingCallbacks {
        std::vector<std::pair<uint64_t, ChangeCallback>> callbacks;
        ConfigChangeEvent event;
    };

    /// Collect callbacks to fire later (called UNDER the lock)
    [[nodiscard]] PendingCallbacks CollectCallbacks(const ConfigChangeEvent& event) const {
        PendingCallbacks pending;
        pending.event = event;
        for (const auto& [id, cb] : m_globalCallbacks) {
            if (cb) pending.callbacks.emplace_back(id, cb);
        }
        auto it = m_keyCallbacks.find(event.key);
        if (it != m_keyCallbacks.end()) {
            for (const auto& [id, cb] : it->second) {
                if (cb) pending.callbacks.emplace_back(id, cb);
            }
        }
        return pending;
    }

    /// Fire collected callbacks (called WITHOUT the lock)
    static void FirePendingCallbacks(const PendingCallbacks& pending) {
        for (const auto& [id, cb] : pending.callbacks) {
            try {
                cb(pending.event);
            } catch (...) {
                SS_LOG_WARN(L"Config", L"Change callback %llu threw exception", id);
            }
        }
    }

    // ========================================================================
    // Fire Change Callbacks (legacy - only safe to call without holding m_mutex)
    // ========================================================================

    void FireChangeCallbacks(const ConfigChangeEvent& event) {
        // Global callbacks
        for (const auto& [id, cb] : m_globalCallbacks) {
            try { if (cb) cb(event); } catch (...) {
                SS_LOG_WARN(L"Config", L"Global change callback %llu threw exception", id);
            }
        }
        // Per-key callbacks
        auto it = m_keyCallbacks.find(event.key);
        if (it != m_keyCallbacks.end()) {
            for (const auto& [id, cb] : it->second) {
                try { if (cb) cb(event); } catch (...) {
                    SS_LOG_WARN(L"Config", L"Key change callback %llu threw exception for key", id);
                }
            }
        }
    }

    // ========================================================================
    // Report Error via Callback
    // ========================================================================

    void ReportError(const std::string& message, int code) {
        if (m_errorCallback) {
            try { m_errorCallback(message, code); } catch (...) {}
        }
    }

    // ========================================================================
    // Persist to DB
    // ========================================================================

    void PersistToDb(const std::string& key, const ConfigValue& value) {
        auto& db = Database::ConfigurationDB::Instance();
        if (!db.IsInitialized()) return;

        auto dbVal = ConfigValueToDbValue(value);
        if (!dbVal.has_value()) return;

        std::wstring wideKey = NarrowToWide(key);
        db.Set(wideKey, dbVal.value(), Database::ConfigurationDB::ConfigScope::Global,
               L"ConfigManager", L"");
    }

    // ========================================================================
    // Load from DB into Default layer
    // ========================================================================

    void LoadFromDb() {
        auto& db = Database::ConfigurationDB::Instance();
        if (!db.IsInitialized()) return;

        try {
            auto keys = db.GetAllKeys();
            for (const auto& wideKey : keys) {
                auto optVal = db.Get(wideKey);
                if (optVal.has_value()) {
                    std::string narrowKey = WideToNarrow(wideKey);
                    m_layers[static_cast<size_t>(ConfigLayer::Default)][narrowKey] =
                        DbValueToConfigValue(optVal.value());
                }
            }
            SS_LOG_INFO(L"Config", L"Loaded %zu keys from ConfigurationDB",
                        keys.size());
        } catch (...) {
            SS_LOG_ERROR(L"Config", L"Exception loading configuration from database");
        }
    }

    // ========================================================================
    // Encrypt/Decrypt Sensitive Values
    // ========================================================================

    [[nodiscard]] ConfigValue EncryptSensitiveValue(const ConfigValue& value) const {
        const auto* strVal = std::get_if<std::string>(&value);
        if (!strVal) return value;

        try {
            auto& crypto = Security::CryptoManager::Instance();
            std::span<const uint8_t> plainSpan(
                reinterpret_cast<const uint8_t*>(strVal->data()), strVal->size());

            auto protectedData = crypto.DPAPIProtect(plainSpan);
            if (!protectedData.has_value() || protectedData->empty()) {
                SS_LOG_ERROR(L"Config",
                    L"DPAPI protection failed for sensitive config value — "
                    L"value will NOT be stored to prevent plaintext exposure");
                return ConfigValue{std::monostate{}};
            }

            // Pack as: marker prefix + DPAPI blob
            std::string packed;
            packed.reserve(6 + protectedData->size());
            packed.append("\x01""DPAPI:");
            packed.append(reinterpret_cast<const char*>(protectedData->data()),
                          protectedData->size());

            return ConfigValue{std::move(packed)};
        } catch (...) {
            SS_LOG_ERROR(L"Config",
                L"Exception encrypting sensitive value — "
                L"refusing to store plaintext");
            return ConfigValue{std::monostate{}};
        }
    }

    [[nodiscard]] ConfigValue DecryptSensitiveValue(const ConfigValue& value) const {
        const auto* strVal = std::get_if<std::string>(&value);
        if (!strVal) return value;

        // Support new DPAPI format
        static constexpr std::string_view kDpapiPrefix = "\x01""DPAPI:";
        if (strVal->size() > kDpapiPrefix.size() &&
            strVal->substr(0, kDpapiPrefix.size()) == kDpapiPrefix) {
            try {
                auto& crypto = Security::CryptoManager::Instance();
                const size_t blobOffset = kDpapiPrefix.size();
                const size_t blobSize = strVal->size() - blobOffset;

                std::span<const uint8_t> protectedSpan(
                    reinterpret_cast<const uint8_t*>(strVal->data() + blobOffset),
                    blobSize);

                auto plainData = crypto.DPAPIUnprotect(protectedSpan);
                if (!plainData.has_value()) {
                    SS_LOG_ERROR(L"Config", L"DPAPI unprotection failed for sensitive config value");
                    return value;
                }

                return ConfigValue{std::string(plainData->begin(), plainData->end())};
            } catch (...) {
                SS_LOG_ERROR(L"Config", L"Exception during DPAPI decryption of sensitive value");
                return value;
            }
        }

        // Legacy ENC format: fail-closed — do not attempt decryption with
        // key-alongside-ciphertext scheme. Log and return opaque value.
        static constexpr std::string_view kLegacyPrefix = "\x01""ENC:";
        if (strVal->size() > kLegacyPrefix.size() &&
            strVal->substr(0, kLegacyPrefix.size()) == kLegacyPrefix) {
            SS_LOG_WARN(L"Config",
                L"Legacy ENC-format sensitive value detected — "
                L"re-encrypt with DPAPI by re-setting the value");
            return value;
        }

        return value;
    }

    // ========================================================================
    // Hot-Reload Background Thread
    // ========================================================================

    void HotReloadLoop(std::stop_token stopToken) {
        SS_LOG_INFO(L"Config", L"Hot-reload thread started, interval=%u ms",
                    m_config.hotReloadIntervalMs);

        while (!stopToken.stop_requested() && !m_shutdownRequested.load()) {
            // Sleep in small increments for responsiveness
            const auto interval = std::chrono::milliseconds(m_config.hotReloadIntervalMs);
            const auto step = std::chrono::milliseconds(100);
            auto remaining = interval;
            while (remaining > std::chrono::milliseconds::zero()) {
                if (stopToken.stop_requested() || m_shutdownRequested.load()) return;
                auto sleepTime = std::min(remaining, step);
                std::this_thread::sleep_for(sleepTime);
                remaining -= sleepTime;
            }

            if (!m_hotReloadEnabled.load()) continue;

            try {
                auto& db = Database::ConfigurationDB::Instance();
                if (!db.IsInitialized()) continue;

                std::vector<PendingCallbacks> pendingList;
                {
                    std::unique_lock lock(m_mutex);
                    m_status.store(ConfigStatus::Reloading, std::memory_order_release);

                    auto keys = db.GetAllKeys();
                    for (const auto& wideKey : keys) {
                        auto optVal = db.Get(wideKey);
                        if (!optVal.has_value()) continue;

                        std::string narrowKey = WideToNarrow(wideKey);
                        auto newValue = DbValueToConfigValue(optVal.value());
                        auto& defaultLayer = m_layers[static_cast<size_t>(ConfigLayer::Default)];
                        auto it = defaultLayer.find(narrowKey);

                        bool changed = (it == defaultLayer.end());
                        if (!changed) {
                            changed = (it->second.index() != newValue.index());
                            if (!changed) {
                                changed = (ConfigValueToString(it->second) !=
                                           ConfigValueToString(newValue));
                            }
                        }

                        if (changed) {
                            ConfigValue oldValue = (it != defaultLayer.end())
                                ? it->second : ConfigValue{std::monostate{}};
                            defaultLayer[narrowKey] = newValue;

                            ConfigChangeEvent event;
                            event.key = narrowKey;
                            event.oldValue = oldValue;
                            event.newValue = newValue;
                            event.layer = ConfigLayer::Default;
                            event.reason = ChangeReason::HotReload;
                            event.timestamp = std::chrono::system_clock::now();
                            event.source = "HotReload";
                            pendingList.push_back(CollectCallbacks(event));
                        }
                    }

                    m_stats.hotReloads.fetch_add(1, std::memory_order_relaxed);
                    m_status.store(ConfigStatus::Running, std::memory_order_release);
                }

                // Fire callbacks OUTSIDE the lock
                for (const auto& pending : pendingList) {
                    FirePendingCallbacks(pending);
                }
            } catch (...) {
                SS_LOG_ERROR(L"Config", L"Exception during hot-reload cycle");
                m_status.store(ConfigStatus::Running, std::memory_order_release);
            }
        }

        SS_LOG_INFO(L"Config", L"Hot-reload thread exiting");
    }
};

// ============================================================================
// STATIC MEMBERS
// ============================================================================

std::atomic<bool> ConfigManager::s_instanceCreated{false};

// ============================================================================
// SINGLETON
// ============================================================================

ConfigManager& ConfigManager::Instance() noexcept {
    static ConfigManager instance;
    return instance;
}

bool ConfigManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

ConfigManager::ConfigManager()
    : m_impl(std::make_unique<ConfigManagerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

ConfigManager::~ConfigManager() {
    Shutdown();
    s_instanceCreated.store(false, std::memory_order_release);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool ConfigManager::Initialize(const ConfigManagerConfiguration& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(L"Config",
            L"Initialize failed: invalid configuration "
            L"(hotReloadIntervalMs=%u, maxSnapshots=%u, cacheTtlSeconds=%u, enableCaching=%d)",
            config.hotReloadIntervalMs, config.maxSnapshots,
            config.cacheTtlSeconds, config.enableCaching ? 1 : 0);
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_status.load(std::memory_order_acquire) == ConfigStatus::Running) {
        SS_LOG_WARN(L"Config", L"ConfigManager already initialized");
        return true;
    }

    m_impl->m_status.store(ConfigStatus::Initializing, std::memory_order_release);
    m_impl->m_config = config;
    m_impl->m_stats.startTime = Clock::now();

    SS_LOG_INFO(L"Config", L"Initializing ConfigManager v%u.%u.%u",
                ConfigConstants::VERSION_MAJOR,
                ConfigConstants::VERSION_MINOR,
                ConfigConstants::VERSION_PATCH);

    // Load values from ConfigurationDB into Default layer
    m_impl->LoadFromDb();

    // Start hot-reload thread if enabled
    if (config.enableHotReload) {
        m_impl->m_shutdownRequested.store(false);
        m_impl->m_hotReloadEnabled.store(true);
        m_impl->m_hotReloadThread = std::jthread(
            [this](std::stop_token st) { m_impl->HotReloadLoop(st); });
    }

    m_impl->m_status.store(ConfigStatus::Running, std::memory_order_release);
    SS_LOG_INFO(L"Config", L"ConfigManager initialized successfully");
    return true;
}

bool ConfigManager::Initialize(const std::wstring& dbPath) {
    ConfigManagerConfiguration config;
    config.databasePath = dbPath;
    return Initialize(config);
}

void ConfigManager::Shutdown() {
    {
        std::unique_lock lock(m_impl->m_mutex);
        auto currentStatus = m_impl->m_status.load(std::memory_order_acquire);
        if (currentStatus == ConfigStatus::Stopped ||
            currentStatus == ConfigStatus::Uninitialized) {
            return;
        }
        m_impl->m_status.store(ConfigStatus::Stopping, std::memory_order_release);
    }

    SS_LOG_INFO(L"Config", L"ConfigManager shutting down");

    // Stop hot-reload thread
    m_impl->m_shutdownRequested.store(true);
    if (m_impl->m_hotReloadThread.joinable()) {
        m_impl->m_hotReloadThread.request_stop();
        m_impl->m_hotReloadThread.join();
    }

    m_impl->m_status.store(ConfigStatus::Stopped, std::memory_order_release);

    SS_LOG_INFO(L"Config", L"ConfigManager shutdown complete");
}

bool ConfigManager::IsInitialized() const noexcept {
    auto s = m_impl->m_status.load(std::memory_order_acquire);
    return s == ConfigStatus::Running || s == ConfigStatus::Reloading;
}

ConfigStatus ConfigManager::GetStatus() const noexcept {
    return m_impl->m_status.load(std::memory_order_acquire);
}

// ============================================================================
// TYPE-SAFE GETTERS (template implementations)
// ============================================================================

template<typename T>
T ConfigManager::GetValue(const std::string& key, const T& defaultValue) const {
    m_impl->m_stats.totalReads.fetch_add(1, std::memory_order_relaxed);

    if (key.empty() || key.size() > ConfigConstants::MAX_KEY_LENGTH) {
        return defaultValue;
    }

    std::shared_lock lock(m_impl->m_mutex);
    ConfigValue resolved = m_impl->ResolveValue(key);

    // If sensitive and encrypted, decrypt first
    auto metaIt = m_impl->m_metadata.find(key);
    if (metaIt != m_impl->m_metadata.end() && metaIt->second.isSensitive &&
        m_impl->m_config.encryptSensitiveValues) {
        resolved = m_impl->DecryptSensitiveValue(resolved);
    }

    const T* ptr = std::get_if<T>(&resolved);
    if (ptr) {
        m_impl->m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
        return *ptr;
    }

    m_impl->m_stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);
    return defaultValue;
}

template<typename T>
T ConfigManager::GetValue(const std::wstring& key, const T& defaultValue) const {
    return GetValue<T>(WideToNarrow(key), defaultValue);
}

template<typename T>
std::optional<T> ConfigManager::GetOptionalValue(const std::string& key) const {
    m_impl->m_stats.totalReads.fetch_add(1, std::memory_order_relaxed);

    if (key.empty() || key.size() > ConfigConstants::MAX_KEY_LENGTH) {
        return std::nullopt;
    }

    std::shared_lock lock(m_impl->m_mutex);
    ConfigValue resolved = m_impl->ResolveValue(key);

    if (std::holds_alternative<std::monostate>(resolved)) {
        return std::nullopt;
    }

    auto metaIt = m_impl->m_metadata.find(key);
    if (metaIt != m_impl->m_metadata.end() && metaIt->second.isSensitive &&
        m_impl->m_config.encryptSensitiveValues) {
        resolved = m_impl->DecryptSensitiveValue(resolved);
    }

    const T* ptr = std::get_if<T>(&resolved);
    if (ptr) {
        return *ptr;
    }
    return std::nullopt;
}

template<typename T>
std::optional<T> ConfigManager::GetValueFromLayer(
    const std::string& key, ConfigLayer layer) const {
    m_impl->m_stats.totalReads.fetch_add(1, std::memory_order_relaxed);

    if (key.empty() || static_cast<uint8_t>(layer) > 6) {
        return std::nullopt;
    }

    std::shared_lock lock(m_impl->m_mutex);
    const auto& layerMap = m_impl->m_layers[static_cast<size_t>(layer)];
    auto it = layerMap.find(key);
    if (it == layerMap.end() || std::holds_alternative<std::monostate>(it->second)) {
        return std::nullopt;
    }

    const T* ptr = std::get_if<T>(&it->second);
    if (ptr) {
        return *ptr;
    }
    return std::nullopt;
}

// ============================================================================
// TYPE-SAFE SETTERS (template implementations)
// ============================================================================

template<typename T>
bool ConfigManager::SetValue(const std::string& key, const T& value, ConfigLayer layer) {
    m_impl->m_stats.totalWrites.fetch_add(1, std::memory_order_relaxed);

    if (key.empty() || key.size() > ConfigConstants::MAX_KEY_LENGTH) {
        SS_LOG_ERROR(L"Config", L"SetValue failed: invalid key length");
        return false;
    }

    ConfigValue cv{value};
    return SetRawValue(key, cv, layer);
}

template<typename T>
bool ConfigManager::SetValue(const std::wstring& key, const T& value, ConfigLayer layer) {
    return SetValue<T>(WideToNarrow(key), value, layer);
}

template<typename T>
std::pair<bool, std::string> ConfigManager::SetValueValidated(
    const std::string& key, const T& value, ConfigLayer layer) {
    ConfigValue cv{value};
    auto result = ValidateValue(key, cv);
    if (result != ValidationResult::Valid) {
        std::string msg = "Validation failed for key '" + key + "': " +
                          std::string(GetValidationResultName(result));
        m_impl->m_stats.validationErrors.fetch_add(1, std::memory_order_relaxed);
        return {false, msg};
    }
    bool ok = SetValue<T>(key, value, layer);
    return {ok, ok ? std::string{} : "Failed to set value"};
}

// ============================================================================
// GENERIC VALUE OPERATIONS
// ============================================================================

ConfigValue ConfigManager::GetRawValue(const std::string& key) const {
    m_impl->m_stats.totalReads.fetch_add(1, std::memory_order_relaxed);

    if (key.empty()) return ConfigValue{std::monostate{}};

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->ResolveValue(key);
}

bool ConfigManager::SetRawValue(const std::string& key, const ConfigValue& value,
                                 ConfigLayer layer) {
    m_impl->m_stats.totalWrites.fetch_add(1, std::memory_order_relaxed);

    if (key.empty() || key.size() > ConfigConstants::MAX_KEY_LENGTH) {
        SS_LOG_ERROR(L"Config", L"SetRawValue failed: invalid key");
        return false;
    }

    if (static_cast<uint8_t>(layer) > 6) {
        SS_LOG_ERROR(L"Config", L"SetRawValue failed: invalid layer");
        return false;
    }

    ConfigManagerImpl::PendingCallbacks pending;
    {
        std::unique_lock lock(m_impl->m_mutex);

        // Check read-only / policy locked (under same unique_lock — no TOCTOU)
        auto metaIt = m_impl->m_metadata.find(key);
        if (metaIt != m_impl->m_metadata.end()) {
            if (metaIt->second.isReadOnly &&
                layer != ConfigLayer::Default && layer != ConfigLayer::Override) {
                SS_LOG_WARN(L"Config", L"Attempt to write read-only key: %hs", key.c_str());
                return false;
            }
        }

        ConfigValue oldValue = m_impl->ResolveValue(key);

        // Handle sensitive value encryption
        ConfigValue storeValue = value;
        if (metaIt != m_impl->m_metadata.end() && metaIt->second.isSensitive &&
            m_impl->m_config.encryptSensitiveValues) {
            storeValue = m_impl->EncryptSensitiveValue(value);
            if (std::holds_alternative<std::monostate>(storeValue)) {
                SS_LOG_ERROR(L"Config",
                    L"Refusing to store sensitive key '%hs': encryption failed", key.c_str());
                return false;
            }
        }

        m_impl->m_layers[static_cast<size_t>(layer)][key] = storeValue;

        // Persist to DB for User and System layers
        if (layer == ConfigLayer::User || layer == ConfigLayer::System) {
            m_impl->PersistToDb(key, value);
        }

        // Collect callbacks to fire OUTSIDE the lock
        ConfigChangeEvent event;
        event.key = key;
        event.oldValue = oldValue;
        event.newValue = value;
        event.layer = layer;
        event.reason = ChangeReason::UserModification;
        event.timestamp = std::chrono::system_clock::now();
        event.source = "SetRawValue";
        pending = m_impl->CollectCallbacks(event);
    }

    // Fire callbacks outside lock to prevent deadlock
    ConfigManagerImpl::FirePendingCallbacks(pending);

    SS_LOG_DEBUG(L"Config", L"Set key '%hs' in layer %hs",
                 key.c_str(), std::string(GetConfigLayerName(layer)).c_str());
    return true;
}

bool ConfigManager::HasKey(const std::string& key) const {
    if (key.empty()) return false;

    std::shared_lock lock(m_impl->m_mutex);
    ConfigValue resolved = m_impl->ResolveValue(key);
    return !std::holds_alternative<std::monostate>(resolved);
}

ValueType ConfigManager::GetValueType(const std::string& key) const {
    std::shared_lock lock(m_impl->m_mutex);
    ConfigValue resolved = m_impl->ResolveValue(key);
    return GetConfigValueType(resolved);
}

bool ConfigManager::DeleteValue(const std::string& key, ConfigLayer layer) {
    if (key.empty() || static_cast<uint8_t>(layer) > 6) return false;

    ConfigManagerImpl::PendingCallbacks pending;
    {
        std::unique_lock lock(m_impl->m_mutex);
        auto& layerMap = m_impl->m_layers[static_cast<size_t>(layer)];
        auto it = layerMap.find(key);
        if (it == layerMap.end()) return false;

        ConfigValue oldValue = it->second;
        layerMap.erase(it);

        ConfigChangeEvent event;
        event.key = key;
        event.oldValue = oldValue;
        event.newValue = ConfigValue{std::monostate{}};
        event.layer = layer;
        event.reason = ChangeReason::Reset;
        event.timestamp = std::chrono::system_clock::now();
        event.source = "DeleteValue";
        pending = m_impl->CollectCallbacks(event);
    }

    ConfigManagerImpl::FirePendingCallbacks(pending);

    SS_LOG_DEBUG(L"Config", L"Deleted key '%hs' from layer %hs",
                 key.c_str(), std::string(GetConfigLayerName(layer)).c_str());
    return true;
}

ConfigLayer ConfigManager::GetEffectiveLayer(const std::string& key) const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->ResolveEffectiveLayer(key);
}

// ============================================================================
// BULK OPERATIONS
// ============================================================================

std::vector<std::string> ConfigManager::GetAllKeys() const {
    std::shared_lock lock(m_impl->m_mutex);

    std::set<std::string> keySet;
    for (const auto& layer : m_impl->m_layers) {
        for (const auto& [k, v] : layer) {
            if (!std::holds_alternative<std::monostate>(v)) {
                keySet.insert(k);
            }
        }
    }
    return {keySet.begin(), keySet.end()};
}

std::vector<std::string> ConfigManager::GetKeysByCategory(const std::string& category) const {
    std::shared_lock lock(m_impl->m_mutex);

    std::vector<std::string> result;
    for (const auto& [key, meta] : m_impl->m_metadata) {
        if (meta.category == category) {
            result.push_back(key);
        }
    }
    return result;
}

std::map<std::string, ConfigValue> ConfigManager::GetAllValues(ConfigLayer layer) const {
    std::shared_lock lock(m_impl->m_mutex);

    if (static_cast<uint8_t>(layer) > 6) return {};
    return m_impl->m_layers[static_cast<size_t>(layer)];
}

bool ConfigManager::SetMultipleValues(
    const std::map<std::string, ConfigValue>& values, ConfigLayer layer) {

    if (static_cast<uint8_t>(layer) > 6) {
        SS_LOG_ERROR(L"Config", L"SetMultipleValues failed: invalid layer");
        return false;
    }

    std::vector<ConfigManagerImpl::PendingCallbacks> pendingList;
    {
        std::unique_lock lock(m_impl->m_mutex);

        // Validate all keys first (fail-fast, no partial writes)
        for (const auto& [key, value] : values) {
            if (key.empty() || key.size() > ConfigConstants::MAX_KEY_LENGTH) {
                SS_LOG_ERROR(L"Config",
                    L"SetMultipleValues: invalid key '%hs' — aborting batch", key.c_str());
                return false;
            }
            auto metaIt = m_impl->m_metadata.find(key);
            if (metaIt != m_impl->m_metadata.end() && metaIt->second.isReadOnly &&
                layer != ConfigLayer::Default && layer != ConfigLayer::Override) {
                SS_LOG_ERROR(L"Config",
                    L"SetMultipleValues: read-only key '%hs' — aborting batch", key.c_str());
                return false;
            }
        }

        // All validation passed — apply atomically
        for (const auto& [key, value] : values) {
            m_impl->m_stats.totalWrites.fetch_add(1, std::memory_order_relaxed);
            ConfigValue oldValue = m_impl->ResolveValue(key);

            ConfigValue storeValue = value;
            auto metaIt = m_impl->m_metadata.find(key);
            if (metaIt != m_impl->m_metadata.end() && metaIt->second.isSensitive &&
                m_impl->m_config.encryptSensitiveValues) {
                storeValue = m_impl->EncryptSensitiveValue(value);
                if (std::holds_alternative<std::monostate>(storeValue)) {
                    SS_LOG_ERROR(L"Config",
                        L"SetMultipleValues: encryption failed for '%hs'", key.c_str());
                    continue;
                }
            }

            m_impl->m_layers[static_cast<size_t>(layer)][key] = storeValue;

            if (layer == ConfigLayer::User || layer == ConfigLayer::System) {
                m_impl->PersistToDb(key, value);
            }

            ConfigChangeEvent event;
            event.key = key;
            event.oldValue = oldValue;
            event.newValue = value;
            event.layer = layer;
            event.reason = ChangeReason::UserModification;
            event.timestamp = std::chrono::system_clock::now();
            event.source = "SetMultipleValues";
            pendingList.push_back(m_impl->CollectCallbacks(event));
        }
    }

    // Fire all callbacks outside the lock
    for (const auto& pending : pendingList) {
        ConfigManagerImpl::FirePendingCallbacks(pending);
    }
    return true;
}

// ============================================================================
// METADATA
// ============================================================================

bool ConfigManager::RegisterKeyMetadata(const ConfigKeyMetadata& metadata) {
    if (metadata.key.empty() || metadata.key.size() > ConfigConstants::MAX_KEY_LENGTH) {
        SS_LOG_ERROR(L"Config", L"RegisterKeyMetadata: invalid key");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_metadata[metadata.key] = metadata;

    // If metadata has a default value and it isn't monostate, set in Default layer
    if (!std::holds_alternative<std::monostate>(metadata.defaultValue)) {
        auto& defLayer = m_impl->m_layers[static_cast<size_t>(ConfigLayer::Default)];
        if (defLayer.find(metadata.key) == defLayer.end()) {
            defLayer[metadata.key] = metadata.defaultValue;
        }
    }

    SS_LOG_DEBUG(L"Config", L"Registered metadata for key '%hs'", metadata.key.c_str());
    return true;
}

std::optional<ConfigKeyMetadata> ConfigManager::GetKeyMetadata(const std::string& key) const {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_metadata.find(key);
    if (it != m_impl->m_metadata.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<std::string> ConfigManager::GetCategories() const {
    std::shared_lock lock(m_impl->m_mutex);

    std::set<std::string> cats;
    for (const auto& [key, meta] : m_impl->m_metadata) {
        if (!meta.category.empty()) {
            cats.insert(meta.category);
        }
    }
    return {cats.begin(), cats.end()};
}

// ============================================================================
// HOT-RELOADING
// ============================================================================

void ConfigManager::Reload() {
    SS_LOG_INFO(L"Config", L"Manual reload requested");

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_status.store(ConfigStatus::Reloading, std::memory_order_release);
    m_impl->LoadFromDb();
    m_impl->m_status.store(ConfigStatus::Running, std::memory_order_release);
    m_impl->m_stats.hotReloads.fetch_add(1, std::memory_order_relaxed);
}

void ConfigManager::ForceReload() {
    SS_LOG_INFO(L"Config", L"Force reload requested — clearing all layers");

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_status.store(ConfigStatus::Reloading, std::memory_order_release);

    // Clear all layers and re-load from DB
    for (auto& layer : m_impl->m_layers) {
        layer.clear();
    }

    m_impl->LoadFromDb();
    m_impl->m_status.store(ConfigStatus::Running, std::memory_order_release);
    m_impl->m_stats.hotReloads.fetch_add(1, std::memory_order_relaxed);
}

void ConfigManager::SetHotReloadEnabled(bool enabled) {
    m_impl->m_hotReloadEnabled.store(enabled, std::memory_order_release);
    SS_LOG_INFO(L"Config", L"Hot-reload %ls",
                enabled ? L"enabled" : L"disabled");
}

bool ConfigManager::IsHotReloadEnabled() const noexcept {
    return m_impl->m_hotReloadEnabled.load(std::memory_order_acquire);
}

// ============================================================================
// VALIDATION
// ============================================================================

ValidationResult ConfigManager::ValidateValue(
    const std::string& key, const ConfigValue& value) const {

    std::shared_lock lock(m_impl->m_mutex);

    // Check metadata constraints
    auto metaIt = m_impl->m_metadata.find(key);
    if (metaIt != m_impl->m_metadata.end()) {
        const auto& meta = metaIt->second;

        if (meta.isReadOnly) {
            return ValidationResult::ReadOnly;
        }

        if (meta.isDeprecated) {
            SS_LOG_WARN(L"Config", L"Key '%hs' is deprecated", key.c_str());
            return ValidationResult::Deprecated;
        }

        // Type checking
        ValueType actualType = GetConfigValueType(value);
        if (meta.valueType != ValueType::Unknown && actualType != meta.valueType &&
            actualType != ValueType::Null) {
            return ValidationResult::InvalidType;
        }

        // Range checking for numeric types
        if (meta.minValue.has_value() || meta.maxValue.has_value()) {
            double numVal = 0.0;
            bool isNumeric = false;
            if (const auto* v = std::get_if<int32_t>(&value)) {
                numVal = static_cast<double>(*v); isNumeric = true;
            } else if (const auto* v = std::get_if<int64_t>(&value)) {
                numVal = static_cast<double>(*v); isNumeric = true;
            } else if (const auto* v = std::get_if<uint32_t>(&value)) {
                numVal = static_cast<double>(*v); isNumeric = true;
            } else if (const auto* v = std::get_if<uint64_t>(&value)) {
                numVal = static_cast<double>(*v); isNumeric = true;
            } else if (const auto* v = std::get_if<double>(&value)) {
                numVal = *v; isNumeric = true;
            }

            if (isNumeric) {
                if (meta.minValue.has_value() && numVal < meta.minValue.value()) {
                    return ValidationResult::OutOfRange;
                }
                if (meta.maxValue.has_value() && numVal > meta.maxValue.value()) {
                    return ValidationResult::OutOfRange;
                }
            }
        }

        // Allowed values check for string types
        if (!meta.allowedValues.empty()) {
            if (const auto* strV = std::get_if<std::string>(&value)) {
                bool found = false;
                for (const auto& av : meta.allowedValues) {
                    if (av == *strV) { found = true; break; }
                }
                if (!found) {
                    return ValidationResult::InvalidFormat;
                }
            }
        }

        // Dependency check
        for (const auto& dep : meta.dependencies) {
            ConfigValue depVal = m_impl->ResolveValue(dep);
            if (std::holds_alternative<std::monostate>(depVal)) {
                return ValidationResult::DependencyFailed;
            }
        }
    }

    // Custom validator
    auto validIt = m_impl->m_validators.find(key);
    if (validIt != m_impl->m_validators.end() && validIt->second) {
        return validIt->second(key, value);
    }

    return ValidationResult::Valid;
}

std::vector<ConfigValidationError> ConfigManager::ValidateAll() const {
    std::vector<ConfigValidationError> errors;

    // Snapshot keys and their resolved values under lock to avoid
    // iterator invalidation when releasing/re-acquiring the lock.
    std::vector<std::pair<std::string, ConfigValue>> keysToValidate;
    {
        std::shared_lock lock(m_impl->m_mutex);
        for (const auto& [key, meta] : m_impl->m_metadata) {
            ConfigValue val = m_impl->ResolveValue(key);
            if (!std::holds_alternative<std::monostate>(val)) {
                keysToValidate.emplace_back(key, std::move(val));
            }
        }
    }

    // Validate each key outside the lock (ValidateValue acquires its own lock)
    for (const auto& [key, val] : keysToValidate) {
        auto result = ValidateValue(key, val);
        if (result != ValidationResult::Valid) {
            ConfigValidationError err;
            err.key = key;
            err.result = result;
            err.message = "Validation failed: " +
                          std::string(GetValidationResultName(result));
            errors.push_back(std::move(err));
        }
    }

    return errors;
}

void ConfigManager::RegisterValidator(const std::string& key, ValidationCallback validator) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_validators[key] = std::move(validator);
    SS_LOG_DEBUG(L"Config", L"Registered custom validator for key '%hs'", key.c_str());
}

// ============================================================================
// SNAPSHOTS
// ============================================================================

uint64_t ConfigManager::CreateSnapshot(const std::string& description) {
    std::unique_lock lock(m_impl->m_mutex);

    // Cap snapshots
    while (m_impl->m_snapshots.size() >= m_impl->m_config.maxSnapshots) {
        if (!m_impl->m_snapshots.empty()) {
            m_impl->m_snapshots.erase(m_impl->m_snapshots.begin());
        } else {
            break;
        }
    }

    ConfigSnapshot snapshot;
    snapshot.snapshotId = m_impl->m_nextSnapshotId++;
    snapshot.timestamp = std::chrono::system_clock::now();
    snapshot.values = m_impl->m_layers[static_cast<size_t>(ConfigLayer::User)];
    snapshot.layer = ConfigLayer::User;
    snapshot.description = description;

    uint64_t id = snapshot.snapshotId;
    m_impl->m_snapshots[id] = std::move(snapshot);
    m_impl->m_stats.snapshotsTaken.fetch_add(1, std::memory_order_relaxed);

    SS_LOG_INFO(L"Config", L"Created snapshot #%llu: %hs", id, description.c_str());
    return id;
}

bool ConfigManager::RestoreSnapshot(uint64_t snapshotId) {
    std::vector<ConfigManagerImpl::PendingCallbacks> pendingList;
    {
        std::unique_lock lock(m_impl->m_mutex);

        auto it = m_impl->m_snapshots.find(snapshotId);
        if (it == m_impl->m_snapshots.end()) {
            SS_LOG_ERROR(L"Config", L"Snapshot #%llu not found", snapshotId);
            return false;
        }

        auto& userLayer = m_impl->m_layers[static_cast<size_t>(ConfigLayer::User)];
        userLayer = it->second.values;

        // Collect callbacks for restored keys
        for (const auto& [key, val] : userLayer) {
            ConfigChangeEvent event;
            event.key = key;
            event.oldValue = ConfigValue{std::monostate{}};
            event.newValue = val;
            event.layer = ConfigLayer::User;
            event.reason = ChangeReason::Rollback;
            event.timestamp = std::chrono::system_clock::now();
            event.source = "RestoreSnapshot";
            pendingList.push_back(m_impl->CollectCallbacks(event));
        }
    }

    // Fire callbacks outside the lock
    for (const auto& pending : pendingList) {
        ConfigManagerImpl::FirePendingCallbacks(pending);
    }

    SS_LOG_INFO(L"Config", L"Restored snapshot #%llu", snapshotId);
    return true;
}

std::vector<ConfigSnapshot> ConfigManager::ListSnapshots() const {
    std::shared_lock lock(m_impl->m_mutex);

    std::vector<ConfigSnapshot> result;
    result.reserve(m_impl->m_snapshots.size());
    for (const auto& [id, snap] : m_impl->m_snapshots) {
        result.push_back(snap);
    }
    return result;
}

bool ConfigManager::DeleteSnapshot(uint64_t snapshotId) {
    std::unique_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_snapshots.find(snapshotId);
    if (it == m_impl->m_snapshots.end()) {
        return false;
    }
    m_impl->m_snapshots.erase(it);
    SS_LOG_DEBUG(L"Config", L"Deleted snapshot #%llu", snapshotId);
    return true;
}

// ============================================================================
// IMPORT / EXPORT
// ============================================================================

std::string ConfigManager::ExportToJson(const ConfigIOOptions& options) const {
    std::shared_lock lock(m_impl->m_mutex);

    try {
        Utils::JSON::Json root = Utils::JSON::Json::object();
        root["version"] = GetVersionString();
        root["exportTime"] = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        Utils::JSON::Json valuesJson = Utils::JSON::Json::object();

        for (const auto& targetLayer : options.layers) {
            if (static_cast<uint8_t>(targetLayer) > 6) continue;
            const auto& layerMap = m_impl->m_layers[static_cast<size_t>(targetLayer)];

            for (const auto& [key, value] : layerMap) {
                if (std::holds_alternative<std::monostate>(value)) continue;

                // Check category filter
                if (!options.categories.empty()) {
                    auto metaIt = m_impl->m_metadata.find(key);
                    if (metaIt != m_impl->m_metadata.end()) {
                        if (options.categories.find(metaIt->second.category) ==
                            options.categories.end()) {
                            continue;
                        }
                    }
                }

                // Check sensitive filter
                if (!options.includeSensitive) {
                    auto metaIt = m_impl->m_metadata.find(key);
                    if (metaIt != m_impl->m_metadata.end() && metaIt->second.isSensitive) {
                        continue;
                    }
                }

                valuesJson[key] = ConfigValueToString(value);
            }
        }

        root["values"] = valuesJson;

        if (options.includeMetadata) {
            Utils::JSON::Json metaJson = Utils::JSON::Json::object();
            for (const auto& [key, meta] : m_impl->m_metadata) {
                Utils::JSON::Json m = Utils::JSON::Json::object();
                m["displayName"] = meta.displayName;
                m["description"] = meta.description;
                m["category"] = meta.category;
                m["valueType"] = std::string(GetValueTypeName(meta.valueType));
                m["isSensitive"] = meta.isSensitive;
                m["isReadOnly"] = meta.isReadOnly;
                m["isDeprecated"] = meta.isDeprecated;
                m["requiresRestart"] = meta.requiresRestart;
                metaJson[key] = m;
            }
            root["metadata"] = metaJson;
        }

        std::string output;
        Utils::JSON::StringifyOptions opts;
        opts.pretty = true;
        opts.indentSpaces = 2;
        if (Utils::JSON::Stringify(root, output, opts)) {
            return output;
        }
        return root.dump(2);
    } catch (...) {
        SS_LOG_ERROR(L"Config", L"Exception during ExportToJson");
        return "{}";
    }
}

bool ConfigManager::ImportFromJson(const std::string& json, ConfigLayer targetLayer) {
    if (json.empty()) {
        SS_LOG_ERROR(L"Config", L"ImportFromJson: empty input");
        return false;
    }

    try {
        Utils::JSON::Json root;
        if (!Utils::JSON::Parse(json, root)) {
            SS_LOG_ERROR(L"Config", L"ImportFromJson: failed to parse JSON");
            return false;
        }

        if (!root.contains("values") || !root["values"].is_object()) {
            SS_LOG_ERROR(L"Config", L"ImportFromJson: missing 'values' object");
            return false;
        }

        const auto& values = root["values"];
        for (auto it = values.begin(); it != values.end(); ++it) {
            std::string key = it.key();
            if (key.empty() || key.size() > ConfigConstants::MAX_KEY_LENGTH) continue;

            ConfigValue cv;
            if (it.value().is_boolean()) {
                cv = ConfigValue{it.value().get<bool>()};
            } else if (it.value().is_number_integer()) {
                cv = ConfigValue{it.value().get<int64_t>()};
            } else if (it.value().is_number_float()) {
                cv = ConfigValue{it.value().get<double>()};
            } else if (it.value().is_string()) {
                cv = ConfigValue{it.value().get<std::string>()};
            } else {
                cv = ConfigValue{it.value().dump()};
            }

            (void)SetRawValue(key, cv, targetLayer);
        }

        SS_LOG_INFO(L"Config", L"Imported %zu keys from JSON into layer %hs",
                     values.size(),
                     std::string(GetConfigLayerName(targetLayer)).c_str());
        return true;
    } catch (...) {
        SS_LOG_ERROR(L"Config", L"Exception during ImportFromJson");
        return false;
    }
}

bool ConfigManager::ExportToFile(const fs::path& filePath,
                                  const ConfigIOOptions& options) const {
    try {
        // Path validation: canonicalize and reject traversal attempts
        std::error_code ec;
        fs::path canonical = fs::weakly_canonical(filePath, ec);
        if (ec) {
            SS_LOG_ERROR(L"Config",
                L"ExportToFile: path canonicalization failed for '%ls': %hs",
                filePath.wstring().c_str(), ec.message().c_str());
            return false;
        }

        // Reject paths containing suspicious components
        std::wstring pathStr = canonical.wstring();
        if (pathStr.find(L"..") != std::wstring::npos) {
            SS_LOG_ERROR(L"Config",
                L"ExportToFile: path traversal detected in '%ls'", pathStr.c_str());
            return false;
        }

        std::string json = ExportToJson(options);
        if (!Utils::FileUtils::WriteAllTextUtf8Atomic(pathStr, json)) {
            SS_LOG_ERROR(L"Config", L"ExportToFile: failed to write file");
            return false;
        }
        SS_LOG_INFO(L"Config", L"Exported configuration to file");
        return true;
    } catch (...) {
        SS_LOG_ERROR(L"Config", L"Exception during ExportToFile");
        return false;
    }
}

bool ConfigManager::ImportFromFile(const fs::path& filePath, ConfigLayer targetLayer) {
    try {
        // Path validation: canonicalize and reject traversal attempts
        std::error_code ec;
        fs::path canonical = fs::canonical(filePath, ec);
        if (ec) {
            SS_LOG_ERROR(L"Config",
                L"ImportFromFile: path canonicalization failed for '%ls': %hs",
                filePath.wstring().c_str(), ec.message().c_str());
            return false;
        }

        std::wstring pathStr = canonical.wstring();
        if (pathStr.find(L"..") != std::wstring::npos) {
            SS_LOG_ERROR(L"Config",
                L"ImportFromFile: path traversal detected in '%ls'", pathStr.c_str());
            return false;
        }

        // Verify file exists and has reasonable size
        auto fileSize = fs::file_size(canonical, ec);
        if (ec || fileSize == 0) {
            SS_LOG_ERROR(L"Config", L"ImportFromFile: file does not exist or is empty");
            return false;
        }
        constexpr uintmax_t kMaxImportSize = 10 * 1024 * 1024; // 10 MB
        if (fileSize > kMaxImportSize) {
            SS_LOG_ERROR(L"Config",
                L"ImportFromFile: file too large (%llu bytes, max %llu)",
                fileSize, kMaxImportSize);
            return false;
        }

        std::string content;
        if (!Utils::FileUtils::ReadAllTextUtf8(pathStr, content)) {
            SS_LOG_ERROR(L"Config", L"ImportFromFile: failed to read file");
            return false;
        }
        return ImportFromJson(content, targetLayer);
    } catch (...) {
        SS_LOG_ERROR(L"Config", L"Exception during ImportFromFile");
        return false;
    }
}

// ============================================================================
// DEFAULTS
// ============================================================================

void ConfigManager::ResetToDefaults(ConfigLayer layer) {
    if (static_cast<uint8_t>(layer) > 6) return;

    std::vector<ConfigManagerImpl::PendingCallbacks> pendingList;
    {
        std::unique_lock lock(m_impl->m_mutex);

        auto& layerMap = m_impl->m_layers[static_cast<size_t>(layer)];
        auto oldValues = std::move(layerMap);
        layerMap.clear();

        // Collect callbacks for cleared keys
        for (const auto& [key, val] : oldValues) {
            if (std::holds_alternative<std::monostate>(val)) continue;

            ConfigChangeEvent event;
            event.key = key;
            event.oldValue = val;
            event.newValue = ConfigValue{std::monostate{}};
            event.layer = layer;
            event.reason = ChangeReason::Reset;
            event.timestamp = std::chrono::system_clock::now();
            event.source = "ResetToDefaults";
            pendingList.push_back(m_impl->CollectCallbacks(event));
        }
    }

    // Fire callbacks outside the lock
    for (const auto& pending : pendingList) {
        ConfigManagerImpl::FirePendingCallbacks(pending);
    }

    SS_LOG_INFO(L"Config", L"Reset layer %hs to defaults",
                std::string(GetConfigLayerName(layer)).c_str());
}

bool ConfigManager::ResetKeyToDefault(const std::string& key) {
    if (key.empty()) return false;

    ConfigManagerImpl::PendingCallbacks pending;
    {
        std::unique_lock lock(m_impl->m_mutex);

        // Remove from all layers except Default
        for (int i = 1; i <= 6; ++i) {
            m_impl->m_layers[static_cast<size_t>(i)].erase(key);
        }

        // Collect callback
        ConfigValue resolved = m_impl->ResolveValue(key);
        ConfigChangeEvent event;
        event.key = key;
        event.oldValue = ConfigValue{std::monostate{}};
        event.newValue = resolved;
        event.layer = ConfigLayer::Default;
        event.reason = ChangeReason::Reset;
        event.timestamp = std::chrono::system_clock::now();
        event.source = "ResetKeyToDefault";
        pending = m_impl->CollectCallbacks(event);
    }

    ConfigManagerImpl::FirePendingCallbacks(pending);

    SS_LOG_DEBUG(L"Config", L"Reset key '%hs' to default", key.c_str());
    return true;
}

void ConfigManager::LoadFactoryDefaults() {
    SS_LOG_INFO(L"Config", L"Loading factory defaults");

    std::unique_lock lock(m_impl->m_mutex);

    // Populate Default layer from registered metadata
    auto& defLayer = m_impl->m_layers[static_cast<size_t>(ConfigLayer::Default)];
    for (const auto& [key, meta] : m_impl->m_metadata) {
        if (!std::holds_alternative<std::monostate>(meta.defaultValue)) {
            defLayer[key] = meta.defaultValue;
        }
    }
}

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t ConfigManager::RegisterChangeCallback(ChangeCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    uint64_t id = m_impl->m_nextCallbackId++;
    m_impl->m_globalCallbacks[id] = std::move(callback);
    SS_LOG_DEBUG(L"Config", L"Registered global change callback #%llu", id);
    return id;
}

uint64_t ConfigManager::RegisterKeyChangeCallback(
    const std::string& key, ChangeCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    uint64_t id = m_impl->m_nextCallbackId++;
    m_impl->m_keyCallbacks[key][id] = std::move(callback);
    SS_LOG_DEBUG(L"Config", L"Registered key change callback #%llu for '%hs'",
                 id, key.c_str());
    return id;
}

void ConfigManager::UnregisterCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_mutex);

    // Try global callbacks
    if (m_impl->m_globalCallbacks.erase(callbackId) > 0) {
        SS_LOG_DEBUG(L"Config", L"Unregistered global callback #%llu", callbackId);
        return;
    }

    // Try per-key callbacks
    for (auto& [key, cbMap] : m_impl->m_keyCallbacks) {
        if (cbMap.erase(callbackId) > 0) {
            SS_LOG_DEBUG(L"Config", L"Unregistered key callback #%llu", callbackId);
            if (cbMap.empty()) {
                m_impl->m_keyCallbacks.erase(key);
            }
            return;
        }
    }
}

void ConfigManager::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_errorCallback = std::move(callback);
}

// ============================================================================
// STATISTICS & DIAGNOSTICS
// ============================================================================

ConfigStatistics ConfigManager::GetStatistics() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_stats;
}

void ConfigManager::ResetStatistics() {
    m_impl->m_stats.Reset();
}

bool ConfigManager::SelfTest() {
    SS_LOG_INFO(L"Config", L"Running ConfigManager self-test");

    try {
        // Test basic set/get cycle
        const std::string testKey = "__selftest__internal__";
        ConfigValue testVal{std::string("selftest_value")};

        {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_layers[static_cast<size_t>(ConfigLayer::Session)][testKey] = testVal;
        }

        {
            std::shared_lock lock(m_impl->m_mutex);
            auto resolved = m_impl->ResolveValue(testKey);
            const auto* strPtr = std::get_if<std::string>(&resolved);
            if (!strPtr || *strPtr != "selftest_value") {
                SS_LOG_ERROR(L"Config", L"Self-test FAILED: get/set mismatch");
                return false;
            }
        }

        // Cleanup
        {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_layers[static_cast<size_t>(ConfigLayer::Session)].erase(testKey);
        }

        SS_LOG_INFO(L"Config", L"Self-test PASSED");
        return true;
    } catch (...) {
        SS_LOG_ERROR(L"Config", L"Self-test FAILED with exception");
        return false;
    }
}

std::string ConfigManager::GetVersionString() noexcept {
    try {
        return std::to_string(ConfigConstants::VERSION_MAJOR) + "." +
               std::to_string(ConfigConstants::VERSION_MINOR) + "." +
               std::to_string(ConfigConstants::VERSION_PATCH);
    } catch (...) {
        return "0.0.0";
    }
}

// ============================================================================
// ConfigManagerConfiguration::IsValid
// ============================================================================

bool ConfigManagerConfiguration::IsValid() const noexcept {
    if (hotReloadIntervalMs < 100) return false;
    if (maxSnapshots == 0) return false;
    if (cacheTtlSeconds == 0 && enableCaching) return false;
    return true;
}

// ============================================================================
// ConfigStatistics
// ============================================================================

void ConfigStatistics::Reset() noexcept {
    totalReads.store(0, std::memory_order_relaxed);
    totalWrites.store(0, std::memory_order_relaxed);
    cacheHits.store(0, std::memory_order_relaxed);
    cacheMisses.store(0, std::memory_order_relaxed);
    validationErrors.store(0, std::memory_order_relaxed);
    hotReloads.store(0, std::memory_order_relaxed);
    policyUpdates.store(0, std::memory_order_relaxed);
    snapshotsTaken.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

std::string ConfigStatistics::ToJson() const {
    try {
        Utils::JSON::Json j = Utils::JSON::Json::object();
        j["totalReads"] = totalReads.load(std::memory_order_relaxed);
        j["totalWrites"] = totalWrites.load(std::memory_order_relaxed);
        j["cacheHits"] = cacheHits.load(std::memory_order_relaxed);
        j["cacheMisses"] = cacheMisses.load(std::memory_order_relaxed);
        j["validationErrors"] = validationErrors.load(std::memory_order_relaxed);
        j["hotReloads"] = hotReloads.load(std::memory_order_relaxed);
        j["policyUpdates"] = policyUpdates.load(std::memory_order_relaxed);
        j["snapshotsTaken"] = snapshotsTaken.load(std::memory_order_relaxed);

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now() - startTime).count();
        j["uptimeSeconds"] = elapsed;

        return j.dump(2);
    } catch (...) {
        return "{}";
    }
}

// ============================================================================
// STRUCT ToJson() IMPLEMENTATIONS
// ============================================================================

std::string ConfigKeyMetadata::ToJson() const {
    try {
        Utils::JSON::Json j = Utils::JSON::Json::object();
        j["key"] = key;
        j["displayName"] = displayName;
        j["description"] = description;
        j["category"] = category;
        j["valueType"] = std::string(GetValueTypeName(valueType));
        j["isSensitive"] = isSensitive;
        j["isReadOnly"] = isReadOnly;
        j["isDeprecated"] = isDeprecated;
        j["requiresRestart"] = requiresRestart;
        j["versionAdded"] = versionAdded;
        if (minValue.has_value()) j["minValue"] = minValue.value();
        if (maxValue.has_value()) j["maxValue"] = maxValue.value();
        if (!allowedValues.empty()) {
            j["allowedValues"] = allowedValues;
        }
        if (!dependencies.empty()) {
            j["dependencies"] = dependencies;
        }
        return j.dump(2);
    } catch (...) {
        return "{}";
    }
}

std::string ConfigChangeEvent::ToJson() const {
    try {
        Utils::JSON::Json j = Utils::JSON::Json::object();
        j["key"] = key;
        j["oldValue"] = ConfigValueToString(oldValue);
        j["newValue"] = ConfigValueToString(newValue);
        j["layer"] = std::string(GetConfigLayerName(layer));
        j["reason"] = std::string(GetChangeReasonName(reason));
        j["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp.time_since_epoch()).count();
        j["source"] = source;
        return j.dump(2);
    } catch (...) {
        return "{}";
    }
}

std::string ConfigSnapshot::ToJson() const {
    try {
        Utils::JSON::Json j = Utils::JSON::Json::object();
        j["snapshotId"] = snapshotId;
        j["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp.time_since_epoch()).count();
        j["layer"] = std::string(GetConfigLayerName(layer));
        j["description"] = description;
        j["keyCount"] = values.size();
        return j.dump(2);
    } catch (...) {
        return "{}";
    }
}

std::string ConfigValidationError::ToJson() const {
    try {
        Utils::JSON::Json j = Utils::JSON::Json::object();
        j["key"] = key;
        j["result"] = std::string(GetValidationResultName(result));
        j["message"] = message;
        if (suggestedFix.has_value()) {
            j["suggestedFix"] = suggestedFix.value();
        }
        return j.dump(2);
    } catch (...) {
        return "{}";
    }
}

// ============================================================================
// UTILITY FUNCTIONS (free functions at namespace scope)
// ============================================================================

std::string_view GetConfigLayerName(ConfigLayer layer) noexcept {
    switch (layer) {
        case ConfigLayer::Default:    return "Default";
        case ConfigLayer::System:     return "System";
        case ConfigLayer::Enterprise: return "Enterprise";
        case ConfigLayer::Policy:     return "Policy";
        case ConfigLayer::User:       return "User";
        case ConfigLayer::Session:    return "Session";
        case ConfigLayer::Override:   return "Override";
        default:                      return "Unknown";
    }
}

std::string_view GetValueTypeName(ValueType type) noexcept {
    switch (type) {
        case ValueType::Null:       return "Null";
        case ValueType::Boolean:    return "Boolean";
        case ValueType::Integer:    return "Integer";
        case ValueType::UInteger:   return "UInteger";
        case ValueType::Float:      return "Float";
        case ValueType::String:     return "String";
        case ValueType::WString:    return "WString";
        case ValueType::StringList: return "StringList";
        case ValueType::IntList:    return "IntList";
        case ValueType::Map:        return "Map";
        case ValueType::Binary:     return "Binary";
        case ValueType::Unknown:    return "Unknown";
        default:                    return "Unknown";
    }
}

std::string_view GetChangeReasonName(ChangeReason reason) noexcept {
    switch (reason) {
        case ChangeReason::Initialization:   return "Initialization";
        case ChangeReason::UserModification: return "UserModification";
        case ChangeReason::PolicyUpdate:     return "PolicyUpdate";
        case ChangeReason::HotReload:        return "HotReload";
        case ChangeReason::Import:           return "Import";
        case ChangeReason::Reset:            return "Reset";
        case ChangeReason::Migration:        return "Migration";
        case ChangeReason::Rollback:         return "Rollback";
        default:                             return "Unknown";
    }
}

std::string_view GetValidationResultName(ValidationResult result) noexcept {
    switch (result) {
        case ValidationResult::Valid:            return "Valid";
        case ValidationResult::InvalidType:      return "InvalidType";
        case ValidationResult::OutOfRange:       return "OutOfRange";
        case ValidationResult::InvalidFormat:    return "InvalidFormat";
        case ValidationResult::DependencyFailed: return "DependencyFailed";
        case ValidationResult::ReadOnly:         return "ReadOnly";
        case ValidationResult::PolicyLocked:     return "PolicyLocked";
        case ValidationResult::Deprecated:       return "Deprecated";
        case ValidationResult::Unknown:          return "Unknown";
        default:                                 return "Unknown";
    }
}

std::string ConfigValueToString(const ConfigValue& value) {
    if (std::holds_alternative<std::monostate>(value)) {
        return "<null>";
    }
    if (const auto* v = std::get_if<bool>(&value)) {
        return *v ? "true" : "false";
    }
    if (const auto* v = std::get_if<int32_t>(&value)) {
        return std::to_string(*v);
    }
    if (const auto* v = std::get_if<int64_t>(&value)) {
        return std::to_string(*v);
    }
    if (const auto* v = std::get_if<uint32_t>(&value)) {
        return std::to_string(*v);
    }
    if (const auto* v = std::get_if<uint64_t>(&value)) {
        return std::to_string(*v);
    }
    if (const auto* v = std::get_if<double>(&value)) {
        std::ostringstream oss;
        oss << *v;
        return oss.str();
    }
    if (const auto* v = std::get_if<std::string>(&value)) {
        return *v;
    }
    if (const auto* v = std::get_if<std::wstring>(&value)) {
        return WideToNarrow(*v);
    }
    if (const auto* v = std::get_if<std::vector<std::string>>(&value)) {
        try {
            Utils::JSON::Json arr = Utils::JSON::Json::array();
            for (const auto& s : *v) arr.push_back(s);
            return arr.dump();
        } catch (...) {
            return "[]";
        }
    }
    if (const auto* v = std::get_if<std::vector<int64_t>>(&value)) {
        try {
            Utils::JSON::Json arr = Utils::JSON::Json::array();
            for (const auto& i : *v) arr.push_back(i);
            return arr.dump();
        } catch (...) {
            return "[]";
        }
    }
    if (const auto* v = std::get_if<std::map<std::string, std::string>>(&value)) {
        try {
            Utils::JSON::Json obj = Utils::JSON::Json::object();
            for (const auto& [k, val] : *v) obj[k] = val;
            return obj.dump();
        } catch (...) {
            return "{}";
        }
    }
    return "<unknown>";
}

ConfigValue ParseConfigValue(const std::string& str, ValueType expectedType) {
    try {
        switch (expectedType) {
            case ValueType::Boolean:
                if (str == "true" || str == "1") return ConfigValue{true};
                if (str == "false" || str == "0") return ConfigValue{false};
                return ConfigValue{std::monostate{}};

            case ValueType::Integer: {
                int64_t val = 0;
                auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), val);
                if (ec == std::errc{}) return ConfigValue{val};
                return ConfigValue{std::monostate{}};
            }

            case ValueType::UInteger: {
                uint64_t val = 0;
                auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), val);
                if (ec == std::errc{}) return ConfigValue{val};
                return ConfigValue{std::monostate{}};
            }

            case ValueType::Float: {
                try {
                    double val = std::stod(str);
                    return ConfigValue{val};
                } catch (...) {
                    return ConfigValue{std::monostate{}};
                }
            }

            case ValueType::String:
                return ConfigValue{str};

            case ValueType::WString:
                return ConfigValue{NarrowToWide(str)};

            case ValueType::StringList: {
                Utils::JSON::Json arr;
                if (Utils::JSON::Parse(str, arr) && arr.is_array()) {
                    std::vector<std::string> vec;
                    for (const auto& elem : arr) {
                        if (elem.is_string()) {
                            vec.push_back(elem.get<std::string>());
                        }
                    }
                    return ConfigValue{std::move(vec)};
                }
                return ConfigValue{std::monostate{}};
            }

            case ValueType::IntList: {
                Utils::JSON::Json arr;
                if (Utils::JSON::Parse(str, arr) && arr.is_array()) {
                    std::vector<int64_t> vec;
                    for (const auto& elem : arr) {
                        if (elem.is_number_integer()) {
                            vec.push_back(elem.get<int64_t>());
                        }
                    }
                    return ConfigValue{std::move(vec)};
                }
                return ConfigValue{std::monostate{}};
            }

            case ValueType::Map: {
                Utils::JSON::Json obj;
                if (Utils::JSON::Parse(str, obj) && obj.is_object()) {
                    std::map<std::string, std::string> map;
                    for (auto it = obj.begin(); it != obj.end(); ++it) {
                        if (it.value().is_string()) {
                            map[it.key()] = it.value().get<std::string>();
                        } else {
                            map[it.key()] = it.value().dump();
                        }
                    }
                    return ConfigValue{std::move(map)};
                }
                return ConfigValue{std::monostate{}};
            }

            case ValueType::Null:
            case ValueType::Binary:
            case ValueType::Unknown:
            default:
                return ConfigValue{str};
        }
    } catch (...) {
        return ConfigValue{std::monostate{}};
    }
}

ValueType GetConfigValueType(const ConfigValue& value) {
    if (std::holds_alternative<std::monostate>(value)) return ValueType::Null;
    if (std::holds_alternative<bool>(value))           return ValueType::Boolean;
    if (std::holds_alternative<int32_t>(value))        return ValueType::Integer;
    if (std::holds_alternative<int64_t>(value))        return ValueType::Integer;
    if (std::holds_alternative<uint32_t>(value))       return ValueType::UInteger;
    if (std::holds_alternative<uint64_t>(value))       return ValueType::UInteger;
    if (std::holds_alternative<double>(value))         return ValueType::Float;
    if (std::holds_alternative<std::string>(value))    return ValueType::String;
    if (std::holds_alternative<std::wstring>(value))   return ValueType::WString;
    if (std::holds_alternative<std::vector<std::string>>(value)) return ValueType::StringList;
    if (std::holds_alternative<std::vector<int64_t>>(value))     return ValueType::IntList;
    if (std::holds_alternative<std::map<std::string, std::string>>(value)) return ValueType::Map;
    return ValueType::Unknown;
}

// ============================================================================
// EXPLICIT TEMPLATE INSTANTIATIONS
// ============================================================================

// GetValue<T>(const std::string&, const T&) const
template bool ConfigManager::GetValue<bool>(const std::string&, const bool&) const;
template int32_t ConfigManager::GetValue<int32_t>(const std::string&, const int32_t&) const;
template int64_t ConfigManager::GetValue<int64_t>(const std::string&, const int64_t&) const;
template uint32_t ConfigManager::GetValue<uint32_t>(const std::string&, const uint32_t&) const;
template uint64_t ConfigManager::GetValue<uint64_t>(const std::string&, const uint64_t&) const;
template double ConfigManager::GetValue<double>(const std::string&, const double&) const;
template std::string ConfigManager::GetValue<std::string>(const std::string&, const std::string&) const;
template std::wstring ConfigManager::GetValue<std::wstring>(const std::string&, const std::wstring&) const;
template std::vector<std::string> ConfigManager::GetValue<std::vector<std::string>>(const std::string&, const std::vector<std::string>&) const;
template std::vector<int64_t> ConfigManager::GetValue<std::vector<int64_t>>(const std::string&, const std::vector<int64_t>&) const;
template std::map<std::string, std::string> ConfigManager::GetValue<std::map<std::string, std::string>>(const std::string&, const std::map<std::string, std::string>&) const;

// GetValue<T>(const std::wstring&, const T&) const
template bool ConfigManager::GetValue<bool>(const std::wstring&, const bool&) const;
template int32_t ConfigManager::GetValue<int32_t>(const std::wstring&, const int32_t&) const;
template int64_t ConfigManager::GetValue<int64_t>(const std::wstring&, const int64_t&) const;
template uint32_t ConfigManager::GetValue<uint32_t>(const std::wstring&, const uint32_t&) const;
template uint64_t ConfigManager::GetValue<uint64_t>(const std::wstring&, const uint64_t&) const;
template double ConfigManager::GetValue<double>(const std::wstring&, const double&) const;
template std::string ConfigManager::GetValue<std::string>(const std::wstring&, const std::string&) const;
template std::wstring ConfigManager::GetValue<std::wstring>(const std::wstring&, const std::wstring&) const;
template std::vector<std::string> ConfigManager::GetValue<std::vector<std::string>>(const std::wstring&, const std::vector<std::string>&) const;
template std::vector<int64_t> ConfigManager::GetValue<std::vector<int64_t>>(const std::wstring&, const std::vector<int64_t>&) const;
template std::map<std::string, std::string> ConfigManager::GetValue<std::map<std::string, std::string>>(const std::wstring&, const std::map<std::string, std::string>&) const;

// GetOptionalValue<T>(const std::string&) const
template std::optional<bool> ConfigManager::GetOptionalValue<bool>(const std::string&) const;
template std::optional<int32_t> ConfigManager::GetOptionalValue<int32_t>(const std::string&) const;
template std::optional<int64_t> ConfigManager::GetOptionalValue<int64_t>(const std::string&) const;
template std::optional<uint32_t> ConfigManager::GetOptionalValue<uint32_t>(const std::string&) const;
template std::optional<uint64_t> ConfigManager::GetOptionalValue<uint64_t>(const std::string&) const;
template std::optional<double> ConfigManager::GetOptionalValue<double>(const std::string&) const;
template std::optional<std::string> ConfigManager::GetOptionalValue<std::string>(const std::string&) const;
template std::optional<std::wstring> ConfigManager::GetOptionalValue<std::wstring>(const std::string&) const;
template std::optional<std::vector<std::string>> ConfigManager::GetOptionalValue<std::vector<std::string>>(const std::string&) const;
template std::optional<std::vector<int64_t>> ConfigManager::GetOptionalValue<std::vector<int64_t>>(const std::string&) const;
template std::optional<std::map<std::string, std::string>> ConfigManager::GetOptionalValue<std::map<std::string, std::string>>(const std::string&) const;

// GetValueFromLayer<T>(const std::string&, ConfigLayer) const
template std::optional<bool> ConfigManager::GetValueFromLayer<bool>(const std::string&, ConfigLayer) const;
template std::optional<int32_t> ConfigManager::GetValueFromLayer<int32_t>(const std::string&, ConfigLayer) const;
template std::optional<int64_t> ConfigManager::GetValueFromLayer<int64_t>(const std::string&, ConfigLayer) const;
template std::optional<uint32_t> ConfigManager::GetValueFromLayer<uint32_t>(const std::string&, ConfigLayer) const;
template std::optional<uint64_t> ConfigManager::GetValueFromLayer<uint64_t>(const std::string&, ConfigLayer) const;
template std::optional<double> ConfigManager::GetValueFromLayer<double>(const std::string&, ConfigLayer) const;
template std::optional<std::string> ConfigManager::GetValueFromLayer<std::string>(const std::string&, ConfigLayer) const;
template std::optional<std::wstring> ConfigManager::GetValueFromLayer<std::wstring>(const std::string&, ConfigLayer) const;
template std::optional<std::vector<std::string>> ConfigManager::GetValueFromLayer<std::vector<std::string>>(const std::string&, ConfigLayer) const;
template std::optional<std::vector<int64_t>> ConfigManager::GetValueFromLayer<std::vector<int64_t>>(const std::string&, ConfigLayer) const;
template std::optional<std::map<std::string, std::string>> ConfigManager::GetValueFromLayer<std::map<std::string, std::string>>(const std::string&, ConfigLayer) const;

// SetValue<T>(const std::string&, const T&, ConfigLayer)
template bool ConfigManager::SetValue<bool>(const std::string&, const bool&, ConfigLayer);
template bool ConfigManager::SetValue<int32_t>(const std::string&, const int32_t&, ConfigLayer);
template bool ConfigManager::SetValue<int64_t>(const std::string&, const int64_t&, ConfigLayer);
template bool ConfigManager::SetValue<uint32_t>(const std::string&, const uint32_t&, ConfigLayer);
template bool ConfigManager::SetValue<uint64_t>(const std::string&, const uint64_t&, ConfigLayer);
template bool ConfigManager::SetValue<double>(const std::string&, const double&, ConfigLayer);
template bool ConfigManager::SetValue<std::string>(const std::string&, const std::string&, ConfigLayer);
template bool ConfigManager::SetValue<std::wstring>(const std::string&, const std::wstring&, ConfigLayer);
template bool ConfigManager::SetValue<std::vector<std::string>>(const std::string&, const std::vector<std::string>&, ConfigLayer);
template bool ConfigManager::SetValue<std::vector<int64_t>>(const std::string&, const std::vector<int64_t>&, ConfigLayer);
template bool ConfigManager::SetValue<std::map<std::string, std::string>>(const std::string&, const std::map<std::string, std::string>&, ConfigLayer);

// SetValue<T>(const std::wstring&, const T&, ConfigLayer)
template bool ConfigManager::SetValue<bool>(const std::wstring&, const bool&, ConfigLayer);
template bool ConfigManager::SetValue<int32_t>(const std::wstring&, const int32_t&, ConfigLayer);
template bool ConfigManager::SetValue<int64_t>(const std::wstring&, const int64_t&, ConfigLayer);
template bool ConfigManager::SetValue<uint32_t>(const std::wstring&, const uint32_t&, ConfigLayer);
template bool ConfigManager::SetValue<uint64_t>(const std::wstring&, const uint64_t&, ConfigLayer);
template bool ConfigManager::SetValue<double>(const std::wstring&, const double&, ConfigLayer);
template bool ConfigManager::SetValue<std::string>(const std::wstring&, const std::string&, ConfigLayer);
template bool ConfigManager::SetValue<std::wstring>(const std::wstring&, const std::wstring&, ConfigLayer);
template bool ConfigManager::SetValue<std::vector<std::string>>(const std::wstring&, const std::vector<std::string>&, ConfigLayer);
template bool ConfigManager::SetValue<std::vector<int64_t>>(const std::wstring&, const std::vector<int64_t>&, ConfigLayer);
template bool ConfigManager::SetValue<std::map<std::string, std::string>>(const std::wstring&, const std::map<std::string, std::string>&, ConfigLayer);

// SetValueValidated<T>(const std::string&, const T&, ConfigLayer)
template std::pair<bool, std::string> ConfigManager::SetValueValidated<bool>(const std::string&, const bool&, ConfigLayer);
template std::pair<bool, std::string> ConfigManager::SetValueValidated<int32_t>(const std::string&, const int32_t&, ConfigLayer);
template std::pair<bool, std::string> ConfigManager::SetValueValidated<int64_t>(const std::string&, const int64_t&, ConfigLayer);
template std::pair<bool, std::string> ConfigManager::SetValueValidated<uint32_t>(const std::string&, const uint32_t&, ConfigLayer);
template std::pair<bool, std::string> ConfigManager::SetValueValidated<uint64_t>(const std::string&, const uint64_t&, ConfigLayer);
template std::pair<bool, std::string> ConfigManager::SetValueValidated<double>(const std::string&, const double&, ConfigLayer);
template std::pair<bool, std::string> ConfigManager::SetValueValidated<std::string>(const std::string&, const std::string&, ConfigLayer);
template std::pair<bool, std::string> ConfigManager::SetValueValidated<std::wstring>(const std::string&, const std::wstring&, ConfigLayer);
template std::pair<bool, std::string> ConfigManager::SetValueValidated<std::vector<std::string>>(const std::string&, const std::vector<std::string>&, ConfigLayer);
template std::pair<bool, std::string> ConfigManager::SetValueValidated<std::vector<int64_t>>(const std::string&, const std::vector<int64_t>&, ConfigLayer);
template std::pair<bool, std::string> ConfigManager::SetValueValidated<std::map<std::string, std::string>>(const std::string&, const std::map<std::string, std::string>&, ConfigLayer);

}  // namespace Config
}  // namespace ShadowStrike
