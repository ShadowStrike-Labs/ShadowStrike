/**
 * ============================================================================
 * ShadowStrike Security - REGISTRY PROTECTION ENGINE IMPLEMENTATION
 * ============================================================================
 *
 * @file RegistryProtection.cpp
 * @brief Enterprise-grade registry protection implementation for securing
 *        ShadowStrike configuration keys, service entries, and startup persistence.
 *
 * This implementation provides comprehensive registry protection mechanisms
 * including key lockdown, integrity monitoring, automatic rollback, and
 * tamper detection for antivirus self-defense.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 * - Thread-safe singleton with PIMPL pattern
 * - Polling-based integrity monitoring (user-mode)
 * - Snapshot-based rollback capability
 * - Process whitelist management
 * - Comprehensive statistics tracking
 * - JSON serialization for diagnostics
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, NIST CSF
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "RegistryProtection.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <random>
#include <format>

namespace ShadowStrike {
namespace Security {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> RegistryProtection::s_instanceCreated{false};

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

namespace {

    /// @brief Log category for registry protection
    constexpr const wchar_t* LOG_CATEGORY = L"RegistryProtection";

    /// @brief Maximum event history size
    constexpr size_t MAX_EVENT_HISTORY = 1000;

    /// @brief Snapshot storage limit per key
    constexpr size_t MAX_SNAPSHOT_STORAGE = 50 * 1024 * 1024;  // 50 MB total

    /// @brief Authorization token prefix
    constexpr std::string_view AUTH_TOKEN_PREFIX = "SS_REG_AUTH_";

    /// @brief Generate unique ID
    [[nodiscard]] std::string GenerateUniqueId() {
        static std::atomic<uint64_t> counter{0};
        const auto now = std::chrono::system_clock::now();
        const auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();

        std::ostringstream oss;
        oss << std::hex << timestamp << "-" << ++counter;
        return oss.str();
    }

    /// @brief Convert wide string to narrow string for JSON
    [[nodiscard]] std::string WideToNarrow(std::wstring_view wide) {
        if (wide.empty()) return {};

        const int len = WideCharToMultiByte(CP_UTF8, 0, wide.data(),
            static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
        if (len <= 0) return {};

        std::string result(static_cast<size_t>(len), '\0');
        WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
            result.data(), len, nullptr, nullptr);
        return result;
    }

    /// @brief Convert narrow string to wide string
    [[nodiscard]] std::wstring NarrowToWide(std::string_view narrow) {
        if (narrow.empty()) return {};

        const int len = MultiByteToWideChar(CP_UTF8, 0, narrow.data(),
            static_cast<int>(narrow.size()), nullptr, 0);
        if (len <= 0) return {};

        std::wstring result(static_cast<size_t>(len), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, narrow.data(), static_cast<int>(narrow.size()),
            result.data(), len);
        return result;
    }

    /// @brief Escape string for JSON
    [[nodiscard]] std::string EscapeJsonString(std::string_view input) {
        std::string result;
        result.reserve(input.size() + 16);

        for (const char c : input) {
            switch (c) {
                case '"':  result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                        result += buf;
                    } else {
                        result += c;
                    }
                    break;
            }
        }
        return result;
    }

    /// @brief Format timestamp for JSON
    [[nodiscard]] std::string FormatTimestamp(TimePoint tp) {
        const auto sysTime = std::chrono::system_clock::now() +
            (tp - Clock::now());
        const auto time_t_val = std::chrono::system_clock::to_time_t(sysTime);
        std::tm tm_val{};
        gmtime_s(&tm_val, &time_t_val);

        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_val);
        return buf;
    }

    /// @brief Compute SHA256 hash of data
    [[nodiscard]] Hash256 ComputeHash256(std::span<const uint8_t> data) {
        Hash256 result{};
        std::vector<uint8_t> hashOut;

        if (Utils::HashUtils::Compute(Utils::HashUtils::Algorithm::SHA256,
                data.data(), data.size(), hashOut)) {
            if (hashOut.size() >= result.size()) {
                std::copy_n(hashOut.begin(), result.size(), result.begin());
            }
        }
        return result;
    }

    /// @brief Convert Hash256 to hex string
    [[nodiscard]] std::string Hash256ToHex(const Hash256& hash) {
        return Utils::HashUtils::ToHexLower(hash.data(), hash.size());
    }

}  // anonymous namespace

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class RegistryProtectionImpl {
public:
    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    RegistryProtectionImpl() noexcept
        : m_status(ModuleStatus::Uninitialized)
        , m_mode(RegistryProtectionMode::Disabled)
        , m_nextCallbackId(1)
        , m_nextEventId(1)
    {
        SS_LOG_DEBUG(LOG_CATEGORY, L"RegistryProtectionImpl constructed");
    }

    ~RegistryProtectionImpl() noexcept {
        try {
            StopMonitoring();
        } catch (...) {
            // Suppress exceptions in destructor
        }
        SS_LOG_DEBUG(LOG_CATEGORY, L"RegistryProtectionImpl destroyed");
    }

    // Non-copyable, non-movable
    RegistryProtectionImpl(const RegistryProtectionImpl&) = delete;
    RegistryProtectionImpl& operator=(const RegistryProtectionImpl&) = delete;
    RegistryProtectionImpl(RegistryProtectionImpl&&) = delete;
    RegistryProtectionImpl& operator=(RegistryProtectionImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const RegistryProtectionConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (m_status == ModuleStatus::Running) {
            SS_LOG_WARN(LOG_CATEGORY, L"Already initialized");
            return true;
        }

        m_status = ModuleStatus::Initializing;
        SS_LOG_INFO(LOG_CATEGORY, L"Initializing registry protection...");

        // Validate configuration
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
            m_status = ModuleStatus::Error;
            return false;
        }

        // Store configuration
        m_config = config;
        m_mode = config.mode;

        // Initialize protected keys from configuration
        for (const auto& keyPath : config.protectedKeys) {
            if (!AddProtectedKeyInternal(keyPath, KeyProtectionType::Full, true)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to add protected key: %ls", keyPath.c_str());
            }
        }

        // Add default protected keys
        for (const auto& defaultKey : RegistryProtectionConstants::DEFAULT_PROTECTED_KEYS) {
            const std::wstring keyPath(defaultKey);
            if (!IsKeyProtectedInternal(keyPath)) {
                AddProtectedKeyInternal(keyPath, KeyProtectionType::Full, true);
            }
        }

        // Initialize whitelisted processes
        for (const auto& process : config.whitelistedProcesses) {
            m_whitelistedProcesses.insert(process);
        }

        // Add ShadowStrike processes to whitelist
        m_whitelistedProcesses.insert(L"ShadowStrikeService.exe");
        m_whitelistedProcesses.insert(L"ShadowStrikeUI.exe");
        m_whitelistedProcesses.insert(L"ShadowStrikeUpdater.exe");

        // Start monitoring if enabled
        if (config.enableUserModePolling &&
            m_mode != RegistryProtectionMode::Disabled) {
            StartMonitoring();
        }

        // Reset statistics
        m_stats.Reset();
        m_stats.startTime = Clock::now();

        m_status = ModuleStatus::Running;
        SS_LOG_INFO(LOG_CATEGORY, L"Registry protection initialized successfully");
        SS_LOG_INFO(LOG_CATEGORY, L"Protected keys: %llu, Mode: %hs",
            m_stats.totalProtectedKeys.load(),
            std::string(GetProtectionModeName(m_mode)).c_str());

        return true;
    }

    void Shutdown(std::string_view authorizationToken) {
        if (!VerifyAuthToken(authorizationToken)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Shutdown blocked: Invalid authorization token");
            return;
        }

        std::unique_lock lock(m_mutex);

        if (m_status == ModuleStatus::Stopped ||
            m_status == ModuleStatus::Uninitialized) {
            return;
        }

        m_status = ModuleStatus::Stopping;
        SS_LOG_INFO(LOG_CATEGORY, L"Shutting down registry protection...");

        // Stop monitoring thread
        StopMonitoring();

        // Clear protected keys
        m_protectedKeys.clear();
        m_protectedValues.clear();
        m_snapshots.clear();

        // Clear callbacks
        m_eventCallbacks.clear();
        m_integrityCallbacks.clear();
        m_valueChangeCallbacks.clear();
        m_decisionCallback = nullptr;

        m_status = ModuleStatus::Stopped;
        SS_LOG_INFO(LOG_CATEGORY, L"Registry protection shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_status == ModuleStatus::Running;
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status.load();
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    [[nodiscard]] bool SetConfiguration(const RegistryProtectionConfiguration& config) {
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
            return false;
        }

        std::unique_lock lock(m_mutex);
        m_config = config;
        m_mode = config.mode;

        // Update monitoring interval if changed
        if (m_monitoringActive &&
            config.pollingIntervalMs != m_config.pollingIntervalMs) {
            // Restart monitoring with new interval
            StopMonitoring();
            StartMonitoring();
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
        return true;
    }

    [[nodiscard]] RegistryProtectionConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    void SetProtectionMode(RegistryProtectionMode mode) {
        std::unique_lock lock(m_mutex);
        m_mode = mode;
        m_config.mode = mode;
        SS_LOG_INFO(LOG_CATEGORY, L"Protection mode changed to: %hs",
            std::string(GetProtectionModeName(mode)).c_str());
    }

    [[nodiscard]] RegistryProtectionMode GetProtectionMode() const noexcept {
        return m_mode.load();
    }

    // ========================================================================
    // KEY PROTECTION
    // ========================================================================

    void ProtectKey(const std::wstring& keyPath) {
        std::unique_lock lock(m_mutex);
        AddProtectedKeyInternal(keyPath, KeyProtectionType::Full, true);
    }

    [[nodiscard]] bool ProtectKey(std::wstring_view keyPath, KeyProtectionType type,
                                  bool includeSubkeys) {
        if (keyPath.empty()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Empty key path");
            return false;
        }

        if (keyPath.size() > RegistryProtectionConstants::MAX_KEY_PATH_LENGTH) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Key path too long: %zu chars", keyPath.size());
            return false;
        }

        std::unique_lock lock(m_mutex);
        return AddProtectedKeyInternal(std::wstring(keyPath), type, includeSubkeys);
    }

    [[nodiscard]] bool UnprotectKey(std::wstring_view keyPath,
                                    std::string_view authorizationToken) {
        if (!VerifyAuthToken(authorizationToken)) {
            SS_LOG_WARN(LOG_CATEGORY, L"UnprotectKey blocked: Invalid authorization");
            return false;
        }

        std::unique_lock lock(m_mutex);
        const auto normalized = NormalizeKeyPath(keyPath);

        auto it = m_protectedKeys.find(normalized);
        if (it == m_protectedKeys.end()) {
            return false;
        }

        m_protectedKeys.erase(it);
        m_stats.totalProtectedKeys--;

        SS_LOG_INFO(LOG_CATEGORY, L"Key unprotected: %ls", normalized.c_str());
        return true;
    }

    [[nodiscard]] bool IsKeyProtected(std::wstring_view keyPath) const {
        std::shared_lock lock(m_mutex);
        return IsKeyProtectedInternal(std::wstring(keyPath));
    }

    [[nodiscard]] std::optional<ProtectedKey> GetProtectedKey(std::wstring_view keyPath) const {
        std::shared_lock lock(m_mutex);
        const auto normalized = NormalizeKeyPath(keyPath);

        auto it = m_protectedKeys.find(normalized);
        if (it != m_protectedKeys.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::vector<ProtectedKey> GetAllProtectedKeys() const {
        std::shared_lock lock(m_mutex);
        std::vector<ProtectedKey> result;
        result.reserve(m_protectedKeys.size());

        for (const auto& [path, key] : m_protectedKeys) {
            result.push_back(key);
        }
        return result;
    }

    [[nodiscard]] bool ProtectServiceKeys() {
        SS_LOG_INFO(LOG_CATEGORY, L"Protecting ShadowStrike service registry keys...");

        bool success = true;

        // Service keys
        success &= ProtectKey(L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrikeService",
            KeyProtectionType::Full, true);
        success &= ProtectKey(L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrikeDriver",
            KeyProtectionType::Full, true);

        // Configuration keys
        success &= ProtectKey(L"HKLM\\SOFTWARE\\ShadowStrike",
            KeyProtectionType::Full, true);
        success &= ProtectKey(L"HKCU\\SOFTWARE\\ShadowStrike",
            KeyProtectionType::Full, true);

        // Safe boot entries
        success &= ProtectKey(
            L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\ShadowStrikeService",
            KeyProtectionType::Full, true);
        success &= ProtectKey(
            L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\ShadowStrikeService",
            KeyProtectionType::Full, true);

        if (success) {
            SS_LOG_INFO(LOG_CATEGORY, L"Service registry keys protected successfully");
        } else {
            SS_LOG_WARN(LOG_CATEGORY, L"Some service registry keys failed to protect");
        }

        return success;
    }

    [[nodiscard]] bool ProtectStartupEntries() {
        SS_LOG_INFO(LOG_CATEGORY, L"Protecting startup registry entries...");

        bool success = true;

        // Run keys
        success &= ProtectKey(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            KeyProtectionType::ValuesOnly, false);
        success &= ProtectKey(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            KeyProtectionType::ValuesOnly, false);
        success &= ProtectKey(L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            KeyProtectionType::ValuesOnly, false);

        // Winlogon
        success &= ProtectKey(L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            KeyProtectionType::ValuesOnly, false);

        if (success) {
            SS_LOG_INFO(LOG_CATEGORY, L"Startup entries protected successfully");
        }

        return success;
    }

    // ========================================================================
    // VALUE PROTECTION
    // ========================================================================

    [[nodiscard]] bool ProtectValue(std::wstring_view keyPath, std::wstring_view valueName) {
        if (keyPath.empty() || valueName.empty()) {
            return false;
        }

        std::unique_lock lock(m_mutex);

        ProtectedValue pv;
        pv.id = GenerateUniqueId();
        pv.keyPath = keyPath;
        pv.valueName = valueName;
        pv.protectedSince = Clock::now();
        pv.integrity = IntegrityStatus::Unknown;

        // Read current value and compute hash
        if (ReadValueAndComputeHash(pv)) {
            pv.integrity = IntegrityStatus::Valid;
        }

        const auto key = std::wstring(keyPath) + L"\\" + std::wstring(valueName);
        m_protectedValues[key] = std::move(pv);
        m_stats.totalProtectedValues++;

        SS_LOG_INFO(LOG_CATEGORY, L"Value protected: %ls\\%ls",
            std::wstring(keyPath).c_str(), std::wstring(valueName).c_str());
        return true;
    }

    [[nodiscard]] bool UnprotectValue(std::wstring_view keyPath, std::wstring_view valueName,
                                      std::string_view authorizationToken) {
        if (!VerifyAuthToken(authorizationToken)) {
            return false;
        }

        std::unique_lock lock(m_mutex);
        const auto key = std::wstring(keyPath) + L"\\" + std::wstring(valueName);

        auto it = m_protectedValues.find(key);
        if (it == m_protectedValues.end()) {
            return false;
        }

        m_protectedValues.erase(it);
        m_stats.totalProtectedValues--;
        return true;
    }

    [[nodiscard]] bool IsValueProtected(std::wstring_view keyPath,
                                        std::wstring_view valueName) const {
        std::shared_lock lock(m_mutex);
        const auto key = std::wstring(keyPath) + L"\\" + std::wstring(valueName);
        return m_protectedValues.contains(key);
    }

    [[nodiscard]] std::optional<ProtectedValue> GetProtectedValue(
        std::wstring_view keyPath, std::wstring_view valueName) const {
        std::shared_lock lock(m_mutex);
        const auto key = std::wstring(keyPath) + L"\\" + std::wstring(valueName);

        auto it = m_protectedValues.find(key);
        if (it != m_protectedValues.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::vector<ProtectedValue> GetProtectedValues(std::wstring_view keyPath) const {
        std::shared_lock lock(m_mutex);
        std::vector<ProtectedValue> result;

        const std::wstring prefix = std::wstring(keyPath) + L"\\";
        for (const auto& [key, value] : m_protectedValues) {
            if (key.starts_with(prefix)) {
                result.push_back(value);
            }
        }
        return result;
    }

    // ========================================================================
    // OPERATION FILTERING
    // ========================================================================

    [[nodiscard]] bool IsOperationAllowed(const std::wstring& keyPath, uint32_t opType) {
        if (m_mode == RegistryProtectionMode::Disabled) {
            return true;
        }

        const auto operation = static_cast<RegistryOperation>(opType);

        RegistryOperationRequest request;
        request.operation = operation;
        request.keyPath = keyPath;
        request.processId = GetCurrentProcessId();
        request.threadId = GetCurrentThreadId();
        request.timestamp = Clock::now();

        const auto decision = FilterOperation(request);
        return decision.decision == OperationDecision::Allow ||
               decision.decision == OperationDecision::AllowLogged;
    }

    [[nodiscard]] OperationDecisionResult FilterOperation(const RegistryOperationRequest& request) {
        OperationDecisionResult result;
        result.decision = OperationDecision::Allow;

        m_stats.totalOperations++;

        // Check if protection is disabled
        if (m_mode == RegistryProtectionMode::Disabled) {
            return result;
        }

        // Check if process is whitelisted
        if (IsProcessWhitelisted(request.processId)) {
            result.decision = OperationDecision::AllowLogged;
            result.reason = "Process is whitelisted";
            return result;
        }

        // Check custom decision callback
        if (m_decisionCallback) {
            auto customResult = m_decisionCallback(request);
            if (customResult.has_value()) {
                return customResult.value();
            }
        }

        // Check if key is protected
        std::shared_lock lock(m_mutex);

        if (!IsKeyProtectedInternal(request.keyPath)) {
            return result;
        }

        // Get protection info
        const auto normalized = NormalizeKeyPath(request.keyPath);
        auto keyIt = m_protectedKeys.find(normalized);

        if (keyIt == m_protectedKeys.end()) {
            // Check parent keys for subkey protection
            for (const auto& [path, key] : m_protectedKeys) {
                if (key.includeSubkeys && normalized.starts_with(path + L"\\")) {
                    keyIt = m_protectedKeys.find(path);
                    break;
                }
            }
        }

        if (keyIt == m_protectedKeys.end()) {
            return result;
        }

        const auto& protectedKey = keyIt->second;

        // Check if operation is blocked
        const auto blockedOps = static_cast<uint32_t>(protectedKey.blockedOperations);
        const auto reqOp = static_cast<uint32_t>(request.operation);

        if ((blockedOps & reqOp) != 0) {
            result.decision = OperationDecision::Block;
            result.reason = "Operation blocked by protection policy";
            result.shouldLog = true;
            result.shouldAlert = true;

            if (m_mode == RegistryProtectionMode::Rollback) {
                result.shouldRollback = true;
                result.shouldSnapshot = true;
            }

            m_stats.totalBlocked++;

            // Fire event
            lock.unlock();
            FireBlockedOperationEvent(request, result);
        } else if (m_mode == RegistryProtectionMode::Monitor) {
            result.decision = OperationDecision::AllowLogged;
            result.shouldLog = true;
        }

        return result;
    }

    void SetDecisionCallback(OperationDecisionCallback callback) {
        std::unique_lock lock(m_mutex);
        m_decisionCallback = std::move(callback);
    }

    void ClearDecisionCallback() {
        std::unique_lock lock(m_mutex);
        m_decisionCallback = nullptr;
    }

    // ========================================================================
    // INTEGRITY MANAGEMENT
    // ========================================================================

    [[nodiscard]] IntegrityStatus VerifyKeyIntegrity(std::wstring_view keyPath) {
        std::unique_lock lock(m_mutex);
        const auto normalized = NormalizeKeyPath(keyPath);

        auto it = m_protectedKeys.find(normalized);
        if (it == m_protectedKeys.end()) {
            return IntegrityStatus::Unknown;
        }

        m_stats.totalIntegrityChecks++;
        it->second.lastVerified = Clock::now();

        // Check if key exists
        HKEY rootKey = nullptr;
        std::wstring subKey;
        if (!Utils::RegistryUtils::SplitPath(normalized, rootKey, subKey)) {
            it->second.integrity = IntegrityStatus::Missing;
            return IntegrityStatus::Missing;
        }

        Utils::RegistryUtils::RegistryKey regKey;
        Utils::RegistryUtils::OpenOptions opts;
        opts.access = KEY_READ;

        if (!regKey.Open(rootKey, subKey, opts)) {
            it->second.integrity = IntegrityStatus::Missing;
            m_stats.integrityViolations++;

            // Fire integrity callback
            lock.unlock();
            FireIntegrityCallback(it->second);

            return IntegrityStatus::Missing;
        }

        it->second.integrity = IntegrityStatus::Valid;
        return IntegrityStatus::Valid;
    }

    [[nodiscard]] IntegrityStatus VerifyValueIntegrity(std::wstring_view keyPath,
                                                       std::wstring_view valueName) {
        std::unique_lock lock(m_mutex);
        const auto key = std::wstring(keyPath) + L"\\" + std::wstring(valueName);

        auto it = m_protectedValues.find(key);
        if (it == m_protectedValues.end()) {
            return IntegrityStatus::Unknown;
        }

        m_stats.totalIntegrityChecks++;
        it->second.lastVerified = Clock::now();

        // Read current value and compare hash
        ProtectedValue currentValue = it->second;
        if (!ReadValueAndComputeHash(currentValue)) {
            it->second.integrity = IntegrityStatus::Missing;
            m_stats.integrityViolations++;
            return IntegrityStatus::Missing;
        }

        if (currentValue.currentHash != it->second.expectedHash) {
            it->second.integrity = IntegrityStatus::Modified;
            it->second.currentHash = currentValue.currentHash;
            it->second.modificationCount++;
            m_stats.integrityViolations++;

            // Fire value change callback
            const auto oldData = it->second.expectedData;
            const auto newData = currentValue.expectedData;
            lock.unlock();
            FireValueChangeCallback(it->second, oldData, newData);

            return IntegrityStatus::Modified;
        }

        it->second.integrity = IntegrityStatus::Valid;
        return IntegrityStatus::Valid;
    }

    [[nodiscard]] std::vector<std::pair<std::wstring, IntegrityStatus>> VerifyAllIntegrity() {
        std::vector<std::pair<std::wstring, IntegrityStatus>> results;

        // Copy keys to avoid holding lock during verification
        std::vector<std::wstring> keyPaths;
        {
            std::shared_lock lock(m_mutex);
            keyPaths.reserve(m_protectedKeys.size());
            for (const auto& [path, key] : m_protectedKeys) {
                keyPaths.push_back(path);
            }
        }

        results.reserve(keyPaths.size());
        for (const auto& path : keyPaths) {
            const auto status = VerifyKeyIntegrity(path);
            results.emplace_back(path, status);
        }

        return results;
    }

    [[nodiscard]] bool UpdateKeyBaseline(std::wstring_view keyPath,
                                         std::string_view authorizationToken) {
        if (!VerifyAuthToken(authorizationToken)) {
            return false;
        }

        std::unique_lock lock(m_mutex);
        const auto normalized = NormalizeKeyPath(keyPath);

        auto it = m_protectedKeys.find(normalized);
        if (it == m_protectedKeys.end()) {
            return false;
        }

        // Create snapshot before updating baseline
        CreateSnapshotInternal(normalized);

        it->second.integrity = IntegrityStatus::Valid;
        it->second.lastVerified = Clock::now();

        SS_LOG_INFO(LOG_CATEGORY, L"Key baseline updated: %ls", normalized.c_str());
        return true;
    }

    [[nodiscard]] bool UpdateValueBaseline(std::wstring_view keyPath, std::wstring_view valueName,
                                           std::string_view authorizationToken) {
        if (!VerifyAuthToken(authorizationToken)) {
            return false;
        }

        std::unique_lock lock(m_mutex);
        const auto key = std::wstring(keyPath) + L"\\" + std::wstring(valueName);

        auto it = m_protectedValues.find(key);
        if (it == m_protectedValues.end()) {
            return false;
        }

        // Read current value as new baseline
        if (!ReadValueAndComputeHash(it->second)) {
            return false;
        }

        it->second.expectedHash = it->second.currentHash;
        it->second.integrity = IntegrityStatus::Valid;
        it->second.lastVerified = Clock::now();

        SS_LOG_INFO(LOG_CATEGORY, L"Value baseline updated: %ls\\%ls",
            std::wstring(keyPath).c_str(), std::wstring(valueName).c_str());
        return true;
    }

    void ForceIntegrityCheck() {
        SS_LOG_INFO(LOG_CATEGORY, L"Forcing integrity check on all protected keys...");

        const auto results = VerifyAllIntegrity();

        size_t violations = 0;
        for (const auto& [path, status] : results) {
            if (status != IntegrityStatus::Valid && status != IntegrityStatus::Unknown) {
                violations++;
                SS_LOG_WARN(LOG_CATEGORY, L"Integrity violation: %ls (status=%hs)",
                    path.c_str(), std::string(GetIntegrityStatusName(status)).c_str());
            }
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Integrity check complete: %zu keys, %zu violations",
            results.size(), violations);
    }

    // ========================================================================
    // SNAPSHOT AND ROLLBACK
    // ========================================================================

    [[nodiscard]] bool CreateSnapshot(std::wstring_view keyPath) {
        std::unique_lock lock(m_mutex);
        return CreateSnapshotInternal(std::wstring(keyPath));
    }

    [[nodiscard]] bool RestoreFromSnapshot(std::wstring_view keyPath, uint32_t version) {
        std::unique_lock lock(m_mutex);
        const auto normalized = NormalizeKeyPath(keyPath);

        auto it = m_snapshots.find(normalized);
        if (it == m_snapshots.end() || it->second.empty()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"No snapshots available for: %ls", normalized.c_str());
            return false;
        }

        const auto& snapshots = it->second;
        const KeySnapshot* snapshotToRestore = nullptr;

        if (version == 0) {
            // Use latest snapshot
            snapshotToRestore = &snapshots.back();
        } else {
            // Find specific version
            for (const auto& s : snapshots) {
                if (s.version == version) {
                    snapshotToRestore = &s;
                    break;
                }
            }
        }

        if (!snapshotToRestore) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Snapshot version %u not found for: %ls",
                version, normalized.c_str());
            return false;
        }

        // Restore values from snapshot
        HKEY rootKey = nullptr;
        std::wstring subKey;
        if (!Utils::RegistryUtils::SplitPath(normalized, rootKey, subKey)) {
            return false;
        }

        Utils::RegistryUtils::RegistryKey regKey;
        Utils::RegistryUtils::OpenOptions opts;
        opts.access = KEY_ALL_ACCESS;

        if (!regKey.Create(rootKey, subKey, opts)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to open key for restore: %ls", normalized.c_str());
            return false;
        }

        bool success = true;
        for (size_t i = 0; i < snapshotToRestore->values.size(); ++i) {
            const auto& [name, data] = snapshotToRestore->values[i];
            const auto type = snapshotToRestore->valueTypes[i].second;

            const LSTATUS st = RegSetValueExW(regKey.Handle(), name.c_str(), 0,
                static_cast<DWORD>(type), data.data(), static_cast<DWORD>(data.size()));

            if (st != ERROR_SUCCESS) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to restore value: %ls (error=%lu)",
                    name.c_str(), st);
                success = false;
            }
        }

        if (success) {
            m_stats.snapshotsRestored++;
            SS_LOG_INFO(LOG_CATEGORY, L"Snapshot restored for: %ls (version=%u)",
                normalized.c_str(), snapshotToRestore->version);
        }

        return success;
    }

    [[nodiscard]] std::vector<KeySnapshot> GetAvailableSnapshots(std::wstring_view keyPath) const {
        std::shared_lock lock(m_mutex);
        const auto normalized = NormalizeKeyPath(keyPath);

        auto it = m_snapshots.find(normalized);
        if (it != m_snapshots.end()) {
            return it->second;
        }
        return {};
    }

    [[nodiscard]] bool RollbackKey(std::wstring_view keyPath) {
        return RestoreFromSnapshot(keyPath, 0);
    }

    [[nodiscard]] bool RollbackValue(std::wstring_view keyPath, std::wstring_view valueName) {
        std::unique_lock lock(m_mutex);
        const auto key = std::wstring(keyPath) + L"\\" + std::wstring(valueName);

        auto it = m_protectedValues.find(key);
        if (it == m_protectedValues.end()) {
            return false;
        }

        const auto& pv = it->second;
        if (pv.expectedData.empty()) {
            SS_LOG_WARN(LOG_CATEGORY, L"No baseline data for value: %ls", key.c_str());
            return false;
        }

        HKEY rootKey = nullptr;
        std::wstring subKey;
        if (!Utils::RegistryUtils::SplitPath(pv.keyPath, rootKey, subKey)) {
            return false;
        }

        Utils::RegistryUtils::RegistryKey regKey;
        Utils::RegistryUtils::OpenOptions opts;
        opts.access = KEY_SET_VALUE;

        if (!regKey.Open(rootKey, subKey, opts)) {
            return false;
        }

        const LSTATUS st = RegSetValueExW(regKey.Handle(), pv.valueName.c_str(), 0,
            static_cast<DWORD>(pv.valueType), pv.expectedData.data(),
            static_cast<DWORD>(pv.expectedData.size()));

        if (st != ERROR_SUCCESS) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to rollback value: %ls (error=%lu)",
                key.c_str(), st);
            return false;
        }

        m_stats.totalRollbacks++;
        it->second.integrity = IntegrityStatus::Restored;
        it->second.currentHash = it->second.expectedHash;

        SS_LOG_INFO(LOG_CATEGORY, L"Value rolled back: %ls", key.c_str());
        return true;
    }

    void CleanupOldSnapshots() {
        std::unique_lock lock(m_mutex);

        for (auto& [path, snapshots] : m_snapshots) {
            while (snapshots.size() > m_config.maxSnapshotsPerKey) {
                snapshots.erase(snapshots.begin());
            }
        }

        SS_LOG_DEBUG(LOG_CATEGORY, L"Old snapshots cleaned up");
    }

    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool AddToWhitelist(std::wstring_view processName,
                                      std::string_view authorizationToken) {
        if (!VerifyAuthToken(authorizationToken)) {
            return false;
        }

        std::unique_lock lock(m_mutex);
        m_whitelistedProcesses.insert(std::wstring(processName));
        SS_LOG_INFO(LOG_CATEGORY, L"Process added to whitelist: %ls",
            std::wstring(processName).c_str());
        return true;
    }

    [[nodiscard]] bool RemoveFromWhitelist(std::wstring_view processName,
                                           std::string_view authorizationToken) {
        if (!VerifyAuthToken(authorizationToken)) {
            return false;
        }

        std::unique_lock lock(m_mutex);
        const auto erased = m_whitelistedProcesses.erase(std::wstring(processName));
        if (erased > 0) {
            SS_LOG_INFO(LOG_CATEGORY, L"Process removed from whitelist: %ls",
                std::wstring(processName).c_str());
        }
        return erased > 0;
    }

    [[nodiscard]] bool IsWhitelisted(std::wstring_view processName) const {
        std::shared_lock lock(m_mutex);
        return m_whitelistedProcesses.contains(std::wstring(processName));
    }

    [[nodiscard]] bool IsWhitelisted(uint32_t processId) const {
        // Get process name from PID
        const auto processName = GetProcessNameFromPid(processId);
        if (processName.empty()) {
            return false;
        }
        return IsWhitelisted(processName);
    }

    [[nodiscard]] std::vector<std::wstring> GetWhitelistedProcesses() const {
        std::shared_lock lock(m_mutex);
        return std::vector<std::wstring>(m_whitelistedProcesses.begin(),
                                         m_whitelistedProcesses.end());
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    [[nodiscard]] uint64_t RegisterEventCallback(RegistryEventCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextCallbackId++;
        m_eventCallbacks[id] = std::move(callback);
        return id;
    }

    void UnregisterEventCallback(uint64_t callbackId) {
        std::unique_lock lock(m_mutex);
        m_eventCallbacks.erase(callbackId);
    }

    [[nodiscard]] uint64_t RegisterIntegrityCallback(IntegrityCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextCallbackId++;
        m_integrityCallbacks[id] = std::move(callback);
        return id;
    }

    void UnregisterIntegrityCallback(uint64_t callbackId) {
        std::unique_lock lock(m_mutex);
        m_integrityCallbacks.erase(callbackId);
    }

    [[nodiscard]] uint64_t RegisterValueChangeCallback(ValueChangeCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextCallbackId++;
        m_valueChangeCallbacks[id] = std::move(callback);
        return id;
    }

    void UnregisterValueChangeCallback(uint64_t callbackId) {
        std::unique_lock lock(m_mutex);
        m_valueChangeCallbacks.erase(callbackId);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] RegistryProtectionStatistics GetStatistics() const {
        // Statistics are already atomic, no lock needed for reading
        return m_stats;
    }

    void ResetStatistics(std::string_view authorizationToken) {
        if (!VerifyAuthToken(authorizationToken)) {
            return;
        }
        m_stats.Reset();
        m_stats.startTime = Clock::now();
        SS_LOG_INFO(LOG_CATEGORY, L"Statistics reset");
    }

    [[nodiscard]] std::vector<RegistryProtectionEvent> GetEventHistory(size_t maxEntries) const {
        std::shared_lock lock(m_mutex);

        const size_t count = std::min(maxEntries, m_eventHistory.size());
        std::vector<RegistryProtectionEvent> result;
        result.reserve(count);

        auto it = m_eventHistory.rbegin();
        for (size_t i = 0; i < count && it != m_eventHistory.rend(); ++i, ++it) {
            result.push_back(*it);
        }

        return result;
    }

    void ClearEventHistory(std::string_view authorizationToken) {
        if (!VerifyAuthToken(authorizationToken)) {
            return;
        }

        std::unique_lock lock(m_mutex);
        m_eventHistory.clear();
        SS_LOG_INFO(LOG_CATEGORY, L"Event history cleared");
    }

    [[nodiscard]] std::string ExportReport() const {
        std::ostringstream json;
        json << "{\n";
        json << "  \"module\": \"RegistryProtection\",\n";
        json << "  \"version\": \"" << GetVersionString() << "\",\n";
        json << "  \"status\": \"" << (IsInitialized() ? "Running" : "Stopped") << "\",\n";
        json << "  \"mode\": \"" << GetProtectionModeName(m_mode) << "\",\n";
        json << "  \"statistics\": " << m_stats.ToJson() << ",\n";

        // Protected keys summary
        {
            std::shared_lock lock(m_mutex);
            json << "  \"protectedKeysCount\": " << m_protectedKeys.size() << ",\n";
            json << "  \"protectedValuesCount\": " << m_protectedValues.size() << ",\n";
            json << "  \"whitelistedProcessesCount\": " << m_whitelistedProcesses.size() << ",\n";
            json << "  \"snapshotsCount\": " << m_snapshots.size() << "\n";
        }

        json << "}";
        return json.str();
    }

    // ========================================================================
    // SELF-TEST
    // ========================================================================

    [[nodiscard]] bool SelfTest() {
        SS_LOG_INFO(LOG_CATEGORY, L"Running self-test...");

        bool success = true;

        // Test 1: Key path normalization
        {
            const auto normalized = NormalizeKeyPath(L"HKLM\\SOFTWARE\\Test");
            if (normalized.empty()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: Key normalization");
                success = false;
            }
        }

        // Test 2: Root key parsing
        {
            const auto rootKey = ParseRootKey(L"HKLM\\SOFTWARE\\Test");
            if (rootKey != HKEY_LOCAL_MACHINE) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: Root key parsing");
                success = false;
            }
        }

        // Test 3: Subkey extraction
        {
            const auto subkey = GetSubkeyPath(L"HKLM\\SOFTWARE\\Test");
            if (subkey != L"SOFTWARE\\Test") {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: Subkey extraction");
                success = false;
            }
        }

        // Test 4: Statistics increment
        {
            const auto before = m_stats.totalOperations.load();
            m_stats.totalOperations++;
            const auto after = m_stats.totalOperations.load();
            if (after != before + 1) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: Atomic statistics");
                success = false;
            }
            m_stats.totalOperations--;
        }

        if (success) {
            SS_LOG_INFO(LOG_CATEGORY, L"Self-test PASSED");
        } else {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED");
        }

        return success;
    }

    // ========================================================================
    // STATIC HELPERS
    // ========================================================================

    [[nodiscard]] static std::wstring NormalizeKeyPath(std::wstring_view keyPath) {
        std::wstring result(keyPath);

        // Convert to uppercase for first segment
        if (result.starts_with(L"HKEY_LOCAL_MACHINE") || result.starts_with(L"hkey_local_machine")) {
            result.replace(0, 18, L"HKLM");
        } else if (result.starts_with(L"HKEY_CURRENT_USER") || result.starts_with(L"hkey_current_user")) {
            result.replace(0, 17, L"HKCU");
        } else if (result.starts_with(L"HKEY_CLASSES_ROOT") || result.starts_with(L"hkey_classes_root")) {
            result.replace(0, 17, L"HKCR");
        } else if (result.starts_with(L"HKEY_USERS") || result.starts_with(L"hkey_users")) {
            result.replace(0, 10, L"HKU");
        } else if (result.starts_with(L"HKEY_CURRENT_CONFIG") || result.starts_with(L"hkey_current_config")) {
            result.replace(0, 19, L"HKCC");
        }

        // Remove trailing backslash
        while (!result.empty() && result.back() == L'\\') {
            result.pop_back();
        }

        return result;
    }

    [[nodiscard]] static HKEY ParseRootKey(std::wstring_view keyPath) {
        if (keyPath.starts_with(L"HKLM\\") || keyPath.starts_with(L"HKEY_LOCAL_MACHINE\\")) {
            return HKEY_LOCAL_MACHINE;
        }
        if (keyPath.starts_with(L"HKCU\\") || keyPath.starts_with(L"HKEY_CURRENT_USER\\")) {
            return HKEY_CURRENT_USER;
        }
        if (keyPath.starts_with(L"HKCR\\") || keyPath.starts_with(L"HKEY_CLASSES_ROOT\\")) {
            return HKEY_CLASSES_ROOT;
        }
        if (keyPath.starts_with(L"HKU\\") || keyPath.starts_with(L"HKEY_USERS\\")) {
            return HKEY_USERS;
        }
        if (keyPath.starts_with(L"HKCC\\") || keyPath.starts_with(L"HKEY_CURRENT_CONFIG\\")) {
            return HKEY_CURRENT_CONFIG;
        }
        return nullptr;
    }

    [[nodiscard]] static std::wstring GetSubkeyPath(std::wstring_view fullPath) {
        const auto pos = fullPath.find(L'\\');
        if (pos == std::wstring_view::npos) {
            return {};
        }
        return std::wstring(fullPath.substr(pos + 1));
    }

    [[nodiscard]] static std::string GetVersionString() noexcept {
        return std::to_string(RegistryProtectionConstants::VERSION_MAJOR) + "." +
               std::to_string(RegistryProtectionConstants::VERSION_MINOR) + "." +
               std::to_string(RegistryProtectionConstants::VERSION_PATCH);
    }

private:
    // ========================================================================
    // PRIVATE METHODS
    // ========================================================================

    [[nodiscard]] bool AddProtectedKeyInternal(const std::wstring& keyPath,
                                               KeyProtectionType type,
                                               bool includeSubkeys) {
        const auto normalized = NormalizeKeyPath(keyPath);

        if (m_protectedKeys.contains(normalized)) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"Key already protected: %ls", normalized.c_str());
            return true;
        }

        if (m_protectedKeys.size() >= RegistryProtectionConstants::MAX_PROTECTED_KEYS) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Maximum protected keys limit reached");
            return false;
        }

        ProtectedKey pk;
        pk.id = GenerateUniqueId();
        pk.keyPath = keyPath;
        pk.normalizedPath = normalized;
        pk.rootKey = ParseRootKey(normalized);
        pk.type = type;
        pk.includeSubkeys = includeSubkeys;
        pk.protectedSince = Clock::now();
        pk.integrity = IntegrityStatus::Unknown;

        // Set blocked operations based on protection type
        switch (type) {
            case KeyProtectionType::ReadOnly:
                pk.blockedOperations = RegistryOperation::AllWrite;
                break;
            case KeyProtectionType::NoDelete:
                pk.blockedOperations = RegistryOperation::DeleteKey | RegistryOperation::DeleteValue;
                break;
            case KeyProtectionType::NoModify:
                pk.blockedOperations = RegistryOperation::SetValue | RegistryOperation::DeleteValue |
                                       RegistryOperation::CreateKey | RegistryOperation::DeleteKey;
                break;
            case KeyProtectionType::Full:
                pk.blockedOperations = RegistryOperation::AllWrite;
                break;
            case KeyProtectionType::ValuesOnly:
                pk.blockedOperations = RegistryOperation::SetValue | RegistryOperation::DeleteValue;
                break;
            default:
                pk.blockedOperations = RegistryOperation::None;
                break;
        }

        m_protectedKeys[normalized] = std::move(pk);
        m_stats.totalProtectedKeys++;

        SS_LOG_INFO(LOG_CATEGORY, L"Key protected: %ls (type=%hs, subkeys=%s)",
            normalized.c_str(), std::string(GetProtectionTypeName(type)).c_str(),
            includeSubkeys ? L"yes" : L"no");

        // Create initial snapshot if enabled
        if (m_config.enableSnapshots) {
            CreateSnapshotInternal(normalized);
        }

        return true;
    }

    [[nodiscard]] bool IsKeyProtectedInternal(const std::wstring& keyPath) const {
        const auto normalized = NormalizeKeyPath(keyPath);

        // Direct match
        if (m_protectedKeys.contains(normalized)) {
            return true;
        }

        // Check if any parent key protects this with includeSubkeys
        for (const auto& [path, key] : m_protectedKeys) {
            if (key.includeSubkeys && normalized.starts_with(path + L"\\")) {
                return true;
            }
        }

        return false;
    }

    [[nodiscard]] bool CreateSnapshotInternal(const std::wstring& keyPath) {
        const auto normalized = NormalizeKeyPath(keyPath);

        HKEY rootKey = nullptr;
        std::wstring subKey;
        if (!Utils::RegistryUtils::SplitPath(normalized, rootKey, subKey)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to parse key path: %ls", normalized.c_str());
            return false;
        }

        Utils::RegistryUtils::RegistryKey regKey;
        Utils::RegistryUtils::OpenOptions opts;
        opts.access = KEY_READ;

        if (!regKey.Open(rootKey, subKey, opts)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Cannot create snapshot - key not accessible: %ls",
                normalized.c_str());
            return false;
        }

        KeySnapshot snapshot;
        snapshot.id = GenerateUniqueId();
        snapshot.keyPath = normalized;
        snapshot.timestamp = Clock::now();
        snapshot.reason = "Protection baseline";

        // Read all values
        std::vector<Utils::RegistryUtils::ValueInfo> valueInfos;
        if (regKey.EnumValues(valueInfos)) {
            for (const auto& vi : valueInfos) {
                std::vector<uint8_t> data;
                Utils::RegistryUtils::ValueType actualType;

                if (regKey.ReadValue(vi.name, Utils::RegistryUtils::ValueType::Unknown,
                        data, &actualType)) {
                    snapshot.values.emplace_back(vi.name, std::move(data));
                    snapshot.valueTypes.emplace_back(vi.name,
                        static_cast<RegistryValueType>(actualType));
                }
            }
        }

        // Read subkeys
        std::vector<std::wstring> subKeys;
        if (regKey.EnumKeys(subKeys)) {
            snapshot.subkeys = std::move(subKeys);
        }

        // Set version number
        auto& snapshots = m_snapshots[normalized];
        snapshot.version = static_cast<uint32_t>(snapshots.size() + 1);

        // Limit snapshot count
        while (snapshots.size() >= m_config.maxSnapshotsPerKey) {
            snapshots.erase(snapshots.begin());
        }

        snapshots.push_back(std::move(snapshot));
        m_stats.snapshotsCreated++;

        SS_LOG_DEBUG(LOG_CATEGORY, L"Snapshot created for: %ls (version=%u)",
            normalized.c_str(), snapshot.version);

        return true;
    }

    [[nodiscard]] bool ReadValueAndComputeHash(ProtectedValue& pv) {
        HKEY rootKey = nullptr;
        std::wstring subKey;
        if (!Utils::RegistryUtils::SplitPath(pv.keyPath, rootKey, subKey)) {
            return false;
        }

        Utils::RegistryUtils::RegistryKey regKey;
        Utils::RegistryUtils::OpenOptions opts;
        opts.access = KEY_READ;

        if (!regKey.Open(rootKey, subKey, opts)) {
            return false;
        }

        std::vector<uint8_t> data;
        Utils::RegistryUtils::ValueType actualType;

        if (!regKey.ReadValue(pv.valueName, Utils::RegistryUtils::ValueType::Unknown,
                data, &actualType)) {
            return false;
        }

        pv.valueType = static_cast<RegistryValueType>(actualType);
        pv.dataSize = data.size();
        pv.currentHash = ComputeHash256(data);

        // Store data if small enough
        if (data.size() <= RegistryProtectionConstants::MAX_VALUE_DATA_SIZE) {
            pv.expectedData = std::move(data);
            pv.expectedHash = pv.currentHash;
        }

        return true;
    }

    [[nodiscard]] bool IsProcessWhitelisted(uint32_t processId) const {
        const auto processName = GetProcessNameFromPid(processId);
        if (processName.empty()) {
            return false;
        }

        std::shared_lock lock(m_mutex);
        return m_whitelistedProcesses.contains(processName);
    }

    [[nodiscard]] static std::wstring GetProcessNameFromPid(uint32_t processId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (!hProcess) {
            return {};
        }

        wchar_t path[MAX_PATH] = {};
        DWORD size = MAX_PATH;

        std::wstring result;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            // Extract filename from path
            const std::wstring fullPath(path);
            const auto pos = fullPath.rfind(L'\\');
            if (pos != std::wstring::npos) {
                result = fullPath.substr(pos + 1);
            } else {
                result = fullPath;
            }
        }

        CloseHandle(hProcess);
        return result;
    }

    [[nodiscard]] bool VerifyAuthToken(std::string_view token) const {
        // Simple token validation - in production, use cryptographic verification
        if (token.empty()) {
            return false;
        }
        if (!token.starts_with(AUTH_TOKEN_PREFIX)) {
            return false;
        }
        return true;
    }

    void StartMonitoring() {
        if (m_monitoringActive.exchange(true)) {
            return;  // Already running
        }

        m_stopMonitoring = false;
        m_monitorThread = std::thread([this]() {
            SS_LOG_INFO(LOG_CATEGORY, L"Monitoring thread started");
            MonitoringLoop();
            SS_LOG_INFO(LOG_CATEGORY, L"Monitoring thread stopped");
        });
    }

    void StopMonitoring() {
        if (!m_monitoringActive.load()) {
            return;
        }

        m_stopMonitoring = true;
        m_monitorCv.notify_all();

        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }

        m_monitoringActive = false;
    }

    void MonitoringLoop() {
        while (!m_stopMonitoring) {
            // Wait for interval or stop signal
            {
                std::unique_lock lock(m_monitorMutex);
                m_monitorCv.wait_for(lock,
                    Milliseconds(m_config.pollingIntervalMs),
                    [this]() { return m_stopMonitoring.load(); });
            }

            if (m_stopMonitoring) {
                break;
            }

            // Perform integrity check
            if (m_config.enableIntegrityMonitoring) {
                PerformIntegrityCheck();
            }
        }
    }

    void PerformIntegrityCheck() {
        // Get keys to check
        std::vector<std::wstring> keysToCheck;
        {
            std::shared_lock lock(m_mutex);
            keysToCheck.reserve(m_protectedKeys.size());
            for (const auto& [path, key] : m_protectedKeys) {
                keysToCheck.push_back(path);
            }
        }

        for (const auto& keyPath : keysToCheck) {
            if (m_stopMonitoring) break;

            const auto status = VerifyKeyIntegrity(keyPath);
            if (status != IntegrityStatus::Valid && status != IntegrityStatus::Unknown) {
                SS_LOG_WARN(LOG_CATEGORY, L"Integrity violation detected: %ls", keyPath.c_str());

                // Auto-rollback if enabled
                if (m_config.enableAutoRollback && m_mode == RegistryProtectionMode::Rollback) {
                    if (RollbackKey(keyPath)) {
                        SS_LOG_INFO(LOG_CATEGORY, L"Key auto-restored: %ls", keyPath.c_str());
                    }
                }
            }
        }
    }

    void FireBlockedOperationEvent(const RegistryOperationRequest& request,
                                   const OperationDecisionResult& decision) {
        RegistryProtectionEvent event;
        event.eventId = m_nextEventId++;
        event.type = ProtectionEventType::OperationBlocked;
        event.timestamp = Clock::now();
        event.keyPath = request.keyPath;
        event.valueName = request.valueName;
        event.operation = request.operation;
        event.decision = decision.decision;
        event.sourceProcessId = request.processId;
        event.sourceProcessName = request.processName;
        event.sourceProcessPath = request.processPath;
        event.wasBlocked = true;
        event.description = decision.reason;

        // Add to history
        {
            std::unique_lock lock(m_mutex);
            m_eventHistory.push_back(event);
            while (m_eventHistory.size() > MAX_EVENT_HISTORY) {
                m_eventHistory.erase(m_eventHistory.begin());
            }
        }

        m_stats.lastEventTime = event.timestamp;

        // Fire callbacks
        std::vector<RegistryEventCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks.reserve(m_eventCallbacks.size());
            for (const auto& [id, cb] : m_eventCallbacks) {
                callbacks.push_back(cb);
            }
        }

        for (const auto& callback : callbacks) {
            try {
                callback(event);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Event callback exception: %hs", e.what());
            }
        }
    }

    void FireIntegrityCallback(const ProtectedKey& key) {
        std::vector<IntegrityCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks.reserve(m_integrityCallbacks.size());
            for (const auto& [id, cb] : m_integrityCallbacks) {
                callbacks.push_back(cb);
            }
        }

        for (const auto& callback : callbacks) {
            try {
                callback(key);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Integrity callback exception: %hs", e.what());
            }
        }
    }

    void FireValueChangeCallback(const ProtectedValue& value,
                                 const std::vector<uint8_t>& oldData,
                                 const std::vector<uint8_t>& newData) {
        std::vector<ValueChangeCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks.reserve(m_valueChangeCallbacks.size());
            for (const auto& [id, cb] : m_valueChangeCallbacks) {
                callbacks.push_back(cb);
            }
        }

        for (const auto& callback : callbacks) {
            try {
                callback(value, oldData, newData);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Value change callback exception: %hs", e.what());
            }
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    // Synchronization
    mutable std::shared_mutex m_mutex;
    mutable std::mutex m_monitorMutex;
    std::condition_variable m_monitorCv;

    // State
    std::atomic<ModuleStatus> m_status;
    std::atomic<RegistryProtectionMode> m_mode;
    RegistryProtectionConfiguration m_config;

    // Protected resources
    std::unordered_map<std::wstring, ProtectedKey> m_protectedKeys;
    std::unordered_map<std::wstring, ProtectedValue> m_protectedValues;
    std::unordered_map<std::wstring, std::vector<KeySnapshot>> m_snapshots;
    std::unordered_set<std::wstring> m_whitelistedProcesses;

    // Callbacks
    std::unordered_map<uint64_t, RegistryEventCallback> m_eventCallbacks;
    std::unordered_map<uint64_t, IntegrityCallback> m_integrityCallbacks;
    std::unordered_map<uint64_t, ValueChangeCallback> m_valueChangeCallbacks;
    OperationDecisionCallback m_decisionCallback;
    std::atomic<uint64_t> m_nextCallbackId;

    // Events
    std::vector<RegistryProtectionEvent> m_eventHistory;
    std::atomic<uint64_t> m_nextEventId;

    // Statistics
    RegistryProtectionStatistics m_stats;

    // Monitoring thread
    std::thread m_monitorThread;
    std::atomic<bool> m_monitoringActive{false};
    std::atomic<bool> m_stopMonitoring{false};
};

// ============================================================================
// REGISTRYPROTECTION PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

RegistryProtection& RegistryProtection::Instance() noexcept {
    static RegistryProtection instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool RegistryProtection::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

RegistryProtection::RegistryProtection()
    : m_impl(std::make_unique<RegistryProtectionImpl>())
{
    SS_LOG_DEBUG(LOG_CATEGORY, L"RegistryProtection singleton created");
}

RegistryProtection::~RegistryProtection() {
    SS_LOG_DEBUG(LOG_CATEGORY, L"RegistryProtection singleton destroyed");
}

bool RegistryProtection::Initialize(const RegistryProtectionConfiguration& config) {
    return m_impl->Initialize(config);
}

bool RegistryProtection::Initialize(RegistryProtectionMode mode) {
    return m_impl->Initialize(RegistryProtectionConfiguration::FromMode(mode));
}

void RegistryProtection::Shutdown(std::string_view authorizationToken) {
    m_impl->Shutdown(authorizationToken);
}

bool RegistryProtection::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus RegistryProtection::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool RegistryProtection::SetConfiguration(const RegistryProtectionConfiguration& config) {
    return m_impl->SetConfiguration(config);
}

RegistryProtectionConfiguration RegistryProtection::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

void RegistryProtection::SetProtectionMode(RegistryProtectionMode mode) {
    m_impl->SetProtectionMode(mode);
}

RegistryProtectionMode RegistryProtection::GetProtectionMode() const noexcept {
    return m_impl->GetProtectionMode();
}

void RegistryProtection::ProtectKey(const std::wstring& keyPath) {
    m_impl->ProtectKey(keyPath);
}

bool RegistryProtection::ProtectKey(std::wstring_view keyPath, KeyProtectionType type,
                                    bool includeSubkeys) {
    return m_impl->ProtectKey(keyPath, type, includeSubkeys);
}

bool RegistryProtection::UnprotectKey(std::wstring_view keyPath,
                                      std::string_view authorizationToken) {
    return m_impl->UnprotectKey(keyPath, authorizationToken);
}

bool RegistryProtection::IsKeyProtected(std::wstring_view keyPath) const {
    return m_impl->IsKeyProtected(keyPath);
}

std::optional<ProtectedKey> RegistryProtection::GetProtectedKey(std::wstring_view keyPath) const {
    return m_impl->GetProtectedKey(keyPath);
}

std::vector<ProtectedKey> RegistryProtection::GetAllProtectedKeys() const {
    return m_impl->GetAllProtectedKeys();
}

bool RegistryProtection::ProtectServiceKeys() {
    return m_impl->ProtectServiceKeys();
}

bool RegistryProtection::ProtectStartupEntries() {
    return m_impl->ProtectStartupEntries();
}

bool RegistryProtection::ProtectValue(std::wstring_view keyPath, std::wstring_view valueName) {
    return m_impl->ProtectValue(keyPath, valueName);
}

bool RegistryProtection::UnprotectValue(std::wstring_view keyPath, std::wstring_view valueName,
                                        std::string_view authorizationToken) {
    return m_impl->UnprotectValue(keyPath, valueName, authorizationToken);
}

bool RegistryProtection::IsValueProtected(std::wstring_view keyPath,
                                          std::wstring_view valueName) const {
    return m_impl->IsValueProtected(keyPath, valueName);
}

std::optional<ProtectedValue> RegistryProtection::GetProtectedValue(
    std::wstring_view keyPath, std::wstring_view valueName) const {
    return m_impl->GetProtectedValue(keyPath, valueName);
}

std::vector<ProtectedValue> RegistryProtection::GetProtectedValues(std::wstring_view keyPath) const {
    return m_impl->GetProtectedValues(keyPath);
}

bool RegistryProtection::IsOperationAllowed(const std::wstring& keyPath, uint32_t opType) {
    return m_impl->IsOperationAllowed(keyPath, opType);
}

OperationDecisionResult RegistryProtection::FilterOperation(const RegistryOperationRequest& request) {
    return m_impl->FilterOperation(request);
}

void RegistryProtection::SetDecisionCallback(OperationDecisionCallback callback) {
    m_impl->SetDecisionCallback(std::move(callback));
}

void RegistryProtection::ClearDecisionCallback() {
    m_impl->ClearDecisionCallback();
}

IntegrityStatus RegistryProtection::VerifyKeyIntegrity(std::wstring_view keyPath) {
    return m_impl->VerifyKeyIntegrity(keyPath);
}

IntegrityStatus RegistryProtection::VerifyValueIntegrity(std::wstring_view keyPath,
                                                         std::wstring_view valueName) {
    return m_impl->VerifyValueIntegrity(keyPath, valueName);
}

std::vector<std::pair<std::wstring, IntegrityStatus>> RegistryProtection::VerifyAllIntegrity() {
    return m_impl->VerifyAllIntegrity();
}

bool RegistryProtection::UpdateKeyBaseline(std::wstring_view keyPath,
                                           std::string_view authorizationToken) {
    return m_impl->UpdateKeyBaseline(keyPath, authorizationToken);
}

bool RegistryProtection::UpdateValueBaseline(std::wstring_view keyPath, std::wstring_view valueName,
                                             std::string_view authorizationToken) {
    return m_impl->UpdateValueBaseline(keyPath, valueName, authorizationToken);
}

void RegistryProtection::ForceIntegrityCheck() {
    m_impl->ForceIntegrityCheck();
}

bool RegistryProtection::CreateSnapshot(std::wstring_view keyPath) {
    return m_impl->CreateSnapshot(keyPath);
}

bool RegistryProtection::RestoreFromSnapshot(std::wstring_view keyPath, uint32_t version) {
    return m_impl->RestoreFromSnapshot(keyPath, version);
}

std::vector<KeySnapshot> RegistryProtection::GetAvailableSnapshots(std::wstring_view keyPath) const {
    return m_impl->GetAvailableSnapshots(keyPath);
}

bool RegistryProtection::RollbackKey(std::wstring_view keyPath) {
    return m_impl->RollbackKey(keyPath);
}

bool RegistryProtection::RollbackValue(std::wstring_view keyPath, std::wstring_view valueName) {
    return m_impl->RollbackValue(keyPath, valueName);
}

void RegistryProtection::CleanupOldSnapshots() {
    m_impl->CleanupOldSnapshots();
}

bool RegistryProtection::AddToWhitelist(std::wstring_view processName,
                                        std::string_view authorizationToken) {
    return m_impl->AddToWhitelist(processName, authorizationToken);
}

bool RegistryProtection::RemoveFromWhitelist(std::wstring_view processName,
                                             std::string_view authorizationToken) {
    return m_impl->RemoveFromWhitelist(processName, authorizationToken);
}

bool RegistryProtection::IsWhitelisted(std::wstring_view processName) const {
    return m_impl->IsWhitelisted(processName);
}

bool RegistryProtection::IsWhitelisted(uint32_t processId) const {
    return m_impl->IsWhitelisted(processId);
}

std::vector<std::wstring> RegistryProtection::GetWhitelistedProcesses() const {
    return m_impl->GetWhitelistedProcesses();
}

uint64_t RegistryProtection::RegisterEventCallback(RegistryEventCallback callback) {
    return m_impl->RegisterEventCallback(std::move(callback));
}

void RegistryProtection::UnregisterEventCallback(uint64_t callbackId) {
    m_impl->UnregisterEventCallback(callbackId);
}

uint64_t RegistryProtection::RegisterIntegrityCallback(IntegrityCallback callback) {
    return m_impl->RegisterIntegrityCallback(std::move(callback));
}

void RegistryProtection::UnregisterIntegrityCallback(uint64_t callbackId) {
    m_impl->UnregisterIntegrityCallback(callbackId);
}

uint64_t RegistryProtection::RegisterValueChangeCallback(ValueChangeCallback callback) {
    return m_impl->RegisterValueChangeCallback(std::move(callback));
}

void RegistryProtection::UnregisterValueChangeCallback(uint64_t callbackId) {
    m_impl->UnregisterValueChangeCallback(callbackId);
}

RegistryProtectionStatistics RegistryProtection::GetStatistics() const {
    return m_impl->GetStatistics();
}

void RegistryProtection::ResetStatistics(std::string_view authorizationToken) {
    m_impl->ResetStatistics(authorizationToken);
}

std::vector<RegistryProtectionEvent> RegistryProtection::GetEventHistory(size_t maxEntries) const {
    return m_impl->GetEventHistory(maxEntries);
}

void RegistryProtection::ClearEventHistory(std::string_view authorizationToken) {
    m_impl->ClearEventHistory(authorizationToken);
}

std::string RegistryProtection::ExportReport() const {
    return m_impl->ExportReport();
}

bool RegistryProtection::SelfTest() {
    return m_impl->SelfTest();
}

std::wstring RegistryProtection::NormalizeKeyPath(std::wstring_view keyPath) {
    return RegistryProtectionImpl::NormalizeKeyPath(keyPath);
}

HKEY RegistryProtection::ParseRootKey(std::wstring_view keyPath) {
    return RegistryProtectionImpl::ParseRootKey(keyPath);
}

std::wstring RegistryProtection::GetSubkeyPath(std::wstring_view fullPath) {
    return RegistryProtectionImpl::GetSubkeyPath(fullPath);
}

std::string RegistryProtection::GetVersionString() noexcept {
    return RegistryProtectionImpl::GetVersionString();
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

bool RegistryProtectionConfiguration::IsValid() const noexcept {
    if (pollingIntervalMs < 100 || pollingIntervalMs > 3600000) {
        return false;
    }
    if (integrityCheckIntervalMs < 1000 || integrityCheckIntervalMs > 86400000) {
        return false;
    }
    if (maxSnapshotsPerKey < 1 || maxSnapshotsPerKey > 100) {
        return false;
    }
    return true;
}

RegistryProtectionConfiguration RegistryProtectionConfiguration::FromMode(RegistryProtectionMode mode) {
    RegistryProtectionConfiguration config;
    config.mode = mode;

    switch (mode) {
        case RegistryProtectionMode::Disabled:
            config.enableKernelCallbacks = false;
            config.enableUserModePolling = false;
            config.enableIntegrityMonitoring = false;
            config.enableAutoRollback = false;
            config.enableSnapshots = false;
            config.defaultResponse = ProtectionResponse::None;
            break;

        case RegistryProtectionMode::Monitor:
            config.enableKernelCallbacks = false;
            config.enableUserModePolling = true;
            config.enableIntegrityMonitoring = true;
            config.enableAutoRollback = false;
            config.enableSnapshots = true;
            config.defaultResponse = ProtectionResponse::Passive;
            break;

        case RegistryProtectionMode::Protect:
            config.enableKernelCallbacks = true;
            config.enableUserModePolling = true;
            config.enableIntegrityMonitoring = true;
            config.enableAutoRollback = false;
            config.enableSnapshots = true;
            config.defaultResponse = ProtectionResponse::Active;
            break;

        case RegistryProtectionMode::Rollback:
            config.enableKernelCallbacks = true;
            config.enableUserModePolling = true;
            config.enableIntegrityMonitoring = true;
            config.enableAutoRollback = true;
            config.enableSnapshots = true;
            config.defaultResponse = ProtectionResponse::Active | ProtectionResponse::Rollback;
            break;

        case RegistryProtectionMode::Strict:
            config.enableKernelCallbacks = true;
            config.enableUserModePolling = true;
            config.enableIntegrityMonitoring = true;
            config.enableAutoRollback = true;
            config.enableSnapshots = true;
            config.pollingIntervalMs = 2000;
            config.integrityCheckIntervalMs = 10000;
            config.defaultResponse = ProtectionResponse::Aggressive;
            break;
    }

    return config;
}

std::string RegistryProtectionEvent::GetSummary() const {
    std::ostringstream oss;
    oss << "Event #" << eventId << ": ";
    oss << (wasBlocked ? "BLOCKED " : "ALLOWED ");
    oss << GetRegistryOperationName(operation) << " on ";
    oss << WideToNarrow(keyPath);
    if (!valueName.empty()) {
        oss << "\\" << WideToNarrow(valueName);
    }
    oss << " by PID " << sourceProcessId;
    return oss.str();
}

std::string RegistryProtectionEvent::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"eventId\":" << eventId << ",";
    json << "\"type\":" << static_cast<uint32_t>(type) << ",";
    json << "\"timestamp\":\"" << FormatTimestamp(timestamp) << "\",";
    json << "\"keyPath\":\"" << EscapeJsonString(WideToNarrow(keyPath)) << "\",";
    json << "\"valueName\":\"" << EscapeJsonString(WideToNarrow(valueName)) << "\",";
    json << "\"operation\":" << static_cast<uint32_t>(operation) << ",";
    json << "\"decision\":" << static_cast<uint8_t>(decision) << ",";
    json << "\"sourceProcessId\":" << sourceProcessId << ",";
    json << "\"sourceProcessName\":\"" << EscapeJsonString(WideToNarrow(sourceProcessName)) << "\",";
    json << "\"wasBlocked\":" << (wasBlocked ? "true" : "false") << ",";
    json << "\"wasRolledBack\":" << (wasRolledBack ? "true" : "false") << ",";
    json << "\"description\":\"" << EscapeJsonString(description) << "\"";
    json << "}";
    return json.str();
}

void RegistryProtectionStatistics::Reset() noexcept {
    totalProtectedKeys = 0;
    totalProtectedValues = 0;
    totalOperations = 0;
    totalBlocked = 0;
    totalRollbacks = 0;
    totalIntegrityChecks = 0;
    integrityViolations = 0;
    snapshotsCreated = 0;
    snapshotsRestored = 0;
    startTime = Clock::now();
    lastEventTime = TimePoint{};
}

std::string RegistryProtectionStatistics::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"totalProtectedKeys\":" << totalProtectedKeys.load() << ",";
    json << "\"totalProtectedValues\":" << totalProtectedValues.load() << ",";
    json << "\"totalOperations\":" << totalOperations.load() << ",";
    json << "\"totalBlocked\":" << totalBlocked.load() << ",";
    json << "\"totalRollbacks\":" << totalRollbacks.load() << ",";
    json << "\"totalIntegrityChecks\":" << totalIntegrityChecks.load() << ",";
    json << "\"integrityViolations\":" << integrityViolations.load() << ",";
    json << "\"snapshotsCreated\":" << snapshotsCreated.load() << ",";
    json << "\"snapshotsRestored\":" << snapshotsRestored.load() << ",";
    json << "\"startTime\":\"" << FormatTimestamp(startTime) << "\",";
    json << "\"uptimeSeconds\":" << std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    json << "}";
    return json.str();
}

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

std::string_view GetProtectionModeName(RegistryProtectionMode mode) noexcept {
    switch (mode) {
        case RegistryProtectionMode::Disabled: return "Disabled";
        case RegistryProtectionMode::Monitor: return "Monitor";
        case RegistryProtectionMode::Protect: return "Protect";
        case RegistryProtectionMode::Rollback: return "Rollback";
        case RegistryProtectionMode::Strict: return "Strict";
        default: return "Unknown";
    }
}

std::string_view GetRegistryOperationName(RegistryOperation operation) noexcept {
    switch (operation) {
        case RegistryOperation::None: return "None";
        case RegistryOperation::QueryKey: return "QueryKey";
        case RegistryOperation::SetValue: return "SetValue";
        case RegistryOperation::DeleteValue: return "DeleteValue";
        case RegistryOperation::CreateKey: return "CreateKey";
        case RegistryOperation::DeleteKey: return "DeleteKey";
        case RegistryOperation::RenameKey: return "RenameKey";
        case RegistryOperation::EnumerateKey: return "EnumerateKey";
        case RegistryOperation::EnumerateValue: return "EnumerateValue";
        case RegistryOperation::QueryValue: return "QueryValue";
        case RegistryOperation::SetKeySecurity: return "SetKeySecurity";
        case RegistryOperation::QueryKeySecurity: return "QueryKeySecurity";
        case RegistryOperation::FlushKey: return "FlushKey";
        case RegistryOperation::LoadKey: return "LoadKey";
        case RegistryOperation::UnloadKey: return "UnloadKey";
        case RegistryOperation::SaveKey: return "SaveKey";
        case RegistryOperation::RestoreKey: return "RestoreKey";
        default: return "Unknown";
    }
}

std::string_view GetProtectionTypeName(KeyProtectionType type) noexcept {
    switch (type) {
        case KeyProtectionType::None: return "None";
        case KeyProtectionType::ReadOnly: return "ReadOnly";
        case KeyProtectionType::NoDelete: return "NoDelete";
        case KeyProtectionType::NoModify: return "NoModify";
        case KeyProtectionType::Full: return "Full";
        case KeyProtectionType::ValuesOnly: return "ValuesOnly";
        case KeyProtectionType::Custom: return "Custom";
        default: return "Unknown";
    }
}

std::string_view GetIntegrityStatusName(IntegrityStatus status) noexcept {
    switch (status) {
        case IntegrityStatus::Unknown: return "Unknown";
        case IntegrityStatus::Valid: return "Valid";
        case IntegrityStatus::Modified: return "Modified";
        case IntegrityStatus::Missing: return "Missing";
        case IntegrityStatus::Corrupted: return "Corrupted";
        case IntegrityStatus::New: return "New";
        case IntegrityStatus::Restored: return "Restored";
        default: return "Unknown";
    }
}

std::string_view GetValueTypeName(RegistryValueType type) noexcept {
    switch (type) {
        case RegistryValueType::None: return "REG_NONE";
        case RegistryValueType::String: return "REG_SZ";
        case RegistryValueType::ExpandString: return "REG_EXPAND_SZ";
        case RegistryValueType::Binary: return "REG_BINARY";
        case RegistryValueType::DWord: return "REG_DWORD";
        case RegistryValueType::DWordBigEndian: return "REG_DWORD_BIG_ENDIAN";
        case RegistryValueType::Link: return "REG_LINK";
        case RegistryValueType::MultiString: return "REG_MULTI_SZ";
        case RegistryValueType::ResourceList: return "REG_RESOURCE_LIST";
        case RegistryValueType::FullResourceDesc: return "REG_FULL_RESOURCE_DESCRIPTOR";
        case RegistryValueType::ResourceReqList: return "REG_RESOURCE_REQUIREMENTS_LIST";
        case RegistryValueType::QWord: return "REG_QWORD";
        default: return "Unknown";
    }
}

std::string FormatRegistryOperation(RegistryOperation operation) {
    std::string result;
    const auto ops = static_cast<uint32_t>(operation);

    if (ops & static_cast<uint32_t>(RegistryOperation::QueryKey)) result += "QueryKey|";
    if (ops & static_cast<uint32_t>(RegistryOperation::SetValue)) result += "SetValue|";
    if (ops & static_cast<uint32_t>(RegistryOperation::DeleteValue)) result += "DeleteValue|";
    if (ops & static_cast<uint32_t>(RegistryOperation::CreateKey)) result += "CreateKey|";
    if (ops & static_cast<uint32_t>(RegistryOperation::DeleteKey)) result += "DeleteKey|";
    if (ops & static_cast<uint32_t>(RegistryOperation::RenameKey)) result += "RenameKey|";
    if (ops & static_cast<uint32_t>(RegistryOperation::SetKeySecurity)) result += "SetKeySecurity|";

    if (!result.empty() && result.back() == '|') {
        result.pop_back();
    }

    return result.empty() ? "None" : result;
}

// ============================================================================
// RAII GUARD IMPLEMENTATION
// ============================================================================

RegistryProtectionGuard::RegistryProtectionGuard(std::wstring_view keyPath, KeyProtectionType type)
    : m_keyPath(keyPath)
    , m_protected(false)
    , m_authToken(std::string(AUTH_TOKEN_PREFIX) + GenerateUniqueId())
{
    m_protected = RegistryProtection::Instance().ProtectKey(keyPath, type, true);
    if (m_protected) {
        SS_LOG_DEBUG(LOG_CATEGORY, L"Guard: Key protected: %ls", m_keyPath.c_str());
    }
}

RegistryProtectionGuard::~RegistryProtectionGuard() {
    if (m_protected) {
        RegistryProtection::Instance().UnprotectKey(m_keyPath, m_authToken);
        SS_LOG_DEBUG(LOG_CATEGORY, L"Guard: Key unprotected: %ls", m_keyPath.c_str());
    }
}

}  // namespace Security
}  // namespace ShadowStrike
