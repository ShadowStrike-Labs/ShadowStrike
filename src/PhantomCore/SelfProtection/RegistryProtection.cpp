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
 * @version 3.1.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, NIST CSF
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "RegistryProtection.hpp"

#include "../Communication/IPCManager.hpp"
#include "../Communication/AlertSystem.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "DigitalSignatureValidator.hpp"

#include <algorithm>
#include <deque>
#include <sstream>
#include <iomanip>
#include <format>
#include <utility>
#include <cwctype>

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
        return Utils::StringUtils::ToNarrow(wide);
    }

    /// @brief Convert narrow string to wide string
    [[nodiscard]] std::wstring NarrowToWide(std::string_view narrow) {
        return Utils::StringUtils::ToWide(narrow);
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
        const auto sysTime = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            std::chrono::system_clock::now() + (tp - Clock::now()));
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
    // INTERNAL STATS (atomic for thread safety; public struct uses uint64_t)
    // ========================================================================

    struct InternalStats {
        std::atomic<uint64_t> totalProtectedKeys{0};
        std::atomic<uint64_t> totalProtectedValues{0};
        std::atomic<uint64_t> totalOperations{0};
        std::atomic<uint64_t> totalBlocked{0};
        std::atomic<uint64_t> totalRollbacks{0};
        std::atomic<uint64_t> totalIntegrityChecks{0};
        std::atomic<uint64_t> integrityViolations{0};
        std::atomic<uint64_t> snapshotsCreated{0};
        std::atomic<uint64_t> snapshotsRestored{0};

        // TimePoints guarded by m_mutex
        TimePoint startTime = Clock::now();
        TimePoint lastEventTime;

        void Reset() noexcept {
            totalProtectedKeys.store(0, std::memory_order_relaxed);
            totalProtectedValues.store(0, std::memory_order_relaxed);
            totalOperations.store(0, std::memory_order_relaxed);
            totalBlocked.store(0, std::memory_order_relaxed);
            totalRollbacks.store(0, std::memory_order_relaxed);
            totalIntegrityChecks.store(0, std::memory_order_relaxed);
            integrityViolations.store(0, std::memory_order_relaxed);
            snapshotsCreated.store(0, std::memory_order_relaxed);
            snapshotsRestored.store(0, std::memory_order_relaxed);
            startTime = Clock::now();
            lastEventTime = TimePoint{};
        }
    };

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

        // Generate cryptographic session secret for auth token verification
        {
            Utils::CryptoUtils::SecureRandom rng;
            m_sessionSecret.resize(32);
            if (!rng.Generate(m_sessionSecret.data(), m_sessionSecret.size())) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to generate session secret");
                m_status = ModuleStatus::Error;
                return false;
            }
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
            if (!IsKeyProtectedInternal(keyPath) &&
                !AddProtectedKeyInternal(keyPath, KeyProtectionType::Full, true)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to add default protected key: %ls", keyPath.c_str());
            }
        }

        // Initialize whitelisted processes
        for (const auto& process : config.whitelistedProcesses) {
            m_whitelistedProcesses.insert(process);
        }

        // Add ShadowStrike processes to whitelist
        m_whitelistedProcesses.insert(L"ShadowStrikePhantomService.exe");
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

        // DESIGN: Keep m_status at Initializing across the kernel-bridge
        // setup. Releasing the lock with status already Running would let a
        // concurrent authorized Shutdown() race in (its own
        // UnregisterKernelHandler() could complete before our
        // RegisterKernelHandler() returns, leaking a kernel registration
        // against torn state). Holding the lock across kernel I/O isn't
        // viable — the filter port can block — so we release the lock,
        // perform kernel I/O, re-acquire, and only then transition to
        // Running after confirming no racing Shutdown occurred.
        lock.unlock();

        const bool kernelSync = SyncProtectedKeysToKernel();
        RegisterKernelHandler();

        lock.lock();

        if (m_status.load() != ModuleStatus::Initializing) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"Initialization aborted - state changed to %d during kernel bridge setup; "
                L"unregistering kernel handler",
                static_cast<int>(m_status.load()));
            lock.unlock();
            UnregisterKernelHandler();
            return false;
        }

        m_status = ModuleStatus::Running;
        SS_LOG_INFO(LOG_CATEGORY, L"Registry protection initialized successfully (kernel sync %s)",
            kernelSync ? L"ok" : L"unavailable");
        SS_LOG_INFO(LOG_CATEGORY, L"Protected keys: %llu, Mode: %hs",
            m_stats.totalProtectedKeys.load(std::memory_order_relaxed),
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

        // Stop monitoring thread (release lock first - StopMonitoring joins thread)
        lock.unlock();
        StopMonitoring();

        // Unregister kernel handler BEFORE clearing state to prevent use-after-free
        UnregisterKernelHandler();

        lock.lock();

        // Clear protected keys
        m_protectedKeys.clear();
        m_protectedValues.clear();
        m_snapshots.clear();

        // Clear callbacks
        m_eventCallbacks.clear();
        m_integrityCallbacks.clear();
        m_valueChangeCallbacks.clear();
        m_decisionCallback = nullptr;

        // Securely wipe session secret
        if (!m_sessionSecret.empty()) {
            SecureZeroMemory(m_sessionSecret.data(), m_sessionSecret.size());
            m_sessionSecret.clear();
        }

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

        bool restartMonitoring = false;
        {
            std::unique_lock lock(m_mutex);

            // Capture old interval BEFORE overwriting config
            const auto oldPollingInterval = m_config.pollingIntervalMs;

            m_config = config;
            m_mode = config.mode;

            // Check if monitoring needs restart (decided under lock, executed outside)
            if (m_monitoringActive &&
                config.pollingIntervalMs != oldPollingInterval) {
                restartMonitoring = true;
            }
        }
        // Lock released — safe to join/launch monitor thread (fixes DEADLOCK)
        if (restartMonitoring) {
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
        if (!AddProtectedKeyInternal(keyPath, KeyProtectionType::Full, true)) {
            SS_LOG_WARN(LOG_CATEGORY, L"ProtectKey default request failed: %ls", keyPath.c_str());
        }
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
        // Guard against underflow
        const auto prev = m_stats.totalProtectedKeys.load(std::memory_order_relaxed);
        if (prev > 0) {
            m_stats.totalProtectedKeys.fetch_sub(1, std::memory_order_relaxed);
        }

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
        success &= ProtectKey(L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrikePhantomService",
            KeyProtectionType::Full, true);
        success &= ProtectKey(L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\PhantomSensor",
            KeyProtectionType::Full, true);

        // Configuration keys
        success &= ProtectKey(L"HKLM\\SOFTWARE\\ShadowStrike",
            KeyProtectionType::Full, true);
        success &= ProtectKey(L"HKCU\\SOFTWARE\\ShadowStrike",
            KeyProtectionType::Full, true);

        // Safe boot entries
        success &= ProtectKey(
            L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\ShadowStrikePhantomService",
            KeyProtectionType::Full, true);
        success &= ProtectKey(
            L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\ShadowStrikePhantomService",
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

    [[nodiscard]] bool ProtectIFEOKeys() {
        SS_LOG_INFO(LOG_CATEGORY, L"Protecting IFEO (Image File Execution Options) keys...");

        bool success = true;

        // IFEO debugger keys for ShadowStrike executables - critical EDR evasion vector
        static constexpr std::array<std::wstring_view, 3> kExecutables = {
            L"ShadowStrikePhantomService.exe",
            L"ShadowStrikeUI.exe",
            L"ShadowStrikeUpdater.exe"
        };

        constexpr std::wstring_view kIFEOBase =
            L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            L"\\Image File Execution Options\\";

        for (const auto& exe : kExecutables) {
            const std::wstring ifeoPath = std::wstring(kIFEOBase) + std::wstring(exe);
            success &= ProtectKey(ifeoPath, KeyProtectionType::Full, true);
        }

        if (success) {
            SS_LOG_INFO(LOG_CATEGORY, L"IFEO keys protected successfully");
        } else {
            SS_LOG_WARN(LOG_CATEGORY, L"Some IFEO keys failed to protect");
        }

        return success;
    }

    [[nodiscard]] bool HardenKeyDACL(std::wstring_view keyPath) {
        const auto normalized = NormalizeKeyPath(keyPath);

        HKEY rootKey = nullptr;
        std::wstring subKey;
        if (!Utils::RegistryUtils::SplitPath(normalized, rootKey, subKey)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"HardenKeyDACL: Invalid key path: %ls",
                normalized.c_str());
            return false;
        }

        // Open key with WRITE_DAC access to modify its security
        Utils::RegistryUtils::RegistryKey regKey;
        Utils::RegistryUtils::OpenOptions opts;
        opts.access = WRITE_DAC | READ_CONTROL;

        if (!regKey.Open(rootKey, subKey, opts)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"HardenKeyDACL: Cannot open key: %ls",
                normalized.c_str());
            return false;
        }

        // Build a restrictive SDDL security descriptor:
        //  Owner: SYSTEM
        //  DACL:
        //    Allow Full Control to SYSTEM (SY)
        //    Allow Full Control to Administrators (BA)
        //    Allow Read to Authenticated Users (AU)
        //    Deny Write/Delete to Everyone (WO) except SYSTEM/Admins
        constexpr const wchar_t* kSddl =
            L"D:P"
            L"(A;;KA;;;SY)"      // SYSTEM: full control
            L"(A;;KA;;;BA)"      // Builtin Administrators: full control
            L"(A;;KR;;;AU)"      // Authenticated Users: read only
            L"(D;;WDWOSDDTKAWP;;;WD)";  // Everyone: deny write/delete/take-ownership/change-perms

        PSECURITY_DESCRIPTOR pSD = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                kSddl, SDDL_REVISION_1, &pSD, nullptr)) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"HardenKeyDACL: Failed to parse SDDL (error=%lu)", GetLastError());
            return false;
        }

        // RAII cleanup for the security descriptor
        struct SDDeleter {
            void operator()(void* p) const noexcept { if (p) LocalFree(p); }
        };
        std::unique_ptr<void, SDDeleter> sdGuard(pSD);

        // Extract DACL from security descriptor
        BOOL daclPresent = FALSE;
        PACL pDacl = nullptr;
        BOOL daclDefaulted = FALSE;
        if (!GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted)
            || !daclPresent || !pDacl) {
            SS_LOG_ERROR(LOG_CATEGORY, L"HardenKeyDACL: Failed to extract DACL");
            return false;
        }

        // Apply DACL to the registry key
        const DWORD result = RegSetKeySecurity(regKey.Handle(),
            DACL_SECURITY_INFORMATION, pSD);

        if (result != ERROR_SUCCESS) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"HardenKeyDACL: RegSetKeySecurity failed (error=%lu) on: %ls",
                result, normalized.c_str());
            return false;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"DACL hardened for: %ls", normalized.c_str());
        return true;
    }

    [[nodiscard]] std::string GenerateAuthorizationToken() const {
        return ComputeAuthToken();
    }

    // ========================================================================
    // VALUE PROTECTION
    // ========================================================================

    [[nodiscard]] bool ProtectValue(std::wstring_view keyPath, std::wstring_view valueName) {
        if (keyPath.empty() || valueName.empty()) {
            return false;
        }

        ProtectedValue pv;
        pv.id = GenerateUniqueId();
        pv.keyPath = keyPath;
        pv.valueName = valueName;
        pv.protectedSince = Clock::now();
        pv.integrity = RegistryIntegrityStatus::Unknown;

        // Registry I/O OUTSIDE lock to avoid blocking readers
        if (ReadValueAndComputeHash(pv)) {
            pv.integrity = RegistryIntegrityStatus::Valid;
        }

        const auto key = std::wstring(keyPath) + L"\\" + std::wstring(valueName);
        {
            std::unique_lock lock(m_mutex);
            m_protectedValues[key] = std::move(pv);
        }
        m_stats.totalProtectedValues.fetch_add(1, std::memory_order_relaxed);

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
        const auto prev = m_stats.totalProtectedValues.load(std::memory_order_relaxed);
        if (prev > 0) {
            m_stats.totalProtectedValues.fetch_sub(1, std::memory_order_relaxed);
        }
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
        return decision.decision == RegistryOperationDecision::Allow ||
               decision.decision == RegistryOperationDecision::AllowLogged;
    }

    [[nodiscard]] RegistryOperationDecisionResult FilterOperation(const RegistryOperationRequest& request) {
        RegistryOperationDecisionResult result;
        result.decision = RegistryOperationDecision::Allow;

        m_stats.totalOperations.fetch_add(1, std::memory_order_relaxed);

        // Check if protection is disabled
        if (m_mode == RegistryProtectionMode::Disabled) {
            return result;
        }

        // Check if process is whitelisted
        if (IsProcessWhitelisted(request.processId)) {
            result.decision = RegistryOperationDecision::AllowLogged;
            result.reason = "Process is whitelisted";
            return result;
        }

        // Snapshot every piece of shared state this decision needs under ONE
        // lock acquisition, then release it before invoking anything a caller
        // registered. m_mutex is a std::shared_mutex and is NOT recursive: a
        // decision callback that calls back into this module - AddProtectedKey,
        // SetDecisionCallback, IsKeyProtected, GetStatistics - acquires m_mutex a
        // second time, and if a writer has queued between the two acquisitions
        // the shared re-acquisition waits behind that writer while this frame
        // still holds the first. That is a self-deadlock on a thread that may owe
        // the kernel a registry verdict.
        //
        // The previous code invoked the callback INSIDE the lock, under a comment
        // asserting it was "now safely under lock". This same function already
        // knew better: its blocked-operation branch below deliberately dropped
        // the lock before firing FireBlockedOperationEvent, for exactly this
        // reason. FileProtection::FilterOperation and BackupProtector's
        // QueryDecision both snapshot for the same reason.
        //
        // The protected-key lookup now always runs, even when the callback goes
        // on to answer and its result is discarded. That is the deliberate cost
        // of keeping this to a single lock cycle, and it is a hash lookup.
        RegistryOperationDecisionCallback callbackCopy;
        bool keyIsProtected = false;
        uint32_t blockedOps = 0;

        {
            std::shared_lock lock(m_mutex);

            callbackCopy = m_decisionCallback;

            if (IsKeyProtectedInternal(request.keyPath)) {
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

                if (keyIt != m_protectedKeys.end()) {
                    keyIsProtected = true;
                    blockedOps = static_cast<uint32_t>(keyIt->second.blockedOperations);
                }
            }
        }

        // Consult the caller's decision hook FIRST and honour whatever answer it
        // gives, exactly as before - only now with no lock held. An engaged
        // optional wins outright, including a deliberate Allow.
        if (callbackCopy) {
            auto customResult = callbackCopy(request);
            if (customResult.has_value()) {
                return customResult.value();
            }
        }

        if (!keyIsProtected) {
            return result;
        }

        // Check if operation is blocked
        const auto reqOp = static_cast<uint32_t>(request.operation);

        if ((blockedOps & reqOp) != 0) {
            result.decision = RegistryOperationDecision::Block;
            result.reason = "Operation blocked by protection policy";
            result.shouldLog = true;
            result.shouldAlert = true;

            if (m_mode == RegistryProtectionMode::Rollback) {
                result.shouldRollback = true;
                result.shouldSnapshot = true;
            }

            m_stats.totalBlocked.fetch_add(1, std::memory_order_relaxed);

            // No lock is held here at all now, so neither this event fan-out nor
            // the decision callback above can re-enter the module and self-block.
            FireBlockedOperationEvent(request, result);
        } else if (m_mode == RegistryProtectionMode::Monitor) {
            result.decision = RegistryOperationDecision::AllowLogged;
            result.shouldLog = true;
        }

        return result;
    }

    void SetDecisionCallback(RegistryOperationDecisionCallback callback) {
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

    [[nodiscard]] RegistryIntegrityStatus VerifyKeyIntegrity(std::wstring_view keyPath) {
        const auto normalized = NormalizeKeyPath(keyPath);

        // Gather key info under shared lock, then do I/O outside
        HKEY rootKey = nullptr;
        std::wstring subKey;
        bool found = false;
        {
            std::shared_lock lock(m_mutex);
            auto it = m_protectedKeys.find(normalized);
            if (it == m_protectedKeys.end()) {
                return RegistryIntegrityStatus::Unknown;
            }
            found = true;
        }

        m_stats.totalIntegrityChecks.fetch_add(1, std::memory_order_relaxed);

        // Registry I/O OUTSIDE lock
        if (!Utils::RegistryUtils::SplitPath(normalized, rootKey, subKey)) {
            std::unique_lock lock(m_mutex);
            auto it = m_protectedKeys.find(normalized);
            if (it != m_protectedKeys.end()) {
                it->second.integrity = RegistryIntegrityStatus::Missing;
            }
            return RegistryIntegrityStatus::Missing;
        }

        Utils::RegistryUtils::RegistryKey regKey;
        Utils::RegistryUtils::OpenOptions opts;
        opts.access = KEY_READ;

        if (!regKey.Open(rootKey, subKey, opts)) {
            // A protected key that cannot be opened is only a TAMPER event if it
            // was previously observed present (baselined). Many protected keys are
            // DEFENSIVE — Image File Execution Options and SafeBoot service entries
            // we guard so an attacker cannot CREATE them — whose ABSENCE is the
            // healthy, expected state. Treating "key does not exist" as a violation
            // produced a perpetual false-positive loop (RegOpenKeyExW code=2 on
            // every poll), which wasted CPU, spammed the log, and raised bogus
            // tamper alerts. Only flag when a key that was Valid on a prior check
            // has now disappeared; otherwise its absence is benign.
            ProtectedKey keyCopy;
            bool wasBaselined = false;
            {
                std::unique_lock lock(m_mutex);
                auto it = m_protectedKeys.find(normalized);
                if (it != m_protectedKeys.end()) {
                    wasBaselined = (it->second.integrity == RegistryIntegrityStatus::Valid);
                    it->second.integrity = wasBaselined
                        ? RegistryIntegrityStatus::Missing
                        : RegistryIntegrityStatus::Unknown;
                    if (wasBaselined) {
                        keyCopy = it->second;  // Copy BEFORE unlock
                    }
                }
            }
            if (!wasBaselined) {
                // Never-present / defensive key: absence is not tampering.
                return RegistryIntegrityStatus::Unknown;
            }
            m_stats.integrityViolations.fetch_add(1, std::memory_order_relaxed);
            // Fire callback outside lock, using safe copy
            FireIntegrityCallback(keyCopy);
            return RegistryIntegrityStatus::Missing;
        }

        {
            std::unique_lock lock(m_mutex);
            auto it = m_protectedKeys.find(normalized);
            if (it != m_protectedKeys.end()) {
                it->second.integrity = RegistryIntegrityStatus::Valid;
                it->second.lastVerified = Clock::now();
            }
        }
        return RegistryIntegrityStatus::Valid;
    }

    [[nodiscard]] RegistryIntegrityStatus VerifyValueIntegrity(std::wstring_view keyPath,
                                                       std::wstring_view valueName) {
        const auto compositeKey = std::wstring(keyPath) + L"\\" + std::wstring(valueName);

        // Copy protected value snapshot under shared lock for I/O outside lock
        ProtectedValue snapshot;
        Hash256 expectedHash{};
        {
            std::shared_lock lock(m_mutex);
            auto it = m_protectedValues.find(compositeKey);
            if (it == m_protectedValues.end()) {
                return RegistryIntegrityStatus::Unknown;
            }
            snapshot = it->second;
            expectedHash = it->second.expectedHash;
        }

        m_stats.totalIntegrityChecks.fetch_add(1, std::memory_order_relaxed);

        // Registry I/O OUTSIDE lock
        ProtectedValue currentValue = snapshot;
        if (!ReadValueAndComputeHash(currentValue)) {
            m_stats.integrityViolations.fetch_add(1, std::memory_order_relaxed);
            std::unique_lock lock(m_mutex);
            auto it = m_protectedValues.find(compositeKey);
            if (it != m_protectedValues.end()) {
                it->second.integrity = RegistryIntegrityStatus::Missing;
                it->second.lastVerified = Clock::now();
            }
            return RegistryIntegrityStatus::Missing;
        }

        if (currentValue.currentHash != expectedHash) {
            m_stats.integrityViolations.fetch_add(1, std::memory_order_relaxed);
            ProtectedValue valueCopy;
            std::vector<uint8_t> oldData, newData;
            {
                std::unique_lock lock(m_mutex);
                auto it = m_protectedValues.find(compositeKey);
                if (it != m_protectedValues.end()) {
                    it->second.integrity = RegistryIntegrityStatus::Modified;
                    it->second.currentHash = currentValue.currentHash;
                    it->second.modificationCount++;
                    it->second.lastVerified = Clock::now();
                    oldData = it->second.expectedData;
                    newData = currentValue.expectedData;
                    valueCopy = it->second;
                }
            }
            FireValueChangeCallback(valueCopy, oldData, newData);
            return RegistryIntegrityStatus::Modified;
        }

        {
            std::unique_lock lock(m_mutex);
            auto it = m_protectedValues.find(compositeKey);
            if (it != m_protectedValues.end()) {
                it->second.integrity = RegistryIntegrityStatus::Valid;
                it->second.lastVerified = Clock::now();
            }
        }
        return RegistryIntegrityStatus::Valid;
    }

    [[nodiscard]] std::vector<std::pair<std::wstring, RegistryIntegrityStatus>> VerifyAllIntegrity() {
        std::vector<std::pair<std::wstring, RegistryIntegrityStatus>> results;

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
        if (!CreateSnapshotInternal(normalized)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Baseline update could not create snapshot: %ls", normalized.c_str());
        }

        it->second.integrity = RegistryIntegrityStatus::Valid;
        it->second.lastVerified = Clock::now();

        SS_LOG_INFO(LOG_CATEGORY, L"Key baseline updated: %ls", normalized.c_str());
        return true;
    }

    [[nodiscard]] bool UpdateValueBaseline(std::wstring_view keyPath, std::wstring_view valueName,
                                           std::string_view authorizationToken) {
        if (!VerifyAuthToken(authorizationToken)) {
            return false;
        }

        const auto compositeKey = std::wstring(keyPath) + L"\\" + std::wstring(valueName);

        // Phase 1: Get a copy of the ProtectedValue for registry I/O
        ProtectedValue pvCopy;
        {
            std::shared_lock lock(m_mutex);
            auto it = m_protectedValues.find(compositeKey);
            if (it == m_protectedValues.end()) {
                return false;
            }
            pvCopy = it->second;
        }

        // Phase 2: Read current value from registry (no lock held)
        if (!ReadValueAndComputeHash(pvCopy)) {
            return false;
        }

        // Phase 3: Write updated baseline under exclusive lock
        {
            std::unique_lock lock(m_mutex);
            auto it = m_protectedValues.find(compositeKey);
            if (it == m_protectedValues.end()) {
                return false;
            }
            it->second.currentHash   = pvCopy.currentHash;
            it->second.expectedHash  = pvCopy.currentHash;
            it->second.expectedData  = std::move(pvCopy.expectedData);
            it->second.valueType     = pvCopy.valueType;
            it->second.dataSize      = pvCopy.dataSize;
            it->second.integrity     = RegistryIntegrityStatus::Valid;
            it->second.lastVerified  = Clock::now();
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Value baseline updated: %ls\\%ls",
            std::wstring(keyPath).c_str(), std::wstring(valueName).c_str());
        return true;
    }

    void ForceIntegrityCheck() {
        SS_LOG_INFO(LOG_CATEGORY, L"Forcing integrity check on all protected keys...");

        const auto results = VerifyAllIntegrity();

        size_t violations = 0;
        for (const auto& [path, status] : results) {
            if (status != RegistryIntegrityStatus::Valid && status != RegistryIntegrityStatus::Unknown) {
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
        // Phase 1: Copy snapshot data under lock (avoid holding lock during I/O)
        struct RestoreEntry {
            std::wstring name;
            std::vector<uint8_t> data;
            RegistryValueType type;
        };
        std::vector<RestoreEntry> entriesToRestore;
        std::wstring normalized;
        uint32_t restoredVersion = 0;
        {
            std::shared_lock lock(m_mutex);
            normalized = NormalizeKeyPath(keyPath);

            auto it = m_snapshots.find(normalized);
            if (it == m_snapshots.end() || it->second.empty()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"No snapshots available for: %ls", normalized.c_str());
                return false;
            }

            const auto& snapshots = it->second;
            const KeySnapshot* snapshotToRestore = nullptr;

            if (version == 0) {
                snapshotToRestore = &snapshots.back();
            } else {
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

            restoredVersion = snapshotToRestore->version;
            entriesToRestore.reserve(snapshotToRestore->values.size());
            for (size_t i = 0; i < snapshotToRestore->values.size(); ++i) {
                if (i >= snapshotToRestore->valueTypes.size()) {
                    SS_LOG_ERROR(LOG_CATEGORY,
                        L"Snapshot corrupt: valueTypes shorter than values at index %zu", i);
                    return false;
                }
                RestoreEntry entry;
                entry.name = snapshotToRestore->values[i].first;
                entry.data = snapshotToRestore->values[i].second;
                entry.type = snapshotToRestore->valueTypes[i].second;
                entriesToRestore.push_back(std::move(entry));
            }
        }
        // Lock released — safe to perform registry I/O

        // Phase 2: Write to registry without holding lock
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
        for (const auto& entry : entriesToRestore) {
            const LSTATUS st = RegSetValueExW(regKey.Handle(), entry.name.c_str(), 0,
                static_cast<DWORD>(entry.type), entry.data.data(),
                static_cast<DWORD>(entry.data.size()));

            if (st != ERROR_SUCCESS) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to restore value: %ls (error=%lu)",
                    entry.name.c_str(), st);
                success = false;
            }
        }

        if (success) {
            m_stats.snapshotsRestored.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(LOG_CATEGORY, L"Snapshot restored for: %ls (version=%u)",
                normalized.c_str(), restoredVersion);
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
        // Phase 1: Copy needed data under shared lock
        std::wstring pvKeyPath;
        std::wstring pvValueName;
        std::vector<uint8_t> expectedData;
        RegistryValueType valueType;
        Hash256 expectedHash;
        std::wstring compositeKey;
        {
            std::shared_lock lock(m_mutex);
            compositeKey = std::wstring(keyPath) + L"\\" + std::wstring(valueName);

            auto it = m_protectedValues.find(compositeKey);
            if (it == m_protectedValues.end()) {
                return false;
            }

            const auto& pv = it->second;
            if (pv.expectedData.empty()) {
                SS_LOG_WARN(LOG_CATEGORY, L"No baseline data for value: %ls", compositeKey.c_str());
                return false;
            }

            pvKeyPath    = pv.keyPath;
            pvValueName  = pv.valueName;
            expectedData = pv.expectedData;
            valueType    = pv.valueType;
            expectedHash = pv.expectedHash;
        }
        // Lock released — safe for registry I/O

        // Phase 2: Write to registry without holding lock
        HKEY rootKey = nullptr;
        std::wstring subKey;
        if (!Utils::RegistryUtils::SplitPath(pvKeyPath, rootKey, subKey)) {
            return false;
        }

        Utils::RegistryUtils::RegistryKey regKey;
        Utils::RegistryUtils::OpenOptions opts;
        opts.access = KEY_SET_VALUE;

        if (!regKey.Open(rootKey, subKey, opts)) {
            return false;
        }

        const LSTATUS st = RegSetValueExW(regKey.Handle(), pvValueName.c_str(), 0,
            static_cast<DWORD>(valueType), expectedData.data(),
            static_cast<DWORD>(expectedData.size()));

        if (st != ERROR_SUCCESS) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to rollback value: %ls (error=%lu)",
                compositeKey.c_str(), st);
            return false;
        }

        // Phase 3: Update state under exclusive lock
        m_stats.totalRollbacks.fetch_add(1, std::memory_order_relaxed);
        {
            std::unique_lock lock(m_mutex);
            auto it = m_protectedValues.find(compositeKey);
            if (it != m_protectedValues.end()) {
                it->second.integrity = RegistryIntegrityStatus::Restored;
                it->second.currentHash = expectedHash;
            }
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Value rolled back: %ls", compositeKey.c_str());
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
        for (const auto& whitelisted : m_whitelistedProcesses) {
            if (Utils::StringUtils::IEquals(processName, whitelisted)) {
                return true;
            }
        }
        return false;
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

    [[nodiscard]] uint64_t RegisterIntegrityCallback(RegistryIntegrityCallback callback) {
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
        RegistryProtectionStatistics result;
        result.totalProtectedKeys = m_stats.totalProtectedKeys.load(std::memory_order_relaxed);
        result.totalProtectedValues = m_stats.totalProtectedValues.load(std::memory_order_relaxed);
        result.totalOperations = m_stats.totalOperations.load(std::memory_order_relaxed);
        result.totalBlocked = m_stats.totalBlocked.load(std::memory_order_relaxed);
        result.totalRollbacks = m_stats.totalRollbacks.load(std::memory_order_relaxed);
        result.totalIntegrityChecks = m_stats.totalIntegrityChecks.load(std::memory_order_relaxed);
        result.integrityViolations = m_stats.integrityViolations.load(std::memory_order_relaxed);
        result.snapshotsCreated = m_stats.snapshotsCreated.load(std::memory_order_relaxed);
        result.snapshotsRestored = m_stats.snapshotsRestored.load(std::memory_order_relaxed);
        {
            std::shared_lock lock(m_mutex);
            result.startTime = m_stats.startTime;
            result.lastEventTime = m_stats.lastEventTime;
        }
        return result;
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
        json << "  \"statistics\": " << GetStatistics().ToJson() << ",\n";

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

        // Case-insensitive root key normalization
        // Extract root segment (everything before first backslash)
        const auto slashPos = result.find(L'\\');
        std::wstring rootSegment = (slashPos != std::wstring::npos)
            ? result.substr(0, slashPos)
            : result;

        // Convert root segment to uppercase for comparison
        std::wstring rootUpper = rootSegment;
        for (auto& ch : rootUpper) {
            ch = static_cast<wchar_t>(towupper(ch));
        }

        if (rootUpper == L"HKEY_LOCAL_MACHINE" || rootUpper == L"HKLM") {
            result.replace(0, rootSegment.size(), L"HKLM");
        } else if (rootUpper == L"HKEY_CURRENT_USER" || rootUpper == L"HKCU") {
            result.replace(0, rootSegment.size(), L"HKCU");
        } else if (rootUpper == L"HKEY_CLASSES_ROOT" || rootUpper == L"HKCR") {
            result.replace(0, rootSegment.size(), L"HKCR");
        } else if (rootUpper == L"HKEY_USERS" || rootUpper == L"HKU") {
            result.replace(0, rootSegment.size(), L"HKU");
        } else if (rootUpper == L"HKEY_CURRENT_CONFIG" || rootUpper == L"HKCC") {
            result.replace(0, rootSegment.size(), L"HKCC");
        }

        // Case-fold the entire subkey path (registry paths are case-insensitive)
        // Without this, an attacker can bypass protection via alternate casing
        if (slashPos != std::wstring::npos && slashPos + 1 < result.size()) {
            for (size_t i = slashPos + 1; i < result.size(); ++i) {
                result[i] = static_cast<wchar_t>(towlower(result[i]));
            }
        }

        // Remove trailing backslash
        while (!result.empty() && result.back() == L'\\') {
            result.pop_back();
        }

        return result;
    }

    [[nodiscard]] static HKEY ParseRootKey(std::wstring_view keyPath) {
        // Normalize first for consistent comparison
        const auto normalized = NormalizeKeyPath(keyPath);
        if (normalized.starts_with(L"HKLM\\") || normalized == L"HKLM") {
            return HKEY_LOCAL_MACHINE;
        }
        if (normalized.starts_with(L"HKCU\\") || normalized == L"HKCU") {
            return HKEY_CURRENT_USER;
        }
        if (normalized.starts_with(L"HKCR\\") || normalized == L"HKCR") {
            return HKEY_CLASSES_ROOT;
        }
        if (normalized.starts_with(L"HKU\\") || normalized == L"HKU") {
            return HKEY_USERS;
        }
        if (normalized.starts_with(L"HKCC\\") || normalized == L"HKCC") {
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
        pk.integrity = RegistryIntegrityStatus::Unknown;

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
        m_stats.totalProtectedKeys.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_INFO(LOG_CATEGORY, L"Key protected: %ls (type=%hs, subkeys=%s)",
            normalized.c_str(), std::string(GetProtectionTypeName(type)).c_str(),
            includeSubkeys ? L"yes" : L"no");

        // Create initial snapshot if enabled
        if (m_config.enableSnapshots && !CreateSnapshotInternal(normalized)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Initial snapshot creation failed for key: %ls", normalized.c_str());
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

        // Set version number using monotonic counter (survives pruning)
        auto& snapshots = m_snapshots[normalized];
        snapshot.version = m_nextSnapshotVersion.fetch_add(1, std::memory_order_relaxed) + 1;

        // Limit snapshot count
        while (snapshots.size() >= m_config.maxSnapshotsPerKey) {
            snapshots.erase(snapshots.begin());
        }

        const auto savedVersion = snapshot.version;
        snapshots.push_back(std::move(snapshot));
        m_stats.snapshotsCreated.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_DEBUG(LOG_CATEGORY, L"Snapshot created for: %ls (version=%u)",
            normalized.c_str(), savedVersion);

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

        // Cap data size to prevent DoS from maliciously large registry values
        constexpr size_t MAX_REGISTRY_DATA_READ = 1u << 20; // 1 MB
        if (data.size() > MAX_REGISTRY_DATA_READ) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"Registry value exceeds safety cap (%zu bytes): %ls\\%ls",
                data.size(), pv.keyPath.c_str(), pv.valueName.c_str());
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
        const auto processInfo = GetProcessInfoFromPid(processId);
        if (processInfo.first.empty()) {
            return false;
        }

        // Check whitelist under shared lock, copy match result before unlock
        bool nameMatched = false;
        {
            std::shared_lock lock(m_mutex);
            for (const auto& whitelisted : m_whitelistedProcesses) {
                if (Utils::StringUtils::IEquals(processInfo.first, whitelisted)) {
                    nameMatched = true;
                    break;
                }
            }
        }
        // Lock released here by RAII — safe for I/O below

        if (!nameMatched) {
            return false;
        }

        // Verify code signature to prevent whitelist bypass via name spoofing.
        // An attacker can rename any executable to match a whitelisted name;
        // without signature verification this would bypass all registry protection.
        try {
            auto& validator = Security::DigitalSignatureValidator::Instance();
            auto sigInfo = validator.VerifyFile(processInfo.second);
            if (!sigInfo.isValid) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"Whitelist bypass attempt: process '%ls' (PID %u) matches name but has invalid signature",
                    processInfo.second.c_str(), processId);
                return false;
            }
        } catch (...) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"Signature verification failed for whitelisted process '%ls' (PID %u), denying whitelist",
                processInfo.second.c_str(), processId);
            return false;
        }
        return true;
    }

    /// @brief Returns {processName, fullPath} from PID with RAII handle management
    [[nodiscard]] static std::pair<std::wstring, std::wstring> GetProcessInfoFromPid(
        uint32_t processId) {
        // RAII handle wrapper - automatically closes on all exit paths
        struct HandleCloser {
            void operator()(HANDLE h) const noexcept {
                if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
            }
        };
        std::unique_ptr<void, HandleCloser> hProcess(
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
        if (!hProcess) {
            return {};
        }

        wchar_t path[MAX_PATH] = {};
        DWORD size = MAX_PATH;

        if (!QueryFullProcessImageNameW(hProcess.get(), 0, path, &size)) {
            return {};
        }

        const std::wstring fullPath(path, size);
        const auto pos = fullPath.rfind(L'\\');
        std::wstring name = (pos != std::wstring::npos)
            ? fullPath.substr(pos + 1) : fullPath;

        return {std::move(name), fullPath};
    }

    /// @brief Legacy API adapter
    [[nodiscard]] static std::wstring GetProcessNameFromPid(uint32_t processId) {
        return GetProcessInfoFromPid(processId).first;
    }

    [[nodiscard]] bool VerifyAuthToken(std::string_view token) const {
        // SECURITY: Avoid short-circuiting on empty/prefix mismatch. We must
        // perform the same HMAC computation and constant-time compare in all
        // cases so an attacker cannot use timing to learn anything about
        // the expected token's length, prefix, or whether the session secret
        // has been initialized. The fixed-cost paths still reject invalid
        // input — they just refuse to leak side-channel information about
        // why.
        const std::string expected = ComputeAuthToken();

        // Constant-time comparison: XOR-fold both lengths into the accumulator
        // to avoid early-exit length oracle that leaks expected token length.
        const size_t maxLen = std::max(token.size(), expected.size());
        volatile uint8_t accumulator = static_cast<uint8_t>(token.size() ^ expected.size());
        for (size_t i = 0; i < maxLen; ++i) {
            const uint8_t a = (i < token.size())
                ? static_cast<uint8_t>(token[i]) : 0;
            const uint8_t b = (i < expected.size())
                ? static_cast<uint8_t>(expected[i]) : 0;
            accumulator |= (a ^ b);
        }
        const bool match = (accumulator == 0);

        // Reject on per-instance invariants that cannot serve as input oracles:
        // an empty session secret (CSPRNG failure or post-shutdown wipe) makes
        // every comparison invalid, and an unexpectedly empty expected token
        // means HMAC computation failed.
        return match && !m_sessionSecret.empty() && !expected.empty();
    }

    [[nodiscard]] std::string ComputeAuthToken() const {
        if (m_sessionSecret.empty()) {
            return {};
        }

        static constexpr std::string_view kPurpose = "ShadowStrike_Registry_Auth";

        Utils::HashUtils::Hmac hmac(Utils::HashUtils::Algorithm::SHA256);
        if (!hmac.Init(m_sessionSecret.data(), m_sessionSecret.size())) {
            return {};
        }
        if (!hmac.Update(kPurpose.data(), kPurpose.size())) {
            return {};
        }
        std::string hexOut;
        if (!hmac.FinalHex(hexOut, false)) {
            return {};
        }

        return std::string(AUTH_TOKEN_PREFIX) + hexOut;
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
        // Get keys and values to check
        std::vector<std::wstring> keysToCheck;
        std::vector<std::pair<std::wstring, std::wstring>> valuesToCheck;
        {
            std::shared_lock lock(m_mutex);
            keysToCheck.reserve(m_protectedKeys.size());
            for (const auto& [path, key] : m_protectedKeys) {
                keysToCheck.push_back(path);
            }
            valuesToCheck.reserve(m_protectedValues.size());
            for (const auto& [compositeKey, pv] : m_protectedValues) {
                valuesToCheck.emplace_back(pv.keyPath, pv.valueName);
            }
        }

        // Check key integrity
        for (const auto& keyPath : keysToCheck) {
            if (m_stopMonitoring) return;

            const auto status = VerifyKeyIntegrity(keyPath);
            if (status != RegistryIntegrityStatus::Valid && status != RegistryIntegrityStatus::Unknown) {
                SS_LOG_WARN(LOG_CATEGORY, L"Integrity violation detected: %ls", keyPath.c_str());

                // Auto-rollback if enabled
                if (m_config.enableAutoRollback && m_mode == RegistryProtectionMode::Rollback) {
                    if (RollbackKey(keyPath)) {
                        SS_LOG_INFO(LOG_CATEGORY, L"Key auto-restored: %ls", keyPath.c_str());
                    }
                }
            }
        }

        // Check value integrity
        for (const auto& [keyPath, valueName] : valuesToCheck) {
            if (m_stopMonitoring) return;

            const auto status = VerifyValueIntegrity(keyPath, valueName);
            if (status == RegistryIntegrityStatus::Modified || status == RegistryIntegrityStatus::Missing) {
                SS_LOG_WARN(LOG_CATEGORY, L"Value integrity violation: %ls\\%ls (status=%hs)",
                    keyPath.c_str(), valueName.c_str(),
                    std::string(GetIntegrityStatusName(status)).c_str());

                if (m_config.enableAutoRollback && m_mode == RegistryProtectionMode::Rollback) {
                    if (RollbackValue(keyPath, valueName)) {
                        SS_LOG_INFO(LOG_CATEGORY, L"Value auto-restored: %ls\\%ls",
                            keyPath.c_str(), valueName.c_str());
                    }
                }
            }
        }
    }

    void FireBlockedOperationEvent(const RegistryOperationRequest& request,
                                   const RegistryOperationDecisionResult& decision) {
        RegistryProtectionEvent event;
        event.eventId = m_nextEventId++;
        event.type = RegistryProtectionEventType::OperationBlocked;
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
                m_eventHistory.pop_front();
            }
            m_stats.lastEventTime = event.timestamp;
        }

        // === Communication wiring: AlertSystem ===
        try {
            if (Communication::AlertSystem::HasInstance()) {
                auto& alertSys = Communication::AlertSystem::Instance();
                const std::string opName(GetRegistryOperationName(event.operation));
                const std::string keyNarrow = WideToNarrow(event.keyPath);
                const std::string procNarrow = WideToNarrow(event.sourceProcessName);

                const std::string subject = "Registry tampering blocked: " + opName
                    + " on " + keyNarrow;
                const std::string details = "PID=" + std::to_string(event.sourceProcessId)
                    + " Process=" + procNarrow
                    + " Key=" + keyNarrow
                    + " Reason=" + event.description;

                const std::string alertId = alertSys.RaiseAlert(
                    Communication::AlertSeverity::High,
                    Communication::AlertType::Security,
                    subject, details, "RegistryProtection");
                if (alertId.empty()) {
                    SS_LOG_WARN(LOG_CATEGORY, L"AlertSystem rejected registry block event alert");
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"AlertSystem dispatch failed: %hs", e.what());
        }

        // === Communication wiring: TelemetryCollector ===
        try {
            if (Communication::TelemetryCollector::HasInstance()) {
                auto& telemetry = Communication::TelemetryCollector::Instance();
                std::map<std::string, std::string> fields;
                fields["event_id"]    = std::to_string(event.eventId);
                fields["operation"]   = std::string(GetRegistryOperationName(event.operation));
                fields["key_path"]    = WideToNarrow(event.keyPath);
                fields["value_name"]  = WideToNarrow(event.valueName);
                fields["process_id"]  = std::to_string(event.sourceProcessId);
                fields["process"]     = WideToNarrow(event.sourceProcessName);
                fields["blocked"]     = "true";
                fields["reason"]      = event.description;
                telemetry.RecordCustom("RegistryProtection.OperationBlocked", fields);
            }
        } catch (const std::exception& e) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"TelemetryCollector dispatch failed: %hs", e.what());
        }

        // Fire registered callbacks
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
        // === Communication wiring: AlertSystem for integrity violations ===
        try {
            if (Communication::AlertSystem::HasInstance()) {
                auto& alertSys = Communication::AlertSystem::Instance();
                const std::string keyNarrow = WideToNarrow(key.keyPath);
                const std::string statusName(GetIntegrityStatusName(key.integrity));

                const std::string alertId = alertSys.RaiseAlert(
                    Communication::AlertSeverity::Critical,
                    Communication::AlertType::Security,
                    "Registry integrity violation: " + keyNarrow,
                    "Key=" + keyNarrow + " Status=" + statusName
                        + " Type=" + std::string(GetProtectionTypeName(key.type)),
                    "RegistryProtection");
                if (alertId.empty()) {
                    SS_LOG_WARN(LOG_CATEGORY, L"AlertSystem rejected registry integrity violation alert");
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"AlertSystem integrity dispatch failed: %hs", e.what());
        }

        // === Communication wiring: TelemetryCollector ===
        try {
            if (Communication::TelemetryCollector::HasInstance()) {
                auto& telemetry = Communication::TelemetryCollector::Instance();
                std::map<std::string, std::string> fields;
                fields["key_path"]   = WideToNarrow(key.keyPath);
                fields["status"]     = std::string(GetIntegrityStatusName(key.integrity));
                fields["protection"] = std::string(GetProtectionTypeName(key.type));
                telemetry.RecordCustom("RegistryProtection.IntegrityViolation", fields);
            }
        } catch (const std::exception& e) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"TelemetryCollector integrity dispatch failed: %hs", e.what());
        }

        // Fire registered callbacks
        std::vector<RegistryIntegrityCallback> callbacks;
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
    // KERNEL BRIDGE METHODS (public — called by forwarding wrappers)
    // ========================================================================
public:

    [[nodiscard]] bool SyncProtectedKeysToKernel() {
        try {
            // Gather keys under shared lock
            std::vector<std::wstring> keys;
            {
                std::shared_lock lock(m_mutex);
                keys.reserve(m_protectedKeys.size());
                for (const auto& [path, _] : m_protectedKeys) {
                    keys.push_back(path);
                }
            }

            if (keys.empty()) {
                SS_LOG_DEBUG(LOG_CATEGORY, L"No registry keys to sync to kernel");
                return true;
            }

            // Build payload: uint32_t count, then count null-terminated wide strings
            uint32_t count = static_cast<uint32_t>(std::min<size_t>(keys.size(), 4096));
            std::vector<uint8_t> payload;
            payload.resize(sizeof(uint32_t));
            std::memcpy(payload.data(), &count, sizeof(count));

            for (uint32_t i = 0; i < count; ++i) {
                const auto& k = keys[i];
                // Sanity cap: skip key paths > 32KB to prevent overflow
                constexpr size_t MAX_KEY_PATH_BYTES = 32768;
                size_t byteLen = (k.size() + 1) * sizeof(wchar_t);
                if (k.size() > MAX_KEY_PATH_BYTES / sizeof(wchar_t) || byteLen > MAX_KEY_PATH_BYTES) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Skipping oversized key path (%zu chars)", k.size());
                    continue;
                }
                size_t offset = payload.size();
                payload.resize(offset + byteLen);
                std::memcpy(payload.data() + offset, k.c_str(), byteLen);
            }

            size_t totalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + payload.size();
            if (totalSize > static_cast<size_t>(UINT32_MAX)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Kernel registry sync payload too large (%zu bytes)", totalSize);
                return false;
            }

            std::vector<uint8_t> message(totalSize, 0);
            auto* header = reinterpret_cast<SHADOWSTRIKE_MESSAGE_HEADER*>(message.data());
            header->Magic       = SHADOWSTRIKE_MESSAGE_MAGIC;
            header->Version     = SHADOWSTRIKE_PROTOCOL_VERSION;
            header->MessageType = static_cast<UINT16>(FilterMessageType_UpdatePolicy);
            header->MessageId   = m_nextEventId.fetch_add(1);
            header->TotalSize   = static_cast<UINT32>(totalSize);
            header->DataSize    = static_cast<UINT32>(payload.size());

            LARGE_INTEGER ts;
            QueryPerformanceCounter(&ts);
            header->Timestamp = ts.QuadPart;
            header->Flags     = 0;

            std::memcpy(message.data() + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
                         payload.data(), payload.size());

            auto& ipc = Communication::IPCManager::Instance();
            bool sent = ipc.SendToKernel(message.data(), message.size());

            if (sent) {
                SS_LOG_INFO(LOG_CATEGORY, L"Synced %u protected registry keys to kernel driver", count);
            } else {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to sync registry keys to kernel (driver may not be loaded)");
            }
            return sent;
        } catch (const std::exception& e) {
            SS_LOG_WARN(LOG_CATEGORY, L"Kernel registry sync exception: %hs", e.what());
            return false;
        }
    }

    void OnKernelRegistryEventInternal(const void* data, size_t size) {
        // Parse RegistryOpRequest from kernel notification
        if (!data || size < sizeof(Communication::RegistryOpRequest)) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"Invalid kernel registry event (size=%zu, min=%zu)",
                size, sizeof(Communication::RegistryOpRequest));
            return;
        }

        const auto* req = static_cast<const Communication::RegistryOpRequest*>(data);

        // Validate variable-length fields individually to prevent integer overflow
        const size_t headerSize = sizeof(Communication::RegistryOpRequest);
        const size_t remaining = size - headerSize;
        if (req->keyPathLength > remaining ||
            req->valueNameLength > remaining - req->keyPathLength ||
            req->dataSize > remaining - req->keyPathLength - req->valueNameLength) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"Kernel registry event truncated (keyPath=%u, valueName=%u, data=%u, avail=%zu)",
                req->keyPathLength, req->valueNameLength, req->dataSize, remaining);
            return;
        }

        // Extract key path safely
        std::wstring keyPath;
        if (req->keyPathLength > 0 && req->keyPathCharLen() > 0) {
            keyPath.assign(req->keyPathData(), req->keyPathCharLen());
        }
        std::wstring valueName;
        if (req->valueNameLength > 0 && req->valueNameCharLen() > 0) {
            valueName.assign(req->valueNameData(), req->valueNameCharLen());
        }

        // Map kernel operation to our RegistryOperation enum
        auto operation = static_cast<RegistryOperation>(req->operation);

        SS_LOG_DEBUG(LOG_CATEGORY,
            L"Kernel registry event: PID=%u Op=%u Key=%ls Value=%ls",
            req->processId, req->operation, keyPath.c_str(), valueName.c_str());

        // Build and dispatch event through our normal event pipeline
        RegistryProtectionEvent event;
        event.eventId = m_nextEventId.fetch_add(1);
        event.operation = operation;
        event.keyPath = std::move(keyPath);
        event.valueName = std::move(valueName);
        event.sourceProcessId = req->processId;
        event.sourceProcessPath = GetProcessNameFromPid(req->processId);
        event.timestamp = Clock::now();

        // DID THE KERNEL ACTUALLY DENY THIS? Until now wasBlocked was hardcoded
        // true and the description hardcoded "Blocked by kernel registry
        // callback" for EVERY event, and totalBlocked was incremented
        // unconditionally alongside totalOperations - so the two counters were
        // always equal and neither could distinguish a denial from an
        // observation. That was invisible while this handler was evicted; it
        // becomes a live false-signal the moment the handler runs, which is why
        // it is corrected in the same change that restores it.
        //
        // The driver reports registry activity it considers notable, not only
        // activity it denied. It denies unconditionally, before notifying, when
        // the target is a protected key and the operation writes
        // (RegistryCallback.c:2007). That is the predicate reproduced here.
        //
        // STATED PRECISELY: this is our own view of the protected set, kept in
        // step with the kernel's by SyncProtectedKeysToKernel. It is a faithful
        // reading of the same rule, not an echo of the kernel's decision - the
        // notification carries no "was denied" bit to read. Where they could
        // disagree, this under-claims rather than over-claims.
        bool denied = false;
        if (!event.keyPath.empty() && IsKeyProtected(event.keyPath)) {
            constexpr auto writeOps = static_cast<uint32_t>(RegistryOperation::AllWrite);
            denied = (static_cast<uint32_t>(operation) & writeOps) != 0;
        }
        event.wasBlocked = denied;
        event.description = denied
            ? "Write to a protected key; denied by the kernel self-protection check"
            : "Registry activity reported by the kernel callback (not denied)";

        m_stats.totalOperations.fetch_add(1, std::memory_order_relaxed);
        if (denied) {
            m_stats.totalBlocked.fetch_add(1, std::memory_order_relaxed);
        }

        // Add to history
        {
            std::unique_lock lock(m_mutex);
            m_eventHistory.push_back(event);
            while (m_eventHistory.size() > MAX_EVENT_HISTORY) {
                m_eventHistory.pop_front();
            }
            m_stats.lastEventTime = event.timestamp;
        }

        // === Communication wiring: AlertSystem for kernel-blocked events ===
        // Gated on `denied`. A Critical alert raised for every reported registry
        // operation would train the reader to ignore Critical, which is the same
        // harm as not alerting at all - and the driver reports far more activity
        // than it denies.
        try {
            if (denied && Communication::AlertSystem::HasInstance()) {
                auto& alertSys = Communication::AlertSystem::Instance();
                const std::string opName(GetRegistryOperationName(event.operation));
                const std::string keyNarrow = WideToNarrow(event.keyPath);

                const std::string alertId = alertSys.RaiseAlert(
                    Communication::AlertSeverity::Critical,
                    Communication::AlertType::Security,
                    "Kernel blocked registry tampering: " + opName + " on " + keyNarrow,
                    "PID=" + std::to_string(event.sourceProcessId)
                        + " Key=" + keyNarrow
                        + " Source=KernelCallback",
                    "RegistryProtection");
                if (alertId.empty()) {
                    SS_LOG_WARN(LOG_CATEGORY, L"AlertSystem rejected kernel registry block alert");
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"AlertSystem kernel event dispatch failed: %hs", e.what());
        }

        // === Communication wiring: TelemetryCollector ===
        try {
            if (Communication::TelemetryCollector::HasInstance()) {
                auto& telemetry = Communication::TelemetryCollector::Instance();
                std::map<std::string, std::string> fields;
                fields["operation"]   = std::string(GetRegistryOperationName(event.operation));
                fields["key_path"]    = WideToNarrow(event.keyPath);
                fields["value_name"]  = WideToNarrow(event.valueName);
                fields["process_id"]  = std::to_string(event.sourceProcessId);
                fields["blocked"]     = "true";
                fields["source"]      = "kernel";
                telemetry.RecordCustom("RegistryProtection.KernelBlock", fields);
            }
        } catch (const std::exception& e) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"TelemetryCollector kernel event dispatch failed: %hs", e.what());
        }

        // Fire callbacks outside lock
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
                SS_LOG_ERROR(LOG_CATEGORY, L"Kernel event callback exception: %hs", e.what());
            }
        }
    }

    void RegisterKernelHandler() {
        try {
            auto& ipc = Communication::IPCManager::Instance();
            // NAMED SUBSCRIPTION, not a slot assignment. Until this was fixed,
            // RegisterRegistryHandler assigned a single member, and
            // RealTimeProtection registered the same slot from Start() - which
            // AntivirusService runs AFTER Impl::Initialize() at all three of its
            // call sites. So this handler was evicted on every startup and
            // everything below it, including the whole event pipeline in
            // OnKernelRegistryEventInternal, never ran once in production.
            ipc.RegisterRegistryHandler("RegistryProtection",
                [this](const Communication::RegistryOpRequest& req) -> SHADOWSTRIKE_SCAN_VERDICT {
                    if (!m_kernelHandlerRegistered.load(std::memory_order_acquire)) {
                        return Verdict_Clean;
                    }
                    OnKernelRegistryEventInternal(&req, sizeof(req)
                        + req.keyPathLength + req.valueNameLength + req.dataSize);

                    // A protected-key WRITE returns Malicious as this module's
                    // vote, and it is combined most-severe-wins with the other
                    // subscribers' verdicts.
                    //
                    // HONEST LIMIT, corrected here: the previous comment claimed
                    // "the kernel will use this to deny the operation
                    // pre-notification". It does not and never did. This path is
                    // reached from a notification the driver sends through
                    // ShadowStrikeSendNotification (CommPort.h:365), which takes
                    // no reply buffer, so the verdict is not transmitted.
                    // ENFORCEMENT IS NOT LOST: the kernel blocks writes to
                    // protected keys itself, unconditionally and before asking
                    // anyone, at RegistryCallback.c:2007
                    // (ShadowStrikeShouldBlockRegistryAccess, commented "not
                    // configurable for security"). What this module contributes
                    // is the user-mode record of the event, which is what the
                    // eviction was actually costing.
                    std::wstring keyPath;
                    if (req.keyPathLength > 0 && req.keyPathCharLen() > 0) {
                        keyPath.assign(req.keyPathData(), req.keyPathCharLen());
                    }
                    if (!keyPath.empty() && IsKeyProtected(keyPath)) {
                        auto operation = static_cast<RegistryOperation>(req.operation);
                        // Only block write operations, not reads
                        constexpr auto writeOps = static_cast<uint32_t>(RegistryOperation::AllWrite);
                        if ((static_cast<uint32_t>(operation) & writeOps) != 0) {
                            return Verdict_Malicious;
                        }
                    }
                    return Verdict_Clean;
                });
            m_kernelHandlerRegistered.store(true, std::memory_order_release);
            SS_LOG_INFO(LOG_CATEGORY, L"Kernel registry handler registered via dedicated dispatch");
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to register kernel handler: %hs", e.what());
        }
    }

    void UnregisterKernelHandler() {
        if (m_kernelHandlerRegistered.load(std::memory_order_acquire)) {
            m_kernelHandlerRegistered.store(false, std::memory_order_release);
            try {
                // Remove ONLY our own subscription. This used to call
                // RegisterRegistryHandler(nullptr), which cleared the whole slot -
                // so this module's shutdown disabled kernel registry dispatch for
                // every other module as a side effect, and self-protection
                // shutdown is exactly what an attacker triggers first.
                auto& ipc = Communication::IPCManager::Instance();
                ipc.UnregisterRegistryHandler("RegistryProtection");
            } catch (...) {
                // Best-effort during shutdown
            }
            SS_LOG_INFO(LOG_CATEGORY, L"Kernel registry handler unregistered");
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================
private:

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
    std::unordered_map<uint64_t, RegistryIntegrityCallback> m_integrityCallbacks;
    std::unordered_map<uint64_t, ValueChangeCallback> m_valueChangeCallbacks;
    RegistryOperationDecisionCallback m_decisionCallback;
    std::atomic<uint64_t> m_nextCallbackId;

    // Events
    std::deque<RegistryProtectionEvent> m_eventHistory;
    std::atomic<uint64_t> m_nextEventId;

    // Statistics (InternalStats has atomics; public API returns plain uint64_t snapshot)
    InternalStats m_stats;

    // Monitoring thread
    std::thread m_monitorThread;
    std::atomic<bool> m_monitoringActive{false};
    std::atomic<bool> m_stopMonitoring{false};

    // Cryptographic session secret for auth token verification
    std::vector<uint8_t> m_sessionSecret;

    // Monotonic snapshot version counter (survives snapshot pruning)
    std::atomic<uint32_t> m_nextSnapshotVersion{0};

    // Kernel bridge state
    std::atomic<bool> m_kernelHandlerRegistered{false};
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

bool RegistryProtection::ProtectIFEOKeys() {
    return m_impl->ProtectIFEOKeys();
}

bool RegistryProtection::HardenKeyDACL(std::wstring_view keyPath) {
    return m_impl->HardenKeyDACL(keyPath);
}

std::string RegistryProtection::GenerateAuthorizationToken() const {
    return m_impl->GenerateAuthorizationToken();
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

RegistryOperationDecisionResult RegistryProtection::FilterOperation(const RegistryOperationRequest& request) {
    return m_impl->FilterOperation(request);
}

void RegistryProtection::SetDecisionCallback(RegistryOperationDecisionCallback callback) {
    m_impl->SetDecisionCallback(std::move(callback));
}

void RegistryProtection::ClearDecisionCallback() {
    m_impl->ClearDecisionCallback();
}

RegistryIntegrityStatus RegistryProtection::VerifyKeyIntegrity(std::wstring_view keyPath) {
    return m_impl->VerifyKeyIntegrity(keyPath);
}

RegistryIntegrityStatus RegistryProtection::VerifyValueIntegrity(std::wstring_view keyPath,
                                                         std::wstring_view valueName) {
    return m_impl->VerifyValueIntegrity(keyPath, valueName);
}

std::vector<std::pair<std::wstring, RegistryIntegrityStatus>> RegistryProtection::VerifyAllIntegrity() {
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

uint64_t RegistryProtection::RegisterIntegrityCallback(RegistryIntegrityCallback callback) {
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

bool RegistryProtection::SyncProtectedKeysToKernel() {
    return m_impl->SyncProtectedKeysToKernel();
}

void RegistryProtection::OnKernelRegistryEvent(const void* data, size_t size) {
    m_impl->OnKernelRegistryEventInternal(data, size);
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
            config.defaultResponse = RegistryProtectionResponse::None;
            break;

        case RegistryProtectionMode::Monitor:
            config.enableKernelCallbacks = false;
            config.enableUserModePolling = true;
            config.enableIntegrityMonitoring = true;
            config.enableAutoRollback = false;
            config.enableSnapshots = true;
            config.defaultResponse = RegistryProtectionResponse::Passive;
            break;

        case RegistryProtectionMode::Protect:
            config.enableKernelCallbacks = true;
            config.enableUserModePolling = true;
            config.enableIntegrityMonitoring = true;
            config.enableAutoRollback = false;
            config.enableSnapshots = true;
            config.defaultResponse = RegistryProtectionResponse::Active;
            break;

        case RegistryProtectionMode::Rollback:
            config.enableKernelCallbacks = true;
            config.enableUserModePolling = true;
            config.enableIntegrityMonitoring = true;
            config.enableAutoRollback = true;
            config.enableSnapshots = true;
            config.defaultResponse = RegistryProtectionResponse::Active | RegistryProtectionResponse::Rollback;
            break;

        case RegistryProtectionMode::Strict:
            config.enableKernelCallbacks = true;
            config.enableUserModePolling = true;
            config.enableIntegrityMonitoring = true;
            config.enableAutoRollback = true;
            config.enableSnapshots = true;
            config.pollingIntervalMs = 2000;
            config.integrityCheckIntervalMs = 10000;
            config.defaultResponse = RegistryProtectionResponse::Aggressive;
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
    json << "\"decision\":" << static_cast<uint32_t>(decision) << ",";
    json << "\"sourceProcessId\":" << sourceProcessId << ",";
    json << "\"sourceProcessName\":\"" << EscapeJsonString(WideToNarrow(sourceProcessName)) << "\",";
    json << "\"wasBlocked\":" << (wasBlocked ? "true" : "false") << ",";
    json << "\"wasRolledBack\":" << (wasRolledBack ? "true" : "false") << ",";
    json << "\"description\":\"" << EscapeJsonString(description) << "\"";
    json << "}";
    return json.str();
}

// Statistics struct is now a plain snapshot (no atomics) — no copy ctor/operator= needed.
// Only ToJson remains as a convenience method.

std::string RegistryProtectionStatistics::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"totalProtectedKeys\":" << totalProtectedKeys << ",";
    json << "\"totalProtectedValues\":" << totalProtectedValues << ",";
    json << "\"totalOperations\":" << totalOperations << ",";
    json << "\"totalBlocked\":" << totalBlocked << ",";
    json << "\"totalRollbacks\":" << totalRollbacks << ",";
    json << "\"totalIntegrityChecks\":" << totalIntegrityChecks << ",";
    json << "\"integrityViolations\":" << integrityViolations << ",";
    json << "\"snapshotsCreated\":" << snapshotsCreated << ",";
    json << "\"snapshotsRestored\":" << snapshotsRestored << ",";
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

std::string_view GetIntegrityStatusName(RegistryIntegrityStatus status) noexcept {
    switch (status) {
        case RegistryIntegrityStatus::Unknown: return "Unknown";
        case RegistryIntegrityStatus::Valid: return "Valid";
        case RegistryIntegrityStatus::Modified: return "Modified";
        case RegistryIntegrityStatus::Missing: return "Missing";
        case RegistryIntegrityStatus::Corrupted: return "Corrupted";
        case RegistryIntegrityStatus::New: return "New";
        case RegistryIntegrityStatus::Restored: return "Restored";
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
    , m_authToken(RegistryProtection::Instance().GenerateAuthorizationToken())
{
    m_protected = RegistryProtection::Instance().ProtectKey(keyPath, type, true);
    if (m_protected) {
        SS_LOG_DEBUG(LOG_CATEGORY, L"Guard: Key protected: %ls", m_keyPath.c_str());
    }
}

RegistryProtectionGuard::~RegistryProtectionGuard() {
    if (m_protected) {
        if (RegistryProtection::Instance().UnprotectKey(m_keyPath, m_authToken)) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"Guard: Key unprotected: %ls", m_keyPath.c_str());
        } else {
            SS_LOG_WARN(LOG_CATEGORY, L"Guard: Failed to unprotect key: %ls", m_keyPath.c_str());
        }
    }
    // Scrub auth token from memory to prevent credential harvesting
    if (!m_authToken.empty()) {
        SecureZeroMemory(m_authToken.data(), m_authToken.size());
        m_authToken.clear();
    }
}

}  // namespace Security
}  // namespace ShadowStrike
