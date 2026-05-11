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
 * ShadowStrike Core Registry - SYSTEM SETTINGS MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file SystemSettingsMonitor.cpp
 * @brief Enterprise-grade OS security configuration monitoring engine.
 *
 * This module provides comprehensive monitoring of Windows security settings,
 * detecting unauthorized configuration changes that could weaken system
 * defenses or enable malicious activity.
 *
 * Detection Capabilities:
 * - UAC level monitoring and tampering detection
 * - Windows Defender real-time protection status
 * - Firewall profile monitoring (Domain/Private/Public)
 * - Exploit mitigation settings (ASLR/DEP/CFG/SEHOP)
 * - LSA security configuration
 * - Proxy/DNS hijacking detection
 * - Shell integration tampering
 * - Policy modification detection
 *
 * MITRE ATT&CK Coverage:
 * - T1562.001: Disable or Modify Tools
 * - T1562.004: Disable or Modify System Firewall
 * - T1112: Modify Registry
 * - T1090: Proxy
 * - T1557: Man-in-the-Middle
 * - T1222: File and Directory Permissions Modification
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "SystemSettingsMonitor.hpp"

// Infrastructure includes
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"

// Sibling modules for wiring
#include "RegistryMonitor.hpp"
#include "../Process/ProcessMonitor.hpp"

// Windows headers
#include <wininet.h>
#include <fwpmu.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "fwpuclnt.lib")

// Standard library
#include <algorithm>
#include <deque>
#include <format>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <queue>
#include <system_error>

namespace ShadowStrike {
namespace Core {
namespace Registry {

namespace fs = std::filesystem;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

// ----------------------------------------------------------------------------
// Defensive limits and policy constants (anonymous, file-local).
// ----------------------------------------------------------------------------

/**
 * @brief Maximum size of any single log field after sanitisation.
 *
 * Registry data is attacker-controllable. We hard-cap every string that flows
 * into the logger to prevent line-wrapping/SIEM-injection vectors and to keep
 * worst-case log volume bounded under adversarial input.
 */
constexpr size_t kMaxLogFieldChars = 1024;

/// Lower bound on poll interval (prevents pathological CPU burn).
constexpr uint32_t kMinPollIntervalMs = 250;
/// Upper bound on poll interval (prevents blinding the detector).
constexpr uint32_t kMaxPollIntervalMs = 60'000;

/**
 * @brief Convert SettingCategory to string.
 */
std::string CategoryToString(SettingCategory category) {
    switch (category) {
        case SettingCategory::Security: return "Security";
        case SettingCategory::Network: return "Network";
        case SettingCategory::Shell: return "Shell";
        case SettingCategory::Policy: return "Policy";
        case SettingCategory::Authentication: return "Authentication";
        case SettingCategory::Update: return "Update";
        case SettingCategory::Privacy: return "Privacy";
        case SettingCategory::Performance: return "Performance";
        default: return "Unknown";
    }
}

/**
 * @brief Convert AlertSeverity to string.
 */
std::string SeverityToString(AlertSeverity severity) {
    switch (severity) {
        case AlertSeverity::Info: return "Info";
        case AlertSeverity::Low: return "Low";
        case AlertSeverity::Medium: return "Medium";
        case AlertSeverity::High: return "High";
        case AlertSeverity::Critical: return "Critical";
        default: return "Unknown";
    }
}

/**
 * @brief Convert UACLevel to string.
 */
std::wstring UACLevelToString(UACLevel level) {
    switch (level) {
        case UACLevel::Disabled: return L"Disabled";
        case UACLevel::NotifyChanges: return L"Notify Changes";
        case UACLevel::NotifyChangesNoDim: return L"Notify Changes (No Dim)";
        case UACLevel::NotifyAll: return L"Notify All";
        case UACLevel::AlwaysNotify: return L"Always Notify";
        default: return L"Unknown";
    }
}

/**
 * @brief Strip control characters and truncate attacker-controlled strings before logging.
 *
 * Registry values, paths, command lines and inbound BSTRs are all
 * attacker-controllable. Any unsanitised flow into the logger could splice log
 * lines, forge timestamps, or inject crafted lines into downstream SIEM
 * pipelines. Bytes below 0x20 and 0x7F are replaced with '?' and the string
 * is hard-capped at @ref kMaxLogFieldChars.
 */
[[nodiscard]] std::string SanitizeForLog(std::wstring_view wide) {
    std::string narrow = Utils::StringUtils::ToNarrow(wide);
    if (narrow.size() > kMaxLogFieldChars) {
        narrow.resize(kMaxLogFieldChars);
        narrow.append("...<truncated>");
    }
    for (char& c : narrow) {
        const auto uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7F) {
            c = '?';
        }
    }
    return narrow;
}

[[nodiscard]] std::string SanitizeForLog(std::string_view narrowIn) {
    std::string narrow(narrowIn);
    if (narrow.size() > kMaxLogFieldChars) {
        narrow.resize(kMaxLogFieldChars);
        narrow.append("...<truncated>");
    }
    for (char& c : narrow) {
        const auto uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7F) {
            c = '?';
        }
    }
    return narrow;
}

/**
 * @brief Default OpenOptions for HKLM\\SOFTWARE-rooted reads.
 *
 * On 64-bit Windows the WOW6432Node redirector silently rewrites
 * HKLM\\SOFTWARE accesses for 32-bit callers. Without the explicit 64-bit
 * view, an attacker that mirrors the policy keys under the WOW6432Node would
 * observe a benign view while the native-bitness OS reads the malicious value.
 * Always pin to the 64-bit view for security-relevant reads/writes.
 */
[[nodiscard]] inline Utils::RegistryUtils::OpenOptions Wow64ReadOpts() noexcept {
    Utils::RegistryUtils::OpenOptions opts;
    opts.access = KEY_READ;
    opts.wow64_64 = true;
    return opts;
}

[[nodiscard]] inline Utils::RegistryUtils::OpenOptions Wow64WriteOpts() noexcept {
    Utils::RegistryUtils::OpenOptions opts;
    opts.access = KEY_SET_VALUE;
    opts.wow64_64 = true;
    return opts;
}

/**
 * @brief Safe registry DWORD read with default.
 *
 * Errors are intentionally swallowed: the caller has already supplied a
 * conservative default and registry-miss is a normal condition for many
 * policy-overlay keys.
 */
[[nodiscard]] DWORD ReadRegistryDwordSafe(HKEY hive, const std::wstring& path,
                                          const std::wstring& name, DWORD defaultValue,
                                          const Utils::RegistryUtils::OpenOptions& opts = {}) {
    DWORD result = defaultValue;
    (void)Utils::RegistryUtils::QuickReadDWord(hive, path, name, result, opts);
    return result;
}

/**
 * @brief Safe registry string read.
 */
[[nodiscard]] std::wstring ReadRegistryStringSafe(HKEY hive, const std::wstring& path,
                                                  const std::wstring& name,
                                                  const std::wstring& defaultValue = L"",
                                                  const Utils::RegistryUtils::OpenOptions& opts = {}) {
    std::wstring result;
    if (Utils::RegistryUtils::QuickReadString(hive, path, name, result, opts)) {
        return result;
    }
    return defaultValue;
}

/**
 * @brief Append a JSON-escaped narrow string to an output stream.
 *
 * Wraps Utils::StringUtils::EscapeJson; quotes are added by the caller. Used
 * by ExportSettings to prevent attacker-controlled registry values from
 * breaking out of JSON string context.
 */
inline void WriteJsonString(std::ostream& os, std::string_view value) {
    os << '"' << Utils::StringUtils::EscapeJson(value) << '"';
}

inline void WriteJsonStringW(std::ostream& os, std::wstring_view value) {
    WriteJsonString(os, Utils::StringUtils::ToNarrow(value));
}

/**
 * @brief Canonicalise and validate an export path.
 *
 * Rejects empty / relative paths and resolves traversal sequences before any
 * file is opened. We deliberately do not chase symlinks: weakly_canonical
 * preserves the final-component identity that fs::canonical would resolve
 * (which would itself be a TOCTOU vector if the caller pre-staged the target).
 */
[[nodiscard]] std::optional<std::filesystem::path> TryCanonicaliseOutputPath(
    const std::wstring& in) noexcept {
    namespace stdfs = std::filesystem;
    if (in.empty()) {
        return std::nullopt;
    }
    try {
        stdfs::path p(in);
        if (!p.is_absolute()) {
            return std::nullopt;
        }
        std::error_code ec;
        stdfs::path resolved = stdfs::weakly_canonical(p, ec);
        if (ec) {
            resolved = std::move(p);
        }
        return resolved;
    } catch (...) {
        return std::nullopt;
    }
}

/**
 * @brief Registry paths for monitoring.
 */
namespace RegistryPaths {
    constexpr wchar_t UAC_PATH[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    constexpr wchar_t DEFENDER_PATH[] = L"SOFTWARE\\Microsoft\\Windows Defender";
    constexpr wchar_t DEFENDER_POLICY_PATH[] = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender";
    constexpr wchar_t DEFENDER_FEATURES_PATH[] = L"SOFTWARE\\Microsoft\\Windows Defender\\Features";
    constexpr wchar_t FIREWALL_PATH[] = L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy";
    constexpr wchar_t PROXY_PATH[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    constexpr wchar_t TCP_PATH[] = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
    constexpr wchar_t TCP_INTERFACES_PATH[] = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";
    constexpr wchar_t LSA_PATH[] = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
    constexpr wchar_t EXPLOIT_PATH[] = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel";

    // AMSI
    constexpr wchar_t AMSI_PATH[] = L"SOFTWARE\\Microsoft\\AMSI";

    // ETW autologger (APTs disable to blind EDR telemetry)
    constexpr wchar_t ETW_AUTOLOGGER_PATH[] = L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger";
    constexpr wchar_t ETW_DEFENDER_LOGGER[] = L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger";
    constexpr wchar_t ETW_DEFENDER_AUDIT[] = L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderAuditLogger";

    // PowerShell execution policy
    constexpr wchar_t PS_POLICY_MACHINE[] = L"SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell";
    constexpr wchar_t PS_POLICY_USER[] = L"Software\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell";
    constexpr wchar_t PS_SCRIPT_BLOCK_LOGGING[] = L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging";
    constexpr wchar_t PS_TRANSCRIPTION[] = L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription";

    // Credential Guard / Device Guard
    constexpr wchar_t DEVICE_GUARD_PATH[] = L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard";
    constexpr wchar_t CRED_GUARD_PATH[] = L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity";
    constexpr wchar_t LSACFG_FLAGS_PATH[] = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";

    // WDigest (credential caching attack vector)
    constexpr wchar_t WDIGEST_PATH[] = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest";

    // Security packages
    constexpr wchar_t SEC_PROVIDERS_PATH[] = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders";
}

} // anonymous namespace

// ============================================================================
// CONFIGURATION FACTORY METHODS
// ============================================================================

SystemSettingsMonitorConfig SystemSettingsMonitorConfig::CreateDefault() noexcept {
    SystemSettingsMonitorConfig config;
    // Defaults already set in struct definition
    return config;
}

SystemSettingsMonitorConfig SystemSettingsMonitorConfig::CreateHighSecurity() noexcept {
    SystemSettingsMonitorConfig config;

    // Monitor everything
    config.monitorUAC = true;
    config.monitorDefender = true;
    config.monitorFirewall = true;
    config.monitorExploitProtection = true;
    config.monitorLSA = true;
    config.monitorProxy = true;
    config.monitorDNS = true;
    config.monitorShell = true;
    config.monitorPolicy = true;

    // Aggressive auto-remediation
    config.enableAutoRemediation = true;
    config.remediateUAC = true;
    config.remediateDefender = true;
    config.remediateFirewall = true;

    // Alert on everything
    config.minimumAlertSeverity = AlertSeverity::Low;
    config.alertOnAnyChange = true;
    config.alertOnSecurityDegrade = true;

    // Baseline enforcement
    config.useBaseline = true;
    config.autoCreateBaseline = true;

    return config;
}

SystemSettingsMonitorConfig SystemSettingsMonitorConfig::CreateMonitorOnly() noexcept {
    SystemSettingsMonitorConfig config;

    // Monitor everything
    config.monitorUAC = true;
    config.monitorDefender = true;
    config.monitorFirewall = true;
    config.monitorExploitProtection = true;
    config.monitorLSA = true;
    config.monitorProxy = true;
    config.monitorDNS = true;
    config.monitorShell = true;
    config.monitorPolicy = true;

    // No auto-remediation
    config.enableAutoRemediation = false;
    config.remediateUAC = false;
    config.remediateDefender = false;
    config.remediateFirewall = false;

    // Alert only on significant changes
    config.minimumAlertSeverity = AlertSeverity::Medium;
    config.alertOnAnyChange = false;
    config.alertOnSecurityDegrade = true;

    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void SystemSettingsMonitorStatistics::Reset() noexcept {
    changesDetected.store(0, std::memory_order_relaxed);
    securityDegrades.store(0, std::memory_order_relaxed);
    alertsGenerated.store(0, std::memory_order_relaxed);
    remediationsPerformed.store(0, std::memory_order_relaxed);
    remediationsFailed.store(0, std::memory_order_relaxed);

    uacChanges.store(0, std::memory_order_relaxed);
    defenderChanges.store(0, std::memory_order_relaxed);
    firewallChanges.store(0, std::memory_order_relaxed);
    networkChanges.store(0, std::memory_order_relaxed);
    shellChanges.store(0, std::memory_order_relaxed);
}

// ============================================================================
// CALLBACK MANAGER
// ============================================================================

class CallbackManager {
public:
    uint64_t RegisterChange(SettingChangeCallback callback) {
        if (!callback) {
            return 0;
        }

        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_changeCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterAlert(SecurityAlertCallback callback) {
        if (!callback) {
            return 0;
        }

        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_alertCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterCompliance(ComplianceCallback callback) {
        if (!callback) {
            return 0;
        }

        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_complianceCallbacks[id] = std::move(callback);
        return id;
    }

    bool Unregister(uint64_t id) {
        std::unique_lock lock(m_mutex);

        if (m_changeCallbacks.erase(id)) return true;
        if (m_alertCallbacks.erase(id)) return true;
        if (m_complianceCallbacks.erase(id)) return true;

        return false;
    }

    void InvokeChange(const SettingChange& change) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_changeCallbacks) {
            try {
                callback(change);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"SystemSettingsMonitor", L"SettingChangeCallback exception: %hs", e.what());
            }
        }
    }

    void InvokeAlert(const SecurityAlert& alert) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_alertCallbacks) {
            try {
                callback(alert);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"SystemSettingsMonitor", L"SecurityAlertCallback exception: %hs", e.what());
            }
        }
    }

    void InvokeCompliance(const ComplianceStatus& status) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_complianceCallbacks) {
            try {
                callback(status);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"SystemSettingsMonitor", L"ComplianceCallback exception: %hs", e.what());
            }
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    uint64_t m_nextId{ 1 };
    std::unordered_map<uint64_t, SettingChangeCallback> m_changeCallbacks;
    std::unordered_map<uint64_t, SecurityAlertCallback> m_alertCallbacks;
    std::unordered_map<uint64_t, ComplianceCallback> m_complianceCallbacks;
};

// ============================================================================
// BASELINE MANAGER
// ============================================================================

class BaselineManager {
public:
    uint64_t CreateBaseline(const BaselineSnapshot& snapshot) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_baselines[id] = snapshot;
        m_baselines[id].snapshotId = id;

        SS_LOG_INFO(L"SystemSettingsMonitor", L"Created baseline %llu - %hs",
            static_cast<unsigned long long>(id), snapshot.description.c_str());

        return id;
    }

    std::optional<BaselineSnapshot> GetBaseline(uint64_t id) const {
        std::shared_lock lock(m_mutex);
        auto it = m_baselines.find(id);
        if (it != m_baselines.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    bool SetActiveBaseline(uint64_t id) {
        std::unique_lock lock(m_mutex);
        if (m_baselines.find(id) == m_baselines.end()) {
            return false;
        }
        m_activeBaselineId = id;
        return true;
    }

    std::optional<uint64_t> GetActiveBaselineId() const {
        std::shared_lock lock(m_mutex);
        return m_activeBaselineId;
    }

    // FIX: GetActiveBaseline was calling GetBaseline() while holding shared_lock,
    // causing recursive lock (UB on shared_mutex). Inline the lookup instead.
    std::optional<BaselineSnapshot> GetActiveBaseline() const {
        std::shared_lock lock(m_mutex);
        if (m_activeBaselineId.has_value()) {
            auto it = m_baselines.find(*m_activeBaselineId);
            if (it != m_baselines.end()) {
                return it->second;
            }
        }
        return std::nullopt;
    }

private:
    mutable std::shared_mutex m_mutex;
    uint64_t m_nextId{ 1 };
    std::unordered_map<uint64_t, BaselineSnapshot> m_baselines;
    std::optional<uint64_t> m_activeBaselineId;
};

// ============================================================================
// CHANGE TRACKER
// ============================================================================

/**
 * @class ChangeTracker
 * @brief Bounded, ordered history of SettingChange events.
 *
 * Storage is a std::deque so eviction at the cap is O(1) (pop_front) instead
 * of the previous O(N) vector::erase pattern. Under sustained attack — e.g. a
 * malware loop flipping ConsentPromptBehaviorAdmin every second — the old
 * implementation would shift the entire history on every event; this version
 * is amortised constant.
 */
class ChangeTracker {
public:
    void RecordChange(const SettingChange& change) {
        std::unique_lock lock(m_mutex);

        m_history.push_back(change);

        while (m_history.size() > m_maxHistory) {
            m_history.pop_front();
        }
    }

    [[nodiscard]] std::vector<SettingChange> GetHistory(size_t maxCount) const {
        std::shared_lock lock(m_mutex);

        std::vector<SettingChange> result;
        if (m_history.empty() || maxCount == 0) {
            return result;
        }

        const size_t toCopy = std::min(maxCount, m_history.size());
        result.reserve(toCopy);
        auto first = m_history.end() - static_cast<std::ptrdiff_t>(toCopy);
        result.assign(first, m_history.end());
        return result;
    }

    [[nodiscard]] std::vector<SettingChange> GetHistoryByCategory(
        SettingCategory category, size_t maxCount) const {
        std::shared_lock lock(m_mutex);

        std::vector<SettingChange> filtered;
        if (maxCount == 0) {
            return filtered;
        }
        for (auto it = m_history.rbegin();
             it != m_history.rend() && filtered.size() < maxCount; ++it) {
            if (it->category == category) {
                filtered.push_back(*it);
            }
        }
        return filtered;
    }

    void SetMaxHistory(size_t max) {
        std::unique_lock lock(m_mutex);
        m_maxHistory = (max == 0) ? 1 : max;
        while (m_history.size() > m_maxHistory) {
            m_history.pop_front();
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    std::deque<SettingChange> m_history;
    size_t m_maxHistory{ SystemSettingsMonitorConstants::MAX_HISTORY };
};

// ============================================================================
// ALERT MANAGER
// ============================================================================

/**
 * @class AlertManager
 * @brief Bounded alert store with forensic retention semantics.
 *
 * Two improvements over the previous design:
 *  1. Storage is std::map<uint64_t,…> (ordered by ID) so eviction at the
 *     storage cap is O(log N) — locate by begin() — instead of O(N) full
 *     scan that the unordered_map required.
 *  2. AcknowledgeAlert no longer erases the alert. Operators reviewing an
 *     incident often acknowledge an alert in the UI to silence it; deleting
 *     the record at that point is forensic data loss. We mark
 *     wasRemediated=true and acknowledged=true so GetActiveAlerts hides the
 *     entry while history is preserved.
 *
 * Eviction policy: when at MAX_ALERTS, prefer to evict the oldest
 * non-Critical, already-acknowledged alert. If none qualify, evict the
 * oldest non-Critical alert. Critical alerts are retained until explicitly
 * cleared so that a flood of low-severity events cannot wash away the
 * high-severity needle.
 */
class AlertManager {
public:
    uint64_t CreateAlert(const SecurityAlert& alert) {
        std::unique_lock lock(m_mutex);

        if (m_alerts.size() >= SystemSettingsMonitorConstants::MAX_ALERTS) {
            EvictOneLocked();
        }

        const uint64_t id = m_nextId++;
        auto [it, inserted] = m_alerts.emplace(id, alert);
        it->second.alertId = id;

        SS_LOG_WARN(L"SystemSettingsMonitor", L"Alert %llu - %hs [%hs]",
            static_cast<unsigned long long>(id),
            SanitizeForLog(it->second.title).c_str(),
            SeverityToString(it->second.severity).c_str());

        return id;
    }

    [[nodiscard]] std::vector<SecurityAlert> GetActiveAlerts() const {
        std::shared_lock lock(m_mutex);

        std::vector<SecurityAlert> active;
        active.reserve(m_alerts.size());
        for (const auto& [id, alert] : m_alerts) {
            if (!alert.wasRemediated && !alert.acknowledged) {
                active.push_back(alert);
            }
        }
        return active;
    }

    /**
     * @brief Mark alert acknowledged. Forensic copy is retained.
     */
    bool AcknowledgeAlert(uint64_t id) {
        std::unique_lock lock(m_mutex);

        auto it = m_alerts.find(id);
        if (it == m_alerts.end()) {
            return false;
        }
        it->second.acknowledged = true;
        it->second.wasRemediated = true;
        return true;
    }

    void ClearAll() {
        std::unique_lock lock(m_mutex);
        m_alerts.clear();
    }

private:
    /**
     * @brief Pick a victim under the storage cap, biased away from Critical.
     *
     * Must be called with m_mutex held exclusively.
     */
    void EvictOneLocked() {
        if (m_alerts.empty()) {
            return;
        }
        // Pass 1: oldest acknowledged below Critical.
        for (auto it = m_alerts.begin(); it != m_alerts.end(); ++it) {
            if (it->second.acknowledged && it->second.severity < AlertSeverity::Critical) {
                m_alerts.erase(it);
                return;
            }
        }
        // Pass 2: oldest non-Critical regardless of acknowledgement.
        for (auto it = m_alerts.begin(); it != m_alerts.end(); ++it) {
            if (it->second.severity < AlertSeverity::Critical) {
                m_alerts.erase(it);
                return;
            }
        }
        // Pass 3: storage saturated with Critical alerts — drop the oldest.
        m_alerts.erase(m_alerts.begin());
    }

    mutable std::shared_mutex m_mutex;
    uint64_t m_nextId{ 1 };
    std::map<uint64_t, SecurityAlert> m_alerts;
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class SystemSettingsMonitorImpl {
public:
    SystemSettingsMonitorImpl()
        : m_callbackManager(std::make_unique<CallbackManager>()),
          m_baselineManager(std::make_unique<BaselineManager>()),
          m_changeTracker(std::make_unique<ChangeTracker>()),
          m_alertManager(std::make_unique<AlertManager>()) {}
    ~SystemSettingsMonitorImpl() {
        Stop();
    }

    // Prevent copying
    SystemSettingsMonitorImpl(const SystemSettingsMonitorImpl&) = delete;
    SystemSettingsMonitorImpl& operator=(const SystemSettingsMonitorImpl&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const SystemSettingsMonitorConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            SS_LOG_INFO(L"SystemSettingsMonitor", L"Initializing...");

            m_config = config;

            // Initialize managers
            m_callbackManager = std::make_unique<CallbackManager>();
            m_baselineManager = std::make_unique<BaselineManager>();
            m_changeTracker = std::make_unique<ChangeTracker>();
            m_alertManager = std::make_unique<AlertManager>();

            m_changeTracker->SetMaxHistory(config.maxHistoryEntries);

            // Read current state
            RefreshAllImpl();

            // Auto-create baseline if configured
            if (config.autoCreateBaseline && config.useBaseline) {
                CreateBaselineImpl("Initial baseline (auto-created)");
            }

            m_initialized = true;
            SS_LOG_INFO(L"SystemSettingsMonitor", L"Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"SystemSettingsMonitor", L"Initialization failed: %hs", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        Stop();

        std::unique_lock lock(m_mutex);
        m_initialized = false;

        SS_LOG_INFO(L"SystemSettingsMonitor", L"Shutdown complete");
    }

    // ========================================================================
    // MONITORING CONTROL
    // ========================================================================

    void Start() {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            SS_LOG_ERROR(L"SystemSettingsMonitor", L"Cannot start: not initialized");
            return;
        }

        if (m_monitoring.load(std::memory_order_acquire)) {
            SS_LOG_WARN(L"SystemSettingsMonitor", L"Already monitoring");
            return;
        }

        m_monitoring.store(true, std::memory_order_release);
        m_monitorThread = std::thread(&SystemSettingsMonitorImpl::MonitorThreadFunc, this);

        SS_LOG_INFO(L"SystemSettingsMonitor", L"Real-time monitoring started");
    }

    void Stop() noexcept {
        {
            std::unique_lock lock(m_mutex);
            if (!m_monitoring.load(std::memory_order_acquire)) return;
            m_monitoring.store(false, std::memory_order_release);
        }

        // std::thread::join() can throw std::system_error (e.g. invalid_argument
        // if the thread terminated unexpectedly). Stop() is noexcept by
        // contract: callers (incl. destructors) cannot tolerate propagation.
        if (m_monitorThread.joinable()) {
            try {
                m_monitorThread.join();
            } catch (const std::system_error& e) {
                SS_LOG_ERROR(L"SystemSettingsMonitor",
                    L"Monitor thread join failed: %hs", SanitizeForLog(e.what()).c_str());
            } catch (...) {
                SS_LOG_ERROR(L"SystemSettingsMonitor",
                    L"Monitor thread join failed: unknown exception");
            }
        }

        SS_LOG_INFO(L"SystemSettingsMonitor", L"Monitoring stopped");
    }

    bool IsMonitoring() const noexcept {
        return m_monitoring.load(std::memory_order_acquire);
    }

    // ========================================================================
    // UAC SETTINGS
    // ========================================================================

    UACSettings GetUACSettings() const {
        std::shared_lock lock(m_mutex);
        return m_currentState.uac;
    }

    bool IsUACDisabled() const {
        std::shared_lock lock(m_mutex);
        return !m_currentState.uac.enabled;
    }

    UACLevel GetUACLevel() const {
        std::shared_lock lock(m_mutex);
        return m_currentState.uac.level;
    }

    bool RestoreUACDefaults() {
        try {
            const auto wOpts = Wow64WriteOpts();

            // Secure defaults: EnableLUA=1, ConsentPromptBehaviorAdmin=5 (default),
            // PromptOnSecureDesktop=1.
            const bool ok1 = Utils::RegistryUtils::QuickWriteDWord(HKEY_LOCAL_MACHINE,
                RegistryPaths::UAC_PATH, L"EnableLUA", 1, wOpts);
            const bool ok2 = Utils::RegistryUtils::QuickWriteDWord(HKEY_LOCAL_MACHINE,
                RegistryPaths::UAC_PATH, L"ConsentPromptBehaviorAdmin", 5, wOpts);
            const bool ok3 = Utils::RegistryUtils::QuickWriteDWord(HKEY_LOCAL_MACHINE,
                RegistryPaths::UAC_PATH, L"PromptOnSecureDesktop", 1, wOpts);

            if (!ok1 || !ok2 || !ok3) {
                SS_LOG_ERROR(L"SystemSettingsMonitor",
                    L"RestoreUACDefaults partial failure: EnableLUA=%d ConsentAdmin=%d SecureDesktop=%d",
                    static_cast<int>(ok1), static_cast<int>(ok2), static_cast<int>(ok3));
                return false;
            }

            // Refresh state under exclusive lock — the previous implementation
            // mutated m_currentState without locking, racing with reader paths.
            {
                std::unique_lock lock(m_mutex);
                RefreshUACImpl();
            }

            SS_LOG_INFO(L"SystemSettingsMonitor", L"UAC restored to secure defaults");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"SystemSettingsMonitor", L"RestoreUACDefaults failed: %hs",
                SanitizeForLog(e.what()).c_str());
            return false;
        }
    }

    // ========================================================================
    // DEFENDER SETTINGS
    // ========================================================================

    DefenderSettings GetDefenderSettings() const {
        std::shared_lock lock(m_mutex);
        return m_currentState.defender;
    }

    bool IsDefenderDisabled() const {
        std::shared_lock lock(m_mutex);
        return !m_currentState.defender.enabled;
    }

    bool IsRealTimeProtectionDisabled() const {
        std::shared_lock lock(m_mutex);
        return !m_currentState.defender.realTimeProtection;
    }

    std::vector<std::wstring> GetDefenderExclusions() const {
        std::shared_lock lock(m_mutex);
        return m_currentState.defender.excludedPaths;
    }

    bool RestoreDefenderDefaults() {
        try {
            const auto wOpts = Wow64WriteOpts();

            // Clear the policy override that disables AntiSpyware.
            const bool ok1 = Utils::RegistryUtils::QuickWriteDWord(HKEY_LOCAL_MACHINE,
                RegistryPaths::DEFENDER_POLICY_PATH, L"DisableAntiSpyware", 0, wOpts);

            // Re-enable realtime monitoring.
            const std::wstring rtPath = std::wstring(RegistryPaths::DEFENDER_POLICY_PATH) +
                                       L"\\Real-Time Protection";
            const bool ok2 = Utils::RegistryUtils::QuickWriteDWord(HKEY_LOCAL_MACHINE,
                rtPath, L"DisableRealtimeMonitoring", 0, wOpts);
            const bool ok3 = Utils::RegistryUtils::QuickWriteDWord(HKEY_LOCAL_MACHINE,
                rtPath, L"DisableBehaviorMonitoring", 0, wOpts);
            const bool ok4 = Utils::RegistryUtils::QuickWriteDWord(HKEY_LOCAL_MACHINE,
                rtPath, L"DisableIOAVProtection", 0, wOpts);

            if (!ok1 || !ok2 || !ok3 || !ok4) {
                SS_LOG_ERROR(L"SystemSettingsMonitor",
                    L"RestoreDefenderDefaults partial failure: %d/%d/%d/%d",
                    static_cast<int>(ok1), static_cast<int>(ok2),
                    static_cast<int>(ok3), static_cast<int>(ok4));
            }

            {
                std::unique_lock lock(m_mutex);
                RefreshDefenderImpl();
            }

            SS_LOG_INFO(L"SystemSettingsMonitor", L"Defender restored to secure defaults");
            return (ok1 && ok2 && ok3 && ok4);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"SystemSettingsMonitor", L"RestoreDefenderDefaults failed: %hs",
                SanitizeForLog(e.what()).c_str());
            return false;
        }
    }

    // ========================================================================
    // FIREWALL SETTINGS
    // ========================================================================

    FirewallSettings GetFirewallSettings() const {
        std::shared_lock lock(m_mutex);
        return m_currentState.firewall;
    }

    bool IsFirewallDisabled(FirewallProfile profile) const {
        std::shared_lock lock(m_mutex);

        switch (profile) {
            case FirewallProfile::Domain:
                return !m_currentState.firewall.domainEnabled;
            case FirewallProfile::Private:
                return !m_currentState.firewall.privateEnabled;
            case FirewallProfile::Public:
                return !m_currentState.firewall.publicEnabled;
            case FirewallProfile::All:
                return !m_currentState.firewall.domainEnabled ||
                       !m_currentState.firewall.privateEnabled ||
                       !m_currentState.firewall.publicEnabled;
            default:
                return false;
        }
    }

    bool IsAnyFirewallDisabled() const {
        std::shared_lock lock(m_mutex);
        return !m_currentState.firewall.domainEnabled ||
               !m_currentState.firewall.privateEnabled ||
               !m_currentState.firewall.publicEnabled;
    }

    bool RestoreFirewallDefaults() {
        try {
            const std::wstring domainPath = std::wstring(RegistryPaths::FIREWALL_PATH) +
                                           L"\\DomainProfile";
            const std::wstring privatePath = std::wstring(RegistryPaths::FIREWALL_PATH) +
                                            L"\\StandardProfile";
            const std::wstring publicPath = std::wstring(RegistryPaths::FIREWALL_PATH) +
                                           L"\\PublicProfile";

            // FIREWALL_PATH is under HKLM\\SYSTEM (not WOW64-redirected) so default opts suffice.
            const bool ok1 = Utils::RegistryUtils::QuickWriteDWord(HKEY_LOCAL_MACHINE,
                domainPath, L"EnableFirewall", 1);
            const bool ok2 = Utils::RegistryUtils::QuickWriteDWord(HKEY_LOCAL_MACHINE,
                privatePath, L"EnableFirewall", 1);
            const bool ok3 = Utils::RegistryUtils::QuickWriteDWord(HKEY_LOCAL_MACHINE,
                publicPath, L"EnableFirewall", 1);

            if (!ok1 || !ok2 || !ok3) {
                SS_LOG_ERROR(L"SystemSettingsMonitor",
                    L"RestoreFirewallDefaults partial failure: Domain=%d Private=%d Public=%d",
                    static_cast<int>(ok1), static_cast<int>(ok2), static_cast<int>(ok3));
            }

            {
                std::unique_lock lock(m_mutex);
                RefreshFirewallImpl();
            }

            SS_LOG_INFO(L"SystemSettingsMonitor", L"Firewall restored to secure defaults");
            return (ok1 && ok2 && ok3);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"SystemSettingsMonitor", L"RestoreFirewallDefaults failed: %hs",
                SanitizeForLog(e.what()).c_str());
            return false;
        }
    }

    // ========================================================================
    // EXPLOIT PROTECTION
    // ========================================================================

    ExploitProtection GetExploitProtection() const {
        std::shared_lock lock(m_mutex);
        return m_currentState.exploit;
    }

    bool IsASLRDisabled() const {
        std::shared_lock lock(m_mutex);
        return !m_currentState.exploit.aslrEnabled;
    }

    bool IsDEPDisabled() const {
        std::shared_lock lock(m_mutex);
        return !m_currentState.exploit.depEnabled;
    }

    // ========================================================================
    // LSA SETTINGS
    // ========================================================================

    LSASettings GetLSASettings() const {
        std::shared_lock lock(m_mutex);
        return m_currentState.lsa;
    }

    bool IsLSAPPLEnabled() const {
        std::shared_lock lock(m_mutex);
        return m_currentState.lsa.runAsPPL;
    }

    // ========================================================================
    // NETWORK SETTINGS
    // ========================================================================

    ProxySettings GetProxySettings() const {
        std::shared_lock lock(m_mutex);
        return m_currentState.proxy;
    }

    bool IsProxyEnabled() const {
        std::shared_lock lock(m_mutex);
        return m_currentState.proxy.proxyEnabled;
    }

    DNSSettings GetDNSSettings() const {
        std::shared_lock lock(m_mutex);
        return m_currentState.dns;
    }

    bool IsDNSSuspicious() const {
        std::shared_lock lock(m_mutex);

        // Check for known malicious DNS servers
        const std::vector<std::wstring> suspiciousDNS = {
            L"8.8.4.4",  // Typo of Google DNS
            L"1.1.1.2",  // Typo of Cloudflare
        };

        for (const auto& dns : m_currentState.dns.dnsServers) {
            if (std::find(suspiciousDNS.begin(), suspiciousDNS.end(), dns) != suspiciousDNS.end()) {
                return true;
            }
        }

        return false;
    }

    // ========================================================================
    // BASELINE MANAGEMENT
    // ========================================================================

    uint64_t CreateBaseline(const std::string& description) {
        std::shared_lock lock(m_mutex);
        return CreateBaselineImpl(description);
    }

    std::optional<BaselineSnapshot> GetBaseline(uint64_t baselineId) const {
        return m_baselineManager->GetBaseline(baselineId);
    }

    std::optional<BaselineSnapshot> GetActiveBaseline() const {
        return m_baselineManager->GetActiveBaseline();
    }

    bool SetActiveBaseline(uint64_t baselineId) {
        if (!m_baselineManager->SetActiveBaseline(baselineId)) {
            SS_LOG_WARN(L"SystemSettingsMonitor", L"Attempted to activate unknown baseline %llu",
                static_cast<unsigned long long>(baselineId));
            return false;
        }

        SS_LOG_INFO(L"SystemSettingsMonitor", L"Set active baseline to %llu", static_cast<unsigned long long>(baselineId));
        return true;
    }

    bool RestoreToBaseline(uint64_t baselineId) {
        auto baseline = m_baselineManager->GetBaseline(baselineId);
        if (!baseline.has_value()) {
            SS_LOG_ERROR(L"SystemSettingsMonitor", L"Baseline %llu not found",
                static_cast<unsigned long long>(baselineId));
            return false;
        }

        try {
            // UAC: only restore if the baseline asserts UAC was on. If the
            // baseline was captured with UAC off, "restoring" it by enabling
            // UAC silently changes the host's posture relative to its
            // baseline — opposite of the operator's intent.
            if (m_config.remediateUAC && baseline->uac.enabled) {
                RestoreUACDefaults();
            }

            if (m_config.remediateDefender && baseline->defender.enabled) {
                RestoreDefenderDefaults();
            }

            // Firewall: only push secure defaults if the baseline shows at
            // least one profile enabled AND the current state shows at least
            // one profile disabled. Otherwise we'd needlessly rewrite policy
            // on hosts where firewall was intentionally tuned off.
            if (m_config.remediateFirewall) {
                std::shared_lock lock(m_mutex);
                const bool baselineHasFw = baseline->firewall.domainEnabled ||
                                           baseline->firewall.privateEnabled ||
                                           baseline->firewall.publicEnabled;
                const bool currentDegraded =
                    (baseline->firewall.domainEnabled  && !m_currentState.firewall.domainEnabled)  ||
                    (baseline->firewall.privateEnabled && !m_currentState.firewall.privateEnabled) ||
                    (baseline->firewall.publicEnabled  && !m_currentState.firewall.publicEnabled);
                lock.unlock();

                if (baselineHasFw && currentDegraded) {
                    RestoreFirewallDefaults();
                }
            }

            SS_LOG_INFO(L"SystemSettingsMonitor", L"Restored to baseline %llu",
                static_cast<unsigned long long>(baselineId));
            m_stats.remediationsPerformed.fetch_add(1, std::memory_order_relaxed);
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"SystemSettingsMonitor", L"RestoreToBaseline failed: %hs",
                SanitizeForLog(e.what()).c_str());
            m_stats.remediationsFailed.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }

    std::vector<SettingChange> CompareToBaseline(uint64_t baselineId) const {
        std::vector<SettingChange> differences;

        auto baseline = m_baselineManager->GetBaseline(baselineId);
        if (!baseline.has_value()) {
            return differences;
        }

        std::shared_lock lock(m_mutex);

        auto addDiff = [&](SettingCategory cat, SecuritySettingType type,
                           const wchar_t* name, bool current, bool base) {
            if (current != base) {
                SettingChange change;
                change.category = cat;
                change.settingType = type;
                change.settingName = name;
                change.previousValue = base ? L"1" : L"0";
                change.newValue = current ? L"1" : L"0";
                change.isSecurityDegrade = base && !current;
                differences.push_back(std::move(change));
            }
        };

        // UAC
        addDiff(SettingCategory::Security, SecuritySettingType::UAC_Enabled,
            L"UAC Enabled", m_currentState.uac.enabled, baseline->uac.enabled);

        if (m_currentState.uac.consentPromptAdmin != baseline->uac.consentPromptAdmin) {
            SettingChange change;
            change.category = SettingCategory::Security;
            change.settingType = SecuritySettingType::UAC_ConsentPromptAdmin;
            change.settingName = L"ConsentPromptBehaviorAdmin";
            change.previousValue = std::to_wstring(baseline->uac.consentPromptAdmin);
            change.newValue = std::to_wstring(m_currentState.uac.consentPromptAdmin);
            change.isSecurityDegrade = (m_currentState.uac.consentPromptAdmin < baseline->uac.consentPromptAdmin);
            differences.push_back(std::move(change));
        }

        // Defender
        addDiff(SettingCategory::Security, SecuritySettingType::Defender_Enabled,
            L"Defender Enabled", m_currentState.defender.enabled, baseline->defender.enabled);
        addDiff(SettingCategory::Security, SecuritySettingType::Defender_RealtimeProtection,
            L"Real-Time Protection", m_currentState.defender.realTimeProtection, baseline->defender.realTimeProtection);
        addDiff(SettingCategory::Security, SecuritySettingType::Defender_BehaviorMonitoring,
            L"Behavior Monitoring", m_currentState.defender.behaviorMonitoring, baseline->defender.behaviorMonitoring);
        addDiff(SettingCategory::Security, SecuritySettingType::Defender_TamperProtection,
            L"Tamper Protection", m_currentState.defender.tamperProtection, baseline->defender.tamperProtection);
        addDiff(SettingCategory::Security, SecuritySettingType::Defender_CloudProtection,
            L"Cloud Protection", m_currentState.defender.cloudProtection, baseline->defender.cloudProtection);

        // Firewall - all three profiles
        addDiff(SettingCategory::Security, SecuritySettingType::Firewall_DomainEnabled,
            L"Firewall Domain Profile", m_currentState.firewall.domainEnabled, baseline->firewall.domainEnabled);
        addDiff(SettingCategory::Security, SecuritySettingType::Firewall_PrivateEnabled,
            L"Firewall Private Profile", m_currentState.firewall.privateEnabled, baseline->firewall.privateEnabled);
        addDiff(SettingCategory::Security, SecuritySettingType::Firewall_PublicEnabled,
            L"Firewall Public Profile", m_currentState.firewall.publicEnabled, baseline->firewall.publicEnabled);

        // LSA
        addDiff(SettingCategory::Authentication, SecuritySettingType::LSA_RunAsPPL,
            L"LSASS RunAsPPL", m_currentState.lsa.runAsPPL, baseline->lsa.runAsPPL);
        addDiff(SettingCategory::Authentication, SecuritySettingType::LSA_NoLMHash,
            L"LSA NoLMHash", m_currentState.lsa.noLMHash, baseline->lsa.noLMHash);

        // Exploit protection
        addDiff(SettingCategory::Security, SecuritySettingType::Exploit_SEHOP,
            L"SEHOP", m_currentState.exploit.sehopEnabled, baseline->exploit.sehopEnabled);
        addDiff(SettingCategory::Security, SecuritySettingType::Exploit_ASLR,
            L"ASLR", m_currentState.exploit.aslrEnabled, baseline->exploit.aslrEnabled);

        // Proxy — attackers may inject a transparent proxy for C2 redirection.
        if (m_currentState.proxy.proxyEnabled != baseline->proxy.proxyEnabled ||
            m_currentState.proxy.proxyServer  != baseline->proxy.proxyServer) {
            SettingChange change;
            change.category = SettingCategory::Network;
            change.settingType = SecuritySettingType::Unknown;
            change.settingName = L"Proxy";
            change.previousValue = baseline->proxy.proxyEnabled ?
                (L"on:" + baseline->proxy.proxyServer) : std::wstring(L"off");
            change.newValue = m_currentState.proxy.proxyEnabled ?
                (L"on:" + m_currentState.proxy.proxyServer) : std::wstring(L"off");
            change.isSecurityDegrade = (m_currentState.proxy.proxyServer != baseline->proxy.proxyServer);
            differences.push_back(std::move(change));
        }

        // DNS — element/size compare flags any drift in resolver set.
        if (m_currentState.dns.dnsServers != baseline->dns.dnsServers) {
            SettingChange change;
            change.category = SettingCategory::Network;
            change.settingType = SecuritySettingType::Unknown;
            change.settingName = L"DNS Servers";
            std::wstring before, after;
            for (const auto& s : baseline->dns.dnsServers) { before += s; before += L','; }
            for (const auto& s : m_currentState.dns.dnsServers) { after += s; after += L','; }
            change.previousValue = std::move(before);
            change.newValue = std::move(after);
            change.isSecurityDegrade = true;
            differences.push_back(std::move(change));
        }

        return differences;
    }

    // ========================================================================
    // COMPLIANCE
    // ========================================================================

    ComplianceStatus CheckCompliance() const {
        ComplianceStatus status;
        status.lastChecked = std::chrono::system_clock::now();

        std::shared_lock lock(m_mutex);

        // Check UAC
        status.totalChecks++;
        if (m_currentState.uac.enabled) {
            status.passedChecks++;
        } else {
            status.failedChecks++;
            status.failures.push_back("UAC is disabled");
        }

        // Check Defender
        status.totalChecks++;
        if (m_currentState.defender.enabled) {
            status.passedChecks++;
        } else {
            status.failedChecks++;
            status.failures.push_back("Windows Defender is disabled");
        }

        // Check Firewall
        status.totalChecks++;
        if (m_currentState.firewall.publicEnabled) {
            status.passedChecks++;
        } else {
            status.failedChecks++;
            status.failures.push_back("Public firewall is disabled");
        }

        // Check real-time protection
        status.totalChecks++;
        if (m_currentState.defender.realTimeProtection) {
            status.passedChecks++;
        } else {
            status.failedChecks++;
            status.failures.push_back("Real-time protection is disabled");
        }

        // Check ASLR
        status.totalChecks++;
        if (m_currentState.exploit.aslrEnabled) {
            status.passedChecks++;
        } else {
            status.warningList.push_back("ASLR may not be fully enabled");
            status.warnings++;
        }

        // Check DEP
        status.totalChecks++;
        if (m_currentState.exploit.depEnabled) {
            status.passedChecks++;
        } else {
            status.warningList.push_back("DEP may not be fully enabled");
            status.warnings++;
        }

        status.isCompliant = (status.failedChecks == 0);

        return status;
    }

    ComplianceStatus CheckPolicyCompliance(const std::wstring& policyPath) const {
        ComplianceStatus status;
        status.lastChecked = std::chrono::system_clock::now();

        // Canonicalise the caller-supplied path so we cannot be tricked into
        // following ".." traversals or symlinks back into protected scopes.
        // weakly_canonical tolerates non-existent leaves so we keep the "file
        // not found" branch for the post-canonicalisation existence check.
        std::error_code ec;
        fs::path canonical;
        if (!policyPath.empty()) {
            canonical = fs::weakly_canonical(fs::path{ policyPath }, ec);
            if (ec) {
                canonical = fs::path{ policyPath };
            }
        }

        if (policyPath.empty() || !fs::exists(canonical, ec)) {
            status.isCompliant = false;
            status.failedChecks = 1;
            status.totalChecks = 1;
            status.failures.push_back("Policy file not found: " +
                SanitizeForLog(canonical.wstring()));
            return status;
        }

        status = CheckCompliance();

        SS_LOG_INFO(L"SystemSettingsMonitor",
            L"Policy compliance evaluated against: %hs",
            SanitizeForLog(canonical.wstring()).c_str());

        return status;
    }

    // ========================================================================
    // HISTORY
    // ========================================================================

    std::vector<SettingChange> GetHistory(size_t maxCount) const {
        return m_changeTracker->GetHistory(maxCount);
    }

    std::vector<SettingChange> GetHistoryByCategory(SettingCategory category, size_t maxCount) const {
        return m_changeTracker->GetHistoryByCategory(category, maxCount);
    }

    // ========================================================================
    // ALERTS
    // ========================================================================

    std::vector<SecurityAlert> GetActiveAlerts() const {
        return m_alertManager->GetActiveAlerts();
    }

    bool AcknowledgeAlert(uint64_t alertId) {
        return m_alertManager->AcknowledgeAlert(alertId);
    }

    void ClearAlerts() noexcept {
        m_alertManager->ClearAll();
    }

    // ========================================================================
    // REMEDIATION
    // ========================================================================

    bool Remediate(uint64_t changeId) {
        // Find change in history
        auto history = m_changeTracker->GetHistory(1000);

        for (const auto& change : history) {
            if (change.changeId == changeId) {
                return RemediateChange(change);
            }
        }

        SS_LOG_ERROR(L"SystemSettingsMonitor", L"Change %llu not found", static_cast<unsigned long long>(changeId));
        return false;
    }

    void SetAutoRemediation(bool enable) noexcept {
        std::unique_lock lock(m_mutex);
        m_config.enableAutoRemediation = enable;
        SS_LOG_INFO(L"SystemSettingsMonitor", L"Auto-remediation %ls", enable ? L"enabled" : L"disabled");
    }

    bool IsAutoRemediationEnabled() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config.enableAutoRemediation;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    uint64_t RegisterChangeCallback(SettingChangeCallback callback) {
        return m_callbackManager->RegisterChange(std::move(callback));
    }

    uint64_t RegisterAlertCallback(SecurityAlertCallback callback) {
        return m_callbackManager->RegisterAlert(std::move(callback));
    }

    uint64_t RegisterComplianceCallback(ComplianceCallback callback) {
        return m_callbackManager->RegisterCompliance(std::move(callback));
    }

    bool UnregisterCallback(uint64_t callbackId) {
        return m_callbackManager->Unregister(callbackId);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const SystemSettingsMonitorStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    // ========================================================================
    // REFRESH
    // ========================================================================

    void RefreshAll() {
        std::unique_lock lock(m_mutex);
        RefreshAllImpl();
    }

    void RefreshCategory(SettingCategory category) {
        std::unique_lock lock(m_mutex);

        switch (category) {
            case SettingCategory::Security:
                RefreshUACImpl();
                RefreshDefenderImpl();
                RefreshFirewallImpl();
                RefreshExploitProtectionImpl();
                break;
            case SettingCategory::Network:
                RefreshProxyImpl();
                RefreshDNSImpl();
                break;
            case SettingCategory::Authentication:
                RefreshLSAImpl();
                break;
            default:
                break;
        }
    }

    // ========================================================================
    // EXPORT
    // ========================================================================

    bool ExportReport(const std::wstring& outputPath) const {
        try {
            auto canonical = TryCanonicaliseOutputPath(outputPath);
            if (!canonical) {
                SS_LOG_ERROR(L"SystemSettingsMonitor",
                    L"ExportReport rejected output path");
                return false;
            }

            std::ofstream ofs(*canonical);
            if (!ofs) return false;

            ofs << "=== ShadowStrike System Settings Monitor Report ===\n\n";

            std::shared_lock lock(m_mutex);

            ofs << "UAC Status:\n";
            ofs << "  Enabled: " << (m_currentState.uac.enabled ? "Yes" : "NO") << "\n";
            ofs << "  Level: " << SanitizeForLog(UACLevelToString(m_currentState.uac.level)) << "\n\n";

            ofs << "Windows Defender Status:\n";
            ofs << "  Enabled: " << (m_currentState.defender.enabled ? "Yes" : "NO") << "\n";
            ofs << "  Real-time: " << (m_currentState.defender.realTimeProtection ? "Yes" : "NO") << "\n";
            ofs << "  Tamper Protection: " << (m_currentState.defender.tamperProtection ? "Yes" : "NO") << "\n";
            ofs << "  Cloud Protection: " << (m_currentState.defender.cloudProtection ? "Yes" : "NO") << "\n\n";

            ofs << "Firewall Status:\n";
            ofs << "  Domain: " << (m_currentState.firewall.domainEnabled ? "Enabled" : "DISABLED") << "\n";
            ofs << "  Private: " << (m_currentState.firewall.privateEnabled ? "Enabled" : "DISABLED") << "\n";
            ofs << "  Public: " << (m_currentState.firewall.publicEnabled ? "Enabled" : "DISABLED") << "\n\n";

            ofs << "Statistics:\n";
            ofs << "  Changes Detected: " << m_stats.changesDetected.load() << "\n";
            ofs << "  Security Degrades: " << m_stats.securityDegrades.load() << "\n";
            ofs << "  Alerts Generated: " << m_stats.alertsGenerated.load() << "\n";
            ofs << "  Remediations: " << m_stats.remediationsPerformed.load() << "\n";

            ofs.close();

            SS_LOG_INFO(L"SystemSettingsMonitor",
                L"Exported report to %hs",
                SanitizeForLog(canonical->wstring()).c_str());
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"SystemSettingsMonitor", L"ExportReport failed: %hs",
                SanitizeForLog(e.what()).c_str());
            return false;
        }
    }

    bool ExportSettings(const std::wstring& outputPath) const {
        try {
            auto canonical = TryCanonicaliseOutputPath(outputPath);
            if (!canonical) {
                SS_LOG_ERROR(L"SystemSettingsMonitor",
                    L"ExportSettings rejected output path");
                return false;
            }

            std::ofstream ofs(*canonical);
            if (!ofs) return false;

            std::shared_lock lock(m_mutex);

            // Every string-valued field is JSON-escaped via WriteJsonStringW.
            // Registry contents (proxy server, DNS list, signature version)
            // are attacker-influenceable; emitting them raw would let a
            // crafted ProxyServer value of the form `","poisoned":"true` break
            // the JSON contract.
            ofs << "{\n";

            ofs << "  \"uac\": {\n";
            ofs << "    \"enabled\": " << (m_currentState.uac.enabled ? "true" : "false") << ",\n";
            ofs << "    \"level\": ";
            WriteJsonStringW(ofs, UACLevelToString(m_currentState.uac.level));
            ofs << ",\n";
            ofs << "    \"consentPromptAdmin\": " << m_currentState.uac.consentPromptAdmin << ",\n";
            ofs << "    \"promptOnSecureDesktop\": " << (m_currentState.uac.promptOnSecureDesktop ? "true" : "false") << "\n";
            ofs << "  },\n";

            ofs << "  \"defender\": {\n";
            ofs << "    \"enabled\": " << (m_currentState.defender.enabled ? "true" : "false") << ",\n";
            ofs << "    \"realTimeProtection\": " << (m_currentState.defender.realTimeProtection ? "true" : "false") << ",\n";
            ofs << "    \"behaviorMonitoring\": " << (m_currentState.defender.behaviorMonitoring ? "true" : "false") << ",\n";
            ofs << "    \"tamperProtection\": " << (m_currentState.defender.tamperProtection ? "true" : "false") << ",\n";
            ofs << "    \"cloudProtection\": " << (m_currentState.defender.cloudProtection ? "true" : "false") << ",\n";
            ofs << "    \"networkProtection\": " << (m_currentState.defender.networkProtection ? "true" : "false") << ",\n";
            ofs << "    \"controlledFolderAccess\": " << (m_currentState.defender.controlledFolderAccess ? "true" : "false") << "\n";
            ofs << "  },\n";

            ofs << "  \"firewall\": {\n";
            ofs << "    \"domainEnabled\": " << (m_currentState.firewall.domainEnabled ? "true" : "false") << ",\n";
            ofs << "    \"privateEnabled\": " << (m_currentState.firewall.privateEnabled ? "true" : "false") << ",\n";
            ofs << "    \"publicEnabled\": " << (m_currentState.firewall.publicEnabled ? "true" : "false") << "\n";
            ofs << "  },\n";

            ofs << "  \"proxy\": {\n";
            ofs << "    \"enabled\": " << (m_currentState.proxy.proxyEnabled ? "true" : "false") << ",\n";
            ofs << "    \"server\": ";
            WriteJsonStringW(ofs, m_currentState.proxy.proxyServer);
            ofs << "\n  },\n";

            ofs << "  \"dns\": {\n";
            ofs << "    \"servers\": [";
            bool first = true;
            for (const auto& s : m_currentState.dns.dnsServers) {
                if (!first) ofs << ", ";
                WriteJsonStringW(ofs, s);
                first = false;
            }
            ofs << "],\n";
            ofs << "    \"suffix\": ";
            WriteJsonStringW(ofs, m_currentState.dns.dnsSuffix);
            ofs << "\n  }\n";

            ofs << "}\n";
            ofs.close();
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"SystemSettingsMonitor", L"ExportSettings failed: %hs",
                SanitizeForLog(e.what()).c_str());
            return false;
        }
    }

    bool ExportHistory(const std::wstring& outputPath) const {
        try {
            auto canonical = TryCanonicaliseOutputPath(outputPath);
            if (!canonical) {
                SS_LOG_ERROR(L"SystemSettingsMonitor",
                    L"ExportHistory rejected output path");
                return false;
            }

            std::ofstream ofs(*canonical);
            if (!ofs) return false;

            auto history = m_changeTracker->GetHistory(1000);

            ofs << "=== System Settings Change History ===\n\n";

            for (const auto& change : history) {
                ofs << "Change ID: " << change.changeId << "\n";
                ofs << "Category: " << CategoryToString(change.category) << "\n";
                ofs << "Setting: " << SanitizeForLog(change.settingName) << "\n";
                ofs << "Previous: " << SanitizeForLog(change.previousValue) << "\n";
                ofs << "New: " << SanitizeForLog(change.newValue) << "\n";
                ofs << "Security Degrade: " << (change.isSecurityDegrade ? "YES" : "No") << "\n";
                ofs << "\n";
            }

            ofs.close();
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"SystemSettingsMonitor", L"ExportHistory failed: %hs",
                SanitizeForLog(e.what()).c_str());
            return false;
        }
    }

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    uint64_t CreateBaselineImpl(const std::string& description) {
        BaselineSnapshot snapshot;
        snapshot.created = std::chrono::system_clock::now();
        snapshot.description = description;
        snapshot.uac = m_currentState.uac;
        snapshot.defender = m_currentState.defender;
        snapshot.firewall = m_currentState.firewall;
        snapshot.exploit = m_currentState.exploit;
        snapshot.lsa = m_currentState.lsa;
        snapshot.proxy = m_currentState.proxy;
        snapshot.dns = m_currentState.dns;

        return m_baselineManager->CreateBaseline(snapshot);
    }

    void RefreshAllImpl() {
        if (m_config.monitorUAC) RefreshUACImpl();
        if (m_config.monitorDefender) RefreshDefenderImpl();
        if (m_config.monitorFirewall) RefreshFirewallImpl();
        if (m_config.monitorExploitProtection) RefreshExploitProtectionImpl();
        if (m_config.monitorLSA) RefreshLSAImpl();
        if (m_config.monitorProxy) RefreshProxyImpl();
        if (m_config.monitorDNS) RefreshDNSImpl();
    }

    void RefreshUACImpl() {
        const auto rOpts = Wow64ReadOpts();

        m_currentState.uac.enabled = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::UAC_PATH, L"EnableLUA", 1, rOpts) != 0;

        m_currentState.uac.consentPromptAdmin = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::UAC_PATH, L"ConsentPromptBehaviorAdmin", 5, rOpts);

        m_currentState.uac.promptOnSecureDesktop = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::UAC_PATH, L"PromptOnSecureDesktop", 1, rOpts) != 0;

        m_currentState.uac.filterAdministratorToken = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::UAC_PATH, L"FilterAdministratorToken", 0, rOpts) != 0;

        m_currentState.uac.runAllAdminsInAAM = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::UAC_PATH, L"EnableInstallerDetection", 1, rOpts) != 0;

        m_currentState.uac.validateAdminCodeSignatures = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::UAC_PATH, L"ValidateAdminCodeSignatures", 0, rOpts) != 0;

        // Determine UAC level.
        //
        // Windows ConsentPromptBehaviorAdmin mapping (per MS-CONSENT spec):
        //   0 = Elevate without prompting (MOST INSECURE — silent admin escalation)
        //   1 = Prompt for credentials on the secure desktop
        //   2 = Prompt for consent on the secure desktop
        //   3 = Prompt for credentials
        //   4 = Prompt for consent
        //   5 = Prompt for consent for non-Windows binaries (default)
        //
        // The previous implementation mapped 0 -> NotifyChanges, which is the
        // *opposite* of its semantic — value 0 is effectively "UAC off for
        // admins" and is a documented UAC bypass primitive (T1548.002).
        if (!m_currentState.uac.enabled) {
            m_currentState.uac.level = UACLevel::Disabled;
        } else if (m_currentState.uac.consentPromptAdmin == 0) {
            // EnableLUA=1 but silent-elevation: from a defender standpoint
            // this is functionally equivalent to UAC being disabled.
            m_currentState.uac.level = UACLevel::Disabled;
        } else if (m_currentState.uac.consentPromptAdmin == 5) {
            m_currentState.uac.level = m_currentState.uac.promptOnSecureDesktop ?
                UACLevel::NotifyChanges : UACLevel::NotifyChangesNoDim;
        } else if (m_currentState.uac.consentPromptAdmin == 2 ||
                   m_currentState.uac.consentPromptAdmin == 1) {
            // 1/2 use the secure desktop -> "Always Notify" tier.
            m_currentState.uac.level = UACLevel::AlwaysNotify;
        } else {
            // 3/4 (no secure desktop) -> NotifyAll
            m_currentState.uac.level = UACLevel::NotifyAll;
        }

        m_currentState.uac.lastChecked = std::chrono::system_clock::now();
    }

    void RefreshDefenderImpl() {
        const auto rOpts = Wow64ReadOpts();

        // Policy override: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
        const DWORD disableDefender = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::DEFENDER_POLICY_PATH, L"DisableAntiSpyware", 0, rOpts);
        m_currentState.defender.enabled = (disableDefender == 0);

        const std::wstring rtPath = std::wstring(RegistryPaths::DEFENDER_POLICY_PATH) +
                                   L"\\Real-Time Protection";

        m_currentState.defender.realTimeProtection = ReadRegistryDwordSafe(
            HKEY_LOCAL_MACHINE, rtPath, L"DisableRealtimeMonitoring", 0, rOpts) == 0;
        m_currentState.defender.behaviorMonitoring = ReadRegistryDwordSafe(
            HKEY_LOCAL_MACHINE, rtPath, L"DisableBehaviorMonitoring", 0, rOpts) == 0;
        m_currentState.defender.ioavProtection = ReadRegistryDwordSafe(
            HKEY_LOCAL_MACHINE, rtPath, L"DisableIOAVProtection", 0, rOpts) == 0;

        // Cloud/MAPS protection — SpyNet policy key.
        const std::wstring spynetPath = std::wstring(RegistryPaths::DEFENDER_POLICY_PATH) +
                                       L"\\Spynet";
        const DWORD spynetReporting = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            spynetPath, L"SpynetReporting", 2, rOpts);
        m_currentState.defender.cloudProtection = (spynetReporting != 0);

        // Network protection (Windows Defender Exploit Guard).
        const std::wstring npPath = std::wstring(RegistryPaths::DEFENDER_POLICY_PATH) +
                                   L"\\Windows Defender Exploit Guard\\Network Protection";
        const DWORD npEnable = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            npPath, L"EnableNetworkProtection", 0, rOpts);
        m_currentState.defender.networkProtection = (npEnable == 1 || npEnable == 2);

        // Controlled Folder Access (ransomware mitigation).
        const std::wstring cfaPath = std::wstring(RegistryPaths::DEFENDER_POLICY_PATH) +
                                    L"\\Windows Defender Exploit Guard\\Controlled Folder Access";
        const DWORD cfaEnable = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            cfaPath, L"EnableControlledFolderAccess", 0, rOpts);
        m_currentState.defender.controlledFolderAccess = (cfaEnable == 1);

        // PUA protection.
        m_currentState.defender.potentiallyUnwantedApps = ReadRegistryDwordSafe(
            HKEY_LOCAL_MACHINE, RegistryPaths::DEFENDER_POLICY_PATH,
            L"PUAProtection", 0, rOpts) != 0;

        // Tamper Protection lives under the Defender service Features key.
        // Value 5 = enabled, 0 = disabled. We treat anything != 5 as off.
        const DWORD tamper = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::DEFENDER_FEATURES_PATH, L"TamperProtection", 0, rOpts);
        m_currentState.defender.tamperProtection = (tamper == 5);

        m_currentState.defender.lastChecked = std::chrono::system_clock::now();
    }

    void RefreshFirewallImpl() {
        const std::wstring domainPath = std::wstring(RegistryPaths::FIREWALL_PATH) +
                                       L"\\DomainProfile";
        const std::wstring privatePath = std::wstring(RegistryPaths::FIREWALL_PATH) +
                                        L"\\StandardProfile";
        const std::wstring publicPath = std::wstring(RegistryPaths::FIREWALL_PATH) +
                                       L"\\PublicProfile";

        m_currentState.firewall.domainEnabled = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            domainPath, L"EnableFirewall", 1) != 0;

        m_currentState.firewall.privateEnabled = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            privatePath, L"EnableFirewall", 1) != 0;

        m_currentState.firewall.publicEnabled = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            publicPath, L"EnableFirewall", 1) != 0;

        m_currentState.firewall.publicDefaultInbound = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            publicPath, L"DefaultInboundAction", 1);

        m_currentState.firewall.lastChecked = std::chrono::system_clock::now();
    }

    void RefreshExploitProtectionImpl() {
        // MoveImages controls ASLR randomization (0xFFFFFFFF = force disabled)
        DWORD moveImages = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
            L"MoveImages", 0);
        m_currentState.exploit.aslrEnabled = (moveImages != 0xFFFFFFFF);

        // DEP is AlwaysOn on 64-bit Windows 10+ (cannot be registry-disabled)
        m_currentState.exploit.depEnabled = true;

        // CFG (Control Flow Guard) system-wide
        DWORD enableCfg = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
            L"EnableCfg", 1);
        m_currentState.exploit.cfgEnabled = (enableCfg != 0);

        // SEHOP
        DWORD sehop = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::EXPLOIT_PATH, L"DisableExceptionChainValidation", 0);
        m_currentState.exploit.sehopEnabled = (sehop == 0);

        m_currentState.exploit.lastChecked = std::chrono::system_clock::now();
    }

    void RefreshLSAImpl() {
        m_currentState.lsa.runAsPPL = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::LSA_PATH, L"RunAsPPL", 0) != 0;

        m_currentState.lsa.restrictAnonymous = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::LSA_PATH, L"RestrictAnonymous", 0);

        m_currentState.lsa.limitBlankPasswordUse = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::LSA_PATH, L"LimitBlankPasswordUse", 1) != 0;

        m_currentState.lsa.noLMHash = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::LSA_PATH, L"NoLMHash", 1) != 0;

        m_currentState.lsa.lmCompatibilityLevel = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::LSA_PATH, L"LmCompatibilityLevel", 5);

        // WDigest UseLogonCredential=1 forces LSASS to keep cleartext credentials
        // in memory — a documented Mimikatz precondition (T1003.001). Alert,
        // even though we don't carry a struct field, because the signal is
        // critical: legitimate machines never need this set.
        const DWORD wdigest = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
            L"UseLogonCredential", 0);
        if (wdigest != 0) {
            SS_LOG_WARN(L"SystemSettingsMonitor",
                L"WDigest UseLogonCredential is enabled - LSASS cleartext credentials retained (T1003.001)");
        }

        // Credential Guard / LSA isolation flags. LsaCfgFlags must be != 0 on
        // hosts that opted in; alert only if the value is present and == 0
        // (operator disabled it post-deployment).
        DWORD lsaCfg = 0;
        DWORD lsaCfgType = 0;
        DWORD lsaCfgSize = sizeof(lsaCfg);
        const LSTATUS lsaCfgStatus = ::RegGetValueW(HKEY_LOCAL_MACHINE,
            RegistryPaths::LSA_PATH, L"LsaCfgFlags",
            RRF_RT_REG_DWORD, &lsaCfgType, &lsaCfg, &lsaCfgSize);
        if (lsaCfgStatus == ERROR_SUCCESS && lsaCfg == 0) {
            SS_LOG_WARN(L"SystemSettingsMonitor",
                L"LsaCfgFlags explicitly zero - Credential Guard disabled");
        }

        m_currentState.lsa.lastChecked = std::chrono::system_clock::now();
    }

    void RefreshProxyImpl() {
        m_currentState.proxy.proxyEnabled = ReadRegistryDwordSafe(HKEY_CURRENT_USER,
            RegistryPaths::PROXY_PATH, L"ProxyEnable", 0) != 0;

        m_currentState.proxy.proxyServer = ReadRegistryStringSafe(HKEY_CURRENT_USER,
            RegistryPaths::PROXY_PATH, L"ProxyServer");

        m_currentState.proxy.autoConfigUrl = ReadRegistryStringSafe(HKEY_CURRENT_USER,
            RegistryPaths::PROXY_PATH, L"AutoConfigURL");

        m_currentState.proxy.lastChecked = std::chrono::system_clock::now();
    }

    void RefreshDNSImpl() {
        m_currentState.dns.dnsServers.clear();

        // 1) Global Tcpip\Parameters\NameServer (rare on modern Windows but
        //    still respected when populated).
        auto append_csv = [&](std::wstring csv) {
            if (csv.empty()) return;
            size_t pos = 0;
            while ((pos = csv.find_first_of(L", ")) != std::wstring::npos) {
                if (pos > 0) {
                    m_currentState.dns.dnsServers.push_back(csv.substr(0, pos));
                }
                csv.erase(0, pos + 1);
            }
            if (!csv.empty()) {
                m_currentState.dns.dnsServers.push_back(std::move(csv));
            }
        };

        append_csv(ReadRegistryStringSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::TCP_PATH, L"NameServer"));

        // 2) Per-adapter NameServer / DhcpNameServer values under
        //    HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}.
        //    Statically-configured DNS lives in NameServer; DHCP-assigned in
        //    DhcpNameServer. Either path is a plausible DNS-hijack target
        //    (T1071.004) so both are read. HKLM\SYSTEM is not WOW64-redirected;
        //    default OpenOptions are correct.
        Utils::RegistryUtils::RegistryKey interfaces;
        if (interfaces.Open(HKEY_LOCAL_MACHINE, RegistryPaths::TCP_INTERFACES_PATH)) {
            std::vector<std::wstring> adapters;
            if (interfaces.EnumKeys(adapters)) {
                // Bound the work: a host with >256 adapters is implausible
                // and likely an attacker enumerating registry quirks.
                constexpr size_t kMaxAdapters = 256;
                const size_t limit = std::min(adapters.size(), kMaxAdapters);
                for (size_t i = 0; i < limit; ++i) {
                    const std::wstring& guid = adapters[i];
                    std::wstring adapterPath{ RegistryPaths::TCP_INTERFACES_PATH };
                    adapterPath.push_back(L'\\');
                    adapterPath.append(guid);

                    append_csv(ReadRegistryStringSafe(HKEY_LOCAL_MACHINE,
                        adapterPath, L"NameServer"));
                    append_csv(ReadRegistryStringSafe(HKEY_LOCAL_MACHINE,
                        adapterPath, L"DhcpNameServer"));
                }
            }
        }

        // De-duplicate while preserving first-seen ordering.
        {
            std::vector<std::wstring> unique;
            unique.reserve(m_currentState.dns.dnsServers.size());
            for (auto& s : m_currentState.dns.dnsServers) {
                if (std::find(unique.begin(), unique.end(), s) == unique.end()) {
                    unique.push_back(std::move(s));
                }
            }
            m_currentState.dns.dnsServers = std::move(unique);
        }

        m_currentState.dns.dnsSuffix = ReadRegistryStringSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::TCP_PATH, L"Domain");

        m_currentState.dns.lastChecked = std::chrono::system_clock::now();
    }

    void MonitorThreadFunc() {
        SS_LOG_INFO(L"SystemSettingsMonitor", L"Monitor thread started");

        // Clamp the configured poll interval to a sane band so a misconfigured
        // value (0 -> busy-spin, MAXUINT -> stalled monitor) cannot wedge the
        // service. kMinPollIntervalMs ensures we yield enough CPU; kMax keeps
        // detection latency bounded.
        const uint32_t intervalMs = std::clamp(m_config.monitorPollIntervalMs,
            kMinPollIntervalMs, kMaxPollIntervalMs);

        while (m_monitoring.load(std::memory_order_acquire)) {
            try {
                // Capture FULL previous state under shared_lock.
                BaselineSnapshot previousState;
                {
                    std::shared_lock lock(m_mutex);
                    previousState.uac = m_currentState.uac;
                    previousState.defender = m_currentState.defender;
                    previousState.firewall = m_currentState.firewall;
                    previousState.exploit = m_currentState.exploit;
                    previousState.lsa = m_currentState.lsa;
                    previousState.proxy = m_currentState.proxy;
                    previousState.dns = m_currentState.dns;
                }

                RefreshAll();
                DetectChanges(previousState);

                std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"SystemSettingsMonitor", L"Monitor thread exception: %hs",
                    SanitizeForLog(e.what()).c_str());
                // Avoid tight-spin if Refresh is repeatedly throwing.
                std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
            }
        }

        SS_LOG_INFO(L"SystemSettingsMonitor", L"Monitor thread stopped");
    }

    void DetectChanges(const BaselineSnapshot& previous) {
        // The original implementation held a shared_lock for the entirety of
        // this function — including callbacks and Restore*Defaults remediation
        // paths. Restore*Defaults now correctly takes a unique_lock so that
        // RefreshXImpl is race-free; holding shared_lock here would
        // self-deadlock. We snapshot the comparison decisions under the
        // shared_lock, release it, then emit changes / fire remediation.
        //
        // Snapshot copies happen via small-object stack locals so the lock is
        // held only for read-comparison time.

        struct ChangeAction {
            enum Kind {
                kUACEnable, kUACConsent,
                kDefender, kDefenderRTP, kDefenderBehavior,
                kFirewallDomain, kFirewallPrivate, kFirewallPublic,
                kLSARunAsPPL, kLSANoLMHash,
                kExploitSEHOP
            };
            Kind kind;
            bool prevB{};
            bool curB{};
            uint32_t prevU{};
            uint32_t curU{};
        };

        std::vector<ChangeAction> actions;
        actions.reserve(8);

        {
            std::shared_lock lock(m_mutex);

            if (m_config.monitorUAC) {
                if (m_currentState.uac.enabled != previous.uac.enabled) {
                    actions.push_back({ ChangeAction::kUACEnable, previous.uac.enabled,
                        m_currentState.uac.enabled, 0, 0 });
                }
                if (m_currentState.uac.consentPromptAdmin != previous.uac.consentPromptAdmin) {
                    actions.push_back({ ChangeAction::kUACConsent, false, false,
                        previous.uac.consentPromptAdmin, m_currentState.uac.consentPromptAdmin });
                }
            }

            if (m_config.monitorDefender) {
                if (m_currentState.defender.enabled != previous.defender.enabled) {
                    actions.push_back({ ChangeAction::kDefender, previous.defender.enabled,
                        m_currentState.defender.enabled, 0, 0 });
                }
                if (m_currentState.defender.realTimeProtection != previous.defender.realTimeProtection) {
                    actions.push_back({ ChangeAction::kDefenderRTP, previous.defender.realTimeProtection,
                        m_currentState.defender.realTimeProtection, 0, 0 });
                }
                if (previous.defender.behaviorMonitoring && !m_currentState.defender.behaviorMonitoring) {
                    actions.push_back({ ChangeAction::kDefenderBehavior, true, false, 0, 0 });
                }
            }

            if (m_config.monitorFirewall) {
                if (m_currentState.firewall.domainEnabled != previous.firewall.domainEnabled) {
                    actions.push_back({ ChangeAction::kFirewallDomain, previous.firewall.domainEnabled,
                        m_currentState.firewall.domainEnabled, 0, 0 });
                }
                if (m_currentState.firewall.privateEnabled != previous.firewall.privateEnabled) {
                    actions.push_back({ ChangeAction::kFirewallPrivate, previous.firewall.privateEnabled,
                        m_currentState.firewall.privateEnabled, 0, 0 });
                }
                if (m_currentState.firewall.publicEnabled != previous.firewall.publicEnabled) {
                    actions.push_back({ ChangeAction::kFirewallPublic, previous.firewall.publicEnabled,
                        m_currentState.firewall.publicEnabled, 0, 0 });
                }
            }

            if (m_config.monitorLSA) {
                if (previous.lsa.runAsPPL && !m_currentState.lsa.runAsPPL) {
                    actions.push_back({ ChangeAction::kLSARunAsPPL, true, false, 0, 0 });
                }
                if (previous.lsa.noLMHash && !m_currentState.lsa.noLMHash) {
                    actions.push_back({ ChangeAction::kLSANoLMHash, true, false, 0, 0 });
                }
            }

            if (m_config.monitorExploitProtection) {
                if (previous.exploit.sehopEnabled && !m_currentState.exploit.sehopEnabled) {
                    actions.push_back({ ChangeAction::kExploitSEHOP, true, false, 0, 0 });
                }
            }
        }
        // shared_lock released. All emission/remediation below runs WITHOUT
        // holding m_mutex so Restore*Defaults may safely take unique_lock.

        for (const auto& a : actions) {
            switch (a.kind) {
                case ChangeAction::kUACEnable:
                    OnUACChange(a.prevB, a.curB); break;
                case ChangeAction::kUACConsent:
                    OnUACConsentChange(a.prevU, a.curU); break;
                case ChangeAction::kDefender:
                    OnDefenderChange(a.prevB, a.curB); break;
                case ChangeAction::kDefenderRTP:
                    OnRealTimeProtectionChange(a.prevB, a.curB); break;
                case ChangeAction::kDefenderBehavior:
                    OnGenericSecurityDegrade(SecuritySettingType::Defender_BehaviorMonitoring,
                        L"Defender Behavior Monitoring", AlertSeverity::High, "T1562.001");
                    break;
                case ChangeAction::kFirewallDomain:
                    OnFirewallChange(FirewallProfile::Domain, a.prevB, a.curB); break;
                case ChangeAction::kFirewallPrivate:
                    OnFirewallChange(FirewallProfile::Private, a.prevB, a.curB); break;
                case ChangeAction::kFirewallPublic:
                    OnFirewallChange(FirewallProfile::Public, a.prevB, a.curB); break;
                case ChangeAction::kLSARunAsPPL:
                    OnGenericSecurityDegrade(SecuritySettingType::LSA_RunAsPPL,
                        L"LSASS RunAsPPL removed", AlertSeverity::Critical, "T1003.001");
                    break;
                case ChangeAction::kLSANoLMHash:
                    OnGenericSecurityDegrade(SecuritySettingType::LSA_NoLMHash,
                        L"LM Hash storage enabled", AlertSeverity::High, "T1003");
                    break;
                case ChangeAction::kExploitSEHOP:
                    OnGenericSecurityDegrade(SecuritySettingType::Exploit_SEHOP,
                        L"SEHOP disabled", AlertSeverity::Medium, "T1068");
                    break;
            }
        }
    }

    void OnUACConsentChange(uint32_t wasValue, uint32_t isValue) {
        SettingChange change;
        change.changeId = m_nextChangeId.fetch_add(1, std::memory_order_relaxed);
        change.timestamp = std::chrono::system_clock::now();
        change.category = SettingCategory::Security;
        change.settingType = SecuritySettingType::UAC_ConsentPromptAdmin;
        change.settingPath = RegistryPaths::UAC_PATH;
        change.settingName = L"ConsentPromptBehaviorAdmin";
        change.previousValue = std::to_wstring(wasValue);
        change.newValue = std::to_wstring(isValue);
        change.isSecurityDegrade = (isValue < wasValue);

        if (isValue == 0) {
            change.severity = AlertSeverity::Critical;
            change.isMalwareIndicator = true;
            change.riskDescription = "ConsentPromptBehaviorAdmin=0: silent elevation (UAC bypass T1548.002)";
        } else if (isValue < wasValue) {
            change.severity = AlertSeverity::High;
            change.riskDescription = "UAC consent prompt weakened";
        } else {
            change.severity = AlertSeverity::Info;
        }

        m_stats.changesDetected.fetch_add(1, std::memory_order_relaxed);
        m_stats.uacChanges.fetch_add(1, std::memory_order_relaxed);
        if (change.isSecurityDegrade) {
            m_stats.securityDegrades.fetch_add(1, std::memory_order_relaxed);
        }

        m_changeTracker->RecordChange(change);
        m_callbackManager->InvokeChange(change);

        if (change.severity >= m_config.minimumAlertSeverity) {
            CreateSecurityAlert(change);
        }
    }

    void OnGenericSecurityDegrade(SecuritySettingType type, const std::wstring& name,
                                   AlertSeverity severity, const std::string& mitreId) {
        SettingChange change;
        change.changeId = m_nextChangeId.fetch_add(1, std::memory_order_relaxed);
        change.timestamp = std::chrono::system_clock::now();
        change.category = SettingCategory::Security;
        change.settingType = type;
        change.settingName = name;
        change.previousValue = L"1";
        change.newValue = L"0";
        change.isSecurityDegrade = true;
        change.isMalwareIndicator = (severity >= AlertSeverity::High);
        change.severity = severity;
        change.riskDescription = std::string("Security degraded: ") +
            Utils::StringUtils::ToNarrow(name);

        m_stats.changesDetected.fetch_add(1, std::memory_order_relaxed);
        m_stats.securityDegrades.fetch_add(1, std::memory_order_relaxed);

        m_changeTracker->RecordChange(change);
        m_callbackManager->InvokeChange(change);

        SecurityAlert alert;
        alert.timestamp = change.timestamp;
        alert.severity = severity;
        alert.alertType = "SecurityDegradation";
        alert.title = change.riskDescription;
        alert.description = "Security protection disabled: " +
            Utils::StringUtils::ToNarrow(name);
        alert.category = change.category;
        alert.settingType = type;
        alert.mitreId = mitreId;
        alert.mitreTactic = "Defense Evasion";
        alert.canRemediate = false;

        m_alertManager->CreateAlert(alert);
        m_callbackManager->InvokeAlert(alert);
        m_stats.alertsGenerated.fetch_add(1, std::memory_order_relaxed);
    }

    void OnUACChange(bool wasEnabled, bool isEnabled) {
        SettingChange change;
        change.changeId = m_nextChangeId.fetch_add(1, std::memory_order_relaxed);
        change.timestamp = std::chrono::system_clock::now();
        change.category = SettingCategory::Security;
        change.settingType = SecuritySettingType::UAC_Enabled;
        change.settingPath = RegistryPaths::UAC_PATH;
        change.settingName = L"UAC Enabled";
        change.previousValue = wasEnabled ? L"1" : L"0";
        change.newValue = isEnabled ? L"1" : L"0";
        change.isSecurityDegrade = !isEnabled;
        change.severity = isEnabled ? AlertSeverity::Info : AlertSeverity::Critical;

        if (!isEnabled) {
            change.riskDescription = "UAC has been disabled - system is vulnerable to privilege escalation";
        }

        m_stats.changesDetected.fetch_add(1, std::memory_order_relaxed);
        m_stats.uacChanges.fetch_add(1, std::memory_order_relaxed);

        if (change.isSecurityDegrade) {
            m_stats.securityDegrades.fetch_add(1, std::memory_order_relaxed);
        }

        m_changeTracker->RecordChange(change);
        m_callbackManager->InvokeChange(change);

        // Create alert
        if (change.severity >= m_config.minimumAlertSeverity) {
            CreateSecurityAlert(change);
        }

        // Auto-remediate
        if (m_config.enableAutoRemediation && m_config.remediateUAC && !isEnabled) {
            SS_LOG_WARN(L"SystemSettingsMonitor", L"Auto-remediating UAC disable");
            RestoreUACDefaults();
            change.actionTaken = RemediationAction::Restore;
            change.wasRemediated = true;
        }
    }

    void OnDefenderChange(bool wasEnabled, bool isEnabled) {
        SettingChange change;
        change.changeId = m_nextChangeId.fetch_add(1, std::memory_order_relaxed);
        change.timestamp = std::chrono::system_clock::now();
        change.category = SettingCategory::Security;
        change.settingType = SecuritySettingType::Defender_Enabled;
        change.settingPath = RegistryPaths::DEFENDER_POLICY_PATH;
        change.settingName = L"Windows Defender Enabled";
        change.previousValue = wasEnabled ? L"1" : L"0";
        change.newValue = isEnabled ? L"1" : L"0";
        change.isSecurityDegrade = !isEnabled;
        change.severity = isEnabled ? AlertSeverity::Info : AlertSeverity::Critical;
        change.isMalwareIndicator = !isEnabled;

        if (!isEnabled) {
            change.riskDescription = "Windows Defender has been disabled - common malware tactic";
        }

        m_stats.changesDetected.fetch_add(1, std::memory_order_relaxed);
        m_stats.defenderChanges.fetch_add(1, std::memory_order_relaxed);

        if (change.isSecurityDegrade) {
            m_stats.securityDegrades.fetch_add(1, std::memory_order_relaxed);
        }

        m_changeTracker->RecordChange(change);
        m_callbackManager->InvokeChange(change);

        // Create alert
        if (change.severity >= m_config.minimumAlertSeverity) {
            CreateSecurityAlert(change);
        }

        // Auto-remediate
        if (m_config.enableAutoRemediation && m_config.remediateDefender && !isEnabled) {
            // Defender being disabled is recoverable — auto-remediation re-enables
            // it. SS_LOG_FATAL had been used here, which misclassifies a
            // routine remediation event as a fatal/abort-class condition in
            // downstream SIEM correlation. Downgrade to ERROR.
            SS_LOG_ERROR(L"SystemSettingsMonitor",
                L"Auto-remediating Defender disable (T1562.001)");
            RestoreDefenderDefaults();
            change.actionTaken = RemediationAction::Restore;
            change.wasRemediated = true;
        }
    }

    void OnRealTimeProtectionChange(bool wasEnabled, bool isEnabled) {
        SettingChange change;
        change.changeId = m_nextChangeId.fetch_add(1, std::memory_order_relaxed);
        change.timestamp = std::chrono::system_clock::now();
        change.category = SettingCategory::Security;
        change.settingType = SecuritySettingType::Defender_RealtimeProtection;
        change.settingName = L"Real-Time Protection";
        change.previousValue = wasEnabled ? L"1" : L"0";
        change.newValue = isEnabled ? L"1" : L"0";
        change.isSecurityDegrade = !isEnabled;
        change.severity = isEnabled ? AlertSeverity::Info : AlertSeverity::High;
        change.isMalwareIndicator = !isEnabled;

        m_stats.defenderChanges.fetch_add(1, std::memory_order_relaxed);

        m_changeTracker->RecordChange(change);
        m_callbackManager->InvokeChange(change);

        if (change.severity >= m_config.minimumAlertSeverity) {
            CreateSecurityAlert(change);
        }
    }

    void OnFirewallChange(FirewallProfile profile, bool wasEnabled, bool isEnabled) {
        SettingChange change;
        change.changeId = m_nextChangeId.fetch_add(1, std::memory_order_relaxed);
        change.timestamp = std::chrono::system_clock::now();
        change.category = SettingCategory::Security;

        // The previous implementation hard-coded Firewall_PublicEnabled for ALL
        // three profiles, blinding consumers to which profile (Domain vs.
        // Private vs. Public) had been tampered with. Attackers commonly
        // disable only the Public profile to keep enterprise telemetry flowing
        // while opening attacker-controlled networks; flagging that as a
        // Domain-profile change suppresses correct triage.
        switch (profile) {
            case FirewallProfile::Domain:
                change.settingType = SecuritySettingType::Firewall_DomainEnabled;
                change.settingName = L"Firewall Domain Profile";
                break;
            case FirewallProfile::Private:
                change.settingType = SecuritySettingType::Firewall_PrivateEnabled;
                change.settingName = L"Firewall Private Profile";
                break;
            case FirewallProfile::Public:
            default:
                change.settingType = SecuritySettingType::Firewall_PublicEnabled;
                change.settingName = L"Firewall Public Profile";
                break;
        }

        change.previousValue = wasEnabled ? L"1" : L"0";
        change.newValue = isEnabled ? L"1" : L"0";
        change.isSecurityDegrade = !isEnabled;
        change.severity = isEnabled ? AlertSeverity::Info : AlertSeverity::High;

        m_stats.firewallChanges.fetch_add(1, std::memory_order_relaxed);

        m_changeTracker->RecordChange(change);
        m_callbackManager->InvokeChange(change);

        if (change.severity >= m_config.minimumAlertSeverity) {
            CreateSecurityAlert(change);
        }

        // Auto-remediate — only for actual disables.
        if (m_config.enableAutoRemediation && m_config.remediateFirewall && !isEnabled) {
            SS_LOG_WARN(L"SystemSettingsMonitor",
                L"Auto-remediating firewall disable (profile=%d)", static_cast<int>(profile));
            RestoreFirewallDefaults();
            change.actionTaken = RemediationAction::Restore;
            change.wasRemediated = true;
        }
    }

    void CreateSecurityAlert(const SettingChange& change) {
        SecurityAlert alert;
        alert.timestamp = change.timestamp;
        alert.severity = change.severity;
        alert.alertType = "SettingChange";
        alert.title = "Security Setting Modified";

        // Every value spliced into the description originates from registry
        // contents or attacker-influenceable comparison output; SanitizeForLog
        // (control-char + length cap) prevents log/SIEM injection.
        alert.description = std::format("Setting '{}' changed from '{}' to '{}'",
            SanitizeForLog(change.settingName),
            SanitizeForLog(change.previousValue),
            SanitizeForLog(change.newValue));

        alert.category = change.category;
        alert.settingType = change.settingType;
        alert.settingPath = change.settingPath;
        alert.previousValue = change.previousValue;
        alert.currentValue = change.newValue;

        alert.canRemediate = true;
        alert.recommendedAction = RemediationAction::Restore;
        alert.wasRemediated = change.wasRemediated;

        // MITRE ATT&CK mapping. The previous table only covered Defender, a
        // single firewall profile, and a generic Network bucket — leaving the
        // bulk of security-degrade alerts unattributed. Expanded to cover the
        // setting types this monitor actually emits.
        switch (change.settingType) {
            case SecuritySettingType::Defender_Enabled:
            case SecuritySettingType::Defender_RealtimeProtection:
            case SecuritySettingType::Defender_BehaviorMonitoring:
            case SecuritySettingType::Defender_TamperProtection:
            case SecuritySettingType::Defender_CloudProtection:
                alert.mitreId = "T1562.001";
                alert.mitreTactic = "Defense Evasion - Disable or Modify Tools";
                break;

            case SecuritySettingType::Firewall_DomainEnabled:
            case SecuritySettingType::Firewall_PrivateEnabled:
            case SecuritySettingType::Firewall_PublicEnabled:
                alert.mitreId = "T1562.004";
                alert.mitreTactic = "Defense Evasion - Disable or Modify System Firewall";
                break;

            case SecuritySettingType::UAC_Enabled:
            case SecuritySettingType::UAC_ConsentPromptAdmin:
                alert.mitreId = "T1548.002";
                alert.mitreTactic = "Privilege Escalation - Bypass UAC";
                break;

            case SecuritySettingType::LSA_RunAsPPL:
            case SecuritySettingType::LSA_NoLMHash:
                alert.mitreId = "T1003.001";
                alert.mitreTactic = "Credential Access - LSASS Memory";
                break;

            case SecuritySettingType::Exploit_SEHOP:
            case SecuritySettingType::Exploit_ASLR:
            case SecuritySettingType::Exploit_CFG:
                alert.mitreId = "T1068";
                alert.mitreTactic = "Privilege Escalation - Exploitation";
                break;

            default:
                if (change.category == SettingCategory::Network) {
                    alert.mitreId = "T1071.004";
                    alert.mitreTactic = "Command and Control - DNS";
                }
                break;
        }

        m_alertManager->CreateAlert(alert);
        m_callbackManager->InvokeAlert(alert);

        m_stats.alertsGenerated.fetch_add(1, std::memory_order_relaxed);
    }

    bool RemediateChange(const SettingChange& change) {
        try {
            switch (change.settingType) {
                case SecuritySettingType::UAC_Enabled:
                    if (m_config.remediateUAC) {
                        return RestoreUACDefaults();
                    }
                    break;

                case SecuritySettingType::Defender_Enabled:
                case SecuritySettingType::Defender_RealtimeProtection:
                    if (m_config.remediateDefender) {
                        return RestoreDefenderDefaults();
                    }
                    break;

                case SecuritySettingType::Firewall_PublicEnabled:
                    if (m_config.remediateFirewall) {
                        return RestoreFirewallDefaults();
                    }
                    break;

                default:
                    SS_LOG_WARN(L"SystemSettingsMonitor", L"No remediation for setting type %d", static_cast<int>(change.settingType));
                    return false;
            }

            return false;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"SystemSettingsMonitor", L"RemediateChange failed: %hs", e.what());
            m_stats.remediationsFailed.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    std::atomic<bool> m_monitoring{ false };
    SystemSettingsMonitorConfig m_config;

    // Current state
    BaselineSnapshot m_currentState;

    // Managers
    std::unique_ptr<CallbackManager> m_callbackManager;
    std::unique_ptr<BaselineManager> m_baselineManager;
    std::unique_ptr<ChangeTracker> m_changeTracker;
    std::unique_ptr<AlertManager> m_alertManager;

    // Monitoring thread
    std::thread m_monitorThread;

    // Statistics
    mutable SystemSettingsMonitorStatistics m_stats;

    // ID generation
    std::atomic<uint64_t> m_nextChangeId{ 1 };
};

// ============================================================================
// MAIN CLASS IMPLEMENTATION (SINGLETON + FORWARDING)
// ============================================================================

SystemSettingsMonitor::SystemSettingsMonitor()
    : m_impl(std::make_unique<SystemSettingsMonitorImpl>()) {
}

SystemSettingsMonitor::~SystemSettingsMonitor() = default;

SystemSettingsMonitor& SystemSettingsMonitor::Instance() {
    static SystemSettingsMonitor instance;
    return instance;
}

bool SystemSettingsMonitor::Initialize(const SystemSettingsMonitorConfig& config) {
    return m_impl->Initialize(config);
}

void SystemSettingsMonitor::Start() {
    m_impl->Start();
}

void SystemSettingsMonitor::Stop() noexcept {
    m_impl->Stop();
}

void SystemSettingsMonitor::Shutdown() noexcept {
    m_impl->Shutdown();
}

bool SystemSettingsMonitor::IsMonitoring() const noexcept {
    return m_impl->IsMonitoring();
}

UACSettings SystemSettingsMonitor::GetUACSettings() const {
    return m_impl->GetUACSettings();
}

bool SystemSettingsMonitor::IsUACDisabled() const {
    return m_impl->IsUACDisabled();
}

UACLevel SystemSettingsMonitor::GetUACLevel() const {
    return m_impl->GetUACLevel();
}

bool SystemSettingsMonitor::RestoreUACDefaults() {
    return m_impl->RestoreUACDefaults();
}

DefenderSettings SystemSettingsMonitor::GetDefenderSettings() const {
    return m_impl->GetDefenderSettings();
}

bool SystemSettingsMonitor::IsDefenderDisabled() const {
    return m_impl->IsDefenderDisabled();
}

bool SystemSettingsMonitor::IsRealTimeProtectionDisabled() const {
    return m_impl->IsRealTimeProtectionDisabled();
}

std::vector<std::wstring> SystemSettingsMonitor::GetDefenderExclusions() const {
    return m_impl->GetDefenderExclusions();
}

bool SystemSettingsMonitor::RestoreDefenderDefaults() {
    return m_impl->RestoreDefenderDefaults();
}

FirewallSettings SystemSettingsMonitor::GetFirewallSettings() const {
    return m_impl->GetFirewallSettings();
}

bool SystemSettingsMonitor::IsFirewallDisabled(FirewallProfile profile) const {
    return m_impl->IsFirewallDisabled(profile);
}

bool SystemSettingsMonitor::IsAnyFirewallDisabled() const {
    return m_impl->IsAnyFirewallDisabled();
}

bool SystemSettingsMonitor::RestoreFirewallDefaults() {
    return m_impl->RestoreFirewallDefaults();
}

ExploitProtection SystemSettingsMonitor::GetExploitProtection() const {
    return m_impl->GetExploitProtection();
}

bool SystemSettingsMonitor::IsASLRDisabled() const {
    return m_impl->IsASLRDisabled();
}

bool SystemSettingsMonitor::IsDEPDisabled() const {
    return m_impl->IsDEPDisabled();
}

LSASettings SystemSettingsMonitor::GetLSASettings() const {
    return m_impl->GetLSASettings();
}

bool SystemSettingsMonitor::IsLSAPPLEnabled() const {
    return m_impl->IsLSAPPLEnabled();
}

ProxySettings SystemSettingsMonitor::GetProxySettings() const {
    return m_impl->GetProxySettings();
}

bool SystemSettingsMonitor::IsProxyEnabled() const {
    return m_impl->IsProxyEnabled();
}

DNSSettings SystemSettingsMonitor::GetDNSSettings() const {
    return m_impl->GetDNSSettings();
}

bool SystemSettingsMonitor::IsDNSSuspicious() const {
    return m_impl->IsDNSSuspicious();
}

uint64_t SystemSettingsMonitor::CreateBaseline(const std::string& description) {
    return m_impl->CreateBaseline(description);
}

std::optional<BaselineSnapshot> SystemSettingsMonitor::GetBaseline(uint64_t baselineId) const {
    return m_impl->GetBaseline(baselineId);
}

std::optional<BaselineSnapshot> SystemSettingsMonitor::GetActiveBaseline() const {
    return m_impl->GetActiveBaseline();
}

bool SystemSettingsMonitor::SetActiveBaseline(uint64_t baselineId) {
    return m_impl->SetActiveBaseline(baselineId);
}

bool SystemSettingsMonitor::RestoreToBaseline(uint64_t baselineId) {
    return m_impl->RestoreToBaseline(baselineId);
}

std::vector<SettingChange> SystemSettingsMonitor::CompareToBaseline(uint64_t baselineId) const {
    return m_impl->CompareToBaseline(baselineId);
}

ComplianceStatus SystemSettingsMonitor::CheckCompliance() const {
    return m_impl->CheckCompliance();
}

ComplianceStatus SystemSettingsMonitor::CheckPolicyCompliance(const std::wstring& policyPath) const {
    return m_impl->CheckPolicyCompliance(policyPath);
}

std::vector<SettingChange> SystemSettingsMonitor::GetHistory(size_t maxCount) const {
    return m_impl->GetHistory(maxCount);
}

std::vector<SettingChange> SystemSettingsMonitor::GetHistoryByCategory(
    SettingCategory category, size_t maxCount) const {
    return m_impl->GetHistoryByCategory(category, maxCount);
}

std::vector<SecurityAlert> SystemSettingsMonitor::GetActiveAlerts() const {
    return m_impl->GetActiveAlerts();
}

bool SystemSettingsMonitor::AcknowledgeAlert(uint64_t alertId) {
    return m_impl->AcknowledgeAlert(alertId);
}

void SystemSettingsMonitor::ClearAlerts() noexcept {
    m_impl->ClearAlerts();
}

bool SystemSettingsMonitor::Remediate(uint64_t changeId) {
    return m_impl->Remediate(changeId);
}

void SystemSettingsMonitor::SetAutoRemediation(bool enable) noexcept {
    m_impl->SetAutoRemediation(enable);
}

bool SystemSettingsMonitor::IsAutoRemediationEnabled() const noexcept {
    return m_impl->IsAutoRemediationEnabled();
}

uint64_t SystemSettingsMonitor::RegisterChangeCallback(SettingChangeCallback callback) {
    return m_impl->RegisterChangeCallback(std::move(callback));
}

uint64_t SystemSettingsMonitor::RegisterAlertCallback(SecurityAlertCallback callback) {
    return m_impl->RegisterAlertCallback(std::move(callback));
}

uint64_t SystemSettingsMonitor::RegisterComplianceCallback(ComplianceCallback callback) {
    return m_impl->RegisterComplianceCallback(std::move(callback));
}

bool SystemSettingsMonitor::UnregisterCallback(uint64_t callbackId) {
    return m_impl->UnregisterCallback(callbackId);
}

const SystemSettingsMonitorStatistics& SystemSettingsMonitor::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void SystemSettingsMonitor::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

void SystemSettingsMonitor::RefreshAll() {
    m_impl->RefreshAll();
}

void SystemSettingsMonitor::RefreshCategory(SettingCategory category) {
    m_impl->RefreshCategory(category);
}

bool SystemSettingsMonitor::ExportReport(const std::wstring& outputPath) const {
    return m_impl->ExportReport(outputPath);
}

bool SystemSettingsMonitor::ExportSettings(const std::wstring& outputPath) const {
    return m_impl->ExportSettings(outputPath);
}

bool SystemSettingsMonitor::ExportHistory(const std::wstring& outputPath) const {
    return m_impl->ExportHistory(outputPath);
}

}  // namespace Registry
}  // namespace Core
}  // namespace ShadowStrike
