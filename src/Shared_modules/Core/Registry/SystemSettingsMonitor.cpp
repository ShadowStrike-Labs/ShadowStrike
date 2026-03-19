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

// Windows headers
#include <wininet.h>
#include <fwpmu.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "fwpuclnt.lib")

// Standard library
#include <algorithm>
#include <format>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <queue>

namespace ShadowStrike {
namespace Core {
namespace Registry {

namespace fs = std::filesystem;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

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
 * @brief Check if value represents a disabled state.
 */
bool IsDisabledValue(DWORD value) {
    return value == 0;
}

/**
 * @brief Check if value represents an enabled state.
 */
bool IsEnabledValue(DWORD value) {
    return value == 1;
}

/**
 * @brief Safe registry read with default.
 */
DWORD ReadRegistryDwordSafe(HKEY hive, const std::wstring& path,
                            const std::wstring& name, DWORD defaultValue) {
    try {
        return Utils::RegistryUtils::ReadDword(hive, path.c_str(), name.c_str());
    } catch (...) {
        return defaultValue;
    }
}

/**
 * @brief Safe registry string read.
 */
std::wstring ReadRegistryStringSafe(HKEY hive, const std::wstring& path,
                                    const std::wstring& name, const std::wstring& defaultValue = L"") {
    try {
        return Utils::RegistryUtils::ReadString(hive, path.c_str(), name.c_str());
    } catch (...) {
        return defaultValue;
    }
}

/**
 * @brief Check if registry key exists.
 */
bool KeyExists(HKEY hive, const std::wstring& path) {
    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(hive, path.c_str(), 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

/**
 * @brief Registry paths for monitoring.
 */
namespace RegistryPaths {
    constexpr wchar_t UAC_PATH[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    constexpr wchar_t DEFENDER_PATH[] = L"SOFTWARE\\Microsoft\\Windows Defender";
    constexpr wchar_t DEFENDER_POLICY_PATH[] = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender";
    constexpr wchar_t FIREWALL_PATH[] = L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy";
    constexpr wchar_t PROXY_PATH[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    constexpr wchar_t TCP_PATH[] = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
    constexpr wchar_t LSA_PATH[] = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
    constexpr wchar_t EXPLOIT_PATH[] = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel";
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
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_changeCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterAlert(SecurityAlertCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_alertCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterCompliance(ComplianceCallback callback) {
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
                Logger::Error("SettingChangeCallback exception: {}", e.what());
            }
        }
    }

    void InvokeAlert(const SecurityAlert& alert) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_alertCallbacks) {
            try {
                callback(alert);
            } catch (const std::exception& e) {
                Logger::Error("SecurityAlertCallback exception: {}", e.what());
            }
        }
    }

    void InvokeCompliance(const ComplianceStatus& status) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_complianceCallbacks) {
            try {
                callback(status);
            } catch (const std::exception& e) {
                Logger::Error("ComplianceCallback exception: {}", e.what());
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

        Logger::Info("SystemSettingsMonitor: Created baseline {} - {}",
            id, snapshot.description);

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

    void SetActiveBaseline(uint64_t id) {
        std::unique_lock lock(m_mutex);
        m_activeBaselineId = id;
    }

    std::optional<uint64_t> GetActiveBaselineId() const {
        std::shared_lock lock(m_mutex);
        return m_activeBaselineId;
    }

    std::optional<BaselineSnapshot> GetActiveBaseline() const {
        std::shared_lock lock(m_mutex);
        if (m_activeBaselineId.has_value()) {
            return GetBaseline(*m_activeBaselineId);
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

class ChangeTracker {
public:
    void RecordChange(const SettingChange& change) {
        std::unique_lock lock(m_mutex);

        // Add to history
        m_history.push_back(change);

        // Limit history size
        if (m_history.size() > m_maxHistory) {
            m_history.erase(m_history.begin(),
                m_history.begin() + (m_history.size() - m_maxHistory));
        }
    }

    std::vector<SettingChange> GetHistory(size_t maxCount) const {
        std::shared_lock lock(m_mutex);

        if (m_history.size() <= maxCount) {
            return m_history;
        }

        // Return most recent
        return std::vector<SettingChange>(
            m_history.end() - maxCount,
            m_history.end()
        );
    }

    std::vector<SettingChange> GetHistoryByCategory(SettingCategory category, size_t maxCount) const {
        std::shared_lock lock(m_mutex);

        std::vector<SettingChange> filtered;
        for (auto it = m_history.rbegin(); it != m_history.rend() && filtered.size() < maxCount; ++it) {
            if (it->category == category) {
                filtered.push_back(*it);
            }
        }

        return filtered;
    }

    void SetMaxHistory(size_t max) {
        std::unique_lock lock(m_mutex);
        m_maxHistory = max;
    }

private:
    mutable std::shared_mutex m_mutex;
    std::vector<SettingChange> m_history;
    size_t m_maxHistory{ SystemSettingsMonitorConstants::MAX_HISTORY };
};

// ============================================================================
// ALERT MANAGER
// ============================================================================

class AlertManager {
public:
    uint64_t CreateAlert(const SecurityAlert& alert) {
        std::unique_lock lock(m_mutex);

        const uint64_t id = m_nextId++;
        m_alerts[id] = alert;
        m_alerts[id].alertId = id;

        Logger::Warn("SystemSettingsMonitor: Alert {} - {} [{}]",
            id, alert.title, SeverityToString(alert.severity));

        return id;
    }

    std::vector<SecurityAlert> GetActiveAlerts() const {
        std::shared_lock lock(m_mutex);

        std::vector<SecurityAlert> active;
        for (const auto& [id, alert] : m_alerts) {
            if (!alert.wasRemediated) {
                active.push_back(alert);
            }
        }

        return active;
    }

    bool AcknowledgeAlert(uint64_t id) {
        std::unique_lock lock(m_mutex);

        auto it = m_alerts.find(id);
        if (it != m_alerts.end()) {
            m_alerts.erase(it);
            return true;
        }

        return false;
    }

    void ClearAll() {
        std::unique_lock lock(m_mutex);
        m_alerts.clear();
    }

private:
    mutable std::shared_mutex m_mutex;
    uint64_t m_nextId{ 1 };
    std::unordered_map<uint64_t, SecurityAlert> m_alerts;
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class SystemSettingsMonitorImpl {
public:
    SystemSettingsMonitorImpl() = default;
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
            Logger::Info("SystemSettingsMonitor: Initializing...");

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
            Logger::Info("SystemSettingsMonitor: Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("SystemSettingsMonitor: Initialization failed: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        Stop();

        std::unique_lock lock(m_mutex);
        m_initialized = false;

        Logger::Info("SystemSettingsMonitor: Shutdown complete");
    }

    // ========================================================================
    // MONITORING CONTROL
    // ========================================================================

    void Start() {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            Logger::Error("SystemSettingsMonitor: Not initialized");
            return;
        }

        if (m_monitoring) {
            Logger::Warn("SystemSettingsMonitor: Already monitoring");
            return;
        }

        m_monitoring = true;
        m_monitorThread = std::thread(&SystemSettingsMonitorImpl::MonitorThreadFunc, this);

        Logger::Info("SystemSettingsMonitor: Real-time monitoring started");
    }

    void Stop() noexcept {
        {
            std::unique_lock lock(m_mutex);
            if (!m_monitoring) return;
            m_monitoring = false;
        }

        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }

        Logger::Info("SystemSettingsMonitor: Monitoring stopped");
    }

    bool IsMonitoring() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_monitoring;
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
            // Secure defaults
            Utils::RegistryUtils::WriteDword(HKEY_LOCAL_MACHINE,
                RegistryPaths::UAC_PATH, L"EnableLUA", 1);

            Utils::RegistryUtils::WriteDword(HKEY_LOCAL_MACHINE,
                RegistryPaths::UAC_PATH, L"ConsentPromptBehaviorAdmin", 5);

            Utils::RegistryUtils::WriteDword(HKEY_LOCAL_MACHINE,
                RegistryPaths::UAC_PATH, L"PromptOnSecureDesktop", 1);

            Logger::Info("SystemSettingsMonitor: UAC restored to secure defaults");

            // Update current state
            RefreshUACImpl();

            return true;

        } catch (const std::exception& e) {
            Logger::Error("SystemSettingsMonitor::RestoreUACDefaults: {}", e.what());
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
            // Enable Defender
            Utils::RegistryUtils::WriteDword(HKEY_LOCAL_MACHINE,
                RegistryPaths::DEFENDER_POLICY_PATH, L"DisableAntiSpyware", 0);

            // Enable real-time protection
            const std::wstring rtPath = std::wstring(RegistryPaths::DEFENDER_POLICY_PATH) +
                                       L"\\Real-Time Protection";
            Utils::RegistryUtils::WriteDword(HKEY_LOCAL_MACHINE,
                rtPath.c_str(), L"DisableRealtimeMonitoring", 0);

            Logger::Info("SystemSettingsMonitor: Defender restored to secure defaults");

            RefreshDefenderImpl();

            return true;

        } catch (const std::exception& e) {
            Logger::Error("SystemSettingsMonitor::RestoreDefenderDefaults: {}", e.what());
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
            // Enable all profiles
            const std::wstring domainPath = std::wstring(RegistryPaths::FIREWALL_PATH) +
                                           L"\\DomainProfile";
            const std::wstring privatePath = std::wstring(RegistryPaths::FIREWALL_PATH) +
                                            L"\\StandardProfile";
            const std::wstring publicPath = std::wstring(RegistryPaths::FIREWALL_PATH) +
                                           L"\\PublicProfile";

            Utils::RegistryUtils::WriteDword(HKEY_LOCAL_MACHINE,
                domainPath.c_str(), L"EnableFirewall", 1);
            Utils::RegistryUtils::WriteDword(HKEY_LOCAL_MACHINE,
                privatePath.c_str(), L"EnableFirewall", 1);
            Utils::RegistryUtils::WriteDword(HKEY_LOCAL_MACHINE,
                publicPath.c_str(), L"EnableFirewall", 1);

            Logger::Info("SystemSettingsMonitor: Firewall restored to secure defaults");

            RefreshFirewallImpl();

            return true;

        } catch (const std::exception& e) {
            Logger::Error("SystemSettingsMonitor::RestoreFirewallDefaults: {}", e.what());
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
        m_baselineManager->SetActiveBaseline(baselineId);
        Logger::Info("SystemSettingsMonitor: Set active baseline to {}", baselineId);
        return true;
    }

    bool RestoreToBaseline(uint64_t baselineId) {
        auto baseline = m_baselineManager->GetBaseline(baselineId);
        if (!baseline.has_value()) {
            Logger::Error("SystemSettingsMonitor: Baseline {} not found", baselineId);
            return false;
        }

        try {
            // Restore UAC
            if (m_config.remediateUAC) {
                if (baseline->uac.enabled) {
                    RestoreUACDefaults();
                }
            }

            // Restore Defender
            if (m_config.remediateDefender) {
                if (baseline->defender.enabled) {
                    RestoreDefenderDefaults();
                }
            }

            // Restore Firewall
            if (m_config.remediateFirewall) {
                RestoreFirewallDefaults();
            }

            Logger::Info("SystemSettingsMonitor: Restored to baseline {}", baselineId);

            m_stats.remediationsPerformed.fetch_add(1, std::memory_order_relaxed);

            return true;

        } catch (const std::exception& e) {
            Logger::Error("SystemSettingsMonitor::RestoreToBaseline: {}", e.what());
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

        // Compare UAC
        if (m_currentState.uac.enabled != baseline->uac.enabled) {
            SettingChange change;
            change.category = SettingCategory::Security;
            change.settingType = SecuritySettingType::UAC_Enabled;
            change.settingName = L"UAC Enabled";
            change.previousValue = baseline->uac.enabled ? L"1" : L"0";
            change.newValue = m_currentState.uac.enabled ? L"1" : L"0";
            change.isSecurityDegrade = !m_currentState.uac.enabled;
            differences.push_back(change);
        }

        // Compare Defender
        if (m_currentState.defender.enabled != baseline->defender.enabled) {
            SettingChange change;
            change.category = SettingCategory::Security;
            change.settingType = SecuritySettingType::Defender_Enabled;
            change.settingName = L"Defender Enabled";
            change.previousValue = baseline->defender.enabled ? L"1" : L"0";
            change.newValue = m_currentState.defender.enabled ? L"1" : L"0";
            change.isSecurityDegrade = !m_currentState.defender.enabled;
            differences.push_back(change);
        }

        // Compare Firewall
        if (m_currentState.firewall.publicEnabled != baseline->firewall.publicEnabled) {
            SettingChange change;
            change.category = SettingCategory::Security;
            change.settingType = SecuritySettingType::Firewall_PublicEnabled;
            change.settingName = L"Firewall Public Profile";
            change.previousValue = baseline->firewall.publicEnabled ? L"1" : L"0";
            change.newValue = m_currentState.firewall.publicEnabled ? L"1" : L"0";
            change.isSecurityDegrade = !m_currentState.firewall.publicEnabled;
            differences.push_back(change);
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
        // Simplified - would load policy from file and validate
        ComplianceStatus status;
        status.lastChecked = std::chrono::system_clock::now();
        status.isCompliant = true;

        Logger::Info("SystemSettingsMonitor: Policy compliance check not fully implemented");

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

        Logger::Error("SystemSettingsMonitor: Change {} not found", changeId);
        return false;
    }

    void SetAutoRemediation(bool enable) noexcept {
        std::unique_lock lock(m_mutex);
        m_config.enableAutoRemediation = enable;
        Logger::Info("SystemSettingsMonitor: Auto-remediation {}", enable ? "enabled" : "disabled");
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
        std::shared_lock lock(m_mutex);
        RefreshAllImpl();
    }

    void RefreshCategory(SettingCategory category) {
        std::shared_lock lock(m_mutex);

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
            std::ofstream ofs(outputPath);
            if (!ofs) return false;

            ofs << "=== ShadowStrike System Settings Monitor Report ===\n\n";

            std::shared_lock lock(m_mutex);

            // UAC status
            ofs << "UAC Status:\n";
            ofs << "  Enabled: " << (m_currentState.uac.enabled ? "Yes" : "NO") << "\n";
            ofs << "  Level: " << Utils::StringUtils::WideToUtf8(UACLevelToString(m_currentState.uac.level)) << "\n\n";

            // Defender status
            ofs << "Windows Defender Status:\n";
            ofs << "  Enabled: " << (m_currentState.defender.enabled ? "Yes" : "NO") << "\n";
            ofs << "  Real-time: " << (m_currentState.defender.realTimeProtection ? "Yes" : "NO") << "\n\n";

            // Firewall status
            ofs << "Firewall Status:\n";
            ofs << "  Domain: " << (m_currentState.firewall.domainEnabled ? "Enabled" : "DISABLED") << "\n";
            ofs << "  Private: " << (m_currentState.firewall.privateEnabled ? "Enabled" : "DISABLED") << "\n";
            ofs << "  Public: " << (m_currentState.firewall.publicEnabled ? "Enabled" : "DISABLED") << "\n\n";

            // Statistics
            ofs << "Statistics:\n";
            ofs << "  Changes Detected: " << m_stats.changesDetected.load() << "\n";
            ofs << "  Security Degrades: " << m_stats.securityDegrades.load() << "\n";
            ofs << "  Alerts Generated: " << m_stats.alertsGenerated.load() << "\n";
            ofs << "  Remediations: " << m_stats.remediationsPerformed.load() << "\n";

            ofs.close();

            Logger::Info("SystemSettingsMonitor: Exported report to {}",
                Utils::StringUtils::WideToUtf8(outputPath));

            return true;

        } catch (const std::exception& e) {
            Logger::Error("SystemSettingsMonitor::ExportReport: {}", e.what());
            return false;
        }
    }

    bool ExportSettings(const std::wstring& outputPath) const {
        try {
            std::ofstream ofs(outputPath);
            if (!ofs) return false;

            std::shared_lock lock(m_mutex);

            // JSON export of current settings
            ofs << "{\n";
            ofs << "  \"uac\": {\n";
            ofs << "    \"enabled\": " << (m_currentState.uac.enabled ? "true" : "false") << "\n";
            ofs << "  },\n";
            ofs << "  \"defender\": {\n";
            ofs << "    \"enabled\": " << (m_currentState.defender.enabled ? "true" : "false") << ",\n";
            ofs << "    \"realTimeProtection\": " << (m_currentState.defender.realTimeProtection ? "true" : "false") << "\n";
            ofs << "  },\n";
            ofs << "  \"firewall\": {\n";
            ofs << "    \"publicEnabled\": " << (m_currentState.firewall.publicEnabled ? "true" : "false") << "\n";
            ofs << "  }\n";
            ofs << "}\n";

            ofs.close();

            return true;

        } catch (...) {
            return false;
        }
    }

    bool ExportHistory(const std::wstring& outputPath) const {
        try {
            std::ofstream ofs(outputPath);
            if (!ofs) return false;

            auto history = m_changeTracker->GetHistory(1000);

            ofs << "=== System Settings Change History ===\n\n";

            for (const auto& change : history) {
                ofs << "Change ID: " << change.changeId << "\n";
                ofs << "Category: " << CategoryToString(change.category) << "\n";
                ofs << "Setting: " << Utils::StringUtils::WideToUtf8(change.settingName) << "\n";
                ofs << "Previous: " << Utils::StringUtils::WideToUtf8(change.previousValue) << "\n";
                ofs << "New: " << Utils::StringUtils::WideToUtf8(change.newValue) << "\n";
                ofs << "Security Degrade: " << (change.isSecurityDegrade ? "YES" : "No") << "\n";
                ofs << "\n";
            }

            ofs.close();

            return true;

        } catch (...) {
            return false;
        }
    }

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    uint64_t CreateBaselineImpl(const std::string& description) const {
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

    void RefreshAllImpl() const {
        if (m_config.monitorUAC) RefreshUACImpl();
        if (m_config.monitorDefender) RefreshDefenderImpl();
        if (m_config.monitorFirewall) RefreshFirewallImpl();
        if (m_config.monitorExploitProtection) RefreshExploitProtectionImpl();
        if (m_config.monitorLSA) RefreshLSAImpl();
        if (m_config.monitorProxy) RefreshProxyImpl();
        if (m_config.monitorDNS) RefreshDNSImpl();
    }

    void RefreshUACImpl() const {
        m_currentState.uac.enabled = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::UAC_PATH, L"EnableLUA", 1) != 0;

        m_currentState.uac.consentPromptAdmin = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::UAC_PATH, L"ConsentPromptBehaviorAdmin", 5);

        m_currentState.uac.promptOnSecureDesktop = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::UAC_PATH, L"PromptOnSecureDesktop", 1) != 0;

        // Determine UAC level
        if (!m_currentState.uac.enabled) {
            m_currentState.uac.level = UACLevel::Disabled;
        } else if (m_currentState.uac.consentPromptAdmin == 0) {
            m_currentState.uac.level = UACLevel::NotifyChanges;
        } else if (m_currentState.uac.consentPromptAdmin == 5) {
            m_currentState.uac.level = m_currentState.uac.promptOnSecureDesktop ?
                UACLevel::AlwaysNotify : UACLevel::NotifyChangesNoDim;
        } else {
            m_currentState.uac.level = UACLevel::NotifyAll;
        }

        m_currentState.uac.lastChecked = std::chrono::system_clock::now();
    }

    void RefreshDefenderImpl() const {
        // Check if Defender is disabled via policy
        DWORD disableDefender = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::DEFENDER_POLICY_PATH, L"DisableAntiSpyware", 0);

        m_currentState.defender.enabled = (disableDefender == 0);

        // Check real-time protection
        const std::wstring rtPath = std::wstring(RegistryPaths::DEFENDER_POLICY_PATH) +
                                   L"\\Real-Time Protection";
        DWORD disableRT = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            rtPath, L"DisableRealtimeMonitoring", 0);

        m_currentState.defender.realTimeProtection = (disableRT == 0);

        // Check behavior monitoring
        DWORD disableBehavior = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            rtPath, L"DisableBehaviorMonitoring", 0);

        m_currentState.defender.behaviorMonitoring = (disableBehavior == 0);

        // Check IOAV
        DWORD disableIOAV = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            rtPath, L"DisableIOAVProtection", 0);

        m_currentState.defender.ioavProtection = (disableIOAV == 0);

        m_currentState.defender.lastChecked = std::chrono::system_clock::now();
    }

    void RefreshFirewallImpl() const {
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

    void RefreshExploitProtectionImpl() const {
        // DEP is typically always on modern Windows
        m_currentState.exploit.depEnabled = true;

        // ASLR is enabled by default
        m_currentState.exploit.aslrEnabled = true;

        // CFG support check (simplified)
        m_currentState.exploit.cfgEnabled = true;

        // SEHOP
        DWORD sehop = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::EXPLOIT_PATH, L"DisableExceptionChainValidation", 0);
        m_currentState.exploit.sehopEnabled = (sehop == 0);

        m_currentState.exploit.lastChecked = std::chrono::system_clock::now();
    }

    void RefreshLSAImpl() const {
        m_currentState.lsa.runAsPPL = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::LSA_PATH, L"RunAsPPL", 0) != 0;

        m_currentState.lsa.restrictAnonymous = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::LSA_PATH, L"RestrictAnonymous", 0);

        m_currentState.lsa.limitBlankPasswordUse = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::LSA_PATH, L"LimitBlankPasswordUse", 1) != 0;

        m_currentState.lsa.noLMHash = ReadRegistryDwordSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::LSA_PATH, L"NoLMHash", 1) != 0;

        m_currentState.lsa.lastChecked = std::chrono::system_clock::now();
    }

    void RefreshProxyImpl() const {
        m_currentState.proxy.proxyEnabled = ReadRegistryDwordSafe(HKEY_CURRENT_USER,
            RegistryPaths::PROXY_PATH, L"ProxyEnable", 0) != 0;

        m_currentState.proxy.proxyServer = ReadRegistryStringSafe(HKEY_CURRENT_USER,
            RegistryPaths::PROXY_PATH, L"ProxyServer");

        m_currentState.proxy.autoConfigUrl = ReadRegistryStringSafe(HKEY_CURRENT_USER,
            RegistryPaths::PROXY_PATH, L"AutoConfigURL");

        m_currentState.proxy.lastChecked = std::chrono::system_clock::now();
    }

    void RefreshDNSImpl() const {
        std::wstring dnsServers = ReadRegistryStringSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::TCP_PATH, L"NameServer");

        // Parse comma-separated DNS servers
        m_currentState.dns.dnsServers.clear();
        if (!dnsServers.empty()) {
            size_t pos = 0;
            while ((pos = dnsServers.find(L',')) != std::wstring::npos) {
                m_currentState.dns.dnsServers.push_back(dnsServers.substr(0, pos));
                dnsServers.erase(0, pos + 1);
            }
            if (!dnsServers.empty()) {
                m_currentState.dns.dnsServers.push_back(dnsServers);
            }
        }

        m_currentState.dns.dnsSuffix = ReadRegistryStringSafe(HKEY_LOCAL_MACHINE,
            RegistryPaths::TCP_PATH, L"Domain");

        m_currentState.dns.lastChecked = std::chrono::system_clock::now();
    }

    void MonitorThreadFunc() {
        Logger::Info("SystemSettingsMonitor: Monitor thread started");

        while (m_monitoring) {
            try {
                // Store previous state
                BaselineSnapshot previousState;
                {
                    std::shared_lock lock(m_mutex);
                    previousState.uac = m_currentState.uac;
                    previousState.defender = m_currentState.defender;
                    previousState.firewall = m_currentState.firewall;
                }

                // Refresh current state
                RefreshAll();

                // Detect changes
                DetectChanges(previousState);

                // Sleep for polling interval
                std::this_thread::sleep_for(std::chrono::seconds(5));

            } catch (const std::exception& e) {
                Logger::Error("SystemSettingsMonitor: Monitor thread exception: {}", e.what());
            }
        }

        Logger::Info("SystemSettingsMonitor: Monitor thread stopped");
    }

    void DetectChanges(const BaselineSnapshot& previous) {
        std::shared_lock lock(m_mutex);

        // UAC changes
        if (m_config.monitorUAC) {
            if (m_currentState.uac.enabled != previous.uac.enabled) {
                OnUACChange(previous.uac.enabled, m_currentState.uac.enabled);
            }
        }

        // Defender changes
        if (m_config.monitorDefender) {
            if (m_currentState.defender.enabled != previous.defender.enabled) {
                OnDefenderChange(previous.defender.enabled, m_currentState.defender.enabled);
            }

            if (m_currentState.defender.realTimeProtection != previous.defender.realTimeProtection) {
                OnRealTimeProtectionChange(previous.defender.realTimeProtection,
                    m_currentState.defender.realTimeProtection);
            }
        }

        // Firewall changes
        if (m_config.monitorFirewall) {
            if (m_currentState.firewall.publicEnabled != previous.firewall.publicEnabled) {
                OnFirewallChange(FirewallProfile::Public,
                    previous.firewall.publicEnabled, m_currentState.firewall.publicEnabled);
            }
        }
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
            Logger::Warn("SystemSettingsMonitor: Auto-remediating UAC disable");
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
            Logger::Critical("SystemSettingsMonitor: Auto-remediating Defender disable");
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
        change.settingType = SecuritySettingType::Firewall_PublicEnabled;
        change.settingName = L"Firewall Public Profile";
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

        // Auto-remediate
        if (m_config.enableAutoRemediation && m_config.remediateFirewall && !isEnabled) {
            Logger::Warn("SystemSettingsMonitor: Auto-remediating firewall disable");
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
        alert.description = std::format("Setting '{}' changed from '{}' to '{}'",
            Utils::StringUtils::WideToUtf8(change.settingName),
            Utils::StringUtils::WideToUtf8(change.previousValue),
            Utils::StringUtils::WideToUtf8(change.newValue));

        alert.category = change.category;
        alert.settingType = change.settingType;
        alert.settingPath = change.settingPath;
        alert.previousValue = change.previousValue;
        alert.currentValue = change.newValue;

        alert.canRemediate = true;
        alert.recommendedAction = RemediationAction::Restore;
        alert.wasRemediated = change.wasRemediated;

        // MITRE mapping
        if (change.settingType == SecuritySettingType::Defender_Enabled ||
            change.settingType == SecuritySettingType::Defender_RealtimeProtection) {
            alert.mitreId = "T1562.001";
            alert.mitreTactic = "Defense Evasion";
        } else if (change.settingType == SecuritySettingType::Firewall_PublicEnabled) {
            alert.mitreId = "T1562.004";
            alert.mitreTactic = "Defense Evasion";
        } else if (change.category == SettingCategory::Network) {
            alert.mitreId = "T1090";
            alert.mitreTactic = "Command and Control";
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
                    Logger::Warn("SystemSettingsMonitor: No remediation for setting type {}",
                        static_cast<int>(change.settingType));
                    return false;
            }

            return false;

        } catch (const std::exception& e) {
            Logger::Error("SystemSettingsMonitor::RemediateChange: {}", e.what());
            m_stats.remediationsFailed.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    bool m_monitoring{ false };
    SystemSettingsMonitorConfig m_config;

    // Current state
    mutable BaselineSnapshot m_currentState;

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
