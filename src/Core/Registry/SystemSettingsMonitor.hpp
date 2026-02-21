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
 * ShadowStrike Core Registry - SYSTEM SETTINGS MONITOR (The Config Guardian)
 * ============================================================================
 *
 * @file SystemSettingsMonitor.hpp
 * @brief Enterprise-grade OS security configuration monitoring engine.
 *
 * This module provides comprehensive monitoring of Windows security settings,
 * detecting unauthorized configuration changes that could weaken system
 * defenses or enable malicious activity.
 *
 * Key Capabilities:
 * =================
 * 1. SECURITY SETTINGS
 *    - UAC level monitoring
 *    - Windows Defender status
 *    - Firewall configuration
 *    - Windows Update settings
 *    - ASLR/DEP/CFG settings
 *
 * 2. NETWORK CONFIGURATION
 *    - Proxy settings
 *    - DNS configuration
 *    - WinHTTP settings
 *    - Network profiles
 *    - HOSTS file (complementary)
 *
 * 3. SHELL CONFIGURATION
 *    - File associations
 *    - Context menu handlers
 *    - Shell extensions
 *    - Default programs
 *
 * 4. POLICY SETTINGS
 *    - Local security policy
 *    - Group Policy objects
 *    - AppLocker/WDAC
 *    - Software Restriction Policies
 *
 * 5. AUTHENTICATION SETTINGS
 *    - LSA configuration
 *    - Credential providers
 *    - Smart card settings
 *    - Authentication packages
 *
 * System Settings Architecture:
 * =============================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                      SystemSettingsMonitor                          │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │SecurityMonitor│ │NetworkMonitor│  │     ShellMonitor         │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - UAC        │  │ - Proxy      │  │ - Associations           │  │
 *   │  │ - Defender   │  │ - DNS        │  │ - Context menu           │  │
 *   │  │ - Firewall   │  │ - WinHTTP    │  │ - Extensions             │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │PolicyMonitor │  │ AuthMonitor  │  │    AlertEngine           │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Group Pol  │  │ - LSA        │  │ - Severity               │  │
 *   │  │ - AppLocker  │  │ - Cred Prov  │  │ - Notifications          │  │
 *   │  │ - SRP        │  │ - Auth Pkg   │  │ - Auto-remediation       │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Monitored Registry Locations:
 * =============================
 * UAC:
 *   - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
 *   - EnableLUA, ConsentPromptBehaviorAdmin, etc.
 *
 * Defender:
 *   - HKLM\SOFTWARE\Microsoft\Windows Defender
 *   - HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
 *
 * Firewall:
 *   - HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy
 *
 * Proxy/Network:
 *   - HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
 *   - HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
 *
 * LSA:
 *   - HKLM\SYSTEM\CurrentControlSet\Control\Lsa
 *
 * Integration Points:
 * ===================
 * - RegistryMonitor: Real-time change detection
 * - NetworkMonitor: Network configuration correlation
 * - ThreatIntel: Known malware configuration patterns
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1562: Impair Defenses
 * - T1112: Modify Registry
 * - T1090: Proxy
 * - T1557: LLMNR/NBT-NS Poisoning
 * - T1222: File and Directory Permissions Modification
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Real-time monitoring via callbacks
 * - State protected by shared mutex
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see RegistryMonitor.hpp for low-level monitoring
 * @see PersistenceDetector.hpp for persistence mechanisms
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/RegistryUtils.hpp"      // Registry access
#include "../../Utils/SystemUtils.hpp"        // System info
#include "../../Utils/NetworkUtils.hpp"       // Network settings
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // Malware patterns

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>

namespace ShadowStrike {
namespace Core {
namespace Registry {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class SystemSettingsMonitorImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace SystemSettingsMonitorConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Limits
    constexpr size_t MAX_ALERTS = 10000;
    constexpr size_t MAX_HISTORY = 5000;

    // UAC levels
    constexpr uint32_t UAC_DISABLED = 0;
    constexpr uint32_t UAC_NOTIFY_CHANGES = 1;
    constexpr uint32_t UAC_NOTIFY_CHANGES_NO_DIM = 2;
    constexpr uint32_t UAC_NOTIFY_ALL = 3;
    constexpr uint32_t UAC_ALWAYS_NOTIFY = 4;

    // Defender flags
    constexpr uint32_t DEFENDER_ENABLED = 0;
    constexpr uint32_t DEFENDER_DISABLED = 1;

    // Auto-remediation delay
    constexpr uint32_t REMEDIATION_DELAY_MS = 100;

}  // namespace SystemSettingsMonitorConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum SettingCategory
 * @brief Category of system setting.
 */
enum class SettingCategory : uint8_t {
    Unknown = 0,
    Security = 1,                  // UAC, Defender, Firewall
    Network = 2,                   // Proxy, DNS, TCP/IP
    Shell = 3,                     // Associations, context menu
    Policy = 4,                    // Group Policy, AppLocker
    Authentication = 5,            // LSA, credential providers
    Update = 6,                    // Windows Update
    Privacy = 7,                   // Telemetry, data collection
    Performance = 8                // Power settings, memory
};

/**
 * @enum SecuritySettingType
 * @brief Type of security setting.
 */
enum class SecuritySettingType : uint16_t {
    Unknown = 0,

    // UAC settings
    UAC_Enabled = 1,
    UAC_ConsentPromptAdmin = 2,
    UAC_ConsentPromptUser = 3,
    UAC_PromptOnSecureDesktop = 4,
    UAC_DetectInstallations = 5,
    UAC_RunAllAdminsInAAM = 6,
    UAC_ValidateAdminCodeSignatures = 7,

    // Defender settings
    Defender_Enabled = 10,
    Defender_RealtimeProtection = 11,
    Defender_BehaviorMonitoring = 12,
    Defender_IOAV = 13,
    Defender_CloudProtection = 14,
    Defender_ControlledFolderAccess = 15,
    Defender_TamperProtection = 16,
    Defender_ExclusionPaths = 17,
    Defender_ExclusionExtensions = 18,
    Defender_ExclusionProcesses = 19,

    // Firewall settings
    Firewall_DomainEnabled = 20,
    Firewall_PrivateEnabled = 21,
    Firewall_PublicEnabled = 22,
    Firewall_DefaultInbound = 23,
    Firewall_DefaultOutbound = 24,

    // ASLR/DEP/CFG
    Exploit_ASLR = 30,
    Exploit_DEP = 31,
    Exploit_CFG = 32,
    Exploit_SEHOP = 33,
    Exploit_HeapTermination = 34,

    // LSA settings
    LSA_RunAsPPL = 40,
    LSA_RestrictAnonymous = 41,
    LSA_LimitBlankPasswords = 42,
    LSA_NoLMHash = 43,
    LSA_AuditPolicy = 44,

    // Credential Guard
    CredGuard_Enabled = 50,
    CredGuard_UEFI = 51,

    // Network settings
    Network_ProxyEnabled = 60,
    Network_ProxyServer = 61,
    Network_ProxyOverride = 62,
    Network_AutoDetect = 63,
    Network_AutoConfigUrl = 64,
    Network_DNS_Servers = 65,
    Network_DNS_Suffix = 66,

    // Shell settings
    Shell_FileAssociation = 70,
    Shell_ContextMenuHandler = 71,
    Shell_ShellExtension = 72,
    Shell_DefaultBrowser = 73,
    Shell_DefaultProgram = 74,

    // Policy settings
    Policy_AppLocker = 80,
    Policy_SRP = 81,
    Policy_WDAC = 82,
    Policy_ScriptExecution = 83,

    // Update settings
    Update_AutoUpdate = 90,
    Update_NotifyLevel = 91,
    Update_DeferUpdates = 92
};

/**
 * @enum ChangeType
 * @brief Type of setting change.
 */
enum class ChangeType : uint8_t {
    Created = 0,
    Modified = 1,
    Deleted = 2,
    Reset = 3
};

/**
 * @enum AlertSeverity
 * @brief Severity of security alert.
 */
enum class AlertSeverity : uint8_t {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

/**
 * @enum RemediationAction
 * @brief Auto-remediation action.
 */
enum class RemediationAction : uint8_t {
    None = 0,
    Restore = 1,                   // Restore to baseline
    Block = 2,                     // Block the change
    Alert = 3,                     // Alert only
    Quarantine = 4                 // Quarantine responsible process
};

/**
 * @enum UACLevel
 * @brief User Account Control level.
 */
enum class UACLevel : uint8_t {
    Disabled = 0,
    NotifyChanges = 1,
    NotifyChangesNoDim = 2,
    NotifyAll = 3,
    AlwaysNotify = 4
};

/**
 * @enum FirewallProfile
 * @brief Windows Firewall profile.
 */
enum class FirewallProfile : uint8_t {
    Domain = 0,
    Private = 1,
    Public = 2,
    All = 3
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct UACSettings
 * @brief Current UAC configuration.
 */
struct alignas(32) UACSettings {
    bool enabled{ true };
    UACLevel level{ UACLevel::NotifyChanges };
    uint32_t consentPromptAdmin{ 5 };
    uint32_t consentPromptUser{ 3 };
    bool promptOnSecureDesktop{ true };
    bool detectInstallations{ true };
    bool runAllAdminsInAAM{ true };
    bool validateAdminCodeSignatures{ false };
    bool filterAdministratorToken{ true };

    std::chrono::system_clock::time_point lastChecked;
};

/**
 * @struct DefenderSettings
 * @brief Current Windows Defender configuration.
 */
struct alignas(128) DefenderSettings {
    bool enabled{ true };
    bool realTimeProtection{ true };
    bool behaviorMonitoring{ true };
    bool ioavProtection{ true };
    bool cloudProtection{ true };
    bool controlledFolderAccess{ false };
    bool tamperProtection{ true };
    bool networkProtection{ false };
    bool potentiallyUnwantedApps{ false };

    // Exclusions
    std::vector<std::wstring> excludedPaths;
    std::vector<std::wstring> excludedExtensions;
    std::vector<std::wstring> excludedProcesses;

    // Signatures
    std::wstring signatureVersion;
    std::chrono::system_clock::time_point lastSignatureUpdate;
    std::chrono::system_clock::time_point lastFullScan;

    std::chrono::system_clock::time_point lastChecked;
};

/**
 * @struct FirewallSettings
 * @brief Current firewall configuration.
 */
struct alignas(64) FirewallSettings {
    bool domainEnabled{ true };
    bool privateEnabled{ true };
    bool publicEnabled{ true };

    uint32_t domainDefaultInbound{ 1 };  // 1 = Block
    uint32_t domainDefaultOutbound{ 0 }; // 0 = Allow
    uint32_t privateDefaultInbound{ 1 };
    uint32_t privateDefaultOutbound{ 0 };
    uint32_t publicDefaultInbound{ 1 };
    uint32_t publicDefaultOutbound{ 0 };

    bool notifyOnBlocked{ true };
    bool allowLocalPolicyMerge{ true };

    std::chrono::system_clock::time_point lastChecked;
};

/**
 * @struct ExploitProtection
 * @brief System exploit protection settings.
 */
struct alignas(32) ExploitProtection {
    bool aslrEnabled{ true };
    bool depEnabled{ true };
    bool cfgEnabled{ true };
    bool sehopEnabled{ true };
    bool heapTerminationEnabled{ true };

    std::chrono::system_clock::time_point lastChecked;
};

/**
 * @struct LSASettings
 * @brief LSA security settings.
 */
struct alignas(32) LSASettings {
    bool runAsPPL{ false };
    uint32_t restrictAnonymous{ 0 };
    bool limitBlankPasswordUse{ true };
    bool noLMHash{ true };
    uint32_t lmCompatibilityLevel{ 3 };

    std::chrono::system_clock::time_point lastChecked;
};

/**
 * @struct ProxySettings
 * @brief Network proxy configuration.
 */
struct alignas(128) ProxySettings {
    bool proxyEnabled{ false };
    std::wstring proxyServer;
    std::wstring proxyOverride;
    bool autoDetect{ true };
    std::wstring autoConfigUrl;

    // Per-user vs system-wide
    bool isSystemWide{ false };

    std::chrono::system_clock::time_point lastChecked;
};

/**
 * @struct DNSSettings
 * @brief DNS configuration.
 */
struct alignas(128) DNSSettings {
    std::vector<std::wstring> dnsServers;
    std::wstring dnsSuffix;
    std::vector<std::wstring> searchList;

    bool useDHCP{ true };
    bool registerAdapterName{ false };

    // DNS over HTTPS
    bool dohEnabled{ false };
    std::wstring dohServer;

    std::chrono::system_clock::time_point lastChecked;
};

/**
 * @struct SettingChange
 * @brief Record of setting change.
 */
struct alignas(256) SettingChange {
    uint64_t changeId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // What changed
    SettingCategory category{ SettingCategory::Unknown };
    SecuritySettingType settingType{ SecuritySettingType::Unknown };
    std::wstring settingPath;
    std::wstring settingName;

    // Change details
    ChangeType changeType{ ChangeType::Modified };
    std::wstring previousValue;
    std::wstring newValue;

    // Who made change
    uint32_t processId{ 0 };
    std::wstring processPath;
    std::wstring processUser;

    // Security assessment
    AlertSeverity severity{ AlertSeverity::Info };
    bool isSecurityDegrade{ false };
    bool isMalwareIndicator{ false };
    std::string riskDescription;

    // Remediation
    RemediationAction actionTaken{ RemediationAction::None };
    bool wasRemediated{ false };
};

/**
 * @struct SecurityAlert
 * @brief Security configuration alert.
 */
struct alignas(256) SecurityAlert {
    uint64_t alertId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // Alert details
    AlertSeverity severity{ AlertSeverity::Info };
    std::string alertType;
    std::string title;
    std::string description;

    // Setting info
    SettingCategory category{ SettingCategory::Unknown };
    SecuritySettingType settingType{ SecuritySettingType::Unknown };
    std::wstring settingPath;

    // Change info
    std::wstring previousValue;
    std::wstring currentValue;

    // Attribution
    uint32_t responsiblePid{ 0 };
    std::wstring responsibleProcess;
    std::wstring responsibleUser;

    // Remediation
    bool canRemediate{ false };
    RemediationAction recommendedAction{ RemediationAction::Alert };
    bool wasRemediated{ false };

    // MITRE mapping
    std::string mitreId;
    std::string mitreTactic;
};

/**
 * @struct BaselineSnapshot
 * @brief Snapshot of security settings for comparison.
 */
struct alignas(64) BaselineSnapshot {
    uint64_t snapshotId{ 0 };
    std::chrono::system_clock::time_point created;
    std::string description;

    // Settings
    UACSettings uac;
    DefenderSettings defender;
    FirewallSettings firewall;
    ExploitProtection exploit;
    LSASettings lsa;
    ProxySettings proxy;
    DNSSettings dns;

    bool isDefault{ false };
};

/**
 * @struct ComplianceStatus
 * @brief Security compliance status.
 */
struct alignas(64) ComplianceStatus {
    bool isCompliant{ true };
    uint32_t totalChecks{ 0 };
    uint32_t passedChecks{ 0 };
    uint32_t failedChecks{ 0 };
    uint32_t warnings{ 0 };

    std::vector<std::string> failures;
    std::vector<std::string> warningList;

    std::chrono::system_clock::time_point lastChecked;
};

/**
 * @struct SystemSettingsMonitorConfig
 * @brief Configuration for system settings monitor.
 */
struct alignas(64) SystemSettingsMonitorConfig {
    // What to monitor
    bool monitorUAC{ true };
    bool monitorDefender{ true };
    bool monitorFirewall{ true };
    bool monitorExploitProtection{ true };
    bool monitorLSA{ true };
    bool monitorProxy{ true };
    bool monitorDNS{ true };
    bool monitorShell{ true };
    bool monitorPolicy{ true };

    // Auto-remediation
    bool enableAutoRemediation{ false };
    bool remediateUAC{ false };
    bool remediateDefender{ true };
    bool remediateFirewall{ true };

    // Alerting
    AlertSeverity minimumAlertSeverity{ AlertSeverity::Medium };
    bool alertOnAnyChange{ false };
    bool alertOnSecurityDegrade{ true };

    // Baseline
    bool useBaseline{ true };
    bool autoCreateBaseline{ true };

    // History
    size_t maxHistoryEntries{ SystemSettingsMonitorConstants::MAX_HISTORY };

    // Factory methods
    static SystemSettingsMonitorConfig CreateDefault() noexcept;
    static SystemSettingsMonitorConfig CreateHighSecurity() noexcept;
    static SystemSettingsMonitorConfig CreateMonitorOnly() noexcept;
};

/**
 * @struct SystemSettingsMonitorStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) SystemSettingsMonitorStatistics {
    std::atomic<uint64_t> changesDetected{ 0 };
    std::atomic<uint64_t> securityDegrades{ 0 };
    std::atomic<uint64_t> alertsGenerated{ 0 };
    std::atomic<uint64_t> remediationsPerformed{ 0 };
    std::atomic<uint64_t> remediationsFailed{ 0 };

    // Per-category
    std::atomic<uint64_t> uacChanges{ 0 };
    std::atomic<uint64_t> defenderChanges{ 0 };
    std::atomic<uint64_t> firewallChanges{ 0 };
    std::atomic<uint64_t> networkChanges{ 0 };
    std::atomic<uint64_t> shellChanges{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for setting change.
 */
using SettingChangeCallback = std::function<void(const SettingChange& change)>;

/**
 * @brief Callback for security alert.
 */
using SecurityAlertCallback = std::function<void(const SecurityAlert& alert)>;

/**
 * @brief Callback for compliance check.
 */
using ComplianceCallback = std::function<void(const ComplianceStatus& status)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class SystemSettingsMonitor
 * @brief Enterprise-grade OS security configuration monitoring.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& monitor = SystemSettingsMonitor::Instance();
 * 
 * // Configure high security mode
 * auto config = SystemSettingsMonitorConfig::CreateHighSecurity();
 * monitor.Initialize(config);
 * 
 * // Register alert callback
 * monitor.RegisterAlertCallback([](const SecurityAlert& alert) {
 *     if (alert.severity >= AlertSeverity::High) {
 *         // Handle high severity alert
 *         LOG_ALERT << alert.description;
 *     }
 * });
 * 
 * // Start monitoring
 * monitor.Start();
 * 
 * // Check current status
 * if (monitor.IsUACDisabled()) {
 *     LOG_CRITICAL << "UAC is disabled!";
 * }
 * 
 * // Create baseline
 * monitor.CreateBaseline("Initial secure state");
 * 
 * // Check compliance
 * auto compliance = monitor.CheckCompliance();
 * if (!compliance.isCompliant) {
 *     for (const auto& failure : compliance.failures) {
 *         LOG_WARNING << failure;
 *     }
 * }
 * @endcode
 */
class SystemSettingsMonitor {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static SystemSettingsMonitor& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the system settings monitor.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const SystemSettingsMonitorConfig& config);

    /**
     * @brief Starts real-time monitoring.
     */
    void Start();

    /**
     * @brief Stops monitoring.
     */
    void Stop() noexcept;

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    /**
     * @brief Checks if monitoring is active.
     * @return True if monitoring.
     */
    [[nodiscard]] bool IsMonitoring() const noexcept;

    // ========================================================================
    // SECURITY SETTINGS - UAC
    // ========================================================================

    /**
     * @brief Gets current UAC settings.
     * @return UAC settings.
     */
    [[nodiscard]] UACSettings GetUACSettings() const;

    /**
     * @brief Checks if UAC is disabled.
     * @return True if disabled.
     */
    [[nodiscard]] bool IsUACDisabled() const;

    /**
     * @brief Gets UAC level.
     * @return Current UAC level.
     */
    [[nodiscard]] UACLevel GetUACLevel() const;

    /**
     * @brief Restores UAC to secure defaults.
     * @return True if successful.
     */
    bool RestoreUACDefaults();

    // ========================================================================
    // SECURITY SETTINGS - DEFENDER
    // ========================================================================

    /**
     * @brief Gets current Defender settings.
     * @return Defender settings.
     */
    [[nodiscard]] DefenderSettings GetDefenderSettings() const;

    /**
     * @brief Checks if Defender is disabled.
     * @return True if disabled.
     */
    [[nodiscard]] bool IsDefenderDisabled() const;

    /**
     * @brief Checks if real-time protection is disabled.
     * @return True if disabled.
     */
    [[nodiscard]] bool IsRealTimeProtectionDisabled() const;

    /**
     * @brief Gets Defender exclusions.
     * @return Vector of excluded paths.
     */
    [[nodiscard]] std::vector<std::wstring> GetDefenderExclusions() const;

    /**
     * @brief Restores Defender to secure defaults.
     * @return True if successful.
     */
    bool RestoreDefenderDefaults();

    // ========================================================================
    // SECURITY SETTINGS - FIREWALL
    // ========================================================================

    /**
     * @brief Gets current firewall settings.
     * @return Firewall settings.
     */
    [[nodiscard]] FirewallSettings GetFirewallSettings() const;

    /**
     * @brief Checks if firewall is disabled for profile.
     * @param profile Firewall profile.
     * @return True if disabled.
     */
    [[nodiscard]] bool IsFirewallDisabled(FirewallProfile profile) const;

    /**
     * @brief Checks if any firewall profile is disabled.
     * @return True if any disabled.
     */
    [[nodiscard]] bool IsAnyFirewallDisabled() const;

    /**
     * @brief Restores firewall to secure defaults.
     * @return True if successful.
     */
    bool RestoreFirewallDefaults();

    // ========================================================================
    // SECURITY SETTINGS - EXPLOIT PROTECTION
    // ========================================================================

    /**
     * @brief Gets exploit protection settings.
     * @return Exploit protection settings.
     */
    [[nodiscard]] ExploitProtection GetExploitProtection() const;

    /**
     * @brief Checks if ASLR is disabled.
     * @return True if disabled.
     */
    [[nodiscard]] bool IsASLRDisabled() const;

    /**
     * @brief Checks if DEP is disabled.
     * @return True if disabled.
     */
    [[nodiscard]] bool IsDEPDisabled() const;

    // ========================================================================
    // SECURITY SETTINGS - LSA
    // ========================================================================

    /**
     * @brief Gets LSA settings.
     * @return LSA settings.
     */
    [[nodiscard]] LSASettings GetLSASettings() const;

    /**
     * @brief Checks if LSA runs as PPL.
     * @return True if PPL enabled.
     */
    [[nodiscard]] bool IsLSAPPLEnabled() const;

    // ========================================================================
    // NETWORK SETTINGS
    // ========================================================================

    /**
     * @brief Gets proxy settings.
     * @return Proxy settings.
     */
    [[nodiscard]] ProxySettings GetProxySettings() const;

    /**
     * @brief Checks if proxy is configured.
     * @return True if proxy enabled.
     */
    [[nodiscard]] bool IsProxyEnabled() const;

    /**
     * @brief Gets DNS settings.
     * @return DNS settings.
     */
    [[nodiscard]] DNSSettings GetDNSSettings() const;

    /**
     * @brief Checks if DNS is hijacked.
     * @return True if suspicious DNS.
     */
    [[nodiscard]] bool IsDNSSuspicious() const;

    // ========================================================================
    // BASELINE MANAGEMENT
    // ========================================================================

    /**
     * @brief Creates security baseline.
     * @param description Baseline description.
     * @return Baseline ID.
     */
    [[nodiscard]] uint64_t CreateBaseline(const std::string& description);

    /**
     * @brief Gets baseline by ID.
     * @param baselineId Baseline ID.
     * @return Baseline, or nullopt.
     */
    [[nodiscard]] std::optional<BaselineSnapshot> GetBaseline(uint64_t baselineId) const;

    /**
     * @brief Gets current active baseline.
     * @return Active baseline, or nullopt.
     */
    [[nodiscard]] std::optional<BaselineSnapshot> GetActiveBaseline() const;

    /**
     * @brief Sets active baseline.
     * @param baselineId Baseline ID.
     * @return True if successful.
     */
    bool SetActiveBaseline(uint64_t baselineId);

    /**
     * @brief Restores settings to baseline.
     * @param baselineId Baseline ID.
     * @return True if successful.
     */
    bool RestoreToBaseline(uint64_t baselineId);

    /**
     * @brief Compares current to baseline.
     * @param baselineId Baseline ID.
     * @return Vector of differences.
     */
    [[nodiscard]] std::vector<SettingChange> CompareToBaseline(uint64_t baselineId) const;

    // ========================================================================
    // COMPLIANCE
    // ========================================================================

    /**
     * @brief Checks security compliance.
     * @return Compliance status.
     */
    [[nodiscard]] ComplianceStatus CheckCompliance() const;

    /**
     * @brief Checks compliance against policy.
     * @param policyPath Path to policy file.
     * @return Compliance status.
     */
    [[nodiscard]] ComplianceStatus CheckPolicyCompliance(const std::wstring& policyPath) const;

    // ========================================================================
    // HISTORY
    // ========================================================================

    /**
     * @brief Gets change history.
     * @param maxCount Maximum entries.
     * @return Vector of changes.
     */
    [[nodiscard]] std::vector<SettingChange> GetHistory(size_t maxCount = 100) const;

    /**
     * @brief Gets history by category.
     * @param category Setting category.
     * @param maxCount Maximum entries.
     * @return Vector of changes.
     */
    [[nodiscard]] std::vector<SettingChange> GetHistoryByCategory(
        SettingCategory category, 
        size_t maxCount = 100) const;

    // ========================================================================
    // ALERTS
    // ========================================================================

    /**
     * @brief Gets active alerts.
     * @return Vector of alerts.
     */
    [[nodiscard]] std::vector<SecurityAlert> GetActiveAlerts() const;

    /**
     * @brief Acknowledges alert.
     * @param alertId Alert ID.
     * @return True if successful.
     */
    bool AcknowledgeAlert(uint64_t alertId);

    /**
     * @brief Clears all alerts.
     */
    void ClearAlerts() noexcept;

    // ========================================================================
    // REMEDIATION
    // ========================================================================

    /**
     * @brief Remediates a setting change.
     * @param changeId Change ID.
     * @return True if successful.
     */
    bool Remediate(uint64_t changeId);

    /**
     * @brief Enables auto-remediation.
     * @param enable Enable flag.
     */
    void SetAutoRemediation(bool enable) noexcept;

    /**
     * @brief Checks if auto-remediation is enabled.
     * @return True if enabled.
     */
    [[nodiscard]] bool IsAutoRemediationEnabled() const noexcept;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterChangeCallback(SettingChangeCallback callback);
    [[nodiscard]] uint64_t RegisterAlertCallback(SecurityAlertCallback callback);
    [[nodiscard]] uint64_t RegisterComplianceCallback(ComplianceCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const SystemSettingsMonitorStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // REFRESH
    // ========================================================================

    /**
     * @brief Forces refresh of all settings.
     */
    void RefreshAll();

    /**
     * @brief Refreshes specific category.
     * @param category Category to refresh.
     */
    void RefreshCategory(SettingCategory category);

    // ========================================================================
    // EXPORT
    // ========================================================================

    bool ExportReport(const std::wstring& outputPath) const;
    bool ExportSettings(const std::wstring& outputPath) const;
    bool ExportHistory(const std::wstring& outputPath) const;

private:
    SystemSettingsMonitor();
    ~SystemSettingsMonitor();

    SystemSettingsMonitor(const SystemSettingsMonitor&) = delete;
    SystemSettingsMonitor& operator=(const SystemSettingsMonitor&) = delete;

    std::unique_ptr<SystemSettingsMonitorImpl> m_impl;
};

}  // namespace Registry
}  // namespace Core
}  // namespace ShadowStrike
