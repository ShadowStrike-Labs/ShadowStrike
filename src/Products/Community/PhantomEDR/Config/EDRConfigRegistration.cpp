// ===========================================================================
// ShadowStrike – PhantomEDR Configuration Registration (Implementation)
// Copyright (c) ShadowStrike-Labs. All rights reserved.
// ===========================================================================
#include "pch.h"
#include "EDRConfigRegistration.hpp"
#include "PhantomCore/Config/ConfigManager.hpp"
#include "PhantomCore/Config/PolicyManager.hpp"
#include "PhantomCore/Config/ProfileManager.hpp"

namespace ShadowStrike::Products::PhantomEDR::Config {

using CM = ShadowStrike::Config::ConfigManager;
using PM = ShadowStrike::Config::PolicyManager;
using ProfM = ShadowStrike::Config::ProfileManager;
using Meta = ShadowStrike::Config::ConfigKeyMetadata;
using ValueType = ShadowStrike::Config::ConfigValueType;
using Layer = ShadowStrike::Config::ConfigLayer;

// ============================================================================
// HELPER: Register a single key with metadata
// ============================================================================

namespace {

template<typename T>
bool RegKey(const std::string& key, const std::string& category,
            const std::string& displayName, const T& defaultValue,
            bool sensitive = false, bool requiresRestart = false) {
    Meta meta{};
    meta.key = key;
    meta.category = category;
    meta.displayName = displayName;
    meta.defaultValue = ShadowStrike::Config::ConfigValue(defaultValue);
    meta.isSensitive = sensitive;
    meta.requiresRestart = requiresRestart;
    return CM::Instance().RegisterKeyMetadata(meta);
}

template<typename T>
bool RegKeyRange(const std::string& key, const std::string& category,
                 const std::string& displayName, const T& defaultValue,
                 const T& minVal, const T& maxVal,
                 bool requiresRestart = false) {
    Meta meta{};
    meta.key = key;
    meta.category = category;
    meta.displayName = displayName;
    meta.defaultValue = ShadowStrike::Config::ConfigValue(defaultValue);
    meta.minValue = ShadowStrike::Config::ConfigValue(minVal);
    meta.maxValue = ShadowStrike::Config::ConfigValue(maxVal);
    meta.requiresRestart = requiresRestart;
    return CM::Instance().RegisterKeyMetadata(meta);
}

} // anonymous namespace

// ============================================================================
// RegisterProductDefaults
// ============================================================================

[[nodiscard]] bool RegisterProductDefaults() {
    bool ok = true;

    // ---- Scan Engine ----
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ScanAggressiveness),
        "Scan", "Scan Aggressiveness Level",
        static_cast<uint32_t>(ScanAggressivenessLevel::Standard), 0, 3);
    ok &= RegKey<bool>(std::string(Keys::ScanOnOpen),
        "Scan", "Scan files on open", true);
    ok &= RegKey<bool>(std::string(Keys::ScanOnExecute),
        "Scan", "Scan files on execute", true);
    ok &= RegKey<bool>(std::string(Keys::ScanOnWrite),
        "Scan", "Scan files on write", true);
    ok &= RegKey<bool>(std::string(Keys::ScanArchives),
        "Scan", "Scan archive files", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ScanMaxFileSize),
        "Scan", "Maximum scan file size (MB)", 256, 1, 4096);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ScanMaxArchiveDepth),
        "Scan", "Maximum archive nesting depth", 5, 1, 20);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ScanHeuristicLevel),
        "Scan", "Heuristic analysis level", 2, 0, 4);
    ok &= RegKey<bool>(std::string(Keys::ScanCloudLookupEnabled),
        "Scan", "Cloud-based file reputation lookup", false);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ScanConcurrentLimit),
        "Scan", "Maximum concurrent scan operations", 4, 1, 32);

    // ---- Detection & Response ----
    ok &= RegKey<bool>(std::string(Keys::AutoContainment),
        "Response", "Auto-contain detected threats", true);
    ok &= RegKey<bool>(std::string(Keys::AutoRemediation),
        "Response", "Auto-remediate detected threats", false);
    ok &= RegKey<bool>(std::string(Keys::AutoIsolation),
        "Response", "Auto-isolate endpoint on critical threat", false);
    ok &= RegKeyRange<double>(std::string(Keys::IsolationThreshold),
        "Response", "Threat score threshold for auto-isolation", 0.95, 0.5, 1.0);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::KillChainSensitivity),
        "Response", "Kill chain detection sensitivity",
        static_cast<uint32_t>(KillChainSensitivity::Medium), 0, 3);
    ok &= RegKeyRange<double>(std::string(Keys::ThreatScoreBlockThreshold),
        "Response", "Threat score threshold for blocking", 0.75, 0.3, 1.0);
    ok &= RegKeyRange<double>(std::string(Keys::ThreatScoreAlertThreshold),
        "Response", "Threat score threshold for alerting", 0.50, 0.1, 1.0);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::MaxQuarantineSizeMB),
        "Response", "Maximum quarantine storage (MB)", 2048, 256, 65536);

    // ---- Behavioral Analysis ----
    ok &= RegKey<bool>(std::string(Keys::BehaviorMonitoring),
        "Behavior", "Behavioral analysis engine", true);
    ok &= RegKey<bool>(std::string(Keys::MemoryScanEnabled),
        "Behavior", "In-memory scan for fileless threats", true);
    ok &= RegKey<bool>(std::string(Keys::AntiExploitEnabled),
        "Behavior", "Anti-exploit mitigations", true);
    ok &= RegKey<bool>(std::string(Keys::CredentialGuard),
        "Behavior", "Credential theft protection", true);
    ok &= RegKey<bool>(std::string(Keys::AmsiIntegration),
        "Behavior", "AMSI integration for script scanning", true);
    ok &= RegKey<bool>(std::string(Keys::ScriptMonitoring),
        "Behavior", "PowerShell/WScript/VBS monitoring", true);
    ok &= RegKey<bool>(std::string(Keys::ProcessInjectionDetection),
        "Behavior", "Process injection detection", true);
    ok &= RegKey<bool>(std::string(Keys::RansomwareProtection),
        "Behavior", "Ransomware behavior detection", true);

    // ---- Telemetry ----
    ok &= RegKeyRange<uint32_t>(std::string(Keys::TelemetryLevel),
        "Telemetry", "Telemetry verbosity level",
        static_cast<uint32_t>(TelemetryLevel::Standard), 0, 3);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::TelemetryBatchSize),
        "Telemetry", "Events per telemetry batch", 100, 10, 10000);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::TelemetryFlushIntervalSec),
        "Telemetry", "Telemetry flush interval (seconds)", 60, 5, 3600);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::TelemetryRetentionDays),
        "Telemetry", "Local telemetry retention (days)", 30, 1, 365);
    ok &= RegKey<bool>(std::string(Keys::SyslogEnabled),
        "Telemetry", "Forward events to syslog", false);
    ok &= RegKey<std::string>(std::string(Keys::SyslogEndpoint),
        "Telemetry", "Syslog server endpoint", std::string(""));
    ok &= RegKey<std::string>(std::string(Keys::SyslogProtocol),
        "Telemetry", "Syslog protocol (UDP/TCP/TLS)", std::string("TLS"));

    // ---- Forensics ----
    ok &= RegKey<bool>(std::string(Keys::ForensicsEnabled),
        "Forensics", "Forensics data collection", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ForensicsRetentionDays),
        "Forensics", "Forensics data retention (days)", 90, 7, 365);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ForensicsMaxStorageMB),
        "Forensics", "Maximum forensics storage (MB)", 4096, 512, 65536);
    ok &= RegKey<bool>(std::string(Keys::MemoryDumpOnCritical),
        "Forensics", "Capture memory dump on critical threats", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ProcessSnapshotDepth),
        "Forensics", "Process tree snapshot depth", 5, 1, 20);

    // ---- Live Response ----
    ok &= RegKey<bool>(std::string(Keys::LiveResponseEnabled),
        "LiveResponse", "Enable live response sessions", true);
    ok &= RegKey<bool>(std::string(Keys::LiveResponseRequireMFA),
        "LiveResponse", "Require MFA for live response", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::LiveResponseSessionTimeout),
        "LiveResponse", "Session timeout (minutes)", 60, 5, 480);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::LiveResponseMaxSessions),
        "LiveResponse", "Max concurrent sessions", 3, 1, 10);
    ok &= RegKey<bool>(std::string(Keys::LiveResponseAuditAll),
        "LiveResponse", "Audit all live response commands", true);
    ok &= RegKey<bool>(std::string(Keys::LiveResponseAllowExec),
        "LiveResponse", "Allow process execution via live response", false);
    ok &= RegKey<bool>(std::string(Keys::LiveResponseAllowRegistry),
        "LiveResponse", "Allow registry modification via live response", false);

    // ---- Endpoint Isolation ----
    ok &= RegKey<bool>(std::string(Keys::IsolationAllowDNS),
        "Isolation", "Allow DNS during isolation", true);
    ok &= RegKey<bool>(std::string(Keys::IsolationAllowDHCP),
        "Isolation", "Allow DHCP during isolation", true);
    ok &= RegKey<bool>(std::string(Keys::IsolationAllowMgmtConsole),
        "Isolation", "Allow management console during isolation", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::IsolationMaxDurationHours),
        "Isolation", "Maximum isolation duration (hours)", 72, 1, 720);
    ok &= RegKey<bool>(std::string(Keys::IsolationAutoRelease),
        "Isolation", "Auto-release after max duration", true);

    // ---- Network ----
    ok &= RegKey<std::string>(std::string(Keys::MgmtServerUrl),
        "Network", "Management server URL", std::string(""), true);
    ok &= RegKey<std::string>(std::string(Keys::MgmtServerBackupUrl),
        "Network", "Backup management server URL", std::string(""), true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::HeartbeatIntervalSec),
        "Network", "Heartbeat interval (seconds)", 60, 10, 600);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::PolicySyncIntervalSec),
        "Network", "Policy sync interval (seconds)", 300, 30, 3600);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::SignatureUpdateIntervalMin),
        "Network", "Signature update interval (minutes)", 60, 5, 1440);
    ok &= RegKey<bool>(std::string(Keys::ProxyEnabled),
        "Network", "Use proxy for connections", false);
    ok &= RegKey<std::string>(std::string(Keys::ProxyAddress),
        "Network", "Proxy server address", std::string(""), true);
    ok &= RegKey<bool>(std::string(Keys::CertificatePinning),
        "Network", "Enable TLS certificate pinning", true);

    // ---- Self-Protection ----
    ok &= RegKey<bool>(std::string(Keys::TamperProtection),
        "SelfProtect", "Tamper protection for agent files/services", true, true);
    ok &= RegKey<bool>(std::string(Keys::AntiDebugEnabled),
        "SelfProtect", "Anti-debugging protection", true, true);
    ok &= RegKey<bool>(std::string(Keys::ServiceRecovery),
        "SelfProtect", "Auto-restart agent service on crash", true);
    ok &= RegKey<bool>(std::string(Keys::DriverProtection),
        "SelfProtect", "Kernel driver self-protection", true, true);

    // ---- Update ----
    ok &= RegKey<bool>(std::string(Keys::AutoUpdateEnabled),
        "Update", "Automatic updates", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::UpdateChannel),
        "Update", "Update channel",
        static_cast<uint32_t>(UpdateChannel::Stable), 0, 2);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::UpdateScheduleHour),
        "Update", "Preferred update hour (0-23)", 3, 0, 23);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::MaintenanceWindowStart),
        "Update", "Maintenance window start hour", 2, 0, 23);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::MaintenanceWindowEnd),
        "Update", "Maintenance window end hour", 5, 0, 23);

    if (!ok) {
        Utils::Logger::Error("[EDR Config] One or more key registrations failed");
    }
    return ok;
}

// ============================================================================
// RegisterPolicyTemplates
// ============================================================================

[[nodiscard]] bool RegisterPolicyTemplates() {
    using PolicyType = ShadowStrike::Config::PolicyType;
    using EnforcementLevel = ShadowStrike::Config::EnforcementLevel;
    using Policy = ShadowStrike::Config::Policy;
    using PolicySetting = ShadowStrike::Config::PolicySetting;

    bool ok = true;

    // Baseline Protection Policy — cannot be overridden by endpoints
    {
        Policy baseline{};
        baseline.id = "EDR-BASELINE-001";
        baseline.name = "EDR Baseline Protection";
        baseline.type = PolicyType::Protection;
        baseline.enforcement = EnforcementLevel::Mandatory;
        baseline.description = "Minimum protection requirements for all EDR endpoints";

        baseline.settings.push_back({std::string(Keys::ScanOnExecute), "true", EnforcementLevel::Mandatory});
        baseline.settings.push_back({std::string(Keys::BehaviorMonitoring), "true", EnforcementLevel::Mandatory});
        baseline.settings.push_back({std::string(Keys::TamperProtection), "true", EnforcementLevel::Mandatory});
        baseline.settings.push_back({std::string(Keys::DriverProtection), "true", EnforcementLevel::Mandatory});
        baseline.settings.push_back({std::string(Keys::RansomwareProtection), "true", EnforcementLevel::Mandatory});
        baseline.settings.push_back({std::string(Keys::ProcessInjectionDetection), "true", EnforcementLevel::Mandatory});
        baseline.settings.push_back({std::string(Keys::CertificatePinning), "true", EnforcementLevel::Mandatory});
        baseline.settings.push_back({std::string(Keys::LiveResponseAuditAll), "true", EnforcementLevel::Mandatory});

        ok &= PM::Instance().ApplyPolicy(baseline);
    }

    // Scan Policy — defaults, overridable by IT admins
    {
        Policy scanPolicy{};
        scanPolicy.id = "EDR-SCAN-001";
        scanPolicy.name = "EDR Default Scan Policy";
        scanPolicy.type = PolicyType::Scan;
        scanPolicy.enforcement = EnforcementLevel::Default;
        scanPolicy.description = "Default scan configuration for EDR endpoints";

        scanPolicy.settings.push_back({std::string(Keys::ScanOnOpen), "true", EnforcementLevel::Default});
        scanPolicy.settings.push_back({std::string(Keys::ScanOnWrite), "true", EnforcementLevel::Default});
        scanPolicy.settings.push_back({std::string(Keys::ScanArchives), "true", EnforcementLevel::Default});
        scanPolicy.settings.push_back({std::string(Keys::ScanMaxFileSize), "256", EnforcementLevel::Default});
        scanPolicy.settings.push_back({std::string(Keys::ScanHeuristicLevel), "2", EnforcementLevel::Default});
        scanPolicy.settings.push_back({std::string(Keys::ScanCloudLookupEnabled), "false", EnforcementLevel::Default});

        ok &= PM::Instance().ApplyPolicy(scanPolicy);
    }

    // Live Response Lockdown — mandatory security constraints
    {
        Policy lrPolicy{};
        lrPolicy.id = "EDR-LIVERESP-001";
        lrPolicy.name = "EDR Live Response Security";
        lrPolicy.type = PolicyType::Application;
        lrPolicy.enforcement = EnforcementLevel::Mandatory;
        lrPolicy.description = "Security constraints for live response sessions";

        lrPolicy.settings.push_back({std::string(Keys::LiveResponseRequireMFA), "true", EnforcementLevel::Mandatory});
        lrPolicy.settings.push_back({std::string(Keys::LiveResponseAllowExec), "false", EnforcementLevel::Mandatory});
        lrPolicy.settings.push_back({std::string(Keys::LiveResponseAllowRegistry), "false", EnforcementLevel::Mandatory});

        ok &= PM::Instance().ApplyPolicy(lrPolicy);
    }

    if (!ok) {
        Utils::Logger::Error("[EDR Config] One or more policy template registrations failed");
    }
    return ok;
}

// ============================================================================
// RegisterProfilePresets
// ============================================================================

[[nodiscard]] bool RegisterProfilePresets() {
    using SystemProfile = ShadowStrike::Config::SystemProfile;
    using ProfileDef = ShadowStrike::Config::ProfileDefinition;
    using ResourceLimits = ShadowStrike::Config::ResourceLimits;
    using ScanSettings = ShadowStrike::Config::ProfileScanSettings;

    bool ok = true;

    // Server Profile — high availability, minimal user disruption
    {
        ProfileDef server{};
        server.type = SystemProfile::Server;
        server.name = "EDR Server";
        server.description = "Optimized for server workloads — high availability, low I/O impact";

        server.resources.maxCpuPercent = 15;
        server.resources.maxMemoryMB = 256;
        server.resources.ioPriority = 0;  // Lowest I/O priority
        server.resources.maxConcurrentScans = 2;
        server.resources.threadPriority = -1; // Below normal

        server.scanSettings.realTimeProtection = true;
        server.scanSettings.behaviorMonitoring = true;
        server.scanSettings.archiveScanning = false; // Skip archives on servers for perf
        server.scanSettings.scanNetworkFiles = false;
        server.scanSettings.heuristicLevel = 1;
        server.scanSettings.cloudLookup = true;

        ok &= ProfM::Instance().CreateCustomProfile(server);
    }

    // Workstation Profile — balanced for endpoint users
    {
        ProfileDef ws{};
        ws.type = SystemProfile::Standard;
        ws.name = "EDR Workstation";
        ws.description = "Balanced protection for workstation endpoints";

        ws.resources.maxCpuPercent = 30;
        ws.resources.maxMemoryMB = 512;
        ws.resources.ioPriority = 1;
        ws.resources.maxConcurrentScans = 4;
        ws.resources.threadPriority = 0;

        ws.scanSettings.realTimeProtection = true;
        ws.scanSettings.behaviorMonitoring = true;
        ws.scanSettings.archiveScanning = true;
        ws.scanSettings.scanNetworkFiles = false;
        ws.scanSettings.heuristicLevel = 2;
        ws.scanSettings.cloudLookup = true;

        ok &= ProfM::Instance().CreateCustomProfile(ws);
    }

    // High-Security Profile — maximum detection, higher resource cost
    {
        ProfileDef hs{};
        hs.type = SystemProfile::HighSecurity;
        hs.name = "EDR High-Security";
        hs.description = "Maximum detection for high-value targets (executives, finance, R&D)";

        hs.resources.maxCpuPercent = 50;
        hs.resources.maxMemoryMB = 1024;
        hs.resources.ioPriority = 2;
        hs.resources.maxConcurrentScans = 8;
        hs.resources.threadPriority = 1; // Above normal

        hs.scanSettings.realTimeProtection = true;
        hs.scanSettings.behaviorMonitoring = true;
        hs.scanSettings.archiveScanning = true;
        hs.scanSettings.scanNetworkFiles = true;
        hs.scanSettings.heuristicLevel = 4; // Maximum
        hs.scanSettings.cloudLookup = true;

        ok &= ProfM::Instance().CreateCustomProfile(hs);
    }

    if (!ok) {
        Utils::Logger::Error("[EDR Config] One or more profile preset registrations failed");
    }
    return ok;
}

// ============================================================================
// ValidateConfiguration
// ============================================================================

[[nodiscard]] bool ValidateConfiguration() {
    auto& cm = CM::Instance();
    auto errors = cm.ValidateAll();

    if (errors.empty()) {
        Utils::Logger::Info("[EDR Config] Configuration validation passed");
        return true;
    }

    for (const auto& err : errors) {
        Utils::Logger::Warn("[EDR Config] Validation error for '{}': {}",
                            err.key, err.message);
    }

    Utils::Logger::Error("[EDR Config] Configuration validation found {} error(s)",
                         errors.size());
    return false;
}

} // namespace ShadowStrike::Products::PhantomEDR::Config
