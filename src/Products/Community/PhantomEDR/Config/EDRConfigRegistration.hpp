// ===========================================================================
// ShadowStrike – PhantomEDR Configuration Registration
// Copyright (c) ShadowStrike-Labs. All rights reserved.
//
// Registers EDR-specific configuration keys, enterprise policies, and
// system profiles with the shared Config infrastructure.
//
// EDR is managed exclusively through the enterprise management console.
// There is NO local UI for configuration — everything is policy-driven.
// ===========================================================================
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace ShadowStrike::Products::PhantomEDR::Config {

// ============================================================================
// CONFIG KEY CONSTANTS
// Keys are hierarchical: "EDR/<Category>/<Setting>"
// ============================================================================

namespace Keys {

    // --- Scan Engine ---
    inline constexpr std::string_view ScanAggressiveness          = "EDR/Scan/Aggressiveness";
    inline constexpr std::string_view ScanOnOpen                  = "EDR/Scan/OnOpen";
    inline constexpr std::string_view ScanOnExecute               = "EDR/Scan/OnExecute";
    inline constexpr std::string_view ScanOnWrite                 = "EDR/Scan/OnWrite";
    inline constexpr std::string_view ScanArchives                = "EDR/Scan/Archives";
    inline constexpr std::string_view ScanMaxFileSize             = "EDR/Scan/MaxFileSizeMB";
    inline constexpr std::string_view ScanMaxArchiveDepth         = "EDR/Scan/MaxArchiveDepth";
    inline constexpr std::string_view ScanHeuristicLevel          = "EDR/Scan/HeuristicLevel";
    inline constexpr std::string_view ScanCloudLookupEnabled      = "EDR/Scan/CloudLookup";
    inline constexpr std::string_view ScanConcurrentLimit         = "EDR/Scan/ConcurrentLimit";

    // --- Detection & Response ---
    inline constexpr std::string_view AutoContainment             = "EDR/Response/AutoContainment";
    inline constexpr std::string_view AutoRemediation             = "EDR/Response/AutoRemediation";
    inline constexpr std::string_view AutoIsolation               = "EDR/Response/AutoIsolation";
    inline constexpr std::string_view IsolationThreshold          = "EDR/Response/IsolationThreshold";
    inline constexpr std::string_view KillChainSensitivity        = "EDR/Response/KillChainSensitivity";
    inline constexpr std::string_view ThreatScoreBlockThreshold   = "EDR/Response/BlockThreshold";
    inline constexpr std::string_view ThreatScoreAlertThreshold   = "EDR/Response/AlertThreshold";
    inline constexpr std::string_view MaxQuarantineSizeMB         = "EDR/Response/MaxQuarantineSizeMB";

    // --- Behavioral Analysis ---
    inline constexpr std::string_view BehaviorMonitoring          = "EDR/Behavior/Enabled";
    inline constexpr std::string_view MemoryScanEnabled           = "EDR/Behavior/MemoryScan";
    inline constexpr std::string_view AntiExploitEnabled          = "EDR/Behavior/AntiExploit";
    inline constexpr std::string_view CredentialGuard             = "EDR/Behavior/CredentialGuard";
    inline constexpr std::string_view AmsiIntegration             = "EDR/Behavior/AMSI";
    inline constexpr std::string_view ScriptMonitoring            = "EDR/Behavior/ScriptMonitoring";
    inline constexpr std::string_view ProcessInjectionDetection   = "EDR/Behavior/InjectionDetection";
    inline constexpr std::string_view RansomwareProtection        = "EDR/Behavior/RansomwareProtection";

    // --- Telemetry & Reporting ---
    inline constexpr std::string_view TelemetryLevel              = "EDR/Telemetry/Level";
    inline constexpr std::string_view TelemetryBatchSize          = "EDR/Telemetry/BatchSize";
    inline constexpr std::string_view TelemetryFlushIntervalSec   = "EDR/Telemetry/FlushIntervalSec";
    inline constexpr std::string_view TelemetryRetentionDays      = "EDR/Telemetry/RetentionDays";
    inline constexpr std::string_view SyslogEnabled               = "EDR/Telemetry/SyslogEnabled";
    inline constexpr std::string_view SyslogEndpoint              = "EDR/Telemetry/SyslogEndpoint";
    inline constexpr std::string_view SyslogProtocol              = "EDR/Telemetry/SyslogProtocol";

    // --- Forensics ---
    inline constexpr std::string_view ForensicsEnabled            = "EDR/Forensics/Enabled";
    inline constexpr std::string_view ForensicsRetentionDays      = "EDR/Forensics/RetentionDays";
    inline constexpr std::string_view ForensicsMaxStorageMB       = "EDR/Forensics/MaxStorageMB";
    inline constexpr std::string_view MemoryDumpOnCritical        = "EDR/Forensics/MemoryDumpOnCritical";
    inline constexpr std::string_view ProcessSnapshotDepth        = "EDR/Forensics/ProcessSnapshotDepth";

    // --- Live Response ---
    inline constexpr std::string_view LiveResponseEnabled         = "EDR/LiveResponse/Enabled";
    inline constexpr std::string_view LiveResponseRequireMFA      = "EDR/LiveResponse/RequireMFA";
    inline constexpr std::string_view LiveResponseSessionTimeout  = "EDR/LiveResponse/SessionTimeoutMin";
    inline constexpr std::string_view LiveResponseMaxSessions     = "EDR/LiveResponse/MaxConcurrentSessions";
    inline constexpr std::string_view LiveResponseAuditAll        = "EDR/LiveResponse/AuditAllCommands";
    inline constexpr std::string_view LiveResponseAllowExec       = "EDR/LiveResponse/AllowExecution";
    inline constexpr std::string_view LiveResponseAllowRegistry   = "EDR/LiveResponse/AllowRegistryMod";

    // --- Endpoint Isolation ---
    inline constexpr std::string_view IsolationAllowDNS           = "EDR/Isolation/AllowDNS";
    inline constexpr std::string_view IsolationAllowDHCP          = "EDR/Isolation/AllowDHCP";
    inline constexpr std::string_view IsolationAllowMgmtConsole   = "EDR/Isolation/AllowMgmtConsole";
    inline constexpr std::string_view IsolationMaxDurationHours   = "EDR/Isolation/MaxDurationHours";
    inline constexpr std::string_view IsolationAutoRelease        = "EDR/Isolation/AutoRelease";

    // --- Network & Communication ---
    inline constexpr std::string_view MgmtServerUrl               = "EDR/Network/MgmtServerUrl";
    inline constexpr std::string_view MgmtServerBackupUrl         = "EDR/Network/MgmtServerBackupUrl";
    inline constexpr std::string_view HeartbeatIntervalSec        = "EDR/Network/HeartbeatIntervalSec";
    inline constexpr std::string_view PolicySyncIntervalSec       = "EDR/Network/PolicySyncIntervalSec";
    inline constexpr std::string_view SignatureUpdateIntervalMin  = "EDR/Network/SigUpdateIntervalMin";
    inline constexpr std::string_view ProxyEnabled                = "EDR/Network/ProxyEnabled";
    inline constexpr std::string_view ProxyAddress                = "EDR/Network/ProxyAddress";
    inline constexpr std::string_view CertificatePinning          = "EDR/Network/CertificatePinning";

    // --- Self-Protection ---
    inline constexpr std::string_view TamperProtection            = "EDR/SelfProtect/TamperProtection";
    inline constexpr std::string_view AntiDebugEnabled            = "EDR/SelfProtect/AntiDebug";
    inline constexpr std::string_view ServiceRecovery             = "EDR/SelfProtect/ServiceRecovery";
    inline constexpr std::string_view DriverProtection            = "EDR/SelfProtect/DriverProtection";

    // --- Update & Maintenance ---
    inline constexpr std::string_view AutoUpdateEnabled           = "EDR/Update/AutoUpdate";
    inline constexpr std::string_view UpdateChannel               = "EDR/Update/Channel";
    inline constexpr std::string_view UpdateScheduleHour          = "EDR/Update/ScheduleHour";
    inline constexpr std::string_view MaintenanceWindowStart      = "EDR/Update/MaintenanceWindowStart";
    inline constexpr std::string_view MaintenanceWindowEnd        = "EDR/Update/MaintenanceWindowEnd";

} // namespace Keys

// ============================================================================
// ENUMS FOR TYPED CONFIG VALUES
// ============================================================================

enum class ScanAggressivenessLevel : uint32_t {
    Low         = 0,    // Minimal scanning — high-confidence signatures only
    Standard    = 1,    // Balanced detection vs. performance
    High        = 2,    // Aggressive — heuristics + behavioral
    Maximum     = 3     // Full-spectrum — all engines, no performance concession
};

enum class TelemetryLevel : uint32_t {
    Minimal     = 0,    // Security events only
    Standard    = 1,    // + process/file events
    Detailed    = 2,    // + network + registry events
    Full        = 3     // Everything — for incident investigation
};

enum class KillChainSensitivity : uint32_t {
    Low         = 0,    // Alert on confirmed kill chains only
    Medium      = 1,    // Alert on probable chains (2+ stages)
    High        = 2,    // Alert on any chain candidate (1+ stages)
    Maximum     = 3     // Alert on any behavioral anomaly
};

enum class UpdateChannel : uint32_t {
    Stable      = 0,    // Production-validated updates
    Preview     = 1,    // Pre-release testing
    Rapid       = 2     // Fastest signature delivery
};

// ============================================================================
// REGISTRATION API
// ============================================================================

/// @brief Registers all EDR configuration keys, defaults, validation rules,
///        enterprise policy templates, and system profiles with the shared
///        Config infrastructure. Must be called once during EDR agent startup.
/// @return true if all registrations succeeded
[[nodiscard]] bool RegisterProductDefaults();

/// @brief Registers EDR-specific enterprise policy templates that the
///        management console can push to endpoints.
/// @return true if all policy templates registered
[[nodiscard]] bool RegisterPolicyTemplates();

/// @brief Configures EDR-appropriate system profile presets (Server,
///        Workstation, DomainController, HighSecurity).
/// @return true if all profiles configured
[[nodiscard]] bool RegisterProfilePresets();

/// @brief Validates the current configuration against EDR requirements.
///        Called at startup and after policy sync.
/// @return true if configuration is valid
[[nodiscard]] bool ValidateConfiguration();

/// @brief Returns the product identifier string for config namespacing.
[[nodiscard]] constexpr std::string_view GetProductIdentifier() noexcept {
    return "PhantomEDR";
}

/// @brief Returns the product version for config compatibility checks.
[[nodiscard]] constexpr uint32_t GetProductVersion() noexcept {
    return 0x03000000; // 3.0.0
}

} // namespace ShadowStrike::Products::PhantomEDR::Config
