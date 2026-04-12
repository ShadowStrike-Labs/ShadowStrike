// ===========================================================================
// ShadowStrike – PhantomXDR Configuration Registration
// Copyright (c) ShadowStrike-Labs. All rights reserved.
//
// Registers XDR-specific configuration keys, enterprise policies, and
// system profiles with the shared Config infrastructure.
//
// XDR extends EDR with cross-endpoint correlation, SIEM/SOAR integration,
// multi-tenancy, and advanced threat hunting. Configuration is managed
// exclusively through the enterprise management console.
// ===========================================================================
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace ShadowStrike::Products::PhantomXDR::Config {

// ============================================================================
// CONFIG KEY CONSTANTS
// XDR inherits ALL EDR keys and adds cross-platform/correlation keys.
// Keys are hierarchical: "XDR/<Category>/<Setting>"
// ============================================================================

namespace Keys {

    // --- SIEM Integration ---
    inline constexpr std::string_view SIEMEnabled                 = "XDR/SIEM/Enabled";
    inline constexpr std::string_view SIEMEndpoint                = "XDR/SIEM/Endpoint";
    inline constexpr std::string_view SIEMProtocol                = "XDR/SIEM/Protocol";
    inline constexpr std::string_view SIEMBatchSize               = "XDR/SIEM/BatchSize";
    inline constexpr std::string_view SIEMFlushIntervalSec        = "XDR/SIEM/FlushIntervalSec";
    inline constexpr std::string_view SIEMTLSEnabled              = "XDR/SIEM/TLSEnabled";
    inline constexpr std::string_view SIEMCertPath                = "XDR/SIEM/CertPath";
    inline constexpr std::string_view SIEMFormat                  = "XDR/SIEM/Format";
    inline constexpr std::string_view SIEMRetryCount              = "XDR/SIEM/RetryCount";
    inline constexpr std::string_view SIEMBackpressureThreshold   = "XDR/SIEM/BackpressureThreshold";

    // --- SOAR Playbooks ---
    inline constexpr std::string_view SOAREnabled                 = "XDR/SOAR/Enabled";
    inline constexpr std::string_view SOARPlaybookDir             = "XDR/SOAR/PlaybookDirectory";
    inline constexpr std::string_view SOARAutoExecute             = "XDR/SOAR/AutoExecute";
    inline constexpr std::string_view SOARMaxConcurrentPlaybooks  = "XDR/SOAR/MaxConcurrent";
    inline constexpr std::string_view SOARExecutionTimeoutSec     = "XDR/SOAR/ExecutionTimeoutSec";
    inline constexpr std::string_view SOARAuditAll                = "XDR/SOAR/AuditAll";
    inline constexpr std::string_view SOARSandboxExecution        = "XDR/SOAR/SandboxExecution";

    // --- Cross-Endpoint Correlation ---
    inline constexpr std::string_view CorrelationEnabled          = "XDR/Correlation/Enabled";
    inline constexpr std::string_view CorrelationWindowSec        = "XDR/Correlation/WindowSec";
    inline constexpr std::string_view CorrelationMinEndpoints     = "XDR/Correlation/MinEndpoints";
    inline constexpr std::string_view CorrelationConfidence       = "XDR/Correlation/MinConfidence";
    inline constexpr std::string_view CorrelationMaxEventsPerWindow = "XDR/Correlation/MaxEventsPerWindow";
    inline constexpr std::string_view CorrelationRulesetVersion   = "XDR/Correlation/RulesetVersion";

    // --- Cloud Correlation ---
    inline constexpr std::string_view CloudCorrelationEnabled     = "XDR/Cloud/Enabled";
    inline constexpr std::string_view CloudAPIEndpoint            = "XDR/Cloud/APIEndpoint";
    inline constexpr std::string_view CloudRegion                 = "XDR/Cloud/Region";
    inline constexpr std::string_view CloudTenantId               = "XDR/Cloud/TenantId";
    inline constexpr std::string_view CloudSyncIntervalSec        = "XDR/Cloud/SyncIntervalSec";
    inline constexpr std::string_view CloudRetentionDays          = "XDR/Cloud/RetentionDays";
    inline constexpr std::string_view CloudEncryptionEnabled      = "XDR/Cloud/EncryptionEnabled";

    // --- Multi-Tenancy ---
    inline constexpr std::string_view MultiTenantEnabled          = "XDR/MultiTenant/Enabled";
    inline constexpr std::string_view TenantIsolationLevel        = "XDR/MultiTenant/IsolationLevel";
    inline constexpr std::string_view TenantMaxEndpoints          = "XDR/MultiTenant/MaxEndpoints";
    inline constexpr std::string_view TenantDataResidency         = "XDR/MultiTenant/DataResidency";
    inline constexpr std::string_view CrossTenantCorrelation      = "XDR/MultiTenant/CrossTenantCorrelation";

    // --- Threat Hunting ---
    inline constexpr std::string_view ThreatHuntEnabled           = "XDR/ThreatHunt/Enabled";
    inline constexpr std::string_view ThreatHuntMaxConcurrent     = "XDR/ThreatHunt/MaxConcurrentHunts";
    inline constexpr std::string_view ThreatHuntTimeoutMin        = "XDR/ThreatHunt/TimeoutMin";
    inline constexpr std::string_view ThreatHuntMaxScopeMachines  = "XDR/ThreatHunt/MaxScopeMachines";
    inline constexpr std::string_view ThreatHuntAuditQueries      = "XDR/ThreatHunt/AuditQueries";
    inline constexpr std::string_view ThreatHuntRetentionDays     = "XDR/ThreatHunt/RetentionDays";
    inline constexpr std::string_view ThreatHuntIOCFeedEnabled    = "XDR/ThreatHunt/IOCFeedEnabled";
    inline constexpr std::string_view ThreatHuntYaraEnabled       = "XDR/ThreatHunt/YaraEnabled";

    // --- Data Lake / Storage ---
    inline constexpr std::string_view DataLakeEnabled             = "XDR/DataLake/Enabled";
    inline constexpr std::string_view DataLakeEndpoint            = "XDR/DataLake/Endpoint";
    inline constexpr std::string_view DataLakeRetentionDays       = "XDR/DataLake/RetentionDays";
    inline constexpr std::string_view DataLakeCompressionEnabled  = "XDR/DataLake/Compression";
    inline constexpr std::string_view DataLakeMaxStorageGB        = "XDR/DataLake/MaxStorageGB";
    inline constexpr std::string_view DataLakeEncryptionAtRest    = "XDR/DataLake/EncryptionAtRest";

    // --- Alert Management ---
    inline constexpr std::string_view AlertAggregation            = "XDR/Alerts/Aggregation";
    inline constexpr std::string_view AlertDeduplication           = "XDR/Alerts/Deduplication";
    inline constexpr std::string_view AlertEscalationEnabled      = "XDR/Alerts/EscalationEnabled";
    inline constexpr std::string_view AlertSLAResponseMin         = "XDR/Alerts/SLAResponseMin";
    inline constexpr std::string_view AlertMaxQueueSize           = "XDR/Alerts/MaxQueueSize";
    inline constexpr std::string_view AlertWebhookEnabled         = "XDR/Alerts/WebhookEnabled";
    inline constexpr std::string_view AlertWebhookUrl             = "XDR/Alerts/WebhookUrl";

} // namespace Keys

// ============================================================================
// ENUMS FOR TYPED CONFIG VALUES
// ============================================================================

enum class SIEMProtocol : uint32_t {
    Syslog_UDP  = 0,
    Syslog_TCP  = 1,
    Syslog_TLS  = 2,
    CEF         = 3,    // Common Event Format
    LEEF        = 4,    // Log Event Extended Format (QRadar)
    JSON_HTTP   = 5,    // REST API (Splunk HEC, Elastic)
    Kafka       = 6     // Apache Kafka
};

enum class SIEMFormat : uint32_t {
    CEF         = 0,    // ArcSight Common Event Format
    LEEF        = 1,    // QRadar Log Event Extended Format
    JSON        = 2,    // Generic JSON
    ECS         = 3     // Elastic Common Schema
};

enum class TenantIsolation : uint32_t {
    Shared      = 0,    // Shared infrastructure, logical separation
    Dedicated   = 1,    // Dedicated compute, shared storage
    Full        = 2     // Fully isolated infrastructure
};

enum class CorrelationConfidence : uint32_t {
    Low         = 0,    // ≥30% confidence
    Medium      = 1,    // ≥60% confidence
    High        = 2,    // ≥80% confidence
    Critical    = 3     // ≥95% confidence only
};

// ============================================================================
// REGISTRATION API
// ============================================================================

/// @brief Registers ALL XDR configuration keys (including inherited EDR keys),
///        defaults, validation rules, enterprise policy templates, and system
///        profiles. Must be called once during XDR agent startup.
/// @return true if all registrations succeeded
[[nodiscard]] bool RegisterProductDefaults();

/// @brief Registers XDR-specific enterprise policy templates including
///        cross-endpoint correlation policies and SIEM/SOAR policies.
/// @return true if all policy templates registered
[[nodiscard]] bool RegisterPolicyTemplates();

/// @brief Configures XDR-appropriate system profile presets.
///        XDR inherits EDR profiles and adds correlation-aware variants.
/// @return true if all profiles configured
[[nodiscard]] bool RegisterProfilePresets();

/// @brief Validates XDR configuration including SIEM connectivity,
///        cloud correlation settings, and multi-tenant isolation.
/// @return true if configuration is valid
[[nodiscard]] bool ValidateConfiguration();

/// @brief Returns the product identifier string for config namespacing.
[[nodiscard]] constexpr std::string_view GetProductIdentifier() noexcept {
    return "PhantomXDR";
}

/// @brief Returns the product version for config compatibility checks.
[[nodiscard]] constexpr uint32_t GetProductVersion() noexcept {
    return 0x03000000; // 3.0.0
}

} // namespace ShadowStrike::Products::PhantomXDR::Config
