// ===========================================================================
// ShadowStrike – PhantomXDR Configuration Registration (Implementation)
// Copyright (c) ShadowStrike-Labs. All rights reserved.
// ===========================================================================
#include "pch.h"
#include "XDRConfigRegistration.hpp"
#include "../../PhantomCore/Config/ConfigManager.hpp"
#include "../../PhantomCore/Config/PolicyManager.hpp"
#include "../../PhantomCore/Config/ProfileManager.hpp"

// XDR inherits EDR defaults — register EDR keys first
#include "../PhantomEDR/Config/EDRConfigRegistration.hpp"

namespace ShadowStrike::Products::PhantomXDR::Config {

using CM = ShadowStrike::Config::ConfigManager;
using PM = ShadowStrike::Config::PolicyManager;
using ProfM = ShadowStrike::Config::ProfileManager;
using Meta = ShadowStrike::Config::ConfigKeyMetadata;
using ValueType = ShadowStrike::Config::ConfigValueType;

// ============================================================================
// HELPER
// ============================================================================

namespace {

template<typename T>
bool RegKey(const std::string& key, const std::string& category,
            const std::string& displayName, const T& defaultValue,
            bool sensitive = false) {
    Meta meta{};
    meta.key = key;
    meta.category = category;
    meta.displayName = displayName;
    meta.defaultValue = ShadowStrike::Config::ConfigValue(defaultValue);
    meta.isSensitive = sensitive;
    return CM::Instance().RegisterKeyMetadata(meta);
}

template<typename T>
bool RegKeyRange(const std::string& key, const std::string& category,
                 const std::string& displayName, const T& defaultValue,
                 const T& minVal, const T& maxVal) {
    Meta meta{};
    meta.key = key;
    meta.category = category;
    meta.displayName = displayName;
    meta.defaultValue = ShadowStrike::Config::ConfigValue(defaultValue);
    meta.minValue = ShadowStrike::Config::ConfigValue(minVal);
    meta.maxValue = ShadowStrike::Config::ConfigValue(maxVal);
    return CM::Instance().RegisterKeyMetadata(meta);
}

} // anonymous namespace

// ============================================================================
// RegisterProductDefaults
// ============================================================================

[[nodiscard]] bool RegisterProductDefaults() {
    bool ok = true;

    // Step 1: Register ALL inherited EDR defaults first
    ok &= PhantomEDR::Config::RegisterProductDefaults();

    // Step 2: Register XDR-specific keys

    // ---- SIEM Integration ----
    ok &= RegKey<bool>(std::string(Keys::SIEMEnabled),
        "SIEM", "SIEM integration enabled", false);
    ok &= RegKey<std::string>(std::string(Keys::SIEMEndpoint),
        "SIEM", "SIEM endpoint URL", std::string(""), true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::SIEMProtocol),
        "SIEM", "SIEM protocol",
        static_cast<uint32_t>(SIEMProtocol::Syslog_TLS), 0, 6);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::SIEMBatchSize),
        "SIEM", "Events per SIEM batch", 500, 10, 50000);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::SIEMFlushIntervalSec),
        "SIEM", "SIEM flush interval (seconds)", 30, 1, 600);
    ok &= RegKey<bool>(std::string(Keys::SIEMTLSEnabled),
        "SIEM", "SIEM TLS encryption", true);
    ok &= RegKey<std::string>(std::string(Keys::SIEMCertPath),
        "SIEM", "SIEM TLS certificate path", std::string(""), true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::SIEMFormat),
        "SIEM", "SIEM event format",
        static_cast<uint32_t>(SIEMFormat::CEF), 0, 3);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::SIEMRetryCount),
        "SIEM", "SIEM delivery retry count", 3, 0, 10);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::SIEMBackpressureThreshold),
        "SIEM", "SIEM backpressure queue threshold", 10000, 100, 1000000);

    // ---- SOAR Playbooks ----
    ok &= RegKey<bool>(std::string(Keys::SOAREnabled),
        "SOAR", "SOAR playbook execution", false);
    ok &= RegKey<std::string>(std::string(Keys::SOARPlaybookDir),
        "SOAR", "Playbook directory path", std::string(""));
    ok &= RegKey<bool>(std::string(Keys::SOARAutoExecute),
        "SOAR", "Auto-execute matching playbooks", false);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::SOARMaxConcurrentPlaybooks),
        "SOAR", "Max concurrent playbook executions", 5, 1, 50);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::SOARExecutionTimeoutSec),
        "SOAR", "Playbook execution timeout (seconds)", 300, 30, 3600);
    ok &= RegKey<bool>(std::string(Keys::SOARAuditAll),
        "SOAR", "Audit all playbook executions", true);
    ok &= RegKey<bool>(std::string(Keys::SOARSandboxExecution),
        "SOAR", "Execute playbooks in sandbox", true);

    // ---- Cross-Endpoint Correlation ----
    ok &= RegKey<bool>(std::string(Keys::CorrelationEnabled),
        "Correlation", "Cross-endpoint event correlation", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::CorrelationWindowSec),
        "Correlation", "Correlation time window (seconds)", 300, 30, 3600);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::CorrelationMinEndpoints),
        "Correlation", "Minimum endpoints for correlation", 2, 2, 100);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::CorrelationConfidence),
        "Correlation", "Minimum correlation confidence",
        static_cast<uint32_t>(CorrelationConfidence::Medium), 0, 3);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::CorrelationMaxEventsPerWindow),
        "Correlation", "Max events per correlation window", 100000, 1000, 10000000);
    ok &= RegKey<std::string>(std::string(Keys::CorrelationRulesetVersion),
        "Correlation", "Correlation ruleset version", std::string("1.0.0"));

    // ---- Cloud Correlation ----
    ok &= RegKey<bool>(std::string(Keys::CloudCorrelationEnabled),
        "Cloud", "Cloud-based correlation", false);
    ok &= RegKey<std::string>(std::string(Keys::CloudAPIEndpoint),
        "Cloud", "Cloud API endpoint", std::string(""), true);
    ok &= RegKey<std::string>(std::string(Keys::CloudRegion),
        "Cloud", "Cloud region for data residency", std::string("auto"));
    ok &= RegKey<std::string>(std::string(Keys::CloudTenantId),
        "Cloud", "Cloud tenant identifier", std::string(""), true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::CloudSyncIntervalSec),
        "Cloud", "Cloud sync interval (seconds)", 60, 10, 600);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::CloudRetentionDays),
        "Cloud", "Cloud data retention (days)", 90, 7, 365);
    ok &= RegKey<bool>(std::string(Keys::CloudEncryptionEnabled),
        "Cloud", "Encrypt data in transit to cloud", true);

    // ---- Multi-Tenancy ----
    ok &= RegKey<bool>(std::string(Keys::MultiTenantEnabled),
        "MultiTenant", "Multi-tenant mode", false);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::TenantIsolationLevel),
        "MultiTenant", "Tenant isolation level",
        static_cast<uint32_t>(TenantIsolation::Shared), 0, 2);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::TenantMaxEndpoints),
        "MultiTenant", "Maximum endpoints per tenant", 10000, 10, 1000000);
    ok &= RegKey<std::string>(std::string(Keys::TenantDataResidency),
        "MultiTenant", "Tenant data residency region", std::string("auto"));
    ok &= RegKey<bool>(std::string(Keys::CrossTenantCorrelation),
        "MultiTenant", "Allow cross-tenant threat correlation", false);

    // ---- Threat Hunting ----
    ok &= RegKey<bool>(std::string(Keys::ThreatHuntEnabled),
        "ThreatHunt", "Threat hunting capabilities", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ThreatHuntMaxConcurrent),
        "ThreatHunt", "Max concurrent hunts", 5, 1, 20);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ThreatHuntTimeoutMin),
        "ThreatHunt", "Hunt execution timeout (minutes)", 60, 5, 480);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ThreatHuntMaxScopeMachines),
        "ThreatHunt", "Max machines per hunt scope", 1000, 1, 100000);
    ok &= RegKey<bool>(std::string(Keys::ThreatHuntAuditQueries),
        "ThreatHunt", "Audit all hunt queries", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ThreatHuntRetentionDays),
        "ThreatHunt", "Hunt result retention (days)", 90, 7, 365);
    ok &= RegKey<bool>(std::string(Keys::ThreatHuntIOCFeedEnabled),
        "ThreatHunt", "IoC feed for hunt enrichment", true);
    ok &= RegKey<bool>(std::string(Keys::ThreatHuntYaraEnabled),
        "ThreatHunt", "YARA rule scanning in hunts", true);

    // ---- Data Lake ----
    ok &= RegKey<bool>(std::string(Keys::DataLakeEnabled),
        "DataLake", "Data lake storage", false);
    ok &= RegKey<std::string>(std::string(Keys::DataLakeEndpoint),
        "DataLake", "Data lake endpoint", std::string(""), true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::DataLakeRetentionDays),
        "DataLake", "Data lake retention (days)", 365, 30, 3650);
    ok &= RegKey<bool>(std::string(Keys::DataLakeCompressionEnabled),
        "DataLake", "Compress data in data lake", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::DataLakeMaxStorageGB),
        "DataLake", "Max data lake storage (GB)", 1024, 10, 102400);
    ok &= RegKey<bool>(std::string(Keys::DataLakeEncryptionAtRest),
        "DataLake", "Encrypt data at rest in data lake", true);

    // ---- Alerts ----
    ok &= RegKey<bool>(std::string(Keys::AlertAggregation),
        "Alerts", "Alert aggregation", true);
    ok &= RegKey<bool>(std::string(Keys::AlertDeduplication),
        "Alerts", "Alert deduplication", true);
    ok &= RegKey<bool>(std::string(Keys::AlertEscalationEnabled),
        "Alerts", "Alert escalation workflow", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::AlertSLAResponseMin),
        "Alerts", "Alert SLA response time (minutes)", 15, 1, 1440);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::AlertMaxQueueSize),
        "Alerts", "Maximum alert queue size", 100000, 1000, 10000000);
    ok &= RegKey<bool>(std::string(Keys::AlertWebhookEnabled),
        "Alerts", "Alert webhook notifications", false);
    ok &= RegKey<std::string>(std::string(Keys::AlertWebhookUrl),
        "Alerts", "Alert webhook URL", std::string(""), true);

    if (!ok) {
        Utils::Logger::Error("[XDR Config] One or more key registrations failed");
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

    bool ok = true;

    // Step 1: Register inherited EDR policies
    ok &= PhantomEDR::Config::RegisterPolicyTemplates();

    // Step 2: XDR-specific mandatory policies

    // SIEM Security Policy — data in transit must be encrypted
    {
        Policy siemSec{};
        siemSec.id = "XDR-SIEM-SEC-001";
        siemSec.name = "XDR SIEM Transport Security";
        siemSec.type = PolicyType::Network;
        siemSec.enforcement = EnforcementLevel::Mandatory;
        siemSec.description = "Mandatory TLS encryption for SIEM data transport";

        siemSec.settings.push_back({std::string(Keys::SIEMTLSEnabled), "true", EnforcementLevel::Mandatory});
        siemSec.settings.push_back({std::string(Keys::CloudEncryptionEnabled), "true", EnforcementLevel::Mandatory});
        siemSec.settings.push_back({std::string(Keys::DataLakeEncryptionAtRest), "true", EnforcementLevel::Mandatory});

        ok &= PM::Instance().ApplyPolicy(siemSec);
    }

    // SOAR Safety Policy — playbooks sandboxed and audited
    {
        Policy soarSafe{};
        soarSafe.id = "XDR-SOAR-SAFE-001";
        soarSafe.name = "XDR SOAR Execution Safety";
        soarSafe.type = PolicyType::Application;
        soarSafe.enforcement = EnforcementLevel::Mandatory;
        soarSafe.description = "Mandatory sandboxing and auditing for SOAR playbook execution";

        soarSafe.settings.push_back({std::string(Keys::SOARAuditAll), "true", EnforcementLevel::Mandatory});
        soarSafe.settings.push_back({std::string(Keys::SOARSandboxExecution), "true", EnforcementLevel::Mandatory});
        soarSafe.settings.push_back({std::string(Keys::ThreatHuntAuditQueries), "true", EnforcementLevel::Mandatory});

        ok &= PM::Instance().ApplyPolicy(soarSafe);
    }

    if (!ok) {
        Utils::Logger::Error("[XDR Config] One or more policy template registrations failed");
    }
    return ok;
}

// ============================================================================
// RegisterProfilePresets
// ============================================================================

[[nodiscard]] bool RegisterProfilePresets() {
    using ProfileDef = ShadowStrike::Config::ProfileDefinition;
    using SystemProfile = ShadowStrike::Config::SystemProfile;

    bool ok = true;

    // Step 1: Inherit EDR profiles
    ok &= PhantomEDR::Config::RegisterProfilePresets();

    // Step 2: XDR Correlation-Aware Profile — higher resource allocation for
    // cross-endpoint event processing
    {
        ProfileDef corrProfile{};
        corrProfile.type = SystemProfile::Custom;
        corrProfile.name = "XDR Correlation Node";
        corrProfile.description = "High-resource profile for endpoints running correlation engine";

        corrProfile.resources.maxCpuPercent = 40;
        corrProfile.resources.maxMemoryMB = 2048;
        corrProfile.resources.ioPriority = 2;
        corrProfile.resources.maxConcurrentScans = 8;
        corrProfile.resources.threadPriority = 1;

        corrProfile.scanSettings.realTimeProtection = true;
        corrProfile.scanSettings.behaviorMonitoring = true;
        corrProfile.scanSettings.archiveScanning = true;
        corrProfile.scanSettings.scanNetworkFiles = true;
        corrProfile.scanSettings.heuristicLevel = 3;
        corrProfile.scanSettings.cloudLookup = true;

        ok &= ProfM::Instance().CreateCustomProfile(corrProfile);
    }

    if (!ok) {
        Utils::Logger::Error("[XDR Config] One or more profile preset registrations failed");
    }
    return ok;
}

// ============================================================================
// ValidateConfiguration
// ============================================================================

[[nodiscard]] bool ValidateConfiguration() {
    auto& cm = CM::Instance();
    bool valid = true;

    // Step 1: Run inherited EDR validation
    valid &= PhantomEDR::Config::ValidateConfiguration();

    // Step 2: XDR-specific validation rules

    // If SIEM is enabled, endpoint must be configured
    bool siemEnabled = cm.GetValue<bool>(std::string(Keys::SIEMEnabled), false);
    if (siemEnabled) {
        auto endpoint = cm.GetValue<std::string>(std::string(Keys::SIEMEndpoint), std::string(""));
        if (endpoint.empty()) {
            Utils::Logger::Error("[XDR Config] SIEM enabled but no endpoint configured");
            valid = false;
        }

        bool tlsEnabled = cm.GetValue<bool>(std::string(Keys::SIEMTLSEnabled), true);
        if (!tlsEnabled) {
            Utils::Logger::Warn("[XDR Config] SIEM TLS is disabled — data in transit is unencrypted");
        }
    }

    // If cloud correlation is enabled, tenant ID must be set
    bool cloudEnabled = cm.GetValue<bool>(std::string(Keys::CloudCorrelationEnabled), false);
    if (cloudEnabled) {
        auto tenantId = cm.GetValue<std::string>(std::string(Keys::CloudTenantId), std::string(""));
        if (tenantId.empty()) {
            Utils::Logger::Error("[XDR Config] Cloud correlation enabled but no tenant ID configured");
            valid = false;
        }
        auto apiEndpoint = cm.GetValue<std::string>(std::string(Keys::CloudAPIEndpoint), std::string(""));
        if (apiEndpoint.empty()) {
            Utils::Logger::Error("[XDR Config] Cloud correlation enabled but no API endpoint configured");
            valid = false;
        }
    }

    // If multi-tenant, validate isolation level
    bool multiTenant = cm.GetValue<bool>(std::string(Keys::MultiTenantEnabled), false);
    if (multiTenant) {
        bool crossTenant = cm.GetValue<bool>(std::string(Keys::CrossTenantCorrelation), false);
        auto isolation = cm.GetValue<uint32_t>(std::string(Keys::TenantIsolationLevel),
            static_cast<uint32_t>(TenantIsolation::Shared));
        if (crossTenant && isolation == static_cast<uint32_t>(TenantIsolation::Full)) {
            Utils::Logger::Error("[XDR Config] Cross-tenant correlation incompatible with Full isolation");
            valid = false;
        }
    }

    auto errors = cm.ValidateAll();
    for (const auto& err : errors) {
        Utils::Logger::Warn("[XDR Config] Validation error for '{}': {}", err.key, err.message);
    }

    if (valid && errors.empty()) {
        Utils::Logger::Info("[XDR Config] Configuration validation passed");
    } else {
        Utils::Logger::Error("[XDR Config] Configuration validation found issues");
        valid = false;
    }

    return valid;
}

} // namespace ShadowStrike::Products::PhantomXDR::Config
