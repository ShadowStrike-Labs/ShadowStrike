/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#include "Products/Community/PhantomEDR/EDRProductOrchestrator.hpp"

#include <format>  // Must precede Logger.hpp — Logger uses std::format_string

// ── PhantomCore ──
#include "PhantomCore/Utils/Logger.hpp"

// ── Config (Tier 1) ──
#include "Products/Community/PhantomEDR/Config/EDRConfigRegistration.hpp"

// ── Forensics (Tier 1) — legacy namespace ShadowStrike::Forensics ──
#include "Products/Community/PhantomEDR/Forensics/ArtifactExtractor.hpp"
#include "Products/Community/PhantomEDR/Forensics/EvidenceCollector.hpp"
#include "Products/Community/PhantomEDR/Forensics/IncidentRecorder.hpp"
#include "Products/Community/PhantomEDR/Forensics/MemoryDumper.hpp"
#include "Products/Community/PhantomEDR/Forensics/NetworkCapture.hpp"
#include "Products/Community/PhantomEDR/Forensics/TimelineAnalyzer.hpp"

// ── ThreatHunting (Tier 1) ──
#include "Products/Community/PhantomEDR/ThreatHunting/HuntQueryEngine.hpp"
#include "Products/Community/PhantomEDR/ThreatHunting/HuntRuleManager.hpp"
#include "Products/Community/PhantomEDR/ThreatHunting/HuntScheduler.hpp"
#include "Products/Community/PhantomEDR/ThreatHunting/IOCScanner.hpp"

// ── IncidentResponse (Tier 1) ──
#include "Products/Community/PhantomEDR/IncidentResponse/AlertCorrelator.hpp"
#include "Products/Community/PhantomEDR/IncidentResponse/ContainmentEngine.hpp"
#include "Products/Community/PhantomEDR/IncidentResponse/IncidentManager.hpp"
#include "Products/Community/PhantomEDR/IncidentResponse/RemediationEngine.hpp"

// ── LiveResponse (Tier 1) ──
#include "Products/Community/PhantomEDR/LiveResponse/FileInspector.hpp"
#include "Products/Community/PhantomEDR/LiveResponse/ProcessInspector.hpp"
#include "Products/Community/PhantomEDR/LiveResponse/RegistryInspector.hpp"

// ── Telemetry (Tier 1) ──
#include "Products/Community/PhantomEDR/Telemetry/TelemetryCollector.hpp"
#include "Products/Community/PhantomEDR/Telemetry/TelemetryFilter.hpp"
#include "Products/Community/PhantomEDR/Telemetry/TelemetrySerializer.hpp"

// ── Playbooks (Tier 2) ──
#include "Products/Community/PhantomEDR/Playbooks/PlaybookAction.hpp"
#include "Products/Community/PhantomEDR/Playbooks/PlaybookEngine.hpp"
#include "Products/Community/PhantomEDR/Playbooks/PlaybookLibrary.hpp"
#include "Products/Community/PhantomEDR/Playbooks/PlaybookScheduler.hpp"

// ── AssetInventory (Tier 2) ──
#include "Products/Community/PhantomEDR/AssetInventory/AssetDatabase.hpp"
#include "Products/Community/PhantomEDR/AssetInventory/AssetDiscovery.hpp"
#include "Products/Community/PhantomEDR/AssetInventory/SoftwareInventory.hpp"

// ── Vulnerability (Tier 2) ──
#include "Products/Community/PhantomEDR/Vulnerability/VulnDatabase.hpp"
#include "Products/Community/PhantomEDR/Vulnerability/VulnScanner.hpp"
#include "Products/Community/PhantomEDR/Vulnerability/PatchAssessment.hpp"
#include "Products/Community/PhantomEDR/Vulnerability/RiskScorer.hpp"

// ── DeviceControl (Tier 2) ──
#include "Products/Community/PhantomEDR/DeviceControl/DevicePolicyEngine.hpp"
#include "Products/Community/PhantomEDR/DeviceControl/DeviceExceptions.hpp"
#include "Products/Community/PhantomEDR/DeviceControl/DeviceAuditLog.hpp"

// ── Compliance (Tier 2) ──
#include "Products/Community/PhantomEDR/Compliance/ComplianceEngine.hpp"
#include "Products/Community/PhantomEDR/Compliance/CompliancePolicies.hpp"
#include "Products/Community/PhantomEDR/Compliance/ComplianceReporter.hpp"
#include "Products/Community/PhantomEDR/Compliance/HardeningAdvisor.hpp"

// ── Sandboxing (Tier 3) ──
#include "Products/Community/PhantomEDR/Sandboxing/LocalSandbox.hpp"
#include "Products/Community/PhantomEDR/Sandboxing/SandboxAnalyzer.hpp"
#include "Products/Community/PhantomEDR/Sandboxing/SandboxPolicy.hpp"

// ── Reporting (Tier 3) ──
#include "Products/Community/PhantomEDR/Reporting/ReportGenerator.hpp"
#include "Products/Community/PhantomEDR/Reporting/ExecutiveSummary.hpp"
#include "Products/Community/PhantomEDR/Reporting/IncidentReport.hpp"

// ── PolicyEngine (Tier 3) ──
#include "Products/Community/PhantomEDR/PolicyEngine/PolicyManager.hpp"
#include "Products/Community/PhantomEDR/PolicyEngine/PolicyEnforcer.hpp"
#include "Products/Community/PhantomEDR/PolicyEngine/PolicyAuditLog.hpp"

#include <atomic>
#include <chrono>
#include <format>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR {

using ShadowStrike::Utils::Logger;

static constexpr std::string_view kLogPrefix = "[EDROrchestrator]";

// ============================================================================
// SUBSYSTEM DESCRIPTOR
// ============================================================================

struct SubsystemDescriptor {
    std::string_view name;
    std::function<bool()> init;
    std::function<void()> shutdown;
    bool critical;  // If critical subsystem fails, entire init fails
};

// ============================================================================
// IMPL
// ============================================================================

class EDRProductOrchestratorImpl {
public:
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized; }
    uint32_t InitializedCount() const noexcept { return m_initCount.load(); }
    uint32_t TotalCount() const noexcept;
    bool IsHealthy() const noexcept { return m_healthy.load(); }

private:
    void BuildBootSequence();
    bool InitSubsystem(const SubsystemDescriptor& desc);

    std::vector<SubsystemDescriptor> m_bootSequence;
    std::vector<size_t> m_initOrder;  // indices into m_bootSequence, for reverse shutdown
    std::atomic<uint32_t> m_initCount{0};
    std::atomic<bool> m_healthy{false};
    bool m_initialized = false;
};

// ============================================================================
// BOOT SEQUENCE DEFINITION
// ============================================================================

void EDRProductOrchestratorImpl::BuildBootSequence() {
    m_bootSequence.clear();

    // -------------------------------------------------------------------
    // Phase 0: Configuration — must come first
    // -------------------------------------------------------------------
    m_bootSequence.push_back({
        "Config/ProductDefaults", []() { return Config::RegisterProductDefaults(); },
        []() {}, true
    });
    m_bootSequence.push_back({
        "Config/PolicyTemplates", []() { return Config::RegisterPolicyTemplates(); },
        []() {}, false
    });
    m_bootSequence.push_back({
        "Config/ProfilePresets", []() { return Config::RegisterProfilePresets(); },
        []() {}, false
    });
    m_bootSequence.push_back({
        "Config/Validate", []() { return Config::ValidateConfiguration(); },
        []() {}, false
    });

    // -------------------------------------------------------------------
    // Phase 1: Core data stores — no inter-module dependencies
    // -------------------------------------------------------------------
    m_bootSequence.push_back({
        "Telemetry/Filter",
        []() { return Telemetry::TelemetryFilter::Instance().Initialize(Telemetry::FilterConfig{}); },
        []() { Telemetry::TelemetryFilter::Instance().Shutdown(); },
        true
    });
    m_bootSequence.push_back({
        "Telemetry/Serializer",
        []() { return Telemetry::TelemetrySerializer::Instance().Initialize(Telemetry::SerializerConfig{}); },
        []() { Telemetry::TelemetrySerializer::Instance().Shutdown(); },
        true
    });
    m_bootSequence.push_back({
        "Telemetry/Collector",
        []() { return Telemetry::TelemetryCollector::Instance().Initialize(Telemetry::CollectorConfig{}); },
        []() { Telemetry::TelemetryCollector::Instance().Shutdown(); },
        true
    });

    // Forensics core — legacy namespace ShadowStrike::Forensics
    m_bootSequence.push_back({
        "Forensics/EvidenceCollector",
        []() { return Forensics::EvidenceCollector::Instance().Initialize(); },
        []() { Forensics::EvidenceCollector::Instance().Shutdown(); },
        true
    });
    m_bootSequence.push_back({
        "Forensics/MemoryDumper",
        []() { return Forensics::MemoryDumper::Instance().Initialize(); },
        []() { Forensics::MemoryDumper::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Forensics/NetworkCapture",
        []() { return Forensics::NetworkCapture::Instance().Initialize(); },
        []() { Forensics::NetworkCapture::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Forensics/ArtifactExtractor",
        []() { return Forensics::ArtifactExtractor::Instance().Initialize(); },
        []() { Forensics::ArtifactExtractor::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Forensics/TimelineAnalyzer",
        []() { return Forensics::TimelineAnalyzer::Instance().Initialize(); },
        []() { Forensics::TimelineAnalyzer::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Forensics/IncidentRecorder",
        []() { return Forensics::IncidentRecorder::Instance().Initialize(); },
        []() { Forensics::IncidentRecorder::Instance().Shutdown(); },
        true
    });

    // -------------------------------------------------------------------
    // Phase 2: Detection & response fundamentals
    // -------------------------------------------------------------------
    m_bootSequence.push_back({
        "ThreatHunting/HuntRuleManager",
        []() { return ThreatHunting::HuntRuleManager::Instance().Initialize(); },
        []() { ThreatHunting::HuntRuleManager::Instance().Shutdown(); },
        true
    });
    m_bootSequence.push_back({
        "ThreatHunting/IOCScanner",
        []() { return ThreatHunting::IOCScanner::Instance().Initialize(); },
        []() { ThreatHunting::IOCScanner::Instance().Shutdown(); },
        true
    });
    m_bootSequence.push_back({
        "ThreatHunting/HuntQueryEngine",
        []() { return ThreatHunting::HuntQueryEngine::Instance().Initialize(); },
        []() { ThreatHunting::HuntQueryEngine::Instance().Shutdown(); },
        true
    });
    m_bootSequence.push_back({
        "ThreatHunting/HuntScheduler",
        []() { return ThreatHunting::HuntScheduler::Instance().Initialize(); },
        []() { ThreatHunting::HuntScheduler::Instance().Shutdown(); },
        false
    });

    m_bootSequence.push_back({
        "IncidentResponse/AlertCorrelator",
        []() { return IncidentResponse::AlertCorrelator::Instance().Initialize(); },
        []() { IncidentResponse::AlertCorrelator::Instance().Shutdown(); },
        true
    });
    m_bootSequence.push_back({
        "IncidentResponse/ContainmentEngine",
        []() { return IncidentResponse::ContainmentEngine::Instance().Initialize(); },
        []() { IncidentResponse::ContainmentEngine::Instance().Shutdown(); },
        true
    });
    m_bootSequence.push_back({
        "IncidentResponse/RemediationEngine",
        []() { return IncidentResponse::RemediationEngine::Instance().Initialize(); },
        []() { IncidentResponse::RemediationEngine::Instance().Shutdown(); },
        true
    });
    m_bootSequence.push_back({
        "IncidentResponse/IncidentManager",
        []() { return IncidentResponse::IncidentManager::Instance().Initialize(); },
        []() { IncidentResponse::IncidentManager::Instance().Shutdown(); },
        true
    });

    // Live Response — interactive forensics
    m_bootSequence.push_back({
        "LiveResponse/ProcessInspector",
        []() { return LiveResponse::ProcessInspector::Instance().Initialize(); },
        []() { LiveResponse::ProcessInspector::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "LiveResponse/FileInspector",
        []() { return LiveResponse::FileInspector::Instance().Initialize(); },
        []() { LiveResponse::FileInspector::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "LiveResponse/RegistryInspector",
        []() { return LiveResponse::RegistryInspector::Instance().Initialize(); },
        []() { LiveResponse::RegistryInspector::Instance().Shutdown(); },
        false
    });

    // -------------------------------------------------------------------
    // Phase 3: Tier 2 — Advanced Operations
    // -------------------------------------------------------------------
    m_bootSequence.push_back({
        "Playbooks/PlaybookLibrary",
        []() { return Playbooks::PlaybookLibrary::Instance().Initialize(); },
        []() { Playbooks::PlaybookLibrary::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Playbooks/PlaybookAction",
        []() { return Playbooks::PlaybookAction::Instance().Initialize(); },
        []() { Playbooks::PlaybookAction::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Playbooks/PlaybookEngine",
        []() { return Playbooks::PlaybookEngine::Instance().Initialize(); },
        []() { Playbooks::PlaybookEngine::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Playbooks/PlaybookScheduler",
        []() { return Playbooks::PlaybookScheduler::Instance().Initialize(); },
        []() { Playbooks::PlaybookScheduler::Instance().Shutdown(); },
        false
    });

    m_bootSequence.push_back({
        "AssetInventory/AssetDatabase",
        []() { return AssetInventory::AssetDatabase::Instance().Initialize(); },
        []() { AssetInventory::AssetDatabase::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "AssetInventory/AssetDiscovery",
        []() { return AssetInventory::AssetDiscovery::Instance().Initialize(); },
        []() { AssetInventory::AssetDiscovery::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "AssetInventory/SoftwareInventory",
        []() { return AssetInventory::SoftwareInventory::Instance().Initialize(); },
        []() { AssetInventory::SoftwareInventory::Instance().Shutdown(); },
        false
    });

    m_bootSequence.push_back({
        "Vulnerability/VulnDatabase",
        []() { return Vulnerability::VulnDatabase::Instance().Initialize(); },
        []() { Vulnerability::VulnDatabase::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Vulnerability/VulnScanner",
        []() { return Vulnerability::VulnScanner::Instance().Initialize(); },
        []() { Vulnerability::VulnScanner::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Vulnerability/PatchAssessment",
        []() { return Vulnerability::PatchAssessment::Instance().Initialize(); },
        []() { Vulnerability::PatchAssessment::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Vulnerability/RiskScorer",
        []() { return Vulnerability::RiskScorer::Instance().Initialize(); },
        []() { Vulnerability::RiskScorer::Instance().Shutdown(); },
        false
    });

    m_bootSequence.push_back({
        "DeviceControl/DevicePolicyEngine",
        []() { return DeviceControl::DevicePolicyEngine::Instance().Initialize(); },
        []() { DeviceControl::DevicePolicyEngine::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "DeviceControl/DeviceExceptions",
        []() { return DeviceControl::DeviceExceptions::Instance().Initialize(); },
        []() { DeviceControl::DeviceExceptions::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "DeviceControl/DeviceAuditLog",
        []() { return DeviceControl::DeviceAuditLog::Instance().Initialize(); },
        []() { DeviceControl::DeviceAuditLog::Instance().Shutdown(); },
        false
    });

    m_bootSequence.push_back({
        "Compliance/CompliancePolicies",
        []() { return Compliance::CompliancePolicies::Instance().Initialize(); },
        []() { Compliance::CompliancePolicies::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Compliance/ComplianceEngine",
        []() { return Compliance::ComplianceEngine::Instance().Initialize(); },
        []() { Compliance::ComplianceEngine::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Compliance/ComplianceReporter",
        []() { return Compliance::ComplianceReporter::Instance().Initialize(); },
        []() { Compliance::ComplianceReporter::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Compliance/HardeningAdvisor",
        []() { return Compliance::HardeningAdvisor::Instance().Initialize(); },
        []() { Compliance::HardeningAdvisor::Instance().Shutdown(); },
        false
    });

    // -------------------------------------------------------------------
    // Phase 4: Tier 3 — Platform Services
    // -------------------------------------------------------------------
    m_bootSequence.push_back({
        "Sandboxing/SandboxPolicy",
        []() { return Sandboxing::SandboxPolicy::Instance().Initialize(); },
        []() { Sandboxing::SandboxPolicy::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Sandboxing/LocalSandbox",
        []() { return Sandboxing::LocalSandbox::Instance().Initialize(); },
        []() { Sandboxing::LocalSandbox::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Sandboxing/SandboxAnalyzer",
        []() { return Sandboxing::SandboxAnalyzer::Instance().Initialize(); },
        []() { Sandboxing::SandboxAnalyzer::Instance().Shutdown(); },
        false
    });

    m_bootSequence.push_back({
        "Reporting/ReportGenerator",
        []() { return Reporting::ReportGenerator::Instance().Initialize(); },
        []() { Reporting::ReportGenerator::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Reporting/ExecutiveSummary",
        []() { return Reporting::ExecutiveSummary::Instance().Initialize(); },
        []() { Reporting::ExecutiveSummary::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "Reporting/IncidentReport",
        []() { return Reporting::IncidentReport::Instance().Initialize(); },
        []() { Reporting::IncidentReport::Instance().Shutdown(); },
        false
    });

    m_bootSequence.push_back({
        "PolicyEngine/PolicyAuditLog",
        []() { return PolicyEngine::PolicyAuditLog::Instance().Initialize(); },
        []() { PolicyEngine::PolicyAuditLog::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "PolicyEngine/PolicyManager",
        []() { return PolicyEngine::PolicyManager::Instance().Initialize(); },
        []() { PolicyEngine::PolicyManager::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "PolicyEngine/PolicyEnforcer",
        []() { return PolicyEngine::PolicyEnforcer::Instance().Initialize(); },
        []() { PolicyEngine::PolicyEnforcer::Instance().Shutdown(); },
        false
    });
}

// ============================================================================
// INIT SUBSYSTEM
// ============================================================================

bool EDRProductOrchestratorImpl::InitSubsystem(const SubsystemDescriptor& desc) {
    const auto start = std::chrono::steady_clock::now();
    bool ok = false;

    try {
        ok = desc.init();
    } catch (const std::exception& ex) {
        Logger::Error("{} Exception in {} init: {}", kLogPrefix, desc.name, ex.what());
        ok = false;
    } catch (...) {
        Logger::Error("{} Unknown exception in {} init", kLogPrefix, desc.name);
        ok = false;
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    if (ok) {
        m_initCount.fetch_add(1, std::memory_order_relaxed);
        Logger::Info("{} [OK] {} initialized ({}ms)", kLogPrefix, desc.name, elapsed);
    } else {
        Logger::Error("{} [FAIL] {} FAILED ({}ms) [critical={}]",
                      kLogPrefix, desc.name, elapsed, desc.critical ? "yes" : "no");
    }
    return ok;
}

// ============================================================================
// INITIALIZE
// ============================================================================

bool EDRProductOrchestratorImpl::Initialize() {
    if (m_initialized) return true;

    Logger::Info("{} ═══════════════════════════════════════════════", kLogPrefix);
    Logger::Info("{} Starting {} ...", kLogPrefix, EDRProductOrchestrator::ProductName());
    Logger::Info("{} ═══════════════════════════════════════════════", kLogPrefix);

    BuildBootSequence();
    m_initOrder.clear();
    m_initOrder.reserve(m_bootSequence.size());

    const auto bootStart = std::chrono::steady_clock::now();
    bool criticalFailure = false;

    for (size_t i = 0; i < m_bootSequence.size(); ++i) {
        const auto& desc = m_bootSequence[i];

        if (criticalFailure) {
            Logger::Warn("{} Skipping {} — critical subsystem already failed",
                         kLogPrefix, desc.name);
            continue;
        }

        const bool ok = InitSubsystem(desc);
        if (ok) {
            m_initOrder.push_back(i);
        } else if (desc.critical) {
            criticalFailure = true;
            Logger::Error("{} Critical subsystem {} failed — aborting boot sequence",
                          kLogPrefix, desc.name);
        }
    }

    const auto bootElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - bootStart).count();

    if (criticalFailure) {
        Logger::Error("{} Boot FAILED after {}ms — {}/{} subsystems started",
                      kLogPrefix, bootElapsed,
                      m_initCount.load(), m_bootSequence.size());
        m_healthy.store(false);
        Shutdown();
        return false;
    }

    m_initialized = true;
    m_healthy.store(true);

    Logger::Info("{} ═══════════════════════════════════════════════", kLogPrefix);
    Logger::Info("{} {} READY — {}/{} subsystems in {}ms",
                 kLogPrefix, EDRProductOrchestrator::ProductName(),
                 m_initCount.load(), m_bootSequence.size(), bootElapsed);
    Logger::Info("{} ═══════════════════════════════════════════════", kLogPrefix);

    return true;
}

// ============================================================================
// SHUTDOWN — REVERSE ORDER
// ============================================================================

void EDRProductOrchestratorImpl::Shutdown() {
    Logger::Info("{} Shutting down {} ({} subsystems to stop)...",
                 kLogPrefix, EDRProductOrchestrator::ProductName(),
                 m_initOrder.size());

    for (auto it = m_initOrder.rbegin(); it != m_initOrder.rend(); ++it) {
        const auto& desc = m_bootSequence[*it];
        try {
            desc.shutdown();
            Logger::Info("{} [OK] {} shut down", kLogPrefix, desc.name);
        } catch (const std::exception& ex) {
            Logger::Error("{} Exception shutting down {}: {}",
                          kLogPrefix, desc.name, ex.what());
        } catch (...) {
            Logger::Error("{} Unknown exception shutting down {}",
                          kLogPrefix, desc.name);
        }
    }

    m_initOrder.clear();
    m_initCount.store(0, std::memory_order_relaxed);
    m_healthy.store(false);
    m_initialized = false;

    Logger::Info("{} {} shutdown complete", kLogPrefix,
                 EDRProductOrchestrator::ProductName());
}

uint32_t EDRProductOrchestratorImpl::TotalCount() const noexcept {
    return static_cast<uint32_t>(m_bootSequence.size());
}

// ============================================================================
// SINGLETON FORWARDING
// ============================================================================

EDRProductOrchestrator::EDRProductOrchestrator()
    : m_impl(std::make_unique<EDRProductOrchestratorImpl>()) {}
EDRProductOrchestrator::~EDRProductOrchestrator() = default;

EDRProductOrchestrator& EDRProductOrchestrator::Instance() {
    static EDRProductOrchestrator inst;
    return inst;
}

bool EDRProductOrchestrator::Initialize() { return m_impl->Initialize(); }
void EDRProductOrchestrator::Shutdown() { m_impl->Shutdown(); }
bool EDRProductOrchestrator::IsInitialized() const noexcept { return m_impl->IsInitialized(); }
uint32_t EDRProductOrchestrator::InitializedSubsystemCount() const noexcept { return m_impl->InitializedCount(); }
uint32_t EDRProductOrchestrator::TotalSubsystemCount() const noexcept { return m_impl->TotalCount(); }
bool EDRProductOrchestrator::IsHealthy() const noexcept { return m_impl->IsHealthy(); }

// ============================================================================
// PRODUCT ENTRY POINT
// ============================================================================

bool RegisterEDRModules() {
    Logger::Info("{} RegisterEDRModules() invoked", kLogPrefix);
    return EDRProductOrchestrator::Instance().Initialize();
}

} // namespace ShadowStrike::Products::PhantomEDR
