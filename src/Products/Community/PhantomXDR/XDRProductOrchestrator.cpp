/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#include "Products/Community/PhantomXDR/XDRProductOrchestrator.hpp"

#include <format>  // Must precede Logger.hpp

// ── PhantomCore ──
#include "PhantomCore/Utils/Logger.hpp"

// ── XDR Config (Tier 3) ──
#include "Products/Community/PhantomXDR/Config/XDRConfigRegistration.hpp"

// ── XDR Correlation (Tier 1) ──
#include "Products/Community/PhantomXDR/XDRCorrelation/CorrelationRules.hpp"
#include "Products/Community/PhantomXDR/XDRCorrelation/CorrelationEngine.hpp"
#include "Products/Community/PhantomXDR/XDRCorrelation/StorylineBuilder.hpp"
#include "Products/Community/PhantomXDR/XDRCorrelation/IncidentScorer.hpp"

// ── Network Detection (Tier 1) ──
#include "Products/Community/PhantomXDR/NetworkDetection/NetworkSensor.hpp"
#include "Products/Community/PhantomXDR/NetworkDetection/DNSAnalyzer.hpp"
#include "Products/Community/PhantomXDR/NetworkDetection/TLSInspector.hpp"
#include "Products/Community/PhantomXDR/NetworkDetection/BeaconDetector.hpp"
#include "Products/Community/PhantomXDR/NetworkDetection/LateralMovementDetector.hpp"

// ── Identity Protection (Tier 1) ──
#include "Products/Community/PhantomXDR/IdentityProtection/ADMonitor.hpp"
#include "Products/Community/PhantomXDR/IdentityProtection/IdentityAnalytics.hpp"
#include "Products/Community/PhantomXDR/IdentityProtection/CredentialProtection.hpp"

// ── Email Threat (Tier 1) ──
#include "Products/Community/PhantomXDR/EmailThreat/EmailAnalyzer.hpp"
#include "Products/Community/PhantomXDR/EmailThreat/PhishingCorrelator.hpp"

// ── SOAR Local (Tier 2) ──
#include "Products/Community/PhantomXDR/SOARLocal/SOARPlaybooks.hpp"
#include "Products/Community/PhantomXDR/SOARLocal/SOAREngine.hpp"

// ── AI Assistant (Tier 2) ──
#include "Products/Community/PhantomXDR/AIAssistant/QueryTranslator.hpp"
#include "Products/Community/PhantomXDR/AIAssistant/IncidentSummarizer.hpp"
#include "Products/Community/PhantomXDR/AIAssistant/SOCAssistant.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR {

using ShadowStrike::Utils::Logger;

static constexpr std::string_view kLogPrefix = "[XDROrchestrator]";

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

class XDRProductOrchestratorImpl {
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
    std::vector<size_t> m_initOrder;  // indices for reverse shutdown
    std::atomic<uint32_t> m_initCount{0};
    std::atomic<bool> m_healthy{false};
    bool m_initialized = false;
};

// ============================================================================
// BOOT SEQUENCE DEFINITION
// ============================================================================

void XDRProductOrchestratorImpl::BuildBootSequence() {
    m_bootSequence.clear();

    // -------------------------------------------------------------------
    // Phase 0: XDR Configuration — must come first
    // -------------------------------------------------------------------
    m_bootSequence.push_back({
        "XDRConfig/ProductDefaults",
        []() { return Config::RegisterProductDefaults(); },
        []() {}, true
    });
    m_bootSequence.push_back({
        "XDRConfig/PolicyTemplates",
        []() { return Config::RegisterPolicyTemplates(); },
        []() {}, false
    });
    m_bootSequence.push_back({
        "XDRConfig/ProfilePresets",
        []() { return Config::RegisterProfilePresets(); },
        []() {}, false
    });
    m_bootSequence.push_back({
        "XDRConfig/Validate",
        []() { return Config::ValidateConfiguration(); },
        []() {}, false
    });

    // -------------------------------------------------------------------
    // Phase 1: Core Correlation Engine — foundation for all XDR
    // -------------------------------------------------------------------
    m_bootSequence.push_back({
        "XDRCorrelation/CorrelationRules",
        []() { return XDRCorrelation::CorrelationRules::Instance().Initialize(); },
        []() { XDRCorrelation::CorrelationRules::Instance().Shutdown(); },
        true
    });
    m_bootSequence.push_back({
        "XDRCorrelation/StorylineBuilder",
        []() { return XDRCorrelation::StorylineBuilder::Instance().Initialize(); },
        []() { XDRCorrelation::StorylineBuilder::Instance().Shutdown(); },
        true
    });
    m_bootSequence.push_back({
        "XDRCorrelation/IncidentScorer",
        []() { return XDRCorrelation::IncidentScorer::Instance().Initialize(); },
        []() { XDRCorrelation::IncidentScorer::Instance().Shutdown(); },
        true
    });
    m_bootSequence.push_back({
        "XDRCorrelation/CorrelationEngine",
        []() { return XDRCorrelation::CorrelationEngine::Instance().Initialize(); },
        []() { XDRCorrelation::CorrelationEngine::Instance().Shutdown(); },
        true
    });

    // -------------------------------------------------------------------
    // Phase 2: Detection Domains — Network, Identity, Email
    // Each domain feeds events into the Correlation Engine.
    // -------------------------------------------------------------------

    // Network Detection
    m_bootSequence.push_back({
        "NetworkDetection/NetworkSensor",
        []() { return NetworkDetection::NetworkSensor::Instance().Initialize(); },
        []() { NetworkDetection::NetworkSensor::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "NetworkDetection/DNSAnalyzer",
        []() { return NetworkDetection::DNSAnalyzer::Instance().Initialize(); },
        []() { NetworkDetection::DNSAnalyzer::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "NetworkDetection/TLSInspector",
        []() { return NetworkDetection::TLSInspector::Instance().Initialize(); },
        []() { NetworkDetection::TLSInspector::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "NetworkDetection/BeaconDetector",
        []() { return NetworkDetection::BeaconDetector::Instance().Initialize(); },
        []() { NetworkDetection::BeaconDetector::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "NetworkDetection/LateralMovementDetector",
        []() { return NetworkDetection::LateralMovementDetector::Instance().Initialize(); },
        []() { NetworkDetection::LateralMovementDetector::Instance().Shutdown(); },
        false
    });

    // Identity Protection
    m_bootSequence.push_back({
        "IdentityProtection/ADMonitor",
        []() { return IdentityProtection::ADMonitor::Instance().Initialize(); },
        []() { IdentityProtection::ADMonitor::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "IdentityProtection/IdentityAnalytics",
        []() { return IdentityProtection::IdentityAnalytics::Instance().Initialize(); },
        []() { IdentityProtection::IdentityAnalytics::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "IdentityProtection/CredentialProtection",
        []() { return IdentityProtection::CredentialProtection::Instance().Initialize(); },
        []() { IdentityProtection::CredentialProtection::Instance().Shutdown(); },
        false
    });

    // Email Threat
    m_bootSequence.push_back({
        "EmailThreat/EmailAnalyzer",
        []() { return EmailThreat::EmailAnalyzer::Instance().Initialize(); },
        []() { EmailThreat::EmailAnalyzer::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "EmailThreat/PhishingCorrelator",
        []() { return EmailThreat::PhishingCorrelator::Instance().Initialize(); },
        []() { EmailThreat::PhishingCorrelator::Instance().Shutdown(); },
        false
    });

    // -------------------------------------------------------------------
    // Phase 3: Automation — SOAR (depends on all detection domains)
    // -------------------------------------------------------------------
    m_bootSequence.push_back({
        "SOARLocal/SOARPlaybooks",
        []() { return SOARLocal::SOARPlaybooks::Instance().Initialize(); },
        []() { SOARLocal::SOARPlaybooks::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "SOARLocal/SOAREngine",
        []() { return SOARLocal::SOAREngine::Instance().Initialize(); },
        []() { SOARLocal::SOAREngine::Instance().Shutdown(); },
        false
    });

    // -------------------------------------------------------------------
    // Phase 4: AI-Assisted Operations (depends on Correlation + SOAR)
    // -------------------------------------------------------------------
    m_bootSequence.push_back({
        "AIAssistant/QueryTranslator",
        []() { return AIAssistant::QueryTranslator::Instance().Initialize(); },
        []() { AIAssistant::QueryTranslator::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "AIAssistant/IncidentSummarizer",
        []() { return AIAssistant::IncidentSummarizer::Instance().Initialize(); },
        []() { AIAssistant::IncidentSummarizer::Instance().Shutdown(); },
        false
    });
    m_bootSequence.push_back({
        "AIAssistant/SOCAssistant",
        []() { return AIAssistant::SOCAssistant::Instance().Initialize(); },
        []() { AIAssistant::SOCAssistant::Instance().Shutdown(); },
        false
    });
}

// ============================================================================
// INIT SUBSYSTEM
// ============================================================================

bool XDRProductOrchestratorImpl::InitSubsystem(const SubsystemDescriptor& desc) {
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
        Logger::Info("{} \xe2\x9c\x93 {} initialized ({}ms)", kLogPrefix, desc.name, elapsed);
    } else {
        Logger::Error("{} \xe2\x9c\x97 {} FAILED ({}ms) [critical={}]",
                      kLogPrefix, desc.name, elapsed, desc.critical ? "yes" : "no");
    }
    return ok;
}

// ============================================================================
// INITIALIZE
// ============================================================================

bool XDRProductOrchestratorImpl::Initialize() {
    if (m_initialized) return true;

    Logger::Info("{} \xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90", kLogPrefix);
    Logger::Info("{} Starting {} ...", kLogPrefix, XDRProductOrchestrator::ProductName());
    Logger::Info("{} \xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90", kLogPrefix);

    BuildBootSequence();
    m_initOrder.clear();
    m_initOrder.reserve(m_bootSequence.size());

    const auto bootStart = std::chrono::steady_clock::now();
    bool criticalFailure = false;

    for (size_t i = 0; i < m_bootSequence.size(); ++i) {
        const auto& desc = m_bootSequence[i];

        if (criticalFailure) {
            Logger::Warn("{} Skipping {} \xe2\x80\x94 critical subsystem already failed",
                         kLogPrefix, desc.name);
            continue;
        }

        const bool ok = InitSubsystem(desc);
        if (ok) {
            m_initOrder.push_back(i);
        } else if (desc.critical) {
            criticalFailure = true;
            Logger::Error("{} Critical subsystem {} failed \xe2\x80\x94 aborting boot sequence",
                          kLogPrefix, desc.name);
        }
    }

    const auto bootElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - bootStart).count();

    if (criticalFailure) {
        Logger::Error("{} Boot FAILED after {}ms \xe2\x80\x94 {}/{} subsystems started",
                      kLogPrefix, bootElapsed,
                      m_initCount.load(), m_bootSequence.size());
        m_healthy.store(false);
        Shutdown();
        return false;
    }

    m_initialized = true;
    m_healthy.store(true);

    Logger::Info("{} \xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90", kLogPrefix);
    Logger::Info("{} {} READY \xe2\x80\x94 {}/{} subsystems in {}ms",
                 kLogPrefix, XDRProductOrchestrator::ProductName(),
                 m_initCount.load(), m_bootSequence.size(), bootElapsed);
    Logger::Info("{} \xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90", kLogPrefix);

    return true;
}

// ============================================================================
// SHUTDOWN — REVERSE ORDER
// ============================================================================

void XDRProductOrchestratorImpl::Shutdown() {
    Logger::Info("{} Shutting down {} ({} subsystems to stop)...",
                 kLogPrefix, XDRProductOrchestrator::ProductName(),
                 m_initOrder.size());

    for (auto it = m_initOrder.rbegin(); it != m_initOrder.rend(); ++it) {
        const auto& desc = m_bootSequence[*it];
        try {
            desc.shutdown();
            Logger::Info("{} \xe2\x9c\x93 {} shut down", kLogPrefix, desc.name);
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
                 XDRProductOrchestrator::ProductName());
}

uint32_t XDRProductOrchestratorImpl::TotalCount() const noexcept {
    return static_cast<uint32_t>(m_bootSequence.size());
}

// ============================================================================
// SINGLETON FORWARDING
// ============================================================================

XDRProductOrchestrator::XDRProductOrchestrator()
    : m_impl(std::make_unique<XDRProductOrchestratorImpl>()) {}
XDRProductOrchestrator::~XDRProductOrchestrator() = default;

XDRProductOrchestrator& XDRProductOrchestrator::Instance() {
    static XDRProductOrchestrator inst;
    return inst;
}

bool     XDRProductOrchestrator::Initialize()                     { return m_impl->Initialize(); }
void     XDRProductOrchestrator::Shutdown()                       { m_impl->Shutdown(); }
bool     XDRProductOrchestrator::IsInitialized()  const noexcept  { return m_impl->IsInitialized(); }
uint32_t XDRProductOrchestrator::InitializedSubsystemCount() const noexcept { return m_impl->InitializedCount(); }
uint32_t XDRProductOrchestrator::TotalSubsystemCount() const noexcept { return m_impl->TotalCount(); }
bool     XDRProductOrchestrator::IsHealthy()      const noexcept  { return m_impl->IsHealthy(); }

// ============================================================================
// PRODUCT ENTRY POINT
// ============================================================================

bool RegisterXDRModules() {
    Logger::Info("{} RegisterXDRModules() invoked", kLogPrefix);
    return XDRProductOrchestrator::Instance().Initialize();
}

} // namespace ShadowStrike::Products::PhantomXDR
