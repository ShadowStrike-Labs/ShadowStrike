/*
 * Fuzzer-only link seam for optional TrafficAnalyzer and NetworkTrafficFilter integrations.
 *
 * The traffic harness exercises the real TrafficAnalyzer and NetworkTrafficFilter
 * implementations. Those modules opportunistically call adjacent detection
 * subsystems that are not part of this specific fuzz target. To keep the harness
 * focused and buildable without dragging unrelated engines into the binary, we
 * provide narrow no-op definitions here for the optional collaborators that the
 * traffic path can reference but does not initialize.
 */

#include "Core/Network/BotnetDetector.hpp"
#include "Core/Network/P2PMonitor.hpp"
#include "Core/Network/TorDetector.hpp"
#include "Core/Network/URLAnalyzer.hpp"
#include "Core/Network/VPNDetector.hpp"
#include "SignatureStore/SignatureStore.hpp"
#include "ThreatIntel/ThreatIntelLookup.hpp"
#include "Utils/ProcessUtils.hpp"

namespace ShadowStrike::Core::Network {

class URLAnalyzerImpl {};
class TorDetectorImpl {};
class VPNDetectorImpl {};
class P2PMonitorImpl {};
class BotnetDetector::BotnetDetectorImpl {};

URLAnalyzer& URLAnalyzer::Instance() {
    static URLAnalyzer instance;
    return instance;
}

URLAnalyzer::URLAnalyzer() = default;
URLAnalyzer::~URLAnalyzer() = default;

bool URLAnalyzer::IsInitialized() const noexcept {
    return false;
}

DomainVerdict URLAnalyzer::AnalyzeDomain(const std::string&) {
    return {};
}

TorDetector& TorDetector::Instance() {
    static TorDetector instance;
    return instance;
}

TorDetector::TorDetector() = default;
TorDetector::~TorDetector() = default;

bool TorDetector::IsRunning() const noexcept {
    return false;
}

bool TorDetector::IsTorTraffic(const std::string&) {
    return false;
}

VPNDetector& VPNDetector::Instance() {
    static VPNDetector instance;
    return instance;
}

VPNDetector::VPNDetector() = default;
VPNDetector::~VPNDetector() = default;

bool VPNDetector::IsRunning() const noexcept {
    return false;
}

bool VPNDetector::IsKnownVPNIP(const std::string&) const {
    return false;
}

P2PMonitor& P2PMonitor::Instance() {
    static P2PMonitor instance;
    return instance;
}

P2PMonitor::P2PMonitor() = default;
P2PMonitor::~P2PMonitor() = default;

bool P2PMonitor::IsRunning() const noexcept {
    return false;
}

void P2PMonitor::FeedPacket(const uint64_t, std::span<const uint8_t>) {
}

BotnetDetector& BotnetDetector::Instance() {
    static BotnetDetector instance;
    return instance;
}

BotnetDetector::BotnetDetector() = default;
BotnetDetector::~BotnetDetector() = default;

bool BotnetDetector::IsRunning() const noexcept {
    return false;
}

C2Detection BotnetDetector::AnalyzePayloadForC2(std::span<const uint8_t>, const C2Protocol) {
    return {};
}

}  // namespace ShadowStrike::Core::Network

namespace ShadowStrike::ThreatIntel {

class ThreatIntelLookup::Impl {};

ThreatIntelLookup::ThreatIntelLookup() = default;
ThreatIntelLookup::~ThreatIntelLookup() = default;

bool ThreatIntelLookup::IsInitialized() const noexcept {
    return false;
}

ThreatLookupResult ThreatIntelLookup::LookupHash(
    std::string_view,
    const UnifiedLookupOptions&) noexcept
{
    return {};
}

}  // namespace ShadowStrike::ThreatIntel

namespace ShadowStrike::SignatureStore {

ScanResult SignatureStore::ScanBuffer(
    std::span<const uint8_t>,
    const ScanOptions&) const noexcept
{
    return {};
}

}  // namespace ShadowStrike::SignatureStore

namespace ShadowStrike::Utils::ProcessUtils {

std::optional<std::wstring> GetProcessName(ProcessId, Error*) noexcept {
    return std::nullopt;
}

}  // namespace ShadowStrike::Utils::ProcessUtils
