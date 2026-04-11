// =============================================================================
// RealTimeProtection_stubs.cpp
//
// Test-harness shim TU for RealTimeProtection_Tests.
//
// Provides minimal out-of-line definitions for every symbol pulled in by
// RealTimeProtection.cpp that is NOT compiled as part of this harness.
// No test logic lives here — these stubs exist solely to satisfy the linker.
//
// Compile flags must match the rest of the harness: /std:c++20 /MDd /EHsc
// =============================================================================

#pragma warning(disable: 4100)  // unreferenced formal parameter
#pragma warning(disable: 4189)  // local variable initialized but not referenced
#pragma warning(disable: 4244)  // conversion possible loss of data
#pragma warning(disable: 4267)  // conversion size_t -> smaller
#pragma warning(disable: 4324)  // structure padded due to alignment specifier
#pragma warning(disable: 4702)  // unreachable code

// ---------------------------------------------------------------------------
// Standard headers (before project headers on Windows)
// ---------------------------------------------------------------------------
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <memory>
#include <functional>
#include <chrono>
#include <filesystem>
#include <vector>
#include <span>
#include <atomic>

// ---------------------------------------------------------------------------
// Store / shared infrastructure
// ---------------------------------------------------------------------------
#include "src/PhantomCore/ThreatIntel/ThreatIntelStore.hpp"
#include "src/PhantomCore/HashStore/HashStore.hpp"
#include "src/PhantomCore/PatternStore/PatternStore.hpp"
#include "src/PhantomCore/SignatureStore/SignatureStore.hpp"

// ---------------------------------------------------------------------------
// Utils
// ---------------------------------------------------------------------------
#include "src/PhantomCore/Utils/ProcessUtils.hpp"

// ---------------------------------------------------------------------------
// RealTime subsystems
// ---------------------------------------------------------------------------
#include "src/PhantomCore/RealTime/FileSystemFilter.hpp"
#include "src/PhantomCore/RealTime/NetworkTrafficFilter.hpp"
#include "src/PhantomCore/RealTime/AccessControlManager.hpp"
#include "src/PhantomCore/RealTime/BehaviorBlocker.hpp"
#include "src/PhantomCore/RealTime/ExploitPrevention.hpp"
#include "src/PhantomCore/RealTime/FileIntegrityMonitor.hpp"
#include "src/PhantomCore/RealTime/MemoryProtection.hpp"
#include "src/PhantomCore/RealTime/ZeroHourProtection.hpp"
#include "src/PhantomCore/RealTime/ProcessCreationMonitor.hpp"

// ---------------------------------------------------------------------------
// AntiEvasion
// ---------------------------------------------------------------------------
#include "src/PhantomCore/AntiEvasion/DebuggerEvasionDetector.hpp"
#include "src/PhantomCore/AntiEvasion/VMEvasionDetector.hpp"
#include "src/PhantomCore/AntiEvasion/SandboxEvasionDetector.hpp"
#include "src/PhantomCore/AntiEvasion/ProcessEvasionDetector.hpp"
#include "src/PhantomCore/AntiEvasion/metamorphic_polymorphicdetector.hpp"
#include "src/PhantomCore/AntiEvasion/TimeBasedEvasionDetector.hpp"
#include "src/PhantomCore/AntiEvasion/NetworkBasedEvasionDetector.hpp"
#include "src/PhantomCore/AntiEvasion/EnvironmentEvasionDetector.hpp"
#include "src/PhantomCore/AntiEvasion/PackerDetector.hpp"

// ---------------------------------------------------------------------------
// AI
// ---------------------------------------------------------------------------
#include "src/PhantomCore/AI/PhantomCortex.hpp"
#include "src/PhantomCore/AI/CortexConfig.hpp"

// ---------------------------------------------------------------------------
// Communication
// ---------------------------------------------------------------------------
#include "src/PhantomCore/Communication/IPCManager.hpp"
#include "src/PhantomCore/Communication/TelemetryCollector.hpp"
#include "src/PhantomCore/Communication/AlertSystem.hpp"

// ---------------------------------------------------------------------------
// Core :: Engine
// ---------------------------------------------------------------------------
#include "src/PhantomCore/Core/Engine/ScanEngine.hpp"
#include "src/PhantomCore/Core/Engine/BehaviorAnalyzer.hpp"
#include "src/PhantomCore/Core/Engine/ThreatDetector.hpp"
#include "src/PhantomCore/Core/Engine/QuarantineManager.hpp"

// ---------------------------------------------------------------------------
// Core :: FileSystem
// ---------------------------------------------------------------------------
#include "src/PhantomCore/Core/FileSystem/ExecutableAnalyzer.hpp"

// ---------------------------------------------------------------------------
// Core :: Network
// ---------------------------------------------------------------------------
#include "src/PhantomCore/Core/Network/NetworkMonitor.hpp"
#include "src/PhantomCore/Core/Network/TrafficAnalyzer.hpp"
#include "src/PhantomCore/Core/Network/DNSMonitor.hpp"
#include "src/PhantomCore/Core/Network/URLAnalyzer.hpp"
#include "src/PhantomCore/Core/Network/BotnetDetector.hpp"
#include "src/PhantomCore/Core/Network/WebProtection.hpp"
#include "src/PhantomCore/Core/Network/TorDetector.hpp"
#include "src/PhantomCore/Core/Network/VPNDetector.hpp"
#include "src/PhantomCore/Core/Network/P2PMonitor.hpp"

// ---------------------------------------------------------------------------
// Core :: Process
// ---------------------------------------------------------------------------
#include "src/PhantomCore/Core/Process/ProcessInjectionDetector.hpp"
#include "src/PhantomCore/Core/Process/ProcessMonitor.hpp"
#include "src/PhantomCore/Core/Process/AtomBombingDetector.hpp"
#include "src/PhantomCore/Core/Process/DLLInjectionDetector.hpp"

// ---------------------------------------------------------------------------
// Exploits
// ---------------------------------------------------------------------------
#include "src/PhantomCore/Exploits/HeapSprayDetector.hpp"
#include "src/PhantomCore/Exploits/JITSprayDetector.hpp"
#include "src/PhantomCore/Exploits/BufferOverflowProtection.hpp"
#include "src/PhantomCore/Exploits/StackPivotDetector.hpp"
#include "src/PhantomCore/Exploits/KernelExploitDetector.hpp"
#include "src/PhantomCore/Exploits/PrivilegeEscalationDetector.hpp"

// ---------------------------------------------------------------------------
// SelfProtection  (namespace ShadowStrike::Security)
// ---------------------------------------------------------------------------
#include "src/PhantomCore/SelfProtection/DigitalSignatureValidator.hpp"
#include "src/PhantomCore/SelfProtection/ProcessProtection.hpp"
#include "src/PhantomCore/SelfProtection/TamperProtection.hpp"
#include "src/PhantomCore/SelfProtection/SelfDefense.hpp"
#include "src/PhantomCore/SelfProtection/AntiDebug.hpp"
#include "src/PhantomCore/SelfProtection/CertificateValidator.hpp"

// ---------------------------------------------------------------------------
// Placement-storage Meyers'-safe singleton helpers.
//   INST_NE  — Instance() declared noexcept in the header
//   INST     — Instance() declared without noexcept in the header
// ---------------------------------------------------------------------------
#define INST_NE(T)                                                      \
    T& T::Instance() noexcept {                                         \
        alignas(T) static unsigned char storage[sizeof(T)]{};          \
        return *std::launder(reinterpret_cast<T*>(storage));            \
    }

#define INST(T)                                                         \
    T& T::Instance() {                                                  \
        alignas(T) static unsigned char storage[sizeof(T)]{};          \
        return *std::launder(reinterpret_cast<T*>(storage));            \
    }

namespace ShadowStrike {

// =============================================================================
// ThreatIntel :: ThreatIntelStore
// =============================================================================
namespace ThreatIntel {

// PIMPL definition - required so unique_ptr<Impl> destructor can compile.
class ThreatIntelStore::Impl {};

ThreatIntelStore::ThreatIntelStore()  = default;
ThreatIntelStore::~ThreatIntelStore() = default;

StoreStatistics    ThreatIntelStore::GetStatistics() const noexcept { return {}; }
ThreatIntelLookup* ThreatIntelStore::GetLookup()     noexcept       { return nullptr; }

} // namespace ThreatIntel

// =============================================================================
// HashStore :: HashStore
// =============================================================================
namespace HashStore {

HashStore::HashStore()  = default;
HashStore::~HashStore() = default;

} // namespace HashStore

// =============================================================================
// PatternStore :: PatternStore
// =============================================================================
namespace PatternStore {

PatternStore::PatternStore()  = default;
PatternStore::~PatternStore() = default;

} // namespace PatternStore

// =============================================================================
// SignatureStore :: SignatureStore
// =============================================================================
namespace SignatureStore {

SignatureStore::SignatureStore()  = default;
SignatureStore::~SignatureStore() = default;

} // namespace SignatureStore

// =============================================================================
// Nested store-type destructors
// Required because default ctors/dtors for HashStore, PatternStore, and
// SignatureStore trigger scalar-deleting destructor instantiation for their
// member types (HashBucket, AhoCorasickAutomaton, PatternIndex, YaraRuleStore),
// which have out-of-line dtors declared in their respective headers.
// =============================================================================
namespace SignatureStore {
    PatternIndex::~PatternIndex()   {}
    SignatureIndex::~SignatureIndex() {}
    YaraRuleStore::~YaraRuleStore() {}
} // namespace SignatureStore

namespace HashStore {
    HashBucket::~HashBucket() {}
} // namespace HashStore

namespace PatternStore {
    AhoCorasickAutomaton::~AhoCorasickAutomaton() {}
} // namespace PatternStore

// =============================================================================
// Utils :: ProcessUtils — free functions
// =============================================================================
namespace Utils::ProcessUtils {

std::optional<std::wstring> GetProcessPath(ProcessId /*pid*/,
                                           Error* /*err*/) noexcept {
    return std::nullopt;
}

bool TerminateProcess(ProcessId /*pid*/, DWORD /*exitCode*/,
                      Error* /*err*/) noexcept {
    return false;
}

} // namespace Utils::ProcessUtils

// =============================================================================
// RealTime subsystems
// =============================================================================
namespace RealTime {

// PIMPL definitions for all PIMPL-using RealTime classes.
struct FileSystemFilter::Impl {};
struct NetworkTrafficFilter::Impl {};
struct ExploitPrevention::Impl {};
struct FileIntegrityMonitor::Impl {};
struct ProcessCreationMonitor::Impl {};

// --- FileSystemFilter --------------------------------------------------------
INST(FileSystemFilter)  // no noexcept on Instance()

bool FileSystemFilter::Initialize()                                   { return false; }
bool FileSystemFilter::Initialize(
        std::shared_ptr<Utils::ThreadPool> /*pool*/)                  { return false; }
bool FileSystemFilter::Initialize(
        std::shared_ptr<Utils::ThreadPool> /*pool*/,
        const FileSystemFilterConfig& /*cfg*/)                        { return false; }
void FileSystemFilter::Shutdown()          {}
bool FileSystemFilter::Start()             { return false; }
void FileSystemFilter::Pause()             {}
void FileSystemFilter::Resume()            {}
void FileSystemFilter::SetScanOnOpen(bool /*v*/)    {}
void FileSystemFilter::SetScanOnExecute(bool /*v*/) {}
void FileSystemFilter::SetScanOnWrite(bool /*v*/)   {}
void FileSystemFilter::SetScanEngine(Core::Engine::ScanEngine* /*e*/) {}
void FileSystemFilter::SetHashStore(HashStore::HashStore* /*h*/)      {}

// --- NetworkTrafficFilter ----------------------------------------------------
INST(NetworkTrafficFilter)  // no noexcept on Instance()

bool     NetworkTrafficFilter::Initialize()                                   { return false; }
bool     NetworkTrafficFilter::Initialize(
             std::shared_ptr<Utils::ThreadPool> /*pool*/)                     { return false; }
bool     NetworkTrafficFilter::Initialize(
             std::shared_ptr<Utils::ThreadPool> /*pool*/,
             const NetworkFilterConfig& /*cfg*/)                              { return false; }
void     NetworkTrafficFilter::Shutdown()                 {}
void     NetworkTrafficFilter::Start()                    {}
void     NetworkTrafficFilter::Stop()                     {}
bool     NetworkTrafficFilter::IsRunning() const noexcept { return false; }
void     NetworkTrafficFilter::BlockIP(const std::string& /*ip*/) {}
bool     NetworkTrafficFilter::LoadBlockListFromFile(
             const std::wstring& /*path*/) { return false; }
uint64_t NetworkTrafficFilter::RegisterEventCallback(
             NetworkEventCallback /*cb*/) { return 0; }

// --- AccessControlManager ----------------------------------------------------
INST(AccessControlManager)  // no noexcept on Instance()

bool AccessControlManager::Initialize(
        const AccessControlManagerConfig& /*cfg*/) { return false; }
void AccessControlManager::Shutdown() noexcept {}

AccessControlManagerConfig
AccessControlManagerConfig::CreateEnterprise() noexcept { return {}; }

// --- BehaviorBlocker ---------------------------------------------------------
INST_NE(BehaviorBlocker)  // noexcept on Instance()

bool BehaviorBlocker::Initialize(const BehaviorBlockerConfig& /*cfg*/) {
    return false;
}
bool BehaviorBlocker::Start()  { return false; }
void BehaviorBlocker::Stop()   {}
void BehaviorBlocker::Pause()  {}
void BehaviorBlocker::Resume() {}
void BehaviorBlocker::Shutdown() {}
bool BehaviorBlocker::IsRunning() const noexcept { return false; }
void BehaviorBlocker::OnKernelBehavioralAlert(
        uint32_t /*pid*/, std::span<const std::byte> /*data*/) {}
bool BehaviorBlocker::LoadDefaultRules()  { return false; }
bool BehaviorBlocker::PushRulesToKernel() { return false; }
BehaviorBlockerStats BehaviorBlocker::GetStatistics() const noexcept { return {}; }

BehaviorBlockerConfig BehaviorBlockerConfig::CreateDefault() { return {}; }

// --- ExploitPrevention -------------------------------------------------------
INST_NE(ExploitPrevention)  // noexcept on Instance()

bool ExploitPrevention::Initialize()                                { return false; }
bool ExploitPrevention::Initialize(
        std::shared_ptr<Utils::ThreadPool> /*pool*/)                { return false; }
bool ExploitPrevention::Initialize(
        std::shared_ptr<Utils::ThreadPool> /*pool*/,
        const ExploitPreventionConfig& /*cfg*/)                     { return false; }
void ExploitPrevention::Shutdown() noexcept {}
bool ExploitPrevention::Start()             { return false; }
bool ExploitPrevention::IsRunning() const noexcept { return false; }
void ExploitPrevention::OnKernelMemoryAlert(
        uint32_t /*msgType*/, std::span<const std::byte> /*data*/) {}
bool ExploitPrevention::PushMitigationsToKernel() { return false; }

// --- FileIntegrityMonitor ----------------------------------------------------
INST_NE(FileIntegrityMonitor)  // noexcept on Instance()

bool   FileIntegrityMonitor::Initialize()                                { return false; }
bool   FileIntegrityMonitor::Initialize(
           std::shared_ptr<Utils::ThreadPool> /*pool*/)                  { return false; }
bool   FileIntegrityMonitor::Initialize(
           std::shared_ptr<Utils::ThreadPool> /*pool*/,
           const FIMConfig& /*cfg*/)                                     { return false; }
void   FileIntegrityMonitor::Shutdown() noexcept {}
void   FileIntegrityMonitor::StartMonitoring()   {}
void   FileIntegrityMonitor::StopMonitoring()    {}
size_t FileIntegrityMonitor::CreateSystemBaselines() { return 0; }
FIMStats FileIntegrityMonitor::GetStats() const      { return {}; }

// --- MemoryProtection --------------------------------------------------------
INST_NE(MemoryProtection)  // noexcept on Instance()

void MemoryProtection::Start()  {}
void MemoryProtection::Stop()   {}
bool MemoryProtection::IsRunning() const noexcept { return false; }
void MemoryProtection::Configure(const MemoryProtectionConfig& /*cfg*/) {}
bool MemoryProtection::MonitorProcess(unsigned long /*pid*/) { return false; }
void MemoryProtection::ProcessKernelMemoryAlert(
        unsigned int /*msgType*/, const void* /*data*/,
        unsigned __int64 /*size*/) {}

// --- ZeroHourProtection ------------------------------------------------------
INST(ZeroHourProtection)  // no noexcept on Instance()

bool ZeroHourProtection::Start() noexcept { return false; }
void ZeroHourProtection::Stop()  noexcept {}

uint64_t ZeroHourProtection::RegisterVerdictCallback(
        std::function<void(const std::wstring&,
                           const FileAnalysisResult&)> /*cb*/) {
    return 0;
}
uint64_t ZeroHourProtection::RegisterOutbreakCallback(
        std::function<void(const OutbreakInfo&, bool)> /*cb*/) {
    return 0;
}
uint64_t ZeroHourProtection::RegisterSignatureUpdateCallback(
        std::function<void(const MicroSigUpdatePackage&, bool)> /*cb*/) {
    return 0;
}

// --- ProcessCreationMonitor --------------------------------------------------
INST(ProcessCreationMonitor)  // no noexcept on Instance()

bool ProcessCreationMonitor::Initialize()                                { return false; }
bool ProcessCreationMonitor::Initialize(
        std::shared_ptr<Utils::ThreadPool> /*pool*/)                     { return false; }
bool ProcessCreationMonitor::Initialize(
        std::shared_ptr<Utils::ThreadPool> /*pool*/,
        const ProcessMonitorConfig& /*cfg*/)                             { return false; }
void ProcessCreationMonitor::Start()   {}
void ProcessCreationMonitor::Stop()    {}
void ProcessCreationMonitor::Pause()   {}
void ProcessCreationMonitor::Resume()  {}
void ProcessCreationMonitor::SetScanEngine(
        Core::Engine::ScanEngine* /*e*/) {}
void ProcessCreationMonitor::SetBehaviorAnalyzer(
        Core::Engine::BehaviorAnalyzer* /*a*/) {}
void ProcessCreationMonitor::SetHashStore(
        HashStore::HashStore* /*h*/) {}

} // namespace RealTime

// =============================================================================
// Core :: Network
// =============================================================================
namespace Core::Network {

// --- NetworkMonitor ----------------------------------------------------------
NetworkMonitorConfig NetworkMonitorConfig::CreateDefault() noexcept { return {}; }

INST_NE(NetworkMonitor)  // noexcept on Instance()

bool NetworkMonitor::Initialize(const NetworkMonitorConfig& /*cfg*/) {
    return false;
}
bool NetworkMonitor::Start()          { return false; }
void NetworkMonitor::Stop()           {}
void NetworkMonitor::Shutdown() noexcept {}

// --- TrafficAnalyzer ---------------------------------------------------------
TrafficAnalyzerConfig TrafficAnalyzerConfig::CreateDefault() noexcept { return {}; }

INST(TrafficAnalyzer)  // no noexcept on Instance()

bool TrafficAnalyzer::Initialize(const TrafficAnalyzerConfig& /*cfg*/) {
    return false;
}
bool TrafficAnalyzer::Start()               { return false; }
void TrafficAnalyzer::Stop()                {}
void TrafficAnalyzer::Shutdown() noexcept   {}
bool TrafficAnalyzer::IsRunning() const noexcept { return false; }

void TrafficAnalyzer::AnalyzePacket(
        const std::vector<uint8_t>& /*pkt*/) {}

AnalysisResult TrafficAnalyzer::AnalyzePacket(
        std::span<const uint8_t> /*pkt*/,
        std::chrono::system_clock::time_point /*ts*/) {
    return {};
}

void TrafficAnalyzer::SetThreatIntelLookup(
        ThreatIntel::ThreatIntelLookup* /*lookup*/) noexcept {}
void TrafficAnalyzer::SetSignatureStore(
        SignatureStore::SignatureStore* /*ss*/) noexcept {}

// --- DNSMonitor --------------------------------------------------------------
DNSMonitorConfig DNSMonitorConfig::CreateDefault() noexcept { return {}; }

INST_NE(DNSMonitor)  // noexcept on Instance()

bool DNSMonitor::Initialize(const DNSMonitorConfig& /*cfg*/) { return false; }
void DNSMonitor::Start()                {}     // void, not bool
void DNSMonitor::Stop()                 {}
void DNSMonitor::Shutdown() noexcept    {}
bool DNSMonitor::IsRunning() const noexcept { return false; }
DGAAnalysis DNSMonitor::AnalyzeDGA(const std::string& /*domain*/) const {
    return {};
}

// --- URLAnalyzer -------------------------------------------------------------
URLAnalyzerConfig URLAnalyzerConfig::CreateDefault() noexcept { return {}; }

INST(URLAnalyzer)  // no noexcept on Instance()

bool URLAnalyzer::Initialize(const URLAnalyzerConfig& /*cfg*/) { return false; }
void URLAnalyzer::Shutdown() noexcept {}
void URLAnalyzer::SetThreatIntelLookup(
        ThreatIntel::ThreatIntelLookup* /*lookup*/) noexcept {}
void URLAnalyzer::SetPatternStore(
        PatternStore::PatternStore* /*ps*/) noexcept {}
DomainVerdict URLAnalyzer::AnalyzeDomain(const std::string& /*domain*/) {
    return {};
}

// --- BotnetDetector ----------------------------------------------------------
BotnetDetectorConfig BotnetDetectorConfig::CreateDefault() noexcept { return {}; }

INST(BotnetDetector)  // no noexcept on Instance()

bool BotnetDetector::Initialize(const BotnetDetectorConfig& /*cfg*/) {
    return false;
}
bool BotnetDetector::Start()             { return false; }
void BotnetDetector::Stop()              {}
void BotnetDetector::Shutdown() noexcept {}
bool BotnetDetector::IsRunning() const noexcept { return false; }
void BotnetDetector::RecordConnectionEvent(
        uint32_t /*pid*/, const std::string& /*remoteIp*/,
        uint16_t /*remotePort*/, uint64_t /*bytesSent*/,
        uint64_t /*bytesRecv*/) {}
void BotnetDetector::SetThreatIntelStore(
        ThreatIntel::ThreatIntelStore* /*store*/) noexcept {}

// --- WebProtection -----------------------------------------------------------
WebProtectionConfig WebProtectionConfig::CreateDefault() noexcept { return {}; }

INST(WebProtection)  // no noexcept on Instance()

bool WebProtection::Initialize(const WebProtectionConfig& /*cfg*/) {
    return false;
}
bool WebProtection::Start()             { return false; }
void WebProtection::Stop()              {}
void WebProtection::Shutdown() noexcept {}
void WebProtection::SetThreatIntelStore(
        ThreatIntel::ThreatIntelStore* /*store*/) noexcept {}

// --- TorDetector -------------------------------------------------------------
TorDetectorConfig TorDetectorConfig::CreateDefault() noexcept { return {}; }

INST(TorDetector)  // no noexcept on Instance()

bool TorDetector::Initialize(const TorDetectorConfig& /*cfg*/) { return false; }
bool TorDetector::Start()               { return false; }
void TorDetector::Stop()                {}
void TorDetector::Shutdown() noexcept   {}
bool TorDetector::IsRunning() const noexcept { return false; }
void TorDetector::FeedPacket(uint64_t /*srcIp*/, uint64_t /*dstIp*/) {}
void TorDetector::SetThreatIntelStore(
        ThreatIntel::ThreatIntelStore* /*store*/) noexcept {}

// --- VPNDetector -------------------------------------------------------------
VPNDetectorConfig VPNDetectorConfig::CreateDefault() noexcept { return {}; }

INST(VPNDetector)  // no noexcept on Instance()

bool VPNDetector::Initialize(const VPNDetectorConfig& /*cfg*/) { return false; }
bool VPNDetector::Start()               { return false; }
void VPNDetector::Stop()                {}
void VPNDetector::Shutdown() noexcept   {}

// --- P2PMonitor --------------------------------------------------------------
P2PMonitorConfig P2PMonitorConfig::CreateDefault() noexcept { return {}; }

INST(P2PMonitor)  // no noexcept on Instance()

bool P2PMonitor::Initialize(const P2PMonitorConfig& /*cfg*/) { return false; }
bool P2PMonitor::Start()                { return false; }
void P2PMonitor::Stop()                 {}
void P2PMonitor::Shutdown() noexcept    {}
void P2PMonitor::SetThreatIntelStore(
        ThreatIntel::ThreatIntelStore* /*store*/) noexcept {}

} // namespace Core::Network

// =============================================================================
// Core :: Engine
// =============================================================================
namespace Core::Engine {

// PIMPL definitions.
class  ScanEngine::Impl {};
struct BehaviorAnalyzer::Impl {};
struct ThreatDetector::Impl {};
class  QuarantineManager::Impl {};

// --- ScanEngine --------------------------------------------------------------
INST(ScanEngine)  // no noexcept on Instance()

bool         ScanEngine::Initialize(const EngineConfig& /*cfg*/) { return false; }
void         ScanEngine::Shutdown() {}
EngineResult ScanEngine::ScanFile(const std::wstring& /*path*/,
                                   const ScanContext& /*ctx*/) { return {}; }

// --- BehaviorAnalyzer --------------------------------------------------------
INST(BehaviorAnalyzer)  // no noexcept on Instance()

bool BehaviorAnalyzer::Initialize(
        std::shared_ptr<Utils::ThreadPool> /*pool*/) { return false; }
void BehaviorAnalyzer::Shutdown() {}
bool BehaviorAnalyzer::IsInitialized() const noexcept { return false; }

// --- ThreatDetector ----------------------------------------------------------
INST(ThreatDetector)  // no noexcept on Instance()

void ThreatDetector::SetBehaviorAnalyzer(BehaviorAnalyzer* /*a*/) {}

// --- QuarantineManager -------------------------------------------------------
INST(QuarantineManager)  // no noexcept on Instance()

bool             QuarantineManager::Initialize() { return false; }
QuarantineResult QuarantineManager::QuarantineFile(
        const QuarantineRequest& /*req*/) { return {}; }
QuarantineResult QuarantineManager::QuarantineFile(
        const std::wstring& /*filePath*/,
        const std::wstring& /*threatName*/,
        uint32_t /*relatedPid*/) { return {}; }

} // namespace Core::Engine

// =============================================================================
// Core :: FileSystem :: ExecutableAnalyzer
// =============================================================================
namespace Core::FileSystem {

INST(ExecutableAnalyzer)  // no noexcept on Instance()

ExecutableInfo ExecutableAnalyzer::AnalyzeForKernel(
        const std::wstring& /*filePath*/,
        uint32_t /*processId*/,
        uint64_t /*fileSize*/) {
    return {};
}

} // namespace Core::FileSystem

// =============================================================================
// Core :: Process
// =============================================================================
namespace Core::Process {

// PIMPL definitions.
struct ProcessInjectionDetector::Impl {};
class  ProcessMonitor::Impl {};
class  AtomBombingDetector::Impl {};

// --- ProcessInjectionDetector ------------------------------------------------
INST(ProcessInjectionDetector)  // no noexcept on Instance()

void ProcessInjectionDetector::SetBehaviorAnalyzer(
        Engine::BehaviorAnalyzer* /*a*/) {}

// --- ProcessMonitor ----------------------------------------------------------
INST(ProcessMonitor)  // no noexcept on Instance()

bool ProcessMonitor::IsInitialized() const noexcept { return false; }
void ProcessMonitor::OnModuleLoad(uint32_t /*pid*/,
                                   const std::wstring& /*path*/,
                                   uint64_t /*base*/,
                                   uint64_t /*size*/) {}

// --- AtomBombingDetector -----------------------------------------------------
AtomBombingConfig AtomBombingConfig::CreateDefault() noexcept { return {}; }

INST(AtomBombingDetector)  // no noexcept on Instance()

bool     AtomBombingDetector::Initialize(const AtomBombingConfig& /*cfg*/) {
    return false;
}
void     AtomBombingDetector::Shutdown()        {}
bool     AtomBombingDetector::StartMonitoring() { return false; }
void     AtomBombingDetector::StopMonitoring()  {}
uint64_t AtomBombingDetector::RegisterAttackCallback(
        std::function<void(const AtomBombingAttack&)> /*cb*/) {
    return 0;
}

// --- DLLInjectionDetector ----------------------------------------------------
INST(DLLInjectionDetector)  // no noexcept on Instance()

bool DLLInjectionDetector::IsInitialized() const noexcept { return false; }
bool DLLInjectionDetector::IsMonitoring()  const noexcept { return false; }
void DLLInjectionDetector::OnThreadCreate(uint32_t /*pid*/,
                                           uint32_t /*tid*/,
                                           uint64_t /*startAddr*/) {}

} // namespace Core::Process

// =============================================================================
// Exploits
// =============================================================================
namespace Exploits {

// --- HeapSprayDetector -------------------------------------------------------
INST_NE(HeapSprayDetector)

bool HeapSprayDetector::Initialize(
        const HeapSprayDetectorConfiguration& /*cfg*/) { return false; }
void HeapSprayDetector::Shutdown() {}
bool HeapSprayDetector::Start()    { return false; }

// --- JITSprayDetector --------------------------------------------------------
INST_NE(JITSprayDetector)

bool JITSprayDetector::Initialize(
        const JITSprayDetectorConfiguration& /*cfg*/) { return false; }
void JITSprayDetector::Shutdown() {}
bool JITSprayDetector::Start()    { return false; }

// --- BufferOverflowProtection ------------------------------------------------
INST_NE(BufferOverflowProtection)

bool BufferOverflowProtection::Initialize(
        const BufferOverflowProtectionConfiguration& /*cfg*/) { return false; }
void BufferOverflowProtection::Shutdown() {}
bool BufferOverflowProtection::Start()    { return false; }

// --- StackPivotDetector ------------------------------------------------------
INST_NE(StackPivotDetector)

bool StackPivotDetector::Initialize(
        const StackPivotDetectorConfiguration& /*cfg*/) { return false; }
void StackPivotDetector::Shutdown() {}
bool StackPivotDetector::Start()    { return false; }

// --- KernelExploitDetector ---------------------------------------------------
INST_NE(KernelExploitDetector)

bool KernelExploitDetector::Initialize(
        const KernelExploitDetectorConfiguration& /*cfg*/) { return false; }
void KernelExploitDetector::Shutdown()               {}
bool KernelExploitDetector::IsInitialized() const noexcept { return false; }
bool KernelExploitDetector::Start()                  { return false; }

DriverInfo KernelExploitDetector::ScanDriver(
        const std::filesystem::path& /*path*/) { return {}; }

IOCTLEventInfo KernelExploitDetector::AnalyzeIOCTL(
        uint32_t /*ioctl*/,
        const std::wstring& /*driverName*/,
        uint32_t /*pid*/,
        std::span<const uint8_t> /*inputBuf*/) { return {}; }

void KernelExploitDetector::RegisterDriverLoadCallback(
        std::function<void(const DriverInfo&, DetectionAction)> /*cb*/) {}
void KernelExploitDetector::RegisterKernelExploitCallback(
        std::function<void(const KernelExploitEvent&)> /*cb*/) {}
void KernelExploitDetector::RegisterErrorCallback(
        std::function<void(const std::string&, int)> /*cb*/) {}

// --- PrivilegeEscalationDetector ---------------------------------------------
INST_NE(PrivilegeEscalationDetector)

bool PrivilegeEscalationDetector::Initialize(
        const PrivilegeEscalationDetectorConfiguration& /*cfg*/) { return false; }
void PrivilegeEscalationDetector::Shutdown() {}
bool PrivilegeEscalationDetector::Start()    { return false; }

void PrivilegeEscalationDetector::OnKernelProcessCreated(
        uint32_t /*pid*/, uint32_t /*parentPid*/,
        const std::wstring& /*imagePath*/,
        const std::wstring& /*cmdLine*/,
        bool /*isElevated*/) {}

void PrivilegeEscalationDetector::OnKernelRegistryModified(
        uint32_t /*pid*/,
        const std::wstring& /*keyPath*/,
        const std::wstring& /*valueName*/,
        const std::vector<uint8_t>& /*data*/) {}

void PrivilegeEscalationDetector::RegisterLpeCallback(
        std::function<void(const LpeEvent&)> /*cb*/) {}
void PrivilegeEscalationDetector::RegisterErrorCallback(
        std::function<void(const std::string&, int)> /*cb*/) {}

// --- Namespace-level free functions ------------------------------------------
std::string_view GetKernelThreatTypeName(KernelThreatType /*type*/) noexcept {
    return "Unknown";
}

std::string_view GetLpeTechniqueName(LpeTechnique /*technique*/) noexcept {
    return "Unknown";
}

} // namespace Exploits

// =============================================================================
// AntiEvasion
// =============================================================================
namespace AntiEvasion {

// Minimal PIMPL bodies — required because ctors/dtors with unique_ptr<Impl>
// members are defined in this TU and need the complete Impl type.
// Declared as `class Impl;` in headers, so use `class` to avoid C4099 warning.
class DebuggerEvasionDetector::Impl {};
class ProcessEvasionDetector::Impl {};
class MetamorphicDetector::Impl {};
class NetworkBasedEvasionDetector::Impl {};
class EnvironmentEvasionDetector::Impl {};
class PackerDetector::Impl {};
struct VMEvasionDetector::Impl {};   // header declares `struct Impl;"
struct SandboxEvasionDetector::Impl {};
struct TimeBasedEvasionDetector::Impl {};

// --- DebuggerEvasionDetector -------------------------------------------------
// Default ctor is noexcept in header
DebuggerEvasionDetector::DebuggerEvasionDetector() noexcept = default;
DebuggerEvasionDetector::~DebuggerEvasionDetector()         = default;

bool DebuggerEvasionDetector::Initialize(
        Error* /*err*/) noexcept { return false; }
void DebuggerEvasionDetector::Shutdown() noexcept {}

DebuggerEvasionResult DebuggerEvasionDetector::AnalyzeProcess(
        uint32_t /*pid*/,
        const AnalysisConfig& /*cfg*/,
        Error* /*err*/) noexcept {
    return {};
}
void DebuggerEvasionDetector::SetDetectionCallback(
        DetectionCallback /*cb*/) noexcept {}
void DebuggerEvasionDetector::SetSignatureStore(
        std::shared_ptr<SignatureStore::SignatureStore> /*ss*/) noexcept {}
void DebuggerEvasionDetector::SetThreatIntelStore(
        std::shared_ptr<ThreatIntel::ThreatIntelStore> /*ti*/) noexcept {}

// --- VMEvasionDetector -------------------------------------------------------
VMEvasionDetector::VMEvasionDetector(
        std::shared_ptr<ThreatIntel::ThreatIntelStore> /*ti*/,
        const VMDetectionConfig& /*cfg*/) {}
VMEvasionDetector::~VMEvasionDetector() = default;

bool VMEvasionDetector::AnalyzeProcessAntiVMBehavior(
        unsigned long /*pid*/, ProcessVMEvasionResult& /*result*/,
        const ProcessAnalysisConfig& /*cfg*/) {
    return false;
}

// --- SandboxEvasionDetector --------------------------------------------------
INST(SandboxEvasionDetector)  // no noexcept on Instance()

bool SandboxEvasionDetector::Initialize(
        std::shared_ptr<Utils::ThreadPool> /*pool*/) { return false; }
void SandboxEvasionDetector::Shutdown() {}

HardwareProfile     SandboxEvasionDetector::AnalyzeHardware()    { return {}; }
EnvironmentAnalysis SandboxEvasionDetector::AnalyzeEnvironment() { return {}; }
uint64_t SandboxEvasionDetector::RegisterCallback(
        std::function<void(const SandboxEvasionResult&)> /*cb*/) {
    return 0;
}

// --- ProcessEvasionDetector --------------------------------------------------
// Default ctor is noexcept in header
ProcessEvasionDetector::ProcessEvasionDetector() noexcept = default;
ProcessEvasionDetector::~ProcessEvasionDetector()         = default;

bool ProcessEvasionDetector::Initialize(
        ProcessEvasionError* /*err*/) noexcept { return false; }
void ProcessEvasionDetector::Shutdown() noexcept {}

ProcessEvasionResult ProcessEvasionDetector::AnalyzeProcess(
        uint32_t /*pid*/,
        const ProcessEvasionAnalysisConfig& /*cfg*/,
        ProcessEvasionError* /*err*/) noexcept {
    return {};
}
void ProcessEvasionDetector::SetDetectionCallback(
        ProcessDetectionCallback /*cb*/) noexcept {}

// --- MetamorphicDetector -----------------------------------------------------
// Default ctor is noexcept in header
MetamorphicDetector::MetamorphicDetector() noexcept = default;
MetamorphicDetector::~MetamorphicDetector()         = default;

bool MetamorphicDetector::Initialize(
        MetamorphicError* /*err*/) noexcept { return false; }
void MetamorphicDetector::Shutdown() noexcept {}

MetamorphicResult MetamorphicDetector::AnalyzeFile(
        const std::wstring& /*path*/,
        const MetamorphicAnalysisConfig& /*cfg*/,
        MetamorphicError* /*err*/) noexcept {
    return {};
}
void MetamorphicDetector::SetDetectionCallback(
        MetamorphicDetectionCallback /*cb*/) noexcept {}
void MetamorphicDetector::SetSignatureStore(
        std::shared_ptr<SignatureStore::SignatureStore> /*ss*/) noexcept {}
void MetamorphicDetector::SetHashStore(
        std::shared_ptr<HashStore::HashStore> /*hs*/) noexcept {}
void MetamorphicDetector::SetPatternStore(
        std::shared_ptr<PatternStore::PatternStore> /*ps*/) noexcept {}

// --- TimeBasedEvasionDetector ------------------------------------------------
INST(TimeBasedEvasionDetector)  // no noexcept on Instance()

bool TimeBasedEvasionDetector::Initialize(
        std::shared_ptr<Utils::ThreadPool> /*pool*/) { return false; }
void TimeBasedEvasionDetector::Shutdown() {}

TimingEvasionResult TimeBasedEvasionDetector::AnalyzeProcess(
        uint32_t /*pid*/) { return {}; }
uint64_t TimeBasedEvasionDetector::RegisterCallback(
        std::function<void(const TimingEvasionResult&)> /*cb*/) {
    return 0;
}

// --- NetworkBasedEvasionDetector ---------------------------------------------
// Default ctor is noexcept in header
NetworkBasedEvasionDetector::NetworkBasedEvasionDetector() noexcept = default;
NetworkBasedEvasionDetector::~NetworkBasedEvasionDetector()         = default;

bool NetworkBasedEvasionDetector::Initialize(
        NetworkEvasionError* /*err*/) noexcept { return false; }
void NetworkBasedEvasionDetector::Shutdown() noexcept {}

NetworkEvasionResult NetworkBasedEvasionDetector::AnalyzeProcess(
        uint32_t /*pid*/,
        const NetworkAnalysisConfig& /*cfg*/,
        NetworkEvasionError* /*err*/) noexcept {
    return {};
}
void NetworkBasedEvasionDetector::SetDetectionCallback(
        NetworkDetectionCallback /*cb*/) noexcept {}
void NetworkBasedEvasionDetector::SetThreatIntelStore(
        std::shared_ptr<ThreatIntel::ThreatIntelStore> /*ti*/) noexcept {}

// --- EnvironmentEvasionDetector ----------------------------------------------
// Default ctor is noexcept in header
EnvironmentEvasionDetector::EnvironmentEvasionDetector() noexcept = default;
EnvironmentEvasionDetector::~EnvironmentEvasionDetector()         = default;

bool EnvironmentEvasionDetector::Initialize(
        EnvironmentError* /*err*/) noexcept { return false; }
void EnvironmentEvasionDetector::Shutdown() noexcept {}

EnvironmentEvasionResult EnvironmentEvasionDetector::AnalyzeProcess(
        uint32_t /*pid*/,
        const EnvironmentAnalysisConfig& /*cfg*/,
        EnvironmentError* /*err*/) noexcept {
    return {};
}
void EnvironmentEvasionDetector::SetDetectionCallback(
        EnvironmentDetectionCallback /*cb*/) noexcept {}
void EnvironmentEvasionDetector::SetThreatIntelStore(
        std::shared_ptr<ThreatIntel::ThreatIntelStore> /*ti*/) noexcept {}

// --- PackerDetector ----------------------------------------------------------
// Default ctor is noexcept in header
PackerDetector::PackerDetector() noexcept = default;
PackerDetector::~PackerDetector()         = default;

bool PackerDetector::Initialize(PackerError* /*err*/) noexcept { return false; }
void PackerDetector::Shutdown() noexcept {}

PackingInfo PackerDetector::AnalyzeFile(
        const std::wstring& /*path*/,
        const PackerAnalysisConfig& /*cfg*/,
        PackerError* /*err*/) noexcept {
    return {};
}
void PackerDetector::SetDetectionCallback(
        PackerDetectionCallback /*cb*/) noexcept {}
void PackerDetector::SetSignatureStore(
        std::shared_ptr<SignatureStore::SignatureStore> /*ss*/) noexcept {}
void PackerDetector::SetPatternStore(
        std::shared_ptr<PatternStore::PatternStore> /*ps*/) noexcept {}
void PackerDetector::SetHashStore(
        std::shared_ptr<HashStore::HashStore> /*hs*/) noexcept {}

} // namespace AntiEvasion

// =============================================================================
// AI
// =============================================================================
namespace AI {

// PIMPL definitions.
struct PhantomCortex::Impl {};
struct CortexConfigManager::Impl {};

// --- PhantomCortex -----------------------------------------------------------
INST_NE(PhantomCortex)  // noexcept on Instance()

bool PhantomCortex::Initialize(const CortexConfig& /*cfg*/) noexcept { return false; }
void PhantomCortex::Shutdown()                              noexcept {}
bool PhantomCortex::IsOperational() const noexcept          { return false; }

CortexVerdict PhantomCortex::AnalyzeFile(
        std::span<const uint8_t> /*data*/) noexcept { return {}; }

// --- CortexConfigManager -----------------------------------------------------
INST_NE(CortexConfigManager)  // noexcept on Instance()

bool         CortexConfigManager::LoadFromRegistry() noexcept { return false; }
CortexConfig CortexConfigManager::GetConfig() const  noexcept { return {}; }

} // namespace AI

// =============================================================================
// Communication
// =============================================================================
namespace Communication {

// --- IPCManager --------------------------------------------------------------
INST_NE(IPCManager)  // noexcept on Instance()

bool IPCManager::HasInstance() noexcept { return false; }
bool IPCManager::Initialize(const IPCConfiguration& /*cfg*/) { return false; }
bool IPCManager::Start(uint32_t /*workerThreads*/)            { return false; }
void IPCManager::Stop()                                       {}
bool IPCManager::ConnectFilterPort()                          { return false; }
void IPCManager::DisconnectFilterPort()                       {}

void IPCManager::RegisterFileScanHandler(
        std::function<_SHADOWSTRIKE_SCAN_VERDICT(
            const _FILE_SCAN_REQUEST&)> /*h*/) {}
void IPCManager::RegisterProcessHandler(
        std::function<_SHADOWSTRIKE_SCAN_VERDICT(
            const ProcessNotifyRequest&)> /*h*/) {}
void IPCManager::RegisterImageLoadHandler(
        std::function<_SHADOWSTRIKE_SCAN_VERDICT(
            const ImageLoadRequest&)> /*h*/) {}
void IPCManager::RegisterRegistryHandler(
        std::function<_SHADOWSTRIKE_SCAN_VERDICT(
            const RegistryOpRequest&)> /*h*/) {}
void IPCManager::RegisterGenericHandler(
        std::function<void(_SHADOWSTRIKE_MESSAGE_TYPE,
                           const void*, uint64_t)> /*h*/) {}

ThreatIntelPusher* IPCManager::GetPusher() noexcept { return nullptr; }

// --- TelemetryCollector ------------------------------------------------------
INST_NE(TelemetryCollector)  // noexcept on Instance()

bool TelemetryCollector::HasInstance() noexcept { return false; }
void TelemetryCollector::RecordDetection(
        const DetectionEventData& /*data*/) {}

// --- AlertSystem -------------------------------------------------------------
INST_NE(AlertSystem)  // noexcept on Instance()

bool AlertSystem::HasInstance() noexcept { return false; }

std::string AlertSystem::RaiseAlert(
        AlertSeverity /*severity*/, AlertType /*type*/,
        const std::string& /*subject*/,
        const std::string& /*details*/,
        const std::string& /*source*/) {
    return {};
}

} // namespace Communication

// =============================================================================
// Security (SelfProtection headers, namespace ShadowStrike::Security)
// =============================================================================
namespace Security {

// --- DigitalSignatureValidator -----------------------------------------------
INST_NE(DigitalSignatureValidator)  // noexcept on Instance()

bool DigitalSignatureValidator::HasInstance() noexcept { return false; }

SignatureAnalysisResult DigitalSignatureValidator::OnKernelImageLoad(
        uint32_t /*pid*/, std::wstring_view /*imagePath*/,
        uint64_t /*imageBase*/, uint64_t /*imageSize*/,
        uint8_t /*signingLevel*/, bool /*isKernelMode*/) {
    return {};
}

SignatureAnalysisResult DigitalSignatureValidator::ValidateProcessImage(
        uint32_t /*pid*/, uint32_t /*parentPid*/,
        std::wstring_view /*imagePath*/) {
    return {};
}

// --- ProcessProtection -------------------------------------------------------
INST_NE(ProcessProtection)  // noexcept on Instance()

bool ProcessProtection::HasInstance() noexcept { return false; }

void ProcessProtection::OnKernelHandleAlert(
        uint32_t /*sourcePid*/, uint32_t /*targetPid*/,
        uint32_t /*handleType*/, uint32_t /*desiredAccess*/,
        uint32_t /*grantedAccess*/, uint32_t /*flags*/) {}

// --- TamperProtection --------------------------------------------------------
INST_NE(TamperProtection)  // noexcept on Instance()

bool TamperProtection::HasInstance()         noexcept { return false; }
bool TamperProtection::IsInitialized() const noexcept { return false; }

bool TamperProtection::Initialize(
        const TamperProtectionConfiguration& /*cfg*/) { return false; }
bool TamperProtection::ProtectInstallation()    { return false; }
bool TamperProtection::ProtectServiceRegistry() { return false; }
bool TamperProtection::ProtectSelf()            { return false; }
void TamperProtection::ForceIntegrityCheck()    {}
bool TamperProtection::RunAPTTamperSweep()      { return false; }

// --- SelfDefense -------------------------------------------------------------
INST_NE(SelfDefense)  // noexcept on Instance()

bool SelfDefense::HasInstance()         noexcept { return false; }
bool SelfDefense::IsInitialized() const noexcept { return false; }

void SelfDefense::OnKernelSelfProtectEvent(
        const void* /*data*/, uint32_t /*size*/) {}

// --- AntiDebug ---------------------------------------------------------------
INST_NE(AntiDebug)  // noexcept on Instance()

bool AntiDebug::HasInstance()         noexcept { return false; }
bool AntiDebug::IsInitialized() const noexcept { return false; }

void AntiDebug::OnKernelProcessNotify(
        uint32_t /*pid*/, uint32_t /*parentPid*/,
        std::wstring_view /*imagePath*/, bool /*isCreate*/) {}
void AntiDebug::OnKernelImageLoad(
        uint32_t /*pid*/, std::wstring_view /*imagePath*/,
        uint64_t /*imageBase*/, uint64_t /*imageSize*/) {}

// --- CertificateValidator ----------------------------------------------------
INST_NE(CertificateValidator)  // noexcept on Instance()

bool CertificateValidator::HasInstance()         noexcept { return false; }
bool CertificateValidator::IsInitialized() const noexcept { return false; }

void CertificateValidator::OnKernelImageLoad(
        std::wstring_view /*imagePath*/,
        uint64_t /*imageBase*/, uint64_t /*imageSize*/,
        uint32_t /*pid*/) {}
void CertificateValidator::OnKernelProcessCreate(
        uint32_t /*pid*/, uint32_t /*parentPid*/,
        std::wstring_view /*imagePath*/) {}

} // namespace Security

} // namespace ShadowStrike

