/*
 * Fuzzer-only dependency seam for behavior-analysis harnessing.
 *
 * The behavior harness intentionally compiles the real BehaviorAnalyzer and
 * BehaviorBlocker implementations. Those modules reference optional enrichment
 * engines and process-control helpers that are outside the scope of this target.
 * To keep the harness deterministic and side-effect free, provide narrow
 * definitions for only the symbols the behavior path links against.
 */

#include "Core/Process/ProcessInjectionDetector.hpp"
#include "Core/Registry/PersistenceDetector.hpp"
#include "RansomwareProtection/RansomwareDetector.hpp"
#include "ThreatIntel/ThreatIntelIndex.hpp"
#include "Utils/ProcessUtils.hpp"
#include "Whitelist/WhiteListStore.hpp"

namespace ShadowStrike::ThreatIntel {

class ThreatIntelIndex::Impl {};

ThreatIntelIndex::ThreatIntelIndex()
    : m_impl(std::make_unique<Impl>()) {}

ThreatIntelIndex::~ThreatIntelIndex() = default;

IndexLookupResult ThreatIntelIndex::LookupDomain(
    std::string_view,
    const IndexQueryOptions&) const noexcept
{
    return IndexLookupResult::NotFound(IOCType::Domain);
}

}  // namespace ShadowStrike::ThreatIntel

namespace ShadowStrike::Utils::ProcessUtils {

// SUBSTITUTED FOR SAFETY, NOT FOR CONVENIENCE.
//
// BehaviorBlocker reaches this when its analysis decides to stop a process, and
// in this target that decision is driven by MUTATED INPUT. Linking the real
// implementation would let a fuzz iteration terminate a real process tree on
// the host machine, chosen by whatever pid the mutator happened to produce.
// A fuzzer must never be able to do that, so this returns false: the blocker
// records "termination failed" and the harness keeps running.
//
// Consequence stated plainly: the real TerminateProcessTree is therefore NOT
// covered by this target. Covering it needs a harness that owns a disposable
// child process of its own, which is a separate piece of work.
bool TerminateProcessTree(ProcessId, DWORD, Error*) noexcept {
    return false;
}

}  // namespace ShadowStrike::Utils::ProcessUtils

namespace ShadowStrike::Whitelist {

HashIndex::~HashIndex() = default;
PathIndex::~PathIndex() = default;
StringPool::~StringPool() = default;

WhitelistStore::WhitelistStore() = default;
WhitelistStore::~WhitelistStore() = default;

LookupResult WhitelistStore::IsPathWhitelisted(
    std::wstring_view,
    const QueryOptions&) const noexcept
{
    return {};
}

}  // namespace ShadowStrike::Whitelist

namespace ShadowStrike::Ransomware {

std::atomic<bool> RansomwareDetector::s_instanceCreated{false};

RansomwareDetector& RansomwareDetector::Instance() noexcept {
    static RansomwareDetector instance;
    return instance;
}

bool RansomwareDetector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

class RansomwareDetectorImpl {};

RansomwareDetector::RansomwareDetector()
    : m_impl(std::make_unique<RansomwareDetectorImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

RansomwareDetector::~RansomwareDetector() = default;

DetectionEvent RansomwareDetector::AnalyzeRenameEx(
    uint32_t,
    std::wstring_view,
    std::wstring_view)
{
    return {};
}

DetectionEvent RansomwareDetector::AnalyzeDeleteEx(
    uint32_t,
    std::wstring_view)
{
    return {};
}

void RansomwareDetector::OnHoneypotTouched(uint32_t, const std::wstring&) {
}

}  // namespace ShadowStrike::Ransomware

namespace ShadowStrike::Core::Process {

struct ProcessInjectionDetector::Impl {};

ProcessInjectionDetector& ProcessInjectionDetector::Instance() {
    static ProcessInjectionDetector instance;
    return instance;
}

ProcessInjectionDetector::ProcessInjectionDetector()
    : m_impl(std::make_unique<Impl>()) {}

ProcessInjectionDetector::~ProcessInjectionDetector() = default;

std::optional<ProcessInjectionState> ProcessInjectionDetector::GetProcessState(uint32_t) const {
    return std::nullopt;
}

}  // namespace ShadowStrike::Core::Process

namespace ShadowStrike::Core::Registry {

class PersistenceDetector::Impl {};

namespace {

[[nodiscard]] bool IsRunKeyPath(const std::wstring& path) {
    return path.find(L"\\CurrentVersion\\Run") != std::wstring::npos ||
           path.find(L"\\CurrentVersion\\RunOnce") != std::wstring::npos;
}

}  // namespace

PersistenceDetector& PersistenceDetector::Instance() {
    static PersistenceDetector instance;
    return instance;
}

PersistenceDetector::PersistenceDetector()
    : m_impl(std::make_unique<Impl>()) {}

PersistenceDetector::~PersistenceDetector() = default;

RealTimeAnalysis PersistenceDetector::AnalyzeRealTimeFull(
    const std::wstring& location,
    const std::wstring& valueName,
    const std::wstring& valueData)
{
    RealTimeAnalysis analysis;
    if (IsRunKeyPath(location)) {
        analysis.risk = PersistenceRiskLevel::Malicious;
        analysis.riskScore = 180;
        analysis.detectedType = PersistenceType::RunKey;
        analysis.resolvedTarget = valueData;
        analysis.isPersistenceAttempt = true;
        analysis.isKnownBad = !valueName.empty();
        analysis.isSuspiciousLocation = true;
        analysis.isSuspiciousTarget = !valueData.empty();
        analysis.indicators.emplace_back("run_key");
        analysis.recommendation = "review_run_key";
    }

    return analysis;
}

PersistenceType PersistenceDetector::IsPersistenceLocation(const std::wstring& location) const {
    return IsRunKeyPath(location) ? PersistenceType::RunKey : PersistenceType::Unknown;
}

}  // namespace ShadowStrike::Core::Registry

namespace ShadowStrike::Utils::ProcessUtils {

bool GetProcessBasicInfo(ProcessId, ProcessBasicInfo&, Error*) noexcept {
    return false;
}

std::optional<std::wstring> GetProcessPath(ProcessId, Error*) noexcept {
    return std::nullopt;
}

bool IsProcessCritical(ProcessId, Error*) noexcept {
    return false;
}

bool TerminateProcess(ProcessId pid, DWORD, Error* err) noexcept {
    const bool allowed = ((pid & 1u) != 0u);
    if (!allowed && err != nullptr) {
        err->win32 = ERROR_ACCESS_DENIED;
        err->message = L"fuzz seam denied terminate request";
        err->context = L"TerminateProcess";
    }
    return allowed;
}

bool SuspendProcess(ProcessId pid, Error* err) noexcept {
    const bool allowed = ((pid & 1u) == 0u);
    if (!allowed && err != nullptr) {
        err->win32 = ERROR_ACCESS_DENIED;
        err->message = L"fuzz seam denied suspend request";
        err->context = L"SuspendProcess";
    }
    return allowed;
}

}  // namespace ShadowStrike::Utils::ProcessUtils
