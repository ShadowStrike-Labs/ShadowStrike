/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "DKOMDetector.hpp"
#include "../Common/Types.hpp"
#include "../Common/Platform.hpp"
#include "../Core/Kernel/KernelStructures.hpp"
#include "../Core/Kernel/KernelAddressSpace.hpp"
#include "../Core/Kernel/MSREmulation.hpp"
#include "../Core/Kernel/RingTransition.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <deque>
#include <limits>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace Phantom {

// ============================================================================
// Hard Caps — prevent resource exhaustion during analysis
// ============================================================================

static constexpr uint32_t kMaxAPICallsPerPid      = 256;
static constexpr uint32_t kMaxTrackedPids          = 1024;
static constexpr uint32_t kMaxMSRWriteRecords      = 4096;
static constexpr uint32_t kMaxRingTransitions       = 4096;
static constexpr uint32_t kMaxMemoryWriteRecords    = 8192;
static constexpr uint32_t kMaxFindings              = 10'000;
static constexpr uint32_t kMaxMitreTechniques       = 256;
static constexpr uint32_t kMaxRelatedAPICalls        = 64;
static constexpr size_t   kMaxStoredAPINameLength    = 128;
static constexpr float    kDefaultRootkitThreshold  = 60.0f;
static constexpr float    kMaxSeverityScore         = 100.0f;

// ============================================================================
// Base severity scores per DKOM detection type
// ============================================================================

static constexpr float kBaseSeverityProcessUnlinked  = 80.0f;
static constexpr float kBaseSeveritySSDTHooked       = 90.0f;
static constexpr float kBaseSeverityIDTHooked        = 85.0f;
static constexpr float kBaseSeverityTokenSwapped     = 75.0f;
static constexpr float kBaseSeverityDriverUnlinked   = 70.0f;
static constexpr float kBaseSeverityThreadUnlinked   = 65.0f;
static constexpr float kBaseSeverityCallbackRemoved  = 60.0f;

// Severity boost values for behavioral correlation
static constexpr float kBoostMSRCorrelation          = 10.0f;
static constexpr float kBoostRingTransition          = 5.0f;
static constexpr float kBoostSuspiciousAPI           = 15.0f;

// ============================================================================
// MSR indices of interest for rootkit detection
// ============================================================================

static constexpr uint32_t kMSR_LSTAR = 0xC0000082;
static constexpr uint32_t kMSR_EFER  = 0xC0000080;
static constexpr uint32_t kMSR_STAR  = 0xC0000081;
static constexpr uint32_t kMSR_CSTAR = 0xC0000083;

// ============================================================================
// Suspicious API set — calls commonly associated with rootkit/DKOM behavior
// ============================================================================

static const std::array<std::string_view, 14> kSuspiciousAPIs = {{
    "ZwWriteVirtualMemory",
    "NtWriteVirtualMemory",
    "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection",
    "NtSystemDebugControl",
    "ZwSystemDebugControl",
    "NtSetSystemInformation",
    "ZwSetSystemInformation",
    "NtLoadDriver",
    "ZwLoadDriver",
    "NtDeviceIoControlFile",
    "MmCopyVirtualMemory",
    "MmMapIoSpace",
    "KeInsertQueueApc",
}};

// ============================================================================
// Internal record types
// ============================================================================

struct APICallEntry {
    std::string apiName;
    uint32_t    pid       = 0;
    uint64_t    timestamp = 0;
};

struct MSRWriteEntry {
    uint32_t msrIndex = 0;
    uint64_t value    = 0;
    uint64_t timestamp = 0;
};

struct RingTransitionEntry {
    uint8_t  fromCPL   = 0;
    uint8_t  toCPL     = 0;
    uint64_t timestamp = 0;
};

struct MemoryWriteEntry {
    GuestAddress addr = 0;
    uint32_t     size = 0;
    uint64_t     timestamp = 0;
};

// ============================================================================
// MITRE ATT&CK mapping tables
// ============================================================================

struct MITREMapping {
    const char* technique;
    const char* subTechnique;
    const char* tactics;
};

[[nodiscard]] static MITREMapping GetPrimaryMITREMapping(DKOMDetection::Type type) noexcept {
    switch (type) {
    case DKOMDetection::Type::ProcessUnlinked:
        return { "T1014", "T1564.001", "Defense Evasion" };
    case DKOMDetection::Type::SSDTHooked:
        return { "T1014", "T1574.013", "Defense Evasion" };
    case DKOMDetection::Type::IDTHooked:
        return { "T1014", "T1547.006", "Defense Evasion, Persistence" };
    case DKOMDetection::Type::TokenSwapped:
        return { "T1134.001", "", "Privilege Escalation, Defense Evasion" };
    case DKOMDetection::Type::DriverUnlinked:
        return { "T1014", "T1543.003", "Defense Evasion, Persistence" };
    case DKOMDetection::Type::ThreadUnlinked:
        return { "T1014", "T1055", "Defense Evasion" };
    case DKOMDetection::Type::CallbackRemoved:
        return { "T1562.001", "", "Defense Evasion" };
    default:
        return { "T1014", "", "Defense Evasion" };
    }
}

[[nodiscard]] static float GetBaseSeverity(DKOMDetection::Type type) noexcept {
    switch (type) {
    case DKOMDetection::Type::ProcessUnlinked:  return kBaseSeverityProcessUnlinked;
    case DKOMDetection::Type::SSDTHooked:       return kBaseSeveritySSDTHooked;
    case DKOMDetection::Type::IDTHooked:        return kBaseSeverityIDTHooked;
    case DKOMDetection::Type::TokenSwapped:     return kBaseSeverityTokenSwapped;
    case DKOMDetection::Type::DriverUnlinked:   return kBaseSeverityDriverUnlinked;
    case DKOMDetection::Type::ThreadUnlinked:   return kBaseSeverityThreadUnlinked;
    case DKOMDetection::Type::CallbackRemoved:  return kBaseSeverityCallbackRemoved;
    default:                                    return 50.0f;
    }
}

[[nodiscard]] static bool IsSuspiciousAPI(std::string_view apiName) noexcept {
    return std::any_of(kSuspiciousAPIs.begin(), kSuspiciousAPIs.end(),
                       [&](std::string_view s) { return s == apiName; });
}

[[nodiscard]] static bool SameDetectionIdentity(
    const DKOMDetection& lhs,
    const DKOMDetection& rhs) noexcept
{
    return lhs.type == rhs.type &&
           lhs.targetPid == rhs.targetPid &&
           lhs.targetAddr == rhs.targetAddr;
}

static void IncrementSaturating(uint32_t& value, uint32_t delta = 1) noexcept {
    const uint32_t remaining = std::numeric_limits<uint32_t>::max() - value;
    value += std::min(delta, remaining);
}

// ============================================================================
// DKOMDetector::Impl
// ============================================================================

struct DKOMDetector::Impl {
    mutable std::shared_mutex mutex;

    // Per-PID circular buffer of recent API calls (capped at kMaxAPICallsPerPid)
    std::unordered_map<uint32_t, std::deque<APICallEntry>> apiCallsPerPid;

    // MSR write tracking — for LSTAR/EFER/STAR/CSTAR modifications
    std::deque<MSRWriteEntry>  msrWrites;
    std::unordered_set<uint32_t> criticalMSRsWritten;

    // Ring transition anomaly history
    std::deque<RingTransitionEntry> ringTransitions;
    bool hasRingTransitionAnomaly = false;

    // Kernel memory write tracking (SSDT/IDT region writes)
    std::deque<MemoryWriteEntry> memoryWrites;

    // Previous scan results for incremental delta
    std::vector<DKOMDetection> previousDKOMResults;
    std::vector<uint32_t>      previousSSDTHooks;
    std::vector<uint8_t>       previousIDTHooks;

    // Configurable rootkit threshold
    float rootkitScoreThreshold = kDefaultRootkitThreshold;

    // Statistics
    uint32_t totalScans    = 0;
    uint32_t totalFindings = 0;
    mutable uint64_t droppedEvents = 0;

    bool initialized = false;

    // Monotonic tick counter used as lightweight logical timestamp
    uint64_t tickCounter = 0;

    [[nodiscard]] uint64_t NextTick() noexcept {
        if (tickCounter != std::numeric_limits<uint64_t>::max()) {
            ++tickCounter;
        }
        return tickCounter;
    }

    void RecordDrop() const noexcept {
        if (droppedEvents != std::numeric_limits<uint64_t>::max()) {
            ++droppedEvents;
        }
    }

    [[nodiscard]] static std::string TruncateAPIName(const std::string& apiName) {
        if (apiName.size() <= kMaxStoredAPINameLength) {
            return apiName;
        }
        return apiName.substr(0, kMaxStoredAPINameLength);
    }

    // ========================================================================
    // Correlation helpers
    // ========================================================================

    // Check if a given PID has made suspicious API calls recently
    [[nodiscard]] bool HasSuspiciousAPICalls(uint32_t pid,
                                             std::vector<std::string>& outCalls) const {
        auto it = apiCallsPerPid.find(pid);
        if (it == apiCallsPerPid.end()) return false;

        bool found = false;
        for (const auto& entry : it->second) {
            if (IsSuspiciousAPI(entry.apiName)) {
                outCalls.push_back(entry.apiName);
                if (outCalls.size() >= kMaxRelatedAPICalls) return true;
                found = true;
            }
        }
        return found;
    }

    // Check if any process has made suspicious API calls (for non-PID findings)
    [[nodiscard]] bool HasAnySuspiciousAPICalls(
            std::vector<std::string>& outCalls) const {
        bool found = false;
        for (const auto& [pid, calls] : apiCallsPerPid) {
            for (const auto& entry : calls) {
                if (IsSuspiciousAPI(entry.apiName)) {
                    outCalls.push_back(entry.apiName);
                    if (outCalls.size() >= kMaxRelatedAPICalls) return true;
                    found = true;
                }
            }
        }
        return found;
    }

    // Check if critical MSRs (LSTAR, EFER) have been written
    [[nodiscard]] bool HasCriticalMSRWrite() const noexcept {
        return criticalMSRsWritten.count(kMSR_LSTAR) > 0 ||
               criticalMSRsWritten.count(kMSR_EFER) > 0 ||
               criticalMSRsWritten.count(kMSR_STAR) > 0 ||
               criticalMSRsWritten.count(kMSR_CSTAR) > 0;
    }

    // Check if ring transition anomalies were observed
    [[nodiscard]] bool HasRingTransitionAnomaly() const noexcept {
        return hasRingTransitionAnomaly;
    }

    // ========================================================================
    // Enrich a raw DKOMDetection into a full DKOMFinding
    // ========================================================================

    [[nodiscard]] DKOMFinding EnrichDetection(const DKOMDetection& raw) const {
        DKOMFinding finding;
        finding.type        = raw.type;
        finding.description = raw.description;
        finding.targetPid   = raw.targetPid;
        finding.targetAddr  = raw.targetAddr;

        // Base severity
        float severity = GetBaseSeverity(raw.type);

        // MITRE mapping
        auto mitre = GetPrimaryMITREMapping(raw.type);
        finding.mitreTechnique    = mitre.technique;
        finding.mitreSubTechnique = mitre.subTechnique;
        finding.mitreTactics      = mitre.tactics;

        // Correlate with API behavior
        std::vector<std::string> relatedAPIs;
        try {
            if (raw.targetPid != 0) {
                finding.correlatedWithAPIBehavior =
                    HasSuspiciousAPICalls(raw.targetPid, relatedAPIs);
            } else {
                finding.correlatedWithAPIBehavior =
                    HasAnySuspiciousAPICalls(relatedAPIs);
            }
        } catch (const std::bad_alloc&) {
            RecordDrop();
            finding.correlatedWithAPIBehavior = true;
        }
        if (finding.correlatedWithAPIBehavior) {
            severity += kBoostSuspiciousAPI;
            finding.relatedAPICalls = std::move(relatedAPIs);
        }

        // Correlate with MSR writes
        finding.correlatedWithMSRWrite = HasCriticalMSRWrite();
        if (finding.correlatedWithMSRWrite) {
            severity += kBoostMSRCorrelation;
        }

        // Correlate with ring transition anomalies
        finding.correlatedWithRingTransition = HasRingTransitionAnomaly();
        if (finding.correlatedWithRingTransition) {
            severity += kBoostRingTransition;
        }

        // Clamp severity
        finding.severityScore = std::min(severity, kMaxSeverityScore);

        return finding;
    }

    // ========================================================================
    // Synthetic findings from SSDT/IDT hook lists
    // ========================================================================

    [[nodiscard]] DKOMFinding MakeSSDTHookFinding(uint32_t serviceNumber) const {
        DKOMDetection raw;
        raw.type        = DKOMDetection::Type::SSDTHooked;
        raw.description = "SSDT entry " + std::to_string(serviceNumber) + " hooked";
        raw.targetAddr  = static_cast<GuestAddress>(serviceNumber);
        return EnrichDetection(raw);
    }

    [[nodiscard]] DKOMFinding MakeIDTHookFinding(uint8_t vector) const {
        DKOMDetection raw;
        raw.type        = DKOMDetection::Type::IDTHooked;
        raw.description = "IDT vector " + std::to_string(vector) + " hooked";
        raw.targetAddr  = static_cast<GuestAddress>(vector);
        return EnrichDetection(raw);
    }

    // ========================================================================
    // Collect MITRE techniques from findings (deduplicated)
    // ========================================================================

    [[nodiscard]] static std::vector<std::string> CollectMITRETechniques(
            const std::vector<DKOMFinding>& findings) {
        std::vector<std::string> result;
        try {
            result.reserve(16);
        } catch (const std::bad_alloc&) {
            return result;
        }

        const auto appendUnique = [&result](const std::string& technique) {
            if (technique.empty() || result.size() >= kMaxMitreTechniques) {
                return;
            }
            if (std::find(result.begin(), result.end(), technique) == result.end()) {
                result.push_back(technique);
            }
        };

        for (const auto& f : findings) {
            try {
                appendUnique(f.mitreTechnique);
                appendUnique(f.mitreSubTechnique);
            } catch (const std::bad_alloc&) {
                break;
            }
            if (result.size() >= kMaxMitreTechniques) break;
        }
        return result;
    }

    // ========================================================================
    // Compute composite rootkit score from all findings
    // ========================================================================

    [[nodiscard]] static float ComputeRootkitScore(
            const std::vector<DKOMFinding>& findings) noexcept {
        if (findings.empty()) return 0.0f;

        // Weighted average: higher-severity findings contribute more
        float weightedSum  = 0.0f;
        float totalWeight  = 0.0f;

        for (const auto& f : findings) {
            float weight = f.severityScore;
            weightedSum += f.severityScore * weight;
            totalWeight += weight;
        }

        if (totalWeight <= 0.0f) return 0.0f;

        float baseScore = weightedSum / totalWeight;

        // Diversity bonus: more distinct types → higher score
        std::array<bool, 8> types{};
        uint32_t typeCount = 0;
        for (const auto& f : findings) {
            const auto typeIndex = static_cast<uint8_t>(f.type);
            if (typeIndex < types.size() && !types[typeIndex]) {
                types[typeIndex] = true;
                ++typeCount;
            }
        }
        float diversityBonus = std::min(static_cast<float>(typeCount) * 3.0f, 15.0f);

        return std::min(baseScore + diversityBonus, kMaxSeverityScore);
    }

    // ========================================================================
    // Count helpers for report generation
    // ========================================================================

    static void TallyFindings(const std::vector<DKOMFinding>& findings,
                              DKOMAnalysisReport& report) noexcept {
        for (const auto& f : findings) {
            switch (f.type) {
            case DKOMDetection::Type::ProcessUnlinked:  IncrementSaturating(report.processesHidden);  break;
            case DKOMDetection::Type::SSDTHooked:       IncrementSaturating(report.ssdtHooksDetected); break;
            case DKOMDetection::Type::IDTHooked:        IncrementSaturating(report.idtHooksDetected);  break;
            case DKOMDetection::Type::DriverUnlinked:   IncrementSaturating(report.driversUnlinked);   break;
            case DKOMDetection::Type::TokenSwapped:     IncrementSaturating(report.tokensSwapped);     break;
            case DKOMDetection::Type::ThreadUnlinked:   break;
            case DKOMDetection::Type::CallbackRemoved:  break;
            }
        }
    }

    // ========================================================================
    // MSR tampering check via MSREmulation
    // ========================================================================

    void CheckMSRTampering(std::vector<DKOMFinding>& findings) const {
        auto modifications = MSREmulation::Instance().DetectModifications();
        for (const auto& mod : modifications) {
            if (findings.size() >= kMaxFindings) break;
            if (mod.msrIndex == kMSR_LSTAR || mod.msrIndex == kMSR_EFER ||
                mod.msrIndex == kMSR_STAR  || mod.msrIndex == kMSR_CSTAR) {

                DKOMDetection raw;
                raw.type        = DKOMDetection::Type::SSDTHooked;
                raw.description = "MSR " + mod.msrName + " tampered: original=0x" +
                                  std::to_string(mod.originalValue) + " current=0x" +
                                  std::to_string(mod.currentValue);
                raw.targetAddr  = static_cast<GuestAddress>(mod.msrIndex);
                try {
                    findings.push_back(EnrichDetection(raw));
                } catch (const std::bad_alloc&) {
                    RecordDrop();
                    break;
                }
            }
        }
    }

    // ========================================================================
    // Ring transition anomaly integration
    // ========================================================================

    void CheckRingTransitionAnomalies(std::vector<DKOMFinding>& findings) const {
        auto anomalies = RingTransition::Instance().DetectAnomalies();
        for (const auto& anomaly : anomalies) {
            if (findings.size() >= kMaxFindings) break;
            DKOMDetection raw;
            raw.description = "Ring transition anomaly: " + anomaly.description;
            raw.targetAddr  = anomaly.event.fromRIP;

            switch (anomaly.type) {
            case RingTransitionAnomaly::Type::UserCodeAtRing0:
            case RingTransitionAnomaly::Type::SysretToKernel:
                raw.type = DKOMDetection::Type::SSDTHooked;
                break;
            case RingTransitionAnomaly::Type::StackPivot:
            case RingTransitionAnomaly::Type::NonCanonicalReturn:
                raw.type = DKOMDetection::Type::TokenSwapped;
                break;
            default:
                raw.type = DKOMDetection::Type::CallbackRemoved;
                break;
            }

            try {
                findings.push_back(EnrichDetection(raw));
            } catch (const std::bad_alloc&) {
                RecordDrop();
                break;
            }
        }
    }
};

// ============================================================================
// Singleton
// ============================================================================

DKOMDetector& DKOMDetector::Instance() {
    static DKOMDetector instance;
    return instance;
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

DKOMDetector::DKOMDetector()
    : m_impl(std::make_unique<Impl>()) {}

DKOMDetector::~DKOMDetector() = default;

// ============================================================================
// Reset
// ============================================================================

void DKOMDetector::Reset() {
    std::unique_lock lock(m_impl->mutex);

    m_impl->apiCallsPerPid.clear();
    m_impl->msrWrites.clear();
    m_impl->criticalMSRsWritten.clear();
    m_impl->ringTransitions.clear();
    m_impl->hasRingTransitionAnomaly = false;
    m_impl->memoryWrites.clear();
    m_impl->previousDKOMResults.clear();
    m_impl->previousSSDTHooks.clear();
    m_impl->previousIDTHooks.clear();
    m_impl->rootkitScoreThreshold = kDefaultRootkitThreshold;
    m_impl->totalScans    = 0;
    m_impl->totalFindings = 0;
    m_impl->tickCounter   = 0;
    m_impl->droppedEvents = 0;
    m_impl->initialized   = false;
}

// ============================================================================
// Initialize
// ============================================================================

bool DKOMDetector::Initialize() {
    std::unique_lock lock(m_impl->mutex);

    if (m_impl->initialized) return true;

    m_impl->apiCallsPerPid.clear();
    m_impl->msrWrites.clear();
    m_impl->criticalMSRsWritten.clear();
    m_impl->ringTransitions.clear();
    m_impl->hasRingTransitionAnomaly = false;
    m_impl->memoryWrites.clear();
    m_impl->previousDKOMResults.clear();
    m_impl->previousSSDTHooks.clear();
    m_impl->previousIDTHooks.clear();
    m_impl->totalScans    = 0;
    m_impl->totalFindings = 0;
    m_impl->tickCounter   = 0;
    m_impl->droppedEvents = 0;
    m_impl->initialized   = true;

    return true;
}

// ============================================================================
// RunFullScan — comprehensive DKOM analysis
// ============================================================================

DKOMAnalysisReport DKOMDetector::RunFullScan() {
    std::unique_lock lock(m_impl->mutex);

    DKOMAnalysisReport report{};
    std::vector<DKOMFinding> allFindings;

    auto& kom = KernelObjectManager::Instance();

    // 1. Raw DKOM scan from KernelObjectManager
    auto dkomDetections = kom.ScanForDKOM();

    // 2. SSDT hook detection
    auto ssdtHooks = kom.DetectSSDTHooks();

    // 3. IDT hook detection
    auto idtHooks = kom.DetectIDTHooks();

    // 4. Integrity validations
    if (!kom.ValidateProcessList()) {
        IncrementSaturating(report.processListIntegrityFailures);
    }
    [[maybe_unused]] bool driverOk = kom.ValidateDriverIntegrity();

    // 5. Enrich raw DKOM detections
    const size_t reserveTarget = std::min<size_t>(
        kMaxFindings,
        std::min<size_t>(kMaxFindings, dkomDetections.size()) +
            std::min<size_t>(kMaxFindings, ssdtHooks.size()) +
            std::min<size_t>(kMaxFindings, idtHooks.size()) +
            32);
    try {
        allFindings.reserve(std::min<size_t>(reserveTarget, kMaxFindings));
    } catch (const std::bad_alloc&) {
        m_impl->RecordDrop();
    }

    for (const auto& detection : dkomDetections) {
        if (allFindings.size() >= kMaxFindings) break;
        try {
            allFindings.push_back(m_impl->EnrichDetection(detection));
        } catch (const std::bad_alloc&) {
            m_impl->RecordDrop();
            break;
        }
    }

    // 6. Add SSDT hook findings
    for (uint32_t svcNum : ssdtHooks) {
        if (allFindings.size() >= kMaxFindings) break;
        try {
            allFindings.push_back(m_impl->MakeSSDTHookFinding(svcNum));
        } catch (const std::bad_alloc&) {
            m_impl->RecordDrop();
            break;
        }
    }

    // 7. Add IDT hook findings
    for (uint8_t vec : idtHooks) {
        if (allFindings.size() >= kMaxFindings) break;
        try {
            allFindings.push_back(m_impl->MakeIDTHookFinding(vec));
        } catch (const std::bad_alloc&) {
            m_impl->RecordDrop();
            break;
        }
    }

    // 8. Check MSR tampering via MSREmulation
    m_impl->CheckMSRTampering(allFindings);

    // 9. Check ring transition anomalies via RingTransition
    m_impl->CheckRingTransitionAnomalies(allFindings);

    // Tally category counts
    Impl::TallyFindings(allFindings, report);

    // Compute composite rootkit score
    report.overallRootkitScore = Impl::ComputeRootkitScore(allFindings);
    report.isRootkitDetected   = report.overallRootkitScore >= m_impl->rootkitScoreThreshold;

    // Collect MITRE techniques
    report.mitreTechniquesUsed = Impl::CollectMITRETechniques(allFindings);

    // Store results for next incremental scan
    m_impl->previousDKOMResults = std::move(dkomDetections);
    m_impl->previousSSDTHooks   = std::move(ssdtHooks);
    m_impl->previousIDTHooks    = std::move(idtHooks);

    // Update statistics
    IncrementSaturating(m_impl->totalScans);
    report.totalScans = m_impl->totalScans;

    IncrementSaturating(m_impl->totalFindings,
                        static_cast<uint32_t>(std::min<size_t>(
                            allFindings.size(),
                            std::numeric_limits<uint32_t>::max())));
    report.findings = std::move(allFindings);

    return report;
}

// ============================================================================
// RunIncrementalScan — delta-only scan (faster than full)
// ============================================================================

std::vector<DKOMFinding> DKOMDetector::RunIncrementalScan() {
    std::unique_lock lock(m_impl->mutex);

    std::vector<DKOMFinding> newFindings;

    auto& kom = KernelObjectManager::Instance();

    // Scan current state
    auto currentDKOM  = kom.ScanForDKOM();
    auto currentSSDT  = kom.DetectSSDTHooks();
    auto currentIDT   = kom.DetectIDTHooks();

    // Delta: find new DKOM detections not present in previous scan
    // Use type + PID + target address as identity; avoid hash-key collisions.
    for (const auto& det : currentDKOM) {
        const bool known = std::any_of(
            m_impl->previousDKOMResults.begin(),
            m_impl->previousDKOMResults.end(),
            [&](const DKOMDetection& prev) noexcept {
                return SameDetectionIdentity(prev, det);
            });
        if (!known) {
            if (newFindings.size() >= kMaxFindings) break;
            try {
                newFindings.push_back(m_impl->EnrichDetection(det));
            } catch (const std::bad_alloc&) {
                m_impl->RecordDrop();
                break;
            }
        }
    }

    // Delta: new SSDT hooks
    for (uint32_t svc : currentSSDT) {
        if (std::find(m_impl->previousSSDTHooks.begin(),
                      m_impl->previousSSDTHooks.end(),
                      svc) == m_impl->previousSSDTHooks.end()) {
            if (newFindings.size() >= kMaxFindings) break;
            try {
                newFindings.push_back(m_impl->MakeSSDTHookFinding(svc));
            } catch (const std::bad_alloc&) {
                m_impl->RecordDrop();
                break;
            }
        }
    }

    // Delta: new IDT hooks
    for (uint8_t vec : currentIDT) {
        if (std::find(m_impl->previousIDTHooks.begin(),
                      m_impl->previousIDTHooks.end(),
                      vec) == m_impl->previousIDTHooks.end()) {
            if (newFindings.size() >= kMaxFindings) break;
            try {
                newFindings.push_back(m_impl->MakeIDTHookFinding(vec));
            } catch (const std::bad_alloc&) {
                m_impl->RecordDrop();
                break;
            }
        }
    }

    // Update previous state
    m_impl->previousDKOMResults = std::move(currentDKOM);
    m_impl->previousSSDTHooks   = std::move(currentSSDT);
    m_impl->previousIDTHooks    = std::move(currentIDT);

    IncrementSaturating(m_impl->totalScans);
    IncrementSaturating(m_impl->totalFindings,
                        static_cast<uint32_t>(std::min<size_t>(
                            newFindings.size(),
                            std::numeric_limits<uint32_t>::max())));

    return newFindings;
}

// ============================================================================
// Correlation Input: OnAPICall
// ============================================================================

void DKOMDetector::OnAPICall(const std::string& apiName, uint32_t pid) {
    std::unique_lock lock(m_impl->mutex);

    if (m_impl->apiCallsPerPid.size() >= kMaxTrackedPids &&
        m_impl->apiCallsPerPid.find(pid) == m_impl->apiCallsPerPid.end()) {
        return;  // Cap tracked PIDs
    }

    std::deque<APICallEntry>* dequePtr = nullptr;
    try {
        dequePtr = &m_impl->apiCallsPerPid[pid];
    } catch (const std::bad_alloc&) {
        m_impl->RecordDrop();
        return;
    }

    auto& deque = *dequePtr;
    if (deque.size() >= kMaxAPICallsPerPid) {
        deque.pop_front();
    }

    APICallEntry entry;
    try {
        entry.apiName = Impl::TruncateAPIName(apiName);
    } catch (const std::bad_alloc&) {
        m_impl->RecordDrop();
        return;
    }
    entry.pid       = pid;
    entry.timestamp = m_impl->NextTick();
    try {
        deque.push_back(std::move(entry));
    } catch (const std::bad_alloc&) {
        m_impl->RecordDrop();
    }
}

// ============================================================================
// Correlation Input: OnMSRWrite
// ============================================================================

void DKOMDetector::OnMSRWrite(uint32_t msrIndex, uint64_t value) {
    std::unique_lock lock(m_impl->mutex);

    if (m_impl->msrWrites.size() >= kMaxMSRWriteRecords) {
        m_impl->msrWrites.pop_front();
    }

    MSRWriteEntry entry;
    entry.msrIndex  = msrIndex;
    entry.value     = value;
    entry.timestamp = m_impl->NextTick();
    try {
        m_impl->msrWrites.push_back(entry);
    } catch (const std::bad_alloc&) {
        m_impl->RecordDrop();
        return;
    }

    // Track critical MSR writes
    if (msrIndex == kMSR_LSTAR || msrIndex == kMSR_EFER ||
        msrIndex == kMSR_STAR  || msrIndex == kMSR_CSTAR) {
        try {
            m_impl->criticalMSRsWritten.insert(msrIndex);
        } catch (const std::bad_alloc&) {
            m_impl->RecordDrop();
        }
    }
}

// ============================================================================
// Correlation Input: OnRingTransition
// ============================================================================

void DKOMDetector::OnRingTransition(uint8_t fromCPL, uint8_t toCPL) {
    std::unique_lock lock(m_impl->mutex);

    if (m_impl->ringTransitions.size() >= kMaxRingTransitions) {
        m_impl->ringTransitions.pop_front();
    }

    RingTransitionEntry entry;
    entry.fromCPL   = fromCPL;
    entry.toCPL     = toCPL;
    entry.timestamp = m_impl->NextTick();
    try {
        m_impl->ringTransitions.push_back(entry);
    } catch (const std::bad_alloc&) {
        m_impl->RecordDrop();
        return;
    }

    // Flag anomalous transitions: user→kernel bypassing normal syscall path
    // or kernel→user bypassing sysret
    if (fromCPL == 3 && toCPL == 0) {
        // Could be normal syscall, but flag for correlation
    }
    if (fromCPL == 0 && toCPL == 0) {
        // Kernel-to-kernel: potential anomaly if unexpected
        m_impl->hasRingTransitionAnomaly = true;
    }
}

// ============================================================================
// Correlation Input: OnMemoryWrite
// ============================================================================

void DKOMDetector::OnMemoryWrite(GuestAddress addr, uint32_t size) {
    std::unique_lock lock(m_impl->mutex);

    if (m_impl->memoryWrites.size() >= kMaxMemoryWriteRecords) {
        m_impl->memoryWrites.pop_front();
    }

    MemoryWriteEntry entry;
    entry.addr      = addr;
    entry.size      = size;
    entry.timestamp = m_impl->NextTick();
    try {
        m_impl->memoryWrites.push_back(entry);
    } catch (const std::bad_alloc&) {
        m_impl->RecordDrop();
        return;
    }

    // Writes to kernel address space are inherently suspicious
    if (KernelAddressSpace::IsKernelAddress(addr)) {
        m_impl->hasRingTransitionAnomaly = true;
    }
}

// ============================================================================
// Threshold Configuration
// ============================================================================

void DKOMDetector::SetRootkitScoreThreshold(float threshold) {
    std::unique_lock lock(m_impl->mutex);
    if (!std::isfinite(threshold)) {
        m_impl->RecordDrop();
        return;
    }
    m_impl->rootkitScoreThreshold = std::clamp(threshold, 0.0f, kMaxSeverityScore);
}

float DKOMDetector::GetRootkitScoreThreshold() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->rootkitScoreThreshold;
}

// ============================================================================
// Statistics
// ============================================================================

uint32_t DKOMDetector::GetTotalScans() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->totalScans;
}

uint32_t DKOMDetector::GetTotalFindings() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->totalFindings;
}

} // namespace Phantom
