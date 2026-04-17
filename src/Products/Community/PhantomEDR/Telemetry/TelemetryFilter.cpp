/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
// ===========================================================================
// ShadowStrike – PhantomEDR Telemetry Filter Implementation
//
// Noise-reduction engine: process-allowlist, path-exclusion, per-process
// frequency cap (sliding-window minute granularity), severity floor.
// Events with MITRE ATT&CK IDs always bypass all filters.
//
// Threading model:
//   - std::shared_mutex guards FilterConfig (concurrent reads, exclusive writes)
//   - std::mutex guards the frequency-tracking map
//   - Atomic counters for statistics
// ===========================================================================

#include "pch.h"
#include "TelemetryFilter.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

#include "PhantomCore/Utils/Logger.hpp"

namespace ShadowStrike::Products::PhantomEDR::Telemetry {

// ============================================================================
// ANONYMOUS HELPERS
// ============================================================================

namespace {

/// Case-insensitive wide-string equality using the OS ordinal comparison
/// (correct for NTFS / Win32 path semantics).
bool WideEqualsIgnoreCase(std::wstring_view a, std::wstring_view b) noexcept
{
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    if (a.size() > static_cast<size_t>(std::numeric_limits<int>::max())) return false;
    return ::CompareStringOrdinal(
               a.data(), static_cast<int>(a.size()),
               b.data(), static_cast<int>(b.size()),
               TRUE) == CSTR_EQUAL;
}

/// Return the filename portion of a path (everything after the last separator).
std::wstring_view ExtractFileName(std::wstring_view path) noexcept
{
    const auto pos = path.find_last_of(L"\\/");
    return (pos != std::wstring_view::npos) ? path.substr(pos + 1) : path;
}

/// Component-by-component path-prefix matcher with single-segment wildcard.
///   Pattern  L"C:\\Users\\*\\AppData\\Local\\Temp\\"
///   Path     L"C:\\Users\\john\\AppData\\Local\\Temp\\evil.exe"  → match
/// The pattern must match as a prefix; the path may extend beyond the pattern.
bool MatchesPathPattern(std::wstring_view path, std::wstring_view pattern) noexcept
{
    if (pattern.empty() || path.empty()) return false;

    // Fast path: no wildcard → simple case-insensitive prefix
    if (pattern.find(L'*') == std::wstring_view::npos) {
        if (path.size() < pattern.size()) return false;
        return ::CompareStringOrdinal(
                   path.data(), static_cast<int>(pattern.size()),
                   pattern.data(), static_cast<int>(pattern.size()),
                   TRUE) == CSTR_EQUAL;
    }

    // Wildcard path: walk both strings component by component
    size_t pi = 0;    // path   cursor
    size_t pati = 0;  // pattern cursor

    while (pati < pattern.size() && pi < path.size()) {
        // Next path component
        size_t pEnd = path.find(L'\\', pi);
        if (pEnd == std::wstring_view::npos) pEnd = path.size();
        const auto pathComp = path.substr(pi, pEnd - pi);

        // Next pattern component
        size_t patEnd = pattern.find(L'\\', pati);
        if (patEnd == std::wstring_view::npos) patEnd = pattern.size();
        const auto patComp = pattern.substr(pati, patEnd - pati);

        // Skip empty components produced by trailing separators
        if (pathComp.empty()) { pi  = pEnd  + 1; continue; }
        if (patComp.empty())  { pati = patEnd + 1; continue; }

        // '*' matches any single component; otherwise require exact match
        if (patComp != L"*" && !WideEqualsIgnoreCase(pathComp, patComp)) {
            return false;
        }

        pi   = (pEnd   < path.size())    ? pEnd   + 1 : path.size();
        pati = (patEnd < pattern.size())  ? patEnd + 1 : pattern.size();
    }

    // All pattern components must have been consumed (trailing separators OK)
    while (pati < pattern.size()) {
        if (pattern[pati] != L'\\') return false;
        ++pati;
    }
    return true;
}

} // anonymous namespace

// ============================================================================
// FREQUENCY-TRACKING STRUCTURES
// ============================================================================

struct FrequencyKey {
    uint32_t      processId;
    EventCategory category;

    bool operator==(const FrequencyKey&) const = default;
};

struct FrequencyKeyHash {
    size_t operator()(const FrequencyKey& k) const noexcept {
        // Combine with a prime-multiplication mix
        const auto h1 = std::hash<uint32_t>{}(k.processId);
        const auto h2 = std::hash<int>{}(static_cast<int>(k.category));
        return h1 ^ (h2 * 2654435761ULL);
    }
};

struct FrequencyEntry {
    uint32_t count        = 0;
    int64_t  windowMinute = 0;
};

// ============================================================================
// TELEMETRY FILTER IMPLEMENTATION  (PIMPL — free class, NOT nested)
// ============================================================================

class TelemetryFilterImpl {
public:
    TelemetryFilterImpl()  = default;
    ~TelemetryFilterImpl() = default;

    // -- Lifecycle -----------------------------------------------------------
    bool Initialize(const FilterConfig& config);
    void Shutdown();

    // -- Core filtering ------------------------------------------------------
    bool ShouldKeep(const TelemetryEvent& event);

    // -- Dynamic updates -----------------------------------------------------
    void AddProcessExclusion(std::wstring_view processName);
    void RemoveProcessExclusion(std::wstring_view processName);
    void AddPathExclusion(std::wstring_view path);
    void RemovePathExclusion(std::wstring_view path);
    void SetMinimumSeverity(EventSeverity severity);

    // -- Statistics ----------------------------------------------------------
    uint64_t GetFilteredCount() const noexcept { return m_filteredCount.load(std::memory_order_relaxed); }
    uint64_t GetPassedCount()   const noexcept { return m_passedCount.load(std::memory_order_relaxed); }
    void ResetStats();

private:
    // -- Internal checks (caller holds m_configMutex in shared mode) ---------
    bool IsProcessExcluded(const TelemetryEvent& event) const;
    bool IsPathExcluded(const TelemetryEvent& event) const;
    bool IsFrequencyCapped(const TelemetryEvent& event, uint32_t cap);
    bool IsBelowSeverityFloor(const TelemetryEvent& event) const;
    static bool ShouldBypassFilters(const TelemetryEvent& event);

    void PopulateDefaultAllowlist();
    void EvictStaleFrequencyEntries(int64_t currentMinute);

    static int64_t GetCurrentMinute() noexcept {
        using namespace std::chrono;
        return duration_cast<minutes>(
                   steady_clock::now().time_since_epoch()).count();
    }

    // -- Configuration (shared-mutex protected) ------------------------------
    FilterConfig             m_config;
    mutable std::shared_mutex m_configMutex;

    // -- Frequency map (mutex protected) -------------------------------------
    std::unordered_map<FrequencyKey, FrequencyEntry, FrequencyKeyHash> m_frequencyMap;
    std::mutex  m_frequencyMutex;
    int64_t     m_lastEvictionMinute = 0;

    static constexpr int64_t kEvictionIntervalMinutes = 5;
    static constexpr size_t  kMaxFrequencyEntries     = 100'000;

    // -- Statistics (atomic) -------------------------------------------------
    std::atomic<uint64_t> m_filteredCount{0};
    std::atomic<uint64_t> m_passedCount{0};

    // -- State ---------------------------------------------------------------
    std::atomic<bool> m_initialized{false};
};

// ============================================================================
// LIFECYCLE
// ============================================================================

bool TelemetryFilterImpl::Initialize(const FilterConfig& config)
{
    if (m_initialized.load(std::memory_order_acquire)) {
        ShadowStrike::Utils::Logger::Warn(
            "[TelemetryFilter] Already initialized — ignoring duplicate call");
        return false;
    }

    {
        std::unique_lock lock(m_configMutex);
        m_config = config;
        PopulateDefaultAllowlist();
    }

    {
        std::lock_guard lock(m_frequencyMutex);
        m_frequencyMap.clear();
        m_lastEvictionMinute = GetCurrentMinute();
    }

    m_filteredCount.store(0, std::memory_order_relaxed);
    m_passedCount.store(0, std::memory_order_relaxed);
    m_initialized.store(true, std::memory_order_release);

    ShadowStrike::Utils::Logger::Info(
        "[TelemetryFilter] Initialized — {} process exclusions, "
        "{} path exclusions, severity floor={}, freq cap={}/min",
        m_config.processAllowlist.size(),
        m_config.pathExclusions.size(),
        static_cast<int>(m_config.minimumSeverity),
        m_config.maxEventsPerProcessPerCategoryPerMinute);

    return true;
}

void TelemetryFilterImpl::Shutdown()
{
    if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    const auto filtered = m_filteredCount.load(std::memory_order_relaxed);
    const auto passed   = m_passedCount.load(std::memory_order_relaxed);

    {
        std::lock_guard lock(m_frequencyMutex);
        m_frequencyMap.clear();
    }

    ShadowStrike::Utils::Logger::Info(
        "[TelemetryFilter] Shutdown — lifetime filtered={}, passed={}", filtered, passed);
}

// ============================================================================
// CORE FILTER LOGIC
// ============================================================================

bool TelemetryFilterImpl::ShouldKeep(const TelemetryEvent& event)
{
    if (!m_initialized.load(std::memory_order_acquire)) {
        return true;  // not yet initialised → pass everything
    }

    // MITRE-tagged events always bypass all filters
    if (ShouldBypassFilters(event)) {
        m_passedCount.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // Hold config shared-lock for the cheap filters, release before frequency
    uint32_t frequencyCap = 0;
    bool     frequencyEnabled = false;
    {
        std::shared_lock configLock(m_configMutex);

        // Always-keep categories
        if (m_config.alwaysKeepCategories.contains(event.category)) {
            m_passedCount.fetch_add(1, std::memory_order_relaxed);
            return true;
        }

        // 1. Severity floor (cheapest check)
        if (IsBelowSeverityFloor(event)) {
            m_filteredCount.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // 2. Process allowlist
        if (m_config.enableProcessFilter && IsProcessExcluded(event)) {
            m_filteredCount.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // 3. Path exclusion
        if (m_config.enablePathFilter && IsPathExcluded(event)) {
            m_filteredCount.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // Snapshot frequency config to avoid holding config lock across freq mutex
        frequencyEnabled = m_config.enableFrequencyFilter;
        frequencyCap     = m_config.maxEventsPerProcessPerCategoryPerMinute;
    }
    // configLock released here

    // 4. Frequency cap (most expensive — mutates internal map)
    if (frequencyEnabled && IsFrequencyCapped(event, frequencyCap)) {
        m_filteredCount.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    m_passedCount.fetch_add(1, std::memory_order_relaxed);
    return true;
}

// ============================================================================
// INDIVIDUAL FILTERS  (caller holds m_configMutex in shared mode except freq)
// ============================================================================

bool TelemetryFilterImpl::ShouldBypassFilters(const TelemetryEvent& event)
{
    return !event.mitreAttackId.empty();
}

bool TelemetryFilterImpl::IsBelowSeverityFloor(const TelemetryEvent& event) const
{
    return static_cast<int>(event.severity) < static_cast<int>(m_config.minimumSeverity);
}

bool TelemetryFilterImpl::IsProcessExcluded(const TelemetryEvent& event) const
{
    const auto procFile = ExtractFileName(event.processName);
    if (procFile.empty()) return false;

    for (const auto& excluded : m_config.processAllowlist) {
        if (WideEqualsIgnoreCase(procFile, excluded)) {
            return true;
        }
    }
    return false;
}

bool TelemetryFilterImpl::IsPathExcluded(const TelemetryEvent& event) const
{
    // Check process path against exclusions
    if (!event.processPath.empty()) {
        for (const auto& pattern : m_config.pathExclusions) {
            if (MatchesPathPattern(event.processPath, pattern)) {
                return true;
            }
        }
    }

    // For file events, also check the file-specific path
    if (event.category == EventCategory::File) {
        if (const auto* fd = std::get_if<FileEventData>(&event.payload)) {
            if (!fd->filePath.empty()) {
                for (const auto& pattern : m_config.pathExclusions) {
                    if (MatchesPathPattern(fd->filePath, pattern)) {
                        return true;
                    }
                }
            }
        }
    }

    // For registry events, check key path
    if (event.category == EventCategory::Registry) {
        if (const auto* rd = std::get_if<RegistryEventData>(&event.payload)) {
            if (!rd->keyPath.empty()) {
                for (const auto& pattern : m_config.pathExclusions) {
                    if (MatchesPathPattern(rd->keyPath, pattern)) {
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

bool TelemetryFilterImpl::IsFrequencyCapped(const TelemetryEvent& event, uint32_t cap)
{
    std::lock_guard lock(m_frequencyMutex);

    const int64_t currentMin = GetCurrentMinute();

    // Periodic stale-entry eviction
    if (currentMin - m_lastEvictionMinute >= kEvictionIntervalMinutes) {
        EvictStaleFrequencyEntries(currentMin);
        m_lastEvictionMinute = currentMin;
    }

    const FrequencyKey key{event.processId, event.category};

    // Guard against unbounded map growth before inserting
    if (m_frequencyMap.size() >= kMaxFrequencyEntries &&
        !m_frequencyMap.contains(key)) {
        EvictStaleFrequencyEntries(currentMin);
        if (m_frequencyMap.size() >= kMaxFrequencyEntries) {
            ShadowStrike::Utils::Logger::Warn(
                "[TelemetryFilter] Frequency map at capacity ({}) — emergency clear",
                kMaxFrequencyEntries);
            m_frequencyMap.clear();
        }
    }

    auto& entry = m_frequencyMap[key];

    if (entry.windowMinute != currentMin) {
        entry.windowMinute = currentMin;
        entry.count        = 1;
    } else {
        ++entry.count;
    }

    return entry.count > cap;
}

// ============================================================================
// STALE-ENTRY EVICTION  (caller holds m_frequencyMutex)
// ============================================================================

void TelemetryFilterImpl::EvictStaleFrequencyEntries(int64_t currentMinute)
{
    const int64_t staleBefore = currentMinute - 2;  // >2 minutes old
    std::erase_if(m_frequencyMap, [staleBefore](const auto& kv) {
        return kv.second.windowMinute < staleBefore;
    });
}

// ============================================================================
// DEFAULT ALLOWLIST
// ============================================================================

void TelemetryFilterImpl::PopulateDefaultAllowlist()
{
    static constexpr std::wstring_view kDefaults[] = {
        L"svchost.exe",
        L"RuntimeBroker.exe",
        L"WmiPrvSE.exe",
        L"SearchIndexer.exe",
        L"MsMpEng.exe",        // Windows Defender — scans go through dedicated APIs
        L"csrss.exe",
        L"smss.exe",
        L"lsass.exe",          // Credential events go via PhantomCore's credential guard
    };

    for (const auto defProc : kDefaults) {
        const bool alreadyPresent = std::ranges::any_of(
            m_config.processAllowlist,
            [&](const std::wstring& existing) {
                return WideEqualsIgnoreCase(existing, defProc);
            });
        if (!alreadyPresent) {
            m_config.processAllowlist.emplace_back(defProc);
        }
    }
}

// ============================================================================
// DYNAMIC UPDATES
// ============================================================================

void TelemetryFilterImpl::AddProcessExclusion(std::wstring_view processName)
{
    if (processName.empty()) return;

    std::unique_lock lock(m_configMutex);
    const bool exists = std::ranges::any_of(
        m_config.processAllowlist,
        [&](const std::wstring& s) { return WideEqualsIgnoreCase(s, processName); });

    if (!exists) {
        m_config.processAllowlist.emplace_back(processName);
        ShadowStrike::Utils::Logger::Debug(
            "[TelemetryFilter] Added process exclusion (total={})",
            m_config.processAllowlist.size());
    }
}

void TelemetryFilterImpl::RemoveProcessExclusion(std::wstring_view processName)
{
    if (processName.empty()) return;

    std::unique_lock lock(m_configMutex);
    std::erase_if(m_config.processAllowlist,
        [&](const std::wstring& s) { return WideEqualsIgnoreCase(s, processName); });
}

void TelemetryFilterImpl::AddPathExclusion(std::wstring_view path)
{
    if (path.empty()) return;

    std::unique_lock lock(m_configMutex);
    const bool exists = std::ranges::any_of(
        m_config.pathExclusions,
        [&](const std::wstring& s) { return WideEqualsIgnoreCase(s, path); });

    if (!exists) {
        m_config.pathExclusions.emplace_back(path);
        ShadowStrike::Utils::Logger::Debug(
            "[TelemetryFilter] Added path exclusion (total={})",
            m_config.pathExclusions.size());
    }
}

void TelemetryFilterImpl::RemovePathExclusion(std::wstring_view path)
{
    if (path.empty()) return;

    std::unique_lock lock(m_configMutex);
    std::erase_if(m_config.pathExclusions,
        [&](const std::wstring& s) { return WideEqualsIgnoreCase(s, path); });
}

void TelemetryFilterImpl::SetMinimumSeverity(EventSeverity severity)
{
    std::unique_lock lock(m_configMutex);
    m_config.minimumSeverity = severity;
    ShadowStrike::Utils::Logger::Info(
        "[TelemetryFilter] Severity floor changed to {}",
        static_cast<int>(severity));
}

void TelemetryFilterImpl::ResetStats()
{
    m_filteredCount.store(0, std::memory_order_relaxed);
    m_passedCount.store(0, std::memory_order_relaxed);
}

// ============================================================================
// TELEMETRY FILTER — SINGLETON + FORWARDING
// ============================================================================

TelemetryFilter& TelemetryFilter::Instance()
{
    static TelemetryFilter instance;
    return instance;
}

TelemetryFilter::TelemetryFilter()
    : m_impl(std::make_unique<TelemetryFilterImpl>()) {}

TelemetryFilter::~TelemetryFilter() = default;

bool TelemetryFilter::Initialize(const FilterConfig& config) {
    return m_impl->Initialize(config);
}

void TelemetryFilter::Shutdown() {
    m_impl->Shutdown();
}

bool TelemetryFilter::ShouldKeep(const TelemetryEvent& event) const {
    return m_impl->ShouldKeep(event);
}

void TelemetryFilter::AddProcessExclusion(std::wstring_view processName) {
    m_impl->AddProcessExclusion(processName);
}

void TelemetryFilter::RemoveProcessExclusion(std::wstring_view processName) {
    m_impl->RemoveProcessExclusion(processName);
}

void TelemetryFilter::AddPathExclusion(std::wstring_view path) {
    m_impl->AddPathExclusion(path);
}

void TelemetryFilter::RemovePathExclusion(std::wstring_view path) {
    m_impl->RemovePathExclusion(path);
}

void TelemetryFilter::SetMinimumSeverity(EventSeverity severity) {
    m_impl->SetMinimumSeverity(severity);
}

uint64_t TelemetryFilter::GetFilteredCount() const noexcept {
    return m_impl->GetFilteredCount();
}

uint64_t TelemetryFilter::GetPassedCount() const noexcept {
    return m_impl->GetPassedCount();
}

void TelemetryFilter::ResetStats() {
    m_impl->ResetStats();
}

} // namespace ShadowStrike::Products::PhantomEDR::Telemetry
