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
/**
 * ============================================================================
 * ShadowStrike Ransomware Detection - LOCKY FAMILY DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file LockyDetector.cpp
 * @brief Enterprise-grade multi-vector Locky ransomware family detection.
 *
 * Implements behavioral, static, and heuristic detection for all Locky
 * variants: Original, Zepto, Odin, Thor, Aesir, Zzzzz, Osiris, Diablo6,
 * Lukitus, and Ykcol. Uses per-process score accumulation across a
 * configurable correlation window for high-fidelity detection with
 * minimal false positives.
 *
 * Detection vectors:
 *   - Mass file rename with Locky extension patterns
 *   - Hex-ID filename rename pattern (e.g. A1B2C3D4E5F6.locky)
 *   - High-entropy file writes (RSA-2048 + AES-128 encrypted content)
 *   - VSS/shadow copy destruction (vssadmin, wmic, bcdedit)
 *   - Ransom note creation across multiple directories
 *   - Wallpaper registry modification
 *   - DGA domain generation and DNS query correlation
 *   - GUID-format mutex creation
 *   - Dropper behavior chain (temp exe + PowerShell download)
 *   - Registry persistence (HKCU Run key, Software\Locky)
 *   - Process memory pattern scanning
 *   - Known-bad SHA-256 hash matching
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "LockyDetector.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../PatternStore/PatternStore.hpp"

// Cross-module wiring
#include "../Communication/AlertSystem.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/IPCManager.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <format>
#include <map>
#include <nlohmann/json.hpp>
#include <ctime>

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// LOG CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CAT = L"LockyDetector";

// ============================================================================
// ANONYMOUS HELPER NAMESPACE
// ============================================================================
namespace {

    // RAII wrapper for registry key handles
    struct RegKeyGuard {
        HKEY key = nullptr;
        RegKeyGuard() = default;
        explicit RegKeyGuard(HKEY k) noexcept : key(k) {}
        ~RegKeyGuard() { if (key) RegCloseKey(key); }
        RegKeyGuard(const RegKeyGuard&) = delete;
        RegKeyGuard& operator=(const RegKeyGuard&) = delete;
        explicit operator bool() const noexcept { return key != nullptr; }
    };

    // Unique event ID generator
    [[nodiscard]] uint64_t GenerateEventId() noexcept {
        static std::atomic<uint64_t> s_counter{0};
        const auto now = static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
        return now ^ s_counter.fetch_add(1, std::memory_order_relaxed);
    }

    // Rotate Right 32-bit
    [[nodiscard]] constexpr uint32_t ROR32(uint32_t x, uint32_t n) noexcept {
        n &= 31;
        return (x >> n) | (x << (32 - n));
    }

    // Rotate Left 32-bit
    [[nodiscard]] constexpr uint32_t ROL32(uint32_t x, uint32_t n) noexcept {
        n &= 31;
        return (x << n) | (x >> (32 - n));
    }

    /**
     * @brief Generates Locky C2 domains for a specific date and seed.
     *
     * Adapted from reverse-engineered Locky DGA algorithm. The domain set
     * changes every 2 days based on the date components and affiliate seed.
     */
    [[nodiscard]] std::vector<std::string> GenerateLockyDomains(
        int year, int month, int day, uint32_t seed)
    {
        std::vector<std::string> domains;
        domains.reserve(12);

        static constexpr const char* tlds[] = {
            "ru", "biz", "info", "org", "net", "top",
            "click", "pl", "in", "us", "eu", "work"
        };
        static constexpr size_t tldCount = std::size(tlds);

        const uint32_t time_const =
            static_cast<uint32_t>(year * 366 + month * 31 + day) / 2u;

        for (int i = 0; i < 12; ++i) {
            uint32_t key = ROL32(seed, static_cast<uint32_t>(i) % 32u);

            key ^= time_const;
            key = ROR32(key, 7);
            key += time_const;
            key ^= static_cast<uint32_t>(i);
            key = ROL32(key, 13);

            const int length = static_cast<int>(key % 12u) + 7;

            std::string domain;
            domain.reserve(static_cast<size_t>(length) + 8);

            for (int k = 0; k < length; ++k) {
                key = (key * 1664525u + 1013904223u);
                domain += static_cast<char>('a' + (key % 26u));
            }

            domain += '.';
            domain += tlds[static_cast<size_t>(i) % tldCount];
            domains.push_back(std::move(domain));
        }

        return domains;
    }

    // Check if a filename matches Locky hex-ID pattern: [hex]{16,32}.[ext]
    [[nodiscard]] bool IsHexIdFilename(std::wstring_view stem) noexcept {
        if (stem.size() < 16 || stem.size() > 32) return false;
        return std::all_of(stem.begin(), stem.end(), [](wchar_t c) {
            return (c >= L'0' && c <= L'9') ||
                   (c >= L'a' && c <= L'f') ||
                   (c >= L'A' && c <= L'F');
        });
    }

    // Check if a mutex name is GUID format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    [[nodiscard]] bool IsGuidFormat(std::wstring_view name) noexcept {
        // Minimum: {8-4-4-4-12} = 38 chars
        if (name.size() < 38) return false;
        if (name.front() != L'{' || name.back() != L'}') return false;
        // Check dash positions: 9, 14, 19, 24
        if (name[9] != L'-' || name[14] != L'-' ||
            name[19] != L'-' || name[24] != L'-')
            return false;

        for (size_t i = 1; i < name.size() - 1; ++i) {
            if (i == 9 || i == 14 || i == 19 || i == 24) continue;
            const wchar_t c = name[i];
            if (!((c >= L'0' && c <= L'9') ||
                  (c >= L'a' && c <= L'f') ||
                  (c >= L'A' && c <= L'F')))
                return false;
        }
        return true;
    }

    // Extract file extension (lowercase) from path
    [[nodiscard]] std::wstring ExtractExtension(std::wstring_view path) noexcept {
        const auto dotPos = path.rfind(L'.');
        if (dotPos == std::wstring_view::npos || dotPos == 0)
            return {};
        std::wstring ext(path.substr(dotPos));
        for (auto& c : ext) {
            if (c >= L'A' && c <= L'Z') c += 32;
        }
        return ext;
    }

    // Extract filename (without directory) from path
    [[nodiscard]] std::wstring_view ExtractFilename(std::wstring_view path) noexcept {
        const auto slashPos = path.find_last_of(L"\\/");
        return (slashPos != std::wstring_view::npos)
            ? path.substr(slashPos + 1) : path;
    }

    // Extract file stem (filename without extension)
    [[nodiscard]] std::wstring_view ExtractStem(std::wstring_view filename) noexcept {
        const auto dotPos = filename.rfind(L'.');
        return (dotPos != std::wstring_view::npos)
            ? filename.substr(0, dotPos) : filename;
    }

    // Extract directory path
    [[nodiscard]] std::wstring ExtractDirectory(std::wstring_view path) noexcept {
        const auto slashPos = path.find_last_of(L"\\/");
        if (slashPos == std::wstring_view::npos) return {};
        std::wstring dir(path.substr(0, slashPos));
        for (auto& c : dir) {
            if (c >= L'A' && c <= L'Z') c += 32;
        }
        return dir;
    }

    // Check if command line contains VSS destruction patterns
    [[nodiscard]] bool ContainsVSSDestructionPattern(std::wstring_view cmdLower) noexcept {
        if (cmdLower.find(L"vssadmin") != std::wstring_view::npos &&
            cmdLower.find(L"delete") != std::wstring_view::npos &&
            cmdLower.find(L"shadows") != std::wstring_view::npos)
            return true;

        if (cmdLower.find(L"wmic") != std::wstring_view::npos &&
            cmdLower.find(L"shadowcopy") != std::wstring_view::npos &&
            cmdLower.find(L"delete") != std::wstring_view::npos)
            return true;

        if (cmdLower.find(L"bcdedit") != std::wstring_view::npos &&
            cmdLower.find(L"recoveryenabled") != std::wstring_view::npos &&
            cmdLower.find(L"no") != std::wstring_view::npos)
            return true;

        return false;
    }

} // anonymous namespace

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

std::string LockyDetectionResult::ToJson() const {
    nlohmann::json j;
    j["detected"]    = detected;
    j["variant"]     = GetLockyVariantName(variant);
    j["confidence"]  = GetDetectionConfidenceName(confidence);
    j["pid"]         = pid;
    j["processName"] = Utils::StringUtils::ToNarrow(processName);
    j["indicators"]  = indicators;
    j["score"]       = score;

    std::vector<std::string> extStr;
    extStr.reserve(extensionsObserved.size());
    for (const auto& ext : extensionsObserved) {
        extStr.push_back(Utils::StringUtils::ToNarrow(ext));
    }
    j["extensionsObserved"] = extStr;

    std::vector<std::string> noteStr;
    noteStr.reserve(ransomNotesFound.size());
    for (const auto& note : ransomNotesFound) {
        noteStr.push_back(Utils::StringUtils::ToNarrow(note));
    }
    j["ransomNotesFound"] = noteStr;

    j["c2Domains"]      = c2Domains;
    j["filesEncrypted"]  = filesEncrypted;
    j["detectionTime"]   = std::chrono::system_clock::to_time_t(detectionTime);

    return j.dump();
}

bool LockyDetectorConfiguration::IsValid() const noexcept {
    if (correlationWindowSecs == 0 || correlationWindowSecs > 3600) return false;
    if (massRenameThreshold == 0)  return false;
    if (massWriteThreshold == 0)   return false;
    if (scoreAlertThreshold <= 0.0 || scoreAlertThreshold > 200.0) return false;
    if (scoreBlockThreshold < scoreAlertThreshold) return false;
    return true;
}

void LockyStatistics::Reset() noexcept {
    totalDetections.store(0, std::memory_order_relaxed);
    processesTerminated.store(0, std::memory_order_relaxed);
    for (auto& counter : byVariant) {
        counter.store(0, std::memory_order_relaxed);
    }
    startTime = Clock::now();
}

std::string LockyStatistics::ToJson() const {
    nlohmann::json j;
    j["totalDetections"]    = totalDetections.load(std::memory_order_relaxed);
    j["processesTerminated"] = processesTerminated.load(std::memory_order_relaxed);

    nlohmann::json variants = nlohmann::json::object();
    for (size_t i = 0; i <= static_cast<size_t>(LockyVariant::Ykcol); ++i) {
        const auto count = byVariant[i].load(std::memory_order_relaxed);
        if (count > 0) {
            variants[std::string(GetLockyVariantName(static_cast<LockyVariant>(i)))] = count;
        }
    }
    j["byVariant"] = variants;

    const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    j["uptimeSeconds"] = uptime;

    return j.dump();
}

// ============================================================================
// PER-PROCESS BEHAVIORAL STATE
// ============================================================================

struct ProcessBehavior {
    uint32_t pid = 0;
    std::wstring processName;
    std::wstring processPath;
    TimePoint firstSeen{};
    TimePoint lastActivity{};

    // Behavioral counters
    uint32_t totalRenames       = 0;
    uint32_t lockyExtRenames    = 0;
    uint32_t hexPatternRenames  = 0;
    uint32_t totalWrites        = 0;
    uint32_t highEntropyWrites  = 0;
    uint32_t ransomNotesCreated = 0;
    uint32_t dgaDomainsContacted = 0;

    // Directories affected
    std::unordered_set<std::wstring> affectedDirectories;
    std::unordered_set<std::wstring> ransomNoteDirectories;

    // Boolean indicators (each can fire score only once)
    bool vssDestruction       = false;
    bool registryPersistence  = false;
    bool wallpaperModified    = false;
    bool guidMutex            = false;
    bool dropperBehavior      = false;
    bool memoryPatterns       = false;
    bool knownHash            = false;
    bool massRenameTriggered  = false;
    bool multiDirTriggered    = false;
    bool hexPatternScored     = false;

    // Rate tracking
    std::vector<TimePoint> renameTimestamps;

    // Accumulated score and detected variant
    double score = 0.0;
    LockyVariant variant = LockyVariant::Unknown;
    std::vector<std::string> indicators;
    std::vector<std::wstring> extensionsObserved;
    std::vector<std::wstring> ransomNotesFound;
    std::vector<std::string>  c2Domains;

    mutable std::mutex mtx;

    void PruneTimestamps(std::chrono::seconds window) {
        const auto cutoff = Clock::now() - window;
        std::erase_if(renameTimestamps, [&](const TimePoint& tp) {
            return tp < cutoff;
        });
    }
};

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

class LockyDetector::LockyDetectorImpl {
public:
    // ====================================================================
    // STATE
    // ====================================================================
    mutable std::shared_mutex m_mutex;
    LockyDetectorConfiguration m_config;
    std::atomic<ModuleStatus>  m_status{ModuleStatus::Uninitialized};
    std::atomic<bool>          m_initialized{false};
    LockyStatistics            m_stats;

    // ====================================================================
    // PATTERN DATABASES
    // ====================================================================
    std::unordered_set<std::wstring> m_knownExtensions;
    std::unordered_set<std::string>  m_generatedDGADomains;
    std::unordered_set<std::string>  m_staticC2Domains;
    std::unordered_set<std::string>  m_knownC2Domains;
    std::unordered_set<std::string>  m_knownBadHashes;
    mutable std::shared_mutex        m_patternsMutex;

    // ====================================================================
    // PER-PROCESS BEHAVIORAL STATE
    // ====================================================================
    std::unordered_map<uint32_t, std::shared_ptr<ProcessBehavior>> m_processBehaviors;
    mutable std::shared_mutex m_behaviorMutex;

    // ====================================================================
    // CALLBACK
    // ====================================================================
    LockyDetectionCallback m_callback;
    std::mutex             m_callbackMutex;

    // ====================================================================
    // CONSTRUCTOR
    // ====================================================================
    LockyDetectorImpl() {
        InitializePatterns();
    }

    // ====================================================================
    // PATTERN INITIALIZATION
    // ====================================================================
    void InitializePatterns() {
        std::unique_lock lock(m_patternsMutex);

        for (const auto* ext : LockyConstants::LOCKY_EXTENSIONS) {
            m_knownExtensions.emplace(ext);
        }

        // Historic C2 domains (sinkholed, used for correlation only)
        m_staticC2Domains.insert("greesxnmo6s.top");
        m_staticC2Domains.insert("qwe123sd.ru");
        m_staticC2Domains.insert("knyete.com");

        UpdateDGADomainsLocked();
    }

    void UpdateDGADomainsLocked() {
        static constexpr uint32_t seeds[] = {1, 3, 5, 7, 12, 17};

        // Compute today as a sys_days so that arithmetic correctly rolls over
        // month and year boundaries. The previous implementation passed
        // day+offset directly (e.g. day=32 on Dec 31), producing an invalid
        // calendar date that Locky's real DGA never generates — opening a
        // detection gap at every month boundary.
        const auto today = std::chrono::floor<std::chrono::days>(
            std::chrono::system_clock::now());

        m_generatedDGADomains.clear();

        // Generate for today and tomorrow (+1 day rollover coverage)
        for (int dayOffset = 0; dayOffset <= 1; ++dayOffset) {
            const std::chrono::year_month_day ymd{
                today + std::chrono::days{dayOffset}};
            const int year  = static_cast<int>(ymd.year());
            const int month = static_cast<int>(static_cast<unsigned>(ymd.month()));
            const int d     = static_cast<int>(static_cast<unsigned>(ymd.day()));

            for (const uint32_t seed : seeds) {
                auto domains = GenerateLockyDomains(year, month, d, seed);
                for (auto& domain : domains) {
                    m_generatedDGADomains.insert(std::move(domain));
                }
            }
        }

        SS_LOG_INFO(LOG_CAT, L"Generated %zu DGA domains for today+tomorrow",
                    m_generatedDGADomains.size());
    }

    // ====================================================================
    // LIFECYCLE
    // ====================================================================
    bool Initialize(const LockyDetectorConfiguration& config) {
        if (m_initialized.exchange(true, std::memory_order_acq_rel)) {
            return true;
        }

        std::unique_lock lock(m_mutex);
        m_config = config;

        if (!m_config.IsValid()) {
            SS_LOG_ERROR(LOG_CAT,
                L"Invalid configuration: windowSecs=%u renameThresh=%u "
                L"alertThresh=%.1f blockThresh=%.1f",
                m_config.correlationWindowSecs,
                m_config.massRenameThreshold,
                m_config.scoreAlertThreshold,
                m_config.scoreBlockThreshold);
            m_initialized.store(false, std::memory_order_release);
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        m_status.store(ModuleStatus::Running, std::memory_order_release);
        SS_LOG_INFO(LOG_CAT, L"Initialized v%u.%u.%u (correlation=%us, "
            L"renameThresh=%u, alertScore=%.0f, blockScore=%.0f)",
            LockyConstants::VERSION_MAJOR,
            LockyConstants::VERSION_MINOR,
            LockyConstants::VERSION_PATCH,
            m_config.correlationWindowSecs,
            m_config.massRenameThreshold,
            m_config.scoreAlertThreshold,
            m_config.scoreBlockThreshold);
        return true;
    }

    void Shutdown() {
        m_status.store(ModuleStatus::Stopping, std::memory_order_release);
        m_initialized.store(false, std::memory_order_release);

        {
            std::unique_lock lock(m_behaviorMutex);
            m_processBehaviors.clear();
        }

        m_status.store(ModuleStatus::Stopped, std::memory_order_release);
        SS_LOG_INFO(LOG_CAT, L"Shutdown complete");
    }

    // ====================================================================
    // PER-PROCESS STATE ACCESS
    // ====================================================================
    [[nodiscard]] std::shared_ptr<ProcessBehavior> GetOrCreateBehavior(uint32_t pid) {
        {
            std::shared_lock lock(m_behaviorMutex);
            auto it = m_processBehaviors.find(pid);
            if (it != m_processBehaviors.end()) return it->second;
        }

        std::unique_lock lock(m_behaviorMutex);

        // Double-check after acquiring exclusive lock
        if (auto it = m_processBehaviors.find(pid); it != m_processBehaviors.end()) {
            return it->second;
        }

        // Enforce cap BEFORE insertion so the purge below can never erase the
        // entry we are about to construct (which previously caused a UAF where
        // a reference to a default-inserted node was invalidated when purge
        // removed it because its zero-initialized lastActivity timestamp
        // already qualified as "stale").
        if (m_processBehaviors.size() >= LockyConstants::MAX_TRACKED_PROCESSES) {
            PurgeStaleProcessesLocked();
        }

        auto behavior = std::make_shared<ProcessBehavior>();

        // Initialize under the per-entry mutex before the entry becomes visible
        // to other threads via the map. This prevents readers from observing a
        // partially-constructed ProcessBehavior.
        {
            std::lock_guard pbLock(behavior->mtx);
            behavior->pid = pid;
            behavior->firstSeen = Clock::now();
            behavior->lastActivity = behavior->firstSeen;

            // Resolve process name (best-effort)
            auto pathOpt = Utils::ProcessUtils::GetProcessPath(pid);
            if (pathOpt) {
                behavior->processPath = *pathOpt;
                behavior->processName = std::wstring(
                    ExtractFilename(*pathOpt));
            }
        }

        auto [it, inserted] = m_processBehaviors.emplace(pid, std::move(behavior));
        return it->second;
    }

    [[nodiscard]] std::shared_ptr<ProcessBehavior> FindBehavior(uint32_t pid) const {
        std::shared_lock lock(m_behaviorMutex);
        auto it = m_processBehaviors.find(pid);
        return (it != m_processBehaviors.end()) ? it->second : nullptr;
    }

    void PurgeStaleProcessesLocked() {
        const auto cutoff = Clock::now() -
            std::chrono::seconds(LockyConstants::STALE_PROCESS_AGE_SECS);
        std::erase_if(m_processBehaviors, [&](const auto& pair) {
            return pair.second->lastActivity < cutoff;
        });
    }

    void PurgeProcessState(uint32_t pid) {
        // Must use m_behaviorMutex (guards m_processBehaviors), NOT m_mutex
        // which guards configuration. Previously this used the wrong mutex,
        // creating a data race with GetOrCreateBehavior / FindBehavior /
        // PurgeStaleProcessesLocked.
        std::unique_lock lock(m_behaviorMutex);
        m_processBehaviors.erase(pid);
    }

    // ====================================================================
    // WHITELISTING
    // ====================================================================
    [[nodiscard]] bool IsWhitelisted(std::wstring_view processName) const {
        std::shared_lock lock(m_mutex);
        for (const auto& wl : m_config.whitelistedProcesses) {
            if (Utils::StringUtils::IEquals(processName, wl)) return true;
        }
        return false;
    }

    // ====================================================================
    // CONFIDENCE CALCULATION FROM SCORE
    // ====================================================================
    [[nodiscard]] static DetectionConfidence ScoreToConfidence(double score) noexcept {
        if (score >= LockyConstants::CONFIDENCE_CONFIRMED_THRESHOLD)
            return DetectionConfidence::Confirmed;
        if (score >= LockyConstants::CONFIDENCE_HIGH_THRESHOLD)
            return DetectionConfidence::High;
        if (score >= LockyConstants::CONFIDENCE_MEDIUM_THRESHOLD)
            return DetectionConfidence::Medium;
        if (score >= LockyConstants::CONFIDENCE_LOW_THRESHOLD)
            return DetectionConfidence::Low;
        return DetectionConfidence::None;
    }

    // ====================================================================
    // ADD SCORE (with deduplication for boolean indicators)
    // ====================================================================
    void AddScore(ProcessBehavior& pb, double points,
                  const char* indicator, bool& flag)
    {
        if (flag) return; // Already scored
        flag = true;
        pb.score += points;
        pb.indicators.push_back(indicator);
    }

    void AddScoreUnguarded(ProcessBehavior& pb, double points,
                           const char* indicator)
    {
        pb.score += points;
        pb.indicators.push_back(indicator);
    }

    // ====================================================================
    // BUILD DETECTION RESULT FROM BEHAVIORAL STATE
    // ====================================================================
    [[nodiscard]] LockyDetectionResult BuildResult(const ProcessBehavior& pb) const {
        LockyDetectionResult result;
        result.detected           = (pb.score >= m_config.scoreAlertThreshold);
        result.variant            = pb.variant;
        result.confidence         = ScoreToConfidence(pb.score);
        result.pid                = pb.pid;
        result.processName        = pb.processName;
        result.indicators         = pb.indicators;
        result.extensionsObserved = pb.extensionsObserved;
        result.ransomNotesFound   = pb.ransomNotesFound;
        result.c2Domains          = pb.c2Domains;
        result.score              = pb.score;
        result.detectionTime      = std::chrono::system_clock::now();
        return result;
    }

    // ====================================================================
    // FIRE CALLBACK + UPDATE STATS + AUTO-TERMINATE
    // ====================================================================
    void HandleDetection(ProcessBehavior& pb, LockyDetectionResult& result) {
        m_stats.totalDetections.fetch_add(1, std::memory_order_relaxed);

        const auto varIdx = static_cast<size_t>(result.variant);
        if (varIdx < m_stats.byVariant.size()) {
            m_stats.byVariant[varIdx].fetch_add(1, std::memory_order_relaxed);
        }

        // Fire callback
        {
            std::lock_guard cbLock(m_callbackMutex);
            if (m_callback) {
                m_callback(result);
            }
        }

        // Auto-terminate if score exceeds block threshold
        if (m_config.autoTerminate &&
            pb.score >= m_config.scoreBlockThreshold)
        {
            Utils::ProcessUtils::Error termErr{};
            if (Utils::ProcessUtils::TerminateProcessTree(
                    pb.pid, 1, &termErr))
            {
                m_stats.processesTerminated.fetch_add(1, std::memory_order_relaxed);
                result.indicators.push_back("Process tree terminated");
                SS_LOG_FATAL(LOG_CAT,
                    L"LOCKY KILL: Terminated PID %u (%ls) score=%.0f variant=%hs",
                    pb.pid, pb.processName.c_str(), pb.score,
                    GetLockyVariantName(pb.variant).data());
            } else {
                SS_LOG_ERROR(LOG_CAT,
                    L"Failed to terminate PID %u: continuing with block",
                    pb.pid);
            }
        }

        SS_LOG_WARN(LOG_CAT,
            L"LOCKY DETECTED: PID=%u name=%ls score=%.0f confidence=%hs "
            L"variant=%hs indicators=%zu",
            result.pid, result.processName.c_str(), result.score,
            GetDetectionConfidenceName(result.confidence).data(),
            GetLockyVariantName(result.variant).data(),
            result.indicators.size());

        // =================================================================
        // CROSS-MODULE WIRING — AlertSystem + TelemetryCollector + kernel IPC
        // =================================================================
        const auto narrow = Utils::StringUtils::ToNarrow(result.processName);
        const auto variantStr = std::string(GetLockyVariantName(result.variant));
        const auto confStr = std::string(GetDetectionConfidenceName(result.confidence));

        if (Communication::AlertSystem::HasInstance()) {
            const auto severity = (result.score >= m_config.scoreBlockThreshold)
                ? Communication::AlertSeverity::Critical
                : Communication::AlertSeverity::High;
            (void)Communication::AlertSystem::Instance().RaiseAlert(
                severity,
                Communication::AlertType::ThreatDetection,
                "LockyDetector",
                std::format("Locky ransomware detected — PID {} ({}) variant={} score={:.0f}",
                    result.pid, narrow, variantStr, result.score),
                std::format("confidence={} indicators={}", confStr, result.indicators.size()));
        }

        if (Communication::TelemetryCollector::HasInstance()) {
            Communication::TelemetryCollector::Instance().RecordCustom(
                "locky_detection",
                {
                    {"pid",         std::to_string(result.pid)},
                    {"process",     narrow},
                    {"variant",     variantStr},
                    {"confidence",  confStr},
                    {"score",       std::format("{:.0f}", result.score)},
                    {"indicators",  std::to_string(result.indicators.size())},
                    {"terminated",  (m_config.autoTerminate &&
                                     pb.score >= m_config.scoreBlockThreshold) ? "true" : "false"}
                });
        }

        if (Communication::IPCManager::HasInstance() &&
            Communication::IPCManager::Instance().IsFilterPortConnected())
        {
            #pragma pack(push, 1)
            struct KernelLockyMsg {
                uint32_t msgType  = 0x31;   // Locky-specific
                uint32_t pid      = 0;
                double   score    = 0.0;
                uint8_t  variant  = 0;
            } msg;
            #pragma pack(pop)
            msg.pid     = pb.pid;
            msg.score   = pb.score;
            msg.variant = static_cast<uint8_t>(pb.variant);
            (void)Communication::IPCManager::Instance().SendToKernel(&msg, sizeof(msg));
        }
    }

    // ====================================================================
    // EVALUATE: check if behavioral state warrants detection
    // Returns populated result if score >= alert threshold
    // ====================================================================
    [[nodiscard]] std::optional<LockyDetectionResult> Evaluate(
        ProcessBehavior& pb)
    {
        pb.lastActivity = Clock::now();
        const auto conf = ScoreToConfidence(pb.score);

        if (pb.score < m_config.scoreAlertThreshold) {
            return std::nullopt;
        }

        auto result = BuildResult(pb);
        HandleDetection(pb, result);
        return result;
    }

    // ====================================================================
    // POINT-IN-TIME DETECTION (Detect / DetectEx)
    // ====================================================================
    [[nodiscard]] LockyDetectionResult DetectEx(uint32_t pid) {
        auto pb = GetOrCreateBehavior(pid);
        if (!pb) return {};

        std::lock_guard pbLock(pb->mtx);

        // Skip whitelisted
        if (IsWhitelisted(pb->processName)) {
            return BuildResult(*pb);
        }

        // 1. Hash check
        CheckProcessHash(*pb);

        // 2. Registry persistence
        CheckRegistryPersistence(*pb);

        // 3. VSS destruction (self + children)
        CheckVSSDestruction(*pb);

        // 4. Process memory scan
        ScanProcessMemory(*pb);

        // Build result (may or may not trigger alert)
        auto result = BuildResult(*pb);
        if (result.detected) {
            HandleDetection(*pb, result);
        }
        return result;
    }

    // ====================================================================
    // STATIC HASH CHECK
    // ====================================================================
    void CheckProcessHash(ProcessBehavior& pb) {
        if (pb.knownHash) return;
        if (pb.processPath.empty()) return;

        std::vector<uint8_t> hashBytes;
        Utils::HashUtils::Error hashErr{};
        if (!Utils::HashUtils::ComputeFile(
                Utils::HashUtils::Algorithm::SHA256,
                pb.processPath, hashBytes, &hashErr))
        {
            return;
        }

        const std::string hexHash = Utils::HashUtils::ToHexLower(
            hashBytes.data(), hashBytes.size());

        std::shared_lock lock(m_patternsMutex);
        if (m_knownBadHashes.contains(hexHash)) {
            AddScore(pb, LockyConstants::SCORE_KNOWN_HASH,
                     "Known Locky SHA-256 hash match", pb.knownHash);
        }
    }

    // ====================================================================
    // REGISTRY PERSISTENCE CHECK (RAII, no stack overflow)
    // ====================================================================
    void CheckRegistryPersistence(ProcessBehavior& pb) {
        if (pb.registryPersistence) return;

#ifdef _WIN32
        // Check 1: HKCU\Software\Locky
        {
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Locky",
                              0, KEY_READ, &hKey) == ERROR_SUCCESS)
            {
                RegKeyGuard guard(hKey);
                AddScore(pb, LockyConstants::SCORE_REGISTRY_PERSISTENCE,
                         "Locky registry key (HKCU\\Software\\Locky)",
                         pb.registryPersistence);
                return;
            }
        }

        // Check 2: Run key pointing to suspicious process
        {
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER,
                    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    0, KEY_READ, &hKey) != ERROR_SUCCESS)
                return;

            RegKeyGuard guard(hKey);

            const std::wstring procPathLower =
                Utils::StringUtils::ToLowerCopy(pb.processPath);
            if (procPathLower.empty()) return;

            constexpr DWORD kBufSize = 1024;
            wchar_t valueName[kBufSize]{};
            wchar_t data[kBufSize]{};
            DWORD index = 0;

            for (;;) {
                DWORD nameSize = kBufSize;
                DWORD dataSize = kBufSize * sizeof(wchar_t);
                DWORD type = 0;

                const LONG rc = RegEnumValueW(
                    hKey, index++, valueName, &nameSize,
                    nullptr, &type, reinterpret_cast<LPBYTE>(data), &dataSize);

                if (rc != ERROR_SUCCESS) break;
                if (type != REG_SZ) continue;
                if (dataSize == 0 || dataSize > sizeof(data)) continue;
                // Ensure dataSize is aligned to wchar_t boundary
                dataSize &= ~static_cast<DWORD>(sizeof(wchar_t) - 1);
                if (dataSize == 0) continue;

                const std::wstring entryLower =
                    Utils::StringUtils::ToLowerCopy(
                        std::wstring_view(data, dataSize / sizeof(wchar_t)));

                if (entryLower.find(procPathLower) == std::wstring::npos)
                    continue;

                // Run value points to our suspicious process — flag it
                AddScore(pb, LockyConstants::SCORE_REGISTRY_PERSISTENCE,
                         "Run key persistence for suspicious process",
                         pb.registryPersistence);
                return;
            }
        }
#endif
    }

    // ====================================================================
    // VSS DESTRUCTION CHECK (self + child processes)
    // ====================================================================
    void CheckVSSDestruction(ProcessBehavior& pb) {
        if (pb.vssDestruction) return;

        // Check the process itself
        auto cmdOpt = Utils::ProcessUtils::GetProcessCommandLine(pb.pid);
        if (cmdOpt) {
            const std::wstring cmdLower =
                Utils::StringUtils::ToLowerCopy(*cmdOpt);
            if (ContainsVSSDestructionPattern(cmdLower)) {
                AddScore(pb, LockyConstants::SCORE_VSS_DESTRUCTION,
                         "VSS destruction command in process cmdline",
                         pb.vssDestruction);
                return;
            }
        }

        // Check child processes
        std::vector<DWORD> children;
        Utils::ProcessUtils::Error childErr{};
        if (Utils::ProcessUtils::GetChildProcesses(
                static_cast<DWORD>(pb.pid), children, &childErr))
        {
            for (const uint32_t childPid : children) {
                auto childCmd = Utils::ProcessUtils::GetProcessCommandLine(childPid);
                if (!childCmd) continue;

                const std::wstring childLower =
                    Utils::StringUtils::ToLowerCopy(*childCmd);
                if (ContainsVSSDestructionPattern(childLower)) {
                    AddScore(pb, LockyConstants::SCORE_VSS_DESTRUCTION,
                             "VSS destruction in child process",
                             pb.vssDestruction);
                    return;
                }
            }
        }
    }

    // ====================================================================
    // PROCESS MEMORY PATTERN SCAN
    // ====================================================================
    void ScanProcessMemory(ProcessBehavior& pb) {
        if (pb.memoryPatterns) return;

        static constexpr uint8_t kLockyAscii[]  = {'L','o','c','k','y'};
        static constexpr uint8_t kRansomNote[]   = {'_','L','o','c','k','y','_',
                                                     'r','e','c','o','v','e','r'};
        static constexpr uint8_t kPubKeyBlob[]   = {0x06, 0x02, 0x00, 0x00,
                                                     0x00, 0xA4, 0x00, 0x00};

        constexpr SIZE_T kMaxScan = 4 * 1024 * 1024;
        std::vector<uint8_t> buffer;
        buffer.resize(kMaxScan);

        SYSTEM_INFO sysInfo{};
        GetSystemInfo(&sysInfo);

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pb.pid);
        if (!hProcess) return;

        // RAII guard for the process handle
        struct HandleGuard {
            HANDLE h;
            ~HandleGuard() { if (h) CloseHandle(h); }
        } handleGuard{hProcess};

        auto* addr = static_cast<uint8_t*>(sysInfo.lpMinimumApplicationAddress);
        auto* maxAddr = static_cast<uint8_t*>(sysInfo.lpMaximumApplicationAddress);

        SIZE_T totalScanned = 0;
        constexpr SIZE_T kScanLimit = 32 * 1024 * 1024;

        while (addr < maxAddr && totalScanned < kScanLimit) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == 0)
                break;

            if (mbi.RegionSize == 0) break;

            // Overflow-safe pointer advance check
            if (static_cast<SIZE_T>(maxAddr - addr) < mbi.RegionSize) break;

            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY |
                                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
            {
                const SIZE_T readSize = (std::min)(
                    static_cast<SIZE_T>(mbi.RegionSize), kMaxScan);

                SIZE_T bytesRead = 0;
                if (::ReadProcessMemory(hProcess, mbi.BaseAddress,
                        buffer.data(), readSize, &bytesRead) && bytesRead > 0)
                {
                    totalScanned += bytesRead;
                    const auto* data = buffer.data();

                    auto contains = [&](const uint8_t* pattern, size_t pLen) -> bool {
                        if (bytesRead < pLen) return false;
                        return std::search(data, data + bytesRead,
                                          pattern, pattern + pLen) !=
                               (data + bytesRead);
                    };

                    if (contains(kLockyAscii, sizeof(kLockyAscii)) &&
                        contains(kRansomNote, sizeof(kRansomNote)))
                    {
                        AddScore(pb, LockyConstants::SCORE_MEMORY_PATTERN,
                                 "Locky string patterns in process memory",
                                 pb.memoryPatterns);
                        return;
                    }

                    if (contains(kPubKeyBlob, sizeof(kPubKeyBlob))) {
                        AddScore(pb, LockyConstants::SCORE_MEMORY_PATTERN,
                                 "RSA PUBLICKEYBLOB in process memory",
                                 pb.memoryPatterns);
                        return;
                    }
                }
            }

            addr += mbi.RegionSize;
        }
    }

    // ====================================================================
    // PATTERN MATCHING HELPERS
    // ====================================================================
    [[nodiscard]] bool IsLockyExtension(std::wstring_view extension) const {
        std::shared_lock lock(m_patternsMutex);
        const std::wstring lowerExt = ExtractExtension(extension);
        if (lowerExt.empty()) {
            // Extension was already just the extension (e.g. ".locky")
            std::wstring lower(extension);
            for (auto& c : lower) {
                if (c >= L'A' && c <= L'Z') c += 32;
            }
            return m_knownExtensions.contains(lower);
        }
        return m_knownExtensions.contains(lowerExt);
    }

    [[nodiscard]] LockyVariant IdentifyVariant(std::wstring_view extension) const {
        std::wstring ext(extension);
        for (auto& c : ext) {
            if (c >= L'A' && c <= L'Z') c += 32;
        }

        if (ext == L".locky")   return LockyVariant::Original;
        if (ext == L".zepto")   return LockyVariant::Zepto;
        if (ext == L".odin")    return LockyVariant::Odin;
        if (ext == L".thor")    return LockyVariant::Thor;
        if (ext == L".aesir")   return LockyVariant::Aesir;
        if (ext == L".zzzzz")   return LockyVariant::Zzzzz;
        if (ext == L".osiris")  return LockyVariant::Osiris;
        if (ext == L".diablo6") return LockyVariant::Diablo6;
        if (ext == L".lukitus") return LockyVariant::Lukitus;
        if (ext == L".ykcol")   return LockyVariant::Ykcol;

        return LockyVariant::Unknown;
    }

    [[nodiscard]] bool IsLockyRansomNote(std::wstring_view filename) const {
        for (const auto* pattern : LockyConstants::RANSOM_NOTE_PATTERNS) {
            if (Utils::StringUtils::IEquals(filename, pattern)) return true;
        }
        // Partial matches for variant-specific notes
        if (Utils::StringUtils::IContains(filename, L"_recover_instructions"))
            return true;
        if (Utils::StringUtils::IContains(filename, L"_HOWDO_text"))
            return true;
        if (Utils::StringUtils::IContains(filename, L"_HELP_instructions"))
            return true;
        if (Utils::StringUtils::IContains(filename, L"_README_"))
            return true;
        return false;
    }

    [[nodiscard]] bool IsLockyC2Domain(std::string_view domain) const {
        std::shared_lock lock(m_patternsMutex);
        std::string d(domain);
        for (auto& c : d) {
            if (c >= 'A' && c <= 'Z') c += 32;
        }

        if (m_knownC2Domains.contains(d))     return true;
        if (m_staticC2Domains.contains(d))     return true;
        if (m_generatedDGADomains.contains(d)) return true;

        return false;
    }

    [[nodiscard]] bool AnalyzeEncryptedFile(std::wstring_view filePath) {
        if (!Utils::FileUtils::Exists(filePath)) return false;

        // Read first 4KB for entropy analysis
        std::vector<std::byte> fileData;
        Utils::FileUtils::Error fileErr{};
        if (!Utils::FileUtils::ReadAllBytes(filePath, fileData, &fileErr))
            return false;

        if (fileData.size() < 256) return false;

        // Calculate Shannon entropy of the first 4KB
        const size_t sampleSize = (std::min)(fileData.size(),
                                             static_cast<size_t>(4096));
        std::array<uint32_t, 256> freq{};
        for (size_t i = 0; i < sampleSize; ++i) {
            freq[static_cast<uint8_t>(fileData[i])]++;
        }

        double entropy = 0.0;
        const double total = static_cast<double>(sampleSize);
        for (const auto& f : freq) {
            if (f == 0) continue;
            const double p = static_cast<double>(f) / total;
            entropy -= p * std::log2(p);
        }

        return entropy > LockyConstants::HIGH_ENTROPY_THRESHOLD;
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> LockyDetector::s_instanceCreated{false};

LockyDetector& LockyDetector::Instance() noexcept {
    static LockyDetector instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool LockyDetector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

LockyDetector::LockyDetector()
    : m_impl(std::make_unique<LockyDetectorImpl>())
{
    SS_LOG_DEBUG(LOG_CAT, L"LockyDetector constructed");
}

LockyDetector::~LockyDetector() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool LockyDetector::Initialize(const LockyDetectorConfiguration& config) {
    return m_impl ? m_impl->Initialize(config) : false;
}

void LockyDetector::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool LockyDetector::IsInitialized() const noexcept {
    return m_impl ? m_impl->m_initialized.load(std::memory_order_acquire) : false;
}

ModuleStatus LockyDetector::GetStatus() const noexcept {
    return m_impl ? m_impl->m_status.load(std::memory_order_acquire)
                  : ModuleStatus::Uninitialized;
}

// ============================================================================
// POINT-IN-TIME DETECTION
// ============================================================================

bool LockyDetector::Detect(uint32_t pid) {
    if (!m_impl) return false;
    auto result = m_impl->DetectEx(pid);
    return result.detected;
}

LockyDetectionResult LockyDetector::DetectEx(uint32_t pid) {
    return m_impl ? m_impl->DetectEx(pid) : LockyDetectionResult{};
}

// ============================================================================
// PATTERN QUERIES
// ============================================================================

bool LockyDetector::IsLockyExtension(std::wstring_view extension) const {
    return m_impl ? m_impl->IsLockyExtension(extension) : false;
}

LockyVariant LockyDetector::IdentifyVariant(std::wstring_view extension) const {
    return m_impl ? m_impl->IdentifyVariant(extension) : LockyVariant::Unknown;
}

bool LockyDetector::IsLockyRansomNote(std::wstring_view filename) const {
    return m_impl ? m_impl->IsLockyRansomNote(filename) : false;
}

bool LockyDetector::IsLockyC2Domain(std::string_view domain) const {
    return m_impl ? m_impl->IsLockyC2Domain(domain) : false;
}

bool LockyDetector::AnalyzeEncryptedFile(std::wstring_view filePath) {
    return m_impl ? m_impl->AnalyzeEncryptedFile(filePath) : false;
}

// ============================================================================
// BEHAVIORAL EVENT HANDLERS
// ============================================================================

std::optional<LockyDetectionResult> LockyDetector::OnFileRename(
    uint32_t pid, std::wstring_view oldPath, std::wstring_view newPath)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire))
        return std::nullopt;

    auto pb = m_impl->GetOrCreateBehavior(pid);
    if (!pb) return std::nullopt;

    std::lock_guard lock(pb->mtx);

    if (m_impl->IsWhitelisted(pb->processName))
        return std::nullopt;

    const auto correlationWindow = std::chrono::seconds(
        m_impl->m_config.correlationWindowSecs);

    pb->totalRenames++;
    pb->renameTimestamps.push_back(Clock::now());
    pb->PruneTimestamps(correlationWindow);

    const std::wstring newExt = ExtractExtension(newPath);
    const std::wstring dir    = ExtractDirectory(newPath);
    const auto filename       = ExtractFilename(newPath);
    const auto stem           = ExtractStem(filename);

    if (!dir.empty()) {
        pb->affectedDirectories.insert(dir);
    }

    // Check if new extension is a known Locky extension
    if (m_impl->IsLockyExtension(newExt)) {
        pb->lockyExtRenames++;
        pb->extensionsObserved.push_back(std::wstring(newExt));

        // Identify variant from extension
        const auto variant = m_impl->IdentifyVariant(newExt);
        if (variant != LockyVariant::Unknown) {
            pb->variant = variant;
        }

        if (pb->lockyExtRenames == 1) {
            m_impl->AddScoreUnguarded(*pb,
                LockyConstants::SCORE_LOCKY_EXT_RENAME,
                "File renamed to Locky family extension");
        }
    }

    // Check for hex-ID filename pattern: [A-Fa-f0-9]{16,32}.[ext]
    if (IsHexIdFilename(stem)) {
        pb->hexPatternRenames++;
        if (pb->hexPatternRenames >= 3) {
            m_impl->AddScore(*pb, LockyConstants::SCORE_HEX_RENAME_PATTERN,
                             "Hex-ID filename rename pattern (Locky dropper)",
                             pb->hexPatternScored);
        }
    }

    // Mass rename rate detection
    if (!pb->massRenameTriggered &&
        pb->renameTimestamps.size() >= m_impl->m_config.massRenameThreshold)
    {
        m_impl->AddScore(*pb, LockyConstants::SCORE_MASS_RENAME,
                         "Mass rename rate exceeded threshold",
                         pb->massRenameTriggered);
    }

    // Multi-directory activity (4+ directories = suspicious)
    if (!pb->multiDirTriggered && pb->affectedDirectories.size() >= 4) {
        m_impl->AddScore(*pb, LockyConstants::SCORE_MULTI_DIR_ACTIVITY,
                         "File operations across 4+ directories",
                         pb->multiDirTriggered);
    }

    // Check if new file is a ransom note
    if (m_impl->IsLockyRansomNote(filename)) {
        pb->ransomNotesCreated++;
        pb->ransomNotesFound.push_back(std::wstring(newPath));
        if (!dir.empty()) {
            pb->ransomNoteDirectories.insert(dir);
        }
        if (pb->ransomNotesCreated == 1) {
            m_impl->AddScoreUnguarded(*pb,
                LockyConstants::SCORE_RANSOM_NOTE,
                "Locky ransom note file created");
        }
    }

    return m_impl->Evaluate(*pb);
}

std::optional<LockyDetectionResult> LockyDetector::OnFileWrite(
    uint32_t pid, std::wstring_view filePath,
    size_t /*dataSize*/, double entropy)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire))
        return std::nullopt;

    auto pb = m_impl->GetOrCreateBehavior(pid);
    if (!pb) return std::nullopt;

    std::lock_guard lock(pb->mtx);

    if (m_impl->IsWhitelisted(pb->processName))
        return std::nullopt;

    pb->totalWrites++;
    pb->lastActivity = Clock::now();

    const std::wstring dir = ExtractDirectory(filePath);
    if (!dir.empty()) {
        pb->affectedDirectories.insert(dir);
    }

    if (entropy > LockyConstants::HIGH_ENTROPY_THRESHOLD) {
        pb->highEntropyWrites++;
        if (pb->highEntropyWrites == 3) {
            m_impl->AddScoreUnguarded(*pb,
                LockyConstants::SCORE_HIGH_ENTROPY_WRITE,
                "Multiple high-entropy file writes (encrypted content)");
        }
    }

    // Check if file being written is a ransom note
    const auto filename = ExtractFilename(filePath);
    if (m_impl->IsLockyRansomNote(filename)) {
        pb->ransomNotesCreated++;
        pb->ransomNotesFound.push_back(std::wstring(filePath));
        if (!dir.empty()) {
            pb->ransomNoteDirectories.insert(dir);
        }
        if (pb->ransomNotesCreated == 1) {
            m_impl->AddScoreUnguarded(*pb,
                LockyConstants::SCORE_RANSOM_NOTE,
                "Locky ransom note written");
        }
    }

    // Multi-directory activity
    if (!pb->multiDirTriggered && pb->affectedDirectories.size() >= 4) {
        m_impl->AddScore(*pb, LockyConstants::SCORE_MULTI_DIR_ACTIVITY,
                         "File operations across 4+ directories",
                         pb->multiDirTriggered);
    }

    return m_impl->Evaluate(*pb);
}

std::optional<LockyDetectionResult> LockyDetector::OnProcessCreate(
    uint32_t pid, uint32_t parentPid,
    std::wstring_view imagePath, std::wstring_view commandLine)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire))
        return std::nullopt;

    // Check for VSS destruction in child processes
    const std::wstring cmdLower =
        Utils::StringUtils::ToLowerCopy(commandLine);

    if (ContainsVSSDestructionPattern(cmdLower)) {
        // Attribute to parent process
        auto pb = m_impl->GetOrCreateBehavior(parentPid);
        if (pb) {
            std::lock_guard lock(pb->mtx);
            if (!m_impl->IsWhitelisted(pb->processName)) {
                m_impl->AddScore(*pb,
                    LockyConstants::SCORE_VSS_DESTRUCTION,
                    "Child process executing VSS destruction",
                    pb->vssDestruction);
                return m_impl->Evaluate(*pb);
            }
        }
    }

    // Dropper behavior: PowerShell downloading executable
    const auto imageNameLower =
        Utils::StringUtils::ToLowerCopy(
            std::wstring(ExtractFilename(imagePath)));

    if (imageNameLower == L"powershell.exe" ||
        imageNameLower == L"pwsh.exe")
    {
        // PowerShell with download cradle patterns
        if (Utils::StringUtils::IContains(commandLine, L"downloadstring") ||
            Utils::StringUtils::IContains(commandLine, L"downloadfile") ||
            Utils::StringUtils::IContains(commandLine, L"invoke-webrequest") ||
            Utils::StringUtils::IContains(commandLine, L"wget") ||
            Utils::StringUtils::IContains(commandLine, L"start-bitstransfer") ||
            Utils::StringUtils::IContains(commandLine, L"invoke-expression") ||
            Utils::StringUtils::IContains(commandLine, L"iex"))
        {
            auto pb = m_impl->GetOrCreateBehavior(parentPid);
            if (pb) {
                std::lock_guard lock(pb->mtx);
                if (!m_impl->IsWhitelisted(pb->processName)) {
                    m_impl->AddScore(*pb,
                        LockyConstants::SCORE_DROPPER_BEHAVIOR,
                        "PowerShell download cradle (dropper chain)",
                        pb->dropperBehavior);
                    return m_impl->Evaluate(*pb);
                }
            }
        }
    }

    // Check if exe in temp directory (common Locky dropper behavior)
    const std::wstring imagePathLower =
        Utils::StringUtils::ToLowerCopy(std::wstring(imagePath));

    if ((Utils::StringUtils::IContains(imagePathLower, L"\\temp\\") ||
         Utils::StringUtils::IContains(imagePathLower, L"\\tmp\\") ||
         Utils::StringUtils::IContains(imagePathLower, L"\\appdata\\local\\temp")) &&
        (Utils::StringUtils::EndsWith(imagePathLower, L".exe") ||
         Utils::StringUtils::EndsWith(imagePathLower, L".scr")))
    {
        auto pb = m_impl->GetOrCreateBehavior(pid);
        if (pb) {
            std::lock_guard lock(pb->mtx);
            pb->processPath = std::wstring(imagePath);
            pb->processName = std::wstring(ExtractFilename(imagePath));

            // Don't score temp exe alone — just track it.
            // Score fires if combined with other indicators.
            if (m_impl->m_config.verboseLogging) {
                SS_LOG_DEBUG(LOG_CAT,
                    L"Tracking temp-dir executable PID=%u path=%ls",
                    pid, imagePath.data());
            }
        }
    }

    return std::nullopt;
}

std::optional<LockyDetectionResult> LockyDetector::OnDnsQuery(
    uint32_t pid, std::string_view domain)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire))
        return std::nullopt;

    if (!m_impl->IsLockyC2Domain(domain))
        return std::nullopt;

    auto pb = m_impl->GetOrCreateBehavior(pid);
    if (!pb) return std::nullopt;

    std::lock_guard lock(pb->mtx);

    if (m_impl->IsWhitelisted(pb->processName))
        return std::nullopt;

    pb->dgaDomainsContacted++;
    pb->c2Domains.emplace_back(domain);

    if (pb->dgaDomainsContacted == 1) {
        m_impl->AddScoreUnguarded(*pb,
            LockyConstants::SCORE_DGA_DOMAIN,
            "DNS query to Locky DGA-generated domain");
    }

    SS_LOG_WARN(LOG_CAT,
        L"DGA domain hit: PID=%u domain=%hs total=%u",
        pid, std::string(domain).c_str(), pb->dgaDomainsContacted);

    return m_impl->Evaluate(*pb);
}

std::optional<LockyDetectionResult> LockyDetector::OnRegistryWrite(
    uint32_t pid, std::wstring_view keyPath,
    std::wstring_view valueName, std::wstring_view data)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire))
        return std::nullopt;

    auto pb = m_impl->GetOrCreateBehavior(pid);
    if (!pb) return std::nullopt;

    std::lock_guard lock(pb->mtx);

    if (m_impl->IsWhitelisted(pb->processName))
        return std::nullopt;

    // Wallpaper modification detection
    if (Utils::StringUtils::IContains(keyPath,
            L"Control Panel\\Desktop") &&
        Utils::StringUtils::IEquals(valueName, L"Wallpaper"))
    {
        m_impl->AddScore(*pb,
            LockyConstants::SCORE_WALLPAPER_CHANGE,
            "Desktop wallpaper registry modification",
            pb->wallpaperModified);
        return m_impl->Evaluate(*pb);
    }

    // Run key persistence detection
    if (Utils::StringUtils::IContains(keyPath,
            L"CurrentVersion\\Run"))
    {
        m_impl->AddScore(*pb,
            LockyConstants::SCORE_REGISTRY_PERSISTENCE,
            "Run key registry persistence attempt",
            pb->registryPersistence);
        return m_impl->Evaluate(*pb);
    }

    // Locky-specific registry key
    if (Utils::StringUtils::IContains(keyPath, L"Software\\Locky")) {
        m_impl->AddScore(*pb,
            LockyConstants::SCORE_REGISTRY_PERSISTENCE,
            "Locky-specific registry key written",
            pb->registryPersistence);
        return m_impl->Evaluate(*pb);
    }

    return std::nullopt;
}

std::optional<LockyDetectionResult> LockyDetector::OnMutexCreate(
    uint32_t pid, std::wstring_view mutexName)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire))
        return std::nullopt;

    if (!IsGuidFormat(mutexName))
        return std::nullopt;

    auto pb = m_impl->GetOrCreateBehavior(pid);
    if (!pb) return std::nullopt;

    std::lock_guard lock(pb->mtx);

    if (m_impl->IsWhitelisted(pb->processName))
        return std::nullopt;

    m_impl->AddScore(*pb,
        LockyConstants::SCORE_GUID_MUTEX,
        "GUID-format mutex creation (Locky signature)",
        pb->guidMutex);

    return m_impl->Evaluate(*pb);
}

double LockyDetector::GetProcessScore(uint32_t pid) const {
    if (!m_impl) return 0.0;
    auto pb = m_impl->FindBehavior(pid);
    if (!pb) return 0.0;
    std::lock_guard lock(pb->mtx);
    return pb->score;
}

LockyDetectionResult LockyDetector::BuildResultFromBehavior(uint32_t pid) const {
    if (!m_impl) return {};
    auto pb = m_impl->FindBehavior(pid);
    if (!pb) return {};
    std::lock_guard lock(pb->mtx);
    return m_impl->BuildResult(*pb);
}

void LockyDetector::PurgeStaleProcesses() {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->m_behaviorMutex);
    m_impl->PurgeStaleProcessesLocked();
}

// ============================================================================
// PATTERN MANAGEMENT
// ============================================================================

void LockyDetector::AddKnownC2Domain(std::string_view domain) {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->m_patternsMutex);
    m_impl->m_knownC2Domains.emplace(domain);
}

void LockyDetector::AddKnownHash(std::string_view sha256Hex) {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->m_patternsMutex);
    std::string lower(sha256Hex);
    for (auto& c : lower) {
        if (c >= 'A' && c <= 'Z') c += 32;
    }
    m_impl->m_knownBadHashes.insert(std::move(lower));
}

void LockyDetector::AddKnownExtension(std::wstring_view extension) {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->m_patternsMutex);
    std::wstring lower(extension);
    for (auto& c : lower) {
        if (c >= L'A' && c <= L'Z') c += 32;
    }
    m_impl->m_knownExtensions.insert(std::move(lower));
}

void LockyDetector::UpdatePatternsFromThreatIntel() {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->m_patternsMutex);
    m_impl->UpdateDGADomainsLocked();
    SS_LOG_INFO(LOG_CAT, L"Patterns refreshed from threat intel");
}

// ============================================================================
// CALLBACKS
// ============================================================================

void LockyDetector::SetDetectionCallback(LockyDetectionCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_callback = std::move(callback);
}

// ============================================================================
// STATISTICS
// ============================================================================

LockyStatisticsSnapshot LockyDetector::GetStatistics() const {
    if (!m_impl) return {};
    LockyStatisticsSnapshot snap;
    snap.totalDetections     = m_impl->m_stats.totalDetections.load(std::memory_order_relaxed);
    snap.processesTerminated = m_impl->m_stats.processesTerminated.load(std::memory_order_relaxed);
    for (size_t i = 0; i < m_impl->m_stats.byVariant.size(); ++i) {
        snap.byVariant[i] = m_impl->m_stats.byVariant[i].load(std::memory_order_relaxed);
    }
    const auto now = Clock::now();
    snap.uptimeSeconds = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now - m_impl->m_stats.startTime).count());
    return snap;
}

void LockyDetector::ResetStatistics() {
    if (m_impl) {
        m_impl->m_stats.Reset();
    }
}

// ============================================================================
// SELF-TEST & VERSION
// ============================================================================

bool LockyDetector::SelfTest() {
    if (!m_impl) return false;

    SS_LOG_INFO(LOG_CAT, L"Starting SelfTest...");

    // 1. Extension detection
    if (!IsLockyExtension(L".locky")) {
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: .locky extension not detected");
        return false;
    }
    if (!IsLockyExtension(L".ZEPTO")) { // Case-insensitive
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: .ZEPTO (uppercase) not detected");
        return false;
    }

    // 2. Variant identification
    if (IdentifyVariant(L".zepto") != LockyVariant::Zepto) {
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: Zepto variant mismatch");
        return false;
    }
    if (IdentifyVariant(L".OSIRIS") != LockyVariant::Osiris) {
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: Osiris variant mismatch");
        return false;
    }

    // 3. Ransom note detection
    if (!IsLockyRansomNote(L"_Locky_recover_instructions.txt")) {
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: Ransom note not detected");
        return false;
    }
    if (!IsLockyRansomNote(L"_HOWDO_text.html")) {
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: _HOWDO_text.html not detected");
        return false;
    }
    if (!IsLockyRansomNote(L"_README_.txt")) {
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: _README_.txt not detected");
        return false;
    }

    // 4. DGA generation
    auto domains = GenerateLockyDomains(2016, 1, 1, 5);
    if (domains.size() != 12) {
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: DGA count=%zu expected=12",
                     domains.size());
        return false;
    }
    for (const auto& d : domains) {
        if (d.find('.') == std::string::npos) {
            SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: DGA domain missing TLD");
            return false;
        }
    }

    // 5. Configuration validation
    LockyDetectorConfiguration badConfig;
    badConfig.correlationWindowSecs = 0; // Invalid
    if (badConfig.IsValid()) {
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: Invalid config passed validation");
        return false;
    }

    // 6. Hex-ID pattern check
    if (!IsHexIdFilename(L"A1B2C3D4E5F6A7B8")) {
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: Hex-ID pattern not detected");
        return false;
    }
    if (IsHexIdFilename(L"hello_world")) {
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: Non-hex falsely detected as hex-ID");
        return false;
    }

    // 7. GUID mutex check
    if (!IsGuidFormat(L"{12345678-1234-1234-1234-123456789012}")) {
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: GUID format not recognized");
        return false;
    }

    // 8. Statistics reset
    ResetStatistics();
    auto resetStats = GetStatistics();
    if (resetStats.totalDetections != 0) {
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: Statistics reset failed");
        return false;
    }

    // 9. Score-to-confidence mapping
    if (LockyDetectorImpl::ScoreToConfidence(0.0) != DetectionConfidence::None) {
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: ScoreToConfidence(0) != None");
        return false;
    }
    if (LockyDetectorImpl::ScoreToConfidence(95.0) != DetectionConfidence::Confirmed) {
        SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: ScoreToConfidence(95) != Confirmed");
        return false;
    }

    SS_LOG_INFO(LOG_CAT, L"SelfTest PASSED (9/9 checks)");
    return true;
}

std::string LockyDetector::GetVersionString() noexcept {
    return std::format("{}.{}.{}",
        LockyConstants::VERSION_MAJOR,
        LockyConstants::VERSION_MINOR,
        LockyConstants::VERSION_PATCH);
}

// ============================================================================
// FREE FUNCTION IMPLEMENTATIONS
// ============================================================================

std::string_view GetLockyVariantName(LockyVariant variant) noexcept {
    switch (variant) {
        case LockyVariant::Original: return "Original (.locky)";
        case LockyVariant::Zepto:    return "Zepto";
        case LockyVariant::Odin:     return "Odin";
        case LockyVariant::Thor:     return "Thor";
        case LockyVariant::Aesir:    return "Aesir";
        case LockyVariant::Zzzzz:    return "Zzzzz";
        case LockyVariant::Osiris:   return "Osiris";
        case LockyVariant::Diablo6:  return "Diablo6";
        case LockyVariant::Lukitus:  return "Lukitus";
        case LockyVariant::Ykcol:    return "Ykcol";
        default:                     return "Unknown";
    }
}

std::wstring_view GetLockyExtension(LockyVariant variant) noexcept {
    switch (variant) {
        case LockyVariant::Original: return L".locky";
        case LockyVariant::Zepto:    return L".zepto";
        case LockyVariant::Odin:     return L".odin";
        case LockyVariant::Thor:     return L".thor";
        case LockyVariant::Aesir:    return L".aesir";
        case LockyVariant::Zzzzz:    return L".zzzzz";
        case LockyVariant::Osiris:   return L".osiris";
        case LockyVariant::Diablo6:  return L".diablo6";
        case LockyVariant::Lukitus:  return L".lukitus";
        case LockyVariant::Ykcol:    return L".ykcol";
        default:                     return L"";
    }
}

// ============================================================================
// LOCKY STATISTICS SNAPSHOT — ToJson
// ============================================================================

std::string LockyStatisticsSnapshot::ToJson() const {
    nlohmann::json j;
    j["totalDetections"]     = totalDetections;
    j["processesTerminated"] = processesTerminated;
    j["uptimeSeconds"]       = uptimeSeconds;
    nlohmann::json varArr = nlohmann::json::array();
    for (size_t i = 0; i < byVariant.size(); ++i) {
        if (byVariant[i] > 0) {
            varArr.push_back({
                {"variant", std::string(GetLockyVariantName(static_cast<LockyVariant>(i)))},
                {"count",   byVariant[i]}
            });
        }
    }
    j["byVariant"] = std::move(varArr);
    return j.dump();
}

// ============================================================================
// KERNEL BRIDGE — OnKernelProcessNotify / OnKernelImageLoad / RequestBlock
// ============================================================================

void LockyDetector::OnKernelProcessNotify(
    uint32_t pid, uint32_t parentPid,
    std::wstring_view imagePath, bool isCreate)
{
    if (!m_impl) return;
    if (isCreate) {
        (void)OnProcessCreate(pid, parentPid, imagePath, L"");
    } else {
        m_impl->PurgeProcessState(pid);
    }
}

void LockyDetector::OnKernelImageLoad(
    uint32_t pid, std::wstring_view imagePath, uintptr_t /*imageBase*/)
{
    if (!m_impl) return;
    // DLL side-load detection: check if image path has Locky extension
    if (IsLockyExtension(imagePath)) {
        SS_LOG_WARN(LOG_CAT,
            L"Locky-named image loaded into PID %u: %.*s",
            pid,
            static_cast<int>(imagePath.size()), imagePath.data());
    }
}

[[nodiscard]] bool LockyDetector::RequestKernelProcessBlock(
    uint32_t pid, std::wstring_view reason)
{
    if (!Communication::IPCManager::HasInstance() ||
        !Communication::IPCManager::Instance().IsFilterPortConnected())
    {
        return false;
    }
    #pragma pack(push, 1)
    struct KernelBlockMsg {
        uint32_t msgType = 0x30;  // standard process block
        uint32_t pid     = 0;
    } msg;
    #pragma pack(pop)
    msg.pid = pid;
    const bool sent = Communication::IPCManager::Instance().SendToKernel(&msg, sizeof(msg));
    if (sent) {
        SS_LOG_INFO(LOG_CAT,
            L"Kernel process block requested for PID %u: %.*s",
            pid,
            static_cast<int>(reason.size()), reason.data());
    }
    return sent;
}

// ============================================================================
// CROSS-MODULE WIRING — AlertSystem & TelemetryCollector helpers
// ============================================================================

void LockyDetector::ReportDetectionToAlertSystem(
    uint32_t pid, const LockyDetectionResult& result)
{
    if (!Communication::AlertSystem::HasInstance()) return;

    const auto severity = (result.score >= 90.0)
        ? Communication::AlertSeverity::Critical
        : Communication::AlertSeverity::High;
    (void)Communication::AlertSystem::Instance().RaiseAlert(
        severity,
        Communication::AlertType::ThreatDetection,
        "LockyDetector",
        std::format("Locky {} PID {} ({}) score={:.0f}",
            GetLockyVariantName(result.variant),
            pid,
            Utils::StringUtils::ToNarrow(result.processName),
            result.score),
        std::format("confidence={}", GetDetectionConfidenceName(result.confidence)));
}

void LockyDetector::ReportDetectionTelemetry(
    const std::string& eventName,
    const std::map<std::string, std::string>& fields)
{
    if (!Communication::TelemetryCollector::HasInstance()) return;
    Communication::TelemetryCollector::Instance().RecordCustom(eventName, fields);
}

} // namespace Ransomware
} // namespace ShadowStrike
