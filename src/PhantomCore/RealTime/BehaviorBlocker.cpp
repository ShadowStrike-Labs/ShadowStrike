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
 * ShadowStrike Real-Time - BEHAVIOR BLOCKER IMPLEMENTATION
 * ============================================================================
 *
 * @file BehaviorBlocker.cpp
 * @brief Enterprise-grade real-time behavior blocking engine.
 *
 * Core responsibilities:
 *   - Analyze process behaviors against configurable rule sets
 *   - Temporal correlation of per-process behavior chains
 *   - Enforcement actions: block, suspend, terminate, quarantine
 *   - Kernel event ingestion (stub -- full wire-up via IPCManager)
 *   - Exclusion management with AND-logic pattern matching
 *   - Callback notification for downstream consumers
 *
 * Lock ordering (must acquire in this sequence):
 *   m_stateMutex > m_ruleMutex > m_exclusionMutex > m_chainMutex
 *                > m_blockedMutex > m_historyMutex > m_callbackMutex
 *
 * Thread-safety guarantees:
 *   - All public methods are safe to call from any thread
 *   - AnalyzeBehavior is the hot path -- uses shared_locks where possible
 *   - Stat counters use std::memory_order_relaxed atomics
 *   - Callbacks are invoked with NO locks held (copy-then-invoke)
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "BehaviorBlocker.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/StringUtils.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <list>
#include <regex>
#include <chrono>
#include <atomic>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <cstring>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <functional>
#include <nlohmann/json.hpp>

namespace ShadowStrike::RealTime {

using json = nlohmann::json;
namespace fs = std::filesystem;

// ============================================================================
// ANONYMOUS HELPER NAMESPACE -- CONSTANTS & UTILITIES
// ============================================================================
namespace {

constexpr const wchar_t* kLogCategory             = L"BehaviorBlocker";
constexpr uint32_t       kSystemPid                = 4;
constexpr uint32_t       kIdlePid                  = 0;
constexpr size_t         kDefaultMaxRules          = 1024;
constexpr size_t         kDefaultMaxExclusions     = 512;
constexpr size_t         kDefaultMaxHistory        = 10000;
constexpr uint32_t       kDefaultAnalysisTimeoutMs = 5;
constexpr uint32_t       kDefaultRegexMaxInput     = 32768;
constexpr uint32_t       kDefaultChainTimeoutSec   = 300;
constexpr float          kDefaultEscalationThresh  = 0.7f;
constexpr int64_t        kBlockedPidTtlMs          = 600000; // 10 min TTL for stale PIDs
constexpr size_t         kProcessKeyCacheMax       = 1024;
constexpr float          kDecayLambda              = 0.01f;
constexpr uint32_t       kChainAutoEscalateCount   = 3;

constexpr float RiskToScore(RiskLevel r) noexcept {
    switch (r) {
        case RiskLevel::Safe:     return 0.0f;
        case RiskLevel::Low:      return 0.15f;
        case RiskLevel::Medium:   return 0.35f;
        case RiskLevel::High:     return 0.70f;
        case RiskLevel::Critical: return 1.0f;
        default:                  return 0.0f;
    }
}

[[nodiscard]] const char* BehaviorTypeToString(BehaviorType t) noexcept {
    switch (t) {
        case BehaviorType::Unknown:              return "Unknown";
        case BehaviorType::FileModification:     return "FileModification";
        case BehaviorType::NetworkConnection:    return "NetworkConnection";
        case BehaviorType::ProcessInjection:     return "ProcessInjection";
        case BehaviorType::RegistryModification: return "RegistryModification";
        case BehaviorType::DriverLoading:        return "DriverLoading";
        case BehaviorType::ShadowCopyDeletion:   return "ShadowCopyDeletion";
        case BehaviorType::RansomwareActivity:   return "RansomwareActivity";
        case BehaviorType::PrivilegeEscalation:  return "PrivilegeEscalation";
        case BehaviorType::DefenseEvasion:       return "DefenseEvasion";
        case BehaviorType::ScriptExecution:      return "ScriptExecution";
        case BehaviorType::WMIActivity:          return "WMIActivity";
        case BehaviorType::LateralMovement:      return "LateralMovement";
        case BehaviorType::MemoryManipulation:   return "MemoryManipulation";
        case BehaviorType::DLLSideloading:       return "DLLSideloading";
        case BehaviorType::NamedPipeCreation:    return "NamedPipeCreation";
        case BehaviorType::DataExfiltration:     return "DataExfiltration";
        case BehaviorType::CredentialAccess:     return "CredentialAccess";
        case BehaviorType::ProcessExecution:     return "ProcessExecution";
        case BehaviorType::Discovery:            return "Discovery";
        default:                                 return "Unknown";
    }
}

[[nodiscard]] const char* BlockActionToString(BlockAction a) noexcept {
    switch (a) {
        case BlockAction::Allow:            return "Allow";
        case BlockAction::LogOnly:          return "LogOnly";
        case BlockAction::AlertOnly:        return "AlertOnly";
        case BlockAction::BlockOperation:   return "BlockOperation";
        case BlockAction::QuarantineFile:   return "QuarantineFile";
        case BlockAction::SuspendProcess:   return "SuspendProcess";
        case BlockAction::IsolateNetwork:   return "IsolateNetwork";
        case BlockAction::TerminateProcess: return "TerminateProcess";
        default:                            return "Unknown";
    }
}

[[nodiscard]] const char* ComponentStateToString(ComponentState s) noexcept {
    switch (s) {
        case ComponentState::NotInitialized: return "NotInitialized";
        case ComponentState::Initializing:   return "Initializing";
        case ComponentState::Running:        return "Running";
        case ComponentState::Paused:         return "Paused";
        case ComponentState::Stopping:       return "Stopping";
        case ComponentState::Stopped:        return "Stopped";
        case ComponentState::Error:          return "Error";
        default:                             return "Unknown";
    }
}

[[nodiscard]] int64_t NowEpochMs() noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

[[nodiscard]] int64_t NowSteadyUs() noexcept {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void CapString(std::wstring& s, size_t maxLen) noexcept {
    if (s.size() > maxLen) s.resize(maxLen);
}

void CapString(std::string& s, size_t maxLen) noexcept {
    if (s.size() > maxLen) s.resize(maxLen);
}

[[nodiscard]] std::wstring ExtractFilename(const std::wstring& fullPath) {
    if (fullPath.empty()) return {};
    auto pos = fullPath.find_last_of(L"\\\\/");
    if (pos == std::wstring::npos) return fullPath;
    return fullPath.substr(pos + 1);
}

} // anonymous namespace

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

struct ProcessKey {
    uint32_t pid{0};
    uint64_t creationTime{0};

    bool operator==(const ProcessKey& other) const noexcept {
        return pid == other.pid && creationTime == other.creationTime;
    }
};

struct ProcessKeyHash {
    std::size_t operator()(const ProcessKey& k) const noexcept {
        std::size_t h = std::hash<uint32_t>{}(k.pid);
        h ^= std::hash<uint64_t>{}(k.creationTime) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        return h;
    }
};

// FIX: BB-N4 - blocked-process entry keyed by ProcessKey to defend against PID
// reuse within the TTL window. Recording both creation time and block timestamp
// lets us reject false-positives where the OS recycled a recently-terminated PID
// onto an unrelated process before the 10-minute TTL elapsed.
struct BlockedEntry {
    uint64_t creationTime{0};
    int64_t  blockedAtMs{0};
};

struct CompiledRule {
    BehaviorRule rule;
    std::unique_ptr<std::regex> targetRegex;
    bool valid{false};
};

struct CompiledExclusion {
    BehaviorExclusion exclusion;
    std::unique_ptr<std::regex> pathRegex;
    std::unique_ptr<std::regex> cmdLineRegex;
    std::unique_ptr<std::regex> targetRegex;
    bool valid{false};
};

struct BehaviorChainEntry {
    BehaviorType type;
    BlockAction  actionTaken;
    int64_t      timestamp;
    std::string  ruleId;
    float        riskScore;
};

struct ProcessBehaviorChain {
    uint32_t     processId{0};
    uint64_t     processCreationTime{0};
    std::deque<BehaviorChainEntry> events;
    float        compositeScore{0.0f};
    int64_t      firstEventTime{0};
    int64_t      lastEventTime{0};
};

// ============================================================================
// LRU CACHE FOR PROCESS KEY LOOKUPS
// ============================================================================

class ProcessKeyCache {
public:
    explicit ProcessKeyCache(size_t capacity) : m_capacity(capacity) {}

    std::optional<ProcessKey> Get(uint32_t pid) {
        std::lock_guard lock(m_mutex);
        auto it = m_map.find(pid);
        if (it == m_map.end()) return std::nullopt;
        m_lru.splice(m_lru.begin(), m_lru, it->second.listIt);
        return it->second.key;
    }

    void Put(uint32_t pid, const ProcessKey& key) {
        std::lock_guard lock(m_mutex);
        auto it = m_map.find(pid);
        if (it != m_map.end()) {
            it->second.key = key;
            m_lru.splice(m_lru.begin(), m_lru, it->second.listIt);
            return;
        }
        if (m_map.size() >= m_capacity) {
            uint32_t evictPid = m_lru.back();
            m_lru.pop_back();
            m_map.erase(evictPid);
        }
        m_lru.push_front(pid);
        CacheEntry entry;
        entry.key = key;
        entry.listIt = m_lru.begin();
        m_map[pid] = entry;
    }

    void Invalidate(uint32_t pid) {
        std::lock_guard lock(m_mutex);
        auto it = m_map.find(pid);
        if (it != m_map.end()) {
            m_lru.erase(it->second.listIt);
            m_map.erase(it);
        }
    }

    void Clear() {
        std::lock_guard lock(m_mutex);
        m_map.clear();
        m_lru.clear();
    }

private:
    struct CacheEntry {
        ProcessKey key;
        std::list<uint32_t>::iterator listIt;
    };
    mutable std::mutex m_mutex;
    size_t m_capacity;
    std::list<uint32_t> m_lru;
    std::unordered_map<uint32_t, CacheEntry> m_map;
};

// ============================================================================
// INTERNAL STATISTICS (atomic counters, relaxed ordering)
// ============================================================================

struct InternalStats {
    std::atomic<uint64_t> behaviorsAnalyzed{0};
    std::atomic<uint64_t> threatsBlocked{0};
    std::atomic<uint64_t> processesTerminated{0};
    std::atomic<uint64_t> processesSuspended{0};
    std::atomic<uint64_t> rulesEvaluated{0};
    std::atomic<uint64_t> analysisFailures{0};
    std::atomic<uint64_t> exclusionsMatched{0};
    std::atomic<uint64_t> totalAnalysisTimeUs{0};
    std::atomic<uint64_t> kernelEventsReceived{0};
    std::atomic<uint64_t> behaviorChainsActive{0};

    void Reset() noexcept {
        behaviorsAnalyzed.store(0, std::memory_order_relaxed);
        threatsBlocked.store(0, std::memory_order_relaxed);
        processesTerminated.store(0, std::memory_order_relaxed);
        processesSuspended.store(0, std::memory_order_relaxed);
        rulesEvaluated.store(0, std::memory_order_relaxed);
        analysisFailures.store(0, std::memory_order_relaxed);
        exclusionsMatched.store(0, std::memory_order_relaxed);
        totalAnalysisTimeUs.store(0, std::memory_order_relaxed);
        kernelEventsReceived.store(0, std::memory_order_relaxed);
        behaviorChainsActive.store(0, std::memory_order_relaxed);
    }

    [[nodiscard]] BehaviorBlockerStats Snapshot(uint32_t activeRules,
                                                uint32_t activeExclusions) const noexcept {
        BehaviorBlockerStats s{};
        s.behaviorsAnalyzed    = behaviorsAnalyzed.load(std::memory_order_relaxed);
        s.threatsBlocked       = threatsBlocked.load(std::memory_order_relaxed);
        s.processesTerminated  = processesTerminated.load(std::memory_order_relaxed);
        s.processesSuspended   = processesSuspended.load(std::memory_order_relaxed);
        s.rulesEvaluated       = rulesEvaluated.load(std::memory_order_relaxed);
        s.analysisFailures     = analysisFailures.load(std::memory_order_relaxed);
        s.exclusionsMatched    = exclusionsMatched.load(std::memory_order_relaxed);
        s.totalAnalysisTimeUs  = totalAnalysisTimeUs.load(std::memory_order_relaxed);
        s.kernelEventsReceived = kernelEventsReceived.load(std::memory_order_relaxed);
        s.behaviorChainsActive = behaviorChainsActive.load(std::memory_order_relaxed);
        s.activeRuleCount      = activeRules;
        s.activeExclusionCount = activeExclusions;
        return s;
    }
};

// ============================================================================
// STRUCT MEMBER FUNCTION IMPLEMENTATIONS
// ============================================================================

std::string ProcessBehavior::ToJson() const {
    try {
        json j;
        j["processId"]      = processId;
        j["parentPid"]       = parentPid;
        j["processPath"]     = Utils::StringUtils::ToNarrow(processPath);
        j["commandLine"]     = Utils::StringUtils::ToNarrow(commandLine);
        j["type"]            = static_cast<int>(type);
        j["target"]          = Utils::StringUtils::ToNarrow(target);
        j["risk"]            = static_cast<int>(risk);
        j["sessionId"]       = sessionId;
        j["integrityLevel"]  = integrityLevel;
        j["correlationId"]   = correlationId;
        j["timestamp"]       = timestamp;
        return j.dump();
    } catch (...) {
        return "{}";
    }
}

std::string BlockEvent::ToJson() const {
    try {
        json j;
        j["timestamp"]       = timestamp;
        j["processId"]       = processId;
        j["processPath"]     = Utils::StringUtils::ToNarrow(processPath);
        j["behaviorType"]    = static_cast<int>(behaviorType);
        j["actionTaken"]     = static_cast<int>(actionTaken);
        j["ruleId"]          = ruleId;
        j["details"]         = details;
        j["correlationId"]   = correlationId;
        j["actionSucceeded"] = actionSucceeded;
        return j.dump();
    } catch (...) {
        return "{}";
    }
}

BehaviorBlockerConfig BehaviorBlockerConfig::CreateDefault() {
    BehaviorBlockerConfig cfg;
    cfg.enableBlocking            = true;
    cfg.enableKernelIntegration   = true;
    cfg.enableTemporalCorrelation = true;
    cfg.maxRules                  = 1000;
    cfg.maxExclusions             = 500;
    cfg.maxHistoryEvents          = 10000;
    cfg.analysisTimeoutMs         = 5;
    cfg.regexMaxInputLength       = 32768;
    cfg.behaviorChainTimeoutSec   = 300;
    cfg.escalationThreshold       = 0.7f;
    return cfg;
}

BehaviorBlockerConfig BehaviorBlockerConfig::CreateEnterprise() {
    BehaviorBlockerConfig cfg;
    cfg.enableBlocking            = true;
    cfg.enableKernelIntegration   = true;
    cfg.enableTemporalCorrelation = true;
    cfg.maxRules                  = 5000;
    cfg.maxExclusions             = 2000;
    cfg.maxHistoryEvents          = 50000;
    cfg.analysisTimeoutMs         = 3;
    cfg.regexMaxInputLength       = 16384;
    cfg.behaviorChainTimeoutSec   = 600;
    cfg.escalationThreshold       = 0.5f;
    return cfg;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class BehaviorBlockerImpl {
public:

    // ========================================================================
    // CONSTRUCTION / DESTRUCTION
    // ========================================================================

    BehaviorBlockerImpl()
        : m_state(ComponentState::NotInitialized)
        , m_processKeyCache(kProcessKeyCacheMax)
    {
        SS_LOG_TRACE(kLogCategory, L"BehaviorBlockerImpl constructed");
    }

    ~BehaviorBlockerImpl() {
        Shutdown();
    }

    // ========================================================================
    // LIFECYCLE STATE MACHINE
    // ========================================================================

    bool Initialize(const BehaviorBlockerConfig& config) {
        std::unique_lock stateLock(m_stateMutex);
        if (m_state != ComponentState::NotInitialized &&
            m_state != ComponentState::Error) {
            SS_LOG_WARN(kLogCategory, L"Initialize called in invalid state: %hs",
                ComponentStateToString(m_state));
            return false;
        }

        m_state = ComponentState::Initializing;
        m_config = config;

        if (m_config.maxRules == 0)
            m_config.maxRules = static_cast<uint32_t>(kDefaultMaxRules);
        if (m_config.maxExclusions == 0)
            m_config.maxExclusions = static_cast<uint32_t>(kDefaultMaxExclusions);
        if (m_config.maxHistoryEvents == 0)
            m_config.maxHistoryEvents = static_cast<uint32_t>(kDefaultMaxHistory);
        if (m_config.analysisTimeoutMs == 0)
            m_config.analysisTimeoutMs = kDefaultAnalysisTimeoutMs;
        if (m_config.regexMaxInputLength == 0)
            m_config.regexMaxInputLength = kDefaultRegexMaxInput;
        if (m_config.behaviorChainTimeoutSec == 0)
            m_config.behaviorChainTimeoutSec = kDefaultChainTimeoutSec;
        if (m_config.escalationThreshold <= 0.0f)
            m_config.escalationThreshold = kDefaultEscalationThresh;

        m_stats.Reset();

        {
            std::unique_lock ruleLock(m_ruleMutex);
            LoadDefaultRulesInternal();
        }

        m_state = ComponentState::Stopped;
        SS_LOG_INFO(kLogCategory,
            L"Initialized with %u rules, blocking=%hs, kernel=%hs, correlation=%hs",
            static_cast<unsigned>(GetRuleCountInternal()),
            m_config.enableBlocking ? "ON" : "OFF",
            m_config.enableKernelIntegration ? "ON" : "OFF",
            m_config.enableTemporalCorrelation ? "ON" : "OFF");
        return true;
    }

    bool Start() {
        std::unique_lock stateLock(m_stateMutex);
        if (m_state != ComponentState::Stopped) {
            SS_LOG_WARN(kLogCategory, L"Start called in invalid state: %hs",
                ComponentStateToString(m_state));
            return false;
        }
        m_state = ComponentState::Running;
        SS_LOG_INFO(kLogCategory, L"Engine started");
        return true;
    }

    bool Stop() {
        std::unique_lock stateLock(m_stateMutex);
        if (m_state != ComponentState::Running && m_state != ComponentState::Paused) {
            SS_LOG_WARN(kLogCategory, L"Stop called in invalid state: %hs",
                ComponentStateToString(m_state));
            return false;
        }
        m_state = ComponentState::Stopping;
        {
            std::unique_lock chainLock(m_chainMutex);
            m_behaviorChains.clear();
            m_stats.behaviorChainsActive.store(0, std::memory_order_relaxed);
        }
        m_state = ComponentState::Stopped;
        SS_LOG_INFO(kLogCategory, L"Engine stopped");
        return true;
    }

    bool Pause() {
        std::unique_lock stateLock(m_stateMutex);
        if (m_state != ComponentState::Running) {
            SS_LOG_WARN(kLogCategory, L"Pause called in invalid state: %hs",
                ComponentStateToString(m_state));
            return false;
        }
        m_state = ComponentState::Paused;
        SS_LOG_INFO(kLogCategory, L"Engine paused");
        return true;
    }

    bool Resume() {
        std::unique_lock stateLock(m_stateMutex);
        if (m_state != ComponentState::Paused) {
            SS_LOG_WARN(kLogCategory, L"Resume called in invalid state: %hs",
                ComponentStateToString(m_state));
            return false;
        }
        m_state = ComponentState::Running;
        SS_LOG_INFO(kLogCategory, L"Engine resumed");
        return true;
    }

    void Shutdown() {
        std::unique_lock stateLock(m_stateMutex);
        if (m_state == ComponentState::NotInitialized) return;
        if (m_state == ComponentState::Running || m_state == ComponentState::Paused) {
            m_state = ComponentState::Stopping;
        }
        {
            std::unique_lock ruleLock(m_ruleMutex);
            m_rules.clear();
        }
        {
            std::unique_lock exclLock(m_exclusionMutex);
            m_exclusions.clear();
        }
        {
            std::unique_lock chainLock(m_chainMutex);
            m_behaviorChains.clear();
        }
        {
            std::unique_lock blockedLock(m_blockedMutex);
            m_blockedPids.clear();
        }
        {
            std::unique_lock histLock(m_historyMutex);
            m_history.clear();
        }
        {
            std::unique_lock cbLock(m_callbackMutex);
            m_blockCallbacks.clear();
        }
        m_processKeyCache.Clear();
        m_stats.Reset();
        m_state = ComponentState::NotInitialized;
        SS_LOG_INFO(kLogCategory, L"Shutdown complete");
    }

    [[nodiscard]] bool IsRunning() const noexcept { return m_state == ComponentState::Running; }
    [[nodiscard]] bool IsPaused() const noexcept { return m_state == ComponentState::Paused; }
    [[nodiscard]] ComponentState GetState() const noexcept { return m_state; }

    // ========================================================================
    // CORE ANALYSIS ENGINE -- HOT PATH
    // ========================================================================

    BlockAction AnalyzeBehavior(const ProcessBehavior& behavior) {
        auto startTime = NowSteadyUs();
        m_stats.behaviorsAnalyzed.fetch_add(1, std::memory_order_relaxed);

        // Step 1: State gate
        if (m_state != ComponentState::Running) {
            return BlockAction::Allow;
        }

        // Step 2: Input validation
        if (behavior.processPath.empty()) {
            SS_LOG_WARN(kLogCategory, L"AnalyzeBehavior: empty processPath for PID %u", behavior.processId);
            return BlockAction::Allow;
        }
        if (behavior.processId == kIdlePid || behavior.processId <= kSystemPid) {
            return BlockAction::Allow;
        }

        // Step 3: Fast path -- already blocked PID (with TTL to prevent PID reuse false positives)
        // FIX: BB-N4 - additionally verify the process creation time matches the blocked
        // entry's recorded creationTime; if the PID was reused within the TTL window the
        // creation times will differ and we fall through to normal evaluation.
        // No heap allocations before this check per performance contract
        {
            std::shared_lock blockedLock(m_blockedMutex);
            auto it = m_blockedPids.find(behavior.processId);
            if (it != m_blockedPids.end() &&
                (NowEpochMs() - it->second.blockedAtMs) <= kBlockedPidTtlMs) {
                // Promote shared lock release before potential cache hit to avoid
                // holding the blockedMutex while querying the ProcessUtils API.
                BlockedEntry entry = it->second;
                blockedLock.unlock();

                ProcessKey live = GetProcessKey(behavior.processId);
                // Only short-circuit if creationTime is known and matches.
                // If we cannot resolve a creation time (entry.creationTime == 0 or
                // live.creationTime == 0) we fall back to the legacy PID-only check
                // because a stale block is preferable to under-blocking a confirmed
                // malicious PID within the TTL.
                if (entry.creationTime == 0 ||
                    live.creationTime == 0 ||
                    entry.creationTime == live.creationTime) {
                    RecordAnalysisTime(startTime);
                    return BlockAction::TerminateProcess;
                }
                // PID was reused - purge the stale entry and proceed with eval.
                {
                    std::unique_lock writeLock(m_blockedMutex);
                    auto stale = m_blockedPids.find(behavior.processId);
                    if (stale != m_blockedPids.end() &&
                        stale->second.creationTime == entry.creationTime) {
                        m_blockedPids.erase(stale);
                    }
                }
            }
        }

        // Step 4: Prepare capped + narrowed strings for regex matching (deferred past fast paths)
        const uint32_t maxInput = m_config.regexMaxInputLength;
        std::wstring cappedPath = behavior.processPath;
        CapString(cappedPath, maxInput);
        std::wstring cappedCmdLine = behavior.commandLine;
        CapString(cappedCmdLine, maxInput);
        std::wstring cappedTarget = behavior.target;
        CapString(cappedTarget, maxInput);

        std::string narrowPath   = Utils::StringUtils::ToNarrow(cappedPath);
        std::string narrowCmd    = Utils::StringUtils::ToNarrow(cappedCmdLine);
        std::string narrowTarget = Utils::StringUtils::ToNarrow(cappedTarget);

        // Step 5: Exclusion check
        if (IsExcluded(behavior, narrowPath, narrowCmd, narrowTarget)) {
            m_stats.exclusionsMatched.fetch_add(1, std::memory_order_relaxed);
            RecordAnalysisTime(startTime);
            return BlockAction::Allow;
        }

        // Step 6: Rule evaluation
        BlockAction resultAction = BlockAction::Allow;
        std::string matchingRuleId;
        std::string matchDetails;
        std::string matchMitreId;

        {
            std::shared_lock ruleLock(m_ruleMutex);
            for (const auto& compiled : m_rules) {
                if (!compiled.valid) continue;
                const auto& rule = compiled.rule;
                if (!rule.enabled) continue;

                if (rule.expiryTimestamp.has_value()) {
                    if (NowEpochMs() > rule.expiryTimestamp.value()) continue;
                }

                m_stats.rulesEvaluated.fetch_add(1, std::memory_order_relaxed);

                if (rule.targetType != behavior.type) continue;
                if (static_cast<int>(behavior.risk) < static_cast<int>(rule.minRiskLevel)) continue;

                bool matched = false;
                try {
                    if (compiled.targetRegex && std::regex_search(narrowTarget, *compiled.targetRegex)) {
                        matched = true;
                    }
                } catch (const std::exception& ex) {
                    SS_LOG_ERROR(kLogCategory, L"Rule %hs regex failure: %hs", rule.ruleId.c_str(), ex.what());
                    m_stats.analysisFailures.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }

                if (matched) {
                    if (static_cast<int>(rule.action) > static_cast<int>(resultAction)) {
                        resultAction   = rule.action;
                        matchingRuleId = rule.ruleId;
                        matchDetails   = "Matched pattern: " + rule.targetPattern;
                        matchMitreId   = rule.mitreAttackId;
                    }
                    if (resultAction == BlockAction::TerminateProcess) break;
                }
            }
        }

        // Step 6: Temporal correlation
        if (m_config.enableTemporalCorrelation) {
            BlockAction escalated = UpdateBehaviorChain(behavior, resultAction, matchingRuleId);
            if (static_cast<int>(escalated) > static_cast<int>(resultAction)) {
                resultAction   = escalated;
                matchDetails  += " [CHAIN-ESCALATED]";
                if (matchingRuleId.empty()) matchingRuleId = "CHAIN_ESCALATION";
            }
        }

        // Step 7: Execute action
        bool actionSucceeded = true;
        if (resultAction != BlockAction::Allow && resultAction != BlockAction::LogOnly) {
            actionSucceeded = HandleBlockAction(behavior, resultAction, matchingRuleId, matchDetails, matchMitreId);
        }

        // Step 8: Record event
        if (resultAction != BlockAction::Allow) {
            RecordBlockEvent(behavior, resultAction, matchingRuleId, matchDetails, actionSucceeded);
        }

        // Step 9: Invoke callbacks (NO locks held)
        if (resultAction != BlockAction::Allow) {
            BlockEvent evt{};
            evt.timestamp       = NowEpochMs();
            evt.processId       = behavior.processId;
            evt.processPath     = behavior.processPath;
            evt.behaviorType    = behavior.type;
            evt.actionTaken     = resultAction;
            evt.ruleId          = matchingRuleId;
            evt.details         = matchDetails;
            evt.correlationId   = behavior.correlationId;
            evt.actionSucceeded = actionSucceeded;
            InvokeCallbacks(evt);
        }

        // Step 10: Update stats
        RecordAnalysisTime(startTime);
        return resultAction;
    }

    // ========================================================================
    // KERNEL EVENT HANDLING
    // ========================================================================

    BlockAction OnKernelBehavioralAlert(BehaviorType type, std::span<const uint8_t> payload) {
        m_stats.kernelEventsReceived.fetch_add(1, std::memory_order_relaxed);

        constexpr size_t kMinPayload = sizeof(uint32_t) * 2;
        if (payload.size() < kMinPayload) {
            SS_LOG_WARN(kLogCategory, L"Kernel payload too small: %zu bytes (min %zu)", payload.size(), kMinPayload);
            return BlockAction::Allow;
        }

        uint32_t pid = 0;
        uint32_t parentPid = 0;
        std::memcpy(&pid, payload.data(), sizeof(uint32_t));
        std::memcpy(&parentPid, payload.data() + sizeof(uint32_t), sizeof(uint32_t));

        SS_LOG_DEBUG(kLogCategory, L"Kernel alert: type=%hs pid=%u ppid=%u payload=%zu bytes",
            BehaviorTypeToString(type), pid, parentPid, payload.size());

        ProcessBehavior mapped{};
        mapped.processId   = pid;
        mapped.parentPid   = parentPid;
        mapped.type        = type;
        mapped.risk        = RiskLevel::High;
        mapped.timestamp   = NowEpochMs();

        auto pathOpt = Utils::ProcessUtils::GetProcessPath(pid);
        if (pathOpt.has_value()) {
            mapped.processPath = pathOpt.value();
        } else {
            mapped.processPath = L"<kernel-event>";
        }

        return AnalyzeBehavior(mapped);
    }

    // ========================================================================
    // PROCESS ENFORCEMENT
    // ========================================================================

    bool BlockProcess(uint32_t pid, const std::string& reason) {
        if (pid == kIdlePid || pid <= kSystemPid) {
            SS_LOG_WARN(kLogCategory, L"Refusing to block system PID %u", pid);
            return false;
        }
        if (IsCriticalProcess(pid)) {
            SS_LOG_ERROR(kLogCategory, L"Refusing to block critical PID %u: %hs", pid, reason.c_str());
            return false;
        }

        SS_LOG_INFO(kLogCategory, L"Manual block for PID %u: %hs", pid, reason.c_str());
        {
            // FIX: BB-N4 - record creation time alongside block timestamp.
            ProcessKey key = GetProcessKey(pid);
            std::unique_lock blockedLock(m_blockedMutex);
            m_blockedPids[pid] = BlockedEntry{ key.creationTime, NowEpochMs() };
        }

        BlockEvent evt{};
        evt.timestamp    = NowEpochMs();
        evt.processId    = pid;
        evt.behaviorType = BehaviorType::Unknown;
        evt.actionTaken  = BlockAction::TerminateProcess;
        evt.ruleId       = "MANUAL_BLOCK";
        evt.details      = reason;
        evt.actionSucceeded = TerminateProcessInternal(pid);

        {
            std::unique_lock histLock(m_historyMutex);
            AppendHistory(evt);
        }
        InvokeCallbacks(evt);
        return evt.actionSucceeded;
    }

    bool TerminateProcess(uint32_t pid) { return TerminateProcessInternal(pid); }

    bool SuspendProcess(uint32_t pid) {
        if (pid == kIdlePid || pid <= kSystemPid) return false;
        if (IsCriticalProcess(pid)) {
            SS_LOG_ERROR(kLogCategory, L"Refusing to suspend critical PID %u", pid);
            return false;
        }
        Utils::ProcessUtils::Error err;
        if (Utils::ProcessUtils::SuspendProcess(pid, &err)) {
            m_stats.processesSuspended.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(kLogCategory, L"Suspended PID %u", pid);
            return true;
        }
        SS_LOG_ERROR(kLogCategory, L"Failed to suspend PID %u: %ls", pid, err.message.c_str());
        return false;
    }

    bool IsBlocked(uint32_t pid) const {
        std::shared_lock blockedLock(m_blockedMutex);
        auto it = m_blockedPids.find(pid);
        return it != m_blockedPids.end() &&
               (NowEpochMs() - it->second.blockedAtMs) <= kBlockedPidTtlMs;
    }

    // ========================================================================
    // RULE MANAGEMENT
    // ========================================================================

    bool AddRule(const BehaviorRule& rule) {
        if (rule.ruleId.empty()) {
            SS_LOG_WARN(kLogCategory, L"AddRule: empty ruleId rejected");
            return false;
        }
        std::unique_lock ruleLock(m_ruleMutex);
        if (m_rules.size() >= m_config.maxRules) {
            SS_LOG_WARN(kLogCategory, L"AddRule: max rules limit (%u)", m_config.maxRules);
            return false;
        }
        for (const auto& r : m_rules) {
            if (r.rule.ruleId == rule.ruleId) {
                SS_LOG_WARN(kLogCategory, L"AddRule: duplicate ruleId '%hs'", rule.ruleId.c_str());
                return false;
            }
        }
        CompiledRule compiled;
        compiled.rule = rule;
        try {
            if (!rule.targetPattern.empty()) {
                compiled.targetRegex = std::make_unique<std::regex>(
                    rule.targetPattern, std::regex::icase | std::regex::optimize | std::regex::nosubs);
            }
            compiled.valid = true;
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(kLogCategory, L"Regex compile failed for rule '%hs': %hs", rule.ruleId.c_str(), ex.what());
            return false;
        }
        auto insertPos = std::lower_bound(m_rules.begin(), m_rules.end(), compiled,
            [](const CompiledRule& a, const CompiledRule& b) { return a.rule.priority > b.rule.priority; });
        m_rules.insert(insertPos, std::move(compiled));
        SS_LOG_INFO(kLogCategory, L"Added rule '%hs' (prio=%d action=%hs MITRE=%hs)",
            rule.ruleId.c_str(), rule.priority, BlockActionToString(rule.action), rule.mitreAttackId.c_str());
        return true;
    }

    bool RemoveRule(const std::string& ruleId) {
        std::unique_lock ruleLock(m_ruleMutex);
        auto it = std::remove_if(m_rules.begin(), m_rules.end(),
            [&](const CompiledRule& r) { return r.rule.ruleId == ruleId; });
        if (it != m_rules.end()) {
            m_rules.erase(it, m_rules.end());
            SS_LOG_INFO(kLogCategory, L"Removed rule '%hs'", ruleId.c_str());
            return true;
        }
        return false;
    }

    bool EnableRule(const std::string& ruleId) {
        std::unique_lock ruleLock(m_ruleMutex);
        for (auto& c : m_rules) {
            if (c.rule.ruleId == ruleId) { c.rule.enabled = true; return true; }
        }
        return false;
    }

    bool DisableRule(const std::string& ruleId) {
        std::unique_lock ruleLock(m_ruleMutex);
        for (auto& c : m_rules) {
            if (c.rule.ruleId == ruleId) { c.rule.enabled = false; return true; }
        }
        return false;
    }

    void ClearRules() {
        std::unique_lock ruleLock(m_ruleMutex);
        size_t n = m_rules.size();
        m_rules.clear();
        SS_LOG_INFO(kLogCategory, L"Cleared %zu rules", n);
    }

    void LoadDefaultRules() {
        std::unique_lock ruleLock(m_ruleMutex);
        LoadDefaultRulesInternal();
    }

    bool LoadRulesFromFile(const std::filesystem::path& filePath) {
        if (!fs::exists(filePath)) {
            SS_LOG_ERROR(kLogCategory, L"Rules file not found: %ls", filePath.c_str());
            return false;
        }
        try {
            std::ifstream ifs(filePath);
            if (!ifs.is_open()) {
                SS_LOG_ERROR(kLogCategory, L"Cannot open rules file: %ls", filePath.c_str());
                return false;
            }
            json j;
            ifs >> j;
            if (!j.is_array()) {
                SS_LOG_ERROR(kLogCategory, L"Rules file must be JSON array: %ls", filePath.c_str());
                return false;
            }
            uint32_t loaded = 0, failed = 0;
            for (const auto& jRule : j) {
                BehaviorRule rule;
                try {
                    rule.ruleId        = jRule.value("ruleId", "");
                    rule.description   = jRule.value("description", "");
                    rule.targetType    = static_cast<BehaviorType>(jRule.value("targetType", 0));
                    rule.targetPattern = jRule.value("targetPattern", "");
                    rule.minRiskLevel  = static_cast<RiskLevel>(jRule.value("minRiskLevel", 0));
                    rule.action        = static_cast<BlockAction>(jRule.value("action", 0));
                    rule.priority      = jRule.value("priority", 0);
                    rule.enabled       = jRule.value("enabled", true);
                    rule.mitreAttackId = jRule.value("mitreAttackId", "");
                    if (jRule.contains("expiryTimestamp") && !jRule["expiryTimestamp"].is_null()) {
                        rule.expiryTimestamp = jRule["expiryTimestamp"].get<int64_t>();
                    }
                    if (AddRule(rule)) ++loaded; else ++failed;
                } catch (const std::exception& ex) {
                    SS_LOG_ERROR(kLogCategory, L"Failed to parse rule: %hs", ex.what());
                    ++failed;
                }
            }
            SS_LOG_INFO(kLogCategory, L"Loaded %u rules from file (failed: %u): %ls", loaded, failed, filePath.c_str());
            return loaded > 0;
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(kLogCategory, L"Exception loading rules: %hs", ex.what());
            return false;
        }
    }

    bool PushRulesToKernel() {
        std::shared_lock ruleLock(m_ruleMutex);
        uint32_t count = static_cast<uint32_t>(m_rules.size());
        SS_LOG_INFO(kLogCategory, L"PushRulesToKernel: %u rules queued for kernel sync", count);
        return true;
    }

    // ========================================================================
    // EXCLUSION MANAGEMENT
    // ========================================================================

    bool AddExclusion(const BehaviorExclusion& exclusion) {
        if (exclusion.exclusionId.empty()) {
            SS_LOG_WARN(kLogCategory, L"AddExclusion: empty exclusionId");
            return false;
        }
        // FIX: BB-N5 - reject "match-everything" exclusions where every pattern
        // field is empty AND no specific behavior types are listed. IsExcluded's
        // "all-fields match" semantics treat empty patterns as wildcards, so an
        // exclusion with no constraints whatsoever would whitelist *every*
        // behavior from *every* process - a catastrophic bypass primitive if
        // such an entry were ever produced (config corruption, parser bug,
        // attacker-controlled exclusion file). At least one constraint must
        // be present.
        if (exclusion.processPathPattern.empty() &&
            exclusion.commandLinePattern.empty() &&
            exclusion.targetPattern.empty() &&
            !exclusion.behaviorType.has_value()) {
            SS_LOG_ERROR(kLogCategory,
                L"AddExclusion: refusing wildcard exclusion '%hs' "
                L"(all pattern fields are empty and no behaviorType filter set)",
                exclusion.exclusionId.c_str());
            return false;
        }
        std::unique_lock exclLock(m_exclusionMutex);
        if (m_exclusions.size() >= m_config.maxExclusions) {
            SS_LOG_WARN(kLogCategory, L"AddExclusion: limit reached (%u)", m_config.maxExclusions);
            return false;
        }
        for (const auto& e : m_exclusions) {
            if (e.exclusion.exclusionId == exclusion.exclusionId) {
                SS_LOG_WARN(kLogCategory, L"AddExclusion: duplicate '%hs'", exclusion.exclusionId.c_str());
                return false;
            }
        }
        CompiledExclusion compiled;
        compiled.exclusion = exclusion;
        try {
            if (!exclusion.processPathPattern.empty())
                compiled.pathRegex = std::make_unique<std::regex>(exclusion.processPathPattern, std::regex::icase | std::regex::optimize | std::regex::nosubs);
            if (!exclusion.commandLinePattern.empty())
                compiled.cmdLineRegex = std::make_unique<std::regex>(exclusion.commandLinePattern, std::regex::icase | std::regex::optimize | std::regex::nosubs);
            if (!exclusion.targetPattern.empty())
                compiled.targetRegex = std::make_unique<std::regex>(exclusion.targetPattern, std::regex::icase | std::regex::optimize | std::regex::nosubs);
            compiled.valid = true;
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(kLogCategory, L"Exclusion regex compile failed '%hs': %hs", exclusion.exclusionId.c_str(), ex.what());
            return false;
        }
        m_exclusions.push_back(std::move(compiled));
        SS_LOG_INFO(kLogCategory, L"Added exclusion '%hs'", exclusion.exclusionId.c_str());
        return true;
    }

    bool RemoveExclusion(const std::string& exclusionId) {
        std::unique_lock exclLock(m_exclusionMutex);
        auto it = std::remove_if(m_exclusions.begin(), m_exclusions.end(),
            [&](const CompiledExclusion& e) { return e.exclusion.exclusionId == exclusionId; });
        if (it != m_exclusions.end()) {
            m_exclusions.erase(it, m_exclusions.end());
            SS_LOG_INFO(kLogCategory, L"Removed exclusion '%hs'", exclusionId.c_str());
            return true;
        }
        return false;
    }

    // ========================================================================
    // CALLBACK MANAGEMENT
    // ========================================================================

    uint64_t RegisterBlockCallback(std::function<void(const BlockEvent&)> callback) {
        if (!callback) return 0;
        uint64_t id = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
        {
            std::unique_lock cbLock(m_callbackMutex);
            m_blockCallbacks[id] = std::move(callback);
        }
        return id;
    }

    bool UnregisterBlockCallback(uint64_t callbackId) {
        std::unique_lock cbLock(m_callbackMutex);
        return m_blockCallbacks.erase(callbackId) > 0;
    }

    // ========================================================================
    // MONITORING & STATISTICS
    // ========================================================================

    [[nodiscard]] std::vector<BlockEvent> GetRecentEvents(size_t limit) const {
        std::shared_lock histLock(m_historyMutex);
        std::vector<BlockEvent> result;
        size_t count = std::min(limit, m_history.size());
        result.reserve(count);
        auto it = m_history.rbegin();
        for (size_t i = 0; i < count && it != m_history.rend(); ++i, ++it) {
            result.push_back(*it);
        }
        return result;
    }

    [[nodiscard]] BehaviorBlockerStats GetStatistics() const {
        const int64_t nowEpochMs = NowEpochMs();
        uint32_t ruleCount = 0;
        uint32_t exclCount = 0;

        {
            std::shared_lock rl(m_ruleMutex);
            for (const auto& compiled : m_rules) {
                if (!compiled.valid || !compiled.rule.enabled) {
                    continue;
                }

                if (compiled.rule.expiryTimestamp.has_value() &&
                    nowEpochMs > compiled.rule.expiryTimestamp.value()) {
                    continue;
                }

                ++ruleCount;
            }
        }

        {
            std::shared_lock el(m_exclusionMutex);
            for (const auto& compiled : m_exclusions) {
                if (!compiled.valid) {
                    continue;
                }

                if (compiled.exclusion.expiryTimestamp.has_value() &&
                    nowEpochMs > compiled.exclusion.expiryTimestamp.value()) {
                    continue;
                }

                ++exclCount;
            }
        }

        return m_stats.Snapshot(ruleCount, exclCount);
    }

    [[nodiscard]] std::string GetStatisticsJson() const {
        auto s = GetStatistics();
        try {
            json j;
            j["behaviorsAnalyzed"]    = s.behaviorsAnalyzed;
            j["threatsBlocked"]       = s.threatsBlocked;
            j["processesTerminated"]  = s.processesTerminated;
            j["processesSuspended"]   = s.processesSuspended;
            j["rulesEvaluated"]       = s.rulesEvaluated;
            j["analysisFailures"]     = s.analysisFailures;
            j["exclusionsMatched"]    = s.exclusionsMatched;
            j["totalAnalysisTimeUs"]  = s.totalAnalysisTimeUs;
            j["kernelEventsReceived"] = s.kernelEventsReceived;
            j["behaviorChainsActive"] = s.behaviorChainsActive;
            j["activeRuleCount"]      = s.activeRuleCount;
            j["activeExclusionCount"] = s.activeExclusionCount;
            j["state"]                = ComponentStateToString(m_state);
            return j.dump();
        } catch (...) {
            return "{}";
        }
    }

    // ========================================================================
    // SELF-TEST
    // ========================================================================

    bool SelfTest() {
        SS_LOG_INFO(kLogCategory, L"SelfTest: starting diagnostic checks");
        bool allPassed = true;

        // Test 1: Rule add/remove cycle
        {
            BehaviorRule testRule{};
            testRule.ruleId       = "SELFTEST_RULE_001";
            testRule.description  = "Self-test rule";
            testRule.targetType   = BehaviorType::FileModification;
            testRule.targetPattern = ".*selftest_target\\.exe$";
            testRule.minRiskLevel = RiskLevel::Low;
            testRule.action       = BlockAction::BlockOperation;
            testRule.priority     = 999;
            testRule.enabled      = true;

            if (!AddRule(testRule)) {
                SS_LOG_ERROR(kLogCategory, L"SelfTest FAILED: cannot add test rule");
                allPassed = false;
            } else {
                if (m_state == ComponentState::Running) {
                    ProcessBehavior tb{};
                    tb.processId   = 99999;
                    tb.processPath = L"C:\\Temp\\selftest.exe";
                    tb.commandLine = L"selftest.exe --verify";
                    tb.type        = BehaviorType::FileModification;
                    tb.target      = L"C:\\Windows\\selftest_target.exe";
                    tb.risk        = RiskLevel::Low;
                    tb.timestamp   = NowEpochMs();

                    BlockAction result = AnalyzeBehavior(tb);
                    if (result != BlockAction::BlockOperation) {
                        SS_LOG_ERROR(kLogCategory, L"SelfTest FAILED: expected BlockOperation got %hs",
                            BlockActionToString(result));
                        allPassed = false;
                    }
                }
                if (!RemoveRule("SELFTEST_RULE_001")) {
                    SS_LOG_ERROR(kLogCategory, L"SelfTest FAILED: cannot remove test rule");
                    allPassed = false;
                }
            }
        }

        // Test 2: Exclusion add/remove
        {
            BehaviorExclusion te{};
            te.exclusionId        = "SELFTEST_EXCL_001";
            te.processPathPattern = ".*selftest_excluded\\.exe$";
            te.description        = "Self-test exclusion";
            if (!AddExclusion(te)) {
                SS_LOG_ERROR(kLogCategory, L"SelfTest FAILED: cannot add exclusion");
                allPassed = false;
            } else if (!RemoveExclusion("SELFTEST_EXCL_001")) {
                SS_LOG_ERROR(kLogCategory, L"SelfTest FAILED: cannot remove exclusion");
                allPassed = false;
            }
        }

        // Test 3: Callback register/unregister
        {
            auto id = RegisterBlockCallback([](const BlockEvent&) {});
            if (id == 0 || !UnregisterBlockCallback(id)) {
                SS_LOG_ERROR(kLogCategory, L"SelfTest FAILED: callback lifecycle");
                allPassed = false;
            }
        }

        // Test 4: Critical process protection
        {
            if (!IsCriticalProcess(kSystemPid)) {
                SS_LOG_ERROR(kLogCategory, L"SelfTest FAILED: PID 4 not critical");
                allPassed = false;
            }
        }

        // Test 5: Statistics snapshot
        { auto s = GetStatistics(); (void)s; }

        if (allPassed) SS_LOG_INFO(kLogCategory, L"SelfTest PASSED");
        else SS_LOG_ERROR(kLogCategory, L"SelfTest FAILED");
        return allPassed;
    }

private:

    ProcessKey GetProcessKey(uint32_t pid) {
        auto cached = m_processKeyCache.Get(pid);
        if (cached.has_value()) return cached.value();
        ProcessKey key{pid, 0};
        Utils::ProcessUtils::ProcessBasicInfo info;
        Utils::ProcessUtils::Error err;
        if (Utils::ProcessUtils::GetProcessBasicInfo(pid, info, &err)) {
            ULARGE_INTEGER ull;
            ull.LowPart  = info.creationTime.dwLowDateTime;
            ull.HighPart = info.creationTime.dwHighDateTime;
            key.creationTime = ull.QuadPart;
        }
        m_processKeyCache.Put(pid, key);
        return key;
    }

    [[nodiscard]] bool IsCriticalProcess(uint32_t pid) const {
        if (pid == kIdlePid || pid == kSystemPid) return true;
        if (pid == ::GetCurrentProcessId()) return true;
        if (Utils::ProcessUtils::IsProcessCritical(pid)) return true;
        auto nameOpt = Utils::ProcessUtils::GetProcessName(pid);
        if (nameOpt.has_value()) {
            std::wstring name = Utils::StringUtils::ToLowerCopy(nameOpt.value());
            static const std::unordered_set<std::wstring> kCritical = {
                L"csrss.exe", L"smss.exe", L"wininit.exe", L"services.exe",
                L"lsass.exe", L"svchost.exe", L"winlogon.exe", L"dwm.exe",
                L"conhost.exe", L"fontdrvhost.exe", L"runtimebroker.exe", L"system"
            };
            if (kCritical.contains(name)) return true;
        }
        return false;
    }

    [[nodiscard]] bool IsExcluded(const ProcessBehavior& behavior,
                                   const std::string& narrowPath,
                                   const std::string& narrowCmd,
                                   const std::string& narrowTarget) const {
        std::shared_lock exclLock(m_exclusionMutex);
        for (const auto& compiled : m_exclusions) {
            if (!compiled.valid) continue;
            const auto& exc = compiled.exclusion;
            if (exc.expiryTimestamp.has_value() && NowEpochMs() > exc.expiryTimestamp.value()) continue;
            if (exc.behaviorType.has_value() && exc.behaviorType.value() != behavior.type) continue;
            bool allMatch = true;
            if (compiled.pathRegex) {
                try { if (!std::regex_search(narrowPath, *compiled.pathRegex)) allMatch = false; }
                catch (...) { allMatch = false; }
            }
            if (allMatch && compiled.cmdLineRegex) {
                try { if (!std::regex_search(narrowCmd, *compiled.cmdLineRegex)) allMatch = false; }
                catch (...) { allMatch = false; }
            }
            if (allMatch && compiled.targetRegex) {
                try { if (!std::regex_search(narrowTarget, *compiled.targetRegex)) allMatch = false; }
                catch (...) { allMatch = false; }
            }
            if (allMatch) return true;
        }
        return false;
    }

    bool HandleBlockAction(const ProcessBehavior& behavior, BlockAction action,
                           const std::string& ruleId, const std::string& details,
                           const std::string& mitreId) {
        bool success = true;
        switch (action) {
            case BlockAction::TerminateProcess:
                success = TerminateProcessInternal(behavior.processId);
                if (success)
                    SS_LOG_FATAL(kLogCategory, L"TERMINATED PID %u rule=%hs MITRE=%hs",
                        behavior.processId, ruleId.c_str(), mitreId.c_str());
                break;
            case BlockAction::SuspendProcess: {
                if (IsCriticalProcess(behavior.processId)) {
                    SS_LOG_ERROR(kLogCategory, L"Refusing suspend of critical PID %u", behavior.processId);
                    success = false;
                } else {
                    Utils::ProcessUtils::Error err;
                    if (Utils::ProcessUtils::SuspendProcess(behavior.processId, &err)) {
                        m_stats.processesSuspended.fetch_add(1, std::memory_order_relaxed);
                        SS_LOG_WARN(kLogCategory, L"SUSPENDED PID %u rule=%hs MITRE=%hs",
                            behavior.processId, ruleId.c_str(), mitreId.c_str());
                    } else {
                        SS_LOG_ERROR(kLogCategory, L"Suspend failed PID %u: %ls", behavior.processId, err.message.c_str());
                        success = false;
                    }
                }
                break;
            }
            case BlockAction::BlockOperation:
                SS_LOG_WARN(kLogCategory, L"BLOCKED op from PID %u rule=%hs MITRE=%hs",
                    behavior.processId, ruleId.c_str(), mitreId.c_str());
                break;
            // FIX: BB-N3 - Quarantine and network-isolation enforcement is not yet
            // wired to QuarantineManager / NetworkIsolator backends. Until those
            // managers are integrated, reporting these actions as successful would
            // produce misleading SOC telemetry ("threat blocked") while the
            // offending process continues to execute. Emit an explicit unenforced
            // warning, mark the action as unsuccessful, and do not count it
            // against `threatsBlocked`. The detection event itself is still
            // recorded by the caller (RecordBlockEvent + InvokeCallbacks).
            case BlockAction::QuarantineFile:
                SS_LOG_WARN(kLogCategory,
                    L"QUARANTINE requested but NOT ENFORCED (QuarantineManager not wired) "
                    L"PID=%u rule=%hs MITRE=%hs",
                    behavior.processId, ruleId.c_str(), mitreId.c_str());
                success = false;
                break;
            case BlockAction::IsolateNetwork:
                SS_LOG_WARN(kLogCategory,
                    L"NETWORK ISOLATE requested but NOT ENFORCED (NetworkIsolator not wired) "
                    L"PID=%u rule=%hs MITRE=%hs",
                    behavior.processId, ruleId.c_str(), mitreId.c_str());
                success = false;
                break;
            case BlockAction::AlertOnly:
                SS_LOG_WARN(kLogCategory, L"ALERT: PID %u rule=%hs MITRE=%hs (%hs)",
                    behavior.processId, ruleId.c_str(), mitreId.c_str(), details.c_str());
                break;
            case BlockAction::LogOnly:
                SS_LOG_INFO(kLogCategory, L"LOG: PID %u rule=%hs MITRE=%hs",
                    behavior.processId, ruleId.c_str(), mitreId.c_str());
                break;
            default:
                success = false;
                break;
        }
        // FIX: BB-N3 - only count toward threatsBlocked when an enforcement
        // action actually succeeded (or when the action class is informational
        // by design, i.e. AlertOnly / LogOnly / BlockOperation). This avoids
        // inflating telemetry with failed terminations and unenforced stubs.
        if (success &&
            action != BlockAction::AlertOnly &&
            action != BlockAction::LogOnly) {
            m_stats.threatsBlocked.fetch_add(1, std::memory_order_relaxed);
        }
        return success;
    }

    bool TerminateProcessInternal(uint32_t pid) {
        if (pid == kIdlePid || pid <= kSystemPid) {
            SS_LOG_ERROR(kLogCategory, L"Refusing to terminate system PID %u", pid);
            return false;
        }
        if (IsCriticalProcess(pid)) {
            SS_LOG_ERROR(kLogCategory, L"Refusing to terminate critical PID %u", pid);
            return false;
        }
        try {
            // FIX: BB-N1 - Resolve the ProcessKey BEFORE termination so we can
            // record the original creation time and defend against PID reuse
            // attacks. Once the process exits, the creation time becomes
            // unrecoverable.
            ProcessKey key = GetProcessKey(pid);

            // FIX: BB-N2 - Terminate the entire process tree, not just the
            // root. This matches the header contract and is essential for
            // ransomware/lateral-movement scenarios where the offending PID
            // has already spawned encryption workers or persistence helpers
            // that would otherwise be orphaned and continue executing.
            Utils::ProcessUtils::Error termErr{};
            if (Utils::ProcessUtils::TerminateProcessTree(pid, 0, &termErr)) {
                m_stats.processesTerminated.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_INFO(kLogCategory, L"Terminated process tree rooted at PID %u", pid);
                {
                    std::unique_lock blockedLock(m_blockedMutex);
                    m_blockedPids[pid] = BlockedEntry{ key.creationTime, NowEpochMs() };
                }
                m_processKeyCache.Invalidate(pid);
                return true;
            }
            SS_LOG_ERROR(kLogCategory,
                L"Failed to terminate process tree for PID %u: code=%u msg=%hs",
                pid,
                static_cast<unsigned>(termErr.win32),
                Utils::StringUtils::ToNarrow(termErr.message).c_str());
            return false;
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(kLogCategory, L"Exception terminating PID %u: %hs", pid, ex.what());
            return false;
        }
    }

    BlockAction UpdateBehaviorChain(const ProcessBehavior& behavior,
                                    BlockAction currentAction,
                                    const std::string& ruleId) {
        std::unique_lock chainLock(m_chainMutex);
        int64_t now = NowEpochMs();
        int64_t timeoutMs = static_cast<int64_t>(m_config.behaviorChainTimeoutSec) * 1000;

        // Evict expired chains
        for (auto it = m_behaviorChains.begin(); it != m_behaviorChains.end(); ) {
            if ((now - it->second.lastEventTime) > timeoutMs)
                it = m_behaviorChains.erase(it);
            else ++it;
        }
        m_stats.behaviorChainsActive.store(static_cast<uint64_t>(m_behaviorChains.size()), std::memory_order_relaxed);

        auto& chain = m_behaviorChains[behavior.processId];
        if (chain.processId == 0) {
            chain.processId = behavior.processId;
            chain.firstEventTime = now;
        }
        chain.lastEventTime = now;

        BehaviorChainEntry entry;
        entry.type        = behavior.type;
        entry.actionTaken = currentAction;
        entry.timestamp   = now;
        entry.ruleId      = ruleId;
        entry.riskScore   = RiskToScore(behavior.risk);
        chain.events.push_back(std::move(entry));

        while (!chain.events.empty() && (now - chain.events.front().timestamp) > timeoutMs) {
            chain.events.pop_front();
        }

        // Recalculate composite score with time decay
        chain.compositeScore = 0.0f;
        for (const auto& e : chain.events) {
            float ageSec = static_cast<float>(now - e.timestamp) / 1000.0f;
            float decay  = std::exp(-kDecayLambda * ageSec);
            chain.compositeScore += e.riskScore * decay;
        }

        uint32_t highRiskCount = 0;
        for (const auto& e : chain.events) {
            if (e.riskScore >= RiskToScore(RiskLevel::High)) ++highRiskCount;
        }

        BlockAction escalated = currentAction;
        if (chain.compositeScore >= m_config.escalationThreshold) {
            escalated = BlockAction::TerminateProcess;
            SS_LOG_WARN(kLogCategory, L"CHAIN ESCALATION: PID %u score=%.2f >= %.2f",
                behavior.processId, chain.compositeScore, m_config.escalationThreshold);
        }
        if (highRiskCount >= kChainAutoEscalateCount && escalated != BlockAction::TerminateProcess) {
            escalated = BlockAction::TerminateProcess;
            SS_LOG_WARN(kLogCategory, L"CHAIN ESCALATION: PID %u %u high-risk events",
                behavior.processId, highRiskCount);
        }
        return escalated;
    }

    void RecordBlockEvent(const ProcessBehavior& behavior, BlockAction action,
                          const std::string& ruleId, const std::string& details, bool actionSucceeded) {
        BlockEvent evt{};
        evt.timestamp       = NowEpochMs();
        evt.processId       = behavior.processId;
        evt.processPath     = behavior.processPath;
        evt.behaviorType    = behavior.type;
        evt.actionTaken     = action;
        evt.ruleId          = ruleId;
        evt.details         = details + (actionSucceeded ? "" : " [ACTION_FAILED]");
        evt.correlationId   = behavior.correlationId;
        evt.actionSucceeded = actionSucceeded;
        std::unique_lock histLock(m_historyMutex);
        AppendHistory(evt);
    }

    void AppendHistory(const BlockEvent& evt) {
        m_history.push_back(evt);
        while (m_history.size() > m_config.maxHistoryEvents) {
            m_history.pop_front();
        }
    }

    void InvokeCallbacks(const BlockEvent& evt) {
        std::vector<std::function<void(const BlockEvent&)>> cbCopy;
        {
            std::shared_lock cbLock(m_callbackMutex);
            cbCopy.reserve(m_blockCallbacks.size());
            for (const auto& [id, cb] : m_blockCallbacks) cbCopy.push_back(cb);
        }
        for (const auto& cb : cbCopy) {
            try { cb(evt); }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(kLogCategory, L"Callback exception: %hs", ex.what());
            } catch (...) {
                SS_LOG_ERROR(kLogCategory, L"Callback unknown exception");
            }
        }
    }

    void RecordAnalysisTime(int64_t startUs) noexcept {
        int64_t elapsed = NowSteadyUs() - startUs;
        if (elapsed > 0)
            m_stats.totalAnalysisTimeUs.fetch_add(static_cast<uint64_t>(elapsed), std::memory_order_relaxed);
    }

    [[nodiscard]] uint32_t GetRuleCountInternal() const noexcept {
        return static_cast<uint32_t>(m_rules.size());
    }

    // ========================================================================
    // DEFAULT RULES -- 15 MITRE ATT&CK technique detections
    // ========================================================================

    void LoadDefaultRulesInternal() {
        m_rules.clear();

        auto addRule = [&](const char* id, const char* desc, BehaviorType type,
                           const char* pattern, RiskLevel risk, BlockAction action,
                           int32_t priority, const char* mitre) {
            CompiledRule c;
            c.rule.ruleId         = id;
            c.rule.description    = desc;
            c.rule.targetType     = type;
            c.rule.targetPattern  = pattern;
            c.rule.minRiskLevel   = risk;
            c.rule.action         = action;
            c.rule.priority       = priority;
            c.rule.enabled        = true;
            c.rule.mitreAttackId  = mitre;
            try {
                c.targetRegex = std::make_unique<std::regex>(pattern,
                    std::regex::icase | std::regex::optimize | std::regex::nosubs);
                c.valid = true;
            } catch (const std::exception& ex) {
                SS_LOG_ERROR(kLogCategory, L"Default rule '%hs' regex failed: %hs", id, ex.what());
                c.valid = false;
            }
            auto pos = std::lower_bound(m_rules.begin(), m_rules.end(), c,
                [](const CompiledRule& a, const CompiledRule& b) { return a.rule.priority > b.rule.priority; });
            m_rules.insert(pos, std::move(c));
        };

        // T1486 - Data Encrypted for Impact
        addRule("RANSOM_EXT_001", "Known ransomware file extension write",
            BehaviorType::FileModification,
            ".*\\.(lock|locked|crypt|crypted|crypto|enc|encrypted|ryuk|wannacry|wcry|wncry|"
            "locky|cerber|zepto|odin|thor|dharma|phobos|maze|conti|revil|sodinokibi|"
            "lockbit|blackcat|alphv|medusa|clop|royal|akira|play|blackbasta|rhysida|8base)$",
            RiskLevel::High, BlockAction::TerminateProcess, 100, "T1486");

        // T1003.001 - LSASS credential access
        addRule("CRED_THEFT_001", "Access to LSASS memory",
            BehaviorType::CredentialAccess, ".*lsass\\.exe.*",
            RiskLevel::Critical, BlockAction::TerminateProcess, 100, "T1003.001");

        // T1490 - Inhibit System Recovery
        addRule("RECOVERY_DEL_001", "Shadow copy or recovery deletion",
            BehaviorType::ShadowCopyDeletion,
            ".*(vssadmin|wmic|diskshadow|bcdedit|wbadmin).*(delete|shadows|recoveryenabled).*",
            RiskLevel::High, BlockAction::TerminateProcess, 95, "T1490");

        // T1547.001 - Registry Run Keys
        addRule("PERSIST_REG_001", "Registry Run key persistence",
            BehaviorType::RegistryModification,
            ".*(CurrentVersion\\\\Run|Policies\\\\Explorer\\\\Run|"
            "CurrentVersion\\\\RunOnce|CurrentVersion\\\\RunServices).*",
            RiskLevel::Medium, BlockAction::BlockOperation, 70, "T1547.001");

        // T1543.003 - Driver Loading
        addRule("DRIVER_LOAD_001", "Kernel driver load attempt",
            BehaviorType::DriverLoading, ".*\\.sys$",
            RiskLevel::High, BlockAction::BlockOperation, 80, "T1543.003");

        // T1059 - Scripting Interpreter
        addRule("SCRIPT_EXEC_001", "Script interpreter execution",
            BehaviorType::ScriptExecution,
            ".*(powershell|pwsh|wscript|cscript|mshta|cmd\\.exe).*",
            RiskLevel::Medium, BlockAction::AlertOnly, 50, "T1059");

        // T1055 - Process Injection
        addRule("INJECT_001", "Process injection detected",
            BehaviorType::ProcessInjection, ".*",
            RiskLevel::High, BlockAction::TerminateProcess, 90, "T1055");

        // T1546.003 - WMI Event Subscription
        addRule("WMI_PERSIST_001", "WMI persistence via event subscription",
            BehaviorType::WMIActivity,
            ".*(subscription|consumer|binding|__EventFilter|CommandLineEventConsumer).*",
            RiskLevel::High, BlockAction::BlockOperation, 75, "T1546.003");

        // T1570 - Lateral Tool Transfer
        addRule("LATERAL_001", "Lateral movement tool detected",
            BehaviorType::LateralMovement,
            ".*(psexec|psexesvc|wmic|winrm|smbexec|atexec|dcomexec|schtasks).*",
            RiskLevel::High, BlockAction::BlockOperation, 80, "T1570");

        // T1574.001 - DLL Side-loading
        addRule("DLL_SIDE_001", "DLL side-loading from suspicious path",
            BehaviorType::DLLSideloading,
            ".*(\\\\temp\\\\|\\\\appdata\\\\|\\\\downloads\\\\|"
            "\\\\public\\\\|\\\\programdata\\\\).*\\.dll$",
            RiskLevel::High, BlockAction::BlockOperation, 75, "T1574.001");

        // T1570 - Named Pipe C2
        addRule("NAMED_PIPE_001", "Known C2 framework named pipe",
            BehaviorType::NamedPipeCreation,
            ".*(MSSE-|msagent_|postex_|status_|ntsvcs|scerpc|samr|lsarpc|"
            "netlogon|cobalt|beacon|meterpreter|havoc|sliver).*",
            RiskLevel::High, BlockAction::AlertOnly, 60, "T1570");

        // T1134 - Access Token Manipulation
        addRule("PRIV_ESC_001", "Token manipulation for privilege escalation",
            BehaviorType::PrivilegeEscalation,
            ".*(token|impersonat|privilege|SeDebug|SeTcb|SeAssignPrimary|SeImpersonate|potato).*",
            RiskLevel::Critical, BlockAction::TerminateProcess, 100, "T1134");

        // T1562 - Impair Defenses
        addRule("DEFENSE_EVASION_001", "Defense evasion / AV tampering",
            BehaviorType::DefenseEvasion,
            ".*(tamper|disable|uninstall|kill|stop).*(defender|shadowstrike|antivirus|"
            "firewall|security|protection|edr|av).*",
            RiskLevel::Critical, BlockAction::TerminateProcess, 100, "T1562");

        // T1041 - Exfiltration Over C2
        addRule("EXFIL_001", "Data exfiltration indicator",
            BehaviorType::DataExfiltration,
            ".*(upload|exfil|transfer|send|post|mega\\.nz|pastebin|discord\\.com|"
            "telegram|rclone|curl.*-d|certutil.*urlcache).*",
            RiskLevel::High, BlockAction::BlockOperation, 70, "T1041");

        // T1055.012 - Process Hollowing / RWX Memory
        addRule("MEMORY_001", "Suspicious RWX memory allocation",
            BehaviorType::MemoryManipulation,
            ".*(rwx|PAGE_EXECUTE_READWRITE|VirtualAlloc.*40|NtAllocateVirtualMemory).*",
            RiskLevel::High, BlockAction::AlertOnly, 65, "T1055.012");

        SS_LOG_INFO(kLogCategory, L"Loaded %u default rules", static_cast<unsigned>(m_rules.size()));
    }

    // ========================================================================
    // MEMBER DATA
    // ========================================================================

    std::atomic<ComponentState> m_state{ComponentState::NotInitialized};
    mutable std::shared_mutex   m_stateMutex;
    BehaviorBlockerConfig       m_config{};

    mutable std::shared_mutex       m_ruleMutex;
    std::vector<CompiledRule>       m_rules;

    mutable std::shared_mutex       m_exclusionMutex;
    std::vector<CompiledExclusion>  m_exclusions;

    mutable std::shared_mutex       m_chainMutex;
    std::unordered_map<uint32_t, ProcessBehaviorChain> m_behaviorChains;

    mutable std::shared_mutex       m_blockedMutex;
    // FIX: BB-N4 - see BlockedEntry. PID -> {creationTime, blockedAtMs}.
    std::unordered_map<uint32_t, BlockedEntry> m_blockedPids;

    mutable std::shared_mutex       m_historyMutex;
    std::deque<BlockEvent>          m_history;

    mutable std::shared_mutex       m_callbackMutex;
    std::unordered_map<uint64_t, std::function<void(const BlockEvent&)>> m_blockCallbacks;
    std::atomic<uint64_t>           m_nextCallbackId{1};

    InternalStats                   m_stats;
    ProcessKeyCache                 m_processKeyCache;
};

// ============================================================================
// SINGLETON WRAPPER -- Meyers' Singleton
// ============================================================================

BehaviorBlocker& BehaviorBlocker::Instance() noexcept {
    static BehaviorBlocker instance;
    return instance;
}

BehaviorBlocker::BehaviorBlocker() : m_impl(std::make_unique<BehaviorBlockerImpl>()) {
    SS_LOG_INFO(kLogCategory, L"BehaviorBlocker singleton constructed");
}

BehaviorBlocker::~BehaviorBlocker() {
    SS_LOG_INFO(kLogCategory, L"BehaviorBlocker singleton destroyed");
}

// ---- Lifecycle ----

bool BehaviorBlocker::Initialize(const BehaviorBlockerConfig& config) {
    return m_impl->Initialize(config);
}

bool BehaviorBlocker::Start() {
    return m_impl->Start();
}

void BehaviorBlocker::Stop() {
    m_impl->Stop();
}

void BehaviorBlocker::Pause() {
    m_impl->Pause();
}

void BehaviorBlocker::Resume() {
    m_impl->Resume();
}

void BehaviorBlocker::Shutdown() {
    m_impl->Shutdown();
}

bool BehaviorBlocker::IsRunning() const noexcept {
    try { return m_impl->IsRunning(); }
    catch (...) { return false; }
}

bool BehaviorBlocker::IsPaused() const noexcept {
    try { return m_impl->IsPaused(); }
    catch (...) { return false; }
}

ComponentState BehaviorBlocker::GetState() const noexcept {
    try { return m_impl->GetState(); }
    catch (...) { return ComponentState::Error; }
}

// ---- Core Analysis ----

BlockAction BehaviorBlocker::AnalyzeBehavior(const ProcessBehavior& behavior) {
    return m_impl->AnalyzeBehavior(behavior);
}

// ---- Kernel Integration ----

void BehaviorBlocker::OnKernelBehavioralAlert(uint32_t messageType,
                                               std::span<const std::byte> payload) {
    // Convert std::byte span to uint8_t span (guaranteed layout-compatible)
    auto uint8Payload = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(payload.data()), payload.size());

    // Extract behavior type from payload (third uint32_t field)
    BehaviorType type = BehaviorType::Unknown;
    if (payload.size() >= sizeof(uint32_t) * 3) {
        uint32_t typeValue = 0;
        std::memcpy(&typeValue, payload.data() + sizeof(uint32_t) * 2, sizeof(uint32_t));
        if (typeValue <= static_cast<uint32_t>(BehaviorType::Discovery)) {
            type = static_cast<BehaviorType>(typeValue);
        }
    }

    (void)messageType; // Already validated by caller (RTP dispatcher)
    m_impl->OnKernelBehavioralAlert(type, uint8Payload);
}

// ---- Process Control ----

bool BehaviorBlocker::BlockProcess(uint32_t pid, const std::wstring& reason) {
    return m_impl->BlockProcess(pid, Utils::StringUtils::ToNarrow(reason));
}

bool BehaviorBlocker::TerminateProcess(uint32_t pid) {
    return m_impl->TerminateProcess(pid);
}

bool BehaviorBlocker::SuspendProcess(uint32_t pid) {
    return m_impl->SuspendProcess(pid);
}

bool BehaviorBlocker::IsBlocked(uint32_t pid) const noexcept {
    try { return m_impl->IsBlocked(pid); }
    catch (...) { return false; }
}

// ---- Rule Management ----

bool BehaviorBlocker::AddRule(const BehaviorRule& rule) {
    return m_impl->AddRule(rule);
}

bool BehaviorBlocker::RemoveRule(const std::string& ruleId) {
    return m_impl->RemoveRule(ruleId);
}

bool BehaviorBlocker::EnableRule(const std::string& ruleId) {
    return m_impl->EnableRule(ruleId);
}

bool BehaviorBlocker::DisableRule(const std::string& ruleId) {
    return m_impl->DisableRule(ruleId);
}

bool BehaviorBlocker::ClearRules() {
    m_impl->ClearRules();
    return true;
}

bool BehaviorBlocker::LoadDefaultRules() {
    m_impl->LoadDefaultRules();
    return true;
}

bool BehaviorBlocker::LoadRulesFromFile(const std::filesystem::path& path) {
    return m_impl->LoadRulesFromFile(path);
}

bool BehaviorBlocker::PushRulesToKernel() {
    return m_impl->PushRulesToKernel();
}

// ---- Exclusion Management ----

bool BehaviorBlocker::AddExclusion(const BehaviorExclusion& exclusion) {
    return m_impl->AddExclusion(exclusion);
}

bool BehaviorBlocker::RemoveExclusion(const std::string& exclusionId) {
    return m_impl->RemoveExclusion(exclusionId);
}

// ---- Callback Management ----

uint64_t BehaviorBlocker::RegisterBlockCallback(BlockEventCallback callback) {
    return m_impl->RegisterBlockCallback(std::move(callback));
}

void BehaviorBlocker::UnregisterBlockCallback(uint64_t callbackId) {
    m_impl->UnregisterBlockCallback(callbackId);
}

// ---- Monitoring & Statistics ----

std::vector<BlockEvent> BehaviorBlocker::GetRecentEvents(size_t limit) const {
    return m_impl->GetRecentEvents(limit);
}

BehaviorBlockerStats BehaviorBlocker::GetStatistics() const noexcept {
    try { return m_impl->GetStatistics(); }
    catch (...) { return BehaviorBlockerStats{}; }
}

std::string BehaviorBlocker::GetStatisticsJson() const {
    return m_impl->GetStatisticsJson();
}

// ---- Diagnostics ----

bool BehaviorBlocker::SelfTest() {
    return m_impl->SelfTest();
}

} // namespace ShadowStrike::RealTime
