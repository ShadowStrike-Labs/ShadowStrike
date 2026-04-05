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
 * ShadowStrike Core Engine - BEHAVIOR ANALYZER IMPLEMENTATION
 * ============================================================================
 *
 * @file BehaviorAnalyzer.cpp
 * @brief Enterprise-grade behavioral analysis engine for detecting malicious
 *        activity patterns including ransomware, injection, credential theft,
 *        lateral movement, C2 communication, and multi-stage attack chains.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security. AGPL-3.0 License.
 * ============================================================================
 */

#include "pch.h"
#include "BehaviorAnalyzer.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/Logger.hpp"
#include "../../Utils/ThreadPool.hpp"
#include "../../ThreatIntel/ThreatIntelIndex.hpp"

#include <algorithm>
#include <numeric>
#include <cmath>
#include <cwctype>

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ============================================================================
// Internal Helpers
// ============================================================================

static std::wstring ToLowerCase(std::wstring_view input) {
    std::wstring result(input);
    for (auto& ch : result) ch = std::towlower(ch);
    return result;
}

static bool ContainsCaseInsensitive(std::wstring_view haystack, std::wstring_view needle) {
    if (needle.size() > haystack.size()) return false;
    auto lower_h = ToLowerCase(haystack);
    auto lower_n = ToLowerCase(needle);
    return lower_h.find(lower_n) != std::wstring::npos;
}

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct BehaviorAnalyzer::Impl {
    // Lifecycle
    std::atomic<bool> m_initialized{false};
    std::shared_ptr<Utils::ThreadPool> m_threadPool;

    // Configuration
    mutable std::shared_mutex m_configMutex;
    BehaviorAnalyzerConfig m_config;

    // External dependencies (non-owning)
    ThreatIntel::ThreatIntelIndex* m_threatIntel{nullptr};
    Whitelist::WhitelistStore* m_whitelist{nullptr};
    SignatureStore::SignatureStore* m_signatureStore{nullptr};

    // Process states
    mutable std::shared_mutex m_statesMutex;
    std::unordered_map<uint32_t, ProcessBehaviorState> m_processStates;

    // Attack chains
    mutable std::shared_mutex m_chainsMutex;
    std::vector<BehaviorAttackChain> m_attackChains;
    std::atomic<uint64_t> m_nextChainId{1};

    // Canary files
    mutable std::shared_mutex m_canaryMutex;
    std::unordered_set<std::wstring> m_canaryFiles;

    // Callbacks
    mutable std::shared_mutex m_callbackMutex;
    std::unordered_map<uint64_t, BehaviorVerdictCallback> m_verdictCallbacks;
    std::unordered_map<uint64_t, BehaviorAttackChainCallback> m_chainCallbacks;
    ProcessTerminateCallback m_terminationCallback;
    std::atomic<uint64_t> m_nextCallbackId{1};

    // Statistics
    BehaviorAnalyzerStats m_stats;

    // Event ID generator
    std::atomic<uint64_t> m_nextEventId{1};

    // Cleanup tracking (atomic to avoid data race in ProcessEvent hot path)
    std::atomic<int64_t> m_lastCleanupTimeRep{
        std::chrono::steady_clock::now().time_since_epoch().count()};

    // Known attack patterns (populated during initialization)
    std::unordered_set<std::wstring> m_ransomwareExtensions;
    std::unordered_set<std::wstring> m_persistenceRegistryPaths;
    std::unordered_set<std::wstring> m_credentialTargets;
    std::unordered_set<std::wstring> m_ransomNotePatterns;
    std::unordered_set<std::wstring> m_documentApps;
    std::unordered_set<std::wstring> m_scriptInterpreters;

    Impl() {
        InitializeKnownPatterns();
    }

    void InitializeKnownPatterns() {
        m_ransomwareExtensions = {
            L".encrypted", L".locked", L".crypto", L".crypt", L".locky",
            L".cerber", L".zepto", L".thor", L".aesir", L".osiris",
            L".zzzzz", L".micro", L".mp3", L".vvv", L".ccc",
            L".abc", L".xxx", L".ttt", L".ecc", L".ezz",
            L".aaa", L".xtbl", L".crysis", L".cryp1", L".crypz",
            L".wallet", L".petya", L".golden", L".dharma", L".arena",
            L".bip", L".combo", L".gamma", L".hese",
            L".gero", L".mado", L".peta", L".pedro", L".nesa",
            L".coot", L".derp", L".meka", L".toec", L".mosk",
            L".lotep", L".grod", L".nols", L".werd", L".bora",
            L".reco", L".kuub", L".mmnn", L".ooss", L".noos",
            L".karl", L".shadow", L".djvu", L".stop", L".puma"
        };

        m_persistenceRegistryPaths = {
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
            L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components",
            L"SYSTEM\\CurrentControlSet\\Services",
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
            L"SOFTWARE\\Classes\\CLSID",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths"
        };

        m_credentialTargets = {
            L"lsass.exe", L"csrss.exe", L"winlogon.exe", L"services.exe",
            L"svchost.exe", L"wininit.exe", L"lsaiso.exe"
        };

        m_ransomNotePatterns = {
            L"readme", L"how_to_decrypt", L"how_to_recover",
            L"restore_files", L"decrypt_instructions", L"help_decrypt",
            L"payment", L"ransom", L"your_files", L"recovery_key",
            L"important_read_me", L"attention", L"warning"
        };

        m_documentApps = {
            L"winword.exe", L"excel.exe", L"powerpnt.exe", L"outlook.exe",
            L"onenote.exe", L"msaccess.exe", L"acrord32.exe",
            L"acrobat.exe", L"foxitreader.exe", L"visio.exe"
        };

        m_scriptInterpreters = {
            L"powershell.exe", L"pwsh.exe", L"cmd.exe", L"wscript.exe",
            L"cscript.exe", L"mshta.exe", L"regsvr32.exe", L"rundll32.exe",
            L"msiexec.exe", L"certutil.exe", L"bitsadmin.exe",
            L"wmic.exe", L"bash.exe", L"python.exe", L"python3.exe",
            L"perl.exe", L"ruby.exe", L"node.exe"
        };
    }
};

// ============================================================================
// Singleton
// ============================================================================

BehaviorAnalyzer& BehaviorAnalyzer::Instance() {
    static BehaviorAnalyzer instance;
    return instance;
}

BehaviorAnalyzer::BehaviorAnalyzer()
    : m_impl(std::make_unique<Impl>()) {}

BehaviorAnalyzer::~BehaviorAnalyzer() {
    if (m_impl && m_impl->m_initialized.load(std::memory_order_acquire)) {
        Shutdown();
    }
}

// ============================================================================
// Lifecycle
// ============================================================================

bool BehaviorAnalyzer::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool) {
    return Initialize(std::move(threadPool), BehaviorAnalyzerConfig::CreateDefault(), nullptr, nullptr);
}

bool BehaviorAnalyzer::Initialize(
    std::shared_ptr<Utils::ThreadPool> threadPool,
    const BehaviorAnalyzerConfig& config)
{
    return Initialize(std::move(threadPool), config, nullptr, nullptr);
}

bool BehaviorAnalyzer::Initialize(
    std::shared_ptr<Utils::ThreadPool> threadPool,
    const BehaviorAnalyzerConfig& config,
    ThreatIntel::ThreatIntelIndex* threatIntel,
    Whitelist::WhitelistStore* whitelist)
{
    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"BehaviorAnalyzer", L"Already initialized, ignoring duplicate call");
        return true;
    }

    try {
        std::unique_lock configLock(m_impl->m_configMutex);
        m_impl->m_config = config;
        m_impl->m_threadPool = std::move(threadPool);
        m_impl->m_threatIntel = threatIntel;
        m_impl->m_whitelist = whitelist;
        configLock.unlock();

        // Populate canary files from config
        if (!config.canaryFilePaths.empty()) {
            std::unique_lock canaryLock(m_impl->m_canaryMutex);
            for (const auto& path : config.canaryFilePaths) {
                m_impl->m_canaryFiles.insert(ToLowerCase(path));
            }
        }

        m_impl->m_stats.Reset();
        m_impl->m_lastCleanupTimeRep.store(
            std::chrono::steady_clock::now().time_since_epoch().count(),
            std::memory_order_relaxed);
        m_impl->m_initialized.store(true, std::memory_order_release);

        SS_LOG_INFO(L"BehaviorAnalyzer", L"Initialized - ransomware=%s injection=%s persistence=%s "
            L"credTheft=%s evasion=%s exfil=%s lateral=%s c2=%s chains=%s",
            config.detectRansomware ? L"ON" : L"OFF",
            config.detectProcessInjection ? L"ON" : L"OFF",
            config.detectPersistence ? L"ON" : L"OFF",
            config.detectCredentialTheft ? L"ON" : L"OFF",
            config.detectEvasion ? L"ON" : L"OFF",
            config.detectExfiltration ? L"ON" : L"OFF",
            config.detectLateralMovement ? L"ON" : L"OFF",
            config.detectC2 ? L"ON" : L"OFF",
            config.enableAttackChains ? L"ON" : L"OFF");

        return true;
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(L"BehaviorAnalyzer", L"Initialization failed: %S", ex.what());
        return false;
    }
}

void BehaviorAnalyzer::Shutdown() {
    if (!m_impl->m_initialized.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    try {
        // Clear callbacks first to prevent notifications during teardown
        {
            std::unique_lock cbLock(m_impl->m_callbackMutex);
            m_impl->m_verdictCallbacks.clear();
            m_impl->m_chainCallbacks.clear();
            m_impl->m_terminationCallback = nullptr;
        }

        {
            std::unique_lock stateLock(m_impl->m_statesMutex);
            m_impl->m_processStates.clear();
        }

        {
            std::unique_lock chainLock(m_impl->m_chainsMutex);
            m_impl->m_attackChains.clear();
        }

        {
            std::unique_lock canaryLock(m_impl->m_canaryMutex);
            m_impl->m_canaryFiles.clear();
        }

        {
            std::unique_lock configLock(m_impl->m_configMutex);
            m_impl->m_threadPool.reset();
            m_impl->m_threatIntel = nullptr;
            m_impl->m_whitelist = nullptr;
            m_impl->m_signatureStore = nullptr;
        }

        SS_LOG_INFO(L"BehaviorAnalyzer", L"Shutdown complete - processed %llu events, %llu verdicts",
            m_impl->m_stats.totalEventsProcessed.load(std::memory_order_relaxed),
            m_impl->m_stats.totalVerdicts.load(std::memory_order_relaxed));
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(L"BehaviorAnalyzer", L"Error during shutdown: %S", ex.what());
    }
}

bool BehaviorAnalyzer::IsInitialized() const noexcept {
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

void BehaviorAnalyzer::UpdateConfig(const BehaviorAnalyzerConfig& config) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = config;

    if (!config.canaryFilePaths.empty()) {
        std::unique_lock canaryLock(m_impl->m_canaryMutex);
        m_impl->m_canaryFiles.clear();
        for (const auto& p : config.canaryFilePaths) {
            m_impl->m_canaryFiles.insert(ToLowerCase(p));
        }
    }

    SS_LOG_DEBUG(L"BehaviorAnalyzer", L"Configuration updated at runtime");
}

BehaviorAnalyzerConfig BehaviorAnalyzer::GetConfig() const {
    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}
// ============================================================================
// Event Processing
// ============================================================================

std::optional<BehaviorVerdict> BehaviorAnalyzer::ProcessEvent(const BehaviorEvent& event) {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    auto startTime = std::chrono::steady_clock::now();

    try {
        // Snapshot config (lock-free after snapshot)
        BehaviorAnalyzerConfig config;
        {
            std::shared_lock cfgLock(m_impl->m_configMutex);
            config = m_impl->m_config;
        }

        if (!config.enabled) return std::nullopt;

        // Update statistics
        m_impl->m_stats.totalEventsProcessed.fetch_add(1, std::memory_order_relaxed);
        auto catIdx = static_cast<size_t>(event.category);
        if (catIdx < m_impl->m_stats.eventsByCategory.size()) {
            m_impl->m_stats.eventsByCategory[catIdx].fetch_add(1, std::memory_order_relaxed);
        }

        // Whitelist check (early exit)
        if (config.applyWhitelist && event.isWhitelisted) {
            return std::nullopt;
        }

        std::optional<BehaviorVerdict> verdict;
        BehaviorEvent enrichedEvent = event;
        if (enrichedEvent.eventId == 0) {
            enrichedEvent.eventId = m_impl->m_nextEventId.fetch_add(1, std::memory_order_relaxed);
        }
        if (enrichedEvent.timestamp == std::chrono::steady_clock::time_point{}) {
            enrichedEvent.timestamp = std::chrono::steady_clock::now();
        }
        if (enrichedEvent.systemTime == std::chrono::system_clock::time_point{}) {
            enrichedEvent.systemTime = std::chrono::system_clock::now();
        }

        // Whitelist store check for process path
        if (config.applyWhitelist && m_impl->m_whitelist && !enrichedEvent.processPath.empty()) {
            auto wlResult = m_impl->m_whitelist->IsPathWhitelisted(enrichedEvent.processPath);
            if (wlResult.found) {
                return std::nullopt;
            }
        }

        // All state mutations under unique lock
        {
            std::unique_lock stateLock(m_impl->m_statesMutex);

            // Fast path: ProcessTerminate clears state to prevent PID reuse contamination
            if (enrichedEvent.eventType == BehaviorEventType::ProcessTerminate) {
                m_impl->m_processStates.erase(enrichedEvent.processId);
                m_impl->m_stats.trackedProcesses.store(m_impl->m_processStates.size(),
                                                        std::memory_order_relaxed);
                stateLock.unlock();
                return std::nullopt;
            }

            auto& state = GetOrCreateState(enrichedEvent.processId, enrichedEvent);
            state.lastUpdateTime = std::chrono::steady_clock::now();
            state.totalEventsProcessed++;

            // Add event to history ring buffer
            state.recentEvents.push_back(enrichedEvent);
            if (state.recentEvents.size() > config.maxEventsPerProcess) {
                state.recentEvents.pop_front();
            }

            // Apply score decay before adding new score (pass config snapshot to avoid lock-order violation)
            ApplyScoreDecay(state, config);

            // Route to specialized detection engines based on event category
            switch (enrichedEvent.category) {
                case BehaviorEventCategory::FileSystem:
                    state.fileOperationCount++;
                    if (config.detectRansomware) UpdateRansomwareScore(state, enrichedEvent);
                    break;

                case BehaviorEventCategory::Registry:
                    state.registryModifications++;
                    if (config.detectPersistence) UpdatePersistenceScore(state, enrichedEvent);
                    break;

                case BehaviorEventCategory::Process:
                    if (config.detectProcessInjection) UpdateInjectionScore(state, enrichedEvent);
                    if (config.detectLateralMovement) UpdateLateralMovementScore(state, enrichedEvent);
                    break;

                case BehaviorEventCategory::Thread:
                    if (config.detectProcessInjection) UpdateInjectionScore(state, enrichedEvent);
                    break;

                case BehaviorEventCategory::Memory:
                    if (config.detectProcessInjection) UpdateInjectionScore(state, enrichedEvent);
                    break;

                case BehaviorEventCategory::Network:
                    state.networkConnections++;
                    if (config.detectExfiltration) UpdateExfiltrationScore(state, enrichedEvent);
                    if (config.detectC2) UpdateC2Score(state, enrichedEvent);
                    if (config.detectLateralMovement) UpdateLateralMovementScore(state, enrichedEvent);
                    break;

                case BehaviorEventCategory::Handle:
                    if (config.detectCredentialTheft) UpdateCredentialScore(state, enrichedEvent);
                    break;

                case BehaviorEventCategory::Service:
                    if (config.detectPersistence) UpdatePersistenceScore(state, enrichedEvent);
                    break;

                case BehaviorEventCategory::WMI:
                    if (config.detectPersistence) UpdatePersistenceScore(state, enrichedEvent);
                    if (config.detectLateralMovement) UpdateLateralMovementScore(state, enrichedEvent);
                    break;

                case BehaviorEventCategory::Script:
                    if (config.detectEvasion) UpdateEvasionScore(state, enrichedEvent);
                    break;

                case BehaviorEventCategory::System:
                    if (config.detectRansomware) UpdateRansomwareScore(state, enrichedEvent);
                    if (config.detectEvasion) UpdateEvasionScore(state, enrichedEvent);
                    break;

                default:
                    break;
            }

            // Evasion detection for specific event types NOT already handled by category routing
            if (config.detectEvasion) {
                auto eType = enrichedEvent.eventType;
                bool alreadyEvasionScored =
                    (enrichedEvent.category == BehaviorEventCategory::Script ||
                     enrichedEvent.category == BehaviorEventCategory::System);
                if (!alreadyEvasionScored &&
                    (eType == BehaviorEventType::AntiDebugAttempt ||
                     eType == BehaviorEventType::VMDetectionAttempt ||
                     eType == BehaviorEventType::SandboxDetectionAttempt ||
                     eType == BehaviorEventType::LogClear ||
                     eType == BehaviorEventType::Timestomp ||
                     eType == BehaviorEventType::SecurityDisable)) {
                    UpdateEvasionScore(state, enrichedEvent);
                }
            }

            // Clamp malice score (modifier factored into threshold, NOT cumulated per event)
            state.maliceScore = std::clamp(state.maliceScore,
                                            0.0, BehaviorConstants::MAX_MALICE_SCORE);
            if (state.maliceScore > state.peakMaliceScore) {
                state.peakMaliceScore = state.maliceScore;
            }

            // MITRE mapping for any matched pattern
            if (enrichedEvent.matchedPattern != BehaviorPatternType::Unknown) {
                AddMitreMapping(state, enrichedEvent.matchedPattern);
            }

            // Check thresholds for verdict generation
            verdict = CheckThresholds(state, enrichedEvent);

            // Update tracked process count
            m_impl->m_stats.trackedProcesses.store(m_impl->m_processStates.size(),
                                                    std::memory_order_relaxed);
            auto peak = m_impl->m_stats.peakTrackedProcesses.load(std::memory_order_relaxed);
            if (m_impl->m_processStates.size() > peak) {
                m_impl->m_stats.peakTrackedProcesses.store(m_impl->m_processStates.size(),
                                                            std::memory_order_relaxed);
            }
        }
        // stateLock released here

        // Attack chain correlation — re-acquire statesMutex (lock order: states→chains OK)
        if (config.enableAttackChains) {
            std::unique_lock chainStateLock(m_impl->m_statesMutex);
            auto chainIt = m_impl->m_processStates.find(enrichedEvent.processId);
            if (chainIt != m_impl->m_processStates.end()) {
                CorrelateWithAttackChains(enrichedEvent, chainIt->second);
            }
        }

        // Invoke callbacks outside all locks
        if (verdict.has_value()) {
            InvokeVerdictCallbacks(*verdict);

            // Auto-action if configured
            if (config.autoTerminateOnCritical &&
                verdict->severity == BehaviorSeverity::Critical) {
                PerformAction(*verdict);
            }
            else if (config.autoSuspendOnBlock &&
                     verdict->action >= RecommendedAction::Suspend) {
                PerformAction(*verdict);
            }
        }

        // Periodic cleanup (atomic time_point to avoid data race)
        auto now = std::chrono::steady_clock::now();
        auto lastCleanup = std::chrono::steady_clock::time_point(
            std::chrono::steady_clock::duration(
                m_impl->m_lastCleanupTimeRep.load(std::memory_order_relaxed)));
        if (now - lastCleanup > BehaviorConstants::CLEANUP_INTERVAL) {
            m_impl->m_lastCleanupTimeRep.store(
                now.time_since_epoch().count(), std::memory_order_relaxed);
            if (m_impl->m_threadPool) {
                try {
                    (void)m_impl->m_threadPool->Submit(
                        [this](const Utils::TaskContext&) { PerformCleanup(); },
                        Utils::TaskPriority::Low, "BA-Cleanup");
                } catch (...) {
                    PerformCleanup();
                }
            }
        }

        // Update processing time (exponential moving average, α=1/8)
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        uint64_t prev = m_impl->m_stats.avgProcessingTimeUs.load(std::memory_order_relaxed);
        uint64_t ema = (prev * 7 + static_cast<uint64_t>(elapsed)) / 8;
        m_impl->m_stats.avgProcessingTimeUs.store(ema, std::memory_order_relaxed);

        return verdict;
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(L"BehaviorAnalyzer", L"ProcessEvent exception for PID %u: %S",
                     event.processId, ex.what());
        return std::nullopt;
    }
}

std::vector<BehaviorVerdict> BehaviorAnalyzer::ProcessEventBatch(
    const std::vector<BehaviorEvent>& events)
{
    std::vector<BehaviorVerdict> verdicts;
    verdicts.reserve(events.size() / 10);  // typically ~10% generate verdicts

    for (const auto& event : events) {
        auto verdict = ProcessEvent(event);
        if (verdict.has_value()) {
            verdicts.push_back(std::move(*verdict));
        }
    }

    return verdicts;
}

bool BehaviorAnalyzer::ProcessEventAsync(BehaviorEvent event) {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) return false;

    std::shared_lock cfgLock(m_impl->m_configMutex);
    auto tp = m_impl->m_threadPool;
    cfgLock.unlock();

    if (!tp) return false;

    try {
        (void)tp->Submit(
            [this, ev = std::move(event)](const Utils::TaskContext&) mutable {
                (void)ProcessEvent(ev);
            },
            Utils::TaskPriority::Normal, "BA-AsyncEvent");
        return true;
    }
    catch (const std::exception&) {
        m_impl->m_stats.eventsDropped.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
}

BehaviorVerdict BehaviorAnalyzer::EvaluateProcess(uint32_t processId) {
    std::shared_lock stateLock(m_impl->m_statesMutex);
    auto it = m_impl->m_processStates.find(processId);
    if (it == m_impl->m_processStates.end()) {
        BehaviorVerdict v;
        v.processId = processId;
        v.verdictType = BehaviorVerdictType::Clean;
        v.severity = BehaviorSeverity::Info;
        v.timestamp = std::chrono::system_clock::now();
        return v;
    }

    BehaviorEvent dummyEvent;
    dummyEvent.processId = processId;
    dummyEvent.timestamp = std::chrono::steady_clock::now();
    dummyEvent.systemTime = std::chrono::system_clock::now();
    return GenerateVerdict(it->second, dummyEvent);
}
// ============================================================================
// Internal: GetOrCreateState (MUST be called under unique m_statesMutex lock)
// ============================================================================

ProcessBehaviorState& BehaviorAnalyzer::GetOrCreateState(
    uint32_t processId, const BehaviorEvent& event)
{
    auto it = m_impl->m_processStates.find(processId);
    if (it != m_impl->m_processStates.end()) {
        return it->second;
    }

    // Enforce tracked process cap
    if (m_impl->m_processStates.size() >= BehaviorConstants::MAX_TRACKED_PROCESSES) {
        // Evict oldest low-score process
        uint32_t evictPid = 0;
        double lowestScore = BehaviorConstants::MAX_MALICE_SCORE + 1.0;
        auto oldestTime = std::chrono::steady_clock::now();

        for (const auto& [pid, st] : m_impl->m_processStates) {
            if (st.maliceScore < lowestScore ||
                (st.maliceScore == lowestScore && st.lastUpdateTime < oldestTime)) {
                lowestScore = st.maliceScore;
                oldestTime = st.lastUpdateTime;
                evictPid = pid;
            }
        }
        if (evictPid != 0) {
            m_impl->m_processStates.erase(evictPid);
        }
    }

    auto& state = m_impl->m_processStates[processId];
    state.processId = processId;
    state.parentProcessId = event.parentProcessId;
    state.processName = event.processName;
    state.processPath = event.processPath;
    state.commandLine = event.commandLine;
    state.userSid = event.userSid;
    state.stateCreatedAt = std::chrono::steady_clock::now();
    state.lastUpdateTime = state.stateCreatedAt;
    state.creationTime = event.systemTime;

    // Enrich from ProcessUtils if available
    try {
        auto procName = Utils::ProcessUtils::GetProcessName(processId);
        if (procName.has_value() && state.processName.empty()) {
            state.processName = *procName;
        }
        auto procPath = Utils::ProcessUtils::GetProcessPath(processId);
        if (procPath.has_value() && state.processPath.empty()) {
            state.processPath = *procPath;
        }
    } catch (...) {}

    // Set trust flags based on process name
    auto lowerName = ToLowerCase(state.processName);
    if (lowerName == L"system" || lowerName == L"idle" ||
        lowerName == L"smss.exe" || lowerName == L"csrss.exe" ||
        lowerName == L"wininit.exe" || lowerName == L"services.exe") {
        state.isSystemProcess = true;
    }
    if (m_impl->m_documentApps.count(lowerName) > 0) {
        state.hasDocumentParent = true;
    }
    if (m_impl->m_scriptInterpreters.count(lowerName) > 0) {
        state.hasScriptParent = true;
    }

    return state;
}

// ============================================================================
// Detection Engine: Ransomware
// ============================================================================

void BehaviorAnalyzer::UpdateRansomwareScore(
    ProcessBehaviorState& state, const BehaviorEvent& event)
{
    double scoreAdd = 0.0;

    switch (event.eventType) {
        case BehaviorEventType::FileWrite:
        case BehaviorEventType::FileCreate: {
            state.filesModified++;

            // High entropy write detection
            if (event.fileEntropy >= BehaviorConstants::ENCRYPTION_ENTROPY_THRESHOLD) {
                state.highEntropyWrites++;
                state.filesEncrypted++;
                scoreAdd += 3.0;

                if (state.highEntropyWrites >= BehaviorConstants::RANSOMWARE_FILE_THRESHOLD) {
                    scoreAdd += 20.0;
                    AddMitreMapping(state, BehaviorPatternType::RansomwareEncryption);
                    m_impl->m_stats.ransomwareDetections.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Canary file check
            if (!event.targetPath.empty()) {
                auto lowerTarget = ToLowerCase(event.targetPath);
                std::shared_lock canaryLock(m_impl->m_canaryMutex);
                if (m_impl->m_canaryFiles.count(lowerTarget) > 0) {
                    state.canaryFilesTouched++;
                    scoreAdd += BehaviorConstants::CANARY_FILE_SCORE;
                    AddMitreMapping(state, BehaviorPatternType::RansomwareCanaryTouch);
                }
            }

            // Ransom note detection
            if (IsRansomNotePattern(event.targetPath)) {
                state.ransomNoteIndicators++;
                scoreAdd += BehaviorConstants::RANSOM_NOTE_SCORE;
                AddMitreMapping(state, BehaviorPatternType::RansomwareNote);
            }

            // File modification rate tracking
            auto now = std::chrono::steady_clock::now();
            if (state.lastFileModTime != std::chrono::steady_clock::time_point{}) {
                auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - state.lastFileModTime).count();
                if (elapsedMs > 0) {
                    state.fileModificationRate = 1000.0 / static_cast<double>(elapsedMs);
                    if (state.fileModificationRate > BehaviorConstants::RANSOMWARE_RATE_THRESHOLD) {
                        scoreAdd += 5.0;
                    }
                }
            }
            state.lastFileModTime = now;
            break;
        }

        case BehaviorEventType::FileRename: {
            state.fileRenames++;
            auto lowerExt = ToLowerCase(event.fileExtension);
            if (!lowerExt.empty() && m_impl->m_ransomwareExtensions.count(lowerExt) > 0) {
                state.extensionChanges++;
                scoreAdd += 8.0;
                AddMitreMapping(state, BehaviorPatternType::RansomwareExtensionChange);
            }
            break;
        }

        case BehaviorEventType::FileDelete: {
            state.filesDeleted++;
            if (state.filesDeleted > BehaviorConstants::RANSOMWARE_FILE_THRESHOLD) {
                scoreAdd += 5.0;
                AddMitreMapping(state, BehaviorPatternType::RansomwareMassDelete);
            }
            break;
        }

        case BehaviorEventType::ShadowCopyDelete: {
            state.shadowCopyOperations++;
            scoreAdd += BehaviorConstants::SHADOW_COPY_DELETE_SCORE;
            AddMitreMapping(state, BehaviorPatternType::RansomwareShadowDelete);
            break;
        }

        default:
            break;
    }

    state.maliceScore += scoreAdd;  // outer clamp to MAX_MALICE_SCORE prevents overflow
}

// ============================================================================
// Detection Engine: Process Injection
// ============================================================================

void BehaviorAnalyzer::UpdateInjectionScore(
    ProcessBehaviorState& state, const BehaviorEvent& event)
{
    double scoreAdd = 0.0;

    switch (event.eventType) {
        case BehaviorEventType::ThreadRemoteCreate:
            state.remoteThreadCount++;
            if (event.targetProcessId != 0) {
                state.targetedProcessIds.insert(event.targetProcessId);
            }
            scoreAdd += BehaviorConstants::REMOTE_THREAD_SCORE;
            AddMitreMapping(state, BehaviorPatternType::InjectionRemoteThread);
            m_impl->m_stats.injectionDetections.fetch_add(1, std::memory_order_relaxed);
            break;

        case BehaviorEventType::MemoryRemoteAllocate:
            if (event.targetProcessId != 0) {
                state.targetedProcessIds.insert(event.targetProcessId);
                state.remoteAllocations.emplace_back(event.targetProcessId, event.targetAddress);
            }
            scoreAdd += BehaviorConstants::REMOTE_ALLOC_SCORE;
            break;

        case BehaviorEventType::MemoryRemoteWrite:
            state.crossProcessWrites++;
            if (event.targetProcessId != 0) {
                state.targetedProcessIds.insert(event.targetProcessId);
            }
            scoreAdd += BehaviorConstants::WRITE_PROCESS_MEMORY_SCORE;
            break;

        case BehaviorEventType::ProcessHollow:
            scoreAdd += BehaviorConstants::PROCESS_HOLLOWING_SCORE;
            AddMitreMapping(state, BehaviorPatternType::InjectionHollowing);
            m_impl->m_stats.injectionDetections.fetch_add(1, std::memory_order_relaxed);
            break;

        case BehaviorEventType::ProcessInject:
            scoreAdd += BehaviorConstants::DLL_INJECTION_SCORE;
            AddMitreMapping(state, BehaviorPatternType::InjectionDLL);
            if (!event.targetPath.empty()) {
                state.injectedDLLs.push_back(event.targetPath);
            }
            m_impl->m_stats.injectionDetections.fetch_add(1, std::memory_order_relaxed);
            break;

        case BehaviorEventType::ThreadQueueAPC:
            scoreAdd += BehaviorConstants::APC_INJECTION_SCORE;
            AddMitreMapping(state, BehaviorPatternType::InjectionAPC);
            m_impl->m_stats.injectionDetections.fetch_add(1, std::memory_order_relaxed);
            break;

        case BehaviorEventType::ThreadHijack:
            scoreAdd += BehaviorConstants::DLL_INJECTION_SCORE;
            AddMitreMapping(state, BehaviorPatternType::InjectionThreadHijack);
            break;

        // Compound pattern: remote alloc + remote write to same target = injection
        case BehaviorEventType::MemoryRemoteProtect:
            if (state.crossProcessWrites > 0 && state.remoteAllocations.size() > 0) {
                scoreAdd += 15.0;
                AddMitreMapping(state, BehaviorPatternType::InjectionReflective);
            }
            break;

        default:
            break;
    }

    state.maliceScore += scoreAdd;  // outer clamp to MAX_MALICE_SCORE prevents overflow
}

// ============================================================================
// Detection Engine: Persistence
// ============================================================================

void BehaviorAnalyzer::UpdatePersistenceScore(
    ProcessBehaviorState& state, const BehaviorEvent& event)
{
    double scoreAdd = 0.0;

    switch (event.eventType) {
        case BehaviorEventType::RegistrySetValue:
        case BehaviorEventType::RegistryCreateKey: {
            if (IsPersistenceRegistryPath(event.targetPath)) {
                scoreAdd += BehaviorConstants::REG_RUN_KEY_SCORE;
                state.persistenceLocations.push_back(event.targetPath);
                AddMitreMapping(state, BehaviorPatternType::PersistenceRunKey);
                m_impl->m_stats.persistenceDetections.fetch_add(1, std::memory_order_relaxed);

                // IFEO hijack is especially suspicious
                if (ContainsCaseInsensitive(event.targetPath,
                        L"Image File Execution Options")) {
                    scoreAdd += 15.0;
                    AddMitreMapping(state, BehaviorPatternType::PersistenceIFEO);
                }

                // AppInit DLLs
                if (ContainsCaseInsensitive(event.targetPath, L"AppInit_DLLs")) {
                    scoreAdd += 10.0;
                    AddMitreMapping(state, BehaviorPatternType::PersistenceAppInit);
                }
            }
            break;
        }

        case BehaviorEventType::TaskCreate:
            scoreAdd += BehaviorConstants::SCHEDULED_TASK_SCORE;
            state.createdTasks.push_back(event.targetPath);
            AddMitreMapping(state, BehaviorPatternType::PersistenceScheduledTask);
            m_impl->m_stats.persistenceDetections.fetch_add(1, std::memory_order_relaxed);
            break;

        case BehaviorEventType::ServiceInstall:
            scoreAdd += BehaviorConstants::SERVICE_INSTALL_SCORE;
            state.createdServices.push_back(event.targetPath);
            AddMitreMapping(state, BehaviorPatternType::PersistenceService);
            m_impl->m_stats.persistenceDetections.fetch_add(1, std::memory_order_relaxed);
            break;

        case BehaviorEventType::WMISubscription:
            scoreAdd += BehaviorConstants::WMI_PERSISTENCE_SCORE;
            AddMitreMapping(state, BehaviorPatternType::PersistenceWMI);
            m_impl->m_stats.persistenceDetections.fetch_add(1, std::memory_order_relaxed);
            break;

        case BehaviorEventType::BootConfigModify:
            scoreAdd += BehaviorConstants::BOOT_CONFIG_SCORE;
            AddMitreMapping(state, BehaviorPatternType::PersistenceBootConfig);
            m_impl->m_stats.persistenceDetections.fetch_add(1, std::memory_order_relaxed);
            break;

        default:
            break;
    }

    state.maliceScore += scoreAdd;  // outer clamp to MAX_MALICE_SCORE prevents overflow
}

// ============================================================================
// Detection Engine: Credential Theft
// ============================================================================

void BehaviorAnalyzer::UpdateCredentialScore(
    ProcessBehaviorState& state, const BehaviorEvent& event)
{
    double scoreAdd = 0.0;

    switch (event.eventType) {
        case BehaviorEventType::LSASSAccess: {
            state.credentialAccessAttempts++;
            scoreAdd += BehaviorConstants::LSASS_ACCESS_SCORE;
            AddMitreMapping(state, BehaviorPatternType::CredentialLSASSDump);
            m_impl->m_stats.credentialTheftDetections.fetch_add(1, std::memory_order_relaxed);
            break;
        }

        case BehaviorEventType::SAMAccess: {
            state.credentialAccessAttempts++;
            scoreAdd += BehaviorConstants::SAM_ACCESS_SCORE;
            AddMitreMapping(state, BehaviorPatternType::CredentialSAMAccess);
            m_impl->m_stats.credentialTheftDetections.fetch_add(1, std::memory_order_relaxed);
            break;
        }

        case BehaviorEventType::CredentialAccess:
        case BehaviorEventType::CredentialDump: {
            state.credentialAccessAttempts++;
            scoreAdd += BehaviorConstants::CREDENTIAL_STORE_SCORE;
            AddMitreMapping(state, BehaviorPatternType::CredentialStoreAccess);
            m_impl->m_stats.credentialTheftDetections.fetch_add(1, std::memory_order_relaxed);
            break;
        }

        case BehaviorEventType::TokenSteal:
        case BehaviorEventType::TokenDuplicate: {
            state.credentialAccessAttempts++;
            scoreAdd += 20.0;
            AddMitreMapping(state, BehaviorPatternType::CredentialTokenManip);
            break;
        }

        // Handle-based detection: process opening LSASS with suspicious access
        case BehaviorEventType::ProcessOpen: {
            if (event.targetProcessId != 0) {
                // Resolve TARGET process name — we detect WHO is being opened, not the opener
                std::wstring targetName;
                auto targetNameOpt = Utils::ProcessUtils::GetProcessName(event.targetProcessId);
                if (targetNameOpt.has_value()) {
                    targetName = ToLowerCase(*targetNameOpt);
                }
                if (m_impl->m_credentialTargets.count(targetName) > 0 ||
                    IsLSASSProcess(targetName)) {
                    if (event.accessMask & (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)) {
                        state.credentialAccessAttempts++;
                        scoreAdd += BehaviorConstants::LSASS_ACCESS_SCORE;
                        AddMitreMapping(state, BehaviorPatternType::CredentialLSASSDump);
                    }
                }
            }
            break;
        }

        default:
            break;
    }

    state.maliceScore += scoreAdd;  // outer clamp to MAX_MALICE_SCORE prevents overflow
}
// ============================================================================
// Detection Engine: Evasion
// ============================================================================

void BehaviorAnalyzer::UpdateEvasionScore(
    ProcessBehaviorState& state, const BehaviorEvent& event)
{
    double scoreAdd = 0.0;

    switch (event.eventType) {
        case BehaviorEventType::AntiDebugAttempt:
            state.evasionAttempts++;
            scoreAdd += BehaviorConstants::ANTI_DEBUG_SCORE;
            AddMitreMapping(state, BehaviorPatternType::EvasionMasquerade);
            break;

        case BehaviorEventType::VMDetectionAttempt:
        case BehaviorEventType::SandboxDetectionAttempt:
            state.evasionAttempts++;
            scoreAdd += BehaviorConstants::ANTI_DEBUG_SCORE;
            break;

        case BehaviorEventType::LogClear:
            state.evasionAttempts++;
            scoreAdd += BehaviorConstants::LOG_TAMPERING_SCORE;
            AddMitreMapping(state, BehaviorPatternType::EvasionLogClear);
            break;

        case BehaviorEventType::Timestomp:
            state.evasionAttempts++;
            scoreAdd += BehaviorConstants::TIMESTOMPING_SCORE;
            AddMitreMapping(state, BehaviorPatternType::EvasionTimestomp);
            break;

        case BehaviorEventType::SecurityDisable:
            state.evasionAttempts++;
            scoreAdd += BehaviorConstants::SECURITY_INTERFERENCE_SCORE;
            AddMitreMapping(state, BehaviorPatternType::EvasionSecurityDisable);
            break;

        // Process masquerading: script interpreters spawning with suspicious args
        case BehaviorEventType::ProcessCreate:
            if (state.hasScriptParent && !state.processPath.empty()) {
                auto lowerPath = ToLowerCase(state.processPath);
                if (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
                    lowerPath.find(L"\\appdata\\") != std::wstring::npos) {
                    state.evasionAttempts++;
                    scoreAdd += 10.0;
                    AddMitreMapping(state, BehaviorPatternType::EvasionMasquerade);
                }
            }
            break;

        default:
            break;
    }

    state.maliceScore += scoreAdd;  // outer clamp to MAX_MALICE_SCORE prevents overflow
}

// ============================================================================
// Detection Engine: Exfiltration
// ============================================================================

void BehaviorAnalyzer::UpdateExfiltrationScore(
    ProcessBehaviorState& state, const BehaviorEvent& event)
{
    double scoreAdd = 0.0;

    switch (event.eventType) {
        case BehaviorEventType::NetworkSend:
        case BehaviorEventType::NetworkUpload: {
            state.outboundBytes += event.bytesSent;

            // Large single transfer (>10MB)
            if (event.bytesSent > 10 * 1024 * 1024) {
                scoreAdd += 10.0;
                AddMitreMapping(state, BehaviorPatternType::ExfilLargeTransfer);
            }

            // Cumulative large transfer (>100MB total) — score only once
            if (state.outboundBytes > 100ULL * 1024 * 1024 &&
                !state.exfilThresholdTriggered) {
                state.exfilThresholdTriggered = true;
                scoreAdd += 15.0;
                AddMitreMapping(state, BehaviorPatternType::ExfilLargeTransfer);
            }
            break;
        }

        case BehaviorEventType::NetworkDNSQuery: {
            state.dnsQueryCount++;

            // DNS tunneling: unusually long subdomain labels
            if (!event.remoteHostname.empty() && event.remoteHostname.size() > 50) {
                scoreAdd += 12.0;
                AddMitreMapping(state, BehaviorPatternType::ExfilDNSTunnel);
            }

            // High DNS query rate (>100 queries from a single process is suspicious)
            if (state.dnsQueryCount > 100) {
                scoreAdd += 5.0;
            }
            break;
        }

        case BehaviorEventType::FileCreate: {
            // Archive creation before transfer
            auto lowerPath = ToLowerCase(event.targetPath);
            if (lowerPath.ends_with(L".zip") || lowerPath.ends_with(L".rar") ||
                lowerPath.ends_with(L".7z") || lowerPath.ends_with(L".tar") ||
                lowerPath.ends_with(L".gz")) {
                if (state.outboundBytes > 1024 * 1024) {
                    scoreAdd += 8.0;
                    AddMitreMapping(state, BehaviorPatternType::ExfilArchiveCreate);
                }
            }
            break;
        }

        default:
            break;
    }

    state.maliceScore += scoreAdd;  // outer clamp to MAX_MALICE_SCORE prevents overflow
}

// ============================================================================
// Detection Engine: Lateral Movement
// ============================================================================

void BehaviorAnalyzer::UpdateLateralMovementScore(
    ProcessBehaviorState& state, const BehaviorEvent& event)
{
    double scoreAdd = 0.0;

    switch (event.eventType) {
        case BehaviorEventType::ServiceInstall:
            // Remote service creation is a lateral movement indicator
            if (event.targetProcessId != 0 && event.targetProcessId != event.processId) {
                scoreAdd += 20.0;
                AddMitreMapping(state, BehaviorPatternType::LateralService);
            }
            break;

        case BehaviorEventType::WMIExec:
            scoreAdd += 15.0;
            AddMitreMapping(state, BehaviorPatternType::LateralWMI);
            break;

        case BehaviorEventType::NetworkConnect: {
            // SMB connections to port 445
            if (event.remotePort == 445) {
                scoreAdd += 8.0;
                AddMitreMapping(state, BehaviorPatternType::LateralSMB);
            }
            // RDP connections to port 3389
            if (event.remotePort == 3389) {
                scoreAdd += 10.0;
                AddMitreMapping(state, BehaviorPatternType::LateralRDP);
            }
            // WinRM / PSRemoting
            if (event.remotePort == 5985 || event.remotePort == 5986) {
                scoreAdd += 12.0;
                AddMitreMapping(state, BehaviorPatternType::LateralPSExec);
            }
            break;
        }

        default:
            break;
    }

    state.maliceScore += scoreAdd;  // outer clamp to MAX_MALICE_SCORE prevents overflow
}

// ============================================================================
// Detection Engine: Command & Control
// ============================================================================

void BehaviorAnalyzer::UpdateC2Score(
    ProcessBehaviorState& state, const BehaviorEvent& event)
{
    double scoreAdd = 0.0;

    if (event.eventType == BehaviorEventType::NetworkConnect ||
        event.eventType == BehaviorEventType::NetworkSend ||
        event.eventType == BehaviorEventType::NetworkHTTPRequest ||
        event.eventType == BehaviorEventType::NetworkHTTPSRequest) {

        // Track contacted destinations
        if (!event.remoteIP.empty()) {
            state.contactedIPs.insert(event.remoteIP);
        }
        if (!event.remoteHostname.empty()) {
            state.contactedDomains.insert(event.remoteHostname);
        }

        // ThreatIntel lookup for network destinations
        if (m_impl->m_threatIntel) {
            if (!event.remoteHostname.empty()) {
                auto result = m_impl->m_threatIntel->LookupDomain(event.remoteHostname);
                if (result.found) {
                    state.c2Indicators++;
                    scoreAdd += 30.0;
                    AddMitreMapping(state, BehaviorPatternType::C2KnownProtocol);
                    SS_LOG_WARN(L"BehaviorAnalyzer", L"PID %u contacted known-bad domain: %S",
                                state.processId, event.remoteHostname.c_str());
                }
            }
        }

        // Beaconing detection: regular interval connections
        if (state.recentEvents.size() >= 5) {
            size_t networkEventCount = 0;
            std::vector<int64_t> intervals;
            std::chrono::steady_clock::time_point lastNetTime{};

            for (auto it = state.recentEvents.rbegin();
                 it != state.recentEvents.rend() && networkEventCount < 20; ++it) {
                if (it->category == BehaviorEventCategory::Network) {
                    if (lastNetTime != std::chrono::steady_clock::time_point{}) {
                        auto interval = std::chrono::duration_cast<std::chrono::seconds>(
                            lastNetTime - it->timestamp).count();
                        if (interval > 0) intervals.push_back(interval);
                    }
                    lastNetTime = it->timestamp;
                    networkEventCount++;
                }
            }

            // Check for regular intervals (low coefficient of variation)
            if (intervals.size() >= 4) {
                double mean = 0.0;
                for (auto iv : intervals) mean += static_cast<double>(iv);
                mean /= static_cast<double>(intervals.size());

                if (mean > 1.0) {
                    double variance = 0.0;
                    for (auto iv : intervals) {
                        double diff = static_cast<double>(iv) - mean;
                        variance += diff * diff;
                    }
                    variance /= static_cast<double>(intervals.size());
                    double stddev = std::sqrt(variance);
                    double cv = stddev / mean;

                    // CV < 0.3 indicates regular beaconing
                    if (cv < 0.3) {
                        state.c2Indicators++;
                        scoreAdd += 20.0;
                        AddMitreMapping(state, BehaviorPatternType::C2Beacon);
                    }
                }
            }
        }

        // DGA detection: high-entropy domain names
        if (!event.remoteHostname.empty()) {
            // Count unique characters / total length as entropy proxy
            std::unordered_set<char> uniqueChars(event.remoteHostname.begin(),
                                                  event.remoteHostname.end());
            double entropyRatio = static_cast<double>(uniqueChars.size()) /
                                  static_cast<double>(event.remoteHostname.size());

            // DGA domains tend to have high unique character ratio with length > 15
            if (event.remoteHostname.size() > 15 && entropyRatio > 0.7) {
                state.c2Indicators++;
                scoreAdd += 10.0;
                AddMitreMapping(state, BehaviorPatternType::C2DGA);
            }
        }
    }

    state.maliceScore += scoreAdd;  // outer clamp to MAX_MALICE_SCORE prevents overflow
}
// ============================================================================
// Internal: Score Decay
// ============================================================================

void BehaviorAnalyzer::ApplyScoreDecay(ProcessBehaviorState& state) {
    // Default overload: snapshot config internally (only safe when statesMutex NOT held)
    BehaviorAnalyzerConfig config;
    {
        std::shared_lock cfgLock(m_impl->m_configMutex);
        config = m_impl->m_config;
    }
    ApplyScoreDecay(state, config);
}

void BehaviorAnalyzer::ApplyScoreDecay(
    ProcessBehaviorState& state, const BehaviorAnalyzerConfig& config)
{
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
        now - state.lastUpdateTime);

    if (elapsed.count() > 0 && state.maliceScore > 0.0) {
        if (config.enableScoreDecay) {
            double decay = config.scoreDecayRate * static_cast<double>(elapsed.count());
            state.maliceScore = std::max(0.0, state.maliceScore - decay);
        }
    }
}

// ============================================================================
// Internal: Threshold Check & Verdict Generation
// ============================================================================

std::optional<BehaviorVerdict> BehaviorAnalyzer::CheckThresholds(
    ProcessBehaviorState& state, const BehaviorEvent& event)
{
    BehaviorAnalyzerConfig config;
    {
        std::shared_lock cfgLock(m_impl->m_configMutex);
        config = m_impl->m_config;
    }

    // Determine verdict type based on score
    BehaviorVerdictType newVerdict = BehaviorVerdictType::Clean;
    RecommendedAction action = RecommendedAction::None;

    if (state.maliceScore >= config.criticalThreshold) {
        newVerdict = BehaviorVerdictType::ConfirmedThreat;
        action = RecommendedAction::Terminate;

        // Special ransomware verdict
        if (state.HasRansomwareBehavior()) {
            newVerdict = BehaviorVerdictType::Ransomware;
            action = RecommendedAction::BlockAndQuarantine;
        }

        // Active multi-process attack
        if (!state.targetedProcessIds.empty() && state.targetedProcessIds.size() >= 3) {
            newVerdict = BehaviorVerdictType::ActiveAttack;
            action = RecommendedAction::IsolateEndpoint;
        }
    }
    else if (state.maliceScore >= config.blockThreshold) {
        newVerdict = BehaviorVerdictType::Malicious;
        action = RecommendedAction::Suspend;
    }
    else if (state.maliceScore >= config.alertThreshold) {
        newVerdict = BehaviorVerdictType::Suspicious;
        action = RecommendedAction::Alert;
    }
    else if (state.maliceScore >= config.warningThreshold) {
        newVerdict = BehaviorVerdictType::Suspicious;
        action = RecommendedAction::Log;
    }

    // Only generate verdict if it escalated from the current level
    if (newVerdict <= state.currentVerdict && state.hasBeenReported) {
        return std::nullopt;
    }

    if (newVerdict == BehaviorVerdictType::Clean) {
        return std::nullopt;
    }

    state.currentVerdict = newVerdict;
    state.recommendedAction = action;
    state.hasBeenReported = true;

    m_impl->m_stats.totalVerdicts.fetch_add(1, std::memory_order_relaxed);
    auto vtIdx = static_cast<size_t>(newVerdict);
    if (vtIdx < m_impl->m_stats.verdictsByType.size()) {
        m_impl->m_stats.verdictsByType[vtIdx].fetch_add(1, std::memory_order_relaxed);
    }

    return GenerateVerdict(state, event);
}

BehaviorVerdict BehaviorAnalyzer::GenerateVerdict(
    const ProcessBehaviorState& state, const BehaviorEvent& event)
{
    BehaviorVerdict verdict;
    verdict.processId = state.processId;
    verdict.verdictType = state.currentVerdict;
    verdict.severity = state.GetSeverity();
    verdict.maliceScore = state.maliceScore;
    verdict.action = state.recommendedAction;
    verdict.triggeringEventId = event.eventId;
    verdict.timestamp = std::chrono::system_clock::now();
    verdict.detectedPatterns = state.detectedPatterns;
    verdict.mitreTechniques = state.triggeredMitreTechniques;

    // Calculate confidence based on evidence breadth
    double evidenceCount = static_cast<double>(state.detectedPatterns.size());
    double eventCount = static_cast<double>(state.totalEventsProcessed);
    verdict.confidence = std::clamp(
        (evidenceCount * 0.15) + (std::min(eventCount, 100.0) * 0.005) +
        (state.maliceScore / BehaviorConstants::MAX_MALICE_SCORE * 0.3),
        0.0, 1.0);

    // Primary pattern is the most recent high-severity pattern
    if (!state.detectedPatterns.empty()) {
        verdict.primaryPattern = state.detectedPatterns.back();
    }

    // Generate threat name
    switch (state.currentVerdict) {
        case BehaviorVerdictType::Ransomware:
            verdict.threatName = L"Behavior:Win32/Ransomware";
            verdict.threatFamily = L"Ransomware";
            break;
        case BehaviorVerdictType::ActiveAttack:
            verdict.threatName = L"Behavior:Win32/ActiveAttack";
            verdict.threatFamily = L"APT";
            break;
        case BehaviorVerdictType::ConfirmedThreat:
            verdict.threatName = L"Behavior:Win32/Malicious";
            verdict.threatFamily = L"Generic";
            break;
        case BehaviorVerdictType::Malicious:
            verdict.threatName = L"Behavior:Win32/Suspicious.High";
            verdict.threatFamily = L"Suspicious";
            break;
        default:
            verdict.threatName = L"Behavior:Win32/Suspicious";
            verdict.threatFamily = L"Suspicious";
            break;
    }

    // Generate findings
    if (state.HasRansomwareBehavior()) {
        verdict.findings.push_back(L"Ransomware behavior: " +
            std::to_wstring(state.filesEncrypted) + L" files encrypted, " +
            std::to_wstring(state.shadowCopyOperations) + L" shadow copy ops");
    }
    if (state.HasInjectionBehavior()) {
        verdict.findings.push_back(L"Process injection: " +
            std::to_wstring(state.remoteThreadCount) + L" remote threads, " +
            std::to_wstring(state.crossProcessWrites) + L" cross-process writes");
    }
    if (state.credentialAccessAttempts > 0) {
        verdict.findings.push_back(L"Credential access: " +
            std::to_wstring(state.credentialAccessAttempts) + L" attempts");
    }
    if (state.evasionAttempts > 0) {
        verdict.findings.push_back(L"Evasion techniques: " +
            std::to_wstring(state.evasionAttempts) + L" attempts detected");
    }
    if (state.c2Indicators > 0) {
        verdict.findings.push_back(L"C2 indicators: " +
            std::to_wstring(state.c2Indicators) + L" matches");
    }

    // Related events (last N event IDs)
    for (auto it = state.recentEvents.rbegin();
         it != state.recentEvents.rend() && verdict.relatedEventIds.size() < 20; ++it) {
        verdict.relatedEventIds.push_back(it->eventId);
    }

    // Build description
    verdict.description = verdict.threatName + L" detected in " +
        state.processName + L" (PID " + std::to_wstring(state.processId) +
        L") - Score: " + std::to_wstring(static_cast<int>(state.maliceScore)) +
        L"/100, Confidence: " + std::to_wstring(static_cast<int>(verdict.confidence * 100)) + L"%";

    return verdict;
}

// ============================================================================
// Internal: Attack Chain Correlation
// ============================================================================

void BehaviorAnalyzer::CorrelateWithAttackChains(
    const BehaviorEvent& event, ProcessBehaviorState& state)
{
    std::unique_lock chainLock(m_impl->m_chainsMutex);

    // Check if this process is already part of an existing chain
    bool foundExisting = false;
    for (auto& chain : m_impl->m_attackChains) {
        if (!chain.isActive) continue;

        for (auto pid : chain.involvedProcessIds) {
            if (pid == event.processId) {
                // Extend existing chain
                chain.events.push_back(event);
                chain.lastUpdateTime = std::chrono::system_clock::now();

                // Cap events per chain
                if (chain.events.size() > BehaviorConstants::MAX_EVENTS_PER_PROCESS) {
                    chain.events.erase(chain.events.begin());
                }

                // Recalculate confidence
                double eventDiv = static_cast<double>(chain.events.size());
                double pidDiv = static_cast<double>(chain.involvedProcessIds.size());
                chain.confidence = std::clamp(
                    0.3 + (eventDiv * 0.02) + (pidDiv * 0.1), 0.0, 1.0);

                foundExisting = true;
                break;
            }
        }
        if (foundExisting) break;

        // Cross-process correlation: check if this event targets a process in the chain
        if (event.targetProcessId != 0) {
            for (auto pid : chain.involvedProcessIds) {
                if (pid == event.targetProcessId) {
                    chain.involvedProcessIds.push_back(event.processId);
                    chain.events.push_back(event);
                    chain.lastUpdateTime = std::chrono::system_clock::now();
                    foundExisting = true;
                    break;
                }
            }
        }
        if (foundExisting) break;
    }

    // Start new chain if process has multi-category suspicious behavior
    if (!foundExisting && state.maliceScore >= BehaviorConstants::WARNING_THRESHOLD) {
        // Count distinct attack categories
        std::unordered_set<uint16_t> categories;
        for (auto pattern : state.detectedPatterns) {
            categories.insert(static_cast<uint16_t>(pattern) / 50);
        }

        // Need at least 2 distinct attack categories for a chain
        if (categories.size() >= 2) {
            if (m_impl->m_attackChains.size() < BehaviorConstants::MAX_ATTACK_CHAINS) {
                BehaviorAttackChain newChain;
                newChain.chainId = m_impl->m_nextChainId.fetch_add(1, std::memory_order_relaxed);
                newChain.creationTime = std::chrono::system_clock::now();
                newChain.lastUpdateTime = newChain.creationTime;
                newChain.involvedProcessIds.push_back(event.processId);
                newChain.events.push_back(event);
                newChain.isActive = true;
                newChain.confidence = 0.3 + (static_cast<double>(categories.size()) * 0.15);

                // Determine primary pattern (highest scoring category)
                if (!state.detectedPatterns.empty()) {
                    newChain.primaryPattern = state.detectedPatterns.back();
                }

                // Copy MITRE techniques
                newChain.mitreTechniques = state.triggeredMitreTechniques;

                newChain.description = L"Multi-stage attack chain from " +
                    state.processName + L" (PID " + std::to_wstring(state.processId) + L")";

                m_impl->m_attackChains.push_back(std::move(newChain));

                m_impl->m_stats.activeAttackChains.store(
                    std::count_if(m_impl->m_attackChains.begin(),
                                  m_impl->m_attackChains.end(),
                                  [](const BehaviorAttackChain& c) { return c.isActive; }),
                    std::memory_order_relaxed);

                // Copy chain to invoke callbacks outside lock (vector may reallocate)
                BehaviorAttackChain chainCopy = m_impl->m_attackChains.back();
                chainLock.unlock();
                InvokeAttackChainCallbacks(chainCopy);
                return;
            }
        }
    }
}

// ============================================================================
// Internal: Actions
// ============================================================================

void BehaviorAnalyzer::PerformAction(const BehaviorVerdict& verdict) {
    switch (verdict.action) {
        case RecommendedAction::Terminate:
        case RecommendedAction::BlockAndQuarantine:
        case RecommendedAction::IsolateEndpoint: {
            std::shared_lock cbLock(m_impl->m_callbackMutex);
            auto terminateCb = m_impl->m_terminationCallback;
            cbLock.unlock();

            if (terminateCb) {
                bool terminated = terminateCb(verdict.processId, verdict.description);
                if (terminated) {
                    m_impl->m_stats.processesTerminated.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_WARN(L"BehaviorAnalyzer", L"Process %u terminated: %ls",
                                verdict.processId, verdict.threatName.c_str());

                    std::unique_lock stateLock(m_impl->m_statesMutex);
                    auto it = m_impl->m_processStates.find(verdict.processId);
                    if (it != m_impl->m_processStates.end()) {
                        it->second.hasBeenTerminated = true;
                    }
                }
            } else {
                SS_LOG_WARN(L"BehaviorAnalyzer", L"No termination callback for PID %u (action=%u)",
                            verdict.processId, static_cast<uint32_t>(verdict.action));
            }
            break;
        }

        case RecommendedAction::Suspend: {
            std::shared_lock cbLock(m_impl->m_callbackMutex);
            auto terminateCb = m_impl->m_terminationCallback;
            cbLock.unlock();

            if (terminateCb) {
                terminateCb(verdict.processId,
                    L"Suspended: " + verdict.threatName);
            }
            break;
        }

        case RecommendedAction::Alert:
            SS_LOG_WARN(L"BehaviorAnalyzer", L"ALERT: %ls (PID %u, score %.1f)",
                        verdict.threatName.c_str(), verdict.processId, verdict.maliceScore);
            break;

        case RecommendedAction::Log:
            SS_LOG_INFO(L"BehaviorAnalyzer", L"Suspicious: %ls (PID %u, score %.1f)",
                        verdict.threatName.c_str(), verdict.processId, verdict.maliceScore);
            break;

        default:
            break;
    }
}

// ============================================================================
// Internal: MITRE ATT&CK Mapping
// ============================================================================

void BehaviorAnalyzer::AddMitreMapping(
    ProcessBehaviorState& state, BehaviorPatternType pattern)
{
    // Deduplicate patterns
    if (std::find(state.detectedPatterns.begin(), state.detectedPatterns.end(), pattern)
        == state.detectedPatterns.end()) {
        state.detectedPatterns.push_back(pattern);

        // Cap pattern list
        if (state.detectedPatterns.size() > BehaviorConstants::MAX_RULES_PER_PROCESS) {
            state.detectedPatterns.erase(state.detectedPatterns.begin());
        }
    }

    // Track pattern counts
    state.patternCounts[pattern]++;

    // Map to MITRE technique ID
    const char* mitreId = BehaviorPatternToMitre(pattern);
    if (mitreId && mitreId[0] != '\0') {
        std::string id(mitreId);
        if (std::find(state.triggeredMitreTechniques.begin(),
                      state.triggeredMitreTechniques.end(), id)
            == state.triggeredMitreTechniques.end()) {
            state.triggeredMitreTechniques.push_back(std::move(id));
        }
    }
}

// ============================================================================
// Internal: Trust & Sensitivity Checks
// ============================================================================

bool BehaviorAnalyzer::IsSensitiveTarget(const BehaviorEvent& event) const {
    if (event.targetPath.empty()) return false;
    auto lowerPath = ToLowerCase(event.targetPath);

    // System directories
    if (lowerPath.find(L"\\windows\\system32\\") != std::wstring::npos) return true;
    if (lowerPath.find(L"\\windows\\syswow64\\") != std::wstring::npos) return true;

    // Security databases (use exact hive paths to avoid false positives)
    if (lowerPath.find(L"\\config\\sam") != std::wstring::npos) return true;
    if (lowerPath.find(L"\\config\\security") != std::wstring::npos) return true;
    if (lowerPath.find(L"\\ntds.dit") != std::wstring::npos) return true;

    // Credential stores
    if (lowerPath.find(L"\\credentials\\") != std::wstring::npos) return true;
    if (lowerPath.find(L"\\vault\\") != std::wstring::npos) return true;

    return false;
}

bool BehaviorAnalyzer::IsProcessTrusted(const ProcessBehaviorState& state) const {
    if (state.isWhitelisted) return true;

    std::shared_lock cfgLock(m_impl->m_configMutex);
    if (m_impl->m_config.trustMicrosoftSigned && state.isSignedByMicrosoft) return true;
    if (m_impl->m_config.trustVendorSigned && state.isSignedByTrustedVendor) return true;

    return state.isSystemProcess;
}
// ============================================================================
// Internal: Callbacks
// ============================================================================

void BehaviorAnalyzer::InvokeVerdictCallbacks(const BehaviorVerdict& verdict) {
    std::vector<BehaviorVerdictCallback> callbacks;
    {
        std::shared_lock cbLock(m_impl->m_callbackMutex);
        callbacks.reserve(m_impl->m_verdictCallbacks.size());
        for (const auto& [id, cb] : m_impl->m_verdictCallbacks) {
            callbacks.push_back(cb);
        }
    }

    for (const auto& cb : callbacks) {
        try {
            cb(verdict);
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(L"BehaviorAnalyzer", L"Verdict callback exception: %S", ex.what());
        }
    }
}

void BehaviorAnalyzer::InvokeAttackChainCallbacks(const BehaviorAttackChain& chain) {
    std::vector<BehaviorAttackChainCallback> callbacks;
    {
        std::shared_lock cbLock(m_impl->m_callbackMutex);
        callbacks.reserve(m_impl->m_chainCallbacks.size());
        for (const auto& [id, cb] : m_impl->m_chainCallbacks) {
            callbacks.push_back(cb);
        }
    }

    for (const auto& cb : callbacks) {
        try {
            cb(chain);
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(L"BehaviorAnalyzer", L"Chain callback exception: %S", ex.what());
        }
    }
}

// ============================================================================
// Internal: Cleanup
// ============================================================================

void BehaviorAnalyzer::PerformCleanup() {
    try {
        auto now = std::chrono::steady_clock::now();

        // Snapshot config BEFORE acquiring statesMutex (lock order: config→states)
        std::chrono::hours retention;
        {
            std::shared_lock cfgLock(m_impl->m_configMutex);
            retention = m_impl->m_config.eventRetentionPeriod;
        }

        // Cleanup old process states
        {
            std::unique_lock stateLock(m_impl->m_statesMutex);

            auto it = m_impl->m_processStates.begin();
            while (it != m_impl->m_processStates.end()) {
                auto stateAge = std::chrono::duration_cast<std::chrono::hours>(
                    now - it->second.lastUpdateTime);
                // Remove if: score is zero AND state is old AND not terminated
                if (it->second.maliceScore < 1.0 &&
                    stateAge >= retention &&
                    !it->second.hasBeenTerminated) {
                    it = m_impl->m_processStates.erase(it);
                } else {
                    // Trim old events from history
                    while (!it->second.recentEvents.empty()) {
                        auto eventAge = std::chrono::duration_cast<std::chrono::hours>(
                            now - it->second.recentEvents.front().timestamp);
                        if (eventAge >= retention) {
                            it->second.recentEvents.pop_front();
                        } else {
                            break;
                        }
                    }
                    ++it;
                }
            }

            m_impl->m_stats.trackedProcesses.store(
                m_impl->m_processStates.size(), std::memory_order_relaxed);
        }

        // Cleanup old attack chains
        {
            std::unique_lock chainLock(m_impl->m_chainsMutex);
            m_impl->m_attackChains.erase(
                std::remove_if(m_impl->m_attackChains.begin(),
                               m_impl->m_attackChains.end(),
                               [&now](const BehaviorAttackChain& chain) {
                                   if (!chain.isActive) {
                                       auto age = std::chrono::duration_cast<std::chrono::hours>(
                                           std::chrono::system_clock::now() - chain.lastUpdateTime);
                                       return age.count() > 24;
                                   }
                                   return false;
                               }),
                m_impl->m_attackChains.end());

            m_impl->m_stats.activeAttackChains.store(
                std::count_if(m_impl->m_attackChains.begin(),
                              m_impl->m_attackChains.end(),
                              [](const BehaviorAttackChain& c) { return c.isActive; }),
                std::memory_order_relaxed);
        }
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(L"BehaviorAnalyzer", L"Cleanup exception: %S", ex.what());
    }
}

// ============================================================================
// Public: State Management
// ============================================================================

ProcessBehaviorState BehaviorAnalyzer::GetProcessState(uint32_t processId) const {
    std::shared_lock lock(m_impl->m_statesMutex);
    auto it = m_impl->m_processStates.find(processId);
    if (it != m_impl->m_processStates.end()) {
        return it->second;  // Return copy
    }
    return ProcessBehaviorState{};
}

bool BehaviorAnalyzer::IsProcessTracked(uint32_t processId) const noexcept {
    try {
        std::shared_lock lock(m_impl->m_statesMutex);
        return m_impl->m_processStates.count(processId) > 0;
    } catch (...) {
        return false;
    }
}

double BehaviorAnalyzer::GetMaliceScore(uint32_t processId) const noexcept {
    try {
        std::shared_lock lock(m_impl->m_statesMutex);
        auto it = m_impl->m_processStates.find(processId);
        if (it != m_impl->m_processStates.end()) {
            return it->second.maliceScore;
        }
    } catch (...) {}
    return 0.0;
}

void BehaviorAnalyzer::ResetProcessState(uint32_t processId) {
    std::unique_lock lock(m_impl->m_statesMutex);
    m_impl->m_processStates.erase(processId);
}

void BehaviorAnalyzer::ClearAllStates() {
    std::unique_lock lock(m_impl->m_statesMutex);
    m_impl->m_processStates.clear();
    m_impl->m_stats.trackedProcesses.store(0, std::memory_order_relaxed);
}

std::vector<uint32_t> BehaviorAnalyzer::GetTrackedProcessIds() const {
    std::shared_lock lock(m_impl->m_statesMutex);
    std::vector<uint32_t> pids;
    pids.reserve(m_impl->m_processStates.size());
    for (const auto& [pid, _] : m_impl->m_processStates) {
        pids.push_back(pid);
    }
    return pids;
}

std::vector<std::pair<uint32_t, double>> BehaviorAnalyzer::GetProcessesAboveThreshold(
    double threshold) const
{
    std::shared_lock lock(m_impl->m_statesMutex);
    std::vector<std::pair<uint32_t, double>> results;
    for (const auto& [pid, state] : m_impl->m_processStates) {
        if (state.maliceScore >= threshold) {
            results.emplace_back(pid, state.maliceScore);
        }
    }
    // Sort descending by score
    std::sort(results.begin(), results.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    return results;
}

// ============================================================================
// Public: Attack Chain Management
// ============================================================================

std::vector<BehaviorAttackChain> BehaviorAnalyzer::GetActiveAttackChains() const {
    std::shared_lock lock(m_impl->m_chainsMutex);
    std::vector<BehaviorAttackChain> active;
    for (const auto& chain : m_impl->m_attackChains) {
        if (chain.isActive) {
            active.push_back(chain);
        }
    }
    return active;
}

std::optional<BehaviorAttackChain> BehaviorAnalyzer::GetAttackChain(uint64_t chainId) const {
    std::shared_lock lock(m_impl->m_chainsMutex);
    for (const auto& chain : m_impl->m_attackChains) {
        if (chain.chainId == chainId) {
            return chain;
        }
    }
    return std::nullopt;
}

std::vector<BehaviorAttackChain> BehaviorAnalyzer::GetAttackChainsForProcess(uint32_t processId) const {
    std::shared_lock lock(m_impl->m_chainsMutex);
    std::vector<BehaviorAttackChain> results;
    for (const auto& chain : m_impl->m_attackChains) {
        for (auto pid : chain.involvedProcessIds) {
            if (pid == processId) {
                results.push_back(chain);
                break;
            }
        }
    }
    return results;
}

// ============================================================================
// Public: Process Operations
// ============================================================================

void BehaviorAnalyzer::WhitelistProcess(uint32_t processId) {
    std::unique_lock lock(m_impl->m_statesMutex);
    auto it = m_impl->m_processStates.find(processId);
    if (it != m_impl->m_processStates.end()) {
        it->second.isWhitelisted = true;
        it->second.maliceScore = 0.0;
        SS_LOG_INFO(L"BehaviorAnalyzer", L"PID %u whitelisted", processId);
    }
}

void BehaviorAnalyzer::UnwhitelistProcess(uint32_t processId) {
    std::unique_lock lock(m_impl->m_statesMutex);
    auto it = m_impl->m_processStates.find(processId);
    if (it != m_impl->m_processStates.end()) {
        it->second.isWhitelisted = false;
    }
}

void BehaviorAnalyzer::SetProcessScoreModifier(uint32_t processId, double modifier) {
    modifier = std::clamp(modifier, -100.0, 100.0);
    std::unique_lock lock(m_impl->m_statesMutex);
    auto it = m_impl->m_processStates.find(processId);
    if (it != m_impl->m_processStates.end()) {
        it->second.baseScoreModifier = modifier;
    }
}

// ============================================================================
// Public: Canary File Management
// ============================================================================

void BehaviorAnalyzer::AddCanaryFile(const std::wstring& path) {
    std::unique_lock lock(m_impl->m_canaryMutex);
    m_impl->m_canaryFiles.insert(ToLowerCase(path));
    SS_LOG_DEBUG(L"BehaviorAnalyzer", L"Canary file added: %ls", path.c_str());
}

void BehaviorAnalyzer::RemoveCanaryFile(const std::wstring& path) {
    std::unique_lock lock(m_impl->m_canaryMutex);
    m_impl->m_canaryFiles.erase(ToLowerCase(path));
}

std::vector<std::wstring> BehaviorAnalyzer::GetCanaryFiles() const {
    std::shared_lock lock(m_impl->m_canaryMutex);
    return std::vector<std::wstring>(m_impl->m_canaryFiles.begin(),
                                      m_impl->m_canaryFiles.end());
}

bool BehaviorAnalyzer::IsCanaryFile(const std::wstring& path) const {
    std::shared_lock lock(m_impl->m_canaryMutex);
    return m_impl->m_canaryFiles.count(ToLowerCase(path)) > 0;
}
// ============================================================================
// Public: Callbacks
// ============================================================================

uint64_t BehaviorAnalyzer::RegisterVerdictCallback(BehaviorVerdictCallback callback) {
    if (!callback) return 0;
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_verdictCallbacks.emplace(id, std::move(callback));
    return id;
}

bool BehaviorAnalyzer::UnregisterVerdictCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    return m_impl->m_verdictCallbacks.erase(callbackId) > 0;
}

uint64_t BehaviorAnalyzer::RegisterAttackChainCallback(BehaviorAttackChainCallback callback) {
    if (!callback) return 0;
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_chainCallbacks.emplace(id, std::move(callback));
    return id;
}

bool BehaviorAnalyzer::UnregisterAttackChainCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    return m_impl->m_chainCallbacks.erase(callbackId) > 0;
}

void BehaviorAnalyzer::SetTerminationCallback(ProcessTerminateCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_terminationCallback = std::move(callback);
}

// ============================================================================
// Public: Statistics
// ============================================================================

BehaviorAnalyzerStats BehaviorAnalyzer::GetStats() const {
    // Copy constructor handles atomic load/store internally
    return BehaviorAnalyzerStats(m_impl->m_stats);
}

void BehaviorAnalyzer::ResetStats() {
    m_impl->m_stats.Reset();
}

// ============================================================================
// Public: External Store Integration
// ============================================================================

void BehaviorAnalyzer::SetThreatIntelIndex(ThreatIntel::ThreatIntelIndex* index) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_threatIntel = index;
    SS_LOG_INFO(L"BehaviorAnalyzer", L"ThreatIntelIndex %s",
                index ? L"connected" : L"disconnected");
}

void BehaviorAnalyzer::SetWhitelistStore(Whitelist::WhitelistStore* store) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_whitelist = store;
    SS_LOG_INFO(L"BehaviorAnalyzer", L"WhitelistStore %s",
                store ? L"connected" : L"disconnected");
}

void BehaviorAnalyzer::SetSignatureStore(SignatureStore::SignatureStore* store) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_signatureStore = store;
    SS_LOG_INFO(L"BehaviorAnalyzer", L"SignatureStore %s",
                store ? L"connected" : L"disconnected");
}

// ============================================================================
// ProcessBehaviorState::Clear
// ============================================================================

void ProcessBehaviorState::Clear() noexcept {
    processId = 0;
    parentProcessId = 0;
    processName.clear();
    processPath.clear();
    commandLine.clear();
    userSid.clear();
    creationTime = {};
    stateCreatedAt = {};
    lastUpdateTime = {};

    maliceScore = 0.0;
    peakMaliceScore = 0.0;
    confidence = 0.0;
    baseScoreModifier = 0.0;

    triggeredMitreTechniques.clear();
    detectedPatterns.clear();
    patternCounts.clear();

    fileOperationCount = 0;
    filesModified = 0;
    filesCreated = 0;
    filesDeleted = 0;
    filesEncrypted = 0;
    canaryFilesTouched = 0;
    registryModifications = 0;
    networkConnections = 0;
    outboundBytes = 0;
    childProcessCount = 0;
    remoteThreadCount = 0;
    crossProcessWrites = 0;
    credentialAccessAttempts = 0;
    evasionAttempts = 0;

    highEntropyWrites = 0;
    fileRenames = 0;
    extensionChanges = 0;
    shadowCopyOperations = 0;
    ransomNoteIndicators = 0;
    fileModificationRate = 0.0;
    lastFileModTime = {};

    targetedProcessIds.clear();
    injectedDLLs.clear();
    remoteAllocations.clear();

    persistenceLocations.clear();
    createdServices.clear();
    createdTasks.clear();

    contactedDomains.clear();
    contactedIPs.clear();
    c2Indicators = 0;
    dnsQueryCount = 0;

    isSignedByMicrosoft = false;
    isSignedByTrustedVendor = false;
    isWhitelisted = false;
    isSystemProcess = false;
    hasDocumentParent = false;
    hasScriptParent = false;
    isNetworkDownloaded = false;

    recentEvents.clear();
    totalEventsProcessed = 0;

    currentVerdict = BehaviorVerdictType::Clean;
    recommendedAction = RecommendedAction::None;
    hasBeenReported = false;
    hasBeenTerminated = false;
}
// ============================================================================
// Free Functions: Constexpr Helpers
// ============================================================================

constexpr const char* BehaviorEventTypeToString(BehaviorEventType type) noexcept {
    switch (type) {
        case BehaviorEventType::Unknown: return "Unknown";
        case BehaviorEventType::ProcessCreate: return "ProcessCreate";
        case BehaviorEventType::ProcessTerminate: return "ProcessTerminate";
        case BehaviorEventType::ProcessOpen: return "ProcessOpen";
        case BehaviorEventType::ProcessDuplicate: return "ProcessDuplicate";
        case BehaviorEventType::ProcessSuspend: return "ProcessSuspend";
        case BehaviorEventType::ProcessResume: return "ProcessResume";
        case BehaviorEventType::ProcessInject: return "ProcessInject";
        case BehaviorEventType::ProcessHollow: return "ProcessHollow";
        case BehaviorEventType::ThreadCreate: return "ThreadCreate";
        case BehaviorEventType::ThreadTerminate: return "ThreadTerminate";
        case BehaviorEventType::ThreadRemoteCreate: return "ThreadRemoteCreate";
        case BehaviorEventType::ThreadSetContext: return "ThreadSetContext";
        case BehaviorEventType::ThreadSuspend: return "ThreadSuspend";
        case BehaviorEventType::ThreadResume: return "ThreadResume";
        case BehaviorEventType::ThreadQueueAPC: return "ThreadQueueAPC";
        case BehaviorEventType::ThreadHijack: return "ThreadHijack";
        case BehaviorEventType::MemoryAllocate: return "MemoryAllocate";
        case BehaviorEventType::MemoryFree: return "MemoryFree";
        case BehaviorEventType::MemoryProtect: return "MemoryProtect";
        case BehaviorEventType::MemoryWrite: return "MemoryWrite";
        case BehaviorEventType::MemoryRead: return "MemoryRead";
        case BehaviorEventType::MemoryRemoteAllocate: return "MemoryRemoteAllocate";
        case BehaviorEventType::MemoryRemoteWrite: return "MemoryRemoteWrite";
        case BehaviorEventType::MemoryRemoteProtect: return "MemoryRemoteProtect";
        case BehaviorEventType::MemoryMap: return "MemoryMap";
        case BehaviorEventType::MemoryUnmap: return "MemoryUnmap";
        case BehaviorEventType::FileCreate: return "FileCreate";
        case BehaviorEventType::FileOpen: return "FileOpen";
        case BehaviorEventType::FileRead: return "FileRead";
        case BehaviorEventType::FileWrite: return "FileWrite";
        case BehaviorEventType::FileDelete: return "FileDelete";
        case BehaviorEventType::FileRename: return "FileRename";
        case BehaviorEventType::FileSetAttributes: return "FileSetAttributes";
        case BehaviorEventType::FileSetSecurity: return "FileSetSecurity";
        case BehaviorEventType::FileLock: return "FileLock";
        case BehaviorEventType::FileUnlock: return "FileUnlock";
        case BehaviorEventType::FileEncrypt: return "FileEncrypt";
        case BehaviorEventType::FileDecrypt: return "FileDecrypt";
        case BehaviorEventType::DirectoryCreate: return "DirectoryCreate";
        case BehaviorEventType::DirectoryDelete: return "DirectoryDelete";
        case BehaviorEventType::DirectoryEnumerate: return "DirectoryEnumerate";
        case BehaviorEventType::RegistryCreateKey: return "RegistryCreateKey";
        case BehaviorEventType::RegistryDeleteKey: return "RegistryDeleteKey";
        case BehaviorEventType::RegistrySetValue: return "RegistrySetValue";
        case BehaviorEventType::RegistryDeleteValue: return "RegistryDeleteValue";
        case BehaviorEventType::RegistryQueryValue: return "RegistryQueryValue";
        case BehaviorEventType::RegistryEnumKey: return "RegistryEnumKey";
        case BehaviorEventType::RegistryEnumValue: return "RegistryEnumValue";
        case BehaviorEventType::RegistryLoadHive: return "RegistryLoadHive";
        case BehaviorEventType::RegistryUnloadHive: return "RegistryUnloadHive";
        case BehaviorEventType::RegistryRenameKey: return "RegistryRenameKey";
        case BehaviorEventType::NetworkConnect: return "NetworkConnect";
        case BehaviorEventType::NetworkListen: return "NetworkListen";
        case BehaviorEventType::NetworkAccept: return "NetworkAccept";
        case BehaviorEventType::NetworkSend: return "NetworkSend";
        case BehaviorEventType::NetworkReceive: return "NetworkReceive";
        case BehaviorEventType::NetworkDNSQuery: return "NetworkDNSQuery";
        case BehaviorEventType::NetworkHTTPRequest: return "NetworkHTTPRequest";
        case BehaviorEventType::NetworkHTTPSRequest: return "NetworkHTTPSRequest";
        case BehaviorEventType::NetworkDownload: return "NetworkDownload";
        case BehaviorEventType::NetworkUpload: return "NetworkUpload";
        case BehaviorEventType::ServiceInstall: return "ServiceInstall";
        case BehaviorEventType::ServiceStart: return "ServiceStart";
        case BehaviorEventType::ServiceStop: return "ServiceStop";
        case BehaviorEventType::ServiceDelete: return "ServiceDelete";
        case BehaviorEventType::ServiceModify: return "ServiceModify";
        case BehaviorEventType::TaskCreate: return "TaskCreate";
        case BehaviorEventType::TaskDelete: return "TaskDelete";
        case BehaviorEventType::TaskModify: return "TaskModify";
        case BehaviorEventType::TaskRun: return "TaskRun";
        case BehaviorEventType::WMIQuery: return "WMIQuery";
        case BehaviorEventType::WMISubscription: return "WMISubscription";
        case BehaviorEventType::WMIExec: return "WMIExec";
        case BehaviorEventType::WMIConsumer: return "WMIConsumer";
        case BehaviorEventType::ScriptExecute: return "ScriptExecute";
        case BehaviorEventType::PowerShellCommand: return "PowerShellCommand";
        case BehaviorEventType::PowerShellScript: return "PowerShellScript";
        case BehaviorEventType::VBScriptExecute: return "VBScriptExecute";
        case BehaviorEventType::JScriptExecute: return "JScriptExecute";
        case BehaviorEventType::BatchExecute: return "BatchExecute";
        case BehaviorEventType::CredentialAccess: return "CredentialAccess";
        case BehaviorEventType::LSASSAccess: return "LSASSAccess";
        case BehaviorEventType::SAMAccess: return "SAMAccess";
        case BehaviorEventType::CredentialDump: return "CredentialDump";
        case BehaviorEventType::TokenSteal: return "TokenSteal";
        case BehaviorEventType::TokenDuplicate: return "TokenDuplicate";
        case BehaviorEventType::AntiDebugAttempt: return "AntiDebugAttempt";
        case BehaviorEventType::VMDetectionAttempt: return "VMDetectionAttempt";
        case BehaviorEventType::SandboxDetectionAttempt: return "SandboxDetectionAttempt";
        case BehaviorEventType::LogClear: return "LogClear";
        case BehaviorEventType::Timestomp: return "Timestomp";
        case BehaviorEventType::SecurityDisable: return "SecurityDisable";
        case BehaviorEventType::SystemShutdown: return "SystemShutdown";
        case BehaviorEventType::SystemReboot: return "SystemReboot";
        case BehaviorEventType::DriverLoad: return "DriverLoad";
        case BehaviorEventType::DriverUnload: return "DriverUnload";
        case BehaviorEventType::ShadowCopyDelete: return "ShadowCopyDelete";
        case BehaviorEventType::BootConfigModify: return "BootConfigModify";
        case BehaviorEventType::CryptoKeyGenerate: return "CryptoKeyGenerate";
        case BehaviorEventType::CryptoKeyImport: return "CryptoKeyImport";
        case BehaviorEventType::CryptoEncrypt: return "CryptoEncrypt";
        case BehaviorEventType::CryptoDecrypt: return "CryptoDecrypt";
        case BehaviorEventType::CryptoSign: return "CryptoSign";
        case BehaviorEventType::CryptoHash: return "CryptoHash";
        default: return "Unknown";
    }
}

constexpr const char* BehaviorPatternToMitre(BehaviorPatternType pattern) noexcept {
    switch (pattern) {
        // Ransomware
        case BehaviorPatternType::RansomwareEncryption: return "T1486";
        case BehaviorPatternType::RansomwareShadowDelete: return "T1490";
        case BehaviorPatternType::RansomwareNote: return "T1486";
        case BehaviorPatternType::RansomwareExtensionChange: return "T1486";
        case BehaviorPatternType::RansomwareCanaryTouch: return "T1486";
        case BehaviorPatternType::RansomwareMassDelete: return "T1485";
        case BehaviorPatternType::RansomwareBackupDestroy: return "T1490";
        // Injection
        case BehaviorPatternType::InjectionDLL: return "T1055.001";
        case BehaviorPatternType::InjectionHollowing: return "T1055.012";
        case BehaviorPatternType::InjectionRemoteThread: return "T1055.002";
        case BehaviorPatternType::InjectionAPC: return "T1055.004";
        case BehaviorPatternType::InjectionAtomBomb: return "T1055.011";
        case BehaviorPatternType::InjectionThreadHijack: return "T1055.003";
        case BehaviorPatternType::InjectionReflective: return "T1055.001";
        case BehaviorPatternType::InjectionDoppelgang: return "T1055.013";
        // Persistence
        case BehaviorPatternType::PersistenceRunKey: return "T1547.001";
        case BehaviorPatternType::PersistenceScheduledTask: return "T1053.005";
        case BehaviorPatternType::PersistenceService: return "T1543.003";
        case BehaviorPatternType::PersistenceWMI: return "T1546.003";
        case BehaviorPatternType::PersistenceStartupFolder: return "T1547.001";
        case BehaviorPatternType::PersistenceBootConfig: return "T1542";
        case BehaviorPatternType::PersistenceDLLHijack: return "T1574.001";
        case BehaviorPatternType::PersistenceCOMHijack: return "T1546.015";
        case BehaviorPatternType::PersistenceAppInit: return "T1546.010";
        case BehaviorPatternType::PersistenceIFEO: return "T1546.012";
        // Credential Access
        case BehaviorPatternType::CredentialLSASSDump: return "T1003.001";
        case BehaviorPatternType::CredentialSAMAccess: return "T1003.002";
        case BehaviorPatternType::CredentialMimikatz: return "T1003";
        case BehaviorPatternType::CredentialStoreAccess: return "T1555";
        case BehaviorPatternType::CredentialKeylogger: return "T1056.001";
        case BehaviorPatternType::CredentialBrowserTheft: return "T1555.003";
        case BehaviorPatternType::CredentialTokenManip: return "T1134";
        // Evasion
        case BehaviorPatternType::EvasionLogClear: return "T1070.001";
        case BehaviorPatternType::EvasionSecurityDisable: return "T1562.001";
        case BehaviorPatternType::EvasionTimestomp: return "T1070.006";
        case BehaviorPatternType::EvasionFileHide: return "T1564.001";
        case BehaviorPatternType::EvasionMasquerade: return "T1036";
        case BehaviorPatternType::EvasionRootkit: return "T1014";
        case BehaviorPatternType::EvasionAMSIBypass: return "T1562.001";
        case BehaviorPatternType::EvasionETWTamper: return "T1562.006";
        // Exfiltration
        case BehaviorPatternType::ExfilLargeTransfer: return "T1048";
        case BehaviorPatternType::ExfilArchiveCreate: return "T1560.001";
        case BehaviorPatternType::ExfilDNSTunnel: return "T1048.003";
        case BehaviorPatternType::ExfilCloudUpload: return "T1567";
        case BehaviorPatternType::ExfilEmail: return "T1048.002";
        case BehaviorPatternType::ExfilClipboard: return "T1115";
        case BehaviorPatternType::ExfilScreenshot: return "T1113";
        // Lateral Movement
        case BehaviorPatternType::LateralService: return "T1021.002";
        case BehaviorPatternType::LateralWMI: return "T1047";
        case BehaviorPatternType::LateralPSExec: return "T1569.002";
        case BehaviorPatternType::LateralRemoteRegistry: return "T1021.001";
        case BehaviorPatternType::LateralRDP: return "T1021.001";
        case BehaviorPatternType::LateralSMB: return "T1021.002";
        // C2
        case BehaviorPatternType::C2Beacon: return "T1071";
        case BehaviorPatternType::C2KnownProtocol: return "T1071.001";
        case BehaviorPatternType::C2Encrypted: return "T1573";
        case BehaviorPatternType::C2DGA: return "T1568.002";
        case BehaviorPatternType::C2FastFlux: return "T1568.001";
        default: return "";
    }
}

constexpr const char* BehaviorPatternTypeToString(BehaviorPatternType pattern) noexcept {
    switch (pattern) {
        case BehaviorPatternType::Unknown: return "Unknown";
        case BehaviorPatternType::RansomwareEncryption: return "RansomwareEncryption";
        case BehaviorPatternType::RansomwareShadowDelete: return "RansomwareShadowDelete";
        case BehaviorPatternType::RansomwareNote: return "RansomwareNote";
        case BehaviorPatternType::RansomwareExtensionChange: return "RansomwareExtensionChange";
        case BehaviorPatternType::RansomwareCanaryTouch: return "RansomwareCanaryTouch";
        case BehaviorPatternType::RansomwareMassDelete: return "RansomwareMassDelete";
        case BehaviorPatternType::RansomwareBackupDestroy: return "RansomwareBackupDestroy";
        case BehaviorPatternType::InjectionDLL: return "InjectionDLL";
        case BehaviorPatternType::InjectionHollowing: return "InjectionHollowing";
        case BehaviorPatternType::InjectionRemoteThread: return "InjectionRemoteThread";
        case BehaviorPatternType::InjectionAPC: return "InjectionAPC";
        case BehaviorPatternType::InjectionAtomBomb: return "InjectionAtomBomb";
        case BehaviorPatternType::InjectionThreadHijack: return "InjectionThreadHijack";
        case BehaviorPatternType::InjectionReflective: return "InjectionReflective";
        case BehaviorPatternType::InjectionDoppelgang: return "InjectionDoppelgang";
        case BehaviorPatternType::PersistenceRunKey: return "PersistenceRunKey";
        case BehaviorPatternType::PersistenceScheduledTask: return "PersistenceScheduledTask";
        case BehaviorPatternType::PersistenceService: return "PersistenceService";
        case BehaviorPatternType::PersistenceWMI: return "PersistenceWMI";
        case BehaviorPatternType::PersistenceStartupFolder: return "PersistenceStartupFolder";
        case BehaviorPatternType::PersistenceBootConfig: return "PersistenceBootConfig";
        case BehaviorPatternType::PersistenceDLLHijack: return "PersistenceDLLHijack";
        case BehaviorPatternType::PersistenceCOMHijack: return "PersistenceCOMHijack";
        case BehaviorPatternType::PersistenceAppInit: return "PersistenceAppInit";
        case BehaviorPatternType::PersistenceIFEO: return "PersistenceIFEO";
        case BehaviorPatternType::CredentialLSASSDump: return "CredentialLSASSDump";
        case BehaviorPatternType::CredentialSAMAccess: return "CredentialSAMAccess";
        case BehaviorPatternType::CredentialMimikatz: return "CredentialMimikatz";
        case BehaviorPatternType::CredentialStoreAccess: return "CredentialStoreAccess";
        case BehaviorPatternType::CredentialKeylogger: return "CredentialKeylogger";
        case BehaviorPatternType::CredentialBrowserTheft: return "CredentialBrowserTheft";
        case BehaviorPatternType::CredentialTokenManip: return "CredentialTokenManip";
        case BehaviorPatternType::EvasionLogClear: return "EvasionLogClear";
        case BehaviorPatternType::EvasionSecurityDisable: return "EvasionSecurityDisable";
        case BehaviorPatternType::EvasionTimestomp: return "EvasionTimestomp";
        case BehaviorPatternType::EvasionFileHide: return "EvasionFileHide";
        case BehaviorPatternType::EvasionMasquerade: return "EvasionMasquerade";
        case BehaviorPatternType::EvasionRootkit: return "EvasionRootkit";
        case BehaviorPatternType::EvasionAMSIBypass: return "EvasionAMSIBypass";
        case BehaviorPatternType::EvasionETWTamper: return "EvasionETWTamper";
        case BehaviorPatternType::ExfilLargeTransfer: return "ExfilLargeTransfer";
        case BehaviorPatternType::ExfilArchiveCreate: return "ExfilArchiveCreate";
        case BehaviorPatternType::ExfilDNSTunnel: return "ExfilDNSTunnel";
        case BehaviorPatternType::ExfilCloudUpload: return "ExfilCloudUpload";
        case BehaviorPatternType::ExfilEmail: return "ExfilEmail";
        case BehaviorPatternType::ExfilClipboard: return "ExfilClipboard";
        case BehaviorPatternType::ExfilScreenshot: return "ExfilScreenshot";
        case BehaviorPatternType::LateralService: return "LateralService";
        case BehaviorPatternType::LateralWMI: return "LateralWMI";
        case BehaviorPatternType::LateralPSExec: return "LateralPSExec";
        case BehaviorPatternType::LateralRemoteRegistry: return "LateralRemoteRegistry";
        case BehaviorPatternType::LateralRDP: return "LateralRDP";
        case BehaviorPatternType::LateralSMB: return "LateralSMB";
        case BehaviorPatternType::C2Beacon: return "C2Beacon";
        case BehaviorPatternType::C2KnownProtocol: return "C2KnownProtocol";
        case BehaviorPatternType::C2Encrypted: return "C2Encrypted";
        case BehaviorPatternType::C2DGA: return "C2DGA";
        case BehaviorPatternType::C2FastFlux: return "C2FastFlux";
        default: return "Unknown";
    }
}
// ============================================================================
// Free Functions: Event Factory Helpers
// ============================================================================

BehaviorEvent CreateFileEvent(
    BehaviorEventType type,
    uint32_t processId,
    const std::wstring& path,
    bool success) noexcept
{
    BehaviorEvent event;
    event.eventType = type;
    event.category = BehaviorEventCategory::FileSystem;
    event.processId = processId;
    event.targetPath = path;
    event.success = success;
    event.timestamp = std::chrono::steady_clock::now();
    event.systemTime = std::chrono::system_clock::now();

    // Extract extension
    auto dotPos = path.rfind(L'.');
    if (dotPos != std::wstring::npos) {
        event.fileExtension = path.substr(dotPos);
    }

    return event;
}

BehaviorEvent CreateRegistryEvent(
    BehaviorEventType type,
    uint32_t processId,
    const std::wstring& keyPath,
    const std::wstring& valueName,
    bool success) noexcept
{
    BehaviorEvent event;
    event.eventType = type;
    event.category = BehaviorEventCategory::Registry;
    event.processId = processId;
    event.targetPath = keyPath;
    event.valueName = valueName;
    event.success = success;
    event.timestamp = std::chrono::steady_clock::now();
    event.systemTime = std::chrono::system_clock::now();
    return event;
}

BehaviorEvent CreateNetworkEvent(
    BehaviorEventType type,
    uint32_t processId,
    const std::string& remoteHost,
    uint16_t remotePort,
    const std::string& protocol) noexcept
{
    BehaviorEvent event;
    event.eventType = type;
    event.category = BehaviorEventCategory::Network;
    event.processId = processId;
    event.remoteHostname = remoteHost;
    event.remotePort = remotePort;
    event.protocol = protocol;
    event.timestamp = std::chrono::steady_clock::now();
    event.systemTime = std::chrono::system_clock::now();

    // Parse IP from hostname if it looks like an address
    if (!remoteHost.empty() && (std::isdigit(static_cast<unsigned char>(remoteHost[0])) ||
                                 remoteHost.find(':') != std::string::npos)) {
        event.remoteIP = remoteHost;
    }

    return event;
}

BehaviorEvent CreateProcessEvent(
    BehaviorEventType type,
    uint32_t sourceProcessId,
    uint32_t targetProcessId) noexcept
{
    BehaviorEvent event;
    event.eventType = type;
    event.category = BehaviorEventCategory::Process;
    event.processId = sourceProcessId;
    event.targetProcessId = targetProcessId;
    event.timestamp = std::chrono::steady_clock::now();
    event.systemTime = std::chrono::system_clock::now();
    return event;
}

// ============================================================================
// Free Functions: Analysis Helpers
// ============================================================================

double CalculateFileEntropy(const std::wstring& filePath) noexcept {
    try {
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return 0.0;

        // Read first 64KB for entropy calculation
        constexpr size_t SAMPLE_SIZE = 65536;
        std::vector<uint8_t> buffer(SAMPLE_SIZE);
        DWORD bytesRead = 0;
        BOOL ok = ReadFile(hFile, buffer.data(), static_cast<DWORD>(SAMPLE_SIZE),
                           &bytesRead, nullptr);
        CloseHandle(hFile);

        if (!ok || bytesRead == 0) return 0.0;

        // Shannon entropy calculation
        std::array<uint64_t, 256> freq{};
        for (DWORD i = 0; i < bytesRead; ++i) {
            freq[buffer[i]]++;
        }

        double entropy = 0.0;
        double total = static_cast<double>(bytesRead);
        for (auto count : freq) {
            if (count > 0) {
                double p = static_cast<double>(count) / total;
                entropy -= p * std::log2(p);
            }
        }

        return entropy;
    }
    catch (...) {
        return 0.0;
    }
}

bool IsRansomNotePattern(const std::wstring& path) noexcept {
    if (path.empty()) return false;

    auto lowerPath = ToLowerCase(path);

    // Extract filename from path
    auto lastSlash = lowerPath.rfind(L'\\');
    std::wstring filename = (lastSlash != std::wstring::npos)
        ? lowerPath.substr(lastSlash + 1) : lowerPath;

    // Known ransom note patterns
    static const std::wstring patterns[] = {
        L"readme", L"how_to_decrypt", L"how_to_recover",
        L"restore_files", L"decrypt_instructions", L"help_decrypt",
        L"ransom", L"your_files", L"recovery_key",
        L"important_read_me", L"attention", L"_readme",
        L"decrypt_info", L"#decrypt", L"recover_files",
        L"all_files_encrypted"
    };

    for (const auto& pattern : patterns) {
        if (filename.find(pattern) != std::wstring::npos) {
            return true;
        }
    }

    // Check for common ransom note extensions
    if (filename.ends_with(L".hta") || filename.ends_with(L".html") ||
        filename.ends_with(L".txt")) {
        for (const auto& pattern : patterns) {
            if (filename.find(pattern) != std::wstring::npos) {
                return true;
            }
        }
    }

    return false;
}

bool IsPersistenceRegistryPath(const std::wstring& path) noexcept {
    if (path.empty()) return false;
    auto lowerPath = ToLowerCase(path);

    static const std::wstring keys[] = {
        L"\\currentversion\\run",
        L"\\currentversion\\runonce",
        L"\\currentversion\\runservices",
        L"\\currentversion\\policies\\explorer\\run",
        L"\\winlogon\\",
        L"\\currentversion\\explorer\\shell folders",
        L"\\active setup\\installed components",
        L"\\currentcontrolset\\services",
        L"\\image file execution options",
        L"\\silentprocessexit",
        L"\\appcompat",
        L"\\app paths",
        L"\\shellserviceobjectdelayload",
        L"\\appinit_dlls",
        L"\\clsid",
        L"\\shellex",
    };

    for (const auto& key : keys) {
        if (lowerPath.find(key) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

bool IsLSASSProcess(const std::wstring& processName) noexcept {
    if (processName.empty()) return false;
    auto lower = ToLowerCase(processName);
    return lower == L"lsass.exe" || lower == L"lsass" || lower == L"lsaiso.exe";
}

bool IsDocumentApplication(const std::wstring& processName) noexcept {
    if (processName.empty()) return false;
    auto lower = ToLowerCase(processName);
    static const std::wstring apps[] = {
        L"winword.exe", L"excel.exe", L"powerpnt.exe", L"outlook.exe",
        L"onenote.exe", L"msaccess.exe", L"acrord32.exe",
        L"acrobat.exe", L"foxitreader.exe", L"visio.exe",
        L"mspub.exe", L"wordpad.exe"
    };
    for (const auto& app : apps) {
        if (lower == app) return true;
    }
    return false;
}

bool IsScriptInterpreter(const std::wstring& processName) noexcept {
    if (processName.empty()) return false;
    auto lower = ToLowerCase(processName);
    static const std::wstring interpreters[] = {
        L"powershell.exe", L"pwsh.exe", L"cmd.exe", L"wscript.exe",
        L"cscript.exe", L"mshta.exe", L"regsvr32.exe", L"rundll32.exe",
        L"msiexec.exe", L"certutil.exe", L"bitsadmin.exe",
        L"wmic.exe", L"bash.exe", L"python.exe", L"python3.exe",
        L"perl.exe", L"ruby.exe", L"node.exe"
    };
    for (const auto& interp : interpreters) {
        if (lower == interp) return true;
    }
    return false;
}

}  // namespace Engine
}  // namespace Core
}  // namespace ShadowStrike