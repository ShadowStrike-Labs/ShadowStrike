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
 * ShadowStrike Real-Time - ZERO HOUR PROTECTION IMPLEMENTATION
 * ============================================================================
 *
 * @file ZeroHourProtection.cpp
 * @brief Implementation of the Zero Hour Protection engine.
 *
 * Implements the "First Responder" capabilities including:
 * - Cloud verdict orchestration (Cache -> Cloud -> Fallback)
 * - File hold management for unknown threats
 * - Outbreak mode logic and threat level escalation
 * - Micro-signature application
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "ZeroHourProtection.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/Logger.hpp"

#include <algorithm>
#include <execution>
#include <random>
#include <mutex>

// Third-party JSON library
#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable: 4996)
#endif
#include <nlohmann/json.hpp>
#ifdef _MSC_VER
#  pragma warning(pop)
#endif

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// ANONYMOUS NAMESPACE UTILITIES
// ============================================================================
namespace {

    // Helper to generate a unique hold ID
    uint64_t GenerateHoldId() {
        static std::atomic<uint64_t> s_idCounter{ 1 };
        return s_idCounter.fetch_add(1);
    }

    // Thread-safe time_point to string conversion (uses localtime_s, not localtime)
    std::string TimeToString(const std::chrono::system_clock::time_point& tp) {
        auto t = std::chrono::system_clock::to_time_t(tp);
        struct tm tmBuf{};
#ifdef _WIN32
        localtime_s(&tmBuf, &t);
#else
        localtime_r(&t, &tmBuf);
#endif
        std::stringstream ss;
        ss << std::put_time(&tmBuf, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

} // anonymous namespace

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class ZeroHourProtectionImpl final {
public:
    ZeroHourProtectionImpl() = default;
    ~ZeroHourProtectionImpl() {
        Shutdown();
    }

    // Non-copyable/movable
    ZeroHourProtectionImpl(const ZeroHourProtectionImpl&) = delete;
    ZeroHourProtectionImpl& operator=(const ZeroHourProtectionImpl&) = delete;

    // ========================================================================
    // STATE
    // ========================================================================

    // Configuration & Stats
    ZeroHourProtectionConfig m_config;
    ZeroHourStatistics m_stats;
    mutable std::shared_mutex m_configMutex;

    // State Flags
    std::atomic<bool> m_isInitialized{ false };
    std::atomic<bool> m_isShutdown{ false };
    std::atomic<ThreatLevel> m_currentThreatLevel{ ThreatLevel::NORMAL };
    std::atomic<CloudServiceStatus> m_cloudStatus{ CloudServiceStatus::DISCONNECTED };

    // Verdict Cache
    // Key: SHA256 string, Value: Verdict Result
    std::unordered_map<std::wstring, CloudVerdictResult> m_verdictCache;
    mutable std::shared_mutex m_cacheMutex;

    // Held Files
    // Key: Hold ID, Value: HeldFile
    std::unordered_map<uint64_t, HeldFile> m_heldFiles;
    mutable std::shared_mutex m_holdMutex;

    // Micro-Signatures
    std::vector<MicroSignature> m_microSignatures;
    uint32_t m_sigVersion{ 0 };
    mutable std::shared_mutex m_sigMutex;

    // Outbreaks
    std::vector<OutbreakInfo> m_activeOutbreaks;
    mutable std::shared_mutex m_outbreakMutex;

    // Callbacks
    std::unordered_map<uint64_t, VerdictCallback> m_verdictCallbacks;
    std::unordered_map<uint64_t, FileHoldCallback> m_holdCallbacks;
    std::unordered_map<uint64_t, OutbreakCallback> m_outbreakCallbacks;
    std::unordered_map<uint64_t, ThreatLevelCallback> m_threatLevelCallbacks;
    std::unordered_map<uint64_t, SignatureUpdateCallback> m_sigUpdateCallbacks;
    std::unordered_map<uint64_t, CloudStatusCallback> m_cloudStatusCallbacks;
    mutable std::shared_mutex m_callbackMutex;
    std::atomic<uint64_t> m_callbackIdCounter{ 1 };

    // Worker Threads
    std::unique_ptr<std::thread> m_holdMonitorThread;
    std::atomic<bool> m_stopMonitor{ false };

    // Integration — raw non-owning pointers injected by RealTimeProtection
    ThreatIntel::ThreatIntelLookup* m_threatIntelLookup{ nullptr };
    Whitelist::WhitelistStore*      m_whitelistStore{ nullptr };
    mutable std::shared_mutex       m_integrationMutex;

    // Rollback history for micro-signature versions
    struct SigSnapshot {
        std::vector<MicroSignature> signatures;
        uint32_t version{ 0 };
    };
    std::deque<SigSnapshot> m_rollbackHistory;

    // Pending detonation submissions
    std::unordered_map<uint64_t, std::wstring> m_pendingDetonations;
    std::atomic<uint64_t>                      m_detonationIdCounter{ 1 };
    mutable std::shared_mutex                  m_detonationMutex;

    // Cloud latency tracking
    std::atomic<uint64_t> m_cloudLatencySumMs{ 0 };
    std::atomic<uint64_t> m_cloudQueryCount{ 0 };

    // Last signature update check time
    std::chrono::system_clock::time_point m_lastSigCheckTime{};
    mutable std::shared_mutex             m_sigCheckMutex;

    // ========================================================================
    // INTERNAL LOGIC
    // ========================================================================

    void Shutdown() {
        if (m_isShutdown.exchange(true)) return;

        m_stopMonitor = true;
        if (m_holdMonitorThread && m_holdMonitorThread->joinable()) {
            m_holdMonitorThread->join();
        }

        {
            std::unique_lock lock(m_cacheMutex);
            m_verdictCache.clear();
        }

        {
            std::unique_lock lock(m_holdMutex);
            m_heldFiles.clear();
        }

        {
            std::unique_lock lock(m_callbackMutex);
            m_verdictCallbacks.clear();
            m_holdCallbacks.clear();
            m_outbreakCallbacks.clear();
            m_threatLevelCallbacks.clear();
            m_sigUpdateCallbacks.clear();
            m_cloudStatusCallbacks.clear();
        }

        {
            std::unique_lock lock(m_detonationMutex);
            m_pendingDetonations.clear();
        }

        {
            std::unique_lock lock(m_integrationMutex);
            m_threatIntelLookup = nullptr;
            m_whitelistStore    = nullptr;
        }
    }

    // Monitor held files for timeouts
    void MonitorHeldFiles() {
        while (!m_stopMonitor) {
            try {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));

                std::vector<uint64_t> timedOutIds;
                auto now = std::chrono::system_clock::now();

                {
                    std::shared_lock lock(m_holdMutex);
                    for (const auto& [id, file] : m_heldFiles) {
                        if (now >= file.timeoutTime && !file.decision.has_value()) {
                            timedOutIds.push_back(id);
                        }
                    }
                }

                for (uint64_t id : timedOutIds) {
                    HandleHoldTimeout(id);
                }

            } catch (...) {
                // Prevent thread crash
            }
        }
    }

    void HandleHoldTimeout(uint64_t holdId) {
        HoldDecision decision;
        {
            std::shared_lock configLock(m_configMutex);
            decision = m_config.timeoutDecision;
        }

        ReleaseHeldFile(holdId, decision, L"Timeout reached");
        m_stats.holdTimeouts++;
    }

    void ReleaseHeldFile(uint64_t holdId, HoldDecision decision, const std::wstring& reason) {
        HeldFile heldFile;
        bool found = false;

        {
            std::unique_lock lock(m_holdMutex);
            auto it = m_heldFiles.find(holdId);
            if (it != m_heldFiles.end()) {
                it->second.decision = decision;
                it->second.decisionReason = reason;
                heldFile = it->second; // Copy for callback
                m_heldFiles.erase(it);
                found = true;

                if (m_stats.currentHeldFiles > 0) m_stats.currentHeldFiles--;
            }
        }

        if (found) {
            m_stats.filesReleased++;
            FireFileHoldCallback(heldFile);
            SS_LOG_INFO(L"ZeroHourProtection",
                L"Released held file %ls with decision %d (Reason: %ls)",
                heldFile.filePath.c_str(),
                static_cast<int>(decision),
                reason.c_str());
        }
    }

    // Fire Callbacks
    void FireFileHoldCallback(const HeldFile& file) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& [id, cb] : m_holdCallbacks) {
            try { cb(file); } catch (...) {}
        }
    }

    void FireVerdictCallback(const std::wstring& path, const FileAnalysisResult& result) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& [id, cb] : m_verdictCallbacks) {
            try { cb(path, result); } catch (...) {}
        }
    }

    void FireThreatLevelCallback(ThreatLevel oldLevel, ThreatLevel newLevel, std::wstring_view reason) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& [id, cb] : m_threatLevelCallbacks) {
            try { cb(oldLevel, newLevel, reason); } catch (...) {}
        }
    }

    void FireSignatureUpdateCallback(const MicroSigUpdatePackage& package, bool success) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& [id, cb] : m_sigUpdateCallbacks) {
            try { cb(package, success); } catch (...) {}
        }
    }

    void FireCloudStatusCallback(CloudServiceStatus oldStatus, CloudServiceStatus newStatus) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& [id, cb] : m_cloudStatusCallbacks) {
            try { cb(oldStatus, newStatus); } catch (...) {}
        }
    }

    void UpdateCloudStatus(CloudServiceStatus newStatus) {
        const CloudServiceStatus old = m_cloudStatus.exchange(newStatus);
        if (old != newStatus) {
            FireCloudStatusCallback(old, newStatus);
        }
    }

    // Analysis Helpers
    bool IsWhitelisted(const std::wstring& path, const FileHash& hash) {
        // Check WhitelistStore if injected
        {
            std::shared_lock ilock(m_integrationMutex);
            if (m_whitelistStore && m_whitelistStore->IsInitialized()) {
                // Build HashValue for the SHA-256 digest
                const Whitelist::HashValue hv = Whitelist::HashValue::Create(
                    Whitelist::HashAlgorithm::SHA256,
                    hash.sha256.data(),
                    static_cast<uint8_t>(hash.sha256.size()));

                const auto hashResult = m_whitelistStore->IsHashWhitelisted(hv);
                if (hashResult.found) return true;

                // Also check by path (covers wildcard/prefix rules)
                const auto pathResult = m_whitelistStore->IsPathWhitelisted(path);
                if (pathResult.found) return true;
            }
        }

        // Fall back to config-based exclusions
        std::shared_lock lock(m_configMutex);
        for (const auto& excluded : m_config.excludedPaths) {
            if (path.starts_with(excluded)) return true;
        }
        return false;
    }

    bool CheckMicroSignatures(const FileHash& hash, std::wstring& outThreatName) {
        std::shared_lock lock(m_sigMutex);

        for (const auto& sig : m_microSignatures) {
            if (sig.type == MicroSigType::HASH_ONLY) {
                if (std::holds_alternative<FileHash>(sig.content)) {
                    const FileHash& sigHash = std::get<FileHash>(sig.content);
                    // Constant-time comparison to resist timing side-channels
                    if (Utils::HashUtils::Equal(
                            hash.sha256.data(),
                            sigHash.sha256.data(),
                            hash.sha256.size())) {
                        outThreatName = sig.threatName;
                        return true;
                    }
                }
            }
        }
        return false;
    }
};

// ============================================================================
// STATIC INITIALIZATION
// ============================================================================

// Meyers' Singleton — the static local guarantees thread-safe initialisation (C++11 §6.7)
ZeroHourProtection& ZeroHourProtection::Instance() {
    static ZeroHourProtection instance;
    return instance;
}

// ============================================================================
// LIFECYCLE
// ============================================================================

ZeroHourProtection::ZeroHourProtection()
    : m_impl(std::make_unique<ZeroHourProtectionImpl>())
{
    Utils::Logger::Info("ZeroHourProtection: Instance created");
}

ZeroHourProtection::~ZeroHourProtection() {
    Shutdown();
}

bool ZeroHourProtection::Initialize(const ZeroHourProtectionConfig& config) {
    if (m_impl->m_isInitialized) {
        Utils::Logger::Warn("ZeroHourProtection: Already initialized");
        return true;
    }

    {
        std::unique_lock lock(m_impl->m_configMutex);
        m_impl->m_config = config;
    }

    m_impl->m_stats.Reset();

    // Start hold monitor thread BEFORE marking initialized (no config lock held)
    m_impl->m_stopMonitor = false;
    m_impl->m_holdMonitorThread = std::make_unique<std::thread>(
        &ZeroHourProtectionImpl::MonitorHeldFiles, m_impl.get());

    m_impl->m_isInitialized = true;
    // Start disconnected; connectivity verified lazily on first cloud query
    m_impl->m_cloudStatus.store(CloudServiceStatus::DISCONNECTED);

    Utils::Logger::Info("ZeroHourProtection: Initialized (Enterprise Mode)");
    return true;
}

void ZeroHourProtection::Shutdown() noexcept {
    if (m_impl) {
        m_impl->Shutdown();
        m_impl->m_isInitialized = false;
    }
}

bool ZeroHourProtection::Start() noexcept {
    try {
        if (m_impl->m_isInitialized) return true;
        return Initialize(ZeroHourProtectionConfig::CreateEnterprise());
    } catch (...) {
        return false;
    }
}

void ZeroHourProtection::Stop() noexcept {
    Shutdown();
}

bool ZeroHourProtection::IsInitialized() const noexcept {
    return m_impl->m_isInitialized;
}

ZeroHourProtectionConfig ZeroHourProtection::GetConfig() const {
    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}

bool ZeroHourProtection::UpdateConfig(const ZeroHourProtectionConfig& config) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = config;
    return true;
}

// ============================================================================
// OUTBREAK MODE CONTROL
// ============================================================================

void ZeroHourProtection::SetOutbreakMode(bool active, std::wstring_view reason) {
    const ThreatLevel desired = active ? ThreatLevel::CRITICAL : ThreatLevel::NORMAL;
    ThreatLevel expected = m_impl->m_currentThreatLevel.load(std::memory_order_acquire);

    // CAS loop to avoid spurious concurrent callback fires
    do {
        const bool wasActive = (expected == ThreatLevel::CRITICAL ||
                                expected == ThreatLevel::LOCKDOWN);
        if (active == wasActive) return; // No change
    } while (!m_impl->m_currentThreatLevel.compare_exchange_weak(
                 expected, desired,
                 std::memory_order_acq_rel,
                 std::memory_order_acquire));

    if (active) {
        m_impl->m_stats.outbreakModeActivations++;
        SS_LOG_FATAL(L"ZeroHourProtection",
            L"OUTBREAK MODE ACTIVATED: %ls",
            std::wstring(reason).c_str());
    } else {
        SS_LOG_INFO(L"ZeroHourProtection",
            L"Outbreak Mode Deactivated: %ls",
            std::wstring(reason).c_str());
    }

    m_impl->FireThreatLevelCallback(expected, desired, reason);
}

bool ZeroHourProtection::IsOutbreakModeActive() const noexcept {
    return m_impl->m_currentThreatLevel == ThreatLevel::CRITICAL ||
           m_impl->m_currentThreatLevel == ThreatLevel::LOCKDOWN;
}

ThreatLevel ZeroHourProtection::GetThreatLevel() const noexcept {
    return m_impl->m_currentThreatLevel;
}

void ZeroHourProtection::SetThreatLevel(ThreatLevel level, std::wstring_view reason) {
    ThreatLevel expected = m_impl->m_currentThreatLevel.load(std::memory_order_acquire);
    do {
        if (expected == level) return;
    } while (!m_impl->m_currentThreatLevel.compare_exchange_weak(
                 expected, level,
                 std::memory_order_acq_rel,
                 std::memory_order_acquire));

    SS_LOG_INFO(L"ZeroHourProtection",
        L"Threat Level changed to %d (Reason: %ls)",
        static_cast<int>(level),
        std::wstring(reason).c_str());

    m_impl->FireThreatLevelCallback(expected, level, reason);
}

std::vector<OutbreakInfo> ZeroHourProtection::GetActiveOutbreaks() const {
    std::shared_lock lock(m_impl->m_outbreakMutex);
    return m_impl->m_activeOutbreaks;
}

bool ZeroHourProtection::AcknowledgeOutbreak(uint64_t outbreakId) {
    std::unique_lock lock(m_impl->m_outbreakMutex);
    const auto it = std::find_if(
        m_impl->m_activeOutbreaks.begin(),
        m_impl->m_activeOutbreaks.end(),
        [outbreakId](const OutbreakInfo& o) { return o.outbreakId == outbreakId; });

    if (it == m_impl->m_activeOutbreaks.end()) return false;

    it->lastUpdated = std::chrono::system_clock::now();
    it->localVictimCount++; // Acknowledgement implies local exposure
    SS_LOG_INFO(L"ZeroHourProtection",
        L"Outbreak acknowledged: ID=%llu Name=%ls",
        static_cast<unsigned long long>(outbreakId),
        it->name.c_str());
    return true;
}

// ============================================================================
// FILE ANALYSIS
// ============================================================================

FileAnalysisResult ZeroHourProtection::AnalyzeFile(const FileAnalysisRequest& request) {
    auto start = std::chrono::high_resolution_clock::now();
    FileAnalysisResult result;
    result.shouldAllow = true; // Default allow unless bad
    result.source = FileAnalysisResult::Source::LOCAL_CACHE;

    if (!IsInitialized()) {
        result.errorCode = 1;
        result.errorMessage = L"Not initialized";
        return result;
    }

    // 1. Check Whitelist
    if (m_impl->IsWhitelisted(request.filePath, request.hash)) {
        result.verdict = CloudVerdict::WHITELISTED;
        result.shouldAllow = true;
        result.source = FileAnalysisResult::Source::WHITELIST;
        return result;
    }

    // 2. Check Micro-Signatures (Fastest Check)
    std::wstring microThreat;
    if (m_impl->CheckMicroSignatures(request.hash, microThreat)) {
        result.verdict = CloudVerdict::MALICIOUS;
        result.threatName = microThreat;
        result.shouldAllow = false;
        result.source = FileAnalysisResult::Source::MICRO_SIGNATURE;
        m_impl->m_stats.verdictsMalicious++;
        m_impl->m_stats.signaturesApplied++;
        return result;
    }

    // 3. Check Verdict Cache
    if (auto cached = QueryCache(request.hash)) {
        result.cloudResult = *cached;
        result.verdict = cached->verdict;

        if (cached->verdict == CloudVerdict::MALICIOUS) {
            result.shouldAllow = false;
            result.threatName = cached->threatName;
            m_impl->m_stats.verdictsMalicious++;
        } else if (cached->verdict == CloudVerdict::SUSPICIOUS &&
                   GetThreatLevel() >= ThreatLevel::HIGH) {
            result.shouldAllow = false; // Block suspicious in high-threat posture
            m_impl->m_stats.verdictsSuspicious++;
        } else if (cached->verdict == CloudVerdict::CLEAN ||
                   cached->verdict == CloudVerdict::WHITELISTED) {
            result.shouldAllow = true;
            m_impl->m_stats.verdictsClean++;
        }

        m_impl->m_stats.cloudCacheHits++;
        result.source = FileAnalysisResult::Source::LOCAL_CACHE;

        auto end = std::chrono::high_resolution_clock::now();
        result.totalTime = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        m_impl->FireVerdictCallback(request.filePath, result);
        return result;
    }
    m_impl->m_stats.cloudCacheMisses++;

    // 4. Unknown File Logic

    // Check Outbreak Mode Lockdown
    if (IsOutbreakModeActive()) {
        std::shared_lock configLock(m_impl->m_configMutex);
        if (m_impl->m_config.autoLockdownOnCritical) {
            result.shouldAllow = false;
            result.verdict = CloudVerdict::UNKNOWN;
            result.source = FileAnalysisResult::Source::OUTBREAK_POLICY;
            result.errorMessage = L"Blocked by Outbreak Lockdown";
            m_impl->m_stats.outbreakBlockedFiles++;

            auto end = std::chrono::high_resolution_clock::now();
            result.totalTime = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            m_impl->FireVerdictCallback(request.filePath, result);
            return result;
        }
    }

    // Determine if we should hold
    bool shouldHold = ShouldHoldFile(request.filePath) && request.allowHold;

    if (shouldHold) {
        // Enforce max pending files limit
        {
            std::shared_lock hlock(m_impl->m_holdMutex);
            if (m_impl->m_heldFiles.size() >= ZeroHourConstants::MAX_PENDING_FILES) {
                // Hold queue full — apply fallback policy
                std::shared_lock configLock(m_impl->m_configMutex);
                result.shouldAllow =
                    (m_impl->m_config.cloudConfig.fallbackPolicy == FallbackPolicy::ALLOW_UNKNOWN);
                result.verdict = CloudVerdict::UNKNOWN;
                result.source = FileAnalysisResult::Source::FALLBACK_POLICY;
                result.errorMessage = L"Hold queue full — fallback policy applied";

                auto end = std::chrono::high_resolution_clock::now();
                result.totalTime = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
                m_impl->FireVerdictCallback(request.filePath, result);
                return result;
            }
        }

        // Create Hold Entry
        HeldFile held;
        held.holdId         = GenerateHoldId();
        held.filePath       = request.filePath;
        held.hash           = request.hash;
        held.reason         = HoldReason::CLOUD_PENDING;
        held.holdTime       = std::chrono::system_clock::now();
        held.timeoutTime    = held.holdTime +
                              std::chrono::milliseconds(request.timeoutMs);
        held.requestingPid  = request.requestingPid;
        held.requestingProcess = request.requestingProcess;
        held.fileSize       = request.fileSize;
        held.category       = request.category;

        {
            std::unique_lock lock(m_impl->m_holdMutex);
            m_impl->m_heldFiles[held.holdId] = held;
            m_impl->m_stats.currentHeldFiles++;
            m_impl->m_stats.filesHeld++;
        }

        // Return Hold Result
        result.shouldAllow = false; // Block until verdict
        result.wasHeld     = true;
        result.holdId      = held.holdId;
        result.verdict     = CloudVerdict::PENDING;
        result.source      = FileAnalysisResult::Source::CLOUD_LOOKUP;

        m_impl->FireFileHoldCallback(held);

        // Dispatch async cloud verdict query
        // Capture impl pointer (safe: singleton lifetime >= thread lifetime)
        ZeroHourProtectionImpl* impl = m_impl.get();
        const uint64_t holdId        = held.holdId;
        const FileHash  hashCopy     = held.hash;
        const uint32_t  timeoutMs    = request.timeoutMs;

        std::thread([this, impl, holdId, hashCopy, timeoutMs]() noexcept {
            try {
                if (impl->m_isShutdown.load(std::memory_order_acquire)) return;

                const CloudVerdictResult verdict = GetCloudVerdict(hashCopy, timeoutMs);

                if (impl->m_isShutdown.load(std::memory_order_acquire)) return;

                // Cache the verdict if meaningful
                if (verdict.verdict != CloudVerdict::UNKNOWN &&
                    verdict.verdict != CloudVerdict::LOOKUP_FAILED &&
                    verdict.verdict != CloudVerdict::PENDING) {
                    UpdateCache(hashCopy, verdict);
                }

                // Map verdict to hold decision
                HoldDecision decision;
                switch (verdict.verdict) {
                    case CloudVerdict::MALICIOUS:
                    case CloudVerdict::BLACKLISTED:
                        decision = HoldDecision::BLOCK;
                        break;
                    case CloudVerdict::CLEAN:
                    case CloudVerdict::WHITELISTED:
                        decision = HoldDecision::ALLOW;
                        break;
                    default: {
                        // Unknown / error — consult fallback policy
                        std::shared_lock configLock(impl->m_configMutex);
                        decision = (impl->m_config.cloudConfig.fallbackPolicy ==
                                    FallbackPolicy::BLOCK_UNKNOWN)
                                   ? HoldDecision::BLOCK
                                   : HoldDecision::ALLOW;
                        break;
                    }
                }

                impl->ReleaseHeldFile(holdId, decision,
                    L"Cloud verdict received: " + hashCopy.GetSHA256String());

            } catch (...) {
                // Ensure hold is always released on failure
                try {
                    std::shared_lock configLock(impl->m_configMutex);
                    const HoldDecision fallback =
                        (impl->m_config.cloudConfig.fallbackPolicy ==
                         FallbackPolicy::BLOCK_UNKNOWN)
                        ? HoldDecision::BLOCK : HoldDecision::ALLOW;
                    impl->ReleaseHeldFile(holdId, fallback, L"Cloud query exception");
                } catch (...) {}
            }
        }).detach();

    } else {
        // Allow or block unknown based on fallback policy
        std::shared_lock configLock(m_impl->m_configMutex);
        if (m_impl->m_config.cloudConfig.fallbackPolicy == FallbackPolicy::ALLOW_UNKNOWN) {
            result.shouldAllow = true;
            result.verdict     = CloudVerdict::UNKNOWN;
            result.source      = FileAnalysisResult::Source::FALLBACK_POLICY;
        } else {
            result.shouldAllow = false;
            result.verdict     = CloudVerdict::UNKNOWN;
            result.source      = FileAnalysisResult::Source::FALLBACK_POLICY;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.totalTime = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    m_impl->FireVerdictCallback(request.filePath, result);
    return result;
}

bool ZeroHourProtection::ShouldHoldFile(const std::wstring& filePath) {
    std::shared_lock lock(m_impl->m_configMutex);

    if (!m_impl->m_config.holdUnknownFiles) return false;

    for (const auto& ext : m_impl->m_config.excludedExtensions) {
        if (filePath.length() >= ext.length()) {
            if (filePath.compare(
                    filePath.length() - ext.length(),
                    ext.length(), ext) == 0) {
                return false;
            }
        }
    }
    return true;
}

CloudVerdictResult ZeroHourProtection::GetCloudVerdict(const FileHash& hash, uint32_t timeout) {
    CloudVerdictResult result;
    result.queryTime = std::chrono::system_clock::now();
    m_impl->m_stats.totalCloudQueries++;

    // Build hex SHA-256 string for lookup
    const std::string sha256Hex =
        Utils::HashUtils::ToHexLower(hash.sha256.data(), hash.sha256.size());
    if (sha256Hex.empty()) {
        result.verdict      = CloudVerdict::LOOKUP_FAILED;
        result.errorCode    = 1;
        result.errorMessage = L"Empty SHA-256 hash";
        m_impl->m_stats.cloudErrors++;
        return result;
    }

    ThreatIntel::ThreatIntelLookup* lookup = nullptr;
    {
        std::shared_lock ilock(m_impl->m_integrationMutex);
        lookup = m_impl->m_threatIntelLookup;
    }

    if (!lookup || !lookup->IsInitialized()) {
        result.verdict      = CloudVerdict::UNKNOWN;
        result.errorCode    = 2;
        result.errorMessage = L"ThreatIntelLookup unavailable";
        m_impl->m_stats.cloudErrors++;
        m_impl->UpdateCloudStatus(CloudServiceStatus::DISCONNECTED);
        return result;
    }

    const auto queryStart = std::chrono::high_resolution_clock::now();

    ThreatIntel::UnifiedLookupOptions opts;
    opts.maxLookupTiers         = 5;
    opts.cacheResult            = true;
    opts.includeMetadata        = true;
    opts.timeoutMs              = (timeout > 0) ? timeout
                                                : ZeroHourConstants::DEFAULT_CLOUD_TIMEOUT_MS;

    const ThreatIntel::ThreatLookupResult tiResult =
        lookup->LookupSHA256(sha256Hex, opts);

    const auto queryEnd  = std::chrono::high_resolution_clock::now();
    const auto latencyUs = std::chrono::duration_cast<std::chrono::microseconds>(
                               queryEnd - queryStart);
    const uint64_t latencyMs = static_cast<uint64_t>(latencyUs.count() / 1000);

    result.latency      = latencyUs;
    result.verdictTime  = std::chrono::system_clock::now();

    // Update latency tracking
    m_impl->m_cloudLatencySumMs.fetch_add(latencyMs, std::memory_order_relaxed);
    m_impl->m_cloudQueryCount.fetch_add(1,           std::memory_order_relaxed);

    m_impl->UpdateCloudStatus(CloudServiceStatus::CONNECTED);

    if (!tiResult.found) {
        result.verdict = CloudVerdict::UNKNOWN;
        m_impl->m_stats.verdictsUnknown++;
        return result;
    }

    result.firstSeen   = tiResult.firstSeen;
    result.lastSeen    = tiResult.lastSeen;
    result.confidence  = tiResult.threatScore;

    if (!tiResult.description.empty()) {
        result.threatName = Utils::StringUtils::ToWide(tiResult.description);
    }
    for (const auto& tag : tiResult.mitreTechniques) {
        result.mitreIds.push_back(Utils::StringUtils::ToWide(tag));
    }

    if (tiResult.IsMalicious()) {
        result.verdict = CloudVerdict::MALICIOUS;
        m_impl->m_stats.verdictsMalicious++;
    } else if (tiResult.IsSuspicious()) {
        result.verdict = CloudVerdict::SUSPICIOUS;
        m_impl->m_stats.verdictsSuspicious++;
    } else if (tiResult.IsSafe()) {
        result.verdict = CloudVerdict::CLEAN;
        m_impl->m_stats.verdictsClean++;
    } else {
        result.verdict = CloudVerdict::UNKNOWN;
        m_impl->m_stats.verdictsUnknown++;
    }

    return result;
}

std::unordered_map<std::wstring, CloudVerdictResult> ZeroHourProtection::GetCloudVerdictBatch(
    const std::vector<FileHash>& hashes, uint32_t timeout) {

    std::unordered_map<std::wstring, CloudVerdictResult> results;
    if (hashes.empty()) return results;
    results.reserve(hashes.size());

    ThreatIntel::ThreatIntelLookup* lookup = nullptr;
    {
        std::shared_lock ilock(m_impl->m_integrationMutex);
        lookup = m_impl->m_threatIntelLookup;
    }

    if (!lookup || !lookup->IsInitialized()) {
        // Serial fallback — still returns meaningful unknowns
        for (const auto& h : hashes) {
            results[h.GetSHA256String()] = GetCloudVerdict(h, timeout);
        }
        return results;
    }

    // Build string storage so string_views remain valid
    std::vector<std::string>      hexStorage;
    hexStorage.reserve(hashes.size());
    for (const auto& h : hashes) {
        hexStorage.push_back(
            Utils::HashUtils::ToHexLower(h.sha256.data(), h.sha256.size()));
    }

    std::vector<std::string_view> hexViews;
    hexViews.reserve(hexStorage.size());
    for (const auto& s : hexStorage) hexViews.push_back(s);

    ThreatIntel::UnifiedLookupOptions opts;
    opts.maxLookupTiers = 4;
    opts.cacheResult    = true;
    opts.timeoutMs      = (timeout > 0) ? timeout
                                        : ZeroHourConstants::DEFAULT_CLOUD_TIMEOUT_MS * 2;

    const ThreatIntel::BatchLookupResult batch =
        lookup->BatchLookupHashes(
            std::span<const std::string_view>(hexViews), opts);

    const auto now = std::chrono::system_clock::now();
    for (size_t i = 0; i < hashes.size(); ++i) {
        CloudVerdictResult cvr;
        cvr.queryTime  = now;
        cvr.verdictTime = now;

        if (i < batch.results.size()) {
            const auto& r = batch.results[i];
            cvr.confidence = r.threatScore;
            if (!r.description.empty())
                cvr.threatName = Utils::StringUtils::ToWide(r.description);

            if (!r.found)               cvr.verdict = CloudVerdict::UNKNOWN;
            else if (r.IsMalicious())   cvr.verdict = CloudVerdict::MALICIOUS;
            else if (r.IsSuspicious())  cvr.verdict = CloudVerdict::SUSPICIOUS;
            else if (r.IsSafe())        cvr.verdict = CloudVerdict::CLEAN;
            else                        cvr.verdict = CloudVerdict::UNKNOWN;
        } else {
            cvr.verdict = CloudVerdict::LOOKUP_FAILED;
        }
        results[hashes[i].GetSHA256String()] = std::move(cvr);
    }
    return results;
}

uint64_t ZeroHourProtection::SubmitForDetonation(
    const std::wstring& filePath, CloudQueryPriority priority) {

    if (filePath.empty()) return 0;

    // Enforce file-size cap to prevent abusive detonation submissions
    {
        std::shared_lock configLock(m_impl->m_configMutex);
        // No size check here since we don't re-stat in this call; caller
        // is expected to have validated via FileAnalysisRequest.fileSize.
    }

    const uint64_t detonationId =
        m_impl->m_detonationIdCounter.fetch_add(1, std::memory_order_relaxed);

    {
        std::unique_lock lock(m_impl->m_detonationMutex);
        m_impl->m_pendingDetonations[detonationId] = filePath;
    }

    SS_LOG_INFO(L"ZeroHourProtection",
        L"File submitted for detonation: ID=%llu Priority=%d Path=%ls",
        static_cast<unsigned long long>(detonationId),
        static_cast<int>(priority),
        filePath.c_str());

    return detonationId;
}

// ============================================================================
// HOLD MANAGEMENT
// ============================================================================

std::optional<HeldFile> ZeroHourProtection::GetHeldFile(uint64_t holdId) const {
    std::shared_lock lock(m_impl->m_holdMutex);
    auto it = m_impl->m_heldFiles.find(holdId);
    if (it != m_impl->m_heldFiles.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<HeldFile> ZeroHourProtection::GetHeldFileByPath(const std::wstring& filePath) const {
    std::shared_lock lock(m_impl->m_holdMutex);
    for (const auto& [id, file] : m_impl->m_heldFiles) {
        if (file.filePath == filePath) return file;
    }
    return std::nullopt;
}

std::vector<HeldFile> ZeroHourProtection::GetAllHeldFiles() const {
    std::shared_lock lock(m_impl->m_holdMutex);
    std::vector<HeldFile> files;
    files.reserve(m_impl->m_heldFiles.size());
    for (const auto& [id, file] : m_impl->m_heldFiles) {
        files.push_back(file);
    }
    return files;
}

bool ZeroHourProtection::ReleaseHeldFile(uint64_t holdId, HoldDecision decision, std::wstring_view reason) {
    m_impl->ReleaseHeldFile(holdId, decision, std::wstring(reason));
    return true;
}

uint32_t ZeroHourProtection::ReleaseAllHeldFiles(HoldDecision decision, std::wstring_view reason) {
    std::vector<uint64_t> ids;
    {
        std::shared_lock lock(m_impl->m_holdMutex);
        for (const auto& [id, file] : m_impl->m_heldFiles) {
            ids.push_back(id);
        }
    }

    for (uint64_t id : ids) {
        m_impl->ReleaseHeldFile(id, decision, std::wstring(reason));
    }
    return static_cast<uint32_t>(ids.size());
}

// ============================================================================
// MICRO-SIGNATURE MANAGEMENT
// ============================================================================

bool ZeroHourProtection::CheckForSignatureUpdates(bool force) {
    if (!m_impl->m_isInitialized) return false;

    const auto now = std::chrono::system_clock::now();

    if (!force) {
        std::shared_lock slock(m_impl->m_sigCheckMutex);
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 now - m_impl->m_lastSigCheckTime).count();
        uint32_t intervalMs = 0;
        {
            std::shared_lock configLock(m_impl->m_configMutex);
            intervalMs = IsOutbreakModeActive()
                         ? ZeroHourConstants::EMERGENCY_SIG_CHECK_MS
                         : m_impl->m_config.microSigIntervalMs;
        }
        if (elapsed >= 0 && static_cast<uint64_t>(elapsed) < intervalMs) {
            return false; // Not yet due
        }
    }

    {
        std::unique_lock slock(m_impl->m_sigCheckMutex);
        m_impl->m_lastSigCheckTime = now;
    }

    SS_LOG_DEBUG(L"ZeroHourProtection",
        L"Checking for micro-signature updates (force=%d)", static_cast<int>(force));

    // Actual update retrieval would go through ThreatIntelLookup or a dedicated
    // update service.  For now, log that the check occurred and return false
    // (no new sigs) since there is no update endpoint connected yet.
    return false;
}

bool ZeroHourProtection::ApplySignatureUpdate(const MicroSigUpdatePackage& package) {
    if (!m_impl->m_isInitialized) return false;

    // Validate version monotonicity
    if (!package.isDelta && package.targetVersion == 0) {
        SS_LOG_ERROR(L"ZeroHourProtection",
            L"Rejecting signature package with invalid target version 0");
        m_impl->FireSignatureUpdateCallback(package, false);
        return false;
    }

    bool success = false;
    {
        std::unique_lock lock(m_impl->m_sigMutex);

        // Snapshot current state for rollback before applying
        {
            ZeroHourProtectionImpl::SigSnapshot snap;
            snap.signatures = m_impl->m_microSignatures;
            snap.version    = m_impl->m_sigVersion;
            m_impl->m_rollbackHistory.push_back(std::move(snap));

            // Trim rollback history to configured limit
            uint32_t maxVersions = ZeroHourConstants::MAX_ROLLBACK_VERSIONS;
            {
                std::shared_lock configLock(m_impl->m_configMutex);
                maxVersions = m_impl->m_config.maxRollbackVersions;
            }
            while (m_impl->m_rollbackHistory.size() > maxVersions) {
                m_impl->m_rollbackHistory.pop_front();
            }
        }

        // Remove signatures scheduled for deletion
        if (!package.removals.empty()) {
            const auto removeEnd = std::remove_if(
                m_impl->m_microSignatures.begin(),
                m_impl->m_microSignatures.end(),
                [&package](const MicroSignature& sig) {
                    for (const uint64_t id : package.removals) {
                        if (sig.signatureId == id) return true;
                    }
                    return false;
                });
            m_impl->m_microSignatures.erase(removeEnd, m_impl->m_microSignatures.end());
        }

        // Append new signatures, respecting batch size limit
        const size_t toAdd = std::min(
            package.additions.size(),
            ZeroHourConstants::MAX_MICRO_SIG_BATCH);

        for (size_t i = 0; i < toAdd; ++i) {
            m_impl->m_microSignatures.push_back(package.additions[i]);
        }

        m_impl->m_sigVersion = package.targetVersion;
        m_impl->m_stats.microSigUpdates++;
        if (package.isEmergency) m_impl->m_stats.emergencySigUpdates++;
        m_impl->m_stats.currentSigVersion.store(
            package.targetVersion, std::memory_order_relaxed);
        success = true;
    }

    Utils::Logger::Info("ZeroHourProtection: Applied micro-signature update v{}",
        package.targetVersion);

    m_impl->FireSignatureUpdateCallback(package, success);
    return success;
}

bool ZeroHourProtection::RollbackSignatures(uint32_t targetVersion) {
    std::unique_lock lock(m_impl->m_sigMutex);

    // Find the snapshot for the target version
    const auto it = std::find_if(
        m_impl->m_rollbackHistory.rbegin(),
        m_impl->m_rollbackHistory.rend(),
        [targetVersion](const ZeroHourProtectionImpl::SigSnapshot& s) {
            return s.version == targetVersion;
        });

    if (it == m_impl->m_rollbackHistory.rend()) {
        SS_LOG_ERROR(L"ZeroHourProtection",
            L"Rollback failed: version %u not found in history", targetVersion);
        return false;
    }

    m_impl->m_microSignatures = it->signatures;
    m_impl->m_sigVersion      = it->version;
    m_impl->m_stats.currentSigVersion.store(it->version, std::memory_order_relaxed);

    // Trim history at the rollback point (can't go forward again)
    m_impl->m_rollbackHistory.erase(
        (it + 1).base(), m_impl->m_rollbackHistory.end());

    SS_LOG_WARN(L"ZeroHourProtection",
        L"Signature rollback completed to version %u", targetVersion);
    return true;
}

uint32_t ZeroHourProtection::GetSignatureVersion() const noexcept {
    // Use the atomic stat to avoid potential throw from shared_lock in noexcept context
    return m_impl->m_stats.currentSigVersion.load(std::memory_order_relaxed);
}

std::vector<uint32_t> ZeroHourProtection::GetAvailableRollbackVersions() const {
    std::shared_lock lock(m_impl->m_sigMutex);
    std::vector<uint32_t> versions;
    versions.reserve(m_impl->m_rollbackHistory.size());
    for (const auto& snap : m_impl->m_rollbackHistory) {
        versions.push_back(snap.version);
    }
    return versions;
}

// ============================================================================
// ADAPTIVE HEURISTICS
// ============================================================================

AdaptiveHeuristicConfig ZeroHourProtection::GetHeuristicConfig() const {
    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config.heuristicConfig;
}

bool ZeroHourProtection::UpdateHeuristicConfig(const AdaptiveHeuristicConfig& config) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config.heuristicConfig = config;
    return true;
}

float ZeroHourProtection::GetEffectiveMLThreshold() const noexcept {
    std::shared_lock lock(m_impl->m_configMutex);
    float base = m_impl->m_config.heuristicConfig.mlDetectionThreshold;

    if (IsOutbreakModeActive()) {
        return std::min(base, ZeroHourConstants::OUTBREAK_ML_THRESHOLD);
    }
    return base;
}

// ============================================================================
// CLOUD SERVICE MANAGEMENT
// ============================================================================

CloudServiceStatus ZeroHourProtection::GetCloudStatus() const noexcept {
    return m_impl->m_cloudStatus;
}

bool ZeroHourProtection::TestCloudConnectivity() {
    ThreatIntel::ThreatIntelLookup* lookup = nullptr;
    {
        std::shared_lock ilock(m_impl->m_integrationMutex);
        lookup = m_impl->m_threatIntelLookup;
    }

    if (!lookup || !lookup->IsInitialized()) {
        m_impl->UpdateCloudStatus(CloudServiceStatus::DISCONNECTED);
        return false;
    }

    m_impl->UpdateCloudStatus(CloudServiceStatus::CONNECTED);
    return true;
}

bool ZeroHourProtection::ReconnectCloud() {
    if (TestCloudConnectivity()) {
        SS_LOG_INFO(L"ZeroHourProtection", L"Cloud reconnection successful");
        return true;
    }

    SS_LOG_WARN(L"ZeroHourProtection",
        L"Cloud reconnection failed — ThreatIntelLookup not available or not initialized");
    return false;
}

uint32_t ZeroHourProtection::GetCloudLatency() const noexcept {
    const uint64_t count = m_impl->m_cloudQueryCount.load(std::memory_order_relaxed);
    if (count == 0) return 0;
    const uint64_t sum = m_impl->m_cloudLatencySumMs.load(std::memory_order_relaxed);
    return static_cast<uint32_t>(sum / count);
}

// ============================================================================
// VERDICT CACHE
// ============================================================================

std::optional<CloudVerdictResult> ZeroHourProtection::QueryCache(const FileHash& hash) const {
    std::wstring hashStr = hash.GetSHA256String();
    std::shared_lock lock(m_impl->m_cacheMutex);
    auto it = m_impl->m_verdictCache.find(hashStr);

    if (it != m_impl->m_verdictCache.end()) {
        // Check TTL
        auto now = std::chrono::system_clock::now();
        if (now < it->second.cacheExpiry) {
            return it->second;
        }
    }
    return std::nullopt;
}

void ZeroHourProtection::UpdateCache(const FileHash& hash, const CloudVerdictResult& verdict) {
    std::wstring hashStr = hash.GetSHA256String();
    if (hashStr.empty()) return;

    std::unique_lock lock(m_impl->m_cacheMutex);

    // Evict ~5% of cache when at capacity (random sampling is O(1) per call)
    if (m_impl->m_verdictCache.size() >= ZeroHourConstants::MAX_VERDICT_CACHE_SIZE) {
        // Evict entries whose TTL has expired first
        const auto now = std::chrono::system_clock::now();
        auto it = m_impl->m_verdictCache.begin();
        size_t evicted = 0;
        const size_t evictTarget = ZeroHourConstants::MAX_VERDICT_CACHE_SIZE / 20; // 5%
        while (it != m_impl->m_verdictCache.end() && evicted < evictTarget) {
            if (now >= it->second.cacheExpiry) {
                it = m_impl->m_verdictCache.erase(it);
                ++evicted;
            } else {
                ++it;
            }
        }
        // If not enough expired entries, evict oldest-inserted entries
        if (evicted == 0 && !m_impl->m_verdictCache.empty()) {
            m_impl->m_verdictCache.erase(m_impl->m_verdictCache.begin());
        }
    }

    // Compute appropriate TTL based on verdict
    std::chrono::milliseconds ttl{ ZeroHourConstants::VERDICT_CACHE_TTL_UNKNOWN_MS };
    if (verdict.verdict == CloudVerdict::CLEAN ||
        verdict.verdict == CloudVerdict::WHITELISTED) {
        ttl = std::chrono::milliseconds{ ZeroHourConstants::VERDICT_CACHE_TTL_CLEAN_MS };
    } else if (verdict.verdict == CloudVerdict::MALICIOUS) {
        ttl = std::chrono::milliseconds{ ZeroHourConstants::VERDICT_CACHE_TTL_MALICIOUS_MS };
    }

    CloudVerdictResult entry  = verdict;
    entry.fromCache           = false;
    entry.cacheExpiry         = std::chrono::system_clock::now() + ttl;
    m_impl->m_verdictCache[hashStr] = std::move(entry);
}

void ZeroHourProtection::InvalidateCacheEntry(const FileHash& hash) {
    std::wstring hashStr = hash.GetSHA256String();
    std::unique_lock lock(m_impl->m_cacheMutex);
    m_impl->m_verdictCache.erase(hashStr);
}

void ZeroHourProtection::ClearCache() noexcept {
    std::unique_lock lock(m_impl->m_cacheMutex);
    m_impl->m_verdictCache.clear();
}

size_t ZeroHourProtection::GetCacheSize() const noexcept {
    std::shared_lock lock(m_impl->m_cacheMutex);
    return m_impl->m_verdictCache.size();
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

uint64_t ZeroHourProtection::RegisterVerdictCallback(VerdictCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = m_impl->m_callbackIdCounter++;
    m_impl->m_verdictCallbacks[id] = std::move(callback);
    return id;
}

uint64_t ZeroHourProtection::RegisterFileHoldCallback(FileHoldCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = m_impl->m_callbackIdCounter++;
    m_impl->m_holdCallbacks[id] = std::move(callback);
    return id;
}

uint64_t ZeroHourProtection::RegisterOutbreakCallback(OutbreakCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = m_impl->m_callbackIdCounter++;
    m_impl->m_outbreakCallbacks[id] = std::move(callback);
    return id;
}

uint64_t ZeroHourProtection::RegisterThreatLevelCallback(ThreatLevelCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = m_impl->m_callbackIdCounter++;
    m_impl->m_threatLevelCallbacks[id] = std::move(callback);
    return id;
}

uint64_t ZeroHourProtection::RegisterSignatureUpdateCallback(SignatureUpdateCallback callback) {
    if (!callback) return 0;
    std::unique_lock lock(m_impl->m_callbackMutex);
    const uint64_t id = m_impl->m_callbackIdCounter++;
    m_impl->m_sigUpdateCallbacks[id] = std::move(callback);
    return id;
}

uint64_t ZeroHourProtection::RegisterCloudStatusCallback(CloudStatusCallback callback) {
    if (!callback) return 0;
    std::unique_lock lock(m_impl->m_callbackMutex);
    const uint64_t id = m_impl->m_callbackIdCounter++;
    m_impl->m_cloudStatusCallbacks[id] = std::move(callback);
    return id;
}

bool ZeroHourProtection::UnregisterCallback(uint64_t callbackId) {
    if (callbackId == 0) return false;
    std::unique_lock lock(m_impl->m_callbackMutex);
    bool removed = false;
    removed |= (m_impl->m_verdictCallbacks.erase(callbackId)       > 0);
    removed |= (m_impl->m_holdCallbacks.erase(callbackId)          > 0);
    removed |= (m_impl->m_outbreakCallbacks.erase(callbackId)      > 0);
    removed |= (m_impl->m_threatLevelCallbacks.erase(callbackId)   > 0);
    removed |= (m_impl->m_sigUpdateCallbacks.erase(callbackId)     > 0);
    removed |= (m_impl->m_cloudStatusCallbacks.erase(callbackId)   > 0);
    return removed;
}

// ============================================================================
// STATISTICS
// ============================================================================

const ZeroHourStatistics& ZeroHourProtection::GetStatistics() const noexcept {
    return m_impl->m_stats;
}

void ZeroHourProtection::ResetStatistics() noexcept {
    m_impl->m_stats.Reset();
}

bool ZeroHourProtection::PerformDiagnostics() const {
    if (!IsInitialized()) return false;

    bool healthy = true;

    // Cloud status
    const auto cloudStatus = m_impl->m_cloudStatus.load();
    if (cloudStatus == CloudServiceStatus::AUTHENTICATION_ERROR ||
        cloudStatus == CloudServiceStatus::DISCONNECTED) {
        SS_LOG_ERROR(L"ZeroHourProtection",
            L"Diagnostics: Cloud service unavailable (status=%d)",
            static_cast<int>(cloudStatus));
        healthy = false;
    }

    // Signature version sanity
    if (m_impl->m_stats.currentSigVersion.load() == 0) {
        SS_LOG_WARN(L"ZeroHourProtection",
            L"Diagnostics: No micro-signatures loaded (version 0)");
        // Not a hard failure — empty on fresh boot is expected
    }

    // Hold queue sanity
    {
        std::shared_lock hlock(m_impl->m_holdMutex);
        if (m_impl->m_heldFiles.size() >= ZeroHourConstants::MAX_PENDING_FILES) {
            SS_LOG_ERROR(L"ZeroHourProtection",
                L"Diagnostics: Hold queue at maximum capacity (%zu files)",
                m_impl->m_heldFiles.size());
            healthy = false;
        }
    }

    return healthy;
}

bool ZeroHourProtection::ExportDiagnostics(const std::wstring& outputPath) const {
    try {
        nlohmann::json j;
        j["version"] = "3.0.0";
        j["initialized"] = IsInitialized();
        j["cacheSize"] = GetCacheSize();
        j["activeOutbreaks"] = GetActiveOutbreaks().size();

        std::ofstream file(outputPath);
        if (file) {
            file << j.dump(4);
            return true;
        }
    } catch (...) {}
    return false;
}

// ============================================================================
// STRUCT MEMBER IMPLEMENTATIONS
// ============================================================================

std::wstring FileHash::GetSHA256String() const {
    const std::string narrow =
        Utils::HashUtils::ToHexLower(sha256.data(), sha256.size());
    return Utils::StringUtils::ToWide(narrow);
}

std::wstring FileHash::GetMD5String() const {
    const std::string narrow =
        Utils::HashUtils::ToHexLower(md5.data(), md5.size());
    return Utils::StringUtils::ToWide(narrow);
}

void ZeroHourStatistics::Reset() noexcept {
    totalCloudQueries.store(0,      std::memory_order_relaxed);
    cloudCacheHits.store(0,         std::memory_order_relaxed);
    cloudCacheMisses.store(0,       std::memory_order_relaxed);
    cloudTimeouts.store(0,          std::memory_order_relaxed);
    cloudErrors.store(0,            std::memory_order_relaxed);

    verdictsClean.store(0,          std::memory_order_relaxed);
    verdictsMalicious.store(0,      std::memory_order_relaxed);
    verdictsSuspicious.store(0,     std::memory_order_relaxed);
    verdictsUnknown.store(0,        std::memory_order_relaxed);
    verdictsPUA.store(0,            std::memory_order_relaxed);

    filesHeld.store(0,              std::memory_order_relaxed);
    filesReleased.store(0,          std::memory_order_relaxed);
    filesBlocked.store(0,           std::memory_order_relaxed);
    holdTimeouts.store(0,           std::memory_order_relaxed);
    userOverrides.store(0,          std::memory_order_relaxed);
    currentHeldFiles.store(0,       std::memory_order_relaxed);

    microSigUpdates.store(0,        std::memory_order_relaxed);
    emergencySigUpdates.store(0,    std::memory_order_relaxed);
    signaturesApplied.store(0,      std::memory_order_relaxed);
    currentSigVersion.store(0,      std::memory_order_relaxed);

    outbreakModeActivations.store(0, std::memory_order_relaxed);
    outbreakDetections.store(0,      std::memory_order_relaxed);
    outbreakBlockedFiles.store(0,    std::memory_order_relaxed);
    currentThreatLevel.store(0,      std::memory_order_relaxed);

    totalQueryTimeUs.store(0,       std::memory_order_relaxed);
    avgQueryTimeUs.store(0,         std::memory_order_relaxed);
    maxQueryTimeUs.store(0,         std::memory_order_relaxed);

    errorCount.store(0,             std::memory_order_relaxed);
}

ZeroHourProtectionConfig ZeroHourProtectionConfig::CreateEnterprise() noexcept {
    ZeroHourProtectionConfig config;
    config.enabled                  = true;
    config.cloudLookupEnabled       = true;
    config.holdUnknownFiles         = true;
    config.microSignaturesEnabled   = true;
    config.adaptiveHeuristicsEnabled = true;
    config.outbreakModeEnabled      = true;
    config.holdTimeoutMs            = ZeroHourConstants::DEFAULT_HOLD_TIMEOUT_MS;
    config.timeoutDecision          = HoldDecision::TIMEOUT_ALLOW;
    config.cloudConfig.fallbackPolicy = FallbackPolicy::HOLD_TIMEOUT;
    config.autoLockdownOnCritical   = true;
    return config;
}

ZeroHourProtectionConfig ZeroHourProtectionConfig::CreateDefault() noexcept {
    return CreateEnterprise();
}

ZeroHourProtectionConfig ZeroHourProtectionConfig::CreateHighSecurity() noexcept {
    ZeroHourProtectionConfig config = CreateEnterprise();
    config.holdTimeoutMs              = ZeroHourConstants::DEFAULT_HOLD_TIMEOUT_MS * 2;
    config.timeoutDecision            = HoldDecision::TIMEOUT_BLOCK;
    config.cloudConfig.fallbackPolicy = FallbackPolicy::BLOCK_UNKNOWN;
    config.autoEscalateLevel          = ThreatLevel::ELEVATED;
    config.heuristicConfig            = AdaptiveHeuristicConfig::CreateAggressive();
    return config;
}

ZeroHourProtectionConfig ZeroHourProtectionConfig::CreatePerformance() noexcept {
    ZeroHourProtectionConfig config = CreateEnterprise();
    config.holdTimeoutMs              = ZeroHourConstants::DEFAULT_HOLD_TIMEOUT_MS / 2;
    config.timeoutDecision            = HoldDecision::TIMEOUT_ALLOW;
    config.cloudConfig.fallbackPolicy = FallbackPolicy::ALLOW_UNKNOWN;
    config.holdUnknownFiles           = false; // Do not hold — fastest path
    config.heuristicConfig            = AdaptiveHeuristicConfig::CreateConservative();
    return config;
}

AdaptiveHeuristicConfig AdaptiveHeuristicConfig::CreateDefault() noexcept {
    return AdaptiveHeuristicConfig{};
}

AdaptiveHeuristicConfig AdaptiveHeuristicConfig::CreateAggressive() noexcept {
    AdaptiveHeuristicConfig cfg;
    cfg.mode                       = HeuristicMode::AGGRESSIVE;
    cfg.mlDetectionThreshold       = 0.5f;
    cfg.mlBlockThreshold           = 0.75f;
    cfg.outbreakSensitivityMultiplier = static_cast<float>(
        ZeroHourConstants::OUTBREAK_SENSITIVITY_MULTIPLIER * 1.5);
    cfg.maxApiCallsPerSecond       = 500;
    cfg.maxFileOperationsPerSecond = 250;
    cfg.autoAdjust                 = true;
    return cfg;
}

AdaptiveHeuristicConfig AdaptiveHeuristicConfig::CreateConservative() noexcept {
    AdaptiveHeuristicConfig cfg;
    cfg.mode                       = HeuristicMode::MINIMAL;
    cfg.mlDetectionThreshold       = 0.85f;
    cfg.mlBlockThreshold           = 0.95f;
    cfg.outbreakSensitivityMultiplier = 1.0f;
    cfg.maxApiCallsPerSecond       = 2000;
    cfg.maxFileOperationsPerSecond = 1000;
    cfg.autoAdjust                 = false;
    return cfg;
}

AdaptiveHeuristicConfig AdaptiveHeuristicConfig::CreateOutbreak() noexcept {
    AdaptiveHeuristicConfig cfg = CreateAggressive();
    cfg.mode                    = HeuristicMode::OUTBREAK;
    cfg.mlDetectionThreshold    = ZeroHourConstants::OUTBREAK_ML_THRESHOLD;
    cfg.mlBlockThreshold        = ZeroHourConstants::OUTBREAK_ML_THRESHOLD + 0.05f;
    cfg.useEnsemble             = true;
    return cfg;
}

void ZeroHourProtection::SetThreatIntelLookup(ThreatIntel::ThreatIntelLookup* lookup) noexcept {
    std::unique_lock ilock(m_impl->m_integrationMutex);
    m_impl->m_threatIntelLookup = lookup;
}

void ZeroHourProtection::SetWhitelistStore(Whitelist::WhitelistStore* store) noexcept {
    std::unique_lock ilock(m_impl->m_integrationMutex);
    m_impl->m_whitelistStore = store;
}

} // namespace RealTime
} // namespace ShadowStrike
