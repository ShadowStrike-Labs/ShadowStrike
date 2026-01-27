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

    // Helper to convert time_point to string
    std::string TimeToString(const std::chrono::system_clock::time_point& tp) {
        auto t = std::chrono::system_clock::to_time_t(tp);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
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
    mutable std::shared_mutex m_callbackMutex;
    std::atomic<uint64_t> m_callbackIdCounter{ 1 };

    // Worker Threads
    std::unique_ptr<std::thread> m_holdMonitorThread;
    std::atomic<bool> m_stopMonitor{ false };

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
            Utils::Logger::Info(L"Released held file {} with decision {} (Reason: {})",
                heldFile.filePath, static_cast<int>(decision), reason);
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

    // Analysis Helpers
    bool IsWhitelisted(const std::wstring& path, const FileHash& hash) {
        // In a real implementation, this would check WhiteListStore
        // For now, check exclusions in config
        std::shared_lock lock(m_configMutex);
        for (const auto& excluded : m_config.excludedPaths) {
            if (path.find(excluded) == 0) return true;
        }
        return false;
    }

    bool CheckMicroSignatures(const FileHash& hash, std::wstring& outThreatName) {
        std::shared_lock lock(m_sigMutex);
        std::wstring hashStr = hash.GetSHA256String();

        for (const auto& sig : m_microSignatures) {
            if (sig.type == MicroSigType::HASH_ONLY) {
                if (std::holds_alternative<FileHash>(sig.content)) {
                     // Simplified comparison for this implementation
                     // In production, full byte comparison
                     if (std::get<FileHash>(sig.content).GetSHA256String() == hashStr) {
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

// Meyers' Singleton instance management
static std::atomic<bool> s_instanceCreated{ false };

ZeroHourProtection& ZeroHourProtection::Instance() {
    static ZeroHourProtection instance;
    s_instanceCreated.store(true, std::memory_order_release);
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
    std::unique_lock lock(m_impl->m_configMutex);

    if (m_impl->m_isInitialized) {
        Utils::Logger::Warn("ZeroHourProtection: Already initialized");
        return true;
    }

    m_impl->m_config = config;
    m_impl->m_stats.Reset();

    // Start monitor thread
    m_impl->m_stopMonitor = false;
    m_impl->m_holdMonitorThread = std::make_unique<std::thread>(&ZeroHourProtectionImpl::MonitorHeldFiles, m_impl.get());

    m_impl->m_isInitialized = true;
    m_impl->m_cloudStatus = CloudServiceStatus::CONNECTED; // Assume connected initially

    Utils::Logger::Info("ZeroHourProtection: Initialized (Enterprise Mode)");
    return true;
}

void ZeroHourProtection::Shutdown() noexcept {
    if (m_impl) {
        m_impl->Shutdown();
        m_impl->m_isInitialized = false;
    }
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
    bool wasActive = m_impl->m_currentThreatLevel == ThreatLevel::CRITICAL;

    if (active != wasActive) {
        ThreatLevel oldLevel = m_impl->m_currentThreatLevel;
        ThreatLevel newLevel = active ? ThreatLevel::CRITICAL : ThreatLevel::NORMAL;

        m_impl->m_currentThreatLevel = newLevel;

        if (active) {
            m_impl->m_stats.outbreakModeActivations++;
            Utils::Logger::Critical(L"OUTBREAK MODE ACTIVATED: {}", reason);
        } else {
            Utils::Logger::Info(L"Outbreak Mode Deactivated: {}", reason);
        }

        m_impl->FireThreatLevelCallback(oldLevel, newLevel, reason);
    }
}

bool ZeroHourProtection::IsOutbreakModeActive() const noexcept {
    return m_impl->m_currentThreatLevel == ThreatLevel::CRITICAL ||
           m_impl->m_currentThreatLevel == ThreatLevel::LOCKDOWN;
}

ThreatLevel ZeroHourProtection::GetThreatLevel() const noexcept {
    return m_impl->m_currentThreatLevel;
}

void ZeroHourProtection::SetThreatLevel(ThreatLevel level, std::wstring_view reason) {
    ThreatLevel oldLevel = m_impl->m_currentThreatLevel;
    if (oldLevel != level) {
        m_impl->m_currentThreatLevel = level;
        m_impl->FireThreatLevelCallback(oldLevel, level, reason);
        Utils::Logger::Info(L"Threat Level changed to {} (Reason: {})", static_cast<int>(level), reason);
    }
}

std::vector<OutbreakInfo> ZeroHourProtection::GetActiveOutbreaks() const {
    std::shared_lock lock(m_impl->m_outbreakMutex);
    return m_impl->m_activeOutbreaks;
}

bool ZeroHourProtection::AcknowledgeOutbreak(uint64_t outbreakId) {
    // In a real implementation, this would mark the outbreak as seen in the DB
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
        } else if (cached->verdict == CloudVerdict::SUSPICIOUS && GetThreatLevel() >= ThreatLevel::HIGH) {
            result.shouldAllow = false; // Block suspicious in high threat
        }

        m_impl->m_stats.cloudCacheHits++;
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
            return result;
        }
    }

    // Determine if we should hold
    bool shouldHold = ShouldHoldFile(request.filePath) && request.allowHold;

    if (shouldHold) {
        // Create Hold Entry
        HeldFile held;
        held.holdId = GenerateHoldId();
        held.filePath = request.filePath;
        held.hash = request.hash;
        held.reason = HoldReason::CLOUD_PENDING;
        held.holdTime = std::chrono::system_clock::now();
        held.timeoutTime = held.holdTime + std::chrono::milliseconds(request.timeoutMs);
        held.requestingPid = request.requestingPid;
        held.requestingProcess = request.requestingProcess;

        {
            std::unique_lock lock(m_impl->m_holdMutex);
            m_impl->m_heldFiles[held.holdId] = held;
            m_impl->m_stats.currentHeldFiles++;
            m_impl->m_stats.filesHeld++;
        }

        // Return Hold Result
        result.shouldAllow = false; // Block until decision
        result.wasHeld = true;
        result.holdId = held.holdId;
        result.verdict = CloudVerdict::PENDING;

        // Trigger Cloud Query (Async)
        // In real code, we'd dispatch to a thread pool
        // For now, assume this triggers the async lookup which eventually calls ReleaseHeldFile
        GetCloudVerdict(request.hash, request.timeoutMs); // Fire and forget logic for this stub

        m_impl->FireFileHoldCallback(held);
    } else {
        // Allow unknown if configured to not hold
        std::shared_lock configLock(m_impl->m_configMutex);
        if (m_impl->m_config.cloudConfig.fallbackPolicy == FallbackPolicy::ALLOW_UNKNOWN) {
            result.shouldAllow = true;
            result.verdict = CloudVerdict::UNKNOWN;
            result.source = FileAnalysisResult::Source::FALLBACK_POLICY;
        } else {
            result.shouldAllow = false;
            result.verdict = CloudVerdict::UNKNOWN;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.totalTime = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    m_impl->FireVerdictCallback(request.filePath, result);
    return result;
}

bool ZeroHourProtection::ShouldHoldFile(const std::wstring& filePath) {
    if (!m_impl->m_config.holdUnknownFiles) return false;

    // Check exclusions
    std::shared_lock lock(m_impl->m_configMutex);
    for (const auto& ext : m_impl->m_config.excludedExtensions) {
        if (filePath.length() >= ext.length()) {
            if (filePath.compare(filePath.length() - ext.length(), ext.length(), ext) == 0) {
                return false;
            }
        }
    }
    return true;
}

CloudVerdictResult ZeroHourProtection::GetCloudVerdict(const FileHash& hash, uint32_t timeout) {
    // Stub for cloud lookup
    // In production, this calls ThreatIntelLookup or makes HTTP request
    CloudVerdictResult result;
    result.verdict = CloudVerdict::UNKNOWN; // Default
    result.queryTime = std::chrono::system_clock::now();

    // Simulate lookup...

    return result;
}

std::unordered_map<std::wstring, CloudVerdictResult> ZeroHourProtection::GetCloudVerdictBatch(
    const std::vector<FileHash>& hashes, uint32_t timeout) {
    std::unordered_map<std::wstring, CloudVerdictResult> results;
    // Batch stub
    return results;
}

uint64_t ZeroHourProtection::SubmitForDetonation(const std::wstring& filePath, CloudQueryPriority priority) {
    // Stub
    return 0;
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
    // Stub for update check
    return false;
}

bool ZeroHourProtection::ApplySignatureUpdate(const MicroSigUpdatePackage& package) {
    std::unique_lock lock(m_impl->m_sigMutex);

    // Remove deleted signatures
    // ... logic ...

    // Add new signatures
    for (const auto& sig : package.additions) {
        m_impl->m_microSignatures.push_back(sig);
    }

    m_impl->m_sigVersion = package.targetVersion;
    m_impl->m_stats.microSigUpdates++;

    Utils::Logger::Info("Applied micro-signature update v{}", package.targetVersion);
    return true;
}

bool ZeroHourProtection::RollbackSignatures(uint32_t targetVersion) {
    // Stub
    return false;
}

uint32_t ZeroHourProtection::GetSignatureVersion() const noexcept {
    std::shared_lock lock(m_impl->m_sigMutex);
    return m_impl->m_sigVersion;
}

std::vector<uint32_t> ZeroHourProtection::GetAvailableRollbackVersions() const {
    return {};
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
    return m_impl->m_cloudStatus == CloudServiceStatus::CONNECTED;
}

bool ZeroHourProtection::ReconnectCloud() {
    m_impl->m_cloudStatus = CloudServiceStatus::CONNECTED;
    return true;
}

uint32_t ZeroHourProtection::GetCloudLatency() const noexcept {
    return 0; // Stub
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
    std::unique_lock lock(m_impl->m_cacheMutex);
    m_impl->m_verdictCache[hashStr] = verdict;

    // Prune if too large
    if (m_impl->m_verdictCache.size() > ZeroHourConstants::MAX_VERDICT_CACHE_SIZE) {
        m_impl->m_verdictCache.erase(m_impl->m_verdictCache.begin());
    }
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
    // Stub
    return 0;
}

uint64_t ZeroHourProtection::RegisterCloudStatusCallback(CloudStatusCallback callback) {
    // Stub
    return 0;
}

bool ZeroHourProtection::UnregisterCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_verdictCallbacks.erase(callbackId);
    m_impl->m_holdCallbacks.erase(callbackId);
    m_impl->m_outbreakCallbacks.erase(callbackId);
    m_impl->m_threatLevelCallbacks.erase(callbackId);
    return true;
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
    return IsInitialized();
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
    return Utils::StringUtils::BytesToHex(sha256);
}

std::wstring FileHash::GetMD5String() const {
    return Utils::StringUtils::BytesToHex(md5);
}

void ZeroHourStatistics::Reset() noexcept {
    totalCloudQueries = 0;
    cloudCacheHits = 0;
    cloudCacheMisses = 0;
    cloudTimeouts = 0;
    cloudErrors = 0;
    verdictsClean = 0;
    verdictsMalicious = 0;
    filesHeld = 0;
    filesReleased = 0;
    // ... reset others ...
}

ZeroHourProtectionConfig ZeroHourProtectionConfig::CreateEnterprise() noexcept {
    ZeroHourProtectionConfig config;
    config.enabled = true;
    config.holdUnknownFiles = true;
    config.cloudConfig.fallbackPolicy = FallbackPolicy::HOLD_TIMEOUT;
    config.outbreakModeEnabled = true;
    return config;
}

} // namespace RealTime
} // namespace ShadowStrike
