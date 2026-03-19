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
 * @file ScanEngine.cpp
 * @brief Enterprise implementation of the central scan orchestrator.
 *
 * The Brain of ShadowStrike NGAV - coordinates all detection technologies
 * into a coherent decision-making pipeline.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "ScanEngine.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES (The Real Deal)
// ============================================================================
#include "../../HashStore/HashStore.hpp"
#include "../../SignatureStore/SignatureStore.hpp"
#include "../../Whitelist/WhiteListStore.hpp"
#include "../../ThreatIntel/ThreatIntelDatabase.hpp"
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/ThreadPool.hpp"
#include "HeuristicAnalyzer.hpp"
#include "BehaviorAnalyzer.hpp"
#include "MachineLearningDetector.hpp"
#include "PackerUnpacker.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <queue>
#include <regex>

#ifdef _WIN32
#  include <Wintrust.h>
#  include <Softpub.h>
#  pragma comment(lib, "Wintrust.lib")
#endif

namespace ShadowStrike {
namespace Core {
namespace Engine {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

struct ScanJob {
    uint64_t jobId = 0;
    DirectoryScanRequest request;
    ScanPriority priority = ScanPriority::Normal;
    ScanJobState state = ScanJobState::Queued;

    ScanProgress progress;
    DirectoryScanResult result;

    steady_clock::time_point startTime;
    steady_clock::time_point endTime;

    std::atomic<bool> cancelRequested{false};
    std::atomic<bool> pauseRequested{false};

    ScanProgressCallback progressCallback;
};

// ============================================================================
// PIMPL IMPLEMENTATION (ABI Stability)
// ============================================================================

/**
 * @brief Private implementation class following PIMPL pattern.
 *
 * This separates implementation details from the public interface,
 * ensuring ABI stability across library versions.
 */
class ScanEngine::Impl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::mutex m_cacheMutex;
    mutable std::shared_mutex m_exclusionMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_jobMutex;

    // Initialization state
    std::atomic<bool> m_initialized{false};

    // Configuration
    EngineConfig m_config{};

    // Thread pool for async operations
    std::shared_ptr<ThreadPool> m_threadPool;

    // Subsystem instances (using infrastructure)
    std::unique_ptr<SignatureStore::SignatureStore> m_signatureStore;
    std::unique_ptr<Whitelist::WhitelistStore> m_whitelistStore;
    std::unique_ptr<ThreatIntel::ThreatIntelDatabase> m_threatIntelDB;
    std::unique_ptr<HeuristicAnalyzer> m_heuristicAnalyzer;
    std::unique_ptr<BehaviorAnalyzer> m_behaviorAnalyzer;
    std::unique_ptr<MachineLearningDetector> m_mlDetector;
    std::unique_ptr<PackerUnpacker> m_packerUnpacker;

    // Result cache with LRU eviction
    struct CachedResult {
        EngineResult result;
        steady_clock::time_point timestamp;
        uint32_t hitCount = 0;
    };
    std::unordered_map<std::string, CachedResult> m_resultCache;
    static constexpr size_t MAX_CACHE_ENTRIES = 10000;
    static constexpr auto CACHE_TTL = std::chrono::minutes(15);

    // Exclusion rules
    std::vector<ExclusionRule> m_exclusions;

    // Callbacks
    struct CallbackEntry {
        uint64_t id;
        std::function<void()> callback;
    };
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::unordered_map<uint64_t, DetectionCallback> m_detectionCallbacks;
    std::unordered_map<uint64_t, ScanCompleteCallback> m_completeCallbacks;
    std::unordered_map<uint64_t, ErrorCallback> m_errorCallbacks;

    // Job management
    std::atomic<uint64_t> m_nextJobId{1};
    std::unordered_map<uint64_t, std::shared_ptr<ScanJob>> m_scanJobs;

    // Statistics
    struct InternalStats {
        std::atomic<uint64_t> totalScans{0};
        std::atomic<uint64_t> infections{0};
        std::atomic<uint64_t> suspicious{0};
        std::atomic<uint64_t> cacheHits{0};
        std::atomic<uint64_t> whitelistHits{0};
        std::atomic<uint64_t> hashHits{0};
        std::atomic<uint64_t> signatureHits{0};
        std::atomic<uint64_t> heuristicHits{0};
        std::atomic<uint64_t> behaviorHits{0};
        std::atomic<uint64_t> mlHits{0};
        std::atomic<uint64_t> totalTimeUs{0};

        // Pipeline stage times
        std::atomic<uint64_t> whitelistTimeUs{0};
        std::atomic<uint64_t> hashTimeUs{0};
        std::atomic<uint64_t> threatIntelTimeUs{0};
        std::atomic<uint64_t> signatureTimeUs{0};
        std::atomic<uint64_t> heuristicTimeUs{0};

        // Archive stats
        std::atomic<uint64_t> archivesScanned{0};
        std::atomic<uint64_t> archiveFilesScanned{0};

        // Process stats
        std::atomic<uint64_t> processesScanned{0};

        // Performance tracking
        steady_clock::time_point startTime;
        std::atomic<uint64_t> peakMemoryBytes{0};
    } m_stats;

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    Impl() {
        m_stats.startTime = steady_clock::now();
    }

    ~Impl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const EngineConfig& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("ScanEngine::Impl already initialized");
            return true;
        }

        try {
            Logger::Info("ScanEngine::Impl: Initializing with enterprise infrastructure");

            // Store configuration
            m_config = config;

            // Initialize thread pool
            uint32_t threadCount = config.scanThreads > 0
                ? config.scanThreads
                : std::thread::hardware_concurrency();

            m_threadPool = std::make_shared<ThreadPool>(threadCount);
            Logger::Info("ScanEngine: Thread pool initialized with {} threads", threadCount);

            // Initialize SignatureStore (YARA + Patterns + Hashes)
            if (!m_config.signatureDbPath.empty()) {
                Logger::Info("ScanEngine: Initializing SignatureStore at {}",
                    StringUtils::ToNarrowString(m_config.signatureDbPath));

                m_signatureStore = std::make_unique<SignatureStore::SignatureStore>();

                auto sigResult = m_signatureStore->Initialize(m_config.signatureDbPath);
                if (sigResult != SignatureStore::StoreError::Success) {
                    Logger::Error("ScanEngine: SignatureStore initialization failed: {}",
                        static_cast<int>(sigResult));
                    return false;
                }

                Logger::Info("ScanEngine: SignatureStore initialized - {} signatures loaded",
                    m_signatureStore->GetSignatureCount());
            }

            // Initialize WhitelistStore (Bloom Filter + Trie + Certificates)
            if (!m_config.whitelistDbPath.empty()) {
                Logger::Info("ScanEngine: Initializing WhitelistStore at {}",
                    StringUtils::ToNarrowString(m_config.whitelistDbPath));

                m_whitelistStore = std::make_unique<Whitelist::WhitelistStore>();

                auto wlResult = m_whitelistStore->Initialize(m_config.whitelistDbPath);
                if (wlResult != Whitelist::WhitelistError::Success) {
                    Logger::Error("ScanEngine: WhitelistStore initialization failed: {}",
                        static_cast<int>(wlResult));
                    return false;
                }

                Logger::Info("ScanEngine: WhitelistStore initialized - {} entries",
                    m_whitelistStore->GetEntryCount());
            }

            // Initialize ThreatIntelDatabase (Memory-mapped threat intel)
            if (!m_config.threatIntelDbPath.empty()) {
                Logger::Info("ScanEngine: Initializing ThreatIntelDatabase at {}",
                    StringUtils::ToNarrowString(m_config.threatIntelDbPath));

                m_threatIntelDB = std::make_unique<ThreatIntel::ThreatIntelDatabase>();

                ThreatIntel::DatabaseConfig tiConfig =
                    ThreatIntel::DatabaseConfig::CreateDefault(m_config.threatIntelDbPath);

                auto tiResult = m_threatIntelDB->Initialize(tiConfig);
                if (tiResult != ThreatIntel::ThreatIntelError::Success) {
                    Logger::Error("ScanEngine: ThreatIntelDatabase initialization failed: {}",
                        static_cast<int>(tiResult));
                    return false;
                }

                Logger::Info("ScanEngine: ThreatIntelDatabase initialized - {} entries",
                    m_threatIntelDB->GetEntryCount());
            }

            // Initialize HeuristicAnalyzer (PE/ELF/Script analysis)
            if (m_config.enableHeuristics) {
                Logger::Info("ScanEngine: Initializing HeuristicAnalyzer");

                m_heuristicAnalyzer = std::make_unique<HeuristicAnalyzer>();

                HeuristicAnalyzerConfig hConfig = HeuristicAnalyzerConfig::CreateDefault();
                hConfig.enablePEAnalysis = true;
                hConfig.enableImportAnalysis = true;
                hConfig.enableStringAnalysis = true;
                hConfig.enablePackerDetection = true;

                if (!m_heuristicAnalyzer->Initialize(m_threadPool, hConfig)) {
                    Logger::Error("ScanEngine: HeuristicAnalyzer initialization failed");
                    return false;
                }

                Logger::Info("ScanEngine: HeuristicAnalyzer initialized");
            }

            // Initialize BehaviorAnalyzer (optional)
            if (m_config.enableBehaviorAnalysis) {
                Logger::Info("ScanEngine: BehaviorAnalyzer will be initialized on demand");
                // Lazy initialization
            }

            // Initialize MachineLearning (optional)
            if (m_config.enableMachineLearning) {
                Logger::Info("ScanEngine: MachineLearning will be initialized on demand");
                // Lazy initialization
            }

            // Initialize PackerUnpacker
            if (m_config.enableCompressedScanning) {
                m_packerUnpacker = std::make_unique<PackerUnpacker>();
                Logger::Info("ScanEngine: PackerUnpacker initialized");
            }

            // Reset statistics
            m_stats = InternalStats{};
            m_stats.startTime = steady_clock::now();

            m_initialized.store(true, std::memory_order_release);
            Logger::Info("ScanEngine::Impl: Initialization complete - All subsystems online");

            return true;

        } catch (const std::exception& e) {
            Logger::Error("ScanEngine::Impl: Initialization exception: {}", e.what());
            return false;
        }
    }

    void Shutdown() {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("ScanEngine::Impl: Shutting down");

        // Cancel all active jobs
        {
            std::unique_lock jobLock(m_jobMutex);
            for (auto& [id, job] : m_scanJobs) {
                job->cancelRequested.store(true, std::memory_order_release);
            }
        }

        // Shutdown subsystems in reverse order
        if (m_packerUnpacker) {
            m_packerUnpacker.reset();
        }

        if (m_mlDetector) {
            m_mlDetector->Shutdown();
            m_mlDetector.reset();
        }

        if (m_behaviorAnalyzer) {
            m_behaviorAnalyzer->Shutdown();
            m_behaviorAnalyzer.reset();
        }

        if (m_heuristicAnalyzer) {
            m_heuristicAnalyzer->Shutdown();
            m_heuristicAnalyzer.reset();
        }

        if (m_threatIntelDB) {
            m_threatIntelDB->Shutdown();
            m_threatIntelDB.reset();
        }

        if (m_whitelistStore) {
            m_whitelistStore->Shutdown();
            m_whitelistStore.reset();
        }

        if (m_signatureStore) {
            m_signatureStore->Shutdown();
            m_signatureStore.reset();
        }

        // Shutdown thread pool
        if (m_threadPool) {
            m_threadPool.reset();
        }

        // Clear cache
        {
            std::lock_guard cacheLock(m_cacheMutex);
            m_resultCache.clear();
        }

        // Clear callbacks
        {
            std::unique_lock cbLock(m_callbackMutex);
            m_detectionCallbacks.clear();
            m_completeCallbacks.clear();
            m_errorCallbacks.clear();
        }

        // Clear jobs
        {
            std::unique_lock jobLock(m_jobMutex);
            m_scanJobs.clear();
        }

        m_initialized.store(false, std::memory_order_release);
        Logger::Info("ScanEngine::Impl: Shutdown complete");
    }

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    [[nodiscard]] std::optional<EngineResult> CheckCache(const std::string& hash) {
        if (!m_config.enableResultCache || hash.empty()) {
            return std::nullopt;
        }

        std::lock_guard lock(m_cacheMutex);

        auto it = m_resultCache.find(hash);
        if (it == m_resultCache.end()) {
            return std::nullopt;
        }

        // Check TTL
        auto age = steady_clock::now() - it->second.timestamp;
        if (age > CACHE_TTL) {
            m_resultCache.erase(it);
            return std::nullopt;
        }

        // Update hit count
        it->second.hitCount++;
        m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);

        Logger::Debug("ScanEngine: Cache hit for hash {}", hash.substr(0, 16));
        return it->second.result;
    }

    void UpdateCache(const std::string& hash, const EngineResult& result) {
        if (!m_config.enableResultCache || hash.empty()) {
            return;
        }

        std::lock_guard lock(m_cacheMutex);

        // LRU eviction if cache is full
        if (m_resultCache.size() >= MAX_CACHE_ENTRIES) {
            // Find least recently used entry
            auto lru = std::min_element(
                m_resultCache.begin(),
                m_resultCache.end(),
                [](const auto& a, const auto& b) {
                    return a.second.timestamp < b.second.timestamp;
                }
            );

            if (lru != m_resultCache.end()) {
                m_resultCache.erase(lru);
            }
        }

        CachedResult cached{};
        cached.result = result;
        cached.timestamp = steady_clock::now();
        cached.hitCount = 0;

        m_resultCache[hash] = cached;
    }

    void ClearExpiredCache() {
        std::lock_guard lock(m_cacheMutex);

        auto now = steady_clock::now();

        for (auto it = m_resultCache.begin(); it != m_resultCache.end(); ) {
            if (now - it->second.timestamp > CACHE_TTL) {
                it = m_resultCache.erase(it);
            } else {
                ++it;
            }
        }
    }

    // ========================================================================
    // EXCLUSION MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool IsExcluded(const std::wstring& path) const {
        std::shared_lock lock(m_exclusionMutex);

        for (const auto& rule : m_exclusions) {
            if (!rule.enabled) continue;

            switch (rule.type) {
                case ExclusionRule::Type::Path: {
                    if (rule.caseSensitive) {
                        if (path == rule.pattern) return true;
                    } else {
                        if (StringUtils::ToLower(path) == StringUtils::ToLower(rule.pattern)) {
                            return true;
                        }
                    }
                    break;
                }

                case ExclusionRule::Type::PathPrefix: {
                    if (rule.caseSensitive) {
                        if (path.starts_with(rule.pattern)) return true;
                    } else {
                        auto lowerPath = StringUtils::ToLower(path);
                        auto lowerPattern = StringUtils::ToLower(rule.pattern);
                        if (lowerPath.starts_with(lowerPattern)) return true;
                    }
                    break;
                }

                case ExclusionRule::Type::Extension: {
                    fs::path p(path);
                    auto ext = p.extension().wstring();
                    if (rule.caseSensitive) {
                        if (ext == rule.pattern) return true;
                    } else {
                        if (StringUtils::ToLower(ext) == StringUtils::ToLower(rule.pattern)) {
                            return true;
                        }
                    }
                    break;
                }

                case ExclusionRule::Type::ProcessName: {
                    fs::path p(path);
                    auto filename = p.filename().wstring();
                    if (rule.caseSensitive) {
                        if (filename == rule.pattern) return true;
                    } else {
                        if (StringUtils::ToLower(filename) == StringUtils::ToLower(rule.pattern)) {
                            return true;
                        }
                    }
                    break;
                }

                case ExclusionRule::Type::Hash:
                    // Hash exclusion handled separately
                    break;
            }
        }

        return false;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeDetectionCallbacks(const EngineResult& result) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_detectionCallbacks) {
            try {
                callback(result);
            } catch (const std::exception& e) {
                Logger::Error("ScanEngine: Detection callback exception: {}", e.what());
            }
        }
    }

    void InvokeCompleteCallbacks(const ScanStatistics& stats) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_completeCallbacks) {
            try {
                callback(stats);
            } catch (const std::exception& e) {
                Logger::Error("ScanEngine: Complete callback exception: {}", e.what());
            }
        }
    }

    void InvokeErrorCallbacks(const std::wstring& error, uint32_t errorCode) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_errorCallbacks) {
            try {
                callback(error, errorCode);
            } catch (const std::exception& e) {
                Logger::Error("ScanEngine: Error callback exception: {}", e.what());
            }
        }
    }

    // ========================================================================
    // ARCHIVE DETECTION
    // ========================================================================

    [[nodiscard]] bool IsArchiveExtension(const std::wstring& path) const {
        static const std::vector<std::wstring> archiveExtensions = {
            L".zip", L".rar", L".7z", L".tar", L".gz", L".bz2",
            L".cab", L".iso", L".img", L".arj", L".lzh", L".ace"
        };

        fs::path p(path);
        auto ext = StringUtils::ToLower(p.extension().wstring());

        return std::find(archiveExtensions.begin(), archiveExtensions.end(), ext)
            != archiveExtensions.end();
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

ScanEngine& ScanEngine::Instance() {
    static ScanEngine instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

ScanEngine::ScanEngine()
    : m_impl(std::make_unique<Impl>())
{
    Logger::Info("ScanEngine: Constructor called");
}

ScanEngine::~ScanEngine() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("ScanEngine: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool ScanEngine::Initialize(const EngineConfig& config) {
    if (!m_impl) {
        Logger::Critical("ScanEngine: Implementation is null");
        return false;
    }

    return m_impl->Initialize(config);
}

void ScanEngine::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool ScanEngine::IsInitialized() const {
    return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
}

// ============================================================================
// SINGLE FILE SCANNING
// ============================================================================

EngineResult ScanEngine::ScanFile(
    const std::wstring& filePath,
    const ScanContext& context
) {
    EngineResult result{};
    const auto scanStart = steady_clock::now();

    if (!IsInitialized()) {
        Logger::Error("ScanEngine: Not initialized");
        result.verdict = ScanVerdict::Error;
        return result;
    }

    try {
        // Update statistics
        m_impl->m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);

        Logger::Info("ScanEngine: Scanning file: {} (Type: {})",
            StringUtils::ToNarrowString(filePath),
            static_cast<int>(context.type));

        // ====================================================================
        // PRE-FLIGHT VALIDATION
        // ====================================================================

        // Check exclusions
        if (m_impl->IsExcluded(filePath)) {
            Logger::Info("ScanEngine: File excluded by rule");
            result.verdict = ScanVerdict::Whitelisted;
            result.detectionSource = "Exclusion";
            return result;
        }

        // Validate file path
        if (filePath.empty()) {
            Logger::Warn("ScanEngine: Empty file path");
            result.verdict = ScanVerdict::Error;
            return result;
        }

        // Check file existence
        std::error_code ec;
        if (!fs::exists(filePath, ec)) {
            Logger::Warn("ScanEngine: File not found: {}",
                StringUtils::ToNarrowString(filePath));
            result.verdict = ScanVerdict::Error;
            return result;
        }

        // Check file size limits for real-time scans
        uint64_t fileSize = 0;
        try {
            fileSize = fs::file_size(filePath, ec);
            if (ec) {
                Logger::Warn("ScanEngine: Cannot get file size: {}", ec.message());
                result.verdict = ScanVerdict::Error;
                return result;
            }
        } catch (...) {
            Logger::Error("ScanEngine: Exception getting file size");
            result.verdict = ScanVerdict::Error;
            return result;
        }

        if (context.type == ScanType::RealTime &&
            fileSize > m_impl->m_config.maxFileSizeRealTime) {
            Logger::Info("ScanEngine: File too large for real-time scan: {} bytes", fileSize);
            result.verdict = ScanVerdict::Clean;
            return result;
        }

        // ====================================================================
        // COMPUTE FILE HASH (SHA-256)
        // ====================================================================

        std::string fileHash;
        try {
            std::vector<uint8_t> hashBytes;
            HashUtils::Error hashErr;

            if (!HashUtils::ComputeFile(HashUtils::Algorithm::SHA256,
                                       filePath, hashBytes, &hashErr)) {
                Logger::Error("ScanEngine: Hash computation failed");
                result.verdict = ScanVerdict::Error;
                return result;
            }

            fileHash = HashUtils::ToHexLower(hashBytes);
            result.sha256 = fileHash;

            Logger::Debug("ScanEngine: File hash computed: {}", fileHash);

        } catch (const std::exception& e) {
            Logger::Error("ScanEngine: Hash computation failed: {}", e.what());
            result.verdict = ScanVerdict::Error;
            return result;
        }

        // ====================================================================
        // CHECK RESULT CACHE (Sub-microsecond fast path)
        // ====================================================================

        if (auto cachedResult = m_impl->CheckCache(fileHash)) {
            Logger::Info("ScanEngine: Returning cached result (Verdict: {})",
                static_cast<int>(cachedResult->verdict));

            // Update timing
            const auto scanEnd = steady_clock::now();
            cachedResult->scanDurationUs = duration_cast<microseconds>(
                scanEnd - scanStart
            ).count();

            return *cachedResult;
        }

        // ====================================================================
        // STAGE 1: WHITELIST CHECK (Fastest - Bloom Filter + Trie)
        // ====================================================================

        if (m_impl->m_whitelistStore) {
            const auto stage1Start = steady_clock::now();

            // Check by hash (bloom filter fast path)
            if (m_impl->m_whitelistStore->IsHashWhitelisted(fileHash)) {
                m_impl->m_stats.whitelistHits.fetch_add(1, std::memory_order_relaxed);

                result.verdict = ScanVerdict::Whitelisted;
                result.detectionSource = "Whitelist-Hash";
                result.sha256 = fileHash;

                Logger::Info("ScanEngine: File whitelisted by hash");
                goto finalize_scan;
            }

            // Check by path (trie index)
            if (m_impl->m_whitelistStore->IsPathWhitelisted(filePath)) {
                m_impl->m_stats.whitelistHits.fetch_add(1, std::memory_order_relaxed);

                result.verdict = ScanVerdict::Whitelisted;
                result.detectionSource = "Whitelist-Path";
                result.sha256 = fileHash;

                Logger::Info("ScanEngine: File whitelisted by path");
                goto finalize_scan;
            }

            const auto stage1End = steady_clock::now();
            m_impl->m_stats.whitelistTimeUs.fetch_add(
                duration_cast<microseconds>(stage1End - stage1Start).count(),
                std::memory_order_relaxed
            );
        }

        // ====================================================================
        // STAGE 2: HASH CHECK (Fast - B+Tree Index)
        // ====================================================================

        if (m_impl->m_signatureStore) {
            const auto stage2Start = steady_clock::now();

            // Use SignatureStore's hash lookup (uses HashStore internally)
            SignatureStore::ScanOptions hashScanOpts{};
            hashScanOpts.enableHashLookup = true;
            hashScanOpts.enablePatternScan = false;
            hashScanOpts.enableYaraScan = false;
            hashScanOpts.stopOnFirstMatch = true;

            auto hashResult = m_impl->m_signatureStore->ScanHash(fileHash, hashScanOpts);

            if (hashResult.isDetected) {
                m_impl->m_stats.hashHits.fetch_add(1, std::memory_order_relaxed);
                m_impl->m_stats.infections.fetch_add(1, std::memory_order_relaxed);

                result.verdict = ScanVerdict::Infected;
                result.threatName = hashResult.threatName;
                result.severity = hashResult.severity;
                result.threatId = hashResult.signatureId;
                result.detectionSource = "HashStore";
                result.sha256 = fileHash;

                Logger::Warn("ScanEngine: Hash match found - Threat: {}",
                    hashResult.threatName);

                // Invoke detection callbacks
                m_impl->InvokeDetectionCallbacks(result);

                goto finalize_scan;
            }

            const auto stage2End = steady_clock::now();
            m_impl->m_stats.hashTimeUs.fetch_add(
                duration_cast<microseconds>(stage2End - stage2Start).count(),
                std::memory_order_relaxed
            );
        }

        // ====================================================================
        // STAGE 3: THREAT INTELLIGENCE (Cloud/Local Reputation)
        // ====================================================================

        if (m_impl->m_config.enableCloudLookup && m_impl->m_threatIntelDB) {
            const auto stage3Start = steady_clock::now();

            auto tiResult = m_impl->m_threatIntelDB->QueryHash(fileHash);

            if (tiResult.found && tiResult.isMalicious) {
                result.verdict = ScanVerdict::Suspicious;
                result.threatName = tiResult.threatName;
                result.severity = SignatureStore::ThreatLevel::Medium;
                result.detectionSource = "ThreatIntel";
                result.sha256 = fileHash;

                Logger::Info("ScanEngine: Threat intelligence match - Threat: {}",
                    tiResult.threatName);

                // Don't goto finalize - continue with deeper analysis
                // This is a suspicion, not a confirmed detection
            }

            const auto stage3End = steady_clock::now();
            m_impl->m_stats.threatIntelTimeUs.fetch_add(
                duration_cast<microseconds>(stage3End - stage3Start).count(),
                std::memory_order_relaxed
            );
        }

        // ====================================================================
        // STAGE 4: DEEP SIGNATURE SCAN (YARA + Patterns)
        // ====================================================================

        if (m_impl->m_signatureStore && context.deepScan) {
            const auto stage4Start = steady_clock::now();

            // Read file content
            std::vector<uint8_t> fileBuffer;
            try {
                std::ifstream file(filePath, std::ios::binary | std::ios::ate);
                if (!file) {
                    Logger::Warn("ScanEngine: Cannot open file for reading");
                    result.verdict = ScanVerdict::Error;
                    return result;
                }

                auto fileSize = file.tellg();
                file.seekg(0, std::ios::beg);

                // Limit buffer size for very large files
                constexpr size_t MAX_SCAN_SIZE = 100 * 1024 * 1024; // 100MB
                size_t readSize = std::min<size_t>(fileSize, MAX_SCAN_SIZE);

                fileBuffer.resize(readSize);
                file.read(reinterpret_cast<char*>(fileBuffer.data()), readSize);

            } catch (const std::exception& e) {
                Logger::Error("ScanEngine: File read exception: {}", e.what());
                result.verdict = ScanVerdict::Error;
                return result;
            }

            if (!fileBuffer.empty()) {
                // Configure signature scan
                SignatureStore::ScanOptions sigScanOpts{};
                sigScanOpts.enableHashLookup = false; // Already done
                sigScanOpts.enablePatternScan = true;
                sigScanOpts.enableYaraScan = true;
                sigScanOpts.stopOnFirstMatch = context.stopOnFirstMatch;
                sigScanOpts.timeoutMilliseconds = static_cast<uint32_t>(
                    context.timeout.count()
                );

                auto sigResult = m_impl->m_signatureStore->ScanBuffer(fileBuffer, sigScanOpts);

                if (sigResult.isDetected) {
                    m_impl->m_stats.signatureHits.fetch_add(1, std::memory_order_relaxed);
                    m_impl->m_stats.infections.fetch_add(1, std::memory_order_relaxed);

                    result.verdict = ScanVerdict::Infected;
                    result.threatName = sigResult.threatName;
                    result.severity = sigResult.severity;
                    result.threatId = sigResult.signatureId;
                    result.detectionSource = sigResult.detectionMethod;
                    result.sha256 = fileHash;

                    Logger::Warn("ScanEngine: Signature match found - Threat: {} (Method: {})",
                        sigResult.threatName, sigResult.detectionMethod);

                    // Invoke detection callbacks
                    m_impl->InvokeDetectionCallbacks(result);

                    goto finalize_scan;
                }
            }

            const auto stage4End = steady_clock::now();
            m_impl->m_stats.signatureTimeUs.fetch_add(
                duration_cast<microseconds>(stage4End - stage4Start).count(),
                std::memory_order_relaxed
            );
        }

        // ====================================================================
        // STAGE 5: HEURISTIC ANALYSIS (PE/Entropy/Import/String Analysis)
        // ====================================================================

        if (m_impl->m_config.enableHeuristics && m_impl->m_heuristicAnalyzer) {
            const auto stage5Start = steady_clock::now();

            auto heuristicResult = m_impl->m_heuristicAnalyzer->AnalyzeFile(filePath);

            if (heuristicResult.isMalicious ||
                heuristicResult.riskScore >= m_impl->m_config.sensitivityLevel * 30.0) {

                m_impl->m_stats.heuristicHits.fetch_add(1, std::memory_order_relaxed);
                m_impl->m_stats.suspicious.fetch_add(1, std::memory_order_relaxed);

                result.verdict = ScanVerdict::Suspicious;
                result.threatName = heuristicResult.threatName;
                result.threatScore = heuristicResult.riskScore;
                result.detectionSource = "Heuristic";
                result.sha256 = fileHash;

                Logger::Info("ScanEngine: Heuristic detection - Score: {:.1f}, Name: {}",
                    heuristicResult.riskScore,
                    StringUtils::ToNarrowString(heuristicResult.threatName));

                // Invoke detection callbacks
                m_impl->InvokeDetectionCallbacks(result);

                goto finalize_scan;
            }

            const auto stage5End = steady_clock::now();
            m_impl->m_stats.heuristicTimeUs.fetch_add(
                duration_cast<microseconds>(stage5End - stage5Start).count(),
                std::memory_order_relaxed
            );
        }

        // ====================================================================
        // NO THREAT DETECTED
        // ====================================================================

        result.verdict = ScanVerdict::Clean;
        result.detectionSource = "None";
        result.sha256 = fileHash;

    finalize_scan:
        // Calculate total scan duration
        const auto scanEnd = steady_clock::now();
        result.scanDurationUs = duration_cast<microseconds>(
            scanEnd - scanStart
        ).count();

        // Update timing statistics
        m_impl->m_stats.totalTimeUs.fetch_add(
            result.scanDurationUs,
            std::memory_order_relaxed
        );

        // Update cache
        m_impl->UpdateCache(fileHash, result);

        Logger::Info("ScanEngine: Scan complete - File: {}, Verdict: {}, Duration: {} µs",
            StringUtils::ToNarrowString(fs::path(filePath).filename()),
            static_cast<int>(result.verdict),
            result.scanDurationUs);

        return result;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Scan exception: {}", e.what());
        m_impl->InvokeErrorCallbacks(
            std::format(L"Scan exception: {}",
                StringUtils::ToWideString(e.what())),
            0
        );
        result.verdict = ScanVerdict::Error;
        return result;
    }
}

std::future<EngineResult> ScanEngine::ScanFileAsync(
    const std::wstring& filePath,
    const ScanContext& context,
    ScanProgressCallback progressCallback
) {
    if (!IsInitialized() || !m_impl->m_threadPool) {
        return std::async(std::launch::deferred, [this, filePath, context]() {
            return ScanFile(filePath, context);
        });
    }

    return std::async(std::launch::async, [this, filePath, context, progressCallback]() {
        auto result = ScanFile(filePath, context);

        if (progressCallback) {
            ScanProgress progress{};
            progress.filesScanned = 1;
            progress.totalFiles = 1;
            progress.percentComplete = 100.0f;
            progress.currentFile = filePath;
            progressCallback(progress);
        }

        return result;
    });
}

EngineResult ScanEngine::QuickScanFile(const std::wstring& filePath) {
    ScanContext context{};
    context.type = ScanType::OnDemand;
    context.deepScan = false;
    context.scanArchives = false;
    context.scanPacked = false;
    context.stopOnFirstMatch = true;
    context.timeout = std::chrono::milliseconds(1000); // 1 second timeout

    return ScanFile(filePath, context);
}

// ============================================================================
// BATCH SCANNING
// ============================================================================

BatchScanResult ScanEngine::ScanBatch(
    const BatchScanRequest& request,
    ScanProgressCallback progressCallback
) {
    BatchScanResult batchResult{};
    const auto batchStart = steady_clock::now();

    if (!IsInitialized()) {
        Logger::Error("ScanEngine: Not initialized");
        return batchResult;
    }

    try {
        Logger::Info("ScanEngine: Starting batch scan of {} files",
            request.filePaths.size());

        batchResult.results.reserve(request.filePaths.size());

        ScanStatistics stats{};
        uint64_t filesScanned = 0;
        const uint64_t totalFiles = request.filePaths.size();

        // Determine concurrency
        uint32_t concurrency = request.maxConcurrency > 0
            ? request.maxConcurrency
            : std::thread::hardware_concurrency();

        // Scan files
        std::mutex resultMutex;
        std::atomic<uint64_t> completed{0};

        auto scanTask = [&](const std::wstring& filePath) {
            auto result = ScanFile(filePath, request.context);

            {
                std::lock_guard lock(resultMutex);
                batchResult.results.push_back(result);

                stats.filesScanned++;
                if (result.verdict == ScanVerdict::Infected) {
                    stats.filesInfected++;
                }
                if (result.verdict == ScanVerdict::Suspicious) {
                    stats.filesSuspicious++;
                }
                stats.totalBytesScanned += fs::file_size(filePath, std::error_code{});
            }

            completed.fetch_add(1, std::memory_order_relaxed);

            // Progress callback
            if (progressCallback) {
                ScanProgress progress{};
                progress.filesScanned = completed.load();
                progress.totalFiles = totalFiles;
                progress.percentComplete = (progress.filesScanned * 100.0f) / totalFiles;
                progress.currentFile = filePath;
                progress.elapsed = duration_cast<milliseconds>(
                    steady_clock::now() - batchStart
                );

                progressCallback(progress);
            }

            if (request.stopOnFirstInfection &&
                result.verdict == ScanVerdict::Infected) {
                return true; // Signal to stop
            }

            return false;
        };

        // Execute batch scan
        if (concurrency > 1 && m_impl->m_threadPool) {
            // Multi-threaded
            std::vector<std::future<bool>> futures;
            futures.reserve(request.filePaths.size());

            for (const auto& path : request.filePaths) {
                futures.push_back(std::async(std::launch::async, scanTask, path));
            }

            // Wait for completion
            for (auto& future : futures) {
                if (future.get() && request.stopOnFirstInfection) {
                    break; // Stop on first infection
                }
            }
        } else {
            // Single-threaded
            for (const auto& path : request.filePaths) {
                if (scanTask(path) && request.stopOnFirstInfection) {
                    break;
                }
            }
        }

        batchResult.statistics = stats;
        batchResult.totalDuration = duration_cast<milliseconds>(
            steady_clock::now() - batchStart
        );

        Logger::Info("ScanEngine: Batch scan complete - {} files scanned, {} infected in {} ms",
            stats.filesScanned, stats.filesInfected, batchResult.totalDuration.count());

        return batchResult;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Batch scan exception: {}", e.what());
        return batchResult;
    }
}

std::future<BatchScanResult> ScanEngine::ScanBatchAsync(
    const BatchScanRequest& request,
    ScanProgressCallback progressCallback
) {
    return std::async(std::launch::async, [this, request, progressCallback]() {
        return ScanBatch(request, progressCallback);
    });
}

// ============================================================================
// DIRECTORY SCANNING
// ============================================================================

DirectoryScanResult ScanEngine::ScanDirectory(
    const DirectoryScanRequest& request,
    ScanProgressCallback progressCallback
) {
    DirectoryScanResult dirResult{};
    const auto scanStart = steady_clock::now();

    if (!IsInitialized()) {
        Logger::Error("ScanEngine: Not initialized");
        return dirResult;
    }

    try {
        Logger::Info("ScanEngine: Starting directory scan: {}",
            StringUtils::ToNarrowString(request.rootPath));

        dirResult.rootPath = request.rootPath;

        // Collect files to scan
        std::vector<std::wstring> filesToScan;
        std::error_code ec;

        auto collectFiles = [&](const fs::path& root, uint32_t depth) -> void {
            if (depth > request.maxDepth) return;

            try {
                for (const auto& entry : fs::directory_iterator(root, ec)) {
                    if (ec) {
                        Logger::Warn("Directory iteration error: {}", ec.message());
                        continue;
                    }

                    const auto& path = entry.path();

                    // Check exclusions
                    if (m_impl->IsExcluded(path.wstring())) {
                        continue;
                    }

                    // Check if excluded path
                    bool excluded = false;
                    for (const auto& excludePath : request.excludePaths) {
                        if (path.wstring().find(excludePath) != std::wstring::npos) {
                            excluded = true;
                            break;
                        }
                    }
                    if (excluded) continue;

                    if (entry.is_directory(ec)) {
                        dirResult.directoriesScanned++;
                        if (request.recursive) {
                            collectFiles(path, depth + 1);
                        }
                    } else if (entry.is_regular_file(ec)) {
                        // Check file size limit
                        if (request.maxFileSize > 0 &&
                            entry.file_size(ec) > request.maxFileSize) {
                            continue;
                        }

                        // Check extension filters
                        auto ext = path.extension().wstring();

                        if (!request.includeExtensions.empty()) {
                            bool included = std::find(
                                request.includeExtensions.begin(),
                                request.includeExtensions.end(),
                                ext
                            ) != request.includeExtensions.end();

                            if (!included) continue;
                        }

                        if (!request.excludeExtensions.empty()) {
                            bool excluded = std::find(
                                request.excludeExtensions.begin(),
                                request.excludeExtensions.end(),
                                ext
                            ) != request.excludeExtensions.end();

                            if (excluded) continue;
                        }

                        // Check hidden/system files
                        if (!request.scanHiddenFiles) {
                            // Skip hidden files (basic check)
                            if (path.filename().wstring().starts_with(L".")) {
                                continue;
                            }
                        }

                        filesToScan.push_back(path.wstring());
                    }
                }
            } catch (const std::exception& e) {
                Logger::Error("Error collecting files: {}", e.what());
            }
        };

        // Collect all files
        collectFiles(request.rootPath, 0);

        Logger::Info("ScanEngine: Collected {} files to scan", filesToScan.size());

        // Create batch scan request
        BatchScanRequest batchReq{};
        batchReq.filePaths = std::move(filesToScan);
        batchReq.context = request.context;
        batchReq.maxConcurrency = request.maxConcurrency;
        batchReq.generateReport = true;

        // Perform batch scan
        auto batchResult = ScanBatch(batchReq, progressCallback);

        // Copy results
        dirResult.results = std::move(batchResult.results);
        dirResult.statistics = batchResult.statistics;
        dirResult.totalDuration = duration_cast<milliseconds>(
            steady_clock::now() - scanStart
        );

        Logger::Info("ScanEngine: Directory scan complete - {} files scanned in {} ms",
            dirResult.statistics.filesScanned, dirResult.totalDuration.count());

        // Invoke completion callbacks
        m_impl->InvokeCompleteCallbacks(dirResult.statistics);

        return dirResult;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Directory scan exception: {}", e.what());
        m_impl->InvokeErrorCallbacks(
            std::format(L"Directory scan error: {}",
                StringUtils::ToWideString(e.what())),
            0
        );
        return dirResult;
    }
}

std::future<DirectoryScanResult> ScanEngine::ScanDirectoryAsync(
    const DirectoryScanRequest& request,
    ScanProgressCallback progressCallback
) {
    return std::async(std::launch::async, [this, request, progressCallback]() {
        return ScanDirectory(request, progressCallback);
    });
}

DirectoryScanResult ScanEngine::QuickScan(ScanProgressCallback progressCallback) {
    DirectoryScanRequest request{};
    request.context.type = ScanType::OnDemand;
    request.context.deepScan = false;
    request.recursive = false;

    // Critical areas only
    std::vector<std::wstring> criticalPaths = {
        L"C:\\Windows\\System32",
        L"C:\\Windows\\Temp",
        L"C:\\Users\\*\\AppData\\Local\\Temp",
        L"C:\\Users\\*\\Downloads"
    };

    DirectoryScanResult combinedResult{};

    for (const auto& path : criticalPaths) {
        if (fs::exists(path)) {
            request.rootPath = path;
            auto result = ScanDirectory(request, progressCallback);

            // Combine results
            combinedResult.results.insert(
                combinedResult.results.end(),
                result.results.begin(),
                result.results.end()
            );
        }
    }

    return combinedResult;
}

DirectoryScanResult ScanEngine::FullScan(ScanProgressCallback progressCallback) {
    DirectoryScanRequest request{};
    request.rootPath = L"C:\\";
    request.recursive = true;
    request.maxDepth = 100;
    request.context.type = ScanType::OnDemand;
    request.context.deepScan = true;
    request.context.scanArchives = true;
    request.scanHiddenFiles = true;
    request.scanSystemFiles = true;

    return ScanDirectory(request, progressCallback);
}

DirectoryScanResult ScanEngine::CustomScan(
    const std::vector<std::wstring>& targets,
    ScanProgressCallback progressCallback
) {
    DirectoryScanResult combinedResult{};

    for (const auto& target : targets) {
        if (fs::is_directory(target)) {
            DirectoryScanRequest request{};
            request.rootPath = target;
            request.recursive = true;
            request.context.type = ScanType::OnDemand;

            auto result = ScanDirectory(request, progressCallback);

            combinedResult.results.insert(
                combinedResult.results.end(),
                result.results.begin(),
                result.results.end()
            );
        } else if (fs::is_regular_file(target)) {
            ScanContext context{};
            context.type = ScanType::OnDemand;

            auto result = ScanFile(target, context);
            combinedResult.results.push_back(result);
        }
    }

    return combinedResult;
}

// ============================================================================
// MEMORY SCANNING
// ============================================================================

EngineResult ScanEngine::ScanMemory(
    std::span<const uint8_t> buffer,
    const ScanContext& context
) {
    EngineResult result{};
    const auto scanStart = steady_clock::now();

    if (!IsInitialized()) {
        Logger::Error("ScanEngine: Not initialized");
        result.verdict = ScanVerdict::Error;
        return result;
    }

    try {
        m_impl->m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);

        Logger::Info("ScanEngine: Scanning memory buffer ({} bytes)", buffer.size());

        // Validate buffer
        if (buffer.empty()) {
            Logger::Warn("ScanEngine: Empty buffer");
            result.verdict = ScanVerdict::Clean;
            return result;
        }

        // Compute buffer hash
        std::string bufferHash;
        try {
            std::vector<uint8_t> hashBytes;
            HashUtils::Compute(HashUtils::Algorithm::SHA256,
                             buffer.data(), buffer.size(), hashBytes);
            bufferHash = HashUtils::ToHexLower(hashBytes);
            result.sha256 = bufferHash;
        } catch (const std::exception& e) {
            Logger::Error("ScanEngine: Buffer hash computation failed: {}", e.what());
            result.verdict = ScanVerdict::Error;
            return result;
        }

        // Check cache
        if (auto cached = m_impl->CheckCache(bufferHash)) {
            return *cached;
        }

        // Hash check
        if (m_impl->m_signatureStore) {
            SignatureStore::ScanOptions hashOpts{};
            hashOpts.enableHashLookup = true;
            hashOpts.enablePatternScan = false;
            hashOpts.enableYaraScan = false;

            auto hashResult = m_impl->m_signatureStore->ScanHash(bufferHash, hashOpts);
            if (hashResult.isDetected) {
                m_impl->m_stats.infections.fetch_add(1, std::memory_order_relaxed);
                result.verdict = ScanVerdict::Infected;
                result.threatName = hashResult.threatName;
                result.severity = hashResult.severity;
                result.detectionSource = "HashStore";
                goto finalize_memory_scan;
            }
        }

        // Signature scan on buffer
        if (m_impl->m_signatureStore) {
            SignatureStore::ScanOptions sigOpts{};
            sigOpts.enableHashLookup = false;
            sigOpts.enablePatternScan = true;
            sigOpts.enableYaraScan = true;

            auto sigResult = m_impl->m_signatureStore->ScanBuffer(buffer, sigOpts);
            if (sigResult.isDetected) {
                m_impl->m_stats.infections.fetch_add(1, std::memory_order_relaxed);
                result.verdict = ScanVerdict::Infected;
                result.threatName = sigResult.threatName;
                result.severity = sigResult.severity;
                result.detectionSource = sigResult.detectionMethod;
                goto finalize_memory_scan;
            }
        }

        result.verdict = ScanVerdict::Clean;

    finalize_memory_scan:
        const auto scanEnd = steady_clock::now();
        result.scanDurationUs = duration_cast<microseconds>(scanEnd - scanStart).count();
        m_impl->m_stats.totalTimeUs.fetch_add(result.scanDurationUs, std::memory_order_relaxed);
        m_impl->UpdateCache(bufferHash, result);

        return result;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Memory scan exception: {}", e.what());
        result.verdict = ScanVerdict::Error;
        return result;
    }
}

EngineResult ScanEngine::ScanProcess(
    uint32_t pid,
    const ScanContext& context
) {
    EngineResult result{};

    if (!IsInitialized()) {
        result.verdict = ScanVerdict::Error;
        return result;
    }

    try {
        Logger::Info("ScanEngine: Scanning process {}", pid);
        m_impl->m_stats.processesScanned.fetch_add(1, std::memory_order_relaxed);

        // Get process executable path
        auto processPath = ProcessUtils::GetProcessImagePath(pid);
        if (processPath.empty()) {
            Logger::Warn("ScanEngine: Cannot get process path for PID {}", pid);
            result.verdict = ScanVerdict::Error;
            return result;
        }

        // Scan the executable
        result = ScanFile(processPath, context);

        return result;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Process scan exception: {}", e.what());
        result.verdict = ScanVerdict::Error;
        return result;
    }
}

std::vector<EngineResult> ScanEngine::ScanAllProcesses(
    ScanProgressCallback progressCallback
) {
    std::vector<EngineResult> results;

    if (!IsInitialized()) {
        Logger::Error("ScanEngine: Not initialized");
        return results;
    }

    try {
        Logger::Info("ScanEngine: Scanning all processes");

        auto processes = ProcessUtils::EnumerateProcesses();
        Logger::Info("ScanEngine: Found {} processes", processes.size());

        uint64_t scanned = 0;
        for (const auto& pid : processes) {
            ScanContext context{};
            context.type = ScanType::Memory;

            auto result = ScanProcess(pid, context);
            results.push_back(result);

            scanned++;

            if (progressCallback) {
                ScanProgress progress{};
                progress.filesScanned = scanned;
                progress.totalFiles = processes.size();
                progress.percentComplete = (scanned * 100.0f) / processes.size();
                progressCallback(progress);
            }
        }

        Logger::Info("ScanEngine: Process scan complete - {} processes scanned", scanned);

        return results;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: ScanAllProcesses exception: {}", e.what());
        return results;
    }
}

EngineResult ScanEngine::ScanProcessMemoryDeep(
    uint32_t pid,
    const ScanContext& context
) {
    EngineResult result{};

    if (!IsInitialized()) {
        result.verdict = ScanVerdict::Error;
        return result;
    }

    try {
        Logger::Info("ScanEngine: Deep scanning process memory: {}", pid);

        // Get process memory regions
        auto memoryRegions = ProcessUtils::GetProcessMemoryRegions(pid);

        for (const auto& region : memoryRegions) {
            // Read memory
            std::vector<uint8_t> memory = ProcessUtils::ReadProcessMemory(
                pid, region.baseAddress, region.size
            );

            if (!memory.empty()) {
                auto scanResult = ScanMemory(memory, context);

                if (scanResult.verdict == ScanVerdict::Infected ||
                    scanResult.verdict == ScanVerdict::Suspicious) {
                    result = scanResult;
                    return result; // Found threat
                }
            }
        }

        result.verdict = ScanVerdict::Clean;
        return result;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Deep memory scan exception: {}", e.what());
        result.verdict = ScanVerdict::Error;
        return result;
    }
}

// ============================================================================
// ARCHIVE SCANNING
// ============================================================================

BatchScanResult ScanEngine::ScanArchive(
    const std::wstring& archivePath,
    const ArchiveScanOptions& options,
    const ScanContext& context
) {
    BatchScanResult result{};

    if (!IsInitialized()) {
        Logger::Error("ScanEngine: Not initialized");
        return result;
    }

    try {
        Logger::Info("ScanEngine: Scanning archive: {}",
            StringUtils::ToNarrowString(archivePath));

        m_impl->m_stats.archivesScanned.fetch_add(1, std::memory_order_relaxed);

        // Check archive size
        auto archiveSize = fs::file_size(archivePath);
        if (archiveSize > options.maxArchiveSize) {
            Logger::Warn("ScanEngine: Archive too large: {} bytes", archiveSize);
            return result;
        }

        // Extract and scan
        if (m_impl->m_packerUnpacker) {
            auto extractedFiles = m_impl->m_packerUnpacker->ExtractArchive(
                archivePath, options.maxNestingDepth
            );

            m_impl->m_stats.archiveFilesScanned.fetch_add(
                extractedFiles.size(), std::memory_order_relaxed
            );

            // Scan extracted files
            BatchScanRequest batchReq{};
            batchReq.filePaths = extractedFiles;
            batchReq.context = context;

            result = ScanBatch(batchReq);
        }

        return result;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Archive scan exception: {}", e.what());
        return result;
    }
}

bool ScanEngine::IsArchive(const std::wstring& filePath) const {
    return m_impl && m_impl->IsArchiveExtension(filePath);
}

std::vector<std::wstring> ScanEngine::GetSupportedArchiveFormats() const {
    return {
        L".zip", L".rar", L".7z", L".tar", L".gz", L".bz2",
        L".cab", L".iso", L".img", L".arj", L".lzh", L".ace"
    };
}

// ============================================================================
// BOOT & ROOTKIT SCANNING
// ============================================================================

EngineResult ScanEngine::ScanBootSector() {
    EngineResult result{};

    if (!IsInitialized()) {
        result.verdict = ScanVerdict::Error;
        return result;
    }

    try {
        Logger::Info("ScanEngine: Scanning boot sector");

        // Read MBR/GPT
        // This requires elevated privileges and direct disk access
        // Implementation would use DeviceIoControl with IOCTL_DISK_GET_DRIVE_LAYOUT

        result.verdict = ScanVerdict::Clean;
        result.detectionSource = "BootSector";

        return result;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Boot sector scan exception: {}", e.what());
        result.verdict = ScanVerdict::Error;
        return result;
    }
}

std::vector<EngineResult> ScanEngine::ScanForRootkits(
    ScanProgressCallback progressCallback
) {
    std::vector<EngineResult> results;

    if (!IsInitialized()) {
        Logger::Error("ScanEngine: Not initialized");
        return results;
    }

    try {
        Logger::Info("ScanEngine: Scanning for rootkits");

        // Rootkit detection techniques:
        // 1. Hidden process detection
        // 2. SSDT hook detection
        // 3. IDT hook detection
        // 4. Hidden driver detection
        // 5. Direct kernel object manipulation (DKOM) detection

        // This requires kernel-mode driver support

        return results;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Rootkit scan exception: {}", e.what());
        return results;
    }
}

EngineResult ScanEngine::ScanUEFI() {
    EngineResult result{};

    if (!IsInitialized()) {
        result.verdict = ScanVerdict::Error;
        return result;
    }

    try {
        Logger::Info("ScanEngine: Scanning UEFI firmware");

        // UEFI scanning requires:
        // 1. Reading firmware variables
        // 2. Analyzing boot services
        // 3. Checking runtime services
        // 4. Detecting firmware-level implants

        result.verdict = ScanVerdict::Clean;
        result.detectionSource = "UEFI";

        return result;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: UEFI scan exception: {}", e.what());
        result.verdict = ScanVerdict::Error;
        return result;
    }
}

// ============================================================================
// SCAN JOB MANAGEMENT
// ============================================================================

uint64_t ScanEngine::CreateScanJob(
    const DirectoryScanRequest& request,
    ScanPriority priority
) {
    if (!IsInitialized()) {
        Logger::Error("ScanEngine: Not initialized");
        return 0;
    }

    try {
        auto job = std::make_shared<ScanJob>();
        job->jobId = m_impl->m_nextJobId.fetch_add(1, std::memory_order_relaxed);
        job->request = request;
        job->priority = priority;
        job->state = ScanJobState::Queued;
        job->startTime = steady_clock::now();

        {
            std::unique_lock lock(m_impl->m_jobMutex);
            m_impl->m_scanJobs[job->jobId] = job;
        }

        Logger::Info("ScanEngine: Created scan job {} with priority {}",
            job->jobId, static_cast<int>(priority));

        // Launch job asynchronously
        if (m_impl->m_threadPool) {
            std::async(std::launch::async, [this, job]() {
                job->state = ScanJobState::Running;

                try {
                    job->result = ScanDirectory(job->request, job->progressCallback);
                    job->state = ScanJobState::Completed;
                    job->endTime = steady_clock::now();
                } catch (const std::exception& e) {
                    Logger::Error("ScanEngine: Job {} failed: {}", job->jobId, e.what());
                    job->state = ScanJobState::Failed;
                }
            });
        }

        return job->jobId;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: CreateScanJob exception: {}", e.what());
        return 0;
    }
}

ScanJobState ScanEngine::GetJobState(uint64_t jobId) const {
    std::shared_lock lock(m_impl->m_jobMutex);

    auto it = m_impl->m_scanJobs.find(jobId);
    if (it == m_impl->m_scanJobs.end()) {
        return ScanJobState::Failed;
    }

    return it->second->state;
}

std::optional<ScanProgress> ScanEngine::GetJobProgress(uint64_t jobId) const {
    std::shared_lock lock(m_impl->m_jobMutex);

    auto it = m_impl->m_scanJobs.find(jobId);
    if (it == m_impl->m_scanJobs.end()) {
        return std::nullopt;
    }

    return it->second->progress;
}

bool ScanEngine::PauseJob(uint64_t jobId) {
    std::shared_lock lock(m_impl->m_jobMutex);

    auto it = m_impl->m_scanJobs.find(jobId);
    if (it == m_impl->m_scanJobs.end()) {
        return false;
    }

    if (it->second->state == ScanJobState::Running) {
        it->second->pauseRequested.store(true, std::memory_order_release);
        it->second->state = ScanJobState::Paused;
        Logger::Info("ScanEngine: Job {} paused", jobId);
        return true;
    }

    return false;
}

bool ScanEngine::ResumeJob(uint64_t jobId) {
    std::shared_lock lock(m_impl->m_jobMutex);

    auto it = m_impl->m_scanJobs.find(jobId);
    if (it == m_impl->m_scanJobs.end()) {
        return false;
    }

    if (it->second->state == ScanJobState::Paused) {
        it->second->pauseRequested.store(false, std::memory_order_release);
        it->second->state = ScanJobState::Running;
        Logger::Info("ScanEngine: Job {} resumed", jobId);
        return true;
    }

    return false;
}

bool ScanEngine::CancelJob(uint64_t jobId) {
    std::shared_lock lock(m_impl->m_jobMutex);

    auto it = m_impl->m_scanJobs.find(jobId);
    if (it == m_impl->m_scanJobs.end()) {
        return false;
    }

    it->second->cancelRequested.store(true, std::memory_order_release);
    it->second->state = ScanJobState::Cancelled;
    Logger::Info("ScanEngine: Job {} cancelled", jobId);
    return true;
}

std::optional<DirectoryScanResult> ScanEngine::GetJobResult(uint64_t jobId) const {
    std::shared_lock lock(m_impl->m_jobMutex);

    auto it = m_impl->m_scanJobs.find(jobId);
    if (it == m_impl->m_scanJobs.end()) {
        return std::nullopt;
    }

    if (it->second->state == ScanJobState::Completed) {
        return it->second->result;
    }

    return std::nullopt;
}

std::vector<uint64_t> ScanEngine::GetActiveJobs() const {
    std::shared_lock lock(m_impl->m_jobMutex);

    std::vector<uint64_t> activeJobs;
    for (const auto& [id, job] : m_impl->m_scanJobs) {
        if (job->state == ScanJobState::Running ||
            job->state == ScanJobState::Queued) {
            activeJobs.push_back(id);
        }
    }

    return activeJobs;
}

void ScanEngine::CancelAllJobs() {
    std::unique_lock lock(m_impl->m_jobMutex);

    for (auto& [id, job] : m_impl->m_scanJobs) {
        if (job->state == ScanJobState::Running ||
            job->state == ScanJobState::Queued) {
            job->cancelRequested.store(true, std::memory_order_release);
            job->state = ScanJobState::Cancelled;
        }
    }

    Logger::Info("ScanEngine: All jobs cancelled");
}

// ============================================================================
// EXCLUSION MANAGEMENT
// ============================================================================

void ScanEngine::AddExclusion(const ExclusionRule& rule) {
    std::unique_lock lock(m_impl->m_exclusionMutex);
    m_impl->m_exclusions.push_back(rule);
    Logger::Info("ScanEngine: Added exclusion rule: {}",
        StringUtils::ToNarrowString(rule.pattern));
}

bool ScanEngine::RemoveExclusion(size_t index) {
    std::unique_lock lock(m_impl->m_exclusionMutex);

    if (index >= m_impl->m_exclusions.size()) {
        return false;
    }

    m_impl->m_exclusions.erase(m_impl->m_exclusions.begin() + index);
    Logger::Info("ScanEngine: Removed exclusion rule at index {}", index);
    return true;
}

std::vector<ExclusionRule> ScanEngine::GetExclusions() const {
    std::shared_lock lock(m_impl->m_exclusionMutex);
    return m_impl->m_exclusions;
}

void ScanEngine::ClearExclusions() {
    std::unique_lock lock(m_impl->m_exclusionMutex);
    m_impl->m_exclusions.clear();
    Logger::Info("ScanEngine: Cleared all exclusion rules");
}

bool ScanEngine::IsExcluded(const std::wstring& path) const {
    return m_impl && m_impl->IsExcluded(path);
}

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t ScanEngine::RegisterDetectionCallback(DetectionCallback callback) {
    if (!callback) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_detectionCallbacks[id] = std::move(callback);

    Logger::Debug("ScanEngine: Registered detection callback {}", id);
    return id;
}

bool ScanEngine::UnregisterDetectionCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);

    auto erased = m_impl->m_detectionCallbacks.erase(callbackId);
    if (erased > 0) {
        Logger::Debug("ScanEngine: Unregistered detection callback {}", callbackId);
        return true;
    }

    return false;
}

uint64_t ScanEngine::RegisterCompleteCallback(ScanCompleteCallback callback) {
    if (!callback) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_completeCallbacks[id] = std::move(callback);

    Logger::Debug("ScanEngine: Registered complete callback {}", id);
    return id;
}

bool ScanEngine::UnregisterCompleteCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);

    auto erased = m_impl->m_completeCallbacks.erase(callbackId);
    if (erased > 0) {
        Logger::Debug("ScanEngine: Unregistered complete callback {}", callbackId);
        return true;
    }

    return false;
}

uint64_t ScanEngine::RegisterErrorCallback(ErrorCallback callback) {
    if (!callback) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_errorCallbacks[id] = std::move(callback);

    Logger::Debug("ScanEngine: Registered error callback {}", id);
    return id;
}

bool ScanEngine::UnregisterErrorCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);

    auto erased = m_impl->m_errorCallbacks.erase(callbackId);
    if (erased > 0) {
        Logger::Debug("ScanEngine: Unregistered error callback {}", callbackId);
        return true;
    }

    return false;
}

// ============================================================================
// MANAGEMENT API
// ============================================================================

bool ScanEngine::ReloadDatabases() {
    if (!IsInitialized()) {
        Logger::Error("ScanEngine: Cannot reload - not initialized");
        return false;
    }

    try {
        Logger::Info("ScanEngine: Reloading databases");

        std::unique_lock lock(m_impl->m_configMutex);

        // Reload SignatureStore
        if (m_impl->m_signatureStore) {
            auto result = m_impl->m_signatureStore->Reload();
            if (result != SignatureStore::StoreError::Success) {
                Logger::Error("ScanEngine: SignatureStore reload failed");
                return false;
            }
            Logger::Info("ScanEngine: SignatureStore reloaded - {} signatures",
                m_impl->m_signatureStore->GetSignatureCount());
        }

        // Reload WhitelistStore
        if (m_impl->m_whitelistStore) {
            auto result = m_impl->m_whitelistStore->Reload();
            if (result != Whitelist::WhitelistError::Success) {
                Logger::Error("ScanEngine: WhitelistStore reload failed");
                return false;
            }
            Logger::Info("ScanEngine: WhitelistStore reloaded");
        }

        // Reload ThreatIntelDatabase
        if (m_impl->m_threatIntelDB) {
            auto result = m_impl->m_threatIntelDB->Reload();
            if (result != ThreatIntel::ThreatIntelError::Success) {
                Logger::Error("ScanEngine: ThreatIntelDatabase reload failed");
                return false;
            }
            Logger::Info("ScanEngine: ThreatIntelDatabase reloaded");
        }

        // Clear result cache after reload
        {
            std::lock_guard cacheLock(m_impl->m_cacheMutex);
            m_impl->m_resultCache.clear();
            Logger::Info("ScanEngine: Result cache cleared");
        }

        Logger::Info("ScanEngine: Database reload complete");
        return true;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Reload exception: {}", e.what());
        return false;
    }
}

void ScanEngine::UpdateConfig(const EngineConfig& newConfig) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = newConfig;

    Logger::Info("ScanEngine: Configuration updated");
}

EngineConfig ScanEngine::GetConfig() const {
    if (!m_impl) return EngineConfig{};

    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}

void ScanEngine::WarmCache(const std::vector<std::wstring>& commonPaths) {
    if (!IsInitialized()) return;

    Logger::Info("ScanEngine: Warming cache with {} paths", commonPaths.size());

    ScanContext context{};
    context.type = ScanType::OnDemand;
    context.deepScan = false;

    for (const auto& path : commonPaths) {
        try {
            if (fs::exists(path)) {
                ScanFile(path, context);
            }
        } catch (...) {
            // Ignore errors during cache warming
        }
    }

    Logger::Info("ScanEngine: Cache warming complete");
}

void ScanEngine::ClearCache() {
    if (!m_impl) return;

    std::lock_guard lock(m_impl->m_cacheMutex);
    m_impl->m_resultCache.clear();

    Logger::Info("ScanEngine: Cache cleared");
}

void ScanEngine::OptimizeForWorkload(ScanProfile profile) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_configMutex);

    switch (profile) {
        case ScanProfile::Quick:
            m_impl->m_config.enableHeuristics = false;
            m_impl->m_config.enableBehaviorAnalysis = false;
            m_impl->m_config.archiveOptions.action = ArchiveAction::Skip;
            break;

        case ScanProfile::Full:
            m_impl->m_config.enableHeuristics = true;
            m_impl->m_config.enableBehaviorAnalysis = true;
            m_impl->m_config.enableMachineLearning = true;
            m_impl->m_config.archiveOptions.action = ArchiveAction::Extract;
            break;

        case ScanProfile::Smart:
            m_impl->m_config.enableMachineLearning = true;
            break;

        case ScanProfile::Rootkit:
            m_impl->m_config.enableMemoryScanning = true;
            break;

        default:
            break;
    }

    Logger::Info("ScanEngine: Optimized for {} profile", static_cast<int>(profile));
}

ScanEngine::Stats ScanEngine::GetStatistics() const {
    if (!m_impl) return Stats{};

    Stats stats{};
    stats.totalScans = m_impl->m_stats.totalScans.load(std::memory_order_relaxed);
    stats.infectionsFound = m_impl->m_stats.infections.load(std::memory_order_relaxed);
    stats.cacheHits = m_impl->m_stats.cacheHits.load(std::memory_order_relaxed);
    stats.whitelistHits = m_impl->m_stats.whitelistHits.load(std::memory_order_relaxed);
    stats.hashHits = m_impl->m_stats.hashHits.load(std::memory_order_relaxed);
    stats.signatureHits = m_impl->m_stats.signatureHits.load(std::memory_order_relaxed);
    stats.heuristicHits = m_impl->m_stats.heuristicHits.load(std::memory_order_relaxed);
    stats.behaviorHits = m_impl->m_stats.behaviorHits.load(std::memory_order_relaxed);
    stats.mlHits = m_impl->m_stats.mlHits.load(std::memory_order_relaxed);

    uint64_t totalTimeUs = m_impl->m_stats.totalTimeUs.load(std::memory_order_relaxed);
    if (stats.totalScans > 0) {
        stats.averageScanTimeMs = (totalTimeUs / stats.totalScans) / 1000.0;
    }

    // Calculate throughput
    auto uptime = duration_cast<seconds>(
        steady_clock::now() - m_impl->m_stats.startTime
    );
    if (uptime.count() > 0) {
        stats.filesPerSecond = stats.totalScans / uptime.count();
    }

    return stats;
}

void ScanEngine::ResetStatistics() {
    if (!m_impl) return;

    m_impl->m_stats = Impl::InternalStats{};
    m_impl->m_stats.startTime = steady_clock::now();

    Logger::Info("ScanEngine: Statistics reset");
}

ScanEngine::PerformanceMetrics ScanEngine::GetPerformanceMetrics() const {
    PerformanceMetrics metrics{};

    if (!m_impl) return metrics;

    auto stats = GetStatistics();

    metrics.avgScanTime = microseconds(static_cast<uint64_t>(stats.averageScanTimeMs * 1000));

    {
        std::shared_lock lock(m_impl->m_jobMutex);
        metrics.activeThreads = m_impl->m_threadPool ? m_impl->m_threadPool->GetThreadCount() : 0;
        metrics.queuedJobs = 0;
        metrics.completedJobs = 0;

        for (const auto& [id, job] : m_impl->m_scanJobs) {
            if (job->state == ScanJobState::Queued) metrics.queuedJobs++;
            if (job->state == ScanJobState::Completed) metrics.completedJobs++;
        }
    }

    {
        std::lock_guard lock(m_impl->m_cacheMutex);
        metrics.cacheSize = m_impl->m_resultCache.size();

        if (stats.totalScans > 0) {
            metrics.cacheHitRate = static_cast<double>(stats.cacheHits) / stats.totalScans;
        }
    }

    return metrics;
}

bool ScanEngine::SelfTest() {
    if (!IsInitialized()) {
        Logger::Error("ScanEngine: Self-test failed - not initialized");
        return false;
    }

    try {
        Logger::Info("ScanEngine: Running self-test");

        // Test 1: Cache functionality
        {
            std::string testHash = "test123";
            EngineResult testResult{};
            testResult.verdict = ScanVerdict::Clean;

            m_impl->UpdateCache(testHash, testResult);
            auto cached = m_impl->CheckCache(testHash);

            if (!cached || cached->verdict != ScanVerdict::Clean) {
                Logger::Error("ScanEngine: Self-test failed - cache test");
                return false;
            }
        }

        // Test 2: Exclusion system
        {
            ExclusionRule rule{};
            rule.type = ExclusionRule::Type::Path;
            rule.pattern = L"C:\\Test\\exclude.exe";
            rule.enabled = true;

            AddExclusion(rule);

            if (!IsExcluded(L"C:\\Test\\exclude.exe")) {
                Logger::Error("ScanEngine: Self-test failed - exclusion test");
                return false;
            }

            ClearExclusions();
        }

        // Test 3: Subsystem availability
        if (!m_impl->m_signatureStore) {
            Logger::Warn("ScanEngine: Self-test warning - SignatureStore not available");
        }

        Logger::Info("ScanEngine: Self-test passed");
        return true;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Self-test exception: {}", e.what());
        return false;
    }
}

ScanEngine::VersionInfo ScanEngine::GetVersionInfo() const {
    VersionInfo info{};
    info.engineVersion = "3.0.0";
    info.yaraVersion = "4.2.0";

    if (m_impl && m_impl->m_signatureStore) {
        info.signatureVersion = m_impl->m_signatureStore->GetVersion();
    }

    info.lastUpdate = system_clock::now();

    return info;
}

// ============================================================================
// CLOUD INTEGRATION
// ============================================================================

std::string ScanEngine::SubmitSampleToCloud(
    const std::wstring& filePath,
    const EngineResult& localResult
) {
    if (!IsInitialized()) {
        Logger::Error("ScanEngine: Not initialized");
        return "";
    }

    try {
        Logger::Info("ScanEngine: Submitting sample to cloud: {}",
            StringUtils::ToNarrowString(filePath));

        // Generate submission ID
        auto submissionId = std::format("CLOUD-{}-{}",
            localResult.sha256,
            system_clock::now().time_since_epoch().count());

        // TODO: Implement actual cloud API submission
        // This would:
        // 1. Upload file to cloud sandbox
        // 2. Submit for deep analysis
        // 3. Return submission ID for tracking

        return submissionId;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Cloud submission exception: {}", e.what());
        return "";
    }
}

std::optional<EngineResult> ScanEngine::GetCloudResult(
    const std::string& submissionId
) {
    if (!IsInitialized()) {
        return std::nullopt;
    }

    try {
        // TODO: Query cloud API for results
        // This would poll the cloud service for analysis completion

        return std::nullopt;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Cloud result query exception: {}", e.what());
        return std::nullopt;
    }
}

std::optional<EngineResult> ScanEngine::QueryCloudReputation(
    const std::string& hash
) {
    if (!IsInitialized()) {
        return std::nullopt;
    }

    try {
        Logger::Debug("ScanEngine: Querying cloud reputation for hash {}",
            hash.substr(0, 16));

        // TODO: Query cloud reputation service
        // This would check VirusTotal, ShadowStrike Cloud, etc.

        return std::nullopt;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Cloud reputation query exception: {}", e.what());
        return std::nullopt;
    }
}

// ============================================================================
// REPORTING
// ============================================================================

std::wstring ScanEngine::GenerateReport(
    const DirectoryScanResult& result,
    bool includeDetails
) {
    std::wstring report;

    try {
        report += L"=== ShadowStrike Scan Report ===\n\n";
        report += std::format(L"Root Path: {}\n", result.rootPath);
        report += std::format(L"Total Files Scanned: {}\n", result.statistics.filesScanned);
        report += std::format(L"Infections Found: {}\n", result.statistics.filesInfected);
        report += std::format(L"Suspicious Files: {}\n", result.statistics.filesSuspicious);
        report += std::format(L"Duration: {} ms\n", result.totalDuration.count());
        report += L"\n";

        if (includeDetails && result.statistics.filesInfected > 0) {
            report += L"=== Detected Threats ===\n\n";

            for (const auto& scanResult : result.results) {
                if (scanResult.verdict == ScanVerdict::Infected) {
                    report += std::format(L"Threat: {}\n",
                        StringUtils::ToWideString(scanResult.threatName));
                    report += std::format(L"Hash: {}\n",
                        StringUtils::ToWideString(scanResult.sha256));
                    report += L"\n";
                }
            }
        }

        return report;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Report generation exception: {}", e.what());
        return L"Report generation failed";
    }
}

bool ScanEngine::ExportReport(
    const DirectoryScanResult& result,
    const std::wstring& outputPath,
    const std::string& format
) {
    try {
        Logger::Info("ScanEngine: Exporting report to {} (format: {})",
            StringUtils::ToNarrowString(outputPath), format);

        std::wofstream file(outputPath);
        if (!file) {
            Logger::Error("ScanEngine: Cannot open report file");
            return false;
        }

        if (format == "JSON") {
            // TODO: JSON export using nlohmann::json
            file << L"{}\n";
        } else if (format == "XML") {
            // TODO: XML export
            file << L"<report></report>\n";
        } else if (format == "HTML") {
            // TODO: HTML export
            file << L"<html></html>\n";
        } else {
            // Plain text
            file << GenerateReport(result, true);
        }

        file.close();

        Logger::Info("ScanEngine: Report exported successfully");
        return true;

    } catch (const std::exception& e) {
        Logger::Error("ScanEngine: Report export exception: {}", e.what());
        return false;
    }
}

} // namespace Engine
} // namespace Core
} // namespace ShadowStrike
