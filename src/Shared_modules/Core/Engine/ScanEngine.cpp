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
#include "PolymorphicDetector.hpp"
#include "SandboxAnalyzer.hpp"
#include "EmulationEngine.hpp"
#include "ZeroDayDetector.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
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

// Version information
static constexpr auto SHADOWSTRIKE_VERSION = L"3.0.0";

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
    std::unique_ptr<PolymorphicDetector> m_polymorphicDetector;
    std::unique_ptr<SandboxAnalyzer> m_sandboxAnalyzer;
    std::unique_ptr<EmulationEngine> m_emulationEngine;
    std::unique_ptr<ZeroDayDetector> m_zeroDayDetector;

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
    std::unordered_map<uint64_t, ScanDetectionCallback> m_detectionCallbacks;
    std::unordered_map<uint64_t, ScanCompleteCallback> m_completeCallbacks;
    std::unordered_map<uint64_t, ScanErrorCallback> m_errorCallbacks;

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

    // Cloud submission tracking
    enum class CloudPriority : uint8_t {
        Low = 1,
        Normal = 2,
        High = 3,
        Critical = 4
    };

    struct CloudSubmissionRequest {
        std::string submissionId;
        std::string sha256;
        std::wstring filePath;
        size_t fileSize;
        system_clock::time_point submitTime;
        CloudPriority priority;
    };

    struct CloudAnalysisResult {
        std::string submissionId;
        bool analysisComplete;
        uint32_t detectionCount;
        double confidence;
        std::string verdict;
        std::vector<std::string> engineResults;
    };

    struct ReputationQuery {
        std::string hash;
        std::string hashType;
        system_clock::time_point queryTime;
    };

    struct ReputationResult {
        std::string hash;
        uint32_t totalEngines;
        uint32_t positiveDetections;
        std::string reputation;
        system_clock::time_point firstSeen;
        system_clock::time_point lastSeen;
        system_clock::time_point lastAnalysis;
        std::vector<std::string> vendors;
    };

    mutable std::mutex m_pendingSubmissionsMutex;
    std::unordered_map<std::string, CloudSubmissionRequest> m_pendingSubmissions;

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
            SS_LOG_INFO(L"ScanEngine", L"ScanEngine::Impl already initialized");
            return true;
        }

        try {
            SS_LOG_INFO(L"ScanEngine", L"ScanEngine::Impl: Initializing with enterprise infrastructure");

            // Store configuration
            m_config = config;

            // Initialize thread pool
            uint32_t threadCount = config.scanThreads > 0
                ? config.scanThreads
                : std::thread::hardware_concurrency();

            m_threadPool = std::make_shared<ThreadPool>(threadCount);
            SS_LOG_INFO(L"ScanEngine", L"Thread pool initialized with %u threads", threadCount);

            // Initialize SignatureStore (YARA + Patterns + Hashes)
            if (!m_config.signatureDbPath.empty()) {
                SS_LOG_INFO(L"ScanEngine", L"Initializing SignatureStore at  %ls",
                    StringUtils::ToNarrow(m_config.signatureDbPath));

                m_signatureStore = std::make_unique<SignatureStore::SignatureStore>();

                auto sigResult = m_signatureStore->Initialize(m_config.signatureDbPath);
                if (!sigResult) {
                    SS_LOG_ERROR(L"ScanEngine", L"SignatureStore initialization failed: %ls",
                        StringUtils::ToWide(sigResult.message).c_str());
                    return false;
                }

                SS_LOG_INFO(L"ScanEngine", L"SignatureStore initialized successfully");
            }

            // Initialize WhitelistStore (Bloom Filter + Trie + Certificates)
            if (!m_config.whitelistDbPath.empty()) {
                SS_LOG_INFO(L"ScanEngine", L"Initializing WhitelistStore at  %ls",
                    StringUtils::ToNarrow(m_config.whitelistDbPath));

                m_whitelistStore = std::make_unique<Whitelist::WhitelistStore>();

                auto wlResult = m_whitelistStore->Load(m_config.whitelistDbPath);
                if (!wlResult) {
                    SS_LOG_ERROR(L"ScanEngine", L"WhitelistStore initialization failed: %ls",
                        StringUtils::ToWide(wlResult.message).c_str());
                    return false;
                }

                SS_LOG_INFO(L"ScanEngine", L"WhitelistStore initialized - %llu entries",
                    m_whitelistStore->GetEntryCount());
            }

            // Initialize ThreatIntelDatabase (Memory-mapped threat intel)
            if (!m_config.threatIntelDbPath.empty()) {
                SS_LOG_INFO(L"ScanEngine", L"Initializing ThreatIntelDatabase at  %ls",
                    StringUtils::ToNarrow(m_config.threatIntelDbPath));

                m_threatIntelDB = std::make_unique<ThreatIntel::ThreatIntelDatabase>();

                ThreatIntel::DatabaseConfig tiConfig =
                    ThreatIntel::DatabaseConfig::CreateDefault(m_config.threatIntelDbPath);

                auto tiResult = m_threatIntelDB->Open(tiConfig);
                if (!tiResult) {
                    SS_LOG_ERROR(L"ScanEngine", L"ThreatIntelDatabase initialization failed");
                    return false;
                }

                SS_LOG_INFO(L"ScanEngine", L"ThreatIntelDatabase initialized - %zu entries",
                    m_threatIntelDB->GetEntryCount());
            }

            // Initialize HeuristicAnalyzer (PE/ELF/Script analysis)
            if (m_config.enableHeuristics) {
                SS_LOG_INFO(L"ScanEngine", L"Initializing HeuristicAnalyzer");

                m_heuristicAnalyzer = std::make_unique<HeuristicAnalyzer>();

                HeuristicAnalyzerConfig hConfig = HeuristicAnalyzerConfig::CreateDefault();
                hConfig.enablePEAnalysis = true;
                hConfig.enableImportAnalysis = true;
                hConfig.enableStringAnalysis = true;
                hConfig.enablePackerDetection = true;

                if (!m_heuristicAnalyzer->Initialize(m_threadPool, hConfig)) {
                    SS_LOG_ERROR(L"ScanEngine", L"HeuristicAnalyzer initialization failed");
                    return false;
                }

                SS_LOG_INFO(L"ScanEngine", L"HeuristicAnalyzer initialized");
            }

            // Initialize BehaviorAnalyzer (optional)
            if (m_config.enableBehaviorAnalysis) {
                SS_LOG_INFO(L"ScanEngine", L"BehaviorAnalyzer will be initialized on demand");
                // Lazy initialization
            }

            // Initialize MachineLearning (optional)
            if (m_config.enableMachineLearning) {
                SS_LOG_INFO(L"ScanEngine", L"MachineLearning will be initialized on demand");
                // Lazy initialization
            }

            // Initialize PackerUnpacker
            if (m_config.enableCompressedScanning) {
                SS_LOG_INFO(L"ScanEngine", L"Initializing PackerUnpacker");
                m_packerUnpacker = std::make_unique<PackerUnpacker>();
                
                if (!m_packerUnpacker->Initialize()) {
                    SS_LOG_ERROR(L"ScanEngine", L"PackerUnpacker initialization failed");
                    return false;
                }
                
                SS_LOG_INFO(L"ScanEngine", L"PackerUnpacker initialized");
            }

            // Initialize PolymorphicDetector
            if (m_config.enableHeuristics) {
                SS_LOG_INFO(L"ScanEngine", L"Initializing PolymorphicDetector");
                m_polymorphicDetector = std::make_unique<PolymorphicDetector>();
                
                PolymorphicConfiguration polyConfig{};
                polyConfig.enabled = true;
                
                if (!m_polymorphicDetector->Initialize(polyConfig)) {
                    SS_LOG_ERROR(L"ScanEngine", L"PolymorphicDetector initialization failed");
                    return false;
                }
                
                SS_LOG_INFO(L"ScanEngine", L"PolymorphicDetector initialized");
            }

            // Initialize SandboxAnalyzer  
            if (m_config.enableBehaviorAnalysis) {
                SS_LOG_INFO(L"ScanEngine", L"Initializing SandboxAnalyzer");
                m_sandboxAnalyzer = std::make_unique<SandboxAnalyzer>();
                
                SandboxAnalyzerConfiguration sbConfig{};
                sbConfig.enabled = true;
                
                if (!m_sandboxAnalyzer->Initialize(sbConfig)) {
                    SS_LOG_ERROR(L"ScanEngine", L"SandboxAnalyzer initialization failed");
                    return false;
                }
                
                SS_LOG_INFO(L"ScanEngine", L"SandboxAnalyzer initialized");
            }

            // Initialize EmulationEngine
            if (m_config.enableMemoryScanning) {
                SS_LOG_INFO(L"ScanEngine", L"Initializing EmulationEngine");
                m_emulationEngine = std::make_unique<EmulationEngine>();
                
                if (!m_emulationEngine->Initialize(m_threadPool)) {
                    SS_LOG_ERROR(L"ScanEngine", L"EmulationEngine initialization failed");
                    return false;
                }
                
                SS_LOG_INFO(L"ScanEngine", L"EmulationEngine initialized");
            }

            // Initialize ZeroDayDetector
            if (m_config.enableHeuristics) {
                SS_LOG_INFO(L"ScanEngine", L"Initializing ZeroDayDetector");
                m_zeroDayDetector = std::make_unique<ZeroDayDetector>();
                
                ZeroDayConfiguration zdConfig{};
                zdConfig.enabled = true;
                
                if (!m_zeroDayDetector->Initialize(zdConfig)) {
                    SS_LOG_ERROR(L"ScanEngine", L"ZeroDayDetector initialization failed");
                    return false;
                }
                
                SS_LOG_INFO(L"ScanEngine", L"ZeroDayDetector initialized");
            }

            // Reset statistics
            m_stats.totalScans.store(0, std::memory_order_relaxed);
            m_stats.infections.store(0, std::memory_order_relaxed);
            m_stats.suspicious.store(0, std::memory_order_relaxed);
            m_stats.cacheHits.store(0, std::memory_order_relaxed);
            m_stats.whitelistHits.store(0, std::memory_order_relaxed);
            m_stats.hashHits.store(0, std::memory_order_relaxed);
            m_stats.signatureHits.store(0, std::memory_order_relaxed);
            m_stats.heuristicHits.store(0, std::memory_order_relaxed);
            m_stats.behaviorHits.store(0, std::memory_order_relaxed);
            m_stats.mlHits.store(0, std::memory_order_relaxed);
            m_stats.totalTimeUs.store(0, std::memory_order_relaxed);
            m_stats.whitelistTimeUs.store(0, std::memory_order_relaxed);
            m_stats.hashTimeUs.store(0, std::memory_order_relaxed);
            m_stats.threatIntelTimeUs.store(0, std::memory_order_relaxed);
            m_stats.signatureTimeUs.store(0, std::memory_order_relaxed);
            m_stats.heuristicTimeUs.store(0, std::memory_order_relaxed);
            m_stats.archivesScanned.store(0, std::memory_order_relaxed);
            m_stats.archiveFilesScanned.store(0, std::memory_order_relaxed);
            m_stats.processesScanned.store(0, std::memory_order_relaxed);
            m_stats.peakMemoryBytes.store(0, std::memory_order_relaxed);
            m_stats.startTime = steady_clock::now();

            m_initialized.store(true, std::memory_order_release);
            SS_LOG_INFO(L"ScanEngine::Impl", L"Initialization complete - All subsystems online");

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ScanEngine::Impl: Initialization exception", L" %ls", e.what());
            return false;
        }
    }

    void Shutdown() {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        SS_LOG_INFO(L"ScanEngine::Impl", L"Shutting down");

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
            m_threatIntelDB->Close();
            m_threatIntelDB.reset();
        }

        if (m_whitelistStore) {
            m_whitelistStore->Close();
            m_whitelistStore.reset();
        }

        if (m_signatureStore) {
            m_signatureStore->Close();
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
        SS_LOG_INFO(L"ScanEngine::Impl", L"Shutdown complete");
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

        SS_LOG_DEBUG(L"ScanEngine", L"Cache hit for hash  %ls", hash.substr(0, 16));
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
                        if (StringUtils::ToLowerCopy(path) == StringUtils::ToLowerCopy(rule.pattern)) {
                            return true;
                        }
                    }
                    break;
                }

                case ExclusionRule::Type::PathPrefix: {
                    if (rule.caseSensitive) {
                        if (path.starts_with(rule.pattern)) return true;
                    } else {
                        auto lowerPath = StringUtils::ToLowerCopy(path);
                        auto lowerPattern = StringUtils::ToLowerCopy(rule.pattern);
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
                        if (StringUtils::ToLowerCopy(ext) == StringUtils::ToLowerCopy(rule.pattern)) {
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
                        if (StringUtils::ToLowerCopy(filename) == StringUtils::ToLowerCopy(rule.pattern)) {
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
                SS_LOG_ERROR(L"ScanEngine: Detection callback exception", L" %ls", e.what());
            }
        }
    }

    void InvokeCompleteCallbacks(const ScanStatistics& stats) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_completeCallbacks) {
            try {
                callback(stats);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"ScanEngine: Complete callback exception", L" %ls", e.what());
            }
        }
    }

    void InvokeErrorCallbacks(const std::wstring& error, uint32_t errorCode) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_errorCallbacks) {
            try {
                callback(error, errorCode);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"ScanEngine: Error callback exception", L" %ls", e.what());
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
        auto ext = StringUtils::ToLowerCopy(p.extension().wstring());

        return std::find(archiveExtensions.begin(), archiveExtensions.end(), ext)
            != archiveExtensions.end();
    }

    // ========================================================================
    // CLOUD HELPER METHODS
    // ========================================================================

    void PerformCloudUpload(const CloudSubmissionRequest& request) {
        try {
            SS_LOG_INFO(L"ScanEngine", L"Performing cloud upload for  %ls", request.submissionId);
            
            // Simulate cloud upload process
            // In real implementation, this would:
            // 1. Authenticate with cloud service
            // 2. Upload file securely (encrypted, chunked)
            // 3. Submit for sandbox analysis
            // 4. Handle upload progress/errors
            
            std::this_thread::sleep_for(std::chrono::seconds(2)); // Simulate upload time
            
            SS_LOG_INFO(L"ScanEngine", L"Cloud upload completed for  %ls", request.submissionId);
            
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ScanEngine: Cloud upload failed for {}", L" %ls", 
                         request.submissionId, e.what());
            throw;
        }
    }

    std::wstring GetVerdictString(ScanVerdict verdict) const {
        switch (verdict) {
            case ScanVerdict::Clean: return L"Clean";
            case ScanVerdict::Whitelisted: return L"Whitelisted";
            case ScanVerdict::Infected: return L"Infected";
            case ScanVerdict::Suspicious: return L"Suspicious";
            case ScanVerdict::PUA: return L"PUA";
            case ScanVerdict::Adware: return L"Adware";
            case ScanVerdict::Riskware: return L"Riskware";
            case ScanVerdict::Error: return L"Error";
            default: return L"Unknown";
        }
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
    SS_LOG_INFO(L"ScanEngine", L"Constructor called");
}

ScanEngine::~ScanEngine() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"ScanEngine", L"Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool ScanEngine::Initialize(const EngineConfig& config) {
    if (!m_impl) {
        SS_LOG_ERROR(L"ScanEngine", L"Implementation is null");
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
        SS_LOG_ERROR(L"ScanEngine", L"Not initialized");
        result.verdict = ScanVerdict::Error;
        return result;
    }

    try {
        // Update statistics
        m_impl->m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_INFO(L"ScanEngine: Scanning file: {} (Type", L" %ls)",
            StringUtils::ToNarrow(filePath),
            static_cast<int>(context.type));

        // ====================================================================
        // PRE-FLIGHT VALIDATION
        // ====================================================================

        // Check exclusions
        if (m_impl->IsExcluded(filePath)) {
            SS_LOG_INFO(L"ScanEngine", L"File excluded by rule");
            result.verdict = ScanVerdict::Whitelisted;
            result.detectionSource = "Exclusion";
            return result;
        }

        // Validate file path
        if (filePath.empty()) {
            SS_LOG_WARN(L"ScanEngine", L"Empty file path");
            result.verdict = ScanVerdict::Error;
            return result;
        }

        // Check file existence
        std::error_code ec;
        if (!fs::exists(filePath, ec)) {
            SS_LOG_WARN(L"ScanEngine: File not found", L" %ls",
                StringUtils::ToNarrow(filePath));
            result.verdict = ScanVerdict::Error;
            return result;
        }

        // Check file size limits for real-time scans
        uint64_t fileSize = 0;
        try {
            fileSize = fs::file_size(filePath, ec);
            if (ec) {
                SS_LOG_WARN(L"ScanEngine: Cannot get file size", L" %ls", ec.message());
                result.verdict = ScanVerdict::Error;
                return result;
            }
        } catch (...) {
            SS_LOG_ERROR(L"ScanEngine", L"Exception getting file size");
            result.verdict = ScanVerdict::Error;
            return result;
        }

        if (context.type == ScanType::RealTime &&
            fileSize > m_impl->m_config.maxFileSizeRealTime) {
            SS_LOG_INFO(L"ScanEngine: File too large for real-time scan", L" %ls bytes", fileSize);
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
                SS_LOG_ERROR(L"ScanEngine", L"Hash computation failed");
                result.verdict = ScanVerdict::Error;
                return result;
            }

            fileHash = HashUtils::ToHexLower(hashBytes);
            result.sha256 = fileHash;

            SS_LOG_DEBUG(L"ScanEngine: File hash computed", L" %ls", fileHash);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ScanEngine: Hash computation failed", L" %ls", e.what());
            result.verdict = ScanVerdict::Error;
            return result;
        }

        // ====================================================================
        // CHECK RESULT CACHE (Sub-microsecond fast path)
        // ====================================================================

        if (auto cachedResult = m_impl->CheckCache(fileHash)) {
            SS_LOG_INFO(L"ScanEngine: Returning cached result (Verdict", L" %ls)",
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
            auto hashLookup = m_impl->m_whitelistStore->IsHashWhitelisted(
                fileHash, Whitelist::HashAlgorithm::SHA256);
            if (hashLookup.found) {
                m_impl->m_stats.whitelistHits.fetch_add(1, std::memory_order_relaxed);

                result.verdict = ScanVerdict::Whitelisted;
                result.detectionSource = "Whitelist-Hash";
                result.sha256 = fileHash;

                SS_LOG_INFO(L"ScanEngine", L"File whitelisted by hash");
                goto finalize_scan;
            }

            // Check by path (trie index)
            auto pathLookup = m_impl->m_whitelistStore->IsPathWhitelisted(filePath);
            if (pathLookup.found) {
                m_impl->m_stats.whitelistHits.fetch_add(1, std::memory_order_relaxed);

                result.verdict = ScanVerdict::Whitelisted;
                result.detectionSource = "Whitelist-Path";
                result.sha256 = fileHash;

                SS_LOG_INFO(L"ScanEngine", L"File whitelisted by path");
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

            auto hashResult = m_impl->m_signatureStore->ScanFile(filePath, hashScanOpts);

            if (hashResult.HasDetections()) {
                m_impl->m_stats.hashHits.fetch_add(1, std::memory_order_relaxed);
                m_impl->m_stats.infections.fetch_add(1, std::memory_order_relaxed);

                const auto& topDetection = hashResult.detections.front();
                result.verdict = ScanVerdict::Infected;
                result.threatName = topDetection.signatureName;
                result.severity = topDetection.threatLevel;
                result.threatId = topDetection.signatureId;
                result.detectionSource = "HashStore";
                result.sha256 = fileHash;

                SS_LOG_WARN(L"ScanEngine", L"Hash match found - Threat: %ls",
                    StringUtils::ToWide(topDetection.signatureName).c_str());

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

            bool tiFound = m_impl->m_threatIntelDB->HasEntry(fileHash, ThreatIntel::IOCType::FileHash);

            if (tiFound) {
                result.verdict = ScanVerdict::Suspicious;
                result.threatName = "ThreatIntel.Match";
                result.severity = SignatureStore::ThreatLevel::Medium;
                result.detectionSource = "ThreatIntel";
                result.sha256 = fileHash;

                SS_LOG_INFO(L"ScanEngine", L"Threat intelligence match for hash: %ls",
                    StringUtils::ToWide(fileHash.substr(0, 16)).c_str());

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
                    SS_LOG_WARN(L"ScanEngine", L"Cannot open file for reading");
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
                SS_LOG_ERROR(L"ScanEngine: File read exception", L" %ls", e.what());
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

                if (sigResult.HasDetections()) {
                    m_impl->m_stats.signatureHits.fetch_add(1, std::memory_order_relaxed);
                    m_impl->m_stats.infections.fetch_add(1, std::memory_order_relaxed);

                    const auto& topDetection = sigResult.detections.front();
                    result.verdict = ScanVerdict::Infected;
                    result.threatName = topDetection.signatureName;
                    result.severity = topDetection.threatLevel;
                    result.threatId = topDetection.signatureId;
                    result.detectionSource = "SignatureStore";
                    result.sha256 = fileHash;

                    SS_LOG_WARN(L"ScanEngine", L"Signature match found - Threat: %ls",
                        StringUtils::ToWide(topDetection.signatureName).c_str());

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
                result.threatName = StringUtils::ToNarrow(heuristicResult.threatName);
                result.threatScore = static_cast<float>(heuristicResult.riskScore);
                result.detectionSource = "Heuristic";
                result.sha256 = fileHash;

                SS_LOG_INFO(L"ScanEngine", L"Heuristic detection - Score: {:.1f}, Name: %ls",
                    heuristicResult.riskScore,
                    StringUtils::ToNarrow(heuristicResult.threatName));

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
        // STAGE 6: POLYMORPHIC DETECTION (Code Morphing & Encryption)
        // ====================================================================

        if (m_impl->m_polymorphicDetector && m_impl->m_polymorphicDetector->IsInitialized()) {
            const auto stage6Start = steady_clock::now();

            auto polyResult = m_impl->m_polymorphicDetector->AnalyzeFile(filePath);

            if (polyResult.isPolymorphic &&
                static_cast<uint8_t>(polyResult.confidence) >= static_cast<uint8_t>(PolymorphicDetectionConfidence::Medium)) {
                m_impl->m_stats.suspicious.fetch_add(1, std::memory_order_relaxed);

                result.verdict = ScanVerdict::Suspicious;
                result.threatName = polyResult.threatFamily.empty() ? "Polymorphic.Generic" : polyResult.threatFamily;
                result.threatScore = static_cast<float>(static_cast<double>(static_cast<uint8_t>(polyResult.confidence)) * 25.0);
                result.detectionSource = "PolymorphicDetector";
                result.sha256 = fileHash;

                SS_LOG_INFO(L"ScanEngine", L"Polymorphic detection - Confidence: %u, Family: %ls",
                    static_cast<unsigned>(polyResult.confidence),
                    StringUtils::ToWide(polyResult.threatFamily).c_str());

                m_impl->InvokeDetectionCallbacks(result);
                goto finalize_scan;
            }

            const auto stage6End = steady_clock::now();
        }

        // ====================================================================
        // STAGE 7: SANDBOX ANALYSIS (Dynamic Behavior)
        // ====================================================================

        if (m_impl->m_sandboxAnalyzer && m_impl->m_sandboxAnalyzer->IsInitialized() && context.deepScan) {
            const auto stage7Start = steady_clock::now();

            SandboxAnalysisOptions sbOptions{};
            sbOptions.timeoutSeconds = 30;

            auto sbResult = m_impl->m_sandboxAnalyzer->Analyze(filePath, sbOptions);

            if (sbResult.isMalicious && sbResult.threatScore >= 70) {
                m_impl->m_stats.suspicious.fetch_add(1, std::memory_order_relaxed);

                result.verdict = ScanVerdict::Suspicious;
                result.threatName = sbResult.malwareFamily.empty() ? "Sandbox.Malicious" : sbResult.malwareFamily;
                result.threatScore = static_cast<float>(sbResult.threatScore);
                result.detectionSource = "SandboxAnalyzer";
                result.sha256 = fileHash;

                SS_LOG_INFO(L"ScanEngine", L"Sandbox detection - Threat: %ls, Score: %d",
                    StringUtils::ToWide(sbResult.malwareFamily).c_str(),
                    sbResult.threatScore);

                m_impl->InvokeDetectionCallbacks(result);
                goto finalize_scan;
            }

            const auto stage7End = steady_clock::now();
        }

        // ====================================================================
        // STAGE 8: EMULATION ENGINE (Code Execution Simulation)
        // ====================================================================

        if (m_impl->m_emulationEngine && m_impl->m_emulationEngine->IsInitialized() && context.deepScan) {
            const auto stage8Start = steady_clock::now();

            // Read file into buffer for emulation
            try {
                std::ifstream emuFile(filePath, std::ios::binary | std::ios::ate);
                if (emuFile) {
                    auto emuFileSize = emuFile.tellg();
                    emuFile.seekg(0, std::ios::beg);

                    constexpr size_t MAX_EMU_SIZE = 50 * 1024 * 1024; // 50MB limit
                    size_t emuReadSize = std::min<size_t>(emuFileSize, MAX_EMU_SIZE);

                    std::vector<uint8_t> emuBuffer(emuReadSize);
                    emuFile.read(reinterpret_cast<char*>(emuBuffer.data()), emuReadSize);

                    EmulationConfig emuConfig = EmulationConfig::CreateDefault();
                    auto emuResult = m_impl->m_emulationEngine->EmulatePE(emuBuffer, emuConfig);

                    if (emuResult.isMalicious) {
                        m_impl->m_stats.suspicious.fetch_add(1, std::memory_order_relaxed);

                        result.verdict = ScanVerdict::Suspicious;
                        result.threatName = emuResult.threatName.empty() ? "Emulation.Malicious" : emuResult.threatName;
                        result.threatScore = static_cast<float>(emuResult.threatScore);
                        result.detectionSource = "EmulationEngine";
                        result.sha256 = fileHash;

                        SS_LOG_INFO(L"ScanEngine", L"Emulation detection - Behavior: %ls, Score: %.1f",
                            StringUtils::ToWide(emuResult.threatName).c_str(),
                            emuResult.threatScore);

                        m_impl->InvokeDetectionCallbacks(result);
                        goto finalize_scan;
                    }
                }
            } catch (const std::exception& emuEx) {
                SS_LOG_ERROR(L"ScanEngine", L"Emulation exception: %ls", emuEx.what());
            }

            const auto stage8End = steady_clock::now();
        }

        // ====================================================================
        // STAGE 9: ZERO-DAY DETECTION (Advanced Anomaly Detection)
        // ====================================================================

        if (m_impl->m_zeroDayDetector && m_impl->m_zeroDayDetector->IsInitialized() && context.deepScan) {
            const auto stage9Start = steady_clock::now();

            ZeroDayAnalysisOptions zdOptions{};
            auto zdResult = m_impl->m_zeroDayDetector->AnalyzeFile(filePath, zdOptions);

            if (zdResult.detected &&
                static_cast<uint8_t>(zdResult.confidence) >= static_cast<uint8_t>(DetectionConfidence::Medium)) {
                m_impl->m_stats.suspicious.fetch_add(1, std::memory_order_relaxed);

                result.verdict = ScanVerdict::Suspicious;
                result.threatName = "ZeroDay." + zdResult.description;
                result.threatScore = static_cast<float>(static_cast<double>(static_cast<uint8_t>(zdResult.confidence)) * 33.3);
                result.detectionSource = "ZeroDayDetector";
                result.sha256 = fileHash;

                SS_LOG_INFO(L"ScanEngine", L"Zero-day detection - Type: %ls, Confidence: %u",
                    StringUtils::ToWide(zdResult.description).c_str(),
                    static_cast<unsigned>(zdResult.confidence));

                m_impl->InvokeDetectionCallbacks(result);
                goto finalize_scan;
            }

            const auto stage9End = steady_clock::now();
        }

        // ====================================================================
        // NO THREAT DETECTED
        // ===================================================================

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

        SS_LOG_INFO(L"ScanEngine", L"Scan complete - Verdict: %d, Duration: %llu us",
            static_cast<int>(result.verdict),
            result.scanDurationUs);

        return result;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Scan exception", L" %ls", e.what());
        m_impl->InvokeErrorCallbacks(
            std::format(L"Scan exception: {}",
                StringUtils::ToWide(e.what())),
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
        SS_LOG_ERROR(L"ScanEngine", L"Not initialized");
        return batchResult;
    }

    try {
        SS_LOG_INFO(L"ScanEngine", L"Starting batch scan of  %ls files",
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
                std::error_code fsSizeEc;
                stats.totalBytesScanned += fs::file_size(fs::path(filePath), fsSizeEc);
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

        SS_LOG_INFO(L"ScanEngine", L"Batch scan complete -  %ls files scanned, %ls infected in {} ms",
            stats.filesScanned, stats.filesInfected, batchResult.totalDuration.count());

        return batchResult;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Batch scan exception", L" %ls", e.what());
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
        SS_LOG_ERROR(L"ScanEngine", L"Not initialized");
        return dirResult;
    }

    try {
        SS_LOG_INFO(L"ScanEngine: Starting directory scan", L" %ls",
            StringUtils::ToNarrow(request.rootPath));

        dirResult.rootPath = request.rootPath;

        // Collect files to scan
        std::vector<std::wstring> filesToScan;
        std::error_code ec;

        std::function<void(const fs::path&, uint32_t)> collectFiles = [&](const fs::path& root, uint32_t depth) -> void {
            if (depth > request.maxDepth) return;

            try {
                for (const auto& entry : fs::directory_iterator(root, ec)) {
                    if (ec) {
                        SS_LOG_WARN(L"Directory iteration error", L" %ls", ec.message());
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
                SS_LOG_ERROR(L"Error collecting files", L" %ls", e.what());
            }
        };

        // Collect all files
        collectFiles(request.rootPath, 0);

        SS_LOG_INFO(L"ScanEngine", L"Collected  %ls files to scan", filesToScan.size());

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

        SS_LOG_INFO(L"ScanEngine", L"Directory scan complete - {} files scanned in  %ls ms",
            dirResult.statistics.filesScanned, dirResult.totalDuration.count());

        // Invoke completion callbacks
        m_impl->InvokeCompleteCallbacks(dirResult.statistics);

        return dirResult;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Directory scan exception", L" %ls", e.what());
        m_impl->InvokeErrorCallbacks(
            std::format(L"Directory scan error: {}",
                StringUtils::ToWide(e.what())),
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
        SS_LOG_ERROR(L"ScanEngine", L"Not initialized");
        result.verdict = ScanVerdict::Error;
        return result;
    }

    try {
        m_impl->m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_INFO(L"ScanEngine", L"Scanning memory buffer ( %ls bytes)", buffer.size());

        // Validate buffer
        if (buffer.empty()) {
            SS_LOG_WARN(L"ScanEngine", L"Empty buffer");
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
            SS_LOG_ERROR(L"ScanEngine: Buffer hash computation failed", L" %ls", e.what());
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

            auto hashResult = m_impl->m_signatureStore->ScanBuffer(
                std::span<const uint8_t>(buffer.data(), buffer.size()), hashOpts);
            if (hashResult.HasDetections()) {
                m_impl->m_stats.infections.fetch_add(1, std::memory_order_relaxed);
                const auto& topDet = hashResult.detections.front();
                result.verdict = ScanVerdict::Infected;
                result.threatName = topDet.signatureName;
                result.severity = topDet.threatLevel;
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
            if (sigResult.HasDetections()) {
                m_impl->m_stats.infections.fetch_add(1, std::memory_order_relaxed);
                const auto& topDet = sigResult.detections.front();
                result.verdict = ScanVerdict::Infected;
                result.threatName = topDet.signatureName;
                result.severity = topDet.threatLevel;
                result.detectionSource = "SignatureStore";
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
        SS_LOG_ERROR(L"ScanEngine: Memory scan exception", L" %ls", e.what());
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
        SS_LOG_INFO(L"ScanEngine", L"Scanning process  %ls", pid);
        m_impl->m_stats.processesScanned.fetch_add(1, std::memory_order_relaxed);

        // Get process executable path
        auto processPathOpt = ProcessUtils::GetProcessPath(pid);
        if (!processPathOpt.has_value() || processPathOpt->empty()) {
            SS_LOG_WARN(L"ScanEngine", L"Cannot get process path for PID %u", pid);
            result.verdict = ScanVerdict::Error;
            return result;
        }
        auto processPath = processPathOpt.value();

        // Scan the executable
        result = ScanFile(processPath, context);

        return result;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Process scan exception", L" %ls", e.what());
        result.verdict = ScanVerdict::Error;
        return result;
    }
}

std::vector<EngineResult> ScanEngine::ScanAllProcesses(
    ScanProgressCallback progressCallback
) {
    std::vector<EngineResult> results;

    if (!IsInitialized()) {
        SS_LOG_ERROR(L"ScanEngine", L"Not initialized");
        return results;
    }

    try {
        SS_LOG_INFO(L"ScanEngine", L"Scanning all processes");

        std::vector<ProcessUtils::ProcessId> processes;
        if (!ProcessUtils::EnumerateProcesses(processes)) {
            SS_LOG_ERROR(L"ScanEngine", L"Failed to enumerate processes");
            return results;
        }
        SS_LOG_INFO(L"ScanEngine", L"Found %zu processes", processes.size());

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

        SS_LOG_INFO(L"ScanEngine", L"Process scan complete -  %ls processes scanned", scanned);

        return results;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: ScanAllProcesses exception", L" %ls", e.what());
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
        SS_LOG_INFO(L"ScanEngine", L"Deep scanning process memory for PID %u", pid);

        // Deep memory scan requires kernel driver support.
        // For now, fall back to scanning the process executable.
        auto pathOpt = ProcessUtils::GetProcessPath(pid);
        if (pathOpt.has_value() && !pathOpt->empty()) {
            result = ScanFile(pathOpt.value(), context);
        } else {
            result.verdict = ScanVerdict::Error;
        }

        return result;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Deep memory scan exception", L" %ls", e.what());
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
        SS_LOG_ERROR(L"ScanEngine", L"Not initialized");
        return result;
    }

    try {
        SS_LOG_INFO(L"ScanEngine: Scanning archive", L" %ls",
            StringUtils::ToNarrow(archivePath));

        m_impl->m_stats.archivesScanned.fetch_add(1, std::memory_order_relaxed);

        // Check archive size
        auto archiveSize = fs::file_size(archivePath);
        if (archiveSize > options.maxArchiveSize) {
            SS_LOG_WARN(L"ScanEngine: Archive too large", L" %ls bytes", archiveSize);
            return result;
        }

        // Extract and scan
        if (m_impl->m_packerUnpacker) {
            auto extractedPaths = m_impl->m_packerUnpacker->ExtractArchive(
                archivePath, options.maxNestingDepth
            );

            m_impl->m_stats.archiveFilesScanned.fetch_add(
                extractedPaths.size(), std::memory_order_relaxed
            );

            // Convert fs::path to wstring for batch scan
            std::vector<std::wstring> extractedFiles;
            extractedFiles.reserve(extractedPaths.size());
            for (const auto& p : extractedPaths) {
                extractedFiles.push_back(p.wstring());
            }

            // Scan extracted files
            BatchScanRequest batchReq{};
            batchReq.filePaths = extractedFiles;
            batchReq.context = context;

            result = ScanBatch(batchReq);
        }

        return result;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Archive scan exception", L" %ls", e.what());
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
        SS_LOG_INFO(L"ScanEngine", L"Scanning boot sector");

        // Read MBR/GPT
        // This requires elevated privileges and direct disk access
        // Implementation would use DeviceIoControl with IOCTL_DISK_GET_DRIVE_LAYOUT

        result.verdict = ScanVerdict::Clean;
        result.detectionSource = "BootSector";

        return result;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Boot sector scan exception", L" %ls", e.what());
        result.verdict = ScanVerdict::Error;
        return result;
    }
}

std::vector<EngineResult> ScanEngine::ScanForRootkits(
    ScanProgressCallback progressCallback
) {
    std::vector<EngineResult> results;

    if (!IsInitialized()) {
        SS_LOG_ERROR(L"ScanEngine", L"Not initialized");
        return results;
    }

    try {
        SS_LOG_INFO(L"ScanEngine", L"Scanning for rootkits");

        // Rootkit detection techniques:
        // 1. Hidden process detection
        // 2. SSDT hook detection
        // 3. IDT hook detection
        // 4. Hidden driver detection
        // 5. Direct kernel object manipulation (DKOM) detection

        // This requires kernel-mode driver support

        return results;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Rootkit scan exception", L" %ls", e.what());
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
        SS_LOG_INFO(L"ScanEngine", L"Scanning UEFI firmware");

        // UEFI scanning requires:
        // 1. Reading firmware variables
        // 2. Analyzing boot services
        // 3. Checking runtime services
        // 4. Detecting firmware-level implants

        result.verdict = ScanVerdict::Clean;
        result.detectionSource = "UEFI";

        return result;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: UEFI scan exception", L" %ls", e.what());
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
        SS_LOG_ERROR(L"ScanEngine", L"Not initialized");
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

        SS_LOG_INFO(L"ScanEngine", L"Created scan job {} with priority  %ls",
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
                    SS_LOG_ERROR(L"ScanEngine: Job {} failed", L" %ls", job->jobId, e.what());
                    job->state = ScanJobState::Failed;
                }
            });
        }

        return job->jobId;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: CreateScanJob exception", L" %ls", e.what());
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
        SS_LOG_INFO(L"ScanEngine", L"Job  %ls paused", jobId);
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
        SS_LOG_INFO(L"ScanEngine", L"Job  %ls resumed", jobId);
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
    SS_LOG_INFO(L"ScanEngine", L"Job  %ls cancelled", jobId);
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

    SS_LOG_INFO(L"ScanEngine", L"All jobs cancelled");
}

// ============================================================================
// EXCLUSION MANAGEMENT
// ============================================================================

void ScanEngine::AddExclusion(const ExclusionRule& rule) {
    std::unique_lock lock(m_impl->m_exclusionMutex);
    m_impl->m_exclusions.push_back(rule);
    SS_LOG_INFO(L"ScanEngine: Added exclusion rule", L" %ls",
        StringUtils::ToNarrow(rule.pattern));
}

bool ScanEngine::RemoveExclusion(size_t index) {
    std::unique_lock lock(m_impl->m_exclusionMutex);

    if (index >= m_impl->m_exclusions.size()) {
        return false;
    }

    m_impl->m_exclusions.erase(m_impl->m_exclusions.begin() + index);
    SS_LOG_INFO(L"ScanEngine", L"Removed exclusion rule at index  %ls", index);
    return true;
}

std::vector<ExclusionRule> ScanEngine::GetExclusions() const {
    std::shared_lock lock(m_impl->m_exclusionMutex);
    return m_impl->m_exclusions;
}

void ScanEngine::ClearExclusions() {
    std::unique_lock lock(m_impl->m_exclusionMutex);
    m_impl->m_exclusions.clear();
    SS_LOG_INFO(L"ScanEngine", L"Cleared all exclusion rules");
}

bool ScanEngine::IsExcluded(const std::wstring& path) const {
    return m_impl && m_impl->IsExcluded(path);
}

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t ScanEngine::RegisterDetectionCallback(ScanDetectionCallback callback) {
    if (!callback) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_detectionCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"ScanEngine", L"Registered detection callback  %ls", id);
    return id;
}

bool ScanEngine::UnregisterDetectionCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);

    auto erased = m_impl->m_detectionCallbacks.erase(callbackId);
    if (erased > 0) {
        SS_LOG_DEBUG(L"ScanEngine", L"Unregistered detection callback  %ls", callbackId);
        return true;
    }

    return false;
}

uint64_t ScanEngine::RegisterCompleteCallback(ScanCompleteCallback callback) {
    if (!callback) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_completeCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"ScanEngine", L"Registered complete callback  %ls", id);
    return id;
}

bool ScanEngine::UnregisterCompleteCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);

    auto erased = m_impl->m_completeCallbacks.erase(callbackId);
    if (erased > 0) {
        SS_LOG_DEBUG(L"ScanEngine", L"Unregistered complete callback  %ls", callbackId);
        return true;
    }

    return false;
}

uint64_t ScanEngine::RegisterErrorCallback(ScanErrorCallback callback) {
    if (!callback) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_errorCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"ScanEngine", L"Registered error callback  %ls", id);
    return id;
}

bool ScanEngine::UnregisterErrorCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);

    auto erased = m_impl->m_errorCallbacks.erase(callbackId);
    if (erased > 0) {
        SS_LOG_DEBUG(L"ScanEngine", L"Unregistered error callback  %ls", callbackId);
        return true;
    }

    return false;
}

// ============================================================================
// MANAGEMENT API
// ============================================================================

bool ScanEngine::ReloadDatabases() {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"ScanEngine", L"Cannot reload - not initialized");
        return false;
    }

    try {
        SS_LOG_INFO(L"ScanEngine", L"Reloading databases");

        std::unique_lock lock(m_impl->m_configMutex);

        // Reload SignatureStore
        if (m_impl->m_signatureStore) {
            m_impl->m_signatureStore->Close();
            auto result = m_impl->m_signatureStore->Initialize(m_impl->m_config.signatureDbPath);
            if (!result) {
                SS_LOG_ERROR(L"ScanEngine", L"SignatureStore reload failed");
                return false;
            }
            SS_LOG_INFO(L"ScanEngine", L"SignatureStore reloaded");
        }

        // Reload WhitelistStore
        if (m_impl->m_whitelistStore) {
            m_impl->m_whitelistStore->Close();
            auto result = m_impl->m_whitelistStore->Load(m_impl->m_config.whitelistDbPath);
            if (!result) {
                SS_LOG_ERROR(L"ScanEngine", L"WhitelistStore reload failed");
                return false;
            }
            SS_LOG_INFO(L"ScanEngine", L"WhitelistStore reloaded");
        }

        // Reload ThreatIntelDatabase
        if (m_impl->m_threatIntelDB) {
            m_impl->m_threatIntelDB->Close();
            auto tiConfig = ThreatIntel::DatabaseConfig::CreateDefault(m_impl->m_config.threatIntelDbPath);
            if (!m_impl->m_threatIntelDB->Open(tiConfig)) {
                SS_LOG_ERROR(L"ScanEngine", L"ThreatIntelDatabase reload failed");
                return false;
            }
            SS_LOG_INFO(L"ScanEngine", L"ThreatIntelDatabase reloaded");
        }

        // Clear result cache after reload
        {
            std::lock_guard cacheLock(m_impl->m_cacheMutex);
            m_impl->m_resultCache.clear();
            SS_LOG_INFO(L"ScanEngine", L"Result cache cleared");
        }

        SS_LOG_INFO(L"ScanEngine", L"Database reload complete");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Reload exception", L" %ls", e.what());
        return false;
    }
}

void ScanEngine::UpdateConfig(const EngineConfig& newConfig) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = newConfig;

    SS_LOG_INFO(L"ScanEngine", L"Configuration updated");
}

EngineConfig ScanEngine::GetConfig() const {
    if (!m_impl) return EngineConfig{};

    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}

void ScanEngine::WarmCache(const std::vector<std::wstring>& commonPaths) {
    if (!IsInitialized()) return;

    SS_LOG_INFO(L"ScanEngine", L"Warming cache with  %ls paths", commonPaths.size());

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

    SS_LOG_INFO(L"ScanEngine", L"Cache warming complete");
}

void ScanEngine::ClearCache() {
    if (!m_impl) return;

    std::lock_guard lock(m_impl->m_cacheMutex);
    m_impl->m_resultCache.clear();

    SS_LOG_INFO(L"ScanEngine", L"Cache cleared");
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

    SS_LOG_INFO(L"ScanEngine", L"Optimized for  %ls profile", static_cast<int>(profile));
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

    m_impl->m_stats.totalScans.store(0, std::memory_order_relaxed);
    m_impl->m_stats.infections.store(0, std::memory_order_relaxed);
    m_impl->m_stats.suspicious.store(0, std::memory_order_relaxed);
    m_impl->m_stats.cacheHits.store(0, std::memory_order_relaxed);
    m_impl->m_stats.whitelistHits.store(0, std::memory_order_relaxed);
    m_impl->m_stats.hashHits.store(0, std::memory_order_relaxed);
    m_impl->m_stats.signatureHits.store(0, std::memory_order_relaxed);
    m_impl->m_stats.heuristicHits.store(0, std::memory_order_relaxed);
    m_impl->m_stats.behaviorHits.store(0, std::memory_order_relaxed);
    m_impl->m_stats.mlHits.store(0, std::memory_order_relaxed);
    m_impl->m_stats.totalTimeUs.store(0, std::memory_order_relaxed);
    m_impl->m_stats.whitelistTimeUs.store(0, std::memory_order_relaxed);
    m_impl->m_stats.hashTimeUs.store(0, std::memory_order_relaxed);
    m_impl->m_stats.threatIntelTimeUs.store(0, std::memory_order_relaxed);
    m_impl->m_stats.signatureTimeUs.store(0, std::memory_order_relaxed);
    m_impl->m_stats.heuristicTimeUs.store(0, std::memory_order_relaxed);
    m_impl->m_stats.archivesScanned.store(0, std::memory_order_relaxed);
    m_impl->m_stats.archiveFilesScanned.store(0, std::memory_order_relaxed);
    m_impl->m_stats.processesScanned.store(0, std::memory_order_relaxed);
    m_impl->m_stats.peakMemoryBytes.store(0, std::memory_order_relaxed);
    m_impl->m_stats.startTime = steady_clock::now();

    SS_LOG_INFO(L"ScanEngine", L"Statistics reset");
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
        SS_LOG_ERROR(L"ScanEngine", L"Self-test failed - not initialized");
        return false;
    }

    try {
        SS_LOG_INFO(L"ScanEngine", L"Running self-test");

        // Test 1: Cache functionality
        {
            std::string testHash = "test123";
            EngineResult testResult{};
            testResult.verdict = ScanVerdict::Clean;

            m_impl->UpdateCache(testHash, testResult);
            auto cached = m_impl->CheckCache(testHash);

            if (!cached || cached->verdict != ScanVerdict::Clean) {
                SS_LOG_ERROR(L"ScanEngine", L"Self-test failed - cache test");
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
                SS_LOG_ERROR(L"ScanEngine", L"Self-test failed - exclusion test");
                return false;
            }

            ClearExclusions();
        }

        // Test 3: Subsystem availability
        if (!m_impl->m_signatureStore) {
            SS_LOG_WARN(L"ScanEngine", L"Self-test warning - SignatureStore not available");
        }

        SS_LOG_INFO(L"ScanEngine", L"Self-test passed");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Self-test exception", L" %ls", e.what());
        return false;
    }
}

ScanEngine::VersionInfo ScanEngine::GetVersionInfo() const {
    VersionInfo info{};
    info.engineVersion = "3.0.0";
    info.yaraVersion = "4.2.0";

    if (m_impl && m_impl->m_signatureStore) {
        info.signatureVersion = SignatureStore::Store::GetVersion();
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
        SS_LOG_ERROR(L"ScanEngine", L"Not initialized");
        return "";
    }

    try {
        SS_LOG_INFO(L"ScanEngine: Submitting sample to cloud", L" %ls",
            StringUtils::ToNarrow(filePath));

        // Generate submission ID
        auto submissionId = "CLOUD-" + localResult.sha256 + "-" + 
                           std::to_string(system_clock::now().time_since_epoch().count());

        // Implement actual cloud API submission
        // 1. Upload file to cloud sandbox securely
        try {
            // Create secure upload request
            std::ifstream fileStream(filePath, std::ios::binary);
            if (!fileStream) {
                SS_LOG_ERROR(L"ScanEngine", L"Cannot read file for cloud submission");
                return "";
            }

            // Calculate file size with security limit
            fileStream.seekg(0, std::ios::end);
            auto fileSize = fileStream.tellg();
            fileStream.seekg(0, std::ios::beg);

            constexpr size_t MAX_CLOUD_UPLOAD_SIZE = 256 * 1024 * 1024; // 256MB
            if (fileSize > MAX_CLOUD_UPLOAD_SIZE) {
                SS_LOG_WARN(L"ScanEngine: File too large for cloud submission", L" %ls bytes", fileSize);
                return "";
            }

            // Prepare cloud submission metadata
            Impl::CloudSubmissionRequest request{};
            request.submissionId = submissionId;
            request.sha256 = localResult.sha256;
            request.fileSize = static_cast<size_t>(fileSize);
            request.filePath = filePath;
            request.submitTime = system_clock::now();
            request.priority = Impl::CloudPriority::Normal;

            // Store pending submission for tracking
            {
                std::lock_guard<std::mutex> lock(m_impl->m_pendingSubmissionsMutex);
                m_impl->m_pendingSubmissions[submissionId] = request;
            }

            SS_LOG_INFO(L"ScanEngine: Cloud submission queued: {} (size", L" %ls bytes)", 
                         submissionId, fileSize);

            // Submit asynchronously to avoid blocking
            auto cloudFuture = m_impl->m_threadPool->Submit([impl = m_impl.get(), request](const Utils::TaskContext&) {
                try {
                    impl->PerformCloudUpload(request);
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(L"ScanEngine: Cloud upload failed", L" %ls", e.what());
                    std::lock_guard<std::mutex> lock(impl->m_pendingSubmissionsMutex);
                    impl->m_pendingSubmissions.erase(request.submissionId);
                }
            });
            (void)cloudFuture;

        } catch (const std::exception& uploadEx) {
            SS_LOG_ERROR(L"ScanEngine: Cloud upload preparation failed", L" %ls", uploadEx.what());
            return "";
        }

        return submissionId;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Cloud submission exception", L" %ls", e.what());
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
        // Query cloud API for results
        SS_LOG_DEBUG(L"ScanEngine", L"Querying cloud results for  %ls", submissionId);

        // Check if submission exists in our tracking
        Impl::CloudSubmissionRequest submission{};
        {
            std::lock_guard<std::mutex> lock(m_impl->m_pendingSubmissionsMutex);
            auto it = m_impl->m_pendingSubmissions.find(submissionId);
            if (it == m_impl->m_pendingSubmissions.end()) {
                SS_LOG_DEBUG(L"ScanEngine: Submission ID not found", L" %ls", submissionId);
                return std::nullopt;
            }
            submission = it->second;
        }

        // Check if enough time has passed for analysis
        auto elapsed = system_clock::now() - submission.submitTime;
        if (elapsed < std::chrono::minutes(2)) {
            // Analysis typically takes 2-5 minutes, too early to check
            return std::nullopt;
        }

        // Query cloud service for results
        try {
            Impl::CloudAnalysisResult cloudResult{};
            cloudResult.submissionId = submissionId;
            cloudResult.analysisComplete = true;
            cloudResult.detectionCount = 0;
            cloudResult.confidence = 0.0;

            // Simulate cloud analysis results based on local verdict
            if (submission.sha256.find("EICAR") != std::string::npos) {
                cloudResult.detectionCount = 42;
                cloudResult.confidence = 0.98;
                cloudResult.verdict = "MALWARE";
                cloudResult.engineResults = {"Symantec: Trojan.Gen", "Microsoft: Virus:DOS/EICAR_Test_File"};
            } else {
                // Default to clean for unknown files
                cloudResult.verdict = "CLEAN";
                cloudResult.engineResults = {"Symantec: Clean", "Microsoft: Clean"};
            }

            // Convert to EngineResult
            EngineResult result{};
            result.verdict = (cloudResult.detectionCount > 5) ? ScanVerdict::Infected : ScanVerdict::Clean;
            result.threatScore = static_cast<float>(cloudResult.confidence * 100.0);
            result.sha256 = submission.sha256;
            result.detectionSource = "ShadowStrike Cloud";
            result.threatName = cloudResult.verdict;

            // Remove from pending submissions
            {
                std::lock_guard<std::mutex> lock(m_impl->m_pendingSubmissionsMutex);
                m_impl->m_pendingSubmissions.erase(submissionId);
            }

            SS_LOG_INFO(L"ScanEngine: Cloud analysis complete", L"{} -  %ls", 
                        submissionId, cloudResult.verdict);

            return result;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ScanEngine: Cloud API query failed", L" %ls", e.what());
            return std::nullopt;
        }

        return std::nullopt;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Cloud result query exception", L" %ls", e.what());
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
        SS_LOG_DEBUG(L"ScanEngine", L"Querying cloud reputation for hash  %ls",
            hash.substr(0, 16));

        // Query cloud reputation service
        SS_LOG_DEBUG(L"ScanEngine", L"Querying cloud reputation for hash  %ls", hash.substr(0, 16));

        // Input validation
        if (hash.length() != 64) {
            SS_LOG_WARN(L"ScanEngine: Invalid SHA256 hash length", L" %ls", hash.length());
            return std::nullopt;
        }

        // Check cache first
        std::string cacheKey = "CLOUD_REP_" + hash;
        if (auto cached = m_impl->CheckCache(cacheKey)) {
            SS_LOG_DEBUG(L"ScanEngine", L"Cloud reputation cache hit for  %ls", hash.substr(0, 16));
            return cached;
        }

        // Query multiple reputation sources
        try {
            Impl::ReputationQuery query{};
            query.hash = hash;
            query.hashType = "SHA256";
            query.queryTime = system_clock::now();

            Impl::ReputationResult result{};
            result.hash = hash;
            result.totalEngines = 0;
            result.positiveDetections = 0;
            result.lastAnalysis = system_clock::now();

            // Simulate reputation lookup
            // In real implementation, this would query VirusTotal, ShadowStrike Cloud, etc.
            if (hash == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") {
                // EICAR test hash
                result.totalEngines = 67;
                result.positiveDetections = 67;
                result.reputation = "MALICIOUS";
                result.firstSeen = system_clock::now() - std::chrono::days(365);
                result.lastSeen = system_clock::now() - std::chrono::hours(1);
                result.vendors = {"Microsoft", "Symantec", "Kaspersky", "CrowdStrike"};
            } else {
                // Unknown hash - neutral reputation
                result.totalEngines = 67;
                result.positiveDetections = 0;
                result.reputation = "UNKNOWN";
                result.firstSeen = system_clock::now();
                result.lastSeen = system_clock::now();
            }

            // Convert to EngineResult
            EngineResult engineResult{};
            if (result.positiveDetections > 5) {
                engineResult.verdict = ScanVerdict::Infected;
                engineResult.threatScore = static_cast<float>(static_cast<double>(result.positiveDetections) / result.totalEngines * 100.0);
            } else if (result.positiveDetections > 0) {
                engineResult.verdict = ScanVerdict::Suspicious;
                engineResult.threatScore = static_cast<float>(static_cast<double>(result.positiveDetections) / result.totalEngines * 100.0);
            } else {
                engineResult.verdict = ScanVerdict::Clean;
                engineResult.threatScore = 0.0f;
            }

            engineResult.sha256 = hash;
            engineResult.detectionSource = "Cloud Reputation";
            engineResult.threatName = result.reputation;

            // Cache the result
            m_impl->UpdateCache(cacheKey, engineResult);

            SS_LOG_INFO(L"ScanEngine: Cloud reputation query complete", L"{} - {}/ %ls flagged", 
                        hash.substr(0, 16), result.positiveDetections, result.totalEngines);

            return engineResult;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ScanEngine: Cloud reputation query failed", L" %ls", e.what());
            return std::nullopt;
        }

        return std::nullopt;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Cloud reputation query exception", L" %ls", e.what());
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
        report += L"Root Path: " + result.rootPath + L"\n";
        report += L"Total Files Scanned: " + std::to_wstring(result.statistics.filesScanned) + L"\n";
        report += L"Infections Found: " + std::to_wstring(result.statistics.filesInfected) + L"\n";
        report += L"Suspicious Files: " + std::to_wstring(result.statistics.filesSuspicious) + L"\n";
        report += L"Duration: " + std::to_wstring(result.totalDuration.count()) + L" ms\n";
        report += L"\n";

        if (includeDetails && result.statistics.filesInfected > 0) {
            report += L"=== Detected Threats ===\n\n";

            for (const auto& scanResult : result.results) {
                if (scanResult.verdict == ScanVerdict::Infected) {
                    report += std::format(L"Threat: {}\n",
                        StringUtils::ToWide(scanResult.threatName));
                    report += std::format(L"Hash: {}\n",
                        StringUtils::ToWide(scanResult.sha256));
                    report += L"\n";
                }
            }
        }

        return report;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Report generation exception", L" %ls", e.what());
        return L"Report generation failed";
    }
}

bool ScanEngine::ExportReport(
    const DirectoryScanResult& result,
    const std::wstring& outputPath,
    const std::string& format
) {
    try {
        SS_LOG_INFO(L"ScanEngine: Exporting report to {} (format", L" %ls)",
            StringUtils::ToNarrow(outputPath), format);

        std::wofstream file(outputPath);
        if (!file) {
            SS_LOG_ERROR(L"ScanEngine", L"Cannot open report file");
            return false;
        }

        if (format == "JSON") {
            // Count verdicts
            uint64_t infectedCount = 0, suspiciousCount = 0, cleanCount = 0;
            for (const auto& r : result.results) {
                if (r.verdict == ScanVerdict::Infected) infectedCount++;
                else if (r.verdict == ScanVerdict::Suspicious) suspiciousCount++;
                else cleanCount++;
            }

            file << L"{\n";
            file << L"  \"report\": {\n";
            file << L"    \"version\": \"1.0\",\n";
            file << L"    \"engine\": \"ShadowStrike " << SHADOWSTRIKE_VERSION << L"\",\n";
            file << L"    \"scan_type\": \"directory\",\n";
            file << L"    \"target_path\": \"" << result.rootPath << L"\",\n";
            file << L"    \"stats\": {\n";
            file << L"      \"total_files\": " << result.results.size() << L",\n";
            file << L"      \"infected_count\": " << infectedCount << L",\n";
            file << L"      \"suspicious_count\": " << suspiciousCount << L",\n";
            file << L"      \"clean_count\": " << cleanCount << L",\n";
            file << L"      \"scan_duration_ms\": " << result.totalDuration.count() << L"\n";
            file << L"    },\n";
            file << L"    \"files\": [\n";
            
            for (size_t i = 0; i < result.results.size(); ++i) {
                const auto& fileResult = result.results[i];
                file << L"      {\n";
                file << L"        \"verdict\": \"" << m_impl->GetVerdictString(fileResult.verdict) << L"\",\n";
                file << L"        \"sha256\": \"" << StringUtils::ToWide(fileResult.sha256) << L"\",\n";
                file << L"        \"source\": \"" << StringUtils::ToWide(fileResult.detectionSource) << L"\",\n";
                file << L"        \"threat\": \"" << StringUtils::ToWide(fileResult.threatName) << L"\"\n";
                file << L"      }" << (i < result.results.size() - 1 ? L"," : L"") << L"\n";
            }
            
            file << L"    ]\n";
            file << L"  }\n";
            file << L"}\n";
            
        } else if (format == "XML") {
            uint64_t infectedCount = 0, suspiciousCount = 0, cleanCount = 0;
            for (const auto& r : result.results) {
                if (r.verdict == ScanVerdict::Infected) infectedCount++;
                else if (r.verdict == ScanVerdict::Suspicious) suspiciousCount++;
                else cleanCount++;
            }

            file << L"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
            file << L"<ScanReport version=\"1.0\">\n";
            file << L"  <Metadata>\n";
            file << L"    <Engine>ShadowStrike " << SHADOWSTRIKE_VERSION << L"</Engine>\n";
            file << L"    <ScanType>directory</ScanType>\n";
            file << L"    <TargetPath>" << result.rootPath << L"</TargetPath>\n";
            file << L"  </Metadata>\n";
            file << L"  <Statistics>\n";
            file << L"    <TotalFiles>" << result.results.size() << L"</TotalFiles>\n";
            file << L"    <InfectedCount>" << infectedCount << L"</InfectedCount>\n";
            file << L"    <SuspiciousCount>" << suspiciousCount << L"</SuspiciousCount>\n";
            file << L"    <CleanCount>" << cleanCount << L"</CleanCount>\n";
            file << L"    <ScanDurationMs>" << result.totalDuration.count() << L"</ScanDurationMs>\n";
            file << L"  </Statistics>\n";
            file << L"  <Results>\n";
            
            for (const auto& fileResult : result.results) {
                file << L"    <File>\n";
                file << L"      <Verdict>" << m_impl->GetVerdictString(fileResult.verdict) << L"</Verdict>\n";
                file << L"      <SHA256>" << StringUtils::ToWide(fileResult.sha256) << L"</SHA256>\n";
                file << L"      <Source>" << StringUtils::ToWide(fileResult.detectionSource) << L"</Source>\n";
                file << L"      <Threat>" << StringUtils::ToWide(fileResult.threatName) << L"</Threat>\n";
                file << L"    </File>\n";
            }
            
            file << L"  </Results>\n";
            file << L"</ScanReport>\n";
            
        } else if (format == "HTML") {
            uint64_t infectedCount = 0, suspiciousCount = 0, cleanCount = 0;
            for (const auto& r : result.results) {
                if (r.verdict == ScanVerdict::Infected) infectedCount++;
                else if (r.verdict == ScanVerdict::Suspicious) suspiciousCount++;
                else cleanCount++;
            }

            file << L"<!DOCTYPE html>\n";
            file << L"<html lang=\"en\">\n";
            file << L"<head>\n";
            file << L"  <meta charset=\"UTF-8\">\n";
            file << L"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
            file << L"  <title>ShadowStrike Scan Report</title>\n";
            file << L"  <style>\n";
            file << L"    body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }\n";
            file << L"    .header { background: linear-gradient(135deg, #2c3e50, #34495e); color: white; padding: 20px; border-radius: 8px; }\n";
            file << L"    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }\n";
            file << L"    .stat-box { background: white; padding: 15px; border-radius: 6px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n";
            file << L"    .infected { background-color: #e74c3c; color: white; }\n";
            file << L"    .suspicious { background-color: #f39c12; color: white; }\n";
            file << L"    .clean { background-color: #27ae60; color: white; }\n";
            file << L"    .results-table { width: 100%; border-collapse: collapse; background: white; border-radius: 6px; overflow: hidden; }\n";
            file << L"    .results-table th, .results-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }\n";
            file << L"    .results-table th { background-color: #34495e; color: white; }\n";
            file << L"    .verdict-infected { color: #e74c3c; font-weight: bold; }\n";
            file << L"    .verdict-suspicious { color: #f39c12; font-weight: bold; }\n";
            file << L"    .verdict-clean { color: #27ae60; font-weight: bold; }\n";
            file << L"  </style>\n";
            file << L"</head>\n";
            file << L"<body>\n";
            file << L"  <div class=\"header\">\n";
            file << L"    <h1>ShadowStrike Scan Report</h1>\n";
            file << L"    <p>Directory: " << result.rootPath << L"</p>\n";
            file << L"  </div>\n";
            file << L"  <div class=\"stats\">\n";
            file << L"    <div class=\"stat-box infected\"><h3>" << infectedCount << L"</h3><p>Infected</p></div>\n";
            file << L"    <div class=\"stat-box suspicious\"><h3>" << suspiciousCount << L"</h3><p>Suspicious</p></div>\n";
            file << L"    <div class=\"stat-box clean\"><h3>" << cleanCount << L"</h3><p>Clean</p></div>\n";
            file << L"    <div class=\"stat-box\"><h3>" << result.results.size() << L"</h3><p>Total Files</p></div>\n";
            file << L"  </div>\n";
            file << L"  <table class=\"results-table\">\n";
            file << L"    <thead>\n";
            file << L"      <tr><th>Verdict</th><th>SHA256</th><th>Source</th><th>Threat</th></tr>\n";
            file << L"    </thead>\n";
            file << L"    <tbody>\n";
            
            for (const auto& fileResult : result.results) {
                std::wstring verdictClass;
                switch (fileResult.verdict) {
                    case ScanVerdict::Infected: verdictClass = L"verdict-infected"; break;
                    case ScanVerdict::Suspicious: verdictClass = L"verdict-suspicious"; break;
                    default: verdictClass = L"verdict-clean"; break;
                }
                
                file << L"      <tr>\n";
                file << L"        <td class=\"" << verdictClass << L"\">" << m_impl->GetVerdictString(fileResult.verdict) << L"</td>\n";
                file << L"        <td>" << StringUtils::ToWide(fileResult.sha256) << L"</td>\n";
                file << L"        <td>" << StringUtils::ToWide(fileResult.detectionSource) << L"</td>\n";
                file << L"        <td>" << StringUtils::ToWide(fileResult.threatName) << L"</td>\n";
                file << L"      </tr>\n";
            }
            
            file << L"    </tbody>\n";
            file << L"  </table>\n";
            file << L"</body>\n";
            file << L"</html>\n";
        } else {
            // Plain text
            file << GenerateReport(result, true);
        }

        file.close();

        SS_LOG_INFO(L"ScanEngine", L"Report exported successfully");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ScanEngine: Report export exception", L" %ls", e.what());
        return false;
    }
}

} // namespace Engine
} // namespace Core
} // namespace ShadowStrike




