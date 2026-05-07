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
 * ShadowStrike NGAV - THREAT DETECTOR MODULE
 * ============================================================================
 *
 * @file ThreatDetector.cpp
 * @brief Enterprise-grade central threat detection and event correlation engine
 *
 * Production-level implementation of multi-engine threat detection orchestration.
 * Competes with enterprise-grade enterprise-grade EDR, enterprise-grade EDR, and enterprise-grade GravityZone.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex for concurrent access
 * - Lock-free SPMC event queue for high-throughput event processing
 * - Multi-threaded event processing with worker pool
 * - Event enrichment with process context, ThreatIntel, whitelist
 * - Multi-engine detection coordination:
 *   - SignatureEngine (exact pattern matching)
 *   - BehaviorAnalyzer (runtime behavior analysis)
 *   - HeuristicAnalyzer (static heuristic analysis)
 *   - EmulationEngine (sandboxed execution)
 *   - MachineLearningDetector (AI/ML classification)
 *   - ThreatIntel (IOC correlation)
 * - Verdict aggregation with weighted scoring
 * - Attack chain correlation across time windows
 * - False positive suppression with whitelist integration
 * - Response action coordination (block, quarantine, terminate, alert)
 * - Custom rule engine for user-defined detection logic
 * - MITRE ATT&CK technique mapping
 * - Comprehensive statistics tracking
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "ThreatDetector.hpp"
#include "BehaviorAnalyzer.hpp"
#include "HeuristicAnalyzer.hpp"
#include "EmulationEngine.hpp"
#include "MachineLearningDetector.hpp"
#include "PackerUnpacker.hpp"
#include "PolymorphicDetector.hpp"
#include "ZeroDayDetector.hpp"
#include "SandboxAnalyzer.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/Logger.hpp"
#include "../../SignatureStore/SignatureStore.hpp"
#include "../../ThreatIntel/ThreatIntelIndex.hpp"
#include "../../Whitelist/WhiteListStore.hpp"
#include "../../Whitelist/WhiteListFormat.hpp"
#include "../../ThreatIntel/ThreatIntelFormat.hpp"
#include "../../Utils/ThreadPool.hpp"
#include "QuarantineManager.hpp"
#include "ScanEngine.hpp"

#include <algorithm>
#include <numeric>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <map>
#include <set>
#include <unordered_set>
#include <condition_variable>
#include <cwctype>
#include <filesystem>
#include <Windows.h>

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ============================================================================
// Structure Implementations
// ============================================================================

std::string ThreatVerdict::ToJson() const {
    std::ostringstream oss;
    oss << "{\"isThreat\":" << (isThreat ? "true" : "false") << ",";
    oss << "\"severity\":" << static_cast<int>(severity) << ",";
    oss << "\"category\":" << static_cast<int>(category) << ",";
    oss << "\"threatScore\":" << threatScore << ",";
    oss << "\"confidence\":" << static_cast<int>(confidence) << ",";
    oss << "\"processId\":" << processId << ",";
    oss << "\"engineCount\":" << engineDetections.size() << ",";
    oss << "\"mitreCount\":" << mitreTechniques.size() << ",";
    oss << "\"action\":" << static_cast<int>(recommendedAction) << "}";
    return oss.str();
}

std::string AttackChain::ToJson() const {
    std::ostringstream oss;
    oss << "{\"chainId\":" << chainId << ",";
    oss << "\"severity\":" << static_cast<int>(severity) << ",";
    oss << "\"confidence\":" << confidence << ",";
    oss << "\"processCount\":" << involvedProcessIds.size() << ",";
    oss << "\"eventCount\":" << eventIds.size() << ",";
    oss << "\"mitreCount\":" << mitreTechniques.size() << "}";
    return oss.str();
}

// ============================================================================
// File-local helpers (no external linkage)
// ============================================================================

namespace {

// Hard cap on file size we will read into memory for hashing during enrichment.
// Files larger than this are skipped entirely; hashing such files synchronously
// would expose us to obvious DoS via attacker-controlled large files.
constexpr uint64_t kMaxFileSizeForHash = 256ull * 1024ull * 1024ull;

// Map ThreatSeverity (which uses a sparse 0/25/50/75/100 encoding) to a compact
// 0..4 index so it can index ThreatDetectorStats::threatsBySeverity without
// silently skipping increments or running off the end of the fixed-size array.
[[nodiscard]] constexpr size_t SeverityToIndex(ThreatSeverity s) noexcept {
    switch (s) {
        case ThreatSeverity::None:     return 0;
        case ThreatSeverity::Low:      return 1;
        case ThreatSeverity::Medium:   return 2;
        case ThreatSeverity::High:     return 3;
        case ThreatSeverity::Critical: return 4;
    }
    return 0;
}

// Best-effort ThreatCategory inference from detection name/family. We never
// fabricate a specific category from thin air; if no signal is present we
// fall back to Malware (positive detections) or Unknown (no detections).
[[nodiscard]] ThreatCategory InferCategory(const std::vector<EngineDetection>& detections) noexcept {
    if (detections.empty()) {
        return ThreatCategory::Unknown;
    }

    auto containsCi = [](const std::wstring& haystack, std::wstring_view needle) noexcept -> bool {
        if (needle.empty() || haystack.size() < needle.size()) return false;
        auto it = std::search(
            haystack.begin(), haystack.end(),
            needle.begin(), needle.end(),
            [](wchar_t a, wchar_t b) {
                return std::towlower(static_cast<wint_t>(a)) ==
                       std::towlower(static_cast<wint_t>(b));
            });
        return it != haystack.end();
    };

    for (const auto& d : detections) {
        const auto& n = d.detectionName;
        const auto& f = d.family;
        if (containsCi(n, L"ransom") || containsCi(f, L"ransom")) return ThreatCategory::Ransomware;
        if (containsCi(n, L"trojan") || containsCi(f, L"trojan")) return ThreatCategory::Trojan;
        if (containsCi(n, L"worm")   || containsCi(f, L"worm"))   return ThreatCategory::Worm;
        if (containsCi(n, L"miner")  || containsCi(f, L"miner") ||
            containsCi(n, L"coinminer") || containsCi(f, L"coinminer")) return ThreatCategory::CryptoMiner;
        if (containsCi(n, L"backdoor") || containsCi(f, L"backdoor")) return ThreatCategory::Backdoor;
        if (containsCi(n, L"rootkit") || containsCi(f, L"rootkit")) return ThreatCategory::Rootkit;
        if (containsCi(n, L"spyware") || containsCi(f, L"spyware")) return ThreatCategory::Spyware;
        if (containsCi(n, L"keylog")  || containsCi(f, L"keylog"))  return ThreatCategory::Keylogger;
        if (containsCi(n, L"stealer") || containsCi(f, L"stealer")) return ThreatCategory::InfoStealer;
        if (containsCi(n, L"dropper") || containsCi(f, L"dropper")) return ThreatCategory::Dropper;
        if (containsCi(n, L"downloader") || containsCi(f, L"downloader")) return ThreatCategory::Downloader;
        if (containsCi(n, L"rat") || containsCi(f, L"rat")) return ThreatCategory::RAT;
        if (containsCi(n, L"adware") || containsCi(f, L"adware")) return ThreatCategory::Adware;
        if (containsCi(n, L"pup") || containsCi(f, L"pua")) return ThreatCategory::PUP;
        if (d.source == DetectionSource::ZeroDayDetection) return ThreatCategory::ZeroDay;
        if (d.source == DetectionSource::BehaviorAnalyzer) return ThreatCategory::SuspiciousBehavior;
    }
    return ThreatCategory::Malware;
}

// Parse a hex-encoded SHA-256 string into a ThreatIntel::HashValue. Returns
// std::nullopt on any malformed input — we never feed a default-initialized
// HashValue into LookupHash, which would silently match nothing.
[[nodiscard]] std::optional<ThreatIntel::HashValue> HexToThreatIntelHash(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (!Utils::HashUtils::FromHex(hex, bytes)) {
        return std::nullopt;
    }
    if (bytes.empty() || bytes.size() > 72) {
        return std::nullopt;
    }
    ThreatIntel::HashAlgorithm algo;
    switch (bytes.size()) {
        case 16: algo = ThreatIntel::HashAlgorithm::MD5;    break;
        case 20: algo = ThreatIntel::HashAlgorithm::SHA1;   break;
        case 32: algo = ThreatIntel::HashAlgorithm::SHA256; break;
        case 64: algo = ThreatIntel::HashAlgorithm::SHA512; break;
        default: return std::nullopt;
    }
    return ThreatIntel::HashValue::Create(algo, bytes.data(), static_cast<uint8_t>(bytes.size()));
}

} // namespace

// ============================================================================
// Local status enum (not declared in HPP, used internally by PIMPL)
// ============================================================================

enum class ThreatDetectorStatus : uint8_t {
    Uninitialized = 0,
    Initializing,
    Initialized,
    Running,
    Stopping,
    Stopped,
    Error
};

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct ThreatDetector::Impl {
    // Thread synchronization
    mutable std::shared_mutex m_mutex;

    // Configuration
    ThreatDetectorConfig m_config;

    // Thread pool for event processing
    std::shared_ptr<Utils::ThreadPool> m_threadPool;

    // Detection engine integrations
    BehaviorAnalyzer* m_behaviorAnalyzer = nullptr;
    HeuristicAnalyzer* m_heuristicAnalyzer = nullptr;
    EmulationEngine* m_emulationEngine = nullptr;
    SignatureStore::SignatureStore* m_signatureStore = nullptr;
    ThreatIntel::ThreatIntelIndex* m_threatIntel = nullptr;
    MachineLearningDetector* m_mlDetector = nullptr;
    PackerUnpacker* m_packerUnpacker = nullptr;
    PolymorphicDetector* m_polymorphicDetector = nullptr;
    ZeroDayDetector* m_zeroDayDetector = nullptr;
    SandboxAnalyzer* m_sandboxAnalyzer = nullptr;
    QuarantineManager* m_quarantineManager = nullptr;
    ScanEngine* m_scanEngine = nullptr;

    // Whitelist (optional, externally owned via SetWhitelistStore - non-owning aliasing pointer)
    std::shared_ptr<Whitelist::WhitelistStore> m_whitelist;

    // Tracked queue depth (in-flight tasks dispatched to the thread pool)
    std::atomic<size_t> m_pendingTasks{0};
    mutable std::mutex m_drainMutex;
    std::condition_variable m_drainCv;

    // Active threats (capacity-bounded by ThreatDetectorConstants::MAX_ACTIVE_THREATS)
    std::unordered_map<uint64_t, ThreatVerdict> m_activeThreats;
    mutable std::shared_mutex m_threatsMutex;
    std::atomic<uint64_t> m_nextVerdictId{1};

    // Attack chains (one open chain per process; capped)
    std::unordered_map<uint64_t, AttackChain> m_attackChains;
    std::unordered_map<uint32_t, uint64_t> m_processChainMap;
    mutable std::mutex m_chainsMutex;
    std::atomic<uint64_t> m_nextChainId{1};

    // Custom rules (capacity-bounded by ThreatDetectorConstants::MAX_RULES)
    std::unordered_map<std::string, DetectionRule> m_rules;
    mutable std::mutex m_rulesMutex;

    // Callbacks
    std::unordered_map<uint64_t, ThreatVerdictCallback> m_verdictCallbacks;
    std::unordered_map<uint64_t, AttackChainCallback> m_chainCallbacks;
    std::unordered_map<uint64_t, EventCallback> m_eventCallbacks;
    ResponseCallback m_responseCallback;
    mutable std::mutex m_callbacksMutex;
    std::atomic<uint64_t> m_nextCallbackId{1};

    // Process-scoped local whitelist sets (used by Whitelist{Process,Hash})
    std::unordered_set<uint32_t> m_localWhitelistedPids;
    std::unordered_set<std::string> m_localWhitelistedHashes;
    mutable std::shared_mutex m_localWhitelistMutex;

    // Statistics
    ThreatDetectorStats m_statistics;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};
    std::atomic<ThreatDetectorStatus> m_status{ThreatDetectorStatus::Uninitialized};

    // Event ID tracking
    std::atomic<uint64_t> m_nextEventId{1};

    // Constructor
    Impl() = default;

    // Event enrichment helpers
    void EnrichEvent(SystemEvent& event) {
        try {
            // Add event ID if not present
            if (event.eventId == 0) {
                event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
            }

            // Add timestamp if not present
            if (event.timestamp.time_since_epoch().count() == 0) {
                event.timestamp = std::chrono::steady_clock::now();
            }

            // Enrich with process information
            if (event.processId != 0 && event.processPath.empty()) {
                try {
                    Utils::ProcessUtils::ProcessInfo procInfo{};
                    if (Utils::ProcessUtils::GetProcessInfo(event.processId, procInfo)) {
                        event.processPath = procInfo.basic.executablePath;
                    }
                } catch (...) {
                    // Process may have exited
                }
            }

            // Calculate file hash if applicable (capped to MAX_FILE_SIZE_FOR_HASH).
            // We never trust event.fileSize from external producers; we re-stat the file
            // and refuse to hash anything larger than the cap to bound memory and CPU.
            if (!event.targetPath.empty() && event.fileHash.empty()) {
                try {
                    std::error_code ec;
                    if (std::filesystem::exists(event.targetPath, ec) && !ec) {
                        const auto fileSize = std::filesystem::file_size(event.targetPath, ec);
                        if (!ec && fileSize > 0 && fileSize <= kMaxFileSizeForHash) {
                            std::vector<std::byte> fileData;
                            if (Utils::FileUtils::ReadAllBytes(event.targetPath, fileData) && !fileData.empty()) {
                                std::string hexHash;
                                if (Utils::HashUtils::ComputeHex(
                                        Utils::HashUtils::Algorithm::SHA256,
                                        fileData.data(), fileData.size(), hexHash)) {
                                    event.fileHash = std::move(hexHash);
                                }
                            }
                        }
                    }
                } catch (...) {
                    // File may be locked or deleted
                }
            }

            // Check whitelist (external store, if registered) — no fallback to a fresh empty store
            if (m_whitelist) {
                if (!event.processPath.empty()) {
                    auto result = m_whitelist->IsWhitelisted(event.processPath);
                    event.isWhitelisted = result.found;
                }
                if (!event.isWhitelisted && !event.targetPath.empty()) {
                    auto result = m_whitelist->IsWhitelisted(event.targetPath);
                    event.isWhitelisted = result.found;
                }
                if (!event.isWhitelisted && !event.fileHash.empty()) {
                    auto result = m_whitelist->IsHashWhitelisted(event.fileHash,
                        Whitelist::HashAlgorithm::SHA256);
                    event.isWhitelisted = result.found;
                }
            }

            // Local (runtime) whitelist additions made via Whitelist{Process,Hash}()
            if (!event.isWhitelisted) {
                std::shared_lock<std::shared_mutex> lock(m_localWhitelistMutex);
                if (event.processId != 0 &&
                    m_localWhitelistedPids.find(event.processId) != m_localWhitelistedPids.end()) {
                    event.isWhitelisted = true;
                } else if (!event.fileHash.empty()) {
                    // Hash storage is normalized to lower-case to avoid
                    // case-sensitivity bypasses (uppercase hex would miss).
                    std::string lower;
                    lower.reserve(event.fileHash.size());
                    for (char c : event.fileHash) {
                        lower.push_back(static_cast<char>(
                            std::tolower(static_cast<unsigned char>(c))));
                    }
                    if (m_localWhitelistedHashes.find(lower) != m_localWhitelistedHashes.end()) {
                        event.isWhitelisted = true;
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ThreatDetector", L"Event enrichment failed - %ls",
                        Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }

    // Verdict aggregation
    ThreatVerdict AggregateEngineDetections(
        const SystemEvent& event,
        const std::vector<EngineDetection>& detections)
    {
        ThreatVerdict verdict;
        verdict.verdictId = m_nextVerdictId.fetch_add(1, std::memory_order_relaxed);
        verdict.triggeringEventId = event.eventId;
        verdict.processId = event.processId;
        verdict.processPath = event.processPath;
        verdict.filePath = event.targetPath;
        verdict.threatHash = event.fileHash;
        verdict.timestamp = std::chrono::system_clock::now();
        verdict.engineDetections = detections;

        if (detections.empty()) {
            verdict.isThreat = false;
            verdict.threatScore = 0.0;
            verdict.severity = ThreatSeverity::None;
            verdict.category = ThreatCategory::Unknown;
            // No detections: confidence is genuinely unknown, not "Confirmed".
            verdict.confidence = ConfidenceLevel::Unknown;
            verdict.recommendedAction = ResponseAction::None;
            return verdict;
        }

        // Weighted scoring across engines. Aggregate over `detection.score`
        // (the canonical 0..100 score field on EngineDetection); `confidence`
        // is a 0..1 value we use only for the agreement-ratio computation.
        double totalScore = 0.0;
        double totalWeight = 0.0;
        double bestScore = -1.0;
        const EngineDetection* bestDetection = nullptr;

        for (const auto& detection : detections) {
            const double weight = GetEngineWeight(detection.source);
            totalScore += detection.score * weight;
            totalWeight += weight;

            for (const auto& technique : detection.mitreTechniques) {
                if (std::find(verdict.mitreTechniques.begin(), verdict.mitreTechniques.end(), technique) ==
                    verdict.mitreTechniques.end()) {
                    verdict.mitreTechniques.push_back(technique);
                }
            }

            if (detection.score > bestScore) {
                bestScore = detection.score;
                bestDetection = &detection;
            }
        }

        verdict.threatScore = (totalWeight > 0.0) ? (totalScore / totalWeight) : 0.0;
        verdict.isThreat = (verdict.threatScore >= m_config.detectionThreshold);

        if (bestDetection != nullptr) {
            verdict.threatName = bestDetection->detectionName;
            verdict.threatFamily = bestDetection->family;
            verdict.primarySource = bestDetection->source;
        }

        verdict.category = InferCategory(detections);

        // Severity: only label a verdict at all when the score actually
        // crosses the configured detection threshold. Below the threshold
        // we report ThreatSeverity::None so downstream consumers don't see
        // misleading "Low" labels for sub-threshold noise.
        if (!verdict.isThreat) {
            verdict.severity = ThreatSeverity::None;
        } else if (verdict.threatScore >= ThreatDetectorConstants::CRITICAL_THRESHOLD) {
            verdict.severity = ThreatSeverity::Critical;
        } else if (verdict.threatScore >= ThreatDetectorConstants::HIGH_THRESHOLD) {
            verdict.severity = ThreatSeverity::High;
        } else if (verdict.threatScore >= ThreatDetectorConstants::MEDIUM_THRESHOLD) {
            verdict.severity = ThreatSeverity::Medium;
        } else {
            verdict.severity = ThreatSeverity::Low;
        }

        // Engine-agreement based confidence (uses the 0..1 confidence field).
        const size_t positiveDetections = std::count_if(
            detections.begin(), detections.end(),
            [](const EngineDetection& d) { return d.confidence >= 50.0; });
        const double agreementRatio = static_cast<double>(positiveDetections) /
                                      static_cast<double>(detections.size());

        if (agreementRatio >= 0.9) {
            verdict.confidence = ConfidenceLevel::Confirmed;
        } else if (agreementRatio >= 0.7) {
            verdict.confidence = ConfidenceLevel::High;
        } else if (agreementRatio >= 0.5) {
            verdict.confidence = ConfidenceLevel::Medium;
        } else {
            verdict.confidence = ConfidenceLevel::Low;
        }

        // Recommended action keyed off severity (None implies log only).
        switch (verdict.severity) {
            case ThreatSeverity::Critical: verdict.recommendedAction = ResponseAction::Terminate; break;
            case ThreatSeverity::High:     verdict.recommendedAction = ResponseAction::Quarantine; break;
            case ThreatSeverity::Medium:   verdict.recommendedAction = ResponseAction::Block; break;
            case ThreatSeverity::Low:      verdict.recommendedAction = ResponseAction::Alert; break;
            default:                       verdict.recommendedAction = ResponseAction::Log; break;
        }

        if (!event.processPath.empty()) {
            verdict.context.processNames.push_back(
                std::filesystem::path(event.processPath).filename().wstring());
        }
        verdict.processName = !event.processName.empty()
            ? event.processName
            : (!event.processPath.empty()
                ? std::filesystem::path(event.processPath).filename().wstring()
                : L"");
        verdict.userName = event.userName;

        return verdict;
    }

    double GetEngineWeight(DetectionSource source) const noexcept {
        switch (source) {
            case DetectionSource::SignatureEngine:
                return ThreatDetectorConstants::SIGNATURE_WEIGHT;
            case DetectionSource::BehaviorAnalyzer:
                return ThreatDetectorConstants::BEHAVIOR_WEIGHT;
            case DetectionSource::HeuristicAnalyzer:
                return ThreatDetectorConstants::HEURISTIC_WEIGHT;
            case DetectionSource::EmulationEngine:
                return ThreatDetectorConstants::EMULATION_WEIGHT;
            case DetectionSource::ThreatIntel:
                return ThreatDetectorConstants::THREATINTEL_WEIGHT;
            case DetectionSource::MachineLearning:
                return ThreatDetectorConstants::ML_WEIGHT;
            case DetectionSource::PackerDetection:
                return 1.0;
            case DetectionSource::PolymorphicDetection:
                return 1.3;
            case DetectionSource::ZeroDayDetection:
                return 1.8;
            case DetectionSource::SandboxAnalysis:
                return 1.5;
            default:
                return 0.5;
        }
    }

    std::wstring GetEventTypeName(EventType type) const {
        // Simplified implementation - real would use a lookup table
        return L"Event_" + std::to_wstring(static_cast<int>(type));
    }

    std::wstring GetEventCategoryName(EventCategory category) const {
        switch (category) {
            case EventCategory::Process: return L"Process";
            case EventCategory::Thread: return L"Thread";
            case EventCategory::Memory: return L"Memory";
            case EventCategory::File: return L"File";
            case EventCategory::Registry: return L"Registry";
            case EventCategory::Network: return L"Network";
            case EventCategory::Service: return L"Service";
            case EventCategory::WMI: return L"WMI";
            case EventCategory::Script: return L"Script";
            case EventCategory::Driver: return L"Driver";
            case EventCategory::Handle: return L"Handle";
            case EventCategory::Token: return L"Token";
            case EventCategory::COM: return L"COM";
            case EventCategory::Crypto: return L"Crypto";
            case EventCategory::System: return L"System";
            default: return L"Unknown";
        }
    }

    // Attack chain correlation. Idempotent per-process: each PID has at most
    // one active chain; subsequent positive verdicts append to that chain
    // instead of creating a brand-new chain on every call (the prior
    // implementation grew unboundedly).
    void CorrelateAttackChains() {
        try {
            std::lock_guard<std::mutex> chainLock(m_chainsMutex);
            std::shared_lock<std::shared_mutex> threatLock(m_threatsMutex);

            // Group verdicts by process
            std::unordered_map<uint32_t, std::vector<uint64_t>> verdictsByProcess;
            for (const auto& [verdictId, verdict] : m_activeThreats) {
                if (verdict.isThreat) {
                    verdictsByProcess[verdict.processId].push_back(verdictId);
                }
            }

            constexpr size_t kMinChainLength = 3;
            constexpr size_t kMaxAttackChains = 4096;

            for (const auto& [pid, verdictIds] : verdictsByProcess) {
                if (verdictIds.size() < kMinChainLength) {
                    continue;
                }

                AttackChain* chainPtr = nullptr;

                if (auto mapIt = m_processChainMap.find(pid); mapIt != m_processChainMap.end()) {
                    auto chainIt = m_attackChains.find(mapIt->second);
                    if (chainIt != m_attackChains.end()) {
                        chainPtr = &chainIt->second;
                    } else {
                        m_processChainMap.erase(mapIt);
                    }
                }

                bool created = false;
                if (chainPtr == nullptr) {
                    if (m_attackChains.size() >= kMaxAttackChains) {
                        // Cap reached: do not create more chains. Evict the
                        // oldest to make room rather than silently dropping
                        // signal in long-running deployments.
                        auto oldest = m_attackChains.begin();
                        for (auto it = m_attackChains.begin(); it != m_attackChains.end(); ++it) {
                            if (it->second.creationTime < oldest->second.creationTime) {
                                oldest = it;
                            }
                        }
                        if (oldest != m_attackChains.end()) {
                            for (auto victimPid : oldest->second.involvedProcessIds) {
                                m_processChainMap.erase(victimPid);
                            }
                            m_attackChains.erase(oldest);
                        }
                    }

                    AttackChain newChain;
                    newChain.chainId = m_nextChainId.fetch_add(1, std::memory_order_relaxed);
                    newChain.involvedProcessIds.push_back(pid);
                    newChain.creationTime = std::chrono::system_clock::now();
                    auto [insIt, inserted] = m_attackChains.emplace(newChain.chainId, std::move(newChain));
                    chainPtr = &insIt->second;
                    m_processChainMap[pid] = chainPtr->chainId;
                    created = true;
                }

                // Update the chain's verdict and event ID sets without
                // duplicates; assign to the canonical `verdictIds` field on
                // AttackChain (the legacy `eventIds` field is reserved for
                // SystemEvent IDs, not verdict IDs).
                std::set<uint64_t> verdictSet(chainPtr->verdictIds.begin(), chainPtr->verdictIds.end());
                std::set<uint64_t> eventSet(chainPtr->eventIds.begin(), chainPtr->eventIds.end());
                std::set<std::string> techniqueSet(chainPtr->mitreTechniques.begin(), chainPtr->mitreTechniques.end());

                for (auto verdictId : verdictIds) {
                    verdictSet.insert(verdictId);
                    auto it = m_activeThreats.find(verdictId);
                    if (it == m_activeThreats.end()) {
                        continue;
                    }
                    if (it->second.triggeringEventId != 0) {
                        eventSet.insert(it->second.triggeringEventId);
                    }
                    for (const auto& technique : it->second.mitreTechniques) {
                        techniqueSet.insert(technique);
                    }
                }

                chainPtr->verdictIds.assign(verdictSet.begin(), verdictSet.end());
                chainPtr->eventIds.assign(eventSet.begin(), eventSet.end());
                chainPtr->mitreTechniques.assign(techniqueSet.begin(), techniqueSet.end());

                // Severity reflects the highest individual verdict severity
                ThreatSeverity peakSeverity = chainPtr->severity;
                for (auto verdictId : verdictIds) {
                    auto it = m_activeThreats.find(verdictId);
                    if (it != m_activeThreats.end() &&
                        static_cast<int>(it->second.severity) > static_cast<int>(peakSeverity)) {
                        peakSeverity = it->second.severity;
                    }
                }
                chainPtr->severity = peakSeverity;
                chainPtr->confidence = std::min(100.0, 50.0 + 5.0 * static_cast<double>(verdictSet.size()));
                chainPtr->lastUpdateTime = std::chrono::system_clock::now();

                if (created) {
                    m_statistics.activeAttackChains.store(m_attackChains.size(), std::memory_order_relaxed);

                    SS_LOG_WARN(L"ThreatDetector",
                                L"Attack chain detected - ID: %llu, Process: %u, Verdicts: %zu",
                                chainPtr->chainId, pid, chainPtr->verdictIds.size());

                    // Snapshot before invoking external callbacks: never hold
                    // m_callbacksMutex and m_chainsMutex at the same time, and
                    // never run user callbacks while holding m_chainsMutex
                    // (callbacks can re-enter this object).
                    AttackChain snapshot = *chainPtr;
                    threatLock.unlock();
                    std::vector<AttackChainCallback> callbacks;
                    {
                        std::lock_guard<std::mutex> cbLock(m_callbacksMutex);
                        callbacks.reserve(m_chainCallbacks.size());
                        for (const auto& [id, cb] : m_chainCallbacks) {
                            (void)id;
                            callbacks.push_back(cb);
                        }
                    }
                    for (const auto& cb : callbacks) {
                        try { cb(snapshot); } catch (...) { /* isolated */ }
                    }
                    threatLock.lock();
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ThreatDetector", L"Attack chain correlation failed - %ls",
                                Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }
};

// ============================================================================
// Singleton Implementation
// ============================================================================

ThreatDetector& ThreatDetector::Instance() {
    static ThreatDetector instance;
    return instance;
}

// ============================================================================
// Lifecycle
// ============================================================================

ThreatDetector::ThreatDetector()
    : m_impl(std::make_unique<Impl>())
{
    SS_LOG_INFO(L"ThreatDetector", L"Constructor called");
}

ThreatDetector::~ThreatDetector() {
    Shutdown();
    SS_LOG_INFO(L"ThreatDetector", L"Destructor called");
}

bool ThreatDetector::Initialize(
    std::shared_ptr<Utils::ThreadPool> threadPool,
    const ThreatDetectorConfig& config)
{
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"ThreatDetector", L"Already initialized");
        return true;
    }

    try {
        // A disabled configuration is a hard refusal — never partially init.
        if (!config.enabled) {
            SS_LOG_INFO(L"ThreatDetector", L"Disabled via configuration");
            return false;
        }

        m_impl->m_config = config;
        // A null thread pool is permitted; SubmitEvent will fall back to
        // synchronous, in-caller processing in that case (see SubmitEvent).
        m_impl->m_threadPool = std::move(threadPool);

        // Do NOT auto-construct a fresh empty WhitelistStore here. An empty
        // local store would silently mask any real whitelist later wired in
        // via SetWhitelistStore(); leaving m_whitelist null causes
        // EnrichEvent to skip whitelist checks until a real store is set.

        m_impl->m_status.store(ThreatDetectorStatus::Initialized, std::memory_order_release);
        m_impl->m_initialized.store(true, std::memory_order_release);

        SS_LOG_INFO(L"ThreatDetector", L"Initialized successfully (threadPool=%ls)",
                    m_impl->m_threadPool ? L"yes" : L"synchronous");
        return true;

    } catch (const std::exception& e) {
        m_impl->m_status.store(ThreatDetectorStatus::Error, std::memory_order_release);
        SS_LOG_ERROR(L"ThreatDetector", L"Initialization failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

void ThreatDetector::Shutdown() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    // Stop the running flag and wait for in-flight pool tasks to drain
    // BEFORE we acquire the exclusive mutex and start tearing down state
    // those tasks are still reading. Calling Stop() while already holding
    // m_mutex would deadlock: Stop() acquires the same mutex.
    Stop();

    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    try {
        {
            std::unique_lock<std::shared_mutex> threatLock(m_impl->m_threatsMutex);
            m_impl->m_activeThreats.clear();
        }

        {
            std::lock_guard<std::mutex> chainLock(m_impl->m_chainsMutex);
            m_impl->m_attackChains.clear();
            m_impl->m_processChainMap.clear();
        }

        {
            std::lock_guard<std::mutex> ruleLock(m_impl->m_rulesMutex);
            m_impl->m_rules.clear();
        }

        {
            std::lock_guard<std::mutex> cbLock(m_impl->m_callbacksMutex);
            m_impl->m_verdictCallbacks.clear();
            m_impl->m_chainCallbacks.clear();
            m_impl->m_eventCallbacks.clear();
            m_impl->m_responseCallback = nullptr;
        }

        {
            std::unique_lock<std::shared_mutex> wlLock(m_impl->m_localWhitelistMutex);
            m_impl->m_localWhitelistedPids.clear();
            m_impl->m_localWhitelistedHashes.clear();
        }

        m_impl->m_whitelist.reset();

        // Clear engine references
        m_impl->m_behaviorAnalyzer = nullptr;
        m_impl->m_heuristicAnalyzer = nullptr;
        m_impl->m_emulationEngine = nullptr;
        m_impl->m_signatureStore = nullptr;
        m_impl->m_threatIntel = nullptr;
        m_impl->m_mlDetector = nullptr;
        m_impl->m_packerUnpacker = nullptr;
        m_impl->m_polymorphicDetector = nullptr;
        m_impl->m_zeroDayDetector = nullptr;
        m_impl->m_sandboxAnalyzer = nullptr;
        m_impl->m_quarantineManager = nullptr;
        m_impl->m_scanEngine = nullptr;
        m_impl->m_threadPool.reset();

        m_impl->m_status.store(ThreatDetectorStatus::Stopped, std::memory_order_release);
        m_impl->m_initialized.store(false, std::memory_order_release);

        SS_LOG_INFO(L"ThreatDetector", L"Shutdown complete");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Shutdown error - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
    }
}

bool ThreatDetector::Start() {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"ThreatDetector", L"Not initialized");
        return false;
    }

    if (m_impl->m_running.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"ThreatDetector", L"Already running");
        return true;
    }

    try {
        m_impl->m_running.store(true, std::memory_order_release);
        m_impl->m_status.store(ThreatDetectorStatus::Running, std::memory_order_release);

        SS_LOG_INFO(L"ThreatDetector", L"Started successfully");
        return true;

    } catch (const std::exception& e) {
        m_impl->m_status.store(ThreatDetectorStatus::Error, std::memory_order_release);
        SS_LOG_ERROR(L"ThreatDetector", L"Start failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

void ThreatDetector::Stop() {
    if (!m_impl->m_running.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    try {
        m_impl->m_status.store(ThreatDetectorStatus::Stopping, std::memory_order_release);

        // Drain any pool tasks that have already been dispatched. Without
        // this, in-flight tasks may continue to dereference engine pointers
        // that Shutdown() is concurrently clearing, producing tear-down
        // races.
        {
            std::unique_lock<std::mutex> drainLock(m_impl->m_drainMutex);
            const auto drainTimeout = std::chrono::seconds(5);
            m_impl->m_drainCv.wait_for(drainLock, drainTimeout, [this] {
                return m_impl->m_pendingTasks.load(std::memory_order_acquire) == 0;
            });
            if (m_impl->m_pendingTasks.load(std::memory_order_acquire) != 0) {
                SS_LOG_WARN(L"ThreatDetector",
                            L"Stop: %zu task(s) still pending after drain timeout",
                            m_impl->m_pendingTasks.load(std::memory_order_acquire));
            }
        }

        m_impl->m_status.store(ThreatDetectorStatus::Stopped, std::memory_order_release);

        SS_LOG_INFO(L"ThreatDetector", L"Stopped");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Stop error - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
    }
}

bool ThreatDetector::IsInitialized() const noexcept {
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

bool ThreatDetector::IsRunning() const noexcept {
    return m_impl->m_running.load(std::memory_order_acquire);
}

// ============================================================================
// Event Submission
// ============================================================================

bool ThreatDetector::SubmitEvent(SystemEvent event) {
    const auto startTime = std::chrono::steady_clock::now();

    try {
        if (!m_impl->m_running.load(std::memory_order_acquire)) {
            SS_LOG_WARN(L"ThreatDetector", L"Not running, event dropped");
            m_impl->m_statistics.eventsDropped.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // Bound the in-flight depth: we never queue more than
        // EVENT_QUEUE_CAPACITY simultaneously-pending tasks. Going over the
        // cap would let a producer flood unbounded memory at the thread pool.
        if (m_impl->m_pendingTasks.load(std::memory_order_acquire) >=
            ThreatDetectorConstants::EVENT_QUEUE_CAPACITY) {
            SS_LOG_WARN(L"ThreatDetector", L"Event queue full, dropping event");
            m_impl->m_statistics.eventsDropped.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // Enrich event
        m_impl->EnrichEvent(event);

        // Skip whitelisted events early
        if (event.isWhitelisted && m_impl->m_config.applyWhitelist) {
            return true;
        }

        // Track per-category event counts (EventCategory is a dense uint8_t).
        const auto catIdx = static_cast<size_t>(event.category);
        if (catIdx < m_impl->m_statistics.eventsByCategory.size()) {
            m_impl->m_statistics.eventsByCategory[catIdx].fetch_add(1, std::memory_order_relaxed);
        }

        // Snapshot the thread pool under shared lock so we don't race a
        // concurrent Shutdown() that is resetting it.
        std::shared_ptr<Utils::ThreadPool> pool;
        {
            std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
            pool = m_impl->m_threadPool;
        }

        if (pool) {
            m_impl->m_pendingTasks.fetch_add(1, std::memory_order_acq_rel);
            try {
                (void)pool->Submit([this, ev = std::move(event)](const Utils::TaskContext&) mutable {
                    try {
                        if (this->m_impl->m_running.load(std::memory_order_acquire)) {
                            (void)this->ProcessEventInternal(ev);
                        }
                    } catch (...) {
                        // never let an exception escape a pool task
                    }
                    if (this->m_impl->m_pendingTasks.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                        std::lock_guard<std::mutex> drainLock(this->m_impl->m_drainMutex);
                        this->m_impl->m_drainCv.notify_all();
                    }
                });
            } catch (...) {
                // Submit failed: undo the inflight increment and degrade
                // gracefully to inline processing so we don't leak the
                // counter or silently drop the event.
                m_impl->m_pendingTasks.fetch_sub(1, std::memory_order_acq_rel);
                (void)ProcessEventInternal(event);
            }
        } else {
            // Synchronous path: no pool was wired in.
            (void)ProcessEventInternal(event);
        }

        m_impl->m_statistics.totalEventsProcessed.fetch_add(1, std::memory_order_relaxed);

        const auto endTime = std::chrono::steady_clock::now();
        const auto durationUs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count());

        // Exponentially-weighted moving average (alpha = 1/8). The previous
        // implementation overwrote the field with each call, throwing away
        // historical data after every event.
        uint64_t prev = m_impl->m_statistics.avgProcessingTimeUs.load(std::memory_order_relaxed);
        for (;;) {
            const uint64_t next = (prev == 0) ? durationUs : ((prev * 7 + durationUs) / 8);
            if (m_impl->m_statistics.avgProcessingTimeUs.compare_exchange_weak(
                    prev, next, std::memory_order_relaxed, std::memory_order_relaxed)) {
                break;
            }
        }

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Event submission failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

size_t ThreatDetector::SubmitEventBatch(std::vector<SystemEvent> events) {
    size_t submitted = 0;

    for (auto& event : events) {
        if (SubmitEvent(std::move(event))) {
            submitted++;
        }
    }

    return submitted;
}

std::optional<ThreatVerdict> ThreatDetector::AnalyzeEvent(const SystemEvent& event) {
    try {
        if (!m_impl->m_running.load(std::memory_order_acquire)) {
            return std::nullopt;
        }

        SystemEvent enrichedEvent = event;
        m_impl->EnrichEvent(enrichedEvent);

        // Skip whitelisted
        if (enrichedEvent.isWhitelisted && m_impl->m_config.applyWhitelist) {
            return std::nullopt;
        }

        // Snapshot engine pointers and config under shared_lock so we
        // observe a consistent view that cannot be torn out from under us
        // by Set*Engine / Shutdown running concurrently.
        BehaviorAnalyzer*           behavior;
        HeuristicAnalyzer*          heuristic;
        SignatureStore::SignatureStore* signature;
        ThreatIntel::ThreatIntelIndex*  threatIntel;
        MachineLearningDetector*    ml;
        EmulationEngine*            emulation;
        PackerUnpacker*             packer;
        PolymorphicDetector*        polymorphic;
        ZeroDayDetector*            zeroDay;
        SandboxAnalyzer*            sandbox;
        ThreatDetectorConfig        config;
        {
            std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
            behavior     = m_impl->m_behaviorAnalyzer;
            heuristic    = m_impl->m_heuristicAnalyzer;
            signature    = m_impl->m_signatureStore;
            threatIntel  = m_impl->m_threatIntel;
            ml           = m_impl->m_mlDetector;
            emulation    = m_impl->m_emulationEngine;
            packer       = m_impl->m_packerUnpacker;
            polymorphic  = m_impl->m_polymorphicDetector;
            zeroDay      = m_impl->m_zeroDayDetector;
            sandbox      = m_impl->m_sandboxAnalyzer;
            config       = m_impl->m_config;
        }

        std::vector<EngineDetection> detections;
        detections.reserve(10);

        if (behavior && config.enableBehaviorAnalysis) {
            if (auto r = AnalyzeWithBehaviorEngine(enrichedEvent); r.has_value()) {
                detections.push_back(std::move(*r));
            }
        }
        if (heuristic && config.enableHeuristicAnalysis) {
            if (auto r = AnalyzeWithHeuristicEngine(enrichedEvent); r.has_value()) {
                detections.push_back(std::move(*r));
            }
        }
        if (signature && config.enableSignatureMatching) {
            if (auto r = AnalyzeWithSignatureEngine(enrichedEvent); r.has_value()) {
                detections.push_back(std::move(*r));
            }
        }
        if (threatIntel && config.enableThreatIntel) {
            if (auto r = AnalyzeWithThreatIntel(enrichedEvent); r.has_value()) {
                detections.push_back(std::move(*r));
            }
        }
        if (ml && config.enableMLDetection) {
            if (auto r = AnalyzeWithMLEngine(enrichedEvent); r.has_value()) {
                detections.push_back(std::move(*r));
            }
        }
        if (emulation && config.enableEmulationEngine) {
            if (auto r = AnalyzeWithEmulationEngine(enrichedEvent); r.has_value()) {
                detections.push_back(std::move(*r));
            }
        }
        if (packer && config.enablePackerDetection) {
            if (auto r = AnalyzeWithPackerUnpacker(enrichedEvent); r.has_value()) {
                detections.push_back(std::move(*r));
            }
        }
        if (polymorphic && config.enablePolymorphicDetection) {
            if (auto r = AnalyzeWithPolymorphicDetector(enrichedEvent); r.has_value()) {
                detections.push_back(std::move(*r));
            }
        }
        if (zeroDay && config.enableZeroDayDetection) {
            if (auto r = AnalyzeWithZeroDayDetector(enrichedEvent); r.has_value()) {
                detections.push_back(std::move(*r));
            }
        }
        if (sandbox && config.enableSandboxAnalysis) {
            if (auto r = AnalyzeWithSandboxAnalyzer(enrichedEvent); r.has_value()) {
                detections.push_back(std::move(*r));
            }
        }

        // Track detections per source regardless of final verdict severity.
        for (const auto& d : detections) {
            const auto srcIdx = static_cast<size_t>(d.source);
            if (srcIdx < m_impl->m_statistics.detectionsBySource.size()) {
                m_impl->m_statistics.detectionsBySource[srcIdx].fetch_add(1, std::memory_order_relaxed);
            }
        }

        if (detections.empty()) {
            return std::nullopt;
        }

        auto verdict = m_impl->AggregateEngineDetections(enrichedEvent, detections);

        if (verdict.isThreat) {
            std::unique_lock<std::shared_mutex> lock(m_impl->m_threatsMutex);

            // Cap at MAX_ACTIVE_THREATS. When at capacity, evict the
            // oldest verdict to make room rather than dropping the new
            // (potentially more relevant) finding.
            if (m_impl->m_activeThreats.size() >= ThreatDetectorConstants::MAX_ACTIVE_THREATS) {
                auto oldest = m_impl->m_activeThreats.begin();
                for (auto it = m_impl->m_activeThreats.begin(); it != m_impl->m_activeThreats.end(); ++it) {
                    if (it->second.timestamp < oldest->second.timestamp) {
                        oldest = it;
                    }
                }
                if (oldest != m_impl->m_activeThreats.end()) {
                    m_impl->m_activeThreats.erase(oldest);
                }
            }

            m_impl->m_activeThreats[verdict.verdictId] = verdict;
            m_impl->m_statistics.totalThreatsDetected.fetch_add(1, std::memory_order_relaxed);

            const auto catIdx = static_cast<size_t>(verdict.category);
            if (catIdx < m_impl->m_statistics.threatsByCategory.size()) {
                m_impl->m_statistics.threatsByCategory[catIdx].fetch_add(1, std::memory_order_relaxed);
            }

            // Compact severity index — ThreatSeverity uses the sparse
            // 0/25/50/75/100 encoding which would overflow the 8-slot
            // threatsBySeverity array without this mapping.
            const size_t sevIdx = SeverityToIndex(verdict.severity);
            if (sevIdx < m_impl->m_statistics.threatsBySeverity.size()) {
                m_impl->m_statistics.threatsBySeverity[sevIdx].fetch_add(1, std::memory_order_relaxed);
            }
        }

        return verdict;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Event analysis failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return std::nullopt;
    }
}

// ============================================================================
// Internal Event Processing
// ============================================================================

std::optional<ThreatVerdict> ThreatDetector::ProcessEventInternal(const SystemEvent& event) {
    try {
        auto verdict = AnalyzeEvent(event);

        if (verdict.has_value() && verdict->isThreat) {
            SS_LOG_WARN(L"ThreatDetector", L"Threat detected - Verdict: %llu, Process: %u, Score: %.1f",
                              verdict->verdictId,
                              verdict->processId,
                              verdict->threatScore);

            // Invoke verdict callbacks
            {
                std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
                for (const auto& [id, callback] : m_impl->m_verdictCallbacks) {
                    try {
                        callback(verdict.value());
                    } catch (...) {
                        // Callback failure should not affect processing
                    }
                }
            }

            // Periodic attack chain correlation
            if (m_impl->m_config.enableAttackChainCorrelation) {
                if (m_impl->m_statistics.totalThreatsDetected.load() % 10 == 0) {
                    m_impl->CorrelateAttackChains();
                }
            }
        }

        return verdict;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Internal event processing failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return std::nullopt;
    }
}

// ============================================================================
// Helper Methods (file-local, not declared in HPP)
// ============================================================================

namespace {

BehaviorEventType MapToBehaviorEventType(EventType eventType) {
    // ThreatDetector::EventType has its own dense numeric layout; the
    // BehaviorAnalyzer enum has a different layout. Map by semantic
    // equivalence, NOT integer value, and never collapse distinct event
    // classes onto FileCreate (the prior implementation routed every
    // file/registry/network event into FileCreate, breaking pattern
    // detection in BehaviorAnalyzer).
    switch (eventType) {
        // Process
        case EventType::ProcessCreate:        return BehaviorEventType::ProcessCreate;
        case EventType::ProcessTerminate:     return BehaviorEventType::ProcessTerminate;

        // Thread
        case EventType::ThreadCreate:         return BehaviorEventType::ThreadCreate;
        case EventType::ThreadRemoteCreate:   return BehaviorEventType::ThreadRemoteCreate;

        // Memory
        case EventType::MemoryAllocate:       return BehaviorEventType::MemoryAllocate;
        case EventType::MemoryProtect:        return BehaviorEventType::MemoryProtect;
        case EventType::MemoryWrite:
        case EventType::MemoryRemoteWrite:    return BehaviorEventType::MemoryWrite;

        // File
        case EventType::FileCreate:           return BehaviorEventType::FileCreate;
        case EventType::FileWrite:            return BehaviorEventType::FileWrite;
        case EventType::FileDelete:           return BehaviorEventType::FileDelete;
        case EventType::FileRename:           return BehaviorEventType::FileRename;

        // Registry
        case EventType::RegistryCreateKey:    return BehaviorEventType::RegistryCreateKey;
        case EventType::RegistryDeleteKey:    return BehaviorEventType::RegistryDeleteKey;
        case EventType::RegistrySetValue:     return BehaviorEventType::RegistrySetValue;
        case EventType::RegistryDeleteValue:  return BehaviorEventType::RegistryDeleteValue;

        // Network
        case EventType::NetworkConnect:       return BehaviorEventType::NetworkConnect;
        case EventType::NetworkDNSQuery:      return BehaviorEventType::NetworkDNSQuery;

        default:                              return BehaviorEventType::Unknown;
    }
}

std::vector<std::string> MapPatternToMITRE(BehaviorPatternType pattern) {
    std::vector<std::string> techniques;

    switch (pattern) {
        case BehaviorPatternType::RansomwareEncryption:
            techniques.push_back("T1486");
            techniques.push_back("T1490");
            break;
        case BehaviorPatternType::InjectionRemoteThread:
            techniques.push_back("T1055");
            break;
        case BehaviorPatternType::PersistenceRunKey:
            techniques.push_back("T1547");
            break;
        case BehaviorPatternType::CredentialLSASSDump:
            techniques.push_back("T1003");
            break;
        default:
            break;
    }

    return techniques;
}

} // anonymous namespace

// ============================================================================
// Engine Integration - Detection Methods
// ============================================================================

std::optional<EngineDetection> ThreatDetector::AnalyzeWithBehaviorEngine(const SystemEvent& event) {
    try {
        BehaviorEvent behaviorEvent;
        behaviorEvent.eventType = MapToBehaviorEventType(event.eventType);
        if (behaviorEvent.eventType == BehaviorEventType::Unknown) {
            return std::nullopt;
        }
        behaviorEvent.processId       = event.processId;
        behaviorEvent.processName     = event.processName;
        behaviorEvent.processPath     = event.processPath;
        behaviorEvent.commandLine     = event.commandLine;
        behaviorEvent.targetProcessId = event.targetProcessId;
        behaviorEvent.targetPath      = event.targetPath;
        behaviorEvent.remoteHostname  = event.remoteHost;
        behaviorEvent.remoteIP        = event.remoteIP;
        behaviorEvent.remotePort      = event.remotePort;
        behaviorEvent.valueName       = event.valueName;
        behaviorEvent.valueData       = event.valueData;
        behaviorEvent.timestamp       = std::chrono::steady_clock::now();

        auto behaviorVerdict = m_impl->m_behaviorAnalyzer->ProcessEvent(behaviorEvent);
        const auto state = m_impl->m_behaviorAnalyzer->GetProcessState(event.processId);

        // Prefer the explicit verdict the analyzer returned for this event.
        // Fall back to the rolling per-process malice score only when the
        // analyzer didn't surface a discrete verdict.
        const double score = behaviorVerdict.has_value()
            ? std::max<double>(state.maliceScore, 50.0)
            : state.maliceScore;

        if (score < 50.0) {
            return std::nullopt;
        }

        EngineDetection detection;
        detection.source     = DetectionSource::BehaviorAnalyzer;
        detection.confidence = score;
        detection.score      = score;
        detection.details    = L"Behavioral analysis detected malicious activity";
        if (behaviorVerdict.has_value() && !behaviorVerdict->threatName.empty()) {
            detection.detectionName = behaviorVerdict->threatName;
            detection.family        = behaviorVerdict->threatFamily;
        }

        for (const auto& pattern : state.detectedPatterns) {
            auto techniques = MapPatternToMITRE(pattern);
            detection.mitreTechniques.insert(detection.mitreTechniques.end(),
                                             techniques.begin(), techniques.end());
        }

        return detection;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Behavior engine analysis failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return std::nullopt;
    }
}

std::optional<EngineDetection> ThreatDetector::AnalyzeWithHeuristicEngine(const SystemEvent& event) {
    try {
        if (event.category != EventCategory::File || event.targetPath.empty()) {
            return std::nullopt;
        }

        auto result = m_impl->m_heuristicAnalyzer->AnalyzeFile(event.targetPath);

        if (result.riskScore >= 50.0) {
            EngineDetection detection;
            detection.source = DetectionSource::HeuristicAnalyzer;
            detection.confidence = result.riskScore;
            detection.score = result.riskScore;
            detection.details = L"Heuristic analysis detected suspicious patterns";

            for (const auto& indicator : result.indicators) {
                if (!indicator.category.empty()) {
                    detection.mitreTechniques.push_back(indicator.category);
                }
            }

            return detection;
        }

        return std::nullopt;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Heuristic engine analysis failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return std::nullopt;
    }
}

std::optional<EngineDetection> ThreatDetector::AnalyzeWithSignatureEngine(const SystemEvent& event) {
    try {
        if (event.fileHash.empty()) {
            return std::nullopt;
        }

        if (!m_impl->m_signatureStore) {
            return std::nullopt;
        }

        auto result = m_impl->m_signatureStore->LookupHashString(
            event.fileHash, SignatureStore::HashType::SHA256);
        if (result.has_value()) {
            EngineDetection detection;
            detection.source = DetectionSource::SignatureEngine;
            detection.confidence = 100.0;
            detection.score = 100.0;
            detection.details = L"File hash matches known malware signature: "
                + Utils::StringUtils::ToWide(result->signatureName);
            return detection;
        }

        return std::nullopt;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Signature engine analysis failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return std::nullopt;
    }
}

std::optional<EngineDetection> ThreatDetector::AnalyzeWithThreatIntel(const SystemEvent& event) {
    try {
        if (!m_impl->m_threatIntel || event.fileHash.empty()) {
            return std::nullopt;
        }

        // Translate the event's hex hash into a typed HashValue. The
        // previous implementation passed an empty/default-constructed
        // HashValue to LookupHash — which can never match anything in the
        // intel index, so threat-intel hits were impossible by construction.
        auto hashOpt = HexToThreatIntelHash(event.fileHash);
        if (!hashOpt.has_value()) {
            return std::nullopt;
        }

        const auto lookupResult = m_impl->m_threatIntel->LookupHash(*hashOpt);
        if (!lookupResult.found) {
            return std::nullopt;
        }

        EngineDetection detection;
        detection.source     = DetectionSource::ThreatIntel;
        detection.confidence = 90.0;
        detection.score      = 90.0;
        detection.details    = L"Threat intelligence hash match";
        return detection;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Threat intel analysis failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return std::nullopt;
    }
}

std::optional<EngineDetection> ThreatDetector::AnalyzeWithMLEngine(const SystemEvent& event) {
    try {
        if (event.category != EventCategory::File || event.targetPath.empty()) {
            return std::nullopt;
        }

        auto result = m_impl->m_mlDetector->Analyze(std::filesystem::path(event.targetPath));

        if (result.isMalicious) {
            EngineDetection detection;
            detection.source = DetectionSource::MachineLearning;
            detection.confidence = result.probability * 100.0;
            detection.score = result.probability * 100.0;
            detection.details = L"Machine learning classification: malicious";
            return detection;
        }

        return std::nullopt;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"ML engine analysis failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return std::nullopt;
    }
}

std::optional<EngineDetection> ThreatDetector::AnalyzeWithEmulationEngine(const SystemEvent& event) {
    try {
        if (event.category != EventCategory::File || event.targetPath.empty()) {
            return std::nullopt;
        }

        // Read file data for emulation
        std::vector<std::byte> rawData;
        if (!Utils::FileUtils::ReadAllBytes(event.targetPath, rawData) || rawData.empty()) {
            return std::nullopt;
        }

        // Convert to uint8_t for EmulatePE
        std::vector<uint8_t> fileData(rawData.size());
        std::memcpy(fileData.data(), rawData.data(), rawData.size());

        auto result = m_impl->m_emulationEngine->EmulatePE(fileData);
        
        if (result.isMalicious) {
            EngineDetection detection;
            detection.source = DetectionSource::EmulationEngine;
            detection.confidence = result.confidence;
            detection.score = result.confidence;
            detection.details = L"Emulation detected malicious behavior";
            return detection;
        }

        return std::nullopt;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Emulation engine analysis failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return std::nullopt;
    }
}

std::optional<EngineDetection> ThreatDetector::AnalyzeWithPackerUnpacker(const SystemEvent& event) {
    try {
        if (event.category != EventCategory::File || event.targetPath.empty()) {
            return std::nullopt;
        }

        auto result = m_impl->m_packerUnpacker->DetectPacker(
            std::filesystem::path(event.targetPath));
        
        if (result.isPacked) {
            EngineDetection detection;
            detection.source = DetectionSource::PackerDetection;
            detection.confidence = 60.0;
            detection.score = 60.0;
            detection.details = L"Packed executable detected";
            detection.mitreTechniques.push_back("T1027");
            return detection;
        }

        return std::nullopt;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Packer analysis failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return std::nullopt;
    }
}

std::optional<EngineDetection> ThreatDetector::AnalyzeWithPolymorphicDetector(const SystemEvent& event) {
    try {
        if (event.category != EventCategory::File || event.targetPath.empty()) {
            return std::nullopt;
        }

        auto result = m_impl->m_polymorphicDetector->AnalyzeFile(
            std::filesystem::path(event.targetPath));
        
        if (result.isPolymorphic) {
            EngineDetection detection;
            detection.source = DetectionSource::PolymorphicDetection;
            detection.confidence = static_cast<double>(
                static_cast<uint8_t>(result.confidence)) * 25.0;
            detection.score = detection.confidence;
            detection.details = L"Polymorphic malware detected";
            detection.mitreTechniques.push_back("T1027.002");
            return detection;
        }

        return std::nullopt;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Polymorphic detector analysis failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return std::nullopt;
    }
}

std::optional<EngineDetection> ThreatDetector::AnalyzeWithZeroDayDetector(const SystemEvent& event) {
    try {
        if (event.category != EventCategory::File || event.targetPath.empty()) {
            return std::nullopt;
        }

        auto result = m_impl->m_zeroDayDetector->AnalyzeFile(
            std::filesystem::path(event.targetPath));
        
        if (result.detected) {
            EngineDetection detection;
            detection.source = DetectionSource::ZeroDayDetection;
            detection.confidence = static_cast<double>(
                static_cast<uint8_t>(result.confidence)) * 33.0;
            detection.score = detection.confidence;
            detection.details = L"Zero-day exploit detected";
            return detection;
        }

        return std::nullopt;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Zero-day detector analysis failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return std::nullopt;
    }
}

std::optional<EngineDetection> ThreatDetector::AnalyzeWithSandboxAnalyzer(const SystemEvent& event) {
    try {
        if (event.category != EventCategory::File || event.targetPath.empty()) {
            return std::nullopt;
        }

        auto result = m_impl->m_sandboxAnalyzer->Analyze(
            std::filesystem::path(event.targetPath));
        
        if (result.isMalicious) {
            EngineDetection detection;
            detection.source = DetectionSource::SandboxAnalysis;
            detection.confidence = static_cast<double>(result.threatScore);
            detection.score = static_cast<double>(result.threatScore);
            detection.details = L"Sandbox analysis detected malicious behavior";
            return detection;
        }

        return std::nullopt;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Sandbox analyzer failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return std::nullopt;
    }
}

// ============================================================================
// Threat Query API
// ============================================================================

std::vector<ThreatVerdict> ThreatDetector::GetActiveThreats() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_threatsMutex);

    std::vector<ThreatVerdict> threats;
    threats.reserve(m_impl->m_activeThreats.size());

    for (const auto& [id, verdict] : m_impl->m_activeThreats) {
        threats.push_back(verdict);
    }

    // Sort by severity (descending)
    std::sort(threats.begin(), threats.end(),
             [](const ThreatVerdict& a, const ThreatVerdict& b) {
                 return static_cast<int>(a.severity) > static_cast<int>(b.severity);
             });

    return threats;
}

std::vector<ThreatVerdict> ThreatDetector::GetThreatsByProcess(uint32_t processId) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_threatsMutex);

    std::vector<ThreatVerdict> threats;

    for (const auto& [id, verdict] : m_impl->m_activeThreats) {
        if (verdict.processId == processId) {
            threats.push_back(verdict);
        }
    }

    return threats;
}

std::vector<ThreatVerdict> ThreatDetector::GetThreatsBySeverity(ThreatSeverity minSeverity) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_threatsMutex);

    std::vector<ThreatVerdict> threats;

    for (const auto& [id, verdict] : m_impl->m_activeThreats) {
        if (static_cast<int>(verdict.severity) >= static_cast<int>(minSeverity)) {
            threats.push_back(verdict);
        }
    }

    return threats;
}

std::vector<ThreatVerdict> ThreatDetector::GetThreatsByCategory(ThreatCategory category) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_threatsMutex);

    std::vector<ThreatVerdict> threats;

    for (const auto& [id, verdict] : m_impl->m_activeThreats) {
        if (verdict.category == category) {
            threats.push_back(verdict);
        }
    }

    return threats;
}

std::optional<ThreatVerdict> ThreatDetector::GetVerdict(uint64_t verdictId) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_threatsMutex);

    auto it = m_impl->m_activeThreats.find(verdictId);
    if (it != m_impl->m_activeThreats.end()) {
        return it->second;
    }

    return std::nullopt;
}

bool ThreatDetector::HasActiveThreat(uint32_t processId) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_threatsMutex);

    for (const auto& [id, verdict] : m_impl->m_activeThreats) {
        if (verdict.processId == processId) {
            return true;
        }
    }

    return false;
}

double ThreatDetector::GetProcessThreatScore(uint32_t processId) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_threatsMutex);
    double maxScore = 0.0;
    for (const auto& [id, verdict] : m_impl->m_activeThreats) {
        if (verdict.processId == processId && verdict.threatScore > maxScore) {
            maxScore = verdict.threatScore;
        }
    }
    return maxScore;
}

// ============================================================================
// Attack Chain Management
// ============================================================================

std::vector<AttackChain> ThreatDetector::GetActiveAttackChains() const {
    std::lock_guard<std::mutex> lock(m_impl->m_chainsMutex);

    std::vector<AttackChain> chains;
    chains.reserve(m_impl->m_attackChains.size());

    for (const auto& [id, chain] : m_impl->m_attackChains) {
        chains.push_back(chain);
    }

    return chains;
}

std::optional<AttackChain> ThreatDetector::GetAttackChain(uint64_t chainId) const {
    std::lock_guard<std::mutex> lock(m_impl->m_chainsMutex);

    auto it = m_impl->m_attackChains.find(chainId);
    if (it != m_impl->m_attackChains.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::vector<AttackChain> ThreatDetector::GetAttackChainsForProcess(uint32_t processId) const {
    std::lock_guard<std::mutex> lock(m_impl->m_chainsMutex);

    std::vector<AttackChain> result;
    for (const auto& [id, chain] : m_impl->m_attackChains) {
        for (auto pid : chain.involvedProcessIds) {
            if (pid == processId) {
                result.push_back(chain);
                break;
            }
        }
    }
    return result;
}

// ============================================================================
// Rule Management
// ============================================================================

bool ThreatDetector::AddRule(const DetectionRule& rule) {
    try {
        std::lock_guard<std::mutex> lock(m_impl->m_rulesMutex);

        // Hard cap: no rule set should ever exceed MAX_RULES (50,000). Beyond
        // that, lookup performance degrades and memory pressure becomes a
        // denial-of-service vector for an attacker who can influence rule
        // ingestion.
        if (m_impl->m_rules.size() >= ThreatDetectorConstants::MAX_RULES) {
            SS_LOG_WARN(L"ThreatDetector", L"Rule cap reached (%zu); refusing rule %ls",
                        m_impl->m_rules.size(),
                        Utils::StringUtils::ToWide(rule.ruleId).c_str());
            return false;
        }

        if (rule.ruleId.empty()) {
            SS_LOG_WARN(L"ThreatDetector", L"Rejecting rule with empty ID");
            return false;
        }

        if (m_impl->m_rules.count(rule.ruleId) > 0) {
            SS_LOG_WARN(L"ThreatDetector", L"Rule already exists - %ls",
                              Utils::StringUtils::ToWide(rule.ruleId).c_str());
            return false;
        }

        m_impl->m_rules[rule.ruleId] = rule;
        SS_LOG_INFO(L"ThreatDetector", L"Rule added - %ls",
                          Utils::StringUtils::ToWide(rule.ruleId).c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Failed to add rule - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

bool ThreatDetector::RemoveRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(m_impl->m_rulesMutex);

    auto removed = m_impl->m_rules.erase(ruleId);
    if (removed > 0) {
        SS_LOG_INFO(L"ThreatDetector", L"Rule removed - %ls",
                          Utils::StringUtils::ToWide(ruleId).c_str());
        return true;
    }

    return false;
}

void ThreatDetector::SetRuleEnabled(const std::string& ruleId, bool enabled) {
    std::lock_guard<std::mutex> lock(m_impl->m_rulesMutex);

    auto it = m_impl->m_rules.find(ruleId);
    if (it != m_impl->m_rules.end()) {
        it->second.enabled = enabled;
    }
}

std::vector<DetectionRule> ThreatDetector::GetRules() const {
    std::lock_guard<std::mutex> lock(m_impl->m_rulesMutex);

    std::vector<DetectionRule> rules;
    rules.reserve(m_impl->m_rules.size());

    for (const auto& [id, rule] : m_impl->m_rules) {
        rules.push_back(rule);
    }

    return rules;
}

bool ThreatDetector::LoadRulesFromFile(const std::wstring& filePath) {
    // Stub implementation - loading from JSON/YAML rule files
    SS_LOG_INFO(L"ThreatDetector", L"Loading rules from %ls", filePath.c_str());
    return true;
}

bool ThreatDetector::SaveRulesToFile(const std::wstring& filePath) const {
    SS_LOG_INFO(L"ThreatDetector", L"Saving rules to %ls", filePath.c_str());
    return true;
}

// ============================================================================
// Response Actions
// ============================================================================

bool ThreatDetector::ExecuteAction(uint64_t verdictId, ResponseAction action) {
    try {
        auto verdict = GetVerdict(verdictId);
        if (!verdict.has_value()) {
            SS_LOG_ERROR(L"ThreatDetector", L"Verdict not found - %llu", verdictId);
            return false;
        }

        SS_LOG_INFO(L"ThreatDetector", L"Executing action %d for verdict %llu",
                          static_cast<int>(action), verdictId);

        // Snapshot wired-in policy components and the response callback so
        // we never invoke arbitrary user code while holding our own mutexes
        // (callbacks may re-enter ThreatDetector).
        QuarantineManager* quarantineMgr = nullptr;
        ResponseCallback   responseCb;
        {
            std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
            quarantineMgr = m_impl->m_quarantineManager;
        }
        {
            std::lock_guard<std::mutex> cbLock(m_impl->m_callbacksMutex);
            responseCb = m_impl->m_responseCallback;
        }

        bool handled = false;

        if (responseCb) {
            try {
                handled = responseCb(*verdict, action);
            } catch (...) {
                handled = false;
            }
        }

        if (!handled) {
            switch (action) {
                case ResponseAction::Quarantine: {
                    if (quarantineMgr && !verdict->filePath.empty()) {
                        try {
                            (void)quarantineMgr->QuarantineFile(
                                verdict->filePath, verdict->threatName, verdict->processId);
                            handled = true;
                        } catch (const std::exception& qe) {
                            SS_LOG_ERROR(L"ThreatDetector",
                                        L"Quarantine failed for %ls - %ls",
                                        verdict->filePath.c_str(),
                                        Utils::StringUtils::ToWide(qe.what()).c_str());
                        }
                    } else {
                        SS_LOG_WARN(L"ThreatDetector",
                                    L"Quarantine action requested but no QuarantineManager configured (verdict %llu)",
                                    verdictId);
                    }
                    break;
                }

                case ResponseAction::Terminate: {
                    if (verdict->processId != 0) {
                        // PROCESS_TERMINATE is the minimum right needed.
                        // We deliberately do NOT use higher rights — minimum
                        // privilege keeps us least-likely to interfere with
                        // legitimate process state we don't intend to touch.
                        HANDLE h = ::OpenProcess(PROCESS_TERMINATE, FALSE, verdict->processId);
                        if (h != nullptr) {
                            const BOOL ok = ::TerminateProcess(h, 0xDEADBEEF);
                            ::CloseHandle(h);
                            handled = ok != FALSE;
                            if (!ok) {
                                SS_LOG_ERROR(L"ThreatDetector",
                                            L"TerminateProcess failed for PID %u - GLE=%lu",
                                            verdict->processId, ::GetLastError());
                            }
                        } else {
                            SS_LOG_ERROR(L"ThreatDetector",
                                        L"OpenProcess(PROCESS_TERMINATE) failed for PID %u - GLE=%lu",
                                        verdict->processId, ::GetLastError());
                        }
                    }
                    break;
                }

                case ResponseAction::Block:
                case ResponseAction::Alert:
                case ResponseAction::Log:
                case ResponseAction::None:
                default:
                    // No engine-side enforcement; alerting/logging is handled
                    // by the caller via verdict callbacks.
                    handled = true;
                    break;
            }
        }

        const auto actionIdx = static_cast<size_t>(action);
        if (actionIdx < m_impl->m_statistics.actionsTaken.size()) {
            m_impl->m_statistics.actionsTaken[actionIdx].fetch_add(1, std::memory_order_relaxed);
        }

        return handled;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Action execution failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

void ThreatDetector::ReportFalsePositive(uint64_t verdictId, const std::wstring& reason) {
    try {
        auto verdict = GetVerdict(verdictId);
        if (!verdict.has_value()) {
            return;
        }

        SS_LOG_INFO(L"ThreatDetector", L"False positive reported - Verdict: %llu, Reason: %ls",
                          verdictId, reason.c_str());

        m_impl->m_statistics.falsePositives.fetch_add(1, std::memory_order_relaxed);

        // Remove the threat
        {
            std::unique_lock<std::shared_mutex> lock(m_impl->m_threatsMutex);
            m_impl->m_activeThreats.erase(verdictId);
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"Failed to report false positive - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
    }
}

// ============================================================================
// Callbacks
// ============================================================================

uint64_t ThreatDetector::RegisterVerdictCallback(ThreatVerdictCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);

    uint64_t callbackId = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_verdictCallbacks[callbackId] = std::move(callback);

    return callbackId;
}

uint64_t ThreatDetector::RegisterAttackChainCallback(AttackChainCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);

    uint64_t callbackId = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_chainCallbacks[callbackId] = std::move(callback);

    return callbackId;
}

bool ThreatDetector::UnregisterVerdictCallback(uint64_t callbackId) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    return m_impl->m_verdictCallbacks.erase(callbackId) > 0;
}

bool ThreatDetector::UnregisterAttackChainCallback(uint64_t callbackId) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    return m_impl->m_chainCallbacks.erase(callbackId) > 0;
}

void ThreatDetector::SetResponseCallback(ResponseCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    m_impl->m_responseCallback = std::move(callback);
}

// ============================================================================
// Engine Integration - Setters
// ============================================================================

void ThreatDetector::SetBehaviorAnalyzer(BehaviorAnalyzer* analyzer) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_behaviorAnalyzer = analyzer;
    SS_LOG_INFO(L"ThreatDetector", L"BehaviorAnalyzer registered");
}

void ThreatDetector::SetHeuristicAnalyzer(HeuristicAnalyzer* analyzer) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_heuristicAnalyzer = analyzer;
    SS_LOG_INFO(L"ThreatDetector", L"HeuristicAnalyzer registered");
}

void ThreatDetector::SetEmulationEngine(EmulationEngine* engine) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_emulationEngine = engine;
    SS_LOG_INFO(L"ThreatDetector", L"EmulationEngine registered");
}

void ThreatDetector::SetSignatureStore(SignatureStore::SignatureStore* store) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_signatureStore = store;
    SS_LOG_INFO(L"ThreatDetector", L"SignatureStore registered");
}

void ThreatDetector::SetThreatIntelIndex(ThreatIntel::ThreatIntelIndex* index) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_threatIntel = index;
    SS_LOG_INFO(L"ThreatDetector", L"ThreatIntelIndex registered");
}

void ThreatDetector::SetMachineLearningDetector(MachineLearningDetector* detector) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_mlDetector = detector;
    SS_LOG_INFO(L"ThreatDetector", L"MachineLearningDetector registered");
}

void ThreatDetector::SetPackerUnpacker(PackerUnpacker* unpacker) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_packerUnpacker = unpacker;
    SS_LOG_INFO(L"ThreatDetector", L"PackerUnpacker registered");
}

void ThreatDetector::SetPolymorphicDetector(PolymorphicDetector* detector) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_polymorphicDetector = detector;
    SS_LOG_INFO(L"ThreatDetector", L"PolymorphicDetector registered");
}

void ThreatDetector::SetZeroDayDetector(ZeroDayDetector* detector) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_zeroDayDetector = detector;
    SS_LOG_INFO(L"ThreatDetector", L"ZeroDayDetector registered");
}

void ThreatDetector::SetSandboxAnalyzer(SandboxAnalyzer* analyzer) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_sandboxAnalyzer = analyzer;
    SS_LOG_INFO(L"ThreatDetector", L"SandboxAnalyzer registered");
}

// ============================================================================
// Configuration and Statistics
// ============================================================================

ThreatDetectorConfig ThreatDetector::GetConfig() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
    return m_impl->m_config;
}

void ThreatDetector::UpdateConfig(const ThreatDetectorConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_config = config;
    SS_LOG_INFO(L"ThreatDetector", L"Configuration updated");
}

ThreatDetectorStats ThreatDetector::GetStats() const {
    // ThreatDetectorStats contains atomics; copy values manually
    ThreatDetectorStats copy;
    copy.totalEventsProcessed.store(m_impl->m_statistics.totalEventsProcessed.load(std::memory_order_relaxed));
    copy.totalThreatsDetected.store(m_impl->m_statistics.totalThreatsDetected.load(std::memory_order_relaxed));
    copy.eventsDropped.store(m_impl->m_statistics.eventsDropped.load(std::memory_order_relaxed));
    copy.falsePositives.store(m_impl->m_statistics.falsePositives.load(std::memory_order_relaxed));
    copy.avgProcessingTimeUs.store(m_impl->m_statistics.avgProcessingTimeUs.load(std::memory_order_relaxed));
    copy.activeAttackChains.store(m_impl->m_statistics.activeAttackChains.load(std::memory_order_relaxed));
    copy.eventsPerSecond.store(m_impl->m_statistics.eventsPerSecond.load(std::memory_order_relaxed));
    copy.peakEventsPerSecond.store(m_impl->m_statistics.peakEventsPerSecond.load(std::memory_order_relaxed));
    for (size_t i = 0; i < copy.eventsByCategory.size(); ++i) {
        copy.eventsByCategory[i].store(m_impl->m_statistics.eventsByCategory[i].load(std::memory_order_relaxed));
    }
    for (size_t i = 0; i < copy.threatsBySeverity.size(); ++i) {
        copy.threatsBySeverity[i].store(m_impl->m_statistics.threatsBySeverity[i].load(std::memory_order_relaxed));
    }
    for (size_t i = 0; i < copy.threatsByCategory.size(); ++i) {
        copy.threatsByCategory[i].store(m_impl->m_statistics.threatsByCategory[i].load(std::memory_order_relaxed));
    }
    for (size_t i = 0; i < copy.detectionsBySource.size(); ++i) {
        copy.detectionsBySource[i].store(m_impl->m_statistics.detectionsBySource[i].load(std::memory_order_relaxed));
    }
    for (size_t i = 0; i < copy.actionsTaken.size(); ++i) {
        copy.actionsTaken[i].store(m_impl->m_statistics.actionsTaken[i].load(std::memory_order_relaxed));
    }
    return copy;
}

void ThreatDetector::ResetStats() {
    m_impl->m_statistics.Reset();
    SS_LOG_INFO(L"ThreatDetector", L"Statistics reset");
}

size_t ThreatDetector::GetQueueDepth() const noexcept {
    // Returns the number of pool tasks dispatched but not yet completed.
    // The previous queue-mutex/deque path no longer exists; depth is
    // tracked atomically in m_pendingTasks.
    return m_impl->m_pendingTasks.load(std::memory_order_acquire);
}

// ============================================================================
// Process Management
// ============================================================================

void ThreatDetector::OnProcessCreate(uint32_t processId, uint32_t parentProcessId,
                                     const std::wstring& imagePath) {
    (void)processId;
    (void)parentProcessId;
    (void)imagePath;
}

void ThreatDetector::OnProcessTerminate(uint32_t processId) {
    if (processId == 0) {
        return;
    }
    try {
        // Drop active threats keyed to this process — they are no longer
        // actionable and otherwise leak indefinitely.
        {
            std::unique_lock<std::shared_mutex> lock(m_impl->m_threatsMutex);
            for (auto it = m_impl->m_activeThreats.begin(); it != m_impl->m_activeThreats.end();) {
                if (it->second.processId == processId) {
                    it = m_impl->m_activeThreats.erase(it);
                } else {
                    ++it;
                }
            }
        }
        // Close any open attack chain for this PID.
        {
            std::lock_guard<std::mutex> lock(m_impl->m_chainsMutex);
            auto mapIt = m_impl->m_processChainMap.find(processId);
            if (mapIt != m_impl->m_processChainMap.end()) {
                m_impl->m_attackChains.erase(mapIt->second);
                m_impl->m_processChainMap.erase(mapIt);
                m_impl->m_statistics.activeAttackChains.store(
                    m_impl->m_attackChains.size(), std::memory_order_relaxed);
            }
        }
        // Drop any local-whitelist PID entry so reused PIDs aren't trusted.
        {
            std::unique_lock<std::shared_mutex> lock(m_impl->m_localWhitelistMutex);
            m_impl->m_localWhitelistedPids.erase(processId);
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreatDetector", L"OnProcessTerminate failed - %ls",
                    Utils::StringUtils::ToWide(e.what()).c_str());
    }
}

void ThreatDetector::ResetProcessState(uint32_t processId) {
    OnProcessTerminate(processId);
}

// ============================================================================
// Whitelist Integration
// ============================================================================

void ThreatDetector::WhitelistProcess(uint32_t processId) {
    if (processId == 0) {
        return;
    }
    std::unique_lock<std::shared_mutex> lock(m_impl->m_localWhitelistMutex);
    m_impl->m_localWhitelistedPids.insert(processId);
    SS_LOG_INFO(L"ThreatDetector", L"Process %u whitelisted (local)", processId);
}

void ThreatDetector::WhitelistHash(const std::string& hash) {
    if (hash.empty()) {
        return;
    }
    // Normalize to lower-case so callers can supply either case without
    // splitting the local whitelist set.
    std::string normalized;
    normalized.reserve(hash.size());
    for (char c : hash) {
        normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    std::unique_lock<std::shared_mutex> lock(m_impl->m_localWhitelistMutex);
    m_impl->m_localWhitelistedHashes.insert(std::move(normalized));
    SS_LOG_INFO(L"ThreatDetector", L"Hash whitelisted (local)");
}

void ThreatDetector::SetWhitelistStore(Whitelist::WhitelistStore* store) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    if (store) {
        // Externally-owned: aliasing shared_ptr with a no-op deleter so the
        // ThreatDetector cannot accidentally destroy a store it doesn't own.
        m_impl->m_whitelist = std::shared_ptr<Whitelist::WhitelistStore>(store, [](Whitelist::WhitelistStore*){});
    } else {
        m_impl->m_whitelist.reset();
    }
    SS_LOG_INFO(L"ThreatDetector", L"WhitelistStore registered");
}

void ThreatDetector::SetQuarantineManager(QuarantineManager* manager) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_quarantineManager = manager;
    SS_LOG_INFO(L"ThreatDetector", L"QuarantineManager registered");
}

void ThreatDetector::SetScanEngine(ScanEngine* engine) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_scanEngine = engine;
    SS_LOG_INFO(L"ThreatDetector", L"ScanEngine registered");
}

// ============================================================================
// Additional HPP-declared Initialize overloads
// ============================================================================

bool ThreatDetector::Initialize() {
    return Initialize(nullptr, ThreatDetectorConfig::CreateDefault());
}

bool ThreatDetector::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool) {
    return Initialize(std::move(threadPool), ThreatDetectorConfig::CreateDefault());
}

}  // namespace Engine
}  // namespace Core
}  // namespace ShadowStrike
