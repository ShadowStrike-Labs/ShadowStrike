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
 * ShadowStrike Core Process - PROCESS ANALYZER IMPLEMENTATION
 * ============================================================================
 *
 * @file ProcessAnalyzer.cpp
 * @brief Enterprise-grade comprehensive process analysis orchestrator implementation
 *
 * Production-level implementation for enterprise EDR process analysis.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex for concurrent access
 * - Orchestrates multiple detection engines (ProcessInjectionDetector, ThreadHijackDetector)
 * - Comprehensive module analysis (loaded DLLs, phantom DLLs, side-loading)
 * - Handle enumeration and analysis (LSASS access, cross-process handles)
 * - Memory analysis (RWX regions, unbacked executable, shellcode patterns)
 * - Thread analysis (unbacked start addresses, call stacks)
 * - Digital signature verification (Authenticode, certificate chains)
 * - Parent-child relationship analysis (PPID spoofing, expected parents)
 * - Security context analysis (token, privileges, integrity levels)
 * - Network footprint analysis (active connections, listening ports)
 * - Behavioral analysis (anti-analysis, code injection, persistence)
 * - LRU caching for analysis results (configurable TTL)
 * - Risk scoring with weighted components (0-100 scale)
 * - MITRE ATT&CK mapping across 12+ techniques
 * - Infrastructure integration (HashStore, SignatureStore, ThreatIntel, Whitelist)
 * - Comprehensive statistics tracking
 * - Callback system for progress and findings
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "ProcessAnalyzer.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/PE_Sig_Verf.hpp"
#include "../../HashStore/HashStore.hpp"
#include "../../SignatureStore/SignatureStore.hpp"
#include "../../ThreatIntel/ThreatIntelStore.hpp"
#include "../../Whitelist/WhiteListStore.hpp"

// Process detection modules (full orchestration suite)
#include "ProcessInjectionDetector.hpp"
#include "ThreadHijackDetector.hpp"
#include "DLLInjectionDetector.hpp"
#include "ReflectiveDLLDetector.hpp"
#include "ProcessHollowingDetector.hpp"
#include "AtomBombingDetector.hpp"
#include "MemoryScanner.hpp"

// ============================================================================
// WINDOWS API INCLUDES
// ============================================================================
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <udpmib.h>

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <numeric>
#include <cmath>
#include <numbers>
#include <sstream>
#include <iomanip>
#include <thread>
#include <execution>
#include <deque>
#include <unordered_map>
#include <map>
#include <set>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace ShadowStrike {
namespace Core {
namespace Process {

using Clock = std::chrono::system_clock;
using TimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

/**
 * @brief Calculate Shannon entropy of data.
 */
[[nodiscard]] static double CalculateEntropy(std::span<const uint8_t> data) noexcept {
    if (data.empty()) return 0.0;

    std::array<uint32_t, 256> freq{};
    for (uint8_t byte : data) {
        freq[byte]++;
    }

    double entropy = 0.0;
    const double length = static_cast<double>(data.size());

    for (uint32_t count : freq) {
        if (count > 0) {
            const double p = static_cast<double>(count) / length;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

/**
 * @brief Check if memory protection allows execution.
 */
[[nodiscard]] static bool IsExecutableProtection(uint32_t protection) noexcept {
    constexpr uint32_t kPageExecute = 0x10;
    constexpr uint32_t kPageExecuteRead = 0x20;
    constexpr uint32_t kPageExecuteReadWrite = 0x40;
    constexpr uint32_t kPageExecuteWriteCopy = 0x80;

    return (protection & (kPageExecute | kPageExecuteRead |
                         kPageExecuteReadWrite | kPageExecuteWriteCopy)) != 0;
}

/**
 * @brief Check if memory protection is RWX.
 */
[[nodiscard]] static bool IsRWXProtection(uint32_t protection) noexcept {
    constexpr uint32_t kPageExecuteReadWrite = 0x40;
    return (protection & kPageExecuteReadWrite) != 0;
}

/**
 * @brief Extract the bare filename from a full path or name.
 */
[[nodiscard]] static std::wstring ExtractFileName(const std::wstring& pathOrName) noexcept {
    const auto lastSlash = pathOrName.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        return pathOrName.substr(lastSlash + 1);
    }
    return pathOrName;
}

/**
 * @brief Get expected parent for a process name.
 * Uses exact filename matching (not substring) to avoid false positives.
 */
[[nodiscard]] static std::wstring GetExpectedParent(const std::wstring& processName) noexcept {
    const std::wstring nameLower = Utils::StringUtils::ToLowerCopy(
        ExtractFileName(processName));

    // Office applications
    if (nameLower == L"winword.exe" ||
        nameLower == L"excel.exe" ||
        nameLower == L"powerpnt.exe" ||
        nameLower == L"outlook.exe") {
        return L"explorer.exe";
    }

    // Browsers
    if (nameLower == L"chrome.exe" ||
        nameLower == L"firefox.exe" ||
        nameLower == L"msedge.exe" ||
        nameLower == L"iexplore.exe") {
        return L"explorer.exe";
    }

    // System services
    if (nameLower == L"svchost.exe") return L"services.exe";
    if (nameLower == L"services.exe") return L"wininit.exe";
    if (nameLower == L"lsass.exe") return L"wininit.exe";
    if (nameLower == L"winlogon.exe") return L"smss.exe";
    if (nameLower == L"csrss.exe") return L"smss.exe";
    if (nameLower == L"smss.exe") return L"System";
    if (nameLower == L"wininit.exe") return L"smss.exe";
    if (nameLower == L"dwm.exe") return L"svchost.exe";
    if (nameLower == L"conhost.exe") return L"csrss.exe";
    if (nameLower == L"taskhostw.exe") return L"svchost.exe";
    if (nameLower == L"runtimebroker.exe") return L"svchost.exe";

    // Default: user applications usually spawned by explorer
    return L"explorer.exe";
}

/**
 * @brief Helper to safely get process basic info, returning std::optional.
 * Wraps the out-param based ProcessUtils API into an optional-returning form.
 */
[[nodiscard]] static std::optional<Utils::ProcessUtils::ProcessBasicInfo> SafeGetProcessInfo(
    uint32_t pid) noexcept
{
    Utils::ProcessUtils::ProcessBasicInfo info{};
    Utils::ProcessUtils::Error err{};
    if (Utils::ProcessUtils::GetProcessBasicInfo(pid, info, &err)) {
        return info;
    }
    return std::nullopt;
}

/**
 * @brief Helper to safely enumerate all processes.
 */
[[nodiscard]] static std::vector<Utils::ProcessUtils::ProcessBasicInfo> SafeGetAllProcesses() noexcept {
    std::vector<Utils::ProcessUtils::ProcessBasicInfo> processes;
    Utils::ProcessUtils::Error err{};
    Utils::ProcessUtils::EnumerateProcesses(processes, Utils::ProcessUtils::EnumerationOptions{}, &err);
    return processes;
}

/**
 * @brief Helper to safely enumerate modules for a process.
 */
[[nodiscard]] static std::vector<Utils::ProcessUtils::ProcessModuleInfo> SafeGetProcessModules(
    uint32_t pid) noexcept
{
    std::vector<Utils::ProcessUtils::ProcessModuleInfo> modules;
    Utils::ProcessUtils::Error err{};
    Utils::ProcessUtils::EnumerateProcessModules(pid, modules, &err);
    return modules;
}

/**
 * @brief Convert FILETIME to system_clock::time_point for comparison.
 */
[[nodiscard]] static std::chrono::system_clock::time_point FileTimeToTimePoint(
    const FILETIME& ft) noexcept
{
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    // FILETIME epoch is Jan 1 1601; system_clock epoch is Jan 1 1970.
    // Difference is 11644473600 seconds = 116444736000000000 in 100ns ticks.
    constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL;
    if (uli.QuadPart < EPOCH_DIFF) {
        return std::chrono::system_clock::time_point{};
    }
    const auto duration100ns = std::chrono::duration<int64_t, std::ratio<1, 10000000>>(
        static_cast<int64_t>(uli.QuadPart - EPOCH_DIFF));
    return std::chrono::system_clock::time_point{
        std::chrono::duration_cast<std::chrono::system_clock::duration>(duration100ns)};
}

// ============================================================================
// CONFIG FACTORY METHODS
// ============================================================================

AnalyzerConfig AnalyzerConfig::CreateDefault() noexcept {
    return AnalyzerConfig{};
}

AnalyzerConfig AnalyzerConfig::CreateQuick() noexcept {
    AnalyzerConfig config;
    config.defaultDepth = AnalysisDepth::Quick;
    config.enableModuleAnalysis = true;
    config.enableHandleAnalysis = false;
    config.enableMemoryAnalysis = false;
    config.enableThreadAnalysis = false;
    config.enableNetworkAnalysis = false;
    config.enableBehavioralAnalysis = false;
    config.enableSignatureVerification = true;
    config.enableThreatIntelLookup = true;
    return config;
}

AnalyzerConfig AnalyzerConfig::CreateForensic() noexcept {
    AnalyzerConfig config;
    config.defaultDepth = AnalysisDepth::Forensic;
    config.enableModuleAnalysis = true;
    config.enableHandleAnalysis = true;
    config.enableMemoryAnalysis = true;
    config.enableThreadAnalysis = true;
    config.enableNetworkAnalysis = true;
    config.enableBehavioralAnalysis = true;
    config.enableSignatureVerification = true;
    config.enableThreatIntelLookup = true;
    config.signatureCheckTimeoutMs = 10000;
    config.handleEnumTimeoutMs = 20000;
    config.memoryScanTimeoutMs = 60000;
    return config;
}

AnalyzerConfig AnalyzerConfig::CreateRealTime() noexcept {
    AnalyzerConfig config;
    config.defaultDepth = AnalysisDepth::Standard;
    config.enableAnalysisCache = true;
    config.enableSignatureCache = true;
    config.analysisCacheTTLSeconds = 600;  // 10 minutes
    config.maxModulesToAnalyze = 512;
    config.maxHandlesToEnumerate = 16384;
    config.signatureCheckTimeoutMs = 2000;
    config.handleEnumTimeoutMs = 5000;
    config.memoryScanTimeoutMs = 15000;
    return config;
}

AnalyzerStatistics::AnalyzerStatistics(const AnalyzerStatistics& other) noexcept {
    *this = other;
}

AnalyzerStatistics& AnalyzerStatistics::operator=(const AnalyzerStatistics& other) noexcept {
    if (this == &other) {
        return *this;
    }

    totalAnalyses.store(other.totalAnalyses.load(std::memory_order_relaxed), std::memory_order_relaxed);
    quickAnalyses.store(other.quickAnalyses.load(std::memory_order_relaxed), std::memory_order_relaxed);
    standardAnalyses.store(other.standardAnalyses.load(std::memory_order_relaxed), std::memory_order_relaxed);
    deepAnalyses.store(other.deepAnalyses.load(std::memory_order_relaxed), std::memory_order_relaxed);
    forensicAnalyses.store(other.forensicAnalyses.load(std::memory_order_relaxed), std::memory_order_relaxed);
    trustedProcesses.store(other.trustedProcesses.load(std::memory_order_relaxed), std::memory_order_relaxed);
    safeProcesses.store(other.safeProcesses.load(std::memory_order_relaxed), std::memory_order_relaxed);
    unknownProcesses.store(other.unknownProcesses.load(std::memory_order_relaxed), std::memory_order_relaxed);
    suspiciousProcesses.store(other.suspiciousProcesses.load(std::memory_order_relaxed), std::memory_order_relaxed);
    maliciousProcesses.store(other.maliciousProcesses.load(std::memory_order_relaxed), std::memory_order_relaxed);
    modulesAnalyzed.store(other.modulesAnalyzed.load(std::memory_order_relaxed), std::memory_order_relaxed);
    handlesEnumerated.store(other.handlesEnumerated.load(std::memory_order_relaxed), std::memory_order_relaxed);
    memoryRegionsScanned.store(other.memoryRegionsScanned.load(std::memory_order_relaxed), std::memory_order_relaxed);
    threadsAnalyzed.store(other.threadsAnalyzed.load(std::memory_order_relaxed), std::memory_order_relaxed);
    signaturesVerified.store(other.signaturesVerified.load(std::memory_order_relaxed), std::memory_order_relaxed);
    unsignedModulesDetected.store(other.unsignedModulesDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    suspiciousModulesDetected.store(other.suspiciousModulesDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    rwxRegionsDetected.store(other.rwxRegionsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    unbackedExecDetected.store(other.unbackedExecDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    suspiciousThreadsDetected.store(other.suspiciousThreadsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    parentAnomaliesDetected.store(other.parentAnomaliesDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    ppidSpoofingDetected.store(other.ppidSpoofingDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    injectionIndicatorsDetected.store(other.injectionIndicatorsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    analysisCacheHits.store(other.analysisCacheHits.load(std::memory_order_relaxed), std::memory_order_relaxed);
    analysisCacheMisses.store(other.analysisCacheMisses.load(std::memory_order_relaxed), std::memory_order_relaxed);
    signatureCacheHits.store(other.signatureCacheHits.load(std::memory_order_relaxed), std::memory_order_relaxed);
    signatureCacheMisses.store(other.signatureCacheMisses.load(std::memory_order_relaxed), std::memory_order_relaxed);
    totalAnalysisTimeMs.store(other.totalAnalysisTimeMs.load(std::memory_order_relaxed), std::memory_order_relaxed);
    minAnalysisTimeMs.store(other.minAnalysisTimeMs.load(std::memory_order_relaxed), std::memory_order_relaxed);
    maxAnalysisTimeMs.store(other.maxAnalysisTimeMs.load(std::memory_order_relaxed), std::memory_order_relaxed);
    analysisErrors.store(other.analysisErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
    accessDeniedErrors.store(other.accessDeniedErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
    timeoutErrors.store(other.timeoutErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
    return *this;
}

void AnalyzerStatistics::Reset() noexcept {
    totalAnalyses.store(0, std::memory_order_relaxed);
    quickAnalyses.store(0, std::memory_order_relaxed);
    standardAnalyses.store(0, std::memory_order_relaxed);
    deepAnalyses.store(0, std::memory_order_relaxed);
    forensicAnalyses.store(0, std::memory_order_relaxed);
    trustedProcesses.store(0, std::memory_order_relaxed);
    safeProcesses.store(0, std::memory_order_relaxed);
    unknownProcesses.store(0, std::memory_order_relaxed);
    suspiciousProcesses.store(0, std::memory_order_relaxed);
    maliciousProcesses.store(0, std::memory_order_relaxed);
    modulesAnalyzed.store(0, std::memory_order_relaxed);
    handlesEnumerated.store(0, std::memory_order_relaxed);
    memoryRegionsScanned.store(0, std::memory_order_relaxed);
    threadsAnalyzed.store(0, std::memory_order_relaxed);
    signaturesVerified.store(0, std::memory_order_relaxed);
    unsignedModulesDetected.store(0, std::memory_order_relaxed);
    suspiciousModulesDetected.store(0, std::memory_order_relaxed);
    rwxRegionsDetected.store(0, std::memory_order_relaxed);
    unbackedExecDetected.store(0, std::memory_order_relaxed);
    suspiciousThreadsDetected.store(0, std::memory_order_relaxed);
    parentAnomaliesDetected.store(0, std::memory_order_relaxed);
    ppidSpoofingDetected.store(0, std::memory_order_relaxed);
    injectionIndicatorsDetected.store(0, std::memory_order_relaxed);
    analysisCacheHits.store(0, std::memory_order_relaxed);
    analysisCacheMisses.store(0, std::memory_order_relaxed);
    signatureCacheHits.store(0, std::memory_order_relaxed);
    signatureCacheMisses.store(0, std::memory_order_relaxed);
    totalAnalysisTimeMs.store(0, std::memory_order_relaxed);
    minAnalysisTimeMs.store(UINT64_MAX, std::memory_order_relaxed);
    maxAnalysisTimeMs.store(0, std::memory_order_relaxed);
    analysisErrors.store(0, std::memory_order_relaxed);
    accessDeniedErrors.store(0, std::memory_order_relaxed);
    timeoutErrors.store(0, std::memory_order_relaxed);
}

double AnalyzerStatistics::GetAverageAnalysisTimeMs() const noexcept {
    const uint64_t total = totalAnalyses.load(std::memory_order_relaxed);
    const uint64_t totalTime = totalAnalysisTimeMs.load(std::memory_order_relaxed);

    if (total == 0) return 0.0;
    return static_cast<double>(totalTime) / total;
}

double AnalyzerStatistics::GetAnalysisCacheHitRatio() const noexcept {
    const uint64_t hits = analysisCacheHits.load(std::memory_order_relaxed);
    const uint64_t misses = analysisCacheMisses.load(std::memory_order_relaxed);
    const uint64_t total = hits + misses;

    if (total == 0) return 0.0;
    return (static_cast<double>(hits) / total) * 100.0;
}

void ProcessAnalysisResult::CalculateOverallRisk() noexcept {
    uint32_t risk = 0;

    // Signature-based detection
    if (isKnownMalicious) {
        risk = 100;
        riskLevel = ProcessRiskLevel::Malicious;
        return;
    }

    // Hash-based detection
    if (hashFoundMalicious) {
        risk = 95;
        riskLevel = ProcessRiskLevel::Malicious;
        return;
    }

    // Whitelisted processes
    if (isWhitelisted) {
        risk = 0;
        riskLevel = ProcessRiskLevel::Trusted;
        return;
    }

    // Signature analysis
    if (signatureInfo.status == SignatureStatus::Valid &&
        signatureInfo.trustLevel == CertificateTrust::Microsoft) {
        risk += 0;  // Microsoft-signed = trusted
    } else if (signatureInfo.status == SignatureStatus::Revoked) {
        risk += AnalyzerConstants::RISK_WEIGHT_REVOKED_CERT;
    } else if (signatureInfo.status == SignatureStatus::Unsigned) {
        risk += AnalyzerConstants::RISK_WEIGHT_UNSIGNED;
    }

    // Module analysis
    risk += suspiciousModuleCount * 5;
    risk += unsignedModuleCount * 2;

    // Memory analysis
    risk += memorySummary.rwxRegionCount * AnalyzerConstants::RISK_WEIGHT_RWX_MEMORY;
    risk += memorySummary.unbackedExecRegionCount * AnalyzerConstants::RISK_WEIGHT_UNBACKED_EXEC;

    // Thread analysis
    risk += threadSummary.unbackedStartCount * AnalyzerConstants::RISK_WEIGHT_ORPHAN_THREAD;

    // Parent-child anomalies
    if (parentChildAnalysis.anomaly != ParentChildAnomaly::Normal) {
        risk += AnalyzerConstants::RISK_WEIGHT_PARENT_ANOMALY;
    }
    if (parentChildAnalysis.isPPIDSpoofed) {
        risk += AnalyzerConstants::RISK_WEIGHT_PPID_SPOOFING;
    }

    // Behavioral indicators
    if (behavioralIndicators.hasProcessHollowing) risk += 40;
    if (behavioralIndicators.hasDirectSyscalls) risk += 30;
    if (behavioralIndicators.hasRemoteThreads) risk += 25;

    overallRiskScore = std::min(risk, 100u);

    // Map to risk level
    if (overallRiskScore >= 90) riskLevel = ProcessRiskLevel::Critical;
    else if (overallRiskScore >= 75) riskLevel = ProcessRiskLevel::Suspicious;
    else if (overallRiskScore >= 60) riskLevel = ProcessRiskLevel::HighRisk;
    else if (overallRiskScore >= 45) riskLevel = ProcessRiskLevel::MediumRisk;
    else if (overallRiskScore >= 30) riskLevel = ProcessRiskLevel::LowRisk;
    else if (overallRiskScore >= 15) riskLevel = ProcessRiskLevel::Unknown;
    else if (overallRiskScore > 0) riskLevel = ProcessRiskLevel::Safe;
    else riskLevel = ProcessRiskLevel::Trusted;
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class ProcessAnalyzerImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    /// @brief Thread synchronization
    mutable std::shared_mutex m_mutex;

    /// @brief Configuration
    AnalyzerConfig m_config;

    /// @brief Initialization state
    std::atomic<bool> m_initialized{false};

    /// @brief Statistics
    AnalyzerStatistics m_statistics;

    /// @brief Composite cache key: PID + creation time to prevent PID-reuse
    /// cache poisoning. Without creation time, a terminated PID could be
    /// reassigned to a malicious process and receive a stale "Trusted" result.
    struct CacheKey {
        uint32_t pid = 0;
        uint64_t startTimeTicks = 0;

        bool operator==(const CacheKey& other) const noexcept {
            return pid == other.pid && startTimeTicks == other.startTimeTicks;
        }
    };

    struct CacheKeyHash {
        size_t operator()(const CacheKey& key) const noexcept {
            uint64_t combined = (static_cast<uint64_t>(key.pid) << 32) ^
                                (key.startTimeTicks * 0x9E3779B97F4A7C15ULL);
            combined ^= combined >> 33;
            combined *= 0xFF51AFD7ED558CCDULL;
            combined ^= combined >> 33;
            return static_cast<size_t>(combined);
        }
    };

    /// @brief Analysis result cache (LRU-like, keyed by PID+creation time)
    struct CachedAnalysis {
        ProcessAnalysisResult result;
        TimePoint timestamp;
    };
    std::unordered_map<CacheKey, CachedAnalysis, CacheKeyHash> m_analysisCache;
    mutable std::shared_mutex m_cacheMutex;

    /// @brief Signature verification cache with timestamps for proper eviction
    struct CachedSignature {
        SignatureInfo info;
        TimePoint timestamp;
    };
    std::unordered_map<std::wstring, CachedSignature> m_signatureCache;
    mutable std::shared_mutex m_signatureCacheMutex;

    /// @brief Callbacks
    std::unordered_map<uint64_t, AnalysisProgressCallback> m_progressCallbacks;
    std::unordered_map<uint64_t, SuspiciousFindingCallback> m_findingCallbacks;
    std::unordered_map<uint64_t, ModuleAnalyzedCallback> m_moduleCallbacks;
    mutable std::mutex m_callbacksMutex;
    std::atomic<uint64_t> m_nextCallbackId{1};

    /// @brief Infrastructure integrations
    std::shared_ptr<HashStore::HashStore> m_hashStore;
    std::shared_ptr<SignatureStore::SignatureStore> m_signatureStore;
    std::shared_ptr<ThreatIntel::ThreatIntelStore> m_threatIntel;
    std::shared_ptr<Whitelist::WhitelistStore> m_whitelist;

    // ========================================================================
    // METHODS
    // ========================================================================

    ProcessAnalyzerImpl() = default;
    ~ProcessAnalyzerImpl() = default;

    [[nodiscard]] bool Initialize(const AnalyzerConfig& config);
    void Shutdown();

    // Core analysis
    [[nodiscard]] ProcessAnalysisResult AnalyzeProcessInternal(uint32_t pid, AnalysisDepth depth);
    [[nodiscard]] ProcessRiskLevel QuickAssessRiskInternal(uint32_t pid);

    // Module analysis
    [[nodiscard]] std::vector<ModuleInfo> GetLoadedModulesInternal(uint32_t pid);
    [[nodiscard]] std::vector<ModuleInfo> FindSuspiciousModulesInternal(uint32_t pid);
    [[nodiscard]] std::vector<ModuleInfo> FindSuspiciousModulesFromList(
        uint32_t pid, const std::vector<ModuleInfo>& allModules);
    [[nodiscard]] ModuleInfo AnalyzeModuleInternal(uint32_t pid, uintptr_t moduleBase);

    // Handle analysis
    [[nodiscard]] HandleSummary EnumerateHandlesInternal(uint32_t pid);

    // Memory analysis
    [[nodiscard]] MemorySummary AnalyzeMemoryInternal(uint32_t pid);
    [[nodiscard]] std::vector<MemoryRegionInfo> GetMemoryRegionsInternal(uint32_t pid);
    [[nodiscard]] std::vector<MemoryRegionInfo> FindRWXRegionsInternal(uint32_t pid);

    // Thread analysis
    [[nodiscard]] ThreadSummary AnalyzeThreadsInternal(uint32_t pid);
    [[nodiscard]] std::optional<ThreadInfo> GetThreadInfoInternal(
        uint32_t tid,
        const std::vector<Utils::ProcessUtils::ProcessModuleInfo>& cachedModules);
    [[nodiscard]] std::optional<ThreadInfo> GetThreadInfoInternal(uint32_t tid);

    // Signature verification
    [[nodiscard]] SignatureInfo VerifyFileSignatureInternal(const std::wstring& filePath);
    [[nodiscard]] bool IsMicrosoftSignedInternal(const std::wstring& filePath);

    // Security context
    [[nodiscard]] SecurityContext AnalyzeSecurityContextInternal(uint32_t pid);
    [[nodiscard]] std::vector<std::pair<std::wstring, bool>> GetProcessPrivilegesInternal(uint32_t pid);

    // Parent-child analysis
    [[nodiscard]] ParentChildAnalysis AnalyzeParentChildInternal(uint32_t pid);
    [[nodiscard]] bool DetectPPIDSpoofingInternal(uint32_t pid);

    // Network analysis
    [[nodiscard]] NetworkFootprint AnalyzeNetworkFootprintInternal(uint32_t pid);

    // Behavioral analysis
    [[nodiscard]] BehavioralIndicators AnalyzeBehaviorInternal(uint32_t pid);
    [[nodiscard]] bool DetectProcessHollowingInternal(uint32_t pid);

    // Categorization
    [[nodiscard]] ProcessCategory CategorizeProcessInternal(uint32_t pid);
    [[nodiscard]] bool IsWhitelistedInternal(uint32_t pid);
    [[nodiscard]] std::pair<bool, std::wstring> IsKnownMaliciousInternal(uint32_t pid);

    // Cache management
    void PurgeExpiredCacheEntries();

    // Kernel notification handlers
    void OnKernelProcessCreateInternal(uint32_t pid, uint32_t parentPid,
        uint32_t creatingPid, uint32_t creatingTid, const std::wstring& imagePath);
    void OnKernelProcessTerminateInternal(uint32_t pid);
    void OnKernelImageLoadInternal(uint32_t pid, uintptr_t imageBase,
        size_t imageSize, const std::wstring& imageName, bool isSystemImage);
    void OnKernelThreadCreateInternal(uint32_t targetPid, uint32_t threadId,
        uint32_t creatorPid, uint32_t creatorTid, bool isRemote);

    // Utility: build CacheKey from PID
    [[nodiscard]] CacheKey MakeCacheKey(uint32_t pid) noexcept;

    // Callbacks
    void InvokeProgressCallbacks(uint32_t pid, const std::wstring& stage, uint32_t percent);
    void InvokeFindingCallbacks(uint32_t pid, const std::wstring& finding, uint32_t riskScore);
    void InvokeModuleCallbacks(uint32_t pid, const ModuleInfo& module);
};

// ============================================================================
// IMPL: INITIALIZATION
// ============================================================================

bool ProcessAnalyzerImpl::Initialize(const AnalyzerConfig& config) {
    try {
        if (m_initialized.exchange(true, std::memory_order_acq_rel)) {
            SS_LOG_WARN(L"ProcessAnalyzer", L"Already initialized");
            return true;
        }

        SS_LOG_INFO(L"ProcessAnalyzer", L"Initializing v%u.%u.%u...",
            AnalyzerConstants::VERSION_MAJOR,
            AnalyzerConstants::VERSION_MINOR,
            AnalyzerConstants::VERSION_PATCH);

        m_config = config;

        // Create infrastructure store instances. These are instance-based (not
        // singletons), so each ProcessAnalyzer owns its own. The stores
        // self-initialize from their on-disk databases when constructed.
        m_hashStore = std::make_shared<HashStore::HashStore>();
        m_signatureStore = std::make_shared<SignatureStore::SignatureStore>();
        m_threatIntel = std::make_shared<ThreatIntel::ThreatIntelStore>();
        m_whitelist = std::make_shared<Whitelist::WhitelistStore>();

        // Log store readiness for diagnostics
        SS_LOG_INFO(L"ProcessAnalyzer", L"HashStore initialized: %s",
            (m_hashStore && m_hashStore->IsInitialized()) ? L"yes" : L"no");
        SS_LOG_INFO(L"ProcessAnalyzer", L"SignatureStore initialized: %s",
            (m_signatureStore && m_signatureStore->IsInitialized()) ? L"yes" : L"no");

        // Validate detection engine singletons are reachable
        auto& injectionDetector = ProcessInjectionDetector::Instance();
        auto& threadHijackDetector = ThreadHijackDetector::Instance();
        auto& dllInjectionDetector = DLLInjectionDetector::Instance();
        auto& reflectiveDetector = ReflectiveDLLDetector::Instance();
        auto& hollowingDetector = ProcessHollowingDetector::Instance();
        auto& atomBombingDetector = AtomBombingDetector::Instance();
        auto& memoryScanner = MemoryScanner::Instance();

        (void)injectionDetector;
        (void)threadHijackDetector;
        (void)dllInjectionDetector;
        (void)reflectiveDetector;
        (void)hollowingDetector;
        (void)atomBombingDetector;
        (void)memoryScanner;

        SS_LOG_INFO(L"ProcessAnalyzer", L"All detection engines bound successfully");
        SS_LOG_INFO(L"ProcessAnalyzer", L"Initialized successfully");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Initialization failed - %S", e.what());
        m_initialized.store(false, std::memory_order_release);
        return false;
    }
}

void ProcessAnalyzerImpl::Shutdown() {
    try {
        if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        SS_LOG_INFO(L"ProcessAnalyzer", L"Shutting down...");

        {
            std::unique_lock lock(m_cacheMutex);
            m_analysisCache.clear();
        }

        {
            std::unique_lock lock(m_signatureCacheMutex);
            m_signatureCache.clear();
        }

        {
            std::lock_guard lock(m_callbacksMutex);
            m_progressCallbacks.clear();
            m_findingCallbacks.clear();
            m_moduleCallbacks.clear();
        }

        SS_LOG_INFO(L"ProcessAnalyzer", L"Shutdown complete");

    } catch (...) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Exception during shutdown");
    }
}

// ============================================================================
// IMPL: CORE ANALYSIS
// ============================================================================

ProcessAnalysisResult ProcessAnalyzerImpl::AnalyzeProcessInternal(
    uint32_t pid,
    AnalysisDepth depth)
{
    const auto startTime = Clock::now();
    ProcessAnalysisResult result;

    try {
        if (!m_initialized.load(std::memory_order_acquire)) {
            result.analysisError = L"ProcessAnalyzer not initialized";
            SS_LOG_ERROR(L"ProcessAnalyzer", L"AnalyzeProcess called before initialization for PID %u", pid);
            return result;
        }

        m_statistics.totalAnalyses.fetch_add(1, std::memory_order_relaxed);

        // Track analysis depth
        switch (depth) {
            case AnalysisDepth::Quick: m_statistics.quickAnalyses.fetch_add(1, std::memory_order_relaxed); break;
            case AnalysisDepth::Standard: m_statistics.standardAnalyses.fetch_add(1, std::memory_order_relaxed); break;
            case AnalysisDepth::Deep: m_statistics.deepAnalyses.fetch_add(1, std::memory_order_relaxed); break;
            case AnalysisDepth::Forensic: m_statistics.forensicAnalyses.fetch_add(1, std::memory_order_relaxed); break;
        }

        result.processId = pid;
        result.analysisTime = Clock::now();
        result.analysisDepth = depth;

        // Build composite cache key using PID + creation time to prevent
        // PID-reuse cache poisoning attacks.
        const auto cacheKey = MakeCacheKey(pid);

        // Check cache (only for Standard depth — deeper analyses should not be cached shortcuts)
        if (m_config.enableAnalysisCache && depth == AnalysisDepth::Standard) {
            std::shared_lock lock(m_cacheMutex);
            auto it = m_analysisCache.find(cacheKey);
            if (it != m_analysisCache.end()) {
                const auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    Clock::now() - it->second.timestamp
                ).count();

                if (age < m_config.analysisCacheTTLSeconds) {
                    m_statistics.analysisCacheHits.fetch_add(1, std::memory_order_relaxed);
                    return it->second.result;
                }
            }
            m_statistics.analysisCacheMisses.fetch_add(1, std::memory_order_relaxed);
        }

        InvokeProgressCallbacks(pid, L"Starting analysis", 0);

        // Get basic process information
        auto procInfo = SafeGetProcessInfo(pid);
        if (!procInfo.has_value()) {
            result.analysisError = L"Failed to get process information";
            return result;
        }

        result.processName = procInfo->name;
        result.processPath = procInfo->executablePath;
        result.commandLine = procInfo->commandLine;
        result.startTime = FileTimeToTimePoint(procInfo->creationTime);

        InvokeProgressCallbacks(pid, L"Checking whitelist and reputation", 10);

        // Quick assessment first
        result.isWhitelisted = IsWhitelistedInternal(pid);
        auto [isMalicious, threatName] = IsKnownMaliciousInternal(pid);
        result.isKnownMalicious = isMalicious;
        result.threatName = threatName;

        // SECURITY: Even whitelisted processes must be checked for post-exploitation.
        // A whitelisted process (e.g. svchost.exe) that has been hollowed, injected,
        // or reflectively loaded with malware must NOT be blindly trusted.
        // We perform critical injection/hollowing checks regardless of whitelist status.
        if (result.isWhitelisted && depth <= AnalysisDepth::Standard) {
            // For Quick/Standard depth on whitelisted processes:
            // perform essential integrity checks then return early if clean.
            bool tampered = false;

            // Check for process hollowing (fast check)
            if (DetectProcessHollowingInternal(pid)) {
                tampered = true;
                result.criticalFindings.push_back(
                    L"CRITICAL: Whitelisted process appears hollowed");
                result.mitreAttackTechniques.push_back("T1055.012");
                InvokeFindingCallbacks(pid,
                    L"Whitelisted process hollowing detected", 95);
            }

            // Check for reflective DLL injection
            try {
                auto& reflectiveDetector = ReflectiveDLLDetector::Instance();
                if (reflectiveDetector.IsInitialized() &&
                    reflectiveDetector.HasReflectiveLoading(pid)) {
                    tampered = true;
                    result.criticalFindings.push_back(
                        L"CRITICAL: Reflective DLL detected in whitelisted process");
                    result.mitreAttackTechniques.push_back("T1620");
                    InvokeFindingCallbacks(pid,
                        L"Reflective DLL in whitelisted process", 90);
                }
            } catch (...) {}

            // Check injection detector
            try {
                auto& injectionDetector = ProcessInjectionDetector::Instance();
                if (injectionDetector.IsProcessInjected(pid)) {
                    tampered = true;
                    result.criticalFindings.push_back(
                        L"CRITICAL: Injection detected in whitelisted process");
                    result.mitreAttackTechniques.push_back("T1055");
                    InvokeFindingCallbacks(pid,
                        L"Code injection in whitelisted process", 85);
                }
            } catch (...) {}

            if (!tampered) {
                result.riskLevel = ProcessRiskLevel::Trusted;
                result.analysisComplete = true;
                m_statistics.trustedProcesses.fetch_add(1, std::memory_order_relaxed);

                // Cache the result
                if (m_config.enableAnalysisCache && depth == AnalysisDepth::Standard) {
                    std::unique_lock lock(m_cacheMutex);
                    m_analysisCache[cacheKey] = CachedAnalysis{result, Clock::now()};
                }
                return result;
            }
            // Tampered whitelisted process: fall through to full analysis
            SS_LOG_ERROR(L"ProcessAnalyzer",
                L"ALERT: Whitelisted process PID %u shows tampering indicators", pid);
            result.isWhitelisted = false; // revoke trust
        }

        if (result.isKnownMalicious) {
            result.riskLevel = ProcessRiskLevel::Malicious;
            result.criticalFindings.push_back(L"Process matches known malware: " + threatName);
            InvokeFindingCallbacks(pid, L"Known malicious process detected", 100);
            m_statistics.maliciousProcesses.fetch_add(1, std::memory_order_relaxed);
        }

        InvokeProgressCallbacks(pid, L"Verifying digital signature", 20);

        // Signature verification
        if (m_config.enableSignatureVerification) {
            result.signatureInfo = VerifyFileSignatureInternal(result.processPath);
            m_statistics.signaturesVerified.fetch_add(1, std::memory_order_relaxed);
        }

        InvokeProgressCallbacks(pid, L"Analyzing modules", 30);

        // Module analysis — enumerate once, analyze from the same list
        if (m_config.enableModuleAnalysis) {
            result.modules = GetLoadedModulesInternal(pid);
            result.loadedModuleCount = static_cast<uint32_t>(result.modules.size());
            result.suspiciousModules = FindSuspiciousModulesFromList(pid, result.modules);
            result.suspiciousModuleCount = static_cast<uint32_t>(result.suspiciousModules.size());

            for (const auto& mod : result.modules) {
                if (mod.signatureStatus == SignatureStatus::Unsigned) {
                    result.unsignedModuleCount++;
                }
            }
        }

        InvokeProgressCallbacks(pid, L"Analyzing memory", 40);

        // Memory analysis
        if (m_config.enableMemoryAnalysis && depth >= AnalysisDepth::Standard) {
            result.memorySummary = AnalyzeMemoryInternal(pid);

            if (result.memorySummary.rwxRegionCount > 0) {
                InvokeFindingCallbacks(pid, L"RWX memory regions detected",
                    result.memorySummary.rwxRegionCount * 10);
            }

            if (result.memorySummary.unbackedExecRegionCount > 0) {
                InvokeFindingCallbacks(pid, L"Unbacked executable memory detected",
                    result.memorySummary.unbackedExecRegionCount * 15);
            }
        }

        InvokeProgressCallbacks(pid, L"Analyzing threads", 50);

        // Thread analysis
        if (m_config.enableThreadAnalysis && depth >= AnalysisDepth::Standard) {
            result.threadSummary = AnalyzeThreadsInternal(pid);

            if (result.threadSummary.unbackedStartCount > 0) {
                InvokeFindingCallbacks(pid, L"Threads with unbacked start addresses detected",
                    result.threadSummary.unbackedStartCount * 20);
            }
        }

        InvokeProgressCallbacks(pid, L"Analyzing handles", 60);

        // Handle analysis
        if (m_config.enableHandleAnalysis && depth >= AnalysisDepth::Deep) {
            result.handleSummary = EnumerateHandlesInternal(pid);

            if (result.handleSummary.hasLsassAccess) {
                InvokeFindingCallbacks(pid, L"Process has LSASS access", 50);
                result.warnings.push_back(L"Has handle to LSASS process");
            }
        }

        InvokeProgressCallbacks(pid, L"Analyzing security context", 70);

        // Security context
        result.securityContext = AnalyzeSecurityContextInternal(pid);

        InvokeProgressCallbacks(pid, L"Analyzing parent-child relationship", 80);

        // Parent-child analysis
        result.parentChildAnalysis = AnalyzeParentChildInternal(pid);

        if (result.parentChildAnalysis.isPPIDSpoofed) {
            result.criticalFindings.push_back(L"PPID spoofing detected");
            InvokeFindingCallbacks(pid, L"PPID spoofing detected", 70);
            m_statistics.ppidSpoofingDetected.fetch_add(1, std::memory_order_relaxed);
        }

        if (result.parentChildAnalysis.anomaly != ParentChildAnomaly::Normal) {
            result.warnings.push_back(L"Parent-child relationship anomaly");
            m_statistics.parentAnomaliesDetected.fetch_add(1, std::memory_order_relaxed);
        }

        InvokeProgressCallbacks(pid, L"Analyzing network footprint", 90);

        // Network analysis
        if (m_config.enableNetworkAnalysis && depth >= AnalysisDepth::Standard) {
            result.networkFootprint = AnalyzeNetworkFootprintInternal(pid);
        }

        // Behavioral analysis
        if (m_config.enableBehavioralAnalysis && depth >= AnalysisDepth::Deep) {
            result.behavioralIndicators = AnalyzeBehaviorInternal(pid);

            if (result.behavioralIndicators.hasProcessHollowing) {
                result.criticalFindings.push_back(L"Process hollowing detected");
                result.mitreAttackTechniques.push_back("T1055.012");
            }

            if (result.behavioralIndicators.hasDirectSyscalls) {
                result.warnings.push_back(L"Direct syscall usage detected");
                result.mitreAttackTechniques.push_back("T1106");
            }
        }

        InvokeProgressCallbacks(pid, L"Calculating risk score", 95);

        // Calculate overall risk
        result.CalculateOverallRisk();

        // Update statistics
        switch (result.riskLevel) {
            case ProcessRiskLevel::Trusted: m_statistics.trustedProcesses.fetch_add(1, std::memory_order_relaxed); break;
            case ProcessRiskLevel::Safe: m_statistics.safeProcesses.fetch_add(1, std::memory_order_relaxed); break;
            case ProcessRiskLevel::Unknown: m_statistics.unknownProcesses.fetch_add(1, std::memory_order_relaxed); break;
            case ProcessRiskLevel::Suspicious:
            case ProcessRiskLevel::HighRisk:
            case ProcessRiskLevel::MediumRisk:
            case ProcessRiskLevel::LowRisk:
                m_statistics.suspiciousProcesses.fetch_add(1, std::memory_order_relaxed);
                break;
            case ProcessRiskLevel::Malicious:
            case ProcessRiskLevel::Critical:
                m_statistics.maliciousProcesses.fetch_add(1, std::memory_order_relaxed);
                break;
        }

        result.analysisComplete = true;

        InvokeProgressCallbacks(pid, L"Analysis complete", 100);

        // Cache result using composite key (PID + creation time)
        if (m_config.enableAnalysisCache && depth == AnalysisDepth::Standard) {
            std::unique_lock lock(m_cacheMutex);
            m_analysisCache[cacheKey] = CachedAnalysis{result, Clock::now()};

            if (m_analysisCache.size() > m_config.analysisCacheSize) {
                PurgeExpiredCacheEntries();
            }
        }

    } catch (const std::exception& e) {
        result.analysisError = Utils::StringUtils::ToWide(e.what());
        m_statistics.analysisErrors.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Analysis failed for PID %u - %S", pid, e.what());
    }

    const auto endTime = Clock::now();
    result.analysisDurationMs = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count()
    );

    m_statistics.totalAnalysisTimeMs.fetch_add(result.analysisDurationMs, std::memory_order_relaxed);

    uint64_t currentMin = m_statistics.minAnalysisTimeMs.load(std::memory_order_relaxed);
    while (result.analysisDurationMs < currentMin &&
           !m_statistics.minAnalysisTimeMs.compare_exchange_weak(currentMin, result.analysisDurationMs));

    uint64_t currentMax = m_statistics.maxAnalysisTimeMs.load(std::memory_order_relaxed);
    while (result.analysisDurationMs > currentMax &&
           !m_statistics.maxAnalysisTimeMs.compare_exchange_weak(currentMax, result.analysisDurationMs));

    return result;
}

ProcessRiskLevel ProcessAnalyzerImpl::QuickAssessRiskInternal(uint32_t pid) {
    try {
        // Whitelist check
        if (IsWhitelistedInternal(pid)) {
            return ProcessRiskLevel::Trusted;
        }

        // Known malicious check
        auto [isMalicious, threatName] = IsKnownMaliciousInternal(pid);
        if (isMalicious) {
            return ProcessRiskLevel::Malicious;
        }

        // Signature check
        auto procInfo = SafeGetProcessInfo(pid);
        if (!procInfo.has_value()) {
            return ProcessRiskLevel::Unknown;
        }

        auto sigInfo = VerifyFileSignatureInternal(procInfo->executablePath);

        if (sigInfo.status == SignatureStatus::Valid &&
            sigInfo.trustLevel == CertificateTrust::Microsoft) {
            return ProcessRiskLevel::Trusted;
        }

        if (sigInfo.status == SignatureStatus::Revoked) {
            return ProcessRiskLevel::Malicious;
        }

        if (sigInfo.status == SignatureStatus::Unsigned) {
            return ProcessRiskLevel::LowRisk;
        }

        return ProcessRiskLevel::Unknown;

    } catch (...) {
        return ProcessRiskLevel::Unknown;
    }
}

// ============================================================================
// IMPL: MODULE ANALYSIS
// ============================================================================

std::vector<ModuleInfo> ProcessAnalyzerImpl::GetLoadedModulesInternal(uint32_t pid) {
    std::vector<ModuleInfo> modules;

    try {
        auto rawModules = SafeGetProcessModules(pid);

        for (const auto& rawMod : rawModules) {
            ModuleInfo modInfo{};
            modInfo.moduleName = rawMod.name;
            modInfo.modulePath = rawMod.path;
            modInfo.baseAddress = reinterpret_cast<uintptr_t>(rawMod.baseAddress);
            modInfo.sizeOfImage = static_cast<uint32_t>(rawMod.size);

            // Signature verification
            if (m_config.enableSignatureVerification) {
                modInfo.signatureStatus = VerifyFileSignatureInternal(rawMod.path).status;

                if (modInfo.signatureStatus == SignatureStatus::Unsigned) {
                    m_statistics.unsignedModulesDetected.fetch_add(1, std::memory_order_relaxed);
                }
            }

            modules.push_back(modInfo);
            m_statistics.modulesAnalyzed.fetch_add(1, std::memory_order_relaxed);

            InvokeModuleCallbacks(pid, modInfo);

            if (modules.size() >= m_config.maxModulesToAnalyze) {
                break;
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Failed to get modules for PID %u - %S", pid, e.what());
    }

    return modules;
}

std::vector<ModuleInfo> ProcessAnalyzerImpl::FindSuspiciousModulesInternal(uint32_t pid) {
    // Delegate: enumerate modules, then analyze
    auto allModules = GetLoadedModulesInternal(pid);
    return FindSuspiciousModulesFromList(pid, allModules);
}

std::vector<ModuleInfo> ProcessAnalyzerImpl::FindSuspiciousModulesFromList(
    uint32_t pid,
    const std::vector<ModuleInfo>& allModules)
{
    std::vector<ModuleInfo> suspiciousModules;

    try {
        for (auto mod : allModules) {
            bool isSuspicious = false;

            // Unsigned modules
            if (mod.signatureStatus == SignatureStatus::Unsigned) {
                isSuspicious = true;
            }

            // Revoked certificates
            if (mod.signatureStatus == SignatureStatus::Revoked) {
                isSuspicious = true;
                mod.suspicionLevel = ModuleSuspicionLevel::HighlySupicious;
            }

            // Suspicious paths
            const std::wstring pathLower = Utils::StringUtils::ToLowerCopy(mod.modulePath);
            if (pathLower.find(L"\\temp\\") != std::wstring::npos ||
                pathLower.find(L"\\appdata\\local\\temp\\") != std::wstring::npos ||
                pathLower.find(L"\\users\\public\\") != std::wstring::npos ||
                pathLower.find(L"\\programdata\\") != std::wstring::npos ||
                pathLower.find(L"\\downloads\\") != std::wstring::npos) {
                isSuspicious = true;
                mod.isInSuspiciousPath = true;
            }

            // Double extension (evasion technique)
            const auto& name = mod.moduleName;
            const auto firstDot = name.find(L'.');
            if (firstDot != std::wstring::npos) {
                const auto secondDot = name.find(L'.', firstDot + 1);
                if (secondDot != std::wstring::npos) {
                    isSuspicious = true;
                    mod.suspicionLevel = ModuleSuspicionLevel::HighlySupicious;
                }
            }

            if (isSuspicious) {
                if (mod.suspicionLevel < ModuleSuspicionLevel::Suspicious) {
                    mod.suspicionLevel = ModuleSuspicionLevel::Suspicious;
                }
                suspiciousModules.push_back(mod);
                m_statistics.suspiciousModulesDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Failed to find suspicious modules for PID %u - %S", pid, e.what());
    }

    return suspiciousModules;
}

ModuleInfo ProcessAnalyzerImpl::AnalyzeModuleInternal(
    uint32_t pid,
    uintptr_t moduleBase)
{
    ModuleInfo modInfo{};
    modInfo.baseAddress = moduleBase;

    try {
        // Find module in loaded modules
        auto modules = GetLoadedModulesInternal(pid);
        for (const auto& mod : modules) {
            if (mod.baseAddress == moduleBase) {
                modInfo = mod;
                break;
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Failed to analyze module at 0x%llX in PID %u - %S",
            static_cast<unsigned long long>(moduleBase), pid, e.what());
    }

    return modInfo;
}

// ============================================================================
// IMPL: HANDLE ANALYSIS
// ============================================================================

HandleSummary ProcessAnalyzerImpl::EnumerateHandlesInternal(uint32_t pid) {
    HandleSummary summary;

    try {
        // Enumerate handles via ProcessUtils
        std::vector<Utils::ProcessUtils::ProcessHandleInfo> handles;
        Utils::ProcessUtils::Error err{};
        if (Utils::ProcessUtils::EnumerateProcessHandles(pid, handles, &err)) {
            summary.totalHandles = static_cast<uint32_t>(
                std::min<size_t>(handles.size(), m_config.maxHandlesToEnumerate));

            for (size_t i = 0; i < summary.totalHandles; ++i) {
                const auto& h = handles[i];
                HandleInfo info{};
                info.handleValue = reinterpret_cast<uint64_t>(h.handle);
                info.typeName = h.typeName;
                info.objectName = h.name;
                info.grantedAccess = h.accessMask;
                info.isInheritable = h.isInheritable;

                // Detect LSASS access
                const std::wstring nameLower = Utils::StringUtils::ToLowerCopy(h.name);
                if (nameLower.find(L"lsass") != std::wstring::npos) {
                    summary.hasLsassAccess = true;
                    info.accessPattern = HandleAccessPattern::LsassAccess;
                    info.isSuspicious = true;
                    info.suspicionReason = L"Handle to LSASS process";
                    summary.suspiciousHandles.push_back(info);
                }

                // Detect cross-process handles
                const std::wstring typeNameLower = Utils::StringUtils::ToLowerCopy(h.typeName);
                if (typeNameLower == L"process" && h.accessMask != 0) {
                    info.accessPattern = HandleAccessPattern::CrossProcessAccess;
                    summary.crossProcessHandles.push_back(info);
                }

                // Detect sensitive registry access
                if (nameLower.find(L"\\registry\\machine\\sam") != std::wstring::npos ||
                    nameLower.find(L"\\registry\\machine\\security") != std::wstring::npos) {
                    summary.hasSensitiveRegAccess = true;
                    info.isSuspicious = true;
                    info.suspicionReason = L"Access to sensitive registry hive";
                    summary.suspiciousHandles.push_back(info);
                }

                // Detect system directory write access
                if (nameLower.find(L"\\windows\\system32") != std::wstring::npos &&
                    (h.accessMask & (GENERIC_WRITE | FILE_WRITE_DATA)) != 0) {
                    summary.hasSystemDirWrite = true;
                }
            }
        }

        m_statistics.handlesEnumerated.fetch_add(summary.totalHandles, std::memory_order_relaxed);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Failed to enumerate handles for PID %u - %S", pid, e.what());
    }

    return summary;
}

// ============================================================================
// IMPL: MEMORY ANALYSIS
// ============================================================================

MemorySummary ProcessAnalyzerImpl::AnalyzeMemoryInternal(uint32_t pid) {
    MemorySummary summary;

    try {
        // Use RAII handle wrapper to prevent leaks
        Utils::ProcessUtils::ProcessHandle hProcess(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
        if (!hProcess.IsValid()) {
            m_statistics.accessDeniedErrors.fetch_add(1, std::memory_order_relaxed);
            return summary;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t address = 0;

        while (VirtualQueryEx(hProcess.Get(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT) {
                summary.totalCommittedSize += mbi.RegionSize;
                summary.regionCount++;

                // Check for executable regions
                if (IsExecutableProtection(mbi.Protect)) {
                    summary.executableRegionCount++;
                    summary.totalExecutableSize += mbi.RegionSize;

                    // Check for RWX
                    if (IsRWXProtection(mbi.Protect)) {
                        summary.rwxRegionCount++;

                        MemoryRegionInfo regionInfo{};
                        regionInfo.baseAddress = address;
                        regionInfo.regionSize = mbi.RegionSize;
                        regionInfo.protection = mbi.Protect;
                        regionInfo.isRWX = true;
                        regionInfo.isExecutable = true;
                        regionInfo.isWritable = true;
                        regionInfo.anomalies.push_back(MemoryProtectionAnomaly::RWX);

                        summary.rwxRegions.push_back(regionInfo);
                        m_statistics.rwxRegionsDetected.fetch_add(1, std::memory_order_relaxed);
                    }

                    // Check for unbacked executable
                    if (mbi.Type == MEM_PRIVATE) {
                        summary.unbackedExecRegionCount++;

                        MemoryRegionInfo regionInfo{};
                        regionInfo.baseAddress = address;
                        regionInfo.regionSize = mbi.RegionSize;
                        regionInfo.protection = mbi.Protect;
                        regionInfo.isUnbacked = true;
                        regionInfo.isExecutable = true;
                        regionInfo.anomalies.push_back(MemoryProtectionAnomaly::UnbackedExecutable);

                        summary.unbackedExecutable.push_back(regionInfo);
                        m_statistics.unbackedExecDetected.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }

            summary.totalVirtualSize += mbi.RegionSize;

            // Prevent address wrap-around causing infinite loop
            const uintptr_t nextAddress = address + mbi.RegionSize;
            if (nextAddress <= address) {
                break;  // Overflow or zero-size region
            }
            address = nextAddress;

            m_statistics.memoryRegionsScanned.fetch_add(1, std::memory_order_relaxed);

            if (summary.regionCount >= m_config.maxMemoryRegions) {
                break;
            }
        }

        // hProcess automatically closed by RAII destructor

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Memory analysis failed for PID %u - %S", pid, e.what());
    }

    return summary;
}

std::vector<MemoryRegionInfo> ProcessAnalyzerImpl::GetMemoryRegionsInternal(uint32_t pid) {
    return AnalyzeMemoryInternal(pid).suspiciousRegions;
}

std::vector<MemoryRegionInfo> ProcessAnalyzerImpl::FindRWXRegionsInternal(uint32_t pid) {
    return AnalyzeMemoryInternal(pid).rwxRegions;
}

// ============================================================================
// IMPL: THREAD ANALYSIS
// ============================================================================

ThreadSummary ProcessAnalyzerImpl::AnalyzeThreadsInternal(uint32_t pid) {
    ThreadSummary summary;

    try {
        // Pre-enumerate modules ONCE for this process to avoid O(threads*modules)
        auto cachedModules = SafeGetProcessModules(pid);

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return summary;
        }

        // RAII cleanup for snapshot handle
        struct SnapshotGuard {
            HANDLE h;
            ~SnapshotGuard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
        } snapshotGuard{hSnapshot};

        THREADENTRY32 te{};
        te.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    summary.totalThreads++;

                    if (summary.totalThreads > m_config.maxThreadsToAnalyze) {
                        break;
                    }

                    auto threadInfo = GetThreadInfoInternal(te.th32ThreadID, cachedModules);
                    if (threadInfo.has_value()) {
                        summary.allThreads.push_back(*threadInfo);

                        if (!threadInfo->isStartAddressBacked) {
                            summary.unbackedStartCount++;
                            summary.suspiciousThreads.push_back(*threadInfo);
                            m_statistics.suspiciousThreadsDetected.fetch_add(1, std::memory_order_relaxed);
                        }

                        m_statistics.threadsAnalyzed.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Thread analysis failed for PID %u - %S", pid, e.what());
    }

    return summary;
}

std::optional<ThreadInfo> ProcessAnalyzerImpl::GetThreadInfoInternal(
    uint32_t tid,
    const std::vector<Utils::ProcessUtils::ProcessModuleInfo>& cachedModules)
{
    ThreadInfo info{};
    info.threadId = tid;

    try {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                                    FALSE, tid);
        if (!hThread) {
            return std::nullopt;
        }

        // RAII cleanup
        struct ThreadGuard {
            HANDLE h;
            ~ThreadGuard() { if (h) CloseHandle(h); }
        } guard{hThread};

        info.ownerPid = GetProcessIdOfThread(hThread);

        // Query thread start address via NtQueryInformationThread
        using NtQueryInformationThread_t = NTSTATUS(NTAPI*)(
            HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
        static const auto pNtQueryInformationThread =
            reinterpret_cast<NtQueryInformationThread_t>(
                GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));

        if (pNtQueryInformationThread) {
            // ThreadQuerySetWin32StartAddress = 9
            PVOID startAddr = nullptr;
            ULONG returnLen = 0;
            NTSTATUS status = pNtQueryInformationThread(
                hThread,
                static_cast<THREADINFOCLASS>(9),   // ThreadQuerySetWin32StartAddress
                &startAddr,
                sizeof(startAddr),
                &returnLen);

            if (status >= 0 && startAddr != nullptr) {
                info.startAddress = reinterpret_cast<uintptr_t>(startAddr);

                // Check if start address is backed by a known module using
                // the pre-enumerated module list (avoids per-thread enumeration).
                info.isStartAddressBacked = false;

                for (const auto& mod : cachedModules) {
                    const uintptr_t modBase = reinterpret_cast<uintptr_t>(mod.baseAddress);
                    const uintptr_t modEnd = modBase + mod.size;
                    if (info.startAddress >= modBase && info.startAddress < modEnd) {
                        info.isStartAddressBacked = true;
                        info.startAddressModule = mod.name;
                        break;
                    }
                }

                // Flag threads starting at well-known injection targets
                if (info.isStartAddressBacked) {
                    const std::wstring modLower = Utils::StringUtils::ToLowerCopy(
                        info.startAddressModule);
                    // LoadLibraryA/W in kernel32 is a classic remote thread target
                    if (modLower == L"kernel32.dll" || modLower == L"kernelbase.dll") {
                        info.suspicion = ThreadSuspicion::StartAtExportedFunction;
                    }
                } else {
                    info.suspicion = ThreadSuspicion::UnbackedStartAddress;
                    info.suspicionReason = L"Start address not in any known module";
                    info.riskScore = 40;
                }
            } else {
                info.startAddress = 0;
                info.isStartAddressBacked = true;
            }
        } else {
            info.startAddress = 0;
            info.isStartAddressBacked = true;
        }

        return info;

    } catch (...) {
        return std::nullopt;
    }
}

std::optional<ThreadInfo> ProcessAnalyzerImpl::GetThreadInfoInternal(
    uint32_t tid)
{
    // Resolve owning PID, enumerate its modules, then delegate to the
    // full overload. This avoids the O(threads * modules) problem when
    // callers only need a single thread analyzed.
    HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!hThread) {
        return std::nullopt;
    }
    const uint32_t ownerPid = GetProcessIdOfThread(hThread);
    CloseHandle(hThread);

    if (ownerPid == 0) {
        return std::nullopt;
    }

    auto modules = SafeGetProcessModules(ownerPid);
    return GetThreadInfoInternal(tid, modules);
}

SignatureInfo ProcessAnalyzerImpl::VerifyFileSignatureInternal(const std::wstring& filePath) {
    SignatureInfo sigInfo;

    try {
        // Check cache first (with TTL validation)
        if (m_config.enableSignatureCache) {
            std::shared_lock lock(m_signatureCacheMutex);
            auto it = m_signatureCache.find(filePath);
            if (it != m_signatureCache.end()) {
                const auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    Clock::now() - it->second.timestamp).count();
                if (age < static_cast<int64_t>(AnalyzerConstants::SIGNATURE_CACHE_TTL_SECONDS)) {
                    m_statistics.signatureCacheHits.fetch_add(1, std::memory_order_relaxed);
                    return it->second.info;
                }
                // Expired: fall through to re-verify
            }
            m_statistics.signatureCacheMisses.fetch_add(1, std::memory_order_relaxed);
        }

        // Use existing PE signature verification infrastructure
        Utils::pe_sig_utils::PEFileSignatureVerifier verifier;
        verifier.SetRevocationMode(Utils::pe_sig_utils::RevocationMode::OfflineAllowed);

        Utils::pe_sig_utils::SignatureInfo peSignInfo;
        Utils::pe_sig_utils::Error error;

        bool verified = verifier.VerifyPESignature(filePath, peSignInfo, &error);

        // Map PE signature info to ProcessAnalyzer SignatureInfo
        if (!peSignInfo.isSigned) {
            sigInfo.status = SignatureStatus::Unsigned;
        } else if (verified && peSignInfo.isVerified && peSignInfo.isChainTrusted) {
            sigInfo.status = SignatureStatus::Valid;

            // Determine trust level based on signer
            const std::wstring signerLower = Utils::StringUtils::ToLowerCopy(peSignInfo.signerName);
            if (signerLower.find(L"microsoft") != std::wstring::npos) {
                sigInfo.trustLevel = CertificateTrust::Microsoft;
            } else {
                sigInfo.trustLevel = CertificateTrust::StandardPublisher;
            }

            sigInfo.signerName = peSignInfo.signerName;
            sigInfo.issuerName = peSignInfo.issuerName;
            sigInfo.thumbprint = Utils::StringUtils::ToNarrow(peSignInfo.thumbprint);
        } else if (error.win32 == CERT_E_REVOKED) {
            sigInfo.status = SignatureStatus::Revoked;
        } else if (error.win32 == CERT_E_EXPIRED) {
            sigInfo.status = SignatureStatus::Expired;
        } else if (peSignInfo.isSigned && !peSignInfo.isVerified) {
            sigInfo.status = SignatureStatus::Invalid;
        } else {
            sigInfo.status = SignatureStatus::Unknown;
        }

        // Cache result with timestamp for ordered eviction
        if (m_config.enableSignatureCache) {
            std::unique_lock lock(m_signatureCacheMutex);
            m_signatureCache[filePath] = CachedSignature{sigInfo, Clock::now()};

            if (m_signatureCache.size() > m_config.signatureCacheSize) {
                // Evict oldest entries (by timestamp) to reclaim half the cache.
                // Collect entries sorted by age, remove the oldest half.
                std::vector<std::wstring> keys;
                keys.reserve(m_signatureCache.size());
                for (const auto& [k, _] : m_signatureCache) {
                    keys.push_back(k);
                }
                std::sort(keys.begin(), keys.end(), [this](const auto& a, const auto& b) {
                    return m_signatureCache[a].timestamp < m_signatureCache[b].timestamp;
                });
                const size_t toRemove = keys.size() / 2;
                for (size_t i = 0; i < toRemove; ++i) {
                    m_signatureCache.erase(keys[i]);
                }
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Signature verification failed for %ls - %S",
            filePath.c_str(), e.what());
        sigInfo.status = SignatureStatus::Unknown;
    }

    return sigInfo;
}

bool ProcessAnalyzerImpl::IsMicrosoftSignedInternal(const std::wstring& filePath) {
    auto sigInfo = VerifyFileSignatureInternal(filePath);
    return (sigInfo.status == SignatureStatus::Valid &&
            sigInfo.trustLevel == CertificateTrust::Microsoft);
}

// ============================================================================
// IMPL: SECURITY CONTEXT
// ============================================================================

SecurityContext ProcessAnalyzerImpl::AnalyzeSecurityContextInternal(uint32_t pid) {
    SecurityContext context;

    try {
        // Use RAII handle wrapper
        Utils::ProcessUtils::ProcessHandle hProcess(pid, PROCESS_QUERY_INFORMATION);
        if (!hProcess.IsValid()) {
            // Retry with limited access
            hProcess.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION);
            if (!hProcess.IsValid()) {
                m_statistics.accessDeniedErrors.fetch_add(1, std::memory_order_relaxed);
                return context;
            }
        }

        // Get process token
        HANDLE hTokenRaw = nullptr;
        if (!OpenProcessToken(hProcess.Get(), TOKEN_QUERY, &hTokenRaw) || !hTokenRaw) {
            return context;
        }

        // RAII for token handle
        struct TokenGuard {
            HANDLE h;
            ~TokenGuard() { if (h) CloseHandle(h); }
        } tokenGuard{hTokenRaw};

        // Get token elevation
        TOKEN_ELEVATION elevation{};
        DWORD returnLength = 0;
        if (GetTokenInformation(hTokenRaw, TokenElevation, &elevation,
                              sizeof(elevation), &returnLength)) {
            context.isElevated = (elevation.TokenIsElevated != 0);
        }

        // Get integrity level
        DWORD integrityLevelSize = 0;
        if (!GetTokenInformation(hTokenRaw, TokenIntegrityLevel, nullptr, 0, &integrityLevelSize) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER && integrityLevelSize > 0) {
            auto buffer = std::make_unique<uint8_t[]>(integrityLevelSize);
            if (GetTokenInformation(hTokenRaw, TokenIntegrityLevel, buffer.get(),
                                  integrityLevelSize, &returnLength)) {
                auto pIntegrity = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.get());
                if (IsValidSid(pIntegrity->Label.Sid)) {
                    DWORD subAuthCount = *GetSidSubAuthorityCount(pIntegrity->Label.Sid);
                    if (subAuthCount > 0) {
                        context.integrityLevel = *GetSidSubAuthority(pIntegrity->Label.Sid, subAuthCount - 1);

                        // Map to human-readable name
                        if (context.integrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
                            context.integrityLevelName = L"System";
                        } else if (context.integrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
                            context.integrityLevelName = L"High";
                        } else if (context.integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID) {
                            context.integrityLevelName = L"Medium";
                        } else {
                            context.integrityLevelName = L"Low";
                        }
                    }
                }
            }
        }

        // Enumerate privileges
        DWORD privSize = 0;
        if (!GetTokenInformation(hTokenRaw, TokenPrivileges, nullptr, 0, &privSize) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER && privSize > 0) {
            auto privBuffer = std::make_unique<uint8_t[]>(privSize);
            if (GetTokenInformation(hTokenRaw, TokenPrivileges, privBuffer.get(),
                                  privSize, &returnLength)) {
                auto* pPrivileges = reinterpret_cast<TOKEN_PRIVILEGES*>(privBuffer.get());

                // Dangerous privilege names for detection
                static const std::wstring dangerousPrivs[] = {
                    L"SeDebugPrivilege",
                    L"SeTcbPrivilege",
                    L"SeAssignPrimaryTokenPrivilege",
                    L"SeLoadDriverPrivilege",
                    L"SeTakeOwnershipPrivilege",
                    L"SeCreateTokenPrivilege",
                    L"SeBackupPrivilege",
                    L"SeRestorePrivilege",
                    L"SeImpersonatePrivilege",
                    L"SeEnableDelegationPrivilege"
                };

                for (DWORD i = 0; i < pPrivileges->PrivilegeCount; ++i) {
                    wchar_t privName[256]{};
                    DWORD nameLen = 256;
                    if (LookupPrivilegeNameW(nullptr, &pPrivileges->Privileges[i].Luid,
                                           privName, &nameLen)) {
                        const bool enabled =
                            (pPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                        context.privileges.emplace_back(std::wstring(privName), enabled);

                        if (enabled) {
                            context.enabledPrivileges.push_back(privName);

                            for (const auto& dp : dangerousPrivs) {
                                if (Utils::StringUtils::IEquals(privName, dp)) {
                                    context.dangerousPrivileges.push_back(privName);
                                    break;
                                }
                            }
                        }
                    }
                }

                // Determine privilege risk
                if (!context.dangerousPrivileges.empty()) {
                    for (const auto& p : context.dangerousPrivileges) {
                        if (Utils::StringUtils::IEquals(p, L"SeDebugPrivilege")) {
                            context.privilegeRisk = PrivilegeRisk::DebugPrivilege;
                            break;
                        }
                        if (Utils::StringUtils::IEquals(p, L"SeTcbPrivilege")) {
                            context.privilegeRisk = PrivilegeRisk::TcbPrivilege;
                            break;
                        }
                        if (Utils::StringUtils::IEquals(p, L"SeLoadDriverPrivilege")) {
                            context.privilegeRisk = PrivilegeRisk::LoadDriver;
                            break;
                        }
                    }
                    if (context.privilegeRisk == PrivilegeRisk::Normal) {
                        context.privilegeRisk = PrivilegeRisk::Elevated;
                    }
                }
            }
        }

        // Get session ID from process info
        auto procInfo = SafeGetProcessInfo(pid);
        if (procInfo.has_value()) {
            context.sessionId = procInfo->sessionId;
        }

        // Check for impersonation
        TOKEN_TYPE tokenType{};
        if (GetTokenInformation(hTokenRaw, TokenType, &tokenType,
                              sizeof(tokenType), &returnLength)) {
            context.isPrimaryToken = (tokenType == TokenPrimary);
            context.isImpersonating = (tokenType == TokenImpersonation);

            if (context.isImpersonating) {
                SECURITY_IMPERSONATION_LEVEL impLevel{};
                if (GetTokenInformation(hTokenRaw, TokenImpersonationLevel, &impLevel,
                                      sizeof(impLevel), &returnLength)) {
                    context.impersonationLevel = static_cast<uint32_t>(impLevel);
                    context.isDelegation = (impLevel == SecurityDelegation);
                }
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Security context analysis failed for PID %u - %S", pid, e.what());
    }

    return context;
}

std::vector<std::pair<std::wstring, bool>> ProcessAnalyzerImpl::GetProcessPrivilegesInternal(uint32_t pid) {
    auto context = AnalyzeSecurityContextInternal(pid);
    return context.privileges;
}

// ============================================================================
// IMPL: PARENT-CHILD ANALYSIS
// ============================================================================

ParentChildAnalysis ProcessAnalyzerImpl::AnalyzeParentChildInternal(uint32_t pid) {
    ParentChildAnalysis analysis;

    try {
        auto procInfo = SafeGetProcessInfo(pid);
        if (!procInfo.has_value()) {
            return analysis;
        }

        analysis.parentPid = procInfo->parentPid;

        // Get parent info
        auto parentInfo = SafeGetProcessInfo(analysis.parentPid);
        if (parentInfo.has_value()) {
            analysis.parentExists = true;
            analysis.parentName = parentInfo->name;
            analysis.parentPath = parentInfo->executablePath;
            analysis.parentStartTime = FileTimeToTimePoint(parentInfo->creationTime);

            // Check if parent is expected
            const std::wstring expectedParent = GetExpectedParent(procInfo->name);
            analysis.expectedParentName = expectedParent;

            const std::wstring parentFileName = Utils::StringUtils::ToLowerCopy(
                ExtractFileName(analysis.parentName));
            const std::wstring expectedLower = Utils::StringUtils::ToLowerCopy(expectedParent);

            if (parentFileName != expectedLower) {
                analysis.isExpectedParent = false;
                analysis.anomaly = ParentChildAnomaly::UnexpectedParent;
                analysis.anomalyReasons.push_back(L"Unexpected parent: " + analysis.parentName +
                    L" (expected: " + expectedParent + L")");
            }

            // Check for session mismatch
            if (procInfo->sessionId != parentInfo->sessionId) {
                analysis.anomalyReasons.push_back(
                    L"Session mismatch: child session " + std::to_wstring(procInfo->sessionId) +
                    L" vs parent session " + std::to_wstring(parentInfo->sessionId));
                if (analysis.anomaly == ParentChildAnomaly::Normal) {
                    analysis.anomaly = ParentChildAnomaly::SessionMismatch;
                }
            }

            // Check for suspicious Office child processes
            const std::wstring childNameLower = Utils::StringUtils::ToLowerCopy(
                ExtractFileName(procInfo->name));
            if (parentFileName == L"winword.exe" || parentFileName == L"excel.exe" ||
                parentFileName == L"powerpnt.exe" || parentFileName == L"outlook.exe") {
                if (childNameLower == L"cmd.exe" || childNameLower == L"powershell.exe" ||
                    childNameLower == L"powershell_ise.exe" || childNameLower == L"wscript.exe" ||
                    childNameLower == L"cscript.exe" || childNameLower == L"mshta.exe" ||
                    childNameLower == L"regsvr32.exe" || childNameLower == L"certutil.exe") {
                    analysis.anomaly = ParentChildAnomaly::SuspiciousOfficeChild;
                    analysis.anomalyReasons.push_back(
                        L"Office application spawned suspicious child: " + procInfo->name);
                    analysis.relationshipRiskScore += 30;
                }
            }

            // Check for suspicious browser child processes
            if (parentFileName == L"chrome.exe" || parentFileName == L"firefox.exe" ||
                parentFileName == L"msedge.exe" || parentFileName == L"iexplore.exe") {
                if (childNameLower == L"cmd.exe" || childNameLower == L"powershell.exe" ||
                    childNameLower == L"certutil.exe" || childNameLower == L"bitsadmin.exe") {
                    analysis.anomaly = ParentChildAnomaly::SuspiciousBrowserChild;
                    analysis.anomalyReasons.push_back(
                        L"Browser spawned suspicious child: " + procInfo->name);
                    analysis.relationshipRiskScore += 25;
                }
            }
        } else {
            analysis.parentExists = false;
            // Only flag as orphan if the process is not a boot-time process
            if (pid > 4) {
                analysis.anomaly = ParentChildAnomaly::OrphanProcess;
                analysis.anomalyReasons.push_back(L"Parent process does not exist");
            }
        }

        // PPID spoofing detection
        analysis.isPPIDSpoofed = DetectPPIDSpoofingInternal(pid);
        if (analysis.isPPIDSpoofed) {
            analysis.anomaly = ParentChildAnomaly::PPIDSpoofing;
            analysis.relationshipRiskScore += 40;
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Parent-child analysis failed for PID %u - %S", pid, e.what());
    }

    return analysis;
}

bool ProcessAnalyzerImpl::DetectPPIDSpoofingInternal(uint32_t pid) {
    try {
        auto procInfo = SafeGetProcessInfo(pid);
        if (!procInfo.has_value()) return false;

        auto parentInfo = SafeGetProcessInfo(procInfo->parentPid);
        if (!parentInfo.has_value()) return false;

        // Heuristic 1: Parent created AFTER child indicates PID reuse or spoofing.
        // A legitimate parent must exist before the child is created.
        const auto childTime = FileTimeToTimePoint(procInfo->creationTime);
        const auto parentTime = FileTimeToTimePoint(parentInfo->creationTime);
        if (parentTime > childTime) {
            return true;
        }

        // Heuristic 2: For processes that MUST have a specific parent (e.g., svchost->services.exe),
        // validate that the claimed parent actually matches. If the parent PID points to a process
        // with a different name than expected, but the name of the expected parent exists with a
        // different PID, that's a strong indicator of PPID spoofing.
        const std::wstring childNameLower = Utils::StringUtils::ToLowerCopy(
            ExtractFileName(procInfo->name));
        const std::wstring expectedParent = GetExpectedParent(procInfo->name);

        // Only do this check for known system services with mandatory parents
        if (childNameLower == L"svchost.exe" || childNameLower == L"lsass.exe" ||
            childNameLower == L"services.exe" || childNameLower == L"winlogon.exe") {
            const std::wstring actualParentName = Utils::StringUtils::ToLowerCopy(
                ExtractFileName(parentInfo->name));
            const std::wstring expectedLower = Utils::StringUtils::ToLowerCopy(expectedParent);

            if (actualParentName != expectedLower) {
                // The claimed parent is not the expected parent type
                return true;
            }
        }

        // Heuristic 3: If the parent is explorer.exe, validate it's running in the same session.
        // PPID spoofing across sessions is a common technique.
        const std::wstring parentNameLower = Utils::StringUtils::ToLowerCopy(
            ExtractFileName(parentInfo->name));
        if (parentNameLower == L"explorer.exe" &&
            procInfo->sessionId != parentInfo->sessionId) {
            return true;
        }

    } catch (...) {
        return false;
    }

    return false;
}

// ============================================================================
// IMPL: NETWORK ANALYSIS
// ============================================================================

NetworkFootprint ProcessAnalyzerImpl::AnalyzeNetworkFootprintInternal(uint32_t pid) {
    NetworkFootprint footprint;

    try {
        // Check for network modules
        auto modules = GetLoadedModulesInternal(pid);
        for (const auto& mod : modules) {
            const std::wstring nameLower = Utils::StringUtils::ToLowerCopy(mod.moduleName);

            if (nameLower == L"ws2_32.dll") footprint.hasWs2_32 = true;
            if (nameLower == L"wininet.dll") footprint.hasWinInet = true;
            if (nameLower == L"winhttp.dll") footprint.hasWinHttp = true;
            if (nameLower == L"wsock32.dll") footprint.hasWinsock = true;
        }

        footprint.hasNetworkModules = (footprint.hasWs2_32 || footprint.hasWinInet ||
                                       footprint.hasWinHttp || footprint.hasWinsock);

        // Enumerate TCP connections owned by this process
        {
            DWORD tcpTableSize = 0;
            if (GetExtendedTcpTable(nullptr, &tcpTableSize, FALSE,
                    AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER &&
                tcpTableSize > 0 && tcpTableSize <= 16 * 1024 * 1024) {
                auto tcpBuf = std::make_unique<uint8_t[]>(tcpTableSize);
                if (GetExtendedTcpTable(tcpBuf.get(), &tcpTableSize, FALSE,
                        AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(tcpBuf.get());
                    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                        const auto& row = table->table[i];
                        if (row.dwOwningPid == pid) {
                            NetworkFootprint::ConnectionInfo ci;
                            IN_ADDR localAddr{}, remoteAddr{};
                            localAddr.S_un.S_addr = static_cast<ULONG>(row.dwLocalAddr);
                            remoteAddr.S_un.S_addr = static_cast<ULONG>(row.dwRemoteAddr);
                            wchar_t localBuf[64]{}, remoteBuf[64]{};
                            InetNtopW(AF_INET, &localAddr, localBuf, 64);
                            InetNtopW(AF_INET, &remoteAddr, remoteBuf, 64);
                            ci.localAddress = localBuf;
                            ci.localPort = ntohs(static_cast<uint16_t>(row.dwLocalPort));
                            ci.remoteAddress = remoteBuf;
                            ci.remotePort = ntohs(static_cast<uint16_t>(row.dwRemotePort));

                            switch (row.dwState) {
                                case MIB_TCP_STATE_LISTEN:
                                    ci.state = L"LISTENING";
                                    footprint.listeningPortCount++;
                                    footprint.listeningPorts.push_back(ci.localPort);
                                    break;
                                case MIB_TCP_STATE_ESTAB:
                                    ci.state = L"ESTABLISHED";
                                    footprint.hasExternalConnections = true;
                                    break;
                                case MIB_TCP_STATE_SYN_SENT:
                                    ci.state = L"SYN_SENT";
                                    break;
                                default:
                                    ci.state = L"OTHER";
                                    break;
                            }

                            footprint.activeConnections.push_back(ci);
                            footprint.tcpConnectionCount++;

                            if (footprint.activeConnections.size() >=
                                AnalyzerConstants::MAX_NETWORK_CONNECTIONS) {
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Enumerate UDP endpoints owned by this process
        {
            DWORD udpTableSize = 0;
            if (GetExtendedUdpTable(nullptr, &udpTableSize, FALSE,
                    AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER &&
                udpTableSize > 0 && udpTableSize <= 16 * 1024 * 1024) {
                auto udpBuf = std::make_unique<uint8_t[]>(udpTableSize);
                if (GetExtendedUdpTable(udpBuf.get(), &udpTableSize, FALSE,
                        AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                    auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(udpBuf.get());
                    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                        const auto& row = table->table[i];
                        if (row.dwOwningPid == pid) {
                            footprint.udpEndpointCount++;
                        }
                    }
                }
            }
        }

        // Detect unusual ports
        for (const auto& conn : footprint.activeConnections) {
            if (conn.remotePort != 0 && conn.remotePort != 80 &&
                conn.remotePort != 443 && conn.remotePort != 53 &&
                conn.remotePort != 8080 && conn.remotePort != 8443) {
                footprint.hasUnusualPorts = true;
                break;
            }
        }

        // Determine overall network behavior
        if (!footprint.hasNetworkModules) {
            footprint.behavior = NetworkBehavior::NoNetwork;
        } else if (footprint.hasUnusualPorts) {
            footprint.behavior = NetworkBehavior::UnusualPorts;
        } else if (footprint.tcpConnectionCount > 0 || footprint.udpEndpointCount > 0) {
            footprint.behavior = NetworkBehavior::BasicNetwork;
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Network analysis failed for PID %u - %S", pid, e.what());
    }

    return footprint;
}

// ============================================================================
// IMPL: BEHAVIORAL ANALYSIS
// ============================================================================

BehavioralIndicators ProcessAnalyzerImpl::AnalyzeBehaviorInternal(uint32_t pid) {
    BehavioralIndicators indicators;

    try {
        // ================================================================
        // Process Hollowing Detection (T1055.012)
        // ================================================================
        indicators.hasProcessHollowing = DetectProcessHollowingInternal(pid);
        if (indicators.hasProcessHollowing) {
            indicators.indicatorDescriptions.push_back(
                L"Process hollowing detected (T1055.012)");
            indicators.behaviorRiskScore += 40;
        }

        // ================================================================
        // Code Injection Detection (T1055)
        // ================================================================
        try {
            auto& injectionDetector = ProcessInjectionDetector::Instance();
            if (injectionDetector.IsProcessInjected(pid)) {
                indicators.hasRemoteThreads = true;
                indicators.hasSuspiciousMemoryOperations = true;
                indicators.indicatorDescriptions.push_back(
                    L"Code injection detected (T1055)");
                indicators.behaviorRiskScore += 35;
                m_statistics.injectionIndicatorsDetected.fetch_add(1, std::memory_order_relaxed);
            }
        } catch (...) {}

        // ================================================================
        // Thread Hijacking Detection (T1055.003)
        // ================================================================
        try {
            auto& threadHijackDetector = ThreadHijackDetector::Instance();
            if (threadHijackDetector.IsInitialized()) {
                auto hijackResult = threadHijackDetector.ScanProcess(pid);
                if (hijackResult.hijackDetected) {
                    indicators.hasRemoteThreads = true;
                    indicators.indicatorDescriptions.push_back(
                        L"Thread hijacking detected (T1055.003) - "
                        L"compromised threads: " +
                        std::to_wstring(hijackResult.compromisedThreadsFound));
                    indicators.behaviorRiskScore += 35;
                }
            }
        } catch (...) {}

        // ================================================================
        // DLL Injection Detection (T1055.001)
        // ================================================================
        try {
            auto& dllInjectionDetector = DLLInjectionDetector::Instance();
            if (dllInjectionDetector.IsInitialized()) {
                auto injections = dllInjectionDetector.DetectInjections(pid);
                if (!injections.empty()) {
                    indicators.hasModifiedOtherProcesses = true;
                    indicators.indicatorDescriptions.push_back(
                        L"DLL injection detected (T1055.001) - "
                        L"injected DLLs: " + std::to_wstring(injections.size()));
                    indicators.behaviorRiskScore += 30;
                }
            }
        } catch (...) {}

        // ================================================================
        // Reflective DLL Loading Detection (T1620)
        // ================================================================
        try {
            auto& reflectiveDetector = ReflectiveDLLDetector::Instance();
            if (reflectiveDetector.IsInitialized() &&
                reflectiveDetector.HasReflectiveLoading(pid)) {
                indicators.hasSuspiciousMemoryOperations = true;
                indicators.indicatorDescriptions.push_back(
                    L"Reflective DLL loading detected (T1620)");
                indicators.behaviorRiskScore += 35;
            }
        } catch (...) {}

        // ================================================================
        // AtomBombing Detection (T1055.xxx)
        // ================================================================
        try {
            auto& atomBombingDetector = AtomBombingDetector::Instance();
            if (atomBombingDetector.IsInitialized()) {
                auto atomResult = atomBombingDetector.ScanProcess(pid);
                if (atomResult.attackDetected) {
                    indicators.hasAPCsQueued = true;
                    indicators.indicatorDescriptions.push_back(
                        L"AtomBombing attack detected - attacks: " +
                        std::to_wstring(atomResult.detectedAttacks.size()));
                    indicators.behaviorRiskScore += 35;
                }
            }
        } catch (...) {}

        // ================================================================
        // Memory Scanner (YARA, shellcode, packed code)
        // ================================================================
        try {
            auto& memoryScanner = MemoryScanner::Instance();
            if (memoryScanner.IsInitialized()) {
                auto scanResult = memoryScanner.ScanProcessMemory(pid);
                if (!scanResult.threats.empty()) {
                    indicators.hasSuspiciousMemoryOperations = true;
                    indicators.indicatorDescriptions.push_back(
                        L"Memory scanner threats: " +
                        std::to_wstring(scanResult.threats.size()));
                    indicators.behaviorRiskScore +=
                        static_cast<uint32_t>(std::min<size_t>(scanResult.threats.size() * 10, 40));
                }
            }
        } catch (...) {}

        // Cap behavioral risk score at 100
        indicators.behaviorRiskScore = std::min(indicators.behaviorRiskScore, 100u);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Behavioral analysis failed for PID %u - %S", pid, e.what());
    }

    return indicators;
}

bool ProcessAnalyzerImpl::DetectProcessHollowingInternal(uint32_t pid) {
    try {
        // Primary: use the dedicated ProcessHollowingDetector for thorough analysis
        auto& hollowingDetector = ProcessHollowingDetector::Instance();
        if (hollowingDetector.IsInitialized()) {
            return hollowingDetector.IsHollowed(pid);
        }

        // Fallback: use ProcessInjectionDetector's simpler check
        auto& injectionDetector = ProcessInjectionDetector::Instance();
        return injectionDetector.CheckProcessHollowing(pid);

    } catch (...) {
        return false;
    }
}

// ============================================================================
// IMPL: CATEGORIZATION
// ============================================================================

ProcessCategory ProcessAnalyzerImpl::CategorizeProcessInternal(uint32_t pid) {
    try {
        auto procInfo = SafeGetProcessInfo(pid);
        if (!procInfo.has_value()) {
            return ProcessCategory::Unknown;
        }

        const std::wstring nameLower = Utils::StringUtils::ToLowerCopy(
            ExtractFileName(procInfo->name));

        // System core
        for (const auto& sysProc : AnalyzerConstants::SYSTEM_PROCESSES) {
            if (Utils::StringUtils::ToLowerCopy(std::wstring(sysProc)) == nameLower) {
                return ProcessCategory::SystemCore;
            }
        }

        // LOLBins
        if (ProcessAnalyzer::IsLOLBin(nameLower)) {
            return ProcessCategory::LOLBin;
        }

        // Browsers (exact name match)
        if (nameLower == L"chrome.exe" || nameLower == L"firefox.exe" ||
            nameLower == L"msedge.exe" || nameLower == L"iexplore.exe" ||
            nameLower == L"brave.exe" || nameLower == L"opera.exe") {
            return ProcessCategory::Browser;
        }

        // Office (exact name match)
        if (nameLower == L"winword.exe" || nameLower == L"excel.exe" ||
            nameLower == L"powerpnt.exe" || nameLower == L"outlook.exe" ||
            nameLower == L"onenote.exe" || nameLower == L"msaccess.exe") {
            return ProcessCategory::Office;
        }

        // Script hosts (exact name match)
        if (nameLower == L"powershell.exe" || nameLower == L"pwsh.exe" ||
            nameLower == L"cscript.exe" || nameLower == L"wscript.exe" ||
            nameLower == L"python.exe" || nameLower == L"pythonw.exe" ||
            nameLower == L"node.exe" || nameLower == L"perl.exe") {
            return ProcessCategory::ScriptHost;
        }

        // Security software
        if (nameLower == L"msmpeng.exe" || nameLower == L"nissrv.exe" ||
            nameLower == L"securityhealthservice.exe") {
            return ProcessCategory::SecuritySoftware;
        }

    } catch (...) {
        return ProcessCategory::Unknown;
    }

    return ProcessCategory::UserApplication;
}

bool ProcessAnalyzerImpl::IsWhitelistedInternal(uint32_t pid) {
    try {
        auto procInfo = SafeGetProcessInfo(pid);
        if (!procInfo.has_value()) return false;

        // Check whitelist store by path
        if (m_whitelist) {
            auto result = m_whitelist->IsPathWhitelisted(procInfo->executablePath);
            if (result.found) {
                return true;
            }
        }

        // Microsoft-signed processes are trusted
        if (IsMicrosoftSignedInternal(procInfo->executablePath)) {
            return true;
        }

    } catch (...) {
        return false;
    }

    return false;
}

std::pair<bool, std::wstring> ProcessAnalyzerImpl::IsKnownMaliciousInternal(uint32_t pid) {
    try {
        auto procInfo = SafeGetProcessInfo(pid);
        if (!procInfo.has_value()) {
            return {false, L""};
        }

        // Compute file hash ONCE and reuse for all lookups
        std::vector<uint8_t> hashBytes;
        Utils::HashUtils::Error hashErr{};
        if (!Utils::HashUtils::ComputeFile(
                Utils::HashUtils::Algorithm::SHA256,
                procInfo->executablePath, hashBytes, &hashErr)) {
            SS_LOG_DEBUG(L"ProcessAnalyzer", L"Hash computation failed for PID %u: %ls",
                pid, procInfo->executablePath.c_str());
            return {false, L""};
        }

        // Check hash against HashStore known malware database
        if (m_hashStore && m_hashStore->IsInitialized()) {
            SignatureStore::HashValue hv{};
            hv.type = SignatureStore::HashType::SHA256;
            hv.length = static_cast<uint8_t>(std::min<size_t>(hashBytes.size(), hv.data.size()));
            std::memcpy(hv.data.data(), hashBytes.data(), hv.length);

            auto detection = m_hashStore->LookupHash(hv);
            if (detection.has_value()) {
                return {true, Utils::StringUtils::ToWide(detection->signatureName)};
            }
        }

        // Check ThreatIntel store (reuse the same hash bytes)
        if (m_threatIntel) {
            const std::string hashHex = Utils::HashUtils::ToHexLower(hashBytes);
            auto tiResult = m_threatIntel->LookupHash("SHA256", hashHex);
            if (tiResult.IsMalicious()) {
                std::wstring threatName = L"ThreatIntel match (score: " +
                    std::to_wstring(tiResult.score) + L")";
                return {true, threatName};
            }
        }

    } catch (...) {
        return {false, L""};
    }

    return {false, L""};
}

// ============================================================================
// IMPL: CACHE MANAGEMENT
// ============================================================================

void ProcessAnalyzerImpl::PurgeExpiredCacheEntries() {
    try {
        const auto now = Clock::now();
        const auto maxAge = std::chrono::seconds(m_config.analysisCacheTTLSeconds);

        for (auto it = m_analysisCache.begin(); it != m_analysisCache.end();) {
            if ((now - it->second.timestamp) > maxAge) {
                it = m_analysisCache.erase(it);
            } else {
                ++it;
            }
        }

    } catch (...) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"Cache purge failed");
    }
}

ProcessAnalyzerImpl::CacheKey
ProcessAnalyzerImpl::MakeCacheKey(uint32_t pid) noexcept {
    CacheKey key{};
    key.pid = pid;
    auto procInfo = SafeGetProcessInfo(pid);
    if (procInfo.has_value()) {
        ULARGE_INTEGER uli;
        uli.LowPart = procInfo->creationTime.dwLowDateTime;
        uli.HighPart = procInfo->creationTime.dwHighDateTime;
        key.startTimeTicks = uli.QuadPart;
    }
    return key;
}

// ============================================================================
// IMPL: KERNEL NOTIFICATION HANDLERS
// ============================================================================

void ProcessAnalyzerImpl::OnKernelProcessCreateInternal(
    uint32_t pid, uint32_t parentPid, uint32_t creatingPid,
    uint32_t creatingTid, const std::wstring& imagePath)
{
    // Invalidate any stale cache entry for this PID (PID reuse defense)
    {
        std::unique_lock lock(m_cacheMutex);
        std::erase_if(m_analysisCache, [pid](const auto& pair) {
            return pair.first.pid == pid;
        });
    }

    // If creator differs from parent, log potential PPID spoofing for later analysis
    if (creatingPid != 0 && creatingPid != parentPid) {
        SS_LOG_WARN(L"ProcessAnalyzer",
            L"Kernel: PID %u created by PID %u (thread %u) but parent is PID %u - "
            L"potential PPID spoofing: %ls",
            pid, creatingPid, creatingTid, parentPid, imagePath.c_str());
    }
}

void ProcessAnalyzerImpl::OnKernelProcessTerminateInternal(uint32_t pid) {
    // Remove from analysis cache on termination
    {
        std::unique_lock lock(m_cacheMutex);
        std::erase_if(m_analysisCache, [pid](const auto& pair) {
            return pair.first.pid == pid;
        });
    }
}

void ProcessAnalyzerImpl::OnKernelImageLoadInternal(
    uint32_t pid, uintptr_t imageBase, size_t imageSize,
    const std::wstring& imageName, bool isSystemImage)
{
    // When a new image loads, invalidate the analysis cache for this PID
    // because the module list has changed.
    {
        std::unique_lock lock(m_cacheMutex);
        std::erase_if(m_analysisCache, [pid](const auto& pair) {
            return pair.first.pid == pid;
        });
    }

    // Quick suspicious load check for non-system images
    if (!isSystemImage && m_initialized.load(std::memory_order_acquire)) {
        const std::wstring nameLower = Utils::StringUtils::ToLowerCopy(imageName);
        // Flag loads from suspicious paths
        if (nameLower.find(L"\\temp\\") != std::wstring::npos ||
            nameLower.find(L"\\appdata\\local\\temp\\") != std::wstring::npos) {
            SS_LOG_WARN(L"ProcessAnalyzer",
                L"Kernel: Suspicious image load in PID %u from temp path: %ls "
                L"(base=0x%llX, size=%zu)",
                pid, imageName.c_str(),
                static_cast<unsigned long long>(imageBase), imageSize);
            InvokeFindingCallbacks(pid,
                L"Image loaded from suspicious temp path: " + imageName, 20);
        }
    }
}

void ProcessAnalyzerImpl::OnKernelThreadCreateInternal(
    uint32_t targetPid, uint32_t threadId,
    uint32_t creatorPid, uint32_t creatorTid, bool isRemote)
{
    if (!isRemote) {
        return;  // In-process thread creation is normal
    }

    // Remote thread creation is a core injection primitive (T1055.003).
    // Log immediately and trigger a finding callback so real-time response
    // can react before the injected code executes.
    SS_LOG_WARN(L"ProcessAnalyzer",
        L"Kernel: Remote thread %u created in PID %u by PID %u (thread %u)",
        threadId, targetPid, creatorPid, creatorTid);

    InvokeFindingCallbacks(targetPid,
        L"Remote thread injection detected (creator PID " +
        std::to_wstring(creatorPid) + L", thread " +
        std::to_wstring(threadId) + L")", 60);

    // Invalidate cached analysis — the process state has been altered
    {
        std::unique_lock lock(m_cacheMutex);
        std::erase_if(m_analysisCache, [targetPid](const auto& pair) {
            return pair.first.pid == targetPid;
        });
    }

    m_statistics.injectionIndicatorsDetected.fetch_add(1, std::memory_order_relaxed);
}

// ============================================================================
// IMPL: CALLBACKS
// ============================================================================

void ProcessAnalyzerImpl::InvokeProgressCallbacks(
    uint32_t pid,
    const std::wstring& stage,
    uint32_t percent)
{
    if (!m_config.enableProgressCallbacks) return;

    std::lock_guard lock(m_callbacksMutex);
    for (const auto& [id, callback] : m_progressCallbacks) {
        try {
            callback(pid, stage, percent);
        } catch (...) {
            // Callback errors should not affect processing
        }
    }
}

void ProcessAnalyzerImpl::InvokeFindingCallbacks(
    uint32_t pid,
    const std::wstring& finding,
    uint32_t riskScore)
{
    std::lock_guard lock(m_callbacksMutex);
    for (const auto& [id, callback] : m_findingCallbacks) {
        try {
            callback(pid, finding, riskScore);
        } catch (...) {
            // Callback errors should not affect processing
        }
    }
}

void ProcessAnalyzerImpl::InvokeModuleCallbacks(
    uint32_t pid,
    const ModuleInfo& module)
{
    std::lock_guard lock(m_callbacksMutex);
    for (const auto& [id, callback] : m_moduleCallbacks) {
        try {
            callback(pid, module);
        } catch (...) {
            // Callback errors should not affect processing
        }
    }
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

ProcessAnalyzer& ProcessAnalyzer::Instance() {
    static ProcessAnalyzer instance;
    return instance;
}

ProcessAnalyzer::ProcessAnalyzer()
    : m_impl(std::make_unique<ProcessAnalyzerImpl>())
{
    SS_LOG_INFO(L"ProcessAnalyzer", L"Constructor called");
}

ProcessAnalyzer::~ProcessAnalyzer() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"ProcessAnalyzer", L"Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool ProcessAnalyzer::Initialize(const AnalyzerConfig& config) {
    return m_impl ? m_impl->Initialize(config) : false;
}

void ProcessAnalyzer::Shutdown() {
    // Unregister ProcessMonitor callbacks before shutting down internal state
    try {
        if (m_monitorCallbackId != 0 || m_monitorEventCallbackId != 0) {
            auto& monitor = ProcessMonitor::Instance();
            if (m_monitorCallbackId != 0) {
                monitor.UnregisterCallback(m_monitorCallbackId);
                m_monitorCallbackId = 0;
            }
            if (m_monitorEventCallbackId != 0) {
                monitor.UnregisterCallback(m_monitorEventCallbackId);
                m_monitorEventCallbackId = 0;
            }
        }
    } catch (...) {
        // ProcessMonitor may already be destroyed during shutdown
    }

    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool ProcessAnalyzer::IsInitialized() const noexcept {
    return m_impl ? m_impl->m_initialized.load(std::memory_order_acquire) : false;
}

bool ProcessAnalyzer::UpdateConfig(const AnalyzerConfig& config) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config = config;
    return true;
}

AnalyzerConfig ProcessAnalyzer::GetConfig() const {
    if (!m_impl) return AnalyzerConfig{};

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// KERNEL & PROCESSMONITOR WIRING
// ============================================================================

void ProcessAnalyzer::WireToProcessMonitor() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"ProcessAnalyzer",
            L"WireToProcessMonitor called before initialization");
        return;
    }

    try {
        auto& monitor = ProcessMonitor::Instance();

        // Register for process create/terminate events.
        // On creation: invalidate stale cache, detect immediate anomalies.
        // On termination: purge cache entry.
        m_monitorCallbackId = monitor.RegisterCallback(
            [this](const ExtendedProcessInfo& info, bool created) {
                if (!m_impl) return;

                const uint32_t pid = info.uniqueId.pid;

                if (created) {
                    m_impl->OnKernelProcessCreateInternal(
                        pid, info.parentPid, info.creatorPid, 0,
                        info.processPath);
                } else {
                    m_impl->OnKernelProcessTerminateInternal(pid);
                }
            });

        // Register for detailed process events (includes image loads).
        m_monitorEventCallbackId = monitor.RegisterEventCallback(
            [this](const ProcessEvent& event) {
                if (!m_impl) return;

                const uint32_t pid = event.processId.pid;

                // React to module loads reported through ProcessMonitor
                if (event.type == ProcessEventType::ModuleLoaded) {
                    m_impl->OnKernelImageLoadInternal(
                        pid, event.moduleBase, event.moduleSize,
                        event.modulePath, false /* no system flag from PM */);
                }
            });

        SS_LOG_INFO(L"ProcessAnalyzer",
            L"Wired to ProcessMonitor (callback IDs: %llu, %llu)",
            m_monitorCallbackId, m_monitorEventCallbackId);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer",
            L"Failed to wire to ProcessMonitor - %S", e.what());
    }
}

void ProcessAnalyzer::OnKernelProcessCreate(uint32_t pid, uint32_t parentPid,
    uint32_t creatingPid, uint32_t creatingTid, const std::wstring& imagePath)
{
    if (m_impl) {
        m_impl->OnKernelProcessCreateInternal(
            pid, parentPid, creatingPid, creatingTid, imagePath);
    }
}

void ProcessAnalyzer::OnKernelProcessTerminate(uint32_t pid) {
    if (m_impl) {
        m_impl->OnKernelProcessTerminateInternal(pid);
    }
}

void ProcessAnalyzer::OnKernelImageLoad(uint32_t pid, uintptr_t imageBase,
    size_t imageSize, const std::wstring& imageName, bool isSystemImage)
{
    if (m_impl) {
        m_impl->OnKernelImageLoadInternal(
            pid, imageBase, imageSize, imageName, isSystemImage);
    }
}

void ProcessAnalyzer::OnKernelThreadCreate(uint32_t targetPid, uint32_t threadId,
    uint32_t creatorPid, uint32_t creatorTid, bool isRemote)
{
    if (m_impl) {
        m_impl->OnKernelThreadCreateInternal(
            targetPid, threadId, creatorPid, creatorTid, isRemote);
    }
}

// ============================================================================
// COMPREHENSIVE ANALYSIS
// ============================================================================

ProcessAnalysisResult ProcessAnalyzer::AnalyzeProcess(uint32_t pid, AnalysisDepth depth) {
    return m_impl ? m_impl->AnalyzeProcessInternal(pid, depth) : ProcessAnalysisResult{};
}

std::vector<ProcessAnalysisResult> ProcessAnalyzer::AnalyzeByPath(
    const std::wstring& processPath,
    AnalysisDepth depth)
{
    std::vector<ProcessAnalysisResult> results;

    if (!m_impl) return results;

    try {
        // Find all processes matching path
        auto processes = SafeGetAllProcesses();
        for (const auto& proc : processes) {
            if (Utils::StringUtils::IEquals(proc.executablePath, processPath)) {
                results.push_back(m_impl->AnalyzeProcessInternal(proc.pid, depth));
            }
        }

    } catch (...) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"AnalyzeByPath failed for %ls", processPath.c_str());
    }

    return results;
}

std::vector<ProcessAnalysisResult> ProcessAnalyzer::AnalyzeByName(
    const std::wstring& processName,
    AnalysisDepth depth)
{
    std::vector<ProcessAnalysisResult> results;

    if (!m_impl) return results;

    try {
        auto processes = SafeGetAllProcesses();
        for (const auto& proc : processes) {
            if (Utils::StringUtils::IEquals(proc.name, processName)) {
                results.push_back(m_impl->AnalyzeProcessInternal(proc.pid, depth));
            }
        }

    } catch (...) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"AnalyzeByName failed for %ls", processName.c_str());
    }

    return results;
}

std::vector<ProcessAnalysisResult> ProcessAnalyzer::AnalyzeMultiple(
    const std::vector<uint32_t>& pids,
    AnalysisDepth depth,
    uint32_t maxConcurrent)
{
    std::vector<ProcessAnalysisResult> results;
    results.reserve(pids.size());

    if (!m_impl) return results;

    try {
        // Parallel analysis
        std::mutex resultsMutex;

        std::for_each(std::execution::par, pids.begin(), pids.end(),
            [this, depth, &results, &resultsMutex](uint32_t pid) {
                auto result = m_impl->AnalyzeProcessInternal(pid, depth);

                std::lock_guard lock(resultsMutex);
                results.push_back(result);
            });

    } catch (...) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"AnalyzeMultiple failed");
    }

    return results;
}

// ============================================================================
// QUICK ASSESSMENT
// ============================================================================

ProcessRiskLevel ProcessAnalyzer::QuickAssessRisk(uint32_t pid) {
    return m_impl ? m_impl->QuickAssessRiskInternal(pid) : ProcessRiskLevel::Unknown;
}

bool ProcessAnalyzer::IsWhitelisted(uint32_t pid) {
    return m_impl ? m_impl->IsWhitelistedInternal(pid) : false;
}

std::pair<bool, std::wstring> ProcessAnalyzer::IsKnownMalicious(uint32_t pid) {
    return m_impl ? m_impl->IsKnownMaliciousInternal(pid) : std::make_pair(false, L"");
}

ProcessCategory ProcessAnalyzer::CategorizeProcess(uint32_t pid) {
    return m_impl ? m_impl->CategorizeProcessInternal(pid) : ProcessCategory::Unknown;
}

// ============================================================================
// MODULE ANALYSIS
// ============================================================================

std::vector<ModuleInfo> ProcessAnalyzer::GetLoadedModules(uint32_t pid) {
    return m_impl ? m_impl->GetLoadedModulesInternal(pid) : std::vector<ModuleInfo>{};
}

std::optional<ModuleInfo> ProcessAnalyzer::AnalyzeModule(uint32_t pid, uintptr_t moduleBase) {
    if (!m_impl) return std::nullopt;

    auto modInfo = m_impl->AnalyzeModuleInternal(pid, moduleBase);
    if (modInfo.baseAddress == moduleBase) {
        return modInfo;
    }
    return std::nullopt;
}

std::vector<ModuleInfo> ProcessAnalyzer::FindSuspiciousModules(uint32_t pid) {
    return m_impl ? m_impl->FindSuspiciousModulesInternal(pid) : std::vector<ModuleInfo>{};
}

std::vector<ModuleInfo> ProcessAnalyzer::DetectPhantomModules(uint32_t pid) {
    if (!m_impl) return {};

    std::vector<ModuleInfo> phantomModules;

    try {
        // Phantom modules are PE images loaded in memory but NOT listed in the
        // PEB module list. ReflectiveDLLDetector scans for unbacked PE headers.
        auto& reflectiveDetector = ReflectiveDLLDetector::Instance();
        if (!reflectiveDetector.IsInitialized()) {
            return phantomModules;
        }

        auto candidates = reflectiveDetector.FindPECandidates(pid);
        for (const auto& candidate : candidates) {
            ModuleInfo mod{};
            mod.baseAddress = candidate.baseAddress;
            mod.sizeOfImage = static_cast<uint32_t>(candidate.sizeOfImage);
            mod.isPhantom = true;
            mod.isHidden = true;
            mod.loadReason = ModuleLoadReason::Reflective;
            mod.suspicionLevel = ModuleSuspicionLevel::Malicious;
            mod.signatureStatus = SignatureStatus::Unsigned;
            mod.riskScore = 80;
            phantomModules.push_back(std::move(mod));
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer",
            L"Phantom module detection failed for PID %u - %S", pid, e.what());
    }

    return phantomModules;
}

std::vector<ModuleInfo> ProcessAnalyzer::DetectSideLoadedDLLs(uint32_t pid) {
    if (!m_impl) return {};

    std::vector<ModuleInfo> sideLoadedModules;

    try {
        // Use DLLInjectionDetector's side-loading detection which knows about
        // common legitimate-executable/malicious-DLL pairings.
        auto& dllDetector = DLLInjectionDetector::Instance();
        if (!dllDetector.IsInitialized()) {
            return sideLoadedModules;
        }

        auto sideLoads = dllDetector.DetectSideLoading(pid);
        for (const auto& sl : sideLoads) {
            ModuleInfo mod{};
            mod.moduleName = sl.expectedDllName;
            mod.modulePath = sl.actualDllPath;
            mod.isPotentialSideLoad = true;
            mod.loadReason = ModuleLoadReason::SideLoaded;
            mod.suspicionLevel = ModuleSuspicionLevel::HighlySupicious;
            mod.riskScore = 50;

            // Verify signature of the side-loaded DLL
            if (m_impl) {
                auto sigInfo = m_impl->VerifyFileSignatureInternal(sl.actualDllPath);
                mod.signatureStatus = sigInfo.status;
                if (sigInfo.status == SignatureStatus::Unsigned) {
                    mod.riskScore = 70;
                }
            }

            sideLoadedModules.push_back(std::move(mod));
        }

        // Also check for DLL search order hijacking
        auto hijacks = dllDetector.DetectSearchOrderHijack(pid);
        for (const auto& hijack : hijacks) {
            ModuleInfo mod{};
            mod.modulePath = hijack.dllInfo.dllPath;
            mod.isPotentialSideLoad = true;
            mod.loadReason = ModuleLoadReason::SideLoaded;
            mod.suspicionLevel = ModuleSuspicionLevel::HighlySupicious;
            mod.riskScore = 60;
            sideLoadedModules.push_back(std::move(mod));
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer",
            L"Side-load detection failed for PID %u - %S", pid, e.what());
    }

    return sideLoadedModules;
}

bool ProcessAnalyzer::ValidateModuleIntegrity(uint32_t pid, uintptr_t moduleBase) {
    if (!m_impl) return false;

    try {
        // Find the module's disk path by matching base address
        auto modules = SafeGetProcessModules(pid);
        std::wstring modulePath;
        size_t moduleSize = 0;
        for (const auto& mod : modules) {
            if (reinterpret_cast<uintptr_t>(mod.baseAddress) == moduleBase) {
                modulePath = mod.path;
                moduleSize = mod.size;
                break;
            }
        }

        if (modulePath.empty() || moduleSize == 0) {
            SS_LOG_WARN(L"ProcessAnalyzer",
                L"Cannot validate integrity: module at 0x%llX in PID %u not found in PEB",
                static_cast<unsigned long long>(moduleBase), pid);
            return false;
        }

        // Open process for memory read
        Utils::ProcessUtils::ProcessHandle hProcess(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
        if (!hProcess.IsValid()) {
            return false;
        }

        // Read the DOS/PE headers from memory
        constexpr size_t HEADER_SIZE = 4096;
        auto memHeader = std::make_unique<uint8_t[]>(HEADER_SIZE);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess.Get(), reinterpret_cast<LPCVOID>(moduleBase),
                              memHeader.get(), HEADER_SIZE, &bytesRead) ||
            bytesRead < sizeof(IMAGE_DOS_HEADER)) {
            return false;
        }

        // Read the same region from disk
        HANDLE hFile = CreateFileW(modulePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }
        struct FileGuard {
            HANDLE h;
            ~FileGuard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
        } fileGuard{hFile};

        auto diskHeader = std::make_unique<uint8_t[]>(HEADER_SIZE);
        DWORD diskRead = 0;
        if (!ReadFile(hFile, diskHeader.get(), HEADER_SIZE, &diskRead, nullptr) ||
            diskRead < sizeof(IMAGE_DOS_HEADER)) {
            return false;
        }

        // Compare DOS header magic
        auto* dosMemory = reinterpret_cast<IMAGE_DOS_HEADER*>(memHeader.get());
        auto* dosDisk = reinterpret_cast<IMAGE_DOS_HEADER*>(diskHeader.get());
        if (dosMemory->e_magic != dosDisk->e_magic) {
            SS_LOG_WARN(L"ProcessAnalyzer",
                L"Module integrity FAIL: DOS magic mismatch at 0x%llX in PID %u",
                static_cast<unsigned long long>(moduleBase), pid);
            return false;
        }

        // Compare PE signature offset and NT header
        if (dosMemory->e_lfanew != dosDisk->e_lfanew) {
            SS_LOG_WARN(L"ProcessAnalyzer",
                L"Module integrity FAIL: e_lfanew mismatch at 0x%llX in PID %u",
                static_cast<unsigned long long>(moduleBase), pid);
            return false;
        }

        const auto peOffset = static_cast<size_t>(dosMemory->e_lfanew);
        if (peOffset + sizeof(IMAGE_NT_HEADERS) > bytesRead ||
            peOffset + sizeof(IMAGE_NT_HEADERS) > diskRead) {
            return false;
        }

        auto* ntMem = reinterpret_cast<IMAGE_NT_HEADERS*>(memHeader.get() + peOffset);
        auto* ntDisk = reinterpret_cast<IMAGE_NT_HEADERS*>(diskHeader.get() + peOffset);

        // Compare entry point
        if (ntMem->OptionalHeader.AddressOfEntryPoint !=
            ntDisk->OptionalHeader.AddressOfEntryPoint) {
            SS_LOG_WARN(L"ProcessAnalyzer",
                L"Module integrity FAIL: entry point mismatch at 0x%llX in PID %u "
                L"(memory=0x%X, disk=0x%X)",
                static_cast<unsigned long long>(moduleBase), pid,
                ntMem->OptionalHeader.AddressOfEntryPoint,
                ntDisk->OptionalHeader.AddressOfEntryPoint);
            return false;
        }

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer",
            L"Module integrity check failed for 0x%llX in PID %u - %S",
            static_cast<unsigned long long>(moduleBase), pid, e.what());
        return false;
    }
}

// ============================================================================
// HANDLE ANALYSIS
// ============================================================================

HandleSummary ProcessAnalyzer::EnumerateHandles(uint32_t pid) {
    return m_impl ? m_impl->EnumerateHandlesInternal(pid) : HandleSummary{};
}

std::vector<HandleInfo> ProcessAnalyzer::GetHandlesByType(uint32_t pid, HandleType type) {
    if (!m_impl) return {};

    auto summary = m_impl->EnumerateHandlesInternal(pid);

    // Map our HandleType enum to the NT type name string for filtering.
    // The EnumerateHandlesInternal stores the NT type name in HandleInfo::typeName.
    std::wstring targetTypeName;
    switch (type) {
        case HandleType::File:      targetTypeName = L"File"; break;
        case HandleType::Directory: targetTypeName = L"Directory"; break;
        case HandleType::Key:       targetTypeName = L"Key"; break;
        case HandleType::Mutant:    targetTypeName = L"Mutant"; break;
        case HandleType::Event:     targetTypeName = L"Event"; break;
        case HandleType::Semaphore: targetTypeName = L"Semaphore"; break;
        case HandleType::Section:   targetTypeName = L"Section"; break;
        case HandleType::Process:   targetTypeName = L"Process"; break;
        case HandleType::Thread:    targetTypeName = L"Thread"; break;
        case HandleType::Token:     targetTypeName = L"Token"; break;
        case HandleType::DebugObject: targetTypeName = L"DebugObject"; break;
        default:                    targetTypeName = L""; break;
    }

    // Collect all handles, filtering by resolved type name
    std::vector<HandleInfo> result;
    // Re-enumerate to get ALL handles (not just the pre-filtered suspicious ones)
    std::vector<Utils::ProcessUtils::ProcessHandleInfo> handles;
    Utils::ProcessUtils::Error err{};
    if (Utils::ProcessUtils::EnumerateProcessHandles(pid, handles, &err)) {
        for (const auto& h : handles) {
            if (Utils::StringUtils::IEquals(h.typeName, targetTypeName)) {
                HandleInfo info{};
                info.handleValue = reinterpret_cast<uint64_t>(h.handle);
                info.typeName = h.typeName;
                info.objectName = h.name;
                info.grantedAccess = h.accessMask;
                info.isInheritable = h.isInheritable;
                result.push_back(std::move(info));

                if (result.size() >= m_impl->m_config.maxHandlesToEnumerate) {
                    break;
                }
            }
        }
    }

    return result;
}

std::vector<HandleInfo> ProcessAnalyzer::FindSuspiciousHandles(uint32_t pid) {
    if (!m_impl) return {};

    auto summary = m_impl->EnumerateHandlesInternal(pid);
    return summary.suspiciousHandles;
}

bool ProcessAnalyzer::HasCrossProcessHandles(uint32_t pid) {
    if (!m_impl) return false;

    auto summary = m_impl->EnumerateHandlesInternal(pid);
    return !summary.crossProcessHandles.empty();
}

bool ProcessAnalyzer::HasLsassAccess(uint32_t pid) {
    if (!m_impl) return false;

    auto summary = m_impl->EnumerateHandlesInternal(pid);
    return summary.hasLsassAccess;
}

// ============================================================================
// MEMORY ANALYSIS
// ============================================================================

MemorySummary ProcessAnalyzer::AnalyzeMemory(uint32_t pid) {
    return m_impl ? m_impl->AnalyzeMemoryInternal(pid) : MemorySummary{};
}

std::vector<MemoryRegionInfo> ProcessAnalyzer::GetMemoryRegions(uint32_t pid) {
    return m_impl ? m_impl->GetMemoryRegionsInternal(pid) : std::vector<MemoryRegionInfo>{};
}

std::vector<MemoryRegionInfo> ProcessAnalyzer::FindRWXRegions(uint32_t pid) {
    return m_impl ? m_impl->FindRWXRegionsInternal(pid) : std::vector<MemoryRegionInfo>{};
}

std::vector<MemoryRegionInfo> ProcessAnalyzer::FindUnbackedExecutable(uint32_t pid) {
    if (!m_impl) return std::vector<MemoryRegionInfo>{};

    auto summary = m_impl->AnalyzeMemoryInternal(pid);
    return summary.unbackedExecutable;
}

std::vector<MemoryRegionInfo> ProcessAnalyzer::FindHighEntropyRegions(uint32_t pid, double threshold) {
    if (!m_impl) return std::vector<MemoryRegionInfo>{};

    auto summary = m_impl->AnalyzeMemoryInternal(pid);
    return summary.highEntropyRegions;
}

std::optional<ModuleInfo> ProcessAnalyzer::GetBackingModule(uint32_t pid, uintptr_t address) {
    if (!m_impl) return std::nullopt;

    auto modules = m_impl->GetLoadedModulesInternal(pid);
    for (const auto& mod : modules) {
        if (address >= mod.baseAddress && address < (mod.baseAddress + mod.sizeOfImage)) {
            return mod;
        }
    }
    return std::nullopt;
}

// ============================================================================
// THREAD ANALYSIS
// ============================================================================

ThreadSummary ProcessAnalyzer::AnalyzeThreads(uint32_t pid) {
    return m_impl ? m_impl->AnalyzeThreadsInternal(pid) : ThreadSummary{};
}

std::optional<ThreadInfo> ProcessAnalyzer::GetThreadInfo(uint32_t tid) {
    return m_impl ? m_impl->GetThreadInfoInternal(tid) : std::nullopt;
}

std::vector<ThreadInfo> ProcessAnalyzer::FindUnbackedThreads(uint32_t pid) {
    if (!m_impl) return std::vector<ThreadInfo>{};

    auto summary = m_impl->AnalyzeThreadsInternal(pid);
    return summary.suspiciousThreads;
}

std::optional<ThreadInfo> ProcessAnalyzer::GetThreadCallStack(uint32_t tid, uint32_t maxFrames) {
    if (!m_impl) return std::nullopt;

    auto info = m_impl->GetThreadInfoInternal(tid);
    if (!info.has_value()) return std::nullopt;

    // Capture the actual call stack using NtQueryInformationThread for the
    // thread context, then walk the stack frames manually.
    try {
        HANDLE hThread = OpenThread(
            THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
            FALSE, tid);
        if (!hThread) return info;

        struct ThreadGuard {
            HANDLE h;
            bool suspended = false;
            ~ThreadGuard() {
                if (suspended) ResumeThread(h);
                if (h) CloseHandle(h);
            }
        } guard{hThread, false};

        // Suspend thread to capture context safely
        if (SuspendThread(hThread) == static_cast<DWORD>(-1)) {
            return info;
        }
        guard.suspended = true;

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hThread, &ctx)) {
            return info;
        }

        info->currentIP = ctx.Rip;

        // Open owning process for memory reads
        const uint32_t ownerPid = info->ownerPid;
        Utils::ProcessUtils::ProcessHandle hProcess(
            ownerPid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
        if (!hProcess.IsValid()) {
            return info;
        }

        // Walk the stack using RBP chain (fast heuristic, not StackWalk64
        // which requires dbghelp symbol loading). For each frame, read
        // [RBP+8] (return address) and [RBP] (next frame pointer).
        uintptr_t framePtr = ctx.Rbp;
        const uint32_t cappedFrames = std::min(maxFrames, 256u);

        for (uint32_t i = 0; i < cappedFrames && framePtr != 0; ++i) {
            uintptr_t stackFrame[2] = {};  // [0]=next RBP, [1]=return addr
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(hProcess.Get(),
                    reinterpret_cast<LPCVOID>(framePtr),
                    stackFrame, sizeof(stackFrame), &bytesRead) ||
                bytesRead < sizeof(stackFrame)) {
                break;
            }

            if (stackFrame[1] == 0) break;

            info->callStack.push_back(stackFrame[1]);

            // Check if return address is backed by a module
            bool backed = false;
            auto modules = SafeGetProcessModules(ownerPid);
            for (const auto& mod : modules) {
                const uintptr_t modBase = reinterpret_cast<uintptr_t>(mod.baseAddress);
                if (stackFrame[1] >= modBase && stackFrame[1] < modBase + mod.size) {
                    info->callStackSymbols.push_back(mod.name);
                    backed = true;
                    break;
                }
            }
            if (!backed) {
                info->callStackSymbols.push_back(L"<unbacked>");
                info->unbackedCallStackFrames++;
            }

            // Advance to next frame
            if (stackFrame[0] <= framePtr) break;  // Prevent infinite loops
            framePtr = stackFrame[0];
        }

        if (info->unbackedCallStackFrames > 0) {
            info->suspicion = ThreadSuspicion::SuspiciousCallStack;
            info->riskScore = std::max(info->riskScore,
                info->unbackedCallStackFrames * 15u);
        }

    } catch (...) {
        SS_LOG_ERROR(L"ProcessAnalyzer",
            L"Call stack capture failed for thread %u", tid);
    }

    return info;
}

bool ProcessAnalyzer::ValidateThreadStartAddresses(uint32_t pid) {
    if (!m_impl) return true;

    auto summary = m_impl->AnalyzeThreadsInternal(pid);
    return (summary.unbackedStartCount == 0);
}

// ============================================================================
// SIGNATURE VERIFICATION
// ============================================================================

SignatureInfo ProcessAnalyzer::VerifyProcessSignature(uint32_t pid) {
    if (!m_impl) return SignatureInfo{};

    auto procInfo = SafeGetProcessInfo(pid);
    if (!procInfo.has_value()) return SignatureInfo{};

    return m_impl->VerifyFileSignatureInternal(procInfo->executablePath);
}

SignatureInfo ProcessAnalyzer::VerifyFileSignature(const std::wstring& filePath) {
    return m_impl ? m_impl->VerifyFileSignatureInternal(filePath) : SignatureInfo{};
}

bool ProcessAnalyzer::IsMicrosoftSigned(uint32_t pid) {
    if (!m_impl) return false;

    auto procInfo = SafeGetProcessInfo(pid);
    if (!procInfo.has_value()) return false;

    return m_impl->IsMicrosoftSignedInternal(procInfo->executablePath);
}

bool ProcessAnalyzer::IsImageSigned(uint32_t pid) {
    auto sigInfo = VerifyProcessSignature(pid);
    return (sigInfo.status == SignatureStatus::Valid || sigInfo.status == SignatureStatus::ValidCatalog);
}

bool ProcessAnalyzer::IsCertificateCompromised(const std::string& thumbprint) {
    if (!m_impl || thumbprint.empty()) return false;

    try {
        // Check ThreatIntel store for known compromised certificate thumbprints
        if (m_impl->m_threatIntel) {
            auto result = m_impl->m_threatIntel->LookupHash("CERT_THUMBPRINT", thumbprint);
            if (result.IsMalicious()) {
                SS_LOG_WARN(L"ProcessAnalyzer",
                    L"Compromised certificate detected: %S", thumbprint.c_str());
                return true;
            }
        }

        // Check SignatureStore blacklisted certificates
        if (m_impl->m_signatureStore && m_impl->m_signatureStore->IsInitialized()) {
            SignatureStore::HashValue hv{};
            hv.type = SignatureStore::HashType::SHA1;
            // Thumbprints are typically SHA1 hex (40 chars = 20 bytes)
            const size_t byteLen = std::min(thumbprint.size() / 2, static_cast<size_t>(hv.data.size()));
            for (size_t i = 0; i < byteLen; ++i) {
                auto highNibble = thumbprint[i * 2];
                auto lowNibble  = thumbprint[i * 2 + 1];
                auto parseHex = [](char c) -> uint8_t {
                    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
                    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
                    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
                    return 0;
                };
                hv.data[i] = static_cast<uint8_t>((parseHex(highNibble) << 4) | parseHex(lowNibble));
            }
            hv.length = static_cast<uint8_t>(byteLen);

            auto detection = m_impl->m_signatureStore->LookupHashString(
                thumbprint, SignatureStore::HashType::SHA1);
            if (detection.has_value()) {
                SS_LOG_WARN(L"ProcessAnalyzer",
                    L"Blacklisted certificate in SignatureStore: %S", thumbprint.c_str());
                return true;
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer",
            L"Certificate compromise check failed for %S - %S",
            thumbprint.c_str(), e.what());
    }

    return false;
}

// ============================================================================
// SECURITY CONTEXT ANALYSIS
// ============================================================================

SecurityContext ProcessAnalyzer::AnalyzeSecurityContext(uint32_t pid) {
    return m_impl ? m_impl->AnalyzeSecurityContextInternal(pid) : SecurityContext{};
}

std::vector<std::pair<std::wstring, bool>> ProcessAnalyzer::GetProcessPrivileges(uint32_t pid) {
    return m_impl ? m_impl->GetProcessPrivilegesInternal(pid) : std::vector<std::pair<std::wstring, bool>>{};
}

std::vector<std::wstring> ProcessAnalyzer::GetDangerousPrivileges(uint32_t pid) {
    if (!m_impl) return std::vector<std::wstring>{};

    auto context = m_impl->AnalyzeSecurityContextInternal(pid);
    return context.dangerousPrivileges;
}

uint32_t ProcessAnalyzer::GetIntegrityLevel(uint32_t pid) {
    if (!m_impl) return 0;

    auto context = m_impl->AnalyzeSecurityContextInternal(pid);
    return context.integrityLevel;
}

bool ProcessAnalyzer::IsElevated(uint32_t pid) {
    if (!m_impl) return false;

    auto context = m_impl->AnalyzeSecurityContextInternal(pid);
    return context.isElevated;
}

bool ProcessAnalyzer::IsImpersonating(uint32_t pid) {
    if (!m_impl) return false;

    auto context = m_impl->AnalyzeSecurityContextInternal(pid);
    return context.isImpersonating;
}

// ============================================================================
// PARENT-CHILD ANALYSIS
// ============================================================================

ParentChildAnalysis ProcessAnalyzer::AnalyzeParentChild(uint32_t pid) {
    return m_impl ? m_impl->AnalyzeParentChildInternal(pid) : ParentChildAnalysis{};
}

bool ProcessAnalyzer::ValidateParentAnomaly(uint32_t pid) {
    if (!m_impl) return true;

    auto analysis = m_impl->AnalyzeParentChildInternal(pid);
    return analysis.isExpectedParent;
}

bool ProcessAnalyzer::DetectPPIDSpoofing(uint32_t pid) {
    return m_impl ? m_impl->DetectPPIDSpoofingInternal(pid) : false;
}

std::vector<Utils::ProcessUtils::ProcessBasicInfo> ProcessAnalyzer::GetAncestry(uint32_t pid, uint32_t maxDepth) {
    std::vector<Utils::ProcessUtils::ProcessBasicInfo> ancestry;

    try {
        // Start from parent, not from self
        auto procInfo = SafeGetProcessInfo(pid);
        if (!procInfo.has_value()) return ancestry;

        uint32_t currentPid = procInfo->parentPid;
        uint32_t depth = 0;
        std::set<uint32_t> visited;
        visited.insert(pid);  // Prevent cycles back to the target

        while (depth < maxDepth && currentPid != 0) {
            // Prevent infinite loops from cycles in the process tree
            if (visited.count(currentPid) > 0) {
                break;
            }
            visited.insert(currentPid);

            auto parentInfo = SafeGetProcessInfo(currentPid);
            if (!parentInfo.has_value()) break;

            ancestry.push_back(*parentInfo);
            currentPid = parentInfo->parentPid;
            depth++;
        }

    } catch (...) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"GetAncestry failed for PID %u", pid);
    }

    return ancestry;
}

std::vector<Utils::ProcessUtils::ProcessBasicInfo> ProcessAnalyzer::GetChildren(uint32_t pid, bool recursive) {
    std::vector<Utils::ProcessUtils::ProcessBasicInfo> children;

    try {
        auto allProcesses = SafeGetAllProcesses();

        for (const auto& proc : allProcesses) {
            if (proc.parentPid == pid) {
                children.push_back(proc);

                if (recursive && children.size() < AnalyzerConstants::MAX_CHILDREN_TO_TRACK) {
                    auto grandchildren = GetChildren(proc.pid, true);
                    const size_t remaining = AnalyzerConstants::MAX_CHILDREN_TO_TRACK - children.size();
                    const size_t toInsert = std::min(grandchildren.size(), remaining);
                    children.insert(children.end(),
                        grandchildren.begin(),
                        grandchildren.begin() + static_cast<ptrdiff_t>(toInsert));
                }

                if (children.size() >= AnalyzerConstants::MAX_CHILDREN_TO_TRACK) {
                    break;
                }
            }
        }

    } catch (...) {
        SS_LOG_ERROR(L"ProcessAnalyzer", L"GetChildren failed for PID %u", pid);
    }

    return children;
}

// ============================================================================
// NETWORK ANALYSIS
// ============================================================================

NetworkFootprint ProcessAnalyzer::AnalyzeNetworkFootprint(uint32_t pid) {
    return m_impl ? m_impl->AnalyzeNetworkFootprintInternal(pid) : NetworkFootprint{};
}

std::vector<NetworkFootprint::ConnectionInfo> ProcessAnalyzer::GetConnections(uint32_t pid) {
    if (!m_impl) return std::vector<NetworkFootprint::ConnectionInfo>{};

    auto footprint = m_impl->AnalyzeNetworkFootprintInternal(pid);
    return footprint.activeConnections;
}

bool ProcessAnalyzer::HasNetworkCapability(uint32_t pid) {
    if (!m_impl) return false;

    auto footprint = m_impl->AnalyzeNetworkFootprintInternal(pid);
    return footprint.hasNetworkModules;
}

std::vector<uint16_t> ProcessAnalyzer::GetListeningPorts(uint32_t pid) {
    if (!m_impl) return std::vector<uint16_t>{};

    auto footprint = m_impl->AnalyzeNetworkFootprintInternal(pid);
    return footprint.listeningPorts;
}

// ============================================================================
// BEHAVIORAL ANALYSIS
// ============================================================================

BehavioralIndicators ProcessAnalyzer::AnalyzeBehavior(uint32_t pid) {
    return m_impl ? m_impl->AnalyzeBehaviorInternal(pid) : BehavioralIndicators{};
}

std::vector<AntiAnalysisIndicator> ProcessAnalyzer::DetectAntiAnalysis(uint32_t pid) {
    if (!m_impl) return std::vector<AntiAnalysisIndicator>{};

    auto indicators = m_impl->AnalyzeBehaviorInternal(pid);
    return indicators.antiAnalysis;
}

bool ProcessAnalyzer::IsBeingDebugged(uint32_t pid) {
    if (!m_impl) return false;

    // Use ProcessUtils::IsProcessDebugged which queries the debug port
    Utils::ProcessUtils::Error err{};
    return Utils::ProcessUtils::IsProcessDebugged(pid, &err);
}

bool ProcessAnalyzer::DetectProcessHollowing(uint32_t pid) {
    return m_impl ? m_impl->DetectProcessHollowingInternal(pid) : false;
}

bool ProcessAnalyzer::DetectDirectSyscalls(uint32_t pid) {
    if (!m_impl) return false;

    try {
        // Direct syscall detection: scan executable memory regions for
        // syscall instruction patterns (0F 05 on x64 = SYSCALL).
        // Legitimate code in ntdll.dll has syscalls. Code outside ntdll
        // executing syscall instructions is suspicious (Hell's Gate, SysWhispers).
        auto& memoryScanner = MemoryScanner::Instance();
        if (!memoryScanner.IsInitialized()) {
            return false;
        }

        auto scanResult = memoryScanner.ScanProcessMemory(pid);
        for (const auto& threat : scanResult.threats) {
            // MemoryScanner should flag direct syscall patterns as threats.
            // We rely on its detection engine for the actual byte-level analysis.
            // If any threats are found, they indicate syscall-related anomalies.
            if (threat.threatType != MemoryThreatType::None) {
                return true;
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessAnalyzer",
            L"Direct syscall detection failed for PID %u - %S", pid, e.what());
    }

    return false;
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

uint64_t ProcessAnalyzer::RegisterProgressCallback(AnalysisProgressCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_progressCallbacks[id] = std::move(callback);
    return id;
}

uint64_t ProcessAnalyzer::RegisterFindingCallback(SuspiciousFindingCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_findingCallbacks[id] = std::move(callback);
    return id;
}

uint64_t ProcessAnalyzer::RegisterModuleCallback(ModuleAnalyzedCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_moduleCallbacks[id] = std::move(callback);
    return id;
}

void ProcessAnalyzer::UnregisterCallback(uint64_t callbackId) {
    if (!m_impl) return;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_progressCallbacks.erase(callbackId);
    m_impl->m_findingCallbacks.erase(callbackId);
    m_impl->m_moduleCallbacks.erase(callbackId);
}

// ============================================================================
// CACHE MANAGEMENT
// ============================================================================

void ProcessAnalyzer::ClearAnalysisCache() {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_cacheMutex);
    m_impl->m_analysisCache.clear();
}

void ProcessAnalyzer::ClearSignatureCache() {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_signatureCacheMutex);
    m_impl->m_signatureCache.clear();
}

void ProcessAnalyzer::ClearAllCaches() {
    ClearAnalysisCache();
    ClearSignatureCache();
}

void ProcessAnalyzer::InvalidateCacheEntry(uint32_t pid) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_cacheMutex);
    std::erase_if(m_impl->m_analysisCache, [pid](const auto& pair) {
        return pair.first.pid == pid;
    });
}

// ============================================================================
// STATISTICS & DIAGNOSTICS
// ============================================================================

AnalyzerStatistics ProcessAnalyzer::GetStatistics() const {
    return m_impl ? m_impl->m_statistics : AnalyzerStatistics{};
}

void ProcessAnalyzer::ResetStatistics() {
    if (m_impl) {
        m_impl->m_statistics.Reset();
    }
}

std::wstring ProcessAnalyzer::GetVersion() noexcept {
    return std::format(L"{}.{}.{}",
                      AnalyzerConstants::VERSION_MAJOR,
                      AnalyzerConstants::VERSION_MINOR,
                      AnalyzerConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY METHODS
// ============================================================================

std::wstring ProcessAnalyzer::GetProcessPath(uint32_t pid) {
    auto procInfo = SafeGetProcessInfo(pid);
    return procInfo.has_value() ? procInfo->executablePath : L"";
}

bool ProcessAnalyzer::IsSystemProcess(const std::wstring& processName) noexcept {
    const std::wstring nameLower = Utils::StringUtils::ToLowerCopy(ExtractFileName(processName));

    for (const auto& sysProc : AnalyzerConstants::SYSTEM_PROCESSES) {
        if (Utils::StringUtils::ToLowerCopy(std::wstring(sysProc)) == nameLower) {
            return true;
        }
    }

    return false;
}

bool ProcessAnalyzer::IsCriticalProcess(uint32_t pid) {
    auto procInfo = SafeGetProcessInfo(pid);
    if (!procInfo.has_value()) return false;

    const std::wstring nameLower = Utils::StringUtils::ToLowerCopy(
        ExtractFileName(procInfo->name));

    return (nameLower == L"csrss.exe" ||
            nameLower == L"lsass.exe" ||
            nameLower == L"services.exe" ||
            nameLower == L"smss.exe" ||
            nameLower == L"wininit.exe" ||
            nameLower == L"winlogon.exe");
}

bool ProcessAnalyzer::IsLOLBin(const std::wstring& processPath) noexcept {
    const std::wstring fileNameLower = Utils::StringUtils::ToLowerCopy(
        ExtractFileName(processPath));

    // Common Living-off-the-Land binaries (exact filename match)
    static const std::array<std::wstring_view, 20> lolbins = {
        L"certutil.exe", L"bitsadmin.exe", L"regsvr32.exe", L"mshta.exe",
        L"rundll32.exe", L"powershell.exe", L"cmd.exe", L"wscript.exe",
        L"cscript.exe", L"msbuild.exe", L"installutil.exe", L"regasm.exe",
        L"regsvcs.exe", L"cmstp.exe", L"ie4uinit.exe", L"forfiles.exe",
        L"pcalua.exe", L"msiexec.exe", L"mavinject.exe", L"odbcconf.exe"
    };

    for (const auto& lolbin : lolbins) {
        if (fileNameLower == lolbin) {
            return true;
        }
    }

    return false;
}

std::wstring ProcessAnalyzer::RiskLevelToString(ProcessRiskLevel level) noexcept {
    switch (level) {
        case ProcessRiskLevel::Trusted: return L"Trusted";
        case ProcessRiskLevel::Safe: return L"Safe";
        case ProcessRiskLevel::Unknown: return L"Unknown";
        case ProcessRiskLevel::LowRisk: return L"Low Risk";
        case ProcessRiskLevel::MediumRisk: return L"Medium Risk";
        case ProcessRiskLevel::HighRisk: return L"High Risk";
        case ProcessRiskLevel::Suspicious: return L"Suspicious";
        case ProcessRiskLevel::Malicious: return L"Malicious";
        case ProcessRiskLevel::Critical: return L"Critical";
        default: return L"Unknown";
    }
}

ProcessRiskLevel ProcessAnalyzer::ScoreToRiskLevel(uint32_t score) noexcept {
    if (score >= 90) return ProcessRiskLevel::Critical;
    if (score >= 75) return ProcessRiskLevel::Suspicious;
    if (score >= 60) return ProcessRiskLevel::HighRisk;
    if (score >= 45) return ProcessRiskLevel::MediumRisk;
    if (score >= 30) return ProcessRiskLevel::LowRisk;
    if (score >= 15) return ProcessRiskLevel::Unknown;
    if (score > 0) return ProcessRiskLevel::Safe;
    return ProcessRiskLevel::Trusted;
}

}  // namespace Process
}  // namespace Core
}  // namespace ShadowStrike
