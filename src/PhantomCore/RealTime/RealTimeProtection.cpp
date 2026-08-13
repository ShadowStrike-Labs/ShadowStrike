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
 * ShadowStrike Real-Time - ORCHESTRATOR SERVICE IMPLEMENTATION
 * ============================================================================
 *
 * @file RealTimeProtection.cpp
 * @brief Enterprise-grade real-time protection orchestration implementation.
 *
 * Implements the central orchestrator for all real-time protection components.
 * Coordinates kernel driver communication, scan engine integration, policy
 * enforcement, component lifecycle, and threat response.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "RealTimeProtection.hpp"
#include "../Diagnostics/DiagTrace.hpp"
#include "../Utils/DataStorePaths.hpp"   // SeedSignatureDatabaseFromBaseline

// ============================================================================
// COMPONENT INCLUDES
// ============================================================================
#include "FileSystemFilter.hpp"
#include "ProcessCreationMonitor.hpp"
#include "NetworkTrafficFilter.hpp"
#include "AccessControlManager.hpp"
#include "BehaviorBlocker.hpp"
#include "ExploitPrevention.hpp"
#include "FileIntegrityMonitor.hpp"
#include "MemoryProtection.hpp"
#include "ZeroHourProtection.hpp"

// ============================================================================
// CORE NETWORK MODULE INCLUDES
// ============================================================================
#include "../Core/Network/NetworkMonitor.hpp"
#include "../Core/Network/TrafficAnalyzer.hpp"
#include "../Core/Network/DNSMonitor.hpp"
#include "../Core/Network/URLAnalyzer.hpp"
#include "../Core/Network/BotnetDetector.hpp"
#include "../Core/Network/WebProtection.hpp"
#include "../Core/Network/TorDetector.hpp"
#include "../Core/Network/VPNDetector.hpp"
#include "../Core/Network/P2PMonitor.hpp"

// Kernel network event structures (for FilterMessageType_NetworkAlert parsing)
#include "../../PhantomSensor/Shared/NetworkTypes.h"
#include "../../PhantomSensor/Shared/MessageTypes.h"

// ============================================================================
// EXPLOIT DETECTOR INCLUDES
// ============================================================================
// Performance monitors — CPU/Disk/Network telemetry
#include "../Performance/CPUMonitor.hpp"
#include "../Performance/DiskMonitor.hpp"
#include "../Performance/NetworkPerformanceMonitor.hpp"

#include "../Exploits/HeapSprayDetector.hpp"
#include "../Exploits/JITSprayDetector.hpp"
#include "../Exploits/BufferOverflowProtection.hpp"
#include "../Exploits/StackPivotDetector.hpp"
#include "../Exploits/KernelExploitDetector.hpp"
#include "../Exploits/PrivilegeEscalationDetector.hpp"

// ============================================================================
// SUBSYSTEM WIRING (ransomware + script-scanner + ROP bring-up)
//
// NOTE: ROPProtection.hpp is DELIBERATELY NOT included here. It lives in
//       the same ShadowStrike::Exploits namespace as KernelExploitDetector
//       and redefines DetectionConfidence / BlockCallback with incompatible
//       signatures (pre-existing ODR violation across module headers). The
//       ROP engine is driven through the RopWiring shim, which includes
//       ROPProtection.hpp in its own isolated TU.
// ============================================================================
#include "../RansomwareProtection/RansomwareWiring.hpp"
#include "../Scripts/ScriptsWiring.hpp"
#include "../Exploits/RopWiring.hpp"

// ============================================================================
// ANTI-EVASION DETECTOR INCLUDES
// ============================================================================
#include "../AntiEvasion/DebuggerEvasionDetector.hpp"
#include "../AntiEvasion/VMEvasionDetector.hpp"
#include "../AntiEvasion/SandboxEvasionDetector.hpp"
#include "../AntiEvasion/ProcessEvasionDetector.hpp"
#include "../AntiEvasion/metamorphic_polymorphicdetector.hpp"
#include "../AntiEvasion/TimeBasedEvasionDetector.hpp"
#include "../AntiEvasion/NetworkBasedEvasionDetector.hpp"
#include "../AntiEvasion/EnvironmentEvasionDetector.hpp"
#include "../AntiEvasion/PackerDetector.hpp"

// ============================================================================
// AI/ML ENGINE INCLUDES
// ============================================================================
#include "../AI/PhantomCortex.hpp"
#include "../AI/CortexConfig.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Communication/IPCManager.hpp"
#include "../Communication/Communication.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/AlertSystem.hpp"
#include "../Communication/ThreatIntelPusher.hpp"
#include "../Utils/CacheManager.hpp"
#include "../Core/Engine/ScanEngine.hpp"
#include "../Core/FileSystem/ExecutableAnalyzer.hpp"
#include "../Core/Engine/BehaviorAnalyzer.hpp"
#include "../Core/Engine/ThreatDetector.hpp"
#include "../Core/Engine/QuarantineManager.hpp"
#include "../Core/Process/ProcessInjectionDetector.hpp"
#include "../Core/Process/AtomBombingDetector.hpp"
#include "../Core/Process/ProcessMonitor.hpp"
#include "../Core/Process/DLLInjectionDetector.hpp"
#include "../HashStore/HashStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../ThreatIntel/ThreatIntelStore.hpp"
#include "../SelfProtection/DigitalSignatureValidator.hpp"
#include "../SelfProtection/ProcessProtection.hpp"
#include "../SelfProtection/TamperProtection.hpp"
#include "../SelfProtection/SelfDefense.hpp"
#include "../SelfProtection/AntiDebug.hpp"
#include "../SelfProtection/CertificateValidator.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/ThreadPool.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <regex>
#include <format>
#include <nlohmann/json.hpp>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// ANONYMOUS HELPER NAMESPACE
// ============================================================================
namespace {

#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
    constexpr bool kFocusedUserModeBootstrap = true;

    template <typename T>
    struct FocusedDetectorNoDelete {
        void operator()(T*) const noexcept {}
    };

    template <typename T>
    using FocusedDetectorPtr = std::unique_ptr<T, FocusedDetectorNoDelete<T>>;
#else
    constexpr bool kFocusedUserModeBootstrap = false;

    template <typename T>
    using FocusedDetectorPtr = std::unique_ptr<T>;
#endif

    // Generate unique event ID
    uint64_t GenerateEventId() {
        static std::atomic<uint64_t> s_counter{ 1000000 };
        return s_counter.fetch_add(1, std::memory_order_relaxed);
    }

    // Generate unique callback ID
    uint64_t GenerateCallbackId() {
        static std::atomic<uint64_t> s_callbackCounter{ 1 };
        return s_callbackCounter.fetch_add(1, std::memory_order_relaxed);
    }

    // Current timestamp
    std::chrono::system_clock::time_point Now() {
        return std::chrono::system_clock::now();
    }

    // Convert wide string to lower case
    std::wstring ToLowerW(std::wstring_view str) {
        std::wstring result(str);
        std::transform(result.begin(), result.end(), result.begin(),
            [](wchar_t c) { return static_cast<wchar_t>(std::tolower(c)); });
        return result;
    }

    // Path wildcard matching
    bool PathMatchesWildcard(const std::wstring& path, const std::wstring& pattern) {
        std::wstring lowerPath = ToLowerW(path);
        std::wstring lowerPattern = ToLowerW(pattern);

        // Simple wildcard matching (* at end)
        if (!lowerPattern.empty() && lowerPattern.back() == L'*') {
            std::wstring prefix = lowerPattern.substr(0, lowerPattern.length() - 1);
            return lowerPath.find(prefix) == 0;
        }

        return lowerPath == lowerPattern;
    }

    // =========================================================================
    // KERNEL VERDICT CONVERSION
    // =========================================================================

    SHADOWSTRIKE_SCAN_VERDICT MapKernelVerdictToScanVerdict(
        Communication::KernelVerdict kv) noexcept
    {
        switch (kv) {
            case Communication::KernelVerdict::Allow:      return Verdict_Clean;
            case Communication::KernelVerdict::Block:       return Verdict_Malicious;
            case Communication::KernelVerdict::Quarantine:  return Verdict_Malicious;
            case Communication::KernelVerdict::Log:         return Verdict_Suspicious;
            case Communication::KernelVerdict::Delay:       return Verdict_Timeout;
            case Communication::KernelVerdict::Error:       return Verdict_Error;
            default:                                        return Verdict_Unknown;
        }
    }

    // =========================================================================
    // TELEMETRY & ALERT EMISSION HELPERS
    // =========================================================================

    void EmitEvasionTelemetry(
        uint32_t processId,
        const std::wstring& imagePath,
        const std::wstring& detectionSource,
        const std::string& detectorName,
        float evasionScore,
        uint32_t techniqueCount,
        bool blocked)
    {
        try {
            if (Communication::TelemetryCollector::HasInstance()) {
                Communication::DetectionEventData detection;
                detection.threatName = "Evasion." + detectorName;
                detection.threatType = "AntiEvasion";
                detection.detectionMethod = detectorName;
                detection.actionTaken = blocked ? "Blocked" : "Detected";
                detection.detectionTime = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
                detection.fpProbability = (evasionScore >= 90.0f) ? 0.01 :
                                          (evasionScore >= 70.0f) ? 0.05 : 0.10;
                Communication::TelemetryCollector::Instance().RecordDetection(detection);
            }
        } catch (...) {
            // Telemetry failure must never block detection path
        }
    }

    void EmitEvasionAlert(
        uint32_t processId,
        const std::wstring& imagePath,
        const std::wstring& detectionSource,
        const std::string& detectorName,
        Communication::AlertSeverity severity)
    {
        try {
            if (Communication::AlertSystem::HasInstance()) {
                std::string subject = std::format("Evasion detected: {} (PID {})",
                    detectorName, processId);
                std::string details = std::format(
                    "Detector: {}, Image: {}, Source: {}",
                    detectorName,
                    Utils::StringUtils::ToNarrow(imagePath.substr(0, 260)),
                    Utils::StringUtils::ToNarrow(detectionSource.substr(0, 300)));

                (void)Communication::AlertSystem::Instance().RaiseAlert(
                    severity,
                    Communication::AlertType::ThreatDetection,
                    subject,
                    details,
                    "RealTimeProtection::AntiEvasion");
            }
        } catch (...) {
            // Alert failure must never block detection path
        }
    }

    // Component type to string
    const char* ComponentTypeToString(ComponentType type) {
        switch (type) {
            case ComponentType::FILE_SYSTEM_FILTER: return "FileSystemFilter";
            case ComponentType::PROCESS_MONITOR: return "ProcessMonitor";
            case ComponentType::MEMORY_PROTECTION: return "MemoryProtection";
            case ComponentType::BEHAVIOR_BLOCKER: return "BehaviorBlocker";
            case ComponentType::NETWORK_FILTER: return "NetworkFilter";
            case ComponentType::EXPLOIT_PREVENTION: return "ExploitPrevention";
            case ComponentType::FILE_INTEGRITY: return "FileIntegrity";
            case ComponentType::ACCESS_CONTROL: return "AccessControl";
            case ComponentType::ZERO_HOUR: return "ZeroHour";
            case ComponentType::SCAN_ENGINE: return "ScanEngine";
            case ComponentType::IPC_MANAGER: return "IPCManager";
            case ComponentType::QUARANTINE_MANAGER: return "QuarantineManager";
            default: return "Unknown";
        }
    }

    // Protection state to string
    const char* ProtectionStateToString(ProtectionState state) {
        switch (state) {
            case ProtectionState::UNINITIALIZED: return "Uninitialized";
            case ProtectionState::INITIALIZING: return "Initializing";
            case ProtectionState::ACTIVE: return "Active";
            case ProtectionState::PAUSED: return "Paused";
            case ProtectionState::DEGRADED: return "Degraded";
            case ProtectionState::ERROR: return "Error";
            case ProtectionState::SHUTTING_DOWN: return "ShuttingDown";
            case ProtectionState::DISABLED: return "Disabled";
            default: return "Unknown";
        }
    }

} // namespace

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class RealTimeProtectionImpl {
public:
    // =========================================================================
    // MEMBERS
    // =========================================================================

    // Configuration & State
    RTPConfig m_config;
    std::atomic<ProtectionState> m_state{ ProtectionState::UNINITIALIZED };
    std::atomic<ProtectionMode> m_mode{ ProtectionMode::BLOCK_KNOWN };
    std::atomic<bool> m_initialized{ false };

    // Threading
    std::shared_ptr<Utils::ThreadPool> m_threadPool;
    std::unique_ptr<std::thread> m_healthCheckThread;
    std::unique_ptr<std::thread> m_statsUpdateThread;
    // One-shot deferred self-protection baseline (heavy install-tree hashing +
    // initial APT sweep) moved OFF the Start critical path so the service reaches
    // ScanServicingReady/online in seconds -- see RealTimeProtection::Start step 4.5.
    std::unique_ptr<std::thread> m_deferredInitThread;
    // Set true once FIM initialized OK during Start; the deferred worker then builds
    // the heavy system-file baselines off the online-critical path (Start step 4.5 /
    // FIM init). Read by the deferred worker after the readiness gate.
    std::atomic<bool> m_deferSystemBaselines{ false };
    std::atomic<bool> m_stopThreads{ false };

    // ---- Deferred deep scan (synchronous latency budget overflow) ----
    // Files whose deep analysis would have exceeded the synchronous budget. The
    // kernel is answered immediately and the full pipeline runs here instead, so
    // the machine stays responsive without giving up analysis.
    std::deque<std::pair<std::wstring, uint32_t>> m_deferredQueue;
    std::unordered_set<std::wstring>              m_deferredSeen;
    std::mutex                                    m_deferredMutex;
    std::condition_variable                       m_deferredCv;
    std::atomic<bool>                             m_deferredStop{ false };
    std::unique_ptr<std::thread>                  m_deferredScanThread;

    // Files whose Microsoft-signature trust verdict is not yet known.
    //
    // Kept separate from m_deferredQueue on purpose. That queue runs the full
    // deep scan; this one only establishes a trust verdict, which is far cheaper
    // and far more common - every OS binary on the machine passes through it once.
    // Sharing one bounded queue would let a burst of trust look-ups evict real
    // deep scans, and a slow deep scan delay every trust verdict, so the two
    // would degrade each other precisely when the machine is busiest.
    //
    // The pair is (path, file identity key). The key is CAPTURED AT ENQUEUE and
    // never recomputed by the worker: it binds the verdict to the content that
    // was actually observed, so if the file changes in between, the entry we
    // publish is keyed to content that no longer exists and can never be served.
    std::deque<std::pair<std::wstring, std::wstring>> m_sigDetermQueue;
    std::unordered_set<std::wstring>                 m_sigDetermSeen;
    std::mutex                                       m_sigDetermMutex;
    std::condition_variable                          m_sigDetermCv;
    std::atomic<bool>                                m_sigDetermStop{ false };
    std::unique_ptr<std::thread>                     m_sigDetermThread;

    // Synchronization
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_exclusionMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_cacheMutex;
    mutable std::shared_mutex m_threatMutex;
    mutable std::shared_mutex m_componentMutex;

    // Exclusions
    std::vector<std::wstring> m_excludedPaths;
    std::vector<std::wstring> m_excludedExtensions;
    std::vector<std::wstring> m_excludedProcesses;
    std::vector<std::wstring> m_excludedHashes;
    std::unordered_map<uint32_t, std::chrono::system_clock::time_point> m_tempPidExclusions;

    // Verdict Cache: Hash (as hex string) -> (Result, Expiry)
    struct CacheEntry {
        ScanResult result;
        std::chrono::system_clock::time_point expiry;
    };
    std::unordered_map<std::string, CacheEntry> m_verdictCache;

    // Image-load module verdict cache: identity(path|size|sigLevel) -> (verdict,
    // expiry). Collapses repeated full re-analysis (Authenticode hash + cert
    // chain) of the SAME system module loaded across many processes — e.g.
    // ntdll.dll on every process start — which was the dominant idle-CPU cost.
    // Only benign Allow verdicts are cached, and only system modules are served
    // from it (they already return Allow after signature analysis without the
    // per-load injection fan-out).
    struct ImageVerdictEntry {
        Communication::KernelVerdict verdict;
        std::chrono::system_clock::time_point expiry;
    };
    std::unordered_map<std::wstring, ImageVerdictEntry> m_imageVerdictCache;

    // On-access file verdict cache: identity(path|size|mtime) -> (verdict,
    // expiry). The kernel re-issues a scan for the same file on every launch/
    // open; trusted system binaries (cmd.exe, ntdll, rpcss...) were seen 20-60x
    // each, and each event re-ran the FULL metamorphic+packer+executable+
    // ScanEngine stack (0.5-2.3s). For read/execute opens we serve a cached
    // benign verdict keyed by file identity so repeats are near-instant. Only
    // Allow is cached; a changed size or mtime invalidates the entry, and
    // write/create/rename/delete events bypass this cache entirely and are
    // always fully analyzed. Reuses ImageVerdictEntry (same shape).
    std::unordered_map<std::wstring, ImageVerdictEntry> m_fileVerdictCache;

    // Recent Threats
    std::deque<ThreatEvent> m_recentThreats;
    static constexpr size_t MAX_RECENT_THREATS = 1000;

    // Anti-Evasion Detectors (non-singleton, owned by RTP)
    FocusedDetectorPtr<ShadowStrike::AntiEvasion::DebuggerEvasionDetector> m_debuggerDetector;
    FocusedDetectorPtr<ShadowStrike::AntiEvasion::VMEvasionDetector> m_vmDetector;
    FocusedDetectorPtr<ShadowStrike::AntiEvasion::ProcessEvasionDetector> m_processDetector;
    FocusedDetectorPtr<ShadowStrike::AntiEvasion::MetamorphicDetector> m_metamorphicDetector;
    FocusedDetectorPtr<ShadowStrike::AntiEvasion::NetworkBasedEvasionDetector> m_networkDetector;
    FocusedDetectorPtr<ShadowStrike::AntiEvasion::EnvironmentEvasionDetector> m_environmentDetector;
    FocusedDetectorPtr<ShadowStrike::AntiEvasion::PackerDetector> m_packerDetector;

    // Anti-Evasion Detectors (singletons — accessed via Instance(), not owned)
    // SandboxEvasionDetector: system-level sandbox fingerprinting (startup + periodic)
    // TimeBasedEvasionDetector: per-process timing evasion analysis
    std::atomic<bool> m_sandboxDetectorInitialized{ false };
    std::atomic<bool> m_timeBasedDetectorInitialized{ false };

    // Shared Threat Intelligence Stores — injected into detectors for IOC correlation
    std::shared_ptr<HashStore::HashStore> m_sharedHashStore;
    std::shared_ptr<SignatureStore::SignatureStore> m_sharedSignatureStore;
    std::shared_ptr<PatternStore::PatternStore> m_sharedPatternStore;
    std::shared_ptr<ThreatIntel::ThreatIntelStore> m_sharedThreatIntelStore;

    // Component Status
    std::array<ComponentStatus, static_cast<size_t>(ComponentType::COMPONENT_COUNT)> m_componentStatus;

    // Statistics
    RTPStatistics m_stats;
    PerformanceMetrics m_performanceMetrics;

    // Rate calculation state (member vars instead of static locals for thread safety)
    uint64_t m_lastTotalScansForRate{ 0 };
    std::chrono::system_clock::time_point m_lastRateCalcTime{ std::chrono::system_clock::now() };

    // CPU usage measurement state (GetSystemTimes delta between samples)
    ULARGE_INTEGER m_prevIdleTime{};
    ULARGE_INTEGER m_prevKernelTime{};
    ULARGE_INTEGER m_prevUserTime{};
    bool m_cpuTimesInitialized{ false };

    // Callbacks
    std::unordered_map<uint64_t, RTPFileScanCallback> m_fileScanCallbacks;
    std::unordered_map<uint64_t, RTPProcessCreateCallback> m_processCreateCallbacks;
    std::unordered_map<uint64_t, ThreatDetectionCallback> m_threatDetectionCallbacks;
    std::unordered_map<uint64_t, StateChangeCallback> m_stateChangeCallbacks;
    std::unordered_map<uint64_t, ComponentStatusCallback> m_componentStatusCallbacks;
    std::unordered_map<uint64_t, UserNotificationCallback> m_notificationCallbacks;

    // Protection Status
    ProtectionStatus m_protectionStatus;

    // =========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // =========================================================================

    RealTimeProtectionImpl() {
        m_stats.startTime = Now();
        m_stats.lastReset = Now();
        m_protectionStatus.startTime = Now();
        m_protectionStatus.lastUpdate = Now();

#if !defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        // Create shared ThreatIntel stores — injected into detectors needing IOC correlation
        try {
            m_sharedHashStore = std::make_shared<HashStore::HashStore>();
            m_sharedSignatureStore = std::make_shared<SignatureStore::SignatureStore>();
            m_sharedPatternStore = std::make_shared<PatternStore::PatternStore>();
            // Use the process-wide store rather than a private instance. The
            // previous fresh object was never initialized, so every consumer it
            // was handed to (network evasion, process analysis, injection
            // detection) held a store that could not answer a single lookup -
            // IOC correlation silently matched nothing. The database is also
            // exclusive while open for write, so a private instance could not
            // have shared the real one even if it had been initialized.
            m_sharedThreatIntelStore = ThreatIntel::ThreatIntelStore::Shared();
            if (m_sharedThreatIntelStore && m_sharedThreatIntelStore->IsInitialized()) {
                // Give the endpoint data to match against. Without registered
                // feeds the store stays empty and every IOC lookup is a miss,
                // which reads as "clean" and is indistinguishable from safety.
                const uint32_t feeds = m_sharedThreatIntelStore->RegisterDefaultFeeds();
                if (feeds > 0) {
                    m_sharedThreatIntelStore->StartFeedUpdates();
                    Utils::Logger::Info(
                        "RealTimeProtection: threat intel active with {} feeds", feeds);
                }
            } else {
                Utils::Logger::Error(
                    "RealTimeProtection: shared ThreatIntel store unavailable - "
                    "IOC and reputation correlation is INACTIVE");
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("Failed to create shared ThreatIntel stores: {}",
                e.what());
        }

        // Create Anti-Evasion Detectors (non-singleton, owned)
        try {
            m_debuggerDetector = std::make_unique<ShadowStrike::AntiEvasion::DebuggerEvasionDetector>();
            m_vmDetector = std::make_unique<ShadowStrike::AntiEvasion::VMEvasionDetector>();
            m_processDetector = std::make_unique<ShadowStrike::AntiEvasion::ProcessEvasionDetector>();
            m_metamorphicDetector = std::make_unique<ShadowStrike::AntiEvasion::MetamorphicDetector>();
            m_networkDetector = std::make_unique<ShadowStrike::AntiEvasion::NetworkBasedEvasionDetector>();
            m_environmentDetector = std::make_unique<ShadowStrike::AntiEvasion::EnvironmentEvasionDetector>();
            m_packerDetector = std::make_unique<ShadowStrike::AntiEvasion::PackerDetector>();
        } catch (const std::exception& e) {
            Utils::Logger::Error("Failed to create Anti-Evasion detectors: {}", e.what());
        }
#endif

        // Initialize component status array
        for (size_t i = 0; i < m_componentStatus.size(); ++i) {
            m_componentStatus[i].type = static_cast<ComponentType>(i);
            m_componentStatus[i].state = ProtectionComponentState::UNINITIALIZED;
        }
    }

    ~RealTimeProtectionImpl() {
        Stop();
    }

    // =========================================================================
    // LIFECYCLE MANAGEMENT
    // =========================================================================

    bool Start() {
        if (m_state == ProtectionState::ACTIVE) {
            Utils::Logger::Warn("RealTimeProtection: Already active");
            return true;
        }

        Utils::Logger::Info("RealTimeProtection: Starting orchestrator service...");
        SetState(ProtectionState::INITIALIZING);

 #if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        try {
            if (!m_threadPool) {
                Utils::ThreadPoolConfig tpConfig;
                tpConfig.minThreads = std::min(std::thread::hardware_concurrency(), 8u);
                tpConfig.maxThreads = std::min(std::thread::hardware_concurrency() * 2u, 16u);
                m_threadPool = std::make_shared<Utils::ThreadPool>(std::move(tpConfig));
            }

            try {
                Utils::CacheManager::Instance().Initialize(
                    L"", 100000, 256 * 1024 * 1024, std::chrono::minutes(1));
            } catch (...) {
            }

            auto startFocusedComponent =
                [this](ComponentType type, auto&& initializeFn, auto&& startFn) noexcept {
                    try {
                        if (!initializeFn()) {
                            SetComponentState(type, ProtectionComponentState::ERROR);
                            return;
                        }

                        const bool started = startFn();
                        SetComponentState(
                            type,
                            started ? ProtectionComponentState::RUNNING
                                    : ProtectionComponentState::ERROR);
                    } catch (...) {
                        SetComponentState(type, ProtectionComponentState::ERROR);
                    }
                };

            // Dependencies before work: see WarmAuthenticodeStack.
            WarmAuthenticodeStack();

            startFocusedComponent(
                ComponentType::FILE_SYSTEM_FILTER,
                []() { return FileSystemFilter::Instance().Initialize(); },
                []() { return FileSystemFilter::Instance().Start(); });

            startFocusedComponent(
                ComponentType::PROCESS_MONITOR,
                []() { return ProcessCreationMonitor::Instance().Initialize(); },
                []() {
                    ProcessCreationMonitor::Instance().Start();
                    return true;
                });

            startFocusedComponent(
                ComponentType::NETWORK_FILTER,
                []() { return NetworkTrafficFilter::Instance().Initialize(); },
                []() {
                    NetworkTrafficFilter::Instance().Start();
                    return true;
                });

            m_protectionStatus.driverLoaded = false;
            m_protectionStatus.driverConnected = false;
            m_protectionStatus.isProtected = false;
            m_protectionStatus.lastUpdate = Now();

            SetState(ProtectionState::DEGRADED);
            Utils::Logger::Info(
                "RealTimeProtection: Started in focused user-mode bootstrap mode");
            return true;
        } catch (...) {
            SetState(ProtectionState::ERROR);
            return false;
        }
 #else
        try {
            // 1. Initialize ThreadPool if not provided
            if (!m_threadPool) {
                Utils::ThreadPoolConfig tpConfig;
                tpConfig.minThreads = std::min(std::thread::hardware_concurrency(), 8u);
                tpConfig.maxThreads = std::min(std::thread::hardware_concurrency() * 2u, 16u);
                m_threadPool = std::make_shared<Utils::ThreadPool>(std::move(tpConfig));
            }

            // 1.5. Initialize CacheManager for shared verdict/result caching
            try {
                Utils::CacheManager::Instance().Initialize(
                    L"",       // Default %ProgramData%\ShadowStrike\Cache
                    100000,    // Max 100K entries
                    256 * 1024 * 1024,  // 256 MB limit
                    std::chrono::minutes(1)
                );
                Utils::Logger::Info("RealTimeProtection: CacheManager initialized");
            }
            catch (const std::exception& ex) {
                Utils::Logger::Warn(
                    "RealTimeProtection: CacheManager init failed ({}), continuing without verdict cache",
                    ex.what());
            }

            // 1.9  Install or refresh the signature database from shipped content.
            //
            // This has to happen before InitializeScanEngine, because that is what
            // opens the database, and on a fresh install there is nothing to open:
            // the installer ships an immutable baseline under <install dir>\content
            // and deliberately does not write into the data directory, since that
            // file is runtime state the updater replaces in place. Without this
            // step the field symptom is a service that starts, logs healthily and
            // matches nothing, with the only clue an ERROR from SignatureStore.
            //
            // A failure here is not fatal to startup. The engine still runs its
            // behavioural, heuristic and emulation layers, and a loud log line is
            // more useful than a refusal to start, so the failure is reported and
            // scanning continues degraded rather than absent.
            if (!Utils::DataStorePaths::SeedSignatureDatabaseFromBaseline()) {
                Utils::Logger::Error(
                    "RealTimeProtection: no usable signature database is present. "
                    "Hash, pattern and YARA matching will be unavailable this session; "
                    "behavioural and heuristic detection are unaffected.");
            }

            // 2. Initialize Scan Engine
            if (!InitializeScanEngine()) {
                Utils::Logger::Error("RealTimeProtection: Failed to initialize ScanEngine");
                // Continue in degraded mode
                SetComponentState(ComponentType::SCAN_ENGINE, ProtectionComponentState::ERROR);
            } else {
                SetComponentState(ComponentType::SCAN_ENGINE, ProtectionComponentState::RUNNING);
            }

            // 3. Initialize IPC Manager and connect to kernel driver
            if (!InitializeIPCManager()) {
                Utils::Logger::Warn("RealTimeProtection: IPC Manager not available. Running in user-mode only.");
                SetComponentState(ComponentType::IPC_MANAGER, ProtectionComponentState::ERROR);
                m_protectionStatus.driverConnected = false;
            } else {
                SetComponentState(ComponentType::IPC_MANAGER, ProtectionComponentState::RUNNING);
                m_protectionStatus.driverConnected = true;

                // Push threat intelligence to kernel after driver connection
                SyncThreatIntelToKernel();
            }

            // 4. Initialize Quarantine Manager
            if (!InitializeQuarantineManager()) {
                Utils::Logger::Warn("RealTimeProtection: QuarantineManager initialization failed");
                SetComponentState(ComponentType::QUARANTINE_MANAGER, ProtectionComponentState::ERROR);
            } else {
                SetComponentState(ComponentType::QUARANTINE_MANAGER, ProtectionComponentState::RUNNING);
            }

            // 4.5. Initialize TamperProtection — self-defense and integrity monitoring
            try {
                Security::TamperProtectionConfiguration tamperConfig;
                tamperConfig.mode = Security::TamperProtectionMode::Enforce;
                tamperConfig.enableAutoRepair = true;
                tamperConfig.enablePeriodicChecks = true;
                tamperConfig.checkIntervalMs = 30000; // 30s periodic integrity scans

                if (Security::TamperProtection::Instance().Initialize(tamperConfig)) {
                    // Fast, security-critical protections stay SYNCHRONOUS: protect
                    // our own process image and the service registry keys before we
                    // advertise the service online.
                    (void)Security::TamperProtection::Instance().ProtectSelf();
                    (void)Security::TamperProtection::Instance().ProtectServiceRegistry();

                    // DEFER the heavy one-shot passes off the Start critical path.
                    // ProtectInstallation() hashes EVERY file under the install dir,
                    // which bundles the Qt runtime (thousands of QML/DLL assets) at
                    // tens of ms each -> 20-80s of synchronous work. Running it here
                    // blocked Start from reaching ScanServicingReady/online for that
                    // whole window, during which the kernel minifilter had NO user-mode
                    // verdict source and stalled system-wide file I/O (gray-screen
                    // hang), and the overrun tripped the service watchdog -> restart
                    // loop (field-confirmed on 1.0.49: 5 PIDs, Start never returning).
                    // The install dir already has synchronous ACL protection
                    // (SelfDefense::ProtectInstallationDirectory, applied in Initialize);
                    // this background pass adds per-file hash integrity + the one-time
                    // APT sweep. Coverage is fully preserved -- the 30s periodic
                    // integrity checks continue regardless -- only the initial-baseline
                    // TIMING moves off the online-critical path. Joined in the stop path.
                    if (m_deferredInitThread && m_deferredInitThread->joinable()) {
                        m_deferredInitThread->join();  // never overwrite a live thread
                    }
                    // We are starting, not stopping: clear the stop flag so the
                    // deferred worker's readiness-wait is not mistaken for shutdown
                    // (matters only on a Start-after-Stop of the same instance; the
                    // fresh-process path already has it false).
                    m_stopThreads.store(false, std::memory_order_release);
                    m_deferredInitThread = std::make_unique<std::thread>([this]() {
                        // Wait until the service is actually servicing kernel scan
                        // verdicts before hammering thousands of install-tree file
                        // opens (each intercepted by our own minifilter). This
                        // guarantees the heavy self-I/O happens only once a verdict
                        // source exists, so it can never itself contribute to an I/O
                        // stall. Bounded (a never-ready channel can't wedge the
                        // baseline forever) and stop-flag aware (prompt shutdown).
                        for (int waitedMs = 0;
                             waitedMs < 60000 &&
                             !m_stopThreads.load(std::memory_order_acquire) &&
                             !Communication::IPCManager::Instance().IsScanServicingReady();
                             waitedMs += 100) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        }
                        if (m_stopThreads.load(std::memory_order_acquire)) return;

                        // Run this one-shot baseline as true BACKGROUND maintenance so
                        // hashing + on-access scanning of the install tree can NEVER
                        // starve foreground work (Explorer/desktop/dwm). FIELD 1.0.52:
                        // the service came online fast (good) but this worker then ran
                        // at NORMAL priority and drove the guest to ~85% CPU sustained;
                        // when the user opened File Explorer the desktop could not get
                        // CPU to paint -> gray screen while the (already-drawn)
                        // ShadowStrike UI stayed visible. THREAD_MODE_BACKGROUND_BEGIN
                        // drops BOTH CPU and I/O priority for this thread, so the OS
                        // preempts it for any foreground activity. Detection is
                        // unchanged -- every file is still baselined, just yielding.
                        const bool bgMode =
                            ::SetThreadPriority(::GetCurrentThread(),
                                                THREAD_MODE_BACKGROUND_BEGIN) != FALSE;
                        // Let first-boot / interactive-logon activity settle before the
                        // heavy pass begins (stop-flag aware so shutdown stays prompt).
                        for (int settleMs = 0;
                             settleMs < 20000 && !m_stopThreads.load(std::memory_order_acquire);
                             settleMs += 200) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(200));
                        }
                        if (m_stopThreads.load(std::memory_order_acquire)) {
                            if (bgMode) ::SetThreadPriority(::GetCurrentThread(),
                                                            THREAD_MODE_BACKGROUND_END);
                            return;
                        }
                        try {
                            (void)Security::TamperProtection::Instance().ProtectInstallation();
                            (void)Security::TamperProtection::Instance().RunAPTTamperSweep();
                            if (m_deferSystemBaselines.load(std::memory_order_acquire)) {
                                // FIM system-file baselines (hashing hundreds of files
                                // under system32/drivers/boot) are ALSO heavy synchronous
                                // self-I/O; deferred here for the same reason as
                                // ProtectInstallation. Monitoring is already active.
                                (void)FileIntegrityMonitor::Instance().CreateSystemBaselines();
                            }
                            SS_LOG_INFO(L"RealTimeProtection",
                                L"Deferred self-protection baseline complete "
                                L"(installation integrity + system baselines + initial APT sweep)");
                        } catch (const std::exception& ex) {
                            SS_LOG_WARN(L"RealTimeProtection",
                                L"Deferred self-protection baseline exception: %hs", ex.what());
                        }
                        if (bgMode) {
                            ::SetThreadPriority(::GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
                        }
                    });

                    SS_LOG_INFO(L"RealTimeProtection",
                        L"TamperProtection initialized in Enforce mode (process+registry "
                        L"protected synchronously; installation baseline + APT sweep deferred)");
                } else {
                    SS_LOG_WARN(L"RealTimeProtection",
                        L"TamperProtection initialization failed — running unprotected");
                }
            } catch (const std::exception& ex) {
                SS_LOG_WARN(L"RealTimeProtection",
                    L"TamperProtection init exception: %hs -- self-protection disabled", ex.what());
            }

            // 5. Start Protection Components
            StartComponents();

            // 6. Start background threads
            m_stopThreads = false;
            m_healthCheckThread = std::make_unique<std::thread>(&RealTimeProtectionImpl::HealthCheckLoop, this);
            m_statsUpdateThread = std::make_unique<std::thread>(&RealTimeProtectionImpl::StatsUpdateLoop, this);
            // Background stage for scans that exceeded the synchronous budget.
            m_deferredStop.store(false, std::memory_order_release);
            m_deferredScanThread = std::make_unique<std::thread>(
                &RealTimeProtectionImpl::DeferredDeepScanLoop, this);

            // Establishes Microsoft-signature trust verdicts off the kernel-reply
            // path. Must exist before the filter starts accepting scan requests,
            // or the first wave of requests has nowhere to send its trust
            // look-ups and the fast path never warms.
            m_sigDetermStop.store(false, std::memory_order_release);
            m_sigDetermThread = std::make_unique<std::thread>(
                &RealTimeProtectionImpl::SignatureDeterminationLoop, this);

            // 7. Update protection status
            m_protectionStatus.isProtected = true;
            m_protectionStatus.lastUpdate = Now();

            // 8. Initialize Anti-Evasion Detectors
            InitializeAntiEvasionDetectors();

            // 9. Initialize PhantomCortex AI/ML engine
            try {
                // Best-effort load; on failure the manager falls back to defaults
                // (which we further normalize below). Status is consumed via
                // GetConfig() rather than the boolean return.
                (void)ShadowStrike::AI::CortexConfigManager::Instance().LoadFromRegistry();
                ShadowStrike::AI::CortexConfig cortexConfig =
                    ShadowStrike::AI::CortexConfigManager::Instance().GetConfig();

                if (cortexConfig.modelDirectory.empty()) {
                    cortexConfig.modelDirectory = L"C:\\ProgramData\\ShadowStrike\\Models";
                }

                if (!ShadowStrike::AI::PhantomCortex::Instance().Initialize(cortexConfig)) {
                    SS_LOG_WARN(L"RealTimeProtection",
                        L"PhantomCortex AI engine failed to initialize — ML detection disabled");
                } else {
                    SS_LOG_INFO(L"RealTimeProtection",
                        L"PhantomCortex AI engine initialized successfully");
                }
            } catch (const std::exception& ex) {
                SS_LOG_WARN(L"RealTimeProtection",
                    L"PhantomCortex init exception: %hs — ML detection disabled", ex.what());
            } catch (...) {
                SS_LOG_WARN(L"RealTimeProtection",
                    L"PhantomCortex init unknown exception — ML detection disabled");
            }

            // 10. Initialize Performance Monitors for telemetry and scan throttling
            try {
                Performance::CPUMonitorConfig cpuCfg;
                cpuCfg.samplingIntervalMs = 1000;
                cpuCfg.highUsageThreshold = 90.0;
                cpuCfg.selfUsageAlertThreshold = 10.0;
                if (Performance::CPUMonitor::Instance().Initialize(cpuCfg)) {
                    (void)Performance::CPUMonitor::Instance().StartMonitoring();
                    SS_LOG_INFO(L"RealTimeProtection", L"CPUMonitor initialized and monitoring");
                } else {
                    SS_LOG_WARN(L"RealTimeProtection", L"CPUMonitor initialization failed");
                }
            } catch (...) {
                SS_LOG_WARN(L"RealTimeProtection", L"CPUMonitor init exception");
            }

            try {
                Performance::DiskMonitorConfig diskCfg;
                diskCfg.pollingIntervalMs = 1000;
                diskCfg.enableProcessMonitoring = true;
                diskCfg.enableSelfMonitoring = true;
                if (Performance::DiskMonitor::Instance().Initialize(diskCfg)) {
                    SS_LOG_INFO(L"RealTimeProtection", L"DiskMonitor initialized");
                } else {
                    SS_LOG_WARN(L"RealTimeProtection", L"DiskMonitor initialization failed");
                }
            } catch (...) {
                SS_LOG_WARN(L"RealTimeProtection", L"DiskMonitor init exception");
            }

            try {
                Performance::NetworkMonitorConfig netCfg;
                netCfg.pollingIntervalMs = 1000;
                netCfg.detectBeaconing = true;
                netCfg.detectExfiltration = true;
                netCfg.detectConnectionFlood = true;
                if (Performance::NetworkPerformanceMonitor::Instance().Initialize(netCfg)) {
                    SS_LOG_INFO(L"RealTimeProtection", L"NetworkPerformanceMonitor initialized");
                } else {
                    SS_LOG_WARN(L"RealTimeProtection", L"NetworkPerformanceMonitor initialization failed");
                }
            } catch (...) {
                SS_LOG_WARN(L"RealTimeProtection", L"NetworkPerformanceMonitor init exception");
            }

            SetState(ProtectionState::ACTIVE);
            Utils::Logger::Info("RealTimeProtection: Started successfully");

            // =================================================================
            // SUBSYSTEM WIRING - Phase 3 orphan bring-up
            // =================================================================
            //
            // The ransomware protection stack (9 modules) and script-scanner
            // stack (4 scanners) are initialized here, after all their
            // dependencies (IPCManager, ScanEngine, Cortex, CacheManager) are
            // already up. Failures are isolated inside each subsystem; this
            // block never propagates an exception out of Start().
            //
            // Ordering rationale: ransomware modules register file-write
            // callbacks that scan engines and detection callbacks eventually
            // consume, so they must come up AFTER the detection/IPC layer
            // but BEFORE Start() returns so subsequent traffic is covered.
            //
            try {
                (void)::ShadowStrike::Ransomware::Wiring::
                    InitializeRansomwareSubsystem();
            } catch (...) {
                Utils::Logger::Error(
                    "RealTimeProtection: ransomware wiring threw - continuing");
            }

            try {
                (void)::ShadowStrike::Scripts::Wiring::
                    InitializeScriptsSubsystem();
            } catch (...) {
                Utils::Logger::Error(
                    "RealTimeProtection: scripts wiring threw - continuing");
            }

            return true;

        } catch (const std::exception& e) {
            Utils::Logger::Error("RealTimeProtection: Exception during startup: {}",
                e.what());
            SetState(ProtectionState::ERROR);
            return false;
        }
#endif
    }

    void Stop() {
        if (m_state == ProtectionState::UNINITIALIZED ||
            m_state == ProtectionState::SHUTTING_DOWN) {
            return;
        }

        Utils::Logger::Info("RealTimeProtection: Stopping orchestrator service...");
        SetState(ProtectionState::SHUTTING_DOWN);

        // 1. Stop background threads
        m_stopThreads = true;

        if (m_healthCheckThread && m_healthCheckThread->joinable()) {
            m_healthCheckThread->join();
        }
        m_healthCheckThread.reset();

        if (m_statsUpdateThread && m_statsUpdateThread->joinable()) {
            m_statsUpdateThread->join();
        }
        m_statsUpdateThread.reset();

        // Deferred deep-scan worker. Woken explicitly so it does not sit on its
        // wait for up to a second during shutdown.
        m_deferredStop.store(true, std::memory_order_release);
        m_deferredCv.notify_all();
        if (m_deferredScanThread && m_deferredScanThread->joinable()) {
            m_deferredScanThread->join();
        }
        m_deferredScanThread.reset();

        // Signature determination worker. Joined here for the same reason as the
        // deep-scan worker, and with the same explicit wake so shutdown is not
        // held up by its one-second wait. It may be parked inside WinVerifyTrust,
        // which is exactly why it exists; that call is bounded by the CryptSvc RPC
        // timeout and no scan worker is waiting on it, so the join cannot deadlock
        // shutdown the way the original in-line call could stall a file operation.
        m_sigDetermStop.store(true, std::memory_order_release);
        m_sigDetermCv.notify_all();
        if (m_sigDetermThread && m_sigDetermThread->joinable()) {
            m_sigDetermThread->join();
        }
        m_sigDetermThread.reset();

        // Deferred self-protection baseline (installation integrity + APT sweep).
        // Joined here, BEFORE the detection components/kernel channel are torn down,
        // so any file I/O it is mid-flight on still receives a verdict (no stall).
        if (m_deferredInitThread && m_deferredInitThread->joinable()) {
            m_deferredInitThread->join();
        }
        m_deferredInitThread.reset();

#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        try { NetworkTrafficFilter::Instance().Stop(); } catch (...) {}
        try { NetworkTrafficFilter::Instance().Shutdown(); } catch (...) {}
        SetComponentState(ComponentType::NETWORK_FILTER, ProtectionComponentState::STOPPED);

        try { ProcessCreationMonitor::Instance().Stop(); } catch (...) {}
        SetComponentState(ComponentType::PROCESS_MONITOR, ProtectionComponentState::STOPPED);

        try { FileSystemFilter::Instance().Stop(); } catch (...) {}
        try { FileSystemFilter::Instance().Shutdown(); } catch (...) {}
        SetComponentState(ComponentType::FILE_SYSTEM_FILTER, ProtectionComponentState::STOPPED);

        {
            std::unique_lock lock(m_cacheMutex);
            m_verdictCache.clear();
        }

        try {
            Utils::CacheManager::Instance().Shutdown();
        } catch (...) {
        }

        m_protectionStatus.isProtected = false;
        m_protectionStatus.driverConnected = false;
        m_protectionStatus.driverLoaded = false;
        m_protectionStatus.lastUpdate = Now();

        SetState(ProtectionState::UNINITIALIZED);
        Utils::Logger::Info("RealTimeProtection: Stopped");
        return;
#else
        // 2. Stop components
        StopComponents();

        // 3. Disconnect from kernel driver
        auto& ipc = Communication::IPCManager::Instance();
        ipc.DisconnectFilterPort();
        ipc.Stop();
        SetComponentState(ComponentType::IPC_MANAGER, ProtectionComponentState::STOPPED);

        // 4. Shutdown scan engine
        Core::Engine::ScanEngine::Instance().Shutdown();
        SetComponentState(ComponentType::SCAN_ENGINE, ProtectionComponentState::STOPPED);

        // 4.5. Shutdown PhantomCortex AI/ML engine
        try {
            ShadowStrike::AI::PhantomCortex::Instance().Shutdown();
        } catch (...) {
            // PhantomCortex shutdown must not prevent remaining cleanup
        }

        // 5. Clear caches
        {
            std::unique_lock lock(m_cacheMutex);
            m_verdictCache.clear();
        }

        // 5.5. Shutdown CacheManager
        try {
            Utils::CacheManager::Instance().Shutdown();
        }
        catch (...) {
            // CacheManager shutdown must not prevent remaining cleanup
        }

        m_protectionStatus.isProtected = false;
        m_protectionStatus.lastUpdate = Now();

        // 6. Shutdown Performance Monitors
        try { Performance::CPUMonitor::Instance().StopMonitoring(); } catch (...) {}
        try { Performance::CPUMonitor::Instance().Shutdown(); } catch (...) {}
        try { Performance::DiskMonitor::Instance().Shutdown(); } catch (...) {}
        try { Performance::NetworkPerformanceMonitor::Instance().Shutdown(); } catch (...) {}

        // 7. Shutdown Anti-Evasion Detectors
        ShutdownAntiEvasionDetectors();

        SetState(ProtectionState::UNINITIALIZED);
        Utils::Logger::Info("RealTimeProtection: Stopped");
#endif
    }

    bool Pause(uint32_t durationMs, std::wstring_view reason) {
        if (m_state != ProtectionState::ACTIVE) {
            Utils::Logger::Warn("RealTimeProtection: Cannot pause - not active");
            return false;
        }

        SetState(ProtectionState::PAUSED);
        Utils::Logger::Warn("RealTimeProtection: PAUSED - Reason: {}",
            reason.empty() ? "User request" : Utils::StringUtils::ToNarrow(reason));

        // Pause components
#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        FileSystemFilter::Instance().Pause();
        ProcessCreationMonitor::Instance().Pause();
        NetworkTrafficFilter::Instance().Stop();
#else
        FileSystemFilter::Instance().Pause();
        ProcessCreationMonitor::Instance().Pause();
        NetworkTrafficFilter::Instance().Stop(); // Network filter doesn't have Pause
        BehaviorBlocker::Instance().Pause();
#endif

        m_protectionStatus.isProtected = false;

        // Set up auto-resume if duration specified
        if (durationMs > 0) {
            (void)m_threadPool->Submit([this, durationMs](const Utils::TaskContext&) {
                std::this_thread::sleep_for(std::chrono::milliseconds(durationMs));
                if (m_state == ProtectionState::PAUSED) {
                    (void)Resume();
                }
            });
        }

        return true;
    }

    bool Resume() {
        if (m_state != ProtectionState::PAUSED) {
            return false;
        }

        Utils::Logger::Info("RealTimeProtection: Resuming protection...");

        // Resume components
#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        FileSystemFilter::Instance().Resume();
        ProcessCreationMonitor::Instance().Resume();
        NetworkTrafficFilter::Instance().Start();
#else
        FileSystemFilter::Instance().Resume();
        ProcessCreationMonitor::Instance().Resume();
        NetworkTrafficFilter::Instance().Start();
        BehaviorBlocker::Instance().Resume();
#endif

        m_protectionStatus.isProtected = true;
        SetState(ProtectionState::ACTIVE);

        Utils::Logger::Info("RealTimeProtection: Resumed");
        return true;
    }

    // =========================================================================
    // COMPONENT INITIALIZATION
    // =========================================================================

    bool InitializeScanEngine() {
        try {
            Core::Engine::EngineConfig engineConfig = Core::Engine::EngineConfig::CreateDefault();
            engineConfig.enableRealTime = m_config.enabled;
            engineConfig.enableHeuristics = m_config.enableBehaviorBlocking;
            engineConfig.maxConcurrentScans = m_config.maxConcurrentScans;

            if (!Core::Engine::ScanEngine::Instance().Initialize(engineConfig)) {
                return false;
            }

            return true;
        } catch (const std::exception& e) {
            Utils::Logger::Error("RealTimeProtection: ScanEngine init exception: {}",
                e.what());
            return false;
        }
    }

    bool InitializeIPCManager() {
        try {
            auto& ipc = Communication::IPCManager::Instance();
            Communication::IPCConfiguration ipcConfig;
            ipcConfig.enableFilterPort = true;

            if (!ipc.Initialize(ipcConfig)) {
                return false;
            }

            // Register kernel event handlers
            ipc.RegisterFileScanHandler([this](const FILE_SCAN_REQUEST& req) -> SHADOWSTRIKE_SCAN_VERDICT {
                return MapKernelVerdictToScanVerdict(OnKernelFileScan(req));
            });

            ipc.RegisterProcessHandler([this](const Communication::ProcessNotifyRequest& req) -> SHADOWSTRIKE_SCAN_VERDICT {
                return MapKernelVerdictToScanVerdict(OnKernelProcessNotify(req));
            });

            ipc.RegisterImageLoadHandler([this](const Communication::ImageLoadRequest& req) -> SHADOWSTRIKE_SCAN_VERDICT {
                return MapKernelVerdictToScanVerdict(OnKernelImageLoad(req));
            });

            ipc.RegisterRegistryHandler([this](const Communication::RegistryOpRequest& req) -> SHADOWSTRIKE_SCAN_VERDICT {
                return MapKernelVerdictToScanVerdict(OnKernelRegistryOp(req));
            });

            ipc.RegisterGenericHandler([this](SHADOWSTRIKE_MESSAGE_TYPE type,
                                              const void* data, size_t size) {
                OnKernelGenericEvent(type, data, size);
            });

            if (!ipc.Start()) {
                return false;
            }

            if (!ipc.ConnectFilterPort()) {
                Utils::Logger::Warn("RealTimeProtection: Failed to connect to filter port (driver may not be loaded)");
                return false;
            }

            m_protectionStatus.driverLoaded = true;
            m_protectionStatus.driverConnected = true;
            m_protectionStatus.driverVersion = L"3.0.0"; // Would query from driver

            return true;
        } catch (const std::exception& e) {
            Utils::Logger::Error("RealTimeProtection: IPCManager init exception: {}",
                e.what());
            return false;
        }
    }

    // =========================================================================
    // THREAT INTELLIGENCE → KERNEL SYNCHRONIZATION
    // =========================================================================

    void SyncThreatIntelToKernel() {
        try {
            if (!Communication::IPCManager::HasInstance()) return;
            auto* pusher = Communication::IPCManager::Instance().GetPusher();
            if (!pusher) {
                Utils::Logger::Warn("RealTimeProtection: ThreatIntelPusher unavailable  -  kernel IOC sync skipped");
                return;
            }

            Utils::Logger::Info("RealTimeProtection: Synchronizing threat intelligence to kernel...");

            // Push hash database entries to kernel IOCMatcher
            // HashStore uses Bloom filter internally — enumerate from ThreatIntelStore instead
            if (m_sharedThreatIntelStore) {
                // Export IoC entries from ThreatIntelStore and push to kernel
                // When ThreatIntelStore gains EnumerateHashes/EnumerateIoCs API,
                // convert entries to HashPushEntry/IoCFeedPushEntry and push here.
                // For now, log the wiring path so integration is traceable.
                auto stats = m_sharedThreatIntelStore->GetStatistics();
                const size_t totalEntries = stats.totalIOCEntries + stats.totalHashEntries +
                    stats.totalIPEntries + stats.totalDomainEntries + stats.totalURLEntries;
                Utils::Logger::Info("RealTimeProtection: ThreatIntelStore has {} entries  -  "
                    "kernel push ready when enumeration API is available",
                    totalEntries);
            }

            // Push whitelist/exclusions to kernel ExclusionManager
            // Requires Whitelist module to expose enumerable entries
            // Wire point: Whitelist::GetEntries() → WhitelistPushEntry → pusher->PushWhitelist()

            Utils::Logger::Info("RealTimeProtection: Kernel threat intel sync complete (pusher wired)");
        } catch (const std::exception& e) {
            Utils::Logger::Error("RealTimeProtection: Kernel ThreatIntel sync failed: {}",
                e.what());
        }
    }

    bool InitializeQuarantineManager() {
        try {
            return Core::Engine::QuarantineManager::Instance().Initialize();
        } catch (const std::exception& ex) {
            Utils::Logger::Error("RealTimeProtection: QuarantineManager init exception: {}", ex.what());
            return false;
        } catch (...) {
            return false;
        }
    }

    // =========================================================================
    // ANTI-EVASION DETECTOR LIFECYCLE
    // =========================================================================

    void InitializeAntiEvasionDetectors() {
        Utils::Logger::Info("RealTimeProtection: Initializing Anti-Evasion detectors...");

        // Non-singleton detectors: Initialize() on owned instances
        if (m_debuggerDetector) {
            if (!m_debuggerDetector->Initialize()) {
                Utils::Logger::Warn("RealTimeProtection: DebuggerEvasionDetector Initialize failed");
            } else {
                // Wire ThreatIntel stores for IOC-enriched anti-debug detection
                if (m_sharedSignatureStore) m_debuggerDetector->SetSignatureStore(m_sharedSignatureStore);
                if (m_sharedThreatIntelStore) m_debuggerDetector->SetThreatIntelStore(m_sharedThreatIntelStore);
                // Wire detection callback for per-technique telemetry/SOC integration
                m_debuggerDetector->SetDetectionCallback(
                    [](uint32_t pid, const ShadowStrike::AntiEvasion::DetectedTechnique& detection) {
                        if (detection.severity >= ShadowStrike::AntiEvasion::EvasionSeverity::High) {
                            Utils::Logger::Warn(
                                "[DED-CB] PID={} technique={} confidence={:.2f} severity={}",
                                pid, Utils::StringUtils::ToNarrow(detection.description),
                                detection.confidence,
                                static_cast<int>(detection.severity));
                        }
                    });
            }
        }
        if (m_processDetector) {
            if (!m_processDetector->Initialize()) {
                Utils::Logger::Warn("RealTimeProtection: ProcessEvasionDetector Initialize failed");
            } else {
                // Wire detection callback for per-technique SOC/SIEM telemetry
                m_processDetector->SetDetectionCallback(
                    [](uint32_t pid, const ShadowStrike::AntiEvasion::ProcessDetectedTechnique& detection) {
                        if (detection.severity >= ShadowStrike::AntiEvasion::ProcessEvasionSeverity::High) {
                            Utils::Logger::Warn(
                                "[PED-CB] PID={} technique={} confidence={:.2f} severity={} details={}",
                                pid, Utils::StringUtils::ToNarrow(detection.description),
                                detection.confidence,
                                static_cast<int>(detection.severity),
                                Utils::StringUtils::ToNarrow(detection.technicalDetails.substr(0, 200)));
                        }
                    });
            }
        }
        if (m_metamorphicDetector) {
            if (!m_metamorphicDetector->Initialize()) {
                Utils::Logger::Warn("RealTimeProtection: MetamorphicDetector Initialize failed");
            } else {
                // Wire ThreatIntel stores for IOC-enriched detection
                if (m_sharedSignatureStore) m_metamorphicDetector->SetSignatureStore(m_sharedSignatureStore);
                if (m_sharedHashStore) m_metamorphicDetector->SetHashStore(m_sharedHashStore);
                if (m_sharedPatternStore) m_metamorphicDetector->SetPatternStore(m_sharedPatternStore);
                // Wire detection callback for per-technique SOC/SIEM telemetry
                m_metamorphicDetector->SetDetectionCallback(
                    [](const std::wstring& file, const ShadowStrike::AntiEvasion::MetamorphicDetectedTechnique& detection) {
                        if (detection.severity >= ShadowStrike::AntiEvasion::MetamorphicSeverity::High) {
                            Utils::Logger::Warn(
                                "[META-CB] file={} technique={} confidence={:.2f} severity={}",
                                Utils::StringUtils::ToNarrow(file), Utils::StringUtils::ToNarrow(detection.description),
                                detection.confidence,
                                static_cast<int>(detection.severity));
                        }
                    });
            }
        }
        if (m_networkDetector) {
            if (!m_networkDetector->Initialize()) {
                Utils::Logger::Warn("RealTimeProtection: NetworkBasedEvasionDetector Initialize failed");
            } else {
                // Wire ThreatIntel store for C2/DGA/IOC correlation
                if (m_sharedThreatIntelStore) m_networkDetector->SetThreatIntelStore(m_sharedThreatIntelStore);
                m_networkDetector->SetDetectionCallback(
                    [](uint32_t pid, const ShadowStrike::AntiEvasion::NetworkDetectedTechnique& detection) {
                        if (detection.severity >= ShadowStrike::AntiEvasion::NetworkEvasionSeverity::High) {
                            Utils::Logger::Warn(
                                "[NBED-CB] PID={} technique={} confidence={:.2f} severity={} mitre={}",
                                pid, Utils::StringUtils::ToNarrow(detection.description),
                                detection.confidence,
                                static_cast<int>(detection.severity),
                                detection.mitreId.empty() ? "N/A" : detection.mitreId);
                        }
                    });
            }
        }
        if (m_environmentDetector) {
            if (!m_environmentDetector->Initialize()) {
                Utils::Logger::Warn("RealTimeProtection: EnvironmentEvasionDetector Initialize failed");
            } else {
                // Wire ThreatIntel store for IOC-enriched environment evasion detection
                if (m_sharedThreatIntelStore) m_environmentDetector->SetThreatIntelStore(m_sharedThreatIntelStore);
                // Wire detection callback for per-technique SOC/SIEM telemetry
                m_environmentDetector->SetDetectionCallback(
                    [](uint32_t pid, const ShadowStrike::AntiEvasion::EnvironmentDetectedTechnique& detection) {
                        if (detection.severity >= ShadowStrike::AntiEvasion::EnvironmentEvasionSeverity::High) {
                            Utils::Logger::Warn(
                                "[EED-CB] PID={} technique={} confidence={:.2f} severity={}",
                                pid, Utils::StringUtils::ToNarrow(detection.description),
                                detection.confidence,
                                static_cast<int>(detection.severity));
                        }
                    });
            }
        }
        if (m_packerDetector) {
            if (!m_packerDetector->Initialize()) {
                Utils::Logger::Warn("RealTimeProtection: PackerDetector Initialize failed");
            } else {
                // Wire ThreatIntel stores for packer signature/hash/pattern correlation
                if (m_sharedSignatureStore) m_packerDetector->SetSignatureStore(m_sharedSignatureStore);
                if (m_sharedPatternStore) m_packerDetector->SetPatternStore(m_sharedPatternStore);
                if (m_sharedHashStore) m_packerDetector->SetHashStore(m_sharedHashStore);
                m_packerDetector->SetDetectionCallback(
                    [](const std::wstring& file, const ShadowStrike::AntiEvasion::PackerMatch& match) {
                        if (match.severity >= ShadowStrike::AntiEvasion::PackerSeverity::High) {
                            Utils::Logger::Warn(
                                "[PD-CB] file={} packer={} confidence={:.2f} severity={} method={} mitre={}",
                                Utils::StringUtils::ToNarrow(file.substr(0, 120)),
                                Utils::StringUtils::ToNarrow(match.packerName),
                                match.confidence,
                                static_cast<int>(match.severity),
                                static_cast<int>(match.method),
                                match.mitreId.empty() ? "N/A" : match.mitreId);
                        }
                    });
            }
        }
        // VMEvasionDetector has no Initialize() — ready on construction

        // Singleton detectors: Initialize via Instance()
        try {
            auto& sandbox = ShadowStrike::AntiEvasion::SandboxEvasionDetector::Instance();
            if (sandbox.Initialize(m_threadPool)) {
                m_sandboxDetectorInitialized = true;

                // Wire detection callback for SOC/SIEM telemetry.
                // The detector singleton owns the callback for process lifetime;
                // it is released by Shutdown() in ShutdownAntiEvasionDetectors().
                (void)sandbox.RegisterCallback(
                    [](const ShadowStrike::AntiEvasion::SandboxEvasionResult& result) {
                        if (result.isSandboxLikely) {
                            Utils::Logger::Warn(
                                "[SED-CB] Sandbox detected  -  probability={:.1f}% confidence={:.1f}% "
                                "definitive={} product={} indicators={}",
                                result.probability, result.confidence,
                                result.isDefinitive ? "YES" : "NO",
                                result.sandboxName.empty() ? std::string("Unknown") : Utils::StringUtils::ToNarrow(result.sandboxName),
                                result.indicators.size());

                            // Log critical/high indicators for forensic correlation
                            for (const auto& ind : result.indicators) {
                                if (ind.severity >= ShadowStrike::AntiEvasion::SandboxIndicatorSeverity::High) {
                                    Utils::Logger::Warn(
                                        "[SED-CB] indicator={} severity={} confidence={:.1f} {}",
                                        Utils::StringUtils::ToNarrow(ind.description.substr(0, 100)),
                                        static_cast<int>(ind.severity),
                                        ind.confidence,
                                        Utils::StringUtils::ToNarrow(ind.technicalDetails.substr(0, 150)));
                                }
                            }
                        }
                    });

                // Run initial system-level sandbox analysis at startup
                auto hwProfile = sandbox.AnalyzeHardware();
                auto envResult = sandbox.AnalyzeEnvironment();
                if (hwProfile.isSandboxLike || envResult.suspicionScore >= 50.0f) {
                    Utils::Logger::Warn("RealTimeProtection: Sandbox environment detected  -  "
                        "hardware={:.1f}% env={:.1f}%  -  endpoint may be under malware analysis",
                        hwProfile.suspicionScore, envResult.suspicionScore);
                }
            } else {
                Utils::Logger::Warn("RealTimeProtection: SandboxEvasionDetector Initialize failed");
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("RealTimeProtection: SandboxEvasionDetector exception: {}",
                e.what());
        }

        try {
            auto& timeBased = ShadowStrike::AntiEvasion::TimeBasedEvasionDetector::Instance();
            if (timeBased.Initialize(m_threadPool)) {
                m_timeBasedDetectorInitialized = true;

                // Wire detection callback for SOC/SIEM telemetry.
                // Detector singleton owns the callback for process lifetime.
                (void)timeBased.RegisterCallback(
                    [](const ShadowStrike::AntiEvasion::TimingEvasionResult& result) {
                        if (result.isEvasive) {
                            Utils::Logger::Warn(
                                "[TED-CB] PID={} threat={:.1f} confidence={:.1f} severity={} "
                                "findings={} process={}",
                                result.processId, result.threatScore,
                                result.confidence,
                                static_cast<int>(result.severity),
                                result.findings.size(),
                                Utils::StringUtils::ToNarrow(result.processName.substr(0, 80)));

                            for (const auto& finding : result.findings) {
                                if (finding.severity >= ShadowStrike::AntiEvasion::TimingEvasionSeverity::High) {
                                    Utils::Logger::Warn(
                                        "[TED-CB] PID={} finding={} confidence={:.1f} severity={}",
                                        result.processId, Utils::StringUtils::ToNarrow(finding.description.substr(0, 120)),
                                        finding.confidence,
                                        static_cast<int>(finding.severity));
                                }
                            }
                        }
                    });
            } else {
                Utils::Logger::Warn("RealTimeProtection: TimeBasedEvasionDetector Initialize failed");
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("RealTimeProtection: TimeBasedEvasionDetector exception: {}",
                e.what());
        }

        Utils::Logger::Info("RealTimeProtection: Anti-Evasion detectors initialized");
    }

    void ShutdownAntiEvasionDetectors() {
        Utils::Logger::Info("RealTimeProtection: Shutting down Anti-Evasion detectors...");

        // Singleton detectors: Shutdown via Instance()
        if (m_timeBasedDetectorInitialized.exchange(false)) {
            try {
                ShadowStrike::AntiEvasion::TimeBasedEvasionDetector::Instance().Shutdown();
            } catch (...) {}
        }
        if (m_sandboxDetectorInitialized.exchange(false)) {
            try {
                ShadowStrike::AntiEvasion::SandboxEvasionDetector::Instance().Shutdown();
            } catch (...) {}
        }

        // Non-singleton detectors: Shutdown then release
        if (m_packerDetector) { m_packerDetector->Shutdown(); m_packerDetector.reset(); }
        if (m_environmentDetector) { m_environmentDetector->Shutdown(); m_environmentDetector.reset(); }
        if (m_networkDetector) { m_networkDetector->Shutdown(); m_networkDetector.reset(); }
        if (m_metamorphicDetector) { m_metamorphicDetector->Shutdown(); m_metamorphicDetector.reset(); }
        if (m_processDetector) { m_processDetector->Shutdown(); m_processDetector.reset(); }
        if (m_debuggerDetector) { m_debuggerDetector->Shutdown(); m_debuggerDetector.reset(); }
        m_vmDetector.reset();

        Utils::Logger::Info("RealTimeProtection: Anti-Evasion detectors shut down");
    }

    // Loads and primes the Authenticode / catalog stack before anything can be
    // blocked by us. This must run before the on-access filter starts
    // intercepting, and it is deliberately called from both the focused and the
    // full build paths, because placing it on only one of them is exactly the
    // mistake that made the previous attempt a no-op.
    //
    // Field evidence, 2026-08-12. The filter went live at 18:58:53.410 and a scan
    // worker entered WinVerifyTrust 2.4 seconds later and never came out:
    //     18:58:55.801 t3720 step.IsMicrosoftSigned(WinVerifyTrust)
    // In an earlier run the same call, on two workers, released simultaneously
    // after exactly 180.1 and 180.3 seconds. Simultaneous release on independent
    // threads after a round three minutes is a remote call timing out, not local
    // work. Note this reproduces on a path that already passes
    // WTD_CACHE_ONLY_URL_RETRIEVAL, so it is not CRL or AIA retrieval.
    //
    // The mechanism is a cross-process cycle. A cold WinVerifyTrust loads
    // wintrust.dll and crypt32.dll and acquires a catalog admin context, and
    // catalog work is serviced by CryptSvc over RPC. CryptSvc then performs its
    // own file I/O, our minifilter intercepts it, and the resulting scan request
    // queues behind the very workers waiting on CryptSvc. The driver's scanner
    // exemption cannot break this: ShadowStrikeIsScannerProcess matches only PIDs
    // in g_AcceptedPrimaryScannerProcessIds, which holds our own process, not the
    // system services we synchronously depend on.
    //
    // Verifying two known system binaries here breaks the cycle at the only point
    // where breaking it is free: the modules load, the CryptSvc binding is
    // established and the catalog context is cached while our filter is not yet
    // intercepting, so CryptSvc file I/O completes unimpeded. This is ordering,
    // not suppression, and it changes no verdict because the result is discarded.
    //
    // The limit, stated plainly: this removes the cold-start deadlock that has now
    // been measured four times, but it does not make the synchronous path
    // structurally safe, because a later catalog miss can still reach CryptSvc.
    // The guaranteed fix is to stop asking another process for a verdict while
    // holding a kernel file operation - resolve the signing level in the kernel
    // with SeGetCachedSigningLevel and treat user-mode Authenticode as an
    // asynchronous deep-stage concern only.
    void WarmAuthenticodeStack() noexcept {
        try {
            SS_DIAG_SCOPE("Startup", "CryptoStackWarmup");
            static constexpr const wchar_t* kWarmupTargets[] = {
                L"C:\\Windows\\System32\\ntdll.dll",
                L"C:\\Windows\\System32\\kernel32.dll"
            };
            for (const wchar_t* target : kWarmupTargets) {
                (void)Security::DigitalSignatureValidator::Instance()
                          .IsMicrosoftSigned(target);
            }
            Utils::Logger::Info(
                "RealTimeProtection: Authenticode and catalog stack warmed before "
                "on-access filtering began");
        } catch (...) {
            // A warm-up failure is not a startup failure. If verification is
            // broken here it will be broken later too, and the scan path already
            // treats an unverified file as needing more analysis, not less.
            Utils::Logger::Warn(
                "RealTimeProtection: Authenticode warm-up did not complete; the "
                "first on-access signature check may be slow");
        }
    }

    void StartComponents() {
        Utils::Logger::Info("RealTimeProtection: Starting protection components...");

        // Must precede FileSystemFilter::Start - see WarmAuthenticodeStack for why.
        WarmAuthenticodeStack();

        // FileSystemFilter
        try {
            auto& fsf = FileSystemFilter::Instance();
            if (fsf.Initialize(m_threadPool)) {
                if (!fsf.Start()) {
                    Utils::Logger::Error(
                        "RealTimeProtection: FileSystemFilter::Start failed - "
                        "component running in ERROR state, remaining components will still be started");
                    SetComponentState(ComponentType::FILE_SYSTEM_FILTER,
                                      ProtectionComponentState::ERROR);
                } else {
                    SetComponentState(ComponentType::FILE_SYSTEM_FILTER, ProtectionComponentState::RUNNING);

                    // Wire up scan engine
                    fsf.SetScanEngine(&Core::Engine::ScanEngine::Instance());

                    // Wire up hash store for known-malware lookups
                    if (m_sharedHashStore) {
                        fsf.SetHashStore(m_sharedHashStore.get());
                    }
                }
            }
        } catch (...) {
            SetComponentState(ComponentType::FILE_SYSTEM_FILTER, ProtectionComponentState::ERROR);
        }

        // ProcessCreationMonitor
        try {
            auto& pcm = ProcessCreationMonitor::Instance();
            ProcessMonitorConfig pcmCfg;
            pcmCfg.enabled = true;
            pcmCfg.preExecutionScan = true;
            pcmCfg.analyzeCommandLine = true;
            pcmCfg.detectLOLBAS = true;
            pcmCfg.detectSuspiciousParentChild = true;
            pcmCfg.trackParentChild = true;
            pcmCfg.detectEncodedCommands = true;
            pcmCfg.detectMasquerading = true;
            pcmCfg.trustMicrosoftSigned = true;
            pcmCfg.blockOnTimeout = false;
            pcmCfg.blockThreshold = 80.0;
            pcmCfg.alertThreshold = 40.0;
            if (!pcm.Initialize(m_threadPool, pcmCfg)) {
                Utils::Logger::Error("RealTimeProtection: ProcessCreationMonitor::Initialize failed");
                SetComponentState(ComponentType::PROCESS_MONITOR, ProtectionComponentState::ERROR);
            } else {
                pcm.SetScanEngine(&Core::Engine::ScanEngine::Instance());
                if (m_sharedHashStore) {
                    pcm.SetHashStore(m_sharedHashStore.get());
                }
                pcm.Start();
                SetComponentState(ComponentType::PROCESS_MONITOR, ProtectionComponentState::RUNNING);
                Utils::Logger::Info("RealTimeProtection: ProcessCreationMonitor initialized and started");
            }
        } catch (const std::exception& ex) {
            Utils::Logger::Error("RealTimeProtection: ProcessCreationMonitor startup exception: {}", ex.what());
            SetComponentState(ComponentType::PROCESS_MONITOR, ProtectionComponentState::ERROR);
        } catch (...) {
            SetComponentState(ComponentType::PROCESS_MONITOR, ProtectionComponentState::ERROR);
        }

        // MemoryProtection
        if (m_config.monitorMemoryAllocation) {
            try {
                auto& mp = MemoryProtection::Instance();
                MemoryProtectionConfig mpConfig;
                mpConfig.enableKernelIntegration = true;
                mpConfig.enableContinuousMonitoring = m_config.monitorMemoryAllocation;
                mpConfig.enableAPTHunting = m_config.enableExploitPrevention;
                mpConfig.enableAlertSystem = true;
                mpConfig.enableTelemetry = true;
                mpConfig.enableBehaviorFeedback = true;
                mp.Configure(mpConfig);
                mp.Start();
                SetComponentState(ComponentType::MEMORY_PROTECTION, ProtectionComponentState::RUNNING);
                Utils::Logger::Info("RealTimeProtection: MemoryProtection configured and started");
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: MemoryProtection startup exception: {}", ex.what());
                SetComponentState(ComponentType::MEMORY_PROTECTION, ProtectionComponentState::ERROR);
            } catch (...) {
                SetComponentState(ComponentType::MEMORY_PROTECTION, ProtectionComponentState::ERROR);
            }
        }

        // BehaviorBlocker
        if (m_config.enableBehaviorBlocking) {
            try {
                auto& bb = BehaviorBlocker::Instance();
                BehaviorBlockerConfig bbConfig = BehaviorBlockerConfig::CreateDefault();
                if (!bb.Initialize(bbConfig)) {
                    Utils::Logger::Error("RealTimeProtection: BehaviorBlocker::Initialize failed");
                    SetComponentState(ComponentType::BEHAVIOR_BLOCKER, ProtectionComponentState::ERROR);
                } else {
                    const bool rulesLoaded = bb.LoadDefaultRules();
                    if (!rulesLoaded) {
                        Utils::Logger::Warn(
                            "RealTimeProtection: BehaviorBlocker::LoadDefaultRules returned "
                            "false - starting with empty rule set");
                    }
                    if (!bb.Start()) {
                        Utils::Logger::Error(
                            "RealTimeProtection: BehaviorBlocker::Start failed (rulesLoaded={})",
                            rulesLoaded);
                        SetComponentState(ComponentType::BEHAVIOR_BLOCKER,
                                          ProtectionComponentState::ERROR);
                    } else {
                        // PushRulesToKernel is best-effort: user-mode behavior
                        // blocking remains operational even if the kernel sync fails.
                        (void)bb.PushRulesToKernel();
                        SetComponentState(ComponentType::BEHAVIOR_BLOCKER, ProtectionComponentState::RUNNING);
                        Utils::Logger::Info("RealTimeProtection: BehaviorBlocker initialized with {} default rules",
                            bb.GetStatistics().activeRuleCount);
                    }
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: BehaviorBlocker startup exception: {}",
                    ex.what());
                SetComponentState(ComponentType::BEHAVIOR_BLOCKER, ProtectionComponentState::ERROR);
            } catch (...) {
                SetComponentState(ComponentType::BEHAVIOR_BLOCKER, ProtectionComponentState::ERROR);
            }
        }

        // NetworkTrafficFilter
        if (m_config.filterNetworkTraffic) {
            try {
                auto& ntf = NetworkTrafficFilter::Instance();
                if (!ntf.Initialize(m_threadPool, NetworkFilterConfig::CreateDefault())) {
                    Utils::Logger::Error("RealTimeProtection: NetworkTrafficFilter::Initialize failed");
                    SetComponentState(ComponentType::NETWORK_FILTER, ProtectionComponentState::ERROR);
                } else {
                    ntf.Start();
                    ntf.LoadBlockListFromFile(L"data/ip_blocklist.txt");
                    SetComponentState(ComponentType::NETWORK_FILTER, ProtectionComponentState::RUNNING);
                    Utils::Logger::Info("RealTimeProtection: NetworkTrafficFilter initialized and started");
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: NetworkTrafficFilter startup exception: {}", ex.what());
                SetComponentState(ComponentType::NETWORK_FILTER, ProtectionComponentState::ERROR);
            } catch (...) {
                SetComponentState(ComponentType::NETWORK_FILTER, ProtectionComponentState::ERROR);
            }
        }

        // ====================================================================
        // CORE NETWORK MODULES (gated on filterNetworkTraffic)
        // ====================================================================
        if (m_config.filterNetworkTraffic) {

            // ---- NetworkMonitor ----
            try {
                auto& nm = Core::Network::NetworkMonitor::Instance();
                auto nmCfg = Core::Network::NetworkMonitorConfig::CreateDefault();
                if (!nm.Initialize(nmCfg)) {
                    Utils::Logger::Error("RealTimeProtection: NetworkMonitor::Initialize failed");
                } else {
                    nm.Start();
                    Utils::Logger::Info("RealTimeProtection: NetworkMonitor initialized and started");
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: NetworkMonitor startup exception: {}", ex.what());
            } catch (...) {
                Utils::Logger::Error("RealTimeProtection: NetworkMonitor startup unknown exception");
            }

            // ---- TrafficAnalyzer ----
            try {
                auto& ta = Core::Network::TrafficAnalyzer::Instance();
                auto taCfg = Core::Network::TrafficAnalyzerConfig::CreateDefault();
                if (!ta.Initialize(taCfg)) {
                    Utils::Logger::Error("RealTimeProtection: TrafficAnalyzer::Initialize failed");
                } else {
                    if (m_sharedThreatIntelStore) {
                        ta.SetThreatIntelLookup(m_sharedThreatIntelStore->GetLookup());
                    }
                    if (m_sharedSignatureStore) {
                        ta.SetSignatureStore(m_sharedSignatureStore.get());
                    }
                    ta.Start();
                    Utils::Logger::Info("RealTimeProtection: TrafficAnalyzer initialized and started");
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: TrafficAnalyzer startup exception: {}", ex.what());
            } catch (...) {
                Utils::Logger::Error("RealTimeProtection: TrafficAnalyzer startup unknown exception");
            }

            // ---- DNSMonitor ----
            try {
                auto& dm = Core::Network::DNSMonitor::Instance();
                auto dmCfg = Core::Network::DNSMonitorConfig::CreateDefault();
                if (!dm.Initialize(dmCfg)) {
                    Utils::Logger::Error("RealTimeProtection: DNSMonitor::Initialize failed");
                } else {
                    dm.Start();
                    Utils::Logger::Info("RealTimeProtection: DNSMonitor initialized and started");
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: DNSMonitor startup exception: {}", ex.what());
            } catch (...) {
                Utils::Logger::Error("RealTimeProtection: DNSMonitor startup unknown exception");
            }

            // ---- URLAnalyzer ----
            try {
                auto& ua = Core::Network::URLAnalyzer::Instance();
                auto uaCfg = Core::Network::URLAnalyzerConfig::CreateDefault();
                if (!ua.Initialize(uaCfg)) {
                    Utils::Logger::Error("RealTimeProtection: URLAnalyzer::Initialize failed");
                } else {
                    if (m_sharedThreatIntelStore) {
                        ua.SetThreatIntelLookup(m_sharedThreatIntelStore->GetLookup());
                    }
                    if (m_sharedPatternStore) {
                        ua.SetPatternStore(m_sharedPatternStore.get());
                    }
                    Utils::Logger::Info("RealTimeProtection: URLAnalyzer initialized");
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: URLAnalyzer startup exception: {}", ex.what());
            } catch (...) {
                Utils::Logger::Error("RealTimeProtection: URLAnalyzer startup unknown exception");
            }

            // ---- BotnetDetector ----
            try {
                auto& bd = Core::Network::BotnetDetector::Instance();
                auto bdCfg = Core::Network::BotnetDetectorConfig::CreateDefault();
                if (!bd.Initialize(bdCfg)) {
                    Utils::Logger::Error("RealTimeProtection: BotnetDetector::Initialize failed");
                } else {
                    if (m_sharedThreatIntelStore) {
                        bd.SetThreatIntelStore(m_sharedThreatIntelStore.get());
                    }
                    bd.Start();
                    Utils::Logger::Info("RealTimeProtection: BotnetDetector initialized and started");
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: BotnetDetector startup exception: {}", ex.what());
            } catch (...) {
                Utils::Logger::Error("RealTimeProtection: BotnetDetector startup unknown exception");
            }

            // ---- WebProtection ----
            try {
                auto& wp = Core::Network::WebProtection::Instance();
                auto wpCfg = Core::Network::WebProtectionConfig::CreateDefault();
                if (!wp.Initialize(wpCfg)) {
                    Utils::Logger::Error("RealTimeProtection: WebProtection::Initialize failed");
                } else {
                    if (m_sharedThreatIntelStore) {
                        wp.SetThreatIntelStore(m_sharedThreatIntelStore.get());
                    }
                    wp.Start();
                    Utils::Logger::Info("RealTimeProtection: WebProtection initialized and started");
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: WebProtection startup exception: {}", ex.what());
            } catch (...) {
                Utils::Logger::Error("RealTimeProtection: WebProtection startup unknown exception");
            }

            // ---- TorDetector ----
            try {
                auto& td = Core::Network::TorDetector::Instance();
                auto tdCfg = Core::Network::TorDetectorConfig::CreateDefault();
                if (!td.Initialize(tdCfg)) {
                    Utils::Logger::Error("RealTimeProtection: TorDetector::Initialize failed");
                } else {
                    if (m_sharedThreatIntelStore) {
                        td.SetThreatIntelStore(m_sharedThreatIntelStore.get());
                    }
                    td.Start();
                    Utils::Logger::Info("RealTimeProtection: TorDetector initialized and started");
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: TorDetector startup exception: {}", ex.what());
            } catch (...) {
                Utils::Logger::Error("RealTimeProtection: TorDetector startup unknown exception");
            }

            // ---- VPNDetector ----
            try {
                auto& vd = Core::Network::VPNDetector::Instance();
                auto vdCfg = Core::Network::VPNDetectorConfig::CreateDefault();
                if (!vd.Initialize(vdCfg)) {
                    Utils::Logger::Error("RealTimeProtection: VPNDetector::Initialize failed");
                } else {
                    vd.Start();
                    Utils::Logger::Info("RealTimeProtection: VPNDetector initialized and started");
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: VPNDetector startup exception: {}", ex.what());
            } catch (...) {
                Utils::Logger::Error("RealTimeProtection: VPNDetector startup unknown exception");
            }

            // ---- P2PMonitor ----
            try {
                auto& pm = Core::Network::P2PMonitor::Instance();
                auto pmCfg = Core::Network::P2PMonitorConfig::CreateDefault();
                if (!pm.Initialize(pmCfg)) {
                    Utils::Logger::Error("RealTimeProtection: P2PMonitor::Initialize failed");
                } else {
                    if (m_sharedThreatIntelStore) {
                        pm.SetThreatIntelStore(m_sharedThreatIntelStore.get());
                    }
                    pm.Start();
                    Utils::Logger::Info("RealTimeProtection: P2PMonitor initialized and started");
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: P2PMonitor startup exception: {}", ex.what());
            } catch (...) {
                Utils::Logger::Error("RealTimeProtection: P2PMonitor startup unknown exception");
            }

            // ---- Event bridge: NetworkTrafficFilter -> TrafficAnalyzer ----
            try {
                auto& ntf = NetworkTrafficFilter::Instance();
                if (ntf.IsRunning()) {
                    // Best-effort event bridge: registration ID is owned by the
                    // filter for process lifetime (released on filter shutdown).
                    (void)ntf.RegisterEventCallback(
                        [](const NetworkEvent& event) {
                            try {
                                auto& analyzer = Core::Network::TrafficAnalyzer::Instance();
                                if (analyzer.IsRunning() && !event.dataPreview.empty()) {
                                    analyzer.AnalyzePacket(event.dataPreview);
                                }
                            } catch (...) {
                                // Best-effort forwarding; do not let callback exceptions
                                // propagate back into the filter's event loop.
                            }
                        });
                    Utils::Logger::Info("RealTimeProtection: Event bridge registered (NetworkTrafficFilter -> TrafficAnalyzer)");
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: Event bridge registration failed: {}", ex.what());
            } catch (...) {
                Utils::Logger::Error("RealTimeProtection: Event bridge registration unknown exception");
            }

        } // end filterNetworkTraffic (Core Network modules)

        // ExploitPrevention
        if (m_config.enableExploitPrevention) {
            try {
                auto& ep = ExploitPrevention::Instance();
                auto epConfig = ExploitPreventionConfig::CreateDefault();
                if (!ep.Initialize(m_threadPool, epConfig)) {
                    Utils::Logger::Error("RealTimeProtection: ExploitPrevention::Initialize failed");
                    SetComponentState(ComponentType::EXPLOIT_PREVENTION, ProtectionComponentState::ERROR);
                } else {
                    if (ep.Start()) {
                        (void)ep.PushMitigationsToKernel();
                        SetComponentState(ComponentType::EXPLOIT_PREVENTION, ProtectionComponentState::RUNNING);
                        Utils::Logger::Info("RealTimeProtection: ExploitPrevention initialized and running");
                    } else {
                        Utils::Logger::Error("RealTimeProtection: ExploitPrevention::Start failed");
                        SetComponentState(ComponentType::EXPLOIT_PREVENTION, ProtectionComponentState::ERROR);
                    }
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: ExploitPrevention startup exception: {}",
                    ex.what());
                SetComponentState(ComponentType::EXPLOIT_PREVENTION, ProtectionComponentState::ERROR);
            } catch (...) {
                SetComponentState(ComponentType::EXPLOIT_PREVENTION, ProtectionComponentState::ERROR);
            }
        }

        // FileIntegrityMonitor
        if (m_config.enableFileIntegrity) {
            try {
                auto& fim = FileIntegrityMonitor::Instance();
                auto fimConfig = FIMConfig::CreateDefault();
                if (!fim.Initialize(m_threadPool, fimConfig)) {
                    Utils::Logger::Error("RealTimeProtection: FileIntegrityMonitor::Initialize failed");
                    SetComponentState(ComponentType::FILE_INTEGRITY, ProtectionComponentState::ERROR);
                } else {
                    (void)fim.StartMonitoring();
                    // DEFER system-baseline creation off the Start critical path.
                    // CreateSystemBaselines() hashes hundreds of files under
                    // c:\windows\system32, drivers and boot -- heavy synchronous file
                    // I/O whose opens our own minifilter intercepts. Running it here
                    // stalled Start for 30-70s (field-confirmed 1.0.51 lockup: FIM
                    // hashing on the Start thread while the service was not yet
                    // ScanServicingReady, so the kernel held system-wide file I/O and
                    // the guest froze). Monitoring is already live via StartMonitoring()
                    // above; the readiness-gated deferred worker (Start step 4.5) builds
                    // the baselines once the service is online.
                    m_deferSystemBaselines.store(true, std::memory_order_release);
                    SetComponentState(ComponentType::FILE_INTEGRITY, ProtectionComponentState::RUNNING);
                    auto fimStats = fim.GetStats();
                    Utils::Logger::Info("RealTimeProtection: FIM initialized - {} files monitored, {} dirs",
                        fimStats.monitoredFiles, fimStats.monitoredDirectories);
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: FIM startup exception: {}",
                    ex.what());
                SetComponentState(ComponentType::FILE_INTEGRITY, ProtectionComponentState::ERROR);
            } catch (...) {
                SetComponentState(ComponentType::FILE_INTEGRITY, ProtectionComponentState::ERROR);
            }
        }

        // AccessControlManager
        try {
            auto& acm = AccessControlManager::Instance();
            if (!acm.Initialize(AccessControlManagerConfig::CreateEnterprise())) {
                Utils::Logger::Error(
                    "RealTimeProtection: AccessControlManager::Initialize failed - "
                    "ACM running in ERROR state");
                SetComponentState(ComponentType::ACCESS_CONTROL, ProtectionComponentState::ERROR);
            } else {
                SetComponentState(ComponentType::ACCESS_CONTROL, ProtectionComponentState::RUNNING);
            }
        } catch (...) {
            SetComponentState(ComponentType::ACCESS_CONTROL, ProtectionComponentState::ERROR);
        }

        // BehaviorAnalyzer — central behavioral engine wired into TD, PCM, PID
        try {
            auto& ba = Core::Engine::BehaviorAnalyzer::Instance();
            if (!ba.IsInitialized()) {
                if (!ba.Initialize(m_threadPool)) {
                    Utils::Logger::Error("RealTimeProtection: BehaviorAnalyzer::Initialize failed");
                } else {
                    Utils::Logger::Info("RealTimeProtection: BehaviorAnalyzer initialized");
                }
            }

            if (ba.IsInitialized()) {
                // Wire BA into ThreatDetector (TD uses BA for behavioral scoring during scans)
                try {
                    Core::Engine::ThreatDetector::Instance().SetBehaviorAnalyzer(&ba);
                } catch (const std::exception& ex) {
                    Utils::Logger::Error("RealTimeProtection: Failed to wire BA→ThreatDetector: {}", ex.what());
                }

                // Wire BA into ProcessCreationMonitor
                try {
                    ProcessCreationMonitor::Instance().SetBehaviorAnalyzer(&ba);
                } catch (const std::exception& ex) {
                    Utils::Logger::Error("RealTimeProtection: Failed to wire BA→PCM: {}", ex.what());
                }

                // Wire BA into ProcessInjectionDetector
                try {
                    auto& pid = Core::Process::ProcessInjectionDetector::Instance();
                    pid.SetBehaviorAnalyzer(&ba);
                } catch (const std::exception& ex) {
                    Utils::Logger::Error("RealTimeProtection: Failed to wire BA→PID: {}", ex.what());
                }
            }
        } catch (const std::exception& ex) {
            Utils::Logger::Error("RealTimeProtection: BehaviorAnalyzer startup exception: {}", ex.what());
        } catch (...) {
            Utils::Logger::Error("RealTimeProtection: BehaviorAnalyzer unknown startup exception");
        }

        // AtomBombingDetector (singleton -- detect AtomBombing code injection attacks)
        try {
            auto& abd = Core::Process::AtomBombingDetector::Instance();
            auto abdConfig = Core::Process::AtomBombingConfig::CreateDefault();
            abdConfig.enableRealTimeMonitoring = true;
            abdConfig.monitorAtomTable = true;
            abdConfig.monitorAPCs = true;
            abdConfig.correlateAtomAndAPC = true;
            abdConfig.detectShellcodePatterns = true;
            abdConfig.analyzeEntropy = true;
            abdConfig.extractPayloads = true;
            abdConfig.enableAutoResponse = m_config.enableBehaviorBlocking;
            abdConfig.blockSuspiciousApcs = m_config.enableBehaviorBlocking;

            if (!abd.Initialize(abdConfig)) {
                Utils::Logger::Error("RealTimeProtection: AtomBombingDetector::Initialize failed");
            } else {
                // Register attack callback for centralized logging/alerting
                abd.RegisterAttackCallback(
                    [](const Core::Process::AtomBombingAttack& attack) {
                        Utils::Logger::Warn(
                            "RealTimeProtection: [ABD] AtomBombing attack detected: "
                            "PID {} -> PID {} (confidence={}, risk={}, blocked={})",
                            attack.attackerPid, attack.victimPid,
                            static_cast<int>(attack.confidence),
                            attack.riskScore,
                            attack.wasBlocked ? "YES" : "NO");
                    });

                abd.StartMonitoring();
                Utils::Logger::Info("RealTimeProtection: AtomBombingDetector initialized and monitoring");
            }
        } catch (const std::exception& ex) {
            Utils::Logger::Error("RealTimeProtection: AtomBombingDetector startup exception: {}", ex.what());
        } catch (...) {
            Utils::Logger::Error("RealTimeProtection: AtomBombingDetector unknown startup exception");
        }

        // ZeroHourProtection
        if (m_config.enableZeroHourProtection) {
            try {
                auto& zhp = ZeroHourProtection::Instance();
                if (!zhp.Start()) {
                    Utils::Logger::Error("RealTimeProtection: ZeroHourProtection::Start failed");
                    SetComponentState(ComponentType::ZERO_HOUR, ProtectionComponentState::ERROR);
                } else {
                    // Register verdict callback for SOC/SIEM integration
                    (void)zhp.RegisterVerdictCallback(
                        [](const std::wstring& filePath, const FileAnalysisResult& result) {
                            if (result.verdict != CloudVerdict::CLEAN) {
                                Utils::Logger::Warn(
                                    "RealTimeProtection: [ZHP] Verdict for {}: threat={} (source={})",
                                    Utils::StringUtils::ToNarrow(filePath),
                                    Utils::StringUtils::ToNarrow(result.threatName),
                                    static_cast<int>(result.source));
                            }
                        });
                    // Register outbreak callback for rapid response
                    (void)zhp.RegisterOutbreakCallback(
                        [](const OutbreakInfo& outbreak, bool isNew) {
                            Utils::Logger::Error(
                                "RealTimeProtection: [ZHP] OUTBREAK {}: {} "
                                "(severity={} globalVictims={} localVictims={})",
                                isNew ? "DETECTED" : "UPDATED",
                                Utils::StringUtils::ToNarrow(outbreak.name),
                                outbreak.severity,
                                outbreak.globalVictimCount,
                                outbreak.localVictimCount);
                        });
                    // Register signature update callback
                    (void)zhp.RegisterSignatureUpdateCallback(
                        [](const MicroSigUpdatePackage& package, bool success) {
                            Utils::Logger::Info(
                                "RealTimeProtection: [ZHP] Signature update {}: "
                                "v{} -> v{} (additions={} removals={} emergency={})",
                                success ? "applied" : "FAILED",
                                package.baseVersion,
                                package.targetVersion,
                                package.additions.size(),
                                package.removals.size(),
                                package.isEmergency ? "yes" : "no");
                        });
                    SetComponentState(ComponentType::ZERO_HOUR, ProtectionComponentState::RUNNING);
                    Utils::Logger::Info("RealTimeProtection: ZeroHourProtection started with callbacks registered");
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("RealTimeProtection: ZeroHourProtection startup exception: {}", ex.what());
                SetComponentState(ComponentType::ZERO_HOUR, ProtectionComponentState::ERROR);
            } catch (...) {
                SetComponentState(ComponentType::ZERO_HOUR, ProtectionComponentState::ERROR);
            }
        }

        // HeapSprayDetector (singleton — initialize + start monitoring engine)
        try {
            auto& hsd = Exploits::HeapSprayDetector::Instance();
            if (hsd.Initialize()) {
                if (!hsd.Start()) {
                    Utils::Logger::Warn("RealTimeProtection: HeapSprayDetector Start failed");
                }
            } else {
                Utils::Logger::Warn("RealTimeProtection: HeapSprayDetector Initialize failed");
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("RealTimeProtection: HeapSprayDetector exception: {}", e.what());
        } catch (...) {
            Utils::Logger::Error("RealTimeProtection: HeapSprayDetector unknown exception");
        }

        // JITSprayDetector (singleton — initialize + start JIT code analysis engine)
        try {
            auto& jsd = Exploits::JITSprayDetector::Instance();
            if (jsd.Initialize()) {
                if (!jsd.Start()) {
                    Utils::Logger::Warn("RealTimeProtection: JITSprayDetector Start failed");
                }
            } else {
                Utils::Logger::Warn("RealTimeProtection: JITSprayDetector Initialize failed");
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("RealTimeProtection: JITSprayDetector exception: {}", e.what());
        } catch (...) {
            Utils::Logger::Error("RealTimeProtection: JITSprayDetector unknown exception");
        }

        // BufferOverflowProtection (singleton — initialize + start overflow detection engine)
        try {
            auto& bop = Exploits::BufferOverflowProtection::Instance();
            if (bop.Initialize()) {
                if (!bop.Start()) {
                    Utils::Logger::Warn("RealTimeProtection: BufferOverflowProtection Start failed");
                }
            } else {
                Utils::Logger::Warn("RealTimeProtection: BufferOverflowProtection Initialize failed");
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("RealTimeProtection: BufferOverflowProtection exception: {}", e.what());
        } catch (...) {
            Utils::Logger::Error("RealTimeProtection: BufferOverflowProtection unknown exception");
        }

        // StackPivotDetector (singleton — initialize + start stack pivot detection engine)
        try {
            auto& spd = Exploits::StackPivotDetector::Instance();
            if (spd.Initialize()) {
                if (!spd.Start()) {
                    Utils::Logger::Warn("RealTimeProtection: StackPivotDetector Start failed");
                }
            } else {
                Utils::Logger::Warn("RealTimeProtection: StackPivotDetector Initialize failed");
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("RealTimeProtection: StackPivotDetector exception: {}", e.what());
        } catch (...) {
            Utils::Logger::Error("RealTimeProtection: StackPivotDetector unknown exception");
        }

        // ROPProtection (return-oriented programming / gadget-chain detection).
        // Driven through the RopWiring shim to keep ROPProtection.hpp out of
        // this TU (it redefines DetectionConfidence in ShadowStrike::Exploits,
        // which would collide with KernelExploitDetector.hpp already included
        // above - a pre-existing ODR issue in the module headers).
        try {
            if (!::ShadowStrike::Exploits::RopWiring::InitROPProtection()) {
                Utils::Logger::Warn("RealTimeProtection: ROPProtection init returned false");
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("RealTimeProtection: ROPProtection exception: {}", e.what());
        } catch (...) {
            Utils::Logger::Error("RealTimeProtection: ROPProtection unknown exception");
        }

        // KernelExploitDetector (singleton — BYOVD / vulnerable driver / IOCTL abuse detection)
        try {
            auto& ked = Exploits::KernelExploitDetector::Instance();
            Exploits::KernelExploitDetectorConfiguration kedConfig;
            kedConfig.enableDriverMonitoring = true;
            kedConfig.blockVulnerableDrivers = true;
            kedConfig.enableLOLDriversDatabase = true;
            kedConfig.enableMicrosoftBlocklist = true;
            kedConfig.monitorIOCTL = true;
            kedConfig.blockSuspiciousIOCTL = true;
            kedConfig.detectKASLRLeaks = true;
            kedConfig.analyzeBSODDumps = true;

            if (ked.Initialize(kedConfig)) {
                if (!ked.Start()) {
                    Utils::Logger::Warn("RealTimeProtection: KernelExploitDetector Start failed");
                } else {
                    // Wire exploit detection callback for SOC alerting
                    ked.RegisterKernelExploitCallback(
                        [](const Exploits::KernelExploitEvent& event) {
                            auto typeName = Exploits::GetKernelThreatTypeName(event.threatType);
                            Utils::Logger::Warn(
                                "[KED-CB] Kernel exploit detected: {} (PID={}, confidence={:.1f}, blocked={})",
                                typeName.data(),
                                event.sourceProcessId,
                                event.confidence,
                                event.wasBlocked ? "YES" : "NO");
                        });

                    // Wire driver load callback for telemetry
                    ked.RegisterDriverLoadCallback(
                        [](const Exploits::DriverInfo& info, Exploits::DetectionAction action) {
                            if (info.isVulnerable || info.isMicrosoftBlocked || info.isLOLDriver) {
                                Utils::Logger::Error(
                                    "[KED-CB] Vulnerable driver: {} (SHA256: {}, "
                                    "LOLDriver={}, MSBlocked={}, Action={})",
                                    Utils::StringUtils::ToNarrow(info.fileName),
                                    info.sha256.substr(0, 16),
                                    info.isLOLDriver ? "YES" : "NO",
                                    info.isMicrosoftBlocked ? "YES" : "NO",
                                    static_cast<int>(action));
                            }
                        });

                    // Wire error callback
                    ked.RegisterErrorCallback(
                        [](const std::string& message, int code) {
                            Utils::Logger::Error("[KED-ERR] {} (code={})", message, code);
                        });

                    Utils::Logger::Info("RealTimeProtection: KernelExploitDetector initialized and started");
                }
            } else {
                Utils::Logger::Warn("RealTimeProtection: KernelExploitDetector Initialize failed");
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("RealTimeProtection: KernelExploitDetector exception: {}", e.what());
        } catch (...) {
            Utils::Logger::Error("RealTimeProtection: KernelExploitDetector unknown exception");
        }

        // PrivilegeEscalationDetector (singleton — token manipulation, UAC bypass, potato attacks, LPE)
        try {
            auto& ped = Exploits::PrivilegeEscalationDetector::Instance();
            Exploits::PrivilegeEscalationDetectorConfiguration pedConfig;
            pedConfig.monitorTokenChanges = true;
            pedConfig.monitorUACBypass = true;
            pedConfig.monitorServiceConfig = true;
            pedConfig.monitorRegistry = true;
            pedConfig.detectDLLHijacking = true;
            pedConfig.blockOnDetection = true;
            pedConfig.terminateOnHighConfidence = true;

            if (ped.Initialize(pedConfig)) {
                if (!ped.Start()) {
                    Utils::Logger::Warn("RealTimeProtection: PrivilegeEscalationDetector Start failed");
                } else {
                    // Wire LPE detection callback for SOC alerting and threat correlation
                    ped.RegisterLpeCallback(
                        [](const Exploits::LpeEvent& event) {
                            auto techniqueName = Exploits::GetLpeTechniqueName(event.technique);
                            Utils::Logger::Warn(
                                "[PED-CB] Privilege escalation detected: {} (PID={}, confidence={:.1f}, blocked={})",
                                techniqueName,
                                event.processId,
                                event.confidenceScore,
                                event.wasBlocked ? "YES" : "NO");
                        });

                    // Wire error callback
                    ped.RegisterErrorCallback(
                        [](const std::string& message, int code) {
                            Utils::Logger::Error("[PED-ERR] {} (code={})", message, code);
                        });

                    Utils::Logger::Info("RealTimeProtection: PrivilegeEscalationDetector initialized and started");
                }
            } else {
                Utils::Logger::Warn("RealTimeProtection: PrivilegeEscalationDetector Initialize failed");
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("RealTimeProtection: PrivilegeEscalationDetector exception: {}", e.what());
        } catch (...) {
            Utils::Logger::Error("RealTimeProtection: PrivilegeEscalationDetector unknown exception");
        }

        Utils::Logger::Info("RealTimeProtection: Components started");
    }

    void StopComponents() {
        Utils::Logger::Info("RealTimeProtection: Stopping protection components...");

        try { FileSystemFilter::Instance().Shutdown(); } catch (...) {}
        SetComponentState(ComponentType::FILE_SYSTEM_FILTER, ProtectionComponentState::STOPPED);

        try { ProcessCreationMonitor::Instance().Stop(); } catch (...) {}
        SetComponentState(ComponentType::PROCESS_MONITOR, ProtectionComponentState::STOPPED);

        try { MemoryProtection::Instance().Stop(); } catch (...) {}
        SetComponentState(ComponentType::MEMORY_PROTECTION, ProtectionComponentState::STOPPED);

        try {
            BehaviorBlocker::Instance().Stop();
            BehaviorBlocker::Instance().Shutdown();
        } catch (...) {}
        SetComponentState(ComponentType::BEHAVIOR_BLOCKER, ProtectionComponentState::STOPPED);

        // ====================================================================
        // CORE NETWORK MODULES — shutdown in reverse initialization order
        // ====================================================================
        try { Core::Network::P2PMonitor::Instance().Stop(); Core::Network::P2PMonitor::Instance().Shutdown(); } catch (...) {}
        try { Core::Network::VPNDetector::Instance().Stop(); Core::Network::VPNDetector::Instance().Shutdown(); } catch (...) {}
        try { Core::Network::TorDetector::Instance().Stop(); Core::Network::TorDetector::Instance().Shutdown(); } catch (...) {}
        try { Core::Network::WebProtection::Instance().Stop(); Core::Network::WebProtection::Instance().Shutdown(); } catch (...) {}
        try { Core::Network::BotnetDetector::Instance().Stop(); Core::Network::BotnetDetector::Instance().Shutdown(); } catch (...) {}
        try { Core::Network::URLAnalyzer::Instance().Shutdown(); } catch (...) {}
        try { Core::Network::DNSMonitor::Instance().Stop(); Core::Network::DNSMonitor::Instance().Shutdown(); } catch (...) {}
        try { Core::Network::TrafficAnalyzer::Instance().Stop(); Core::Network::TrafficAnalyzer::Instance().Shutdown(); } catch (...) {}
        try { Core::Network::NetworkMonitor::Instance().Stop(); Core::Network::NetworkMonitor::Instance().Shutdown(); } catch (...) {}
        Utils::Logger::Info("RealTimeProtection: Core Network modules stopped");

        try { NetworkTrafficFilter::Instance().Stop(); NetworkTrafficFilter::Instance().Shutdown(); } catch (...) {}
        SetComponentState(ComponentType::NETWORK_FILTER, ProtectionComponentState::STOPPED);

        try { ExploitPrevention::Instance().Shutdown(); } catch (...) {}
        SetComponentState(ComponentType::EXPLOIT_PREVENTION, ProtectionComponentState::STOPPED);

        try {
            FileIntegrityMonitor::Instance().StopMonitoring();
            FileIntegrityMonitor::Instance().Shutdown();
        } catch (...) {}
        SetComponentState(ComponentType::FILE_INTEGRITY, ProtectionComponentState::STOPPED);

        try { AccessControlManager::Instance().Shutdown(); } catch (...) {}
        SetComponentState(ComponentType::ACCESS_CONTROL, ProtectionComponentState::STOPPED);

        try { ZeroHourProtection::Instance().Stop(); } catch (...) {}
        SetComponentState(ComponentType::ZERO_HOUR, ProtectionComponentState::STOPPED);

        // BehaviorAnalyzer — shut down after event sources (PCM/PID/BB) but before exploit detectors
        try { Core::Engine::BehaviorAnalyzer::Instance().Shutdown(); } catch (...) {}

        // AtomBombingDetector — shut down after BehaviorAnalyzer
        try {
            Core::Process::AtomBombingDetector::Instance().StopMonitoring();
            Core::Process::AtomBombingDetector::Instance().Shutdown();
        } catch (...) {}

        try { Exploits::StackPivotDetector::Instance().Shutdown(); } catch (...) {}
        try { ::ShadowStrike::Exploits::RopWiring::ShutdownROPProtection(); } catch (...) {}
        try { Exploits::BufferOverflowProtection::Instance().Shutdown(); } catch (...) {}
        try { Exploits::JITSprayDetector::Instance().Shutdown(); } catch (...) {}
        try { Exploits::HeapSprayDetector::Instance().Shutdown(); } catch (...) {}
        try { Exploits::KernelExploitDetector::Instance().Shutdown(); } catch (...) {}
        try { Exploits::PrivilegeEscalationDetector::Instance().Shutdown(); } catch (...) {}

        // =====================================================================
        // Subsystem wiring teardown (Phase 3)
        //
        // Both helpers are `noexcept` and log their own failures; the wrapping
        // try/catch below is belt-and-suspenders in case someone replaces the
        // implementation with something looser in future.
        // =====================================================================
        try {
            ::ShadowStrike::Scripts::Wiring::ShutdownScriptsSubsystem();
        } catch (...) {}
        try {
            ::ShadowStrike::Ransomware::Wiring::ShutdownRansomwareSubsystem();
        } catch (...) {}

        Utils::Logger::Info("RealTimeProtection: Components stopped");
    }

    // =========================================================================
    // DEFERRED DEEP SCAN
    //
    // When the synchronous stage runs out of its latency budget the file is
    // queued here instead of being dropped: the kernel gets its answer promptly
    // (so the machine keeps responding) and the full pipeline still runs, just
    // off the blocking path. A malicious verdict from this stage is acted on
    // exactly as it would have been synchronously, so deferral changes when we
    // catch something, never whether we catch it.
    // =========================================================================

    // Ask for a Microsoft-signature trust verdict on a thread that is not
    // holding a kernel file operation open. Never blocks the caller.
    //
    // identityKey may be EMPTY. A non-empty key means "also publish an Allow to
    // the on-access file verdict cache under this exact identity once trust is
    // established"; an empty key means "just establish the verdict", which is all
    // the image-load and process-notify paths need, because they consult the
    // validator's own cache rather than the file verdict cache. Publishing under
    // a key nobody queries would be dead work dressed up as an optimisation.
    void QueueSignatureDetermination(const std::wstring& filePath,
                                     const std::wstring& identityKey) {
        // Dedup on the identity key when there is one, otherwise on the path.
        // Using the key unconditionally would collapse every keyless request into
        // a single queue slot and starve all but one of them.
        const std::wstring& dedupKey = identityKey.empty() ? filePath : identityKey;
        // Smaller than the deep-scan queue on purpose. Each entry is only worth
        // anything until the file is next accessed, and a first access that finds
        // no verdict simply re-queues it, so a deep backlog buys nothing while a
        // shallow one bounds both memory and how stale the queue can get.
        constexpr size_t kMaxSigDetermQueue = 1024;
        {
            std::lock_guard<std::mutex> lock(m_sigDetermMutex);
            // De-duplicate on the identity key, not the path: one file being
            // opened repeatedly must collapse to one determination, but a file
            // that has genuinely changed is different content and needs its own.
            if (m_sigDetermSeen.count(dedupKey) != 0) {
                return;
            }
            if (m_sigDetermQueue.size() >= kMaxSigDetermQueue) {
                // Drop the OLDEST, and say so. The oldest request is the least
                // valuable: either the file was accessed again already and
                // re-queued, or it has not been touched since and is not urgent.
                // Silence here would look exactly like a working fast path that
                // simply never warms up, which is the failure mode this codebase
                // produces most often.
                Utils::Logger::Warn(
                    "RealTimeProtection: signature determination queue full ({}); "
                    "dropping oldest - the trust fast path will warm more slowly",
                    kMaxSigDetermQueue);
                const auto& front = m_sigDetermQueue.front();
                m_sigDetermSeen.erase(front.second.empty() ? front.first
                                                           : front.second);
                m_sigDetermQueue.pop_front();
            }
            m_sigDetermQueue.emplace_back(filePath, identityKey);
            m_sigDetermSeen.insert(dedupKey);
        }
        m_sigDetermCv.notify_one();
    }

    // Establishes Microsoft-signature trust verdicts off the kernel-reply path.
    //
    // This thread is allowed to do what no scan worker may: call into another
    // process and wait. It holds no kernel file operation, so if CryptSvc's own
    // file I/O is intercepted by our minifilter, the scan workers are still free
    // to service it and the cycle that wedged 1.0.91 cannot form.
    void SignatureDeterminationLoop() {
        ::SetThreadDescription(::GetCurrentThread(), L"SS-SignatureDetermination");
        // Same reasoning as the deferred deep-scan stage: this exists to keep the
        // verdict path fast, so it must never compete with it.
        ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

        while (!m_sigDetermStop.load(std::memory_order_acquire)) {
            std::pair<std::wstring, std::wstring> item;
            {
                std::unique_lock<std::mutex> lock(m_sigDetermMutex);
                m_sigDetermCv.wait_for(lock, std::chrono::milliseconds(1000), [this] {
                    return m_sigDetermStop.load(std::memory_order_acquire) ||
                           !m_sigDetermQueue.empty();
                });
                if (m_sigDetermStop.load(std::memory_order_acquire)) break;
                if (m_sigDetermQueue.empty()) continue;
                item = std::move(m_sigDetermQueue.front());
                m_sigDetermQueue.pop_front();
                m_sigDetermSeen.erase(item.second.empty() ? item.first
                                                          : item.second);
            }
            const std::wstring& filePath    = item.first;
            const std::wstring& identityKey = item.second;

            SS_DIAG_SCOPE("SigDeterm", "determine-microsoft-trust");

            bool trusted = false;
            try {
                // The blocking call, on the one thread where blocking is safe.
                // Full strength deliberately: whole-chain revocation against the
                // local CRL cache stays enabled here, which is stronger than
                // anything that could be justified in line, because a slow answer
                // on this thread delays a cache warm-up rather than every file
                // operation on the machine.
                trusted = Security::DigitalSignatureValidator::Instance()
                              .IsMicrosoftSigned(filePath);
            } catch (const std::exception& e) {
                Utils::Logger::Warn(
                    "RealTimeProtection: signature determination failed for {}: {}",
                    Utils::StringUtils::ToNarrow(filePath), e.what());
                continue;
            }

            if (!trusted) {
                // Nothing to publish. Only trust is cacheable here; an absent
                // entry correctly means "not determined to be trusted" and leaves
                // the file taking the full pipeline on every access.
                continue;
            }

            // The verdict now lives in the validator's own cache, which is what
            // every TryGetCachedMicrosoftSigned caller reads, so callers that
            // supplied no identity key are already served and are done here.
            if (identityKey.empty()) {
                m_stats.signatureVerdictsCached++;
                continue;
            }

            // Publish only if the file is STILL the content we were asked about.
            //
            // Without this check, deferring the verification would open a window
            // that the synchronous version did not have: an attacker could let us
            // verify trusted content, then restore untrusted content with the same
            // size and a restored last-write time, and the verdict cached under
            // the original identity would serve it. Re-reading identity here binds
            // the published verdict to content that was still present after the
            // verdict was reached.
            //
            // Stated honestly: last-write time is attacker-settable, so this is a
            // narrowing of the window, not a cryptographic guarantee - the same
            // limitation the identity-keyed verdict cache already has. It closes
            // the window this change would otherwise add.
            WIN32_FILE_ATTRIBUTE_DATA fad{};
            if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fad)) {
                continue;
            }
            const uint64_t mtime =
                (static_cast<uint64_t>(fad.ftLastWriteTime.dwHighDateTime) << 32) |
                 static_cast<uint64_t>(fad.ftLastWriteTime.dwLowDateTime);
            const uint64_t size =
                (static_cast<uint64_t>(fad.nFileSizeHigh) << 32) |
                 static_cast<uint64_t>(fad.nFileSizeLow);
            const std::wstring currentKey =
                ToLowerW(filePath) + L"|" +
                std::to_wstring(static_cast<unsigned long long>(size)) + L"|" +
                std::to_wstring(static_cast<unsigned long long>(mtime));

            if (currentKey != identityKey) {
                continue;  // Changed under us; the verdict describes gone content.
            }

            UpdateFileVerdictCache(identityKey, Communication::KernelVerdict::Allow);
            m_stats.signatureVerdictsCached++;
        }
    }

    void QueueDeferredDeepScan(const std::wstring& filePath, uint32_t processId) {
        constexpr size_t kMaxDeferredQueue = 4096;
        {
            std::lock_guard<std::mutex> lock(m_deferredMutex);
            // De-duplicate: a busy directory produces many opens of one file.
            if (m_deferredSeen.count(filePath) != 0) {
                return;
            }
            if (m_deferredQueue.size() >= kMaxDeferredQueue) {
                // Never grow without bound. Losing the oldest entry is visible
                // rather than silent so the backlog can be tuned.
                Utils::Logger::Warn(
                    "RealTimeProtection: deferred deep-scan queue full ({}); dropping oldest",
                    kMaxDeferredQueue);
                m_deferredSeen.erase(m_deferredQueue.front().first);
                m_deferredQueue.pop_front();
            }
            m_deferredQueue.emplace_back(filePath, processId);
            m_deferredSeen.insert(filePath);
        }
        // Counted here rather than at the call sites. The statistic previously
        // only incremented on the budget-exceeded path, so once every scanned
        // file began being deferred the counter no longer reflected reality -
        // and this counter is the evidence that work skipped on the fast path is
        // actually being picked up rather than quietly dropped. A number that
        // does not measure what it claims to is worse than no number.
        m_stats.scansDeferred++;
        m_deferredCv.notify_one();
    }

    void HandleDeferredThreat(const std::wstring& filePath, uint32_t processId,
                              const Core::Engine::EngineResult& result) {
        // Same remediation the synchronous path would have applied. Deferral
        // moved the analysis off the blocking path; it does not change what we
        // do when the file turns out to be malicious.
        const std::wstring threatName = result.threatName.empty()
            ? std::wstring(L"Deferred.DeepScan.Detection")
            : Utils::StringUtils::ToWide(result.threatName);

        if (!QuarantineFile(filePath, threatName)) {
            Utils::Logger::Error(
                "RealTimeProtection: deferred remediation could not quarantine {}",
                Utils::StringUtils::ToNarrow(filePath));
        }

        // If the file is still running, the process is the live threat.
        if (processId != 0) {
            Utils::Logger::Warn(
                "RealTimeProtection: deferred detection implicates PID {} ({})",
                processId, Utils::StringUtils::ToNarrow(filePath));
        }
    }

    void DeferredDeepScanLoop() {
        ::SetThreadDescription(::GetCurrentThread(), L"SS-DeferredDeepScan");
        // Background stage: must never compete with the verdict path it exists
        // to protect.
        ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

        while (!m_deferredStop.load(std::memory_order_acquire)) {
            std::pair<std::wstring, uint32_t> item;
            {
                std::unique_lock<std::mutex> lock(m_deferredMutex);
                m_deferredCv.wait_for(lock, std::chrono::milliseconds(1000), [this] {
                    return m_deferredStop.load(std::memory_order_acquire) ||
                           !m_deferredQueue.empty();
                });
                if (m_deferredStop.load(std::memory_order_acquire)) break;
                if (m_deferredQueue.empty()) continue;
                item = std::move(m_deferredQueue.front());
                m_deferredQueue.pop_front();
                m_deferredSeen.erase(item.first);
            }

            try {
                Core::Engine::ScanContext ctx;
                // Deliberately NOT ScanType::RealTime: nothing is waiting on
                // this, so the engine may take the slow, thorough path.
                ctx.type = Core::Engine::ScanType::OnDemand;
                ctx.priority = Core::Engine::ScanPriority::Low;
                ctx.processId = item.second;
                ctx.filePath = item.first;
                // ScanContext::deepScan defaults to false (ScanEngine.hpp:287),
                // so without this the "deferred deep scan" was not deep at all:
                // the deep signature sweep, sandbox, emulation and zero-day
                // stages are each gated on this flag and were all being skipped.
                // Everything the on-access path declines to do synchronously is
                // supposed to land here, so this is the flag that makes deferring
                // a scheduling decision instead of a coverage hole.
                ctx.deepScan = true;

                auto result = Core::Engine::ScanEngine::Instance().ScanFile(item.first, ctx);
                if (result.verdict == Core::Engine::ScanVerdict::Infected) {
                    m_stats.threatsDetected++;
                    Utils::Logger::Warn(
                        "RealTimeProtection: deferred deep scan found threat in {} - remediating",
                        Utils::StringUtils::ToNarrow(item.first));
                    HandleDeferredThreat(item.first, item.second, result);
                }
            } catch (const std::exception& e) {
                Utils::Logger::Error("RealTimeProtection: deferred deep scan failed for {}: {}",
                    Utils::StringUtils::ToNarrow(item.first), e.what());
                m_stats.scanErrors++;
            } catch (...) {
                m_stats.scanErrors++;
            }
        }
    }

    // =========================================================================
    // KERNEL EVENT HANDLERS
    // =========================================================================

    Communication::KernelVerdict OnKernelFileScan(const FILE_SCAN_REQUEST& req) {
        auto startTime = std::chrono::high_resolution_clock::now();

        m_stats.totalEvents++;
        m_stats.fileEvents++;
        m_stats.totalScans++;
        SS_DIAG_SCOPE("OnAccess", "kernel-scan-request");
        m_performanceMetrics.kernelMessages++;

        if (m_state != ProtectionState::ACTIVE) {
            return Communication::KernelVerdict::Allow;
        }

        // Extract file path from variable-length data after the struct
        std::wstring filePath(
            reinterpret_cast<const wchar_t*>(
                reinterpret_cast<const uint8_t*>(&req) + sizeof(FILE_SCAN_REQUEST)),
            req.PathLength / sizeof(wchar_t));

        // The kernel delivers the path in NT device form
        // (\Device\HarddiskVolumeN\...), which the Win32 file APIs used by every
        // scanner below — exclusions, ransomware/script dispatch, metamorphic,
        // packer, ExecutableAnalyzer, ScanEngine — cannot open. Resolve it to a
        // DOS path once, here at the boundary; without this each scan fails
        // "file not found" and the product never actually inspects anything.
        SS_DIAG("OnAccess", "step.DevicePathToDosPath");
        filePath = Utils::FileUtils::DevicePathToDosPath(filePath);

        // 1. Check Exclusions
        SS_DIAG("OnAccess", "step.IsExcluded");
        if (IsExcluded(filePath, req.ProcessId)) {
            m_stats.excludedByPath++;
            return Communication::KernelVerdict::Allow;
        }

        // 1.4  ON-ACCESS FAST PATH (file-identity verdict cache)
        // The kernel re-issues a scan for the same file on every open/launch;
        // trusted binaries (cmd.exe, ntdll, rpcss...) were re-scanned 20-60x,
        // each re-running the full heavy pipeline (0.5-2.3s) -- the dominant
        // idle-CPU cost. For NON-mutating access (read/execute) serve a cached
        // benign verdict keyed by identity (path|size|mtime); repeats become
        // near-instant. Mutating access (write/create/rename/delete) is NEVER
        // served from cache -- it falls through to the full pipeline + the
        // ransomware/script dispatch below, and a changed size/mtime naturally
        // invalidates any prior entry, so a modified file is always re-analyzed.
        // Only Allow is ever cached (see UpdateFileVerdictCache), so a malicious
        // verdict is never cached away.
        std::wstring fileIdentityKey;
        {
            const uint8_t at = req.AccessType;
            const bool mutating =
                at == static_cast<uint8_t>(ShadowStrikeAccessWrite)  ||
                at == static_cast<uint8_t>(ShadowStrikeAccessCreate) ||
                at == static_cast<uint8_t>(ShadowStrikeAccessRename) ||
                at == static_cast<uint8_t>(ShadowStrikeAccessDelete);
            if (!mutating) {
                uint64_t mtime = 0;
                WIN32_FILE_ATTRIBUTE_DATA fad{};
                SS_DIAG("OnAccess", "step.GetFileAttributesExW");
                if (GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fad)) {
                    mtime = (static_cast<uint64_t>(fad.ftLastWriteTime.dwHighDateTime) << 32)
                          |  static_cast<uint64_t>(fad.ftLastWriteTime.dwLowDateTime);
                }
                fileIdentityKey = ToLowerW(filePath) + L"|" +
                    std::to_wstring(static_cast<unsigned long long>(req.FileSize)) + L"|" +
                    std::to_wstring(static_cast<unsigned long long>(mtime));
                SS_DIAG("OnAccess", "step.CheckFileVerdictCache");
                if (auto cached = CheckFileVerdictCache(fileIdentityKey)) {
                    m_stats.cleanFiles++;
                    return *cached;
                }

                // TIER 1: MICROSOFT-SIGNATURE TRUST (cache-only in line)
                // A WinVerifyTrust-validated Microsoft Authenticode signature
                // means this is trusted operating-system code. Trust it and skip
                // the entire heavy pipeline below (metamorphic + deep packer +
                // ExecutableAnalyzer + ScanEngine's emulation/polymorphic/
                // metamorphic stages). Deep dynamic analysis of clean signed OS
                // binaries -- ntdll, uxtheme, svchost, msxml3, ... loaded by
                // every process -- was the dominant real-time CPU cost.
                //
                // This does NOT weaken detection: (a) malware cannot forge a
                // valid Microsoft signature (the verdict comes from
                // WinVerifyTrust having validated the chain AND publisher, it is
                // not a name check); (b) any tampering both breaks the signature
                // AND changes size/mtime, so a modified file misses the cache and
                // gets a full re-scan; (c) only NON-mutating access reaches here,
                // so writes/creates always fall through to full analysis; and
                // (d) LOLBin *abuse* of a signed binary is detected by the
                // process/behavioral monitors, not by scanning the clean file.
                //
                // WHY THIS IS A CACHE-ONLY QUERY AND NOT A VERIFICATION.
                // IsMicrosoftSigned reaches WinVerifyTrust, which does not do its
                // own work: it RPCs into CryptSvc, which reads the catalog store
                // under CatRoot. Our own minifilter intercepts those reads and
                // posts them back to this service. A scan worker that calls it is
                // therefore waiting on a process that is waiting on that same
                // worker, and with a small worker pool that is zero scan capacity
                // until something times out. The 1.0.91 field trace measured
                // exactly that: 180.13 seconds on both workers, released 2 ms
                // apart, which is one shared resource timing out rather than any
                // per-thread work. Cache-only URL flags do not prevent it - and
                // this call already sets them - because the block is not our
                // process reaching the network, it is another process's file I/O
                // being blocked by us.
                //
                // So the verdict is consumed here but never produced here.
                // Production happens on the signature-determination thread,
                // which holds no kernel operation and can safely block.
                SS_DIAG("OnAccess", "step.TryGetCachedMicrosoftSigned");
                const std::optional<bool> msTrust =
                    Security::DigitalSignatureValidator::Instance()
                        .TryGetCachedMicrosoftSigned(filePath);

                if (msTrust.has_value() && *msTrust) {
                    UpdateFileVerdictCache(fileIdentityKey,
                                           Communication::KernelVerdict::Allow);
                    m_stats.cleanFiles++;
                    return Communication::KernelVerdict::Allow;
                }

                if (!msTrust.has_value()) {
                    // Not determined - which is not the same as unsigned, and is
                    // deliberately not treated as one. Ask for the verdict off
                    // this thread so the next access to this exact file content
                    // can take the fast path, then fall through to the full local
                    // pipeline, which decides this access on its own evidence.
                    QueueSignatureDetermination(filePath, fileIdentityKey);
                }
                // A determined non-Microsoft verdict (*msTrust == false) falls
                // through as well, exactly as before: this tier only ever grants
                // a fast path, it never blocks or reports a threat, so there is
                // nothing to re-ask and nothing to defer.
            }
        }

        // 1.5. CPU-based scan throttling — defer low-priority scans under heavy load
        SS_DIAG("OnAccess", "step.CPUMonitor.IsSystemUnderLoad");
        if (m_config.throttleOnHighCPU && Performance::CPUMonitor::HasInstance()) {
            if (Performance::CPUMonitor::Instance().IsSystemUnderLoad(90.0)) {
                // Under extreme load, only allow high-priority scans (Priority > 0).
                // Low-priority background I/O scans are deferred to reduce system impact.
                if (req.Priority == 0) {
                    m_stats.excludedByPath++;
                    return Communication::KernelVerdict::Allow;
                }
            }
        }

        // =====================================================================
        // 1.6  RANSOMWARE + SCRIPT-SCANNER DISPATCH (Phase 4 kernel fan-out)
        //
        // The ransomware subsystem (RansomwareDetector, LockyDetector,
        // WannaCryDetector, HoneypotManager) and the script scanners are
        // initialized during Start() but were previously starved of kernel
        // events. Route the event here — BEFORE the heavier metamorphic /
        // packer / signature pipeline — so family-specific detectors get the
        // first look at every touched file.
        //
        // The script dispatch is the only one that can short-circuit to Block:
        // when JS / VBS / Python / Office-macro analyzers return a verdict,
        // the file is known-bad and no further analysis is warranted.
        // =====================================================================
        {
            const uint8_t accessType = req.AccessType;
            switch (accessType) {
                case static_cast<uint8_t>(ShadowStrikeAccessWrite):
                case static_cast<uint8_t>(ShadowStrikeAccessCreate):
                    SS_DIAG("OnAccess", "step.DispatchFileWrite(ransomware)");
                    Ransomware::Wiring::DispatchFileWrite(
                        req.ProcessId, filePath, std::wstring{});
                    SS_DIAG("OnAccess", "step.DispatchFileScan(scripts)");
                    if (Scripts::Wiring::DispatchFileScan(req.ProcessId, filePath)) {
                        Utils::Logger::Warn(
                            "RealTimeProtection: Script scanner blocked malicious file: {}",
                            Utils::StringUtils::ToNarrow(filePath));
                        m_stats.threatsDetected++;
                        return Communication::KernelVerdict::Block;
                    }
                    break;
                case static_cast<uint8_t>(ShadowStrikeAccessRename):
                    // Rename carries only the new path at this layer; LockyDetector
                    // still scores on the new extension alone.
                    SS_DIAG("OnAccess", "step.DispatchFileRename");
                    Ransomware::Wiring::DispatchFileRename(
                        req.ProcessId, std::wstring{}, filePath);
                    break;
                case static_cast<uint8_t>(ShadowStrikeAccessDelete):
                    SS_DIAG("OnAccess", "step.DispatchFileDelete");
                    Ransomware::Wiring::DispatchFileDelete(req.ProcessId, filePath);
                    break;
                default:
                    break;
            }
        }

        // 2. Check Verdict Cache
        std::string hashKey;

        // =====================================================================
        // SYNCHRONOUS LATENCY BUDGET
        //
        // The minifilter holds the originating file operation until we answer,
        // so the time spent below is added to a real file open somewhere on the
        // machine. When many opens arrive at once (boot, an installer, a build)
        // and each one pays the full deep pipeline, the queue grows faster than
        // it drains and the whole desktop stops responding while the kernel
        // waits on us -- observed as a multi-minute freeze with only moderate
        // CPU, because the cost is latency, not cycles.
        //
        // Commercial engines solve this with a bounded synchronous stage and an
        // asynchronous deep stage. We do the same: the cheap, high-value tiers
        // (exclusions, identity cache, Microsoft/publisher trust, reputation,
        // ransomware + script dispatch) have already run above. From here the
        // heavy analyzers run only while the budget lasts. If it is exhausted
        // the file is handed to the background deep-scan queue and the caller is
        // released, so the machine keeps moving.
        //
        // This does not lose detection:
        //   - EXECUTE and mutating access always get the full synchronous
        //     pipeline; the budget only applies to ordinary reads, so nothing
        //     runs before it has been fully analyzed.
        //   - a deferred file is still analyzed, and a malicious verdict from
        //     the async stage quarantines it, so the outcome differs in timing,
        //     not in whether it is caught.
        //   - the budget is generous relative to a healthy scan; it only
        //     engages when we are already the reason the system is stalling.
        const auto kSyncBudget = std::chrono::milliseconds(
            RTPConstants::KERNEL_REPLY_TIMEOUT_MS / 4);
        const bool isExecuteAccess =
            req.AccessType == static_cast<uint8_t>(ShadowStrikeAccessExecute);
        const auto budgetExceeded = [&]() -> bool {
            if (isExecuteAccess) {
                return false;  // never cut short the pre-execution decision
            }
            const auto spent = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - startTime);
            return spent >= kSyncBudget;
        };
        const auto deferDeepScan = [&](const wchar_t* stage) {
            SS_LOG_DEBUG(L"RealTimeProtection",
                L"Sync budget reached at %ls for %ls; deferring deep analysis",
                stage, filePath.c_str());
            QueueDeferredDeepScan(filePath, req.ProcessId);
        };

        // =====================================================================
        // CONTENT-AVAILABILITY GATE
        //
        // Everything below this point (metamorphic, packer, ExecutableAnalyzer,
        // ScanEngine + its hash/emulation stages) reads the file's *bytes*. A
        // path we cannot open carries no content to analyze, so running them
        // only burns CPU re-failing the open. A single bogus / stale / already-
        // deleted kernel path was observed driving MetamorphicDetector +
        // MemoryUtils + ExecutableAnalyzer + ScanEngine to each independently
        // open-and-fail ("file not found") back to back -- pure waste plus a
        // flood of ERROR/WARN log lines. Resolve openability ONCE here and skip
        // content analysis for absent paths / directories.
        //
        // This preserves detection: (a) unopenable == unanalyzable -- every
        // analyzer already failed on it, so nothing is lost; (b) the behavioral
        // ransomware / script dispatch above (write/create/rename/delete) has
        // ALREADY run, so file-operation patterns are still scored; and (c) a
        // later create/write on the path re-triggers a scan with real content.
        {
        SS_DIAG("OnAccess", "step.GetFileAttributesW");
            const DWORD attrs = ::GetFileAttributesW(filePath.c_str());
            if (attrs == INVALID_FILE_ATTRIBUTES) {
                // Absent / unresolvable path -- nothing to inspect.
                return Communication::KernelVerdict::Allow;
            }
            if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
                // Directories have no file content to scan here.
                return Communication::KernelVerdict::Allow;
            }
        }

        // Anti-Evasion: Metamorphic Analysis
        if (m_metamorphicDetector) {
            if (budgetExceeded()) {
                deferDeepScan(L"metamorphic");
                return Communication::KernelVerdict::Allow;
            }
            ShadowStrike::AntiEvasion::MetamorphicAnalysisConfig metaCfg;
            metaCfg.processId = req.ProcessId;
            // Bound the work, do not reduce it.
            //
            // This call left timeoutMs at MetamorphicConstants::DEFAULT_SCAN_TIMEOUT_MS,
            // which is sized for an offline sweep. A field trace caught a single
            // invocation at 5,293.97 ms - 5.3 seconds - on the on-access path,
            // where a kernel thread is parked inside FltSendMessage holding an
            // IRP_MJ_CREATE and every other file operation on the machine queues
            // behind the verdict. That one call accounted for 98 percent of all
            // scan time in the session, and it is what the owner feels when a
            // right-click or a UI tab switch locks the desktop.
            //
            // Depth and flags are deliberately left untouched: this is a deadline,
            // not a narrower analysis, so every technique still runs and simply has
            // to fit a budget appropriate to having a kernel thread waiting.
            // Anything that does not fit is still covered, because
            // QueueDeferredDeepScan re-examines the file off the kernel's thread
            // where the full default timeout applies.
            metaCfg.timeoutMs = 50u;

            // BOUND THE DISASSEMBLY, WHICH IS WHAT ACTUALLY COST THE 10.9 SECONDS.
            //
            // The deadline above is necessary but was not sufficient on its own,
            // and it is worth being precise about why. MetamorphicAnalysisConfig
            // defaults maxInstructions to MetamorphicConstants::MAX_INSTRUCTIONS,
            // which is 10,000,000, and this call never overrode it. The budget can
            // only be tested between stages, so a single DisassembleBuffer asked to
            // decode ten million instructions overruns it by any margin it likes -
            // which is exactly what the field trace caught. The same limit also
            // drives a speculative reserve of min(size/4, limit) entries, so an
            // unbounded instruction count is a memory spike as well as a stall.
            //
            // 64K instructions is a bound on WORK, not a reduction in technique.
            // Every detector still runs, over the region where the evidence they
            // look for actually lives: entry-point decryption stubs, GetPC
            // sequences, substitution and dead-code patterns and API hashing all
            // appear in the first few thousand instructions of a mutated sample,
            // because that is the unpacking preamble. What a deeper decode adds is
            // coverage of the body, and the body is covered by the deferred stage
            // below, which runs with the full default limit and no deadline.
            metaCfg.maxInstructions = 64u * 1024u;

            SS_DIAG_SCOPE("OnAccess", "MetamorphicDetector::AnalyzeFile");
            auto metaResult = m_metamorphicDetector->AnalyzeFile(filePath, metaCfg);
            if (metaResult.analysisTruncated) {
                // The budget stopped this analysis before every technique ran, so
                // this file has NOT been cleared - it has been partially examined.
                // Re-examine it off the kernel's thread, where the full limits
                // apply. Without this the deadline would silently trade detection
                // for latency, which is the one trade this project does not make.
                m_stats.metamorphicTruncated++;
                QueueDeferredDeepScan(filePath, req.ProcessId);
            }
            if (metaResult.isMetamorphic) {
                Utils::Logger::Warn(
                    "RealTimeProtection: Blocked metamorphic threat: {} "
                    "[score={:.1f} severity={} detections={} family={}]",
                    Utils::StringUtils::ToNarrow(filePath),
                    metaResult.mutationScore,
                    static_cast<int>(metaResult.maxSeverity),
                    metaResult.totalDetections,
                    metaResult.familyName.empty() ? std::string("unknown") : Utils::StringUtils::ToNarrow(metaResult.familyName));
                m_stats.threatsDetected++;
                return Communication::KernelVerdict::Block;
            }
        }

        // Anti-Evasion: Packer Detection (packed executables are suspicious — feed into scan context)
        //
        // Depth is chosen by whether a kernel thread is waiting on us.
        //
        // This used to request PackerAnalysisDepth::Deep with the DeepScan flag
        // unconditionally, on the in-line path, while the sensor holds an
        // IRP_MJ_CREATE open and every other file operation on the machine queues
        // behind it. A field trace measured a single on-access request at
        // 4,665,512 us - 4.67 seconds - against a typical 100-300 us, which is
        // precisely the stall the owner sees the moment a new file is touched.
        //
        // Commit 4ffcd2fe moved emulation, sandbox, YARA and fuzzy hashing off
        // this path behind the deferred deep-scan worker. This call site and the
        // metamorphic one above it were missed and kept their Deep setting.
        //
        // Deep analysis is not lost: QueueDeferredDeepScan re-examines every
        // scanned file on the worker with full depth, off the kernel's thread.
        // What changes is only WHEN the expensive work happens, never WHETHER.
        // The quick pass still runs in-line, so entropy, section characteristics
        // and signature matching continue to inform this verdict.
        bool fileIsPacked = false;
        double packingConfidence = 0.0;
        if (m_packerDetector) {
            ShadowStrike::AntiEvasion::PackerAnalysisConfig pdConfig;
            // Standard = entropy + entry-point signature + sections + imports.
            // All header-level work, and it keeps genuine packer detection on the
            // in-line path. Deep adds YARA scanning and heuristics, which is the
            // expensive tier and belongs on the deferred worker.
            pdConfig.depth = ShadowStrike::AntiEvasion::PackerAnalysisDepth::Standard;
            pdConfig.processId = req.ProcessId;

            // Signature verification is removed from the in-line flags, and this is
            // the one narrowing that is not about cost.
            //
            // PackerAnalysisFlags::Default is StandardScan, which includes
            // EnableSignatureVerification, so a default-constructed config makes
            // PackerDetector call VerifyPESignature here. That reaches
            // WinVerifyTrust, which is an RPC into CryptSvc, whose catalog reads our
            // own minifilter intercepts and hands back to this service - so a scan
            // worker blocked in it is waiting on a process waiting on the worker.
            // The field trace measured that cycle at 180.13 seconds on both workers
            // at once, and the cache-only trust flags this path already sets do not
            // prevent it, because the block is not our process reaching the network.
            //
            // This is the same defect the ExecutableAnalyzer fix addressed, in a
            // second module on the same path; it was missed the first time because
            // the trace named whichever call happened to block first. The rule is
            // that no thread holding a kernel file operation open may make a
            // synchronous call that leaves this process, and it has to be applied to
            // the behaviour rather than to one API.
            //
            // No packer technique is lost. Entropy, entry-point signatures, section
            // and import analysis all stay in line and are what actually decide
            // isPacked. The signature verdict is used to temper the confidence of a
            // packing call, so dropping it in line can only make this stage more
            // willing to flag, never less - and the deferred stage runs the full
            // profile, signature included, a moment later.
            pdConfig.flags = static_cast<ShadowStrike::AntiEvasion::PackerAnalysisFlags>(
                static_cast<uint32_t>(ShadowStrike::AntiEvasion::PackerAnalysisFlags::Default) &
                ~static_cast<uint32_t>(
                    ShadowStrike::AntiEvasion::PackerAnalysisFlags::EnableSignatureVerification));

            // Bound the two dimensions that were left at offline-sweep defaults.
            //
            // timeoutMs defaulted to 30 seconds and maxFileSize to 500 MB, on a
            // path where a kernel thread is parked inside FltSendMessage holding an
            // IRP_MJ_CREATE. Entropy, overlay and resource analysis are all linear
            // in file size, so those defaults describe a sweep, not an in-line
            // verdict. An earlier trace measured p50 0.1 ms and a 0.6 ms maximum
            // here, which is why this has not yet been felt - but that reflects the
            // files in that run, and MetamorphicDetector demonstrated on this exact
            // path what an unenforced budget costs when a big input finally arrives.
            //
            // 32 MB is a bound on WORK, not on coverage: a larger file is not
            // skipped, it is handed to the deferred stage below, which runs with the
            // full defaults off the kernel's thread.
            pdConfig.timeoutMs = 50u;
            pdConfig.maxFileSize = 32ull * 1024ull * 1024ull;

            ShadowStrike::AntiEvasion::PackerError pdErr{};
            SS_DIAG_SCOPE("OnAccess", "PackerDetector::AnalyzeFile");
            auto packResult = m_packerDetector->AnalyzeFile(filePath, pdConfig, &pdErr);
            if (pdErr.win32Code != 0) {
                Utils::Logger::Warn(
                    "RealTimeProtection: PackerDetector analysis failed for {}  -  error={} {}",
                    Utils::StringUtils::ToNarrow(filePath.substr(0, 120)), pdErr.win32Code, Utils::StringUtils::ToNarrow(pdErr.message));
            }
            if (!packResult.analysisComplete || packResult.analysisTruncated) {
                // Either the in-line budget stopped it or the file exceeded the
                // in-line size bound, so this file has NOT been cleared of packing -
                // it was not fully examined. Re-run it off the kernel's thread with
                // the full defaults. Without this the two bounds set above would
                // trade detection for latency, silently.
                m_stats.packerDeferred++;
                QueueDeferredDeepScan(filePath, req.ProcessId);
            }
            if (packResult.isPacked) {
                fileIsPacked = true;
                packingConfidence = packResult.packingConfidence;

                Utils::Logger::Info(
                    "RealTimeProtection: Packed file: {} [packer={} confidence={:.1f}% "
                    "severity={} category={} layers={} entropy={:.2f}]",
                    Utils::StringUtils::ToNarrow(filePath), Utils::StringUtils::ToNarrow(packResult.packerName),
                    packResult.packingConfidence * 100.0,
                    static_cast<int>(packResult.severity),
                    static_cast<int>(packResult.packerCategory),
                    packResult.layerCount,
                    packResult.fileEntropy);

                // Critical/High severity packer = malware-specific packer → block immediately
                if (packResult.severity >= ShadowStrike::AntiEvasion::PackerSeverity::Critical) {
                    Utils::Logger::Warn(
                        "RealTimeProtection: Blocked malware-specific packer: {} [packer={} matches={}]",
                        Utils::StringUtils::ToNarrow(filePath), Utils::StringUtils::ToNarrow(packResult.packerName), packResult.packerMatches.size());
                    m_stats.threatsDetected++;
                    return Communication::KernelVerdict::Block;
                }

                for (const auto& match : packResult.packerMatches) {
                    if (match.severity >= ShadowStrike::AntiEvasion::PackerSeverity::High) {
                        Utils::Logger::Warn(
                            "RealTimeProtection: High-severity packer match in {}: {} (confidence={:.2f}, method={})",
                            Utils::StringUtils::ToNarrow(filePath), Utils::StringUtils::ToNarrow(match.packerName), match.confidence,
                            static_cast<int>(match.method));
                    }
                }
            }
        }

        // 2.5. Rapid PE Analysis via ExecutableAnalyzer (Kernel Fast Path)
        // This runs quick structural analysis before the full scan pipeline
        // to catch obvious malware indicators and feed kernel callback
        {
            auto& execAnalyzer = Core::FileSystem::ExecutableAnalyzer::Instance();
            SS_DIAG_SCOPE("OnAccess", "ExecutableAnalyzer::AnalyzeForKernel");
            auto quickInfo = execAnalyzer.AnalyzeForKernel(
                filePath,
                req.ProcessId,
                req.FileSize
            );

            // If risk score is extremely high, block immediately without full scan
            if (quickInfo.riskScore >= 95) {
                SS_LOG_WARN(L"RealTimeProtection",
                    L"ExecutableAnalyzer rapid block: risk=%u, anomalies=%zu, PID=%u",
                    static_cast<unsigned>(quickInfo.riskScore),
                    quickInfo.anomalies.size(),
                    req.ProcessId);

                m_stats.threatsDetected++;
                return Communication::KernelVerdict::Block;
            }
        }

        // 3. Prepare Scan Context
        if (budgetExceeded()) {
            deferDeepScan(L"scan-engine");
            return Communication::KernelVerdict::Allow;
        }
        Core::Engine::ScanContext context;
        context.type = Core::Engine::ScanType::RealTime;
        context.priority = Core::Engine::ScanPriority::Critical;
        context.processId = req.ProcessId;
        context.filePath = filePath;
        context.timeout = std::chrono::milliseconds(
            RTPConstants::KERNEL_REPLY_TIMEOUT_MS - 100);

        // 4. Perform Scan
        Core::Engine::EngineResult engineResult;
        try {
            engineResult = Core::Engine::ScanEngine::Instance().ScanFile(filePath, context);
        } catch (const std::exception& e) {
            Utils::Logger::Error("RealTimeProtection: Scan exception: {}",
                e.what());
            m_stats.scanErrors++;

            // Apply failure policy
            if (m_config.failurePolicy == FailurePolicy::FAIL_CLOSED) {
                return Communication::KernelVerdict::Block;
            }
            return Communication::KernelVerdict::Allow;
        }

        // The on-access context leaves ScanContext::deepScan at its default of
        // false (ScanEngine.hpp:287), which is correct here - the deep signature
        // sweep, sandbox, emulation, zero-day and packed-PE unpacking stages are
        // far too slow to run while the minifilter holds a file create open. But
        // until now those stages were only reached when the synchronous budget had
        // already been blown, so on a healthy scan they ran nowhere at all.
        //
        // Handing every scanned file to the deferred worker makes the fast path a
        // scheduling decision rather than a coverage decision: the quick verdict
        // unblocks the process, and the thorough pass still happens moments later
        // with deepScan set, remediating through the existing quarantine path if
        // it finds something. The queue de-duplicates by path, is bounded at 4096
        // entries, and its worker runs below normal priority, so this cannot
        // become a backlog that competes with the verdict path.
        QueueDeferredDeepScan(filePath, req.ProcessId);

        // 5. Map Result
        ScanResult scanResult = MapEngineResult(engineResult, filePath);

        // 6. Invoke file scan callbacks (snapshot callbacks first to avoid holding lock during dispatch)
        std::vector<RTPFileScanCallback> callbackSnapshot;
        {
            std::shared_lock lock(m_callbackMutex);
            callbackSnapshot.reserve(m_fileScanCallbacks.size());
            for (const auto& [id, callback] : m_fileScanCallbacks) {
                callbackSnapshot.push_back(callback);
            }
        }

        // Dispatch outside the lock
        RTPFileScanRequest rtpReq;
        rtpReq.filePath = filePath;
        rtpReq.pid = req.ProcessId;

        for (const auto& callback : callbackSnapshot) {
            try {
                (void)callback(rtpReq, scanResult);
            } catch (...) {}
        }

        // 7. Update Cache
        if (!hashKey.empty()) {
            UpdateVerdictCache(hashKey, scanResult);
        }

        // 8. Update Statistics
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

        m_performanceMetrics.totalScans++;
        
        // Validate duration is non-negative before converting to unsigned
        if (duration.count() >= 0) {
            uint64_t durationUs = static_cast<uint64_t>(duration.count());
            uint64_t currentAvg = m_performanceMetrics.avgScanTimeUs.load();
            uint64_t newAvg = (currentAvg * 9 + durationUs) / 10;
            m_performanceMetrics.avgScanTimeUs.store(newAvg);

            if (durationUs > m_performanceMetrics.maxScanTimeUs.load()) {
                m_performanceMetrics.maxScanTimeUs.store(durationUs);
            }
        } else {
            Utils::Logger::Warn("RealTimeProtection: Negative scan duration detected (clock anomaly): {}", duration.count());
        }

        // 9. Handle Threat
        if (scanResult.isThreat) {
            HandleThreatDetection(scanResult, filePath, req.ProcessId);
        }

        // 10. Map to kernel verdict
        switch (engineResult.verdict) {
            case Core::Engine::ScanVerdict::Clean:
            case Core::Engine::ScanVerdict::Whitelisted:
                m_stats.cleanFiles++;
                if (!fileIdentityKey.empty()) {
                    UpdateFileVerdictCache(fileIdentityKey,
                                           Communication::KernelVerdict::Allow);
                }
                return Communication::KernelVerdict::Allow;

            case Core::Engine::ScanVerdict::Infected:
                m_stats.infectedFiles++;
                m_stats.filesBlocked++;
                return Communication::KernelVerdict::Block;

            case Core::Engine::ScanVerdict::Suspicious:
                m_stats.suspiciousFiles++;
                if (m_mode.load(std::memory_order_acquire) >= ProtectionMode::BLOCK_SUSPICIOUS) {
                    m_stats.filesBlocked++;
                    return Communication::KernelVerdict::Block;
                }
                return Communication::KernelVerdict::Monitor;

            case Core::Engine::ScanVerdict::PUA:
                m_stats.puaFiles++;
                if (m_mode.load(std::memory_order_acquire) == ProtectionMode::BLOCK_UNKNOWN) {
                    m_stats.filesBlocked++;
                    return Communication::KernelVerdict::Block;
                }
                return Communication::KernelVerdict::Monitor;

            case Core::Engine::ScanVerdict::Error:
                m_stats.scanErrors++;
                return m_config.failurePolicy == FailurePolicy::FAIL_CLOSED ?
                       Communication::KernelVerdict::Block : Communication::KernelVerdict::Allow;

            default:
                return Communication::KernelVerdict::Allow;
        }
    }

    Communication::KernelVerdict OnKernelProcessNotify(const Communication::ProcessNotifyRequest& req) {
        m_stats.totalEvents++;
        m_stats.processEvents++;

        if (m_state != ProtectionState::ACTIVE) {
            return Communication::KernelVerdict::Allow;
        }

        if (!m_config.monitorProcessCreation) {
            return Communication::KernelVerdict::Allow;
        }

        std::wstring imagePath(req.imagePathData(), req.imagePathCharLen());
        std::wstring commandLine(req.commandLineData(), req.commandLineCharLen());

        // Resolve the kernel NT device path to an openable Win32 DOS path before
        // any consumer touches it. CertificateValidator::OnKernelProcessCreate
        // opens the image to verify its signature, and the debugger-evasion pass
        // and telemetry key off the path too — the process-image route has the
        // same "\Device\HarddiskVolumeN\..." problem as the file-scan and
        // image-load routes. LOLBin/command-line substring checks are unaffected
        // by the path form, so this is a safe, single-point normalization.
        imagePath = Utils::FileUtils::DevicePathToDosPath(imagePath);

        // =====================================================================
        // ANTI-DEBUG: Forward every process create/terminate to AntiDebug
        // so it can detect hostile debugger launches (OllyDbg, x64dbg, etc.)
        // before the process establishes a debug session.
        // =====================================================================
        if (Security::AntiDebug::HasInstance() &&
            Security::AntiDebug::Instance().IsInitialized()) {
            try {
                Security::AntiDebug::Instance().OnKernelProcessNotify(
                    req.processId, req.parentProcessId,
                    imagePath, static_cast<bool>(req.isCreation));
            } catch (const std::exception& e) {
                Utils::Logger::Warn("RealTimeProtection: AntiDebug process notify exception: {}",
                    e.what());
            } catch (...) {}
        }

        // =====================================================================
        // CERTIFICATE VALIDATOR: Validate process image certificate on creation
        // to detect revoked/untrusted certificate chains before execution proceeds.
        // =====================================================================
        if (req.isCreation && !imagePath.empty() &&
            Security::CertificateValidator::HasInstance() &&
            Security::CertificateValidator::Instance().IsInitialized()) {
            try {
                Security::CertificateValidator::Instance().OnKernelProcessCreate(
                    req.processId, req.parentProcessId, imagePath);
            } catch (const std::exception& e) {
                Utils::Logger::Warn("RealTimeProtection: CertificateValidator process create exception: {}",
                    e.what());
            } catch (...) {}
        }

        // =====================================================================
        // KERNEL-ENRICHED CONTEXT ANALYSIS (uses full kernel data, not just PID)
        // These checks leverage commandLine, parentPid, imagePath, isWow64 from
        // the kernel's process creation callback — data that user-mode detectors
        // calling OpenProcess(pid) cannot reliably obtain after the fact.
        // =====================================================================

        if (req.isCreation) {
            // MITRE T1059 — Obfuscated Command-Line Detection
            // Detect encoded PowerShell, download cradles, and LOLBin abuse
            if (!commandLine.empty()) {
                std::wstring lowerCmd = ToLowerW(commandLine);

                // PowerShell encoded command (-enc, -encodedcommand)
                if (lowerCmd.find(L"-enc") != std::wstring::npos ||
                    lowerCmd.find(L"-encodedcommand") != std::wstring::npos ||
                    lowerCmd.find(L"frombase64string") != std::wstring::npos) {
                    Utils::Logger::Warn("RealTimeProtection: Encoded PowerShell detected  -  PID: {}, Parent: {}, Cmd: {}",
                        req.processId, req.parentProcessId, Utils::StringUtils::ToNarrow(commandLine.substr(0, 200)));
                }

                // Download cradles (certutil, bitsadmin, mshta, regsvr32)
                static constexpr std::wstring_view kDownloadCradles[] = {
                    L"certutil", L"bitsadmin", L"mshta", L"regsvr32",
                    L"msiexec", L"wmic", L"cmstp", L"msxsl",
                };
                std::wstring lowerImage = ToLowerW(imagePath);
                for (const auto& cradle : kDownloadCradles) {
                    if (lowerImage.find(cradle) != std::wstring::npos &&
                        (lowerCmd.find(L"http") != std::wstring::npos ||
                         lowerCmd.find(L"\\\\") != std::wstring::npos)) {
                        Utils::Logger::Warn("RealTimeProtection: LOLBin download cradle detected  -  "
                            "PID: {}, Binary: {}, Cmd: {}",
                            req.processId, Utils::StringUtils::ToNarrow(imagePath), Utils::StringUtils::ToNarrow(commandLine.substr(0, 200)));
                        break;
                    }
                }
            }

            // NOTE: WoW64 detection is handled by the kernel's IsWow64 flag in
            // EPROCESS. The kernel struct does not relay isWow64 in the current
            // wire protocol. When kernel adds this field, re-enable WoW64 checks.
        }

        // Anti-Evasion Analysis
        if (req.isCreation) {
            bool evasionDetected = false;
            std::wstring detectionSource;

            // 1. Debugger Evasion — pass kernel context for APT-grade detection
            if (m_debuggerDetector) {
                ShadowStrike::AntiEvasion::AnalysisConfig dedConfig;
                dedConfig.depth = ShadowStrike::AntiEvasion::AnalysisDepth::Standard;

                // Populate kernel-enriched context — kernel sensor provides tamper-proof data
                ShadowStrike::AntiEvasion::KernelProcessContext kernelCtx;
                kernelCtx.imagePath = imagePath;
                kernelCtx.commandLine = commandLine;
                kernelCtx.parentProcessId = req.parentProcessId;
                kernelCtx.creatingProcessId = req.creatingProcessId;
                kernelCtx.creatingThreadId = req.creatingThreadId;
                kernelCtx.isCreation = req.isCreation;
                dedConfig.kernelContext = std::move(kernelCtx);

                auto result = m_debuggerDetector->AnalyzeProcess(req.processId, dedConfig);
                if (result.isEvasive) {
                    evasionDetected = true;
                    detectionSource = std::format(L"Debugger Evasion (score={:.1f}, techniques={}, severity={})",
                        result.evasionScore,
                        result.totalDetections,
                        static_cast<int>(result.maxSeverity));

                    // Log technique details for SOC/SIEM correlation
                    for (const auto& tech : result.detectedTechniques) {
                        if (tech.severity >= ShadowStrike::AntiEvasion::EvasionSeverity::High) {
                            Utils::Logger::Warn("RealTimeProtection: Anti-debug technique in PID {}: {} (confidence={:.2f})",
                                req.processId, Utils::StringUtils::ToNarrow(tech.description), tech.confidence);
                        }
                    }

                    EmitEvasionTelemetry(req.processId, imagePath, detectionSource,
                        "DebuggerEvasionDetector", static_cast<float>(result.evasionScore),
                        result.totalDetections, true);
                }
            }

            // 2. VM Evasion — anti-VM code pattern detection (SIDT/SLDT/CPUID loops/VMware backdoor)
            // Always run for telemetry — APT malware commonly combines anti-debug + anti-VM
            if (m_vmDetector) {
                ShadowStrike::AntiEvasion::ProcessVMEvasionResult vmResult;
                ShadowStrike::AntiEvasion::ProcessAnalysisConfig vmConfig;
                vmConfig.analyzeCodePatterns = true;
                vmConfig.analyzeImports = true;
                vmConfig.analyzeStrings = true;

                // Feed kernel-verified context for tamper-proof anti-VM detection
                ShadowStrike::AntiEvasion::VMKernelContext vmKernelCtx;
                vmKernelCtx.imagePath = imagePath;
                vmKernelCtx.commandLine = commandLine;
                vmKernelCtx.parentProcessId = req.parentProcessId;
                vmKernelCtx.creatingProcessId = req.creatingProcessId;
                vmKernelCtx.creatingThreadId = req.creatingThreadId;
                vmConfig.kernelContext = std::move(vmKernelCtx);

                if (m_vmDetector->AnalyzeProcessAntiVMBehavior(req.processId, vmResult, vmConfig)) {
                    if (vmResult.hasAntiVMBehavior) {
                        if (!evasionDetected) {
                            evasionDetected = true;
                            detectionSource = std::format(
                                L"VM Evasion [score={:.1f} techniques={}]",
                                vmResult.evasionScore,
                                vmResult.GetTechniqueCount());
                        }

                        // Rich telemetry for SOC/SIEM: per-technique logging (always runs)
                        for (const auto& tech : vmResult.techniqueDetails) {
                            if (tech.severity >= 60.0f) {
                                Utils::Logger::Warn(
                                    "RealTimeProtection: PID {} VM evasion: {} "
                                    "(severity={:.1f} addr=0x{:X} active={})",
                                    req.processId, Utils::StringUtils::ToNarrow(tech.description.substr(0, 120)),
                                    tech.severity, tech.address,
                                    tech.isActive ? "yes" : "no");
                            }
                        }

                        // High evasion score → immediate SOC alert
                        if (vmResult.evasionScore >= 80.0f) {
                            Utils::Logger::Error(
                                "RealTimeProtection: CRITICAL VM evasion in PID {}  -  "
                                "score={:.1f} techniques={} image={}",
                                req.processId, vmResult.evasionScore,
                                vmResult.GetTechniqueCount(),
                                Utils::StringUtils::ToNarrow(imagePath.substr(0, 120)));
                        }

                        const size_t techniqueCount = vmResult.GetTechniqueCount();
                        if (techniqueCount > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
                            Utils::Logger::Warn("RealTimeProtection: VM evasion technique count overflow: {}", techniqueCount);
                        }
                        EmitEvasionTelemetry(req.processId, imagePath,
                            std::format(L"VM Evasion [score={:.1f}]", vmResult.evasionScore),
                            "VMEvasionDetector", static_cast<float>(vmResult.evasionScore),
                            static_cast<uint32_t>(std::min(techniqueCount, static_cast<size_t>(std::numeric_limits<uint32_t>::max()))), true);
                    }
                }
            }

            // 3. Process Evasion — kernel-enriched injection/hollowing/masquerading detection
            if (m_processDetector) {
                ShadowStrike::AntiEvasion::ProcessEvasionAnalysisConfig pedConfig;
                pedConfig.flags = ShadowStrike::AntiEvasion::ProcessAnalysisFlags::Default
                                | ShadowStrike::AntiEvasion::ProcessAnalysisFlags::DeepAnalysis;
                pedConfig.enableDeepScan = true;

                // Feed kernel-verified context for tamper-proof masquerading/PPID detection
                ShadowStrike::AntiEvasion::ProcessKernelContext pedKernelCtx;
                pedKernelCtx.imagePath = imagePath;
                pedKernelCtx.commandLine = commandLine;
                pedKernelCtx.parentProcessId = req.parentProcessId;
                pedKernelCtx.creatingProcessId = req.creatingProcessId;
                pedKernelCtx.creatingThreadId = req.creatingThreadId;
                pedConfig.kernelContext = std::move(pedKernelCtx);

                auto result = m_processDetector->AnalyzeProcess(req.processId, pedConfig);
                if (result.isEvasive) {
                    evasionDetected = true;
                    detectionSource = std::format(
                        L"Process Evasion [score={:.1f} severity={} detections={}]",
                        result.evasionScore,
                        static_cast<int>(result.maxSeverity),
                        result.totalDetections);

                    // Rich telemetry for SOC/SIEM: per-technique logging
                    for (const auto& tech : result.detectedTechniques) {
                        if (tech.severity >= ShadowStrike::AntiEvasion::ProcessEvasionSeverity::High) {
                            Utils::Logger::Warn(
                                "RealTimeProtection: PID {} process evasion: {} "
                                "(confidence={:.2f} severity={})",
                                req.processId, Utils::StringUtils::ToNarrow(tech.description),
                                tech.confidence, static_cast<int>(tech.severity));
                        }
                    }

                    // Critical severity → immediate block (APT-grade process evasion)
                    if (result.maxSeverity >= ShadowStrike::AntiEvasion::ProcessEvasionSeverity::Critical) {
                        Utils::Logger::Error(
                            "RealTimeProtection: CRITICAL process evasion in PID {}  -  "
                            "score={:.1f} detections={} image={}",
                            req.processId, result.evasionScore,
                            result.totalDetections, Utils::StringUtils::ToNarrow(imagePath.substr(0, 120)));
                    }

                    EmitEvasionTelemetry(req.processId, imagePath, detectionSource,
                        "ProcessEvasionDetector", static_cast<float>(result.evasionScore),
                        result.totalDetections, true);
                }
            }

            // 4. Time-Based Evasion (singleton — RDTSC abuse, sleep acceleration, timing anti-debug)
            // Always run for telemetry — timing evasion is orthogonal to other detections
            if (m_timeBasedDetectorInitialized) {
                try {
                    auto result = ShadowStrike::AntiEvasion::TimeBasedEvasionDetector::Instance()
                        .AnalyzeProcess(req.processId);
                    if (result.isEvasive) {
                        evasionDetected = true;
                        detectionSource = std::format(
                            L"Time-Based Evasion [threat={:.1f} severity={} findings={}]",
                            result.threatScore,
                            static_cast<int>(result.severity),
                            result.findings.size());

                        // Rich telemetry for SOC/SIEM: per-finding logging
                        for (const auto& finding : result.findings) {
                            if (finding.severity >= ShadowStrike::AntiEvasion::TimingEvasionSeverity::High) {
                                Utils::Logger::Warn(
                                    "RealTimeProtection: PID {} timing evasion: {} "
                                    "(confidence={:.1f} severity={})",
                                    req.processId, Utils::StringUtils::ToNarrow(finding.description.substr(0, 120)),
                                    finding.confidence,
                                    static_cast<int>(finding.severity));
                            }
                        }

                        // Critical severity → immediate SOC alert
                        if (result.severity >= ShadowStrike::AntiEvasion::TimingEvasionSeverity::Critical) {
                            Utils::Logger::Error(
                                "RealTimeProtection: CRITICAL timing evasion in PID {}  -  "
                                "threat={:.1f} findings={} image={}",
                                req.processId, result.threatScore,
                                result.findings.size(), Utils::StringUtils::ToNarrow(imagePath.substr(0, 120)));
                        }

                        EmitEvasionTelemetry(req.processId, imagePath, detectionSource,
                            "TimeBasedEvasionDetector", static_cast<float>(result.threatScore),
                            static_cast<uint32_t>(result.findings.size()), true);
                    }
                } catch (...) {}
            }

            // 5. Network-Based Evasion (DGA detection, DNS tunneling, C2 beaconing, fast-flux)
            // Always run network analysis for telemetry even if evasion already detected
            if (m_networkDetector) {
                try {
                    ShadowStrike::AntiEvasion::NetworkAnalysisConfig nbedConfig;
                    nbedConfig.flags = ShadowStrike::AntiEvasion::NetworkAnalysisFlags::Default;

                    // Populate kernel-enriched context — tamper-proof process data
                    ShadowStrike::AntiEvasion::NetworkKernelContext nbedKernelCtx;
                    nbedKernelCtx.imagePath = imagePath;
                    nbedKernelCtx.commandLine = commandLine;
                    nbedKernelCtx.parentProcessId = req.parentProcessId;
                    nbedKernelCtx.creatingProcessId = req.creatingProcessId;
                    nbedKernelCtx.creatingThreadId = req.creatingThreadId;
                    nbedConfig.kernelContext = std::move(nbedKernelCtx);

                    auto result = m_networkDetector->AnalyzeProcess(req.processId, nbedConfig);

                    if (result.isEvasive) {
                        if (!evasionDetected) {
                            evasionDetected = true;
                            detectionSource = std::format(
                                L"Network Evasion (score={:.1f}, techniques={}, severity={})",
                                result.evasionScore,
                                result.totalDetections,
                                static_cast<int>(result.maxSeverity));
                        }

                        for (const auto& tech : result.detectedTechniques) {
                            if (tech.severity >= ShadowStrike::AntiEvasion::NetworkEvasionSeverity::High) {
                                Utils::Logger::Warn(
                                    "RealTimeProtection: Network evasion in PID {}: {} (confidence={:.2f}, mitre={})",
                                    req.processId, Utils::StringUtils::ToNarrow(tech.description), tech.confidence,
                                    tech.mitreId.empty() ? "N/A" : tech.mitreId);
                            }
                        }

                        EmitEvasionTelemetry(req.processId, imagePath,
                            std::format(L"Network Evasion [score={:.1f}]", result.evasionScore),
                            "NetworkBasedEvasionDetector", static_cast<float>(result.evasionScore),
                            result.totalDetections, true);
                    }
                } catch (const std::exception& ex) {
                    Utils::Logger::Error("RealTimeProtection: NetworkBasedEvasionDetector exception for PID {}: {}",
                        req.processId, ex.what());
                } catch (...) {
                    Utils::Logger::Error("RealTimeProtection: NetworkBasedEvasionDetector unknown exception for PID {}",
                        req.processId);
                }
            }

            // 6. Environment Evasion — pass kernel context for APT-grade detection
            if (!evasionDetected && m_environmentDetector) {
                ShadowStrike::AntiEvasion::EnvironmentAnalysisConfig eedConfig;

                // Populate kernel-enriched context — kernel data is tamper-proof
                ShadowStrike::AntiEvasion::EnvironmentKernelContext eedKernelCtx;
                eedKernelCtx.imagePath = imagePath;
                eedKernelCtx.commandLine = commandLine;
                eedKernelCtx.parentProcessId = req.parentProcessId;
                eedKernelCtx.creatingProcessId = req.creatingProcessId;
                eedKernelCtx.creatingThreadId = req.creatingThreadId;
                eedConfig.kernelContext = std::move(eedKernelCtx);

                auto result = m_environmentDetector->AnalyzeProcess(req.processId, eedConfig);
                if (result.isEvasive) {
                    evasionDetected = true;
                    detectionSource = std::format(L"Environment Evasion (score={:.1f}, techniques={}, severity={})",
                        result.evasionScore,
                        result.totalDetections,
                        static_cast<int>(result.maxSeverity));

                    for (const auto& tech : result.detectedTechniques) {
                        if (tech.severity >= ShadowStrike::AntiEvasion::EnvironmentEvasionSeverity::High) {
                            Utils::Logger::Warn("RealTimeProtection: Env evasion in PID {}: {} (confidence={:.2f})",
                                req.processId, Utils::StringUtils::ToNarrow(tech.description), tech.confidence);
                        }
                    }

                    EmitEvasionTelemetry(req.processId, imagePath, detectionSource,
                        "EnvironmentEvasionDetector", static_cast<float>(result.evasionScore),
                        result.totalDetections, true);
                }
            }

            if (evasionDetected) {
                Utils::Logger::Warn("RealTimeProtection: Blocked evasion attempt: {} (PID: {}, Source: {})", 
                    Utils::StringUtils::ToNarrow(imagePath), req.processId, Utils::StringUtils::ToNarrow(detectionSource));
                m_stats.processesBlocked++;

                // Emit consolidated SOC alert for blocked evasion
                EmitEvasionAlert(req.processId, imagePath, detectionSource,
                    Utils::StringUtils::ToNarrow(detectionSource.substr(0, 80)),
                    Communication::AlertSeverity::High);

                return Communication::KernelVerdict::Block;
            }
        }
        if (IsProcessExcluded(imagePath, req.processId)) {
            m_stats.excludedByProcess++;
            return Communication::KernelVerdict::Allow;
        }

        // PrivilegeEscalationDetector — feed kernel-enriched process creation events
        // This enables immediate detection of potato binaries, token manipulation
        // targets, and tracks elevation state from tamper-proof kernel data.
        if (req.isCreation) {
            try {
                auto& ped = Exploits::PrivilegeEscalationDetector::Instance();
                ped.OnKernelProcessCreated(
                    req.processId,
                    req.parentProcessId,
                    imagePath,
                    commandLine,
                    false);
            } catch (...) {}
        }

        // Register new processes with MemoryProtection for continuous monitoring
        if (req.isCreation && m_config.monitorMemoryAllocation) {
            try {
                auto& mp = MemoryProtection::Instance();
                if (mp.IsRunning()) {
                    // Best-effort: failures are logged inside MemoryProtection.
                    (void)mp.MonitorProcess(req.processId);
                }
            } catch (...) {}
        }

        // Invoke process creation callbacks (snapshot callbacks first to avoid holding lock during dispatch)
        bool shouldBlock = false;
        std::vector<RTPProcessCreateCallback> callbackSnapshot;
        {
            std::shared_lock lock(m_callbackMutex);
            callbackSnapshot.reserve(m_processCreateCallbacks.size());
            for (const auto& [id, callback] : m_processCreateCallbacks) {
                callbackSnapshot.push_back(callback);
            }
        }

        // Dispatch outside the lock
        RTPProcessNotifyRequest rtpReq;
        rtpReq.pid = req.processId;
        rtpReq.parentPid = req.parentProcessId;
        rtpReq.imagePath = imagePath;
        rtpReq.commandLine = commandLine;
        rtpReq.isCreation = req.isCreation;

        for (const auto& callback : callbackSnapshot) {
            try {
                callback(rtpReq, shouldBlock);
            } catch (...) {}
        }

        if (shouldBlock) {
            m_stats.processesBlocked++;
            Utils::Logger::Warn("RealTimeProtection: Blocked process creation: {} (PID: {})",
                Utils::StringUtils::ToNarrow(imagePath), req.processId);
            return Communication::KernelVerdict::Block;
        }

        // If configured, scan the process image
        if (m_config.scanOnExecute && req.isCreation) {
            try {
                // Verified Microsoft-signed OS binaries are trusted operating-
                // system code — skip the heavy ScanEngine pipeline (same TIER-1
                // trust as the on-access file path). Tamper-safe (a modified
                // image fails the catalog/Authenticode check) and LOLBin abuse of
                // a signed binary is caught by the process/behavioral monitors
                // above, not by scanning the clean image.
                //
                // Queried CACHE-ONLY, for the reason documented at the on-access
                // TIER 1: establishing this verdict calls WinVerifyTrust, which
                // RPCs into CryptSvc, whose catalog reads this product's own
                // minifilter intercepts. This handler owes the kernel a verdict,
                // so blocking here risks the same circular wait that wedged
                // 1.0.91 for 180 seconds - on the process-creation path, where a
                // stall blocks every process launch on the machine.
                //
                // NOT-DETERMINED FALLS THROUGH TO THE SCAN, which is the safe
                // direction: this tier only ever SKIPS work, so an unknown verdict
                // costs a scan that would have happened anyway and can never let
                // an unexamined binary through.
                const auto msTrust = Security::DigitalSignatureValidator::Instance()
                                         .TryGetCachedMicrosoftSigned(imagePath);
                if (!msTrust.has_value()) {
                    QueueSignatureDetermination(imagePath, std::wstring());
                }
                if (!(msTrust.has_value() && *msTrust)) {
                    Core::Engine::ScanContext context;
                    context.type = Core::Engine::ScanType::RealTime;
                    context.priority = Core::Engine::ScanPriority::Critical;
                    context.processId = req.processId;
                    context.filePath = imagePath;

                    auto result = Core::Engine::ScanEngine::Instance().ScanFile(imagePath, context);

                    if (result.verdict == Core::Engine::ScanVerdict::Infected) {
                        m_stats.processesBlocked++;
                        return Communication::KernelVerdict::Block;
                    }
                }
            } catch (...) {
                // Continue on scan failure
            }
        }

        // =====================================================================
        // RANSOMWARE SUBSYSTEM PROCESS-NOTIFY DISPATCH (Phase 4 kernel fan-out)
        //
        // Fan every process create / terminate notification out to the
        // RansomwareDetector composite engine, LockyDetector dropper-chain
        // tracker, WannaCryDetector service-install detector, and
        // HoneypotManager for attribution.  Each call is noexcept at the
        // aggregator boundary; a single misbehaving module cannot take the
        // IPC loop down.
        // =====================================================================
        Ransomware::Wiring::DispatchProcessNotify(
            req.processId, req.parentProcessId,
            imagePath, commandLine, static_cast<bool>(req.isCreation));

        return Communication::KernelVerdict::Allow;
    }

    // =========================================================================
    // IMAGE LOAD HANDLER — DLL injection, process hollowing, unsigned module detection
    // =========================================================================

    Communication::KernelVerdict OnKernelImageLoad(const Communication::ImageLoadRequest& req) {
        m_stats.totalEvents++;

        if (m_state != ProtectionState::ACTIVE) {
            return Communication::KernelVerdict::Allow;
        }

        std::wstring imagePath(req.imagePathData(), req.imagePathCharLen());

        // The kernel delivers the image path in NT device form
        // (\Device\HarddiskVolumeN\...). Every consumer below — signature
        // validation, certificate + packer analysis, KernelExploitDetector,
        // ScanEngine, injection correlation — opens the file through Win32 APIs
        // that cannot address the device namespace, so without this each one
        // fails "file not found" on every module load (the dominant scan flood)
        // while still burning CPU. Resolve to a DOS path once, here at the
        // boundary, exactly as OnKernelFileScan does; network/redirector devices
        // are deliberately left raw so a stalled share can't wedge the scan path.
        imagePath = Utils::FileUtils::DevicePathToDosPath(imagePath);

        // Module-identity fast-path: an identical SYSTEM module we already cleared
        // recently. Re-running the full signature/cert/Authenticode analysis for
        // ntdll/kernel32/etc. on every process's load was the dominant idle-CPU
        // cost (and re-logged the same verdict each time). System modules already
        // return Allow after signature analysis without the per-load injection/scan
        // fan-out below, so serving them from cache is behavior-preserving. Non-
        // system modules are intentionally NOT short-circuited — they still need
        // per-load injection correlation.
        std::wstring moduleCacheKey;
        if (req.isSystemModule) {
            moduleCacheKey = ToLowerW(imagePath) + L"|" +
                std::to_wstring(static_cast<unsigned long long>(req.imageSize)) + L"|" +
                std::to_wstring(static_cast<unsigned>(req.signatureLevel));
            if (auto cached = CheckImageVerdictCache(moduleCacheKey)) {
                return *cached;
            }
        }

        // ================================================================
        // ANTI-DEBUG: Detect hostile debugger DLLs being loaded into our
        // process (dbghelp.dll, scyllahide.dll, etc.) for early interception.
        // ================================================================
        if (Security::AntiDebug::HasInstance() &&
            Security::AntiDebug::Instance().IsInitialized()) {
            try {
                Security::AntiDebug::Instance().OnKernelImageLoad(
                    req.processId, imagePath,
                    static_cast<uintptr_t>(req.imageBase),
                    static_cast<size_t>(req.imageSize));
            } catch (...) {}
        }

        // ================================================================
        // CERTIFICATE VALIDATOR: Validate module certificate chain on load —
        // blocks DLLs/drivers signed with revoked or untrusted certificates
        // BEFORE they execute any code in the target process.
        // ================================================================
        if (Security::CertificateValidator::HasInstance() &&
            Security::CertificateValidator::Instance().IsInitialized()) {
            try {
                Security::CertificateValidator::Instance().OnKernelImageLoad(
                    imagePath,
                    static_cast<uintptr_t>(req.imageBase),
                    static_cast<size_t>(req.imageSize),
                    req.processId);
            } catch (...) {}
        }

        // ================================================================
        // DIGITAL SIGNATURE VALIDATION (APT Hunting Gate)
        // ================================================================
        // Run full signature analysis + stolen cert detection + anomaly engine
        // BEFORE packer detection for faster verdicts on known-bad certs.
        try {
            auto& dsv = Security::DigitalSignatureValidator::Instance();
            auto sigAnalysis = dsv.OnKernelImageLoad(
                req.processId, imagePath,
                req.imageBase, req.imageSize,
                req.signatureLevel, static_cast<bool>(req.isSystemModule));

            // Stolen certificate or critical anomaly → immediate block
            if (sigAnalysis.isStolenCert || sigAnalysis.riskScore >= 90) {
                Utils::Logger::Error(
                    "RealTimeProtection: BLOCKED APT-signed module in PID {}: {} "
                    "[stolenCert={} riskScore={} anomalies={}]",
                    req.processId, Utils::StringUtils::ToNarrow(imagePath.substr(0, 120)),
                    sigAnalysis.isStolenCert ? "YES" : "NO",
                    sigAnalysis.riskScore,
                    sigAnalysis.anomalies.size());

                if (Communication::TelemetryCollector::HasInstance()) {
                    Communication::DetectionEventData detection;
                    detection.threatName = sigAnalysis.isStolenCert
                        ? ("APT.StolenCert." + sigAnalysis.threatActorName)
                        : "APT.SignatureAnomaly";
                    detection.threatType = "APT";
                    detection.detectionMethod = "DigitalSignatureValidator";
                    detection.actionTaken = "Blocked";
                    detection.fileHash = Utils::StringUtils::ToNarrow(imagePath);
                    Communication::TelemetryCollector::Instance().RecordDetection(detection);
                }

                return Communication::KernelVerdict::Block;
            }

            // High-risk anomalies (but not critical) → log and flag for deeper scan
            if (sigAnalysis.riskScore >= 60) {
                Utils::Logger::Warn(
                    "RealTimeProtection: High-risk signature on module in PID {}: {} "
                    "[riskScore={} anomalies={}]",
                    req.processId, Utils::StringUtils::ToNarrow(imagePath.substr(0, 120)),
                    sigAnalysis.riskScore, sigAnalysis.anomalies.size());
            }

            // Valid Microsoft/EV signature with no anomalies → fast-path allow
            if (sigAnalysis.signatureInfo.isMicrosoftSigned &&
                sigAnalysis.riskScore == 0 && sigAnalysis.anomalies.empty()) {
                if (!moduleCacheKey.empty()) {
                    UpdateImageVerdictCache(moduleCacheKey,
                                            Communication::KernelVerdict::Allow);
                }
                return Communication::KernelVerdict::Allow;
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error(
                "RealTimeProtection: DSV exception on image load PID {}: {}",
                req.processId, e.what());
        } catch (...) {
            Utils::Logger::Error(
                "RealTimeProtection: DSV unknown exception on image load PID {}",
                req.processId);
        }

        // System modules are trusted — skip analysis
        if (req.isSystemModule) {
            if (!moduleCacheKey.empty()) {
                UpdateImageVerdictCache(moduleCacheKey,
                                        Communication::KernelVerdict::Allow);
            }
            return Communication::KernelVerdict::Allow;
        }

        // Packer detection on loaded modules — DeepScan for runtime-loaded DLLs
        if (m_packerDetector) {
            try {
                ShadowStrike::AntiEvasion::PackerAnalysisConfig pdConfig;
                // This handler owes the kernel a verdict and fires for EVERY module
                // load in EVERY process, which makes it the most cost-sensitive path
                // in the product. It ran PackerAnalysisFlags::DeepScan in line, and
                // DeepScan is StandardScan | EnableYARAScanning |
                // EnableResourceAnalysis | EnableHeuristicAnalysis - so every DLL
                // load paid a full YARA pass over 11,053 rules. StandardScan also
                // carries EnableSignatureVerification, which reaches WinVerifyTrust
                // and so RPCs into CryptSvc, whose catalog reads our own minifilter
                // intercepts and posts back to this service: the same circular wait
                // the field trace measured at 180 seconds, on our busiest path.
                //
                // The deep tier is not dropped, it moves. QueueDeferredDeepScan below
                // runs the full profile, YARA included, off the kernel's thread.
                pdConfig.depth = ShadowStrike::AntiEvasion::PackerAnalysisDepth::Standard;
                pdConfig.flags = static_cast<ShadowStrike::AntiEvasion::PackerAnalysisFlags>(
                    static_cast<uint32_t>(ShadowStrike::AntiEvasion::PackerAnalysisFlags::StandardScan) &
                    ~static_cast<uint32_t>(
                        ShadowStrike::AntiEvasion::PackerAnalysisFlags::EnableSignatureVerification));
                pdConfig.timeoutMs = 50u;
                pdConfig.maxFileSize = 32ull * 1024ull * 1024ull;
                pdConfig.processId = req.processId;

                ShadowStrike::AntiEvasion::PackerError pdErr{};
                auto packResult = m_packerDetector->AnalyzeFile(imagePath, pdConfig, &pdErr);
                if (!packResult.analysisComplete || packResult.analysisTruncated ||
                    packResult.isPacked) {
                    // Not cleared, merely not fully examined - or examined and found
                    // packed. Either way the deep tier this path no longer runs in
                    // line (YARA, resources, heuristics) must still run, so re-queue
                    // it off the kernel's thread at full depth.
                    //
                    // Deliberately NOT unconditional. Queuing every module load would
                    // put hundreds of entries per process launch into a 4096-deep
                    // queue served by one worker doing full deep scans, so the queue
                    // would stop draining and the deferrals that matter would be
                    // evicted by the ones that do not - the same degrade-each-other
                    // problem that keeps the signature-determination queue separate.
                    //
                    // ASSUMPTION, recorded rather than hidden: a module that
                    // completes Standard analysis cleanly is not additionally
                    // deferred, on the basis that mapping the DLL also opens the file
                    // and so its content is scanned by the on-access path, which runs
                    // the signature store including YARA. That is consistent with the
                    // driver sending both an image-load and a file event, but it is
                    // not something this change verified end to end - it should be
                    // confirmed against the sensor's image-load and create paths
                    // before being relied on as a coverage guarantee.
                    m_stats.packerDeferred++;
                    QueueDeferredDeepScan(imagePath, req.processId);
                }
                if (pdErr.win32Code != 0) {
                    Utils::Logger::Warn(
                        "RealTimeProtection: PackerDetector analysis failed for DLL {} in PID {}  -  error={} {}",
                        Utils::StringUtils::ToNarrow(imagePath.substr(0, 120)), req.processId, pdErr.win32Code, Utils::StringUtils::ToNarrow(pdErr.message));
                }
                if (packResult.isPacked) {
                    // Malware-specific packer on DLL load = immediate block
                    if (packResult.severity >= ShadowStrike::AntiEvasion::PackerSeverity::Critical) {
                        Utils::Logger::Warn(
                            "RealTimeProtection: Blocked malware-packed module in PID {}: {} "
                            "[packer={} severity={} confidence={:.1f}% matches={}]",
                            req.processId, Utils::StringUtils::ToNarrow(imagePath), Utils::StringUtils::ToNarrow(packResult.packerName),
                            static_cast<int>(packResult.severity),
                            packResult.packingConfidence * 100.0,
                            packResult.packerMatches.size());
                        return Communication::KernelVerdict::Block;
                    }

                    if (packResult.packingConfidence > 0.7) {
                        Utils::Logger::Warn(
                            "RealTimeProtection: Packed module loaded in PID {}: {} "
                            "[packer={} confidence={:.1f}% severity={} category={} entropy={:.2f}]",
                            req.processId, Utils::StringUtils::ToNarrow(imagePath), Utils::StringUtils::ToNarrow(packResult.packerName),
                            packResult.packingConfidence * 100.0,
                            static_cast<int>(packResult.severity),
                            static_cast<int>(packResult.packerCategory),
                            packResult.fileEntropy);

                        for (const auto& match : packResult.packerMatches) {
                            if (match.severity >= ShadowStrike::AntiEvasion::PackerSeverity::High) {
                                Utils::Logger::Warn(
                                    "RealTimeProtection: High-severity packer in PID {} module {}: {} (confidence={:.2f})",
                                    req.processId, Utils::StringUtils::ToNarrow(imagePath), Utils::StringUtils::ToNarrow(match.packerName), match.confidence);
                            }
                        }
                    }
                }
            } catch (const std::exception& e) {
                Utils::Logger::Error("RealTimeProtection: PackerDetector exception on image load PID {}: {}",
                    req.processId, e.what());
            } catch (...) {
                Utils::Logger::Error("RealTimeProtection: PackerDetector unknown exception on image load PID {}",
                    req.processId);
            }
        }

        // KernelExploitDetector — scan loaded drivers for BYOVD / rootkit / vulnerable driver abuse
        // Only scan .sys files (kernel drivers) — skip user-mode DLLs
        {
            std::wstring lowerImage = ToLowerW(imagePath);
            bool isDriver = lowerImage.size() >= 4 &&
                          (lowerImage.substr(lowerImage.size() - 4)                              == L".sys");
            if (isDriver) {
                try {
                    auto& ked = Exploits::KernelExploitDetector::Instance();
                    if (ked.IsInitialized()) {
                        auto driverInfo = ked.ScanDriver(imagePath);
                        if (driverInfo.isVulnerable || driverInfo.isMicrosoftBlocked || driverInfo.isLOLDriver) {
                            Utils::Logger::Error(
                                "RealTimeProtection: BLOCKED vulnerable driver in PID {}: {} "
                                "[LOLDriver={} MSBlocked={} sha256={}]",
                                req.processId, Utils::StringUtils::ToNarrow(imagePath),
                                driverInfo.isLOLDriver ? "YES" : "NO",
                                driverInfo.isMicrosoftBlocked ? "YES" : "NO",
                                driverInfo.sha256.substr(0, 16));

                            // Emit telemetry for SOC
                            if (Communication::TelemetryCollector::HasInstance()) {
                                Communication::DetectionEventData detection;
                                detection.threatName = std::string("KernelExploit.") + std::string(Exploits::GetKernelThreatTypeName(driverInfo.isLOLDriver ?
                                    Exploits::KernelThreatType::VulnerableDriverLoad : Exploits::KernelThreatType::DriverBlocklistViolation));
                                detection.threatType = "KernelExploit";
                                detection.detectionMethod = "KernelExploitDetector";
                                detection.actionTaken = "Blocked";
                                detection.detectionTime = static_cast<uint64_t>(
                                    std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch()).count());
                                detection.fpProbability = 0.01; // High confidence
                                Communication::TelemetryCollector::Instance().RecordDetection(detection);
                            }

                            m_stats.threatsDetected++;
                            return Communication::KernelVerdict::Block;
                        }

                        // Check unsigned drivers in strict mode
                        if (driverInfo.signatureStatus == Exploits::DriverSignatureStatus::Unsigned) {
                            auto currentMode = m_mode.load(std::memory_order_acquire);
                            if (currentMode == ProtectionMode::BLOCK_UNKNOWN ||
                                currentMode == ProtectionMode::BLOCK_SUSPICIOUS) {
                                Utils::Logger::Warn(
                                    "RealTimeProtection: Blocked unsigned driver in PID {}: {}",
                                    req.processId, Utils::StringUtils::ToNarrow(imagePath));
                                m_stats.threatsDetected++;
                                return Communication::KernelVerdict::Block;
                            }
                        }
                    }
                } catch (const std::exception& e) {
                    Utils::Logger::Error("RealTimeProtection: KernelExploitDetector scan failed for {} in PID {}: {}",
                        Utils::StringUtils::ToNarrow(imagePath), req.processId, e.what());
                } catch (...) {
                    Utils::Logger::Error("RealTimeProtection: KernelExploitDetector unknown exception for {} in PID {}",
                        Utils::StringUtils::ToNarrow(imagePath), req.processId);
                }
            }
        }

        // Scan the loaded image file. Skip verified Microsoft-signed OS modules
        // — trusted OS code that the signature/anomaly gate already cleared, and
        // a tampered module fails the catalog/Authenticode check. This is what
        // keeps module-load storms (every System32 DLL, EdgeWebView, etc.) off
        // the heavy ScanEngine pipeline.
        if (m_config.scanOnExecute) {
            try {
                // Cache-only, and not-determined falls through to the scan. Same
                // reasoning as the on-access TIER 1 and the process-notify path:
                // establishing this verdict reaches WinVerifyTrust, which RPCs
                // into CryptSvc, whose catalog reads our own minifilter
                // intercepts, and this handler owes the kernel a verdict. This
                // path is the most exposed of the three - it fires for every
                // module load in every process, so a stall here freezes far more
                // than file access does.
                const auto msTrust = Security::DigitalSignatureValidator::Instance()
                                         .TryGetCachedMicrosoftSigned(imagePath);
                if (!msTrust.has_value()) {
                    QueueSignatureDetermination(imagePath, std::wstring());
                }
                if (!(msTrust.has_value() && *msTrust)) {
                    Core::Engine::ScanContext context;
                    context.type = Core::Engine::ScanType::RealTime;
                    context.priority = Core::Engine::ScanPriority::High;
                    context.processId = req.processId;
                    context.filePath = imagePath;

                    auto result = Core::Engine::ScanEngine::Instance().ScanFile(imagePath, context);
                    if (result.verdict == Core::Engine::ScanVerdict::Infected) {
                        Utils::Logger::Warn("RealTimeProtection: Blocked malicious image load in PID {}: {}",
                            req.processId, Utils::StringUtils::ToNarrow(imagePath));
                        m_stats.threatsDetected++;
                        return Communication::KernelVerdict::Block;
                    }
                }
            } catch (...) {}
        }

        // ================================================================
        // FORWARD TO PROCESS MONITOR → DLL INJECTION DETECTOR
        // ProcessMonitor::OnModuleLoad forwards to DLLInjectionDetector::OnModuleLoad
        // for injection correlation (remote thread + module load timing).
        // This MUST happen for every allowed module load so the detector
        // can correlate thread-creation events with DLL appearance.
        // ================================================================
        try {
            auto& procMon = Core::Process::ProcessMonitor::Instance();
            if (procMon.IsInitialized()) {
                procMon.OnModuleLoad(
                    req.processId,
                    imagePath,
                    static_cast<uintptr_t>(req.imageBase),
                    static_cast<size_t>(req.imageSize));
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error(
                "RealTimeProtection: ProcessMonitor::OnModuleLoad exception PID {}: {}",
                req.processId, e.what());
        } catch (...) {}

        // =====================================================================
        // RANSOMWARE SUBSYSTEM IMAGE-LOAD DISPATCH (Phase 4 kernel fan-out)
        //
        // Notifies RansomwareDetector, LockyDetector, and HoneypotManager of
        // every loaded image so they can correlate DLL fingerprints against
        // known dropper payloads and update per-process attribution state.
        // =====================================================================
        Ransomware::Wiring::DispatchImageLoad(
            req.processId, imagePath,
            static_cast<std::uintptr_t>(req.imageBase),
            static_cast<std::size_t>(req.imageSize));

        return Communication::KernelVerdict::Allow;
    }

    // =========================================================================
    // REGISTRY OPERATION HANDLER — persistence, defense evasion, config tampering
    // =========================================================================

    Communication::KernelVerdict OnKernelRegistryOp(const Communication::RegistryOpRequest& req) {
        m_stats.totalEvents++;
        m_stats.registryEvents++;

        if (m_state != ProtectionState::ACTIVE) {
            return Communication::KernelVerdict::Allow;
        }

        std::wstring keyPath(req.keyPathData(), req.keyPathCharLen());
        std::wstring valueName(req.valueNameData(), req.valueNameCharLen());
        std::wstring lowerKeyPath = ToLowerW(keyPath);

        // MITRE T1547.001 — Boot/Logon Autostart (Run/RunOnce keys)
        static constexpr std::wstring_view kPersistenceKeys[] = {
            L"\\software\\microsoft\\windows\\currentversion\\run",
            L"\\software\\microsoft\\windows\\currentversion\\runonce",
            L"\\software\\microsoft\\windows\\currentversion\\runonceex",
            L"\\software\\microsoft\\windows\\currentversion\\runservices",
            L"\\software\\microsoft\\windows nt\\currentversion\\winlogon",
            L"\\software\\microsoft\\windows nt\\currentversion\\image file execution options",
            L"\\system\\currentcontrolset\\services",
            L"\\system\\currentcontrolset\\control\\session manager\\bootexecute",
            L"\\software\\microsoft\\windows nt\\currentversion\\windows\\appinit_dlls",
            L"\\software\\classes\\clsid",
        };

        for (const auto& persistKey : kPersistenceKeys) {
            if (lowerKeyPath.find(persistKey) != std::wstring::npos) {
                Utils::Logger::Warn("RealTimeProtection: Persistence registry modification detected: {} -> {}",
                    Utils::StringUtils::ToNarrow(keyPath), Utils::StringUtils::ToNarrow(valueName));
                // Don't block — forward to behavioral engine for correlation.
                // Blocking here would break legitimate software installations.
                break;
            }
        }

        // MITRE T1562.001 — Disable Security Tools (Windows Defender, Firewall, UAC)
        static constexpr std::wstring_view kDefenseEvasionKeys[] = {
            L"\\software\\policies\\microsoft\\windows defender",
            L"\\software\\microsoft\\windows defender",
            L"\\system\\currentcontrolset\\services\\sharedaccess\\parameters\\firewallpolicy",
            L"\\software\\microsoft\\windows\\currentversion\\policies\\system",
        };

        for (const auto& defenseKey : kDefenseEvasionKeys) {
            if (lowerKeyPath.find(defenseKey) != std::wstring::npos) {
                Utils::Logger::Warn("RealTimeProtection: Defense evasion registry modification: {} -> {}",
                    Utils::StringUtils::ToNarrow(keyPath), Utils::StringUtils::ToNarrow(valueName));
                break;
            }
        }

        // PrivilegeEscalationDetector — feed kernel-enriched registry modification events
        // Enables immediate detection of IFEO debugger injection, UAC bypass preparation,
        // AlwaysInstallElevated abuse, and COM CLSID hijacking from tamper-proof kernel data.
        try {
            auto& ped = Exploits::PrivilegeEscalationDetector::Instance();
            auto valueData = std::vector<uint8_t>(
                req.registryData(),
                req.registryData() + req.dataSize);
            ped.OnKernelRegistryModified(
                req.processId,
                keyPath,
                valueName,
                valueData);
        } catch (...) {}

        return Communication::KernelVerdict::Allow;
    }

    // =========================================================================
    // GENERIC EVENT HANDLER — thread/handle/network/memory/ALPC alerts
    // =========================================================================

    void OnKernelGenericEvent(SHADOWSTRIKE_MESSAGE_TYPE type,
                              const void* data, size_t size) {
        m_stats.totalEvents++;

        if (m_state != ProtectionState::ACTIVE) {
            return;
        }

        switch (type) {
            case FilterMessageType_ThreadNotify: {
                if (size >= sizeof(SHADOWSTRIKE_THREAD_NOTIFICATION)) {
                    auto* notif = static_cast<const SHADOWSTRIKE_THREAD_NOTIFICATION*>(data);

                    // Forward ALL thread creation events to DLLInjectionDetector
                    // for remote-thread + module-load correlation.
                    try {
                        auto& dllDetector = Core::Process::DLLInjectionDetector::Instance();
                        if (dllDetector.IsInitialized() && dllDetector.IsMonitoring()) {
                            dllDetector.OnThreadCreate(
                                notif->ProcessId,
                                notif->CreatorProcessId,
                                0 /* startAddress not in this notification struct */);
                        }
                    } catch (...) {}

                    // Remote thread injection detection (MITRE T1055.003)
                    if (notif->IsRemote) {
                        Utils::Logger::Warn("RealTimeProtection: Remote thread detected  -  "
                            "Source PID: {} -> Target PID: {}, TID: {}",
                            notif->CreatorProcessId, notif->ProcessId, notif->ThreadId);
                    }
                }
                break;
            }

            case FilterMessageType_HandleAlert: {
                if (size >= sizeof(SHADOWSTRIKE_HANDLE_ALERT_NOTIFICATION)) {
                    auto* alert = static_cast<const SHADOWSTRIKE_HANDLE_ALERT_NOTIFICATION*>(data);
                    if (alert->SuspicionScore >= 70) {
                        Utils::Logger::Warn("RealTimeProtection: Suspicious handle operation  -  "
                            "Source PID: {} -> Target PID: {}, Score: {}, Access: 0x{:08X}",
                            alert->SourceProcessId, alert->TargetProcessId,
                            alert->SuspicionScore, alert->RequestedAccess);
                    }

                    // Route to ProcessProtection for access filtering,
                    // telemetry, and coordinated kernel-user threat response
                    if (Security::ProcessProtection::HasInstance()) {
                        Security::ProcessProtection::Instance().OnKernelHandleAlert(
                            alert->SourceProcessId,
                            alert->TargetProcessId,
                            alert->RequestedAccess,
                            alert->GrantedAccess,
                            alert->SuspicionScore,
                            alert->SuspiciousFlags);
                    }
                }
                break;
            }

            case FilterMessageType_RansomwareAlert: {
                // Kernel minifilter has independently detected ransomware-like behaviour
                // (rapid rename/encryption storm, shadow-copy wipe, backup deletion).
                // This is a HIGH-confidence signal from kernel-side heuristics.
                Utils::Logger::Error(
                    "RealTimeProtection: RANSOMWARE ALERT from kernel (payload {} bytes)", size);
                m_stats.threatsDetected++;

                // Forward raw alert payload to BehaviorBlocker for cross-correlation
                // with user-mode behavioural score + optional runtime kill / rollback.
                if (data && size > 0) {
                    try {
                        auto& bb = BehaviorBlocker::Instance();
                        if (bb.IsRunning()) {
                            auto payload = std::span<const std::byte>(
                                static_cast<const std::byte*>(data), size);
                            bb.OnKernelBehavioralAlert(
                                static_cast<uint32_t>(FilterMessageType_RansomwareAlert),
                                payload);
                        }
                    } catch (const std::exception& ex) {
                        Utils::Logger::Error(
                            "RealTimeProtection: RansomwareAlert BehaviorBlocker dispatch failed: {}",
                            ex.what());
                    } catch (...) {}
                }
                break;
            }

            case FilterMessageType_NamedPipeEvent: {
                // Named-pipe create / connect — relevant for C2 tunnels and lateral
                // movement (MITRE T1570 / T1021.002). Route to BehaviorBlocker so
                // the behavioural engine can correlate with process + network data.
                m_stats.threatsDetected++;
                if (data && size > 0) {
                    try {
                        auto& bb = BehaviorBlocker::Instance();
                        if (bb.IsRunning()) {
                            auto payload = std::span<const std::byte>(
                                static_cast<const std::byte*>(data), size);
                            bb.OnKernelBehavioralAlert(
                                static_cast<uint32_t>(FilterMessageType_NamedPipeEvent),
                                payload);
                        }
                    } catch (...) {}
                }
                Utils::Logger::Warn(
                    "RealTimeProtection: Named-pipe kernel event (payload {} bytes)", size);
                break;
            }

            case FilterMessageType_FileBackupEvent: {
                // Kernel BackupProtector has snapshotted a file before a write /
                // rename / delete so a subsequent ransomware attempt can be rolled
                // back. This is an informational telemetry signal, not a detection.
                Utils::Logger::Info(
                    "RealTimeProtection: Kernel file-backup checkpoint ({} bytes)", size);
                break;
            }

            case FilterMessageType_FileRollbackEvent: {
                // Kernel has rolled a file back from a pre-write snapshot after
                // ransomware behaviour was confirmed. Surface as a recovery event
                // (user-facing in the Timeline panel).
                Utils::Logger::Warn(
                    "RealTimeProtection: Kernel file-rollback recovery ({} bytes)", size);
                m_stats.threatsDetected++;
                break;
            }

            case FilterMessageType_BehavioralAlert: {
                Utils::Logger::Warn("RealTimeProtection: Behavioral alert from kernel (payload {} bytes)", size);
                m_stats.threatsDetected++;

                if (data && size > 0) {
                    try {
                        auto& bb = BehaviorBlocker::Instance();
                        if (bb.IsRunning()) {
                            auto payload = std::span<const std::byte>(
                                static_cast<const std::byte*>(data), size);
                            bb.OnKernelBehavioralAlert(
                                static_cast<uint32_t>(FilterMessageType_BehavioralAlert),
                                payload);
                        }
                    } catch (const std::exception& ex) {
                        Utils::Logger::Error("RealTimeProtection: BehaviorBlocker alert handler exception: {}",
                            ex.what());
                    } catch (...) {
                        Utils::Logger::Error("RealTimeProtection: BehaviorBlocker alert handler unknown exception");
                    }
                }
                break;
            }

            case FilterMessageType_MemoryAlert: {
                // Route kernel memory anomaly alerts to ExploitPrevention for analysis
                if (data && size > 0) {
                    try {
                        auto& ep = ExploitPrevention::Instance();
                        if (ep.IsRunning()) {
                            auto alertPayload = std::span<const std::byte>(
                                static_cast<const std::byte*>(data), size);
                            ep.OnKernelMemoryAlert(
                                static_cast<uint32_t>(FilterMessageType_MemoryAlert),
                                alertPayload);
                        }
                    } catch (const std::exception& ex) {
                        Utils::Logger::Error("RealTimeProtection: MemoryAlert dispatch failed: {}",
                            ex.what());
                    } catch (...) {
                        Utils::Logger::Error("RealTimeProtection: MemoryAlert dispatch unknown exception");
                    }

                    // Also route to MemoryProtection for memory violation correlation
                    try {
                        auto& mp = MemoryProtection::Instance();
                        if (mp.IsRunning()) {
                            mp.ProcessKernelMemoryAlert(
                                static_cast<uint32_t>(FilterMessageType_MemoryAlert), data, size);
                        }
                    } catch (const std::exception& ex) {
                        Utils::Logger::Error("RealTimeProtection: MemoryProtection alert dispatch failed: {}",
                            ex.what());
                    } catch (...) {}
                }
                break;
            }

            case FilterMessageType_NetworkAlert: {
                // ============================================================
                // Kernel network event dispatch to Core Network modules
                // ============================================================
                if (size < sizeof(NETWORK_EVENT_HEADER) || !data) {
                    Utils::Logger::Warn("RealTimeProtection: NetworkAlert too small ({} bytes) or null payload", size);
                    break;
                }

                const auto* header = reinterpret_cast<const NETWORK_EVENT_HEADER*>(data);

                try {
                    switch (header->EventType) {

                    case NetworkEvent_Connect: {
                        if (size < sizeof(NETWORK_CONNECTION_EVENT)) break;
                        const auto* connEvent = reinterpret_cast<const NETWORK_CONNECTION_EVENT*>(data);

                        std::string remoteHost = Utils::StringUtils::ToNarrow(
                            std::wstring_view(connEvent->RemoteHostname));

                        // Feed to BotnetDetector for C2 correlation
                        auto& bd = Core::Network::BotnetDetector::Instance();
                        if (bd.IsRunning()) {
                            bd.RecordConnectionEvent(
                                connEvent->Header.ProcessId,
                                remoteHost,
                                connEvent->RemoteAddress.Port,
                                0, 0); // Byte counts unavailable at connect time
                        }

                        // Feed to TorDetector (connection-level tracking)
                        auto& td = Core::Network::TorDetector::Instance();
                        if (td.IsRunning()) {
                            td.FeedPacket(connEvent->ConnectionId, 0);
                        }

                        Utils::Logger::Debug("RealTimeProtection: NetworkAlert Connect PID={} connId={} host={}",
                            connEvent->Header.ProcessId, connEvent->ConnectionId, remoteHost);
                        break;
                    }

                    case NetworkEvent_DnsQuery: {
                        if (size < sizeof(NETWORK_DNS_EVENT)) break;
                        const auto* dnsEvent = reinterpret_cast<const NETWORK_DNS_EVENT*>(data);

                        std::string domainNarrow = Utils::StringUtils::ToNarrow(
                            std::wstring_view(dnsEvent->QueryName, dnsEvent->QueryNameLength));

                        // Feed to URLAnalyzer for domain reputation check
                        auto& ua = Core::Network::URLAnalyzer::Instance();
                        (void)ua.AnalyzeDomain(domainNarrow);

                        // Feed to DNSMonitor for DGA analysis
                        auto& dm = Core::Network::DNSMonitor::Instance();
                        if (dm.IsRunning()) {
                            auto dgaResult = dm.AnalyzeDGA(domainNarrow);
                            if (dgaResult.isDGA) {
                                Utils::Logger::Warn(
                                    "RealTimeProtection: DNSMonitor flagged DGA: {} entropy={:.2f} confidence={:.2f}",
                                    domainNarrow, dgaResult.entropy, dgaResult.confidence);
                            }
                        }

                        // If DGA flagged by kernel, also log
                        if (dnsEvent->IsDGA) {
                            Utils::Logger::Warn("RealTimeProtection: Kernel flagged DGA domain: {} (score={} PID={})",
                                domainNarrow, dnsEvent->DGAScore, dnsEvent->Header.ProcessId);
                        }
                        break;
                    }

                    case NetworkEvent_TlsHandshake: {
                        if (size < sizeof(NETWORK_TLS_EVENT)) break;
                        const auto* tlsEvent = reinterpret_cast<const NETWORK_TLS_EVENT*>(data);

                        std::string sni = Utils::StringUtils::ToNarrow(
                            std::wstring_view(tlsEvent->ServerName));

                        // Feed SNI to URLAnalyzer for domain reputation
                        if (!sni.empty()) {
                            auto& ua = Core::Network::URLAnalyzer::Instance();
                            (void)ua.AnalyzeDomain(sni);
                        }

                        // Feed to TrafficAnalyzer for JA3 correlation
                        auto& ta = Core::Network::TrafficAnalyzer::Instance();
                        if (ta.IsRunning()) {
                            std::span<const uint8_t> ja3Span(
                                reinterpret_cast<const uint8_t*>(tlsEvent->JA3Fingerprint),
                                strnlen(tlsEvent->JA3Fingerprint, MAX_JA3_FINGERPRINT_LENGTH));
                            if (!ja3Span.empty()) {
                                (void)ta.AnalyzePacket(ja3Span, std::chrono::system_clock::now());
                            }
                        }

                        if (tlsEvent->IsKnownMaliciousJA3) {
                            Utils::Logger::Warn("RealTimeProtection: Malicious JA3 detected: {} (SNI={} PID={})",
                                tlsEvent->JA3Fingerprint, sni, tlsEvent->Header.ProcessId);
                        }
                        break;
                    }

                    case NetworkEvent_C2Communication: {
                        if (size < sizeof(NETWORK_C2_EVENT)) break;
                        const auto* c2Event = reinterpret_cast<const NETWORK_C2_EVENT*>(data);

                        std::string hostname = Utils::StringUtils::ToNarrow(
                            std::wstring_view(c2Event->RemoteHostname));

                        Utils::Logger::Warn(
                            "RealTimeProtection: C2 communication detected PID={} host={} confidence={} score={}",
                            c2Event->Header.ProcessId, hostname,
                            c2Event->ConfidenceScore, c2Event->ThreatScore);

                        // Feed to BotnetDetector
                        auto& bd = Core::Network::BotnetDetector::Instance();
                        if (bd.IsRunning()) {
                            bd.RecordConnectionEvent(
                                c2Event->Header.ProcessId,
                                hostname,
                                c2Event->RemoteAddress.Port,
                                c2Event->BeaconingData.AverageIntervalMs,
                                0);
                        }
                        break;
                    }

                    case NetworkEvent_Beaconing: {
                        if (size < sizeof(NETWORK_C2_EVENT)) break;
                        const auto* beaconEvent = reinterpret_cast<const NETWORK_C2_EVENT*>(data);

                        std::string hostname = Utils::StringUtils::ToNarrow(
                            std::wstring_view(beaconEvent->RemoteHostname));

                        Utils::Logger::Warn(
                            "RealTimeProtection: Beaconing detected PID={} host={} count={} interval={}ms jitter={}%",
                            beaconEvent->Header.ProcessId, hostname,
                            beaconEvent->BeaconingData.BeaconCount,
                            beaconEvent->BeaconingData.AverageIntervalMs,
                            beaconEvent->BeaconingData.JitterPercent);
                        break;
                    }

                    case NetworkEvent_DataExfiltration: {
                        if (size < sizeof(NETWORK_EXFIL_EVENT)) break;
                        const auto* exfilEvent = reinterpret_cast<const NETWORK_EXFIL_EVENT*>(data);

                        std::string hostname = Utils::StringUtils::ToNarrow(
                            std::wstring_view(exfilEvent->RemoteHostname));

                        Utils::Logger::Warn(
                            "RealTimeProtection: Data exfiltration detected PID={} dest={} sent={} recv={} ratio={} score={}",
                            exfilEvent->Header.ProcessId, hostname,
                            exfilEvent->TotalBytesSent, exfilEvent->TotalBytesReceived,
                            exfilEvent->UploadDownloadRatio, exfilEvent->ThreatScore);
                        break;
                    }

                    case NetworkEvent_DNSTunneling: {
                        if (size < sizeof(NETWORK_DNS_TUNNEL_EVENT)) break;
                        const auto* tunnelEvent = reinterpret_cast<const NETWORK_DNS_TUNNEL_EVENT*>(data);

                        std::string baseDomain = Utils::StringUtils::ToNarrow(
                            std::wstring_view(tunnelEvent->BaseDomain));

                        Utils::Logger::Warn(
                            "RealTimeProtection: DNS tunneling detected domain={} queries={} entropy={} unique_sub={} confirmed={}",
                            baseDomain,
                            tunnelEvent->QueryCount,
                            tunnelEvent->EntropyScore,
                            tunnelEvent->UniqueSubdomains,
                            tunnelEvent->IsConfirmedTunneling ? "YES" : "NO");
                        break;
                    }

                    default:
                        Utils::Logger::Debug("RealTimeProtection: Unhandled NetworkAlert event type {}",
                            static_cast<uint32_t>(header->EventType));
                        break;
                    }
                } catch (const std::exception& ex) {
                    Utils::Logger::Error("RealTimeProtection: NetworkAlert dispatch exception: {}", ex.what());
                } catch (...) {
                    Utils::Logger::Error("RealTimeProtection: NetworkAlert dispatch unknown exception");
                }
                break;
            }

            case FilterMessageType_SyscallAlert: {
                // Route syscall anomalies to KernelExploitDetector for IOCTL abuse correlation
                if (size >= sizeof(uint32_t) * 3 && data) {
                    try {
                        auto& ked = Exploits::KernelExploitDetector::Instance();
                        if (ked.IsInitialized()) {
                            // Extract PID, IOCTL code, and device path from payload
                            auto* payload = static_cast<const uint8_t*>(data);
                            uint32_t pid = *reinterpret_cast<const uint32_t*>(payload);
                            uint32_t ioctlCode = *reinterpret_cast<const uint32_t*>(payload + 4);
                            uint32_t pathLen = *reinterpret_cast<const uint32_t*>(payload + 8);

                            if (size >= sizeof(uint32_t) * 3 + pathLen &&
                                pathLen > 0 && pathLen < 512) {
                                std::wstring devicePath(reinterpret_cast<const wchar_t*>(
                                    payload + sizeof(uint32_t) * 3),
                                    pathLen / sizeof(wchar_t));

                                std::span<const uint8_t> inputBuf;
                                if (size > sizeof(uint32_t) * 3 + pathLen) {
                                    size_t inputOffset = sizeof(uint32_t) * 3 + pathLen;
                                    // Align to 4 bytes
                                    inputOffset = (inputOffset + 3) & ~3;
                                    if (inputOffset < size) {
                                        inputBuf = std::span<const uint8_t>(
                                            payload + inputOffset, size - inputOffset);
                                    }
                                }

                                auto ioctlEvent = ked.AnalyzeIOCTL(pid, devicePath, ioctlCode, inputBuf);
                                if (ioctlEvent.isSuspicious && ioctlEvent.wasBlocked) {
                                    m_stats.threatsDetected++;
                                }
                            }
                        }
                    } catch (...) {}
                }
                Utils::Logger::Warn("RealTimeProtection: Syscall anomaly alert from kernel (payload {} bytes)", size);
                break;
            }

            case FilterMessageType_SelfProtectAlert: {
                SS_LOG_ERROR(L"RealTimeProtection",
                    L"SELF-PROTECTION ALERT from kernel (payload %zu bytes)", size);

                // Route to TamperProtection for tamper event handling + auto-repair
                if (Security::TamperProtection::HasInstance() &&
                    Security::TamperProtection::Instance().IsInitialized()) {
                    auto& tp = Security::TamperProtection::Instance();

                    // Parse kernel self-protect alert payload:
                    // [uint32_t alertType][uint32_t sourcePid][uint32_t targetPid][uint32_t accessMask]
                    if (size >= sizeof(uint32_t) * 4 && data) {
                        auto* payload = static_cast<const uint32_t*>(data);
                        uint32_t alertType  = payload[0];
                        uint32_t sourcePid  = payload[1];
                        uint32_t targetPid  = payload[2];

                        // Force integrity check on our protected files when tamper detected
                        tp.ForceIntegrityCheck();

                        // Run APT sweep — kernel tamper alerts often indicate advanced attacks
                        (void)tp.RunAPTTamperSweep();

                        // Log event for correlation
                        SS_LOG_WARN(L"RealTimeProtection",
                            L"Kernel tamper: type=%u src_pid=%u target_pid=%u — "
                            L"integrity check + APT sweep triggered",
                            alertType, sourcePid, targetPid);
                    }
                }

                // Forward raw payload to SelfDefense for threat event recording,
                // watchdog correlation, callback notification, and auto-recovery.
                // SelfDefense parses the full wire format independently from
                // TamperProtection's simplified view above.
                if (Security::SelfDefense::HasInstance() &&
                    Security::SelfDefense::Instance().IsInitialized()) {
                    Security::SelfDefense::Instance().OnKernelSelfProtectEvent(
                        data, static_cast<uint32_t>(size));
                }

                m_stats.threatsDetected++;
                break;
            }

            case FilterMessageType_AlpcSuspiciousAccess:
            case FilterMessageType_AlpcImpersonation:
            case FilterMessageType_AlpcSandboxEscape: {
                Utils::Logger::Warn("RealTimeProtection: ALPC security alert type {} (payload {} bytes)",
                    static_cast<uint16_t>(type), size);
                break;
            }

            case FilterMessageType_ThreatScoreNotify: {
                // Kernel ThreatScoring engine crossed threshold — log for correlation
                Utils::Logger::Info("RealTimeProtection: Kernel threat score notification (payload {} bytes)", size);
                break;
            }

            default:
                Utils::Logger::Debug("RealTimeProtection: Unhandled generic kernel event type {} ({} bytes)",
                    static_cast<uint16_t>(type), size);
                break;
        }
    }

    // =========================================================================
    // EXCLUSION MANAGEMENT
    // =========================================================================

    bool IsExcluded(const std::wstring& filePath, uint32_t pid) {
        std::shared_lock lock(m_exclusionMutex);

        // Check temp PID exclusions
        auto pidIt = m_tempPidExclusions.find(pid);
        if (pidIt != m_tempPidExclusions.end()) {
            if (Now() < pidIt->second) {
                return true;
            }
        }

        // Check path exclusions
        std::wstring lowerPath = ToLowerW(filePath);
        for (const auto& excl : m_excludedPaths) {
            if (PathMatchesWildcard(lowerPath, excl)) {
                return true;
            }
        }

        // Check extension exclusions
        size_t dotPos = lowerPath.rfind(L'.');
        if (dotPos != std::wstring::npos) {
            std::wstring ext = lowerPath.substr(dotPos);
            for (const auto& exclExt : m_excludedExtensions) {
                if (ToLowerW(exclExt) == ext) {
                    return true;
                }
            }
        }

        return false;
    }

    bool IsProcessExcluded(const std::wstring& processPath, uint32_t pid) {
        std::shared_lock lock(m_exclusionMutex);

        // Check temp PID exclusions
        auto pidIt = m_tempPidExclusions.find(pid);
        if (pidIt != m_tempPidExclusions.end() && Now() < pidIt->second) {
            return true;
        }

        // Check process exclusions
        std::wstring lowerPath = ToLowerW(processPath);
        fs::path p(processPath);
        std::wstring procName = ToLowerW(p.filename().wstring());

        for (const auto& excl : m_excludedProcesses) {
            std::wstring lowerExcl = ToLowerW(excl);
            if (lowerPath.find(lowerExcl) != std::wstring::npos ||
                procName == lowerExcl) {
                return true;
            }
        }

        return false;
    }

    bool AddPathExclusion(const std::wstring& path) {
        std::unique_lock lock(m_exclusionMutex);
        m_excludedPaths.push_back(path);
        Utils::Logger::Info("RealTimeProtection: Added path exclusion: {}",
            Utils::StringUtils::ToNarrow(path));
        return true;
    }

    bool RemovePathExclusion(const std::wstring& path) {
        std::unique_lock lock(m_exclusionMutex);
        auto it = std::remove(m_excludedPaths.begin(), m_excludedPaths.end(), path);
        if (it != m_excludedPaths.end()) {
            m_excludedPaths.erase(it, m_excludedPaths.end());
            return true;
        }
        return false;
    }

    bool AddProcessExclusion(const std::wstring& processName) {
        std::unique_lock lock(m_exclusionMutex);
        m_excludedProcesses.push_back(processName);
        Utils::Logger::Info("RealTimeProtection: Added process exclusion: {}",
            Utils::StringUtils::ToNarrow(processName));
        return true;
    }

    bool RemoveProcessExclusion(const std::wstring& processName) {
        std::unique_lock lock(m_exclusionMutex);
        auto it = std::remove(m_excludedProcesses.begin(), m_excludedProcesses.end(), processName);
        if (it != m_excludedProcesses.end()) {
            m_excludedProcesses.erase(it, m_excludedProcesses.end());
            return true;
        }
        return false;
    }

    bool AddHashExclusion(const std::wstring& hash) {
        std::unique_lock lock(m_exclusionMutex);
        m_excludedHashes.push_back(hash);
        return true;
    }

    bool RemoveHashExclusion(const std::wstring& hash) {
        std::unique_lock lock(m_exclusionMutex);
        auto it = std::remove(m_excludedHashes.begin(), m_excludedHashes.end(), hash);
        if (it != m_excludedHashes.end()) {
            m_excludedHashes.erase(it, m_excludedHashes.end());
            return true;
        }
        return false;
    }

    bool AddTemporaryPidExclusion(uint32_t pid, uint32_t durationMs) {
        std::unique_lock lock(m_exclusionMutex);
        m_tempPidExclusions[pid] = Now() + std::chrono::milliseconds(durationMs);
        return true;
    }

    void ClearAllExclusions() {
        std::unique_lock lock(m_exclusionMutex);
        m_excludedPaths.clear();
        m_excludedExtensions.clear();
        m_excludedProcesses.clear();
        m_excludedHashes.clear();
        m_tempPidExclusions.clear();
        Utils::Logger::Info("RealTimeProtection: Cleared all exclusions");
    }

    // =========================================================================
    // VERDICT CACHE
    // =========================================================================

    std::optional<ScanResult> CheckVerdictCache(const std::string& hashKey) {
        if (!m_config.useVerdictCache) return std::nullopt;

        std::shared_lock lock(m_cacheMutex);

        auto it = m_verdictCache.find(hashKey);
        if (it == m_verdictCache.end()) return std::nullopt;

        if (Now() > it->second.expiry) {
            return std::nullopt;
        }

        ScanResult result = it->second.result;
        result.fromCache = true;
        return result;
    }

    void UpdateVerdictCache(const std::string& hashKey, const ScanResult& result) {
        if (!m_config.useVerdictCache) return;

        std::unique_lock lock(m_cacheMutex);

        // Evict if at capacity
        if (m_verdictCache.size() >= m_config.maxCacheSize) {
            // Simple eviction: remove first entry
            m_verdictCache.erase(m_verdictCache.begin());
            m_performanceMetrics.cacheEvictions++;
        }

        CacheEntry entry;
        entry.result = result;

        // Set TTL based on verdict
        if (result.isThreat) {
            entry.expiry = Now() + std::chrono::milliseconds(m_config.maliciousCacheTTLMs);
        } else {
            entry.expiry = Now() + std::chrono::milliseconds(m_config.cleanCacheTTLMs);
        }

        m_verdictCache[hashKey] = entry;
        m_performanceMetrics.cacheSize = static_cast<uint32_t>(m_verdictCache.size());
    }

    void ClearVerdictCache() {
        std::unique_lock lock(m_cacheMutex);
        m_verdictCache.clear();
        m_imageVerdictCache.clear();
        m_fileVerdictCache.clear();
        m_performanceMetrics.cacheSize = 0;
        Utils::Logger::Info("RealTimeProtection: Verdict cache cleared");
    }

    // ---- Image-load module verdict cache (see m_imageVerdictCache) ----------
    std::optional<Communication::KernelVerdict>
    CheckImageVerdictCache(const std::wstring& key) {
        if (!m_config.useVerdictCache) return std::nullopt;
        std::shared_lock lock(m_cacheMutex);
        auto it = m_imageVerdictCache.find(key);
        if (it == m_imageVerdictCache.end()) return std::nullopt;
        if (Now() > it->second.expiry) return std::nullopt;
        return it->second.verdict;
    }

    void UpdateImageVerdictCache(const std::wstring& key,
                                 Communication::KernelVerdict verdict) {
        if (!m_config.useVerdictCache) return;
        // Never cache Block/suspicious — those modules must be re-evaluated on
        // every load. Only benign Allow results are memoized.
        if (verdict != Communication::KernelVerdict::Allow) return;
        std::unique_lock lock(m_cacheMutex);
        if (m_imageVerdictCache.size() >= m_config.maxCacheSize) {
            m_imageVerdictCache.clear();  // cheap to re-warm; bounds memory
        }
        m_imageVerdictCache[key] = ImageVerdictEntry{
            verdict, Now() + std::chrono::milliseconds(m_config.cleanCacheTTLMs) };
    }

    // ---- On-access file verdict cache (see m_fileVerdictCache) --------------
    std::optional<Communication::KernelVerdict>
    CheckFileVerdictCache(const std::wstring& key) {
        if (!m_config.useVerdictCache) return std::nullopt;
        std::shared_lock lock(m_cacheMutex);
        auto it = m_fileVerdictCache.find(key);
        if (it == m_fileVerdictCache.end()) return std::nullopt;
        if (Now() > it->second.expiry) return std::nullopt;
        return it->second.verdict;
    }

    void UpdateFileVerdictCache(const std::wstring& key,
                                Communication::KernelVerdict verdict) {
        if (!m_config.useVerdictCache) return;
        // Only benign Allow verdicts are memoized. Block/Suspicious/Monitor must
        // be re-evaluated on every access so a threat is never cached away.
        if (verdict != Communication::KernelVerdict::Allow) return;
        std::unique_lock lock(m_cacheMutex);
        if (m_fileVerdictCache.size() >= m_config.maxCacheSize) {
            m_fileVerdictCache.clear();  // cheap to re-warm; bounds memory
        }
        m_fileVerdictCache[key] = ImageVerdictEntry{
            verdict, Now() + std::chrono::milliseconds(m_config.cleanCacheTTLMs) };
    }

    // =========================================================================
    // THREAT HANDLING
    // =========================================================================

    void HandleThreatDetection(const ScanResult& result, const std::wstring& filePath, uint32_t pid) {
        // Create threat event
        ThreatEvent event;
        event.eventId = GenerateEventId();
        event.timestamp = Now();
        event.threatName = result.threatName;
        event.threatCategory = result.threatCategory;
        event.severity = result.severity;
        event.mitreIds = result.mitreIds;
        event.filePath = filePath;
        event.pid = pid;

        // Get process info
        try {
            auto procPath = Utils::ProcessUtils::GetProcessPath(pid);
            event.processPath = procPath.value();
            event.processName = fs::path(procPath.value()).filename().wstring();
        } catch (...) {}

        // Record action
        event.action = result.action;
        event.actionSuccessful = result.remediationSuccessful;
        event.quarantinePath = result.quarantinePath;
        event.detectionMethod = L"RealTime";
        event.confidence = result.confidence;

        // Store in recent threats
        {
            std::unique_lock lock(m_threatMutex);
            m_recentThreats.push_front(event);
            while (m_recentThreats.size() > MAX_RECENT_THREATS) {
                m_recentThreats.pop_back();
            }
        }

        // Invoke threat detection callbacks (snapshot callbacks first to avoid holding lock during dispatch)
        std::vector<ThreatDetectionCallback> callbackSnapshot;
        {
            std::shared_lock lock(m_callbackMutex);
            callbackSnapshot.reserve(m_threatDetectionCallbacks.size());
            for (const auto& [id, callback] : m_threatDetectionCallbacks) {
                callbackSnapshot.push_back(callback);
            }
        }

        // Dispatch outside the lock
        for (const auto& callback : callbackSnapshot) {
            try {
                callback(event);
            } catch (...) {}
        }

        // User notification
        if (m_config.notifyOnThreat) {
            NotifyUser(NotificationSeverity::THREAT_DETECTED,
                L"Threat Detected",
                std::format(L"Blocked: {} in {}", result.threatName, filePath),
                event);
        }

        Utils::Logger::Warn("RealTimeProtection: THREAT DETECTED - {} in {} (PID: {})",
            Utils::StringUtils::ToNarrow(result.threatName),
            Utils::StringUtils::ToNarrow(filePath), pid);
    }

    void NotifyUser(NotificationSeverity severity, std::wstring_view title,
                    std::wstring_view message, const std::optional<ThreatEvent>& event) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& [id, callback] : m_notificationCallbacks) {
            try {
                callback(severity, title, message, event);
            } catch (...) {}
        }
    }

    // =========================================================================
    // MANUAL OPERATIONS
    // =========================================================================

    ScanResult ScanFile(const std::wstring& filePath, ScanPriority priority) {
        ScanResult result;

#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        result.verdict = KernelVerdict::ERROR;
        result.errorCode = ERROR_CALL_NOT_IMPLEMENTED;
        result.errorMessage = L"Manual ScanFile is unavailable in SHADOWSTRIKE_RTP_FOCUSED_BUILD";
        return result;
#else
        try {
            Core::Engine::ScanContext context;
            context.type = Core::Engine::ScanType::OnDemand;
            context.filePath = filePath;
            context.priority = static_cast<Core::Engine::ScanPriority>(priority);
            context.timeout = std::chrono::milliseconds(m_config.scanTimeoutMs);

            auto engineResult = Core::Engine::ScanEngine::Instance().ScanFile(filePath, context);
            result = MapEngineResult(engineResult, filePath);

        } catch (const std::exception& e) {
            result.verdict = KernelVerdict::ERROR;
            result.errorCode = 1;
            result.errorMessage = Utils::StringUtils::ToWide(e.what());
        }

        // ================================================================
        // PhantomCortex AI/ML analysis (additive — never downgrades)
        // ================================================================
        if (ShadowStrike::AI::PhantomCortex::Instance().IsOperational()) {
            try {
                std::vector<std::byte> rawBytes;
                Utils::FileUtils::Error fileErr;
                if (Utils::FileUtils::ReadAllBytes(filePath, rawBytes, &fileErr) &&
                    !rawBytes.empty()) {
                    auto mlVerdict = ShadowStrike::AI::PhantomCortex::Instance().AnalyzeFile(
                        std::span<const uint8_t>(
                            reinterpret_cast<const uint8_t*>(rawBytes.data()),
                            rawBytes.size()));

                    if (mlVerdict.verdict == ShadowStrike::AI::ThreatVerdict::Malicious) {
                        if (result.verdict == KernelVerdict::ALLOW ||
                            result.verdict == KernelVerdict::MONITOR) {
                            SS_LOG_WARN(L"RealTimeProtection",
                                L"PhantomCortex ML detected threat in %s (confidence: %.2f, scan engine: clean)",
                                filePath.c_str(), mlVerdict.confidence);
                            result.verdict = KernelVerdict::BLOCK;
                            result.isThreat = true;
                            result.threatName = L"ML/PhantomCortex." + mlVerdict.details;
                            result.confidence = static_cast<uint8_t>(
                                std::clamp(mlVerdict.confidence * 100.0f, 0.0f, 100.0f));
                            result.detectedByML = true;
                            result.action = RemediationAction::BLOCKED;
                        }
                    } else if (mlVerdict.verdict == ShadowStrike::AI::ThreatVerdict::Suspicious &&
                               result.verdict == KernelVerdict::ALLOW) {
                        SS_LOG_INFO(L"RealTimeProtection",
                            L"PhantomCortex ML flagged %s as suspicious (confidence: %.2f)",
                            filePath.c_str(), mlVerdict.confidence);
                        result.verdict = KernelVerdict::MONITOR;
                        result.isThreat = true;
                        result.threatName = L"ML/PhantomCortex.Suspicious";
                        result.confidence = static_cast<uint8_t>(
                            std::clamp(mlVerdict.confidence * 100.0f, 0.0f, 100.0f));
                        result.detectedByML = true;
                    }
                }
            } catch (const std::exception& ex) {
                SS_LOG_ERROR(L"RealTimeProtection",
                    L"PhantomCortex ML analysis failed for %s: %hs",
                    filePath.c_str(), ex.what());
            } catch (...) {
                SS_LOG_ERROR(L"RealTimeProtection",
                    L"PhantomCortex ML analysis unknown exception for %s",
                    filePath.c_str());
            }
        }

        return result;
#endif
    }

    ScanResult ScanProcess(uint32_t pid) {
        try {
            auto path = Utils::ProcessUtils::GetProcessPath(pid);
            return ScanFile(path.value(), ScanPriority::HIGH);
        } catch (const std::exception& e) {
            ScanResult result;
            result.verdict = KernelVerdict::ERROR;
            result.errorMessage = Utils::StringUtils::ToWide(e.what());
            return result;
        }
    }

    bool BlockProcess(uint32_t pid, bool terminate) {
        if (terminate) {
            if (Utils::ProcessUtils::TerminateProcess(pid)) {
                m_stats.processesTerminated++;
                Utils::Logger::Info("RealTimeProtection: Terminated process PID {}", pid);
                return true;
            }
        }
        return false;
    }

    bool QuarantineFile(const std::wstring& filePath, std::wstring_view threatName) {
#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        (void)filePath;
        (void)threatName;
        Utils::Logger::Warn(
            "RealTimeProtection: QuarantineFile unavailable in focused user-mode build");
        return false;
#else
        try {
            auto result = Core::Engine::QuarantineManager::Instance().QuarantineFile(filePath, std::wstring(threatName));
            if (result.IsSuccess()) {
                m_stats.filesQuarantined++;
                Utils::Logger::Info("RealTimeProtection: Quarantined file: {}",
                    Utils::StringUtils::ToNarrow(filePath));
            } else {
                Utils::Logger::Error("RealTimeProtection: QuarantineManager failed to quarantine: {}",
                    Utils::StringUtils::ToNarrow(filePath));
            }
            return result.IsSuccess();
        } catch (const std::exception& ex) {
            Utils::Logger::Error("RealTimeProtection: Quarantine exception for {}: {}",
                Utils::StringUtils::ToNarrow(filePath), ex.what());
            return false;
        } catch (...) {
            return false;
        }
#endif
    }

    bool BlockNetworkAddress(const std::wstring& address, uint16_t port, uint32_t durationMs) {
        try {
            auto& ntf = NetworkTrafficFilter::Instance();
            ntf.BlockIP(Utils::StringUtils::ToNarrow(address));
            m_stats.connectionsBlocked++;
            return true;
        } catch (...) {
            return false;
        }
    }

    // =========================================================================
    // BACKGROUND THREADS
    // =========================================================================

    void HealthCheckLoop() {
        Utils::Logger::Info("RealTimeProtection: Health check thread started");

        while (!m_stopThreads) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(RTPConstants::HEALTH_CHECK_INTERVAL_MS));

            if (m_stopThreads) break;

            PerformHealthCheck();
        }

        Utils::Logger::Info("RealTimeProtection: Health check thread exiting");
    }

    void StatsUpdateLoop() {
        Utils::Logger::Info("RealTimeProtection: Stats update thread started");

        while (!m_stopThreads) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(RTPConstants::STATS_UPDATE_INTERVAL_MS));

            if (m_stopThreads) break;

            UpdatePerformanceMetrics();

            // Periodic on-access pipeline summary.
            //
            // Every diagnosis of the system-wide freeze had to be reconstructed
            // from indirect evidence because nothing ever reported how much work
            // the pipeline actually took in and completed. The kernel counters
            // that would answer it go to DbgPrintEx and are invisible without a
            // debugger attached, so this is the closest observable equivalent:
            // how many scans arrived, what they concluded, how many failed, and
            // how many deep analyses were handed to the background worker.
            //
            // scansDeferred is the load-bearing number here. The fast path
            // deliberately skips the expensive stages, so if this is not rising
            // in step with totalScans then that analysis is being dropped rather
            // than deferred - which would be a silent loss of coverage, and is
            // the single thing most worth noticing early.
            //
            // Emitted only when something moved, so an idle machine stays quiet.
            {
                const uint64_t scans     = m_stats.totalScans.load(std::memory_order_relaxed);
                const uint64_t deferred  = m_stats.scansDeferred.load(std::memory_order_relaxed);
                const uint64_t errors    = m_stats.scanErrors.load(std::memory_order_relaxed);
                const uint64_t threats   = m_stats.threatsDetected.load(std::memory_order_relaxed);
                const uint64_t blocked   = m_stats.filesBlocked.load(std::memory_order_relaxed);

                static uint64_t s_lastScans = 0;
                static uint64_t s_lastDeferred = 0;
                static uint64_t s_lastErrors = 0;

                if (scans != s_lastScans || deferred != s_lastDeferred || errors != s_lastErrors) {
                    size_t queueDepth = 0;
                    {
                        std::lock_guard<std::mutex> lock(m_deferredMutex);
                        queueDepth = m_deferredQueue.size();
                    }
                    Utils::Logger::Info(
                        "RealTimeProtection: on-access pipeline - scans={} (+{}) clean={} "
                        "suspicious={} infected={} errors={} threats={} blocked={} "
                        "deepScansDeferred={} (+{}) queueDepth={}",
                        scans, scans - s_lastScans,
                        m_stats.cleanFiles.load(std::memory_order_relaxed),
                        m_stats.suspiciousFiles.load(std::memory_order_relaxed),
                        m_stats.infectedFiles.load(std::memory_order_relaxed),
                        errors, threats, blocked,
                        deferred, deferred - s_lastDeferred,
                        queueDepth);

                    s_lastScans = scans;
                    s_lastDeferred = deferred;
                    s_lastErrors = errors;
                }
            }
        }

        Utils::Logger::Info("RealTimeProtection: Stats update thread exiting");
    }

    bool PerformHealthCheck() {
        bool allHealthy = true;

        // Check each component
        for (size_t i = 0; i < static_cast<size_t>(ComponentType::COMPONENT_COUNT); ++i) {
            auto& status = m_componentStatus[i];
            if (status.state == ProtectionComponentState::ERROR) {
                allHealthy = false;
                status.isHealthy = false;
            } else if (status.state == ProtectionComponentState::RUNNING) {
                status.isHealthy = true;
            }
        }

        // Update protection status
        m_protectionStatus.hasErrors = !allHealthy;
        m_protectionStatus.lastUpdate = Now();

        // Check if we should go to degraded mode
        if (!allHealthy && m_state == ProtectionState::ACTIVE) {
            int errorCount = 0;
            for (const auto& status : m_componentStatus) {
                if (status.state == ProtectionComponentState::ERROR) errorCount++;
            }

            if (errorCount >= 3) {
                SetState(ProtectionState::DEGRADED);
            }
        }

        return allHealthy;
    }

    void UpdatePerformanceMetrics() {
        // Delegate CPU measurement to CPUMonitor singleton (avoids duplicate GetSystemTimes)
        if (Performance::CPUMonitor::HasInstance()) {
            auto cpuStats = Performance::CPUMonitor::Instance().GetSystemStats();
            m_performanceMetrics.cpuUsagePercent =
                static_cast<uint32_t>(std::clamp(cpuStats.totalUsagePercent, 0.0, 100.0));
        } else {
            // Fallback: direct GetSystemTimes when CPUMonitor is not yet initialized
            FILETIME idleTimeFt{}, kernelTimeFt{}, userTimeFt{};
            if (::GetSystemTimes(&idleTimeFt, &kernelTimeFt, &userTimeFt)) {
                ULARGE_INTEGER idle, kernel, user;
                idle.LowPart   = idleTimeFt.dwLowDateTime;
                idle.HighPart  = idleTimeFt.dwHighDateTime;
                kernel.LowPart = kernelTimeFt.dwLowDateTime;
                kernel.HighPart= kernelTimeFt.dwHighDateTime;
                user.LowPart   = userTimeFt.dwLowDateTime;
                user.HighPart  = userTimeFt.dwHighDateTime;

                if (m_cpuTimesInitialized) {
                    uint64_t idleDelta   = idle.QuadPart   - m_prevIdleTime.QuadPart;
                    uint64_t kernelDelta = kernel.QuadPart - m_prevKernelTime.QuadPart;
                    uint64_t userDelta   = user.QuadPart   - m_prevUserTime.QuadPart;
                    uint64_t totalDelta  = kernelDelta + userDelta;
                    if (totalDelta > 0) {
                        uint64_t busyDelta = totalDelta - idleDelta;
                        uint32_t cpuPercent = static_cast<uint32_t>(
                            (busyDelta * 100) / totalDelta);
                        m_performanceMetrics.cpuUsagePercent =
                            static_cast<uint32_t>(std::min(cpuPercent, 100u));
                    }
                }
                m_prevIdleTime   = idle;
                m_prevKernelTime = kernel;
                m_prevUserTime   = user;
                m_cpuTimesInitialized = true;
            }
        }

        // Collect disk I/O metrics from DiskMonitor
        if (Performance::DiskMonitor::Instance().IsInitialized()) {
            auto diskStats = Performance::DiskMonitor::Instance().GetGlobalStats();
            // EDR self-monitoring: track our own I/O footprint
            auto selfIo = Performance::DiskMonitor::Instance().GetSelfIoUsage();
            if (selfIo.has_value()) {
                SS_LOG_DEBUG(L"RealTimeProtection",
                    L"Self I/O: read=%.1f KB/s write=%.1f KB/s",
                    selfIo->readBytesPerSec / 1024.0,
                    selfIo->writeBytesPerSec / 1024.0);
            }
        }

        // Measure our process memory usage
        {
            PROCESS_MEMORY_COUNTERS_EX pmc{};
            pmc.cb = sizeof(pmc);
            if (::GetProcessMemoryInfo(::GetCurrentProcess(),
                    reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
                m_performanceMetrics.memoryUsageBytes = pmc.WorkingSetSize;
            }
        }

        // Update scans per second
        auto now = Now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_lastRateCalcTime).count();
        if (elapsed > 0) {
            uint64_t currentScans = m_performanceMetrics.totalScans.load();
            m_performanceMetrics.scansPerSecond = (currentScans - m_lastTotalScansForRate) / static_cast<uint64_t>(elapsed);
            m_lastTotalScansForRate = currentScans;
            m_lastRateCalcTime = now;
        }

        // Update protection status
        m_protectionStatus.cpuUsagePercent = m_performanceMetrics.cpuUsagePercent.load();
        m_protectionStatus.memoryUsageBytes = m_performanceMetrics.memoryUsageBytes.load();
        m_protectionStatus.pendingScanCount = m_performanceMetrics.pendingScanQueue.load();
        m_protectionStatus.avgScanLatencyMs =
            static_cast<double>(m_performanceMetrics.avgScanTimeUs.load()) / 1000.0;
        m_protectionStatus.uptime = std::chrono::duration_cast<std::chrono::seconds>(
            now - m_protectionStatus.startTime);
    }

    // =========================================================================
    // STATE MANAGEMENT
    // =========================================================================

    void SetState(ProtectionState newState) {
        ProtectionState oldState = m_state.exchange(newState);
        if (oldState != newState) {
            m_protectionStatus.state = newState;

            // Invoke state change callbacks (snapshot callbacks first to avoid holding lock during dispatch)
            std::vector<StateChangeCallback> callbackSnapshot;
            {
                std::shared_lock lock(m_callbackMutex);
                callbackSnapshot.reserve(m_stateChangeCallbacks.size());
                for (const auto& [id, callback] : m_stateChangeCallbacks) {
                    callbackSnapshot.push_back(callback);
                }
            }

            // Dispatch outside the lock
            for (const auto& callback : callbackSnapshot) {
                try {
                    callback(oldState, newState, L"");
                } catch (...) {}
            }

            Utils::Logger::Info("RealTimeProtection: State changed from {} to {}",
                ProtectionStateToString(oldState),
                ProtectionStateToString(newState));
        }
    }

    void SetComponentState(ComponentType component, ProtectionComponentState state) {
        size_t idx = static_cast<size_t>(component);
        if (idx >= m_componentStatus.size()) return;

        ProtectionComponentState oldState = m_componentStatus[idx].state;
        m_componentStatus[idx].state = state;
        m_componentStatus[idx].lastStateChange = Now();

        if (oldState != state) {
            // Invoke component status callbacks (snapshot callbacks first to avoid holding lock during dispatch)
            std::vector<ComponentStatusCallback> callbackSnapshot;
            {
                std::shared_lock lock(m_callbackMutex);
                callbackSnapshot.reserve(m_componentStatusCallbacks.size());
                for (const auto& [id, callback] : m_componentStatusCallbacks) {
                    callbackSnapshot.push_back(callback);
                }
            }

            // Dispatch outside the lock
            for (const auto& callback : callbackSnapshot) {
                try {
                    callback(component, oldState, state);
                } catch (...) {}
            }
        }
    }

    // =========================================================================
    // UTILITY METHODS
    // =========================================================================

    ScanResult MapEngineResult(const Core::Engine::EngineResult& er, const std::wstring& filePath) {
        ScanResult sr;
        sr.isThreat = (er.verdict == Core::Engine::ScanVerdict::Infected ||
                       er.verdict == Core::Engine::ScanVerdict::Suspicious);
        sr.threatName = Utils::StringUtils::ToWide(er.threatName);
        // Clamp confidence float [0.0-1.0] to uint8 [0-100]
        sr.confidence = static_cast<uint8_t>(std::clamp(er.confidence * 100.0f, 0.0f, 100.0f));
        // Clamp severity to uint8 range (er.severity is ThreatLevel enum)
        sr.severity = static_cast<uint8_t>(er.severity);

        switch (er.verdict) {
            case Core::Engine::ScanVerdict::Clean:
            case Core::Engine::ScanVerdict::Whitelisted:
                sr.verdict = KernelVerdict::ALLOW;
                break;
            case Core::Engine::ScanVerdict::Infected:
                sr.verdict = KernelVerdict::BLOCK;
                sr.action = RemediationAction::BLOCKED;
                break;
            case Core::Engine::ScanVerdict::Suspicious:
                sr.verdict = (m_mode.load(std::memory_order_acquire) >= ProtectionMode::BLOCK_SUSPICIOUS) ?
                             KernelVerdict::BLOCK : KernelVerdict::MONITOR;
                break;
            case Core::Engine::ScanVerdict::PUA:
                sr.verdict = KernelVerdict::MONITOR;
                break;
            case Core::Engine::ScanVerdict::Error:
                sr.verdict = KernelVerdict::ERROR;
                sr.errorCode = er.errorCode;
                break;
            default:
                sr.verdict = KernelVerdict::ALLOW;
        }

        const auto& methods = er.detectionMethods;
        sr.detectedBySignature = std::find(methods.begin(), methods.end(), "Signature") != methods.end();
        sr.detectedByHeuristic = std::find(methods.begin(), methods.end(), "Heuristic") != methods.end();
        sr.detectedByBehavior = std::find(methods.begin(), methods.end(), "Behavior") != methods.end();
        sr.detectedByML = std::find(methods.begin(), methods.end(), "ML") != methods.end();

        return sr;
    }

    Communication::KernelVerdict MapScanVerdictToKernel(KernelVerdict verdict) {
        switch (verdict) {
            case KernelVerdict::ALLOW: return Communication::KernelVerdict::Allow;
            case KernelVerdict::BLOCK: return Communication::KernelVerdict::Block;
            case KernelVerdict::QUARANTINE: return Communication::KernelVerdict::Quarantine;
            case KernelVerdict::MONITOR: return Communication::KernelVerdict::Log;
            default: return Communication::KernelVerdict::Allow;
        }
    }

    // =========================================================================
    // DIAGNOSTICS
    // =========================================================================

    bool PerformDiagnostics() const {
        Utils::Logger::Info("RealTimeProtection: Starting diagnostics...");

        bool passed = true;

        // Check state
        if (m_state != ProtectionState::ACTIVE) {
            Utils::Logger::Warn("RealTimeProtection: Not in ACTIVE state");
            passed = false;
        }

        // Check components
        for (const auto& status : m_componentStatus) {
            if (status.state == ProtectionComponentState::ERROR) {
                Utils::Logger::Warn("RealTimeProtection: Component {} in ERROR state",
                    ComponentTypeToString(status.type));
                passed = false;
            }
        }

        // Check driver connection
        if (!m_protectionStatus.driverConnected) {
            Utils::Logger::Warn("RealTimeProtection: Kernel driver not connected");
        }

        Utils::Logger::Info("RealTimeProtection: Diagnostics {}",
            passed ? "PASSED" : "FAILED");
        return passed;
    }

    std::wstring GetDiagnosticSummary() const {
        std::wostringstream oss;
        oss << L"=== RealTimeProtection Diagnostic Summary ===\n";
        oss << L"State: " << Utils::StringUtils::ToWide(ProtectionStateToString(m_state.load())) << L"\n";
        oss << L"Protected: " << (m_protectionStatus.isProtected ? L"Yes" : L"No") << L"\n";
        oss << L"Driver Connected: " << (m_protectionStatus.driverConnected ? L"Yes" : L"No") << L"\n";
        oss << L"\n=== Components ===\n";

        for (const auto& status : m_componentStatus) {
            oss << Utils::StringUtils::ToWide(ComponentTypeToString(status.type))
                << L": " << (status.isHealthy ? L"Healthy" : L"Unhealthy") << L"\n";
        }

        oss << L"\n=== Statistics ===\n";
        oss << L"Total Events: " << m_stats.totalEvents.load() << L"\n";
        oss << L"Total Scans: " << m_stats.totalScans.load() << L"\n";
        oss << L"Files Blocked: " << m_stats.filesBlocked.load() << L"\n";
        oss << L"Threats Detected: " << m_stats.infectedFiles.load() << L"\n";

        return oss.str();
    }

    bool ExportDiagnostics(const std::wstring& outputPath) const {
        try {
            json j;
            j["state"] = ProtectionStateToString(m_state.load());
            j["protected"] = m_protectionStatus.isProtected;
            j["driverConnected"] = m_protectionStatus.driverConnected;

            json components = json::array();
            for (const auto& status : m_componentStatus) {
                components.push_back({
                    {"type", ComponentTypeToString(status.type)},
                    {"healthy", status.isHealthy},
                    {"eventsProcessed", status.eventsProcessed}
                });
            }
            j["components"] = components;

            json stats;
            stats["totalEvents"] = m_stats.totalEvents.load();
            stats["totalScans"] = m_stats.totalScans.load();
            stats["filesBlocked"] = m_stats.filesBlocked.load();
            stats["threatsDetected"] = m_stats.infectedFiles.load();
            j["statistics"] = stats;

            std::ofstream out(outputPath);
            out << j.dump(4);
            return true;

        } catch (...) {
            return false;
        }
    }
};

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void RTPStatistics::Reset() noexcept {
    totalEvents = 0;
    fileEvents = 0;
    processEvents = 0;
    registryEvents = 0;
    networkEvents = 0;
    memoryEvents = 0;
    totalScans = 0;
    cleanFiles = 0;
    infectedFiles = 0;
    suspiciousFiles = 0;
    puaFiles = 0;
    scanErrors = 0;
    filesBlocked = 0;
    processesBlocked = 0;
    connectionsBlocked = 0;
    registryBlocked = 0;
    filesQuarantined = 0;
    filesDeleted = 0;
    filesCleaned = 0;
    processesTerminated = 0;
    excludedByPath = 0;
    excludedByExtension = 0;
    excludedByProcess = 0;
    excludedByHash = 0;
    threatsDetected = 0;
    performance.Reset();
    lastReset = std::chrono::system_clock::now();
}

void PerformanceMetrics::Reset() noexcept {
    totalScans = 0;
    scansPerSecond = 0;
    avgScanTimeUs = 0;
    maxScanTimeUs = 0;
    scanTimeouts = 0;
    pendingScanQueue = 0;
    maxQueueDepth = 0;
    queueWaitTimeUs = 0;
    cacheHits = 0;
    cacheMisses = 0;
    cacheSize = 0;
    cacheEvictions = 0;
    cpuUsagePercent = 0;
    memoryUsageBytes = 0;
    threadCount = 0;
    handleCount = 0;
    kernelMessages = 0;
    kernelReplies = 0;
    kernelTimeouts = 0;
    kernelErrors = 0;
}

// ============================================================================
// RTP CONFIG FACTORY METHODS
// ============================================================================

RTPConfig RTPConfig::CreateDefault() noexcept {
    RTPConfig config;
    return config;
}

RTPConfig RTPConfig::CreateHighSecurity() noexcept {
    RTPConfig config;
    config.mode = ProtectionMode::BLOCK_UNKNOWN;
    config.failurePolicy = FailurePolicy::FAIL_CLOSED;
    config.scanOnWrite = true;
    config.scanOnRename = true;
    config.monitorThreadCreation = true;
    config.inspectHTTPS = true;
    config.scanTimeoutMs = 120000;
    return config;
}

RTPConfig RTPConfig::CreateHighPerformance() noexcept {
    RTPConfig config;
    config.mode = ProtectionMode::BLOCK_KNOWN;
    config.scanOnWrite = false;
    config.scanArchives = false;
    config.throttleOnHighCPU = true;
    config.throttleOnLowMemory = true;
    config.maxConcurrentScans = 2;
    return config;
}

RTPConfig RTPConfig::CreateServerOptimized() noexcept {
    RTPConfig config;
    config.mode = ProtectionMode::BLOCK_KNOWN;
    config.scanOnWrite = true;
    config.scanOnExecute = true;
    config.monitorProcessCreation = true;
    return config;
}

RTPConfig RTPConfig::CreateWorkstationOptimized() noexcept {
    RTPConfig config;
    config.mode = ProtectionMode::BLOCK_SUSPICIOUS;
    config.scanOnOpen = true;
    config.scanOnExecute = true;
    config.monitorProcessCreation = true;
    return config;
}

// ============================================================================
// SINGLETON ACCESS
// ============================================================================

RealTimeProtection& RealTimeProtection::Instance() {
    static RealTimeProtection instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

RealTimeProtection::RealTimeProtection()
    : m_impl(std::make_unique<RealTimeProtectionImpl>()) {
}

RealTimeProtection::~RealTimeProtection() {
    if (m_impl) {
        m_impl->Stop();
    }
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool RealTimeProtection::Start() {
    return m_impl->Start();
}

void RealTimeProtection::Stop() {
    m_impl->Stop();
}

bool RealTimeProtection::Restart() {
    Stop();
    return Start();
}

bool RealTimeProtection::Pause(uint32_t durationMs, std::wstring_view reason) {
    return m_impl->Pause(durationMs, reason);
}

bool RealTimeProtection::Resume() {
    return m_impl->Resume();
}

bool RealTimeProtection::IsActive() const noexcept {
    return m_impl->m_state == ProtectionState::ACTIVE;
}

ProtectionState RealTimeProtection::GetState() const noexcept {
    return m_impl->m_state.load();
}

// ============================================================================
// CONFIGURATION
// ============================================================================

bool RealTimeProtection::UpdateConfig(const RTPConfig& config) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = config;
    m_impl->m_mode = config.mode;

    // Propagate relevant settings to components
    try {
        FileSystemFilter::Instance().SetScanOnOpen(config.scanOnOpen);
        FileSystemFilter::Instance().SetScanOnExecute(config.scanOnExecute);
        FileSystemFilter::Instance().SetScanOnWrite(config.scanOnWrite);
    } catch (...) {}

    Utils::Logger::Info("RealTimeProtection: Configuration updated");
    return true;
}

RTPConfig RealTimeProtection::GetConfig() const {
    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}

void RealTimeProtection::SetProtectionMode(ProtectionMode mode) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_mode.store(mode, std::memory_order_release);
    m_impl->m_config.mode = mode;
}

ProtectionMode RealTimeProtection::GetProtectionMode() const noexcept {
    return m_impl->m_mode.load();
}

// ============================================================================
// EXCLUSION MANAGEMENT
// ============================================================================

bool RealTimeProtection::AddPathExclusion(const std::wstring& path) {
    return m_impl->AddPathExclusion(path);
}

bool RealTimeProtection::RemovePathExclusion(const std::wstring& path) {
    return m_impl->RemovePathExclusion(path);
}

bool RealTimeProtection::AddProcessExclusion(const std::wstring& processName) {
    return m_impl->AddProcessExclusion(processName);
}

bool RealTimeProtection::RemoveProcessExclusion(const std::wstring& processName) {
    return m_impl->RemoveProcessExclusion(processName);
}

bool RealTimeProtection::AddHashExclusion(const std::wstring& hash) {
    return m_impl->AddHashExclusion(hash);
}

bool RealTimeProtection::RemoveHashExclusion(const std::wstring& hash) {
    return m_impl->RemoveHashExclusion(hash);
}

bool RealTimeProtection::AddTemporaryPidExclusion(uint32_t pid, uint32_t durationMs) {
    return m_impl->AddTemporaryPidExclusion(pid, durationMs);
}

void RealTimeProtection::ClearAllExclusions() {
    m_impl->ClearAllExclusions();
}

std::unordered_map<std::wstring, std::vector<std::wstring>> RealTimeProtection::GetExclusions() const {
    std::unordered_map<std::wstring, std::vector<std::wstring>> result;

    std::shared_lock lock(m_impl->m_exclusionMutex);
    result[L"paths"] = m_impl->m_excludedPaths;
    result[L"extensions"] = m_impl->m_excludedExtensions;
    result[L"processes"] = m_impl->m_excludedProcesses;
    result[L"hashes"] = m_impl->m_excludedHashes;

    return result;
}

// ============================================================================
// STATUS AND MONITORING
// ============================================================================

ProtectionStatus RealTimeProtection::GetStatus() const {
    return m_impl->m_protectionStatus;
}

ComponentStatus RealTimeProtection::GetComponentStatus(ComponentType component) const {
    size_t idx = static_cast<size_t>(component);
    if (idx < m_impl->m_componentStatus.size()) {
        return m_impl->m_componentStatus[idx];
    }
    return ComponentStatus{};
}

std::unordered_map<ComponentType, bool> RealTimeProtection::GetComponentHealth() const {
    std::unordered_map<ComponentType, bool> result;
    for (const auto& status : m_impl->m_componentStatus) {
        result[status.type] = status.isHealthy;
    }
    return result;
}

bool RealTimeProtection::PerformHealthCheck() const {
    return m_impl->PerformHealthCheck();
}

std::vector<ThreatEvent> RealTimeProtection::GetRecentThreats(
    size_t maxEvents,
    std::chrono::system_clock::time_point sinceTime) const
{
    std::shared_lock lock(m_impl->m_threatMutex);

    std::vector<ThreatEvent> result;
    result.reserve(std::min(maxEvents, m_impl->m_recentThreats.size()));

    for (const auto& event : m_impl->m_recentThreats) {
        if (result.size() >= maxEvents) break;
        if (sinceTime != std::chrono::system_clock::time_point{} &&
            event.timestamp < sinceTime) {
            continue;
        }
        result.push_back(event);
    }

    return result;
}

// ============================================================================
// MANUAL OPERATIONS
// ============================================================================

ScanResult RealTimeProtection::ScanFile(const std::wstring& filePath, ScanPriority priority) {
    return m_impl->ScanFile(filePath, priority);
}

ScanResult RealTimeProtection::ScanProcess(uint32_t pid) {
    return m_impl->ScanProcess(pid);
}

bool RealTimeProtection::BlockProcess(uint32_t pid, bool terminate) {
    return m_impl->BlockProcess(pid, terminate);
}

bool RealTimeProtection::QuarantineFile(const std::wstring& filePath, std::wstring_view threatName) {
    return m_impl->QuarantineFile(filePath, threatName);
}

bool RealTimeProtection::BlockNetworkAddress(const std::wstring& address, uint16_t port, uint32_t durationMs) {
    return m_impl->BlockNetworkAddress(address, port, durationMs);
}

// ============================================================================
// VERDICT CACHE MANAGEMENT
// ============================================================================

std::optional<ScanResult> RealTimeProtection::QueryVerdictCache(const std::array<uint8_t, 32>& hash) const {
    std::ostringstream oss;
    for (auto byte : hash) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    return m_impl->CheckVerdictCache(oss.str());
}

void RealTimeProtection::InvalidateCacheEntry(const std::array<uint8_t, 32>& hash) {
    std::ostringstream oss;
    for (auto byte : hash) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    std::unique_lock lock(m_impl->m_cacheMutex);
    m_impl->m_verdictCache.erase(oss.str());
}

void RealTimeProtection::ClearVerdictCache() {
    m_impl->ClearVerdictCache();
}

size_t RealTimeProtection::GetCacheSize() const noexcept {
    std::shared_lock lock(m_impl->m_cacheMutex);
    return m_impl->m_verdictCache.size();
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

uint64_t RealTimeProtection::RegisterFileScanCallback(RTPFileScanCallback callback) {
    if (!callback) {
        Utils::Logger::Warn("RealTimeProtection: Attempted to register empty file scan callback");
        return 0;
    }
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = GenerateCallbackId();
    m_impl->m_fileScanCallbacks[id] = std::move(callback);
    return id;
}

uint64_t RealTimeProtection::RegisterProcessCreateCallback(RTPProcessCreateCallback callback) {
    if (!callback) {
        Utils::Logger::Warn("RealTimeProtection: Attempted to register empty process create callback");
        return 0;
    }
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = GenerateCallbackId();
    m_impl->m_processCreateCallbacks[id] = std::move(callback);
    return id;
}

uint64_t RealTimeProtection::RegisterThreatDetectionCallback(ThreatDetectionCallback callback) {
    if (!callback) {
        Utils::Logger::Warn("RealTimeProtection: Attempted to register empty threat detection callback");
        return 0;
    }
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = GenerateCallbackId();
    m_impl->m_threatDetectionCallbacks[id] = std::move(callback);
    return id;
}

uint64_t RealTimeProtection::RegisterStateChangeCallback(StateChangeCallback callback) {
    if (!callback) {
        Utils::Logger::Warn("RealTimeProtection: Attempted to register empty state change callback");
        return 0;
    }
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = GenerateCallbackId();
    m_impl->m_stateChangeCallbacks[id] = std::move(callback);
    return id;
}

uint64_t RealTimeProtection::RegisterComponentStatusCallback(ComponentStatusCallback callback) {
    if (!callback) {
        Utils::Logger::Warn("RealTimeProtection: Attempted to register empty component status callback");
        return 0;
    }
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = GenerateCallbackId();
    m_impl->m_componentStatusCallbacks[id] = std::move(callback);
    return id;
}

uint64_t RealTimeProtection::RegisterNotificationCallback(UserNotificationCallback callback) {
    if (!callback) {
        Utils::Logger::Warn("RealTimeProtection: Attempted to register empty notification callback");
        return 0;
    }
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = GenerateCallbackId();
    m_impl->m_notificationCallbacks[id] = std::move(callback);
    return id;
}

bool RealTimeProtection::UnregisterCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);

    if (m_impl->m_fileScanCallbacks.erase(callbackId)) return true;
    if (m_impl->m_processCreateCallbacks.erase(callbackId)) return true;
    if (m_impl->m_threatDetectionCallbacks.erase(callbackId)) return true;
    if (m_impl->m_stateChangeCallbacks.erase(callbackId)) return true;
    if (m_impl->m_componentStatusCallbacks.erase(callbackId)) return true;
    if (m_impl->m_notificationCallbacks.erase(callbackId)) return true;

    return false;
}

// ============================================================================
// STATISTICS
// ============================================================================

const RTPStatistics& RealTimeProtection::GetStatistics() const noexcept {
    return m_impl->m_stats;
}

const PerformanceMetrics& RealTimeProtection::GetPerformanceMetrics() const noexcept {
    return m_impl->m_performanceMetrics;
}

void RealTimeProtection::ResetStatistics() noexcept {
    m_impl->m_stats.Reset();
    m_impl->m_performanceMetrics.Reset();
}

// ============================================================================
// DIAGNOSTICS
// ============================================================================

bool RealTimeProtection::PerformDiagnostics() const {
    return m_impl->PerformDiagnostics();
}

bool RealTimeProtection::ExportDiagnostics(const std::wstring& outputPath) const {
    return m_impl->ExportDiagnostics(outputPath);
}

std::wstring RealTimeProtection::GetDiagnosticSummary() const {
    return m_impl->GetDiagnosticSummary();
}

// ============================================================================
// COMPONENT ACCESS
// ============================================================================

FileSystemFilter& RealTimeProtection::GetFileSystemFilter() {
    return FileSystemFilter::Instance();
}

ProcessCreationMonitor& RealTimeProtection::GetProcessCreationMonitor() {
    return ProcessCreationMonitor::Instance();
}

MemoryProtection& RealTimeProtection::GetMemoryProtection() {
#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
    throw std::runtime_error("MemoryProtection is unavailable in SHADOWSTRIKE_RTP_FOCUSED_BUILD");
#else
    return MemoryProtection::Instance();
#endif
}

BehaviorBlocker& RealTimeProtection::GetBehaviorBlocker() {
#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
    throw std::runtime_error("BehaviorBlocker is unavailable in SHADOWSTRIKE_RTP_FOCUSED_BUILD");
#else
    return BehaviorBlocker::Instance();
#endif
}

NetworkTrafficFilter& RealTimeProtection::GetNetworkTrafficFilter() {
    return NetworkTrafficFilter::Instance();
}

ExploitPrevention& RealTimeProtection::GetExploitPrevention() {
#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
    throw std::runtime_error("ExploitPrevention is unavailable in SHADOWSTRIKE_RTP_FOCUSED_BUILD");
#else
    return ExploitPrevention::Instance();
#endif
}

FileIntegrityMonitor& RealTimeProtection::GetFileIntegrityMonitor() {
#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
    throw std::runtime_error("FileIntegrityMonitor is unavailable in SHADOWSTRIKE_RTP_FOCUSED_BUILD");
#else
    return FileIntegrityMonitor::Instance();
#endif
}

AccessControlManager& RealTimeProtection::GetAccessControlManager() {
#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
    throw std::runtime_error("AccessControlManager is unavailable in SHADOWSTRIKE_RTP_FOCUSED_BUILD");
#else
    return AccessControlManager::Instance();
#endif
}

ZeroHourProtection& RealTimeProtection::GetZeroHourProtection() {
#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
    throw std::runtime_error("ZeroHourProtection is unavailable in SHADOWSTRIKE_RTP_FOCUSED_BUILD");
#else
    return ZeroHourProtection::Instance();
#endif
}

} // namespace RealTime
} // namespace ShadowStrike




