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
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Communication/IPCManager.hpp"
#include "../Core/Engine/ScanEngine.hpp"
#include "../Core/Engine/QuarantineManager.hpp"
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

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// ANONYMOUS HELPER NAMESPACE
// ============================================================================
namespace {

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
    std::atomic<bool> m_stopThreads{ false };

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

    // Recent Threats
    std::deque<ThreatEvent> m_recentThreats;
    static constexpr size_t MAX_RECENT_THREATS = 1000;

    // Anti-Evasion Detectors
    std::unique_ptr<ShadowStrike::AntiEvasion::DebuggerEvasionDetector> m_debuggerDetector;
    std::unique_ptr<ShadowStrike::AntiEvasion::VMEvasionDetector> m_vmDetector;
    std::unique_ptr<ShadowStrike::AntiEvasion::SandboxEvasionDetector> m_sandboxDetector;
    std::unique_ptr<ShadowStrike::AntiEvasion::ProcessEvasionDetector> m_processDetector;
    std::unique_ptr<ShadowStrike::AntiEvasion::MetamorphicDetector> m_metamorphicDetector;

    // Component Status
    std::array<ComponentStatus, static_cast<size_t>(ComponentType::COMPONENT_COUNT)> m_componentStatus;

    // Statistics
    RTPStatistics m_stats;
    PerformanceMetrics m_performanceMetrics;

    // Callbacks
    std::unordered_map<uint64_t, FileScanCallback> m_fileScanCallbacks;
    std::unordered_map<uint64_t, ProcessCreateCallback> m_processCreateCallbacks;
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
        // Initialize Anti-Evasion Detectors
        try {
            m_debuggerDetector = std::make_unique<ShadowStrike::AntiEvasion::DebuggerEvasionDetector>();
            m_vmDetector = std::make_unique<ShadowStrike::AntiEvasion::VMEvasionDetector>();
            m_sandboxDetector = std::make_unique<ShadowStrike::AntiEvasion::SandboxEvasionDetector>();
            m_processDetector = std::make_unique<ShadowStrike::AntiEvasion::ProcessEvasionDetector>();
            m_metamorphicDetector = std::make_unique<ShadowStrike::AntiEvasion::MetamorphicDetector>();
        } catch (const std::exception& e) {
            Utils::Logger::Error(L"Failed to initialize Anti-Evasion detectors: {}", Utils::StringUtils::ToWideString(e.what()));
        }

        // Initialize component status array
        for (size_t i = 0; i < m_componentStatus.size(); ++i) {
            m_componentStatus[i].type = static_cast<ComponentType>(i);
            m_componentStatus[i].state = ComponentState::UNINITIALIZED;
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
            Utils::Logger::Warn(L"RealTimeProtection: Already active");
            return true;
        }

        Utils::Logger::Info(L"RealTimeProtection: Starting orchestrator service...");
        SetState(ProtectionState::INITIALIZING);

        try {
            // 1. Initialize ThreadPool if not provided
            if (!m_threadPool) {
                m_threadPool = std::make_shared<Utils::ThreadPool>(
                    std::min(std::thread::hardware_concurrency(), 8u));
            }

            // 2. Initialize Scan Engine
            if (!InitializeScanEngine()) {
                Utils::Logger::Error(L"RealTimeProtection: Failed to initialize ScanEngine");
                // Continue in degraded mode
                SetComponentState(ComponentType::SCAN_ENGINE, ComponentState::ERROR);
            } else {
                SetComponentState(ComponentType::SCAN_ENGINE, ComponentState::RUNNING);
            }

            // 3. Initialize IPC Manager and connect to kernel driver
            if (!InitializeIPCManager()) {
                Utils::Logger::Warn(L"RealTimeProtection: IPC Manager not available. Running in user-mode only.");
                SetComponentState(ComponentType::IPC_MANAGER, ComponentState::ERROR);
                m_protectionStatus.driverConnected = false;
            } else {
                SetComponentState(ComponentType::IPC_MANAGER, ComponentState::RUNNING);
                m_protectionStatus.driverConnected = true;
            }

            // 4. Initialize Quarantine Manager
            if (!InitializeQuarantineManager()) {
                Utils::Logger::Warn(L"RealTimeProtection: QuarantineManager initialization failed");
                SetComponentState(ComponentType::QUARANTINE_MANAGER, ComponentState::ERROR);
            } else {
                SetComponentState(ComponentType::QUARANTINE_MANAGER, ComponentState::RUNNING);
            }

            // 5. Start Protection Components
            StartComponents();

            // 6. Start background threads
            m_stopThreads = false;
            m_healthCheckThread = std::make_unique<std::thread>(&RealTimeProtectionImpl::HealthCheckLoop, this);
            m_statsUpdateThread = std::make_unique<std::thread>(&RealTimeProtectionImpl::StatsUpdateLoop, this);

            // 7. Update protection status
            m_protectionStatus.isProtected = true;
            m_protectionStatus.lastUpdate = Now();
        // Initialize Anti-Evasion Detectors
        try {
            m_debuggerDetector = std::make_unique<ShadowStrike::AntiEvasion::DebuggerEvasionDetector>();
            m_vmDetector = std::make_unique<ShadowStrike::AntiEvasion::VMEvasionDetector>();
            m_sandboxDetector = std::make_unique<ShadowStrike::AntiEvasion::SandboxEvasionDetector>();
            m_processDetector = std::make_unique<ShadowStrike::AntiEvasion::ProcessEvasionDetector>();
            m_metamorphicDetector = std::make_unique<ShadowStrike::AntiEvasion::MetamorphicDetector>();
        } catch (const std::exception& e) {
            Utils::Logger::Error(L"Failed to initialize Anti-Evasion detectors: {}", Utils::StringUtils::ToWideString(e.what()));
        }

            SetState(ProtectionState::ACTIVE);
            Utils::Logger::Info(L"RealTimeProtection: Started successfully");
            return true;

        } catch (const std::exception& e) {
            Utils::Logger::Critical(L"RealTimeProtection: Exception during startup: {}",
                Utils::StringUtils::Utf8ToWide(e.what()));
            SetState(ProtectionState::ERROR);
            return false;
        }
    }

    void Stop() {
        if (m_state == ProtectionState::UNINITIALIZED ||
            m_state == ProtectionState::SHUTTING_DOWN) {
            return;
        }

        Utils::Logger::Info(L"RealTimeProtection: Stopping orchestrator service...");
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

        // 2. Stop components
        StopComponents();

        // 3. Disconnect from kernel driver
        auto& ipc = Communication::IPCManager::Instance();
        ipc.DisconnectFilterPort();
        ipc.Stop();
        SetComponentState(ComponentType::IPC_MANAGER, ComponentState::STOPPED);

        // 4. Shutdown scan engine
        Core::Engine::ScanEngine::Instance().Shutdown();
        SetComponentState(ComponentType::SCAN_ENGINE, ComponentState::STOPPED);

        // 5. Clear caches
        {
            std::unique_lock lock(m_cacheMutex);
            m_verdictCache.clear();
        }

        m_protectionStatus.isProtected = false;
        m_protectionStatus.lastUpdate = Now();
        // Initialize Anti-Evasion Detectors
        try {
            m_debuggerDetector = std::make_unique<ShadowStrike::AntiEvasion::DebuggerEvasionDetector>();
            m_vmDetector = std::make_unique<ShadowStrike::AntiEvasion::VMEvasionDetector>();
            m_sandboxDetector = std::make_unique<ShadowStrike::AntiEvasion::SandboxEvasionDetector>();
            m_processDetector = std::make_unique<ShadowStrike::AntiEvasion::ProcessEvasionDetector>();
            m_metamorphicDetector = std::make_unique<ShadowStrike::AntiEvasion::MetamorphicDetector>();
        } catch (const std::exception& e) {
            Utils::Logger::Error(L"Failed to initialize Anti-Evasion detectors: {}", Utils::StringUtils::ToWideString(e.what()));
        }

        SetState(ProtectionState::UNINITIALIZED);
        Utils::Logger::Info(L"RealTimeProtection: Stopped");
    }

    bool Pause(uint32_t durationMs, std::wstring_view reason) {
        if (m_state != ProtectionState::ACTIVE) {
            Utils::Logger::Warn(L"RealTimeProtection: Cannot pause - not active");
            return false;
        }

        SetState(ProtectionState::PAUSED);
        Utils::Logger::Warn(L"RealTimeProtection: PAUSED - Reason: {}",
            reason.empty() ? L"User request" : reason);

        // Pause components
        FileSystemFilter::Instance().Pause();
        ProcessCreationMonitor::Instance().Pause();
        NetworkTrafficFilter::Instance().Stop(); // Network filter doesn't have Pause
        BehaviorBlocker::Instance().Pause();

        m_protectionStatus.isProtected = false;

        // Set up auto-resume if duration specified
        if (durationMs > 0) {
            m_threadPool->Submit([this, durationMs]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(durationMs));
                if (m_state == ProtectionState::PAUSED) {
                    Resume();
                }
            });
        }

        return true;
    }

    bool Resume() {
        if (m_state != ProtectionState::PAUSED) {
            return false;
        }

        Utils::Logger::Info(L"RealTimeProtection: Resuming protection...");

        // Resume components
        FileSystemFilter::Instance().Resume();
        ProcessCreationMonitor::Instance().Resume();
        NetworkTrafficFilter::Instance().Start();
        BehaviorBlocker::Instance().Resume();

        m_protectionStatus.isProtected = true;
        SetState(ProtectionState::ACTIVE);

        Utils::Logger::Info(L"RealTimeProtection: Resumed");
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
            Utils::Logger::Error(L"RealTimeProtection: ScanEngine init exception: {}",
                Utils::StringUtils::Utf8ToWide(e.what()));
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
            ipc.RegisterFileScanHandler([this](const Communication::FileScanRequest& req) {
                return OnKernelFileScan(req);
            });

            ipc.RegisterProcessHandler([this](const Communication::ProcessNotifyRequest& req) {
                return OnKernelProcessNotify(req);
            });

            if (!ipc.Start()) {
                return false;
            }

            if (!ipc.ConnectFilterPort()) {
                Utils::Logger::Warn(L"RealTimeProtection: Failed to connect to filter port (driver may not be loaded)");
                return false;
            }

            m_protectionStatus.driverLoaded = true;
            m_protectionStatus.driverConnected = true;
            m_protectionStatus.driverVersion = L"3.0.0"; // Would query from driver

            return true;
        } catch (const std::exception& e) {
            Utils::Logger::Error(L"RealTimeProtection: IPCManager init exception: {}",
                Utils::StringUtils::Utf8ToWide(e.what()));
            return false;
        }
    }

    bool InitializeQuarantineManager() {
        try {
            // QuarantineManager would be initialized here
            // Core::Engine::QuarantineManager::Instance().Initialize();
            return true;
        } catch (...) {
            return false;
        }
    }

    void StartComponents() {
        Utils::Logger::Info(L"RealTimeProtection: Starting protection components...");

        // FileSystemFilter
        try {
            auto& fsf = FileSystemFilter::Instance();
            if (fsf.Initialize(m_threadPool)) {
                fsf.Start();
                SetComponentState(ComponentType::FILE_SYSTEM_FILTER, ComponentState::RUNNING);

                // Wire up scan engine
                fsf.SetScanEngine(&Core::Engine::ScanEngine::Instance());
            }
        } catch (...) {
            SetComponentState(ComponentType::FILE_SYSTEM_FILTER, ComponentState::ERROR);
        }

        // ProcessCreationMonitor
        try {
            auto& pcm = ProcessCreationMonitor::Instance();
            pcm.Start();
            SetComponentState(ComponentType::PROCESS_MONITOR, ComponentState::RUNNING);
        } catch (...) {
            SetComponentState(ComponentType::PROCESS_MONITOR, ComponentState::ERROR);
        }

        // MemoryProtection
        if (m_config.monitorMemoryAllocation) {
            try {
                auto& mp = MemoryProtection::Instance();
                mp.Start();
                SetComponentState(ComponentType::MEMORY_PROTECTION, ComponentState::RUNNING);
            } catch (...) {
                SetComponentState(ComponentType::MEMORY_PROTECTION, ComponentState::ERROR);
            }
        }

        // BehaviorBlocker
        if (m_config.enableBehaviorBlocking) {
            try {
                auto& bb = BehaviorBlocker::Instance();
                bb.Start();
                SetComponentState(ComponentType::BEHAVIOR_BLOCKER, ComponentState::RUNNING);
            } catch (...) {
                SetComponentState(ComponentType::BEHAVIOR_BLOCKER, ComponentState::ERROR);
            }
        }

        // NetworkTrafficFilter
        if (m_config.filterNetworkTraffic) {
            try {
                auto& ntf = NetworkTrafficFilter::Instance();
                ntf.Initialize(m_threadPool);
                ntf.Start();
                SetComponentState(ComponentType::NETWORK_FILTER, ComponentState::RUNNING);
            } catch (...) {
                SetComponentState(ComponentType::NETWORK_FILTER, ComponentState::ERROR);
            }
        }

        // ExploitPrevention
        if (m_config.enableExploitPrevention) {
            try {
                auto& ep = ExploitPrevention::Instance();
                ep.Start();
                SetComponentState(ComponentType::EXPLOIT_PREVENTION, ComponentState::RUNNING);
            } catch (...) {
                SetComponentState(ComponentType::EXPLOIT_PREVENTION, ComponentState::ERROR);
            }
        }

        // FileIntegrityMonitor
        if (m_config.enableFileIntegrity) {
            try {
                auto& fim = FileIntegrityMonitor::Instance();
                fim.Start();
                SetComponentState(ComponentType::FILE_INTEGRITY, ComponentState::RUNNING);
            } catch (...) {
                SetComponentState(ComponentType::FILE_INTEGRITY, ComponentState::ERROR);
            }
        }

        // AccessControlManager
        try {
            auto& acm = AccessControlManager::Instance();
            acm.Initialize(AccessControlManagerConfig::CreateEnterprise());
            SetComponentState(ComponentType::ACCESS_CONTROL, ComponentState::RUNNING);
        } catch (...) {
            SetComponentState(ComponentType::ACCESS_CONTROL, ComponentState::ERROR);
        }

        // ZeroHourProtection
        if (m_config.enableZeroHourProtection) {
            try {
                auto& zhp = ZeroHourProtection::Instance();
                zhp.Start();
                SetComponentState(ComponentType::ZERO_HOUR, ComponentState::RUNNING);
            } catch (...) {
                SetComponentState(ComponentType::ZERO_HOUR, ComponentState::ERROR);
            }
        }

        Utils::Logger::Info(L"RealTimeProtection: Components started");
    }

    void StopComponents() {
        Utils::Logger::Info(L"RealTimeProtection: Stopping protection components...");

        try { FileSystemFilter::Instance().Stop(); } catch (...) {}
        SetComponentState(ComponentType::FILE_SYSTEM_FILTER, ComponentState::STOPPED);

        try { ProcessCreationMonitor::Instance().Stop(); } catch (...) {}
        SetComponentState(ComponentType::PROCESS_MONITOR, ComponentState::STOPPED);

        try { MemoryProtection::Instance().Stop(); } catch (...) {}
        SetComponentState(ComponentType::MEMORY_PROTECTION, ComponentState::STOPPED);

        try { BehaviorBlocker::Instance().Stop(); } catch (...) {}
        SetComponentState(ComponentType::BEHAVIOR_BLOCKER, ComponentState::STOPPED);

        try { NetworkTrafficFilter::Instance().Stop(); } catch (...) {}
        SetComponentState(ComponentType::NETWORK_FILTER, ComponentState::STOPPED);

        try { ExploitPrevention::Instance().Stop(); } catch (...) {}
        SetComponentState(ComponentType::EXPLOIT_PREVENTION, ComponentState::STOPPED);

        try { FileIntegrityMonitor::Instance().Stop(); } catch (...) {}
        SetComponentState(ComponentType::FILE_INTEGRITY, ComponentState::STOPPED);

        try { AccessControlManager::Instance().Shutdown(); } catch (...) {}
        SetComponentState(ComponentType::ACCESS_CONTROL, ComponentState::STOPPED);

        try { ZeroHourProtection::Instance().Stop(); } catch (...) {}
        SetComponentState(ComponentType::ZERO_HOUR, ComponentState::STOPPED);

        Utils::Logger::Info(L"RealTimeProtection: Components stopped");
    }

    // =========================================================================
    // KERNEL EVENT HANDLERS
    // =========================================================================

    Communication::KernelVerdict OnKernelFileScan(const Communication::FileScanRequest& req) {
        auto startTime = std::chrono::high_resolution_clock::now();

        m_stats.totalEvents++;
        m_stats.fileEvents++;
        m_stats.totalScans++;
        m_performanceMetrics.kernelMessages++;

        if (m_state != ProtectionState::ACTIVE) {
            return Communication::KernelVerdict::Allow;
        }

        std::wstring filePath(req.fileName);

        // 1. Check Exclusions
        if (IsExcluded(filePath, req.header.processId)) {
            m_stats.excludedByPath++;
            return Communication::KernelVerdict::Allow;
        }

        // 2. Check Verdict Cache
        std::string hashKey;
        if (req.hashValid) {
            // Convert hash to hex string for cache lookup
            std::ostringstream oss;
            for (size_t i = 0; i < 32 && i < sizeof(req.hash); ++i) {
                oss << std::hex << std::setfill('0') << std::setw(2)
                    << static_cast<int>(req.hash[i]);
            }
            hashKey = oss.str();

            auto cached = CheckVerdictCache(hashKey);
            if (cached.has_value()) {
                m_performanceMetrics.cacheHits++;
                return MapScanVerdictToKernel(cached->verdict);
            }
            m_performanceMetrics.cacheMisses++;
        }

        // Anti-Evasion: Metamorphic Analysis
        if (m_metamorphicDetector) {
            auto metaResult = m_metamorphicDetector->AnalyzeFile(filePath);
            if (metaResult.isEvasive) {
                Utils::Logger::Warn(L"RealTimeProtection: Blocked metamorphic threat: {}", filePath);
                m_stats.threatsDetected++;
                return Communication::KernelVerdict::Block;
            }
        }

        // 3. Prepare Scan Context
        Core::Engine::ScanContext context;
        context.type = Core::Engine::ScanType::RealTime;
        context.priority = Core::Engine::ScanPriority::Critical;
        context.processId = req.header.processId;
        context.filePath = filePath;
        context.timeout = std::chrono::milliseconds(
            RTPConstants::KERNEL_REPLY_TIMEOUT_MS - 100);

        // 4. Perform Scan
        Core::Engine::EngineResult engineResult;
        try {
            engineResult = Core::Engine::ScanEngine::Instance().ScanFile(filePath, context);
        } catch (const std::exception& e) {
            Utils::Logger::Error(L"RealTimeProtection: Scan exception: {}",
                Utils::StringUtils::Utf8ToWide(e.what()));
            m_stats.scanErrors++;

            // Apply failure policy
            if (m_config.failurePolicy == FailurePolicy::FAIL_CLOSED) {
                return Communication::KernelVerdict::Block;
            }
            return Communication::KernelVerdict::Allow;
        }

        // 5. Map Result
        ScanResult scanResult = MapEngineResult(engineResult, filePath);

        // 6. Invoke file scan callbacks
        {
            std::shared_lock lock(m_callbackMutex);
            FileScanRequest rtpReq;
            rtpReq.filePath = filePath;
            rtpReq.pid = req.header.processId;

            for (const auto& [id, callback] : m_fileScanCallbacks) {
                try {
                    callback(rtpReq, scanResult);
                } catch (...) {}
            }
        }

        // 7. Update Cache
        if (!hashKey.empty()) {
            UpdateVerdictCache(hashKey, scanResult);
        }

        // 8. Update Statistics
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

        m_performanceMetrics.totalScans++;
        uint64_t currentAvg = m_performanceMetrics.avgScanTimeUs.load();
        uint64_t newAvg = (currentAvg * 9 + duration.count()) / 10;
        m_performanceMetrics.avgScanTimeUs.store(newAvg);

        if (duration.count() > m_performanceMetrics.maxScanTimeUs.load()) {
            m_performanceMetrics.maxScanTimeUs.store(duration.count());
        }

        // 9. Handle Threat
        if (scanResult.isThreat) {
            HandleThreatDetection(scanResult, filePath, req.header.processId);
        }

        // 10. Map to kernel verdict
        switch (engineResult.verdict) {
            case Core::Engine::ScanVerdict::Clean:
            case Core::Engine::ScanVerdict::Whitelisted:
                m_stats.cleanFiles++;
                return Communication::KernelVerdict::Allow;

            case Core::Engine::ScanVerdict::Infected:
                m_stats.infectedFiles++;
                m_stats.filesBlocked++;
                return Communication::KernelVerdict::Block;

            case Core::Engine::ScanVerdict::Suspicious:
                m_stats.suspiciousFiles++;
                if (m_config.mode >= ProtectionMode::BLOCK_SUSPICIOUS) {
                    m_stats.filesBlocked++;
                    return Communication::KernelVerdict::Block;
                }
                return Communication::KernelVerdict::Monitor;

            case Core::Engine::ScanVerdict::PUA:
                m_stats.puaFiles++;
                if (m_config.mode == ProtectionMode::BLOCK_UNKNOWN) {
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

        std::wstring imagePath(req.imagePath);

        // Check exclusions
        // Anti-Evasion Analysis
        if (req.isCreation) {
            bool evasionDetected = false;
            std::wstring detectionSource;

            // 1. Debugger Evasion
            if (m_debuggerDetector) {
                auto result = m_debuggerDetector->AnalyzeProcess(req.processId);
                if (result.isEvasive) {
                    evasionDetected = true;
                    detectionSource = L"Debugger Evasion";
                }
            }

            // 2. VM Evasion
            if (!evasionDetected && m_vmDetector) {
                ShadowStrike::AntiEvasion::VMEvasionResult result;
                if (m_vmDetector->AnalyzeProcessAntiVMBehavior(req.processId, result)) {
                    if (result.isEvasive) {
                        evasionDetected = true;
                        detectionSource = L"VM Evasion";
                    }
                }
            }

            // 3. Process Evasion
            if (!evasionDetected && m_processDetector) {
                auto result = m_processDetector->AnalyzeProcess(req.processId);
                if (result.isEvasive) {
                    evasionDetected = true;
                    detectionSource = L"Process Evasion";
                }
            }

            if (evasionDetected) {
                Utils::Logger::Warn(L"RealTimeProtection: Blocked evasion attempt: {} (PID: {}, Source: {})", 
                    imagePath, req.processId, detectionSource);
                m_stats.processesBlocked++;
                return Communication::KernelVerdict::Block;
            }
        }
        if (IsProcessExcluded(imagePath, req.processId)) {
            m_stats.excludedByProcess++;
            return Communication::KernelVerdict::Allow;
        }

        // Invoke process creation callbacks
        bool shouldBlock = false;
        {
            std::shared_lock lock(m_callbackMutex);
            ProcessNotifyRequest rtpReq;
            rtpReq.pid = req.processId;
            rtpReq.parentPid = req.parentProcessId;
            rtpReq.imagePath = imagePath;
            rtpReq.commandLine = std::wstring(req.commandLine);
            rtpReq.isCreation = req.isCreation;

            for (const auto& [id, callback] : m_processCreateCallbacks) {
                try {
                    callback(rtpReq, shouldBlock);
                } catch (...) {}
            }
        }

        if (shouldBlock) {
            m_stats.processesBlocked++;
            Utils::Logger::Warn(L"RealTimeProtection: Blocked process creation: {} (PID: {})",
                imagePath, req.processId);
            return Communication::KernelVerdict::Block;
        }

        // If configured, scan the process image
        if (m_config.scanOnExecute && req.isCreation) {
            try {
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

            } catch (...) {
                // Continue on scan failure
            }
        }

        return Communication::KernelVerdict::Allow;
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
        Utils::Logger::Info(L"RealTimeProtection: Added path exclusion: {}", path);
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
        Utils::Logger::Info(L"RealTimeProtection: Added process exclusion: {}", processName);
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
        Utils::Logger::Info(L"RealTimeProtection: Cleared all exclusions");
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
        m_performanceMetrics.cacheSize = 0;
        Utils::Logger::Info(L"RealTimeProtection: Verdict cache cleared");
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
            event.processPath = procPath.wstring();
            event.processName = procPath.filename().wstring();
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

        // Invoke threat detection callbacks
        {
            std::shared_lock lock(m_callbackMutex);
            for (const auto& [id, callback] : m_threatDetectionCallbacks) {
                try {
                    callback(event);
                } catch (...) {}
            }
        }

        // User notification
        if (m_config.notifyOnThreat) {
            NotifyUser(NotificationSeverity::THREAT_DETECTED,
                L"Threat Detected",
                std::format(L"Blocked: {} in {}", result.threatName, filePath),
                event);
        }

        Utils::Logger::Warn(L"RealTimeProtection: THREAT DETECTED - {} in {} (PID: {})",
            result.threatName, filePath, pid);
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
            result.errorMessage = Utils::StringUtils::Utf8ToWide(e.what());
        }

        return result;
    }

    ScanResult ScanProcess(uint32_t pid) {
        try {
            auto path = Utils::ProcessUtils::GetProcessPath(pid);
            return ScanFile(path.wstring(), ScanPriority::HIGH);
        } catch (const std::exception& e) {
            ScanResult result;
            result.verdict = KernelVerdict::ERROR;
            result.errorMessage = Utils::StringUtils::Utf8ToWide(e.what());
            return result;
        }
    }

    bool BlockProcess(uint32_t pid, bool terminate) {
        if (terminate) {
            if (Utils::ProcessUtils::TerminateProcess(pid)) {
                m_stats.processesTerminated++;
                Utils::Logger::Info(L"RealTimeProtection: Terminated process PID {}", pid);
                return true;
            }
        }
        return false;
    }

    bool QuarantineFile(const std::wstring& filePath, std::wstring_view threatName) {
        try {
            // Would call QuarantineManager
            // return Core::Engine::QuarantineManager::Instance().Quarantine(filePath, threatName);
            m_stats.filesQuarantined++;
            Utils::Logger::Info(L"RealTimeProtection: Quarantined file: {}", filePath);
            return true;
        } catch (...) {
            return false;
        }
    }

    bool BlockNetworkAddress(const std::wstring& address, uint16_t port, uint32_t durationMs) {
        try {
            auto& ntf = NetworkTrafficFilter::Instance();
            ntf.BlockIP(Utils::StringUtils::WideToUtf8(address));
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
        Utils::Logger::Info(L"RealTimeProtection: Health check thread started");

        while (!m_stopThreads) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(RTPConstants::HEALTH_CHECK_INTERVAL_MS));

            if (m_stopThreads) break;

            PerformHealthCheck();
        }

        Utils::Logger::Info(L"RealTimeProtection: Health check thread exiting");
    }

    void StatsUpdateLoop() {
        Utils::Logger::Info(L"RealTimeProtection: Stats update thread started");

        while (!m_stopThreads) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(RTPConstants::STATS_UPDATE_INTERVAL_MS));

            if (m_stopThreads) break;

            UpdatePerformanceMetrics();
        }

        Utils::Logger::Info(L"RealTimeProtection: Stats update thread exiting");
    }

    bool PerformHealthCheck() {
        bool allHealthy = true;

        // Check each component
        for (size_t i = 0; i < static_cast<size_t>(ComponentType::COMPONENT_COUNT); ++i) {
            auto& status = m_componentStatus[i];
            if (status.state == ComponentState::ERROR) {
                allHealthy = false;
                status.isHealthy = false;
            } else if (status.state == ComponentState::RUNNING) {
                status.isHealthy = true;
            }
        }

        // Update protection status
        m_protectionStatus.hasErrors = !allHealthy;
        m_protectionStatus.lastUpdate = Now();
        // Initialize Anti-Evasion Detectors
        try {
            m_debuggerDetector = std::make_unique<ShadowStrike::AntiEvasion::DebuggerEvasionDetector>();
            m_vmDetector = std::make_unique<ShadowStrike::AntiEvasion::VMEvasionDetector>();
            m_sandboxDetector = std::make_unique<ShadowStrike::AntiEvasion::SandboxEvasionDetector>();
            m_processDetector = std::make_unique<ShadowStrike::AntiEvasion::ProcessEvasionDetector>();
            m_metamorphicDetector = std::make_unique<ShadowStrike::AntiEvasion::MetamorphicDetector>();
        } catch (const std::exception& e) {
            Utils::Logger::Error(L"Failed to initialize Anti-Evasion detectors: {}", Utils::StringUtils::ToWideString(e.what()));
        }

        // Check if we should go to degraded mode
        if (!allHealthy && m_state == ProtectionState::ACTIVE) {
            int errorCount = 0;
            for (const auto& status : m_componentStatus) {
                if (status.state == ComponentState::ERROR) errorCount++;
            }

            if (errorCount >= 3) {
                SetState(ProtectionState::DEGRADED);
            }
        }

        return allHealthy;
    }

    void UpdatePerformanceMetrics() {
        // Update CPU usage (placeholder - would use SystemUtils)
        m_performanceMetrics.cpuUsagePercent = 5; // Placeholder

        // Update memory usage
        m_performanceMetrics.memoryUsageBytes = 0; // Would query actual usage

        // Update scans per second
        static uint64_t lastTotalScans = 0;
        static auto lastTime = Now();

        auto now = Now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastTime).count();
        if (elapsed > 0) {
            uint64_t currentScans = m_performanceMetrics.totalScans.load();
            m_performanceMetrics.scansPerSecond = (currentScans - lastTotalScans) / elapsed;
            lastTotalScans = currentScans;
            lastTime = now;
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

            // Invoke state change callbacks
            std::shared_lock lock(m_callbackMutex);
            for (const auto& [id, callback] : m_stateChangeCallbacks) {
                try {
                    callback(oldState, newState, L"");
                } catch (...) {}
            }

            Utils::Logger::Info(L"RealTimeProtection: State changed from {} to {}",
                Utils::StringUtils::Utf8ToWide(ProtectionStateToString(oldState)),
                Utils::StringUtils::Utf8ToWide(ProtectionStateToString(newState)));
        }
    }

    void SetComponentState(ComponentType component, ComponentState state) {
        size_t idx = static_cast<size_t>(component);
        if (idx >= m_componentStatus.size()) return;

        ComponentState oldState = m_componentStatus[idx].state;
        m_componentStatus[idx].state = state;
        m_componentStatus[idx].lastStateChange = Now();

        if (oldState != state) {
            // Invoke component status callbacks
            std::shared_lock lock(m_callbackMutex);
            for (const auto& [id, callback] : m_componentStatusCallbacks) {
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
        sr.threatName = Utils::StringUtils::Utf8ToWide(er.threatName);
        sr.confidence = er.confidence;
        sr.severity = er.severity;

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
                sr.verdict = (m_config.mode >= ProtectionMode::BLOCK_SUSPICIOUS) ?
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

        sr.detectedBySignature = er.detectedBySignature;
        sr.detectedByHeuristic = er.detectedByHeuristic;
        sr.detectedByBehavior = er.detectedByBehavior;
        sr.detectedByML = er.detectedByML;

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
        Utils::Logger::Info(L"RealTimeProtection: Starting diagnostics...");

        bool passed = true;

        // Check state
        if (m_state != ProtectionState::ACTIVE) {
            Utils::Logger::Warn(L"RealTimeProtection: Not in ACTIVE state");
            passed = false;
        }

        // Check components
        for (const auto& status : m_componentStatus) {
            if (status.state == ComponentState::ERROR) {
                Utils::Logger::Warn(L"RealTimeProtection: Component {} in ERROR state",
                    Utils::StringUtils::Utf8ToWide(ComponentTypeToString(status.type)));
                passed = false;
            }
        }

        // Check driver connection
        if (!m_protectionStatus.driverConnected) {
            Utils::Logger::Warn(L"RealTimeProtection: Kernel driver not connected");
        }

        Utils::Logger::Info(L"RealTimeProtection: Diagnostics {}",
            passed ? L"PASSED" : L"FAILED");
        return passed;
    }

    std::wstring GetDiagnosticSummary() const {
        std::wostringstream oss;
        oss << L"=== RealTimeProtection Diagnostic Summary ===\n";
        oss << L"State: " << Utils::StringUtils::Utf8ToWide(ProtectionStateToString(m_state.load())) << L"\n";
        oss << L"Protected: " << (m_protectionStatus.isProtected ? L"Yes" : L"No") << L"\n";
        oss << L"Driver Connected: " << (m_protectionStatus.driverConnected ? L"Yes" : L"No") << L"\n";
        oss << L"\n=== Components ===\n";

        for (const auto& status : m_componentStatus) {
            oss << Utils::StringUtils::Utf8ToWide(ComponentTypeToString(status.type))
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

    Utils::Logger::Info(L"RealTimeProtection: Configuration updated");
    return true;
}

RTPConfig RealTimeProtection::GetConfig() const {
    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}

void RealTimeProtection::SetProtectionMode(ProtectionMode mode) {
    m_impl->m_mode = mode;
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

uint64_t RealTimeProtection::RegisterFileScanCallback(FileScanCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = GenerateCallbackId();
    m_impl->m_fileScanCallbacks[id] = std::move(callback);
    return id;
}

uint64_t RealTimeProtection::RegisterProcessCreateCallback(ProcessCreateCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = GenerateCallbackId();
    m_impl->m_processCreateCallbacks[id] = std::move(callback);
    return id;
}

uint64_t RealTimeProtection::RegisterThreatDetectionCallback(ThreatDetectionCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = GenerateCallbackId();
    m_impl->m_threatDetectionCallbacks[id] = std::move(callback);
    return id;
}

uint64_t RealTimeProtection::RegisterStateChangeCallback(StateChangeCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = GenerateCallbackId();
    m_impl->m_stateChangeCallbacks[id] = std::move(callback);
    return id;
}

uint64_t RealTimeProtection::RegisterComponentStatusCallback(ComponentStatusCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    uint64_t id = GenerateCallbackId();
    m_impl->m_componentStatusCallbacks[id] = std::move(callback);
    return id;
}

uint64_t RealTimeProtection::RegisterNotificationCallback(UserNotificationCallback callback) {
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
    return MemoryProtection::Instance();
}

BehaviorBlocker& RealTimeProtection::GetBehaviorBlocker() {
    return BehaviorBlocker::Instance();
}

NetworkTrafficFilter& RealTimeProtection::GetNetworkTrafficFilter() {
    return NetworkTrafficFilter::Instance();
}

ExploitPrevention& RealTimeProtection::GetExploitPrevention() {
    return ExploitPrevention::Instance();
}

FileIntegrityMonitor& RealTimeProtection::GetFileIntegrityMonitor() {
    return FileIntegrityMonitor::Instance();
}

AccessControlManager& RealTimeProtection::GetAccessControlManager() {
    return AccessControlManager::Instance();
}

ZeroHourProtection& RealTimeProtection::GetZeroHourProtection() {
    return ZeroHourProtection::Instance();
}

} // namespace RealTime
} // namespace ShadowStrike
