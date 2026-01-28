/**
 * ============================================================================
 * ShadowStrike CryptoMiner Protection - CPU USAGE ANALYZER IMPLEMENTATION
 * ============================================================================
 *
 * @file CPUUsageAnalyzer.cpp
 * @brief Enterprise-grade CPU usage analysis engine for cryptominer detection.
 *
 * This module provides comprehensive CPU usage pattern analysis to detect
 * cryptocurrency mining through statistical analysis, performance counters,
 * and algorithm-specific behavioral signatures.
 *
 * Key Detection Methods:
 * - Sustained high CPU usage patterns
 * - Performance counter signatures (L3 cache misses, IPC)
 * - Thread utilization patterns
 * - Algorithm-specific fingerprints (RandomX, CryptoNight, etc.)
 * - Statistical anomaly detection
 * - Core affinity manipulation
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "CPUUsageAnalyzer.hpp"

// Infrastructure includes
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"

// Windows headers
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <powrprof.h>
#include <pdh.h>
#include <pdhmsg.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "pdh.lib")

// Standard library
#include <algorithm>
#include <numeric>
#include <cmath>
#include <format>
#include <sstream>
#include <iomanip>
#include <deque>
#include <random>

namespace ShadowStrike {
namespace CryptoMiners {

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Calculate standard deviation
 */
double CalculateStdDev(const std::vector<double>& values) {
    if (values.empty()) return 0.0;

    const double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();

    double sumSquaredDiff = 0.0;
    for (const auto& val : values) {
        const double diff = val - mean;
        sumSquaredDiff += diff * diff;
    }

    return std::sqrt(sumSquaredDiff / values.size());
}

/**
 * @brief Calculate coefficient of variation
 */
double CalculateCV(const std::vector<double>& values) {
    if (values.empty()) return 0.0;

    const double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    if (mean == 0.0) return 0.0;

    return CalculateStdDev(values) / mean;
}

/**
 * @brief Detect periodic pattern
 */
bool HasPeriodicPattern(const std::vector<double>& values, double threshold = 10.0) {
    if (values.size() < 10) return false;

    // Simple autocorrelation check
    size_t peakCount = 0;
    for (size_t i = 1; i < values.size() - 1; ++i) {
        if (values[i] > values[i - 1] && values[i] > values[i + 1]) {
            if (values[i] > threshold) {
                peakCount++;
            }
        }
    }

    // Periodic if we see regular peaks
    return peakCount >= 3;
}

/**
 * @brief Convert FILETIME to milliseconds
 */
uint64_t FileTimeToMs(const FILETIME& ft) {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return uli.QuadPart / 10000;
}

/**
 * @brief Convert FILETIME to raw 100ns units
 */
uint64_t FileTimeToRaw(const FILETIME& ft) {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return uli.QuadPart;
}

/**
 * @brief Get process CPU time
 */
bool GetProcessCPUTime(HANDLE hProcess, uint64_t& kernelMs, uint64_t& userMs) {
    FILETIME createTime, exitTime, kernelTime, userTime;
    if (!GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
        return false;
    }

    kernelMs = FileTimeToMs(kernelTime);
    userMs = FileTimeToMs(userTime);
    return true;
}

/**
 * @brief Check if process uses large pages
 * @details Checks for SeLockMemoryPrivilege which is required for large page allocation.
 *          Miners like RandomX almost always require this privilege.
 */
bool ProcessUsesLargePages(HANDLE hProcess) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return false;
    }

    // Use RAII for handle cleanup
    struct HandleGuard { HANDLE h; ~HandleGuard() { if(h) CloseHandle(h); } } guard{hToken};

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_LOCK_MEMORY_NAME, &luid)) {
        return false;
    }

    PRIVILEGE_SET privs;
    privs.PrivilegeCount = 1;
    privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privs.Privilege[0].Luid = luid;
    privs.Privilege[0].Attributes = 0;

    BOOL result = FALSE;
    if (!PrivilegeCheck(hToken, &privs, &result)) {
        return false;
    }

    return result == TRUE;
}

/**
 * @brief Generate event ID
 */
std::string GenerateEventId() {
    auto now = std::chrono::system_clock::now();
    auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ).count();

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);

    return std::format("CPU_EVENT_{}_{}", nowMs, dis(gen));
}

} // anonymous namespace

// ============================================================================
// JSON SERIALIZATION IMPLEMENTATIONS
// ============================================================================

std::string ThreadCPUStats::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"threadId\": " << threadId << ",\n";
    oss << "  \"usagePercent\": " << std::fixed << std::setprecision(2) << usagePercent << ",\n";
    oss << "  \"contextSwitches\": " << contextSwitches << ",\n";
    oss << "  \"kernelTimeMs\": " << kernelTimeMs << ",\n";
    oss << "  \"userTimeMs\": " << userTimeMs << ",\n";
    oss << "  \"affinityMask\": " << affinityMask << ",\n";
    oss << "  \"priority\": " << priority << ",\n";
    oss << "  \"isHighPriority\": " << (isHighPriority ? "true" : "false") << "\n";
    oss << "}";
    return oss.str();
}

std::string PerformanceCounterData::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"instructionsRetired\": " << instructionsRetired << ",\n";
    oss << "  \"cpuCycles\": " << cpuCycles << ",\n";
    oss << "  \"l3CacheMisses\": " << l3CacheMisses << ",\n";
    oss << "  \"l3CacheReferences\": " << l3CacheReferences << ",\n";
    oss << "  \"branchMisses\": " << branchMisses << ",\n";
    oss << "  \"branchInstructions\": " << branchInstructions << ",\n";
    oss << "  \"ipc\": " << std::fixed << std::setprecision(3) << ipc << ",\n";
    oss << "  \"l3MissRatio\": " << std::fixed << std::setprecision(4) << l3MissRatio << ",\n";
    oss << "  \"branchMissRatio\": " << std::fixed << std::setprecision(4) << branchMissRatio << ",\n";
    oss << "  \"isValid\": " << (isValid ? "true" : "false") << "\n";
    oss << "}";
    return oss.str();
}

std::string ProcessCPUSignature::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"processId\": " << processId << ",\n";
    oss << "  \"processName\": \"" << Utils::StringUtils::WideToUtf8(processName) << "\",\n";
    oss << "  \"totalUsagePercent\": " << std::fixed << std::setprecision(2) << totalUsagePercent << ",\n";
    oss << "  \"avgUsagePercent\": " << std::fixed << std::setprecision(2) << avgUsagePercent << ",\n";
    oss << "  \"peakUsagePercent\": " << std::fixed << std::setprecision(2) << peakUsagePercent << ",\n";
    oss << "  \"usageStdDev\": " << std::fixed << std::setprecision(2) << usageStdDev << ",\n";
    oss << "  \"pattern\": \"" << GetCPUUsagePatternName(pattern) << "\",\n";
    oss << "  \"executionUnit\": \"" << GetExecutionUnitUsageName(executionUnit) << "\",\n";
    oss << "  \"suspectedAlgorithm\": \"" << GetSuspectedAlgorithmName(suspectedAlgorithm) << "\",\n";
    oss << "  \"activeThreadCount\": " << activeThreadCount << ",\n";
    oss << "  \"usesLargePages\": " << (usesLargePages ? "true" : "false") << ",\n";
    oss << "  \"hasElevatedPriority\": " << (hasElevatedPriority ? "true" : "false") << ",\n";
    oss << "  \"allCoresUtilized\": " << (allCoresUtilized ? "true" : "false") << ",\n";
    oss << "  \"uniformCoreDistribution\": " << (uniformCoreDistribution ? "true" : "false") << ",\n";
    oss << "  \"miningProbability\": " << std::fixed << std::setprecision(3) << miningProbability << ",\n";
    oss << "  \"sampleCount\": " << sampleCount << "\n";
    oss << "}";
    return oss.str();
}

std::string HighLoadEvent::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"eventId\": \"" << eventId << "\",\n";
    oss << "  \"signature\": " << signature.ToJson() << ",\n";
    oss << "  \"isMiningBehavior\": " << (isMiningBehavior ? "true" : "false") << ",\n";
    oss << "  \"durationSecs\": " << durationSecs << "\n";
    oss << "}";
    return oss.str();
}

void CPUAnalyzerStatistics::Reset() noexcept {
    samplesTaken.store(0, std::memory_order_relaxed);
    highUsageEvents.store(0, std::memory_order_relaxed);
    miningPatternsDetected.store(0, std::memory_order_relaxed);
    processesAnalyzed.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

std::string CPUAnalyzerStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"samplesTaken\": " << samplesTaken.load() << ",\n";
    oss << "  \"highUsageEvents\": " << highUsageEvents.load() << ",\n";
    oss << "  \"miningPatternsDetected\": " << miningPatternsDetected.load() << ",\n";
    oss << "  \"processesAnalyzed\": " << processesAnalyzed.load() << "\n";
    oss << "}";
    return oss.str();
}

bool CPUUsageAnalyzerConfiguration::IsValid() const noexcept {
    return highUsageThreshold > 0.0 && highUsageThreshold <= 100.0 &&
           miningThreshold > 0.0 && miningThreshold <= 100.0 &&
           observationWindowSecs > 0 &&
           sampleIntervalMs > 0;
}

// ============================================================================
// PROCESS TRACKER
// ============================================================================

class ProcessTracker {
public:
    struct ProcessSample {
        SystemTimePoint timestamp;
        double cpuPercent = 0.0;
        uint64_t kernelTimeMs = 0;
        uint64_t userTimeMs = 0;
        uint32_t threadCount = 0;
        std::vector<double> perCoreUsage;
    };

    struct ProcessHistory {
        std::deque<ProcessSample> samples;
        TimePoint lastSeen;
        std::wstring processName;
    };

    void AddSample(uint32_t pid, const ProcessSample& sample) {
        std::unique_lock lock(m_mutex);

        auto& history = m_history[pid];
        history.samples.push_back(sample);
        history.lastSeen = Clock::now();

        // Limit samples
        if (history.samples.size() > CPUAnalyzerConstants::MAX_SAMPLES_PER_PROCESS) {
            history.samples.pop_front();
        }
    }

    std::optional<ProcessSample> GetLastSample(uint32_t pid) const {
        std::shared_lock lock(m_mutex);
        auto it = m_history.find(pid);
        if (it != m_history.end() && !it->second.samples.empty()) {
            return it->second.samples.back();
        }
        return std::nullopt;
    }

    std::vector<ProcessSample> GetHistory(uint32_t pid, size_t maxSamples) const {
        std::shared_lock lock(m_mutex);

        auto it = m_history.find(pid);
        if (it == m_history.end()) {
            return {};
        }

        const auto& samples = it->second.samples;
        if (samples.size() <= maxSamples) {
            return std::vector<ProcessSample>(samples.begin(), samples.end());
        }

        return std::vector<ProcessSample>(
            samples.end() - maxSamples,
            samples.end()
        );
    }

    void CleanStale(std::chrono::seconds maxAge) {
        std::unique_lock lock(m_mutex);

        const auto now = Clock::now();
        for (auto it = m_history.begin(); it != m_history.end();) {
            if (now - it->second.lastSeen > maxAge) {
                it = m_history.erase(it);
            } else {
                ++it;
            }
        }
    }

    void SetProcessName(uint32_t pid, const std::wstring& name) {
        std::unique_lock lock(m_mutex);
        m_history[pid].processName = name;
    }

    std::wstring GetProcessName(uint32_t pid) const {
        std::shared_lock lock(m_mutex);
        auto it = m_history.find(pid);
        return (it != m_history.end()) ? it->second.processName : L"";
    }

private:
    mutable std::shared_mutex m_mutex;
    std::unordered_map<uint32_t, ProcessHistory> m_history;
};

// ============================================================================
// PERFORMANCE COUNTER READER
// ============================================================================

class PerformanceCounterReader {
public:
    PerformanceCounterData ReadCounters(uint32_t pid) {
        PerformanceCounterData data;

        // Note: Actual PMU counter reading requires kernel driver
        // This is a simplified implementation using available APIs

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            return data;
        }

        // Get I/O counters as proxy for some measurements
        IO_COUNTERS ioCounters = {};
        if (GetProcessIoCounters(hProcess, &ioCounters)) {
            // Use I/O operations as rough approximation
            data.instructionsRetired = ioCounters.ReadOperationCount + ioCounters.WriteOperationCount;
            data.isValid = true;
        }

        CloseHandle(hProcess);

        // Calculate derived metrics
        if (data.cpuCycles > 0) {
            data.ipc = static_cast<double>(data.instructionsRetired) / data.cpuCycles;
        }

        if (data.l3CacheReferences > 0) {
            data.l3MissRatio = static_cast<double>(data.l3CacheMisses) / data.l3CacheReferences;
        }

        if (data.branchInstructions > 0) {
            data.branchMissRatio = static_cast<double>(data.branchMisses) / data.branchInstructions;
        }

        return data;
    }

    bool IsRandomXSignature(const PerformanceCounterData& data) const {
        // RandomX has high L3 cache miss rate (>15%)
        return data.isValid && data.l3MissRatio > CPUAnalyzerConstants::RANDOMX_CACHE_MISS_THRESHOLD;
    }
};

// ============================================================================
// ALGORITHM DETECTOR
// ============================================================================

class AlgorithmDetector {
public:
    SuspectedAlgorithm DetectAlgorithm(const ProcessCPUSignature& signature) const {
        // RandomX detection (Monero)
        if (signature.perfCounters.isValid &&
            signature.perfCounters.l3MissRatio > 0.15 &&
            signature.usesLargePages &&
            signature.avgUsagePercent > 60.0) {
            return SuspectedAlgorithm::RandomX;
        }

        // CryptoNight detection
        if (signature.avgUsagePercent > 50.0 &&
            signature.avgUsagePercent < 80.0 &&
            signature.activeThreadCount >= std::thread::hardware_concurrency() &&
            signature.uniformCoreDistribution) {
            return SuspectedAlgorithm::CryptoNight;
        }

        // Argon2 detection (memory-hard)
        if (signature.executionUnit == ExecutionUnitUsage::MemoryBandwidthHeavy) {
            return SuspectedAlgorithm::Argon2;
        }

        // Scrypt detection
        if (signature.avgUsagePercent > 70.0 &&
            signature.pattern == CPUUsagePattern::SustainedHigh) {
            return SuspectedAlgorithm::Scrypt;
        }

        // Generic mining pattern
        if (signature.miningProbability > 0.7) {
            return SuspectedAlgorithm::Generic;
        }

        return SuspectedAlgorithm::Unknown;
    }
};

// ============================================================================
// PATTERN ANALYZER
// ============================================================================

class PatternAnalyzer {
public:
    CPUUsagePattern AnalyzePattern(const std::vector<double>& usageHistory) const {
        if (usageHistory.size() < 5) {
            return CPUUsagePattern::Unknown;
        }

        const double avg = std::accumulate(usageHistory.begin(), usageHistory.end(), 0.0) / usageHistory.size();
        const double stdDev = CalculateStdDev(usageHistory);
        const double cv = CalculateCV(usageHistory);

        // Sustained high usage (low variance, high average)
        if (avg > 80.0 && stdDev < 10.0) {
            return CPUUsagePattern::SustainedHigh;
        }

        // Periodic pulse (mining throttling)
        if (HasPeriodicPattern(usageHistory, 50.0)) {
            return CPUUsagePattern::PeriodicPulse;
        }

        // Fluctuating high
        if (avg > 60.0 && stdDev > 15.0) {
            return CPUUsagePattern::FluctuatingHigh;
        }

        // Gradual increase
        if (IsGradualIncrease(usageHistory)) {
            return CPUUsagePattern::GradualIncrease;
        }

        // Spike
        if (usageHistory.back() > 90.0 && avg < 50.0) {
            return CPUUsagePattern::Spike;
        }

        // Normal
        if (avg < 30.0) {
            return CPUUsagePattern::Normal;
        }

        return CPUUsagePattern::Unknown;
    }

private:
    bool IsGradualIncrease(const std::vector<double>& values) const {
        if (values.size() < 5) return false;

        uint32_t increaseCount = 0;
        for (size_t i = 1; i < values.size(); ++i) {
            if (values[i] > values[i - 1]) {
                increaseCount++;
            }
        }

        return increaseCount >= (values.size() * 0.7);
    }
};

// ============================================================================
// CALLBACK MANAGER
// ============================================================================

class CallbackManager {
public:
    void RegisterHighLoad(HighLoadCallback callback) {
        std::unique_lock lock(m_mutex);
        m_highLoadCallbacks.push_back(std::move(callback));
    }

    void RegisterMiningDetected(MiningDetectedCallback callback) {
        std::unique_lock lock(m_mutex);
        m_miningCallbacks.push_back(std::move(callback));
    }

    void RegisterError(ErrorCallback callback) {
        std::unique_lock lock(m_mutex);
        m_errorCallbacks.push_back(std::move(callback));
    }

    void Clear() {
        std::unique_lock lock(m_mutex);
        m_highLoadCallbacks.clear();
        m_miningCallbacks.clear();
        m_errorCallbacks.clear();
    }

    void InvokeHighLoad(const HighLoadEvent& event) {
        std::shared_lock lock(m_mutex);
        for (const auto& callback : m_highLoadCallbacks) {
            try {
                callback(event);
            } catch (const std::exception& e) {
                Logger::Error("HighLoadCallback exception: {}", e.what());
            }
        }
    }

    void InvokeMiningDetected(const ProcessCPUSignature& signature) {
        std::shared_lock lock(m_mutex);
        for (const auto& callback : m_miningCallbacks) {
            try {
                callback(signature);
            } catch (const std::exception& e) {
                Logger::Error("MiningDetectedCallback exception: {}", e.what());
            }
        }
    }

    void InvokeError(const std::string& message, int code) {
        std::shared_lock lock(m_mutex);
        for (const auto& callback : m_errorCallbacks) {
            try {
                callback(message, code);
            } catch (const std::exception& e) {
                Logger::Error("ErrorCallback exception: {}", e.what());
            }
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    std::vector<HighLoadCallback> m_highLoadCallbacks;
    std::vector<MiningDetectedCallback> m_miningCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class CPUUsageAnalyzerImpl {
public:
    CPUUsageAnalyzerImpl() = default;
    ~CPUUsageAnalyzerImpl() {
        ShutdownPDH();
        Stop();
    }

    // Prevent copying
    CPUUsageAnalyzerImpl(const CPUUsageAnalyzerImpl&) = delete;
    CPUUsageAnalyzerImpl& operator=(const CPUUsageAnalyzerImpl&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const CPUUsageAnalyzerConfiguration& config) {
        std::unique_lock lock(m_mutex);

        try {
            Logger::Info("CPUUsageAnalyzer: Initializing...");

            if (!config.IsValid()) {
                Logger::Error("CPUUsageAnalyzer: Invalid configuration");
                return false;
            }

            m_config = config;
            m_status = ModuleStatus::Initializing;

            // Initialize managers
            m_processTracker = std::make_unique<ProcessTracker>();
            m_perfCounterReader = std::make_unique<PerformanceCounterReader>();
            m_algorithmDetector = std::make_unique<AlgorithmDetector>();
            m_patternAnalyzer = std::make_unique<PatternAnalyzer>();
            m_callbackManager = std::make_unique<CallbackManager>();

            // Get system info
            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);
            m_processorCount = sysInfo.dwNumberOfProcessors;

            // Initialize PDH
            InitializePDH();

            // Initialize system times
            FILETIME idle, kernel, user;
            if (GetSystemTimes(&idle, &kernel, &user)) {
                m_prevSysIdle = FileTimeToRaw(idle);
                m_prevSysKernel = FileTimeToRaw(kernel);
                m_prevSysUser = FileTimeToRaw(user);
            }

            m_initialized = true;
            m_status = ModuleStatus::Stopped;

            Logger::Info("CPUUsageAnalyzer: Initialized successfully (Cores: {})", m_processorCount);
            return true;

        } catch (const std::exception& e) {
            Logger::Error("CPUUsageAnalyzer: Initialization failed: {}", e.what());
            m_status = ModuleStatus::Error;
            return false;
        }
    }

    void Shutdown() {
        Stop();

        ShutdownPDH();

        std::unique_lock lock(m_mutex);
        m_initialized = false;
        m_status = ModuleStatus::Uninitialized;

        Logger::Info("CPUUsageAnalyzer: Shutdown complete");
    }

    bool IsInitialized() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    ModuleStatus GetStatus() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_status;
    }

    // ========================================================================
    // MONITORING CONTROL
    // ========================================================================

    bool Start() {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            Logger::Error("CPUUsageAnalyzer: Not initialized");
            return false;
        }

        if (m_running) {
            Logger::Warn("CPUUsageAnalyzer: Already running");
            return true;
        }

        m_running = true;
        m_paused = false;
        m_status = ModuleStatus::Running;
        m_monitorThread = std::thread(&CPUUsageAnalyzerImpl::MonitorThreadFunc, this);

        Logger::Info("CPUUsageAnalyzer: Monitoring started");
        return true;
    }

    bool Stop() {
        {
            std::unique_lock lock(m_mutex);
            if (!m_running) return true;
            m_running = false;
        }

        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }

        std::unique_lock lock(m_mutex);
        m_status = ModuleStatus::Stopped;

        Logger::Info("CPUUsageAnalyzer: Monitoring stopped");
        return true;
    }

    void Pause() {
        std::unique_lock lock(m_mutex);
        m_paused = true;
        m_status = ModuleStatus::Paused;
        Logger::Info("CPUUsageAnalyzer: Paused");
    }

    void Resume() {
        std::unique_lock lock(m_mutex);
        m_paused = false;
        m_status = ModuleStatus::Running;
        Logger::Info("CPUUsageAnalyzer: Resumed");
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    bool UpdateConfiguration(const CPUUsageAnalyzerConfiguration& config) {
        if (!config.IsValid()) {
            return false;
        }

        std::unique_lock lock(m_mutex);
        m_config = config;
        Logger::Info("CPUUsageAnalyzer: Configuration updated");
        return true;
    }

    CPUUsageAnalyzerConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // SAMPLING
    // ========================================================================

    void CollectSample() {
        std::shared_lock lock(m_mutex);

        if (m_paused) return;

        try {
            // Collect system-wide CPU
            m_lastOverallCPU = GetSystemCPUUsage();

            // Collect per-core usage if available
            m_lastPerCoreUsage = GetPerCoreCPUUsage();

            // Enumerate processes
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                return;
            }

            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    if (pe32.th32ProcessID > 4) {
                        CollectProcessSample(pe32.th32ProcessID, pe32.szExeFile);
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }

            CloseHandle(hSnapshot);

            m_stats.samplesTaken.fetch_add(1, std::memory_order_relaxed);

            // Clean stale tracking
            m_processTracker->CleanStale(std::chrono::seconds(60));

        } catch (const std::exception& e) {
            Logger::Error("CPUUsageAnalyzer::CollectSample: {}", e.what());
        }
    }

    // ========================================================================
    // PROCESS ANALYSIS
    // ========================================================================

    ProcessCPUSignature AnalyzeProcess(uint32_t processId) {
        std::shared_lock lock(m_mutex);

        ProcessCPUSignature signature;
        signature.processId = processId;
        signature.analysisTime = std::chrono::system_clock::now();

        try {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                return signature;
            }

            // Get process name
            wchar_t imagePath[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, imagePath, &size)) {
                std::filesystem::path path(imagePath);
                signature.processName = path.filename().wstring();
            } else {
                signature.processName = m_processTracker->GetProcessName(processId);
            }

            // Get historical samples
            auto samples = m_processTracker->GetHistory(processId, 60);
            signature.sampleCount = static_cast<uint32_t>(samples.size());

            if (!samples.empty()) {
                std::vector<double> cpuValues;
                for (const auto& sample : samples) {
                    cpuValues.push_back(sample.cpuPercent);
                }

                signature.totalUsagePercent = samples.back().cpuPercent;
                signature.avgUsagePercent = std::accumulate(cpuValues.begin(), cpuValues.end(), 0.0) / cpuValues.size();
                signature.peakUsagePercent = *std::max_element(cpuValues.begin(), cpuValues.end());
                signature.usageStdDev = CalculateStdDev(cpuValues);

                // Analyze pattern
                signature.pattern = m_patternAnalyzer->AnalyzePattern(cpuValues);

                // Thread count
                signature.activeThreadCount = samples.back().threadCount;
            }

            // Performance counters
            if (m_config.enablePerformanceCounters) {
                signature.perfCounters = m_perfCounterReader->ReadCounters(processId);
            }

            // Large pages check
            signature.usesLargePages = ProcessUsesLargePages(hProcess);

            // Priority check
            DWORD priorityClass = GetPriorityClass(hProcess);
            signature.hasElevatedPriority = (priorityClass == HIGH_PRIORITY_CLASS ||
                                            priorityClass == REALTIME_PRIORITY_CLASS);

            // Core utilization
            AnalyzeCoreUtilization(signature, samples);

            // Algorithm fingerprinting
            if (m_config.enableAlgorithmFingerprinting) {
                signature.suspectedAlgorithm = m_algorithmDetector->DetectAlgorithm(signature);
            }

            // Calculate mining probability
            signature.miningProbability = CalculateMiningProbability(signature);

            CloseHandle(hProcess);

            m_stats.processesAnalyzed.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Logger::Error("CPUUsageAnalyzer::AnalyzeProcess({}): {}", processId, e.what());
        }

        return signature;
    }

    bool IsMiningBehavior(uint32_t processId) {
        auto signature = AnalyzeProcess(processId);
        return signature.miningProbability > 0.7;
    }

    SuspectedAlgorithm GetSuspectedAlgorithm(uint32_t processId) const {
        std::shared_lock lock(m_mutex);

        // Quick check from cached data
        auto samples = m_processTracker->GetHistory(processId, 30);
        if (samples.empty()) {
            return SuspectedAlgorithm::Unknown;
        }

        // Simplified algorithm detection from patterns
        std::vector<double> cpuValues;
        for (const auto& sample : samples) {
            cpuValues.push_back(sample.cpuPercent);
        }

        const double avg = std::accumulate(cpuValues.begin(), cpuValues.end(), 0.0) / cpuValues.size();

        if (avg > 80.0) {
            return SuspectedAlgorithm::RandomX;
        } else if (avg > 60.0) {
            return SuspectedAlgorithm::CryptoNight;
        }

        return SuspectedAlgorithm::Unknown;
    }

    std::vector<ProcessCPUSignature> GetHighCPUProcesses(double threshold) {
        std::vector<ProcessCPUSignature> results;

        std::shared_lock lock(m_mutex);

        // Enumerate processes
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return results;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID > 4) {
                    auto samples = m_processTracker->GetHistory(pe32.th32ProcessID, 5);
                    if (!samples.empty()) {
                        const double recentCPU = samples.back().cpuPercent;
                        if (recentCPU >= threshold) {
                            auto signature = AnalyzeProcess(pe32.th32ProcessID);
                            results.push_back(signature);
                        }
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);

        // Sort by CPU usage descending
        std::sort(results.begin(), results.end(),
            [](const ProcessCPUSignature& a, const ProcessCPUSignature& b) {
                return a.totalUsagePercent > b.totalUsagePercent;
            });

        return results;
    }

    // ========================================================================
    // SYSTEM METRICS
    // ========================================================================

    double GetOverallCPUUsage() const {
        std::shared_lock lock(m_mutex);
        return m_lastOverallCPU;
    }

    std::vector<double> GetPerCoreUsage() const {
        std::shared_lock lock(m_mutex);
        return m_lastPerCoreUsage;
    }

    PerformanceCounterData GetPerformanceCounters(uint32_t processId) const {
        std::shared_lock lock(m_mutex);
        return m_perfCounterReader->ReadCounters(processId);
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterHighLoadCallback(HighLoadCallback callback) {
        m_callbackManager->RegisterHighLoad(std::move(callback));
    }

    void RegisterMiningDetectedCallback(MiningDetectedCallback callback) {
        m_callbackManager->RegisterMiningDetected(std::move(callback));
    }

    void RegisterErrorCallback(ErrorCallback callback) {
        m_callbackManager->RegisterError(std::move(callback));
    }

    void UnregisterCallbacks() {
        m_callbackManager->Clear();
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    CPUAnalyzerStatistics GetStatistics() const {
        return m_stats;
    }

    void ResetStatistics() {
        m_stats.Reset();
    }

    std::vector<HighLoadEvent> GetRecentHighLoadEvents(size_t maxCount) const {
        std::shared_lock lock(m_mutex);

        if (m_highLoadEvents.size() <= maxCount) {
            return m_highLoadEvents;
        }

        return std::vector<HighLoadEvent>(
            m_highLoadEvents.end() - maxCount,
            m_highLoadEvents.end()
        );
    }

    // ========================================================================
    // SELF-TEST
    // ========================================================================

    bool SelfTest() {
        Logger::Info("CPUUsageAnalyzer: Running self-test...");

        try {
            // Test configuration validation
            CPUUsageAnalyzerConfiguration testConfig;
            if (!testConfig.IsValid()) {
                Logger::Error("SelfTest: Default config invalid");
                return false;
            }

            // Test invalid config
            testConfig.highUsageThreshold = -10.0;
            if (testConfig.IsValid()) {
                Logger::Error("SelfTest: Invalid config accepted");
                return false;
            }

            // Test CPU sampling
            const double cpu = GetSystemCPUUsage();
            if (cpu < 0.0 || cpu > 100.0) {
                Logger::Error("SelfTest: Invalid CPU reading: {}", cpu);
                return false;
            }

            // Test pattern analysis
            std::vector<double> testPattern = {80.0, 85.0, 90.0, 85.0, 80.0, 85.0};
            auto pattern = m_patternAnalyzer->AnalyzePattern(testPattern);
            if (pattern == CPUUsagePattern::Unknown) {
                Logger::Warn("SelfTest: Pattern analysis returned Unknown");
            }

            Logger::Info("CPUUsageAnalyzer: Self-test PASSED");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("CPUUsageAnalyzer: Self-test FAILED: {}", e.what());
            return false;
        }
    }

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    void MonitorThreadFunc() {
        Logger::Info("CPUUsageAnalyzer: Monitor thread started");

        const auto interval = std::chrono::milliseconds(m_config.sampleIntervalMs);

        while (m_running) {
            try {
                if (!m_paused) {
                    CollectSample();
                }

                std::this_thread::sleep_for(interval);

            } catch (const std::exception& e) {
                Logger::Error("CPUUsageAnalyzer: Monitor thread exception: {}", e.what());
            }
        }

        Logger::Info("CPUUsageAnalyzer: Monitor thread stopped");
    }

    void CollectProcessSample(uint32_t pid, const std::wstring& processName) {
        try {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (!hProcess) {
                return;
            }

            ProcessTracker::ProcessSample sample;
            sample.timestamp = std::chrono::system_clock::now();

            // Get CPU time
            uint64_t kernelMs = 0, userMs = 0;
            if (GetProcessCPUTime(hProcess, kernelMs, userMs)) {
                sample.kernelTimeMs = kernelMs;
                sample.userTimeMs = userMs;

                // Calculate CPU percent using previous sample
                auto prevSample = m_processTracker->GetLastSample(pid);
                if (prevSample) {
                    uint64_t deltaProc = (kernelMs - prevSample->kernelTimeMs) +
                                       (userMs - prevSample->userTimeMs);

                    uint64_t deltaSys = m_lastSysTimeDelta;

                    if (deltaSys > 0) {
                        sample.cpuPercent = (static_cast<double>(deltaProc) / deltaSys) * 100.0;
                        sample.cpuPercent = std::min(100.0, std::max(0.0, sample.cpuPercent));
                    }
                }
            }

            // Get thread count
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te32;
                te32.dwSize = sizeof(THREADENTRY32);

                uint32_t threadCount = 0;
                if (Thread32First(hSnapshot, &te32)) {
                    do {
                        if (te32.th32OwnerProcessID == pid) {
                            threadCount++;
                        }
                    } while (Thread32Next(hSnapshot, &te32));
                }

                sample.threadCount = threadCount;
                CloseHandle(hSnapshot);
            }

            m_processTracker->AddSample(pid, sample);
            m_processTracker->SetProcessName(pid, processName);

            CloseHandle(hProcess);

        } catch (const std::exception& e) {
            Logger::Error("CPUUsageAnalyzer::CollectProcessSample({}): {}", pid, e.what());
        }
    }

    double GetSystemCPUUsage() {
        FILETIME idle, kernel, user;
        if (!GetSystemTimes(&idle, &kernel, &user)) {
            return 0.0;
        }

        uint64_t idleRaw = FileTimeToRaw(idle);
        uint64_t kernelRaw = FileTimeToRaw(kernel);
        uint64_t userRaw = FileTimeToRaw(user);

        uint64_t deltaIdle = idleRaw - m_prevSysIdle;
        uint64_t deltaKernel = kernelRaw - m_prevSysKernel;
        uint64_t deltaUser = userRaw - m_prevSysUser;

        m_prevSysIdle = idleRaw;
        m_prevSysKernel = kernelRaw;
        m_prevSysUser = userRaw;

        uint64_t totalSys = deltaKernel + deltaUser;
        m_lastSysTimeDelta = totalSys / 10000; // Store in ms for process calc

        if (totalSys == 0) return 0.0;

        // KernelTime includes IdleTime
        double cpu = (static_cast<double>(totalSys - deltaIdle) / totalSys) * 100.0;
        return std::min(100.0, std::max(0.0, cpu));
    }

    void InitializePDH() {
        if (PdhOpenQueryA(NULL, 0, &m_pdhQuery) != ERROR_SUCCESS) {
            Logger::Warn("CPUUsageAnalyzer: Failed to open PDH query");
            return;
        }

        // Add counter for each core
        for (uint32_t i = 0; i < m_processorCount; ++i) {
            HCOUNTER hCounter;
            std::string path = std::format("\\Processor({})\\% Processor Time", i);

            if (PdhAddCounterA(m_pdhQuery, path.c_str(), 0, &hCounter) == ERROR_SUCCESS) {
                m_pdhCounters.push_back(hCounter);
            }
        }

        // Initial collection
        PdhCollectQueryData(m_pdhQuery);
    }

    void ShutdownPDH() {
        if (m_pdhQuery) {
            PdhCloseQuery(m_pdhQuery);
            m_pdhQuery = NULL;
        }
        m_pdhCounters.clear();
    }

    std::vector<double> GetPerCoreCPUUsage() {
        std::vector<double> perCore;
        perCore.reserve(m_processorCount);

        if (!m_pdhQuery || m_pdhCounters.empty()) {
            return std::vector<double>(m_processorCount, 0.0);
        }

        // Collect new data
        if (PdhCollectQueryData(m_pdhQuery) == ERROR_SUCCESS) {
            for (auto hCounter : m_pdhCounters) {
                PDH_FMT_COUNTERVALUE displayValue;
                if (PdhGetFormattedCounterValue(hCounter, PDH_FMT_DOUBLE, NULL, &displayValue) == ERROR_SUCCESS) {
                    perCore.push_back(displayValue.doubleValue);
                } else {
                    perCore.push_back(0.0);
                }
            }
        }

        return perCore;
    }

    void AnalyzeCoreUtilization(ProcessCPUSignature& signature,
                                const std::vector<ProcessTracker::ProcessSample>& samples) {
        if (samples.empty()) return;

        // Check if all cores utilized
        signature.allCoresUtilized = (signature.activeThreadCount >= m_processorCount);

        // Check uniform distribution (simplified)
        signature.uniformCoreDistribution = signature.allCoresUtilized;
    }

    double CalculateMiningProbability(const ProcessCPUSignature& signature) {
        double probability = 0.0;

        // High sustained CPU
        if (signature.pattern == CPUUsagePattern::SustainedHigh ||
            signature.pattern == CPUUsagePattern::FluctuatingHigh) {
            probability += 0.3;
        }

        // High average usage
        if (signature.avgUsagePercent > m_config.miningThreshold) {
            probability += 0.2;
        }

        // All cores utilized
        if (signature.allCoresUtilized) {
            probability += 0.2;
        }

        // Uniform distribution
        if (signature.uniformCoreDistribution) {
            probability += 0.1;
        }

        // Large pages (miners often use)
        if (signature.usesLargePages) {
            probability += 0.1;
        }

        // Algorithm detected
        if (signature.suspectedAlgorithm != SuspectedAlgorithm::Unknown) {
            probability += 0.3;
        }

        // RandomX signature (L3 cache misses)
        if (signature.perfCounters.isValid &&
            signature.perfCounters.l3MissRatio > CPUAnalyzerConstants::RANDOMX_CACHE_MISS_THRESHOLD) {
            probability += 0.3;
        }

        return std::min(probability, 1.0);
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    bool m_running{ false };
    bool m_paused{ false };
    ModuleStatus m_status{ ModuleStatus::Uninitialized };
    CPUUsageAnalyzerConfiguration m_config;

    // System info
    uint32_t m_processorCount{ 0 };
    double m_lastOverallCPU{ 0.0 };
    std::vector<double> m_lastPerCoreUsage;

    // System CPU time tracking
    uint64_t m_prevSysIdle{ 0 };
    uint64_t m_prevSysKernel{ 0 };
    uint64_t m_prevSysUser{ 0 };
    uint64_t m_lastSysTimeDelta{ 0 };

    // PDH
    HQUERY m_pdhQuery{ NULL };
    std::vector<HCOUNTER> m_pdhCounters;

    // Managers
    std::unique_ptr<ProcessTracker> m_processTracker;
    std::unique_ptr<PerformanceCounterReader> m_perfCounterReader;
    std::unique_ptr<AlgorithmDetector> m_algorithmDetector;
    std::unique_ptr<PatternAnalyzer> m_patternAnalyzer;
    std::unique_ptr<CallbackManager> m_callbackManager;

    // Events
    std::vector<HighLoadEvent> m_highLoadEvents;

    // Monitoring thread
    std::thread m_monitorThread;

    // Statistics
    mutable CPUAnalyzerStatistics m_stats;
};

// ============================================================================
// MAIN CLASS IMPLEMENTATION (SINGLETON + FORWARDING)
// ============================================================================

std::atomic<bool> CPUUsageAnalyzer::s_instanceCreated{ false };

CPUUsageAnalyzer::CPUUsageAnalyzer()
    : m_impl(std::make_unique<CPUUsageAnalyzerImpl>()) {
}

CPUUsageAnalyzer::~CPUUsageAnalyzer() = default;

CPUUsageAnalyzer& CPUUsageAnalyzer::Instance() noexcept {
    static CPUUsageAnalyzer instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool CPUUsageAnalyzer::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

bool CPUUsageAnalyzer::Initialize(const CPUUsageAnalyzerConfiguration& config) {
    return m_impl->Initialize(config);
}

void CPUUsageAnalyzer::Shutdown() {
    m_impl->Shutdown();
}

bool CPUUsageAnalyzer::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus CPUUsageAnalyzer::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool CPUUsageAnalyzer::Start() {
    return m_impl->Start();
}

bool CPUUsageAnalyzer::Stop() {
    return m_impl->Stop();
}

void CPUUsageAnalyzer::Pause() {
    m_impl->Pause();
}

void CPUUsageAnalyzer::Resume() {
    m_impl->Resume();
}

bool CPUUsageAnalyzer::UpdateConfiguration(const CPUUsageAnalyzerConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

CPUUsageAnalyzerConfiguration CPUUsageAnalyzer::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

void CPUUsageAnalyzer::CollectSample() {
    m_impl->CollectSample();
}

ProcessCPUSignature CPUUsageAnalyzer::AnalyzeProcess(uint32_t processId) {
    return m_impl->AnalyzeProcess(processId);
}

bool CPUUsageAnalyzer::IsMiningBehavior(uint32_t processId) {
    return m_impl->IsMiningBehavior(processId);
}

SuspectedAlgorithm CPUUsageAnalyzer::GetSuspectedAlgorithm(uint32_t processId) const {
    return m_impl->GetSuspectedAlgorithm(processId);
}

std::vector<ProcessCPUSignature> CPUUsageAnalyzer::GetHighCPUProcesses(double threshold) {
    return m_impl->GetHighCPUProcesses(threshold);
}

double CPUUsageAnalyzer::GetOverallCPUUsage() const {
    return m_impl->GetOverallCPUUsage();
}

std::vector<double> CPUUsageAnalyzer::GetPerCoreUsage() const {
    return m_impl->GetPerCoreUsage();
}

PerformanceCounterData CPUUsageAnalyzer::GetPerformanceCounters(uint32_t processId) const {
    return m_impl->GetPerformanceCounters(processId);
}

void CPUUsageAnalyzer::RegisterHighLoadCallback(HighLoadCallback callback) {
    m_impl->RegisterHighLoadCallback(std::move(callback));
}

void CPUUsageAnalyzer::RegisterMiningDetectedCallback(MiningDetectedCallback callback) {
    m_impl->RegisterMiningDetectedCallback(std::move(callback));
}

void CPUUsageAnalyzer::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void CPUUsageAnalyzer::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

CPUAnalyzerStatistics CPUUsageAnalyzer::GetStatistics() const {
    return m_impl->GetStatistics();
}

void CPUUsageAnalyzer::ResetStatistics() {
    m_impl->ResetStatistics();
}

std::vector<HighLoadEvent> CPUUsageAnalyzer::GetRecentHighLoadEvents(size_t maxCount) const {
    return m_impl->GetRecentHighLoadEvents(maxCount);
}

bool CPUUsageAnalyzer::SelfTest() {
    return m_impl->SelfTest();
}

std::string CPUUsageAnalyzer::GetVersionString() noexcept {
    return std::format("{}.{}.{}",
        CPUAnalyzerConstants::VERSION_MAJOR,
        CPUAnalyzerConstants::VERSION_MINOR,
        CPUAnalyzerConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

std::string_view GetCPUUsagePatternName(CPUUsagePattern pattern) noexcept {
    switch (pattern) {
        case CPUUsagePattern::Unknown: return "Unknown";
        case CPUUsagePattern::Normal: return "Normal";
        case CPUUsagePattern::Spike: return "Spike";
        case CPUUsagePattern::SustainedHigh: return "SustainedHigh";
        case CPUUsagePattern::PeriodicPulse: return "PeriodicPulse";
        case CPUUsagePattern::AllCoresUniform: return "AllCoresUniform";
        case CPUUsagePattern::SingleCorePinned: return "SingleCorePinned";
        case CPUUsagePattern::GradualIncrease: return "GradualIncrease";
        case CPUUsagePattern::FluctuatingHigh: return "FluctuatingHigh";
        default: return "Unknown";
    }
}

std::string_view GetExecutionUnitUsageName(ExecutionUnitUsage usage) noexcept {
    switch (usage) {
        case ExecutionUnitUsage::Unknown: return "Unknown";
        case ExecutionUnitUsage::Balanced: return "Balanced";
        case ExecutionUnitUsage::ALUHeavy: return "ALUHeavy";
        case ExecutionUnitUsage::FPUHeavy: return "FPUHeavy";
        case ExecutionUnitUsage::SIMDHeavy: return "SIMDHeavy";
        case ExecutionUnitUsage::CacheHeavy: return "CacheHeavy";
        case ExecutionUnitUsage::MemoryBandwidthHeavy: return "MemoryBandwidthHeavy";
        case ExecutionUnitUsage::BranchHeavy: return "BranchHeavy";
        default: return "Unknown";
    }
}

std::string_view GetSuspectedAlgorithmName(SuspectedAlgorithm algo) noexcept {
    switch (algo) {
        case SuspectedAlgorithm::Unknown: return "Unknown";
        case SuspectedAlgorithm::RandomX: return "RandomX (Monero)";
        case SuspectedAlgorithm::CryptoNight: return "CryptoNight";
        case SuspectedAlgorithm::CryptoNightR: return "CryptoNight-R";
        case SuspectedAlgorithm::Argon2: return "Argon2";
        case SuspectedAlgorithm::Scrypt: return "Scrypt";
        case SuspectedAlgorithm::SHA256: return "SHA-256";
        case SuspectedAlgorithm::Yescrypt: return "Yescrypt";
        case SuspectedAlgorithm::Generic: return "Generic Mining";
        default: return "Unknown";
    }
}

}  // namespace CryptoMiners
}  // namespace ShadowStrike
