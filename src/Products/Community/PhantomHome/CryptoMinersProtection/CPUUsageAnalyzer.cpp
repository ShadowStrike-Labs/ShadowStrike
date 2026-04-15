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
#include "../../../../PhantomCore/Utils/Logger.hpp"
#include "../../../../PhantomCore/Utils/StringUtils.hpp"
#include "../../../../PhantomCore/Utils/ProcessUtils.hpp"
#include "../../../../PhantomCore/Utils/SystemUtils.hpp"

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
#pragma comment(lib, "ole32.lib")

// Standard library
#include <algorithm>
#include <numeric>
#include <cmath>
#include <condition_variable>
#include <format>
#include <sstream>
#include <iomanip>
#include <deque>
#include <filesystem>

namespace ShadowStrike {
namespace CryptoMiners {

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

constexpr size_t MAX_WORKING_SET_REGIONS_TO_SCAN = 4096;

/**
 * @brief RAII wrapper for Win32 HANDLE resources.
 * Automatically calls CloseHandle on destruction.
 */
struct ScopedHandle {
    HANDLE h = NULL;

    ScopedHandle() noexcept = default;
    explicit ScopedHandle(HANDLE handle) noexcept : h(handle) {}
    ~ScopedHandle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept : h(other.h) { other.h = NULL; }
    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            reset();
            h = other.h;
            other.h = NULL;
        }
        return *this;
    }

    explicit operator bool() const noexcept { return h != NULL && h != INVALID_HANDLE_VALUE; }
    [[nodiscard]] HANDLE get() const noexcept { return h; }

    void reset(HANDLE newHandle = NULL) noexcept {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = newHandle;
    }
};

/**
 * @brief Escape a UTF-8 string for safe JSON embedding.
 */
std::string EscapeJsonString(const std::string& input) {
    std::string output;
    output.reserve(input.size() + 16);
    for (const char c : input) {
        switch (c) {
            case '"':  output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    output += buf;
                } else {
                    output += c;
                }
        }
    }
    return output;
}

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
 * @brief Capture process timing snapshot.
 */
bool GetProcessTimingSnapshot(HANDLE hProcess,
                              uint64_t& startTimeRaw,
                              uint64_t& kernelMs,
                              uint64_t& userMs) {
    FILETIME createTime, exitTime, kernelTime, userTime;
    if (!GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
        return false;
    }

    startTimeRaw = FileTimeToRaw(createTime);
    kernelMs = FileTimeToMs(kernelTime);
    userMs = FileTimeToMs(userTime);
    return true;
}

/**
 * @brief Check if process has committed large pages in its working set.
 */
bool ProcessUsesLargePages(HANDLE hProcess) {
    const SIZE_T largePageMinimum = GetLargePageMinimum();
    if (largePageMinimum == 0) {
        return false;
    }

    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);

    auto* address = static_cast<std::byte*>(systemInfo.lpMinimumApplicationAddress);
    const auto maxAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);

    for (size_t regionsScanned = 0;
         reinterpret_cast<uintptr_t>(address) < maxAddress &&
         regionsScanned < MAX_WORKING_SET_REGIONS_TO_SCAN;
         ++regionsScanned) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            break;
        }

        const auto baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const auto nextAddress = baseAddress + static_cast<uintptr_t>(mbi.RegionSize);
        if (nextAddress <= baseAddress) {
            break;
        }

        if (mbi.State == MEM_COMMIT && mbi.RegionSize >= largePageMinimum) {
            PSAPI_WORKING_SET_EX_INFORMATION workingSetInfo{};
            workingSetInfo.VirtualAddress = mbi.BaseAddress;

            if (QueryWorkingSetEx(hProcess, &workingSetInfo, sizeof(workingSetInfo)) != FALSE &&
                workingSetInfo.VirtualAttributes.Valid &&
                workingSetInfo.VirtualAttributes.LargePage) {
                return true;
            }
        }

        address = reinterpret_cast<std::byte*>(nextAddress);
    }

    return false;
}

/**
 * @brief Generate a non-predictable correlation identifier for high-load events.
 */
std::string GenerateEventId() {
    GUID guid{};
    if (FAILED(::CoCreateGuid(&guid))) {
        return {};
    }

    return std::format(
        "CPU_EVENT_{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        guid.Data1,
        guid.Data2,
        guid.Data3,
        guid.Data4[0],
        guid.Data4[1],
        guid.Data4[2],
        guid.Data4[3],
        guid.Data4[4],
        guid.Data4[5],
        guid.Data4[6],
        guid.Data4[7]);
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
    oss << "  \"processName\": \"" << EscapeJsonString(Utils::StringUtils::ToNarrow(processName)) << "\",\n";
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
    oss << "  \"eventId\": \"" << EscapeJsonString(eventId) << "\",\n";
    oss << "  \"signature\": " << signature.ToJson() << ",\n";
    oss << "  \"isMiningBehavior\": " << (isMiningBehavior ? "true" : "false") << ",\n";
    oss << "  \"durationSecs\": " << durationSecs << "\n";
    oss << "}";
    return oss.str();
}

CPUAnalyzerStatistics::CPUAnalyzerStatistics(const CPUAnalyzerStatistics& other) noexcept
    : samplesTaken(other.samplesTaken.load(std::memory_order_relaxed)),
      highUsageEvents(other.highUsageEvents.load(std::memory_order_relaxed)),
      miningPatternsDetected(other.miningPatternsDetected.load(std::memory_order_relaxed)),
      processesAnalyzed(other.processesAnalyzed.load(std::memory_order_relaxed)),
      startTime(other.startTime) {
}

CPUAnalyzerStatistics& CPUAnalyzerStatistics::operator=(
    const CPUAnalyzerStatistics& other) noexcept {
    if (this != &other) {
        samplesTaken.store(other.samplesTaken.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        highUsageEvents.store(other.highUsageEvents.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        miningPatternsDetected.store(other.miningPatternsDetected.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        processesAnalyzed.store(other.processesAnalyzed.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        startTime = other.startTime;
    }

    return *this;
}

CPUAnalyzerStatistics::CPUAnalyzerStatistics(CPUAnalyzerStatistics&& other) noexcept
    : CPUAnalyzerStatistics(static_cast<const CPUAnalyzerStatistics&>(other)) {
}

CPUAnalyzerStatistics& CPUAnalyzerStatistics::operator=(CPUAnalyzerStatistics&& other) noexcept {
    return operator=(static_cast<const CPUAnalyzerStatistics&>(other));
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
           observationWindowSecs > 0 && observationWindowSecs <= 3600 &&
           sampleIntervalMs > 0 && sampleIntervalMs <= 60000;
}

// ============================================================================
// PROCESS TRACKER
// ============================================================================

class ProcessTracker {
public:
    struct ProcessSample {
        SystemTimePoint timestamp;
        double cpuPercent = 0.0;
        uint64_t processStartTimeRaw = 0;
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

        // Enforce max tracked processes: reject new PIDs at capacity
        if (m_history.find(pid) == m_history.end() &&
            m_history.size() >= CPUAnalyzerConstants::MAX_TRACKED_PROCESSES) {
            return;
        }

        auto& history = m_history[pid];
        history.samples.push_back(sample);
        history.lastSeen = Clock::now();

        // Limit samples per process
        if (history.samples.size() > CPUAnalyzerConstants::MAX_SAMPLES_PER_PROCESS) {
            history.samples.pop_front();
        }
    }

    [[nodiscard]] std::optional<ProcessSample> GetLastSample(uint32_t pid) const {
        std::shared_lock lock(m_mutex);
        auto it = m_history.find(pid);
        if (it != m_history.end() && !it->second.samples.empty()) {
            return it->second.samples.back();
        }
        return std::nullopt;
    }

    [[nodiscard]] std::vector<ProcessSample> GetHistory(uint32_t pid, size_t maxSamples) const {
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

    [[nodiscard]] std::vector<uint32_t> GetTrackedPids() const {
        std::shared_lock lock(m_mutex);
        std::vector<uint32_t> pids;
        pids.reserve(m_history.size());
        for (const auto& [pid, _] : m_history) {
            pids.push_back(pid);
        }
        return pids;
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
        auto it = m_history.find(pid);
        if (it != m_history.end()) {
            it->second.processName = name;
        }
    }

    [[nodiscard]] std::wstring GetProcessName(uint32_t pid) const {
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
    /**
     * @brief Read hardware performance counters for a process.
     *
     * Real PMU counter reading (IPC, L3 cache misses, branch prediction)
     * requires kernel driver support (e.g., via ETW or custom driver).
     * User-mode APIs do not expose these metrics. Returns invalid data
     * so callers can correctly skip PMU-dependent analysis paths.
     */
    [[nodiscard]] PerformanceCounterData ReadCounters([[maybe_unused]] uint32_t pid) const {
        PerformanceCounterData data;
        // isValid remains false: no real PMU data available from user mode.
        // Callers must check isValid before using any counter fields.
        return data;
    }

    [[nodiscard]] bool IsRandomXSignature(const PerformanceCounterData& data) const {
        return data.isValid && data.l3MissRatio > CPUAnalyzerConstants::RANDOMX_CACHE_MISS_THRESHOLD;
    }
};

// ============================================================================
// ALGORITHM DETECTOR
// ============================================================================

class AlgorithmDetector {
public:
    [[nodiscard]] SuspectedAlgorithm DetectAlgorithm(const ProcessCPUSignature& signature) const {
        // RandomX detection (Monero): high L3 cache misses + large pages + high CPU
        if (signature.perfCounters.isValid &&
            signature.perfCounters.l3MissRatio > 0.15 &&
            signature.usesLargePages &&
            signature.avgUsagePercent > 60.0) {
            return SuspectedAlgorithm::RandomX;
        }

        // CryptoNight detection: moderate CPU, all cores, uniform distribution
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
    [[nodiscard]] CPUUsagePattern AnalyzePattern(const std::vector<double>& usageHistory) const {
        if (usageHistory.size() < 5) {
            return CPUUsagePattern::Unknown;
        }

        const double avg = std::accumulate(usageHistory.begin(), usageHistory.end(), 0.0) / usageHistory.size();
        const double stdDev = CalculateStdDev(usageHistory);

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
    [[nodiscard]] bool IsGradualIncrease(const std::vector<double>& values) const {
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
        if (!callback) {
            return;
        }

        std::unique_lock lock(m_mutex);
        m_highLoadCallbacks.push_back(std::move(callback));
    }

    void RegisterMiningDetected(CPUMiningDetectedCallback callback) {
        if (!callback) {
            return;
        }

        std::unique_lock lock(m_mutex);
        m_miningCallbacks.push_back(std::move(callback));
    }

    void RegisterError(ErrorCallback callback) {
        if (!callback) {
            return;
        }

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
        const auto callbacks = SnapshotCallbacks(m_highLoadCallbacks);
        for (const auto& callback : callbacks) {
            try {
                callback(event);
            } catch (const std::exception& e) {
                Utils::Logger::Error("CPUUsageAnalyzer: HighLoadCallback exception: {}",
                    e.what());
            }
        }
    }

    void InvokeMiningDetected(const ProcessCPUSignature& signature) {
        const auto callbacks = SnapshotCallbacks(m_miningCallbacks);
        for (const auto& callback : callbacks) {
            try {
                callback(signature);
            } catch (const std::exception& e) {
                Utils::Logger::Error("CPUUsageAnalyzer: CPUMiningDetectedCallback exception: {}",
                    e.what());
            }
        }
    }

    void InvokeError(const std::string& message, int code) {
        const auto callbacks = SnapshotCallbacks(m_errorCallbacks);
        for (const auto& callback : callbacks) {
            try {
                callback(message, code);
            } catch (const std::exception& e) {
                Utils::Logger::Error("CPUUsageAnalyzer: ErrorCallback exception: {}",
                    e.what());
            }
        }
    }

private:
    template <typename CallbackType>
    [[nodiscard]] std::vector<CallbackType> SnapshotCallbacks(
        const std::vector<CallbackType>& callbacks) const {
        std::shared_lock lock(m_mutex);
        return callbacks;
    }

    mutable std::shared_mutex m_mutex;
    std::vector<HighLoadCallback> m_highLoadCallbacks;
    std::vector<CPUMiningDetectedCallback> m_miningCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class CPUUsageAnalyzerImpl {
public:
    CPUUsageAnalyzerImpl() = default;

    ~CPUUsageAnalyzerImpl() {
        // Stop monitor thread first - it may reference PDH and other resources
        Stop();
        ShutdownPDH();
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
            Utils::Logger::Info("CPUUsageAnalyzer: Initializing...");

            if (m_initialized) {
                Utils::Logger::Warn("CPUUsageAnalyzer: Already initialized");
                return true;
            }

            if (!config.IsValid()) {
                Utils::Logger::Error("CPUUsageAnalyzer: Invalid configuration");
                lock.unlock();
                ReportError("Invalid CPU usage analyzer configuration", ERROR_INVALID_PARAMETER);
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

            // Initialize PDH for per-core CPU monitoring
            InitializePDH();

            // Initialize system times baseline
            FILETIME idle, kernel, user;
            if (GetSystemTimes(&idle, &kernel, &user)) {
                m_prevSysIdle = FileTimeToRaw(idle);
                m_prevSysKernel = FileTimeToRaw(kernel);
                m_prevSysUser = FileTimeToRaw(user);
            }

            m_highLoadEvents.clear();
            m_lastAlertedPids.clear();
            m_stats.Reset();
            m_initialized = true;
            m_status = ModuleStatus::Stopped;

            Utils::Logger::Info("CPUUsageAnalyzer: Initialized successfully (Cores: {})",
                m_processorCount);
            return true;

        } catch (const std::exception& e) {
            Utils::Logger::Error("CPUUsageAnalyzer: Initialization failed: {}",
                e.what());
            m_status = ModuleStatus::Error;
            lock.unlock();
            ReportError("CPU usage analyzer initialization failed", ERROR_GEN_FAILURE);
            return false;
        }
    }

    void Shutdown() {
        Stop();

        ShutdownPDH();

        std::unique_lock lock(m_mutex);
        m_initialized = false;
        m_status = ModuleStatus::Uninitialized;

        Utils::Logger::Info("CPUUsageAnalyzer: Shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_status;
    }

    // ========================================================================
    // MONITORING CONTROL
    // ========================================================================

    bool Start() {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            Utils::Logger::Error("CPUUsageAnalyzer: Cannot start - not initialized");
            lock.unlock();
            ReportError("CPU usage analyzer start rejected because the module is not initialized",
                ERROR_NOT_READY);
            return false;
        }

        if (m_running.load(std::memory_order_acquire)) {
            Utils::Logger::Warn("CPUUsageAnalyzer: Already running");
            return true;
        }

        m_running.store(true, std::memory_order_release);
        m_paused.store(false, std::memory_order_release);
        m_status = ModuleStatus::Running;
        m_monitorThread = std::thread(&CPUUsageAnalyzerImpl::MonitorThreadFunc, this);

        Utils::Logger::Info("CPUUsageAnalyzer: Monitoring started");
        return true;
    }

    bool Stop() {
        // Signal the thread to stop (atomic, no lock needed)
        bool wasRunning = m_running.exchange(false, std::memory_order_acq_rel);
        if (!wasRunning) return true;

        {
            std::unique_lock lock(m_mutex);
            m_status = ModuleStatus::Stopping;
        }
        m_monitorWakeup.notify_all();

        // Join outside lock to avoid deadlock with monitor thread
        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }

        std::unique_lock lock(m_mutex);
        m_status = ModuleStatus::Stopped;

        Utils::Logger::Info("CPUUsageAnalyzer: Monitoring stopped");
        return true;
    }

    void Pause() {
        {
            std::shared_lock lock(m_mutex);
            if (!m_initialized || m_status != ModuleStatus::Running) {
                Utils::Logger::Warn("CPUUsageAnalyzer: Pause rejected — module is not running");
                return;
            }
        }

        m_paused.store(true, std::memory_order_release);
        m_monitorWakeup.notify_all();

        std::unique_lock lock(m_mutex);
        m_status = ModuleStatus::Paused;
        Utils::Logger::Info("CPUUsageAnalyzer: Paused");
    }

    void Resume() {
        {
            std::shared_lock lock(m_mutex);
            if (!m_initialized || m_status != ModuleStatus::Paused) {
                Utils::Logger::Warn("CPUUsageAnalyzer: Resume rejected — module is not paused");
                return;
            }
        }

        m_paused.store(false, std::memory_order_release);
        m_monitorWakeup.notify_all();

        std::unique_lock lock(m_mutex);
        m_status = ModuleStatus::Running;
        Utils::Logger::Info("CPUUsageAnalyzer: Resumed");
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    bool UpdateConfiguration(const CPUUsageAnalyzerConfiguration& config) {
        if (!config.IsValid()) {
            Utils::Logger::Error("CPUUsageAnalyzer: Invalid configuration update rejected");
            ReportError("CPU usage analyzer configuration update rejected", ERROR_INVALID_PARAMETER);
            return false;
        }

        std::unique_lock lock(m_mutex);
        m_config = config;
        Utils::Logger::Info("CPUUsageAnalyzer: Configuration updated");
        lock.unlock();
        m_monitorWakeup.notify_all();
        return true;
    }

    [[nodiscard]] CPUUsageAnalyzerConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // SAMPLING
    // ========================================================================

    void CollectSample() {
        if (m_paused.load(std::memory_order_acquire)) return;

        try {
            uint64_t systemDeltaMs = 0;
            {
                std::unique_lock lock(m_mutex);

                // Collect system-wide CPU
                m_lastOverallCPU = GetSystemCPUUsage();
                systemDeltaMs = m_lastSysTimeDelta;

                // Collect per-core usage
                m_lastPerCoreUsage = GetPerCoreCPUUsage();
            }

            // Enumerate processes with RAII snapshot
            ScopedHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
            if (!hSnapshot) {
                return;
            }

            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(hSnapshot.get(), &pe32)) {
                do {
                    if (pe32.th32ProcessID > 4) {
                        CollectProcessSample(pe32.th32ProcessID, pe32.szExeFile, systemDeltaMs);
                    }
                } while (Process32NextW(hSnapshot.get(), &pe32));
            }

            m_stats.samplesTaken.fetch_add(1, std::memory_order_relaxed);

            // Clean stale tracking data
            m_processTracker->CleanStale(std::chrono::seconds(60));

        } catch (const std::exception& e) {
            Utils::Logger::Error("CPUUsageAnalyzer::CollectSample: {}",
                e.what());
            ReportError("CPU usage analyzer sample collection failed", ERROR_GEN_FAILURE);
        }
    }

    // ========================================================================
    // PROCESS ANALYSIS
    // ========================================================================

    ProcessCPUSignature AnalyzeProcess(uint32_t processId) {
        std::shared_lock lock(m_mutex);
        return AnalyzeProcessUnlocked(processId);
    }

    bool IsMiningBehavior(uint32_t processId) {
        auto signature = AnalyzeProcess(processId);
        return signature.miningProbability > 0.7;
    }

    [[nodiscard]] SuspectedAlgorithm GetSuspectedAlgorithm(uint32_t processId) const {
        std::shared_lock lock(m_mutex);

        auto samples = m_processTracker->GetHistory(processId, 30);
        if (samples.empty()) {
            return SuspectedAlgorithm::Unknown;
        }

        // Build a partial signature from cached sample data
        ProcessCPUSignature signature;
        signature.processId = processId;

        std::vector<double> cpuValues;
        cpuValues.reserve(samples.size());
        for (const auto& sample : samples) {
            cpuValues.push_back(sample.cpuPercent);
        }

        signature.avgUsagePercent = std::accumulate(
            cpuValues.begin(), cpuValues.end(), 0.0) / cpuValues.size();
        signature.peakUsagePercent = *std::max_element(cpuValues.begin(), cpuValues.end());
        signature.activeThreadCount = samples.back().threadCount;
        signature.allCoresUtilized =
            (signature.avgUsagePercent >= 90.0 &&
             signature.activeThreadCount >= m_processorCount &&
             m_processorCount > 0);
        signature.uniformCoreDistribution = false;
        signature.pattern = m_patternAnalyzer->AnalyzePattern(cpuValues);
        signature.miningProbability = CalculateMiningProbability(signature);

        return m_algorithmDetector->DetectAlgorithm(signature);
    }

    std::vector<ProcessCPUSignature> GetHighCPUProcesses(double threshold) {
        std::vector<ProcessCPUSignature> results;

        std::shared_lock lock(m_mutex);

        // Enumerate processes with RAII snapshot
        ScopedHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!hSnapshot) {
            return results;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot.get(), &pe32)) {
            do {
                if (pe32.th32ProcessID > 4) {
                    auto samples = m_processTracker->GetHistory(pe32.th32ProcessID, 5);
                    if (!samples.empty()) {
                        const double recentCPU = samples.back().cpuPercent;
                        if (recentCPU >= threshold) {
                            // Use unlocked version to avoid recursive shared_lock deadlock
                            auto signature = AnalyzeProcessUnlocked(pe32.th32ProcessID);
                            results.push_back(std::move(signature));
                        }
                    }
                }
            } while (Process32NextW(hSnapshot.get(), &pe32));
        }

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

    [[nodiscard]] double GetOverallCPUUsage() const {
        std::shared_lock lock(m_mutex);
        return m_lastOverallCPU;
    }

    [[nodiscard]] std::vector<double> GetPerCoreUsage() const {
        std::shared_lock lock(m_mutex);
        return m_lastPerCoreUsage;
    }

    [[nodiscard]] PerformanceCounterData GetPerformanceCounters(uint32_t processId) const {
        std::shared_lock lock(m_mutex);
        return m_perfCounterReader->ReadCounters(processId);
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterHighLoadCallback(HighLoadCallback callback) {
        m_callbackManager->RegisterHighLoad(std::move(callback));
    }

    void RegisterMiningDetectedCallback(CPUMiningDetectedCallback callback) {
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

    [[nodiscard]] CPUAnalyzerStatistics GetStatistics() const {
        std::shared_lock lock(m_mutex);
        CPUAnalyzerStatistics snapshot;
        snapshot.samplesTaken.store(m_stats.samplesTaken.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        snapshot.highUsageEvents.store(m_stats.highUsageEvents.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        snapshot.miningPatternsDetected.store(
            m_stats.miningPatternsDetected.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        snapshot.processesAnalyzed.store(m_stats.processesAnalyzed.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        snapshot.startTime = m_stats.startTime;
        return snapshot;
    }

    void ResetStatistics() {
        std::unique_lock lock(m_mutex);
        m_stats.Reset();
    }

    [[nodiscard]] std::vector<HighLoadEvent> GetRecentHighLoadEvents(size_t maxCount) const {
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
        Utils::Logger::Info("CPUUsageAnalyzer: Running self-test...");

        try {
            // Test configuration validation
            CPUUsageAnalyzerConfiguration testConfig;
            if (!testConfig.IsValid()) {
                Utils::Logger::Error("CPUUsageAnalyzer: SelfTest - Default config invalid");
                return false;
            }

            // Test invalid config rejection
            testConfig.highUsageThreshold = -10.0;
            if (testConfig.IsValid()) {
                Utils::Logger::Error("CPUUsageAnalyzer: SelfTest - Invalid config accepted");
                return false;
            }

            // Test CPU sampling
            double cpu = 0.0;
            {
                std::unique_lock lock(m_mutex);
                cpu = GetSystemCPUUsage();
            }
            if (cpu < 0.0 || cpu > 100.0) {
                Utils::Logger::Error("CPUUsageAnalyzer: SelfTest - Invalid CPU reading: {:.2f}", cpu);
                return false;
            }

            // Test pattern analysis
            std::vector<double> testPattern = {80.0, 85.0, 90.0, 85.0, 80.0, 85.0};
            auto pattern = m_patternAnalyzer->AnalyzePattern(testPattern);
            if (pattern == CPUUsagePattern::Unknown) {
                Utils::Logger::Warn("CPUUsageAnalyzer: SelfTest - Pattern analysis returned Unknown");
            }

            Utils::Logger::Info("CPUUsageAnalyzer: Self-test PASSED");
            return true;

        } catch (const std::exception& e) {
            Utils::Logger::Error("CPUUsageAnalyzer: Self-test FAILED: {}",
                e.what());
            return false;
        }
    }

private:
    // ========================================================================
    // INTERNAL ANALYSIS (caller must hold at least shared_lock on m_mutex)
    // ========================================================================

    ProcessCPUSignature AnalyzeProcessUnlocked(uint32_t processId) {
        ProcessCPUSignature signature;
        signature.processId = processId;
        signature.analysisTime = std::chrono::system_clock::now();

        try {
            ScopedHandle hProcess(OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId));
            if (!hProcess) {
                return signature;
            }

            // Get process name
            wchar_t imagePath[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess.get(), 0, imagePath, &size)) {
                std::filesystem::path filePath(imagePath);
                signature.processName = filePath.filename().wstring();
            } else {
                signature.processName = m_processTracker->GetProcessName(processId);
            }

            // Get historical samples
            auto samples = m_processTracker->GetHistory(processId, 60);
            signature.sampleCount = static_cast<uint32_t>(samples.size());

            if (!samples.empty()) {
                std::vector<double> cpuValues;
                cpuValues.reserve(samples.size());
                for (const auto& sample : samples) {
                    cpuValues.push_back(sample.cpuPercent);
                }

                signature.totalUsagePercent = samples.back().cpuPercent;
                signature.avgUsagePercent = std::accumulate(
                    cpuValues.begin(), cpuValues.end(), 0.0) / cpuValues.size();
                signature.peakUsagePercent = *std::max_element(
                    cpuValues.begin(), cpuValues.end());
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
            signature.usesLargePages = ProcessUsesLargePages(hProcess.get());

            // Priority check
            DWORD priorityClass = GetPriorityClass(hProcess.get());
            signature.hasElevatedPriority = (priorityClass == HIGH_PRIORITY_CLASS ||
                                            priorityClass == REALTIME_PRIORITY_CLASS);

            // Core utilization analysis
            AnalyzeCoreUtilization(signature, samples);

            // Algorithm fingerprinting
            if (m_config.enableAlgorithmFingerprinting) {
                signature.suspectedAlgorithm = m_algorithmDetector->DetectAlgorithm(signature);
            }

            // Calculate mining probability
            signature.miningProbability = CalculateMiningProbability(signature);

            m_stats.processesAnalyzed.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Utils::Logger::Error("CPUUsageAnalyzer::AnalyzeProcess({}): {}",
                processId, e.what());
        }

        return signature;
    }

    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    void MonitorThreadFunc() {
        Utils::Logger::Info("CPUUsageAnalyzer: Monitor thread started");

        while (m_running.load(std::memory_order_acquire)) {
            try {
                if (!m_paused.load(std::memory_order_acquire)) {
                    CollectSample();
                    EvaluateAndNotify();
                }

                uint32_t sampleIntervalMs = CPUAnalyzerConstants::SAMPLE_INTERVAL_MS;
                {
                    std::shared_lock lock(m_mutex);
                    sampleIntervalMs = m_config.sampleIntervalMs;
                }

                std::unique_lock wakeLock(m_monitorWakeupMutex);
                m_monitorWakeup.wait_for(
                    wakeLock,
                    std::chrono::milliseconds(sampleIntervalMs),
                    [this]() { return !m_running.load(std::memory_order_acquire); });

            } catch (const std::exception& e) {
                Utils::Logger::Error("CPUUsageAnalyzer: Monitor thread exception: {}",
                    e.what());
                ReportError("CPU usage analyzer monitor thread faulted", ERROR_GEN_FAILURE);
            }
        }

        Utils::Logger::Info("CPUUsageAnalyzer: Monitor thread stopped");
    }

    /**
     * @brief Evaluate tracked processes and invoke callbacks for high CPU / mining.
     * Separate from CollectSample to keep sampling fast and decoupled from notifications.
     */
    void EvaluateAndNotify() {
        auto trackedPids = m_processTracker->GetTrackedPids();
        if (trackedPids.empty()) return;

        std::vector<HighLoadEvent> newEvents;
        std::vector<ProcessCPUSignature> miningSignatures;
        const auto now = Clock::now();
        CPUUsageAnalyzerConfiguration configSnapshot;

        {
            std::shared_lock lock(m_mutex);
            configSnapshot = m_config;

            for (const uint32_t pid : trackedPids) {
                auto samples = m_processTracker->GetHistory(pid, 5);
                if (samples.empty()) continue;

                const double recentCPU = samples.back().cpuPercent;
                if (recentCPU < configSnapshot.highUsageThreshold) continue;

                // Deduplicate: skip PIDs alerted within the observation window
                auto alertIt = m_lastAlertedPids.find(pid);
                if (alertIt != m_lastAlertedPids.end()) {
                    if (now - alertIt->second <
                        std::chrono::seconds(configSnapshot.observationWindowSecs)) {
                        continue;
                    }
                }

                auto signature = AnalyzeProcessUnlocked(pid);

                HighLoadEvent event;
                event.eventId = GenerateEventId();
                event.signature = signature;
                event.isMiningBehavior = (signature.miningProbability > 0.7);
                event.detectionTime = std::chrono::system_clock::now();
                event.durationSecs = static_cast<uint32_t>(
                    signature.sampleCount * configSnapshot.sampleIntervalMs / 1000);

                newEvents.push_back(std::move(event));

                if (signature.miningProbability > 0.7) {
                    miningSignatures.push_back(std::move(signature));
                }
            }
        }

        if (newEvents.empty()) return;

        // Store events and update alert dedup map under unique_lock
        {
            std::unique_lock lock(m_mutex);
            for (const auto& event : newEvents) {
                // Cap stored events — deque provides O(1) pop_front
                if (m_highLoadEvents.size() >= 1000) {
                    m_highLoadEvents.pop_front();
                }
                m_highLoadEvents.push_back(event);

                // Cap dedup map to prevent unbounded growth
                if (m_lastAlertedPids.size() < kMaxAlertedPids) {
                    m_lastAlertedPids[event.signature.processId] = now;
                }
            }

            // Clean stale dedup entries
            for (auto it = m_lastAlertedPids.begin(); it != m_lastAlertedPids.end();) {
                if (now - it->second >
                    std::chrono::seconds(configSnapshot.observationWindowSecs * 2)) {
                    it = m_lastAlertedPids.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // Invoke callbacks without holding m_mutex to avoid deadlock
        for (const auto& event : newEvents) {
            m_stats.highUsageEvents.fetch_add(1, std::memory_order_relaxed);
            m_callbackManager->InvokeHighLoad(event);
        }

        for (const auto& sig : miningSignatures) {
            m_stats.miningPatternsDetected.fetch_add(1, std::memory_order_relaxed);
            m_callbackManager->InvokeMiningDetected(sig);
        }
    }

    void CollectProcessSample(uint32_t pid,
                              const std::wstring& processName,
                              uint64_t systemDeltaMs) {
        try {
            ScopedHandle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
            if (!hProcess) {
                return;
            }

            ProcessTracker::ProcessSample sample;
            sample.timestamp = std::chrono::system_clock::now();

            // Get CPU time
            uint64_t processStartTimeRaw = 0;
            uint64_t kernelMs = 0;
            uint64_t userMs = 0;
            if (GetProcessTimingSnapshot(hProcess.get(), processStartTimeRaw, kernelMs, userMs)) {
                sample.processStartTimeRaw = processStartTimeRaw;
                sample.kernelTimeMs = kernelMs;
                sample.userTimeMs = userMs;

                // Calculate CPU percent using delta from previous sample
                auto prevSample = m_processTracker->GetLastSample(pid);
                if (prevSample &&
                    prevSample->processStartTimeRaw == processStartTimeRaw &&
                    kernelMs >= prevSample->kernelTimeMs &&
                    userMs >= prevSample->userTimeMs) {
                    uint64_t deltaProc = (kernelMs - prevSample->kernelTimeMs) +
                                       (userMs - prevSample->userTimeMs);

                    if (systemDeltaMs > 0) {
                        sample.cpuPercent =
                            (static_cast<double>(deltaProc) / static_cast<double>(systemDeltaMs)) *
                            100.0;
                        sample.cpuPercent = std::min(100.0, std::max(0.0, sample.cpuPercent));
                    }
                }
            }

            // Get thread count with RAII snapshot
            {
                ScopedHandle hThreadSnap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
                if (hThreadSnap) {
                    THREADENTRY32 te32;
                    te32.dwSize = sizeof(THREADENTRY32);

                    uint32_t threadCount = 0;
                    if (Thread32First(hThreadSnap.get(), &te32)) {
                        do {
                            if (te32.th32OwnerProcessID == pid) {
                                threadCount++;
                            }
                        } while (Thread32Next(hThreadSnap.get(), &te32));
                    }

                    sample.threadCount = threadCount;
                }
            }

            m_processTracker->AddSample(pid, sample);
            m_processTracker->SetProcessName(pid, processName);

        } catch (const std::exception& e) {
            Utils::Logger::Error("CPUUsageAnalyzer::CollectProcessSample({}): {}",
                pid, e.what());
            ReportError("CPU usage analyzer failed to sample a process", ERROR_GEN_FAILURE);
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

        if (idleRaw < m_prevSysIdle ||
            kernelRaw < m_prevSysKernel ||
            userRaw < m_prevSysUser) {
            m_prevSysIdle = idleRaw;
            m_prevSysKernel = kernelRaw;
            m_prevSysUser = userRaw;
            m_lastSysTimeDelta = 0;
            return 0.0;
        }

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
            Utils::Logger::Warn("CPUUsageAnalyzer: Failed to open PDH query");
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

        // Initial collection to prime the counters
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
        if (PdhCollectQueryData(m_pdhQuery) != ERROR_SUCCESS) {
            return std::vector<double>(m_processorCount, 0.0);
        }

        for (auto hCounter : m_pdhCounters) {
            PDH_FMT_COUNTERVALUE displayValue;
            if (PdhGetFormattedCounterValue(hCounter, PDH_FMT_DOUBLE, NULL, &displayValue) ==
                ERROR_SUCCESS) {
                perCore.push_back(std::clamp(displayValue.doubleValue, 0.0, 100.0));
            } else {
                perCore.push_back(0.0);
            }
        }

        if (perCore.size() < m_processorCount) {
            perCore.resize(m_processorCount, 0.0);
        }

        return perCore;
    }

    void AnalyzeCoreUtilization(ProcessCPUSignature& signature,
                                const std::vector<ProcessTracker::ProcessSample>& samples) {
        if (samples.empty()) return;

        signature.allCoresUtilized =
            (signature.avgUsagePercent >= 90.0 &&
             signature.activeThreadCount >= m_processorCount &&
             m_processorCount > 0);

        // Analyze per-core usage distribution from samples that carry it
        size_t samplesWithCoreData = 0;
        std::vector<double> coreAverages;

        for (const auto& sample : samples) {
            if (sample.perCoreUsage.empty()) continue;

            if (coreAverages.empty()) {
                coreAverages.resize(sample.perCoreUsage.size(), 0.0);
            }
            for (size_t i = 0; i < std::min(coreAverages.size(), sample.perCoreUsage.size()); ++i) {
                coreAverages[i] += sample.perCoreUsage[i];
            }
            ++samplesWithCoreData;
        }

        if (samplesWithCoreData > 0 && !coreAverages.empty()) {
            for (auto& avg : coreAverages) {
                avg /= static_cast<double>(samplesWithCoreData);
            }

            // Uniform distribution: low coefficient of variation across cores
            const double cv = CalculateCV(coreAverages);
            signature.uniformCoreDistribution = (cv < 0.3 && signature.allCoresUtilized);
        } else {
            signature.uniformCoreDistribution = false;
        }
    }

    void ReportError(const std::string& message, int code) const {
        if (m_callbackManager) {
            m_callbackManager->InvokeError(message, code);
        }
    }

    double CalculateMiningProbability(const ProcessCPUSignature& signature) const {
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
    std::atomic<bool> m_running{ false };
    std::atomic<bool> m_paused{ false };
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

    // Events — deque for O(1) front removal instead of O(N) vector::erase(begin())
    std::deque<HighLoadEvent> m_highLoadEvents;

    // Alert deduplication: PID -> last alert time (capped to prevent unbounded growth)
    std::unordered_map<uint32_t, TimePoint> m_lastAlertedPids;
    static constexpr size_t kMaxAlertedPids = 4096;

    // Monitoring thread
    std::thread m_monitorThread;
    std::condition_variable m_monitorWakeup;
    mutable std::mutex m_monitorWakeupMutex;

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

void CPUUsageAnalyzer::RegisterMiningDetectedCallback(CPUMiningDetectedCallback callback) {
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
