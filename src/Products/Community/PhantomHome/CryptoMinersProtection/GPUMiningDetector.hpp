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
 * ShadowStrike CryptoMiner Protection - GPU MINING DETECTOR
 * ============================================================================
 */

#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

namespace ShadowStrike::CryptoMiners {
    class GPUMiningDetectorImpl;
}

namespace ShadowStrike {
namespace CryptoMiners {

namespace GPUMiningConstants {
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 1;
    inline constexpr uint32_t VERSION_PATCH = 0;

    inline constexpr double GPU_LOAD_THRESHOLD = 90.0;
    inline constexpr double GPU_MEMORY_THRESHOLD = 80.0;
    inline constexpr double TEMP_WARNING_C = 75.0;
    inline constexpr double TEMP_CRITICAL_C = 85.0;
    inline constexpr double DAG_MIN_SIZE_GB = 4.0;
    inline constexpr double DAG_MAX_SIZE_GB = 8.0;
    inline constexpr size_t MAX_GPU_DEVICES = 16;
    inline constexpr uint32_t SCAN_INTERVAL_MS = 2000;
}

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

enum class GPUVendor : uint8_t {
    Unknown = 0,
    NVIDIA = 1,
    AMD = 2,
    Intel = 3,
    Other = 255
};

enum class ComputeAPI : uint8_t {
    Unknown = 0,
    CUDA = 1,
    OpenCL = 2,
    DirectCompute = 3,
    VulkanCompute = 4,
    Metal = 5,
    None = 255
};

enum class GPUMiningAlgorithm : uint8_t {
    Unknown = 0,
    Ethash = 1,
    Etchash = 2,
    Kawpow = 3,
    Autolykos = 4,
    Equihash = 5,
    ProgPow = 6,
    CuckooCycle = 7,
    ZHash = 8,
    BeamHash = 9,
    Generic = 255
};

enum class DetectionConfidence : uint8_t {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Confirmed = 4
};

enum class ModuleStatus : uint8_t {
    Uninitialized = 0,
    Initializing = 1,
    Running = 2,
    Scanning = 3,
    Paused = 4,
    Stopped = 5,
    Error = 6
};

struct GPUProcessInfo {
    uint32_t processId = 0;
    std::wstring processName;
    std::wstring processPath;
    uint64_t vramUsedBytes = 0;
    bool hasComputeContext = false;
    ComputeAPI computeAPI = ComputeAPI::Unknown;
    double gpuUtilization = 0.0;
    double computeLoadPercent = 0.0;
    double graphicsLoadPercent = 0.0;
    double copyLoadPercent = 0.0;
    bool telemetryAvailable = false;
    bool isComputeIntensive = false;
    bool isWhitelisted = false;
    bool isSuspectedMiner = false;
    GPUMiningAlgorithm suspectedAlgorithm = GPUMiningAlgorithm::Unknown;
    DetectionConfidence confidence = DetectionConfidence::None;

    [[nodiscard]] std::string ToJson() const;
};

struct GPUDeviceStats {
    uint32_t deviceIndex = 0;
    std::string deviceName;
    GPUVendor vendor = GPUVendor::Unknown;
    std::string pciBusId;
    double gpuLoadPercent = 0.0;
    double computeLoadPercent = 0.0;
    double graphicsLoadPercent = 0.0;
    double copyLoadPercent = 0.0;
    double encodeLoadPercent = 0.0;
    double decodeLoadPercent = 0.0;
    double memoryControllerLoad = 0.0;
    double memoryUsedPercent = 0.0;
    double temperatureC = 0.0;
    uint32_t fanSpeedPercent = 0;
    double powerDrawWatts = 0.0;
    double powerLimitWatts = 0.0;
    uint32_t coreClockMHz = 0;
    uint32_t memoryClockMHz = 0;
    uint64_t memoryTotalBytes = 0;
    uint64_t memoryUsedBytes = 0;
    uint64_t memoryFreeBytes = 0;
    uint32_t computeUnits = 0;
    bool telemetryAvailable = false;
    bool processTelemetryAvailable = false;
    bool vendorTelemetryAvailable = false;
    bool isMiningActivity = false;
    bool dagDetected = false;
    GPUMiningAlgorithm suspectedAlgorithm = GPUMiningAlgorithm::Unknown;
    DetectionConfidence confidence = DetectionConfidence::None;
    std::string detectionSummary;
    std::vector<GPUProcessInfo> processes;
    SystemTimePoint sampleTime;

    [[nodiscard]] std::string ToJson() const;
};

struct GPUMiningDetectionResult {
    std::string detectionId;
    bool isMiningDetected = false;
    GPUDeviceStats deviceStats;
    std::vector<GPUProcessInfo> miningProcesses;
    GPUMiningAlgorithm primaryAlgorithm = GPUMiningAlgorithm::Unknown;
    DetectionConfidence confidence = DetectionConfidence::None;
    std::string detectionSummary;
    SystemTimePoint detectionTime;
    std::chrono::milliseconds analysisDuration{0};

    [[nodiscard]] std::string ToJson() const;
};

struct GPUMiningStatistics {
    uint64_t totalScans = 0;
    uint64_t devicesMonitored = 0;
    uint64_t miningDetections = 0;
    uint64_t processesTerminated = 0;
    uint64_t dagDetections = 0;
    std::array<uint64_t, 16> byAlgorithm{};
    TimePoint startTime = Clock::now();

    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

struct GPUMiningDetectorConfiguration {
    double gpuLoadThreshold = GPUMiningConstants::GPU_LOAD_THRESHOLD;
    double memoryThreshold = GPUMiningConstants::GPU_MEMORY_THRESHOLD;
    double temperatureWarning = GPUMiningConstants::TEMP_WARNING_C;
    bool enableCUDAMonitoring = true;
    bool enableOpenCLMonitoring = true;
    bool detectDAGAllocation = true;
    bool monitorTemperatures = true;
    uint32_t scanIntervalMs = GPUMiningConstants::SCAN_INTERVAL_MS;
    bool terminateMiningProcesses = false;
    std::vector<std::wstring> whitelistedApplications;
    bool verboseLogging = false;

    [[nodiscard]] bool IsValid() const noexcept;
};

using GPUAnomalyCallback = std::function<void(const GPUDeviceStats&)>;
using MiningDetectedCallback = std::function<void(const GPUMiningDetectionResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

class GPUMiningDetector final {
public:
    [[nodiscard]] static GPUMiningDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;

    GPUMiningDetector(const GPUMiningDetector&) = delete;
    GPUMiningDetector& operator=(const GPUMiningDetector&) = delete;
    GPUMiningDetector(GPUMiningDetector&&) = delete;
    GPUMiningDetector& operator=(GPUMiningDetector&&) = delete;

    [[nodiscard]] bool Initialize(const GPUMiningDetectorConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;

    [[nodiscard]] bool Start();
    [[nodiscard]] bool Stop();
    void Pause();
    void Resume();

    [[nodiscard]] bool UpdateConfiguration(const GPUMiningDetectorConfiguration& config);
    [[nodiscard]] GPUMiningDetectorConfiguration GetConfiguration() const;

    [[nodiscard]] std::vector<GPUDeviceStats> ScanDevices();
    [[nodiscard]] std::optional<GPUDeviceStats> GetDeviceStats(uint32_t deviceIndex) const;
    [[nodiscard]] std::vector<uint32_t> IdentifyMiningProcesses();
    [[nodiscard]] std::vector<GPUProcessInfo> GetGPUProcesses(uint32_t deviceIndex = 0) const;
    [[nodiscard]] bool DetectDAGGenerated(uint32_t processId);
    [[nodiscard]] std::optional<uint64_t> GetDetectedDAGSize(uint32_t processId) const;
    [[nodiscard]] size_t GetDeviceCount() const noexcept;
    [[nodiscard]] bool IsNVMLAvailable() const noexcept;
    [[nodiscard]] bool IsADLAvailable() const noexcept;
    [[nodiscard]] bool TerminateMiningProcess(uint32_t processId);

    void RegisterAnomalyCallback(GPUAnomalyCallback callback);
    void RegisterMiningDetectedCallback(MiningDetectedCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    [[nodiscard]] GPUMiningStatistics GetStatistics() const;
    void ResetStatistics();
    [[nodiscard]] std::vector<GPUMiningDetectionResult> GetRecentDetections(size_t maxCount = 100) const;

    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    GPUMiningDetector();
    ~GPUMiningDetector();

    std::unique_ptr<GPUMiningDetectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

[[nodiscard]] std::string_view GetGPUVendorName(GPUVendor vendor) noexcept;
[[nodiscard]] std::string_view GetComputeAPIName(ComputeAPI api) noexcept;
[[nodiscard]] std::string_view GetGPUMiningAlgorithmName(GPUMiningAlgorithm algo) noexcept;
[[nodiscard]] std::string_view GetDetectionConfidenceName(DetectionConfidence conf) noexcept;

}  // namespace CryptoMiners
}  // namespace ShadowStrike

#define SS_SCAN_GPU_DEVICES() \
    ::ShadowStrike::CryptoMiners::GPUMiningDetector::Instance().ScanDevices()

#define SS_IDENTIFY_GPU_MINERS() \
    ::ShadowStrike::CryptoMiners::GPUMiningDetector::Instance().IdentifyMiningProcesses()
