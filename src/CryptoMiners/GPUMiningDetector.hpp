/**
 * ============================================================================
 * ShadowStrike CryptoMiner Protection - GPU MINING DETECTOR
 * ============================================================================
 *
 * @file GPUMiningDetector.hpp
 * @brief Enterprise-grade GPU mining detection engine for identifying
 *        unauthorized cryptocurrency mining on graphics hardware.
 *
 * Monitors NVIDIA (NVML), AMD (ADL), and Intel GPUs for compute workloads
 * characteristic of cryptocurrency mining operations.
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. GPU LOAD MONITORING
 *    - Compute unit utilization
 *    - Shader/SM usage
 *    - Memory controller load
 *    - Power consumption
 *    - Clock frequency analysis
 *
 * 2. VRAM ANALYSIS
 *    - Memory allocation patterns
 *    - DAG file detection (Ethash)
 *    - Large contiguous allocations
 *    - Memory bandwidth usage
 *
 * 3. COMPUTE API DETECTION
 *    - CUDA context monitoring
 *    - OpenCL context detection
 *    - DirectCompute workloads
 *    - Vulkan compute shaders
 *
 * 4. THERMAL MONITORING
 *    - Temperature spikes
 *    - Fan speed anomalies
 *    - Thermal throttling
 *    - Power limit hitting
 *
 * 5. PROCESS CORRELATION
 *    - GPU process enumeration
 *    - VRAM per process
 *    - Compute context tracking
 *    - Process-GPU mapping
 *
 * 6. ALGORITHM FINGERPRINTING
 *    - Ethash/Etchash (DAG)
 *    - Kawpow (Ravencoin)
 *    - Autolykos (Ergo)
 *    - Equihash (Zcash)
 *    - ProgPow variants
 *
 * SUPPORTED GPUs:
 * ===============
 * - NVIDIA (NVML API)
 * - AMD (ADL/ADLX API)
 * - Intel (proprietary APIs)
 *
 * INTEGRATION:
 * ============
 * - Utils::SystemUtils for hardware detection
 * - CryptoMinerDetector for process correlation
 * - ThreatIntel for known miner signatures
 *
 * @note Requires vendor-specific runtime libraries.
 * @note Some features require elevated privileges.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::CryptoMiners {
    class GPUMiningDetectorImpl;
}

namespace ShadowStrike {
namespace CryptoMiners {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace GPUMiningConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief GPU load threshold for mining suspicion (%)
    inline constexpr double GPU_LOAD_THRESHOLD = 90.0;
    
    /// @brief GPU memory threshold (%)
    inline constexpr double GPU_MEMORY_THRESHOLD = 80.0;
    
    /// @brief Temperature warning (Celsius)
    inline constexpr double TEMP_WARNING_C = 75.0;
    
    /// @brief Temperature critical (Celsius)
    inline constexpr double TEMP_CRITICAL_C = 85.0;
    
    /// @brief DAG minimum size (GB) - Ethereum
    inline constexpr double DAG_MIN_SIZE_GB = 4.0;
    
    /// @brief DAG maximum size (GB)
    inline constexpr double DAG_MAX_SIZE_GB = 8.0;
    
    /// @brief Maximum GPUs to monitor
    inline constexpr size_t MAX_GPU_DEVICES = 16;
    
    /// @brief Scan interval (ms)
    inline constexpr uint32_t SCAN_INTERVAL_MS = 2000;

}  // namespace GPUMiningConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief GPU vendor
 */
enum class GPUVendor : uint8_t {
    Unknown     = 0,
    NVIDIA      = 1,
    AMD         = 2,
    Intel       = 3,
    Other       = 255
};

/**
 * @brief Compute API
 */
enum class ComputeAPI : uint8_t {
    Unknown         = 0,
    CUDA            = 1,    ///< NVIDIA CUDA
    OpenCL          = 2,    ///< OpenCL
    DirectCompute   = 3,    ///< DirectX Compute
    VulkanCompute   = 4,    ///< Vulkan compute shaders
    Metal           = 5,    ///< Apple Metal
    None            = 255
};

/**
 * @brief GPU mining algorithm
 */
enum class GPUMiningAlgorithm : uint8_t {
    Unknown         = 0,
    Ethash          = 1,    ///< Ethereum (PoW)
    Etchash         = 2,    ///< Ethereum Classic
    Kawpow          = 3,    ///< Ravencoin
    Autolykos       = 4,    ///< Ergo
    Equihash        = 5,    ///< Zcash
    ProgPow         = 6,    ///< ProgPow variants
    CuckooCycle     = 7,    ///< Grin/Beam
    ZHash           = 8,    ///< ZHash
    BeamHash        = 9,    ///< Beam
    Generic         = 255
};

/**
 * @brief Mining detection confidence
 */
enum class DetectionConfidence : uint8_t {
    None        = 0,
    Low         = 1,
    Medium      = 2,
    High        = 3,
    Confirmed   = 4
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Scanning        = 3,
    Paused          = 4,
    Stopped         = 5,
    Error           = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief GPU process info
 */
struct GPUProcessInfo {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief VRAM used (bytes)
    uint64_t vramUsedBytes = 0;
    
    /// @brief Compute context active
    bool hasComputeContext = false;
    
    /// @brief Compute API used
    ComputeAPI computeAPI = ComputeAPI::Unknown;
    
    /// @brief GPU utilization by this process (%)
    double gpuUtilization = 0.0;
    
    /// @brief Is compute intensive
    bool isComputeIntensive = false;
    
    /// @brief Is suspected miner
    bool isSuspectedMiner = false;
    
    /// @brief Suspected algorithm
    GPUMiningAlgorithm suspectedAlgorithm = GPUMiningAlgorithm::Unknown;
    
    /// @brief Mining confidence
    DetectionConfidence confidence = DetectionConfidence::None;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief GPU device statistics
 */
struct GPUDeviceStats {
    /// @brief Device index
    uint32_t deviceIndex = 0;
    
    /// @brief Device name
    std::string deviceName;
    
    /// @brief Vendor
    GPUVendor vendor = GPUVendor::Unknown;
    
    /// @brief PCI Bus ID
    std::string pciBusId;
    
    /// @brief GPU load (%)
    double gpuLoadPercent = 0.0;
    
    /// @brief Memory controller load (%)
    double memoryControllerLoad = 0.0;
    
    /// @brief Memory used (%)
    double memoryUsedPercent = 0.0;
    
    /// @brief Temperature (Celsius)
    double temperatureC = 0.0;
    
    /// @brief Fan speed (%)
    uint32_t fanSpeedPercent = 0;
    
    /// @brief Power draw (Watts)
    double powerDrawWatts = 0.0;
    
    /// @brief Power limit (Watts)
    double powerLimitWatts = 0.0;
    
    /// @brief Core clock (MHz)
    uint32_t coreClockMHz = 0;
    
    /// @brief Memory clock (MHz)
    uint32_t memoryClockMHz = 0;
    
    /// @brief Total VRAM (bytes)
    uint64_t memoryTotalBytes = 0;
    
    /// @brief Used VRAM (bytes)
    uint64_t memoryUsedBytes = 0;
    
    /// @brief Free VRAM (bytes)
    uint64_t memoryFreeBytes = 0;
    
    /// @brief CUDA cores / Stream processors
    uint32_t computeUnits = 0;
    
    /// @brief Is mining suspected
    bool isMiningActivity = false;
    
    /// @brief DAG detected
    bool dagDetected = false;
    
    /// @brief Suspected algorithm
    GPUMiningAlgorithm suspectedAlgorithm = GPUMiningAlgorithm::Unknown;
    
    /// @brief Processes using this GPU
    std::vector<GPUProcessInfo> processes;
    
    /// @brief Sample time
    SystemTimePoint sampleTime;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief GPU mining detection result
 */
struct GPUMiningDetectionResult {
    /// @brief Detection ID
    std::string detectionId;
    
    /// @brief Is mining detected
    bool isMiningDetected = false;
    
    /// @brief Device stats
    GPUDeviceStats deviceStats;
    
    /// @brief Mining processes
    std::vector<GPUProcessInfo> miningProcesses;
    
    /// @brief Primary algorithm
    GPUMiningAlgorithm primaryAlgorithm = GPUMiningAlgorithm::Unknown;
    
    /// @brief Confidence
    DetectionConfidence confidence = DetectionConfidence::None;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    /// @brief Analysis duration
    std::chrono::milliseconds analysisDuration{0};
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct GPUMiningStatistics {
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> devicesMonitored{0};
    std::atomic<uint64_t> miningDetections{0};
    std::atomic<uint64_t> processesTerminated{0};
    std::atomic<uint64_t> dagDetections{0};
    std::array<std::atomic<uint64_t>, 16> byAlgorithm{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct GPUMiningDetectorConfiguration {
    /// @brief GPU load threshold (%)
    double gpuLoadThreshold = GPUMiningConstants::GPU_LOAD_THRESHOLD;
    
    /// @brief Memory threshold (%)
    double memoryThreshold = GPUMiningConstants::GPU_MEMORY_THRESHOLD;
    
    /// @brief Temperature warning (C)
    double temperatureWarning = GPUMiningConstants::TEMP_WARNING_C;
    
    /// @brief Enable CUDA monitoring
    bool enableCUDAMonitoring = true;
    
    /// @brief Enable OpenCL monitoring
    bool enableOpenCLMonitoring = true;
    
    /// @brief Check for DAG allocation
    bool detectDAGAllocation = true;
    
    /// @brief Monitor temperatures
    bool monitorTemperatures = true;
    
    /// @brief Scan interval (ms)
    uint32_t scanIntervalMs = GPUMiningConstants::SCAN_INTERVAL_MS;
    
    /// @brief Terminate mining processes
    bool terminateMiningProcesses = false;
    
    /// @brief Whitelisted applications
    std::vector<std::wstring> whitelistedApplications;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using GPUAnomalyCallback = std::function<void(const GPUDeviceStats&)>;
using MiningDetectedCallback = std::function<void(const GPUMiningDetectionResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// GPU MINING DETECTOR CLASS
// ============================================================================

/**
 * @class GPUMiningDetector
 * @brief Enterprise-grade GPU mining detection engine
 */
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
    
    /// @brief Scan all GPU devices
    [[nodiscard]] std::vector<GPUDeviceStats> ScanDevices();
    
    /// @brief Get specific device stats
    [[nodiscard]] std::optional<GPUDeviceStats> GetDeviceStats(uint32_t deviceIndex) const;
    
    /// @brief Identify mining processes
    [[nodiscard]] std::vector<uint32_t> IdentifyMiningProcesses();
    
    /// @brief Get processes using GPU
    [[nodiscard]] std::vector<GPUProcessInfo> GetGPUProcesses(uint32_t deviceIndex = 0) const;
    
    /// @brief Detect DAG allocation (Ethash)
    [[nodiscard]] bool DetectDAGGenerated(uint32_t processId);
    
    /// @brief Get DAG size (bytes) if detected
    [[nodiscard]] std::optional<uint64_t> GetDetectedDAGSize(uint32_t processId) const;
    
    /// @brief Get device count
    [[nodiscard]] size_t GetDeviceCount() const noexcept;
    
    /// @brief Check if NVML available
    [[nodiscard]] bool IsNVMLAvailable() const noexcept;
    
    /// @brief Check if ADL available
    [[nodiscard]] bool IsADLAvailable() const noexcept;
    
    /// @brief Terminate mining process
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

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

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