/**
 * ============================================================================
 * ShadowStrike NGAV - PERFORMANCE OPTIMIZER MODULE
 * ============================================================================
 *
 * @file PerformanceOptimizer.hpp
 * @brief Enterprise-grade system performance optimization for gaming and
 *        high-load scenarios with intelligent resource management.
 *
 * Provides comprehensive performance optimization including process priority
 * management, I/O throttling, memory optimization, and CPU affinity control.
 *
 * OPTIMIZATION CAPABILITIES:
 * ==========================
 *
 * 1. PROCESS PRIORITY
 *    - Priority class adjustment
 *    - I/O priority management
 *    - Memory priority
 *    - Per-thread priority
 *    - Scheduling hints
 *
 * 2. I/O THROTTLING
 *    - Disk throughput limiting
 *    - IOPS limiting
 *    - Queue depth control
 *    - Read/write balancing
 *    - Scan rate limiting
 *
 * 3. MEMORY MANAGEMENT
 *    - Working set trimming
 *    - Cache flushing
 *    - Memory compression
 *    - Large page optimization
 *    - NUMA awareness
 *
 * 4. CPU MANAGEMENT
 *    - Core affinity
 *    - Thread parking
 *    - P-state optimization
 *    - Background work deferral
 *    - Efficiency cores usage
 *
 * 5. POWER OPTIMIZATION
 *    - Power plan switching
 *    - Turbo boost control
 *    - Battery mode detection
 *    - Thermal awareness
 *
 * @note Thread-safe singleton design.
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
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>

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
#include "../Utils/SystemUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::GameMode {
    class PerformanceOptimizerImpl;
}

namespace ShadowStrike {
namespace GameMode {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace OptimizerConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default throttle rate (MB/s)
    inline constexpr uint32_t DEFAULT_THROTTLE_MBPS = 50;
    
    /// @brief Minimum working set (MB)
    inline constexpr size_t MIN_WORKING_SET_MB = 50;
    
    /// @brief Default scan rate limit (files/sec)
    inline constexpr uint32_t DEFAULT_SCAN_RATE_LIMIT = 10;

}  // namespace OptimizerConstants

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
 * @brief Optimization profile
 */
enum class OptimizationProfile : uint8_t {
    Normal          = 0,    ///< Normal operation
    Balanced        = 1,    ///< Balanced (light gaming)
    Performance     = 2,    ///< Maximum performance
    PowerSaver      = 3,    ///< Battery/power saver
    Silent          = 4,    ///< Silent operation
    Custom          = 5
};

/**
 * @brief Process priority class
 */
enum class ProcessPriorityClass : uint8_t {
    Realtime        = 0,    ///< REALTIME_PRIORITY_CLASS
    High            = 1,    ///< HIGH_PRIORITY_CLASS
    AboveNormal     = 2,    ///< ABOVE_NORMAL_PRIORITY_CLASS
    Normal          = 3,    ///< NORMAL_PRIORITY_CLASS
    BelowNormal     = 4,    ///< BELOW_NORMAL_PRIORITY_CLASS
    Idle            = 5     ///< IDLE_PRIORITY_CLASS
};

/**
 * @brief I/O priority
 */
enum class IOPriority : uint8_t {
    Critical        = 0,
    High            = 1,
    Normal          = 2,
    Low             = 3,
    VeryLow         = 4
};

/**
 * @brief Memory priority
 */
enum class MemoryPriority : uint8_t {
    VeryHigh        = 0,    ///< 5 - Default
    High            = 1,    ///< 4
    Medium          = 2,    ///< 3
    Low             = 3,    ///< 2
    VeryLow         = 4,    ///< 1
    Lowest          = 5     ///< 0
};

/**
 * @brief Resource type
 */
enum class ResourceType : uint8_t {
    CPU             = 0,
    Memory          = 1,
    DiskIO          = 2,
    NetworkIO       = 3,
    GPU             = 4
};

/**
 * @brief Module status
 */
enum class OptimizerStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Normal          = 2,
    Optimized       = 3,
    Boosted         = 4,
    Restoring       = 5,
    Stopping        = 6,
    Stopped         = 7,
    Error           = 8
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Process resource state
 */
struct ProcessResourceState {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Original priority class
    ProcessPriorityClass originalPriority = ProcessPriorityClass::Normal;
    
    /// @brief Current priority class
    ProcessPriorityClass currentPriority = ProcessPriorityClass::Normal;
    
    /// @brief Original I/O priority
    IOPriority originalIOPriority = IOPriority::Normal;
    
    /// @brief Current I/O priority
    IOPriority currentIOPriority = IOPriority::Normal;
    
    /// @brief Original memory priority
    MemoryPriority originalMemoryPriority = MemoryPriority::VeryHigh;
    
    /// @brief Current memory priority
    MemoryPriority currentMemoryPriority = MemoryPriority::VeryHigh;
    
    /// @brief Original affinity mask
    uint64_t originalAffinityMask = 0;
    
    /// @brief Current affinity mask
    uint64_t currentAffinityMask = 0;
    
    /// @brief Is modified
    bool isModified = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief System resource snapshot
 */
struct SystemResourceSnapshot {
    /// @brief CPU usage (%)
    double cpuUsage = 0.0;
    
    /// @brief Memory usage (%)
    double memoryUsage = 0.0;
    
    /// @brief Available memory (MB)
    uint64_t availableMemoryMB = 0;
    
    /// @brief Disk read rate (MB/s)
    double diskReadMBps = 0.0;
    
    /// @brief Disk write rate (MB/s)
    double diskWriteMBps = 0.0;
    
    /// @brief Disk queue length
    double diskQueueLength = 0.0;
    
    /// @brief Network usage (Mbps)
    double networkMbps = 0.0;
    
    /// @brief GPU usage (%)
    double gpuUsage = 0.0;
    
    /// @brief Power status
    bool onBattery = false;
    
    /// @brief Battery percentage
    uint8_t batteryPercent = 100;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Throttle settings
 */
struct ThrottleSettings {
    /// @brief Disk throughput limit (MB/s)
    uint32_t diskThroughputMBps = OptimizerConstants::DEFAULT_THROTTLE_MBPS;
    
    /// @brief IOPS limit
    uint32_t iopsLimit = 100;
    
    /// @brief Scan rate limit (files/sec)
    uint32_t scanRateLimit = OptimizerConstants::DEFAULT_SCAN_RATE_LIMIT;
    
    /// @brief Network bandwidth limit (Mbps)
    uint32_t networkBandwidthMbps = 0;  // 0 = no limit
    
    /// @brief CPU usage limit (%)
    uint8_t cpuUsageLimit = 25;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Optimization profile settings
 */
struct ProfileSettings {
    /// @brief Profile name
    std::string name;
    
    /// @brief Description
    std::string description;
    
    /// @brief Process priority
    ProcessPriorityClass processPriority = ProcessPriorityClass::Idle;
    
    /// @brief I/O priority
    IOPriority ioPriority = IOPriority::VeryLow;
    
    /// @brief Memory priority
    MemoryPriority memoryPriority = MemoryPriority::Low;
    
    /// @brief Throttle settings
    ThrottleSettings throttle;
    
    /// @brief Trim working set
    bool trimWorkingSet = true;
    
    /// @brief Flush caches
    bool flushCaches = true;
    
    /// @brief Use efficiency cores only
    bool useEfficiencyCoresOnly = false;
    
    /// @brief Defer background work
    bool deferBackgroundWork = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Optimization result
 */
struct OptimizationResult {
    /// @brief Success
    bool success = false;
    
    /// @brief Profile applied
    OptimizationProfile profile = OptimizationProfile::Normal;
    
    /// @brief Processes modified
    uint32_t processesModified = 0;
    
    /// @brief Memory freed (MB)
    uint64_t memoryFreedMB = 0;
    
    /// @brief Estimated performance gain (%)
    double estimatedGainPercent = 0.0;
    
    /// @brief Applied time
    SystemTimePoint appliedTime;
    
    /// @brief Error message
    std::string errorMessage;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct OptimizerStatistics {
    std::atomic<uint64_t> boostActivations{0};
    std::atomic<uint64_t> restorations{0};
    std::atomic<uint64_t> workingSetTrims{0};
    std::atomic<uint64_t> totalMemoryFreedMB{0};
    std::atomic<uint64_t> priorityChanges{0};
    std::atomic<uint64_t> throttleActivations{0};
    std::atomic<uint64_t> totalBoostDurationSeconds{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct PerformanceOptimizerConfiguration {
    /// @brief Enable optimizer
    bool enabled = true;
    
    /// @brief Enable auto-optimization
    bool enableAutoOptimization = true;
    
    /// @brief Default profile
    OptimizationProfile defaultProfile = OptimizationProfile::Balanced;
    
    /// @brief Minimum working set (MB)
    size_t minWorkingSetMB = OptimizerConstants::MIN_WORKING_SET_MB;
    
    /// @brief Enable aggressive memory release
    bool enableAggressiveMemoryRelease = false;
    
    /// @brief Enable efficiency core routing
    bool enableEfficiencyCoreRouting = true;
    
    /// @brief Restore delay after game exit (seconds)
    uint32_t restoreDelaySeconds = 5;
    
    /// @brief Processes to exclude from optimization
    std::vector<std::wstring> excludedProcesses;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using OptimizationCallback = std::function<void(const OptimizationResult&)>;
using ResourceCallback = std::function<void(const SystemResourceSnapshot&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// PERFORMANCE OPTIMIZER CLASS
// ============================================================================

/**
 * @class PerformanceOptimizer
 * @brief Enterprise performance optimization
 */
class PerformanceOptimizer final {
public:
    [[nodiscard]] static PerformanceOptimizer& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    PerformanceOptimizer(const PerformanceOptimizer&) = delete;
    PerformanceOptimizer& operator=(const PerformanceOptimizer&) = delete;
    PerformanceOptimizer(PerformanceOptimizer&&) = delete;
    PerformanceOptimizer& operator=(PerformanceOptimizer&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const PerformanceOptimizerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] OptimizerStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const PerformanceOptimizerConfiguration& config);
    [[nodiscard]] PerformanceOptimizerConfiguration GetConfiguration() const;

    // ========================================================================
    // OPTIMIZATION CONTROL
    // ========================================================================
    
    /// @brief Apply optimizations for gaming
    [[nodiscard]] OptimizationResult BoostSystem();
    
    /// @brief Apply specific profile
    [[nodiscard]] OptimizationResult ApplyProfile(OptimizationProfile profile);
    
    /// @brief Apply custom settings
    [[nodiscard]] OptimizationResult ApplyCustomSettings(const ProfileSettings& settings);
    
    /// @brief Restore to normal
    [[nodiscard]] OptimizationResult RestoreSystem();
    
    /// @brief Is currently boosted
    [[nodiscard]] bool IsBoosted() const noexcept;
    
    /// @brief Get current profile
    [[nodiscard]] OptimizationProfile GetCurrentProfile() const noexcept;

    // ========================================================================
    // PROCESS MANAGEMENT
    // ========================================================================
    
    /// @brief Set process priority
    [[nodiscard]] bool SetProcessPriority(uint32_t pid, ProcessPriorityClass priority);
    
    /// @brief Set I/O priority
    [[nodiscard]] bool SetIOPriority(uint32_t pid, IOPriority priority);
    
    /// @brief Set memory priority
    [[nodiscard]] bool SetMemoryPriority(uint32_t pid, MemoryPriority priority);
    
    /// @brief Set CPU affinity
    [[nodiscard]] bool SetCPUAffinity(uint32_t pid, uint64_t affinityMask);
    
    /// @brief Get process resource state
    [[nodiscard]] std::optional<ProcessResourceState> GetProcessState(uint32_t pid) const;
    
    /// @brief Get modified processes
    [[nodiscard]] std::vector<ProcessResourceState> GetModifiedProcesses() const;

    // ========================================================================
    // MEMORY MANAGEMENT
    // ========================================================================
    
    /// @brief Trim working set
    [[nodiscard]] uint64_t TrimWorkingSet();
    
    /// @brief Flush caches
    void FlushCaches();
    
    /// @brief Release memory
    [[nodiscard]] uint64_t ReleaseMemory(size_t targetMB);
    
    /// @brief Get available memory (MB)
    [[nodiscard]] uint64_t GetAvailableMemoryMB() const;

    // ========================================================================
    // THROTTLING
    // ========================================================================
    
    /// @brief Enable throttling
    void EnableThrottling(const ThrottleSettings& settings);
    
    /// @brief Disable throttling
    void DisableThrottling();
    
    /// @brief Is throttling active
    [[nodiscard]] bool IsThrottlingActive() const noexcept;
    
    /// @brief Get throttle settings
    [[nodiscard]] ThrottleSettings GetThrottleSettings() const;

    // ========================================================================
    // MONITORING
    // ========================================================================
    
    /// @brief Get system resource snapshot
    [[nodiscard]] SystemResourceSnapshot GetResourceSnapshot() const;
    
    /// @brief Start resource monitoring
    void StartResourceMonitoring(uint32_t intervalMs = 1000);
    
    /// @brief Stop resource monitoring
    void StopResourceMonitoring();

    // ========================================================================
    // PROFILE MANAGEMENT
    // ========================================================================
    
    /// @brief Get profile settings
    [[nodiscard]] ProfileSettings GetProfileSettings(OptimizationProfile profile) const;
    
    /// @brief Set custom profile
    void SetCustomProfile(const ProfileSettings& settings);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterOptimizationCallback(OptimizationCallback callback);
    void RegisterResourceCallback(ResourceCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] OptimizerStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    PerformanceOptimizer();
    ~PerformanceOptimizer();
    
    std::unique_ptr<PerformanceOptimizerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetProfileName(OptimizationProfile profile) noexcept;
[[nodiscard]] std::string_view GetPriorityClassName(ProcessPriorityClass priority) noexcept;
[[nodiscard]] std::string_view GetIOPriorityName(IOPriority priority) noexcept;
[[nodiscard]] std::string_view GetMemoryPriorityName(MemoryPriority priority) noexcept;
[[nodiscard]] std::string_view GetResourceTypeName(ResourceType type) noexcept;

/// @brief Get Windows priority class constant
[[nodiscard]] DWORD GetWindowsPriorityClass(ProcessPriorityClass priority) noexcept;

/// @brief Detect CPU efficiency cores
[[nodiscard]] uint64_t GetEfficiencyCoresMask();

/// @brief Detect CPU performance cores
[[nodiscard]] uint64_t GetPerformanceCoresMask();

}  // namespace GameMode
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_BOOST_SYSTEM() \
    ::ShadowStrike::GameMode::PerformanceOptimizer::Instance().BoostSystem()

#define SS_RESTORE_SYSTEM() \
    ::ShadowStrike::GameMode::PerformanceOptimizer::Instance().RestoreSystem()
