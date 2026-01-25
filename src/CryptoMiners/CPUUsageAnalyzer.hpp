/**
 * ============================================================================
 * ShadowStrike CryptoMiner Protection - CPU USAGE ANALYZER
 * ============================================================================
 *
 * @file CPUUsageAnalyzer.hpp
 * @brief Enterprise-grade CPU usage analysis engine for detecting cryptocurrency
 *        mining behavior through resource utilization patterns.
 *
 * Uses statistical analysis, hardware performance counters (PMU), and behavioral
 * heuristics to identify crypto-mining algorithms with distinct CPU signatures.
 *
 * ANALYSIS CAPABILITIES:
 * ======================
 *
 * 1. USAGE PATTERN ANALYSIS
 *    - Sustained high CPU usage detection
 *    - Periodic throttling patterns
 *    - Core utilization distribution
 *    - Thread pool patterns
 *    - Affinity manipulation
 *
 * 2. PERFORMANCE COUNTER ANALYSIS (PMU)
 *    - L3 cache miss patterns (RandomX)
 *    - Branch misprediction rates
 *    - Instructions per cycle (IPC)
 *    - Memory bandwidth usage
 *    - SIMD instruction density
 *
 * 3. ALGORITHM FINGERPRINTING
 *    - RandomX (Monero) signatures
 *    - CryptoNight variants
 *    - Argon2 patterns
 *    - Scrypt patterns
 *    - Memory-hard algorithm detection
 *
 * 4. PROCESS ANALYSIS
 *    - Thread utilization patterns
 *    - Context switch rates
 *    - Kernel vs user time ratio
 *    - Large page usage (huge pages)
 *    - Priority manipulation
 *
 * 5. STATISTICAL ANALYSIS
 *    - Usage variance analysis
 *    - Trend detection
 *    - Anomaly scoring
 *    - Baseline comparison
 *    - Historical patterns
 *
 * INTEGRATION:
 * ============
 * - Utils::ProcessUtils for process enumeration
 * - Utils::SystemUtils for system metrics
 * - CryptoMinerDetector for correlation
 *
 * @note PMU access requires elevated privileges.
 * @note Some counters may not be available on all CPUs.
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

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::CryptoMiners {
    class CPUUsageAnalyzerImpl;
}

namespace ShadowStrike {
namespace CryptoMiners {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace CPUAnalyzerConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default high usage threshold (%)
    inline constexpr double HIGH_USAGE_THRESHOLD = 80.0;
    
    /// @brief Default mining threshold (%)
    inline constexpr double MINING_THRESHOLD = 60.0;
    
    /// @brief Default observation window (seconds)
    inline constexpr uint32_t OBSERVATION_WINDOW_SECS = 30;
    
    /// @brief Sample interval (ms)
    inline constexpr uint32_t SAMPLE_INTERVAL_MS = 1000;
    
    /// @brief Maximum processes to track
    inline constexpr size_t MAX_TRACKED_PROCESSES = 1024;
    
    /// @brief Maximum samples per process
    inline constexpr size_t MAX_SAMPLES_PER_PROCESS = 300;
    
    /// @brief L3 cache miss threshold for RandomX
    inline constexpr double RANDOMX_CACHE_MISS_THRESHOLD = 0.15;

}  // namespace CPUAnalyzerConstants

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
 * @brief CPU usage pattern
 */
enum class CPUUsagePattern : uint8_t {
    Unknown             = 0,
    Normal              = 1,    ///< Normal usage
    Spike               = 2,    ///< Short burst
    SustainedHigh       = 3,    ///< Sustained high usage
    PeriodicPulse       = 4,    ///< Mining throttling pattern
    AllCoresUniform     = 5,    ///< All cores evenly loaded
    SingleCorePinned    = 6,    ///< Single core high usage
    GradualIncrease     = 7,    ///< Gradual ramp up
    FluctuatingHigh     = 8     ///< Fluctuating but high
};

/**
 * @brief Execution unit usage pattern
 */
enum class ExecutionUnitUsage : uint8_t {
    Unknown             = 0,
    Balanced            = 1,    ///< Balanced usage
    ALUHeavy            = 2,    ///< Integer heavy
    FPUHeavy            = 3,    ///< Floating point heavy
    SIMDHeavy           = 4,    ///< SIMD/AVX heavy
    CacheHeavy          = 5,    ///< L3 cache heavy (RandomX)
    MemoryBandwidthHeavy= 6,    ///< Memory bound
    BranchHeavy         = 7     ///< Branch intensive
};

/**
 * @brief Suspected mining algorithm
 */
enum class SuspectedAlgorithm : uint8_t {
    Unknown         = 0,
    RandomX         = 1,    ///< Monero RandomX
    CryptoNight     = 2,    ///< CryptoNight variants
    CryptoNightR    = 3,    ///< CryptoNight-R
    Argon2          = 4,    ///< Argon2 based
    Scrypt          = 5,    ///< Scrypt based
    SHA256          = 6,    ///< SHA-256 (rare on CPU)
    Yescrypt        = 7,    ///< Yescrypt
    Generic         = 255   ///< Generic mining
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Paused          = 3,
    Stopped         = 4,
    Error           = 5
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Thread CPU statistics
 */
struct ThreadCPUStats {
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief CPU usage (%)
    double usagePercent = 0.0;
    
    /// @brief Context switches
    uint64_t contextSwitches = 0;
    
    /// @brief Kernel time (ms)
    uint64_t kernelTimeMs = 0;
    
    /// @brief User time (ms)
    uint64_t userTimeMs = 0;
    
    /// @brief Affinity mask
    uint64_t affinityMask = 0;
    
    /// @brief Priority
    int32_t priority = 0;
    
    /// @brief Is high priority
    bool isHighPriority = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Performance counter data (PMU)
 */
struct PerformanceCounterData {
    /// @brief Instructions retired
    uint64_t instructionsRetired = 0;
    
    /// @brief CPU cycles
    uint64_t cpuCycles = 0;
    
    /// @brief L3 cache misses
    uint64_t l3CacheMisses = 0;
    
    /// @brief L3 cache references
    uint64_t l3CacheReferences = 0;
    
    /// @brief Branch misses
    uint64_t branchMisses = 0;
    
    /// @brief Branch instructions
    uint64_t branchInstructions = 0;
    
    /// @brief Instructions per cycle (IPC)
    double ipc = 0.0;
    
    /// @brief L3 cache miss ratio
    double l3MissRatio = 0.0;
    
    /// @brief Branch miss ratio
    double branchMissRatio = 0.0;
    
    /// @brief Is data valid
    bool isValid = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Process CPU signature
 */
struct ProcessCPUSignature {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Total CPU usage (%)
    double totalUsagePercent = 0.0;
    
    /// @brief Average CPU usage (%)
    double avgUsagePercent = 0.0;
    
    /// @brief Peak CPU usage (%)
    double peakUsagePercent = 0.0;
    
    /// @brief Usage standard deviation
    double usageStdDev = 0.0;
    
    /// @brief Usage pattern
    CPUUsagePattern pattern = CPUUsagePattern::Unknown;
    
    /// @brief Execution unit usage
    ExecutionUnitUsage executionUnit = ExecutionUnitUsage::Unknown;
    
    /// @brief Suspected algorithm
    SuspectedAlgorithm suspectedAlgorithm = SuspectedAlgorithm::Unknown;
    
    /// @brief Active thread count
    uint32_t activeThreadCount = 0;
    
    /// @brief Thread statistics
    std::vector<ThreadCPUStats> threadStats;
    
    /// @brief Performance counter data
    PerformanceCounterData perfCounters;
    
    /// @brief Uses large pages
    bool usesLargePages = false;
    
    /// @brief Has elevated priority
    bool hasElevatedPriority = false;
    
    /// @brief All cores utilized
    bool allCoresUtilized = false;
    
    /// @brief Uniform core distribution
    bool uniformCoreDistribution = false;
    
    /// @brief Mining probability (0-1)
    double miningProbability = 0.0;
    
    /// @brief Sample count
    uint32_t sampleCount = 0;
    
    /// @brief Analysis time
    SystemTimePoint analysisTime;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief CPU usage sample
 */
struct CPUUsageSample {
    /// @brief Sample time
    SystemTimePoint timestamp;
    
    /// @brief Overall CPU usage (%)
    double overallUsage = 0.0;
    
    /// @brief Per-core usage (%)
    std::vector<double> perCoreUsage;
    
    /// @brief Process samples
    std::vector<std::pair<uint32_t, double>> processSamples;
};

/**
 * @brief High load event
 */
struct HighLoadEvent {
    /// @brief Event ID
    std::string eventId;
    
    /// @brief Process signature
    ProcessCPUSignature signature;
    
    /// @brief Is mining behavior
    bool isMiningBehavior = false;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    /// @brief Duration (seconds)
    uint32_t durationSecs = 0;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct CPUAnalyzerStatistics {
    /// @brief Samples taken
    std::atomic<uint64_t> samplesTaken{0};
    
    /// @brief High usage events
    std::atomic<uint64_t> highUsageEvents{0};
    
    /// @brief Mining patterns detected
    std::atomic<uint64_t> miningPatternsDetected{0};
    
    /// @brief Processes analyzed
    std::atomic<uint64_t> processesAnalyzed{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct CPUUsageAnalyzerConfiguration {
    /// @brief High usage threshold (%)
    double highUsageThreshold = CPUAnalyzerConstants::HIGH_USAGE_THRESHOLD;
    
    /// @brief Mining detection threshold (%)
    double miningThreshold = CPUAnalyzerConstants::MINING_THRESHOLD;
    
    /// @brief Observation window (seconds)
    uint32_t observationWindowSecs = CPUAnalyzerConstants::OBSERVATION_WINDOW_SECS;
    
    /// @brief Sample interval (ms)
    uint32_t sampleIntervalMs = CPUAnalyzerConstants::SAMPLE_INTERVAL_MS;
    
    /// @brief Enable performance counters (requires admin)
    bool enablePerformanceCounters = true;
    
    /// @brief Monitor background processes only
    bool monitorBackgroundOnly = false;
    
    /// @brief Enable algorithm fingerprinting
    bool enableAlgorithmFingerprinting = true;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using HighLoadCallback = std::function<void(const HighLoadEvent&)>;
using MiningDetectedCallback = std::function<void(const ProcessCPUSignature&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// CPU USAGE ANALYZER CLASS
// ============================================================================

/**
 * @class CPUUsageAnalyzer
 * @brief Enterprise-grade CPU usage analysis for miner detection
 */
class CPUUsageAnalyzer final {
public:
    [[nodiscard]] static CPUUsageAnalyzer& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    CPUUsageAnalyzer(const CPUUsageAnalyzer&) = delete;
    CPUUsageAnalyzer& operator=(const CPUUsageAnalyzer&) = delete;
    CPUUsageAnalyzer(CPUUsageAnalyzer&&) = delete;
    CPUUsageAnalyzer& operator=(CPUUsageAnalyzer&&) = delete;

    [[nodiscard]] bool Initialize(const CPUUsageAnalyzerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool Start();
    [[nodiscard]] bool Stop();
    void Pause();
    void Resume();
    
    [[nodiscard]] bool UpdateConfiguration(const CPUUsageAnalyzerConfiguration& config);
    [[nodiscard]] CPUUsageAnalyzerConfiguration GetConfiguration() const;
    
    /// @brief Collect CPU usage sample
    void CollectSample();
    
    /// @brief Analyze specific process
    [[nodiscard]] ProcessCPUSignature AnalyzeProcess(uint32_t processId);
    
    /// @brief Check if process exhibits mining behavior
    [[nodiscard]] bool IsMiningBehavior(uint32_t processId);
    
    /// @brief Get suspected algorithm
    [[nodiscard]] SuspectedAlgorithm GetSuspectedAlgorithm(uint32_t processId) const;
    
    /// @brief Get high CPU processes
    [[nodiscard]] std::vector<ProcessCPUSignature> GetHighCPUProcesses(
        double threshold = CPUAnalyzerConstants::MINING_THRESHOLD);
    
    /// @brief Get overall CPU usage
    [[nodiscard]] double GetOverallCPUUsage() const;
    
    /// @brief Get per-core usage
    [[nodiscard]] std::vector<double> GetPerCoreUsage() const;
    
    /// @brief Get performance counters for process
    [[nodiscard]] PerformanceCounterData GetPerformanceCounters(uint32_t processId) const;
    
    void RegisterHighLoadCallback(HighLoadCallback callback);
    void RegisterMiningDetectedCallback(MiningDetectedCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();
    
    [[nodiscard]] CPUAnalyzerStatistics GetStatistics() const;
    void ResetStatistics();
    [[nodiscard]] std::vector<HighLoadEvent> GetRecentHighLoadEvents(size_t maxCount = 100) const;
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    CPUUsageAnalyzer();
    ~CPUUsageAnalyzer();
    
    std::unique_ptr<CPUUsageAnalyzerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetCPUUsagePatternName(CPUUsagePattern pattern) noexcept;
[[nodiscard]] std::string_view GetExecutionUnitUsageName(ExecutionUnitUsage usage) noexcept;
[[nodiscard]] std::string_view GetSuspectedAlgorithmName(SuspectedAlgorithm algo) noexcept;

}  // namespace CryptoMiners
}  // namespace ShadowStrike

#define SS_ANALYZE_CPU_PROCESS(pid) \
    ::ShadowStrike::CryptoMiners::CPUUsageAnalyzer::Instance().AnalyzeProcess(pid)

#define SS_IS_CPU_MINING(pid) \
    ::ShadowStrike::CryptoMiners::CPUUsageAnalyzer::Instance().IsMiningBehavior(pid)