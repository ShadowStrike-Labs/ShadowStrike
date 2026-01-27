/**
 * ============================================================================
 * ShadowStrike NGAV - MEMORY PROFILER
 * ============================================================================
 *
 * @file MemoryProfiler.hpp
 * @brief Enterprise-grade Memory usage monitoring and profiling engine.
 *        Tracks system-wide and per-process memory consumption, identifying
 *        leaks and high-resource consumers.
 *
 * FEATURES:
 * - System-wide memory analysis (Physical, Commit Charge, Paged Pool)
 * - Per-process memory breakdown (Working Set, Private Bytes)
 * - High-usage alerting and leak detection heuristics
 * - Thread-safe access to real-time data
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

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <chrono>
#include <optional>

namespace ShadowStrike {
namespace Performance {

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief Detailed memory statistics for a specific process
 */
struct ProcessMemoryInfo {
    uint32_t pid;
    std::wstring name;

    // Size in bytes
    uint64_t workingSetSize;        // Current RAM usage
    uint64_t privateUsage;          // Commit charge (Private Bytes)
    uint64_t peakWorkingSetSize;    // Peak RAM usage
    uint64_t pageFaultCount;        // Hard/Soft page faults

    // Analysis
    double percentOfSystemMemory;   // % of total physical RAM
    bool isLeaking;                 // Heuristic detection

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief System-wide memory statistics
 */
struct SystemMemoryStats {
    uint64_t totalPhysical;         // Total RAM installed
    uint64_t availablePhysical;     // Free RAM
    uint64_t totalCommit;           // Total Commit Limit (RAM + PageFile)
    uint64_t availableCommit;       // Free Commit Space
    uint64_t nonPagedPool;          // Kernel Non-Paged Pool
    uint64_t pagedPool;             // Kernel Paged Pool
    uint32_t memoryLoad;            // Global memory load (0-100%)

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration for the Memory Profiler
 */
struct MemoryProfilerConfig {
    bool enabled = true;
    uint32_t samplingIntervalMs = 2000; // Sample every 2 seconds
    uint32_t historySize = 30;          // Keep last 30 samples

    // Alerting thresholds
    uint32_t highLoadThreshold = 90;    // Alert if system RAM > 90%
    uint64_t leakThresholdBytes = 100 * 1024 * 1024; // Alert if growth > 100MB over history

    bool trackPerProcess = true;        // Enable process scanning

    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// MEMORY PROFILER CLASS
// ============================================================================

class MemoryProfilerImpl; // PIMPL

/**
 * @class MemoryProfiler
 * @brief Singleton class for profiling system and process memory.
 */
class MemoryProfiler final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    [[nodiscard]] static MemoryProfiler& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;

    // Deleted copy/move
    MemoryProfiler(const MemoryProfiler&) = delete;
    MemoryProfiler& operator=(const MemoryProfiler&) = delete;
    MemoryProfiler(MemoryProfiler&&) = delete;
    MemoryProfiler& operator=(MemoryProfiler&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    /**
     * @brief Initialize the profiler with configuration
     * @param config Initial configuration
     * @return true if successful
     */
    [[nodiscard]] bool Initialize(const MemoryProfilerConfig& config);

    /**
     * @brief Shutdown the profiler and stop background threads
     */
    void Shutdown();

    /**
     * @brief Start the monitoring thread
     * @return true if started
     */
    [[nodiscard]] bool StartMonitoring();

    /**
     * @brief Stop the monitoring thread
     */
    void StopMonitoring();

    [[nodiscard]] bool IsMonitoring() const noexcept;

    // ========================================================================
    // ACCESSORS
    // ========================================================================

    /**
     * @brief Get the latest system-wide memory statistics
     */
    [[nodiscard]] SystemMemoryStats GetSystemStats() const;

    /**
     * @brief Get memory usage for a specific process
     * @param pid Process ID
     * @return Info or nullopt if not found
     */
    [[nodiscard]] std::optional<ProcessMemoryInfo> GetProcessInfo(uint32_t pid) const;

    /**
     * @brief Get top N memory consumers
     * @param count Number of processes to return
     * @param byPrivateBytes Sort by Private Bytes (true) or Working Set (false)
     * @return Vector of top consumers sorted by usage desc
     */
    [[nodiscard]] std::vector<ProcessMemoryInfo> GetTopConsumers(size_t count, bool byPrivateBytes = true) const;

    /**
     * @brief Force an immediate refresh of data (blocking)
     * @return true if successful
     */
    [[nodiscard]] bool RefreshNow();

    // ========================================================================
    // UTILITIES
    // ========================================================================

    [[nodiscard]] bool UpdateConfiguration(const MemoryProfilerConfig& config);
    [[nodiscard]] MemoryProfilerConfig GetConfiguration() const;

    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    MemoryProfiler();
    ~MemoryProfiler();

    std::unique_ptr<MemoryProfilerImpl> m_impl;
};

} // namespace Performance
} // namespace ShadowStrike
