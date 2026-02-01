/**
 * @file TimeBasedEvasionDetector.cpp
 * @brief Enterprise-grade detection of timing-based sandbox/analysis evasion techniques
 *
 * ShadowStrike AntiEvasion - Time-Based Evasion Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * ============================================================================
 * IMPLEMENTATION OVERVIEW
 * ============================================================================
 *
 * This module implements comprehensive detection of timing attacks:
 *
 * 1. RDTSC/RDTSCP ANALYSIS
 *    - Instruction pattern scanning via Zydis disassembler
 *    - High-frequency RDTSC detection
 *    - RDTSC delta checks for VM detection
 *    - RDTSC+CPUID serialization patterns
 *
 * 2. SLEEP EVASION DETECTION
 *    - Sleep bombing (extended delays)
 *    - Sleep acceleration detection
 *    - Sleep fragmentation patterns
 *    - NtDelayExecution abuse
 *
 * 3. API TIMING ANALYSIS
 *    - GetTickCount/GetTickCount64 monitoring
 *    - QueryPerformanceCounter patterns
 *    - System time API cross-checking
 *
 * 4. NTP/NETWORK TIME EVASION
 *    - NTP server query detection
 *    - HTTP Date header checks
 *    - External time validation
 *
 * 5. HARDWARE TIMER ABUSE
 *    - HPET access detection
 *    - ACPI PM Timer queries
 *    - Direct hardware timer access
 *
 * ============================================================================
 * THREAD SAFETY
 * ============================================================================
 *
 * All public methods are thread-safe. Uses:
 * - std::shared_mutex for read/write separation
 * - std::atomic for statistics counters
 * - Thread-local storage for per-thread analysis buffers
 *
 * ============================================================================
 */

#include "pch.h"
#include "TimeBasedEvasionDetector.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <algorithm>
#include <cmath>
#include <numeric>
#include <queue>
#include <sstream>
#include <thread>
#include <future>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#include <TlHelp32.h>
#include <intrin.h>
#include <emmintrin.h>  // SSE2 intrinsics for fallback functions

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../PEParser/PEParser.hpp"

#include <Zydis/Zydis.h>

// =============================================================================
// ASSEMBLY FUNCTION FALLBACKS
// =============================================================================
// These fallback implementations are used when the assembly module is not
// linked (e.g., on non-Windows platforms or during testing). They provide
// equivalent functionality using C++ and compiler intrinsics where possible.
//
// MSVC linker directive /ALTERNATENAME automatically falls back to these
// if the primary assembly symbols are not found.
// =============================================================================

#ifdef _MSC_VER
#pragma comment(linker, "/ALTERNATENAME:TimingGetPreciseRDTSC=Fallback_TimingGetPreciseRDTSC")
#pragma comment(linker, "/ALTERNATENAME:TimingGetPreciseRDTSCP=Fallback_TimingGetPreciseRDTSCP")
#pragma comment(linker, "/ALTERNATENAME:TimingRDTSCDelta=Fallback_TimingRDTSCDelta")
#pragma comment(linker, "/ALTERNATENAME:TimingSerializedRDTSC=Fallback_TimingSerializedRDTSC")
#pragma comment(linker, "/ALTERNATENAME:TimingCompareRDTSCvRDTSCP=Fallback_TimingCompareRDTSCvRDTSCP")
#pragma comment(linker, "/ALTERNATENAME:TimingCPUIDLatency=Fallback_TimingCPUIDLatency")
#pragma comment(linker, "/ALTERNATENAME:TimingCheckHypervisorLeaf=Fallback_TimingCheckHypervisorLeaf")
#pragma comment(linker, "/ALTERNATENAME:TimingCPUIDVariance=Fallback_TimingCPUIDVariance")
#pragma comment(linker, "/ALTERNATENAME:TimingMeasureSleep=Fallback_TimingMeasureSleep")
#pragma comment(linker, "/ALTERNATENAME:TimingDetectSleepAcceleration=Fallback_TimingDetectSleepAcceleration")
#pragma comment(linker, "/ALTERNATENAME:TimingCalibrateTimebase=Fallback_TimingCalibrateTimebase")
#pragma comment(linker, "/ALTERNATENAME:TimingMeasureInstructions=Fallback_TimingMeasureInstructions")
#pragma comment(linker, "/ALTERNATENAME:TimingMeasureMemory=Fallback_TimingMeasureMemory")
#pragma comment(linker, "/ALTERNATENAME:TimingDetectSingleStep=Fallback_TimingDetectSingleStep")
#pragma comment(linker, "/ALTERNATENAME:TimingGetTSCFrequency=Fallback_TimingGetTSCFrequency")
#pragma comment(linker, "/ALTERNATENAME:TimingDetectVMExit=Fallback_TimingDetectVMExit")
#pragma comment(linker, "/ALTERNATENAME:TimingMeasureHypervisor=Fallback_TimingMeasureHypervisor")
#endif

extern "C" {

/// Fallback: TimingGetPreciseRDTSC
uint64_t Fallback_TimingGetPreciseRDTSC(void) {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);  // Serialize
    return __rdtsc();
}

/// Fallback: TimingGetPreciseRDTSCP
uint64_t Fallback_TimingGetPreciseRDTSCP(uint32_t* processorId) {
    unsigned int aux = 0;
    uint64_t tsc = __rdtscp(&aux);
    if (processorId) {
        *processorId = aux;
    }
    return tsc;
}

/// Fallback: TimingRDTSCDelta
uint64_t Fallback_TimingRDTSCDelta(void) {
    uint64_t sum = 0;
    constexpr int iterations = 100;
    
    for (int i = 0; i < iterations; ++i) {
        uint64_t start = __rdtsc();
        uint64_t end = __rdtsc();
        sum += (end - start);
    }
    
    return sum / iterations;
}

/// Fallback: TimingSerializedRDTSC
uint64_t Fallback_TimingSerializedRDTSC(void) {
    uint64_t sum = 0;
    int cpuInfo[4];
    constexpr int iterations = 100;
    
    for (int i = 0; i < iterations; ++i) {
        __cpuid(cpuInfo, 0);
        uint64_t start = __rdtsc();
        __cpuid(cpuInfo, 0);
        uint64_t end = __rdtsc();
        sum += (end - start);
    }
    
    return sum / iterations;
}

/// Fallback: TimingCompareRDTSCvRDTSCP
int64_t Fallback_TimingCompareRDTSCvRDTSCP(void) {
    int cpuInfo[4];
    unsigned int aux;
    
    // Measure RDTSC
    __cpuid(cpuInfo, 0);
    uint64_t rdtscStart = __rdtsc();
    __cpuid(cpuInfo, 0);
    uint64_t rdtscEnd = __rdtsc();
    uint64_t rdtscDelta = rdtscEnd - rdtscStart;
    
    // Measure RDTSCP
    uint64_t rdtscpStart = __rdtscp(&aux);
    uint64_t rdtscpEnd = __rdtscp(&aux);
    uint64_t rdtscpDelta = rdtscpEnd - rdtscpStart;
    
    return static_cast<int64_t>(rdtscpDelta) - static_cast<int64_t>(rdtscDelta);
}

/// Fallback: TimingCPUIDLatency
uint64_t Fallback_TimingCPUIDLatency(void) {
    uint64_t sum = 0;
    int cpuInfo[4];
    constexpr int iterations = 100;
    
    for (int i = 0; i < iterations; ++i) {
        uint64_t start = __rdtsc();
        __cpuid(cpuInfo, 0);
        uint64_t end = __rdtsc();
        sum += (end - start);
    }
    
    return sum / iterations;
}

/// Fallback: TimingCheckHypervisorLeaf
uint32_t Fallback_TimingCheckHypervisorLeaf(char* vendorOut) {
    int cpuInfo[4];
    
    // Check hypervisor bit (CPUID.1:ECX.31)
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 31))) {
        return 0;  // No hypervisor
    }
    
    // Query hypervisor leaf
    __cpuid(cpuInfo, 0x40000000);
    
    if (vendorOut) {
        *reinterpret_cast<int*>(vendorOut) = cpuInfo[1];
        *reinterpret_cast<int*>(vendorOut + 4) = cpuInfo[2];
        *reinterpret_cast<int*>(vendorOut + 8) = cpuInfo[3];
        vendorOut[12] = '\0';
    }
    
    return 1;
}

/// Fallback: TimingCPUIDVariance
uint64_t Fallback_TimingCPUIDVariance(void) {
    constexpr int iterations = 50;
    uint64_t measurements[50];
    int cpuInfo[4];
    uint64_t sum = 0;
    
    // Collect measurements
    for (int i = 0; i < iterations; ++i) {
        uint64_t start = __rdtsc();
        __cpuid(cpuInfo, 0);
        uint64_t end = __rdtsc();
        measurements[i] = end - start;
        sum += measurements[i];
    }
    
    // Calculate mean
    uint64_t mean = sum / iterations;
    
    // Calculate variance
    uint64_t variance = 0;
    for (int i = 0; i < iterations; ++i) {
        int64_t diff = static_cast<int64_t>(measurements[i]) - static_cast<int64_t>(mean);
        variance += static_cast<uint64_t>(diff * diff);
    }
    
    return variance / iterations;
}

/// Fallback: TimingMeasureSleep
uint64_t Fallback_TimingMeasureSleep(uint32_t sleepMs) {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    uint64_t start = __rdtsc();
    
    Sleep(sleepMs);
    
    __cpuid(cpuInfo, 0);
    uint64_t end = __rdtsc();
    
    return end - start;
}

/// Fallback: TimingDetectSleepAcceleration
uint32_t Fallback_TimingDetectSleepAcceleration(uint32_t sleepMs) {
    if (sleepMs < 100) return 0;
    
    ULONGLONG startTicks = GetTickCount64();
    Sleep(sleepMs);
    ULONGLONG endTicks = GetTickCount64();
    
    ULONGLONG actualMs = endTicks - startTicks;
    
    if (actualMs >= sleepMs) {
        return 0;  // No acceleration
    }
    
    // Calculate acceleration percentage
    return static_cast<uint32_t>(((sleepMs - actualMs) * 100) / sleepMs);
}

/// Fallback: TimingCalibrateTimebase - stored frequency
/// THREAD-SAFETY FIX: Use atomic variables and call_once for thread-safe calibration
static std::atomic<uint64_t> g_tscFrequency_fallback{0};
static std::atomic<int> g_calibration_state{0};  // 0=not done, 1=in progress, 2=complete
static constexpr uint64_t DEFAULT_TSC_FREQ = 3000000000ULL;  // 3 GHz fallback

uint64_t Fallback_TimingCalibrateTimebase(void) {
    // Fast path: already calibrated
    if (g_calibration_state.load(std::memory_order_acquire) == 2) {
        return g_tscFrequency_fallback.load(std::memory_order_relaxed);
    }
    
    // Try to acquire calibration lock (0 -> 1)
    int expected = 0;
    if (!g_calibration_state.compare_exchange_strong(expected, 1, 
            std::memory_order_acq_rel, std::memory_order_acquire)) {
        // Another thread is calibrating or already done
        if (expected == 2) {
            return g_tscFrequency_fallback.load(std::memory_order_relaxed);
        }
        // Spin-wait for calibration to complete
        while (g_calibration_state.load(std::memory_order_acquire) == 1) {
            Sleep(1);
        }
        return g_tscFrequency_fallback.load(std::memory_order_relaxed);
    }
    
    // We won the race - perform calibration
    LARGE_INTEGER freq, startQpc, endQpc;
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) {
        g_tscFrequency_fallback.store(DEFAULT_TSC_FREQ, std::memory_order_relaxed);
        g_calibration_state.store(2, std::memory_order_release);
        return DEFAULT_TSC_FREQ;
    }
    
    QueryPerformanceCounter(&startQpc);
    
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);  // Serialize
    uint64_t startTsc = __rdtsc();
    
    // Sleep for reliable timing (not busy wait)
    Sleep(100);
    
    __cpuid(cpuInfo, 0);  // Serialize
    uint64_t endTsc = __rdtsc();
    QueryPerformanceCounter(&endQpc);
    
    // Calculate frequency with overflow protection
    uint64_t tscDelta = endTsc - startTsc;
    uint64_t qpcDelta = static_cast<uint64_t>(endQpc.QuadPart - startQpc.QuadPart);
    
    uint64_t frequency = DEFAULT_TSC_FREQ;
    if (qpcDelta > 0) {
        // Use 128-bit multiplication via compiler intrinsic to prevent overflow
        // TSC_freq = (TSC_delta * QPC_freq) / QPC_delta
        uint64_t high;
        uint64_t low = _umul128(tscDelta, static_cast<uint64_t>(freq.QuadPart), &high);
        
        // Perform 128-bit / 64-bit division
        if (high == 0) {
            // No overflow case - simple division
            frequency = low / qpcDelta;
        } else {
            // Overflow case - approximate by shifting
            // Shift right until high is 0, divide, shift result back
            int shift = 0;
            while (high > 0 && shift < 64) {
                high >>= 1;
                low = (low >> 1) | ((high & 1) << 63);
                high >>= 1;
                shift++;
            }
            frequency = (low / qpcDelta) << shift;
        }
        
        // Sanity check: frequency should be between 100MHz and 10GHz
        if (frequency < 100000000ULL) frequency = DEFAULT_TSC_FREQ;
        if (frequency > 10000000000ULL) frequency = DEFAULT_TSC_FREQ;
    }
    
    g_tscFrequency_fallback.store(frequency, std::memory_order_relaxed);
    g_calibration_state.store(2, std::memory_order_release);
    
    return frequency;
}

/// Fallback: TimingMeasureInstructions
uint64_t Fallback_TimingMeasureInstructions(void) {
    uint64_t start = __rdtsc();
    
    // 100 simple operations
    volatile int x = 0;
    for (int i = 0; i < 100; ++i) {
        x++;
    }
    (void)x;
    
    uint64_t end = __rdtsc();
    return end - start;
}

/// Fallback: TimingMeasureMemory
uint64_t Fallback_TimingMeasureMemory(void) {
    alignas(64) static volatile char buffer[4096];
    
    // Flush cache
    _mm_clflush(const_cast<char*>(&buffer[0]));
    _mm_mfence();
    
    // Measure uncached access
    uint64_t start = __rdtsc();
    volatile char x = buffer[0];
    (void)x;
    _mm_lfence();
    uint64_t end = __rdtsc();
    
    return end - start;
}

/// Fallback: TimingDetectSingleStep
uint32_t Fallback_TimingDetectSingleStep(void) {
    uint64_t start = __rdtsc();
    
    // 20 NOPs - should take ~20 cycles normally
    for (int i = 0; i < 20; ++i) {
        __nop();
    }
    
    uint64_t end = __rdtsc();
    
    // > 500 cycles indicates single-stepping
    return (end - start > 500) ? 1 : 0;
}

/// Fallback: TimingGetTSCFrequency
uint64_t Fallback_TimingGetTSCFrequency(void) {
    // Check if calibration is complete
    if (g_calibration_state.load(std::memory_order_acquire) == 2) {
        return g_tscFrequency_fallback.load(std::memory_order_relaxed);
    }
    
    // Try CPUID leaf 0x15 first (doesn't require calibration)
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x15);
    
    uint32_t denominator = cpuInfo[0];
    uint32_t numerator = cpuInfo[1];
    uint32_t frequency = cpuInfo[2];
    
    if (numerator != 0 && denominator != 0 && frequency != 0) {
        return (static_cast<uint64_t>(frequency) * numerator) / denominator;
    }
    
    // Fall back to calibrated value (may trigger calibration)
    return Fallback_TimingCalibrateTimebase();
}

/// Fallback: TimingDetectVMExit
uint32_t Fallback_TimingDetectVMExit(uint64_t* details) {
    uint32_t score = 0;
    
    // Test 1: RDTSC overhead
    uint64_t rdtscOverhead = Fallback_TimingSerializedRDTSC();
    if (rdtscOverhead > 500) {
        score += 35;
    }
    
    // Test 2: CPUID latency
    uint64_t cpuidLatency = Fallback_TimingCPUIDLatency();
    if (cpuidLatency > 1500) {
        score += 40;
    }
    
    // Test 3: Hypervisor bit
    uint32_t hvPresent = Fallback_TimingCheckHypervisorLeaf(nullptr);
    if (hvPresent) {
        score += 25;
    }
    
    // Store details if requested
    if (details) {
        details[0] = rdtscOverhead;
        details[1] = cpuidLatency;
        details[2] = hvPresent;
    }
    
    return (score > 100) ? 100 : score;
}

/// Fallback: TimingMeasureHypervisor
uint64_t Fallback_TimingMeasureHypervisor(void) {
    int cpuInfo[4];
    
    // Check for hypervisor first
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 31))) {
        return 0;  // No hypervisor
    }
    
    // Measure hypervisor CPUID leaf timing
    uint64_t start = __rdtsc();
    __cpuid(cpuInfo, 0x40000000);
    uint64_t end = __rdtsc();
    
    return end - start;
}

} // extern "C"

#include "../Utils/ThreadPool.hpp"

namespace ShadowStrike {
namespace AntiEvasion {

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

namespace {

    /// @brief Log category for this module
    constexpr const wchar_t* LOG_CATEGORY = L"TimeEvasion";

    /// @brief Maximum code bytes to scan for RDTSC patterns
    constexpr size_t MAX_CODE_SCAN_SIZE = 1024 * 1024;  // 1MB

    /// @brief Maximum instructions to disassemble per function
    constexpr size_t MAX_INSTRUCTIONS_PER_SCAN = 10000;

    /// @brief Minimum RDTSC call count to consider suspicious
    /// FALSE POSITIVE FIX: Raised significantly to reduce false positives
    /// 
    /// Legitimate software that uses RDTSC heavily:
    /// - Game engines (Unreal, Unity): Frame timing, performance profiling
    /// - Profilers (VTune, perf tools): Instruction-level timing
    /// - Crypto libraries: RNG seeding, timing attack mitigations
    /// - Scientific software: High-precision benchmarking
    /// - Multimedia codecs: A/V synchronization
    /// - Database engines: Query timing, lock contention measurement
    ///
    /// Previous value (20) was flagging too many legitimate applications.
    /// New threshold requires significant RDTSC usage pattern to trigger.
    constexpr uint64_t MIN_RDTSC_FOR_SUSPICION = 100;

    /// @brief Default callback ID counter start
    constexpr uint64_t CALLBACK_ID_START = 1000;

    /// @brief Timing API import names for detection
    const std::vector<std::string> TIMING_API_IMPORTS = {
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
        "QueryPerformanceFrequency",
        "GetSystemTimeAsFileTime",
        "GetSystemTimePreciseAsFileTime",
        "timeGetTime",
        "NtQuerySystemTime",
        "RtlGetSystemTimePrecise"
    };

    /// @brief Sleep-related API imports
    const std::vector<std::string> SLEEP_API_IMPORTS = {
        "Sleep",
        "SleepEx",
        "NtDelayExecution",
        "WaitForSingleObject",
        "WaitForSingleObjectEx",
        "WaitForMultipleObjects",
        "WaitForMultipleObjectsEx",
        "MsgWaitForMultipleObjects",
        "MsgWaitForMultipleObjectsEx",
        "SetWaitableTimer",
        "SetWaitableTimerEx"
    };

    /// @brief NTP-related patterns in strings
    const std::vector<std::wstring> NTP_PATTERNS = {
        L"time.windows.com",
        L"time.nist.gov",
        L"pool.ntp.org",
        L"time.google.com",
        L"ntp.ubuntu.com",
        L"time.apple.com",
        L"clock.isc.org"
    };

} // anonymous namespace

// ============================================================================
// TIMING INSTRUCTION PATTERNS
// ============================================================================

namespace TimingPatterns {

    /// @brief Pattern for RDTSC instruction (0F 31)
    static const std::vector<uint8_t> RDTSC_PATTERN = { 0x0F, 0x31 };

    /// @brief Pattern for RDTSCP instruction (0F 01 F9)
    static const std::vector<uint8_t> RDTSCP_PATTERN = { 0x0F, 0x01, 0xF9 };

    /// @brief Pattern for CPUID instruction (0F A2)
    static const std::vector<uint8_t> CPUID_PATTERN = { 0x0F, 0xA2 };

    /// @brief Match pattern in buffer
    [[nodiscard]] bool MatchPattern(
        const uint8_t* buffer,
        size_t bufferSize,
        size_t offset,
        const std::vector<uint8_t>& pattern) noexcept
    {
        if (offset + pattern.size() > bufferSize) {
            return false;
        }

        for (size_t i = 0; i < pattern.size(); ++i) {
            if (buffer[offset + i] != pattern[i]) {
                return false;
            }
        }
        return true;
    }

    /// @brief Count pattern occurrences in buffer
    [[nodiscard]] size_t CountPatternOccurrences(
        const uint8_t* buffer,
        size_t bufferSize,
        const std::vector<uint8_t>& pattern) noexcept
    {
        size_t count = 0;
        for (size_t i = 0; i + pattern.size() <= bufferSize; ++i) {
            if (MatchPattern(buffer, bufferSize, i, pattern)) {
                ++count;
                i += pattern.size() - 1;  // Skip past matched pattern
            }
        }
        return count;
    }

} // namespace TimingPatterns

// ============================================================================
// PROCESS MONITORING STATE
// ============================================================================

struct ProcessMonitoringContext {
    uint32_t processId = 0;
    MonitoringState state = MonitoringState::Inactive;
    std::chrono::steady_clock::time_point startTime{};
    std::chrono::steady_clock::time_point lastUpdate{};

    // Accumulated statistics
    uint64_t rdtscCount = 0;
    uint64_t sleepTotalMs = 0;
    uint32_t sleepCallCount = 0;
    uint32_t getTickCountCalls = 0;
    uint32_t qpcCalls = 0;

    // Event history (ring buffer)
    std::vector<TimingEventRecord> events;
    size_t eventWriteIndex = 0;
    size_t eventCount = 0;

    // Detection flags
    bool rdtscHighFrequencyDetected = false;
    bool sleepBombingDetected = false;
    bool sleepAccelerationDetected = false;

    void AddEvent(const TimingEventRecord& event, size_t maxEvents) {
        if (events.size() < maxEvents) {
            events.push_back(event);
            ++eventCount;
        } else {
            events[eventWriteIndex] = event;
            eventWriteIndex = (eventWriteIndex + 1) % maxEvents;
            if (eventCount < maxEvents) ++eventCount;
        }
    }
};

// ============================================================================
// IMPLEMENTATION CLASS
// ============================================================================

struct TimeBasedEvasionDetector::Impl {
    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    std::atomic<bool> m_initialized{ false };
    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_monitorMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_cacheMutex;

    TimingDetectorConfig m_config;
    TimingDetectorStats m_stats;

    std::shared_ptr<Utils::ThreadPool> m_threadPool;

    // Zydis disassembler contexts
    ZydisDecoder m_decoder32{};
    ZydisDecoder m_decoder64{};
    ZydisFormatter m_formatter{};

    // Process monitoring contexts
    std::unordered_map<uint32_t, std::unique_ptr<ProcessMonitoringContext>> m_monitoredProcesses;

    // Callbacks
    std::atomic<uint64_t> m_nextCallbackId{ CALLBACK_ID_START };
    std::unordered_map<uint64_t, TimingEvasionCallback> m_callbacks;
    std::unordered_map<uint64_t, TimingEventCallback> m_eventCallbacks;

    // Result cache
    struct CacheEntry {
        TimingEvasionResult result;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::unordered_map<uint32_t, CacheEntry> m_resultCache;

    // Monitoring thread control
    std::atomic<bool> m_monitoringActive{ false };
    std::thread m_monitoringThread;
    std::condition_variable m_monitoringCv;
    std::mutex m_monitoringCvMutex;

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    Impl() {
        // Initialize Zydis decoders
        ZydisDecoderInit(&m_decoder32, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
        ZydisDecoderInit(&m_decoder64, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        ZydisFormatterInit(&m_formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    }

    ~Impl() {
        Shutdown();
    }

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(
        std::shared_ptr<Utils::ThreadPool> threadPool,
        const TimingDetectorConfig& config)
    {
        std::unique_lock lock(m_mutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            return true;
        }

        m_threadPool = std::move(threadPool);
        m_config = config;

        // Validate configuration
        if (m_config.sampleInterval < TimingConstants::MIN_SAMPLE_INTERVAL) {
            m_config.sampleInterval = TimingConstants::MIN_SAMPLE_INTERVAL;
        }
        if (m_config.sampleInterval > TimingConstants::MAX_SAMPLE_INTERVAL) {
            m_config.sampleInterval = TimingConstants::MAX_SAMPLE_INTERVAL;
        }

        m_initialized.store(true, std::memory_order_release);

        SS_LOG_INFO(LOG_CATEGORY, L"TimeBasedEvasionDetector initialized");

        return true;
    }

    void Shutdown() {
        if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        // Stop monitoring thread
        StopAllMonitoring();

        // Clear state
        {
            std::unique_lock lock(m_mutex);
            m_threadPool.reset();
        }

        {
            std::unique_lock lock(m_monitorMutex);
            m_monitoredProcesses.clear();
        }

        {
            std::unique_lock lock(m_callbackMutex);
            m_callbacks.clear();
            m_eventCallbacks.clear();
        }

        {
            std::unique_lock lock(m_cacheMutex);
            m_resultCache.clear();
        }

        SS_LOG_INFO(LOG_CATEGORY, L"TimeBasedEvasionDetector shut down");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    void UpdateConfig(const TimingDetectorConfig& config) {
        std::unique_lock lock(m_mutex);
        m_config = config;

        // Validate bounds
        if (m_config.sampleInterval < TimingConstants::MIN_SAMPLE_INTERVAL) {
            m_config.sampleInterval = TimingConstants::MIN_SAMPLE_INTERVAL;
        }
        if (m_config.sampleInterval > TimingConstants::MAX_SAMPLE_INTERVAL) {
            m_config.sampleInterval = TimingConstants::MAX_SAMPLE_INTERVAL;
        }
    }

    [[nodiscard]] TimingDetectorConfig GetConfig() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // PROCESS ANALYSIS
    // ========================================================================

    [[nodiscard]] TimingEvasionResult AnalyzeProcess(uint32_t processId) {
        TimingEvasionResult result;
        result.processId = processId;
        result.analysisStartTime = std::chrono::system_clock::now();

        // Check cache first
        if (m_config.enableResultCache) {
            auto cached = GetCachedResult(processId);
            if (cached) {
                m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
                return *cached;
            }
            m_stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);
        }

        // Get process info
        Utils::ProcessUtils::ProcessBasicInfo procInfo;
        Utils::ProcessUtils::Error err;
        if (!Utils::ProcessUtils::GetProcessBasicInfo(processId, procInfo, &err)) {
            result.errorMessage = L"Failed to get process info: " + err.message;
            result.analysisComplete = false;
            m_stats.analysisErrors.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        result.processName = procInfo.name;
        result.processPath = procInfo.executablePath;
        result.commandLine = procInfo.commandLine;
        result.parentProcessId = procInfo.parentPid;

        // Get parent process name
        Utils::ProcessUtils::ProcessBasicInfo parentInfo;
        if (Utils::ProcessUtils::GetProcessBasicInfo(procInfo.parentPid, parentInfo, nullptr)) {
            result.parentProcessName = parentInfo.name;
        }

        // Run detection checks
        TimingDetectorConfig config;
        {
            std::shared_lock lock(m_mutex);
            config = m_config;
        }

        if (config.detectRDTSC) {
            CheckRDTSCAbuse(processId, procInfo.is64Bit, result);
        }

        if (config.detectSleepEvasion) {
            CheckSleepEvasion(processId, result);
        }

        if (config.detectAPITiming) {
            CheckTimerAnomalies(processId, result);
            CheckTimeDriftChecks(processId, result);
        }

        if (config.detectNTPEvasion) {
            CheckNTPEvasion(processId, result);
        }

        if (config.detectHardwareTimers) {
            CheckHardwareTimers(processId, result);
        }

        // Correlate findings
        if (config.enableCorrelation) {
            CorrelateFindings(result);
        }

        // Calculate threat score
        CalculateThreatScore(result);

        // Add MITRE mappings
        if (config.enableMitreMapping) {
            AddMitreMappings(result);
        }

        // Finalize
        result.analysisEndTime = std::chrono::system_clock::now();
        result.analysisDurationMs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                result.analysisEndTime - result.analysisStartTime
            ).count()
        );
        result.analysisComplete = true;

        // Update statistics
        m_stats.totalProcessesAnalyzed.fetch_add(1, std::memory_order_relaxed);
        if (result.isEvasive) {
            m_stats.totalEvasionsDetected.fetch_add(1, std::memory_order_relaxed);
        }

        // Update cache
        if (config.enableResultCache) {
            UpdateCache(processId, result);
        }

        return result;
    }

    [[nodiscard]] bool AnalyzeProcessAsync(
        uint32_t processId,
        std::function<void(TimingEvasionResult)> callback)
    {
        if (!m_threadPool) {
            // Run synchronously if no thread pool
            callback(AnalyzeProcess(processId));
            return true;
        }

        // FIX (Issue #3): Use thread pool instead of detached thread
        // Detached threads capture 'this' and cause use-after-free on shutdown
        // ThreadPool properly manages thread lifetime and allows graceful shutdown
        try {
            // Use Submit with TaskContext parameter as required by ThreadPool API
            (void)m_threadPool->Submit([this, processId, callback = std::move(callback)](const Utils::TaskContext& /*ctx*/) {
                // Check if detector is still active before proceeding
                if (!m_initialized.load(std::memory_order_acquire)) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Async analysis cancelled - detector shutdown");
                    return;
                }
                
                try {
                    auto result = AnalyzeProcess(processId);
                    callback(std::move(result));
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Async analysis failed: %hs", e.what());
                    // Create error result to notify caller
                    TimingEvasionResult errorResult;
                    errorResult.processId = processId;
                    errorResult.isEvasive = false;
                    callback(std::move(errorResult));
                }
            });
            return true;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to queue async analysis: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool QuickScanProcess(uint32_t processId) {
        // Quick check for obvious timing evasion
        Utils::ProcessUtils::ProcessHandle hProcess(processId,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);

        if (!hProcess.IsValid()) {
            return false;
        }

        // Get process modules and check for timing API imports
        std::vector<Utils::ProcessUtils::ProcessModuleInfo> modules;
        if (!Utils::ProcessUtils::EnumerateProcessModules(processId, modules)) {
            return false;
        }

        // Check main module for suspicious patterns
        if (modules.empty()) {
            return false;
        }

        const auto& mainModule = modules[0];

        // Check if high number of timing-related imports
        size_t timingImportCount = 0;

        // Parse PE to check imports
        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        if (parser.ParseFile(mainModule.path, peInfo, nullptr)) {
            std::vector<PEParser::ImportInfo> imports;
            if (parser.ParseImports(imports, nullptr)) {
                for (const auto& dll : imports) {
                    for (const auto& func : dll.functions) {
                        for (const auto& timingApi : TIMING_API_IMPORTS) {
                            if (func.name == timingApi) {
                                ++timingImportCount;
                            }
                        }
                    }
                }
            }
        }

        // FIX (Issue #8): Raised from >4 to >8 with context - multimedia apps use many timing APIs
        // More than 8 timing APIs is suspicious, but only if not known-good software
        return timingImportCount > 8;
    }

    // ========================================================================
    // RDTSC ANALYSIS
    // ========================================================================

    [[nodiscard]] RDTSCAnalysis AnalyzeRDTSC(uint32_t processId) {
        RDTSCAnalysis analysis;
        analysis.processId = processId;

        auto startTime = std::chrono::steady_clock::now();

        Utils::ProcessUtils::ProcessHandle hProcess(processId,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);

        if (!hProcess.IsValid()) {
            return analysis;
        }

        // Get executable module
        std::vector<Utils::ProcessUtils::ProcessModuleInfo> modules;
        if (!Utils::ProcessUtils::EnumerateProcessModules(processId, modules) || modules.empty()) {
            return analysis;
        }

        const auto& mainModule = modules[0];
        bool is64Bit = false;

        // FIX (Issue #1): Capture the return value - previous code ignored it!
        // This caused all 64-bit malware to be analyzed with wrong Zydis decoder
        is64Bit = Utils::ProcessUtils::IsProcess64Bit(processId);

        // Read code section and scan for RDTSC patterns
        if (mainModule.baseAddress && mainModule.size > 0) {
            size_t scanSize = std::min(mainModule.size, MAX_CODE_SCAN_SIZE);
            std::vector<uint8_t> codeBuffer(scanSize);

            SIZE_T bytesRead = 0;
            if (Utils::ProcessUtils::ReadProcessMemory(processId,
                mainModule.baseAddress, codeBuffer.data(), scanSize, &bytesRead)) {

                // Count RDTSC instructions
                analysis.rdtscCount = TimingPatterns::CountPatternOccurrences(
                    codeBuffer.data(), bytesRead, TimingPatterns::RDTSC_PATTERN);

                // Count RDTSCP instructions
                analysis.rdtscpCount = TimingPatterns::CountPatternOccurrences(
                    codeBuffer.data(), bytesRead, TimingPatterns::RDTSCP_PATTERN);

                // Check for RDTSC+CPUID combinations
                analysis.rdtscCpuidComboCount = CountRDTSCCPUIDCombos(
                    codeBuffer.data(), bytesRead);

                // Analyze using Zydis for more accurate detection
                AnalyzeCodeWithZydis(codeBuffer.data(), bytesRead, is64Bit, analysis);
            }
        }

        auto endTime = std::chrono::steady_clock::now();
        analysis.observationDurationMs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count()
        );

        // Determine detection flags
        TimingDetectorConfig config;
        {
            std::shared_lock lock(m_mutex);
            config = m_config;
        }

        if (analysis.rdtscCount >= MIN_RDTSC_FOR_SUSPICION) {
            analysis.highFrequencyDetected = true;
            // PRECISION FIX: Calculate confidence with proper clamping before float conversion
            // Scale: 100 RDTSC = 10% confidence base, up to 1000 = 100% confidence
            // Using integer math first to avoid float precision issues
            uint64_t scaledCount = std::min(analysis.rdtscCount, 1000ULL);
            analysis.confidence = static_cast<float>(scaledCount) / 10.0f;
        }

        if (analysis.rdtscCpuidComboCount >= 2) {
            analysis.deltaCheckDetected = true;
            analysis.confidence = std::max(analysis.confidence, 70.0f);
        }

        return analysis;
    }

    // ========================================================================
    // SLEEP ANALYSIS
    // ========================================================================

    [[nodiscard]] SleepAnalysis AnalyzeSleep(uint32_t processId) {
        SleepAnalysis analysis;
        analysis.processId = processId;

        // Get process modules
        std::vector<Utils::ProcessUtils::ProcessModuleInfo> modules;
        if (!Utils::ProcessUtils::EnumerateProcessModules(processId, modules) || modules.empty()) {
            return analysis;
        }

        // Parse PE imports for sleep-related APIs
        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        if (!parser.ParseFile(modules[0].path, peInfo, nullptr)) {
            return analysis;
        }

        std::vector<PEParser::ImportInfo> imports;
        if (!parser.ParseImports(imports, nullptr)) {
            return analysis;
        }

        // Check for sleep-related imports
        for (const auto& dll : imports) {
            std::string dllNameLower = Utils::StringUtils::ToNarrow(dll.dllName);
            std::transform(dllNameLower.begin(), dllNameLower.end(),
                dllNameLower.begin(), ::tolower);

            for (const auto& func : dll.functions) {
                for (const auto& sleepApi : SLEEP_API_IMPORTS) {
                    if (func.name == sleepApi) {
                        analysis.sleepAPIsUsed.push_back(
                            Utils::StringUtils::ToWide(func.name));
                    }
                }
            }
        }

        // Check monitoring context for runtime data
        {
            std::shared_lock lock(m_monitorMutex);
            auto it = m_monitoredProcesses.find(processId);
            if (it != m_monitoredProcesses.end()) {
                const auto& ctx = *it->second;
                analysis.sleepCallCount = ctx.sleepCallCount;
                analysis.totalRequestedDurationMs = ctx.sleepTotalMs;
                analysis.sleepBombingDetected = ctx.sleepBombingDetected;
                analysis.accelerationDetected = ctx.sleepAccelerationDetected;
            }
        }

        // Detect sleep bombing (many sleep APIs + high import count)
        if (analysis.sleepAPIsUsed.size() >= 3) {
            analysis.sleepBombingDetected = true;
            analysis.confidence = 60.0f;
        }

        return analysis;
    }

    // ========================================================================
    // API TIMING ANALYSIS
    // ========================================================================

    [[nodiscard]] APITimingAnalysis AnalyzeAPITiming(uint32_t processId) {
        APITimingAnalysis analysis;
        analysis.processId = processId;

        // Get expected QPC frequency
        LARGE_INTEGER freq;
        if (QueryPerformanceFrequency(&freq)) {
            analysis.expectedQpcFrequencyHz = static_cast<uint64_t>(freq.QuadPart);
        }

        // Get process modules
        std::vector<Utils::ProcessUtils::ProcessModuleInfo> modules;
        if (!Utils::ProcessUtils::EnumerateProcessModules(processId, modules) || modules.empty()) {
            return analysis;
        }

        // Parse PE imports
        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        if (!parser.ParseFile(modules[0].path, peInfo, nullptr)) {
            return analysis;
        }

        std::vector<PEParser::ImportInfo> imports;
        if (!parser.ParseImports(imports, nullptr)) {
            return analysis;
        }

        // Count timing API imports
        for (const auto& dll : imports) {
            for (const auto& func : dll.functions) {
                if (func.name == "GetTickCount" || func.name == "GetTickCount64") {
                    ++analysis.getTickCountCalls;
                }
                if (func.name == "QueryPerformanceCounter") {
                    ++analysis.qpcCalls;
                }
                if (func.name == "GetSystemTimeAsFileTime") {
                    ++analysis.systemTimeCalls;
                }
                if (func.name == "timeGetTime") {
                    ++analysis.timeGetTimeCalls;
                }
                if (func.name == "GetSystemTimePreciseAsFileTime") {
                    ++analysis.preciseTimeCalls;
                }
            }
        }

        // Detect cross-checking (multiple timing APIs used together)
        uint32_t timingApiCount = 0;
        if (analysis.getTickCountCalls > 0) ++timingApiCount;
        if (analysis.qpcCalls > 0) ++timingApiCount;
        if (analysis.systemTimeCalls > 0) ++timingApiCount;
        if (analysis.timeGetTimeCalls > 0) ++timingApiCount;
        if (analysis.preciseTimeCalls > 0) ++timingApiCount;

        if (timingApiCount >= 3) {
            analysis.crossCheckDetected = true;
            analysis.crossCheckCount = timingApiCount;
            analysis.confidence = 70.0f;
        }

        return analysis;
    }

    // ========================================================================
    // NTP ANALYSIS
    // ========================================================================

    [[nodiscard]] NTPAnalysis AnalyzeNTP(uint32_t processId) {
        NTPAnalysis analysis;
        analysis.processId = processId;

        // Get process command line and search for NTP server references
        auto cmdLine = Utils::ProcessUtils::GetProcessCommandLine(processId);
        if (cmdLine) {
            std::wstring cmdLower = *cmdLine;
            std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::towlower);

            for (const auto& pattern : NTP_PATTERNS) {
                if (cmdLower.find(pattern) != std::wstring::npos) {
                    analysis.ntpServers.push_back(pattern);
                    ++analysis.ntpQueryCount;
                }
            }
        }

        // Check network connections for NTP port (123)
        // This would require network monitoring which is beyond scope here
        // For now, we check imports for network-related APIs

        std::vector<Utils::ProcessUtils::ProcessModuleInfo> modules;
        if (!Utils::ProcessUtils::EnumerateProcessModules(processId, modules) || modules.empty()) {
            return analysis;
        }

        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        if (parser.ParseFile(modules[0].path, peInfo, nullptr)) {
            std::vector<PEParser::ImportInfo> imports;
            if (parser.ParseImports(imports, nullptr)) {
                for (const auto& dll : imports) {
                    std::string dllNameLower = Utils::StringUtils::ToNarrow(dll.dllName);
                    std::transform(dllNameLower.begin(), dllNameLower.end(),
                        dllNameLower.begin(), ::tolower);

                    // Check for WinHTTP/WinInet (used for HTTP time checks)
                    if (dllNameLower.find("winhttp") != std::string::npos ||
                        dllNameLower.find("wininet") != std::string::npos) {
                        ++analysis.httpTimeCheckCount;
                    }

                    // Check for ws2_32 (UDP for NTP)
                    if (dllNameLower.find("ws2_32") != std::string::npos) {
                        // Could be NTP client
                        ++analysis.externalTimeAPICalls;
                    }
                }
            }
        }

        if (analysis.ntpQueryCount > 0 || analysis.httpTimeCheckCount > 0) {
            analysis.externalValidationDetected = true;
            analysis.confidence = 50.0f;
        }

        return analysis;
    }

    // ========================================================================
    // DETECTION CHECKS
    // ========================================================================

    void CheckRDTSCAbuse(uint32_t processId, bool is64Bit, TimingEvasionResult& result) {
        auto rdtscAnalysis = AnalyzeRDTSC(processId);

        if (rdtscAnalysis.HasRDTSCEvasion()) {
            TimingEvasionFinding finding;
            finding.detectionTime = std::chrono::system_clock::now();
            finding.detectionMethod = TimingDetectionMethod::StaticAnalysis;

            if (rdtscAnalysis.highFrequencyDetected) {
                finding.type = TimingEvasionType::RDTSCHighFrequency;
                finding.severity = TimingEvasionSeverity::High;
                finding.confidence = rdtscAnalysis.confidence;
                finding.description = L"High-frequency RDTSC instruction usage detected";
                finding.technicalDetails = Utils::StringUtils::Format(
                    L"RDTSC count: %llu, RDTSCP count: %llu",
                    rdtscAnalysis.rdtscCount, rdtscAnalysis.rdtscpCount);
                finding.mitreId = "T1497.003";

                result.findings.push_back(finding);
                result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::RDTSCHighFrequency));
                result.rdtscCallCount = rdtscAnalysis.rdtscCount;
            }

            if (rdtscAnalysis.deltaCheckDetected) {
                finding.type = TimingEvasionType::RDTSCDeltaCheck;
                finding.severity = TimingEvasionSeverity::High;
                finding.confidence = 80.0f;
                finding.description = L"RDTSC delta checking pattern detected (VM detection)";
                finding.technicalDetails = Utils::StringUtils::Format(
                    L"RDTSC+CPUID combos: %llu", rdtscAnalysis.rdtscCpuidComboCount);
                finding.mitreId = "T1497.003";

                result.findings.push_back(finding);
                result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::RDTSCDeltaCheck));
            }

            if (rdtscAnalysis.rdtscpCount > 0) {
                finding.type = TimingEvasionType::RDTSCPUsage;
                finding.severity = TimingEvasionSeverity::Medium;
                finding.confidence = 60.0f;
                finding.description = L"RDTSCP instruction usage detected";
                finding.mitreId = "T1497.003";

                result.findings.push_back(finding);
                result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::RDTSCPUsage));
            }

            result.isEvasive = true;
        }
    }

    void CheckSleepEvasion(uint32_t processId, TimingEvasionResult& result) {
        auto sleepAnalysis = AnalyzeSleep(processId);

        if (sleepAnalysis.HasSleepEvasion()) {
            TimingEvasionFinding finding;
            finding.detectionTime = std::chrono::system_clock::now();
            finding.detectionMethod = TimingDetectionMethod::StaticAnalysis;

            if (sleepAnalysis.sleepBombingDetected) {
                finding.type = TimingEvasionType::SleepBombing;
                finding.severity = TimingEvasionSeverity::High;
                finding.confidence = sleepAnalysis.confidence;
                finding.description = L"Sleep bombing pattern detected (sandbox timeout attempt)";
                finding.technicalDetails = Utils::StringUtils::Format(
                    L"Sleep APIs used: %zu, Total sleep: %llu ms",
                    sleepAnalysis.sleepAPIsUsed.size(),
                    sleepAnalysis.totalRequestedDurationMs);
                finding.mitreId = "T1497.003";

                result.findings.push_back(finding);
                result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::SleepBombing));
                result.totalSleepDurationMs = sleepAnalysis.totalRequestedDurationMs;
                result.sleepCallCount = sleepAnalysis.sleepCallCount;
            }

            if (sleepAnalysis.accelerationDetected) {
                finding.type = TimingEvasionType::SleepAccelerationDetect;
                finding.severity = TimingEvasionSeverity::Critical;
                finding.confidence = 90.0f;
                finding.description = L"Sleep acceleration detection attempt";
                finding.technicalDetails = Utils::StringUtils::Format(
                    L"Acceleration ratio: %.2f", sleepAnalysis.accelerationRatio);
                finding.mitreId = "T1497.003";

                result.findings.push_back(finding);
                result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::SleepAccelerationDetect));
            }

            if (sleepAnalysis.fragmentationDetected) {
                finding.type = TimingEvasionType::SleepFragmentation;
                finding.severity = TimingEvasionSeverity::High;
                finding.confidence = 75.0f;
                finding.description = L"Sleep fragmentation pattern detected";
                finding.technicalDetails = Utils::StringUtils::Format(
                    L"Fragment count: %u, Avg fragment: %llu ms",
                    sleepAnalysis.fragmentedSleepCount,
                    sleepAnalysis.avgFragmentDurationMs);
                finding.mitreId = "T1497.003";

                result.findings.push_back(finding);
                result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::SleepFragmentation));
            }

            result.isEvasive = true;
        }
    }

    void CheckTimeDriftChecks(uint32_t processId, TimingEvasionResult& result) {
        // Check for patterns that indicate time drift detection
        auto apiAnalysis = AnalyzeAPITiming(processId);

        if (apiAnalysis.crossCheckDetected) {
            TimingEvasionFinding finding;
            finding.type = TimingEvasionType::TimingAPICrossCheck;
            finding.severity = TimingEvasionSeverity::High;
            finding.confidence = apiAnalysis.confidence;
            finding.detectionTime = std::chrono::system_clock::now();
            finding.detectionMethod = TimingDetectionMethod::StaticAnalysis;
            finding.description = L"Multiple timing API cross-check pattern detected";
            finding.technicalDetails = Utils::StringUtils::Format(
                L"Timing APIs detected: %u (GetTickCount: %u, QPC: %u, SystemTime: %u)",
                apiAnalysis.crossCheckCount,
                apiAnalysis.getTickCountCalls,
                apiAnalysis.qpcCalls,
                apiAnalysis.systemTimeCalls);
            finding.mitreId = "T1497.003";

            result.findings.push_back(finding);
            result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::TimingAPICrossCheck));
            result.getTickCountCalls = apiAnalysis.getTickCountCalls;
            result.qpcCallCount = apiAnalysis.qpcCalls;
            result.isEvasive = true;
        }
    }

    void CheckTimerAnomalies(uint32_t processId, TimingEvasionResult& result) {
        auto apiAnalysis = AnalyzeAPITiming(processId);

        // FIX (Issue #8): Raised thresholds to reduce false positives
        // Network monitoring tools, audio/video software legitimately use these APIs frequently
        
        // High GetTickCount usage - raised from 5 to 15
        // Legitimate use: Network tools (Wireshark), performance monitors, game engines
        if (apiAnalysis.getTickCountCalls > 15) {
            TimingEvasionFinding finding;
            finding.type = TimingEvasionType::GetTickCountDelta;
            finding.severity = TimingEvasionSeverity::Low;  // Reduced from Medium
            finding.confidence = 35.0f;  // Reduced from 50.0f - many false positives
            finding.detectionTime = std::chrono::system_clock::now();
            finding.detectionMethod = TimingDetectionMethod::StaticAnalysis;
            finding.description = L"High GetTickCount usage detected";
            finding.technicalDetails = Utils::StringUtils::Format(
                L"GetTickCount import count: %u (threshold: 15)", apiAnalysis.getTickCountCalls);
            finding.mitreId = "T1497.003";

            result.findings.push_back(finding);
            result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::GetTickCountDelta));
        }

        // High QPC usage - raised from 3 to 10
        // Legitimate use: Audio/video software, game engines, profilers, high-precision timing
        if (apiAnalysis.qpcCalls > 10) {
            TimingEvasionFinding finding;
            finding.type = TimingEvasionType::QPCAnomaly;
            finding.severity = TimingEvasionSeverity::Low;  // Reduced from Medium
            finding.confidence = 30.0f;  // Reduced from 45.0f - QPC is very commonly used
            finding.detectionTime = std::chrono::system_clock::now();
            finding.detectionMethod = TimingDetectionMethod::StaticAnalysis;
            finding.description = L"High QueryPerformanceCounter usage pattern detected";
            finding.technicalDetails = Utils::StringUtils::Format(
                L"QPC import count: %u (threshold: 10)", apiAnalysis.qpcCalls);
            finding.mitreId = "T1497.003";

            result.findings.push_back(finding);
            result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::QPCAnomaly));
        }

        // Precise time API usage (suspicious)
        if (apiAnalysis.preciseTimeCalls > 0) {
            TimingEvasionFinding finding;
            finding.type = TimingEvasionType::PreciseTimeCheck;
            finding.severity = TimingEvasionSeverity::Medium;
            finding.confidence = 55.0f;
            finding.detectionTime = std::chrono::system_clock::now();
            finding.detectionMethod = TimingDetectionMethod::StaticAnalysis;
            finding.description = L"GetSystemTimePreciseAsFileTime usage detected";
            finding.mitreId = "T1497.003";

            result.findings.push_back(finding);
            result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::PreciseTimeCheck));
        }
    }

    void CheckNTPEvasion(uint32_t processId, TimingEvasionResult& result) {
        auto ntpAnalysis = AnalyzeNTP(processId);

        if (ntpAnalysis.HasNTPEvasion()) {
            TimingEvasionFinding finding;
            finding.detectionTime = std::chrono::system_clock::now();
            finding.detectionMethod = TimingDetectionMethod::StaticAnalysis;

            if (ntpAnalysis.ntpQueryCount > 0) {
                finding.type = TimingEvasionType::NTPQuery;
                finding.severity = TimingEvasionSeverity::High;
                finding.confidence = ntpAnalysis.confidence;
                finding.description = L"NTP server query pattern detected";

                std::wstring servers;
                for (const auto& server : ntpAnalysis.ntpServers) {
                    if (!servers.empty()) servers += L", ";
                    servers += server;
                }
                finding.technicalDetails = L"NTP servers: " + servers;
                finding.mitreId = "T1497.003";

                result.findings.push_back(finding);
                result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::NTPQuery));
                result.ntpQueryCount = ntpAnalysis.ntpQueryCount;
            }

            if (ntpAnalysis.externalValidationDetected) {
                finding.type = TimingEvasionType::ExternalTimeValidation;
                finding.severity = TimingEvasionSeverity::High;
                finding.confidence = 65.0f;
                finding.description = L"External time validation attempt detected";
                finding.technicalDetails = Utils::StringUtils::Format(
                    L"HTTP time checks: %u, External API calls: %u",
                    ntpAnalysis.httpTimeCheckCount,
                    ntpAnalysis.externalTimeAPICalls);
                finding.mitreId = "T1497.003";

                result.findings.push_back(finding);
                result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::ExternalTimeValidation));
            }

            result.isEvasive = true;
        }
    }

    void CheckHardwareTimers(uint32_t processId, TimingEvasionResult& result) {
        // Check for direct hardware timer access patterns
        std::vector<Utils::ProcessUtils::ProcessModuleInfo> modules;
        if (!Utils::ProcessUtils::EnumerateProcessModules(processId, modules) || modules.empty()) {
            return;
        }

        // Look for kernel32/ntdll timing functions that might access hardware
        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        if (!parser.ParseFile(modules[0].path, peInfo, nullptr)) {
            return;
        }

        std::vector<PEParser::ImportInfo> imports;
        if (!parser.ParseImports(imports, nullptr)) {
            return;
        }

        bool hasNtQueryTimerResolution = false;
        bool hasNtSetTimerResolution = false;

        for (const auto& dll : imports) {
            std::string dllNameLower = Utils::StringUtils::ToNarrow(dll.dllName);
            std::transform(dllNameLower.begin(), dllNameLower.end(),
                dllNameLower.begin(), ::tolower);

            if (dllNameLower.find("ntdll") != std::string::npos) {
                for (const auto& func : dll.functions) {
                    if (func.name == "NtQueryTimerResolution") {
                        hasNtQueryTimerResolution = true;
                    }
                    if (func.name == "NtSetTimerResolution") {
                        hasNtSetTimerResolution = true;
                    }
                }
            }
        }

        if (hasNtQueryTimerResolution || hasNtSetTimerResolution) {
            TimingEvasionFinding finding;
            finding.type = TimingEvasionType::HardwareTimerDirect;
            finding.severity = TimingEvasionSeverity::Medium;
            finding.confidence = 55.0f;
            finding.detectionTime = std::chrono::system_clock::now();
            finding.detectionMethod = TimingDetectionMethod::StaticAnalysis;
            finding.description = L"Direct timer resolution manipulation detected";
            finding.technicalDetails = Utils::StringUtils::Format(
                L"NtQueryTimerResolution: %s, NtSetTimerResolution: %s",
                hasNtQueryTimerResolution ? L"yes" : L"no",
                hasNtSetTimerResolution ? L"yes" : L"no");
            finding.mitreId = "T1497.003";

            result.findings.push_back(finding);
            result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::HardwareTimerDirect));
        }
    }

    // ========================================================================
    // CORRELATION AND SCORING
    // ========================================================================

    void CorrelateFindings(TimingEvasionResult& result) {
        if (result.findings.size() < 2) {
            return;
        }

        // Check for multi-technique evasion
        size_t rdtscCount = 0;
        size_t sleepCount = 0;
        size_t apiCount = 0;
        size_t ntpCount = 0;

        for (const auto& finding : result.findings) {
            auto typeVal = static_cast<uint8_t>(finding.type);
            if (typeVal >= 1 && typeVal <= 19) ++rdtscCount;
            else if (typeVal >= 20 && typeVal <= 39) ++sleepCount;
            else if (typeVal >= 40 && typeVal <= 59) ++apiCount;
            else if (typeVal >= 60 && typeVal <= 79) ++ntpCount;
        }

        size_t categoryCount = 0;
        if (rdtscCount > 0) ++categoryCount;
        if (sleepCount > 0) ++categoryCount;
        if (apiCount > 0) ++categoryCount;
        if (ntpCount > 0) ++categoryCount;

        if (categoryCount >= 2) {
            TimingEvasionFinding finding;
            finding.type = TimingEvasionType::MultiTechniqueEvasion;
            finding.severity = TimingEvasionSeverity::Critical;
            finding.confidence = 90.0f;
            finding.detectionTime = std::chrono::system_clock::now();
            finding.detectionMethod = TimingDetectionMethod::BehavioralHeuristics;
            finding.description = L"Multiple timing evasion techniques detected";
            finding.technicalDetails = Utils::StringUtils::Format(
                L"Categories: %zu (RDTSC: %zu, Sleep: %zu, API: %zu, NTP: %zu)",
                categoryCount, rdtscCount, sleepCount, apiCount, ntpCount);
            finding.mitreId = "T1497.003";

            result.findings.push_back(finding);
            result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::MultiTechniqueEvasion));
        }
    }

    void CalculateThreatScore(TimingEvasionResult& result) {
        if (result.findings.empty()) {
            result.threatScore = 0.0f;
            result.confidence = 0.0f;
            result.severity = TimingEvasionSeverity::Info;
            result.isEvasive = false;
            return;
        }

        // Calculate weighted threat score
        float totalScore = 0.0f;
        float maxConfidence = 0.0f;
        TimingEvasionSeverity maxSeverity = TimingEvasionSeverity::Info;
        TimingEvasionType primaryType = TimingEvasionType::None;

        for (const auto& finding : result.findings) {
            // Weight by severity
            float severityWeight = 1.0f;
            switch (finding.severity) {
                case TimingEvasionSeverity::Critical: severityWeight = 4.0f; break;
                case TimingEvasionSeverity::High: severityWeight = 3.0f; break;
                case TimingEvasionSeverity::Medium: severityWeight = 2.0f; break;
                case TimingEvasionSeverity::Low: severityWeight = 1.0f; break;
                default: severityWeight = 0.5f; break;
            }

            totalScore += finding.confidence * severityWeight;

            if (finding.confidence > maxConfidence) {
                maxConfidence = finding.confidence;
                primaryType = finding.type;
            }

            if (finding.severity > maxSeverity) {
                maxSeverity = finding.severity;
            }
        }

        // Normalize score
        result.threatScore = std::min(100.0f, totalScore / 4.0f);
        result.confidence = maxConfidence;
        result.severity = maxSeverity;
        result.primaryEvasionType = primaryType;
        result.isEvasive = (result.threatScore >= 20.0f ||
            maxSeverity >= TimingEvasionSeverity::Medium);
    }

    void AddMitreMappings(TimingEvasionResult& result) {
        std::unordered_set<std::string> mitreIds;

        for (const auto& finding : result.findings) {
            const char* mitreId = TimingEvasionTypeToMitre(finding.type);
            if (mitreId && *mitreId) {
                mitreIds.insert(mitreId);
            }
        }

        result.mitreIds.assign(mitreIds.begin(), mitreIds.end());
        result.mitreTactic = "TA0005";  // Defense Evasion
    }

    // ========================================================================
    // SLEEP ACCELERATION DETECTION
    // ========================================================================

    [[nodiscard]] bool DetectSleepAcceleration(uint32_t processId) {
        // This would require runtime monitoring
        // For static analysis, we can only detect patterns
        auto sleepAnalysis = AnalyzeSleep(processId);
        return sleepAnalysis.accelerationDetected;
    }

    // ========================================================================
    // TIMING ANTI-DEBUG DETECTION
    // ========================================================================

    [[nodiscard]] bool DetectTimingAntiDebug(uint32_t processId) {
        auto rdtscAnalysis = AnalyzeRDTSC(processId);

        // RDTSC delta checks are commonly used for anti-debugging
        if (rdtscAnalysis.deltaCheckDetected || rdtscAnalysis.rdtscCpuidComboCount > 0) {
            return true;
        }

        // High QPC usage can also indicate timing-based anti-debug
        auto apiAnalysis = AnalyzeAPITiming(processId);
        if (apiAnalysis.qpcCalls > 5 && apiAnalysis.crossCheckDetected) {
            return true;
        }

        return false;
    }

    // ========================================================================
    // MONITORING
    // ========================================================================

    [[nodiscard]] bool StartMonitoring(uint32_t processId) {
        std::unique_lock lock(m_monitorMutex);

        if (m_monitoredProcesses.size() >= m_config.maxMonitoredProcesses) {
            SS_LOG_WARN(LOG_CATEGORY, L"Maximum monitored processes reached");
            return false;
        }

        auto& ctx = m_monitoredProcesses[processId];
        if (!ctx) {
            ctx = std::make_unique<ProcessMonitoringContext>();
            ctx->processId = processId;
            ctx->events.reserve(m_config.maxEventsPerProcess);
        }

        ctx->state = MonitoringState::Active;
        ctx->startTime = std::chrono::steady_clock::now();
        ctx->lastUpdate = ctx->startTime;

        m_stats.currentlyMonitoring.fetch_add(1, std::memory_order_relaxed);

        // FIX (Issue #4): Use compare_exchange_strong to prevent race condition
        // Multiple threads could previously pass the exchange(true) check simultaneously
        // compare_exchange_strong ensures only ONE thread starts the monitoring thread
        bool expected = false;
        if (m_monitoringActive.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel, std::memory_order_acquire)) {
            StartMonitoringThread();
        }

        return true;
    }

    void StopMonitoring(uint32_t processId) {
        std::unique_lock lock(m_monitorMutex);

        auto it = m_monitoredProcesses.find(processId);
        if (it != m_monitoredProcesses.end()) {
            it->second->state = MonitoringState::Completed;
            m_stats.currentlyMonitoring.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    void StopAllMonitoring() {
        {
            std::unique_lock lock(m_monitorMutex);
            for (auto& [pid, ctx] : m_monitoredProcesses) {
                ctx->state = MonitoringState::Completed;
            }
            m_stats.currentlyMonitoring.store(0, std::memory_order_relaxed);
        }

        // Stop monitoring thread
        m_monitoringActive.store(false, std::memory_order_release);
        m_monitoringCv.notify_all();

        if (m_monitoringThread.joinable()) {
            m_monitoringThread.join();
        }
    }

    [[nodiscard]] bool IsMonitoring(uint32_t processId) const {
        std::shared_lock lock(m_monitorMutex);
        auto it = m_monitoredProcesses.find(processId);
        if (it != m_monitoredProcesses.end()) {
            return it->second->state == MonitoringState::Active;
        }
        return false;
    }

    [[nodiscard]] MonitoringState GetMonitoringState(uint32_t processId) const {
        std::shared_lock lock(m_monitorMutex);
        auto it = m_monitoredProcesses.find(processId);
        if (it != m_monitoredProcesses.end()) {
            return it->second->state;
        }
        return MonitoringState::Inactive;
    }

    void PauseMonitoring(uint32_t processId) {
        std::unique_lock lock(m_monitorMutex);
        auto it = m_monitoredProcesses.find(processId);
        if (it != m_monitoredProcesses.end() &&
            it->second->state == MonitoringState::Active) {
            it->second->state = MonitoringState::Paused;
        }
    }

    void ResumeMonitoring(uint32_t processId) {
        std::unique_lock lock(m_monitorMutex);
        auto it = m_monitoredProcesses.find(processId);
        if (it != m_monitoredProcesses.end() &&
            it->second->state == MonitoringState::Paused) {
            it->second->state = MonitoringState::Active;
        }
    }

    [[nodiscard]] std::vector<uint32_t> GetMonitoredProcesses() const {
        std::shared_lock lock(m_monitorMutex);
        std::vector<uint32_t> pids;
        pids.reserve(m_monitoredProcesses.size());
        for (const auto& [pid, ctx] : m_monitoredProcesses) {
            if (ctx->state == MonitoringState::Active ||
                ctx->state == MonitoringState::Paused) {
                pids.push_back(pid);
            }
        }
        return pids;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    [[nodiscard]] uint64_t RegisterCallback(TimingEvasionCallback callback) {
        std::unique_lock lock(m_callbackMutex);
        uint64_t id = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
        m_callbacks[id] = std::move(callback);
        return id;
    }

    bool UnregisterCallback(uint64_t callbackId) {
        std::unique_lock lock(m_callbackMutex);
        return m_callbacks.erase(callbackId) > 0;
    }

    [[nodiscard]] uint64_t RegisterEventCallback(TimingEventCallback callback) {
        std::unique_lock lock(m_callbackMutex);
        uint64_t id = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
        m_eventCallbacks[id] = std::move(callback);
        return id;
    }

    bool UnregisterEventCallback(uint64_t callbackId) {
        std::unique_lock lock(m_callbackMutex);
        return m_eventCallbacks.erase(callbackId) > 0;
    }

    void InvokeCallbacks(const TimingEvasionResult& result) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& [id, callback] : m_callbacks) {
            if (callback) {
                try {
                    callback(result);
                } catch (...) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Exception in timing evasion callback");
                }
            }
        }
    }

    // ========================================================================
    // STATISTICS & CACHE
    // ========================================================================

    [[nodiscard]] const TimingDetectorStats& GetStats() const {
        return m_stats;
    }

    void ResetStats() {
        m_stats.Reset();
    }

    [[nodiscard]] std::optional<TimingEvasionResult> GetCachedResult(uint32_t processId) const {
        std::shared_lock lock(m_cacheMutex);

        auto it = m_resultCache.find(processId);
        if (it == m_resultCache.end()) {
            return std::nullopt;
        }

        // Check TTL
        auto now = std::chrono::steady_clock::now();
        auto age = std::chrono::duration_cast<std::chrono::minutes>(
            now - it->second.timestamp);

        if (age > m_config.resultCacheTTL) {
            return std::nullopt;
        }

        return it->second.result;
    }

    void ClearCache() {
        std::unique_lock lock(m_cacheMutex);
        m_resultCache.clear();
    }

    void ClearCacheForProcess(uint32_t processId) {
        std::unique_lock lock(m_cacheMutex);
        m_resultCache.erase(processId);
    }

    void UpdateCache(uint32_t processId, const TimingEvasionResult& result) {
        std::unique_lock lock(m_cacheMutex);

        // FIX (Issue #5): O(n²) cache eviction replaced with O(n) single-pass
        // Previous code: O(n) loop inside O(n) eviction = O(n²) under exclusive lock
        // This blocked all cache operations when cache was full
        constexpr size_t CACHE_MAX_SIZE = 1000;
        constexpr size_t CACHE_EVICT_COUNT = 50;  // Evict 50 at once to amortize cost
        
        if (m_resultCache.size() >= CACHE_MAX_SIZE) {
            // Find and remove oldest entries in single pass
            // Use partial_sort for O(n log k) instead of O(n²)
            std::vector<std::pair<uint32_t, std::chrono::steady_clock::time_point>> entries;
            entries.reserve(m_resultCache.size());
            
            for (const auto& [pid, cached] : m_resultCache) {
                entries.emplace_back(pid, cached.timestamp);
            }
            
            // Partial sort to find oldest CACHE_EVICT_COUNT entries - O(n log k)
            size_t evictCount = std::min(CACHE_EVICT_COUNT, entries.size());
            std::partial_sort(entries.begin(), entries.begin() + evictCount, entries.end(),
                [](const auto& a, const auto& b) {
                    return a.second < b.second;  // Oldest first
                });
            
            // Remove the oldest entries
            for (size_t i = 0; i < evictCount; ++i) {
                m_resultCache.erase(entries[i].first);
            }
        }

        m_resultCache[processId] = { result, std::chrono::steady_clock::now() };
    }

    [[nodiscard]] std::vector<TimingEventRecord> GetEventHistory(
        uint32_t processId,
        size_t maxEvents) const
    {
        std::shared_lock lock(m_monitorMutex);

        auto it = m_monitoredProcesses.find(processId);
        if (it == m_monitoredProcesses.end()) {
            return {};
        }

        const auto& ctx = *it->second;
        
        // FIX (Issue #7): Check for empty events vector to prevent division by zero
        if (ctx.events.empty() || ctx.eventCount == 0) {
            return {};
        }
        
        size_t count = (maxEvents == 0) ? ctx.eventCount : std::min(maxEvents, ctx.eventCount);
        
        // FIX (Issue #2): Correct ring buffer index calculation
        // Previous code had integer underflow when count > eventWriteIndex
        std::vector<TimingEventRecord> result;
        result.reserve(count);

        const size_t bufferSize = ctx.events.size();
        
        // Check if ring buffer has wrapped around
        if (ctx.eventCount < bufferSize) {
            // Buffer hasn't wrapped - events are at indices [0, eventCount)
            size_t startIdx = (ctx.eventCount > count) ? (ctx.eventCount - count) : 0;
            size_t actualCount = std::min(count, ctx.eventCount);
            for (size_t i = 0; i < actualCount; ++i) {
                result.push_back(ctx.events[startIdx + i]);
            }
        } else {
            // Buffer has wrapped - use proper ring buffer arithmetic
            // eventWriteIndex points to next write position (oldest entry when full)
            // We want the last 'count' entries before the write position
            for (size_t i = 0; i < count; ++i) {
                // Safe calculation: add bufferSize first to prevent underflow
                size_t idx = (bufferSize + ctx.eventWriteIndex - count + i) % bufferSize;
                result.push_back(ctx.events[idx]);
            }
        }

        return result;
    }

private:
    // ========================================================================
    // INTERNAL HELPERS (truly private - not accessed via public wrappers)
    // ========================================================================

    void StartMonitoringThread() {
        m_monitoringThread = std::thread([this]() {
            while (m_monitoringActive.load(std::memory_order_acquire)) {
                MonitoringLoop();

                // Sleep for sample interval
                std::unique_lock lock(m_monitoringCvMutex);
                m_monitoringCv.wait_for(lock, m_config.sampleInterval, [this]() {
                    return !m_monitoringActive.load(std::memory_order_acquire);
                });
            }
        });
    }

    void MonitoringLoop() {
        std::vector<uint32_t> activeProcesses;

        {
            std::shared_lock lock(m_monitorMutex);
            for (const auto& [pid, ctx] : m_monitoredProcesses) {
                if (ctx->state == MonitoringState::Active) {
                    activeProcesses.push_back(pid);
                }
            }
        }

        for (uint32_t pid : activeProcesses) {
            MonitoringTickInternal(pid);
        }
    }
    
    /// @brief Internal tick - called from MonitoringLoop (private)
    void MonitoringTickInternal(uint32_t processId) {
        // FIX (Issue #6): TOCTOU race condition
        // Wrap analysis in try-catch to handle process termination gracefully
        
        if (!Utils::ProcessUtils::IsProcessRunning(processId)) {
            MarkProcessCompleted(processId);
            return;
        }

        TimingEvasionResult result;
        bool analysisSucceeded = false;
        
        try {
            result = AnalyzeProcess(processId);
            analysisSucceeded = true;
        } catch (const std::exception& e) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"Process %u analysis failed (likely terminated): %hs", 
                processId, e.what());
            MarkProcessCompleted(processId);
            return;
        }
        
        if (!analysisSucceeded || !Utils::ProcessUtils::IsProcessRunning(processId)) {
            MarkProcessCompleted(processId);
            return;
        }

        if (result.isEvasive) {
            InvokeCallbacks(result);
        }

        {
            std::unique_lock lock(m_monitorMutex);
            auto it = m_monitoredProcesses.find(processId);
            if (it != m_monitoredProcesses.end()) {
                it->second->lastUpdate = std::chrono::steady_clock::now();
                it->second->rdtscCount = result.rdtscCallCount;
            }
        }
    }
    
    /// @brief Helper to mark a process as completed
    void MarkProcessCompleted(uint32_t processId) {
        std::unique_lock lock(m_monitorMutex);
        auto it = m_monitoredProcesses.find(processId);
        if (it != m_monitoredProcesses.end() && 
            it->second->state != MonitoringState::Completed) {
            it->second->state = MonitoringState::Completed;
            m_stats.currentlyMonitoring.fetch_sub(1, std::memory_order_relaxed);
        }
    }

public:
    // ========================================================================
    // PUBLIC HELPER METHODS (called via public wrapper methods in main class)
    // ========================================================================

    void MonitoringTick(uint32_t processId) {
        MonitoringTickInternal(processId);
    }

    void RecordTimingEvent(const TimingEventRecord& event) {
        {
            std::unique_lock lock(m_monitorMutex);
            auto it = m_monitoredProcesses.find(event.processId);
            if (it != m_monitoredProcesses.end()) {
                it->second->AddEvent(event, m_config.maxEventsPerProcess);
            }
        }

        // Invoke event callbacks
        {
            std::shared_lock lock(m_callbackMutex);
            for (const auto& [id, callback] : m_eventCallbacks) {
                if (callback) {
                    try {
                        callback(event);
                    } catch (...) {
                        SS_LOG_ERROR(LOG_CATEGORY, L"Exception in timing event callback");
                    }
                }
            }
        }

        m_stats.totalEventsProcessed.fetch_add(1, std::memory_order_relaxed);
    }

    [[nodiscard]] size_t CountRDTSCCPUIDCombos(
        const uint8_t* buffer,
        size_t bufferSize) const
    {
        size_t count = 0;
        const size_t MAX_DISTANCE = 20;  // Max bytes between CPUID and RDTSC

        for (size_t i = 0; i + TimingPatterns::CPUID_PATTERN.size() <= bufferSize; ++i) {
            if (TimingPatterns::MatchPattern(buffer, bufferSize, i, TimingPatterns::CPUID_PATTERN)) {
                // Look for RDTSC within MAX_DISTANCE bytes
                for (size_t j = i + TimingPatterns::CPUID_PATTERN.size();
                     j < std::min(i + MAX_DISTANCE, bufferSize - 1); ++j) {
                    if (TimingPatterns::MatchPattern(buffer, bufferSize, j, TimingPatterns::RDTSC_PATTERN)) {
                        ++count;
                        i = j;  // Skip past this combo
                        break;
                    }
                }
            }
        }

        return count;
    }

    void AnalyzeCodeWithZydis(
        const uint8_t* code,
        size_t codeSize,
        bool is64Bit,
        RDTSCAnalysis& analysis)
    {
        ZydisDecoder* decoder = is64Bit ? &m_decoder64 : &m_decoder32;

        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZyanUSize offset = 0;
        size_t instructionCount = 0;

        uint64_t rdtscCount = 0;
        uint64_t rdtscpCount = 0;
        bool seenCpuid = false;

        while (offset < codeSize && instructionCount < MAX_INSTRUCTIONS_PER_SCAN) {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, code + offset,
                codeSize - offset, &instruction, operands))) {
                ++offset;
                continue;
            }

            switch (instruction.mnemonic) {
                case ZYDIS_MNEMONIC_RDTSC:
                    ++rdtscCount;
                    if (seenCpuid) {
                        // CPUID+RDTSC combo for serialization
                        ++analysis.rdtscCpuidComboCount;
                    }
                    seenCpuid = false;
                    break;

                case ZYDIS_MNEMONIC_RDTSCP:
                    ++rdtscpCount;
                    break;

                case ZYDIS_MNEMONIC_CPUID:
                    seenCpuid = true;
                    break;

                default:
                    // Reset CPUID tracking after non-RDTSC instruction
                    if (instruction.mnemonic != ZYDIS_MNEMONIC_MOV &&
                        instruction.mnemonic != ZYDIS_MNEMONIC_PUSH &&
                        instruction.mnemonic != ZYDIS_MNEMONIC_XOR) {
                        seenCpuid = false;
                    }
                    break;
            }

            offset += instruction.length;
            ++instructionCount;
        }

        analysis.rdtscCount = std::max(analysis.rdtscCount, rdtscCount);
        analysis.rdtscpCount = std::max(analysis.rdtscpCount, rdtscpCount);
    }
};

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

TimeBasedEvasionDetector& TimeBasedEvasionDetector::Instance() {
    static TimeBasedEvasionDetector instance;
    return instance;
}

TimeBasedEvasionDetector::TimeBasedEvasionDetector()
    : m_impl(std::make_unique<Impl>())
{}

TimeBasedEvasionDetector::~TimeBasedEvasionDetector() = default;

bool TimeBasedEvasionDetector::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool) {
    return m_impl->Initialize(std::move(threadPool), TimingDetectorConfig::CreateDefault());
}

bool TimeBasedEvasionDetector::Initialize(
    std::shared_ptr<Utils::ThreadPool> threadPool,
    const TimingDetectorConfig& config)
{
    return m_impl->Initialize(std::move(threadPool), config);
}

void TimeBasedEvasionDetector::Shutdown() {
    m_impl->Shutdown();
}

bool TimeBasedEvasionDetector::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

void TimeBasedEvasionDetector::UpdateConfig(const TimingDetectorConfig& config) {
    m_impl->UpdateConfig(config);
}

TimingDetectorConfig TimeBasedEvasionDetector::GetConfig() const {
    return m_impl->GetConfig();
}

TimingEvasionResult TimeBasedEvasionDetector::AnalyzeProcess(uint32_t processId) {
    return m_impl->AnalyzeProcess(processId);
}

bool TimeBasedEvasionDetector::AnalyzeProcessAsync(
    uint32_t processId,
    std::function<void(TimingEvasionResult)> callback)
{
    return m_impl->AnalyzeProcessAsync(processId, std::move(callback));
}

bool TimeBasedEvasionDetector::QuickScanProcess(uint32_t processId) {
    return m_impl->QuickScanProcess(processId);
}

RDTSCAnalysis TimeBasedEvasionDetector::AnalyzeRDTSC(uint32_t processId) {
    return m_impl->AnalyzeRDTSC(processId);
}

SleepAnalysis TimeBasedEvasionDetector::AnalyzeSleep(uint32_t processId) {
    return m_impl->AnalyzeSleep(processId);
}

APITimingAnalysis TimeBasedEvasionDetector::AnalyzeAPITiming(uint32_t processId) {
    return m_impl->AnalyzeAPITiming(processId);
}

NTPAnalysis TimeBasedEvasionDetector::AnalyzeNTP(uint32_t processId) {
    return m_impl->AnalyzeNTP(processId);
}

bool TimeBasedEvasionDetector::DetectSleepAcceleration(uint32_t processId) {
    return m_impl->DetectSleepAcceleration(processId);
}

bool TimeBasedEvasionDetector::DetectTimingAntiDebug(uint32_t processId) {
    return m_impl->DetectTimingAntiDebug(processId);
}

bool TimeBasedEvasionDetector::StartMonitoring(uint32_t processId) {
    return m_impl->StartMonitoring(processId);
}

void TimeBasedEvasionDetector::StopMonitoring(uint32_t processId) {
    m_impl->StopMonitoring(processId);
}

void TimeBasedEvasionDetector::StopAllMonitoring() {
    m_impl->StopAllMonitoring();
}

bool TimeBasedEvasionDetector::IsMonitoring(uint32_t processId) const {
    return m_impl->IsMonitoring(processId);
}

MonitoringState TimeBasedEvasionDetector::GetMonitoringState(uint32_t processId) const {
    return m_impl->GetMonitoringState(processId);
}

void TimeBasedEvasionDetector::PauseMonitoring(uint32_t processId) {
    m_impl->PauseMonitoring(processId);
}

void TimeBasedEvasionDetector::ResumeMonitoring(uint32_t processId) {
    m_impl->ResumeMonitoring(processId);
}

std::vector<uint32_t> TimeBasedEvasionDetector::GetMonitoredProcesses() const {
    return m_impl->GetMonitoredProcesses();
}

uint64_t TimeBasedEvasionDetector::RegisterCallback(TimingEvasionCallback callback) {
    return m_impl->RegisterCallback(std::move(callback));
}

bool TimeBasedEvasionDetector::UnregisterCallback(uint64_t callbackId) {
    return m_impl->UnregisterCallback(callbackId);
}

uint64_t TimeBasedEvasionDetector::RegisterEventCallback(TimingEventCallback callback) {
    return m_impl->RegisterEventCallback(std::move(callback));
}

bool TimeBasedEvasionDetector::UnregisterEventCallback(uint64_t callbackId) {
    return m_impl->UnregisterEventCallback(callbackId);
}

const TimingDetectorStats& TimeBasedEvasionDetector::GetStats() const {
    return m_impl->GetStats();
}

void TimeBasedEvasionDetector::ResetStats() {
    m_impl->ResetStats();
}

std::optional<TimingEvasionResult> TimeBasedEvasionDetector::GetCachedResult(uint32_t processId) const {
    return m_impl->GetCachedResult(processId);
}

void TimeBasedEvasionDetector::ClearCache() {
    m_impl->ClearCache();
}

void TimeBasedEvasionDetector::ClearCacheForProcess(uint32_t processId) {
    m_impl->ClearCacheForProcess(processId);
}

std::vector<TimingEventRecord> TimeBasedEvasionDetector::GetEventHistory(
    uint32_t processId,
    size_t maxEvents) const
{
    return m_impl->GetEventHistory(processId, maxEvents);
}

// ============================================================================
// PRIVATE METHOD IMPLEMENTATIONS
// ============================================================================

void TimeBasedEvasionDetector::CheckRDTSCAbuse(uint32_t processId, TimingEvasionResult& result) {
    bool is64Bit = Utils::ProcessUtils::IsProcess64Bit(processId);
    m_impl->CheckRDTSCAbuse(processId, is64Bit, result);
}

void TimeBasedEvasionDetector::CheckTimeDriftChecks(uint32_t processId, TimingEvasionResult& result) {
    m_impl->CheckTimeDriftChecks(processId, result);
}

void TimeBasedEvasionDetector::CheckTimerAnomalies(uint32_t processId, TimingEvasionResult& result) {
    m_impl->CheckTimerAnomalies(processId, result);
}

void TimeBasedEvasionDetector::CheckSleepEvasion(uint32_t processId, TimingEvasionResult& result) {
    m_impl->CheckSleepEvasion(processId, result);
}

void TimeBasedEvasionDetector::CheckNTPEvasion(uint32_t processId, TimingEvasionResult& result) {
    m_impl->CheckNTPEvasion(processId, result);
}

void TimeBasedEvasionDetector::CheckHardwareTimers(uint32_t processId, TimingEvasionResult& result) {
    m_impl->CheckHardwareTimers(processId, result);
}

void TimeBasedEvasionDetector::CorrelateFindings(TimingEvasionResult& result) {
    m_impl->CorrelateFindings(result);
}

void TimeBasedEvasionDetector::CalculateThreatScore(TimingEvasionResult& result) {
    m_impl->CalculateThreatScore(result);
}

void TimeBasedEvasionDetector::AddMitreMappings(TimingEvasionResult& result) {
    m_impl->AddMitreMappings(result);
}

void TimeBasedEvasionDetector::MonitoringTick(uint32_t processId) {
    m_impl->MonitoringTick(processId);
}

void TimeBasedEvasionDetector::InvokeCallbacks(const TimingEvasionResult& result) {
    m_impl->InvokeCallbacks(result);
}

void TimeBasedEvasionDetector::RecordTimingEvent(const TimingEventRecord& event) {
    m_impl->RecordTimingEvent(event);
}

void TimeBasedEvasionDetector::UpdateCache(uint32_t processId, const TimingEvasionResult& result) {
    m_impl->UpdateCache(processId, result);
}

} // namespace AntiEvasion
} // namespace ShadowStrike
