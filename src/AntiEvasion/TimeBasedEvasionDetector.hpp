/**
 * @file TimeBasedEvasionDetector.hpp
 * @brief Enterprise-grade detection of timing-based sandbox/analysis evasion techniques.
 *
 * This module provides comprehensive detection of timing attacks used by malware to
 * evade sandbox analysis, virtual machine detection, and automated security tools.
 *
 * =============================================================================
 * DETECTED TECHNIQUES (MITRE ATT&CK T1497.003 - Time Based Evasion)
 * =============================================================================
 *
 * 1. RDTSC (Read Time-Stamp Counter) Abuse:
 *    - High-frequency RDTSC instruction execution for VM detection
 *    - RDTSC delta checks to detect hypervisor overhead
 *    - RDTSCP instruction usage for serialized timing
 *
 * 2. Sleep-Based Evasion:
 *    - Extended sleep calls to timeout analysis (Sleep bombing)
 *    - Sleep acceleration detection (sandbox fast-forwarding)
 *    - Fragmented sleeps to evade acceleration
 *    - NtDelayExecution/SleepEx abuse
 *
 * 3. API Timing Checks:
 *    - GetTickCount/GetTickCount64 delta analysis
 *    - QueryPerformanceCounter/QueryPerformanceFrequency checks
 *    - GetSystemTimeAsFileTime comparisons
 *    - timeGetTime() inconsistencies
 *
 * 4. NTP/Network Time Evasion:
 *    - NTP server queries to detect time drift
 *    - External time source validation
 *    - Time synchronization monitoring
 *
 * 5. Hardware Timer Abuse:
 *    - HPET (High Precision Event Timer) access
 *    - ACPI PM Timer queries
 *    - TSC frequency measurement
 *
 * 6. Timing Side-Channel Detection:
 *    - Instruction timing analysis
 *    - Cache timing attacks
 *    - Branch prediction timing
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    TimeBasedEvasionDetector                              │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
 * │  │  RDTSC Monitor  │  │  Sleep Analyzer │  │  API Tracker    │         │
 * │  │  - Instruction  │  │  - Duration     │  │  - GetTickCount │         │
 * │  │    frequency    │  │  - Acceleration │  │  - QPC          │         │
 * │  │  - Delta check  │  │  - Fragmentation│  │  - SystemTime   │         │
 * │  └─────────────────┘  └─────────────────┘  └─────────────────┘         │
 * │           │                   │                   │                     │
 * │           └───────────────────┼───────────────────┘                     │
 * │                               ▼                                         │
 * │                    ┌─────────────────────┐                              │
 * │                    │  Detection Engine   │                              │
 * │                    │  - Correlation      │                              │
 * │                    │  - Confidence calc  │                              │
 * │                    │  - Pattern matching │                              │
 * │                    └─────────────────────┘                              │
 * │                               │                                         │
 * │                               ▼                                         │
 * │                    ┌─────────────────────┐                              │
 * │                    │  Result Aggregator  │                              │
 * │                    │  - MITRE mapping    │                              │
 * │                    │  - Threat scoring   │                              │
 * │                    └─────────────────────┘                              │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * @note Thread-safe for all public methods.
 * @note Requires PROCESS_QUERY_INFORMATION and PROCESS_VM_READ access rights.
 *
 * @see ProcessUtils for process monitoring utilities
 * @see Timer for timing infrastructure
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#pragma once

 // ============================================================================
 // INFRASTRUCTURE INCLUDES
 // ============================================================================
#include "../Utils/ProcessUtils.hpp"          // Process context
#include "../Utils/SystemUtils.hpp"           // System timing
#include "../PatternStore/PatternStore.hpp"   // Timing patterns

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <bitset>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// =============================================================================
// ASSEMBLY FUNCTION DECLARATIONS (TimeBasedEvasionDetector_x64.asm)
// =============================================================================
// These functions provide low-level CPU timing measurements that CANNOT be
// reliably implemented in C++ due to:
// - Compiler optimizations that reorder or eliminate timing instructions
// - Instruction scheduling that adds variable overhead
// - Need for precise CPUID serialization before RDTSC
// - Detection of sub-microsecond VM exit latency
// =============================================================================

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Gets RDTSC value with CPUID serialization
/// @return 64-bit TSC value
uint64_t TimingGetPreciseRDTSC(void);

/// @brief Gets RDTSCP value with optional processor ID
/// @param processorId Optional pointer for processor ID (can be NULL)
/// @return 64-bit TSC value
uint64_t TimingGetPreciseRDTSCP(uint32_t* processorId);

/// @brief Measures raw RDTSC instruction overhead
/// @return Average RDTSC overhead in cycles
uint64_t TimingRDTSCDelta(void);

/// @brief Measures RDTSC with CPUID serialization (gold-standard for VM detection)
/// @return Average serialized RDTSC overhead in cycles
uint64_t TimingSerializedRDTSC(void);

/// @brief Compares RDTSC and RDTSCP timing
/// @return Difference (RDTSCP - RDTSC) in cycles
int64_t TimingCompareRDTSCvRDTSCP(void);

/// @brief Measures CPUID instruction latency (always causes VM exit)
/// @return Average CPUID overhead in cycles
uint64_t TimingCPUIDLatency(void);

/// @brief Checks for hypervisor via CPUID leaf 0x40000000
/// @param vendorOut Buffer for vendor string (13 bytes min) or NULL
/// @return 1 if hypervisor present, 0 otherwise
uint32_t TimingCheckHypervisorLeaf(char* vendorOut);

/// @brief Measures variance in CPUID timing (VMs have higher variance)
/// @return Variance metric (higher = likely VM)
uint64_t TimingCPUIDVariance(void);

/// @brief Measures actual sleep duration using TSC
/// @param sleepMs Requested sleep duration in milliseconds
/// @return Actual sleep duration in TSC cycles
uint64_t TimingMeasureSleep(uint32_t sleepMs);

/// @brief Detects sandbox sleep acceleration
/// @param sleepMs Sleep duration to test (recommended: 500-1000ms)
/// @return Acceleration percentage (0 = none, >30 = likely sandbox)
uint32_t TimingDetectSleepAcceleration(uint32_t sleepMs);

/// @brief Calibrates TSC frequency using QueryPerformanceCounter
/// @return TSC frequency in Hz
uint64_t TimingCalibrateTimebase(void);

/// @brief Measures timing of known instruction sequence (single-step detection)
/// @return Cycles for 100 simple instructions
uint64_t TimingMeasureInstructions(void);

/// @brief Measures memory access latency (VM memory virtualization detection)
/// @return Memory access latency in cycles
uint64_t TimingMeasureMemory(void);

/// @brief Detects single-step debugging via timing
/// @return 1 if single-stepping detected, 0 otherwise
uint32_t TimingDetectSingleStep(void);

/// @brief Returns cached or estimated TSC frequency
/// @return TSC frequency in Hz (0 if not calibrated)
uint64_t TimingGetTSCFrequency(void);

/// @brief Comprehensive VM detection using multiple timing sources
/// @param details Optional pointer to receive detailed measurements (3 uint64_t)
/// @return Confidence score 0-100 (>50 = likely VM)
uint32_t TimingDetectVMExit(uint64_t* details);

/// @brief Measures timing characteristics specific to hypervisors
/// @return Hypervisor overhead measurement (0 if no hypervisor)
uint64_t TimingMeasureHypervisor(void);

#ifdef __cplusplus
}
#endif

// Forward declarations to avoid header pollution
namespace ShadowStrike::Utils {
    class ThreadPool;
    class TimerManager;
    namespace ProcessUtils {
        struct ProcessInfo;
        struct ProcessThreadInfo;
        struct ProcessBasicInfo;
    }
}

namespace ShadowStrike {
    namespace AntiEvasion {

        // ============================================================================
        // FORWARD DECLARATIONS
        // ============================================================================

        class TimeBasedEvasionDetector;
        struct TimingEvasionResult;
        struct TimingEventRecord;

        // ============================================================================
        // CONSTANTS
        // ============================================================================

        namespace TimingConstants {
            /// @brief Maximum monitored processes (memory safety)
            constexpr size_t MAX_MONITORED_PROCESSES = 10000;

            /// @brief Maximum timing events per process
            constexpr size_t MAX_EVENTS_PER_PROCESS = 50000;

            /// @brief Default sample interval for continuous monitoring
            constexpr std::chrono::milliseconds DEFAULT_SAMPLE_INTERVAL{ 100 };

            /// @brief Minimum sample interval (prevent excessive CPU usage)
            constexpr std::chrono::milliseconds MIN_SAMPLE_INTERVAL{ 10 };

            /// @brief Maximum sample interval
            constexpr std::chrono::milliseconds MAX_SAMPLE_INTERVAL{ 60000 };

            /// @brief RDTSC threshold for high-frequency detection (calls per second)
            constexpr uint64_t RDTSC_HIGH_FREQUENCY_THRESHOLD = 10000;

            /// @brief RDTSC delta threshold for VM detection (nanoseconds)
            constexpr uint64_t RDTSC_DELTA_VM_THRESHOLD_NS = 1000;

            /// @brief Sleep duration threshold for evasion detection (milliseconds)
            constexpr uint64_t SLEEP_EVASION_THRESHOLD_MS = 60000;  // 1 minute

            /// @brief Sleep acceleration detection threshold (ratio)
            constexpr double SLEEP_ACCELERATION_RATIO_THRESHOLD = 0.5;

            /// @brief Minimum sleep fragments to trigger fragmentation detection
            constexpr size_t MIN_SLEEP_FRAGMENTS_FOR_DETECTION = 10;

            /// @brief Time drift threshold for NTP evasion (seconds)
            constexpr int64_t TIME_DRIFT_THRESHOLD_SECONDS = 60;

            /// @brief GetTickCount delta anomaly threshold (percentage)
            constexpr double TICKCOUNT_DELTA_ANOMALY_PERCENT = 10.0;

            /// @brief QPC frequency anomaly threshold (percentage)
            constexpr double QPC_FREQUENCY_ANOMALY_PERCENT = 5.0;

            /// @brief Maximum confidence score
            constexpr float MAX_CONFIDENCE_SCORE = 100.0f;

            /// @brief Minimum confidence for detection reporting
            constexpr float MIN_REPORTABLE_CONFIDENCE = 10.0f;

            /// @brief History retention duration for analysis
            constexpr std::chrono::hours HISTORY_RETENTION_DURATION{ 24 };

            /// @brief Cache TTL for analysis results
            constexpr std::chrono::minutes RESULT_CACHE_TTL{ 5 };
        }

        // ============================================================================
        // ENUMERATIONS
        // ============================================================================

        /**
         * @brief Types of timing-based evasion techniques detected.
         *
         * Maps to MITRE ATT&CK T1497.003 (Time Based Evasion) sub-techniques.
         */
        enum class TimingEvasionType : uint8_t {
            /// @brief No evasion detected
            None = 0,

            // -------------------------------------------------------------------------
            // RDTSC-Based Techniques (1-19)
            // -------------------------------------------------------------------------

            /// @brief High-frequency RDTSC instruction execution
            RDTSCHighFrequency = 1,

            /// @brief RDTSC delta check for VM/hypervisor detection
            RDTSCDeltaCheck = 2,

            /// @brief RDTSCP instruction usage (serialized timing)
            RDTSCPUsage = 3,

            /// @brief RDTSC combined with CPUID for serialization
            RDTSCCPUIDCombo = 4,

            /// @brief TSC frequency measurement for VM detection
            TSCFrequencyMeasurement = 5,

            // -------------------------------------------------------------------------
            // Sleep-Based Techniques (20-39)
            // -------------------------------------------------------------------------

            /// @brief Extended sleep to timeout sandbox analysis
            SleepBombing = 20,

            /// @brief Sleep acceleration detection (sandbox fast-forward)
            SleepAccelerationDetect = 21,

            /// @brief Fragmented sleeps to evade acceleration
            SleepFragmentation = 22,

            /// @brief NtDelayExecution direct syscall usage
            NtDelayExecutionAbuse = 23,

            /// @brief SleepEx with alertable wait abuse
            SleepExAlertable = 24,

            /// @brief WaitForSingleObject with timeout for delay
            WaitForSingleObjectDelay = 25,

            /// @brief MsgWaitForMultipleObjects for stealthy delay
            MsgWaitDelay = 26,

            /// @brief SetTimer/WaitableTimer for delayed execution
            WaitableTimerDelay = 27,

            // -------------------------------------------------------------------------
            // API Timing Checks (40-59)
            // -------------------------------------------------------------------------

            /// @brief GetTickCount/GetTickCount64 delta analysis
            GetTickCountDelta = 40,

            /// @brief QueryPerformanceCounter anomaly detection
            QPCAnomaly = 41,

            /// @brief GetSystemTimeAsFileTime comparison
            SystemTimeCheck = 42,

            /// @brief timeGetTime() inconsistency check
            TimeGetTimeCheck = 43,

            /// @brief Multiple timing API cross-validation
            TimingAPICrossCheck = 44,

            /// @brief GetSystemTimePreciseAsFileTime usage
            PreciseTimeCheck = 45,

            // -------------------------------------------------------------------------
            // NTP/Network Time (60-79)
            // -------------------------------------------------------------------------

            /// @brief NTP server query for time validation
            NTPQuery = 60,

            /// @brief External time source validation
            ExternalTimeValidation = 61,

            /// @brief HTTP Date header time check
            HTTPDateCheck = 62,

            /// @brief Time zone anomaly detection
            TimeZoneAnomaly = 63,

            // -------------------------------------------------------------------------
            // Hardware Timer Techniques (80-99)
            // -------------------------------------------------------------------------

            /// @brief HPET (High Precision Event Timer) access
            HPETAccess = 80,

            /// @brief ACPI PM Timer query
            ACPIPMTimer = 81,

            /// @brief Direct hardware timer register access
            HardwareTimerDirect = 82,

            /// @brief Interrupt timing analysis
            InterruptTiming = 83,

            // -------------------------------------------------------------------------
            // Side-Channel Timing (100-119)
            // -------------------------------------------------------------------------

            /// @brief Instruction timing analysis (timing attack)
            InstructionTiming = 100,

            /// @brief Cache timing side-channel
            CacheTiming = 101,

            /// @brief Branch prediction timing
            BranchPredictionTiming = 102,

            /// @brief Memory access timing patterns
            MemoryAccessTiming = 103,

            // -------------------------------------------------------------------------
            // Combined/Advanced (120-139)
            // -------------------------------------------------------------------------

            /// @brief Multiple timing techniques combined
            MultiTechniqueEvasion = 120,

            /// @brief Adaptive timing based on environment
            AdaptiveTiming = 121,

            /// @brief Time-locked payload (executes at specific time)
            TimeLockedPayload = 122,

            /// @brief Timing-based anti-debugging
            TimingAntiDebug = 123,

            /// @brief Reserved for future use
            Reserved = 254,

            /// @brief Unknown/unclassified timing evasion
            Unknown = 255
        };

        /**
         * @brief Severity level of detected timing evasion.
         */
        enum class TimingEvasionSeverity : uint8_t {
            /// @brief Informational only (benign behavior)
            Info = 0,

            /// @brief Low severity (single indicator, possibly benign)
            Low = 25,

            /// @brief Medium severity (multiple indicators or suspicious pattern)
            Medium = 50,

            /// @brief High severity (strong evasion indicators)
            High = 75,

            /// @brief Critical severity (confirmed evasion behavior)
            Critical = 100
        };

        /**
         * @brief Detection method used to identify evasion.
         */
        enum class TimingDetectionMethod : uint8_t {
            /// @brief Unknown detection method
            Unknown = 0,

            /// @brief Static analysis of code/imports
            StaticAnalysis = 1,

            /// @brief Dynamic runtime monitoring
            DynamicMonitoring = 2,

            /// @brief API hooking/interception
            APIHooking = 3,

            /// @brief Hardware performance counters
            HardwareCounters = 4,

            /// @brief Kernel driver instrumentation
            KernelInstrumentation = 5,

            /// @brief Hypervisor-based monitoring
            HypervisorMonitoring = 6,

            /// @brief ETW (Event Tracing for Windows)
            ETWTracing = 7,

            /// @brief Behavioral heuristics
            BehavioralHeuristics = 8,

            /// @brief Machine learning classification
            MLClassification = 9
        };

        /**
         * @brief State of timing evasion monitoring for a process.
         */
        enum class MonitoringState : uint8_t {
            /// @brief Not monitoring
            Inactive = 0,

            /// @brief Monitoring active
            Active = 1,

            /// @brief Monitoring paused
            Paused = 2,

            /// @brief Monitoring completed (process terminated)
            Completed = 3,

            /// @brief Monitoring failed (access denied, etc.)
            Failed = 4
        };

        /**
         * @brief Get string representation of timing evasion type.
         */
        [[nodiscard]] constexpr const char* TimingEvasionTypeToString(TimingEvasionType type) noexcept {
            switch (type) {
            case TimingEvasionType::None:                   return "None";
            case TimingEvasionType::RDTSCHighFrequency:     return "RDTSC High Frequency";
            case TimingEvasionType::RDTSCDeltaCheck:        return "RDTSC Delta Check";
            case TimingEvasionType::RDTSCPUsage:            return "RDTSCP Usage";
            case TimingEvasionType::RDTSCCPUIDCombo:        return "RDTSC+CPUID Combo";
            case TimingEvasionType::TSCFrequencyMeasurement: return "TSC Frequency Measurement";
            case TimingEvasionType::SleepBombing:           return "Sleep Bombing";
            case TimingEvasionType::SleepAccelerationDetect: return "Sleep Acceleration Detection";
            case TimingEvasionType::SleepFragmentation:     return "Sleep Fragmentation";
            case TimingEvasionType::NtDelayExecutionAbuse:  return "NtDelayExecution Abuse";
            case TimingEvasionType::SleepExAlertable:       return "SleepEx Alertable";
            case TimingEvasionType::WaitForSingleObjectDelay: return "WaitForSingleObject Delay";
            case TimingEvasionType::MsgWaitDelay:           return "MsgWait Delay";
            case TimingEvasionType::WaitableTimerDelay:     return "Waitable Timer Delay";
            case TimingEvasionType::GetTickCountDelta:      return "GetTickCount Delta";
            case TimingEvasionType::QPCAnomaly:             return "QPC Anomaly";
            case TimingEvasionType::SystemTimeCheck:        return "System Time Check";
            case TimingEvasionType::TimeGetTimeCheck:       return "timeGetTime Check";
            case TimingEvasionType::TimingAPICrossCheck:    return "Timing API Cross-Check";
            case TimingEvasionType::PreciseTimeCheck:       return "Precise Time Check";
            case TimingEvasionType::NTPQuery:               return "NTP Query";
            case TimingEvasionType::ExternalTimeValidation: return "External Time Validation";
            case TimingEvasionType::HTTPDateCheck:          return "HTTP Date Check";
            case TimingEvasionType::TimeZoneAnomaly:        return "Time Zone Anomaly";
            case TimingEvasionType::HPETAccess:             return "HPET Access";
            case TimingEvasionType::ACPIPMTimer:            return "ACPI PM Timer";
            case TimingEvasionType::HardwareTimerDirect:    return "Hardware Timer Direct";
            case TimingEvasionType::InterruptTiming:        return "Interrupt Timing";
            case TimingEvasionType::InstructionTiming:      return "Instruction Timing";
            case TimingEvasionType::CacheTiming:            return "Cache Timing";
            case TimingEvasionType::BranchPredictionTiming: return "Branch Prediction Timing";
            case TimingEvasionType::MemoryAccessTiming:     return "Memory Access Timing";
            case TimingEvasionType::MultiTechniqueEvasion:  return "Multi-Technique Evasion";
            case TimingEvasionType::AdaptiveTiming:         return "Adaptive Timing";
            case TimingEvasionType::TimeLockedPayload:      return "Time-Locked Payload";
            case TimingEvasionType::TimingAntiDebug:        return "Timing Anti-Debug";
            case TimingEvasionType::Reserved:               return "Reserved";
            case TimingEvasionType::Unknown:                return "Unknown";
            default:                                        return "Unknown";
            }
        }

        /**
         * @brief Get MITRE ATT&CK technique ID for timing evasion type.
         */
        [[nodiscard]] constexpr const char* TimingEvasionTypeToMitre(TimingEvasionType type) noexcept {
            switch (type) {
                // All timing evasion maps to T1497.003 (Time Based Evasion)
            case TimingEvasionType::None:
                return "";
            case TimingEvasionType::TimingAntiDebug:
                return "T1622";  // Debugger Evasion
            default:
                return "T1497.003";  // Virtualization/Sandbox Evasion: Time Based Evasion
            }
        }

        /**
         * @brief Get string representation of timing evasion severity.
         */
        [[nodiscard]] constexpr const char* TimingEvasionSeverityToString(TimingEvasionSeverity severity) noexcept {
            switch (severity) {
            case TimingEvasionSeverity::Info:     return "Info";
            case TimingEvasionSeverity::Low:      return "Low";
            case TimingEvasionSeverity::Medium:   return "Medium";
            case TimingEvasionSeverity::High:     return "High";
            case TimingEvasionSeverity::Critical: return "Critical";
            default:                              return "Unknown";
            }
        }

        // ============================================================================
        // DATA STRUCTURES
        // ============================================================================

        /**
         * @brief Record of a single timing event for analysis.
         */
        struct alignas(64) TimingEventRecord {
            /// @brief Timestamp when event occurred
            std::chrono::steady_clock::time_point timestamp{};

            /// @brief Process ID
            uint32_t processId = 0;

            /// @brief Thread ID (if applicable)
            uint32_t threadId = 0;

            /// @brief Type of timing event
            TimingEvasionType eventType = TimingEvasionType::Unknown;

            /// @brief Detection method used
            TimingDetectionMethod detectionMethod = TimingDetectionMethod::Unknown;

            /// @brief Raw timing value (interpretation depends on eventType)
            uint64_t timingValue = 0;

            /// @brief Expected timing value (for comparison)
            uint64_t expectedValue = 0;

            /// @brief Delta/deviation from expected
            int64_t deviation = 0;

            /// @brief Call count (for frequency analysis)
            uint32_t callCount = 0;

            /// @brief Padding for cache line alignment
            uint8_t reserved_[8] = {};
        };

        static_assert(sizeof(TimingEventRecord) == 64, "TimingEventRecord must be cache-line aligned");

        /**
         * @brief Individual detection finding within a result.
         */
        struct TimingEvasionFinding {
            /// @brief Type of evasion detected
            TimingEvasionType type = TimingEvasionType::None;

            /// @brief Severity of this finding
            TimingEvasionSeverity severity = TimingEvasionSeverity::Info;

            /// @brief Confidence score (0.0 - 100.0)
            float confidence = 0.0f;

            /// @brief Detection method used
            TimingDetectionMethod detectionMethod = TimingDetectionMethod::Unknown;

            /// @brief MITRE ATT&CK technique ID
            std::string mitreId;

            /// @brief Human-readable description
            std::wstring description;

            /// @brief Technical details for analysts
            std::wstring technicalDetails;

            /// @brief Timestamp of detection
            std::chrono::system_clock::time_point detectionTime{};

            /// @brief Associated timing events
            std::vector<TimingEventRecord> relatedEvents;

            /// @brief Evidence data (raw bytes if applicable)
            std::vector<uint8_t> evidence;

            /// @brief Thread IDs involved
            std::vector<uint32_t> involvedThreads;

            /// @brief API calls observed (for tracking)
            std::vector<std::wstring> observedAPICalls;
        };

        /**
         * @brief Comprehensive result of timing evasion analysis.
         */
        struct TimingEvasionResult {
            // -------------------------------------------------------------------------
            // Core Detection Status
            // -------------------------------------------------------------------------

            /// @brief Whether any evasion was detected
            bool isEvasive = false;

            /// @brief Overall confidence score (0.0 - 100.0)
            float confidence = 0.0f;

            /// @brief Overall severity (highest among findings)
            TimingEvasionSeverity severity = TimingEvasionSeverity::Info;

            /// @brief Composite threat score (weighted combination)
            float threatScore = 0.0f;

            // -------------------------------------------------------------------------
            // Process Information
            // -------------------------------------------------------------------------

            /// @brief Target process ID
            uint32_t processId = 0;

            /// @brief Process name
            std::wstring processName;

            /// @brief Process executable path
            std::wstring processPath;

            /// @brief Process command line
            std::wstring commandLine;

            /// @brief Parent process ID
            uint32_t parentProcessId = 0;

            /// @brief Parent process name
            std::wstring parentProcessName;

            // -------------------------------------------------------------------------
            // Detection Details
            // -------------------------------------------------------------------------

            /// @brief Individual findings
            std::vector<TimingEvasionFinding> findings;

            /// @brief Summary messages for quick review
            std::vector<std::wstring> details;

            /// @brief Primary evasion type detected (most severe)
            TimingEvasionType primaryEvasionType = TimingEvasionType::None;

            /// @brief All detected evasion types (bitmap for fast checking)
            std::bitset<256> detectedTypes{};

            // -------------------------------------------------------------------------
            // MITRE ATT&CK Mapping
            // -------------------------------------------------------------------------

            /// @brief MITRE ATT&CK technique IDs
            std::vector<std::string> mitreIds;

            /// @brief MITRE ATT&CK tactic (Defense Evasion)
            std::string mitreTactic = "TA0005";

            // -------------------------------------------------------------------------
            // Timing Statistics
            // -------------------------------------------------------------------------

            /// @brief Total RDTSC calls observed
            uint64_t rdtscCallCount = 0;

            /// @brief Average RDTSC delta (nanoseconds)
            uint64_t avgRdtscDeltaNs = 0;

            /// @brief Maximum RDTSC delta observed
            uint64_t maxRdtscDeltaNs = 0;

            /// @brief Total sleep duration requested (milliseconds)
            uint64_t totalSleepDurationMs = 0;

            /// @brief Actual sleep duration (for acceleration detection)
            uint64_t actualSleepDurationMs = 0;

            /// @brief Sleep call count
            uint32_t sleepCallCount = 0;

            /// @brief GetTickCount call count
            uint32_t getTickCountCalls = 0;

            /// @brief QueryPerformanceCounter call count
            uint32_t qpcCallCount = 0;

            /// @brief NTP query count
            uint32_t ntpQueryCount = 0;

            // -------------------------------------------------------------------------
            // Analysis Metadata
            // -------------------------------------------------------------------------

            /// @brief Analysis start time
            std::chrono::system_clock::time_point analysisStartTime{};

            /// @brief Analysis end time
            std::chrono::system_clock::time_point analysisEndTime{};

            /// @brief Analysis duration (milliseconds)
            uint64_t analysisDurationMs = 0;

            /// @brief Number of timing events analyzed
            uint64_t eventsAnalyzed = 0;

            /// @brief Analysis error (if any)
            std::wstring errorMessage;

            /// @brief Whether analysis completed successfully
            bool analysisComplete = false;

            // -------------------------------------------------------------------------
            // Utility Methods
            // -------------------------------------------------------------------------

            /**
             * @brief Check if a specific evasion type was detected.
             */
            [[nodiscard]] bool HasEvasionType(TimingEvasionType type) const noexcept {
                return detectedTypes.test(static_cast<size_t>(type));
            }

            /**
             * @brief Get the number of unique evasion types detected.
             */
            [[nodiscard]] size_t GetEvasionTypeCount() const noexcept {
                return detectedTypes.count();
            }

            /**
             * @brief Check if result indicates high-risk behavior.
             */
            [[nodiscard]] bool IsHighRisk() const noexcept {
                return severity >= TimingEvasionSeverity::High || threatScore >= 70.0f;
            }

            /**
             * @brief Get analysis duration.
             */
            [[nodiscard]] std::chrono::milliseconds GetAnalysisDuration() const noexcept {
                return std::chrono::duration_cast<std::chrono::milliseconds>(
                    analysisEndTime - analysisStartTime
                );
            }

            /**
             * @brief Clear all result data.
             */
            void Clear() noexcept {
                isEvasive = false;
                confidence = 0.0f;
                severity = TimingEvasionSeverity::Info;
                threatScore = 0.0f;
                processId = 0;
                processName.clear();
                processPath.clear();
                commandLine.clear();
                parentProcessId = 0;
                parentProcessName.clear();
                findings.clear();
                details.clear();
                primaryEvasionType = TimingEvasionType::None;
                detectedTypes.reset();
                mitreIds.clear();
                rdtscCallCount = 0;
                avgRdtscDeltaNs = 0;
                maxRdtscDeltaNs = 0;
                totalSleepDurationMs = 0;
                actualSleepDurationMs = 0;
                sleepCallCount = 0;
                getTickCountCalls = 0;
                qpcCallCount = 0;
                ntpQueryCount = 0;
                analysisStartTime = {};
                analysisEndTime = {};
                analysisDurationMs = 0;
                eventsAnalyzed = 0;
                errorMessage.clear();
                analysisComplete = false;
            }
        };

        /**
         * @brief Configuration for timing evasion detection.
         */
        struct TimingDetectorConfig {
            // -------------------------------------------------------------------------
            // General Settings
            // -------------------------------------------------------------------------

            /// @brief Enable detection (master switch)
            bool enabled = true;

            /// @brief Enable continuous monitoring mode
            bool continuousMonitoring = false;

            /// @brief Sample interval for continuous monitoring
            std::chrono::milliseconds sampleInterval = TimingConstants::DEFAULT_SAMPLE_INTERVAL;

            /// @brief Maximum processes to monitor simultaneously
            size_t maxMonitoredProcesses = TimingConstants::MAX_MONITORED_PROCESSES;

            /// @brief Maximum events to retain per process
            size_t maxEventsPerProcess = TimingConstants::MAX_EVENTS_PER_PROCESS;

            // -------------------------------------------------------------------------
            // Detection Sensitivity
            // -------------------------------------------------------------------------

            /// @brief RDTSC high-frequency threshold (calls/second)
            uint64_t rdtscFrequencyThreshold = TimingConstants::RDTSC_HIGH_FREQUENCY_THRESHOLD;

            /// @brief RDTSC delta threshold for VM detection (nanoseconds)
            uint64_t rdtscDeltaThresholdNs = TimingConstants::RDTSC_DELTA_VM_THRESHOLD_NS;

            /// @brief Sleep duration threshold for evasion (milliseconds)
            uint64_t sleepEvasionThresholdMs = TimingConstants::SLEEP_EVASION_THRESHOLD_MS;

            /// @brief Sleep acceleration detection threshold (ratio)
            double sleepAccelerationThreshold = TimingConstants::SLEEP_ACCELERATION_RATIO_THRESHOLD;

            /// @brief Minimum sleep fragments for fragmentation detection
            size_t minSleepFragments = TimingConstants::MIN_SLEEP_FRAGMENTS_FOR_DETECTION;

            /// @brief Time drift threshold (seconds)
            int64_t timeDriftThresholdSeconds = TimingConstants::TIME_DRIFT_THRESHOLD_SECONDS;

            /// @brief GetTickCount anomaly threshold (percentage)
            double tickCountAnomalyPercent = TimingConstants::TICKCOUNT_DELTA_ANOMALY_PERCENT;

            /// @brief QPC frequency anomaly threshold (percentage)
            double qpcAnomalyPercent = TimingConstants::QPC_FREQUENCY_ANOMALY_PERCENT;

            // -------------------------------------------------------------------------
            // Detection Features
            // -------------------------------------------------------------------------

            /// @brief Enable RDTSC monitoring
            bool detectRDTSC = true;

            /// @brief Enable sleep-based evasion detection
            bool detectSleepEvasion = true;

            /// @brief Enable API timing checks
            bool detectAPITiming = true;

            /// @brief Enable NTP/network time detection
            bool detectNTPEvasion = true;

            /// @brief Enable hardware timer detection
            bool detectHardwareTimers = true;

            /// @brief Enable side-channel timing detection
            bool detectSideChannels = false;  // Expensive, disabled by default

            /// @brief Enable multi-technique correlation
            bool enableCorrelation = true;

            // -------------------------------------------------------------------------
            // Reporting
            // -------------------------------------------------------------------------

            /// @brief Minimum confidence to report finding
            float minReportableConfidence = TimingConstants::MIN_REPORTABLE_CONFIDENCE;

            /// @brief Include timing event details in results
            bool includeEventDetails = true;

            /// @brief Include evidence data in results
            bool includeEvidence = false;  // Can be large

            /// @brief Enable MITRE ATT&CK mapping
            bool enableMitreMapping = true;

            // -------------------------------------------------------------------------
            // Caching
            // -------------------------------------------------------------------------

            /// @brief Enable result caching
            bool enableResultCache = true;

            /// @brief Result cache TTL
            std::chrono::minutes resultCacheTTL = TimingConstants::RESULT_CACHE_TTL;

            // -------------------------------------------------------------------------
            // Factory Methods
            // -------------------------------------------------------------------------

            /**
             * @brief Create default configuration.
             */
            [[nodiscard]] static TimingDetectorConfig CreateDefault() noexcept {
                return TimingDetectorConfig{};
            }

            /**
             * @brief Create high-sensitivity configuration for sandbox analysis.
             */
            [[nodiscard]] static TimingDetectorConfig CreateHighSensitivity() noexcept {
                TimingDetectorConfig config;
                config.rdtscFrequencyThreshold = 1000;
                config.sleepEvasionThresholdMs = 10000;
                config.sleepAccelerationThreshold = 0.3;
                config.minReportableConfidence = 5.0f;
                config.detectSideChannels = true;
                config.includeEvidence = true;
                return config;
            }

            /**
             * @brief Create performance-optimized configuration.
             */
            [[nodiscard]] static TimingDetectorConfig CreatePerformanceOptimized() noexcept {
                TimingDetectorConfig config;
                config.sampleInterval = std::chrono::milliseconds{ 500 };
                config.maxEventsPerProcess = 10000;
                config.detectSideChannels = false;
                config.includeEventDetails = false;
                config.includeEvidence = false;
                return config;
            }
        };

        /**
         * @brief Statistics for timing evasion detection.
         */
        struct TimingDetectorStats {
            /// @brief Total processes analyzed
            std::atomic<uint64_t> totalProcessesAnalyzed{ 0 };

            /// @brief Total timing events processed
            std::atomic<uint64_t> totalEventsProcessed{ 0 };

            /// @brief Total evasions detected
            std::atomic<uint64_t> totalEvasionsDetected{ 0 };

            /// @brief Detection counts by type
            std::array<std::atomic<uint64_t>, 256> detectionsByType{};

            /// @brief Currently monitored processes
            std::atomic<size_t> currentlyMonitoring{ 0 };

            /// @brief Cache hits
            std::atomic<uint64_t> cacheHits{ 0 };

            /// @brief Cache misses
            std::atomic<uint64_t> cacheMisses{ 0 };

            /// @brief Analysis errors
            std::atomic<uint64_t> analysisErrors{ 0 };

            /// @brief Average analysis duration (microseconds)
            std::atomic<uint64_t> avgAnalysisDurationUs{ 0 };

            /// @brief Last analysis timestamp
            std::atomic<uint64_t> lastAnalysisTimestamp{ 0 };

            /**
             * @brief Get cache hit ratio.
             */
            [[nodiscard]] double GetCacheHitRatio() const noexcept {
                const uint64_t total = cacheHits.load(std::memory_order_relaxed) +
                    cacheMisses.load(std::memory_order_relaxed);
                return total > 0 ? static_cast<double>(cacheHits.load(std::memory_order_relaxed)) / total : 0.0;
            }

            /**
             * @brief Reset all statistics.
             */
            void Reset() noexcept {
                totalProcessesAnalyzed.store(0, std::memory_order_relaxed);
                totalEventsProcessed.store(0, std::memory_order_relaxed);
                totalEvasionsDetected.store(0, std::memory_order_relaxed);
                for (auto& count : detectionsByType) {
                    count.store(0, std::memory_order_relaxed);
                }
                currentlyMonitoring.store(0, std::memory_order_relaxed);
                cacheHits.store(0, std::memory_order_relaxed);
                cacheMisses.store(0, std::memory_order_relaxed);
                analysisErrors.store(0, std::memory_order_relaxed);
                avgAnalysisDurationUs.store(0, std::memory_order_relaxed);
                lastAnalysisTimestamp.store(0, std::memory_order_relaxed);
            }
        };

        /**
         * @brief Callback for real-time evasion detection notifications.
         */
        using TimingEvasionCallback = std::function<void(const TimingEvasionResult&)>;

        /**
         * @brief Callback for individual timing events (for advanced monitoring).
         */
        using TimingEventCallback = std::function<void(const TimingEventRecord&)>;

        // ============================================================================
        // SLEEP ANALYSIS STRUCTURES
        // ============================================================================

        /**
         * @brief Detailed analysis of sleep behavior.
         */
        struct SleepAnalysis {
            /// @brief Process ID analyzed
            uint32_t processId = 0;

            /// @brief Thread ID analyzed
            uint32_t threadId = 0;

            /// @brief Number of sleep calls observed
            uint32_t sleepCallCount = 0;

            /// @brief Total requested sleep duration (milliseconds)
            uint64_t totalRequestedDurationMs = 0;

            /// @brief Total actual sleep duration (milliseconds)
            uint64_t totalActualDurationMs = 0;

            /// @brief Average requested sleep duration
            uint64_t avgRequestedDurationMs = 0;

            /// @brief Average actual sleep duration
            uint64_t avgActualDurationMs = 0;

            /// @brief Maximum single sleep duration requested
            uint64_t maxRequestedDurationMs = 0;

            /// @brief Sleep acceleration ratio (actual/requested)
            double accelerationRatio = 1.0;

            /// @brief Number of fragmented sleeps detected
            uint32_t fragmentedSleepCount = 0;

            /// @brief Average fragment duration if fragmented
            uint64_t avgFragmentDurationMs = 0;

            /// @brief Whether sleep bombing was detected
            bool sleepBombingDetected = false;

            /// @brief Whether sleep acceleration was detected
            bool accelerationDetected = false;

            /// @brief Whether sleep fragmentation was detected
            bool fragmentationDetected = false;

            /// @brief Confidence score for sleep evasion (0.0 - 100.0)
            float confidence = 0.0f;

            /// @brief Sleep APIs used
            std::vector<std::wstring> sleepAPIsUsed;

            /// @brief Individual sleep durations for pattern analysis
            std::vector<uint64_t> sleepDurations;

            /**
             * @brief Check if any sleep evasion was detected.
             */
            [[nodiscard]] bool HasSleepEvasion() const noexcept {
                return sleepBombingDetected || accelerationDetected || fragmentationDetected;
            }
        };

        /**
         * @brief RDTSC analysis results.
         */
        struct RDTSCAnalysis {
            /// @brief Process ID analyzed
            uint32_t processId = 0;

            /// @brief Number of RDTSC instructions detected
            uint64_t rdtscCount = 0;

            /// @brief Number of RDTSCP instructions detected
            uint64_t rdtscpCount = 0;

            /// @brief RDTSC+CPUID combinations detected
            uint64_t rdtscCpuidComboCount = 0;

            /// @brief Average RDTSC delta (nanoseconds)
            uint64_t avgDeltaNs = 0;

            /// @brief Minimum RDTSC delta
            uint64_t minDeltaNs = 0;

            /// @brief Maximum RDTSC delta
            uint64_t maxDeltaNs = 0;

            /// @brief Standard deviation of deltas
            double deltaStdDev = 0.0;

            /// @brief RDTSC calls per second
            double callsPerSecond = 0.0;

            /// @brief Whether high-frequency RDTSC was detected
            bool highFrequencyDetected = false;

            /// @brief Whether delta checking was detected
            bool deltaCheckDetected = false;

            /// @brief Whether TSC frequency measurement was detected
            bool frequencyMeasurementDetected = false;

            /// @brief Confidence score (0.0 - 100.0)
            float confidence = 0.0f;

            /// @brief Analysis observation duration (milliseconds)
            uint64_t observationDurationMs = 0;

            /**
             * @brief Check if any RDTSC evasion was detected.
             */
            [[nodiscard]] bool HasRDTSCEvasion() const noexcept {
                return highFrequencyDetected || deltaCheckDetected || frequencyMeasurementDetected;
            }
        };

        /**
         * @brief API timing analysis results.
         */
        struct APITimingAnalysis {
            /// @brief Process ID analyzed
            uint32_t processId = 0;

            /// @brief GetTickCount/GetTickCount64 call count
            uint32_t getTickCountCalls = 0;

            /// @brief QueryPerformanceCounter call count
            uint32_t qpcCalls = 0;

            /// @brief GetSystemTimeAsFileTime call count
            uint32_t systemTimeCalls = 0;

            /// @brief timeGetTime call count
            uint32_t timeGetTimeCalls = 0;

            /// @brief GetSystemTimePreciseAsFileTime call count
            uint32_t preciseTimeCalls = 0;

            /// @brief Number of timing API cross-checks detected
            uint32_t crossCheckCount = 0;

            /// @brief Maximum GetTickCount delta observed (milliseconds)
            uint64_t maxTickCountDeltaMs = 0;

            /// @brief QPC frequency measured (Hz)
            uint64_t qpcFrequencyHz = 0;

            /// @brief Expected QPC frequency (Hz)
            uint64_t expectedQpcFrequencyHz = 0;

            /// @brief QPC frequency deviation (percentage)
            double qpcFrequencyDeviation = 0.0;

            /// @brief Whether GetTickCount anomaly was detected
            bool tickCountAnomalyDetected = false;

            /// @brief Whether QPC anomaly was detected
            bool qpcAnomalyDetected = false;

            /// @brief Whether cross-checking was detected
            bool crossCheckDetected = false;

            /// @brief Confidence score (0.0 - 100.0)
            float confidence = 0.0f;

            /**
             * @brief Check if any API timing evasion was detected.
             */
            [[nodiscard]] bool HasAPITimingEvasion() const noexcept {
                return tickCountAnomalyDetected || qpcAnomalyDetected || crossCheckDetected;
            }
        };

        /**
         * @brief NTP/network time analysis results.
         */
        struct NTPAnalysis {
            /// @brief Process ID analyzed
            uint32_t processId = 0;

            /// @brief NTP server queries detected
            uint32_t ntpQueryCount = 0;

            /// @brief HTTP time header checks detected
            uint32_t httpTimeCheckCount = 0;

            /// @brief External time API calls detected
            uint32_t externalTimeAPICalls = 0;

            /// @brief NTP servers contacted
            std::vector<std::wstring> ntpServers;

            /// @brief HTTP hosts with time headers checked
            std::vector<std::wstring> httpTimeHosts;

            /// @brief Detected time drift (seconds)
            int64_t detectedDriftSeconds = 0;

            /// @brief Whether NTP evasion was detected
            bool ntpEvasionDetected = false;

            /// @brief Whether external time validation was detected
            bool externalValidationDetected = false;

            /// @brief Confidence score (0.0 - 100.0)
            float confidence = 0.0f;

            /**
             * @brief Check if any NTP evasion was detected.
             */
            [[nodiscard]] bool HasNTPEvasion() const noexcept {
                return ntpEvasionDetected || externalValidationDetected;
            }
        };

        // ============================================================================
        // MAIN DETECTOR CLASS
        // ============================================================================

        /**
         * @brief Enterprise-grade timing-based evasion detector.
         *
         * Provides comprehensive detection of timing attacks used by malware to
         * evade sandbox analysis, VM detection, and automated security tools.
         *
         * Thread Safety: All public methods are thread-safe.
         *
         * Usage Example:
         * @code
         * auto& detector = TimeBasedEvasionDetector::Instance();
         *
         * // Initialize with custom configuration
         * TimingDetectorConfig config = TimingDetectorConfig::CreateHighSensitivity();
         * detector.Initialize(threadPool, config);
         *
         * // Analyze a specific process
         * auto result = detector.AnalyzeProcess(targetPid);
         * if (result.isEvasive) {
         *     for (const auto& finding : result.findings) {
         *         LOG_WARN(L"Detected: {} (confidence: {}%)",
         *                  TimingEvasionTypeToString(finding.type),
         *                  finding.confidence);
         *     }
         * }
         *
         * // Start continuous monitoring with callback
         * detector.RegisterCallback([](const TimingEvasionResult& result) {
         *     if (result.IsHighRisk()) {
         *         // Take action
         *     }
         * });
         * detector.StartMonitoring(targetPid);
         *
         * // Cleanup
         * detector.Shutdown();
         * @endcode
         */
        class TimeBasedEvasionDetector {
        public:
            // =========================================================================
            // Singleton Access
            // =========================================================================

            /**
             * @brief Get the singleton instance.
             * @return Reference to the global TimeBasedEvasionDetector instance.
             * @note Thread-safe (Meyers' singleton).
             */
            [[nodiscard]] static TimeBasedEvasionDetector& Instance();

            // Non-copyable, non-movable
            TimeBasedEvasionDetector(const TimeBasedEvasionDetector&) = delete;
            TimeBasedEvasionDetector& operator=(const TimeBasedEvasionDetector&) = delete;
            TimeBasedEvasionDetector(TimeBasedEvasionDetector&&) = delete;
            TimeBasedEvasionDetector& operator=(TimeBasedEvasionDetector&&) = delete;

            // =========================================================================
            // Lifecycle Management
            // =========================================================================

            /**
             * @brief Initialize the detector with default configuration.
             * @param threadPool Shared pointer to thread pool for async operations.
             * @return true on success, false on failure.
             * @note Must be called before any detection operations.
             * @note Safe to call multiple times (subsequent calls are no-ops).
             */
            [[nodiscard]] bool Initialize(std::shared_ptr<Utils::ThreadPool> threadPool);

            /**
             * @brief Initialize the detector with custom configuration.
             * @param threadPool Shared pointer to thread pool for async operations.
             * @param config Detection configuration.
             * @return true on success, false on failure.
             */
            [[nodiscard]] bool Initialize(
                std::shared_ptr<Utils::ThreadPool> threadPool,
                const TimingDetectorConfig& config
            );

            /**
             * @brief Shutdown the detector and release resources.
             * @note Stops all monitoring, clears caches, and waits for pending operations.
             * @note Safe to call multiple times.
             */
            void Shutdown();

            /**
             * @brief Check if detector is initialized and ready.
             */
            [[nodiscard]] bool IsInitialized() const noexcept;

            /**
             * @brief Update configuration at runtime.
             * @param config New configuration.
             * @note Some settings may require restart of monitoring to take effect.
             */
            void UpdateConfig(const TimingDetectorConfig& config);

            /**
             * @brief Get current configuration.
             */
            [[nodiscard]] TimingDetectorConfig GetConfig() const;

            // =========================================================================
            // Single Process Analysis
            // =========================================================================

            /**
             * @brief Analyze a process for timing evasion techniques.
             * @param processId Target process ID.
             * @return Analysis result with all detected evasion techniques.
             * @note This is a synchronous operation that may take several seconds.
             * @note Requires PROCESS_QUERY_INFORMATION and PROCESS_VM_READ access.
             */
            [[nodiscard]] TimingEvasionResult AnalyzeProcess(uint32_t processId);

            /**
             * @brief Analyze a process asynchronously.
             * @param processId Target process ID.
             * @param callback Callback invoked when analysis completes.
             * @return true if analysis was started, false on error.
             */
            [[nodiscard]] bool AnalyzeProcessAsync(
                uint32_t processId,
                std::function<void(TimingEvasionResult)> callback
            );

            /**
             * @brief Quick check if a process exhibits obvious timing evasion.
             * @param processId Target process ID.
             * @return true if obvious evasion detected, false otherwise.
             * @note Faster but less comprehensive than AnalyzeProcess().
             */
            [[nodiscard]] bool QuickScanProcess(uint32_t processId);

            // =========================================================================
            // Specific Analysis Methods
            // =========================================================================

            /**
             * @brief Analyze RDTSC usage patterns.
             * @param processId Target process ID.
             * @return RDTSC-specific analysis results.
             */
            [[nodiscard]] RDTSCAnalysis AnalyzeRDTSC(uint32_t processId);

            /**
             * @brief Analyze sleep behavior for evasion.
             * @param processId Target process ID.
             * @return Sleep-specific analysis results.
             */
            [[nodiscard]] SleepAnalysis AnalyzeSleep(uint32_t processId);

            /**
             * @brief Analyze API timing behavior.
             * @param processId Target process ID.
             * @return API timing analysis results.
             */
            [[nodiscard]] APITimingAnalysis AnalyzeAPITiming(uint32_t processId);

            /**
             * @brief Analyze NTP/network time behavior.
             * @param processId Target process ID.
             * @return NTP analysis results.
             */
            [[nodiscard]] NTPAnalysis AnalyzeNTP(uint32_t processId);

            /**
             * @brief Detect sleep acceleration (sandbox fast-forward).
             * @param processId Target process ID.
             * @return true if acceleration detected, false otherwise.
             * @note Uses Utils::ProcessUtils::GetThreadInfo for thread state analysis.
             */
            [[nodiscard]] bool DetectSleepAcceleration(uint32_t processId);

            /**
             * @brief Detect timing-based anti-debugging.
             * @param processId Target process ID.
             * @return true if timing anti-debug detected, false otherwise.
             */
            [[nodiscard]] bool DetectTimingAntiDebug(uint32_t processId);

            // =========================================================================
            // Continuous Monitoring
            // =========================================================================

            /**
             * @brief Start continuous monitoring of a process.
             * @param processId Target process ID.
             * @return true if monitoring started, false on error.
             * @note Requires prior callback registration for notifications.
             */
            [[nodiscard]] bool StartMonitoring(uint32_t processId);

            /**
             * @brief Stop monitoring a specific process.
             * @param processId Target process ID.
             */
            void StopMonitoring(uint32_t processId);

            /**
             * @brief Stop monitoring all processes.
             */
            void StopAllMonitoring();

            /**
             * @brief Check if a process is being monitored.
             * @param processId Target process ID.
             */
            [[nodiscard]] bool IsMonitoring(uint32_t processId) const;

            /**
             * @brief Get monitoring state for a process.
             * @param processId Target process ID.
             */
            [[nodiscard]] MonitoringState GetMonitoringState(uint32_t processId) const;

            /**
             * @brief Pause monitoring for a process.
             * @param processId Target process ID.
             */
            void PauseMonitoring(uint32_t processId);

            /**
             * @brief Resume monitoring for a paused process.
             * @param processId Target process ID.
             */
            void ResumeMonitoring(uint32_t processId);

            /**
             * @brief Get list of currently monitored process IDs.
             */
            [[nodiscard]] std::vector<uint32_t> GetMonitoredProcesses() const;

            // =========================================================================
            // Callbacks
            // =========================================================================

            /**
             * @brief Register callback for evasion detection notifications.
             * @param callback Function to call when evasion is detected.
             * @return Registration ID for callback management.
             * @note Multiple callbacks can be registered.
             */
            [[nodiscard]] uint64_t RegisterCallback(TimingEvasionCallback callback);

            /**
             * @brief Unregister a previously registered callback.
             * @param callbackId ID returned by RegisterCallback.
             * @return true if callback was found and removed.
             */
            bool UnregisterCallback(uint64_t callbackId);

            /**
             * @brief Register callback for individual timing events.
             * @param callback Function to call for each timing event.
             * @return Registration ID.
             * @note Use sparingly - can generate high volume of events.
             */
            [[nodiscard]] uint64_t RegisterEventCallback(TimingEventCallback callback);

            /**
             * @brief Unregister an event callback.
             * @param callbackId ID returned by RegisterEventCallback.
             */
            bool UnregisterEventCallback(uint64_t callbackId);

            // =========================================================================
            // Statistics & Diagnostics
            // =========================================================================

            /**
             * @brief Get current detection statistics.
             */
            [[nodiscard]] const TimingDetectorStats& GetStats() const;

            /**
             * @brief Reset all statistics.
             */
            void ResetStats();

            /**
             * @brief Get cached result for a process (if available).
             * @param processId Target process ID.
             * @return Cached result or std::nullopt if not cached.
             */
            [[nodiscard]] std::optional<TimingEvasionResult> GetCachedResult(uint32_t processId) const;

            /**
             * @brief Clear all cached results.
             */
            void ClearCache();

            /**
             * @brief Clear cached result for a specific process.
             * @param processId Target process ID.
             */
            void ClearCacheForProcess(uint32_t processId);

            /**
             * @brief Get timing event history for a process.
             * @param processId Target process ID.
             * @param maxEvents Maximum events to return (0 = all).
             * @return Vector of timing events.
             */
            [[nodiscard]] std::vector<TimingEventRecord> GetEventHistory(
                uint32_t processId,
                size_t maxEvents = 0
            ) const;

        private:
            // =========================================================================
            // Private Constructor (Singleton)
            // =========================================================================

            TimeBasedEvasionDetector();
            ~TimeBasedEvasionDetector();

            // =========================================================================
            // Internal Analysis Methods
            // =========================================================================

            /**
             * @brief Check for RDTSC instruction abuse.
             */
            void CheckRDTSCAbuse(uint32_t processId, TimingEvasionResult& result);

            /**
             * @brief Check for time drift detection attempts.
             */
            void CheckTimeDriftChecks(uint32_t processId, TimingEvasionResult& result);

            /**
             * @brief Check for timer API anomalies.
             */
            void CheckTimerAnomalies(uint32_t processId, TimingEvasionResult& result);

            /**
             * @brief Check for sleep-based evasion.
             */
            void CheckSleepEvasion(uint32_t processId, TimingEvasionResult& result);

            /**
             * @brief Check for NTP-based evasion.
             */
            void CheckNTPEvasion(uint32_t processId, TimingEvasionResult& result);

            /**
             * @brief Check for hardware timer abuse.
             */
            void CheckHardwareTimers(uint32_t processId, TimingEvasionResult& result);

            /**
             * @brief Correlate multiple findings for combined detection.
             */
            void CorrelateFindings(TimingEvasionResult& result);

            /**
             * @brief Calculate overall threat score from findings.
             */
            void CalculateThreatScore(TimingEvasionResult& result);

            /**
             * @brief Add MITRE ATT&CK mappings to result.
             */
            void AddMitreMappings(TimingEvasionResult& result);

            /**
             * @brief Process monitoring tick (for continuous monitoring).
             */
            void MonitoringTick(uint32_t processId);

            /**
             * @brief Invoke registered callbacks.
             */
            void InvokeCallbacks(const TimingEvasionResult& result);

            /**
             * @brief Record a timing event.
             */
            void RecordTimingEvent(const TimingEventRecord& event);

            /**
             * @brief Update cache with analysis result.
             */
            void UpdateCache(uint32_t processId, const TimingEvasionResult& result);

            // =========================================================================
            // Internal Data (PIMPL pattern for ABI stability)
            // =========================================================================

            struct Impl;
            std::unique_ptr<Impl> m_impl;
        };

        // ============================================================================
        // UTILITY FUNCTIONS
        // ============================================================================

        /**
         * @brief Calculate sleep acceleration ratio.
         * @param requestedMs Requested sleep duration in milliseconds.
         * @param actualMs Actual sleep duration in milliseconds.
         * @return Acceleration ratio (< 1.0 indicates acceleration).
         */
        [[nodiscard]] inline double CalculateSleepAccelerationRatio(
            uint64_t requestedMs,
            uint64_t actualMs
        ) noexcept {
            if (requestedMs == 0) return 1.0;
            return static_cast<double>(actualMs) / static_cast<double>(requestedMs);
        }

        /**
         * @brief Calculate confidence from multiple factors.
         * @param factors Vector of individual confidence factors (0.0 - 1.0).
         * @param weights Optional weights for each factor.
         * @return Combined confidence (0.0 - 100.0).
         */
        [[nodiscard]] inline float CalculateCombinedConfidence(
            const std::vector<float>& factors,
            const std::vector<float>& weights = {}
        ) noexcept {
            if (factors.empty()) return 0.0f;

            float sum = 0.0f;
            float weightSum = 0.0f;

            for (size_t i = 0; i < factors.size(); ++i) {
                const float weight = (i < weights.size()) ? weights[i] : 1.0f;
                sum += factors[i] * weight;
                weightSum += weight;
            }

            return (weightSum > 0.0f) ? (sum / weightSum) * 100.0f : 0.0f;
        }

        /**
         * @brief Determine severity from confidence score.
         * @param confidence Confidence score (0.0 - 100.0).
         * @return Corresponding severity level.
         */
        [[nodiscard]] inline TimingEvasionSeverity ConfidenceToSeverity(float confidence) noexcept {
            if (confidence >= 90.0f) return TimingEvasionSeverity::Critical;
            if (confidence >= 70.0f) return TimingEvasionSeverity::High;
            if (confidence >= 40.0f) return TimingEvasionSeverity::Medium;
            if (confidence >= 15.0f) return TimingEvasionSeverity::Low;
            return TimingEvasionSeverity::Info;
        }

    } // namespace AntiEvasion
} // namespace ShadowStrike