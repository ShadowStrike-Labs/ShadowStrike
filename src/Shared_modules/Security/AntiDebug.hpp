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
 * ShadowStrike Security - ANTI-DEBUG PROTECTION ENGINE
 * ============================================================================
 *
 * @file AntiDebug.hpp
 * @brief Enterprise-grade anti-debugging and anti-reverse-engineering protection
 *        for ShadowStrike antivirus self-defense mechanisms.
 *
 * This module implements comprehensive anti-debugging techniques to prevent
 * malware from analyzing, tampering with, or disabling the antivirus engine.
 * It employs multiple detection layers to identify debuggers, sandboxes,
 * virtual machines, and instrumentation frameworks.
 *
 * DETECTION CATEGORIES:
 * =====================
 * 1. PEB/TEB Inspection
 *    - BeingDebugged flag monitoring
 *    - NtGlobalFlag analysis
 *    - Heap flags inspection (ForceFlags, Flags)
 *    - ProcessHeap verification
 *
 * 2. Hardware Debug Register Detection
 *    - DR0-DR7 register monitoring
 *    - Hardware breakpoint detection
 *    - Context manipulation detection
 *    - Debug register clearing
 *
 * 3. Timing-Based Detection
 *    - RDTSC/RDTSCP timing analysis
 *    - QueryPerformanceCounter deltas
 *    - GetTickCount/GetTickCount64 analysis
 *    - Instruction timing measurement
 *    - Single-step detection
 *
 * 4. API-Based Detection
 *    - IsDebuggerPresent
 *    - CheckRemoteDebuggerPresent
 *    - NtQueryInformationProcess (ProcessDebugPort, ProcessDebugFlags)
 *    - NtQuerySystemInformation
 *    - OutputDebugString behavior
 *
 * 5. Exception-Based Detection
 *    - INT 3 (0xCC) breakpoint detection
 *    - INT 2D detection
 *    - Single-step exception handling
 *    - Guard page violations
 *    - Vectored exception handler analysis
 *
 * 6. Memory Artifact Detection
 *    - Software breakpoint scanning (0xCC patterns)
 *    - Code integrity verification
 *    - Import Address Table (IAT) hook detection
 *    - Inline hook detection
 *    - Memory region permission analysis
 *
 * 7. Process/Thread Analysis
 *    - Parent process validation
 *    - Thread enumeration anomalies
 *    - Hidden thread detection
 *    - Debug object handle detection
 *    - Job object analysis
 *
 * 8. System Artifact Detection
 *    - Debugger process detection (ollydbg, x64dbg, windbg, ida)
 *    - Debugger window detection
 *    - Driver presence detection (SoftICE, Syser)
 *    - Registry key analysis
 *    - Known debugger file detection
 *
 * 9. Instrumentation Framework Detection
 *    - DynamoRIO detection
 *    - Pin detection
 *    - Frida detection
 *    - API Monitor detection
 *    - Process Monitor detection
 *
 * 10. Anti-Attach Protection
 *     - Thread hiding (NtSetInformationThread)
 *     - Debug privilege removal
 *     - Handle table manipulation
 *     - Debug object destruction
 *
 * PROTECTION MECHANISMS:
 * ======================
 * - Continuous monitoring with configurable intervals
 * - Multi-layered detection with scoring system
 * - Automated response actions (alert, terminate, corrupt)
 * - Thread protection via HideFromDebugger
 * - Code integrity verification with CRC32/SHA256
 * - Anti-tampering hooks
 *
 * ENTERPRISE FEATURES:
 * ====================
 * - Centralized policy management
 * - Detailed event logging and telemetry
 * - Configurable detection sensitivity
 * - False positive mitigation for legitimate tools
 * - Integration with ShadowStrike threat intelligence
 *
 * @note This module is designed for Windows x86/x64 platforms.
 * @note Some techniques may trigger AV false positives on other systems.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, NIST CSF
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
#include <unordered_set>
#include <set>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <future>
#include <span>
#include <bitset>
#include <queue>
#include <any>
#include <type_traits>
#include <concepts>

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
#  include <winternl.h>
#  include <TlHelp32.h>
#  include <Psapi.h>
#  include <intrin.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/ThreadPool.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Security {
    class AntiDebugImpl;
}

namespace ShadowStrike {
namespace Security {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace AntiDebugConstants {

    // ========================================================================
    // VERSION INFORMATION
    // ========================================================================
    
    /// @brief Module major version
    inline constexpr uint32_t VERSION_MAJOR = 3;
    
    /// @brief Module minor version
    inline constexpr uint32_t VERSION_MINOR = 0;
    
    /// @brief Module patch version
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // DETECTION THRESHOLDS
    // ========================================================================
    
    /// @brief Minimum score to consider debugger present (0-100)
    inline constexpr uint32_t MIN_DETECTION_SCORE = 30;
    
    /// @brief High confidence detection threshold
    inline constexpr uint32_t HIGH_CONFIDENCE_SCORE = 70;
    
    /// @brief Critical detection threshold (immediate action)
    inline constexpr uint32_t CRITICAL_SCORE = 90;
    
    /// @brief Maximum detection checks per cycle
    inline constexpr size_t MAX_CHECKS_PER_CYCLE = 50;
    
    /// @brief Number of timing samples for analysis
    inline constexpr size_t TIMING_SAMPLE_COUNT = 10;

    // ========================================================================
    // TIMING THRESHOLDS
    // ========================================================================
    
    /// @brief RDTSC threshold for single instruction (cycles)
    inline constexpr uint64_t RDTSC_SINGLE_INSTRUCTION_THRESHOLD = 500;
    
    /// @brief RDTSC threshold for instruction block (cycles)
    inline constexpr uint64_t RDTSC_BLOCK_THRESHOLD = 10000;
    
    /// @brief Timing delta tolerance percentage
    inline constexpr double TIMING_TOLERANCE_PERCENT = 50.0;
    
    /// @brief Minimum time between checks (milliseconds)
    inline constexpr uint32_t MIN_CHECK_INTERVAL_MS = 100;
    
    /// @brief Default monitoring interval (milliseconds)
    inline constexpr uint32_t DEFAULT_MONITOR_INTERVAL_MS = 5000;
    
    /// @brief Maximum monitoring interval (milliseconds)
    inline constexpr uint32_t MAX_MONITOR_INTERVAL_MS = 60000;
    
    /// @brief Timing anomaly threshold (nanoseconds)
    inline constexpr uint64_t TIMING_ANOMALY_THRESHOLD_NS = 1000000;

    // ========================================================================
    // MEMORY SCANNING LIMITS
    // ========================================================================
    
    /// @brief Maximum memory regions to scan
    inline constexpr size_t MAX_MEMORY_REGIONS = 1000;
    
    /// @brief Maximum code section size to scan (bytes)
    inline constexpr size_t MAX_CODE_SECTION_SIZE = 10 * 1024 * 1024;
    
    /// @brief Minimum code section size to scan (bytes)
    inline constexpr size_t MIN_CODE_SECTION_SIZE = 256;
    
    /// @brief Breakpoint scan chunk size (bytes)
    inline constexpr size_t BREAKPOINT_SCAN_CHUNK = 4096;
    
    /// @brief Maximum breakpoints before alert
    inline constexpr size_t MAX_BREAKPOINTS_THRESHOLD = 3;

    // ========================================================================
    // PROCESS DETECTION LIMITS
    // ========================================================================
    
    /// @brief Maximum debugger processes to track
    inline constexpr size_t MAX_DEBUGGER_PROCESSES = 100;
    
    /// @brief Maximum debugger windows to detect
    inline constexpr size_t MAX_DEBUGGER_WINDOWS = 50;
    
    /// @brief Maximum parent process chain depth
    inline constexpr size_t MAX_PARENT_CHAIN_DEPTH = 10;
    
    /// @brief Process name maximum length
    inline constexpr size_t MAX_PROCESS_NAME_LENGTH = 260;

    // ========================================================================
    // CODE INTEGRITY
    // ========================================================================
    
    /// @brief Maximum integrity check regions
    inline constexpr size_t MAX_INTEGRITY_REGIONS = 100;
    
    /// @brief Integrity check hash size (SHA256)
    inline constexpr size_t INTEGRITY_HASH_SIZE = 32;
    
    /// @brief CRC32 polynomial for fast integrity checks
    inline constexpr uint32_t CRC32_POLYNOMIAL = 0xEDB88320;

    // ========================================================================
    // HOOK DETECTION
    // ========================================================================
    
    /// @brief Maximum hooks to detect per module
    inline constexpr size_t MAX_HOOKS_PER_MODULE = 500;
    
    /// @brief Jump instruction opcodes to detect
    inline constexpr std::array<uint8_t, 5> JUMP_OPCODES = {
        0xE9,   // JMP rel32
        0xEB,   // JMP rel8
        0xFF,   // JMP r/m (with ModR/M)
        0xEA,   // JMP far
        0xCC    // INT 3 (breakpoint)
    };
    
    /// @brief Minimum hook displacement to consider suspicious
    inline constexpr size_t MIN_HOOK_DISPLACEMENT = 5;

    // ========================================================================
    // EXCEPTION HANDLING
    // ========================================================================
    
    /// @brief Maximum exception handlers to track
    inline constexpr size_t MAX_EXCEPTION_HANDLERS = 100;
    
    /// @brief Exception test timeout (milliseconds)
    inline constexpr uint32_t EXCEPTION_TEST_TIMEOUT_MS = 1000;

    // ========================================================================
    // DETECTION WEIGHTS (for scoring)
    // ========================================================================
    
    /// @brief Weight for PEB-based detection
    inline constexpr uint32_t WEIGHT_PEB_DETECTION = 25;
    
    /// @brief Weight for API-based detection
    inline constexpr uint32_t WEIGHT_API_DETECTION = 30;
    
    /// @brief Weight for timing-based detection
    inline constexpr uint32_t WEIGHT_TIMING_DETECTION = 20;
    
    /// @brief Weight for hardware breakpoint detection
    inline constexpr uint32_t WEIGHT_HARDWARE_BP_DETECTION = 35;
    
    /// @brief Weight for software breakpoint detection
    inline constexpr uint32_t WEIGHT_SOFTWARE_BP_DETECTION = 40;
    
    /// @brief Weight for exception-based detection
    inline constexpr uint32_t WEIGHT_EXCEPTION_DETECTION = 15;
    
    /// @brief Weight for process-based detection
    inline constexpr uint32_t WEIGHT_PROCESS_DETECTION = 20;
    
    /// @brief Weight for hook detection
    inline constexpr uint32_t WEIGHT_HOOK_DETECTION = 45;
    
    /// @brief Weight for instrumentation detection
    inline constexpr uint32_t WEIGHT_INSTRUMENTATION_DETECTION = 50;

    // ========================================================================
    // KNOWN DEBUGGER SIGNATURES
    // ========================================================================
    
    /// @brief Known debugger process names
    inline constexpr std::array<std::string_view, 25> DEBUGGER_PROCESSES = {
        "ollydbg.exe",
        "x64dbg.exe",
        "x32dbg.exe",
        "windbg.exe",
        "ida.exe",
        "ida64.exe",
        "idag.exe",
        "idag64.exe",
        "idaw.exe",
        "idaw64.exe",
        "idaq.exe",
        "idaq64.exe",
        "radare2.exe",
        "r2.exe",
        "ghidra.exe",
        "immunity debugger.exe",
        "devenv.exe",
        "dbgview.exe",
        "procmon.exe",
        "procexp.exe",
        "wireshark.exe",
        "fiddler.exe",
        "apimonitor.exe",
        "dnspy.exe",
        "cheatengine.exe"
    };
    
    /// @brief Known debugger window classes
    inline constexpr std::array<std::string_view, 15> DEBUGGER_WINDOW_CLASSES = {
        "OLLYDBG",
        "X64DBG",
        "X32DBG",
        "WinDbgFrameClass",
        "IDASteelClass",
        "Qt5QWindowIcon",
        "TIdaWindow",
        "Rock Debugger",
        "GHIDRA",
        "ImmunityDebugger",
        "SoftICE",
        "PROCMON_WINDOW_CLASS",
        "ProcessExplorer",
        "APIMonitor",
        "dnSpy"
    };
    
    /// @brief Known debugger driver names
    inline constexpr std::array<std::string_view, 10> DEBUGGER_DRIVERS = {
        "SICE",
        "SIWVID",
        "NTICE",
        "ICEEXT",
        "SYSER",
        "SYSERDEBUGGER",
        "REGMON",
        "FILEMON",
        "DBGHELP",
        "PROCMON"
    };
    
    /// @brief Known instrumentation framework signatures
    inline constexpr std::array<std::string_view, 8> INSTRUMENTATION_SIGNATURES = {
        "frida",
        "dynamorio",
        "pin",
        "valgrind",
        "drmemory",
        "apimonitor",
        "winapis",
        "detours"
    };

    // ========================================================================
    // NTDLL FUNCTION INDICES (for syscall usage)
    // ========================================================================
    
    /// @brief NtQueryInformationProcess syscall index (Windows 10 21H2)
    inline constexpr uint32_t SYSCALL_NtQueryInformationProcess = 0x19;
    
    /// @brief NtSetInformationThread syscall index
    inline constexpr uint32_t SYSCALL_NtSetInformationThread = 0x0D;
    
    /// @brief NtClose syscall index
    inline constexpr uint32_t SYSCALL_NtClose = 0x0F;

}  // namespace AntiDebugConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using Duration = std::chrono::steady_clock::duration;
using Milliseconds = std::chrono::milliseconds;
using Microseconds = std::chrono::microseconds;
using Nanoseconds = std::chrono::nanoseconds;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Detection technique categories
 */
enum class DetectionTechnique : uint32_t {
    None                    = 0x00000000,
    
    // PEB/TEB based
    PEB_BeingDebugged       = 0x00000001,
    PEB_NtGlobalFlag        = 0x00000002,
    PEB_HeapFlags           = 0x00000004,
    PEB_ProcessHeap         = 0x00000008,
    TEB_Analysis            = 0x00000010,
    
    // API based
    API_IsDebuggerPresent   = 0x00000020,
    API_CheckRemoteDebugger = 0x00000040,
    API_NtQueryInfoProcess  = 0x00000080,
    API_NtQuerySystemInfo   = 0x00000100,
    API_OutputDebugString   = 0x00000200,
    API_CloseHandle         = 0x00000400,
    
    // Timing based
    Timing_RDTSC            = 0x00000800,
    Timing_QPC              = 0x00001000,
    Timing_GetTickCount     = 0x00002000,
    Timing_TimeGetTime      = 0x00004000,
    Timing_Instruction      = 0x00008000,
    
    // Hardware based
    Hardware_DebugRegisters = 0x00010000,
    Hardware_Breakpoints    = 0x00020000,
    Hardware_Context        = 0x00040000,
    
    // Exception based
    Exception_INT3          = 0x00080000,
    Exception_INT2D         = 0x00100000,
    Exception_SingleStep    = 0x00200000,
    Exception_GuardPage     = 0x00400000,
    Exception_VEH           = 0x00800000,
    
    // Memory based
    Memory_Breakpoints      = 0x01000000,
    Memory_CodeIntegrity    = 0x02000000,
    Memory_IATHooks         = 0x04000000,
    Memory_InlineHooks      = 0x08000000,
    
    // Process based
    Process_ParentCheck     = 0x10000000,
    Process_DebuggerSearch  = 0x20000000,
    Process_WindowSearch    = 0x40000000,
    Process_DriverSearch    = 0x80000000,
    
    // Combined flags
    All_PEB                 = 0x0000001F,
    All_API                 = 0x000007E0,
    All_Timing              = 0x0000F800,
    All_Hardware            = 0x00070000,
    All_Exception           = 0x00F80000,
    All_Memory              = 0x0F000000,
    All_Process             = 0xF0000000,
    All                     = 0xFFFFFFFF
};

/// @brief Enable bitwise operations for DetectionTechnique
inline constexpr DetectionTechnique operator|(DetectionTechnique a, DetectionTechnique b) noexcept {
    return static_cast<DetectionTechnique>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr DetectionTechnique operator&(DetectionTechnique a, DetectionTechnique b) noexcept {
    return static_cast<DetectionTechnique>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline constexpr DetectionTechnique operator~(DetectionTechnique a) noexcept {
    return static_cast<DetectionTechnique>(~static_cast<uint32_t>(a));
}

inline constexpr bool HasFlag(DetectionTechnique value, DetectionTechnique flag) noexcept {
    return (static_cast<uint32_t>(value) & static_cast<uint32_t>(flag)) != 0;
}

/**
 * @brief Detection result confidence levels
 */
enum class DetectionConfidence : uint8_t {
    None        = 0,    ///< No detection
    Low         = 1,    ///< Low confidence (possible false positive)
    Medium      = 2,    ///< Medium confidence
    High        = 3,    ///< High confidence
    Critical    = 4     ///< Critical - definite debugger presence
};

/**
 * @brief Response actions when debugger is detected
 */
enum class ResponseAction : uint32_t {
    None            = 0x00000000,   ///< No action (logging only)
    Log             = 0x00000001,   ///< Log the detection
    Alert           = 0x00000002,   ///< Send alert notification
    Notify          = 0x00000004,   ///< Notify user
    HideThreads     = 0x00000008,   ///< Hide threads from debugger
    ClearBreakpoints= 0x00000010,   ///< Clear debug registers
    CorruptContext  = 0x00000020,   ///< Corrupt debugging context
    SuspendDebugger = 0x00000040,   ///< Attempt to suspend debugger
    TerminateSelf   = 0x00000080,   ///< Terminate own process (last resort)
    Quarantine      = 0x00000100,   ///< Quarantine suspicious processes
    BlockAPIs       = 0x00000200,   ///< Block debugging APIs
    EncryptMemory   = 0x00000400,   ///< Encrypt sensitive memory regions
    Relocate        = 0x00000800,   ///< Relocate code to evade analysis
    
    // Preset combinations
    Passive         = Log | Alert,
    Moderate        = Log | Alert | HideThreads | ClearBreakpoints,
    Aggressive      = Log | Alert | HideThreads | ClearBreakpoints | CorruptContext | BlockAPIs,
    Maximum         = 0xFFFFFFFF
};

inline constexpr ResponseAction operator|(ResponseAction a, ResponseAction b) noexcept {
    return static_cast<ResponseAction>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr ResponseAction operator&(ResponseAction a, ResponseAction b) noexcept {
    return static_cast<ResponseAction>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/**
 * @brief Monitoring mode for anti-debug checks
 */
enum class MonitoringMode : uint8_t {
    Disabled        = 0,    ///< No monitoring
    OnDemand        = 1,    ///< Check only when explicitly called
    Periodic        = 2,    ///< Check at regular intervals
    Continuous      = 3,    ///< Continuous background monitoring
    Adaptive        = 4     ///< Adjust frequency based on threat level
};

/**
 * @brief Protection level presets
 */
enum class ProtectionLevel : uint8_t {
    Disabled    = 0,    ///< No protection
    Minimal     = 1,    ///< Basic checks only
    Standard    = 2,    ///< Standard protection
    Enhanced    = 3,    ///< Enhanced protection
    Maximum     = 4,    ///< Maximum protection (may affect performance)
    Paranoid    = 5     ///< Paranoid mode (aggressive, may cause issues)
};

/**
 * @brief Debugger type classification
 */
enum class DebuggerType : uint8_t {
    Unknown         = 0,
    UserMode        = 1,    ///< User-mode debugger (OllyDbg, x64dbg)
    KernelMode      = 2,    ///< Kernel-mode debugger (WinDbg kernel)
    Remote          = 3,    ///< Remote debugger
    Attached        = 4,    ///< Attached to existing process
    JustInTime      = 5,    ///< Just-in-time debugger
    Instrumentation = 6,    ///< Instrumentation framework (Frida, DynamoRIO)
    Sandbox         = 7,    ///< Sandbox environment
    VirtualMachine  = 8     ///< Virtual machine debugger
};

/**
 * @brief Hook type classification
 */
enum class HookType : uint8_t {
    None            = 0,
    InlineJump      = 1,    ///< Inline JMP hook
    InlineCall      = 2,    ///< Inline CALL hook
    IAT             = 3,    ///< Import Address Table hook
    EAT             = 4,    ///< Export Address Table hook
    VTable          = 5,    ///< Virtual function table hook
    HotPatch        = 6,    ///< Hot-patching hook
    Trampoline      = 7,    ///< Trampoline-based hook
    PageGuard       = 8,    ///< Page guard hook
    Hardware        = 9     ///< Hardware breakpoint
};

/**
 * @brief Integrity check status
 */
enum class IntegrityStatus : uint8_t {
    Unknown     = 0,
    Valid       = 1,    ///< Integrity verified
    Modified    = 2,    ///< Code has been modified
    Hooked      = 3,    ///< Hooks detected
    Corrupted   = 4     ///< Code is corrupted
};

/**
 * @brief Anti-debug module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Paused          = 3,
    Stopping        = 4,
    Stopped         = 5,
    Error           = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Configuration for anti-debug protection
 */
struct AntiDebugConfiguration {
    /// @brief Protection level preset
    ProtectionLevel protectionLevel = ProtectionLevel::Standard;
    
    /// @brief Monitoring mode
    MonitoringMode monitoringMode = MonitoringMode::Periodic;
    
    /// @brief Detection techniques to enable (bitmask)
    DetectionTechnique enabledTechniques = DetectionTechnique::All;
    
    /// @brief Response actions to take on detection
    ResponseAction responseActions = ResponseAction::Moderate;
    
    /// @brief Monitoring interval (milliseconds)
    uint32_t monitoringIntervalMs = AntiDebugConstants::DEFAULT_MONITOR_INTERVAL_MS;
    
    /// @brief Minimum detection score to trigger response
    uint32_t detectionThreshold = AntiDebugConstants::MIN_DETECTION_SCORE;
    
    /// @brief Enable code integrity verification
    bool enableCodeIntegrity = true;
    
    /// @brief Enable hook detection
    bool enableHookDetection = true;
    
    /// @brief Enable timing-based detection
    bool enableTimingDetection = true;
    
    /// @brief Enable exception-based detection
    bool enableExceptionDetection = true;
    
    /// @brief Enable process enumeration detection
    bool enableProcessDetection = true;
    
    /// @brief Enable hardware breakpoint detection
    bool enableHardwareDetection = true;
    
    /// @brief Hide threads from debugger on startup
    bool autoHideThreads = true;
    
    /// @brief Clear debug registers periodically
    bool autoClearDebugRegisters = true;
    
    /// @brief Log all detection events
    bool verboseLogging = false;
    
    /// @brief Send telemetry on detections
    bool sendTelemetry = true;
    
    /// @brief Whitelist for legitimate development tools
    std::vector<std::wstring> whitelistedProcesses;
    
    /// @brief Custom debugger signatures to detect
    std::vector<std::string> customDebuggerSignatures;
    
    /// @brief Maximum false positives before auto-disable
    uint32_t maxFalsePositives = 10;
    
    /// @brief Critical regions to protect (addresses)
    std::vector<std::pair<uintptr_t, size_t>> criticalRegions;
    
    /**
     * @brief Create configuration from protection level preset
     */
    static AntiDebugConfiguration FromProtectionLevel(ProtectionLevel level);
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
    
    /**
     * @brief Merge with another configuration (other takes precedence)
     */
    void Merge(const AntiDebugConfiguration& other);
};

/**
 * @brief Result of a single detection check
 */
struct DetectionCheckResult {
    /// @brief Technique that was used
    DetectionTechnique technique = DetectionTechnique::None;
    
    /// @brief Whether debugger was detected
    bool detected = false;
    
    /// @brief Confidence level
    DetectionConfidence confidence = DetectionConfidence::None;
    
    /// @brief Detection score contribution (0-100)
    uint32_t score = 0;
    
    /// @brief Detected debugger type (if identified)
    DebuggerType debuggerType = DebuggerType::Unknown;
    
    /// @brief Descriptive message
    std::string message;
    
    /// @brief Additional details (technique-specific)
    std::unordered_map<std::string, std::string> details;
    
    /// @brief Timestamp of detection
    TimePoint timestamp = Clock::now();
    
    /// @brief Duration of check
    Microseconds checkDuration{0};
    
    /// @brief Error code if check failed
    uint32_t errorCode = 0;
};

/**
 * @brief Aggregated detection result from all checks
 */
struct DetectionResult {
    /// @brief Overall detection status
    bool debuggerDetected = false;
    
    /// @brief Aggregated confidence level
    DetectionConfidence overallConfidence = DetectionConfidence::None;
    
    /// @brief Total detection score (0-100+)
    uint32_t totalScore = 0;
    
    /// @brief Techniques that triggered detection
    DetectionTechnique triggeredTechniques = DetectionTechnique::None;
    
    /// @brief Most likely debugger type
    DebuggerType primaryDebuggerType = DebuggerType::Unknown;
    
    /// @brief Individual check results
    std::vector<DetectionCheckResult> checkResults;
    
    /// @brief Detected debugger processes
    std::vector<std::wstring> detectedProcesses;
    
    /// @brief Detected debugger windows
    std::vector<std::wstring> detectedWindows;
    
    /// @brief Detected hooks
    std::vector<std::pair<uintptr_t, HookType>> detectedHooks;
    
    /// @brief Timestamp of scan
    TimePoint scanTimestamp = Clock::now();
    
    /// @brief Total scan duration
    Milliseconds scanDuration{0};
    
    /// @brief Number of checks performed
    uint32_t checksPerformed = 0;
    
    /// @brief Number of checks that detected something
    uint32_t checksTriggered = 0;
    
    /// @brief Recommended response action
    ResponseAction recommendedAction = ResponseAction::None;
    
    /// @brief Whether this is likely a false positive
    bool possibleFalsePositive = false;
    
    /// @brief False positive reason (if applicable)
    std::string falsePositiveReason;
    
    /**
     * @brief Check if score exceeds threshold
     */
    [[nodiscard]] bool ExceedsThreshold(uint32_t threshold) const noexcept {
        return totalScore >= threshold;
    }
    
    /**
     * @brief Get detection summary string
     */
    [[nodiscard]] std::string GetSummary() const;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Hardware debug register state
 */
struct DebugRegisterState {
    /// @brief DR0 - Linear address for breakpoint 0
    uintptr_t dr0 = 0;
    
    /// @brief DR1 - Linear address for breakpoint 1
    uintptr_t dr1 = 0;
    
    /// @brief DR2 - Linear address for breakpoint 2
    uintptr_t dr2 = 0;
    
    /// @brief DR3 - Linear address for breakpoint 3
    uintptr_t dr3 = 0;
    
    /// @brief DR6 - Debug status register
    uintptr_t dr6 = 0;
    
    /// @brief DR7 - Debug control register
    uintptr_t dr7 = 0;
    
    /// @brief Check if any hardware breakpoints are set
    [[nodiscard]] bool HasBreakpoints() const noexcept {
        return dr0 != 0 || dr1 != 0 || dr2 != 0 || dr3 != 0 ||
               (dr7 & 0xFF) != 0;
    }
    
    /// @brief Get number of active breakpoints
    [[nodiscard]] uint32_t GetActiveBreakpointCount() const noexcept;
    
    /// @brief Clear all breakpoint addresses
    void Clear() noexcept {
        dr0 = dr1 = dr2 = dr3 = dr6 = dr7 = 0;
    }
};

/**
 * @brief Detected hook information
 */
struct HookInfo {
    /// @brief Address of the hook
    uintptr_t address = 0;
    
    /// @brief Original address (target of hook)
    uintptr_t originalTarget = 0;
    
    /// @brief Hook destination address
    uintptr_t hookDestination = 0;
    
    /// @brief Type of hook
    HookType type = HookType::None;
    
    /// @brief Module containing the hook
    std::wstring moduleName;
    
    /// @brief Function name if known
    std::string functionName;
    
    /// @brief Original bytes that were overwritten
    std::vector<uint8_t> originalBytes;
    
    /// @brief Current bytes at the location
    std::vector<uint8_t> currentBytes;
    
    /// @brief Size of the hook
    size_t hookSize = 0;
    
    /// @brief Whether this is a suspicious hook
    bool isSuspicious = true;
    
    /// @brief Detection timestamp
    TimePoint detectionTime = Clock::now();
};

/**
 * @brief Code integrity region information
 */
struct IntegrityRegion {
    /// @brief Region identifier
    std::string id;
    
    /// @brief Start address
    uintptr_t startAddress = 0;
    
    /// @brief Region size
    size_t size = 0;
    
    /// @brief Expected hash (SHA256)
    std::array<uint8_t, 32> expectedHash{};
    
    /// @brief Current hash
    std::array<uint8_t, 32> currentHash{};
    
    /// @brief Fast CRC32 for quick checks
    uint32_t expectedCrc32 = 0;
    
    /// @brief Current CRC32
    uint32_t currentCrc32 = 0;
    
    /// @brief Integrity status
    IntegrityStatus status = IntegrityStatus::Unknown;
    
    /// @brief Last verification timestamp
    TimePoint lastVerified;
    
    /// @brief Number of integrity failures
    uint32_t failureCount = 0;
    
    /**
     * @brief Check if integrity is valid
     */
    [[nodiscard]] bool IsValid() const noexcept {
        return status == IntegrityStatus::Valid;
    }
};

/**
 * @brief Timing analysis data
 */
struct TimingAnalysis {
    /// @brief RDTSC samples
    std::vector<uint64_t> rdtscSamples;
    
    /// @brief QueryPerformanceCounter samples
    std::vector<int64_t> qpcSamples;
    
    /// @brief GetTickCount64 samples
    std::vector<uint64_t> tickCountSamples;
    
    /// @brief Average RDTSC delta
    uint64_t avgRdtscDelta = 0;
    
    /// @brief Average QPC delta (100ns units)
    int64_t avgQpcDelta = 0;
    
    /// @brief Standard deviation of RDTSC
    double rdtscStdDev = 0.0;
    
    /// @brief Anomaly score (0-100)
    uint32_t anomalyScore = 0;
    
    /// @brief Whether timing anomaly detected
    bool anomalyDetected = false;
    
    /// @brief Analysis timestamp
    TimePoint analysisTime = Clock::now();
};

/**
 * @brief Detection event for callbacks
 */
struct DetectionEvent {
    /// @brief Event identifier
    uint64_t eventId = 0;
    
    /// @brief Detection technique
    DetectionTechnique technique = DetectionTechnique::None;
    
    /// @brief Detection confidence
    DetectionConfidence confidence = DetectionConfidence::None;
    
    /// @brief Detection score
    uint32_t score = 0;
    
    /// @brief Detected debugger type
    DebuggerType debuggerType = DebuggerType::Unknown;
    
    /// @brief Event message
    std::string message;
    
    /// @brief Event timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Thread ID that detected
    uint32_t threadId = 0;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Response actions taken
    ResponseAction actionsTaken = ResponseAction::None;
    
    /// @brief Additional context
    std::unordered_map<std::string, std::string> context;
};

/**
 * @brief Statistics for anti-debug module
 */
struct AntiDebugStatistics {
    /// @brief Total detection checks performed
    std::atomic<uint64_t> totalChecks{0};
    
    /// @brief Total detections triggered
    std::atomic<uint64_t> totalDetections{0};
    
    /// @brief Detections by technique
    std::unordered_map<DetectionTechnique, uint64_t> detectionsByTechnique;
    
    /// @brief Detections by debugger type
    std::unordered_map<DebuggerType, uint64_t> detectionsByType;
    
    /// @brief False positives identified
    std::atomic<uint64_t> falsePositives{0};
    
    /// @brief Response actions executed
    std::atomic<uint64_t> actionsExecuted{0};
    
    /// @brief Threads hidden
    std::atomic<uint64_t> threadsHidden{0};
    
    /// @brief Hardware breakpoints cleared
    std::atomic<uint64_t> breakpointsCleared{0};
    
    /// @brief Hooks detected
    std::atomic<uint64_t> hooksDetected{0};
    
    /// @brief Integrity violations detected
    std::atomic<uint64_t> integrityViolations{0};
    
    /// @brief Average check duration (microseconds)
    std::atomic<uint64_t> avgCheckDurationUs{0};
    
    /// @brief Maximum check duration (microseconds)
    std::atomic<uint64_t> maxCheckDurationUs{0};
    
    /// @brief Module uptime
    TimePoint startTime = Clock::now();
    
    /// @brief Last detection timestamp
    TimePoint lastDetectionTime;
    
    /// @brief Last check timestamp
    TimePoint lastCheckTime;
    
    /**
     * @brief Get uptime in seconds
     */
    [[nodiscard]] uint64_t GetUptimeSeconds() const noexcept {
        return std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now() - startTime).count();
    }
    
    /**
     * @brief Reset all statistics
     */
    void Reset() noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Thread protection state
 */
struct ThreadProtectionState {
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Thread handle
    void* threadHandle = nullptr;
    
    /// @brief Whether thread is hidden from debugger
    bool isHidden = false;
    
    /// @brief Whether debug registers are cleared
    bool debugRegistersClear = false;
    
    /// @brief Protection timestamp
    TimePoint protectionTime;
    
    /// @brief Last verification timestamp
    TimePoint lastVerified;
    
    /// @brief Protection failure count
    uint32_t failureCount = 0;
};

/**
 * @brief Process information for debugger detection
 */
struct DebuggerProcessInfo {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Full path
    std::wstring fullPath;
    
    /// @brief Debugger type classification
    DebuggerType type = DebuggerType::Unknown;
    
    /// @brief Window handle (if has visible window)
    void* windowHandle = nullptr;
    
    /// @brief Window title
    std::wstring windowTitle;
    
    /// @brief Whether process is debugging us
    bool isDebuggingUs = false;
    
    /// @brief Detection confidence
    DetectionConfidence confidence = DetectionConfidence::None;
    
    /// @brief Detection timestamp
    TimePoint detectionTime = Clock::now();
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Callback for detection events
using DetectionCallback = std::function<void(const DetectionEvent&)>;

/// @brief Callback for response actions
using ResponseCallback = std::function<bool(ResponseAction action, const DetectionResult&)>;

/// @brief Callback for integrity violations
using IntegrityCallback = std::function<void(const IntegrityRegion&)>;

/// @brief Callback for hook detection
using HookCallback = std::function<void(const HookInfo&)>;

/// @brief Callback for status changes
using StatusCallback = std::function<void(ModuleStatus oldStatus, ModuleStatus newStatus)>;

// ============================================================================
// CONCEPTS
// ============================================================================

/**
 * @brief Concept for detection check functions
 */
template<typename T>
concept DetectionCheck = requires(T check) {
    { check() } -> std::convertible_to<DetectionCheckResult>;
};

/**
 * @brief Concept for response action handlers
 */
template<typename T>
concept ResponseHandler = requires(T handler, ResponseAction action, const DetectionResult& result) {
    { handler(action, result) } -> std::convertible_to<bool>;
};

// ============================================================================
// ANTI-DEBUG ENGINE CLASS
// ============================================================================

/**
 * @class AntiDebug
 * @brief Enterprise-grade anti-debugging protection engine
 *
 * This class provides comprehensive protection against debugging, reverse
 * engineering, and instrumentation attacks. It implements multiple detection
 * layers with configurable sensitivity and response actions.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& antiDebug = AntiDebug::Instance();
 *     
 *     AntiDebugConfiguration config;
 *     config.protectionLevel = ProtectionLevel::Enhanced;
 *     config.monitoringMode = MonitoringMode::Continuous;
 *     
 *     if (!antiDebug.Initialize(config)) {
 *         // Handle initialization failure
 *     }
 *     
 *     // Register detection callback
 *     antiDebug.RegisterDetectionCallback([](const DetectionEvent& event) {
 *         LOG_WARNING("Debugger detected: {}", event.message);
 *     });
 *     
 *     // Perform manual check
 *     auto result = antiDebug.PerformFullScan();
 *     if (result.debuggerDetected) {
 *         // Take appropriate action
 *     }
 *     
 *     // Protect current thread
 *     antiDebug.ProtectThread(GetCurrentThreadId());
 * @endcode
 */
class AntiDebug final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance (thread-safe)
     * @return Reference to the singleton instance
     */
    [[nodiscard]] static AntiDebug& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     * @return true if instance has been created
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Delete copy and move operations
    AntiDebug(const AntiDebug&) = delete;
    AntiDebug& operator=(const AntiDebug&) = delete;
    AntiDebug(AntiDebug&&) = delete;
    AntiDebug& operator=(AntiDebug&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize the anti-debug engine
     * @param config Configuration settings
     * @return true if initialization succeeded
     */
    [[nodiscard]] bool Initialize(const AntiDebugConfiguration& config = {});
    
    /**
     * @brief Initialize with protection level preset
     * @param level Protection level preset
     * @return true if initialization succeeded
     */
    [[nodiscard]] bool Initialize(ProtectionLevel level);
    
    /**
     * @brief Shutdown the anti-debug engine
     */
    void Shutdown() noexcept;
    
    /**
     * @brief Check if engine is initialized
     * @return true if initialized and running
     */
    [[nodiscard]] bool IsInitialized() const noexcept;
    
    /**
     * @brief Get current module status
     * @return Current status
     */
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    /**
     * @brief Pause monitoring (keeps state)
     */
    void Pause() noexcept;
    
    /**
     * @brief Resume monitoring
     */
    void Resume() noexcept;
    
    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    
    /**
     * @brief Update configuration
     * @param config New configuration
     * @return true if configuration was applied
     */
    [[nodiscard]] bool SetConfiguration(const AntiDebugConfiguration& config);
    
    /**
     * @brief Get current configuration
     * @return Current configuration (copy)
     */
    [[nodiscard]] AntiDebugConfiguration GetConfiguration() const;
    
    /**
     * @brief Set protection level
     * @param level Protection level preset
     */
    void SetProtectionLevel(ProtectionLevel level);
    
    /**
     * @brief Get current protection level
     * @return Current protection level
     */
    [[nodiscard]] ProtectionLevel GetProtectionLevel() const noexcept;
    
    /**
     * @brief Set monitoring mode
     * @param mode Monitoring mode
     */
    void SetMonitoringMode(MonitoringMode mode);
    
    /**
     * @brief Get current monitoring mode
     * @return Current monitoring mode
     */
    [[nodiscard]] MonitoringMode GetMonitoringMode() const noexcept;
    
    /**
     * @brief Set monitoring interval
     * @param intervalMs Interval in milliseconds
     */
    void SetMonitoringInterval(uint32_t intervalMs);
    
    /**
     * @brief Enable specific detection technique
     * @param technique Technique to enable
     */
    void EnableTechnique(DetectionTechnique technique);
    
    /**
     * @brief Disable specific detection technique
     * @param technique Technique to disable
     */
    void DisableTechnique(DetectionTechnique technique);
    
    /**
     * @brief Check if technique is enabled
     * @param technique Technique to check
     * @return true if enabled
     */
    [[nodiscard]] bool IsTechniqueEnabled(DetectionTechnique technique) const noexcept;
    
    /**
     * @brief Set response actions
     * @param actions Response action flags
     */
    void SetResponseActions(ResponseAction actions);
    
    /**
     * @brief Get current response actions
     * @return Current response action flags
     */
    [[nodiscard]] ResponseAction GetResponseActions() const noexcept;
    
    /**
     * @brief Add process to whitelist
     * @param processName Process name to whitelist
     */
    void AddToWhitelist(std::wstring_view processName);
    
    /**
     * @brief Remove process from whitelist
     * @param processName Process name to remove
     */
    void RemoveFromWhitelist(std::wstring_view processName);
    
    /**
     * @brief Check if process is whitelisted
     * @param processName Process name to check
     * @return true if whitelisted
     */
    [[nodiscard]] bool IsWhitelisted(std::wstring_view processName) const;
    
    // ========================================================================
    // DETECTION - FULL SCANS
    // ========================================================================
    
    /**
     * @brief Perform a full anti-debug scan using all enabled techniques
     * @return Aggregated detection result
     */
    [[nodiscard]] DetectionResult PerformFullScan();
    
    /**
     * @brief Perform a quick scan using fastest techniques only
     * @return Aggregated detection result
     */
    [[nodiscard]] DetectionResult PerformQuickScan();
    
    /**
     * @brief Perform scan with specific techniques only
     * @param techniques Techniques to use
     * @return Aggregated detection result
     */
    [[nodiscard]] DetectionResult PerformScan(DetectionTechnique techniques);
    
    /**
     * @brief Check if debugger is currently detected (cached result)
     * @return true if debugger was detected in last scan
     */
    [[nodiscard]] bool IsDebuggerDetected() const noexcept;
    
    /**
     * @brief Get last detection result
     * @return Last detection result (may be stale)
     */
    [[nodiscard]] DetectionResult GetLastResult() const;
    
    /**
     * @brief Get current detection score
     * @return Detection score from last scan (0-100+)
     */
    [[nodiscard]] uint32_t GetDetectionScore() const noexcept;
    
    // ========================================================================
    // DETECTION - PEB/TEB BASED
    // ========================================================================
    
    /**
     * @brief Check BeingDebugged flag in PEB
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckPEB_BeingDebugged();
    
    /**
     * @brief Check NtGlobalFlag in PEB
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckPEB_NtGlobalFlag();
    
    /**
     * @brief Check heap flags for debugging indicators
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckPEB_HeapFlags();
    
    /**
     * @brief Check ProcessHeap for debugging artifacts
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckPEB_ProcessHeap();
    
    /**
     * @brief Perform all PEB-based checks
     * @return Combined detection result
     */
    [[nodiscard]] DetectionCheckResult CheckAllPEB();
    
    // ========================================================================
    // DETECTION - API BASED
    // ========================================================================
    
    /**
     * @brief Use IsDebuggerPresent API
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckAPI_IsDebuggerPresent();
    
    /**
     * @brief Use CheckRemoteDebuggerPresent API
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckAPI_CheckRemoteDebuggerPresent();
    
    /**
     * @brief Use NtQueryInformationProcess with ProcessDebugPort
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckAPI_NtQueryInformationProcess_DebugPort();
    
    /**
     * @brief Use NtQueryInformationProcess with ProcessDebugFlags
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckAPI_NtQueryInformationProcess_DebugFlags();
    
    /**
     * @brief Use NtQueryInformationProcess with ProcessDebugObjectHandle
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckAPI_NtQueryInformationProcess_DebugObjectHandle();
    
    /**
     * @brief Check OutputDebugString behavior
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckAPI_OutputDebugString();
    
    /**
     * @brief Check CloseHandle with invalid handle
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckAPI_CloseHandle();
    
    /**
     * @brief Perform all API-based checks
     * @return Combined detection result
     */
    [[nodiscard]] DetectionCheckResult CheckAllAPI();
    
    // ========================================================================
    // DETECTION - TIMING BASED
    // ========================================================================
    
    /**
     * @brief Perform RDTSC timing analysis
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckTiming_RDTSC();
    
    /**
     * @brief Perform QueryPerformanceCounter timing analysis
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckTiming_QPC();
    
    /**
     * @brief Perform GetTickCount64 timing analysis
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckTiming_GetTickCount();
    
    /**
     * @brief Check for timing anomalies in instruction execution
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckTiming_InstructionExecution();
    
    /**
     * @brief Perform comprehensive timing analysis
     * @return Detailed timing analysis result
     */
    [[nodiscard]] TimingAnalysis PerformTimingAnalysis();
    
    /**
     * @brief Perform all timing-based checks
     * @return Combined detection result
     */
    [[nodiscard]] DetectionCheckResult CheckAllTiming();
    
    // ========================================================================
    // DETECTION - HARDWARE BASED
    // ========================================================================
    
    /**
     * @brief Check hardware debug registers (DR0-DR7)
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckHardware_DebugRegisters();
    
    /**
     * @brief Get current debug register state
     * @return Debug register state
     */
    [[nodiscard]] DebugRegisterState GetDebugRegisterState();
    
    /**
     * @brief Check for hardware breakpoints via context
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckHardware_BreakpointsViaContext();
    
    /**
     * @brief Perform all hardware-based checks
     * @return Combined detection result
     */
    [[nodiscard]] DetectionCheckResult CheckAllHardware();
    
    // ========================================================================
    // DETECTION - EXCEPTION BASED
    // ========================================================================
    
    /**
     * @brief Check using INT 3 exception
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckException_INT3();
    
    /**
     * @brief Check using INT 2D exception
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckException_INT2D();
    
    /**
     * @brief Check using single-step exception
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckException_SingleStep();
    
    /**
     * @brief Check using guard page exception
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckException_GuardPage();
    
    /**
     * @brief Analyze Vectored Exception Handlers
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckException_VEH();
    
    /**
     * @brief Perform all exception-based checks
     * @return Combined detection result
     */
    [[nodiscard]] DetectionCheckResult CheckAllException();
    
    // ========================================================================
    // DETECTION - MEMORY BASED
    // ========================================================================
    
    /**
     * @brief Scan for software breakpoints (0xCC)
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckMemory_SoftwareBreakpoints();
    
    /**
     * @brief Scan specific memory range for breakpoints
     * @param address Start address
     * @param size Size to scan
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckMemory_SoftwareBreakpoints(
        uintptr_t address, size_t size);
    
    /**
     * @brief Verify code integrity of protected regions
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckMemory_CodeIntegrity();
    
    /**
     * @brief Check for IAT hooks
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckMemory_IATHooks();
    
    /**
     * @brief Check for IAT hooks in specific module
     * @param moduleName Module to check
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckMemory_IATHooks(std::wstring_view moduleName);
    
    /**
     * @brief Check for inline hooks
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckMemory_InlineHooks();
    
    /**
     * @brief Check for inline hooks in specific module
     * @param moduleName Module to check
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckMemory_InlineHooks(std::wstring_view moduleName);
    
    /**
     * @brief Get all detected hooks
     * @return Vector of detected hooks
     */
    [[nodiscard]] std::vector<HookInfo> GetDetectedHooks() const;
    
    /**
     * @brief Perform all memory-based checks
     * @return Combined detection result
     */
    [[nodiscard]] DetectionCheckResult CheckAllMemory();
    
    // ========================================================================
    // DETECTION - PROCESS BASED
    // ========================================================================
    
    /**
     * @brief Validate parent process
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckProcess_ParentProcess();
    
    /**
     * @brief Search for debugger processes
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckProcess_DebuggerProcesses();
    
    /**
     * @brief Search for debugger windows
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckProcess_DebuggerWindows();
    
    /**
     * @brief Search for debugger drivers
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckProcess_DebuggerDrivers();
    
    /**
     * @brief Detect instrumentation frameworks
     * @return Detection result
     */
    [[nodiscard]] DetectionCheckResult CheckProcess_InstrumentationFrameworks();
    
    /**
     * @brief Get detected debugger processes
     * @return Vector of debugger process info
     */
    [[nodiscard]] std::vector<DebuggerProcessInfo> GetDetectedDebuggers() const;
    
    /**
     * @brief Perform all process-based checks
     * @return Combined detection result
     */
    [[nodiscard]] DetectionCheckResult CheckAllProcess();
    
    // ========================================================================
    // PROTECTION - THREAD HIDING
    // ========================================================================
    
    /**
     * @brief Hide thread from debugger
     * @param threadId Thread ID to hide (0 = current thread)
     * @return true if successful
     */
    [[nodiscard]] bool HideThread(uint32_t threadId = 0);
    
    /**
     * @brief Hide all threads in current process
     * @return Number of threads hidden
     */
    [[nodiscard]] size_t HideAllThreads();
    
    /**
     * @brief Check if thread is hidden
     * @param threadId Thread ID to check (0 = current thread)
     * @return true if hidden
     */
    [[nodiscard]] bool IsThreadHidden(uint32_t threadId = 0) const;
    
    /**
     * @brief Get thread protection state
     * @param threadId Thread ID (0 = current thread)
     * @return Thread protection state
     */
    [[nodiscard]] ThreadProtectionState GetThreadProtectionState(uint32_t threadId = 0) const;
    
    /**
     * @brief Apply protection to current thread (legacy method)
     */
    void SecureThread();
    
    /**
     * @brief Protect thread with full security measures
     * @param threadId Thread ID (0 = current thread)
     * @return true if all protections applied
     */
    [[nodiscard]] bool ProtectThread(uint32_t threadId = 0);
    
    // ========================================================================
    // PROTECTION - DEBUG REGISTERS
    // ========================================================================
    
    /**
     * @brief Clear hardware debug registers
     * @param threadId Thread ID (0 = current thread)
     * @return true if successful
     */
    [[nodiscard]] bool ClearDebugRegisters(uint32_t threadId = 0);
    
    /**
     * @brief Clear debug registers for all threads
     * @return Number of threads processed
     */
    [[nodiscard]] size_t ClearAllDebugRegisters();
    
    /**
     * @brief Monitor and auto-clear debug registers
     * @param enable Enable/disable monitoring
     */
    void SetAutoClearing(bool enable);
    
    // ========================================================================
    // PROTECTION - CODE INTEGRITY
    // ========================================================================
    
    /**
     * @brief Register region for integrity protection
     * @param id Region identifier
     * @param address Start address
     * @param size Region size
     * @return true if registered
     */
    [[nodiscard]] bool RegisterIntegrityRegion(
        std::string_view id, uintptr_t address, size_t size);
    
    /**
     * @brief Register current module's code section for integrity
     * @return true if registered
     */
    [[nodiscard]] bool RegisterSelfIntegrity();
    
    /**
     * @brief Unregister integrity region
     * @param id Region identifier
     */
    void UnregisterIntegrityRegion(std::string_view id);
    
    /**
     * @brief Verify integrity of specific region
     * @param id Region identifier
     * @return Integrity status
     */
    [[nodiscard]] IntegrityStatus VerifyIntegrity(std::string_view id);
    
    /**
     * @brief Verify all registered regions
     * @return Map of region ID to integrity status
     */
    [[nodiscard]] std::unordered_map<std::string, IntegrityStatus> VerifyAllIntegrity();
    
    /**
     * @brief Get integrity region info
     * @param id Region identifier
     * @return Integrity region info (nullopt if not found)
     */
    [[nodiscard]] std::optional<IntegrityRegion> GetIntegrityRegion(std::string_view id) const;
    
    /**
     * @brief Get all integrity regions
     * @return Vector of all registered regions
     */
    [[nodiscard]] std::vector<IntegrityRegion> GetAllIntegrityRegions() const;
    
    // ========================================================================
    // PROTECTION - RESPONSE ACTIONS
    // ========================================================================
    
    /**
     * @brief Execute response action
     * @param action Action to execute
     * @param result Detection result triggering the action
     * @return true if action was executed
     */
    [[nodiscard]] bool ExecuteResponse(ResponseAction action, const DetectionResult& result);
    
    /**
     * @brief Execute recommended response for detection result
     * @param result Detection result
     * @return Actions that were executed
     */
    [[nodiscard]] ResponseAction ExecuteRecommendedResponse(const DetectionResult& result);
    
    // ========================================================================
    // CALLBACKS AND EVENTS
    // ========================================================================
    
    /**
     * @brief Register detection callback
     * @param callback Callback function
     * @return Callback ID for removal
     */
    [[nodiscard]] uint64_t RegisterDetectionCallback(DetectionCallback callback);
    
    /**
     * @brief Unregister detection callback
     * @param callbackId Callback ID from registration
     */
    void UnregisterDetectionCallback(uint64_t callbackId);
    
    /**
     * @brief Register response callback
     * @param callback Callback function
     * @return Callback ID for removal
     */
    [[nodiscard]] uint64_t RegisterResponseCallback(ResponseCallback callback);
    
    /**
     * @brief Unregister response callback
     * @param callbackId Callback ID from registration
     */
    void UnregisterResponseCallback(uint64_t callbackId);
    
    /**
     * @brief Register integrity violation callback
     * @param callback Callback function
     * @return Callback ID for removal
     */
    [[nodiscard]] uint64_t RegisterIntegrityCallback(IntegrityCallback callback);
    
    /**
     * @brief Unregister integrity callback
     * @param callbackId Callback ID from registration
     */
    void UnregisterIntegrityCallback(uint64_t callbackId);
    
    /**
     * @brief Register hook detection callback
     * @param callback Callback function
     * @return Callback ID for removal
     */
    [[nodiscard]] uint64_t RegisterHookCallback(HookCallback callback);
    
    /**
     * @brief Unregister hook callback
     * @param callbackId Callback ID from registration
     */
    void UnregisterHookCallback(uint64_t callbackId);
    
    /**
     * @brief Register status change callback
     * @param callback Callback function
     * @return Callback ID for removal
     */
    [[nodiscard]] uint64_t RegisterStatusCallback(StatusCallback callback);
    
    /**
     * @brief Unregister status callback
     * @param callbackId Callback ID from registration
     */
    void UnregisterStatusCallback(uint64_t callbackId);
    
    // ========================================================================
    // STATISTICS AND MONITORING
    // ========================================================================
    
    /**
     * @brief Get statistics
     * @return Current statistics
     */
    [[nodiscard]] AntiDebugStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    /**
     * @brief Get detection history
     * @param maxEntries Maximum entries to return
     * @return Vector of detection events
     */
    [[nodiscard]] std::vector<DetectionEvent> GetDetectionHistory(size_t maxEntries = 100) const;
    
    /**
     * @brief Clear detection history
     */
    void ClearDetectionHistory();
    
    /**
     * @brief Export detection report
     * @return JSON formatted report
     */
    [[nodiscard]] std::string ExportReport() const;
    
    // ========================================================================
    // UTILITY METHODS
    // ========================================================================
    
    /**
     * @brief Get module version string
     * @return Version string (e.g., "3.0.0")
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;
    
    /**
     * @brief Get module build information
     * @return Build information string
     */
    [[nodiscard]] static std::string GetBuildInfo() noexcept;
    
    /**
     * @brief Validate that anti-debug is functional
     * @return true if all systems operational
     */
    [[nodiscard]] bool SelfTest();
    
    /**
     * @brief Force garbage collection of internal caches
     */
    void ForceGarbageCollection();

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (Singleton)
    // ========================================================================
    
    AntiDebug();
    ~AntiDebug();
    
    // ========================================================================
    // PIMPL IMPLEMENTATION
    // ========================================================================
    
    std::unique_ptr<AntiDebugImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// INLINE UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Quick check if any debugger is attached (no object creation)
 * @return true if debugger detected
 */
[[nodiscard]] inline bool QuickDebuggerCheck() noexcept {
#ifdef _WIN32
    return ::IsDebuggerPresent() != FALSE;
#else
    return false;
#endif
}

/**
 * @brief Get detection technique name
 * @param technique Technique enum value
 * @return Human-readable name
 */
[[nodiscard]] std::string_view GetTechniqueName(DetectionTechnique technique) noexcept;

/**
 * @brief Get debugger type name
 * @param type Debugger type enum value
 * @return Human-readable name
 */
[[nodiscard]] std::string_view GetDebuggerTypeName(DebuggerType type) noexcept;

/**
 * @brief Get confidence level name
 * @param confidence Confidence enum value
 * @return Human-readable name
 */
[[nodiscard]] std::string_view GetConfidenceName(DetectionConfidence confidence) noexcept;

/**
 * @brief Get response action name
 * @param action Response action enum value
 * @return Human-readable name
 */
[[nodiscard]] std::string_view GetResponseActionName(ResponseAction action) noexcept;

/**
 * @brief Get hook type name
 * @param type Hook type enum value
 * @return Human-readable name
 */
[[nodiscard]] std::string_view GetHookTypeName(HookType type) noexcept;

/**
 * @brief Get protection level name
 * @param level Protection level enum value
 * @return Human-readable name
 */
[[nodiscard]] std::string_view GetProtectionLevelName(ProtectionLevel level) noexcept;

// ============================================================================
// RAII HELPERS
// ============================================================================

/**
 * @class ScopedThreadProtection
 * @brief RAII wrapper for thread protection
 *
 * Automatically protects thread on construction and can optionally
 * restore original state on destruction.
 */
class ScopedThreadProtection final {
public:
    /**
     * @brief Construct and protect current thread
     */
    explicit ScopedThreadProtection() noexcept;
    
    /**
     * @brief Construct and protect specified thread
     * @param threadId Thread ID to protect
     */
    explicit ScopedThreadProtection(uint32_t threadId) noexcept;
    
    /// @brief Destructor (no restoration needed for thread hiding)
    ~ScopedThreadProtection() = default;
    
    // Non-copyable
    ScopedThreadProtection(const ScopedThreadProtection&) = delete;
    ScopedThreadProtection& operator=(const ScopedThreadProtection&) = delete;
    
    // Movable
    ScopedThreadProtection(ScopedThreadProtection&&) noexcept = default;
    ScopedThreadProtection& operator=(ScopedThreadProtection&&) noexcept = default;
    
    /**
     * @brief Check if protection was successful
     * @return true if thread is protected
     */
    [[nodiscard]] bool IsProtected() const noexcept { return m_protected; }
    
    /**
     * @brief Get protected thread ID
     * @return Thread ID
     */
    [[nodiscard]] uint32_t GetThreadId() const noexcept { return m_threadId; }

private:
    uint32_t m_threadId = 0;
    bool m_protected = false;
};

/**
 * @class ScopedAntiDebugPause
 * @brief RAII wrapper to pause/resume anti-debug monitoring
 *
 * Useful when performing operations that might trigger false positives.
 */
class ScopedAntiDebugPause final {
public:
    /**
     * @brief Construct and pause anti-debug monitoring
     */
    explicit ScopedAntiDebugPause() noexcept;
    
    /**
     * @brief Destructor - resumes monitoring
     */
    ~ScopedAntiDebugPause() noexcept;
    
    // Non-copyable, non-movable
    ScopedAntiDebugPause(const ScopedAntiDebugPause&) = delete;
    ScopedAntiDebugPause& operator=(const ScopedAntiDebugPause&) = delete;
    ScopedAntiDebugPause(ScopedAntiDebugPause&&) = delete;
    ScopedAntiDebugPause& operator=(ScopedAntiDebugPause&&) = delete;

private:
    bool m_wasPaused = false;
};

/**
 * @class IntegrityGuard
 * @brief RAII wrapper for code integrity protection
 *
 * Registers a code region for integrity monitoring on construction
 * and unregisters on destruction.
 */
class IntegrityGuard final {
public:
    /**
     * @brief Construct and register integrity region
     * @param id Region identifier
     * @param address Start address
     * @param size Region size
     */
    IntegrityGuard(std::string_view id, uintptr_t address, size_t size);
    
    /**
     * @brief Destructor - unregisters region
     */
    ~IntegrityGuard();
    
    // Non-copyable
    IntegrityGuard(const IntegrityGuard&) = delete;
    IntegrityGuard& operator=(const IntegrityGuard&) = delete;
    
    // Movable
    IntegrityGuard(IntegrityGuard&& other) noexcept;
    IntegrityGuard& operator=(IntegrityGuard&& other) noexcept;
    
    /**
     * @brief Check if registration was successful
     * @return true if registered
     */
    [[nodiscard]] bool IsRegistered() const noexcept { return m_registered; }
    
    /**
     * @brief Verify integrity now
     * @return Current integrity status
     */
    [[nodiscard]] IntegrityStatus Verify();
    
    /**
     * @brief Get region ID
     * @return Region identifier
     */
    [[nodiscard]] const std::string& GetId() const noexcept { return m_id; }

private:
    std::string m_id;
    bool m_registered = false;
};

}  // namespace Security
}  // namespace ShadowStrike

// ============================================================================
// MACROS FOR CONVENIENT USAGE
// ============================================================================

/**
 * @brief Quick debugger check macro
 * @return true if debugger detected
 */
#define SS_IS_DEBUGGED() ::ShadowStrike::Security::QuickDebuggerCheck()

/**
 * @brief Protect current thread from debugger
 */
#define SS_PROTECT_THREAD() \
    ::ShadowStrike::Security::ScopedThreadProtection _ss_thread_protection_##__LINE__

/**
 * @brief Pause anti-debug monitoring in current scope
 */
#define SS_PAUSE_ANTIDEBUG() \
    ::ShadowStrike::Security::ScopedAntiDebugPause _ss_antidebug_pause_##__LINE__

/**
 * @brief Register code region for integrity protection
 */
#define SS_PROTECT_CODE(id, addr, size) \
    ::ShadowStrike::Security::IntegrityGuard _ss_integrity_##__LINE__((id), (addr), (size))

/**
 * @brief Anti-debug check with action on detection
 */
#define SS_ANTIDEBUG_CHECK(action) \
    do { \
        if (::ShadowStrike::Security::AntiDebug::Instance().IsDebuggerDetected()) { \
            action; \
        } \
    } while(0)

/**
 * @brief Periodic anti-debug check (only runs every N calls)
 */
#define SS_PERIODIC_ANTIDEBUG_CHECK(interval, action) \
    do { \
        static std::atomic<uint32_t> _ss_check_counter{0}; \
        if ((_ss_check_counter.fetch_add(1) % (interval)) == 0) { \
            if (::ShadowStrike::Security::AntiDebug::Instance().PerformQuickScan().debuggerDetected) { \
                action; \
            } \
        } \
    } while(0)
