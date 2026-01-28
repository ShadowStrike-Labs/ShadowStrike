/**
 * @file DebuggerEvasionDetector.hpp
 * @brief Enterprise-grade detection of anti-debugging and anti-analysis techniques
 *
 * ShadowStrike AntiEvasion - Debugger Evasion Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * This module provides comprehensive detection of anti-debugging techniques used
 * by malware to evade security analysis. It detects 50+ distinct evasion methods
 * across multiple categories including:
 *
 * - PEB-based detection (BeingDebugged, NtGlobalFlag, ProcessHeap flags)
 * - Debug register manipulation (DR0-DR7 hardware breakpoints)
 * - API-level checks (IsDebuggerPresent, CheckRemoteDebuggerPresent, etc.)
 * - Timing-based detection (RDTSC, QueryPerformanceCounter, GetTickCount)
 * - Exception-based detection (INT 2D, INT 3, EXCEPTION_BREAKPOINT handlers)
 * - Object handle tricks (NtQueryInformationProcess, DebugObject presence)
 * - Parent process validation (explorer.exe spoofing detection)
 * - Memory artifact detection (breakpoint opcodes, debug heaps)
 * - Self-debugging techniques (process hollowing with debug attachment)
 * - Anti-attach mechanisms (thread hiding, TLS callbacks)
 * - Kernel-mode checks (NtQuerySystemInformation, KUSER_SHARED_DATA)
 * - Virtualization detection overlap (hypervisor presence via debug)
 *
 * ============================================================================
 * PERFORMANCE TARGETS
 * ============================================================================
 *
 * - Full process analysis: < 50ms for typical process
 * - PEB flag check only: < 1ms
 * - Hardware breakpoint scan: < 5ms per thread
 * - Memory pattern scan: < 100ms for 100MB address space
 * - Batch analysis (100 processes): < 2 seconds
 *
 * ============================================================================
 * INTEGRATION POINTS
 * ============================================================================
 *
 * - Utils::ProcessUtils - Memory reading, thread enumeration, handle queries
 * - Utils::Logger - Structured async logging
 * - SignatureStore - Known anti-debug code pattern matching
 * - ThreatIntel - Correlation with known evasive malware families
 *
 * ============================================================================
 * MITRE ATT&CK COVERAGE
 * ============================================================================
 *
 * - T1622: Debugger Evasion
 * - T1497.001: System Checks (Virtualization/Sandbox Evasion)
 * - T1106: Native API (anti-debug via NTDLL)
 * - T1055: Process Injection (debug-based hollowing detection)
 *
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
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <bitset>
#include <span>
#include <variant>

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
#  pragma comment(lib, "ntdll.lib")
#endif

// Undefine conflicting macros if previously defined
#ifdef HEAP_TAIL_CHECKING_ENABLED
#undef HEAP_TAIL_CHECKING_ENABLED
#endif

#ifdef HEAP_FREE_CHECKING_ENABLED
#undef HEAP_FREE_CHECKING_ENABLED
#endif


// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../Utils/ProcessUtils.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/MemoryUtils.hpp"

// Forward declarations to avoid circular dependencies
namespace ShadowStrike::SignatureStore {
    class SignatureStore;
}

namespace ShadowStrike::ThreatIntel {
    class ThreatIntelStore;
}

namespace ShadowStrike {
    namespace AntiEvasion {

        // ============================================================================
        // CONSTANTS
        // ============================================================================

        namespace Constants {

            /// @brief Maximum threads to scan per process (DoS protection)
            inline constexpr size_t MAX_THREADS_TO_SCAN = 1024;

            /// @brief Maximum memory regions to scan per process
            inline constexpr size_t MAX_MEMORY_REGIONS = 4096;

            /// @brief Maximum process handles to enumerate
            inline constexpr size_t MAX_HANDLES_TO_ENUMERATE = 65536;

            /// @brief Default scan timeout in milliseconds
            inline constexpr uint32_t DEFAULT_SCAN_TIMEOUT_MS = 30000;

            /// @brief Memory pattern scan buffer size
            inline constexpr size_t PATTERN_SCAN_BUFFER_SIZE = 4 * 1024 * 1024; // 4MB

            /// @brief Cache entry TTL for analysis results (seconds)
            inline constexpr uint32_t RESULT_CACHE_TTL_SECONDS = 60;

            /// @brief Maximum cache entries
            inline constexpr size_t MAX_CACHE_ENTRIES = 4096;

            /// @brief High evasion score threshold (0-100)
            inline constexpr double HIGH_EVASION_THRESHOLD = 70.0;

            /// @brief Critical evasion score threshold (0-100)
            inline constexpr double CRITICAL_EVASION_THRESHOLD = 90.0;

            /// @brief Weight multipliers for different technique categories
            inline constexpr double WEIGHT_PEB_TECHNIQUES = 1.5;
            inline constexpr double WEIGHT_TIMING_TECHNIQUES = 2.0;
            inline constexpr double WEIGHT_HARDWARE_BREAKPOINTS = 2.5;
            inline constexpr double WEIGHT_EXCEPTION_TECHNIQUES = 1.8;
            inline constexpr double WEIGHT_API_TECHNIQUES = 1.2;
            inline constexpr double WEIGHT_MEMORY_ARTIFACTS = 1.3;
            inline constexpr double WEIGHT_OBJECT_HANDLE_TECHNIQUES = 1.6;
            inline constexpr double WEIGHT_ADVANCED_TECHNIQUES = 3.0;

            /// @brief NtGlobalFlag values indicating debugging
            inline constexpr uint32_t FLG_HEAP_ENABLE_TAIL_CHECK = 0x10;
            inline constexpr uint32_t FLG_HEAP_ENABLE_FREE_CHECK = 0x20;
            inline constexpr uint32_t FLG_HEAP_VALIDATE_PARAMETERS = 0x40;
            inline constexpr uint32_t FLG_DEBUG_FLAGS_MASK = FLG_HEAP_ENABLE_TAIL_CHECK |
                FLG_HEAP_ENABLE_FREE_CHECK |
                FLG_HEAP_VALIDATE_PARAMETERS;

            /// @brief Heap flags indicating debugging (ForceFlags)
            inline constexpr uint32_t HEAP_TAIL_CHECKING_ENABLED = 0x20;
            inline constexpr uint32_t HEAP_FREE_CHECKING_ENABLED = 0x40;
            inline constexpr uint32_t HEAP_DEBUG_FLAGS_MASK = HEAP_TAIL_CHECKING_ENABLED |
                HEAP_FREE_CHECKING_ENABLED;

            /// @brief Known debugger process names (lowercase for comparison)
            inline constexpr std::array<std::wstring_view, 32> KNOWN_DEBUGGER_PROCESSES = { {
                L"ollydbg.exe", L"x64dbg.exe", L"x32dbg.exe", L"windbg.exe",
                L"idaq.exe", L"idaq64.exe", L"ida.exe", L"ida64.exe",
                L"radare2.exe", L"r2.exe", L"immunity debugger.exe", L"immunitydebugger.exe",
                L"softice.exe", L"devenv.exe", L"dbgview.exe", L"procmon.exe",
                L"procexp.exe", L"procexp64.exe", L"apimonitor.exe", L"apispy32.exe",
                L"wireshark.exe", L"fiddler.exe", L"charles.exe", L"dnspy.exe",
                L"de4dot.exe", L"ilspy.exe", L"dotpeek.exe", L"pestudio.exe",
                L"processhacker.exe", L"cheatengine-x86_64.exe", L"cheatengine.exe", L"hxd.exe"
            } };

            /// @brief Known analysis tool window class names
            inline constexpr std::array<std::wstring_view, 16> KNOWN_DEBUGGER_WINDOW_CLASSES = { {
                L"OLLYDBG", L"x64dbg", L"x32dbg", L"WinDbgFrameClass",
                L"ID", L"IDA", L"Zeta Debugger", L"Rock Debugger",
                L"ObsidianGUI", L"Qt5QWindowIcon", L"SunAwtFrame", L"PROCMON_WINDOW_CLASS",
                L"PROCEXPL", L"ProcessHacker", L"HxD", L"Cheat Engine"
            } };

            /// @brief INT 3 opcode for software breakpoint detection
            inline constexpr uint8_t OPCODE_INT3 = 0xCC;

            /// @brief INT 2D opcode for debug service interrupt
            inline constexpr uint8_t OPCODE_INT2D_PREFIX = 0xCD;
            inline constexpr uint8_t OPCODE_INT2D_SUFFIX = 0x2D;

            /// @brief CPUID hypervisor bit position
            inline constexpr uint32_t CPUID_HYPERVISOR_BIT = (1 << 31);

        } // namespace Constants

        // ============================================================================
        // FORWARD DECLARATIONS
        // ============================================================================

        class DebuggerEvasionDetector;
        class EvasionAnalysisContext;
        struct DebuggerEvasionResult;

        // ============================================================================
        // ENUMERATIONS
        // ============================================================================

        /**
         * @brief Categories of debugger evasion techniques
         *
         * Organized by detection mechanism for prioritized scanning
         */
        enum class EvasionCategory : uint8_t {
            /// @brief Process Environment Block based checks
            PEBBased = 0,

            /// @brief Hardware debug register manipulation
            HardwareDebugRegisters = 1,

            /// @brief Windows API-based detection calls
            APIBased = 2,

            /// @brief Timing attack detection (RDTSC, QPC, etc.)
            TimingBased = 3,

            /// @brief Exception handler manipulation
            ExceptionBased = 4,

            /// @brief Object handle queries
            ObjectHandleBased = 5,

            /// @brief Parent/Child process validation
            ProcessRelationship = 6,

            /// @brief Memory region analysis
            MemoryArtifacts = 7,

            /// @brief Self-debugging/anti-attach
            SelfDebugging = 8,

            /// @brief Thread-based evasion
            ThreadBased = 9,

            /// @brief Kernel-mode information queries
            KernelQueries = 10,

            /// @brief Code integrity checks
            CodeIntegrity = 11,

            /// @brief Multiple techniques combined
            Combined = 12,

            /// @brief Unknown or unclassified
            Unknown = 255
        };

        /**
         * @brief Specific debugger evasion technique identifiers
         *
         * Comprehensive list of 60+ known anti-debugging techniques
         */
        enum class EvasionTechnique : uint16_t {
            // ========================================================================
            // NONE/UNKNOWN (0)
            // ========================================================================
            None = 0,

            // ========================================================================
            // PEB-BASED TECHNIQUES (1-20)
            // ========================================================================

            /// @brief PEB.BeingDebugged flag check
            PEB_BeingDebugged = 1,

            /// @brief PEB.NtGlobalFlag check for debug heap flags
            PEB_NtGlobalFlag = 2,

            /// @brief Process heap Flags/ForceFlags check
            PEB_HeapFlags = 3,

            /// @brief Heap.Flags debug indicator
            PEB_HeapFlagsForceFlags = 4,

            /// @brief PEB.ProcessHeap tail checking
            PEB_HeapTailChecking = 5,

            /// @brief PEB.Ldr module list manipulation
            PEB_LdrModuleList = 6,

            /// @brief PEB.ProcessParameters manipulation
            PEB_ProcessParameters = 7,

            /// @brief PEB.OSMajorVersion checks for emulator detection
            PEB_OSVersionCheck = 8,

            // ========================================================================
            // HARDWARE DEBUG REGISTER TECHNIQUES (21-40)
            // ========================================================================

            /// @brief DR0-DR3 breakpoint register check
            HW_BreakpointRegisters = 21,

            /// @brief DR6 debug status register check
            HW_DebugStatusRegister = 22,

            /// @brief DR7 debug control register check
            HW_DebugControlRegister = 23,

            /// @brief GetThreadContext for debug register inspection
            HW_GetThreadContext = 24,

            /// @brief SetThreadContext debug register clearing
            HW_SetThreadContext = 25,

            /// @brief CONTEXT_DEBUG_REGISTERS enumeration
            HW_ContextDebugEnum = 26,

            // ========================================================================
            // API-BASED TECHNIQUES (41-80)
            // ========================================================================

            /// @brief IsDebuggerPresent API call
            API_IsDebuggerPresent = 41,

            /// @brief CheckRemoteDebuggerPresent API call
            API_CheckRemoteDebuggerPresent = 42,

            /// @brief NtQueryInformationProcess with ProcessDebugPort
            API_NtQueryInformationProcess_DebugPort = 43,

            /// @brief NtQueryInformationProcess with ProcessDebugFlags
            API_NtQueryInformationProcess_DebugFlags = 44,

            /// @brief NtQueryInformationProcess with ProcessDebugObjectHandle
            API_NtQueryInformationProcess_DebugObjectHandle = 45,

            /// @brief NtQuerySystemInformation for debug objects
            API_NtQuerySystemInformation_DebugObject = 46,

            /// @brief NtSetInformationThread with ThreadHideFromDebugger
            API_NtSetInformationThread_HideFromDebugger = 47,

            /// @brief NtCreateThreadEx with THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
            API_NtCreateThreadEx_HideFromDebugger = 48,

            /// @brief NtClose with invalid handle to trigger debug exception
            API_NtClose_InvalidHandle = 49,

            /// @brief OutputDebugString error code check
            API_OutputDebugString_ErrorCheck = 50,

            /// @brief FindWindow for debugger window detection
            API_FindWindow_DebuggerClass = 51,

            /// @brief EnumWindows for analysis tool detection
            API_EnumWindows_AnalysisTools = 52,

            /// @brief GetModuleHandle for debug DLLs
            API_GetModuleHandle_DebugDLL = 53,

            /// @brief BlockInput to prevent analyst interaction
            API_BlockInput = 54,

            /// @brief SuspendThread on debugger threads
            API_SuspendThread_DebuggerThread = 55,

            /// @brief TerminateThread on debugger injection
            API_TerminateThread_DebuggerThread = 56,

            /// @brief ZwSetInformationProcess to detach debugger
            API_ZwSetInformationProcess_Detach = 57,

            /// @brief NtQueryObject for debug object enumeration
            API_NtQueryObject_DebugObject = 58,

            /// @brief RtlQueryProcessHeapInformation for debug heap
            API_RtlQueryProcessHeapInformation = 59,

            /// @brief DbgBreakPoint detection
            API_DbgBreakPoint = 60,

            /// @brief DbgUiRemoteBreakin hook detection
            API_DbgUiRemoteBreakin = 61,

            // ========================================================================
            // TIMING-BASED TECHNIQUES (81-100)
            // ========================================================================

            /// @brief RDTSC instruction timing check
            TIMING_RDTSC = 81,

            /// @brief RDTSCP instruction timing check
            TIMING_RDTSCP = 82,

            /// @brief QueryPerformanceCounter timing check
            TIMING_QueryPerformanceCounter = 83,

            /// @brief GetTickCount timing check
            TIMING_GetTickCount = 84,

            /// @brief GetTickCount64 timing check
            TIMING_GetTickCount64 = 85,

            /// @brief GetLocalTime/GetSystemTime timing check
            TIMING_GetSystemTime = 86,

            /// @brief timeGetTime multimedia timer check
            TIMING_timeGetTime = 87,

            /// @brief NtQueryPerformanceCounter timing check
            TIMING_NtQueryPerformanceCounter = 88,

            /// @brief KUSER_SHARED_DATA timing fields
            TIMING_KUSER_SHARED_DATA = 89,

            /// @brief Sleep/SleepEx timing validation
            TIMING_SleepValidation = 90,

            /// @brief WaitForSingleObject timing validation
            TIMING_WaitValidation = 91,

            // ========================================================================
            // EXCEPTION-BASED TECHNIQUES (101-130)
            // ========================================================================

            /// @brief INT 2D debug service interrupt
            EXCEPTION_INT2D = 101,

            /// @brief INT 3 software breakpoint
            EXCEPTION_INT3 = 102,

            /// @brief INT 1 single-step interrupt
            EXCEPTION_INT1 = 103,

            /// @brief EXCEPTION_BREAKPOINT handler check
            EXCEPTION_BreakpointHandler = 104,

            /// @brief EXCEPTION_SINGLE_STEP handler check
            EXCEPTION_SingleStepHandler = 105,

            /// @brief SetUnhandledExceptionFilter manipulation
            EXCEPTION_UnhandledExceptionFilter = 106,

            /// @brief AddVectoredExceptionHandler chain manipulation
            EXCEPTION_VectoredHandlerChain = 107,

            /// @brief Structured Exception Handling (SEH) chain walk
            EXCEPTION_SEHChainWalk = 108,

            /// @brief EXCEPTION_GUARD_PAGE for memory breakpoints
            EXCEPTION_GuardPage = 109,

            /// @brief EXCEPTION_INVALID_HANDLE for CloseHandle trick
            EXCEPTION_InvalidHandle = 110,

            /// @brief UD2 undefined instruction exception
            EXCEPTION_UD2 = 111,

            /// @brief Prefetch NTA exception handling
            EXCEPTION_PrefetchNTA = 112,

            /// @brief RaiseException with DBG_CONTROL_C
            EXCEPTION_RaiseException_DbgControlC = 113,

            /// @brief RaiseException with DBG_RIPEXCEPTION
            EXCEPTION_RaiseException_RipException = 114,

            /// @brief ICEBP (0xF1) single-step exception
            EXCEPTION_ICEBP = 115,

            // ========================================================================
            // OBJECT HANDLE TECHNIQUES (131-150)
            // ========================================================================

            /// @brief Debug object handle query via NtQueryInformationProcess
            OBJECT_DebugObjectHandle = 131,

            /// @brief Kernel object enumeration for debug objects
            OBJECT_KernelObjectEnum = 132,

            /// @brief Process handle enumeration for debugger handles
            OBJECT_ProcessHandleEnum = 133,

            /// @brief File handle check for debug log files
            OBJECT_FileHandleDebugLog = 134,

            /// @brief Named pipe for debugger communication
            OBJECT_NamedPipeDebugger = 135,

            /// @brief Mailslot for debugger detection
            OBJECT_MailslotDebugger = 136,

            // ========================================================================
            // PROCESS RELATIONSHIP TECHNIQUES (151-170)
            // ========================================================================

            /// @brief Parent process name check (non-explorer.exe)
            PROCESS_ParentNotExplorer = 151,

            /// @brief Parent process is known debugger
            PROCESS_ParentIsDebugger = 152,

            /// @brief Process tree depth analysis
            PROCESS_TreeDepthAnalysis = 153,

            /// @brief Sibling process check for analysis tools
            PROCESS_SiblingAnalysisTools = 154,

            /// @brief Child process monitoring for debug spawning
            PROCESS_ChildDebugSpawning = 155,

            /// @brief CSRSS.exe parent check (process hollowing)
            PROCESS_CSRSSParent = 156,

            /// @brief Windows subsystem process validation
            PROCESS_SubsystemValidation = 157,

            // ========================================================================
            // MEMORY ARTIFACT TECHNIQUES (171-200)
            // ========================================================================

            /// @brief Software breakpoint (0xCC) in code sections
            MEMORY_SoftwareBreakpoints = 171,

            /// @brief Hardware breakpoint trap flag in memory
            MEMORY_HardwareBreakpointTraps = 172,

            /// @brief Debug heap page signatures
            MEMORY_DebugHeapSignatures = 173,

            /// @brief Memory page protection anomalies
            MEMORY_PageProtectionAnomalies = 174,

            /// @brief Injected debugger DLL detection
            MEMORY_InjectedDebuggerDLL = 175,

            /// @brief Code cave analysis for debug stubs
            MEMORY_CodeCaveAnalysis = 176,

            /// @brief API hook detection (inline/IAT/EAT)
            MEMORY_APIHookDetection = 177,

            /// @brief Trampoline code detection
            MEMORY_TrampolineDetection = 178,

            /// @brief Memory mapped debug files
            MEMORY_MappedDebugFiles = 179,

            /// @brief VEH/SEH corruption detection
            MEMORY_ExceptionHandlerCorruption = 180,

            /// @brief NtDll.dll integrity check
            MEMORY_NtDllIntegrity = 181,

            /// @brief Kernel32.dll integrity check
            MEMORY_Kernel32Integrity = 182,

            // ========================================================================
            // SELF-DEBUGGING TECHNIQUES (201-220)
            // ========================================================================

            /// @brief Self-attach via DebugActiveProcess
            SELF_DebugActiveProcess = 201,

            /// @brief Self-debugging via CreateProcess with DEBUG flags
            SELF_CreateProcessDebug = 202,

            /// @brief Anti-attach via already-debugged state
            SELF_AntiAttach = 203,

            /// @brief Debug loop on self
            SELF_DebugLoop = 204,

            /// @brief WaitForDebugEvent self-monitoring
            SELF_WaitForDebugEvent = 205,

            // ========================================================================
            // THREAD-BASED TECHNIQUES (221-240)
            // ========================================================================

            /// @brief TLS callback anti-debug code
            THREAD_TLSCallback = 221,

            /// @brief Thread local storage debug data
            THREAD_TLSDebugData = 222,

            /// @brief Hidden thread creation
            THREAD_HiddenThread = 223,

            /// @brief Thread context manipulation
            THREAD_ContextManipulation = 224,

            /// @brief Thread enumeration for debugger threads
            THREAD_EnumerationDebugger = 225,

            /// @brief Thread priority boost detection
            THREAD_PriorityBoost = 226,

            // ========================================================================
            // KERNEL QUERY TECHNIQUES (241-260)
            // ========================================================================

            /// @brief NtQuerySystemInformation KernelDebugger
            KERNEL_SystemKernelDebugger = 241,

            /// @brief System debug control via NtSystemDebugControl
            KERNEL_SystemDebugControl = 242,

            /// @brief KUSER_SHARED_DATA debug fields
            KERNEL_KUserSharedData = 243,

            /// @brief System boot configuration (bcdedit debug)
            KERNEL_BootConfigDebug = 244,

            /// @brief Driver signing debug mode
            KERNEL_DriverSigningDebug = 245,

            // ========================================================================
            // CODE INTEGRITY TECHNIQUES (261-280)
            // ========================================================================

            /// @brief Code section checksum validation
            CODE_SectionChecksum = 261,

            /// @brief Entry point integrity check
            CODE_EntryPointIntegrity = 262,

            /// @brief Import table hook detection
            CODE_ImportTableHooks = 263,

            /// @brief Export table hook detection
            CODE_ExportTableHooks = 264,

            /// @brief Inline hook detection
            CODE_InlineHooks = 265,

            /// @brief Debug string obfuscation
            CODE_DebugStringObfuscation = 266,

            // ========================================================================
            // ADVANCED/COMBINED TECHNIQUES (281-300)
            // ========================================================================

            /// @brief Multi-technique combined check
            ADVANCED_MultiTechniqueCheck = 281,

            /// @brief Polymorphic anti-debug code
            ADVANCED_PolymorphicAntiDebug = 282,

            /// @brief Encrypted anti-debug payload
            ADVANCED_EncryptedAntiDebug = 283,

            /// @brief VM-exit based detection
            ADVANCED_VMExitDetection = 284,

            /// @brief Hypervisor debug detection
            ADVANCED_HypervisorDebug = 285,

            /// @brief Anti-debug via side-channel
            ADVANCED_SideChannelDetection = 286,

            /// @brief Maximum valid technique ID (for bounds checking)
            _MaxTechniqueId = 300
        };

        /**
         * @brief Severity level of detected evasion technique
         */
        enum class EvasionSeverity : uint8_t {
            /// @brief Informational only (common, possibly legitimate)
            Low = 0,

            /// @brief Moderate concern (suspicious but not definitive)
            Medium = 1,

            /// @brief High concern (strong indicator of evasion intent)
            High = 2,

            /// @brief Critical (definitive evasion, likely malicious)
            Critical = 3
        };

        /**
         * @brief Analysis depth level
         */
        enum class AnalysisDepth : uint8_t {
            /// @brief Quick scan - PEB and basic API checks only
            Quick = 0,

            /// @brief Standard scan - adds timing and exception checks
            Standard = 1,

            /// @brief Deep scan - includes memory artifact analysis
            Deep = 2,

            /// @brief Comprehensive - all techniques including kernel queries
            Comprehensive = 3
        };

        /**
         * @brief Analysis flags for selective technique scanning
         */
        enum class AnalysisFlags : uint32_t {
            None = 0,

            // Category flags
            ScanPEBTechniques = 1 << 0,
            ScanHardwareBreakpoints = 1 << 1,
            ScanAPITechniques = 1 << 2,
            ScanTimingTechniques = 1 << 3,
            ScanExceptionTechniques = 1 << 4,
            ScanObjectHandles = 1 << 5,
            ScanProcessRelationships = 1 << 6,
            ScanMemoryArtifacts = 1 << 7,
            ScanSelfDebugging = 1 << 8,
            ScanThreadTechniques = 1 << 9,
            ScanKernelQueries = 1 << 10,
            ScanCodeIntegrity = 1 << 11,

            // Behavior flags
            EnableCaching = 1 << 16,
            EnableParallelScan = 1 << 17,
            EnableSignatureMatching = 1 << 18,
            EnableThreatIntelCorrelation = 1 << 19,
            StopOnFirstDetection = 1 << 20,
            IncludeDisassembly = 1 << 21,

            // Presets
            QuickScan = ScanPEBTechniques | ScanAPITechniques | EnableCaching,
            StandardScan = QuickScan | ScanHardwareBreakpoints | ScanTimingTechniques |
            ScanExceptionTechniques | ScanProcessRelationships,
            DeepScan = StandardScan | ScanMemoryArtifacts | ScanThreadTechniques |
            ScanObjectHandles | EnableSignatureMatching,
            ComprehensiveScan = 0x0FFF | EnableCaching | EnableParallelScan |
            EnableSignatureMatching | EnableThreatIntelCorrelation,

            /// @brief Default analysis flags
            Default = StandardScan
        };

        // Bitwise operators for AnalysisFlags
        inline constexpr AnalysisFlags operator|(AnalysisFlags a, AnalysisFlags b) noexcept {
            return static_cast<AnalysisFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
        }

        inline constexpr AnalysisFlags operator&(AnalysisFlags a, AnalysisFlags b) noexcept {
            return static_cast<AnalysisFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
        }

        inline constexpr AnalysisFlags operator~(AnalysisFlags a) noexcept {
            return static_cast<AnalysisFlags>(~static_cast<uint32_t>(a));
        }

        inline constexpr bool HasFlag(AnalysisFlags flags, AnalysisFlags flag) noexcept {
            return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(flag)) != 0;
        }

        // ============================================================================
        // UTILITY FUNCTIONS
        // ============================================================================

        /**
         * @brief Get string representation of evasion category
         */
        [[nodiscard]] constexpr const char* EvasionCategoryToString(EvasionCategory category) noexcept {
            switch (category) {
            case EvasionCategory::PEBBased:             return "PEB-Based";
            case EvasionCategory::HardwareDebugRegisters: return "Hardware Debug Registers";
            case EvasionCategory::APIBased:             return "API-Based";
            case EvasionCategory::TimingBased:          return "Timing-Based";
            case EvasionCategory::ExceptionBased:       return "Exception-Based";
            case EvasionCategory::ObjectHandleBased:    return "Object Handle";
            case EvasionCategory::ProcessRelationship:  return "Process Relationship";
            case EvasionCategory::MemoryArtifacts:      return "Memory Artifacts";
            case EvasionCategory::SelfDebugging:        return "Self-Debugging";
            case EvasionCategory::ThreadBased:          return "Thread-Based";
            case EvasionCategory::KernelQueries:        return "Kernel Queries";
            case EvasionCategory::CodeIntegrity:        return "Code Integrity";
            case EvasionCategory::Combined:             return "Combined";
            default:                                    return "Unknown";
            }
        }

        /**
         * @brief Get string representation of evasion technique
         */
        [[nodiscard]] const wchar_t* EvasionTechniqueToString(EvasionTechnique technique) noexcept;

        /**
         * @brief Get MITRE ATT&CK technique ID for evasion technique
         */
        [[nodiscard]] constexpr const char* EvasionTechniqueToMitreId(EvasionTechnique technique) noexcept {
            switch (technique) {
                // Most anti-debug techniques map to T1622
            case EvasionTechnique::PEB_BeingDebugged:
            case EvasionTechnique::PEB_NtGlobalFlag:
            case EvasionTechnique::PEB_HeapFlags:
            case EvasionTechnique::API_IsDebuggerPresent:
            case EvasionTechnique::API_CheckRemoteDebuggerPresent:
            case EvasionTechnique::HW_BreakpointRegisters:
                return "T1622";

                // Timing techniques often relate to sandbox detection
            case EvasionTechnique::TIMING_RDTSC:
            case EvasionTechnique::TIMING_QueryPerformanceCounter:
            case EvasionTechnique::TIMING_GetTickCount:
                return "T1497.003";

                // API abuse techniques
            case EvasionTechnique::API_NtQueryInformationProcess_DebugPort:
            case EvasionTechnique::API_NtSetInformationThread_HideFromDebugger:
                return "T1106";

            default:
                return "T1622";
            }
        }

        /**
         * @brief Get category for a specific technique
         */
        [[nodiscard]] constexpr EvasionCategory GetTechniqueCategory(EvasionTechnique technique) noexcept {
            const auto id = static_cast<uint16_t>(technique);

            if (id >= 1 && id <= 20)    return EvasionCategory::PEBBased;
            if (id >= 21 && id <= 40)   return EvasionCategory::HardwareDebugRegisters;
            if (id >= 41 && id <= 80)   return EvasionCategory::APIBased;
            if (id >= 81 && id <= 100)  return EvasionCategory::TimingBased;
            if (id >= 101 && id <= 130) return EvasionCategory::ExceptionBased;
            if (id >= 131 && id <= 150) return EvasionCategory::ObjectHandleBased;
            if (id >= 151 && id <= 170) return EvasionCategory::ProcessRelationship;
            if (id >= 171 && id <= 200) return EvasionCategory::MemoryArtifacts;
            if (id >= 201 && id <= 220) return EvasionCategory::SelfDebugging;
            if (id >= 221 && id <= 240) return EvasionCategory::ThreadBased;
            if (id >= 241 && id <= 260) return EvasionCategory::KernelQueries;
            if (id >= 261 && id <= 280) return EvasionCategory::CodeIntegrity;
            if (id >= 281 && id <= 300) return EvasionCategory::Combined;

            return EvasionCategory::Unknown;
        }

        /**
         * @brief Get default severity for a technique
         */
        [[nodiscard]] constexpr EvasionSeverity GetDefaultTechniqueSeverity(EvasionTechnique technique) noexcept {
            switch (technique) {
                // Critical techniques (definitive evasion)
            case EvasionTechnique::API_NtSetInformationThread_HideFromDebugger:
            case EvasionTechnique::API_NtCreateThreadEx_HideFromDebugger:
            case EvasionTechnique::SELF_DebugActiveProcess:
            case EvasionTechnique::SELF_AntiAttach:
            case EvasionTechnique::ADVANCED_PolymorphicAntiDebug:
            case EvasionTechnique::ADVANCED_EncryptedAntiDebug:
                return EvasionSeverity::Critical;

                // High severity (strong indicators)
            case EvasionTechnique::HW_BreakpointRegisters:
            case EvasionTechnique::TIMING_RDTSC:
            case EvasionTechnique::EXCEPTION_INT2D:
            case EvasionTechnique::EXCEPTION_ICEBP:
            case EvasionTechnique::MEMORY_APIHookDetection:
            case EvasionTechnique::CODE_SectionChecksum:
            case EvasionTechnique::THREAD_TLSCallback:
                return EvasionSeverity::High;

                // Medium severity (suspicious)
            case EvasionTechnique::PEB_BeingDebugged:
            case EvasionTechnique::PEB_NtGlobalFlag:
            case EvasionTechnique::API_IsDebuggerPresent:
            case EvasionTechnique::API_CheckRemoteDebuggerPresent:
            case EvasionTechnique::PROCESS_ParentIsDebugger:
                return EvasionSeverity::Medium;

                // Low severity (common, possibly legitimate)
            default:
                return EvasionSeverity::Low;
            }
        }

        // ============================================================================
        // DATA STRUCTURES
        // ============================================================================

        /**
         * @brief Error information for detector operations
         */
        struct Error {
            DWORD win32Code = ERROR_SUCCESS;
            LONG ntStatus = 0;
            std::wstring message;
            std::wstring context;

            [[nodiscard]] bool HasError() const noexcept {
                return win32Code != ERROR_SUCCESS || ntStatus != 0;
            }

            void Clear() noexcept {
                win32Code = ERROR_SUCCESS;
                ntStatus = 0;
                message.clear();
                context.clear();
            }

            [[nodiscard]] static Error FromWin32(DWORD code, std::wstring_view ctx = {}) noexcept {
                Error err;
                err.win32Code = code;
                err.context = ctx;
                return err;
            }

            [[nodiscard]] static Error FromNtStatus(LONG status, std::wstring_view ctx = {}) noexcept {
                Error err;
                err.ntStatus = status;
                err.context = ctx;
                return err;
            }
        };

        /**
         * @brief Detailed information about a single detected technique
         */
        struct DetectedTechnique {
            /// @brief Technique identifier
            EvasionTechnique technique = EvasionTechnique::None;

            /// @brief Category of the technique
            EvasionCategory category = EvasionCategory::Unknown;

            /// @brief Severity assessment
            EvasionSeverity severity = EvasionSeverity::Low;

            /// @brief Confidence level (0.0 - 1.0)
            double confidence = 0.0;

            /// @brief Weight contribution to overall score
            double weight = 1.0;

            /// @brief Memory address where technique was found (if applicable)
            uintptr_t address = 0;

            /// @brief Size of the detection artifact (if applicable)
            size_t artifactSize = 0;

            /// @brief Thread ID where detected (if thread-specific)
            uint32_t threadId = 0;

            /// @brief Human-readable description
            std::wstring description;

            /// @brief Technical details (hex dumps, disassembly, etc.)
            std::wstring technicalDetails;

            /// @brief MITRE ATT&CK technique ID
            std::string mitreId;

            /// @brief Raw data snapshot (limited size for evidence)
            std::vector<uint8_t> rawData;

            /// @brief Detection timestamp
            std::chrono::system_clock::time_point detectionTime;

            /// @brief Constructor with defaults
            DetectedTechnique() = default;

            /// @brief Constructor with technique ID
            explicit DetectedTechnique(EvasionTechnique tech) noexcept
                : technique(tech)
                , category(GetTechniqueCategory(tech))
                , severity(GetDefaultTechniqueSeverity(tech))
                , mitreId(EvasionTechniqueToMitreId(tech))
                , detectionTime(std::chrono::system_clock::now())
            {
            }
        };

        /**
         * @brief Statistics from PEB analysis
         */
        struct PEBAnalysisInfo {
            /// @brief PEB base address in target process
            uintptr_t pebAddress = 0;

            /// @brief BeingDebugged flag value
            bool beingDebugged = false;

            /// @brief NtGlobalFlag value
            uint32_t ntGlobalFlag = 0;

            /// @brief ProcessHeap address
            uintptr_t processHeapAddress = 0;

            /// @brief Heap Flags value
            uint32_t heapFlags = 0;

            /// @brief Heap ForceFlags value
            uint32_t heapForceFlags = 0;

            /// @brief Is 64-bit process
            bool is64Bit = false;

            /// @brief Successfully read PEB
            bool valid = false;
        };

        /**
         * @brief Statistics from hardware breakpoint analysis
         */
        struct HardwareBreakpointInfo {
            /// @brief Thread ID analyzed
            uint32_t threadId = 0;

            /// @brief DR0 register value
            uintptr_t dr0 = 0;

            /// @brief DR1 register value
            uintptr_t dr1 = 0;

            /// @brief DR2 register value
            uintptr_t dr2 = 0;

            /// @brief DR3 register value
            uintptr_t dr3 = 0;

            /// @brief DR6 (debug status) register value
            uintptr_t dr6 = 0;

            /// @brief DR7 (debug control) register value
            uintptr_t dr7 = 0;

            /// @brief Number of active breakpoints (DR0-DR3 non-zero)
            uint32_t activeBreakpointCount = 0;

            /// @brief Successfully read context
            bool valid = false;
        };

        /**
         * @brief Memory region information for artifact scanning
         */
        struct MemoryRegionInfo {
            /// @brief Base address of region
            uintptr_t baseAddress = 0;

            /// @brief Size of region
            size_t regionSize = 0;

            /// @brief Memory protection flags
            uint32_t protection = 0;

            /// @brief Memory state (committed, reserved, free)
            uint32_t state = 0;

            /// @brief Memory type (private, mapped, image)
            uint32_t type = 0;

            /// @brief Number of software breakpoints found
            uint32_t softwareBreakpointCount = 0;

            /// @brief Addresses of found breakpoints
            std::vector<uintptr_t> breakpointAddresses;

            /// @brief Is executable region
            bool isExecutable = false;

            /// @brief Is in system DLL
            bool isSystemModule = false;
        };

        /**
         * @brief Parent process analysis information
         */
        struct ParentProcessInfo {
            /// @brief Parent process ID
            uint32_t parentPid = 0;

            /// @brief Parent process name
            std::wstring parentName;

            /// @brief Parent process path
            std::wstring parentPath;

            /// @brief Is parent a known debugger
            bool isKnownDebugger = false;

            /// @brief Is parent explorer.exe (normal)
            bool isExplorer = false;

            /// @brief Is parent cmd.exe or powershell.exe
            bool isCommandShell = false;

            /// @brief Is parent a service host
            bool isServiceHost = false;

            /// @brief Parent analysis successful
            bool valid = false;
        };

        /**
         * @brief Configuration for analysis operations
         */
        struct AnalysisConfig {
            /// @brief Analysis depth level
            AnalysisDepth depth = AnalysisDepth::Standard;

            /// @brief Specific flags for technique selection
            AnalysisFlags flags = AnalysisFlags::Default;

            /// @brief Maximum scan timeout in milliseconds
            uint32_t timeoutMs = Constants::DEFAULT_SCAN_TIMEOUT_MS;

            /// @brief Maximum threads to scan
            size_t maxThreads = Constants::MAX_THREADS_TO_SCAN;

            /// @brief Maximum memory regions to scan
            size_t maxMemoryRegions = Constants::MAX_MEMORY_REGIONS;

            /// @brief Maximum handles to enumerate
            size_t maxHandles = Constants::MAX_HANDLES_TO_ENUMERATE;

            /// @brief Enable result caching
            bool enableCaching = true;

            /// @brief Cache TTL in seconds
            uint32_t cacheTtlSeconds = Constants::RESULT_CACHE_TTL_SECONDS;

            /// @brief Custom debugger process names to check (additional to built-in list)
            std::vector<std::wstring> customDebuggerNames;

            /// @brief Custom window class names to check
            std::vector<std::wstring> customWindowClasses;

            /// @brief Minimum confidence threshold for reporting (0.0 - 1.0)
            double minConfidenceThreshold = 0.5;

            /// @brief Include raw data in detection results
            bool includeRawData = false;

            /// @brief Maximum raw data size per detection
            size_t maxRawDataSize = 256;
        };

        /**
         * @brief Comprehensive analysis result
         */
        struct DebuggerEvasionResult {
            // ========================================================================
            // IDENTIFICATION
            // ========================================================================

            /// @brief Target process ID
            uint32_t targetPid = 0;

            /// @brief Target process name
            std::wstring processName;

            /// @brief Target process path
            std::wstring processPath;

            /// @brief Is 64-bit process
            bool is64Bit = false;

            // ========================================================================
            // DETECTION SUMMARY
            // ========================================================================

            /// @brief Were any evasion techniques detected?
            bool isEvasive = false;

            /// @brief Overall evasion score (0.0 - 100.0)
            double evasionScore = 0.0;

            /// @brief Highest severity detected
            EvasionSeverity maxSeverity = EvasionSeverity::Low;

            /// @brief Total techniques detected
            uint32_t totalDetections = 0;

            /// @brief Categories with detections (bitfield)
            uint32_t detectedCategories = 0;

            // ========================================================================
            // DETAILED FINDINGS
            // ========================================================================

            /// @brief List of all detected techniques with details
            std::vector<DetectedTechnique> detectedTechniques;

            /// @brief PEB analysis results
            PEBAnalysisInfo pebInfo;

            /// @brief Hardware breakpoint info per thread
            std::vector<HardwareBreakpointInfo> hardwareBreakpoints;

            /// @brief Memory regions analyzed
            std::vector<MemoryRegionInfo> memoryRegions;

            /// @brief Parent process information
            ParentProcessInfo parentInfo;

            // ========================================================================
            // STATISTICS
            // ========================================================================

            /// @brief Number of techniques checked
            uint32_t techniquesChecked = 0;

            /// @brief Number of threads scanned
            uint32_t threadsScanned = 0;

            /// @brief Number of memory regions scanned
            uint32_t memoryRegionsScanned = 0;

            /// @brief Number of handles enumerated
            uint32_t handlesEnumerated = 0;

            /// @brief Total bytes scanned for patterns
            uint64_t bytesScanned = 0;

            // ========================================================================
            // TIMING & METADATA
            // ========================================================================

            /// @brief Analysis start time
            std::chrono::system_clock::time_point analysisStartTime;

            /// @brief Analysis end time
            std::chrono::system_clock::time_point analysisEndTime;

            /// @brief Total analysis duration in milliseconds
            uint64_t analysisDurationMs = 0;

            /// @brief Analysis configuration used
            AnalysisConfig config;

            /// @brief Any errors encountered during analysis
            std::vector<Error> errors;

            /// @brief Was analysis completed successfully?
            bool analysisComplete = false;

            /// @brief Was result from cache?
            bool fromCache = false;

            // ========================================================================
            // METHODS
            // ========================================================================

            /**
             * @brief Check if any technique of given category was detected
             */
            [[nodiscard]] bool HasCategory(EvasionCategory category) const noexcept {
                return (detectedCategories & (1u << static_cast<uint32_t>(category))) != 0;
            }

            /**
             * @brief Check if specific technique was detected
             */
            [[nodiscard]] bool HasTechnique(EvasionTechnique technique) const noexcept {
                for (const auto& det : detectedTechniques) {
                    if (det.technique == technique) return true;
                }
                return false;
            }

            /**
             * @brief Get count of techniques in a category
             */
            [[nodiscard]] size_t GetCategoryCount(EvasionCategory category) const noexcept {
                size_t count = 0;
                for (const auto& det : detectedTechniques) {
                    if (det.category == category) ++count;
                }
                return count;
            }

            /**
             * @brief Get detections filtered by severity
             */
            [[nodiscard]] std::vector<const DetectedTechnique*> GetBySeverity(EvasionSeverity minSeverity) const noexcept {
                std::vector<const DetectedTechnique*> filtered;
                for (const auto& det : detectedTechniques) {
                    if (det.severity >= minSeverity) {
                        filtered.push_back(&det);
                    }
                }
                return filtered;
            }

            /**
             * @brief Clear all result data
             */
            void Clear() noexcept {
                targetPid = 0;
                processName.clear();
                processPath.clear();
                is64Bit = false;
                isEvasive = false;
                evasionScore = 0.0;
                maxSeverity = EvasionSeverity::Low;
                totalDetections = 0;
                detectedCategories = 0;
                detectedTechniques.clear();
                pebInfo = {};
                hardwareBreakpoints.clear();
                memoryRegions.clear();
                parentInfo = {};
                techniquesChecked = 0;
                threadsScanned = 0;
                memoryRegionsScanned = 0;
                handlesEnumerated = 0;
                bytesScanned = 0;
                analysisStartTime = {};
                analysisEndTime = {};
                analysisDurationMs = 0;
                config = {};
                errors.clear();
                analysisComplete = false;
                fromCache = false;
            }
        };

        /**
         * @brief Batch analysis result for multiple processes
         */
        struct BatchAnalysisResult {
            /// @brief Individual results per process
            std::vector<DebuggerEvasionResult> results;

            /// @brief Total processes analyzed
            uint32_t totalProcesses = 0;

            /// @brief Processes with evasion detected
            uint32_t evasiveProcesses = 0;

            /// @brief Processes that failed analysis
            uint32_t failedProcesses = 0;

            /// @brief Total analysis time in milliseconds
            uint64_t totalDurationMs = 0;

            /// @brief Batch start time
            std::chrono::system_clock::time_point startTime;

            /// @brief Batch end time
            std::chrono::system_clock::time_point endTime;
        };

        /**
         * @brief Callback for analysis progress notifications
         */
        using AnalysisProgressCallback = std::function<void(
            uint32_t pid,
            EvasionCategory currentCategory,
            uint32_t techniquesChecked,
            uint32_t totalTechniques
            )>;

        /**
         * @brief Callback for detection notifications (real-time)
         */
        using DetectionCallback = std::function<void(
            uint32_t pid,
            const DetectedTechnique& detection
            )>;

        // ============================================================================
        // MAIN DETECTOR CLASS
        // ============================================================================

        /**
         * @brief Enterprise-grade debugger evasion detection engine
         *
         * Provides comprehensive detection of anti-debugging techniques used by malware.
         * Thread-safe for concurrent analysis of multiple processes.
         *
         * @note Requires SeDebugPrivilege for full functionality on protected processes.
         *
         * Usage example:
         * @code
         *     auto detector = std::make_unique<DebuggerEvasionDetector>();
         *     if (!detector->Initialize()) {
         *         // Handle initialization failure
         *     }
         *
         *     AnalysisConfig config;
         *     config.depth = AnalysisDepth::Deep;
         *
         *     auto result = detector->AnalyzeProcess(targetPid, config);
         *     if (result.isEvasive) {
         *         for (const auto& technique : result.detectedTechniques) {
         *             // Process detection
         *         }
         *     }
         * @endcode
         */
        class DebuggerEvasionDetector {
        public:
            // ========================================================================
            // CONSTRUCTION & LIFECYCLE
            // ========================================================================

            /**
             * @brief Default constructor
             */
            DebuggerEvasionDetector() noexcept;

            /**
             * @brief Constructor with optional signature store for pattern matching
             * @param sigStore Signature store for known anti-debug code patterns
             */
            explicit DebuggerEvasionDetector(
                std::shared_ptr<SignatureStore::SignatureStore> sigStore
            ) noexcept;

            /**
             * @brief Constructor with signature store and threat intel
             * @param sigStore Signature store for pattern matching
             * @param threatIntel Threat intel store for correlation
             */
            DebuggerEvasionDetector(
                std::shared_ptr<SignatureStore::SignatureStore> sigStore,
                std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel
            ) noexcept;

            /**
             * @brief Destructor - releases resources and stops any pending operations
             */
            ~DebuggerEvasionDetector();

            // Non-copyable, movable
            DebuggerEvasionDetector(const DebuggerEvasionDetector&) = delete;
            DebuggerEvasionDetector& operator=(const DebuggerEvasionDetector&) = delete;
            DebuggerEvasionDetector(DebuggerEvasionDetector&&) noexcept;
            DebuggerEvasionDetector& operator=(DebuggerEvasionDetector&&) noexcept;

            // ========================================================================
            // INITIALIZATION
            // ========================================================================

            /**
             * @brief Initialize the detector
             * @param err Optional error output
             * @return true on success
             * @note Should be called before any analysis operations
             */
            [[nodiscard]] bool Initialize(Error* err = nullptr) noexcept;

            /**
             * @brief Shutdown and release resources
             */
            void Shutdown() noexcept;

            /**
             * @brief Check if detector is initialized
             */
            [[nodiscard]] bool IsInitialized() const noexcept;

            // ========================================================================
            // SINGLE PROCESS ANALYSIS
            // ========================================================================

            /**
             * @brief Perform full analysis on a process
             * @param processId Target process ID
             * @param config Analysis configuration
             * @param err Optional error output
             * @return Analysis result
             */
            [[nodiscard]] DebuggerEvasionResult AnalyzeProcess(
                uint32_t processId,
                const AnalysisConfig& config = AnalysisConfig{},
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Perform full analysis using process handle
             * @param hProcess Process handle with appropriate access rights
             * @param config Analysis configuration
             * @param err Optional error output
             * @return Analysis result
             */
            [[nodiscard]] DebuggerEvasionResult AnalyzeProcess(
                HANDLE hProcess,
                const AnalysisConfig& config = AnalysisConfig{},
                Error* err = nullptr
            ) noexcept;

            // ========================================================================
            // BATCH ANALYSIS
            // ========================================================================

            /**
             * @brief Analyze multiple processes
             * @param processIds List of process IDs to analyze
             * @param config Analysis configuration
             * @param progressCallback Optional progress callback
             * @param err Optional error output
             * @return Batch analysis result
             */
            [[nodiscard]] BatchAnalysisResult AnalyzeProcesses(
                const std::vector<Utils::ProcessUtils::ProcessId>& processIds,
                const AnalysisConfig& config = AnalysisConfig{},
                AnalysisProgressCallback progressCallback = nullptr,
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze all running processes
             * @param config Analysis configuration
             * @param progressCallback Optional progress callback
             * @param err Optional error output
             * @return Batch analysis result
             */
            [[nodiscard]] BatchAnalysisResult AnalyzeAllProcesses(
                const AnalysisConfig& config = AnalysisConfig{},
                AnalysisProgressCallback progressCallback = nullptr,
                Error* err = nullptr
            ) noexcept;

            // ========================================================================
            // SPECIFIC TECHNIQUE CHECKS
            // ========================================================================

            /**
             * @brief Quick check for PEB-based evasion only
             * @param processId Target process ID
             * @param outPebInfo Output PEB analysis info
             * @param err Optional error output
             * @return true if evasion detected
             */
            [[nodiscard]] bool CheckPEBFlags(
                uint32_t processId,
                PEBAnalysisInfo& outPebInfo,
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Check for hardware breakpoints in all threads
             * @param processId Target process ID
             * @param outBreakpoints Output breakpoint info per thread
             * @param err Optional error output
             * @return true if hardware breakpoints detected
             */
            [[nodiscard]] bool CheckHardwareBreakpoints(
                uint32_t processId,
                std::vector<HardwareBreakpointInfo>& outBreakpoints,
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Check for timing-based evasion code
             * @param processId Target process ID
             * @param outDetections Output detected techniques
             * @param err Optional error output
             * @return true if timing evasion detected
             */
            [[nodiscard]] bool CheckTimingTechniques(
                uint32_t processId,
                std::vector<DetectedTechnique>& outDetections,
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Check for API-based evasion calls
             * @param processId Target process ID
             * @param outDetections Output detected techniques
             * @param err Optional error output
             * @return true if API evasion detected
             */
            [[nodiscard]] bool CheckAPITechniques(
                uint32_t processId,
                std::vector<DetectedTechnique>& outDetections,
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Check for exception-based evasion
             * @param processId Target process ID
             * @param outDetections Output detected techniques
             * @param err Optional error output
             * @return true if exception evasion detected
             */
            [[nodiscard]] bool CheckExceptionTechniques(
                uint32_t processId,
                std::vector<DetectedTechnique>& outDetections,
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Check parent process for debugger indicators
             * @param processId Target process ID
             * @param outParentInfo Output parent process info
             * @param err Optional error output
             * @return true if parent is suspicious
             */
            [[nodiscard]] bool CheckParentProcess(
                uint32_t processId,
                ParentProcessInfo& outParentInfo,
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Scan memory for breakpoint artifacts
             * @param processId Target process ID
             * @param outRegions Output memory region info
             * @param err Optional error output
             * @return true if artifacts detected
             */
            [[nodiscard]] bool ScanMemoryArtifacts(
                uint32_t processId,
                std::vector<MemoryRegionInfo>& outRegions,
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Check for debug object handles
             * @param processId Target process ID
             * @param outDetections Output detected techniques
             * @param err Optional error output
             * @return true if debug objects found
             */
            [[nodiscard]] bool CheckDebugObjectHandles(
                uint32_t processId,
                std::vector<DetectedTechnique>& outDetections,
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Check for self-debugging techniques
             * @param processId Target process ID
             * @param outDetections Output detected techniques
             * @param err Optional error output
             * @return true if self-debugging detected
             */
            [[nodiscard]] bool CheckSelfDebugging(
                uint32_t processId,
                std::vector<DetectedTechnique>& outDetections,
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Check for TLS callback anti-debug code
             * @param processId Target process ID
             * @param outDetections Output detected techniques
             * @param err Optional error output
             * @return true if TLS anti-debug detected
             */
            [[nodiscard]] bool CheckTLSCallbacks(
                uint32_t processId,
                std::vector<DetectedTechnique>& outDetections,
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Check for hidden threads
             * @param processId Target process ID
             * @param outDetections Output detected techniques
             * @param err Optional error output
             * @return true if hidden threads detected
             */
            [[nodiscard]] bool CheckHiddenThreads(
                uint32_t processId,
                std::vector<DetectedTechnique>& outDetections,
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Check for kernel-level debug information
             * @param outDetections Output detected techniques
             * @param err Optional error output
             * @return true if kernel debug mode detected
             */
            [[nodiscard]] bool CheckKernelDebugInfo(
                std::vector<DetectedTechnique>& outDetections,
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Check for API hook detection code
             * @param processId Target process ID
             * @param outDetections Output detected techniques
             * @param err Optional error output
             * @return true if hook detection code found
             */
            [[nodiscard]] bool CheckAPIHookDetection(
                uint32_t processId,
                std::vector<DetectedTechnique>& outDetections,
                Error* err = nullptr
            ) noexcept;

            /**
             * @brief Check for code integrity verification
             * @param processId Target process ID
             * @param outDetections Output detected techniques
             * @param err Optional error output
             * @return true if integrity checks detected
             */
            [[nodiscard]] bool CheckCodeIntegrity(
                uint32_t processId,
                std::vector<DetectedTechnique>& outDetections,
                Error* err = nullptr
            ) noexcept;

            // ========================================================================
            // REAL-TIME DETECTION
            // ========================================================================

            /**
             * @brief Set callback for real-time detection notifications
             * @param callback Callback function
             */
            void SetDetectionCallback(DetectionCallback callback) noexcept;

            /**
             * @brief Clear detection callback
             */
            void ClearDetectionCallback() noexcept;

            // ========================================================================
            // CACHING
            // ========================================================================

            /**
             * @brief Get cached result for a process
             * @param processId Process ID
             * @return Cached result if available and not expired
             */
            [[nodiscard]] std::optional<DebuggerEvasionResult> GetCachedResult(
                uint32_t processId
            ) const noexcept;

            /**
             * @brief Invalidate cached result for a process
             * @param processId Process ID
             */
            void InvalidateCache(uint32_t processId) noexcept;

            /**
             * @brief Clear all cached results
             */
            void ClearCache() noexcept;

            /**
             * @brief Get current cache size
             */
            [[nodiscard]] size_t GetCacheSize() const noexcept;

            // ========================================================================
            // CONFIGURATION
            // ========================================================================

            /**
             * @brief Set signature store for pattern matching
             * @param sigStore Signature store instance
             */
            void SetSignatureStore(
                std::shared_ptr<SignatureStore::SignatureStore> sigStore
            ) noexcept;

            /**
             * @brief Set threat intel store for correlation
             * @param threatIntel Threat intel store instance
             */
            void SetThreatIntelStore(
                std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel
            ) noexcept;

            /**
             * @brief Add custom debugger process name to detection list
             * @param name Process name (case-insensitive)
             */
            void AddCustomDebuggerName(std::wstring_view name) noexcept;

            /**
             * @brief Add custom window class name to detection list
             * @param className Window class name
             */
            void AddCustomWindowClass(std::wstring_view className) noexcept;

            /**
             * @brief Clear custom detection lists
             */
            void ClearCustomDetectionLists() noexcept;

            // ========================================================================
            // STATISTICS
            // ========================================================================

            /**
             * @brief Statistics from detector operations
             */
            struct Statistics {
                /// @brief Total analyses performed
                std::atomic<uint64_t> totalAnalyses{ 0 };

                /// @brief Total evasive processes found
                std::atomic<uint64_t> evasiveProcesses{ 0 };

                /// @brief Total techniques detected
                std::atomic<uint64_t> totalDetections{ 0 };

                /// @brief Cache hits
                std::atomic<uint64_t> cacheHits{ 0 };

                /// @brief Cache misses
                std::atomic<uint64_t> cacheMisses{ 0 };

                /// @brief Analysis errors
                std::atomic<uint64_t> analysisErrors{ 0 };

                /// @brief Total analysis time in microseconds
                std::atomic<uint64_t> totalAnalysisTimeUs{ 0 };

                /// @brief Per-category detection counts
                std::array<std::atomic<uint64_t>, 16> categoryDetections{};

                void Reset() noexcept {
                    totalAnalyses = 0;
                    evasiveProcesses = 0;
                    totalDetections = 0;
                    cacheHits = 0;
                    cacheMisses = 0;
                    analysisErrors = 0;
                    totalAnalysisTimeUs = 0;
                    for (auto& cat : categoryDetections) {
                        cat = 0;
                    }
                }
            };

            /**
             * @brief Get detector statistics
             */
            [[nodiscard]] const Statistics& GetStatistics() const noexcept;

            /**
             * @brief Reset statistics
             */
            void ResetStatistics() noexcept;

        private:
            // ========================================================================
            // INTERNAL IMPLEMENTATION
            // ========================================================================

            /// @brief Implementation details (PIMPL pattern for ABI stability)
            class Impl;
            std::unique_ptr<Impl> m_impl;

            // ========================================================================
            // INTERNAL ANALYSIS METHODS
            // ========================================================================

            /**
             * @brief Core analysis implementation
             */
            void AnalyzeProcessInternal(
                HANDLE hProcess,
                uint32_t processId,
                const AnalysisConfig& config,
                DebuggerEvasionResult& result
            ) noexcept;

            // Internal helpers with HANDLE reuse for performance
            [[nodiscard]] bool CheckTimingTechniquesInternal(
                HANDLE hProcess,
                uint32_t processId,
                std::vector<DetectedTechnique>& outDetections,
                Error* err
            ) noexcept;

            [[nodiscard]] bool CheckExceptionTechniquesInternal(
                HANDLE hProcess,
                uint32_t processId,
                std::vector<DetectedTechnique>& outDetections,
                Error* err
            ) noexcept;

            [[nodiscard]] bool CheckHiddenThreadsInternal(
                HANDLE hProcess,
                uint32_t processId,
                std::vector<DetectedTechnique>& outDetections,
                Error* err
            ) noexcept;

            [[nodiscard]] bool CheckTLSCallbacksInternal(
                HANDLE hProcess,
                uint32_t processId,
                std::vector<DetectedTechnique>& outDetections,
                Error* err
            ) noexcept;

            [[nodiscard]] bool CheckAPIHookDetectionInternal(
                HANDLE hProcess,
                uint32_t processId,
                std::vector<DetectedTechnique>& outDetections,
                Error* err
            ) noexcept;

            /**
             * @brief Analyze PEB structures
             */
            void AnalyzePEB(
                HANDLE hProcess,
                uint32_t processId,
                DebuggerEvasionResult& result
            ) noexcept;

            /**
             * @brief Analyze thread contexts for debug registers
             */
            void AnalyzeThreadContexts(
                uint32_t processId,
                DebuggerEvasionResult& result
            ) noexcept;

            /**
             * @brief Analyze process for API-based evasion
             */
            void AnalyzeAPIUsage(
                HANDLE hProcess,
                uint32_t processId,
                DebuggerEvasionResult& result
            ) noexcept;

            /**
             * @brief Analyze timing-based evasion patterns
             */
            void AnalyzeTimingPatterns(
                HANDLE hProcess,
                uint32_t processId,
                DebuggerEvasionResult& result
            ) noexcept;

            /**
             * @brief Analyze exception handling manipulation
             */
            void AnalyzeExceptionHandling(
                HANDLE hProcess,
                uint32_t processId,
                DebuggerEvasionResult& result
            ) noexcept;

            /**
             * @brief Analyze process handles for debug objects
             */
            void AnalyzeHandles(
                HANDLE hProcess,
                uint32_t processId,
                DebuggerEvasionResult& result
            ) noexcept;

            /**
             * @brief Analyze process relationships
             */
            void AnalyzeProcessRelationships(
                uint32_t processId,
                DebuggerEvasionResult& result
            ) noexcept;

            /**
             * @brief Scan memory for artifacts
             */
            void ScanMemory(
                HANDLE hProcess,
                uint32_t processId,
                DebuggerEvasionResult& result
            ) noexcept;

            /**
             * @brief Analyze thread-based evasion
             */
            void AnalyzeThreads(
                HANDLE hProcess,
                uint32_t processId,
                DebuggerEvasionResult& result
            ) noexcept;

            /**
             * @brief Query kernel debug information
             */
            void QueryKernelDebugInfo(
                DebuggerEvasionResult& result
            ) noexcept;

            /**
             * @brief Analyze code integrity checks
             */
            void AnalyzeCodeIntegrity(
                HANDLE hProcess,
                uint32_t processId,
                DebuggerEvasionResult& result
            ) noexcept;

            /**
             * @brief Calculate final evasion score
             */
            void CalculateEvasionScore(
                DebuggerEvasionResult& result
            ) noexcept;

            /**
             * @brief Add detection to result
             */
            void AddDetection(
                DebuggerEvasionResult& result,
                DetectedTechnique detection
            ) noexcept;

            /**
             * @brief Check if process name matches known debugger
             */
            [[nodiscard]] bool IsKnownDebugger(std::wstring_view processName) const noexcept;

            /**
             * @brief Check if window class matches known debugger
             */
            [[nodiscard]] bool IsKnownDebuggerWindow(std::wstring_view className) const noexcept;

            /**
             * @brief Update cache with result
             */
            void UpdateCache(
                uint32_t processId,
                const DebuggerEvasionResult& result
            ) noexcept;
        };

        // ============================================================================
        // HELPER CLASSES
        // ============================================================================

        /**
         * @brief RAII wrapper for analysis context
         *
         * Manages process handle lifetime and provides convenient access to
         * analysis methods.
         */
        class EvasionAnalysisContext {
        public:
            /**
             * @brief Create context for process
             * @param processId Target process ID
             * @param accessRights Desired process access rights
             */
            explicit EvasionAnalysisContext(
                uint32_t processId,
                DWORD accessRights = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
            ) noexcept;

            /**
             * @brief Destructor - closes process handle
             */
            ~EvasionAnalysisContext();

            // Non-copyable, movable
            EvasionAnalysisContext(const EvasionAnalysisContext&) = delete;
            EvasionAnalysisContext& operator=(const EvasionAnalysisContext&) = delete;
            EvasionAnalysisContext(EvasionAnalysisContext&&) noexcept;
            EvasionAnalysisContext& operator=(EvasionAnalysisContext&&) noexcept;

            /**
             * @brief Check if context is valid
             */
            [[nodiscard]] bool IsValid() const noexcept;

            /**
             * @brief Get process handle
             */
            [[nodiscard]] HANDLE GetHandle() const noexcept;

            /**
             * @brief Get process ID
             */
            [[nodiscard]] uint32_t GetProcessId() const noexcept;

            /**
             * @brief Get process bitness
             */
            [[nodiscard]] bool Is64Bit() const noexcept;

            /**
             * @brief Get last error
             */
            [[nodiscard]] const Error& GetLastError() const noexcept;

            /**
             * @brief Read PEB address
             */
            [[nodiscard]] std::optional<uintptr_t> GetPEBAddress() noexcept;

            /**
             * @brief Read memory from process
             */
            [[nodiscard]] bool ReadMemory(
                uintptr_t address,
                void* buffer,
                size_t size,
                size_t* bytesRead = nullptr
            ) noexcept;

            /**
             * @brief Enumerate threads
             */
            [[nodiscard]] bool EnumerateThreads(
                std::vector<uint32_t>& threadIds
            ) noexcept;

            /**
             * @brief Get thread context
             */
            [[nodiscard]] bool GetThreadContext(
                uint32_t threadId,
                CONTEXT& context,
                DWORD contextFlags = CONTEXT_DEBUG_REGISTERS
            ) noexcept;

        private:
            HANDLE m_hProcess = nullptr;
            uint32_t m_processId = 0;
            bool m_is64Bit = false;
            Error m_lastError;
        };

        /**
         * @brief Utility class for detection pattern building
         */
        class DetectionPatternBuilder {
        public:
            DetectionPatternBuilder() = default;

            /**
             * @brief Set technique
             */
            DetectionPatternBuilder& Technique(EvasionTechnique tech) noexcept {
                m_detection.technique = tech;
                m_detection.category = GetTechniqueCategory(tech);
                m_detection.severity = GetDefaultTechniqueSeverity(tech);
                m_detection.mitreId = EvasionTechniqueToMitreId(tech);
                return *this;
            }

            /**
             * @brief Set confidence
             */
            DetectionPatternBuilder& Confidence(double conf) noexcept {
                m_detection.confidence = conf;
                return *this;
            }

            /**
             * @brief Set address
             */
            DetectionPatternBuilder& Address(uintptr_t addr) noexcept {
                m_detection.address = addr;
                return *this;
            }

            /**
             * @brief Set thread ID
             */
            DetectionPatternBuilder& ThreadId(uint32_t tid) noexcept {
                m_detection.threadId = tid;
                return *this;
            }

            /**
             * @brief Set description
             */
            DetectionPatternBuilder& Description(std::wstring_view desc) noexcept {
                m_detection.description = desc;
                return *this;
            }

            /**
             * @brief Set technical details
             */
            DetectionPatternBuilder& TechnicalDetails(std::wstring_view details) noexcept {
                m_detection.technicalDetails = details;
                return *this;
            }

            /**
             * @brief Override severity
             */
            DetectionPatternBuilder& Severity(EvasionSeverity sev) noexcept {
                m_detection.severity = sev;
                return *this;
            }

            /**
             * @brief Set raw data
             */
            DetectionPatternBuilder& RawData(const uint8_t* data, size_t size) noexcept {
                if (data && size > 0) {
                    m_detection.rawData.assign(data, data + size);
                }
                return *this;
            }

            /**
             * @brief Build the detection
             */
            [[nodiscard]] DetectedTechnique Build() noexcept {
                m_detection.detectionTime = std::chrono::system_clock::now();
                return std::move(m_detection);
            }

        private:
            DetectedTechnique m_detection;
        };

    } // namespace AntiEvasion
} // namespace ShadowStrike