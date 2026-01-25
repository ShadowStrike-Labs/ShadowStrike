/**
 * ============================================================================
 * ShadowStrike Core Process - INJECTION DETECTOR (The Shield)
 * ============================================================================
 *
 * @file ProcessInjectionDetector.hpp
 * @brief Enterprise-grade universal code injection detection.
 *
 * This module provides comprehensive detection of all known code injection
 * techniques used by malware, APTs, and exploit kits. It aggregates findings
 * from specialized detectors and correlates events for high-fidelity alerts.
 *
 * =============================================================================
 * CORE CAPABILITIES
 * =============================================================================
 *
 * 1. **Classic Injection Detection**
 *    - CreateRemoteThread injection
 *    - NtCreateThreadEx injection
 *    - RtlCreateUserThread injection
 *    - Direct syscall injection
 *
 * 2. **APC-Based Injection**
 *    - QueueUserAPC injection
 *    - NtQueueApcThread injection
 *    - Early bird injection
 *    - APC write primitive
 *
 * 3. **Process Manipulation**
 *    - Process hollowing
 *    - Process doppelgänging
 *    - Process herpaderping
 *    - Process ghosting
 *    - Transacted hollowing
 *
 * 4. **DLL Injection**
 *    - LoadLibrary injection
 *    - Reflective DLL injection
 *    - Manual mapping
 *    - Module stomping
 *    - DLL search order hijacking
 *
 * 5. **Advanced Techniques**
 *    - Atom bombing
 *    - Extra window bytes injection
 *    - PROPagate injection
 *    - Ctrl-inject (CTRL+C handler)
 *    - Shim injection
 *    - Thread execution hijacking
 *    - Fiber-based injection
 *
 * 6. **Kernel-Assisted Injection**
 *    - APC callback injection
 *    - System thread injection
 *    - Kernel callback injection
 *
 * =============================================================================
 * DETECTION ARCHITECTURE
 * =============================================================================
 *
 * ```
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                    KERNEL MODE TELEMETRY                                    │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐    │
 * │  │ObRegister   │  │PsSetCreate  │  │PsSetLoad    │  │ETW Thread/     │    │
 * │  │Callbacks    │  │ThreadNotify │  │ImageNotify  │  │Memory Events   │    │
 * │  │(handle mon) │  │(thread mon) │  │(module mon) │  │                │    │
 * │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └───────┬────────┘    │
 * │         │                │                │                 │              │
 * └─────────┼────────────────┼────────────────┼─────────────────┼──────────────┘
 *           │                │                │                 │
 * ══════════╪════════════════╪════════════════╪═════════════════╪══════════════
 *           │                │                │                 │
 * ┌─────────┼────────────────┼────────────────┼─────────────────┼──────────────┐
 * │         ▼                ▼                ▼                 ▼              │
 * │  ┌─────────────────────────────────────────────────────────────────────┐  │
 * │  │                   ProcessInjectionDetector                          │  │
 * │  │                                                                      │  │
 * │  │  ┌────────────────────────────────────────────────────────────┐    │  │
 * │  │  │                    Event Correlator                         │    │  │
 * │  │  │  - Cross-reference handle + memory + thread events          │    │  │
 * │  │  │  - Build injection timeline                                 │    │  │
 * │  │  │  - Identify attacker → victim relationships                 │    │  │
 * │  │  └────────────────────────────────────────────────────────────┘    │  │
 * │  │                                                                      │  │
 * │  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐    │  │
 * │  │  │  Remote    │  │   APC      │  │  Process   │  │   DLL      │    │  │
 * │  │  │  Thread    │  │  Injection │  │  Hollowing │  │ Injection  │    │  │
 * │  │  │  Detector  │  │  Detector  │  │  Detector  │  │ Detector   │    │  │
 * │  │  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘    │  │
 * │  │        │               │               │               │           │  │
 * │  │  ┌─────┴───────────────┴───────────────┴───────────────┴─────┐    │  │
 * │  │  │                   Pattern Matchers                         │    │  │
 * │  │  │  - Memory pattern analysis                                 │    │  │
 * │  │  │  - API call sequence analysis                              │    │  │
 * │  │  │  - Behavioral indicators                                   │    │  │
 * │  │  └───────────────────────────────────────────────────────────┘    │  │
 * │  │                                                                      │  │
 * │  │  ┌───────────────────────────────────────────────────────────┐    │  │
 * │  │  │                   Verdict Engine                           │    │  │
 * │  │  │  - Confidence scoring                                      │    │  │
 * │  │  │  - False positive filtering                                │    │  │
 * │  │  │  - Whitelist checking                                      │    │  │
 * │  │  │  - MITRE ATT&CK mapping                                    │    │  │
 * │  │  └───────────────────────────────────────────────────────────┘    │  │
 * │  │                                                                      │  │
 * │  └─────────────────────────────────────────────────────────────────────┘  │
 * │                                                                            │
 * │                           USER MODE                                        │
 * └────────────────────────────────────────────────────────────────────────────┘
 * ```
 *
 * =============================================================================
 * INJECTION TECHNIQUE MATRIX
 * =============================================================================
 *
 * | Technique                | API Sequence                                   |
 * |--------------------------|------------------------------------------------|
 * | Classic DLL Injection    | OpenProcess→VirtualAllocEx→WriteProcessMemory→|
 * |                          | CreateRemoteThread(LoadLibrary)                |
 * | Reflective DLL           | OpenProcess→VirtualAllocEx→WriteProcessMemory→|
 * |                          | CreateRemoteThread(ReflectiveLoader)           |
 * | Process Hollowing        | CreateProcess(SUSPENDED)→NtUnmapViewOfSection→ |
 * |                          | VirtualAllocEx→WriteProcessMemory→SetContext   |
 * | Thread Hijacking         | OpenThread→SuspendThread→GetContext→SetContext→|
 * |                          | ResumeThread                                   |
 * | APC Injection            | OpenThread→QueueUserAPC→ResumeThread           |
 * | Early Bird               | CreateProcess(SUSPENDED)→QueueUserAPC→Resume   |
 * | Atom Bombing             | GlobalAddAtom→NtQueueApcThread(GlobalGetAtom)  |
 * | Process Doppelgänging    | NtCreateTransaction→CreateFileTransacted→...   |
 *
 * =============================================================================
 * MITRE ATT&CK COVERAGE
 * =============================================================================
 *
 * | Technique | Sub-Technique | Description                                   |
 * |-----------|---------------|-----------------------------------------------|
 * | T1055     | .001          | Dynamic-link Library Injection                |
 * | T1055     | .002          | Portable Executable Injection                 |
 * | T1055     | .003          | Thread Execution Hijacking                    |
 * | T1055     | .004          | Asynchronous Procedure Call                   |
 * | T1055     | .005          | Thread Local Storage                          |
 * | T1055     | .008          | Ptrace System Calls                           |
 * | T1055     | .009          | Proc Memory                                   |
 * | T1055     | .011          | Extra Window Memory Injection                 |
 * | T1055     | .012          | Process Hollowing                             |
 * | T1055     | .013          | Process Doppelgänging                         |
 * | T1055     | .014          | VDSO Hijacking                                |
 * | T1055     | .015          | ListPlanting                                  |
 *
 * @note Thread-safe for all public methods
 * @note Requires kernel driver for comprehensive detection
 *
 * @see MemoryProtection for memory-level detection
 * @see ProcessMonitor for process tracking
 * @see BehaviorAnalyzer for behavioral correlation
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/ProcessUtils.hpp"       // Process context
#include "../../Utils/SystemUtils.hpp"        // System information
#include "../../PatternStore/PatternStore.hpp" // Injection patterns
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // IOC correlation
#include "../../Whitelist/WhiteListStore.hpp" // Trusted processes/modules

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
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

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// Forward declarations
namespace ShadowStrike {
    namespace Utils {
        class ThreadPool;
    }
    namespace Core {
        namespace Engine {
            class BehaviorAnalyzer;
            class ThreatDetector;
        }
    }
    namespace Whitelist {
        class WhitelistStore;
    }
    namespace RealTime {
        class MemoryProtection;
    }
}

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class ProcessInjectionDetector;
struct InjectionEvent;
struct InjectionAlert;
struct InjectionChain;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace InjectionConstants {
    // -------------------------------------------------------------------------
    // Detection Limits
    // -------------------------------------------------------------------------
    
    /// @brief Maximum tracked injection events
    constexpr size_t MAX_INJECTION_EVENTS = 50000;
    
    /// @brief Maximum events per source process
    constexpr size_t MAX_EVENTS_PER_SOURCE = 1000;
    
    /// @brief Event correlation window (seconds)
    constexpr uint32_t CORRELATION_WINDOW_SEC = 30;
    
    /// @brief Maximum injection chain depth
    constexpr size_t MAX_CHAIN_DEPTH = 10;
    
    // -------------------------------------------------------------------------
    // Thresholds
    // -------------------------------------------------------------------------
    
    /// @brief Minimum confidence for alert
    constexpr double MIN_ALERT_CONFIDENCE = 60.0;
    
    /// @brief High confidence threshold
    constexpr double HIGH_CONFIDENCE_THRESHOLD = 85.0;
    
    /// @brief Cross-process handle threshold (suspicious count)
    constexpr size_t SUSPICIOUS_HANDLE_THRESHOLD = 10;
    
    // -------------------------------------------------------------------------
    // Risk Scores
    // -------------------------------------------------------------------------
    
    /// @brief Remote thread injection score
    constexpr double REMOTE_THREAD_SCORE = 70.0;
    
    /// @brief APC injection score
    constexpr double APC_INJECTION_SCORE = 75.0;
    
    /// @brief Process hollowing score
    constexpr double PROCESS_HOLLOWING_SCORE = 95.0;
    
    /// @brief Reflective DLL injection score
    constexpr double REFLECTIVE_DLL_SCORE = 90.0;
    
    /// @brief Atom bombing score
    constexpr double ATOM_BOMBING_SCORE = 85.0;
    
    /// @brief Thread hijacking score
    constexpr double THREAD_HIJACKING_SCORE = 80.0;
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Injection technique type.
 */
enum class InjectionType : uint16_t {
    /// @brief Unknown injection
    Unknown = 0,
    
    // -------------------------------------------------------------------------
    // Thread-Based Injection
    // -------------------------------------------------------------------------
    
    /// @brief CreateRemoteThread injection
    RemoteThread = 1,
    
    /// @brief NtCreateThreadEx injection
    NtCreateThreadEx = 2,
    
    /// @brief RtlCreateUserThread injection
    RtlCreateUserThread = 3,
    
    /// @brief Direct syscall thread creation
    DirectSyscallThread = 4,
    
    // -------------------------------------------------------------------------
    // APC-Based Injection
    // -------------------------------------------------------------------------
    
    /// @brief QueueUserAPC injection
    APC = 10,
    
    /// @brief NtQueueApcThread injection
    NtQueueApcThread = 11,
    
    /// @brief Early bird APC injection
    EarlyBird = 12,
    
    /// @brief APC write primitive
    APCWritePrimitive = 13,
    
    // -------------------------------------------------------------------------
    // Process Manipulation
    // -------------------------------------------------------------------------
    
    /// @brief Process hollowing
    ProcessHollowing = 20,
    
    /// @brief Process doppelgänging
    ProcessDoppelganging = 21,
    
    /// @brief Process herpaderping
    ProcessHerpaderping = 22,
    
    /// @brief Process ghosting
    ProcessGhosting = 23,
    
    /// @brief Transacted hollowing
    TransactedHollowing = 24,
    
    /// @brief Process reimaging
    ProcessReimaging = 25,
    
    // -------------------------------------------------------------------------
    // DLL Injection
    // -------------------------------------------------------------------------
    
    /// @brief Classic DLL injection (LoadLibrary)
    DLLInjection = 30,
    
    /// @brief Reflective DLL injection
    ReflectiveDLL = 31,
    
    /// @brief Manual mapping injection
    ManualMapping = 32,
    
    /// @brief Module stomping
    ModuleStomping = 33,
    
    /// @brief DLL search order hijacking
    DLLSearchOrderHijack = 34,
    
    /// @brief DLL side-loading
    DLLSideLoading = 35,
    
    // -------------------------------------------------------------------------
    // Memory-Based Injection
    // -------------------------------------------------------------------------
    
    /// @brief Shellcode injection
    ShellcodeInjection = 40,
    
    /// @brief PE injection
    PEInjection = 41,
    
    /// @brief .NET assembly injection
    DotNetInjection = 42,
    
    // -------------------------------------------------------------------------
    // Advanced Techniques
    // -------------------------------------------------------------------------
    
    /// @brief Atom bombing
    AtomBombing = 50,
    
    /// @brief Extra window bytes injection
    ExtraWindowBytes = 51,
    
    /// @brief PROPagate injection
    PROPagate = 52,
    
    /// @brief Ctrl-inject (CTRL+C handler)
    CtrlInject = 53,
    
    /// @brief Shim injection
    ShimInjection = 54,
    
    /// @brief Thread execution hijacking
    ThreadHijacking = 55,
    
    /// @brief Fiber-based injection
    FiberInjection = 56,
    
    /// @brief Callback injection (TLS, DLL_PROCESS_ATTACH)
    CallbackInjection = 57,
    
    /// @brief NtMapViewOfSection injection
    SectionMapping = 58,
    
    /// @brief Windows hook injection (SetWindowsHookEx)
    SetWindowsHook = 59,
    
    // -------------------------------------------------------------------------
    // Registry/COM-Based
    // -------------------------------------------------------------------------
    
    /// @brief COM hijacking
    COMHijacking = 60,
    
    /// @brief AppInit_DLLs injection
    AppInitDLLs = 61,
    
    /// @brief Image File Execution Options
    IFEO = 62,
    
    // -------------------------------------------------------------------------
    // Kernel-Assisted
    // -------------------------------------------------------------------------
    
    /// @brief Kernel APC injection
    KernelAPC = 70,
    
    /// @brief System thread injection
    SystemThread = 71
};

/**
 * @brief Injection detection stage.
 */
enum class InjectionStage : uint8_t {
    /// @brief Unknown stage
    Unknown = 0,
    
    /// @brief Handle acquisition
    HandleAcquisition = 1,
    
    /// @brief Memory allocation
    MemoryAllocation = 2,
    
    /// @brief Memory write
    MemoryWrite = 3,
    
    /// @brief Protection change
    ProtectionChange = 4,
    
    /// @brief Execution trigger
    ExecutionTrigger = 5,
    
    /// @brief Code execution
    CodeExecution = 6,
    
    /// @brief Post-injection activity
    PostInjection = 7
};

/**
 * @brief Injection detection verdict.
 */
enum class InjectionVerdict : uint8_t {
    /// @brief Clean (no injection)
    Clean = 0,
    
    /// @brief Suspicious (possible injection)
    Suspicious = 1,
    
    /// @brief Injection detected
    Detected = 2,
    
    /// @brief Confirmed injection (high confidence)
    Confirmed = 3,
    
    /// @brief Blocked (prevented)
    Blocked = 4,
    
    /// @brief Whitelisted
    Whitelisted = 5,
    
    /// @brief Unknown
    Unknown = 6
};

/**
 * @brief Injection source classification.
 */
enum class InjectorType : uint8_t {
    /// @brief Unknown
    Unknown = 0,
    
    /// @brief Legitimate software (debugger, AV)
    Legitimate = 1,
    
    /// @brief Potentially unwanted
    PUP = 2,
    
    /// @brief Malware
    Malware = 3,
    
    /// @brief Exploit
    Exploit = 4,
    
    /// @brief APT/targeted
    APT = 5
};

/**
 * @brief Get string for InjectionType.
 */
[[nodiscard]] constexpr const char* InjectionTypeToString(InjectionType type) noexcept;

/**
 * @brief Get MITRE ATT&CK sub-technique for injection type.
 */
[[nodiscard]] constexpr const char* InjectionTypeToMitre(InjectionType type) noexcept;

/**
 * @brief Get typical API sequence for injection type.
 */
[[nodiscard]] const char* InjectionTypeToAPISequence(InjectionType type) noexcept;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief Handle access event.
 */
struct HandleAccessEvent {
    /// @brief Event timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Source process ID
    uint32_t sourceProcessId = 0;
    
    /// @brief Target process ID
    uint32_t targetProcessId = 0;
    
    /// @brief Desired access rights
    uint32_t desiredAccess = 0;
    
    /// @brief Granted access rights
    uint32_t grantedAccess = 0;
    
    /// @brief Handle value
    uint64_t handleValue = 0;
    
    /// @brief Has PROCESS_VM_WRITE
    bool hasVMWrite = false;
    
    /// @brief Has PROCESS_VM_OPERATION
    bool hasVMOperation = false;
    
    /// @brief Has PROCESS_CREATE_THREAD
    bool hasCreateThread = false;
    
    /// @brief Has PROCESS_DUP_HANDLE
    bool hasDupHandle = false;
};

/**
 * @brief Memory operation event.
 */
struct MemoryOperationEvent {
    /// @brief Event timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Operation type
    enum class OpType : uint8_t {
        Allocate,
        Free,
        Protect,
        Write,
        Map,
        Unmap
    } operation = OpType::Allocate;
    
    /// @brief Source process ID
    uint32_t sourceProcessId = 0;
    
    /// @brief Target process ID
    uint32_t targetProcessId = 0;
    
    /// @brief Base address
    uintptr_t baseAddress = 0;
    
    /// @brief Region size
    size_t regionSize = 0;
    
    /// @brief Old protection
    uint32_t oldProtection = 0;
    
    /// @brief New protection
    uint32_t newProtection = 0;
    
    /// @brief Allocation type
    uint32_t allocationType = 0;
    
    /// @brief Is cross-process
    bool isCrossProcess = false;
    
    /// @brief Data hash (for write operations)
    std::string dataHash;
    
    /// @brief Data preview
    std::vector<uint8_t> dataPreview;
};

/**
 * @brief Thread operation event.
 */
struct ThreadOperationEvent {
    /// @brief Event timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Operation type
    enum class OpType : uint8_t {
        Create,
        Terminate,
        Suspend,
        Resume,
        SetContext,
        QueueAPC
    } operation = OpType::Create;
    
    /// @brief Source process ID
    uint32_t sourceProcessId = 0;
    
    /// @brief Target process ID
    uint32_t targetProcessId = 0;
    
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Start address (for create)
    uintptr_t startAddress = 0;
    
    /// @brief Parameter (for create)
    uintptr_t parameter = 0;
    
    /// @brief APC routine (for queue APC)
    uintptr_t apcRoutine = 0;
    
    /// @brief Is remote thread
    bool isRemote = false;
    
    /// @brief Is suspended start
    bool isSuspended = false;
    
    /// @brief Start address module
    std::wstring startAddressModule;
};

/**
 * @brief Injection event (aggregated).
 */
struct InjectionEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Detection timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Injection type
    InjectionType injectionType = InjectionType::Unknown;
    
    /// @brief Detection stage
    InjectionStage stage = InjectionStage::Unknown;
    
    /// @brief Source (attacker) process ID
    uint32_t sourceProcessId = 0;
    
    /// @brief Source process name
    std::wstring sourceProcessName;
    
    /// @brief Source process path
    std::wstring sourceProcessPath;
    
    /// @brief Target (victim) process ID
    uint32_t targetProcessId = 0;
    
    /// @brief Target process name
    std::wstring targetProcessName;
    
    /// @brief Target process path
    std::wstring targetProcessPath;
    
    /// @brief Target thread ID (if applicable)
    uint32_t targetThreadId = 0;
    
    /// @brief Target address
    uintptr_t targetAddress = 0;
    
    /// @brief Injected data size
    size_t dataSize = 0;
    
    /// @brief Injected module path (if DLL injection)
    std::wstring injectedModulePath;
    
    /// @brief Start address (for thread creation)
    uintptr_t startAddress = 0;
    
    /// @brief Start address is in legitimate module
    bool startAddressLegitimate = true;
    
    /// @brief Confidence score (0-100)
    double confidence = 0.0;
    
    /// @brief Risk score (0-100)
    double riskScore = 0.0;
    
    /// @brief Verdict
    InjectionVerdict verdict = InjectionVerdict::Unknown;
    
    /// @brief Was blocked
    bool blocked = false;
    
    /// @brief MITRE technique
    std::string mitreTechnique;
    
    /// @brief MITRE sub-technique
    std::string mitreSubTechnique;
    
    /// @brief Related handle events
    std::vector<HandleAccessEvent> handleEvents;
    
    /// @brief Related memory events
    std::vector<MemoryOperationEvent> memoryEvents;
    
    /// @brief Related thread events
    std::vector<ThreadOperationEvent> threadEvents;
    
    /// @brief Evidence data
    std::vector<uint8_t> evidence;
    
    /// @brief Additional context
    std::map<std::string, std::wstring> context;
};

/**
 * @brief Injection alert.
 */
struct InjectionAlert {
    /// @brief Alert ID
    uint64_t alertId = 0;
    
    /// @brief Alert timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Source process ID
    uint32_t sourceProcessId = 0;
    
    /// @brief Source process name
    std::wstring sourceProcessName;
    
    /// @brief Target process ID
    uint32_t targetProcessId = 0;
    
    /// @brief Target process name
    std::wstring targetProcessName;
    
    /// @brief Injection type
    InjectionType injectionType = InjectionType::Unknown;
    
    /// @brief Verdict
    InjectionVerdict verdict = InjectionVerdict::Unknown;
    
    /// @brief Confidence
    double confidence = 0.0;
    
    /// @brief Risk score
    double riskScore = 0.0;
    
    /// @brief Was blocked
    bool blocked = false;
    
    /// @brief Alert details
    std::wstring details;
    
    /// @brief MITRE technique
    std::string mitreTechnique;
    
    /// @brief Injector classification
    InjectorType injectorType = InjectorType::Unknown;
    
    /// @brief Related events
    std::vector<uint64_t> relatedEventIds;
};

/**
 * @brief Injection chain (multi-hop injection).
 */
struct InjectionChain {
    /// @brief Chain ID
    uint64_t chainId = 0;
    
    /// @brief Chain start timestamp
    std::chrono::system_clock::time_point startTime{};
    
    /// @brief Chain end timestamp
    std::chrono::system_clock::time_point endTime{};
    
    /// @brief Initial attacker process ID
    uint32_t initialAttackerPid = 0;
    
    /// @brief Initial attacker name
    std::wstring initialAttackerName;
    
    /// @brief Final victim process ID
    uint32_t finalVictimPid = 0;
    
    /// @brief Final victim name
    std::wstring finalVictimName;
    
    /// @brief Chain depth
    size_t depth = 0;
    
    /// @brief Chain path (PIDs)
    std::vector<uint32_t> chainPath;
    
    /// @brief Injection events in chain
    std::vector<InjectionEvent> events;
    
    /// @brief Total risk score
    double totalRiskScore = 0.0;
};

/**
 * @brief Process injection state.
 */
struct ProcessInjectionState {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Is currently being injected into
    bool isBeingInjected = false;
    
    /// @brief Has been injected
    bool hasBeenInjected = false;
    
    /// @brief Is actively injecting others
    bool isInjecting = false;
    
    /// @brief Injection events targeting this process
    std::vector<uint64_t> incomingInjectionIds;
    
    /// @brief Injection events from this process
    std::vector<uint64_t> outgoingInjectionIds;
    
    /// @brief Cross-process handles opened by this process
    std::vector<HandleAccessEvent> crossProcessHandles;
    
    /// @brief Remote memory operations
    std::vector<MemoryOperationEvent> remoteMemoryOps;
    
    /// @brief Remote thread operations
    std::vector<ThreadOperationEvent> remoteThreadOps;
    
    /// @brief Total injections detected (as target)
    uint32_t totalInjectionsAsTarget = 0;
    
    /// @brief Total injections detected (as source)
    uint32_t totalInjectionsAsSource = 0;
    
    /// @brief Risk score
    double riskScore = 0.0;
    
    /// @brief First activity timestamp
    std::chrono::system_clock::time_point firstActivity{};
    
    /// @brief Last activity timestamp
    std::chrono::system_clock::time_point lastActivity{};
};

/**
 * @brief Configuration for injection detector.
 */
struct InjectionDetectorConfig {
    // -------------------------------------------------------------------------
    // General Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable detection
    bool enabled = true;
    
    /// @brief Enable blocking
    bool blockInjections = true;
    
    /// @brief Enable correlation
    bool enableCorrelation = true;
    
    /// @brief Enable chain detection
    bool detectChains = true;
    
    // -------------------------------------------------------------------------
    // Detection Settings
    // -------------------------------------------------------------------------
    
    /// @brief Detect remote thread injection
    bool detectRemoteThread = true;
    
    /// @brief Detect APC injection
    bool detectAPC = true;
    
    /// @brief Detect process hollowing
    bool detectHollowing = true;
    
    /// @brief Detect reflective DLL
    bool detectReflectiveDLL = true;
    
    /// @brief Detect atom bombing
    bool detectAtomBombing = true;
    
    /// @brief Detect all other techniques
    bool detectAdvanced = true;
    
    // -------------------------------------------------------------------------
    // Threshold Settings
    // -------------------------------------------------------------------------
    
    /// @brief Minimum confidence to alert
    double alertConfidence = InjectionConstants::MIN_ALERT_CONFIDENCE;
    
    /// @brief Minimum confidence to block
    double blockConfidence = InjectionConstants::HIGH_CONFIDENCE_THRESHOLD;
    
    /// @brief Correlation window (seconds)
    uint32_t correlationWindowSec = InjectionConstants::CORRELATION_WINDOW_SEC;
    
    // -------------------------------------------------------------------------
    // Trust Settings
    // -------------------------------------------------------------------------
    
    /// @brief Trust Microsoft signed injectors
    bool trustMicrosoftSigned = true;
    
    /// @brief Trust whitelisted processes
    bool trustWhitelisted = true;
    
    /// @brief Trusted injector signers
    std::vector<std::wstring> trustedSigners;
    
    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Create default configuration.
     */
    [[nodiscard]] static InjectionDetectorConfig CreateDefault() noexcept {
        return InjectionDetectorConfig{};
    }
    
    /**
     * @brief Create strict configuration.
     */
    [[nodiscard]] static InjectionDetectorConfig CreateStrict() noexcept {
        InjectionDetectorConfig config;
        config.alertConfidence = 40.0;
        config.blockConfidence = 60.0;
        config.trustMicrosoftSigned = false;
        return config;
    }
    
    /**
     * @brief Create monitor-only configuration.
     */
    [[nodiscard]] static InjectionDetectorConfig CreateMonitorOnly() noexcept {
        InjectionDetectorConfig config;
        config.blockInjections = false;
        config.blockConfidence = 100.0;  // Never block
        return config;
    }
};

/**
 * @brief Injection detector statistics.
 */
struct InjectionDetectorStats {
    /// @brief Total events processed
    std::atomic<uint64_t> totalEvents{ 0 };
    
    /// @brief Handle events processed
    std::atomic<uint64_t> handleEvents{ 0 };
    
    /// @brief Memory events processed
    std::atomic<uint64_t> memoryEvents{ 0 };
    
    /// @brief Thread events processed
    std::atomic<uint64_t> threadEvents{ 0 };
    
    /// @brief Injections detected
    std::atomic<uint64_t> injectionsDetected{ 0 };
    
    /// @brief Injections blocked
    std::atomic<uint64_t> injectionsBlocked{ 0 };
    
    /// @brief Remote threads detected
    std::atomic<uint64_t> remoteThreadsDetected{ 0 };
    
    /// @brief APC injections detected
    std::atomic<uint64_t> apcInjectionsDetected{ 0 };
    
    /// @brief Process hollowing detected
    std::atomic<uint64_t> hollowingDetected{ 0 };
    
    /// @brief Reflective DLL detected
    std::atomic<uint64_t> reflectiveDLLDetected{ 0 };
    
    /// @brief Injection chains detected
    std::atomic<uint64_t> chainsDetected{ 0 };
    
    /// @brief False positives suppressed
    std::atomic<uint64_t> falsePositivesSuppressed{ 0 };
    
    /// @brief Processes currently tracked
    std::atomic<size_t> trackedProcesses{ 0 };
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept {
        totalEvents.store(0, std::memory_order_relaxed);
        handleEvents.store(0, std::memory_order_relaxed);
        memoryEvents.store(0, std::memory_order_relaxed);
        threadEvents.store(0, std::memory_order_relaxed);
        injectionsDetected.store(0, std::memory_order_relaxed);
        injectionsBlocked.store(0, std::memory_order_relaxed);
        remoteThreadsDetected.store(0, std::memory_order_relaxed);
        apcInjectionsDetected.store(0, std::memory_order_relaxed);
        hollowingDetected.store(0, std::memory_order_relaxed);
        reflectiveDLLDetected.store(0, std::memory_order_relaxed);
        chainsDetected.store(0, std::memory_order_relaxed);
        falsePositivesSuppressed.store(0, std::memory_order_relaxed);
        trackedProcesses.store(0, std::memory_order_relaxed);
    }
};

/**
 * @brief Callback types.
 */
using InjectionCallback = std::function<InjectionVerdict(const InjectionEvent&)>;
using InjectionAlertCallback = std::function<void(const InjectionAlert&)>;
using InjectionChainCallback = std::function<void(const InjectionChain&)>;
using HandleAccessCallback = std::function<bool(const HandleAccessEvent&)>;

// ============================================================================
// MAIN PROCESS INJECTION DETECTOR CLASS
// ============================================================================

/**
 * @brief Enterprise-grade universal code injection detection.
 *
 * Provides comprehensive detection of all known code injection techniques
 * with event correlation and chain detection.
 *
 * Thread Safety: All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& detector = ProcessInjectionDetector::Instance();
 * 
 * // Initialize
 * InjectionDetectorConfig config = InjectionDetectorConfig::CreateDefault();
 * detector.Initialize(threadPool, config);
 * 
 * // Set integrations
 * detector.SetWhitelistStore(&WhitelistStore::Instance());
 * detector.SetBehaviorAnalyzer(&BehaviorAnalyzer::Instance());
 * 
 * // Register callbacks
 * detector.RegisterAlertCallback([](const InjectionAlert& alert) {
 *     LOG_ALERT("Injection detected: {} -> {} ({})",
 *               alert.sourceProcessName, alert.targetProcessName,
 *               InjectionTypeToString(alert.injectionType));
 * });
 * 
 * // Start detection
 * detector.Start();
 * 
 * // Check if process is injected
 * if (detector.IsProcessInjected(targetPid)) {
 *     LOG_WARN("Process {} shows signs of injection", targetPid);
 * }
 * 
 * // Get injection state
 * auto state = detector.GetProcessState(targetPid);
 * if (state && state->hasBeenInjected) {
 *     LOG_INFO("Process was injected {} times", state->totalInjectionsAsTarget);
 * }
 * 
 * detector.Stop();
 * detector.Shutdown();
 * @endcode
 */
class ProcessInjectionDetector {
public:
    // =========================================================================
    // Singleton Access
    // =========================================================================

    /**
     * @brief Get the singleton instance.
     */
    [[nodiscard]] static ProcessInjectionDetector& Instance();

    // Non-copyable, non-movable
    ProcessInjectionDetector(const ProcessInjectionDetector&) = delete;
    ProcessInjectionDetector& operator=(const ProcessInjectionDetector&) = delete;
    ProcessInjectionDetector(ProcessInjectionDetector&&) = delete;
    ProcessInjectionDetector& operator=(ProcessInjectionDetector&&) = delete;

    // =========================================================================
    // Lifecycle Management
    // =========================================================================

    /**
     * @brief Initialize the detector.
     */
    [[nodiscard]] bool Initialize();

    /**
     * @brief Initialize with thread pool.
     */
    [[nodiscard]] bool Initialize(std::shared_ptr<Utils::ThreadPool> threadPool);

    /**
     * @brief Initialize with configuration.
     */
    [[nodiscard]] bool Initialize(
        std::shared_ptr<Utils::ThreadPool> threadPool,
        const InjectionDetectorConfig& config
    );

    /**
     * @brief Shutdown the detector.
     */
    void Shutdown();

    /**
     * @brief Start detection.
     */
    void Start();

    /**
     * @brief Stop detection.
     */
    void Stop();

    /**
     * @brief Check if detector is running.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    /**
     * @brief Update configuration.
     */
    void UpdateConfig(const InjectionDetectorConfig& config);

    /**
     * @brief Get current configuration.
     */
    [[nodiscard]] InjectionDetectorConfig GetConfig() const;

    // =========================================================================
    // Event Handlers
    // =========================================================================

    /**
     * @brief Handle handle access event.
     * @return true if should allow, false to block.
     */
    [[nodiscard]] bool OnHandleAccess(const HandleAccessEvent& event);

    /**
     * @brief Handle memory operation event.
     */
    void OnMemoryOperation(const MemoryOperationEvent& event);

    /**
     * @brief Handle thread operation event.
     * @return true if should allow, false to block.
     */
    [[nodiscard]] bool OnThreadOperation(const ThreadOperationEvent& event);

    /**
     * @brief Analyze a cross-process event (simplified).
     */
    void AnalyzeEvent(
        uint32_t sourceProcessId,
        uint32_t targetProcessId,
        InjectionType type
    );

    // =========================================================================
    // Query
    // =========================================================================

    /**
     * @brief Check if process shows signs of injection.
     */
    [[nodiscard]] bool IsProcessInjected(uint32_t pid) const;

    /**
     * @brief Check if process is actively injecting.
     */
    [[nodiscard]] bool IsProcessInjecting(uint32_t pid) const;

    /**
     * @brief Get injection state for process.
     */
    [[nodiscard]] std::optional<ProcessInjectionState> GetProcessState(uint32_t pid) const;

    /**
     * @brief Get injection events for process (as target).
     */
    [[nodiscard]] std::vector<InjectionEvent> GetInjectionsInto(uint32_t pid) const;

    /**
     * @brief Get injection events from process (as source).
     */
    [[nodiscard]] std::vector<InjectionEvent> GetInjectionsFrom(uint32_t pid) const;

    /**
     * @brief Get recent injection alerts.
     */
    [[nodiscard]] std::vector<InjectionAlert> GetRecentAlerts(size_t count = 100) const;

    /**
     * @brief Get injection chains.
     */
    [[nodiscard]] std::vector<InjectionChain> GetInjectionChains() const;

    /**
     * @brief Get all tracked processes.
     */
    [[nodiscard]] std::vector<uint32_t> GetTrackedProcesses() const;

    // =========================================================================
    // Analysis
    // =========================================================================

    /**
     * @brief Analyze process for injection indicators.
     */
    [[nodiscard]] InjectionVerdict AnalyzeProcess(uint32_t pid);

    /**
     * @brief Detect injection type from indicators.
     */
    [[nodiscard]] InjectionType ClassifyInjection(
        const std::vector<HandleAccessEvent>& handleEvents,
        const std::vector<MemoryOperationEvent>& memoryEvents,
        const std::vector<ThreadOperationEvent>& threadEvents
    ) const;

    /**
     * @brief Calculate injection confidence.
     */
    [[nodiscard]] double CalculateConfidence(
        InjectionType type,
        const InjectionEvent& event
    ) const;

    /**
     * @brief Check for injection chain.
     */
    [[nodiscard]] std::optional<InjectionChain> DetectChain(uint32_t startPid) const;

    // =========================================================================
    // Specialized Detectors
    // =========================================================================

    /**
     * @brief Check for process hollowing indicators.
     */
    [[nodiscard]] bool CheckProcessHollowing(uint32_t pid);

    /**
     * @brief Check for reflective DLL injection.
     */
    [[nodiscard]] bool CheckReflectiveDLL(uint32_t pid);

    /**
     * @brief Check for atom bombing.
     */
    [[nodiscard]] bool CheckAtomBombing(uint32_t pid);

    /**
     * @brief Check for thread hijacking.
     */
    [[nodiscard]] bool CheckThreadHijacking(uint32_t pid, uint32_t threadId);

    // =========================================================================
    // Statistics
    // =========================================================================

    /**
     * @brief Get statistics.
     */
    [[nodiscard]] InjectionDetectorStats GetStats() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStats();

    // =========================================================================
    // Callbacks
    // =========================================================================

    /**
     * @brief Register injection callback (can modify verdict).
     */
    [[nodiscard]] uint64_t RegisterInjectionCallback(InjectionCallback callback);

    /**
     * @brief Unregister injection callback.
     */
    bool UnregisterInjectionCallback(uint64_t callbackId);

    /**
     * @brief Register alert callback.
     */
    [[nodiscard]] uint64_t RegisterAlertCallback(InjectionAlertCallback callback);

    /**
     * @brief Unregister alert callback.
     */
    bool UnregisterAlertCallback(uint64_t callbackId);

    /**
     * @brief Register chain callback.
     */
    [[nodiscard]] uint64_t RegisterChainCallback(InjectionChainCallback callback);

    /**
     * @brief Unregister chain callback.
     */
    bool UnregisterChainCallback(uint64_t callbackId);

    /**
     * @brief Register handle access callback.
     */
    [[nodiscard]] uint64_t RegisterHandleCallback(HandleAccessCallback callback);

    /**
     * @brief Unregister handle callback.
     */
    bool UnregisterHandleCallback(uint64_t callbackId);

    // =========================================================================
    // External Integration
    // =========================================================================

    /**
     * @brief Set whitelist store.
     */
    void SetWhitelistStore(Whitelist::WhitelistStore* store);

    /**
     * @brief Set behavior analyzer.
     */
    void SetBehaviorAnalyzer(Core::Engine::BehaviorAnalyzer* analyzer);

    /**
     * @brief Set threat detector.
     */
    void SetThreatDetector(Core::Engine::ThreatDetector* detector);

    /**
     * @brief Set memory protection.
     */
    void SetMemoryProtection(RealTime::MemoryProtection* memProtect);

private:
    // =========================================================================
    // Private Constructor (Singleton)
    // =========================================================================

    ProcessInjectionDetector();
    ~ProcessInjectionDetector();

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /**
     * @brief Correlate events to detect injection.
     */
    std::optional<InjectionEvent> CorrelateEvents(
        uint32_t sourceProcessId,
        uint32_t targetProcessId
    );

    /**
     * @brief Create injection alert.
     */
    InjectionAlert CreateAlert(const InjectionEvent& event);

    /**
     * @brief Check if injection should be whitelisted.
     */
    bool ShouldWhitelist(const InjectionEvent& event) const;

    /**
     * @brief Calculate risk score.
     */
    double CalculateRiskScore(const InjectionEvent& event) const;

    /**
     * @brief Event cleanup thread.
     */
    void EventCleanupThread();

    /**
     * @brief Invoke injection callbacks.
     */
    InjectionVerdict InvokeInjectionCallbacks(const InjectionEvent& event);

    /**
     * @brief Invoke alert callbacks.
     */
    void InvokeAlertCallbacks(const InjectionAlert& alert);

    /**
     * @brief Invoke chain callbacks.
     */
    void InvokeChainCallbacks(const InjectionChain& chain);

    // =========================================================================
    // Internal Data (PIMPL)
    // =========================================================================

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Check if handle access rights are suspicious.
 */
[[nodiscard]] bool IsSuspiciousHandleAccess(uint32_t accessRights) noexcept;

/**
 * @brief Check if memory protection is executable.
 */
[[nodiscard]] bool IsExecutableProtection(uint32_t protection) noexcept;

/**
 * @brief Check if address is in legitimate module.
 */
[[nodiscard]] bool IsAddressInModule(uint32_t pid, uintptr_t address) noexcept;

/**
 * @brief Get module name for address.
 */
[[nodiscard]] std::wstring GetModuleForAddress(uint32_t pid, uintptr_t address) noexcept;

/**
 * @brief Check if process pair is whitelisted for injection.
 */
[[nodiscard]] bool IsInjectionPairWhitelisted(
    const std::wstring& sourceName,
    const std::wstring& targetName
) noexcept;

} // namespace Process
} // namespace Core
} // namespace ShadowStrike
