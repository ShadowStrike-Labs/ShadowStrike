/**
 * ============================================================================
 * ShadowStrike Real-Time - MEMORY PROTECTION (The Buffer Guard)
 * ============================================================================
 *
 * @file MemoryProtection.hpp
 * @brief Enterprise-grade memory protection and injection prevention.
 *
 * This module provides comprehensive memory protection capabilities including:
 * - Process injection detection (DLL injection, thread hijacking, etc.)
 * - Memory integrity verification (hook detection, tampering)
 * - Exploit mitigation (DEP, ASLR, CFI enforcement)
 * - Memory scanning for suspicious patterns
 *
 * =============================================================================
 * CORE CAPABILITIES
 * =============================================================================
 *
 * 1. **Process Injection Detection**
 *    - Classic DLL injection (LoadLibrary)
 *    - Remote thread injection
 *    - APC queue injection
 *    - Process hollowing
 *    - Process doppelgänging
 *    - Thread execution hijacking
 *    - Atom bombing
 *    - Extra window bytes injection
 *
 * 2. **Memory Integrity Monitoring**
 *    - System DLL hook detection (ntdll, kernel32)
 *    - IAT/EAT modification detection
 *    - Inline hook detection
 *    - .text section integrity
 *    - Module base relocation tracking
 *
 * 3. **Exploit Mitigation**
 *    - DEP (Data Execution Prevention) enforcement
 *    - ASLR verification
 *    - CFG (Control Flow Guard) support
 *    - CET (Control-flow Enforcement Technology)
 *    - Stack canary validation
 *    - SafeSEH verification
 *    - ACG (Arbitrary Code Guard)
 *
 * 4. **Memory Pattern Scanning**
 *    - Shellcode detection
 *    - ROP gadget chains
 *    - Heap spray detection
 *    - Suspicious allocation patterns
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 * ```
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                          KERNEL MODE                                         │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                    Kernel Callbacks/Hooks                            │   │
 * │  │                                                                       │   │
 * │  │  - ObRegisterCallbacks (handle creation)                             │   │
 * │  │  - PsSetLoadImageNotifyRoutine (module loading)                      │   │
 * │  │  - MmSetPageProtection monitoring (ETW)                              │   │
 * │  │  - ZwAllocateVirtualMemory hooks                                     │   │
 * │  │                                                                       │   │
 * │  └────────────────────────────────────┬──────────────────────────────────┘   │
 * │                                       │                                      │
 * └───────────────────────────────────────┼──────────────────────────────────────┘
 *                                         │
 * ════════════════════════════════════════╪══════════════════════════════════════
 *                                         │ ETW + Filter Port
 * ════════════════════════════════════════╪══════════════════════════════════════
 *                                         │
 * ┌───────────────────────────────────────┼──────────────────────────────────────┐
 * │                                       ▼                                      │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                      MemoryProtection Engine                         │   │
 * │  │                                                                       │   │
 * │  │  ┌───────────────┐  ┌───────────────┐  ┌────────────────────────┐   │   │
 * │  │  │   Injection   │  │   Integrity   │  │        Exploit         │   │   │
 * │  │  │   Detector    │  │    Monitor    │  │       Mitigation       │   │   │
 * │  │  └───────┬───────┘  └───────┬───────┘  └───────────┬────────────┘   │   │
 * │  │          │                  │                      │                │   │
 * │  │          └──────────────────┼──────────────────────┘                │   │
 * │  │                             │                                       │   │
 * │  │  ┌──────────────────────────▼──────────────────────────────────┐   │   │
 * │  │  │                     Memory Scanner                           │   │   │
 * │  │  │  - Pattern matching (shellcode signatures)                   │   │   │
 * │  │  │  - Heuristic analysis (ROP chains, heap spray)              │   │   │
 * │  │  │  - Emulation (suspicious code paths)                        │   │   │
 * │  │  └─────────────────────────────────────────────────────────────┘   │   │
 * │  │                                                                       │   │
 * │  │  ┌─────────────────────────────────────────────────────────────┐   │   │
 * │  │  │                   Per-Process State                          │   │   │
 * │  │  │  - Loaded modules + hashes                                   │   │   │
 * │  │  │  - Critical section integrity snapshots                      │   │   │
 * │  │  │  - Allocation history                                        │   │   │
 * │  │  │  - Thread context tracking                                   │   │   │
 * │  │  └─────────────────────────────────────────────────────────────┘   │   │
 * │  │                                                                       │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                              │
 * │                           USER MODE                                          │
 * └──────────────────────────────────────────────────────────────────────────────┘
 * ```
 *
 * =============================================================================
 * INJECTION TECHNIQUES DETECTED
 * =============================================================================
 *
 * | Technique                    | Detection Method                              |
 * |------------------------------|-----------------------------------------------|
 * | Classic DLL Injection        | LoadLibrary call to remote process            |
 * | Reflective DLL Injection     | Memory mapping + manual loading patterns      |
 * | Process Hollowing            | Section unmapping + replacement               |
 * | Process Doppelgänging        | NTFS transaction abuse detection              |
 * | Process Herpaderping         | Post-map file modification                    |
 * | Process Ghosting             | Delete-pending file execution                 |
 * | Thread Execution Hijacking   | SetThreadContext to remote thread             |
 * | APC Queue Injection          | QueueUserAPC to remote thread                 |
 * | Atom Bombing                 | GlobalAddAtom + NtQueueApcThread              |
 * | Extra Window Bytes           | SetWindowLongPtr abuse                        |
 * | Shim Injection               | Application compatibility shim abuse          |
 * | IAT/EAT Hooking              | Import/Export table modifications             |
 * | Inline Hooking               | JMP/CALL at function prologues                |
 * | VEH Hijacking                | VectoredHandlerList manipulation              |
 *
 * =============================================================================
 * MITRE ATT&CK COVERAGE
 * =============================================================================
 *
 * | Technique | Description                              | Detection Method      |
 * |-----------|------------------------------------------|-----------------------|
 * | T1055.001 | DLL Injection                            | Handle + write mon    |
 * | T1055.002 | PE Injection                             | Executable memory     |
 * | T1055.003 | Thread Execution Hijacking               | Context modification  |
 * | T1055.004 | Asynchronous Procedure Call              | APC queue monitoring  |
 * | T1055.005 | Thread Local Storage                     | TLS callback mon      |
 * | T1055.008 | Ptrace System Calls (Linux)              | N/A (Windows focus)   |
 * | T1055.009 | Proc Memory                              | /proc monitoring      |
 * | T1055.011 | Extra Window Memory                      | Window bytes mon      |
 * | T1055.012 | Process Hollowing                        | Section replacement   |
 * | T1055.013 | Process Doppelgänging                    | Transaction abuse     |
 * | T1055.014 | VDSO Hijacking (Linux)                   | N/A (Windows focus)   |
 * | T1574.001 | DLL Search Order Hijacking               | Load path validation  |
 * | T1574.002 | DLL Side-Loading                         | Signature verification|
 *
 * @note Thread-safe for all public methods
 * @note Requires elevated privileges for cross-process monitoring
 *
 * @see ProcessCreationMonitor for process tracking
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
#include "../Utils/ProcessUtils.hpp"          // Process memory access
#include "../Utils/SystemUtils.hpp"           // System information
#include "../PatternStore/PatternStore.hpp"   // Shellcode/injection patterns
#include "../ThreatIntel/ThreatIntelLookup.hpp"  // IOC correlation
#include "../Whitelist/WhiteListStore.hpp"    // Trusted processes

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
            class EmulationEngine;
        }
    }
    namespace PatternStore {
        class PatternIndex;
    }
}

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class MemoryProtection;
struct MemoryRegion;
struct InjectionEvent;
struct ModuleInfo;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace MemoryProtectionConstants {
    // -------------------------------------------------------------------------
    // General Limits
    // -------------------------------------------------------------------------
    
    /// @brief Maximum monitored processes
    constexpr size_t MAX_MONITORED_PROCESSES = 10000;
    
    /// @brief Maximum modules per process
    constexpr size_t MAX_MODULES_PER_PROCESS = 500;
    
    /// @brief Maximum allocations to track per process
    constexpr size_t MAX_ALLOCATIONS_PER_PROCESS = 10000;
    
    /// @brief Maximum threads per process to monitor
    constexpr size_t MAX_THREADS_PER_PROCESS = 500;
    
    // -------------------------------------------------------------------------
    // Scanning
    // -------------------------------------------------------------------------
    
    /// @brief Maximum memory region scan size
    constexpr size_t MAX_SCAN_REGION_SIZE = 256 * 1024 * 1024;  // 256 MB
    
    /// @brief Minimum shellcode size to detect
    constexpr size_t MIN_SHELLCODE_SIZE = 16;
    
    /// @brief Maximum shellcode patterns to maintain
    constexpr size_t MAX_SHELLCODE_PATTERNS = 5000;
    
    // -------------------------------------------------------------------------
    // Integrity Verification
    // -------------------------------------------------------------------------
    
    /// @brief Number of critical DLLs to monitor
    constexpr size_t CRITICAL_DLL_COUNT = 20;
    
    /// @brief Integrity check interval (ms)
    constexpr uint32_t INTEGRITY_CHECK_INTERVAL_MS = 5000;
    
    // -------------------------------------------------------------------------
    // Thresholds
    // -------------------------------------------------------------------------
    
    /// @brief Heap spray detection threshold (allocations/second)
    constexpr uint32_t HEAP_SPRAY_THRESHOLD = 100;
    
    /// @brief Suspicious allocation size threshold
    constexpr size_t SUSPICIOUS_ALLOC_SIZE = 10 * 1024 * 1024;  // 10 MB
    
    /// @brief ROP gadget chain minimum length
    constexpr size_t MIN_ROP_CHAIN_LENGTH = 5;
    
    // -------------------------------------------------------------------------
    // Risk Scores
    // -------------------------------------------------------------------------
    
    /// @brief Remote thread creation score
    constexpr double REMOTE_THREAD_SCORE = 60.0;
    
    /// @brief Cross-process write score
    constexpr double CROSS_PROCESS_WRITE_SCORE = 70.0;
    
    /// @brief Shellcode detection score
    constexpr double SHELLCODE_SCORE = 85.0;
    
    /// @brief Process hollowing score
    constexpr double PROCESS_HOLLOWING_SCORE = 95.0;
    
    /// @brief Hook detection score
    constexpr double HOOK_DETECTION_SCORE = 50.0;
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Memory region type.
 */
enum class MemoryRegionType : uint8_t {
    /// @brief Unknown region
    Unknown = 0,
    
    /// @brief Stack
    Stack = 1,
    
    /// @brief Heap
    Heap = 2,
    
    /// @brief Image/module
    Image = 3,
    
    /// @brief Mapped file
    MappedFile = 4,
    
    /// @brief Private allocation
    Private = 5,
    
    /// @brief PEB/TEB
    ProcessEnvironment = 6,
    
    /// @brief Thread Local Storage
    TLS = 7
};

/**
 * @brief Memory protection flags.
 */
enum class MemoryProtectionType : uint8_t {
    /// @brief No access
    NoAccess = 0,
    
    /// @brief Read only
    ReadOnly = 1,
    
    /// @brief Read/Write
    ReadWrite = 2,
    
    /// @brief Read/Execute
    ReadExecute = 3,
    
    /// @brief Read/Write/Execute (suspicious)
    ReadWriteExecute = 4,
    
    /// @brief Execute only
    ExecuteOnly = 5,
    
    /// @brief Copy on write
    CopyOnWrite = 6,
    
    /// @brief Guard page
    Guard = 7
};

/**
 * @brief Injection technique type.
 */
enum class InjectionType : uint16_t {
    /// @brief Unknown injection
    Unknown = 0,
    
    // -------------------------------------------------------------------------
    // DLL Injection
    // -------------------------------------------------------------------------
    
    /// @brief Classic LoadLibrary injection
    ClassicDLLInjection = 1,
    
    /// @brief Reflective DLL injection
    ReflectiveDLLInjection = 2,
    
    /// @brief Manual map injection
    ManualMapInjection = 3,
    
    // -------------------------------------------------------------------------
    // Code Injection
    // -------------------------------------------------------------------------
    
    /// @brief Remote thread injection
    RemoteThreadInjection = 10,
    
    /// @brief APC queue injection
    APCQueueInjection = 11,
    
    /// @brief Thread context hijacking
    ThreadHijacking = 12,
    
    /// @brief Atom bombing
    AtomBombing = 13,
    
    /// @brief Extra window bytes
    ExtraWindowBytes = 14,
    
    /// @brief Shim injection
    ShimInjection = 15,
    
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
    
    // -------------------------------------------------------------------------
    // Hooking
    // -------------------------------------------------------------------------
    
    /// @brief IAT hooking
    IATHooking = 30,
    
    /// @brief EAT hooking
    EATHooking = 31,
    
    /// @brief Inline hooking (detour)
    InlineHooking = 32,
    
    /// @brief VEH hijacking
    VEHHijacking = 33,
    
    /// @brief HWBP hook
    HardwareBreakpointHook = 34,
    
    // -------------------------------------------------------------------------
    // Shellcode
    // -------------------------------------------------------------------------
    
    /// @brief Shellcode in stack
    ShellcodeStack = 40,
    
    /// @brief Shellcode in heap
    ShellcodeHeap = 41,
    
    /// @brief Shellcode in mapped section
    ShellcodeMapped = 42,
    
    /// @brief Heap spray
    HeapSpray = 43,
    
    /// @brief ROP chain execution
    ROPExecution = 44,
    
    /// @brief JIT spray
    JITSpray = 45
};

/**
 * @brief Memory event type.
 */
enum class MemoryEventType : uint16_t {
    /// @brief Unknown event
    Unknown = 0,
    
    /// @brief Memory allocation
    Allocation = 1,
    
    /// @brief Memory free
    Free = 2,
    
    /// @brief Protection change
    ProtectionChange = 3,
    
    /// @brief Cross-process read
    CrossProcessRead = 4,
    
    /// @brief Cross-process write
    CrossProcessWrite = 5,
    
    /// @brief Module load
    ModuleLoad = 6,
    
    /// @brief Module unload
    ModuleUnload = 7,
    
    /// @brief Thread creation
    ThreadCreation = 8,
    
    /// @brief Thread termination
    ThreadTermination = 9,
    
    /// @brief Handle duplication
    HandleDuplication = 10,
    
    /// @brief Section mapping
    SectionMapping = 11,
    
    /// @brief Section unmapping
    SectionUnmapping = 12,
    
    /// @brief Thread context modification
    ThreadContextChange = 13,
    
    /// @brief APC queue
    APCQueue = 14
};

/**
 * @brief Integrity check result.
 */
enum class IntegrityStatus : uint8_t {
    /// @brief Unknown status
    Unknown = 0,
    
    /// @brief Integrity verified
    Intact = 1,
    
    /// @brief Module modified
    Modified = 2,
    
    /// @brief Hook detected
    Hooked = 3,
    
    /// @brief Section missing
    SectionMissing = 4,
    
    /// @brief Check failed
    CheckFailed = 5
};

/**
 * @brief Mitigation status.
 */
enum class MitigationStatus : uint8_t {
    /// @brief Unknown
    Unknown = 0,
    
    /// @brief Mitigation enabled
    Enabled = 1,
    
    /// @brief Mitigation disabled
    Disabled = 2,
    
    /// @brief Mitigation not applicable
    NotApplicable = 3,
    
    /// @brief Check failed
    CheckFailed = 4
};

/**
 * @brief Memory protection action.
 */
enum class MemoryProtectionAction : uint8_t {
    /// @brief Allow operation
    Allow = 0,
    
    /// @brief Block operation
    Block = 1,
    
    /// @brief Terminate process
    TerminateProcess = 2,
    
    /// @brief Log and allow
    LogOnly = 3,
    
    /// @brief Quarantine process
    Quarantine = 4
};

/**
 * @brief Get string for InjectionType.
 */
[[nodiscard]] constexpr const char* InjectionTypeToString(InjectionType type) noexcept;

/**
 * @brief Get MITRE ATT&CK technique for injection type.
 */
[[nodiscard]] constexpr const char* InjectionTypeToMitre(InjectionType type) noexcept;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief Memory region descriptor.
 */
struct MemoryRegion {
    /// @brief Base address
    uintptr_t baseAddress = 0;
    
    /// @brief Region size
    size_t size = 0;
    
    /// @brief Region type
    MemoryRegionType type = MemoryRegionType::Unknown;
    
    /// @brief Protection type
    MemoryProtectionType protection = MemoryProtectionType::NoAccess;
    
    /// @brief State (committed, reserved, free)
    uint32_t state = 0;
    
    /// @brief Allocation base
    uintptr_t allocationBase = 0;
    
    /// @brief Allocation protection
    uint32_t allocationProtect = 0;
    
    /// @brief Associated module (if Image type)
    std::wstring moduleName;
    
    /// @brief Associated file (if MappedFile type)
    std::wstring mappedFile;
    
    /// @brief Thread ID (if Stack type)
    uint32_t threadId = 0;
    
    /// @brief Is executable
    bool isExecutable = false;
    
    /// @brief Is writable
    bool isWritable = false;
    
    /// @brief Hash of region content (for integrity)
    std::string contentHash;
    
    /// @brief Timestamp of last check
    std::chrono::system_clock::time_point lastCheck{};
};

/**
 * @brief Memory allocation event.
 */
struct MemoryAllocationEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Event timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Event type
    MemoryEventType eventType = MemoryEventType::Unknown;
    
    /// @brief Source process ID
    uint32_t sourceProcessId = 0;
    
    /// @brief Target process ID
    uint32_t targetProcessId = 0;
    
    /// @brief Source thread ID
    uint32_t threadId = 0;
    
    /// @brief Base address
    uintptr_t baseAddress = 0;
    
    /// @brief Size
    size_t size = 0;
    
    /// @brief Protection requested/set
    uint32_t protection = 0;
    
    /// @brief Old protection (for protection change)
    uint32_t oldProtection = 0;
    
    /// @brief Allocation type (MEM_COMMIT, MEM_RESERVE, etc.)
    uint32_t allocationType = 0;
    
    /// @brief Is cross-process operation
    bool isCrossProcess = false;
    
    /// @brief Data written (first N bytes, for cross-process write)
    std::vector<uint8_t> dataPreview;
};

/**
 * @brief Injection detection event.
 */
struct InjectionEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Event timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Injection type detected
    InjectionType injectionType = InjectionType::Unknown;
    
    /// @brief Source (attacker) process ID
    uint32_t sourceProcessId = 0;
    
    /// @brief Source process name
    std::wstring sourceProcessName;
    
    /// @brief Target (victim) process ID
    uint32_t targetProcessId = 0;
    
    /// @brief Target process name
    std::wstring targetProcessName;
    
    /// @brief Thread ID involved
    uint32_t threadId = 0;
    
    /// @brief Target address
    uintptr_t targetAddress = 0;
    
    /// @brief Data size
    size_t dataSize = 0;
    
    /// @brief Injected module path (if DLL injection)
    std::wstring injectedModulePath;
    
    /// @brief Confidence score (0-100)
    double confidence = 0.0;
    
    /// @brief Risk score
    double riskScore = 0.0;
    
    /// @brief MITRE technique ID
    std::string mitreTechnique;
    
    /// @brief Action taken
    MemoryProtectionAction actionTaken = MemoryProtectionAction::Allow;
    
    /// @brief Was blocked
    bool blocked = false;
    
    /// @brief Additional context
    std::wstring context;
    
    /// @brief Evidence data (shellcode preview, etc.)
    std::vector<uint8_t> evidence;
};

/**
 * @brief Module/DLL information.
 */
struct ModuleInfo {
    /// @brief Module base address
    uintptr_t baseAddress = 0;
    
    /// @brief Module size
    size_t size = 0;
    
    /// @brief Module path
    std::wstring path;
    
    /// @brief Module name
    std::wstring name;
    
    /// @brief Is system module
    bool isSystemModule = false;
    
    /// @brief Is Microsoft signed
    bool isMicrosoftSigned = false;
    
    /// @brief Module hash (SHA256)
    std::string hash;
    
    /// @brief .text section hash
    std::string textSectionHash;
    
    /// @brief Entry point
    uintptr_t entryPoint = 0;
    
    /// @brief Load timestamp
    std::chrono::system_clock::time_point loadTime{};
    
    /// @brief Integrity status
    IntegrityStatus integrityStatus = IntegrityStatus::Unknown;
    
    /// @brief Hook count detected
    uint32_t hookCount = 0;
    
    /// @brief List of detected hooks
    std::vector<std::pair<std::string, uintptr_t>> detectedHooks;
};

/**
 * @brief Hook detection result.
 */
struct HookDetectionResult {
    /// @brief Module name
    std::wstring moduleName;
    
    /// @brief Function name
    std::string functionName;
    
    /// @brief Function address
    uintptr_t functionAddress = 0;
    
    /// @brief Hook type detected
    std::string hookType;  // "Inline", "IAT", "EAT"
    
    /// @brief Original bytes
    std::vector<uint8_t> originalBytes;
    
    /// @brief Current bytes
    std::vector<uint8_t> currentBytes;
    
    /// @brief Hook target address
    uintptr_t hookTarget = 0;
    
    /// @brief Hook target module
    std::wstring hookTargetModule;
};

/**
 * @brief Per-process memory state.
 */
struct ProcessMemoryState {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Is protected process
    bool isProtectedProcess = false;
    
    /// @brief Loaded modules
    std::vector<ModuleInfo> modules;
    
    /// @brief Memory regions
    std::vector<MemoryRegion> regions;
    
    /// @brief Recent allocations
    std::vector<MemoryAllocationEvent> recentAllocations;
    
    /// @brief Heap allocation count
    uint64_t heapAllocationCount = 0;
    
    /// @brief Total heap size
    uint64_t totalHeapSize = 0;
    
    /// @brief Executable private memory count
    uint32_t executablePrivateCount = 0;
    
    /// @brief RWX region count (suspicious)
    uint32_t rwxRegionCount = 0;
    
    /// @brief Integrity check results
    std::vector<HookDetectionResult> detectedHooks;
    
    /// @brief Last integrity check
    std::chrono::system_clock::time_point lastIntegrityCheck{};
    
    /// @brief Risk score
    double riskScore = 0.0;
    
    /// @brief Injection events
    std::vector<InjectionEvent> injectionEvents;
    
    /// @brief Monitoring started
    std::chrono::system_clock::time_point monitoringStarted{};
};

/**
 * @brief Mitigation policy for a process.
 */
struct ProcessMitigationPolicy {
    /// @brief DEP (Data Execution Prevention)
    MitigationStatus dep = MitigationStatus::Unknown;
    
    /// @brief ASLR (Address Space Layout Randomization)
    MitigationStatus aslr = MitigationStatus::Unknown;
    
    /// @brief High-entropy ASLR
    MitigationStatus highEntropyASLR = MitigationStatus::Unknown;
    
    /// @brief CFG (Control Flow Guard)
    MitigationStatus cfg = MitigationStatus::Unknown;
    
    /// @brief CET (Control-flow Enforcement Technology)
    MitigationStatus cet = MitigationStatus::Unknown;
    
    /// @brief ACG (Arbitrary Code Guard)
    MitigationStatus acg = MitigationStatus::Unknown;
    
    /// @brief SEHOP (Structured Exception Handler Overwrite Protection)
    MitigationStatus sehop = MitigationStatus::Unknown;
    
    /// @brief Heap terminate on corruption
    MitigationStatus heapTerminate = MitigationStatus::Unknown;
    
    /// @brief Win32k system call disable
    MitigationStatus win32kDisable = MitigationStatus::Unknown;
    
    /// @brief Block remote image
    MitigationStatus blockRemoteImage = MitigationStatus::Unknown;
    
    /// @brief Block low integrity image
    MitigationStatus blockLowIntegrity = MitigationStatus::Unknown;
    
    /// @brief Dynamic code disable
    MitigationStatus dynamicCodeDisable = MitigationStatus::Unknown;
    
    /// @brief Block child process creation
    MitigationStatus blockChildProcess = MitigationStatus::Unknown;
    
    /// @brief Image load from remote
    MitigationStatus imageLoadRemote = MitigationStatus::Unknown;
};

/**
 * @brief Memory protection configuration.
 */
struct MemoryProtectionConfig {
    // -------------------------------------------------------------------------
    // General Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable memory protection
    bool enabled = true;
    
    /// @brief Enable injection detection
    bool detectInjection = true;
    
    /// @brief Enable integrity monitoring
    bool monitorIntegrity = true;
    
    /// @brief Enable shellcode detection
    bool detectShellcode = true;
    
    /// @brief Enable heap spray detection
    bool detectHeapSpray = true;
    
    // -------------------------------------------------------------------------
    // Action Settings
    // -------------------------------------------------------------------------
    
    /// @brief Action on injection detection
    MemoryProtectionAction injectionAction = MemoryProtectionAction::Block;
    
    /// @brief Action on shellcode detection
    MemoryProtectionAction shellcodeAction = MemoryProtectionAction::Block;
    
    /// @brief Action on hook detection
    MemoryProtectionAction hookAction = MemoryProtectionAction::LogOnly;
    
    /// @brief Block RWX allocations
    bool blockRWX = true;
    
    /// @brief Block cross-process writes
    bool blockCrossProcessWrite = true;
    
    /// @brief Block remote thread creation
    bool blockRemoteThread = true;
    
    // -------------------------------------------------------------------------
    // Protected Process Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable self-protection
    bool protectSelf = true;
    
    /// @brief Processes to protect (by name)
    std::vector<std::wstring> protectedProcessNames;
    
    /// @brief Processes to protect (by PID)
    std::vector<uint32_t> protectedProcessIds;
    
    // -------------------------------------------------------------------------
    // Exclusions
    // -------------------------------------------------------------------------
    
    /// @brief Excluded source processes
    std::vector<std::wstring> excludedSourceProcesses;
    
    /// @brief Excluded target processes
    std::vector<std::wstring> excludedTargetProcesses;
    
    /// @brief Trusted signers (allowed to inject)
    std::vector<std::wstring> trustedSigners;
    
    // -------------------------------------------------------------------------
    // Integrity Settings
    // -------------------------------------------------------------------------
    
    /// @brief Integrity check interval (ms)
    uint32_t integrityCheckIntervalMs = MemoryProtectionConstants::INTEGRITY_CHECK_INTERVAL_MS;
    
    /// @brief Critical DLLs to verify
    std::vector<std::wstring> criticalDlls;
    
    // -------------------------------------------------------------------------
    // Scanning Settings
    // -------------------------------------------------------------------------
    
    /// @brief Maximum memory scan size
    size_t maxScanSize = MemoryProtectionConstants::MAX_SCAN_REGION_SIZE;
    
    /// @brief Scan timeout (ms)
    uint32_t scanTimeoutMs = 5000;
    
    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Create default configuration.
     */
    [[nodiscard]] static MemoryProtectionConfig CreateDefault() noexcept {
        MemoryProtectionConfig config;
        config.criticalDlls = {
            L"ntdll.dll",
            L"kernel32.dll",
            L"kernelbase.dll",
            L"user32.dll",
            L"advapi32.dll",
            L"ws2_32.dll",
            L"msvcrt.dll",
            L"crypt32.dll"
        };
        return config;
    }
    
    /**
     * @brief Create aggressive configuration.
     */
    [[nodiscard]] static MemoryProtectionConfig CreateAggressive() noexcept {
        MemoryProtectionConfig config = CreateDefault();
        config.injectionAction = MemoryProtectionAction::TerminateProcess;
        config.shellcodeAction = MemoryProtectionAction::TerminateProcess;
        config.hookAction = MemoryProtectionAction::Block;
        config.blockRWX = true;
        config.blockCrossProcessWrite = true;
        config.blockRemoteThread = true;
        return config;
    }
    
    /**
     * @brief Create monitoring-only configuration.
     */
    [[nodiscard]] static MemoryProtectionConfig CreateMonitorOnly() noexcept {
        MemoryProtectionConfig config = CreateDefault();
        config.injectionAction = MemoryProtectionAction::LogOnly;
        config.shellcodeAction = MemoryProtectionAction::LogOnly;
        config.hookAction = MemoryProtectionAction::LogOnly;
        config.blockRWX = false;
        config.blockCrossProcessWrite = false;
        config.blockRemoteThread = false;
        return config;
    }
};

/**
 * @brief Memory protection statistics.
 */
struct MemoryProtectionStats {
    /// @brief Total memory events processed
    std::atomic<uint64_t> totalEvents{ 0 };
    
    /// @brief Memory allocations observed
    std::atomic<uint64_t> allocationsObserved{ 0 };
    
    /// @brief Cross-process operations detected
    std::atomic<uint64_t> crossProcessOps{ 0 };
    
    /// @brief Injection attempts detected
    std::atomic<uint64_t> injectionAttempts{ 0 };
    
    /// @brief Injection attempts blocked
    std::atomic<uint64_t> injectionsBlocked{ 0 };
    
    /// @brief Shellcode detections
    std::atomic<uint64_t> shellcodeDetections{ 0 };
    
    /// @brief Heap spray detections
    std::atomic<uint64_t> heapSprayDetections{ 0 };
    
    /// @brief Hooks detected
    std::atomic<uint64_t> hooksDetected{ 0 };
    
    /// @brief RWX allocations detected
    std::atomic<uint64_t> rwxAllocations{ 0 };
    
    /// @brief Integrity checks performed
    std::atomic<uint64_t> integrityChecks{ 0 };
    
    /// @brief Integrity failures
    std::atomic<uint64_t> integrityFailures{ 0 };
    
    /// @brief Processes currently monitored
    std::atomic<size_t> monitoredProcesses{ 0 };
    
    /// @brief Scans performed
    std::atomic<uint64_t> scansPerformed{ 0 };
    
    /// @brief Average scan time (microseconds)
    std::atomic<uint64_t> avgScanTimeUs{ 0 };
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept {
        totalEvents.store(0, std::memory_order_relaxed);
        allocationsObserved.store(0, std::memory_order_relaxed);
        crossProcessOps.store(0, std::memory_order_relaxed);
        injectionAttempts.store(0, std::memory_order_relaxed);
        injectionsBlocked.store(0, std::memory_order_relaxed);
        shellcodeDetections.store(0, std::memory_order_relaxed);
        heapSprayDetections.store(0, std::memory_order_relaxed);
        hooksDetected.store(0, std::memory_order_relaxed);
        rwxAllocations.store(0, std::memory_order_relaxed);
        integrityChecks.store(0, std::memory_order_relaxed);
        integrityFailures.store(0, std::memory_order_relaxed);
        monitoredProcesses.store(0, std::memory_order_relaxed);
        scansPerformed.store(0, std::memory_order_relaxed);
        avgScanTimeUs.store(0, std::memory_order_relaxed);
    }
};

/**
 * @brief Callback types.
 */
using InjectionCallback = std::function<MemoryProtectionAction(const InjectionEvent&)>;
using MemoryEventCallback = std::function<void(const MemoryAllocationEvent&)>;
using IntegrityCallback = std::function<void(uint32_t pid, const std::vector<HookDetectionResult>&)>;
using ShellcodeCallback = std::function<MemoryProtectionAction(uint32_t pid, uintptr_t address, const std::vector<uint8_t>& data)>;

// ============================================================================
// MAIN MEMORY PROTECTION CLASS
// ============================================================================

/**
 * @brief Enterprise-grade memory protection and injection prevention.
 *
 * Provides comprehensive memory protection including injection detection,
 * integrity monitoring, shellcode detection, and exploit mitigation enforcement.
 *
 * Thread Safety: All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& memProtect = MemoryProtection::Instance();
 * 
 * // Initialize
 * MemoryProtectionConfig config = MemoryProtectionConfig::CreateDefault();
 * config.detectInjection = true;
 * config.injectionAction = MemoryProtectionAction::Block;
 * memProtect.Initialize(threadPool, config);
 * 
 * // Set integrations
 * memProtect.SetPatternIndex(&PatternIndex::Instance());
 * memProtect.SetBehaviorAnalyzer(&BehaviorAnalyzer::Instance());
 * 
 * // Register callbacks
 * memProtect.RegisterInjectionCallback([](const InjectionEvent& event) {
 *     LOG_WARN("Injection detected: {} -> {} ({})",
 *              event.sourceProcessName, event.targetProcessName,
 *              InjectionTypeToString(event.injectionType));
 *     return MemoryProtectionAction::Block;
 * });
 * 
 * // Start monitoring
 * memProtect.Start();
 * 
 * // Add process to monitor
 * memProtect.MonitorProcess(targetPid);
 * 
 * // Check process integrity
 * auto state = memProtect.GetProcessMemoryState(targetPid);
 * if (state && !state->detectedHooks.empty()) {
 *     LOG_WARN("Hooks detected in process {}", targetPid);
 * }
 * 
 * // Verify mitigations
 * auto policy = memProtect.GetProcessMitigations(targetPid);
 * if (policy.dep == MitigationStatus::Disabled) {
 *     LOG_WARN("DEP disabled for process {}", targetPid);
 * }
 * 
 * memProtect.Stop();
 * memProtect.Shutdown();
 * @endcode
 */
class MemoryProtection {
public:
    // =========================================================================
    // Singleton Access
    // =========================================================================

    /**
     * @brief Get the singleton instance.
     */
    [[nodiscard]] static MemoryProtection& Instance();

    // Non-copyable, non-movable
    MemoryProtection(const MemoryProtection&) = delete;
    MemoryProtection& operator=(const MemoryProtection&) = delete;
    MemoryProtection(MemoryProtection&&) = delete;
    MemoryProtection& operator=(MemoryProtection&&) = delete;

    // =========================================================================
    // Lifecycle Management
    // =========================================================================

    /**
     * @brief Initialize memory protection.
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
        const MemoryProtectionConfig& config
    );

    /**
     * @brief Shutdown memory protection.
     */
    void Shutdown();

    /**
     * @brief Start protection.
     */
    void Start();

    /**
     * @brief Stop protection.
     */
    void Stop();

    /**
     * @brief Check if protection is running.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    /**
     * @brief Update configuration.
     */
    void UpdateConfig(const MemoryProtectionConfig& config);

    /**
     * @brief Get current configuration.
     */
    [[nodiscard]] MemoryProtectionConfig GetConfig() const;

    // =========================================================================
    // Process Monitoring
    // =========================================================================

    /**
     * @brief Start monitoring a process.
     */
    bool MonitorProcess(uint32_t pid);

    /**
     * @brief Start monitoring a process (via handle).
     */
    bool MonitorProcess(HANDLE processHandle);

    /**
     * @brief Stop monitoring a process.
     */
    void StopMonitoringProcess(uint32_t pid);

    /**
     * @brief Monitor all processes.
     */
    void MonitorAllProcesses();

    /**
     * @brief Check if process is being monitored.
     */
    [[nodiscard]] bool IsProcessMonitored(uint32_t pid) const;

    /**
     * @brief Get list of monitored processes.
     */
    [[nodiscard]] std::vector<uint32_t> GetMonitoredProcesses() const;

    // =========================================================================
    // Memory Events
    // =========================================================================

    /**
     * @brief Handle memory allocation event.
     */
    MemoryProtectionAction OnMemoryAllocation(const MemoryAllocationEvent& event);

    /**
     * @brief Handle cross-process operation.
     * @return true if operation should be allowed.
     */
    [[nodiscard]] bool OnCrossProcessOperation(
        uint32_t sourcePid,
        uint32_t targetPid,
        MemoryEventType eventType,
        uintptr_t address,
        size_t size
    );

    /**
     * @brief Handle remote thread creation.
     * @return true if should be allowed.
     */
    [[nodiscard]] bool OnRemoteThreadCreation(
        uint32_t sourcePid,
        uint32_t targetPid,
        uintptr_t startAddress
    );

    /**
     * @brief Handle module load.
     */
    void OnModuleLoad(uint32_t pid, const ModuleInfo& module);

    /**
     * @brief Handle module unload.
     */
    void OnModuleUnload(uint32_t pid, uintptr_t moduleBase);

    /**
     * @brief Prevent cross-process write.
     */
    [[nodiscard]] bool PreventCrossProcessWrite(uint32_t sourcePid, uint32_t targetPid);

    // =========================================================================
    // Injection Detection
    // =========================================================================

    /**
     * @brief Detect injection in process.
     */
    [[nodiscard]] std::vector<InjectionEvent> DetectInjection(uint32_t pid);

    /**
     * @brief Classify injection type from indicators.
     */
    [[nodiscard]] InjectionType ClassifyInjection(
        const MemoryAllocationEvent& event,
        const ProcessMemoryState& state
    );

    /**
     * @brief Check for process hollowing indicators.
     */
    [[nodiscard]] bool CheckProcessHollowing(uint32_t pid);

    /**
     * @brief Check for reflective DLL injection.
     */
    [[nodiscard]] bool CheckReflectiveDLL(uint32_t pid, uintptr_t address, size_t size);

    // =========================================================================
    // Memory Scanning
    // =========================================================================

    /**
     * @brief Scan memory region for shellcode.
     */
    [[nodiscard]] bool ScanForShellcode(uint32_t pid, uintptr_t address, size_t size);

    /**
     * @brief Scan memory region for shellcode (with data).
     */
    [[nodiscard]] bool ScanForShellcode(const std::vector<uint8_t>& data);

    /**
     * @brief Scan process for suspicious memory regions.
     */
    [[nodiscard]] std::vector<MemoryRegion> ScanProcessMemory(uint32_t pid);

    /**
     * @brief Check for heap spray pattern.
     */
    [[nodiscard]] bool CheckHeapSpray(uint32_t pid);

    /**
     * @brief Detect ROP gadget chains.
     */
    [[nodiscard]] bool DetectROPChain(const std::vector<uint8_t>& data);

    // =========================================================================
    // Integrity Monitoring
    // =========================================================================

    /**
     * @brief Verify module integrity.
     */
    [[nodiscard]] IntegrityStatus VerifyModuleIntegrity(uint32_t pid, const std::wstring& moduleName);

    /**
     * @brief Check for inline hooks.
     */
    [[nodiscard]] std::vector<HookDetectionResult> DetectInlineHooks(
        uint32_t pid,
        const std::wstring& moduleName
    );

    /**
     * @brief Check for IAT hooks.
     */
    [[nodiscard]] std::vector<HookDetectionResult> DetectIATHooks(
        uint32_t pid,
        const std::wstring& moduleName
    );

    /**
     * @brief Check all critical DLLs for hooks.
     */
    [[nodiscard]] std::vector<HookDetectionResult> CheckCriticalDLLs(uint32_t pid);

    /**
     * @brief Perform integrity check on process.
     */
    void PerformIntegrityCheck(uint32_t pid);

    /**
     * @brief Unhook module (restore original bytes).
     */
    bool UnhookModule(uint32_t pid, const std::wstring& moduleName);

    // =========================================================================
    // Mitigation Enforcement
    // =========================================================================

    /**
     * @brief Get process mitigation policy.
     */
    [[nodiscard]] ProcessMitigationPolicy GetProcessMitigations(uint32_t pid);

    /**
     * @brief Verify DEP is enabled for process.
     */
    [[nodiscard]] MitigationStatus VerifyDEP(uint32_t pid);

    /**
     * @brief Verify ASLR for process.
     */
    [[nodiscard]] MitigationStatus VerifyASLR(uint32_t pid);

    /**
     * @brief Verify CFG for process.
     */
    [[nodiscard]] MitigationStatus VerifyCFG(uint32_t pid);

    /**
     * @brief Enable mitigation for process.
     */
    bool EnableMitigation(uint32_t pid, const std::string& mitigationName);

    // =========================================================================
    // Query
    // =========================================================================

    /**
     * @brief Get process memory state.
     */
    [[nodiscard]] std::optional<ProcessMemoryState> GetProcessMemoryState(uint32_t pid) const;

    /**
     * @brief Get loaded modules for process.
     */
    [[nodiscard]] std::vector<ModuleInfo> GetProcessModules(uint32_t pid) const;

    /**
     * @brief Get memory regions for process.
     */
    [[nodiscard]] std::vector<MemoryRegion> GetProcessMemoryRegions(uint32_t pid) const;

    /**
     * @brief Get recent injection events.
     */
    [[nodiscard]] std::vector<InjectionEvent> GetRecentInjectionEvents(size_t count = 100) const;

    // =========================================================================
    // Statistics
    // =========================================================================

    /**
     * @brief Get statistics.
     */
    [[nodiscard]] MemoryProtectionStats GetStats() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStats();

    // =========================================================================
    // Callbacks
    // =========================================================================

    /**
     * @brief Register injection callback.
     */
    [[nodiscard]] uint64_t RegisterInjectionCallback(InjectionCallback callback);

    /**
     * @brief Unregister injection callback.
     */
    bool UnregisterInjectionCallback(uint64_t callbackId);

    /**
     * @brief Register memory event callback.
     */
    [[nodiscard]] uint64_t RegisterMemoryEventCallback(MemoryEventCallback callback);

    /**
     * @brief Unregister memory event callback.
     */
    bool UnregisterMemoryEventCallback(uint64_t callbackId);

    /**
     * @brief Register integrity callback.
     */
    [[nodiscard]] uint64_t RegisterIntegrityCallback(IntegrityCallback callback);

    /**
     * @brief Unregister integrity callback.
     */
    bool UnregisterIntegrityCallback(uint64_t callbackId);

    /**
     * @brief Register shellcode callback.
     */
    [[nodiscard]] uint64_t RegisterShellcodeCallback(ShellcodeCallback callback);

    /**
     * @brief Unregister shellcode callback.
     */
    bool UnregisterShellcodeCallback(uint64_t callbackId);

    // =========================================================================
    // External Integration
    // =========================================================================

    /**
     * @brief Set pattern index for shellcode signatures.
     */
    void SetPatternIndex(PatternStore::PatternIndex* index);

    /**
     * @brief Set behavior analyzer.
     */
    void SetBehaviorAnalyzer(Core::Engine::BehaviorAnalyzer* analyzer);

    /**
     * @brief Set threat detector.
     */
    void SetThreatDetector(Core::Engine::ThreatDetector* detector);

    /**
     * @brief Set emulation engine for shellcode analysis.
     */
    void SetEmulationEngine(Core::Engine::EmulationEngine* engine);

private:
    // =========================================================================
    // Private Constructor (Singleton)
    // =========================================================================

    MemoryProtection();
    ~MemoryProtection();

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /**
     * @brief Initialize module integrity baselines.
     */
    void InitializeIntegrityBaselines(uint32_t pid);

    /**
     * @brief Calculate module .text hash.
     */
    std::string CalculateTextSectionHash(uint32_t pid, uintptr_t moduleBase);

    /**
     * @brief Compare function prologue against known patterns.
     */
    bool IsFunctionHooked(uint32_t pid, uintptr_t functionAddress);

    /**
     * @brief Run shellcode through emulation.
     */
    bool EmulateShellcode(const std::vector<uint8_t>& code);

    /**
     * @brief Background integrity check thread.
     */
    void IntegrityCheckThread();

    /**
     * @brief Invoke injection callbacks.
     */
    MemoryProtectionAction InvokeInjectionCallbacks(const InjectionEvent& event);

    /**
     * @brief Invoke memory event callbacks.
     */
    void InvokeMemoryEventCallbacks(const MemoryAllocationEvent& event);

    /**
     * @brief Invoke integrity callbacks.
     */
    void InvokeIntegrityCallbacks(uint32_t pid, const std::vector<HookDetectionResult>& hooks);

    /**
     * @brief Invoke shellcode callbacks.
     */
    MemoryProtectionAction InvokeShellcodeCallbacks(uint32_t pid, uintptr_t address, const std::vector<uint8_t>& data);

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
 * @brief Convert memory protection flags to string.
 */
[[nodiscard]] std::string MemoryProtectionFlagsToString(uint32_t protection) noexcept;

/**
 * @brief Check if memory is executable.
 */
[[nodiscard]] bool IsMemoryExecutable(uint32_t protection) noexcept;

/**
 * @brief Check if memory is writable.
 */
[[nodiscard]] bool IsMemoryWritable(uint32_t protection) noexcept;

/**
 * @brief Check if memory is RWX (suspicious).
 */
[[nodiscard]] bool IsMemoryRWX(uint32_t protection) noexcept;

/**
 * @brief Read process memory safely.
 */
[[nodiscard]] std::vector<uint8_t> ReadProcessMemorySafe(
    HANDLE process,
    uintptr_t address,
    size_t size
) noexcept;

/**
 * @brief Get module base address.
 */
[[nodiscard]] uintptr_t GetModuleBaseAddress(
    uint32_t pid,
    const std::wstring& moduleName
) noexcept;

/**
 * @brief Check if address is in module .text section.
 */
[[nodiscard]] bool IsAddressInTextSection(
    uint32_t pid,
    uintptr_t moduleBase,
    uintptr_t address
) noexcept;

} // namespace RealTime
} // namespace ShadowStrike
