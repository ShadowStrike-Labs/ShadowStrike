/**
 * ============================================================================
 * ShadowStrike Core Process - THREAD HIJACK DETECTOR (The Snatcher)
 * ============================================================================
 *
 * @file ThreadHijackDetector.hpp
 * @brief Enterprise-grade detection of Thread Execution Hijacking attacks.
 *
 * Thread Hijacking (Thread Execution Hijacking) is a code injection technique
 * where an attacker modifies a thread's execution context to redirect execution
 * to malicious code. Unlike creating new threads, this hijacks existing threads.
 *
 * ============================================================================
 * ATTACK MECHANISM
 * ============================================================================
 *
 * Standard Thread Hijack Sequence:
 * 1. OpenThread() - Get handle to target thread
 * 2. SuspendThread() - Pause the thread
 * 3. GetThreadContext() - Read current state (RIP/EIP, RSP/ESP, etc.)
 * 4. VirtualAllocEx() - Allocate memory for payload
 * 5. WriteProcessMemory() - Write shellcode
 * 6. SetThreadContext() - Modify RIP to point to shellcode
 * 7. ResumeThread() - Execute the payload
 *
 * Variations:
 * - Stack Pivoting: Modify RSP to attacker-controlled stack
 * - Register-based: Pass parameters via registers
 * - Trampoline: Inject minimal stub that calls larger payload
 * - Return-oriented: Modify stack return address
 *
 * ============================================================================
 * DETECTION VECTORS
 * ============================================================================
 *
 * | Detection Method             | Description                             |
 * |------------------------------|-----------------------------------------|
 * | Context Modification Monitor | Track SetThreadContext calls            |
 * | RIP/EIP Validation           | Verify instruction pointer is in module |
 * | Stack Integrity              | Check RSP points to valid stack         |
 * | Cross-Process Context Change | Detect external context modification    |
 * | Thread State Analysis        | Analyze suspend/resume patterns         |
 * | Call Stack Validation        | Verify call stack integrity             |
 * | Register Anomaly Detection   | Detect unusual register values          |
 * | Timing Analysis              | Detect Suspend->SetContext->Resume      |
 *
 * ============================================================================
 * MITRE ATT&CK COVERAGE
 * ============================================================================
 *
 * | Technique ID | Technique Name                 | Detection Method           |
 * |--------------|--------------------------------|----------------------------|
 * | T1055.003    | Thread Execution Hijacking     | Core detection             |
 * | T1055        | Process Injection              | Context monitoring         |
 * | T1106        | Native API                     | NtSetContextThread detect  |
 * | T1574        | Hijack Execution Flow          | RIP modification detect    |
 *
 * ============================================================================
 * THREAD CONTEXT VALIDATION
 * ============================================================================
 *
 * The detector validates these critical CONTEXT members:
 *
 * x64 (AMD64):
 * - Rip: Instruction pointer - must be in valid module
 * - Rsp: Stack pointer - must be in valid stack region
 * - SegCs: Code segment - must be user-mode selector
 * - SegSs: Stack segment - must match Rsp segment
 * - EFlags: Processor flags - check for suspicious flags
 *
 * x86 (i386):
 * - Eip: Instruction pointer
 * - Esp: Stack pointer
 * - SegCs/SegSs: Segment selectors
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

// ============================================================================
// INCLUDES
// ============================================================================

// Internal infrastructure
#include "ProcessMonitor.hpp"
#include "MemoryScanner.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/ErrorUtils.hpp"
#include "../../ThreatIntel/ThreatIntelManager.hpp"
#include "../../Whitelist/WhiteListStore.hpp" // Trusted processes

// Standard library
#include <string>
#include <string_view>
#include <vector>
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
#include <span>
#include <array>
#include <cstdint>

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class ThreadHijackDetectorImpl;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace ThreadHijackConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 4;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Thread context flags
    constexpr uint32_t CONTEXT_CONTROL = 0x00010001;
    constexpr uint32_t CONTEXT_INTEGER = 0x00010002;
    constexpr uint32_t CONTEXT_SEGMENTS = 0x00010004;
    constexpr uint32_t CONTEXT_FLOATING_POINT = 0x00010008;
    constexpr uint32_t CONTEXT_DEBUG_REGISTERS = 0x00010010;
    constexpr uint32_t CONTEXT_FULL = 0x0001001F;

    // x64 segment selectors (typical Windows values)
    constexpr uint16_t USER_CS_64 = 0x33;     ///< User-mode 64-bit code segment
    constexpr uint16_t USER_DS_64 = 0x2B;     ///< User-mode data segment
    constexpr uint16_t USER_SS_64 = 0x2B;     ///< User-mode stack segment
    constexpr uint16_t KERNEL_CS = 0x10;      ///< Kernel-mode code segment

    // x86 segment selectors
    constexpr uint16_t USER_CS_32 = 0x1B;
    constexpr uint16_t USER_DS_32 = 0x23;

    // Detection thresholds
    constexpr uint32_t SUSPEND_DURATION_THRESHOLD_MS = 100;
    constexpr uint32_t CONTEXT_CHANGE_CORRELATION_MS = 1000;
    constexpr uint32_t MAX_THREADS_TO_MONITOR = 65536;
    constexpr uint32_t MAX_CONTEXT_CHANGES_PER_THREAD = 100;

    // Timeouts
    constexpr uint32_t VALIDATION_TIMEOUT_MS = 5000;
    constexpr uint32_t SCAN_TIMEOUT_MS = 30000;

    // Monitoring limits
    constexpr size_t EVENT_QUEUE_SIZE = 8192;
    constexpr size_t MAX_HIJACK_EVENTS = 4096;

    // Call stack analysis
    constexpr uint32_t MAX_STACK_FRAMES = 64;
    constexpr uint32_t MAX_UNBACKED_FRAMES_THRESHOLD = 1;

} // namespace ThreadHijackConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum HijackType
 * @brief Types of thread hijacking attacks.
 */
enum class HijackType : uint8_t {
    Unknown = 0,
    RIPModification = 1,          ///< Direct instruction pointer change
    StackPivot = 2,               ///< Stack pointer changed to attacker stack
    RegisterModification = 3,     ///< Suspicious register value changes
    ReturnAddressOverwrite = 4,   ///< Return address on stack modified
    TrampolineInjection = 5,      ///< Small stub injected
    ContextReplacement = 6,       ///< Full context replaced
    HardwareBreakpoint = 7,       ///< Debug registers modified
    SegmentModification = 8       ///< Segment selectors modified
};

/**
 * @enum DetectionConfidence
 * @brief Confidence level of detection.
 */
enum class DetectionConfidence : uint8_t {
    None = 0,
    Low = 1,              ///< Single weak indicator
    Medium = 2,           ///< Multiple indicators
    High = 3,             ///< Strong indicators
    Confirmed = 4         ///< Definitive evidence
};

/**
 * @enum ThreadState
 * @brief Current state of a monitored thread.
 */
enum class ThreadState : uint8_t {
    Unknown = 0,
    Running = 1,
    Waiting = 2,
    Suspended = 3,
    SuspendedByExternal = 4,      ///< Suspended by another process
    Terminated = 5
};

/**
 * @enum ContextModificationType
 * @brief Type of context modification detected.
 */
enum class ContextModificationType : uint8_t {
    None = 0,
    InstructionPointer = 1,       ///< RIP/EIP changed
    StackPointer = 2,             ///< RSP/ESP changed
    BasePointer = 3,              ///< RBP/EBP changed
    GeneralRegisters = 4,         ///< Other GPRs changed
    SegmentRegisters = 5,         ///< CS/SS/DS/ES/FS/GS changed
    Flags = 6,                    ///< EFLAGS/RFLAGS changed
    DebugRegisters = 7,           ///< DR0-DR7 changed
    FloatingPoint = 8,            ///< FPU/SSE/AVX state
    Full = 9                      ///< Complete context replacement
};

/**
 * @enum MonitoringMode
 * @brief Real-time monitoring mode.
 */
enum class MonitoringMode : uint8_t {
    Disabled = 0,
    PassiveOnly = 1,          ///< Monitor and alert
    Active = 2,               ///< Can block suspicious modifications
    Aggressive = 3            ///< Block all cross-process context changes
};

/**
 * @enum ValidationResult
 * @brief Result of thread context validation.
 */
enum class ValidationResult : uint8_t {
    Valid = 0,
    InvalidRIP = 1,               ///< RIP not in valid module
    InvalidRSP = 2,               ///< RSP not in valid stack
    InvalidSegments = 3,          ///< Invalid segment selectors
    SuspiciousFlags = 4,          ///< Unusual EFLAGS
    UnbackedRIP = 5,              ///< RIP in unbacked memory
    ShellcodeRIP = 6,             ///< RIP points to shellcode
    StackPivoted = 7,             ///< Stack moved to unusual location
    DebugRegistersSet = 8,        ///< Hardware breakpoints active
    MultipleAnomalies = 9         ///< Multiple issues detected
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct ThreadContext64
 * @brief Simplified x64 thread context for analysis.
 */
struct ThreadContext64 {
    // Control registers
    uint64_t rip = 0;                         ///< Instruction pointer
    uint64_t rsp = 0;                         ///< Stack pointer
    uint64_t rbp = 0;                         ///< Base pointer
    uint64_t rflags = 0;                      ///< Flags register

    // General purpose registers
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
    uint64_t rsi = 0, rdi = 0;
    uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0;
    uint64_t r12 = 0, r13 = 0, r14 = 0, r15 = 0;

    // Segment registers
    uint16_t segCs = 0;                       ///< Code segment
    uint16_t segSs = 0;                       ///< Stack segment
    uint16_t segDs = 0;
    uint16_t segEs = 0;
    uint16_t segFs = 0;
    uint16_t segGs = 0;

    // Debug registers
    uint64_t dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0;
    uint64_t dr6 = 0, dr7 = 0;

    // Context flags (what parts are valid)
    uint32_t contextFlags = 0;
};

/**
 * @struct ThreadContext32
 * @brief Simplified x86 thread context for analysis.
 */
struct ThreadContext32 {
    uint32_t eip = 0;
    uint32_t esp = 0;
    uint32_t ebp = 0;
    uint32_t eflags = 0;
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    uint32_t esi = 0, edi = 0;
    uint16_t segCs = 0, segSs = 0;
    uint16_t segDs = 0, segEs = 0;
    uint16_t segFs = 0, segGs = 0;
    uint32_t dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0;
    uint32_t dr6 = 0, dr7 = 0;
    uint32_t contextFlags = 0;
};

/**
 * @struct ContextChange
 * @brief Detected change in thread context.
 */
struct ContextChange {
    ContextModificationType type = ContextModificationType::None;
    std::wstring description;

    // For pointer changes
    uint64_t oldValue = 0;
    uint64_t newValue = 0;

    // For RIP changes
    std::wstring oldModule;                   ///< Module containing old RIP
    std::wstring newModule;                   ///< Module containing new RIP (if any)
    bool newRIPIsBacked = false;
    bool newRIPIsExecutable = false;

    // Risk assessment
    bool isSuspicious = false;
    std::wstring suspicionReason;
};

/**
 * @struct ThreadValidation
 * @brief Result of validating a thread's state.
 */
struct ThreadValidation {
    uint32_t threadId = 0;
    uint32_t ownerPid = 0;
    std::wstring ownerProcessName;
    std::chrono::system_clock::time_point validationTime;

    // Context snapshot
    bool is64Bit = true;
    ThreadContext64 context64;
    ThreadContext32 context32;

    // Instruction pointer validation
    uintptr_t instructionPointer = 0;
    std::wstring ripModule;                   ///< Module containing RIP
    bool ripInKnownModule = false;
    bool ripIsExecutable = false;
    bool ripIsBacked = false;
    bool ripHasShellcodePattern = false;

    // Stack validation
    uintptr_t stackPointer = 0;
    uintptr_t stackBase = 0;                  ///< Stack top (higher address)
    uintptr_t stackLimit = 0;                 ///< Stack bottom (lower address)
    bool stackInValidRange = false;
    bool stackPivoted = false;                ///< Stack moved to unusual location

    // Segment validation
    bool segmentsValid = false;
    std::wstring segmentIssue;

    // Debug register analysis
    bool hasHardwareBreakpoints = false;
    uint32_t activeBreakpointCount = 0;

    // Call stack analysis
    std::vector<uintptr_t> callStack;
    uint32_t unbackedFrameCount = 0;
    std::vector<std::wstring> callStackModules;

    // Overall result
    ValidationResult result = ValidationResult::Valid;
    bool isCompromised = false;
    std::vector<std::wstring> issues;
    uint32_t riskScore = 0;
};

/**
 * @struct HijackEvent
 * @brief Detected thread hijack event.
 */
struct alignas(64) HijackEvent {
    uint64_t eventId = 0;
    std::chrono::system_clock::time_point timestamp;

    // Attacker information
    uint32_t attackerPid = 0;
    std::wstring attackerProcessName;
    std::wstring attackerProcessPath;
    uint32_t attackerTid = 0;

    // Victim information
    uint32_t victimPid = 0;
    std::wstring victimProcessName;
    std::wstring victimProcessPath;
    uint32_t victimTid = 0;

    // Hijack details
    HijackType hijackType = HijackType::Unknown;
    std::vector<ContextChange> contextChanges;

    // Before/After context
    ThreadContext64 beforeContext;
    ThreadContext64 afterContext;

    // Target analysis
    uintptr_t targetAddress = 0;              ///< Where execution was redirected
    std::wstring targetModule;                ///< Module at target (if any)
    bool targetIsUnbacked = false;
    bool targetIsShellcode = false;

    // Attack sequence
    std::chrono::system_clock::time_point suspendTime;
    std::chrono::system_clock::time_point contextChangeTime;
    std::chrono::system_clock::time_point resumeTime;
    uint32_t suspendDurationMs = 0;

    // Detection confidence
    DetectionConfidence confidence = DetectionConfidence::None;
    std::vector<std::wstring> detectionReasons;

    // Risk assessment
    uint32_t riskScore = 0;                   ///< 0-100

    // Response
    bool wasBlocked = false;
    bool contextRestored = false;
    std::wstring mitigationAction;

    // Threat correlation
    bool correlatedWithThreat = false;
    std::wstring threatName;
    std::string mitreAttackId;
};

/**
 * @struct MonitoredThread
 * @brief Information about a thread being monitored.
 */
struct MonitoredThread {
    uint32_t threadId = 0;
    uint32_t ownerPid = 0;
    std::wstring ownerProcessName;
    std::chrono::system_clock::time_point createTime;
    std::chrono::system_clock::time_point lastChecked;

    // State tracking
    ThreadState currentState = ThreadState::Unknown;
    ThreadState previousState = ThreadState::Unknown;
    uint32_t suspendCount = 0;

    // Context baseline
    bool baselineEstablished = false;
    uintptr_t baselineRIP = 0;
    uintptr_t baselineRSP = 0;
    std::wstring baselineModule;

    // Modification history
    uint32_t contextChangeCount = 0;
    std::vector<ContextChange> recentChanges;

    // Monitoring flags
    bool isHighValue = false;                 ///< Main thread, GUI thread, etc.
    bool hasSuspiciousHistory = false;
};

/**
 * @struct ScanResult
 * @brief Result of scanning for thread hijacking.
 */
struct ScanResult {
    std::chrono::system_clock::time_point scanTime;

    // Scope
    uint32_t targetPid = 0;                   ///< 0 for all processes
    uint32_t targetTid = 0;                   ///< 0 for all threads

    // Scan statistics
    uint32_t threadsScanned = 0;
    uint32_t threadsValidated = 0;
    uint32_t compromisedThreadsFound = 0;

    // Validation results
    std::vector<ThreadValidation> validations;
    std::vector<ThreadValidation> compromisedThreads;

    // Detected hijacks
    std::vector<HijackEvent> detectedHijacks;

    // Overall
    bool hijackDetected = false;
    DetectionConfidence highestConfidence = DetectionConfidence::None;
    uint32_t highestRiskScore = 0;

    // Metadata
    uint32_t scanDurationMs = 0;
    bool scanComplete = false;
    std::wstring scanError;
};

/**
 * @struct ThreadHijackConfig
 * @brief Configuration for the detector.
 */
struct ThreadHijackConfig {
    // Monitoring mode
    MonitoringMode mode = MonitoringMode::Active;
    bool enableRealTimeMonitoring = true;
    bool enableOnDemandScanning = true;

    // Detection features
    bool validateInstructionPointer = true;
    bool validateStackPointer = true;
    bool validateSegmentRegisters = true;
    bool checkDebugRegisters = true;
    bool analyzeCallStack = true;
    bool trackContextChanges = true;
    bool detectCrossProcessModification = true;

    // Sensitivity
    DetectionConfidence alertThreshold = DetectionConfidence::Medium;
    uint32_t maxUnbackedFrames = ThreadHijackConstants::MAX_UNBACKED_FRAMES_THRESHOLD;

    // Correlation
    uint32_t contextChangeCorrelationMs = ThreadHijackConstants::CONTEXT_CHANGE_CORRELATION_MS;
    uint32_t suspendDurationThresholdMs = ThreadHijackConstants::SUSPEND_DURATION_THRESHOLD_MS;

    // Response
    bool enableAutoResponse = false;
    bool blockSuspiciousChanges = false;
    bool restoreContext = false;
    bool terminateAttacker = false;

    // Performance
    uint32_t scanTimeoutMs = ThreadHijackConstants::SCAN_TIMEOUT_MS;
    size_t maxThreadsToMonitor = ThreadHijackConstants::MAX_THREADS_TO_MONITOR;

    // Exclusions
    std::vector<std::wstring> excludedProcesses;
    std::vector<uint32_t> excludedPids;

    /**
     * @brief Create default configuration.
     */
    static ThreadHijackConfig CreateDefault() noexcept;

    /**
     * @brief Create high-sensitivity configuration.
     */
    static ThreadHijackConfig CreateHighSensitivity() noexcept;

    /**
     * @brief Create performance-optimized configuration.
     */
    static ThreadHijackConfig CreatePerformance() noexcept;
};

/**
 * @struct ThreadHijackStatistics
 * @brief Runtime statistics for the detector.
 */
struct alignas(64) ThreadHijackStatistics {
    // Thread monitoring
    std::atomic<uint64_t> threadsMonitored{0};
    std::atomic<uint64_t> threadValidations{0};
    std::atomic<uint64_t> contextReads{0};

    // Detection counts
    std::atomic<uint64_t> hijacksDetected{0};
    std::atomic<uint64_t> ripModifications{0};
    std::atomic<uint64_t> stackPivots{0};
    std::atomic<uint64_t> crossProcessChanges{0};
    std::atomic<uint64_t> unbackedRIPDetected{0};
    std::atomic<uint64_t> shellcodeRIPDetected{0};

    // Confidence breakdown
    std::atomic<uint64_t> lowConfidenceDetections{0};
    std::atomic<uint64_t> mediumConfidenceDetections{0};
    std::atomic<uint64_t> highConfidenceDetections{0};
    std::atomic<uint64_t> confirmedHijacks{0};

    // Response actions
    std::atomic<uint64_t> changesBlocked{0};
    std::atomic<uint64_t> contextsRestored{0};
    std::atomic<uint64_t> attackersTerminated{0};

    // Call stack analysis
    std::atomic<uint64_t> callStacksAnalyzed{0};
    std::atomic<uint64_t> unbackedFramesDetected{0};

    // Performance
    std::atomic<uint64_t> totalScanTimeMs{0};
    std::atomic<uint64_t> scansPerformed{0};

    // Errors
    std::atomic<uint64_t> scanErrors{0};
    std::atomic<uint64_t> accessDeniedErrors{0};
    std::atomic<uint64_t> timeoutErrors{0};

    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept;

    /**
     * @brief Get detection rate.
     */
    [[nodiscard]] double GetDetectionRate() const noexcept;
};

// ============================================================================
// CALLBACK DEFINITIONS
// ============================================================================

/**
 * @brief Callback when thread hijack is detected.
 * @param event Hijack event details
 */
using HijackDetectedCallback = std::function<void(
    const HijackEvent& event
)>;

/**
 * @brief Callback when suspicious context change is detected.
 * @param tid Thread ID
 * @param change Context change details
 */
using ContextChangeCallback = std::function<void(
    uint32_t tid,
    const ContextChange& change
)>;

/**
 * @brief Callback for thread validation results.
 * @param validation Validation result
 */
using ValidationCallback = std::function<void(
    const ThreadValidation& validation
)>;

// ============================================================================
// THREAD HIJACK DETECTOR CLASS
// ============================================================================

/**
 * @class ThreadHijackDetector
 * @brief Enterprise-grade thread execution hijacking detection engine.
 *
 * Thread-safety: All public methods are thread-safe.
 * Pattern: Singleton with PIMPL for ABI stability.
 *
 * Usage:
 * @code
 * auto& detector = ThreadHijackDetector::Instance();
 * 
 * // Validate specific thread
 * auto validation = detector.ValidateThread(targetTid);
 * if (validation.isCompromised) {
 *     std::wcout << L"Thread compromised: " << validation.issues[0] << std::endl;
 * }
 * 
 * // Enable real-time monitoring
 * detector.RegisterCallback([](const HijackEvent& event) {
 *     // Handle hijack detection...
 * });
 * detector.StartMonitoring();
 * @endcode
 */
class ThreadHijackDetector {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Get singleton instance.
     * @return Reference to the singleton instance.
     */
    [[nodiscard]] static ThreadHijackDetector& Instance();

    /**
     * @brief Delete copy constructor.
     */
    ThreadHijackDetector(const ThreadHijackDetector&) = delete;

    /**
     * @brief Delete copy assignment.
     */
    ThreadHijackDetector& operator=(const ThreadHijackDetector&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initialize the detector.
     * @param config Configuration settings.
     * @return True if initialization succeeded.
     */
    [[nodiscard]] bool Initialize(
        const ThreadHijackConfig& config = ThreadHijackConfig::CreateDefault()
    );

    /**
     * @brief Shutdown the detector.
     */
    void Shutdown();

    /**
     * @brief Check if detector is initialized.
     * @return True if ready.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Update configuration.
     * @param config New configuration.
     * @return True if applied successfully.
     */
    bool UpdateConfig(const ThreadHijackConfig& config);

    /**
     * @brief Get current configuration.
     * @return Current configuration.
     */
    [[nodiscard]] ThreadHijackConfig GetConfig() const;

    // ========================================================================
    // THREAD VALIDATION
    // ========================================================================

    /**
     * @brief Validate the integrity of a thread's context.
     * @param tid Thread ID.
     * @return Validation result.
     */
    [[nodiscard]] ThreadValidation ValidateThread(uint32_t tid);

    /**
     * @brief Validate start address of a thread.
     * @param tid Thread ID.
     * @return True if start address is valid.
     */
    [[nodiscard]] bool ValidateThreadStart(uint32_t tid);

    /**
     * @brief Validate all threads in a process.
     * @param pid Process ID.
     * @return Validation results for all threads.
     */
    [[nodiscard]] std::vector<ThreadValidation> ValidateProcessThreads(
        uint32_t pid
    );

    /**
     * @brief Check if thread's RIP is in a valid module.
     * @param tid Thread ID.
     * @return True if RIP is backed by a module.
     */
    [[nodiscard]] bool IsRIPValid(uint32_t tid);

    /**
     * @brief Check if thread's stack is in valid range.
     * @param tid Thread ID.
     * @return True if RSP is in valid stack region.
     */
    [[nodiscard]] bool IsStackValid(uint32_t tid);

    /**
     * @brief Get thread's call stack.
     * @param tid Thread ID.
     * @param maxFrames Maximum frames to capture.
     * @return Call stack frames.
     */
    [[nodiscard]] std::vector<uintptr_t> GetCallStack(
        uint32_t tid,
        uint32_t maxFrames = ThreadHijackConstants::MAX_STACK_FRAMES
    );

    /**
     * @brief Count unbacked frames in call stack.
     * @param tid Thread ID.
     * @return Number of frames not in known modules.
     */
    [[nodiscard]] uint32_t CountUnbackedFrames(uint32_t tid);

    // ========================================================================
    // CONTEXT ANALYSIS
    // ========================================================================

    /**
     * @brief Get current thread context.
     * @param tid Thread ID.
     * @return Thread context.
     */
    [[nodiscard]] ThreadContext64 GetThreadContext(uint32_t tid);

    /**
     * @brief Compare two contexts for changes.
     * @param before Previous context.
     * @param after Current context.
     * @return List of changes detected.
     */
    [[nodiscard]] std::vector<ContextChange> CompareContexts(
        const ThreadContext64& before,
        const ThreadContext64& after
    );

    /**
     * @brief Analyze context for suspicious characteristics.
     * @param context Context to analyze.
     * @param pid Owning process ID.
     * @return Validation result.
     */
    [[nodiscard]] ValidationResult AnalyzeContext(
        const ThreadContext64& context,
        uint32_t pid
    );

    /**
     * @brief Check if debug registers are active.
     * @param tid Thread ID.
     * @return True if hardware breakpoints are set.
     */
    [[nodiscard]] bool HasActiveDebugRegisters(uint32_t tid);

    // ========================================================================
    // HIJACK DETECTION
    // ========================================================================

    /**
     * @brief Scan for thread hijacking in a process.
     * @param pid Process ID.
     * @return Scan result.
     */
    [[nodiscard]] ScanResult ScanProcess(uint32_t pid);

    /**
     * @brief Scan all processes for thread hijacking.
     * @return Scan result.
     */
    [[nodiscard]] ScanResult ScanAllProcesses();

    /**
     * @brief Detect hijacking of a specific thread.
     * @param tid Thread ID.
     * @return Hijack event if detected, nullopt otherwise.
     */
    [[nodiscard]] std::optional<HijackEvent> DetectHijack(uint32_t tid);

    /**
     * @brief Get recent hijack events.
     * @return Vector of hijack events.
     */
    [[nodiscard]] std::vector<HijackEvent> GetRecentHijacks() const;

    // ========================================================================
    // REAL-TIME MONITORING
    // ========================================================================

    /**
     * @brief Start real-time monitoring.
     * @return True if monitoring started.
     */
    bool StartMonitoring();

    /**
     * @brief Stop real-time monitoring.
     */
    void StopMonitoring();

    /**
     * @brief Check if monitoring is active.
     * @return True if monitoring.
     */
    [[nodiscard]] bool IsMonitoring() const noexcept;

    /**
     * @brief Set monitoring mode.
     * @param mode New monitoring mode.
     */
    void SetMonitoringMode(MonitoringMode mode);

    /**
     * @brief Get current monitoring mode.
     * @return Current mode.
     */
    [[nodiscard]] MonitoringMode GetMonitoringMode() const noexcept;

    // ========================================================================
    // EVENT HANDLERS (from kernel/ETW)
    // ========================================================================

    /**
     * @brief Notify of thread suspension.
     * @param targetTid Target thread ID.
     * @param suspenderPid Suspending process ID.
     */
    void OnThreadSuspend(uint32_t targetTid, uint32_t suspenderPid);

    /**
     * @brief Notify of thread resume.
     * @param targetTid Target thread ID.
     * @param resumerPid Resuming process ID.
     */
    void OnThreadResume(uint32_t targetTid, uint32_t resumerPid);

    /**
     * @brief Notify of context modification.
     * @param targetTid Target thread ID.
     * @param modifierPid Modifying process ID.
     * @param contextFlags What parts of context were modified.
     */
    void OnContextChange(
        uint32_t targetTid,
        uint32_t modifierPid,
        uint32_t contextFlags
    );

    /**
     * @brief Notify of NtSetContextThread call.
     * @param callerPid Calling process ID.
     * @param targetTid Target thread ID.
     * @param newContext New context being set.
     */
    void OnSetContextThread(
        uint32_t callerPid,
        uint32_t targetTid,
        const ThreadContext64& newContext
    );

    // ========================================================================
    // RESPONSE ACTIONS
    // ========================================================================

    /**
     * @brief Block a context modification.
     * @param targetTid Target thread ID.
     * @param modifierPid Modifying process ID.
     * @return True if blocked successfully.
     */
    bool BlockContextChange(uint32_t targetTid, uint32_t modifierPid);

    /**
     * @brief Restore thread context from baseline.
     * @param tid Thread ID.
     * @return True if restored successfully.
     */
    bool RestoreContext(uint32_t tid);

    /**
     * @brief Terminate the attacking process.
     * @param event Hijack event.
     * @return True if terminated.
     */
    bool TerminateAttacker(const HijackEvent& event);

    // ========================================================================
    // BASELINE MANAGEMENT
    // ========================================================================

    /**
     * @brief Establish baseline context for a thread.
     * @param tid Thread ID.
     */
    void EstablishBaseline(uint32_t tid);

    /**
     * @brief Clear baseline for a thread.
     * @param tid Thread ID.
     */
    void ClearBaseline(uint32_t tid);

    /**
     * @brief Get baseline context for a thread.
     * @param tid Thread ID.
     * @return Baseline context if established.
     */
    [[nodiscard]] std::optional<ThreadContext64> GetBaseline(uint32_t tid) const;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Register callback for hijack detection.
     * @param callback Hijack callback.
     * @return Callback ID.
     */
    uint64_t RegisterCallback(HijackDetectedCallback callback);

    /**
     * @brief Register callback for context changes.
     * @param callback Context change callback.
     * @return Callback ID.
     */
    uint64_t RegisterContextCallback(ContextChangeCallback callback);

    /**
     * @brief Register callback for validation results.
     * @param callback Validation callback.
     * @return Callback ID.
     */
    uint64_t RegisterValidationCallback(ValidationCallback callback);

    /**
     * @brief Unregister a callback.
     * @param callbackId Callback ID.
     */
    void UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    /**
     * @brief Get detector statistics.
     * @return Current statistics.
     */
    [[nodiscard]] ThreadHijackStatistics GetStatistics() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStatistics();

    /**
     * @brief Get version string.
     * @return Version.
     */
    [[nodiscard]] static std::wstring GetVersion() noexcept;

    // ========================================================================
    // UTILITY
    // ========================================================================

    /**
     * @brief Convert hijack type to string.
     * @param type Hijack type.
     * @return String representation.
     */
    [[nodiscard]] static std::wstring HijackTypeToString(
        HijackType type
    ) noexcept;

    /**
     * @brief Convert validation result to string.
     * @param result Validation result.
     * @return String representation.
     */
    [[nodiscard]] static std::wstring ValidationResultToString(
        ValidationResult result
    ) noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (SINGLETON)
    // ========================================================================

    ThreadHijackDetector();
    ~ThreadHijackDetector();

    // ========================================================================
    // IMPLEMENTATION
    // ========================================================================

    std::unique_ptr<ThreadHijackDetectorImpl> m_impl;
};

} // namespace Process
} // namespace Core
} // namespace ShadowStrike
