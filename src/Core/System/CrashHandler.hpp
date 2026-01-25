/**
 * ============================================================================
 * ShadowStrike Core System - CRASH HANDLER (The Safety Net)
 * ============================================================================
 *
 * @file CrashHandler.hpp
 * @brief Enterprise-grade crash handling, diagnostics, and recovery system.
 *
 * This module provides comprehensive crash handling including minidump
 * generation, exception analysis, automatic recovery, and forensic capture
 * to ensure antivirus reliability and maintainability.
 *
 * Key Capabilities:
 * =================
 * 1. EXCEPTION HANDLING
 *    - SEH (Structured Exception Handling)
 *    - C++ exception catching
 *    - Vectored exception handling
 *    - Unhandled exception fallback
 *
 * 2. MINIDUMP GENERATION
 *    - Full/Mini/Heap dumps
 *    - Automatic dump on crash
 *    - On-demand dump creation
 *    - Symbol-ready dumps
 *
 * 3. CRASH ANALYSIS
 *    - Exception type identification
 *    - Faulting module detection
 *    - Stack trace capture
 *    - Register state snapshot
 *
 * 4. RECOVERY
 *    - Watchdog notification
 *    - Automatic restart
 *    - State preservation
 *    - Graceful degradation
 *
 * 5. TELEMETRY
 *    - Crash statistics
 *    - Error reporting (optional)
 *    - Pattern analysis
 *    - Reliability metrics
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see EventLogger.hpp for crash event logging
 * @see ServiceManager.hpp for service restart
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/SystemUtils.hpp"        // System info for crash context
#include "../../Utils/ProcessUtils.hpp"       // Stack trace, module info
#include "../../Utils/FileUtils.hpp"          // Dump file operations
#include "../../Utils/Logger.hpp"             // Crash logging

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>

namespace ShadowStrike {
namespace Core {
namespace System {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class CrashHandlerImpl;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum ExceptionType
 * @brief Type of exception/crash.
 */
enum class ExceptionType : uint8_t {
    Unknown = 0,
    AccessViolation = 1,           // EXCEPTION_ACCESS_VIOLATION
    StackOverflow = 2,             // EXCEPTION_STACK_OVERFLOW
    ArrayBoundsExceeded = 3,       // EXCEPTION_ARRAY_BOUNDS_EXCEEDED
    IllegalInstruction = 4,        // EXCEPTION_ILLEGAL_INSTRUCTION
    PrivilegedInstruction = 5,     // EXCEPTION_PRIV_INSTRUCTION
    IntegerDivideByZero = 6,       // EXCEPTION_INT_DIVIDE_BY_ZERO
    IntegerOverflow = 7,           // EXCEPTION_INT_OVERFLOW
    FloatDivideByZero = 8,         // EXCEPTION_FLT_DIVIDE_BY_ZERO
    InvalidHandle = 9,             // EXCEPTION_INVALID_HANDLE
    HeapCorruption = 10,           // STATUS_HEAP_CORRUPTION
    GuardPage = 11,                // EXCEPTION_GUARD_PAGE
    CppException = 12,             // C++ throw
    Abort = 13,                    // std::abort
    Assertion = 14,                // Assertion failure
    PureVirtualCall = 15,          // Pure virtual call
    InvalidParameter = 16          // Invalid parameter
};

/**
 * @enum DumpType
 * @brief Type of minidump to create.
 */
enum class DumpType : uint8_t {
    Mini = 0,                      // Minimal dump (stack only)
    Normal = 1,                    // Standard dump
    WithDataSegments = 2,          // Include data segments
    WithFullMemory = 3,            // Full memory dump
    WithHandleData = 4,            // Include handle info
    WithThreadInfo = 5,            // Include all threads
    FilterMemory = 6,              // Privacy-filtered
    Custom = 7
};

/**
 * @enum RecoveryAction
 * @brief Action to take after crash.
 */
enum class RecoveryAction : uint8_t {
    None = 0,
    LogAndContinue = 1,            // Log and try to continue
    RestartService = 2,            // Restart the service
    RestartProcess = 3,            // Restart this process
    NotifyWatchdog = 4,            // Let watchdog decide
    DisableFeature = 5,            // Disable crashing feature
    GracefulShutdown = 6           // Clean shutdown
};

/**
 * @enum CrashSeverity
 * @brief Severity of the crash.
 */
enum class CrashSeverity : uint8_t {
    Recoverable = 0,               // Can continue
    NonCritical = 1,               // Feature failure
    Critical = 2,                  // Service compromised
    Fatal = 3                      // Cannot continue
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct StackFrame
 * @brief Single frame in a stack trace.
 */
struct alignas(64) StackFrame {
    uint64_t instructionPointer{ 0 };
    uint64_t returnAddress{ 0 };
    uint64_t framePointer{ 0 };
    std::wstring moduleName;
    std::wstring functionName;
    std::wstring sourceFile;
    uint32_t lineNumber{ 0 };
    uint64_t displacement{ 0 };
};

/**
 * @struct RegisterState
 * @brief CPU register state at crash.
 */
struct alignas(256) RegisterState {
#ifdef _M_X64
    // General purpose
    uint64_t rax{ 0 }, rbx{ 0 }, rcx{ 0 }, rdx{ 0 };
    uint64_t rsi{ 0 }, rdi{ 0 }, rsp{ 0 }, rbp{ 0 };
    uint64_t r8{ 0 }, r9{ 0 }, r10{ 0 }, r11{ 0 };
    uint64_t r12{ 0 }, r13{ 0 }, r14{ 0 }, r15{ 0 };
    // Special
    uint64_t rip{ 0 };
    uint64_t rflags{ 0 };
    // Segment
    uint16_t cs{ 0 }, ds{ 0 }, es{ 0 }, fs{ 0 }, gs{ 0 }, ss{ 0 };
#else
    // x86 registers
    uint32_t eax{ 0 }, ebx{ 0 }, ecx{ 0 }, edx{ 0 };
    uint32_t esi{ 0 }, edi{ 0 }, esp{ 0 }, ebp{ 0 };
    uint32_t eip{ 0 };
    uint32_t eflags{ 0 };
#endif
};

/**
 * @struct CrashContext
 * @brief Full context of a crash.
 */
struct alignas(256) CrashContext {
    // Exception info
    ExceptionType exceptionType{ ExceptionType::Unknown };
    uint32_t exceptionCode{ 0 };
    uint64_t exceptionAddress{ 0 };
    std::wstring exceptionDescription;
    
    // Access violation specifics
    bool isWriteViolation{ false };
    uint64_t accessAddress{ 0 };
    
    // Process/thread info
    uint32_t processId{ 0 };
    uint32_t threadId{ 0 };
    std::wstring processName;
    
    // Module info
    std::wstring faultingModule;
    uint64_t moduleBaseAddress{ 0 };
    std::wstring moduleVersion;
    
    // Registers
    RegisterState registers;
    
    // Stack trace
    std::vector<StackFrame> stackTrace;
    
    // Memory around crash
    std::vector<uint8_t> memoryNearRIP;     // Code around crash
    std::vector<uint8_t> memoryNearRSP;     // Stack memory
    
    // Severity
    CrashSeverity severity{ CrashSeverity::Critical };
    
    // Timing
    std::chrono::system_clock::time_point crashTime;
    std::chrono::milliseconds uptime{ 0 };
};

/**
 * @struct DumpFileInfo
 * @brief Information about generated dump file.
 */
struct alignas(64) DumpFileInfo {
    std::wstring filePath;
    DumpType dumpType{ DumpType::Normal };
    uint64_t fileSizeBytes{ 0 };
    std::chrono::system_clock::time_point creationTime;
    std::string sha256Hash;
    bool isCompressed{ false };
    bool wasUploaded{ false };
};

/**
 * @struct CrashReport
 * @brief Complete crash report.
 */
struct alignas(256) CrashReport {
    // Identity
    std::wstring reportId;
    uint64_t crashSequence{ 0 };      // Nth crash since install
    
    // Context
    CrashContext context;
    
    // Dump
    DumpFileInfo dumpFile;
    
    // Additional info
    std::wstring osVersion;
    std::wstring avVersion;
    std::wstring machineId;
    std::unordered_map<std::wstring, std::wstring> additionalData;
    
    // Recent activity (from forensic buffer)
    std::vector<std::wstring> recentEvents;
    
    // Recovery
    RecoveryAction actionTaken{ RecoveryAction::None };
    bool recoverySuccessful{ false };
    
    // Status
    bool isReported{ false };
    std::chrono::system_clock::time_point reportTime;
};

/**
 * @struct CrashHandlerConfig
 * @brief Configuration for crash handler.
 */
struct alignas(64) CrashHandlerConfig {
    // Dump settings
    bool createDumpOnCrash{ true };
    DumpType defaultDumpType{ DumpType::Normal };
    std::wstring dumpDirectory;
    uint32_t maxDumpFiles{ 10 };
    bool compressDumps{ true };
    
    // Recovery settings
    RecoveryAction defaultRecoveryAction{ RecoveryAction::NotifyWatchdog };
    bool enableAutoRestart{ true };
    uint32_t maxRestartAttempts{ 3 };
    std::chrono::milliseconds restartCooldown{ 60000 };
    
    // Telemetry settings
    bool enableCrashReporting{ false };
    std::wstring reportingEndpoint;
    bool includeMemoryDump{ false };
    
    // Debug settings
    bool breakOnCrash{ false };       // For attached debuggers
    bool logStackTrace{ true };
    
    static CrashHandlerConfig CreateDefault() noexcept;
    static CrashHandlerConfig CreateDebug() noexcept;
    static CrashHandlerConfig CreateProduction() noexcept;
};

/**
 * @struct CrashHandlerStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) CrashHandlerStatistics {
    std::atomic<uint64_t> totalCrashes{ 0 };
    std::atomic<uint64_t> recoveredCrashes{ 0 };
    std::atomic<uint64_t> fatalCrashes{ 0 };
    std::atomic<uint64_t> dumpsCreated{ 0 };
    std::atomic<uint64_t> dumpsUploaded{ 0 };
    std::atomic<uint64_t> restartAttempts{ 0 };
    std::atomic<uint64_t> handledExceptions{ 0 };
    
    // By type
    std::atomic<uint64_t> accessViolations{ 0 };
    std::atomic<uint64_t> stackOverflows{ 0 };
    std::atomic<uint64_t> heapCorruptions{ 0 };
    std::atomic<uint64_t> cppExceptions{ 0 };
    
    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using PreCrashCallback = std::function<void(const CrashContext& context)>;
using PostCrashCallback = std::function<void(const CrashReport& report)>;
using RecoveryCallback = std::function<RecoveryAction(const CrashContext& context)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class CrashHandler
 * @brief Enterprise-grade crash handling system.
 *
 * Thread-safe singleton providing comprehensive crash handling
 * with dump generation, analysis, and recovery capabilities.
 */
class CrashHandler {
public:
    /**
     * @brief Gets singleton instance.
     */
    static CrashHandler& Instance();
    
    /**
     * @brief Initializes crash handler (installs exception handlers).
     */
    bool Initialize(const CrashHandlerConfig& config);
    
    /**
     * @brief Shuts down crash handler.
     */
    void Shutdown() noexcept;
    
    // ========================================================================
    // DUMP CREATION
    // ========================================================================
    
    /**
     * @brief Creates a minidump of current process.
     */
    [[nodiscard]] DumpFileInfo CreateDump(
        DumpType type = DumpType::Normal,
        const std::wstring& reason = L"ManualDump");
    
    /**
     * @brief Creates a minidump of another process.
     */
    [[nodiscard]] DumpFileInfo CreateProcessDump(
        uint32_t processId,
        DumpType type = DumpType::Normal);
    
    /**
     * @brief Gets list of existing dump files.
     */
    [[nodiscard]] std::vector<DumpFileInfo> GetDumpFiles() const;
    
    /**
     * @brief Deletes old dump files.
     */
    uint32_t CleanupOldDumps(std::chrono::hours maxAge = std::chrono::hours(168));
    
    // ========================================================================
    // CRASH ANALYSIS
    // ========================================================================
    
    /**
     * @brief Analyzes an exception.
     */
    [[nodiscard]] CrashContext AnalyzeException(void* exceptionPointers) const;
    
    /**
     * @brief Gets stack trace for current thread.
     */
    [[nodiscard]] std::vector<StackFrame> CaptureStackTrace(
        uint32_t maxFrames = 64) const;
    
    /**
     * @brief Gets stack trace for another thread.
     */
    [[nodiscard]] std::vector<StackFrame> CaptureThreadStackTrace(
        uint32_t threadId,
        uint32_t maxFrames = 64) const;
    
    // ========================================================================
    // CRASH HISTORY
    // ========================================================================
    
    /**
     * @brief Gets crash history.
     */
    [[nodiscard]] std::vector<CrashReport> GetCrashHistory() const;
    
    /**
     * @brief Gets most recent crash.
     */
    [[nodiscard]] std::optional<CrashReport> GetLastCrash() const;
    
    /**
     * @brief Clears crash history.
     */
    void ClearCrashHistory();
    
    // ========================================================================
    // WATCHDOG INTEGRATION
    // ========================================================================
    
    /**
     * @brief Registers watchdog process for notifications.
     */
    void RegisterWatchdog(uint32_t watchdogProcessId);
    
    /**
     * @brief Sends heartbeat to watchdog.
     */
    void SendHeartbeat();
    
    /**
     * @brief Notifies watchdog of impending restart.
     */
    void NotifyWatchdogRestart();
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Registers pre-crash callback (called before dump creation).
     */
    uint64_t RegisterPreCrashCallback(PreCrashCallback callback);
    
    /**
     * @brief Unregisters pre-crash callback.
     */
    void UnregisterPreCrashCallback(uint64_t callbackId);
    
    /**
     * @brief Registers post-crash callback (called after crash handling).
     */
    uint64_t RegisterPostCrashCallback(PostCrashCallback callback);
    
    /**
     * @brief Unregisters post-crash callback.
     */
    void UnregisterPostCrashCallback(uint64_t callbackId);
    
    /**
     * @brief Registers recovery decision callback.
     */
    void SetRecoveryCallback(RecoveryCallback callback);
    
    // ========================================================================
    // MANUAL CRASH SIMULATION
    // ========================================================================
    
    /**
     * @brief Triggers a controlled crash (for testing).
     */
    [[noreturn]] void TriggerCrash(ExceptionType type = ExceptionType::AccessViolation);
    
    /**
     * @brief Triggers an assertion failure.
     */
    [[noreturn]] void TriggerAssertion(
        const char* expression,
        const char* file,
        int line);
    
    // ========================================================================
    // FEATURE CONTROL
    // ========================================================================
    
    /**
     * @brief Disables crash handling temporarily.
     */
    void DisableHandling() noexcept;
    
    /**
     * @brief Re-enables crash handling.
     */
    void EnableHandling() noexcept;
    
    /**
     * @brief Checks if crash handling is enabled.
     */
    [[nodiscard]] bool IsHandlingEnabled() const noexcept;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] const CrashHandlerStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    CrashHandler();
    ~CrashHandler();
    
    CrashHandler(const CrashHandler&) = delete;
    CrashHandler& operator=(const CrashHandler&) = delete;
    
    std::unique_ptr<CrashHandlerImpl> m_impl;
};

// ============================================================================
// ASSERTION MACRO
// ============================================================================

#define SS_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            ShadowStrike::Core::System::CrashHandler::Instance().TriggerAssertion( \
                #expr, __FILE__, __LINE__); \
        } \
    } while (false)

#define SS_ASSERT_MSG(expr, msg) \
    do { \
        if (!(expr)) { \
            ShadowStrike::Core::System::CrashHandler::Instance().TriggerAssertion( \
                msg, __FILE__, __LINE__); \
        } \
    } while (false)

}  // namespace System
}  // namespace Core
}  // namespace ShadowStrike
