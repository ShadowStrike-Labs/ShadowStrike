/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ProcessManager.hpp — Multi-Process Emulation Manager
 *
 * Tracks child processes spawned during emulation and detects multi-process
 * attack techniques: process hollowing, classic/reflective DLL injection,
 * APC injection, early-bird injection, thread hijacking, and parent-PID
 * spoofing.  Every cross-process memory operation feeds a per-target state
 * machine that classifies the injection technique and captures the injected
 * payload for downstream YARA scanning.
 *
 * Thread safety: NOT internally synchronised — driven from the single-
 * threaded emulation loop, same as EmulationSession.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Phantom {

// Forward declarations
class EmulationSession;

// ============================================================================
// Process Creation Flags (matching Win32 constants)
// ============================================================================

enum class ProcessCreationFlags : uint32_t {
    None                = 0,
    CreateSuspended     = 0x00000004,
    DetachedProcess     = 0x00000008,
    CreateNewConsole    = 0x00000010,
    CreateNoWindow      = 0x08000000,
    ExtendedStartupInfo = 0x00080000,
};

[[nodiscard]] constexpr ProcessCreationFlags operator|(
    ProcessCreationFlags a, ProcessCreationFlags b) noexcept
{
    return static_cast<ProcessCreationFlags>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

[[nodiscard]] constexpr ProcessCreationFlags operator&(
    ProcessCreationFlags a, ProcessCreationFlags b) noexcept
{
    return static_cast<ProcessCreationFlags>(
        static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

[[nodiscard]] constexpr bool HasFlag(ProcessCreationFlags flags,
                                     ProcessCreationFlags test) noexcept
{
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(test)) != 0;
}

// ============================================================================
// Process State
// ============================================================================

enum class ProcessState : uint8_t {
    Created,          // Just created, not yet started
    Suspended,        // Created with CREATE_SUSPENDED
    Running,          // Actively executing
    WaitingForChild,  // Parent waiting on child
    Terminated,       // Process has exited
};

// ============================================================================
// Process Hollowing Detection State Machine
// ============================================================================

enum class HollowingStage : uint8_t {
    None,
    SuspendedCreation,   // CreateProcess(SUSPENDED) detected
    SectionUnmapped,     // NtUnmapViewOfSection on child
    MemoryWritten,       // WriteProcessMemory to child
    ContextModified,     // SetThreadContext (entry point changed)
    Resumed,             // ResumeThread — hollowing complete
};

// ============================================================================
// Injection Technique Classification
// ============================================================================

enum class InjectionTechnique : uint8_t {
    None,
    ProcessHollowing,        // Classic hollowing
    ClassicDLLInjection,     // VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibrary)
    ReflectiveDLLInjection,  // Same but with reflective loader stub
    APCInjection,            // QueueUserAPC to suspended thread
    AtomBombing,             // GlobalAddAtom + NtQueueApcThread
    ProcessDoppelganging,    // NtCreateTransaction + ... + NtCreateProcessEx
    EarlyBirdInjection,      // CreateProcess(SUSPENDED) + QueueUserAPC before main thread runs
    ThreadHijacking,         // SuspendThread + SetThreadContext + ResumeThread
    ParentPIDSpoof,          // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
};

// ============================================================================
// Injected Memory Region
// ============================================================================

struct InjectedRegion {
    GuestAddress          base      = 0;
    GuestSize             size      = 0;
    std::vector<uint8_t>  data;       // Captured payload (bounded by config)
    bool                  truncated = false;  // true if payload exceeded capture limit
};

// ============================================================================
// Child Process Descriptor
// ============================================================================

struct ChildProcess {
    uint32_t              processId       = 0;
    uint32_t              parentProcessId = 0;
    uint32_t              mainThreadId    = 0;
    ProcessState          state           = ProcessState::Created;
    ProcessCreationFlags  flags           = ProcessCreationFlags::None;

    // Image information
    std::wstring          imagePath;
    std::wstring          commandLine;

    // Hollowing / injection tracking
    HollowingStage        hollowingStage    = HollowingStage::None;
    InjectionTechnique    detectedTechnique = InjectionTechnique::None;

    // Memory written by parent (for hollowing / injection analysis)
    std::vector<InjectedRegion> injectedRegions;

    // Cross-process operation flags (used by the injection classifier)
    bool hadCrossProcessAlloc  = false;
    bool hadCrossProcessWrite  = false;
    bool hadRemoteThread       = false;
    bool hadAPCQueue           = false;
    bool hadContextModification = false;

    // Execution statistics
    uint64_t              instructionsExecuted = 0;
    uint32_t              exitCode             = 0;
};

// ============================================================================
// Inter-Process Event (for behaviour analysis pipeline)
// ============================================================================

struct ProcessEvent {
    enum class Type : uint8_t {
        Created,
        Suspended,
        Resumed,
        Terminated,
        MemoryWritten,
        SectionUnmapped,
        ContextModified,
        ThreadCreated,
        HollowingDetected,
        InjectionDetected,
        ParentPIDSpoof,
    };

    Type          type            = Type::Created;
    uint32_t      sourceProcessId = 0;
    uint32_t      targetProcessId = 0;
    GuestAddress  address         = 0;
    GuestSize     size            = 0;
    uint64_t      timestamp       = 0;  // Global instruction count at event time
};

// ============================================================================
// ProcessManager — Multi-Process Emulation Manager
// ============================================================================
//
// Owns the table of child processes spawned during emulation and implements
// the injection-detection state machine.  Designed to be held by the
// EmulationSession::Impl and called from API hooks (CreateProcessW/A,
// NtWriteVirtualMemory, NtUnmapViewOfSection, etc.).
//
// All public methods are noexcept.  Error conditions (process-limit reached,
// unknown PID) are communicated through return values and event logging
// rather than exceptions — consistent with the rest of the hot-path
// emulation infrastructure.

class ProcessManager {
public:
    explicit ProcessManager(const EmulationConfig& config) noexcept;
    ~ProcessManager() noexcept;

    ProcessManager(const ProcessManager&)            = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;

    // ========================================================================
    // Process Lifecycle
    // ========================================================================

    /// Create a child process.  Returns the new PID, or 0 on failure
    /// (e.g. process limit reached).
    [[nodiscard]] uint32_t CreateChildProcess(
        std::wstring_view     imagePath,
        std::wstring_view     commandLine,
        ProcessCreationFlags  flags,
        uint32_t              parentPid = 1) noexcept;

    /// Terminate a child process by PID.
    void TerminateProcess(uint32_t processId, uint32_t exitCode) noexcept;

    /// Resume a suspended process (maps to ResumeThread on main thread).
    [[nodiscard]] bool ResumeProcess(uint32_t processId) noexcept;

    /// Look up a child process (read-only).  Returns nullptr if not found.
    [[nodiscard]] const ChildProcess* GetProcess(uint32_t processId) const noexcept;

    /// Return PIDs of all tracked child processes.
    [[nodiscard]] std::vector<uint32_t> GetChildProcessIds() const noexcept;

    /// Return current child-process count.
    [[nodiscard]] uint32_t GetProcessCount() const noexcept;

    // ========================================================================
    // Cross-Process Memory Operations  (Injection Detection)
    // ========================================================================

    /// Called when WriteProcessMemory targets a child.
    void OnCrossProcessWrite(uint32_t targetPid, GuestAddress addr,
                             ByteSpan data) noexcept;

    /// Called when NtUnmapViewOfSection targets a child.
    void OnSectionUnmap(uint32_t targetPid, GuestAddress addr) noexcept;

    /// Called when VirtualAllocEx targets a child.
    void OnCrossProcessAlloc(uint32_t targetPid, GuestAddress addr,
                             GuestSize size, uint32_t protect) noexcept;

    /// Called when SetThreadContext targets a child's thread.
    void OnContextModification(uint32_t targetPid, uint32_t threadId,
                               GuestAddress newRIP) noexcept;

    /// Called when CreateRemoteThread targets a child.
    void OnRemoteThreadCreation(uint32_t targetPid, GuestAddress startAddr,
                                uint64_t parameter) noexcept;

    /// Called when QueueUserAPC targets a child's thread.
    void OnAPCQueue(uint32_t targetPid, uint32_t threadId,
                    GuestAddress apcRoutine) noexcept;

    // ========================================================================
    // Hollowing / Injection Detection Queries
    // ========================================================================

    [[nodiscard]] InjectionTechnique GetDetectedTechnique(uint32_t processId) const noexcept;
    [[nodiscard]] HollowingStage    GetHollowingStage(uint32_t processId) const noexcept;
    [[nodiscard]] std::vector<ByteSpan> GetInjectedPayloads(uint32_t processId) const noexcept;

    // ========================================================================
    // Parent PID Spoofing Detection
    // ========================================================================

    void OnParentPIDAttribute(uint32_t childPid, uint32_t spoofedParentPid) noexcept;

    // ========================================================================
    // Process Events (for behaviour analysis)
    // ========================================================================

    [[nodiscard]] const std::vector<ProcessEvent>& GetEvents() const noexcept;
    void ClearEvents() noexcept;

    // ========================================================================
    // Shared Resource Accounting
    // ========================================================================

    /// Aggregate instruction count across ALL child processes.
    [[nodiscard]] uint64_t GetTotalInstructions() const noexcept;

    /// True when the aggregate instruction budget is exhausted.
    [[nodiscard]] bool IsInstructionLimitReached() const noexcept;

    /// Increment instruction counter for a specific child process.
    void AddInstructions(uint32_t processId, uint64_t count) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
