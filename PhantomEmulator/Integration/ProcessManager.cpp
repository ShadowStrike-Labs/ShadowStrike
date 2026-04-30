/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ProcessManager.cpp — Multi-Process Emulation Manager Implementation
 *
 * Implements the child-process table, injection-detection state machine,
 * payload capture, and event logging described in ProcessManager.hpp.
 *
 * PID allocation mimics Windows: starts at 1000, increments by 4.
 * Process table and event log are strictly bounded by EmulationConfig.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ProcessManager.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_map>

namespace Phantom {

// ============================================================================
// Internal Constants
// ============================================================================

static constexpr uint32_t kStartPID       = 1000;
static constexpr uint32_t kPIDStep        = 4;
static constexpr uint32_t kThreadIDBase   = 2000;
static constexpr uint32_t kThreadIDStep   = 4;
static constexpr size_t   kMaxEvents      = 4096;
static constexpr uint32_t kAbsoluteMaxProcesses = 32;

// ============================================================================
// ProcessManager::Impl
// ============================================================================

struct ProcessManager::Impl {
    // Configuration snapshot — immutable after construction
    bool      enabled          = true;
    uint32_t  maxChildren      = 8;
    GuestSize maxPayloadCapture = 64 * 1024;
    uint64_t  maxTotalInstructions = 0;

    // PID / TID generators
    uint32_t nextPID      = kStartPID;
    uint32_t nextThreadID = kThreadIDBase;

    // Process table (PID → ChildProcess).  Unordered map gives O(1) lookup
    // by PID which is the dominant access pattern from API hooks.
    std::unordered_map<uint32_t, ChildProcess> processes;

    // Chronological event log (bounded to kMaxEvents)
    std::vector<ProcessEvent> events;

    // Global instruction counter aggregated across all children
    uint64_t totalInstructions = 0;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    [[nodiscard]] uint32_t AllocatePID() noexcept {
        const uint32_t pid = nextPID;
        nextPID += kPIDStep;
        return pid;
    }

    [[nodiscard]] uint32_t AllocateThreadID() noexcept {
        const uint32_t tid = nextThreadID;
        nextThreadID += kThreadIDStep;
        return tid;
    }

    ChildProcess* FindProcess(uint32_t pid) noexcept {
        auto it = processes.find(pid);
        return (it != processes.end()) ? &it->second : nullptr;
    }

    const ChildProcess* FindProcess(uint32_t pid) const noexcept {
        auto it = processes.find(pid);
        return (it != processes.end()) ? &it->second : nullptr;
    }

    void RecordEvent(ProcessEvent evt) noexcept {
        if (events.size() >= kMaxEvents) {
            return; // Silently drop — bounded by design
        }
        evt.timestamp = totalInstructions;
        events.push_back(std::move(evt));
    }

    // Advance the hollowing state machine for a given child.
    // Returns true if the stage was advanced.
    bool AdvanceHollowingStage(ChildProcess& child,
                               HollowingStage requiredCurrent,
                               HollowingStage nextStage) noexcept
    {
        if (child.hollowingStage == requiredCurrent) {
            child.hollowingStage = nextStage;
            return true;
        }
        return false;
    }

    // Classify the injection technique based on accumulated operation flags
    // and the hollowing state machine.
    void ClassifyInjection(ChildProcess& child) noexcept {
        // If hollowing state machine reached the terminal state, that wins.
        if (child.hollowingStage == HollowingStage::Resumed) {
            child.detectedTechnique = InjectionTechnique::ProcessHollowing;
            return;
        }

        // Early-bird: suspended creation + APC queue + resumed (without full
        // hollowing sequence)
        if (child.state == ProcessState::Running &&
            HasFlag(child.flags, ProcessCreationFlags::CreateSuspended) &&
            child.hadAPCQueue &&
            !child.hadRemoteThread)
        {
            child.detectedTechnique = InjectionTechnique::EarlyBirdInjection;
            return;
        }

        // Thread hijacking: context modification + resume without unmap
        if (child.hadContextModification &&
            child.hollowingStage < HollowingStage::SectionUnmapped &&
            child.state == ProcessState::Running)
        {
            child.detectedTechnique = InjectionTechnique::ThreadHijacking;
            return;
        }

        // Classic / reflective DLL injection: alloc + write + remote thread
        if (child.hadCrossProcessAlloc &&
            child.hadCrossProcessWrite &&
            child.hadRemoteThread)
        {
            // Heuristic: if any injected region starts with an MZ header or
            // contains a reflective loader stub signature, classify as
            // reflective.  Otherwise classic DLL injection.
            bool hasReflectiveSignature = false;
            for (const auto& region : child.injectedRegions) {
                if (region.data.size() >= 2 &&
                    region.data[0] == 0x4D && region.data[1] == 0x5A)
                {
                    hasReflectiveSignature = true;
                    break;
                }
            }
            child.detectedTechnique = hasReflectiveSignature
                ? InjectionTechnique::ReflectiveDLLInjection
                : InjectionTechnique::ClassicDLLInjection;
            return;
        }

        // APC injection: alloc + write + APC queue (no remote thread)
        if (child.hadCrossProcessAlloc &&
            child.hadCrossProcessWrite &&
            child.hadAPCQueue)
        {
            child.detectedTechnique = InjectionTechnique::APCInjection;
            return;
        }
    }

    // Capture payload data from a cross-process write, respecting the
    // configured capture limit.
    void CapturePayload(ChildProcess& child,
                        GuestAddress addr,
                        ByteSpan data) noexcept
    {
        InjectedRegion region;
        region.base = addr;
        region.size = data.size();

        const auto limit = static_cast<size_t>(maxPayloadCapture);
        if (data.size() <= limit) {
            region.data.assign(data.begin(), data.end());
            region.truncated = false;
        } else {
            region.data.assign(data.begin(), data.begin() + limit);
            region.truncated = true;
        }

        child.injectedRegions.push_back(std::move(region));
    }
};

// ============================================================================
// Construction / Destruction
// ============================================================================

ProcessManager::ProcessManager(const EmulationConfig& config) noexcept
    : m_impl(std::make_unique<Impl>())
{
    m_impl->enabled               = config.enableMultiProcess;
    m_impl->maxChildren           = std::min(config.maxChildProcesses,
                                             kAbsoluteMaxProcesses);
    m_impl->maxPayloadCapture     = config.maxInjectedPayloadCapture;
    m_impl->maxTotalInstructions  = config.maxInstructions;

    // Pre-reserve event vector to avoid repeated small allocations.
    m_impl->events.reserve(256);
}

ProcessManager::~ProcessManager() noexcept = default;

// ============================================================================
// Process Lifecycle
// ============================================================================

uint32_t ProcessManager::CreateChildProcess(
    std::wstring_view     imagePath,
    std::wstring_view     commandLine,
    ProcessCreationFlags  flags,
    uint32_t              parentPid) noexcept
{
    if (!m_impl->enabled) {
        return 0;
    }

    if (m_impl->processes.size() >= m_impl->maxChildren) {
        return 0; // Process limit reached
    }

    const uint32_t pid = m_impl->AllocatePID();
    const uint32_t tid = m_impl->AllocateThreadID();

    ChildProcess child;
    child.processId       = pid;
    child.parentProcessId = parentPid;
    child.mainThreadId    = tid;
    child.flags           = flags;
    // DESIGN: defense-in-depth — even though guest-API readers already cap
    // PE-image paths and command-line lengths, the wstring_view here flows
    // through OnParentPIDAttribute / event logging and downstream UI/IPC
    // serialisers. A hostile guest that bypasses an upstream cap could
    // otherwise inflate the per-process descriptor without bound. Cap
    // each string at 32 KiB chars (Win32 MAX_PATH × 32, well above any
    // legitimate path or command line).
    constexpr size_t kMaxNameChars = 32u * 1024u;
    {
        const auto truncImage = imagePath.size() > kMaxNameChars
                                    ? imagePath.substr(0, kMaxNameChars)
                                    : imagePath;
        const auto truncCmd   = commandLine.size() > kMaxNameChars
                                    ? commandLine.substr(0, kMaxNameChars)
                                    : commandLine;
        child.imagePath   = std::wstring(truncImage);
        child.commandLine = std::wstring(truncCmd);
    }

    // Determine initial state
    if (HasFlag(flags, ProcessCreationFlags::CreateSuspended)) {
        child.state          = ProcessState::Suspended;
        child.hollowingStage = HollowingStage::SuspendedCreation;

        ProcessEvent evt;
        evt.type            = ProcessEvent::Type::Suspended;
        evt.sourceProcessId = parentPid;
        evt.targetProcessId = pid;
        m_impl->RecordEvent(std::move(evt));
    } else {
        child.state = ProcessState::Running;
    }

    // Always log creation
    ProcessEvent createEvt;
    createEvt.type            = ProcessEvent::Type::Created;
    createEvt.sourceProcessId = parentPid;
    createEvt.targetProcessId = pid;
    m_impl->RecordEvent(std::move(createEvt));

    m_impl->processes.emplace(pid, std::move(child));
    return pid;
}

void ProcessManager::TerminateProcess(uint32_t processId,
                                      uint32_t exitCode) noexcept
{
    auto* child = m_impl->FindProcess(processId);
    if (!child) {
        return;
    }

    child->state    = ProcessState::Terminated;
    child->exitCode = exitCode;

    ProcessEvent evt;
    evt.type            = ProcessEvent::Type::Terminated;
    evt.sourceProcessId = child->parentProcessId;
    evt.targetProcessId = processId;
    m_impl->RecordEvent(std::move(evt));
}

bool ProcessManager::ResumeProcess(uint32_t processId) noexcept {
    auto* child = m_impl->FindProcess(processId);
    if (!child) {
        return false;
    }

    if (child->state != ProcessState::Suspended) {
        return false;
    }

    child->state = ProcessState::Running;

    // Advance hollowing state machine if applicable
    if (child->hollowingStage == HollowingStage::ContextModified) {
        child->hollowingStage = HollowingStage::Resumed;

        ProcessEvent hollowEvt;
        hollowEvt.type            = ProcessEvent::Type::HollowingDetected;
        hollowEvt.sourceProcessId = child->parentProcessId;
        hollowEvt.targetProcessId = processId;
        m_impl->RecordEvent(std::move(hollowEvt));
    }

    // Run the classifier — resuming may complete several patterns
    m_impl->ClassifyInjection(*child);

    if (child->detectedTechnique != InjectionTechnique::None) {
        ProcessEvent injEvt;
        injEvt.type            = ProcessEvent::Type::InjectionDetected;
        injEvt.sourceProcessId = child->parentProcessId;
        injEvt.targetProcessId = processId;
        m_impl->RecordEvent(std::move(injEvt));
    }

    ProcessEvent evt;
    evt.type            = ProcessEvent::Type::Resumed;
    evt.sourceProcessId = child->parentProcessId;
    evt.targetProcessId = processId;
    m_impl->RecordEvent(std::move(evt));

    return true;
}

const ChildProcess* ProcessManager::GetProcess(uint32_t processId) const noexcept {
    return m_impl->FindProcess(processId);
}

std::vector<uint32_t> ProcessManager::GetChildProcessIds() const noexcept {
    std::vector<uint32_t> ids;
    ids.reserve(m_impl->processes.size());
    for (const auto& [pid, _] : m_impl->processes) {
        ids.push_back(pid);
    }
    return ids;
}

uint32_t ProcessManager::GetProcessCount() const noexcept {
    return static_cast<uint32_t>(m_impl->processes.size());
}

// ============================================================================
// Cross-Process Memory Operations
// ============================================================================

void ProcessManager::OnCrossProcessWrite(uint32_t targetPid,
                                         GuestAddress addr,
                                         ByteSpan data) noexcept
{
    auto* child = m_impl->FindProcess(targetPid);
    if (!child) {
        return;
    }

    child->hadCrossProcessWrite = true;

    // Capture the payload
    m_impl->CapturePayload(*child, addr, data);

    // Advance hollowing state machine: SectionUnmapped → MemoryWritten
    // Also allow the write to register after SuspendedCreation (some variants
    // skip the unmap step and just overwrite in-place).
    if (child->hollowingStage == HollowingStage::SectionUnmapped ||
        child->hollowingStage == HollowingStage::SuspendedCreation)
    {
        child->hollowingStage = HollowingStage::MemoryWritten;
    }

    ProcessEvent evt;
    evt.type            = ProcessEvent::Type::MemoryWritten;
    evt.sourceProcessId = child->parentProcessId;
    evt.targetProcessId = targetPid;
    evt.address         = addr;
    evt.size            = data.size();
    m_impl->RecordEvent(std::move(evt));
}

void ProcessManager::OnSectionUnmap(uint32_t targetPid,
                                    GuestAddress addr) noexcept
{
    auto* child = m_impl->FindProcess(targetPid);
    if (!child) {
        return;
    }

    // Advance hollowing state machine: SuspendedCreation → SectionUnmapped
    m_impl->AdvanceHollowingStage(*child,
                                  HollowingStage::SuspendedCreation,
                                  HollowingStage::SectionUnmapped);

    ProcessEvent evt;
    evt.type            = ProcessEvent::Type::SectionUnmapped;
    evt.sourceProcessId = child->parentProcessId;
    evt.targetProcessId = targetPid;
    evt.address         = addr;
    m_impl->RecordEvent(std::move(evt));
}

void ProcessManager::OnCrossProcessAlloc(uint32_t targetPid,
                                         GuestAddress /*addr*/,
                                         GuestSize /*size*/,
                                         uint32_t /*protect*/) noexcept
{
    auto* child = m_impl->FindProcess(targetPid);
    if (!child) {
        return;
    }

    child->hadCrossProcessAlloc = true;

    // No dedicated event type for alloc — it is implicitly tracked via the
    // operation flags that feed the injection classifier.
}

void ProcessManager::OnContextModification(uint32_t targetPid,
                                           uint32_t /*threadId*/,
                                           GuestAddress newRIP) noexcept
{
    auto* child = m_impl->FindProcess(targetPid);
    if (!child) {
        return;
    }

    child->hadContextModification = true;

    // Advance hollowing state machine: MemoryWritten → ContextModified
    m_impl->AdvanceHollowingStage(*child,
                                  HollowingStage::MemoryWritten,
                                  HollowingStage::ContextModified);

    ProcessEvent evt;
    evt.type            = ProcessEvent::Type::ContextModified;
    evt.sourceProcessId = child->parentProcessId;
    evt.targetProcessId = targetPid;
    evt.address         = newRIP;
    m_impl->RecordEvent(std::move(evt));
}

void ProcessManager::OnRemoteThreadCreation(uint32_t targetPid,
                                            GuestAddress startAddr,
                                            uint64_t /*parameter*/) noexcept
{
    auto* child = m_impl->FindProcess(targetPid);
    if (!child) {
        return;
    }

    child->hadRemoteThread = true;

    // If enough preconditions are met, classify immediately
    m_impl->ClassifyInjection(*child);

    if (child->detectedTechnique != InjectionTechnique::None) {
        ProcessEvent injEvt;
        injEvt.type            = ProcessEvent::Type::InjectionDetected;
        injEvt.sourceProcessId = child->parentProcessId;
        injEvt.targetProcessId = targetPid;
        injEvt.address         = startAddr;
        m_impl->RecordEvent(std::move(injEvt));
    }

    ProcessEvent evt;
    evt.type            = ProcessEvent::Type::ThreadCreated;
    evt.sourceProcessId = child->parentProcessId;
    evt.targetProcessId = targetPid;
    evt.address         = startAddr;
    m_impl->RecordEvent(std::move(evt));
}

void ProcessManager::OnAPCQueue(uint32_t targetPid,
                                uint32_t /*threadId*/,
                                GuestAddress apcRoutine) noexcept
{
    auto* child = m_impl->FindProcess(targetPid);
    if (!child) {
        return;
    }

    child->hadAPCQueue = true;

    // If the process was created suspended and an APC is queued before resume,
    // this may be an early-bird injection.  Classification happens on resume.

    ProcessEvent evt;
    evt.type            = ProcessEvent::Type::ThreadCreated; // Reuse closest type
    evt.sourceProcessId = child->parentProcessId;
    evt.targetProcessId = targetPid;
    evt.address         = apcRoutine;
    m_impl->RecordEvent(std::move(evt));
}

// ============================================================================
// Hollowing / Injection Detection Queries
// ============================================================================

InjectionTechnique ProcessManager::GetDetectedTechnique(
    uint32_t processId) const noexcept
{
    const auto* child = m_impl->FindProcess(processId);
    return child ? child->detectedTechnique : InjectionTechnique::None;
}

HollowingStage ProcessManager::GetHollowingStage(
    uint32_t processId) const noexcept
{
    const auto* child = m_impl->FindProcess(processId);
    return child ? child->hollowingStage : HollowingStage::None;
}

std::vector<ByteSpan> ProcessManager::GetInjectedPayloads(
    uint32_t processId) const noexcept
{
    std::vector<ByteSpan> payloads;
    const auto* child = m_impl->FindProcess(processId);
    if (!child) {
        return payloads;
    }

    payloads.reserve(child->injectedRegions.size());
    for (const auto& region : child->injectedRegions) {
        if (!region.data.empty()) {
            payloads.emplace_back(region.data);
        }
    }
    return payloads;
}

// ============================================================================
// Parent PID Spoofing Detection
// ============================================================================

void ProcessManager::OnParentPIDAttribute(uint32_t childPid,
                                          uint32_t spoofedParentPid) noexcept
{
    auto* child = m_impl->FindProcess(childPid);
    if (!child) {
        return;
    }

    // The true parent is the one that called CreateProcess (already stored).
    // The spoofed parent is the one specified via
    // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.  If they differ, flag it.
    if (spoofedParentPid != child->parentProcessId) {
        child->detectedTechnique = InjectionTechnique::ParentPIDSpoof;

        ProcessEvent evt;
        evt.type            = ProcessEvent::Type::ParentPIDSpoof;
        evt.sourceProcessId = child->parentProcessId;
        evt.targetProcessId = childPid;
        evt.address         = spoofedParentPid;  // Encode spoofed PID in address field
        m_impl->RecordEvent(std::move(evt));
    }
}

// ============================================================================
// Process Events
// ============================================================================

const std::vector<ProcessEvent>& ProcessManager::GetEvents() const noexcept {
    return m_impl->events;
}

void ProcessManager::ClearEvents() noexcept {
    m_impl->events.clear();
}

// ============================================================================
// Shared Resource Accounting
// ============================================================================

uint64_t ProcessManager::GetTotalInstructions() const noexcept {
    return m_impl->totalInstructions;
}

bool ProcessManager::IsInstructionLimitReached() const noexcept {
    return m_impl->maxTotalInstructions > 0 &&
           m_impl->totalInstructions >= m_impl->maxTotalInstructions;
}

void ProcessManager::AddInstructions(uint32_t processId,
                                     uint64_t count) noexcept
{
    auto* child = m_impl->FindProcess(processId);
    if (child) {
        child->instructionsExecuted += count;
    }
    m_impl->totalInstructions += count;
}

} // namespace Phantom
