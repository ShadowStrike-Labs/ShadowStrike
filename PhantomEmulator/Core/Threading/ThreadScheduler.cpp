/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "ThreadScheduler.hpp"
#include "../../Common/Constants.hpp"
#include <algorithm>
#include <cstring>
#include <limits>

namespace Phantom {

// ============================================================================
// Constants
// ============================================================================

// Ticks-per-millisecond approximation for Sleep / timeout accounting.
// One "tick" equals one instruction executed by any thread.
// At ~50 MIPS emulated throughput, 1 ms ≈ 50 000 instructions.
// We use a conservative 1000 ticks/ms so that timeouts don't expire too fast
// relative to the amount of guest work performed.
static constexpr uint64_t kTicksPerMs = 1000;

// Guard value for infinite timeouts (matches INFINITE = 0xFFFFFFFF on Windows).
static constexpr uint32_t kInfiniteTimeout = 0xFFFFFFFF;

// ============================================================================
// Construction / Destruction
// ============================================================================

ThreadScheduler::ThreadScheduler(const EmulationConfig& config) noexcept
    : m_config(config)
{
    m_threads.reserve(config.maxThreads);
}

ThreadScheduler::~ThreadScheduler() noexcept = default;

// ============================================================================
// Thread Lifecycle
// ============================================================================

uint32_t ThreadScheduler::CreateThread(
    GuestAddress startAddr,
    uint64_t parameter,
    GuestAddress stackBase,
    GuestSize stackSize,
    bool suspended)
{
    if (m_threads.size() >= m_config.maxThreads) {
        return 0;  // Thread limit exceeded.
    }

    uint32_t tid = m_nextThreadId++;

    ThreadContext ctx;
    ctx.threadId       = tid;
    ctx.ownerProcessId = 1;
    ctx.startAddress   = startAddr;
    ctx.stackBase      = stackBase;
    ctx.stackSize      = stackSize;

    if (suspended) {
        ctx.state = ThreadState::Suspended;
    } else {
        ctx.state = ThreadState::Ready;
    }

    // Initialize the per-thread CPU state.
    if (m_config.cpuMode == CPUMode::Long64) {
        ctx.cpuState.Reset64();
    } else {
        ctx.cpuState.Reset32();
    }

    ctx.cpuState.SetRIP(startAddr);

    // Set up the stack pointer.  The stack grows downward:
    //   RSP = stackBase + stackSize - 8  (leave room for alignment/return address)
    GuestAddress stackTop = stackBase + stackSize - 8;
    ctx.cpuState.SetReg64(GPR::RSP, stackTop);
    ctx.cpuState.SetReg64(GPR::RBP, stackTop);

    // Pass the thread parameter in RCX (x64 calling convention) or on the stack (x86).
    if (m_config.cpuMode == CPUMode::Long64) {
        ctx.cpuState.SetReg64(GPR::RCX, parameter);
    } else {
        // x86 __stdcall: parameter is pushed on the stack.
        // We simply store it at [RSP+4] (after the return address placeholder).
        // The actual push will be handled when the scheduler writes memory.
    }

    ctx.priority          = 8;
    ctx.lastScheduledTick = m_globalTick;
    ctx.quantum           = 2000;

    m_threads.push_back(std::move(ctx));
    return tid;
}

void ThreadScheduler::TerminateThread(uint32_t threadId, uint32_t exitCode)
{
    auto* t = FindThread(threadId);
    if (!t) return;
    if (t->state == ThreadState::Terminated) return;

    t->state    = ThreadState::Terminated;
    t->exitCode = exitCode;
    t->ClearWait();

    // Remove from all sync object wait queues so we don't pollute the graph.
    m_syncStore.RemoveWaiterFromAll(threadId);
}

void ThreadScheduler::SuspendThread(uint32_t threadId)
{
    auto* t = FindThread(threadId);
    if (!t) return;

    // Only suspend running or ready threads.
    if (t->state == ThreadState::Running || t->state == ThreadState::Ready) {
        t->state = ThreadState::Suspended;
    }
}

void ThreadScheduler::ResumeThread(uint32_t threadId)
{
    auto* t = FindThread(threadId);
    if (!t) return;

    if (t->state == ThreadState::Suspended) {
        t->state = ThreadState::Ready;
    }
}

// ============================================================================
// Current Thread Accessors
// ============================================================================

ThreadContext* ThreadScheduler::GetCurrentThread() noexcept
{
    if (m_threads.empty()) return nullptr;
    if (m_currentThreadIndex >= m_threads.size()) return nullptr;
    auto& t = m_threads[m_currentThreadIndex];
    if (t.state == ThreadState::Running) return &t;
    return nullptr;
}

const ThreadContext* ThreadScheduler::GetCurrentThread() const noexcept
{
    if (m_threads.empty()) return nullptr;
    if (m_currentThreadIndex >= m_threads.size()) return nullptr;
    const auto& t = m_threads[m_currentThreadIndex];
    if (t.state == ThreadState::Running) return &t;
    return nullptr;
}

uint32_t ThreadScheduler::GetCurrentThreadId() const noexcept
{
    const auto* t = GetCurrentThread();
    return t ? t->threadId : 0;
}

// ============================================================================
// Core Scheduling Loop — RunQuantum
// ============================================================================
// Selects the next runnable thread, context-switches onto the CPU, executes
// up to `quantum` instructions, then context-switches back.

uint32_t ThreadScheduler::RunQuantum(
    CPU& cpu,
    VirtualMemory& memory,
    MemoryTracker* tracker)
{
    // Process wait timeouts before selecting the next thread.
    CheckWaitTimeouts();

    // If the current thread is still running but a yield was requested,
    // transition it back to Ready.
    if (m_yieldRequested) {
        auto* cur = GetCurrentThread();
        if (cur && cur->state == ThreadState::Running) {
            SaveThreadState(*cur, cpu);
            cur->state = ThreadState::Ready;
        }
        m_yieldRequested = false;
    }

    // Select the next thread to run.
    auto nextIdx = SelectNextThread();
    if (!nextIdx.has_value()) {
        return 0;  // All threads blocked or terminated.
    }

    // Context switch: save the old thread, load the new one.
    uint32_t oldIdx = m_currentThreadIndex;

    // If the old thread is still Running (quantum expired, not yielded/waited),
    // save its state and move it to Ready.
    if (oldIdx < m_threads.size() && m_threads[oldIdx].state == ThreadState::Running) {
        SaveThreadState(m_threads[oldIdx], cpu);
        m_threads[oldIdx].state = ThreadState::Ready;
    }

    m_currentThreadIndex = nextIdx.value();
    auto& thread = m_threads[m_currentThreadIndex];

    thread.state = ThreadState::Running;
    thread.lastScheduledTick = m_globalTick;
    thread.contextSwitchCount++;

    LoadThreadState(thread, cpu);

    // Deliver any pending APCs before executing guest code.
    DeliverAPCs(thread, cpu, memory);

    // Execute the quantum.
    uint32_t instructionsThisQuantum = 0;
    uint32_t quantumLimit = thread.quantum;

    // Build a per-quantum config with a capped instruction limit so the CPU
    // stops after the quantum even if the global budget is larger.
    EmulationConfig quantumConfig = m_config;
    quantumConfig.maxInstructions = quantumLimit;

    auto result = cpu.Execute(memory, tracker, quantumConfig);

    instructionsThisQuantum = static_cast<uint32_t>(result.instructionsExecuted);
    thread.instructionsExecuted += instructionsThisQuantum;
    m_globalTick += instructionsThisQuantum;

    // Save back state after execution.
    SaveThreadState(thread, cpu);

    // Handle stop reasons that terminate this thread.
    switch (result.reason) {
        case StopReason::ExitProcess:
            // ExitProcess terminates ALL threads.
            for (auto& t : m_threads) {
                if (t.state != ThreadState::Terminated) {
                    t.state = ThreadState::Terminated;
                    t.exitCode = 0;
                }
            }
            break;

        case StopReason::AccessViolation:
        case StopReason::InvalidInstruction:
        case StopReason::StackOverflow:
        case StopReason::DivideByZero:
        case StopReason::Crashed:
            TerminateThread(thread.threadId, 0xC0000005);
            break;

        case StopReason::InstructionLimit:
            // Quantum expired normally — thread remains runnable.
            if (thread.state == ThreadState::Running) {
                thread.state = ThreadState::Ready;
            }
            break;

        case StopReason::APICallTrap:
            // API call may have changed thread state (e.g., WaitForSingleObject).
            // State transitions are handled by the API hooks calling our
            // WaitOnHandle/Sleep/etc. methods. Just leave the thread as-is
            // unless it's still Running.
            break;

        case StopReason::Breakpoint:
        case StopReason::Syscall:
            // These are informational — thread stays runnable.
            break;

        default:
            // For any other reason (UserAborted, TimeLimit, etc.), stop scheduling.
            break;
    }

    return instructionsThisQuantum;
}

// ============================================================================
// Yield
// ============================================================================

void ThreadScheduler::Yield()
{
    m_yieldRequested = true;
}

// ============================================================================
// Wait State Management
// ============================================================================

void ThreadScheduler::WaitOnHandle(uint32_t handle, uint32_t timeoutMs)
{
    auto* t = GetCurrentThread();
    if (!t) return;

    // Try to acquire immediately.
    bool acquired = false;

    if (m_syncStore.HandleExists(handle)) {
        // Try mutex first, then event, then semaphore.
        acquired = m_syncStore.TryAcquireMutex(handle, t->threadId);
        if (!acquired) {
            acquired = m_syncStore.TryWaitEvent(handle);
        }
        if (!acquired) {
            acquired = m_syncStore.TryAcquireSemaphore(handle);
        }
    }

    if (acquired) {
        // Object was signaled — no need to wait.
        return;
    }

    // Must wait.
    t->state = ThreadState::Waiting;
    t->waitInfo.type          = WaitInfo::WaitType::SingleObject;
    t->waitInfo.waitHandles   = { handle };
    t->waitInfo.waitAll       = false;
    t->waitInfo.waitStartTick = m_globalTick;
    t->waitInfo.timeoutMs     = timeoutMs;

    m_syncStore.AddWaiter(handle, t->threadId);
}

void ThreadScheduler::WaitOnMultiple(
    const std::vector<uint32_t>& handles,
    bool waitAll,
    uint32_t timeoutMs)
{
    auto* t = GetCurrentThread();
    if (!t) return;

    if (handles.empty()) return;

    if (!waitAll) {
        // WaitAny: try each handle; if any is immediately acquired, return.
        for (uint32_t h : handles) {
            bool acquired = m_syncStore.TryAcquireMutex(h, t->threadId) ||
                            m_syncStore.TryWaitEvent(h)                 ||
                            m_syncStore.TryAcquireSemaphore(h);
            if (acquired) return;
        }
    } else {
        // WaitAll: all handles must be signaled.  We don't acquire any until
        // all are available (two-phase check).
        bool allAvailable = true;
        for (uint32_t h : handles) {
            if (!m_syncStore.HandleExists(h)) {
                allAvailable = false;
                break;
            }
            // Peek without consuming — we need to check all before committing.
            // For simplicity, we skip the optimistic path and go straight to wait.
            allAvailable = false;
            break;
        }
        // If all were available we'd acquire them here, but the peek-without-
        // consuming model is complex. For correctness, always wait.
        if (allAvailable) {
            // Acquire each one.
            for (uint32_t h : handles) {
                m_syncStore.TryAcquireMutex(h, t->threadId);
                m_syncStore.TryWaitEvent(h);
                m_syncStore.TryAcquireSemaphore(h);
            }
            return;
        }
    }

    // Must wait on all specified handles.
    t->state = ThreadState::Waiting;
    t->waitInfo.type          = WaitInfo::WaitType::MultipleObjects;
    t->waitInfo.waitHandles   = handles;
    t->waitInfo.waitAll       = waitAll;
    t->waitInfo.waitStartTick = m_globalTick;
    t->waitInfo.timeoutMs     = timeoutMs;

    for (uint32_t h : handles) {
        m_syncStore.AddWaiter(h, t->threadId);
    }
}

void ThreadScheduler::Sleep(uint32_t milliseconds)
{
    auto* t = GetCurrentThread();
    if (!t) return;

    if (milliseconds == 0) {
        // Sleep(0) = yield without blocking.
        Yield();
        return;
    }

    t->state = ThreadState::Waiting;
    t->waitInfo.type          = WaitInfo::WaitType::Sleep;
    t->waitInfo.waitHandles.clear();
    t->waitInfo.waitAll       = false;
    t->waitInfo.waitStartTick = m_globalTick;
    t->waitInfo.timeoutMs     = milliseconds;
}

void ThreadScheduler::SignalHandle(uint32_t handle)
{
    auto woken = m_syncStore.Signal(handle);

    for (uint32_t tid : woken) {
        auto* t = FindThread(tid);
        if (!t) continue;

        if (t->state == ThreadState::Waiting) {
            bool canWake = true;

            if (t->waitInfo.type == WaitInfo::WaitType::MultipleObjects && t->waitInfo.waitAll) {
                // WaitAll: check that ALL handles the thread is waiting on are now satisfied.
                for (uint32_t h : t->waitInfo.waitHandles) {
                    if (h == handle) continue;  // This one was just signaled.
                    // Check if the other handles are signaled.
                    bool otherSignaled =
                        m_syncStore.TryAcquireMutex(h, tid) ||
                        m_syncStore.TryWaitEvent(h) ||
                        m_syncStore.TryAcquireSemaphore(h);
                    if (!otherSignaled) {
                        canWake = false;
                        break;
                    }
                }
            }

            if (canWake) {
                t->state = ThreadState::Ready;
                t->ClearWait();
                m_syncStore.RemoveWaiterFromAll(tid);
            }
        }
    }
}

// ============================================================================
// APC Support
// ============================================================================

void ThreadScheduler::QueueUserAPC(uint32_t threadId, GuestAddress routine, uint64_t parameter)
{
    auto* t = FindThread(threadId);
    if (!t) return;
    if (t->state == ThreadState::Terminated) return;

    // Cap APC queue to prevent unbounded growth.
    static constexpr size_t kMaxAPCQueueSize = 256;
    if (t->apcQueue.size() >= kMaxAPCQueueSize) return;

    APCEntry entry;
    entry.routine   = routine;
    entry.parameter = parameter;
    t->apcQueue.push_back(entry);

    // If the thread is in an alertable wait (WaitType::APC or Sleep), wake it.
    if (t->state == ThreadState::Waiting &&
        (t->waitInfo.type == WaitInfo::WaitType::APC ||
         t->waitInfo.type == WaitInfo::WaitType::Sleep))
    {
        t->state = ThreadState::Ready;
        t->ClearWait();
        m_syncStore.RemoveWaiterFromAll(threadId);
    }
}

// ============================================================================
// TLS Support
// ============================================================================

uint32_t ThreadScheduler::TlsAlloc()
{
    for (uint32_t i = 0; i < kMaxTLSSlots; ++i) {
        if (!m_tlsAllocated.test(i)) {
            m_tlsAllocated.set(i);
            // Zero the slot in all threads.
            for (auto& t : m_threads) {
                t.tlsSlots[i] = 0;
            }
            return i;
        }
    }
    return kMaxTLSSlots; // Failure — no free slots (caller interprets as TLS_OUT_OF_INDEXES).
}

void ThreadScheduler::TlsFree(uint32_t index)
{
    if (index >= kMaxTLSSlots) return;
    m_tlsAllocated.reset(index);

    for (auto& t : m_threads) {
        t.tlsSlots[index] = 0;
    }
}

uint64_t ThreadScheduler::TlsGetValue(uint32_t index)
{
    if (index >= kMaxTLSSlots) return 0;
    auto* t = GetCurrentThread();
    if (!t) return 0;
    return t->tlsSlots[index];
}

void ThreadScheduler::TlsSetValue(uint32_t index, uint64_t value)
{
    if (index >= kMaxTLSSlots) return;
    auto* t = GetCurrentThread();
    if (!t) return;
    t->tlsSlots[index] = value;
}

// ============================================================================
// Query
// ============================================================================

bool ThreadScheduler::AllThreadsTerminated() const noexcept
{
    return std::all_of(m_threads.begin(), m_threads.end(),
        [](const ThreadContext& t) { return t.state == ThreadState::Terminated; });
}

uint32_t ThreadScheduler::ActiveThreadCount() const noexcept
{
    return static_cast<uint32_t>(std::count_if(m_threads.begin(), m_threads.end(),
        [](const ThreadContext& t) { return t.state != ThreadState::Terminated; }));
}

const std::vector<ThreadContext>& ThreadScheduler::GetAllThreads() const noexcept
{
    return m_threads;
}

ThreadContext* ThreadScheduler::FindThread(uint32_t threadId) noexcept
{
    for (auto& t : m_threads) {
        if (t.threadId == threadId) return &t;
    }
    return nullptr;
}

const ThreadContext* ThreadScheduler::FindThread(uint32_t threadId) const noexcept
{
    for (const auto& t : m_threads) {
        if (t.threadId == threadId) return &t;
    }
    return nullptr;
}

// ============================================================================
// Forensics
// ============================================================================

bool ThreadScheduler::HasDeadlock() const noexcept
{
    return m_syncStore.HasDeadlock();
}

std::vector<uint32_t> ThreadScheduler::GetDeadlockedThreads() const noexcept
{
    return m_syncStore.GetDeadlockedThreads();
}

uint64_t ThreadScheduler::TotalInstructionsExecuted() const noexcept
{
    uint64_t total = 0;
    for (const auto& t : m_threads) {
        total += t.instructionsExecuted;
    }
    return total;
}

// ============================================================================
// Internal: Thread Selection (Round-Robin with Priority)
// ============================================================================
// Algorithm:
//   1. Starting from the index *after* the current thread, scan forward.
//   2. Among all Ready threads, pick the one with the highest priority.
//      On ties, pick the thread that has waited the longest (lowest
//      lastScheduledTick).
//   3. If no thread is Ready, return nullopt.

std::optional<uint32_t> ThreadScheduler::SelectNextThread() noexcept
{
    if (m_threads.empty()) return std::nullopt;

    uint32_t bestIdx     = std::numeric_limits<uint32_t>::max();
    uint8_t  bestPrio    = 0;
    uint64_t bestTick    = std::numeric_limits<uint64_t>::max();
    bool     found       = false;

    const uint32_t count = static_cast<uint32_t>(m_threads.size());

    for (uint32_t i = 0; i < count; ++i) {
        // Round-robin: start scanning after the current thread.
        uint32_t idx = (m_currentThreadIndex + 1 + i) % count;
        const auto& t = m_threads[idx];

        if (t.state != ThreadState::Ready) continue;

        // Higher priority number = higher priority (matches Windows convention
        // where THREAD_PRIORITY_NORMAL = 8, ABOVE_NORMAL = 9, etc.)
        if (!found || t.priority > bestPrio ||
            (t.priority == bestPrio && t.lastScheduledTick < bestTick))
        {
            bestIdx  = idx;
            bestPrio = t.priority;
            bestTick = t.lastScheduledTick;
            found    = true;
        }
    }

    // If no other thread is Ready, allow the current thread to continue
    // if it is still Ready.
    if (!found) {
        if (m_currentThreadIndex < count &&
            m_threads[m_currentThreadIndex].state == ThreadState::Ready)
        {
            bestIdx = m_currentThreadIndex;
            found = true;
        }
    }

    if (!found) return std::nullopt;
    return bestIdx;
}

// ============================================================================
// Internal: Context Switch — Save / Load
// ============================================================================

void ThreadScheduler::SaveThreadState(ThreadContext& thread, const CPU& cpu) noexcept
{
    // Copy the entire CPUState (registers, flags, FPU/SSE/AVX, mode, counters).
    thread.cpuState = cpu.State();
}

void ThreadScheduler::LoadThreadState(const ThreadContext& thread, CPU& cpu) noexcept
{
    cpu.State() = thread.cpuState;
}

// ============================================================================
// Internal: Wait Timeout Processing
// ============================================================================
// Scans all waiting threads and transitions those whose timeout has expired
// back to Ready.

void ThreadScheduler::CheckWaitTimeouts() noexcept
{
    for (auto& t : m_threads) {
        if (t.state != ThreadState::Waiting) continue;

        // Infinite timeout — never expires.
        if (t.waitInfo.timeoutMs == kInfiniteTimeout) continue;
        if (t.waitInfo.timeoutMs == 0 && t.waitInfo.type != WaitInfo::WaitType::Sleep) {
            // Timeout of 0 = try-and-fail immediately.
            t.state = ThreadState::Ready;
            t.ClearWait();
            m_syncStore.RemoveWaiterFromAll(t.threadId);
            continue;
        }

        uint64_t elapsed = m_globalTick - t.waitInfo.waitStartTick;
        uint64_t timeoutTicks = MsToTicks(t.waitInfo.timeoutMs);

        if (elapsed >= timeoutTicks) {
            // Timeout expired.
            t.state = ThreadState::Ready;
            t.ClearWait();
            m_syncStore.RemoveWaiterFromAll(t.threadId);

            // Set EAX = WAIT_TIMEOUT (0x102) so the guest code sees the timeout.
            t.cpuState.SetReg64(GPR::RAX, 0x00000102ULL);
        }
    }
}

// ============================================================================
// Internal: APC Delivery
// ============================================================================
// Before a thread resumes execution, deliver any queued APCs by pushing a
// fake call frame onto the guest stack that will invoke the APC routine.
// We set up the CPU so the next instruction fetch runs the APC routine.
// When the APC routine returns, execution resumes at the thread's original RIP.
//
// Stack layout (x64):
//   [RSP-8]  = saved RIP  (return address = original RIP to resume after APC)
//   RCX      = parameter
//   RIP      = APC routine
//
// NOTE: We deliver at most one APC per quantum.  The rest are delivered on
//       subsequent quanta, matching Windows behavior where APCs are delivered
//       one at a time at each alertable wait point.

void ThreadScheduler::DeliverAPCs(
    ThreadContext& thread,
    CPU& cpu,
    VirtualMemory& memory) noexcept
{
    if (thread.apcQueue.empty()) return;

    // Pop one APC entry.
    APCEntry apc = thread.apcQueue.front();
    thread.apcQueue.erase(thread.apcQueue.begin());

    // Save the current RIP as the return address.
    GuestAddress savedRIP = cpu.State().GetRIP();
    uint64_t rsp = cpu.State().GetReg64(GPR::RSP);

    // Push the return address onto the guest stack.
    rsp -= 8;
    memory.WriteU64(rsp, savedRIP);

    cpu.State().SetReg64(GPR::RSP, rsp);
    cpu.State().SetReg64(GPR::RCX, apc.parameter);
    cpu.State().SetRIP(apc.routine);
}

// ============================================================================
// Internal: Timeout Conversion
// ============================================================================

uint64_t ThreadScheduler::MsToTicks(uint32_t ms) const noexcept
{
    if (ms == kInfiniteTimeout) {
        return std::numeric_limits<uint64_t>::max();
    }

    // If timing acceleration is enabled, scale timeouts down aggressively so
    // Sleep() calls don't burn the instruction budget.
    if (m_config.enableTimingAcceleration) {
        // Accelerate by 100x: 1 ms of guest time = 10 ticks instead of 1000.
        static constexpr uint64_t kAcceleratedTicksPerMs = 10;
        return static_cast<uint64_t>(ms) * kAcceleratedTicksPerMs;
    }

    return static_cast<uint64_t>(ms) * kTicksPerMs;
}

} // namespace Phantom
