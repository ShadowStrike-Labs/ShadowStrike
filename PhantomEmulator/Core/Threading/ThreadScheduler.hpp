/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "ThreadContext.hpp"
#include "SyncPrimitives.hpp"
#include "../CPU/CPU.hpp"
#include "../Memory/VirtualMemory.hpp"
#include "../Memory/MemoryTracker.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"
#include "../../Common/Errors.hpp"
#include <bitset>
#include <cstdint>
#include <optional>
#include <vector>

namespace Phantom {

// ============================================================================
// Cooperative Thread Scheduler
// ============================================================================
// Manages N emulated guest threads on top of a single CPU instance.
// Scheduling is cooperative: the scheduler runs one thread for a quantum
// (measured in instruction count), then context-switches to the next
// runnable thread.  Wait states, APCs, TLS, and deadlock detection are
// handled here.
//
// Lifetime: one ThreadScheduler per emulation session.
// Thread safety: NOT internally synchronized — the scheduler is invoked
//   from the single-threaded emulation loop only.

class ThreadScheduler {
public:
    explicit ThreadScheduler(const EmulationConfig& config) noexcept;
    ~ThreadScheduler() noexcept;

    // Non-copyable
    ThreadScheduler(const ThreadScheduler&) = delete;
    ThreadScheduler& operator=(const ThreadScheduler&) = delete;

    // ========================================================================
    // Thread Lifecycle
    // ========================================================================

    // Create a new guest thread.  Returns the thread ID, or 0 on failure.
    [[nodiscard]] uint32_t CreateThread(
        GuestAddress startAddr,
        uint64_t parameter,
        GuestAddress stackBase,
        GuestSize stackSize,
        bool suspended = false);

    void TerminateThread(uint32_t threadId, uint32_t exitCode);
    void SuspendThread(uint32_t threadId);
    void ResumeThread(uint32_t threadId);

    // ========================================================================
    // Scheduling
    // ========================================================================

    // Get the currently running ThreadContext (nullptr if none).
    [[nodiscard]] ThreadContext* GetCurrentThread() noexcept;
    [[nodiscard]] const ThreadContext* GetCurrentThread() const noexcept;
    [[nodiscard]] uint32_t GetCurrentThreadId() const noexcept;

    // Run one scheduling quantum on the current (or next runnable) thread.
    // Returns the number of instructions executed during this quantum.
    // Returns 0 if all threads are blocked or terminated.
    [[nodiscard]] uint32_t RunQuantum(
        CPU& cpu,
        VirtualMemory& memory,
        MemoryTracker* tracker);

    // Yield the current thread's remaining quantum (SwitchToThread equivalent).
    void Yield();

    // ========================================================================
    // Wait State
    // ========================================================================

    // Put the current thread into a wait state on a single handle.
    void WaitOnHandle(uint32_t handle, uint32_t timeoutMs);

    // Put the current thread into a wait state on multiple handles.
    void WaitOnMultiple(
        const std::vector<uint32_t>& handles,
        bool waitAll,
        uint32_t timeoutMs);

    // Put the current thread to sleep for the given number of milliseconds.
    // In emulation, sleep duration is measured in global ticks, not real time.
    void Sleep(uint32_t milliseconds);

    // Wake all threads waiting on the given handle.
    void SignalHandle(uint32_t handle);

    // ========================================================================
    // APC Support
    // ========================================================================

    void QueueUserAPC(uint32_t threadId, GuestAddress routine, uint64_t parameter);

    // ========================================================================
    // TLS Support
    // ========================================================================

    [[nodiscard]] uint32_t TlsAlloc();
    void TlsFree(uint32_t index);
    [[nodiscard]] uint64_t TlsGetValue(uint32_t index);
    void TlsSetValue(uint32_t index, uint64_t value);

    // ========================================================================
    // Query
    // ========================================================================

    [[nodiscard]] bool AllThreadsTerminated() const noexcept;
    [[nodiscard]] uint32_t ActiveThreadCount() const noexcept;
    [[nodiscard]] const std::vector<ThreadContext>& GetAllThreads() const noexcept;
    [[nodiscard]] ThreadContext* FindThread(uint32_t threadId) noexcept;
    [[nodiscard]] const ThreadContext* FindThread(uint32_t threadId) const noexcept;

    // ========================================================================
    // Forensics
    // ========================================================================

    [[nodiscard]] bool HasDeadlock() const noexcept;
    [[nodiscard]] std::vector<uint32_t> GetDeadlockedThreads() const noexcept;
    [[nodiscard]] uint64_t TotalInstructionsExecuted() const noexcept;

    // ========================================================================
    // Sync Object Store (shared across all emulated threads)
    // ========================================================================

    [[nodiscard]] SyncObjectStore& GetSyncStore() noexcept { return m_syncStore; }
    [[nodiscard]] const SyncObjectStore& GetSyncStore() const noexcept { return m_syncStore; }

private:
    EmulationConfig m_config;
    std::vector<ThreadContext> m_threads;
    uint32_t m_currentThreadIndex = 0;
    uint32_t m_nextThreadId       = 1000;
    uint64_t m_globalTick         = 0;
    bool     m_yieldRequested     = false;

    SyncObjectStore m_syncStore;

    // TLS slot allocation bitmap (1 = allocated).
    static constexpr uint32_t kMaxTLSSlots = ThreadContext::kMaxTLSSlots;
    std::bitset<kMaxTLSSlots> m_tlsAllocated{};

    // ========================================================================
    // Internal Scheduling
    // ========================================================================

    // Select the next runnable thread index using round-robin with priority.
    // Returns nullopt if no thread is runnable.
    [[nodiscard]] std::optional<uint32_t> SelectNextThread() noexcept;

    // Save the CPU state into the given thread context.
    void SaveThreadState(ThreadContext& thread, const CPU& cpu) noexcept;

    // Load a thread context's saved state onto the CPU.
    void LoadThreadState(const ThreadContext& thread, CPU& cpu) noexcept;

    // Walk all waiting threads and check for timeout expiry.
    void CheckWaitTimeouts() noexcept;

    // Deliver pending APCs to the thread before resuming it.
    void DeliverAPCs(
        ThreadContext& thread,
        CPU& cpu,
        VirtualMemory& memory) noexcept;

    // Translate a timeout in milliseconds to a tick delta.
    [[nodiscard]] uint64_t MsToTicks(uint32_t ms) const noexcept;
};

} // namespace Phantom
