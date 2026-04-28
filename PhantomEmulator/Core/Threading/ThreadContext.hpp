/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "../CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace Phantom {

// ============================================================================
// Thread Context — Represents a Single Emulated Guest Thread
// ============================================================================
// Each emulated thread carries its own full CPU register snapshot, TLS slots,
// wait state, APC queue, and scheduling metadata.  The ThreadScheduler owns
// the vector of ThreadContext instances and performs context switches by
// saving/restoring the CPUState to/from the active CPU.
//
// Design constraints:
//   - No heap allocation on the scheduling hot path (context switch).
//   - All fields are value types or small inline vectors to keep the
//     per-thread footprint predictable.
//   - The waitInfo and apcQueue vectors are bounded by the scheduler.

// ============================================================================
// Thread Lifecycle States
// ============================================================================

enum class ThreadState : uint8_t {
    Created,      // Allocated but not yet scheduled
    Running,      // Currently executing on the CPU
    Ready,        // Runnable — waiting for its time slice
    Waiting,      // Blocked on a synchronization object or Sleep
    Suspended,    // Suspended via SuspendThread (not runnable)
    Terminated,   // Exited — exit code is set
};

// ============================================================================
// Wait Descriptor
// ============================================================================

struct WaitInfo {
    enum class WaitType : uint8_t {
        None,
        SingleObject,
        MultipleObjects,
        Sleep,
        APC,
    };

    WaitType type = WaitType::None;
    uint32_t timeoutMs    = 0;           // 0 = poll/no wait, UINT32_MAX = infinite
    uint64_t waitStartTick = 0;          // Global tick when wait began
    std::vector<uint32_t> waitHandles;   // Handle(s) being waited on
    bool waitAll = false;                // WaitForMultipleObjects fWaitAll
};

// ============================================================================
// APC Entry
// ============================================================================

struct APCEntry {
    GuestAddress routine   = 0;
    uint64_t     parameter = 0;
};

// ============================================================================
// Thread Context
// ============================================================================

struct ThreadContext {
    // Identity
    uint32_t     threadId        = 0;
    uint32_t     ownerProcessId  = 1;  // Default process ID for single-process emulation
    GuestAddress startAddress    = 0;
    GuestAddress stackBase       = 0;
    GuestSize    stackSize       = 0;

    // Lifecycle state
    ThreadState  state = ThreadState::Created;

    // Full CPU register snapshot — saved/restored on context switch
    CPUState cpuState;

    // Thread Environment Block address in guest memory
    GuestAddress tebAddress = 0;

    // Wait state (only meaningful when state == Waiting)
    WaitInfo waitInfo;

    // Thread-Local Storage (TLS) — 64 slots matching Windows TLS minimum
    static constexpr uint32_t kMaxTLSSlots = 64;
    static constexpr size_t kMaxWaitHandles = 64;
    static constexpr size_t kMaxAPCQueueDepth = 256;
    static constexpr uint8_t kDefaultPriority = 8;
    static constexpr uint32_t kDefaultQuantum = 2000;
    std::array<uint64_t, kMaxTLSSlots> tlsSlots{};

    // Asynchronous Procedure Call queue
    std::vector<APCEntry> apcQueue;

    // Execution statistics
    uint64_t instructionsExecuted = 0;
    uint64_t contextSwitchCount   = 0;
    uint32_t exitCode             = 0;

    // Scheduling metadata
    uint8_t  priority          = kDefaultPriority; // Windows THREAD_PRIORITY_NORMAL
    uint64_t lastScheduledTick = 0;
    uint32_t quantum           = kDefaultQuantum;  // Instructions per time slice

    // ========================================================================
    // Helpers
    // ========================================================================

    [[nodiscard]] bool IsRunnable() const noexcept {
        return state == ThreadState::Running || state == ThreadState::Ready;
    }

    [[nodiscard]] bool IsBlocked() const noexcept {
        return state == ThreadState::Waiting || state == ThreadState::Suspended;
    }

    [[nodiscard]] bool IsTerminated() const noexcept {
        return state == ThreadState::Terminated;
    }

    [[nodiscard]] bool HasPendingAPCs() const noexcept {
        return !apcQueue.empty();
    }

    void ClearWait() noexcept {
        waitInfo.type = WaitInfo::WaitType::None;
        waitInfo.timeoutMs = 0;
        waitInfo.waitStartTick = 0;
        waitInfo.waitHandles.clear();
        waitInfo.waitAll = false;
    }
};

} // namespace Phantom
