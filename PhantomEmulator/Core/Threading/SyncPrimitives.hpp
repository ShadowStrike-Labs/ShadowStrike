/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace Phantom {

// ============================================================================
// Emulated Synchronization Objects
// ============================================================================
// These model the Win32 kernel synchronization primitives at a logical level.
// They exist entirely in emulator space — no host OS objects are created.
// The SyncObjectStore manages lifetime, ownership, and wait queues.

// ============================================================================
// Emulated Mutex
// ============================================================================

struct EmulatedMutex {
    uint32_t handle            = 0;
    std::string name;                       // Named mutex for infection marker detection
    uint32_t ownerThreadId     = 0;
    uint32_t recursionCount    = 0;
    bool     signaled          = true;      // Initially signaled (unowned)
    std::vector<uint32_t> waitQueue;        // Threads waiting for this mutex
};

// ============================================================================
// Emulated Event
// ============================================================================

struct EmulatedEvent {
    uint32_t handle            = 0;
    std::string name;
    bool     manualReset       = false;
    bool     signaled          = false;
    std::vector<uint32_t> waitQueue;
};

// ============================================================================
// Emulated Semaphore
// ============================================================================

struct EmulatedSemaphore {
    uint32_t handle            = 0;
    std::string name;
    int32_t  count             = 0;
    int32_t  maxCount          = 1;
    std::vector<uint32_t> waitQueue;
};

// ============================================================================
// Emulated Critical Section (identified by guest address, not handle)
// ============================================================================

struct EmulatedCriticalSection {
    GuestAddress address       = 0;         // Guest memory address of CRITICAL_SECTION
    uint32_t ownerThreadId     = 0;
    uint32_t recursionCount    = 0;
    uint32_t spinCount         = 0;
    std::vector<uint32_t> waitQueue;
};

// ============================================================================
// Synchronization Object Store
// ============================================================================
// Central registry for all emulated sync objects in a session.
// Provides create/acquire/release operations and deadlock detection.
//
// Thread safety: This class is NOT internally synchronized.  The caller
// (ThreadScheduler) is responsible for external synchronization since all
// access occurs on the single emulation thread.

class SyncObjectStore {
public:
    SyncObjectStore() noexcept = default;
    ~SyncObjectStore() noexcept = default;

    // Non-copyable (owns collections of sync objects)
    SyncObjectStore(const SyncObjectStore&) = delete;
    SyncObjectStore& operator=(const SyncObjectStore&) = delete;

    // === Object Creation ===

    [[nodiscard]] uint32_t CreateMutex(
        const std::string& name,
        bool initialOwner,
        uint32_t creatorTid);

    [[nodiscard]] uint32_t CreateEvent(
        const std::string& name,
        bool manualReset,
        bool initialState);

    [[nodiscard]] uint32_t CreateSemaphore(
        const std::string& name,
        int32_t initial,
        int32_t max);

    // === Critical Section Lifecycle ===

    void InitializeCriticalSection(GuestAddress addr, uint32_t spinCount);
    void DeleteCriticalSection(GuestAddress addr);

    // === Acquire / Release Operations ===
    // TryAcquire* returns true if the object was immediately acquired,
    // false if the caller must be placed in a wait state.

    [[nodiscard]] bool TryAcquireMutex(uint32_t handle, uint32_t threadId);
    void ReleaseMutex(uint32_t handle, uint32_t threadId);

    [[nodiscard]] bool TryWaitEvent(uint32_t handle);
    void SetEvent(uint32_t handle);
    void ResetEvent(uint32_t handle);
    void PulseEvent(uint32_t handle);

    [[nodiscard]] bool TryAcquireSemaphore(uint32_t handle);
    void ReleaseSemaphore(uint32_t handle, int32_t count);

    [[nodiscard]] bool TryEnterCriticalSection(GuestAddress addr, uint32_t threadId);
    void LeaveCriticalSection(GuestAddress addr, uint32_t threadId);

    // === Signaling ===
    // Signal a handle and return the list of thread IDs that should be woken.
    [[nodiscard]] std::vector<uint32_t> Signal(uint32_t handle);

    // Add a thread to the wait queue of a handle.
    void AddWaiter(uint32_t handle, uint32_t threadId);

    // Remove a thread from all wait queues (e.g., on timeout or termination).
    void RemoveWaiterFromAll(uint32_t threadId);

    // === Query / Forensics ===

    // Retrieve all named mutexes (useful for infection marker analysis).
    [[nodiscard]] std::vector<std::string> GetNamedMutexes() const;

    // Deadlock detection: build wait-for graph and detect cycles via DFS.
    [[nodiscard]] bool HasDeadlock() const;
    [[nodiscard]] std::vector<uint32_t> GetDeadlockedThreads() const;

    // Check if a handle exists in any of the object maps.
    [[nodiscard]] bool HandleExists(uint32_t handle) const noexcept;

    // Determine which thread owns the handle (0 if unowned / not a mutex-like object).
    [[nodiscard]] uint32_t GetOwnerThread(uint32_t handle) const noexcept;

private:
    std::unordered_map<uint32_t, EmulatedMutex>     m_mutexes;
    std::unordered_map<uint32_t, EmulatedEvent>      m_events;
    std::unordered_map<uint32_t, EmulatedSemaphore>  m_semaphores;
    std::unordered_map<GuestAddress, EmulatedCriticalSection> m_critSections;

    // Handle allocator — starts above typical OS handle range to avoid collisions.
    uint32_t m_nextHandle = 0x8000;

    [[nodiscard]] uint32_t AllocHandle() noexcept { return m_nextHandle++; }

    // Internal helper: remove threadId from a specific wait queue vector.
    static void RemoveFromQueue(std::vector<uint32_t>& queue, uint32_t threadId);

    // Build an adjacency list representing the wait-for graph:
    //   waiterTid -> ownerTid  (thread is waiting for a resource owned by owner)
    // Used by HasDeadlock() and GetDeadlockedThreads().
    [[nodiscard]] std::unordered_map<uint32_t, uint32_t> BuildWaitForGraph() const;
};

} // namespace Phantom
