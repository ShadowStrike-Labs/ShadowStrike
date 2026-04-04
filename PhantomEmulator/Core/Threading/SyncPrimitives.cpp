/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "SyncPrimitives.hpp"
#include <algorithm>
#include <unordered_set>

namespace Phantom {

// ============================================================================
// Internal Helpers
// ============================================================================

void SyncObjectStore::RemoveFromQueue(std::vector<uint32_t>& queue, uint32_t threadId)
{
    queue.erase(
        std::remove(queue.begin(), queue.end(), threadId),
        queue.end());
}

// ============================================================================
// Mutex Operations
// ============================================================================

uint32_t SyncObjectStore::CreateMutex(
    const std::string& name,
    bool initialOwner,
    uint32_t creatorTid)
{
    // If a named mutex already exists, return the existing handle.
    if (!name.empty()) {
        for (auto& [h, mtx] : m_mutexes) {
            if (mtx.name == name) {
                return h;
            }
        }
    }

    uint32_t handle = AllocHandle();

    EmulatedMutex mtx;
    mtx.handle = handle;
    mtx.name   = name;

    if (initialOwner) {
        mtx.ownerThreadId  = creatorTid;
        mtx.recursionCount = 1;
        mtx.signaled       = false;
    }

    m_mutexes.emplace(handle, std::move(mtx));
    return handle;
}

bool SyncObjectStore::TryAcquireMutex(uint32_t handle, uint32_t threadId)
{
    auto it = m_mutexes.find(handle);
    if (it == m_mutexes.end()) return false;

    auto& mtx = it->second;

    if (mtx.signaled) {
        // Unowned — acquire it.
        mtx.ownerThreadId  = threadId;
        mtx.recursionCount = 1;
        mtx.signaled       = false;
        return true;
    }

    if (mtx.ownerThreadId == threadId) {
        // Recursive acquisition by the same thread.
        mtx.recursionCount++;
        return true;
    }

    // Owned by another thread — caller must wait.
    return false;
}

void SyncObjectStore::ReleaseMutex(uint32_t handle, uint32_t threadId)
{
    auto it = m_mutexes.find(handle);
    if (it == m_mutexes.end()) return;

    auto& mtx = it->second;

    // Only the owning thread may release.
    if (mtx.ownerThreadId != threadId) return;

    if (mtx.recursionCount > 1) {
        mtx.recursionCount--;
        return;
    }

    // Fully released — mark signaled and clear owner.
    mtx.ownerThreadId  = 0;
    mtx.recursionCount = 0;
    mtx.signaled       = true;
}

// ============================================================================
// Event Operations
// ============================================================================

uint32_t SyncObjectStore::CreateEvent(
    const std::string& name,
    bool manualReset,
    bool initialState)
{
    // If a named event already exists, return the existing handle.
    if (!name.empty()) {
        for (auto& [h, evt] : m_events) {
            if (evt.name == name) {
                return h;
            }
        }
    }

    uint32_t handle = AllocHandle();

    EmulatedEvent evt;
    evt.handle      = handle;
    evt.name        = name;
    evt.manualReset = manualReset;
    evt.signaled    = initialState;

    m_events.emplace(handle, std::move(evt));
    return handle;
}

bool SyncObjectStore::TryWaitEvent(uint32_t handle)
{
    auto it = m_events.find(handle);
    if (it == m_events.end()) return false;

    auto& evt = it->second;

    if (!evt.signaled) return false;

    // For auto-reset events, consuming the signal resets it.
    if (!evt.manualReset) {
        evt.signaled = false;
    }
    return true;
}

void SyncObjectStore::SetEvent(uint32_t handle)
{
    auto it = m_events.find(handle);
    if (it == m_events.end()) return;

    it->second.signaled = true;
}

void SyncObjectStore::ResetEvent(uint32_t handle)
{
    auto it = m_events.find(handle);
    if (it == m_events.end()) return;

    it->second.signaled = false;
}

void SyncObjectStore::PulseEvent(uint32_t handle)
{
    auto it = m_events.find(handle);
    if (it == m_events.end()) return;

    auto& evt = it->second;

    // PulseEvent: signal, wake waiting threads, then immediately reset.
    evt.signaled = true;
    // The scheduler will call Signal() to drain waiters.
    evt.signaled = false;
}

// ============================================================================
// Semaphore Operations
// ============================================================================

uint32_t SyncObjectStore::CreateSemaphore(
    const std::string& name,
    int32_t initial,
    int32_t max)
{
    if (!name.empty()) {
        for (auto& [h, sem] : m_semaphores) {
            if (sem.name == name) {
                return h;
            }
        }
    }

    uint32_t handle = AllocHandle();

    EmulatedSemaphore sem;
    sem.handle   = handle;
    sem.name     = name;
    sem.count    = initial;
    sem.maxCount = max;

    m_semaphores.emplace(handle, std::move(sem));
    return handle;
}

bool SyncObjectStore::TryAcquireSemaphore(uint32_t handle)
{
    auto it = m_semaphores.find(handle);
    if (it == m_semaphores.end()) return false;

    auto& sem = it->second;

    if (sem.count > 0) {
        sem.count--;
        return true;
    }

    return false;
}

void SyncObjectStore::ReleaseSemaphore(uint32_t handle, int32_t count)
{
    auto it = m_semaphores.find(handle);
    if (it == m_semaphores.end()) return;

    auto& sem = it->second;

    // Cap at maxCount.
    int32_t newCount = sem.count + count;
    if (newCount > sem.maxCount) {
        newCount = sem.maxCount;
    }
    sem.count = newCount;
}

// ============================================================================
// Critical Section Operations
// ============================================================================

void SyncObjectStore::InitializeCriticalSection(GuestAddress addr, uint32_t spinCount)
{
    EmulatedCriticalSection cs;
    cs.address   = addr;
    cs.spinCount = spinCount;

    m_critSections[addr] = std::move(cs);
}

void SyncObjectStore::DeleteCriticalSection(GuestAddress addr)
{
    m_critSections.erase(addr);
}

bool SyncObjectStore::TryEnterCriticalSection(GuestAddress addr, uint32_t threadId)
{
    auto it = m_critSections.find(addr);
    if (it == m_critSections.end()) {
        // Auto-initialize on first use (some malware skips InitializeCriticalSection).
        InitializeCriticalSection(addr, 0);
        it = m_critSections.find(addr);
    }

    auto& cs = it->second;

    if (cs.ownerThreadId == 0) {
        // Unowned — acquire.
        cs.ownerThreadId  = threadId;
        cs.recursionCount = 1;
        return true;
    }

    if (cs.ownerThreadId == threadId) {
        // Recursive entry.
        cs.recursionCount++;
        return true;
    }

    // Owned by another thread.
    return false;
}

void SyncObjectStore::LeaveCriticalSection(GuestAddress addr, uint32_t threadId)
{
    auto it = m_critSections.find(addr);
    if (it == m_critSections.end()) return;

    auto& cs = it->second;

    if (cs.ownerThreadId != threadId) return;

    if (cs.recursionCount > 1) {
        cs.recursionCount--;
        return;
    }

    cs.ownerThreadId  = 0;
    cs.recursionCount = 0;
}

// ============================================================================
// Signaling
// ============================================================================

std::vector<uint32_t> SyncObjectStore::Signal(uint32_t handle)
{
    std::vector<uint32_t> woken;

    // Try mutexes
    {
        auto it = m_mutexes.find(handle);
        if (it != m_mutexes.end()) {
            auto& mtx = it->second;
            if (mtx.signaled && !mtx.waitQueue.empty()) {
                // Wake the first waiter and transfer ownership.
                uint32_t waiterTid = mtx.waitQueue.front();
                mtx.waitQueue.erase(mtx.waitQueue.begin());
                mtx.ownerThreadId  = waiterTid;
                mtx.recursionCount = 1;
                mtx.signaled       = false;
                woken.push_back(waiterTid);
            }
            return woken;
        }
    }

    // Try events
    {
        auto it = m_events.find(handle);
        if (it != m_events.end()) {
            auto& evt = it->second;
            if (evt.signaled) {
                if (evt.manualReset) {
                    // Wake ALL waiters for manual-reset events.
                    woken = std::move(evt.waitQueue);
                    evt.waitQueue.clear();
                } else {
                    // Wake exactly one waiter for auto-reset events and reset signal.
                    if (!evt.waitQueue.empty()) {
                        woken.push_back(evt.waitQueue.front());
                        evt.waitQueue.erase(evt.waitQueue.begin());
                        evt.signaled = false;
                    }
                }
            }
            return woken;
        }
    }

    // Try semaphores
    {
        auto it = m_semaphores.find(handle);
        if (it != m_semaphores.end()) {
            auto& sem = it->second;
            while (sem.count > 0 && !sem.waitQueue.empty()) {
                woken.push_back(sem.waitQueue.front());
                sem.waitQueue.erase(sem.waitQueue.begin());
                sem.count--;
            }
            return woken;
        }
    }

    return woken;
}

void SyncObjectStore::AddWaiter(uint32_t handle, uint32_t threadId)
{
    // Mutex
    {
        auto it = m_mutexes.find(handle);
        if (it != m_mutexes.end()) {
            auto& q = it->second.waitQueue;
            if (std::find(q.begin(), q.end(), threadId) == q.end()) {
                q.push_back(threadId);
            }
            return;
        }
    }
    // Event
    {
        auto it = m_events.find(handle);
        if (it != m_events.end()) {
            auto& q = it->second.waitQueue;
            if (std::find(q.begin(), q.end(), threadId) == q.end()) {
                q.push_back(threadId);
            }
            return;
        }
    }
    // Semaphore
    {
        auto it = m_semaphores.find(handle);
        if (it != m_semaphores.end()) {
            auto& q = it->second.waitQueue;
            if (std::find(q.begin(), q.end(), threadId) == q.end()) {
                q.push_back(threadId);
            }
            return;
        }
    }
}

void SyncObjectStore::RemoveWaiterFromAll(uint32_t threadId)
{
    for (auto& [h, mtx] : m_mutexes) {
        RemoveFromQueue(mtx.waitQueue, threadId);
    }
    for (auto& [h, evt] : m_events) {
        RemoveFromQueue(evt.waitQueue, threadId);
    }
    for (auto& [h, sem] : m_semaphores) {
        RemoveFromQueue(sem.waitQueue, threadId);
    }
    for (auto& [a, cs] : m_critSections) {
        RemoveFromQueue(cs.waitQueue, threadId);
    }
}

// ============================================================================
// Query / Forensics
// ============================================================================

std::vector<std::string> SyncObjectStore::GetNamedMutexes() const
{
    std::vector<std::string> names;
    names.reserve(m_mutexes.size());

    for (const auto& [h, mtx] : m_mutexes) {
        if (!mtx.name.empty()) {
            names.push_back(mtx.name);
        }
    }
    return names;
}

bool SyncObjectStore::HandleExists(uint32_t handle) const noexcept
{
    return m_mutexes.count(handle) ||
           m_events.count(handle)  ||
           m_semaphores.count(handle);
}

uint32_t SyncObjectStore::GetOwnerThread(uint32_t handle) const noexcept
{
    auto itM = m_mutexes.find(handle);
    if (itM != m_mutexes.end()) {
        return itM->second.ownerThreadId;
    }
    return 0;
}

// ============================================================================
// Wait-For Graph Construction
// ============================================================================
// Maps each waiting thread to the thread that currently owns the resource
// it is blocked on.  Only mutex-like objects (mutexes, critical sections)
// produce ownership edges.

std::unordered_map<uint32_t, uint32_t> SyncObjectStore::BuildWaitForGraph() const
{
    std::unordered_map<uint32_t, uint32_t> graph;

    for (const auto& [h, mtx] : m_mutexes) {
        if (mtx.ownerThreadId == 0) continue;
        for (uint32_t waiter : mtx.waitQueue) {
            graph[waiter] = mtx.ownerThreadId;
        }
    }

    for (const auto& [addr, cs] : m_critSections) {
        if (cs.ownerThreadId == 0) continue;
        for (uint32_t waiter : cs.waitQueue) {
            graph[waiter] = cs.ownerThreadId;
        }
    }

    return graph;
}

// ============================================================================
// Deadlock Detection — DFS Cycle Detection on the Wait-For Graph
// ============================================================================

bool SyncObjectStore::HasDeadlock() const
{
    auto graph = BuildWaitForGraph();
    if (graph.empty()) return false;

    // For each node, follow the chain. If we revisit a node on the current
    // path, we have a cycle.
    std::unordered_set<uint32_t> visited;
    std::unordered_set<uint32_t> inPath;

    for (const auto& [node, _] : graph) {
        if (visited.count(node)) continue;

        // Walk the chain from this node.
        inPath.clear();
        uint32_t cur = node;
        while (true) {
            if (inPath.count(cur)) {
                return true; // Cycle found.
            }
            if (visited.count(cur)) break;

            inPath.insert(cur);
            visited.insert(cur);

            auto it = graph.find(cur);
            if (it == graph.end()) break;
            cur = it->second;
        }
    }

    return false;
}

std::vector<uint32_t> SyncObjectStore::GetDeadlockedThreads() const
{
    auto graph = BuildWaitForGraph();
    if (graph.empty()) return {};

    std::vector<uint32_t> deadlocked;
    std::unordered_set<uint32_t> globalVisited;

    for (const auto& [startNode, _] : graph) {
        if (globalVisited.count(startNode)) continue;

        // Trace from startNode, recording the path.
        std::vector<uint32_t> path;
        std::unordered_set<uint32_t> pathSet;
        uint32_t cur = startNode;

        while (true) {
            if (pathSet.count(cur)) {
                // Cycle found — collect all nodes in the cycle.
                bool inCycle = false;
                for (uint32_t n : path) {
                    if (n == cur) inCycle = true;
                    if (inCycle) {
                        deadlocked.push_back(n);
                    }
                }
                break;
            }
            if (globalVisited.count(cur)) break;

            path.push_back(cur);
            pathSet.insert(cur);

            auto it = graph.find(cur);
            if (it == graph.end()) break;
            cur = it->second;
        }

        for (uint32_t n : path) {
            globalVisited.insert(n);
        }
    }

    // Deduplicate
    std::sort(deadlocked.begin(), deadlocked.end());
    deadlocked.erase(std::unique(deadlocked.begin(), deadlocked.end()), deadlocked.end());

    return deadlocked;
}

} // namespace Phantom
