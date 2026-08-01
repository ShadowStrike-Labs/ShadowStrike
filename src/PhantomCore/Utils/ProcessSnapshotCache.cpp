/**
 * @file ProcessSnapshotCache.cpp
 * @brief Implementation of the shared process snapshot cache.
 *
 * @copyright ShadowStrike Labs. Licensed under AGPL-3.0.
 */

#include "pch.h"
#include "ProcessSnapshotCache.hpp"

#include "Logger.hpp"

#include <Windows.h>
#include <tlhelp32.h>

#include <atomic>
#include <mutex>
#include <unordered_set>

namespace ShadowStrike::Utils {

namespace {

constexpr const wchar_t* kLogCat = L"ProcSnapshot";

// Readers must NEVER block.
//
// The first version of this cache held a mutex while enumerating. That put a
// process-wide lock, held across a kernel process-list walk, directly into the
// scan verdict path: BehaviorBlocker asks for process info while handling a
// kernel scan request, so a background sweep refreshing the snapshot could stall
// the reply the minifilter was waiting on - and the minifilter holds the file
// operation until that reply arrives. The result was a circular wait that got
// worse under load, and it stopped scans completing entirely.
//
// So: the published snapshot is swapped atomically, enumeration happens with no
// lock held, and a caller that arrives while a refresh is in flight is handed
// the slightly stale snapshot instead of waiting. Staleness of a few hundred
// milliseconds costs nothing here - arrivals are meant to be driven by kernel
// process-create events - whereas blocking the verdict path costs the machine.
std::atomic<std::shared_ptr<const ProcessSnapshot>> g_current{ nullptr };
std::atomic_flag                        g_refreshing = ATOMIC_FLAG_INIT;
std::mutex                              g_pidSetMutex;   // guards g_lastPids only
std::unordered_set<uint32_t>            g_lastPids;
std::atomic<uint64_t>                   g_generation{ 0 };
std::atomic<uint64_t>                   g_enumerations{ 0 };
std::atomic<uint64_t>                   g_cacheHits{ 0 };
std::atomic<bool>                       g_forceRefresh{ true };

/// @brief Walk the kernel process list once.
[[nodiscard]] std::shared_ptr<const ProcessSnapshot> Enumerate() {
    auto snapshot = std::make_shared<ProcessSnapshot>();
    snapshot->takenAtTick = ::GetTickCount64();

    HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        SS_LOG_WARN(kLogCat, L"CreateToolhelp32Snapshot failed: %lu",
                    static_cast<unsigned long>(::GetLastError()));
        // Return an empty snapshot rather than null: callers must never have to
        // null-check, and an empty list is correctly interpreted as "nothing
        // observed this pass" instead of silently reusing stale data.
        snapshot->generation = g_generation.load(std::memory_order_relaxed);
        return snapshot;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    std::unordered_set<uint32_t> pids;

    if (::Process32FirstW(hSnap, &pe)) {
        do {
            ProcessSnapshotEntry entry;
            entry.pid         = pe.th32ProcessID;
            entry.parentPid   = pe.th32ParentProcessID;
            entry.threadCount = pe.cntThreads;
            entry.basePriority = pe.pcPriClassBase;
            entry.name        = pe.szExeFile;
            pids.insert(entry.pid);
            snapshot->processes.push_back(std::move(entry));
        } while (::Process32NextW(hSnap, &pe));
    }

    ::CloseHandle(hSnap);

    // Bump the generation only when the observed set actually changed, so a
    // consumer comparing generations learns "something arrived or left" rather
    // than merely "time passed". This short lock guards only the previous PID
    // set - never the enumeration itself.
    {
        std::lock_guard<std::mutex> lock(g_pidSetMutex);
        if (pids != g_lastPids) {
            g_lastPids = std::move(pids);
            snapshot->generation = g_generation.fetch_add(1, std::memory_order_relaxed) + 1;
        } else {
            snapshot->generation = g_generation.load(std::memory_order_relaxed);
        }
    }

    g_enumerations.fetch_add(1, std::memory_order_relaxed);
    return snapshot;
}

}  // namespace

ProcessSnapshotCache& ProcessSnapshotCache::Instance() noexcept {
    static ProcessSnapshotCache instance;
    return instance;
}

std::shared_ptr<const ProcessSnapshot> ProcessSnapshotCache::Get() {
    auto existing = g_current.load(std::memory_order_acquire);

    const bool forced = g_forceRefresh.load(std::memory_order_acquire);

    if (existing && !forced) {
        const uint64_t age = ::GetTickCount64() - existing->takenAtTick;
        if (age < kFreshnessWindowMs) {
            g_cacheHits.fetch_add(1, std::memory_order_relaxed);
            return existing;
        }
    }

    // Stale (or first call). Exactly one caller performs the refresh; everyone
    // else keeps moving with what we already have. This is the property that
    // keeps the scan verdict path from ever waiting on a background sweep.
    if (g_refreshing.test_and_set(std::memory_order_acquire)) {
        if (existing) {
            g_cacheHits.fetch_add(1, std::memory_order_relaxed);
            return existing;   // slightly stale, but immediate
        }
        // No snapshot published yet and another thread is building the first
        // one. Enumerate locally rather than block; the result is not published,
        // so this happens at most once per caller during startup.
        return Enumerate();
    }

    std::shared_ptr<const ProcessSnapshot> fresh;
    try {
        fresh = Enumerate();          // no lock held here, by design
    } catch (...) {
        g_refreshing.clear(std::memory_order_release);
        return existing ? existing : std::make_shared<const ProcessSnapshot>();
    }

    g_current.store(fresh, std::memory_order_release);
    g_forceRefresh.store(false, std::memory_order_release);
    g_refreshing.clear(std::memory_order_release);
    return fresh;
}

void ProcessSnapshotCache::Invalidate() noexcept {
    g_forceRefresh.store(true, std::memory_order_release);
}

uint64_t ProcessSnapshotCache::EnumerationCount() const noexcept {
    return g_enumerations.load(std::memory_order_relaxed);
}

uint64_t ProcessSnapshotCache::CacheHitCount() const noexcept {
    return g_cacheHits.load(std::memory_order_relaxed);
}

}  // namespace ShadowStrike::Utils
