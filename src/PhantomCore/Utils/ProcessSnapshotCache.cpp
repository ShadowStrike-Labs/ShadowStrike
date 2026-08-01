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

std::mutex                              g_mutex;
std::shared_ptr<const ProcessSnapshot>  g_current;
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
    // than merely "time passed".
    if (pids != g_lastPids) {
        g_lastPids = std::move(pids);
        snapshot->generation = g_generation.fetch_add(1, std::memory_order_relaxed) + 1;
    } else {
        snapshot->generation = g_generation.load(std::memory_order_relaxed);
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
    std::lock_guard<std::mutex> lock(g_mutex);

    const bool forced = g_forceRefresh.exchange(false, std::memory_order_acq_rel);

    if (!forced && g_current) {
        const uint64_t age = ::GetTickCount64() - g_current->takenAtTick;
        if (age < kFreshnessWindowMs) {
            g_cacheHits.fetch_add(1, std::memory_order_relaxed);
            return g_current;
        }
    }

    g_current = Enumerate();
    return g_current;
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
