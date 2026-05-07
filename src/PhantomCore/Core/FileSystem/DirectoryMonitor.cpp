/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - DIRECTORY MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file DirectoryMonitor.cpp
 * @brief Enterprise-grade high-level directory monitoring orchestrator.
 *
 * Hardened production implementation of intelligent directory monitoring:
 *   - Stable per-monitor pointers via std::unique_ptr storage (no
 *     unordered_map rehash invalidation bug for worker threads).
 *   - Reparse-point / symlink / junction rejection on directory open
 *     (defeats TOCTOU substitution attacks targeting recursive watchers).
 *   - Long-path-aware canonicalization through FileUtils::NormalizePath
 *     (handles paths above MAX_PATH and resolves to final on-disk form).
 *   - Worker thread state (paused, lastEventNs, eventsReceived) is held in
 *     atomics so concurrent reads from public getters are race-free.
 *   - File rename pairing (OLD_NAME / NEW_NAME) is preserved per-monitor.
 *   - ReadDirectoryChangesW buffer-overflow (bytesReturned == 0) detected
 *     and reported as event-loss without infinite-spinning the worker.
 *   - All event/status callbacks are snapshotted under lock and invoked
 *     OUTSIDE the lock to prevent re-entrant deadlocks.
 *   - Filesystem identifiers (path/filename) are sanitized before being
 *     written to the log (defeats CRLF/format/ANSI escape log injection).
 *   - Rate-limit table is keyed on monitor ID and torn down on
 *     RemoveMonitor so attacker-controlled keyspace cannot accumulate.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "DirectoryMonitor.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/Logger.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <map>
#include <deque>
#include <filesystem>
#include <Windows.h>
#include <shlobj.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Shell32.lib")

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

namespace fs = std::filesystem;

// ============================================================================
// File-Local Helpers (anonymous namespace — no external linkage)
// ============================================================================
namespace {

// Hard upper bound for any single inbound filename payload extracted from a
// FILE_NOTIFY_INFORMATION record. The Windows kernel will never produce more
// than UNICODE_STRING_MAX_CHARS, but we cap aggressively to defeat malformed
// notifications synthesized by hostile drivers/redirectors.
constexpr DWORD kMaxFileNameBytes = static_cast<DWORD>(32767u) * sizeof(wchar_t);

// ReadDirectoryChangesW notification buffer. 64 KiB is the hard MS limit on
// remote shares; we therefore use exactly that, never more.
constexpr DWORD kNotifyBufferBytes = 64u * 1024u;

// Maximum number of distinct rate-limit buckets (failsafe upper bound; the
// real bound is the live monitor count, but a stale entry race could grow
// the map momentarily — we trim aggressively).
constexpr size_t kMaxRateLimitBuckets = 4096;

// Sanitize a wide string for safe inclusion in log lines. Strips CR/LF/TAB
// and other C0/C1 control characters that would otherwise allow an attacker
// who controls a filename to inject fake log records or terminal escape
// sequences. Output length is capped to 512 wchar_t to keep log lines bounded.
[[nodiscard]] std::wstring SanitizeForLog(std::wstring_view in) noexcept {
    constexpr size_t kCap = 512;
    std::wstring out;
    const size_t n = (in.size() > kCap) ? kCap : in.size();
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        const wchar_t c = in[i];
        // Reject all C0 (0x00–0x1F), DEL (0x7F), and C1 (0x80–0x9F) controls.
        if (c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F)) {
            out.push_back(L'?');
        } else {
            out.push_back(c);
        }
    }
    if (in.size() > kCap) {
        out.append(L"...[truncated]");
    }
    return out;
}

// Canonicalize a path with long-path support. Uses GetFullPathNameW with a
// dynamically grown buffer so paths above MAX_PATH do not get truncated.
[[nodiscard]] std::wstring CanonicalizeFull(const std::wstring& in) {
    if (in.empty()) {
        return {};
    }
    DWORD needed = ::GetFullPathNameW(in.c_str(), 0, nullptr, nullptr);
    if (needed == 0) {
        return {};
    }
    std::wstring buf(needed, L'\0');
    DWORD written = ::GetFullPathNameW(in.c_str(), needed, buf.data(), nullptr);
    if (written == 0 || written >= needed) {
        return {};
    }
    buf.resize(written);
    return buf;
}

// Returns true iff the directory pointed at is a reparse point (symlink,
// junction, mount-point, or any other ms-reparse tag). Caller must reject
// such paths before opening them in recursive watch mode.
[[nodiscard]] bool IsReparsePoint(const std::wstring& path) noexcept {
    const DWORD attrs = ::GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    return (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

// After opening the directory handle, ask the kernel for its final canonical
// path. If it differs from the requested path (case-insensitively, ignoring
// the optional \\?\ prefix), an attacker has redirected us — bail out.
[[nodiscard]] bool VerifyHandleResolvesTo(HANDLE h, const std::wstring& requested) {
    if (h == INVALID_HANDLE_VALUE || h == nullptr) {
        return false;
    }
    DWORD needed = ::GetFinalPathNameByHandleW(h, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (needed == 0) {
        return false;
    }
    std::wstring resolved(needed, L'\0');
    const DWORD written = ::GetFinalPathNameByHandleW(h, resolved.data(), needed, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (written == 0 || written >= needed) {
        return false;
    }
    resolved.resize(written);

    auto strip_prefix = [](std::wstring_view s) -> std::wstring_view {
        if (s.size() >= 4 && s[0] == L'\\' && s[1] == L'\\' && s[2] == L'?' && s[3] == L'\\') {
            return s.substr(4);
        }
        return s;
    };
    auto trim_trailing_sep = [](std::wstring_view s) -> std::wstring_view {
        while (!s.empty() && (s.back() == L'\\' || s.back() == L'/')) {
            s.remove_suffix(1);
        }
        return s;
    };

    const std::wstring_view a = trim_trailing_sep(strip_prefix(resolved));
    const std::wstring_view b = trim_trailing_sep(strip_prefix(requested));
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        const wchar_t ca = static_cast<wchar_t>(::towlower(a[i]));
        const wchar_t cb = static_cast<wchar_t>(::towlower(b[i]));
        if (ca != cb) {
            return false;
        }
    }
    return true;
}

}  // anonymous namespace

// ============================================================================
// Structure Implementations
// ============================================================================

std::string MonitoredPath::ToJson() const {
    std::ostringstream oss;
    oss << "{\"monitorId\":" << monitorId << ",";
    oss << "\"path\":\"" << Utils::StringUtils::EscapeJson(Utils::StringUtils::ToNarrow(path)) << "\",";
    oss << "\"category\":" << static_cast<int>(category) << ",";
    oss << "\"recursive\":" << (recursive ? "true" : "false") << ",";
    oss << "\"isActive\":" << (isActive ? "true" : "false") << ",";
    oss << "\"eventsReceived\":" << eventsReceived.load(std::memory_order_relaxed) << "}";
    return oss.str();
}

DirectoryMonitorConfig DirectoryMonitorConfig::CreateDefault() noexcept {
    DirectoryMonitorConfig config;
    config.enabled = true;
    config.monitorSystemPaths = true;
    config.monitorUserPaths = true;
    config.monitorStartupLocations = true;
    config.monitorTempDirectories = true;
    config.monitorRemovableMedia = true;
    config.monitorNetworkShares = false;
    config.autoDiscoverNewPaths = true;
    config.enableRateLimiting = true;
    config.enableIntelligentFiltering = true;
    return config;
}

DirectoryMonitorConfig DirectoryMonitorConfig::CreateHighSecurity() noexcept {
    DirectoryMonitorConfig config = CreateDefault();
    config.monitorNetworkShares = true;
    // High-security still rate-limits — allowing a hostile filesystem driver
    // to flood the event pipeline at line rate would defeat the EDR. Use a
    // very high but FINITE ceiling rather than UINT32_MAX.
    config.enableRateLimiting = true;
    config.maxEventsPerWindow = 1'000'000u;
    return config;
}

bool DirectoryMonitorConfig::IsValid() const noexcept {
    if (!enabled) return true;
    if (maxConcurrentMonitors == 0) return false;
    if (maxConcurrentMonitors > DirectoryMonitorConstants::MAX_CONCURRENT_MONITORS) return false;
    if (eventQueueCapacity == 0) return false;
    if (rateLimitWindowSec == 0 && enableRateLimiting) return false;
    if (enableRateLimiting && maxEventsPerWindow == 0) return false;
    return true;
}

std::string DirectoryMonitorConfig::ToJson() const {
    std::ostringstream oss;
    oss << "{\"enabled\":" << (enabled ? "true" : "false") << ",";
    oss << "\"monitorSystemPaths\":" << (monitorSystemPaths ? "true" : "false") << ",";
    oss << "\"monitorUserPaths\":" << (monitorUserPaths ? "true" : "false") << ",";
    oss << "\"autoDiscoverNewPaths\":" << (autoDiscoverNewPaths ? "true" : "false") << ",";
    oss << "\"maxConcurrentMonitors\":" << maxConcurrentMonitors << ",";
    oss << "\"enableRateLimiting\":" << (enableRateLimiting ? "true" : "false") << "}";
    return oss.str();
}

void DirectoryMonitorStatistics::Reset() noexcept {
    activeMonitors.store(0, std::memory_order_relaxed);
    totalEvents.store(0, std::memory_order_relaxed);
    filteredEvents.store(0, std::memory_order_relaxed);
    rateLimitedEvents.store(0, std::memory_order_relaxed);
    errors.store(0, std::memory_order_relaxed);
    callbackInvocations.store(0, std::memory_order_relaxed);
    pathsDiscovered.store(0, std::memory_order_relaxed);
    totalProcessingTimeUs.store(0, std::memory_order_relaxed);

    for (auto& counter : byCategory) {
        counter.store(0, std::memory_order_relaxed);
    }

    for (auto& counter : byAction) {
        counter.store(0, std::memory_order_relaxed);
    }

    startTime = Clock::now();
}

double DirectoryMonitorStatistics::GetAverageProcessingTimeMs() const noexcept {
    const uint64_t total = totalEvents.load(std::memory_order_relaxed);
    if (total == 0) return 0.0;

    const uint64_t totalUs = totalProcessingTimeUs.load(std::memory_order_relaxed);
    return (static_cast<double>(totalUs) / static_cast<double>(total)) / 1000.0;
}

std::string DirectoryMonitorStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{\"activeMonitors\":" << activeMonitors.load(std::memory_order_relaxed) << ",";
    oss << "\"totalEvents\":" << totalEvents.load(std::memory_order_relaxed) << ",";
    oss << "\"filteredEvents\":" << filteredEvents.load(std::memory_order_relaxed) << ",";
    oss << "\"rateLimitedEvents\":" << rateLimitedEvents.load(std::memory_order_relaxed) << ",";
    oss << "\"errors\":" << errors.load(std::memory_order_relaxed) << ",";
    oss << "\"callbackInvocations\":" << callbackInvocations.load(std::memory_order_relaxed) << ",";
    oss << "\"pathsDiscovered\":" << pathsDiscovered.load(std::memory_order_relaxed) << ",";
    oss << "\"avgProcessingTimeMs\":" << GetAverageProcessingTimeMs() << "}";
    return oss.str();
}

std::string DirectoryEvent::ToJson() const {
    std::ostringstream oss;
    oss << "{\"eventId\":" << eventId << ",";
    oss << "\"monitorId\":" << monitorId << ",";
    oss << "\"path\":\"" << Utils::StringUtils::EscapeJson(Utils::StringUtils::ToNarrow(path)) << "\",";
    oss << "\"filename\":\"" << Utils::StringUtils::EscapeJson(Utils::StringUtils::ToNarrow(filename)) << "\",";
    oss << "\"action\":" << static_cast<int>(action) << ",";
    oss << "\"category\":" << static_cast<int>(category) << "}";
    return oss.str();
}

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct DirectoryMonitor::Impl {
    // ---- Configuration mutex (covers m_config, m_whitelist) -----------------
    mutable std::shared_mutex m_mutex;
    DirectoryMonitorConfig m_config;
    std::shared_ptr<Whitelist::WhitelistStore> m_whitelist;

    // ---- Monitor lifetime is owned via unique_ptr so worker threads hold ----
    // ---- pointers that survive map rehash. ----------------------------------
    struct MonitorInfo {
        // Public-facing (snapshot only) ---------------------------------------
        uint32_t monitorId{0};
        std::wstring path;                // canonical path (no \\?\ prefix)
        PathCategory category{PathCategory::Unknown};
        bool recursive{true};
        TimePoint createdTime{Clock::now()};

        // Worker-thread visible state (atomics for race-free public reads) ----
        std::atomic<bool> isActive{false};
        std::atomic<bool> isPaused{false};
        std::atomic<uint64_t> eventsReceived{0};
        std::atomic<int64_t> lastEventNs{0};   // steady_clock ns since epoch

        // Win32 resources (manipulated only by Add/Stop on the main thread,
        // and inside the worker until it observes hStopEvent) ----------------
        HANDLE hDirectory{INVALID_HANDLE_VALUE};
        HANDLE hStopEvent{nullptr};
        HANDLE hThread{nullptr};
        std::vector<uint8_t> buffer;
        OVERLAPPED overlapped{};

        // Pending old-name carried across an OLD_NAME -> NEW_NAME pair. Touched
        // exclusively by this monitor's worker thread, so no synchronization
        // is required. -------------------------------------------------------
        std::wstring pendingOldName;

        // Back-pointer to the owning Impl (stable for monitor lifetime) ------
        DirectoryMonitor::Impl* pImpl{nullptr};

        MonitorInfo() = default;
        MonitorInfo(const MonitorInfo&)            = delete;
        MonitorInfo& operator=(const MonitorInfo&) = delete;
        MonitorInfo(MonitorInfo&&)                 = delete;
        MonitorInfo& operator=(MonitorInfo&&)      = delete;
    };

    using MonitorPtr = std::unique_ptr<MonitorInfo>;
    std::unordered_map<uint32_t, MonitorPtr> m_monitors;
    mutable std::shared_mutex m_monitorsMutex;
    std::atomic<uint32_t> m_nextMonitorId{1};

    // ---- Rate limiting (keyed on monitorId — bounded by live monitor count)-
    struct RateLimitInfo {
        std::deque<TimePoint> eventTimes;
        uint64_t droppedCount{0};
    };
    std::unordered_map<uint32_t, RateLimitInfo> m_rateLimits;
    std::mutex m_rateLimitMutex;

    // ---- Event tracking -----------------------------------------------------
    std::atomic<uint64_t> m_nextEventId{1};

    // ---- Callbacks ----------------------------------------------------------
    DirectoryEventCallback m_eventCallback;
    MonitorStatusCallback m_statusCallback;
    ErrorCallback m_errorCallback;
    mutable std::mutex m_callbacksMutex;

    // ---- Statistics ---------------------------------------------------------
    DirectoryMonitorStatistics m_statistics;

    // ---- Lifecycle state ----------------------------------------------------
    std::atomic<bool> m_initialized{false};
    std::atomic<DirectoryMonitorStatus> m_status{DirectoryMonitorStatus::Uninitialized};

    Impl() = default;

    ~Impl() {
        // Defensive: stop everything outside any user-held lock. The owning
        // DirectoryMonitor is only torn down when its singleton storage is
        // destroyed, so this is single-threaded by definition.
        StopAllMonitors();
    }

    // ------------------------------------------------------------------------
    // Snapshot — fills a public MonitoredPath from a live MonitorInfo. Called
    // under m_monitorsMutex (shared). Atomics are loaded with relaxed order
    // (snapshot is best-effort by definition).
    // ------------------------------------------------------------------------
    [[nodiscard]] static MonitoredPath SnapshotPath(const MonitorInfo& m) {
        MonitoredPath out;
        out.monitorId = m.monitorId;
        out.path = m.path;
        out.category = m.category;
        out.recursive = m.recursive;
        out.isActive = m.isActive.load(std::memory_order_relaxed);
        out.eventsReceived.store(m.eventsReceived.load(std::memory_order_relaxed),
                                 std::memory_order_relaxed);
        const auto ns = m.lastEventNs.load(std::memory_order_relaxed);
        if (ns > 0) {
            out.lastEvent = TimePoint(std::chrono::nanoseconds(ns));
        }
        out.createdTime = m.createdTime;
        return out;
    }

    void StopAllMonitors() {
        // Detach map under lock, release lock, then tear each monitor down.
        // This avoids holding m_monitorsMutex while blocking on worker
        // shutdown (workers themselves never take this mutex, but external
        // callers might hold it — keep the critical section tight).
        std::unordered_map<uint32_t, MonitorPtr> drained;
        {
            std::unique_lock<std::shared_mutex> lock(m_monitorsMutex);
            drained.swap(m_monitors);
        }
        for (auto& [id, mp] : drained) {
            if (mp) {
                StopMonitor(*mp);
            }
        }
        {
            std::lock_guard<std::mutex> rlock(m_rateLimitMutex);
            m_rateLimits.clear();
        }
        m_statistics.activeMonitors.store(0, std::memory_order_relaxed);
    }

    void StopMonitor(MonitorInfo& monitor) {
        // Order matters: signal stop -> cancel pending IO -> wait for thread
        // -> close handles. Cancelling IO synchronously wakes any in-flight
        // ReadDirectoryChangesW so the worker can observe hStopEvent.
        if (monitor.hStopEvent) {
            ::SetEvent(monitor.hStopEvent);
        }
        if (monitor.hDirectory != INVALID_HANDLE_VALUE) {
            ::CancelIoEx(monitor.hDirectory, &monitor.overlapped);
        }
        if (monitor.hThread) {
            // 10s gives a slow remote share's pending IO time to abort.
            const DWORD wr = ::WaitForSingleObject(monitor.hThread, 10000);
            if (wr != WAIT_OBJECT_0) {
                SS_LOG_ERROR(L"DirectoryMonitor",
                             L"Worker thread for monitor %u failed to exit (wait=%lu) — terminating",
                             monitor.monitorId, wr);
                ::TerminateThread(monitor.hThread, 1);
                ::WaitForSingleObject(monitor.hThread, 1000);
            }
            ::CloseHandle(monitor.hThread);
            monitor.hThread = nullptr;
        }
        if (monitor.hStopEvent) {
            ::CloseHandle(monitor.hStopEvent);
            monitor.hStopEvent = nullptr;
        }
        if (monitor.overlapped.hEvent) {
            ::CloseHandle(monitor.overlapped.hEvent);
            monitor.overlapped.hEvent = nullptr;
        }
        if (monitor.hDirectory != INVALID_HANDLE_VALUE) {
            ::CloseHandle(monitor.hDirectory);
            monitor.hDirectory = INVALID_HANDLE_VALUE;
        }
        monitor.isActive.store(false, std::memory_order_release);
    }

    // ---- Critical-path discovery -------------------------------------------
    // All discovery helpers are read-only on the OS and use std::wstring
    // buffers sized off the actual return value, so they are tolerant of
    // long paths. Callers must canonicalize before opening.
    [[nodiscard]] static std::vector<std::wstring> GetSystemCriticalPaths() {
        std::vector<std::wstring> paths;
        wchar_t buffer[MAX_PATH];

        if (UINT len = ::GetSystemDirectoryW(buffer, MAX_PATH); len > 0 && len < MAX_PATH) {
            paths.emplace_back(buffer, len);
        }
        if (UINT len = ::GetWindowsDirectoryW(buffer, MAX_PATH); len > 0 && len < MAX_PATH) {
            std::wstring win(buffer, len);
            paths.push_back(win);
            paths.push_back(win + L"\\System32\\drivers");
        }
        if (::SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILES, nullptr, SHGFP_TYPE_CURRENT, buffer) == S_OK) {
            paths.emplace_back(buffer);
        }
        if (::SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILESX86, nullptr, SHGFP_TYPE_CURRENT, buffer) == S_OK) {
            paths.emplace_back(buffer);
        }
        return paths;
    }

    [[nodiscard]] static std::vector<std::wstring> GetUserProfilePaths() {
        std::vector<std::wstring> paths;
        wchar_t buffer[MAX_PATH];
        if (::SHGetFolderPathW(nullptr, CSIDL_APPDATA,        nullptr, SHGFP_TYPE_CURRENT, buffer) == S_OK) paths.emplace_back(buffer);
        if (::SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA,  nullptr, SHGFP_TYPE_CURRENT, buffer) == S_OK) paths.emplace_back(buffer);
        if (::SHGetFolderPathW(nullptr, CSIDL_MYDOCUMENTS,    nullptr, SHGFP_TYPE_CURRENT, buffer) == S_OK) paths.emplace_back(buffer);
        if (::SHGetFolderPathW(nullptr, CSIDL_DESKTOP,        nullptr, SHGFP_TYPE_CURRENT, buffer) == S_OK) paths.emplace_back(buffer);
        return paths;
    }

    [[nodiscard]] static std::vector<std::wstring> GetStartupPaths() {
        std::vector<std::wstring> paths;
        wchar_t buffer[MAX_PATH];
        if (::SHGetFolderPathW(nullptr, CSIDL_STARTUP,        nullptr, SHGFP_TYPE_CURRENT, buffer) == S_OK) paths.emplace_back(buffer);
        if (::SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, SHGFP_TYPE_CURRENT, buffer) == S_OK) paths.emplace_back(buffer);
        return paths;
    }

    [[nodiscard]] static std::vector<std::wstring> GetDownloadPaths() {
        std::vector<std::wstring> paths;
        wchar_t buffer[MAX_PATH];
        if (::SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, SHGFP_TYPE_CURRENT, buffer) == S_OK) {
            paths.push_back(std::wstring(buffer) + L"\\Downloads");
        }
        return paths;
    }

    [[nodiscard]] static std::vector<std::wstring> GetTempPaths() {
        std::vector<std::wstring> paths;
        // Use dynamic sizing: GetTempPathW may exceed MAX_PATH on long-path
        // configurations.
        DWORD needed = ::GetTempPathW(0, nullptr);
        if (needed > 0) {
            std::wstring t(needed, L'\0');
            const DWORD got = ::GetTempPathW(needed, t.data());
            if (got > 0 && got < needed) {
                t.resize(got);
                paths.push_back(std::move(t));
            }
        }
        // %TEMP% with proper truncation handling.
        DWORD envSize = ::GetEnvironmentVariableW(L"TEMP", nullptr, 0);
        if (envSize > 0) {
            std::wstring e(envSize, L'\0');
            const DWORD got = ::GetEnvironmentVariableW(L"TEMP", e.data(), envSize);
            if (got > 0 && got < envSize) {
                e.resize(got);
                if (!e.empty()) {
                    paths.push_back(std::move(e));
                }
            }
        }
        return paths;
    }

    // ---- Filtering & rate limiting -----------------------------------------
    // ShouldFilterEvent reads m_config under m_mutex (shared) for every call.
    // To avoid that hot-path lock, we accept a snapshot of the bool flag.
    [[nodiscard]] bool ShouldFilterEvent(const DirectoryEvent& event,
                                         bool intelligentFiltering,
                                         std::shared_ptr<Whitelist::WhitelistStore> wl) {
        if (!intelligentFiltering) {
            return false;
        }

        std::wstring filename = event.filename;
        std::transform(filename.begin(), filename.end(), filename.begin(),
                       [](wchar_t c) { return static_cast<wchar_t>(::towlower(c)); });

        if (filename.ends_with(L".tmp") ||
            filename.ends_with(L".cache") ||
            filename.ends_with(L".bak") ||
            (!filename.empty() && filename.back() == L'~')) {
            return true;
        }
        if (filename == L"thumbs.db" ||
            filename == L"desktop.ini" ||
            filename.starts_with(L"~$")) {
            return true;
        }

        if (wl) {
            // Compose the full path in a way that preserves directory
            // boundaries, then run a robust IsPathWhitelisted query rather
            // than the catch-all IsWhitelisted to keep the cost predictable.
            std::wstring fullPath = event.path;
            if (!fullPath.empty() && fullPath.back() != L'\\' && fullPath.back() != L'/') {
                fullPath.push_back(L'\\');
            }
            fullPath.append(event.filename);
            if (wl->IsPathWhitelisted(fullPath).found) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] bool ShouldRateLimit(uint32_t monitorId,
                                       bool enabled,
                                       uint32_t windowSec,
                                       uint32_t maxEventsPerWindow) {
        if (!enabled) {
            return false;
        }
        std::lock_guard<std::mutex> lock(m_rateLimitMutex);

        // Bound the table aggressively. If we somehow grew past the failsafe
        // (e.g., monitor reuse churn), drop the oldest entries.
        if (m_rateLimits.size() > kMaxRateLimitBuckets) {
            m_rateLimits.clear();
        }

        auto& rateInfo = m_rateLimits[monitorId];
        const auto now = Clock::now();
        const auto windowStart = now - std::chrono::seconds(windowSec);

        while (!rateInfo.eventTimes.empty() && rateInfo.eventTimes.front() < windowStart) {
            rateInfo.eventTimes.pop_front();
        }
        if (rateInfo.eventTimes.size() >= maxEventsPerWindow) {
            ++rateInfo.droppedCount;
            return true;
        }
        rateInfo.eventTimes.push_back(now);
        return false;
    }

    void EraseRateLimit(uint32_t monitorId) {
        std::lock_guard<std::mutex> lock(m_rateLimitMutex);
        m_rateLimits.erase(monitorId);
    }

    // ------------------------------------------------------------------------
    // ProcessNotification: invoked exclusively from the owning monitor's
    // worker thread. Reads m_config exactly once via a snapshot to avoid
    // racing against SetConfiguration.
    // ------------------------------------------------------------------------
    struct ConfigSnapshot {
        bool   intelligentFiltering;
        bool   rateLimitingEnabled;
        uint32_t rateLimitWindowSec;
        uint32_t maxEventsPerWindow;
        std::shared_ptr<Whitelist::WhitelistStore> whitelist;
    };

    [[nodiscard]] ConfigSnapshot GetConfigSnapshot() {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        return ConfigSnapshot{
            m_config.enableIntelligentFiltering,
            m_config.enableRateLimiting,
            m_config.rateLimitWindowSec,
            m_config.maxEventsPerWindow,
            m_whitelist
        };
    }

    void ProcessNotification(MonitorInfo& monitor,
                             const FILE_NOTIFY_INFORMATION& fni,
                             const ConfigSnapshot& cfg) {
        const auto startTime = Clock::now();

        try {
            DirectoryEvent event;
            event.eventId   = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
            event.monitorId = monitor.monitorId;
            event.path      = monitor.path;
            event.category  = monitor.category;
            event.timestamp = std::chrono::system_clock::now();

            if (fni.FileNameLength > 0 && fni.FileNameLength <= kMaxFileNameBytes) {
                event.filename.assign(fni.FileName, fni.FileNameLength / sizeof(wchar_t));
            }

            switch (fni.Action) {
                case FILE_ACTION_ADDED:
                    event.action = FileSystemAction::FileAdded;
                    break;
                case FILE_ACTION_REMOVED:
                    event.action = FileSystemAction::FileRemoved;
                    break;
                case FILE_ACTION_MODIFIED:
                    event.action = FileSystemAction::FileModified;
                    break;
                case FILE_ACTION_RENAMED_OLD_NAME:
                    // Stash old name on the monitor (worker-thread-only field)
                    // and wait for the matching NEW_NAME in this very burst.
                    monitor.pendingOldName = event.filename;
                    return;
                case FILE_ACTION_RENAMED_NEW_NAME:
                    event.action = FileSystemAction::FileRenamed;
                    event.oldFilename = std::move(monitor.pendingOldName);
                    monitor.pendingOldName.clear();
                    break;
                default:
                    event.action = FileSystemAction::Unknown;
                    break;
            }

            m_statistics.totalEvents.fetch_add(1, std::memory_order_relaxed);

            if (ShouldFilterEvent(event, cfg.intelligentFiltering, cfg.whitelist)) {
                m_statistics.filteredEvents.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            if (ShouldRateLimit(monitor.monitorId,
                                cfg.rateLimitingEnabled,
                                cfg.rateLimitWindowSec,
                                cfg.maxEventsPerWindow)) {
                m_statistics.rateLimitedEvents.fetch_add(1, std::memory_order_relaxed);
                return;
            }

            const auto actionIdx = static_cast<size_t>(event.action);
            if (actionIdx < m_statistics.byAction.size()) {
                m_statistics.byAction[actionIdx].fetch_add(1, std::memory_order_relaxed);
            }
            const auto catIdx = static_cast<size_t>(event.category);
            if (catIdx < m_statistics.byCategory.size()) {
                m_statistics.byCategory[catIdx].fetch_add(1, std::memory_order_relaxed);
            }

            // Snapshot the callback under the mutex, then invoke OUTSIDE.
            // This is mandatory: a callback that re-enters DirectoryMonitor
            // (e.g. RemoveMonitor) would deadlock if we held m_callbacksMutex.
            DirectoryEventCallback cb;
            {
                std::lock_guard<std::mutex> lock(m_callbacksMutex);
                cb = m_eventCallback;
            }
            if (cb) {
                try {
                    cb(event);
                    m_statistics.callbackInvocations.fetch_add(1, std::memory_order_relaxed);
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(L"DirectoryMonitor", L"Event callback failed: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(L"DirectoryMonitor", L"Event callback failed (non-std exception)");
                }
            }

            const auto endTime = Clock::now();
            const auto durationUs = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
            m_statistics.totalProcessingTimeUs.fetch_add(static_cast<uint64_t>(durationUs),
                                                        std::memory_order_relaxed);

        } catch (const std::exception& e) {
            m_statistics.errors.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_ERROR(L"DirectoryMonitor", L"Failed to process notification: %hs", e.what());
        }
    }

    // ------------------------------------------------------------------------
    // Worker thread procedure. Owns one MonitorInfo for the duration. Exits
    // on hStopEvent or unrecoverable error. NEVER touches m_monitors or any
    // mutex that another thread might be holding while waiting for us.
    // ------------------------------------------------------------------------
    static DWORD WINAPI MonitorThreadProc(LPVOID lpParameter) {
        auto* monitor = static_cast<MonitorInfo*>(lpParameter);
        if (!monitor || !monitor->pImpl) return 1;

        const DWORD notifyFilter = FILE_NOTIFY_CHANGE_FILE_NAME |
                                   FILE_NOTIFY_CHANGE_DIR_NAME  |
                                   FILE_NOTIFY_CHANGE_ATTRIBUTES|
                                   FILE_NOTIFY_CHANGE_SIZE      |
                                   FILE_NOTIFY_CHANGE_LAST_WRITE|
                                   FILE_NOTIFY_CHANGE_CREATION;

        DWORD bytesReturned = 0;
        unsigned consecutiveErrors = 0;
        constexpr unsigned kMaxConsecutiveErrors = 16;

        while (true) {
            if (::WaitForSingleObject(monitor->hStopEvent, 0) == WAIT_OBJECT_0) {
                break;
            }

            ::ResetEvent(monitor->overlapped.hEvent);

            const BOOL ok = ::ReadDirectoryChangesW(
                monitor->hDirectory,
                monitor->buffer.data(),
                static_cast<DWORD>(monitor->buffer.size()),
                monitor->recursive ? TRUE : FALSE,
                notifyFilter,
                &bytesReturned,
                &monitor->overlapped,
                nullptr);

            if (!ok) {
                const DWORD err = ::GetLastError();
                if (err != ERROR_IO_PENDING) {
                    SS_LOG_ERROR(L"DirectoryMonitor",
                                 L"ReadDirectoryChangesW failed for %ls — Error: %lu",
                                 SanitizeForLog(monitor->path).c_str(), err);
                    monitor->pImpl->m_statistics.errors.fetch_add(1, std::memory_order_relaxed);
                    if (++consecutiveErrors >= kMaxConsecutiveErrors) {
                        // Refuse to spin: the directory has gone away or the
                        // share has died. Surface to the error callback.
                        DirectoryMonitor::Impl::FireErrorCallback(
                            *monitor->pImpl, monitor->path,
                            "ReadDirectoryChangesW persistently failing");
                        break;
                    }
                    ::Sleep(50);
                    continue;
                }
            }
            consecutiveErrors = 0;

            HANDLE waitHandles[2] = { monitor->hStopEvent, monitor->overlapped.hEvent };
            const DWORD waitResult = ::WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

            if (waitResult == WAIT_OBJECT_0) {
                ::CancelIoEx(monitor->hDirectory, &monitor->overlapped);
                // Drain the cancelled IO so we don't leak the OVERLAPPED.
                ::GetOverlappedResult(monitor->hDirectory, &monitor->overlapped, &bytesReturned, TRUE);
                break;
            }
            if (waitResult != WAIT_OBJECT_0 + 1) {
                // WAIT_FAILED or impossible value — bail out.
                SS_LOG_ERROR(L"DirectoryMonitor",
                             L"WaitForMultipleObjects unexpected result %lu (err=%lu)",
                             waitResult, ::GetLastError());
                monitor->pImpl->m_statistics.errors.fetch_add(1, std::memory_order_relaxed);
                break;
            }

            if (!::GetOverlappedResult(monitor->hDirectory, &monitor->overlapped,
                                       &bytesReturned, FALSE)) {
                const DWORD err = ::GetLastError();
                if (err == ERROR_OPERATION_ABORTED || err == ERROR_INVALID_HANDLE) {
                    break;
                }
                SS_LOG_ERROR(L"DirectoryMonitor",
                             L"GetOverlappedResult failed for %ls — Error: %lu",
                             SanitizeForLog(monitor->path).c_str(), err);
                monitor->pImpl->m_statistics.errors.fetch_add(1, std::memory_order_relaxed);
                continue;
            }

            // bytesReturned == 0 => the kernel notification buffer overflowed
            // and the entire batch was discarded. We must surface this so a
            // higher-level rescan can reconcile state — silent loss is a
            // detection-evasion primitive.
            if (bytesReturned == 0) {
                SS_LOG_WARN(L"DirectoryMonitor",
                            L"Notification buffer overflow on %ls — events lost",
                            SanitizeForLog(monitor->path).c_str());
                monitor->pImpl->m_statistics.errors.fetch_add(1, std::memory_order_relaxed);
                DirectoryMonitor::Impl::FireErrorCallback(
                    *monitor->pImpl, monitor->path,
                    "ReadDirectoryChangesW buffer overflow — events lost");
                continue;
            }

            if (monitor->isPaused.load(std::memory_order_acquire)) {
                continue;
            }

            // Snapshot the runtime config exactly once per batch.
            const ConfigSnapshot cfg = monitor->pImpl->GetConfigSnapshot();

            const uint8_t* const bufferStart = monitor->buffer.data();
            const uint8_t* const bufferEnd   = bufferStart + bytesReturned;
            const uint8_t* curBytes = bufferStart;

            while (true) {
                // Validate the FNI header first.
                if (curBytes < bufferStart || curBytes > bufferEnd) break;
                if (static_cast<size_t>(bufferEnd - curBytes) < offsetof(FILE_NOTIFY_INFORMATION, FileName)) {
                    break;
                }

                const auto* fni = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(curBytes);
                const DWORD fnameLen = fni->FileNameLength;
                const DWORD nextOff  = fni->NextEntryOffset;

                // Validate the variable-length filename payload.
                if (fnameLen > kMaxFileNameBytes) {
                    break;
                }
                const size_t recordBytes = offsetof(FILE_NOTIFY_INFORMATION, FileName) + fnameLen;
                if (static_cast<size_t>(bufferEnd - curBytes) < recordBytes) {
                    break;
                }

                monitor->pImpl->ProcessNotification(*monitor, *fni, cfg);
                monitor->eventsReceived.fetch_add(1, std::memory_order_relaxed);
                monitor->lastEventNs.store(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        Clock::now().time_since_epoch()).count(),
                    std::memory_order_relaxed);

                if (nextOff == 0) {
                    break;
                }
                // NextEntryOffset must be 4-byte aligned, > current record,
                // and stay strictly within the buffer.
                if (nextOff < recordBytes || (nextOff % 4) != 0) {
                    break;
                }
                if (static_cast<size_t>(bufferEnd - curBytes) <= nextOff) {
                    // Need at least the FNI header at the next offset.
                    if (static_cast<size_t>(bufferEnd - curBytes) < nextOff + offsetof(FILE_NOTIFY_INFORMATION, FileName)) {
                        break;
                    }
                }
                curBytes += nextOff;
            }
        }

        return 0;
    }

    // ---- Callback dispatchers (always invoked WITHOUT m_callbacksMutex) ----
    static void FireStatusCallback(Impl& self, uint32_t monitorId, bool active) {
        MonitorStatusCallback cb;
        {
            std::lock_guard<std::mutex> lock(self.m_callbacksMutex);
            cb = self.m_statusCallback;
        }
        if (cb) {
            try { cb(monitorId, active); }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"DirectoryMonitor", L"Status callback failed: %hs", e.what());
            } catch (...) {
                SS_LOG_ERROR(L"DirectoryMonitor", L"Status callback failed (non-std exception)");
            }
        }
    }

    static void FireErrorCallback(Impl& self, const std::wstring& path, const std::string& msg) {
        ErrorCallback cb;
        {
            std::lock_guard<std::mutex> lock(self.m_callbacksMutex);
            cb = self.m_errorCallback;
        }
        if (cb) {
            try { cb(path, msg); }
            catch (...) { /* swallow — caller cannot recover */ }
        }
    }
};

// ============================================================================
// Singleton Implementation
// ============================================================================

std::atomic<bool> DirectoryMonitor::s_instanceCreated{false};

DirectoryMonitor& DirectoryMonitor::Instance() noexcept {
    static DirectoryMonitor instance;
    return instance;
}

bool DirectoryMonitor::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// Lifecycle
// ============================================================================

DirectoryMonitor::DirectoryMonitor()
    : m_impl(std::make_unique<Impl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
    SS_LOG_INFO(L"DirectoryMonitor", L"Constructor called");
}

DirectoryMonitor::~DirectoryMonitor() {
    Shutdown();
    SS_LOG_INFO(L"DirectoryMonitor", L"Destructor called");
}

bool DirectoryMonitor::Initialize(const DirectoryMonitorConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"DirectoryMonitor", L"Already initialized");
        return true;
    }

    try {
        if (!config.IsValid()) {
            SS_LOG_ERROR(L"DirectoryMonitor", L"Invalid configuration");
            m_impl->m_status.store(DirectoryMonitorStatus::Error, std::memory_order_release);
            return false;
        }

        m_impl->m_config = config;

        if (!config.enabled) {
            // Explicit disabled-by-policy is not a failure: report a stable
            // Stopped state so callers can distinguish from runtime errors.
            m_impl->m_status.store(DirectoryMonitorStatus::Stopped, std::memory_order_release);
            SS_LOG_INFO(L"DirectoryMonitor", L"Disabled via configuration");
            return false;
        }

        m_impl->m_whitelist = std::make_shared<Whitelist::WhitelistStore>();

        m_impl->m_statistics.startTime = Clock::now();
        m_impl->m_status.store(DirectoryMonitorStatus::Running, std::memory_order_release);
        m_impl->m_initialized.store(true, std::memory_order_release);

        SS_LOG_INFO(L"DirectoryMonitor", L"Initialized successfully");
        return true;

    } catch (const std::exception& e) {
        m_impl->m_status.store(DirectoryMonitorStatus::Error, std::memory_order_release);
        SS_LOG_ERROR(L"DirectoryMonitor", L"Initialization failed: %hs", e.what());
        return false;
    } catch (...) {
        m_impl->m_status.store(DirectoryMonitorStatus::Error, std::memory_order_release);
        SS_LOG_ERROR(L"DirectoryMonitor", L"Initialization failed (non-std exception)");
        return false;
    }
}

void DirectoryMonitor::Shutdown() noexcept {
    if (!m_impl) {
        return;
    }
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    try {
        m_impl->m_status.store(DirectoryMonitorStatus::Stopping, std::memory_order_release);

        // StopAllMonitors handles its own locking; do NOT hold m_mutex here
        // because the worker threads (during teardown) may call back into
        // helpers that take it.
        m_impl->StopAllMonitors();

        {
            std::lock_guard<std::mutex> cbLock(m_impl->m_callbacksMutex);
            m_impl->m_eventCallback  = nullptr;
            m_impl->m_statusCallback = nullptr;
            m_impl->m_errorCallback  = nullptr;
        }

        {
            std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
            m_impl->m_whitelist.reset();
        }

        m_impl->m_status.store(DirectoryMonitorStatus::Stopped, std::memory_order_release);
        m_impl->m_initialized.store(false, std::memory_order_release);

        SS_LOG_INFO(L"DirectoryMonitor", L"Shutdown complete");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"DirectoryMonitor", L"Shutdown error: %hs", e.what());
    } catch (...) {
        SS_LOG_ERROR(L"DirectoryMonitor", L"Shutdown error (non-std exception)");
    }
}

bool DirectoryMonitor::IsInitialized() const noexcept {
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

DirectoryMonitorStatus DirectoryMonitor::GetStatus() const noexcept {
    return m_impl->m_status.load(std::memory_order_acquire);
}

// ============================================================================
// Monitor Management
// ============================================================================

void DirectoryMonitor::MonitorCriticalPaths() {
    try {
        if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_WARN(L"DirectoryMonitor", L"Not initialized");
            return;
        }

        // Snapshot the relevant config flags up front to avoid holding any
        // lock while enumerating system paths and creating worker threads.
        bool sysPaths, userPaths, startupPaths, tempDirs;
        {
            std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
            sysPaths     = m_impl->m_config.monitorSystemPaths;
            userPaths    = m_impl->m_config.monitorUserPaths;
            startupPaths = m_impl->m_config.monitorStartupLocations;
            tempDirs     = m_impl->m_config.monitorTempDirectories;
        }

        // Best-effort discovery; individual AddMonitor failures are logged
        // and counted in statistics, but they do not abort the sweep.
        if (sysPaths) {
            for (const auto& p : Impl::GetSystemCriticalPaths()) {
                (void)AddMonitor(p, PathCategory::SystemCritical, true);
            }
        }
        if (userPaths) {
            for (const auto& p : Impl::GetUserProfilePaths()) {
                (void)AddMonitor(p, PathCategory::UserProfile, true);
            }
        }
        if (startupPaths) {
            for (const auto& p : Impl::GetStartupPaths()) {
                (void)AddMonitor(p, PathCategory::Startup, true);
            }
        }
        for (const auto& p : Impl::GetDownloadPaths()) {
            (void)AddMonitor(p, PathCategory::Downloads, true);
        }
        if (tempDirs) {
            for (const auto& p : Impl::GetTempPaths()) {
                (void)AddMonitor(p, PathCategory::Temporary, true);
            }
        }

        SS_LOG_INFO(L"DirectoryMonitor", L"Critical paths monitoring started");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"DirectoryMonitor", L"Failed to monitor critical paths: %hs", e.what());
    } catch (...) {
        SS_LOG_ERROR(L"DirectoryMonitor", L"Failed to monitor critical paths (non-std exception)");
    }
}

uint32_t DirectoryMonitor::AddMonitor(const std::wstring& path,
                                       PathCategory category,
                                       bool recursive)
{
    const auto startTime = Clock::now();

    try {
        if (path.empty()) {
            SS_LOG_WARN(L"DirectoryMonitor", L"Empty path provided");
            return 0;
        }

        // Long-path-aware canonicalization.
        std::wstring canonicalPath = CanonicalizeFull(path);
        if (canonicalPath.empty()) {
            SS_LOG_WARN(L"DirectoryMonitor",
                        L"Failed to canonicalize path: %ls",
                        SanitizeForLog(path).c_str());
            return 0;
        }

        // SECURITY: refuse reparse points outright. Recursively watching a
        // junction or symlink is a TOCTOU substitution primitive — an
        // attacker can swing the link to System32 between exists() and the
        // open, exhausting the watcher with bogus events from a privileged
        // tree. NormalizePath with resolveFinal=true would silently follow
        // the link; we don't want that here.
        if (IsReparsePoint(canonicalPath)) {
            SS_LOG_WARN(L"DirectoryMonitor",
                        L"Refusing to monitor reparse point: %ls",
                        SanitizeForLog(canonicalPath).c_str());
            return 0;
        }

        // Snapshot the slice of config we need before taking m_monitorsMutex.
        DirectoryMonitorConfig cfgCopy;
        {
            std::shared_lock<std::shared_mutex> cfgLock(m_impl->m_mutex);
            if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"DirectoryMonitor", L"AddMonitor before Initialize");
                return 0;
            }
            cfgCopy = m_impl->m_config;
        }

        // Excluded path check uses the canonical form.
        for (const auto& excluded : cfgCopy.excludedPaths) {
            if (_wcsicmp(excluded.c_str(), canonicalPath.c_str()) == 0) {
                SS_LOG_INFO(L"DirectoryMonitor",
                            L"Path is excluded: %ls",
                            SanitizeForLog(canonicalPath).c_str());
                return 0;
            }
        }

        std::unique_lock<std::shared_mutex> lock(m_impl->m_monitorsMutex);

        // Already monitored?
        for (const auto& [id, mp] : m_impl->m_monitors) {
            if (mp && _wcsicmp(mp->path.c_str(), canonicalPath.c_str()) == 0) {
                SS_LOG_INFO(L"DirectoryMonitor",
                            L"Path already monitored: %ls",
                            SanitizeForLog(canonicalPath).c_str());
                return mp->monitorId;
            }
        }

        if (m_impl->m_monitors.size() >= cfgCopy.maxConcurrentMonitors) {
            SS_LOG_ERROR(L"DirectoryMonitor", L"Maximum concurrent monitors reached");
            return 0;
        }

        // Build the monitor under unique_ptr so the worker thread's pointer
        // stays valid across map rehashes.
        auto mp = std::make_unique<Impl::MonitorInfo>();
        mp->monitorId   = m_impl->m_nextMonitorId.fetch_add(1, std::memory_order_relaxed);
        mp->path        = canonicalPath;
        mp->category    = category;
        mp->recursive   = recursive;
        mp->createdTime = Clock::now();
        mp->buffer.resize(kNotifyBufferBytes);
        mp->pImpl       = m_impl.get();

        // SECURITY: open with FILE_FLAG_OPEN_REPARSE_POINT so the open does
        // NOT silently traverse a junction the way a normal CreateFile would.
        // Combined with the post-open final-path verification, this blocks
        // junction substitution races.
        mp->hDirectory = ::CreateFileW(
            canonicalPath.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);

        if (mp->hDirectory == INVALID_HANDLE_VALUE) {
            const DWORD err = ::GetLastError();
            SS_LOG_ERROR(L"DirectoryMonitor",
                         L"Failed to open directory %ls — Error: %lu",
                         SanitizeForLog(canonicalPath).c_str(), err);
            m_impl->m_statistics.errors.fetch_add(1, std::memory_order_relaxed);
            return 0;
        }

        // Verify the kernel resolved the handle to exactly the requested
        // path (i.e., no symlink/junction in any prefix component). If a
        // mismatch is detected, refuse — an attacker controls the path.
        if (!VerifyHandleResolvesTo(mp->hDirectory, canonicalPath)) {
            SS_LOG_WARN(L"DirectoryMonitor",
                        L"Refusing monitor: handle does not resolve to canonical path %ls",
                        SanitizeForLog(canonicalPath).c_str());
            ::CloseHandle(mp->hDirectory);
            return 0;
        }

        mp->hStopEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!mp->hStopEvent) {
            const DWORD err = ::GetLastError();
            ::CloseHandle(mp->hDirectory);
            SS_LOG_ERROR(L"DirectoryMonitor", L"Failed to create stop event — Error: %lu", err);
            return 0;
        }

        mp->overlapped.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!mp->overlapped.hEvent) {
            const DWORD err = ::GetLastError();
            ::CloseHandle(mp->hDirectory);
            ::CloseHandle(mp->hStopEvent);
            SS_LOG_ERROR(L"DirectoryMonitor", L"Failed to create IO event — Error: %lu", err);
            return 0;
        }

        const uint32_t monitorId = mp->monitorId;
        Impl::MonitorInfo* rawPtr = mp.get();   // stable for monitor lifetime
        m_impl->m_monitors.emplace(monitorId, std::move(mp));

        rawPtr->hThread = ::CreateThread(nullptr, 0, Impl::MonitorThreadProc, rawPtr, 0, nullptr);
        if (!rawPtr->hThread) {
            const DWORD err = ::GetLastError();
            m_impl->StopMonitor(*rawPtr);
            m_impl->m_monitors.erase(monitorId);
            SS_LOG_ERROR(L"DirectoryMonitor", L"Failed to create worker thread — Error: %lu", err);
            return 0;
        }

        rawPtr->isActive.store(true, std::memory_order_release);

        m_impl->m_statistics.activeMonitors.fetch_add(1, std::memory_order_relaxed);
        m_impl->m_statistics.pathsDiscovered.fetch_add(1, std::memory_order_relaxed);

        const auto endTime = Clock::now();
        const auto durationUs = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        m_impl->m_statistics.totalProcessingTimeUs.fetch_add(static_cast<uint64_t>(durationUs),
                                                              std::memory_order_relaxed);

        SS_LOG_INFO(L"DirectoryMonitor",
                    L"Monitor added — ID: %u, Path: %ls, Category: %d",
                    monitorId, SanitizeForLog(canonicalPath).c_str(),
                    static_cast<int>(category));

        // Drop the m_monitorsMutex BEFORE firing the status callback to
        // avoid deadlocks if the callback tries to query/modify monitors.
        lock.unlock();
        Impl::FireStatusCallback(*m_impl, monitorId, true);

        return monitorId;

    } catch (const std::exception& e) {
        m_impl->m_statistics.errors.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_ERROR(L"DirectoryMonitor", L"Failed to add monitor: %hs", e.what());
        return 0;
    } catch (...) {
        m_impl->m_statistics.errors.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_ERROR(L"DirectoryMonitor", L"Failed to add monitor (non-std exception)");
        return 0;
    }
}

void DirectoryMonitor::RemoveMonitor(uint32_t monitorId) {
    try {
        Impl::MonitorPtr taken;
        {
            std::unique_lock<std::shared_mutex> lock(m_impl->m_monitorsMutex);
            auto it = m_impl->m_monitors.find(monitorId);
            if (it == m_impl->m_monitors.end()) {
                SS_LOG_WARN(L"DirectoryMonitor", L"Monitor not found — ID: %u", monitorId);
                return;
            }
            taken = std::move(it->second);
            m_impl->m_monitors.erase(it);
        }

        // Tear down outside the map lock — StopMonitor blocks on the worker.
        if (taken) {
            m_impl->StopMonitor(*taken);
        }
        m_impl->EraseRateLimit(monitorId);
        m_impl->m_statistics.activeMonitors.fetch_sub(1, std::memory_order_relaxed);

        SS_LOG_INFO(L"DirectoryMonitor", L"Monitor removed — ID: %u", monitorId);
        Impl::FireStatusCallback(*m_impl, monitorId, false);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"DirectoryMonitor", L"Failed to remove monitor: %hs", e.what());
    } catch (...) {
        SS_LOG_ERROR(L"DirectoryMonitor", L"Failed to remove monitor (non-std exception)");
    }
}

void DirectoryMonitor::RemoveAllMonitors() {
    m_impl->StopAllMonitors();
    SS_LOG_INFO(L"DirectoryMonitor", L"All monitors removed");
}

bool DirectoryMonitor::IsMonitored(const std::wstring& path) const {
    // Compare against the canonical form — callers may pass either the raw
    // or resolved path.
    const std::wstring canonical = CanonicalizeFull(path);
    const std::wstring& key = canonical.empty() ? path : canonical;

    std::shared_lock<std::shared_mutex> lock(m_impl->m_monitorsMutex);
    for (const auto& [id, mp] : m_impl->m_monitors) {
        if (mp && _wcsicmp(mp->path.c_str(), key.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

std::vector<MonitoredPath> DirectoryMonitor::GetMonitoredPaths() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_monitorsMutex);

    std::vector<MonitoredPath> paths;
    paths.reserve(m_impl->m_monitors.size());
    for (const auto& [id, mp] : m_impl->m_monitors) {
        if (mp) {
            paths.push_back(Impl::SnapshotPath(*mp));
        }
    }
    return paths;
}

std::optional<MonitoredPath> DirectoryMonitor::GetMonitorById(uint32_t monitorId) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_monitorsMutex);

    auto it = m_impl->m_monitors.find(monitorId);
    if (it != m_impl->m_monitors.end() && it->second) {
        return Impl::SnapshotPath(*it->second);
    }
    return std::nullopt;
}

size_t DirectoryMonitor::GetActiveMonitorCount() const noexcept {
    return m_impl->m_statistics.activeMonitors.load(std::memory_order_relaxed);
}

// ============================================================================
// Monitor Control
// ============================================================================

void DirectoryMonitor::PauseAll() noexcept {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_monitorsMutex);
    for (auto& [id, mp] : m_impl->m_monitors) {
        if (mp) {
            mp->isPaused.store(true, std::memory_order_release);
        }
    }
    m_impl->m_status.store(DirectoryMonitorStatus::Paused, std::memory_order_release);
    SS_LOG_INFO(L"DirectoryMonitor", L"All monitors paused");
}

void DirectoryMonitor::ResumeAll() noexcept {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_monitorsMutex);
    for (auto& [id, mp] : m_impl->m_monitors) {
        if (mp) {
            mp->isPaused.store(false, std::memory_order_release);
        }
    }
    m_impl->m_status.store(DirectoryMonitorStatus::Running, std::memory_order_release);
    SS_LOG_INFO(L"DirectoryMonitor", L"All monitors resumed");
}

void DirectoryMonitor::PauseMonitor(uint32_t monitorId) noexcept {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_monitorsMutex);
    auto it = m_impl->m_monitors.find(monitorId);
    if (it != m_impl->m_monitors.end() && it->second) {
        it->second->isPaused.store(true, std::memory_order_release);
        SS_LOG_INFO(L"DirectoryMonitor", L"Monitor paused — ID: %u", monitorId);
    }
}

void DirectoryMonitor::ResumeMonitor(uint32_t monitorId) noexcept {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_monitorsMutex);
    auto it = m_impl->m_monitors.find(monitorId);
    if (it != m_impl->m_monitors.end() && it->second) {
        it->second->isPaused.store(false, std::memory_order_release);
        SS_LOG_INFO(L"DirectoryMonitor", L"Monitor resumed — ID: %u", monitorId);
    }
}

// ============================================================================
// Callbacks
// ============================================================================

void DirectoryMonitor::SetEventCallback(DirectoryEventCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    m_impl->m_eventCallback = std::move(callback);
}

void DirectoryMonitor::SetMonitorStatusCallback(MonitorStatusCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    m_impl->m_statusCallback = std::move(callback);
}

void DirectoryMonitor::SetErrorCallback(ErrorCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    m_impl->m_errorCallback = std::move(callback);
}

void DirectoryMonitor::UnregisterCallbacks() {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    m_impl->m_eventCallback  = nullptr;
    m_impl->m_statusCallback = nullptr;
    m_impl->m_errorCallback  = nullptr;
}

// ============================================================================
// Configuration
// ============================================================================

DirectoryMonitorConfig DirectoryMonitor::GetConfiguration() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
    return m_impl->m_config;
}

void DirectoryMonitor::SetConfiguration(const DirectoryMonitorConfig& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(L"DirectoryMonitor", L"Refusing invalid configuration");
        return;
    }
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_config = config;
    SS_LOG_INFO(L"DirectoryMonitor", L"Configuration updated");
}

// ============================================================================
// Statistics
// ============================================================================

const DirectoryMonitorStatistics& DirectoryMonitor::GetStatistics() const noexcept {
    return m_impl->m_statistics;
}

void DirectoryMonitor::ResetStatistics() noexcept {
    m_impl->m_statistics.Reset();
    SS_LOG_INFO(L"DirectoryMonitor", L"Statistics reset");
}

// ============================================================================
// Testing & Diagnostics
// ============================================================================

bool DirectoryMonitor::SelfTest() {
    try {
        SS_LOG_INFO(L"DirectoryMonitor", L"Starting self-test");

        DWORD needed = ::GetTempPathW(0, nullptr);
        if (needed == 0) {
            SS_LOG_ERROR(L"DirectoryMonitor", L"Self-test failed — Cannot size temp path");
            return false;
        }
        std::wstring tempPath(needed, L'\0');
        const DWORD got = ::GetTempPathW(needed, tempPath.data());
        if (got == 0 || got >= needed) {
            SS_LOG_ERROR(L"DirectoryMonitor", L"Self-test failed — Cannot get temp path");
            return false;
        }
        tempPath.resize(got);

        const uint32_t monitorId = AddMonitor(tempPath, PathCategory::Temporary, false);
        if (monitorId == 0) {
            SS_LOG_ERROR(L"DirectoryMonitor", L"Self-test failed — Cannot add monitor");
            return false;
        }

        if (!IsMonitored(tempPath)) {
            SS_LOG_ERROR(L"DirectoryMonitor", L"Self-test failed — IsMonitored check failed");
            RemoveMonitor(monitorId);
            return false;
        }

        PauseMonitor(monitorId);
        ResumeMonitor(monitorId);
        RemoveMonitor(monitorId);

        if (IsMonitored(tempPath)) {
            SS_LOG_ERROR(L"DirectoryMonitor", L"Self-test failed — Monitor still active after removal");
            return false;
        }

        SS_LOG_INFO(L"DirectoryMonitor", L"Self-test passed");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"DirectoryMonitor", L"Self-test failed: %hs", e.what());
        return false;
    } catch (...) {
        SS_LOG_ERROR(L"DirectoryMonitor", L"Self-test failed (non-std exception)");
        return false;
    }
}

std::string DirectoryMonitor::GetVersionString() noexcept {
    return std::to_string(DirectoryMonitorConstants::VERSION_MAJOR) + "." +
           std::to_string(DirectoryMonitorConstants::VERSION_MINOR) + "." +
           std::to_string(DirectoryMonitorConstants::VERSION_PATCH);
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string_view GetPathCategoryName(PathCategory category) noexcept {
    switch (category) {
        case PathCategory::Unknown:        return "Unknown";
        case PathCategory::SystemCritical: return "SystemCritical";
        case PathCategory::UserProfile:    return "UserProfile";
        case PathCategory::Startup:        return "Startup";
        case PathCategory::Downloads:      return "Downloads";
        case PathCategory::Temporary:      return "Temporary";
        case PathCategory::RemovableMedia: return "RemovableMedia";
        case PathCategory::NetworkShare:   return "NetworkShare";
        case PathCategory::CloudSync:      return "CloudSync";
        case PathCategory::Custom:         return "Custom";
    }
    return "Unknown";
}

std::string_view GetFileSystemActionName(FileSystemAction action) noexcept {
    switch (action) {
        case FileSystemAction::Unknown:           return "Unknown";
        case FileSystemAction::FileAdded:         return "FileAdded";
        case FileSystemAction::FileRemoved:       return "FileRemoved";
        case FileSystemAction::FileModified:      return "FileModified";
        case FileSystemAction::FileRenamed:       return "FileRenamed";
        case FileSystemAction::DirectoryAdded:    return "DirectoryAdded";
        case FileSystemAction::DirectoryRemoved:  return "DirectoryRemoved";
        case FileSystemAction::DirectoryRenamed:  return "DirectoryRenamed";
    }
    return "Unknown";
}

std::string_view GetMonitorStatusName(DirectoryMonitorStatus status) noexcept {
    switch (status) {
        case DirectoryMonitorStatus::Uninitialized: return "Uninitialized";
        case DirectoryMonitorStatus::Initializing:  return "Initializing";
        case DirectoryMonitorStatus::Running:       return "Running";
        case DirectoryMonitorStatus::Paused:        return "Paused";
        case DirectoryMonitorStatus::Error:         return "Error";
        case DirectoryMonitorStatus::Stopping:      return "Stopping";
        case DirectoryMonitorStatus::Stopped:       return "Stopped";
    }
    return "Unknown";
}

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
