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
 * ShadowStrike Core FileSystem - FILE WATCHER IMPLEMENTATION
 * ============================================================================
 *
 * @file FileWatcher.cpp
 * @brief Enterprise-grade high-performance directory monitoring using IOCP.
 *
 * This module provides real-time file system monitoring using Windows I/O
 * Completion Ports (IOCP) for maximum performance and scalability. It serves
 * as the user-mode companion to the kernel minifilter driver.
 *
 * Key Features:
 * - IOCP-based asynchronous monitoring (handles 10,000+ events/sec)
 * - Event debouncing and coalescing to reduce noise
 * - Rapid change detection for ransomware patterns (T1486)
 * - Multi-threaded event processing with priority queue
 * - Pattern-based filtering (glob/regex)
 * - Comprehensive statistics tracking
 * - Self-healing watch recovery
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "FileWatcher.hpp"

// Infrastructure includes
#include "../../Utils/Logger.hpp"

// Windows headers
#include <winioctl.h>

// Standard library
#include <algorithm>
#include <fstream>
#include <queue>
#include <deque>
#include <map>
#include <sstream>
#include <iomanip>

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

namespace fs = std::filesystem;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Converts FileAction to string for logging.
 */
const char* ActionToString(FileAction action) {
    switch (action) {
        case FileAction::Added: return "Added";
        case FileAction::Removed: return "Removed";
        case FileAction::Modified: return "Modified";
        case FileAction::RenamedOldName: return "RenamedOldName";
        case FileAction::RenamedNewName: return "RenamedNewName";
        case FileAction::SecurityChanged: return "SecurityChanged";
        case FileAction::AttributesChanged: return "AttributesChanged";
        default: return "Unknown";
    }
}

/**
 * @brief Converts Windows FILE_ACTION to FileAction.
 */
FileAction ConvertFileAction(DWORD dwAction) {
    switch (dwAction) {
        case FILE_ACTION_ADDED: return FileAction::Added;
        case FILE_ACTION_REMOVED: return FileAction::Removed;
        case FILE_ACTION_MODIFIED: return FileAction::Modified;
        case FILE_ACTION_RENAMED_OLD_NAME: return FileAction::RenamedOldName;
        case FILE_ACTION_RENAMED_NEW_NAME: return FileAction::RenamedNewName;
        default: return FileAction::Unknown;
    }
}

/**
 * @brief Converts WatchFilter to Windows notification flags.
 */
DWORD ConvertWatchFilter(WatchFilter filter) {
    return static_cast<DWORD>(filter);
}

/**
 * @brief Simple glob pattern matching.
 */
bool MatchesGlobPattern(const std::wstring& str, const std::wstring& pattern) {
    if (pattern.empty()) return true;
    if (pattern == L"*") return true;

    // Simple wildcard matching
    size_t sPos = 0, pPos = 0;
    size_t sStar = std::wstring::npos, pStar = std::wstring::npos;

    while (sPos < str.length()) {
        if (pPos < pattern.length() && (pattern[pPos] == str[sPos] || pattern[pPos] == L'?')) {
            sPos++;
            pPos++;
        } else if (pPos < pattern.length() && pattern[pPos] == L'*') {
            pStar = pPos++;
            sStar = sPos;
        } else if (pStar != std::wstring::npos) {
            pPos = pStar + 1;
            sPos = ++sStar;
        } else {
            return false;
        }
    }

    while (pPos < pattern.length() && pattern[pPos] == L'*') {
        pPos++;
    }

    return pPos == pattern.length();
}

/**
 * @brief Checks if file should be excluded.
 */
bool ShouldExclude(const std::wstring& filename, const std::vector<std::wstring>& patterns) {
    for (const auto& pattern : patterns) {
        if (MatchesGlobPattern(filename, pattern)) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Gets file size safely.
 */
uint64_t GetFileSizeSafe(const std::wstring& path) {
    try {
        if (fs::exists(path) && fs::is_regular_file(path)) {
            return fs::file_size(path);
        }
    } catch (...) {
    }
    return 0;
}

/**
 * @brief Checks if file is executable.
 */
bool IsExecutableFile(const std::wstring& filename) {
    std::wstring lower = filename;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    return lower.ends_with(L".exe") || lower.ends_with(L".dll") ||
           lower.ends_with(L".sys") || lower.ends_with(L".scr") ||
           lower.ends_with(L".com") || lower.ends_with(L".bat") ||
           lower.ends_with(L".cmd") || lower.ends_with(L".ps1") ||
           lower.ends_with(L".vbs") || lower.ends_with(L".js");
}

/**
 * @brief Normalizes path for comparison.
 */
std::wstring NormalizePath(const std::wstring& path) {
    try {
        return fs::path(path).lexically_normal().wstring();
    } catch (...) {
        return path;
    }
}

} // anonymous namespace

// ============================================================================
// CONFIGURATION STATIC METHODS
// ============================================================================

FileWatcherConfig FileWatcherConfig::CreateDefault() noexcept {
    FileWatcherConfig config;
    config.workerThreads = FileWatcherConstants::DEFAULT_WORKER_THREADS;
    config.debounceMs = FileWatcherConstants::DEFAULT_DEBOUNCE_MS;
    config.enableEventCoalescing = true;
    config.enableRapidChangeDetection = true;
    return config;
}

FileWatcherConfig FileWatcherConfig::CreateHighPerformance() noexcept {
    FileWatcherConfig config;
    config.workerThreads = FileWatcherConstants::MAX_WORKER_THREADS;
    config.debounceMs = 50;
    config.eventQueueSize = 50000;
    config.enableEventCoalescing = true;
    config.enablePriorityProcessing = true;
    config.collectFileMetadata = false;  // Skip for performance
    return config;
}

FileWatcherConfig FileWatcherConfig::CreateLowLatency() noexcept {
    FileWatcherConfig config;
    config.workerThreads = 2;
    config.debounceMs = FileWatcherConstants::MIN_DEBOUNCE_MS;
    config.enableEventCoalescing = false;
    config.collectFileMetadata = true;
    return config;
}

FileWatcherConfig FileWatcherConfig::CreateRansomwareDetection() noexcept {
    FileWatcherConfig config;
    config.workerThreads = 4;
    config.debounceMs = 50;
    config.enableRapidChangeDetection = true;
    config.rapidChangeConfig.enabled = true;
    config.rapidChangeConfig.windowSizeMs = 1000;
    config.rapidChangeConfig.thresholdCount = 50;
    config.rapidChangeConfig.alertOnDetection = true;
    config.rapidChangeConfig.pauseWatchOnDetection = true;
    config.collectFileMetadata = true;
    config.excludeTempFiles = true;
    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void FileWatcherStatistics::Reset() noexcept {
    totalEventsReceived.store(0, std::memory_order_relaxed);
    eventsProcessed.store(0, std::memory_order_relaxed);
    eventsDropped.store(0, std::memory_order_relaxed);
    eventsCoalesced.store(0, std::memory_order_relaxed);
    byType.Reset();
    peakEventsPerSecond.store(0, std::memory_order_relaxed);
    averageLatencyUs.store(0, std::memory_order_relaxed);
    maxLatencyUs.store(0, std::memory_order_relaxed);
    activeWatches.store(0, std::memory_order_relaxed);
    failedWatches.store(0, std::memory_order_relaxed);
    watchRestarts.store(0, std::memory_order_relaxed);
    memoryUsageBytes.store(0, std::memory_order_relaxed);
    bufferPoolSize.store(0, std::memory_order_relaxed);
    rapidChangeAlerts.store(0, std::memory_order_relaxed);
}

// ============================================================================
// INTERNAL WATCH HANDLE STRUCTURE
// ============================================================================

struct WatchHandle {
    HANDLE directoryHandle{ INVALID_HANDLE_VALUE };
    OVERLAPPED overlapped{};
    std::vector<uint8_t> buffer;
    WatchEntry entry;
    std::atomic<bool> active{ false };
    std::atomic<uint32_t> retryCount{ 0 };
    static constexpr uint32_t MAX_RETRIES = 5;
    std::chrono::steady_clock::time_point deathTime;

    WatchHandle(size_t bufferSize) : buffer(bufferSize) {
        ZeroMemory(&overlapped, sizeof(OVERLAPPED));
    }

    ~WatchHandle() {
        Close();
    }

    void Close() {
        active.store(false, std::memory_order_release);

        if (directoryHandle != INVALID_HANDLE_VALUE) {
            CancelIoEx(directoryHandle, &overlapped);
            CloseHandle(directoryHandle);
            directoryHandle = INVALID_HANDLE_VALUE;
        }
        deathTime = std::chrono::steady_clock::now();
    }
};

// ============================================================================
// RAPID CHANGE TRACKER
// ============================================================================

class RapidChangeTracker {
public:
    struct EventRecord {
        std::chrono::steady_clock::time_point timestamp;
        std::wstring path;
        FileAction action;
    };

    RapidChangeTracker(const RapidChangeDetection& config)
        : m_config(config)
        , m_windowSize(std::chrono::milliseconds(config.windowSizeMs)) {
    }

    bool AddEvent(const FileEvent& event) {
        if (!m_config.enabled) return false;

        std::lock_guard lock(m_mutex);

        const auto now = std::chrono::steady_clock::now();

        // Cap deque size to prevent unbounded memory growth under flood
        constexpr size_t MAX_TRACKED_EVENTS = 10000;
        if (m_events.size() >= MAX_TRACKED_EVENTS) {
            m_events.pop_front();
        }

        // Add event
        m_events.push_back({now, event.GetFullPath(), event.action});

        // Remove old events outside window
        const auto cutoff = now - m_windowSize;
        while (!m_events.empty() && m_events.front().timestamp < cutoff) {
            m_events.pop_front();
        }

        // Check threshold
        if (m_events.size() >= m_config.thresholdCount) {
            // Rapid change detected
            m_lastDetectionTime = now;
            m_detectionCount++;

            SS_LOG_WARN(L"FileWatcher", L"RapidChange: %zu events in %u ms - possible ransomware",
                        m_events.size(), m_config.windowSizeMs);

            return true;
        }

        return false;
    }

    void Reset() {
        std::lock_guard lock(m_mutex);
        m_events.clear();
        m_detectionCount = 0;
    }

    size_t GetEventCount() const {
        std::lock_guard lock(m_mutex);
        return m_events.size();
    }

    uint64_t GetDetectionCount() const {
        return m_detectionCount.load(std::memory_order_relaxed);
    }

    std::vector<std::wstring> GetAffectedFiles(size_t maxCount = 100) const {
        std::lock_guard lock(m_mutex);
        std::vector<std::wstring> files;
        files.reserve(std::min(m_events.size(), maxCount));

        for (size_t i = 0; i < std::min(m_events.size(), maxCount); ++i) {
            files.push_back(m_events[i].path);
        }

        return files;
    }

private:
    RapidChangeDetection m_config;
    std::chrono::milliseconds m_windowSize;
    mutable std::mutex m_mutex;
    std::deque<EventRecord> m_events;
    std::chrono::steady_clock::time_point m_lastDetectionTime;
    std::atomic<uint64_t> m_detectionCount{ 0 };
};

// ============================================================================
// EVENT DEBOUNCER
// ============================================================================

class EventDebouncer {
public:
    EventDebouncer(uint32_t debounceMs)
        : m_debounceTime(std::chrono::milliseconds(debounceMs)) {
    }

    std::optional<FileEvent> ProcessEvent(const FileEvent& event) {
        std::lock_guard lock(m_mutex);

        const auto now = std::chrono::steady_clock::now();
        const std::wstring key = event.GetFullPath() + L":" +
                                std::to_wstring(static_cast<int>(event.action));

        auto it = m_pendingEvents.find(key);

        if (it != m_pendingEvents.end()) {
            const auto elapsed = now - it->second.timestamp;

            if (elapsed < m_debounceTime) {
                // Within debounce window: suppress duplicate
                it->second.event.coalescedCount++;
                it->second.timestamp = now;
                return std::nullopt;
            }

            // Debounce window expired: new distinct occurrence, emit and restart window
            it->second.event = event;
            it->second.timestamp = now;
            return event;
        }

        // First occurrence: emit immediately, start debounce window for dedup
        m_pendingEvents[key] = {event, now};

        // Clean up old entries
        CleanupOldEntries(now);

        return event;
    }

    std::vector<FileEvent> Flush() {
        std::lock_guard lock(m_mutex);
        std::vector<FileEvent> events;
        events.reserve(m_pendingEvents.size());

        for (const auto& [key, pending] : m_pendingEvents) {
            events.push_back(pending.event);
        }

        m_pendingEvents.clear();
        return events;
    }

    void SetDebounceTime(uint32_t ms) {
        std::lock_guard lock(m_mutex);
        m_debounceTime = std::chrono::milliseconds(ms);
    }

private:
    struct PendingEvent {
        FileEvent event;
        std::chrono::steady_clock::time_point timestamp;
    };

    void CleanupOldEntries(std::chrono::steady_clock::time_point now) {
        // Remove entries older than 10x debounce time
        const auto cutoff = now - (m_debounceTime * 10);

        for (auto it = m_pendingEvents.begin(); it != m_pendingEvents.end();) {
            if (it->second.timestamp < cutoff) {
                it = m_pendingEvents.erase(it);
            } else {
                ++it;
            }
        }
    }

    std::chrono::milliseconds m_debounceTime;
    std::mutex m_mutex;
    std::unordered_map<std::wstring, PendingEvent> m_pendingEvents;
};

// ============================================================================
// CALLBACK MANAGER
// ============================================================================

class CallbackManager {
public:
    uint64_t RegisterEventCallback(EventCallback callback) {
        std::lock_guard lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_eventCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterAlertCallback(WatchAlertCallback callback) {
        std::lock_guard lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_alertCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterStateCallback(WatchStateCallback callback) {
        std::lock_guard lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_stateCallbacks[id] = std::move(callback);
        return id;
    }

    bool Unregister(uint64_t id) {
        std::lock_guard lock(m_mutex);

        if (m_eventCallbacks.erase(id) > 0) return true;
        if (m_alertCallbacks.erase(id) > 0) return true;
        if (m_stateCallbacks.erase(id) > 0) return true;

        return false;
    }

    void InvokeEventCallbacks(const FileEvent& event) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_eventCallbacks) {
            try {
                callback(event);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"FileWatcher", L"EventCallback exception: %hs", e.what());
            }
        }
    }

    void InvokeAlertCallbacks(const WatchAlert& alert) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_alertCallbacks) {
            try {
                callback(alert);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"FileWatcher", L"AlertCallback exception: %hs", e.what());
            }
        }
    }

    void InvokeStateCallbacks(uint32_t watchId, WatchState newState) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_stateCallbacks) {
            try {
                callback(watchId, newState);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"FileWatcher", L"StateCallback exception: %hs", e.what());
            }
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    uint64_t m_nextId{ 1 };
    std::unordered_map<uint64_t, EventCallback> m_eventCallbacks;
    std::unordered_map<uint64_t, WatchAlertCallback> m_alertCallbacks;
    std::unordered_map<uint64_t, WatchStateCallback> m_stateCallbacks;
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class FileWatcherImpl {
public:
    FileWatcherImpl() = default;
    ~FileWatcherImpl() {
        Stop();
    }

    // Prevent copying
    FileWatcherImpl(const FileWatcherImpl&) = delete;
    FileWatcherImpl& operator=(const FileWatcherImpl&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const FileWatcherConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Initializing...");

            m_config = config;

            // Validate configuration
            if (m_config.workerThreads < FileWatcherConstants::MIN_WORKER_THREADS ||
                m_config.workerThreads > FileWatcherConstants::MAX_WORKER_THREADS) {
                SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Invalid worker thread count: %u", m_config.workerThreads);
                return false;
            }

            // Create IOCP
            m_completionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, m_config.workerThreads);
            if (m_completionPort == nullptr) {
                SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Failed to create IOCP: %lu", GetLastError());
                return false;
            }

            // Initialize debouncer
            m_debouncer = std::make_unique<EventDebouncer>(m_config.debounceMs);

            // Initialize rapid change tracker
            if (m_config.enableRapidChangeDetection) {
                m_rapidChangeTracker = std::make_unique<RapidChangeTracker>(m_config.rapidChangeConfig);
            }

            // Initialize callback manager
            m_callbackManager = std::make_unique<CallbackManager>();

            m_initialized = true;
            SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Initialization failed: %hs", e.what());
            return false;
        }
    }

    bool Start(EventCallback callback) {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Not initialized");
            return false;
        }

        if (m_running) {
            SS_LOG_WARN(L"FileWatcher", L"FileWatcher: Already running");
            return true;
        }

        try {
            // Register primary callback
            m_callbackManager->RegisterEventCallback(std::move(callback));

            // Start worker threads
            m_running = true;
            m_startTime = std::chrono::steady_clock::now();
            for (uint32_t i = 0; i < m_config.workerThreads; ++i) {
                m_workerThreads.emplace_back([this]() { WorkerThread(); });
            }

            SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Started with %u worker threads", m_config.workerThreads);
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Start failed: %hs", e.what());
            m_running = false;
            return false;
        }
    }

    void Stop() noexcept {
        {
            std::unique_lock lock(m_mutex);
            if (!m_running) return;

            SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Stopping...");
            m_running = false;
        }

        // Wake batch flush thread if running
        m_batchCv.notify_all();
        if (m_batchThread.joinable()) {
            m_batchThread.join();
        }

        // Final batch flush
        FlushBatchEvents();

        // Stop all watches — move to zombie list to prevent use-after-free
        {
            std::unique_lock lock(m_mutex);
            for (auto& [id, handle] : m_watches) {
                handle->Close();
                m_zombieHandles.push_back(std::move(handle));
            }
            m_watches.clear();
            m_stats.activeWatches.store(0, std::memory_order_relaxed);
        }

        // Signal worker threads to exit
        if (m_completionPort != nullptr) {
            for (size_t i = 0; i < m_workerThreads.size(); ++i) {
                PostQueuedCompletionStatus(m_completionPort, 0, 0, nullptr);
            }
        }

        // Wait for worker threads
        for (auto& thread : m_workerThreads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        m_workerThreads.clear();

        // Now safe to destroy zombies — all workers have exited
        {
            std::unique_lock lock(m_mutex);
            m_zombieHandles.clear();
        }

        // Cleanup IOCP
        if (m_completionPort != nullptr) {
            CloseHandle(m_completionPort);
            m_completionPort = nullptr;
        }

        SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Stopped");
    }

    bool IsRunning() const noexcept {
        return m_running.load(std::memory_order_acquire);
    }

    // ========================================================================
    // WATCH MANAGEMENT
    // ========================================================================

    uint32_t AddWatch(const std::wstring& directory, bool recursive,
                     WatchPriority priority, WatchFilter filter) {
        if (!m_initialized || !m_running) {
            SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Not initialized or not running");
            return 0;
        }

        try {
            // Validate path
            if (directory.empty() || directory.length() > FileWatcherConstants::MAX_PATH_LENGTH) {
                SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Invalid directory path");
                return 0;
            }

            // Security: reject UNC/network paths to prevent monitoring redirection
            if (directory.starts_with(L"\\\\")) {
                SS_LOG_WARN(L"FileWatcher", L"FileWatcher: Rejecting UNC/network path: %hs",
                            Utils::StringUtils::ToNarrow(directory).c_str());
                return 0;
            }

            if (!fs::exists(directory) || !fs::is_directory(directory)) {
                SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Directory does not exist: %hs",
                             Utils::StringUtils::ToNarrow(directory).c_str());
                return 0;
            }

            // Security: reject reparse points (symlinks/junctions) to prevent monitoring manipulation
            const DWORD attrs = GetFileAttributesW(directory.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
                SS_LOG_WARN(L"FileWatcher", L"FileWatcher: Rejecting reparse point (symlink/junction): %hs",
                            Utils::StringUtils::ToNarrow(directory).c_str());
                return 0;
            }

            uint32_t watchId = 0;

            {
                std::unique_lock lock(m_mutex);

                // Check limit
                if (m_watches.size() >= FileWatcherConstants::MAX_WATCHES) {
                    SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Maximum watches reached");
                    return 0;
                }

                // Check for duplicate path
                const std::wstring normalizedDir = NormalizePath(directory);
                for (const auto& [existingId, existingHandle] : m_watches) {
                    if (existingHandle->entry.directory == normalizedDir) {
                        SS_LOG_WARN(L"FileWatcher", L"FileWatcher: Directory already watched (ID %u): %hs",
                                    existingId, Utils::StringUtils::ToNarrow(directory).c_str());
                        return existingId;
                    }
                }

                // Create watch handle
                auto handle = std::make_unique<WatchHandle>(m_config.watchBufferSize);

                // Open directory
                handle->directoryHandle = CreateFileW(
                    directory.c_str(),
                    FILE_LIST_DIRECTORY,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                    nullptr
                );

                if (handle->directoryHandle == INVALID_HANDLE_VALUE) {
                    SS_LOG_LAST_ERROR(L"FileWatcher", L"FileWatcher: Failed to open directory: %hs",
                                     Utils::StringUtils::ToNarrow(directory).c_str());
                    m_stats.failedWatches.fetch_add(1, std::memory_order_relaxed);
                    return 0;
                }

                // Associate with IOCP
                if (CreateIoCompletionPort(handle->directoryHandle, m_completionPort,
                                          reinterpret_cast<ULONG_PTR>(handle.get()), 0) == nullptr) {
                    SS_LOG_LAST_ERROR(L"FileWatcher", L"FileWatcher: Failed to associate with IOCP");
                    m_stats.failedWatches.fetch_add(1, std::memory_order_relaxed);
                    return 0;
                }

                // Setup watch entry
                watchId = m_nextWatchId++;
                handle->entry.watchId = watchId;
                handle->entry.directory = NormalizePath(directory);
                handle->entry.recursive = recursive;
                handle->entry.filter = filter;
                handle->entry.priority = priority;
                handle->entry.state = WatchState::Active;
                handle->entry.createdTime = std::chrono::steady_clock::now();

                // Start async read
                if (!StartWatchRead(handle.get())) {
                    SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Failed to start watch read for ID %u", watchId);
                    m_stats.failedWatches.fetch_add(1, std::memory_order_relaxed);
                    return 0;
                }

                handle->active.store(true, std::memory_order_release);

                // Store watch
                m_watches[watchId] = std::move(handle);
                m_stats.activeWatches.fetch_add(1, std::memory_order_relaxed);

                SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Added watch %u for: %hs",
                            watchId, Utils::StringUtils::ToNarrow(directory).c_str());
            }

            // Invoke state callback WITHOUT holding m_mutex to prevent deadlock
            m_callbackManager->InvokeStateCallbacks(watchId, WatchState::Active);

            return watchId;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileWatcher", L"FileWatcher::AddWatch: Exception: %hs", e.what());
            return 0;
        }
    }

    uint32_t AddWatchWithPatterns(const std::wstring& directory,
                                 const std::vector<std::wstring>& includePatterns,
                                 const std::vector<std::wstring>& excludePatterns,
                                 bool recursive) {
        uint32_t watchId = AddWatch(directory, recursive, WatchPriority::Normal, WatchFilter::AllChanges);

        if (watchId == 0) {
            return 0;
        }

        // Add patterns to watch entry
        std::unique_lock lock(m_mutex);
        auto it = m_watches.find(watchId);
        if (it != m_watches.end()) {
            it->second->entry.includePatterns = includePatterns;
            it->second->entry.excludePatterns = excludePatterns;
        }

        return watchId;
    }

    bool RemoveWatch(uint32_t watchId) {
        {
            std::unique_lock lock(m_mutex);

            auto it = m_watches.find(watchId);
            if (it == m_watches.end()) {
                return false;
            }

            SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Removing watch %u", watchId);

            it->second->Close();
            // Move to zombie list to prevent use-after-free from pending IOCP completions
            m_zombieHandles.push_back(std::move(it->second));
            m_watches.erase(it);

            m_stats.activeWatches.fetch_sub(1, std::memory_order_relaxed);
        }

        // Invoke callback WITHOUT holding m_mutex to prevent deadlock
        m_callbackManager->InvokeStateCallbacks(watchId, WatchState::Removed);

        return true;
    }

    void RemoveAll() noexcept {
        std::unique_lock lock(m_mutex);

        SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Removing all watches (%zu total)", m_watches.size());

        for (auto& [id, handle] : m_watches) {
            handle->Close();
            m_zombieHandles.push_back(std::move(handle));
        }

        m_watches.clear();
        m_stats.activeWatches.store(0, std::memory_order_relaxed);
    }

    bool PauseWatch(uint32_t watchId) {
        {
            std::unique_lock lock(m_mutex);

            auto it = m_watches.find(watchId);
            if (it == m_watches.end()) {
                return false;
            }

            it->second->entry.state = WatchState::Paused;
        }
        m_callbackManager->InvokeStateCallbacks(watchId, WatchState::Paused);
        return true;
    }

    bool ResumeWatch(uint32_t watchId) {
        {
            std::unique_lock lock(m_mutex);

            auto it = m_watches.find(watchId);
            if (it == m_watches.end()) {
                return false;
            }

            if (it->second->entry.state != WatchState::Paused) {
                return false;
            }

            it->second->entry.state = WatchState::Active;
        }
        m_callbackManager->InvokeStateCallbacks(watchId, WatchState::Active);
        return true;
    }

    std::optional<WatchEntry> GetWatchInfo(uint32_t watchId) const {
        std::shared_lock lock(m_mutex);

        auto it = m_watches.find(watchId);
        if (it == m_watches.end()) {
            return std::nullopt;
        }

        return it->second->entry;
    }

    std::vector<WatchEntry> GetAllWatches() const {
        std::shared_lock lock(m_mutex);
        std::vector<WatchEntry> watches;
        watches.reserve(m_watches.size());

        for (const auto& [id, handle] : m_watches) {
            watches.push_back(handle->entry);
        }

        return watches;
    }

    bool IsWatched(const std::wstring& path) const {
        std::shared_lock lock(m_mutex);
        std::wstring normalized = NormalizePath(path);

        for (const auto& [id, handle] : m_watches) {
            if (normalized.starts_with(handle->entry.directory)) {
                return true;
            }
        }

        return false;
    }

    // ========================================================================
    // FILTERING
    // ========================================================================

    void AddExclusionPattern(const std::wstring& pattern) {
        std::unique_lock lock(m_mutex);
        m_globalExclusions.insert(pattern);
        SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Added exclusion pattern: %hs", Utils::StringUtils::ToNarrow(pattern).c_str());
    }

    void RemoveExclusionPattern(const std::wstring& pattern) {
        std::unique_lock lock(m_mutex);
        m_globalExclusions.erase(pattern);
    }

    void AddExclusionPath(const std::wstring& path) {
        std::unique_lock lock(m_mutex);
        m_excludedPaths.insert(NormalizePath(path));
        SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Added exclusion path: %hs", Utils::StringUtils::ToNarrow(path).c_str());
    }

    void RemoveExclusionPath(const std::wstring& path) {
        std::unique_lock lock(m_mutex);
        m_excludedPaths.erase(NormalizePath(path));
    }

    std::vector<std::wstring> GetExclusionPatterns() const {
        std::shared_lock lock(m_mutex);
        return std::vector<std::wstring>(m_globalExclusions.begin(), m_globalExclusions.end());
    }

    // ========================================================================
    // RAPID CHANGE DETECTION
    // ========================================================================

    void EnableRapidChangeDetection(WatchAlertCallback callback, const RapidChangeDetection& config) {
        std::unique_lock lock(m_mutex);

        if (!m_rapidChangeTracker) {
            m_rapidChangeTracker = std::make_unique<RapidChangeTracker>(config);
        }

        m_callbackManager->RegisterAlertCallback(std::move(callback));
        m_config.enableRapidChangeDetection = true;
    }

    void DisableRapidChangeDetection() noexcept {
        std::unique_lock lock(m_mutex);
        m_config.enableRapidChangeDetection = false;
    }

    bool IsRapidChangeDetected(uint32_t watchId) const {
        std::shared_lock lock(m_mutex);

        if (!m_rapidChangeTracker) {
            return false;
        }

        return m_rapidChangeTracker->GetDetectionCount() > 0;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    uint64_t RegisterEventCallback(EventCallback callback) {
        return m_callbackManager->RegisterEventCallback(std::move(callback));
    }

    uint64_t RegisterAlertCallback(WatchAlertCallback callback) {
        return m_callbackManager->RegisterAlertCallback(std::move(callback));
    }

    uint64_t RegisterStateCallback(WatchStateCallback callback) {
        return m_callbackManager->RegisterStateCallback(std::move(callback));
    }

    bool UnregisterCallback(uint64_t callbackId) {
        return m_callbackManager->Unregister(callbackId);
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    void SetDebounceTime(uint32_t debounceMs) {
        debounceMs = std::clamp(debounceMs,
                                FileWatcherConstants::MIN_DEBOUNCE_MS,
                                FileWatcherConstants::MAX_DEBOUNCE_MS);
        if (m_debouncer) {
            m_debouncer->SetDebounceTime(debounceMs);
            m_config.debounceMs = debounceMs;
        }
    }

    void SetEventCoalescing(bool enable) noexcept {
        m_config.enableEventCoalescing = enable;
    }

    void SetRateLimit(uint32_t eventsPerSecond) {
        m_rateLimitPerSec.store(eventsPerSecond, std::memory_order_relaxed);
        m_rateLimitCounter.store(0, std::memory_order_relaxed);
        m_rateLimitWindowTicks.store(
            std::chrono::steady_clock::now().time_since_epoch().count(),
            std::memory_order_relaxed);
        SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Rate limit set to %u events/sec", eventsPerSecond);
    }

    bool StartBatch(BatchEventCallback callback, size_t batchSize, uint32_t batchTimeoutMs) {
        if (!m_initialized) {
            SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Not initialized for batch start");
            return false;
        }

        m_batchCallback = std::move(callback);
        m_batchSize = (batchSize > 0) ? batchSize : 100;
        m_batchTimeoutMs = (batchTimeoutMs > 0) ? batchTimeoutMs : 100;

        // Wrap with a no-op event callback; actual dispatch goes through batch accumulator
        auto noopCallback = [](const FileEvent&) {};

        SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Starting batch mode (size=%zu, timeout=%u ms)",
                    m_batchSize, m_batchTimeoutMs);

        if (!Start(noopCallback)) {
            return false;
        }

        // Enable batch mode and start flush thread AFTER Start succeeds
        m_batchMode.store(true, std::memory_order_release);
        m_batchThread = std::thread([this]() { BatchFlushThread(); });

        return true;
    }

    bool ExportDiagnostics(const std::wstring& outputPath) const {
        try {
            std::wofstream out(outputPath);
            if (!out.is_open()) {
                SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Failed to open diagnostics output: %hs",
                             Utils::StringUtils::ToNarrow(outputPath).c_str());
                return false;
            }

            out << L"=== FileWatcher Diagnostics ===\n";
            out << L"Running: " << (m_running.load() ? L"Yes" : L"No") << L"\n";
            out << L"Active watches: " << m_stats.activeWatches.load() << L"\n";
            out << L"Failed watches: " << m_stats.failedWatches.load() << L"\n";
            out << L"Watch restarts: " << m_stats.watchRestarts.load() << L"\n\n";

            out << L"=== Event Statistics ===\n";
            out << L"Total received: " << m_stats.totalEventsReceived.load() << L"\n";
            out << L"Processed: " << m_stats.eventsProcessed.load() << L"\n";
            out << L"Dropped: " << m_stats.eventsDropped.load() << L"\n";
            out << L"Coalesced: " << m_stats.eventsCoalesced.load() << L"\n\n";

            out << L"=== By Type ===\n";
            out << L"Added: " << m_stats.byType.added.load() << L"\n";
            out << L"Removed: " << m_stats.byType.removed.load() << L"\n";
            out << L"Modified: " << m_stats.byType.modified.load() << L"\n";
            out << L"Renamed: " << m_stats.byType.renamed.load() << L"\n";
            out << L"Security: " << m_stats.byType.securityChanged.load() << L"\n";
            out << L"Attributes: " << m_stats.byType.attributesChanged.load() << L"\n\n";

            out << L"=== Performance ===\n";
            out << L"Peak events/sec: " << m_stats.peakEventsPerSecond.load() << L"\n";
            out << L"Avg latency (us): " << m_stats.averageLatencyUs.load() << L"\n";
            out << L"Max latency (us): " << m_stats.maxLatencyUs.load() << L"\n";
            out << L"Memory usage: " << m_stats.memoryUsageBytes.load() << L" bytes\n\n";

            out << L"=== Alerts ===\n";
            out << L"Rapid change alerts: " << m_stats.rapidChangeAlerts.load() << L"\n";

            // List active watches
            {
                std::shared_lock lock(m_mutex);
                out << L"\n=== Active Watches ===\n";
                for (const auto& [id, handle] : m_watches) {
                    out << L"Watch " << id << L": " << handle->entry.directory
                        << L" (events=" << handle->entry.eventsReceived.load(std::memory_order_relaxed)
                        << L", state=" << static_cast<int>(handle->entry.state.load(std::memory_order_relaxed)) << L")\n";
                }
            }

            out.flush();
            SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Diagnostics exported to %hs",
                        Utils::StringUtils::ToNarrow(outputPath).c_str());
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: ExportDiagnostics failed: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const FileWatcherStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    size_t GetPendingEventCount() const noexcept {
        return m_pendingEvents.load(std::memory_order_relaxed);
    }

    double GetCurrentEventsPerSecond() const noexcept {
        const uint64_t total = m_stats.totalEventsReceived.load(std::memory_order_relaxed);
        const auto now = std::chrono::steady_clock::now();
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_startTime);

        if (elapsed.count() == 0) return 0.0;
        return static_cast<double>(total) / elapsed.count();
    }

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    bool StartWatchRead(WatchHandle* handle) {
        if (!handle || handle->directoryHandle == INVALID_HANDLE_VALUE) {
            return false;
        }

        ZeroMemory(&handle->overlapped, sizeof(OVERLAPPED));

        const DWORD notifyFilter = ConvertWatchFilter(handle->entry.filter);

        BOOL result = ReadDirectoryChangesW(
            handle->directoryHandle,
            handle->buffer.data(),
            static_cast<DWORD>(handle->buffer.size()),
            handle->entry.recursive ? TRUE : FALSE,
            notifyFilter,
            nullptr,
            &handle->overlapped,
            nullptr
        );

        if (!result) {
            SS_LOG_ERROR(L"FileWatcher", L"ReadDirectoryChangesW failed: %lu", GetLastError());
            return false;
        }

        return true;
    }

    void WorkerThread() {
        SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Worker thread started");

        while (m_running.load(std::memory_order_acquire)) {
            DWORD bytesTransferred = 0;
            ULONG_PTR completionKey = 0;
            OVERLAPPED* overlapped = nullptr;

            const BOOL result = GetQueuedCompletionStatus(
                m_completionPort,
                &bytesTransferred,
                &completionKey,
                &overlapped,
                1000  // 1 second timeout
            );

            if (!result) {
                const DWORD error = GetLastError();

                if (error == WAIT_TIMEOUT) {
                    // Periodic maintenance: clean up zombie handles
                    CleanupZombies();
                    continue;
                }

                if (error == ERROR_ABANDONED_WAIT_0) {
                    SS_LOG_INFO(L"FileWatcher", L"FileWatcher: IOCP abandoned, thread exiting");
                    break;
                }

                if (overlapped == nullptr) {
                    continue;
                }

                // Error on specific watch — validate handle is still alive
                auto* handle = reinterpret_cast<WatchHandle*>(completionKey);
                if (handle && handle->active.load(std::memory_order_acquire)) {
                    SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Error on watch %u: Win32 error %lu",
                                 handle->entry.watchId, error);
                    HandleWatchError(handle);
                }

                continue;
            }

            // Check for shutdown signal
            if (bytesTransferred == 0 && completionKey == 0 && overlapped == nullptr) {
                SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Shutdown signal received");
                break;
            }

            // Process completion — check active flag to skip zombies
            auto* handle = reinterpret_cast<WatchHandle*>(completionKey);
            if (handle && handle->active.load(std::memory_order_acquire)) {
                ProcessNotifications(handle, bytesTransferred);

                // Restart read
                if (handle->active.load(std::memory_order_acquire)) {
                    StartWatchRead(handle);
                }
            }
        }

        SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Worker thread exited");
    }

    void ProcessNotifications(WatchHandle* handle, DWORD bytesTransferred) {
        if (bytesTransferred == 0) {
            // Buffer overflow: too many changes happened — some events are lost
            SS_LOG_WARN(L"FileWatcher", L"FileWatcher: Buffer overflow on watch %u (events lost), consider increasing buffer size",
                        handle->entry.watchId);
            return;
        }

        // Bounds checking: FILE_NOTIFY_INFORMATION has variable-length FileName at the end.
        // Minimum size is the fixed header fields (without any filename characters).
        constexpr size_t kMinNotificationSize = offsetof(FILE_NOTIFY_INFORMATION, FileName);

        if (bytesTransferred < kMinNotificationSize) {
            SS_LOG_WARN(L"FileWatcher", L"FileWatcher: Notification buffer too small: %lu bytes",
                        bytesTransferred);
            return;
        }

        const uint8_t* bufferStart = handle->buffer.data();
        const uint8_t* bufferEnd = bufferStart + bytesTransferred;
        const uint8_t* current = bufferStart;

        while (true) {
            // Ensure the fixed header fits within bounds
            if (current + kMinNotificationSize > bufferEnd) {
                SS_LOG_WARN(L"FileWatcher", L"FileWatcher: Notification header extends past buffer");
                break;
            }

            const auto* notification = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(current);

            // Validate FileNameLength doesn't exceed remaining buffer
            const size_t remainingAfterHeader = static_cast<size_t>(bufferEnd - current) - kMinNotificationSize;
            if (notification->FileNameLength > remainingAfterHeader) {
                SS_LOG_WARN(L"FileWatcher", L"FileWatcher: Notification filename exceeds buffer: nameLen=%lu, remaining=%zu",
                            notification->FileNameLength, remainingAfterHeader);
                break;
            }

            // FileNameLength must be even (it's measured in bytes for wchar_t pairs)
            if (notification->FileNameLength % sizeof(wchar_t) != 0) {
                SS_LOG_WARN(L"FileWatcher", L"FileWatcher: Odd FileNameLength: %lu", notification->FileNameLength);
                break;
            }

            try {
                ProcessSingleNotification(handle, notification);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Exception processing notification: %hs", e.what());
            }

            if (notification->NextEntryOffset == 0) {
                break;
            }

            // Validate NextEntryOffset: must advance forward and stay in bounds
            const uint8_t* next = current + notification->NextEntryOffset;
            if (next <= current || next + kMinNotificationSize > bufferEnd) {
                SS_LOG_WARN(L"FileWatcher", L"FileWatcher: Invalid NextEntryOffset: %lu at buffer offset %zu",
                            notification->NextEntryOffset, static_cast<size_t>(current - bufferStart));
                break;
            }

            current = next;
        }
    }

    void ProcessSingleNotification(WatchHandle* handle, const FILE_NOTIFY_INFORMATION* notification) {
        // Skip if watch is paused
        if (handle->entry.state != WatchState::Active) {
            return;
        }

        // Extract filename
        std::wstring filename(notification->FileName, notification->FileNameLength / sizeof(wchar_t));

        // Check exclusions
        if (ShouldExcludeFile(filename, handle->entry)) {
            return;
        }

        // Create event
        FileEvent event;
        event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
        event.timestamp = std::chrono::steady_clock::now();
        event.directory = handle->entry.directory;
        event.filename = filename;
        event.fullPath = (fs::path(handle->entry.directory) / filename).wstring();
        event.action = ConvertFileAction(notification->Action);
        event.watchId = handle->entry.watchId;
        event.priority = handle->entry.priority;

        // Collect metadata if enabled
        if (m_config.collectFileMetadata) {
            CollectFileMetadata(event);
        }

        // Determine severity
        event.severity = DetermineSeverity(event);

        // Update statistics
        m_stats.totalEventsReceived.fetch_add(1, std::memory_order_relaxed);
        handle->entry.eventsReceived.fetch_add(1, std::memory_order_relaxed);
        handle->entry.lastEventTime = event.timestamp;
        UpdateEventStatistics(event);

        // Check rapid change detection
        if (m_config.enableRapidChangeDetection && m_rapidChangeTracker) {
            if (m_rapidChangeTracker->AddEvent(event)) {
                // Rapid change detected
                HandleRapidChange(handle, event);
            }
        }

        // Debounce if enabled
        if (m_config.enableEventCoalescing && m_debouncer) {
            auto debouncedEvent = m_debouncer->ProcessEvent(event);
            if (debouncedEvent.has_value()) {
                DispatchEvent(debouncedEvent.value());
            } else {
                m_stats.eventsCoalesced.fetch_add(1, std::memory_order_relaxed);
            }
        } else {
            DispatchEvent(event);
        }
    }

    bool ShouldExcludeFile(const std::wstring& filename, const WatchEntry& entry) const {
        // Check watch-specific exclusions
        if (ShouldExclude(filename, entry.excludePatterns)) {
            return true;
        }

        // Check global pattern exclusions and full-path exclusions
        {
            std::shared_lock lock(m_mutex);

            for (const auto& pattern : m_globalExclusions) {
                if (MatchesGlobPattern(filename, pattern)) {
                    return true;
                }
            }

            // Check full-path exclusions
            if (!m_excludedPaths.empty()) {
                const std::wstring fullPath = (fs::path(entry.directory) / filename).wstring();
                const std::wstring normalizedFull = NormalizePath(fullPath);
                for (const auto& excludedPath : m_excludedPaths) {
                    if (normalizedFull == excludedPath || normalizedFull.starts_with(excludedPath + L"\\")) {
                        return true;
                    }
                }
            }
        }

        // Check config exclusions
        if (m_config.excludeTempFiles) {
            if (filename.ends_with(L".tmp") || filename.ends_with(L".temp") || filename.starts_with(L"~$")) {
                return true;
            }
        }

        // Enforce include patterns: if specified, file must match at least one
        if (!entry.includePatterns.empty()) {
            bool matchedAny = false;
            for (const auto& pattern : entry.includePatterns) {
                if (MatchesGlobPattern(filename, pattern)) {
                    matchedAny = true;
                    break;
                }
            }
            if (!matchedAny) {
                return true;
            }
        }

        return false;
    }

    void CollectFileMetadata(FileEvent& event) {
        try {
            const fs::path path(event.fullPath);

            if (!fs::exists(path)) {
                return;
            }

            event.isDirectory = fs::is_directory(path);

            if (!event.isDirectory) {
                event.fileSize = GetFileSizeSafe(event.fullPath);
                event.isExecutable = IsExecutableFile(event.filename);
            }

            // Get attributes
            const DWORD attrs = GetFileAttributesW(event.fullPath.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES) {
                event.isHidden = (attrs & FILE_ATTRIBUTE_HIDDEN) != 0;
                event.isSystem = (attrs & FILE_ATTRIBUTE_SYSTEM) != 0;
            }

        } catch (...) {
            // Metadata collection is best-effort
        }
    }

    EventSeverity DetermineSeverity(const FileEvent& event) const {
        // Critical: Executable modifications
        if (event.isExecutable && event.action == FileAction::Modified) {
            return EventSeverity::Critical;
        }

        // High: Executable added/removed
        if (event.isExecutable && (event.action == FileAction::Added || event.action == FileAction::Removed)) {
            return EventSeverity::High;
        }

        // High: Security/attribute changes
        if (event.action == FileAction::SecurityChanged || event.action == FileAction::AttributesChanged) {
            return EventSeverity::High;
        }

        // Medium: Regular file modifications
        if (event.action == FileAction::Modified) {
            return EventSeverity::Medium;
        }

        // Low: Everything else
        return EventSeverity::Low;
    }

    void UpdateEventStatistics(const FileEvent& event) {
        switch (event.action) {
            case FileAction::Added:
                m_stats.byType.added.fetch_add(1, std::memory_order_relaxed);
                break;
            case FileAction::Removed:
                m_stats.byType.removed.fetch_add(1, std::memory_order_relaxed);
                break;
            case FileAction::Modified:
                m_stats.byType.modified.fetch_add(1, std::memory_order_relaxed);
                break;
            case FileAction::RenamedOldName:
            case FileAction::RenamedNewName:
                m_stats.byType.renamed.fetch_add(1, std::memory_order_relaxed);
                break;
            case FileAction::SecurityChanged:
                m_stats.byType.securityChanged.fetch_add(1, std::memory_order_relaxed);
                break;
            case FileAction::AttributesChanged:
                m_stats.byType.attributesChanged.fetch_add(1, std::memory_order_relaxed);
                break;
            default:
                break;
        }
    }

    void DispatchEvent(const FileEvent& event) {
        // Rate limiting check (lock-free using atomics)
        const uint32_t limit = m_rateLimitPerSec.load(std::memory_order_relaxed);
        if (limit > 0) {
            const auto nowTicks = std::chrono::steady_clock::now().time_since_epoch().count();
            auto windowStart = m_rateLimitWindowTicks.load(std::memory_order_relaxed);
            const auto oneSecTicks = std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                std::chrono::seconds(1)).count();

            if (nowTicks - windowStart >= oneSecTicks) {
                // Window expired: CAS to reset (only one thread wins)
                if (m_rateLimitWindowTicks.compare_exchange_strong(
                        windowStart, nowTicks, std::memory_order_relaxed)) {
                    m_rateLimitCounter.store(0, std::memory_order_relaxed);
                }
            }

            if (m_rateLimitCounter.fetch_add(1, std::memory_order_relaxed) >= limit) {
                m_stats.eventsDropped.fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }

        m_pendingEvents.fetch_add(1, std::memory_order_relaxed);

        try {
            // If batch mode, accumulate instead of dispatching directly
            if (m_batchMode.load(std::memory_order_acquire)) {
                AccumulateBatchEvent(event);
            } else {
                m_callbackManager->InvokeEventCallbacks(event);
            }
            m_stats.eventsProcessed.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Exception dispatching event: %hs", e.what());
            m_stats.eventsDropped.fetch_add(1, std::memory_order_relaxed);
        }

        m_pendingEvents.fetch_sub(1, std::memory_order_relaxed);
    }

    void HandleRapidChange(WatchHandle* handle, const FileEvent& event) {
        m_stats.rapidChangeAlerts.fetch_add(1, std::memory_order_relaxed);

        // Create alert
        WatchAlert alert;
        alert.alertId = m_nextAlertId.fetch_add(1, std::memory_order_relaxed);
        alert.timestamp = std::chrono::system_clock::now();
        alert.alertType = "RapidChange";
        alert.severity = EventSeverity::Critical;
        alert.watchDirectory = handle->entry.directory;
        alert.watchId = handle->entry.watchId;
        alert.description = "Rapid file system changes detected - possible ransomware activity";
        alert.eventCount = m_rapidChangeTracker->GetEventCount();
        alert.timeWindowMs = m_config.rapidChangeConfig.windowSizeMs;
        alert.affectedFiles = m_rapidChangeTracker->GetAffectedFiles();

        SS_LOG_FATAL(L"FileWatcher", L"RAPID CHANGE ALERT - %llu events in %u ms on watch %u",
                     static_cast<unsigned long long>(alert.eventCount),
                     alert.timeWindowMs, alert.watchId);

        // Invoke alert callbacks
        m_callbackManager->InvokeAlertCallbacks(alert);

        // Pause watch if configured
        if (m_config.rapidChangeConfig.pauseWatchOnDetection) {
            SS_LOG_WARN(L"FileWatcher", L"FileWatcher: Pausing watch %u due to rapid change",
                        handle->entry.watchId);
            handle->entry.state = WatchState::Paused;
            m_callbackManager->InvokeStateCallbacks(handle->entry.watchId, WatchState::Paused);
        }
    }

    void HandleWatchError(WatchHandle* handle) {
        m_stats.failedWatches.fetch_add(1, std::memory_order_relaxed);

        const uint32_t retries = handle->retryCount.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Watch %u encountered error (retry %u/%u)",
                     handle->entry.watchId, retries + 1, WatchHandle::MAX_RETRIES);

        if (retries >= WatchHandle::MAX_RETRIES) {
            SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Watch %u exceeded max retries, marking as error",
                         handle->entry.watchId);
            handle->entry.state = WatchState::Error;
            m_callbackManager->InvokeStateCallbacks(handle->entry.watchId, WatchState::Error);
            return;
        }

        handle->entry.state = WatchState::Error;
        m_callbackManager->InvokeStateCallbacks(handle->entry.watchId, WatchState::Error);

        // Attempt immediate restart without blocking the IOCP worker thread
        if (StartWatchRead(handle)) {
            SS_LOG_INFO(L"FileWatcher", L"FileWatcher: Successfully restarted watch %u",
                        handle->entry.watchId);
            handle->entry.state = WatchState::Active;
            handle->retryCount.store(0, std::memory_order_relaxed);
            m_callbackManager->InvokeStateCallbacks(handle->entry.watchId, WatchState::Active);
            m_stats.watchRestarts.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    std::atomic<bool> m_running{ false };
    FileWatcherConfig m_config;

    // IOCP
    HANDLE m_completionPort{ nullptr };
    std::vector<std::thread> m_workerThreads;

    // Watches
    std::unordered_map<uint32_t, std::unique_ptr<WatchHandle>> m_watches;
    uint32_t m_nextWatchId{ 1 };

    // Zombie handles: kept alive until IOCP cancellation notifications drain
    std::vector<std::unique_ptr<WatchHandle>> m_zombieHandles;

    // Event management
    std::unique_ptr<EventDebouncer> m_debouncer;
    std::unique_ptr<RapidChangeTracker> m_rapidChangeTracker;
    std::unique_ptr<CallbackManager> m_callbackManager;

    // Filtering
    std::unordered_set<std::wstring> m_globalExclusions;
    std::unordered_set<std::wstring> m_excludedPaths;  // Full-path exclusions (normalized)

    // Rate limiting (all atomics — accessed from multiple worker threads)
    std::atomic<uint32_t> m_rateLimitPerSec{ 0 };
    std::atomic<uint64_t> m_rateLimitCounter{ 0 };
    std::atomic<int64_t> m_rateLimitWindowTicks{
        std::chrono::steady_clock::now().time_since_epoch().count() };

    // Batch mode
    std::atomic<bool> m_batchMode{ false };
    BatchEventCallback m_batchCallback;
    size_t m_batchSize{ 100 };
    uint32_t m_batchTimeoutMs{ 100 };
    std::vector<FileEvent> m_batchBuffer;
    std::mutex m_batchMutex;
    std::condition_variable m_batchCv;
    std::thread m_batchThread;

    // Statistics
    FileWatcherStatistics m_stats;
    std::atomic<uint64_t> m_nextEventId{ 1 };
    std::atomic<uint64_t> m_nextAlertId{ 1 };
    std::atomic<size_t> m_pendingEvents{ 0 };
    std::chrono::steady_clock::time_point m_startTime{ std::chrono::steady_clock::now() };

    // ========================================================================
    // BATCH PROCESSING HELPERS
    // ========================================================================

    void AccumulateBatchEvent(const FileEvent& event) {
        bool shouldFlush = false;
        {
            std::lock_guard lock(m_batchMutex);
            // Cap batch buffer to prevent unbounded growth under event flood
            if (m_batchBuffer.size() >= FileWatcherConstants::MAX_PENDING_EVENTS) {
                m_stats.eventsDropped.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            m_batchBuffer.push_back(event);
            shouldFlush = (m_batchBuffer.size() >= m_batchSize);
        }
        if (shouldFlush) {
            FlushBatchEvents();
        }
    }

    void FlushBatchEvents() {
        std::vector<FileEvent> batch;
        {
            std::lock_guard lock(m_batchMutex);
            if (m_batchBuffer.empty()) return;
            batch.swap(m_batchBuffer);
        }
        try {
            if (m_batchCallback) {
                m_batchCallback(batch);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileWatcher", L"FileWatcher: Batch callback exception: %hs", e.what());
        }
    }

    void BatchFlushThread() {
        SS_LOG_DEBUG(L"FileWatcher", L"FileWatcher: Batch flush thread started");
        while (m_running.load(std::memory_order_acquire)) {
            {
                std::unique_lock lock(m_batchMutex);
                m_batchCv.wait_for(lock, std::chrono::milliseconds(m_batchTimeoutMs));
            }
            FlushBatchEvents();
        }
        FlushBatchEvents();
        SS_LOG_DEBUG(L"FileWatcher", L"FileWatcher: Batch flush thread exited");
    }

    // ========================================================================
    // ZOMBIE CLEANUP
    // ========================================================================

    void CleanupZombies() {
        std::unique_lock lock(m_mutex);
        if (m_zombieHandles.empty()) return;

        const auto now = std::chrono::steady_clock::now();
        const auto safeAge = std::chrono::seconds(5);

        std::erase_if(m_zombieHandles, [&](const std::unique_ptr<WatchHandle>& z) {
            return (now - z->deathTime) > safeAge;
        });
    }
};

// ============================================================================
// MAIN CLASS IMPLEMENTATION (FORWARDING)
// ============================================================================

FileWatcher::FileWatcher()
    : m_impl(std::make_unique<FileWatcherImpl>()) {
}

FileWatcher::~FileWatcher() = default;

FileWatcher::FileWatcher(FileWatcher&& other) noexcept = default;
FileWatcher& FileWatcher::operator=(FileWatcher&& other) noexcept = default;

bool FileWatcher::Initialize(const FileWatcherConfig& config) {
    return m_impl->Initialize(config);
}

bool FileWatcher::Start(EventCallback callback) {
    return m_impl->Start(std::move(callback));
}

bool FileWatcher::StartBatch(BatchEventCallback callback, size_t batchSize, uint32_t batchTimeoutMs) {
    return m_impl->StartBatch(std::move(callback), batchSize, batchTimeoutMs);
}

void FileWatcher::Stop() noexcept {
    m_impl->Stop();
}

bool FileWatcher::IsRunning() const noexcept {
    return m_impl->IsRunning();
}

uint32_t FileWatcher::AddWatch(const std::wstring& directory, bool recursive,
                               WatchPriority priority, WatchFilter filter) {
    return m_impl->AddWatch(directory, recursive, priority, filter);
}

uint32_t FileWatcher::AddWatchWithPatterns(const std::wstring& directory,
                                          const std::vector<std::wstring>& includePatterns,
                                          const std::vector<std::wstring>& excludePatterns,
                                          bool recursive) {
    return m_impl->AddWatchWithPatterns(directory, includePatterns, excludePatterns, recursive);
}

bool FileWatcher::RemoveWatch(uint32_t watchId) {
    return m_impl->RemoveWatch(watchId);
}

bool FileWatcher::RemoveWatchByPath(const std::wstring& directory) {
    auto watches = m_impl->GetAllWatches();
    for (const auto& watch : watches) {
        if (watch.directory == NormalizePath(directory)) {
            return m_impl->RemoveWatch(watch.watchId);
        }
    }
    return false;
}

void FileWatcher::RemoveAll() noexcept {
    m_impl->RemoveAll();
}

bool FileWatcher::PauseWatch(uint32_t watchId) {
    return m_impl->PauseWatch(watchId);
}

bool FileWatcher::ResumeWatch(uint32_t watchId) {
    return m_impl->ResumeWatch(watchId);
}

std::optional<WatchEntry> FileWatcher::GetWatchInfo(uint32_t watchId) const {
    return m_impl->GetWatchInfo(watchId);
}

std::vector<WatchEntry> FileWatcher::GetAllWatches() const {
    return m_impl->GetAllWatches();
}

bool FileWatcher::IsWatched(const std::wstring& path) const {
    return m_impl->IsWatched(path);
}

void FileWatcher::AddExclusionPattern(const std::wstring& pattern) {
    m_impl->AddExclusionPattern(pattern);
}

void FileWatcher::RemoveExclusionPattern(const std::wstring& pattern) {
    m_impl->RemoveExclusionPattern(pattern);
}

void FileWatcher::AddExclusionPath(const std::wstring& path) {
    m_impl->AddExclusionPath(path);
}

void FileWatcher::RemoveExclusionPath(const std::wstring& path) {
    m_impl->RemoveExclusionPath(path);
}

std::vector<std::wstring> FileWatcher::GetExclusionPatterns() const {
    return m_impl->GetExclusionPatterns();
}

void FileWatcher::EnableRapidChangeDetection(WatchAlertCallback callback, const RapidChangeDetection& config) {
    m_impl->EnableRapidChangeDetection(std::move(callback), config);
}

void FileWatcher::DisableRapidChangeDetection() noexcept {
    m_impl->DisableRapidChangeDetection();
}

bool FileWatcher::IsRapidChangeDetected(uint32_t watchId) const {
    return m_impl->IsRapidChangeDetected(watchId);
}

uint64_t FileWatcher::RegisterEventCallback(EventCallback callback) {
    return m_impl->RegisterEventCallback(std::move(callback));
}

uint64_t FileWatcher::RegisterAlertCallback(WatchAlertCallback callback) {
    return m_impl->RegisterAlertCallback(std::move(callback));
}

uint64_t FileWatcher::RegisterStateCallback(WatchStateCallback callback) {
    return m_impl->RegisterStateCallback(std::move(callback));
}

bool FileWatcher::UnregisterCallback(uint64_t callbackId) {
    return m_impl->UnregisterCallback(callbackId);
}

void FileWatcher::SetDebounceTime(uint32_t debounceMs) {
    m_impl->SetDebounceTime(debounceMs);
}

void FileWatcher::SetRateLimit(uint32_t eventsPerSecond) {
    m_impl->SetRateLimit(eventsPerSecond);
}

void FileWatcher::SetEventCoalescing(bool enable) noexcept {
    m_impl->SetEventCoalescing(enable);
}

const FileWatcherStatistics& FileWatcher::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void FileWatcher::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

size_t FileWatcher::GetPendingEventCount() const noexcept {
    return m_impl->GetPendingEventCount();
}

double FileWatcher::GetCurrentEventsPerSecond() const noexcept {
    return m_impl->GetCurrentEventsPerSecond();
}

bool FileWatcher::ExportDiagnostics(const std::wstring& outputPath) const {
    return m_impl->ExportDiagnostics(outputPath);
}

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
