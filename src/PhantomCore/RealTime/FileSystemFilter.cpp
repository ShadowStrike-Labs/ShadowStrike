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
 * ShadowStrike Real-Time - FILE SYSTEM FILTER IMPLEMENTATION
 * ============================================================================
 *
 * @file FileSystemFilter.cpp
 * @brief Enterprise-grade user-mode interface for kernel minifilter driver.
 *
 * Implements the complete communication layer with the ShadowStrike kernel
 * minifilter driver via Windows Filter Manager communication ports.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "FileSystemFilter.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Core/Engine/ScanEngine.hpp"
#include "../Core/FileSystem/FileLockManager.hpp"
#include "../AI/PhantomCortex.hpp"
#include "../HashStore/HashStore.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <deque>
#include <list>
#include <format>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// ANONYMOUS HELPER NAMESPACE
// ============================================================================
namespace {

#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
    constexpr bool kFocusedUserModeBuild = true;
#else
    constexpr bool kFocusedUserModeBuild = false;
#endif

    // Generate unique message ID
    uint64_t GenerateMessageId() {
        static std::atomic<uint64_t> s_counter{ 1000000 };
        return s_counter.fetch_add(1, std::memory_order_relaxed);
    }

    // Generate unique callback ID
    uint64_t GenerateCallbackId() {
        static std::atomic<uint64_t> s_callbackCounter{ 1 };
        return s_callbackCounter.fetch_add(1, std::memory_order_relaxed);
    }

    // Current timestamp
    std::chrono::system_clock::time_point Now() {
        return std::chrono::system_clock::now();
    }

    // Convert wide string to lower case
    std::wstring ToLowerW(std::wstring_view str) {
        std::wstring result(str);
        std::transform(result.begin(), result.end(), result.begin(),
            [](wchar_t c) { return static_cast<wchar_t>(std::tolower(c)); });
        return result;
    }

    // Executable extensions set
    const std::unordered_set<std::wstring> EXECUTABLE_EXTENSIONS = {
        L".exe", L".dll", L".sys", L".drv", L".ocx", L".scr", L".cpl", L".msi"
    };

    // Script extensions set
    const std::unordered_set<std::wstring> SCRIPT_EXTENSIONS = {
        L".ps1", L".vbs", L".js", L".bat", L".cmd", L".wsf", L".hta", L".py"
    };

    [[nodiscard]] bool FitsWidePayload(size_t bodySize,
                                       size_t fixedSize,
                                       uint16_t firstLength,
                                       uint16_t secondLength,
                                       uint16_t thirdLength = 0) noexcept {
        if (bodySize < fixedSize) {
            return false;
        }

        const size_t availableChars = (bodySize - fixedSize) / sizeof(wchar_t);
        const size_t requiredChars =
            static_cast<size_t>(firstLength) +
            static_cast<size_t>(secondLength) +
            static_cast<size_t>(thirdLength);
        return requiredChars <= availableChars;
    }

} // namespace

// ============================================================================
// PIMPL IMPLEMENTATION STRUCT
// ============================================================================
struct FileSystemFilter::Impl {
    // =========================================================================
    // MEMBERS
    // =========================================================================

    // Configuration & State
    FileSystemFilterConfig m_config;
    std::atomic<bool> m_initialized{ false };
    std::atomic<bool> m_running{ false };
    std::atomic<FilterStatus> m_status{ FilterStatus::NotInitialized };

    // Driver Communication
    HANDLE m_hPort{ INVALID_HANDLE_VALUE };
    HANDLE m_hCompletionPort{ nullptr };
    std::wstring m_portName;

    // Threading
    std::shared_ptr<Utils::ThreadPool> m_threadPool;
    std::vector<std::unique_ptr<std::thread>> m_messageThreads;
    std::atomic<bool> m_stopMessageLoop{ false };

    // Synchronization
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_exclusionMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_cacheMutex;
    mutable std::shared_mutex m_pendingMutex;

    // Exclusions
    std::vector<FilterExclusion> m_exclusions;

    // Scan Cache: LRU — list front is most-recently-used
    struct CacheEntry {
        std::wstring path;
        ScanVerdict verdict;
        std::chrono::system_clock::time_point expiry;
    };
    std::list<CacheEntry> m_cacheOrder;
    std::unordered_map<std::wstring, std::list<CacheEntry>::iterator> m_scanCache;

    // Pending Requests: MessageId -> Event
    std::unordered_map<uint64_t, FileAccessEvent> m_pendingRequests;

    // Statistics (internal atomics — snapshotted for public GetStats())
    struct InternalStats {
        std::atomic<uint64_t> totalScanRequests{ 0 };
        std::atomic<uint64_t> scanRequestsCompleted{ 0 };
        std::atomic<uint64_t> filesAllowed{ 0 };
        std::atomic<uint64_t> filesBlocked{ 0 };
        std::atomic<uint64_t> filesQuarantined{ 0 };
        std::atomic<uint64_t> scanTimeouts{ 0 };
        std::atomic<uint64_t> scanErrors{ 0 };
        std::atomic<uint64_t> cacheHits{ 0 };
        std::atomic<uint64_t> cacheMisses{ 0 };
        std::atomic<uint64_t> notificationsReceived{ 0 };
        std::atomic<uint64_t> exclusionsMatched{ 0 };
        std::atomic<uint32_t> pendingRequests{ 0 };
        std::atomic<uint32_t> peakPendingRequests{ 0 };
        std::atomic<uint64_t> avgScanTimeUs{ 0 };
        std::atomic<uint64_t> totalBytesScanned{ 0 };
        std::atomic<uint32_t> driverReconnects{ 0 };

        void Reset() noexcept {
            totalScanRequests.store(0, std::memory_order_relaxed);
            scanRequestsCompleted.store(0, std::memory_order_relaxed);
            filesAllowed.store(0, std::memory_order_relaxed);
            filesBlocked.store(0, std::memory_order_relaxed);
            filesQuarantined.store(0, std::memory_order_relaxed);
            scanTimeouts.store(0, std::memory_order_relaxed);
            scanErrors.store(0, std::memory_order_relaxed);
            cacheHits.store(0, std::memory_order_relaxed);
            cacheMisses.store(0, std::memory_order_relaxed);
            notificationsReceived.store(0, std::memory_order_relaxed);
            exclusionsMatched.store(0, std::memory_order_relaxed);
            pendingRequests.store(0, std::memory_order_relaxed);
            peakPendingRequests.store(0, std::memory_order_relaxed);
            avgScanTimeUs.store(0, std::memory_order_relaxed);
            totalBytesScanned.store(0, std::memory_order_relaxed);
            driverReconnects.store(0, std::memory_order_relaxed);
        }

        [[nodiscard]] FileSystemFilterStats Snapshot() const noexcept {
            FileSystemFilterStats s;
            s.totalScanRequests = totalScanRequests.load(std::memory_order_relaxed);
            s.scanRequestsCompleted = scanRequestsCompleted.load(std::memory_order_relaxed);
            s.filesAllowed = filesAllowed.load(std::memory_order_relaxed);
            s.filesBlocked = filesBlocked.load(std::memory_order_relaxed);
            s.filesQuarantined = filesQuarantined.load(std::memory_order_relaxed);
            s.scanTimeouts = scanTimeouts.load(std::memory_order_relaxed);
            s.scanErrors = scanErrors.load(std::memory_order_relaxed);
            s.cacheHits = cacheHits.load(std::memory_order_relaxed);
            s.cacheMisses = cacheMisses.load(std::memory_order_relaxed);
            s.notificationsReceived = notificationsReceived.load(std::memory_order_relaxed);
            s.exclusionsMatched = exclusionsMatched.load(std::memory_order_relaxed);
            s.pendingRequests = pendingRequests.load(std::memory_order_relaxed);
            s.peakPendingRequests = peakPendingRequests.load(std::memory_order_relaxed);
            s.avgScanTimeUs = avgScanTimeUs.load(std::memory_order_relaxed);
            s.totalBytesScanned = totalBytesScanned.load(std::memory_order_relaxed);
            s.driverReconnects = driverReconnects.load(std::memory_order_relaxed);
            return s;
        }
    } m_stats;

    // Snapshot of config + integration pointers, captured under lock once per
    // scan request so the hot path never races with Set* / UpdatePolicy.
    struct ScanSnapshot {
        Core::Engine::ScanEngine* scanEngine{ nullptr };
        HashStore::HashStore* hashStore{ nullptr };
        Whitelist::WhitelistStore* whitelistStore{ nullptr };
        ScanRequestCallback scanCallback;
        uint32_t scanTimeoutMs{ 0 };
        bool blockOnTimeout{ false };
        bool blockOnError{ false };
        bool enableCache{ true };
        bool cacheNegativeResults{ false };
        uint32_t cacheTTLSeconds{ 300 };
        size_t cacheCapacity{ 10000 };
    };

    // Callbacks
    ScanRequestCallback m_scanCallback;
    std::unordered_map<uint64_t, FileNotificationCallback> m_notificationCallbacks;
    std::unordered_map<uint64_t, FilterStatusCallback> m_statusCallbacks;
    std::unordered_map<uint64_t, ThreatDetectedCallback> m_threatCallbacks;

    // External Integration
    Core::Engine::ScanEngine* m_scanEngine{ nullptr };
    Core::Engine::ThreatDetector* m_threatDetector{ nullptr };
    Whitelist::WhitelistStore* m_whitelistStore{ nullptr };
    HashStore::HashStore* m_hashStore{ nullptr };
    Utils::CacheManager* m_cacheManager{ nullptr };

    // =========================================================================
    // LIFECYCLE METHODS
    // =========================================================================

    bool Initialize(std::shared_ptr<Utils::ThreadPool> threadPool,
                    const FileSystemFilterConfig& config) {
        if (m_initialized.exchange(true)) {
            Utils::Logger::Warn("FileSystemFilter: Already initialized");
            return true;
        }

        Utils::Logger::Info("FileSystemFilter: Initializing...");
        SetStatus(FilterStatus::Initializing);

        m_threadPool = threadPool;
        m_config = config;
        m_portName = config.portName;

        // Reset statistics
        m_stats.Reset();

        // Initialize exclusions from config
        // (Config exclusions would be populated from policy)

        SetStatus(FilterStatus::Stopped);
        Utils::Logger::Info("FileSystemFilter: Initialized successfully");
        return true;
    }

    void Shutdown() {
        if (!m_initialized.exchange(false)) return;

        Utils::Logger::Info("FileSystemFilter: Shutting down...");

        Stop();

        // Clear data structures
        {
            std::unique_lock lock(m_exclusionMutex);
            m_exclusions.clear();
        }

        {
            std::unique_lock lock(m_cacheMutex);
            m_scanCache.clear();
            m_cacheOrder.clear();
        }

        {
            std::unique_lock lock(m_pendingMutex);
            m_pendingRequests.clear();
        }

        {
            std::unique_lock lock(m_callbackMutex);
            m_notificationCallbacks.clear();
            m_statusCallbacks.clear();
            m_threatCallbacks.clear();
            m_scanCallback = nullptr;
        }

        SetStatus(FilterStatus::NotInitialized);
        Utils::Logger::Info("FileSystemFilter: Shutdown complete");
    }

    bool Start() {
        if (m_running.exchange(true)) {
            Utils::Logger::Warn("FileSystemFilter: Already running");
            return true;
        }

        Utils::Logger::Info("FileSystemFilter: Starting...");

        // Attempt to connect to driver
        if (!ConnectToDriver()) {
            Utils::Logger::Warn("FileSystemFilter: Driver not available. Running in user-mode only.");
            // Don't fail - we can still function without the driver for testing
        }

        // Start message threads if connected
        if (m_hPort != INVALID_HANDLE_VALUE) {
            m_stopMessageLoop = false;
            for (size_t i = 0; i < m_config.messageThreadCount; ++i) {
                m_messageThreads.push_back(std::make_unique<std::thread>(
                    &Impl::MessageLoop, this));
            }
        }

        SetStatus(FilterStatus::Running);
        Utils::Logger::Info("FileSystemFilter: Started successfully");
        return true;
    }

    void Stop() {
        if (!m_running.exchange(false)) return;

        Utils::Logger::Info("FileSystemFilter: Stopping...");

        // Stop message threads
        m_stopMessageLoop = true;

        // Close port to wake up waiting threads
        DisconnectFromDriver();

        // Join threads
        for (auto& thread : m_messageThreads) {
            if (thread && thread->joinable()) {
                thread->join();
            }
        }
        m_messageThreads.clear();

        SetStatus(FilterStatus::Stopped);
        Utils::Logger::Info("FileSystemFilter: Stopped");
    }

    void Pause() {
        if (m_status == FilterStatus::Running) {
            SetStatus(FilterStatus::Paused);
            Utils::Logger::Info("FileSystemFilter: Paused");
        }
    }

    void Resume() {
        if (m_status == FilterStatus::Paused) {
            SetStatus(FilterStatus::Running);
            Utils::Logger::Info("FileSystemFilter: Resumed");
        }
    }

    // =========================================================================
    // DRIVER COMMUNICATION
    // =========================================================================

    bool ConnectToDriver() {
#ifdef _WIN32
        Utils::Logger::Info("FileSystemFilter: Connecting to driver port: {}",
            Utils::StringUtils::ToNarrow(m_portName));

        // Connect to the minifilter communication port
        HRESULT hr = FilterConnectCommunicationPort(
            m_portName.c_str(),
            0,                          // Options
            nullptr,                    // Context
            0,                          // Context size
            nullptr,                    // Security attributes
            &m_hPort
        );

        if (FAILED(hr)) {
            DWORD err = HRESULT_CODE(hr);
            if (err == ERROR_FILE_NOT_FOUND) {
                Utils::Logger::Warn("FileSystemFilter: Driver not installed (port not found)");
                SetStatus(FilterStatus::DriverNotInstalled);
            } else if (err == ERROR_ACCESS_DENIED) {
                Utils::Logger::Error("FileSystemFilter: Access denied connecting to driver");
                SetStatus(FilterStatus::AccessDenied);
            } else {
                Utils::Logger::Error("FileSystemFilter: Failed to connect to driver, HRESULT: 0x{:08X}", hr);
                SetStatus(FilterStatus::Error);
            }
            return false;
        }

        // Create I/O completion port for async operations
        m_hCompletionPort = CreateIoCompletionPort(
            m_hPort,
            nullptr,
            0,
            static_cast<DWORD>(m_config.messageThreadCount)
        );

        if (!m_hCompletionPort) {
            Utils::Logger::Error("FileSystemFilter: Failed to create completion port");
            CloseHandle(m_hPort);
            m_hPort = INVALID_HANDLE_VALUE;
            return false;
        }

        Utils::Logger::Info("FileSystemFilter: Connected to driver successfully");
        m_stats.driverReconnects++;
        return true;
#else
        return false;
#endif
    }

    void DisconnectFromDriver() {
        if (m_hCompletionPort) {
            // Post completion to wake up threads
            for (size_t i = 0; i < m_messageThreads.size(); ++i) {
                PostQueuedCompletionStatus(m_hCompletionPort, 0, 0, nullptr);
            }
            CloseHandle(m_hCompletionPort);
            m_hCompletionPort = nullptr;
        }

        if (m_hPort != INVALID_HANDLE_VALUE) {
            CloseHandle(m_hPort);
            m_hPort = INVALID_HANDLE_VALUE;
        }
    }

    bool Reconnect() {
        DisconnectFromDriver();
        return ConnectToDriver();
    }

    // =========================================================================
    // MESSAGE LOOP
    // =========================================================================

    void MessageLoop() {
        Utils::Logger::Info("FileSystemFilter: Message thread started");

        // Snapshot the buffer size once; ignore later UpdateConfig() changes -
        // resizing under FilterGetMessage is unsafe.
        const size_t bufferSize = m_config.messageBufferSize;
        if (bufferSize < sizeof(FILTER_MESSAGE_HEADER) + sizeof(FilterMessageHeader)) {
            Utils::Logger::Error(
                "FileSystemFilter: Message buffer too small ({} bytes) - aborting message thread",
                bufferSize);
            return;
        }

        // Allocate message buffer
        std::vector<uint8_t> buffer(bufferSize);
        PFILTER_MESSAGE_HEADER pMessage = reinterpret_cast<PFILTER_MESSAGE_HEADER>(buffer.data());

        // Maximum bytes the kernel could have written after the FILTER_MESSAGE_HEADER.
        const size_t maxPayloadBytes = bufferSize - sizeof(FILTER_MESSAGE_HEADER);

        while (!m_stopMessageLoop) {
            if (m_hPort == INVALID_HANDLE_VALUE) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }

            // [FSF-A-001] Reset the application-level header before each call so
            // a short kernel write cannot leave stale magic/size from a prior
            // iteration to be re-interpreted as a valid frame.
            std::memset(buffer.data(), 0, sizeof(FILTER_MESSAGE_HEADER) + sizeof(FilterMessageHeader));

            // Get message from driver
            HRESULT hr = FilterGetMessage(
                m_hPort,
                pMessage,
                static_cast<DWORD>(bufferSize),
                nullptr  // Overlapped (NULL = synchronous)
            );

            if (FAILED(hr)) {
                if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) ||
                    hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
                    // Port closed, exit loop
                    break;
                }
                Utils::Logger::Error("FileSystemFilter: FilterGetMessage failed: 0x{:08X}", hr);
                continue;
            }

            // [FSF-A-001] Validate the application-level header lies inside the
            // buffer before reading any of its fields.
            const uint8_t* payload = buffer.data() + sizeof(FILTER_MESSAGE_HEADER);
            const FilterMessageHeader* header =
                reinterpret_cast<const FilterMessageHeader*>(payload);

            if (header->magic != FilterConstants::MESSAGE_MAGIC) {
                Utils::Logger::Warn("FileSystemFilter: Invalid message magic 0x{:08X}",
                    header->magic);
                continue;
            }

            // [FSF-A-002] Refuse unknown protocol versions - never parse layouts we
            // do not control.
            if (header->version != FilterConstants::PROTOCOL_VERSION) {
                Utils::Logger::Warn(
                    "FileSystemFilter: Unsupported protocol version {} (expected {})",
                    header->version, FilterConstants::PROTOCOL_VERSION);
                continue;
            }

            // [FSF-A-001] header->dataSize is the length of the payload that
            // follows the FilterMessageHeader. Validate it fits inside the buffer
            // we actually allocated.
            const uint32_t dataSize = header->dataSize;
            if (dataSize > maxPayloadBytes - sizeof(FilterMessageHeader)) {
                Utils::Logger::Warn(
                    "FileSystemFilter: Declared dataSize {} exceeds buffer ({} bytes available) - dropping",
                    dataSize, maxPayloadBytes - sizeof(FilterMessageHeader));
                continue;
            }

            const void* bodyPtr = payload + sizeof(FilterMessageHeader);
            ProcessMessage(header, bodyPtr, dataSize);
        }

        Utils::Logger::Info("FileSystemFilter: Message thread exiting");
    }

    void ProcessMessage(const FilterMessageHeader* header,
                        const void* data, size_t dataSize) {
        switch (header->messageType) {
            case FilterMessageType::FileScanOnOpen:
            case FilterMessageType::FileScanOnExecute:
            case FilterMessageType::FileScanOnWrite:
            case FilterMessageType::FileScanNetwork:
                if (dataSize < sizeof(FileScanRequest)) {
                    Utils::Logger::Warn(
                        "FileSystemFilter: Scan request body too small ({} < {}) - dropping",
                        dataSize, sizeof(FileScanRequest));
                    return;
                }
                {
                    const auto* request = reinterpret_cast<const FileScanRequest*>(data);
                    if (!FitsWidePayload(dataSize, sizeof(FileScanRequest),
                                         request->pathLength,
                                         request->processNameLength)) {
                        Utils::Logger::Warn(
                            "FileSystemFilter: Scan request string lengths exceed body size - dropping");
                        return;
                    }
                    HandleScanRequest(request, data);
                }
                break;

            case FilterMessageType::NotifyFileCreate:
            case FilterMessageType::NotifyFileWrite:
            case FilterMessageType::NotifyFileRename:
            case FilterMessageType::NotifyFileDelete:
            case FilterMessageType::NotifyFileMap:
                if (dataSize < sizeof(FileNotification)) {
                    Utils::Logger::Warn(
                        "FileSystemFilter: Notification body too small ({} < {}) - dropping",
                        dataSize, sizeof(FileNotification));
                    return;
                }
                {
                    const auto* notification = reinterpret_cast<const FileNotification*>(data);
                    if (!FitsWidePayload(dataSize, sizeof(FileNotification),
                                         notification->pathLength,
                                         notification->newPathLength,
                                         notification->processNameLength)) {
                        Utils::Logger::Warn(
                            "FileSystemFilter: Notification string lengths exceed body size - dropping");
                        return;
                    }
                    HandleNotification(notification, data);
                }
                break;

            default:
                Utils::Logger::Warn("FileSystemFilter: Unknown message type: {}",
                    static_cast<uint16_t>(header->messageType));
                break;
        }
    }

    // =========================================================================
    // SCAN REQUEST HANDLING
    // =========================================================================

    void HandleScanRequest(const FileScanRequest* request, const void* data) {
        auto startTime = std::chrono::high_resolution_clock::now();
        m_stats.totalScanRequests++;
        m_stats.pendingRequests++;

        // Update peak pending
        uint32_t current = m_stats.pendingRequests.load();
        uint32_t peak = m_stats.peakPendingRequests.load();
        while (current > peak &&
               !m_stats.peakPendingRequests.compare_exchange_weak(peak, current));

        // Decode event from raw message
        FileAccessEvent event = DecodeEvent(request, data);
        event.timestamp = Now();

        // Snapshot config + integration pointers under lock — the scan hot path
        // then operates lock-free against Set*/UpdatePolicy races.
        ScanSnapshot snap;
        {
            std::shared_lock configLock(m_configMutex);
            snap.scanEngine = m_scanEngine;
            snap.hashStore = m_hashStore;
            snap.whitelistStore = m_whitelistStore;
            snap.scanTimeoutMs = m_config.scanTimeoutMs;
            snap.blockOnTimeout = m_config.blockOnTimeout;
            snap.blockOnError = m_config.blockOnError;
            snap.enableCache = m_config.enableCache;
            snap.cacheNegativeResults = m_config.cacheNegativeResults;
            snap.cacheTTLSeconds = m_config.cacheTTLSeconds;
            snap.cacheCapacity = m_config.cacheCapacity;
        }
        {
            std::shared_lock cbLock(m_callbackMutex);
            snap.scanCallback = m_scanCallback;
        }

        // Check exclusions first
        if (CheckExclusions(event, snap)) {
            m_stats.exclusionsMatched++;
            SendVerdictReply(event.messageId, ScanVerdict::Allow, L"", true);
            m_stats.pendingRequests--;
            m_stats.filesAllowed++;
            return;
        }

        // Check cache
        auto cachedVerdict = CheckCache(event.filePath, snap);
        if (cachedVerdict.has_value()) {
            m_stats.cacheHits++;
            ScanVerdict verdict = cachedVerdict.value();
            SendVerdictReply(event.messageId, verdict, L"", false);
            m_stats.pendingRequests--;
            if (verdict == ScanVerdict::Allow || verdict == ScanVerdict::CacheHitAllow) {
                m_stats.filesAllowed++;
            } else {
                m_stats.filesBlocked++;
            }
            return;
        }
        m_stats.cacheMisses++;

        // Perform scan
        ScanVerdict verdict = PerformScan(event, snap);

        // Update cache
        UpdateCache(event.filePath, verdict, snap);

        // Send verdict reply
        std::wstring threatName = event.handled ? L"" : L"";  // Would come from scan result
        SendVerdictReply(event.messageId, verdict, threatName, true);

        // Update statistics
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

        m_stats.scanRequestsCompleted++;
        m_stats.pendingRequests--;
        m_stats.totalBytesScanned += event.fileSize;

        // Update average scan time (simple moving average)
        uint64_t currentAvg = m_stats.avgScanTimeUs.load();
        uint64_t newAvg = (currentAvg * 9 + duration.count()) / 10;
        m_stats.avgScanTimeUs.store(newAvg);

        if (verdict == ScanVerdict::Allow) {
            m_stats.filesAllowed++;
        } else if (verdict == ScanVerdict::Block || verdict == ScanVerdict::BlockAndQuarantine) {
            m_stats.filesBlocked++;
            if (verdict == ScanVerdict::BlockAndQuarantine) {
                m_stats.filesQuarantined++;
            }
        }

        // Invoke notification callbacks
        InvokeNotificationCallbacks(event);
    }

    FileAccessEvent DecodeEvent(const FileScanRequest* request, const void* data) {
        FileAccessEvent event;
        event.messageId = request->messageId;
        event.accessType = request->accessType;
        event.processId = request->processId;
        event.threadId = request->threadId;
        event.parentProcessId = request->parentProcessId;
        event.fileSize = request->fileSize;
        event.fileAttributes = request->fileAttributes;
        event.desiredAccess = request->desiredAccess;
        event.isDirectory = request->isDirectory;
        event.isNetworkFile = request->isNetworkFile;
        event.isRemovableMedia = request->isRemovableMedia;
        event.requiresReply = request->requiresReply;
        event.priority = request->priority;

        // Extract variable-length strings
        const wchar_t* strings = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const uint8_t*>(request) + sizeof(FileScanRequest));

        if (request->pathLength > 0) {
            event.filePath = std::wstring(strings, request->pathLength);
            // The kernel delivers NT device paths (\Device\HarddiskVolumeN\...).
            // This filesystem-filter route feeds event.filePath straight to
            // ScanEngine / DigitalSignatureValidator / hashing, all of which open
            // the file with Win32 APIs — which cannot open the NT form, so every
            // scan on this (dominant) route failed "file not found". Resolve to a
            // DOS path once, here at the boundary, matching RealTimeProtection's
            // OnKernelFileScan.
            event.filePath = Utils::FileUtils::DevicePathToDosPath(event.filePath);
        }

        if (request->processNameLength > 0) {
            const wchar_t* procName = strings + request->pathLength;
            event.processName = std::wstring(procName, request->processNameLength);
        }

        return event;
    }

    ScanVerdict PerformScan(const FileAccessEvent& event, const ScanSnapshot& snap) {
        // 1. Check custom scan callback first (snapshot — no callback lock needed)
        if (snap.scanCallback) {
            try {
                return snap.scanCallback(event);
            } catch (const std::exception& e) {
                Utils::Logger::Error("FileSystemFilter: Scan callback exception: {}",
                    e.what());
            }
        }

        // 2. Use integrated scan engine if available (snapshot pointer)
#if !defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        if (snap.scanEngine) {
            try {
                Core::Engine::ScanContext context;
                context.type = Core::Engine::ScanType::RealTime;

                // Map priority
                switch (event.priority) {
                    case RequestPriority::Critical:
                        context.priority = Core::Engine::ScanPriority::Critical;
                        break;
                    case RequestPriority::High:
                        context.priority = Core::Engine::ScanPriority::High;
                        break;
                    case RequestPriority::Background:
                        context.priority = Core::Engine::ScanPriority::Low;
                        break;
                    default:
                        context.priority = Core::Engine::ScanPriority::Normal;
                        break;
                }

                context.processId = event.processId;
                context.filePath = event.filePath;
                context.isNetworkPath = event.isNetworkFile;
                context.isRemovableMedia = event.isRemovableMedia;
                context.timeout = std::chrono::milliseconds(snap.scanTimeoutMs);

                // Perform lock-aware threat detection before scan
                auto& fileLockMgr = Core::FileSystem::FileLockManager::Instance();
                auto lockInfo = fileLockMgr.GetLockInfo(event.filePath);
                if (lockInfo.threatAssessment.requiresImmediateAction) {
                    SS_LOG_WARN(L"FileSystemFilter", L"Pre-scan lock threat: %s (score=%.1f, pattern=%u)",
                        event.filePath.c_str(), lockInfo.threatAssessment.overallThreatScore,
                        static_cast<unsigned>(lockInfo.threatAssessment.dominantPattern));
                    InvokeThreatCallbacks(event, L"SuspiciousLockPattern",
                        lockInfo.threatAssessment.overallThreatScore);
                }

                // Perform the scan
                auto result = snap.scanEngine->ScanFile(event.filePath, context);

                // Handle results
                switch (result.verdict) {
                    case Core::Engine::ScanVerdict::Clean:
                    case Core::Engine::ScanVerdict::Whitelisted:
                        return ScanVerdict::Allow;

                    case Core::Engine::ScanVerdict::Infected:
                        InvokeThreatCallbacks(event,
                            Utils::StringUtils::ToWide(result.threatName),
                            result.threatScore);
                        return ScanVerdict::BlockAndQuarantine;

                    case Core::Engine::ScanVerdict::Suspicious:
                    case Core::Engine::ScanVerdict::PUA:
                    case Core::Engine::ScanVerdict::Adware:
                    case Core::Engine::ScanVerdict::Riskware:
                        InvokeThreatCallbacks(event,
                            Utils::StringUtils::ToWide(result.threatName),
                            result.threatScore);
                        return ScanVerdict::Block;

                    case Core::Engine::ScanVerdict::Timeout:
                        return snap.blockOnTimeout ? ScanVerdict::Block : ScanVerdict::Timeout;

                    case Core::Engine::ScanVerdict::Error:
                        return snap.blockOnError ? ScanVerdict::Block : ScanVerdict::Error;

                    case Core::Engine::ScanVerdict::Cancelled:
                        return ScanVerdict::Error;

                    default:
                        return ScanVerdict::Allow;
                }

            } catch (const std::exception& e) {
                Utils::Logger::Error("FileSystemFilter: ScanEngine exception: {}",
                    e.what());

                if (snap.blockOnError) return ScanVerdict::Block;
            }
        }
#endif

        // 3. Check hash store if available (snapshot pointer)
#if !defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        if (snap.hashStore) {
            try {
                std::vector<uint8_t> hashBytes;
                Utils::HashUtils::Error hashErr;
                if (Utils::HashUtils::ComputeFile(
                        Utils::HashUtils::Algorithm::SHA256,
                        event.filePath, hashBytes, &hashErr)) {
                    // Convert raw hash to hex string for lookup
                    std::string hexHash;
                    hexHash.reserve(hashBytes.size() * 2);
                    for (uint8_t b : hashBytes) {
                        char buf[3];
                        std::snprintf(buf, sizeof(buf), "%02x", b);
                        hexHash.append(buf, 2);
                    }

                    auto detection = m_hashStore->LookupHashString(
                        hexHash, HashStore::HashType::SHA256);
                    if (detection.has_value()) {
                        Utils::Logger::Warn(
                            "FileSystemFilter: Hash match — {} flagged as {}",
                            Utils::StringUtils::ToNarrow(event.filePath),
                            detection->signatureName);
                        return ScanVerdict::Block;
                    }
                }
            } catch (const std::exception& e) {
                Utils::Logger::Error("FileSystemFilter: Hash store check failed: {}",
                    e.what());
            }
        }
#endif

        // 4. PhantomCortex AI/ML pre-screening for high-risk file types
#if !defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        if (ShadowStrike::AI::PhantomCortex::Instance().IsOperational()) {
            try {
                const std::wstring ext = GetFileExtension(event.filePath);
                if (IsExecutableExtension(ext) || IsScriptExtension(ext)) {
                    std::ifstream ifs(event.filePath, std::ios::binary | std::ios::ate);
                    if (ifs.is_open()) {
                        const auto fileSize = ifs.tellg();
                        if (fileSize > 0 &&
                            static_cast<size_t>(fileSize) <= ShadowStrike::AI::CortexConstants::MAX_PE_FILE_SIZE) {
                            ifs.seekg(0, std::ios::beg);
                            std::vector<uint8_t> fileBytes(static_cast<size_t>(fileSize));
                            if (ifs.read(reinterpret_cast<char*>(fileBytes.data()),
                                         static_cast<std::streamsize>(fileSize))) {
                                auto mlVerdict = ShadowStrike::AI::PhantomCortex::Instance().AnalyzeFile(
                                    std::span<const uint8_t>(fileBytes));

                                if (mlVerdict.verdict == ShadowStrike::AI::ThreatVerdict::Malicious) {
                                    SS_LOG_WARN(L"FileSystemFilter",
                                        L"PhantomCortex ML blocked high-risk file: %s (confidence: %.2f)",
                                        event.filePath.c_str(), mlVerdict.confidence);
                                    InvokeThreatCallbacks(event,
                                        L"ML/PhantomCortex." + mlVerdict.details,
                                        mlVerdict.confidence);
                                    return ScanVerdict::BlockAndQuarantine;
                                }

                                if (mlVerdict.verdict == ShadowStrike::AI::ThreatVerdict::Suspicious) {
                                    SS_LOG_INFO(L"FileSystemFilter",
                                        L"PhantomCortex ML flagged suspicious file: %s (confidence: %.2f)",
                                        event.filePath.c_str(), mlVerdict.confidence);
                                    InvokeThreatCallbacks(event,
                                        L"ML/PhantomCortex.Suspicious",
                                        mlVerdict.confidence);
                                    return ScanVerdict::Block;
                                }
                            }
                        }
                    }
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("FileSystemFilter: PhantomCortex ML analysis failed: {}",
                    ex.what());
            } catch (...) {
                Utils::Logger::Error("FileSystemFilter: PhantomCortex ML unknown exception");
            }
        }
#endif

        // 5. Default: Allow (fail-open by default)
        return ScanVerdict::Allow;
    }

    void SendVerdictReply(uint64_t messageId, ScanVerdict verdict,
                          const std::wstring& threatName, bool cacheResult) {
        if (m_hPort == INVALID_HANDLE_VALUE) return;

        // Prepare reply structure
        struct ReplyBuffer {
            FILTER_REPLY_HEADER header;
            ScanVerdictReply verdict;
        };

        ReplyBuffer reply{};
        reply.header.MessageId = messageId;
        reply.header.Status = 0;
        reply.verdict.messageId = messageId;
        reply.verdict.verdict = verdict;
        reply.verdict.threatDetected = (verdict == ScanVerdict::Block ||
                                        verdict == ScanVerdict::BlockAndQuarantine);
        reply.verdict.cacheResult = cacheResult;
        reply.verdict.cacheTTL = m_config.cacheTTLSeconds;

        HRESULT hr = FilterReplyMessage(
            m_hPort,
            &reply.header,
            sizeof(reply)
        );

        if (FAILED(hr)) {
            Utils::Logger::Error("FileSystemFilter: FilterReplyMessage failed: 0x{:08X}", hr);
        }
    }

    // =========================================================================
    // NOTIFICATION HANDLING
    // =========================================================================

    void HandleNotification(const FileNotification* notification, const void* data) {
        m_stats.notificationsReceived++;

        FileAccessEvent event;
        event.messageId = GenerateMessageId();
        event.messageType = notification->notificationType;
        event.processId = notification->processId;
        event.threadId = notification->threadId;
        event.fileSize = notification->fileSize;
        event.bytesTransferred = notification->bytesWritten;
        event.fileAttributes = notification->fileAttributes;
        event.isDirectory = notification->isDirectory;
        event.requiresReply = false;
        event.timestamp = Now();

        // Extract paths
        const wchar_t* strings = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const uint8_t*>(notification) + sizeof(FileNotification));

        if (notification->pathLength > 0) {
            event.filePath = std::wstring(strings, notification->pathLength);
        }

        if (notification->newPathLength > 0) {
            const wchar_t* newPath = strings + notification->pathLength;
            event.newPath = std::wstring(newPath, notification->newPathLength);
        }

        // Invoke callbacks
        InvokeNotificationCallbacks(event);
    }

    // =========================================================================
    // EXCLUSION MANAGEMENT
    // =========================================================================

    bool CheckExclusions(const FileAccessEvent& event, const ScanSnapshot& snap) {
        std::shared_lock lock(m_exclusionMutex);

        std::wstring lowerPath = ToLowerW(event.filePath);
        std::wstring lowerProcess = ToLowerW(event.processName);

        for (const auto& exclusion : m_exclusions) {
            // Check expiration
            if (exclusion.expiration.has_value() && Now() > exclusion.expiration.value()) {
                continue;
            }

            bool matched = false;

            switch (exclusion.type) {
                case FilterExclusion::Type::Path: {
                    std::wstring pattern = exclusion.caseInsensitive ?
                        ToLowerW(exclusion.pattern) : exclusion.pattern;
                    const std::wstring& path = exclusion.caseInsensitive ? lowerPath : event.filePath;

                    if (exclusion.isWildcard) {
                        matched = PathMatchesPattern(path, pattern, exclusion.caseInsensitive);
                    } else {
                        matched = (path.find(pattern) == 0); // Prefix match
                    }
                    break;
                }

                case FilterExclusion::Type::Extension: {
                    std::wstring ext = GetFileExtension(event.filePath);
                    std::wstring pattern = exclusion.caseInsensitive ?
                        ToLowerW(exclusion.pattern) : exclusion.pattern;
                    if (exclusion.caseInsensitive) {
                        ext = ToLowerW(ext);
                    }
                    matched = (ext == pattern);
                    break;
                }

                case FilterExclusion::Type::Process: {
                    std::wstring pattern = exclusion.caseInsensitive ?
                        ToLowerW(exclusion.pattern) : exclusion.pattern;
                    const std::wstring& proc = exclusion.caseInsensitive ?
                        lowerProcess : event.processName;
                    matched = (proc == pattern);
                    break;
                }

                case FilterExclusion::Type::ProcessPath: {
                    std::wstring pattern = exclusion.caseInsensitive ?
                        ToLowerW(exclusion.pattern) : exclusion.pattern;
                    std::wstring procPath = exclusion.caseInsensitive ?
                        ToLowerW(event.processPath) : event.processPath;
                    matched = (procPath.find(pattern) == 0);
                    break;
                }

                default:
                    break;
            }

            if (matched) {
                return true;
            }
        }

        // Also check whitelist store (snapshot pointer — no config lock needed)
        if (snap.whitelistStore) {
#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
            (void)snap;
#else
            auto result = snap.whitelistStore->IsPathWhitelisted(event.filePath);
            if (result.found) return true;
#endif
        }

        return false;
    }

    bool AddExclusion(const FilterExclusion& exclusion) {
        std::unique_lock lock(m_exclusionMutex);

        if (m_exclusions.size() >= FilterConstants::MAX_EXCLUSION_PATHS) {
            Utils::Logger::Error("FileSystemFilter: Maximum exclusions reached");
            return false;
        }

        m_exclusions.push_back(exclusion);
        Utils::Logger::Info("FileSystemFilter: Added exclusion: {}",
            Utils::StringUtils::ToNarrow(exclusion.pattern));
        return true;
    }

    bool RemoveExclusion(const std::wstring& pattern) {
        std::unique_lock lock(m_exclusionMutex);

        auto it = std::remove_if(m_exclusions.begin(), m_exclusions.end(),
            [&pattern](const FilterExclusion& e) { return e.pattern == pattern; });

        if (it != m_exclusions.end()) {
            m_exclusions.erase(it, m_exclusions.end());
            Utils::Logger::Info("FileSystemFilter: Removed exclusion: {}",
                Utils::StringUtils::ToNarrow(pattern));
            return true;
        }
        return false;
    }

    void ClearExclusions() {
        std::unique_lock lock(m_exclusionMutex);
        m_exclusions.clear();
        Utils::Logger::Info("FileSystemFilter: Cleared all exclusions");
    }

    std::vector<FilterExclusion> GetExclusions() const {
        std::shared_lock lock(m_exclusionMutex);
        return m_exclusions;
    }

    bool IsPathExcluded(const std::wstring& path) const {
        FileAccessEvent event;
        event.filePath = path;
        ScanSnapshot snap{};
        {
            std::shared_lock configLock(m_configMutex);
            snap.whitelistStore = m_whitelistStore;
        }
        return const_cast<Impl*>(this)->CheckExclusions(event, snap);
    }

    // =========================================================================
    // CACHE MANAGEMENT
    // =========================================================================

    std::optional<ScanVerdict> CheckCache(const std::wstring& path, const ScanSnapshot& snap) {
        if (!snap.enableCache) return std::nullopt;

        std::unique_lock lock(m_cacheMutex);

        auto it = m_scanCache.find(path);
        if (it == m_scanCache.end()) return std::nullopt;

        auto listIt = it->second;

        // Check expiry
        if (Now() > listIt->expiry) {
            m_cacheOrder.erase(listIt);
            m_scanCache.erase(it);
            return std::nullopt;
        }

        // Move to front (most-recently-used)
        if (listIt != m_cacheOrder.begin()) {
            m_cacheOrder.splice(m_cacheOrder.begin(), m_cacheOrder, listIt);
        }

        return listIt->verdict;
    }

    void UpdateCache(const std::wstring& path, ScanVerdict verdict, const ScanSnapshot& snap) {
        if (!snap.enableCache) return;

        // Don't cache errors
        if (verdict == ScanVerdict::Error || verdict == ScanVerdict::Timeout) return;

        // Maybe don't cache blocks if configured
        if (!snap.cacheNegativeResults &&
            (verdict == ScanVerdict::Block || verdict == ScanVerdict::BlockAndQuarantine)) {
            return;
        }

        std::unique_lock lock(m_cacheMutex);

        auto existing = m_scanCache.find(path);
        if (existing != m_scanCache.end()) {
            // Update existing: move to front
            existing->second->verdict = verdict;
            existing->second->expiry = Now() + std::chrono::seconds(snap.cacheTTLSeconds);
            m_cacheOrder.splice(m_cacheOrder.begin(), m_cacheOrder, existing->second);
            return;
        }

        // Evict LRU entry if at capacity
        while (m_scanCache.size() >= snap.cacheCapacity && !m_cacheOrder.empty()) {
            auto& lru = m_cacheOrder.back();
            m_scanCache.erase(lru.path);
            m_cacheOrder.pop_back();
        }

        CacheEntry entry;
        entry.path = path;
        entry.verdict = verdict;
        entry.expiry = Now() + std::chrono::seconds(snap.cacheTTLSeconds);

        m_cacheOrder.push_front(std::move(entry));
        m_scanCache[path] = m_cacheOrder.begin();
    }

    void FlushCache() {
        std::unique_lock lock(m_cacheMutex);
        m_scanCache.clear();
        m_cacheOrder.clear();
        Utils::Logger::Info("FileSystemFilter: Cache flushed");
    }

    void InvalidateCacheEntry(const std::wstring& path) {
        std::unique_lock lock(m_cacheMutex);
        auto it = m_scanCache.find(path);
        if (it != m_scanCache.end()) {
            m_cacheOrder.erase(it->second);
            m_scanCache.erase(it);
        }
    }

    double GetCacheHitRate() const noexcept {
        uint64_t hits = m_stats.cacheHits.load(std::memory_order_relaxed);
        uint64_t misses = m_stats.cacheMisses.load(std::memory_order_relaxed);
        uint64_t total = hits + misses;
        return total > 0 ? (static_cast<double>(hits) / total) * 100.0 : 0.0;
    }

    // =========================================================================
    // POLICY MANAGEMENT
    // =========================================================================

    bool UpdatePolicy(const PolicyUpdate& policy) {
        std::unique_lock lock(m_configMutex);

        m_config.scanOnOpen = policy.scanOnOpen;
        m_config.scanOnExecute = policy.scanOnExecute;
        m_config.scanOnWrite = policy.scanOnWrite;
        m_config.enableNotifications = policy.enableNotifications;
        m_config.blockOnTimeout = policy.blockOnTimeout;
        m_config.blockOnError = policy.blockOnError;
        m_config.scanNetworkFiles = policy.scanNetworkFiles;
        m_config.scanRemovableMedia = policy.scanRemovableMedia;

        if (policy.maxScanFileSize > 0) {
            m_config.maxScanFileSize = policy.maxScanFileSize;
        }
        if (policy.scanTimeoutMs > 0) {
            m_config.scanTimeoutMs = policy.scanTimeoutMs;
        }
        if (policy.cacheTTLSeconds > 0) {
            m_config.cacheTTLSeconds = policy.cacheTTLSeconds;
        }

        // Forward policy to kernel driver if connected
        if (m_hPort != INVALID_HANDLE_VALUE) {
            struct PolicyMsg {
                FilterMessageHeader fsfHeader;
                PolicyUpdate payload;
            };
            PolicyMsg msg{};
            msg.fsfHeader.magic = FilterConstants::MESSAGE_MAGIC;
            msg.fsfHeader.version = FilterConstants::PROTOCOL_VERSION;
            msg.fsfHeader.messageType = FilterMessageType::UpdatePolicy;
            msg.fsfHeader.messageId = GenerateMessageId();
            msg.fsfHeader.dataSize = static_cast<uint32_t>(sizeof(PolicyUpdate));
            msg.payload = policy;

            DWORD bytesReturned = 0;
            HRESULT hr = FilterSendMessage(
                m_hPort, &msg, sizeof(msg),
                nullptr, 0, &bytesReturned);
            if (FAILED(hr)) {
                Utils::Logger::Warn(
                    "FileSystemFilter: Failed to forward policy to driver: 0x{:08X}",
                    static_cast<uint32_t>(hr));
            }
        }

        Utils::Logger::Info("FileSystemFilter: Policy updated");
        return true;
    }

    // =========================================================================
    // DRIVER STATUS
    // =========================================================================

    DriverStatus GetDriverStatus() const {
        DriverStatus status;

        if (m_hPort == INVALID_HANDLE_VALUE) {
            return status;
        }

        // Populate from actual internal state
        status.filteringActive = m_running.load();
        {
            std::shared_lock lock(m_configMutex);
            status.scanOnOpenEnabled = m_config.scanOnOpen;
            status.scanOnExecuteEnabled = m_config.scanOnExecute;
            status.scanOnWriteEnabled = m_config.scanOnWrite;
            status.notificationsEnabled = m_config.enableNotifications;
        }
        status.totalFilesScanned = m_stats.totalScanRequests.load(std::memory_order_relaxed);
        status.filesBlocked = m_stats.filesBlocked.load(std::memory_order_relaxed);
        status.pendingRequests = m_stats.pendingRequests.load(std::memory_order_relaxed);
        status.peakPendingRequests = m_stats.peakPendingRequests.load(std::memory_order_relaxed);
        status.cacheHits = m_stats.cacheHits.load(std::memory_order_relaxed);
        status.cacheMisses = m_stats.cacheMisses.load(std::memory_order_relaxed);

        return status;
    }

    bool IsDriverInstalled() const {
        // Check if driver service exists
        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCM) return false;

        SC_HANDLE hService = OpenServiceW(hSCM, L"PhantomSensor", SERVICE_QUERY_STATUS);
        bool installed = (hService != nullptr);

        if (hService) CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);

        return installed;
    }

    std::string GetDriverVersion() const {
        auto status = GetDriverStatus();
        return std::format("{}.{}.{}", status.versionMajor, status.versionMinor, status.versionBuild);
    }

    // =========================================================================
    // CALLBACK MANAGEMENT
    // =========================================================================

    uint64_t RegisterNotificationCallback(FileNotificationCallback callback) {
        std::unique_lock lock(m_callbackMutex);
        uint64_t id = GenerateCallbackId();
        m_notificationCallbacks[id] = std::move(callback);
        return id;
    }

    bool UnregisterNotificationCallback(uint64_t callbackId) {
        std::unique_lock lock(m_callbackMutex);
        return m_notificationCallbacks.erase(callbackId) > 0;
    }

    uint64_t RegisterStatusCallback(FilterStatusCallback callback) {
        std::unique_lock lock(m_callbackMutex);
        uint64_t id = GenerateCallbackId();
        m_statusCallbacks[id] = std::move(callback);
        return id;
    }

    bool UnregisterStatusCallback(uint64_t callbackId) {
        std::unique_lock lock(m_callbackMutex);
        return m_statusCallbacks.erase(callbackId) > 0;
    }

    uint64_t RegisterThreatCallback(ThreatDetectedCallback callback) {
        std::unique_lock lock(m_callbackMutex);
        uint64_t id = GenerateCallbackId();
        m_threatCallbacks[id] = std::move(callback);
        return id;
    }

    bool UnregisterThreatCallback(uint64_t callbackId) {
        std::unique_lock lock(m_callbackMutex);
        return m_threatCallbacks.erase(callbackId) > 0;
    }

    void InvokeNotificationCallbacks(const FileAccessEvent& event) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& [id, callback] : m_notificationCallbacks) {
            try {
                callback(event);
            } catch (const std::exception& e) {
                Utils::Logger::Error("FileSystemFilter: Notification callback exception: {}",
                    e.what());
            }
        }
    }

    void InvokeStatusCallbacks(FilterStatus status, const std::wstring& message) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& [id, callback] : m_statusCallbacks) {
            try {
                callback(status, message);
            } catch (const std::exception& e) {
                Utils::Logger::Error("FileSystemFilter: Status callback exception: {}",
                    e.what());
            }
        }
    }

    void InvokeThreatCallbacks(const FileAccessEvent& event,
                               const std::wstring& threatName, double score) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& [id, callback] : m_threatCallbacks) {
            try {
                callback(event, threatName, score);
            } catch (const std::exception& e) {
                Utils::Logger::Error("FileSystemFilter: Threat callback exception: {}",
                    e.what());
            }
        }
    }

    // =========================================================================
    // STATUS MANAGEMENT
    // =========================================================================

    void SetStatus(FilterStatus status) {
        FilterStatus oldStatus = m_status.exchange(status);
        if (oldStatus != status) {
            InvokeStatusCallbacks(status, L"");
        }
    }
};

// ============================================================================
// SINGLETON ACCESS
// ============================================================================

FileSystemFilter& FileSystemFilter::Instance() {
    static FileSystemFilter instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

FileSystemFilter::FileSystemFilter() : m_impl(std::make_unique<Impl>()) {
}

FileSystemFilter::~FileSystemFilter() {
    Shutdown();
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool FileSystemFilter::Initialize() {
    return Initialize(nullptr, FileSystemFilterConfig::CreateDefault());
}

bool FileSystemFilter::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool) {
    return Initialize(threadPool, FileSystemFilterConfig::CreateDefault());
}

bool FileSystemFilter::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool,
                                   const FileSystemFilterConfig& config) {
    return m_impl->Initialize(threadPool, config);
}

void FileSystemFilter::Shutdown() {
    m_impl->Shutdown();
}

bool FileSystemFilter::Start() {
    return m_impl->Start();
}

void FileSystemFilter::Stop() {
    m_impl->Stop();
}

void FileSystemFilter::Pause() {
    m_impl->Pause();
}

void FileSystemFilter::Resume() {
    m_impl->Resume();
}

bool FileSystemFilter::IsRunning() const noexcept {
    return m_impl->m_running.load();
}

bool FileSystemFilter::IsInitialized() const noexcept {
    return m_impl->m_initialized.load();
}

FilterStatus FileSystemFilter::GetStatus() const noexcept {
    return m_impl->m_status.load();
}

void FileSystemFilter::UpdateConfig(const FileSystemFilterConfig& config) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = config;
    Utils::Logger::Info("FileSystemFilter: Configuration updated");
}

FileSystemFilterConfig FileSystemFilter::GetConfig() const {
    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}

// ============================================================================
// POLICY MANAGEMENT
// ============================================================================

bool FileSystemFilter::UpdatePolicy(const PolicyUpdate& policy) {
    return m_impl->UpdatePolicy(policy);
}

void FileSystemFilter::SetScanOnOpen(bool enable) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config.scanOnOpen = enable;
}

void FileSystemFilter::SetScanOnExecute(bool enable) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config.scanOnExecute = enable;
}

void FileSystemFilter::SetScanOnWrite(bool enable) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config.scanOnWrite = enable;
}

void FileSystemFilter::SetNotificationsEnabled(bool enable) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config.enableNotifications = enable;
}

void FileSystemFilter::SetScanTimeout(uint32_t timeoutMs) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config.scanTimeoutMs = timeoutMs;
}

void FileSystemFilter::SetMaxScanFileSize(uint64_t maxSize) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config.maxScanFileSize = maxSize;
}

// ============================================================================
// EXCLUSION MANAGEMENT
// ============================================================================

bool FileSystemFilter::AddExclusion(const FilterExclusion& exclusion) {
    return m_impl->AddExclusion(exclusion);
}

bool FileSystemFilter::RemoveExclusion(const std::wstring& pattern) {
    return m_impl->RemoveExclusion(pattern);
}

void FileSystemFilter::ClearExclusions() {
    m_impl->ClearExclusions();
}

std::vector<FilterExclusion> FileSystemFilter::GetExclusions() const {
    return m_impl->GetExclusions();
}

bool FileSystemFilter::IsPathExcluded(const std::wstring& path) const {
    return m_impl->IsPathExcluded(path);
}

bool FileSystemFilter::IsProcessExcluded(const std::wstring& processName,
                                          const std::wstring& processPath) const {
    std::shared_lock lock(m_impl->m_exclusionMutex);

    std::wstring lowerName = ToLowerW(processName);
    std::wstring lowerPath = ToLowerW(processPath);

    for (const auto& excl : m_impl->m_exclusions) {
        if (excl.type == FilterExclusion::Type::Process) {
            std::wstring pattern = excl.caseInsensitive ? ToLowerW(excl.pattern) : excl.pattern;
            const std::wstring& candidateName = excl.caseInsensitive ? lowerName : processName;
            if (candidateName == pattern) return true;
        } else if (excl.type == FilterExclusion::Type::ProcessPath && !processPath.empty()) {
            std::wstring pattern = excl.caseInsensitive ? ToLowerW(excl.pattern) : excl.pattern;
            const std::wstring& candidatePath = excl.caseInsensitive ? lowerPath : processPath;
            if (candidatePath.find(pattern) == 0) return true;
        }
    }
    return false;
}

bool FileSystemFilter::SyncExclusionsToDriver() {
    if (m_impl->m_hPort == INVALID_HANDLE_VALUE) {
        Utils::Logger::Warn("FileSystemFilter: Cannot sync exclusions — driver not connected");
        return false;
    }

    std::shared_lock lock(m_impl->m_exclusionMutex);

    // Serialize each exclusion and send to driver via FilterSendMessage
    for (const auto& excl : m_impl->m_exclusions) {
        if (excl.expiration.has_value() && Now() > excl.expiration.value()) continue;

        struct ExclMsg {
            FilterMessageHeader header;
            uint32_t exclusionType;
            uint16_t patternLength;
            wchar_t pattern[260];
        };
        ExclMsg msg{};

        msg.header.magic = FilterConstants::MESSAGE_MAGIC;
        msg.header.version = FilterConstants::PROTOCOL_VERSION;
        msg.header.messageType = FilterMessageType::UpdateExclusions;
        msg.header.messageId = GenerateMessageId();
        msg.exclusionType = static_cast<uint32_t>(excl.type);
        size_t copyLen = (std::min)(excl.pattern.size(), static_cast<size_t>(259));
        wcsncpy_s(msg.pattern, excl.pattern.c_str(), copyLen);
        msg.patternLength = static_cast<uint16_t>(copyLen);
        msg.header.dataSize = static_cast<uint32_t>(
            sizeof(msg.exclusionType) + sizeof(msg.patternLength) +
            (copyLen + 1) * sizeof(wchar_t));

        DWORD bytesReturned = 0;
        HRESULT hr = FilterSendMessage(
            m_impl->m_hPort, &msg,
            sizeof(msg.header) + msg.header.dataSize,
            nullptr, 0, &bytesReturned);
        if (FAILED(hr)) {
            Utils::Logger::Error(
                "FileSystemFilter: Failed to sync exclusion '{}' to driver: 0x{:08X}",
                Utils::StringUtils::ToNarrow(excl.pattern), static_cast<uint32_t>(hr));
            return false;
        }
    }

    Utils::Logger::Info("FileSystemFilter: {} exclusions synced to driver",
        m_impl->m_exclusions.size());
    return true;
}

// ============================================================================
// VERDICT OPERATIONS
// ============================================================================

bool FileSystemFilter::SendVerdict(uint64_t messageId, ScanVerdict verdict,
                                    const std::wstring& threatName, bool cacheResult) {
    m_impl->SendVerdictReply(messageId, verdict, threatName, cacheResult);
    return true;
}

void FileSystemFilter::CancelRequest(uint64_t messageId) {
    std::unique_lock lock(m_impl->m_pendingMutex);
    m_impl->m_pendingRequests.erase(messageId);
}

// ============================================================================
// CACHE MANAGEMENT
// ============================================================================

void FileSystemFilter::FlushCache() {
    m_impl->FlushCache();
}

void FileSystemFilter::InvalidateCacheEntry(const std::wstring& path) {
    m_impl->InvalidateCacheEntry(path);
}

void FileSystemFilter::InvalidateCacheEntryByHash(const std::string& hash) {
    if (hash.empty()) return;

    // Phase 1: Copy cache keys under shared lock (no file I/O under lock)
    std::vector<std::wstring> cachedPaths;
    {
        std::shared_lock lock(m_impl->m_cacheMutex);
        cachedPaths.reserve(m_impl->m_scanCache.size());
        for (const auto& [path, _] : m_impl->m_scanCache) {
            cachedPaths.push_back(path);
        }
    }

    // Phase 2: Compute hashes lock-free (file I/O happens here)
    std::vector<std::wstring> keysToRemove;
    for (const auto& path : cachedPaths) {
        std::vector<uint8_t> hashBytes;
        if (Utils::HashUtils::ComputeFile(
                Utils::HashUtils::Algorithm::SHA256, path, hashBytes)) {
            std::string hexHash;
            hexHash.reserve(hashBytes.size() * 2);
            for (uint8_t b : hashBytes) {
                char buf[3];
                std::snprintf(buf, sizeof(buf), "%02x", b);
                hexHash.append(buf, 2);
            }
            if (hexHash == hash) {
                keysToRemove.push_back(path);
            }
        }
    }

    // Phase 3: Re-acquire exclusive lock, erase from BOTH cache structures
    if (!keysToRemove.empty()) {
        std::unique_lock lock(m_impl->m_cacheMutex);
        for (const auto& key : keysToRemove) {
            auto it = m_impl->m_scanCache.find(key);
            if (it != m_impl->m_scanCache.end()) {
                m_impl->m_cacheOrder.erase(it->second);
                m_impl->m_scanCache.erase(it);
            }
        }

        Utils::Logger::Info("FileSystemFilter: Invalidated {} cache entries by hash",
            keysToRemove.size());
    }
}

double FileSystemFilter::GetCacheHitRate() const noexcept {
    return m_impl->GetCacheHitRate();
}

// ============================================================================
// DRIVER COMMUNICATION
// ============================================================================

DriverStatus FileSystemFilter::GetDriverStatus() const {
    return m_impl->GetDriverStatus();
}

bool FileSystemFilter::IsDriverInstalled() const {
    return m_impl->IsDriverInstalled();
}

std::string FileSystemFilter::GetDriverVersion() const {
    return m_impl->GetDriverVersion();
}

bool FileSystemFilter::Reconnect() {
    return m_impl->Reconnect();
}

// ============================================================================
// STATISTICS
// ============================================================================

FileSystemFilterStats FileSystemFilter::GetStats() const {
    return m_impl->m_stats.Snapshot();
}

void FileSystemFilter::ResetStats() {
    m_impl->m_stats.Reset();
}

// ============================================================================
// CALLBACKS
// ============================================================================

void FileSystemFilter::RegisterScanCallback(ScanRequestCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_scanCallback = std::move(callback);
}

uint64_t FileSystemFilter::RegisterNotificationCallback(FileNotificationCallback callback) {
    return m_impl->RegisterNotificationCallback(std::move(callback));
}

bool FileSystemFilter::UnregisterNotificationCallback(uint64_t callbackId) {
    return m_impl->UnregisterNotificationCallback(callbackId);
}

uint64_t FileSystemFilter::RegisterStatusCallback(FilterStatusCallback callback) {
    return m_impl->RegisterStatusCallback(std::move(callback));
}

bool FileSystemFilter::UnregisterStatusCallback(uint64_t callbackId) {
    return m_impl->UnregisterStatusCallback(callbackId);
}

uint64_t FileSystemFilter::RegisterThreatCallback(ThreatDetectedCallback callback) {
    return m_impl->RegisterThreatCallback(std::move(callback));
}

bool FileSystemFilter::UnregisterThreatCallback(uint64_t callbackId) {
    return m_impl->UnregisterThreatCallback(callbackId);
}

// ============================================================================
// EXTERNAL INTEGRATION
// ============================================================================

void FileSystemFilter::SetScanEngine(Core::Engine::ScanEngine* engine) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_scanEngine = engine;
}

void FileSystemFilter::SetThreatDetector(Core::Engine::ThreatDetector* detector) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_threatDetector = detector;
}

void FileSystemFilter::SetWhitelistStore(Whitelist::WhitelistStore* store) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_whitelistStore = store;
}

void FileSystemFilter::SetHashStore(HashStore::HashStore* store) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_hashStore = store;
}

void FileSystemFilter::SetCacheManager(Utils::CacheManager* cache) {
    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_cacheManager = cache;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

const char* FilterStatusToString(FilterStatus status) noexcept {
    switch (status) {
        case FilterStatus::NotInitialized: return "NotInitialized";
        case FilterStatus::Initializing: return "Initializing";
        case FilterStatus::Running: return "Running";
        case FilterStatus::Paused: return "Paused";
        case FilterStatus::Stopped: return "Stopped";
        case FilterStatus::Error: return "Error";
        case FilterStatus::DriverNotInstalled: return "DriverNotInstalled";
        case FilterStatus::AccessDenied: return "AccessDenied";
        case FilterStatus::PortBusy: return "PortBusy";
        default: return "Unknown";
    }
}

const char* ScanVerdictToString(ScanVerdict verdict) noexcept {
    switch (verdict) {
        case ScanVerdict::Allow: return "Allow";
        case ScanVerdict::Block: return "Block";
        case ScanVerdict::AllowSuspicious: return "AllowSuspicious";
        case ScanVerdict::BlockAndQuarantine: return "BlockAndQuarantine";
        case ScanVerdict::Timeout: return "Timeout";
        case ScanVerdict::Error: return "Error";
        case ScanVerdict::Retry: return "Retry";
        case ScanVerdict::CacheHitAllow: return "CacheHitAllow";
        case ScanVerdict::CacheHitBlock: return "CacheHitBlock";
        default: return "Unknown";
    }
}

const char* FilterMessageTypeToString(FilterMessageType type) noexcept {
    switch (type) {
        case FilterMessageType::FileScanOnOpen: return "FileScanOnOpen";
        case FilterMessageType::FileScanOnExecute: return "FileScanOnExecute";
        case FilterMessageType::FileScanOnWrite: return "FileScanOnWrite";
        case FilterMessageType::FileScanNetwork: return "FileScanNetwork";
        case FilterMessageType::NotifyFileCreate: return "NotifyFileCreate";
        case FilterMessageType::NotifyFileWrite: return "NotifyFileWrite";
        case FilterMessageType::NotifyFileRename: return "NotifyFileRename";
        case FilterMessageType::NotifyFileDelete: return "NotifyFileDelete";
        case FilterMessageType::NotifyFileMap: return "NotifyFileMap";
        default: return "Unknown";
    }
}

const char* FileAccessTypeToString(FileAccessType type) noexcept {
    switch (type) {
        case FileAccessType::Read: return "Read";
        case FileAccessType::Write: return "Write";
        case FileAccessType::Execute: return "Execute";
        case FileAccessType::Map: return "Map";
        case FileAccessType::Delete: return "Delete";
        case FileAccessType::Rename: return "Rename";
        case FileAccessType::Create: return "Create";
        default: return "Unknown";
    }
}

std::wstring GetFileExtension(const std::wstring& path) noexcept {
    size_t dotPos = path.rfind(L'.');
    if (dotPos == std::wstring::npos || dotPos == path.length() - 1) {
        return L"";
    }
    return path.substr(dotPos);
}

std::wstring NormalizePath(const std::wstring& path) noexcept {
    if (path.empty()) return {};

    std::wstring resolved;

    // Resolve reparse points (junctions/symlinks) via GetFinalPathNameByHandleW
    HANDLE hFile = CreateFileW(
        path.c_str(),
        0,  // No access needed
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD needed = GetFinalPathNameByHandleW(hFile, nullptr, 0, FILE_NAME_NORMALIZED);
        if (needed > 0 && needed <= 32768) {
            auto buf = std::make_unique<wchar_t[]>(needed);
            DWORD written = GetFinalPathNameByHandleW(
                hFile, buf.get(), needed, FILE_NAME_NORMALIZED);
            if (written > 0 && written < needed) {
                resolved.assign(buf.get(), written);
                // Strip \\?\ prefix
                if (resolved.starts_with(L"\\\\?\\")) {
                    resolved = resolved.substr(4);
                }
            }
        }
        CloseHandle(hFile);
    }

    // Fallback to GetFullPathNameW for non-existent files
    if (resolved.empty()) {
        DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
        if (needed > 0 && needed <= 32768) {
            auto buf = std::make_unique<wchar_t[]>(needed);
            DWORD written = GetFullPathNameW(path.c_str(), needed, buf.get(), nullptr);
            if (written > 0 && written < needed) {
                resolved.assign(buf.get(), written);
            } else {
                resolved = path;
            }
        } else {
            resolved = path;
        }
    }

    // Convert forward slashes to backslashes
    std::replace(resolved.begin(), resolved.end(), L'/', L'\\');

    // Remove trailing backslash
    while (resolved.size() > 3 && resolved.back() == L'\\') {
        resolved.pop_back();
    }

    // Lowercase for comparison
    std::transform(resolved.begin(), resolved.end(), resolved.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(std::tolower(c)); });

    return resolved;
}

bool PathMatchesPattern(const std::wstring& path, const std::wstring& pattern,
                        bool caseInsensitive) noexcept {
    const std::wstring& p = caseInsensitive ? ToLowerW(path) : path;
    const std::wstring& pat = caseInsensitive ? ToLowerW(pattern) : pattern;

    // O(n*m) worst-case wildcard matching without regex compilation
    size_t pi = 0, si = 0;
    size_t starIdx = std::wstring::npos, matchIdx = 0;

    while (si < p.size()) {
        if (pi < pat.size() && (pat[pi] == L'?' || pat[pi] == p[si])) {
            ++pi;
            ++si;
        } else if (pi < pat.size() && pat[pi] == L'*') {
            starIdx = pi;
            matchIdx = si;
            ++pi;
        } else if (starIdx != std::wstring::npos) {
            pi = starIdx + 1;
            ++matchIdx;
            si = matchIdx;
        } else {
            return false;
        }
    }

    while (pi < pat.size() && pat[pi] == L'*') ++pi;
    return pi == pat.size();
}

bool IsExecutableExtension(const std::wstring& extension) noexcept {
    std::wstring ext = ToLowerW(extension);
    return EXECUTABLE_EXTENSIONS.count(ext) > 0;
}

bool IsScriptExtension(const std::wstring& extension) noexcept {
    std::wstring ext = ToLowerW(extension);
    return SCRIPT_EXTENSIONS.count(ext) > 0;
}

} // namespace RealTime
} // namespace ShadowStrike
