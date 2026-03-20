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
 * @file IPCManager.cpp
 * @brief Implementation of kernel-user mode IPC Manager
 *
 * This is the CRITICAL integration point between the kernel minifilter
 * driver and user-mode scanning components.
 *
 * @copyright ShadowStrike NGAV - Enterprise Security Platform
 */

#include "IPCManager.hpp"
#include "FilterConnection.hpp"
#include "ThreatIntelPusher.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <aclapi.h>
#include <sddl.h>
#include <wintrust.h>
#include <softpub.h>

#ifdef _WIN32
#pragma comment(lib, "fltlib.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#endif

namespace ShadowStrike {
namespace Communication {

// ============================================================================
// STATIC MEMBERS
// ============================================================================

std::atomic<bool> IPCManager::s_instanceCreated{false};

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class IPCManagerImpl {
public:
    IPCManagerImpl() = default;
    ~IPCManagerImpl() = default;

    // Configuration
    IPCConfiguration config;
    mutable std::shared_mutex configMutex;

    // Statistics
    IPCStatistics stats;

    // Callbacks
    ConnectionCallback connectionCallback;
    ErrorCallback errorCallback;
    mutable std::mutex callbackMutex;

    // Message buffers (pool for performance - avoids allocations in hot path)
    static constexpr size_t BUFFER_POOL_SIZE = 16;
    std::array<std::vector<uint8_t>, BUFFER_POOL_SIZE> bufferPool;
    std::atomic<uint32_t> nextBufferIndex{0};

    // Pending replies for async operations
    struct PendingReply {
        uint64_t messageId;
        TimePoint expirationTime;
        std::promise<SHADOWSTRIKE_SCAN_VERDICT_REPLY> promise;
    };
    std::unordered_map<uint64_t, std::unique_ptr<PendingReply>> pendingReplies;
    mutable std::mutex pendingMutex;

    // Message ID generator (atomic for thread safety)
    std::atomic<uint64_t> nextMessageId{1};

    // Shutdown event for clean termination
    HANDLE shutdownEvent = nullptr;

    [[nodiscard]] std::vector<uint8_t>& GetBuffer() noexcept {
        uint32_t index = nextBufferIndex.fetch_add(1, std::memory_order_relaxed) % BUFFER_POOL_SIZE;
        auto& buffer = bufferPool[index];
        if (buffer.size() < IPCConstants::MAX_MESSAGE_SIZE) {
            buffer.resize(IPCConstants::MAX_MESSAGE_SIZE);
        }
        return buffer;
    }

    [[nodiscard]] uint64_t GenerateMessageId() noexcept {
        return nextMessageId.fetch_add(1, std::memory_order_relaxed);
    }

    void NotifyError(const std::string& message, int code) {
        std::lock_guard lock(callbackMutex);
        if (errorCallback) {
            try {
                errorCallback(message, code);
            } catch (...) {
                // Don't let callback exceptions propagate
            }
        }
    }

    void NotifyConnectionChange(ChannelType channel, ConnectionStatus status) {
        std::lock_guard lock(callbackMutex);
        if (connectionCallback) {
            try {
                connectionCallback(channel, status);
            } catch (...) {
                // Don't let callback exceptions propagate
            }
        }
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

IPCManager& IPCManager::Instance() noexcept {
    static IPCManager instance;
    return instance;
}

bool IPCManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

IPCManager::IPCManager()
    : m_impl(std::make_unique<IPCManagerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);

    // Create shutdown event
    m_impl->shutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    Utils::Logger::Info("[IPCManager] Instance created - version {}",
                        GetVersionString());
}

IPCManager::~IPCManager() {
    Shutdown();

    if (m_impl->shutdownEvent != nullptr) {
        CloseHandle(m_impl->shutdownEvent);
        m_impl->shutdownEvent = nullptr;
    }

    s_instanceCreated.store(false, std::memory_order_release);
    Utils::Logger::Info("[IPCManager] Instance destroyed");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool IPCManager::Initialize(const IPCConfiguration& config) {
    IPCStatus expected = IPCStatus::Uninitialized;
    if (!m_status.compare_exchange_strong(expected, IPCStatus::Initializing)) {
        Utils::Logger::Warn("[IPCManager] Already initialized (status: {})",
                            static_cast<int>(m_status.load()));
        return m_status.load() != IPCStatus::Error;
    }

    if (!config.IsValid()) {
        Utils::Logger::Error("[IPCManager] Invalid configuration provided");
        m_status.store(IPCStatus::Error);
        return false;
    }

    {
        std::unique_lock lock(m_impl->configMutex);
        m_impl->config = config;
    }

    // Pre-allocate buffer pool
    for (auto& buffer : m_impl->bufferPool) {
        try {
            buffer.reserve(IPCConstants::MAX_MESSAGE_SIZE);
        } catch (const std::bad_alloc& e) {
            Utils::Logger::Error("[IPCManager] Failed to allocate buffer pool: {}", e.what());
            m_status.store(IPCStatus::Error);
            return false;
        }
    }

    // Create IOCP for async I/O if enabled
    if (config.useIOCP) {
        m_hIOCP = CreateIoCompletionPort(
            INVALID_HANDLE_VALUE,
            nullptr,
            0,
            config.workerThreadCount
        );

        if (m_hIOCP == nullptr) {
            DWORD error = GetLastError();
            Utils::Logger::Error("[IPCManager] Failed to create IOCP: {}", error);
            m_status.store(IPCStatus::Error);
            return false;
        }
    }

    // Reset shutdown event
    if (m_impl->shutdownEvent != nullptr) {
        ResetEvent(m_impl->shutdownEvent);
    }

    m_impl->stats.startTime = Clock::now();
    m_status.store(IPCStatus::Stopped);

    Utils::Logger::Info("[IPCManager] Initialized successfully");
    Utils::Logger::Info("[IPCManager]   Filter port: {}",
                        Utils::StringUtils::WideToUtf8(config.filterPortName));
    Utils::Logger::Info("[IPCManager]   Worker threads: {}", config.workerThreadCount);
    Utils::Logger::Info("[IPCManager]   Reply timeout: {} ms", config.replyTimeoutMs);

    return true;
}

bool IPCManager::Start(uint32_t workerThreadCount) {
    IPCStatus expected = IPCStatus::Stopped;
    if (!m_status.compare_exchange_strong(expected, IPCStatus::Running)) {
        Utils::Logger::Warn("[IPCManager] Cannot start - current status: {}",
                            static_cast<int>(m_status.load()));
        return false;
    }

    m_running.store(true, std::memory_order_release);

    // Reset shutdown event
    if (m_impl->shutdownEvent != nullptr) {
        ResetEvent(m_impl->shutdownEvent);
    }

    // Connect to filter port (driver communication)
    if (m_impl->config.enableFilterPort) {
        if (!ConnectFilterPort()) {
            Utils::Logger::Warn("[IPCManager] Filter port connection failed - "
                               "driver may not be loaded. Continuing anyway...");
            // Don't fail - we can still provide pipe/shared memory services
        }
    }

    // Start worker threads
    uint32_t numWorkers = (workerThreadCount > 0)
                          ? workerThreadCount
                          : m_impl->config.workerThreadCount;

    if (numWorkers == 0) {
        numWorkers = std::thread::hardware_concurrency();
        if (numWorkers == 0) numWorkers = 4;  // Fallback
    }

    m_workerThreads.reserve(numWorkers);

    for (uint32_t i = 0; i < numWorkers; ++i) {
        try {
            m_workerThreads.emplace_back(&IPCManager::WorkerRoutine, this);
        } catch (const std::system_error& e) {
            Utils::Logger::Error("[IPCManager] Failed to create worker thread {}: {}",
                                 i, e.what());
        }
    }

    if (m_workerThreads.empty()) {
        Utils::Logger::Error("[IPCManager] No worker threads created");
        m_running.store(false);
        m_status.store(IPCStatus::Error);
        return false;
    }

    Utils::Logger::Info("[IPCManager] Started with {} worker threads",
                        m_workerThreads.size());

    return true;
}

void IPCManager::Stop() {
    if (!m_running.load(std::memory_order_acquire)) {
        return;
    }

    Utils::Logger::Info("[IPCManager] Stopping...");
    m_status.store(IPCStatus::Stopping);
    m_running.store(false, std::memory_order_release);

    // Signal shutdown event
    if (m_impl->shutdownEvent != nullptr) {
        SetEvent(m_impl->shutdownEvent);
    }

    // Post completion packets to wake up IOCP workers
    if (m_hIOCP != nullptr) {
        for (size_t i = 0; i < m_workerThreads.size(); ++i) {
            PostQueuedCompletionStatus(m_hIOCP, 0, 0, nullptr);
        }
    }

    // Cancel any pending filter operations
    {
        HANDLE hPort = m_hPort.load(std::memory_order_acquire);
        if (hPort != nullptr) {
            CancelIoEx(hPort, nullptr);
        }
    }

    // Wait for all workers to finish
    for (auto& thread : m_workerThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_workerThreads.clear();

    // Disconnect channels
    DisconnectFilterPort();
    DisconnectPipe();

    m_status.store(IPCStatus::Stopped);
    Utils::Logger::Info("[IPCManager] Stopped");
}

void IPCManager::Shutdown() {
    Stop();

    // Close IOCP handle
    if (m_hIOCP != nullptr) {
        CloseHandle(m_hIOCP);
        m_hIOCP = nullptr;
    }

    // Close all shared memory regions
    {
        std::unique_lock lock(m_sharedMemoryMutex);
        for (auto& [name, region] : m_sharedMemory) {
            if (region.baseAddress != nullptr) {
                UnmapViewOfFile(region.baseAddress);
                region.baseAddress = nullptr;
            }
            if (region.mappingHandle != nullptr) {
                CloseHandle(region.mappingHandle);
                region.mappingHandle = nullptr;
            }
            if (region.eventHandle != nullptr) {
                CloseHandle(region.eventHandle);
                region.eventHandle = nullptr;
            }
        }
        m_sharedMemory.clear();
    }

    // Clear pending replies
    {
        std::lock_guard lock(m_impl->pendingMutex);
        m_impl->pendingReplies.clear();
    }

    m_status.store(IPCStatus::Uninitialized);
    Utils::Logger::Info("[IPCManager] Shutdown complete");
}

bool IPCManager::IsInitialized() const noexcept {
    auto status = m_status.load(std::memory_order_acquire);
    return status != IPCStatus::Uninitialized && status != IPCStatus::Error;
}

bool IPCManager::IsConnected() const noexcept {
    return m_connected.load(std::memory_order_acquire);
}

IPCStatus IPCManager::GetStatus() const noexcept {
    return m_status.load(std::memory_order_acquire);
}

bool IPCManager::UpdateConfiguration(const IPCConfiguration& config) {
    if (!config.IsValid()) {
        Utils::Logger::Error("[IPCManager] Invalid configuration");
        return false;
    }

    std::unique_lock lock(m_impl->configMutex);
    m_impl->config = config;

    Utils::Logger::Info("[IPCManager] Configuration updated");
    return true;
}

IPCConfiguration IPCManager::GetConfiguration() const {
    std::shared_lock lock(m_impl->configMutex);
    return m_impl->config;
}

// ============================================================================
// FILTER PORT OPERATIONS
// ============================================================================

bool IPCManager::ConnectFilterPort() {
    if (m_hPort.load(std::memory_order_acquire) != nullptr) {
        Utils::Logger::Debug("[IPCManager] Filter port already connected");
        return true;
    }

    std::wstring portName;
    {
        std::shared_lock lock(m_impl->configMutex);
        portName = m_impl->config.filterPortName;
    }

    Utils::Logger::Info("[IPCManager] Connecting to filter port: {}",
                        Utils::StringUtils::WideToUtf8(portName));

    // FIX [BUG #11]: Use temp handle — FilterConnectCommunicationPort writes
    // directly to &handle. Storing into atomic<HANDLE> address isn't portable.
    HANDLE hPortTemp = nullptr;
    HRESULT hr = FilterConnectCommunicationPort(
        portName.c_str(),
        0,
        nullptr,
        0,
        nullptr,
        &hPortTemp
    );

    if (FAILED(hr)) {
        Utils::Logger::Error("[IPCManager] FilterConnectCommunicationPort failed: 0x{:08X}",
                             static_cast<unsigned int>(hr));

        if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
            Utils::Logger::Error("[IPCManager] Driver port not found - is driver loaded?");
        } else if (hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) {
            Utils::Logger::Error("[IPCManager] Access denied - check service permissions");
        }

        m_impl->NotifyError("Filter port connection failed", hr);
        return false;
    }

    // Associate with IOCP for async operations
    if (m_hIOCP != nullptr) {
        HANDLE result = CreateIoCompletionPort(
            hPortTemp,
            m_hIOCP,
            reinterpret_cast<ULONG_PTR>(hPortTemp),
            0
        );

        if (result == nullptr) {
            Utils::Logger::Warn("[IPCManager] Failed to associate port with IOCP: {}",
                               GetLastError());
        }
    }

    m_hPort.store(hPortTemp, std::memory_order_release);
    m_connected.store(true, std::memory_order_release);
    m_impl->NotifyConnectionChange(ChannelType::FilterPort, ConnectionStatus::Connected);

    // Create dedicated push connection + ThreatIntelPusher
    {
        std::lock_guard lock(m_pusherMutex);
        try {
            m_pushConnection = std::make_unique<FilterConnection>();
            if (m_pushConnection->Connect()) {
                m_pusher = std::make_unique<ThreatIntelPusher>(*m_pushConnection);
                Utils::Logger::Info("[IPCManager] ThreatIntelPusher created on dedicated push connection");
            } else {
                Utils::Logger::Warn("[IPCManager] Push connection failed — ThreatIntelPusher unavailable");
                m_pushConnection.reset();
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("[IPCManager] Failed to create ThreatIntelPusher: {}", e.what());
            m_pusher.reset();
            m_pushConnection.reset();
        }
    }

    Utils::Logger::Info("[IPCManager] Successfully connected to filter port");
    return true;
}

void IPCManager::DisconnectFilterPort() {
    // Tear down pusher before closing the port
    {
        std::lock_guard lock(m_pusherMutex);
        m_pusher.reset();
        if (m_pushConnection) {
            m_pushConnection->Disconnect();
            m_pushConnection.reset();
        }
    }

    // FIX [BUG #11]: Atomic exchange prevents double-close race between
    // Stop() and worker threads seeing ERROR_INVALID_HANDLE.
    HANDLE hOld = m_hPort.exchange(nullptr, std::memory_order_acq_rel);
    if (hOld != nullptr) {
        CancelIoEx(hOld, nullptr);
        CloseHandle(hOld);
        m_connected.store(false, std::memory_order_release);

        m_impl->NotifyConnectionChange(ChannelType::FilterPort, ConnectionStatus::Disconnected);
        Utils::Logger::Info("[IPCManager] Disconnected from filter port");
    }
}

bool IPCManager::IsFilterPortConnected() const noexcept {
    return m_hPort.load(std::memory_order_acquire) != nullptr
        && m_connected.load(std::memory_order_acquire);
}

ThreatIntelPusher* IPCManager::GetPusher() noexcept {
    std::lock_guard lock(m_pusherMutex);
    return m_pusher.get();
}

bool IPCManager::SendToKernel(
    const void* message,
    size_t messageSize,
    void* reply,
    size_t* replySize,
    uint32_t timeoutMs) {

    // FIX [BUG #11]: Atomic snapshot of handle
    HANDLE hPort = m_hPort.load(std::memory_order_acquire);
    if (hPort == nullptr) {
        Utils::Logger::Error("[IPCManager] Cannot send - not connected to filter port");
        return false;
    }

    if (message == nullptr || messageSize == 0) {
        Utils::Logger::Error("[IPCManager] Invalid message parameters");
        return false;
    }

    if (messageSize > IPCConstants::MAX_MESSAGE_SIZE) {
        Utils::Logger::Error("[IPCManager] Message too large: {} > {}",
                             messageSize, IPCConstants::MAX_MESSAGE_SIZE);
        return false;
    }

    auto startTime = Clock::now();

    // FIX [BUG #7]: Guard against reply != nullptr && replySize == nullptr
    DWORD replyBufSize = 0;
    if (reply != nullptr && replySize != nullptr) {
        replyBufSize = static_cast<DWORD>(*replySize);
    } else if (reply != nullptr && replySize == nullptr) {
        Utils::Logger::Error("[IPCManager] reply buffer provided but replySize is null");
        return false;
    }

    DWORD bytesReturned = 0;
    HRESULT hr = FilterSendMessage(
        hPort,
        const_cast<void*>(message),
        static_cast<DWORD>(messageSize),
        reply,
        replyBufSize,
        &bytesReturned
    );

    auto endTime = Clock::now();
    auto latencyUs = std::chrono::duration_cast<std::chrono::microseconds>(
        endTime - startTime).count();

    if (FAILED(hr)) {
        Utils::Logger::Error("[IPCManager] FilterSendMessage failed: 0x{:08X}",
                             static_cast<unsigned int>(hr));
        m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);

        if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
            m_connected.store(false);
            m_impl->NotifyConnectionChange(ChannelType::FilterPort, ConnectionStatus::Error);
        }

        return false;
    }

    if (replySize != nullptr) {
        *replySize = bytesReturned;
    }

    // Update statistics
    m_impl->stats.messagesSent.fetch_add(1, std::memory_order_relaxed);
    m_impl->stats.bytesSent.fetch_add(messageSize, std::memory_order_relaxed);

    // Update latency tracking (exponential moving average)
    uint64_t currentAvg = m_impl->stats.avgLatencyUs.load(std::memory_order_relaxed);
    m_impl->stats.avgLatencyUs.store(
        (currentAvg * 95 + static_cast<uint64_t>(latencyUs) * 5) / 100,
        std::memory_order_relaxed);

    // FIX [BUG #15]: CAS loop for maxLatencyUs — plain store races under contention
    uint64_t currentMax = m_impl->stats.maxLatencyUs.load(std::memory_order_relaxed);
    uint64_t newLatency = static_cast<uint64_t>(latencyUs);
    while (newLatency > currentMax) {
        if (m_impl->stats.maxLatencyUs.compare_exchange_weak(
                currentMax, newLatency, std::memory_order_relaxed)) {
            break;
        }
    }

    return true;
}

// ============================================================================
// NAMED PIPE OPERATIONS
// ============================================================================

bool IPCManager::CreatePipeServer(const std::wstring& pipeName) {
    if (m_hPipe != nullptr) {
        Utils::Logger::Warn("[IPCManager] Pipe server already exists");
        return false;
    }

    // Create secure DACL for pipe
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE };
    if (!CreateSecurePipeDacl(sa)) {
        Utils::Logger::Warn("[IPCManager] Failed to create secure DACL, using default");
    }

    m_hPipe = CreateNamedPipeW(
        pipeName.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,  // FIX [BUG #16]: Single instance prevents named pipe squatting attacks
        static_cast<DWORD>(IPCConstants::MAX_MESSAGE_SIZE),
        static_cast<DWORD>(IPCConstants::MAX_MESSAGE_SIZE),
        0,
        &sa
    );

    // Free security descriptor if allocated
    if (sa.lpSecurityDescriptor != nullptr) {
        LocalFree(sa.lpSecurityDescriptor);
    }

    if (m_hPipe == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        Utils::Logger::Error("[IPCManager] CreateNamedPipe failed: {}", error);
        m_hPipe = nullptr;
        return false;
    }

    Utils::Logger::Info("[IPCManager] Created pipe server: {}",
                        Utils::StringUtils::WideToUtf8(pipeName));
    return true;
}

bool IPCManager::ConnectToPipe(const std::wstring& pipeName) {
    // Wait for pipe to be available
    if (!WaitNamedPipeW(pipeName.c_str(), 5000)) {
        Utils::Logger::Error("[IPCManager] Pipe not available: {}", GetLastError());
        return false;
    }

    m_hPipe = CreateFileW(
        pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        nullptr
    );

    if (m_hPipe == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        Utils::Logger::Error("[IPCManager] Failed to connect to pipe: {}", error);
        m_hPipe = nullptr;
        return false;
    }

    // Set message mode
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(m_hPipe, &mode, nullptr, nullptr)) {
        Utils::Logger::Warn("[IPCManager] Failed to set pipe message mode: {}",
                            GetLastError());
    }

    Utils::Logger::Info("[IPCManager] Connected to pipe: {}",
                        Utils::StringUtils::WideToUtf8(pipeName));
    return true;
}

void IPCManager::DisconnectPipe() {
    if (m_hPipe != nullptr) {
        FlushFileBuffers(m_hPipe);
        DisconnectNamedPipe(m_hPipe);
        CloseHandle(m_hPipe);
        m_hPipe = nullptr;
        Utils::Logger::Info("[IPCManager] Pipe disconnected");
    }
}

bool IPCManager::SendPipeMessage(const void* data, size_t size) {
    if (m_hPipe == nullptr) {
        Utils::Logger::Error("[IPCManager] Cannot send - pipe not connected");
        return false;
    }

    if (data == nullptr || size == 0) {
        return false;
    }

    DWORD bytesWritten = 0;
    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    if (overlapped.hEvent == nullptr) {
        return false;
    }

    BOOL result = WriteFile(
        m_hPipe,
        data,
        static_cast<DWORD>(size),
        &bytesWritten,
        &overlapped
    );

    if (!result) {
        DWORD error = GetLastError();
        if (error == ERROR_IO_PENDING) {
            // Wait for completion
            DWORD waitResult = WaitForSingleObject(overlapped.hEvent, 5000);
            if (waitResult == WAIT_OBJECT_0) {
                GetOverlappedResult(m_hPipe, &overlapped, &bytesWritten, FALSE);
            } else {
                // FIX [BUG #8]: After CancelIoEx, MUST drain with
                // GetOverlappedResult(bWait=TRUE) before OVERLAPPED goes out
                // of scope. Without this, the kernel may write to freed stack.
                CancelIoEx(m_hPipe, &overlapped);
                GetOverlappedResult(m_hPipe, &overlapped, &bytesWritten, TRUE);
                CloseHandle(overlapped.hEvent);
                return false;
            }
        } else {
            CloseHandle(overlapped.hEvent);
            return false;
        }
    }

    CloseHandle(overlapped.hEvent);

    m_impl->stats.messagesSent++;
    m_impl->stats.bytesSent += bytesWritten;

    return bytesWritten == static_cast<DWORD>(size);
}

void IPCManager::SendCommand(const std::string& cmd) {
    if (!cmd.empty()) {
        SendPipeMessage(cmd.data(), cmd.size());
    }
}

// ============================================================================
// SHARED MEMORY OPERATIONS
// ============================================================================

bool IPCManager::CreateSharedMemory(const std::wstring& name, size_t size, bool writable) {
    std::unique_lock lock(m_sharedMemoryMutex);

    if (m_sharedMemory.contains(name)) {
        Utils::Logger::Warn("[IPCManager] Shared memory already exists: {}",
                            Utils::StringUtils::WideToUtf8(name));
        return true;  // Already exists, consider it success
    }

    SharedMemoryRegion region;
    region.name = name;
    region.size = size;
    region.isWritable = writable;

    // FIX [BUG #13]: Create restricted SECURITY_ATTRIBUTES (SYSTEM + Admins only)
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE };
    PSECURITY_DESCRIPTOR pSD = nullptr;

    // SDDL: D:P(A;;GA;;;SY)(A;;GA;;;BA) = SYSTEM full + Admins full, deny all others
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
            SDDL_REVISION_1,
            &pSD,
            nullptr)) {
        sa.lpSecurityDescriptor = pSD;
    } else {
        Utils::Logger::Warn("[IPCManager] Failed to create shared memory DACL: {}", GetLastError());
    }

    // Create file mapping
    region.mappingHandle = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        &sa,
        writable ? PAGE_READWRITE : PAGE_READONLY,
        static_cast<DWORD>(size >> 32),
        static_cast<DWORD>(size & 0xFFFFFFFF),
        name.c_str()
    );

    if (pSD != nullptr) {
        LocalFree(pSD);
    }

    if (region.mappingHandle == nullptr) {
        Utils::Logger::Error("[IPCManager] CreateFileMapping failed: {}", GetLastError());
        return false;
    }

    // Map view of file
    region.baseAddress = MapViewOfFile(
        region.mappingHandle,
        writable ? FILE_MAP_ALL_ACCESS : FILE_MAP_READ,
        0, 0, size
    );

    if (region.baseAddress == nullptr) {
        Utils::Logger::Error("[IPCManager] MapViewOfFile failed: {}", GetLastError());
        CloseHandle(region.mappingHandle);
        return false;
    }

    // Create signaling event
    std::wstring eventName = name + L"_Event";
    region.eventHandle = CreateEventW(nullptr, FALSE, FALSE, eventName.c_str());

    m_sharedMemory[name] = std::move(region);

    Utils::Logger::Info("[IPCManager] Created shared memory: {} ({} bytes)",
                        Utils::StringUtils::WideToUtf8(name), size);
    return true;
}

bool IPCManager::OpenSharedMemory(const std::wstring& name, bool writable) {
    std::unique_lock lock(m_sharedMemoryMutex);

    if (m_sharedMemory.contains(name)) {
        return true;
    }

    SharedMemoryRegion region;
    region.name = name;
    region.isWritable = writable;

    region.mappingHandle = OpenFileMappingW(
        writable ? FILE_MAP_ALL_ACCESS : FILE_MAP_READ,
        FALSE,
        name.c_str()
    );

    if (region.mappingHandle == nullptr) {
        Utils::Logger::Error("[IPCManager] OpenFileMapping failed: {}", GetLastError());
        return false;
    }

    region.baseAddress = MapViewOfFile(
        region.mappingHandle,
        writable ? FILE_MAP_ALL_ACCESS : FILE_MAP_READ,
        0, 0, 0
    );

    if (region.baseAddress == nullptr) {
        Utils::Logger::Error("[IPCManager] MapViewOfFile failed: {}", GetLastError());
        CloseHandle(region.mappingHandle);
        return false;
    }

    // Get size from mapping
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(region.baseAddress, &mbi, sizeof(mbi))) {
        region.size = mbi.RegionSize;
    }

    // Open signaling event
    std::wstring eventName = name + L"_Event";
    region.eventHandle = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, eventName.c_str());

    m_sharedMemory[name] = std::move(region);
    return true;
}

void* IPCManager::GetSharedMemoryPtr(const std::wstring& name) {
    std::shared_lock lock(m_sharedMemoryMutex);
    auto it = m_sharedMemory.find(name);
    return (it != m_sharedMemory.end()) ? it->second.baseAddress : nullptr;
}

void IPCManager::SignalSharedMemory(const std::wstring& name) {
    std::shared_lock lock(m_sharedMemoryMutex);
    auto it = m_sharedMemory.find(name);
    if (it != m_sharedMemory.end() && it->second.eventHandle != nullptr) {
        SetEvent(it->second.eventHandle);
    }
}

bool IPCManager::WaitSharedMemory(const std::wstring& name, uint32_t timeoutMs) {
    HANDLE eventHandle = nullptr;
    {
        std::shared_lock lock(m_sharedMemoryMutex);
        auto it = m_sharedMemory.find(name);
        if (it != m_sharedMemory.end()) {
            eventHandle = it->second.eventHandle;
        }
    }

    if (eventHandle == nullptr) {
        return false;
    }

    return WaitForSingleObject(eventHandle, timeoutMs) == WAIT_OBJECT_0;
}

void IPCManager::CloseSharedMemory(const std::wstring& name) {
    std::unique_lock lock(m_sharedMemoryMutex);
    auto it = m_sharedMemory.find(name);
    if (it != m_sharedMemory.end()) {
        if (it->second.baseAddress != nullptr) {
            UnmapViewOfFile(it->second.baseAddress);
        }
        if (it->second.mappingHandle != nullptr) {
            CloseHandle(it->second.mappingHandle);
        }
        if (it->second.eventHandle != nullptr) {
            CloseHandle(it->second.eventHandle);
        }
        m_sharedMemory.erase(it);
        Utils::Logger::Info("[IPCManager] Closed shared memory: {}",
                            Utils::StringUtils::WideToUtf8(name));
    }
}

// ============================================================================
// HANDLER REGISTRATION
// ============================================================================

void IPCManager::RegisterFileScanHandler(FileScanCallback handler) {
    std::lock_guard lock(m_handlerMutex);
    m_fileScanHandler = std::move(handler);
    Utils::Logger::Info("[IPCManager] Registered file scan handler");
}

void IPCManager::RegisterProcessHandler(ProcessNotifyCallback handler) {
    std::lock_guard lock(m_handlerMutex);
    m_processHandler = std::move(handler);
    Utils::Logger::Info("[IPCManager] Registered process handler");
}

void IPCManager::RegisterImageLoadHandler(ImageLoadCallback handler) {
    std::lock_guard lock(m_handlerMutex);
    m_imageLoadHandler = std::move(handler);
    Utils::Logger::Info("[IPCManager] Registered image load handler");
}

void IPCManager::RegisterRegistryHandler(RegistryOpCallback handler) {
    std::lock_guard lock(m_handlerMutex);
    m_registryHandler = std::move(handler);
    Utils::Logger::Info("[IPCManager] Registered registry handler");
}

void IPCManager::RegisterGenericHandler(GenericMessageCallback handler) {
    std::lock_guard lock(m_handlerMutex);
    m_genericHandler = std::move(handler);
}

void IPCManager::SetMessageCallback(std::function<void(const std::string&)> cb) {
    std::lock_guard lock(m_handlerMutex);
    m_messageCallback = std::move(cb);
}

void IPCManager::UnregisterHandlers() {
    std::lock_guard lock(m_handlerMutex);
    m_fileScanHandler = nullptr;
    m_processHandler = nullptr;
    m_imageLoadHandler = nullptr;
    m_registryHandler = nullptr;
    m_genericHandler = nullptr;
    m_messageCallback = nullptr;
    Utils::Logger::Info("[IPCManager] Unregistered all handlers");
}

// ============================================================================
// CONNECTION MANAGEMENT
// ============================================================================

ConnectionInfo IPCManager::GetConnectionInfo(ChannelType channel) const {
    ConnectionInfo info;
    info.channelType = channel;
    info.lastActivity = Clock::now();

    switch (channel) {
        case ChannelType::FilterPort:
            info.status = m_hPort.load(std::memory_order_acquire) != nullptr
                          ? ConnectionStatus::Connected
                          : ConnectionStatus::Disconnected;
            {
                std::shared_lock lock(m_impl->configMutex);
                info.endpoint = m_impl->config.filterPortName;
            }
            break;

        case ChannelType::NamedPipe:
            info.status = m_hPipe != nullptr
                          ? ConnectionStatus::Connected
                          : ConnectionStatus::Disconnected;
            {
                std::shared_lock lock(m_impl->configMutex);
                info.endpoint = m_impl->config.servicePipeName;
            }
            break;

        default:
            info.status = ConnectionStatus::Disconnected;
            break;
    }

    info.messagesReceived = m_impl->stats.messagesReceived.load();
    info.messagesSent = m_impl->stats.messagesSent.load();
    info.bytesReceived = m_impl->stats.bytesReceived.load();
    info.bytesSent = m_impl->stats.bytesSent.load();
    info.reconnectCount = static_cast<uint32_t>(m_impl->stats.reconnects.load());

    return info;
}

std::vector<ConnectionInfo> IPCManager::GetAllConnections() const {
    std::vector<ConnectionInfo> connections;
    connections.reserve(3);

    connections.push_back(GetConnectionInfo(ChannelType::FilterPort));
    connections.push_back(GetConnectionInfo(ChannelType::NamedPipe));
    connections.push_back(GetConnectionInfo(ChannelType::SharedMemory));

    return connections;
}

void IPCManager::Reconnect(ChannelType channel) {
    Utils::Logger::Info("[IPCManager] Reconnecting channel: {}",
                        std::string(GetChannelTypeName(channel)));

    switch (channel) {
        case ChannelType::FilterPort:
            DisconnectFilterPort();
            if (ConnectFilterPort()) {
                m_impl->stats.reconnects++;
            }
            break;

        case ChannelType::NamedPipe:
            DisconnectPipe();
            {
                std::shared_lock lock(m_impl->configMutex);
                ConnectToPipe(m_impl->config.servicePipeName);
            }
            m_impl->stats.reconnects++;
            break;

        default:
            break;
    }
}

// ============================================================================
// CALLBACKS
// ============================================================================

void IPCManager::RegisterConnectionCallback(ConnectionCallback callback) {
    std::lock_guard lock(m_impl->callbackMutex);
    m_impl->connectionCallback = std::move(callback);
}

void IPCManager::RegisterErrorCallback(ErrorCallback callback) {
    std::lock_guard lock(m_impl->callbackMutex);
    m_impl->errorCallback = std::move(callback);
}

void IPCManager::UnregisterCallbacks() {
    std::lock_guard lock(m_impl->callbackMutex);
    m_impl->connectionCallback = nullptr;
    m_impl->errorCallback = nullptr;
}

// ============================================================================
// STATISTICS
// ============================================================================

IPCStatisticsSnapshot IPCManager::GetStatistics() const {
    return TakeSnapshot(m_impl->stats);
}

void IPCManager::ResetStatistics() {
    m_impl->stats.Reset();
    Utils::Logger::Info("[IPCManager] Statistics reset");
}

// ============================================================================
// WORKER ROUTINE - Core message processing loop
// ============================================================================

void IPCManager::WorkerRoutine() {
    Utils::Logger::Debug("[IPCManager] Worker thread {} started",
                         std::this_thread::get_id());

    // Allocate per-thread receive buffer.
    // Wire format: [FILTER_MESSAGE_HEADER (WDK, 12 bytes)] [SHADOWSTRIKE_MESSAGE_HEADER (40 bytes)] [payload]
    std::vector<uint8_t> buffer(IPCConstants::MAX_MESSAGE_SIZE);

    while (m_running.load(std::memory_order_acquire)) {
        // FIX [BUG #11]: Atomic snapshot of handle — prevents TOCTOU
        HANDLE hPort = m_hPort.load(std::memory_order_acquire);
        if (hPort == nullptr) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            std::shared_lock lock(m_impl->configMutex);
            if (m_impl->config.autoReconnect && m_running.load()) {
                lock.unlock();
                ConnectFilterPort();
            }
            continue;
        }

        // Cast buffer start to WDK FILTER_MESSAGE_HEADER for FilterGetMessage
        PFILTER_MESSAGE_HEADER pWdkHeader =
            reinterpret_cast<PFILTER_MESSAGE_HEADER>(buffer.data());

        HRESULT hr = FilterGetMessage(
            hPort,
            pWdkHeader,
            static_cast<DWORD>(buffer.size()),
            nullptr  // Synchronous
        );

        if (FAILED(hr)) {
            if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) ||
                hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
                Utils::Logger::Debug("[IPCManager] Worker: Operation aborted (shutdown)");
                break;
            }

            if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
                Utils::Logger::Error("[IPCManager] Worker: Invalid port handle");
                m_connected.store(false);
                // Don't null-out m_hPort here — DisconnectFilterPort handles that.
                // Just sleep and let reconnect logic handle it.
                std::shared_lock lock(m_impl->configMutex);
                if (m_impl->config.autoReconnect && m_running.load()) {
                    lock.unlock();
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(m_impl->config.reconnectDelayMs));
                }
                continue;
            }

            if (hr != HRESULT_FROM_WIN32(ERROR_SEM_TIMEOUT)) {
                Utils::Logger::Warn("[IPCManager] FilterGetMessage failed: 0x{:08X}",
                                    static_cast<unsigned int>(hr));
                m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
            }
            continue;
        }

        // FIX [BUG #1,#2]: Proper two-header parsing.
        // After FILTER_MESSAGE_HEADER comes SHADOWSTRIKE_MESSAGE_HEADER + payload.
        constexpr size_t kWdkHeaderSize = sizeof(FILTER_MESSAGE_HEADER);
        constexpr size_t kAppHeaderSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);

        if (buffer.size() < kWdkHeaderSize + kAppHeaderSize) {
            Utils::Logger::Error("[IPCManager] Buffer too small for dual-header parse");
            continue;
        }

        auto* pAppHeader = reinterpret_cast<PSHADOWSTRIKE_MESSAGE_HEADER>(
            buffer.data() + kWdkHeaderSize);

        // Validate magic
        if (pAppHeader->Magic != SHADOWSTRIKE_MESSAGE_MAGIC) {
            Utils::Logger::Warn("[IPCManager] Invalid message magic: 0x{:08X}",
                                pAppHeader->Magic);
            m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        m_impl->stats.messagesReceived.fetch_add(1, std::memory_order_relaxed);
        m_impl->stats.bytesReceived.fetch_add(
            kAppHeaderSize + pAppHeader->DataSize, std::memory_order_relaxed);

        // Dispatch with WDK MessageId (needed for FilterReplyMessage)
        DispatchMessage(buffer.data(), pWdkHeader->MessageId);
    }

    Utils::Logger::Debug("[IPCManager] Worker thread {} exiting",
                         std::this_thread::get_id());
}

void IPCManager::DispatchMessage(uint8_t* buffer, uint64_t messageId) {
    if (!buffer) return;

    // FIX [BUG #1,#2,#3,#5]: Parse two-header wire format correctly.
    // buffer layout: [FILTER_MESSAGE_HEADER (WDK)] [SHADOWSTRIKE_MESSAGE_HEADER] [payload]
    constexpr size_t kWdkHeaderSize = sizeof(FILTER_MESSAGE_HEADER);
    constexpr size_t kAppHeaderSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);

    auto* pAppHeader = reinterpret_cast<PSHADOWSTRIKE_MESSAGE_HEADER>(
        buffer + kWdkHeaderSize);
    uint8_t* pPayload = buffer + kWdkHeaderSize + kAppHeaderSize;

    SHADOWSTRIKE_SCAN_VERDICT verdict = Verdict_Unknown;
    bool needsReply = false;

    // FIX [BUG #14]: Snapshot handlers under lock, invoke outside lock.
    // Holding the mutex during file scan I/O would serialize all worker threads.
    FileScanCallback fileScanHandler;
    ProcessNotifyCallback processHandler;
    ImageLoadCallback imageLoadHandler;
    RegistryOpCallback registryHandler;
    GenericMessageCallback genericHandler;

    {
        std::lock_guard lock(m_handlerMutex);
        fileScanHandler  = m_fileScanHandler;
        processHandler   = m_processHandler;
        imageLoadHandler = m_imageLoadHandler;
        registryHandler  = m_registryHandler;
        genericHandler   = m_genericHandler;
    }

    switch (static_cast<SHADOWSTRIKE_MESSAGE_TYPE>(pAppHeader->MessageType)) {
        case FilterMessageType_ScanRequest: {
            if (fileScanHandler) {
                if (pAppHeader->DataSize < sizeof(FILE_SCAN_REQUEST)) {
                    Utils::Logger::Error("[IPCManager] Truncated FileScanRequest: {} < {}",
                                         pAppHeader->DataSize, sizeof(FILE_SCAN_REQUEST));
                    break;
                }

                auto* req = reinterpret_cast<PFILE_SCAN_REQUEST>(pPayload);
                try {
                    verdict = fileScanHandler(*req);
                    needsReply = true;
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] File scan handler exception: {}", e.what());
                    verdict = Verdict_Error;
                    needsReply = true;
                }
            }

            auto idx = static_cast<size_t>(FilterMessageType_ScanRequest);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        case FilterMessageType_ProcessNotify: {
            if (processHandler) {
                if (pAppHeader->DataSize < sizeof(ProcessNotifyRequest)) {
                    Utils::Logger::Error("[IPCManager] Truncated ProcessNotify payload");
                    break;
                }
                auto* req = reinterpret_cast<ProcessNotifyRequest*>(pPayload);
                try {
                    verdict = processHandler(*req);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] Process handler exception: {}", e.what());
                }
            }
            break;
        }

        case FilterMessageType_Register:
        case FilterMessageType_Heartbeat:
            break;

        default:
            if (genericHandler) {
                try {
                    genericHandler(
                        static_cast<SHADOWSTRIKE_MESSAGE_TYPE>(pAppHeader->MessageType),
                        pPayload,
                        pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] Generic handler exception: {}", e.what());
                }
            } else {
                Utils::Logger::Warn("[IPCManager] Unhandled message type: {}",
                                    pAppHeader->MessageType);
            }
            break;
    }

    // FIX [BUG #1 CRITICAL]: Reply using FilterReplyMessage, NOT FilterSendMessage.
    // The kernel's FltSendMessage is BLOCKING until we call FilterReplyMessage.
    if (needsReply) {
        SHADOWSTRIKE_SCAN_VERDICT_REPLY verdictReply = {};
        verdictReply.MessageId  = pAppHeader->MessageId;
        verdictReply.Verdict    = static_cast<UINT8>(verdict);
        verdictReply.ThreatScore = (verdict == Verdict_Malicious) ? 100 : 0;
        verdictReply.ResultCode = 0;
        verdictReply.CacheResult = (verdict == Verdict_Clean) ? 1 : 0;
        verdictReply.CacheTTL   = (verdict == Verdict_Clean) ? 300 : 0;

        if (!ReplyToKernel(messageId, verdictReply)) {
            Utils::Logger::Error("[IPCManager] Failed to reply to kernel for messageId {}",
                                 messageId);
        }

        auto vIdx = static_cast<size_t>(verdict);
        if (vIdx < m_impl->stats.byVerdict.size()) {
            m_impl->stats.byVerdict[vIdx].fetch_add(1, std::memory_order_relaxed);
        }
    }
}

bool IPCManager::ReplyToKernel(
    uint64_t messageId,
    const SHADOWSTRIKE_SCAN_VERDICT_REPLY& verdictReply) {

    HANDLE hPort = m_hPort.load(std::memory_order_acquire);
    if (hPort == nullptr) {
        Utils::Logger::Error("[IPCManager] ReplyToKernel: not connected");
        return false;
    }

    // Wire format: [FILTER_REPLY_HEADER (WDK)] [SHADOWSTRIKE_SCAN_VERDICT_REPLY]
    struct alignas(8) ReplyBuffer {
        FILTER_REPLY_HEADER  wdkHeader;
        SHADOWSTRIKE_SCAN_VERDICT_REPLY payload;
    };

    ReplyBuffer replyBuf = {};
    replyBuf.wdkHeader.Status    = 0;  // STATUS_SUCCESS
    replyBuf.wdkHeader.MessageId = messageId;
    replyBuf.payload = verdictReply;

    HRESULT hr = FilterReplyMessage(
        hPort,
        &replyBuf.wdkHeader,
        static_cast<DWORD>(sizeof(replyBuf))
    );

    if (FAILED(hr)) {
        Utils::Logger::Error("[IPCManager] FilterReplyMessage failed: 0x{:08X} for msgId {}",
                             static_cast<unsigned int>(hr), messageId);
        m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    return true;
}

// ============================================================================
// SELF TEST
// ============================================================================

bool IPCManager::SelfTest() {
    Utils::Logger::Info("[IPCManager] Running self-test...");
    bool allPassed = true;
    int testNum = 0;

    // Test 1: Configuration validation
    testNum++;
    {
        IPCConfiguration config;
        if (!config.IsValid()) {
            Utils::Logger::Error("[IPCManager] Test {} FAILED: Default config invalid", testNum);
            allPassed = false;
        } else {
            Utils::Logger::Debug("[IPCManager] Test {} PASSED: Config validation", testNum);
        }
    }

    // Test 2: Buffer pool allocation
    testNum++;
    {
        try {
            auto& buffer1 = m_impl->GetBuffer();
            auto& buffer2 = m_impl->GetBuffer();

            if (buffer1.size() < IPCConstants::MAX_MESSAGE_SIZE ||
                buffer2.size() < IPCConstants::MAX_MESSAGE_SIZE) {
                Utils::Logger::Error("[IPCManager] Test {} FAILED: Buffer size incorrect", testNum);
                allPassed = false;
            } else {
                Utils::Logger::Debug("[IPCManager] Test {} PASSED: Buffer pool", testNum);
            }
        } catch (...) {
            Utils::Logger::Error("[IPCManager] Test {} FAILED: Buffer pool exception", testNum);
            allPassed = false;
        }
    }

    // Test 3: Message ID generation (monotonically increasing)
    testNum++;
    {
        uint64_t id1 = m_impl->GenerateMessageId();
        uint64_t id2 = m_impl->GenerateMessageId();
        uint64_t id3 = m_impl->GenerateMessageId();

        if (id1 >= id2 || id2 >= id3) {
            Utils::Logger::Error("[IPCManager] Test {} FAILED: Message IDs not increasing", testNum);
            allPassed = false;
        } else {
            Utils::Logger::Debug("[IPCManager] Test {} PASSED: Message ID generation", testNum);
        }
    }

    // Test 4: Statistics reset
    testNum++;
    {
        m_impl->stats.messagesReceived = 100;
        m_impl->stats.Reset();
        if (m_impl->stats.messagesReceived.load() != 0) {
            Utils::Logger::Error("[IPCManager] Test {} FAILED: Stats not reset", testNum);
            allPassed = false;
        } else {
            Utils::Logger::Debug("[IPCManager] Test {} PASSED: Statistics reset", testNum);
        }
    }

    // Test 5: Enum name lookups
    testNum++;
    {
        auto cmdName = GetMessageTypeName(FilterMessageType_ScanRequest);
        auto verdictName = GetVerdictName(Verdict_Malicious);

        if (cmdName.empty() || verdictName.empty()) {
            Utils::Logger::Error("[IPCManager] Test {} FAILED: Enum name lookup", testNum);
            allPassed = false;
        } else {
            Utils::Logger::Debug("[IPCManager] Test {} PASSED: Enum name lookup", testNum);
        }
    }

    if (allPassed) {
        Utils::Logger::Info("[IPCManager] Self-test PASSED ({} tests)", testNum);
    } else {
        Utils::Logger::Error("[IPCManager] Self-test FAILED");
    }

    return allPassed;
}

std::string IPCManager::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << IPCConstants::VERSION_MAJOR << "."
        << IPCConstants::VERSION_MINOR << "."
        << IPCConstants::VERSION_PATCH;
    return oss.str();
}

// ============================================================================
// HELPER STRUCTURE IMPLEMENTATIONS
// ============================================================================

bool IPCConfiguration::IsValid() const noexcept {
    if (filterPortName.empty()) {
        return false;
    }
    if (workerThreadCount == 0 || workerThreadCount > 64) {
        return false;
    }
    if (maxQueueDepth == 0 || maxQueueDepth > 1000000) {
        return false;
    }
    if (replyTimeoutMs == 0 || replyTimeoutMs > 300000) {  // Max 5 minutes
        return false;
    }
    return true;
}

void IPCStatistics::Reset() noexcept {
    messagesReceived.store(0, std::memory_order_relaxed);
    messagesSent.store(0, std::memory_order_relaxed);
    messagesDropped.store(0, std::memory_order_relaxed);
    bytesReceived.store(0, std::memory_order_relaxed);
    bytesSent.store(0, std::memory_order_relaxed);
    timeouts.store(0, std::memory_order_relaxed);
    errors.store(0, std::memory_order_relaxed);
    reconnects.store(0, std::memory_order_relaxed);
    avgLatencyUs.store(0, std::memory_order_relaxed);
    maxLatencyUs.store(0, std::memory_order_relaxed);

    for (auto& counter : byMessageType) {
        counter.store(0, std::memory_order_relaxed);
    }
    for (auto& counter : byVerdict) {
        counter.store(0, std::memory_order_relaxed);
    }

    startTime = Clock::now();
}

std::string IPCStatistics::ToJson() const {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();

    std::ostringstream oss;
    oss << "{"
        << "\"uptimeSeconds\":" << uptime << ","
        << "\"messagesReceived\":" << messagesReceived.load() << ","
        << "\"messagesSent\":" << messagesSent.load() << ","
        << "\"messagesDropped\":" << messagesDropped.load() << ","
        << "\"bytesReceived\":" << bytesReceived.load() << ","
        << "\"bytesSent\":" << bytesSent.load() << ","
        << "\"timeouts\":" << timeouts.load() << ","
        << "\"errors\":" << errors.load() << ","
        << "\"reconnects\":" << reconnects.load() << ","
        << "\"avgLatencyUs\":" << avgLatencyUs.load() << ","
        << "\"maxLatencyUs\":" << maxLatencyUs.load()
        << "}";
    return oss.str();
}

std::string IPCStatisticsSnapshot::ToJson() const {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();

    std::ostringstream oss;
    oss << "{"
        << "\"uptimeSeconds\":" << uptime << ","
        << "\"messagesReceived\":" << messagesReceived << ","
        << "\"messagesSent\":" << messagesSent << ","
        << "\"messagesDropped\":" << messagesDropped << ","
        << "\"bytesReceived\":" << bytesReceived << ","
        << "\"bytesSent\":" << bytesSent << ","
        << "\"timeouts\":" << timeouts << ","
        << "\"errors\":" << errors << ","
        << "\"reconnects\":" << reconnects << ","
        << "\"avgLatencyUs\":" << avgLatencyUs << ","
        << "\"maxLatencyUs\":" << maxLatencyUs
        << "}";
    return oss.str();
}

std::string ConnectionInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"channelType\":\"" << GetChannelTypeName(channelType) << "\","
        << "\"status\":\"" << GetConnectionStatusName(status) << "\","
        << "\"endpoint\":\"" << Utils::StringUtils::WideToUtf8(endpoint) << "\","
        << "\"messagesReceived\":" << messagesReceived << ","
        << "\"messagesSent\":" << messagesSent << ","
        << "\"bytesReceived\":" << bytesReceived << ","
        << "\"bytesSent\":" << bytesSent << ","
        << "\"reconnectCount\":" << reconnectCount
        << "}";
    return oss.str();
}

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

std::string_view GetMessageTypeName(SHADOWSTRIKE_MESSAGE_TYPE type) noexcept {
    switch (type) {
        case FilterMessageType_None:          return "None";
        case FilterMessageType_Register:      return "Register";
        case FilterMessageType_Unregister:    return "Unregister";
        case FilterMessageType_Heartbeat:     return "Heartbeat";
        case FilterMessageType_ScanRequest:   return "ScanRequest";
        case FilterMessageType_ScanVerdict:   return "ScanVerdict";
        case FilterMessageType_ConfigUpdate:  return "ConfigUpdate";
        case FilterMessageType_ProcessNotify: return "ProcessNotify";
        case FilterMessageType_ThreadNotify:  return "ThreadNotify";
        case FilterMessageType_ImageLoad:     return "ImageLoad";
        case FilterMessageType_RegistryNotify:return "RegistryNotify";
        case FilterMessageType_BehavioralAlert: return "BehavioralAlert";
        case FilterMessageType_MemoryAlert:   return "MemoryAlert";
        case FilterMessageType_NetworkAlert:  return "NetworkAlert";
        case FilterMessageType_HandleAlert:   return "HandleAlert";
        case FilterMessageType_RansomwareAlert: return "RansomwareAlert";
        default: return "Unknown";
    }
}

std::string_view GetVerdictName(SHADOWSTRIKE_SCAN_VERDICT verdict) noexcept {
    switch (verdict) {
        case Verdict_Unknown: return "Unknown";
        case Verdict_Clean: return "Clean";
        case Verdict_Malicious: return "Malicious";
        case Verdict_Suspicious: return "Suspicious";
        case Verdict_Error: return "Error";
        case Verdict_Timeout: return "Timeout";
        default: return "Invalid";
    }
}

std::string_view GetChannelTypeName(ChannelType type) noexcept {
    switch (type) {
        case ChannelType::FilterPort:   return "FilterPort";
        case ChannelType::NamedPipe:    return "NamedPipe";
        case ChannelType::SharedMemory: return "SharedMemory";
        case ChannelType::LocalSocket:  return "LocalSocket";
        default:                        return "Unknown";
    }
}

std::string_view GetConnectionStatusName(ConnectionStatus status) noexcept {
    switch (status) {
        case ConnectionStatus::Disconnected:    return "Disconnected";
        case ConnectionStatus::Connecting:      return "Connecting";
        case ConnectionStatus::Connected:       return "Connected";
        case ConnectionStatus::Authenticating:  return "Authenticating";
        case ConnectionStatus::Ready:           return "Ready";
        case ConnectionStatus::Reconnecting:    return "Reconnecting";
        case ConnectionStatus::Error:           return "Error";
        default:                                return "Unknown";
    }
}

bool CreateSecurePipeDacl(SECURITY_ATTRIBUTES& sa) {
    // FIX [BUG #10 CRITICAL]: NULL DACL = Everyone full access.
    // Build proper DACL: SYSTEM + Administrators only.
    //
    // SDDL string breakdown:
    //   D:P         — DACL present, protected (no inheritance)
    //   (A;;GA;;;SY) — Allow GENERIC_ALL to SYSTEM
    //   (A;;GA;;;BA) — Allow GENERIC_ALL to Built-in Administrators
    PSECURITY_DESCRIPTOR pSD = nullptr;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
            SDDL_REVISION_1,
            &pSD,
            nullptr)) {
        Utils::Logger::Error("[IPCManager] ConvertStringSecurityDescriptor failed: {}",
                             GetLastError());
        return false;
    }

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    return true;
}

bool VerifyDriverSignature(const std::wstring& driverPath) {
    if (driverPath.empty()) {
        return false;
    }

    // FIX [BUG #11 CRITICAL]: Stub always returned true — complete security bypass.
    // Implement real Authenticode verification via WinVerifyTrust.

    GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct      = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = driverPath.c_str();
    fileInfo.hFile         = nullptr;
    fileInfo.pgKnownSubject= nullptr;

    WINTRUST_DATA trustData = {};
    trustData.cbStruct            = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = nullptr;
    trustData.pSIPClientData      = nullptr;
    trustData.dwUIChoice          = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice       = WTD_CHOICE_FILE;
    trustData.pFile               = &fileInfo;
    trustData.dwStateAction       = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData       = nullptr;
    trustData.dwProvFlags         = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG status = WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &actionId,
        &trustData
    );

    // Clean up state
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &actionId,
        &trustData
    );

    if (status != ERROR_SUCCESS) {
        Utils::Logger::Error("[IPCManager] Driver signature verification FAILED "
                             "for '{}': WinVerifyTrust returned 0x{:08X}",
                             Utils::StringUtils::WideToUtf8(driverPath),
                             static_cast<unsigned long>(status));
        return false;
    }

    Utils::Logger::Info("[IPCManager] Driver signature verified: {}",
                        Utils::StringUtils::WideToUtf8(driverPath));
    return true;
}

}  // namespace Communication
}  // namespace ShadowStrike
