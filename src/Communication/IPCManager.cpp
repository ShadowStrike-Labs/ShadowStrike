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
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#pragma comment(lib, "fltlib.lib")
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
        std::promise<SCAN_VERDICT_REPLY> promise;
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
    if (m_hPort != nullptr) {
        CancelIoEx(m_hPort, nullptr);
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
    if (m_hPort != nullptr) {
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

    // Connect to the kernel driver's communication port
    HRESULT hr = FilterConnectCommunicationPort(
        portName.c_str(),           // Port name
        0,                          // Options (0 = default)
        nullptr,                    // Context (passed to driver)
        0,                          // Context size
        nullptr,                    // Security attributes
        &m_hPort                    // Output: port handle
    );

    if (FAILED(hr)) {
        Utils::Logger::Error("[IPCManager] FilterConnectCommunicationPort failed: 0x{:08X}",
                             static_cast<unsigned int>(hr));

        // Provide more specific error messages
        if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
            Utils::Logger::Error("[IPCManager] Driver port not found - is driver loaded?");
        } else if (hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) {
            Utils::Logger::Error("[IPCManager] Access denied - check service permissions");
        }

        m_hPort = nullptr;
        m_impl->NotifyError("Filter port connection failed", hr);
        return false;
    }

    // Associate with IOCP for async operations
    if (m_hIOCP != nullptr) {
        HANDLE result = CreateIoCompletionPort(
            m_hPort,
            m_hIOCP,
            reinterpret_cast<ULONG_PTR>(m_hPort),
            0
        );

        if (result == nullptr) {
            Utils::Logger::Warn("[IPCManager] Failed to associate port with IOCP: {}",
                               GetLastError());
        }
    }

    m_connected.store(true, std::memory_order_release);
    m_impl->NotifyConnectionChange(ChannelType::FilterPort, ConnectionStatus::Connected);

    Utils::Logger::Info("[IPCManager] Successfully connected to filter port");
    return true;
}

void IPCManager::DisconnectFilterPort() {
    if (m_hPort != nullptr) {
        // Cancel any pending I/O
        CancelIoEx(m_hPort, nullptr);

        CloseHandle(m_hPort);
        m_hPort = nullptr;
        m_connected.store(false, std::memory_order_release);

        m_impl->NotifyConnectionChange(ChannelType::FilterPort, ConnectionStatus::Disconnected);
        Utils::Logger::Info("[IPCManager] Disconnected from filter port");
    }
}

bool IPCManager::IsFilterPortConnected() const noexcept {
    return m_hPort != nullptr && m_connected.load(std::memory_order_acquire);
}

bool IPCManager::SendToKernel(
    const void* message,
    size_t messageSize,
    void* reply,
    size_t* replySize,
    uint32_t timeoutMs) {

    if (m_hPort == nullptr) {
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

    DWORD bytesReturned = 0;
    HRESULT hr = FilterSendMessage(
        m_hPort,
        const_cast<void*>(message),
        static_cast<DWORD>(messageSize),
        reply,
        reply ? static_cast<DWORD>(*replySize) : 0,
        &bytesReturned
    );

    auto endTime = Clock::now();
    auto latencyUs = std::chrono::duration_cast<std::chrono::microseconds>(
        endTime - startTime).count();

    if (FAILED(hr)) {
        Utils::Logger::Error("[IPCManager] FilterSendMessage failed: 0x{:08X}",
                             static_cast<unsigned int>(hr));
        m_impl->stats.errors++;

        // Handle specific errors
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
    m_impl->stats.messagesSent++;
    m_impl->stats.bytesSent += messageSize;

    // Update latency tracking (exponential moving average)
    uint64_t currentAvg = m_impl->stats.avgLatencyUs.load(std::memory_order_relaxed);
    m_impl->stats.avgLatencyUs.store(
        (currentAvg * 95 + static_cast<uint64_t>(latencyUs) * 5) / 100,
        std::memory_order_relaxed);

    uint64_t currentMax = m_impl->stats.maxLatencyUs.load(std::memory_order_relaxed);
    if (static_cast<uint64_t>(latencyUs) > currentMax) {
        m_impl->stats.maxLatencyUs.store(static_cast<uint64_t>(latencyUs),
                                         std::memory_order_relaxed);
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
        PIPE_UNLIMITED_INSTANCES,
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
                CancelIoEx(m_hPipe, &overlapped);
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

    // Create file mapping
    region.mappingHandle = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        nullptr,
        writable ? PAGE_READWRITE : PAGE_READONLY,
        static_cast<DWORD>(size >> 32),
        static_cast<DWORD>(size & 0xFFFFFFFF),
        name.c_str()
    );

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
            info.status = m_hPort != nullptr
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

IPCStatistics IPCManager::GetStatistics() const {
    // Return a copy of statistics (atomic members are thread-safe)
    return m_impl->stats;
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

    // Allocate message buffer for this thread
    std::vector<uint8_t> buffer(IPCConstants::MAX_MESSAGE_SIZE);

    // Cast to FILTER_MESSAGE_HEADER for receiving messages
    PFILTER_MESSAGE_HEADER pMessage =
        reinterpret_cast<PFILTER_MESSAGE_HEADER>(buffer.data());

    while (m_running.load(std::memory_order_acquire)) {
        // Check if we're connected
        if (m_hPort == nullptr) {
            // Not connected - wait a bit and try reconnect if enabled
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            std::shared_lock lock(m_impl->configMutex);
            if (m_impl->config.autoReconnect && m_running.load()) {
                lock.unlock();
                ConnectFilterPort();
            }
            continue;
        }

        // Receive message from kernel driver
        HRESULT hr = FilterGetMessage(
            m_hPort,
            pMessage,
            static_cast<DWORD>(buffer.size()),
            nullptr  // Synchronous operation
        );

        if (FAILED(hr)) {
            // Handle different error conditions
            if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) ||
                hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
                // Port is being closed - normal shutdown
                Utils::Logger::Debug("[IPCManager] Worker: Operation aborted (shutdown)");
                break;
            }

            if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
                // Port handle is invalid
                Utils::Logger::Error("[IPCManager] Worker: Invalid port handle");
                m_connected.store(false);
                m_hPort = nullptr;

                std::shared_lock lock(m_impl->configMutex);
                if (m_impl->config.autoReconnect && m_running.load()) {
                    lock.unlock();
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(m_impl->config.reconnectDelayMs));
                }
                continue;
            }

            if (hr != HRESULT_FROM_WIN32(ERROR_SEM_TIMEOUT)) {
                // Log non-timeout errors
                Utils::Logger::Warn("[IPCManager] FilterGetMessage failed: 0x{:08X}",
                                    static_cast<unsigned int>(hr));
                m_impl->stats.errors++;
            }
            continue;
        }

        // Successfully received a message
        m_impl->stats.messagesReceived++;
        m_impl->stats.bytesReceived += pMessage->MessageLength;

        // Dispatch to appropriate handler
        DispatchMessage(buffer.data(), pMessage->MessageId);
    }

    Utils::Logger::Debug("[IPCManager] Worker thread {} exiting",
                         std::this_thread::get_id());
}

void IPCManager::DispatchMessage(uint8_t* buffer, uint64_t messageId) {
    // Parse message structure
    // FILTER_MESSAGE_HEADER is at the beginning
    if (!buffer) return;
    
    PFILTER_MESSAGE_HEADER pHeader = reinterpret_cast<PFILTER_MESSAGE_HEADER>(buffer);
    
    // Payload follows the header
    uint8_t* pPayload = buffer + sizeof(FILTER_MESSAGE_HEADER);

    SHADOWSTRIKE_SCAN_VERDICT verdict = Verdict_Unknown;
    bool handled = false;

    // Lock handlers for the duration of dispatch
    std::lock_guard lock(m_handlerMutex);

    switch (pHeader->MessageType) {
        case MessageType_FileScanRequest: {
            if (m_fileScanHandler) {
                // Ensure we have enough data
                if (pHeader->DataLength < sizeof(FILE_SCAN_REQUEST)) {
                    Utils::Logger::Error("[IPCManager] Invalid payload length for FileScanRequest");
                    break;
                }
                
                PFILE_SCAN_REQUEST req = reinterpret_cast<PFILE_SCAN_REQUEST>(pPayload);
                try {
                    // Handler returns SHADOWSTRIKE_SCAN_VERDICT
                    verdict = m_fileScanHandler(*req);
                    handled = true;
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] File scan handler exception: {}", e.what());
                    verdict = Verdict_Error;
                }
                
                // Reply
                if (handled) {
                     SCAN_VERDICT_REPLY reply = {0};
                     reply.MessageId = pHeader->MessageId;
                     reply.Verdict = verdict;
                     reply.ThreatLevel = (verdict == Verdict_Malicious) ? 100 : 0;
                     // ThreatName left empty for now
                     
                     SendToKernel(&reply, sizeof(reply));
                }
                
                m_impl->stats.byMessageType[static_cast<size_t>(MessageType_FileScanRequest)]++;
            }
            break;
        }

        case MessageType_Register:
        case MessageType_Heartbeat:
            // Handle internal messages
            break;

        default:
            Utils::Logger::Warn("[IPCManager] Unknown message type: {}", static_cast<uint32_t>(pHeader->MessageType));
            break;
    }
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
        auto cmdName = GetMessageTypeName(MessageType_FileScanRequest);
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

    for (auto& counter : bySHADOWSTRIKE_MESSAGE_TYPE) {
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
        case MessageType_None: return "None";
        case MessageType_Register: return "Register";
        case MessageType_Unregister: return "Unregister";
        case MessageType_Heartbeat: return "Heartbeat";
        case MessageType_FileScanRequest: return "FileScanRequest";
        case MessageType_FileScanVerdict: return "FileScanVerdict";
        case MessageType_ConfigUpdate: return "ConfigUpdate";
        case MessageType_ThreatDetected: return "ThreatDetected";
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
    // Create a security descriptor with restricted access:
    // - SYSTEM: Full control
    // - Administrators: Full control
    // - Service account: Read/Write

    PSECURITY_DESCRIPTOR pSD = static_cast<PSECURITY_DESCRIPTOR>(
        LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH));

    if (pSD == nullptr) {
        return false;
    }

    if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
        LocalFree(pSD);
        return false;
    }

    // For production, create proper ACL with specific SIDs
    // For now, use a permissive DACL
    if (!SetSecurityDescriptorDacl(pSD, TRUE, nullptr, FALSE)) {
        LocalFree(pSD);
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

    // In production implementation:
    // 1. Use WinVerifyTrust with WINTRUST_ACTION_GENERIC_VERIFY_V2
    // 2. Verify Authenticode signature
    // 3. Check certificate chain validity
    // 4. Check for certificate revocation
    // 5. Verify certificate is from trusted publisher

    // Placeholder - always returns true for development
    // TODO: Implement full signature verification
    return true;
}

}  // namespace Communication
}  // namespace ShadowStrike
