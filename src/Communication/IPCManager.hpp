/**
 * ============================================================================
 * ShadowStrike NGAV - IPC MANAGER MODULE
 * ============================================================================
 *
 * @file IPCManager.hpp
 * @brief Enterprise-grade inter-process communication between kernel minifilter
 *        driver and user-mode services with zero-copy design and IOCP.
 *
 * Manages high-performance bidirectional communication between Ring 0 kernel
 * components and Ring 3 user-mode services using Windows Filter Manager.
 *
 * ARCHITECTURE POSITION:
 * ======================
 *
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                  Kernel Minifilter Driver                    │
 *   │            (Intercepts File I/O, Process Create)             │
 *   └──────────────────────────┬──────────────────────────────────┘
 *                              │ (FltSendMessage)
 *                              ▼
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                     IPC MANAGER                              │ ◄── YOU ARE HERE
 *   │       (Worker Threads, Message Dispatcher, IOCP)             │
 *   └──────────────────────────┬──────────────────────────────────┘
 *                              │ (Callbacks)
 *                              ▼
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                 RealTimeProtection Module                    │
 *   │           (Calls ScanEngine -> Returns Verdict)              │
 *   └─────────────────────────────────────────────────────────────┘
 *
 * IPC CAPABILITIES:
 * =================
 *
 * 1. FILTER COMMUNICATION PORT
 *    - Kernel-user messaging
 *    - Synchronous operations
 *    - Asynchronous operations
 *    - Large buffer support
 *    - Connection management
 *
 * 2. NAMED PIPES
 *    - Service-GUI communication
 *    - Secure pipe creation
 *    - Access control
 *    - Message framing
 *
 * 3. SHARED MEMORY
 *    - Zero-copy transfers
 *    - Ring buffers
 *    - Event signaling
 *    - Memory mapping
 *
 * 4. WORKER POOL
 *    - IOCP-based dispatch
 *    - Thread affinity
 *    - Priority management
 *    - Load balancing
 *
 * 5. MESSAGE HANDLING
 *    - Command dispatching
 *    - Reply management
 *    - Timeout handling
 *    - Error recovery
 *
 * PERFORMANCE REQUIREMENTS:
 * =========================
 * - Zero-copy where possible
 * - Handle 10000+ events/sec
 * - Sub-millisecond latency
 * - No blocking operations
 *
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <queue>
#include <optional>
#include <memory>
#include <functional>
#include <span>
#include <variant>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <condition_variable>
#include <future>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  include <fltUser.h>  // Filter Communication Port API
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"

#include "../../Drivers/Shared/MessageProtocol.h"
#include "../../Drivers/Shared/MessageTypes.h"
#include "../../Drivers/Shared/VerdictTypes.h"
#include "../../Drivers/Shared/PortName.h"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Communication {
    class IPCManagerImpl;
}

namespace ShadowStrike {
namespace Communication {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace IPCConstants {

    inline constexpr uint32_t VERSION_MAJOR = 2;
    inline constexpr uint32_t VERSION_MINOR = 1;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Filter port name
    inline constexpr const wchar_t* FILTER_PORT_NAME = L"\\ShadowStrikePort";
    
    /// @brief Named pipe name (Service-GUI)
    inline constexpr const wchar_t* SERVICE_PIPE_NAME = L"\\\\.\\pipe\\ShadowStrikeService";
    
    /// @brief Maximum message size
    inline constexpr size_t MAX_MESSAGE_SIZE = 65536;
    
    /// @brief Default worker thread count
    inline constexpr uint32_t DEFAULT_WORKER_COUNT = 8;
    
    /// @brief Maximum queue depth
    inline constexpr size_t MAX_QUEUE_DEPTH = 10000;
    
    /// @brief Reply timeout (ms)
    inline constexpr uint32_t REPLY_TIMEOUT_MS = 5000;
    
    /// @brief Heartbeat interval (ms)
    inline constexpr uint32_t HEARTBEAT_INTERVAL_MS = 10000;
    
    /// @brief Reconnect delay (ms)
    inline constexpr uint32_t RECONNECT_DELAY_MS = 1000;
    
    /// @brief Shared memory size
    inline constexpr size_t SHARED_MEMORY_SIZE = 64 * 1024 * 1024;  // 64 MB

}  // namespace IPCConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Command type from kernel
 */
// enum class CommandType replaced by SHADOWSTRIKE_MESSAGE_TYPE from shared headers

/**
 * @brief Verdict sent back to kernel
 */
// enum class KernelVerdict replaced by SHADOWSTRIKE_SCAN_VERDICT from shared headers

/**
 * @brief IPC channel type
 */
enum class ChannelType : uint8_t {
    FilterPort      = 0,        ///< Kernel filter port
    NamedPipe       = 1,        ///< Named pipe
    SharedMemory    = 2,        ///< Shared memory
    LocalSocket     = 3         ///< Local socket
};

/**
 * @brief Connection status
 */
enum class ConnectionStatus : uint8_t {
    Disconnected    = 0,
    Connecting      = 1,
    Connected       = 2,
    Authenticating  = 3,
    Ready           = 4,
    Reconnecting    = 5,
    Error           = 6
};

/**
 * @brief Message priority
 */
enum class MessagePriority : uint8_t {
    Low             = 0,
    Normal          = 1,
    High            = 2,
    Critical        = 3
};

/**
 * @brief Module status
 */
enum class IPCStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Paused          = 3,
    Stopping        = 4,
    Stopped         = 5,
    Error           = 6
};

// ============================================================================
// PACKED STRUCTURES (Kernel-User Protocol)
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief Kernel request header
 */
// struct KernelRequestHeader replaced by FILTER_MESSAGE_HEADER

/**
 * @brief File scan request
 */
// struct FileScanRequest replaced by FILE_SCAN_REQUEST

/**
 * @brief Process notification request
 */
struct ProcessNotifyRequest {
    /// @brief Header
    FILTER_MESSAGE_HEADER header;
    
    /// @brief Parent process ID
    uint32_t parentProcessId;
    
    /// @brief Creating process ID
    uint32_t creatingProcessId;
    
    /// @brief Creating thread ID
    uint32_t creatingThreadId;
    
    /// @brief Session ID
    uint32_t sessionId;
    
    /// @brief Token info
    uint64_t tokenHandle;
    
    /// @brief Is WoW64
    uint8_t isWow64;
    
    /// @brief Reserved
    uint8_t reserved[3];
    
    /// @brief Image path length
    uint16_t imagePathLength;
    
    /// @brief Command line length
    uint16_t commandLineLength;
    
    /// @brief Image path
    wchar_t imagePath[260];
    
    /// @brief Command line (follows image path in actual buffer)
    wchar_t commandLine[512];
};

/**
 * @brief Image load notification
 */
struct ImageLoadRequest {
    /// @brief Header
    FILTER_MESSAGE_HEADER header;
    
    /// @brief Process ID
    uint32_t processId;
    
    /// @brief Image base address
    uint64_t imageBase;
    
    /// @brief Image size
    uint64_t imageSize;
    
    /// @brief Is system module
    uint8_t isSystemModule;
    
    /// @brief Reserved
    uint8_t reserved[3];
    
    /// @brief Image path length
    uint16_t imagePathLength;
    
    /// @brief Image path
    wchar_t imagePath[260];
};

/**
 * @brief Registry operation request
 */
struct RegistryOpRequest {
    /// @brief Header
    FILTER_MESSAGE_HEADER header;
    
    /// @brief Operation type
    uint32_t operationType;
    
    /// @brief Key handle
    uint64_t keyHandle;
    
    /// @brief Key path length
    uint16_t keyPathLength;
    
    /// @brief Value name length
    uint16_t valueNameLength;
    
    /// @brief Value type
    uint32_t valueType;
    
    /// @brief Data length
    uint32_t dataLength;
    
    /// @brief Key path
    wchar_t keyPath[260];
    
    /// @brief Value name
    wchar_t valueName[128];
};

/**
 * @brief Kernel reply
 */
// struct KernelReply replaced by SCAN_VERDICT_REPLY

#pragma pack(pop)

// ============================================================================
// NON-PACKED STRUCTURES
// ============================================================================

/**
 * @brief Connection info
 */
struct ConnectionInfo {
    /// @brief Channel type
    ChannelType channelType = ChannelType::FilterPort;
    
    /// @brief Status
    ConnectionStatus status = ConnectionStatus::Disconnected;
    
    /// @brief Remote endpoint
    std::wstring endpoint;
    
    /// @brief Connected time
    std::optional<SystemTimePoint> connectedTime;
    
    /// @brief Last activity time
    TimePoint lastActivity;
    
    /// @brief Messages received
    uint64_t messagesReceived = 0;
    
    /// @brief Messages sent
    uint64_t messagesSent = 0;
    
    /// @brief Bytes received
    uint64_t bytesReceived = 0;
    
    /// @brief Bytes sent
    uint64_t bytesSent = 0;
    
    /// @brief Reconnect count
    uint32_t reconnectCount = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Pending message
 */
struct PendingMessage {
    /// @brief Message ID
    uint64_t messageId = 0;
    
    /// @brief Command type
    SHADOWSTRIKE_MESSAGE_TYPE command = MessageType_None;
    
    /// @brief Queued time
    TimePoint queuedTime;
    
    /// @brief Timeout time
    TimePoint timeoutTime;
    
    /// @brief Priority
    MessagePriority priority = MessagePriority::Normal;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Context data
    std::vector<uint8_t> contextData;
};

/**
 * @brief Shared memory region
 */
struct SharedMemoryRegion {
    /// @brief Region name
    std::wstring name;
    
    /// @brief Base address
    void* baseAddress = nullptr;
    
    /// @brief Size
    size_t size = 0;
    
    /// @brief Is writable
    bool isWritable = false;
    
    /// @brief File mapping handle
    HANDLE mappingHandle = nullptr;
    
    /// @brief Event handle (for signaling)
    HANDLE eventHandle = nullptr;
};

/**
 * @brief Statistics
 */
struct IPCStatistics {
    std::atomic<uint64_t> messagesReceived{0};
    std::atomic<uint64_t> messagesSent{0};
    std::atomic<uint64_t> messagesDropped{0};
    std::atomic<uint64_t> bytesReceived{0};
    std::atomic<uint64_t> bytesSent{0};
    std::atomic<uint64_t> timeouts{0};
    std::atomic<uint64_t> errors{0};
    std::atomic<uint64_t> reconnects{0};
    std::atomic<uint64_t> avgLatencyUs{0};
    std::atomic<uint64_t> maxLatencyUs{0};
    std::array<std::atomic<uint64_t>, 16> bySHADOWSTRIKE_MESSAGE_TYPE{};
    std::array<std::atomic<uint64_t>, 8> byVerdict{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct IPCConfiguration {
    /// @brief Enable filter port
    bool enableFilterPort = true;
    
    /// @brief Enable named pipes
    bool enableNamedPipes = true;
    
    /// @brief Enable shared memory
    bool enableSharedMemory = true;
    
    /// @brief Filter port name
    std::wstring filterPortName = IPCConstants::FILTER_PORT_NAME;
    
    /// @brief Service pipe name
    std::wstring servicePipeName = IPCConstants::SERVICE_PIPE_NAME;
    
    /// @brief Worker thread count
    uint32_t workerThreadCount = IPCConstants::DEFAULT_WORKER_COUNT;
    
    /// @brief Max queue depth
    size_t maxQueueDepth = IPCConstants::MAX_QUEUE_DEPTH;
    
    /// @brief Reply timeout (ms)
    uint32_t replyTimeoutMs = IPCConstants::REPLY_TIMEOUT_MS;
    
    /// @brief Heartbeat interval (ms)
    uint32_t heartbeatIntervalMs = IPCConstants::HEARTBEAT_INTERVAL_MS;
    
    /// @brief Auto-reconnect
    bool autoReconnect = true;
    
    /// @brief Reconnect delay (ms)
    uint32_t reconnectDelayMs = IPCConstants::RECONNECT_DELAY_MS;
    
    /// @brief Max reconnect attempts
    uint32_t maxReconnectAttempts = 10;
    
    /// @brief Shared memory size
    size_t sharedMemorySize = IPCConstants::SHARED_MEMORY_SIZE;
    
    /// @brief Use IOCP
    bool useIOCP = true;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using FileScanCallback = std::function<SHADOWSTRIKE_SCAN_VERDICT(const FILE_SCAN_REQUEST&)>;
using ProcessNotifyCallback = std::function<SHADOWSTRIKE_SCAN_VERDICT(const ProcessNotifyRequest&)>;
using ImageLoadCallback = std::function<SHADOWSTRIKE_SCAN_VERDICT(const ImageLoadRequest&)>;
using RegistryOpCallback = std::function<SHADOWSTRIKE_SCAN_VERDICT(const RegistryOpRequest&)>;
using GenericMessageCallback = std::function<void(SHADOWSTRIKE_MESSAGE_TYPE, const void*, size_t)>;
using ConnectionCallback = std::function<void(ChannelType, ConnectionStatus)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// IPC MANAGER CLASS
// ============================================================================

/**
 * @class IPCManager
 * @brief Enterprise inter-process communication
 */
class IPCManager final {
public:
    [[nodiscard]] static IPCManager& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    IPCManager(const IPCManager&) = delete;
    IPCManager& operator=(const IPCManager&) = delete;
    IPCManager(IPCManager&&) = delete;
    IPCManager& operator=(IPCManager&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const IPCConfiguration& config = {});
    [[nodiscard]] bool Start(uint32_t workerThreadCount = std::thread::hardware_concurrency());
    void Stop();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] bool IsConnected() const noexcept;
    [[nodiscard]] IPCStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const IPCConfiguration& config);
    [[nodiscard]] IPCConfiguration GetConfiguration() const;

    // ========================================================================
    // FILTER PORT OPERATIONS
    // ========================================================================
    
    /// @brief Connect to kernel filter port
    [[nodiscard]] bool ConnectFilterPort();
    
    /// @brief Disconnect from filter port
    void DisconnectFilterPort();
    
    /// @brief Check filter port connection
    [[nodiscard]] bool IsFilterPortConnected() const noexcept;
    
    /// @brief Send message to kernel
    [[nodiscard]] bool SendToKernel(
        const void* message,
        size_t messageSize,
        void* reply = nullptr,
        size_t* replySize = nullptr,
        uint32_t timeoutMs = IPCConstants::REPLY_TIMEOUT_MS);

    // ========================================================================
    // NAMED PIPE OPERATIONS
    // ========================================================================
    
    /// @brief Create named pipe server
    [[nodiscard]] bool CreatePipeServer(const std::wstring& pipeName = IPCConstants::SERVICE_PIPE_NAME);
    
    /// @brief Connect to pipe server
    [[nodiscard]] bool ConnectToPipe(const std::wstring& pipeName = IPCConstants::SERVICE_PIPE_NAME);
    
    /// @brief Disconnect pipe
    void DisconnectPipe();
    
    /// @brief Send through pipe
    [[nodiscard]] bool SendPipeMessage(const void* data, size_t size);
    
    /// @brief Send command string
    void SendCommand(const std::string& cmd);

    // ========================================================================
    // SHARED MEMORY OPERATIONS
    // ========================================================================
    
    /// @brief Create shared memory region
    [[nodiscard]] bool CreateSharedMemory(
        const std::wstring& name,
        size_t size,
        bool writable = true);
    
    /// @brief Open existing shared memory
    [[nodiscard]] bool OpenSharedMemory(
        const std::wstring& name,
        bool writable = false);
    
    /// @brief Get shared memory pointer
    [[nodiscard]] void* GetSharedMemoryPtr(const std::wstring& name);
    
    /// @brief Signal shared memory event
    void SignalSharedMemory(const std::wstring& name);
    
    /// @brief Wait for shared memory event
    [[nodiscard]] bool WaitSharedMemory(const std::wstring& name, uint32_t timeoutMs);
    
    /// @brief Close shared memory
    void CloseSharedMemory(const std::wstring& name);

    // ========================================================================
    // HANDLER REGISTRATION
    // ========================================================================
    
    /// @brief Register file scan handler
    void RegisterFileScanHandler(FileScanCallback handler);
    
    /// @brief Register process notification handler
    void RegisterProcessHandler(ProcessNotifyCallback handler);
    
    /// @brief Register image load handler
    void RegisterImageLoadHandler(ImageLoadCallback handler);
    
    /// @brief Register registry operation handler
    void RegisterRegistryHandler(RegistryOpCallback handler);
    
    /// @brief Register generic message handler
    void RegisterGenericHandler(GenericMessageCallback handler);
    
    /// @brief Set message callback (for pipe messages)
    void SetMessageCallback(std::function<void(const std::string&)> cb);
    
    /// @brief Unregister all handlers
    void UnregisterHandlers();

    // ========================================================================
    // CONNECTION MANAGEMENT
    // ========================================================================
    
    /// @brief Get connection info
    [[nodiscard]] ConnectionInfo GetConnectionInfo(ChannelType channel) const;
    
    /// @brief Get all connections
    [[nodiscard]] std::vector<ConnectionInfo> GetAllConnections() const;
    
    /// @brief Force reconnect
    void Reconnect(ChannelType channel);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterConnectionCallback(ConnectionCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] IPCStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    IPCManager();
    ~IPCManager();
    
    /// @brief Worker thread routine
    void WorkerRoutine();
    
    /// @brief Dispatch message to handler
    void DispatchMessage(uint8_t* buffer, uint64_t messageId);
    
    std::unique_ptr<IPCManagerImpl> m_impl;
    
    // Core handles
    HANDLE m_hPort = nullptr;
    HANDLE m_hPipe = nullptr;
    HANDLE m_hIOCP = nullptr;
    
    // State
    std::atomic<bool> m_connected{false};
    std::atomic<bool> m_running{false};
    std::atomic<IPCStatus> m_status{IPCStatus::Uninitialized};
    
    // Thread pool
    std::vector<std::thread> m_workerThreads;
    
    // Handlers
    FileScanCallback m_fileScanHandler;
    ProcessNotifyCallback m_processHandler;
    ImageLoadCallback m_imageLoadHandler;
    RegistryOpCallback m_registryHandler;
    GenericMessageCallback m_genericHandler;
    std::function<void(const std::string&)> m_messageCallback;
    mutable std::mutex m_handlerMutex;
    
    // Shared memory regions
    std::map<std::wstring, SharedMemoryRegion> m_sharedMemory;
    mutable std::shared_mutex m_sharedMemoryMutex;
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetSHADOWSTRIKE_MESSAGE_TYPEName(SHADOWSTRIKE_MESSAGE_TYPE type) noexcept;
[[nodiscard]] std::string_view GetVerdictName(SHADOWSTRIKE_SCAN_VERDICT verdict) noexcept;
[[nodiscard]] std::string_view GetChannelTypeName(ChannelType type) noexcept;
[[nodiscard]] std::string_view GetConnectionStatusName(ConnectionStatus status) noexcept;

/// @brief Create secure DACL for named pipe
[[nodiscard]] bool CreateSecurePipeDacl(SECURITY_ATTRIBUTES& sa);

/// @brief Verify driver signature
[[nodiscard]] bool VerifyDriverSignature(const std::wstring& driverPath);

}  // namespace Communication
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_IPC_SEND_VERDICT(msgId, verdict) \
    ::ShadowStrike::Communication::IPCManager::Instance().SendToKernel( \
        &(verdict), sizeof(verdict), nullptr, nullptr, 0)

#define SS_IPC_IS_CONNECTED() \
    ::ShadowStrike::Communication::IPCManager::Instance().IsConnected()
