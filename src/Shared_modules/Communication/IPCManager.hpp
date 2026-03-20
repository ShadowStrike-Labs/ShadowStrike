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

// FIX [BUG #3 CRITICAL]: fltUser.h defines FILTER_MESSAGE_HEADER (WDK version:
// ReplyLength + MessageId, 12 bytes). MessageProtocol.h tries to typedef
// SHADOWSTRIKE_MESSAGE_HEADER as FILTER_MESSAGE_HEADER, but only when
// __FLT_USER_STRUCTURES_H__ is not defined. The guard name doesn't match
// the WDK's actual guard, causing a type redefinition conflict. Force the
// guard so the WDK version takes precedence.
#ifndef __FLT_USER_STRUCTURES_H__
#  define __FLT_USER_STRUCTURES_H__
#endif

#include "../../Drivers/Shared/MessageProtocol.h"
#include "../../Drivers/Shared/MessageTypes.h"
#include "../../Drivers/Shared/VerdictTypes.h"
#include "../../Drivers/Shared/PortName.h"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Communication {
    class IPCManagerImpl;
    class FilterConnection;
    class ThreatIntelPusher;
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
 * @brief Process notification wire struct — mirrors SHADOWSTRIKE_PROCESS_NOTIFICATION (pack 1).
 *
 * Wire layout at pPayload:
 *   [SS_MESSAGE_HEADER (40B, kernel inner header — redundant, skip)]
 *   [ProcessId (4B)]  [ParentProcessId (4B)]
 *   [CreatingProcessId (4B)]  [CreatingThreadId (4B)]
 *   [Create (1B)]  [ImagePathLength (2B)]  [CommandLineLength (2B)]
 *   [ImagePath (variable)]  [CommandLine (variable)]
 *
 * sizeof(ProcessNotifyRequest) == sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION) == 61 bytes (pack 1).
 * Dispatch validates variable-length bounds before invoking handler.
 */
struct ProcessNotifyRequest {
    /// Kernel SHADOWSTRIKE_PROCESS_NOTIFICATION has SS_MESSAGE_HEADER as first field.
    /// Redundant (outer header already parsed by dispatch) but must be accounted for.
    SS_MESSAGE_HEADER _kernelInnerHeader;

    uint32_t processId;
    uint32_t parentProcessId;
    uint32_t creatingProcessId;
    uint32_t creatingThreadId;
    uint8_t  isCreation;        ///< BOOLEAN Create: 1=creation, 0=termination
    uint16_t imagePathLength;   ///< Byte count of ImagePath (not char count)
    uint16_t commandLineLength; ///< Byte count of CommandLine (not char count)

    // Variable-length data follows the fixed struct in the wire buffer.
    // Accessors return pointers INTO the message buffer — valid only while buffer is alive.
    // Caller must ensure dispatch validated variable bounds before use.

    [[nodiscard]] const wchar_t* imagePathData() const noexcept {
        return reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const uint8_t*>(this) + sizeof(ProcessNotifyRequest));
    }
    [[nodiscard]] size_t imagePathCharLen() const noexcept {
        return imagePathLength / sizeof(wchar_t);
    }
    [[nodiscard]] const wchar_t* commandLineData() const noexcept {
        return reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const uint8_t*>(this) + sizeof(ProcessNotifyRequest) + imagePathLength);
    }
    [[nodiscard]] size_t commandLineCharLen() const noexcept {
        return commandLineLength / sizeof(wchar_t);
    }
};

/**
 * @brief Image load notification wire struct — mirrors SHADOWSTRIKE_IMAGE_NOTIFICATION (pack 1).
 *
 * Wire layout at pPayload:
 *   [ProcessId (4B)]  [ImageBase (8B)]  [ImageSize (8B)]
 *   [SignatureLevel (1B)]  [SignatureType (1B)]  [IsSystemImage (1B)]
 *   [ImageNameLength (2B)]
 *   [ImageName (variable)]
 *
 * sizeof(ImageLoadRequest) == sizeof(SHADOWSTRIKE_IMAGE_NOTIFICATION) == 25 bytes (pack 1).
 * NO embedded header — kernel struct starts directly with ProcessId.
 */
struct ImageLoadRequest {
    uint32_t processId;
    uint64_t imageBase;
    uint64_t imageSize;
    uint8_t  signatureLevel;
    uint8_t  signatureType;
    uint8_t  isSystemModule;    ///< BOOLEAN IsSystemImage
    uint16_t imagePathLength;   ///< Byte count of ImageName

    [[nodiscard]] const wchar_t* imagePathData() const noexcept {
        return reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const uint8_t*>(this) + sizeof(ImageLoadRequest));
    }
    [[nodiscard]] size_t imagePathCharLen() const noexcept {
        return imagePathLength / sizeof(wchar_t);
    }
};

/**
 * @brief Registry operation wire struct — mirrors SHADOWSTRIKE_REGISTRY_NOTIFICATION (pack 1).
 *
 * Wire layout at pPayload:
 *   [ProcessId (4B)]  [ThreadId (4B)]  [Operation (1B)]
 *   [KeyPathLength (2B)]  [ValueNameLength (2B)]
 *   [DataSize (4B)]  [DataType (4B)]
 *   [KeyPath (variable)]  [ValueName (variable)]  [Data (variable)]
 *
 * sizeof(RegistryOpRequest) == sizeof(SHADOWSTRIKE_REGISTRY_NOTIFICATION) == 21 bytes (pack 1).
 * NO embedded header — kernel struct starts directly with ProcessId.
 */
struct RegistryOpRequest {
    uint32_t processId;
    uint32_t threadId;
    uint8_t  operation;         ///< Create, Set, Delete
    uint16_t keyPathLength;     ///< Byte count of KeyPath
    uint16_t valueNameLength;   ///< Byte count of ValueName
    uint32_t dataSize;          ///< Byte count of registry Data
    uint32_t dataType;          ///< REG_SZ, REG_DWORD, etc.

    [[nodiscard]] const wchar_t* keyPathData() const noexcept {
        return reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const uint8_t*>(this) + sizeof(RegistryOpRequest));
    }
    [[nodiscard]] size_t keyPathCharLen() const noexcept {
        return keyPathLength / sizeof(wchar_t);
    }
    [[nodiscard]] const wchar_t* valueNameData() const noexcept {
        return reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const uint8_t*>(this) + sizeof(RegistryOpRequest) + keyPathLength);
    }
    [[nodiscard]] size_t valueNameCharLen() const noexcept {
        return valueNameLength / sizeof(wchar_t);
    }
    [[nodiscard]] const uint8_t* registryData() const noexcept {
        return reinterpret_cast<const uint8_t*>(this) +
               sizeof(RegistryOpRequest) + keyPathLength + valueNameLength;
    }
};

/**
 * @brief Kernel reply — uses SHADOWSTRIKE_SCAN_VERDICT_REPLY from MessageProtocol.h
 */

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
    SHADOWSTRIKE_MESSAGE_TYPE command = FilterMessageType_None;
    
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
    std::array<std::atomic<uint64_t>, 16> byMessageType{};
    std::array<std::atomic<uint64_t>, 8> byVerdict{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Copyable snapshot of IPCStatistics for return-by-value.
 *        IPCStatistics contains std::atomic members and is non-copyable.
 */
struct IPCStatisticsSnapshot {
    uint64_t messagesReceived{0};
    uint64_t messagesSent{0};
    uint64_t messagesDropped{0};
    uint64_t bytesReceived{0};
    uint64_t bytesSent{0};
    uint64_t timeouts{0};
    uint64_t errors{0};
    uint64_t reconnects{0};
    uint64_t avgLatencyUs{0};
    uint64_t maxLatencyUs{0};
    std::array<uint64_t, 16> byMessageType{};
    std::array<uint64_t, 8> byVerdict{};
    TimePoint startTime{};
    
    [[nodiscard]] std::string ToJson() const;
};

/// @brief Take a thread-safe snapshot of live IPCStatistics
[[nodiscard]] inline IPCStatisticsSnapshot TakeSnapshot(const IPCStatistics& stats) noexcept {
    IPCStatisticsSnapshot snap;
    snap.messagesReceived = stats.messagesReceived.load(std::memory_order_relaxed);
    snap.messagesSent     = stats.messagesSent.load(std::memory_order_relaxed);
    snap.messagesDropped  = stats.messagesDropped.load(std::memory_order_relaxed);
    snap.bytesReceived    = stats.bytesReceived.load(std::memory_order_relaxed);
    snap.bytesSent        = stats.bytesSent.load(std::memory_order_relaxed);
    snap.timeouts         = stats.timeouts.load(std::memory_order_relaxed);
    snap.errors           = stats.errors.load(std::memory_order_relaxed);
    snap.reconnects       = stats.reconnects.load(std::memory_order_relaxed);
    snap.avgLatencyUs     = stats.avgLatencyUs.load(std::memory_order_relaxed);
    snap.maxLatencyUs     = stats.maxLatencyUs.load(std::memory_order_relaxed);
    for (size_t i = 0; i < stats.byMessageType.size(); ++i)
        snap.byMessageType[i] = stats.byMessageType[i].load(std::memory_order_relaxed);
    for (size_t i = 0; i < stats.byVerdict.size(); ++i)
        snap.byVerdict[i] = stats.byVerdict[i].load(std::memory_order_relaxed);
    snap.startTime = stats.startTime;
    return snap;
}

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
    
    /// @brief Reply to a pending kernel message (FilterReplyMessage wrapper).
    ///        This is for responding to FltSendMessage from the kernel driver —
    ///        NOT for initiating new user→kernel messages.
    [[nodiscard]] bool ReplyToKernel(
        uint64_t messageId,
        const SHADOWSTRIKE_SCAN_VERDICT_REPLY& verdictReply);

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
    // THREAT INTEL PUSH OPERATIONS
    // ========================================================================

    /// @brief Get the ThreatIntelPusher for pushing data to kernel stores.
    ///        Returns nullptr if not connected to filter port.
    [[nodiscard]] ThreatIntelPusher* GetPusher() noexcept;

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] IPCStatisticsSnapshot GetStatistics() const;
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
    
    // Core handles (m_hPort is atomic — accessed by multiple worker threads)
    std::atomic<HANDLE> m_hPort{nullptr};
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

    // Dedicated push connection (separate handle for user→kernel data push)
    std::unique_ptr<FilterConnection> m_pushConnection;
    std::unique_ptr<ThreatIntelPusher> m_pusher;
    mutable std::mutex m_pusherMutex;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetMessageTypeName(SHADOWSTRIKE_MESSAGE_TYPE type) noexcept;
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

#define SS_IPC_SEND_VERDICT(msgId, verdictReply) \
    ::ShadowStrike::Communication::IPCManager::Instance().ReplyToKernel( \
        (msgId), (verdictReply))

#define SS_IPC_IS_CONNECTED() \
    ::ShadowStrike::Communication::IPCManager::Instance().IsConnected()
