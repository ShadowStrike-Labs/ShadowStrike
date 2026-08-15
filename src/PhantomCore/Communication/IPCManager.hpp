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

// The transport header comes from <fltUser.h> above, and MessageProtocol.h no
// longer aliases FILTER_MESSAGE_HEADER to anything.
//
// This is where a `#define __FLT_USER_STRUCTURES_H__` used to sit, to suppress
// that alias. Two things were wrong with it. It force-defined a RESERVED
// WDK-INTERNAL GUARD NAME to steer a third header's behaviour - so an SDK that
// ever adopted that name as its real guard would have had its own structure
// definitions suppressed instead - and it only protected translation units that
// included THIS header, which FileSystemFilter.cpp does not. The alias is gone
// at its source, so nothing needs suppressing here.
//
// The size claim that used to accompany it was also wrong: the OS structure is
// 16 bytes on x64, not 12. It is asserted in FilterPortGate.hpp.

#include "../../../PhantomSensor/Shared/MessageProtocol.h"
#include "../../../PhantomSensor/Shared/MessageTypes.h"
#include "../../../PhantomSensor/Shared/VerdictTypes.h"
#include "../../../PhantomSensor/Shared/PortName.h"

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

    /// @brief Number of per-message-type statistic slots.
    ///
    /// DERIVED FROM THE ENUM, NOT CHOSEN. This was the literal 16 while
    /// SHADOWSTRIKE_MESSAGE_TYPE already ran well past 40, and every counting
    /// site guards with `if (idx < byMessageType.size())` - so every type with an
    /// ordinal of 16 or more was silently not counted, and the guard is exactly
    /// what made that invisible. That set was not arbitrary: it was all of the
    /// alerts. HandleAlert, RansomwareAlert, BehavioralAlert, MemoryAlert,
    /// NetworkAlert, SyscallAlert and SelfProtectAlert each reported zero
    /// received, permanently, no matter how many arrived.
    ///
    /// A statistic that is structurally always zero is worse than an absent one,
    /// because it argues against the symptom someone is investigating.
    inline constexpr size_t MESSAGE_TYPE_SLOTS =
        static_cast<size_t>(FilterMessageType_Max);

    static_assert(MESSAGE_TYPE_SLOTS > 16,
                  "Sanity check on the derivation: the enum is known to exceed the old "
                  "hardcoded 16 slots. If this fails, the enum shrank and the note above "
                  "needs revisiting.");
    
    // The service pipe name is deliberately NOT declared here.
    //
    // This header previously carried
    //     SERVICE_PIPE_NAME = L"\\\\.\\pipe\\ShadowStrikeService"
    // commented "Named pipe name (Service-GUI)". That comment was wrong and
    // wrong in the most misleading direction available: the Service-to-GUI pipe
    // is \\.\pipe\ShadowStrikeServicePipe, declared as
    // ShadowStrike::Service::CommunicationConstants::PIPE_NAME and served by
    // ServiceCommunicator. A reader wiring new UI traffic to the constant that
    // called itself the Service-GUI pipe would have reached a different channel
    // and produced a failure indistinguishable from the service being down.
    //
    // The literal was also a second, independent copy of a name already declared
    // by ServiceCommConstants::SERVICE_PIPE_NAME for the same channel. Two
    // declarations of one wire-level name agreed on the day they were written
    // with nothing able to report when they stopped agreeing - the same
    // arrangement that let SelfDefenseConstants::DRIVER_SERVICE_NAME name a
    // service which has never existed.
    //
    // Where the names now live, once each:
    //   UI and tray channel   Service::CommunicationConstants::PIPE_NAME
    //   control channel       Communication::ServiceCommConstants::SERVICE_PIPE_NAME
    //   kernel filter port    FILTER_PORT_NAME, immediately above
    
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

// The kernel writes SHADOWSTRIKE_REGISTRY_NOTIFICATION and we read it back as
// RegistryOpRequest, so the two layouts are one wire contract maintained in two
// files. That equality was asserted only in the comment above, which enforces
// nothing: adding or reordering a field on either side would silently shift every
// subsequent offset and misparse every registry notification, and the
// variable-length accessors above compute their offsets from this very size.
// Pin it so a divergence is a build failure rather than a field mystery.
static_assert(sizeof(RegistryOpRequest) == 21,
              "RegistryOpRequest must stay byte-identical to "
              "SHADOWSTRIKE_REGISTRY_NOTIFICATION in PhantomSensor/Shared/MessageProtocol.h "
              "(UINT32 x2 + UINT8 + UINT16 x2 + UINT32 x2 under pack(1)). If this fires, the "
              "kernel and user-mode views of the registry wire format have diverged.");
static_assert(offsetof(RegistryOpRequest, keyPathLength) == 9,
              "keyPathLength offset pins the packed layout against silent padding");
static_assert(offsetof(RegistryOpRequest, dataSize) == 13,
              "dataSize offset pins the packed layout against silent padding");

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
    std::array<std::atomic<uint64_t>, IPCConstants::MESSAGE_TYPE_SLOTS> byMessageType{};
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
    std::array<uint64_t, IPCConstants::MESSAGE_TYPE_SLOTS> byMessageType{};
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

#define SS_IPC_CALLBACK_TYPES_DEFINED
using FileScanCallback = std::function<SHADOWSTRIKE_SCAN_VERDICT(const FILE_SCAN_REQUEST&)>;
using ProcessNotifyCallback = std::function<SHADOWSTRIKE_SCAN_VERDICT(const ProcessNotifyRequest&)>;
using ImageLoadCallback = std::function<SHADOWSTRIKE_SCAN_VERDICT(const ImageLoadRequest&)>;
using RegistryOpCallback = std::function<SHADOWSTRIKE_SCAN_VERDICT(const RegistryOpRequest&)>;
using GenericMessageCallback = std::function<void(SHADOWSTRIKE_MESSAGE_TYPE, const void*, size_t)>;
using ConnectionCallback = std::function<void(ChannelType, ConnectionStatus)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

/**
 * @brief One named subscriber to the generic (non-verdict) kernel message feed.
 *
 * The generic feed is a FAN-OUT, not a slot. It used to be a single
 * std::function, and eight modules registered against it: RealTimeProtection,
 * ProcessInjectionDetector, AtomBombingDetector, StackPivotDetector,
 * ROPProtection, BufferOverflowProtection, FileProtection and SelfDefense.
 * The last registrant silently evicted the other seven, so exactly one of
 * eight consumers ever received a kernel event, and which one depended on
 * module startup order rather than on any decision.
 *
 * Two consequences were measured rather than inferred:
 *   - FilterMessageType_ThreadNotify has THREE would-be consumers
 *     (RealTimeProtection, ProcessInjectionDetector, AtomBombingDetector).
 *   - FilterMessageType_SelfProtectAlert has TWO, both of them self-defence
 *     (SelfDefense and FileProtection), so one half of self-defence's kernel
 *     reporting was always dead.
 *
 * The subscriber NAME is load-bearing, not decorative: every registrant used
 * to emit the identical "[IPCManager] Registered generic handler" line, so a
 * field log could not say which module owned the feed. The name makes the
 * subscription list answerable from a log.
 */
struct GenericSubscription {
    std::string            name;
    GenericMessageCallback handler;
};

/**
 * @brief One named subscriber to the kernel registry-notification feed.
 *
 * SAME SHAPE AS GenericSubscription AND FOR THE SAME REASON, but it had to be
 * argued separately because this feed carries a VERDICT-returning callback and
 * the generic feed does not.
 *
 * WHY A FAN-OUT IS CORRECT HERE: the registry verdict has NO KERNEL WAITER.
 * ShadowStrikeSendRegistryNotification (ScanBridge.c:1807) delivers through
 * ShadowStrikeSendNotification, whose declaration (CommPort.h:365) takes no
 * reply buffer at all and is documented "no reply expected ... Uses
 * zero-timeout to avoid blocking". The registry callback DOES deny operations
 * (RegistryCallback.c:2440 returns STATUS_ACCESS_DENIED) but only from
 * kernel-side policy - ShadowStrikeShouldBlockRegistryAccess (:2007) and
 * ShadowStrikeDetectRansomwareRegistryBehavior (:2074). Neither consults user
 * mode. So no thread is blocked while these subscribers run, and there is no
 * latency budget to negotiate the way the process-notify path needs one.
 */
struct RegistrySubscription {
    std::string        name;
    RegistryOpCallback handler;
};

/**
 * @brief One named subscriber to the kernel image-load notification feed.
 *
 * SAME SHAPE, SAME REASON, AND THE SAME NO-WAITER ARGUMENT AS
 * RegistrySubscription: ShadowStrikeSendImageNotification (ScanBridge.c:1639,
 * called from ImageNotify.c:2686) also delivers through
 * ShadowStrikeSendNotification, whose declaration takes no reply buffer, so no
 * kernel thread is blocked while these subscribers run.
 *
 * Two production modules registered against the single slot this replaces:
 * RealTimeProtection (RealTimeProtection.cpp:1361, from Start()) and
 * ReflectiveDLLDetector (ReflectiveDLLDetector.cpp:2542, from
 * RegisterKernelHandlers, called unconditionally inside its Initialize()).
 * The contest is LATENT rather than active only because nothing in production
 * calls ReflectiveDLLDetector::Instance().Initialize() - grepped, not assumed.
 * Wiring that module up would have silently evicted RealTimeProtection's whole
 * image-load analysis, and no log line would have named either party.
 *
 * SEPARATE DEFECT ON THIS PATH, DELIBERATELY NOT ADDRESSED HERE:
 * OnKernelImageLoad returns KernelVerdict::Block for a stolen code-signing
 * certificate and records actionTaken="Blocked", but the module loads anyway.
 * The verdict is never transmitted, AND ImageNotify.c:2341 states plainly that
 * "ImageNotify is notification-only (cannot block loads)" - the documented
 * PsSetLoadImageNotifyRoutine contract. So that is a reporting-honesty defect
 * requiring an owner decision about what SHOULD act, not a wiring gap this
 * fan-out could close. Fanning the slot out neither fixes nor worsens it.
 */
struct ImageLoadSubscription {
    std::string       name;
    ImageLoadCallback handler;
};

/**
 * @brief One named subscriber to the kernel process-creation feed.
 *
 * THE ONLY FANNED-OUT SLOT WHERE THE KERNEL IS ACTUALLY WAITING, and that
 * changes what the fan-out must guarantee. ProcessNotify.c requests a reply
 * whenever the process scored PN_SUSPICION_MEDIUM or above, then blocks the
 * thread that called CreateProcess for PN_VERDICT_REPLY_TIMEOUT_MS
 * (500 ms, ProcessNotify.c:301) waiting for it. Verdict_Malicious is the one
 * value the driver converts into STATUS_ACCESS_DENIED, so this feed can stop a
 * process from starting - it is the only fanned-out feed that can.
 *
 * Subscribers therefore run under a SHARED DEADLINE (kProcessFanOutBudgetMs)
 * instead of running for as long as they like. Without one, wiring up a second
 * subscriber would push the total past the driver's budget, the kernel would
 * time out and fail open, and EVERY subscriber's evidence would be discarded
 * while the process launched anyway - strictly worse than answering on time
 * with the evidence gathered. That is the same argument, and the same choice,
 * as the 250 ms budget already covering the five evasion detectors inside
 * RealTimeProtection::OnKernelProcessNotify.
 *
 * Two production modules registered against the single slot this replaces:
 * RealTimeProtection (RealTimeProtection.cpp:1357, from Start()) and
 * ProcessMonitor (ProcessMonitor.cpp:1623, from RegisterKernelProcessHandler).
 * LATENT rather than active only because nothing in production calls
 * ProcessMonitor::Initialize() - grepped. MonitorConfig::useKernelCallback
 * defaults TRUE (ProcessMonitor.hpp:596), so initializing that module would
 * have replaced RealTimeProtection's ENTIRE process analysis - the five
 * evasion detectors, the ScanEngine verdict and the Microsoft-trust gate - with
 * ProcessMonitor's own, on every startup, with nothing reporting the swap.
 */
struct ProcessSubscription {
    std::string           name;
    ProcessNotifyCallback handler;
};

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

    /**
     * @brief Gate kernel scan-request servicing on engine readiness.
     *
     * While false, DispatchMessage answers file-scan requests with an immediate
     * fail-open Verdict_Clean instead of invoking the still-initializing scan
     * handler. This prevents the cold-boot scan storm: the kernel gets fast
     * verdicts (no reply-timeout flood, no login I/O stall) while
     * RealTimeProtection is warming up. Set true once the engine is fully up.
     */
    void SetScanServicingReady(bool ready) noexcept;
    [[nodiscard]] bool IsScanServicingReady() const noexcept;
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

    /// @brief Reply to a pending kernel PROCESS notification.
    ///
    /// THE REPLY TYPE IS NOT INTERCHANGEABLE WITH THE SCAN ONE, and that is the
    /// whole reason this overload exists rather than reusing the scan reply.
    /// ProcessNotify.c sizes its reply buffer as
    /// sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY) - 16 bytes - while
    /// SHADOWSTRIKE_SCAN_VERDICT_REPLY is 26 bytes packed. Replying with the scan
    /// struct hands Filter Manager 10 bytes more than the driver allocated, so the
    /// verdict never lands, the kernel waits out its full budget and fails open,
    /// and the only trace is one Debug line. Both structs happen to place Verdict
    /// at offset 8, so the byte itself would have been right - the SIZE is what
    /// fails, which is exactly why this looked like a working change.
    [[nodiscard]] bool ReplyToKernel(
        uint64_t messageId,
        const SHADOWSTRIKE_PROCESS_VERDICT_REPLY& verdictReply);

    // ========================================================================
    // NAMED PIPE OPERATIONS
    // ========================================================================
    //
    // NOT REACHED BY ANY PRODUCTION CODE TODAY, established by measurement
    // rather than assumed: CreatePipeServer has no callers anywhere in src,
    // tests or Fuzzer; ConnectToPipe is called only from IPCManager::Reconnect,
    // which itself has no callers. So this transport can neither be served nor
    // connected, and the send/receive machinery behind m_hPipe is unreachable
    // with it. It is left in place rather than deleted here because removing a
    // whole transport from the class that also owns the kernel filter port
    // deserves its own change, with its own verification, rather than riding
    // along with a naming fix.
    //
    // The pipe name is now a REQUIRED argument. It previously defaulted to a
    // duplicate of ServiceCommConstants::SERVICE_PIPE_NAME declared in this
    // header - see the note where that literal used to be. A caller must state
    // which channel it means.

    /// @brief Create named pipe server
    [[nodiscard]] bool CreatePipeServer(const std::wstring& pipeName);
    
    /// @brief Connect to pipe server
    [[nodiscard]] bool ConnectToPipe(const std::wstring& pipeName);
    
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
    
    /**
     * @brief Register the file-scan handler.
     *
     * DELIBERATELY STILL A SINGLE SLOT while the process, image-load, registry
     * and generic feeds are all fan-outs. It has exactly ONE registrant in
     * production - RealTimeProtection.cpp:1353, measured - so there is no
     * contest here to resolve, and it is the hottest reply-bearing path in the
     * product, so it has no latency headroom to spend running a second
     * consumer while IRP_MJ_CREATE is held open.
     *
     * If a second consumer is ever genuinely needed, fan this out the way
     * RegisterProcessHandler below was rather than adding a second assignment
     * to the member: a second assignment is how the registry and generic feeds
     * each lost a detector without a single log line naming either party.
     */
    void RegisterFileScanHandler(FileScanCallback handler);

    /**
     * @brief Subscribe to the kernel process-creation feed.
     *
     * ADDITIVE, not a slot. Registering twice under the same @p subscriber name
     * REPLACES that subscriber's callback and leaves the others intact, which
     * is what makes an Stop()/Start() cycle safe: RealTimeProtection
     * re-registers from InitializeIPCManager() on every Start(), and nothing in
     * production ever calls UnregisterHandlers().
     *
     * Subscribers are invoked under a shared deadline and their verdicts are
     * combined most-severe-wins by CombineKernelVerdicts, so a subscriber
     * asking to block cannot be overruled by one reporting Clean. See
     * ProcessSubscription for why the deadline exists on this feed and not on
     * the registry or image-load feeds.
     *
     * @param subscriber Stable identity of the registering module. Must be
     *                   non-empty: an unnamed subscriber cannot be removed and
     *                   cannot be attributed in a log, which is precisely the
     *                   condition that hid the original eviction.
     * @param handler    Verdict-returning callback. Passing a null handler for
     *                   a KNOWN subscriber removes only that subscriber, so the
     *                   legacy Register(nullptr) teardown idiom keeps working
     *                   without clearing the whole feed.
     */
    void RegisterProcessHandler(std::string subscriber, ProcessNotifyCallback handler);

    /// @brief Remove one named subscriber from the process feed. No-op if absent.
    void UnregisterProcessHandler(std::string_view subscriber);

    /// @brief Number of live process subscribers. Exposed so a test can prove a
    ///        registration was ADDITIVE rather than a silent replacement.
    [[nodiscard]] size_t ProcessSubscriberCount() const noexcept;

    /**
     * @brief Subscribe to the kernel image-load notification feed.
     *
     * ADDITIVE, not a slot, with the same name semantics as the process feed
     * above. No shared deadline here, and that asymmetry is deliberate: this
     * feed has no kernel waiter (see ImageLoadSubscription), and both existing
     * consumers already bound their own work - RealTimeProtection's image-load
     * path runs Standard-depth packer analysis at 50 ms / 32 MB with signature
     * verification cleared.
     */
    void RegisterImageLoadHandler(std::string subscriber, ImageLoadCallback handler);

    /// @brief Remove one named subscriber from the image-load feed. No-op if absent.
    void UnregisterImageLoadHandler(std::string_view subscriber);

    /// @brief Number of live image-load subscribers.
    [[nodiscard]] size_t ImageLoadSubscriberCount() const noexcept;
    
    /**
     * @brief Subscribe to the kernel registry-notification feed.
     *
     * ADDITIVE, not a slot. This replaced a single-assignment
     * `m_registryHandler` that two production modules registered against:
     * RealTimeProtection (RealTimeProtection.cpp:1366, from Start()) and
     * RegistryProtection (RegistryProtection.cpp:2494, from Initialize()).
     * AntivirusService runs Impl::Initialize() before Impl::Start() at all
     * three of its call sites, so RegistryProtection registered first and
     * RealTimeProtection silently evicted it on EVERY startup - taking with it
     * RegistryProtection's entire kernel-event pipeline (event history,
     * totalOperations/totalBlocked, and every registered event callback).
     *
     * Registering twice under the same @p subscriber name REPLACES that
     * subscriber's callback and leaves the others intact.
     *
     * @param subscriber Stable identity of the registering module. Must be
     *                   non-empty: an unnamed subscriber cannot be removed and
     *                   cannot be attributed in a log, which is precisely what
     *                   made the eviction invisible.
     * @param handler    Invoked OUTSIDE the handler mutex. Verdicts from all
     *                   subscribers are combined most-severe-wins; see
     *                   CombineKernelVerdicts.
     */
    void RegisterRegistryHandler(std::string subscriber, RegistryOpCallback handler);

    /// @brief Remove one named registry subscriber. Unknown names are ignored.
    void UnregisterRegistryHandler(std::string_view subscriber);

    /// @brief Number of live registry subscribers. Zero means no module sees kernel registry events.
    [[nodiscard]] size_t RegistrySubscriberCount() const noexcept;

    /**
     * @brief Combine two kernel verdicts, most severe wins.
     *
     * ONE POLICY WITH THREE USERS, NOT THREE COPIES. Every fanned-out
     * verdict-bearing feed - process, image-load and registry - reduces its
     * subscribers' answers through this function. It was originally written as
     * CombineRegistryVerdicts; generalising it rather than copying it is
     * deliberate, because duplication-with-drift is the single most repeated
     * defect in this codebase (two YARA metadata builders where the poorer one
     * ran, two on-disk trie producers where the broken one ran, six copies of
     * one compile-and-adopt sequence).
     *
     * PUBLIC AND STATIC BECAUSE THE ORDERING IS A POLICY, NOT AN IMPLEMENTATION
     * DETAIL, and a policy nobody can test is a policy nobody can verify.
     *
     * THE TRAP THIS EXISTS TO AVOID: SHADOWSTRIKE_SCAN_VERDICT is NOT ordered by
     * severity. VerdictTypes.h:21 declares Unknown 0, Clean 1, Malicious 2,
     * Suspicious 3, Error 4, Timeout 5 - so a naive std::max would rank Timeout
     * and Error ABOVE Malicious and silently downgrade a conviction to a
     * transient failure. The rank in the definition is explicit for that reason.
     *
     * Malicious outranks everything: it is the only value the driver turns into
     * STATUS_ACCESS_DENIED, so a subscriber asking to deny must never be
     * overruled by another subscriber's "nothing to report". On the process feed
     * that is not a theoretical ordering - it decides whether a process starts.
     */
    [[nodiscard]] static SHADOWSTRIKE_SCAN_VERDICT CombineKernelVerdicts(
        SHADOWSTRIKE_SCAN_VERDICT a, SHADOWSTRIKE_SCAN_VERDICT b) noexcept;
    
    /**
     * @brief Subscribe to the generic (non-verdict) kernel message feed.
     *
     * ADDITIVE, not a slot: every subscriber receives every generic message
     * that reaches the feed. Registering twice under the same @p subscriber
     * name REPLACES that subscriber's callback and leaves all others intact,
     * so a module that re-initializes cannot accumulate duplicate deliveries.
     *
     * @param subscriber Stable identity of the registering module. Must be
     *                   non-empty; an unnamed subscriber cannot be removed and
     *                   cannot be attributed in a log, which is the defect this
     *                   signature exists to prevent.
     * @param handler    Invoked OUTSIDE the handler mutex. Must not throw; a
     *                   throwing subscriber is contained so it cannot starve
     *                   the subscribers behind it, but it will be dropped for
     *                   that message.
     */
    void RegisterGenericHandler(std::string subscriber, GenericMessageCallback handler);

    /// @brief Remove one named subscriber from the generic feed. Unknown names are ignored.
    void UnregisterGenericHandler(std::string_view subscriber);

    /// @brief Number of live generic subscribers. Zero means no module observes kernel alerts.
    [[nodiscard]] size_t GenericSubscriberCount() const noexcept;
    
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

    /// @brief THE one place a reply reaches the kernel.
    ///
    /// Both ReplyToKernel overloads funnel through this, deliberately. The reply
    /// path carries a channel-readiness check, a no-plaintext-fallback rule and a
    /// benign-race logging policy; two copies of that drift, and this codebase has
    /// already paid for exactly that twice (the two YARA metadata builders and the
    /// two on-disk trie producers, where in both cases the WORSE copy was the one
    /// that ran). The typed overloads exist only to fix the size and the label.
    [[nodiscard]] bool DeliverKernelReply(uint64_t messageId,
                                          const void* reply,
                                          size_t replySize,
                                          const char* replyKind);
    
    std::unique_ptr<IPCManagerImpl> m_impl;
    
    // Core handles (m_hPort/m_hPipe are atomic — accessed by multiple worker threads
    // and by Stop()/Disconnect*() concurrently)
    std::atomic<HANDLE> m_hPort{nullptr};
    std::atomic<HANDLE> m_hPipe{nullptr};
    HANDLE m_hIOCP = nullptr;

    // Serializes ConnectFilterPort against itself: worker threads on a stale port
    // may all attempt reconnect simultaneously. Without this mutex, the
    // FilterConnectCommunicationPort race leaks port handles and can spawn
    // multiple primary FilterConnection / ThreatIntelPusher instances.
    mutable std::mutex m_connectMutex;

    // Reconnect coordination — ensures only one worker drives reconnects so
    // we never hammer the kernel ConnectNotify path with N concurrent attempts
    // (which has been observed to wedge VMware guests during first-boot
    // service start while the minifilter is still warming up). Other workers
    // back off and wait until m_hPort becomes non-null again.
    std::atomic<bool> m_reconnectClaim{false};

    // Current reconnect back-off (ms). Starts at config.reconnectDelayMs on
    // first failure and doubles up to kReconnectBackoffCapMs. Reset to 0 on
    // successful connect. Read/written only by the worker that owns the
    // reconnect claim.
    std::atomic<uint32_t> m_reconnectBackoffMs{0};

    // Permanent-failure tracking for the filter port.
    //
    // ERROR_ACCESS_DENIED (0x80070005) from FilterConnectCommunicationPort is
    // *structural* — the kernel port DACL rejected SYSTEM, or
    // ShadowStrikeConnectNotify rejected this exe (wrong filename, wrong
    // token, stale .sys on disk). Retrying does not help; only re-install,
    // a service-identity fix, or a driver rebuild will. We therefore cap the
    // streak at kAccessDeniedAttemptCeiling and transition IPCStatus::Error
    // so the UI can surface an actionable, terminal failure rather than
    // logging the same denial every second forever.
    //
    // m_accessDeniedStreak is incremented by the connect attempt; the gate
    // m_filterPortPermanentlyDenied is exchanged once on transition so any
    // worker can short-circuit. m_lastFilterPortHr is mutated only while
    // m_connectMutex is held (the same critical section that wraps the
    // FilterConnectCommunicationPort call), so does not need atomicity.
    std::atomic<uint32_t> m_accessDeniedStreak{0};
    std::atomic<bool>     m_filterPortPermanentlyDenied{false};
    HRESULT               m_lastFilterPortHr{S_OK};
    static constexpr uint32_t kAccessDeniedAttemptCeiling = 5;

    // State
    std::atomic<bool> m_connected{false};

    /// Scan-servicing readiness gate (see SetScanServicingReady). While false,
    /// DispatchMessage fail-opens kernel file-scan requests to avoid the
    /// cold-boot scan storm during engine warm-up.
    std::atomic<bool> m_scanServicingReady{false};
    std::atomic<bool> m_running{false};
    std::atomic<IPCStatus> m_status{IPCStatus::Uninitialized};
    
    // Thread pool
    std::vector<std::thread> m_workerThreads;
    
    // Handlers
    //
    // File scan stays a single slot on purpose - one registrant, hottest
    // reply-bearing path. See RegisterFileScanHandler for the full reasoning.
    FileScanCallback m_fileScanHandler;

    /// Shared wall-clock budget for one process-notification fan-out.
    ///
    /// MUST STAY BELOW the driver's PN_VERDICT_REPLY_TIMEOUT_MS (500 ms,
    /// ProcessNotify.c:301), which is how long the thread that called
    /// CreateProcess is blocked waiting for this answer. The remainder covers
    /// payload validation, verdict serialisation and the ReplyMessage round
    /// trip; an answer that arrives after the driver gave up is not an answer,
    /// and the driver then fails open having discarded every subscriber's
    /// evidence. A kernel-source contract test pins this constant beneath the
    /// driver's so the two numbers cannot drift apart in separate commits.
    ///
    /// CANNOT BIND TODAY, and that is stated rather than glossed: there is
    /// exactly one production process subscriber, the first subscriber is never
    /// skipped, so with one subscriber this budget is unreachable by
    /// construction. It exists so that wiring up the second one cannot
    /// silently turn every suspicious process creation into a stalled
    /// fail-open, which is what an unbounded fan-out here would do.
    static constexpr uint32_t kProcessFanOutBudgetMs = 400;

    // Process subscribers, same copy-on-write snapshot discipline as the
    // registry and generic feeds: rebuilt on registration (a startup event),
    // copied by refcount on delivery. Never null once constructed.
    std::shared_ptr<const std::vector<ProcessSubscription>> m_processSubscribers{
        std::make_shared<const std::vector<ProcessSubscription>>() };

    // Image-load subscribers, same discipline. This is the highest-frequency
    // kernel feed in the product (every module load in every process), which is
    // why delivery copies one refcount rather than N std::functions.
    std::shared_ptr<const std::vector<ImageLoadSubscription>> m_imageLoadSubscribers{
        std::make_shared<const std::vector<ImageLoadSubscription>>() };

    // Registry subscribers, same copy-on-write snapshot discipline as the
    // generic feed below: rebuilt on registration (a startup event), copied by
    // refcount on delivery. Never null once constructed, so the dispatch path
    // does not have to defend against a null list.
    std::shared_ptr<const std::vector<RegistrySubscription>> m_registrySubscribers{
        std::make_shared<const std::vector<RegistrySubscription>>() };

    // Generic (non-verdict) subscribers, held as an immutable snapshot behind a
    // shared_ptr so the DISPATCH path copies one refcount instead of N
    // std::functions. Registration is a startup-time event and rebuilds the
    // vector; delivery happens per kernel message and must stay cheap.
    // Never null once constructed.
    std::shared_ptr<const std::vector<GenericSubscription>> m_genericSubscribers{
        std::make_shared<const std::vector<GenericSubscription>>() };
    std::function<void(const std::string&)> m_messageCallback;
    mutable std::mutex m_handlerMutex;
    
    // Shared memory regions
    std::map<std::wstring, SharedMemoryRegion> m_sharedMemory;
    mutable std::shared_mutex m_sharedMemoryMutex;
    
    static std::atomic<bool> s_instanceCreated;

    // Primary filter connection (encrypts all kernel communication).
    // This is the kernel's designated primary-scanner port: scan requests and
    // notifications are received on it (encrypted), and verdict replies are
    // sent back on the SAME connection (so the WDK MessageId scope and the
    // per-connection session key both match). shared_ptr so a worker can hold
    // a strong reference across a blocking GetMessage while DisconnectFilterPort
    // tears the channel down concurrently.
    std::shared_ptr<FilterConnection> m_primaryConnection;
    mutable std::mutex m_primaryConnMutex;

    /// True once the primary connection has been observed connected at least once.
    /// Guarded by m_primaryConnMutex on write; read unsynchronised only to decide
    /// whether the bounded startup wait in SendToKernel applies, where a stale
    /// false costs one short wait and a stale true costs nothing.
    bool m_everConnected{ false };

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
