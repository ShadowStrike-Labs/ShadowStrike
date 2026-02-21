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
 * ShadowStrike NGAV - SERVICE COMMUNICATION MODULE
 * ============================================================================
 *
 * @file ServiceCommunication.hpp
 * @brief Enterprise-grade inter-service communication with secure named pipes,
 *        encrypted channels, and robust message framing.
 *
 * Manages bidirectional communication between the background service and user
 * interface components using secure Windows Named Pipes with proper ACLs.
 *
 * SERVICE COMMUNICATION CAPABILITIES:
 * ===================================
 *
 * 1. NAMED PIPE COMMUNICATION
 *    - Secure pipe creation
 *    - Access control (ACLs)
 *    - Impersonation protection
 *    - Overlapped I/O
 *    - Multiple client support
 *
 * 2. MESSAGE PROTOCOL
 *    - Length-prefixed framing
 *    - Message typing
 *    - Request/response pairing
 *    - Async notifications
 *    - Heartbeat/keepalive
 *
 * 3. SECURITY
 *    - Encrypted channels
 *    - Client authentication
 *    - Session management
 *    - Rate limiting
 *    - Audit logging
 *
 * 4. COMMANDS
 *    - Scan control
 *    - Update triggers
 *    - Configuration sync
 *    - Status queries
 *    - Quarantine operations
 *
 * 5. EVENTS
 *    - Threat notifications
 *    - Scan progress
 *    - Update status
 *    - System alerts
 *    - Module status
 *
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
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
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <thread>
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
#  include <sddl.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/CryptoUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Communication {
    class ServiceCommunicationImpl;
}

namespace ShadowStrike {
namespace Communication {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace ServiceCommConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Service pipe name
    inline constexpr const wchar_t* SERVICE_PIPE_NAME = L"\\\\.\\pipe\\ShadowStrikeService";
    
    /// @brief GUI pipe name
    inline constexpr const wchar_t* GUI_PIPE_NAME = L"\\\\.\\pipe\\ShadowStrikeGUI";
    
    /// @brief Maximum message size
    inline constexpr size_t MAX_MESSAGE_SIZE = 1024 * 1024;  // 1 MB
    
    /// @brief Maximum clients
    inline constexpr uint32_t MAX_CLIENTS = 16;
    
    /// @brief Connection timeout (ms)
    inline constexpr uint32_t CONNECTION_TIMEOUT_MS = 10000;
    
    /// @brief Heartbeat interval (ms)
    inline constexpr uint32_t HEARTBEAT_INTERVAL_MS = 30000;
    
    /// @brief Protocol magic
    inline constexpr uint32_t PROTOCOL_MAGIC = 0x53535043;  // "SSPC"
    
    /// @brief Protocol version
    inline constexpr uint32_t PROTOCOL_VERSION = 0x00030000;

}  // namespace ServiceCommConstants

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
 * @brief Message type
 */
enum class MessageType : uint16_t {
    // System messages (0x00xx)
    Handshake       = 0x0001,
    HandshakeAck    = 0x0002,
    Heartbeat       = 0x0003,
    HeartbeatAck    = 0x0004,
    Disconnect      = 0x0005,
    Error           = 0x000F,
    
    // Commands (0x01xx)
    CmdStartScan    = 0x0101,
    CmdStopScan     = 0x0102,
    CmdPauseScan    = 0x0103,
    CmdResumeScan   = 0x0104,
    CmdQuickScan    = 0x0105,
    CmdFullScan     = 0x0106,
    CmdCustomScan   = 0x0107,
    CmdCancelScan   = 0x0108,
    
    // Update commands (0x02xx)
    CmdCheckUpdate  = 0x0201,
    CmdStartUpdate  = 0x0202,
    CmdCancelUpdate = 0x0203,
    
    // Quarantine commands (0x03xx)
    CmdQuarantine   = 0x0301,
    CmdRestore      = 0x0302,
    CmdDelete       = 0x0303,
    CmdGetQuarantine = 0x0304,
    
    // Configuration (0x04xx)
    CmdGetConfig    = 0x0401,
    CmdSetConfig    = 0x0402,
    CmdResetConfig  = 0x0403,
    
    // Status queries (0x05xx)
    QueryStatus     = 0x0501,
    QueryStats      = 0x0502,
    QueryLicense    = 0x0503,
    QueryModules    = 0x0504,
    
    // Events (0x10xx)
    EventThreat     = 0x1001,
    EventScanProgress = 0x1002,
    EventScanComplete = 0x1003,
    EventUpdateAvail = 0x1004,
    EventUpdateProgress = 0x1005,
    EventUpdateComplete = 0x1006,
    EventSystemAlert = 0x1007,
    EventModuleStatus = 0x1008,
    EventQuarantine = 0x1009,
    
    // Responses (0xF0xx)
    Response        = 0xF001,
    ResponseOk      = 0xF002,
    ResponseError   = 0xF003
};

/**
 * @brief Connection state
 */
enum class ConnectionState : uint8_t {
    Disconnected    = 0,
    Connecting      = 1,
    Authenticating  = 2,
    Connected       = 3,
    Error           = 4
};

/**
 * @brief Client type
 */
enum class ClientType : uint8_t {
    Unknown         = 0,
    GUI             = 1,
    CLI             = 2,
    Tray            = 3,
    Management      = 4,
    API             = 5
};

/**
 * @brief Authentication result
 */
enum class AuthResult : uint8_t {
    Success         = 0,
    InvalidToken    = 1,
    Expired         = 2,
    PermissionDenied = 3,
    TooManyClients  = 4,
    InternalError   = 5
};

/**
 * @brief Module status
 */
enum class ServiceCommStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Listening       = 3,
    Stopping        = 4,
    Stopped         = 5,
    Error           = 6
};

// ============================================================================
// PACKED STRUCTURES (Wire Protocol)
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief Message header
 */
struct MessageHeader {
    /// @brief Protocol magic
    uint32_t magic = ServiceCommConstants::PROTOCOL_MAGIC;
    
    /// @brief Protocol version
    uint32_t version = ServiceCommConstants::PROTOCOL_VERSION;
    
    /// @brief Message type
    MessageType type = MessageType::Heartbeat;
    
    /// @brief Flags
    uint16_t flags = 0;
    
    /// @brief Sequence number
    uint32_t sequence = 0;
    
    /// @brief Response to (sequence)
    uint32_t responseTo = 0;
    
    /// @brief Payload length
    uint32_t payloadLength = 0;
    
    /// @brief Checksum (CRC32)
    uint32_t checksum = 0;
};

/**
 * @brief Handshake message
 */
struct HandshakeMessage {
    /// @brief Header
    MessageHeader header;
    
    /// @brief Client type
    ClientType clientType = ClientType::Unknown;
    
    /// @brief Client version (major.minor.patch.build as uint32s)
    uint32_t clientVersion[4] = {0, 0, 0, 0};
    
    /// @brief Session token (for reconnection)
    uint8_t sessionToken[32] = {0};
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Capabilities flags
    uint64_t capabilities = 0;
};

/**
 * @brief Scan command message
 */
struct ScanCommandMessage {
    /// @brief Header
    MessageHeader header;
    
    /// @brief Target count
    uint32_t targetCount = 0;
    
    /// @brief Options flags
    uint32_t options = 0;
    
    /// @brief Priority
    uint8_t priority = 0;
    
    /// @brief Reserved
    uint8_t reserved[3] = {0};
    
    // Followed by target paths (null-terminated strings)
};

/**
 * @brief Threat event message
 */
struct ThreatEventMessage {
    /// @brief Header
    MessageHeader header;
    
    /// @brief Threat ID
    uint64_t threatId = 0;
    
    /// @brief Severity (0-10)
    uint8_t severity = 0;
    
    /// @brief Action taken
    uint8_t actionTaken = 0;
    
    /// @brief Reserved
    uint8_t reserved[2] = {0};
    
    /// @brief Detection time
    uint64_t detectionTime = 0;
    
    /// @brief Threat name length
    uint16_t threatNameLength = 0;
    
    /// @brief File path length
    uint16_t filePathLength = 0;
    
    // Followed by threat name and file path (null-terminated)
};

/**
 * @brief Progress event message
 */
struct ProgressEventMessage {
    /// @brief Header
    MessageHeader header;
    
    /// @brief Task ID
    uint64_t taskId = 0;
    
    /// @brief Progress (0-10000 for 0.00-100.00%)
    uint16_t progress = 0;
    
    /// @brief State
    uint8_t state = 0;
    
    /// @brief Reserved
    uint8_t reserved = 0;
    
    /// @brief Items processed
    uint64_t itemsProcessed = 0;
    
    /// @brief Items total
    uint64_t itemsTotal = 0;
    
    /// @brief Current item length
    uint16_t currentItemLength = 0;
    
    // Followed by current item path
};

#pragma pack(pop)

// ============================================================================
// NON-PACKED STRUCTURES
// ============================================================================

/**
 * @brief Client session info
 */
struct ClientSession {
    /// @brief Session ID
    std::string sessionId;
    
    /// @brief Client type
    ClientType clientType = ClientType::Unknown;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Pipe handle
    HANDLE pipeHandle = nullptr;
    
    /// @brief Connection state
    ConnectionState state = ConnectionState::Disconnected;
    
    /// @brief Connected time
    std::optional<SystemTimePoint> connectedTime;
    
    /// @brief Last activity
    TimePoint lastActivity;
    
    /// @brief Messages sent
    uint64_t messagesSent = 0;
    
    /// @brief Messages received
    uint64_t messagesReceived = 0;
    
    /// @brief Current sequence
    std::atomic<uint32_t> sequence{0};
    
    /// @brief Is authenticated
    bool isAuthenticated = false;
    
    /// @brief Capabilities
    uint64_t capabilities = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Service message (high-level)
 */
struct ServiceMessage {
    /// @brief Message type
    MessageType type = MessageType::Heartbeat;
    
    /// @brief Sequence number
    uint32_t sequence = 0;
    
    /// @brief Response to
    uint32_t responseTo = 0;
    
    /// @brief Payload (JSON or binary)
    std::vector<uint8_t> payload;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Source session
    std::string sourceSession;
    
    [[nodiscard]] std::string GetPayloadString() const;
    void SetPayloadString(const std::string& str);
};

/**
 * @brief Statistics
 */
struct ServiceCommStatistics {
    std::atomic<uint64_t> messagesReceived{0};
    std::atomic<uint64_t> messagesSent{0};
    std::atomic<uint64_t> bytesReceived{0};
    std::atomic<uint64_t> bytesSent{0};
    std::atomic<uint64_t> connectionsTotal{0};
    std::atomic<uint64_t> connectionsFailed{0};
    std::atomic<uint64_t> authFailures{0};
    std::atomic<uint64_t> errors{0};
    std::array<std::atomic<uint64_t>, 32> byMessageType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct ServiceCommConfiguration {
    /// @brief Enable service communication
    bool enabled = true;
    
    /// @brief Is service side
    bool isService = true;
    
    /// @brief Pipe name
    std::wstring pipeName = ServiceCommConstants::SERVICE_PIPE_NAME;
    
    /// @brief Max clients
    uint32_t maxClients = ServiceCommConstants::MAX_CLIENTS;
    
    /// @brief Connection timeout (ms)
    uint32_t connectionTimeoutMs = ServiceCommConstants::CONNECTION_TIMEOUT_MS;
    
    /// @brief Heartbeat interval (ms)
    uint32_t heartbeatIntervalMs = ServiceCommConstants::HEARTBEAT_INTERVAL_MS;
    
    /// @brief Enable encryption
    bool enableEncryption = true;
    
    /// @brief Enable authentication
    bool enableAuthentication = true;
    
    /// @brief Enable rate limiting
    bool enableRateLimiting = true;
    
    /// @brief Max messages per second
    uint32_t maxMessagesPerSecond = 1000;
    
    /// @brief Audit logging
    bool enableAuditLog = true;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using MessageCallback = std::function<void(const std::string&)>;
using ServiceMessageCallback = std::function<void(const ServiceMessage&, const std::string& sessionId)>;
using ConnectionCallback = std::function<void(const ClientSession&, bool connected)>;
using CommandCallback = std::function<bool(MessageType cmd, const std::vector<uint8_t>& payload, std::vector<uint8_t>& response)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// SERVICE COMMUNICATION CLASS
// ============================================================================

/**
 * @class ServiceCommunication
 * @brief Enterprise service communication
 */
class ServiceCommunication final {
public:
    [[nodiscard]] static ServiceCommunication& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    ServiceCommunication(const ServiceCommunication&) = delete;
    ServiceCommunication& operator=(const ServiceCommunication&) = delete;
    ServiceCommunication(ServiceCommunication&&) = delete;
    ServiceCommunication& operator=(ServiceCommunication&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const ServiceCommConfiguration& config = {});
    [[nodiscard]] bool Start(bool isService);
    void Stop();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] bool IsRunning() const noexcept;
    [[nodiscard]] ServiceCommStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const ServiceCommConfiguration& config);
    [[nodiscard]] ServiceCommConfiguration GetConfiguration() const;

    // ========================================================================
    // CONNECTION (CLIENT SIDE)
    // ========================================================================
    
    /// @brief Connect to service
    [[nodiscard]] bool Connect(
        const std::wstring& pipeName = ServiceCommConstants::SERVICE_PIPE_NAME,
        uint32_t timeoutMs = ServiceCommConstants::CONNECTION_TIMEOUT_MS);
    
    /// @brief Disconnect from service
    void Disconnect();
    
    /// @brief Is connected
    [[nodiscard]] bool IsConnected() const noexcept;
    
    /// @brief Get connection state
    [[nodiscard]] ConnectionState GetConnectionState() const noexcept;

    // ========================================================================
    // MESSAGING
    // ========================================================================
    
    /// @brief Send command string (legacy)
    void SendCommand(const std::string& cmd);
    
    /// @brief Send message
    [[nodiscard]] bool SendMessage(const ServiceMessage& message);
    
    /// @brief Send message to specific session (server only)
    [[nodiscard]] bool SendMessage(const ServiceMessage& message, const std::string& sessionId);
    
    /// @brief Send request and wait for response
    [[nodiscard]] std::optional<ServiceMessage> SendRequest(
        const ServiceMessage& request,
        uint32_t timeoutMs = 5000);
    
    /// @brief Broadcast to all clients (server only)
    void Broadcast(const ServiceMessage& message);

    // ========================================================================
    // COMMANDS (HIGH-LEVEL API)
    // ========================================================================
    
    /// @brief Request scan
    [[nodiscard]] bool RequestScan(
        MessageType scanType,
        const std::vector<std::wstring>& targets = {},
        uint32_t options = 0);
    
    /// @brief Request scan stop
    [[nodiscard]] bool RequestStopScan();
    
    /// @brief Request status
    [[nodiscard]] std::optional<std::string> RequestStatus();
    
    /// @brief Request configuration
    [[nodiscard]] std::optional<std::string> RequestConfiguration();
    
    /// @brief Send configuration update
    [[nodiscard]] bool SendConfigurationUpdate(const std::string& configJson);

    // ========================================================================
    // EVENTS (HIGH-LEVEL API)
    // ========================================================================
    
    /// @brief Send threat event
    void SendThreatEvent(
        uint64_t threatId,
        const std::string& threatName,
        const std::wstring& filePath,
        uint8_t severity,
        uint8_t action);
    
    /// @brief Send progress event
    void SendProgressEvent(
        uint64_t taskId,
        uint16_t progress,
        uint64_t itemsProcessed,
        uint64_t itemsTotal,
        const std::wstring& currentItem = L"");
    
    /// @brief Send system alert
    void SendSystemAlert(
        const std::string& alertType,
        const std::string& message,
        uint8_t severity);

    // ========================================================================
    // SESSION MANAGEMENT (SERVER SIDE)
    // ========================================================================
    
    /// @brief Get connected clients
    [[nodiscard]] std::vector<ClientSession> GetConnectedClients() const;
    
    /// @brief Get client count
    [[nodiscard]] size_t GetClientCount() const noexcept;
    
    /// @brief Disconnect client
    [[nodiscard]] bool DisconnectClient(const std::string& sessionId);
    
    /// @brief Disconnect all clients
    void DisconnectAllClients();

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /// @brief Set message callback (legacy)
    void SetMessageCallback(std::function<void(const std::string&)> cb);
    
    void RegisterMessageCallback(ServiceMessageCallback callback);
    void RegisterConnectionCallback(ConnectionCallback callback);
    void RegisterCommandCallback(CommandCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] ServiceCommStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    ServiceCommunication();
    ~ServiceCommunication();
    
    std::unique_ptr<ServiceCommunicationImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetMessageTypeName(MessageType type) noexcept;
[[nodiscard]] std::string_view GetConnectionStateName(ConnectionState state) noexcept;
[[nodiscard]] std::string_view GetClientTypeName(ClientType type) noexcept;
[[nodiscard]] std::string_view GetAuthResultName(AuthResult result) noexcept;

/// @brief Create secure pipe security descriptor
[[nodiscard]] bool CreateSecurePipeSecurityDescriptor(SECURITY_ATTRIBUTES& sa);

/// @brief Calculate message checksum
[[nodiscard]] uint32_t CalculateMessageChecksum(const MessageHeader& header, const void* payload, size_t payloadSize);

/// @brief Verify message checksum
[[nodiscard]] bool VerifyMessageChecksum(const MessageHeader& header, const void* payload, size_t payloadSize);

}  // namespace Communication
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_SERVICE_SEND(cmd) \
    ::ShadowStrike::Communication::ServiceCommunication::Instance().SendCommand(cmd)

#define SS_SERVICE_IS_CONNECTED() \
    ::ShadowStrike::Communication::ServiceCommunication::Instance().IsConnected()
