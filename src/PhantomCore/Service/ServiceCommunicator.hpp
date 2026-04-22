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
 * @file ServiceCommunicator.hpp
 * @brief Enterprise-grade IPC engine for secure communication between the
 *        privileged ShadowStrike service and user-mode components (UI, CLI, Tray).
 *
 * Implements a secure, asynchronous Named Pipe server with strict access control
 * (ACLs) to prevent privilege escalation. Handles command dispatching, status
 * broadcasting, and client session management.
 *
 * SECURITY FEATURES:
 * ==================
 * - Secure Named Pipes (\\.\pipe\ShadowStrikeServicePipe)
 * - Strict SDDL (Security Descriptor Definition Language) enforcement
 *   (Allow: SYSTEM, Administrators; Deny: Everyone else)
 * - Message size limits to prevent DoS
 * - Input validation and sanitization
 * - Client impersonation checks
 *
 * ARCHITECTURE:
 * =============
 * - Uses I/O Completion Ports (IOCP) or Overlapped I/O for scalability
 * - Thread pool integration for request processing
 * - JSON-based messaging protocol for extensibility
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
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include <shared_mutex>
#include <map>
#include <chrono>
#include <optional>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
namespace ShadowStrike::Service {
    class ServiceCommunicatorImpl;
}

namespace ShadowStrike {
namespace Service {

// ============================================================================
// CONSTANTS
// ============================================================================
namespace CommunicationConstants {
    constexpr const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\ShadowStrikeServicePipe";

    // Default buffer sizes
    constexpr uint32_t IN_BUFFER_SIZE = 64 * 1024;  // 64KB
    constexpr uint32_t OUT_BUFFER_SIZE = 64 * 1024; // 64KB

    // Timeouts
    constexpr uint32_t CONNECT_TIMEOUT_MS = 5000;
    constexpr uint32_t WRITE_TIMEOUT_MS = 2000;

    // Limits
    constexpr size_t MAX_CONCURRENT_CLIENTS = 10;
    constexpr size_t MAX_MESSAGE_SIZE = 10 * 1024 * 1024; // 10MB limit

    // Magic header for binary protocol validation (if used)
    constexpr uint32_t PROTOCOL_MAGIC = 0x53534156; // "SSAV"
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Communication command types
 */
enum class CommandType : uint32_t {
    Unknown             = 0,
    Heartbeat           = 1,    ///< Keep-alive
    GetStatus           = 10,   ///< Request service status
    StartScan           = 20,   ///< Initiate scan
    StopScan            = 21,   ///< Cancel scan
    UpdateConfig        = 30,   ///< Update configuration
    GetConfig           = 31,   ///< Retrieve configuration
    UpdateSignatures    = 40,   ///< Trigger update
    QuarantineAction    = 50,   ///< Restore/Delete quarantined items
    ThreatAlert         = 100,  ///< Server->Client: Threat detected
    LogMessage          = 101,  ///< Server->Client: Log stream

    // ── Server -> Client push events (v2 protocol) ─────────────────────────
    ProtectionStateChanged  = 102,  ///< Real-time protection state flipped
    ScanProgressEvent       = 103,  ///< Async scan progress update
    HeadlineStateChanged    = 104,  ///< Headline protection indicator changed
    AuthFailed              = 105,  ///< Service rejected a client auth attempt
    PgtiFeedUpdated         = 106,  ///< PGTI feed health or status changed
    RecommendationsChanged  = 107,  ///< Active recommendation set changed

    // ── Extended UI command set (v2 protocol) ──────────────────────────────
    AuthHandshake           = 199,  ///< Client presents session auth token

    // Module management
    ListModules             = 200,  ///< Enumerate available protection modules
    SetModuleEnabled        = 201,  ///< Enable / disable a named module
    SetModuleMode           = 202,  ///< Change a module's operating mode
    GetModuleConfig         = 203,  ///< Retrieve module configuration blob
    SetModuleConfig         = 204,  ///< Update module configuration blob

    // Protection control
    PauseProtection         = 210,  ///< Temporarily suspend real-time protection
    ResumeProtection        = 211,  ///< Resume real-time protection

    // Scan control
    // NOTE: Enum member names StartScan and StopScan are already used at values 20
    // and 21 above (existing wire protocol).  In the v2 UI protocol, the dispatcher
    // routes these commands by CommandType value; numeric codes 220 and 221 are
    // reserved in the v2 spec as wire-level routing values but are NOT represented
    // as named C++ enum members to avoid duplicate-name ODR issues.  Dispatcher
    // implementations must use static_cast<CommandType>(220) and (221) or their
    // own routing tables when handling those v2 codes.
    // Similarly, QuarantineAction is at 50 (legacy); 231 is the v2 dispatch code.
    GetScanProgress         = 222,  ///< Poll in-progress scan completion %

    // Quarantine — see also QuarantineAction=50 (legacy restore/delete verb)
    ListQuarantine          = 230,  ///< List all quarantined items

    // Reporting
    GetReports              = 240,  ///< Retrieve historical detection reports
    GetDashboard            = 250,  ///< Dashboard summary (threats, scans, modules)

    // Event subscription
    SubscribeEvents         = 260,  ///< Register for real-time push events

    // PGTI feed management
    ListPGTIFeeds           = 270,  ///< Enumerate configured threat-intel feeds
    SetPGTIFeedEnabled      = 271,  ///< Enable / disable a specific feed
    RefreshPGTIFeeds        = 272,  ///< Force-refresh all enabled feeds

    // Zero-Trust
    GetZeroTrustState       = 280,  ///< Query current Zero-Trust posture
    SetZeroTrustConfig      = 281,  ///< Update Zero-Trust policy
    AnswerZeroTrustPrompt   = 282,  ///< User response to a Zero-Trust prompt

    // Recommendations
    GetRecommendations      = 290,  ///< List pending security recommendations
    DismissRecommendation   = 291,  ///< Dismiss a specific recommendation
};

/**
 * @brief Client connection status
 */
enum class ClientStatus : uint8_t {
    Disconnected = 0,
    Connecting   = 1,
    Connected    = 2,
    Authenticated= 3,
    Error        = 4
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief IPC Message Structure
 */
struct IpcMessage {
    uint32_t magic = CommunicationConstants::PROTOCOL_MAGIC;
    CommandType type = CommandType::Unknown;
    uint32_t payloadSize = 0;
    uint64_t timestamp = 0;
    // Payload follows immediately after header in wire format
    std::vector<uint8_t> payload;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics for the communication subsystem
 */
struct CommunicatorStats {
    std::atomic<uint64_t> messagesReceived{0};
    std::atomic<uint64_t> messagesSent{0};
    std::atomic<uint64_t> bytesReceived{0};
    std::atomic<uint64_t> bytesSent{0};
    std::atomic<uint64_t> connectionAttempts{0};
    std::atomic<uint64_t> activeConnections{0};
    std::atomic<uint64_t> droppedPackets{0};
    std::atomic<uint64_t> authFailures{0};

    CommunicatorStats() noexcept = default;
    CommunicatorStats(const CommunicatorStats& other) noexcept;
    CommunicatorStats& operator=(const CommunicatorStats& other) noexcept;
    CommunicatorStats(CommunicatorStats&&) = delete;
    CommunicatorStats& operator=(CommunicatorStats&&) = delete;

    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/**
 * @brief Callback for handling received commands
 * @param cmd The command type
 * @param payload The raw payload data
 * @param responsePayload [Out] Data to send back to client
 * @return true if handled successfully
 */
using CommandHandler = std::function<bool(CommandType cmd,
                                          const std::vector<uint8_t>& payload,
                                          std::vector<uint8_t>& responsePayload)>;

/**
 * @brief Callback for connection events
 */
using ConnectionCallback = std::function<void(uint64_t clientId, bool connected)>;

// ============================================================================
// SERVICE COMMUNICATOR CLASS
// ============================================================================

/**
 * @class ServiceCommunicator
 * @brief Manages secure IPC between the service and clients.
 */
class ServiceCommunicator final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    [[nodiscard]] static ServiceCommunicator& Instance() noexcept;

    // Delete copy/move
    ServiceCommunicator(const ServiceCommunicator&) = delete;
    ServiceCommunicator& operator=(const ServiceCommunicator&) = delete;
    ServiceCommunicator(ServiceCommunicator&&) = delete;
    ServiceCommunicator& operator=(ServiceCommunicator&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initialize the IPC server
     * @return true if initialized successfully (security descriptor created)
     */
    [[nodiscard]] bool Initialize();

    /**
     * @brief Start accepting connections
     * @return true if server started
     */
    [[nodiscard]] bool Start();

    /**
     * @brief Stop the server and close connections
     */
    void Stop();

    /**
     * @brief Check if server is running
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    // ========================================================================
    // COMMUNICATION
    // ========================================================================

    /**
     * @brief Register a handler for a specific command type
     * @param type Command type to handle
     * @param handler Function to execute
     */
    void RegisterHandler(CommandType type, CommandHandler handler);

    /**
     * @brief Broadcast a message to all connected and authenticated clients
     * @param type Message type
     * @param payload Data payload
     * @return Number of clients reached
     */
    [[nodiscard]] size_t Broadcast(CommandType type, const std::string& payload);

    /**
     * @brief Broadcast binary data
     */
    [[nodiscard]] size_t Broadcast(CommandType type, const std::vector<uint8_t>& payload);

    /**
     * @brief Broadcast a pre-serialised 24-byte Envelope to all authenticated clients.
     *
     * The serialised envelope is written as-is (caller must use EventPush::Build*
     * or Envelope::Serialize to produce it). Each client is subject to an
     * independent per-event-type token-bucket rate limit (20 events/sec, burst 20).
     * Unauthenticated clients are silently skipped.
     *
     * @param eventType           Command type (used for rate-bucket keying only).
     * @param serializedEnvelope  Pre-built wire bytes including 24-byte header.
     * @return Number of clients that received the message.
     */
    [[nodiscard]] size_t BroadcastEvent(CommandType                       eventType,
                                        const std::vector<std::uint8_t>& serializedEnvelope);

    /**
     * @brief Mark a client as authenticated so it receives BroadcastEvent messages.
     *
     * Called by the AuthHandshake command handler after successful token
     * verification. Safe to call from any thread.
     *
     * @param clientId  The client identifier assigned during connection.
     */
    void MarkClientAuthenticated(std::uint64_t clientId);

    /**
     * @brief Revoke a client's authenticated status.
     *
     * Idempotent. Called automatically when the client disconnects.
     *
     * @param clientId  The client identifier to revoke.
     */
    void RevokeClientAuthentication(std::uint64_t clientId);

    // ========================================================================
    // DIAGNOSTICS & MANAGEMENT
    // ========================================================================

    /**
     * @brief Get current statistics
     */
    [[nodiscard]] CommunicatorStats GetStats() const;

    /**
     * @brief Reset statistics
     */
    void ResetStats();

    /**
     * @brief Perform self-test of IPC mechanisms
     */
    [[nodiscard]] bool SelfTest();

    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    ServiceCommunicator();
    ~ServiceCommunicator();

    // PIMPL
    std::unique_ptr<ServiceCommunicatorImpl> m_impl;

    static std::atomic<bool> s_instanceCreated;
};

} // namespace Service
} // namespace ShadowStrike
