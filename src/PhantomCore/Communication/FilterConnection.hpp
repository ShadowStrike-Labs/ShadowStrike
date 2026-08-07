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
 * @file FilterConnection.hpp
 * @brief Filter Manager connection management for ShadowStrike NGAV
 *
 * Manages the low-level connection to the kernel minifilter driver
 * using Windows Filter Manager APIs (fltlib.h).
 *
 * Thread Safety: All public methods are thread-safe.
 * Pattern: PIMPL
 *
 * @copyright ShadowStrike NGAV - Enterprise Security Platform
 */

#pragma once

#include "Communication.hpp"
#include <memory>
#include <functional>
#include <span>

namespace ShadowStrike {
namespace Communication {

// Forward declaration for PIMPL
class FilterConnectionImpl;

/**
 * @class FilterConnection
 * @brief Low-level Filter Manager port connection
 *
 * Responsibilities:
 * - Establish connection via FilterConnectCommunicationPort
 * - Receive messages via FilterGetMessage
 * - Send replies via FilterReplyMessage
 * - Send control messages via FilterSendMessage
 * - Handle connection lifecycle and errors
 *
 * This class is used internally by IPCManager and MessageDispatcher.
 * Most users should use IPCManager instead of this class directly.
 */
class FilterConnection final {
public:
    /**
     * @brief Construct a new FilterConnection
     * @param portName Name of the kernel port (e.g., L"\\ShadowStrikePort")
     */
    explicit FilterConnection(const std::wstring& portName = SS_COMM_PORT_NAME);

    ~FilterConnection();

    // Non-copyable, movable
    FilterConnection(const FilterConnection&) = delete;
    FilterConnection& operator=(const FilterConnection&) = delete;
    FilterConnection(FilterConnection&& other) noexcept;
    FilterConnection& operator=(FilterConnection&& other) noexcept;

    //=========================================================================
    // Connection Lifecycle
    //=========================================================================

    /**
     * @brief Connect to the kernel filter port
     * @param registerAsPrimaryScanner When true, the connection advertises
     *        itself to the kernel minifilter as the primary scanner port
     *        (ConnectionContext type == 1). The kernel routes scan requests
     *        and notifications exclusively to this connection and requires it
     *        to have an established session key. Exactly one connection per
     *        client process must set this; auxiliary channels (e.g. the
     *        threat-intel push connection) must pass false.
     * @return true if connection successful
     */
    [[nodiscard]] bool Connect(bool registerAsPrimaryScanner = false);

    /**
     * @brief Disconnect from the kernel filter port
     */
    void Disconnect();

    /**
     * @brief Check if currently connected
     * @return true if connected
     */
    [[nodiscard]] bool IsConnected() const noexcept;

    /**
     * @brief Get the port handle (for advanced use)
     * @return Native HANDLE or nullptr if not connected
     */
    [[nodiscard]] void* GetHandle() const noexcept;

    //=========================================================================
    // Message Operations
    //=========================================================================

    /**
     * @brief Receive a message from the kernel driver
     * @param buffer Buffer to receive message into
     * @param timeoutMs Timeout in milliseconds (0 = infinite)
     * @return Number of bytes received, or 0 on timeout/error
     *
     * This is a blocking call that waits for a message from the kernel.
     * The buffer must be at least MAX_MESSAGE_SIZE bytes.
     */
    /**
     * @brief Outcome of a receive attempt on the kernel port.
     *
     * A frame can arrive intact at the FRAMING level and still be unusable at
     * the PAYLOAD level, because HMAC verification or AES-GCM decryption failed.
     * Those two outcomes must be distinguishable to the caller, and reporting
     * only a byte count collapsed them into one.
     *
     * Filter Manager writes FILTER_MESSAGE_HEADER itself, in cleartext, ahead of
     * our own encrypted payload. So on a frame whose payload we cannot decrypt,
     * the MessageId is still valid and the kernel thread parked inside
     * FltSendMessage can - and must - still be answered. Returning a bare 0 left
     * that thread to wait out its entire timeout budget.
     *
     * That is not merely a latency cost. The driver's scan-bridge circuit
     * breaker trips on reply-timeout RATE (SB_CIRCUIT_TIMEOUT_TRIP_COUNT within
     * SB_CIRCUIT_TIMEOUT_WINDOW_MS) and then short-circuits the create path for
     * SB_CIRCUIT_BREAKER_RECOVERY_MS, during which files are not scanned at all.
     * Silently dropping undecryptable frames therefore fed a counter that can
     * switch scanning off entirely, so answering is a detection requirement
     * rather than an optimisation.
     */
    struct ReceiveResult {
        /// Usable cleartext bytes in the buffer. Zero means DO NOT parse it.
        size_t payloadBytes = 0;

        /// Filter Manager MessageId of a frame still awaiting a reply, or zero
        /// when nothing is owed (no frame arrived, or it was one-way).
        uint64_t replyOwedId = 0;

        [[nodiscard]] bool HasPayload() const noexcept { return payloadBytes != 0; }
        [[nodiscard]] bool ReplyOwed()  const noexcept { return replyOwedId  != 0; }
    };

    [[nodiscard]] ReceiveResult GetMessage(std::span<uint8_t> buffer, uint32_t timeoutMs = 0);

    /**
     * @brief Send a reply to a kernel message
     * @param replyBuffer Buffer containing the reply
     * @param originalMessageId Message ID being replied to
     * @return true if reply sent successfully
     */
    [[nodiscard]] bool ReplyMessage(std::span<const uint8_t> replyBuffer, uint64_t originalMessageId);

    /**
     * @brief Send a control message to the kernel (with response)
     * @param sendBuffer Message to send
     * @param replyBuffer Buffer for reply
     * @param timeoutMs Timeout in milliseconds
     * @return Number of bytes in reply, or 0 on error
     */
    [[nodiscard]] size_t SendMessage(
        std::span<const uint8_t> sendBuffer,
        std::span<uint8_t> replyBuffer,
        uint32_t timeoutMs = DEFAULT_REPLY_TIMEOUT_MS
    );

    /**
     * @brief Send a control message to the kernel (no response expected)
     * @param sendBuffer Message to send
     * @return true if sent successfully
     */
    [[nodiscard]] bool SendMessageNoReply(std::span<const uint8_t> sendBuffer);

    //=========================================================================
    // Error Handling
    //=========================================================================

    /**
     * @brief Get the last error code
     * @return Windows error code (HRESULT)
     */
    [[nodiscard]] int32_t GetLastError() const noexcept;

    /**
     * @brief Get the last error message
     * @return Human-readable error description
     */
    [[nodiscard]] std::string GetLastErrorMessage() const;

    //=========================================================================
    // Diagnostics
    //=========================================================================

    /**
     * @brief Get connection statistics
     * @return Statistics structure
     */
    [[nodiscard]] CommunicationStatisticsSnapshot GetStatistics() const;

    /**
     * @brief Get status as JSON
     * @return JSON string
     */
    [[nodiscard]] std::string ToJson() const;

private:
    std::unique_ptr<FilterConnectionImpl> m_impl;
};

} // namespace Communication
} // namespace ShadowStrike
