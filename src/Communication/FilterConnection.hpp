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
    explicit FilterConnection(const std::wstring& portName = SHADOWSTRIKE_PORT_NAME);

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
     * @return true if connection successful
     */
    [[nodiscard]] bool Connect();

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
    [[nodiscard]] size_t GetMessage(std::span<uint8_t> buffer, uint32_t timeoutMs = 0);

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
    [[nodiscard]] CommunicationStatistics GetStatistics() const;

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
