/**
 * @file MessageDispatcher.hpp
 * @brief Message routing and dispatching for ShadowStrike NGAV
 *
 * Routes incoming kernel messages to appropriate handlers and
 * manages the reply pipeline.
 *
 * Thread Safety: All public methods are thread-safe.
 * Pattern: PIMPL
 *
 * @copyright ShadowStrike NGAV - Enterprise Security Platform
 */

#pragma once

#include "Communication.hpp"
#include "FilterConnection.hpp"
#include <memory>
#include <span>
#include <future>

namespace ShadowStrike {
namespace Communication {

// Forward declaration for PIMPL
class MessageDispatcherImpl;

/**
 * @class MessageDispatcher
 * @brief Routes kernel messages to registered handlers
 *
 * Responsibilities:
 * - Parse incoming message headers
 * - Deserialize message payloads to C++ structures
 * - Route to appropriate callback based on message type
 * - Serialize and send replies
 * - Handle unknown message types gracefully
 * - Track dispatch statistics
 */
class MessageDispatcher final {
public:
    /**
     * @brief Construct a new MessageDispatcher
     * @param connection Filter connection for sending replies
     */
    explicit MessageDispatcher(FilterConnection& connection);

    ~MessageDispatcher();

    // Non-copyable
    MessageDispatcher(const MessageDispatcher&) = delete;
    MessageDispatcher& operator=(const MessageDispatcher&) = delete;

    //=========================================================================
    // Callback Registration
    //=========================================================================

    /**
     * @brief Register handler for file scan requests
     * @param callback Handler function
     */
    void RegisterFileScanHandler(FileScanCallback callback);

    /**
     * @brief Register handler for process scan requests
     * @param callback Handler function
     */
    void RegisterProcessScanHandler(ProcessNotifyCallback callback);

    /**
     * @brief Register handler for registry scan requests
     * @param callback Handler function
     */
    void RegisterRegistryScanHandler(RegistryNotifyCallback callback);

    /**
     * @brief Register handler for file notifications (no reply)
     * @param callback Handler function
     */
    void RegisterFileNotifyHandler(FileNotifyCallback callback);

    /**
     * @brief Register handler for process notifications (no reply)
     * @param callback Handler function
     */
    void RegisterProcessNotifyHandler(ProcessEventCallback callback);

    /**
     * @brief Register handler for registry notifications (no reply)
     * @param callback Handler function
     */
    void RegisterRegistryNotifyHandler(RegistryEventCallback callback);

    //=========================================================================
    // Message Dispatching
    //=========================================================================

    /**
     * @brief Dispatch a raw message buffer
     * @param messageBuffer Raw message from kernel
     * @return true if message was handled successfully
     *
     * This method:
     * 1. Validates the message header
     * 2. Deserializes the payload
     * 3. Calls the appropriate handler
     * 4. Sends the reply if required
     */
    [[nodiscard]] bool DispatchMessage(std::span<const uint8_t> messageBuffer);

    /**
     * @brief Dispatch message asynchronously
     * @param messageBuffer Raw message from kernel
     * @return Future that completes when dispatch is done
     */
    [[nodiscard]] std::future<bool> DispatchMessageAsync(std::span<const uint8_t> messageBuffer);

    //=========================================================================
    // Message Parsing (Static utilities)
    //=========================================================================

    /**
     * @brief Parse a file scan request from raw buffer
     * @param data Raw payload data
     * @return Parsed request or nullopt on error
     */
    [[nodiscard]] static std::optional<FileScanRequest> ParseFileScanRequest(std::span<const uint8_t> data);

    /**
     * @brief Parse a process notification from raw buffer
     * @param data Raw payload data
     * @return Parsed notification or nullopt on error
     */
    [[nodiscard]] static std::optional<ProcessNotification> ParseProcessNotification(std::span<const uint8_t> data);

    /**
     * @brief Parse a registry notification from raw buffer
     * @param data Raw payload data
     * @return Parsed notification or nullopt on error
     */
    [[nodiscard]] static std::optional<RegistryNotification> ParseRegistryNotification(std::span<const uint8_t> data);

    /**
     * @brief Serialize a scan verdict reply to buffer
     * @param reply Reply structure
     * @return Serialized buffer
     */
    [[nodiscard]] static std::vector<uint8_t> SerializeVerdictReply(const ScanVerdictReply& reply);

    //=========================================================================
    // Configuration
    //=========================================================================

    /**
     * @brief Set the default verdict for unhandled messages
     * @param verdict Default verdict
     */
    void SetDefaultVerdict(ScanVerdict verdict);

    /**
     * @brief Set whether to block on timeout
     * @param block true to block, false to allow
     */
    void SetBlockOnTimeout(bool block);

    /**
     * @brief Set whether to block on error
     * @param block true to block, false to allow
     */
    void SetBlockOnError(bool block);

    //=========================================================================
    // Statistics
    //=========================================================================

    /**
     * @brief Get dispatch statistics
     */
    struct DispatchStatistics {
        std::atomic<uint64_t> messagesDispatched{0};
        std::atomic<uint64_t> fileScanRequests{0};
        std::atomic<uint64_t> processScanRequests{0};
        std::atomic<uint64_t> registryScanRequests{0};
        std::atomic<uint64_t> fileNotifications{0};
        std::atomic<uint64_t> processNotifications{0};
        std::atomic<uint64_t> registryNotifications{0};
        std::atomic<uint64_t> unknownMessages{0};
        std::atomic<uint64_t> parseErrors{0};
        std::atomic<uint64_t> handlerErrors{0};
        std::atomic<uint64_t> repliesSent{0};
        std::atomic<uint64_t> replyErrors{0};
        std::atomic<uint64_t> totalProcessingTimeUs{0};

        void Reset() noexcept;
        [[nodiscard]] std::string ToJson() const;
    };

    /**
     * @brief Get dispatch statistics
     * @return Reference to statistics
     */
    [[nodiscard]] const DispatchStatistics& GetStatistics() const noexcept;

    /**
     * @brief Reset statistics
     */
    void ResetStatistics() noexcept;

    /**
     * @brief Get status as JSON
     * @return JSON string
     */
    [[nodiscard]] std::string ToJson() const;

private:
    std::unique_ptr<MessageDispatcherImpl> m_impl;
};

} // namespace Communication
} // namespace ShadowStrike
