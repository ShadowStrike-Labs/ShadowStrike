/**
 * @file MessageDispatcher.cpp
 * @brief Message routing and dispatching implementation
 *
 * CRITICAL SAFETY REQUIREMENTS:
 * - All message buffers are bounds-checked before access
 * - All handlers are wrapped in try-catch to prevent crashes
 * - Fail-open on errors (allow operation, log for analysis)
 * - Thread-safe dispatch from multiple worker threads
 * - Latency tracking for performance monitoring
 *
 * @copyright ShadowStrike NGAV - Enterprise Security Platform
 */

#include "MessageDispatcher.hpp"
#include "FilterConnection.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"

#include <algorithm>
#include <sstream>
#include <chrono>

namespace ShadowStrike {
namespace Communication {

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class MessageDispatcherImpl {
public:
    explicit MessageDispatcherImpl(FilterConnection& connection)
        : m_connection(connection) {
        m_stats.startTime = std::chrono::steady_clock::now();
    }

    ~MessageDispatcherImpl() = default;

    // Non-copyable
    MessageDispatcherImpl(const MessageDispatcherImpl&) = delete;
    MessageDispatcherImpl& operator=(const MessageDispatcherImpl&) = delete;

    //=========================================================================
    // Callback Registration
    //=========================================================================

    void RegisterFileScanHandler(FileScanCallback callback) {
        std::lock_guard<std::mutex> lock(m_handlerMutex);
        m_fileScanHandler = std::move(callback);
        Utils::Logger::Info("[MessageDispatcher] Registered file scan handler");
    }

    void RegisterProcessScanHandler(ProcessNotifyCallback callback) {
        std::lock_guard<std::mutex> lock(m_handlerMutex);
        m_processScanHandler = std::move(callback);
        Utils::Logger::Info("[MessageDispatcher] Registered process scan handler");
    }

    void RegisterRegistryScanHandler(RegistryNotifyCallback callback) {
        std::lock_guard<std::mutex> lock(m_handlerMutex);
        m_registryScanHandler = std::move(callback);
        Utils::Logger::Info("[MessageDispatcher] Registered registry scan handler");
    }

    void RegisterFileNotifyHandler(FileNotifyCallback callback) {
        std::lock_guard<std::mutex> lock(m_handlerMutex);
        m_fileNotifyHandler = std::move(callback);
    }

    void RegisterProcessNotifyHandler(ProcessEventCallback callback) {
        std::lock_guard<std::mutex> lock(m_handlerMutex);
        m_processNotifyHandler = std::move(callback);
    }

    void RegisterRegistryNotifyHandler(RegistryEventCallback callback) {
        std::lock_guard<std::mutex> lock(m_handlerMutex);
        m_registryNotifyHandler = std::move(callback);
    }

    //=========================================================================
    // Message Dispatching
    //=========================================================================

    [[nodiscard]] bool DispatchMessage(std::span<const uint8_t> messageBuffer) {
        auto startTime = std::chrono::steady_clock::now();

        // CRITICAL: Validate buffer before ANY access
        if (messageBuffer.empty()) {
            Utils::Logger::Error("[MessageDispatcher] Empty message buffer");
            m_stats.parseErrors++;
            return false;
        }

        if (messageBuffer.size() < sizeof(MessageHeader)) {
            Utils::Logger::Error("[MessageDispatcher] Buffer too small for header: {} < {}",
                               messageBuffer.size(), sizeof(MessageHeader));
            m_stats.parseErrors++;
            return false;
        }

        // CRITICAL: Safe header access with bounds check
        const MessageHeader* header =
            reinterpret_cast<const MessageHeader*>(messageBuffer.data());

        // Validate header fields
        if (!header->IsValid()) {
            Utils::Logger::Warn("[MessageDispatcher] Invalid message header "
                              "(magic=0x{:08X}, version={}, size={})",
                              header->magic, header->version, header->totalSize);
            m_stats.parseErrors++;
            return false;
        }

        // CRITICAL: Verify total size matches buffer
        if (header->totalSize > messageBuffer.size()) {
            Utils::Logger::Warn("[MessageDispatcher] Message size mismatch: {} > {}",
                              header->totalSize, messageBuffer.size());
            m_stats.parseErrors++;
            return false;
        }

        m_stats.messagesDispatched++;

        // Extract payload (data after header)
        const size_t payloadOffset = sizeof(MessageHeader);
        const size_t payloadSize = header->dataSize;

        if (payloadOffset + payloadSize > messageBuffer.size()) {
            Utils::Logger::Warn("[MessageDispatcher] Payload extends beyond buffer");
            m_stats.parseErrors++;
            return false;
        }

        std::span<const uint8_t> payload(
            messageBuffer.data() + payloadOffset,
            payloadSize
        );

        // Dispatch based on message type
        bool handled = false;
        bool needsReply = false;
        ScanVerdictReply reply;
        reply.messageId = header->messageId;
        reply.verdict = m_defaultVerdict;
        reply.resultCode = 0;
        reply.threatDetected = false;
        reply.threatScore = 0;
        reply.shouldCache = true;
        reply.cacheTTL = 60;

        MessageType msgType = static_cast<MessageType>(header->messageType);

        try {
            switch (msgType) {
                //=============================================================
                // Scan requests (require reply)
                //=============================================================
                case MessageType::FileScanOnOpen:
                case MessageType::FileScanOnExecute:
                case MessageType::FileScanOnWrite:
                case MessageType::FileScanOnClose: {
                    needsReply = true;
                    m_stats.fileScanRequests++;

                    auto request = ParseFileScanRequest(payload);
                    if (request.has_value()) {
                        std::lock_guard<std::mutex> lock(m_handlerMutex);
                        if (m_fileScanHandler) {
                            try {
                                reply = m_fileScanHandler(request.value());
                                handled = true;
                            } catch (const std::exception& e) {
                                Utils::Logger::Error(
                                    "[MessageDispatcher] File scan handler exception: {}",
                                    e.what());
                                m_stats.handlerErrors++;
                                // Fail-open: allow on error
                                reply.verdict = ScanVerdict::Allow;
                            }
                        }
                    } else {
                        m_stats.parseErrors++;
                    }
                    break;
                }

                case MessageType::ProcessScan: {
                    needsReply = true;
                    m_stats.processScanRequests++;

                    auto notification = ParseProcessNotification(payload);
                    if (notification.has_value()) {
                        std::lock_guard<std::mutex> lock(m_handlerMutex);
                        if (m_processScanHandler) {
                            try {
                                reply = m_processScanHandler(notification.value());
                                handled = true;
                            } catch (const std::exception& e) {
                                Utils::Logger::Error(
                                    "[MessageDispatcher] Process scan handler exception: {}",
                                    e.what());
                                m_stats.handlerErrors++;
                                reply.verdict = ScanVerdict::Allow;
                            }
                        }
                    } else {
                        m_stats.parseErrors++;
                    }
                    break;
                }

                case MessageType::RegistryScan: {
                    needsReply = true;
                    m_stats.registryScanRequests++;

                    auto notification = ParseRegistryNotification(payload);
                    if (notification.has_value()) {
                        std::lock_guard<std::mutex> lock(m_handlerMutex);
                        if (m_registryScanHandler) {
                            try {
                                reply = m_registryScanHandler(notification.value());
                                handled = true;
                            } catch (const std::exception& e) {
                                Utils::Logger::Error(
                                    "[MessageDispatcher] Registry scan handler exception: {}",
                                    e.what());
                                m_stats.handlerErrors++;
                                reply.verdict = ScanVerdict::Allow;
                            }
                        }
                    } else {
                        m_stats.parseErrors++;
                    }
                    break;
                }

                //=============================================================
                // Notifications (no reply required)
                //=============================================================
                case MessageType::NotifyFileCreate:
                case MessageType::NotifyFileModify:
                case MessageType::NotifyFileDelete:
                case MessageType::NotifyFileRename: {
                    m_stats.fileNotifications++;

                    auto request = ParseFileScanRequest(payload);
                    if (request.has_value()) {
                        std::lock_guard<std::mutex> lock(m_handlerMutex);
                        if (m_fileNotifyHandler) {
                            try {
                                m_fileNotifyHandler(request.value());
                                handled = true;
                            } catch (...) {
                                m_stats.handlerErrors++;
                            }
                        }
                    }
                    break;
                }

                case MessageType::NotifyProcessCreate:
                case MessageType::NotifyProcessTerminate:
                case MessageType::NotifyImageLoad:
                case MessageType::NotifyThreadCreate: {
                    m_stats.processNotifications++;

                    auto notification = ParseProcessNotification(payload);
                    if (notification.has_value()) {
                        std::lock_guard<std::mutex> lock(m_handlerMutex);
                        if (m_processNotifyHandler) {
                            try {
                                m_processNotifyHandler(notification.value());
                                handled = true;
                            } catch (...) {
                                m_stats.handlerErrors++;
                            }
                        }
                    }
                    break;
                }

                case MessageType::NotifyRegistryCreate:
                case MessageType::NotifyRegistrySetValue:
                case MessageType::NotifyRegistryDelete: {
                    m_stats.registryNotifications++;

                    auto notification = ParseRegistryNotification(payload);
                    if (notification.has_value()) {
                        std::lock_guard<std::mutex> lock(m_handlerMutex);
                        if (m_registryNotifyHandler) {
                            try {
                                m_registryNotifyHandler(notification.value());
                                handled = true;
                            } catch (...) {
                                m_stats.handlerErrors++;
                            }
                        }
                    }
                    break;
                }

                //=============================================================
                // Control messages
                //=============================================================
                case MessageType::ControlPing: {
                    // Simple ping - just reply with success
                    needsReply = true;
                    reply.verdict = ScanVerdict::Allow;
                    reply.resultCode = 0;
                    handled = true;
                    break;
                }

                default: {
                    m_stats.unknownMessages++;
                    Utils::Logger::Warn("[MessageDispatcher] Unknown message type: {}",
                                       header->messageType);
                    break;
                }
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("[MessageDispatcher] Dispatch exception: {}", e.what());
            m_stats.handlerErrors++;
            // Ensure we still reply if needed
            reply.verdict = m_blockOnError ? ScanVerdict::Block : ScanVerdict::Allow;
        } catch (...) {
            Utils::Logger::Error("[MessageDispatcher] Unknown dispatch exception");
            m_stats.handlerErrors++;
            reply.verdict = m_blockOnError ? ScanVerdict::Block : ScanVerdict::Allow;
        }

        // Send reply if required
        if (needsReply) {
            auto replyBuffer = SerializeVerdictReply(reply);

            if (!m_connection.ReplyMessage(replyBuffer, header->messageId)) {
                Utils::Logger::Warn("[MessageDispatcher] Failed to send reply for msg {}",
                                   header->messageId);
                m_stats.replyErrors++;
            } else {
                m_stats.repliesSent++;
            }
        }

        // Update timing statistics
        auto endTime = std::chrono::steady_clock::now();
        auto durationUs = std::chrono::duration_cast<std::chrono::microseconds>(
            endTime - startTime).count();
        m_stats.totalProcessingTimeUs += static_cast<uint64_t>(durationUs);

        return handled;
    }

    [[nodiscard]] std::future<bool> DispatchMessageAsync(
        std::span<const uint8_t> messageBuffer) {
        // Copy buffer for async processing
        std::vector<uint8_t> bufferCopy(messageBuffer.begin(), messageBuffer.end());

        return std::async(std::launch::async, [this, buffer = std::move(bufferCopy)]() {
            return DispatchMessage(std::span<const uint8_t>(buffer));
        });
    }

    //=========================================================================
    // Configuration
    //=========================================================================

    void SetDefaultVerdict(ScanVerdict verdict) {
        m_defaultVerdict = verdict;
    }

    void SetBlockOnTimeout(bool block) {
        m_blockOnTimeout = block;
    }

    void SetBlockOnError(bool block) {
        m_blockOnError = block;
    }

    //=========================================================================
    // Statistics
    //=========================================================================

    [[nodiscard]] const MessageDispatcher::DispatchStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    [[nodiscard]] std::string ToJson() const {
        return m_stats.ToJson();
    }

    //=========================================================================
    // Static Parsing Utilities
    //=========================================================================

    [[nodiscard]] static std::optional<FileScanRequest> ParseFileScanRequest(
        std::span<const uint8_t> data) {

        // CRITICAL: Validate minimum size
        if (data.size() < sizeof(FileScanRequestData)) {
            Utils::Logger::Warn("[MessageDispatcher] FileScanRequest too small: {}",
                              data.size());
            return std::nullopt;
        }

        const FileScanRequestData* raw =
            reinterpret_cast<const FileScanRequestData*>(data.data());

        // Validate variable-length fields don't exceed buffer
        size_t requiredSize = sizeof(FileScanRequestData) +
                             (raw->pathLength * sizeof(wchar_t)) +
                             (raw->processNameLength * sizeof(wchar_t));

        if (data.size() < requiredSize) {
            Utils::Logger::Warn("[MessageDispatcher] FileScanRequest buffer too small "
                              "for variable data: {} < {}",
                              data.size(), requiredSize);
            return std::nullopt;
        }

        FileScanRequest request;
        request.messageId = raw->messageId;
        request.accessType = static_cast<FileAccessType>(raw->accessType);
        request.priority = static_cast<ScanPriority>(raw->priority);
        request.processId = raw->processId;
        request.threadId = raw->threadId;
        request.parentProcessId = raw->parentProcessId;
        request.sessionId = raw->sessionId;
        request.fileSize = raw->fileSize;
        request.fileAttributes = raw->fileAttributes;
        request.desiredAccess = raw->desiredAccess;
        request.shareAccess = raw->shareAccess;
        request.createOptions = raw->createOptions;
        request.volumeSerial = raw->volumeSerial;
        request.fileId = raw->fileId;
        request.isDirectory = raw->isDirectory != 0;
        request.isNetworkFile = raw->isNetworkFile != 0;
        request.isRemovableMedia = raw->isRemovableMedia != 0;
        request.hasADS = raw->hasADS != 0;
        request.requiresReply = raw->requiresReply != 0;
        request.timestamp = std::chrono::system_clock::now();

        // Extract file path
        const wchar_t* pathPtr = reinterpret_cast<const wchar_t*>(
            data.data() + sizeof(FileScanRequestData));
        request.filePath = std::wstring(pathPtr, raw->pathLength);

        // Extract process name
        const wchar_t* procNamePtr = pathPtr + raw->pathLength;
        request.processName = std::wstring(procNamePtr, raw->processNameLength);

        return request;
    }

    [[nodiscard]] static std::optional<ProcessNotification> ParseProcessNotification(
        std::span<const uint8_t> data) {

        if (data.size() < sizeof(ProcessNotificationData)) {
            return std::nullopt;
        }

        const ProcessNotificationData* raw =
            reinterpret_cast<const ProcessNotificationData*>(data.data());

        size_t requiredSize = sizeof(ProcessNotificationData) +
                             (raw->imagePathLength * sizeof(wchar_t)) +
                             (raw->commandLineLength * sizeof(wchar_t));

        if (data.size() < requiredSize) {
            return std::nullopt;
        }

        ProcessNotification notification;
        notification.messageId = raw->messageId;
        notification.processId = raw->processId;
        notification.parentProcessId = raw->parentProcessId;
        notification.creatingProcessId = raw->creatingProcessId;
        notification.creatingThreadId = raw->creatingThreadId;
        notification.sessionId = raw->sessionId;
        notification.isWow64 = raw->isWow64 != 0;
        notification.isElevated = raw->isElevated != 0;
        notification.integrityLevel = raw->integrityLevel;
        notification.requiresReply = raw->requiresReply != 0;
        notification.flags = raw->flags;

        // Convert FILETIME to time_point
        notification.createTime = std::chrono::system_clock::now();

        // Extract paths
        const wchar_t* imagePathPtr = reinterpret_cast<const wchar_t*>(
            data.data() + sizeof(ProcessNotificationData));
        notification.imagePath = std::wstring(imagePathPtr, raw->imagePathLength);

        const wchar_t* cmdLinePtr = imagePathPtr + raw->imagePathLength;
        notification.commandLine = std::wstring(cmdLinePtr, raw->commandLineLength);

        return notification;
    }

    [[nodiscard]] static std::optional<RegistryNotification> ParseRegistryNotification(
        std::span<const uint8_t> data) {

        if (data.size() < sizeof(RegistryNotificationData)) {
            return std::nullopt;
        }

        const RegistryNotificationData* raw =
            reinterpret_cast<const RegistryNotificationData*>(data.data());

        size_t requiredSize = sizeof(RegistryNotificationData) +
                             (raw->keyPathLength * sizeof(wchar_t)) +
                             (raw->valueNameLength * sizeof(wchar_t)) +
                             raw->valueDataLength;

        if (data.size() < requiredSize) {
            return std::nullopt;
        }

        RegistryNotification notification;
        notification.messageId = raw->messageId;
        notification.processId = raw->processId;
        notification.threadId = raw->threadId;
        notification.operationType = raw->operationType;
        notification.valueType = raw->valueType;
        notification.requiresReply = raw->requiresReply != 0;
        notification.timestamp = std::chrono::system_clock::now();

        // Extract key path
        const wchar_t* keyPathPtr = reinterpret_cast<const wchar_t*>(
            data.data() + sizeof(RegistryNotificationData));
        notification.keyPath = std::wstring(keyPathPtr, raw->keyPathLength);

        // Extract value name
        const wchar_t* valueNamePtr = keyPathPtr + raw->keyPathLength;
        notification.valueName = std::wstring(valueNamePtr, raw->valueNameLength);

        // Extract value data
        const uint8_t* valueDataPtr = reinterpret_cast<const uint8_t*>(
            valueNamePtr + raw->valueNameLength);
        notification.valueData.assign(valueDataPtr,
                                      valueDataPtr + raw->valueDataLength);

        return notification;
    }

    [[nodiscard]] static std::vector<uint8_t> SerializeVerdictReply(
        const ScanVerdictReply& reply) {

        size_t threatNameBytes = reply.threatName.length() * sizeof(wchar_t);
        size_t totalSize = sizeof(ScanVerdictReplyData) + threatNameBytes;

        std::vector<uint8_t> buffer(totalSize);

        ScanVerdictReplyData* data =
            reinterpret_cast<ScanVerdictReplyData*>(buffer.data());

        data->messageId = reply.messageId;
        data->verdict = static_cast<uint8_t>(reply.verdict);
        data->resultCode = reply.resultCode;
        data->threatDetected = reply.threatDetected ? 1 : 0;
        data->threatScore = reply.threatScore;
        data->cacheResult = reply.shouldCache ? 1 : 0;
        data->cacheTTL = reply.cacheTTL;
        data->threatNameLength = static_cast<uint16_t>(reply.threatName.length());

        // Copy threat name
        if (!reply.threatName.empty()) {
            std::memcpy(buffer.data() + sizeof(ScanVerdictReplyData),
                       reply.threatName.data(), threatNameBytes);
        }

        return buffer;
    }

private:
    // Connection reference
    FilterConnection& m_connection;

    // Handler callbacks
    FileScanCallback m_fileScanHandler;
    ProcessNotifyCallback m_processScanHandler;
    RegistryNotifyCallback m_registryScanHandler;
    FileNotifyCallback m_fileNotifyHandler;
    ProcessEventCallback m_processNotifyHandler;
    RegistryEventCallback m_registryNotifyHandler;
    mutable std::mutex m_handlerMutex;

    // Configuration
    ScanVerdict m_defaultVerdict = ScanVerdict::Allow;
    bool m_blockOnTimeout = false;
    bool m_blockOnError = false;

    // Statistics
    MessageDispatcher::DispatchStatistics m_stats;
};

// ============================================================================
// MESSAGEDISPATCHER IMPLEMENTATION
// ============================================================================

MessageDispatcher::MessageDispatcher(FilterConnection& connection)
    : m_impl(std::make_unique<MessageDispatcherImpl>(connection)) {
}

MessageDispatcher::~MessageDispatcher() = default;

void MessageDispatcher::RegisterFileScanHandler(FileScanCallback callback) {
    if (m_impl) m_impl->RegisterFileScanHandler(std::move(callback));
}

void MessageDispatcher::RegisterProcessScanHandler(ProcessNotifyCallback callback) {
    if (m_impl) m_impl->RegisterProcessScanHandler(std::move(callback));
}

void MessageDispatcher::RegisterRegistryScanHandler(RegistryNotifyCallback callback) {
    if (m_impl) m_impl->RegisterRegistryScanHandler(std::move(callback));
}

void MessageDispatcher::RegisterFileNotifyHandler(FileNotifyCallback callback) {
    if (m_impl) m_impl->RegisterFileNotifyHandler(std::move(callback));
}

void MessageDispatcher::RegisterProcessNotifyHandler(ProcessEventCallback callback) {
    if (m_impl) m_impl->RegisterProcessNotifyHandler(std::move(callback));
}

void MessageDispatcher::RegisterRegistryNotifyHandler(RegistryEventCallback callback) {
    if (m_impl) m_impl->RegisterRegistryNotifyHandler(std::move(callback));
}

bool MessageDispatcher::DispatchMessage(std::span<const uint8_t> messageBuffer) {
    if (!m_impl) return false;
    return m_impl->DispatchMessage(messageBuffer);
}

std::future<bool> MessageDispatcher::DispatchMessageAsync(
    std::span<const uint8_t> messageBuffer) {
    if (!m_impl) {
        std::promise<bool> p;
        p.set_value(false);
        return p.get_future();
    }
    return m_impl->DispatchMessageAsync(messageBuffer);
}

std::optional<FileScanRequest> MessageDispatcher::ParseFileScanRequest(
    std::span<const uint8_t> data) {
    return MessageDispatcherImpl::ParseFileScanRequest(data);
}

std::optional<ProcessNotification> MessageDispatcher::ParseProcessNotification(
    std::span<const uint8_t> data) {
    return MessageDispatcherImpl::ParseProcessNotification(data);
}

std::optional<RegistryNotification> MessageDispatcher::ParseRegistryNotification(
    std::span<const uint8_t> data) {
    return MessageDispatcherImpl::ParseRegistryNotification(data);
}

std::vector<uint8_t> MessageDispatcher::SerializeVerdictReply(
    const ScanVerdictReply& reply) {
    return MessageDispatcherImpl::SerializeVerdictReply(reply);
}

void MessageDispatcher::SetDefaultVerdict(ScanVerdict verdict) {
    if (m_impl) m_impl->SetDefaultVerdict(verdict);
}

void MessageDispatcher::SetBlockOnTimeout(bool block) {
    if (m_impl) m_impl->SetBlockOnTimeout(block);
}

void MessageDispatcher::SetBlockOnError(bool block) {
    if (m_impl) m_impl->SetBlockOnError(block);
}

const MessageDispatcher::DispatchStatistics& MessageDispatcher::GetStatistics() const noexcept {
    static DispatchStatistics empty;
    return m_impl ? m_impl->GetStatistics() : empty;
}

void MessageDispatcher::ResetStatistics() noexcept {
    if (m_impl) m_impl->ResetStatistics();
}

std::string MessageDispatcher::ToJson() const {
    return m_impl ? m_impl->ToJson() : "{}";
}

// ============================================================================
// DISPATCH STATISTICS IMPLEMENTATION
// ============================================================================

void MessageDispatcher::DispatchStatistics::Reset() noexcept {
    messagesDispatched.store(0, std::memory_order_relaxed);
    fileScanRequests.store(0, std::memory_order_relaxed);
    processScanRequests.store(0, std::memory_order_relaxed);
    registryScanRequests.store(0, std::memory_order_relaxed);
    fileNotifications.store(0, std::memory_order_relaxed);
    processNotifications.store(0, std::memory_order_relaxed);
    registryNotifications.store(0, std::memory_order_relaxed);
    unknownMessages.store(0, std::memory_order_relaxed);
    parseErrors.store(0, std::memory_order_relaxed);
    handlerErrors.store(0, std::memory_order_relaxed);
    repliesSent.store(0, std::memory_order_relaxed);
    replyErrors.store(0, std::memory_order_relaxed);
    totalProcessingTimeUs.store(0, std::memory_order_relaxed);
}

std::string MessageDispatcher::DispatchStatistics::ToJson() const {
    uint64_t dispatched = messagesDispatched.load();
    uint64_t totalTime = totalProcessingTimeUs.load();
    double avgTimeUs = dispatched > 0 ? static_cast<double>(totalTime) / dispatched : 0.0;

    std::ostringstream oss;
    oss << "{"
        << "\"messagesDispatched\":" << dispatched << ","
        << "\"fileScanRequests\":" << fileScanRequests.load() << ","
        << "\"processScanRequests\":" << processScanRequests.load() << ","
        << "\"registryScanRequests\":" << registryScanRequests.load() << ","
        << "\"fileNotifications\":" << fileNotifications.load() << ","
        << "\"processNotifications\":" << processNotifications.load() << ","
        << "\"registryNotifications\":" << registryNotifications.load() << ","
        << "\"unknownMessages\":" << unknownMessages.load() << ","
        << "\"parseErrors\":" << parseErrors.load() << ","
        << "\"handlerErrors\":" << handlerErrors.load() << ","
        << "\"repliesSent\":" << repliesSent.load() << ","
        << "\"replyErrors\":" << replyErrors.load() << ","
        << "\"totalProcessingTimeUs\":" << totalTime << ","
        << "\"avgProcessingTimeUs\":" << avgTimeUs
        << "}";
    return oss.str();
}

// ============================================================================
// USER-MODE STRUCTURE JSON SERIALIZATION
// ============================================================================

std::string FileScanRequest::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"messageId\":" << messageId << ","
        << "\"filePath\":\"" << Utils::StringUtils::WideToUtf8(filePath) << "\","
        << "\"processName\":\"" << Utils::StringUtils::WideToUtf8(processName) << "\","
        << "\"processId\":" << processId << ","
        << "\"fileSize\":" << fileSize << ","
        << "\"isDirectory\":" << (isDirectory ? "true" : "false") << ","
        << "\"isNetworkFile\":" << (isNetworkFile ? "true" : "false") << ","
        << "\"requiresReply\":" << (requiresReply ? "true" : "false")
        << "}";
    return oss.str();
}

std::string ProcessNotification::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"messageId\":" << messageId << ","
        << "\"processId\":" << processId << ","
        << "\"parentProcessId\":" << parentProcessId << ","
        << "\"imagePath\":\"" << Utils::StringUtils::WideToUtf8(imagePath) << "\","
        << "\"commandLine\":\"" << Utils::StringUtils::WideToUtf8(commandLine) << "\","
        << "\"isWow64\":" << (isWow64 ? "true" : "false") << ","
        << "\"isElevated\":" << (isElevated ? "true" : "false") << ","
        << "\"requiresReply\":" << (requiresReply ? "true" : "false")
        << "}";
    return oss.str();
}

std::string RegistryNotification::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"messageId\":" << messageId << ","
        << "\"processId\":" << processId << ","
        << "\"keyPath\":\"" << Utils::StringUtils::WideToUtf8(keyPath) << "\","
        << "\"valueName\":\"" << Utils::StringUtils::WideToUtf8(valueName) << "\","
        << "\"operationType\":" << operationType << ","
        << "\"valueType\":" << valueType << ","
        << "\"requiresReply\":" << (requiresReply ? "true" : "false")
        << "}";
    return oss.str();
}

std::string ScanVerdictReply::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"messageId\":" << messageId << ","
        << "\"verdict\":" << static_cast<int>(verdict) << ","
        << "\"resultCode\":" << resultCode << ","
        << "\"threatDetected\":" << (threatDetected ? "true" : "false") << ","
        << "\"threatScore\":" << static_cast<int>(threatScore) << ","
        << "\"shouldCache\":" << (shouldCache ? "true" : "false") << ","
        << "\"cacheTTL\":" << cacheTTL << ","
        << "\"threatName\":\"" << Utils::StringUtils::WideToUtf8(threatName) << "\""
        << "}";
    return oss.str();
}

std::string CommunicationConfig::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"portName\":\"" << Utils::StringUtils::WideToUtf8(portName) << "\","
        << "\"replyTimeoutMs\":" << replyTimeoutMs << ","
        << "\"reconnectIntervalMs\":" << reconnectIntervalMs << ","
        << "\"maxReconnectAttempts\":" << maxReconnectAttempts << ","
        << "\"messageQueueSize\":" << messageQueueSize << ","
        << "\"workerThreadCount\":" << workerThreadCount << ","
        << "\"autoReconnect\":" << (autoReconnect ? "true" : "false") << ","
        << "\"blockOnTimeout\":" << (blockOnTimeout ? "true" : "false") << ","
        << "\"enableStatistics\":" << (enableStatistics ? "true" : "false")
        << "}";
    return oss.str();
}

CommunicationConfig CommunicationConfig::FromJson(const std::string& json) {
    // Basic JSON parsing - for production use nlohmann::json
    CommunicationConfig config;
    // Parse implementation would go here
    // For now, return defaults
    return config;
}

} // namespace Communication
} // namespace ShadowStrike
