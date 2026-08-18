#include "pch.h"
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

#include "../Utils/JSONUtils.hpp"

#include <algorithm>
#include <sstream>
#include <chrono>

namespace {

/// Escape a UTF-8 string for safe embedding in a JSON value.
std::string EscapeJsonString(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (const char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x",
                             static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

} // anonymous namespace

namespace ShadowStrike {
namespace Communication {

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class MessageDispatcherImpl {
public:
    explicit MessageDispatcherImpl(FilterConnection& connection)
        : m_connection(connection) {
    }

    ~MessageDispatcherImpl() {
        // FIX [BUG #24]: Drain any in-flight async dispatch tasks before the
        // PIMPL goes away. Without this, std::async-launched tasks that capture
        // 'this' would race against destruction and dereference freed handler
        // storage / m_connection on shutdown.
        std::unique_lock lock(m_pendingMutex);
        m_pendingCv.wait(lock, [this] {
            return m_pendingAsync.load(std::memory_order_acquire) == 0;
        });
    }

    // Non-copyable
    MessageDispatcherImpl(const MessageDispatcherImpl&) = delete;
    MessageDispatcherImpl& operator=(const MessageDispatcherImpl&) = delete;

    //=========================================================================
    // Callback Registration
    //=========================================================================

    void RegisterFileScanHandler(ParsedFileScanCallback callback) {
        std::lock_guard<std::mutex> lock(m_handlerMutex);
        m_fileScanHandler = std::move(callback);
        Utils::Logger::Info("[MessageDispatcher] Registered file scan handler");
    }

    void RegisterProcessScanHandler(ParsedProcessNotifyCallback callback) {
        std::lock_guard<std::mutex> lock(m_handlerMutex);
        m_processScanHandler = std::move(callback);
        Utils::Logger::Info("[MessageDispatcher] Registered process scan handler");
    }

    void RegisterRegistryScanHandler(ParsedRegistryNotifyCallback callback) {
        std::lock_guard<std::mutex> lock(m_handlerMutex);
        m_registryScanHandler = std::move(callback);
        Utils::Logger::Info("[MessageDispatcher] Registered registry scan handler");
    }

    void RegisterFileNotifyHandler(ParsedFileNotifyCallback callback) {
        std::lock_guard<std::mutex> lock(m_handlerMutex);
        m_fileNotifyHandler = std::move(callback);
    }

    void RegisterProcessNotifyHandler(ParsedProcessEventCallback callback) {
        std::lock_guard<std::mutex> lock(m_handlerMutex);
        m_processNotifyHandler = std::move(callback);
    }

    void RegisterRegistryNotifyHandler(ParsedRegistryEventCallback callback) {
        std::lock_guard<std::mutex> lock(m_handlerMutex);
        m_registryNotifyHandler = std::move(callback);
    }

    //=========================================================================
    // Message Dispatching
    //=========================================================================

    [[nodiscard]] bool DispatchMessage(std::span<const uint8_t> messageBuffer) {
        auto startTime = std::chrono::steady_clock::now();

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

        const MessageHeader* header =
            reinterpret_cast<const MessageHeader*>(messageBuffer.data());

        if (!header->IsValid()) {
            Utils::Logger::Warn("[MessageDispatcher] Invalid message header "
                              "(magic=0x{:08X}, version={}, size={})",
                              header->magic, header->version, header->totalSize);
            m_stats.parseErrors++;
            return false;
        }

        if (header->totalSize > messageBuffer.size()) {
            Utils::Logger::Warn("[MessageDispatcher] Message size mismatch: {} > {}",
                              header->totalSize, messageBuffer.size());
            m_stats.parseErrors++;
            return false;
        }

        m_stats.messagesDispatched++;

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

        bool handled = false;
        bool needsReply = false;
        ScanVerdictReply reply;
        reply.messageId = header->messageId;
        reply.verdict = m_defaultVerdict.load(std::memory_order_relaxed);
        reply.resultCode = 0;
        reply.threatDetected = false;
        reply.threatScore = 0;
        reply.shouldCache = true;
        reply.cacheTTL = 60;

        MessageType msgType = static_cast<MessageType>(header->messageType);

        try {
            switch (msgType) {
                //=============================================================
                // Scan request — the ONLY kernel→user type requiring a reply
                //=============================================================
                case MessageType::ScanRequest: {
                    needsReply = true;
                    m_stats.fileScanRequests++;

                    auto request = ParseFileScanRequest(payload);
                    if (request.has_value()) {
                        ParsedFileScanCallback handlerCopy;
                        {
                            std::lock_guard<std::mutex> lock(m_handlerMutex);
                            handlerCopy = m_fileScanHandler;
                        }
                        if (handlerCopy) {
                            try {
                                reply = handlerCopy(request.value());
                                handled = true;
                            } catch (const std::exception& e) {
                                Utils::Logger::Error(
                                    "[MessageDispatcher] File scan handler exception: {}",
                                    e.what());
                                m_stats.handlerErrors++;
                                reply.verdict = ScanVerdict::Clean;
                            }
                        }
                    } else {
                        m_stats.parseErrors++;
                    }
                    break;
                }

                //=============================================================
                // Process notification (no reply)
                //=============================================================
                case MessageType::ProcessNotify: {
                    m_stats.processNotifications++;

                    auto notification = ParseProcessNotification(payload);
                    if (notification.has_value()) {
                        ParsedProcessEventCallback handlerCopy;
                        {
                            std::lock_guard<std::mutex> lock(m_handlerMutex);
                            handlerCopy = m_processNotifyHandler;
                        }
                        if (handlerCopy) {
                            try {
                                handlerCopy(notification.value());
                                handled = true;
                            } catch (const std::exception& e) {
                                Utils::Logger::Error(
                                    "[MessageDispatcher] Process notify handler exception: {}",
                                    e.what());
                                m_stats.handlerErrors++;
                            }
                        }
                    } else {
                        m_stats.parseErrors++;
                    }
                    break;
                }

                //=============================================================
                // Thread / Image load notifications (no reply)
                //=============================================================
                case MessageType::ThreadNotify:
                case MessageType::ImageLoad: {
                    m_stats.processNotifications++;

                    auto notification = ParseProcessNotification(payload);
                    if (notification.has_value()) {
                        ParsedProcessEventCallback handlerCopy;
                        {
                            std::lock_guard<std::mutex> lock(m_handlerMutex);
                            handlerCopy = m_processNotifyHandler;
                        }
                        if (handlerCopy) {
                            try {
                                handlerCopy(notification.value());
                                handled = true;
                            } catch (...) {
                                m_stats.handlerErrors++;
                            }
                        }
                    } else {
                        m_stats.parseErrors++;
                    }
                    break;
                }

                //=============================================================
                // Registry notification (no reply)
                //=============================================================
                case MessageType::RegistryNotify: {
                    m_stats.registryNotifications++;

                    auto notification = ParseRegistryNotification(payload);
                    if (notification.has_value()) {
                        ParsedRegistryEventCallback handlerCopy;
                        {
                            std::lock_guard<std::mutex> lock(m_handlerMutex);
                            handlerCopy = m_registryNotifyHandler;
                        }
                        if (handlerCopy) {
                            try {
                                handlerCopy(notification.value());
                                handled = true;
                            } catch (...) {
                                m_stats.handlerErrors++;
                            }
                        }
                    } else {
                        m_stats.parseErrors++;
                    }
                    break;
                }

                //=============================================================
                // Heartbeat (kernel-initiated keepalive, reply with success)
                //=============================================================
                case MessageType::Heartbeat: {
                    needsReply = true;
                    reply.verdict = ScanVerdict::Clean;
                    reply.resultCode = 0;
                    handled = true;
                    break;
                }

                //=============================================================
                // Alert/notification types (no reply, count + log)
                //=============================================================
                case MessageType::HandleAlert:
                case MessageType::RansomwareAlert:
                case MessageType::BehavioralAlert:
                case MessageType::MemoryAlert:
                case MessageType::NetworkAlert:
                case MessageType::SyscallAlert:
                case MessageType::SelfProtectAlert:
                case MessageType::ThreatScoreNotify:
                case MessageType::NamedPipeEvent:
                case MessageType::FileBackupEvent:
                case MessageType::FileRollbackEvent:
                case MessageType::AlpcPortCreated:
                case MessageType::AlpcPortConnected:
                case MessageType::AlpcPortDisconnected:
                case MessageType::AlpcSuspiciousAccess:
                case MessageType::AlpcImpersonation:
                case MessageType::AlpcSandboxEscape:
                case MessageType::AlpcRateLimitExceeded: {
                    m_stats.fileNotifications++;
                    Utils::Logger::Debug(
                        "[MessageDispatcher] Alert/notification type={} id={}",
                        header->messageType, header->messageId);
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
            reply.verdict = m_blockOnError.load(std::memory_order_relaxed)
                ? ScanVerdict::Malicious : ScanVerdict::Clean;
        } catch (...) {
            Utils::Logger::Error("[MessageDispatcher] Unknown dispatch exception");
            m_stats.handlerErrors++;
            reply.verdict = m_blockOnError.load(std::memory_order_relaxed)
                ? ScanVerdict::Malicious : ScanVerdict::Clean;
        }

        // Send reply if required
        if (needsReply) {
            // FIX [BUG #25]: SerializeVerdictReply allocates a buffer sized
            // by attacker-influenced threatName length and ReplyMessage may
            // throw on transport failure. An uncaught std::bad_alloc /
            // std::system_error here would propagate out of the dispatch
            // worker and unwind the kernel-message receive loop. Contain the
            // failure, count it, and return false so the worker stays alive.
            try {
                auto replyBuffer = SerializeVerdictReply(reply);

                if (!m_connection.ReplyMessage(replyBuffer, header->messageId)) {
                    Utils::Logger::Warn("[MessageDispatcher] Failed to send reply for msg {}",
                                       header->messageId);
                    m_stats.replyErrors++;
                } else {
                    m_stats.repliesSent++;
                }
            } catch (const std::exception& e) {
                Utils::Logger::Error("[MessageDispatcher] Reply path exception for msg {}: {}",
                                     header->messageId, e.what());
                m_stats.replyErrors++;
                handled = false;
            } catch (...) {
                Utils::Logger::Error("[MessageDispatcher] Reply path unknown exception for msg {}",
                                     header->messageId);
                m_stats.replyErrors++;
                handled = false;
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

        // FIX [BUG #24]: Track pending async tasks so the destructor can
        // drain them. The captured `this` would otherwise dangle if the
        // dispatcher is torn down before the future is awaited.
        m_pendingAsync.fetch_add(1, std::memory_order_acq_rel);

        return std::async(std::launch::async,
            [this, buffer = std::move(bufferCopy)]() {
                bool result = false;
                try {
                    result = DispatchMessage(std::span<const uint8_t>(buffer));
                } catch (...) {
                    // Never let exceptions escape the async task — DispatchMessage
                    // already swallows handler exceptions, but defend against
                    // SerializeVerdictReply / std::bad_alloc on the reply path.
                    result = false;
                }
                if (m_pendingAsync.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                    std::lock_guard lock(m_pendingMutex);
                    m_pendingCv.notify_all();
                }
                return result;
            });
    }

    //=========================================================================
    // Configuration
    //=========================================================================

    void SetDefaultVerdict(ScanVerdict verdict) {
        m_defaultVerdict.store(verdict, std::memory_order_relaxed);
    }

    void SetBlockOnTimeout(bool block) {
        m_blockOnTimeout.store(block, std::memory_order_relaxed);
    }

    void SetBlockOnError(bool block) {
        m_blockOnError.store(block, std::memory_order_relaxed);
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

        // Validate variable-length fields don't exceed buffer.
        //
        // pathLength and processNameLength are BYTE counts (see FILE_SCAN_REQUEST
        // in MessageProtocol.h). This used to multiply each by sizeof(wchar_t),
        // i.e. read them as CHARACTER counts, which made the bound twice as
        // strict as the contract AND paired with a decode step below that then
        // read only half of each string. Both halves are now byte-based.
        size_t requiredSize = sizeof(FileScanRequestData) +
                             static_cast<size_t>(raw->pathLength) +
                             static_cast<size_t>(raw->processNameLength);

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

        // Extract file path. Byte counts divided down to character counts at the
        // point of use, matching RealTimeProtection::OnKernelFileScan.
        const wchar_t* pathPtr = reinterpret_cast<const wchar_t*>(
            data.data() + sizeof(FileScanRequestData));
        request.filePath = std::wstring(pathPtr, raw->pathLength / sizeof(wchar_t));

        // Extract process name. The offset advances by CHARACTERS because pathPtr
        // is a wchar_t*, so the byte length must be converted here too.
        const wchar_t* procNamePtr = pathPtr + (raw->pathLength / sizeof(wchar_t));
        request.processName =
            std::wstring(procNamePtr, raw->processNameLength / sizeof(wchar_t));

        return request;
    }

    // Parses SHADOWSTRIKE_PROCESS_NOTIFICATION (MessageProtocol.h) - the layout the
    // driver actually writes, at PnpSendProcessNotification (ProcessNotify.c:3798)
    // and SbBuildProcessEvent (ScanBridge.c:1491).
    //
    // This previously parsed Communication::ProcessNotificationData, a 48-byte
    // struct opening with a uint64 messageId that the driver has never emitted.
    // The real payload is 21 bytes of fields behind a 40-byte dead header, so the
    // minimum-size check below rejected every genuine notification and this
    // function returned nullopt for all real input. It failed closed, which is why
    // it never produced a wrong answer - but it could never produce a right one.
    //
    // TWO PROPERTIES OF THIS WIRE FORMAT ARE EASY TO GET WRONG:
    //  1. The struct OPENS WITH A 40-BYTE SS_MESSAGE_HEADER that the driver zeroes
    //     and never fills (RtlZeroMemory over the whole buffer, then the fields are
    //     written after it). It is redundant with the outer frame header the caller
    //     has already parsed, but it occupies real wire space and every field
    //     offset depends on it.
    //  2. ImagePathLength and CommandLineLength are BYTE counts, not character
    //     counts - the driver RtlCopyMemory's exactly that many bytes. Multiplying
    //     them by sizeof(wchar_t) reads twice the payload.
    [[nodiscard]] static std::optional<ProcessNotification> ParseProcessNotification(
        std::span<const uint8_t> data) {

        if (data.size() < sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION)) {
            Utils::Logger::Warn("[MessageDispatcher] ProcessNotification too small: {} < {}",
                                data.size(), sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION));
            return std::nullopt;
        }

        const auto* raw =
            reinterpret_cast<const SHADOWSTRIKE_PROCESS_NOTIFICATION*>(data.data());

        // Bound the variable region against the bytes actually delivered. Widen to
        // size_t BEFORE summing: both lengths are uint16_t, so the sum cannot wrap
        // a size_t here, but the widening is written explicitly so that changing
        // either field to a wider type does not silently introduce a wrap.
        const size_t imagePathBytes  = static_cast<size_t>(raw->ImagePathLength);
        const size_t commandLineBytes = static_cast<size_t>(raw->CommandLineLength);
        const size_t variableBytes = imagePathBytes + commandLineBytes;

        if (data.size() - sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION) < variableBytes) {
            Utils::Logger::Warn("[MessageDispatcher] ProcessNotification variable data "
                                "exceeds payload: image={} cmdline={} available={}",
                                imagePathBytes, commandLineBytes,
                                data.size() - sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION));
            return std::nullopt;
        }

        ProcessNotification notification;
        notification.processId         = raw->ProcessId;
        notification.parentProcessId   = raw->ParentProcessId;
        notification.creatingProcessId = raw->CreatingProcessId;
        notification.creatingThreadId  = raw->CreatingThreadId;
        notification.isCreation        = raw->Create != 0;

        // FIELDS THE WIRE DOES NOT CARRY, LEFT AT THEIR DECLARED DEFAULTS.
        // messageId, sessionId, isWow64, isElevated, integrityLevel, requiresReply,
        // createTime and flags have no source in SHADOWSTRIKE_PROCESS_NOTIFICATION.
        // They are deliberately NOT invented here: a fabricated zero that looks like
        // a measurement is worse than an absent value, because a consumer cannot
        // tell "session 0" from "nobody asked". If any of them is ever needed it has
        // to be added to the wire format on both sides, not defaulted here.

        const auto* variable = data.data() + sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION);

        if (imagePathBytes > 0) {
            notification.imagePath.assign(
                reinterpret_cast<const wchar_t*>(variable),
                imagePathBytes / sizeof(wchar_t));
        }
        if (commandLineBytes > 0) {
            notification.commandLine.assign(
                reinterpret_cast<const wchar_t*>(variable + imagePathBytes),
                commandLineBytes / sizeof(wchar_t));
        }

        return notification;
    }

    // Parses SHADOWSTRIKE_REGISTRY_NOTIFICATION (MessageProtocol.h) - 21 bytes,
    // opening with ProcessId, written by the driver at ScanBridge.c:1952.
    //
    // This previously parsed Communication::RegistryNotificationData, a 40-byte
    // struct opening with a uint64 messageId. That is the SAME wrong struct that
    // RegistryMonitor parsed until commit 5fe45d55, where it was proven that no
    // registry event had ever been processed because of it. The defect is
    // reproduced here because both modules read the same fabricated declaration;
    // deleting the declaration is what prevents a third instance.
    //
    // KeyPathLength / ValueNameLength are BYTE counts and DataSize is a byte count
    // of opaque registry data. There is no character count anywhere in this payload.
    [[nodiscard]] static std::optional<RegistryNotification> ParseRegistryNotification(
        std::span<const uint8_t> data) {

        if (data.size() < sizeof(SHADOWSTRIKE_REGISTRY_NOTIFICATION)) {
            Utils::Logger::Warn("[MessageDispatcher] RegistryNotification too small: {} < {}",
                                data.size(), sizeof(SHADOWSTRIKE_REGISTRY_NOTIFICATION));
            return std::nullopt;
        }

        const auto* raw =
            reinterpret_cast<const SHADOWSTRIKE_REGISTRY_NOTIFICATION*>(data.data());

        // FIX [BUG #26] PRESERVED: cap each length independently BEFORE summing.
        // DataSize is a UINT32 straight off the wire, so on a 32-bit build the sum
        // of the three lengths can wrap and defeat the bounds check below. Reject
        // implausible values up front, well under MAX_MESSAGE_SIZE, so the addition
        // is provably safe on every target rather than only on x64.
        if (raw->KeyPathLength > MAX_MESSAGE_SIZE ||
            raw->ValueNameLength > MAX_MESSAGE_SIZE ||
            raw->DataSize > MAX_MESSAGE_SIZE) {
            Utils::Logger::Warn("[MessageDispatcher] RegistryNotification field too large: "
                                "key={} valueName={} data={}",
                                raw->KeyPathLength, raw->ValueNameLength, raw->DataSize);
            return std::nullopt;
        }

        const size_t keyPathBytes   = static_cast<size_t>(raw->KeyPathLength);
        const size_t valueNameBytes = static_cast<size_t>(raw->ValueNameLength);
        const size_t dataBytes      = static_cast<size_t>(raw->DataSize);
        const size_t variableBytes  = keyPathBytes + valueNameBytes + dataBytes;

        if (data.size() - sizeof(SHADOWSTRIKE_REGISTRY_NOTIFICATION) < variableBytes) {
            Utils::Logger::Warn("[MessageDispatcher] RegistryNotification variable data "
                                "exceeds payload: key={} valueName={} data={} available={}",
                                keyPathBytes, valueNameBytes, dataBytes,
                                data.size() - sizeof(SHADOWSTRIKE_REGISTRY_NOTIFICATION));
            return std::nullopt;
        }

        RegistryNotification notification;
        notification.processId     = raw->ProcessId;
        notification.threadId      = raw->ThreadId;
        notification.operationType = raw->Operation;
        notification.valueType     = raw->DataType;

        // FIELDS THE WIRE DOES NOT CARRY, LEFT AT THEIR DECLARED DEFAULTS.
        // messageId and requiresReply have no source in this payload, and the
        // registry feed is fire-and-forget in the driver (ShadowStrikeSendNotification,
        // no reply buffer), so requiresReply could only ever be false. Not invented
        // here for the same reason as the process path: a defaulted value that looks
        // measured is worse than an absent one.

        const auto* variable = data.data() + sizeof(SHADOWSTRIKE_REGISTRY_NOTIFICATION);

        if (keyPathBytes > 0) {
            notification.keyPath.assign(
                reinterpret_cast<const wchar_t*>(variable),
                keyPathBytes / sizeof(wchar_t));
        }
        if (valueNameBytes > 0) {
            notification.valueName.assign(
                reinterpret_cast<const wchar_t*>(variable + keyPathBytes),
                valueNameBytes / sizeof(wchar_t));
        }
        if (dataBytes > 0) {
            const auto* valueData = variable + keyPathBytes + valueNameBytes;
            notification.valueData.assign(valueData, valueData + dataBytes);
        }

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
    ParsedFileScanCallback m_fileScanHandler;
    ParsedProcessNotifyCallback m_processScanHandler;
    ParsedRegistryNotifyCallback m_registryScanHandler;
    ParsedFileNotifyCallback m_fileNotifyHandler;
    ParsedProcessEventCallback m_processNotifyHandler;
    ParsedRegistryEventCallback m_registryNotifyHandler;
    mutable std::mutex m_handlerMutex;

    // Configuration (atomic — written by config thread, read by dispatch workers)
    std::atomic<ScanVerdict> m_defaultVerdict{ScanVerdict::Clean};
    std::atomic<bool> m_blockOnTimeout{false};
    std::atomic<bool> m_blockOnError{false};

    // Statistics
    MessageDispatcher::DispatchStatistics m_stats;

    // FIX [BUG #24]: Async dispatch lifetime tracking. The destructor blocks
    // until every task launched by DispatchMessageAsync has retired so that
    // captured `this` and m_connection cannot be torn down underneath them.
    std::atomic<uint32_t> m_pendingAsync{0};
    std::mutex m_pendingMutex;
    std::condition_variable m_pendingCv;
};

// ============================================================================
// MESSAGEDISPATCHER IMPLEMENTATION
// ============================================================================

MessageDispatcher::MessageDispatcher(FilterConnection& connection)
    : m_impl(std::make_unique<MessageDispatcherImpl>(connection)) {
}

MessageDispatcher::~MessageDispatcher() = default;

void MessageDispatcher::RegisterFileScanHandler(ParsedFileScanCallback callback) {
    if (m_impl) m_impl->RegisterFileScanHandler(std::move(callback));
}

void MessageDispatcher::RegisterProcessScanHandler(ParsedProcessNotifyCallback callback) {
    if (m_impl) m_impl->RegisterProcessScanHandler(std::move(callback));
}

void MessageDispatcher::RegisterRegistryScanHandler(ParsedRegistryNotifyCallback callback) {
    if (m_impl) m_impl->RegisterRegistryScanHandler(std::move(callback));
}

void MessageDispatcher::RegisterFileNotifyHandler(ParsedFileNotifyCallback callback) {
    if (m_impl) m_impl->RegisterFileNotifyHandler(std::move(callback));
}

void MessageDispatcher::RegisterProcessNotifyHandler(ParsedProcessEventCallback callback) {
    if (m_impl) m_impl->RegisterProcessNotifyHandler(std::move(callback));
}

void MessageDispatcher::RegisterRegistryNotifyHandler(ParsedRegistryEventCallback callback) {
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
        << "\"filePath\":\"" << EscapeJsonString(Utils::StringUtils::ToNarrow(filePath)) << "\","
        << "\"processName\":\"" << EscapeJsonString(Utils::StringUtils::ToNarrow(processName)) << "\","
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
        << "\"imagePath\":\"" << EscapeJsonString(Utils::StringUtils::ToNarrow(imagePath)) << "\","
        << "\"commandLine\":\"" << EscapeJsonString(Utils::StringUtils::ToNarrow(commandLine)) << "\","
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
        << "\"keyPath\":\"" << EscapeJsonString(Utils::StringUtils::ToNarrow(keyPath)) << "\","
        << "\"valueName\":\"" << EscapeJsonString(Utils::StringUtils::ToNarrow(valueName)) << "\","
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
        << "\"threatName\":\"" << EscapeJsonString(Utils::StringUtils::ToNarrow(threatName)) << "\""
        << "}";
    return oss.str();
}

std::string CommunicationConfig::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"portName\":\"" << EscapeJsonString(Utils::StringUtils::ToNarrow(portName)) << "\","
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
    namespace JSON = ShadowStrike::Utils::JSON;

    CommunicationConfig config;
    if (json.empty()) {
        return config;
    }

    JSON::Json root;
    JSON::Error parseErr;
    if (!JSON::Parse(json, root, &parseErr)) {
        Utils::Logger::Warn("[CommunicationConfig] JSON parse failed: {}", parseErr.message);
        return config;
    }

    std::string portNameNarrow;
    if (JSON::Get<std::string>(root, "portName", portNameNarrow)) {
        config.portName = Utils::StringUtils::ToWide(portNameNarrow);
    }
    config.replyTimeoutMs       = JSON::GetOr<uint32_t>(root, "replyTimeoutMs", config.replyTimeoutMs);
    config.reconnectIntervalMs  = JSON::GetOr<uint32_t>(root, "reconnectIntervalMs", config.reconnectIntervalMs);
    config.maxReconnectAttempts = JSON::GetOr<uint32_t>(root, "maxReconnectAttempts", config.maxReconnectAttempts);
    config.messageQueueSize     = JSON::GetOr<uint32_t>(root, "messageQueueSize", config.messageQueueSize);
    config.workerThreadCount    = JSON::GetOr<uint32_t>(root, "workerThreadCount", config.workerThreadCount);
    config.autoReconnect        = JSON::GetOr<bool>(root, "autoReconnect", config.autoReconnect);
    config.blockOnTimeout       = JSON::GetOr<bool>(root, "blockOnTimeout", config.blockOnTimeout);
    config.enableStatistics     = JSON::GetOr<bool>(root, "enableStatistics", config.enableStatistics);

    return config;
}

// ============================================================================
// DISPATCH STATISTICS SNAPSHOT
// ============================================================================

DispatchStatisticsSnapshot
MessageDispatcher::DispatchStatistics::TakeSnapshot() const noexcept {
    DispatchStatisticsSnapshot snap;
    snap.messagesDispatched   = messagesDispatched.load(std::memory_order_relaxed);
    snap.fileScanRequests     = fileScanRequests.load(std::memory_order_relaxed);
    snap.processScanRequests  = processScanRequests.load(std::memory_order_relaxed);
    snap.registryScanRequests = registryScanRequests.load(std::memory_order_relaxed);
    snap.fileNotifications    = fileNotifications.load(std::memory_order_relaxed);
    snap.processNotifications = processNotifications.load(std::memory_order_relaxed);
    snap.registryNotifications = registryNotifications.load(std::memory_order_relaxed);
    snap.unknownMessages      = unknownMessages.load(std::memory_order_relaxed);
    snap.parseErrors          = parseErrors.load(std::memory_order_relaxed);
    snap.handlerErrors        = handlerErrors.load(std::memory_order_relaxed);
    snap.repliesSent          = repliesSent.load(std::memory_order_relaxed);
    snap.replyErrors          = replyErrors.load(std::memory_order_relaxed);
    snap.totalProcessingTimeUs = totalProcessingTimeUs.load(std::memory_order_relaxed);
    snap.avgProcessingTimeUs  = snap.messagesDispatched > 0
        ? static_cast<double>(snap.totalProcessingTimeUs) / snap.messagesDispatched
        : 0.0;
    return snap;
}

std::string DispatchStatisticsSnapshot::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"messagesDispatched\":" << messagesDispatched << ","
        << "\"fileScanRequests\":" << fileScanRequests << ","
        << "\"processScanRequests\":" << processScanRequests << ","
        << "\"registryScanRequests\":" << registryScanRequests << ","
        << "\"fileNotifications\":" << fileNotifications << ","
        << "\"processNotifications\":" << processNotifications << ","
        << "\"registryNotifications\":" << registryNotifications << ","
        << "\"unknownMessages\":" << unknownMessages << ","
        << "\"parseErrors\":" << parseErrors << ","
        << "\"handlerErrors\":" << handlerErrors << ","
        << "\"repliesSent\":" << repliesSent << ","
        << "\"replyErrors\":" << replyErrors << ","
        << "\"totalProcessingTimeUs\":" << totalProcessingTimeUs << ","
        << "\"avgProcessingTimeUs\":" << avgProcessingTimeUs
        << "}";
    return oss.str();
}

} // namespace Communication
} // namespace ShadowStrike
