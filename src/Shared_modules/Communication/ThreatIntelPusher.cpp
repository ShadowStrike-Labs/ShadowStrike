/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * @file ThreatIntelPusher.cpp
 * @brief Implementation of kernel data push via FilterConnection.
 *
 * Serializes user-mode threat intelligence into packed wire format
 * (MessageProtocol.h structures) and sends via FilterSendMessage
 * to the kernel MessageHandler's 8 registered push handlers.
 */

#include "ThreatIntelPusher.hpp"
#include "FilterConnection.hpp"
#include "../Utils/Logger.hpp"

#include <Windows.h>
#include <mutex>
#include <algorithm>
#include <cstring>

// Shared protocol definitions (kernel/user-mode compatible)
#include "../../PhantomSensor/Shared/MessageProtocol.h"
#include "../../PhantomSensor/Shared/MessageTypes.h"
#include "../../PhantomSensor/PhantomSensor/Behavioral/RuleEngine.h"

namespace ShadowStrike {
namespace Communication {

// ============================================================================
// CONSTANTS
// ============================================================================

static constexpr uint32_t DEFAULT_MAX_BATCH_SIZE = SHADOWSTRIKE_PUSH_MAX_BATCH_ENTRIES;
static constexpr uint32_t DEFAULT_REPLY_TIMEOUT_MS = 30000;
static constexpr uint32_t MAX_MESSAGE_BUFFER_SIZE = 64 * 1024; // 64KB per message

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class ThreatIntelPusher::Impl {
public:
    explicit Impl(FilterConnection& connection)
        : m_connection(connection)
        , m_maxBatchSize(DEFAULT_MAX_BATCH_SIZE)
        , m_replyTimeoutMs(DEFAULT_REPLY_TIMEOUT_MS)
        , m_nextMessageId(1)
    {
        Utils::Logger::Info("[ThreatIntelPusher] Initialized (maxBatch={}, timeout={}ms)",
            DEFAULT_MAX_BATCH_SIZE, DEFAULT_REPLY_TIMEOUT_MS);
    }

    // ========================================================================
    // Message Building Helpers
    // ========================================================================

    void BuildMessageHeader(
        SHADOWSTRIKE_MESSAGE_HEADER& header,
        uint16_t messageType,
        uint32_t dataSize) noexcept
    {
        memset(&header, 0, sizeof(header));
        header.Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
        header.Version = SHADOWSTRIKE_PROTOCOL_VERSION;
        header.MessageType = messageType;
        header.MessageId = m_nextMessageId.fetch_add(1, std::memory_order_relaxed);
        header.TotalSize = static_cast<uint32_t>(sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) + dataSize;
        header.DataSize = dataSize;

        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER li;
        li.LowPart = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;
        header.Timestamp = li.QuadPart;
    }

    void BuildBatchHeader(
        SHADOWSTRIKE_PUSH_BATCH_HEADER& batch,
        uint32_t entryCount,
        uint32_t entrySize,
        uint32_t totalDataSize) noexcept
    {
        batch.EntryCount = entryCount;
        batch.EntrySize = entrySize;
        batch.TotalDataSize = totalDataSize;
        batch.Flags = 0;
    }

    // ========================================================================
    // Send + Reply Handling
    // ========================================================================

    PushResult SendBatchMessage(
        std::span<const uint8_t> messageBuffer,
        uint32_t entryCount)
    {
        PushResult result;

        uint8_t replyBuf[sizeof(SHADOWSTRIKE_PUSH_REPLY) + 64];
        std::span<uint8_t> replySpan(replyBuf, sizeof(replyBuf));

        const uint32_t timeout = m_replyTimeoutMs.load(std::memory_order_relaxed);
        size_t replySize = m_connection.SendMessage(
            messageBuffer, replySpan, timeout);

        if (replySize >= sizeof(SHADOWSTRIKE_PUSH_REPLY)) {
            auto* reply = reinterpret_cast<const SHADOWSTRIKE_PUSH_REPLY*>(replyBuf);
            result.success = (reply->Status == 0); // STATUS_SUCCESS
            result.entriesAccepted = reply->EntriesAccepted;
            result.entriesRejected = reply->EntriesRejected;
            result.kernelStatus = reply->Status;
            result.batchesSent = 1;

            if (!result.success) {
                char ntBuf[32];
                snprintf(ntBuf, sizeof(ntBuf), "0x%08X", reply->Status);
                result.errorMessage = std::string("Kernel returned NTSTATUS ") + ntBuf;
                Utils::Logger::Warn(
                    "[ThreatIntelPusher] Kernel rejected batch: NTSTATUS=0x{:08X} "
                    "accepted={} rejected={}",
                    reply->Status, reply->EntriesAccepted, reply->EntriesRejected);
            }
        } else {
            // replySize==0 or undersized reply — treat as error
            result.success = false;
            result.batchesSent = 1;
            if (!m_connection.IsConnected()) {
                result.errorMessage = "FilterConnection disconnected during push";
            } else if (replySize == 0) {
                result.errorMessage = "Kernel returned empty reply (timeout or protocol error)";
            } else {
                result.errorMessage = "Invalid reply size: " + std::to_string(replySize);
            }
            Utils::Logger::Error(
                "[ThreatIntelPusher] SendBatchMessage failed: {} (replySize={})",
                result.errorMessage, replySize);
        }

        // Update statistics (all atomic)
        auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        m_stats.totalBatchesSent.fetch_add(1, std::memory_order_relaxed);
        m_stats.totalBytesSent.fetch_add(
            messageBuffer.size(), std::memory_order_relaxed);
        m_stats.totalPushes.fetch_add(1, std::memory_order_relaxed);
        m_stats.lastPushTimeMs.store(nowMs, std::memory_order_relaxed);

        if (result.success) {
            m_stats.successfulPushes.fetch_add(1, std::memory_order_relaxed);
            m_stats.totalEntriesPushed.fetch_add(
                result.entriesAccepted, std::memory_order_relaxed);
            m_stats.lastSuccessTimeMs.store(nowMs, std::memory_order_relaxed);
        } else {
            m_stats.failedPushes.fetch_add(1, std::memory_order_relaxed);
        }

        return result;
    }

    // ========================================================================
    // Hash Push Implementation
    // ========================================================================

    PushResult PushHashBatch(
        std::span<const HashPushEntry> entries,
        uint16_t messageType)
    {
        std::lock_guard lock(m_mutex);

        PushResult aggregate;

        if (entries.empty()) {
            aggregate.success = true;
            return aggregate;
        }

        if (!m_connection.IsConnected()) {
            aggregate.success = false;
            aggregate.errorMessage = "FilterConnection not connected";
            Utils::Logger::Warn("[ThreatIntelPusher] PushHash aborted: not connected");
            return aggregate;
        }

        aggregate.success = true;

        const uint32_t maxBatch = m_maxBatchSize.load(std::memory_order_relaxed);
        const uint32_t batchMax = std::min(
            maxBatch,
            static_cast<uint32_t>(
                (MAX_MESSAGE_BUFFER_SIZE - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
                 - sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER))
                / sizeof(SHADOWSTRIKE_PUSH_HASH_ENTRY)));

        size_t offset = 0;
        while (offset < entries.size()) {
            const uint32_t count = static_cast<uint32_t>(
                std::min<size_t>(entries.size() - offset, batchMax));

            const uint32_t dataSize =
                static_cast<uint32_t>(sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER))
                + count * static_cast<uint32_t>(sizeof(SHADOWSTRIKE_PUSH_HASH_ENTRY));

            std::vector<uint8_t> buffer(
                sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + dataSize);

            auto* header = reinterpret_cast<SHADOWSTRIKE_MESSAGE_HEADER*>(buffer.data());
            BuildMessageHeader(*header, messageType, dataSize);

            auto* batch = reinterpret_cast<SHADOWSTRIKE_PUSH_BATCH_HEADER*>(
                buffer.data() + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
            BuildBatchHeader(*batch, count,
                static_cast<uint32_t>(sizeof(SHADOWSTRIKE_PUSH_HASH_ENTRY)),
                count * static_cast<uint32_t>(sizeof(SHADOWSTRIKE_PUSH_HASH_ENTRY)));

            auto* entryPtr = reinterpret_cast<SHADOWSTRIKE_PUSH_HASH_ENTRY*>(
                buffer.data() + sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
                + sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER));

            for (uint32_t i = 0; i < count; ++i) {
                const auto& src = entries[offset + i];
                auto& dst = entryPtr[i];

                memset(&dst, 0, sizeof(dst));
                dst.HashType = std::min<uint8_t>(src.hashType, 2);
                dst.Verdict = std::min<uint8_t>(src.verdict, 3);
                dst.Severity = src.severity;
                dst.Reserved = 0;
                dst.Score = std::min(src.score, 100u);
                memcpy(dst.Hash, src.hash, sizeof(dst.Hash));
                strncpy_s(dst.ThreatName, sizeof(dst.ThreatName),
                    src.threatName.c_str(), _TRUNCATE);
                dst.Expiry.QuadPart = src.expiry;
            }

            auto batchResult = SendBatchMessage(
                std::span<const uint8_t>(buffer.data(), buffer.size()), count);

            aggregate.entriesAccepted += batchResult.entriesAccepted;
            aggregate.entriesRejected += batchResult.entriesRejected;
            aggregate.batchesSent += batchResult.batchesSent;
            if (!batchResult.success) {
                aggregate.success = false;
                aggregate.kernelStatus = batchResult.kernelStatus;
                aggregate.errorMessage = batchResult.errorMessage;
                break;
            }

            offset += count;
        }

        Utils::Logger::Debug(
            "[ThreatIntelPusher] PushHash complete: type=0x{:04X} accepted={} rejected={} batches={}",
            messageType, aggregate.entriesAccepted, aggregate.entriesRejected, aggregate.batchesSent);

        return aggregate;
    }

    // ========================================================================
    // Network IoC Push Implementation
    // ========================================================================

    PushResult PushNetworkIOCBatch(std::span<const NetworkIOCPushEntry> entries)
    {
        std::lock_guard lock(m_mutex);

        PushResult aggregate;

        if (entries.empty()) {
            aggregate.success = true;
            return aggregate;
        }

        if (!m_connection.IsConnected()) {
            aggregate.success = false;
            aggregate.errorMessage = "FilterConnection not connected";
            Utils::Logger::Warn("[ThreatIntelPusher] PushNetworkIOC aborted: not connected");
            return aggregate;
        }

        aggregate.success = true;

        const uint32_t maxBatch = m_maxBatchSize.load(std::memory_order_relaxed);
        const uint32_t batchMax = std::min(
            maxBatch,
            static_cast<uint32_t>(
                (MAX_MESSAGE_BUFFER_SIZE - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
                 - sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER))
                / sizeof(SHADOWSTRIKE_PUSH_NETWORK_IOC_ENTRY)));

        size_t offset = 0;
        while (offset < entries.size()) {
            const uint32_t count = static_cast<uint32_t>(
                std::min<size_t>(entries.size() - offset, batchMax));

            const uint32_t dataSize =
                static_cast<uint32_t>(sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER))
                + count * static_cast<uint32_t>(sizeof(SHADOWSTRIKE_PUSH_NETWORK_IOC_ENTRY));

            std::vector<uint8_t> buffer(
                sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + dataSize);

            auto* header = reinterpret_cast<SHADOWSTRIKE_MESSAGE_HEADER*>(buffer.data());
            BuildMessageHeader(*header, FilterMessageType_PushNetworkIoC, dataSize);

            auto* batch = reinterpret_cast<SHADOWSTRIKE_PUSH_BATCH_HEADER*>(
                buffer.data() + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
            BuildBatchHeader(*batch, count,
                static_cast<uint32_t>(sizeof(SHADOWSTRIKE_PUSH_NETWORK_IOC_ENTRY)),
                count * static_cast<uint32_t>(sizeof(SHADOWSTRIKE_PUSH_NETWORK_IOC_ENTRY)));

            auto* entryPtr = reinterpret_cast<SHADOWSTRIKE_PUSH_NETWORK_IOC_ENTRY*>(
                buffer.data() + sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
                + sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER));

            for (uint32_t i = 0; i < count; ++i) {
                const auto& src = entries[offset + i];
                auto& dst = entryPtr[i];

                memset(&dst, 0, sizeof(dst));
                dst.Type = static_cast<UINT8>(std::min<uint8_t>(
                    static_cast<uint8_t>(src.type), 4));
                dst.Reputation = src.reputation;
                dst.Categories = src.categories;
                dst.Score = std::min(src.score, 100u);
                strncpy_s(dst.ThreatName, sizeof(dst.ThreatName),
                    src.threatName.c_str(), _TRUNCATE);
                strncpy_s(dst.MalwareFamily, sizeof(dst.MalwareFamily),
                    src.malwareFamily.c_str(), _TRUNCATE);
                dst.Expiry.QuadPart = src.expiry;

                switch (src.type) {
                case NetworkIOCPushEntry::IPv4:
                    memcpy(&dst.Value.IPv4, src.ipv4, 4);
                    break;
                case NetworkIOCPushEntry::IPv6:
                    memcpy(dst.Value.IPv6, src.ipv6, 16);
                    break;
                case NetworkIOCPushEntry::Domain:
                    strncpy_s(dst.Value.Domain, sizeof(dst.Value.Domain),
                        src.value.c_str(), _TRUNCATE);
                    break;
                case NetworkIOCPushEntry::JA3:
                    memcpy(dst.Value.JA3Hash, src.ja3Hash, 16);
                    break;
                case NetworkIOCPushEntry::URL:
                    strncpy_s(dst.Value.URL, sizeof(dst.Value.URL),
                        src.value.c_str(), _TRUNCATE);
                    break;
                }
            }

            auto batchResult = SendBatchMessage(
                std::span<const uint8_t>(buffer.data(), buffer.size()), count);

            aggregate.entriesAccepted += batchResult.entriesAccepted;
            aggregate.entriesRejected += batchResult.entriesRejected;
            aggregate.batchesSent += batchResult.batchesSent;
            if (!batchResult.success) {
                aggregate.success = false;
                aggregate.kernelStatus = batchResult.kernelStatus;
                aggregate.errorMessage = batchResult.errorMessage;
                break;
            }

            offset += count;
        }

        Utils::Logger::Debug(
            "[ThreatIntelPusher] PushNetworkIOC complete: accepted={} rejected={} batches={}",
            aggregate.entriesAccepted, aggregate.entriesRejected, aggregate.batchesSent);

        return aggregate;
    }

    // ========================================================================
    // Whitelist Push Implementation
    // ========================================================================

    PushResult PushWhitelistBatch(std::span<const WhitelistPushEntry> entries)
    {
        std::lock_guard lock(m_mutex);

        PushResult aggregate;

        if (entries.empty()) {
            aggregate.success = true;
            return aggregate;
        }

        if (!m_connection.IsConnected()) {
            aggregate.success = false;
            aggregate.errorMessage = "FilterConnection not connected";
            Utils::Logger::Warn("[ThreatIntelPusher] PushWhitelist aborted: not connected");
            return aggregate;
        }

        aggregate.success = true;
        const uint32_t maxBatch = m_maxBatchSize.load(std::memory_order_relaxed);

        size_t offset = 0;
        while (offset < entries.size()) {
            std::vector<uint8_t> buffer;
            buffer.reserve(MAX_MESSAGE_BUFFER_SIZE);

            buffer.resize(sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
                         + sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER));

            uint32_t count = 0;
            size_t idx = offset;

            while (idx < entries.size() && count < maxBatch) {
                const auto& src = entries[idx];

                size_t entrySize = sizeof(SHADOWSTRIKE_PUSH_WHITELIST_ENTRY)
                    + src.value.size() * sizeof(wchar_t);

                if (buffer.size() + entrySize > MAX_MESSAGE_BUFFER_SIZE) {
                    if (count == 0) {
                        Utils::Logger::Warn(
                            "[ThreatIntelPusher] Whitelist entry too large ({} bytes), skipping",
                            entrySize);
                        aggregate.entriesRejected++;
                        m_stats.oversizedEntriesSkipped.fetch_add(1, std::memory_order_relaxed);
                        ++idx;
                        continue;
                    }
                    break;
                }

                size_t entryOffset = buffer.size();
                buffer.resize(entryOffset + sizeof(SHADOWSTRIKE_PUSH_WHITELIST_ENTRY)
                             + src.value.size() * sizeof(wchar_t));

                auto* dst = reinterpret_cast<SHADOWSTRIKE_PUSH_WHITELIST_ENTRY*>(
                    buffer.data() + entryOffset);
                memset(dst, 0, sizeof(*dst));
                dst->EntryType = static_cast<UINT8>(std::min<uint8_t>(
                    static_cast<uint8_t>(src.entryType), 3));
                dst->HashType = std::min<uint8_t>(src.hashType, 2);
                dst->Flags = src.flags;
                memcpy(dst->Hash, src.hash, sizeof(dst->Hash));
                dst->ValueLength = static_cast<UINT16>(src.value.size());

                if (!src.value.empty()) {
                    auto* valuePtr = reinterpret_cast<wchar_t*>(
                        buffer.data() + entryOffset
                        + sizeof(SHADOWSTRIKE_PUSH_WHITELIST_ENTRY));
                    memcpy(valuePtr, src.value.data(),
                        src.value.size() * sizeof(wchar_t));
                }

                ++count;
                ++idx;
            }

            if (count == 0) {
                offset = idx;
                continue;
            }

            uint32_t dataSize = static_cast<uint32_t>(
                buffer.size() - sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

            auto* header = reinterpret_cast<SHADOWSTRIKE_MESSAGE_HEADER*>(buffer.data());
            BuildMessageHeader(*header, FilterMessageType_PushWhitelist, dataSize);

            auto* batch = reinterpret_cast<SHADOWSTRIKE_PUSH_BATCH_HEADER*>(
                buffer.data() + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
            BuildBatchHeader(*batch, count, 0,
                dataSize - static_cast<uint32_t>(sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER)));

            auto batchResult = SendBatchMessage(
                std::span<const uint8_t>(buffer.data(), buffer.size()), count);

            aggregate.entriesAccepted += batchResult.entriesAccepted;
            aggregate.entriesRejected += batchResult.entriesRejected;
            aggregate.batchesSent += batchResult.batchesSent;
            if (!batchResult.success) {
                aggregate.success = false;
                aggregate.kernelStatus = batchResult.kernelStatus;
                aggregate.errorMessage = batchResult.errorMessage;
                break;
            }

            offset = idx;
        }

        Utils::Logger::Debug(
            "[ThreatIntelPusher] PushWhitelist complete: accepted={} rejected={} batches={}",
            aggregate.entriesAccepted, aggregate.entriesRejected, aggregate.batchesSent);

        return aggregate;
    }

    // ========================================================================
    // Exclusion Push Implementation
    // ========================================================================

    PushResult PushExclusionBatch(std::span<const ExclusionPushEntry> entries)
    {
        std::lock_guard lock(m_mutex);

        PushResult aggregate;

        if (entries.empty()) {
            aggregate.success = true;
            return aggregate;
        }

        if (!m_connection.IsConnected()) {
            aggregate.success = false;
            aggregate.errorMessage = "FilterConnection not connected";
            Utils::Logger::Warn("[ThreatIntelPusher] PushExclusion aborted: not connected");
            return aggregate;
        }

        aggregate.success = true;
        const uint32_t maxBatch = m_maxBatchSize.load(std::memory_order_relaxed);

        size_t offset = 0;
        while (offset < entries.size()) {
            std::vector<uint8_t> buffer;
            buffer.reserve(MAX_MESSAGE_BUFFER_SIZE);
            buffer.resize(sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
                         + sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER));

            uint32_t count = 0;
            size_t idx = offset;

            while (idx < entries.size() && count < maxBatch) {
                const auto& src = entries[idx];

                size_t valueBytes = (src.exclusionType == ExclusionPushEntry::PIDExcl)
                    ? sizeof(uint64_t)
                    : src.value.size() * sizeof(wchar_t);

                size_t entrySize = sizeof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY) + valueBytes;

                if (buffer.size() + entrySize > MAX_MESSAGE_BUFFER_SIZE) {
                    if (count == 0) {
                        Utils::Logger::Warn(
                            "[ThreatIntelPusher] Exclusion entry too large ({} bytes), skipping",
                            entrySize);
                        aggregate.entriesRejected++;
                        m_stats.oversizedEntriesSkipped.fetch_add(1, std::memory_order_relaxed);
                        ++idx;
                        continue;
                    }
                    break;
                }

                size_t entryOffset = buffer.size();
                buffer.resize(entryOffset + entrySize);

                auto* dst = reinterpret_cast<SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY*>(
                    buffer.data() + entryOffset);
                memset(dst, 0, sizeof(*dst));
                dst->ExclusionType = static_cast<UINT8>(std::min<uint8_t>(
                    static_cast<uint8_t>(src.exclusionType), 3));
                dst->Operation = static_cast<UINT8>(std::min<uint8_t>(
                    static_cast<uint8_t>(src.operation), 2));
                dst->Flags = src.flags;
                dst->TTLSeconds = src.ttlSeconds;

                if (src.exclusionType == ExclusionPushEntry::PIDExcl) {
                    dst->ValueLength = static_cast<UINT16>(sizeof(uint64_t) / sizeof(wchar_t));
                    auto* pidPtr = reinterpret_cast<uint64_t*>(
                        buffer.data() + entryOffset
                        + sizeof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY));
                    *pidPtr = src.pid;
                } else {
                    dst->ValueLength = static_cast<UINT16>(src.value.size());
                    if (!src.value.empty()) {
                        auto* valPtr = reinterpret_cast<wchar_t*>(
                            buffer.data() + entryOffset
                            + sizeof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY));
                        memcpy(valPtr, src.value.data(),
                            src.value.size() * sizeof(wchar_t));
                    }
                }

                ++count;
                ++idx;
            }

            if (count == 0) {
                offset = idx;
                continue;
            }

            uint32_t dataSize = static_cast<uint32_t>(
                buffer.size() - sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

            auto* header = reinterpret_cast<SHADOWSTRIKE_MESSAGE_HEADER*>(buffer.data());
            BuildMessageHeader(*header, FilterMessageType_ExclusionUpdate, dataSize);

            auto* batch = reinterpret_cast<SHADOWSTRIKE_PUSH_BATCH_HEADER*>(
                buffer.data() + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
            BuildBatchHeader(*batch, count, 0,
                dataSize - static_cast<uint32_t>(sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER)));

            auto batchResult = SendBatchMessage(
                std::span<const uint8_t>(buffer.data(), buffer.size()), count);

            aggregate.entriesAccepted += batchResult.entriesAccepted;
            aggregate.entriesRejected += batchResult.entriesRejected;
            aggregate.batchesSent += batchResult.batchesSent;
            if (!batchResult.success) {
                aggregate.success = false;
                aggregate.kernelStatus = batchResult.kernelStatus;
                aggregate.errorMessage = batchResult.errorMessage;
                break;
            }

            offset = idx;
        }

        Utils::Logger::Debug(
            "[ThreatIntelPusher] PushExclusion complete: accepted={} rejected={} batches={}",
            aggregate.entriesAccepted, aggregate.entriesRejected, aggregate.batchesSent);

        return aggregate;
    }

    // ========================================================================
    // IoC Feed Push Implementation (variable-length entries)
    // ========================================================================

    PushResult PushIoCFeedBatch(std::span<const IoCFeedPushEntry> entries)
    {
        std::lock_guard lock(m_mutex);

        PushResult aggregate;

        if (entries.empty()) {
            aggregate.success = true;
            return aggregate;
        }

        if (!m_connection.IsConnected()) {
            aggregate.success = false;
            aggregate.errorMessage = "FilterConnection not connected";
            Utils::Logger::Warn("[ThreatIntelPusher] PushIoCFeed aborted: not connected");
            return aggregate;
        }

        aggregate.success = true;
        const uint32_t maxBatch = m_maxBatchSize.load(std::memory_order_relaxed);

        size_t offset = 0;
        while (offset < entries.size()) {
            std::vector<uint8_t> buffer;
            buffer.reserve(MAX_MESSAGE_BUFFER_SIZE);
            buffer.resize(sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
                         + sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER));

            uint32_t count = 0;
            size_t idx = offset;

            while (idx < entries.size() && count < maxBatch) {
                const auto& src = entries[idx];

                // Validate value length fits in UINT16
                if (src.value.size() > UINT16_MAX) {
                    Utils::Logger::Warn(
                        "[ThreatIntelPusher] IoC value too large ({} bytes, max 65535), skipping",
                        src.value.size());
                    aggregate.entriesRejected++;
                    m_stats.oversizedEntriesSkipped.fetch_add(1, std::memory_order_relaxed);
                    ++idx;
                    continue;
                }

                // Wire: fixed IOC_ENTRY header + variable Value[ValueLength]
                size_t entrySize = sizeof(SHADOWSTRIKE_PUSH_IOC_ENTRY)
                    + src.value.size();  // Value is CHAR[], not WCHAR

                if (buffer.size() + entrySize > MAX_MESSAGE_BUFFER_SIZE) {
                    if (count == 0) {
                        Utils::Logger::Warn(
                            "[ThreatIntelPusher] IoC feed entry too large ({} bytes), skipping",
                            entrySize);
                        aggregate.entriesRejected++;
                        m_stats.oversizedEntriesSkipped.fetch_add(1, std::memory_order_relaxed);
                        ++idx;
                        continue;
                    }
                    break;
                }

                size_t entryOffset = buffer.size();
                buffer.resize(entryOffset + entrySize);

                auto* dst = reinterpret_cast<SHADOWSTRIKE_PUSH_IOC_ENTRY*>(
                    buffer.data() + entryOffset);
                memset(dst, 0, sizeof(*dst));
                dst->Type = src.type;
                dst->Severity = std::min<uint8_t>(src.severity, 4);
                dst->MatchMode = src.matchMode;
                dst->CaseSensitive = src.caseSensitive ? 1 : 0;
                dst->ValueLength = static_cast<UINT16>(src.value.size());
                dst->Reserved = 0;
                strncpy_s(dst->ThreatName, sizeof(dst->ThreatName),
                    src.threatName.c_str(), _TRUNCATE);
                strncpy_s(dst->Source, sizeof(dst->Source),
                    src.source.c_str(), _TRUNCATE);
                dst->Expiry.QuadPart = src.expiry;

                // Append value string after the fixed struct
                if (!src.value.empty()) {
                    auto* valPtr = reinterpret_cast<char*>(
                        buffer.data() + entryOffset
                        + sizeof(SHADOWSTRIKE_PUSH_IOC_ENTRY));
                    memcpy(valPtr, src.value.data(), src.value.size());
                }

                ++count;
                ++idx;
            }

            if (count == 0) {
                offset = idx;
                continue;
            }

            uint32_t dataSize = static_cast<uint32_t>(
                buffer.size() - sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

            auto* header = reinterpret_cast<SHADOWSTRIKE_MESSAGE_HEADER*>(buffer.data());
            BuildMessageHeader(*header, FilterMessageType_PushIoCFeed, dataSize);

            auto* batch = reinterpret_cast<SHADOWSTRIKE_PUSH_BATCH_HEADER*>(
                buffer.data() + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
            BuildBatchHeader(*batch, count, 0,
                dataSize - static_cast<uint32_t>(sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER)));

            auto batchResult = SendBatchMessage(
                std::span<const uint8_t>(buffer.data(), buffer.size()), count);

            aggregate.entriesAccepted += batchResult.entriesAccepted;
            aggregate.entriesRejected += batchResult.entriesRejected;
            aggregate.batchesSent += batchResult.batchesSent;
            if (!batchResult.success) {
                aggregate.success = false;
                aggregate.kernelStatus = batchResult.kernelStatus;
                aggregate.errorMessage = batchResult.errorMessage;
                break;
            }

            offset = idx;
        }

        Utils::Logger::Debug(
            "[ThreatIntelPusher] PushIoCFeed complete: accepted={} rejected={} batches={}",
            aggregate.entriesAccepted, aggregate.entriesRejected, aggregate.batchesSent);

        return aggregate;
    }

    // ========================================================================
    // Behavioral Rule Push Implementation (variable-length entries)
    // ========================================================================

    PushResult PushBehavioralRulesBatch(std::span<const BehavioralRulePushEntry> entries)
    {
        std::lock_guard lock(m_mutex);

        PushResult aggregate;

        if (entries.empty()) {
            aggregate.success = true;
            return aggregate;
        }

        if (!m_connection.IsConnected()) {
            aggregate.success = false;
            aggregate.errorMessage = "FilterConnection not connected";
            Utils::Logger::Warn("[ThreatIntelPusher] PushBehavioralRules aborted: not connected");
            return aggregate;
        }

        aggregate.success = true;
        const uint32_t maxBatch = m_maxBatchSize.load(std::memory_order_relaxed);

        size_t offset = 0;
        while (offset < entries.size()) {
            std::vector<uint8_t> buffer;
            buffer.reserve(MAX_MESSAGE_BUFFER_SIZE);
            buffer.resize(sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
                         + sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER));

            uint32_t count = 0;
            size_t idx = offset;

            while (idx < entries.size() && count < maxBatch) {
                const auto& src = entries[idx];

                // Clamp conditions/actions to kernel maximums
                const uint32_t condCount = static_cast<uint32_t>(
                    std::min<size_t>(src.conditions.size(), RE_MAX_CONDITIONS));
                const uint32_t actCount = static_cast<uint32_t>(
                    std::min<size_t>(src.actions.size(), RE_MAX_ACTIONS));

                // Wire: fixed BEHAVIORAL_RULE header + RE_CONDITION[] + RE_ACTION[]
                size_t entrySize = sizeof(SHADOWSTRIKE_PUSH_BEHAVIORAL_RULE)
                    + condCount * sizeof(RE_CONDITION)
                    + actCount * sizeof(RE_ACTION);

                if (buffer.size() + entrySize > MAX_MESSAGE_BUFFER_SIZE) {
                    if (count == 0) {
                        Utils::Logger::Warn(
                            "[ThreatIntelPusher] Behavioral rule entry too large ({} bytes), skipping",
                            entrySize);
                        aggregate.entriesRejected++;
                        m_stats.oversizedEntriesSkipped.fetch_add(1, std::memory_order_relaxed);
                        ++idx;
                        continue;
                    }
                    break;
                }

                size_t entryOffset = buffer.size();
                buffer.resize(entryOffset + entrySize);

                auto* dst = reinterpret_cast<SHADOWSTRIKE_PUSH_BEHAVIORAL_RULE*>(
                    buffer.data() + entryOffset);
                memset(dst, 0, sizeof(*dst));
                dst->Operation = static_cast<UINT8>(
                    std::min<uint8_t>(static_cast<uint8_t>(src.operation), 3));
                dst->StopProcessing = src.stopProcessing ? 1 : 0;
                dst->Reserved = 0;
                dst->Priority = src.priority;
                strncpy_s(dst->RuleId, sizeof(dst->RuleId),
                    src.ruleId.c_str(), _TRUNCATE);
                strncpy_s(dst->RuleName, sizeof(dst->RuleName),
                    src.ruleName.c_str(), _TRUNCATE);
                strncpy_s(dst->Description, sizeof(dst->Description),
                    src.description.c_str(), _TRUNCATE);
                dst->ConditionCount = condCount;
                dst->ActionCount = actCount;

                // Serialize conditions after the fixed struct
                auto* condPtr = reinterpret_cast<RE_CONDITION*>(
                    buffer.data() + entryOffset
                    + sizeof(SHADOWSTRIKE_PUSH_BEHAVIORAL_RULE));

                for (uint32_t c = 0; c < condCount; ++c) {
                    memset(&condPtr[c], 0, sizeof(RE_CONDITION));
                    condPtr[c].Type = static_cast<RE_CONDITION_TYPE>(
                        std::min(src.conditions[c].type,
                            static_cast<uint32_t>(ReCondition_MaxValue) - 1));
                    condPtr[c].Operator = static_cast<RE_OPERATOR>(
                        std::min(src.conditions[c].op,
                            static_cast<uint32_t>(ReOp_MaxValue) - 1));
                    strncpy_s(condPtr[c].Value, sizeof(condPtr[c].Value),
                        src.conditions[c].value.c_str(), _TRUNCATE);
                    condPtr[c].Negate = src.conditions[c].negate ? TRUE : FALSE;
                }

                // Serialize actions after conditions
                auto* actPtr = reinterpret_cast<RE_ACTION*>(
                    reinterpret_cast<uint8_t*>(condPtr)
                    + condCount * sizeof(RE_CONDITION));

                for (uint32_t a = 0; a < actCount; ++a) {
                    memset(&actPtr[a], 0, sizeof(RE_ACTION));
                    actPtr[a].Type = static_cast<RE_ACTION_TYPE>(
                        std::min(src.actions[a].type,
                            static_cast<uint32_t>(ReAction_MaxValue) - 1));
                    strncpy_s(actPtr[a].Parameter, sizeof(actPtr[a].Parameter),
                        src.actions[a].parameter.c_str(), _TRUNCATE);
                }

                ++count;
                ++idx;
            }

            if (count == 0) {
                offset = idx;
                continue;
            }

            uint32_t dataSize = static_cast<uint32_t>(
                buffer.size() - sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

            auto* header = reinterpret_cast<SHADOWSTRIKE_MESSAGE_HEADER*>(buffer.data());
            BuildMessageHeader(*header, FilterMessageType_UpdateBehavioralRules, dataSize);

            auto* batch = reinterpret_cast<SHADOWSTRIKE_PUSH_BATCH_HEADER*>(
                buffer.data() + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
            BuildBatchHeader(*batch, count, 0,
                dataSize - static_cast<uint32_t>(sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER)));

            auto batchResult = SendBatchMessage(
                std::span<const uint8_t>(buffer.data(), buffer.size()), count);

            aggregate.entriesAccepted += batchResult.entriesAccepted;
            aggregate.entriesRejected += batchResult.entriesRejected;
            aggregate.batchesSent += batchResult.batchesSent;
            if (!batchResult.success) {
                aggregate.success = false;
                aggregate.kernelStatus = batchResult.kernelStatus;
                aggregate.errorMessage = batchResult.errorMessage;
                break;
            }

            offset = idx;
        }

        Utils::Logger::Debug(
            "[ThreatIntelPusher] PushBehavioralRules complete: accepted={} rejected={} batches={}",
            aggregate.entriesAccepted, aggregate.entriesRejected, aggregate.batchesSent);

        return aggregate;
    }

    FilterConnection&               m_connection;
    std::mutex                      m_mutex;
    std::atomic<uint32_t>           m_maxBatchSize;
    std::atomic<uint32_t>           m_replyTimeoutMs;
    std::atomic<uint64_t>           m_nextMessageId;
    PusherStatistics                m_stats;
};

// ============================================================================
// PUBLIC INTERFACE FORWARDING
// ============================================================================

ThreatIntelPusher::ThreatIntelPusher(FilterConnection& connection)
    : m_impl(std::make_unique<Impl>(connection))
{
}

ThreatIntelPusher::~ThreatIntelPusher() = default;

ThreatIntelPusher::ThreatIntelPusher(ThreatIntelPusher&&) noexcept = default;
ThreatIntelPusher& ThreatIntelPusher::operator=(ThreatIntelPusher&&) noexcept = default;

PushResult ThreatIntelPusher::PushHashes(std::span<const HashPushEntry> entries)
{
    return m_impl->PushHashBatch(entries, FilterMessageType_PushHashDatabase);
}

PushResult ThreatIntelPusher::PushPatterns(std::span<const HashPushEntry> entries)
{
    return m_impl->PushHashBatch(entries, FilterMessageType_PushPatternDatabase);
}

PushResult ThreatIntelPusher::PushSignatures(std::span<const HashPushEntry> entries)
{
    return m_impl->PushHashBatch(entries, FilterMessageType_PushSignatureDatabase);
}

PushResult ThreatIntelPusher::PushNetworkIOCs(std::span<const NetworkIOCPushEntry> entries)
{
    return m_impl->PushNetworkIOCBatch(entries);
}

PushResult ThreatIntelPusher::PushWhitelist(std::span<const WhitelistPushEntry> entries)
{
    return m_impl->PushWhitelistBatch(entries);
}

PushResult ThreatIntelPusher::PushExclusions(std::span<const ExclusionPushEntry> entries)
{
    return m_impl->PushExclusionBatch(entries);
}

PushResult ThreatIntelPusher::PushIoCFeed(std::span<const IoCFeedPushEntry> entries)
{
    return m_impl->PushIoCFeedBatch(entries);
}

PushResult ThreatIntelPusher::PushBehavioralRules(std::span<const BehavioralRulePushEntry> entries)
{
    return m_impl->PushBehavioralRulesBatch(entries);
}

PusherStatisticsSnapshot ThreatIntelPusher::GetStatistics() const noexcept
{
    PusherStatisticsSnapshot snap;
    snap.totalPushes         = m_impl->m_stats.totalPushes.load(std::memory_order_relaxed);
    snap.successfulPushes    = m_impl->m_stats.successfulPushes.load(std::memory_order_relaxed);
    snap.failedPushes        = m_impl->m_stats.failedPushes.load(std::memory_order_relaxed);
    snap.totalEntriesPushed  = m_impl->m_stats.totalEntriesPushed.load(std::memory_order_relaxed);
    snap.totalBatchesSent    = m_impl->m_stats.totalBatchesSent.load(std::memory_order_relaxed);
    snap.totalBytesSent      = m_impl->m_stats.totalBytesSent.load(std::memory_order_relaxed);
    snap.oversizedEntriesSkipped = m_impl->m_stats.oversizedEntriesSkipped.load(std::memory_order_relaxed);
    snap.lastPushTimeMs      = m_impl->m_stats.lastPushTimeMs.load(std::memory_order_relaxed);
    snap.lastSuccessTimeMs   = m_impl->m_stats.lastSuccessTimeMs.load(std::memory_order_relaxed);
    return snap;
}

void ThreatIntelPusher::ResetStatistics() noexcept
{
    m_impl->m_stats.totalPushes.store(0, std::memory_order_relaxed);
    m_impl->m_stats.successfulPushes.store(0, std::memory_order_relaxed);
    m_impl->m_stats.failedPushes.store(0, std::memory_order_relaxed);
    m_impl->m_stats.totalEntriesPushed.store(0, std::memory_order_relaxed);
    m_impl->m_stats.totalBatchesSent.store(0, std::memory_order_relaxed);
    m_impl->m_stats.totalBytesSent.store(0, std::memory_order_relaxed);
    m_impl->m_stats.oversizedEntriesSkipped.store(0, std::memory_order_relaxed);
    m_impl->m_stats.lastPushTimeMs.store(0, std::memory_order_relaxed);
    m_impl->m_stats.lastSuccessTimeMs.store(0, std::memory_order_relaxed);
}

bool ThreatIntelPusher::IsConnected() const noexcept
{
    return m_impl->m_connection.IsConnected();
}

void ThreatIntelPusher::SetMaxBatchSize(uint32_t maxEntries) noexcept
{
    m_impl->m_maxBatchSize.store(
        std::min(maxEntries, static_cast<uint32_t>(SHADOWSTRIKE_PUSH_MAX_BATCH_ENTRIES)),
        std::memory_order_relaxed);
}

void ThreatIntelPusher::SetReplyTimeout(uint32_t timeoutMs) noexcept
{
    m_impl->m_replyTimeoutMs.store(timeoutMs, std::memory_order_relaxed);
}

} // namespace Communication
} // namespace ShadowStrike
