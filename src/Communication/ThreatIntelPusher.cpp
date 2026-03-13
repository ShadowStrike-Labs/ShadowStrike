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

#include <Windows.h>
#include <mutex>
#include <algorithm>
#include <cstring>

// Shared protocol definitions (kernel/user-mode compatible)
#include "../../PhantomSensor/Shared/MessageProtocol.h"
#include "../../PhantomSensor/Shared/MessageTypes.h"

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
    explicit Impl(FilterConnection& connection) noexcept
        : m_connection(connection)
        , m_maxBatchSize(DEFAULT_MAX_BATCH_SIZE)
        , m_replyTimeoutMs(DEFAULT_REPLY_TIMEOUT_MS)
        , m_nextMessageId(1)
    {
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

        // Allocate reply buffer for SHADOWSTRIKE_PUSH_REPLY
        uint8_t replyBuf[sizeof(SHADOWSTRIKE_PUSH_REPLY) + 64];
        std::span<uint8_t> replySpan(replyBuf, sizeof(replyBuf));

        size_t replySize = m_connection.SendMessage(
            messageBuffer, replySpan, m_replyTimeoutMs);

        if (replySize >= sizeof(SHADOWSTRIKE_PUSH_REPLY)) {
            auto* reply = reinterpret_cast<const SHADOWSTRIKE_PUSH_REPLY*>(replyBuf);
            result.success = (reply->Status == 0); // STATUS_SUCCESS
            result.entriesAccepted = reply->EntriesAccepted;
            result.entriesRejected = reply->EntriesRejected;
            result.kernelStatus = reply->Status;
            result.batchesSent = 1;
        } else if (replySize == 0) {
            // SendMessage returned 0 — might be fire-and-forget success
            // or connection error. Check connection state.
            if (m_connection.IsConnected()) {
                // Assume success with no reply (fire-and-forget mode)
                result.success = true;
                result.entriesAccepted = entryCount;
                result.batchesSent = 1;
            } else {
                result.success = false;
                result.errorMessage = "FilterConnection disconnected";
            }
        } else {
            result.success = false;
            result.errorMessage = "Invalid reply size: " + std::to_string(replySize);
        }

        // Update statistics
        m_stats.totalBatchesSent.fetch_add(1, std::memory_order_relaxed);
        m_stats.totalBytesSent.fetch_add(
            messageBuffer.size(), std::memory_order_relaxed);

        if (result.success) {
            m_stats.successfulPushes.fetch_add(1, std::memory_order_relaxed);
            m_stats.totalEntriesPushed.fetch_add(
                result.entriesAccepted, std::memory_order_relaxed);
            m_stats.lastSuccessTime = std::chrono::system_clock::now();
        } else {
            m_stats.failedPushes.fetch_add(1, std::memory_order_relaxed);
        }

        m_stats.totalPushes.fetch_add(1, std::memory_order_relaxed);
        m_stats.lastPushTime = std::chrono::system_clock::now();

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
        aggregate.success = true;

        const uint32_t batchMax = std::min(
            m_maxBatchSize,
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

            // Build message buffer
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
                dst.HashType = src.hashType;
                dst.Verdict = src.verdict;
                dst.Severity = src.severity;
                dst.Reserved = 0;
                dst.Score = src.score;
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
                break; // Stop on first failure
            }

            offset += count;
        }

        return aggregate;
    }

    // ========================================================================
    // Network IoC Push Implementation
    // ========================================================================

    PushResult PushNetworkIOCBatch(std::span<const NetworkIOCPushEntry> entries)
    {
        std::lock_guard lock(m_mutex);

        PushResult aggregate;
        aggregate.success = true;

        const uint32_t batchMax = std::min(
            m_maxBatchSize,
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
                dst.Type = static_cast<UINT8>(src.type);
                dst.Reputation = src.reputation;
                dst.Categories = src.categories;
                dst.Score = src.score;
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

        return aggregate;
    }

    // ========================================================================
    // Whitelist Push Implementation
    // ========================================================================

    PushResult PushWhitelistBatch(std::span<const WhitelistPushEntry> entries)
    {
        std::lock_guard lock(m_mutex);

        PushResult aggregate;
        aggregate.success = true;

        // Whitelist entries are variable-length (path/process names appended).
        // Send one batch at a time, packing as many entries as fit in 64KB.
        size_t offset = 0;
        while (offset < entries.size()) {
            std::vector<uint8_t> buffer;
            buffer.reserve(MAX_MESSAGE_BUFFER_SIZE);

            // Reserve space for headers
            buffer.resize(sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
                         + sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER));

            uint32_t count = 0;
            size_t idx = offset;

            while (idx < entries.size() && count < m_maxBatchSize) {
                const auto& src = entries[idx];

                // Calculate this entry's wire size
                size_t entrySize = sizeof(SHADOWSTRIKE_PUSH_WHITELIST_ENTRY)
                    + src.value.size() * sizeof(wchar_t);

                if (buffer.size() + entrySize > MAX_MESSAGE_BUFFER_SIZE) {
                    if (count == 0) {
                        // Single entry exceeds buffer — skip it
                        ++idx;
                        continue;
                    }
                    break;
                }

                // Serialize entry
                size_t entryOffset = buffer.size();
                buffer.resize(entryOffset + sizeof(SHADOWSTRIKE_PUSH_WHITELIST_ENTRY)
                             + src.value.size() * sizeof(wchar_t));

                auto* dst = reinterpret_cast<SHADOWSTRIKE_PUSH_WHITELIST_ENTRY*>(
                    buffer.data() + entryOffset);
                memset(dst, 0, sizeof(*dst));
                dst->EntryType = static_cast<UINT8>(src.entryType);
                dst->HashType = src.hashType;
                dst->Flags = src.flags;
                memcpy(dst->Hash, src.hash, sizeof(dst->Hash));
                dst->ValueLength = static_cast<UINT16>(src.value.size());

                // Append wide string value after the fixed structure
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

            // Fill headers
            uint32_t dataSize = static_cast<uint32_t>(
                buffer.size() - sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

            auto* header = reinterpret_cast<SHADOWSTRIKE_MESSAGE_HEADER*>(buffer.data());
            BuildMessageHeader(*header, FilterMessageType_PushWhitelist, dataSize);

            auto* batch = reinterpret_cast<SHADOWSTRIKE_PUSH_BATCH_HEADER*>(
                buffer.data() + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
            BuildBatchHeader(*batch, count, 0, // 0 = variable size entries
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

        return aggregate;
    }

    // ========================================================================
    // Exclusion Push Implementation
    // ========================================================================

    PushResult PushExclusionBatch(std::span<const ExclusionPushEntry> entries)
    {
        std::lock_guard lock(m_mutex);

        PushResult aggregate;
        aggregate.success = true;

        size_t offset = 0;
        while (offset < entries.size()) {
            std::vector<uint8_t> buffer;
            buffer.reserve(MAX_MESSAGE_BUFFER_SIZE);
            buffer.resize(sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
                         + sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER));

            uint32_t count = 0;
            size_t idx = offset;

            while (idx < entries.size() && count < m_maxBatchSize) {
                const auto& src = entries[idx];

                size_t valueBytes = (src.exclusionType == ExclusionPushEntry::PIDExcl)
                    ? sizeof(uint64_t)
                    : src.value.size() * sizeof(wchar_t);

                size_t entrySize = sizeof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY) + valueBytes;

                if (buffer.size() + entrySize > MAX_MESSAGE_BUFFER_SIZE) {
                    if (count == 0) { ++idx; continue; }
                    break;
                }

                size_t entryOffset = buffer.size();
                buffer.resize(entryOffset + entrySize);

                auto* dst = reinterpret_cast<SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY*>(
                    buffer.data() + entryOffset);
                memset(dst, 0, sizeof(*dst));
                dst->ExclusionType = static_cast<UINT8>(src.exclusionType);
                dst->Operation = static_cast<UINT8>(src.operation);
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

        return aggregate;
    }

    // ========================================================================
    // State
    // ========================================================================

    FilterConnection&       m_connection;
    std::mutex              m_mutex;
    uint32_t                m_maxBatchSize;
    uint32_t                m_replyTimeoutMs;
    std::atomic<uint64_t>   m_nextMessageId;
    PusherStatistics        m_stats;
};

// ============================================================================
// PUBLIC INTERFACE FORWARDING
// ============================================================================

ThreatIntelPusher::ThreatIntelPusher(FilterConnection& connection) noexcept
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

const PusherStatistics& ThreatIntelPusher::GetStatistics() const noexcept
{
    return m_impl->m_stats;
}

void ThreatIntelPusher::ResetStatistics() noexcept
{
    m_impl->m_stats.totalPushes.store(0);
    m_impl->m_stats.successfulPushes.store(0);
    m_impl->m_stats.failedPushes.store(0);
    m_impl->m_stats.totalEntriesPushed.store(0);
    m_impl->m_stats.totalBatchesSent.store(0);
    m_impl->m_stats.totalBytesSent.store(0);
}

bool ThreatIntelPusher::IsConnected() const noexcept
{
    return m_impl->m_connection.IsConnected();
}

void ThreatIntelPusher::SetMaxBatchSize(uint32_t maxEntries) noexcept
{
    m_impl->m_maxBatchSize = std::min(maxEntries,
        static_cast<uint32_t>(SHADOWSTRIKE_PUSH_MAX_BATCH_ENTRIES));
}

void ThreatIntelPusher::SetReplyTimeout(uint32_t timeoutMs) noexcept
{
    m_impl->m_replyTimeoutMs = timeoutMs;
}

} // namespace Communication
} // namespace ShadowStrike
