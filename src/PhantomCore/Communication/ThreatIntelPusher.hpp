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
 * @file ThreatIntelPusher.hpp
 * @brief Pushes threat intelligence data from user-mode stores to the kernel
 *        driver's detection modules via the FilterConnection communication port.
 *
 * Architecture:
 *   ThreatIntelStore / HashStore / WhiteListStore
 *              ↓ (enumeration)
 *   ThreatIntelPusher (serialization + batching)
 *              ↓ (FilterConnection::SendMessage)
 *   Kernel MessageHandler → IOCMatcher / C2Detection / DnsMonitor /
 *                           NetworkReputation / ExclusionManager / RuleEngine
 *
 * Wire format: SHADOWSTRIKE_MESSAGE_HEADER + SHADOWSTRIKE_PUSH_BATCH_HEADER
 *              + N × SHADOWSTRIKE_PUSH_*_ENTRY
 *
 * Thread safety: All public methods are thread-safe via internal mutex.
 *
 * @see PhantomSensor/Shared/MessageProtocol.h for wire format definitions
 * @see PhantomSensor/Communication/MessageHandler.c for kernel-side handlers
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <functional>
#include <atomic>
#include <chrono>
#include <optional>

namespace ShadowStrike {
namespace Communication {

// Forward declarations
class FilterConnection;

/**
 * @brief Result of a push operation to the kernel driver.
 */
struct PushResult {
    bool success = false;
    uint32_t entriesAccepted = 0;
    uint32_t entriesRejected = 0;
    uint32_t batchesSent = 0;
    uint32_t kernelStatus = 0;   // NTSTATUS from kernel reply
    std::string errorMessage;

    [[nodiscard]] bool IsComplete() const noexcept {
        return success && entriesRejected == 0;
    }

    [[nodiscard]] uint32_t TotalEntries() const noexcept {
        return entriesAccepted + entriesRejected;
    }
};

/**
 * @brief Aggregate result of a full sync operation.
 */
struct SyncResult {
    PushResult hashes;
    PushResult patterns;
    PushResult signatures;
    PushResult networkIOCs;
    PushResult whitelist;
    PushResult exclusions;
    PushResult iocFeed;
    PushResult behavioralRules;
    std::chrono::milliseconds elapsed{0};

    [[nodiscard]] bool AllSucceeded() const noexcept {
        return hashes.success && patterns.success && signatures.success &&
               networkIOCs.success && whitelist.success && exclusions.success &&
               iocFeed.success && behavioralRules.success;
    }

    [[nodiscard]] uint32_t TotalAccepted() const noexcept {
        return hashes.entriesAccepted + patterns.entriesAccepted +
               signatures.entriesAccepted + networkIOCs.entriesAccepted +
               whitelist.entriesAccepted + exclusions.entriesAccepted +
               iocFeed.entriesAccepted + behavioralRules.entriesAccepted;
    }
};

/**
 * @brief Hash entry for pushing to kernel IOCMatcher.
 */
struct HashPushEntry {
    uint8_t  hashType;      // 0=MD5, 1=SHA1, 2=SHA256
    uint8_t  verdict;       // 0=Unknown, 1=Clean, 2=Malicious, 3=Suspicious
    uint8_t  severity;      // Severity level (0-4)
    uint32_t score;         // Threat score 0-100
    uint8_t  hash[32];      // Hash bytes (left-padded for shorter hashes)
    std::string threatName; // Threat family name
    int64_t  expiry;        // FILETIME expiry (0 = no expiry)
};

/**
 * @brief Network IoC entry for pushing to C2Detection/DnsMonitor/NetworkReputation.
 */
struct NetworkIOCPushEntry {
    enum Type : uint8_t {
        IPv4 = 0, IPv6 = 1, Domain = 2, JA3 = 3, URL = 4
    };

    Type     type;
    uint8_t  reputation;    // NR_REPUTATION value
    uint16_t categories;    // NR_CATEGORY bitmask
    uint32_t score;         // 0-100
    std::string threatName;
    std::string malwareFamily;
    std::string value;      // IP string, domain, JA3 hex, or URL
    uint8_t  ipv4[4];       // For IPv4 type
    uint8_t  ipv6[16];      // For IPv6 type
    uint8_t  ja3Hash[16];   // For JA3 type (MD5)
    int64_t  expiry;
};

/**
 * @brief Whitelist entry for pushing to ExclusionManager.
 */
struct WhitelistPushEntry {
    enum Type : uint8_t {
        Hash = 0, Path = 1, Process = 2, Certificate = 3
    };

    Type     entryType;
    uint8_t  hashType;      // For hash entries
    uint8_t  flags;
    uint8_t  hash[32];      // For hash entries
    std::wstring value;     // Path or process name (wide string for kernel)
};

/**
 * @brief Exclusion entry for pushing to ExclusionManager.
 */
struct ExclusionPushEntry {
    enum ExclType : uint8_t {
        PathExcl = 0, ExtensionExcl = 1, ProcessNameExcl = 2, PIDExcl = 3
    };
    enum Operation : uint8_t {
        Add = 0, Remove = 1, Clear = 2
    };

    ExclType  exclusionType;
    Operation operation;
    uint8_t   flags;
    uint32_t  ttlSeconds;   // 0 = permanent
    std::wstring value;     // Path, extension, or process name
    uint64_t  pid;          // For PID exclusions
};

/**
 * @brief IoC Feed entry for pushing to kernel IOCMatcher.
 *
 * Variable-length entry — the value string (hash, IP, domain, URL)
 * is appended after the fixed header on the wire.
 */
struct IoCFeedPushEntry {
    uint8_t     type;           // IOM_IOC_TYPE value
    uint8_t     severity;       // IOM_SEVERITY value (0-4)
    uint8_t     matchMode;      // IOM_MATCH_MODE value
    bool        caseSensitive;
    std::string threatName;     // max 63 chars
    std::string source;         // max 63 chars (attribution)
    std::string value;          // The IoC value (hash hex, IP, domain, URL)
    int64_t     expiry;         // FILETIME expiry (0 = no expiry)
};

/**
 * @brief Condition for behavioral rule push.
 */
struct BehavioralRuleCondition {
    uint32_t    type;           // RE_CONDITION_TYPE (0-12)
    uint32_t    op;             // RE_OPERATOR (0-9)
    std::string value;          // max 255 chars
    bool        negate = false;
};

/**
 * @brief Action for behavioral rule push.
 */
struct BehavioralRuleAction {
    uint32_t    type;           // RE_ACTION_TYPE (0-8)
    std::string parameter;      // max 255 chars
};

/**
 * @brief Behavioral rule entry for pushing to kernel RuleEngine.
 *
 * Supports Add/Remove/Enable/Disable operations.
 * For Add: conditions and actions must be populated.
 * For Remove/Enable/Disable: only ruleId is required.
 */
struct BehavioralRulePushEntry {
    enum Operation : uint8_t {
        Add = 0, Remove = 1, Enable = 2, Disable = 3
    };

    Operation   operation;
    bool        stopProcessing = false;
    uint32_t    priority = 0;
    std::string ruleId;         // max 31 chars
    std::string ruleName;       // max 63 chars (Add only)
    std::string description;    // max 255 chars (Add only)
    std::vector<BehavioralRuleCondition> conditions;  // max 16
    std::vector<BehavioralRuleAction>    actions;      // max 8
};

/**
 * @brief Thread-safe statistics for push operations.
 *
 * All fields are atomic. Timestamps stored as epoch milliseconds
 * (int64_t) to avoid data races on non-atomic time_point.
 */
struct PusherStatistics {
    std::atomic<uint64_t> totalPushes{0};
    std::atomic<uint64_t> successfulPushes{0};
    std::atomic<uint64_t> failedPushes{0};
    std::atomic<uint64_t> totalEntriesPushed{0};
    std::atomic<uint64_t> totalBatchesSent{0};
    std::atomic<uint64_t> totalBytesSent{0};
    std::atomic<uint64_t> oversizedEntriesSkipped{0};
    std::atomic<int64_t>  lastPushTimeMs{0};     // epoch ms
    std::atomic<int64_t>  lastSuccessTimeMs{0};  // epoch ms
};

/**
 * @brief POD snapshot of PusherStatistics for thread-safe reading.
 */
struct PusherStatisticsSnapshot {
    uint64_t totalPushes = 0;
    uint64_t successfulPushes = 0;
    uint64_t failedPushes = 0;
    uint64_t totalEntriesPushed = 0;
    uint64_t totalBatchesSent = 0;
    uint64_t totalBytesSent = 0;
    uint64_t oversizedEntriesSkipped = 0;
    int64_t  lastPushTimeMs = 0;
    int64_t  lastSuccessTimeMs = 0;
};

/**
 * @class ThreatIntelPusher
 * @brief Serializes threat intelligence data and pushes it to the kernel
 *        driver's detection modules via the minifilter communication port.
 *
 * Usage:
 * @code
 *   auto pusher = std::make_unique<ThreatIntelPusher>(filterConnection);
 *
 *   // Push individual hash batch
 *   std::vector<HashPushEntry> hashes = ...;
 *   auto result = pusher->PushHashes(hashes);
 *
 *   // Push network IoCs
 *   std::vector<NetworkIOCPushEntry> iocs = ...;
 *   auto result = pusher->PushNetworkIOCs(iocs);
 * @endcode
 */
class ThreatIntelPusher final {
public:
    /**
     * @brief Construct a ThreatIntelPusher with an existing FilterConnection.
     * @param connection Active FilterConnection to the kernel driver.
     *                   Must remain valid for the lifetime of this pusher.
     */
    explicit ThreatIntelPusher(FilterConnection& connection);

    ~ThreatIntelPusher();

    ThreatIntelPusher(const ThreatIntelPusher&) = delete;
    ThreatIntelPusher& operator=(const ThreatIntelPusher&) = delete;
    ThreatIntelPusher(ThreatIntelPusher&&) noexcept;
    ThreatIntelPusher& operator=(ThreatIntelPusher&&) noexcept;

    // =========================================================================
    // Hash Pushes (FilterMessageType_PushHashDatabase)
    // =========================================================================

    /**
     * @brief Push a batch of file hashes to the kernel IOCMatcher.
     * @param entries Hash entries to push.
     * @return Push result with accepted/rejected counts.
     *
     * Automatically batches into chunks of SHADOWSTRIKE_PUSH_MAX_BATCH_ENTRIES
     * (4096) if the input exceeds that limit.
     */
    [[nodiscard]] PushResult PushHashes(std::span<const HashPushEntry> entries);

    // =========================================================================
    // Pattern Pushes (FilterMessageType_PushPatternDatabase)
    // =========================================================================

    /**
     * @brief Push pattern entries to the kernel IOCMatcher.
     * @param entries Pattern entries (same wire format as hashes).
     * @return Push result.
     */
    [[nodiscard]] PushResult PushPatterns(std::span<const HashPushEntry> entries);

    // =========================================================================
    // Signature Pushes (FilterMessageType_PushSignatureDatabase)
    // =========================================================================

    /**
     * @brief Push signature entries to the kernel IOCMatcher.
     * @param entries Signature entries (same wire format as hashes).
     * @return Push result.
     */
    [[nodiscard]] PushResult PushSignatures(std::span<const HashPushEntry> entries);

    // =========================================================================
    // Network IoC Pushes (FilterMessageType_PushNetworkIoC)
    // =========================================================================

    /**
     * @brief Push network IoCs to C2Detection/DnsMonitor/NetworkReputation.
     * @param entries Network IoC entries (IPs, domains, JA3, URLs).
     * @return Push result.
     */
    [[nodiscard]] PushResult PushNetworkIOCs(std::span<const NetworkIOCPushEntry> entries);

    // =========================================================================
    // Whitelist Pushes (FilterMessageType_PushWhitelist)
    // =========================================================================

    /**
     * @brief Push whitelist entries to ExclusionManager.
     * @param entries Whitelist entries (hashes, paths, processes).
     * @return Push result.
     */
    [[nodiscard]] PushResult PushWhitelist(std::span<const WhitelistPushEntry> entries);

    // =========================================================================
    // Exclusion Updates (FilterMessageType_ExclusionUpdate)
    // =========================================================================

    /**
     * @brief Push exclusion updates (add/remove/clear).
     * @param entries Exclusion entries.
     * @return Push result.
     */
    [[nodiscard]] PushResult PushExclusions(std::span<const ExclusionPushEntry> entries);

    // =========================================================================
    // IoC Feed Pushes (FilterMessageType_PushIoCFeed)
    // =========================================================================

    /**
     * @brief Push IoC feed entries to kernel IOCMatcher.
     * @param entries Variable-length IoC entries (hashes, IPs, domains, URLs).
     * @return Push result.
     *
     * Uses SHADOWSTRIKE_PUSH_IOC_ENTRY wire format. Entries are variable-length
     * (value string appended after fixed header). Auto-batched to fit 64KB.
     */
    [[nodiscard]] PushResult PushIoCFeed(std::span<const IoCFeedPushEntry> entries);

    // =========================================================================
    // Behavioral Rule Updates (FilterMessageType_UpdateBehavioralRules)
    // =========================================================================

    /**
     * @brief Push behavioral rule updates to kernel RuleEngine.
     * @param entries Rule entries (Add/Remove/Enable/Disable).
     * @return Push result.
     *
     * For Add operations, RE_CONDITION and RE_ACTION structs are appended
     * after the fixed SHADOWSTRIKE_PUSH_BEHAVIORAL_RULE header.
     * Max 16 conditions and 8 actions per rule.
     */
    [[nodiscard]] PushResult PushBehavioralRules(std::span<const BehavioralRulePushEntry> entries);

    // =========================================================================
    // Diagnostics
    // =========================================================================

    /**
     * @brief Get a thread-safe snapshot of push operation statistics.
     */
    [[nodiscard]] PusherStatisticsSnapshot GetStatistics() const noexcept;

    /**
     * @brief Reset statistics counters.
     */
    void ResetStatistics() noexcept;

    /**
     * @brief Check if the underlying connection is active.
     */
    [[nodiscard]] bool IsConnected() const noexcept;

    /**
     * @brief Set maximum entries per batch (default: 4096).
     */
    void SetMaxBatchSize(uint32_t maxEntries) noexcept;

    /**
     * @brief Set reply timeout in milliseconds (default: 30000).
     */
    void SetReplyTimeout(uint32_t timeoutMs) noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Communication
} // namespace ShadowStrike
