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
 * @file Communication.hpp
 * @brief Shared communication structures for kernel-user mode IPC
 *
 * This header defines structures shared between the kernel minifilter driver
 * and user-mode components. These MUST match the kernel definitions in
 * Drivers/Shared/MessageProtocol.h exactly.
 *
 * @copyright ShadowStrike NGAV - Enterprise Security Platform
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <optional>
#include <functional>
#include <memory>

namespace ShadowStrike {
namespace Communication {

//=============================================================================
// Constants
//=============================================================================

constexpr const wchar_t* SHADOWSTRIKE_PORT_NAME = L"\\ShadowStrikePort";
constexpr uint32_t MESSAGE_MAGIC = 0x53534653;  // "SSFS"
constexpr uint16_t PROTOCOL_VERSION = 2;
constexpr size_t MAX_MESSAGE_SIZE = 65536;
constexpr size_t MAX_PATH_LENGTH = 32767;
constexpr uint32_t DEFAULT_REPLY_TIMEOUT_MS = 30000;
constexpr uint32_t MAX_CONCURRENT_CONNECTIONS = 8;

//=============================================================================
// Enumerations — MUST match kernel SHADOWSTRIKE_MESSAGE_TYPE (MessageTypes.h)
// Values are sequential; do NOT reorder without updating the kernel enum.
//=============================================================================

enum class MessageType : uint16_t {
    // Control (0–4)
    None                     = 0,
    Register                 = 1,
    Unregister               = 2,
    Heartbeat                = 3,
    ConfigUpdate             = 4,

    // Scan (5–6) — ScanRequest is the ONLY type requiring a verdict reply
    ScanRequest              = 5,
    ScanVerdictReply         = 6,

    // Behavioral notifications (7–13) — no reply required
    ProcessNotify            = 7,
    ThreadNotify             = 8,
    ImageLoad                = 9,
    RegistryNotify           = 10,
    NamedPipeEvent           = 11,
    FileBackupEvent          = 12,
    FileRollbackEvent        = 13,

    // ALPC notifications (14–20)
    AlpcPortCreated          = 14,
    AlpcPortConnected        = 15,
    AlpcPortDisconnected     = 16,
    AlpcSuspiciousAccess     = 17,
    AlpcImpersonation        = 18,
    AlpcSandboxEscape        = 19,
    AlpcRateLimitExceeded    = 20,

    // Policy (21–25)
    QueryDriverStatus        = 21,
    UpdatePolicy             = 22,
    EnableFiltering          = 23,
    DisableFiltering         = 24,
    RegisterProtectedProcess = 25,

    // Alerts (26–27)
    HandleAlert              = 26,
    RansomwareAlert          = 27,

    // Data push: user → kernel (28–35)
    PushHashDatabase         = 28,
    PushPatternDatabase      = 29,
    PushSignatureDatabase    = 30,
    PushIoCFeed              = 31,
    PushWhitelist            = 32,
    UpdateBehavioralRules    = 33,
    PushNetworkIoC           = 34,
    ExclusionUpdate          = 35,

    // Telemetry / status (36–42)
    BehavioralAlert          = 36,
    MemoryAlert              = 37,
    NetworkAlert             = 38,
    SyscallAlert             = 39,
    SelfProtectAlert         = 40,
    ExclusionQuery           = 41,
    ThreatScoreNotify        = 42,

    Max                      = 43
};

//=============================================================================
// Wire-protocol verdict — MUST match kernel SHADOWSTRIKE_SCAN_VERDICT
// (VerdictTypes.h). Only these values are valid on the comm port wire.
//=============================================================================

enum class ScanVerdict : uint8_t {
    Unknown    = 0,   // Verdict_Unknown    — not yet determined
    Clean      = 1,   // Verdict_Clean      — file is safe
    Malicious  = 2,   // Verdict_Malicious  — confirmed malware
    Suspicious = 3,   // Verdict_Suspicious — heuristic hit, not confirmed
    Error      = 4,   // Verdict_Error      — scan failed
    Timeout    = 5,   // Verdict_Timeout    — scan timed out

    // Backward-compatibility aliases (map action names → verdict values)
    Allow = Clean,
    Block = Malicious
};

enum class FileAccessType : uint8_t {
    Read = 0,
    Write = 1,
    Execute = 2,
    Delete = 3,
    Rename = 4,
    CreateNew = 5,
    OpenExisting = 6
};

enum class ScanPriority : uint8_t {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
    RealTime = 4
};

enum class ConnectionState : uint8_t {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Reconnecting = 3,
    Failed = 4,
    ShuttingDown = 5
};

//=============================================================================
// Message Header (40 bytes, packed)
//=============================================================================

#pragma pack(push, 1)

struct MessageHeader {
    uint32_t magic;           // SHADOWSTRIKE_MESSAGE_MAGIC
    uint16_t version;         // Protocol version
    uint16_t messageType;     // MessageType enum
    uint64_t messageId;       // Unique correlation ID
    uint32_t totalSize;       // Total message size including header
    uint32_t dataSize;        // Payload size
    uint64_t timestamp;       // FILETIME
    uint32_t flags;           // Message flags
    uint32_t reserved;        // Reserved for future use

    [[nodiscard]] bool IsValid() const noexcept {
        return magic == MESSAGE_MAGIC &&
               version <= PROTOCOL_VERSION &&
               totalSize >= sizeof(MessageHeader) &&
               totalSize <= MAX_MESSAGE_SIZE;
    }
};

static_assert(sizeof(MessageHeader) == 40, "MessageHeader must be 40 bytes");

//=============================================================================
// File Scan Request
//=============================================================================

struct FileScanRequestData {
    uint64_t messageId;
    uint8_t accessType;       // FileAccessType
    uint8_t disposition;      // File disposition
    uint8_t priority;         // ScanPriority
    uint8_t requiresReply;    // 1 if reply expected
    uint32_t processId;
    uint32_t threadId;
    uint32_t parentProcessId;
    uint32_t sessionId;
    uint64_t fileSize;
    uint32_t fileAttributes;
    uint32_t desiredAccess;
    uint32_t shareAccess;
    uint32_t createOptions;
    uint32_t volumeSerial;
    uint64_t fileId;
    uint8_t isDirectory;
    uint8_t isNetworkFile;
    uint8_t isRemovableMedia;
    uint8_t hasADS;
    uint16_t pathLength;
    uint16_t processNameLength;
    // Variable length data follows:
    // WCHAR filePath[pathLength]
    // WCHAR processName[processNameLength]
};

//=============================================================================
// Process Notification
//=============================================================================

struct ProcessNotificationData {
    uint64_t messageId;
    uint32_t processId;
    uint32_t parentProcessId;
    uint32_t creatingProcessId;
    uint32_t creatingThreadId;
    uint32_t sessionId;
    uint8_t isWow64;
    uint8_t isElevated;
    uint8_t integrityLevel;
    uint8_t requiresReply;
    uint64_t createTime;
    uint32_t flags;
    uint16_t imagePathLength;
    uint16_t commandLineLength;
    // Variable length data follows
};

//=============================================================================
// Registry Notification
//=============================================================================

struct RegistryNotificationData {
    uint64_t messageId;
    uint32_t processId;
    uint32_t threadId;
    uint32_t operationType;
    uint32_t flags;
    uint8_t requiresReply;
    uint8_t reserved[3];
    uint16_t keyPathLength;
    uint16_t valueNameLength;
    uint32_t valueType;
    uint32_t valueDataLength;
    // Variable length data follows
};

//=============================================================================
// Scan Verdict Reply
//=============================================================================

struct ScanVerdictReplyData {
    uint64_t messageId;       // Correlation with request
    uint8_t verdict;          // ScanVerdict
    uint32_t resultCode;      // Detailed result code
    uint8_t threatDetected;
    uint8_t threatScore;      // 0-100
    uint8_t cacheResult;      // Should cache this verdict
    uint32_t cacheTTL;        // Cache TTL in seconds
    uint32_t reserved;
    uint16_t threatNameLength;
    // Variable: WCHAR threatName[threatNameLength]
};

//=============================================================================
// Policy Update
//=============================================================================

struct PolicyUpdateData {
    uint32_t policyVersion;
    uint32_t flags;
    uint8_t scanOnOpen;
    uint8_t scanOnExecute;
    uint8_t scanOnWrite;
    uint8_t scanOnClose;
    uint8_t blockOnTimeout;
    uint8_t blockOnError;
    uint8_t enableSelfProtection;
    uint8_t enableCaching;
    uint32_t cacheMaxEntries;
    uint32_t cacheTTLSeconds;
    uint32_t replyTimeoutMs;
    uint32_t maxPendingRequests;
    uint32_t reserved[4];
};

//=============================================================================
// Driver Statistics
//=============================================================================

struct DriverStatisticsData {
    uint64_t uptimeSeconds;
    uint64_t filesScanned;
    uint64_t filesBlocked;
    uint64_t filesQuarantined;
    uint64_t processesScanned;
    uint64_t processesBlocked;
    uint64_t registryOpsScanned;
    uint64_t registryOpsBlocked;
    uint64_t cacheHits;
    uint64_t cacheMisses;
    uint64_t messagesReceived;
    uint64_t messagesSent;
    uint64_t timeoutsOccurred;
    uint64_t errorsOccurred;
    uint32_t currentPendingRequests;
    uint32_t peakPendingRequests;
    uint32_t currentConnections;
    uint32_t cacheEntries;
};

#pragma pack(pop)

//=============================================================================
// User-mode Structures (unpacked, for internal use)
//=============================================================================

struct FileScanRequest {
    uint64_t messageId;
    std::wstring filePath;
    std::wstring processName;
    FileAccessType accessType;
    ScanPriority priority;
    uint32_t processId;
    uint32_t threadId;
    uint32_t parentProcessId;
    uint32_t sessionId;
    uint64_t fileSize;
    uint32_t fileAttributes;
    uint32_t desiredAccess;
    uint32_t shareAccess;
    uint32_t createOptions;
    uint32_t volumeSerial;
    uint64_t fileId;
    bool isDirectory;
    bool isNetworkFile;
    bool isRemovableMedia;
    bool hasADS;
    bool requiresReply;
    std::chrono::system_clock::time_point timestamp;

    [[nodiscard]] std::string ToJson() const;
};

struct ProcessNotification {
    uint64_t messageId;
    std::wstring imagePath;
    std::wstring commandLine;
    uint32_t processId;
    uint32_t parentProcessId;
    uint32_t creatingProcessId;
    uint32_t creatingThreadId;
    uint32_t sessionId;
    bool isWow64;
    bool isElevated;
    uint8_t integrityLevel;
    bool requiresReply;
    std::chrono::system_clock::time_point createTime;
    uint32_t flags;

    [[nodiscard]] std::string ToJson() const;
};

struct RegistryNotification {
    uint64_t messageId;
    std::wstring keyPath;
    std::wstring valueName;
    std::vector<uint8_t> valueData;
    uint32_t processId;
    uint32_t threadId;
    uint32_t operationType;
    uint32_t valueType;
    bool requiresReply;
    std::chrono::system_clock::time_point timestamp;

    [[nodiscard]] std::string ToJson() const;
};

struct ScanVerdictReply {
    uint64_t messageId;
    ScanVerdict verdict;
    uint32_t resultCode;
    bool threatDetected;
    uint8_t threatScore;
    bool shouldCache;
    uint32_t cacheTTL;
    std::wstring threatName;

    [[nodiscard]] std::string ToJson() const;
};

//=============================================================================
// Callback Types
//=============================================================================

using FileScanCallback = std::function<ScanVerdictReply(const FileScanRequest&)>;
using ProcessNotifyCallback = std::function<ScanVerdictReply(const ProcessNotification&)>;
using RegistryNotifyCallback = std::function<ScanVerdictReply(const RegistryNotification&)>;
using FileNotifyCallback = std::function<void(const FileScanRequest&)>;
using ProcessEventCallback = std::function<void(const ProcessNotification&)>;
using RegistryEventCallback = std::function<void(const RegistryNotification&)>;
using ConnectionStateCallback = std::function<void(ConnectionState, const std::string&)>;

//=============================================================================
// Statistics
//=============================================================================

struct CommunicationStatistics {
    std::atomic<uint64_t> messagesReceived{0};
    std::atomic<uint64_t> messagesSent{0};
    std::atomic<uint64_t> fileScanRequests{0};
    std::atomic<uint64_t> processNotifications{0};
    std::atomic<uint64_t> registryNotifications{0};
    std::atomic<uint64_t> repliesSent{0};
    std::atomic<uint64_t> timeouts{0};
    std::atomic<uint64_t> errors{0};
    std::atomic<uint64_t> reconnections{0};
    std::atomic<uint64_t> bytesReceived{0};
    std::atomic<uint64_t> bytesSent{0};
    std::chrono::steady_clock::time_point startTime;

    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;

    /**
     * @brief Take a thread-safe point-in-time snapshot of all counters.
     *
     * CommunicationStatistics contains std::atomic members and is non-copyable.
     * Use this method to obtain a copyable snapshot for reporting/serialization.
     */
    [[nodiscard]] CommunicationStatisticsSnapshot TakeSnapshot() const noexcept;
};

/**
 * @brief POD snapshot of CommunicationStatistics (no atomics, freely copyable).
 */
struct CommunicationStatisticsSnapshot {
    uint64_t messagesReceived = 0;
    uint64_t messagesSent = 0;
    uint64_t fileScanRequests = 0;
    uint64_t processNotifications = 0;
    uint64_t registryNotifications = 0;
    uint64_t repliesSent = 0;
    uint64_t timeouts = 0;
    uint64_t errors = 0;
    uint64_t reconnections = 0;
    uint64_t bytesReceived = 0;
    uint64_t bytesSent = 0;
    int64_t uptimeSeconds = 0;

    [[nodiscard]] std::string ToJson() const;
};

//=============================================================================
// Configuration
//=============================================================================

struct CommunicationConfig {
    std::wstring portName = SHADOWSTRIKE_PORT_NAME;
    uint32_t replyTimeoutMs = DEFAULT_REPLY_TIMEOUT_MS;
    uint32_t reconnectIntervalMs = 5000;
    uint32_t maxReconnectAttempts = 10;
    uint32_t messageQueueSize = 1000;
    uint32_t workerThreadCount = 4;
    bool autoReconnect = true;
    bool blockOnTimeout = false;
    bool enableStatistics = true;

    [[nodiscard]] std::string ToJson() const;
    [[nodiscard]] static CommunicationConfig FromJson(const std::string& json);
};

} // namespace Communication
} // namespace ShadowStrike
