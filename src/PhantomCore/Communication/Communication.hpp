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

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// The kernel is the authority on every wire layout in this file. Including it
// here is what allows the static_asserts below to exist at all: before this
// include there was no compile-time relationship between the structs declared
// in this header and the structs the driver actually writes, and two of them
// had silently drifted into layouts the driver has never emitted (see the
// note above ProcessNotificationData / RegistryNotificationData below).
#include "../../../PhantomSensor/Shared/MessageProtocol.h"

namespace ShadowStrike {
namespace Communication {

//=============================================================================
// Constants
//=============================================================================

#ifdef SHADOWSTRIKE_PORT_NAME
inline constexpr const wchar_t* SS_COMM_PORT_NAME = SHADOWSTRIKE_PORT_NAME;
#else
inline constexpr const wchar_t* SS_COMM_PORT_NAME = L"\\ShadowStrikePort";
#endif
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

//=============================================================================
// Kernel verdict — action returned to kernel driver for callback decisions.
// Maps to higher-level scan results for kernel-side enforcement.
//=============================================================================

enum class KernelVerdict : uint8_t {
    Allow      = 0,   // Allow the operation
    Block      = 1,   // Block the operation
    Quarantine = 2,   // Block and quarantine the file
    Log        = 3,   // Allow but log for monitoring
    Monitor    = 3,   // Alias for Log (monitor = log + allow)
    Delay      = 4,   // Defer decision (async scan pending)
    Error      = 5    // Processing error
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

// This struct is a second declaration of FILE_SCAN_REQUEST (MessageProtocol.h).
// It happens to be byte-identical today, field for field, which is precisely why
// it survived while its two neighbours drifted into fiction unnoticed - nothing
// checked either way. Pin it so a divergence is a build failure rather than a
// misparsed file path on the hottest path in the product.
static_assert(sizeof(FileScanRequestData) == sizeof(FILE_SCAN_REQUEST),
              "FileScanRequestData must stay byte-identical to FILE_SCAN_REQUEST in "
              "PhantomSensor/Shared/MessageProtocol.h. If this fires, the kernel and "
              "user-mode views of the file scan request have diverged.");
static_assert(sizeof(FileScanRequestData) == 72,
              "FILE_SCAN_REQUEST is 72 bytes under pack(1); a change on either side "
              "must be made deliberately and on both sides.");
static_assert(offsetof(FileScanRequestData, processId) == 12,
              "processId offset pins the packed layout against silent padding");
static_assert(offsetof(FileScanRequestData, pathLength) == 68,
              "pathLength offset pins the packed layout; the variable-length strings "
              "are located from the end of this struct");
static_assert(offsetof(FileScanRequestData, processNameLength) == 70,
              "processNameLength offset pins the packed layout");

// LENGTH UNITS ARE NOT UNIFORM ACROSS THIS PROTOCOL, and the difference is not
// visible from the field names. Measured, all four sites:
//
//   DECLARED CONTRACT (both headers): CHARACTERS. FILE_SCAN_REQUEST
//     (MessageProtocol.h:159) and SHADOWSTRIKE_FILE_SCAN_REQUEST (SharedDefs.h:539)
//     are byte-identical 72-byte declarations of one layout under two names, and
//     both document "WCHAR FilePath[PathLength]". SHADOWSTRIKE_FILE_SCAN_REQUEST_SIZE
//     (SharedDefs.h:576) budgets pathLen * sizeof(WCHAR), which only makes sense
//     for a character count.
//
//   PIPELINE A - CommPort.c:5380 ShadowStrikeBuildFileScanRequest writes
//     Name.Length / sizeof(WCHAR) = CHARACTERS. Its consumer,
//     FileSystemFilter.cpp:924, does std::wstring(strings, request->pathLength)
//     = reads CHARACTERS. Agrees with the declared contract.
//
//   PIPELINE B - ScanBridge.c:723 SbBuildFileScanRequestEx writes Name.Length
//     = BYTES (this is the live IRP_MJ_CREATE path, via PreCreate.c:1494). Its
//     consumer, RealTimeProtection.cpp:3223, does PathLength / sizeof(wchar_t)
//     = reads BYTES. Self-consistent, and CONTRARY to the declared contract.
//
// Both pipelines therefore work today only because each builder happens to be
// matched to its own reader. Nothing enforces that pairing, and the two structs
// are mutually castable, so routing a pipeline B frame to a pipeline A reader
// doubles the character count (a read past the declared payload) and the reverse
// halves it (a silently truncated file path). Anything parsing this payload must
// state which unit it is using and against which builder it was verified.
//
// This header cannot resolve the disagreement on its own - changing either side
// in isolation breaks the pipeline that currently works - so it is recorded
// rather than silently picked.

//=============================================================================
// Process Notification / Registry Notification - REMOVED, NOT RELOCATED
//=============================================================================
//
// struct ProcessNotificationData  replaced by SHADOWSTRIKE_PROCESS_NOTIFICATION
// struct RegistryNotificationData replaced by SHADOWSTRIKE_REGISTRY_NOTIFICATION
//
// Both structs described layouts THE DRIVER HAS NEVER SENT. Measured against
// PhantomSensor/Shared/MessageProtocol.h:
//
//   ProcessNotificationData  was 48 bytes opening with a uint64 messageId and
//     carrying sessionId / isWow64 / isElevated / integrityLevel / requiresReply
//     / createTime / flags. The wire truth is SHADOWSTRIKE_PROCESS_NOTIFICATION:
//     61 bytes opening with a 40-byte SS_MESSAGE_HEADER the driver zeroes and
//     never fills, then ProcessId / ParentProcessId / CreatingProcessId /
//     CreatingThreadId / Create / ImagePathLength / CommandLineLength. NONE of
//     the seven fields listed above exists on the wire at all.
//
//   RegistryNotificationData was 40 bytes opening with a uint64 messageId and
//     char-count lengths. The wire truth is SHADOWSTRIKE_REGISTRY_NOTIFICATION:
//     21 bytes opening with ProcessId, with BYTE-count lengths.
//
// Because both fabricated structs were LARGER than the real payloads (48 > 21
// and 40 > 21), every parser built on them rejected every genuine frame on its
// minimum-size check and returned nullopt. They failed closed rather than
// misparsing, which is the only reason this never corrupted a verdict - but it
// also means no module built on them could ever read a kernel notification.
//
// THIS IS NOT A HYPOTHETICAL. RegistryMonitor shipped a parser built on
// RegistryNotificationData and consequently never processed a single registry
// event until commit 5fe45d55 replaced it with the kernel struct. Leaving these
// declarations in a header that any module may include is what made that defect
// reachable, so they are deleted rather than corrected: a second declaration of
// the wire format is the defect, and adding a third correct copy would preserve
// the mechanism while fixing only today's instance.
//
// The authoritative user-mode mirrors, which carry their own offset
// static_asserts, are IPCManager::ProcessNotifyRequest and
// IPCManager::RegistryOpRequest (IPCManager.hpp). Parse kernel notifications
// with the kernel structs or with those mirrors - never by re-declaring a
// layout here.

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

// Second declaration of SHADOWSTRIKE_SCAN_VERDICT_REPLY (MessageProtocol.h:319).
// A unit test already compared the two sizes; asserting it here makes the
// divergence a build failure in every translation unit that can produce a reply,
// rather than a failure in one test that could be excluded from the build.
// The verdict byte at offset 8 is load-bearing: it is what turns an
// IRP_MJ_CREATE into STATUS_ACCESS_DENIED, so a shifted layout is a wrong
// allow/block decision, not a cosmetic bug.
static_assert(sizeof(ScanVerdictReplyData) == sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY),
              "ScanVerdictReplyData must stay byte-identical to "
              "SHADOWSTRIKE_SCAN_VERDICT_REPLY in PhantomSensor/Shared/MessageProtocol.h.");
static_assert(sizeof(ScanVerdictReplyData) == 26,
              "SHADOWSTRIKE_SCAN_VERDICT_REPLY is 26 bytes under pack(1), and that number "
              "is also the kernel's entire reply buffer - see "
              "SHADOWSTRIKE_MAX_KERNEL_REPLY_SIZE.");
static_assert(offsetof(ScanVerdictReplyData, verdict) == 8,
              "the verdict byte is read from offset 8 by the driver's create path");
static_assert(offsetof(ScanVerdictReplyData, threatNameLength) == 24,
              "threatNameLength offset pins the packed layout");

//=============================================================================
// Policy Update - REMOVED, NOT RELOCATED
//=============================================================================
//
// struct PolicyUpdateData replaced by SHADOWSTRIKE_POLICY_UPDATE (SharedDefs.h:477)
//
// The third fabricated wire struct in this header, and it did not resemble the
// kernel's policy message even loosely. Measured:
//
//   PolicyUpdateData        48 bytes. Opened with policyVersion + flags, neither of
//                           which exists on the wire. Carried scanOnClose,
//                           enableSelfProtection, enableCaching, cacheMaxEntries,
//                           replyTimeoutMs and reserved[4].
//   SHADOWSTRIKE_POLICY_UPDATE  44 bytes. Opens with eight BOOLEANs
//                           (ScanOnOpen, ScanOnExecute, ScanOnWrite,
//                           EnableNotifications, BlockOnTimeout, BlockOnError,
//                           ScanNetworkFiles, ScanRemovableMedia), then
//                           MaxScanFileSize, ScanTimeoutMs, CacheTTLSeconds,
//                           MaxPendingRequests and four Mq* queue-tuning fields.
//
// Six fields the user-mode struct declared do not exist on the wire, and seven the
// wire carries were absent from it - including MaxScanFileSize and the entire
// message-queue tuning block. It had ZERO consumers repo-wide (declaration only),
// so nothing was broken by it; it was purely a wrong answer waiting to be found by
// whoever implemented policy push next.
//
// Send policy with SHADOWSTRIKE_POLICY_UPDATE.

//=============================================================================
// Driver Statistics
//=============================================================================
//
// UNVERIFIED AGAINST THE KERNEL. DriverStatisticsData below has ZERO consumers
// repo-wide, and the nearest kernel declaration is SHADOWSTRIKE_DRIVER_STATUS
// (SharedDefs.h:301), which was NOT compared field by field. It is therefore left
// in place rather than deleted alongside the three structs above: three of them
// were measured and proven wrong, this one was not measured, and removing an
// unmeasured declaration on the strength of its neighbours would be guessing.
// Anyone wiring driver statistics must compare it against the kernel struct FIRST
// and pin the result, exactly as FileScanRequestData and ScanVerdictReplyData now
// are.

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
    /// NOT CARRIED BY THE KERNEL PAYLOAD. See the block below.
    uint64_t messageId = 0;
    std::wstring imagePath;
    std::wstring commandLine;
    uint32_t processId = 0;
    uint32_t parentProcessId = 0;
    uint32_t creatingProcessId = 0;
    uint32_t creatingThreadId = 0;

    /// TRUE for a process creation, FALSE for a process exit. This mirrors
    /// SHADOWSTRIKE_PROCESS_NOTIFICATION::Create, and it is the only field in the
    /// payload that says which of the two events this is. It was absent from this
    /// struct entirely while the parser read a fabricated layout, so a caller had
    /// no way to distinguish a launch from a termination.
    bool isCreation = false;

    /// FIELDS BELOW HAVE NO SOURCE IN THE KERNEL PAYLOAD.
    /// SHADOWSTRIKE_PROCESS_NOTIFICATION carries only the four ids, Create, and the
    /// two length fields. messageId (correlation lives in the outer frame header),
    /// sessionId, isWow64, isElevated, integrityLevel, requiresReply, createTime and
    /// flags are therefore whatever the producer chose to put here - they are NOT
    /// reported by the driver. Resolving any of them means either a wire-format
    /// change on both sides or a user-mode query against the pid, and such a query
    /// must not be made on a thread that owes the kernel a verdict (see
    /// ProcessUtils::SecurityInfoScope).
    ///
    /// EVERY ONE OF THESE IS EXPLICITLY INITIALISED. A parser that legitimately
    /// leaves them alone must leave a determinate value behind: an indeterminate
    /// read is undefined behaviour, and a garbage session id or elevation flag is
    /// far worse than a zero, because it can be acted upon.
    uint32_t sessionId = 0;
    bool isWow64 = false;
    bool isElevated = false;
    uint8_t integrityLevel = 0;
    bool requiresReply = false;
    std::chrono::system_clock::time_point createTime{};
    uint32_t flags = 0;

    [[nodiscard]] std::string ToJson() const;
};

struct RegistryNotification {
    /// NOT CARRIED BY THE KERNEL PAYLOAD - correlation lives in the outer frame
    /// header. Initialised so an unset value is a determinate zero, never garbage.
    uint64_t messageId = 0;
    std::wstring keyPath;
    std::wstring valueName;
    std::vector<uint8_t> valueData;
    uint32_t processId = 0;
    uint32_t threadId = 0;
    uint32_t operationType = 0;
    uint32_t valueType = 0;

    /// NOT CARRIED BY THE KERNEL PAYLOAD. The registry feed is fire-and-forget in
    /// the driver (ShadowStrikeSendNotification, no reply buffer), so this could
    /// only ever be false for a kernel-sourced event.
    bool requiresReply = false;
    std::chrono::system_clock::time_point timestamp{};

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
// Callback Types (only if not already defined by IPCManager.hpp kernel types)
//=============================================================================

#ifndef SS_IPC_CALLBACK_TYPES_DEFINED
using FileScanCallback = std::function<ScanVerdictReply(const FileScanRequest&)>;
using ProcessNotifyCallback = std::function<ScanVerdictReply(const ProcessNotification&)>;
using RegistryNotifyCallback = std::function<ScanVerdictReply(const RegistryNotification&)>;
using FileNotifyCallback = std::function<void(const FileScanRequest&)>;
using ProcessEventCallback = std::function<void(const ProcessNotification&)>;
using RegistryEventCallback = std::function<void(const RegistryNotification&)>;
using ConnectionStateCallback = std::function<void(ConnectionState, const std::string&)>;
#endif

//=============================================================================
// Statistics
//=============================================================================

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

//=============================================================================
// Configuration
//=============================================================================

struct CommunicationConfig {
    std::wstring portName = SS_COMM_PORT_NAME;
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
