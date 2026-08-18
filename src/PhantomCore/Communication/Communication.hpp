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
    // EVERY VALUE IS DERIVED from the kernel enum in
    // PhantomSensor/Shared/MessageTypes.h, which is the single authority for what
    // travels on the comm port. Do not restate a number here.
    //
    // This list previously carried explicit literals and they had DRIFTED. It was
    // missing FilterMessageType_KeyExchange, so every value from ScanRequest
    // onward was low by one, and it was missing FileOperationEvent, so Max was low
    // by two: 39 of 45 enumerators named a different message class than the one
    // they select on the wire. ProcessNotify read 7, which is ScanVerdict - a type
    // with a registered driver handler. Nothing compared the two declarations,
    // which is the only reason it survived.
    //
    // Deriving the values makes that drift UNREPRESENTABLE rather than merely
    // detectable. Derivation cannot catch an enumerator being ABSENT, so the
    // static_assert below fails the build when the kernel enum grows.

    None                     = FilterMessageType_None,
    Register                 = FilterMessageType_Register,
    Unregister               = FilterMessageType_Unregister,
    Heartbeat                = FilterMessageType_Heartbeat,
    ConfigUpdate             = FilterMessageType_ConfigUpdate,
    KeyExchange              = FilterMessageType_KeyExchange,
    ScanRequest              = FilterMessageType_ScanRequest,
    ScanVerdictReply         = FilterMessageType_ScanVerdict,
    ProcessNotify            = FilterMessageType_ProcessNotify,
    ThreadNotify             = FilterMessageType_ThreadNotify,
    ImageLoad                = FilterMessageType_ImageLoad,
    RegistryNotify           = FilterMessageType_RegistryNotify,
    NamedPipeEvent           = FilterMessageType_NamedPipeEvent,
    FileBackupEvent          = FilterMessageType_FileBackupEvent,
    FileRollbackEvent        = FilterMessageType_FileRollbackEvent,
    AlpcPortCreated          = FilterMessageType_AlpcPortCreated,
    AlpcPortConnected        = FilterMessageType_AlpcPortConnected,
    AlpcPortDisconnected     = FilterMessageType_AlpcPortDisconnected,
    AlpcSuspiciousAccess     = FilterMessageType_AlpcSuspiciousAccess,
    AlpcImpersonation        = FilterMessageType_AlpcImpersonation,
    AlpcSandboxEscape        = FilterMessageType_AlpcSandboxEscape,
    AlpcRateLimitExceeded    = FilterMessageType_AlpcRateLimitExceeded,
    QueryDriverStatus        = FilterMessageType_QueryDriverStatus,
    UpdatePolicy             = FilterMessageType_UpdatePolicy,
    EnableFiltering          = FilterMessageType_EnableFiltering,
    DisableFiltering         = FilterMessageType_DisableFiltering,
    RegisterProtectedProcess = FilterMessageType_RegisterProtectedProcess,
    HandleAlert              = FilterMessageType_HandleAlert,
    RansomwareAlert          = FilterMessageType_RansomwareAlert,
    PushHashDatabase         = FilterMessageType_PushHashDatabase,
    PushPatternDatabase      = FilterMessageType_PushPatternDatabase,
    PushSignatureDatabase    = FilterMessageType_PushSignatureDatabase,
    PushIoCFeed              = FilterMessageType_PushIoCFeed,
    PushWhitelist            = FilterMessageType_PushWhitelist,
    UpdateBehavioralRules    = FilterMessageType_UpdateBehavioralRules,
    PushNetworkIoC           = FilterMessageType_PushNetworkIoC,
    ExclusionUpdate          = FilterMessageType_ExclusionUpdate,
    BehavioralAlert          = FilterMessageType_BehavioralAlert,
    MemoryAlert              = FilterMessageType_MemoryAlert,
    NetworkAlert             = FilterMessageType_NetworkAlert,
    SyscallAlert             = FilterMessageType_SyscallAlert,
    SelfProtectAlert         = FilterMessageType_SelfProtectAlert,
    ExclusionQuery           = FilterMessageType_ExclusionQuery,
    ThreatScoreNotify        = FilterMessageType_ThreatScoreNotify,
    FileOperationEvent       = FilterMessageType_FileOperationEvent,

    Max                      = FilterMessageType_Max
};

// REVIEW PROMPT, deliberately not a tautology. The values above cannot drift, but
// an enumerator missing from this mirror still can - that is exactly how
// KeyExchange and FileOperationEvent went absent. This fails the build when the
// kernel enum grows, so whoever appends a type is forced to visit this list.
static_assert(static_cast<uint16_t>(MessageType::Max) == 45,
              "Kernel message enum grew: add the new type to Communication::MessageType, "
              "then bump this count in the same change.");
static_assert(sizeof(MessageType) == sizeof(uint16_t),
              "MessageType must stay 16-bit to match SHADOWSTRIKE_MESSAGE_HEADER::MessageType.");

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

// LENGTH UNITS ARE UNIFORM ACROSS THIS PROTOCOL: EVERY VARIABLE-LENGTH FIELD IS
// A BYTE COUNT. That is now true; it was not, and the disagreement was invisible
// from the field names. Recorded here because the shape of the defect matters
// more than the fix.
//
// THREE kernel builders fill this one layout, and they did not agree:
//
//   ScanBridge.c  SbBuildFileScanRequestEx  wrote Name.Length = BYTES.
//     Live on every IRP_MJ_CREATE via PreCreate.c. Correct.
//
//   CommPort.c  ShadowStrikeBuildFileScanRequest  wrote Name.Length /
//     sizeof(WCHAR) = CHARACTERS. Live on every rename and delete via
//     FilterRegistration.c's post-operation callback.
//
//   FilterRegistration.c  ShadowStrikeQueueRescan  wrote copyLen /
//     sizeof(WCHAR) = CHARACTERS. Live on IRP_MJ_CLEANUP for modified files.
//
// All three stamp FilterMessageType_ScanRequest and all three route to the
// primary scanner connection, so all three arrive at ONE reader:
// RealTimeProtection::OnKernelFileScan, which divides by sizeof(wchar_t) and
// therefore reads BYTES. The create path agreed with it; the rename, delete and
// rescan paths did not, and delivered a path the service truncated to HALF its
// length. That failure is silent - a halved path is not an error, it is a path
// that cannot be opened, and an unopenable path is an unexamined file.
//
// The earlier note here concluded this was latent because "each builder happens
// to be matched to its own reader". That was wrong, and it was wrong because it
// traced only the create path. The reader it credited to the character-count
// builders - FileSystemFilter::DecodeEvent - is field-proven never to run: its
// message-type enum numbers scan requests 1..4 while the kernel sends 6, and the
// 1.0.94 log contains exactly one line from it, "Unknown message type: 5".
//
// BYTES rather than characters, for four reasons, in order of weight:
//   1. Every sibling notification already uses bytes and says so -
//      ProcessNotifyRequest::imagePathLength, ImageLoadRequest::imagePathLength,
//      RegistryOpRequest::keyPathLength. Making file scan the exception is drift.
//   2. UNICODE_STRING::Length, which every builder already holds, is bytes.
//      Characters need a division per producer, and that division is exactly
//      where the three builders diverged.
//   3. A receiver must bound these against a delivered size expressed in bytes.
//      One unit means one comparison with nothing to round or overflow.
//   4. It corrects the two broken producers instead of changing the producer and
//      the reader that demonstrably work on the highest-volume path.
//
// Pinned by tests/kernel_contracts (every builder writes a byte count, no
// consumer multiplies one by sizeof(wchar_t)) and by the wire-format suite.

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
// MEASURED AND REMOVED. struct DriverStatisticsData described a layout the driver
// has never sent, exactly like the three notification structs above. Task 134
// deliberately left it in place because it had NOT been compared field by field,
// and removing an unmeasured declaration on the strength of its neighbours would
// have been guessing. It has now been compared.
//
//   It was 128 bytes: uptimeSeconds, filesScanned, filesBlocked,
//   filesQuarantined, processesScanned, processesBlocked, registryOpsScanned,
//   registryOpsBlocked, cacheHits, cacheMisses, messagesReceived, messagesSent,
//   timeoutsOccurred, errorsOccurred (14 x uint64) then currentPendingRequests,
//   peakPendingRequests, currentConnections, cacheEntries (4 x uint32).
//
//   The wire truth is SHADOWSTRIKE_DRIVER_STATUS (SharedDefs.h:301). It opens
//   with VersionMajor / VersionMinor / VersionBuild / Reserved1, then five
//   BOOLEAN feature flags and padding, and only then reaches TotalFilesScanned /
//   FilesBlocked / CacheHits / CacheMisses. After those it carries PendingRequests
//   / PeakPendingRequests / ConnectedClients as LONG, a compression block
//   (CompressedMessages, CompressionBytesSaved, CompressionAvgRatio,
//   CompressionErrors) and a message-queue block (MqTotalEnqueued, MqTotalDequeued,
//   MqTotalDropped, MqCurrentDepth, MqPeakDepth, MqFlowControlActive).
//
//   ELEVEN of the declared fields do not exist on the wire at all (uptimeSeconds,
//   filesQuarantined, processesScanned, processesBlocked, registryOpsScanned,
//   registryOpsBlocked, messagesReceived, messagesSent, timeoutsOccurred,
//   errorsOccurred, cacheEntries) and every wire field describing the driver's
//   configuration, compression transport and queue health is absent from it.
//   The seven that overlap semantically sit at different offsets, because the
//   16 bytes of version and flags that open the real struct have no counterpart
//   here, so nothing lines up.
//
// NO CAPABILITY IS LOST. It had zero consumers repo-wide, and being a wrong
// layout it could not have parsed a driver status message if one had been wired
// to it - it would have reported whatever the version fields and feature flags
// happened to look like as an uptime and a scan count. Driver statistics remain
// fully available: consume SHADOWSTRIKE_DRIVER_STATUS directly, the way
// IPCManager.hpp consumes FILE_SCAN_REQUEST and FILTER_MESSAGE_HEADER, and pin
// the size and key offsets against the kernel declaration as the two survivors
// in this header now are. Do not reintroduce a hand-written mirror.

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
// Callback Types - the DECODED-message vocabulary
//=============================================================================
//
// The six message callbacks below take the rich C++ representations declared
// above, i.e. what MessageDispatcher::ParseFileScanRequest /
// ParseProcessNotification / ParseRegistryNotification produce AFTER a kernel
// frame has been decoded and bounds-checked. That is what the Parsed prefix
// records.
//
// They are deliberately NOT interchangeable with IPCManager.hpp's
// FileScanCallback / ProcessNotifyCallback, which take the packed kernel structs
// (FILE_SCAN_REQUEST, ProcessNotifyRequest) and return the kernel verdict enum
// SHADOWSTRIKE_SCAN_VERDICT. Two vocabularies for two layers is correct; what was
// wrong was that both layers spelled two of them with the SAME NAMES in this one
// namespace, since IPCManager.hpp is also ShadowStrike::Communication.
//
// WHAT THE PREFIX REPLACED. The old arrangement guarded this block with
// "#ifndef SS_IPC_CALLBACK_TYPES_DEFINED" and failed in two ways, only one of
// which was ever written down:
//
//   1. Communication.hpp before IPCManager.hpp was a hard C2371. The guard
//      suppressed only THIS side, so whichever header came first won and the
//      other redeclared an alias with a different type. Include ORDER decided
//      whether a translation unit compiled at all, and three production sources
//      (RealTimeProtection.cpp, ProcessInjectionDetector.cpp,
//      AMSIIntegration.cpp) carried the working order by hand.
//   2. The guard suppressed ALL SEVEN aliases whenever IPCManager.hpp won,
//      including the five that collided with nothing. A translation unit that
//      included IPCManager.hpp first could not name FileNotifyCallback or
//      ConnectionStateCallback at all, and the diagnostic it produced was an
//      undeclared identifier - naming neither the guard nor the real conflict.
//
// MEASURED before renaming: these two headers declare 23 and 28 type names and
// the intersection was exactly those two aliases. So the rename REMOVES the
// conflict rather than relocating it, which is what makes deleting the guard
// correct instead of merely inverting it. A contract test recomputes that
// intersection and fails if it is ever non-empty again - that catches a future
// collision on ANY name, which a naming prefix by itself cannot.
//
// ConnectionStateCallback keeps its name on purpose: it reports transport
// lifecycle rather than a decoded message, and it has no counterpart in
// IPCManager.hpp to collide with. It has no consumer anywhere in the tree today;
// that is stated rather than silently removed, because it is the only written
// form of the connection-state contract.
using ParsedFileScanCallback = std::function<ScanVerdictReply(const FileScanRequest&)>;
using ParsedProcessNotifyCallback = std::function<ScanVerdictReply(const ProcessNotification&)>;
using ParsedRegistryNotifyCallback = std::function<ScanVerdictReply(const RegistryNotification&)>;
using ParsedFileNotifyCallback = std::function<void(const FileScanRequest&)>;
using ParsedProcessEventCallback = std::function<void(const ProcessNotification&)>;
using ParsedRegistryEventCallback = std::function<void(const RegistryNotification&)>;
using ConnectionStateCallback = std::function<void(ConnectionState, const std::string&)>;

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
