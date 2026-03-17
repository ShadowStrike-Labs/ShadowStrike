// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
#pragma once

#include "SharedDefs.h"
#include "MessageTypes.h"
#include "VerdictTypes.h"

// Magic value: "SSFS" (ShadowStrike Filter Service)
#define SHADOWSTRIKE_MESSAGE_MAGIC 0x53534653
#define SHADOWSTRIKE_PROTOCOL_VERSION 2

//
// Message flags (SHADOWSTRIKE_MESSAGE_HEADER.Flags)
//
#define SHADOWSTRIKE_MSG_FLAG_COMPRESSED        0x00000001  // Payload compressed (original size in Reserved)
#define SHADOWSTRIKE_MSG_FLAG_HMAC              0x00000002  // HMAC-SHA256 appended after data (32 bytes)
#define SHADOWSTRIKE_MSG_FLAG_PRIORITY_HIGH     0x00000004  // High-priority delivery
#define SHADOWSTRIKE_MSG_FLAG_NO_ACK            0x00000008  // Fire-and-forget, no acknowledgment needed

// Ensure structure packing is consistent
#pragma pack(push, 1)

//
// Common Message Header
//
typedef struct _SHADOWSTRIKE_MESSAGE_HEADER {
    UINT32 Magic;           // SHADOWSTRIKE_MESSAGE_MAGIC
    UINT16 Version;         // SHADOWSTRIKE_PROTOCOL_VERSION
    UINT16 MessageType;     // SHADOWSTRIKE_MESSAGE_TYPE
    UINT64 MessageId;       // Correlation ID
    UINT32 TotalSize;       // Size of Header + Data
    UINT32 DataSize;        // Size of Data only
    UINT64 Timestamp;       // Kernel timestamp
    UINT32 Flags;           // Message flags
    UINT32 Reserved;        // Padding/Reserved
} SHADOWSTRIKE_MESSAGE_HEADER, *PSHADOWSTRIKE_MESSAGE_HEADER;

//
// Backward compatibility aliases for code that references FILTER_MESSAGE_HEADER.
// In kernel mode, WDK defines its own FILTER_MESSAGE_HEADER (fltUserStructures.h)
// with a completely different layout, so we must NOT redefine it there.
// Instead, redirect all our references to SHADOWSTRIKE_MESSAGE_HEADER.
//
#ifdef __FLT_USER_STRUCTURES_H__
// Kernel mode: WDK owns FILTER_MESSAGE_HEADER. Our code must use SHADOWSTRIKE_MESSAGE_HEADER.
// MessageHandler code uses SS_MESSAGE_HEADER as the portable alias.
#define SS_MESSAGE_HEADER   SHADOWSTRIKE_MESSAGE_HEADER
#define PSS_MESSAGE_HEADER  PSHADOWSTRIKE_MESSAGE_HEADER
#else
// User mode: no WDK conflict, provide direct aliases.
typedef SHADOWSTRIKE_MESSAGE_HEADER  FILTER_MESSAGE_HEADER;
typedef PSHADOWSTRIKE_MESSAGE_HEADER PFILTER_MESSAGE_HEADER;
#define SS_MESSAGE_HEADER   SHADOWSTRIKE_MESSAGE_HEADER
#define PSS_MESSAGE_HEADER  PSHADOWSTRIKE_MESSAGE_HEADER
#endif

//
// 1. File Scan Request (FilterMessageType_ScanRequest)
//
typedef struct _FILE_SCAN_REQUEST {
    UINT64 MessageId;
    UINT8  AccessType;      // Read, Write, Execute...
    UINT8  Disposition;
    UINT8  Priority;
    UINT8  RequiresReply;
    UINT32 ProcessId;
    UINT32 ThreadId;
    UINT32 ParentProcessId;
    UINT32 SessionId;
    UINT64 FileSize;
    UINT32 FileAttributes;
    UINT32 DesiredAccess;
    UINT32 ShareAccess;
    UINT32 CreateOptions;
    UINT32 VolumeSerial;
    UINT64 FileId;
    UINT8  IsDirectory;
    UINT8  IsNetworkFile;
    UINT8  IsRemovableMedia;
    UINT8  HasADS;
    UINT16 PathLength;
    UINT16 ProcessNameLength;
    // Followed by:
    // WCHAR FilePath[PathLength]
    // WCHAR ProcessName[ProcessNameLength]
} FILE_SCAN_REQUEST, *PFILE_SCAN_REQUEST;

//
// 2. Scan Verdict Reply (FilterMessageType_ScanVerdict)
//
typedef struct _SHADOWSTRIKE_SCAN_VERDICT_REPLY {
    UINT64 MessageId;
    UINT8  Verdict;         // SHADOWSTRIKE_SCAN_VERDICT
    UINT32 ResultCode;
    UINT8  ThreatDetected;
    UINT8  ThreatScore;
    UINT8  CacheResult;
    UINT32 CacheTTL;
    UINT32 Reserved;
    UINT16 ThreatNameLength;
    // Followed by:
    // WCHAR ThreatName[ThreatNameLength]
} SHADOWSTRIKE_SCAN_VERDICT_REPLY, *PSHADOWSTRIKE_SCAN_VERDICT_REPLY;

//
// 3. Process Notification (FilterMessageType_ProcessNotify)
//
typedef struct _SHADOWSTRIKE_PROCESS_NOTIFICATION {
    SS_MESSAGE_HEADER Header; // Header included for convenience in some contexts, or payload starts here?
                                  // Standard convention: Payload struct follows header.
                                  // BUT ScanBridge.c casts Header+1 to specific type.
                                  // So this struct should contain ONLY payload.

    UINT32 ProcessId;
    UINT32 ParentProcessId;
    UINT32 CreatingProcessId; // For explicit creator tracking
    UINT32 CreatingThreadId;
    BOOLEAN Create;
    UINT16 ImagePathLength;
    UINT16 CommandLineLength;
    // Followed by:
    // WCHAR ImagePath[ImagePathLength]
    // WCHAR CommandLine[CommandLineLength]
} SHADOWSTRIKE_PROCESS_NOTIFICATION, *PSHADOWSTRIKE_PROCESS_NOTIFICATION;

//
// 4. Thread Notification (FilterMessageType_ThreadNotify)
//
typedef struct _SHADOWSTRIKE_THREAD_NOTIFICATION {
    UINT32 ProcessId;        // Target Process
    UINT32 ThreadId;         // New Thread
    UINT32 CreatorProcessId; // Source Process (Current)
    UINT32 CreatorThreadId;  // Source Thread (Current)
    BOOLEAN IsRemote;        // TRUE if Creator != Target
    // Additional Context could go here
} SHADOWSTRIKE_THREAD_NOTIFICATION, *PSHADOWSTRIKE_THREAD_NOTIFICATION;

//
// 5. Image Load Notification (FilterMessageType_ImageLoad)
//
typedef struct _SHADOWSTRIKE_IMAGE_NOTIFICATION {
    UINT32 ProcessId;
    UINT64 ImageBase;
    UINT64 ImageSize;
    UINT8  SignatureLevel;
    UINT8  SignatureType;
    BOOLEAN IsSystemImage;
    UINT16 ImageNameLength;
    // Followed by:
    // WCHAR ImageName[ImageNameLength]
} SHADOWSTRIKE_IMAGE_NOTIFICATION, *PSHADOWSTRIKE_IMAGE_NOTIFICATION;

//
// 6. Registry Notification (FilterMessageType_RegistryNotify)
//
typedef struct _SHADOWSTRIKE_REGISTRY_NOTIFICATION {
    UINT32 ProcessId;
    UINT32 ThreadId;
    UINT8  Operation; // Create, Set, Delete
    UINT16 KeyPathLength;
    UINT16 ValueNameLength;
    UINT32 DataSize;
    UINT32 DataType;
    // Followed by:
    // WCHAR KeyPath[KeyPathLength]
    // WCHAR ValueName[ValueNameLength]
    // BYTE Data[DataSize]
} SHADOWSTRIKE_REGISTRY_NOTIFICATION, *PSHADOWSTRIKE_REGISTRY_NOTIFICATION;

//
// 7. Handle Alert Notification (FilterMessageType_HandleAlert)
//
typedef struct _SHADOWSTRIKE_HANDLE_ALERT_NOTIFICATION {
    UINT32 SourceProcessId;
    UINT32 TargetProcessId;
    UINT32 RequestedAccess;
    UINT32 GrantedAccess;
    UINT32 SuspicionScore;
    UINT32 SuspiciousFlags;
    UINT32 TargetCategory;
    UINT32 OperationType;
    UINT32 Verdict;
} SHADOWSTRIKE_HANDLE_ALERT_NOTIFICATION, *PSHADOWSTRIKE_HANDLE_ALERT_NOTIFICATION;

// ============================================================================
// DATA PUSH PAYLOAD STRUCTURES (User-Mode â†’ Kernel)
// ============================================================================
//
// These structures define the wire format for data push messages from the
// user-mode agent to the kernel driver. Each message carries a batch header
// followed by one or more entries. The kernel-side handlers convert these
// wire-format entries to the internal module API structures.
//

//
// Push operation flags (used in BatchHeader.Flags)
//
#define SHADOWSTRIKE_PUSH_FLAG_NONE       0x00000000
#define SHADOWSTRIKE_PUSH_FLAG_REPLACE    0x00000001  // Clear existing + add
#define SHADOWSTRIKE_PUSH_FLAG_APPEND     0x00000002  // Append to existing
#define SHADOWSTRIKE_PUSH_FLAG_REMOVE     0x00000004  // Remove specified entries
#define SHADOWSTRIKE_PUSH_FLAG_CLEAR      0x00000008  // Clear all entries

//
// Max entries per batch (prevent excessive kernel time in single call)
//
#define SHADOWSTRIKE_PUSH_MAX_BATCH_ENTRIES  4096

//
// 8. Push Reply (returned by all data push handlers)
//
typedef struct _SHADOWSTRIKE_PUSH_REPLY {
    UINT64 MessageId;
    UINT32 Status;          // NTSTATUS
    UINT32 EntriesAccepted;
    UINT32 EntriesRejected;
    UINT32 Reserved;
} SHADOWSTRIKE_PUSH_REPLY, *PSHADOWSTRIKE_PUSH_REPLY;

//
// 9. Batch Header (prefix for all batched push messages)
//
typedef struct _SHADOWSTRIKE_PUSH_BATCH_HEADER {
    UINT32 EntryCount;      // Number of entries in this batch
    UINT32 EntrySize;       // Size of each fixed-size entry (0 if variable)
    UINT32 TotalDataSize;   // Total bytes of entry data following this header
    UINT32 Flags;           // SHADOWSTRIKE_PUSH_FLAG_*
} SHADOWSTRIKE_PUSH_BATCH_HEADER, *PSHADOWSTRIKE_PUSH_BATCH_HEADER;

//
// 10. Hash Database Push Entry (FilterMessageType_PushHashDatabase)
//
// Wire format for pushing file hashes (good/bad) from user-mode stores.
// Handler converts to IOM_IOC_INPUT and calls IomLoadIOC().
//
typedef struct _SHADOWSTRIKE_PUSH_HASH_ENTRY {
    UINT8  HashType;        // 0=MD5(16 bytes), 1=SHA1(20 bytes), 2=SHA256(32 bytes)
    UINT8  Verdict;         // 0=Unknown, 1=Clean, 2=Malicious, 3=Suspicious
    UINT8  Severity;        // IOM_SEVERITY value
    UINT8  Reserved;
    UINT32 Score;           // Threat score 0-100
    UCHAR  Hash[32];       // Hash bytes (left-padded for shorter hashes)
    CHAR   ThreatName[64]; // Null-terminated threat name
    LARGE_INTEGER Expiry;   // Expiration time (0 = no expiry)
} SHADOWSTRIKE_PUSH_HASH_ENTRY, *PSHADOWSTRIKE_PUSH_HASH_ENTRY;

//
// 11. Pattern Database Push Entry (FilterMessageType_PushPatternDatabase)
//
// Same wire format as hash entry â€” patterns are loaded via IOCMatcher
// with IOM_IOC_TYPE set to pattern type.
//
typedef SHADOWSTRIKE_PUSH_HASH_ENTRY   SHADOWSTRIKE_PUSH_PATTERN_ENTRY;
typedef PSHADOWSTRIKE_PUSH_HASH_ENTRY  PSHADOWSTRIKE_PUSH_PATTERN_ENTRY;

//
// 12. Signature Database Push Entry (FilterMessageType_PushSignatureDatabase)
//
// Same wire format â€” signatures routed via IOCMatcher.
//
typedef SHADOWSTRIKE_PUSH_HASH_ENTRY   SHADOWSTRIKE_PUSH_SIGNATURE_ENTRY;
typedef PSHADOWSTRIKE_PUSH_HASH_ENTRY  PSHADOWSTRIKE_PUSH_SIGNATURE_ENTRY;

//
// 13. IoC Feed Push Entry (FilterMessageType_PushIoCFeed)
//
// Variable-length entry for IoC indicators (hashes, IPs, domains, URLs).
// Handler converts to IOM_IOC_INPUT and calls IomLoadIOC().
//
typedef struct _SHADOWSTRIKE_PUSH_IOC_ENTRY {
    UINT8  Type;            // IOM_IOC_TYPE value
    UINT8  Severity;        // IOM_SEVERITY value
    UINT8  MatchMode;       // IOM_MATCH_MODE value
    UINT8  CaseSensitive;   // Boolean
    UINT16 ValueLength;     // Byte length of Value string (excluding null)
    UINT16 Reserved;
    CHAR   ThreatName[64];  // Null-terminated
    CHAR   Source[64];       // Null-terminated source attribution
    LARGE_INTEGER Expiry;
    // Followed by:
    // CHAR Value[ValueLength]  (the IoC value, null-terminated by handler)
} SHADOWSTRIKE_PUSH_IOC_ENTRY, *PSHADOWSTRIKE_PUSH_IOC_ENTRY;

//
// 14. Network IoC Push Entry (FilterMessageType_PushNetworkIoC)
//
// For C2 IPs, malicious domains, JA3 hashes, bad URLs.
// Handler routes to C2Detection, DnsMonitor, NetworkReputation, SSLInspection.
//
typedef struct _SHADOWSTRIKE_PUSH_NETWORK_IOC_ENTRY {
    UINT8  Type;            // 0=IPv4, 1=IPv6, 2=Domain, 3=JA3, 4=URL
    UINT8  Reputation;      // NR_REPUTATION value
    UINT16 Categories;      // NR_CATEGORY bitmask
    UINT32 Score;           // Reputation score 0-100
    CHAR   ThreatName[64];  // Null-terminated malware family / threat name
    CHAR   MalwareFamily[64]; // For C2/JA3 attribution
    union {
        UINT32 IPv4;        // Network byte order
        UCHAR  IPv6[16];    // IPv6 address bytes
        CHAR   Domain[256]; // Null-terminated domain name
        UCHAR  JA3Hash[16]; // MD5 hash of JA3 fingerprint
        CHAR   URL[512];    // Null-terminated URL
    } Value;
    LARGE_INTEGER Expiry;
} SHADOWSTRIKE_PUSH_NETWORK_IOC_ENTRY, *PSHADOWSTRIKE_PUSH_NETWORK_IOC_ENTRY;

//
// Network IoC type constants
//
#define SHADOWSTRIKE_NET_IOC_IPV4    0
#define SHADOWSTRIKE_NET_IOC_IPV6    1
#define SHADOWSTRIKE_NET_IOC_DOMAIN  2
#define SHADOWSTRIKE_NET_IOC_JA3     3
#define SHADOWSTRIKE_NET_IOC_URL     4

//
// 15. Behavioral Rule Push Entry (FilterMessageType_UpdateBehavioralRules)
//
// Variable-length entry. Handler converts to RE_RULE and calls
// ReLoadRule() / ReRemoveRule() / ReEnableRule().
//
#define SHADOWSTRIKE_RULE_OP_ADD      0
#define SHADOWSTRIKE_RULE_OP_REMOVE   1
#define SHADOWSTRIKE_RULE_OP_ENABLE   2
#define SHADOWSTRIKE_RULE_OP_DISABLE  3

typedef struct _SHADOWSTRIKE_PUSH_BEHAVIORAL_RULE {
    UINT8  Operation;       // SHADOWSTRIKE_RULE_OP_*
    UINT8  StopProcessing;  // Boolean
    UINT16 Reserved;
    UINT32 Priority;
    CHAR   RuleId[32];      // Null-terminated rule identifier
    CHAR   RuleName[64];    // Null-terminated (for Add only)
    CHAR   Description[256];// Null-terminated (for Add only)
    UINT32 ConditionCount;  // Number of RE_CONDITION structs following (for Add)
    UINT32 ActionCount;     // Number of RE_ACTION structs following (for Add)
    // Followed by (for Operation == Add only):
    // RE_CONDITION Conditions[ConditionCount]
    // RE_ACTION Actions[ActionCount]
} SHADOWSTRIKE_PUSH_BEHAVIORAL_RULE, *PSHADOWSTRIKE_PUSH_BEHAVIORAL_RULE;

//
// 16. Whitelist Push Entry (FilterMessageType_PushWhitelist)
//
// Routes to ExclusionManager with system-level exclusion flags.
//
#define SHADOWSTRIKE_WL_TYPE_HASH         0
#define SHADOWSTRIKE_WL_TYPE_PATH         1
#define SHADOWSTRIKE_WL_TYPE_PROCESS      2
#define SHADOWSTRIKE_WL_TYPE_CERTIFICATE  3

typedef struct _SHADOWSTRIKE_PUSH_WHITELIST_ENTRY {
    UINT8  EntryType;       // SHADOWSTRIKE_WL_TYPE_*
    UINT8  HashType;        // 0=MD5, 1=SHA1, 2=SHA256 (for EntryType==Hash)
    UINT8  Flags;           // SHADOWSTRIKE_EXCLUSION_FLAGS
    UINT8  Reserved;
    UCHAR  Hash[32];       // For hash-based entries (zero-filled otherwise)
    UINT16 ValueLength;     // WCHAR count for path/name entries
    UINT16 Reserved2;
    // Followed by:
    // WCHAR Value[ValueLength]  (for path or process name entries)
} SHADOWSTRIKE_PUSH_WHITELIST_ENTRY, *PSHADOWSTRIKE_PUSH_WHITELIST_ENTRY;

//
// 17. Exclusion Update Entry (FilterMessageType_ExclusionUpdate)
//
// Add/remove/clear exclusions. Routes to ExclusionManager APIs.
//
#define SHADOWSTRIKE_EXCL_OP_ADD     0
#define SHADOWSTRIKE_EXCL_OP_REMOVE  1
#define SHADOWSTRIKE_EXCL_OP_CLEAR   2

typedef struct _SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY {
    UINT8  ExclusionType;   // SHADOWSTRIKE_EXCLUSION_TYPE (Path/Extension/Process/PID)
    UINT8  Operation;       // SHADOWSTRIKE_EXCL_OP_*
    UINT8  Flags;           // SHADOWSTRIKE_EXCLUSION_FLAGS
    UINT8  Reserved;
    UINT32 TTLSeconds;      // 0 = permanent (for Add only)
    UINT16 ValueLength;     // WCHAR count
    UINT16 Reserved2;
    // Followed by:
    // WCHAR Value[ValueLength]  (path, extension, process name)
    // For PID exclusions: HANDLE ProcessId stored as UINT64 in first 8 bytes of Value
} SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY, *PSHADOWSTRIKE_PUSH_EXCLUSION_ENTRY;

#pragma pack(pop)
