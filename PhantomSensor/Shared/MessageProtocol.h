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
#define SHADOWSTRIKE_MSG_FLAG_ENCRYPTED         0x00000010  // Payload encrypted with per-session AES-256-GCM key

//
// Flags that TRANSFORM the payload bytes, as opposed to merely describing how
// the frame should be delivered.
//
// The distinction is load-bearing, which is why it is stated here in the one
// header both the driver and the service include rather than being re-derived
// on each side. PRIORITY_HIGH and NO_ACK are delivery hints: a receiver that
// ignores them still parses the payload correctly. COMPRESSED and ENCRYPTED
// change the bytes, so a receiver that ignores either one parses transformed
// data as though it were a structure - which yields plausible-looking garbage,
// not an error.
//
// THE CONTRACT: a receiver MUST reverse every transform named here, or REFUSE
// the frame. It must never pass a frame upward with one of these bits still
// set, and it must never ignore a bit it does not recognise.
//
// This exists because that rule was broken. The driver compressed notification
// payloads whenever compression saved at least 10% and set COMPRESSED, and no
// user-mode reader ever tested for that bit or decompressed anything - measured
// as zero references to this flag anywhere in the service. The frame decrypted
// cleanly, the flag was left set, and the consumer read compressed bytes as a
// struct. Nothing failed; the values were simply wrong, which is the worst
// available outcome on a detection path.
//
// Adding a new transform flag therefore also means adding it here, so every
// receiver that has not implemented it fails closed instead of silently
// misreading the payload.
//
#define SHADOWSTRIKE_MSG_FLAG_PAYLOAD_TRANSFORMS \
    (SHADOWSTRIKE_MSG_FLAG_COMPRESSED | SHADOWSTRIKE_MSG_FLAG_ENCRYPTED)

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
// Portable alias used by driver-side code that predates this header's naming.
// Defined unconditionally: it is the same type on both sides of the boundary.
//
#define SS_MESSAGE_HEADER   SHADOWSTRIKE_MESSAGE_HEADER
#define PSS_MESSAGE_HEADER  PSHADOWSTRIKE_MESSAGE_HEADER

//
// THIS HEADER DELIBERATELY DOES NOT DEFINE FILTER_MESSAGE_HEADER.
//
// It used to. In user mode - selected by `#ifndef __FLT_USER_STRUCTURES_H__` -
// it did:
//
//     typedef SHADOWSTRIKE_MESSAGE_HEADER  FILTER_MESSAGE_HEADER;
//
// which made the name of a 16-byte OPERATING SYSTEM structure resolve to a
// 40-byte structure of ours, on the same received buffer, decided purely by
// whether the translation unit had reached <fltUser.h> first.
//
// FILTER_MESSAGE_HEADER belongs to the filter manager. It is the transport
// prefix fltmgr itself writes ahead of our payload, in cleartext, and every
// consumer in this product uses the name to mean exactly that - all of them
// compute the payload offset as `buffer + sizeof(FILTER_MESSAGE_HEADER)`. The
// alias was therefore not merely risky, it was wrong for every real caller: a
// translation unit that resolved it to our 40-byte header located the payload
// 24 bytes past where the kernel put it, and then read whatever was there as a
// structure. That is a silent wrong answer, not an error.
//
// Nothing detected it, and it could not have. `sizeof` compiles either way, the
// only pre-existing compile-time check on this type was
// `C_ASSERT(sizeof(SS_MESSAGE_HEADER) <= 64)` (MessageHandler.h) - which 16 and
// 40 both satisfy - and the protection relied on each consumer remembering to
// include <fltUser.h>, or force-defining __FLT_USER_STRUCTURES_H__, which is a
// RESERVED WDK-INTERNAL GUARD NAME. Two of the four filter-port consumers had
// that include and a comment explaining it; two did not.
//
// So the name is not defined here at all. A user-mode translation unit that
// needs the transport prefix must obtain it from the OS, which is guaranteed by
// including Communication/FilterPortGate.hpp - the one header every filter-port
// consumer already includes, and where the OS structure's size is asserted. A
// translation unit that forgets now fails to COMPILE rather than silently
// reading the wrong offset.
//
// Do not reintroduce an alias for an OS type under any condition.
//

//
// ============================================================================
// WIRE FORMAT CONTRACT - ASSERTED, NOT DOCUMENTED
// ============================================================================
//
// Both the driver and the service include this header, so this is the one place
// the on-wire layout can be pinned once for both sides. Every field offset is
// asserted, not just the total size: a struct can keep its size while two
// fields swap, and that reads back as plausible values rather than as an error.
//
// If one of these fails, do not adjust the number - find the edit that moved the
// field, because the other side of the boundary has not moved with it.
//
C_ASSERT(sizeof(SHADOWSTRIKE_MESSAGE_HEADER) == 40);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_MESSAGE_HEADER, Magic)       ==  0);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_MESSAGE_HEADER, Version)     ==  4);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_MESSAGE_HEADER, MessageType) ==  6);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_MESSAGE_HEADER, MessageId)   ==  8);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_MESSAGE_HEADER, TotalSize)   == 16);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_MESSAGE_HEADER, DataSize)    == 20);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_MESSAGE_HEADER, Timestamp)   == 24);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_MESSAGE_HEADER, Flags)       == 32);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_MESSAGE_HEADER, Reserved)    == 36);

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
// 1b. File Operation Event (FilterMessageType_FileOperationEvent)
//
// Emitted by the PreSetInformation callback when a rename or delete has been
// evaluated - including operations the driver BLOCKED, which by definition never
// reach a post-operation callback and so cannot be reported by any other path.
//
// THIS STRUCTURE EXISTS BECAUSE ITS ABSENCE CAUSED A SILENT WIRE DEFECT.
// The callback used to allocate a private struct declared inside PreSetInfo.c
// and hand it to the send API *with no SHADOWSTRIKE_MESSAGE_HEADER in front of
// it*. The service therefore read the payload's first field where the frame's
// Magic belongs. That field was a kernel HANDLE ProcessId, so the reported magic
// was the low half of a process id - and because the operation being reported
// was performed by the scanner itself, it was OUR OWN process id. Field logs
// show exactly that: "[IPCManager] Invalid message magic: 0x00002CA4", where
// 0x2CA4 is 11428, the only pid in the run.
//
// It was worse than a rejected frame. Read at the header's offsets, the payload
// also supplied the Flags field from its FileNameBytes member, so whether the
// receiver took the encrypted path, the HMAC path, or refused on magic depended
// on THE BYTE LENGTH OF THE FILE NAME - which is why the failures arrived in
// groups of three (one per rename/delete on a decoy file) with the mode constant
// within a group and varying between files.
//
// Two properties are therefore deliberate here:
//   - It lives in the header BOTH SIDES include, so the payload cannot be a type
//     only one side can name.
//   - Every field is fixed-width. The original used HANDLE (8 bytes, and a
//     kernel type) and FILE_INFORMATION_CLASS (an enum, whose width is the
//     compiler's choice) in a structure that crosses a process boundary.
//
typedef struct _SHADOWSTRIKE_FILE_OPERATION_EVENT {
    UINT32 ProcessId;          // Process that issued the operation
    UINT32 InfoClass;          // FILE_INFORMATION_CLASS value, as a number
    UINT32 BlockReason;        // Driver's reason code; 0 when not blocked
    UINT32 SuspicionScore;     // Driver's score for the operation
    UINT8  WasBlocked;         // Non-zero if the operation was refused
    UINT8  Reserved0[3];       // Explicit padding - never implicit on the wire
    INT64  Timestamp;          // KeQuerySystemTime value
    UINT16 FileNameBytes;      // Length of FileName in BYTES, not characters
    // Followed by:
    // WCHAR FileName[FileNameBytes / sizeof(WCHAR)]  (NUL-terminated)
} SHADOWSTRIKE_FILE_OPERATION_EVENT, *PSHADOWSTRIKE_FILE_OPERATION_EVENT;

//
// Pinned for the same reason as the frame header: this crosses the boundary, and
// a field that moves on one side only reads back as a plausible value rather
// than as an error.
//
C_ASSERT(sizeof(SHADOWSTRIKE_FILE_OPERATION_EVENT) == 30);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_FILE_OPERATION_EVENT, ProcessId)      ==  0);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_FILE_OPERATION_EVENT, InfoClass)      ==  4);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_FILE_OPERATION_EVENT, BlockReason)    ==  8);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_FILE_OPERATION_EVENT, SuspicionScore) == 12);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_FILE_OPERATION_EVENT, WasBlocked)     == 16);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_FILE_OPERATION_EVENT, Timestamp)      == 20);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_FILE_OPERATION_EVENT, FileNameBytes)  == 28);

//
// 1b. Behavioural Alert (FilterMessageType_BehavioralAlert)
//
// THE FIRST TWO FIELDS ARE NOT FREE CHOICES. BehaviorBlocker::
// OnKernelBehavioralAlert already reads a UINT32 process id at offset 0 and a
// UINT32 parent process id at offset 4, and refuses any payload shorter than
// those eight bytes. That consumer predates this structure; it has simply never
// been reached, because the only producer of this message type in the driver sent
// a bare SHADOWSTRIKE_MESSAGE_HEADER with DataSize == 0 and the consumer is gated
// behind `if (data && size > 0)`. So the wire contract already existed and was
// unsatisfiable. Do not reorder these two fields.
//
// Every field is fixed-width. The kernel source of this event is EC_EVENT_RECORD,
// whose Priority and Source members are C enumerations - their width is at the
// compiler's discretion, so they are narrowed to UINT8 here on purpose rather
// than being placed on the wire as enums. This is the same defect class as the
// HANDLE and FILE_INFORMATION_CLASS members that used to sit on the file
// operation payload above.
//
// ParentProcessId == 0 means NOT RESOLVED, not "parent is process 0". The ETW
// record carries no parent, and resolving one per event would mean a
// PASSIVE_LEVEL process lookup on a path the driver's own comments describe as
// running at thousands of events per second - the class of per-event cost that
// produced the multi-minute stalls this product has already had to remove. The
// consumer uses parentPid for reporting only (BehaviorBlocker.cpp:795 assigns it
// and :377 serialises it); no blocking decision reads it, so an unresolved value
// costs a field in a report and nothing else.
//
typedef struct _SHADOWSTRIKE_BEHAVIORAL_ALERT {
    UINT32 ProcessId;         // Originating process. Consumer reads this at 0.
    UINT32 ParentProcessId;   // 0 == not resolved in kernel. Consumer reads at 4.
    UINT32 ThreadId;          // Originating thread
    UINT32 SequenceNumber;    // Monotonic per-record sequence from the consumer
    INT64  Timestamp;         // KeQuerySystemTime, 100ns units
    UINT64 Keywords;          // ETW provider keywords
    UINT64 CorrelationId;     // Attack-chain correlation, 0 if uncorrelated
    UINT16 EventId;           // ETW event id within the provider
    UINT16 Task;              // ETW task
    UINT8  Level;             // ETW level
    UINT8  Opcode;            // ETW opcode
    UINT8  Priority;          // EC_EVENT_PRIORITY, narrowed
    UINT8  Source;            // EC_EVENT_SOURCE, narrowed
    UINT32 UserDataBytes;     // Provider payload the kernel saw; NOT carried here
    UINT32 Reserved0;         // Must be zero
} SHADOWSTRIKE_BEHAVIORAL_ALERT, *PSHADOWSTRIKE_BEHAVIORAL_ALERT;

C_ASSERT(sizeof(SHADOWSTRIKE_BEHAVIORAL_ALERT) == 56);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, ProcessId)       ==  0);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, ParentProcessId) ==  4);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, ThreadId)        ==  8);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, SequenceNumber)  == 12);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, Timestamp)       == 16);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, Keywords)        == 24);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, CorrelationId)   == 32);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, EventId)         == 40);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, Task)            == 42);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, Level)           == 44);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, Opcode)          == 45);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, Priority)        == 46);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, Source)          == 47);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, UserDataBytes)   == 48);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_BEHAVIORAL_ALERT, Reserved0)       == 52);

//
// The consumer's minimum is eight bytes - one process id and one parent process
// id. Asserting that here means a future edit cannot shrink this payload below
// what BehaviorBlocker requires without failing the build, instead of producing a
// payload the consumer logs as "too small" and then answers Allow to.
//
C_ASSERT(sizeof(SHADOWSTRIKE_BEHAVIORAL_ALERT) >= (2 * sizeof(UINT32)));

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
// FIELD OFFSETS PINNED, BECAUSE THE VERDICT BYTE IS LOAD-BEARING FOR A BLOCKING
// FILE CREATE. PreCreate reads Verdict to decide STATUS_ACCESS_DENIED and
// Verdict_Malicious is the only value that denies. Verdict sits at offset 8 -
// the SAME offset it occupies in SHADOWSTRIKE_PROCESS_VERDICT_REPLY - so replying
// with the wrong one of the two reply structs yields a correct-looking verdict
// byte and a reply Filter Manager rejects only for its length. Pinning the layout
// means a future field insertion fails the build instead of silently shifting the
// verdict under its reader.
//
C_ASSERT(sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY) == 26);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_SCAN_VERDICT_REPLY, MessageId)        ==  0);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_SCAN_VERDICT_REPLY, Verdict)          ==  8);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_SCAN_VERDICT_REPLY, ResultCode)       ==  9);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_SCAN_VERDICT_REPLY, ThreatDetected)   == 13);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_SCAN_VERDICT_REPLY, ThreatScore)      == 14);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_SCAN_VERDICT_REPLY, CacheResult)      == 15);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_SCAN_VERDICT_REPLY, CacheTTL)         == 16);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_SCAN_VERDICT_REPLY, Reserved)         == 20);
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_SCAN_VERDICT_REPLY, ThreatNameLength) == 24);

//
// ==========================================================================
// A VERDICT STRUCT HAS TWO CARRIERS AND ONLY ONE OF THEM IS VARIABLE-LENGTH
// ==========================================================================
//
// CARRIER 1 - THE FILTER MANAGER REPLY. The driver calls FltSendMessage supplying
// a reply buffer; user mode answers with FilterReplyMessage. Every reply buffer in
// this driver is a stack object sized EXACTLY sizeof(struct):
//     PreCreate.c:705       ULONG  ReplySize = sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY)
//     ScanBridge.c:1159     replySize = sizeof(reply)          // same struct
//     ProcessNotify.c:3687  SIZE_T ReplySize = sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY)
// Two consequences follow, and both are contracts rather than accidents:
//   (a) the ThreatName declared above CANNOT be delivered on this carrier, and a
//       reply longer than the struct is refused by Filter Manager - after which
//       the kernel waits out its whole budget and fails open, leaving a single
//       Debug line as the only evidence that a verdict was computed and lost;
//   (b) this carrier is NOT DECRYPTED. The sole EncDecrypt in CommPort.c (:2947)
//       is on the user->kernel MESSAGE path; nothing on the reply path examines an
//       ENC_HEADER. Ciphertext arriving here is parsed as the struct itself, which
//       would read Verdict out of an ENC_HEADER byte.
//
// CARRIER 2 - AN ORDINARY MESSAGE. FilterMessageType_ScanVerdict sent as a normal
// message reaches MhpHandleScanVerdict (MessageHandler.c:2234), which accepts
// PayloadSize >= sizeof(struct) and forwards the FULL PayloadSize to
// MqCompleteMessage. That path IS decrypted and DOES carry ThreatName.
//
// The bound below governs CARRIER 1 ONLY. Carrier 2 keeps its variable-length
// capability untouched - a threat name is still deliverable there, and that is
// where a caller wanting one must send it.
//
#define SHADOWSTRIKE_MAX_KERNEL_REPLY_SIZE                                     \
    (sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY) >                                 \
     sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY)                                \
        ? sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY)                              \
        : sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY))

C_ASSERT(sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY)    <= SHADOWSTRIKE_MAX_KERNEL_REPLY_SIZE);
C_ASSERT(sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY) <= SHADOWSTRIKE_MAX_KERNEL_REPLY_SIZE);

//
// The literal is deliberate and is a REVIEW PROMPT, not a duplicate of the
// expression above. The driver's three reply buffers are sized from the structs so
// they grow automatically; the user-mode sender's refusal threshold and the tests
// that pin it do not. Failing here is how a struct change is made to visit both
// sides of the carrier instead of one.
//
C_ASSERT(SHADOWSTRIKE_MAX_KERNEL_REPLY_SIZE == 26);

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

//
// 18. Process Verdict Reply (FilterMessageType_ProcessNotify with RequireReply)
//
// Defined in SharedDefs.h. Keep a single canonical declaration to prevent
// kernel/user header skew and ODR-style type collisions during shared builds.

//
// 19. Key Exchange Message (FilterMessageType_KeyExchange)
//
// Sent by the kernel driver to user-mode immediately after successful client
// verification (ShadowStrikeVerifyClient) during ShadowStrikeConnectNotify.
//
// The session key is wrapped (encrypted) using a Key-Wrapping-Key (KWK) derived
// via HKDF(client_image_hash, Salt, "ShadowStrike-KEX-v1"). The user-mode
// process derives the same KWK from its own executable hash to unwrap.
//
// All subsequent messages on this connection use the unwrapped session key for
// AES-256-GCM encryption (indicated by SHADOWSTRIKE_MSG_FLAG_ENCRYPTED).
//
typedef struct _SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE {
    SS_MESSAGE_HEADER Header;

    UCHAR Salt[32];              // Random salt for HKDF KWK derivation
    UCHAR Nonce[12];             // AES-256-GCM nonce for wrapping the session key
    UCHAR WrappedSessionKey[32]; // Session key encrypted with KWK (AES-256-GCM)
    UCHAR Tag[16];               // AES-256-GCM auth tag over WrappedSessionKey
    UCHAR SessionNoncePrefix[4]; // First 4 bytes of all message nonces for this session
    UINT32 KeyExpirySeconds;     // Suggested key lifetime (0 = no expiry)
    UINT32 ProtocolFlags;        // Reserved for protocol negotiation
    UINT32 Reserved;
} SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE, *PSHADOWSTRIKE_KEY_EXCHANGE_MESSAGE;

#define SHADOWSTRIKE_KEX_PROTOCOL_FLAG_MANDATORY_ENCRYPTION  0x00000001

//
// Connection context — passed by the user-mode client as the lpContext buffer
// of FilterConnectCommunicationPort and delivered to the kernel's
// ShadowStrikeConnectNotify as ConnectionContext.
//
//   ConnectionType : 1 = primary scanner connection (the only one the kernel
//                    targets with scan requests and whose session key gates
//                    those sends); 0 = auxiliary.
//   ClientImageHash: SHA-256 of the connecting client's OWN executable,
//                    computed in USER MODE. The kernel uses this as the
//                    key-exchange / key-wrapping input so both ends derive the
//                    identical KWK WITHOUT the kernel performing any file I/O
//                    inside its connect callback (such I/O re-enters the
//                    minifilter and can deadlock the filesystem stack). The
//                    connection itself is independently authenticated by
//                    ShadowStrikeVerifyClient (exact image path + SYSTEM
//                    token); this hash only binds the local session-key
//                    handoff. A later protocol revision (ephemeral ECDH)
//                    supersedes it with forward secrecy.
//
// Older/auxiliary clients that pass a smaller context (or none) remain
// supported: the kernel reads the hash only when SizeOfContext covers the full
// structure, otherwise it falls back without failing the connection.
//
#define SHADOWSTRIKE_CLIENT_IMAGE_HASH_SIZE 32

typedef struct _SHADOWSTRIKE_CONNECTION_CONTEXT {
    UINT32 ConnectionType;
    UCHAR  ClientImageHash[SHADOWSTRIKE_CLIENT_IMAGE_HASH_SIZE];
} SHADOWSTRIKE_CONNECTION_CONTEXT, *PSHADOWSTRIKE_CONNECTION_CONTEXT;

#pragma pack(pop)
