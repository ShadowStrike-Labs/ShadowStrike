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
 * ============================================================================
 * ShadowStrike NGAV - MESSAGE TYPES
 * ============================================================================
 *
 * @file MessageTypes.h
 * @brief Message type definitions for kernel<->user communication.
 *
 * Defines all message types used in the communication protocol between
 * the kernel driver and user-mode service.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

/**
 * @brief Message types for kernel<->user-mode communication.
 *
/**
 * @brief Message types for kernel<->user-mode communication.
 *
 * These values are used in the MessageType field of SHADOWSTRIKE_MESSAGE_HEADER.
 *
 * ---------------------------------------------------------------------------
 * HOW THESE VALUES ARE ASSIGNED - read this before adding a type
 * ---------------------------------------------------------------------------
 *
 * There are NO explicit initialisers below except None = 0, so the values are
 * SEQUENTIAL FROM ZERO in declaration order. FilterMessageType_Max is simply
 * "one past the last type" and is 45 today. A test under tests/kernel_contracts
 * pins both facts, so neither can drift silently.
 *
 * APPEND ONLY, immediately before FilterMessageType_Max. Two separate things
 * depend on that: the type number travels on the wire, so an insertion anywhere
 * else silently re-labels every later message class between a driver and a
 * service built at different times; and SHADOWSTRIKE_IS_DATA_PUSH_MESSAGE below
 * is a RELATIONAL test over a contiguous run of enumerators, so an insertion
 * inside that run changes what it classifies. Note the corollary: a new
 * data-push type appended at the end lands OUTSIDE that run, so it must be
 * added to that macro explicitly or it will not be recognised as a push.
 *
 * The group headings below are CATEGORY LABELS ONLY and carry no numeric
 * meaning. They previously advertised hex ranges - "Policy Messages
 * (0x30 - 0x3F)" and ten others - that this enum has never implemented. Nine
 * of the eleven were arithmetically false; the two that held did so only
 * because the enum happens to start at zero. That fiction is the documented
 * reason several user-mode modules stamped a "block this process" request with
 * 0x30, the opening value of the range labelled Policy. See task 158.
 *
 * 0x30, 0x31, 0x35 AND 0x36 ARE NOT MESSAGE TYPES. They are invented constants
 * in user-mode enforcement-request senders that transmit a bare struct with no
 * SHADOWSTRIKE_MESSAGE_HEADER at all. The driver refuses those frames at
 * MessageHandler.c:1125, because the first four bytes are read as Magic and do
 * not equal SHADOWSTRIKE_MESSAGE_MAGIC - NOT because the type is out of range.
 * Do NOT "fix" such a sender by adding a header while keeping the constant:
 * the magic check is the only gate that was stopping the frame, and adding a
 * header removes it. The type check now refuses 48 as well, because
 * ShadowStrikeProcessUserMessage tests SHADOWSTRIKE_VALID_MESSAGE_TYPE before
 * the MH_MAX_HANDLERS bound, so an out-of-enum value is rejected by RANGE
 * rather than merely by an empty handler slot. That closes the window only
 * while _Max stays below 48: once _Max exceeds 48 the value becomes a real
 * type again and the frame would dispatch to whatever occupies that slot.
 *
 * The receive path is, in order: Magic (MhpValidateAndCopyMessage), then
 * SHADOWSTRIKE_VALID_MESSAGE_TYPE and the MH_MAX_HANDLERS bound, then a
 * registered handler in that slot. MessageHandler.c:122 carries
 * C_ASSERT(MH_MAX_HANDLERS >= FilterMessageType_Max) - the build-time tie
 * between this enum and that table. If this enum ever outgrows 64 the driver
 * FAILS TO BUILD rather than silently truncating dispatch.
 *
 * Finally, the classification macros at the foot of this file.
 * SHADOWSTRIKE_VALID_MESSAGE_TYPE is now ENFORCED, at both MhRegisterHandler
 * and ShadowStrikeProcessUserMessage, so the handler table can neither bind
 * nor dispatch a type this enum does not define. The other five are CLASSIFIERS with no C caller;
 * a contract test enumerates this enum and fails if any type is classified by
 * none of them, which is what stops them rotting the way
 * IS_NOTIFICATION_MESSAGE already had. Read the note beside them before using
 * one: DIRECTION AND REPLY SEMANTICS ARE INDEPENDENT here.
 * ---------------------------------------------------------------------------
 */
typedef enum _SHADOWSTRIKE_MESSAGE_TYPE {
    //
    // Control
    //
    FilterMessageType_None = 0,
    FilterMessageType_Register,           // User-mode service registering
    FilterMessageType_Unregister,         // User-mode service disconnecting
    FilterMessageType_Heartbeat,          // Keep-alive
    FilterMessageType_ConfigUpdate,       // Configuration update

    //
    // Security / Key Exchange
    //
    FilterMessageType_KeyExchange,         // Session key exchange (K->U after client verification)

    //
    // Scan
    //
    FilterMessageType_ScanRequest,        // File scan request (Pre-Create/Write)
    FilterMessageType_ScanVerdict,        // Verdict reply

    //
    // Behavioral Notifications
    //
    FilterMessageType_ProcessNotify,      // Process creation/termination
    FilterMessageType_ThreadNotify,       // Remote thread creation
    FilterMessageType_ImageLoad,          // Image load (DLL/Driver)
    FilterMessageType_RegistryNotify,     // Registry operation
    FilterMessageType_NamedPipeEvent,     // Named pipe creation/connection (C2/lateral movement)
    FilterMessageType_FileBackupEvent,    // File backed up for ransomware rollback
    FilterMessageType_FileRollbackEvent,  // Files restored from ransomware backup

    //
    // ALPC Notifications
    //
    FilterMessageType_AlpcPortCreated,        // ALPC port created
    FilterMessageType_AlpcPortConnected,      // ALPC connection established
    FilterMessageType_AlpcPortDisconnected,   // ALPC connection terminated
    FilterMessageType_AlpcSuspiciousAccess,   // Suspicious ALPC access detected
    FilterMessageType_AlpcImpersonation,      // ALPC impersonation attempt
    FilterMessageType_AlpcSandboxEscape,      // Potential sandbox escape via ALPC
    FilterMessageType_AlpcRateLimitExceeded,  // ALPC rate limit exceeded

    //
    // Policy
    //
    FilterMessageType_QueryDriverStatus,  // Query driver status
    FilterMessageType_UpdatePolicy,       // Update driver policy
    FilterMessageType_EnableFiltering,    // Enable filtering
    FilterMessageType_DisableFiltering,   // Disable filtering
    FilterMessageType_RegisterProtectedProcess, // Register process for protection

    //
    // Handle Alert
    //
    FilterMessageType_HandleAlert,            // Suspicious handle operation detected

    //
    // Ransomware Detection
    //
    FilterMessageType_RansomwareAlert,        // Ransomware behavior detected (PostWrite)

    //
    // User-Mode -> Kernel Data Push
    // These enable the user-mode agent to push updated threat intelligence,
    // behavioral rules, and configuration to the kernel driver at runtime.
    //
    FilterMessageType_PushHashDatabase,       // Updated hash DB (good/bad hashes)
    FilterMessageType_PushPatternDatabase,    // Updated pattern matching rules
    FilterMessageType_PushSignatureDatabase,  // Updated file signatures
    FilterMessageType_PushIoCFeed,            // IoC feed injection (hashes, IPs, domains)
    FilterMessageType_PushWhitelist,          // Whitelist/allowlist updates
    FilterMessageType_UpdateBehavioralRules,  // Runtime behavioral rule updates
    FilterMessageType_PushNetworkIoC,         // Network IoC (C2 IPs, malicious domains)
    FilterMessageType_ExclusionUpdate,        // Exclusion list add/remove/clear

    //
    // Telemetry & Status
    //
    FilterMessageType_BehavioralAlert,        // Behavioral detection event
    FilterMessageType_MemoryAlert,            // Memory anomaly detection
    FilterMessageType_NetworkAlert,           // Network threat detection
    FilterMessageType_SyscallAlert,           // Suspicious syscall pattern
    FilterMessageType_SelfProtectAlert,       // Tamper attempt detected
    FilterMessageType_ExclusionQuery,         // Query current exclusion state
    FilterMessageType_ThreatScoreNotify,      // Composite threat score update

    //
    // File Operation Events
    //
    // Appended here deliberately. This enum has no explicit values, so a new
    // enumerator inserted anywhere except immediately before _Max renumbers
    // every type after it - and the type number is on the wire, so that would
    // silently re-label every subsequent message class between a driver and a
    // service built at different times. Append only.
    //
    FilterMessageType_FileOperationEvent,     // Rename/delete evaluated by PreSetInformation

    FilterMessageType_Max
} SHADOWSTRIKE_MESSAGE_TYPE;

// ============================================================================
// COMPATIBILITY ALIASES
// ============================================================================
//
// The codebase uses two naming conventions:
//   FilterMessageType_*     - Used in MessageTypes.h (original)
//   ShadowStrikeMessage*    - Used in CommPort.c and other files
//
// These aliases ensure both naming styles work correctly.
//

#define ShadowStrikeMessageNone                     FilterMessageType_None
#define ShadowStrikeMessageRegister                 FilterMessageType_Register
#define ShadowStrikeMessageUnregister               FilterMessageType_Unregister
#define ShadowStrikeMessageHeartbeat                FilterMessageType_Heartbeat
#define ShadowStrikeMessageConfigUpdate             FilterMessageType_ConfigUpdate
#define ShadowStrikeMessageKeyExchange              FilterMessageType_KeyExchange

#define ShadowStrikeMessageFileScanOnOpen           FilterMessageType_ScanRequest
#define ShadowStrikeMessageFileScanOnExecute        FilterMessageType_ScanRequest
#define ShadowStrikeMessageScanVerdict              FilterMessageType_ScanVerdict

#define ShadowStrikeMessageProcessNotify            FilterMessageType_ProcessNotify
#define ShadowStrikeMessageThreadNotify             FilterMessageType_ThreadNotify
#define ShadowStrikeMessageImageLoad                FilterMessageType_ImageLoad
#define ShadowStrikeMessageRegistryNotify           FilterMessageType_RegistryNotify

// ALPC message aliases
#define ShadowStrikeMessageAlpcPortCreated          FilterMessageType_AlpcPortCreated
#define ShadowStrikeMessageAlpcPortConnected        FilterMessageType_AlpcPortConnected
#define ShadowStrikeMessageAlpcPortDisconnected     FilterMessageType_AlpcPortDisconnected
#define ShadowStrikeMessageAlpcSuspiciousAccess     FilterMessageType_AlpcSuspiciousAccess
#define ShadowStrikeMessageAlpcImpersonation        FilterMessageType_AlpcImpersonation
#define ShadowStrikeMessageAlpcSandboxEscape        FilterMessageType_AlpcSandboxEscape
#define ShadowStrikeMessageAlpcRateLimitExceeded    FilterMessageType_AlpcRateLimitExceeded

#define ShadowStrikeMessageQueryDriverStatus        FilterMessageType_QueryDriverStatus
#define ShadowStrikeMessageUpdatePolicy             FilterMessageType_UpdatePolicy
#define ShadowStrikeMessageEnableFiltering          FilterMessageType_EnableFiltering
#define ShadowStrikeMessageDisableFiltering         FilterMessageType_DisableFiltering
#define ShadowStrikeMessageRegisterProtectedProcess FilterMessageType_RegisterProtectedProcess

// Handle alert message alias
#define ShadowStrikeMessageHandleAlert              FilterMessageType_HandleAlert
#define SHADOWSTRIKE_MSG_PROCESS_HANDLE_ALERT        FilterMessageType_HandleAlert

// Ransomware alert alias
#define ShadowStrikeMessageRansomwareAlert          FilterMessageType_RansomwareAlert

// Data push aliases (user-mode -> kernel)
#define ShadowStrikeMessagePushHashDB               FilterMessageType_PushHashDatabase
#define ShadowStrikeMessagePushPatternDB            FilterMessageType_PushPatternDatabase
#define ShadowStrikeMessagePushSignatureDB          FilterMessageType_PushSignatureDatabase
#define ShadowStrikeMessagePushIoCFeed              FilterMessageType_PushIoCFeed
#define ShadowStrikeMessagePushWhitelist            FilterMessageType_PushWhitelist
#define ShadowStrikeMessageUpdateBehavioralRules    FilterMessageType_UpdateBehavioralRules
#define ShadowStrikeMessagePushNetworkIoC           FilterMessageType_PushNetworkIoC
#define ShadowStrikeMessageExclusionUpdate          FilterMessageType_ExclusionUpdate

// Telemetry/alert aliases
#define ShadowStrikeMessageBehavioralAlert          FilterMessageType_BehavioralAlert
#define ShadowStrikeMessageMemoryAlert              FilterMessageType_MemoryAlert
#define ShadowStrikeMessageNetworkAlert             FilterMessageType_NetworkAlert
#define ShadowStrikeMessageSyscallAlert             FilterMessageType_SyscallAlert
#define ShadowStrikeMessageSelfProtectAlert         FilterMessageType_SelfProtectAlert
#define ShadowStrikeMessageExclusionQuery           FilterMessageType_ExclusionQuery
#define ShadowStrikeMessageThreatScoreNotify        FilterMessageType_ThreatScoreNotify

// ============================================================================
// MESSAGE TYPE CLASSIFICATION
// ============================================================================
//
// These six macros are the only written statement of the protocol's
// classification policy, which is why they are kept correct rather than
// deleted. Two things about them are load-bearing:
//
//   SHADOWSTRIKE_VALID_MESSAGE_TYPE IS ENFORCED. MhRegisterHandler refuses to
//   bind a handler to a type outside this enum, and ShadowStrikeProcessUserMessage refuses
//   an incoming frame whose type is outside it. Together those two gates make
//   the handler table's index space and this enum the same set, instead of the
//   table being 64 wide while the enum defines 45 values.
//
//   THE OTHER FIVE ARE CLASSIFIERS, NOT GATES, and have no C caller. They are
//   still not dead: a test under tests/kernel_contracts enumerates this enum
//   and fails if any enumerator is left out of every category, so appending a
//   type forces a decision here rather than letting it fall silently outside
//   all of them. That test exists because IS_NOTIFICATION_MESSAGE had drifted
//   to omit THIRTEEN real notification types - every ALPC type, both file
//   backup events, the named-pipe event, the handle and ransomware alerts and
//   the file-operation event - so anything wiring it to decide "is this a
//   notification" would have misclassified all thirteen.
//
// DIRECTION AND REPLY SEMANTICS ARE INDEPENDENT. Do not infer either from the
// other. FilterMessageType_ProcessNotify is BOTH a notification (the kernel
// sends it unsolicited) AND reply-bearing (the driver waits for a verdict when
// it sets RequireReply, which it does when the creation scored at or above
// PN_SUSPICION_MEDIUM). Whether a reply is owed for a PARTICULAR frame is
// therefore not a property of its type at all: it is decided per frame by
// Filter Manager's ReplyLength, which is the gate IPCManager honours. Never
// reply on the strength of a type test alone.
//

/**
 * @brief Is this a value this enum actually defines?
 *
 * ENFORCED - see MhRegisterHandler and ShadowStrikeProcessUserMessage. None is deliberately
 * excluded: it means "no message", not "message number zero".
 */
#define SHADOWSTRIKE_VALID_MESSAGE_TYPE(type) \
    ((type) > FilterMessageType_None && (type) < FilterMessageType_Max)

/**
 * @brief Control and session establishment. User -> kernel.
 */
#define SHADOWSTRIKE_IS_CONTROL_MESSAGE(type) \
    ((type) == FilterMessageType_Register || \
     (type) == FilterMessageType_Unregister || \
     (type) == FilterMessageType_Heartbeat || \
     (type) == FilterMessageType_ConfigUpdate || \
     (type) == FilterMessageType_KeyExchange)

/**
 * @brief The scan request / verdict pair.
 */
#define SHADOWSTRIKE_IS_SCAN_MESSAGE(type) \
    ((type) == FilterMessageType_ScanRequest || \
     (type) == FilterMessageType_ScanVerdict)

/**
 * @brief Policy and state queries. User -> kernel.
 */
#define SHADOWSTRIKE_IS_POLICY_MESSAGE(type) \
    ((type) == FilterMessageType_QueryDriverStatus || \
     (type) == FilterMessageType_UpdatePolicy || \
     (type) == FilterMessageType_EnableFiltering || \
     (type) == FilterMessageType_DisableFiltering || \
     (type) == FilterMessageType_RegisterProtectedProcess || \
     (type) == FilterMessageType_ExclusionQuery)

/**
 * @brief Kernel -> user, unsolicited.
 *
 * Says NOTHING about replies - see the note above. Complete as of
 * FilterMessageType_Max == 45.
 */
#define SHADOWSTRIKE_IS_NOTIFICATION_MESSAGE(type) \
    ((type) == FilterMessageType_ProcessNotify || \
     (type) == FilterMessageType_ThreadNotify || \
     (type) == FilterMessageType_ImageLoad || \
     (type) == FilterMessageType_RegistryNotify || \
     (type) == FilterMessageType_NamedPipeEvent || \
     (type) == FilterMessageType_FileBackupEvent || \
     (type) == FilterMessageType_FileRollbackEvent || \
     (type) == FilterMessageType_AlpcPortCreated || \
     (type) == FilterMessageType_AlpcPortConnected || \
     (type) == FilterMessageType_AlpcPortDisconnected || \
     (type) == FilterMessageType_AlpcSuspiciousAccess || \
     (type) == FilterMessageType_AlpcImpersonation || \
     (type) == FilterMessageType_AlpcSandboxEscape || \
     (type) == FilterMessageType_AlpcRateLimitExceeded || \
     (type) == FilterMessageType_HandleAlert || \
     (type) == FilterMessageType_RansomwareAlert || \
     (type) == FilterMessageType_BehavioralAlert || \
     (type) == FilterMessageType_MemoryAlert || \
     (type) == FilterMessageType_NetworkAlert || \
     (type) == FilterMessageType_SyscallAlert || \
     (type) == FilterMessageType_SelfProtectAlert || \
     (type) == FilterMessageType_ThreatScoreNotify || \
     (type) == FilterMessageType_FileOperationEvent)

/**
 * @brief User -> kernel data push.
 *
 * RELATIONAL over a contiguous run, so it is in tension with the append-only
 * rule: a new push type appended before _Max lands OUTSIDE this range and
 * would not be recognised. The contract test catches exactly that, because an
 * appended type classified by nothing fails it.
 */
#define SHADOWSTRIKE_IS_DATA_PUSH_MESSAGE(type) \
    ((type) >= FilterMessageType_PushHashDatabase && \
     (type) <= FilterMessageType_ExclusionUpdate)

/**
 * @brief Types for which a reply is DEFINED by the protocol.
 *
 * Necessary, not sufficient - the per-frame gate is ReplyLength, see above.
 * ProcessNotify is listed because the driver genuinely waits for a verdict on
 * suspicious creations (PN_VERDICT_REPLY_TIMEOUT_MS); it was absent while user
 * mode computed that verdict and discarded it.
 *
 * ExclusionQuery is deliberately ABSENT: it has no registered driver handler
 * and no user-mode producer, so nothing can answer it. Add it here in the same
 * change that gives it a handler, not before.
 */
#define SHADOWSTRIKE_REQUIRES_REPLY(type) \
    ((type) == FilterMessageType_ScanRequest || \
     (type) == FilterMessageType_ProcessNotify || \
     (type) == FilterMessageType_QueryDriverStatus)
