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
 * These values are used in the MessageType field of SHADOWSTRIKE_MESSAGE_HEADER.
 */
typedef enum _SHADOWSTRIKE_MESSAGE_TYPE {
    //
    // Control Messages (0x00 - 0x0F)
    //
    FilterMessageType_None = 0,
    FilterMessageType_Register,           // User-mode service registering
    FilterMessageType_Unregister,         // User-mode service disconnecting
    FilterMessageType_Heartbeat,          // Keep-alive
    FilterMessageType_ConfigUpdate,       // Configuration update

    //
    // Scan Messages (0x10 - 0x1F)
    //
    FilterMessageType_ScanRequest,        // File scan request (Pre-Create/Write)
    FilterMessageType_ScanVerdict,        // Verdict reply

    //
    // Behavioral Notifications (0x20 - 0x2F)
    //
    FilterMessageType_ProcessNotify,      // Process creation/termination
    FilterMessageType_ThreadNotify,       // Remote thread creation
    FilterMessageType_ImageLoad,          // Image load (DLL/Driver)
    FilterMessageType_RegistryNotify,     // Registry operation
    FilterMessageType_NamedPipeEvent,     // Named pipe creation/connection (C2/lateral movement)
    FilterMessageType_FileBackupEvent,    // File backed up for ransomware rollback
    FilterMessageType_FileRollbackEvent,  // Files restored from ransomware backup

    //
    // ALPC Notifications (0x40 - 0x4F)
    //
    FilterMessageType_AlpcPortCreated,        // ALPC port created
    FilterMessageType_AlpcPortConnected,      // ALPC connection established
    FilterMessageType_AlpcPortDisconnected,   // ALPC connection terminated
    FilterMessageType_AlpcSuspiciousAccess,   // Suspicious ALPC access detected
    FilterMessageType_AlpcImpersonation,      // ALPC impersonation attempt
    FilterMessageType_AlpcSandboxEscape,      // Potential sandbox escape via ALPC
    FilterMessageType_AlpcRateLimitExceeded,  // ALPC rate limit exceeded

    //
    // Policy Messages (0x30 - 0x3F)
    //
    FilterMessageType_QueryDriverStatus,  // Query driver status
    FilterMessageType_UpdatePolicy,       // Update driver policy
    FilterMessageType_EnableFiltering,    // Enable filtering
    FilterMessageType_DisableFiltering,   // Disable filtering
    FilterMessageType_RegisterProtectedProcess, // Register process for protection

    //
    // Handle Alert Messages (0x50 - 0x5F)
    //
    FilterMessageType_HandleAlert,            // Suspicious handle operation detected

    //
    // Ransomware Detection Messages (0x60 - 0x6F)
    //
    FilterMessageType_RansomwareAlert,        // Ransomware behavior detected (PostWrite)

    //
    // User-Mode → Kernel Data Push Messages (0x70 - 0x8F)
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
    // Telemetry & Status Messages (0x90 - 0x9F)
    //
    FilterMessageType_BehavioralAlert,        // Behavioral detection event
    FilterMessageType_MemoryAlert,            // Memory anomaly detection
    FilterMessageType_NetworkAlert,           // Network threat detection
    FilterMessageType_SyscallAlert,           // Suspicious syscall pattern
    FilterMessageType_SelfProtectAlert,       // Tamper attempt detected
    FilterMessageType_ExclusionQuery,         // Query current exclusion state
    FilterMessageType_ThreatScoreNotify,      // Composite threat score update

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

// Data push aliases (user-mode → kernel)
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
// MESSAGE TYPE VALIDATION
// ============================================================================

/**
 * @brief Check if message type is valid.
 */
#define SHADOWSTRIKE_VALID_MESSAGE_TYPE(type) \
    ((type) > FilterMessageType_None && (type) < FilterMessageType_Max)

/**
 * @brief Check if message type is a scan-related message.
 */
#define SHADOWSTRIKE_IS_SCAN_MESSAGE(type) \
    ((type) == FilterMessageType_ScanRequest || (type) == FilterMessageType_ScanVerdict)

/**
 * @brief Check if message type is a notification (async, no reply needed).
 */
#define SHADOWSTRIKE_IS_NOTIFICATION_MESSAGE(type) \
    ((type) == FilterMessageType_ProcessNotify || \
     (type) == FilterMessageType_ThreadNotify || \
     (type) == FilterMessageType_ImageLoad || \
     (type) == FilterMessageType_RegistryNotify || \
     (type) == FilterMessageType_BehavioralAlert || \
     (type) == FilterMessageType_MemoryAlert || \
     (type) == FilterMessageType_NetworkAlert || \
     (type) == FilterMessageType_SyscallAlert || \
     (type) == FilterMessageType_SelfProtectAlert || \
     (type) == FilterMessageType_ThreatScoreNotify)

/**
 * @brief Check if message type is a user-mode → kernel data push.
 */
#define SHADOWSTRIKE_IS_DATA_PUSH_MESSAGE(type) \
    ((type) >= FilterMessageType_PushHashDatabase && \
     (type) <= FilterMessageType_ExclusionUpdate)

/**
 * @brief Check if message type requires a reply.
 */
#define SHADOWSTRIKE_REQUIRES_REPLY(type) \
    ((type) == FilterMessageType_ScanRequest || \
     (type) == FilterMessageType_QueryDriverStatus)
