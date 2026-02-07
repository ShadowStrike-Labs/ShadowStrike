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

    //
    // Policy Messages (0x30 - 0x3F)
    //
    FilterMessageType_QueryDriverStatus,  // Query driver status
    FilterMessageType_UpdatePolicy,       // Update driver policy
    FilterMessageType_EnableFiltering,    // Enable filtering
    FilterMessageType_DisableFiltering,   // Disable filtering
    FilterMessageType_RegisterProtectedProcess, // Register process for protection

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

#define ShadowStrikeMessageQueryDriverStatus        FilterMessageType_QueryDriverStatus
#define ShadowStrikeMessageUpdatePolicy             FilterMessageType_UpdatePolicy
#define ShadowStrikeMessageEnableFiltering          FilterMessageType_EnableFiltering
#define ShadowStrikeMessageDisableFiltering         FilterMessageType_DisableFiltering
#define ShadowStrikeMessageRegisterProtectedProcess FilterMessageType_RegisterProtectedProcess

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
     (type) == FilterMessageType_RegistryNotify)

/**
 * @brief Check if message type requires a reply.
 */
#define SHADOWSTRIKE_REQUIRES_REPLY(type) \
    ((type) == FilterMessageType_ScanRequest || \
     (type) == FilterMessageType_QueryDriverStatus)
