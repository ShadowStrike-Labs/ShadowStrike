/**
 * ============================================================================
 * ShadowStrike NGAV - ERROR CODES
 * ============================================================================
 *
 * @file ErrorCodes.h
 * @brief Custom NTSTATUS error codes for the kernel driver.
 *
 * Defines driver-specific error codes in the customer-defined range
 * (Severity=3, Facility=0, Customer=1).
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_ERROR_CODES_H
#define SHADOWSTRIKE_ERROR_CODES_H

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// NTSTATUS CODE LAYOUT
// ============================================================================
//
// NTSTATUS format:
// [31:30] Severity (0=Success, 1=Info, 2=Warning, 3=Error)
// [29]    Customer flag (1=customer-defined)
// [28]    Reserved
// [27:16] Facility code
// [15:0]  Error code
//
// We use: Severity=3, Customer=1, Facility=0x100 (custom)
// Base: 0xE0100000
//
// ============================================================================

/// @brief Base for ShadowStrike error codes
#define SHADOWSTRIKE_ERROR_BASE         0xE0100000

// ============================================================================
// GENERAL ERRORS (0x001 - 0x0FF)
// ============================================================================

/// @brief Unspecified internal error
#define SHADOWSTRIKE_ERROR_INTERNAL             (SHADOWSTRIKE_ERROR_BASE | 0x001)

/// @brief Driver not initialized
#define SHADOWSTRIKE_ERROR_NOT_INITIALIZED      (SHADOWSTRIKE_ERROR_BASE | 0x002)

/// @brief Driver already initialized
#define SHADOWSTRIKE_ERROR_ALREADY_INITIALIZED  (SHADOWSTRIKE_ERROR_BASE | 0x003)

/// @brief Invalid parameter
#define SHADOWSTRIKE_ERROR_INVALID_PARAMETER    (SHADOWSTRIKE_ERROR_BASE | 0x004)

/// @brief Operation not supported
#define SHADOWSTRIKE_ERROR_NOT_SUPPORTED        (SHADOWSTRIKE_ERROR_BASE | 0x005)

/// @brief Resource allocation failed
#define SHADOWSTRIKE_ERROR_ALLOCATION_FAILED    (SHADOWSTRIKE_ERROR_BASE | 0x006)

/// @brief Buffer too small
#define SHADOWSTRIKE_ERROR_BUFFER_TOO_SMALL     (SHADOWSTRIKE_ERROR_BASE | 0x007)

/// @brief Invalid message format
#define SHADOWSTRIKE_ERROR_INVALID_MESSAGE      (SHADOWSTRIKE_ERROR_BASE | 0x008)

/// @brief Version mismatch
#define SHADOWSTRIKE_ERROR_VERSION_MISMATCH     (SHADOWSTRIKE_ERROR_BASE | 0x009)

// ============================================================================
// COMMUNICATION ERRORS (0x100 - 0x1FF)
// ============================================================================

/// @brief Communication port not connected
#define SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED   (SHADOWSTRIKE_ERROR_BASE | 0x100)

/// @brief Failed to create communication port
#define SHADOWSTRIKE_ERROR_PORT_CREATE_FAILED   (SHADOWSTRIKE_ERROR_BASE | 0x101)

/// @brief Client connection rejected
#define SHADOWSTRIKE_ERROR_CONNECTION_REJECTED  (SHADOWSTRIKE_ERROR_BASE | 0x102)

/// @brief Maximum connections exceeded
#define SHADOWSTRIKE_ERROR_MAX_CONNECTIONS      (SHADOWSTRIKE_ERROR_BASE | 0x103)

/// @brief Message send failed
#define SHADOWSTRIKE_ERROR_SEND_FAILED          (SHADOWSTRIKE_ERROR_BASE | 0x104)

/// @brief Reply timeout
#define SHADOWSTRIKE_ERROR_REPLY_TIMEOUT        (SHADOWSTRIKE_ERROR_BASE | 0x105)

/// @brief Invalid reply received
#define SHADOWSTRIKE_ERROR_INVALID_REPLY        (SHADOWSTRIKE_ERROR_BASE | 0x106)

/// @brief Message queue full
#define SHADOWSTRIKE_ERROR_QUEUE_FULL           (SHADOWSTRIKE_ERROR_BASE | 0x107)

/// @brief Client disconnected unexpectedly
#define SHADOWSTRIKE_ERROR_CLIENT_DISCONNECTED  (SHADOWSTRIKE_ERROR_BASE | 0x108)

// ============================================================================
// SCANNING ERRORS (0x200 - 0x2FF)
// ============================================================================

/// @brief Scan failed
#define SHADOWSTRIKE_ERROR_SCAN_FAILED          (SHADOWSTRIKE_ERROR_BASE | 0x200)

/// @brief Scan timeout
#define SHADOWSTRIKE_ERROR_SCAN_TIMEOUT         (SHADOWSTRIKE_ERROR_BASE | 0x201)

/// @brief Scan cancelled
#define SHADOWSTRIKE_ERROR_SCAN_CANCELLED       (SHADOWSTRIKE_ERROR_BASE | 0x202)

/// @brief User-mode scanner unavailable
#define SHADOWSTRIKE_ERROR_SCANNER_UNAVAILABLE  (SHADOWSTRIKE_ERROR_BASE | 0x203)

/// @brief File access denied during scan
#define SHADOWSTRIKE_ERROR_SCAN_ACCESS_DENIED   (SHADOWSTRIKE_ERROR_BASE | 0x204)

/// @brief File too large for scan
#define SHADOWSTRIKE_ERROR_FILE_TOO_LARGE       (SHADOWSTRIKE_ERROR_BASE | 0x205)

// ============================================================================
// CACHE ERRORS (0x300 - 0x3FF)
// ============================================================================

/// @brief Cache lookup failed
#define SHADOWSTRIKE_ERROR_CACHE_LOOKUP_FAILED  (SHADOWSTRIKE_ERROR_BASE | 0x300)

/// @brief Cache insert failed
#define SHADOWSTRIKE_ERROR_CACHE_INSERT_FAILED  (SHADOWSTRIKE_ERROR_BASE | 0x301)

/// @brief Cache entry not found
#define SHADOWSTRIKE_ERROR_CACHE_NOT_FOUND      (SHADOWSTRIKE_ERROR_BASE | 0x302)

/// @brief Cache entry expired
#define SHADOWSTRIKE_ERROR_CACHE_EXPIRED        (SHADOWSTRIKE_ERROR_BASE | 0x303)

// ============================================================================
// EXCLUSION ERRORS (0x400 - 0x4FF)
// ============================================================================

/// @brief Exclusion list full
#define SHADOWSTRIKE_ERROR_EXCLUSION_FULL       (SHADOWSTRIKE_ERROR_BASE | 0x400)

/// @brief Invalid exclusion pattern
#define SHADOWSTRIKE_ERROR_INVALID_EXCLUSION    (SHADOWSTRIKE_ERROR_BASE | 0x401)

/// @brief Exclusion not found
#define SHADOWSTRIKE_ERROR_EXCLUSION_NOT_FOUND  (SHADOWSTRIKE_ERROR_BASE | 0x402)

// ============================================================================
// SELF-PROTECTION ERRORS (0x500 - 0x5FF)
// ============================================================================

/// @brief Protected process registration failed
#define SHADOWSTRIKE_ERROR_PROTECTION_FAILED    (SHADOWSTRIKE_ERROR_BASE | 0x500)

/// @brief Process not in protected list
#define SHADOWSTRIKE_ERROR_NOT_PROTECTED        (SHADOWSTRIKE_ERROR_BASE | 0x501)

/// @brief Maximum protected processes exceeded
#define SHADOWSTRIKE_ERROR_MAX_PROTECTED        (SHADOWSTRIKE_ERROR_BASE | 0x502)

/// @brief Invalid process for protection
#define SHADOWSTRIKE_ERROR_INVALID_PROCESS      (SHADOWSTRIKE_ERROR_BASE | 0x503)

/// @brief Access denied by self-protection
#define SHADOWSTRIKE_ERROR_SELF_PROTECTION      (SHADOWSTRIKE_ERROR_BASE | 0x504)

// ============================================================================
// FILTER REGISTRATION ERRORS (0x600 - 0x6FF)
// ============================================================================

/// @brief Filter registration failed
#define SHADOWSTRIKE_ERROR_FILTER_REGISTER      (SHADOWSTRIKE_ERROR_BASE | 0x600)

/// @brief Filter start failed
#define SHADOWSTRIKE_ERROR_FILTER_START         (SHADOWSTRIKE_ERROR_BASE | 0x601)

/// @brief Instance attach failed
#define SHADOWSTRIKE_ERROR_INSTANCE_ATTACH      (SHADOWSTRIKE_ERROR_BASE | 0x602)

/// @brief Callback registration failed
#define SHADOWSTRIKE_ERROR_CALLBACK_REGISTER    (SHADOWSTRIKE_ERROR_BASE | 0x603)

// ============================================================================
// SUCCESS CODES
// ============================================================================

/// @brief Operation succeeded
#define SHADOWSTRIKE_SUCCESS                    ((NTSTATUS)0x00000000)

/// @brief Operation succeeded, file is clean
#define SHADOWSTRIKE_SUCCESS_CLEAN              ((NTSTATUS)0x00100001)

/// @brief Operation succeeded, file is whitelisted
#define SHADOWSTRIKE_SUCCESS_WHITELISTED        ((NTSTATUS)0x00100002)

/// @brief Operation succeeded, result from cache
#define SHADOWSTRIKE_SUCCESS_CACHED             ((NTSTATUS)0x00100003)

/// @brief Operation succeeded, file excluded
#define SHADOWSTRIKE_SUCCESS_EXCLUDED           ((NTSTATUS)0x00100004)

// ============================================================================
// WARNING CODES
// ============================================================================

/// @brief File is suspicious but allowed
#define SHADOWSTRIKE_WARNING_SUSPICIOUS         ((NTSTATUS)0x80100001)

/// @brief Scan was skipped
#define SHADOWSTRIKE_WARNING_SKIPPED            ((NTSTATUS)0x80100002)

/// @brief Using default policy due to error
#define SHADOWSTRIKE_WARNING_DEFAULT_POLICY     ((NTSTATUS)0x80100003)

// ============================================================================
// ERROR CHECKING MACROS
// ============================================================================

/// @brief Check if status is a ShadowStrike error
#define SHADOWSTRIKE_IS_ERROR(status) \
    (((status) & 0xFFFF0000) == SHADOWSTRIKE_ERROR_BASE)

/// @brief Check if status is a ShadowStrike success
#define SHADOWSTRIKE_IS_SUCCESS(status) \
    (((status) == STATUS_SUCCESS) || (((status) & 0xFFF00000) == 0x00100000))

/// @brief Check if status is a ShadowStrike warning
#define SHADOWSTRIKE_IS_WARNING(status) \
    (((status) & 0xFFF00000) == 0x80100000)

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_ERROR_CODES_H
