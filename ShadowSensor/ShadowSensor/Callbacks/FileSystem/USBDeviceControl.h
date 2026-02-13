/*++
===============================================================================
ShadowStrike NGAV - USB DEVICE CONTROL MODULE
===============================================================================

@file USBDeviceControl.h
@brief USB removable device policy enforcement for data exfiltration prevention.

Provides enterprise-grade USB device control including:
  - Removable media write blocking (policy-driven)
  - Device whitelist/blacklist by VendorID, ProductID, SerialNumber
  - Volume mount/dismount tracking via minifilter InstanceSetup
  - Autorun.inf detection and blocking
  - BadUSB/Rubber Ducky keystroke injection detection
  - Per-device and per-class policy enforcement

Policy Modes:
  - Allow:    Full access to removable device
  - ReadOnly: Read allowed, write blocked via PreWrite/PreSetInfo callbacks
  - Block:    Volume attachment rejected entirely via InstanceSetup
  - Audit:    Log only, no blocking

Integration Points:
  - InstanceSetup callback → UdcCheckVolumePolicy()
  - PreWrite callback → UdcIsWriteBlocked()
  - PreSetInfo callback → UdcIsSetInfoBlocked()
  - PreCreate callback → UdcCheckAutorun()
  - DriverEntry → UdcInitialize() / UdcShutdown()

MITRE ATT&CK Coverage:
  - T1052.001: Exfiltration over USB
  - T1091: Replication through Removable Media
  - T1200: Hardware Additions (BadUSB)
  - T1204.002: Malicious File (Autorun)

@author ShadowStrike Security Team
@version 1.0.0
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#pragma once

#include <fltKernel.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define UDC_POOL_TAG            'cDUF'  // FUDc - USB Device Control
#define UDC_DEVICE_POOL_TAG     'dDUF'  // FUDd - Device Entry
#define UDC_EVENT_POOL_TAG      'eDUF'  // FUDe - Event

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

#define UDC_MAX_WHITELIST_ENTRIES        256
#define UDC_MAX_BLACKLIST_ENTRIES        256
#define UDC_MAX_TRACKED_VOLUMES         64
#define UDC_SERIAL_MAX_LENGTH           128
#define UDC_MAX_AUTORUN_SIZE            (64 * 1024)     // 64 KB max autorun.inf

// ============================================================================
// DEVICE POLICY
// ============================================================================

typedef enum _UDC_DEVICE_POLICY {
    UdcPolicy_Allow = 0,        // Full access
    UdcPolicy_ReadOnly,         // Read-only, write operations blocked
    UdcPolicy_Block,            // Volume attachment rejected entirely
    UdcPolicy_Audit             // Log only, no blocking
} UDC_DEVICE_POLICY;

// ============================================================================
// DEVICE CLASS
// ============================================================================

typedef enum _UDC_DEVICE_CLASS {
    UdcClass_Unknown = 0,
    UdcClass_MassStorage,       // USB mass storage (flash drives, HDDs)
    UdcClass_CDROM,             // USB CD/DVD
    UdcClass_HID,               // Human Interface Device (keyboard, mouse)
    UdcClass_Network,           // USB network adapter
    UdcClass_Printer,           // USB printer
    UdcClass_Other              // Unclassified
} UDC_DEVICE_CLASS;

// ============================================================================
// DEVICE RULE ENTRY
// ============================================================================

typedef struct _UDC_DEVICE_RULE {

    LIST_ENTRY Link;

    //
    // Match criteria (0 = wildcard/match any)
    //
    USHORT VendorId;
    USHORT ProductId;
    WCHAR SerialNumber[UDC_SERIAL_MAX_LENGTH];
    USHORT SerialNumberLength;      // 0 = match any serial

    //
    // Device class filter (UdcClass_Unknown = match any class)
    //
    UDC_DEVICE_CLASS DeviceClass;

    //
    // Policy to apply
    //
    UDC_DEVICE_POLICY Policy;

    //
    // Rule metadata
    //
    LARGE_INTEGER CreatedTime;
    ULONG RuleId;

} UDC_DEVICE_RULE, *PUDC_DEVICE_RULE;

// ============================================================================
// TRACKED VOLUME
// ============================================================================

typedef struct _UDC_TRACKED_VOLUME {

    LIST_ENTRY Link;

    //
    // Volume identification
    //
    UNICODE_STRING VolumeName;
    WCHAR VolumeNameBuffer[260];
    ULONG VolumeSerial;

    //
    // Device information
    //
    USHORT VendorId;
    USHORT ProductId;
    WCHAR SerialNumber[UDC_SERIAL_MAX_LENGTH];
    UDC_DEVICE_CLASS DeviceClass;

    //
    // Effective policy
    //
    UDC_DEVICE_POLICY EffectivePolicy;

    //
    // Tracking
    //
    LARGE_INTEGER MountTime;
    PFLT_INSTANCE Instance;         // Minifilter instance on this volume
    volatile LONG WriteAttempts;
    volatile LONG WriteBlocked;
    volatile LONG FilesAccessed;

} UDC_TRACKED_VOLUME, *PUDC_TRACKED_VOLUME;

// ============================================================================
// STATISTICS
// ============================================================================

typedef struct _UDC_STATISTICS {

    volatile LONG64 VolumeMounts;
    volatile LONG64 VolumeDismounts;
    volatile LONG64 WritesBlocked;
    volatile LONG64 WritesAllowed;
    volatile LONG64 VolumeAttachRejected;
    volatile LONG64 AutorunDetected;
    volatile LONG64 AutorunBlocked;
    volatile LONG64 PolicyChecks;

} UDC_STATISTICS, *PUDC_STATISTICS;

// ============================================================================
// CONFIGURATION
// ============================================================================

typedef struct _UDC_CONFIG {

    UDC_DEVICE_POLICY DefaultPolicy;    // Policy for unlisted devices
    BOOLEAN EnableAutorunBlocking;      // Block autorun.inf access
    BOOLEAN EnableWriteProtection;      // Enforce write policies
    BOOLEAN EnableAuditLogging;         // Log all USB events
    BOOLEAN Enabled;                    // Master enable/disable

} UDC_CONFIG, *PUDC_CONFIG;

// ============================================================================
// PUBLIC API — LIFECYCLE
// ============================================================================

/**
 * @brief Initialize the USB device control module.
 *
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
UdcInitialize(VOID);

/**
 * @brief Shutdown the USB device control module.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UdcShutdown(VOID);

// ============================================================================
// PUBLIC API — POLICY CHECKS (called from minifilter callbacks)
// ============================================================================

/**
 * @brief Check volume attachment policy for InstanceSetup callback.
 *
 * Determines whether the minifilter should attach to a removable volume
 * and returns the effective policy.
 *
 * @param[in]  FltObjects   Filter objects with volume information.
 * @param[out] Policy       Receives the effective policy for this volume.
 *
 * @return TRUE if volume should be attached (Allow/ReadOnly/Audit).
 *         FALSE if volume should be rejected (Block policy).
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
UdcCheckVolumePolicy(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PUDC_DEVICE_POLICY Policy
    );

/**
 * @brief Check if a write operation should be blocked on a removable volume.
 *
 * @param[in] FltObjects    Filter objects identifying the volume.
 *
 * @return TRUE if write should be blocked (ReadOnly policy).
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
UdcIsWriteBlocked(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

/**
 * @brief Check if a set-information operation should be blocked (rename/delete).
 *
 * @param[in] FltObjects    Filter objects identifying the volume.
 *
 * @return TRUE if operation should be blocked.
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
UdcIsSetInfoBlocked(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

/**
 * @brief Check if file access targets autorun.inf and should be blocked.
 *
 * @param[in] FileName      Normalized file path.
 *
 * @return TRUE if autorun.inf should be blocked.
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
UdcCheckAutorun(
    _In_ PCUNICODE_STRING FileName
    );

// ============================================================================
// PUBLIC API — VOLUME TRACKING
// ============================================================================

/**
 * @brief Notify module of volume mount (called from InstanceSetup).
 *
 * @param[in] FltObjects    Filter objects for the new volume.
 * @param[in] Policy        Effective policy assigned to this volume.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UdcNotifyVolumeMount(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ UDC_DEVICE_POLICY Policy
    );

/**
 * @brief Notify module of volume dismount (called from InstanceTeardown).
 *
 * @param[in] FltObjects    Filter objects for the departing volume.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
UdcNotifyVolumeDismount(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

// ============================================================================
// PUBLIC API — QUERY
// ============================================================================

/**
 * @brief Get USB device control statistics.
 *
 * @param[out] Statistics   Receives statistics snapshot.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
UdcGetStatistics(
    _Out_ PUDC_STATISTICS Statistics
    );
