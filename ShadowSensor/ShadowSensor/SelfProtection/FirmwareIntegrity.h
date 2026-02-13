/*++
===============================================================================
ShadowStrike NGAV - FIRMWARE/UEFI INTEGRITY MONITOR
===============================================================================

@file FirmwareIntegrity.h
@brief Boot firmware integrity verification and bootkit detection.

Monitors firmware and boot configuration integrity:
  - UEFI Secure Boot state verification
  - Boot Configuration Data (BCD) monitoring
  - EFI System Partition access detection
  - Known bootkit signature patterns
  - UEFI variable integrity checks

Integration Points:
  - Driver initialization → FiInitialize() (one-time check)
  - PreCreate callback → FiCheckEspAccess() (ESP monitoring)
  - Periodic timer → FiVerifyBootIntegrity()
  - DriverEntry → FiInitialize() / FiShutdown()

MITRE ATT&CK Coverage:
  - T1542.001: System Firmware (UEFI implants)
  - T1542.003: Bootkit
  - T1014: Rootkit (firmware-level persistence)
  - T1495: Firmware Corruption

@author ShadowStrike Security Team
@version 1.0.0
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#pragma once

#include <ntddk.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define FI_POOL_TAG             'iFWF'  // FWFi - Firmware Integrity
#define FI_CHECK_POOL_TAG       'cFWF'  // FWFc - Check buffer

// ============================================================================
// BOOT INTEGRITY STATUS
// ============================================================================

typedef enum _FI_BOOT_STATUS {
    FiBoot_Unknown = 0,
    FiBoot_SecureBootEnabled,       // Secure Boot active
    FiBoot_SecureBootDisabled,      // Secure Boot OFF (risk)
    FiBoot_SecureBootSetupMode,     // Setup mode (vulnerable)
    FiBoot_Compromised              // Integrity failure detected
} FI_BOOT_STATUS;

// ============================================================================
// THREAT TYPE
// ============================================================================

typedef enum _FI_THREAT_TYPE {
    FiThreat_None = 0,
    FiThreat_SecureBootDisabled,
    FiThreat_EspModification,       // EFI System Partition write
    FiThreat_BcdModification,       // Boot config changed
    FiThreat_UefiVariableTamper,    // UEFI variable modified
    FiThreat_BootkitSignature,      // Known bootkit pattern
    FiThreat_FirmwareCorruption     // Firmware integrity failure
} FI_THREAT_TYPE;

// ============================================================================
// STATISTICS
// ============================================================================

typedef struct _FI_STATISTICS {

    volatile LONG64 IntegrityChecks;
    volatile LONG64 ThreatsDetected;
    volatile LONG64 EspAccessBlocked;
    volatile LONG64 BcdModificationsDetected;
    FI_BOOT_STATUS  CurrentBootStatus;

} FI_STATISTICS, *PFI_STATISTICS;

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * @brief Initialize firmware integrity monitor.
 *
 * Performs initial boot integrity assessment (Secure Boot state,
 * BCD integrity, ESP status).
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FiInitialize(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
FiShutdown(VOID);

/**
 * @brief Check if file access targets EFI System Partition.
 *
 * Called from PreCreate callback. Detects writes to EFI partition
 * which could indicate bootkit installation.
 *
 * @param[in] FileName      Normalized file path.
 * @param[in] DesiredAccess Requested access rights.
 *
 * @return FI_THREAT_TYPE if suspicious, FiThreat_None if clean.
 */
_IRQL_requires_max_(APC_LEVEL)
FI_THREAT_TYPE
FiCheckEspAccess(
    _In_ PCUNICODE_STRING FileName,
    _In_ ACCESS_MASK DesiredAccess
    );

/**
 * @brief Verify current boot integrity state.
 *
 * Can be called periodically to re-check firmware integrity.
 */
_IRQL_requires_(PASSIVE_LEVEL)
FI_BOOT_STATUS
FiVerifyBootIntegrity(VOID);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
FiGetStatistics(
    _Out_ PFI_STATISTICS Statistics
    );
