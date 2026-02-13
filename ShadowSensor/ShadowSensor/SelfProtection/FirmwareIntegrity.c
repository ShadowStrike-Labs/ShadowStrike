/*++
===============================================================================
ShadowStrike NGAV - FIRMWARE/UEFI INTEGRITY IMPLEMENTATION
===============================================================================

@file FirmwareIntegrity.c
@brief Boot firmware verification, Secure Boot monitoring, and ESP protection.

Implementation Strategy:
  - ExGetFirmwareEnvironmentVariable for UEFI variable queries
  - Secure Boot state read from "SecureBoot" UEFI variable
  - EFI System Partition detection via path pattern matching
  - BCD store monitoring via file path interception

@author ShadowStrike Security Team
@version 1.0.0
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "FirmwareIntegrity.h"
#include "../Core/Globals.h"
#include <ntstrsafe.h>

// ============================================================================
// UEFI GUIDS
// ============================================================================

//
// EFI Global Variable GUID: {8BE4DF61-93CA-11D2-AA0D-00E098032B8C}
//
static const GUID EFI_GLOBAL_VARIABLE_GUID = {
    0x8BE4DF61, 0x93CA, 0x11D2,
    { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C }
};

// ============================================================================
// ESP PATH PATTERNS
// ============================================================================

static const UNICODE_STRING g_EspPaths[] = {
    RTL_CONSTANT_STRING(L"\\EFI\\"),
    RTL_CONSTANT_STRING(L"\\EFI\\Microsoft\\Boot\\"),
    RTL_CONSTANT_STRING(L"\\EFI\\Boot\\"),
    RTL_CONSTANT_STRING(L"\\Boot\\BCD"),
};

#define FI_ESP_PATH_COUNT \
    (sizeof(g_EspPaths) / sizeof(g_EspPaths[0]))

// ============================================================================
// STATE
// ============================================================================

typedef struct _FI_STATE {
    volatile LONG       State;
    EX_RUNDOWN_REF      RundownRef;
    FI_BOOT_STATUS      BootStatus;
    FI_STATISTICS       Stats;
} FI_STATE;

static FI_STATE g_FiState;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static FI_BOOT_STATUS
FipQuerySecureBootState(VOID);

static BOOLEAN
FipIsEspPath(
    _In_ PCUNICODE_STRING FileName
    );

static BOOLEAN
FipEnterOperation(VOID);

static VOID
FipLeaveOperation(VOID);

// ============================================================================
// LIFECYCLE
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FiInitialize(VOID)
{
    LONG Previous;

    PAGED_CODE();

    Previous = InterlockedCompareExchange(&g_FiState.State, 1, 0);
    if (Previous != 0) {
        return (Previous == 2) ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
    }

    ExInitializeRundownProtection(&g_FiState.RundownRef);
    RtlZeroMemory(&g_FiState.Stats, sizeof(FI_STATISTICS));

    //
    // Perform initial boot integrity assessment
    //
    g_FiState.BootStatus = FipQuerySecureBootState();
    g_FiState.Stats.CurrentBootStatus = g_FiState.BootStatus;
    g_FiState.Stats.IntegrityChecks = 1;

    if (g_FiState.BootStatus == FiBoot_SecureBootDisabled) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/FI] WARNING: Secure Boot is DISABLED! "
                   "System is vulnerable to firmware-level attacks.\n");
        InterlockedIncrement64(&g_FiState.Stats.ThreatsDetected);
    } else if (g_FiState.BootStatus == FiBoot_SecureBootEnabled) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike/FI] Secure Boot: ENABLED (Verified)\n");
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike/FI] Secure Boot state: %d\n",
                   g_FiState.BootStatus);
    }

    InterlockedExchange(&g_FiState.State, 2);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/FI] Firmware Integrity monitor initialized\n");

    return STATUS_SUCCESS;
}


_IRQL_requires_(PASSIVE_LEVEL)
VOID
FiShutdown(VOID)
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_FiState.State, 3, 2) != 2) {
        return;
    }

    ExWaitForRundownProtectionRelease(&g_FiState.RundownRef);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/FI] Shutdown complete. "
               "Checks=%lld, Threats=%lld, EspBlocked=%lld\n",
               g_FiState.Stats.IntegrityChecks,
               g_FiState.Stats.ThreatsDetected,
               g_FiState.Stats.EspAccessBlocked);
}

// ============================================================================
// ESP ACCESS MONITORING
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
FI_THREAT_TYPE
FiCheckEspAccess(
    _In_ PCUNICODE_STRING FileName,
    _In_ ACCESS_MASK DesiredAccess
    )
{
    if (!FipEnterOperation()) {
        return FiThreat_None;
    }

    if (!FipIsEspPath(FileName)) {
        FipLeaveOperation();
        return FiThreat_None;
    }

    //
    // Read access to ESP is acceptable (for backup tools, etc.)
    // Write access is suspicious and may indicate bootkit installation
    //
    if (FlagOn(DesiredAccess, FILE_WRITE_DATA | FILE_APPEND_DATA |
               FILE_WRITE_ATTRIBUTES | DELETE | FILE_WRITE_EA)) {

        InterlockedIncrement64(&g_FiState.Stats.ThreatsDetected);
        InterlockedIncrement64(&g_FiState.Stats.EspAccessBlocked);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike/FI] CRITICAL: Write access to EFI partition detected! "
                   "File=%wZ, Access=0x%08X, PID=%lu\n",
                   FileName,
                   DesiredAccess,
                   HandleToULong(PsGetCurrentProcessId()));

        FipLeaveOperation();
        return FiThreat_EspModification;
    }

    //
    // Check for BCD modification specifically
    //
    UNICODE_STRING BcdPath = RTL_CONSTANT_STRING(L"\\Boot\\BCD");
    if (FileName->Length >= BcdPath.Length) {
        UNICODE_STRING Suffix;
        Suffix.Buffer = FileName->Buffer +
            (FileName->Length - BcdPath.Length) / sizeof(WCHAR);
        Suffix.Length = BcdPath.Length;
        Suffix.MaximumLength = BcdPath.Length;

        if (RtlEqualUnicodeString(&Suffix, &BcdPath, TRUE)) {
            InterlockedIncrement64(&g_FiState.Stats.BcdModificationsDetected);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/FI] BCD access detected: %wZ\n",
                       FileName);
        }
    }

    FipLeaveOperation();
    return FiThreat_None;
}

// ============================================================================
// BOOT INTEGRITY VERIFICATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
FI_BOOT_STATUS
FiVerifyBootIntegrity(VOID)
{
    FI_BOOT_STATUS Status;

    PAGED_CODE();

    if (!FipEnterOperation()) {
        return FiBoot_Unknown;
    }

    InterlockedIncrement64(&g_FiState.Stats.IntegrityChecks);

    Status = FipQuerySecureBootState();
    g_FiState.BootStatus = Status;
    g_FiState.Stats.CurrentBootStatus = Status;

    FipLeaveOperation();
    return Status;
}

// ============================================================================
// QUERY
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
FiGetStatistics(
    _Out_ PFI_STATISTICS Statistics
    )
{
    RtlCopyMemory(Statistics, &g_FiState.Stats, sizeof(FI_STATISTICS));
}

// ============================================================================
// PRIVATE — SECURE BOOT QUERY
// ============================================================================

static FI_BOOT_STATUS
FipQuerySecureBootState(VOID)
{
    NTSTATUS Status;
    UNICODE_STRING VariableName = RTL_CONSTANT_STRING(L"SecureBoot");
    UCHAR Value = 0;
    ULONG ResultLength = 0;

    //
    // Query the SecureBoot UEFI variable
    // On BIOS systems, this will fail — that's expected
    //
    Status = ExGetFirmwareEnvironmentVariable(
        &VariableName,
        (LPGUID)&EFI_GLOBAL_VARIABLE_GUID,
        &Value,
        &ResultLength,
        NULL
        );

    if (!NT_SUCCESS(Status)) {
        //
        // Failure could mean:
        // - Legacy BIOS (no UEFI variables)
        // - Insufficient privilege
        // - Variable doesn't exist
        //
        if (Status == STATUS_NOT_IMPLEMENTED ||
            Status == STATUS_NOT_SUPPORTED) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike/FI] UEFI not supported (Legacy BIOS)\n");
            return FiBoot_Unknown;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/FI] Failed to query SecureBoot variable: 0x%08X\n",
                   Status);
        return FiBoot_Unknown;
    }

    return (Value != 0) ? FiBoot_SecureBootEnabled : FiBoot_SecureBootDisabled;
}

// ============================================================================
// PRIVATE — ESP PATH DETECTION
// ============================================================================

static BOOLEAN
FipIsEspPath(
    _In_ PCUNICODE_STRING FileName
    )
{
    for (ULONG i = 0; i < FI_ESP_PATH_COUNT; i++) {
        //
        // Check if ESP path pattern appears anywhere in the filename
        //
        USHORT PathLen = FileName->Length / sizeof(WCHAR);
        USHORT PatternLen = g_EspPaths[i].Length / sizeof(WCHAR);

        if (PathLen >= PatternLen) {
            for (USHORT j = 0; j <= PathLen - PatternLen; j++) {
                UNICODE_STRING Sub;
                Sub.Buffer = &FileName->Buffer[j];
                Sub.Length = g_EspPaths[i].Length;
                Sub.MaximumLength = g_EspPaths[i].Length;

                if (RtlEqualUnicodeString(&Sub, &g_EspPaths[i], TRUE)) {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

// ============================================================================
// PRIVATE — LIFECYCLE
// ============================================================================

static BOOLEAN
FipEnterOperation(VOID)
{
    if (g_FiState.State != 2) return FALSE;
    return ExAcquireRundownProtection(&g_FiState.RundownRef);
}

static VOID
FipLeaveOperation(VOID)
{
    ExReleaseRundownProtection(&g_FiState.RundownRef);
}
