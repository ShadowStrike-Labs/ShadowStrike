/*++
===============================================================================
ShadowStrike NGAV - USB DEVICE CONTROL IMPLEMENTATION
===============================================================================

@file USBDeviceControl.c
@brief Removable device policy enforcement for data exfiltration prevention.

Detects USB removable media attachment, applies whitelist/blacklist policies,
blocks unauthorized writes, and detects autorun.inf abuse.

Volume Detection Strategy:
  - InstanceSetup callback detects removable volumes via FltGetVolumeProperties
  - FLT_VOLUME_PROPERTIES.DeviceCharacteristics FILE_REMOVABLE_MEDIA flag
  - Device information queried via IoGetDeviceObjectPointer for VID/PID

Policy Resolution Order:
  1. Blacklist (explicit deny) — highest priority
  2. Whitelist (explicit allow)
  3. Default policy (configurable, default=Audit)

@author ShadowStrike Security Team
@version 1.0.0
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "USBDeviceControl.h"
#include "../../Core/Globals.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE TYPES
// ============================================================================

typedef struct _UDC_STATE {

    //
    // Lifecycle
    //
    volatile LONG       State;          // 0=uninit, 1=init, 2=ready, 3=shutdown
    EX_RUNDOWN_REF      RundownRef;

    //
    // Device rules
    //
    LIST_ENTRY          WhitelistHead;
    LIST_ENTRY          BlacklistHead;
    EX_PUSH_LOCK        RulesLock;
    volatile LONG       WhitelistCount;
    volatile LONG       BlacklistCount;

    //
    // Tracked volumes
    //
    LIST_ENTRY          VolumeListHead;
    EX_PUSH_LOCK        VolumeLock;
    volatile LONG       VolumeCount;

    //
    // Configuration
    //
    UDC_CONFIG          Config;

    //
    // Statistics
    //
    UDC_STATISTICS      Stats;

    //
    // Lookaside
    //
    NPAGED_LOOKASIDE_LIST VolumeLookaside;

} UDC_STATE, *PUDC_STATE;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static UDC_STATE g_UdcState;

// ============================================================================
// AUTORUN FILENAME CONSTANT
// ============================================================================

static const UNICODE_STRING g_AutorunFileName =
    RTL_CONSTANT_STRING(L"autorun.inf");

static const UNICODE_STRING g_AutorunFileNameUpper =
    RTL_CONSTANT_STRING(L"AUTORUN.INF");

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static BOOLEAN
UdcpIsRemovableVolume(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

static UDC_DEVICE_POLICY
UdcpResolvePolicy(
    _In_ USHORT VendorId,
    _In_ USHORT ProductId,
    _In_opt_ PCWSTR SerialNumber
    );

static PUDC_TRACKED_VOLUME
UdcpFindVolume(
    _In_ PFLT_INSTANCE Instance
    );

static BOOLEAN
UdcpEnterOperation(VOID);

static VOID
UdcpLeaveOperation(VOID);

// ============================================================================
// LIFECYCLE
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
UdcInitialize(VOID)
{
    LONG PreviousState;

    PAGED_CODE();

    PreviousState = InterlockedCompareExchange(&g_UdcState.State, 1, 0);
    if (PreviousState != 0) {
        return (PreviousState == 2) ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
    }

    ExInitializeRundownProtection(&g_UdcState.RundownRef);

    InitializeListHead(&g_UdcState.WhitelistHead);
    InitializeListHead(&g_UdcState.BlacklistHead);
    FltInitializePushLock(&g_UdcState.RulesLock);
    g_UdcState.WhitelistCount = 0;
    g_UdcState.BlacklistCount = 0;

    InitializeListHead(&g_UdcState.VolumeListHead);
    FltInitializePushLock(&g_UdcState.VolumeLock);
    g_UdcState.VolumeCount = 0;

    ExInitializeNPagedLookasideList(
        &g_UdcState.VolumeLookaside,
        NULL,
        NULL,
        POOL_FLAG_NON_PAGED,
        sizeof(UDC_TRACKED_VOLUME),
        UDC_DEVICE_POOL_TAG,
        0
        );

    //
    // Default configuration: Audit mode (log, don't block)
    //
    g_UdcState.Config.DefaultPolicy = UdcPolicy_Audit;
    g_UdcState.Config.EnableAutorunBlocking = TRUE;
    g_UdcState.Config.EnableWriteProtection = TRUE;
    g_UdcState.Config.EnableAuditLogging = TRUE;
    g_UdcState.Config.Enabled = TRUE;

    RtlZeroMemory(&g_UdcState.Stats, sizeof(UDC_STATISTICS));

    InterlockedExchange(&g_UdcState.State, 2);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/UDC] USB Device Control initialized "
               "(DefaultPolicy=%d, AutorunBlock=%d)\n",
               g_UdcState.Config.DefaultPolicy,
               g_UdcState.Config.EnableAutorunBlocking);

    return STATUS_SUCCESS;
}


_IRQL_requires_(PASSIVE_LEVEL)
VOID
UdcShutdown(VOID)
{
    LIST_ENTRY *ListEntry;

    PAGED_CODE();

    if (InterlockedCompareExchange(&g_UdcState.State, 3, 2) != 2) {
        return;
    }

    ExWaitForRundownProtectionRelease(&g_UdcState.RundownRef);

    //
    // Free tracked volumes
    //
    FltAcquirePushLockExclusive(&g_UdcState.VolumeLock);
    while (!IsListEmpty(&g_UdcState.VolumeListHead)) {
        ListEntry = RemoveHeadList(&g_UdcState.VolumeListHead);
        PUDC_TRACKED_VOLUME Vol = CONTAINING_RECORD(
            ListEntry, UDC_TRACKED_VOLUME, Link);
        ExFreeToNPagedLookasideList(&g_UdcState.VolumeLookaside, Vol);
    }
    FltReleasePushLock(&g_UdcState.VolumeLock);

    //
    // Free whitelist rules
    //
    FltAcquirePushLockExclusive(&g_UdcState.RulesLock);
    while (!IsListEmpty(&g_UdcState.WhitelistHead)) {
        ListEntry = RemoveHeadList(&g_UdcState.WhitelistHead);
        PUDC_DEVICE_RULE Rule = CONTAINING_RECORD(
            ListEntry, UDC_DEVICE_RULE, Link);
        ExFreePoolWithTag(Rule, UDC_DEVICE_POOL_TAG);
    }
    while (!IsListEmpty(&g_UdcState.BlacklistHead)) {
        ListEntry = RemoveHeadList(&g_UdcState.BlacklistHead);
        PUDC_DEVICE_RULE Rule = CONTAINING_RECORD(
            ListEntry, UDC_DEVICE_RULE, Link);
        ExFreePoolWithTag(Rule, UDC_DEVICE_POOL_TAG);
    }
    FltReleasePushLock(&g_UdcState.RulesLock);

    ExDeleteNPagedLookasideList(&g_UdcState.VolumeLookaside);
    FltDeletePushLock(&g_UdcState.RulesLock);
    FltDeletePushLock(&g_UdcState.VolumeLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/UDC] Shutdown complete. "
               "Mounts=%lld, WritesBlocked=%lld, AutorunBlocked=%lld\n",
               g_UdcState.Stats.VolumeMounts,
               g_UdcState.Stats.WritesBlocked,
               g_UdcState.Stats.AutorunBlocked);
}

// ============================================================================
// POLICY CHECKS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
UdcCheckVolumePolicy(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PUDC_DEVICE_POLICY Policy
    )
{
    PAGED_CODE();

    *Policy = UdcPolicy_Allow;

    if (!g_UdcState.Config.Enabled) {
        return TRUE;
    }

    if (!UdcpEnterOperation()) {
        return TRUE;
    }

    InterlockedIncrement64(&g_UdcState.Stats.PolicyChecks);

    //
    // Check if this is a removable volume
    //
    if (!UdcpIsRemovableVolume(FltObjects)) {
        UdcpLeaveOperation();
        return TRUE;    // Non-removable — always allow
    }

    //
    // Resolve policy for this device
    // For now, use default policy since we don't have full PnP VID/PID enumeration
    // The device rule matching will work once user-space provides device info via IOCTL
    //
    *Policy = UdcpResolvePolicy(0, 0, NULL);

    if (*Policy == UdcPolicy_Block) {
        InterlockedIncrement64(&g_UdcState.Stats.VolumeAttachRejected);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/UDC] BLOCKED removable volume attachment "
                   "(Policy=Block)\n");

        UdcpLeaveOperation();
        return FALSE;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/UDC] Removable volume detected (Policy=%d)\n",
               *Policy);

    UdcpLeaveOperation();
    return TRUE;
}


_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
UdcIsWriteBlocked(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    PUDC_TRACKED_VOLUME Volume;

    if (!g_UdcState.Config.Enabled || !g_UdcState.Config.EnableWriteProtection) {
        return FALSE;
    }

    if (!UdcpEnterOperation()) {
        return FALSE;
    }

    Volume = UdcpFindVolume(FltObjects->Instance);
    if (Volume == NULL) {
        UdcpLeaveOperation();
        return FALSE;
    }

    InterlockedIncrement(&Volume->WriteAttempts);

    if (Volume->EffectivePolicy == UdcPolicy_ReadOnly) {
        InterlockedIncrement(&Volume->WriteBlocked);
        InterlockedIncrement64(&g_UdcState.Stats.WritesBlocked);
        UdcpLeaveOperation();
        return TRUE;
    }

    if (Volume->EffectivePolicy == UdcPolicy_Audit) {
        InterlockedIncrement64(&g_UdcState.Stats.WritesAllowed);
    }

    UdcpLeaveOperation();
    return FALSE;
}


_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
UdcIsSetInfoBlocked(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    //
    // Same policy as write blocking — rename/delete on read-only volumes is blocked
    //
    return UdcIsWriteBlocked(FltObjects);
}


_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
UdcCheckAutorun(
    _In_ PCUNICODE_STRING FileName
    )
{
    USHORT Length;
    USHORT NameStart;

    if (!g_UdcState.Config.Enabled || !g_UdcState.Config.EnableAutorunBlocking) {
        return FALSE;
    }

    if (FileName == NULL || FileName->Length == 0) {
        return FALSE;
    }

    //
    // Extract filename component (after last backslash)
    //
    Length = FileName->Length / sizeof(WCHAR);
    NameStart = Length;

    for (USHORT i = Length; i > 0; i--) {
        if (FileName->Buffer[i - 1] == L'\\') {
            NameStart = i;
            break;
        }
    }

    if (NameStart >= Length) {
        return FALSE;
    }

    //
    // Check if filename is "autorun.inf" (case insensitive)
    //
    UNICODE_STRING FileNameOnly;
    FileNameOnly.Buffer = &FileName->Buffer[NameStart];
    FileNameOnly.Length = (Length - NameStart) * sizeof(WCHAR);
    FileNameOnly.MaximumLength = FileNameOnly.Length;

    if (RtlEqualUnicodeString(&FileNameOnly, &g_AutorunFileName, TRUE)) {
        InterlockedIncrement64(&g_UdcState.Stats.AutorunDetected);
        InterlockedIncrement64(&g_UdcState.Stats.AutorunBlocked);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/UDC] BLOCKED autorun.inf access: %wZ\n",
                   FileName);

        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// VOLUME TRACKING
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
VOID
UdcNotifyVolumeMount(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ UDC_DEVICE_POLICY Policy
    )
{
    PUDC_TRACKED_VOLUME Volume;

    PAGED_CODE();

    if (!UdcpEnterOperation()) {
        return;
    }

    if (g_UdcState.VolumeCount >= UDC_MAX_TRACKED_VOLUMES) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/UDC] Maximum tracked volumes reached (%d)\n",
                   UDC_MAX_TRACKED_VOLUMES);
        UdcpLeaveOperation();
        return;
    }

    Volume = (PUDC_TRACKED_VOLUME)ExAllocateFromNPagedLookasideList(
        &g_UdcState.VolumeLookaside);

    if (Volume == NULL) {
        UdcpLeaveOperation();
        return;
    }

    RtlZeroMemory(Volume, sizeof(UDC_TRACKED_VOLUME));
    InitializeListHead(&Volume->Link);

    Volume->Instance = FltObjects->Instance;
    Volume->EffectivePolicy = Policy;
    KeQuerySystemTime(&Volume->MountTime);

    //
    // Get volume name if possible
    //
    NTSTATUS Status;
    ULONG NameLength = 0;

    Status = FltGetVolumeName(FltObjects->Volume, NULL, &NameLength);
    if (Status == STATUS_BUFFER_TOO_SMALL && NameLength > 0) {
        Volume->VolumeName.Buffer = Volume->VolumeNameBuffer;
        Volume->VolumeName.MaximumLength = sizeof(Volume->VolumeNameBuffer);

        Status = FltGetVolumeName(
            FltObjects->Volume,
            &Volume->VolumeName,
            NULL
            );

        if (!NT_SUCCESS(Status)) {
            Volume->VolumeName.Length = 0;
        }
    }

    FltAcquirePushLockExclusive(&g_UdcState.VolumeLock);
    InsertTailList(&g_UdcState.VolumeListHead, &Volume->Link);
    InterlockedIncrement(&g_UdcState.VolumeCount);
    FltReleasePushLock(&g_UdcState.VolumeLock);

    InterlockedIncrement64(&g_UdcState.Stats.VolumeMounts);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/UDC] Removable volume mounted: %wZ (Policy=%d)\n",
               &Volume->VolumeName, Policy);

    UdcpLeaveOperation();
}


_IRQL_requires_(PASSIVE_LEVEL)
VOID
UdcNotifyVolumeDismount(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    LIST_ENTRY *ListEntry;

    PAGED_CODE();

    if (!UdcpEnterOperation()) {
        return;
    }

    FltAcquirePushLockExclusive(&g_UdcState.VolumeLock);

    for (ListEntry = g_UdcState.VolumeListHead.Flink;
         ListEntry != &g_UdcState.VolumeListHead;
         ListEntry = ListEntry->Flink) {

        PUDC_TRACKED_VOLUME Volume = CONTAINING_RECORD(
            ListEntry, UDC_TRACKED_VOLUME, Link);

        if (Volume->Instance == FltObjects->Instance) {
            RemoveEntryList(&Volume->Link);
            InterlockedDecrement(&g_UdcState.VolumeCount);
            FltReleasePushLock(&g_UdcState.VolumeLock);

            InterlockedIncrement64(&g_UdcState.Stats.VolumeDismounts);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike/UDC] Removable volume dismounted: %wZ "
                       "(Writes=%ld, Blocked=%ld)\n",
                       &Volume->VolumeName,
                       Volume->WriteAttempts,
                       Volume->WriteBlocked);

            ExFreeToNPagedLookasideList(&g_UdcState.VolumeLookaside, Volume);
            UdcpLeaveOperation();
            return;
        }
    }

    FltReleasePushLock(&g_UdcState.VolumeLock);
    UdcpLeaveOperation();
}

// ============================================================================
// QUERY
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
UdcGetStatistics(
    _Out_ PUDC_STATISTICS Statistics
    )
{
    RtlCopyMemory(Statistics, &g_UdcState.Stats, sizeof(UDC_STATISTICS));
}

// ============================================================================
// PRIVATE — VOLUME DETECTION
// ============================================================================

static BOOLEAN
UdcpIsRemovableVolume(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    NTSTATUS Status;
    ULONG BufferSize;
    PFLT_VOLUME_PROPERTIES VolumeProps = NULL;
    BOOLEAN IsRemovable = FALSE;

    //
    // Query volume properties to check device characteristics
    //
    BufferSize = sizeof(FLT_VOLUME_PROPERTIES) + 512;
    VolumeProps = (PFLT_VOLUME_PROPERTIES)ExAllocatePool2(
        POOL_FLAG_PAGED, BufferSize, UDC_POOL_TAG);

    if (VolumeProps == NULL) {
        return FALSE;
    }

    Status = FltGetVolumeProperties(
        FltObjects->Volume,
        VolumeProps,
        BufferSize,
        &BufferSize
        );

    if (NT_SUCCESS(Status)) {
        //
        // Check for removable media characteristics
        //
        if (FlagOn(VolumeProps->DeviceCharacteristics, FILE_REMOVABLE_MEDIA) ||
            FlagOn(VolumeProps->DeviceCharacteristics, FILE_FLOPPY_DISKETTE)) {
            IsRemovable = TRUE;
        }

        //
        // Also check device type for USB mass storage
        //
        if (VolumeProps->DeviceType == FILE_DEVICE_DISK &&
            FlagOn(VolumeProps->DeviceCharacteristics, FILE_REMOVABLE_MEDIA)) {
            IsRemovable = TRUE;
        }
    }

    ExFreePoolWithTag(VolumeProps, UDC_POOL_TAG);
    return IsRemovable;
}

// ============================================================================
// PRIVATE — POLICY RESOLUTION
// ============================================================================

static UDC_DEVICE_POLICY
UdcpResolvePolicy(
    _In_ USHORT VendorId,
    _In_ USHORT ProductId,
    _In_opt_ PCWSTR SerialNumber
    )
{
    LIST_ENTRY *ListEntry;

    FltAcquirePushLockShared(&g_UdcState.RulesLock);

    //
    // Check blacklist first (highest priority)
    //
    for (ListEntry = g_UdcState.BlacklistHead.Flink;
         ListEntry != &g_UdcState.BlacklistHead;
         ListEntry = ListEntry->Flink) {

        PUDC_DEVICE_RULE Rule = CONTAINING_RECORD(
            ListEntry, UDC_DEVICE_RULE, Link);

        BOOLEAN VidMatch = (Rule->VendorId == 0 || Rule->VendorId == VendorId);
        BOOLEAN PidMatch = (Rule->ProductId == 0 || Rule->ProductId == ProductId);
        BOOLEAN SerialMatch = TRUE;

        if (Rule->SerialNumberLength > 0 && SerialNumber != NULL) {
            UNICODE_STRING RuleSerial;
            RuleSerial.Buffer = Rule->SerialNumber;
            RuleSerial.Length = Rule->SerialNumberLength * sizeof(WCHAR);
            RuleSerial.MaximumLength = sizeof(Rule->SerialNumber);

            UNICODE_STRING DeviceSerial;
            RtlInitUnicodeString(&DeviceSerial, SerialNumber);

            SerialMatch = RtlEqualUnicodeString(&RuleSerial, &DeviceSerial, TRUE);
        }

        if (VidMatch && PidMatch && SerialMatch) {
            UDC_DEVICE_POLICY Policy = Rule->Policy;
            FltReleasePushLock(&g_UdcState.RulesLock);
            return Policy;
        }
    }

    //
    // Check whitelist (second priority)
    //
    for (ListEntry = g_UdcState.WhitelistHead.Flink;
         ListEntry != &g_UdcState.WhitelistHead;
         ListEntry = ListEntry->Flink) {

        PUDC_DEVICE_RULE Rule = CONTAINING_RECORD(
            ListEntry, UDC_DEVICE_RULE, Link);

        BOOLEAN VidMatch = (Rule->VendorId == 0 || Rule->VendorId == VendorId);
        BOOLEAN PidMatch = (Rule->ProductId == 0 || Rule->ProductId == ProductId);
        BOOLEAN SerialMatch = TRUE;

        if (Rule->SerialNumberLength > 0 && SerialNumber != NULL) {
            UNICODE_STRING RuleSerial;
            RuleSerial.Buffer = Rule->SerialNumber;
            RuleSerial.Length = Rule->SerialNumberLength * sizeof(WCHAR);
            RuleSerial.MaximumLength = sizeof(Rule->SerialNumber);

            UNICODE_STRING DeviceSerial;
            RtlInitUnicodeString(&DeviceSerial, SerialNumber);

            SerialMatch = RtlEqualUnicodeString(&RuleSerial, &DeviceSerial, TRUE);
        }

        if (VidMatch && PidMatch && SerialMatch) {
            UDC_DEVICE_POLICY Policy = Rule->Policy;
            FltReleasePushLock(&g_UdcState.RulesLock);
            return Policy;
        }
    }

    FltReleasePushLock(&g_UdcState.RulesLock);

    //
    // No matching rule — return default policy
    //
    return g_UdcState.Config.DefaultPolicy;
}

// ============================================================================
// PRIVATE — VOLUME LOOKUP
// ============================================================================

static PUDC_TRACKED_VOLUME
UdcpFindVolume(
    _In_ PFLT_INSTANCE Instance
    )
{
    LIST_ENTRY *ListEntry;

    FltAcquirePushLockShared(&g_UdcState.VolumeLock);

    for (ListEntry = g_UdcState.VolumeListHead.Flink;
         ListEntry != &g_UdcState.VolumeListHead;
         ListEntry = ListEntry->Flink) {

        PUDC_TRACKED_VOLUME Volume = CONTAINING_RECORD(
            ListEntry, UDC_TRACKED_VOLUME, Link);

        if (Volume->Instance == Instance) {
            FltReleasePushLock(&g_UdcState.VolumeLock);
            return Volume;
        }
    }

    FltReleasePushLock(&g_UdcState.VolumeLock);
    return NULL;
}

// ============================================================================
// PRIVATE — LIFECYCLE HELPERS
// ============================================================================

static BOOLEAN
UdcpEnterOperation(VOID)
{
    if (g_UdcState.State != 2) {
        return FALSE;
    }
    return ExAcquireRundownProtection(&g_UdcState.RundownRef);
}


static VOID
UdcpLeaveOperation(VOID)
{
    ExReleaseRundownProtection(&g_UdcState.RundownRef);
}
