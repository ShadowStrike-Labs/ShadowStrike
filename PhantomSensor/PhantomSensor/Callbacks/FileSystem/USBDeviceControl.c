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
  - Device VID/PID/Serial extracted via IOCTL_STORAGE_QUERY_PROPERTY
  - Hardware ID parsed from physical device object for USB VID_xxxx/PID_xxxx

Policy Resolution Order:
  1. Blacklist (explicit deny) — highest priority
  2. Whitelist (explicit allow)
  3. Default policy (configurable, default=Audit)

@author ShadowStrike Security Team
@version 2.0.0
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "USBDeviceControl.h"
#include "../../Core/Globals.h"
#include <ntstrsafe.h>
#include <ntddstor.h>

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
    volatile LONG       NextRuleId;

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
// CONSTANTS
// ============================================================================

static const UNICODE_STRING g_AutorunFileName =
    RTL_CONSTANT_STRING(L"autorun.inf");

#define UDC_STORAGE_QUERY_BUFFER_SIZE   1024
#define UDC_HARDWARE_ID_BUFFER_SIZE     512

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
    _In_opt_ PCWSTR SerialNumber,
    _In_ UDC_DEVICE_CLASS DeviceClass
    );

static PUDC_TRACKED_VOLUME
UdcpFindVolumeUnlocked(
    _In_ PFLT_INSTANCE Instance
    );

static BOOLEAN
UdcpEnterOperation(VOID);

static VOID
UdcpLeaveOperation(VOID);

static NTSTATUS
UdcpQueryDeviceInfo(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PUSHORT VendorId,
    _Out_ PUSHORT ProductId,
    _Out_writes_(UDC_SERIAL_MAX_LENGTH) PWCHAR SerialNumber,
    _Out_ PUSHORT SerialLength,
    _Out_ PUDC_DEVICE_CLASS DeviceClass
    );

static NTSTATUS
UdcpSendStorageQuery(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PSTORAGE_DEVICE_DESCRIPTOR *Descriptor
    );

static PDEVICE_OBJECT
UdcpGetPhysicalDeviceObject(
    _In_ PDEVICE_OBJECT DeviceObject
    );

static VOID
UdcpParseHardwareIdForVidPid(
    _In_reads_bytes_(LengthInBytes) PCWSTR HardwareId,
    _In_ ULONG LengthInBytes,
    _Out_ PUSHORT VendorId,
    _Out_ PUSHORT ProductId
    );

static USHORT
UdcpParseHex4(
    _In_reads_(AvailableChars) PCWSTR Str,
    _In_ ULONG AvailableChars
    );

// ============================================================================
// ALLOC_TEXT
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, UdcInitialize)
#pragma alloc_text(PAGE, UdcShutdown)
#pragma alloc_text(PAGE, UdcCheckVolumePolicy)
#pragma alloc_text(PAGE, UdcNotifyVolumeMount)
#pragma alloc_text(PAGE, UdcNotifyVolumeDismount)
#pragma alloc_text(PAGE, UdcAddRule)
#pragma alloc_text(PAGE, UdcRemoveRule)
#pragma alloc_text(PAGE, UdcClearRules)
#pragma alloc_text(PAGE, UdcUpdateConfig)
#pragma alloc_text(PAGE, UdcpIsRemovableVolume)
#pragma alloc_text(PAGE, UdcpQueryDeviceInfo)
#pragma alloc_text(PAGE, UdcpSendStorageQuery)
#pragma alloc_text(PAGE, UdcpGetPhysicalDeviceObject)
#endif

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
    g_UdcState.NextRuleId = 1;

    InitializeListHead(&g_UdcState.VolumeListHead);
    FltInitializePushLock(&g_UdcState.VolumeLock);
    g_UdcState.VolumeCount = 0;

    //
    // UDC-5 FIX: Use 0 for Flags — NPagedPool is already non-executable
    // since Windows 8+. POOL_FLAG_NON_PAGED (0x40) is for ExAllocatePool2,
    // NOT for ExInitializeNPagedLookasideList.
    //
    ExInitializeNPagedLookasideList(
        &g_UdcState.VolumeLookaside,
        NULL,
        NULL,
        0,
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
    // Free all rules
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
    USHORT VendorId = 0;
    USHORT ProductId = 0;
    WCHAR SerialNumber[UDC_SERIAL_MAX_LENGTH];
    USHORT SerialLength = 0;
    UDC_DEVICE_CLASS DeviceClass = UdcClass_Unknown;

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
    // UDC-4 FIX: Extract actual device information from storage stack
    //
    RtlZeroMemory(SerialNumber, sizeof(SerialNumber));

    NTSTATUS InfoStatus = UdcpQueryDeviceInfo(
        FltObjects,
        &VendorId,
        &ProductId,
        SerialNumber,
        &SerialLength,
        &DeviceClass
        );

    if (!NT_SUCCESS(InfoStatus)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike/UDC] Device info query returned 0x%08X, "
                   "applying default policy\n", InfoStatus);
    }

    //
    // Resolve policy using device identity against whitelist/blacklist
    //
    *Policy = UdcpResolvePolicy(
        VendorId,
        ProductId,
        (SerialLength > 0) ? SerialNumber : NULL,
        DeviceClass
        );

    if (*Policy == UdcPolicy_Block) {
        InterlockedIncrement64(&g_UdcState.Stats.VolumeAttachRejected);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/UDC] BLOCKED removable volume attachment "
                   "(VID=0x%04X, PID=0x%04X, Policy=Block)\n",
                   VendorId, ProductId);

        UdcpLeaveOperation();
        return FALSE;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/UDC] Removable volume detected "
               "(VID=0x%04X, PID=0x%04X, Policy=%d)\n",
               VendorId, ProductId, *Policy);

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
    BOOLEAN Blocked = FALSE;

    if (!g_UdcState.Config.Enabled || !g_UdcState.Config.EnableWriteProtection) {
        return FALSE;
    }

    if (!UdcpEnterOperation()) {
        return FALSE;
    }

    //
    // UDC-1 FIX: Hold VolumeLock shared for the entire operation to prevent
    // use-after-free from concurrent UdcNotifyVolumeDismount. The old code
    // released the lock inside UdcpFindVolume then dereferenced the returned
    // pointer — a classic TOCTOU leading to BSOD.
    //
    FltAcquirePushLockShared(&g_UdcState.VolumeLock);

    Volume = UdcpFindVolumeUnlocked(FltObjects->Instance);
    if (Volume != NULL) {
        InterlockedIncrement(&Volume->WriteAttempts);

        if (Volume->EffectivePolicy == UdcPolicy_ReadOnly) {
            InterlockedIncrement(&Volume->WriteBlocked);
            InterlockedIncrement64(&g_UdcState.Stats.WritesBlocked);
            Blocked = TRUE;
        } else if (Volume->EffectivePolicy == UdcPolicy_Audit) {
            InterlockedIncrement64(&g_UdcState.Stats.WritesAllowed);
        }
    }

    FltReleasePushLock(&g_UdcState.VolumeLock);

    UdcpLeaveOperation();
    return Blocked;
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
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName
    )
{
    USHORT Length;
    USHORT NameStart;
    PUDC_TRACKED_VOLUME Volume;
    BOOLEAN Result = FALSE;

    if (!g_UdcState.Config.Enabled || !g_UdcState.Config.EnableAutorunBlocking) {
        return FALSE;
    }

    if (FileName == NULL || FileName->Length == 0 || FileName->Buffer == NULL) {
        return FALSE;
    }

    //
    // UDC-9 FIX: Acquire rundown protection to prevent access during shutdown
    //
    if (!UdcpEnterOperation()) {
        return FALSE;
    }

    //
    // UDC-7 FIX: Only block autorun.inf on tracked removable volumes.
    // Hold lock for the entire check to prevent use-after-free on Volume.
    //
    FltAcquirePushLockShared(&g_UdcState.VolumeLock);

    Volume = UdcpFindVolumeUnlocked(FltObjects->Instance);
    if (Volume == NULL) {
        FltReleasePushLock(&g_UdcState.VolumeLock);
        UdcpLeaveOperation();
        return FALSE;   // Not a tracked removable volume
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

    if (NameStart < Length) {
        UNICODE_STRING FileNameOnly;
        FileNameOnly.Buffer = &FileName->Buffer[NameStart];
        FileNameOnly.Length = (Length - NameStart) * sizeof(WCHAR);
        FileNameOnly.MaximumLength = FileNameOnly.Length;

        if (RtlEqualUnicodeString(&FileNameOnly, &g_AutorunFileName, TRUE)) {
            InterlockedIncrement64(&g_UdcState.Stats.AutorunDetected);
            InterlockedIncrement64(&g_UdcState.Stats.AutorunBlocked);
            InterlockedIncrement(&Volume->FilesAccessed);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/UDC] BLOCKED autorun.inf access: %wZ\n",
                       FileName);

            Result = TRUE;
        }
    }

    FltReleasePushLock(&g_UdcState.VolumeLock);
    UdcpLeaveOperation();
    return Result;
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
    if (Status == STATUS_BUFFER_TOO_SMALL &&
        NameLength > 0 &&
        NameLength <= sizeof(Volume->VolumeNameBuffer)) {

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

    //
    // UDC-4 FIX: Query device VID/PID/Serial for the tracking record
    //
    USHORT SerialLength = 0;
    UDC_DEVICE_CLASS DeviceClass = UdcClass_Unknown;

    UdcpQueryDeviceInfo(
        FltObjects,
        &Volume->VendorId,
        &Volume->ProductId,
        Volume->SerialNumber,
        &SerialLength,
        &DeviceClass
        );

    Volume->DeviceClass = DeviceClass;

    FltAcquirePushLockExclusive(&g_UdcState.VolumeLock);
    InsertTailList(&g_UdcState.VolumeListHead, &Volume->Link);
    InterlockedIncrement(&g_UdcState.VolumeCount);
    FltReleasePushLock(&g_UdcState.VolumeLock);

    InterlockedIncrement64(&g_UdcState.Stats.VolumeMounts);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/UDC] Removable volume mounted: %wZ "
               "(VID=0x%04X, PID=0x%04X, Policy=%d)\n",
               &Volume->VolumeName,
               Volume->VendorId, Volume->ProductId, Policy);

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
// RULE MANAGEMENT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
UdcAddRule(
    _In_ BOOLEAN IsBlacklist,
    _In_ USHORT VendorId,
    _In_ USHORT ProductId,
    _In_opt_ PCWSTR SerialNumber,
    _In_ UDC_DEVICE_CLASS DeviceClass,
    _In_ UDC_DEVICE_POLICY Policy,
    _Out_ PULONG RuleId
    )
{
    PUDC_DEVICE_RULE Rule;
    PLIST_ENTRY TargetList;
    volatile LONG *TargetCount;
    LONG MaxEntries;

    PAGED_CODE();

    if (RuleId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *RuleId = 0;

    if (!UdcpEnterOperation()) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (IsBlacklist) {
        TargetList = &g_UdcState.BlacklistHead;
        TargetCount = &g_UdcState.BlacklistCount;
        MaxEntries = UDC_MAX_BLACKLIST_ENTRIES;
    } else {
        TargetList = &g_UdcState.WhitelistHead;
        TargetCount = &g_UdcState.WhitelistCount;
        MaxEntries = UDC_MAX_WHITELIST_ENTRIES;
    }

    if (*TargetCount >= MaxEntries) {
        UdcpLeaveOperation();
        return STATUS_QUOTA_EXCEEDED;
    }

    Rule = (PUDC_DEVICE_RULE)ExAllocatePool2(
        POOL_FLAG_PAGED, sizeof(UDC_DEVICE_RULE), UDC_DEVICE_POOL_TAG);

    if (Rule == NULL) {
        UdcpLeaveOperation();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Rule, sizeof(UDC_DEVICE_RULE));
    InitializeListHead(&Rule->Link);

    Rule->VendorId = VendorId;
    Rule->ProductId = ProductId;
    Rule->DeviceClass = DeviceClass;
    Rule->Policy = Policy;
    Rule->RuleId = (ULONG)InterlockedIncrement(&g_UdcState.NextRuleId);
    KeQuerySystemTime(&Rule->CreatedTime);

    if (SerialNumber != NULL) {
        size_t SerialLen = 0;

        NTSTATUS CopyStatus = RtlStringCchLengthW(
            SerialNumber,
            UDC_SERIAL_MAX_LENGTH - 1,
            &SerialLen
            );

        if (NT_SUCCESS(CopyStatus) && SerialLen > 0) {
            RtlCopyMemory(Rule->SerialNumber, SerialNumber,
                         SerialLen * sizeof(WCHAR));
            Rule->SerialNumber[SerialLen] = L'\0';
            Rule->SerialNumberLength = (USHORT)SerialLen;
        }
    }

    FltAcquirePushLockExclusive(&g_UdcState.RulesLock);
    InsertTailList(TargetList, &Rule->Link);
    InterlockedIncrement(TargetCount);
    FltReleasePushLock(&g_UdcState.RulesLock);

    *RuleId = Rule->RuleId;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/UDC] Rule added: ID=%lu, %s, VID=0x%04X, "
               "PID=0x%04X, Policy=%d\n",
               Rule->RuleId,
               IsBlacklist ? "BLACKLIST" : "WHITELIST",
               VendorId, ProductId, Policy);

    UdcpLeaveOperation();
    return STATUS_SUCCESS;
}


_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
UdcRemoveRule(
    _In_ ULONG RuleId
    )
{
    LIST_ENTRY *ListEntry;
    BOOLEAN Found = FALSE;

    PAGED_CODE();

    if (RuleId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!UdcpEnterOperation()) {
        return STATUS_DEVICE_NOT_READY;
    }

    FltAcquirePushLockExclusive(&g_UdcState.RulesLock);

    //
    // Search blacklist
    //
    for (ListEntry = g_UdcState.BlacklistHead.Flink;
         ListEntry != &g_UdcState.BlacklistHead;
         ListEntry = ListEntry->Flink) {

        PUDC_DEVICE_RULE Rule = CONTAINING_RECORD(
            ListEntry, UDC_DEVICE_RULE, Link);

        if (Rule->RuleId == RuleId) {
            RemoveEntryList(&Rule->Link);
            InterlockedDecrement(&g_UdcState.BlacklistCount);
            FltReleasePushLock(&g_UdcState.RulesLock);
            ExFreePoolWithTag(Rule, UDC_DEVICE_POOL_TAG);
            Found = TRUE;
            goto Done;
        }
    }

    //
    // Search whitelist
    //
    for (ListEntry = g_UdcState.WhitelistHead.Flink;
         ListEntry != &g_UdcState.WhitelistHead;
         ListEntry = ListEntry->Flink) {

        PUDC_DEVICE_RULE Rule = CONTAINING_RECORD(
            ListEntry, UDC_DEVICE_RULE, Link);

        if (Rule->RuleId == RuleId) {
            RemoveEntryList(&Rule->Link);
            InterlockedDecrement(&g_UdcState.WhitelistCount);
            FltReleasePushLock(&g_UdcState.RulesLock);
            ExFreePoolWithTag(Rule, UDC_DEVICE_POOL_TAG);
            Found = TRUE;
            goto Done;
        }
    }

    FltReleasePushLock(&g_UdcState.RulesLock);

Done:
    UdcpLeaveOperation();
    return Found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}


_IRQL_requires_(PASSIVE_LEVEL)
VOID
UdcClearRules(VOID)
{
    LIST_ENTRY *ListEntry;

    PAGED_CODE();

    if (!UdcpEnterOperation()) {
        return;
    }

    FltAcquirePushLockExclusive(&g_UdcState.RulesLock);

    while (!IsListEmpty(&g_UdcState.WhitelistHead)) {
        ListEntry = RemoveHeadList(&g_UdcState.WhitelistHead);
        PUDC_DEVICE_RULE Rule = CONTAINING_RECORD(
            ListEntry, UDC_DEVICE_RULE, Link);
        ExFreePoolWithTag(Rule, UDC_DEVICE_POOL_TAG);
    }
    g_UdcState.WhitelistCount = 0;

    while (!IsListEmpty(&g_UdcState.BlacklistHead)) {
        ListEntry = RemoveHeadList(&g_UdcState.BlacklistHead);
        PUDC_DEVICE_RULE Rule = CONTAINING_RECORD(
            ListEntry, UDC_DEVICE_RULE, Link);
        ExFreePoolWithTag(Rule, UDC_DEVICE_POOL_TAG);
    }
    g_UdcState.BlacklistCount = 0;

    FltReleasePushLock(&g_UdcState.RulesLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/UDC] All rules cleared\n");

    UdcpLeaveOperation();
}


_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
UdcUpdateConfig(
    _In_ PUDC_CONFIG NewConfig
    )
{
    PAGED_CODE();

    if (NewConfig == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!UdcpEnterOperation()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Copy config under rules lock for consistency with policy resolution.
    // Config fields are small (BOOLEANs + enum), so the critical section
    // is extremely short.
    //
    FltAcquirePushLockExclusive(&g_UdcState.RulesLock);
    RtlCopyMemory(&g_UdcState.Config, NewConfig, sizeof(UDC_CONFIG));
    FltReleasePushLock(&g_UdcState.RulesLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/UDC] Config updated: Enabled=%d, "
               "DefaultPolicy=%d, WriteProtect=%d, AutorunBlock=%d\n",
               NewConfig->Enabled,
               NewConfig->DefaultPolicy,
               NewConfig->EnableWriteProtection,
               NewConfig->EnableAutorunBlocking);

    UdcpLeaveOperation();
    return STATUS_SUCCESS;
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
    //
    // On x64, aligned LONG64 reads are atomic. Snapshot each field
    // individually rather than RtlCopyMemory to avoid torn reads on
    // 32-bit builds.
    //
    Statistics->VolumeMounts = g_UdcState.Stats.VolumeMounts;
    Statistics->VolumeDismounts = g_UdcState.Stats.VolumeDismounts;
    Statistics->WritesBlocked = g_UdcState.Stats.WritesBlocked;
    Statistics->WritesAllowed = g_UdcState.Stats.WritesAllowed;
    Statistics->VolumeAttachRejected = g_UdcState.Stats.VolumeAttachRejected;
    Statistics->AutorunDetected = g_UdcState.Stats.AutorunDetected;
    Statistics->AutorunBlocked = g_UdcState.Stats.AutorunBlocked;
    Statistics->PolicyChecks = g_UdcState.Stats.PolicyChecks;
}

// ============================================================================
// PRIVATE — DEVICE INFORMATION EXTRACTION
// ============================================================================

/*++
    Queries the storage stack for USB device identity information.

    Step 1: FltGetDiskDeviceObject → disk device for this volume
    Step 2: IOCTL_STORAGE_QUERY_PROPERTY → STORAGE_DEVICE_DESCRIPTOR
            → BusType, serial number (ASCII → Unicode)
    Step 3: Walk device stack to PDO → IoGetDeviceProperty(HardwareID)
            → Parse VID_xxxx&PID_xxxx for numeric USB VID/PID

    All steps are best-effort: failure at any stage leaves the
    corresponding output fields at zero/empty. This ensures devices
    that don't support certain queries still get the default policy.
--*/
static NTSTATUS
UdcpQueryDeviceInfo(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PUSHORT VendorId,
    _Out_ PUSHORT ProductId,
    _Out_writes_(UDC_SERIAL_MAX_LENGTH) PWCHAR SerialNumber,
    _Out_ PUSHORT SerialLength,
    _Out_ PUDC_DEVICE_CLASS DeviceClass
    )
{
    NTSTATUS Status;
    PDEVICE_OBJECT DiskDevice = NULL;
    PSTORAGE_DEVICE_DESCRIPTOR Descriptor = NULL;
    PDEVICE_OBJECT PhysicalDevice = NULL;

    PAGED_CODE();

    *VendorId = 0;
    *ProductId = 0;
    *SerialLength = 0;
    *DeviceClass = UdcClass_MassStorage;    // Default for removable

    Status = FltGetDiskDeviceObject(FltObjects->Volume, &DiskDevice);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Step 1: Query STORAGE_DEVICE_DESCRIPTOR for bus type and serial
    //
    Status = UdcpSendStorageQuery(DiskDevice, &Descriptor);
    if (NT_SUCCESS(Status) && Descriptor != NULL) {

        //
        // Classify device by bus type
        //
        switch (Descriptor->BusType) {
            case BusTypeUsb:
                *DeviceClass = UdcClass_MassStorage;
                break;

            case BusTypeScsi:
            case BusTypeAta:
            case BusTypeSata:
                *DeviceClass = UdcClass_MassStorage;
                break;

            default:
                if (Descriptor->RemovableMedia) {
                    *DeviceClass = UdcClass_MassStorage;
                } else {
                    *DeviceClass = UdcClass_Other;
                }
                break;
        }

        //
        // Extract serial number (ASCII → Unicode)
        // Storage firmware often pads serial strings with whitespace
        //
        if (Descriptor->SerialNumberOffset != 0 &&
            Descriptor->SerialNumberOffset < Descriptor->Size) {

            PCSTR AsciiSerial = (PCSTR)((PUCHAR)Descriptor +
                                        Descriptor->SerialNumberOffset);

            //
            // Validate the ASCII string stays within descriptor bounds
            //
            ULONG MaxLen = Descriptor->Size - Descriptor->SerialNumberOffset;
            ULONG AsciiLen = 0;

            while (AsciiLen < MaxLen && AsciiSerial[AsciiLen] != '\0') {
                AsciiLen++;
            }

            //
            // Trim leading and trailing whitespace
            //
            ULONG Start = 0;
            while (Start < AsciiLen && AsciiSerial[Start] == ' ') {
                Start++;
            }

            ULONG End = AsciiLen;
            while (End > Start && AsciiSerial[End - 1] == ' ') {
                End--;
            }

            ULONG TrimmedLen = End - Start;
            if (TrimmedLen > UDC_SERIAL_MAX_LENGTH - 1) {
                TrimmedLen = UDC_SERIAL_MAX_LENGTH - 1;
            }

            //
            // Convert ASCII to Unicode
            //
            for (ULONG i = 0; i < TrimmedLen; i++) {
                SerialNumber[i] = (WCHAR)(UCHAR)AsciiSerial[Start + i];
            }

            *SerialLength = (USHORT)TrimmedLen;
            SerialNumber[*SerialLength] = L'\0';
        }

        ExFreePoolWithTag(Descriptor, UDC_POOL_TAG);
        Descriptor = NULL;
    }

    //
    // Step 2: Walk device stack to PDO, query hardware ID for VID/PID
    //
    PhysicalDevice = UdcpGetPhysicalDeviceObject(DiskDevice);
    if (PhysicalDevice != NULL) {

        UCHAR HardwareIdBuffer[UDC_HARDWARE_ID_BUFFER_SIZE];
        ULONG ResultLength = 0;

        Status = IoGetDeviceProperty(
            PhysicalDevice,
            DevicePropertyHardwareID,
            sizeof(HardwareIdBuffer),
            HardwareIdBuffer,
            &ResultLength
            );

        if (NT_SUCCESS(Status) && ResultLength > sizeof(WCHAR)) {
            UdcpParseHardwareIdForVidPid(
                (PCWSTR)HardwareIdBuffer,
                ResultLength,
                VendorId,
                ProductId
                );
        }

        ObDereferenceObject(PhysicalDevice);
    }

    ObDereferenceObject(DiskDevice);
    return STATUS_SUCCESS;
}


/*++
    Sends IOCTL_STORAGE_QUERY_PROPERTY synchronously to the given device
    to retrieve the STORAGE_DEVICE_DESCRIPTOR.

    Caller must free the returned Descriptor with ExFreePoolWithTag(, UDC_POOL_TAG).
--*/
static NTSTATUS
UdcpSendStorageQuery(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PSTORAGE_DEVICE_DESCRIPTOR *Descriptor
    )
{
    NTSTATUS Status;
    STORAGE_PROPERTY_QUERY Query;
    IO_STATUS_BLOCK IoStatus;
    KEVENT Event;
    PIRP Irp;
    PSTORAGE_DEVICE_DESCRIPTOR Desc;

    PAGED_CODE();

    *Descriptor = NULL;

    Desc = (PSTORAGE_DEVICE_DESCRIPTOR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        UDC_STORAGE_QUERY_BUFFER_SIZE,
        UDC_POOL_TAG
        );

    if (Desc == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&Query, sizeof(Query));
    Query.PropertyId = StorageDeviceProperty;
    Query.QueryType = PropertyStandardQuery;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildDeviceIoControlRequest(
        IOCTL_STORAGE_QUERY_PROPERTY,
        DeviceObject,
        &Query,
        sizeof(Query),
        Desc,
        UDC_STORAGE_QUERY_BUFFER_SIZE,
        FALSE,
        &Event,
        &IoStatus
        );

    if (Irp == NULL) {
        ExFreePoolWithTag(Desc, UDC_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(
            &Event,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );
        Status = IoStatus.Status;
    }

    if (NT_SUCCESS(Status)) {
        //
        // Validate descriptor integrity before returning to caller
        //
        if (Desc->Size > UDC_STORAGE_QUERY_BUFFER_SIZE ||
            Desc->Version == 0) {
            ExFreePoolWithTag(Desc, UDC_POOL_TAG);
            return STATUS_DATA_ERROR;
        }
        *Descriptor = Desc;
    } else {
        ExFreePoolWithTag(Desc, UDC_POOL_TAG);
    }

    return Status;
}


/*++
    Walks the device stack from the given device object down to the
    Physical Device Object (PDO) at the bottom of the stack.

    Returns a referenced PDO — caller must call ObDereferenceObject.
    Returns NULL if the walk fails for any reason.
--*/
static PDEVICE_OBJECT
UdcpGetPhysicalDeviceObject(
    _In_ PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_OBJECT Current;
    PDEVICE_OBJECT Lower;
    ULONG Depth = 0;

    PAGED_CODE();

    //
    // Start from the given device, walk down via IoGetLowerDeviceObject
    // until we hit the bottom (PDO). Cap depth to prevent infinite loops
    // in case of corrupted device stacks.
    //
    Current = DeviceObject;
    ObReferenceObject(Current);

    while (Depth < 64) {
        Lower = IoGetLowerDeviceObject(Current);
        if (Lower == NULL) {
            break;
        }
        ObDereferenceObject(Current);
        Current = Lower;
        Depth++;
    }

    //
    // Current is now the PDO (bottom of stack), referenced once.
    //
    return Current;
}


/*++
    Parses a REG_MULTI_SZ hardware ID string for USB VID_xxxx and PID_xxxx
    patterns. USB hardware IDs look like: USB\VID_1234&PID_5678\serial

    Case-insensitive search — firmware may use any case.
--*/
static VOID
UdcpParseHardwareIdForVidPid(
    _In_reads_bytes_(LengthInBytes) PCWSTR HardwareId,
    _In_ ULONG LengthInBytes,
    _Out_ PUSHORT VendorId,
    _Out_ PUSHORT ProductId
    )
{
    ULONG TotalChars = LengthInBytes / sizeof(WCHAR);
    PCWSTR Current = HardwareId;

    *VendorId = 0;
    *ProductId = 0;

    //
    // REG_MULTI_SZ: multiple null-terminated strings followed by
    // a double-null terminator. Iterate each string.
    //
    while (Current < HardwareId + TotalChars && *Current != L'\0') {

        //
        // Calculate string length
        //
        ULONG StrLen = 0;
        while (Current + StrLen < HardwareId + TotalChars &&
               Current[StrLen] != L'\0') {
            StrLen++;
        }

        //
        // Search for VID_ and PID_ patterns in this string
        //
        for (ULONG i = 0; i + 4 <= StrLen; i++) {
            if ((Current[i] == L'V' || Current[i] == L'v') &&
                (Current[i + 1] == L'I' || Current[i + 1] == L'i') &&
                (Current[i + 2] == L'D' || Current[i + 2] == L'd') &&
                Current[i + 3] == L'_') {

                if (i + 8 <= StrLen) {
                    *VendorId = UdcpParseHex4(
                        &Current[i + 4], StrLen - i - 4);
                }
            }

            if ((Current[i] == L'P' || Current[i] == L'p') &&
                (Current[i + 1] == L'I' || Current[i + 1] == L'i') &&
                (Current[i + 2] == L'D' || Current[i + 2] == L'd') &&
                Current[i + 3] == L'_') {

                if (i + 8 <= StrLen) {
                    *ProductId = UdcpParseHex4(
                        &Current[i + 4], StrLen - i - 4);
                }
            }
        }

        //
        // If we found both, stop early
        //
        if (*VendorId != 0 && *ProductId != 0) {
            return;
        }

        //
        // Advance past null terminator to next string
        //
        Current += StrLen + 1;
    }
}


static USHORT
UdcpParseHex4(
    _In_reads_(AvailableChars) PCWSTR Str,
    _In_ ULONG AvailableChars
    )
{
    USHORT Result = 0;
    ULONG Count = (AvailableChars < 4) ? AvailableChars : 4;

    for (ULONG i = 0; i < Count; i++) {
        WCHAR Ch = Str[i];
        if (Ch >= L'0' && Ch <= L'9') {
            Result = (Result << 4) | (USHORT)(Ch - L'0');
        } else if (Ch >= L'A' && Ch <= L'F') {
            Result = (Result << 4) | (USHORT)(Ch - L'A' + 10);
        } else if (Ch >= L'a' && Ch <= L'f') {
            Result = (Result << 4) | (USHORT)(Ch - L'a' + 10);
        } else {
            break;
        }
    }

    return Result;
}

// ============================================================================
// PRIVATE — POLICY RESOLUTION
// ============================================================================

static UDC_DEVICE_POLICY
UdcpResolvePolicy(
    _In_ USHORT VendorId,
    _In_ USHORT ProductId,
    _In_opt_ PCWSTR SerialNumber,
    _In_ UDC_DEVICE_CLASS DeviceClass
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
        BOOLEAN ClassMatch = (Rule->DeviceClass == UdcClass_Unknown ||
                              Rule->DeviceClass == DeviceClass);
        BOOLEAN SerialMatch;

        //
        // UDC-6 FIX: When a rule specifies a serial number requirement
        // (SerialNumberLength > 0), the device MUST provide a matching
        // serial. If the device has no serial (NULL), the rule does NOT
        // match. Previously, SerialMatch defaulted to TRUE when
        // SerialNumber was NULL, allowing any device to match serial-
        // specific rules.
        //
        if (Rule->SerialNumberLength > 0) {
            if (SerialNumber == NULL) {
                SerialMatch = FALSE;
            } else {
                UNICODE_STRING RuleSerial;
                RuleSerial.Buffer = Rule->SerialNumber;
                RuleSerial.Length = Rule->SerialNumberLength * sizeof(WCHAR);
                RuleSerial.MaximumLength = sizeof(Rule->SerialNumber);

                UNICODE_STRING DeviceSerial;
                RtlInitUnicodeString(&DeviceSerial, SerialNumber);

                SerialMatch = RtlEqualUnicodeString(
                    &RuleSerial, &DeviceSerial, TRUE);
            }
        } else {
            SerialMatch = TRUE;     // Rule doesn't care about serial
        }

        if (VidMatch && PidMatch && ClassMatch && SerialMatch) {
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
        BOOLEAN ClassMatch = (Rule->DeviceClass == UdcClass_Unknown ||
                              Rule->DeviceClass == DeviceClass);
        BOOLEAN SerialMatch;

        if (Rule->SerialNumberLength > 0) {
            if (SerialNumber == NULL) {
                SerialMatch = FALSE;
            } else {
                UNICODE_STRING RuleSerial;
                RuleSerial.Buffer = Rule->SerialNumber;
                RuleSerial.Length = Rule->SerialNumberLength * sizeof(WCHAR);
                RuleSerial.MaximumLength = sizeof(Rule->SerialNumber);

                UNICODE_STRING DeviceSerial;
                RtlInitUnicodeString(&DeviceSerial, SerialNumber);

                SerialMatch = RtlEqualUnicodeString(
                    &RuleSerial, &DeviceSerial, TRUE);
            }
        } else {
            SerialMatch = TRUE;
        }

        if (VidMatch && PidMatch && ClassMatch && SerialMatch) {
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

    PAGED_CODE();

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
        if (FlagOn(VolumeProps->DeviceCharacteristics, FILE_REMOVABLE_MEDIA) ||
            FlagOn(VolumeProps->DeviceCharacteristics, FILE_FLOPPY_DISKETTE)) {
            IsRemovable = TRUE;
        }
    }

    ExFreePoolWithTag(VolumeProps, UDC_POOL_TAG);
    return IsRemovable;
}

// ============================================================================
// PRIVATE — VOLUME LOOKUP (CALLER MUST HOLD VolumeLock)
// ============================================================================

static PUDC_TRACKED_VOLUME
UdcpFindVolumeUnlocked(
    _In_ PFLT_INSTANCE Instance
    )
{
    LIST_ENTRY *ListEntry;

    for (ListEntry = g_UdcState.VolumeListHead.Flink;
         ListEntry != &g_UdcState.VolumeListHead;
         ListEntry = ListEntry->Flink) {

        PUDC_TRACKED_VOLUME Volume = CONTAINING_RECORD(
            ListEntry, UDC_TRACKED_VOLUME, Link);

        if (Volume->Instance == Instance) {
            return Volume;
        }
    }

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
