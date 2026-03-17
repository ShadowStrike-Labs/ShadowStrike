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
    ShadowStrike Next-Generation Antivirus
    Module: ELAMCallbacks.c - ELAM callback registration and boot driver tracking

    This module provides:
    - Boot phase tracking (Early, BeforeDriverInit, AfterDriverInit, Complete)
    - Boot driver list management with classification results
    - User callback registration for external notification
    - Policy enforcement (BlockUnknown, AllowUnsigned)
    - Query interface for processed boot drivers

    Copyright (c) ShadowStrike Team
--*/

#include "ELAMCallbacks.h"
#include "ELAMDriver.h"
#include "BootDriverVerify.h"
#include "BootThreatDetector.h"
#include <ntstrsafe.h>

// ============================================================================
// CONSTANTS
// ============================================================================

#define EC_MAX_BOOT_DRIVERS         256
#define EC_MAX_PATH_LENGTH          520

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

/**
 * @brief Extended boot driver entry with allocated path buffers
 */
typedef struct _EC_BOOT_DRIVER_INTERNAL {
    EC_BOOT_DRIVER Public;

    // Allocated buffers for path strings
    WCHAR DriverPathBuffer[EC_MAX_PATH_LENGTH];
    WCHAR RegistryPathBuffer[EC_MAX_PATH_LENGTH];

    // Extended classification info
    UCHAR ImageHash[32];
    LARGE_INTEGER LoadTime;
    EC_BOOT_PHASE LastPhase;

} EC_BOOT_DRIVER_INTERNAL, *PEC_BOOT_DRIVER_INTERNAL;

/**
 * @brief Internal callback context
 */
typedef struct _EC_ELAM_CALLBACKS_INTERNAL {
    EC_ELAM_CALLBACKS Public;

    // Current boot phase (accessed via InterlockedExchange/CompareExchange)
    volatile LONG CurrentPhase;

    // Lookaside for driver allocations
    NPAGED_LOOKASIDE_LIST DriverLookaside;
    BOOLEAN LookasideInitialized;

    // Phase completion events
    KEVENT PhaseCompleteEvent;

    // Boot complete flag (accessed via InterlockedExchange/CompareExchange)
    volatile LONG BootComplete;

} EC_ELAM_CALLBACKS_INTERNAL, *PEC_ELAM_CALLBACKS_INTERNAL;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PEC_BOOT_DRIVER_INTERNAL
ElcbpAllocateBootDriver(
    _In_ PEC_ELAM_CALLBACKS_INTERNAL Internal
    );

static VOID
ElcbpFreeBootDriver(
    _In_ PEC_ELAM_CALLBACKS_INTERNAL Internal,
    _In_ PEC_BOOT_DRIVER_INTERNAL Driver
    );

static VOID
ElcbpCopyUnicodeString(
    _Out_ PUNICODE_STRING Dest,
    _In_ PWCHAR DestBuffer,
    _In_ ULONG DestBufferSize,
    _In_ PCUNICODE_STRING Source
    );

static PEC_BOOT_DRIVER_INTERNAL
ElcbpFindDriverByPath(
    _In_ PEC_ELAM_CALLBACKS Callbacks,
    _In_ PCUNICODE_STRING DriverPath
    );

static BOOLEAN
ElcbpApplyPolicy(
    _In_ PEC_ELAM_CALLBACKS Callbacks,
    _In_ PEC_BOOT_DRIVER_INTERNAL Driver
    );

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Allocate boot driver entry from lookaside
 */
static PEC_BOOT_DRIVER_INTERNAL
ElcbpAllocateBootDriver(
    _In_ PEC_ELAM_CALLBACKS_INTERNAL Internal
    )
{
    PEC_BOOT_DRIVER_INTERNAL driver;

    if (!Internal->LookasideInitialized) {
        return NULL;
    }

    driver = (PEC_BOOT_DRIVER_INTERNAL)ExAllocateFromNPagedLookasideList(
        &Internal->DriverLookaside
        );

    if (driver != NULL) {
        RtlZeroMemory(driver, sizeof(EC_BOOT_DRIVER_INTERNAL));
    }

    return driver;
}

/**
 * @brief Free boot driver entry to lookaside
 */
static VOID
ElcbpFreeBootDriver(
    _In_ PEC_ELAM_CALLBACKS_INTERNAL Internal,
    _In_ PEC_BOOT_DRIVER_INTERNAL Driver
    )
{
    if (Driver != NULL && Internal->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Internal->DriverLookaside, Driver);
    }
}

/**
 * @brief Copy unicode string with bounds checking
 */
static VOID
ElcbpCopyUnicodeString(
    _Out_ PUNICODE_STRING Dest,
    _In_ PWCHAR DestBuffer,
    _In_ ULONG DestBufferSize,
    _In_ PCUNICODE_STRING Source
    )
{
    ULONG copyLength;

    Dest->Buffer = DestBuffer;
    Dest->MaximumLength = (USHORT)DestBufferSize;

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0 ||
        DestBufferSize < sizeof(WCHAR)) {
        Dest->Length = 0;
        if (DestBufferSize >= sizeof(WCHAR)) {
            DestBuffer[0] = L'\0';
        }
        return;
    }

    copyLength = min(Source->Length, DestBufferSize - sizeof(WCHAR));

    RtlCopyMemory(DestBuffer, Source->Buffer, copyLength);
    DestBuffer[copyLength / sizeof(WCHAR)] = L'\0';

    Dest->Length = (USHORT)copyLength;
}

/**
 * @brief Find driver entry by path
 */
static PEC_BOOT_DRIVER_INTERNAL
ElcbpFindDriverByPath(
    _In_ PEC_ELAM_CALLBACKS Callbacks,
    _In_ PCUNICODE_STRING DriverPath
    )
{
    PLIST_ENTRY entry;
    PEC_BOOT_DRIVER_INTERNAL driver;

    if (DriverPath == NULL || DriverPath->Buffer == NULL) {
        return NULL;
    }

    for (entry = Callbacks->DriverList.Flink;
         entry != &Callbacks->DriverList;
         entry = entry->Flink) {

        driver = CONTAINING_RECORD(entry, EC_BOOT_DRIVER_INTERNAL, Public.ListEntry);

        if (RtlEqualUnicodeString(&driver->Public.DriverPath, DriverPath, TRUE)) {
            return driver;
        }
    }

    return NULL;
}

/**
 * @brief Apply policy to determine if driver should be allowed
 */
static BOOLEAN
ElcbpApplyPolicy(
    _In_ PEC_ELAM_CALLBACKS Callbacks,
    _In_ PEC_BOOT_DRIVER_INTERNAL Driver
    )
{
    switch (Driver->Public.Classification) {
        case EC_BDCB_KNOWN_GOOD_IMAGE:
            Driver->Public.IsAllowed = TRUE;
            return TRUE;

        case EC_BDCB_KNOWN_BAD_IMAGE:
            Driver->Public.IsAllowed = FALSE;
            RtlStringCbCopyA(Driver->Public.BlockReason,
                           sizeof(Driver->Public.BlockReason),
                           "Known malicious driver");
            return FALSE;

        case EC_BDCB_UNKNOWN_IMAGE:
        default:
            if (Callbacks->BlockUnknown) {
                Driver->Public.IsAllowed = FALSE;
                RtlStringCbCopyA(Driver->Public.BlockReason,
                               sizeof(Driver->Public.BlockReason),
                               "Unknown driver blocked by policy");
                return FALSE;
            }

            //
            // Enforce signature requirement: unsigned drivers are blocked
            // unless the AllowUnsigned policy flag is explicitly set.
            //
            if (!Driver->Public.IsSigned && !Callbacks->AllowUnsigned) {
                Driver->Public.IsAllowed = FALSE;
                RtlStringCbCopyA(Driver->Public.BlockReason,
                               sizeof(Driver->Public.BlockReason),
                               "Unsigned driver blocked by signature policy");
                return FALSE;
            }

            Driver->Public.IsAllowed = TRUE;
            return TRUE;
    }
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

/**
 * @brief Initialize the ELAM callbacks subsystem
 */
_Use_decl_annotations_
NTSTATUS
ElcbInitialize(
    PEC_ELAM_CALLBACKS* Callbacks
    )
{
    PEC_ELAM_CALLBACKS_INTERNAL internal = NULL;

    if (Callbacks == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Callbacks = NULL;

    // Allocate internal structure
    internal = (PEC_ELAM_CALLBACKS_INTERNAL)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(EC_ELAM_CALLBACKS_INTERNAL),
        EC_POOL_TAG
        );

    if (internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(internal, sizeof(EC_ELAM_CALLBACKS_INTERNAL));

    // Initialize driver list
    InitializeListHead(&internal->Public.DriverList);
    ExInitializePushLock(&internal->Public.DriverLock);

    // Initialize lookaside list for driver entries
    ExInitializeNPagedLookasideList(
        &internal->DriverLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(EC_BOOT_DRIVER_INTERNAL),
        EC_POOL_TAG,
        0
        );
    internal->LookasideInitialized = TRUE;

    // Initialize phase event
    KeInitializeEvent(&internal->PhaseCompleteEvent, NotificationEvent, FALSE);

    // Set initial phase
    internal->CurrentPhase = EcPhase_Early;
    internal->BootComplete = FALSE;

    // Default policy: allow unknown, require signatures
    internal->Public.BlockUnknown = FALSE;
    internal->Public.AllowUnsigned = FALSE;

    // Initialize rundown protection for shutdown safety
    ExInitializeRundownProtection(&internal->Public.RundownRef);

    // Record start time
    KeQuerySystemTimePrecise(&internal->Public.Stats.StartTime);

    InterlockedExchange(&internal->Public.Initialized, TRUE);
    *Callbacks = &internal->Public;

    return STATUS_SUCCESS;
}

/**
 * @brief Shutdown the ELAM callbacks subsystem
 *
 * Uses CAS on Initialized to prevent double-shutdown, then waits for
 * all in-flight API calls to drain via EX_RUNDOWN_REF before freeing.
 */
_Use_decl_annotations_
VOID
ElcbShutdown(
    PEC_ELAM_CALLBACKS Callbacks
    )
{
    PEC_ELAM_CALLBACKS_INTERNAL internal;
    PLIST_ENTRY entry;
    PEC_BOOT_DRIVER_INTERNAL driver;

    if (Callbacks == NULL) {
        return;
    }

    // CAS guard: only one thread proceeds past this point
    if (InterlockedCompareExchange(&Callbacks->Initialized, 0, 1) != 1) {
        return;
    }

    internal = CONTAINING_RECORD(Callbacks, EC_ELAM_CALLBACKS_INTERNAL, Public);

    // Unregister callbacks first
    ElcbUnregisterCallbacks(Callbacks);

    // Wait for all in-flight public API calls to complete.
    // After this returns, no new ExAcquireRundownProtection can succeed.
    ExWaitForRundownProtectionRelease(&Callbacks->RundownRef);

    // All in-flight calls have drained — safe to tear down
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Callbacks->DriverLock);
    while (!IsListEmpty(&Callbacks->DriverList)) {
        entry = RemoveHeadList(&Callbacks->DriverList);
        driver = CONTAINING_RECORD(entry, EC_BOOT_DRIVER_INTERNAL, Public.ListEntry);
        ElcbpFreeBootDriver(internal, driver);
    }
    Callbacks->DriverCount = 0;
    ExReleasePushLockExclusive(&Callbacks->DriverLock);
    KeLeaveCriticalRegion();

    // Delete lookaside list
    if (internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&internal->DriverLookaside);
        internal->LookasideInitialized = FALSE;
    }

    // Free structure
    ExFreePoolWithTag(internal, EC_POOL_TAG);
}

/**
 * @brief Register system callbacks for boot driver monitoring
 *
 * Marks this subsystem as actively tracking boot drivers.
 * Actual kernel callback registration (PsSetLoadImageNotifyRoutine,
 * CmRegisterCallbackEx) is handled by ELAMDriver.c which calls
 * ElcbProcessBootDriver for each detected driver load.
 */
_Use_decl_annotations_
NTSTATUS
ElcbRegisterCallbacks(
    PEC_ELAM_CALLBACKS Callbacks
    )
{
    if (Callbacks == NULL || !InterlockedCompareExchange(&Callbacks->Initialized, 1, 1)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Callbacks->Registered, 1, 0) != 0) {
        return STATUS_ALREADY_REGISTERED;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[ShadowStrike/EC] Boot driver tracking callbacks registered\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Unregister system callbacks
 *
 * Marks this subsystem as no longer tracking boot drivers.
 * Actual kernel callback unregistration is handled by ELAMDriver.c.
 */
_Use_decl_annotations_
NTSTATUS
ElcbUnregisterCallbacks(
    PEC_ELAM_CALLBACKS Callbacks
    )
{
    if (Callbacks == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Callbacks->Registered, 0, 1) != 1) {
        return STATUS_SUCCESS;
    }

    Callbacks->CallbackRegistration = NULL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[ShadowStrike/EC] Boot driver tracking callbacks unregistered\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Set user callback for boot driver notifications
 */
_Use_decl_annotations_
NTSTATUS
ElcbSetUserCallback(
    PEC_ELAM_CALLBACKS Callbacks,
    EC_DRIVER_CALLBACK Callback,
    PVOID Context
    )
{
    if (Callbacks == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Callbacks->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Callbacks->DriverLock);
    Callbacks->UserCallback = Callback;
    Callbacks->UserContext = Context;
    ExReleasePushLockExclusive(&Callbacks->DriverLock);
    KeLeaveCriticalRegion();

    ExReleaseRundownProtection(&Callbacks->RundownRef);
    return STATUS_SUCCESS;
}

/**
 * @brief Set boot driver policy
 */
_Use_decl_annotations_
NTSTATUS
ElcbSetPolicy(
    PEC_ELAM_CALLBACKS Callbacks,
    BOOLEAN BlockUnknown,
    BOOLEAN AllowUnsigned
    )
{
    if (Callbacks == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Callbacks->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Callbacks->DriverLock);
    Callbacks->BlockUnknown = BlockUnknown;
    Callbacks->AllowUnsigned = AllowUnsigned;
    ExReleasePushLockExclusive(&Callbacks->DriverLock);
    KeLeaveCriticalRegion();

    ExReleaseRundownProtection(&Callbacks->RundownRef);
    return STATUS_SUCCESS;
}

/**
 * @brief Get list of processed boot drivers (deep-copy, caller-owned)
 *
 * Allocates independent copies of each EC_BOOT_DRIVER so the caller
 * can safely use them after this function returns. Each returned
 * pointer must be freed via ElcbFreeBootDriverSnapshot when done.
 *
 * Layout per entry: [EC_BOOT_DRIVER][DriverPathChars][RegistryPathChars]
 */
_Use_decl_annotations_
NTSTATUS
ElcbGetBootDrivers(
    PEC_ELAM_CALLBACKS Callbacks,
    PEC_BOOT_DRIVER* Drivers,
    ULONG Max,
    PULONG Count
    )
{
    PLIST_ENTRY entry;
    PEC_BOOT_DRIVER_INTERNAL driver;
    ULONG index = 0;

    if (Callbacks == NULL || Drivers == NULL || Count == NULL || Max == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    if (!ExAcquireRundownProtection(&Callbacks->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Callbacks->DriverLock);

    for (entry = Callbacks->DriverList.Flink;
         entry != &Callbacks->DriverList && index < Max;
         entry = entry->Flink) {

        driver = CONTAINING_RECORD(entry, EC_BOOT_DRIVER_INTERNAL, Public.ListEntry);

        //
        // Compute allocation size: struct + both path buffers (WCHAR-sized)
        //
        USHORT drvLen = driver->Public.DriverPath.Length;
        USHORT regLen = driver->Public.RegistryPath.Length;
        SIZE_T allocSize = sizeof(EC_BOOT_DRIVER) + drvLen + regLen;

        PEC_BOOT_DRIVER copy = (PEC_BOOT_DRIVER)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, allocSize, EC_POOL_TAG);

        if (copy == NULL) {
            // Out of memory — free already-allocated copies and bail
            ExReleasePushLockShared(&Callbacks->DriverLock);
            KeLeaveCriticalRegion();
            ExReleaseRundownProtection(&Callbacks->RundownRef);

            ElcbFreeBootDriverSnapshot(Drivers, index);
            *Count = 0;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Copy flat fields
        RtlCopyMemory(copy, &driver->Public, sizeof(EC_BOOT_DRIVER));

        // Fixup DriverPath → points past the struct
        PWCHAR dstDriverPath = (PWCHAR)((PUCHAR)copy + sizeof(EC_BOOT_DRIVER));
        if (drvLen > 0 && driver->Public.DriverPath.Buffer != NULL) {
            RtlCopyMemory(dstDriverPath, driver->Public.DriverPath.Buffer, drvLen);
        }
        copy->DriverPath.Buffer = dstDriverPath;
        copy->DriverPath.Length = drvLen;
        copy->DriverPath.MaximumLength = drvLen;

        // Fixup RegistryPath → points past DriverPath data
        PWCHAR dstRegistryPath = (PWCHAR)((PUCHAR)dstDriverPath + drvLen);
        if (regLen > 0 && driver->Public.RegistryPath.Buffer != NULL) {
            RtlCopyMemory(dstRegistryPath, driver->Public.RegistryPath.Buffer, regLen);
        }
        copy->RegistryPath.Buffer = dstRegistryPath;
        copy->RegistryPath.Length = regLen;
        copy->RegistryPath.MaximumLength = regLen;

        // Clear ListEntry — snapshot entry is not in any list
        InitializeListHead(&copy->ListEntry);

        Drivers[index] = copy;
        index++;
    }

    ExReleasePushLockShared(&Callbacks->DriverLock);
    KeLeaveCriticalRegion();

    *Count = index;

    ExReleaseRundownProtection(&Callbacks->RundownRef);
    return STATUS_SUCCESS;
}

/**
 * @brief Free an array of deep-copied boot driver snapshots
 *
 * Frees each entry allocated by ElcbGetBootDrivers. Safe to call
 * with Count=0 (no-op).
 */
_Use_decl_annotations_
VOID
ElcbFreeBootDriverSnapshot(
    PEC_BOOT_DRIVER* Drivers,
    ULONG Count
    )
{
    ULONG i;

    if (Drivers == NULL) {
        return;
    }

    for (i = 0; i < Count; i++) {
        if (Drivers[i] != NULL) {
            ExFreePoolWithTag(Drivers[i], EC_POOL_TAG);
            Drivers[i] = NULL;
        }
    }
}

// ============================================================================
// INTERNAL API - Called by ELAMDriver.c
// ============================================================================

/**
 * @brief Process a boot driver load event
 *
 * Called by ELAMDriver's image load callback to track boot drivers.
 * Thread-safe: user callback is invoked outside the push lock to
 * prevent deadlock if the callback calls ElcbGetBootDrivers etc.
 *
 * Deep-copies the public snapshot (including string data) to stack
 * buffers before releasing the lock, so the user callback never
 * dereferences internal allocations. After re-acquiring the lock
 * for the user-callback-block path, re-looks up the driver entry
 * to guard against concurrent ElcbShutdown.
 */
NTSTATUS
ElcbProcessBootDriver(
    _In_ PEC_ELAM_CALLBACKS Callbacks,
    _In_ PCUNICODE_STRING DriverPath,
    _In_opt_ PCUNICODE_STRING RegistryPath,
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ ULONG Classification,
    _In_ BOOLEAN IsSigned,
    _In_ EC_BOOT_PHASE Phase,
    _Out_opt_ PBOOLEAN AllowDriver
    )
{
    PEC_ELAM_CALLBACKS_INTERNAL internal;
    PEC_BOOT_DRIVER_INTERNAL driver;
    BOOLEAN allow = TRUE;
    EC_DRIVER_CALLBACK savedCallback = NULL;
    PVOID savedContext = NULL;

    // Deep-copy snapshot for user callback — stack buffers for string data
    EC_BOOT_DRIVER publicCopy;
    WCHAR copyDriverPathBuf[EC_MAX_PATH_LENGTH];
    WCHAR copyRegistryPathBuf[EC_MAX_PATH_LENGTH];

    if (Callbacks == NULL || DriverPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Callbacks->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    internal = CONTAINING_RECORD(Callbacks, EC_ELAM_CALLBACKS_INTERNAL, Public);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Callbacks->DriverLock);

    driver = ElcbpFindDriverByPath(Callbacks, DriverPath);

    if (driver == NULL) {
        if (Callbacks->DriverCount >= EC_MAX_BOOT_DRIVERS) {
            ExReleasePushLockExclusive(&Callbacks->DriverLock);
            KeLeaveCriticalRegion();
            ExReleaseRundownProtection(&Callbacks->RundownRef);
            return STATUS_QUOTA_EXCEEDED;
        }

        driver = ElcbpAllocateBootDriver(internal);
        if (driver == NULL) {
            ExReleasePushLockExclusive(&Callbacks->DriverLock);
            KeLeaveCriticalRegion();
            ExReleaseRundownProtection(&Callbacks->RundownRef);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ElcbpCopyUnicodeString(
            &driver->Public.DriverPath,
            driver->DriverPathBuffer,
            sizeof(driver->DriverPathBuffer),
            DriverPath
            );

        if (RegistryPath != NULL) {
            ElcbpCopyUnicodeString(
                &driver->Public.RegistryPath,
                driver->RegistryPathBuffer,
                sizeof(driver->RegistryPathBuffer),
                RegistryPath
                );
        }

        driver->Public.ImageBase = ImageBase;
        driver->Public.ImageSize = ImageSize;

        InsertTailList(&Callbacks->DriverList, &driver->Public.ListEntry);
        Callbacks->DriverCount++;
    }

    // Update classification, signature status, and phase
    driver->Public.Classification = Classification;
    driver->Public.IsSigned = IsSigned;
    driver->Public.ImageFlags = 0;
    driver->LastPhase = Phase;
    KeQuerySystemTimePrecise(&driver->LoadTime);

    // Apply policy
    allow = ElcbpApplyPolicy(Callbacks, driver);

    // Update statistics
    InterlockedIncrement64(&Callbacks->Stats.DriversProcessed);
    if (allow) {
        InterlockedIncrement64(&Callbacks->Stats.DriversAllowed);
    } else {
        InterlockedIncrement64(&Callbacks->Stats.DriversBlocked);
    }

    //
    // Capture user callback and DEEP-COPY the driver's public state
    // including string data to stack buffers. This prevents UAF: after
    // lock release, the internal driver entry could be freed by shutdown,
    // so the callback must never dereference internal pointers.
    //
    savedCallback = Callbacks->UserCallback;
    savedContext = Callbacks->UserContext;
    if (savedCallback != NULL) {
        RtlCopyMemory(&publicCopy, &driver->Public, sizeof(EC_BOOT_DRIVER));

        // Deep-copy DriverPath string data to stack buffer
        if (driver->Public.DriverPath.Buffer != NULL && driver->Public.DriverPath.Length > 0) {
            ULONG copyLen = min(driver->Public.DriverPath.Length,
                               (ULONG)(sizeof(copyDriverPathBuf) - sizeof(WCHAR)));
            RtlCopyMemory(copyDriverPathBuf, driver->Public.DriverPath.Buffer, copyLen);
            copyDriverPathBuf[copyLen / sizeof(WCHAR)] = L'\0';
            publicCopy.DriverPath.Buffer = copyDriverPathBuf;
            publicCopy.DriverPath.Length = (USHORT)copyLen;
            publicCopy.DriverPath.MaximumLength = (USHORT)sizeof(copyDriverPathBuf);
        } else {
            copyDriverPathBuf[0] = L'\0';
            publicCopy.DriverPath.Buffer = copyDriverPathBuf;
            publicCopy.DriverPath.Length = 0;
            publicCopy.DriverPath.MaximumLength = (USHORT)sizeof(copyDriverPathBuf);
        }

        // Deep-copy RegistryPath string data to stack buffer
        if (driver->Public.RegistryPath.Buffer != NULL && driver->Public.RegistryPath.Length > 0) {
            ULONG copyLen = min(driver->Public.RegistryPath.Length,
                               (ULONG)(sizeof(copyRegistryPathBuf) - sizeof(WCHAR)));
            RtlCopyMemory(copyRegistryPathBuf, driver->Public.RegistryPath.Buffer, copyLen);
            copyRegistryPathBuf[copyLen / sizeof(WCHAR)] = L'\0';
            publicCopy.RegistryPath.Buffer = copyRegistryPathBuf;
            publicCopy.RegistryPath.Length = (USHORT)copyLen;
            publicCopy.RegistryPath.MaximumLength = (USHORT)sizeof(copyRegistryPathBuf);
        } else {
            copyRegistryPathBuf[0] = L'\0';
            publicCopy.RegistryPath.Buffer = copyRegistryPathBuf;
            publicCopy.RegistryPath.Length = 0;
            publicCopy.RegistryPath.MaximumLength = (USHORT)sizeof(copyRegistryPathBuf);
        }
    }

    ExReleasePushLockExclusive(&Callbacks->DriverLock);
    KeLeaveCriticalRegion();

    //
    // Invoke user callback outside the lock — publicCopy is fully self-contained
    //
    if (savedCallback != NULL) {
        BOOLEAN userAllow = allow;

        savedCallback(
            &publicCopy,
            Phase,
            &userAllow,
            savedContext
            );

        // User callback can further restrict (block), but not unblock
        if (!userAllow && allow) {
            allow = FALSE;

            //
            // Re-acquire lock and RE-LOOKUP the driver. Between lock release
            // above and re-acquire here, ElcbShutdown could have freed the entry.
            //
            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Callbacks->DriverLock);

            driver = ElcbpFindDriverByPath(Callbacks, DriverPath);
            if (driver != NULL) {
                driver->Public.IsAllowed = FALSE;
                RtlStringCbCopyA(driver->Public.BlockReason,
                               sizeof(driver->Public.BlockReason),
                               "Blocked by user callback");
            }

            ExReleasePushLockExclusive(&Callbacks->DriverLock);
            KeLeaveCriticalRegion();

            InterlockedDecrement64(&Callbacks->Stats.DriversAllowed);
            InterlockedIncrement64(&Callbacks->Stats.DriversBlocked);
        }
    }

    if (AllowDriver != NULL) {
        *AllowDriver = allow;
    }

    ExReleaseRundownProtection(&Callbacks->RundownRef);
    return STATUS_SUCCESS;
}

/**
 * @brief Update current boot phase
 */
NTSTATUS
ElcbSetBootPhase(
    _In_ PEC_ELAM_CALLBACKS Callbacks,
    _In_ EC_BOOT_PHASE Phase
    )
{
    PEC_ELAM_CALLBACKS_INTERNAL internal;

    if (Callbacks == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Callbacks->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    internal = CONTAINING_RECORD(Callbacks, EC_ELAM_CALLBACKS_INTERNAL, Public);

    InterlockedExchange((volatile LONG*)&internal->CurrentPhase, (LONG)Phase);

    if (Phase == EcPhase_Complete) {
        InterlockedExchange((volatile LONG*)&internal->BootComplete, TRUE);
        KeSetEvent(&internal->PhaseCompleteEvent, IO_NO_INCREMENT, FALSE);
    }

    ExReleaseRundownProtection(&Callbacks->RundownRef);
    return STATUS_SUCCESS;
}

/**
 * @brief Get current boot phase
 */
EC_BOOT_PHASE
ElcbGetBootPhase(
    _In_ PEC_ELAM_CALLBACKS Callbacks
    )
{
    PEC_ELAM_CALLBACKS_INTERNAL internal;
    EC_BOOT_PHASE phase;

    if (Callbacks == NULL) {
        return EcPhase_Complete;
    }

    if (!ExAcquireRundownProtection(&Callbacks->RundownRef)) {
        return EcPhase_Complete;
    }

    internal = CONTAINING_RECORD(Callbacks, EC_ELAM_CALLBACKS_INTERNAL, Public);
    phase = (EC_BOOT_PHASE)InterlockedCompareExchange(
        (volatile LONG*)&internal->CurrentPhase, 0, 0);

    ExReleaseRundownProtection(&Callbacks->RundownRef);
    return phase;
}

/**
 * @brief Check if boot is complete
 */
BOOLEAN
ElcbIsBootComplete(
    _In_ PEC_ELAM_CALLBACKS Callbacks
    )
{
    PEC_ELAM_CALLBACKS_INTERNAL internal;
    BOOLEAN complete;

    if (Callbacks == NULL) {
        return TRUE;
    }

    if (!ExAcquireRundownProtection(&Callbacks->RundownRef)) {
        return TRUE;
    }

    internal = CONTAINING_RECORD(Callbacks, EC_ELAM_CALLBACKS_INTERNAL, Public);
    complete = (BOOLEAN)InterlockedCompareExchange(
        (volatile LONG*)&internal->BootComplete, 0, 0);

    ExReleaseRundownProtection(&Callbacks->RundownRef);
    return complete;
}

/**
 * @brief Get statistics
 */
NTSTATUS
ElcbGetStatistics(
    _In_ PEC_ELAM_CALLBACKS Callbacks,
    _Out_ PLONG64 DriversProcessed,
    _Out_ PLONG64 DriversAllowed,
    _Out_ PLONG64 DriversBlocked
    )
{
    if (Callbacks == NULL ||
        DriversProcessed == NULL || DriversAllowed == NULL ||
        DriversBlocked == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Callbacks->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    *DriversProcessed = Callbacks->Stats.DriversProcessed;
    *DriversAllowed = Callbacks->Stats.DriversAllowed;
    *DriversBlocked = Callbacks->Stats.DriversBlocked;

    ExReleaseRundownProtection(&Callbacks->RundownRef);
    return STATUS_SUCCESS;
}
