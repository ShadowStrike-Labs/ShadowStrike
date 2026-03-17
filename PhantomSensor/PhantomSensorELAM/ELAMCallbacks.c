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

    // Current boot phase
    EC_BOOT_PHASE CurrentPhase;

    // Lookaside for driver allocations
    NPAGED_LOOKASIDE_LIST DriverLookaside;
    BOOLEAN LookasideInitialized;

    // Phase completion events
    KEVENT PhaseCompleteEvent;

    // Boot complete flag
    BOOLEAN BootComplete;

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

    // Record start time
    KeQuerySystemTimePrecise(&internal->Public.Stats.StartTime);

    internal->Public.Initialized = TRUE;
    *Callbacks = &internal->Public;

    return STATUS_SUCCESS;
}

/**
 * @brief Shutdown the ELAM callbacks subsystem
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

    internal = CONTAINING_RECORD(Callbacks, EC_ELAM_CALLBACKS_INTERNAL, Public);

    // Unregister callbacks first
    ElcbUnregisterCallbacks(Callbacks);

    Callbacks->Initialized = FALSE;

    // Free all driver entries
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
    if (Callbacks == NULL || !Callbacks->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Callbacks->Registered) {
        return STATUS_ALREADY_REGISTERED;
    }

    Callbacks->Registered = TRUE;

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

    if (!Callbacks->Registered) {
        return STATUS_SUCCESS;
    }

    Callbacks->CallbackRegistration = NULL;
    Callbacks->Registered = FALSE;

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
    if (Callbacks == NULL || !Callbacks->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    // Thread-safe update of callback
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Callbacks->DriverLock);
    Callbacks->UserCallback = Callback;
    Callbacks->UserContext = Context;
    ExReleasePushLockExclusive(&Callbacks->DriverLock);
    KeLeaveCriticalRegion();

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
    if (Callbacks == NULL || !Callbacks->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Callbacks->DriverLock);
    Callbacks->BlockUnknown = BlockUnknown;
    Callbacks->AllowUnsigned = AllowUnsigned;
    ExReleasePushLockExclusive(&Callbacks->DriverLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/**
 * @brief Get list of processed boot drivers
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

    if (Callbacks == NULL || !Callbacks->Initialized ||
        Drivers == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Callbacks->DriverLock);

    for (entry = Callbacks->DriverList.Flink;
         entry != &Callbacks->DriverList && index < Max;
         entry = entry->Flink) {

        driver = CONTAINING_RECORD(entry, EC_BOOT_DRIVER_INTERNAL, Public.ListEntry);
        Drivers[index] = &driver->Public;
        index++;
    }

    ExReleasePushLockShared(&Callbacks->DriverLock);
    KeLeaveCriticalRegion();

    *Count = index;

    return STATUS_SUCCESS;
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
    EC_BOOT_DRIVER publicCopy;

    if (Callbacks == NULL || !Callbacks->Initialized || DriverPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Callbacks, EC_ELAM_CALLBACKS_INTERNAL, Public);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Callbacks->DriverLock);

    driver = ElcbpFindDriverByPath(Callbacks, DriverPath);

    if (driver == NULL) {
        if (Callbacks->DriverCount >= EC_MAX_BOOT_DRIVERS) {
            ExReleasePushLockExclusive(&Callbacks->DriverLock);
            KeLeaveCriticalRegion();
            return STATUS_QUOTA_EXCEEDED;
        }

        driver = ElcbpAllocateBootDriver(internal);
        if (driver == NULL) {
            ExReleasePushLockExclusive(&Callbacks->DriverLock);
            KeLeaveCriticalRegion();
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
    // Capture user callback and a snapshot of the driver's public state
    // BEFORE releasing the lock. This prevents deadlock: the user callback
    // may call ElcbGetBootDrivers (which takes shared lock), and push locks
    // are NOT re-entrant.
    //
    savedCallback = Callbacks->UserCallback;
    savedContext = Callbacks->UserContext;
    if (savedCallback != NULL) {
        RtlCopyMemory(&publicCopy, &driver->Public, sizeof(EC_BOOT_DRIVER));
    }

    ExReleasePushLockExclusive(&Callbacks->DriverLock);
    KeLeaveCriticalRegion();

    //
    // Invoke user callback outside the lock
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

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Callbacks->DriverLock);
            driver->Public.IsAllowed = FALSE;
            RtlStringCbCopyA(driver->Public.BlockReason,
                           sizeof(driver->Public.BlockReason),
                           "Blocked by user callback");
            ExReleasePushLockExclusive(&Callbacks->DriverLock);
            KeLeaveCriticalRegion();

            InterlockedDecrement64(&Callbacks->Stats.DriversAllowed);
            InterlockedIncrement64(&Callbacks->Stats.DriversBlocked);
        }
    }

    if (AllowDriver != NULL) {
        *AllowDriver = allow;
    }

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

    if (Callbacks == NULL || !Callbacks->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Callbacks, EC_ELAM_CALLBACKS_INTERNAL, Public);

    internal->CurrentPhase = Phase;

    if (Phase == EcPhase_Complete) {
        internal->BootComplete = TRUE;
        KeSetEvent(&internal->PhaseCompleteEvent, IO_NO_INCREMENT, FALSE);
    }

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

    if (Callbacks == NULL || !Callbacks->Initialized) {
        return EcPhase_Complete;  // Assume boot complete if invalid
    }

    internal = CONTAINING_RECORD(Callbacks, EC_ELAM_CALLBACKS_INTERNAL, Public);

    return internal->CurrentPhase;
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

    if (Callbacks == NULL || !Callbacks->Initialized) {
        return TRUE;
    }

    internal = CONTAINING_RECORD(Callbacks, EC_ELAM_CALLBACKS_INTERNAL, Public);

    return internal->BootComplete;
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
    if (Callbacks == NULL || !Callbacks->Initialized ||
        DriversProcessed == NULL || DriversAllowed == NULL ||
        DriversBlocked == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DriversProcessed = Callbacks->Stats.DriversProcessed;
    *DriversAllowed = Callbacks->Stats.DriversAllowed;
    *DriversBlocked = Callbacks->Stats.DriversBlocked;

    return STATUS_SUCCESS;
}
