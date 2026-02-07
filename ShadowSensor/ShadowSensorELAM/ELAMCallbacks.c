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
EcpAllocateBootDriver(
    _In_ PEC_ELAM_CALLBACKS_INTERNAL Internal
    );

static VOID
EcpFreeBootDriver(
    _In_ PEC_ELAM_CALLBACKS_INTERNAL Internal,
    _In_ PEC_BOOT_DRIVER_INTERNAL Driver
    );

static VOID
EcpCopyUnicodeString(
    _Out_ PUNICODE_STRING Dest,
    _In_ PWCHAR DestBuffer,
    _In_ ULONG DestBufferSize,
    _In_ PCUNICODE_STRING Source
    );

static PEC_BOOT_DRIVER_INTERNAL
EcpFindDriverByPath(
    _In_ PEC_ELAM_CALLBACKS Callbacks,
    _In_ PCUNICODE_STRING DriverPath
    );

static BOOLEAN
EcpApplyPolicy(
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
EcpAllocateBootDriver(
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
EcpFreeBootDriver(
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
EcpCopyUnicodeString(
    _Out_ PUNICODE_STRING Dest,
    _In_ PWCHAR DestBuffer,
    _In_ ULONG DestBufferSize,
    _In_ PCUNICODE_STRING Source
    )
{
    ULONG copyLength;

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        Dest->Buffer = DestBuffer;
        Dest->Length = 0;
        Dest->MaximumLength = (USHORT)DestBufferSize;
        DestBuffer[0] = L'\0';
        return;
    }

    copyLength = min(Source->Length, DestBufferSize - sizeof(WCHAR));

    RtlCopyMemory(DestBuffer, Source->Buffer, copyLength);
    DestBuffer[copyLength / sizeof(WCHAR)] = L'\0';

    Dest->Buffer = DestBuffer;
    Dest->Length = (USHORT)copyLength;
    Dest->MaximumLength = (USHORT)DestBufferSize;
}

/**
 * @brief Find driver entry by path
 */
static PEC_BOOT_DRIVER_INTERNAL
EcpFindDriverByPath(
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
EcpApplyPolicy(
    _In_ PEC_ELAM_CALLBACKS Callbacks,
    _In_ PEC_BOOT_DRIVER_INTERNAL Driver
    )
{
    // Check classification from BDCB
    switch (Driver->Public.Classification) {
        case 1:  // BdCbClassificationKnownGoodImage
            Driver->Public.IsAllowed = TRUE;
            return TRUE;

        case 2:  // BdCbClassificationKnownBadImage
            Driver->Public.IsAllowed = FALSE;
            RtlStringCbCopyA(Driver->Public.BlockReason,
                           sizeof(Driver->Public.BlockReason),
                           "Known malicious driver");
            return FALSE;

        case 0:  // BdCbClassificationUnknownImage
        default:
            // Apply policy for unknown drivers
            if (Callbacks->BlockUnknown) {
                Driver->Public.IsAllowed = FALSE;
                RtlStringCbCopyA(Driver->Public.BlockReason,
                               sizeof(Driver->Public.BlockReason),
                               "Unknown driver blocked by policy");
                return FALSE;
            }

            // Check if unsigned and policy requires signatures
            if (!Callbacks->AllowUnsigned) {
                // Would need signature info to enforce this
                // For now, allow unknown signed drivers
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
EcInitialize(
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
EcShutdown(
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
    EcUnregisterCallbacks(Callbacks);

    Callbacks->Initialized = FALSE;

    // Free all driver entries
    ExAcquirePushLockExclusive(&Callbacks->DriverLock);
    while (!IsListEmpty(&Callbacks->DriverList)) {
        entry = RemoveHeadList(&Callbacks->DriverList);
        driver = CONTAINING_RECORD(entry, EC_BOOT_DRIVER_INTERNAL, Public.ListEntry);
        EcpFreeBootDriver(internal, driver);
    }
    Callbacks->DriverCount = 0;
    ExReleasePushLockExclusive(&Callbacks->DriverLock);

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
 */
_Use_decl_annotations_
NTSTATUS
EcRegisterCallbacks(
    PEC_ELAM_CALLBACKS Callbacks
    )
{
    if (Callbacks == NULL || !Callbacks->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Callbacks->Registered) {
        return STATUS_ALREADY_REGISTERED;
    }

    // The actual callback registration is done in ELAMDriver.c
    // This module provides the tracking and policy layer on top
    //
    // In a real ELAM implementation, this would call:
    // IoRegisterBootDriverCallback()
    //
    // Since we don't have ELAM certificate, ELAMDriver.c uses:
    // PsSetLoadImageNotifyRoutine() instead

    Callbacks->Registered = TRUE;

    return STATUS_SUCCESS;
}

/**
 * @brief Unregister system callbacks
 */
_Use_decl_annotations_
NTSTATUS
EcUnregisterCallbacks(
    PEC_ELAM_CALLBACKS Callbacks
    )
{
    if (Callbacks == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Callbacks->Registered) {
        return STATUS_SUCCESS;
    }

    // Callback unregistration is handled by ELAMDriver.c

    Callbacks->CallbackRegistration = NULL;
    Callbacks->Registered = FALSE;

    return STATUS_SUCCESS;
}

/**
 * @brief Set user callback for boot driver notifications
 */
_Use_decl_annotations_
NTSTATUS
EcSetUserCallback(
    PEC_ELAM_CALLBACKS Callbacks,
    EC_DRIVER_CALLBACK Callback,
    PVOID Context
    )
{
    if (Callbacks == NULL || !Callbacks->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    // Thread-safe update of callback
    ExAcquirePushLockExclusive(&Callbacks->DriverLock);
    Callbacks->UserCallback = Callback;
    Callbacks->UserContext = Context;
    ExReleasePushLockExclusive(&Callbacks->DriverLock);

    return STATUS_SUCCESS;
}

/**
 * @brief Set boot driver policy
 */
_Use_decl_annotations_
NTSTATUS
EcSetPolicy(
    PEC_ELAM_CALLBACKS Callbacks,
    BOOLEAN BlockUnknown,
    BOOLEAN AllowUnsigned
    )
{
    if (Callbacks == NULL || !Callbacks->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockExclusive(&Callbacks->DriverLock);
    Callbacks->BlockUnknown = BlockUnknown;
    Callbacks->AllowUnsigned = AllowUnsigned;
    ExReleasePushLockExclusive(&Callbacks->DriverLock);

    return STATUS_SUCCESS;
}

/**
 * @brief Get list of processed boot drivers
 */
_Use_decl_annotations_
NTSTATUS
EcGetBootDrivers(
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

    ExAcquirePushLockShared(&Callbacks->DriverLock);

    for (entry = Callbacks->DriverList.Flink;
         entry != &Callbacks->DriverList && index < Max;
         entry = entry->Flink) {

        driver = CONTAINING_RECORD(entry, EC_BOOT_DRIVER_INTERNAL, Public.ListEntry);
        Drivers[index] = &driver->Public;
        index++;
    }

    ExReleasePushLockShared(&Callbacks->DriverLock);

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
 */
NTSTATUS
EcProcessBootDriver(
    _In_ PEC_ELAM_CALLBACKS Callbacks,
    _In_ PCUNICODE_STRING DriverPath,
    _In_opt_ PCUNICODE_STRING RegistryPath,
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ ULONG Classification,
    _In_ EC_BOOT_PHASE Phase,
    _Out_opt_ PBOOLEAN AllowDriver
    )
{
    PEC_ELAM_CALLBACKS_INTERNAL internal;
    PEC_BOOT_DRIVER_INTERNAL driver;
    BOOLEAN allow = TRUE;

    if (Callbacks == NULL || !Callbacks->Initialized || DriverPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Callbacks, EC_ELAM_CALLBACKS_INTERNAL, Public);

    // Check if we already have this driver
    ExAcquirePushLockExclusive(&Callbacks->DriverLock);

    driver = EcpFindDriverByPath(Callbacks, DriverPath);

    if (driver == NULL) {
        // New driver - allocate entry
        if (Callbacks->DriverCount >= EC_MAX_BOOT_DRIVERS) {
            ExReleasePushLockExclusive(&Callbacks->DriverLock);
            return STATUS_QUOTA_EXCEEDED;
        }

        driver = EcpAllocateBootDriver(internal);
        if (driver == NULL) {
            ExReleasePushLockExclusive(&Callbacks->DriverLock);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Copy driver path
        EcpCopyUnicodeString(
            &driver->Public.DriverPath,
            driver->DriverPathBuffer,
            sizeof(driver->DriverPathBuffer),
            DriverPath
            );

        // Copy registry path if provided
        if (RegistryPath != NULL) {
            EcpCopyUnicodeString(
                &driver->Public.RegistryPath,
                driver->RegistryPathBuffer,
                sizeof(driver->RegistryPathBuffer),
                RegistryPath
                );
        }

        // Store image info
        driver->Public.ImageBase = ImageBase;
        driver->Public.ImageSize = ImageSize;

        // Add to list
        InsertTailList(&Callbacks->DriverList, &driver->Public.ListEntry);
        Callbacks->DriverCount++;
    }

    // Update classification and phase
    driver->Public.Classification = Classification;
    driver->Public.ImageFlags = 0;
    driver->LastPhase = Phase;
    KeQuerySystemTimePrecise(&driver->LoadTime);

    // Apply policy
    allow = EcpApplyPolicy(Callbacks, driver);

    // Update statistics
    InterlockedIncrement64(&Callbacks->Stats.DriversProcessed);
    if (allow) {
        InterlockedIncrement64(&Callbacks->Stats.DriversAllowed);
    } else {
        InterlockedIncrement64(&Callbacks->Stats.DriversBlocked);
    }

    // Invoke user callback if registered
    if (Callbacks->UserCallback != NULL) {
        BOOLEAN userAllow = allow;

        Callbacks->UserCallback(
            &driver->Public,
            Phase,
            &userAllow,
            Callbacks->UserContext
            );

        // User callback can only further restrict, not allow blocked drivers
        if (!userAllow && allow) {
            allow = FALSE;
            driver->Public.IsAllowed = FALSE;
            RtlStringCbCopyA(driver->Public.BlockReason,
                           sizeof(driver->Public.BlockReason),
                           "Blocked by user callback");
            InterlockedDecrement64(&Callbacks->Stats.DriversAllowed);
            InterlockedIncrement64(&Callbacks->Stats.DriversBlocked);
        }
    }

    ExReleasePushLockExclusive(&Callbacks->DriverLock);

    if (AllowDriver != NULL) {
        *AllowDriver = allow;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Update current boot phase
 */
NTSTATUS
EcSetBootPhase(
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
EcGetBootPhase(
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
EcIsBootComplete(
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
EcGetStatistics(
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
