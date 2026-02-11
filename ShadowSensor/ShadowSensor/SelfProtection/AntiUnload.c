/**
 * ============================================================================
 * ShadowStrike NGAV - ANTI-UNLOAD PROTECTION IMPLEMENTATION
 * ============================================================================
 *
 * @file AntiUnload.c
 * @brief Enterprise-grade driver unload prevention and tamper resistance.
 *
 * Architecture:
 * - DriverUnload = NULL blocks NtUnloadDriver (AuLevel_Basic).
 * - ObRegisterCallbacks strips dangerous access from handles targeting
 *   registered protected PIDs (AuLevel_Full).
 * - Protected processes identified by PID registration (not image name).
 *   User-mode service calls AuProtectProcess via secured IOCTL.
 * - PsGetProcessImageFileName for event logging (ANSI, 15 chars, any IRQL).
 * - EX_RUNDOWN_REF guarantees OB callbacks finish before AuShutdown frees.
 * - EX_PUSH_LOCK serializes level transitions and callback registration.
 * - Event history: eviction under spin lock into local list, free outside.
 * - AuGetEvents deep-copies events (no dangling pointers).
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "AntiUnload.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, AuInitialize)
#pragma alloc_text(PAGE, AuShutdown)
#pragma alloc_text(PAGE, AuSetLevel)
#pragma alloc_text(PAGE, AuRegisterCallback)
#endif

// ============================================================================
// PRIVATE PROTOTYPES
// ============================================================================

static PAU_UNLOAD_EVENT
AupCreateEvent(
    _In_ AU_UNLOAD_ATTEMPT Type,
    _In_ HANDLE CallerPid,
    _In_ HANDLE TargetPid,
    _In_ BOOLEAN WasBlocked
    );

static VOID
AupFreeEvent(
    _In_ PAU_UNLOAD_EVENT Event
    );

static VOID
AupAddEvent(
    _In_ PAU_PROTECTOR Protector,
    _In_ PAU_UNLOAD_EVENT Event
    );

static NTSTATUS
AupRegisterObCallbacks(
    _In_ PAU_PROTECTOR Protector
    );

static VOID
AupUnregisterObCallbacks(
    _In_ PAU_PROTECTOR Protector
    );

static OB_PREOP_CALLBACK_STATUS
AupProcessPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

static OB_PREOP_CALLBACK_STATUS
AupThreadPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

static BOOLEAN
AupIsPidProtected(
    _In_ PAU_PROTECTOR Protector,
    _In_ HANDLE ProcessId
    );

static VOID
AupNotifyCallback(
    _In_ PAU_PROTECTOR Protector,
    _In_ AU_UNLOAD_ATTEMPT AttemptType,
    _In_ HANDLE CallerPid
    );

// ============================================================================
// CALLBACK ALTITUDE
// ============================================================================

/**
 * Altitude for ObRegisterCallbacks.
 * NOTE: For production, register an official altitude with Microsoft.
 * This value is a placeholder that must be replaced before WHQL submission.
 */
static const WCHAR g_AltitudeBuffer[] = L"385201.1337";

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * @brief Initialize anti-unload protection.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AuInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _Out_ PAU_PROTECTOR* Protector
    )
{
    PAU_PROTECTOR p = NULL;

    PAGED_CODE();

    if (DriverObject == NULL || Protector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Protector = NULL;

    p = (PAU_PROTECTOR)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(AU_PROTECTOR),
        AU_POOL_TAG
    );
    if (p == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize synchronization primitives.
    //
    ExInitializePushLock(&p->ConfigLock);
    ExInitializeRundownProtection(&p->RundownRef);
    KeInitializeSpinLock(&p->EventLock);
    KeInitializeSpinLock(&p->PidLock);
    InitializeListHead(&p->EventList);

    //
    // Reference the driver object to prevent premature deletion.
    //
    ObReferenceObject(DriverObject);
    p->ProtectedDriver = DriverObject;

    //
    // Null the unload routine — core anti-unload mechanism.
    // Save original so AuShutdown can restore it for controlled unload.
    //
    p->OriginalUnload = DriverObject->DriverUnload;
    DriverObject->DriverUnload = NULL;

    //
    // Set up altitude string for OB callbacks (from const buffer).
    //
    RtlInitUnicodeString(&p->ObAltitude, g_AltitudeBuffer);

    //
    // Default protection level.
    //
    InterlockedExchange(&p->Level, (LONG)AuLevel_Basic);

    KeQuerySystemTime(&p->Stats.StartTime);
    p->Initialized = TRUE;
    *Protector = p;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Anti-unload initialized (Driver=%p, Unload nulled)\n",
               DriverObject);

    return STATUS_SUCCESS;
}

/**
 * @brief Shutdown anti-unload protection.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
AuShutdown(
    _Inout_ PAU_PROTECTOR Protector
    )
{
    LIST_ENTRY evictList;
    PLIST_ENTRY entry;
    PAU_UNLOAD_EVENT event;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized) {
        return;
    }

    //
    // STEP 1: Mark not initialized so OB callbacks bail out early.
    //
    Protector->Initialized = FALSE;

    //
    // STEP 2: Unregister OB callbacks.
    // After this, no NEW callbacks will fire. But in-flight ones
    // may still be executing on other CPUs.
    //
    AupUnregisterObCallbacks(Protector);

    //
    // STEP 3: Wait for all in-flight OB callbacks to complete.
    // ExWaitForRundownProtectionRelease blocks until every
    // ExAcquireRundownProtection holder calls ExReleaseRundownProtection.
    //
    ExWaitForRundownProtectionRelease(&Protector->RundownRef);

    //
    // STEP 4: Free event list (no lock needed — all callbacks are done).
    //
    InitializeListHead(&evictList);

    KeAcquireSpinLock(&Protector->EventLock, &oldIrql);
    while (!IsListEmpty(&Protector->EventList)) {
        entry = RemoveHeadList(&Protector->EventList);
        InsertTailList(&evictList, entry);
    }
    Protector->EventCount = 0;
    KeReleaseSpinLock(&Protector->EventLock, oldIrql);

    while (!IsListEmpty(&evictList)) {
        entry = RemoveHeadList(&evictList);
        event = CONTAINING_RECORD(entry, AU_UNLOAD_EVENT, ListEntry);
        AupFreeEvent(event);
    }

    //
    // STEP 5: Restore DriverUnload for controlled unload and deref.
    //
    if (Protector->ProtectedDriver != NULL) {
        Protector->ProtectedDriver->DriverUnload = Protector->OriginalUnload;
        ObDereferenceObject(Protector->ProtectedDriver);
        Protector->ProtectedDriver = NULL;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Anti-unload shutdown (attempts=%lld, blocked=%lld)\n",
               Protector->Stats.TotalAttempts,
               Protector->Stats.AttemptsBlocked);

    //
    // STEP 6: Free protector.
    //
    ExFreePoolWithTag(Protector, AU_POOL_TAG);
}

/**
 * @brief Set protection level.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AuSetLevel(
    _In_ PAU_PROTECTOR Protector,
    _In_ AU_PROTECTION_LEVEL Level
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    LONG oldLevel;

    PAGED_CODE();

    if (Protector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!Protector->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (Level > AuLevel_Full) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Serialize level transitions under exclusive lock.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Protector->ConfigLock);

    oldLevel = (LONG)InterlockedCompareExchange(&Protector->Level, 0, 0);

    if ((LONG)Level == oldLevel) {
        ExReleasePushLockExclusive(&Protector->ConfigLock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    //
    // Handle OB callback transitions.
    //
    if (Level >= AuLevel_Full && oldLevel < (LONG)AuLevel_Full) {
        status = AupRegisterObCallbacks(Protector);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] OB callback registration failed: 0x%X "
                       "(continuing at Basic level)\n", status);
            //
            // Don't fail the overall call — Basic protection remains.
            //
            InterlockedExchange(&Protector->Level, (LONG)AuLevel_Basic);
            ExReleasePushLockExclusive(&Protector->ConfigLock);
            KeLeaveCriticalRegion();
            return STATUS_SUCCESS;
        }
    } else if ((LONG)Level < (LONG)AuLevel_Full && oldLevel >= (LONG)AuLevel_Full) {
        AupUnregisterObCallbacks(Protector);
    }

    InterlockedExchange(&Protector->Level, (LONG)Level);

    ExReleasePushLockExclusive(&Protector->ConfigLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Protection level: %d -> %d\n", oldLevel, (LONG)Level);

    return STATUS_SUCCESS;
}

/**
 * @brief Register notification callback.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AuRegisterCallback(
    _In_ PAU_PROTECTOR Protector,
    _In_ AU_UNLOAD_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PAGED_CODE();

    if (Protector == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!Protector->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Protector->ConfigLock);

    Protector->UserCallback = Callback;
    Protector->CallbackContext = Context;

    ExReleasePushLockExclusive(&Protector->ConfigLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/**
 * @brief Register a PID as protected.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
AuProtectProcess(
    _In_ PAU_PROTECTOR Protector,
    _In_ HANDLE ProcessId
    )
{
    KIRQL oldIrql;
    ULONG i;

    if (Protector == NULL || !Protector->Initialized || ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Protector->PidLock, &oldIrql);

    //
    // Check for duplicate.
    //
    for (i = 0; i < Protector->ProtectedPidCount; i++) {
        if (Protector->ProtectedPids[i] == ProcessId) {
            KeReleaseSpinLock(&Protector->PidLock, oldIrql);
            return STATUS_DUPLICATE_OBJECTID;
        }
    }

    //
    // Check capacity.
    //
    if (Protector->ProtectedPidCount >= AU_MAX_PROTECTED_PIDS) {
        KeReleaseSpinLock(&Protector->PidLock, oldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Protector->ProtectedPids[Protector->ProtectedPidCount] = ProcessId;
    Protector->ProtectedPidCount++;

    KeReleaseSpinLock(&Protector->PidLock, oldIrql);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Protected PID registered: %p\n", ProcessId);

    return STATUS_SUCCESS;
}

/**
 * @brief Unregister a protected PID.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
AuUnprotectProcess(
    _In_ PAU_PROTECTOR Protector,
    _In_ HANDLE ProcessId
    )
{
    KIRQL oldIrql;
    ULONG i;

    if (Protector == NULL || !Protector->Initialized || ProcessId == NULL) {
        return;
    }

    KeAcquireSpinLock(&Protector->PidLock, &oldIrql);

    for (i = 0; i < Protector->ProtectedPidCount; i++) {
        if (Protector->ProtectedPids[i] == ProcessId) {
            //
            // Compact: move last element into this slot.
            //
            Protector->ProtectedPidCount--;
            if (i < Protector->ProtectedPidCount) {
                Protector->ProtectedPids[i] =
                    Protector->ProtectedPids[Protector->ProtectedPidCount];
            }
            Protector->ProtectedPids[Protector->ProtectedPidCount] = NULL;
            break;
        }
    }

    KeReleaseSpinLock(&Protector->PidLock, oldIrql);
}

/**
 * @brief Get recent events (deep copy into caller buffer).
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
AuGetEvents(
    _In_ PAU_PROTECTOR Protector,
    _Out_writes_to_(Max, *Count) PAU_UNLOAD_EVENT Events,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
{
    PLIST_ENTRY listEntry;
    PAU_UNLOAD_EVENT srcEvent;
    ULONG count = 0;
    KIRQL oldIrql;

    if (Protector == NULL || Events == NULL || Count == NULL || Max == 0) {
        if (Count) *Count = 0;
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    if (!Protector->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeAcquireSpinLock(&Protector->EventLock, &oldIrql);

    //
    // Walk from newest (tail) to oldest (head).
    // Deep-copy each event into the caller's flat buffer.
    //
    for (listEntry = Protector->EventList.Blink;
         listEntry != &Protector->EventList && count < Max;
         listEntry = listEntry->Blink)
    {
        srcEvent = CONTAINING_RECORD(listEntry, AU_UNLOAD_EVENT, ListEntry);

        //
        // Flat copy — AU_UNLOAD_EVENT has no embedded pointers.
        //
        Events[count].Type              = srcEvent->Type;
        Events[count].CallerProcessId   = srcEvent->CallerProcessId;
        Events[count].TargetProcessId   = srcEvent->TargetProcessId;
        Events[count].Timestamp         = srcEvent->Timestamp;
        Events[count].WasBlocked        = srcEvent->WasBlocked;

        RtlCopyMemory(Events[count].CallerImageName,
                       srcEvent->CallerImageName,
                       AU_PROCESS_NAME_LEN);

        //
        // ListEntry in copy is meaningless — zero it.
        //
        InitializeListHead(&Events[count].ListEntry);

        count++;
    }

    KeReleaseSpinLock(&Protector->EventLock, oldIrql);

    *Count = count;
    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE: EVENT MANAGEMENT
// ============================================================================

/**
 * @brief Create a flat event (no embedded pointers).
 *
 * Uses PsGetProcessImageFileName for caller name — safe at any IRQL,
 * returns ANSI 15-char max, no allocation needed.
 */
static PAU_UNLOAD_EVENT
AupCreateEvent(
    _In_ AU_UNLOAD_ATTEMPT Type,
    _In_ HANDLE CallerPid,
    _In_ HANDLE TargetPid,
    _In_ BOOLEAN WasBlocked
    )
{
    PAU_UNLOAD_EVENT event;
    PEPROCESS callerProcess = NULL;
    PCHAR imageName;

    event = (PAU_UNLOAD_EVENT)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(AU_UNLOAD_EVENT),
        AU_POOL_TAG_EVENT
    );
    if (event == NULL) {
        return NULL;
    }

    event->Type = Type;
    event->CallerProcessId = CallerPid;
    event->TargetProcessId = TargetPid;
    event->WasBlocked = WasBlocked;
    KeQuerySystemTime(&event->Timestamp);
    InitializeListHead(&event->ListEntry);

    //
    // Get caller image name (ANSI, max 15 chars, safe at any IRQL).
    //
    if (NT_SUCCESS(PsLookupProcessByProcessId(CallerPid, &callerProcess))) {
        imageName = PsGetProcessImageFileName(callerProcess);
        if (imageName != NULL) {
            RtlStringCchCopyA(event->CallerImageName,
                              AU_PROCESS_NAME_LEN,
                              imageName);
        }
        ObDereferenceObject(callerProcess);
    }

    return event;
}

/**
 * @brief Free an event (flat struct, single pool free).
 */
static VOID
AupFreeEvent(
    _In_ PAU_UNLOAD_EVENT Event
    )
{
    if (Event != NULL) {
        ExFreePoolWithTag(Event, AU_POOL_TAG_EVENT);
    }
}

/**
 * @brief Add event to history, evicting oldest if at capacity.
 *
 * Eviction list is built under the spin lock; pool frees happen
 * OUTSIDE the lock. No lock drop/re-acquire during eviction.
 */
static VOID
AupAddEvent(
    _In_ PAU_PROTECTOR Protector,
    _In_ PAU_UNLOAD_EVENT Event
    )
{
    KIRQL oldIrql;
    LIST_ENTRY evictList;
    PLIST_ENTRY entry;
    PAU_UNLOAD_EVENT oldEvent;

    InitializeListHead(&evictList);

    KeAcquireSpinLock(&Protector->EventLock, &oldIrql);

    //
    // Evict oldest entries to make room (under lock, no pool free here).
    //
    while (Protector->EventCount >= AU_MAX_EVENTS &&
           !IsListEmpty(&Protector->EventList))
    {
        entry = RemoveHeadList(&Protector->EventList);
        InsertTailList(&evictList, entry);
        Protector->EventCount--;
    }

    //
    // Insert new event.
    //
    InsertTailList(&Protector->EventList, &Event->ListEntry);
    Protector->EventCount++;

    KeReleaseSpinLock(&Protector->EventLock, oldIrql);

    //
    // Free evicted events OUTSIDE the lock.
    //
    while (!IsListEmpty(&evictList)) {
        entry = RemoveHeadList(&evictList);
        oldEvent = CONTAINING_RECORD(entry, AU_UNLOAD_EVENT, ListEntry);
        AupFreeEvent(oldEvent);
    }
}

// ============================================================================
// PRIVATE: OB CALLBACK REGISTRATION
// ============================================================================

/**
 * @brief Register process/thread OB callbacks.
 *
 * Uses per-instance registration structs (not global).
 * ConfigLock must be held exclusive by caller.
 */
static NTSTATUS
AupRegisterObCallbacks(
    _In_ PAU_PROTECTOR Protector
    )
{
    NTSTATUS status;

    if (Protector->ObCallbackHandle != NULL) {
        return STATUS_SUCCESS;
    }

    //
    // Process handle operations.
    //
    RtlZeroMemory(&Protector->ObOperations, sizeof(Protector->ObOperations));

    Protector->ObOperations[0].ObjectType = PsProcessType;
    Protector->ObOperations[0].Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    Protector->ObOperations[0].PreOperation = AupProcessPreCallback;
    Protector->ObOperations[0].PostOperation = NULL;

    //
    // Thread handle operations.
    //
    Protector->ObOperations[1].ObjectType = PsThreadType;
    Protector->ObOperations[1].Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    Protector->ObOperations[1].PreOperation = AupThreadPreCallback;
    Protector->ObOperations[1].PostOperation = NULL;

    //
    // Registration.
    //
    RtlZeroMemory(&Protector->ObRegistration, sizeof(Protector->ObRegistration));
    Protector->ObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    Protector->ObRegistration.OperationRegistrationCount = 2;
    Protector->ObRegistration.Altitude = Protector->ObAltitude;
    Protector->ObRegistration.RegistrationContext = Protector;
    Protector->ObRegistration.OperationRegistration = Protector->ObOperations;

    status = ObRegisterCallbacks(&Protector->ObRegistration,
                                 &Protector->ObCallbackHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] ObRegisterCallbacks failed: 0x%X\n", status);
        Protector->ObCallbackHandle = NULL;
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] OB callbacks registered\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Unregister OB callbacks. ConfigLock must be held exclusive by caller.
 */
static VOID
AupUnregisterObCallbacks(
    _In_ PAU_PROTECTOR Protector
    )
{
    if (Protector->ObCallbackHandle != NULL) {
        ObUnRegisterCallbacks(Protector->ObCallbackHandle);
        Protector->ObCallbackHandle = NULL;

#if DBG
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike] OB callbacks unregistered\n");
#endif
    }
}

// ============================================================================
// PRIVATE: PID LOOKUP
// ============================================================================

/**
 * @brief Check if a PID is in the protected table.
 *
 * Safe at any IRQL <= DISPATCH_LEVEL (spin lock).
 */
static BOOLEAN
AupIsPidProtected(
    _In_ PAU_PROTECTOR Protector,
    _In_ HANDLE ProcessId
    )
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&Protector->PidLock, &oldIrql);

    for (i = 0; i < Protector->ProtectedPidCount; i++) {
        if (Protector->ProtectedPids[i] == ProcessId) {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&Protector->PidLock, oldIrql);
    return found;
}

// ============================================================================
// PRIVATE: OB CALLBACKS
// ============================================================================

/**
 * @brief Process handle pre-operation callback.
 *
 * Strips dangerous access rights from handles targeting protected PIDs.
 * Skips kernel handles. Uses rundown protection to guarantee the
 * Protector struct remains valid for the duration of this callback.
 */
static OB_PREOP_CALLBACK_STATUS
AupProcessPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    PAU_PROTECTOR protector = (PAU_PROTECTOR)RegistrationContext;
    PEPROCESS targetProcess;
    HANDLE targetPid;
    HANDLE callerPid;
    ACCESS_MASK originalAccess;
    ACCESS_MASK stripped;
    AU_UNLOAD_ATTEMPT attemptType;
    PAU_UNLOAD_EVENT event;

    //
    // Acquire rundown protection. If this fails, the protector is
    // shutting down — bail immediately.
    //
    if (!ExAcquireRundownProtection(&protector->RundownRef)) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Quick checks.
    //
    if (!protector->Initialized ||
        InterlockedCompareExchange(&protector->Level, 0, 0) < (LONG)AuLevel_Full)
    {
        goto done;
    }

    //
    // Only process objects.
    //
    if (OperationInformation->ObjectType != *PsProcessType) {
        goto done;
    }

    //
    // Never filter kernel-mode handles — they're trusted and
    // stripping access can break WER, AV scanners, etc.
    //
    if (OperationInformation->KernelHandle) {
        goto done;
    }

    targetProcess = (PEPROCESS)OperationInformation->Object;
    targetPid = PsGetProcessId(targetProcess);
    callerPid = PsGetCurrentProcessId();

    //
    // Don't filter self-access.
    //
    if (callerPid == targetPid) {
        goto done;
    }

    //
    // Check if target PID is protected (PID-based, not name-based).
    //
    if (!AupIsPidProtected(protector, targetPid)) {
        goto done;
    }

    //
    // Get original desired access.
    //
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        originalAccess = OperationInformation->Parameters->
            CreateHandleInformation.OriginalDesiredAccess;
    } else {
        originalAccess = OperationInformation->Parameters->
            DuplicateHandleInformation.OriginalDesiredAccess;
    }

    //
    // Identify dangerous access bits.
    //
    stripped = originalAccess & (PROCESS_TERMINATE |
                                PROCESS_VM_WRITE |
                                PROCESS_VM_OPERATION |
                                PROCESS_CREATE_THREAD |
                                PROCESS_SUSPEND_RESUME);

    if (stripped == 0) {
        goto done;
    }

    InterlockedIncrement64(&protector->Stats.TotalAttempts);

    //
    // Strip dangerous access.
    //
    {
        ACCESS_MASK safe = originalAccess & ~stripped;

        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            OperationInformation->Parameters->
                CreateHandleInformation.DesiredAccess = safe;
        } else {
            OperationInformation->Parameters->
                DuplicateHandleInformation.DesiredAccess = safe;
        }
    }

    InterlockedIncrement64(&protector->Stats.AttemptsBlocked);

    //
    // Determine attempt type for logging.
    //
    attemptType = (stripped & PROCESS_TERMINATE)
                  ? AuAttempt_ProcessTerminate
                  : AuAttempt_ProcessInject;

#if DBG
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
               "[ShadowStrike] Blocked process access: caller=%p target=%p "
               "original=0x%X stripped=0x%X\n",
               callerPid, targetPid, originalAccess, stripped);
#endif

    //
    // Record event.
    //
    event = AupCreateEvent(attemptType, callerPid, targetPid, TRUE);
    if (event != NULL) {
        AupAddEvent(protector, event);
    }

    //
    // Notify registered callback.
    //
    AupNotifyCallback(protector, attemptType, callerPid);

done:
    ExReleaseRundownProtection(&protector->RundownRef);
    return OB_PREOP_SUCCESS;
}

/**
 * @brief Thread handle pre-operation callback.
 *
 * Strips dangerous access from handles targeting threads owned by
 * protected PIDs. Same architecture as the process callback.
 */
static OB_PREOP_CALLBACK_STATUS
AupThreadPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    PAU_PROTECTOR protector = (PAU_PROTECTOR)RegistrationContext;
    PETHREAD targetThread;
    PEPROCESS owningProcess;
    HANDLE ownerPid;
    HANDLE callerPid;
    ACCESS_MASK originalAccess;
    ACCESS_MASK stripped;
    PAU_UNLOAD_EVENT event;

    if (!ExAcquireRundownProtection(&protector->RundownRef)) {
        return OB_PREOP_SUCCESS;
    }

    if (!protector->Initialized ||
        InterlockedCompareExchange(&protector->Level, 0, 0) < (LONG)AuLevel_Full)
    {
        goto done;
    }

    if (OperationInformation->ObjectType != *PsThreadType) {
        goto done;
    }

    if (OperationInformation->KernelHandle) {
        goto done;
    }

    targetThread = (PETHREAD)OperationInformation->Object;
    owningProcess = IoThreadToProcess(targetThread);
    ownerPid = PsGetProcessId(owningProcess);
    callerPid = PsGetCurrentProcessId();

    if (callerPid == ownerPid) {
        goto done;
    }

    if (!AupIsPidProtected(protector, ownerPid)) {
        goto done;
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        originalAccess = OperationInformation->Parameters->
            CreateHandleInformation.OriginalDesiredAccess;
    } else {
        originalAccess = OperationInformation->Parameters->
            DuplicateHandleInformation.OriginalDesiredAccess;
    }

    stripped = originalAccess & (THREAD_TERMINATE |
                                THREAD_SUSPEND_RESUME |
                                THREAD_SET_CONTEXT |
                                THREAD_SET_INFORMATION);

    if (stripped == 0) {
        goto done;
    }

    {
        ACCESS_MASK safe = originalAccess & ~stripped;

        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            OperationInformation->Parameters->
                CreateHandleInformation.DesiredAccess = safe;
        } else {
            OperationInformation->Parameters->
                DuplicateHandleInformation.DesiredAccess = safe;
        }
    }

    InterlockedIncrement64(&protector->Stats.AttemptsBlocked);

    event = AupCreateEvent(
        (stripped & THREAD_TERMINATE) ? AuAttempt_ThreadTerminate : AuAttempt_ThreadInject,
        callerPid, ownerPid, TRUE);
    if (event != NULL) {
        AupAddEvent(protector, event);
    }

done:
    ExReleaseRundownProtection(&protector->RundownRef);
    return OB_PREOP_SUCCESS;
}

// ============================================================================
// PRIVATE: CALLBACK NOTIFICATION
// ============================================================================

/**
 * @brief Notify the registered user callback.
 *
 * The callback must not fault — no SEH wrapper. If it faults, the
 * bugcheck correctly points to the buggy callback, not to us.
 */
static VOID
AupNotifyCallback(
    _In_ PAU_PROTECTOR Protector,
    _In_ AU_UNLOAD_ATTEMPT AttemptType,
    _In_ HANDLE CallerPid
    )
{
    AU_UNLOAD_CALLBACK callback;
    PVOID context;

    //
    // Read callback/context atomically under shared lock.
    // We're in an OB callback context (≤ APC_LEVEL typically),
    // but push locks require KeEnterCriticalRegion.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Protector->ConfigLock);

    callback = Protector->UserCallback;
    context = Protector->CallbackContext;

    ExReleasePushLockShared(&Protector->ConfigLock);
    KeLeaveCriticalRegion();

    if (callback != NULL) {
        callback(AttemptType, CallerPid, context);
    }
}
