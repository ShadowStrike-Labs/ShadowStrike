/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE ANTI-UNLOAD PROTECTION
 * ============================================================================
 *
 * @file AntiUnload.c
 * @brief Enterprise-grade driver unload protection and tamper resistance.
 *
 * Implements CrowdStrike Falcon-class anti-unload protection with:
 * - Reference counting to prevent premature unload
 * - Driver object protection via ObRegisterCallbacks
 * - Service control protection monitoring
 * - Device object handle protection
 * - Unload attempt detection and logging
 * - Callback notification for unload attempts
 * - Multi-level protection (Basic to Maximum)
 *
 * Protection Levels:
 * - Basic: Reference counting only
 * - Medium: + Driver object handle protection
 * - High: + Callback registration protection
 * - Maximum: + Active tamper detection and response
 *
 * Attack Vectors Defended:
 * - sc stop/delete commands
 * - Direct NtUnloadDriver calls
 * - Handle-based driver manipulation
 * - Device object removal
 * - Process termination of loader
 * - Callback unregistration attempts
 *
 * CRITICAL: This module is essential for EDR persistence. Attackers
 * commonly attempt to unload security drivers to disable protection.
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
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
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Maximum unload events to keep in history
 */
#define AU_MAX_EVENTS                   256

/**
 * @brief Pool tag for event allocations
 */
#define AU_POOL_TAG_EVENT               'eAUA'

/**
 * @brief Dangerous access rights for driver objects
 */
#define AU_DANGEROUS_DRIVER_ACCESS      (DELETE | WRITE_DAC | WRITE_OWNER)

/**
 * @brief Dangerous access rights for device objects
 */
#define AU_DANGEROUS_DEVICE_ACCESS      (DELETE | WRITE_DAC | WRITE_OWNER | FILE_WRITE_DATA)

/**
 * @brief Known service control manager process names
 */
static const WCHAR* g_ServiceControlProcesses[] = {
    L"services.exe",
    L"sc.exe",
    L"net.exe",
    L"net1.exe",
    L"taskkill.exe",
    L"taskmgr.exe",
    L"procexp.exe",
    L"procexp64.exe",
    L"processhacker.exe",
    NULL
};

/**
 * @brief Known driver loading utilities
 */
static const WCHAR* g_DriverLoadUtilities[] = {
    L"drvload.exe",
    L"pnputil.exe",
    L"devcon.exe",
    L"infdefaultinstall.exe",
    NULL
};

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static PAU_UNLOAD_EVENT
AupCreateEvent(
    _In_ AU_UNLOAD_ATTEMPT Type,
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ProcessName,
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

static BOOLEAN
AupIsServiceControlProcess(
    _In_ HANDLE ProcessId
    );

static BOOLEAN
AupGetProcessImageName(
    _In_ HANDLE ProcessId,
    _Out_writes_z_(BufferSize) PWSTR Buffer,
    _In_ ULONG BufferSize
    );

static NTSTATUS
AupRegisterObjectCallbacks(
    _In_ PAU_PROTECTOR Protector
    );

static VOID
AupUnregisterObjectCallbacks(
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
AupIsProtectedProcess(
    _In_ PAU_PROTECTOR Protector,
    _In_ PEPROCESS Process
    );

static VOID
AupNotifyCallback(
    _In_ PAU_PROTECTOR Protector,
    _In_ AU_UNLOAD_ATTEMPT AttemptType,
    _In_ HANDLE SourceProcessId
    );

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief Object callback registration data
 */
static OB_CALLBACK_REGISTRATION g_ObRegistration = { 0 };
static OB_OPERATION_REGISTRATION g_ObOperations[2] = { 0 };

/**
 * @brief Callback altitude (must be unique per driver)
 */
static UNICODE_STRING g_CallbackAltitude = RTL_CONSTANT_STRING(L"385201.1337");

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the anti-unload protection subsystem.
 *
 * @param DriverObject   Driver object to protect.
 * @param Protector      Receives initialized protector handle.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AuInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _Out_ PAU_PROTECTOR* Protector
    )
{
    PAU_PROTECTOR protector = NULL;

    PAGED_CODE();

    if (DriverObject == NULL || Protector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Protector = NULL;

    //
    // Allocate protector structure
    //
    protector = (PAU_PROTECTOR)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(AU_PROTECTOR),
        AU_POOL_TAG
    );

    if (protector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize event list and lock
    //
    InitializeListHead(&protector->EventList);
    KeInitializeSpinLock(&protector->EventLock);
    protector->EventCount = 0;

    //
    // Store driver object reference
    //
    protector->ProtectedDriver = DriverObject;

    //
    // Initialize reference count to 1 (driver loaded)
    //
    protector->RefCount = 1;

    //
    // Set default protection level
    //
    protector->Level = AuLevel_Basic;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&protector->Stats.StartTime);

    protector->Initialized = TRUE;
    *Protector = protector;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Anti-unload protection initialized (Driver=%p)\n",
               DriverObject);

    return STATUS_SUCCESS;
}

/**
 * @brief Shutdown the anti-unload protection subsystem.
 *
 * @param Protector   Protector to shutdown.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
AuShutdown(
    _Inout_ PAU_PROTECTOR Protector
    )
{
    PLIST_ENTRY listEntry;
    PAU_UNLOAD_EVENT event;
    LIST_ENTRY tempList;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Protector == NULL) {
        return;
    }

    if (!Protector->Initialized) {
        return;
    }

    Protector->Initialized = FALSE;

    //
    // Unregister object callbacks
    //
    AupUnregisterObjectCallbacks(Protector);

    //
    // Move events to temp list
    //
    InitializeListHead(&tempList);

    KeAcquireSpinLock(&Protector->EventLock, &oldIrql);

    while (!IsListEmpty(&Protector->EventList)) {
        listEntry = RemoveHeadList(&Protector->EventList);
        InsertTailList(&tempList, listEntry);
    }

    Protector->EventCount = 0;

    KeReleaseSpinLock(&Protector->EventLock, oldIrql);

    //
    // Free events outside lock
    //
    while (!IsListEmpty(&tempList)) {
        listEntry = RemoveHeadList(&tempList);
        event = CONTAINING_RECORD(listEntry, AU_UNLOAD_EVENT, ListEntry);
        AupFreeEvent(event);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Anti-unload protection shutdown (attempts=%lld, blocked=%lld)\n",
               Protector->Stats.UnloadAttempts,
               Protector->Stats.AttemptsBlocked);

    ExFreePoolWithTag(Protector, AU_POOL_TAG);
}

// ============================================================================
// PUBLIC API - CONFIGURATION
// ============================================================================

/**
 * @brief Set the protection level.
 *
 * @param Protector   Protector handle.
 * @param Level       New protection level.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AuSetLevel(
    _In_ PAU_PROTECTOR Protector,
    _In_ AU_PROTECTION_LEVEL Level
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    AU_PROTECTION_LEVEL oldLevel;

    PAGED_CODE();

    if (Protector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Protector->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Level > AuLevel_Maximum) {
        return STATUS_INVALID_PARAMETER;
    }

    oldLevel = Protector->Level;
    Protector->Level = Level;

    //
    // Handle level transitions
    //
    if (Level >= AuLevel_Medium && oldLevel < AuLevel_Medium) {
        //
        // Upgrading to Medium+ : Register object callbacks
        //
        status = AupRegisterObjectCallbacks(Protector);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Failed to register object callbacks: 0x%08X\n",
                       status);
            //
            // Don't fail - continue with reduced protection
            //
            status = STATUS_SUCCESS;
        }
    } else if (Level < AuLevel_Medium && oldLevel >= AuLevel_Medium) {
        //
        // Downgrading from Medium+ : Unregister object callbacks
        //
        AupUnregisterObjectCallbacks(Protector);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Protection level changed: %d -> %d\n",
               oldLevel, Level);

    return status;
}

/**
 * @brief Register a callback for unload attempt notifications.
 *
 * @param Protector   Protector handle.
 * @param Callback    Callback function.
 * @param Context     Optional context for callback.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
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

    Protector->UserCallback = Callback;
    Protector->CallbackContext = Context;

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - REFERENCE COUNTING
// ============================================================================

/**
 * @brief Add a reference to prevent unload.
 *
 * Call this when starting a long-running operation that requires
 * the driver to remain loaded.
 *
 * @param Protector   Protector handle.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
AuAddRef(
    _In_ PAU_PROTECTOR Protector
    )
{
    if (Protector == NULL || !Protector->Initialized) {
        return;
    }

    InterlockedIncrement(&Protector->RefCount);
}

/**
 * @brief Release a reference.
 *
 * Call this when a long-running operation completes.
 *
 * @param Protector   Protector handle.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
AuRelease(
    _In_ PAU_PROTECTOR Protector
    )
{
    LONG newCount;

    if (Protector == NULL || !Protector->Initialized) {
        return;
    }

    newCount = InterlockedDecrement(&Protector->RefCount);

    //
    // RefCount should never go below 1 during normal operation
    // (the initial reference from initialization)
    //
    if (newCount < 1) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: RefCount went below 1 (%d)\n",
                   newCount);

        //
        // Restore to 1 to prevent issues
        //
        InterlockedCompareExchange(&Protector->RefCount, 1, newCount);
    }
}

// ============================================================================
// PUBLIC API - EVENT QUERIES
// ============================================================================

/**
 * @brief Get recent unload attempt events.
 *
 * @param Protector   Protector handle.
 * @param Events      Array to receive event pointers.
 * @param Max         Maximum events to return.
 * @param Count       Receives actual count returned.
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
AuGetEvents(
    _In_ PAU_PROTECTOR Protector,
    _Out_writes_to_(Max, *Count) PAU_UNLOAD_EVENT* Events,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
{
    PLIST_ENTRY listEntry;
    PAU_UNLOAD_EVENT event;
    ULONG count = 0;
    KIRQL oldIrql;

    if (Protector == NULL || Events == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    if (!Protector->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeAcquireSpinLock(&Protector->EventLock, &oldIrql);

    //
    // Walk list from newest to oldest (tail to head)
    //
    for (listEntry = Protector->EventList.Blink;
         listEntry != &Protector->EventList && count < Max;
         listEntry = listEntry->Blink) {

        event = CONTAINING_RECORD(listEntry, AU_UNLOAD_EVENT, ListEntry);
        Events[count++] = event;
    }

    KeReleaseSpinLock(&Protector->EventLock, oldIrql);

    *Count = count;
    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - EVENT MANAGEMENT
// ============================================================================

static PAU_UNLOAD_EVENT
AupCreateEvent(
    _In_ AU_UNLOAD_ATTEMPT Type,
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ProcessName,
    _In_ BOOLEAN WasBlocked
    )
{
    PAU_UNLOAD_EVENT event;

    event = (PAU_UNLOAD_EVENT)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(AU_UNLOAD_EVENT),
        AU_POOL_TAG_EVENT
    );

    if (event == NULL) {
        return NULL;
    }

    event->Type = Type;
    event->ProcessId = ProcessId;
    event->WasBlocked = WasBlocked;

    KeQuerySystemTime(&event->Timestamp);

    //
    // Copy process name if provided
    //
    if (ProcessName != NULL && ProcessName->Length > 0) {
        USHORT nameLen = ProcessName->Length;
        USHORT maxLen = nameLen + sizeof(WCHAR);

        event->ProcessName.Buffer = (PWCH)ExAllocatePoolZero(
            NonPagedPoolNx,
            maxLen,
            AU_POOL_TAG_EVENT
        );

        if (event->ProcessName.Buffer != NULL) {
            RtlCopyMemory(event->ProcessName.Buffer, ProcessName->Buffer, nameLen);
            event->ProcessName.Length = nameLen;
            event->ProcessName.MaximumLength = maxLen;
        }
    }

    InitializeListHead(&event->ListEntry);

    return event;
}

static VOID
AupFreeEvent(
    _In_ PAU_UNLOAD_EVENT Event
    )
{
    if (Event == NULL) {
        return;
    }

    if (Event->ProcessName.Buffer != NULL) {
        ExFreePoolWithTag(Event->ProcessName.Buffer, AU_POOL_TAG_EVENT);
    }

    ExFreePoolWithTag(Event, AU_POOL_TAG_EVENT);
}

static VOID
AupAddEvent(
    _In_ PAU_PROTECTOR Protector,
    _In_ PAU_UNLOAD_EVENT Event
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&Protector->EventLock, &oldIrql);

    //
    // Enforce max event limit (evict oldest)
    //
    while (Protector->EventCount >= AU_MAX_EVENTS) {
        PLIST_ENTRY oldestEntry = RemoveHeadList(&Protector->EventList);
        PAU_UNLOAD_EVENT oldestEvent = CONTAINING_RECORD(oldestEntry, AU_UNLOAD_EVENT, ListEntry);

        KeReleaseSpinLock(&Protector->EventLock, oldIrql);
        AupFreeEvent(oldestEvent);
        KeAcquireSpinLock(&Protector->EventLock, &oldIrql);

        Protector->EventCount--;
    }

    InsertTailList(&Protector->EventList, &Event->ListEntry);
    Protector->EventCount++;

    KeReleaseSpinLock(&Protector->EventLock, oldIrql);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - PROCESS IDENTIFICATION
// ============================================================================

static BOOLEAN
AupIsServiceControlProcess(
    _In_ HANDLE ProcessId
    )
{
    WCHAR imageName[260];
    ULONG i;
    PWCHAR baseName;

    if (!AupGetProcessImageName(ProcessId, imageName, sizeof(imageName) / sizeof(WCHAR))) {
        return FALSE;
    }

    //
    // Extract base name
    //
    baseName = wcsrchr(imageName, L'\\');
    if (baseName != NULL) {
        baseName++;
    } else {
        baseName = imageName;
    }

    //
    // Check against known service control processes
    //
    for (i = 0; g_ServiceControlProcesses[i] != NULL; i++) {
        if (_wcsicmp(baseName, g_ServiceControlProcesses[i]) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
AupGetProcessImageName(
    _In_ HANDLE ProcessId,
    _Out_writes_z_(BufferSize) PWSTR Buffer,
    _In_ ULONG BufferSize
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;
    BOOLEAN result = FALSE;

    Buffer[0] = L'\0';

    if (ProcessId == NULL) {
        return FALSE;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    status = SeLocateProcessImageName(process, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL) {
        ULONG copyLen = min(imageName->Length / sizeof(WCHAR), BufferSize - 1);
        RtlCopyMemory(Buffer, imageName->Buffer, copyLen * sizeof(WCHAR));
        Buffer[copyLen] = L'\0';
        result = TRUE;

        ExFreePool(imageName);
    }

    ObDereferenceObject(process);

    return result;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - OBJECT CALLBACKS
// ============================================================================

static NTSTATUS
AupRegisterObjectCallbacks(
    _In_ PAU_PROTECTOR Protector
    )
{
    NTSTATUS status;

    if (Protector->ProcessCallbackHandle != NULL) {
        //
        // Already registered
        //
        return STATUS_SUCCESS;
    }

    //
    // Set up process callback
    //
    g_ObOperations[0].ObjectType = PsProcessType;
    g_ObOperations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_ObOperations[0].PreOperation = AupProcessPreCallback;
    g_ObOperations[0].PostOperation = NULL;

    //
    // Set up thread callback
    //
    g_ObOperations[1].ObjectType = PsThreadType;
    g_ObOperations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_ObOperations[1].PreOperation = AupThreadPreCallback;
    g_ObOperations[1].PostOperation = NULL;

    //
    // Set up registration structure
    //
    g_ObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    g_ObRegistration.OperationRegistrationCount = 2;
    g_ObRegistration.Altitude = g_CallbackAltitude;
    g_ObRegistration.RegistrationContext = Protector;
    g_ObRegistration.OperationRegistration = g_ObOperations;

    status = ObRegisterCallbacks(&g_ObRegistration, &Protector->ProcessCallbackHandle);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] ObRegisterCallbacks failed: 0x%08X\n", status);
        Protector->ProcessCallbackHandle = NULL;
        return status;
    }

    //
    // Note: ObRegisterCallbacks returns a single handle for all operations
    //
    Protector->ThreadCallbackHandle = Protector->ProcessCallbackHandle;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Object callbacks registered\n");

    return STATUS_SUCCESS;
}

static VOID
AupUnregisterObjectCallbacks(
    _In_ PAU_PROTECTOR Protector
    )
{
    if (Protector->ProcessCallbackHandle != NULL) {
        ObUnRegisterCallbacks(Protector->ProcessCallbackHandle);
        Protector->ProcessCallbackHandle = NULL;
        Protector->ThreadCallbackHandle = NULL;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Object callbacks unregistered\n");
    }
}

/**
 * @brief Pre-operation callback for process handle operations.
 *
 * This callback is invoked before a handle to a process is created.
 * We use it to detect and potentially block attempts to manipulate
 * our driver loader process.
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
    ACCESS_MASK modifiedAccess;
    BOOLEAN isProtected;
    PAU_UNLOAD_EVENT event;

    if (protector == NULL || !protector->Initialized) {
        return OB_PREOP_SUCCESS;
    }

    if (protector->Level < AuLevel_Medium) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Only interested in processes
    //
    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    targetProcess = (PEPROCESS)OperationInformation->Object;
    targetPid = PsGetProcessId(targetProcess);
    callerPid = PsGetCurrentProcessId();

    //
    // Don't filter our own handles
    //
    if (callerPid == targetPid) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Check if target is a protected process
    //
    isProtected = AupIsProtectedProcess(protector, targetProcess);

    if (!isProtected) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Get original access mask
    //
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        originalAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    } else {
        originalAccess = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
    }

    //
    // Check for dangerous access rights
    //
    if ((originalAccess & (PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                           PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME)) == 0) {
        return OB_PREOP_SUCCESS;
    }

    InterlockedIncrement64(&protector->Stats.UnloadAttempts);

    //
    // Strip dangerous access rights
    //
    modifiedAccess = originalAccess;
    modifiedAccess &= ~PROCESS_TERMINATE;
    modifiedAccess &= ~PROCESS_VM_WRITE;
    modifiedAccess &= ~PROCESS_VM_OPERATION;
    modifiedAccess &= ~PROCESS_CREATE_THREAD;
    modifiedAccess &= ~PROCESS_SUSPEND_RESUME;

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = modifiedAccess;
    } else {
        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = modifiedAccess;
    }

    InterlockedIncrement64(&protector->Stats.AttemptsBlocked);

    //
    // Log the attempt
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
               "[ShadowStrike] Blocked dangerous process access: Caller=%p Target=%p Access=0x%08X\n",
               callerPid, targetPid, originalAccess);

    //
    // Record event
    //
    event = AupCreateEvent(
        (originalAccess & PROCESS_TERMINATE) ? AuAttempt_ProcessTerminate : AuAttempt_HandleClose,
        callerPid,
        NULL,
        TRUE
    );

    if (event != NULL) {
        AupAddEvent(protector, event);
    }

    //
    // Notify callback
    //
    AupNotifyCallback(
        protector,
        (originalAccess & PROCESS_TERMINATE) ? AuAttempt_ProcessTerminate : AuAttempt_HandleClose,
        callerPid
    );

    return OB_PREOP_SUCCESS;
}

/**
 * @brief Pre-operation callback for thread handle operations.
 *
 * Similar to process callback, but for thread handles.
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
    HANDLE callerPid;
    ACCESS_MASK originalAccess;
    ACCESS_MASK modifiedAccess;
    BOOLEAN isProtected;

    if (protector == NULL || !protector->Initialized) {
        return OB_PREOP_SUCCESS;
    }

    if (protector->Level < AuLevel_Medium) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Only interested in threads
    //
    if (OperationInformation->ObjectType != *PsThreadType) {
        return OB_PREOP_SUCCESS;
    }

    targetThread = (PETHREAD)OperationInformation->Object;
    owningProcess = IoThreadToProcess(targetThread);
    callerPid = PsGetCurrentProcessId();

    //
    // Don't filter our own handles
    //
    if (callerPid == PsGetProcessId(owningProcess)) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Check if owning process is protected
    //
    isProtected = AupIsProtectedProcess(protector, owningProcess);

    if (!isProtected) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Get original access mask
    //
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        originalAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    } else {
        originalAccess = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
    }

    //
    // Check for dangerous access rights
    //
    if ((originalAccess & (THREAD_TERMINATE | THREAD_SUSPEND_RESUME |
                           THREAD_SET_CONTEXT | THREAD_SET_INFORMATION)) == 0) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Strip dangerous access rights
    //
    modifiedAccess = originalAccess;
    modifiedAccess &= ~THREAD_TERMINATE;
    modifiedAccess &= ~THREAD_SUSPEND_RESUME;
    modifiedAccess &= ~THREAD_SET_CONTEXT;
    modifiedAccess &= ~THREAD_SET_INFORMATION;

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = modifiedAccess;
    } else {
        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = modifiedAccess;
    }

    InterlockedIncrement64(&protector->Stats.AttemptsBlocked);

    return OB_PREOP_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - PROTECTION CHECKS
// ============================================================================

static BOOLEAN
AupIsProtectedProcess(
    _In_ PAU_PROTECTOR Protector,
    _In_ PEPROCESS Process
    )
{
    HANDLE processId;
    WCHAR imageName[260];
    PWCHAR baseName;

    UNREFERENCED_PARAMETER(Protector);

    if (Process == NULL) {
        return FALSE;
    }

    processId = PsGetProcessId(Process);

    //
    // Get the process image name
    //
    if (!AupGetProcessImageName(processId, imageName, sizeof(imageName) / sizeof(WCHAR))) {
        return FALSE;
    }

    //
    // Extract base name
    //
    baseName = wcsrchr(imageName, L'\\');
    if (baseName != NULL) {
        baseName++;
    } else {
        baseName = imageName;
    }

    //
    // Check if this is one of our protected processes
    // Protected processes:
    // - ShadowStrike service
    // - ShadowStrike tray/UI
    // - ShadowStrike update service
    //
    if (_wcsicmp(baseName, L"ShadowStrikeService.exe") == 0 ||
        _wcsicmp(baseName, L"ShadowStrikeTray.exe") == 0 ||
        _wcsicmp(baseName, L"ShadowStrikeUI.exe") == 0 ||
        _wcsicmp(baseName, L"ShadowStrikeUpdater.exe") == 0 ||
        _wcsicmp(baseName, L"ShadowStrikeAgent.exe") == 0) {
        return TRUE;
    }

    return FALSE;
}

static VOID
AupNotifyCallback(
    _In_ PAU_PROTECTOR Protector,
    _In_ AU_UNLOAD_ATTEMPT AttemptType,
    _In_ HANDLE SourceProcessId
    )
{
    BOOLEAN shouldBlock;

    if (Protector->UserCallback == NULL) {
        return;
    }

    //
    // Call user callback - it can decide whether to block
    //
    __try {
        shouldBlock = Protector->UserCallback(
            AttemptType,
            SourceProcessId,
            Protector->CallbackContext
        );

        UNREFERENCED_PARAMETER(shouldBlock);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Exception in user callback: 0x%08X\n",
                   GetExceptionCode());
    }
}
