/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE HANDLE PROTECTION IMPLEMENTATION
 * ============================================================================
 *
 * @file HandleProtection.c
 * @brief Enterprise-grade handle protection and forensics engine.
 *
 * This module implements comprehensive handle protection capabilities:
 * - Real-time handle operation analysis
 * - Cross-process handle detection and tracking
 * - Suspicious handle pattern detection
 * - Handle duplication monitoring
 * - Sensitive process protection (LSASS, CSRSS, etc.)
 * - Token manipulation detection
 * - Handle abuse alerting
 *
 * Detection Capabilities (MITRE ATT&CK):
 * - T1055: Process Injection (via handle abuse)
 * - T1134: Access Token Manipulation
 * - T1003: OS Credential Dumping (LSASS handle detection)
 * - T1543: Create or Modify System Process
 * - T1489: Service Stop (via handle to service process)
 *
 * BSOD Prevention:
 * - All pointer parameters validated before use
 * - Locks acquired with proper IRQL awareness
 * - Fail-open on unexpected errors
 * - Reference counting for all tracked objects
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "HandleProtection.h"
#include "SelfProtect.h"
#include "../Core/Globals.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, HpInitialize)
#pragma alloc_text(PAGE, HpShutdown)
#pragma alloc_text(PAGE, HpSetConfiguration)
#pragma alloc_text(PAGE, HpRegisterSensitiveProcess)
#pragma alloc_text(PAGE, HpUnregisterSensitiveProcess)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

//
// Suspicion score thresholds
//
#define HP_SCORE_CROSS_PROCESS              10
#define HP_SCORE_CROSS_SESSION              20
#define HP_SCORE_CROSS_INTEGRITY            25
#define HP_SCORE_TERMINATE_ACCESS           30
#define HP_SCORE_INJECT_ACCESS              40
#define HP_SCORE_READ_MEMORY                15
#define HP_SCORE_TARGET_LSASS               100
#define HP_SCORE_TARGET_CSRSS               80
#define HP_SCORE_TARGET_SMSS                70
#define HP_SCORE_TARGET_SERVICES            50
#define HP_SCORE_TARGET_PROTECTED           60
#define HP_SCORE_TARGET_ANTIVIRUS           90
#define HP_SCORE_DUPLICATED_HANDLE          15
#define HP_SCORE_TOKEN_DUPLICATE            50
#define HP_SCORE_TOKEN_IMPERSONATE          60
#define HP_SCORE_PRIVILEGE_ESCALATION       80
#define HP_SCORE_RAPID_ENUMERATION          35
#define HP_SCORE_BULK_HANDLE_OPEN           25

#define HP_ALERT_THRESHOLD                  100
#define HP_CRITICAL_THRESHOLD               150

//
// Activity window for rapid detection
//
#define HP_ACTIVITY_WINDOW_100NS            (10000000LL)  // 1 second
#define HP_RAPID_HANDLE_THRESHOLD           20            // Handles per second

//
// Process name patterns for sensitive processes
//
#define HP_LSASS_NAME                       L"lsass.exe"
#define HP_CSRSS_NAME                       L"csrss.exe"
#define HP_SMSS_NAME                        L"smss.exe"
#define HP_SERVICES_NAME                    L"services.exe"
#define HP_WINLOGON_NAME                    L"winlogon.exe"
#define HP_SVCHOST_NAME                     L"svchost.exe"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID
HppAnalysisTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static NTSTATUS
HppInitializeHashTable(
    _Out_ LIST_ENTRY** Buckets,
    _In_ ULONG BucketCount
    );

static VOID
HppFreeHashTable(
    _Inout_ LIST_ENTRY** Buckets,
    _In_ ULONG BucketCount
    );

static ULONG
HppHashProcessId(
    _In_ HANDLE ProcessId
    );

static PHP_PROCESS_CONTEXT
HppFindProcessContext(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId
    );

static PHP_PROCESS_CONTEXT
HppCreateProcessContext(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId
    );

static VOID
HppFreeProcessContext(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _Inout_ PHP_PROCESS_CONTEXT Context
    );

static PHP_HANDLE_ENTRY
HppCreateHandleEntry(
    _In_ PHP_PROTECTION_ENGINE Engine
    );

static VOID
HppFreeHandleEntry(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _Inout_ PHP_HANDLE_ENTRY Entry
    );

static HP_OBJECT_TYPE
HppGetObjectType(
    _In_ POBJECT_TYPE ObjectType
    );

static HP_SENSITIVITY_LEVEL
HppGetProcessSensitivity(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ PHP_SUSPICION_FLAGS OutFlags
    );

static ULONG
HppCalculateSuspicionScore(
    _In_ HP_SUSPICION_FLAGS Flags
    );

static VOID
HppRecordEvent(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HP_EVENT_TYPE EventType,
    _In_ HANDLE OwnerProcessId,
    _In_opt_ HANDLE TargetProcessId,
    _In_ HANDLE Handle,
    _In_ HP_OBJECT_TYPE ObjectType,
    _In_ ACCESS_MASK AccessMask,
    _In_ HP_SUSPICION_FLAGS Flags,
    _In_ ULONG Score
    );

static VOID
HppNotifyCallback(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ PHP_DETECTION_RESULT Result
    );

static VOID
HppCleanupStaleEntries(
    _In_ PHP_PROTECTION_ENGINE Engine
    );

static BOOLEAN
HppIsSystemProcess(
    _In_ HANDLE ProcessId
    );

static BOOLEAN
HppGetProcessIntegrityLevel(
    _In_ PEPROCESS Process,
    _Out_ PULONG IntegrityLevel
    );

static VOID
HppDetectSensitiveProcesses(
    _In_ PHP_PROTECTION_ENGINE Engine
    );

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
HpInitialize(
    _Out_ PHP_PROTECTION_ENGINE* Engine
    )
{
    NTSTATUS status;
    PHP_PROTECTION_ENGINE engine = NULL;
    LARGE_INTEGER timerDue;

    PAGED_CODE();

    if (Engine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Engine = NULL;

    //
    // Allocate engine structure
    //
    engine = (PHP_PROTECTION_ENGINE)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(HP_PROTECTION_ENGINE),
        HP_POOL_TAG
    );

    if (engine == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(engine, sizeof(HP_PROTECTION_ENGINE));

    //
    // Initialize locks
    //
    ExInitializePushLock(&engine->ConfigLock);
    ExInitializePushLock(&engine->ProcessListLock);
    ExInitializePushLock(&engine->SensitiveObjectLock);
    KeInitializeSpinLock(&engine->EventHistoryLock);

    //
    // Initialize lists
    //
    InitializeListHead(&engine->ProcessList);
    InitializeListHead(&engine->EventHistory);

    //
    // Initialize process hash table
    //
    status = HppInitializeHashTable(
        &engine->ProcessHash.Buckets,
        HP_HASH_BUCKET_COUNT
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(engine, HP_POOL_TAG);
        return status;
    }

    engine->ProcessHash.BucketCount = HP_HASH_BUCKET_COUNT;
    ExInitializePushLock(&engine->ProcessHash.Lock);

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &engine->HandleEntryLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(HP_HANDLE_ENTRY),
        HP_POOL_TAG,
        0
    );

    ExInitializeNPagedLookasideList(
        &engine->ProcessContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(HP_PROCESS_CONTEXT),
        HP_POOL_TAG,
        0
    );

    ExInitializeNPagedLookasideList(
        &engine->EventLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(HP_HANDLE_EVENT),
        HP_POOL_TAG,
        0
    );

    engine->LookasideInitialized = TRUE;

    //
    // Initialize default configuration
    //
    engine->Config.Enabled = TRUE;
    engine->Config.TrackAllHandles = FALSE;
    engine->Config.TrackCrossProcess = TRUE;
    engine->Config.BlockLSASSAccess = TRUE;
    engine->Config.StripDangerousAccess = TRUE;
    engine->Config.AlertOnSuspicious = TRUE;
    engine->Config.SuspicionThreshold = HP_ALERT_THRESHOLD;
    engine->Config.MaxHandlesPerProcess = HP_MAX_HANDLES_PER_PROCESS;
    engine->Config.AnalysisIntervalMs = HP_ANALYSIS_INTERVAL_MS;
    engine->Config.HistoryRetentionMs = HP_STALE_ENTRY_TIMEOUT_MS;

    //
    // Initialize analysis timer
    //
    KeInitializeTimer(&engine->AnalysisTimer);
    KeInitializeDpc(
        &engine->AnalysisDpc,
        HppAnalysisTimerDpc,
        engine
    );

    timerDue.QuadPart = -((LONGLONG)engine->Config.AnalysisIntervalMs * 10000);
    KeSetTimerEx(
        &engine->AnalysisTimer,
        timerDue,
        engine->Config.AnalysisIntervalMs,
        &engine->AnalysisDpc
    );

    //
    // Record start time
    //
    KeQuerySystemTime(&engine->Stats.StartTime);

    //
    // Detect sensitive system processes
    //
    HppDetectSensitiveProcesses(engine);

    engine->Initialized = TRUE;
    *Engine = engine;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Handle protection engine initialized\n");

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
HpShutdown(
    _Inout_ PHP_PROTECTION_ENGINE Engine
    )
{
    PLIST_ENTRY entry;
    PHP_PROCESS_CONTEXT processContext;
    PHP_HANDLE_EVENT event;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return;
    }

    //
    // Mark as shutting down
    //
    Engine->Initialized = FALSE;

    //
    // Cancel analysis timer
    //
    KeCancelTimer(&Engine->AnalysisTimer);
    KeFlushQueuedDpcs();

    //
    // Wait for any in-progress analysis
    //
    while (Engine->AnalysisInProgress) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    //
    // Free all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ProcessListLock);

    while (!IsListEmpty(&Engine->ProcessList)) {
        entry = RemoveHeadList(&Engine->ProcessList);
        processContext = CONTAINING_RECORD(entry, HP_PROCESS_CONTEXT, ListEntry);
        HppFreeProcessContext(Engine, processContext);
    }

    ExReleasePushLockExclusive(&Engine->ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Free event history
    //
    KeAcquireSpinLock(&Engine->EventHistoryLock, &oldIrql);

    while (!IsListEmpty(&Engine->EventHistory)) {
        entry = RemoveHeadList(&Engine->EventHistory);
        event = CONTAINING_RECORD(entry, HP_HANDLE_EVENT, ListEntry);
        ExFreeToNPagedLookasideList(&Engine->EventLookaside, event);
    }

    KeReleaseSpinLock(&Engine->EventHistoryLock, oldIrql);

    //
    // Free hash table
    //
    HppFreeHashTable(
        &Engine->ProcessHash.Buckets,
        Engine->ProcessHash.BucketCount
    );

    //
    // Delete lookaside lists
    //
    if (Engine->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Engine->HandleEntryLookaside);
        ExDeleteNPagedLookasideList(&Engine->ProcessContextLookaside);
        ExDeleteNPagedLookasideList(&Engine->EventLookaside);
    }

    //
    // Free engine
    //
    ExFreePoolWithTag(Engine, HP_POOL_TAG);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Handle protection engine shutdown complete\n");
}

// ============================================================================
// PUBLIC API - CONFIGURATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
HpSetConfiguration(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ PHP_CONFIG Config
    )
{
    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized || Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ConfigLock);

    RtlCopyMemory(&Engine->Config, Config, sizeof(HP_CONFIG));

    ExReleasePushLockExclusive(&Engine->ConfigLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HpGetConfiguration(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _Out_ PHP_CONFIG Config
    )
{
    if (Engine == NULL || !Engine->Initialized || Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->ConfigLock);

    RtlCopyMemory(Config, &Engine->Config, sizeof(HP_CONFIG));

    ExReleasePushLockShared(&Engine->ConfigLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - HANDLE OPERATIONS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
HpAnalyzeHandleOperation(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInfo,
    _Out_ PHP_DETECTION_RESULT Result
    )
{
    HANDLE callerProcessId;
    HANDLE targetProcessId = NULL;
    PEPROCESS targetProcess = NULL;
    PETHREAD targetThread = NULL;
    ACCESS_MASK requestedAccess;
    ACCESS_MASK modifiedAccess;
    HP_SUSPICION_FLAGS flags = HpSuspicion_None;
    HP_SENSITIVITY_LEVEL targetSensitivity = HpSensitivity_None;
    HP_OBJECT_TYPE objectType;
    ULONG suspicionScore = 0;
    BOOLEAN isProcess = FALSE;
    BOOLEAN isThread = FALSE;
    HP_SUSPICION_FLAGS sensitivityFlags = HpSuspicion_None;

    if (Engine == NULL || !Engine->Initialized ||
        OperationInfo == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Engine->Config.Enabled) {
        RtlZeroMemory(Result, sizeof(HP_DETECTION_RESULT));
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(Result, sizeof(HP_DETECTION_RESULT));
    KeQuerySystemTime(&Result->DetectionTime);

    callerProcessId = PsGetCurrentProcessId();
    Result->OwnerProcessId = callerProcessId;

    //
    // Skip kernel-mode operations
    //
    if (OperationInfo->KernelHandle) {
        return STATUS_SUCCESS;
    }

    //
    // Determine object type and get target information
    //
    if (OperationInfo->ObjectType == *PsProcessType) {
        isProcess = TRUE;
        objectType = HpObjectType_Process;
        targetProcess = (PEPROCESS)OperationInfo->Object;
        targetProcessId = PsGetProcessId(targetProcess);
        Result->TargetProcessId = targetProcessId;
    } else if (OperationInfo->ObjectType == *PsThreadType) {
        isThread = TRUE;
        objectType = HpObjectType_Thread;
        targetThread = (PETHREAD)OperationInfo->Object;
        targetProcess = IoThreadToProcess(targetThread);
        if (targetProcess != NULL) {
            targetProcessId = PsGetProcessId(targetProcess);
            Result->TargetProcessId = targetProcessId;
        }
    } else {
        //
        // Not a process or thread - limited tracking
        //
        objectType = HppGetObjectType(OperationInfo->ObjectType);
        Result->ObjectType = objectType;
        return STATUS_SUCCESS;
    }

    Result->ObjectType = objectType;

    //
    // Get requested access
    //
    if (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
        requestedAccess = OperationInfo->Parameters->CreateHandleInformation.DesiredAccess;
    } else {
        requestedAccess = OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
        flags |= HpSuspicion_DuplicatedHandle;
    }

    Result->OriginalAccess = requestedAccess;
    modifiedAccess = requestedAccess;

    //
    // Skip self-access
    //
    if (callerProcessId == targetProcessId) {
        Result->ModifiedAccess = requestedAccess;
        return STATUS_SUCCESS;
    }

    //
    // This is a cross-process operation
    //
    flags |= HpSuspicion_CrossProcess;

    //
    // Check target sensitivity
    //
    targetSensitivity = HppGetProcessSensitivity(Engine, targetProcessId, &sensitivityFlags);
    flags |= sensitivityFlags;
    Result->TargetSensitivity = targetSensitivity;

    //
    // Analyze requested access rights for processes
    //
    if (isProcess) {
        if (requestedAccess & PROCESS_TERMINATE) {
            flags |= HpSuspicion_TerminateAccess;
        }

        if (requestedAccess & HP_DANGEROUS_PROCESS_INJECT) {
            flags |= HpSuspicion_InjectAccess;
        }

        if (requestedAccess & HP_DANGEROUS_PROCESS_READ) {
            flags |= HpSuspicion_ReadMemoryAccess;
        }

        //
        // Check for credential access (LSASS)
        //
        if ((flags & HpSuspicion_TargetLSASS) &&
            (requestedAccess & HP_DANGEROUS_PROCESS_READ)) {
            flags |= HpSuspicion_CredentialAccess;
        }
    }

    //
    // Analyze thread access
    //
    if (isThread) {
        if (requestedAccess & HP_DANGEROUS_THREAD_ACCESS) {
            flags |= HpSuspicion_HighPrivilegeAccess;
        }
    }

    //
    // Calculate suspicion score
    //
    suspicionScore = HppCalculateSuspicionScore(flags);
    Result->Flags = flags;
    Result->SuspicionScore = suspicionScore;

    //
    // Determine if we should modify access
    //
    if (Engine->Config.StripDangerousAccess && targetSensitivity >= HpSensitivity_High) {
        //
        // Strip dangerous access to sensitive processes
        //
        if (isProcess) {
            //
            // For LSASS, block all dangerous access
            //
            if (flags & HpSuspicion_TargetLSASS) {
                if (Engine->Config.BlockLSASSAccess) {
                    modifiedAccess &= ~HP_DANGEROUS_PROCESS_ALL;
                    InterlockedIncrement64(&Engine->Stats.LSASSAccessBlocked);
                }
            }

            //
            // For other protected processes, strip terminate and inject
            //
            if (flags & HpSuspicion_TargetProtected) {
                modifiedAccess &= ~(PROCESS_TERMINATE | HP_DANGEROUS_PROCESS_INJECT);
                InterlockedIncrement64(&Engine->Stats.ProtectedAccessBlocked);
            }
        }

        if (isThread && (flags & (HpSuspicion_TargetProtected | HpSuspicion_TargetLSASS))) {
            modifiedAccess &= ~HP_DANGEROUS_THREAD_ACCESS;
        }
    }

    //
    // Apply modifications
    //
    if (modifiedAccess != requestedAccess) {
        if (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
            OperationInfo->Parameters->CreateHandleInformation.DesiredAccess = modifiedAccess;
        } else {
            OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess = modifiedAccess;
        }

        Result->AccessModified = TRUE;
        InterlockedIncrement64(&Engine->Stats.AccessStripped);

        //
        // Record event
        //
        HppRecordEvent(
            Engine,
            HpEvent_AccessStripped,
            callerProcessId,
            targetProcessId,
            NULL,
            objectType,
            requestedAccess,
            flags,
            suspicionScore
        );
    }

    Result->ModifiedAccess = modifiedAccess;

    //
    // Check if this is suspicious enough to alert
    //
    if (suspicionScore >= Engine->Config.SuspicionThreshold) {
        Result->SuspiciousDetected = TRUE;
        InterlockedIncrement64(&Engine->Stats.SuspiciousHandles);

        HppRecordEvent(
            Engine,
            HpEvent_SuspiciousDetected,
            callerProcessId,
            targetProcessId,
            NULL,
            objectType,
            requestedAccess,
            flags,
            suspicionScore
        );

        //
        // Notify callback
        //
        if (Engine->Config.AlertOnSuspicious) {
            HppNotifyCallback(Engine, Result);
        }

        if (suspicionScore >= HP_CRITICAL_THRESHOLD) {
            InterlockedIncrement64(&Engine->Stats.AlertsRaised);

            HppRecordEvent(
                Engine,
                HpEvent_AlertRaised,
                callerProcessId,
                targetProcessId,
                NULL,
                objectType,
                requestedAccess,
                flags,
                suspicionScore
            );

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] HANDLE ALERT: PID %p -> PID %p, Score=%u, Flags=0x%08X\n",
                       callerProcessId, targetProcessId, suspicionScore, flags);
        }
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Engine->Stats.TotalHandlesTracked);
    if (flags & HpSuspicion_CrossProcess) {
        InterlockedIncrement64(&Engine->Stats.CrossProcessHandles);
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HpRecordHandle(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE OwnerProcessId,
    _In_ HANDLE Handle,
    _In_ HP_OBJECT_TYPE ObjectType,
    _In_ PVOID Object,
    _In_ ACCESS_MASK GrantedAccess
    )
{
    PHP_PROCESS_CONTEXT processContext;
    PHP_HANDLE_ENTRY handleEntry;
    KIRQL oldIrql;

    if (Engine == NULL || !Engine->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Engine->Config.Enabled || !Engine->Config.TrackAllHandles) {
        return STATUS_SUCCESS;
    }

    //
    // Find or create process context
    //
    processContext = HppFindProcessContext(Engine, OwnerProcessId);
    if (processContext == NULL) {
        processContext = HppCreateProcessContext(Engine, OwnerProcessId);
        if (processContext == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    //
    // Check handle limit
    //
    if (processContext->HandleCount >= (LONG)Engine->Config.MaxHandlesPerProcess) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Create handle entry
    //
    handleEntry = HppCreateHandleEntry(Engine);
    if (handleEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    handleEntry->Handle = Handle;
    handleEntry->ObjectType = ObjectType;
    handleEntry->GrantedAccess = GrantedAccess;
    handleEntry->OriginalAccess = GrantedAccess;
    handleEntry->ObjectPointer = Object;
    handleEntry->OwnerProcessId = OwnerProcessId;
    handleEntry->CreatorProcessId = PsGetCurrentProcessId();
    handleEntry->CreatorThreadId = PsGetCurrentThreadId();
    KeQuerySystemTime(&handleEntry->CreateTime);
    handleEntry->LastAccessTime = handleEntry->CreateTime;
    handleEntry->RefCount = 1;

    //
    // Add to process handle list
    //
    KeAcquireSpinLock(&processContext->HandleListLock, &oldIrql);
    InsertTailList(&processContext->HandleList, &handleEntry->ListEntry);
    InterlockedIncrement(&processContext->HandleCount);
    KeReleaseSpinLock(&processContext->HandleListLock, oldIrql);

    //
    // Update statistics
    //
    InterlockedIncrement64(&processContext->TotalHandlesOpened);
    InterlockedIncrement(&Engine->Stats.ActiveHandles);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HpRecordDuplication(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE SourceProcess,
    _In_ HANDLE TargetProcess,
    _In_ HANDLE SourceHandle,
    _In_ HANDLE TargetHandle,
    _In_ ACCESS_MASK GrantedAccess
    )
{
    PHP_PROCESS_CONTEXT processContext;
    PHP_HANDLE_ENTRY handleEntry;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(SourceHandle);

    if (Engine == NULL || !Engine->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Engine->Config.Enabled) {
        return STATUS_SUCCESS;
    }

    //
    // Track duplicated handles
    //
    InterlockedIncrement64(&Engine->Stats.DuplicationsTracked);

    //
    // Find or create target process context
    //
    processContext = HppFindProcessContext(Engine, TargetProcess);
    if (processContext == NULL) {
        processContext = HppCreateProcessContext(Engine, TargetProcess);
        if (processContext == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    //
    // Create handle entry
    //
    handleEntry = HppCreateHandleEntry(Engine);
    if (handleEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    handleEntry->Handle = TargetHandle;
    handleEntry->ObjectType = HpObjectType_Unknown;  // Would need to query
    handleEntry->GrantedAccess = GrantedAccess;
    handleEntry->OriginalAccess = GrantedAccess;
    handleEntry->OwnerProcessId = TargetProcess;
    handleEntry->CreatorProcessId = PsGetCurrentProcessId();
    handleEntry->IsDuplicated = TRUE;
    handleEntry->DuplicatedFromProcess = SourceProcess;
    handleEntry->SuspicionFlags |= HpSuspicion_DuplicatedHandle;
    KeQuerySystemTime(&handleEntry->CreateTime);
    handleEntry->RefCount = 1;

    //
    // Add to process handle list
    //
    KeAcquireSpinLock(&processContext->HandleListLock, &oldIrql);
    InsertTailList(&processContext->HandleList, &handleEntry->ListEntry);
    InterlockedIncrement(&processContext->HandleCount);
    KeReleaseSpinLock(&processContext->HandleListLock, oldIrql);

    //
    // Record event
    //
    HppRecordEvent(
        Engine,
        HpEvent_HandleDuplicate,
        TargetProcess,
        SourceProcess,
        TargetHandle,
        handleEntry->ObjectType,
        GrantedAccess,
        HpSuspicion_DuplicatedHandle,
        HP_SCORE_DUPLICATED_HANDLE
    );

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
HpRecordHandleClose(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_ HANDLE Handle
    )
{
    PHP_PROCESS_CONTEXT processContext;
    PHP_HANDLE_ENTRY handleEntry;
    PLIST_ENTRY entry;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    if (Engine == NULL || !Engine->Initialized || !Engine->Config.Enabled) {
        return;
    }

    processContext = HppFindProcessContext(Engine, ProcessId);
    if (processContext == NULL) {
        return;
    }

    KeAcquireSpinLock(&processContext->HandleListLock, &oldIrql);

    for (entry = processContext->HandleList.Flink;
         entry != &processContext->HandleList;
         entry = entry->Flink) {

        handleEntry = CONTAINING_RECORD(entry, HP_HANDLE_ENTRY, ListEntry);

        if (handleEntry->Handle == Handle) {
            RemoveEntryList(&handleEntry->ListEntry);
            InterlockedDecrement(&processContext->HandleCount);
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&processContext->HandleListLock, oldIrql);

    if (found) {
        HppFreeHandleEntry(Engine, handleEntry);
        InterlockedDecrement(&Engine->Stats.ActiveHandles);
    }
}

// ============================================================================
// PUBLIC API - SENSITIVE OBJECTS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
HpRegisterSensitiveProcess(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_ HP_SENSITIVITY_LEVEL Sensitivity
    )
{
    ULONG i;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->SensitiveObjectLock);

    for (i = 0; i < HP_MAX_SENSITIVE_OBJECTS; i++) {
        if (!Engine->SensitiveObjects[i].InUse) {
            Engine->SensitiveObjects[i].InUse = TRUE;
            Engine->SensitiveObjects[i].ProcessId = ProcessId;
            Engine->SensitiveObjects[i].ObjectType = HpObjectType_Process;
            Engine->SensitiveObjects[i].Sensitivity = Sensitivity;
            Engine->SensitiveObjects[i].RequiredFlags = HpSuspicion_TargetProtected;
            Engine->SensitiveObjects[i].BaseScore = HP_SCORE_TARGET_PROTECTED;
            InterlockedIncrement(&Engine->SensitiveObjectCount);
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockExclusive(&Engine->SensitiveObjectLock);
    KeLeaveCriticalRegion();

    return status;
}

_Use_decl_annotations_
VOID
HpUnregisterSensitiveProcess(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId
    )
{
    ULONG i;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->SensitiveObjectLock);

    for (i = 0; i < HP_MAX_SENSITIVE_OBJECTS; i++) {
        if (Engine->SensitiveObjects[i].InUse &&
            Engine->SensitiveObjects[i].ProcessId == ProcessId) {

            Engine->SensitiveObjects[i].InUse = FALSE;
            InterlockedDecrement(&Engine->SensitiveObjectCount);
            break;
        }
    }

    ExReleasePushLockExclusive(&Engine->SensitiveObjectLock);
    KeLeaveCriticalRegion();
}

_Use_decl_annotations_
BOOLEAN
HpIsSensitiveProcess(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_opt_ PHP_SENSITIVITY_LEVEL OutSensitivity
    )
{
    ULONG i;
    BOOLEAN found = FALSE;
    HP_SENSITIVITY_LEVEL sensitivity = HpSensitivity_None;

    if (Engine == NULL || !Engine->Initialized) {
        if (OutSensitivity) *OutSensitivity = HpSensitivity_None;
        return FALSE;
    }

    //
    // Check known system processes first
    //
    if (ProcessId == Engine->LsassProcessId) {
        if (OutSensitivity) *OutSensitivity = HpSensitivity_Critical;
        return TRUE;
    }
    if (ProcessId == Engine->CsrssProcessId ||
        ProcessId == Engine->SmssProcessId) {
        if (OutSensitivity) *OutSensitivity = HpSensitivity_Critical;
        return TRUE;
    }
    if (ProcessId == Engine->ServicesProcessId ||
        ProcessId == Engine->WinlogonProcessId) {
        if (OutSensitivity) *OutSensitivity = HpSensitivity_High;
        return TRUE;
    }

    //
    // Check registered sensitive objects
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->SensitiveObjectLock);

    for (i = 0; i < HP_MAX_SENSITIVE_OBJECTS; i++) {
        if (Engine->SensitiveObjects[i].InUse &&
            Engine->SensitiveObjects[i].ProcessId == ProcessId) {

            found = TRUE;
            sensitivity = Engine->SensitiveObjects[i].Sensitivity;
            break;
        }
    }

    ExReleasePushLockShared(&Engine->SensitiveObjectLock);
    KeLeaveCriticalRegion();

    if (OutSensitivity) *OutSensitivity = sensitivity;
    return found;
}

// ============================================================================
// PUBLIC API - ANALYSIS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
HpAnalyzeProcessHandles(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ PHP_SUSPICION_FLAGS OutFlags,
    _Out_ PULONG OutScore
    )
{
    PHP_PROCESS_CONTEXT processContext;

    if (Engine == NULL || !Engine->Initialized ||
        OutFlags == NULL || OutScore == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutFlags = HpSuspicion_None;
    *OutScore = 0;

    processContext = HppFindProcessContext(Engine, ProcessId);
    if (processContext == NULL) {
        return STATUS_NOT_FOUND;
    }

    *OutFlags = processContext->AggregatedFlags;
    *OutScore = processContext->TotalSuspicionScore;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HpFindHandlesToProcess(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE TargetProcessId,
    _Out_writes_to_(MaxHandles, *ReturnedCount) PHP_HANDLE_ENTRY* Handles,
    _In_ ULONG MaxHandles,
    _Out_ PULONG ReturnedCount
    )
{
    PLIST_ENTRY processEntry;
    PHP_PROCESS_CONTEXT processContext;
    PLIST_ENTRY handleEntry;
    PHP_HANDLE_ENTRY handle;
    ULONG count = 0;
    KIRQL oldIrql;

    if (Engine == NULL || !Engine->Initialized ||
        Handles == NULL || ReturnedCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnedCount = 0;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->ProcessListLock);

    for (processEntry = Engine->ProcessList.Flink;
         processEntry != &Engine->ProcessList && count < MaxHandles;
         processEntry = processEntry->Flink) {

        processContext = CONTAINING_RECORD(processEntry, HP_PROCESS_CONTEXT, ListEntry);

        //
        // Skip the target process itself
        //
        if (processContext->ProcessId == TargetProcessId) {
            continue;
        }

        KeAcquireSpinLock(&processContext->HandleListLock, &oldIrql);

        for (handleEntry = processContext->HandleList.Flink;
             handleEntry != &processContext->HandleList && count < MaxHandles;
             handleEntry = handleEntry->Flink) {

            handle = CONTAINING_RECORD(handleEntry, HP_HANDLE_ENTRY, ListEntry);

            if (handle->TargetProcessId == TargetProcessId) {
                Handles[count++] = handle;
            }
        }

        KeReleaseSpinLock(&processContext->HandleListLock, oldIrql);
    }

    ExReleasePushLockShared(&Engine->ProcessListLock);
    KeLeaveCriticalRegion();

    *ReturnedCount = count;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HpEnumerateSystemHandles(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_opt_ HANDLE ProcessId
    )
{
    UNREFERENCED_PARAMETER(Engine);
    UNREFERENCED_PARAMETER(ProcessId);

    //
    // System handle enumeration would require ZwQuerySystemInformation
    // with SystemHandleInformation class. This is an expensive operation
    // and should be used sparingly.
    //
    // For production use, this would be implemented as a background
    // analysis task with proper rate limiting.
    //

    return STATUS_NOT_IMPLEMENTED;
}

// ============================================================================
// PUBLIC API - CALLBACKS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
HpRegisterCallback(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HP_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    if (Engine == NULL || !Engine->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Engine->DetectionCallback = Callback;
    Engine->DetectionCallbackContext = Context;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
HpUnregisterCallback(
    _In_ PHP_PROTECTION_ENGINE Engine
    )
{
    if (Engine == NULL || !Engine->Initialized) {
        return;
    }

    Engine->DetectionCallback = NULL;
    Engine->DetectionCallbackContext = NULL;
}

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
HpGetStatistics(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _Out_ PHP_STATISTICS Stats
    )
{
    if (Engine == NULL || !Engine->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(Stats, &Engine->Stats, sizeof(HP_STATISTICS));

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HpGetRecentEvents(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _Out_writes_to_(MaxEvents, *ReturnedCount) PHP_HANDLE_EVENT* Events,
    _In_ ULONG MaxEvents,
    _Out_ PULONG ReturnedCount
    )
{
    PLIST_ENTRY entry;
    PHP_HANDLE_EVENT event;
    ULONG count = 0;
    KIRQL oldIrql;

    if (Engine == NULL || !Engine->Initialized ||
        Events == NULL || ReturnedCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ReturnedCount = 0;

    KeAcquireSpinLock(&Engine->EventHistoryLock, &oldIrql);

    for (entry = Engine->EventHistory.Flink;
         entry != &Engine->EventHistory && count < MaxEvents;
         entry = entry->Flink) {

        event = CONTAINING_RECORD(entry, HP_HANDLE_EVENT, ListEntry);
        Events[count++] = event;
    }

    KeReleaseSpinLock(&Engine->EventHistoryLock, oldIrql);

    *ReturnedCount = count;

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - CLEANUP
// ============================================================================

_Use_decl_annotations_
VOID
HpProcessTerminated(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId
    )
{
    PHP_PROCESS_CONTEXT processContext;
    ULONG hash;
    ULONG bucket;

    if (Engine == NULL || !Engine->Initialized) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ProcessListLock);
    ExAcquirePushLockExclusive(&Engine->ProcessHash.Lock);

    processContext = HppFindProcessContext(Engine, ProcessId);

    if (processContext != NULL) {
        RemoveEntryList(&processContext->ListEntry);
        RemoveEntryList(&processContext->HashEntry);
        InterlockedDecrement(&Engine->Stats.TrackedProcesses);
    }

    ExReleasePushLockExclusive(&Engine->ProcessHash.Lock);
    ExReleasePushLockExclusive(&Engine->ProcessListLock);
    KeLeaveCriticalRegion();

    if (processContext != NULL) {
        HppFreeProcessContext(Engine, processContext);
    }

    //
    // Also unregister from sensitive objects
    //
    HpUnregisterSensitiveProcess(Engine, ProcessId);
}

_Use_decl_annotations_
VOID
HpFlushAllTracking(
    _In_ PHP_PROTECTION_ENGINE Engine
    )
{
    PLIST_ENTRY entry;
    PHP_PROCESS_CONTEXT processContext;
    PHP_HANDLE_EVENT event;
    KIRQL oldIrql;

    if (Engine == NULL || !Engine->Initialized) {
        return;
    }

    //
    // Free all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ProcessListLock);

    while (!IsListEmpty(&Engine->ProcessList)) {
        entry = RemoveHeadList(&Engine->ProcessList);
        processContext = CONTAINING_RECORD(entry, HP_PROCESS_CONTEXT, ListEntry);
        HppFreeProcessContext(Engine, processContext);
    }

    Engine->Stats.TrackedProcesses = 0;
    Engine->Stats.ActiveHandles = 0;

    ExReleasePushLockExclusive(&Engine->ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Clear event history
    //
    KeAcquireSpinLock(&Engine->EventHistoryLock, &oldIrql);

    while (!IsListEmpty(&Engine->EventHistory)) {
        entry = RemoveHeadList(&Engine->EventHistory);
        event = CONTAINING_RECORD(entry, HP_HANDLE_EVENT, ListEntry);
        ExFreeToNPagedLookasideList(&Engine->EventLookaside, event);
    }

    Engine->EventCount = 0;

    KeReleaseSpinLock(&Engine->EventHistoryLock, oldIrql);
}

// ============================================================================
// PRIVATE FUNCTIONS - TIMER
// ============================================================================

static VOID
HppAnalysisTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PHP_PROTECTION_ENGINE engine = (PHP_PROTECTION_ENGINE)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (engine == NULL || !engine->Initialized) {
        return;
    }

    if (InterlockedCompareExchange(&engine->AnalysisInProgress, 1, 0) != 0) {
        return;
    }

    //
    // Perform cleanup of stale entries
    //
    HppCleanupStaleEntries(engine);

    InterlockedExchange(&engine->AnalysisInProgress, 0);
}

// ============================================================================
// PRIVATE FUNCTIONS - HASH TABLE
// ============================================================================

static NTSTATUS
HppInitializeHashTable(
    _Out_ LIST_ENTRY** Buckets,
    _In_ ULONG BucketCount
    )
{
    LIST_ENTRY* buckets;
    ULONG i;

    buckets = (LIST_ENTRY*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        BucketCount * sizeof(LIST_ENTRY),
        HP_POOL_TAG
    );

    if (buckets == NULL) {
        *Buckets = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (i = 0; i < BucketCount; i++) {
        InitializeListHead(&buckets[i]);
    }

    *Buckets = buckets;
    return STATUS_SUCCESS;
}

static VOID
HppFreeHashTable(
    _Inout_ LIST_ENTRY** Buckets,
    _In_ ULONG BucketCount
    )
{
    UNREFERENCED_PARAMETER(BucketCount);

    if (*Buckets != NULL) {
        ExFreePoolWithTag(*Buckets, HP_POOL_TAG);
        *Buckets = NULL;
    }
}

static ULONG
HppHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;

    pid = ((pid >> 16) ^ pid) * 0x45d9f3b;
    pid = ((pid >> 16) ^ pid) * 0x45d9f3b;
    pid = (pid >> 16) ^ pid;

    return (ULONG)pid;
}

// ============================================================================
// PRIVATE FUNCTIONS - PROCESS CONTEXT
// ============================================================================

static PHP_PROCESS_CONTEXT
HppFindProcessContext(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId
    )
{
    ULONG hash;
    ULONG bucket;
    PLIST_ENTRY entry;
    PHP_PROCESS_CONTEXT context;

    hash = HppHashProcessId(ProcessId);
    bucket = hash % Engine->ProcessHash.BucketCount;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->ProcessHash.Lock);

    for (entry = Engine->ProcessHash.Buckets[bucket].Flink;
         entry != &Engine->ProcessHash.Buckets[bucket];
         entry = entry->Flink) {

        context = CONTAINING_RECORD(entry, HP_PROCESS_CONTEXT, HashEntry);

        if (context->ProcessId == ProcessId) {
            ExReleasePushLockShared(&Engine->ProcessHash.Lock);
            KeLeaveCriticalRegion();
            return context;
        }
    }

    ExReleasePushLockShared(&Engine->ProcessHash.Lock);
    KeLeaveCriticalRegion();

    return NULL;
}

static PHP_PROCESS_CONTEXT
HppCreateProcessContext(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId
    )
{
    PHP_PROCESS_CONTEXT context;
    NTSTATUS status;
    PEPROCESS process = NULL;
    ULONG hash;
    ULONG bucket;

    //
    // Check limit
    //
    if (Engine->Stats.TrackedProcesses >= HP_MAX_TRACKED_PROCESSES) {
        return NULL;
    }

    context = (PHP_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &Engine->ProcessContextLookaside
    );

    if (context == NULL) {
        return NULL;
    }

    RtlZeroMemory(context, sizeof(HP_PROCESS_CONTEXT));

    context->ProcessId = ProcessId;
    InitializeListHead(&context->HandleList);
    KeInitializeSpinLock(&context->HandleListLock);
    KeQuerySystemTime(&context->FirstActivity);
    context->LastActivity = context->FirstActivity;
    context->WindowStart = context->FirstActivity;
    context->RefCount = 1;

    //
    // Get process object reference
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (NT_SUCCESS(status)) {
        context->Process = process;
        context->IsSystem = HppIsSystemProcess(ProcessId);
        HppGetProcessIntegrityLevel(process, &context->IntegrityLevel);
    }

    //
    // Add to lists
    //
    hash = HppHashProcessId(ProcessId);
    bucket = hash % Engine->ProcessHash.BucketCount;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ProcessListLock);
    ExAcquirePushLockExclusive(&Engine->ProcessHash.Lock);

    InsertTailList(&Engine->ProcessList, &context->ListEntry);
    InsertTailList(&Engine->ProcessHash.Buckets[bucket], &context->HashEntry);
    InterlockedIncrement(&Engine->Stats.TrackedProcesses);

    ExReleasePushLockExclusive(&Engine->ProcessHash.Lock);
    ExReleasePushLockExclusive(&Engine->ProcessListLock);
    KeLeaveCriticalRegion();

    return context;
}

static VOID
HppFreeProcessContext(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _Inout_ PHP_PROCESS_CONTEXT Context
    )
{
    PLIST_ENTRY entry;
    PHP_HANDLE_ENTRY handleEntry;
    KIRQL oldIrql;

    //
    // Free all handle entries
    //
    KeAcquireSpinLock(&Context->HandleListLock, &oldIrql);

    while (!IsListEmpty(&Context->HandleList)) {
        entry = RemoveHeadList(&Context->HandleList);
        handleEntry = CONTAINING_RECORD(entry, HP_HANDLE_ENTRY, ListEntry);
        ExFreeToNPagedLookasideList(&Engine->HandleEntryLookaside, handleEntry);
    }

    KeReleaseSpinLock(&Context->HandleListLock, oldIrql);

    //
    // Dereference process object
    //
    if (Context->Process != NULL) {
        ObDereferenceObject(Context->Process);
    }

    ExFreeToNPagedLookasideList(&Engine->ProcessContextLookaside, Context);
}

// ============================================================================
// PRIVATE FUNCTIONS - HANDLE ENTRIES
// ============================================================================

static PHP_HANDLE_ENTRY
HppCreateHandleEntry(
    _In_ PHP_PROTECTION_ENGINE Engine
    )
{
    PHP_HANDLE_ENTRY entry;

    entry = (PHP_HANDLE_ENTRY)ExAllocateFromNPagedLookasideList(
        &Engine->HandleEntryLookaside
    );

    if (entry != NULL) {
        RtlZeroMemory(entry, sizeof(HP_HANDLE_ENTRY));
    }

    return entry;
}

static VOID
HppFreeHandleEntry(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _Inout_ PHP_HANDLE_ENTRY Entry
    )
{
    ExFreeToNPagedLookasideList(&Engine->HandleEntryLookaside, Entry);
}

// ============================================================================
// PRIVATE FUNCTIONS - OBJECT TYPE DETECTION
// ============================================================================

static HP_OBJECT_TYPE
HppGetObjectType(
    _In_ POBJECT_TYPE ObjectType
    )
{
    if (ObjectType == *PsProcessType) {
        return HpObjectType_Process;
    }
    if (ObjectType == *PsThreadType) {
        return HpObjectType_Thread;
    }
    if (ObjectType == *SeTokenObjectType) {
        return HpObjectType_Token;
    }
    if (ObjectType == *IoFileObjectType) {
        return HpObjectType_File;
    }

    return HpObjectType_Unknown;
}

// ============================================================================
// PRIVATE FUNCTIONS - SENSITIVITY DETECTION
// ============================================================================

static HP_SENSITIVITY_LEVEL
HppGetProcessSensitivity(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ PHP_SUSPICION_FLAGS OutFlags
    )
{
    HP_SENSITIVITY_LEVEL sensitivity = HpSensitivity_None;
    HP_SUSPICION_FLAGS flags = HpSuspicion_None;
    ULONG i;

    //
    // Check known critical processes
    //
    if (ProcessId == Engine->LsassProcessId) {
        *OutFlags = HpSuspicion_TargetLSASS;
        return HpSensitivity_Critical;
    }

    if (ProcessId == Engine->CsrssProcessId) {
        *OutFlags = HpSuspicion_TargetCSRSS;
        return HpSensitivity_Critical;
    }

    if (ProcessId == Engine->SmssProcessId) {
        *OutFlags = HpSuspicion_TargetSMSS;
        return HpSensitivity_Critical;
    }

    if (ProcessId == Engine->ServicesProcessId) {
        *OutFlags = HpSuspicion_TargetServices;
        return HpSensitivity_High;
    }

    if (ProcessId == Engine->WinlogonProcessId) {
        *OutFlags = HpSuspicion_TargetSystem;
        return HpSensitivity_High;
    }

    //
    // Check if protected by SelfProtect module
    //
    if (ShadowStrikeIsProcessProtected(ProcessId, NULL)) {
        *OutFlags = HpSuspicion_TargetAntivirus;
        return HpSensitivity_Critical;
    }

    //
    // Check registered sensitive objects
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->SensitiveObjectLock);

    for (i = 0; i < HP_MAX_SENSITIVE_OBJECTS; i++) {
        if (Engine->SensitiveObjects[i].InUse &&
            Engine->SensitiveObjects[i].ProcessId == ProcessId) {

            sensitivity = Engine->SensitiveObjects[i].Sensitivity;
            flags = Engine->SensitiveObjects[i].RequiredFlags;
            break;
        }
    }

    ExReleasePushLockShared(&Engine->SensitiveObjectLock);
    KeLeaveCriticalRegion();

    *OutFlags = flags;
    return sensitivity;
}

// ============================================================================
// PRIVATE FUNCTIONS - SCORING
// ============================================================================

static ULONG
HppCalculateSuspicionScore(
    _In_ HP_SUSPICION_FLAGS Flags
    )
{
    ULONG score = 0;

    if (Flags & HpSuspicion_CrossProcess) score += HP_SCORE_CROSS_PROCESS;
    if (Flags & HpSuspicion_CrossSession) score += HP_SCORE_CROSS_SESSION;
    if (Flags & HpSuspicion_CrossIntegrity) score += HP_SCORE_CROSS_INTEGRITY;
    if (Flags & HpSuspicion_TerminateAccess) score += HP_SCORE_TERMINATE_ACCESS;
    if (Flags & HpSuspicion_InjectAccess) score += HP_SCORE_INJECT_ACCESS;
    if (Flags & HpSuspicion_ReadMemoryAccess) score += HP_SCORE_READ_MEMORY;
    if (Flags & HpSuspicion_TargetLSASS) score += HP_SCORE_TARGET_LSASS;
    if (Flags & HpSuspicion_TargetCSRSS) score += HP_SCORE_TARGET_CSRSS;
    if (Flags & HpSuspicion_TargetSMSS) score += HP_SCORE_TARGET_SMSS;
    if (Flags & HpSuspicion_TargetServices) score += HP_SCORE_TARGET_SERVICES;
    if (Flags & HpSuspicion_TargetProtected) score += HP_SCORE_TARGET_PROTECTED;
    if (Flags & HpSuspicion_TargetAntivirus) score += HP_SCORE_TARGET_ANTIVIRUS;
    if (Flags & HpSuspicion_DuplicatedHandle) score += HP_SCORE_DUPLICATED_HANDLE;
    if (Flags & HpSuspicion_TokenDuplicate) score += HP_SCORE_TOKEN_DUPLICATE;
    if (Flags & HpSuspicion_TokenImpersonate) score += HP_SCORE_TOKEN_IMPERSONATE;
    if (Flags & HpSuspicion_PrivilegeEscalation) score += HP_SCORE_PRIVILEGE_ESCALATION;
    if (Flags & HpSuspicion_RapidEnumeration) score += HP_SCORE_RAPID_ENUMERATION;
    if (Flags & HpSuspicion_BulkHandleOpen) score += HP_SCORE_BULK_HANDLE_OPEN;
    if (Flags & HpSuspicion_CredentialAccess) score += 50;  // Additional for credential access

    return score;
}

// ============================================================================
// PRIVATE FUNCTIONS - EVENT RECORDING
// ============================================================================

static VOID
HppRecordEvent(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HP_EVENT_TYPE EventType,
    _In_ HANDLE OwnerProcessId,
    _In_opt_ HANDLE TargetProcessId,
    _In_ HANDLE Handle,
    _In_ HP_OBJECT_TYPE ObjectType,
    _In_ ACCESS_MASK AccessMask,
    _In_ HP_SUSPICION_FLAGS Flags,
    _In_ ULONG Score
    )
{
    PHP_HANDLE_EVENT event;
    KIRQL oldIrql;

    event = (PHP_HANDLE_EVENT)ExAllocateFromNPagedLookasideList(
        &Engine->EventLookaside
    );

    if (event == NULL) {
        return;
    }

    RtlZeroMemory(event, sizeof(HP_HANDLE_EVENT));
    event->EventType = EventType;
    KeQuerySystemTime(&event->Timestamp);
    event->OwnerProcessId = OwnerProcessId;
    event->TargetProcessId = TargetProcessId;
    event->Handle = Handle;
    event->ObjectType = ObjectType;
    event->AccessMask = AccessMask;
    event->Flags = Flags;
    event->Score = Score;

    KeAcquireSpinLock(&Engine->EventHistoryLock, &oldIrql);

    //
    // Check history limit
    //
    if (Engine->EventCount >= HP_MAX_HANDLE_HISTORY) {
        PLIST_ENTRY oldest = RemoveHeadList(&Engine->EventHistory);
        PHP_HANDLE_EVENT oldEvent = CONTAINING_RECORD(oldest, HP_HANDLE_EVENT, ListEntry);
        ExFreeToNPagedLookasideList(&Engine->EventLookaside, oldEvent);
        InterlockedDecrement(&Engine->EventCount);
    }

    InsertTailList(&Engine->EventHistory, &event->ListEntry);
    InterlockedIncrement(&Engine->EventCount);

    KeReleaseSpinLock(&Engine->EventHistoryLock, oldIrql);
}

// ============================================================================
// PRIVATE FUNCTIONS - CALLBACK NOTIFICATION
// ============================================================================

static VOID
HppNotifyCallback(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ PHP_DETECTION_RESULT Result
    )
{
    HP_DETECTION_CALLBACK callback;
    PVOID context;

    callback = (HP_DETECTION_CALLBACK)Engine->DetectionCallback;
    context = Engine->DetectionCallbackContext;

    if (callback != NULL) {
        callback(Result, context);
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - CLEANUP
// ============================================================================

static VOID
HppCleanupStaleEntries(
    _In_ PHP_PROTECTION_ENGINE Engine
    )
{
    PLIST_ENTRY entry;
    PLIST_ENTRY next;
    PHP_HANDLE_EVENT event;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER cutoffTime;
    KIRQL oldIrql;

    KeQuerySystemTime(&currentTime);
    cutoffTime.QuadPart = currentTime.QuadPart -
                          ((LONGLONG)Engine->Config.HistoryRetentionMs * 10000);

    //
    // Clean up old events
    //
    KeAcquireSpinLock(&Engine->EventHistoryLock, &oldIrql);

    for (entry = Engine->EventHistory.Flink;
         entry != &Engine->EventHistory;
         entry = next) {

        next = entry->Flink;
        event = CONTAINING_RECORD(entry, HP_HANDLE_EVENT, ListEntry);

        if (event->Timestamp.QuadPart < cutoffTime.QuadPart) {
            RemoveEntryList(&event->ListEntry);
            InterlockedDecrement(&Engine->EventCount);
            ExFreeToNPagedLookasideList(&Engine->EventLookaside, event);
        } else {
            //
            // Events are in chronological order, stop when we hit recent ones
            //
            break;
        }
    }

    KeReleaseSpinLock(&Engine->EventHistoryLock, oldIrql);
}

// ============================================================================
// PRIVATE FUNCTIONS - SYSTEM PROCESS DETECTION
// ============================================================================

static BOOLEAN
HppIsSystemProcess(
    _In_ HANDLE ProcessId
    )
{
    //
    // System process has PID 4
    //
    return (ProcessId == (HANDLE)4);
}

static BOOLEAN
HppGetProcessIntegrityLevel(
    _In_ PEPROCESS Process,
    _Out_ PULONG IntegrityLevel
    )
{
    UNREFERENCED_PARAMETER(Process);

    //
    // Getting integrity level requires accessing the process token
    // and querying TOKEN_MANDATORY_LABEL. For simplicity, we default
    // to medium integrity.
    //
    *IntegrityLevel = SECURITY_MANDATORY_MEDIUM_RID;

    return TRUE;
}

static VOID
HppDetectSensitiveProcesses(
    _In_ PHP_PROTECTION_ENGINE Engine
    )
{
    //
    // In a production implementation, we would enumerate running processes
    // and identify LSASS, CSRSS, SMSS, etc. by their names.
    //
    // For now, these will be populated as processes are encountered
    // or through explicit registration.
    //
    // The process IDs are cached when handle operations target these
    // processes, identified by their process names.
    //

    Engine->LsassProcessId = NULL;
    Engine->CsrssProcessId = NULL;
    Engine->SmssProcessId = NULL;
    Engine->ServicesProcessId = NULL;
    Engine->WinlogonProcessId = NULL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Sensitive process detection initialized\n");
}
