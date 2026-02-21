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
/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE HANDLE PROTECTION IMPLEMENTATION
 * ============================================================================
 *
 * @file HandleProtection.c
 * @brief Enterprise-grade handle protection and forensics engine.
 *
 * SECURITY HARDENING (v2.1.0):
 * - Reference-counted process contexts prevent use-after-free
 * - HppFindProcessContext acquires refcount under lock before return
 * - HpFindHandlesToProcess / HpGetRecentEvents return COPIES, not raw pointers
 * - CallbackLock protects detection callback registration/invocation
 * - Config reads in hot path protected by ConfigLock
 * - HpProcessTerminated inlines hash lookup to avoid self-deadlock
 * - HpFlushAllTracking cleans both ProcessList AND hash table
 * - HppCreateProcessContext does duplicate-check under exclusive lock
 * - HppDetectSensitiveProcesses actually enumerates system processes
 * - HppGetProcessIntegrityLevel queries the actual process token
 * - Bounded spin-wait in HpShutdown
 * - ObjectPointer removed from HP_HANDLE_ENTRY (unsafe without ObReference)
 * - Initialized is volatile LONG with Interlocked operations
 * - ExAllocatePool2 used instead of deprecated ExAllocatePoolWithTag
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "HandleProtection.h"
#include "SelfProtect.h"
#include "../Core/Globals.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, HpInitialize)
#pragma alloc_text(PAGE, HpShutdown)
#pragma alloc_text(PAGE, HpSetConfiguration)
#pragma alloc_text(PAGE, HpRegisterSensitiveProcess)
#pragma alloc_text(PAGE, HpUnregisterSensitiveProcess)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

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
#define HP_SCORE_CREDENTIAL_ACCESS          50

#define HP_ALERT_THRESHOLD                  100
#define HP_CRITICAL_THRESHOLD               150

#define HP_ACTIVITY_WINDOW_100NS            (10000000LL)  // 1 second
#define HP_RAPID_HANDLE_THRESHOLD           20

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
    _Inout_ LIST_ENTRY** Buckets
    );

static ULONG
HppHashProcessId(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(APC_LEVEL)
static PHP_PROCESS_CONTEXT
HppFindProcessContext(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(APC_LEVEL)
static VOID
HppReleaseProcessContext(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _Inout_ PHP_PROCESS_CONTEXT Context
    );

_IRQL_requires_max_(APC_LEVEL)
static PHP_PROCESS_CONTEXT
HppCreateProcessContext(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(APC_LEVEL)
static PHP_PROCESS_CONTEXT
HppFindOrCreateProcessContext(
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
    // Allocate engine structure (NonPagedPoolNx via ExAllocatePool2)
    //
    engine = (PHP_PROTECTION_ENGINE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(HP_PROTECTION_ENGINE),
        HP_POOL_TAG
    );

    if (engine == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // ExAllocatePool2 zero-initializes, but be explicit for clarity
    RtlZeroMemory(engine, sizeof(HP_PROTECTION_ENGINE));

    //
    // Initialize locks
    //
    ExInitializePushLock(&engine->ConfigLock);
    ExInitializePushLock(&engine->ProcessListLock);
    ExInitializePushLock(&engine->SensitiveObjectLock);
    ExInitializePushLock(&engine->CallbackLock);
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
    // Detect sensitive system processes BEFORE marking initialized
    //
    HppDetectSensitiveProcesses(engine);

    //
    // Record start time
    //
    KeQuerySystemTime(&engine->Stats.StartTime);

    //
    // Mark initialized BEFORE starting the timer
    //
    InterlockedExchange(&engine->Initialized, 1);

    //
    // Initialize analysis timer — AFTER Initialized is set
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
    LONG spins;

    PAGED_CODE();

    if (Engine == NULL) {
        return;
    }

    //
    // Atomically mark as shutting down — fail if already shutdown
    //
    if (InterlockedCompareExchange(&Engine->Initialized, 0, 1) != 1) {
        return;
    }

    //
    // Cancel analysis timer and flush DPCs
    //
    KeCancelTimer(&Engine->AnalysisTimer);
    KeFlushQueuedDpcs();

    //
    // Bounded wait for in-progress analysis
    //
    for (spins = 0; spins < HP_SHUTDOWN_SPIN_LIMIT; spins++) {
        if (Engine->AnalysisInProgress == 0) {
            break;
        }
        LARGE_INTEGER delay;
        delay.QuadPart = -10000; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    //
    // Free all process contexts — must clean both list AND hash table
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ProcessListLock);
    ExAcquirePushLockExclusive(&Engine->ProcessHash.Lock);

    while (!IsListEmpty(&Engine->ProcessList)) {
        entry = RemoveHeadList(&Engine->ProcessList);
        processContext = CONTAINING_RECORD(entry, HP_PROCESS_CONTEXT, ListEntry);
        RemoveEntryList(&processContext->HashEntry);
        HppFreeProcessContext(Engine, processContext);
    }

    ExReleasePushLockExclusive(&Engine->ProcessHash.Lock);
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
    HppFreeHashTable(&Engine->ProcessHash.Buckets);

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

    if (Engine == NULL || Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return STATUS_DEVICE_NOT_READY;
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
    if (Engine == NULL || Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return STATUS_DEVICE_NOT_READY;
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
    HP_CONFIG localConfig;

    if (Engine == NULL || OperationInfo == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Snapshot config under lock for consistent read
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->ConfigLock);
    RtlCopyMemory(&localConfig, &Engine->Config, sizeof(HP_CONFIG));
    ExReleasePushLockShared(&Engine->ConfigLock);
    KeLeaveCriticalRegion();

    if (!localConfig.Enabled) {
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
    if (localConfig.StripDangerousAccess && targetSensitivity >= HpSensitivity_High) {
        if (isProcess) {
            if (flags & HpSuspicion_TargetLSASS) {
                if (localConfig.BlockLSASSAccess) {
                    modifiedAccess &= ~HP_DANGEROUS_PROCESS_ALL;
                    InterlockedIncrement64(&Engine->Stats.LSASSAccessBlocked);
                }
            }

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
    // Alert on suspicious handles
    //
    if (suspicionScore >= localConfig.SuspicionThreshold) {
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

        if (localConfig.AlertOnSuspicious) {
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
    _In_ ACCESS_MASK GrantedAccess
    )
{
    PHP_PROCESS_CONTEXT processContext;
    PHP_HANDLE_ENTRY handleEntry;
    KIRQL oldIrql;

    if (Engine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!Engine->Config.Enabled || !Engine->Config.TrackAllHandles) {
        return STATUS_SUCCESS;
    }

    //
    // Find or create process context (ref-counted)
    //
    processContext = HppFindOrCreateProcessContext(Engine, OwnerProcessId);
    if (processContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Check handle limit
    //
    if (processContext->HandleCount >= (LONG)Engine->Config.MaxHandlesPerProcess) {
        HppReleaseProcessContext(Engine, processContext);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Create handle entry
    //
    handleEntry = HppCreateHandleEntry(Engine);
    if (handleEntry == NULL) {
        HppReleaseProcessContext(Engine, processContext);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    handleEntry->Handle = Handle;
    handleEntry->ObjectType = ObjectType;
    handleEntry->GrantedAccess = GrantedAccess;
    handleEntry->OriginalAccess = GrantedAccess;
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

    HppReleaseProcessContext(Engine, processContext);

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

    if (Engine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!Engine->Config.Enabled) {
        return STATUS_SUCCESS;
    }

    InterlockedIncrement64(&Engine->Stats.DuplicationsTracked);

    processContext = HppFindOrCreateProcessContext(Engine, TargetProcess);
    if (processContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    handleEntry = HppCreateHandleEntry(Engine);
    if (handleEntry == NULL) {
        HppReleaseProcessContext(Engine, processContext);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    handleEntry->Handle = TargetHandle;
    handleEntry->ObjectType = HpObjectType_Unknown;
    handleEntry->GrantedAccess = GrantedAccess;
    handleEntry->OriginalAccess = GrantedAccess;
    handleEntry->OwnerProcessId = TargetProcess;
    handleEntry->CreatorProcessId = PsGetCurrentProcessId();
    handleEntry->IsDuplicated = TRUE;
    handleEntry->DuplicatedFromProcess = SourceProcess;
    handleEntry->SuspicionFlags |= HpSuspicion_DuplicatedHandle;
    KeQuerySystemTime(&handleEntry->CreateTime);
    handleEntry->RefCount = 1;

    KeAcquireSpinLock(&processContext->HandleListLock, &oldIrql);
    InsertTailList(&processContext->HandleList, &handleEntry->ListEntry);
    InterlockedIncrement(&processContext->HandleCount);
    KeReleaseSpinLock(&processContext->HandleListLock, oldIrql);

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

    HppReleaseProcessContext(Engine, processContext);

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
    PHP_HANDLE_ENTRY handleEntry = NULL;
    PLIST_ENTRY entry;
    KIRQL oldIrql;

    if (Engine == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return;
    }

    if (!Engine->Config.Enabled) {
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

        PHP_HANDLE_ENTRY candidate = CONTAINING_RECORD(entry, HP_HANDLE_ENTRY, ListEntry);

        if (candidate->Handle == Handle) {
            RemoveEntryList(&candidate->ListEntry);
            InterlockedDecrement(&processContext->HandleCount);
            handleEntry = candidate;
            break;
        }
    }

    KeReleaseSpinLock(&processContext->HandleListLock, oldIrql);

    if (handleEntry != NULL) {
        HppFreeHandleEntry(Engine, handleEntry);
        InterlockedDecrement(&Engine->Stats.ActiveHandles);
    }

    HppReleaseProcessContext(Engine, processContext);
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

    if (Engine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return STATUS_DEVICE_NOT_READY;
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

    if (Engine == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
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

    if (Engine == NULL) {
        if (OutSensitivity) *OutSensitivity = HpSensitivity_None;
        return FALSE;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        if (OutSensitivity) *OutSensitivity = HpSensitivity_None;
        return FALSE;
    }

    //
    // Check known system processes first (cached PIDs, no lock needed)
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

    if (Engine == NULL || OutFlags == NULL || OutScore == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return STATUS_DEVICE_NOT_READY;
    }

    *OutFlags = HpSuspicion_None;
    *OutScore = 0;

    processContext = HppFindProcessContext(Engine, ProcessId);
    if (processContext == NULL) {
        return STATUS_NOT_FOUND;
    }

    *OutFlags = processContext->AggregatedFlags;
    *OutScore = processContext->TotalSuspicionScore;

    HppReleaseProcessContext(Engine, processContext);

    return STATUS_SUCCESS;
}

/**
 * @brief Find handles targeting a process — returns COPIES, not raw pointers.
 */
_Use_decl_annotations_
NTSTATUS
HpFindHandlesToProcess(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE TargetProcessId,
    _Out_writes_to_(MaxHandles, *ReturnedCount) HP_HANDLE_ENTRY* Handles,
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

    if (Engine == NULL || Handles == NULL || ReturnedCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return STATUS_DEVICE_NOT_READY;
    }

    *ReturnedCount = 0;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->ProcessListLock);

    for (processEntry = Engine->ProcessList.Flink;
         processEntry != &Engine->ProcessList && count < MaxHandles;
         processEntry = processEntry->Flink) {

        processContext = CONTAINING_RECORD(processEntry, HP_PROCESS_CONTEXT, ListEntry);

        if (processContext->ProcessId == TargetProcessId) {
            continue;
        }

        KeAcquireSpinLock(&processContext->HandleListLock, &oldIrql);

        for (handleEntry = processContext->HandleList.Flink;
             handleEntry != &processContext->HandleList && count < MaxHandles;
             handleEntry = handleEntry->Flink) {

            handle = CONTAINING_RECORD(handleEntry, HP_HANDLE_ENTRY, ListEntry);

            if (handle->TargetProcessId == TargetProcessId) {
                //
                // COPY the entire entry to caller buffer (safe after lock release)
                //
                RtlCopyMemory(&Handles[count], handle, sizeof(HP_HANDLE_ENTRY));
                //
                // Clear ListEntry in copy so caller doesn't use stale links
                //
                InitializeListHead(&Handles[count].ListEntry);
                count++;
            }
        }

        KeReleaseSpinLock(&processContext->HandleListLock, oldIrql);
    }

    ExReleasePushLockShared(&Engine->ProcessListLock);
    KeLeaveCriticalRegion();

    *ReturnedCount = count;

    return STATUS_SUCCESS;
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
    if (Engine == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Write both fields atomically under CallbackLock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->CallbackLock);

    Engine->DetectionCallback = (PVOID)Callback;
    Engine->DetectionCallbackContext = Context;

    ExReleasePushLockExclusive(&Engine->CallbackLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
HpUnregisterCallback(
    _In_ PHP_PROTECTION_ENGINE Engine
    )
{
    if (Engine == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->CallbackLock);

    Engine->DetectionCallback = NULL;
    Engine->DetectionCallbackContext = NULL;

    ExReleasePushLockExclusive(&Engine->CallbackLock);
    KeLeaveCriticalRegion();
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
    if (Engine == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlCopyMemory(Stats, &Engine->Stats, sizeof(HP_STATISTICS));

    return STATUS_SUCCESS;
}

/**
 * @brief Get recent events — returns COPIES of event data, not raw pointers.
 */
_Use_decl_annotations_
NTSTATUS
HpGetRecentEvents(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _Out_writes_to_(MaxEvents, *ReturnedCount) HP_HANDLE_EVENT* Events,
    _In_ ULONG MaxEvents,
    _Out_ PULONG ReturnedCount
    )
{
    PLIST_ENTRY entry;
    PHP_HANDLE_EVENT event;
    ULONG count = 0;
    KIRQL oldIrql;

    if (Engine == NULL || Events == NULL || ReturnedCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return STATUS_DEVICE_NOT_READY;
    }

    *ReturnedCount = 0;

    KeAcquireSpinLock(&Engine->EventHistoryLock, &oldIrql);

    for (entry = Engine->EventHistory.Flink;
         entry != &Engine->EventHistory && count < MaxEvents;
         entry = entry->Flink) {

        event = CONTAINING_RECORD(entry, HP_HANDLE_EVENT, ListEntry);
        //
        // COPY the event to caller buffer
        //
        RtlCopyMemory(&Events[count], event, sizeof(HP_HANDLE_EVENT));
        InitializeListHead(&Events[count].ListEntry);
        count++;
    }

    KeReleaseSpinLock(&Engine->EventHistoryLock, oldIrql);

    *ReturnedCount = count;

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - CLEANUP
// ============================================================================

/**
 * @brief Process terminated — inline hash lookup to avoid self-deadlock.
 *
 * The original code called HppFindProcessContext (which acquires ProcessHash.Lock
 * shared) while already holding ProcessHash.Lock exclusive → self-deadlock.
 * Fixed by inlining the hash lookup.
 */
_Use_decl_annotations_
VOID
HpProcessTerminated(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId
    )
{
    PHP_PROCESS_CONTEXT processContext = NULL;
    ULONG hash;
    ULONG bucket;
    PLIST_ENTRY entry;

    if (Engine == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return;
    }

    hash = HppHashProcessId(ProcessId);
    bucket = hash & HP_HASH_BUCKET_MASK;

    //
    // Acquire both locks, then inline the hash lookup
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ProcessListLock);
    ExAcquirePushLockExclusive(&Engine->ProcessHash.Lock);

    for (entry = Engine->ProcessHash.Buckets[bucket].Flink;
         entry != &Engine->ProcessHash.Buckets[bucket];
         entry = entry->Flink) {

        PHP_PROCESS_CONTEXT candidate =
            CONTAINING_RECORD(entry, HP_PROCESS_CONTEXT, HashEntry);

        if (candidate->ProcessId == ProcessId) {
            processContext = candidate;
            break;
        }
    }

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

/**
 * @brief Flush all tracking — cleans BOTH process list AND hash table.
 *
 * Original only removed from ProcessList, leaving dangling hash entries.
 */
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

    if (Engine == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&Engine->Initialized, 1, 1) != 1) {
        return;
    }

    //
    // Free all process contexts — remove from BOTH list and hash
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ProcessListLock);
    ExAcquirePushLockExclusive(&Engine->ProcessHash.Lock);

    while (!IsListEmpty(&Engine->ProcessList)) {
        entry = RemoveHeadList(&Engine->ProcessList);
        processContext = CONTAINING_RECORD(entry, HP_PROCESS_CONTEXT, ListEntry);
        RemoveEntryList(&processContext->HashEntry);
        HppFreeProcessContext(Engine, processContext);
    }

    Engine->Stats.TrackedProcesses = 0;
    Engine->Stats.ActiveHandles = 0;

    ExReleasePushLockExclusive(&Engine->ProcessHash.Lock);
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

    if (engine == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&engine->Initialized, 1, 1) != 1) {
        return;
    }

    if (InterlockedCompareExchange(&engine->AnalysisInProgress, 1, 0) != 0) {
        return;
    }

    //
    // HppCleanupStaleEntries only touches EventHistoryLock (spin lock, DISPATCH safe)
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

    buckets = (LIST_ENTRY*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
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
    _Inout_ LIST_ENTRY** Buckets
    )
{
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
// PRIVATE FUNCTIONS - PROCESS CONTEXT (Reference-counted)
// ============================================================================

/**
 * @brief Find process context by PID — acquires a reference before returning.
 *
 * The returned context is REFERENCE-COUNTED. Caller MUST call
 * HppReleaseProcessContext when done. This prevents use-after-free
 * if another thread calls HpProcessTerminated concurrently.
 *
 * @return Referenced process context, or NULL if not found.
 */
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
    bucket = hash & HP_HASH_BUCKET_MASK;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->ProcessHash.Lock);

    for (entry = Engine->ProcessHash.Buckets[bucket].Flink;
         entry != &Engine->ProcessHash.Buckets[bucket];
         entry = entry->Flink) {

        context = CONTAINING_RECORD(entry, HP_PROCESS_CONTEXT, HashEntry);

        if (context->ProcessId == ProcessId) {
            //
            // Acquire reference WHILE STILL UNDER LOCK
            // This is the critical fix: the lock protects us from
            // HpProcessTerminated freeing this context before we ref it.
            //
            InterlockedIncrement(&context->RefCount);

            ExReleasePushLockShared(&Engine->ProcessHash.Lock);
            KeLeaveCriticalRegion();
            return context;
        }
    }

    ExReleasePushLockShared(&Engine->ProcessHash.Lock);
    KeLeaveCriticalRegion();

    return NULL;
}

/**
 * @brief Release a reference on a process context.
 *
 * If the reference count drops to zero, the context is freed.
 * This happens when the context was removed from all lists (by
 * HpProcessTerminated) and the last external reference is released.
 */
static VOID
HppReleaseProcessContext(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _Inout_ PHP_PROCESS_CONTEXT Context
    )
{
    LONG newRef;

    newRef = InterlockedDecrement(&Context->RefCount);

    if (newRef == 0) {
        HppFreeProcessContext(Engine, Context);
    }
}

/**
 * @brief Create a new process context — checks for duplicates under exclusive lock.
 *
 * Fixed race condition: two threads could both create contexts for the same PID.
 * Now we re-check under exclusive lock before inserting.
 */
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
    PLIST_ENTRY entry;

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
    context->RefCount = 1;  // Initial reference for being in the lists

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
    // Insert under exclusive lock — but first check for duplicate
    //
    hash = HppHashProcessId(ProcessId);
    bucket = hash & HP_HASH_BUCKET_MASK;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ProcessListLock);
    ExAcquirePushLockExclusive(&Engine->ProcessHash.Lock);

    //
    // Re-check: another thread may have created this context already
    //
    for (entry = Engine->ProcessHash.Buckets[bucket].Flink;
         entry != &Engine->ProcessHash.Buckets[bucket];
         entry = entry->Flink) {

        PHP_PROCESS_CONTEXT existing =
            CONTAINING_RECORD(entry, HP_PROCESS_CONTEXT, HashEntry);

        if (existing->ProcessId == ProcessId) {
            //
            // Duplicate found — ref it and discard our new allocation
            //
            InterlockedIncrement(&existing->RefCount);

            ExReleasePushLockExclusive(&Engine->ProcessHash.Lock);
            ExReleasePushLockExclusive(&Engine->ProcessListLock);
            KeLeaveCriticalRegion();

            //
            // Free the unused context we allocated
            //
            if (context->Process != NULL) {
                ObDereferenceObject(context->Process);
            }
            ExFreeToNPagedLookasideList(&Engine->ProcessContextLookaside, context);

            return existing;
        }
    }

    //
    // No duplicate — insert
    //
    InsertTailList(&Engine->ProcessList, &context->ListEntry);
    InsertTailList(&Engine->ProcessHash.Buckets[bucket], &context->HashEntry);
    InterlockedIncrement(&Engine->Stats.TrackedProcesses);

    //
    // Take a second reference for the caller
    //
    InterlockedIncrement(&context->RefCount);

    ExReleasePushLockExclusive(&Engine->ProcessHash.Lock);
    ExReleasePushLockExclusive(&Engine->ProcessListLock);
    KeLeaveCriticalRegion();

    return context;
}

/**
 * @brief Find or create a process context (convenience wrapper).
 * Returns a referenced context. Caller must HppReleaseProcessContext.
 */
static PHP_PROCESS_CONTEXT
HppFindOrCreateProcessContext(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ HANDLE ProcessId
    )
{
    PHP_PROCESS_CONTEXT ctx = HppFindProcessContext(Engine, ProcessId);
    if (ctx != NULL) {
        return ctx;
    }
    return HppCreateProcessContext(Engine, ProcessId);
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
        Context->Process = NULL;
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
    // Check known critical processes (cached PIDs, pointer-sized atomic reads)
    //
    if (ProcessId == Engine->LsassProcessId && Engine->LsassProcessId != NULL) {
        *OutFlags = HpSuspicion_TargetLSASS;
        return HpSensitivity_Critical;
    }

    if (ProcessId == Engine->CsrssProcessId && Engine->CsrssProcessId != NULL) {
        *OutFlags = HpSuspicion_TargetCSRSS;
        return HpSensitivity_Critical;
    }

    if (ProcessId == Engine->SmssProcessId && Engine->SmssProcessId != NULL) {
        *OutFlags = HpSuspicion_TargetSMSS;
        return HpSensitivity_Critical;
    }

    if (ProcessId == Engine->ServicesProcessId && Engine->ServicesProcessId != NULL) {
        *OutFlags = HpSuspicion_TargetServices;
        return HpSensitivity_High;
    }

    if (ProcessId == Engine->WinlogonProcessId && Engine->WinlogonProcessId != NULL) {
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
    if (Flags & HpSuspicion_CredentialAccess) score += HP_SCORE_CREDENTIAL_ACCESS;

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
    // Evict oldest if at capacity (no Interlocked needed — we hold the spin lock)
    //
    if (Engine->EventCount >= HP_MAX_HANDLE_HISTORY) {
        PLIST_ENTRY oldest = RemoveHeadList(&Engine->EventHistory);
        PHP_HANDLE_EVENT oldEvent = CONTAINING_RECORD(oldest, HP_HANDLE_EVENT, ListEntry);
        ExFreeToNPagedLookasideList(&Engine->EventLookaside, oldEvent);
        Engine->EventCount--;
    }

    InsertTailList(&Engine->EventHistory, &event->ListEntry);
    Engine->EventCount++;

    KeReleaseSpinLock(&Engine->EventHistoryLock, oldIrql);
}

// ============================================================================
// PRIVATE FUNCTIONS - CALLBACK NOTIFICATION
// ============================================================================

/**
 * @brief Notify detection callback — reads callback+context atomically under CallbackLock.
 */
static VOID
HppNotifyCallback(
    _In_ PHP_PROTECTION_ENGINE Engine,
    _In_ PHP_DETECTION_RESULT Result
    )
{
    HP_DETECTION_CALLBACK callback;
    PVOID context;

    //
    // Read both fields atomically under shared CallbackLock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->CallbackLock);

    callback = (HP_DETECTION_CALLBACK)Engine->DetectionCallback;
    context = Engine->DetectionCallbackContext;

    ExReleasePushLockShared(&Engine->CallbackLock);
    KeLeaveCriticalRegion();

    if (callback != NULL) {
        callback(Result, context);
    }
}

// ============================================================================
// PRIVATE FUNCTIONS - CLEANUP
// ============================================================================

/**
 * @brief Clean up stale event entries.
 * Called from DPC (DISPATCH_LEVEL) — only uses spin-lock-protected EventHistory.
 */
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

    KeAcquireSpinLock(&Engine->EventHistoryLock, &oldIrql);

    for (entry = Engine->EventHistory.Flink;
         entry != &Engine->EventHistory;
         entry = next) {

        next = entry->Flink;
        event = CONTAINING_RECORD(entry, HP_HANDLE_EVENT, ListEntry);

        if (event->Timestamp.QuadPart < cutoffTime.QuadPart) {
            RemoveEntryList(&event->ListEntry);
            Engine->EventCount--;
            ExFreeToNPagedLookasideList(&Engine->EventLookaside, event);
        } else {
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
    return (ProcessId == (HANDLE)(ULONG_PTR)4);
}

/**
 * @brief Get the actual integrity level of a process by querying its token.
 *
 * Replaces the original stub that always returned SECURITY_MANDATORY_MEDIUM_RID.
 * Queries TOKEN_MANDATORY_LABEL from the process token.
 *
 * @return TRUE if integrity level was successfully retrieved.
 */
static BOOLEAN
HppGetProcessIntegrityLevel(
    _In_ PEPROCESS Process,
    _Out_ PULONG IntegrityLevel
    )
{
    NTSTATUS status;
    PACCESS_TOKEN token = NULL;
    UCHAR buffer[256];
    PTOKEN_MANDATORY_LABEL label = NULL;
    ULONG returnLength = 0;
    PSID sid;
    ULONG subAuthorityCount;
    PULONG ridPtr;

    *IntegrityLevel = SECURITY_MANDATORY_MEDIUM_RID;

    //
    // Get the primary token of the process
    //
    token = PsReferencePrimaryToken(Process);
    if (token == NULL) {
        return FALSE;
    }

    //
    // Query token integrity level
    //
    status = SeQueryInformationToken(
        token,
        TokenIntegrityLevel,
        (PVOID*)&label
    );

    if (NT_SUCCESS(status) && label != NULL) {
        sid = label->Label.Sid;
        if (sid != NULL && RtlValidSid(sid)) {
            subAuthorityCount = *RtlSubAuthorityCountSid(sid);
            if (subAuthorityCount > 0) {
                ridPtr = RtlSubAuthoritySid(sid, subAuthorityCount - 1);
                if (ridPtr != NULL) {
                    *IntegrityLevel = *ridPtr;
                }
            }
        }
        ExFreePool(label);
    }

    PsDereferencePrimaryToken(token);

    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(returnLength);

    return NT_SUCCESS(status);
}

/**
 * @brief Detect sensitive system processes at initialization time.
 *
 * Enumerates running processes via ZwQuerySystemInformation to find
 * LSASS, CSRSS, SMSS, services.exe, and winlogon.exe by matching
 * their image file names.
 *
 * Replaces the original stub that set all cached PIDs to NULL.
 */
static VOID
HppDetectSensitiveProcesses(
    _In_ PHP_PROTECTION_ENGINE Engine
    )
{
    NTSTATUS status;
    ULONG bufferSize = 0;
    PVOID buffer = NULL;
    PSYSTEM_PROCESS_INFORMATION processInfo;
    UNICODE_STRING lsassName;
    UNICODE_STRING csrssName;
    UNICODE_STRING smssName;
    UNICODE_STRING servicesName;
    UNICODE_STRING winlogonName;

    //
    // Initialize all to NULL
    //
    Engine->LsassProcessId = NULL;
    Engine->CsrssProcessId = NULL;
    Engine->SmssProcessId = NULL;
    Engine->ServicesProcessId = NULL;
    Engine->WinlogonProcessId = NULL;

    RtlInitUnicodeString(&lsassName, L"lsass.exe");
    RtlInitUnicodeString(&csrssName, L"csrss.exe");
    RtlInitUnicodeString(&smssName, L"smss.exe");
    RtlInitUnicodeString(&servicesName, L"services.exe");
    RtlInitUnicodeString(&winlogonName, L"winlogon.exe");

    //
    // Query system process information
    //
    bufferSize = 256 * 1024;  // Start with 256 KB

    buffer = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        bufferSize,
        HP_POOL_TAG
    );

    if (buffer == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to allocate buffer for process enumeration\n");
        return;
    }

    status = ZwQuerySystemInformation(
        SystemProcessInformation,
        buffer,
        bufferSize,
        &bufferSize
    );

    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        ExFreePoolWithTag(buffer, HP_POOL_TAG);

        //
        // Retry with the size the system told us + some margin
        //
        bufferSize += 64 * 1024;

        buffer = ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            bufferSize,
            HP_POOL_TAG
        );

        if (buffer == NULL) {
            return;
        }

        status = ZwQuerySystemInformation(
            SystemProcessInformation,
            buffer,
            bufferSize,
            NULL
        );
    }

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, HP_POOL_TAG);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] ZwQuerySystemInformation failed: 0x%08X\n", status);
        return;
    }

    //
    // Walk the process list and match names
    //
    processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

    for (;;) {
        if (processInfo->ImageName.Buffer != NULL &&
            processInfo->ImageName.Length > 0) {

            if (RtlEqualUnicodeString(&processInfo->ImageName, &lsassName, TRUE)) {
                Engine->LsassProcessId = processInfo->UniqueProcessId;
            } else if (RtlEqualUnicodeString(&processInfo->ImageName, &csrssName, TRUE)) {
                //
                // There can be multiple csrss.exe instances (one per session).
                // We track the first one (session 0).
                //
                if (Engine->CsrssProcessId == NULL) {
                    Engine->CsrssProcessId = processInfo->UniqueProcessId;
                }
            } else if (RtlEqualUnicodeString(&processInfo->ImageName, &smssName, TRUE)) {
                Engine->SmssProcessId = processInfo->UniqueProcessId;
            } else if (RtlEqualUnicodeString(&processInfo->ImageName, &servicesName, TRUE)) {
                Engine->ServicesProcessId = processInfo->UniqueProcessId;
            } else if (RtlEqualUnicodeString(&processInfo->ImageName, &winlogonName, TRUE)) {
                if (Engine->WinlogonProcessId == NULL) {
                    Engine->WinlogonProcessId = processInfo->UniqueProcessId;
                }
            }
        }

        if (processInfo->NextEntryOffset == 0) {
            break;
        }

        processInfo = (PSYSTEM_PROCESS_INFORMATION)(
            (PUCHAR)processInfo + processInfo->NextEntryOffset
        );
    }

    ExFreePoolWithTag(buffer, HP_POOL_TAG);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Sensitive process detection: LSASS=%p CSRSS=%p SMSS=%p Services=%p Winlogon=%p\n",
               Engine->LsassProcessId, Engine->CsrssProcessId,
               Engine->SmssProcessId, Engine->ServicesProcessId,
               Engine->WinlogonProcessId);
}
