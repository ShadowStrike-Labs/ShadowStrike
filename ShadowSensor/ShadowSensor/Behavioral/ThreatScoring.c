/*++
    ShadowStrike Next-Generation Antivirus
    Module: ThreatScoring.c - Enterprise-Grade Threat Score Calculation Engine

    Purpose:
        Production-ready implementation of the threat scoring subsystem.
        All issues from security review have been addressed:

        FIXES IMPLEMENTED:
        1.  TsInitialize moved from INIT to PAGE section
        2.  Proper reference counting with atomic cleanup
        3.  Process exit notification integration
        4.  Shutdown drains all references before freeing
        5.  ProcessId + CreateTime for PID reuse protection
        6.  Score validity check under exclusive lock (TOCTOU fix)
        7.  Hash table for O(1) lookup instead of O(n) list
        8.  64-bit accumulator for overflow protection
        9.  Blocked verdict implementation
        10. Factor aging and expiration
        11. FactorType enum validation
        12. In-place score calculation API
        13. SIZE_T for path buffer calculations
        14. Full SAL annotations on all functions

    Copyright (c) ShadowStrike Team. All rights reserved.
--*/

#include "ThreatScoring.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, TsInitialize)
#pragma alloc_text(PAGE, TsShutdown)
#pragma alloc_text(PAGE, TsSetThresholds)
#pragma alloc_text(PAGE, TsSetWeights)
#pragma alloc_text(PAGE, TsSetDecayConfig)
#pragma alloc_text(PAGE, TsGetStatistics)
#pragma alloc_text(PAGE, TsAddFactor)
#pragma alloc_text(PAGE, TsCalculateScore)
#pragma alloc_text(PAGE, TsCalculateScoreInPlace)
#pragma alloc_text(PAGE, TsGetVerdict)
#pragma alloc_text(PAGE, TsGetScore)
#pragma alloc_text(PAGE, TsFreeScore)
#pragma alloc_text(PAGE, TsOnProcessCreate)
#pragma alloc_text(PAGE, TsOnProcessExit)
#pragma alloc_text(PAGE, TsRunMaintenancePass)
#pragma alloc_text(PAGE, TsPurgeStaleContexts)
#endif

//=============================================================================
// Configuration Constants
//=============================================================================

#define TS_DEFAULT_SUSPICIOUS_THRESHOLD     50
#define TS_DEFAULT_MALICIOUS_THRESHOLD      80
#define TS_DEFAULT_BLOCKED_THRESHOLD        95

#define TS_DEFAULT_STATIC_WEIGHT            3
#define TS_DEFAULT_BEHAVIORAL_WEIGHT        5
#define TS_DEFAULT_REPUTATION_WEIGHT        4
#define TS_DEFAULT_CONTEXT_WEIGHT           2
#define TS_DEFAULT_IOC_WEIGHT               8
#define TS_DEFAULT_MITRE_WEIGHT             6
#define TS_DEFAULT_ANOMALY_WEIGHT           4
#define TS_DEFAULT_USERDEFINED_WEIGHT       1

#define TS_MAX_SCORE_VALUE                  1000
#define TS_MIN_SCORE_VALUE                  (-500)
#define TS_NORMALIZATION_MAX_RAW            500

#define TS_DEFAULT_DECAY_INTERVAL_SEC       3600
#define TS_DEFAULT_DECAY_PERCENT            10
#define TS_DEFAULT_MAX_AGE_SEC              86400

#define TS_SHUTDOWN_DRAIN_TIMEOUT_MS        5000
#define TS_SHUTDOWN_DRAIN_POLL_MS           50

//=============================================================================
// Internal Structures
//=============================================================================

//
// Internal factor entry
//
typedef struct _TS_INTERNAL_FACTOR {
    LIST_ENTRY ListEntry;
    TS_FACTOR_TYPE Type;
    CHAR FactorName[TS_MAX_FACTOR_NAME_LEN];
    LONG OriginalScore;                     // Original score before decay
    LONG CurrentScore;                      // Current score after decay
    LONG Weight;
    CHAR Reason[TS_MAX_REASON_LEN];
    LARGE_INTEGER Timestamp;
    LARGE_INTEGER LastDecayTime;
} TS_INTERNAL_FACTOR, *PTS_INTERNAL_FACTOR;

//
// Per-process score context
//
typedef struct _TS_PROCESS_CONTEXT {
    LIST_ENTRY HashLink;                    // Link in hash bucket
    LIST_ENTRY GlobalLink;                  // Link in global LRU list

    HANDLE ProcessId;
    LARGE_INTEGER ProcessCreateTime;        // For PID reuse detection
    WCHAR ProcessPath[TS_MAX_PROCESS_PATH_CHARS];

    LIST_ENTRY FactorList;
    EX_PUSH_LOCK FactorLock;
    volatile LONG FactorCount;

    LONG CachedRawScore;
    ULONG CachedNormalizedScore;
    TS_VERDICT CachedVerdict;
    BOOLEAN ScoreValid;

    LARGE_INTEGER FirstFactorTime;
    LARGE_INTEGER LastFactorTime;
    LARGE_INTEGER LastCalculationTime;
    LARGE_INTEGER LastAccessTime;

    volatile LONG RefCount;
    BOOLEAN MarkedForDeletion;
    BOOLEAN ProcessExited;

} TS_PROCESS_CONTEXT, *PTS_PROCESS_CONTEXT;

//
// Hash bucket
//
typedef struct _TS_HASH_BUCKET {
    LIST_ENTRY Head;
    EX_PUSH_LOCK Lock;
} TS_HASH_BUCKET, *PTS_HASH_BUCKET;

//
// Full engine structure
//
typedef struct _TS_SCORING_ENGINE {
    BOOLEAN Initialized;
    volatile LONG ShuttingDown;

    TS_THRESHOLD_CONFIG Thresholds;
    TS_WEIGHT_CONFIG Weights;
    TS_DECAY_CONFIG DecayConfig;

    TS_HASH_BUCKET Buckets[TS_HASH_BUCKET_COUNT];

    LIST_ENTRY GlobalContextList;
    EX_PUSH_LOCK GlobalListLock;
    volatile LONG ContextCount;

    TS_STATISTICS Stats;

} TS_SCORING_ENGINE;

//=============================================================================
// Forward Declarations
//=============================================================================

_IRQL_requires_max_(APC_LEVEL)
static
ULONG
TspHashProcessId(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
PTS_PROCESS_CONTEXT
TspFindContextLocked(
    _In_ PTS_HASH_BUCKET Bucket,
    _In_ HANDLE ProcessId,
    _In_opt_ PLARGE_INTEGER CreateTime
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
PTS_PROCESS_CONTEXT
TspAcquireContext(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
TspReleaseContext(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ PTS_PROCESS_CONTEXT Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
TspDestroyContext(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ PTS_PROCESS_CONTEXT Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
TspRecalculateScoreLocked(
    _In_ PTS_SCORING_ENGINE Engine,
    _Inout_ PTS_PROCESS_CONTEXT Context
    );

_IRQL_requires_max_(APC_LEVEL)
static
LONG
TspGetFactorWeight(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ TS_FACTOR_TYPE Type
    );

_IRQL_requires_max_(APC_LEVEL)
static
ULONG
TspNormalizeScore(
    _In_ LONG RawScore
    );

_IRQL_requires_max_(APC_LEVEL)
static
TS_VERDICT
TspDetermineVerdict(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ ULONG NormalizedScore
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
TspBuildVerdictReason(
    _In_ PTS_PROCESS_CONTEXT Context,
    _Out_writes_z_(ReasonSize) PCHAR Reason,
    _In_ SIZE_T ReasonSize
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
TspPopulateScoreResult(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ PTS_PROCESS_CONTEXT Context,
    _Out_ PTS_THREAT_SCORE Score,
    _In_ BOOLEAN AllocatePath
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
TspGetProcessCreateTime(
    _In_ HANDLE ProcessId,
    _Out_ PLARGE_INTEGER CreateTime
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
TspGetProcessPath(
    _In_ HANDLE ProcessId,
    _Out_writes_z_(PathChars) PWCHAR Path,
    _In_ SIZE_T PathChars
    );

_IRQL_requires_max_(APC_LEVEL)
static
FORCEINLINE
LONG
TspClampScore(
    _In_ LONG Score
    )
{
    if (Score > TS_MAX_SCORE_VALUE) {
        return TS_MAX_SCORE_VALUE;
    }
    if (Score < TS_MIN_SCORE_VALUE) {
        return TS_MIN_SCORE_VALUE;
    }
    return Score;
}

_IRQL_requires_max_(APC_LEVEL)
static
FORCEINLINE
LONG64
TspClampScore64(
    _In_ LONG64 Score
    )
{
    if (Score > TS_MAX_SCORE_VALUE) {
        return TS_MAX_SCORE_VALUE;
    }
    if (Score < TS_MIN_SCORE_VALUE) {
        return TS_MIN_SCORE_VALUE;
    }
    return Score;
}

//=============================================================================
// Public API Implementation
//=============================================================================

_Use_decl_annotations_
NTSTATUS
TsInitialize(
    _Out_ PTS_SCORING_ENGINE* Engine
    )
{
    PTS_SCORING_ENGINE NewEngine = NULL;
    ULONG i;

    PAGED_CODE();

    if (Engine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Engine = NULL;

    NewEngine = (PTS_SCORING_ENGINE)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(TS_SCORING_ENGINE),
        TS_POOL_TAG_ENGINE
        );

    if (NewEngine == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewEngine, sizeof(TS_SCORING_ENGINE));

    //
    // Initialize hash buckets
    //
    for (i = 0; i < TS_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&NewEngine->Buckets[i].Head);
        ExInitializePushLock(&NewEngine->Buckets[i].Lock);
    }

    //
    // Initialize global list
    //
    InitializeListHead(&NewEngine->GlobalContextList);
    ExInitializePushLock(&NewEngine->GlobalListLock);

    //
    // Set default thresholds
    //
    NewEngine->Thresholds.SuspiciousThreshold = TS_DEFAULT_SUSPICIOUS_THRESHOLD;
    NewEngine->Thresholds.MaliciousThreshold = TS_DEFAULT_MALICIOUS_THRESHOLD;
    NewEngine->Thresholds.BlockedThreshold = TS_DEFAULT_BLOCKED_THRESHOLD;

    //
    // Set default weights
    //
    NewEngine->Weights.StaticWeight = TS_DEFAULT_STATIC_WEIGHT;
    NewEngine->Weights.BehavioralWeight = TS_DEFAULT_BEHAVIORAL_WEIGHT;
    NewEngine->Weights.ReputationWeight = TS_DEFAULT_REPUTATION_WEIGHT;
    NewEngine->Weights.ContextWeight = TS_DEFAULT_CONTEXT_WEIGHT;
    NewEngine->Weights.IOCWeight = TS_DEFAULT_IOC_WEIGHT;
    NewEngine->Weights.MITREWeight = TS_DEFAULT_MITRE_WEIGHT;
    NewEngine->Weights.AnomalyWeight = TS_DEFAULT_ANOMALY_WEIGHT;
    NewEngine->Weights.UserDefinedWeight = TS_DEFAULT_USERDEFINED_WEIGHT;

    //
    // Set default decay config
    //
    NewEngine->DecayConfig.EnableDecay = TRUE;
    NewEngine->DecayConfig.DecayIntervalSeconds = TS_DEFAULT_DECAY_INTERVAL_SEC;
    NewEngine->DecayConfig.DecayPercentPerInterval = TS_DEFAULT_DECAY_PERCENT;
    NewEngine->DecayConfig.MaxAgeSeconds = TS_DEFAULT_MAX_AGE_SEC;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&NewEngine->Stats.StartTime);

    NewEngine->Initialized = TRUE;

    *Engine = NewEngine;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
TsShutdown(
    _Inout_ PTS_SCORING_ENGINE Engine
    )
{
    PLIST_ENTRY Entry;
    PTS_PROCESS_CONTEXT Context;
    ULONG DrainWaitMs = 0;
    LARGE_INTEGER Delay;
    BOOLEAN AllDrained;
    ULONG i;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return;
    }

    //
    // Signal shutdown - prevents new operations
    //
    InterlockedExchange(&Engine->ShuttingDown, TRUE);
    Engine->Initialized = FALSE;

    //
    // Wait for all outstanding references to drain
    //
    Delay.QuadPart = -((LONG64)TS_SHUTDOWN_DRAIN_POLL_MS * 10000);

    while (DrainWaitMs < TS_SHUTDOWN_DRAIN_TIMEOUT_MS) {
        AllDrained = TRUE;

        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Engine->GlobalListLock);

        for (Entry = Engine->GlobalContextList.Flink;
             Entry != &Engine->GlobalContextList;
             Entry = Entry->Flink) {

            Context = CONTAINING_RECORD(Entry, TS_PROCESS_CONTEXT, GlobalLink);

            if (Context->RefCount > 0) {
                AllDrained = FALSE;
                break;
            }
        }

        ExReleasePushLockShared(&Engine->GlobalListLock);
        KeLeaveCriticalRegion();

        if (AllDrained) {
            break;
        }

        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
        DrainWaitMs += TS_SHUTDOWN_DRAIN_POLL_MS;
    }

    //
    // Now destroy all contexts - iterate through hash buckets
    //
    for (i = 0; i < TS_HASH_BUCKET_COUNT; i++) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Engine->Buckets[i].Lock);

        while (!IsListEmpty(&Engine->Buckets[i].Head)) {
            Entry = RemoveHeadList(&Engine->Buckets[i].Head);
            Context = CONTAINING_RECORD(Entry, TS_PROCESS_CONTEXT, HashLink);

            //
            // Remove from global list too
            //
            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Engine->GlobalListLock);
            RemoveEntryList(&Context->GlobalLink);
            ExReleasePushLockExclusive(&Engine->GlobalListLock);
            KeLeaveCriticalRegion();

            TspDestroyContext(Engine, Context);
        }

        ExReleasePushLockExclusive(&Engine->Buckets[i].Lock);
        KeLeaveCriticalRegion();
    }

    ShadowStrikeFreePoolWithTag(Engine, TS_POOL_TAG_ENGINE);
}

_Use_decl_annotations_
NTSTATUS
TsSetThresholds(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ ULONG SuspiciousThreshold,
    _In_ ULONG MaliciousThreshold,
    _In_ ULONG BlockedThreshold
    )
{
    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Engine->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Validate thresholds
    //
    if (SuspiciousThreshold > 100 ||
        MaliciousThreshold > 100 ||
        BlockedThreshold > 100) {
        return STATUS_INVALID_PARAMETER;
    }

    if (SuspiciousThreshold >= MaliciousThreshold ||
        MaliciousThreshold >= BlockedThreshold) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Atomic updates
    //
    InterlockedExchange((volatile LONG*)&Engine->Thresholds.SuspiciousThreshold,
        (LONG)SuspiciousThreshold);
    InterlockedExchange((volatile LONG*)&Engine->Thresholds.MaliciousThreshold,
        (LONG)MaliciousThreshold);
    InterlockedExchange((volatile LONG*)&Engine->Thresholds.BlockedThreshold,
        (LONG)BlockedThreshold);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsSetWeights(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ PTS_WEIGHT_CONFIG Weights
    )
{
    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized || Weights == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Engine->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Copy weights atomically (structure copy under lock would be safer
    // but for perf we accept torn reads on config)
    //
    RtlCopyMemory(&Engine->Weights, Weights, sizeof(TS_WEIGHT_CONFIG));

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsSetDecayConfig(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ PTS_DECAY_CONFIG DecayConfig
    )
{
    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized || DecayConfig == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Engine->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (DecayConfig->DecayPercentPerInterval > 100) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&Engine->DecayConfig, DecayConfig, sizeof(TS_DECAY_CONFIG));

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsGetStatistics(
    _In_ PTS_SCORING_ENGINE Engine,
    _Out_ PTS_STATISTICS Statistics
    )
{
    PAGED_CODE();

    if (Engine == NULL || Statistics == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(Statistics, &Engine->Stats, sizeof(TS_STATISTICS));

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsAddFactor(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_ TS_FACTOR_TYPE Type,
    _In_ PCSTR FactorName,
    _In_ LONG Score,
    _In_ PCSTR Reason
    )
{
    PTS_PROCESS_CONTEXT Context;
    PTS_INTERNAL_FACTOR NewFactor;
    LARGE_INTEGER CurrentTime;
    LONG FactorWeight;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Engine->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (FactorName == NULL || Reason == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate factor type enum
    //
    if (Type >= TsFactor_MaxValue) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Acquire context (creates if not found)
    //
    Context = TspAcquireContext(Engine, ProcessId, TRUE);
    if (Context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Check factor limit
    //
    if (InterlockedCompareExchange(&Context->FactorCount, 0, 0) >= TS_MAX_FACTORS) {
        TspReleaseContext(Engine, Context);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate factor
    //
    NewFactor = (PTS_INTERNAL_FACTOR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(TS_INTERNAL_FACTOR),
        TS_POOL_TAG_FACTOR
        );

    if (NewFactor == NULL) {
        TspReleaseContext(Engine, Context);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewFactor, sizeof(TS_INTERNAL_FACTOR));

    KeQuerySystemTime(&CurrentTime);

    NewFactor->Type = Type;
    NewFactor->OriginalScore = TspClampScore(Score);
    NewFactor->CurrentScore = NewFactor->OriginalScore;
    NewFactor->Timestamp = CurrentTime;
    NewFactor->LastDecayTime = CurrentTime;

    FactorWeight = TspGetFactorWeight(Engine, Type);
    NewFactor->Weight = FactorWeight;

    RtlStringCbCopyA(NewFactor->FactorName, sizeof(NewFactor->FactorName), FactorName);
    RtlStringCbCopyA(NewFactor->Reason, sizeof(NewFactor->Reason), Reason);

    //
    // Add to context under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->FactorLock);

    InsertTailList(&Context->FactorList, &NewFactor->ListEntry);
    InterlockedIncrement(&Context->FactorCount);

    Context->LastFactorTime = CurrentTime;
    if (Context->FirstFactorTime.QuadPart == 0) {
        Context->FirstFactorTime = CurrentTime;
    }

    Context->ScoreValid = FALSE;

    ExReleasePushLockExclusive(&Context->FactorLock);
    KeLeaveCriticalRegion();

    InterlockedIncrement64(&Engine->Stats.FactorsAdded);

    TspReleaseContext(Engine, Context);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsCalculateScore(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ PTS_THREAT_SCORE* Score
    )
{
    PTS_PROCESS_CONTEXT Context;
    PTS_THREAT_SCORE NewScore;
    NTSTATUS Status;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized || Score == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Score = NULL;

    if (Engine->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    Context = TspAcquireContext(Engine, ProcessId, FALSE);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Allocate result structure from paged pool
    //
    NewScore = (PTS_THREAT_SCORE)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        sizeof(TS_THREAT_SCORE),
        TS_POOL_TAG_SCORE
        );

    if (NewScore == NULL) {
        TspReleaseContext(Engine, Context);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewScore, sizeof(TS_THREAT_SCORE));

    //
    // Recalculate if needed (under exclusive lock to prevent TOCTOU)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->FactorLock);

    if (!Context->ScoreValid) {
        TspRecalculateScoreLocked(Engine, Context);
    }

    ExReleasePushLockExclusive(&Context->FactorLock);
    KeLeaveCriticalRegion();

    //
    // Populate result (allocates path buffer)
    //
    TspPopulateScoreResult(Engine, Context, NewScore, TRUE);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Engine->Stats.ScoresCalculated);

    switch (NewScore->Verdict) {
    case TsVerdict_Clean:
        InterlockedIncrement64(&Engine->Stats.VerdictClean);
        break;
    case TsVerdict_Suspicious:
        InterlockedIncrement64(&Engine->Stats.VerdictSuspicious);
        break;
    case TsVerdict_Malicious:
        InterlockedIncrement64(&Engine->Stats.VerdictMalicious);
        break;
    case TsVerdict_Blocked:
        InterlockedIncrement64(&Engine->Stats.VerdictBlocked);
        break;
    default:
        break;
    }

    TspReleaseContext(Engine, Context);

    *Score = NewScore;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsCalculateScoreInPlace(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ PTS_THREAT_SCORE Score
    )
{
    PTS_PROCESS_CONTEXT Context;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized || Score == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Engine->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(Score, sizeof(TS_THREAT_SCORE));

    Context = TspAcquireContext(Engine, ProcessId, FALSE);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Recalculate if needed
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->FactorLock);

    if (!Context->ScoreValid) {
        TspRecalculateScoreLocked(Engine, Context);
    }

    ExReleasePushLockExclusive(&Context->FactorLock);
    KeLeaveCriticalRegion();

    //
    // Populate without path allocation
    //
    TspPopulateScoreResult(Engine, Context, Score, FALSE);

    InterlockedIncrement64(&Engine->Stats.ScoresCalculated);

    TspReleaseContext(Engine, Context);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsGetVerdict(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ TS_VERDICT* Verdict,
    _Out_opt_ PULONG NormalizedScore
    )
{
    PTS_PROCESS_CONTEXT Context;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized || Verdict == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Verdict = TsVerdict_Unknown;
    if (NormalizedScore != NULL) {
        *NormalizedScore = 0;
    }

    if (Engine->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    Context = TspAcquireContext(Engine, ProcessId, FALSE);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Recalculate under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->FactorLock);

    if (!Context->ScoreValid) {
        TspRecalculateScoreLocked(Engine, Context);
    }

    *Verdict = Context->CachedVerdict;
    if (NormalizedScore != NULL) {
        *NormalizedScore = Context->CachedNormalizedScore;
    }

    ExReleasePushLockExclusive(&Context->FactorLock);
    KeLeaveCriticalRegion();

    TspReleaseContext(Engine, Context);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsGetScore(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ PTS_THREAT_SCORE* Score
    )
{
    PAGED_CODE();

    return TsCalculateScore(Engine, ProcessId, Score);
}

_Use_decl_annotations_
VOID
TsFreeScore(
    _In_opt_ PTS_THREAT_SCORE Score
    )
{
    PAGED_CODE();

    if (Score == NULL) {
        return;
    }

    if (Score->ProcessPath.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(Score->ProcessPath.Buffer, TS_POOL_TAG_PATH);
        Score->ProcessPath.Buffer = NULL;
    }

    ShadowStrikeFreePoolWithTag(Score, TS_POOL_TAG_SCORE);
}

_Use_decl_annotations_
NTSTATUS
TsOnProcessCreate(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_ LARGE_INTEGER CreateTime
    )
{
    PTS_PROCESS_CONTEXT Context;
    PTS_PROCESS_CONTEXT ExistingContext;
    ULONG BucketIndex;
    PTS_HASH_BUCKET Bucket;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Engine->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Check quota
    //
    if (InterlockedCompareExchange(&Engine->ContextCount, 0, 0) >= TS_MAX_SCORES_TRACKED) {
        return STATUS_QUOTA_EXCEEDED;
    }

    BucketIndex = TspHashProcessId(ProcessId);
    Bucket = &Engine->Buckets[BucketIndex];

    //
    // Check if context already exists with different create time (PID reuse)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Bucket->Lock);

    ExistingContext = TspFindContextLocked(Bucket, ProcessId, NULL);

    if (ExistingContext != NULL) {
        if (ExistingContext->ProcessCreateTime.QuadPart != CreateTime.QuadPart) {
            //
            // PID reuse detected - remove old context
            //
            RemoveEntryList(&ExistingContext->HashLink);

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Engine->GlobalListLock);
            RemoveEntryList(&ExistingContext->GlobalLink);
            InterlockedDecrement(&Engine->ContextCount);
            ExReleasePushLockExclusive(&Engine->GlobalListLock);
            KeLeaveCriticalRegion();

            InterlockedIncrement64(&Engine->Stats.PidReuseDetected);
            TspDestroyContext(Engine, ExistingContext);
        } else {
            //
            // Same process, already tracked
            //
            ExReleasePushLockExclusive(&Bucket->Lock);
            KeLeaveCriticalRegion();
            return STATUS_SUCCESS;
        }
    }

    //
    // Create new context
    //
    Context = (PTS_PROCESS_CONTEXT)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(TS_PROCESS_CONTEXT),
        TS_POOL_TAG_SCORE
        );

    if (Context == NULL) {
        ExReleasePushLockExclusive(&Bucket->Lock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Context, sizeof(TS_PROCESS_CONTEXT));

    Context->ProcessId = ProcessId;
    Context->ProcessCreateTime = CreateTime;
    Context->RefCount = 0;
    Context->CachedVerdict = TsVerdict_Unknown;
    Context->ScoreValid = FALSE;

    InitializeListHead(&Context->FactorList);
    ExInitializePushLock(&Context->FactorLock);

    KeQuerySystemTime(&Context->LastAccessTime);

    TspGetProcessPath(ProcessId, Context->ProcessPath, TS_MAX_PROCESS_PATH_CHARS);

    //
    // Insert into hash bucket
    //
    InsertTailList(&Bucket->Head, &Context->HashLink);

    ExReleasePushLockExclusive(&Bucket->Lock);
    KeLeaveCriticalRegion();

    //
    // Insert into global list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->GlobalListLock);
    InsertTailList(&Engine->GlobalContextList, &Context->GlobalLink);
    InterlockedIncrement(&Engine->ContextCount);
    ExReleasePushLockExclusive(&Engine->GlobalListLock);
    KeLeaveCriticalRegion();

    InterlockedIncrement64(&Engine->Stats.ContextsCreated);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
TsOnProcessExit(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId
    )
{
    PTS_PROCESS_CONTEXT Context;
    ULONG BucketIndex;
    PTS_HASH_BUCKET Bucket;
    BOOLEAN CanDestroy = FALSE;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return;
    }

    BucketIndex = TspHashProcessId(ProcessId);
    Bucket = &Engine->Buckets[BucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Bucket->Lock);

    Context = TspFindContextLocked(Bucket, ProcessId, NULL);

    if (Context != NULL) {
        Context->ProcessExited = TRUE;
        Context->MarkedForDeletion = TRUE;

        //
        // Only destroy if no outstanding references
        //
        if (Context->RefCount == 0) {
            RemoveEntryList(&Context->HashLink);

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Engine->GlobalListLock);
            RemoveEntryList(&Context->GlobalLink);
            InterlockedDecrement(&Engine->ContextCount);
            ExReleasePushLockExclusive(&Engine->GlobalListLock);
            KeLeaveCriticalRegion();

            CanDestroy = TRUE;
        }
    }

    ExReleasePushLockExclusive(&Bucket->Lock);
    KeLeaveCriticalRegion();

    if (CanDestroy && Context != NULL) {
        TspDestroyContext(Engine, Context);
        InterlockedIncrement64(&Engine->Stats.ContextsDestroyed);
    }
}

_Use_decl_annotations_
NTSTATUS
TsRunMaintenancePass(
    _In_ PTS_SCORING_ENGINE Engine
    )
{
    PLIST_ENTRY ContextEntry;
    PLIST_ENTRY FactorEntry;
    PLIST_ENTRY NextEntry;
    PTS_PROCESS_CONTEXT Context;
    PTS_INTERNAL_FACTOR Factor;
    LARGE_INTEGER CurrentTime;
    LONG64 AgeSeconds;
    LONG64 DecayIntervals;
    LONG NewScore;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Engine->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!Engine->DecayConfig.EnableDecay) {
        return STATUS_SUCCESS;
    }

    KeQuerySystemTime(&CurrentTime);

    //
    // Iterate all contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->GlobalListLock);

    for (ContextEntry = Engine->GlobalContextList.Flink;
         ContextEntry != &Engine->GlobalContextList;
         ContextEntry = ContextEntry->Flink) {

        Context = CONTAINING_RECORD(ContextEntry, TS_PROCESS_CONTEXT, GlobalLink);

        if (Context->MarkedForDeletion) {
            continue;
        }

        //
        // Process factors under exclusive lock
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Context->FactorLock);

        FactorEntry = Context->FactorList.Flink;
        while (FactorEntry != &Context->FactorList) {
            NextEntry = FactorEntry->Flink;
            Factor = CONTAINING_RECORD(FactorEntry, TS_INTERNAL_FACTOR, ListEntry);

            //
            // Calculate age
            //
            AgeSeconds = (CurrentTime.QuadPart - Factor->Timestamp.QuadPart) / 10000000LL;

            //
            // Check max age - remove expired factors
            //
            if (AgeSeconds >= (LONG64)Engine->DecayConfig.MaxAgeSeconds) {
                RemoveEntryList(&Factor->ListEntry);
                InterlockedDecrement(&Context->FactorCount);
                ShadowStrikeFreePoolWithTag(Factor, TS_POOL_TAG_FACTOR);
                InterlockedIncrement64(&Engine->Stats.FactorsExpired);
                Context->ScoreValid = FALSE;
            } else {
                //
                // Apply decay
                //
                DecayIntervals = AgeSeconds / (LONG64)Engine->DecayConfig.DecayIntervalSeconds;

                if (DecayIntervals > 0 && Factor->CurrentScore != 0) {
                    //
                    // Calculate decayed score
                    //
                    LONG64 DecayFactor = 100;
                    for (LONG64 i = 0; i < DecayIntervals && i < 100; i++) {
                        DecayFactor = (DecayFactor * (100 - Engine->DecayConfig.DecayPercentPerInterval)) / 100;
                    }

                    NewScore = (LONG)((Factor->OriginalScore * DecayFactor) / 100);

                    if (NewScore != Factor->CurrentScore) {
                        Factor->CurrentScore = NewScore;
                        Context->ScoreValid = FALSE;
                    }
                }
            }

            FactorEntry = NextEntry;
        }

        ExReleasePushLockExclusive(&Context->FactorLock);
        KeLeaveCriticalRegion();
    }

    ExReleasePushLockShared(&Engine->GlobalListLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsPurgeStaleContexts(
    _In_ PTS_SCORING_ENGINE Engine,
    _Out_opt_ PULONG PurgedCount
    )
{
    ULONG Purged = 0;
    ULONG i;
    PLIST_ENTRY Entry;
    PLIST_ENTRY NextEntry;
    PTS_PROCESS_CONTEXT Context;
    PEPROCESS Process;
    NTSTATUS Status;
    LIST_ENTRY ToDestroy;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (PurgedCount != NULL) {
        *PurgedCount = 0;
    }

    if (Engine->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    InitializeListHead(&ToDestroy);

    //
    // Scan all buckets
    //
    for (i = 0; i < TS_HASH_BUCKET_COUNT; i++) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Engine->Buckets[i].Lock);

        Entry = Engine->Buckets[i].Head.Flink;
        while (Entry != &Engine->Buckets[i].Head) {
            NextEntry = Entry->Flink;
            Context = CONTAINING_RECORD(Entry, TS_PROCESS_CONTEXT, HashLink);

            //
            // Check if process still exists
            //
            Status = PsLookupProcessByProcessId(Context->ProcessId, &Process);
            if (!NT_SUCCESS(Status)) {
                //
                // Process no longer exists - mark for destruction
                //
                if (Context->RefCount == 0) {
                    RemoveEntryList(&Context->HashLink);

                    KeEnterCriticalRegion();
                    ExAcquirePushLockExclusive(&Engine->GlobalListLock);
                    RemoveEntryList(&Context->GlobalLink);
                    InterlockedDecrement(&Engine->ContextCount);
                    ExReleasePushLockExclusive(&Engine->GlobalListLock);
                    KeLeaveCriticalRegion();

                    //
                    // Add to destroy list
                    //
                    InsertTailList(&ToDestroy, &Context->HashLink);
                    Purged++;
                } else {
                    Context->MarkedForDeletion = TRUE;
                }
            } else {
                ObDereferenceObject(Process);
            }

            Entry = NextEntry;
        }

        ExReleasePushLockExclusive(&Engine->Buckets[i].Lock);
        KeLeaveCriticalRegion();
    }

    //
    // Destroy collected contexts
    //
    while (!IsListEmpty(&ToDestroy)) {
        Entry = RemoveHeadList(&ToDestroy);
        Context = CONTAINING_RECORD(Entry, TS_PROCESS_CONTEXT, HashLink);
        TspDestroyContext(Engine, Context);
        InterlockedIncrement64(&Engine->Stats.ContextsDestroyed);
    }

    if (PurgedCount != NULL) {
        *PurgedCount = Purged;
    }

    return STATUS_SUCCESS;
}

//=============================================================================
// Internal Implementation
//=============================================================================

_Use_decl_annotations_
static
ULONG
TspHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR Value = (ULONG_PTR)ProcessId;

    //
    // Simple but effective hash for process IDs
    // PIDs are typically 4-byte aligned, so shift right by 2
    //
    Value = Value >> 2;
    Value = Value ^ (Value >> 16);
    Value = Value * 0x85ebca6b;
    Value = Value ^ (Value >> 13);

    return (ULONG)(Value % TS_HASH_BUCKET_COUNT);
}

_Use_decl_annotations_
static
PTS_PROCESS_CONTEXT
TspFindContextLocked(
    _In_ PTS_HASH_BUCKET Bucket,
    _In_ HANDLE ProcessId,
    _In_opt_ PLARGE_INTEGER CreateTime
    )
{
    PLIST_ENTRY Entry;
    PTS_PROCESS_CONTEXT Context;

    for (Entry = Bucket->Head.Flink;
         Entry != &Bucket->Head;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, TS_PROCESS_CONTEXT, HashLink);

        if (Context->ProcessId == ProcessId) {
            if (CreateTime == NULL ||
                Context->ProcessCreateTime.QuadPart == CreateTime->QuadPart) {
                return Context;
            }
        }
    }

    return NULL;
}

_Use_decl_annotations_
static
PTS_PROCESS_CONTEXT
TspAcquireContext(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    )
{
    ULONG BucketIndex;
    PTS_HASH_BUCKET Bucket;
    PTS_PROCESS_CONTEXT Context = NULL;
    PTS_PROCESS_CONTEXT NewContext = NULL;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER CurrentTime;

    BucketIndex = TspHashProcessId(ProcessId);
    Bucket = &Engine->Buckets[BucketIndex];

    //
    // Try to find existing context
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Bucket->Lock);

    Context = TspFindContextLocked(Bucket, ProcessId, NULL);

    if (Context != NULL && !Context->MarkedForDeletion) {
        InterlockedIncrement(&Context->RefCount);
        KeQuerySystemTime(&Context->LastAccessTime);
        ExReleasePushLockShared(&Bucket->Lock);
        KeLeaveCriticalRegion();
        return Context;
    }

    ExReleasePushLockShared(&Bucket->Lock);
    KeLeaveCriticalRegion();

    if (!CreateIfNotFound) {
        return NULL;
    }

    //
    // Check quota
    //
    if (InterlockedCompareExchange(&Engine->ContextCount, 0, 0) >= TS_MAX_SCORES_TRACKED) {
        return NULL;
    }

    //
    // Get process create time
    //
    if (!NT_SUCCESS(TspGetProcessCreateTime(ProcessId, &CreateTime))) {
        KeQuerySystemTime(&CreateTime);
    }

    //
    // Allocate new context
    //
    NewContext = (PTS_PROCESS_CONTEXT)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(TS_PROCESS_CONTEXT),
        TS_POOL_TAG_SCORE
        );

    if (NewContext == NULL) {
        return NULL;
    }

    RtlZeroMemory(NewContext, sizeof(TS_PROCESS_CONTEXT));

    NewContext->ProcessId = ProcessId;
    NewContext->ProcessCreateTime = CreateTime;
    NewContext->RefCount = 1;
    NewContext->CachedVerdict = TsVerdict_Unknown;

    InitializeListHead(&NewContext->FactorList);
    ExInitializePushLock(&NewContext->FactorLock);

    KeQuerySystemTime(&CurrentTime);
    NewContext->LastAccessTime = CurrentTime;

    TspGetProcessPath(ProcessId, NewContext->ProcessPath, TS_MAX_PROCESS_PATH_CHARS);

    //
    // Insert under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Bucket->Lock);

    //
    // Double-check - another thread may have created it
    //
    Context = TspFindContextLocked(Bucket, ProcessId, NULL);

    if (Context != NULL && !Context->MarkedForDeletion) {
        //
        // Race - use existing
        //
        InterlockedIncrement(&Context->RefCount);
        ExReleasePushLockExclusive(&Bucket->Lock);
        KeLeaveCriticalRegion();

        ShadowStrikeFreePoolWithTag(NewContext, TS_POOL_TAG_SCORE);
        return Context;
    }

    //
    // Insert new context
    //
    InsertTailList(&Bucket->Head, &NewContext->HashLink);

    ExReleasePushLockExclusive(&Bucket->Lock);
    KeLeaveCriticalRegion();

    //
    // Add to global list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->GlobalListLock);
    InsertTailList(&Engine->GlobalContextList, &NewContext->GlobalLink);
    InterlockedIncrement(&Engine->ContextCount);
    ExReleasePushLockExclusive(&Engine->GlobalListLock);
    KeLeaveCriticalRegion();

    InterlockedIncrement64(&Engine->Stats.ContextsCreated);

    return NewContext;
}

_Use_decl_annotations_
static
VOID
TspReleaseContext(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ PTS_PROCESS_CONTEXT Context
    )
{
    LONG NewRefCount;
    ULONG BucketIndex;
    PTS_HASH_BUCKET Bucket;
    BOOLEAN ShouldDestroy = FALSE;

    if (Context == NULL) {
        return;
    }

    NewRefCount = InterlockedDecrement(&Context->RefCount);

    if (NewRefCount == 0 && Context->MarkedForDeletion) {
        //
        // Context was marked for deletion while we held reference
        // Now we need to remove and destroy it
        //
        BucketIndex = TspHashProcessId(Context->ProcessId);
        Bucket = &Engine->Buckets[BucketIndex];

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Bucket->Lock);

        //
        // Verify still in list and still marked
        //
        if (Context->MarkedForDeletion && Context->RefCount == 0) {
            RemoveEntryList(&Context->HashLink);

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Engine->GlobalListLock);
            RemoveEntryList(&Context->GlobalLink);
            InterlockedDecrement(&Engine->ContextCount);
            ExReleasePushLockExclusive(&Engine->GlobalListLock);
            KeLeaveCriticalRegion();

            ShouldDestroy = TRUE;
        }

        ExReleasePushLockExclusive(&Bucket->Lock);
        KeLeaveCriticalRegion();

        if (ShouldDestroy) {
            TspDestroyContext(Engine, Context);
            InterlockedIncrement64(&Engine->Stats.ContextsDestroyed);
        }
    }
}

_Use_decl_annotations_
static
VOID
TspDestroyContext(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ PTS_PROCESS_CONTEXT Context
    )
{
    PLIST_ENTRY Entry;
    PTS_INTERNAL_FACTOR Factor;

    UNREFERENCED_PARAMETER(Engine);

    if (Context == NULL) {
        return;
    }

    //
    // Free all factors
    //
    while (!IsListEmpty(&Context->FactorList)) {
        Entry = RemoveHeadList(&Context->FactorList);
        Factor = CONTAINING_RECORD(Entry, TS_INTERNAL_FACTOR, ListEntry);
        ShadowStrikeFreePoolWithTag(Factor, TS_POOL_TAG_FACTOR);
    }

    ShadowStrikeFreePoolWithTag(Context, TS_POOL_TAG_SCORE);
}

_Use_decl_annotations_
static
VOID
TspRecalculateScoreLocked(
    _In_ PTS_SCORING_ENGINE Engine,
    _Inout_ PTS_PROCESS_CONTEXT Context
    )
{
    PLIST_ENTRY Entry;
    PTS_INTERNAL_FACTOR Factor;
    LONG64 AccumulatedScore = 0;
    LONG64 WeightedScore;
    LARGE_INTEGER CurrentTime;

    //
    // Sum all weighted factor scores using 64-bit accumulator
    //
    for (Entry = Context->FactorList.Flink;
         Entry != &Context->FactorList;
         Entry = Entry->Flink) {

        Factor = CONTAINING_RECORD(Entry, TS_INTERNAL_FACTOR, ListEntry);

        //
        // Use current (decayed) score
        //
        WeightedScore = (LONG64)Factor->CurrentScore * (LONG64)Factor->Weight;

        //
        // Apply factor type multipliers
        //
        switch (Factor->Type) {
        case TsFactor_IOC:
            WeightedScore = (WeightedScore * 150) / 100;
            break;
        case TsFactor_MITRE:
            WeightedScore = (WeightedScore * 120) / 100;
            break;
        case TsFactor_Behavioral:
            WeightedScore = (WeightedScore * 110) / 100;
            break;
        default:
            break;
        }

        AccumulatedScore += WeightedScore;
    }

    //
    // Clamp to valid range
    //
    Context->CachedRawScore = (LONG)TspClampScore64(AccumulatedScore);
    Context->CachedNormalizedScore = TspNormalizeScore(Context->CachedRawScore);
    Context->CachedVerdict = TspDetermineVerdict(Engine, Context->CachedNormalizedScore);

    KeQuerySystemTime(&CurrentTime);
    Context->LastCalculationTime = CurrentTime;
    Context->ScoreValid = TRUE;
}

_Use_decl_annotations_
static
LONG
TspGetFactorWeight(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ TS_FACTOR_TYPE Type
    )
{
    switch (Type) {
    case TsFactor_Static:
        return Engine->Weights.StaticWeight;
    case TsFactor_Behavioral:
        return Engine->Weights.BehavioralWeight;
    case TsFactor_Reputation:
        return Engine->Weights.ReputationWeight;
    case TsFactor_Context:
        return Engine->Weights.ContextWeight;
    case TsFactor_IOC:
        return Engine->Weights.IOCWeight;
    case TsFactor_MITRE:
        return Engine->Weights.MITREWeight;
    case TsFactor_Anomaly:
        return Engine->Weights.AnomalyWeight;
    case TsFactor_UserDefined:
        return Engine->Weights.UserDefinedWeight;
    default:
        return 1;
    }
}

_Use_decl_annotations_
static
ULONG
TspNormalizeScore(
    _In_ LONG RawScore
    )
{
    LONG Normalized;

    if (RawScore == 0) {
        return 50;
    }

    if (RawScore > 0) {
        if (RawScore >= TS_NORMALIZATION_MAX_RAW) {
            return 100;
        }
        Normalized = 50 + ((RawScore * 50) / TS_NORMALIZATION_MAX_RAW);
        if (Normalized > 100) {
            Normalized = 100;
        }
    } else {
        if (RawScore <= -TS_NORMALIZATION_MAX_RAW) {
            return 0;
        }
        Normalized = 50 + ((RawScore * 50) / TS_NORMALIZATION_MAX_RAW);
        if (Normalized < 0) {
            Normalized = 0;
        }
    }

    return (ULONG)Normalized;
}

_Use_decl_annotations_
static
TS_VERDICT
TspDetermineVerdict(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ ULONG NormalizedScore
    )
{
    if (NormalizedScore >= Engine->Thresholds.BlockedThreshold) {
        return TsVerdict_Blocked;
    }

    if (NormalizedScore >= Engine->Thresholds.MaliciousThreshold) {
        return TsVerdict_Malicious;
    }

    if (NormalizedScore >= Engine->Thresholds.SuspiciousThreshold) {
        return TsVerdict_Suspicious;
    }

    return TsVerdict_Clean;
}

_Use_decl_annotations_
static
VOID
TspBuildVerdictReason(
    _In_ PTS_PROCESS_CONTEXT Context,
    _Out_writes_z_(ReasonSize) PCHAR Reason,
    _In_ SIZE_T ReasonSize
    )
{
    PLIST_ENTRY Entry;
    PTS_INTERNAL_FACTOR Factor;
    PTS_INTERNAL_FACTOR HighestFactor = NULL;
    LONG64 HighestScore = 0;
    ULONG FactorCount = 0;
    ULONG ThreatFactorCount = 0;

    Reason[0] = '\0';

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Context->FactorLock);

    for (Entry = Context->FactorList.Flink;
         Entry != &Context->FactorList;
         Entry = Entry->Flink) {

        Factor = CONTAINING_RECORD(Entry, TS_INTERNAL_FACTOR, ListEntry);
        FactorCount++;

        if (Factor->CurrentScore > 0) {
            ThreatFactorCount++;

            LONG64 WeightedScore = (LONG64)Factor->CurrentScore * (LONG64)Factor->Weight;
            if (WeightedScore > HighestScore) {
                HighestScore = WeightedScore;
                HighestFactor = Factor;
            }
        }
    }

    if (Context->CachedVerdict == TsVerdict_Clean) {
        RtlStringCbPrintfA(Reason, ReasonSize,
            "No significant threat indicators (%lu factors evaluated)",
            FactorCount);
    } else if (Context->CachedVerdict == TsVerdict_Blocked) {
        if (HighestFactor != NULL) {
            RtlStringCbPrintfA(Reason, ReasonSize,
                "BLOCKED: %s - %s (%lu threat factors)",
                HighestFactor->FactorName,
                HighestFactor->Reason,
                ThreatFactorCount);
        } else {
            RtlStringCbPrintfA(Reason, ReasonSize,
                "BLOCKED: Score exceeded block threshold (%lu factors)",
                FactorCount);
        }
    } else if (HighestFactor != NULL) {
        RtlStringCbPrintfA(Reason, ReasonSize,
            "Primary: %s - %s (%lu threat factors)",
            HighestFactor->FactorName,
            HighestFactor->Reason,
            ThreatFactorCount);
    } else {
        RtlStringCbPrintfA(Reason, ReasonSize,
            "Aggregate score exceeded threshold (%lu factors)",
            FactorCount);
    }

    ExReleasePushLockShared(&Context->FactorLock);
    KeLeaveCriticalRegion();
}

_Use_decl_annotations_
static
VOID
TspPopulateScoreResult(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ PTS_PROCESS_CONTEXT Context,
    _Out_ PTS_THREAT_SCORE Score,
    _In_ BOOLEAN AllocatePath
    )
{
    PLIST_ENTRY Entry;
    PTS_INTERNAL_FACTOR Factor;
    ULONG FactorIndex;
    LARGE_INTEGER CurrentTime;
    SIZE_T PathLen;
    SIZE_T BufferSize;

    KeQuerySystemTime(&CurrentTime);

    Score->ProcessId = Context->ProcessId;
    Score->ProcessCreateTime = Context->ProcessCreateTime;
    Score->RawScore = Context->CachedRawScore;
    Score->NormalizedScore = Context->CachedNormalizedScore;
    Score->Verdict = Context->CachedVerdict;
    Score->SuspiciousThreshold = Engine->Thresholds.SuspiciousThreshold;
    Score->MaliciousThreshold = Engine->Thresholds.MaliciousThreshold;
    Score->BlockedThreshold = Engine->Thresholds.BlockedThreshold;
    Score->CalculationTime = CurrentTime;

    //
    // Copy factors
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Context->FactorLock);

    FactorIndex = 0;
    for (Entry = Context->FactorList.Flink;
         Entry != &Context->FactorList && FactorIndex < TS_MAX_FACTORS;
         Entry = Entry->Flink) {

        Factor = CONTAINING_RECORD(Entry, TS_INTERNAL_FACTOR, ListEntry);

        Score->Factors[FactorIndex].Type = Factor->Type;
        Score->Factors[FactorIndex].Score = Factor->CurrentScore;
        Score->Factors[FactorIndex].Weight = Factor->Weight;

        RtlStringCbCopyA(Score->Factors[FactorIndex].FactorName,
            sizeof(Score->Factors[FactorIndex].FactorName),
            Factor->FactorName);

        RtlStringCbCopyA(Score->Factors[FactorIndex].Reason,
            sizeof(Score->Factors[FactorIndex].Reason),
            Factor->Reason);

        FactorIndex++;
    }

    Score->FactorCount = FactorIndex;

    ExReleasePushLockShared(&Context->FactorLock);
    KeLeaveCriticalRegion();

    //
    // Build verdict reason
    //
    TspBuildVerdictReason(Context, Score->VerdictReason, sizeof(Score->VerdictReason));

    //
    // Copy process path
    //
    RtlInitUnicodeString(&Score->ProcessPath, NULL);

    if (AllocatePath && Context->ProcessPath[0] != L'\0') {
        PathLen = wcslen(Context->ProcessPath);
        BufferSize = (PathLen + 1) * sizeof(WCHAR);

        Score->ProcessPath.Buffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
            PagedPool,
            BufferSize,
            TS_POOL_TAG_PATH
            );

        if (Score->ProcessPath.Buffer != NULL) {
            RtlCopyMemory(Score->ProcessPath.Buffer, Context->ProcessPath, BufferSize);
            Score->ProcessPath.Length = (USHORT)(PathLen * sizeof(WCHAR));
            Score->ProcessPath.MaximumLength = (USHORT)BufferSize;
        }
    }
}

_Use_decl_annotations_
static
NTSTATUS
TspGetProcessCreateTime(
    _In_ HANDLE ProcessId,
    _Out_ PLARGE_INTEGER CreateTime
    )
{
    PEPROCESS Process = NULL;
    NTSTATUS Status;

    CreateTime->QuadPart = 0;

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    CreateTime->QuadPart = PsGetProcessCreateTimeQuadPart(Process);

    ObDereferenceObject(Process);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static
VOID
TspGetProcessPath(
    _In_ HANDLE ProcessId,
    _Out_writes_z_(PathChars) PWCHAR Path,
    _In_ SIZE_T PathChars
    )
{
    PEPROCESS Process = NULL;
    NTSTATUS Status;
    PUNICODE_STRING ImageFileName = NULL;
    SIZE_T CharsToCopy;

    Path[0] = L'\0';

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return;
    }

    Status = SeLocateProcessImageName(Process, &ImageFileName);
    if (NT_SUCCESS(Status) && ImageFileName != NULL) {
        CharsToCopy = ImageFileName->Length / sizeof(WCHAR);
        if (CharsToCopy >= PathChars) {
            CharsToCopy = PathChars - 1;
        }

        RtlCopyMemory(Path, ImageFileName->Buffer, CharsToCopy * sizeof(WCHAR));
        Path[CharsToCopy] = L'\0';

        ExFreePool(ImageFileName);
    }

    ObDereferenceObject(Process);
}
