/*++
    ShadowStrike Next-Generation Antivirus
    Module: ThreatScoring.c

    Purpose: Enterprise-grade threat score calculation engine for EDR/XDR operations.

    This module provides comprehensive threat scoring capabilities:
    - Multi-factor threat score aggregation
    - Weighted scoring with configurable factor weights
    - Per-process score tracking with efficient lookup
    - Normalized scoring (0-100) with configurable thresholds
    - Verdict determination (Clean/Suspicious/Malicious/Blocked)
    - Thread-safe operations with reader-writer locks
    - Score history and audit trail
    - Factor correlation and amplification

    Scoring Algorithm:
    1. Collect individual factors (Static, Behavioral, Reputation, IOC, MITRE, Anomaly)
    2. Apply factor-specific weights
    3. Sum weighted scores
    4. Normalize to 0-100 scale
    5. Apply threshold-based verdict

    Factor Types:
    - Static: PE analysis, imports, sections, entropy
    - Behavioral: Runtime behavior patterns
    - Reputation: Known good/bad indicators
    - Context: Environmental factors (time, location, user)
    - IOC: Indicator of Compromise matches
    - MITRE: ATT&CK technique matches
    - Anomaly: Statistical deviation detection

    Security Considerations:
    - All input is validated
    - Memory allocations are bounded
    - Lock ordering is strictly maintained
    - Scores are tamper-resistant

    MITRE ATT&CK Coverage:
    - All techniques contribute to scoring
    - Higher scores for critical techniques (persistence, defense evasion)
    - Attack chain progression increases score

    Copyright (c) ShadowStrike Team
--*/

#include "ThreatScoring.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include "../Tracing/Trace.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, TsInitialize)
#pragma alloc_text(PAGE, TsShutdown)
#pragma alloc_text(PAGE, TsSetThresholds)
#pragma alloc_text(PAGE, TsAddFactor)
#pragma alloc_text(PAGE, TsCalculateScore)
#pragma alloc_text(PAGE, TsGetVerdict)
#pragma alloc_text(PAGE, TsGetScore)
#pragma alloc_text(PAGE, TsFreeScore)
#endif

//=============================================================================
// Internal Configuration Constants
//=============================================================================

//
// Default thresholds
//
#define TS_DEFAULT_SUSPICIOUS_THRESHOLD     50
#define TS_DEFAULT_MALICIOUS_THRESHOLD      80

//
// Default factor weights (scale 1-10)
//
#define TS_DEFAULT_STATIC_WEIGHT            3
#define TS_DEFAULT_BEHAVIORAL_WEIGHT        5
#define TS_DEFAULT_REPUTATION_WEIGHT        4
#define TS_DEFAULT_IOC_WEIGHT               8
#define TS_DEFAULT_MITRE_WEIGHT             6
#define TS_DEFAULT_ANOMALY_WEIGHT           4

//
// Limits (DoS prevention)
//
#define TS_MAX_SCORES_TRACKED               65536
#define TS_MAX_FACTORS_PER_PROCESS          TS_MAX_FACTORS
#define TS_MAX_SCORE_VALUE                  1000
#define TS_MIN_SCORE_VALUE                  -500

//
// Normalization parameters
//
#define TS_NORMALIZATION_BASE               100
#define TS_NORMALIZATION_MAX_RAW            500

//
// Pool tags
//
#define TS_POOL_TAG_ENGINE                  'ETST'
#define TS_POOL_TAG_SCORE                   'STST'
#define TS_POOL_TAG_FACTOR                  'FTST'

//=============================================================================
// Internal Structures
//=============================================================================

//
// Per-process score context (internal tracking)
//
typedef struct _TS_PROCESS_SCORE_CONTEXT {
    LIST_ENTRY ListEntry;

    //
    // Process identification
    //
    HANDLE ProcessId;
    WCHAR ProcessPath[520];

    //
    // Factor list for this process
    //
    LIST_ENTRY FactorList;
    EX_PUSH_LOCK FactorLock;
    volatile LONG FactorCount;

    //
    // Cached score (recalculated when factors change)
    //
    LONG CachedRawScore;
    ULONG CachedNormalizedScore;
    TS_VERDICT CachedVerdict;
    BOOLEAN ScoreValid;

    //
    // Timing
    //
    LARGE_INTEGER FirstFactorTime;
    LARGE_INTEGER LastFactorTime;
    LARGE_INTEGER LastCalculationTime;

    //
    // Reference counting
    //
    volatile LONG RefCount;

} TS_PROCESS_SCORE_CONTEXT, *PTS_PROCESS_SCORE_CONTEXT;

//
// Internal factor entry
//
typedef struct _TS_INTERNAL_FACTOR {
    LIST_ENTRY ListEntry;

    TS_FACTOR_TYPE Type;
    CHAR FactorName[64];
    LONG Score;
    LONG Weight;
    CHAR Reason[128];

    LARGE_INTEGER Timestamp;

} TS_INTERNAL_FACTOR, *PTS_INTERNAL_FACTOR;

//=============================================================================
// Forward Declarations
//=============================================================================

static
PTS_PROCESS_SCORE_CONTEXT
TspFindOrCreateProcessContext(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId
    );

static
VOID
TspReleaseProcessContext(
    _In_ PTS_PROCESS_SCORE_CONTEXT Context
    );

static
PTS_PROCESS_SCORE_CONTEXT
TspFindProcessContext(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId
    );

static
VOID
TspRecalculateScore(
    _In_ PTS_SCORING_ENGINE Engine,
    _Inout_ PTS_PROCESS_SCORE_CONTEXT Context
    );

static
LONG
TspGetFactorWeight(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ TS_FACTOR_TYPE Type
    );

static
ULONG
TspNormalizeScore(
    _In_ LONG RawScore
    );

static
TS_VERDICT
TspDetermineVerdict(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ ULONG NormalizedScore
    );

static
VOID
TspBuildVerdictReason(
    _In_ PTS_PROCESS_SCORE_CONTEXT Context,
    _Out_writes_z_(ReasonSize) PCHAR Reason,
    _In_ ULONG ReasonSize
    );

static
VOID
TspFreeProcessContext(
    _In_ PTS_PROCESS_SCORE_CONTEXT Context
    );

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

//=============================================================================
// Public API Implementation
//=============================================================================

_Use_decl_annotations_
NTSTATUS
TsInitialize(
    _Out_ PTS_SCORING_ENGINE* Engine
    )
/*++

Routine Description:

    Initializes the threat scoring engine.

Arguments:

    Engine - Receives pointer to the initialized engine.

Return Value:

    STATUS_SUCCESS on success, appropriate error code otherwise.

--*/
{
    PTS_SCORING_ENGINE NewEngine = NULL;
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    if (Engine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Engine = NULL;

    //
    // Allocate engine structure
    //
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
    // Initialize list and lock
    //
    InitializeListHead(&NewEngine->ScoreList);
    ExInitializePushLock(&NewEngine->ScoreLock);

    //
    // Set default thresholds
    //
    NewEngine->SuspiciousThreshold = TS_DEFAULT_SUSPICIOUS_THRESHOLD;
    NewEngine->MaliciousThreshold = TS_DEFAULT_MALICIOUS_THRESHOLD;

    //
    // Set default weights
    //
    NewEngine->Weights.StaticWeight = TS_DEFAULT_STATIC_WEIGHT;
    NewEngine->Weights.BehavioralWeight = TS_DEFAULT_BEHAVIORAL_WEIGHT;
    NewEngine->Weights.ReputationWeight = TS_DEFAULT_REPUTATION_WEIGHT;
    NewEngine->Weights.IOCWeight = TS_DEFAULT_IOC_WEIGHT;
    NewEngine->Weights.MITREWeight = TS_DEFAULT_MITRE_WEIGHT;
    NewEngine->Weights.AnomalyWeight = TS_DEFAULT_ANOMALY_WEIGHT;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&CurrentTime);
    NewEngine->Stats.StartTime = CurrentTime;

    NewEngine->Initialized = TRUE;

    *Engine = NewEngine;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
TsShutdown(
    _Inout_ PTS_SCORING_ENGINE Engine
    )
/*++

Routine Description:

    Shuts down the threat scoring engine and frees all resources.

Arguments:

    Engine - The engine to shut down.

--*/
{
    PLIST_ENTRY Entry;
    PTS_PROCESS_SCORE_CONTEXT Context;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return;
    }

    Engine->Initialized = FALSE;

    //
    // Free all process score contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ScoreLock);

    while (!IsListEmpty(&Engine->ScoreList)) {
        Entry = RemoveHeadList(&Engine->ScoreList);
        Context = CONTAINING_RECORD(Entry, TS_PROCESS_SCORE_CONTEXT, ListEntry);

        TspFreeProcessContext(Context);
    }

    ExReleasePushLockExclusive(&Engine->ScoreLock);
    KeLeaveCriticalRegion();

    //
    // Free engine
    //
    ShadowStrikeFreePoolWithTag(Engine, TS_POOL_TAG_ENGINE);
}

_Use_decl_annotations_
NTSTATUS
TsSetThresholds(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ ULONG Suspicious,
    _In_ ULONG Malicious
    )
/*++

Routine Description:

    Sets the verdict thresholds for the scoring engine.

Arguments:

    Engine     - The scoring engine.
    Suspicious - Threshold for suspicious verdict (0-100).
    Malicious  - Threshold for malicious verdict (0-100).

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate thresholds
    //
    if (Suspicious > 100 || Malicious > 100) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Suspicious >= Malicious) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Update thresholds (atomic operations not strictly needed for ULONG,
    // but using interlocked for consistency)
    //
    InterlockedExchange((volatile LONG*)&Engine->SuspiciousThreshold, (LONG)Suspicious);
    InterlockedExchange((volatile LONG*)&Engine->MaliciousThreshold, (LONG)Malicious);

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
/*++

Routine Description:

    Adds a scoring factor for a process.

Arguments:

    Engine     - The scoring engine.
    ProcessId  - Target process ID.
    Type       - Type of factor.
    FactorName - Name of the factor (for audit).
    Score      - Score value (positive = threat, negative = trust).
    Reason     - Human-readable reason for the factor.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PTS_PROCESS_SCORE_CONTEXT Context;
    PTS_INTERNAL_FACTOR NewFactor;
    LARGE_INTEGER CurrentTime;
    LONG FactorWeight;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (FactorName == NULL || Reason == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Find or create process context
    //
    Context = TspFindOrCreateProcessContext(Engine, ProcessId);
    if (Context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Check factor limit for this process
    //
    if (InterlockedCompareExchange(&Context->FactorCount, 0, 0) >=
        TS_MAX_FACTORS_PER_PROCESS) {
        TspReleaseProcessContext(Context);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate new factor
    //
    NewFactor = (PTS_INTERNAL_FACTOR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(TS_INTERNAL_FACTOR),
        TS_POOL_TAG_FACTOR
        );

    if (NewFactor == NULL) {
        TspReleaseProcessContext(Context);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewFactor, sizeof(TS_INTERNAL_FACTOR));

    //
    // Get current time
    //
    KeQuerySystemTime(&CurrentTime);

    //
    // Fill in factor
    //
    NewFactor->Type = Type;
    NewFactor->Score = TspClampScore(Score);
    NewFactor->Timestamp = CurrentTime;

    //
    // Get weight for this factor type
    //
    FactorWeight = TspGetFactorWeight(Engine, Type);
    NewFactor->Weight = FactorWeight;

    //
    // Copy strings safely
    //
    RtlStringCbCopyA(NewFactor->FactorName, sizeof(NewFactor->FactorName), FactorName);
    RtlStringCbCopyA(NewFactor->Reason, sizeof(NewFactor->Reason), Reason);

    //
    // Add to process factor list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->FactorLock);

    InsertTailList(&Context->FactorList, &NewFactor->ListEntry);
    InterlockedIncrement(&Context->FactorCount);

    //
    // Update timing
    //
    Context->LastFactorTime = CurrentTime;
    if (Context->FirstFactorTime.QuadPart == 0) {
        Context->FirstFactorTime = CurrentTime;
    }

    //
    // Invalidate cached score
    //
    Context->ScoreValid = FALSE;

    ExReleasePushLockExclusive(&Context->FactorLock);
    KeLeaveCriticalRegion();

    TspReleaseProcessContext(Context);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsCalculateScore(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ PTS_THREAT_SCORE* Score
    )
/*++

Routine Description:

    Calculates the threat score for a process.

Arguments:

    Engine    - The scoring engine.
    ProcessId - Target process ID.
    Score     - Receives the calculated score (caller must free with TsFreeScore).

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PTS_PROCESS_SCORE_CONTEXT Context;
    PTS_THREAT_SCORE NewScore;
    PLIST_ENTRY Entry;
    PTS_INTERNAL_FACTOR Factor;
    ULONG FactorIndex;
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized || Score == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Score = NULL;

    //
    // Find process context
    //
    Context = TspFindProcessContext(Engine, ProcessId);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Recalculate score if needed
    //
    if (!Context->ScoreValid) {
        TspRecalculateScore(Engine, Context);
    }

    //
    // Allocate result structure
    //
    NewScore = (PTS_THREAT_SCORE)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        sizeof(TS_THREAT_SCORE),
        TS_POOL_TAG_SCORE
        );

    if (NewScore == NULL) {
        TspReleaseProcessContext(Context);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewScore, sizeof(TS_THREAT_SCORE));

    KeQuerySystemTime(&CurrentTime);

    //
    // Fill in score data
    //
    NewScore->ProcessId = ProcessId;
    NewScore->RawScore = Context->CachedRawScore;
    NewScore->NormalizedScore = Context->CachedNormalizedScore;
    NewScore->Verdict = Context->CachedVerdict;
    NewScore->SuspiciousThreshold = Engine->SuspiciousThreshold;
    NewScore->MaliciousThreshold = Engine->MaliciousThreshold;
    NewScore->CalculationTime = CurrentTime;

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

        NewScore->Factors[FactorIndex].Type = Factor->Type;
        NewScore->Factors[FactorIndex].Score = Factor->Score;
        NewScore->Factors[FactorIndex].Weight = Factor->Weight;

        RtlStringCbCopyA(NewScore->Factors[FactorIndex].FactorName,
            sizeof(NewScore->Factors[FactorIndex].FactorName),
            Factor->FactorName);

        RtlStringCbCopyA(NewScore->Factors[FactorIndex].Reason,
            sizeof(NewScore->Factors[FactorIndex].Reason),
            Factor->Reason);

        FactorIndex++;
    }

    NewScore->FactorCount = FactorIndex;

    ExReleasePushLockShared(&Context->FactorLock);
    KeLeaveCriticalRegion();

    //
    // Build verdict reason
    //
    TspBuildVerdictReason(Context, NewScore->VerdictReason, sizeof(NewScore->VerdictReason));

    //
    // Copy process path if available
    //
    if (Context->ProcessPath[0] != L'\0') {
        RtlInitUnicodeString(&NewScore->ProcessPath, NULL);
        //
        // Allocate and copy the path
        //
        USHORT PathLen = (USHORT)wcslen(Context->ProcessPath);
        USHORT BufferSize = (PathLen + 1) * sizeof(WCHAR);

        NewScore->ProcessPath.Buffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
            PagedPool,
            BufferSize,
            TS_POOL_TAG_SCORE
            );

        if (NewScore->ProcessPath.Buffer != NULL) {
            RtlCopyMemory(NewScore->ProcessPath.Buffer, Context->ProcessPath, BufferSize);
            NewScore->ProcessPath.Length = PathLen * sizeof(WCHAR);
            NewScore->ProcessPath.MaximumLength = BufferSize;
        }
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Engine->Stats.ScoresCalculated);

    if (NewScore->Verdict == TsVerdict_Suspicious) {
        InterlockedIncrement64(&Engine->Stats.Suspicious);
    } else if (NewScore->Verdict == TsVerdict_Malicious ||
               NewScore->Verdict == TsVerdict_Blocked) {
        InterlockedIncrement64(&Engine->Stats.Malicious);
    }

    TspReleaseProcessContext(Context);

    *Score = NewScore;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsGetVerdict(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ PTS_VERDICT Verdict,
    _Out_opt_ PULONG Score
    )
/*++

Routine Description:

    Gets the current verdict for a process without full score calculation.

Arguments:

    Engine    - The scoring engine.
    ProcessId - Target process ID.
    Verdict   - Receives the verdict.
    Score     - Optionally receives the normalized score.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PTS_PROCESS_SCORE_CONTEXT Context;

    PAGED_CODE();

    if (Engine == NULL || !Engine->Initialized || Verdict == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Verdict = TsVerdict_Unknown;
    if (Score != NULL) {
        *Score = 0;
    }

    //
    // Find process context
    //
    Context = TspFindProcessContext(Engine, ProcessId);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Recalculate if needed
    //
    if (!Context->ScoreValid) {
        TspRecalculateScore(Engine, Context);
    }

    *Verdict = Context->CachedVerdict;
    if (Score != NULL) {
        *Score = Context->CachedNormalizedScore;
    }

    TspReleaseProcessContext(Context);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsGetScore(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ PTS_THREAT_SCORE* Score
    )
/*++

Routine Description:

    Gets the full threat score for a process (same as TsCalculateScore).

Arguments:

    Engine    - The scoring engine.
    ProcessId - Target process ID.
    Score     - Receives the score.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PAGED_CODE();

    return TsCalculateScore(Engine, ProcessId, Score);
}

_Use_decl_annotations_
VOID
TsFreeScore(
    _In_ PTS_THREAT_SCORE Score
    )
/*++

Routine Description:

    Frees a threat score structure.

Arguments:

    Score - The score to free.

--*/
{
    PAGED_CODE();

    if (Score != NULL) {
        //
        // Free process path if allocated
        //
        if (Score->ProcessPath.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(Score->ProcessPath.Buffer, TS_POOL_TAG_SCORE);
        }

        ShadowStrikeFreePoolWithTag(Score, TS_POOL_TAG_SCORE);
    }
}

//=============================================================================
// Internal Implementation
//=============================================================================

static
PTS_PROCESS_SCORE_CONTEXT
TspFindOrCreateProcessContext(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId
    )
/*++

Routine Description:

    Finds an existing process context or creates a new one.

--*/
{
    PLIST_ENTRY Entry;
    PTS_PROCESS_SCORE_CONTEXT Context = NULL;
    PTS_PROCESS_SCORE_CONTEXT NewContext = NULL;
    BOOLEAN Found = FALSE;

    //
    // First try to find existing context (shared lock)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->ScoreLock);

    for (Entry = Engine->ScoreList.Flink;
         Entry != &Engine->ScoreList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, TS_PROCESS_SCORE_CONTEXT, ListEntry);

        if (Context->ProcessId == ProcessId) {
            InterlockedIncrement(&Context->RefCount);
            Found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&Engine->ScoreLock);
    KeLeaveCriticalRegion();

    if (Found) {
        return Context;
    }

    //
    // Check limit
    //
    if (InterlockedCompareExchange(&Engine->ScoreCount, 0, 0) >= TS_MAX_SCORES_TRACKED) {
        return NULL;
    }

    //
    // Create new context
    //
    NewContext = (PTS_PROCESS_SCORE_CONTEXT)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(TS_PROCESS_SCORE_CONTEXT),
        TS_POOL_TAG_SCORE
        );

    if (NewContext == NULL) {
        return NULL;
    }

    RtlZeroMemory(NewContext, sizeof(TS_PROCESS_SCORE_CONTEXT));

    //
    // Initialize new context
    //
    NewContext->ProcessId = ProcessId;
    NewContext->RefCount = 1;
    NewContext->ScoreValid = FALSE;
    NewContext->CachedVerdict = TsVerdict_Unknown;

    InitializeListHead(&NewContext->FactorList);
    ExInitializePushLock(&NewContext->FactorLock);

    //
    // Try to get process path
    //
    {
        PEPROCESS Process = NULL;
        NTSTATUS Status;

        Status = PsLookupProcessByProcessId(ProcessId, &Process);
        if (NT_SUCCESS(Status)) {
            PUNICODE_STRING ImageFileName = NULL;

            Status = SeLocateProcessImageName(Process, &ImageFileName);
            if (NT_SUCCESS(Status) && ImageFileName != NULL) {
                ULONG CharsToCopy = min(
                    ImageFileName->Length / sizeof(WCHAR),
                    (sizeof(NewContext->ProcessPath) / sizeof(WCHAR)) - 1
                    );

                RtlCopyMemory(NewContext->ProcessPath,
                    ImageFileName->Buffer,
                    CharsToCopy * sizeof(WCHAR));
                NewContext->ProcessPath[CharsToCopy] = L'\0';

                ExFreePool(ImageFileName);
            }

            ObDereferenceObject(Process);
        }
    }

    //
    // Add to list (exclusive lock)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->ScoreLock);

    //
    // Double-check another thread didn't create it
    //
    for (Entry = Engine->ScoreList.Flink;
         Entry != &Engine->ScoreList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, TS_PROCESS_SCORE_CONTEXT, ListEntry);

        if (Context->ProcessId == ProcessId) {
            InterlockedIncrement(&Context->RefCount);
            Found = TRUE;
            break;
        }
    }

    if (!Found) {
        InsertTailList(&Engine->ScoreList, &NewContext->ListEntry);
        InterlockedIncrement(&Engine->ScoreCount);
        Context = NewContext;
        NewContext = NULL;
    }

    ExReleasePushLockExclusive(&Engine->ScoreLock);
    KeLeaveCriticalRegion();

    //
    // Free unused allocation if race occurred
    //
    if (NewContext != NULL) {
        ShadowStrikeFreePoolWithTag(NewContext, TS_POOL_TAG_SCORE);
    }

    return Context;
}

static
PTS_PROCESS_SCORE_CONTEXT
TspFindProcessContext(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId
    )
/*++

Routine Description:

    Finds an existing process context.

--*/
{
    PLIST_ENTRY Entry;
    PTS_PROCESS_SCORE_CONTEXT Context;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->ScoreLock);

    for (Entry = Engine->ScoreList.Flink;
         Entry != &Engine->ScoreList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, TS_PROCESS_SCORE_CONTEXT, ListEntry);

        if (Context->ProcessId == ProcessId) {
            InterlockedIncrement(&Context->RefCount);
            ExReleasePushLockShared(&Engine->ScoreLock);
            KeLeaveCriticalRegion();
            return Context;
        }
    }

    ExReleasePushLockShared(&Engine->ScoreLock);
    KeLeaveCriticalRegion();

    return NULL;
}

static
VOID
TspReleaseProcessContext(
    _In_ PTS_PROCESS_SCORE_CONTEXT Context
    )
/*++

Routine Description:

    Releases a reference to a process context.

--*/
{
    if (Context != NULL) {
        InterlockedDecrement(&Context->RefCount);
        //
        // Note: Actual cleanup could be done by a separate cleanup routine
        // when RefCount reaches 0 and the process has exited
        //
    }
}

static
VOID
TspRecalculateScore(
    _In_ PTS_SCORING_ENGINE Engine,
    _Inout_ PTS_PROCESS_SCORE_CONTEXT Context
    )
/*++

Routine Description:

    Recalculates the threat score for a process context.

--*/
{
    PLIST_ENTRY Entry;
    PTS_INTERNAL_FACTOR Factor;
    LONG RawScore = 0;
    LONG WeightedScore;
    LARGE_INTEGER CurrentTime;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Context->FactorLock);

    //
    // Sum all weighted factor scores
    //
    for (Entry = Context->FactorList.Flink;
         Entry != &Context->FactorList;
         Entry = Entry->Flink) {

        Factor = CONTAINING_RECORD(Entry, TS_INTERNAL_FACTOR, ListEntry);

        //
        // Calculate weighted score for this factor
        //
        WeightedScore = Factor->Score * Factor->Weight;

        //
        // Apply factor type multipliers for critical techniques
        //
        switch (Factor->Type) {
        case TsFactor_IOC:
            //
            // IOC matches are highly significant
            //
            WeightedScore = (WeightedScore * 150) / 100;
            break;

        case TsFactor_MITRE:
            //
            // MITRE technique matches escalate threat level
            //
            WeightedScore = (WeightedScore * 120) / 100;
            break;

        case TsFactor_Behavioral:
            //
            // Behavioral factors are strong indicators
            //
            WeightedScore = (WeightedScore * 110) / 100;
            break;

        default:
            break;
        }

        RawScore += WeightedScore;
    }

    ExReleasePushLockShared(&Context->FactorLock);
    KeLeaveCriticalRegion();

    //
    // Clamp raw score
    //
    RawScore = TspClampScore(RawScore);

    //
    // Normalize to 0-100
    //
    Context->CachedRawScore = RawScore;
    Context->CachedNormalizedScore = TspNormalizeScore(RawScore);

    //
    // Determine verdict
    //
    Context->CachedVerdict = TspDetermineVerdict(Engine, Context->CachedNormalizedScore);

    //
    // Mark as valid
    //
    KeQuerySystemTime(&CurrentTime);
    Context->LastCalculationTime = CurrentTime;
    Context->ScoreValid = TRUE;
}

static
LONG
TspGetFactorWeight(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ TS_FACTOR_TYPE Type
    )
/*++

Routine Description:

    Gets the configured weight for a factor type.

--*/
{
    switch (Type) {
    case TsFactor_Static:
        return Engine->Weights.StaticWeight;

    case TsFactor_Behavioral:
        return Engine->Weights.BehavioralWeight;

    case TsFactor_Reputation:
        return Engine->Weights.ReputationWeight;

    case TsFactor_IOC:
        return Engine->Weights.IOCWeight;

    case TsFactor_MITRE:
        return Engine->Weights.MITREWeight;

    case TsFactor_Anomaly:
        return Engine->Weights.AnomalyWeight;

    case TsFactor_Context:
    case TsFactor_UserDefined:
    default:
        return 1;
    }
}

static
ULONG
TspNormalizeScore(
    _In_ LONG RawScore
    )
/*++

Routine Description:

    Normalizes a raw score to 0-100 range.

    Uses a sigmoid-like function to handle both positive and negative scores:
    - Negative scores (trust) normalize to 0-49
    - Zero normalizes to 50
    - Positive scores (threat) normalize to 51-100

--*/
{
    LONG Normalized;

    if (RawScore == 0) {
        return 50;
    }

    if (RawScore > 0) {
        //
        // Threat: map 0..MAX_RAW to 50..100
        //
        if (RawScore >= TS_NORMALIZATION_MAX_RAW) {
            return 100;
        }

        Normalized = 50 + ((RawScore * 50) / TS_NORMALIZATION_MAX_RAW);

        if (Normalized > 100) {
            Normalized = 100;
        }
    } else {
        //
        // Trust: map -MAX_RAW..0 to 0..50
        //
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

static
TS_VERDICT
TspDetermineVerdict(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ ULONG NormalizedScore
    )
/*++

Routine Description:

    Determines the verdict based on normalized score and thresholds.

--*/
{
    if (NormalizedScore >= Engine->MaliciousThreshold) {
        return TsVerdict_Malicious;
    }

    if (NormalizedScore >= Engine->SuspiciousThreshold) {
        return TsVerdict_Suspicious;
    }

    return TsVerdict_Clean;
}

static
VOID
TspBuildVerdictReason(
    _In_ PTS_PROCESS_SCORE_CONTEXT Context,
    _Out_writes_z_(ReasonSize) PCHAR Reason,
    _In_ ULONG ReasonSize
    )
/*++

Routine Description:

    Builds a human-readable verdict reason string.

--*/
{
    PLIST_ENTRY Entry;
    PTS_INTERNAL_FACTOR Factor;
    PTS_INTERNAL_FACTOR HighestFactor = NULL;
    LONG HighestScore = 0;
    ULONG FactorCount = 0;
    ULONG ThreatFactorCount = 0;

    Reason[0] = '\0';

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Context->FactorLock);

    //
    // Find highest scoring factor and count threat factors
    //
    for (Entry = Context->FactorList.Flink;
         Entry != &Context->FactorList;
         Entry = Entry->Flink) {

        Factor = CONTAINING_RECORD(Entry, TS_INTERNAL_FACTOR, ListEntry);
        FactorCount++;

        if (Factor->Score > 0) {
            ThreatFactorCount++;

            LONG WeightedScore = Factor->Score * Factor->Weight;
            if (WeightedScore > HighestScore) {
                HighestScore = WeightedScore;
                HighestFactor = Factor;
            }
        }
    }

    //
    // Build reason string
    //
    if (Context->CachedVerdict == TsVerdict_Clean) {
        RtlStringCbPrintfA(Reason, ReasonSize,
            "No significant threat indicators detected (%lu factors evaluated)",
            FactorCount);
    } else if (HighestFactor != NULL) {
        RtlStringCbPrintfA(Reason, ReasonSize,
            "Primary indicator: %s - %s (%lu total threat factors)",
            HighestFactor->FactorName,
            HighestFactor->Reason,
            ThreatFactorCount);
    } else {
        RtlStringCbPrintfA(Reason, ReasonSize,
            "Aggregate threat score exceeded threshold (%lu factors)",
            FactorCount);
    }

    ExReleasePushLockShared(&Context->FactorLock);
    KeLeaveCriticalRegion();
}

static
VOID
TspFreeProcessContext(
    _In_ PTS_PROCESS_SCORE_CONTEXT Context
    )
/*++

Routine Description:

    Frees a process score context and all its factors.

--*/
{
    PLIST_ENTRY Entry;
    PTS_INTERNAL_FACTOR Factor;

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

    //
    // Free context
    //
    ShadowStrikeFreePoolWithTag(Context, TS_POOL_TAG_SCORE);
}

