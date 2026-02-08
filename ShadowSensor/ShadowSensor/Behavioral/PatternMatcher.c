/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE BEHAVIORAL PATTERN MATCHER
 * ============================================================================
 *
 * @file PatternMatcher.c
 * @brief Enterprise-grade behavioral pattern matching engine for attack detection.
 *
 * This module provides comprehensive behavioral pattern matching:
 * - Event sequence matching with temporal constraints
 * - Partial pattern matching with configurable thresholds
 * - Per-process match state tracking
 * - MITRE ATT&CK technique correlation
 * - Wildcard pattern support with length limits
 * - Efficient pattern indexing by event type
 * - Real-time match callback notifications
 * - Thread-safe concurrent event processing
 *
 * SECURITY CONSIDERATIONS:
 * - All timing uses monotonic counters (KeQueryPerformanceCounter)
 * - String operations are length-bounded
 * - Reference counting prevents use-after-free
 * - Push locks used for PASSIVE_LEVEL safety
 * - Atomic operations for statistics and state counts
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition - Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "PatternMatcher.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, PmInitialize)
#pragma alloc_text(PAGE, PmShutdown)
#pragma alloc_text(PAGE, PmLoadPattern)
#pragma alloc_text(PAGE, PmUnloadPattern)
#pragma alloc_text(PAGE, PmRegisterCallback)
#pragma alloc_text(PAGE, PmSubmitEvent)
#pragma alloc_text(PAGE, PmGetActiveStates)
#pragma alloc_text(PAGE, PmReleaseState)
#pragma alloc_text(PAGE, PmCleanupProcessStates)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define PM_MAX_PATTERNS                     1024
#define PM_MAX_ACTIVE_STATES                50000
#define PM_MAX_STATES_PER_PROCESS           100
#define PM_STATE_TIMEOUT_MS                 300000      // 5 minutes
#define PM_CLEANUP_INTERVAL_MS              60000       // 1 minute
#define PM_LOOKASIDE_DEPTH                  512
#define PM_MAX_WILDCARD_ITERATIONS          10000       // Prevent ReDoS
#define PM_MAX_PATH_CONVERSION_LENGTH       1024

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Pattern index entry for fast lookup by event type.
 */
typedef struct _PM_PATTERN_INDEX_ENTRY {
    LIST_ENTRY ListEntry;
    PPM_PATTERN Pattern;
    ULONG EventIndex;               // Which event in pattern triggers this
} PM_PATTERN_INDEX_ENTRY, *PPM_PATTERN_INDEX_ENTRY;

/**
 * @brief Extended match state (internal).
 */
typedef struct _PM_MATCH_STATE_INTERNAL {
    //
    // Public structure (must be first for CONTAINING_RECORD)
    //
    PM_MATCH_STATE Public;

    //
    // Per-event tracking
    //
    LARGE_INTEGER EventTimes[PM_MAX_EVENTS_PER_PATTERN];
    BOOLEAN EventMatched[PM_MAX_EVENTS_PER_PATTERN];
    ULONG EventMatchOrder[PM_MAX_EVENTS_PER_PATTERN];
    ULONG NextMatchOrder;

    //
    // Per-process hash linkage
    //
    LIST_ENTRY ProcessHashEntry;
    ULONG ProcessHashBucket;

    //
    // Reference counting (interlocked operations only)
    //
    volatile LONG RefCount;

    //
    // State flags
    //
    volatile BOOLEAN IsStale;
    volatile BOOLEAN NotificationSent;
    volatile BOOLEAN IsRemoved;         // Marked when removed from lists

} PM_MATCH_STATE_INTERNAL, *PPM_MATCH_STATE_INTERNAL;

/**
 * @brief Extended matcher state (internal).
 */
typedef struct _PM_MATCHER_INTERNAL {
    //
    // Public structure (must be first for CONTAINING_RECORD)
    //
    PM_MATCHER Public;

    //
    // Pattern indexing by event type for O(1) lookup
    //
    struct {
        LIST_ENTRY Patterns;
        ULONG Count;
    } PatternIndex[PmEvent_MaxType];
    EX_PUSH_LOCK IndexLock;

    //
    // Per-process state hash table (256 buckets)
    //
    struct {
        LIST_ENTRY Buckets[256];
        EX_PUSH_LOCK Lock;
    } ProcessStateHash;

    //
    // Pattern ID generator
    //
    volatile LONG NextPatternId;

    //
    // Lookaside lists for efficient allocation
    //
    NPAGED_LOOKASIDE_LIST PatternLookaside;
    NPAGED_LOOKASIDE_LIST StateLookaside;
    NPAGED_LOOKASIDE_LIST IndexEntryLookaside;
    volatile BOOLEAN LookasideInitialized;

    //
    // Cleanup work item
    //
    PIO_WORKITEM CleanupWorkItem;
    volatile BOOLEAN CleanupScheduled;
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    volatile BOOLEAN CleanupTimerActive;

    //
    // Configuration
    //
    struct {
        ULONG StateTimeoutMs;
        ULONG MaxStatesPerProcess;
        BOOLEAN EnablePartialMatching;
    } Config;

} PM_MATCHER_INTERNAL, *PPM_MATCHER_INTERNAL;

/**
 * @brief Work item context for cleanup operations.
 */
typedef struct _PM_CLEANUP_CONTEXT {
    PPM_MATCHER_INTERNAL Matcher;
} PM_CLEANUP_CONTEXT, *PPM_CLEANUP_CONTEXT;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static ULONG
PmpHashProcessId(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
PmpMatchWildcardSafe(
    _In_reads_or_z_(PatternMaxLen) PCSTR Pattern,
    _In_ SIZE_T PatternMaxLen,
    _In_reads_or_z_(StringMaxLen) PCSTR String,
    _In_ SIZE_T StringMaxLen
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static PPM_MATCH_STATE_INTERNAL
PmpCreateMatchState(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_PATTERN Pattern,
    _In_ HANDLE ProcessId,
    _In_ PLARGE_INTEGER CurrentTime
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpReferenceState(
    _In_ PPM_MATCH_STATE_INTERNAL State
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpDereferenceState(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_MATCH_STATE_INTERNAL State
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
PmpCheckEventConstraint(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_EVENT_CONSTRAINT* Constraint,
    _In_ PM_EVENT_TYPE EventType,
    _In_opt_ PCUNICODE_STRING Path,
    _In_opt_ PCSTR Value,
    _In_opt_ PPM_MATCH_STATE_INTERNAL State,
    _In_ PLARGE_INTEGER CurrentTime
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpAdvanceMatchState(
    _In_ PPM_MATCH_STATE_INTERNAL State,
    _In_ ULONG EventIndex,
    _In_ PLARGE_INTEGER EventTime
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpCheckPatternComplete(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_MATCH_STATE_INTERNAL State,
    _In_ PLARGE_INTEGER CurrentTime
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpNotifyCallback(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_PATTERN Pattern,
    _In_ PPM_MATCH_STATE State
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpInsertStateIntoProcessHash(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_MATCH_STATE_INTERNAL State
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpRemoveStateFromProcessHash(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_MATCH_STATE_INTERNAL State
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpIndexPattern(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_PATTERN Pattern
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpUnindexPattern(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_PATTERN Pattern
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
PmpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

IO_WORKITEM_ROUTINE PmpCleanupWorkItemRoutine;

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpCleanupStaleStates(
    _In_ PPM_MATCHER_INTERNAL Matcher
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static LONGLONG
PmpGetElapsedMs(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PLARGE_INTEGER StartTime,
    _In_ PLARGE_INTEGER EndTime
    );

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PmInitialize(
    PPM_MATCHER* Matcher
    )
/**
 * @brief Initialize the behavioral pattern matcher.
 *
 * Allocates and initializes all data structures required for
 * pattern matching including indices, state tracking, and cleanup timer.
 *
 * @param Matcher Receives pointer to initialized matcher
 * @return STATUS_SUCCESS or error code
 */
{
    NTSTATUS status = STATUS_SUCCESS;
    PPM_MATCHER_INTERNAL matcher = NULL;
    ULONG i;
    LARGE_INTEGER dueTime;

    PAGED_CODE();

    if (Matcher == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Matcher = NULL;

    //
    // Allocate matcher structure from non-paged pool
    //
    matcher = (PPM_MATCHER_INTERNAL)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(PM_MATCHER_INTERNAL),
        PM_POOL_TAG
    );

    if (matcher == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize pattern list and lock
    //
    InitializeListHead(&matcher->Public.PatternList);
    ExInitializePushLock(&matcher->Public.PatternLock);

    //
    // Initialize state list and lock (push lock for PASSIVE_LEVEL safety)
    //
    InitializeListHead(&matcher->Public.StateList);
    ExInitializePushLock(&matcher->Public.StateLock);

    //
    // Initialize callback lock
    //
    ExInitializePushLock(&matcher->Public.CallbackLock);

    //
    // Initialize pattern index (by event type)
    //
    for (i = 0; i < PmEvent_MaxType; i++) {
        InitializeListHead(&matcher->PatternIndex[i].Patterns);
        matcher->PatternIndex[i].Count = 0;
    }
    ExInitializePushLock(&matcher->IndexLock);

    //
    // Initialize per-process state hash
    //
    for (i = 0; i < 256; i++) {
        InitializeListHead(&matcher->ProcessStateHash.Buckets[i]);
    }
    ExInitializePushLock(&matcher->ProcessStateHash.Lock);

    //
    // Get performance counter frequency for timing calculations
    //
    KeQueryPerformanceCounter(&matcher->Public.PerformanceFrequency);
    if (matcher->Public.PerformanceFrequency.QuadPart == 0) {
        //
        // Fallback: assume 10MHz if query fails (should never happen)
        //
        matcher->Public.PerformanceFrequency.QuadPart = 10000000LL;
    }

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &matcher->PatternLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PM_PATTERN),
        PM_POOL_TAG,
        PM_LOOKASIDE_DEPTH
    );

    ExInitializeNPagedLookasideList(
        &matcher->StateLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PM_MATCH_STATE_INTERNAL),
        PM_POOL_TAG_STATE,
        PM_LOOKASIDE_DEPTH
    );

    ExInitializeNPagedLookasideList(
        &matcher->IndexEntryLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PM_PATTERN_INDEX_ENTRY),
        PM_POOL_TAG_INDEX,
        PM_LOOKASIDE_DEPTH
    );

    InterlockedExchange8((CHAR*)&matcher->LookasideInitialized, TRUE);

    //
    // Set default configuration
    //
    matcher->Config.StateTimeoutMs = PM_STATE_TIMEOUT_MS;
    matcher->Config.MaxStatesPerProcess = PM_MAX_STATES_PER_PROCESS;
    matcher->Config.EnablePartialMatching = TRUE;

    //
    // Initialize statistics with monotonic start time
    //
    matcher->Public.Stats.StartTime = KeQueryPerformanceCounter(NULL);

    //
    // Initialize cleanup timer and DPC
    //
    KeInitializeTimer(&matcher->CleanupTimer);
    KeInitializeDpc(&matcher->CleanupDpc, PmpCleanupTimerDpc, matcher);

    //
    // Start cleanup timer (periodic)
    //
    dueTime.QuadPart = -((LONGLONG)PM_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &matcher->CleanupTimer,
        dueTime,
        PM_CLEANUP_INTERVAL_MS,
        &matcher->CleanupDpc
    );
    InterlockedExchange8((CHAR*)&matcher->CleanupTimerActive, TRUE);

    //
    // Mark as initialized
    //
    InterlockedExchange8((CHAR*)&matcher->Public.Initialized, TRUE);
    *Matcher = &matcher->Public;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PmShutdown(
    PPM_MATCHER Matcher
    )
/**
 * @brief Shutdown and cleanup the pattern matcher.
 *
 * Cancels cleanup timer, waits for pending operations,
 * releases all patterns and states, frees all allocated memory.
 *
 * @param Matcher Matcher instance to shutdown
 */
{
    PPM_MATCHER_INTERNAL matcher;
    PLIST_ENTRY entry;
    PPM_PATTERN pattern;
    PPM_MATCH_STATE_INTERNAL state;
    PPM_PATTERN_INDEX_ENTRY indexEntry;
    ULONG i;
    LIST_ENTRY freePatternList;
    LIST_ENTRY freeStateList;
    LIST_ENTRY freeIndexList;

    PAGED_CODE();

    if (Matcher == NULL) {
        return;
    }

    if (!InterlockedCompareExchange8((CHAR*)&Matcher->Initialized, FALSE, TRUE)) {
        return;
    }

    matcher = CONTAINING_RECORD(Matcher, PM_MATCHER_INTERNAL, Public);

    //
    // Signal shutdown to prevent new operations
    //
    InterlockedExchange8((CHAR*)&Matcher->ShuttingDown, TRUE);

    //
    // Cancel cleanup timer first
    //
    if (InterlockedExchange8((CHAR*)&matcher->CleanupTimerActive, FALSE)) {
        KeCancelTimer(&matcher->CleanupTimer);
    }

    //
    // Wait for any queued DPCs to complete
    //
    KeFlushQueuedDpcs();

    //
    // Initialize temporary lists for deferred freeing
    //
    InitializeListHead(&freePatternList);
    InitializeListHead(&freeStateList);
    InitializeListHead(&freeIndexList);

    //
    // Collect all states under lock, then free outside lock
    //
    ExAcquirePushLockExclusive(&Matcher->StateLock);

    while (!IsListEmpty(&Matcher->StateList)) {
        entry = RemoveHeadList(&Matcher->StateList);
        state = CONTAINING_RECORD(entry, PM_MATCH_STATE_INTERNAL, Public.ListEntry);
        state->IsRemoved = TRUE;
        InsertTailList(&freeStateList, entry);
    }
    Matcher->StateCount = 0;

    ExReleasePushLockExclusive(&Matcher->StateLock);

    //
    // Clear process hash table
    //
    ExAcquirePushLockExclusive(&matcher->ProcessStateHash.Lock);
    for (i = 0; i < 256; i++) {
        InitializeListHead(&matcher->ProcessStateHash.Buckets[i]);
    }
    ExReleasePushLockExclusive(&matcher->ProcessStateHash.Lock);

    //
    // Free collected states
    //
    while (!IsListEmpty(&freeStateList)) {
        entry = RemoveHeadList(&freeStateList);
        state = CONTAINING_RECORD(entry, PM_MATCH_STATE_INTERNAL, Public.ListEntry);

        if (matcher->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&matcher->StateLookaside, state);
        } else {
            ExFreePoolWithTag(state, PM_POOL_TAG_STATE);
        }
    }

    //
    // Collect all index entries under lock
    //
    ExAcquirePushLockExclusive(&matcher->IndexLock);

    for (i = 0; i < PmEvent_MaxType; i++) {
        while (!IsListEmpty(&matcher->PatternIndex[i].Patterns)) {
            entry = RemoveHeadList(&matcher->PatternIndex[i].Patterns);
            InsertTailList(&freeIndexList, entry);
        }
        matcher->PatternIndex[i].Count = 0;
    }

    ExReleasePushLockExclusive(&matcher->IndexLock);

    //
    // Free collected index entries
    //
    while (!IsListEmpty(&freeIndexList)) {
        entry = RemoveHeadList(&freeIndexList);
        indexEntry = CONTAINING_RECORD(entry, PM_PATTERN_INDEX_ENTRY, ListEntry);

        if (matcher->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&matcher->IndexEntryLookaside, indexEntry);
        } else {
            ExFreePoolWithTag(indexEntry, PM_POOL_TAG_INDEX);
        }
    }

    //
    // Collect all patterns under lock
    //
    ExAcquirePushLockExclusive(&Matcher->PatternLock);

    while (!IsListEmpty(&Matcher->PatternList)) {
        entry = RemoveHeadList(&Matcher->PatternList);
        InsertTailList(&freePatternList, entry);
    }
    Matcher->PatternCount = 0;

    ExReleasePushLockExclusive(&Matcher->PatternLock);

    //
    // Free collected patterns
    //
    while (!IsListEmpty(&freePatternList)) {
        entry = RemoveHeadList(&freePatternList);
        pattern = CONTAINING_RECORD(entry, PM_PATTERN, ListEntry);

        if (matcher->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&matcher->PatternLookaside, pattern);
        } else {
            ExFreePoolWithTag(pattern, PM_POOL_TAG);
        }
    }

    //
    // Delete lookaside lists
    //
    if (InterlockedExchange8((CHAR*)&matcher->LookasideInitialized, FALSE)) {
        ExDeleteNPagedLookasideList(&matcher->PatternLookaside);
        ExDeleteNPagedLookasideList(&matcher->StateLookaside);
        ExDeleteNPagedLookasideList(&matcher->IndexEntryLookaside);
    }

    //
    // Free matcher structure
    //
    ExFreePoolWithTag(matcher, PM_POOL_TAG);
}

// ============================================================================
// PATTERN MANAGEMENT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PmLoadPattern(
    PPM_MATCHER Matcher,
    PPM_PATTERN Pattern
    )
/**
 * @brief Load a behavioral pattern into the matcher.
 *
 * Validates and copies the pattern, then indexes for efficient event matching.
 *
 * @param Matcher Matcher instance
 * @param Pattern Pattern to load (copied internally)
 * @return STATUS_SUCCESS or error code
 */
{
    PPM_MATCHER_INTERNAL matcher;
    PPM_PATTERN newPattern = NULL;
    LONG currentCount;
    ULONG i;

    PAGED_CODE();

    if (Matcher == NULL || Pattern == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Matcher->Initialized || Matcher->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Validate event count
    //
    if (Pattern->EventCount == 0 || Pattern->EventCount > PM_MAX_EVENTS_PER_PATTERN) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate event types
    //
    for (i = 0; i < Pattern->EventCount; i++) {
        if (Pattern->Events[i].Type >= PmEvent_MaxType) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    matcher = CONTAINING_RECORD(Matcher, PM_MATCHER_INTERNAL, Public);

    //
    // Atomic check-and-increment for pattern limit
    //
    do {
        currentCount = Matcher->PatternCount;
        if (currentCount >= (LONG)PM_MAX_PATTERNS) {
            return STATUS_QUOTA_EXCEEDED;
        }
    } while (InterlockedCompareExchange(&Matcher->PatternCount, currentCount + 1, currentCount) != currentCount);

    //
    // Allocate pattern from lookaside
    //
    newPattern = (PPM_PATTERN)ExAllocateFromNPagedLookasideList(
        &matcher->PatternLookaside
    );

    if (newPattern == NULL) {
        InterlockedDecrement(&Matcher->PatternCount);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy pattern data
    //
    RtlCopyMemory(newPattern, Pattern, sizeof(PM_PATTERN));

    //
    // Ensure null termination of all strings
    //
    newPattern->PatternId[PM_MAX_PATTERN_ID_LENGTH - 1] = '\0';
    newPattern->PatternName[PM_MAX_PATTERN_NAME_LENGTH - 1] = '\0';
    newPattern->Description[PM_MAX_DESCRIPTION_LENGTH - 1] = '\0';
    newPattern->MITRETechnique[PM_MAX_MITRE_TECHNIQUE_LENGTH - 1] = '\0';

    for (i = 0; i < newPattern->EventCount; i++) {
        newPattern->Events[i].ProcessNamePattern[PM_MAX_PROCESS_NAME_LENGTH - 1] = '\0';
        newPattern->Events[i].PathPattern[PM_MAX_PATH_PATTERN_LENGTH - 1] = '\0';
        newPattern->Events[i].ValuePattern[PM_MAX_VALUE_PATTERN_LENGTH - 1] = '\0';
    }

    //
    // Generate pattern ID if not set
    //
    if (newPattern->PatternId[0] == '\0') {
        LONG id = InterlockedIncrement(&matcher->NextPatternId);
        RtlStringCbPrintfA(
            newPattern->PatternId,
            sizeof(newPattern->PatternId),
            "PATTERN_%08X",
            id
        );
    }

    //
    // Reset match count
    //
    InterlockedExchange64(&newPattern->MatchCount, 0);

    //
    // Initialize list entry
    //
    InitializeListHead(&newPattern->ListEntry);

    //
    // Insert into pattern list
    //
    ExAcquirePushLockExclusive(&Matcher->PatternLock);
    InsertTailList(&Matcher->PatternList, &newPattern->ListEntry);
    ExReleasePushLockExclusive(&Matcher->PatternLock);

    //
    // Index pattern by event types it matches
    //
    PmpIndexPattern(matcher, newPattern);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PmUnloadPattern(
    PPM_MATCHER Matcher,
    PCSTR PatternId
    )
/**
 * @brief Unload a pattern from the matcher.
 *
 * @param Matcher Matcher instance
 * @param PatternId ID of pattern to unload
 * @return STATUS_SUCCESS or STATUS_NOT_FOUND
 */
{
    PPM_MATCHER_INTERNAL matcher;
    PLIST_ENTRY entry;
    PPM_PATTERN pattern = NULL;
    BOOLEAN found = FALSE;

    PAGED_CODE();

    if (Matcher == NULL || PatternId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Matcher->Initialized || Matcher->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    matcher = CONTAINING_RECORD(Matcher, PM_MATCHER_INTERNAL, Public);

    //
    // Find and remove pattern
    //
    ExAcquirePushLockExclusive(&Matcher->PatternLock);

    for (entry = Matcher->PatternList.Flink;
         entry != &Matcher->PatternList;
         entry = entry->Flink) {

        pattern = CONTAINING_RECORD(entry, PM_PATTERN, ListEntry);

        if (strncmp(pattern->PatternId, PatternId, PM_MAX_PATTERN_ID_LENGTH) == 0) {
            RemoveEntryList(&pattern->ListEntry);
            InterlockedDecrement(&Matcher->PatternCount);
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockExclusive(&Matcher->PatternLock);

    if (!found) {
        return STATUS_NOT_FOUND;
    }

    //
    // Remove from index
    //
    PmpUnindexPattern(matcher, pattern);

    //
    // Free pattern
    //
    if (matcher->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&matcher->PatternLookaside, pattern);
    } else {
        ExFreePoolWithTag(pattern, PM_POOL_TAG);
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PmRegisterCallback(
    PPM_MATCHER Matcher,
    PM_MATCH_CALLBACK Callback,
    PVOID Context
    )
/**
 * @brief Register callback for pattern match notifications.
 *
 * Uses lock to ensure callback and context are updated atomically.
 *
 * @param Matcher Matcher instance
 * @param Callback Callback function (NULL to unregister)
 * @param Context Context passed to callback
 * @return STATUS_SUCCESS
 */
{
    PAGED_CODE();

    if (Matcher == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Matcher->Initialized || Matcher->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Atomically update both callback and context under lock
    //
    ExAcquirePushLockExclusive(&Matcher->CallbackLock);

    //
    // Use volatile write to ensure visibility
    //
    ((volatile PM_CALLBACK_REGISTRATION*)&Matcher->CallbackReg)->Callback = Callback;
    ((volatile PM_CALLBACK_REGISTRATION*)&Matcher->CallbackReg)->Context = Context;

    ExReleasePushLockExclusive(&Matcher->CallbackLock);

    return STATUS_SUCCESS;
}

// ============================================================================
// EVENT PROCESSING
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PmSubmitEvent(
    PPM_MATCHER Matcher,
    PM_EVENT_TYPE Type,
    HANDLE ProcessId,
    PCUNICODE_STRING Path,
    PCSTR Value
    )
/**
 * @brief Submit a behavioral event for pattern matching.
 *
 * Evaluates the event against all loaded patterns, updates
 * active match states, and creates new states as needed.
 * All operations at PASSIVE_LEVEL with push locks.
 *
 * @param Matcher Matcher instance
 * @param Type Event type
 * @param ProcessId Process ID for the event
 * @param Path Optional path (file, registry, etc.)
 * @param Value Optional value string
 * @return STATUS_SUCCESS or error code
 */
{
    PPM_MATCHER_INTERNAL matcher;
    LARGE_INTEGER currentTime;
    PLIST_ENTRY stateEntry;
    PLIST_ENTRY indexEntry;
    PPM_PATTERN_INDEX_ENTRY patternIndex;
    PPM_PATTERN pattern;
    PPM_MATCH_STATE_INTERNAL state;
    PPM_MATCH_STATE_INTERNAL newState;
    ULONG i;
    BOOLEAN stateExists;
    ULONG processStateCount = 0;
    ULONG bucket;

    PAGED_CODE();

    if (Matcher == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Matcher->Initialized || Matcher->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Type >= PmEvent_MaxType) {
        return STATUS_INVALID_PARAMETER;
    }

    matcher = CONTAINING_RECORD(Matcher, PM_MATCHER_INTERNAL, Public);

    //
    // Get current time using monotonic counter
    //
    currentTime = KeQueryPerformanceCounter(NULL);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Matcher->Stats.EventsProcessed);

    //
    // Count existing states for this process
    //
    bucket = PmpHashProcessId(ProcessId);

    ExAcquirePushLockShared(&matcher->ProcessStateHash.Lock);

    for (stateEntry = matcher->ProcessStateHash.Buckets[bucket].Flink;
         stateEntry != &matcher->ProcessStateHash.Buckets[bucket];
         stateEntry = stateEntry->Flink) {

        state = CONTAINING_RECORD(stateEntry, PM_MATCH_STATE_INTERNAL, ProcessHashEntry);
        if (state->Public.ProcessId == ProcessId && !state->IsStale && !state->IsRemoved) {
            processStateCount++;
        }
    }

    ExReleasePushLockShared(&matcher->ProcessStateHash.Lock);

    //
    // Phase 1: Check existing active states for this process
    //
    ExAcquirePushLockShared(&Matcher->StateLock);

    for (stateEntry = Matcher->StateList.Flink;
         stateEntry != &Matcher->StateList;
         stateEntry = stateEntry->Flink) {

        state = CONTAINING_RECORD(stateEntry, PM_MATCH_STATE_INTERNAL, Public.ListEntry);

        if (state->Public.ProcessId != ProcessId) {
            continue;
        }

        if (state->Public.IsComplete || state->IsStale || state->IsRemoved) {
            continue;
        }

        //
        // Reference state while we work with it
        //
        PmpReferenceState(state);

        //
        // Release lock while checking constraints (may be expensive)
        //
        ExReleasePushLockShared(&Matcher->StateLock);

        pattern = state->Public.Pattern;

        //
        // Try to match against expected events
        //
        for (i = state->Public.CurrentEventIndex;
             i < pattern->EventCount && i < PM_MAX_EVENTS_PER_PATTERN;
             i++) {

            if (state->EventMatched[i]) {
                continue;
            }

            if (PmpCheckEventConstraint(
                    matcher,
                    &pattern->Events[i],
                    Type,
                    Path,
                    Value,
                    state,
                    &currentTime)) {

                //
                // Event matches - advance state
                //
                PmpAdvanceMatchState(state, i, &currentTime);
                PmpCheckPatternComplete(matcher, state, &currentTime);
                break;
            }

            //
            // If exact order required and not optional, stop checking
            //
            if (pattern->RequireExactOrder && !pattern->Events[i].Optional) {
                break;
            }
        }

        //
        // Release our reference
        //
        PmpDereferenceState(matcher, state);

        //
        // Re-acquire lock and restart iteration
        // (list may have changed while lock was released)
        //
        ExAcquirePushLockShared(&Matcher->StateLock);
        stateEntry = &Matcher->StateList;  // Restart from beginning
    }

    ExReleasePushLockShared(&Matcher->StateLock);

    //
    // Phase 2: Check if this event starts any new patterns
    //
    ExAcquirePushLockShared(&matcher->IndexLock);

    for (indexEntry = matcher->PatternIndex[Type].Patterns.Flink;
         indexEntry != &matcher->PatternIndex[Type].Patterns;
         indexEntry = indexEntry->Flink) {

        patternIndex = CONTAINING_RECORD(indexEntry, PM_PATTERN_INDEX_ENTRY, ListEntry);
        pattern = patternIndex->Pattern;
        i = patternIndex->EventIndex;

        //
        // Only start new state from first event or if order not required
        //
        if (i != 0 && pattern->RequireExactOrder) {
            continue;
        }

        //
        // Check per-process state limit
        //
        if (processStateCount >= matcher->Config.MaxStatesPerProcess) {
            continue;
        }

        //
        // Check if we already have a state for this pattern/process
        //
        stateExists = FALSE;

        ExAcquirePushLockShared(&Matcher->StateLock);

        for (stateEntry = Matcher->StateList.Flink;
             stateEntry != &Matcher->StateList;
             stateEntry = stateEntry->Flink) {

            state = CONTAINING_RECORD(stateEntry, PM_MATCH_STATE_INTERNAL, Public.ListEntry);

            if (state->Public.ProcessId == ProcessId &&
                state->Public.Pattern == pattern &&
                !state->Public.IsComplete &&
                !state->IsStale &&
                !state->IsRemoved) {

                stateExists = TRUE;
                break;
            }
        }

        ExReleasePushLockShared(&Matcher->StateLock);

        if (stateExists) {
            continue;
        }

        //
        // Check if event matches constraint
        //
        if (!PmpCheckEventConstraint(
                matcher,
                &pattern->Events[i],
                Type,
                Path,
                Value,
                NULL,
                &currentTime)) {
            continue;
        }

        //
        // Atomically check and increment global state count
        //
        LONG currentCount;
        do {
            currentCount = Matcher->StateCount;
            if (currentCount >= (LONG)PM_MAX_ACTIVE_STATES) {
                goto NextPattern;
            }
        } while (InterlockedCompareExchange(&Matcher->StateCount, currentCount + 1, currentCount) != currentCount);

        //
        // Create new match state
        //
        newState = PmpCreateMatchState(matcher, pattern, ProcessId, &currentTime);

        if (newState == NULL) {
            InterlockedDecrement(&Matcher->StateCount);
            goto NextPattern;
        }

        //
        // Mark first event as matched
        //
        PmpAdvanceMatchState(newState, i, &currentTime);

        //
        // Insert into state list (under exclusive lock)
        //
        ExAcquirePushLockExclusive(&Matcher->StateLock);
        InsertTailList(&Matcher->StateList, &newState->Public.ListEntry);
        ExReleasePushLockExclusive(&Matcher->StateLock);

        //
        // Insert into process hash
        //
        PmpInsertStateIntoProcessHash(matcher, newState);

        processStateCount++;
        InterlockedIncrement64(&Matcher->Stats.StatesCreated);

        //
        // Check if already complete (single-event pattern)
        //
        PmpCheckPatternComplete(matcher, newState, &currentTime);

NextPattern:
        ;  // Continue to next pattern
    }

    ExReleasePushLockShared(&matcher->IndexLock);

    return STATUS_SUCCESS;
}

// ============================================================================
// STATE QUERIES
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PmGetActiveStates(
    PPM_MATCHER Matcher,
    HANDLE ProcessId,
    PPM_MATCH_STATE* States,
    ULONG MaxStates,
    PULONG StateCount
    )
/**
 * @brief Get active match states for a process.
 *
 * Returns array of state pointers with incremented reference counts.
 * Caller must release each using PmReleaseState.
 *
 * @param Matcher Matcher instance
 * @param ProcessId Process to query
 * @param States Output array for state pointers
 * @param MaxStates Maximum states to return
 * @param StateCount Receives count of states returned
 * @return STATUS_SUCCESS or error code
 */
{
    PPM_MATCHER_INTERNAL matcher;
    PLIST_ENTRY entry;
    PPM_MATCH_STATE_INTERNAL state;
    ULONG bucket;
    ULONG count = 0;

    PAGED_CODE();

    if (Matcher == NULL || States == NULL || StateCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Matcher->Initialized || Matcher->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    *StateCount = 0;

    if (MaxStates == 0) {
        return STATUS_SUCCESS;
    }

    matcher = CONTAINING_RECORD(Matcher, PM_MATCHER_INTERNAL, Public);
    bucket = PmpHashProcessId(ProcessId);

    ExAcquirePushLockShared(&matcher->ProcessStateHash.Lock);

    for (entry = matcher->ProcessStateHash.Buckets[bucket].Flink;
         entry != &matcher->ProcessStateHash.Buckets[bucket];
         entry = entry->Flink) {

        state = CONTAINING_RECORD(entry, PM_MATCH_STATE_INTERNAL, ProcessHashEntry);

        if (state->Public.ProcessId == ProcessId &&
            !state->IsStale &&
            !state->IsRemoved &&
            count < MaxStates) {

            PmpReferenceState(state);
            States[count++] = &state->Public;
        }
    }

    ExReleasePushLockShared(&matcher->ProcessStateHash.Lock);

    *StateCount = count;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PmReleaseState(
    PPM_MATCHER Matcher,
    PPM_MATCH_STATE State
    )
/**
 * @brief Release a match state reference obtained from PmGetActiveStates.
 *
 * @param Matcher Matcher instance
 * @param State State to release
 */
{
    PPM_MATCHER_INTERNAL matcher;
    PPM_MATCH_STATE_INTERNAL internalState;

    PAGED_CODE();

    if (Matcher == NULL || State == NULL) {
        return;
    }

    matcher = CONTAINING_RECORD(Matcher, PM_MATCHER_INTERNAL, Public);
    internalState = CONTAINING_RECORD(State, PM_MATCH_STATE_INTERNAL, Public);

    PmpDereferenceState(matcher, internalState);
}

_Use_decl_annotations_
VOID
PmCleanupProcessStates(
    PPM_MATCHER Matcher,
    HANDLE ProcessId
    )
/**
 * @brief Clean up all states for a terminated process.
 *
 * Called when a process terminates to free resources immediately.
 *
 * @param Matcher Matcher instance
 * @param ProcessId Process that terminated
 */
{
    PPM_MATCHER_INTERNAL matcher;
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PPM_MATCH_STATE_INTERNAL state;
    ULONG bucket;
    LIST_ENTRY staleList;

    PAGED_CODE();

    if (Matcher == NULL) {
        return;
    }

    if (!Matcher->Initialized) {
        return;
    }

    matcher = CONTAINING_RECORD(Matcher, PM_MATCHER_INTERNAL, Public);
    bucket = PmpHashProcessId(ProcessId);

    InitializeListHead(&staleList);

    //
    // Mark states as stale under lock
    //
    ExAcquirePushLockExclusive(&matcher->ProcessStateHash.Lock);

    for (entry = matcher->ProcessStateHash.Buckets[bucket].Flink;
         entry != &matcher->ProcessStateHash.Buckets[bucket];
         entry = nextEntry) {

        nextEntry = entry->Flink;
        state = CONTAINING_RECORD(entry, PM_MATCH_STATE_INTERNAL, ProcessHashEntry);

        if (state->Public.ProcessId == ProcessId) {
            InterlockedExchange8((CHAR*)&state->IsStale, TRUE);
        }
    }

    ExReleasePushLockExclusive(&matcher->ProcessStateHash.Lock);

    //
    // Trigger cleanup
    //
    PmpCleanupStaleStates(matcher);
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS
// ============================================================================

static ULONG
PmpHashProcessId(
    _In_ HANDLE ProcessId
    )
/**
 * @brief Hash function for process ID.
 *
 * Simple shift-and-modulo hash for 256 buckets.
 */
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    return (ULONG)((pid >> 2) & 0xFF);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
PmpMatchWildcardSafe(
    _In_reads_or_z_(PatternMaxLen) PCSTR Pattern,
    _In_ SIZE_T PatternMaxLen,
    _In_reads_or_z_(StringMaxLen) PCSTR String,
    _In_ SIZE_T StringMaxLen
    )
/**
 * @brief Match string against wildcard pattern with length limits.
 *
 * Supports '*' (any characters) and '?' (single character).
 * Includes iteration limit to prevent ReDoS attacks.
 *
 * @param Pattern Wildcard pattern
 * @param PatternMaxLen Maximum pattern length to consider
 * @param String String to match
 * @param StringMaxLen Maximum string length to consider
 * @return TRUE if matches, FALSE otherwise
 */
{
    PCSTR p;
    PCSTR s;
    PCSTR starP = NULL;
    PCSTR starS = NULL;
    SIZE_T patternLen;
    SIZE_T stringLen;
    ULONG iterations = 0;

    PAGED_CODE();

    //
    // Handle NULL or empty pattern (matches everything)
    //
    if (Pattern == NULL || PatternMaxLen == 0) {
        return TRUE;
    }

    //
    // Calculate actual lengths with bounds
    //
    patternLen = strnlen(Pattern, PatternMaxLen);
    if (patternLen == 0) {
        return TRUE;  // Empty pattern matches everything
    }

    if (String == NULL || StringMaxLen == 0) {
        //
        // Empty string only matches pattern of all '*'
        //
        for (SIZE_T i = 0; i < patternLen; i++) {
            if (Pattern[i] != '*') {
                return FALSE;
            }
        }
        return TRUE;
    }

    stringLen = strnlen(String, StringMaxLen);

    p = Pattern;
    s = String;

    while ((SIZE_T)(s - String) < stringLen && *s != '\0') {
        //
        // Prevent infinite loops / ReDoS
        //
        if (++iterations > PM_MAX_WILDCARD_ITERATIONS) {
            return FALSE;
        }

        //
        // Check pattern bounds
        //
        if ((SIZE_T)(p - Pattern) >= patternLen && starP == NULL) {
            return FALSE;
        }

        if ((SIZE_T)(p - Pattern) < patternLen && *p == '*') {
            starP = p++;
            starS = s;
        } else if ((SIZE_T)(p - Pattern) < patternLen &&
                   (*p == '?' ||
                    *p == *s ||
                    (*p >= 'A' && *p <= 'Z' && (*p + 32) == *s) ||
                    (*p >= 'a' && *p <= 'z' && (*p - 32) == *s))) {
            p++;
            s++;
        } else if (starP != NULL) {
            p = starP + 1;
            s = ++starS;
        } else {
            return FALSE;
        }
    }

    //
    // Skip trailing '*' in pattern
    //
    while ((SIZE_T)(p - Pattern) < patternLen && *p == '*') {
        p++;
    }

    return ((SIZE_T)(p - Pattern) >= patternLen || *p == '\0');
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static PPM_MATCH_STATE_INTERNAL
PmpCreateMatchState(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_PATTERN Pattern,
    _In_ HANDLE ProcessId,
    _In_ PLARGE_INTEGER CurrentTime
    )
/**
 * @brief Create a new match state for pattern/process.
 *
 * @param Matcher Internal matcher
 * @param Pattern Pattern being matched
 * @param ProcessId Process ID
 * @param CurrentTime Current performance counter value
 * @return New state or NULL on failure
 */
{
    PPM_MATCH_STATE_INTERNAL state;

    PAGED_CODE();

    state = (PPM_MATCH_STATE_INTERNAL)ExAllocateFromNPagedLookasideList(
        &Matcher->StateLookaside
    );

    if (state == NULL) {
        return NULL;
    }

    RtlZeroMemory(state, sizeof(PM_MATCH_STATE_INTERNAL));

    state->Public.Pattern = Pattern;
    state->Public.ProcessId = ProcessId;
    state->Public.CurrentEventIndex = 0;
    state->Public.MatchedEvents = 0;
    state->Public.IsComplete = FALSE;
    state->Public.ConfidenceScore = 0;
    state->Public.FirstEventTime = *CurrentTime;
    state->Public.LastEventTime = *CurrentTime;

    //
    // Initialize reference count to 1 (creator holds reference)
    //
    state->RefCount = 1;
    state->IsStale = FALSE;
    state->NotificationSent = FALSE;
    state->IsRemoved = FALSE;
    state->NextMatchOrder = 0;

    InitializeListHead(&state->Public.ListEntry);
    InitializeListHead(&state->ProcessHashEntry);

    return state;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpReferenceState(
    _In_ PPM_MATCH_STATE_INTERNAL State
    )
/**
 * @brief Increment state reference count.
 */
{
    PAGED_CODE();

    InterlockedIncrement(&State->RefCount);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpDereferenceState(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_MATCH_STATE_INTERNAL State
    )
/**
 * @brief Decrement state reference count, free if zero.
 *
 * @param Matcher Internal matcher
 * @param State State to dereference
 */
{
    LONG newRef;

    PAGED_CODE();

    newRef = InterlockedDecrement(&State->RefCount);

    //
    // Safety check for underflow
    //
    if (newRef < 0) {
        //
        // This should never happen - indicates a bug
        // Log and force to 0 to prevent double-free
        //
        InterlockedExchange(&State->RefCount, 0);
        return;
    }

    //
    // Only free if removed from all lists and refcount is zero
    //
    if (newRef == 0 && State->IsRemoved) {
        if (Matcher->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&Matcher->StateLookaside, State);
        } else {
            ExFreePoolWithTag(State, PM_POOL_TAG_STATE);
        }

        InterlockedIncrement64(&Matcher->Public.Stats.StatesCleanedUp);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
PmpCheckEventConstraint(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_EVENT_CONSTRAINT* Constraint,
    _In_ PM_EVENT_TYPE EventType,
    _In_opt_ PCUNICODE_STRING Path,
    _In_opt_ PCSTR Value,
    _In_opt_ PPM_MATCH_STATE_INTERNAL State,
    _In_ PLARGE_INTEGER CurrentTime
    )
/**
 * @brief Check if event matches constraint.
 *
 * @param Matcher Internal matcher
 * @param Constraint Constraint to check
 * @param EventType Event type
 * @param Path Optional path
 * @param Value Optional value
 * @param State Optional state for timing checks
 * @param CurrentTime Current performance counter
 * @return TRUE if matches
 */
{
    LONGLONG timeDelta;
    NTSTATUS status;
    ANSI_STRING ansiPath;
    CHAR pathBuffer[PM_MAX_PATH_CONVERSION_LENGTH];

    PAGED_CODE();

    //
    // Check event type first (cheapest check)
    //
    if (Constraint->Type != EventType) {
        return FALSE;
    }

    //
    // Check path pattern if specified
    //
    if (Constraint->PathPattern[0] != '\0' && Path != NULL && Path->Buffer != NULL && Path->Length > 0) {
        //
        // Convert to ANSI for pattern matching
        //
        ansiPath.Buffer = pathBuffer;
        ansiPath.MaximumLength = sizeof(pathBuffer) - 1;
        ansiPath.Length = 0;

        status = RtlUnicodeStringToAnsiString(&ansiPath, Path, FALSE);

        if (NT_SUCCESS(status)) {
            //
            // Ensure null termination
            //
            pathBuffer[ansiPath.Length] = '\0';

            if (!PmpMatchWildcardSafe(
                    Constraint->PathPattern,
                    PM_MAX_PATH_PATTERN_LENGTH,
                    pathBuffer,
                    sizeof(pathBuffer))) {
                return FALSE;
            }
        } else {
            //
            // Conversion failed - treat as non-match for security
            // (don't bypass pattern due to conversion errors)
            //
            return FALSE;
        }
    }

    //
    // Check value pattern if specified
    //
    if (Constraint->ValuePattern[0] != '\0' && Value != NULL) {
        if (!PmpMatchWildcardSafe(
                Constraint->ValuePattern,
                PM_MAX_VALUE_PATTERN_LENGTH,
                Value,
                PM_MAX_VALUE_PATTERN_LENGTH)) {
            return FALSE;
        }
    }

    //
    // Check timing constraints using monotonic time
    //
    if (State != NULL &&
        (Constraint->MaxTimeFromPrevious > 0 || Constraint->MinTimeFromPrevious > 0)) {

        timeDelta = PmpGetElapsedMs(Matcher, &State->Public.LastEventTime, CurrentTime);

        if (Constraint->MaxTimeFromPrevious > 0 &&
            timeDelta > (LONGLONG)Constraint->MaxTimeFromPrevious) {
            return FALSE;
        }

        if (Constraint->MinTimeFromPrevious > 0 &&
            timeDelta < (LONGLONG)Constraint->MinTimeFromPrevious) {
            return FALSE;
        }
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpAdvanceMatchState(
    _In_ PPM_MATCH_STATE_INTERNAL State,
    _In_ ULONG EventIndex,
    _In_ PLARGE_INTEGER EventTime
    )
/**
 * @brief Advance match state after event match.
 *
 * @param State State to advance
 * @param EventIndex Index of matched event
 * @param EventTime Time of event
 */
{
    PAGED_CODE();

    //
    // Bounds check
    //
    if (EventIndex >= PM_MAX_EVENTS_PER_PATTERN) {
        return;
    }

    //
    // Bounds check for NextMatchOrder
    //
    if (State->NextMatchOrder >= PM_MAX_EVENTS_PER_PATTERN) {
        return;
    }

    //
    // Mark event as matched
    //
    State->EventMatched[EventIndex] = TRUE;
    State->EventTimes[EventIndex] = *EventTime;
    State->EventMatchOrder[State->NextMatchOrder] = EventIndex;
    State->NextMatchOrder++;
    State->Public.MatchedEvents++;
    State->Public.LastEventTime = *EventTime;

    //
    // Advance current event index if in order
    //
    if (EventIndex == State->Public.CurrentEventIndex) {
        State->Public.CurrentEventIndex++;

        //
        // Skip optional events that were skipped
        //
        while (State->Public.CurrentEventIndex < State->Public.Pattern->EventCount &&
               State->Public.CurrentEventIndex < PM_MAX_EVENTS_PER_PATTERN) {

            if (!State->EventMatched[State->Public.CurrentEventIndex] &&
                State->Public.Pattern->Events[State->Public.CurrentEventIndex].Optional) {
                State->Public.CurrentEventIndex++;
            } else {
                break;
            }
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpCheckPatternComplete(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_MATCH_STATE_INTERNAL State,
    _In_ PLARGE_INTEGER CurrentTime
    )
/**
 * @brief Check if pattern matching is complete.
 *
 * @param Matcher Internal matcher
 * @param State State to check
 * @param CurrentTime Current performance counter
 */
{
    PPM_PATTERN pattern;
    ULONG requiredEvents = 0;
    ULONG matchedRequired = 0;
    ULONG i;
    LONGLONG totalTime;
    BOOLEAN hasTerminal = FALSE;
    BOOLEAN terminalMatched = FALSE;

    PAGED_CODE();

    if (State->Public.IsComplete) {
        return;
    }

    pattern = State->Public.Pattern;

    //
    // Count required events and check terminal events
    //
    for (i = 0; i < pattern->EventCount && i < PM_MAX_EVENTS_PER_PATTERN; i++) {
        if (!pattern->Events[i].Optional) {
            requiredEvents++;
            if (State->EventMatched[i]) {
                matchedRequired++;
            }
        }

        if (pattern->Events[i].Terminal) {
            hasTerminal = TRUE;
            if (State->EventMatched[i]) {
                terminalMatched = TRUE;
            }
        }
    }

    //
    // Check total time constraint
    //
    if (pattern->MaxTotalTimeMs > 0) {
        totalTime = PmpGetElapsedMs(Matcher, &State->Public.FirstEventTime, CurrentTime);

        if (totalTime > (LONGLONG)pattern->MaxTotalTimeMs) {
            InterlockedExchange8((CHAR*)&State->IsStale, TRUE);
            return;
        }
    }

    //
    // Determine completion
    //
    if (pattern->MinMatchedEvents > 0) {
        //
        // Partial matching mode
        //
        if (State->Public.MatchedEvents < pattern->MinMatchedEvents) {
            return;
        }
    } else {
        //
        // All required events must be matched
        //
        if (matchedRequired < requiredEvents) {
            return;
        }
    }

    //
    // Check terminal event requirement
    //
    if (hasTerminal && !terminalMatched) {
        return;
    }

    //
    // Pattern is complete
    //
    State->Public.IsComplete = TRUE;

    //
    // Calculate confidence score (0-100)
    //
    if (pattern->EventCount > 0) {
        State->Public.ConfidenceScore =
            (State->Public.MatchedEvents * 100) / pattern->EventCount;
    } else {
        State->Public.ConfidenceScore = 100;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&pattern->MatchCount);
    InterlockedIncrement64(&Matcher->Public.Stats.PatternsMatched);

    //
    // Notify callback (only once)
    //
    if (!InterlockedCompareExchange8((CHAR*)&State->NotificationSent, TRUE, FALSE)) {
        PmpNotifyCallback(Matcher, pattern, &State->Public);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpNotifyCallback(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_PATTERN Pattern,
    _In_ PPM_MATCH_STATE State
    )
/**
 * @brief Notify registered callback of pattern match.
 *
 * Reads callback atomically under lock to ensure consistency.
 */
{
    PM_CALLBACK_REGISTRATION reg;

    PAGED_CODE();

    //
    // Read callback registration atomically
    //
    ExAcquirePushLockShared(&Matcher->Public.CallbackLock);
    reg = Matcher->Public.CallbackReg;
    ExReleasePushLockShared(&Matcher->Public.CallbackLock);

    if (reg.Callback != NULL) {
        reg.Callback(Pattern, State, reg.Context);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpIndexPattern(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_PATTERN Pattern
    )
/**
 * @brief Index pattern by event types for fast lookup.
 */
{
    ULONG i;
    PPM_PATTERN_INDEX_ENTRY indexEntry;
    PM_EVENT_TYPE eventType;

    PAGED_CODE();

    ExAcquirePushLockExclusive(&Matcher->IndexLock);

    for (i = 0; i < Pattern->EventCount && i < PM_MAX_EVENTS_PER_PATTERN; i++) {
        eventType = Pattern->Events[i].Type;

        if (eventType >= PmEvent_MaxType) {
            continue;
        }

        //
        // Only index first event or non-optional events
        //
        if (i == 0 || !Pattern->Events[i].Optional) {
            indexEntry = (PPM_PATTERN_INDEX_ENTRY)ExAllocateFromNPagedLookasideList(
                &Matcher->IndexEntryLookaside
            );

            if (indexEntry != NULL) {
                indexEntry->Pattern = Pattern;
                indexEntry->EventIndex = i;
                InsertTailList(
                    &Matcher->PatternIndex[eventType].Patterns,
                    &indexEntry->ListEntry
                );
                Matcher->PatternIndex[eventType].Count++;
            }
        }
    }

    ExReleasePushLockExclusive(&Matcher->IndexLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpUnindexPattern(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_PATTERN Pattern
    )
/**
 * @brief Remove pattern from index.
 */
{
    ULONG i;
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PPM_PATTERN_INDEX_ENTRY indexEntry;
    LIST_ENTRY freeList;

    PAGED_CODE();

    InitializeListHead(&freeList);

    ExAcquirePushLockExclusive(&Matcher->IndexLock);

    for (i = 0; i < PmEvent_MaxType; i++) {
        for (entry = Matcher->PatternIndex[i].Patterns.Flink;
             entry != &Matcher->PatternIndex[i].Patterns;
             entry = nextEntry) {

            nextEntry = entry->Flink;
            indexEntry = CONTAINING_RECORD(entry, PM_PATTERN_INDEX_ENTRY, ListEntry);

            if (indexEntry->Pattern == Pattern) {
                RemoveEntryList(&indexEntry->ListEntry);
                Matcher->PatternIndex[i].Count--;
                InsertTailList(&freeList, &indexEntry->ListEntry);
            }
        }
    }

    ExReleasePushLockExclusive(&Matcher->IndexLock);

    //
    // Free collected entries outside lock
    //
    while (!IsListEmpty(&freeList)) {
        entry = RemoveHeadList(&freeList);
        indexEntry = CONTAINING_RECORD(entry, PM_PATTERN_INDEX_ENTRY, ListEntry);

        if (Matcher->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&Matcher->IndexEntryLookaside, indexEntry);
        } else {
            ExFreePoolWithTag(indexEntry, PM_POOL_TAG_INDEX);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpInsertStateIntoProcessHash(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_MATCH_STATE_INTERNAL State
    )
/**
 * @brief Insert state into per-process hash table.
 */
{
    ULONG bucket;

    PAGED_CODE();

    bucket = PmpHashProcessId(State->Public.ProcessId);

    ExAcquirePushLockExclusive(&Matcher->ProcessStateHash.Lock);
    InsertTailList(&Matcher->ProcessStateHash.Buckets[bucket], &State->ProcessHashEntry);
    State->ProcessHashBucket = bucket;
    ExReleasePushLockExclusive(&Matcher->ProcessStateHash.Lock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpRemoveStateFromProcessHash(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PPM_MATCH_STATE_INTERNAL State
    )
/**
 * @brief Remove state from per-process hash table.
 */
{
    PAGED_CODE();

    ExAcquirePushLockExclusive(&Matcher->ProcessStateHash.Lock);

    //
    // Check if actually in list before removing
    //
    if (!IsListEmpty(&State->ProcessHashEntry)) {
        RemoveEntryList(&State->ProcessHashEntry);
        InitializeListHead(&State->ProcessHashEntry);
    }

    ExReleasePushLockExclusive(&Matcher->ProcessStateHash.Lock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
PmpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/**
 * @brief DPC callback for periodic cleanup.
 *
 * Queues a work item to perform actual cleanup at PASSIVE_LEVEL.
 */
{
    PPM_MATCHER_INTERNAL matcher = (PPM_MATCHER_INTERNAL)DeferredContext;
    PIO_WORKITEM workItem;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (matcher == NULL || matcher->Public.ShuttingDown) {
        return;
    }

    //
    // Skip if cleanup already scheduled
    //
    if (InterlockedCompareExchange8((CHAR*)&matcher->CleanupScheduled, TRUE, FALSE)) {
        return;
    }

    //
    // Queue work item for PASSIVE_LEVEL cleanup
    // Note: In a real driver, we would use IoAllocateWorkItem with a device object
    // For this implementation, we use a simplified approach with ExQueueWorkItem
    //
    workItem = (PIO_WORKITEM)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(WORK_QUEUE_ITEM),
        PM_POOL_TAG_WORKITEM
    );

    if (workItem != NULL) {
        ExInitializeWorkItem(
            (PWORK_QUEUE_ITEM)workItem,
            (PWORKER_THREAD_ROUTINE)PmpCleanupWorkItemRoutine,
            matcher
        );
        ExQueueWorkItem((PWORK_QUEUE_ITEM)workItem, DelayedWorkQueue);
    } else {
        InterlockedExchange8((CHAR*)&matcher->CleanupScheduled, FALSE);
    }
}

_Use_decl_annotations_
VOID
PmpCleanupWorkItemRoutine(
    PDEVICE_OBJECT DeviceObject,
    PVOID Context
    )
/**
 * @brief Work item routine for cleanup at PASSIVE_LEVEL.
 */
{
    PPM_MATCHER_INTERNAL matcher = (PPM_MATCHER_INTERNAL)Context;
    PWORK_QUEUE_ITEM workItem;

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    if (matcher == NULL || matcher->Public.ShuttingDown) {
        return;
    }

    //
    // Perform cleanup
    //
    PmpCleanupStaleStates(matcher);

    //
    // Clear scheduled flag
    //
    InterlockedExchange8((CHAR*)&matcher->CleanupScheduled, FALSE);

    //
    // Free work item (it was passed as Context in a simplified manner)
    // In production, use proper IoFreeWorkItem
    //
    workItem = CONTAINING_RECORD(Context, WORK_QUEUE_ITEM, Parameter);
    ExFreePoolWithTag(workItem, PM_POOL_TAG_WORKITEM);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PmpCleanupStaleStates(
    _In_ PPM_MATCHER_INTERNAL Matcher
    )
/**
 * @brief Clean up stale and completed states.
 *
 * Runs at PASSIVE_LEVEL via work item.
 */
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PPM_MATCH_STATE_INTERNAL state;
    LIST_ENTRY removeList;
    LARGE_INTEGER currentTime;
    LONGLONG timeout;
    LONGLONG stateAge;

    PAGED_CODE();

    if (Matcher->Public.ShuttingDown) {
        return;
    }

    InitializeListHead(&removeList);

    currentTime = KeQueryPerformanceCounter(NULL);
    timeout = (LONGLONG)Matcher->Config.StateTimeoutMs;

    //
    // Phase 1: Mark stale states and collect removable states
    //
    ExAcquirePushLockExclusive(&Matcher->Public.StateLock);

    for (entry = Matcher->Public.StateList.Flink;
         entry != &Matcher->Public.StateList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        state = CONTAINING_RECORD(entry, PM_MATCH_STATE_INTERNAL, Public.ListEntry);

        //
        // Check for timeout
        //
        if (!state->IsStale && !state->Public.IsComplete) {
            stateAge = PmpGetElapsedMs(Matcher, &state->Public.LastEventTime, &currentTime);

            if (stateAge > timeout) {
                InterlockedExchange8((CHAR*)&state->IsStale, TRUE);
            }
        }

        //
        // Remove completed or stale states with no external references
        // RefCount of 1 means only we hold a reference
        //
        if ((state->Public.IsComplete || state->IsStale) && state->RefCount <= 1) {
            RemoveEntryList(&state->Public.ListEntry);
            InterlockedDecrement(&Matcher->Public.StateCount);
            state->IsRemoved = TRUE;
            InsertTailList(&removeList, &state->Public.ListEntry);
        }
    }

    ExReleasePushLockExclusive(&Matcher->Public.StateLock);

    //
    // Phase 2: Remove from process hash and free
    //
    while (!IsListEmpty(&removeList)) {
        entry = RemoveHeadList(&removeList);
        state = CONTAINING_RECORD(entry, PM_MATCH_STATE_INTERNAL, Public.ListEntry);

        PmpRemoveStateFromProcessHash(Matcher, state);

        //
        // Dereference (will free if refcount reaches 0)
        //
        PmpDereferenceState(Matcher, state);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static LONGLONG
PmpGetElapsedMs(
    _In_ PPM_MATCHER_INTERNAL Matcher,
    _In_ PLARGE_INTEGER StartTime,
    _In_ PLARGE_INTEGER EndTime
    )
/**
 * @brief Calculate elapsed time in milliseconds using performance counter.
 *
 * Uses monotonic time that cannot be manipulated by attackers.
 *
 * @param Matcher Matcher with frequency info
 * @param StartTime Start performance counter value
 * @param EndTime End performance counter value
 * @return Elapsed milliseconds
 */
{
    LONGLONG elapsed;
    LONGLONG frequency;

    PAGED_CODE();

    elapsed = EndTime->QuadPart - StartTime->QuadPart;
    frequency = Matcher->Public.PerformanceFrequency.QuadPart;

    if (frequency == 0 || elapsed < 0) {
        return 0;
    }

    //
    // Convert to milliseconds: (elapsed * 1000) / frequency
    // Use careful ordering to avoid overflow
    //
    return (elapsed / (frequency / 1000));
}
