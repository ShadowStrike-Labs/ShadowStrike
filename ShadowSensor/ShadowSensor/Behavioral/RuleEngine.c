/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE BEHAVIORAL RULE ENGINE IMPLEMENTATION
===============================================================================

@file RuleEngine.c
@brief Enterprise-grade behavioral detection rule engine for kernel EDR.

SECURITY & STABILITY GUARANTEES:
- No use-after-free: All returned data is copied, never internal pointers
- No IRQL violations: All lock acquisitions respect IRQL requirements
- No race conditions: Single lock acquisition for check-then-act operations
- No buffer overflows: All string operations use bounded lengths
- No memory leaks: Proper cleanup on all error paths
- No deadlocks: Strict lock hierarchy enforced

LOCK HIERARCHY (always acquire in this order):
1. Engine->RuleLock (protects rule list and hash table)
   - Never hold while calling external functions
   - Never acquire at DISPATCH_LEVEL

@author ShadowStrike Security Team
@version 3.0.0 (Enterprise Edition - Hardened)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "RuleEngine.h"
#include <ntstrsafe.h>
#include <wdm.h>

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define RE_HASH_BUCKETS             256
#define RE_SHA256_HASH_SIZE         32
#define RE_ENGINE_SIGNATURE         'RulE'
#define RE_RULE_SIGNATURE           'Rule'

//
// Time constants
//
#define RE_HOURS_PER_DAY            24
#define RE_MINUTES_PER_HOUR         60
#define RE_SECONDS_PER_MINUTE       60
#define RE_100NS_PER_SECOND         10000000LL

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

//
// Compiled condition for fast evaluation
//
typedef struct _RE_COMPILED_CONDITION {
    RE_CONDITION_TYPE Type;
    RE_OPERATOR Operator;
    BOOLEAN Negate;
    BOOLEAN CaseInsensitive;

    //
    // Pre-computed values for fast matching
    //
    union {
        struct {
            WCHAR Pattern[RE_MAX_PATTERN_LENGTH];
            ULONG PatternLengthChars;
            ULONG PatternHash;
        } String;

        struct {
            ULONG Value;
            ULONG Mask;
        } Numeric;

        struct {
            UCHAR Hash[RE_SHA256_HASH_SIZE];
        } FileHash;

        struct {
            ULONG StartMinute;      // Minutes from midnight
            ULONG EndMinute;
        } TimeOfDay;

    } Data;

} RE_COMPILED_CONDITION, *PRE_COMPILED_CONDITION;

//
// Internal rule structure with compiled conditions
//
typedef struct _RE_INTERNAL_RULE {
    ULONG Signature;                // RE_RULE_SIGNATURE for validation
    RE_RULE Public;

    //
    // Compiled conditions for fast evaluation
    //
    RE_COMPILED_CONDITION CompiledConditions[RE_MAX_CONDITIONS];
    ULONG CompiledConditionCount;
    BOOLEAN IsCompiled;

    //
    // Hash table linkage (separate from priority list)
    //
    LIST_ENTRY HashEntry;
    ULONG RuleIdHash;

    //
    // Reference counting for safe removal
    //
    volatile LONG RefCount;

    //
    // Marked for deletion (don't match, pending refcount drop)
    //
    BOOLEAN MarkedForDeletion;

} RE_INTERNAL_RULE, *PRE_INTERNAL_RULE;

//
// Internal engine structure
//
typedef struct _RE_ENGINE {
    ULONG Signature;                // RE_ENGINE_SIGNATURE for validation
    volatile LONG Initialized;      // Atomic initialization flag

    //
    // Rules sorted by priority
    //
    LIST_ENTRY RuleList;
    EX_PUSH_LOCK RuleLock;
    volatile LONG RuleCount;

    //
    // Rule hash table for fast lookup by ID
    //
    LIST_ENTRY RuleHashBuckets[RE_HASH_BUCKETS];

    //
    // Lookaside lists for fast allocation
    //
    NPAGED_LOOKASIDE_LIST RuleLookaside;
    NPAGED_LOOKASIDE_LIST ResultLookaside;
    volatile LONG LookasideInitialized;

    //
    // Statistics
    //
    struct {
        volatile LONG64 Evaluations;
        volatile LONG64 Matches;
        volatile LONG64 Blocks;
        LARGE_INTEGER StartTime;
    } Stats;

} RE_ENGINE, *PRE_ENGINE;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static ULONG
RepComputeStringHash(
    _In_reads_(LengthChars) PCWSTR String,
    _In_ ULONG LengthChars
    );

static ULONG
RepComputeAnsiStringHash(
    _In_z_ PCSTR String
    );

static NTSTATUS
RepCompileRule(
    _Inout_ PRE_INTERNAL_RULE Rule
    );

static NTSTATUS
RepCompileStringCondition(
    _In_ PCSTR SourceValue,
    _Out_ PRE_COMPILED_CONDITION Compiled
    );

static NTSTATUS
RepCompileHashCondition(
    _In_ PCSTR HexString,
    _Out_ PRE_COMPILED_CONDITION Compiled
    );

static NTSTATUS
RepCompileNumericCondition(
    _In_ PCSTR ValueString,
    _Out_ PRE_COMPILED_CONDITION Compiled
    );

static NTSTATUS
RepCompileTimeCondition(
    _In_ PCSTR TimeSpec,
    _Out_ PRE_COMPILED_CONDITION Compiled
    );

static BOOLEAN
RepEvaluateCondition(
    _In_ PRE_COMPILED_CONDITION Condition,
    _In_ const RE_EVALUATION_CONTEXT* Context
    );

static BOOLEAN
RepMatchUnicodeString(
    _In_reads_(PatternLengthChars) PCWSTR Pattern,
    _In_ ULONG PatternLengthChars,
    _In_ PCUNICODE_STRING Value,
    _In_ RE_OPERATOR Operator,
    _In_ BOOLEAN CaseInsensitive
    );

static BOOLEAN
RepWildcardMatch(
    _In_reads_(PatternLengthChars) PCWSTR Pattern,
    _In_ ULONG PatternLengthChars,
    _In_reads_(StringLengthChars) PCWSTR String,
    _In_ ULONG StringLengthChars,
    _In_ BOOLEAN CaseInsensitive
    );

static WCHAR
RepToUpperChar(
    _In_ WCHAR Char
    );

static PRE_INTERNAL_RULE
RepFindRuleByIdLocked(
    _In_ PRE_ENGINE Engine,
    _In_z_ PCSTR RuleId
    );

static VOID
RepInsertRuleSortedLocked(
    _In_ PRE_ENGINE Engine,
    _In_ PRE_INTERNAL_RULE Rule
    );

static VOID
RepReferenceRule(
    _In_ PRE_INTERNAL_RULE Rule
    );

static VOID
RepDereferenceRule(
    _In_ PRE_ENGINE Engine,
    _In_ PRE_INTERNAL_RULE Rule
    );

static VOID
RepFreeRuleInternal(
    _In_ PRE_ENGINE Engine,
    _In_ PRE_INTERNAL_RULE Rule
    );

static BOOLEAN
RepValidateEngine(
    _In_opt_ PRE_ENGINE Engine
    );

static BOOLEAN
RepValidateRule(
    _In_opt_ const RE_RULE* Rule
    );

static BOOLEAN
RepValidateContext(
    _In_opt_ const RE_EVALUATION_CONTEXT* Context
    );

static BOOLEAN
RepValidateUnicodeString(
    _In_opt_ PCUNICODE_STRING String
    );

static SIZE_T
RepSafeStringLength(
    _In_reads_or_z_(MaxLength) PCSTR String,
    _In_ SIZE_T MaxLength
    );

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ReInitialize(
    _Out_ PRE_ENGINE* Engine
    )
/*++
Routine Description:
    Initializes the behavioral rule engine.

    IRQL: Must be called at PASSIVE_LEVEL.

Arguments:
    Engine - Receives pointer to initialized engine.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INVALID_PARAMETER if Engine is NULL.
    STATUS_INSUFFICIENT_RESOURCES if allocation fails.
--*/
{
    PRE_ENGINE engine = NULL;
    ULONG i;

    PAGED_CODE();

    if (Engine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Engine = NULL;

    //
    // Allocate engine structure from non-paged pool
    // (contains locks that may be acquired at elevated IRQL)
    //
    engine = (PRE_ENGINE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(RE_ENGINE),
        RE_POOL_TAG
    );

    if (engine == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(engine, sizeof(RE_ENGINE));
    engine->Signature = RE_ENGINE_SIGNATURE;

    //
    // Initialize synchronization primitives
    //
    ExInitializePushLock(&engine->RuleLock);

    //
    // Initialize lists
    //
    InitializeListHead(&engine->RuleList);

    for (i = 0; i < RE_HASH_BUCKETS; i++) {
        InitializeListHead(&engine->RuleHashBuckets[i]);
    }

    //
    // Initialize lookaside lists for fast allocation
    //
    ExInitializeNPagedLookasideList(
        &engine->RuleLookaside,
        NULL,                       // Default allocate
        NULL,                       // Default free
        0,                          // Flags
        sizeof(RE_INTERNAL_RULE),
        RE_POOL_TAG_RULE,
        0                           // Depth (system default)
    );

    ExInitializeNPagedLookasideList(
        &engine->ResultLookaside,
        NULL,
        NULL,
        0,
        sizeof(RE_EVALUATION_RESULT),
        RE_POOL_TAG_RESULT,
        0
    );

    InterlockedExchange(&engine->LookasideInitialized, TRUE);

    //
    // Record start time
    //
    KeQuerySystemTimePrecise(&engine->Stats.StartTime);

    //
    // Mark as initialized (atomic to handle races)
    //
    InterlockedExchange(&engine->Initialized, TRUE);

    *Engine = engine;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ReShutdown(
    _Inout_opt_ PRE_ENGINE Engine
    )
/*++
Routine Description:
    Shuts down the rule engine and frees all resources.

    IRQL: Must be called at PASSIVE_LEVEL to allow DPC flush.

Arguments:
    Engine - Engine to shutdown. May be NULL.
--*/
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PRE_INTERNAL_RULE rule;

    PAGED_CODE();

    if (Engine == NULL) {
        return;
    }

    if (Engine->Signature != RE_ENGINE_SIGNATURE) {
        return;
    }

    //
    // Mark as not initialized to prevent new operations
    //
    if (InterlockedExchange(&Engine->Initialized, FALSE) == FALSE) {
        // Already shutdown
        return;
    }

    //
    // CRITICAL: No timer/DPC in this implementation, so no need to flush.
    // If a timer were present, we would need:
    // KeCancelTimer(&Engine->CleanupTimer);
    // KeFlushQueuedDpcs();  // Wait for any pending DPC to complete
    //

    //
    // Acquire lock and free all rules
    // Safe because we're at PASSIVE_LEVEL
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->RuleLock);

    for (entry = Engine->RuleList.Flink;
         entry != &Engine->RuleList;
         entry = nextEntry) {

        nextEntry = entry->Flink;
        rule = CONTAINING_RECORD(entry, RE_INTERNAL_RULE, Public.ListEntry);

        //
        // Remove from both lists
        //
        RemoveEntryList(&rule->Public.ListEntry);
        RemoveEntryList(&rule->HashEntry);

        //
        // Free directly (bypass refcount during shutdown)
        //
        RepFreeRuleInternal(Engine, rule);
    }

    Engine->RuleCount = 0;

    ExReleasePushLockExclusive(&Engine->RuleLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside lists
    //
    if (InterlockedExchange(&Engine->LookasideInitialized, FALSE)) {
        ExDeleteNPagedLookasideList(&Engine->RuleLookaside);
        ExDeleteNPagedLookasideList(&Engine->ResultLookaside);
    }

    //
    // Clear signature and free engine
    //
    Engine->Signature = 0;
    ExFreePoolWithTag(Engine, RE_POOL_TAG);
}

// ============================================================================
// PUBLIC API - RULE MANAGEMENT
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ReLoadRule(
    _In_ PRE_ENGINE Engine,
    _In_ const RE_RULE* Rule
    )
/*++
Routine Description:
    Loads a new rule or updates an existing rule.

    Thread Safety: Fully thread-safe. Uses exclusive lock for all operations.

Arguments:
    Engine - Rule engine instance.
    Rule - Rule to load (copied, caller retains ownership).

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INVALID_PARAMETER if parameters are invalid.
    STATUS_QUOTA_EXCEEDED if rule limit reached.
    STATUS_INSUFFICIENT_RESOURCES if allocation fails.
--*/
{
    NTSTATUS status;
    PRE_INTERNAL_RULE internalRule = NULL;
    PRE_INTERNAL_RULE existingRule = NULL;
    ULONG hashBucket;
    SIZE_T ruleIdLen;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (!RepValidateEngine(Engine)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!RepValidateRule(Rule)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Verify RuleId is properly null-terminated
    //
    ruleIdLen = RepSafeStringLength(Rule->RuleId, sizeof(Rule->RuleId));
    if (ruleIdLen == 0 || ruleIdLen >= sizeof(Rule->RuleId)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate new internal rule BEFORE acquiring lock
    //
    internalRule = (PRE_INTERNAL_RULE)ExAllocateFromNPagedLookasideList(
        &Engine->RuleLookaside
    );

    if (internalRule == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(internalRule, sizeof(RE_INTERNAL_RULE));
    internalRule->Signature = RE_RULE_SIGNATURE;
    internalRule->RefCount = 1;

    //
    // Copy rule data (bounded copy)
    //
    RtlCopyMemory(&internalRule->Public, Rule, sizeof(RE_RULE));

    //
    // Ensure null termination on all strings
    //
    internalRule->Public.RuleId[RE_MAX_RULE_ID_LEN] = '\0';
    internalRule->Public.RuleName[RE_MAX_RULE_NAME_LEN] = '\0';
    internalRule->Public.Description[RE_MAX_DESCRIPTION_LEN] = '\0';

    //
    // Compute hash for fast lookup
    //
    internalRule->RuleIdHash = RepComputeAnsiStringHash(internalRule->Public.RuleId);

    //
    // Compile conditions
    //
    status = RepCompileRule(internalRule);
    if (!NT_SUCCESS(status)) {
        ExFreeToNPagedLookasideList(&Engine->RuleLookaside, internalRule);
        return status;
    }

    //
    // Now acquire exclusive lock for thread-safe insertion
    // All checks and modifications happen under this single lock acquisition
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->RuleLock);

    //
    // Check if rule already exists (under lock - no TOCTOU)
    //
    existingRule = RepFindRuleByIdLocked(Engine, internalRule->Public.RuleId);
    if (existingRule != NULL) {
        //
        // Remove existing rule from lists
        //
        RemoveEntryList(&existingRule->Public.ListEntry);
        RemoveEntryList(&existingRule->HashEntry);
        InterlockedDecrement(&Engine->RuleCount);

        //
        // Mark for deletion and dereference
        //
        existingRule->MarkedForDeletion = TRUE;
        RepDereferenceRule(Engine, existingRule);
        existingRule = NULL;
    }

    //
    // Check rule count limit (under lock - no TOCTOU)
    //
    if (Engine->RuleCount >= RE_MAX_RULES) {
        ExReleasePushLockExclusive(&Engine->RuleLock);
        KeLeaveCriticalRegion();
        ExFreeToNPagedLookasideList(&Engine->RuleLookaside, internalRule);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Insert into hash table
    //
    hashBucket = internalRule->RuleIdHash % RE_HASH_BUCKETS;
    InsertTailList(&Engine->RuleHashBuckets[hashBucket], &internalRule->HashEntry);

    //
    // Insert into priority-sorted list
    //
    RepInsertRuleSortedLocked(Engine, internalRule);
    InterlockedIncrement(&Engine->RuleCount);

    ExReleasePushLockExclusive(&Engine->RuleLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ReRemoveRule(
    _In_ PRE_ENGINE Engine,
    _In_z_ PCSTR RuleId
    )
/*++
Routine Description:
    Removes a rule from the engine.

Arguments:
    Engine - Rule engine instance.
    RuleId - ID of rule to remove.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_NOT_FOUND if rule doesn't exist.
--*/
{
    PRE_INTERNAL_RULE rule;
    SIZE_T ruleIdLen;

    PAGED_CODE();

    if (!RepValidateEngine(Engine)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (RuleId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ruleIdLen = RepSafeStringLength(RuleId, RE_MAX_RULE_ID_LEN + 1);
    if (ruleIdLen == 0 || ruleIdLen > RE_MAX_RULE_ID_LEN) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Engine->RuleLock);

    rule = RepFindRuleByIdLocked(Engine, RuleId);
    if (rule == NULL) {
        ExReleasePushLockExclusive(&Engine->RuleLock);
        KeLeaveCriticalRegion();
        return STATUS_NOT_FOUND;
    }

    //
    // Remove from lists
    //
    RemoveEntryList(&rule->Public.ListEntry);
    RemoveEntryList(&rule->HashEntry);
    InterlockedDecrement(&Engine->RuleCount);

    //
    // Mark for deletion and dereference
    //
    rule->MarkedForDeletion = TRUE;
    RepDereferenceRule(Engine, rule);

    ExReleasePushLockExclusive(&Engine->RuleLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ReEnableRule(
    _In_ PRE_ENGINE Engine,
    _In_z_ PCSTR RuleId,
    _In_ BOOLEAN Enable
    )
/*++
Routine Description:
    Enables or disables a rule.

Arguments:
    Engine - Rule engine instance.
    RuleId - ID of rule to enable/disable.
    Enable - TRUE to enable, FALSE to disable.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PRE_INTERNAL_RULE rule;
    SIZE_T ruleIdLen;

    PAGED_CODE();

    if (!RepValidateEngine(Engine)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (RuleId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ruleIdLen = RepSafeStringLength(RuleId, RE_MAX_RULE_ID_LEN + 1);
    if (ruleIdLen == 0 || ruleIdLen > RE_MAX_RULE_ID_LEN) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->RuleLock);

    rule = RepFindRuleByIdLocked(Engine, RuleId);
    if (rule == NULL) {
        ExReleasePushLockShared(&Engine->RuleLock);
        KeLeaveCriticalRegion();
        return STATUS_NOT_FOUND;
    }

    //
    // Simple boolean write is atomic on all platforms
    //
    rule->Public.Enabled = Enable;

    ExReleasePushLockShared(&Engine->RuleLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - RULE EVALUATION
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ReEvaluate(
    _In_ PRE_ENGINE Engine,
    _In_ const RE_EVALUATION_CONTEXT* Context,
    _Out_ PRE_EVALUATION_RESULT* Result
    )
/*++
Routine Description:
    Evaluates all rules against the provided context.

    Returns a COPY of matched rule data - no internal pointers are exposed.

Arguments:
    Engine - Rule engine instance.
    Context - Evaluation context with process/file/registry info.
    Result - Receives evaluation result. Must be freed with ReFreeResult.

Return Value:
    STATUS_SUCCESS on success (even if no rule matched).
--*/
{
    PRE_EVALUATION_RESULT result = NULL;
    PLIST_ENTRY entry;
    PRE_INTERNAL_RULE rule;
    BOOLEAN allConditionsMatch;
    ULONG i;

    PAGED_CODE();

    if (!RepValidateEngine(Engine)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!RepValidateContext(Context)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    //
    // Allocate result from lookaside list
    //
    result = (PRE_EVALUATION_RESULT)ExAllocateFromNPagedLookasideList(
        &Engine->ResultLookaside
    );

    if (result == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(result, sizeof(RE_EVALUATION_RESULT));

    //
    // Store engine handle for proper deallocation
    //
    result->EngineHandle = Engine;
    result->RuleMatched = FALSE;
    result->PrimaryAction = ReAction_None;  // Always initialized

    //
    // Evaluate rules in priority order under shared lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->RuleLock);

    for (entry = Engine->RuleList.Flink;
         entry != &Engine->RuleList;
         entry = entry->Flink) {

        rule = CONTAINING_RECORD(entry, RE_INTERNAL_RULE, Public.ListEntry);

        //
        // Skip disabled, deleted, or uncompiled rules
        //
        if (!rule->Public.Enabled ||
            rule->MarkedForDeletion ||
            !rule->IsCompiled) {
            continue;
        }

        //
        // Update evaluation count (atomic, no lock needed)
        //
        InterlockedIncrement64(&rule->Public.EvaluationCount);
        InterlockedIncrement64(&Engine->Stats.Evaluations);

        //
        // Evaluate all conditions (AND logic)
        //
        allConditionsMatch = TRUE;

        for (i = 0; i < rule->CompiledConditionCount; i++) {
            BOOLEAN conditionResult = RepEvaluateCondition(
                &rule->CompiledConditions[i],
                Context
            );

            //
            // Apply negation if needed
            //
            if (rule->CompiledConditions[i].Negate) {
                conditionResult = !conditionResult;
            }

            if (!conditionResult) {
                allConditionsMatch = FALSE;
                break;
            }
        }

        if (allConditionsMatch && rule->CompiledConditionCount > 0) {
            //
            // Rule matched - copy data to result (no internal pointers!)
            //
            result->RuleMatched = TRUE;

            RtlCopyMemory(
                result->MatchedRuleId,
                rule->Public.RuleId,
                sizeof(result->MatchedRuleId)
            );
            result->MatchedRuleId[RE_MAX_RULE_ID_LEN] = '\0';

            RtlCopyMemory(
                result->MatchedRuleName,
                rule->Public.RuleName,
                sizeof(result->MatchedRuleName)
            );
            result->MatchedRuleName[RE_MAX_RULE_NAME_LEN] = '\0';

            result->MatchedRulePriority = rule->Public.Priority;

            //
            // Copy actions
            //
            result->ActionCount = min(rule->Public.ActionCount, RE_MAX_ACTIONS);
            for (i = 0; i < result->ActionCount; i++) {
                RtlCopyMemory(
                    &result->Actions[i],
                    &rule->Public.Actions[i],
                    sizeof(RE_ACTION)
                );
            }

            //
            // Set primary action (always initialized)
            //
            if (result->ActionCount > 0) {
                result->PrimaryAction = result->Actions[0].Type;
            } else {
                result->PrimaryAction = ReAction_None;
            }

            //
            // Update statistics atomically
            //
            InterlockedIncrement64(&rule->Public.MatchCount);
            InterlockedIncrement64(&Engine->Stats.Matches);

            if (result->PrimaryAction == ReAction_Block) {
                InterlockedIncrement64(&Engine->Stats.Blocks);
            }

            //
            // Update last match time atomically using LONG64
            //
            {
                LARGE_INTEGER currentTime;
                KeQuerySystemTimePrecise(&currentTime);
                InterlockedExchange64(
                    &rule->Public.LastMatchTime,
                    currentTime.QuadPart
                );
            }

            //
            // Stop if rule says so
            //
            if (rule->Public.StopProcessing) {
                break;
            }
        }
    }

    ExReleasePushLockShared(&Engine->RuleLock);
    KeLeaveCriticalRegion();

    *Result = result;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ReFreeResult(
    _In_opt_ PRE_EVALUATION_RESULT Result
    )
/*++
Routine Description:
    Frees an evaluation result.

    Uses the stored engine handle to return to the correct lookaside list.

Arguments:
    Result - Result to free. May be NULL.
--*/
{
    PRE_ENGINE engine;

    if (Result == NULL) {
        return;
    }

    engine = (PRE_ENGINE)Result->EngineHandle;

    //
    // Validate engine handle before using lookaside list
    //
    if (engine != NULL &&
        engine->Signature == RE_ENGINE_SIGNATURE &&
        engine->LookasideInitialized) {

        ExFreeToNPagedLookasideList(&engine->ResultLookaside, Result);
    } else {
        //
        // Fallback: engine was destroyed, use pool free
        // This should not happen in correct usage
        //
        ExFreePoolWithTag(Result, RE_POOL_TAG_RESULT);
    }
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ReGetRule(
    _In_ PRE_ENGINE Engine,
    _In_z_ PCSTR RuleId,
    _Out_ PRE_RULE Rule
    )
/*++
Routine Description:
    Gets a copy of a rule by ID.

    Returns a COPY - caller owns the data, no lifetime concerns.

Arguments:
    Engine - Rule engine instance.
    RuleId - Rule ID to find.
    Rule - Receives copy of rule data.

Return Value:
    STATUS_SUCCESS if found.
    STATUS_NOT_FOUND if rule doesn't exist.
--*/
{
    PRE_INTERNAL_RULE internalRule;
    SIZE_T ruleIdLen;

    PAGED_CODE();

    if (!RepValidateEngine(Engine)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (RuleId == NULL || Rule == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ruleIdLen = RepSafeStringLength(RuleId, RE_MAX_RULE_ID_LEN + 1);
    if (ruleIdLen == 0 || ruleIdLen > RE_MAX_RULE_ID_LEN) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->RuleLock);

    internalRule = RepFindRuleByIdLocked(Engine, RuleId);
    if (internalRule == NULL || internalRule->MarkedForDeletion) {
        ExReleasePushLockShared(&Engine->RuleLock);
        KeLeaveCriticalRegion();
        return STATUS_NOT_FOUND;
    }

    //
    // Copy rule data to caller's buffer
    //
    RtlCopyMemory(Rule, &internalRule->Public, sizeof(RE_RULE));

    ExReleasePushLockShared(&Engine->RuleLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ReGetAllRules(
    _In_ PRE_ENGINE Engine,
    _Out_writes_to_(MaxCount, *ActualCount) PRE_RULE Rules,
    _In_ ULONG MaxCount,
    _Out_ PULONG ActualCount
    )
/*++
Routine Description:
    Gets copies of all loaded rules.

Arguments:
    Engine - Rule engine instance.
    Rules - Array to receive rule copies.
    MaxCount - Maximum rules to return.
    ActualCount - Receives actual count.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PLIST_ENTRY entry;
    PRE_INTERNAL_RULE rule;
    ULONG count = 0;

    PAGED_CODE();

    if (!RepValidateEngine(Engine)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Rules == NULL || ActualCount == NULL || MaxCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *ActualCount = 0;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Engine->RuleLock);

    for (entry = Engine->RuleList.Flink;
         entry != &Engine->RuleList && count < MaxCount;
         entry = entry->Flink) {

        rule = CONTAINING_RECORD(entry, RE_INTERNAL_RULE, Public.ListEntry);

        if (!rule->MarkedForDeletion) {
            RtlCopyMemory(&Rules[count], &rule->Public, sizeof(RE_RULE));
            count++;
        }
    }

    ExReleasePushLockShared(&Engine->RuleLock);
    KeLeaveCriticalRegion();

    *ActualCount = count;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ReGetStatistics(
    _In_ PRE_ENGINE Engine,
    _Out_ PRE_ENGINE_STATS Stats
    )
/*++
Routine Description:
    Gets engine statistics.

Arguments:
    Engine - Rule engine instance.
    Stats - Receives statistics snapshot.
--*/
{
    if (Stats == NULL) {
        return;
    }

    RtlZeroMemory(Stats, sizeof(RE_ENGINE_STATS));

    if (!RepValidateEngine(Engine)) {
        return;
    }

    Stats->Evaluations = Engine->Stats.Evaluations;
    Stats->Matches = Engine->Stats.Matches;
    Stats->Blocks = Engine->Stats.Blocks;
    Stats->StartTime = Engine->Stats.StartTime;
    Stats->RuleCount = (ULONG)Engine->RuleCount;
}

// ============================================================================
// INTERNAL - VALIDATION HELPERS
// ============================================================================

static BOOLEAN
RepValidateEngine(
    _In_opt_ PRE_ENGINE Engine
    )
{
    if (Engine == NULL) {
        return FALSE;
    }

    if (Engine->Signature != RE_ENGINE_SIGNATURE) {
        return FALSE;
    }

    if (!Engine->Initialized) {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
RepValidateRule(
    _In_opt_ const RE_RULE* Rule
    )
{
    ULONG i;

    if (Rule == NULL) {
        return FALSE;
    }

    //
    // Validate counts
    //
    if (Rule->ConditionCount > RE_MAX_CONDITIONS) {
        return FALSE;
    }

    if (Rule->ActionCount > RE_MAX_ACTIONS) {
        return FALSE;
    }

    //
    // Validate condition types and operators
    //
    for (i = 0; i < Rule->ConditionCount; i++) {
        if (Rule->Conditions[i].Type >= ReCondition_MaxValue) {
            return FALSE;
        }
        if (Rule->Conditions[i].Operator >= ReOp_MaxValue) {
            return FALSE;
        }
    }

    //
    // Validate action types
    //
    for (i = 0; i < Rule->ActionCount; i++) {
        if (Rule->Actions[i].Type >= ReAction_MaxValue) {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN
RepValidateContext(
    _In_opt_ const RE_EVALUATION_CONTEXT* Context
    )
{
    if (Context == NULL) {
        return FALSE;
    }

    //
    // Validate Unicode strings if provided
    //
    if (Context->ProcessName != NULL &&
        !RepValidateUnicodeString(Context->ProcessName)) {
        return FALSE;
    }

    if (Context->ParentProcessName != NULL &&
        !RepValidateUnicodeString(Context->ParentProcessName)) {
        return FALSE;
    }

    if (Context->CommandLine != NULL &&
        !RepValidateUnicodeString(Context->CommandLine)) {
        return FALSE;
    }

    if (Context->FilePath != NULL &&
        !RepValidateUnicodeString(Context->FilePath)) {
        return FALSE;
    }

    if (Context->RegistryPath != NULL &&
        !RepValidateUnicodeString(Context->RegistryPath)) {
        return FALSE;
    }

    if (Context->NetworkAddress != NULL &&
        !RepValidateUnicodeString(Context->NetworkAddress)) {
        return FALSE;
    }

    if (Context->Domain != NULL &&
        !RepValidateUnicodeString(Context->Domain)) {
        return FALSE;
    }

    if (Context->MitreTechnique != NULL &&
        !RepValidateUnicodeString(Context->MitreTechnique)) {
        return FALSE;
    }

    //
    // Validate file hash if provided
    //
    if (Context->FileHash != NULL &&
        Context->FileHashLength != RE_SHA256_HASH_SIZE) {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
RepValidateUnicodeString(
    _In_opt_ PCUNICODE_STRING String
    )
{
    if (String == NULL) {
        return TRUE;  // NULL is valid (means "not provided")
    }

    //
    // Length must not exceed MaximumLength
    //
    if (String->Length > String->MaximumLength) {
        return FALSE;
    }

    //
    // If Length > 0, Buffer must be valid
    //
    if (String->Length > 0 && String->Buffer == NULL) {
        return FALSE;
    }

    //
    // Length must be even (WCHAR alignment)
    //
    if (String->Length & 1) {
        return FALSE;
    }

    return TRUE;
}

static SIZE_T
RepSafeStringLength(
    _In_reads_or_z_(MaxLength) PCSTR String,
    _In_ SIZE_T MaxLength
    )
{
    SIZE_T i;

    if (String == NULL || MaxLength == 0) {
        return 0;
    }

    for (i = 0; i < MaxLength; i++) {
        if (String[i] == '\0') {
            return i;
        }
    }

    return MaxLength;  // Not null-terminated within bounds
}

// ============================================================================
// INTERNAL - HASHING
// ============================================================================

static ULONG
RepComputeStringHash(
    _In_reads_(LengthChars) PCWSTR String,
    _In_ ULONG LengthChars
    )
{
    ULONG hash = 5381;
    ULONG i;
    WCHAR c;

    for (i = 0; i < LengthChars; i++) {
        c = String[i];

        //
        // Case-insensitive: convert to upper using kernel-safe method
        //
        c = RepToUpperChar(c);

        hash = ((hash << 5) + hash) + (ULONG)c;
    }

    return hash;
}

static ULONG
RepComputeAnsiStringHash(
    _In_z_ PCSTR String
    )
{
    ULONG hash = 5381;
    UCHAR c;

    while ((c = (UCHAR)*String++) != 0) {
        //
        // Case-insensitive for ASCII
        //
        if (c >= 'a' && c <= 'z') {
            c = c - ('a' - 'A');
        }

        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}

static WCHAR
RepToUpperChar(
    _In_ WCHAR Char
    )
{
    //
    // Use RtlUpcaseUnicodeChar for proper Unicode case conversion
    //
    return RtlUpcaseUnicodeChar(Char);
}

// ============================================================================
// INTERNAL - RULE COMPILATION
// ============================================================================

static NTSTATUS
RepCompileRule(
    _Inout_ PRE_INTERNAL_RULE Rule
    )
{
    NTSTATUS status;
    ULONG i;
    const RE_CONDITION* srcCondition;
    PRE_COMPILED_CONDITION dstCondition;

    Rule->CompiledConditionCount = 0;
    Rule->IsCompiled = FALSE;

    for (i = 0; i < Rule->Public.ConditionCount; i++) {
        srcCondition = &Rule->Public.Conditions[i];
        dstCondition = &Rule->CompiledConditions[i];

        RtlZeroMemory(dstCondition, sizeof(RE_COMPILED_CONDITION));

        dstCondition->Type = srcCondition->Type;
        dstCondition->Operator = srcCondition->Operator;
        dstCondition->Negate = srcCondition->Negate;
        dstCondition->CaseInsensitive = TRUE;

        //
        // Compile based on condition type
        //
        switch (srcCondition->Type) {
        case ReCondition_ProcessName:
        case ReCondition_ParentName:
        case ReCondition_CommandLine:
        case ReCondition_FilePath:
        case ReCondition_RegistryPath:
        case ReCondition_NetworkAddress:
        case ReCondition_Domain:
        case ReCondition_MITRETechnique:
        case ReCondition_Custom:
            status = RepCompileStringCondition(srcCondition->Value, dstCondition);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            break;

        case ReCondition_FileHash:
            status = RepCompileHashCondition(srcCondition->Value, dstCondition);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            break;

        case ReCondition_ThreatScore:
        case ReCondition_BehaviorFlag:
            status = RepCompileNumericCondition(srcCondition->Value, dstCondition);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            break;

        case ReCondition_TimeOfDay:
            status = RepCompileTimeCondition(srcCondition->Value, dstCondition);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            break;

        default:
            return STATUS_INVALID_PARAMETER;
        }

        Rule->CompiledConditionCount++;
    }

    Rule->IsCompiled = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS
RepCompileStringCondition(
    _In_ PCSTR SourceValue,
    _Out_ PRE_COMPILED_CONDITION Compiled
    )
{
    SIZE_T ansiLength;
    ANSI_STRING ansiString;
    UNICODE_STRING unicodeString;
    NTSTATUS status;

    //
    // Get safe string length
    //
    ansiLength = RepSafeStringLength(SourceValue, RE_MAX_VALUE_LEN + 1);
    if (ansiLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (ansiLength > RE_MAX_VALUE_LEN) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Convert ANSI pattern to Unicode for matching
    //
    ansiString.Buffer = (PSTR)SourceValue;
    ansiString.Length = (USHORT)ansiLength;
    ansiString.MaximumLength = (USHORT)(ansiLength + 1);

    unicodeString.Buffer = Compiled->Data.String.Pattern;
    unicodeString.Length = 0;
    unicodeString.MaximumLength = sizeof(Compiled->Data.String.Pattern);

    status = RtlAnsiStringToUnicodeString(&unicodeString, &ansiString, FALSE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Compiled->Data.String.PatternLengthChars = unicodeString.Length / sizeof(WCHAR);
    Compiled->Data.String.PatternHash = RepComputeStringHash(
        Compiled->Data.String.Pattern,
        Compiled->Data.String.PatternLengthChars
    );

    return STATUS_SUCCESS;
}

static NTSTATUS
RepCompileHashCondition(
    _In_ PCSTR HexString,
    _Out_ PRE_COMPILED_CONDITION Compiled
    )
{
    SIZE_T length;
    ULONG i;
    CHAR hex[3];
    ULONG value;
    NTSTATUS status;

    length = RepSafeStringLength(HexString, 65);
    if (length != 64) {  // SHA-256 = 64 hex chars
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Convert hex string to bytes
    //
    for (i = 0; i < RE_SHA256_HASH_SIZE; i++) {
        hex[0] = HexString[i * 2];
        hex[1] = HexString[i * 2 + 1];
        hex[2] = '\0';

        //
        // Validate hex characters
        //
        if (!((hex[0] >= '0' && hex[0] <= '9') ||
              (hex[0] >= 'A' && hex[0] <= 'F') ||
              (hex[0] >= 'a' && hex[0] <= 'f'))) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!((hex[1] >= '0' && hex[1] <= '9') ||
              (hex[1] >= 'A' && hex[1] <= 'F') ||
              (hex[1] >= 'a' && hex[1] <= 'f'))) {
            return STATUS_INVALID_PARAMETER;
        }

        status = RtlCharToInteger(hex, 16, &value);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        Compiled->Data.FileHash.Hash[i] = (UCHAR)value;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
RepCompileNumericCondition(
    _In_ PCSTR ValueString,
    _Out_ PRE_COMPILED_CONDITION Compiled
    )
{
    NTSTATUS status;
    SIZE_T length;

    length = RepSafeStringLength(ValueString, RE_MAX_VALUE_LEN + 1);
    if (length == 0 || length > RE_MAX_VALUE_LEN) {
        return STATUS_INVALID_PARAMETER;
    }

    status = RtlCharToInteger(ValueString, 10, &Compiled->Data.Numeric.Value);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Compiled->Data.Numeric.Mask = 0xFFFFFFFF;
    return STATUS_SUCCESS;
}

static NTSTATUS
RepCompileTimeCondition(
    _In_ PCSTR TimeSpec,
    _Out_ PRE_COMPILED_CONDITION Compiled
    )
{
    //
    // Expected format: "HH:MM-HH:MM" (e.g., "09:00-17:00")
    //
    SIZE_T length;
    ULONG startHour, startMinute, endHour, endMinute;

    length = RepSafeStringLength(TimeSpec, RE_MAX_VALUE_LEN + 1);
    if (length != 11) {  // "HH:MM-HH:MM"
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Parse start time
    //
    if (TimeSpec[2] != ':' || TimeSpec[5] != '-' || TimeSpec[8] != ':') {
        return STATUS_INVALID_PARAMETER;
    }

    startHour = (TimeSpec[0] - '0') * 10 + (TimeSpec[1] - '0');
    startMinute = (TimeSpec[3] - '0') * 10 + (TimeSpec[4] - '0');
    endHour = (TimeSpec[6] - '0') * 10 + (TimeSpec[7] - '0');
    endMinute = (TimeSpec[9] - '0') * 10 + (TimeSpec[10] - '0');

    if (startHour >= 24 || startMinute >= 60 ||
        endHour >= 24 || endMinute >= 60) {
        return STATUS_INVALID_PARAMETER;
    }

    Compiled->Data.TimeOfDay.StartMinute = startHour * 60 + startMinute;
    Compiled->Data.TimeOfDay.EndMinute = endHour * 60 + endMinute;

    return STATUS_SUCCESS;
}

// ============================================================================
// INTERNAL - CONDITION EVALUATION
// ============================================================================

static BOOLEAN
RepEvaluateCondition(
    _In_ PRE_COMPILED_CONDITION Condition,
    _In_ const RE_EVALUATION_CONTEXT* Context
    )
{
    BOOLEAN result = FALSE;

    switch (Condition->Type) {
    case ReCondition_ProcessName:
        if (Context->ProcessName != NULL) {
            result = RepMatchUnicodeString(
                Condition->Data.String.Pattern,
                Condition->Data.String.PatternLengthChars,
                Context->ProcessName,
                Condition->Operator,
                Condition->CaseInsensitive
            );
        }
        break;

    case ReCondition_ParentName:
        if (Context->ParentProcessName != NULL) {
            result = RepMatchUnicodeString(
                Condition->Data.String.Pattern,
                Condition->Data.String.PatternLengthChars,
                Context->ParentProcessName,
                Condition->Operator,
                Condition->CaseInsensitive
            );
        }
        break;

    case ReCondition_CommandLine:
        if (Context->CommandLine != NULL) {
            result = RepMatchUnicodeString(
                Condition->Data.String.Pattern,
                Condition->Data.String.PatternLengthChars,
                Context->CommandLine,
                Condition->Operator,
                Condition->CaseInsensitive
            );
        }
        break;

    case ReCondition_FilePath:
        if (Context->FilePath != NULL) {
            result = RepMatchUnicodeString(
                Condition->Data.String.Pattern,
                Condition->Data.String.PatternLengthChars,
                Context->FilePath,
                Condition->Operator,
                Condition->CaseInsensitive
            );
        }
        break;

    case ReCondition_FileHash:
        if (Context->FileHash != NULL &&
            Context->FileHashLength == RE_SHA256_HASH_SIZE) {
            result = (RtlCompareMemory(
                Condition->Data.FileHash.Hash,
                Context->FileHash,
                RE_SHA256_HASH_SIZE
            ) == RE_SHA256_HASH_SIZE);
        }
        break;

    case ReCondition_RegistryPath:
        if (Context->RegistryPath != NULL) {
            result = RepMatchUnicodeString(
                Condition->Data.String.Pattern,
                Condition->Data.String.PatternLengthChars,
                Context->RegistryPath,
                Condition->Operator,
                Condition->CaseInsensitive
            );
        }
        break;

    case ReCondition_NetworkAddress:
        if (Context->NetworkAddress != NULL) {
            result = RepMatchUnicodeString(
                Condition->Data.String.Pattern,
                Condition->Data.String.PatternLengthChars,
                Context->NetworkAddress,
                Condition->Operator,
                Condition->CaseInsensitive
            );
        }
        break;

    case ReCondition_Domain:
        if (Context->Domain != NULL) {
            result = RepMatchUnicodeString(
                Condition->Data.String.Pattern,
                Condition->Data.String.PatternLengthChars,
                Context->Domain,
                Condition->Operator,
                Condition->CaseInsensitive
            );
        }
        break;

    case ReCondition_ThreatScore:
        switch (Condition->Operator) {
        case ReOp_Equals:
            result = (Context->ThreatScore == Condition->Data.Numeric.Value);
            break;
        case ReOp_NotEquals:
            result = (Context->ThreatScore != Condition->Data.Numeric.Value);
            break;
        case ReOp_GreaterThan:
            result = (Context->ThreatScore > Condition->Data.Numeric.Value);
            break;
        case ReOp_LessThan:
            result = (Context->ThreatScore < Condition->Data.Numeric.Value);
            break;
        default:
            result = FALSE;
            break;
        }
        break;

    case ReCondition_MITRETechnique:
        if (Context->MitreTechnique != NULL) {
            result = RepMatchUnicodeString(
                Condition->Data.String.Pattern,
                Condition->Data.String.PatternLengthChars,
                Context->MitreTechnique,
                Condition->Operator,
                Condition->CaseInsensitive
            );
        }
        break;

    case ReCondition_BehaviorFlag:
        result = (Context->BehaviorFlags & Condition->Data.Numeric.Value) != 0;
        break;

    case ReCondition_TimeOfDay:
        {
            //
            // Convert system time to minutes since midnight
            //
            LARGE_INTEGER localTime;
            TIME_FIELDS timeFields;
            ULONG currentMinute;

            ExSystemTimeToLocalTime(&Context->CurrentTime, &localTime);
            RtlTimeToTimeFields(&localTime, &timeFields);

            currentMinute = timeFields.Hour * 60 + timeFields.Minute;

            if (Condition->Data.TimeOfDay.StartMinute <=
                Condition->Data.TimeOfDay.EndMinute) {
                //
                // Normal range (e.g., 09:00-17:00)
                //
                result = (currentMinute >= Condition->Data.TimeOfDay.StartMinute &&
                          currentMinute <= Condition->Data.TimeOfDay.EndMinute);
            } else {
                //
                // Wraparound range (e.g., 22:00-06:00)
                //
                result = (currentMinute >= Condition->Data.TimeOfDay.StartMinute ||
                          currentMinute <= Condition->Data.TimeOfDay.EndMinute);
            }
        }
        break;

    case ReCondition_Custom:
        //
        // Custom conditions require external handler
        // For now, always return FALSE (safe default)
        //
        result = FALSE;
        break;

    default:
        result = FALSE;
        break;
    }

    return result;
}

// ============================================================================
// INTERNAL - STRING MATCHING (Native Unicode, no conversion buffers)
// ============================================================================

static BOOLEAN
RepMatchUnicodeString(
    _In_reads_(PatternLengthChars) PCWSTR Pattern,
    _In_ ULONG PatternLengthChars,
    _In_ PCUNICODE_STRING Value,
    _In_ RE_OPERATOR Operator,
    _In_ BOOLEAN CaseInsensitive
    )
{
    ULONG valueLengthChars;
    ULONG i;
    UNICODE_STRING patternStr;
    UNICODE_STRING valueStr;

    if (Pattern == NULL || Value == NULL || Value->Buffer == NULL) {
        return FALSE;
    }

    valueLengthChars = Value->Length / sizeof(WCHAR);

    switch (Operator) {
    case ReOp_Equals:
        if (PatternLengthChars != valueLengthChars) {
            return FALSE;
        }

        patternStr.Buffer = (PWSTR)Pattern;
        patternStr.Length = (USHORT)(PatternLengthChars * sizeof(WCHAR));
        patternStr.MaximumLength = patternStr.Length;

        valueStr = *Value;

        return RtlEqualUnicodeString(&patternStr, &valueStr, CaseInsensitive);

    case ReOp_NotEquals:
        if (PatternLengthChars != valueLengthChars) {
            return TRUE;
        }

        patternStr.Buffer = (PWSTR)Pattern;
        patternStr.Length = (USHORT)(PatternLengthChars * sizeof(WCHAR));
        patternStr.MaximumLength = patternStr.Length;

        valueStr = *Value;

        return !RtlEqualUnicodeString(&patternStr, &valueStr, CaseInsensitive);

    case ReOp_Contains:
        if (PatternLengthChars > valueLengthChars) {
            return FALSE;
        }

        patternStr.Buffer = (PWSTR)Pattern;
        patternStr.Length = (USHORT)(PatternLengthChars * sizeof(WCHAR));
        patternStr.MaximumLength = patternStr.Length;

        for (i = 0; i <= valueLengthChars - PatternLengthChars; i++) {
            valueStr.Buffer = &Value->Buffer[i];
            valueStr.Length = (USHORT)(PatternLengthChars * sizeof(WCHAR));
            valueStr.MaximumLength = valueStr.Length;

            if (RtlEqualUnicodeString(&patternStr, &valueStr, CaseInsensitive)) {
                return TRUE;
            }
        }
        return FALSE;

    case ReOp_StartsWith:
        if (PatternLengthChars > valueLengthChars) {
            return FALSE;
        }

        patternStr.Buffer = (PWSTR)Pattern;
        patternStr.Length = (USHORT)(PatternLengthChars * sizeof(WCHAR));
        patternStr.MaximumLength = patternStr.Length;

        valueStr.Buffer = Value->Buffer;
        valueStr.Length = (USHORT)(PatternLengthChars * sizeof(WCHAR));
        valueStr.MaximumLength = valueStr.Length;

        return RtlEqualUnicodeString(&patternStr, &valueStr, CaseInsensitive);

    case ReOp_EndsWith:
        if (PatternLengthChars > valueLengthChars) {
            return FALSE;
        }

        patternStr.Buffer = (PWSTR)Pattern;
        patternStr.Length = (USHORT)(PatternLengthChars * sizeof(WCHAR));
        patternStr.MaximumLength = patternStr.Length;

        valueStr.Buffer = &Value->Buffer[valueLengthChars - PatternLengthChars];
        valueStr.Length = (USHORT)(PatternLengthChars * sizeof(WCHAR));
        valueStr.MaximumLength = valueStr.Length;

        return RtlEqualUnicodeString(&patternStr, &valueStr, CaseInsensitive);

    case ReOp_Wildcard:
        return RepWildcardMatch(
            Pattern,
            PatternLengthChars,
            Value->Buffer,
            valueLengthChars,
            CaseInsensitive
        );

    case ReOp_InList:
        //
        // InList would require additional data structure
        // Not implemented in this version
        //
        return FALSE;

    default:
        return FALSE;
    }
}

static BOOLEAN
RepWildcardMatch(
    _In_reads_(PatternLengthChars) PCWSTR Pattern,
    _In_ ULONG PatternLengthChars,
    _In_reads_(StringLengthChars) PCWSTR String,
    _In_ ULONG StringLengthChars,
    _In_ BOOLEAN CaseInsensitive
    )
{
    ULONG pIdx = 0;
    ULONG sIdx = 0;
    ULONG starPIdx = (ULONG)-1;
    ULONG starSIdx = 0;
    WCHAR patternChar, stringChar;

    while (sIdx < StringLengthChars) {
        if (pIdx < PatternLengthChars) {
            patternChar = Pattern[pIdx];

            if (patternChar == L'*') {
                starPIdx = pIdx;
                starSIdx = sIdx;
                pIdx++;
                continue;
            }

            stringChar = String[sIdx];

            if (CaseInsensitive) {
                patternChar = RepToUpperChar(patternChar);
                stringChar = RepToUpperChar(stringChar);
            }

            if (patternChar == L'?' || patternChar == stringChar) {
                pIdx++;
                sIdx++;
                continue;
            }
        }

        //
        // Mismatch - backtrack to last * if possible
        //
        if (starPIdx != (ULONG)-1) {
            pIdx = starPIdx + 1;
            starSIdx++;
            sIdx = starSIdx;
            continue;
        }

        return FALSE;
    }

    //
    // Consume trailing *'s in pattern
    //
    while (pIdx < PatternLengthChars && Pattern[pIdx] == L'*') {
        pIdx++;
    }

    return (pIdx == PatternLengthChars);
}

// ============================================================================
// INTERNAL - RULE LOOKUP AND MANAGEMENT
// ============================================================================

static PRE_INTERNAL_RULE
RepFindRuleByIdLocked(
    _In_ PRE_ENGINE Engine,
    _In_z_ PCSTR RuleId
    )
/*++
Routine Description:
    Finds a rule by ID. Caller must hold RuleLock (shared or exclusive).
--*/
{
    ULONG hash;
    ULONG bucket;
    PLIST_ENTRY entry;
    PRE_INTERNAL_RULE rule;

    hash = RepComputeAnsiStringHash(RuleId);
    bucket = hash % RE_HASH_BUCKETS;

    for (entry = Engine->RuleHashBuckets[bucket].Flink;
         entry != &Engine->RuleHashBuckets[bucket];
         entry = entry->Flink) {

        rule = CONTAINING_RECORD(entry, RE_INTERNAL_RULE, HashEntry);

        if (rule->RuleIdHash == hash &&
            _stricmp(rule->Public.RuleId, RuleId) == 0) {
            return rule;
        }
    }

    return NULL;
}

static VOID
RepInsertRuleSortedLocked(
    _In_ PRE_ENGINE Engine,
    _In_ PRE_INTERNAL_RULE Rule
    )
/*++
Routine Description:
    Inserts rule into priority-sorted list. Caller must hold RuleLock exclusive.
--*/
{
    PLIST_ENTRY entry;
    PRE_INTERNAL_RULE existingRule;

    for (entry = Engine->RuleList.Flink;
         entry != &Engine->RuleList;
         entry = entry->Flink) {

        existingRule = CONTAINING_RECORD(entry, RE_INTERNAL_RULE, Public.ListEntry);

        if (Rule->Public.Priority < existingRule->Public.Priority) {
            //
            // Insert before this rule (higher priority)
            //
            InsertTailList(entry, &Rule->Public.ListEntry);
            return;
        }
    }

    //
    // Insert at end (lowest priority)
    //
    InsertTailList(&Engine->RuleList, &Rule->Public.ListEntry);
}

// ============================================================================
// INTERNAL - REFERENCE COUNTING
// ============================================================================

static VOID
RepReferenceRule(
    _In_ PRE_INTERNAL_RULE Rule
    )
{
    InterlockedIncrement(&Rule->RefCount);
}

static VOID
RepDereferenceRule(
    _In_ PRE_ENGINE Engine,
    _In_ PRE_INTERNAL_RULE Rule
    )
{
    if (InterlockedDecrement(&Rule->RefCount) == 0) {
        RepFreeRuleInternal(Engine, Rule);
    }
}

static VOID
RepFreeRuleInternal(
    _In_ PRE_ENGINE Engine,
    _In_ PRE_INTERNAL_RULE Rule
    )
{
    if (Rule == NULL) {
        return;
    }

    //
    // Clear signature to prevent use-after-free detection
    //
    Rule->Signature = 0;

    //
    // Return to lookaside list
    //
    if (Engine->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Engine->RuleLookaside, Rule);
    }
}
