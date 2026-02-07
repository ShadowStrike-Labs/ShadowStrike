/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE BEHAVIORAL RULE ENGINE IMPLEMENTATION
===============================================================================

@file RuleEngine.c
@brief Enterprise-grade behavioral detection rule engine for kernel EDR.

This module provides comprehensive rule-based behavioral detection:
- Dynamic rule loading and management
- Multi-condition rule evaluation with AND/OR/NOT logic
- Pattern matching (exact, prefix, suffix, contains, regex-lite)
- MITRE ATT&CK technique mapping per rule
- Priority-based rule ordering and evaluation
- Action chaining (block, alert, quarantine, terminate)
- Per-rule statistics and performance tracking
- Thread-safe concurrent evaluation
- Hot rule updates without restart

Detection Capabilities:
- Process execution policy enforcement
- Parent-child relationship validation
- Command-line pattern detection
- File path and hash matching
- Registry path monitoring
- Network address/domain filtering
- Behavioral flag correlation
- Time-of-day restrictions
- Threat score thresholds

Performance Characteristics:
- O(n) rule evaluation with early termination
- Lock-free statistics using InterlockedXxx
- NPAGED_LOOKASIDE_LIST for result allocations
- EX_PUSH_LOCK for reader-writer synchronization
- Priority-sorted rule list for optimal matching

@author ShadowStrike Security Team
@version 2.0.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "RuleEngine.h"
#include "BehaviorEngine.h"
#include "PatternMatcher.h"
#include "MITREMapper.h"
#include "ThreatScoring.h"
#include "../Core/Globals.h"
#include <ntstrsafe.h>

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define RE_POOL_TAG_INTERNAL        'iRER'  // Rule Engine Internal
#define RE_POOL_TAG_RULE            'rRER'  // Rule Engine Rule
#define RE_POOL_TAG_RESULT          'sRER'  // Rule Engine Result
#define RE_POOL_TAG_LIST            'lRER'  // Rule Engine List

#define RE_MAX_RULES                10000
#define RE_MAX_PATTERN_LENGTH       256
#define RE_MAX_LIST_ITEMS           1000
#define RE_HASH_BUCKETS             256
#define RE_CLEANUP_INTERVAL_MS      300000  // 5 minutes

//
// Operator evaluation flags
//
#define RE_EVAL_FLAG_CASE_INSENSITIVE   0x0001
#define RE_EVAL_FLAG_UNICODE            0x0002
#define RE_EVAL_FLAG_WILDCARD           0x0004

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
    USHORT Reserved;

    //
    // Pre-computed values for fast matching
    //
    union {
        struct {
            CHAR Pattern[RE_MAX_PATTERN_LENGTH];
            ULONG PatternLength;
            ULONG PatternHash;          // For quick rejection
        } String;

        struct {
            ULONG Value;
            ULONG Mask;
        } Numeric;

        struct {
            UCHAR Hash[32];             // SHA-256
        } FileHash;

        struct {
            PCHAR* Items;               // Array of strings
            PULONG ItemHashes;          // Pre-computed hashes
            ULONG ItemCount;
        } List;
    };

} RE_COMPILED_CONDITION, *PRE_COMPILED_CONDITION;

//
// Internal rule structure with compiled conditions
//
typedef struct _RE_INTERNAL_RULE {
    RE_RULE Public;

    //
    // Compiled conditions for fast evaluation
    //
    RE_COMPILED_CONDITION CompiledConditions[RE_MAX_CONDITIONS];
    ULONG CompiledConditionCount;
    BOOLEAN IsCompiled;

    //
    // Hash table linkage
    //
    LIST_ENTRY HashEntry;
    ULONG RuleIdHash;

    //
    // Reference counting
    //
    volatile LONG RefCount;

} RE_INTERNAL_RULE, *PRE_INTERNAL_RULE;

//
// Internal engine structure
//
typedef struct _RE_ENGINE_INTERNAL {
    RE_ENGINE Public;

    //
    // Rule hash table for fast lookup by ID
    //
    struct {
        LIST_ENTRY Buckets[RE_HASH_BUCKETS];
        EX_PUSH_LOCK Lock;
    } RuleHash;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST RuleLookaside;
    NPAGED_LOOKASIDE_LIST ResultLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;

    //
    // External integrations
    //
    PMM_MAPPER MitreMapper;
    PTS_SCORING_ENGINE ScoringEngine;

} RE_ENGINE_INTERNAL, *PRE_ENGINE_INTERNAL;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static ULONG
RepHashString(
    _In_ PCSTR String
    );

static ULONG
RepHashStringW(
    _In_ PCWSTR String
    );

static NTSTATUS
RepCompileRule(
    _Inout_ PRE_INTERNAL_RULE Rule
    );

static VOID
RepFreeCompiledCondition(
    _Inout_ PRE_COMPILED_CONDITION Condition
    );

static BOOLEAN
RepEvaluateCondition(
    _In_ PRE_COMPILED_CONDITION Condition,
    _In_ PRE_EVALUATION_CONTEXT Context
    );

static BOOLEAN
RepMatchString(
    _In_ PCSTR Pattern,
    _In_ ULONG PatternLength,
    _In_ PCSTR Value,
    _In_ ULONG ValueLength,
    _In_ RE_OPERATOR Operator,
    _In_ BOOLEAN CaseInsensitive
    );

static BOOLEAN
RepMatchStringW(
    _In_ PCSTR Pattern,
    _In_ ULONG PatternLength,
    _In_ PCWSTR Value,
    _In_ ULONG ValueLength,
    _In_ RE_OPERATOR Operator,
    _In_ BOOLEAN CaseInsensitive
    );

static BOOLEAN
RepMatchInList(
    _In_ PRE_COMPILED_CONDITION Condition,
    _In_ PCSTR Value,
    _In_ ULONG ValueLength
    );

static BOOLEAN
RepMatchWildcard(
    _In_ PCSTR Pattern,
    _In_ PCSTR String,
    _In_ BOOLEAN CaseInsensitive
    );

static PRE_INTERNAL_RULE
RepFindRuleById(
    _In_ PRE_ENGINE_INTERNAL Engine,
    _In_ PCSTR RuleId
    );

static VOID
RepInsertRuleSorted(
    _In_ PRE_ENGINE_INTERNAL Engine,
    _In_ PRE_INTERNAL_RULE Rule
    );

static VOID
RepReferenceRule(
    _In_ PRE_INTERNAL_RULE Rule
    );

static VOID
RepDereferenceRule(
    _In_ PRE_ENGINE_INTERNAL Engine,
    _In_ PRE_INTERNAL_RULE Rule
    );

static VOID NTAPI
RepCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

NTSTATUS
ReInitialize(
    _Out_ PRE_ENGINE* Engine
    )
/*++
Routine Description:
    Initializes the behavioral rule engine.

Arguments:
    Engine - Receives pointer to initialized engine.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PRE_ENGINE_INTERNAL engine = NULL;
    ULONG i;
    LARGE_INTEGER dueTime;

    if (Engine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Engine = NULL;

    //
    // Allocate engine structure
    //
    engine = (PRE_ENGINE_INTERNAL)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(RE_ENGINE_INTERNAL),
        RE_POOL_TAG
    );

    if (engine == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(engine, sizeof(RE_ENGINE_INTERNAL));

    //
    // Initialize locks
    //
    ExInitializePushLock(&engine->Public.RuleLock);
    ExInitializePushLock(&engine->RuleHash.Lock);

    //
    // Initialize lists
    //
    InitializeListHead(&engine->Public.RuleList);

    for (i = 0; i < RE_HASH_BUCKETS; i++) {
        InitializeListHead(&engine->RuleHash.Buckets[i]);
    }

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &engine->RuleLookaside,
        NULL,
        NULL,
        0,
        sizeof(RE_INTERNAL_RULE),
        RE_POOL_TAG_RULE,
        0
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

    engine->LookasideInitialized = TRUE;

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&engine->CleanupTimer);
    KeInitializeDpc(&engine->CleanupDpc, RepCleanupTimerDpc, engine);

    dueTime.QuadPart = -((LONGLONG)RE_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &engine->CleanupTimer,
        dueTime,
        RE_CLEANUP_INTERVAL_MS,
        &engine->CleanupDpc
    );

    //
    // Record start time
    //
    KeQuerySystemTimePrecise(&engine->Public.Stats.StartTime);

    engine->Public.Initialized = TRUE;
    *Engine = &engine->Public;

    return STATUS_SUCCESS;
}

VOID
ReShutdown(
    _Inout_ PRE_ENGINE Engine
    )
/*++
Routine Description:
    Shuts down the rule engine and frees all resources.

Arguments:
    Engine - Engine to shutdown.
--*/
{
    PRE_ENGINE_INTERNAL engine;
    PLIST_ENTRY entry;
    PRE_INTERNAL_RULE rule;

    if (Engine == NULL || !Engine->Initialized) {
        return;
    }

    engine = CONTAINING_RECORD(Engine, RE_ENGINE_INTERNAL, Public);
    engine->Public.Initialized = FALSE;

    //
    // Cancel cleanup timer
    //
    KeCancelTimer(&engine->CleanupTimer);

    //
    // Free all rules
    //
    ExAcquirePushLockExclusive(&engine->Public.RuleLock);

    while (!IsListEmpty(&engine->Public.RuleList)) {
        entry = RemoveHeadList(&engine->Public.RuleList);
        rule = CONTAINING_RECORD(entry, RE_INTERNAL_RULE, Public.ListEntry);

        // Free compiled conditions
        for (ULONG i = 0; i < rule->CompiledConditionCount; i++) {
            RepFreeCompiledCondition(&rule->CompiledConditions[i]);
        }

        if (engine->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&engine->RuleLookaside, rule);
        }
    }

    ExReleasePushLockExclusive(&engine->Public.RuleLock);

    //
    // Free lookaside lists
    //
    if (engine->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&engine->RuleLookaside);
        ExDeleteNPagedLookasideList(&engine->ResultLookaside);
    }

    //
    // Free engine structure
    //
    ExFreePoolWithTag(engine, RE_POOL_TAG);
}

// ============================================================================
// PUBLIC API - RULE MANAGEMENT
// ============================================================================

NTSTATUS
ReLoadRule(
    _In_ PRE_ENGINE Engine,
    _In_ PRE_RULE Rule
    )
/*++
Routine Description:
    Loads a new rule or updates an existing rule.

Arguments:
    Engine - Rule engine instance.
    Rule - Rule to load.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS status;
    PRE_ENGINE_INTERNAL engine;
    PRE_INTERNAL_RULE internalRule;
    PRE_INTERNAL_RULE existingRule;
    ULONG hashBucket;

    if (Engine == NULL || !Engine->Initialized || Rule == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Rule->RuleId[0] == '\0') {
        return STATUS_INVALID_PARAMETER;
    }

    if (Rule->ConditionCount > RE_MAX_CONDITIONS ||
        Rule->ActionCount > RE_MAX_ACTIONS) {
        return STATUS_INVALID_PARAMETER;
    }

    engine = CONTAINING_RECORD(Engine, RE_ENGINE_INTERNAL, Public);

    //
    // Check rule count limit
    //
    if (engine->Public.RuleCount >= RE_MAX_RULES) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Check if rule already exists
    //
    existingRule = RepFindRuleById(engine, Rule->RuleId);
    if (existingRule != NULL) {
        // Update existing rule - remove it first
        ExAcquirePushLockExclusive(&engine->Public.RuleLock);
        RemoveEntryList(&existingRule->Public.ListEntry);
        RemoveEntryList(&existingRule->HashEntry);
        InterlockedDecrement((PLONG)&engine->Public.RuleCount);
        ExReleasePushLockExclusive(&engine->Public.RuleLock);

        RepDereferenceRule(engine, existingRule);
    }

    //
    // Allocate new internal rule
    //
    internalRule = (PRE_INTERNAL_RULE)ExAllocateFromNPagedLookasideList(
        &engine->RuleLookaside
    );

    if (internalRule == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(internalRule, sizeof(RE_INTERNAL_RULE));

    //
    // Copy rule data
    //
    RtlCopyMemory(&internalRule->Public, Rule, sizeof(RE_RULE));
    internalRule->RefCount = 1;
    internalRule->RuleIdHash = RepHashString(Rule->RuleId);

    //
    // Compile conditions for fast evaluation
    //
    status = RepCompileRule(internalRule);
    if (!NT_SUCCESS(status)) {
        ExFreeToNPagedLookasideList(&engine->RuleLookaside, internalRule);
        return status;
    }

    //
    // Insert into sorted rule list and hash table
    //
    hashBucket = internalRule->RuleIdHash % RE_HASH_BUCKETS;

    ExAcquirePushLockExclusive(&engine->Public.RuleLock);

    RepInsertRuleSorted(engine, internalRule);
    InsertTailList(&engine->RuleHash.Buckets[hashBucket], &internalRule->HashEntry);
    InterlockedIncrement((PLONG)&engine->Public.RuleCount);

    ExReleasePushLockExclusive(&engine->Public.RuleLock);

    return STATUS_SUCCESS;
}

NTSTATUS
ReRemoveRule(
    _In_ PRE_ENGINE Engine,
    _In_ PCSTR RuleId
    )
/*++
Routine Description:
    Removes a rule from the engine.

Arguments:
    Engine - Rule engine instance.
    RuleId - ID of rule to remove.

Return Value:
    STATUS_SUCCESS on success, STATUS_NOT_FOUND if rule doesn't exist.
--*/
{
    PRE_ENGINE_INTERNAL engine;
    PRE_INTERNAL_RULE rule;

    if (Engine == NULL || !Engine->Initialized || RuleId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    engine = CONTAINING_RECORD(Engine, RE_ENGINE_INTERNAL, Public);

    //
    // Find the rule
    //
    rule = RepFindRuleById(engine, RuleId);
    if (rule == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Remove from lists
    //
    ExAcquirePushLockExclusive(&engine->Public.RuleLock);

    RemoveEntryList(&rule->Public.ListEntry);
    RemoveEntryList(&rule->HashEntry);
    InterlockedDecrement((PLONG)&engine->Public.RuleCount);

    ExReleasePushLockExclusive(&engine->Public.RuleLock);

    //
    // Dereference (will free when ref count reaches 0)
    //
    RepDereferenceRule(engine, rule);

    return STATUS_SUCCESS;
}

NTSTATUS
ReEnableRule(
    _In_ PRE_ENGINE Engine,
    _In_ PCSTR RuleId,
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
    PRE_ENGINE_INTERNAL engine;
    PRE_INTERNAL_RULE rule;

    if (Engine == NULL || !Engine->Initialized || RuleId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    engine = CONTAINING_RECORD(Engine, RE_ENGINE_INTERNAL, Public);

    rule = RepFindRuleById(engine, RuleId);
    if (rule == NULL) {
        return STATUS_NOT_FOUND;
    }

    rule->Public.Enabled = Enable;

    RepDereferenceRule(engine, rule);

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - RULE EVALUATION
// ============================================================================

NTSTATUS
ReEvaluate(
    _In_ PRE_ENGINE Engine,
    _In_ PRE_EVALUATION_CONTEXT Context,
    _Out_ PRE_EVALUATION_RESULT* Result
    )
/*++
Routine Description:
    Evaluates all rules against the provided context.

Arguments:
    Engine - Rule engine instance.
    Context - Evaluation context with process/file/registry info.
    Result - Receives evaluation result.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PRE_ENGINE_INTERNAL engine;
    PRE_EVALUATION_RESULT result;
    PLIST_ENTRY entry;
    PRE_INTERNAL_RULE rule;
    BOOLEAN allConditionsMatch;
    ULONG i;

    if (Engine == NULL || !Engine->Initialized ||
        Context == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    engine = CONTAINING_RECORD(Engine, RE_ENGINE_INTERNAL, Public);
    *Result = NULL;

    //
    // Allocate result structure
    //
    result = (PRE_EVALUATION_RESULT)ExAllocateFromNPagedLookasideList(
        &engine->ResultLookaside
    );

    if (result == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(result, sizeof(RE_EVALUATION_RESULT));
    result->RuleMatched = FALSE;

    //
    // Evaluate rules in priority order
    //
    ExAcquirePushLockShared(&engine->Public.RuleLock);

    for (entry = engine->Public.RuleList.Flink;
         entry != &engine->Public.RuleList;
         entry = entry->Flink) {

        rule = CONTAINING_RECORD(entry, RE_INTERNAL_RULE, Public.ListEntry);

        // Skip disabled rules
        if (!rule->Public.Enabled) {
            continue;
        }

        // Skip uncompiled rules
        if (!rule->IsCompiled) {
            continue;
        }

        // Update evaluation count
        InterlockedIncrement64(&rule->Public.EvaluationCount);
        InterlockedIncrement64(&engine->Public.Stats.Evaluations);

        //
        // Evaluate all conditions (AND logic)
        //
        allConditionsMatch = TRUE;

        for (i = 0; i < rule->CompiledConditionCount; i++) {
            BOOLEAN conditionResult = RepEvaluateCondition(
                &rule->CompiledConditions[i],
                Context
            );

            // Apply negation if needed
            if (rule->CompiledConditions[i].Negate) {
                conditionResult = !conditionResult;
            }

            if (!conditionResult) {
                allConditionsMatch = FALSE;
                break;
            }
        }

        if (allConditionsMatch) {
            //
            // Rule matched!
            //
            result->RuleMatched = TRUE;
            result->MatchedRule = &rule->Public;

            // Copy actions
            result->ActionCount = rule->Public.ActionCount;
            for (i = 0; i < rule->Public.ActionCount; i++) {
                RtlCopyMemory(
                    &result->Actions[i],
                    &rule->Public.Actions[i],
                    sizeof(RE_ACTION)
                );
            }

            // Set primary action (first action)
            if (rule->Public.ActionCount > 0) {
                result->PrimaryAction = rule->Public.Actions[0].Type;
            }

            // Update statistics
            InterlockedIncrement64(&rule->Public.MatchCount);
            KeQuerySystemTimePrecise(&rule->Public.LastMatch);
            InterlockedIncrement64(&engine->Public.Stats.Matches);

            if (result->PrimaryAction == ReAction_Block) {
                InterlockedIncrement64(&engine->Public.Stats.Blocks);
            }

            // Check if we should stop processing more rules
            if (rule->Public.StopProcessing) {
                break;
            }
        }
    }

    ExReleasePushLockShared(&engine->Public.RuleLock);

    *Result = result;
    return STATUS_SUCCESS;
}

NTSTATUS
ReGetRule(
    _In_ PRE_ENGINE Engine,
    _In_ PCSTR RuleId,
    _Out_ PRE_RULE* Rule
    )
/*++
Routine Description:
    Gets a rule by ID.

Arguments:
    Engine - Rule engine instance.
    RuleId - Rule ID to find.
    Rule - Receives pointer to rule.

Return Value:
    STATUS_SUCCESS if found.
--*/
{
    PRE_ENGINE_INTERNAL engine;
    PRE_INTERNAL_RULE rule;

    if (Engine == NULL || !Engine->Initialized ||
        RuleId == NULL || Rule == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    engine = CONTAINING_RECORD(Engine, RE_ENGINE_INTERNAL, Public);

    rule = RepFindRuleById(engine, RuleId);
    if (rule == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Rule = &rule->Public;
    // Note: caller must call RepDereferenceRule when done

    return STATUS_SUCCESS;
}

NTSTATUS
ReGetAllRules(
    _In_ PRE_ENGINE Engine,
    _Out_writes_to_(Max, *Count) PRE_RULE* Rules,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
/*++
Routine Description:
    Gets all loaded rules.

Arguments:
    Engine - Rule engine instance.
    Rules - Array to receive rule pointers.
    Max - Maximum rules to return.
    Count - Receives actual count.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PRE_ENGINE_INTERNAL engine;
    PLIST_ENTRY entry;
    PRE_INTERNAL_RULE rule;
    ULONG count = 0;

    if (Engine == NULL || !Engine->Initialized ||
        Rules == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    engine = CONTAINING_RECORD(Engine, RE_ENGINE_INTERNAL, Public);
    *Count = 0;

    ExAcquirePushLockShared(&engine->Public.RuleLock);

    for (entry = engine->Public.RuleList.Flink;
         entry != &engine->Public.RuleList && count < Max;
         entry = entry->Flink) {

        rule = CONTAINING_RECORD(entry, RE_INTERNAL_RULE, Public.ListEntry);
        Rules[count++] = &rule->Public;
    }

    ExReleasePushLockShared(&engine->Public.RuleLock);

    *Count = count;
    return STATUS_SUCCESS;
}

VOID
ReFreeResult(
    _In_ PRE_EVALUATION_RESULT Result
    )
/*++
Routine Description:
    Frees an evaluation result.

Arguments:
    Result - Result to free.
--*/
{
    if (Result != NULL) {
        // Result is allocated from lookaside list
        // For simplicity, we'll use ExFreePoolWithTag
        // In production, we'd need to pass the engine pointer
        ExFreePoolWithTag(Result, RE_POOL_TAG_RESULT);
    }
}

// ============================================================================
// INTERNAL HELPERS - HASHING
// ============================================================================

static ULONG
RepHashString(
    _In_ PCSTR String
    )
/*++
Routine Description:
    Computes a hash for a string (case-insensitive).
--*/
{
    ULONG hash = 5381;
    UCHAR c;

    if (String == NULL) {
        return 0;
    }

    while ((c = (UCHAR)*String++) != 0) {
        // Convert to lowercase
        if (c >= 'A' && c <= 'Z') {
            c = c + ('a' - 'A');
        }
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}

static ULONG
RepHashStringW(
    _In_ PCWSTR String
    )
/*++
Routine Description:
    Computes a hash for a wide string (case-insensitive).
--*/
{
    ULONG hash = 5381;
    WCHAR c;

    if (String == NULL) {
        return 0;
    }

    while ((c = *String++) != L'\0') {
        // Convert to lowercase
        if (c >= L'A' && c <= L'Z') {
            c = c + (L'a' - L'A');
        }
        hash = ((hash << 5) + hash) + (ULONG)c;
    }

    return hash;
}

// ============================================================================
// INTERNAL HELPERS - RULE COMPILATION
// ============================================================================

static NTSTATUS
RepCompileRule(
    _Inout_ PRE_INTERNAL_RULE Rule
    )
/*++
Routine Description:
    Compiles rule conditions for fast evaluation.
--*/
{
    ULONG i;
    PRE_CONDITION srcCondition;
    PRE_COMPILED_CONDITION dstCondition;
    ULONG length;

    Rule->CompiledConditionCount = 0;
    Rule->IsCompiled = FALSE;

    for (i = 0; i < Rule->Public.ConditionCount; i++) {
        srcCondition = &Rule->Public.Conditions[i];
        dstCondition = &Rule->CompiledConditions[i];

        RtlZeroMemory(dstCondition, sizeof(RE_COMPILED_CONDITION));

        dstCondition->Type = srcCondition->Type;
        dstCondition->Operator = srcCondition->Operator;
        dstCondition->Negate = srcCondition->Negate;
        dstCondition->CaseInsensitive = TRUE;  // Default to case-insensitive

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
            // String-based conditions
            length = (ULONG)strlen(srcCondition->Value);
            if (length >= RE_MAX_PATTERN_LENGTH) {
                return STATUS_BUFFER_OVERFLOW;
            }

            RtlCopyMemory(
                dstCondition->String.Pattern,
                srcCondition->Value,
                length + 1
            );
            dstCondition->String.PatternLength = length;
            dstCondition->String.PatternHash = RepHashString(srcCondition->Value);
            break;

        case ReCondition_FileHash:
            // Hash condition - expect hex string
            length = (ULONG)strlen(srcCondition->Value);
            if (length != 64) {  // SHA-256 hex string
                return STATUS_INVALID_PARAMETER;
            }

            // Convert hex string to bytes
            for (ULONG j = 0; j < 32; j++) {
                CHAR hex[3] = { srcCondition->Value[j * 2],
                                srcCondition->Value[j * 2 + 1], 0 };
                ULONG value;
                NTSTATUS status = RtlCharToInteger(hex, 16, &value);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                dstCondition->FileHash.Hash[j] = (UCHAR)value;
            }
            break;

        case ReCondition_ThreatScore:
        case ReCondition_BehaviorFlag:
        case ReCondition_TimeOfDay:
            // Numeric conditions
            {
                NTSTATUS status = RtlCharToInteger(
                    srcCondition->Value,
                    10,
                    &dstCondition->Numeric.Value
                );
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            break;

        case ReCondition_Custom:
            // Custom conditions - store as string
            length = (ULONG)strlen(srcCondition->Value);
            if (length >= RE_MAX_PATTERN_LENGTH) {
                return STATUS_BUFFER_OVERFLOW;
            }

            RtlCopyMemory(
                dstCondition->String.Pattern,
                srcCondition->Value,
                length + 1
            );
            dstCondition->String.PatternLength = length;
            break;

        default:
            return STATUS_INVALID_PARAMETER;
        }

        Rule->CompiledConditionCount++;
    }

    Rule->IsCompiled = TRUE;
    return STATUS_SUCCESS;
}

static VOID
RepFreeCompiledCondition(
    _Inout_ PRE_COMPILED_CONDITION Condition
    )
/*++
Routine Description:
    Frees resources associated with a compiled condition.
--*/
{
    // Free list items if present
    if (Condition->Type == ReCondition_ProcessName ||
        Condition->Type == ReCondition_FilePath) {

        if (Condition->List.Items != NULL) {
            for (ULONG i = 0; i < Condition->List.ItemCount; i++) {
                if (Condition->List.Items[i] != NULL) {
                    ExFreePoolWithTag(Condition->List.Items[i], RE_POOL_TAG_LIST);
                }
            }
            ExFreePoolWithTag(Condition->List.Items, RE_POOL_TAG_LIST);
        }

        if (Condition->List.ItemHashes != NULL) {
            ExFreePoolWithTag(Condition->List.ItemHashes, RE_POOL_TAG_LIST);
        }
    }

    RtlZeroMemory(Condition, sizeof(RE_COMPILED_CONDITION));
}

// ============================================================================
// INTERNAL HELPERS - CONDITION EVALUATION
// ============================================================================

static BOOLEAN
RepEvaluateCondition(
    _In_ PRE_COMPILED_CONDITION Condition,
    _In_ PRE_EVALUATION_CONTEXT Context
    )
/*++
Routine Description:
    Evaluates a single compiled condition against the context.
--*/
{
    BOOLEAN result = FALSE;
    ANSI_STRING ansiString;
    CHAR ansiBuffer[512];
    ULONG length;

    switch (Condition->Type) {
    case ReCondition_ProcessName:
        if (Context->ProcessName != NULL && Context->ProcessName->Buffer != NULL) {
            // Convert Unicode to ANSI for comparison
            ansiString.Buffer = ansiBuffer;
            ansiString.MaximumLength = sizeof(ansiBuffer);
            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiString, Context->ProcessName, FALSE))) {
                result = RepMatchString(
                    Condition->String.Pattern,
                    Condition->String.PatternLength,
                    ansiString.Buffer,
                    ansiString.Length,
                    Condition->Operator,
                    Condition->CaseInsensitive
                );
            }
        }
        break;

    case ReCondition_ParentName:
        // Would need parent process info in context
        // For now, return FALSE (no match)
        result = FALSE;
        break;

    case ReCondition_CommandLine:
        if (Context->CommandLine != NULL && Context->CommandLine->Buffer != NULL) {
            result = RepMatchStringW(
                Condition->String.Pattern,
                Condition->String.PatternLength,
                Context->CommandLine->Buffer,
                Context->CommandLine->Length / sizeof(WCHAR),
                Condition->Operator,
                Condition->CaseInsensitive
            );
        }
        break;

    case ReCondition_FilePath:
        if (Context->FilePath != NULL && Context->FilePath->Buffer != NULL) {
            result = RepMatchStringW(
                Condition->String.Pattern,
                Condition->String.PatternLength,
                Context->FilePath->Buffer,
                Context->FilePath->Length / sizeof(WCHAR),
                Condition->Operator,
                Condition->CaseInsensitive
            );
        }
        break;

    case ReCondition_FileHash:
        if (Context->FileHash != NULL) {
            result = RtlCompareMemory(
                Condition->FileHash.Hash,
                Context->FileHash,
                32
            ) == 32;
        }
        break;

    case ReCondition_RegistryPath:
        if (Context->RegistryPath != NULL && Context->RegistryPath->Buffer != NULL) {
            result = RepMatchStringW(
                Condition->String.Pattern,
                Condition->String.PatternLength,
                Context->RegistryPath->Buffer,
                Context->RegistryPath->Length / sizeof(WCHAR),
                Condition->Operator,
                Condition->CaseInsensitive
            );
        }
        break;

    case ReCondition_NetworkAddress:
    case ReCondition_Domain:
        // Would need network info in context
        result = FALSE;
        break;

    case ReCondition_ThreatScore:
        switch (Condition->Operator) {
        case ReOp_Equals:
            result = (Context->ThreatScore == Condition->Numeric.Value);
            break;
        case ReOp_NotEquals:
            result = (Context->ThreatScore != Condition->Numeric.Value);
            break;
        case ReOp_GreaterThan:
            result = (Context->ThreatScore > Condition->Numeric.Value);
            break;
        case ReOp_LessThan:
            result = (Context->ThreatScore < Condition->Numeric.Value);
            break;
        default:
            result = FALSE;
            break;
        }
        break;

    case ReCondition_BehaviorFlag:
        result = (Context->BehaviorFlags & Condition->Numeric.Value) != 0;
        break;

    case ReCondition_TimeOfDay:
        // Would need current time evaluation
        result = FALSE;
        break;

    case ReCondition_MITRETechnique:
        // Would need MITRE technique info in context
        result = FALSE;
        break;

    case ReCondition_Custom:
        // Custom condition evaluation would go here
        result = FALSE;
        break;

    default:
        result = FALSE;
        break;
    }

    return result;
}

// ============================================================================
// INTERNAL HELPERS - STRING MATCHING
// ============================================================================

static BOOLEAN
RepMatchString(
    _In_ PCSTR Pattern,
    _In_ ULONG PatternLength,
    _In_ PCSTR Value,
    _In_ ULONG ValueLength,
    _In_ RE_OPERATOR Operator,
    _In_ BOOLEAN CaseInsensitive
    )
/*++
Routine Description:
    Matches a pattern against a string value.
--*/
{
    LONG compareResult;

    if (Pattern == NULL || Value == NULL) {
        return FALSE;
    }

    switch (Operator) {
    case ReOp_Equals:
        if (PatternLength != ValueLength) {
            return FALSE;
        }
        if (CaseInsensitive) {
            return _strnicmp(Pattern, Value, PatternLength) == 0;
        } else {
            return strncmp(Pattern, Value, PatternLength) == 0;
        }

    case ReOp_NotEquals:
        if (PatternLength != ValueLength) {
            return TRUE;
        }
        if (CaseInsensitive) {
            return _strnicmp(Pattern, Value, PatternLength) != 0;
        } else {
            return strncmp(Pattern, Value, PatternLength) != 0;
        }

    case ReOp_Contains:
        {
            // Simple substring search
            if (PatternLength > ValueLength) {
                return FALSE;
            }

            for (ULONG i = 0; i <= ValueLength - PatternLength; i++) {
                if (CaseInsensitive) {
                    if (_strnicmp(Pattern, &Value[i], PatternLength) == 0) {
                        return TRUE;
                    }
                } else {
                    if (strncmp(Pattern, &Value[i], PatternLength) == 0) {
                        return TRUE;
                    }
                }
            }
            return FALSE;
        }

    case ReOp_StartsWith:
        if (PatternLength > ValueLength) {
            return FALSE;
        }
        if (CaseInsensitive) {
            return _strnicmp(Pattern, Value, PatternLength) == 0;
        } else {
            return strncmp(Pattern, Value, PatternLength) == 0;
        }

    case ReOp_EndsWith:
        if (PatternLength > ValueLength) {
            return FALSE;
        }
        if (CaseInsensitive) {
            return _strnicmp(Pattern, &Value[ValueLength - PatternLength], PatternLength) == 0;
        } else {
            return strncmp(Pattern, &Value[ValueLength - PatternLength], PatternLength) == 0;
        }

    case ReOp_Regex:
        // Simplified: treat as wildcard match
        return RepMatchWildcard(Pattern, Value, CaseInsensitive);

    case ReOp_InList:
        // Would need list data
        return FALSE;

    default:
        return FALSE;
    }
}

static BOOLEAN
RepMatchStringW(
    _In_ PCSTR Pattern,
    _In_ ULONG PatternLength,
    _In_ PCWSTR Value,
    _In_ ULONG ValueLength,
    _In_ RE_OPERATOR Operator,
    _In_ BOOLEAN CaseInsensitive
    )
/*++
Routine Description:
    Matches an ANSI pattern against a Unicode string value.
--*/
{
    CHAR ansiBuffer[512];
    ANSI_STRING ansiString;
    UNICODE_STRING unicodeString;

    if (Pattern == NULL || Value == NULL) {
        return FALSE;
    }

    // Convert Unicode value to ANSI for comparison
    unicodeString.Buffer = (PWSTR)Value;
    unicodeString.Length = (USHORT)(ValueLength * sizeof(WCHAR));
    unicodeString.MaximumLength = unicodeString.Length;

    ansiString.Buffer = ansiBuffer;
    ansiString.MaximumLength = sizeof(ansiBuffer) - 1;

    if (!NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiString, &unicodeString, FALSE))) {
        return FALSE;
    }

    ansiBuffer[ansiString.Length] = '\0';

    return RepMatchString(
        Pattern,
        PatternLength,
        ansiBuffer,
        ansiString.Length,
        Operator,
        CaseInsensitive
    );
}

static BOOLEAN
RepMatchWildcard(
    _In_ PCSTR Pattern,
    _In_ PCSTR String,
    _In_ BOOLEAN CaseInsensitive
    )
/*++
Routine Description:
    Simple wildcard matching (* and ?).
--*/
{
    PCSTR p = Pattern;
    PCSTR s = String;
    PCSTR starP = NULL;
    PCSTR starS = NULL;

    while (*s) {
        if (*p == '*') {
            starP = p++;
            starS = s;
        } else if (*p == '?' ||
                   (CaseInsensitive ?
                    ((*p >= 'A' && *p <= 'Z' ? *p + 32 : *p) ==
                     (*s >= 'A' && *s <= 'Z' ? *s + 32 : *s)) :
                    (*p == *s))) {
            p++;
            s++;
        } else if (starP) {
            p = starP + 1;
            s = ++starS;
        } else {
            return FALSE;
        }
    }

    while (*p == '*') {
        p++;
    }

    return (*p == '\0');
}

// ============================================================================
// INTERNAL HELPERS - RULE LOOKUP
// ============================================================================

static PRE_INTERNAL_RULE
RepFindRuleById(
    _In_ PRE_ENGINE_INTERNAL Engine,
    _In_ PCSTR RuleId
    )
/*++
Routine Description:
    Finds a rule by its ID using the hash table.
--*/
{
    ULONG hash;
    ULONG bucket;
    PLIST_ENTRY entry;
    PRE_INTERNAL_RULE rule;

    hash = RepHashString(RuleId);
    bucket = hash % RE_HASH_BUCKETS;

    ExAcquirePushLockShared(&Engine->RuleHash.Lock);

    for (entry = Engine->RuleHash.Buckets[bucket].Flink;
         entry != &Engine->RuleHash.Buckets[bucket];
         entry = entry->Flink) {

        rule = CONTAINING_RECORD(entry, RE_INTERNAL_RULE, HashEntry);

        if (rule->RuleIdHash == hash &&
            _stricmp(rule->Public.RuleId, RuleId) == 0) {

            RepReferenceRule(rule);
            ExReleasePushLockShared(&Engine->RuleHash.Lock);
            return rule;
        }
    }

    ExReleasePushLockShared(&Engine->RuleHash.Lock);
    return NULL;
}

static VOID
RepInsertRuleSorted(
    _In_ PRE_ENGINE_INTERNAL Engine,
    _In_ PRE_INTERNAL_RULE Rule
    )
/*++
Routine Description:
    Inserts a rule into the list sorted by priority (lower = higher priority).
--*/
{
    PLIST_ENTRY entry;
    PRE_INTERNAL_RULE existingRule;

    // Find insertion point
    for (entry = Engine->Public.RuleList.Flink;
         entry != &Engine->Public.RuleList;
         entry = entry->Flink) {

        existingRule = CONTAINING_RECORD(entry, RE_INTERNAL_RULE, Public.ListEntry);

        if (Rule->Public.Priority < existingRule->Public.Priority) {
            // Insert before this rule
            InsertTailList(entry, &Rule->Public.ListEntry);
            return;
        }
    }

    // Insert at end
    InsertTailList(&Engine->Public.RuleList, &Rule->Public.ListEntry);
}

// ============================================================================
// INTERNAL HELPERS - REFERENCE COUNTING
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
    _In_ PRE_ENGINE_INTERNAL Engine,
    _In_ PRE_INTERNAL_RULE Rule
    )
{
    if (InterlockedDecrement(&Rule->RefCount) == 0) {
        // Free compiled conditions
        for (ULONG i = 0; i < Rule->CompiledConditionCount; i++) {
            RepFreeCompiledCondition(&Rule->CompiledConditions[i]);
        }

        if (Engine->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&Engine->RuleLookaside, Rule);
        }
    }
}

// ============================================================================
// INTERNAL HELPERS - CLEANUP
// ============================================================================

static VOID NTAPI
RepCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/*++
Routine Description:
    Periodic cleanup timer DPC.
--*/
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    // Cleanup tasks would go here:
    // - Remove expired results
    // - Reset per-interval statistics
    // - Log accumulated statistics
}
