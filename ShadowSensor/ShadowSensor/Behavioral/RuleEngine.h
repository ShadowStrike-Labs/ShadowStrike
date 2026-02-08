/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE BEHAVIORAL RULE ENGINE
===============================================================================

@file RuleEngine.h
@brief Enterprise-grade behavioral detection rule engine for kernel EDR.

This module provides comprehensive rule-based behavioral detection with
full thread-safety, proper resource management, and no undefined behavior.

@author ShadowStrike Security Team
@version 3.0.0 (Enterprise Edition - Hardened)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

//
// Pool tags
//
#define RE_POOL_TAG             'ERER'
#define RE_POOL_TAG_RULE        'rRER'
#define RE_POOL_TAG_RESULT      'sRER'
#define RE_POOL_TAG_LIST        'lRER'
#define RE_POOL_TAG_BUFFER      'bRER'

//
// Limits - enforced at all boundaries
//
#define RE_MAX_CONDITIONS       16
#define RE_MAX_ACTIONS          8
#define RE_MAX_RULES            10000
#define RE_MAX_RULE_ID_LEN      31
#define RE_MAX_RULE_NAME_LEN    63
#define RE_MAX_DESCRIPTION_LEN  255
#define RE_MAX_VALUE_LEN        255
#define RE_MAX_PARAMETER_LEN    255
#define RE_MAX_PATTERN_LENGTH   256
#define RE_MAX_CONVERSION_LEN   4096    // Max string conversion buffer

//
// Condition types for rule matching
//
typedef enum _RE_CONDITION_TYPE {
    ReCondition_ProcessName = 0,
    ReCondition_ParentName,
    ReCondition_CommandLine,
    ReCondition_FilePath,
    ReCondition_FileHash,
    ReCondition_RegistryPath,
    ReCondition_NetworkAddress,
    ReCondition_Domain,
    ReCondition_ThreatScore,
    ReCondition_MITRETechnique,
    ReCondition_BehaviorFlag,
    ReCondition_TimeOfDay,
    ReCondition_Custom,
    ReCondition_MaxValue          // Sentinel for validation
} RE_CONDITION_TYPE;

//
// Operators for condition matching
//
typedef enum _RE_OPERATOR {
    ReOp_Equals = 0,
    ReOp_NotEquals,
    ReOp_Contains,
    ReOp_StartsWith,
    ReOp_EndsWith,
    ReOp_Wildcard,                // Explicit wildcard (was ReOp_Regex)
    ReOp_GreaterThan,
    ReOp_LessThan,
    ReOp_InList,
    ReOp_MaxValue                 // Sentinel for validation
} RE_OPERATOR;

//
// Action types to take when a rule matches
//
typedef enum _RE_ACTION_TYPE {
    ReAction_None = 0,            // Explicit no-action
    ReAction_Allow,
    ReAction_Block,
    ReAction_Quarantine,
    ReAction_Terminate,
    ReAction_Alert,
    ReAction_Log,
    ReAction_Investigate,
    ReAction_Custom,
    ReAction_MaxValue             // Sentinel for validation
} RE_ACTION_TYPE;

//
// Condition structure - user-facing
//
typedef struct _RE_CONDITION {
    RE_CONDITION_TYPE Type;
    RE_OPERATOR Operator;
    CHAR Value[RE_MAX_VALUE_LEN + 1];
    BOOLEAN Negate;               // NOT condition
    UCHAR Reserved[3];            // Alignment padding
} RE_CONDITION, *PRE_CONDITION;

//
// Action structure - user-facing
//
typedef struct _RE_ACTION {
    RE_ACTION_TYPE Type;
    CHAR Parameter[RE_MAX_PARAMETER_LEN + 1];
} RE_ACTION, *PRE_ACTION;

//
// Rule structure - user-facing (copied to caller, never internal pointer)
//
typedef struct _RE_RULE {
    CHAR RuleId[RE_MAX_RULE_ID_LEN + 1];
    CHAR RuleName[RE_MAX_RULE_NAME_LEN + 1];
    CHAR Description[RE_MAX_DESCRIPTION_LEN + 1];

    // Conditions (AND logic)
    RE_CONDITION Conditions[RE_MAX_CONDITIONS];
    ULONG ConditionCount;

    // Actions
    RE_ACTION Actions[RE_MAX_ACTIONS];
    ULONG ActionCount;

    // Rule settings
    BOOLEAN Enabled;
    ULONG Priority;               // Lower = higher priority
    BOOLEAN StopProcessing;       // Don't evaluate more rules if matched

    // Statistics (read-only, updated atomically)
    volatile LONG64 EvaluationCount;
    volatile LONG64 MatchCount;
    LONG64 LastMatchTime;         // System time as LONG64 for atomic access

    LIST_ENTRY ListEntry;         // Internal use only
} RE_RULE, *PRE_RULE;

//
// Evaluation context - all pointers must be valid kernel addresses
// Caller is responsible for lifetime of pointed-to data during evaluation
//
typedef struct _RE_EVALUATION_CONTEXT {
    HANDLE ProcessId;
    HANDLE ParentProcessId;       // Added for ParentName support
    PUNICODE_STRING ProcessName;
    PUNICODE_STRING ParentProcessName;  // Added for ParentName support
    PUNICODE_STRING CommandLine;
    PUNICODE_STRING FilePath;
    PUCHAR FileHash;              // Must point to 32 bytes (SHA-256)
    ULONG FileHashLength;         // Must be 32 for SHA-256
    PUNICODE_STRING RegistryPath;
    PUNICODE_STRING NetworkAddress;     // Added for NetworkAddress support
    PUNICODE_STRING Domain;             // Added for Domain support
    ULONG ThreatScore;
    ULONG BehaviorFlags;
    PUNICODE_STRING MitreTechnique;     // Added for MITRE support
    LARGE_INTEGER CurrentTime;          // Added for TimeOfDay support
} RE_EVALUATION_CONTEXT, *PRE_EVALUATION_CONTEXT;

//
// Evaluation result - caller-owned, must be freed with ReFreeResult
//
typedef struct _RE_EVALUATION_RESULT {
    BOOLEAN RuleMatched;
    RE_ACTION_TYPE PrimaryAction;       // Always initialized (ReAction_None if no actions)

    // Copy of matched rule data (no internal pointers)
    CHAR MatchedRuleId[RE_MAX_RULE_ID_LEN + 1];
    CHAR MatchedRuleName[RE_MAX_RULE_NAME_LEN + 1];
    ULONG MatchedRulePriority;

    // All actions to take
    RE_ACTION Actions[RE_MAX_ACTIONS];
    ULONG ActionCount;

    // Opaque engine handle for proper deallocation
    PVOID EngineHandle;

    LIST_ENTRY ListEntry;
} RE_EVALUATION_RESULT, *PRE_EVALUATION_RESULT;

//
// Engine statistics - exposed for monitoring
//
typedef struct _RE_ENGINE_STATS {
    volatile LONG64 Evaluations;
    volatile LONG64 Matches;
    volatile LONG64 Blocks;
    LARGE_INTEGER StartTime;
    ULONG RuleCount;
    ULONG Reserved;
} RE_ENGINE_STATS, *PRE_ENGINE_STATS;

//
// Opaque engine handle
//
typedef struct _RE_ENGINE *PRE_ENGINE;

// ============================================================================
// PUBLIC API
// ============================================================================

//
// Initialization and shutdown
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ReInitialize(
    _Out_ PRE_ENGINE* Engine
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ReShutdown(
    _Inout_opt_ PRE_ENGINE Engine
    );

//
// Rule management
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ReLoadRule(
    _In_ PRE_ENGINE Engine,
    _In_ const RE_RULE* Rule
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ReRemoveRule(
    _In_ PRE_ENGINE Engine,
    _In_z_ PCSTR RuleId
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ReEnableRule(
    _In_ PRE_ENGINE Engine,
    _In_z_ PCSTR RuleId,
    _In_ BOOLEAN Enable
    );

//
// Rule evaluation
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ReEvaluate(
    _In_ PRE_ENGINE Engine,
    _In_ const RE_EVALUATION_CONTEXT* Context,
    _Out_ PRE_EVALUATION_RESULT* Result
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ReFreeResult(
    _In_opt_ PRE_EVALUATION_RESULT Result
    );

//
// Rule query (returns copy, not internal pointer)
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ReGetRule(
    _In_ PRE_ENGINE Engine,
    _In_z_ PCSTR RuleId,
    _Out_ PRE_RULE Rule
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ReGetAllRules(
    _In_ PRE_ENGINE Engine,
    _Out_writes_to_(MaxCount, *ActualCount) PRE_RULE Rules,
    _In_ ULONG MaxCount,
    _Out_ PULONG ActualCount
    );

//
// Statistics
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ReGetStatistics(
    _In_ PRE_ENGINE Engine,
    _Out_ PRE_ENGINE_STATS Stats
    );

#ifdef __cplusplus
}
#endif
