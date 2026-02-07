/*++
    ShadowStrike Next-Generation Antivirus
    Module: RuleEngine.h - Detection rule engine
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define RE_POOL_TAG 'ERER'
#define RE_MAX_CONDITIONS 16
#define RE_MAX_ACTIONS 8

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
} RE_CONDITION_TYPE;

typedef enum _RE_OPERATOR {
    ReOp_Equals = 0,
    ReOp_NotEquals,
    ReOp_Contains,
    ReOp_StartsWith,
    ReOp_EndsWith,
    ReOp_Regex,
    ReOp_GreaterThan,
    ReOp_LessThan,
    ReOp_InList,
} RE_OPERATOR;

typedef enum _RE_ACTION_TYPE {
    ReAction_Allow = 0,
    ReAction_Block,
    ReAction_Quarantine,
    ReAction_Terminate,
    ReAction_Alert,
    ReAction_Log,
    ReAction_Investigate,
    ReAction_Custom,
} RE_ACTION_TYPE;

typedef struct _RE_CONDITION {
    RE_CONDITION_TYPE Type;
    RE_OPERATOR Operator;
    CHAR Value[256];
    BOOLEAN Negate;                     // NOT condition
} RE_CONDITION, *PRE_CONDITION;

typedef struct _RE_ACTION {
    RE_ACTION_TYPE Type;
    CHAR Parameter[256];                // Action-specific parameter
} RE_ACTION, *PRE_ACTION;

typedef struct _RE_RULE {
    CHAR RuleId[32];
    CHAR RuleName[64];
    CHAR Description[256];
    
    // Conditions (AND logic)
    RE_CONDITION Conditions[RE_MAX_CONDITIONS];
    ULONG ConditionCount;
    
    // Actions
    RE_ACTION Actions[RE_MAX_ACTIONS];
    ULONG ActionCount;
    
    // Rule settings
    BOOLEAN Enabled;
    ULONG Priority;                     // Lower = higher priority
    BOOLEAN StopProcessing;             // Don't evaluate more rules if matched
    
    // Statistics
    volatile LONG64 EvaluationCount;
    volatile LONG64 MatchCount;
    LARGE_INTEGER LastMatch;
    
    LIST_ENTRY ListEntry;
} RE_RULE, *PRE_RULE;

typedef struct _RE_EVALUATION_CONTEXT {
    HANDLE ProcessId;
    PUNICODE_STRING ProcessName;
    PUNICODE_STRING CommandLine;
    PUNICODE_STRING FilePath;
    PUCHAR FileHash;
    PUNICODE_STRING RegistryPath;
    ULONG ThreatScore;
    ULONG BehaviorFlags;
} RE_EVALUATION_CONTEXT, *PRE_EVALUATION_CONTEXT;

typedef struct _RE_EVALUATION_RESULT {
    PRE_RULE MatchedRule;
    BOOLEAN RuleMatched;
    RE_ACTION_TYPE PrimaryAction;
    
    // All actions to take
    RE_ACTION Actions[RE_MAX_ACTIONS];
    ULONG ActionCount;
    
    LIST_ENTRY ListEntry;
} RE_EVALUATION_RESULT, *PRE_EVALUATION_RESULT;

typedef struct _RE_ENGINE {
    BOOLEAN Initialized;
    
    // Rules (sorted by priority)
    LIST_ENTRY RuleList;
    EX_PUSH_LOCK RuleLock;
    ULONG RuleCount;
    
    struct {
        volatile LONG64 Evaluations;
        volatile LONG64 Matches;
        volatile LONG64 Blocks;
        LARGE_INTEGER StartTime;
    } Stats;
} RE_ENGINE, *PRE_ENGINE;

NTSTATUS ReInitialize(_Out_ PRE_ENGINE* Engine);
VOID ReShutdown(_Inout_ PRE_ENGINE Engine);
NTSTATUS ReLoadRule(_In_ PRE_ENGINE Engine, _In_ PRE_RULE Rule);
NTSTATUS ReRemoveRule(_In_ PRE_ENGINE Engine, _In_ PCSTR RuleId);
NTSTATUS ReEnableRule(_In_ PRE_ENGINE Engine, _In_ PCSTR RuleId, _In_ BOOLEAN Enable);
NTSTATUS ReEvaluate(_In_ PRE_ENGINE Engine, _In_ PRE_EVALUATION_CONTEXT Context, _Out_ PRE_EVALUATION_RESULT* Result);
NTSTATUS ReGetRule(_In_ PRE_ENGINE Engine, _In_ PCSTR RuleId, _Out_ PRE_RULE* Rule);
NTSTATUS ReGetAllRules(_In_ PRE_ENGINE Engine, _Out_writes_to_(Max, *Count) PRE_RULE* Rules, _In_ ULONG Max, _Out_ PULONG Count);
VOID ReFreeResult(_In_ PRE_EVALUATION_RESULT Result);

#ifdef __cplusplus
}
#endif
