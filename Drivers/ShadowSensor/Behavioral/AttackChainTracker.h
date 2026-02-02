/*++
    ShadowStrike Next-Generation Antivirus
    Module: AttackChainTracker.h - Multi-stage attack correlation
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "../Shared/AttackPatterns.h"

#define ACT_POOL_TAG 'TCAA'
#define ACT_MAX_CHAIN_EVENTS 64
#define ACT_MAX_ACTIVE_CHAINS 1024

typedef enum _ACT_CHAIN_STATE {
    ActState_Initial = 0,
    ActState_Reconnaissance,
    ActState_InitialAccess,
    ActState_Execution,
    ActState_Persistence,
    ActState_PrivilegeEscalation,
    ActState_DefenseEvasion,
    ActState_CredentialAccess,
    ActState_Discovery,
    ActState_LateralMovement,
    ActState_Collection,
    ActState_Exfiltration,
    ActState_Impact,
} ACT_CHAIN_STATE;

typedef struct _ACT_CHAIN_EVENT {
    MITRE_TECHNIQUE Technique;
    ACT_CHAIN_STATE Phase;
    HANDLE ProcessId;
    UNICODE_STRING ProcessName;
    LARGE_INTEGER Timestamp;
    ULONG ConfidenceScore;
    
    // Evidence
    CHAR EvidenceDescription[256];
    PVOID EvidenceData;
    SIZE_T EvidenceSize;
    
    LIST_ENTRY ListEntry;
} ACT_CHAIN_EVENT, *PACT_CHAIN_EVENT;

typedef struct _ACT_ATTACK_CHAIN {
    GUID ChainId;
    ACT_CHAIN_STATE CurrentState;
    
    // Root cause
    HANDLE RootProcessId;
    UNICODE_STRING RootProcessName;
    LARGE_INTEGER StartTime;
    
    // Events in chain
    LIST_ENTRY EventList;
    KSPIN_LOCK EventLock;
    volatile LONG EventCount;
    
    // Scoring
    ULONG ThreatScore;
    ULONG ConfidenceScore;
    BOOLEAN IsConfirmedAttack;
    
    // Correlation
    HANDLE RelatedProcessIds[32];
    ULONG RelatedProcessCount;
    
    LIST_ENTRY ListEntry;
} ACT_ATTACK_CHAIN, *PACT_ATTACK_CHAIN;

typedef VOID (*ACT_CHAIN_CALLBACK)(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ PACT_CHAIN_EVENT NewEvent,
    _In_opt_ PVOID Context
);

typedef struct _ACT_TRACKER {
    BOOLEAN Initialized;
    
    // Active chains
    LIST_ENTRY ChainList;
    EX_PUSH_LOCK ChainLock;
    volatile LONG ChainCount;
    
    // Callbacks
    ACT_CHAIN_CALLBACK AlertCallback;
    PVOID CallbackContext;
    
    // Correlation rules
    LIST_ENTRY RuleList;
    
    struct {
        volatile LONG64 EventsProcessed;
        volatile LONG64 ChainsCreated;
        volatile LONG64 AttacksConfirmed;
        LARGE_INTEGER StartTime;
    } Stats;
} ACT_TRACKER, *PACT_TRACKER;

NTSTATUS ActInitialize(_Out_ PACT_TRACKER* Tracker);
VOID ActShutdown(_Inout_ PACT_TRACKER Tracker);
NTSTATUS ActRegisterCallback(_In_ PACT_TRACKER Tracker, _In_ ACT_CHAIN_CALLBACK Callback, _In_opt_ PVOID Context);
NTSTATUS ActSubmitEvent(_In_ PACT_TRACKER Tracker, _In_ MITRE_TECHNIQUE Technique, _In_ HANDLE ProcessId, _In_ PUNICODE_STRING ProcessName, _In_opt_ PVOID Evidence, _In_ SIZE_T EvidenceSize);
NTSTATUS ActGetChain(_In_ PACT_TRACKER Tracker, _In_ PGUID ChainId, _Out_ PACT_ATTACK_CHAIN* Chain);
NTSTATUS ActCorrelateEvents(_In_ PACT_TRACKER Tracker, _In_ HANDLE ProcessId, _Out_ PACT_ATTACK_CHAIN* Chain);
NTSTATUS ActGetActiveChains(_In_ PACT_TRACKER Tracker, _Out_writes_to_(Max, *Count) PACT_ATTACK_CHAIN* Chains, _In_ ULONG Max, _Out_ PULONG Count);
VOID ActFreeChain(_In_ PACT_ATTACK_CHAIN Chain);

#ifdef __cplusplus
}
#endif
