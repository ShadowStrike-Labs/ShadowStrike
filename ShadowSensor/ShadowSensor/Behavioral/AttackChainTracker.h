/*++
    ShadowStrike Next-Generation Antivirus
    Module: AttackChainTracker.h - Multi-stage attack correlation
    Copyright (c) ShadowStrike Team

    Enterprise-grade attack chain tracking with:
    - Reference-counted chain objects for thread-safe lifetime management
    - Full synchronization for all shared data structures
    - IRQL-safe design with proper lock ordering
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "../Shared/AttackPatterns.h"

//
// Pool tags
//
#define ACT_POOL_TAG        'TCAA'
#define ACT_CHAIN_TAG       'hCAA'
#define ACT_EVENT_TAG       'eCAA'
#define ACT_CALLBACK_TAG    'cCAA'

//
// Limits - all enforced
//
#define ACT_MAX_CHAIN_EVENTS        64
#define ACT_MAX_ACTIVE_CHAINS       1024
#define ACT_MAX_RELATED_PROCESSES   32
#define ACT_MAX_PROCESS_NAME_LEN    520     // MAX_PATH * sizeof(WCHAR) + slack
#define ACT_MAX_EVIDENCE_SIZE       4096
#define ACT_MAX_DANGEROUS_COMBOS    32      // For combo tracking bitmask

//
// Kill chain states aligned with MITRE ATT&CK
//
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
    ActState_MaxValue
} ACT_CHAIN_STATE;

//
// Forward declarations
//
typedef struct _ACT_TRACKER ACT_TRACKER, *PACT_TRACKER;
typedef struct _ACT_ATTACK_CHAIN ACT_ATTACK_CHAIN, *PACT_ATTACK_CHAIN;
typedef struct _ACT_CHAIN_EVENT ACT_CHAIN_EVENT, *PACT_CHAIN_EVENT;

//
// Chain event - represents a single detected technique
//
typedef struct _ACT_CHAIN_EVENT {
    ULONG Technique;                        // MITRE technique ID
    ACT_CHAIN_STATE Phase;                  // Kill chain phase
    HANDLE ProcessId;                       // Source process
    UNICODE_STRING ProcessName;             // Process name (allocated buffer)
    LARGE_INTEGER Timestamp;                // Detection time
    ULONG ConfidenceScore;                  // Score for this event

    //
    // Evidence storage
    //
    CHAR EvidenceDescription[256];          // Human-readable description
    PVOID EvidenceData;                     // Binary evidence (allocated)
    SIZE_T EvidenceSize;                    // Size of evidence

    LIST_ENTRY ListEntry;                   // Chain linkage
} ACT_CHAIN_EVENT, *PACT_CHAIN_EVENT;

//
// Attack chain - collection of correlated events
// Reference counted for safe cross-thread access
//
typedef struct _ACT_ATTACK_CHAIN {
    //
    // Reference counting for safe lifetime management
    //
    volatile LONG ReferenceCount;

    //
    // Identity
    //
    GUID ChainId;
    ACT_CHAIN_STATE CurrentState;

    //
    // Root cause process
    //
    HANDLE RootProcessId;
    UNICODE_STRING RootProcessName;         // Allocated buffer
    LARGE_INTEGER StartTime;
    LARGE_INTEGER LastActivityTime;         // For expiration tracking

    //
    // Event list - protected by EventLock
    //
    LIST_ENTRY EventList;
    KSPIN_LOCK EventLock;
    volatile LONG EventCount;

    //
    // Scoring - updated under EventLock
    //
    ULONG ThreatScore;
    ULONG ConfidenceScore;
    BOOLEAN IsConfirmedAttack;

    //
    // Dangerous combo tracking - bitmask of applied combos
    //
    ULONG AppliedComboMask;

    //
    // Related processes - protected by EventLock
    //
    HANDLE RelatedProcessIds[ACT_MAX_RELATED_PROCESSES];
    ULONG RelatedProcessCount;

    //
    // List linkage in tracker - protected by tracker's ChainLock
    //
    LIST_ENTRY ListEntry;
} ACT_ATTACK_CHAIN, *PACT_ATTACK_CHAIN;

//
// Callback context - atomically swappable
//
typedef struct _ACT_CALLBACK_REGISTRATION {
    PVOID Callback;                         // ACT_CHAIN_CALLBACK function
    PVOID Context;                          // User context
} ACT_CALLBACK_REGISTRATION, *PACT_CALLBACK_REGISTRATION;

//
// Callback signature for attack alerts
// Called with chain reference held - caller must NOT release
//
typedef VOID (*ACT_CHAIN_CALLBACK)(
    _In_ PACT_ATTACK_CHAIN Chain,
    _In_ PACT_CHAIN_EVENT NewEvent,
    _In_opt_ PVOID Context
    );

//
// Main tracker structure
//
typedef struct _ACT_TRACKER {
    volatile LONG Initialized;              // Atomic init flag

    //
    // Active chains - protected by ChainLock
    //
    LIST_ENTRY ChainList;
    EX_PUSH_LOCK ChainLock;
    volatile LONG ChainCount;

    //
    // Callback registration - atomically accessed
    //
    PACT_CALLBACK_REGISTRATION CallbackReg;
    KSPIN_LOCK CallbackLock;

    //
    // Cleanup timer for expired chains
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    volatile LONG CleanupRunning;

    //
    // Statistics
    //
    struct {
        volatile LONG64 EventsProcessed;
        volatile LONG64 ChainsCreated;
        volatile LONG64 ChainsExpired;
        volatile LONG64 AttacksConfirmed;
        LARGE_INTEGER StartTime;
    } Stats;
} ACT_TRACKER, *PACT_TRACKER;

//
// Public API - Initialization
//

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ActInitialize(
    _Out_ PACT_TRACKER* Tracker
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ActShutdown(
    _Inout_ PACT_TRACKER Tracker
    );

//
// Public API - Callback Registration
//

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ActRegisterCallback(
    _In_ PACT_TRACKER Tracker,
    _In_ ACT_CHAIN_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
ActUnregisterCallback(
    _In_ PACT_TRACKER Tracker
    );

//
// Public API - Event Submission
//

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
ActSubmitEvent(
    _In_ PACT_TRACKER Tracker,
    _In_ ULONG Technique,
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ProcessName,
    _In_reads_bytes_opt_(EvidenceSize) PVOID Evidence,
    _In_ SIZE_T EvidenceSize
    );

//
// Public API - Chain Queries
// All functions that return chains add a reference.
// Caller MUST call ActReleaseChain when done.
//

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ActGetChain(
    _In_ PACT_TRACKER Tracker,
    _In_ PGUID ChainId,
    _Outptr_ PACT_ATTACK_CHAIN* Chain
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ActCorrelateEvents(
    _In_ PACT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Outptr_ PACT_ATTACK_CHAIN* Chain
    );

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ActGetActiveChains(
    _In_ PACT_TRACKER Tracker,
    _Out_writes_to_(MaxChains, *ChainCount) PACT_ATTACK_CHAIN* Chains,
    _In_ ULONG MaxChains,
    _Out_ PULONG ChainCount
    );

//
// Public API - Chain Lifetime Management
//

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ActReferenceChain(
    _In_ PACT_ATTACK_CHAIN Chain
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ActReleaseChain(
    _In_ PACT_ATTACK_CHAIN Chain
    );

#ifdef __cplusplus
}
#endif
