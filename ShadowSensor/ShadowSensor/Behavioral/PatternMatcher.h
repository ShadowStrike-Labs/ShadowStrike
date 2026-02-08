/*++
    ShadowStrike Next-Generation Antivirus
    Module: PatternMatcher.h - Behavioral pattern matching
    Copyright (c) ShadowStrike Team

    Enterprise-grade behavioral pattern matching engine for attack detection.
    Thread-safe, IRQL-aware, with proper synchronization primitives.
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <ntstrsafe.h>

//
// Pool tags
//
#define PM_POOL_TAG                     'MPMP'
#define PM_POOL_TAG_STATE               'tSMP'
#define PM_POOL_TAG_INDEX               'xIMP'
#define PM_POOL_TAG_WORKITEM            'wIMP'

//
// Limits
//
#define PM_MAX_PATTERN_LENGTH           256
#define PM_MAX_EVENTS_PER_PATTERN       32
#define PM_MAX_PROCESS_NAME_LENGTH      64
#define PM_MAX_PATH_PATTERN_LENGTH      256
#define PM_MAX_VALUE_PATTERN_LENGTH     128
#define PM_MAX_PATTERN_ID_LENGTH        32
#define PM_MAX_PATTERN_NAME_LENGTH      64
#define PM_MAX_DESCRIPTION_LENGTH       256
#define PM_MAX_MITRE_TECHNIQUE_LENGTH   16

//
// Event types for behavioral pattern matching
//
typedef enum _PM_EVENT_TYPE {
    PmEvent_ProcessCreate = 0,
    PmEvent_ProcessTerminate,
    PmEvent_ThreadCreate,
    PmEvent_ThreadTerminate,
    PmEvent_ImageLoad,
    PmEvent_FileCreate,
    PmEvent_FileWrite,
    PmEvent_FileDelete,
    PmEvent_RegistryCreate,
    PmEvent_RegistryWrite,
    PmEvent_RegistryDelete,
    PmEvent_NetworkConnect,
    PmEvent_NetworkListen,
    PmEvent_MemoryAllocate,
    PmEvent_MemoryProtect,
    PmEvent_HandleDuplicate,
    PmEvent_Custom,
    PmEvent_MaxType
} PM_EVENT_TYPE;

//
// Event constraint for pattern matching
//
typedef struct _PM_EVENT_CONSTRAINT {
    PM_EVENT_TYPE Type;

    //
    // Pattern constraints (wildcard patterns with * and ?)
    //
    CHAR ProcessNamePattern[PM_MAX_PROCESS_NAME_LENGTH];
    CHAR PathPattern[PM_MAX_PATH_PATTERN_LENGTH];
    CHAR ValuePattern[PM_MAX_VALUE_PATTERN_LENGTH];

    //
    // Timing constraints (in milliseconds)
    // Uses monotonic time to prevent manipulation
    //
    ULONG MaxTimeFromPrevious;          // Max ms from previous event (0 = no constraint)
    ULONG MinTimeFromPrevious;          // Min ms from previous event (0 = no constraint)

    //
    // Behavioral flags
    //
    BOOLEAN Optional;                   // Pattern matches even if this event doesn't occur
    BOOLEAN Terminal;                   // Pattern complete when this matches

} PM_EVENT_CONSTRAINT, *PPM_EVENT_CONSTRAINT;

//
// Behavioral pattern definition
//
typedef struct _PM_PATTERN {
    CHAR PatternId[PM_MAX_PATTERN_ID_LENGTH];
    CHAR PatternName[PM_MAX_PATTERN_NAME_LENGTH];
    CHAR Description[PM_MAX_DESCRIPTION_LENGTH];

    //
    // Event sequence definition
    //
    PM_EVENT_CONSTRAINT Events[PM_MAX_EVENTS_PER_PATTERN];
    ULONG EventCount;

    //
    // Match settings
    //
    BOOLEAN RequireExactOrder;          // Events must occur in defined order
    ULONG MaxTotalTimeMs;               // Max time window for full pattern (0 = unlimited)
    ULONG MinMatchedEvents;             // Minimum events to trigger match (0 = all required)

    //
    // Threat scoring
    //
    ULONG ThreatScore;                  // 0-100 severity score
    CHAR MITRETechnique[PM_MAX_MITRE_TECHNIQUE_LENGTH];

    //
    // Statistics (lock-free updates)
    //
    volatile LONG64 MatchCount;

    //
    // List linkage (protected by PatternLock)
    //
    LIST_ENTRY ListEntry;

} PM_PATTERN, *PPM_PATTERN;

//
// Match state for tracking partial pattern matches
//
typedef struct _PM_MATCH_STATE {
    PPM_PATTERN Pattern;
    HANDLE ProcessId;

    //
    // Match progress
    //
    ULONG CurrentEventIndex;            // Next expected event index
    ULONG MatchedEvents;                // Count of matched events

    //
    // Timing (monotonic)
    //
    LARGE_INTEGER FirstEventTime;       // Performance counter at first event
    LARGE_INTEGER LastEventTime;        // Performance counter at last event

    //
    // Completion status
    //
    BOOLEAN IsComplete;
    ULONG ConfidenceScore;              // 0-100 confidence

    //
    // List linkage (protected by StateLock)
    //
    LIST_ENTRY ListEntry;

} PM_MATCH_STATE, *PPM_MATCH_STATE;

//
// Match callback function type
// Called at PASSIVE_LEVEL when pattern match is complete
//
typedef VOID (*PM_MATCH_CALLBACK)(
    _In_ PPM_PATTERN Pattern,
    _In_ PPM_MATCH_STATE State,
    _In_opt_ PVOID Context
);

//
// Callback registration structure for atomic updates
//
typedef struct _PM_CALLBACK_REGISTRATION {
    PM_MATCH_CALLBACK Callback;
    PVOID Context;
} PM_CALLBACK_REGISTRATION, *PPM_CALLBACK_REGISTRATION;

//
// Pattern matcher instance
//
typedef struct _PM_MATCHER {
    //
    // Initialization state
    //
    volatile BOOLEAN Initialized;
    volatile BOOLEAN ShuttingDown;

    //
    // Pattern storage
    //
    LIST_ENTRY PatternList;
    EX_PUSH_LOCK PatternLock;
    volatile LONG PatternCount;

    //
    // Active match states
    // Using push lock instead of spinlock to allow PASSIVE_LEVEL operations
    //
    LIST_ENTRY StateList;
    EX_PUSH_LOCK StateLock;
    volatile LONG StateCount;

    //
    // Callback (atomic structure for thread-safe updates)
    //
    volatile PM_CALLBACK_REGISTRATION CallbackReg;
    EX_PUSH_LOCK CallbackLock;

    //
    // Performance counter frequency for timing
    //
    LARGE_INTEGER PerformanceFrequency;

    //
    // Statistics
    //
    struct {
        volatile LONG64 EventsProcessed;
        volatile LONG64 PatternsMatched;
        volatile LONG64 StatesCreated;
        volatile LONG64 StatesCleanedUp;
        LARGE_INTEGER StartTime;
    } Stats;

} PM_MATCHER, *PPM_MATCHER;

//
// Public API functions
//

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PmInitialize(
    _Out_ PPM_MATCHER* Matcher
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
PmShutdown(
    _Inout_ PPM_MATCHER Matcher
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PmLoadPattern(
    _In_ PPM_MATCHER Matcher,
    _In_ PPM_PATTERN Pattern
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PmUnloadPattern(
    _In_ PPM_MATCHER Matcher,
    _In_ PCSTR PatternId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PmRegisterCallback(
    _In_ PPM_MATCHER Matcher,
    _In_opt_ PM_MATCH_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PmSubmitEvent(
    _In_ PPM_MATCHER Matcher,
    _In_ PM_EVENT_TYPE Type,
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING Path,
    _In_opt_ PCSTR Value
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PmGetActiveStates(
    _In_ PPM_MATCHER Matcher,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(MaxStates, *StateCount) PPM_MATCH_STATE* States,
    _In_ ULONG MaxStates,
    _Out_ PULONG StateCount
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
PmReleaseState(
    _In_ PPM_MATCHER Matcher,
    _In_ PPM_MATCH_STATE State
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
PmCleanupProcessStates(
    _In_ PPM_MATCHER Matcher,
    _In_ HANDLE ProcessId
    );

#ifdef __cplusplus
}
#endif
