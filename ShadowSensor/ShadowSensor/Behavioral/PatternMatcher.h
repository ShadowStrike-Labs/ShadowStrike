/*++
    ShadowStrike Next-Generation Antivirus
    Module: PatternMatcher.h - Behavioral pattern matching
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define PM_POOL_TAG 'MPMP'
#define PM_MAX_PATTERN_LENGTH 256
#define PM_MAX_EVENTS_PER_PATTERN 32

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
} PM_EVENT_TYPE;

typedef struct _PM_EVENT_CONSTRAINT {
    PM_EVENT_TYPE Type;
    
    // Constraints
    CHAR ProcessNamePattern[64];        // Regex
    CHAR PathPattern[256];              // Regex
    CHAR ValuePattern[128];             // For registry
    
    // Timing
    ULONG MaxTimeFromPrevious;          // Max ms from previous event (0 = no constraint)
    ULONG MinTimeFromPrevious;
    
    // Flags
    BOOLEAN Optional;                   // Pattern matches even if this event doesn't occur
    BOOLEAN Terminal;                   // Pattern complete when this matches
    
} PM_EVENT_CONSTRAINT, *PPM_EVENT_CONSTRAINT;

typedef struct _PM_PATTERN {
    CHAR PatternId[32];
    CHAR PatternName[64];
    CHAR Description[256];
    
    // Event sequence
    PM_EVENT_CONSTRAINT Events[PM_MAX_EVENTS_PER_PATTERN];
    ULONG EventCount;
    
    // Match settings
    BOOLEAN RequireExactOrder;
    ULONG MaxTotalTimeMs;               // Max time for full pattern
    ULONG MinMatchedEvents;             // Minimum events to match
    
    // Scoring
    ULONG ThreatScore;
    CHAR MITRETechnique[16];
    
    volatile LONG64 MatchCount;
    LIST_ENTRY ListEntry;
} PM_PATTERN, *PPM_PATTERN;

typedef struct _PM_MATCH_STATE {
    PPM_PATTERN Pattern;
    HANDLE ProcessId;
    
    // Match progress
    ULONG CurrentEventIndex;
    ULONG MatchedEvents;
    
    // Timing
    LARGE_INTEGER FirstEventTime;
    LARGE_INTEGER LastEventTime;
    
    // Match complete?
    BOOLEAN IsComplete;
    ULONG ConfidenceScore;
    
    LIST_ENTRY ListEntry;
} PM_MATCH_STATE, *PPM_MATCH_STATE;

typedef VOID (*PM_MATCH_CALLBACK)(
    _In_ PPM_PATTERN Pattern,
    _In_ PPM_MATCH_STATE State,
    _In_opt_ PVOID Context
);

typedef struct _PM_MATCHER {
    BOOLEAN Initialized;
    
    // Patterns
    LIST_ENTRY PatternList;
    EX_PUSH_LOCK PatternLock;
    ULONG PatternCount;
    
    // Active match states
    LIST_ENTRY StateList;
    KSPIN_LOCK StateLock;
    volatile LONG StateCount;
    
    // Callback
    PM_MATCH_CALLBACK Callback;
    PVOID CallbackContext;
    
    struct {
        volatile LONG64 EventsProcessed;
        volatile LONG64 PatternsMatched;
        LARGE_INTEGER StartTime;
    } Stats;
} PM_MATCHER, *PPM_MATCHER;

NTSTATUS PmInitialize(_Out_ PPM_MATCHER* Matcher);
VOID PmShutdown(_Inout_ PPM_MATCHER Matcher);
NTSTATUS PmLoadPattern(_In_ PPM_MATCHER Matcher, _In_ PPM_PATTERN Pattern);
NTSTATUS PmRegisterCallback(_In_ PPM_MATCHER Matcher, _In_ PM_MATCH_CALLBACK Callback, _In_opt_ PVOID Context);
NTSTATUS PmSubmitEvent(_In_ PPM_MATCHER Matcher, _In_ PM_EVENT_TYPE Type, _In_ HANDLE ProcessId, _In_opt_ PUNICODE_STRING Path, _In_opt_ PCSTR Value);
NTSTATUS PmGetActiveStates(_In_ PPM_MATCHER Matcher, _In_ HANDLE ProcessId, _Out_writes_to_(Max, *Count) PPM_MATCH_STATE* States, _In_ ULONG Max, _Out_ PULONG Count);
VOID PmFreeState(_In_ PPM_MATCH_STATE State);

#ifdef __cplusplus
}
#endif
