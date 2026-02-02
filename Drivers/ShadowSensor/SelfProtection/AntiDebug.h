/*++
    ShadowStrike Next-Generation Antivirus
    Module: AntiDebug.h - Anti-debugging protection
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define ADB_POOL_TAG 'BDBA'

typedef enum _ADB_DEBUG_ATTEMPT {
    AdbAttempt_None = 0,
    AdbAttempt_KernelDebugger,
    AdbAttempt_UserDebugger,
    AdbAttempt_DriverVerifier,
    AdbAttempt_Hypervisor,
    AdbAttempt_VMIntrospection,
    AdbAttempt_MemoryDump,
    AdbAttempt_BreakpointSet,
    AdbAttempt_StepExecution,
} ADB_DEBUG_ATTEMPT;

typedef struct _ADB_DEBUG_EVENT {
    ADB_DEBUG_ATTEMPT Type;
    HANDLE ProcessId;
    UNICODE_STRING ProcessName;
    
    // Details
    PVOID TargetAddress;
    CHAR Details[256];
    
    LARGE_INTEGER Timestamp;
    BOOLEAN WasBlocked;
    LIST_ENTRY ListEntry;
} ADB_DEBUG_EVENT, *PADB_DEBUG_EVENT;

typedef BOOLEAN (*ADB_DEBUG_CALLBACK)(
    _In_ ADB_DEBUG_ATTEMPT AttemptType,
    _In_opt_ PVOID Details,
    _In_opt_ PVOID Context
);

typedef struct _ADB_PROTECTOR {
    BOOLEAN Initialized;
    
    // Detection state
    BOOLEAN KernelDebuggerPresent;
    BOOLEAN HypervisorPresent;
    BOOLEAN VerifierEnabled;
    
    // Protection settings
    BOOLEAN BlockDebugger;
    BOOLEAN BlockMemoryDump;
    BOOLEAN BlockBreakpoints;
    
    // Callback
    ADB_DEBUG_CALLBACK UserCallback;
    PVOID CallbackContext;
    
    // Events
    LIST_ENTRY EventList;
    KSPIN_LOCK EventLock;
    ULONG EventCount;
    
    // Periodic check
    KTIMER CheckTimer;
    KDPC CheckDpc;
    
    struct {
        volatile LONG64 DebugAttempts;
        volatile LONG64 AttemptsBlocked;
        LARGE_INTEGER StartTime;
    } Stats;
} ADB_PROTECTOR, *PADB_PROTECTOR;

NTSTATUS AdbInitialize(_Out_ PADB_PROTECTOR* Protector);
VOID AdbShutdown(_Inout_ PADB_PROTECTOR Protector);
NTSTATUS AdbRegisterCallback(_In_ PADB_PROTECTOR Protector, _In_ ADB_DEBUG_CALLBACK Callback, _In_opt_ PVOID Context);
NTSTATUS AdbCheckForDebugger(_In_ PADB_PROTECTOR Protector, _Out_ PBOOLEAN DebuggerPresent);
NTSTATUS AdbCheckForHypervisor(_In_ PADB_PROTECTOR Protector, _Out_ PBOOLEAN HypervisorPresent);
NTSTATUS AdbEnableProtection(_In_ PADB_PROTECTOR Protector, _In_ BOOLEAN BlockDebugger, _In_ BOOLEAN BlockDump, _In_ BOOLEAN BlockBreakpoints);
NTSTATUS AdbGetEvents(_In_ PADB_PROTECTOR Protector, _Out_writes_to_(Max, *Count) PADB_DEBUG_EVENT* Events, _In_ ULONG Max, _Out_ PULONG Count);

#ifdef __cplusplus
}
#endif
