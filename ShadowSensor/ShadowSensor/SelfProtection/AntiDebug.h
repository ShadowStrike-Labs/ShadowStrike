/*++
    ShadowStrike Next-Generation Antivirus
    Module: AntiDebug.h - Anti-debugging detection & alerting

    Architecture:
    - EX_PUSH_LOCK for all synchronization (IRQL <= APC_LEVEL)
    - EX_RUNDOWN_REF for safe shutdown (all public APIs acquire rundown)
    - Work-item based periodic checks (no raw DPC event processing)
    - Value-type event snapshots returned to callers (no internal pointers exposed)
    - Detect-and-alert model: detects debugging/VM/verifier presence,
      logs events, and invokes callback. Does NOT block kernel debugger
      attachment (which is not possible from a driver).

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define ADB_POOL_TAG_CTX    'cBDA'   // ADB_PROTECTOR context
#define ADB_POOL_TAG_EVENT  'eBDA'   // Internal ADB_EVENT nodes

// ============================================================================
// LIMITS
// ============================================================================

#define ADB_MAX_PROCESS_NAME    260
#define ADB_MAX_DETAIL_LENGTH   256
#define ADB_MAX_EVENTS          1024   // Cap internal event list
#define ADB_CHECK_INTERVAL_SEC  30     // Periodic check interval

// ============================================================================
// ENUMERATIONS
// ============================================================================

typedef enum _ADB_DEBUG_ATTEMPT {
    AdbAttemptNone = 0,
    AdbAttemptKernelDebugger,       // KD_DEBUGGER_ENABLED detected
    AdbAttemptUserDebugger,         // DebugPort on our process
    AdbAttemptDriverVerifier,       // Driver Verifier enabled on our driver
    AdbAttemptHypervisor,           // Hypervisor/VM detected
    AdbAttemptVMIntrospection,      // VM introspection artifacts
    AdbAttemptMemoryDump,           // Crash dump configuration change
    AdbAttemptMax
} ADB_DEBUG_ATTEMPT;

// ============================================================================
// EVENT SNAPSHOT (returned to callers — self-contained value type)
// ============================================================================

typedef struct _ADB_EVENT_INFO {
    ADB_DEBUG_ATTEMPT   Type;
    HANDLE              ProcessId;
    WCHAR               ProcessName[ADB_MAX_PROCESS_NAME];
    USHORT              ProcessNameLength;  // In characters, not bytes
    CHAR                Details[ADB_MAX_DETAIL_LENGTH];
    LARGE_INTEGER       Timestamp;
    BOOLEAN             WasBlocked;
} ADB_EVENT_INFO, *PADB_EVENT_INFO;

// ============================================================================
// CALLBACK TYPE
// ============================================================================

//
// Callback invoked on each debug/VM detection event.
// Called at IRQL <= APC_LEVEL with NO locks held.
// Must NOT call back into ADB APIs (deadlock risk).
// Returns TRUE to log the event, FALSE to suppress.
//
// LIFETIME CONTRACT: The callback function pointer and Context must remain
// valid (in memory, not unloaded) until AdbShutdown() returns. The caller
// must NOT unload the module containing the callback before shutdown.
// To deregister, call AdbRegisterCallback(Protector, NULL, NULL) — this
// guarantees no further invocations after it returns.
//
typedef BOOLEAN (ADB_DEBUG_CALLBACK)(
    _In_ ADB_DEBUG_ATTEMPT  AttemptType,
    _In_ PADB_EVENT_INFO    EventInfo,
    _In_opt_ PVOID          Context
);
typedef ADB_DEBUG_CALLBACK *PADB_DEBUG_CALLBACK;

// ============================================================================
// STATISTICS
// ============================================================================

typedef struct _ADB_STATISTICS {
    volatile LONG64     TotalDetections;
    volatile LONG64     CallbackInvocations;
    LONG                CurrentEventCount;
    BOOLEAN             KernelDebuggerPresent;
    BOOLEAN             HypervisorPresent;
    BOOLEAN             VerifierEnabled;
    LARGE_INTEGER       LastCheckTime;
    LARGE_INTEGER       StartTime;
} ADB_STATISTICS, *PADB_STATISTICS;

// ============================================================================
// PROTECTOR CONTEXT (opaque to callers except for type name)
// ============================================================================

typedef struct _ADB_PROTECTOR {
    volatile LONG       Initialized;

    // Shutdown synchronization
    EX_RUNDOWN_REF      RundownRef;

    // Detection state — written atomically, read atomically
    volatile LONG       KernelDebuggerPresent;
    volatile LONG       HypervisorPresent;
    volatile LONG       VerifierEnabled;
    volatile LONG       CrashDumpEnabled;   // Complete memory dump (type 1)

    // Callback — set via InterlockedExchangePointer
    PADB_DEBUG_CALLBACK UserCallback;
    PVOID               CallbackContext;
    EX_PUSH_LOCK        CallbackLock;   // Protects callback registration

    // Event list — protected by EventLock (push lock, <= APC_LEVEL)
    LIST_ENTRY          EventList;
    EX_PUSH_LOCK        EventLock;
    volatile LONG       EventCount;

    // Periodic check — work-item based (not raw DPC)
    PIO_WORKITEM        CheckWorkItem;
    KTIMER              CheckTimer;
    KDPC                CheckDpc;       // DPC just queues the work item
    volatile LONG       TimerActive;
    volatile LONG       ShutdownRequested;
    PDEVICE_OBJECT      DeviceObject;   // For IoAllocateWorkItem

    // Statistics
    ADB_STATISTICS      Stats;
} ADB_PROTECTOR, *PADB_PROTECTOR;

// ============================================================================
// RUNDOWN MACROS
// ============================================================================

#define ADB_ACQUIRE_RUNDOWN(p)  ExAcquireRundownProtection(&(p)->RundownRef)
#define ADB_RELEASE_RUNDOWN(p)  ExReleaseRundownProtection(&(p)->RundownRef)

// ============================================================================
// PUBLIC API
// ============================================================================

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
AdbInitialize(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PADB_PROTECTOR *Protector
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
AdbShutdown(
    _Inout_ PADB_PROTECTOR Protector
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
AdbRegisterCallback(
    _In_ PADB_PROTECTOR Protector,
    _In_opt_ PADB_DEBUG_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
AdbCheckForDebugger(
    _In_ PADB_PROTECTOR Protector,
    _Out_ PBOOLEAN DebuggerPresent
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
AdbCheckForHypervisor(
    _In_ PADB_PROTECTOR Protector,
    _Out_ PBOOLEAN HypervisorPresent
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
AdbGetEvents(
    _In_ PADB_PROTECTOR Protector,
    _Out_writes_to_(MaxEvents, *ReturnedCount) PADB_EVENT_INFO EventArray,
    _In_ ULONG MaxEvents,
    _Out_ PULONG ReturnedCount
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
AdbGetStatistics(
    _In_ PADB_PROTECTOR Protector,
    _Out_ PADB_STATISTICS Stats
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
AdbClearEvents(
    _In_ PADB_PROTECTOR Protector
    );

#ifdef __cplusplus
}
#endif
