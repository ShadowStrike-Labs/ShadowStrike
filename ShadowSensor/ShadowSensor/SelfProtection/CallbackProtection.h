/*++
    ShadowStrike Next-Generation Antivirus
    Module: CallbackProtection.h - Callback registration protection

    Purpose: Protects kernel callback registrations (process, thread, image,
             registry, object, minifilter, WFP, ETW) against tampering by
             hashing the callback code region and periodically verifying
             integrity.

    Architecture:
    - CP_PROTECTOR is opaque; internal state defined only in .c.
    - All public APIs run at IRQL PASSIVE_LEVEL.
    - Single EX_PUSH_LOCK for the callback list (always bracketed
      with KeEnterCriticalRegion / KeLeaveCriticalRegion).
    - EX_RUNDOWN_REF on all APIs to prevent teardown during in-flight ops.
    - Periodic timer DPC queues a PASSIVE_LEVEL work item for verification;
      DPC itself does no lock acquisition or callback invocation.
    - Tamper notification callback is always invoked at PASSIVE_LEVEL.

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

// ============================================================================
// Pool Tags & Limits
// ============================================================================

#define CP_POOL_TAG             'ORPC'
#define CP_POOL_TAG_ENTRY       'eRPC'
#define CP_MAX_CALLBACKS        256
#define CP_CALLBACK_HASH_BYTES  256     // bytes of code hashed per callback

// ============================================================================
// Callback type enumeration
// ============================================================================

typedef enum _CP_CALLBACK_TYPE {
    CpCallback_Process = 0,
    CpCallback_Thread,
    CpCallback_Image,
    CpCallback_Registry,
    CpCallback_Object,
    CpCallback_Minifilter,
    CpCallback_WFP,
    CpCallback_ETW,
    CpCallback_MaxType
} CP_CALLBACK_TYPE;

// ============================================================================
// Tamper notification callback — always invoked at PASSIVE_LEVEL
// ============================================================================

typedef VOID (*CP_TAMPER_CALLBACK)(
    _In_ CP_CALLBACK_TYPE Type,
    _In_ PVOID Registration,
    _In_opt_ PVOID Context
    );

// ============================================================================
// Opaque protector handle
// ============================================================================

typedef struct _CP_PROTECTOR CP_PROTECTOR, *PCP_PROTECTOR;

// ============================================================================
// Statistics (read-only snapshot)
// ============================================================================

typedef struct _CP_STATISTICS {
    LONG64 CallbacksProtected;
    LONG64 TamperAttempts;
    LONG64 CallbacksRestored;
    LONG64 VerificationsRun;
    ULONG CallbackCount;
    LARGE_INTEGER UpTime;
} CP_STATISTICS, *PCP_STATISTICS;

// ============================================================================
// Public API — all PASSIVE_LEVEL only
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CpInitialize(
    _Out_ PCP_PROTECTOR* Protector
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
CpShutdown(
    _Inout_ PCP_PROTECTOR Protector
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CpProtectCallback(
    _In_ PCP_PROTECTOR Protector,
    _In_ CP_CALLBACK_TYPE Type,
    _In_ PVOID Registration,
    _In_ PVOID Callback
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CpUnprotectCallback(
    _In_ PCP_PROTECTOR Protector,
    _In_ PVOID Registration
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CpRegisterTamperCallback(
    _In_ PCP_PROTECTOR Protector,
    _In_ CP_TAMPER_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CpEnablePeriodicVerify(
    _In_ PCP_PROTECTOR Protector,
    _In_ ULONG IntervalMs
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CpDisablePeriodicVerify(
    _In_ PCP_PROTECTOR Protector
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CpVerifyAll(
    _In_ PCP_PROTECTOR Protector,
    _Out_ PULONG TamperedCount
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CpGetStatistics(
    _In_ PCP_PROTECTOR Protector,
    _Out_ PCP_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
