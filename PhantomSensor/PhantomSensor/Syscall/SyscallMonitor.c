/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/*++
    ShadowStrike Next-Generation Antivirus
    Module: SyscallMonitor.c - Syscall Monitoring Orchestration Layer

    This module is the top-level orchestrator for all syscall monitoring.
    It delegates ALL specialized detection work to dedicated sub-modules:

        SyscallTable           - Syscall number/name/metadata resolution
        SyscallHooks           - Hook registration and callback dispatch
        NtdllIntegrity         - NTDLL tampering/hook detection
        HeavensGateDetector    - WoW64 abuse detection
        DirectSyscallDetector  - Direct/indirect syscall technique detection
        CallstackAnalyzer      - Call stack capture and anomaly analysis

    SyscallMonitor owns the POLICY (what to monitor, when to block, event
    emission) while the sub-modules own their respective DETECTION DOMAINS.

    Copyright (c) ShadowStrike Team
--*/

#include "SyscallMonitor.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/ProcessUtils.h"
#include "../Behavioral/BehaviorEngine.h"

//
// WDK-exported but not declared in public headers
//
NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(
    _In_ PEPROCESS Process
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
    );

// ============================================================================
// Internal Constants
// ============================================================================

#define SC_MAGIC                        0x53434D4E  // 'SCMN'
//
// Shutdown drain is INFINITE — we MUST wait for all in-flight operations
// to complete before freeing sub-modules and process contexts. A timeout
// here leads to use-after-free and BSOD under adversarial load.
//

//
// NTDLL integrity is expensive. Check interval is randomized per-process
// in [SC_NTDLL_CHECK_MIN, SC_NTDLL_CHECK_MAX) to prevent timing attacks.
//
#define SC_NTDLL_CHECK_MIN              200
#define SC_NTDLL_CHECK_MAX              800

//
// Threat score thresholds
//
#define SC_SCORE_BLOCK_THRESHOLD        700
#define SC_SCORE_ALERT_THRESHOLD        400

//
// User-mode address range for basic sanity
//
#define SC_MAX_USER_ADDRESS             0x7FFFFFFFFFFFULL
#define SC_MIN_USER_ADDRESS             0x10000ULL

// ============================================================================
// Module-Scoped Init Flags (for rollback on partial init)
// ============================================================================

#define SC_INIT_LOOKASIDE_CONTEXT       0x00000001
#define SC_INIT_LOOKASIDE_EVENT         0x00000002
#define SC_INIT_SYSCALL_TABLE           0x00000004
#define SC_INIT_SYSCALL_HOOKS           0x00000008
#define SC_INIT_NTDLL_INTEGRITY         0x00000010
#define SC_INIT_HEAVENS_GATE            0x00000020
#define SC_INIT_DIRECT_SYSCALL          0x00000040
#define SC_INIT_CALLSTACK_ANALYZER      0x00000080

// ============================================================================
// Global State
// ============================================================================

static SYSCALL_MONITOR_GLOBALS g_ScState = { 0 };

// ============================================================================
// Forward Declarations
// ============================================================================

static VOID ScpAcquireReference(VOID);
static VOID ScpReleaseReference(VOID);

static NTSTATUS ScpAllocateProcessContext(_Out_ PSC_PROCESS_CONTEXT* Context);
static VOID ScpFreeProcessContext(_In_ PSC_PROCESS_CONTEXT Context);
static PSC_PROCESS_CONTEXT ScpFindProcessContextLocked(_In_ UINT32 ProcessId);
static NTSTATUS ScpCreateProcessContext(_In_ UINT32 ProcessId, _Out_ PSC_PROCESS_CONTEXT* Context);
static VOID ScpPopulateProcessNtdllInfo(_Inout_ PSC_PROCESS_CONTEXT Context);
static BOOLEAN ScpIsAddressInRange(_In_ UINT64 Address, _In_ UINT64 Base, _In_ UINT64 Size);
static VOID ScpAddSuspiciousCaller(_Inout_ PSC_PROCESS_CONTEXT Context, _In_ UINT64 CallerAddress);

static VOID ScpEmitEvasionEvent(
    _In_ UINT32 ProcessId,
    _In_ UINT32 SyscallNumber,
    _In_ UINT32 DetectionFlags,
    _In_ UINT32 ThreatScore,
    _In_ BOOLEAN ShouldBlock
    );

static VOID ScpCleanupByFlags(_In_ ULONG InitFlags);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ScMonitorInitialize)
#pragma alloc_text(PAGE, ScMonitorShutdown)
#pragma alloc_text(PAGE, ScMonitorSetEnabled)
#pragma alloc_text(PAGE, ScMonitorAnalyzeSyscall)
#pragma alloc_text(PAGE, ScMonitorGetProcessContext)
#pragma alloc_text(PAGE, ScMonitorRemoveProcessContext)
#pragma alloc_text(PAGE, ScMonitorVerifyNtdllIntegrity)
#pragma alloc_text(PAGE, ScMonitorGetNtdllHooks)
#pragma alloc_text(PAGE, ScMonitorRestoreNtdllFunction)
#pragma alloc_text(PAGE, ScMonitorAnalyzeCallStack)
#pragma alloc_text(PAGE, ScMonitorDetectHeavensGate)
#pragma alloc_text(PAGE, ScMonitorGetProcessStats)
#endif

// ============================================================================
// Reference Counting
// ============================================================================

static
VOID
ScpAcquireReference(VOID)
{
    InterlockedIncrement(&g_ScState.ReferenceCount);
}

static
VOID
ScpReleaseReference(VOID)
{
    LONG newCount = InterlockedDecrement(&g_ScState.ReferenceCount);
    if (newCount == 0) {
        KeSetEvent(&g_ScState.ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// Initialization / Shutdown
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ScMonitorInitialize(VOID)
{
    NTSTATUS status;
    ULONG initFlags = 0;

    PAGED_CODE();

    if (g_ScState.Initialized) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(&g_ScState, sizeof(g_ScState));

    g_ScState.Magic = SC_MAGIC;
    g_ScState.ReferenceCount = 1;
    KeInitializeEvent(&g_ScState.ShutdownEvent, NotificationEvent, FALSE);

    InitializeListHead(&g_ScState.ProcessContextList);
    ExInitializePushLock(&g_ScState.ProcessLock);

    InitializeListHead(&g_ScState.KnownGoodCallers);
    ExInitializePushLock(&g_ScState.CallerCacheLock);

    //
    // Lookaside lists for hot-path allocations
    //
    ExInitializeNPagedLookasideList(
        &g_ScState.ContextLookaside,
        NULL, NULL,
        POOL_NX_ALLOCATION,
        sizeof(SC_PROCESS_CONTEXT),
        SC_POOL_TAG_GENERAL,
        0
        );
    initFlags |= SC_INIT_LOOKASIDE_CONTEXT;

    ExInitializeNPagedLookasideList(
        &g_ScState.EventLookaside,
        NULL, NULL,
        POOL_NX_ALLOCATION,
        sizeof(SYSCALL_CALL_CONTEXT),
        SC_POOL_TAG_EVENT,
        0
        );
    initFlags |= SC_INIT_LOOKASIDE_EVENT;
    g_ScState.ContextLookasideInitialized = TRUE;
    g_ScState.EventLookasideInitialized = TRUE;

    //
    // Step 1: Syscall Table
    //
    status = SstInitialize(&g_ScState.SyscallTableHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike-SC] SyscallTable init failed: 0x%08X\n", status);
        goto Cleanup;
    }
    initFlags |= SC_INIT_SYSCALL_TABLE;

    //
    // Step 2: Syscall Hooks
    //
    status = ShInitialize(&g_ScState.SyscallHooksFramework);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike-SC] SyscallHooks init failed: 0x%08X\n", status);
        goto Cleanup;
    }
    initFlags |= SC_INIT_SYSCALL_HOOKS;

    //
    // Step 3: NtDll Integrity
    //
    status = NiInitialize(&g_ScState.NtdllIntegrityMonitor);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike-SC] NtdllIntegrity init failed: 0x%08X\n", status);
        goto Cleanup;
    }
    initFlags |= SC_INIT_NTDLL_INTEGRITY;

    //
    // Step 4: Heaven's Gate Detector
    //
    status = HgdInitialize(&g_ScState.HeavensGateDetector);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike-SC] HeavensGateDetector init failed: 0x%08X\n", status);
        goto Cleanup;
    }
    initFlags |= SC_INIT_HEAVENS_GATE;

    //
    // Step 5: Direct Syscall Detector
    //
    status = DsdInitialize(&g_ScState.DirectSyscallDetector);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike-SC] DirectSyscallDetector init failed: 0x%08X\n", status);
        goto Cleanup;
    }
    initFlags |= SC_INIT_DIRECT_SYSCALL;

    //
    // Step 6: Callstack Analyzer
    //
    status = CsaInitialize(&g_ScState.CallstackAnalyzer);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike-SC] CallstackAnalyzer init failed: 0x%08X\n", status);
        goto Cleanup;
    }
    initFlags |= SC_INIT_CALLSTACK_ANALYZER;

    g_ScState.Initialized = TRUE;
    g_ScState.Enabled = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[ShadowStrike-SC] Syscall monitoring initialized (6 sub-modules active)\n");

    return STATUS_SUCCESS;

Cleanup:
    ScpCleanupByFlags(initFlags);
    return status;
}


_Use_decl_annotations_
VOID
ScMonitorShutdown(VOID)
{
    PLIST_ENTRY entry;
    PLIST_ENTRY next;

    PAGED_CODE();

    if (!g_ScState.Initialized || g_ScState.Magic != SC_MAGIC) {
        return;
    }

    InterlockedExchange(&g_ScState.ShuttingDown, TRUE);
    g_ScState.Initialized = FALSE;
    g_ScState.Enabled = FALSE;
    KeMemoryBarrier();

    //
    // Drain outstanding operations
    //
    KeClearEvent(&g_ScState.ShutdownEvent);
    ScpReleaseReference();

    //
    // Wait INDEFINITELY for in-flight operations to drain.
    // A timeout here would allow use-after-free when we free sub-modules
    // and process contexts below. Under adversarial load, threads may be
    // deep inside sub-module calls (NI reading process memory, CSA walking
    // stacks). We MUST wait for them to finish.
    //
    (VOID)KeWaitForSingleObject(
        &g_ScState.ShutdownEvent, Executive, KernelMode, FALSE, NULL);

    //
    // Shutdown sub-modules in reverse initialization order
    //
    if (g_ScState.CallstackAnalyzer != NULL) {
        CsaShutdown(g_ScState.CallstackAnalyzer);
        g_ScState.CallstackAnalyzer = NULL;
    }

    if (g_ScState.DirectSyscallDetector != NULL) {
        DsdShutdown(g_ScState.DirectSyscallDetector);
        g_ScState.DirectSyscallDetector = NULL;
    }

    if (g_ScState.HeavensGateDetector != NULL) {
        HgdShutdown(g_ScState.HeavensGateDetector);
        g_ScState.HeavensGateDetector = NULL;
    }

    if (g_ScState.NtdllIntegrityMonitor != NULL) {
        NiShutdown(g_ScState.NtdllIntegrityMonitor);
        g_ScState.NtdllIntegrityMonitor = NULL;
    }

    if (g_ScState.SyscallHooksFramework != NULL) {
        ShShutdown(g_ScState.SyscallHooksFramework);
        g_ScState.SyscallHooksFramework = NULL;
    }

    if (g_ScState.SyscallTableHandle != NULL) {
        SstShutdown(g_ScState.SyscallTableHandle);
        g_ScState.SyscallTableHandle = NULL;
    }

    //
    // Free all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ScState.ProcessLock);

    for (entry = g_ScState.ProcessContextList.Flink;
         entry != &g_ScState.ProcessContextList;
         entry = next) {

        next = entry->Flink;
        PSC_PROCESS_CONTEXT ctx = CONTAINING_RECORD(entry, SC_PROCESS_CONTEXT, ListEntry);
        RemoveEntryList(entry);

        if (ctx->ProcessObject != NULL) {
            ObDereferenceObject(ctx->ProcessObject);
            ctx->ProcessObject = NULL;
        }

        ExFreeToNPagedLookasideList(&g_ScState.ContextLookaside, ctx);
    }

    ExReleasePushLockExclusive(&g_ScState.ProcessLock);
    KeLeaveCriticalRegion();

    //
    // Free known-good caller cache
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ScState.CallerCacheLock);

    for (entry = g_ScState.KnownGoodCallers.Flink;
         entry != &g_ScState.KnownGoodCallers;
         entry = next) {

        next = entry->Flink;
        PSC_KNOWN_GOOD_CALLER caller =
            CONTAINING_RECORD(entry, SC_KNOWN_GOOD_CALLER, ListEntry);
        RemoveEntryList(entry);
        ShadowStrikeFreePoolWithTag(caller, SC_POOL_TAG_CACHE);
    }

    ExReleasePushLockExclusive(&g_ScState.CallerCacheLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside lists
    //
    if (g_ScState.EventLookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_ScState.EventLookaside);
        g_ScState.EventLookasideInitialized = FALSE;
    }

    if (g_ScState.ContextLookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_ScState.ContextLookaside);
        g_ScState.ContextLookasideInitialized = FALSE;
    }

    g_ScState.Magic = 0;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[ShadowStrike-SC] Syscall monitoring shutdown complete\n");
}


static
VOID
ScpCleanupByFlags(
    _In_ ULONG InitFlags
    )
{
    if (InitFlags & SC_INIT_CALLSTACK_ANALYZER) {
        if (g_ScState.CallstackAnalyzer != NULL) {
            CsaShutdown(g_ScState.CallstackAnalyzer);
            g_ScState.CallstackAnalyzer = NULL;
        }
    }
    if (InitFlags & SC_INIT_DIRECT_SYSCALL) {
        if (g_ScState.DirectSyscallDetector != NULL) {
            DsdShutdown(g_ScState.DirectSyscallDetector);
            g_ScState.DirectSyscallDetector = NULL;
        }
    }
    if (InitFlags & SC_INIT_HEAVENS_GATE) {
        if (g_ScState.HeavensGateDetector != NULL) {
            HgdShutdown(g_ScState.HeavensGateDetector);
            g_ScState.HeavensGateDetector = NULL;
        }
    }
    if (InitFlags & SC_INIT_NTDLL_INTEGRITY) {
        if (g_ScState.NtdllIntegrityMonitor != NULL) {
            NiShutdown(g_ScState.NtdllIntegrityMonitor);
            g_ScState.NtdllIntegrityMonitor = NULL;
        }
    }
    if (InitFlags & SC_INIT_SYSCALL_HOOKS) {
        if (g_ScState.SyscallHooksFramework != NULL) {
            ShShutdown(g_ScState.SyscallHooksFramework);
            g_ScState.SyscallHooksFramework = NULL;
        }
    }
    if (InitFlags & SC_INIT_SYSCALL_TABLE) {
        if (g_ScState.SyscallTableHandle != NULL) {
            SstShutdown(g_ScState.SyscallTableHandle);
            g_ScState.SyscallTableHandle = NULL;
        }
    }
    if (InitFlags & SC_INIT_LOOKASIDE_EVENT) {
        ExDeleteNPagedLookasideList(&g_ScState.EventLookaside);
    }
    if (InitFlags & SC_INIT_LOOKASIDE_CONTEXT) {
        ExDeleteNPagedLookasideList(&g_ScState.ContextLookaside);
    }
}


_Use_decl_annotations_
NTSTATUS
ScMonitorSetEnabled(
    _In_ BOOLEAN Enable
    )
{
    PAGED_CODE();

    if (!g_ScState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    g_ScState.Enabled = Enable;
    KeMemoryBarrier();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[ShadowStrike-SC] Syscall monitoring %s\n",
        Enable ? "enabled" : "disabled");

    return STATUS_SUCCESS;
}

// ============================================================================
// Process Context Management
// ============================================================================

static
NTSTATUS
ScpAllocateProcessContext(
    _Out_ PSC_PROCESS_CONTEXT* Context
    )
{
    PSC_PROCESS_CONTEXT ctx;

    *Context = NULL;

    ctx = (PSC_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_ScState.ContextLookaside);
    if (ctx == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ctx, sizeof(SC_PROCESS_CONTEXT));
    ctx->RefCount = 1;

    *Context = ctx;
    return STATUS_SUCCESS;
}


static
VOID
ScpFreeProcessContext(
    _In_ PSC_PROCESS_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    if (Context->ProcessObject != NULL) {
        ObDereferenceObject(Context->ProcessObject);
        Context->ProcessObject = NULL;
    }

    ExFreeToNPagedLookasideList(&g_ScState.ContextLookaside, Context);
}


static
PSC_PROCESS_CONTEXT
ScpFindProcessContextLocked(
    _In_ UINT32 ProcessId
    )
/*++
    Must be called while holding ProcessLock (shared or exclusive).
    Returns a referenced context or NULL.
--*/
{
    PLIST_ENTRY entry;

    for (entry = g_ScState.ProcessContextList.Flink;
         entry != &g_ScState.ProcessContextList;
         entry = entry->Flink) {

        PSC_PROCESS_CONTEXT ctx =
            CONTAINING_RECORD(entry, SC_PROCESS_CONTEXT, ListEntry);

        if (ctx->ProcessId == ProcessId && !ctx->Removed) {
            InterlockedIncrement(&ctx->RefCount);
            return ctx;
        }
    }

    return NULL;
}


static
NTSTATUS
ScpCreateProcessContext(
    _In_ UINT32 ProcessId,
    _Out_ PSC_PROCESS_CONTEXT* Context
    )
{
    NTSTATUS status;
    PSC_PROCESS_CONTEXT ctx;
    PSC_PROCESS_CONTEXT existing;
    PEPROCESS process = NULL;

    PAGED_CODE();

    *Context = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ScState.ProcessLock);

    //
    // Race check
    //
    existing = ScpFindProcessContextLocked(ProcessId);
    if (existing != NULL) {
        ExReleasePushLockExclusive(&g_ScState.ProcessLock);
        KeLeaveCriticalRegion();
        *Context = existing;
        return STATUS_SUCCESS;
    }

    if (g_ScState.ProcessContextCount >= (LONG)SC_MAX_PROCESS_CONTEXTS) {
        ExReleasePushLockExclusive(&g_ScState.ProcessLock);
        KeLeaveCriticalRegion();
        return STATUS_QUOTA_EXCEEDED;
    }

    status = ScpAllocateProcessContext(&ctx);
    if (!NT_SUCCESS(status)) {
        ExReleasePushLockExclusive(&g_ScState.ProcessLock);
        KeLeaveCriticalRegion();
        return status;
    }

    ctx->ProcessId = ProcessId;

    //
    // Reference the process object for lifetime safety.
    // If the process already exited (race between hook entry and lookup),
    // do NOT create a context — it would be permanently leaked since
    // no process-exit notification will fire for a dead PID.
    //
    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        ScpFreeProcessContext(ctx);
        ExReleasePushLockExclusive(&g_ScState.ProcessLock);
        KeLeaveCriticalRegion();
        return STATUS_PROCESS_IS_TERMINATING;
    }

    ctx->ProcessObject = process;   // Already referenced by PsLookup
    ctx->IsWoW64 = (BOOLEAN)(PsGetProcessWow64Process(process) != NULL);

    ctx->ProcessCreateTime = (UINT64)KeQueryPerformanceCounter(NULL).QuadPart;

    ScpPopulateProcessNtdllInfo(ctx);

    InsertTailList(&g_ScState.ProcessContextList, &ctx->ListEntry);
    InterlockedIncrement(&g_ScState.ProcessContextCount);

    //
    // Second reference for the caller
    //
    InterlockedIncrement(&ctx->RefCount);

    ExReleasePushLockExclusive(&g_ScState.ProcessLock);
    KeLeaveCriticalRegion();

    *Context = ctx;
    return STATUS_SUCCESS;
}


static
VOID
ScpPopulateProcessNtdllInfo(
    _Inout_ PSC_PROCESS_CONTEXT Context
    )
/*++
    Delegates to NtdllIntegrity module for NTDLL base/size.
--*/
{
    NTSTATUS status;
    PNI_PROCESS_NTDLL ntdllState = NULL;

    if (g_ScState.NtdllIntegrityMonitor == NULL) {
        return;
    }

    status = NiScanProcess(
        g_ScState.NtdllIntegrityMonitor,
        (HANDLE)(ULONG_PTR)Context->ProcessId,
        &ntdllState
        );

    if (NT_SUCCESS(status) && ntdllState != NULL) {
        Context->NtdllBase = (UINT64)(ULONG_PTR)ntdllState->NtdllBase;
        Context->NtdllSize = (UINT64)ntdllState->NtdllSize;

        //
        // Populate integrity state.
        // Do NOT set IsIntact=TRUE without actual verification.
        // The first syscall will trigger an immediate NI check (callCount==1).
        //
        Context->NtdllIntegrity.NtdllBase = Context->NtdllBase;
        Context->NtdllIntegrity.NtdllSize = Context->NtdllSize;
        Context->NtdllIntegrity.IsIntact = FALSE;

        if (ntdllState->HashValid) {
            RtlCopyMemory(
                Context->NtdllIntegrity.TextSectionHash,
                ntdllState->Hash,
                min(sizeof(Context->NtdllIntegrity.TextSectionHash),
                    sizeof(ntdllState->Hash))
                );
        }

        NiFreeState(g_ScState.NtdllIntegrityMonitor, ntdllState);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[ShadowStrike-SC] NTDLL info failed for PID %u: 0x%08X\n",
            Context->ProcessId, status);
    }
}


static
BOOLEAN
ScpIsAddressInRange(
    _In_ UINT64 Address,
    _In_ UINT64 Base,
    _In_ UINT64 Size
    )
{
    if (Size == 0 || Address < Base) {
        return FALSE;
    }
    return (Address - Base) < Size;
}


static
VOID
ScpAddSuspiciousCaller(
    _Inout_ PSC_PROCESS_CONTEXT Context,
    _In_ UINT64 CallerAddress
    )
/*++
    Adds to the circular buffer of suspicious callers.
    Uses atomic increment-first to claim slots and avoid race collisions.
--*/
{
    LONG claimed;
    UINT32 index;

    //
    // Atomically claim a slot index FIRST, then write.
    // This prevents two threads from computing the same index
    // and silently overwriting each other.
    //
    claimed = InterlockedIncrement((volatile LONG*)&Context->SuspiciousCallerCount) - 1;
    index = ((UINT32)claimed) % SC_MAX_SUSPICIOUS_CALLERS;
    Context->SuspiciousCallers[index] = CallerAddress;
}


// ============================================================================
// Public Process Context API
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ScMonitorGetProcessContext(
    _In_ UINT32 ProcessId,
    _Outptr_ PSC_PROCESS_CONTEXT* Context
    )
{
    PSC_PROCESS_CONTEXT ctx;

    PAGED_CODE();

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Context = NULL;

    if (!g_ScState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ScState.ProcessLock);
    ctx = ScpFindProcessContextLocked(ProcessId);
    ExReleasePushLockShared(&g_ScState.ProcessLock);
    KeLeaveCriticalRegion();

    if (ctx != NULL) {
        *Context = ctx;
        return STATUS_SUCCESS;
    }

    return ScpCreateProcessContext(ProcessId, Context);
}


_Use_decl_annotations_
VOID
ScMonitorReleaseProcessContext(
    _In_ PSC_PROCESS_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    if (InterlockedDecrement(&Context->RefCount) == 0) {
        ScpFreeProcessContext(Context);
    }
}


_Use_decl_annotations_
VOID
ScMonitorRemoveProcessContext(
    _In_ UINT32 ProcessId
    )
{
    PLIST_ENTRY entry;

    PAGED_CODE();

    if (!g_ScState.Initialized) {
        return;
    }

    //
    // Notify sub-modules about process exit
    //
    if (g_ScState.CallstackAnalyzer != NULL) {
        CsaOnProcessExit(g_ScState.CallstackAnalyzer,
            (HANDLE)(ULONG_PTR)ProcessId);
    }

    if (g_ScState.HeavensGateDetector != NULL) {
        HgdRemoveProcessContext(g_ScState.HeavensGateDetector,
            (HANDLE)(ULONG_PTR)ProcessId);
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ScState.ProcessLock);

    for (entry = g_ScState.ProcessContextList.Flink;
         entry != &g_ScState.ProcessContextList;
         entry = entry->Flink) {

        PSC_PROCESS_CONTEXT ctx =
            CONTAINING_RECORD(entry, SC_PROCESS_CONTEXT, ListEntry);

        if (ctx->ProcessId == ProcessId) {
            RemoveEntryList(entry);
            InterlockedDecrement(&g_ScState.ProcessContextCount);
            ctx->Removed = TRUE;

            ExReleasePushLockExclusive(&g_ScState.ProcessLock);
            KeLeaveCriticalRegion();

            //
            // Drop list reference. Last holder will free.
            //
            if (InterlockedDecrement(&ctx->RefCount) == 0) {
                ScpFreeProcessContext(ctx);
            }
            return;
        }
    }

    ExReleasePushLockExclusive(&g_ScState.ProcessLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// Core Syscall Analysis — The Orchestrator
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ScMonitorAnalyzeSyscall(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ThreadId,
    _In_ UINT32 SyscallNumber,
    _In_ UINT64 ReturnAddress,
    _In_reads_opt_(ArgumentCount) PUINT64 Arguments,
    _In_ UINT32 ArgumentCount,
    _Out_opt_ PSYSCALL_CALL_CONTEXT Context
    )
/*++
Routine Description:
    Top-level syscall analysis orchestrator. Coordinates all 6 detection
    sub-modules and produces a composite threat assessment.

    Flow:
    1. Guard checks (enabled, shutdown, valid addresses)
    2. Get/create process context
    3. SyscallTable lookup (metadata)
    4. Quick NTDLL range check
    5. Direct Syscall Detection (DSD)
    6. Heaven's Gate Detection (HGD)
    7. Callstack capture + analysis (CSA)
    8. Periodic NTDLL integrity check (NI)
    9. Dispatch to registered hooks (SH)
    10. Composite threat score + block/allow decision
    11. Behavioral event emission + statistics

Arguments:
    ProcessId      - Calling process ID.
    ThreadId       - Calling thread ID.
    SyscallNumber  - Syscall number.
    ReturnAddress  - User-mode return address of the syscall.
    Arguments      - Optional array of syscall arguments.
    ArgumentCount  - Number of arguments (max 8).
    Context        - Optional output call context.

Return Value:
    STATUS_SUCCESS       - Syscall allowed.
    STATUS_ACCESS_DENIED - Syscall blocked.
--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PSC_PROCESS_CONTEXT procCtx = NULL;
    UINT32 detectFlags = 0;
    UINT32 threatScore = 0;
    BOOLEAN fromNtdll = FALSE;
    BOOLEAN shouldBlock = FALSE;

    SST_ENTRY_INFO syscallInfo = { 0 };
    PDSD_DETECTION dsdDetection = NULL;
    PCSA_CALLSTACK csaCallstack = NULL;
    CSA_ANOMALY csaAnomalies = CsaAnomaly_None;
    ULONG csaScore = 0;

    PAGED_CODE();

    //
    // Initialize output
    //
    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(SYSCALL_CALL_CONTEXT));
        Context->SyscallNumber = SyscallNumber;
        Context->ProcessId = ProcessId;
        Context->ThreadId = ThreadId;
        Context->ReturnAddress = ReturnAddress;
        Context->Timestamp = (UINT64)KeQueryPerformanceCounter(NULL).QuadPart;

        if (Arguments != NULL && ArgumentCount > 0) {
            UINT32 count = min(ArgumentCount, 8);
            RtlCopyMemory(Context->Arguments, Arguments,
                count * sizeof(UINT64));
            Context->ArgumentCount = count;
        }
    }

    //
    // Guard: must be initialized and enabled
    //
    if (!g_ScState.Initialized || !g_ScState.Enabled || g_ScState.ShuttingDown) {
        return STATUS_SUCCESS;
    }

    //
    // Basic address sanity check
    //
    if (ReturnAddress < SC_MIN_USER_ADDRESS || ReturnAddress > SC_MAX_USER_ADDRESS) {
        detectFlags |= SC_DETECT_DIRECT_SYSCALL;
        threatScore += 300;
    }

    ScpAcquireReference();

    if (g_ScState.ShuttingDown) {
        ScpReleaseReference();
        return STATUS_SUCCESS;
    }

    //
    // Get or create process context
    //
    status = ScMonitorGetProcessContext(ProcessId, &procCtx);
    if (!NT_SUCCESS(status)) {
        ScpReleaseReference();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[ShadowStrike-SC] PID %u context failed: 0x%08X\n",
            ProcessId, status);
        return STATUS_SUCCESS;
    }

    //
    // Step 1: Syscall Table Lookup
    //
    status = SstLookupByNumber(
        g_ScState.SyscallTableHandle, SyscallNumber, &syscallInfo);

    if (!NT_SUCCESS(status)) {
        detectFlags |= SC_DETECT_DIRECT_SYSCALL;
        threatScore += 200;
    }

    //
    // Step 2: NTDLL range check (cheap — just pointer arithmetic)
    //
    if (procCtx->NtdllBase != 0 && procCtx->NtdllSize != 0) {
        fromNtdll = ScpIsAddressInRange(
            ReturnAddress, procCtx->NtdllBase, procCtx->NtdllSize);

        //
        // Also check WoW64 NTDLL for 32-bit processes
        //
        if (!fromNtdll && procCtx->IsWoW64 &&
            procCtx->Wow64NtdllBase != 0 && procCtx->Wow64NtdllSize != 0) {
            fromNtdll = ScpIsAddressInRange(
                ReturnAddress, procCtx->Wow64NtdllBase,
                procCtx->Wow64NtdllSize);
        }
    }

    if (!fromNtdll) {
        detectFlags |= SC_DETECT_DIRECT_SYSCALL;
        threatScore += 100;
    }

    if (Context != NULL) {
        Context->IsFromNtdll = fromNtdll;
    }

    //
    // Step 3: Direct Syscall Detection (delegate to DSD)
    //
    if (g_ScState.DirectSyscallDetector != NULL) {
        NTSTATUS dsdStatus = DsdAnalyzeSyscall(
            g_ScState.DirectSyscallDetector,
            (HANDLE)(ULONG_PTR)ProcessId,
            (HANDLE)(ULONG_PTR)ThreadId,
            (PVOID)(ULONG_PTR)ReturnAddress,
            SyscallNumber,
            &dsdDetection
            );

        if (NT_SUCCESS(dsdStatus) && dsdDetection != NULL) {
            detectFlags |= SC_DETECT_DIRECT_SYSCALL;
            threatScore += dsdDetection->SuspicionScore;

            if (dsdDetection->Technique == DsdTechnique_HellsGate ||
                dsdDetection->Technique == DsdTechnique_HalosGate ||
                dsdDetection->Technique == DsdTechnique_TartarusGate) {
                detectFlags |= SC_DETECT_HOOK_BYPASS;
                threatScore += 200;
            }

            if (!dsdDetection->CallFromKnownModule) {
                detectFlags |= SC_DETECT_UNBACKED_CALLER;
                threatScore += 150;
            }

            if (Context != NULL) {
                Context->IsFromKnownModule = dsdDetection->CallFromKnownModule;
                Context->CallerModuleBase = dsdDetection->CallerModuleBase;
                Context->CallerModuleSize = dsdDetection->CallerModuleSize;

                RtlCopyMemory(Context->CallerModuleName,
                    dsdDetection->CallerModuleName,
                    min(sizeof(Context->CallerModuleName),
                        sizeof(dsdDetection->CallerModuleName)));
            }

            DsdFreeDetection(dsdDetection);
            dsdDetection = NULL;
        }
    }

    //
    // Step 4: Heaven's Gate Detection (delegate to HGD)
    //
    if (g_ScState.HeavensGateDetector != NULL) {
        BOOLEAN hgdSuspicious = FALSE;
        HGD_GATE_TYPE gateType = HgdGate_None;

        NTSTATUS hgdStatus = HgdDetectSyscallOrigin(
            g_ScState.HeavensGateDetector,
            (HANDLE)(ULONG_PTR)ProcessId,
            SyscallNumber,
            (PVOID)(ULONG_PTR)ReturnAddress,
            &hgdSuspicious,
            &gateType
            );

        if (NT_SUCCESS(hgdStatus) && hgdSuspicious) {
            detectFlags |= SC_DETECT_HEAVENS_GATE;
            threatScore += 350;

            if (Context != NULL) {
                Context->IsFromWoW64 = TRUE;
            }

            //
            // Check for legitimate WoW64 transition
            //
            BOOLEAN isLegitimate = FALSE;
            HgdIsLegitimateWow64(
                g_ScState.HeavensGateDetector,
                (PVOID)(ULONG_PTR)ReturnAddress,
                &isLegitimate
                );

            if (isLegitimate) {
                detectFlags &= ~SC_DETECT_HEAVENS_GATE;
                threatScore -= min(threatScore, 300);
            }
        }
    }

    //
    // Step 5: Callstack Capture + Analysis (delegate to CSA)
    //
    // Only perform expensive analysis when we have early suspicion
    // or when the syscall itself is high-risk.
    //
    if (g_ScState.CallstackAnalyzer != NULL &&
        (detectFlags != 0 ||
         (NT_SUCCESS(status) && syscallInfo.RiskLevel >= SstRisk_High))) {

        NTSTATUS csaStatus = CsaCaptureCallstack(
            g_ScState.CallstackAnalyzer,
            (HANDLE)(ULONG_PTR)ProcessId,
            (HANDLE)(ULONG_PTR)ThreadId,
            &csaCallstack
            );

        if (NT_SUCCESS(csaStatus) && csaCallstack != NULL) {
            csaStatus = CsaAnalyzeCallstack(
                g_ScState.CallstackAnalyzer,
                csaCallstack,
                &csaAnomalies,
                &csaScore
                );

            if (NT_SUCCESS(csaStatus)) {
                if (csaAnomalies & CsaAnomaly_DirectSyscall) {
                    detectFlags |= SC_DETECT_DIRECT_SYSCALL;
                    threatScore += 100;
                }
                if (csaAnomalies & CsaAnomaly_ReturnGadget) {
                    detectFlags |= SC_DETECT_STACK_ANOMALY;
                    threatScore += 500;
                }
                if (csaAnomalies & CsaAnomaly_StackPivot) {
                    detectFlags |= SC_DETECT_STACK_ANOMALY;
                    threatScore += 400;
                }
                if (csaAnomalies & CsaAnomaly_UnbackedCode) {
                    detectFlags |= SC_DETECT_UNBACKED_CALLER;
                    threatScore += 200;
                }
                if (csaAnomalies & CsaAnomaly_RWXMemory) {
                    detectFlags |= SC_DETECT_SHELLCODE_CALLER;
                    threatScore += 250;
                }

                //
                // Copy stack frames to output context
                //
                if (Context != NULL) {
                    UINT32 count = min(csaCallstack->FrameCount, 16);
                    for (UINT32 i = 0; i < count; i++) {
                        Context->StackFrames[i] =
                            (UINT64)(ULONG_PTR)
                            csaCallstack->Frames[i].ReturnAddress;
                    }
                    Context->StackFrameCount = count;
                }
            }

            CsaFreeCallstack(csaCallstack);
            csaCallstack = NULL;
        }
    }

    //
    // Step 6: Periodic NTDLL Integrity Check (delegate to NI)
    //
    // Check interval is randomized per-process using a hash of ProcessId
    // to prevent attackers from predicting when the next check fires.
    // Also checks on the FIRST syscall (callCount==1) so newly created
    // processes are not given a free 500-syscall window.
    //
    if (g_ScState.NtdllIntegrityMonitor != NULL &&
        procCtx->NtdllBase != 0) {

        LONG64 callCount = InterlockedIncrement64(&procCtx->TotalSyscalls);

        //
        // Per-process randomized interval in [SC_NTDLL_CHECK_MIN, SC_NTDLL_CHECK_MAX)
        // Uses a simple hash of ProcessId — different per process but deterministic.
        //
        ULONG perProcessInterval = SC_NTDLL_CHECK_MIN +
            ((ProcessId * 2654435761UL) % (SC_NTDLL_CHECK_MAX - SC_NTDLL_CHECK_MIN));

        if (callCount == 1 || (callCount % perProcessInterval) == 0) {
            BOOLEAN isModified = FALSE;

            NTSTATUS niStatus = NiCompareToClean(
                g_ScState.NtdllIntegrityMonitor,
                (HANDLE)(ULONG_PTR)procCtx->ProcessId,
                &isModified
                );

            if (NT_SUCCESS(niStatus) && isModified) {
                detectFlags |= SC_DETECT_HOOK_BYPASS;
                threatScore += 300;
                procCtx->NtdllIntegrity.IsIntact = FALSE;
                procCtx->NtdllIntegrity.IsHooked = TRUE;
                InterlockedOr((volatile LONG*)&procCtx->Flags, SC_PROC_FLAG_NTDLL_MODIFIED);
            }

            procCtx->NtdllIntegrity.LastVerifyTime =
                (UINT64)KeQueryPerformanceCounter(NULL).QuadPart;
        }
    } else {
        InterlockedIncrement64(&procCtx->TotalSyscalls);
    }

    //
    // Step 7: Dispatch to registered hooks (SH framework)
    //
    if (g_ScState.SyscallHooksFramework != NULL) {
        SH_SYSCALL_CONTEXT hookCtx = { 0 };
        SH_HOOK_RESULT hookResult = ShResult_Allow;

        hookCtx.ProcessId = (HANDLE)(ULONG_PTR)ProcessId;
        hookCtx.ThreadId = (HANDLE)(ULONG_PTR)ThreadId;
        hookCtx.SyscallNumber = SyscallNumber;
        hookCtx.CallerReturnAddress = ReturnAddress;
        hookCtx.IsPreCall = TRUE;

        if (Arguments != NULL && ArgumentCount > 0) {
            UINT32 count = min(ArgumentCount, SH_MAX_ARGUMENTS);
            RtlCopyMemory(hookCtx.Arguments, Arguments,
                count * sizeof(ULONG64));
            hookCtx.ArgumentCount = count;
        }

        NTSTATUS hookStatus = ShDispatchSyscall(
            g_ScState.SyscallHooksFramework,
            &hookCtx,
            &hookResult
            );

        if (NT_SUCCESS(hookStatus) && hookResult == ShResult_Block) {
            shouldBlock = TRUE;
        }
    }

    //
    // Step 8: Composite threat assessment
    //
    if (threatScore >= SC_SCORE_BLOCK_THRESHOLD) {
        shouldBlock = TRUE;
    }

    //
    // Step 9: Emit behavioral event if suspicious
    //
    if (detectFlags != 0 && threatScore >= SC_SCORE_ALERT_THRESHOLD) {
        ScpEmitEvasionEvent(ProcessId, SyscallNumber,
            detectFlags, threatScore, shouldBlock);
    }

    //
    // Track suspicious callers
    //
    if (detectFlags != 0) {
        ScpAddSuspiciousCaller(procCtx, ReturnAddress);

        if (detectFlags & SC_DETECT_DIRECT_SYSCALL) {
            InterlockedIncrement64(&procCtx->DirectSyscalls);
            InterlockedOr((volatile LONG*)&procCtx->Flags, SC_PROC_FLAG_DIRECT_SYSCALLS);
        }
        if (detectFlags & SC_DETECT_HEAVENS_GATE) {
            InterlockedOr((volatile LONG*)&procCtx->Flags, SC_PROC_FLAG_HEAVENS_GATE);
        }

        InterlockedIncrement64(&procCtx->SuspiciousSyscalls);
    }

    //
    // Step 10: Update global statistics
    //
    InterlockedIncrement64(&g_ScState.TotalSyscallsMonitored);

    if (detectFlags & SC_DETECT_DIRECT_SYSCALL) {
        InterlockedIncrement64(&g_ScState.TotalDirectSyscalls);
    }
    if (detectFlags & SC_DETECT_HEAVENS_GATE) {
        InterlockedIncrement64(&g_ScState.TotalHeavensGate);
    }
    if (detectFlags != 0) {
        InterlockedIncrement64(&g_ScState.TotalSuspiciousCalls);
    }
    if (shouldBlock) {
        InterlockedIncrement64(&g_ScState.TotalBlocked);
    }

    //
    // Fill remaining output context fields
    //
    if (Context != NULL) {
        Context->ThreatScore = threatScore;
        Context->DetectionFlags = detectFlags;
        Context->IsSuspiciousRegion = (detectFlags & SC_DETECT_UNBACKED_CALLER) != 0;
    }

    ScMonitorReleaseProcessContext(procCtx);
    ScpReleaseReference();

    return shouldBlock ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
}

// ============================================================================
// Delegation Wrappers — Exact header signature matches
// ============================================================================

_Use_decl_annotations_
BOOLEAN
ScMonitorIsFromNtdll(
    _In_ UINT32 ProcessId,
    _In_ UINT64 ReturnAddress,
    _In_ BOOLEAN IsWoW64
    )
{
    PSC_PROCESS_CONTEXT ctx = NULL;
    BOOLEAN result = FALSE;

    if (!g_ScState.Initialized) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ScState.ProcessLock);
    ctx = ScpFindProcessContextLocked(ProcessId);
    ExReleasePushLockShared(&g_ScState.ProcessLock);
    KeLeaveCriticalRegion();

    if (ctx != NULL) {
        if (IsWoW64 && ctx->Wow64NtdllBase != 0) {
            result = ScpIsAddressInRange(
                ReturnAddress, ctx->Wow64NtdllBase, ctx->Wow64NtdllSize);
        } else if (ctx->NtdllBase != 0) {
            result = ScpIsAddressInRange(
                ReturnAddress, ctx->NtdllBase, ctx->NtdllSize);
        }
        ScMonitorReleaseProcessContext(ctx);
    }

    return result;
}


_Use_decl_annotations_
BOOLEAN
ScMonitorDetectHeavensGate(
    _In_ UINT32 ProcessId,
    _In_ PSYSCALL_CALL_CONTEXT Context
    )
{
    BOOLEAN isSuspicious = FALSE;
    HGD_GATE_TYPE gateType = HgdGate_None;

    PAGED_CODE();

    if (Context == NULL) {
        return FALSE;
    }

    if (!g_ScState.Initialized || g_ScState.HeavensGateDetector == NULL) {
        return FALSE;
    }

    NTSTATUS status = HgdDetectSyscallOrigin(
        g_ScState.HeavensGateDetector,
        (HANDLE)(ULONG_PTR)ProcessId,
        Context->SyscallNumber,
        (PVOID)(ULONG_PTR)Context->ReturnAddress,
        &isSuspicious,
        &gateType
        );

    if (NT_SUCCESS(status) && isSuspicious) {
        //
        // Check for legitimate WoW64
        //
        BOOLEAN isLegitimate = FALSE;
        HgdIsLegitimateWow64(
            g_ScState.HeavensGateDetector,
            (PVOID)(ULONG_PTR)Context->ReturnAddress,
            &isLegitimate
            );

        if (!isLegitimate) {
            Context->IsFromWoW64 = TRUE;
            Context->DetectionFlags |= SC_DETECT_HEAVENS_GATE;
            return TRUE;
        }
    }

    return FALSE;
}


_Use_decl_annotations_
NTSTATUS
ScMonitorAnalyzeCallStack(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ThreadId,
    _Out_writes_to_(MaxFrames, *FrameCount) PUINT64 StackFrames,
    _In_ UINT32 MaxFrames,
    _Out_ PUINT32 FrameCount,
    _Out_ PUINT32 AnomalyFlags
    )
{
    NTSTATUS status;
    PCSA_CALLSTACK callstack = NULL;
    CSA_ANOMALY anomalies = CsaAnomaly_None;
    ULONG score = 0;

    PAGED_CODE();

    if (StackFrames == NULL || FrameCount == NULL ||
        AnomalyFlags == NULL || MaxFrames == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *FrameCount = 0;
    *AnomalyFlags = 0;
    RtlZeroMemory(StackFrames, MaxFrames * sizeof(UINT64));

    if (!g_ScState.Initialized || g_ScState.CallstackAnalyzer == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = CsaCaptureCallstack(
        g_ScState.CallstackAnalyzer,
        (HANDLE)(ULONG_PTR)ProcessId,
        (HANDLE)(ULONG_PTR)ThreadId,
        &callstack
        );

    if (!NT_SUCCESS(status) || callstack == NULL) {
        return status;
    }

    status = CsaAnalyzeCallstack(
        g_ScState.CallstackAnalyzer,
        callstack,
        &anomalies,
        &score
        );

    if (NT_SUCCESS(status)) {
        //
        // Copy frame return addresses to output
        //
        UINT32 count = min(callstack->FrameCount, MaxFrames);
        for (UINT32 i = 0; i < count; i++) {
            StackFrames[i] =
                (UINT64)(ULONG_PTR)callstack->Frames[i].ReturnAddress;
        }
        *FrameCount = count;

        //
        // Map CSA anomaly flags to SC stack anomaly flags
        //
        if (anomalies & CsaAnomaly_UnbackedCode) {
            *AnomalyFlags |= SC_STACK_ANOMALY_UNBACKED;
        }
        if (anomalies & CsaAnomaly_RWXMemory) {
            *AnomalyFlags |= SC_STACK_ANOMALY_RWX;
        }
        if (anomalies & CsaAnomaly_StackPivot) {
            *AnomalyFlags |= SC_STACK_ANOMALY_PIVOT;
        }
        if (anomalies & CsaAnomaly_ReturnGadget) {
            *AnomalyFlags |= SC_STACK_ANOMALY_GADGET;
        }
        if (anomalies & CsaAnomaly_MissingFrames) {
            *AnomalyFlags |= SC_STACK_ANOMALY_CORRUPTED;
        }
    }

    CsaFreeCallstack(callstack);
    return status;
}


_Use_decl_annotations_
NTSTATUS
ScMonitorVerifyNtdllIntegrity(
    _In_ UINT32 ProcessId,
    _Out_ PNTDLL_INTEGRITY_STATE IntegrityState
    )
{
    NTSTATUS status;
    PNI_PROCESS_NTDLL ntdllState = NULL;

    PAGED_CODE();

    if (IntegrityState == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(IntegrityState, sizeof(NTDLL_INTEGRITY_STATE));

    if (!g_ScState.Initialized || g_ScState.NtdllIntegrityMonitor == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Get NTDLL baseline info
    //
    status = NiScanProcess(
        g_ScState.NtdllIntegrityMonitor,
        (HANDLE)(ULONG_PTR)ProcessId,
        &ntdllState
        );

    if (!NT_SUCCESS(status) || ntdllState == NULL) {
        return status;
    }

    IntegrityState->NtdllBase = (UINT64)(ULONG_PTR)ntdllState->NtdllBase;
    IntegrityState->NtdllSize = (UINT64)ntdllState->NtdllSize;

    if (ntdllState->HashValid) {
        RtlCopyMemory(IntegrityState->TextSectionHash,
            ntdllState->Hash, sizeof(ntdllState->Hash));
    }

    IntegrityState->LastVerifyTime =
        (UINT64)KeQueryPerformanceCounter(NULL).QuadPart;

    //
    // Check for modifications
    //
    BOOLEAN isModified = FALSE;
    NTSTATUS compareStatus = NiCompareToClean(
        g_ScState.NtdllIntegrityMonitor,
        (HANDLE)(ULONG_PTR)ProcessId,
        &isModified
        );

    IntegrityState->IsIntact = NT_SUCCESS(compareStatus) && !isModified;

    //
    // Enumerate hooks to get count
    //
    #define SC_MAX_HOOK_ENUM 128
    ULONG foundCount = 0;

    //
    // We allocate a small array on pool since we just need the count
    //
    PNI_FUNCTION_STATE* hookBuffer = (PNI_FUNCTION_STATE*)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        SC_MAX_HOOK_ENUM * sizeof(PNI_FUNCTION_STATE),
        SC_POOL_TAG_GENERAL
        );

    if (hookBuffer != NULL) {
        NTSTATUS hookStatus = NiDetectHooks(
            g_ScState.NtdllIntegrityMonitor,
            (HANDLE)(ULONG_PTR)ProcessId,
            hookBuffer,
            SC_MAX_HOOK_ENUM,
            &foundCount
            );

        if (NT_SUCCESS(hookStatus) && foundCount > 0) {
            IntegrityState->IsHooked = TRUE;
            IntegrityState->HookedFunctionCount = (UINT16)min(foundCount, 0xFFFF);

            //
            // Free each returned function state
            //
            for (ULONG i = 0; i < foundCount; i++) {
                if (hookBuffer[i] != NULL) {
                    NiFreeFunctionState(g_ScState.NtdllIntegrityMonitor,
                        hookBuffer[i]);
                }
            }
        }

        ShadowStrikeFreePoolWithTag(hookBuffer, SC_POOL_TAG_GENERAL);
    }

    NiFreeState(g_ScState.NtdllIntegrityMonitor, ntdllState);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
ScMonitorGetNtdllHooks(
    _In_ UINT32 ProcessId,
    _Out_writes_to_(MaxFunctions, *FunctionCount) PHOOKED_FUNCTION_ENTRY HookedFunctions,
    _In_ UINT32 MaxFunctions,
    _Out_ PUINT32 FunctionCount
    )
{
    NTSTATUS status;
    PNI_FUNCTION_STATE* niHooks = NULL;
    ULONG niCount = 0;
    UINT32 i;

    PAGED_CODE();

    if (HookedFunctions == NULL || FunctionCount == NULL || MaxFunctions == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *FunctionCount = 0;
    RtlZeroMemory(HookedFunctions, MaxFunctions * sizeof(HOOKED_FUNCTION_ENTRY));

    if (!g_ScState.Initialized || g_ScState.NtdllIntegrityMonitor == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    niHooks = (PNI_FUNCTION_STATE*)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        MaxFunctions * sizeof(PNI_FUNCTION_STATE),
        SC_POOL_TAG_GENERAL
        );

    if (niHooks == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = NiDetectHooks(
        g_ScState.NtdllIntegrityMonitor,
        (HANDLE)(ULONG_PTR)ProcessId,
        niHooks,
        (ULONG)MaxFunctions,
        &niCount
        );

    if (NT_SUCCESS(status)) {
        for (i = 0; i < niCount && i < MaxFunctions; i++) {
            if (niHooks[i] != NULL) {
                RtlStringCchCopyA(
                    HookedFunctions[i].FunctionName,
                    sizeof(HookedFunctions[i].FunctionName),
                    niHooks[i]->FunctionName
                    );

                HookedFunctions[i].OriginalAddress =
                    (UINT64)(ULONG_PTR)niHooks[i]->ExpectedAddress;
                HookedFunctions[i].CurrentAddress =
                    (UINT64)(ULONG_PTR)niHooks[i]->CurrentAddress;

                //
                // Determine hook type from modification type
                //
                switch (niHooks[i]->ModificationType) {
                case NiMod_HookInstalled:
                    HookedFunctions[i].HookType = (UINT32)HookType_InlineJmp;
                    break;
                case NiMod_ImportModified:
                    HookedFunctions[i].HookType = (UINT32)HookType_IAT;
                    break;
                case NiMod_ExportModified:
                    HookedFunctions[i].HookType = (UINT32)HookType_EAT;
                    break;
                default:
                    HookedFunctions[i].HookType = (UINT32)HookType_None;
                    break;
                }

                NiFreeFunctionState(g_ScState.NtdllIntegrityMonitor,
                    niHooks[i]);
            }
        }
        *FunctionCount = min((UINT32)niCount, MaxFunctions);
    }

    ShadowStrikeFreePoolWithTag(niHooks, SC_POOL_TAG_GENERAL);
    return status;
}


_Use_decl_annotations_
NTSTATUS
ScMonitorRestoreNtdllFunction(
    _In_ UINT32 ProcessId,
    _In_z_ PCSTR FunctionName
    )
/*++
    Restores a hooked NTDLL function using the clean baseline from NI.

    Security: This function writes to another process's address space.
    We validate the function is actually hooked before attempting restoration.
    Full audit trail is emitted.
--*/
{
    NTSTATUS status;
    PNI_FUNCTION_STATE funcState = NULL;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    SIZE_T bytesWritten = 0;

    PAGED_CODE();

    if (FunctionName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_ScState.Initialized || g_ScState.NtdllIntegrityMonitor == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Verify the function is actually hooked
    //
    status = NiCheckFunction(
        g_ScState.NtdllIntegrityMonitor,
        (HANDLE)(ULONG_PTR)ProcessId,
        FunctionName,
        &funcState
        );

    if (!NT_SUCCESS(status) || funcState == NULL) {
        return status;
    }

    if (!funcState->IsModified) {
        NiFreeFunctionState(g_ScState.NtdllIntegrityMonitor, funcState);
        return STATUS_SUCCESS;
    }

    //
    // Audit log
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[ShadowStrike-SC] Restoring %s in PID %u "
        "(expected=0x%p, current=0x%p, mod=%d)\n",
        FunctionName, ProcessId,
        funcState->ExpectedAddress, funcState->CurrentAddress,
        funcState->ModificationType);

    //
    // Attach to target process and write original prologue
    //
    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        NiFreeFunctionState(g_ScState.NtdllIntegrityMonitor, funcState);
        return status;
    }

    if (ShadowStrikeIsProcessTerminating(process)) {
        ObDereferenceObject(process);
        NiFreeFunctionState(g_ScState.NtdllIntegrityMonitor, funcState);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        ProbeForWrite(funcState->CurrentAddress, sizeof(funcState->ExpectedPrologue), 1);

        //
        // Write original prologue bytes back
        //
        status = ZwWriteVirtualMemory(
            ZwCurrentProcess(),
            funcState->CurrentAddress,
            funcState->ExpectedPrologue,
            sizeof(funcState->ExpectedPrologue),
            &bytesWritten
            );

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[ShadowStrike-SC] Restored %s in PID %u (%llu bytes)\n",
            FunctionName, ProcessId, (UINT64)bytesWritten);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike-SC] Restore failed for %s in PID %u: 0x%08X\n",
            FunctionName, ProcessId, status);
    }

    NiFreeFunctionState(g_ScState.NtdllIntegrityMonitor, funcState);
    return status;
}

// ============================================================================
// Syscall Table Delegation Wrappers
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ScMonitorGetSyscallName(
    _In_ UINT32 SyscallNumber,
    _Out_writes_z_(NameSize) PSTR Name,
    _In_ UINT32 NameSize
    )
{
    SST_ENTRY_INFO info = { 0 };
    NTSTATUS status;

    if (Name == NULL || NameSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    Name[0] = '\0';

    if (!g_ScState.Initialized || g_ScState.SyscallTableHandle == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = SstLookupByNumber(
        g_ScState.SyscallTableHandle, SyscallNumber, &info);
    if (NT_SUCCESS(status) && info.Name != NULL) {
        RtlStringCchCopyA(Name, NameSize, info.Name);
    }

    return status;
}


_Use_decl_annotations_
NTSTATUS
ScMonitorGetSyscallNumber(
    _In_z_ PCSTR Name,
    _Out_ PUINT32 SyscallNumber
    )
{
    SST_ENTRY_INFO info = { 0 };
    NTSTATUS status;

    if (Name == NULL || SyscallNumber == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *SyscallNumber = 0;

    if (!g_ScState.Initialized || g_ScState.SyscallTableHandle == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = SstLookupByName(
        g_ScState.SyscallTableHandle, Name, &info);
    if (NT_SUCCESS(status)) {
        *SyscallNumber = info.Number;
    }

    return status;
}


_Use_decl_annotations_
NTSTATUS
ScMonitorGetSyscallDefinition(
    _In_ UINT32 SyscallNumber,
    _Out_ PSYSCALL_DEFINITION Definition
    )
{
    SST_ENTRY_INFO info = { 0 };
    NTSTATUS status;

    if (Definition == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Definition, sizeof(SYSCALL_DEFINITION));

    if (!g_ScState.Initialized || g_ScState.SyscallTableHandle == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = SstLookupByNumber(
        g_ScState.SyscallTableHandle, SyscallNumber, &info);

    if (NT_SUCCESS(status)) {
        Definition->SyscallNumber = SyscallNumber;

        if (info.Name != NULL) {
            RtlStringCchCopyA(Definition->SyscallName,
                sizeof(Definition->SyscallName), info.Name);
        }

        //
        // Map SST types to SYSCALL_DEFINITION types
        //
        switch (info.Category) {
        case SstCategory_Process: Definition->Category = SyscallCategory_Process; break;
        case SstCategory_Thread:  Definition->Category = SyscallCategory_Thread; break;
        case SstCategory_Memory:  Definition->Category = SyscallCategory_Memory; break;
        case SstCategory_File:    Definition->Category = SyscallCategory_File; break;
        case SstCategory_Registry: Definition->Category = SyscallCategory_Registry; break;
        case SstCategory_Object:  Definition->Category = SyscallCategory_Object; break;
        case SstCategory_Security: Definition->Category = SyscallCategory_Security; break;
        case SstCategory_System:  Definition->Category = SyscallCategory_System; break;
        case SstCategory_Network: Definition->Category = SyscallCategory_Network; break;
        default:                  Definition->Category = SyscallCategory_Unknown; break;
        }

        switch (info.RiskLevel) {
        case SstRisk_Low:      Definition->RiskCategory = SyscallRisk_Low; break;
        case SstRisk_Medium:   Definition->RiskCategory = SyscallRisk_Medium; break;
        case SstRisk_High:     Definition->RiskCategory = SyscallRisk_High; break;
        case SstRisk_Critical: Definition->RiskCategory = SyscallRisk_Critical; break;
        default:               Definition->RiskCategory = SyscallRisk_None; break;
        }

        Definition->ArgumentCount = info.ArgumentCount;
        Definition->Flags = info.Flags;
    }

    return status;
}


// ============================================================================
// Event Emission
// ============================================================================

static
VOID
ScpEmitEvasionEvent(
    _In_ UINT32 ProcessId,
    _In_ UINT32 SyscallNumber,
    _In_ UINT32 DetectionFlags,
    _In_ UINT32 ThreatScore,
    _In_ BOOLEAN ShouldBlock
    )
{
    BEHAVIOR_EVENT_TYPE eventType = BehaviorEvent_DirectSyscall;
    BEHAVIOR_RESPONSE_ACTION response = BehaviorResponse_Allow;

    if (DetectionFlags & SC_DETECT_HEAVENS_GATE) {
        eventType = BehaviorEvent_HeavensGate;
    } else if (DetectionFlags & SC_DETECT_HOOK_BYPASS) {
        eventType = BehaviorEvent_NtdllUnhooking;
    }

    //
    // Allocate event payload from the EventLookaside (not stack).
    // SYSCALL_CALL_CONTEXT is ~800 bytes — too large for kernel stack,
    // especially in a deep call chain (hook→analysis→sub-modules→emit).
    //
    PSYSCALL_CALL_CONTEXT eventData = (PSYSCALL_CALL_CONTEXT)
        ExAllocateFromNPagedLookasideList(&g_ScState.EventLookaside);
    if (eventData == NULL) {
        return;
    }

    RtlZeroMemory(eventData, sizeof(SYSCALL_CALL_CONTEXT));
    eventData->SyscallNumber = SyscallNumber;
    eventData->ProcessId = ProcessId;
    eventData->DetectionFlags = DetectionFlags;
    eventData->ThreatScore = ThreatScore;

    (VOID)BeEngineSubmitEvent(
        eventType,
        BehaviorCategory_DefenseEvasion,
        ProcessId,
        eventData,
        sizeof(SYSCALL_CALL_CONTEXT),
        ThreatScore,
        ShouldBlock,
        &response
        );

    ExFreeToNPagedLookasideList(&g_ScState.EventLookaside, eventData);

    if (response == BehaviorResponse_Terminate) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[ShadowStrike-SC] BehaviorEngine requests termination for PID %u "
            "(syscall=%u, flags=0x%X, score=%u)\n",
            ProcessId, SyscallNumber, DetectionFlags, ThreatScore);
    }
}


// ============================================================================
// Statistics API
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ScMonitorGetStatistics(
    _Out_ PSYSCALL_MONITOR_STATISTICS Stats
    )
{
    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(SYSCALL_MONITOR_STATISTICS));

    if (!g_ScState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    Stats->Initialized = g_ScState.Initialized;
    Stats->Enabled = g_ScState.Enabled;
    Stats->ProcessContextCount = (UINT32)g_ScState.ProcessContextCount;
    Stats->KnownGoodCallerCount = (UINT32)g_ScState.KnownGoodCallerCount;
    Stats->TotalSyscallsMonitored = g_ScState.TotalSyscallsMonitored;
    Stats->TotalDirectSyscalls = g_ScState.TotalDirectSyscalls;
    Stats->TotalHeavensGate = g_ScState.TotalHeavensGate;
    Stats->TotalSuspiciousCalls = g_ScState.TotalSuspiciousCalls;
    Stats->TotalBlocked = g_ScState.TotalBlocked;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
ScMonitorGetProcessStats(
    _In_ UINT32 ProcessId,
    _Out_ PUINT64 TotalSyscalls,
    _Out_ PUINT64 DirectSyscalls,
    _Out_ PUINT64 SuspiciousSyscalls
    )
{
    PSC_PROCESS_CONTEXT ctx = NULL;

    PAGED_CODE();

    if (TotalSyscalls == NULL || DirectSyscalls == NULL ||
        SuspiciousSyscalls == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *TotalSyscalls = 0;
    *DirectSyscalls = 0;
    *SuspiciousSyscalls = 0;

    if (!g_ScState.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ScState.ProcessLock);
    ctx = ScpFindProcessContextLocked(ProcessId);
    ExReleasePushLockShared(&g_ScState.ProcessLock);
    KeLeaveCriticalRegion();

    if (ctx == NULL) {
        return STATUS_NOT_FOUND;
    }

    *TotalSyscalls = (UINT64)ctx->TotalSyscalls;
    *DirectSyscalls = (UINT64)ctx->DirectSyscalls;
    *SuspiciousSyscalls = (UINT64)ctx->SuspiciousSyscalls;

    ScMonitorReleaseProcessContext(ctx);

    return STATUS_SUCCESS;
}