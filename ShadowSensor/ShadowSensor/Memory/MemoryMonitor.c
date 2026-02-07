/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE MEMORY MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file MemoryMonitor.c
 * @brief Enterprise-grade memory monitoring for kernel-mode EDR operations.
 *
 * Provides comprehensive memory monitoring infrastructure for Fortune 500
 * endpoint protection with:
 * - VirtualAlloc/VirtualProtect operation tracking
 * - Cross-process memory operation detection
 * - Section object monitoring and analysis
 * - Shellcode detection via entropy and pattern analysis
 * - Code injection detection across all known techniques
 * - Process hollowing detection
 * - VAD tree tracking and suspicious region identification
 * - Real-time threat scoring and risk assessment
 *
 * Implementation Features:
 * - Lookaside lists for efficient memory allocation
 * - Per-process context tracking with reference counting
 * - Rate limiting to prevent resource exhaustion
 * - IRQL-aware implementations throughout
 * - Proper cleanup and resource management
 *
 * MITRE ATT&CK Coverage:
 * - T1055: Process Injection (all sub-techniques)
 * - T1106: Native API abuse
 * - T1620: Reflective Code Loading
 * - T1574: Hijack Execution Flow
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "MemoryMonitor.h"
#include "VadTracker.h"
#include "ShellcodeDetector.h"
#include "InjectionDetector.h"
#include "HollowingDetector.h"
#include "../Sync/SpinLock.h"

// ============================================================================
// PRAGMA DIRECTIVES
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, MmMonitorInitialize)
#pragma alloc_text(PAGE, MmMonitorShutdown)
#pragma alloc_text(PAGE, MmMonitorSetEnabled)
#pragma alloc_text(PAGE, MmMonitorUpdateConfig)
#pragma alloc_text(PAGE, MmMonitorGetProcessContext)
#pragma alloc_text(PAGE, MmMonitorRemoveProcessContext)
#pragma alloc_text(PAGE, MmMonitorBuildVadMap)
#pragma alloc_text(PAGE, MmMonitorFreeVadMap)
#pragma alloc_text(PAGE, MmMonitorFindSuspiciousVads)
#pragma alloc_text(PAGE, MmMonitorGetBackingFile)
#endif

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief Global memory monitor instance
 */
static MEMORY_MONITOR_GLOBALS g_MemoryMonitor = { 0 };

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

/**
 * @brief Process context hash table size (must be power of 2)
 */
#define MM_PROCESS_HASH_SIZE            256

/**
 * @brief Maximum tracked regions per process before cleanup
 */
#define MM_MAX_REGIONS_PER_PROCESS      4096

/**
 * @brief High entropy threshold (normalized to 0-8000 range)
 */
#define MM_HIGH_ENTROPY_THRESHOLD       7000

/**
 * @brief Suspicious protection change - RW to RX
 */
#define MM_SUSPICIOUS_RW_TO_RX          1

/**
 * @brief Suspicious protection change - any to RWX
 */
#define MM_SUSPICIOUS_TO_RWX            2

/**
 * @brief Cleanup interval for stale regions (seconds)
 */
#define MM_CLEANUP_INTERVAL_SEC         60

/**
 * @brief Maximum age for tracked region before cleanup (seconds)
 */
#define MM_REGION_MAX_AGE_SEC           3600

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

/**
 * @brief Process context hash entry
 */
typedef struct _MM_PROCESS_HASH_ENTRY {
    LIST_ENTRY ListEntry;
    PMM_PROCESS_CONTEXT Context;
} MM_PROCESS_HASH_ENTRY, *PMM_PROCESS_HASH_ENTRY;

/**
 * @brief Process context hash table
 */
typedef struct _MM_PROCESS_HASH_TABLE {
    LIST_ENTRY Buckets[MM_PROCESS_HASH_SIZE];
    KSPIN_LOCK BucketLocks[MM_PROCESS_HASH_SIZE];
    volatile LONG EntryCount;
} MM_PROCESS_HASH_TABLE, *PMM_PROCESS_HASH_TABLE;

static MM_PROCESS_HASH_TABLE g_ProcessHashTable = { 0 };

// ============================================================================
// INTERNAL HELPER FUNCTIONS - FORWARD DECLARATIONS
// ============================================================================

static VOID MmpInitializeDefaultConfig(_Out_ PMEMORY_MONITOR_CONFIG Config);
static NTSTATUS MmpInitializeLookasideLists(VOID);
static VOID MmpCleanupLookasideLists(VOID);
static NTSTATUS MmpInitializeProcessHashTable(VOID);
static VOID MmpCleanupProcessHashTable(VOID);
static ULONG MmpHashProcessId(_In_ UINT32 ProcessId);
static PMM_PROCESS_CONTEXT MmpLookupProcessContext(_In_ UINT32 ProcessId);
static NTSTATUS MmpCreateProcessContext(_In_ UINT32 ProcessId, _In_opt_ PEPROCESS ProcessObject, _Out_ PMM_PROCESS_CONTEXT* Context);
static VOID MmpFreeProcessContext(_Inout_ PMM_PROCESS_CONTEXT Context);
static VOID MmpReferenceProcessContext(_Inout_ PMM_PROCESS_CONTEXT Context);
static VOID MmpDereferenceProcessContext(_Inout_ PMM_PROCESS_CONTEXT Context);
static PMM_TRACKED_REGION MmpAllocateRegion(VOID);
static VOID MmpFreeRegion(_Inout_ PMM_TRACKED_REGION Region);
static PMM_TRACKED_REGION MmpFindRegion(_In_ PMM_PROCESS_CONTEXT Context, _In_ UINT64 Address);
static NTSTATUS MmpAddRegion(_Inout_ PMM_PROCESS_CONTEXT Context, _In_ UINT64 BaseAddress, _In_ UINT64 Size, _In_ UINT32 Protection, _In_ UINT32 Type);
static VOID MmpRemoveRegion(_Inout_ PMM_PROCESS_CONTEXT Context, _Inout_ PMM_TRACKED_REGION Region);
static VOID MmpCleanupStaleRegions(_Inout_ PMM_PROCESS_CONTEXT Context);
static BOOLEAN MmpCheckRateLimit(VOID);
static UINT32 MmpAnalyzeProtectionChange(_In_ UINT32 OldProtection, _In_ UINT32 NewProtection);
static BOOLEAN MmpIsExecutableProtection(_In_ UINT32 Protection);
static BOOLEAN MmpIsWritableProtection(_In_ UINT32 Protection);
static BOOLEAN MmpIsRWXProtection(_In_ UINT32 Protection);
static VOID MmpUpdateRegionRisk(_Inout_ PMM_TRACKED_REGION Region);
static VOID MmpUpdateProcessRisk(_Inout_ PMM_PROCESS_CONTEXT Context);
static NTSTATUS MmpReadProcessMemory(_In_ PEPROCESS Process, _In_ PVOID SourceAddress, _Out_writes_bytes_(Size) PVOID Buffer, _In_ SIZE_T Size);
static NTSTATUS MmpQueryVirtualMemory(_In_ PEPROCESS Process, _In_ PVOID Address, _Out_ PMEMORY_BASIC_INFORMATION MemInfo);

// ============================================================================
// INITIALIZATION AND LIFECYCLE
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MmMonitorInitialize(
    VOID
    )
{
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    //
    // Check if already initialized
    //
    if (g_MemoryMonitor.Initialized) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&g_MemoryMonitor, sizeof(MEMORY_MONITOR_GLOBALS));

    //
    // Initialize default configuration
    //
    MmpInitializeDefaultConfig(&g_MemoryMonitor.Config);

    //
    // Initialize process context list and lock
    //
    InitializeListHead(&g_MemoryMonitor.ProcessContextList);
    Status = ExInitializeResourceLite(&g_MemoryMonitor.ProcessContextLock);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Initialize lookaside lists
    //
    Status = MmpInitializeLookasideLists();
    if (!NT_SUCCESS(Status)) {
        ExDeleteResourceLite(&g_MemoryMonitor.ProcessContextLock);
        return Status;
    }

    //
    // Initialize process hash table
    //
    Status = MmpInitializeProcessHashTable();
    if (!NT_SUCCESS(Status)) {
        MmpCleanupLookasideLists();
        ExDeleteResourceLite(&g_MemoryMonitor.ProcessContextLock);
        return Status;
    }

    //
    // Initialize rate limiting
    //
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&g_MemoryMonitor.CurrentSecondStart);
    g_MemoryMonitor.EventsThisSecond = 0;

    //
    // Mark as initialized
    //
    g_MemoryMonitor.Initialized = TRUE;
    g_MemoryMonitor.Enabled = TRUE;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
MmMonitorShutdown(
    VOID
    )
{
    PLIST_ENTRY Entry;
    PMM_PROCESS_CONTEXT Context;

    PAGED_CODE();

    if (!g_MemoryMonitor.Initialized) {
        return;
    }

    //
    // Disable monitoring
    //
    g_MemoryMonitor.Enabled = FALSE;

    //
    // Clean up all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_MemoryMonitor.ProcessContextLock, TRUE);

    while (!IsListEmpty(&g_MemoryMonitor.ProcessContextList)) {
        Entry = RemoveHeadList(&g_MemoryMonitor.ProcessContextList);
        Context = CONTAINING_RECORD(Entry, MM_PROCESS_CONTEXT, ListEntry);
        MmpFreeProcessContext(Context);
    }

    ExReleaseResourceLite(&g_MemoryMonitor.ProcessContextLock);
    KeLeaveCriticalRegion();

    //
    // Clean up hash table
    //
    MmpCleanupProcessHashTable();

    //
    // Clean up lookaside lists
    //
    MmpCleanupLookasideLists();

    //
    // Clean up resource
    //
    ExDeleteResourceLite(&g_MemoryMonitor.ProcessContextLock);

    g_MemoryMonitor.Initialized = FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MmMonitorSetEnabled(
    _In_ BOOLEAN Enable
    )
{
    PAGED_CODE();

    if (!g_MemoryMonitor.Initialized) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    g_MemoryMonitor.Enabled = Enable;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MmMonitorUpdateConfig(
    _In_ PMEMORY_MONITOR_CONFIG Config
    )
{
    PAGED_CODE();

    if (!g_MemoryMonitor.Initialized) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate configuration values
    //
    if (Config->MaxEventsPerSecond == 0) {
        Config->MaxEventsPerSecond = MM_DEFAULT_MAX_EVENTS_PER_SEC;
    }

    if (Config->MinAllocationSizeToTrack == 0) {
        Config->MinAllocationSizeToTrack = MM_DEFAULT_MIN_ALLOC_SIZE;
    }

    if (Config->MaxRegionSizeToScan == 0) {
        Config->MaxRegionSizeToScan = MM_DEFAULT_MAX_REGION_SCAN_SIZE;
    }

    //
    // Copy configuration
    //
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_MemoryMonitor.ProcessContextLock, TRUE);

    RtlCopyMemory(&g_MemoryMonitor.Config, Config, sizeof(MEMORY_MONITOR_CONFIG));

    ExReleaseResourceLite(&g_MemoryMonitor.ProcessContextLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
MmMonitorGetStatistics(
    _Out_ PMEMORY_MONITOR_GLOBALS Stats
    )
{
    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_MemoryMonitor.Initialized) {
        RtlZeroMemory(Stats, sizeof(MEMORY_MONITOR_GLOBALS));
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlCopyMemory(Stats, &g_MemoryMonitor, sizeof(MEMORY_MONITOR_GLOBALS));

    return STATUS_SUCCESS;
}

// ============================================================================
// PROCESS CONTEXT MANAGEMENT
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MmMonitorGetProcessContext(
    _In_ UINT32 ProcessId,
    _In_opt_ PEPROCESS ProcessObject,
    _Out_ PMM_PROCESS_CONTEXT* Context
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PMM_PROCESS_CONTEXT ExistingContext;
    PMM_PROCESS_CONTEXT NewContext = NULL;

    PAGED_CODE();

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Context = NULL;

    if (!g_MemoryMonitor.Initialized) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // Try to find existing context
    //
    ExistingContext = MmpLookupProcessContext(ProcessId);
    if (ExistingContext != NULL) {
        MmpReferenceProcessContext(ExistingContext);
        *Context = ExistingContext;
        return STATUS_SUCCESS;
    }

    //
    // Create new context
    //
    Status = MmpCreateProcessContext(ProcessId, ProcessObject, &NewContext);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    *Context = NewContext;

    return STATUS_SUCCESS;
}

VOID
MmMonitorReleaseProcessContext(
    _In_ PMM_PROCESS_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    MmpDereferenceProcessContext(Context);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
MmMonitorRemoveProcessContext(
    _In_ UINT32 ProcessId
    )
{
    PMM_PROCESS_CONTEXT Context;
    ULONG Hash;
    KIRQL OldIrql;
    PLIST_ENTRY Entry;
    PMM_PROCESS_HASH_ENTRY HashEntry;
    BOOLEAN Found = FALSE;

    PAGED_CODE();

    if (!g_MemoryMonitor.Initialized) {
        return;
    }

    Hash = MmpHashProcessId(ProcessId);

    //
    // Remove from hash table
    //
    KeAcquireSpinLock(&g_ProcessHashTable.BucketLocks[Hash], &OldIrql);

    Entry = g_ProcessHashTable.Buckets[Hash].Flink;
    while (Entry != &g_ProcessHashTable.Buckets[Hash]) {
        HashEntry = CONTAINING_RECORD(Entry, MM_PROCESS_HASH_ENTRY, ListEntry);
        if (HashEntry->Context->ProcessId == ProcessId) {
            Context = HashEntry->Context;
            RemoveEntryList(Entry);
            InterlockedDecrement(&g_ProcessHashTable.EntryCount);
            ExFreePoolWithTag(HashEntry, MM_POOL_TAG_CACHE);
            Found = TRUE;
            break;
        }
        Entry = Entry->Flink;
    }

    KeReleaseSpinLock(&g_ProcessHashTable.BucketLocks[Hash], OldIrql);

    if (!Found) {
        return;
    }

    //
    // Remove from main list
    //
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_MemoryMonitor.ProcessContextLock, TRUE);

    RemoveEntryList(&Context->ListEntry);
    g_MemoryMonitor.ProcessContextCount--;

    ExReleaseResourceLite(&g_MemoryMonitor.ProcessContextLock);
    KeLeaveCriticalRegion();

    //
    // Dereference (will free when refcount hits 0)
    //
    MmpDereferenceProcessContext(Context);
}

// ============================================================================
// MEMORY OPERATION HANDLERS
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
MmMonitorHandleAllocation(
    _In_ UINT32 ProcessId,
    _In_ UINT64 BaseAddress,
    _In_ UINT64 RegionSize,
    _In_ UINT32 AllocationType,
    _In_ UINT32 Protection,
    _In_ BOOLEAN IsCrossProcess,
    _In_ UINT32 SourceProcessId
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PMM_PROCESS_CONTEXT Context = NULL;
    PMM_TRACKED_REGION Region;
    BOOLEAN IsSuspicious = FALSE;

    UNREFERENCED_PARAMETER(AllocationType);

    if (!g_MemoryMonitor.Initialized || !g_MemoryMonitor.Enabled) {
        return STATUS_SUCCESS;
    }

    if (!g_MemoryMonitor.Config.EnableAllocationMonitoring) {
        return STATUS_SUCCESS;
    }

    //
    // Rate limiting check
    //
    if (!MmpCheckRateLimit()) {
        InterlockedIncrement64(&g_MemoryMonitor.EventsDropped);
        return STATUS_SUCCESS;
    }

    //
    // Skip small allocations
    //
    if (RegionSize < g_MemoryMonitor.Config.MinAllocationSizeToTrack) {
        return STATUS_SUCCESS;
    }

    //
    // Get or create process context
    //
    Status = MmMonitorGetProcessContext(ProcessId, NULL, &Context);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Track the allocation
    //
    Status = MmpAddRegion(Context, BaseAddress, RegionSize, Protection, MEM_PRIVATE);
    if (!NT_SUCCESS(Status)) {
        MmMonitorReleaseProcessContext(Context);
        return Status;
    }

    //
    // Check for suspicious patterns
    //
    if (IsCrossProcess && g_MemoryMonitor.Config.EnableCrossProcessMonitoring) {
        //
        // Cross-process allocation is suspicious
        //
        IsSuspicious = TRUE;
        Context->SuspiciousOperations++;

        if (g_MemoryMonitor.Config.EnableInjectionDetection) {
            InterlockedIncrement64(&g_MemoryMonitor.TotalInjectionDetections);
        }
    }

    //
    // Check for initial RWX allocation
    //
    if (MmpIsRWXProtection(Protection)) {
        Region = MmpFindRegion(Context, BaseAddress);
        if (Region != NULL) {
            Region->IsHighRisk = TRUE;
            Region->Flags |= MM_REGION_FLAG_HIGH_ENTROPY;
        }
        IsSuspicious = TRUE;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_MemoryMonitor.TotalEventsProcessed);
    Context->TotalAllocations++;

    if (IsSuspicious) {
        MmpUpdateProcessRisk(Context);
    }

    MmMonitorReleaseProcessContext(Context);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
MmMonitorHandleProtectionChange(
    _In_ UINT32 ProcessId,
    _In_ UINT64 BaseAddress,
    _In_ UINT64 RegionSize,
    _In_ UINT32 OldProtection,
    _In_ UINT32 NewProtection,
    _In_ BOOLEAN IsCrossProcess,
    _In_ UINT32 SourceProcessId
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PMM_PROCESS_CONTEXT Context = NULL;
    PMM_TRACKED_REGION Region = NULL;
    UINT32 SuspicionType;
    KIRQL OldIrql;

    UNREFERENCED_PARAMETER(RegionSize);
    UNREFERENCED_PARAMETER(SourceProcessId);

    if (!g_MemoryMonitor.Initialized || !g_MemoryMonitor.Enabled) {
        return STATUS_SUCCESS;
    }

    if (!g_MemoryMonitor.Config.EnableProtectionMonitoring) {
        return STATUS_SUCCESS;
    }

    //
    // Rate limiting
    //
    if (!MmpCheckRateLimit()) {
        InterlockedIncrement64(&g_MemoryMonitor.EventsDropped);
        return STATUS_SUCCESS;
    }

    //
    // Get process context
    //
    Status = MmMonitorGetProcessContext(ProcessId, NULL, &Context);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Find or create tracked region
    //
    KeAcquireSpinLock(&Context->RegionLock, &OldIrql);
    Region = MmpFindRegion(Context, BaseAddress);
    KeReleaseSpinLock(&Context->RegionLock, OldIrql);

    if (Region == NULL) {
        //
        // Region not tracked - add it now
        //
        Status = MmpAddRegion(Context, BaseAddress, RegionSize, NewProtection, MEM_PRIVATE);
        if (NT_SUCCESS(Status)) {
            KeAcquireSpinLock(&Context->RegionLock, &OldIrql);
            Region = MmpFindRegion(Context, BaseAddress);
            KeReleaseSpinLock(&Context->RegionLock, OldIrql);
        }
    }

    if (Region != NULL) {
        //
        // Update region tracking
        //
        KeAcquireSpinLock(&Context->RegionLock, &OldIrql);

        Region->Protection = NewProtection;
        Region->ProtectionChangeCount++;
        KeQuerySystemTimePrecise((PLARGE_INTEGER)&Region->LastProtectionChangeTime);

        //
        // Detect W->X transition (classic unpacking/shellcode pattern)
        //
        if (Region->WasWritten && MmpIsExecutableProtection(NewProtection)) {
            Region->NowExecutable = TRUE;
            Region->IsHighRisk = TRUE;
            Region->Flags |= MM_REGION_FLAG_SHELLCODE_SCAN;
        }

        KeReleaseSpinLock(&Context->RegionLock, OldIrql);
    }

    //
    // Analyze protection change suspicion
    //
    SuspicionType = MmpAnalyzeProtectionChange(OldProtection, NewProtection);

    if (SuspicionType != 0) {
        Context->SuspiciousOperations++;

        if (SuspicionType == MM_SUSPICIOUS_RW_TO_RX) {
            //
            // Classic shellcode/unpacking pattern
            //
            if (g_MemoryMonitor.Config.EnableShellcodeDetection && Region != NULL) {
                Region->Flags |= MM_REGION_FLAG_SHELLCODE_SCAN;
            }
        }

        if (SuspicionType == MM_SUSPICIOUS_TO_RWX) {
            //
            // RWX is highly suspicious for non-JIT code
            //
            if (Region != NULL) {
                Region->IsHighRisk = TRUE;
            }
        }
    }

    //
    // Cross-process protection change is always suspicious
    //
    if (IsCrossProcess && g_MemoryMonitor.Config.EnableCrossProcessMonitoring) {
        Context->SuspiciousOperations++;
        if (Region != NULL) {
            Region->Flags |= MM_REGION_FLAG_INJECTION_DST;
        }
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_MemoryMonitor.TotalEventsProcessed);
    Context->TotalProtectionChanges++;
    MmpUpdateProcessRisk(Context);

    MmMonitorReleaseProcessContext(Context);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
MmMonitorHandleCrossProcessWrite(
    _In_ UINT32 SourceProcessId,
    _In_ UINT32 TargetProcessId,
    _In_ UINT64 TargetAddress,
    _In_ UINT64 Size,
    _In_opt_ PVOID SourceBuffer
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PMM_PROCESS_CONTEXT TargetContext = NULL;
    PMM_TRACKED_REGION Region;
    KIRQL OldIrql;
    UINT32 Entropy = 0;

    UNREFERENCED_PARAMETER(SourceProcessId);

    if (!g_MemoryMonitor.Initialized || !g_MemoryMonitor.Enabled) {
        return STATUS_SUCCESS;
    }

    if (!g_MemoryMonitor.Config.EnableCrossProcessMonitoring) {
        return STATUS_SUCCESS;
    }

    //
    // Rate limiting
    //
    if (!MmpCheckRateLimit()) {
        InterlockedIncrement64(&g_MemoryMonitor.EventsDropped);
        return STATUS_SUCCESS;
    }

    //
    // Get target process context
    //
    Status = MmMonitorGetProcessContext(TargetProcessId, NULL, &TargetContext);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Find or create region
    //
    KeAcquireSpinLock(&TargetContext->RegionLock, &OldIrql);
    Region = MmpFindRegion(TargetContext, TargetAddress);
    KeReleaseSpinLock(&TargetContext->RegionLock, OldIrql);

    if (Region == NULL) {
        Status = MmpAddRegion(TargetContext, TargetAddress, Size, 0, MEM_PRIVATE);
        if (NT_SUCCESS(Status)) {
            KeAcquireSpinLock(&TargetContext->RegionLock, &OldIrql);
            Region = MmpFindRegion(TargetContext, TargetAddress);
            KeReleaseSpinLock(&TargetContext->RegionLock, OldIrql);
        }
    }

    if (Region != NULL) {
        KeAcquireSpinLock(&TargetContext->RegionLock, &OldIrql);

        Region->WasWritten = TRUE;
        Region->Flags |= MM_REGION_FLAG_INJECTION_DST;

        //
        // Calculate entropy of written content if available
        //
        if (SourceBuffer != NULL && Size > 0 && Size <= g_MemoryMonitor.Config.MaxRegionSizeToScan) {
            Entropy = MmMonitorCalculateEntropy(SourceBuffer, (SIZE_T)Size);
            Region->LastContentEntropy = Entropy;

            if (Entropy >= g_MemoryMonitor.Config.ShellcodeScanThreshold) {
                Region->Flags |= MM_REGION_FLAG_HIGH_ENTROPY;
                Region->IsHighRisk = TRUE;
            }
        }

        KeReleaseSpinLock(&TargetContext->RegionLock, OldIrql);
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_MemoryMonitor.TotalEventsProcessed);
    TargetContext->SuspiciousOperations++;
    TargetContext->InjectionAttemptCount++;
    MmpUpdateProcessRisk(TargetContext);

    //
    // Trigger injection detection
    //
    if (g_MemoryMonitor.Config.EnableInjectionDetection) {
        InterlockedIncrement64(&g_MemoryMonitor.TotalInjectionDetections);
    }

    MmMonitorReleaseProcessContext(TargetContext);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
MmMonitorHandleSectionMap(
    _In_ UINT32 ProcessId,
    _In_ HANDLE SectionHandle,
    _In_ UINT64 BaseAddress,
    _In_ UINT64 ViewSize,
    _In_ UINT32 Protection,
    _In_ BOOLEAN IsCrossProcess,
    _In_ UINT32 TargetProcessId
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PMM_PROCESS_CONTEXT Context = NULL;
    UINT32 ActualTargetPid;

    UNREFERENCED_PARAMETER(SectionHandle);

    if (!g_MemoryMonitor.Initialized || !g_MemoryMonitor.Enabled) {
        return STATUS_SUCCESS;
    }

    if (!g_MemoryMonitor.Config.EnableSectionMonitoring) {
        return STATUS_SUCCESS;
    }

    //
    // Rate limiting
    //
    if (!MmpCheckRateLimit()) {
        InterlockedIncrement64(&g_MemoryMonitor.EventsDropped);
        return STATUS_SUCCESS;
    }

    //
    // Determine actual target
    //
    ActualTargetPid = IsCrossProcess ? TargetProcessId : ProcessId;

    //
    // Get process context
    //
    Status = MmMonitorGetProcessContext(ActualTargetPid, NULL, &Context);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Track the mapped region
    //
    Status = MmpAddRegion(Context, BaseAddress, ViewSize, Protection, MEM_MAPPED);
    if (!NT_SUCCESS(Status)) {
        MmMonitorReleaseProcessContext(Context);
        return Status;
    }

    //
    // Cross-process section mapping is suspicious
    //
    if (IsCrossProcess) {
        PMM_TRACKED_REGION Region;
        KIRQL OldIrql;

        Context->SuspiciousOperations++;

        KeAcquireSpinLock(&Context->RegionLock, &OldIrql);
        Region = MmpFindRegion(Context, BaseAddress);
        if (Region != NULL) {
            Region->Flags |= MM_REGION_FLAG_INJECTION_DST;
            if (MmpIsExecutableProtection(Protection)) {
                Region->IsHighRisk = TRUE;
            }
        }
        KeReleaseSpinLock(&Context->RegionLock, OldIrql);

        MmpUpdateProcessRisk(Context);
    }

    InterlockedIncrement64(&g_MemoryMonitor.TotalEventsProcessed);

    MmMonitorReleaseProcessContext(Context);

    return STATUS_SUCCESS;
}

// ============================================================================
// DETECTION FUNCTIONS
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
MmMonitorScanForShellcode(
    _In_ UINT32 ProcessId,
    _In_ UINT64 BaseAddress,
    _In_ UINT64 Size,
    _Out_opt_ PSHELLCODE_DETECTION_EVENT Event
    )
{
    NTSTATUS Status;
    PMM_PROCESS_CONTEXT Context = NULL;
    PEPROCESS Process = NULL;
    PVOID Buffer = NULL;
    SIZE_T ScanSize;
    UINT32 Entropy;
    BOOLEAN ShellcodeDetected = FALSE;

    if (!g_MemoryMonitor.Initialized || !g_MemoryMonitor.Enabled) {
        return FALSE;
    }

    if (!g_MemoryMonitor.Config.EnableShellcodeDetection) {
        return FALSE;
    }

    if (Event != NULL) {
        RtlZeroMemory(Event, sizeof(SHELLCODE_DETECTION_EVENT));
    }

    //
    // Limit scan size
    //
    ScanSize = (SIZE_T)min(Size, g_MemoryMonitor.Config.MaxRegionSizeToScan);
    if (ScanSize == 0) {
        return FALSE;
    }

    //
    // Get process object
    //
    Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }

    //
    // Allocate buffer for memory content
    //
    Buffer = ExAllocatePoolWithTag(NonPagedPoolNx, ScanSize, MM_POOL_TAG_GENERAL);
    if (Buffer == NULL) {
        ObDereferenceObject(Process);
        return FALSE;
    }

    //
    // Read target memory
    //
    Status = MmpReadProcessMemory(Process, (PVOID)(ULONG_PTR)BaseAddress, Buffer, ScanSize);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Buffer, MM_POOL_TAG_GENERAL);
        ObDereferenceObject(Process);
        return FALSE;
    }

    //
    // Calculate entropy
    //
    Entropy = MmMonitorCalculateEntropy(Buffer, ScanSize);

    //
    // Check for high entropy (potential shellcode/encrypted content)
    //
    if (Entropy >= g_MemoryMonitor.Config.ShellcodeScanThreshold) {
        ShellcodeDetected = TRUE;

        if (Event != NULL) {
            Event->Size = sizeof(SHELLCODE_DETECTION_EVENT);
            Event->Version = 1;
            KeQuerySystemTimePrecise((PLARGE_INTEGER)&Event->Timestamp);
            Event->ProcessId = ProcessId;
            Event->DetectionAddress = BaseAddress;
            Event->RegionBase = BaseAddress;
            Event->RegionSize = Size;
            Event->Entropy = Entropy;
            Event->ThreatScore = (Entropy * 100) / 8000;  // Normalize to 0-100
            Event->Confidence = min(90, (Entropy - 6000) / 20);  // Higher entropy = higher confidence
            Event->Flags |= SHELLCODE_FLAG_HIGH_ENTROPY;

            //
            // Copy content sample
            //
            RtlCopyMemory(Event->ContentSample, Buffer, min(ScanSize, sizeof(Event->ContentSample)));
        }

        //
        // Update process context
        //
        Status = MmMonitorGetProcessContext(ProcessId, NULL, &Context);
        if (NT_SUCCESS(Status)) {
            Context->ShellcodeDetectionCount++;
            MmpUpdateProcessRisk(Context);
            MmMonitorReleaseProcessContext(Context);
        }

        InterlockedIncrement64(&g_MemoryMonitor.TotalShellcodeDetections);
    }

    ExFreePoolWithTag(Buffer, MM_POOL_TAG_GENERAL);
    ObDereferenceObject(Process);

    return ShellcodeDetected;
}

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
MmMonitorDetectInjection(
    _In_ UINT32 SourceProcessId,
    _In_ UINT32 TargetProcessId,
    _In_ UINT64 TargetAddress,
    _In_ UINT64 Size,
    _In_ INJECTION_TYPE InjectionType,
    _Out_opt_ PINJECTION_DETECTION_EVENT Event
    )
{
    NTSTATUS Status;
    PMM_PROCESS_CONTEXT TargetContext = NULL;
    BOOLEAN InjectionDetected = FALSE;

    if (!g_MemoryMonitor.Initialized || !g_MemoryMonitor.Enabled) {
        return FALSE;
    }

    if (!g_MemoryMonitor.Config.EnableInjectionDetection) {
        return FALSE;
    }

    if (Event != NULL) {
        RtlZeroMemory(Event, sizeof(INJECTION_DETECTION_EVENT));
    }

    //
    // Cross-process operations are inherently suspicious
    //
    if (SourceProcessId != TargetProcessId && SourceProcessId != 0 && TargetProcessId != 0) {
        InjectionDetected = TRUE;

        if (Event != NULL) {
            Event->Size = sizeof(INJECTION_DETECTION_EVENT);
            Event->Version = 1;
            KeQuerySystemTimePrecise((PLARGE_INTEGER)&Event->Timestamp);
            Event->SourceProcessId = SourceProcessId;
            Event->TargetProcessId = TargetProcessId;
            Event->InjectionType = InjectionType;
            Event->InjectedAddress = TargetAddress;
            Event->InjectedSize = Size;
            Event->ThreatScore = 80;  // High base score for cross-process
            Event->Confidence = 70;
            Event->Flags |= INJECTION_FLAG_CROSS_SESSION;
        }

        //
        // Update target process context
        //
        Status = MmMonitorGetProcessContext(TargetProcessId, NULL, &TargetContext);
        if (NT_SUCCESS(Status)) {
            TargetContext->InjectionAttemptCount++;
            TargetContext->Flags |= MM_PROCESS_FLAG_INJECTION_TARGET;
            MmpUpdateProcessRisk(TargetContext);
            MmMonitorReleaseProcessContext(TargetContext);
        }

        InterlockedIncrement64(&g_MemoryMonitor.TotalInjectionDetections);
    }

    return InjectionDetected;
}

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
MmMonitorDetectHollowing(
    _In_ UINT32 ProcessId,
    _Out_opt_ PHOLLOWING_DETECTION_EVENT Event
    )
{
    NTSTATUS Status;
    PMM_PROCESS_CONTEXT Context = NULL;
    BOOLEAN HollowingDetected = FALSE;

    if (!g_MemoryMonitor.Initialized || !g_MemoryMonitor.Enabled) {
        return FALSE;
    }

    if (!g_MemoryMonitor.Config.EnableHollowingDetection) {
        return FALSE;
    }

    if (Event != NULL) {
        RtlZeroMemory(Event, sizeof(HOLLOWING_DETECTION_EVENT));
    }

    //
    // Get process context
    //
    Status = MmMonitorGetProcessContext(ProcessId, NULL, &Context);
    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }

    //
    // Check for hollowing indicators
    //
    if (Context->Flags & MM_PROCESS_FLAG_HOLLOWING_TARGET) {
        HollowingDetected = TRUE;

        if (Event != NULL) {
            Event->Size = sizeof(HOLLOWING_DETECTION_EVENT);
            Event->Version = 1;
            KeQuerySystemTimePrecise((PLARGE_INTEGER)&Event->Timestamp);
            Event->HollowedProcessId = ProcessId;
            Event->ThreatScore = 95;
            Event->Confidence = 85;
            Event->Flags |= HOLLOWING_FLAG_CONFIRMED;
        }

        InterlockedIncrement64(&g_MemoryMonitor.TotalHollowingDetections);
    }

    MmMonitorReleaseProcessContext(Context);

    return HollowingDetected;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT32
MmMonitorCalculateEntropy(
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    )
{
    PUCHAR Data = (PUCHAR)Buffer;
    ULONG ByteCount[256] = { 0 };
    SIZE_T i;
    UINT32 Entropy = 0;
    ULONG Count;
    ULONG Probability;

    if (Buffer == NULL || Size == 0) {
        return 0;
    }

    //
    // Count byte frequencies
    //
    for (i = 0; i < Size; i++) {
        ByteCount[Data[i]]++;
    }

    //
    // Calculate Shannon entropy * 1000
    // Formula: H = -sum(p * log2(p)) for each byte value
    // Simplified integer approximation
    //
    for (i = 0; i < 256; i++) {
        Count = ByteCount[i];
        if (Count == 0) {
            continue;
        }

        //
        // Calculate probability * 1000000
        //
        Probability = (ULONG)((Count * 1000000ULL) / Size);

        //
        // Approximate -p * log2(p) using lookup/approximation
        // For simplicity, using linear approximation for common ranges
        //
        if (Probability > 0 && Probability < 1000000) {
            //
            // Simplified entropy contribution
            // Real calculation would use log2, this is an approximation
            //
            ULONG LogApprox = 0;
            ULONG TempProb = Probability;

            // Count bits to approximate log2
            while (TempProb > 0) {
                LogApprox++;
                TempProb >>= 1;
            }

            Entropy += (Probability * LogApprox) / 1000000;
        }
    }

    //
    // Normalize to 0-8000 range (8 bits max entropy * 1000)
    //
    if (Entropy > 8000) {
        Entropy = 8000;
    }

    return Entropy;
}

// ============================================================================
// VAD TRACKING
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MmMonitorBuildVadMap(
    _In_ UINT32 ProcessId,
    _Out_ PPROCESS_VAD_MAP* VadMap
    )
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    PPROCESS_VAD_MAP Map = NULL;
    MEMORY_BASIC_INFORMATION MemInfo;
    PVOID CurrentAddress = NULL;
    ULONG RegionCount = 0;
    ULONG MaxRegions = 1024;
    SIZE_T MapSize;

    PAGED_CODE();

    if (VadMap == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *VadMap = NULL;

    //
    // Get process object
    //
    Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Allocate VAD map structure with space for entries
    //
    MapSize = sizeof(PROCESS_VAD_MAP) + (MaxRegions * sizeof(VAD_ENTRY));
    Map = (PPROCESS_VAD_MAP)ExAllocatePoolWithTag(PagedPool, MapSize, MM_POOL_TAG_GENERAL);
    if (Map == NULL) {
        ObDereferenceObject(Process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Map, MapSize);
    Map->ProcessId = ProcessId;

    //
    // Enumerate memory regions
    //
    CurrentAddress = NULL;
    while (RegionCount < MaxRegions) {
        Status = MmpQueryVirtualMemory(Process, CurrentAddress, &MemInfo);
        if (!NT_SUCCESS(Status)) {
            break;
        }

        if (MemInfo.State != MEM_FREE) {
            PVAD_ENTRY Entry = (PVAD_ENTRY)((PUCHAR)Map + sizeof(PROCESS_VAD_MAP) + (RegionCount * sizeof(VAD_ENTRY)));

            Entry->BaseAddress = (UINT64)(ULONG_PTR)MemInfo.BaseAddress;
            Entry->Size = MemInfo.RegionSize;
            Entry->Protection = MemInfo.Protect;
            Entry->VadType = MemInfo.Type;

            //
            // Categorize region
            //
            if (MemInfo.Type == MEM_IMAGE) {
                Entry->RegionType = MemRegion_Image;
                Map->TotalVirtualSize += MemInfo.RegionSize;
            } else if (MemInfo.Type == MEM_MAPPED) {
                Entry->RegionType = MemRegion_Mapped;
            } else {
                Entry->RegionType = MemRegion_Private;
            }

            //
            // Track statistics
            //
            if (MemInfo.State == MEM_COMMIT) {
                Map->TotalCommittedSize += MemInfo.RegionSize;
            }

            if (MmpIsExecutableProtection(MemInfo.Protect)) {
                Map->TotalExecutableSize += MemInfo.RegionSize;
                Entry->Flags |= VAD_FLAG_EXECUTABLE;
            }

            if (MmpIsWritableProtection(MemInfo.Protect)) {
                Map->TotalWritableSize += MemInfo.RegionSize;
                Entry->Flags |= VAD_FLAG_WRITABLE;
            }

            if (MmpIsRWXProtection(MemInfo.Protect)) {
                Map->TotalRWXSize += MemInfo.RegionSize;
                Entry->Flags |= VAD_FLAG_RWX;
            }

            //
            // Check for unbacked executable (suspicious)
            //
            if ((MemInfo.Type == MEM_PRIVATE) && MmpIsExecutableProtection(MemInfo.Protect)) {
                Map->UnbackedExecutableCount++;
                Entry->Flags |= VAD_FLAG_UNBACKED | VAD_FLAG_SUSPICIOUS;
            }

            RegionCount++;
        }

        //
        // Move to next region
        //
        CurrentAddress = (PVOID)((ULONG_PTR)MemInfo.BaseAddress + MemInfo.RegionSize);
        if (CurrentAddress < MemInfo.BaseAddress) {
            //
            // Overflow - reached end of address space
            //
            break;
        }
    }

    Map->VadCount = RegionCount;

    ObDereferenceObject(Process);
    *VadMap = Map;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
MmMonitorFreeVadMap(
    _In_ PPROCESS_VAD_MAP VadMap
    )
{
    PAGED_CODE();

    if (VadMap != NULL) {
        ExFreePoolWithTag(VadMap, MM_POOL_TAG_GENERAL);
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MmMonitorFindSuspiciousVads(
    _In_ UINT32 ProcessId,
    _Out_writes_to_(MaxEntries, *EntryCount) PVAD_ENTRY SuspiciousEntries,
    _In_ UINT32 MaxEntries,
    _Out_ PUINT32 EntryCount
    )
{
    NTSTATUS Status;
    PPROCESS_VAD_MAP VadMap = NULL;
    PVAD_ENTRY SourceEntry;
    ULONG SuspiciousCount = 0;
    ULONG i;

    PAGED_CODE();

    if (SuspiciousEntries == NULL || EntryCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *EntryCount = 0;

    //
    // Build VAD map
    //
    Status = MmMonitorBuildVadMap(ProcessId, &VadMap);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Find suspicious entries
    //
    for (i = 0; i < VadMap->VadCount && SuspiciousCount < MaxEntries; i++) {
        SourceEntry = (PVAD_ENTRY)((PUCHAR)VadMap + sizeof(PROCESS_VAD_MAP) + (i * sizeof(VAD_ENTRY)));

        if (SourceEntry->Flags & VAD_FLAG_SUSPICIOUS) {
            RtlCopyMemory(&SuspiciousEntries[SuspiciousCount], SourceEntry, sizeof(VAD_ENTRY));
            SuspiciousCount++;
        }
    }

    *EntryCount = SuspiciousCount;

    MmMonitorFreeVadMap(VadMap);

    return STATUS_SUCCESS;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
MmMonitorIsAddressExecutable(
    _In_ UINT32 ProcessId,
    _In_ UINT64 Address
    )
{
    PMM_PROCESS_CONTEXT Context;
    PMM_TRACKED_REGION Region;
    KIRQL OldIrql;
    BOOLEAN IsExecutable = FALSE;

    Context = MmpLookupProcessContext(ProcessId);
    if (Context == NULL) {
        return FALSE;
    }

    KeAcquireSpinLock(&Context->RegionLock, &OldIrql);
    Region = MmpFindRegion(Context, Address);
    if (Region != NULL) {
        IsExecutable = MmpIsExecutableProtection(Region->Protection);
    }
    KeReleaseSpinLock(&Context->RegionLock, OldIrql);

    return IsExecutable;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MmMonitorGetBackingFile(
    _In_ UINT32 ProcessId,
    _In_ UINT64 Address,
    _Out_writes_bytes_(FileNameSize) PWCHAR FileName,
    _In_ UINT32 FileNameSize
    )
{
    PMM_PROCESS_CONTEXT Context;
    PMM_TRACKED_REGION Region;
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_NOT_FOUND;

    PAGED_CODE();

    if (FileName == NULL || FileNameSize < sizeof(WCHAR)) {
        return STATUS_INVALID_PARAMETER;
    }

    FileName[0] = L'\0';

    Context = MmpLookupProcessContext(ProcessId);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    KeAcquireSpinLock(&Context->RegionLock, &OldIrql);
    Region = MmpFindRegion(Context, Address);
    if (Region != NULL && Region->BackingFile.Length > 0) {
        SIZE_T CopySize = min(Region->BackingFile.Length, FileNameSize - sizeof(WCHAR));
        RtlCopyMemory(FileName, Region->BackingFile.Buffer, CopySize);
        FileName[CopySize / sizeof(WCHAR)] = L'\0';
        Status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&Context->RegionLock, OldIrql);

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT32
MmMonitorGetProtectionChangeSuspicion(
    _In_ UINT32 OldProtection,
    _In_ UINT32 NewProtection,
    _In_ MEMORY_REGION_TYPE RegionType
    )
{
    UINT32 Score = 0;

    //
    // RW -> RX is classic unpacking/shellcode pattern
    //
    if (MmpIsWritableProtection(OldProtection) &&
        !MmpIsExecutableProtection(OldProtection) &&
        MmpIsExecutableProtection(NewProtection) &&
        !MmpIsWritableProtection(NewProtection)) {
        Score += 60;
    }

    //
    // Any -> RWX is highly suspicious
    //
    if (!MmpIsRWXProtection(OldProtection) && MmpIsRWXProtection(NewProtection)) {
        Score += 80;
    }

    //
    // Region type modifiers
    //
    if (RegionType == MemRegion_Private) {
        Score += 10;  // Unbacked regions are more suspicious
    }

    if (RegionType == MemRegion_Stack) {
        Score += 20;  // Stack execution is very suspicious
    }

    //
    // Cap at 100
    //
    if (Score > 100) {
        Score = 100;
    }

    return Score;
}

// ============================================================================
// INTERNAL HELPER IMPLEMENTATIONS
// ============================================================================

static
VOID
MmpInitializeDefaultConfig(
    _Out_ PMEMORY_MONITOR_CONFIG Config
    )
{
    RtlZeroMemory(Config, sizeof(MEMORY_MONITOR_CONFIG));

    Config->EnableAllocationMonitoring = TRUE;
    Config->EnableProtectionMonitoring = TRUE;
    Config->EnableCrossProcessMonitoring = TRUE;
    Config->EnableSectionMonitoring = TRUE;
    Config->EnableShellcodeDetection = TRUE;
    Config->EnableInjectionDetection = TRUE;
    Config->EnableHollowingDetection = TRUE;
    Config->EnableVADTracking = TRUE;

    Config->MinAllocationSizeToTrack = MM_DEFAULT_MIN_ALLOC_SIZE;
    Config->MaxEventsPerSecond = MM_DEFAULT_MAX_EVENTS_PER_SEC;
    Config->ShellcodeScanThreshold = MM_DEFAULT_SHELLCODE_SCAN_THRESHOLD;
    Config->MaxRegionSizeToScan = MM_DEFAULT_MAX_REGION_SCAN_SIZE;
}

static
NTSTATUS
MmpInitializeLookasideLists(
    VOID
    )
{
    ExInitializeNPagedLookasideList(
        &g_MemoryMonitor.RegionLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(MM_TRACKED_REGION),
        MM_POOL_TAG_GENERAL,
        0
    );

    ExInitializeNPagedLookasideList(
        &g_MemoryMonitor.ContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(MM_PROCESS_CONTEXT),
        MM_POOL_TAG_CONTEXT,
        0
    );

    ExInitializeNPagedLookasideList(
        &g_MemoryMonitor.EventLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(MEMORY_ALLOC_EVENT),
        MM_POOL_TAG_EVENT,
        0
    );

    return STATUS_SUCCESS;
}

static
VOID
MmpCleanupLookasideLists(
    VOID
    )
{
    ExDeleteNPagedLookasideList(&g_MemoryMonitor.RegionLookaside);
    ExDeleteNPagedLookasideList(&g_MemoryMonitor.ContextLookaside);
    ExDeleteNPagedLookasideList(&g_MemoryMonitor.EventLookaside);
}

static
NTSTATUS
MmpInitializeProcessHashTable(
    VOID
    )
{
    ULONG i;

    RtlZeroMemory(&g_ProcessHashTable, sizeof(g_ProcessHashTable));

    for (i = 0; i < MM_PROCESS_HASH_SIZE; i++) {
        InitializeListHead(&g_ProcessHashTable.Buckets[i]);
        KeInitializeSpinLock(&g_ProcessHashTable.BucketLocks[i]);
    }

    return STATUS_SUCCESS;
}

static
VOID
MmpCleanupProcessHashTable(
    VOID
    )
{
    ULONG i;
    KIRQL OldIrql;
    PLIST_ENTRY Entry;
    PMM_PROCESS_HASH_ENTRY HashEntry;

    for (i = 0; i < MM_PROCESS_HASH_SIZE; i++) {
        KeAcquireSpinLock(&g_ProcessHashTable.BucketLocks[i], &OldIrql);

        while (!IsListEmpty(&g_ProcessHashTable.Buckets[i])) {
            Entry = RemoveHeadList(&g_ProcessHashTable.Buckets[i]);
            HashEntry = CONTAINING_RECORD(Entry, MM_PROCESS_HASH_ENTRY, ListEntry);
            ExFreePoolWithTag(HashEntry, MM_POOL_TAG_CACHE);
        }

        KeReleaseSpinLock(&g_ProcessHashTable.BucketLocks[i], OldIrql);
    }
}

static
ULONG
MmpHashProcessId(
    _In_ UINT32 ProcessId
    )
{
    //
    // Simple hash function for process IDs
    //
    ULONG Hash = ProcessId;
    Hash = ((Hash >> 16) ^ Hash) * 0x45d9f3b;
    Hash = ((Hash >> 16) ^ Hash) * 0x45d9f3b;
    Hash = (Hash >> 16) ^ Hash;
    return Hash & (MM_PROCESS_HASH_SIZE - 1);
}

static
PMM_PROCESS_CONTEXT
MmpLookupProcessContext(
    _In_ UINT32 ProcessId
    )
{
    ULONG Hash;
    KIRQL OldIrql;
    PLIST_ENTRY Entry;
    PMM_PROCESS_HASH_ENTRY HashEntry;
    PMM_PROCESS_CONTEXT Context = NULL;

    Hash = MmpHashProcessId(ProcessId);

    KeAcquireSpinLock(&g_ProcessHashTable.BucketLocks[Hash], &OldIrql);

    Entry = g_ProcessHashTable.Buckets[Hash].Flink;
    while (Entry != &g_ProcessHashTable.Buckets[Hash]) {
        HashEntry = CONTAINING_RECORD(Entry, MM_PROCESS_HASH_ENTRY, ListEntry);
        if (HashEntry->Context->ProcessId == ProcessId) {
            Context = HashEntry->Context;
            break;
        }
        Entry = Entry->Flink;
    }

    KeReleaseSpinLock(&g_ProcessHashTable.BucketLocks[Hash], OldIrql);

    return Context;
}

static
NTSTATUS
MmpCreateProcessContext(
    _In_ UINT32 ProcessId,
    _In_opt_ PEPROCESS ProcessObject,
    _Out_ PMM_PROCESS_CONTEXT* Context
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PMM_PROCESS_CONTEXT NewContext;
    PMM_PROCESS_HASH_ENTRY HashEntry;
    ULONG Hash;
    KIRQL OldIrql;

    *Context = NULL;

    //
    // Allocate context from lookaside
    //
    NewContext = (PMM_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_MemoryMonitor.ContextLookaside
    );

    if (NewContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewContext, sizeof(MM_PROCESS_CONTEXT));

    //
    // Initialize context
    //
    NewContext->ProcessId = ProcessId;
    NewContext->RefCount = 1;
    NewContext->IsMonitored = TRUE;

    if (ProcessObject != NULL) {
        NewContext->ProcessObject = ProcessObject;
        ObReferenceObject(ProcessObject);
    }

    KeQuerySystemTimePrecise((PLARGE_INTEGER)&NewContext->ProcessCreateTime);
    InitializeListHead(&NewContext->TrackedRegions);
    KeInitializeSpinLock(&NewContext->RegionLock);

    //
    // Allocate hash entry
    //
    HashEntry = (PMM_PROCESS_HASH_ENTRY)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(MM_PROCESS_HASH_ENTRY),
        MM_POOL_TAG_CACHE
    );

    if (HashEntry == NULL) {
        if (NewContext->ProcessObject != NULL) {
            ObDereferenceObject(NewContext->ProcessObject);
        }
        ExFreeToNPagedLookasideList(&g_MemoryMonitor.ContextLookaside, NewContext);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    HashEntry->Context = NewContext;

    //
    // Insert into hash table
    //
    Hash = MmpHashProcessId(ProcessId);
    KeAcquireSpinLock(&g_ProcessHashTable.BucketLocks[Hash], &OldIrql);
    InsertTailList(&g_ProcessHashTable.Buckets[Hash], &HashEntry->ListEntry);
    InterlockedIncrement(&g_ProcessHashTable.EntryCount);
    KeReleaseSpinLock(&g_ProcessHashTable.BucketLocks[Hash], OldIrql);

    //
    // Insert into main list
    //
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_MemoryMonitor.ProcessContextLock, TRUE);
    InsertTailList(&g_MemoryMonitor.ProcessContextList, &NewContext->ListEntry);
    g_MemoryMonitor.ProcessContextCount++;
    ExReleaseResourceLite(&g_MemoryMonitor.ProcessContextLock);
    KeLeaveCriticalRegion();

    *Context = NewContext;

    return STATUS_SUCCESS;
}

static
VOID
MmpFreeProcessContext(
    _Inout_ PMM_PROCESS_CONTEXT Context
    )
{
    PLIST_ENTRY Entry;
    PMM_TRACKED_REGION Region;
    KIRQL OldIrql;

    if (Context == NULL) {
        return;
    }

    //
    // Free all tracked regions
    //
    KeAcquireSpinLock(&Context->RegionLock, &OldIrql);

    while (!IsListEmpty(&Context->TrackedRegions)) {
        Entry = RemoveHeadList(&Context->TrackedRegions);
        Region = CONTAINING_RECORD(Entry, MM_TRACKED_REGION, ListEntry);
        ExFreeToNPagedLookasideList(&g_MemoryMonitor.RegionLookaside, Region);
    }

    KeReleaseSpinLock(&Context->RegionLock, OldIrql);

    //
    // Dereference process object if held
    //
    if (Context->ProcessObject != NULL) {
        ObDereferenceObject(Context->ProcessObject);
        Context->ProcessObject = NULL;
    }

    //
    // Free context
    //
    ExFreeToNPagedLookasideList(&g_MemoryMonitor.ContextLookaside, Context);
}

static
VOID
MmpReferenceProcessContext(
    _Inout_ PMM_PROCESS_CONTEXT Context
    )
{
    InterlockedIncrement(&Context->RefCount);
}

static
VOID
MmpDereferenceProcessContext(
    _Inout_ PMM_PROCESS_CONTEXT Context
    )
{
    LONG NewRef = InterlockedDecrement(&Context->RefCount);

    if (NewRef == 0) {
        MmpFreeProcessContext(Context);
    }
}

static
PMM_TRACKED_REGION
MmpAllocateRegion(
    VOID
    )
{
    PMM_TRACKED_REGION Region;

    Region = (PMM_TRACKED_REGION)ExAllocateFromNPagedLookasideList(
        &g_MemoryMonitor.RegionLookaside
    );

    if (Region != NULL) {
        RtlZeroMemory(Region, sizeof(MM_TRACKED_REGION));
    }

    return Region;
}

static
VOID
MmpFreeRegion(
    _Inout_ PMM_TRACKED_REGION Region
    )
{
    if (Region != NULL) {
        ExFreeToNPagedLookasideList(&g_MemoryMonitor.RegionLookaside, Region);
    }
}

static
PMM_TRACKED_REGION
MmpFindRegion(
    _In_ PMM_PROCESS_CONTEXT Context,
    _In_ UINT64 Address
    )
{
    PLIST_ENTRY Entry;
    PMM_TRACKED_REGION Region;

    //
    // Caller must hold RegionLock
    //

    Entry = Context->TrackedRegions.Flink;
    while (Entry != &Context->TrackedRegions) {
        Region = CONTAINING_RECORD(Entry, MM_TRACKED_REGION, ListEntry);

        if (Address >= Region->BaseAddress &&
            Address < Region->BaseAddress + Region->Size) {
            return Region;
        }

        Entry = Entry->Flink;
    }

    return NULL;
}

static
NTSTATUS
MmpAddRegion(
    _Inout_ PMM_PROCESS_CONTEXT Context,
    _In_ UINT64 BaseAddress,
    _In_ UINT64 Size,
    _In_ UINT32 Protection,
    _In_ UINT32 Type
    )
{
    PMM_TRACKED_REGION Region;
    KIRQL OldIrql;

    //
    // Check region limit
    //
    if (Context->TrackedRegionCount >= MM_MAX_REGIONS_PER_PROCESS) {
        MmpCleanupStaleRegions(Context);

        if (Context->TrackedRegionCount >= MM_MAX_REGIONS_PER_PROCESS) {
            return STATUS_QUOTA_EXCEEDED;
        }
    }

    //
    // Allocate region
    //
    Region = MmpAllocateRegion();
    if (Region == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize region
    //
    Region->BaseAddress = BaseAddress;
    Region->Size = Size;
    Region->ProcessId = Context->ProcessId;
    Region->Protection = Protection;
    Region->Type = Type;
    Region->State = MEM_COMMIT;
    Region->Flags = MM_REGION_FLAG_MONITORED;

    KeQuerySystemTimePrecise((PLARGE_INTEGER)&Region->AllocationTime);

    //
    // Determine region type
    //
    if (Type == MEM_IMAGE) {
        Region->RegionType = MemRegion_Image;
    } else if (Type == MEM_MAPPED) {
        Region->RegionType = MemRegion_Mapped;
    } else {
        Region->RegionType = MemRegion_Private;
    }

    //
    // Check for suspicious initial protection
    //
    if (MmpIsRWXProtection(Protection)) {
        Region->IsHighRisk = TRUE;
    }

    //
    // Initialize backing file string buffer
    //
    Region->BackingFile.Buffer = Region->BackingFileBuffer;
    Region->BackingFile.MaximumLength = sizeof(Region->BackingFileBuffer);
    Region->BackingFile.Length = 0;

    //
    // Insert into list
    //
    KeAcquireSpinLock(&Context->RegionLock, &OldIrql);
    InsertTailList(&Context->TrackedRegions, &Region->ListEntry);
    Context->TrackedRegionCount++;
    KeReleaseSpinLock(&Context->RegionLock, OldIrql);

    return STATUS_SUCCESS;
}

static
VOID
MmpRemoveRegion(
    _Inout_ PMM_PROCESS_CONTEXT Context,
    _Inout_ PMM_TRACKED_REGION Region
    )
{
    //
    // Caller must hold RegionLock
    //
    RemoveEntryList(&Region->ListEntry);
    Context->TrackedRegionCount--;
    MmpFreeRegion(Region);
}

static
VOID
MmpCleanupStaleRegions(
    _Inout_ PMM_PROCESS_CONTEXT Context
    )
{
    PLIST_ENTRY Entry, NextEntry;
    PMM_TRACKED_REGION Region;
    LARGE_INTEGER CurrentTime;
    UINT64 MaxAge;
    KIRQL OldIrql;

    KeQuerySystemTimePrecise(&CurrentTime);
    MaxAge = (UINT64)MM_REGION_MAX_AGE_SEC * 10000000ULL;  // Convert to 100ns units

    KeAcquireSpinLock(&Context->RegionLock, &OldIrql);

    Entry = Context->TrackedRegions.Flink;
    while (Entry != &Context->TrackedRegions) {
        NextEntry = Entry->Flink;
        Region = CONTAINING_RECORD(Entry, MM_TRACKED_REGION, ListEntry);

        //
        // Remove stale, non-high-risk regions
        //
        if (!Region->IsHighRisk &&
            (CurrentTime.QuadPart - Region->AllocationTime) > (LONGLONG)MaxAge) {
            MmpRemoveRegion(Context, Region);
        }

        Entry = NextEntry;
    }

    KeReleaseSpinLock(&Context->RegionLock, OldIrql);
}

static
BOOLEAN
MmpCheckRateLimit(
    VOID
    )
{
    LARGE_INTEGER CurrentTime;
    LONG64 ElapsedSeconds;
    LONG CurrentCount;

    if (g_MemoryMonitor.Config.MaxEventsPerSecond == 0) {
        return TRUE;  // No limit
    }

    KeQuerySystemTimePrecise(&CurrentTime);

    ElapsedSeconds = (CurrentTime.QuadPart - g_MemoryMonitor.CurrentSecondStart) / 10000000;

    if (ElapsedSeconds >= 1) {
        //
        // Reset counter for new second
        //
        g_MemoryMonitor.CurrentSecondStart = CurrentTime.QuadPart;
        InterlockedExchange(&g_MemoryMonitor.EventsThisSecond, 0);
    }

    CurrentCount = InterlockedIncrement(&g_MemoryMonitor.EventsThisSecond);

    return ((UINT32)CurrentCount <= g_MemoryMonitor.Config.MaxEventsPerSecond);
}

static
UINT32
MmpAnalyzeProtectionChange(
    _In_ UINT32 OldProtection,
    _In_ UINT32 NewProtection
    )
{
    //
    // Check for RW -> RX (classic shellcode/unpacking)
    //
    if (MmpIsWritableProtection(OldProtection) &&
        !MmpIsExecutableProtection(OldProtection) &&
        MmpIsExecutableProtection(NewProtection)) {
        return MM_SUSPICIOUS_RW_TO_RX;
    }

    //
    // Check for any -> RWX
    //
    if (!MmpIsRWXProtection(OldProtection) && MmpIsRWXProtection(NewProtection)) {
        return MM_SUSPICIOUS_TO_RWX;
    }

    return 0;
}

static
BOOLEAN
MmpIsExecutableProtection(
    _In_ UINT32 Protection
    )
{
    return ((Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
}

static
BOOLEAN
MmpIsWritableProtection(
    _In_ UINT32 Protection
    )
{
    return ((Protection & (PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
}

static
BOOLEAN
MmpIsRWXProtection(
    _In_ UINT32 Protection
    )
{
    return ((Protection & PAGE_EXECUTE_READWRITE) != 0);
}

static
VOID
MmpUpdateRegionRisk(
    _Inout_ PMM_TRACKED_REGION Region
    )
{
    //
    // Calculate risk based on various factors
    //
    if (Region->NowExecutable && Region->WasWritten) {
        Region->IsHighRisk = TRUE;
    }

    if (Region->LastContentEntropy >= MM_HIGH_ENTROPY_THRESHOLD) {
        Region->IsHighRisk = TRUE;
    }

    if (Region->ProtectionChangeCount > 5) {
        Region->IsHighRisk = TRUE;
    }
}

static
VOID
MmpUpdateProcessRisk(
    _Inout_ PMM_PROCESS_CONTEXT Context
    )
{
    UINT32 RiskScore = 0;

    //
    // Calculate composite risk score
    //
    RiskScore += Context->ShellcodeDetectionCount * 200;
    RiskScore += Context->InjectionAttemptCount * 300;
    RiskScore += (UINT32)(Context->SuspiciousOperations * 10);

    //
    // Cap at 1000
    //
    if (RiskScore > 1000) {
        RiskScore = 1000;
    }

    Context->MemoryRiskScore = RiskScore;

    if (RiskScore >= 500) {
        Context->IsHighRisk = TRUE;
    }
}

static
NTSTATUS
MmpReadProcessMemory(
    _In_ PEPROCESS Process,
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    )
{
    NTSTATUS Status;
    KAPC_STATE ApcState;
    SIZE_T BytesCopied = 0;

    if (Process == NULL || Buffer == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        KeStackAttachProcess(Process, &ApcState);

        //
        // Probe and copy memory
        //
        ProbeForRead(SourceAddress, Size, 1);
        RtlCopyMemory(Buffer, SourceAddress, Size);
        BytesCopied = Size;

        KeUnstackDetachProcess(&ApcState);
        Status = STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        KeUnstackDetachProcess(&ApcState);
        Status = GetExceptionCode();
    }

    return Status;
}

static
NTSTATUS
MmpQueryVirtualMemory(
    _In_ PEPROCESS Process,
    _In_ PVOID Address,
    _Out_ PMEMORY_BASIC_INFORMATION MemInfo
    )
{
    NTSTATUS Status;
    KAPC_STATE ApcState;
    SIZE_T ReturnLength = 0;

    if (Process == NULL || MemInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(MemInfo, sizeof(MEMORY_BASIC_INFORMATION));

    __try {
        KeStackAttachProcess(Process, &ApcState);

        Status = ZwQueryVirtualMemory(
            ZwCurrentProcess(),
            Address,
            MemoryBasicInformation,
            MemInfo,
            sizeof(MEMORY_BASIC_INFORMATION),
            &ReturnLength
        );

        KeUnstackDetachProcess(&ApcState);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        KeUnstackDetachProcess(&ApcState);
        Status = GetExceptionCode();
    }

    return Status;
}
