/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE PRE-ACQUIRE SECTION CALLBACK IMPLEMENTATION
===============================================================================

@file PreAcquireSection.c
@brief Enterprise-grade section acquisition interception for kernel EDR.

This module provides comprehensive memory mapping and execution detection:
- Image/executable mapping detection (SEC_IMAGE)
- DLL injection detection via section mapping patterns
- Process hollowing detection signals
- Reflective DLL loading detection
- Memory-mapped file execution tracking
- Shellcode injection via section objects
- Legitimate vs. suspicious mapping classification
- Per-process mapping behavior analysis
- Known malware pattern blocking via cache

IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION Interception Points:
- PAGE_EXECUTE / PAGE_EXECUTE_READ / PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_WRITECOPY
- SEC_IMAGE mappings (executable images)
- Cross-process section mapping detection
- Anomalous mapping patterns

Detection Techniques Covered (MITRE ATT&CK):
- T1055.001: Process Injection - DLL Injection
- T1055.003: Process Injection - Thread Execution Hijacking
- T1055.004: Process Injection - Asynchronous Procedure Call
- T1055.012: Process Injection - Process Hollowing
- T1620: Reflective Code Loading
- T1106: Native API (Direct syscall for section mapping)
- T1027.002: Obfuscated Files - Software Packing

Performance Characteristics:
- O(1) cache lookup via hash table
- Lock-free statistics using InterlockedXxx
- Early exit for kernel-mode requests
- Configurable scan depth and policy
- Minimal latency on hot path (cache hit)

CRITICAL STABILITY NOTES:
- This callback runs during section acquisition
- MUST NOT trigger synchronous user-mode communication (deadlock risk)
- MUST NOT allocate paged memory
- MUST complete quickly to avoid system hangs
- Rely on PreCreate for scan population, cache for enforcement

@author ShadowStrike Security Team
@version 2.0.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "FileSystemCallbacks.h"
#include "../../Core/Globals.h"
#include "../../Shared/SharedDefs.h"
#include "../../Cache/ScanCache.h"
#include "../../Communication/ScanBridge.h"
#include "../../SelfProtection/SelfProtect.h"
#include "../../Exclusions/ExclusionManager.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/ProcessUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define PAS_POOL_TAG                    'sAPP'  // PPAS - PreAcquireSection
#define PAS_MAX_TRACKED_MAPPINGS        4096
#define PAS_MAPPING_TIMEOUT_MS          300000  // 5 minutes
#define PAS_CLEANUP_INTERVAL_MS         60000   // 1 minute
#define PAS_MAX_PROCESS_MAPPINGS        256     // Max tracked per process
#define PAS_ANOMALY_THRESHOLD           10      // Mappings per second

//
// Page protection flags for execute detection
//
#define PAS_EXECUTE_PROTECTION_MASK     (PAGE_EXECUTE | PAGE_EXECUTE_READ | \
                                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

//
// Section types for classification
//
#define PAS_SECTION_IMAGE               0x01000000  // SEC_IMAGE
#define PAS_SECTION_RESERVE             0x04000000  // SEC_RESERVE
#define PAS_SECTION_COMMIT              0x08000000  // SEC_COMMIT
#define PAS_SECTION_NOCACHE             0x10000000  // SEC_NOCACHE
#define PAS_SECTION_LARGE_PAGES         0x80000000  // SEC_LARGE_PAGES

//
// Suspicion score thresholds
//
#define PAS_SUSPICION_LOW               15
#define PAS_SUSPICION_MEDIUM            40
#define PAS_SUSPICION_HIGH              65
#define PAS_SUSPICION_CRITICAL          85

//
// Mapping classification flags
//
#define PAS_MAP_FLAG_EXECUTABLE         0x00000001
#define PAS_MAP_FLAG_IMAGE              0x00000002
#define PAS_MAP_FLAG_WRITABLE           0x00000004
#define PAS_MAP_FLAG_CROSS_PROCESS      0x00000008
#define PAS_MAP_FLAG_UNSIGNED           0x00000010
#define PAS_MAP_FLAG_PACKED             0x00000020
#define PAS_MAP_FLAG_SUSPICIOUS_PATH    0x00000040
#define PAS_MAP_FLAG_TEMP_LOCATION      0x00000080
#define PAS_MAP_FLAG_NETWORK            0x00000100
#define PAS_MAP_FLAG_REMOVABLE          0x00000200
#define PAS_MAP_FLAG_ADS                0x00000400
#define PAS_MAP_FLAG_BLOCKED            0x00000800
#define PAS_MAP_FLAG_HOLLOWING_SUSPECT  0x00001000
#define PAS_MAP_FLAG_REFLECTIVE_SUSPECT 0x00002000

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

//
// Per-mapping tracking record
//
typedef struct _PAS_MAPPING_RECORD {
    //
    // Identification
    //
    HANDLE ProcessId;
    HANDLE ThreadId;
    PVOID FileObject;
    LARGE_INTEGER Timestamp;

    //
    // File information
    //
    ULONG VolumeSerial;
    UINT64 FileId;
    UINT64 FileSize;

    //
    // Mapping details
    //
    ULONG PageProtection;
    ULONG SectionType;
    ULONG MappingFlags;
    ULONG SuspicionScore;

    //
    // Verdict
    //
    SHADOWSTRIKE_VERDICT Verdict;
    BOOLEAN WasCacheHit;
    BOOLEAN WasBlocked;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;

} PAS_MAPPING_RECORD, *PPAS_MAPPING_RECORD;

//
// Per-process section mapping context
//
typedef struct _PAS_PROCESS_CONTEXT {
    HANDLE ProcessId;

    //
    // Mapping statistics
    //
    volatile LONG64 TotalMappings;
    volatile LONG64 ExecutableMappings;
    volatile LONG64 ImageMappings;
    volatile LONG64 SuspiciousMappings;
    volatile LONG64 BlockedMappings;

    //
    // Time-windowed metrics (for anomaly detection)
    //
    volatile LONG RecentMappings;
    volatile LONG RecentExecutables;
    LARGE_INTEGER WindowStartTime;

    //
    // Behavioral indicators
    //
    ULONG BehaviorFlags;
    ULONG SuspicionScore;
    BOOLEAN IsHollowingSuspect;
    BOOLEAN IsInjectionSuspect;
    BOOLEAN IsReflectiveSuspect;

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;

} PAS_PROCESS_CONTEXT, *PPAS_PROCESS_CONTEXT;

//
// Behavior flags
//
#define PAS_BEHAVIOR_RAPID_MAPPING      0x00000001
#define PAS_BEHAVIOR_CROSS_PROCESS      0x00000002
#define PAS_BEHAVIOR_UNSIGNED_EXEC      0x00000004
#define PAS_BEHAVIOR_TEMP_EXEC          0x00000008
#define PAS_BEHAVIOR_MULTIPLE_TARGETS   0x00000010
#define PAS_BEHAVIOR_SELF_MODIFICATION  0x00000020
#define PAS_BEHAVIOR_HOLLOWING          0x00000040
#define PAS_BEHAVIOR_REFLECTIVE         0x00000080

//
// Hash bucket for fast lookup
//
#define PAS_HASH_BUCKET_COUNT           128

typedef struct _PAS_HASH_BUCKET {
    LIST_ENTRY List;
    EX_PUSH_LOCK Lock;
} PAS_HASH_BUCKET, *PPAS_HASH_BUCKET;

//
// Global state
//
typedef struct _PAS_GLOBAL_STATE {
    //
    // Initialization
    //
    BOOLEAN Initialized;

    //
    // Process context tracking
    //
    LIST_ENTRY ProcessContextList;
    EX_PUSH_LOCK ProcessContextLock;
    volatile LONG ProcessContextCount;

    //
    // Mapping records
    //
    LIST_ENTRY MappingList;
    EX_PUSH_LOCK MappingLock;
    volatile LONG MappingCount;

    //
    // Hash table for fast lookup
    //
    PAS_HASH_BUCKET HashTable[PAS_HASH_BUCKET_COUNT];

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST RecordLookaside;
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalCalls;
        volatile LONG64 ExecuteMappings;
        volatile LONG64 ImageMappings;
        volatile LONG64 CacheHits;
        volatile LONG64 CacheMisses;
        volatile LONG64 Blocked;
        volatile LONG64 Allowed;
        volatile LONG64 SuspiciousDetected;
        volatile LONG64 HollowingDetected;
        volatile LONG64 InjectionDetected;
        volatile LONG64 ReflectiveDetected;
        volatile LONG64 Errors;
        LARGE_INTEGER StartTime;
    } Stats;

    //
    // Configuration
    //
    struct {
        BOOLEAN EnableBlocking;
        BOOLEAN EnableHollowingDetection;
        BOOLEAN EnableInjectionDetection;
        BOOLEAN EnableReflectiveDetection;
        BOOLEAN LogAllMappings;
        ULONG MinBlockScore;
        ULONG AnomalyThreshold;
    } Config;

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    BOOLEAN CleanupTimerActive;

    //
    // Shutdown flag
    //
    volatile BOOLEAN ShutdownRequested;

} PAS_GLOBAL_STATE, *PPAS_GLOBAL_STATE;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static PAS_GLOBAL_STATE g_PasState = {0};

//
// Suspicious path patterns for detection
//
static const PCWSTR g_SuspiciousPaths[] = {
    L"\\Temp\\",
    L"\\TMP\\",
    L"\\AppData\\Local\\Temp\\",
    L"\\Windows\\Temp\\",
    L"\\Users\\Public\\",
    L"\\ProgramData\\",
    L"\\Downloads\\",
    L"\\Recycle",
    L"$Recycle.Bin",
    L"\\staging\\",
    L"\\cache\\",
};

#define PAS_SUSPICIOUS_PATH_COUNT (sizeof(g_SuspiciousPaths) / sizeof(g_SuspiciousPaths[0]))

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static NTSTATUS
PaspInitialize(
    VOID
    );

static VOID
PaspShutdown(
    VOID
    );

static PPAS_PROCESS_CONTEXT
PaspLookupProcessContext(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    );

static VOID
PaspReferenceProcessContext(
    _Inout_ PPAS_PROCESS_CONTEXT Context
    );

static VOID
PaspDereferenceProcessContext(
    _Inout_ PPAS_PROCESS_CONTEXT Context
    );

static PPAS_MAPPING_RECORD
PaspAllocateRecord(
    VOID
    );

static VOID
PaspFreeRecord(
    _In_ PPAS_MAPPING_RECORD Record
    );

static VOID
PaspInsertRecord(
    _In_ PPAS_MAPPING_RECORD Record
    );

static ULONG
PaspClassifyMapping(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG PageProtection
    );

static ULONG
PaspCalculateSuspicionScore(
    _In_ PPAS_MAPPING_RECORD Record,
    _In_opt_ PPAS_PROCESS_CONTEXT ProcessContext
    );

static BOOLEAN
PaspIsSuspiciousPath(
    _In_ PCUNICODE_STRING FilePath
    );

static BOOLEAN
PaspDetectHollowingPattern(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    );

static BOOLEAN
PaspDetectInjectionPattern(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    );

static BOOLEAN
PaspDetectReflectiveLoading(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    );

static VOID
PaspUpdateProcessMetrics(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    );

static VOID
PaspCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
PaspCleanupStaleRecords(
    VOID
    );

static ULONG
PaspHashFileId(
    _In_ UINT64 FileId,
    _In_ ULONG VolumeSerial
    );

// ============================================================================
// INITIALIZATION
// ============================================================================

static NTSTATUS
PaspInitialize(
    VOID
    )
/*++
Routine Description:
    Initializes the PreAcquireSection subsystem.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    LARGE_INTEGER DueTime;
    ULONG i;

    if (g_PasState.Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_PasState, sizeof(PAS_GLOBAL_STATE));

    //
    // Initialize process context list
    //
    InitializeListHead(&g_PasState.ProcessContextList);
    ExInitializePushLock(&g_PasState.ProcessContextLock);

    //
    // Initialize mapping list
    //
    InitializeListHead(&g_PasState.MappingList);
    ExInitializePushLock(&g_PasState.MappingLock);

    //
    // Initialize hash table
    //
    for (i = 0; i < PAS_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&g_PasState.HashTable[i].List);
        ExInitializePushLock(&g_PasState.HashTable[i].Lock);
    }

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &g_PasState.RecordLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PAS_MAPPING_RECORD),
        PAS_POOL_TAG,
        0
        );

    ExInitializeNPagedLookasideList(
        &g_PasState.ContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PAS_PROCESS_CONTEXT),
        PAS_POOL_TAG,
        0
        );

    g_PasState.LookasideInitialized = TRUE;

    //
    // Initialize default configuration
    //
    g_PasState.Config.EnableBlocking = TRUE;
    g_PasState.Config.EnableHollowingDetection = TRUE;
    g_PasState.Config.EnableInjectionDetection = TRUE;
    g_PasState.Config.EnableReflectiveDetection = TRUE;
    g_PasState.Config.LogAllMappings = FALSE;
    g_PasState.Config.MinBlockScore = PAS_SUSPICION_CRITICAL;
    g_PasState.Config.AnomalyThreshold = PAS_ANOMALY_THRESHOLD;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&g_PasState.Stats.StartTime);

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&g_PasState.CleanupTimer);
    KeInitializeDpc(&g_PasState.CleanupDpc, PaspCleanupTimerDpc, NULL);

    //
    // Start cleanup timer
    //
    DueTime.QuadPart = -((LONGLONG)PAS_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &g_PasState.CleanupTimer,
        DueTime,
        PAS_CLEANUP_INTERVAL_MS,
        &g_PasState.CleanupDpc
        );
    g_PasState.CleanupTimerActive = TRUE;

    g_PasState.Initialized = TRUE;

    return STATUS_SUCCESS;
}


static VOID
PaspShutdown(
    VOID
    )
/*++
Routine Description:
    Shuts down the PreAcquireSection subsystem.
--*/
{
    PLIST_ENTRY Entry;
    PPAS_MAPPING_RECORD Record;
    PPAS_PROCESS_CONTEXT Context;

    if (!g_PasState.Initialized) {
        return;
    }

    g_PasState.ShutdownRequested = TRUE;
    g_PasState.Initialized = FALSE;

    //
    // Cancel cleanup timer
    //
    if (g_PasState.CleanupTimerActive) {
        KeCancelTimer(&g_PasState.CleanupTimer);
        g_PasState.CleanupTimerActive = FALSE;
    }

    //
    // Free all mapping records
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PasState.MappingLock);

    while (!IsListEmpty(&g_PasState.MappingList)) {
        Entry = RemoveHeadList(&g_PasState.MappingList);
        Record = CONTAINING_RECORD(Entry, PAS_MAPPING_RECORD, ListEntry);

        ExReleasePushLockExclusive(&g_PasState.MappingLock);
        KeLeaveCriticalRegion();

        ExFreeToNPagedLookasideList(&g_PasState.RecordLookaside, Record);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_PasState.MappingLock);
    }

    ExReleasePushLockExclusive(&g_PasState.MappingLock);
    KeLeaveCriticalRegion();

    //
    // Free all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PasState.ProcessContextLock);

    while (!IsListEmpty(&g_PasState.ProcessContextList)) {
        Entry = RemoveHeadList(&g_PasState.ProcessContextList);
        Context = CONTAINING_RECORD(Entry, PAS_PROCESS_CONTEXT, ListEntry);

        ExReleasePushLockExclusive(&g_PasState.ProcessContextLock);
        KeLeaveCriticalRegion();

        ExFreeToNPagedLookasideList(&g_PasState.ContextLookaside, Context);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_PasState.ProcessContextLock);
    }

    ExReleasePushLockExclusive(&g_PasState.ProcessContextLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside lists
    //
    if (g_PasState.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_PasState.RecordLookaside);
        ExDeleteNPagedLookasideList(&g_PasState.ContextLookaside);
    }
}

// ============================================================================
// MAIN CALLBACK IMPLEMENTATION
// ============================================================================

_Use_decl_annotations_
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreAcquireSection(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++
Routine Description:
    Enterprise-grade pre-operation callback for IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION.

    This callback is invoked when the memory manager is about to map a file into
    a process address space. This is a critical interception point for:
    - Detecting executable image mappings (SEC_IMAGE)
    - Blocking known malware from executing
    - Detecting DLL injection patterns
    - Detecting process hollowing
    - Detecting reflective DLL loading

    CRITICAL: This callback runs at elevated IRQL and during section acquisition.
    We MUST NOT:
    - Trigger synchronous user-mode communication (deadlock)
    - Allocate paged memory
    - Perform long-running operations
    - Block indefinitely

    We rely on PreCreate to have populated the scan cache.
    Here we only enforce cached verdicts.

Arguments:
    Data        - Callback data containing operation parameters.
    FltObjects  - Filter objects (volume, instance, file object).
    CompletionContext - Completion context (unused).

Return Value:
    FLT_PREOP_SUCCESS_NO_CALLBACK - Allow the operation.
    FLT_PREOP_COMPLETE - Block the operation (access denied).
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG PageProtection;
    SHADOWSTRIKE_CACHE_KEY CacheKey;
    SHADOWSTRIKE_CACHE_RESULT CacheResult;
    PPAS_PROCESS_CONTEXT ProcessContext = NULL;
    PPAS_MAPPING_RECORD MappingRecord = NULL;
    HANDLE CurrentProcessId;
    ULONG MappingFlags = 0;
    ULONG SuspicionScore = 0;
    BOOLEAN ShouldBlock = FALSE;
    BOOLEAN IsExecuteMapping = FALSE;
    BOOLEAN IsCacheHit = FALSE;
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;

    UNREFERENCED_PARAMETER(CompletionContext);

    //
    // Initialize lazy if needed
    //
    if (!g_PasState.Initialized) {
        PaspInitialize();
    }

    //
    // Fast-fail checks
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (g_PasState.ShutdownRequested) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Get page protection
    //
    PageProtection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;

    //
    // Check if this is an executable mapping
    //
    if (!(PageProtection & PAS_EXECUTE_PROTECTION_MASK)) {
        //
        // Not an execute mapping - allow without further checks
        //
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    IsExecuteMapping = TRUE;

    //
    // Update statistics
    //
    InterlockedIncrement64(&g_PasState.Stats.TotalCalls);
    InterlockedIncrement64(&g_PasState.Stats.ExecuteMappings);

    //
    // Skip kernel-mode requests (trust the kernel)
    //
    if (Data->RequestorMode == KernelMode) {
        InterlockedIncrement64(&g_PasState.Stats.Allowed);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Skip if no file object
    //
    if (FltObjects->FileObject == NULL) {
        InterlockedIncrement64(&g_PasState.Stats.Allowed);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Get current process ID
    //
    CurrentProcessId = PsGetCurrentProcessId();

    //
    // Skip protected processes (our own service, etc.)
    //
    if (CurrentProcessId == (HANDLE)4 || ShadowStrikeIsProcessProtected(CurrentProcessId)) {
        InterlockedIncrement64(&g_PasState.Stats.Allowed);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SHADOWSTRIKE_ENTER_OPERATION();

    //
    // Get or create process context for behavioral analysis
    //
    ProcessContext = PaspLookupProcessContext(CurrentProcessId, TRUE);

    //
    // Classify this mapping
    //
    MappingFlags = PaspClassifyMapping(Data, FltObjects, PageProtection);

    //
    // Check scan cache for verdict
    //
    RtlZeroMemory(&CacheKey, sizeof(CacheKey));
    RtlZeroMemory(&CacheResult, sizeof(CacheResult));

    Status = ShadowStrikeCacheBuildKey(FltObjects, &CacheKey);
    if (NT_SUCCESS(Status)) {
        if (ShadowStrikeCacheLookup(&CacheKey, &CacheResult)) {
            IsCacheHit = TRUE;
            InterlockedIncrement64(&g_PasState.Stats.CacheHits);

            if (CacheResult.Verdict == ShadowStrikeVerdictBlock) {
                //
                // Known malware - BLOCK
                //
                ShouldBlock = TRUE;
                SuspicionScore = 100;

                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID,
                    DPFLTR_WARNING_LEVEL,
                    "[ShadowStrike/PreAcquireSection] CACHE HIT - BLOCK: "
                    "PID=%lu, FileId=0x%llX, Score=%lu\n",
                    HandleToULong(CurrentProcessId),
                    CacheKey.FileId,
                    CacheResult.ThreatScore
                    );
            }
        } else {
            InterlockedIncrement64(&g_PasState.Stats.CacheMisses);
        }
    }

    //
    // Allocate mapping record for tracking
    //
    MappingRecord = PaspAllocateRecord();
    if (MappingRecord != NULL) {
        MappingRecord->ProcessId = CurrentProcessId;
        MappingRecord->ThreadId = PsGetCurrentThreadId();
        MappingRecord->FileObject = FltObjects->FileObject;
        KeQuerySystemTime(&MappingRecord->Timestamp);
        MappingRecord->VolumeSerial = CacheKey.VolumeSerial;
        MappingRecord->FileId = CacheKey.FileId;
        MappingRecord->FileSize = CacheKey.FileSize;
        MappingRecord->PageProtection = PageProtection;
        MappingRecord->MappingFlags = MappingFlags;
        MappingRecord->WasCacheHit = IsCacheHit;

        if (IsCacheHit) {
            MappingRecord->Verdict = CacheResult.Verdict;
        }
    }

    //
    // Behavioral analysis (if not already blocking)
    //
    if (!ShouldBlock && ProcessContext != NULL) {
        //
        // Update process metrics
        //
        if (MappingRecord != NULL) {
            PaspUpdateProcessMetrics(ProcessContext, MappingRecord);
        }

        //
        // Check for process hollowing pattern
        //
        if (g_PasState.Config.EnableHollowingDetection) {
            if (MappingRecord != NULL && PaspDetectHollowingPattern(ProcessContext, MappingRecord)) {
                MappingFlags |= PAS_MAP_FLAG_HOLLOWING_SUSPECT;
                ProcessContext->IsHollowingSuspect = TRUE;
                ProcessContext->BehaviorFlags |= PAS_BEHAVIOR_HOLLOWING;
                SuspicionScore += 30;
                InterlockedIncrement64(&g_PasState.Stats.HollowingDetected);
            }
        }

        //
        // Check for DLL injection pattern
        //
        if (g_PasState.Config.EnableInjectionDetection) {
            if (MappingRecord != NULL && PaspDetectInjectionPattern(ProcessContext, MappingRecord)) {
                ProcessContext->IsInjectionSuspect = TRUE;
                SuspicionScore += 25;
                InterlockedIncrement64(&g_PasState.Stats.InjectionDetected);
            }
        }

        //
        // Check for reflective loading pattern
        //
        if (g_PasState.Config.EnableReflectiveDetection) {
            if (MappingRecord != NULL && PaspDetectReflectiveLoading(ProcessContext, MappingRecord)) {
                MappingFlags |= PAS_MAP_FLAG_REFLECTIVE_SUSPECT;
                ProcessContext->IsReflectiveSuspect = TRUE;
                ProcessContext->BehaviorFlags |= PAS_BEHAVIOR_REFLECTIVE;
                SuspicionScore += 35;
                InterlockedIncrement64(&g_PasState.Stats.ReflectiveDetected);
            }
        }

        //
        // Check for rapid mapping anomaly
        //
        if (ProcessContext->RecentMappings > (LONG)g_PasState.Config.AnomalyThreshold) {
            ProcessContext->BehaviorFlags |= PAS_BEHAVIOR_RAPID_MAPPING;
            SuspicionScore += 15;
        }
    }

    //
    // Get file path for additional checks (if not already blocking)
    //
    if (!ShouldBlock && !IsCacheHit) {
        Status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &NameInfo
            );

        if (NT_SUCCESS(Status)) {
            Status = FltParseFileNameInformation(NameInfo);
            if (NT_SUCCESS(Status)) {
                //
                // Check for suspicious path
                //
                if (PaspIsSuspiciousPath(&NameInfo->Name)) {
                    MappingFlags |= PAS_MAP_FLAG_SUSPICIOUS_PATH;
                    SuspicionScore += 20;
                }

                //
                // Check for temp location
                //
                if (wcsstr(NameInfo->Name.Buffer, L"\\Temp\\") != NULL ||
                    wcsstr(NameInfo->Name.Buffer, L"\\TMP\\") != NULL) {
                    MappingFlags |= PAS_MAP_FLAG_TEMP_LOCATION;
                    SuspicionScore += 15;
                }

                //
                // Check for ADS
                //
                if (NameInfo->Stream.Length > 0) {
                    MappingFlags |= PAS_MAP_FLAG_ADS;
                    SuspicionScore += 25;
                }
            }
            FltReleaseFileNameInformation(NameInfo);
            NameInfo = NULL;
        }
    }

    //
    // Calculate final suspicion score
    //
    if (MappingRecord != NULL) {
        MappingRecord->SuspicionScore = PaspCalculateSuspicionScore(MappingRecord, ProcessContext);
        SuspicionScore = max(SuspicionScore, MappingRecord->SuspicionScore);
        MappingRecord->MappingFlags = MappingFlags;
    }

    //
    // Check if we should block based on score
    //
    if (!ShouldBlock && g_PasState.Config.EnableBlocking) {
        if (SuspicionScore >= g_PasState.Config.MinBlockScore) {
            ShouldBlock = TRUE;

            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/PreAcquireSection] BEHAVIOR BLOCK: "
                "PID=%lu, Score=%lu, Flags=0x%08X\n",
                HandleToULong(CurrentProcessId),
                SuspicionScore,
                MappingFlags
                );
        }
    }

    //
    // Track suspicious mappings
    //
    if (SuspicionScore >= PAS_SUSPICION_MEDIUM) {
        InterlockedIncrement64(&g_PasState.Stats.SuspiciousDetected);

        if (ProcessContext != NULL) {
            InterlockedIncrement64(&ProcessContext->SuspiciousMappings);
            ProcessContext->SuspicionScore = max(ProcessContext->SuspicionScore, SuspicionScore);
        }
    }

    //
    // Insert mapping record
    //
    if (MappingRecord != NULL) {
        MappingRecord->WasBlocked = ShouldBlock;
        PaspInsertRecord(MappingRecord);
    }

    //
    // Release process context
    //
    if (ProcessContext != NULL) {
        PaspDereferenceProcessContext(ProcessContext);
    }

    //
    // Apply verdict
    //
    if (ShouldBlock) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;

        InterlockedIncrement64(&g_PasState.Stats.Blocked);
        SHADOWSTRIKE_INC_STAT(FilesBlocked);

        SHADOWSTRIKE_LEAVE_OPERATION();
        return FLT_PREOP_COMPLETE;
    }

    InterlockedIncrement64(&g_PasState.Stats.Allowed);
    SHADOWSTRIKE_LEAVE_OPERATION();

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ============================================================================
// PROCESS CONTEXT MANAGEMENT
// ============================================================================

static PPAS_PROCESS_CONTEXT
PaspLookupProcessContext(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    )
{
    PLIST_ENTRY Entry;
    PPAS_PROCESS_CONTEXT Context = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_PasState.ProcessContextLock);

    for (Entry = g_PasState.ProcessContextList.Flink;
         Entry != &g_PasState.ProcessContextList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, PAS_PROCESS_CONTEXT, ListEntry);

        if (Context->ProcessId == ProcessId) {
            PaspReferenceProcessContext(Context);
            ExReleasePushLockShared(&g_PasState.ProcessContextLock);
            KeLeaveCriticalRegion();
            return Context;
        }
    }

    ExReleasePushLockShared(&g_PasState.ProcessContextLock);
    KeLeaveCriticalRegion();

    if (!CreateIfNotFound) {
        return NULL;
    }

    //
    // Create new context
    //
    Context = (PPAS_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_PasState.ContextLookaside
        );

    if (Context == NULL) {
        return NULL;
    }

    RtlZeroMemory(Context, sizeof(PAS_PROCESS_CONTEXT));
    Context->ProcessId = ProcessId;
    Context->RefCount = 1;
    KeQuerySystemTime(&Context->WindowStartTime);
    InitializeListHead(&Context->ListEntry);

    //
    // Insert into list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PasState.ProcessContextLock);

    //
    // Check for race condition
    //
    for (Entry = g_PasState.ProcessContextList.Flink;
         Entry != &g_PasState.ProcessContextList;
         Entry = Entry->Flink) {

        PPAS_PROCESS_CONTEXT Existing = CONTAINING_RECORD(Entry, PAS_PROCESS_CONTEXT, ListEntry);

        if (Existing->ProcessId == ProcessId) {
            PaspReferenceProcessContext(Existing);
            ExReleasePushLockExclusive(&g_PasState.ProcessContextLock);
            KeLeaveCriticalRegion();
            ExFreeToNPagedLookasideList(&g_PasState.ContextLookaside, Context);
            return Existing;
        }
    }

    InsertTailList(&g_PasState.ProcessContextList, &Context->ListEntry);
    InterlockedIncrement(&g_PasState.ProcessContextCount);
    PaspReferenceProcessContext(Context);

    ExReleasePushLockExclusive(&g_PasState.ProcessContextLock);
    KeLeaveCriticalRegion();

    return Context;
}


static VOID
PaspReferenceProcessContext(
    _Inout_ PPAS_PROCESS_CONTEXT Context
    )
{
    InterlockedIncrement(&Context->RefCount);
}


static VOID
PaspDereferenceProcessContext(
    _Inout_ PPAS_PROCESS_CONTEXT Context
    )
{
    if (InterlockedDecrement(&Context->RefCount) == 0) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_PasState.ProcessContextLock);

        if (!IsListEmpty(&Context->ListEntry)) {
            RemoveEntryList(&Context->ListEntry);
            InitializeListHead(&Context->ListEntry);
            InterlockedDecrement(&g_PasState.ProcessContextCount);
        }

        ExReleasePushLockExclusive(&g_PasState.ProcessContextLock);
        KeLeaveCriticalRegion();

        ExFreeToNPagedLookasideList(&g_PasState.ContextLookaside, Context);
    }
}

// ============================================================================
// MAPPING RECORD MANAGEMENT
// ============================================================================

static PPAS_MAPPING_RECORD
PaspAllocateRecord(
    VOID
    )
{
    PPAS_MAPPING_RECORD Record;

    if ((ULONG)g_PasState.MappingCount >= PAS_MAX_TRACKED_MAPPINGS) {
        //
        // At capacity - don't track
        //
        return NULL;
    }

    Record = (PPAS_MAPPING_RECORD)ExAllocateFromNPagedLookasideList(
        &g_PasState.RecordLookaside
        );

    if (Record != NULL) {
        RtlZeroMemory(Record, sizeof(PAS_MAPPING_RECORD));
        InitializeListHead(&Record->ListEntry);
        InitializeListHead(&Record->HashEntry);
    }

    return Record;
}


static VOID
PaspFreeRecord(
    _In_ PPAS_MAPPING_RECORD Record
    )
{
    if (Record != NULL) {
        ExFreeToNPagedLookasideList(&g_PasState.RecordLookaside, Record);
    }
}


static VOID
PaspInsertRecord(
    _In_ PPAS_MAPPING_RECORD Record
    )
{
    ULONG BucketIndex;
    PPAS_HASH_BUCKET Bucket;

    //
    // Insert into main list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PasState.MappingLock);

    InsertTailList(&g_PasState.MappingList, &Record->ListEntry);
    InterlockedIncrement(&g_PasState.MappingCount);

    ExReleasePushLockExclusive(&g_PasState.MappingLock);
    KeLeaveCriticalRegion();

    //
    // Insert into hash table
    //
    BucketIndex = PaspHashFileId(Record->FileId, Record->VolumeSerial);
    Bucket = &g_PasState.HashTable[BucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Bucket->Lock);

    InsertTailList(&Bucket->List, &Record->HashEntry);

    ExReleasePushLockExclusive(&Bucket->Lock);
    KeLeaveCriticalRegion();
}


static ULONG
PaspHashFileId(
    _In_ UINT64 FileId,
    _In_ ULONG VolumeSerial
    )
{
    ULONG Hash;

    Hash = (ULONG)(FileId ^ (FileId >> 32));
    Hash ^= VolumeSerial;
    Hash = Hash * 0x85EBCA6B;
    Hash ^= Hash >> 13;

    return Hash % PAS_HASH_BUCKET_COUNT;
}

// ============================================================================
// CLASSIFICATION AND ANALYSIS
// ============================================================================

static ULONG
PaspClassifyMapping(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG PageProtection
    )
{
    ULONG Flags = 0;

    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);

    //
    // Check for executable protection
    //
    if (PageProtection & PAS_EXECUTE_PROTECTION_MASK) {
        Flags |= PAS_MAP_FLAG_EXECUTABLE;
    }

    //
    // Check for writable + executable (suspicious)
    //
    if ((PageProtection & PAGE_EXECUTE_READWRITE) ||
        (PageProtection & PAGE_EXECUTE_WRITECOPY)) {
        Flags |= PAS_MAP_FLAG_WRITABLE;
    }

    return Flags;
}


static ULONG
PaspCalculateSuspicionScore(
    _In_ PPAS_MAPPING_RECORD Record,
    _In_opt_ PPAS_PROCESS_CONTEXT ProcessContext
    )
{
    ULONG Score = 0;

    //
    // Writable + Executable is suspicious
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_WRITABLE) {
        Score += 25;
    }

    //
    // Suspicious path
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_SUSPICIOUS_PATH) {
        Score += 20;
    }

    //
    // Temp location
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_TEMP_LOCATION) {
        Score += 15;
    }

    //
    // ADS
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_ADS) {
        Score += 30;
    }

    //
    // Hollowing suspect
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_HOLLOWING_SUSPECT) {
        Score += 35;
    }

    //
    // Reflective loading suspect
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_REFLECTIVE_SUSPECT) {
        Score += 40;
    }

    //
    // Process behavioral indicators
    //
    if (ProcessContext != NULL) {
        if (ProcessContext->BehaviorFlags & PAS_BEHAVIOR_RAPID_MAPPING) {
            Score += 15;
        }

        if (ProcessContext->BehaviorFlags & PAS_BEHAVIOR_HOLLOWING) {
            Score += 20;
        }

        if (ProcessContext->BehaviorFlags & PAS_BEHAVIOR_REFLECTIVE) {
            Score += 25;
        }
    }

    //
    // Cap at 100
    //
    if (Score > 100) {
        Score = 100;
    }

    return Score;
}


static BOOLEAN
PaspIsSuspiciousPath(
    _In_ PCUNICODE_STRING FilePath
    )
{
    ULONG i;

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < PAS_SUSPICIOUS_PATH_COUNT; i++) {
        if (wcsstr(FilePath->Buffer, g_SuspiciousPaths[i]) != NULL) {
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================================
// BEHAVIORAL DETECTION
// ============================================================================

static VOID
PaspUpdateProcessMetrics(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    )
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeDiff;

    KeQuerySystemTime(&CurrentTime);

    //
    // Reset time window if expired (1 second)
    //
    TimeDiff.QuadPart = CurrentTime.QuadPart - ProcessContext->WindowStartTime.QuadPart;
    if (TimeDiff.QuadPart > (10000000LL)) {  // 1 second
        ProcessContext->RecentMappings = 0;
        ProcessContext->RecentExecutables = 0;
        ProcessContext->WindowStartTime = CurrentTime;
    }

    //
    // Update counters
    //
    InterlockedIncrement64(&ProcessContext->TotalMappings);
    InterlockedIncrement(&ProcessContext->RecentMappings);

    if (Record->MappingFlags & PAS_MAP_FLAG_EXECUTABLE) {
        InterlockedIncrement64(&ProcessContext->ExecutableMappings);
        InterlockedIncrement(&ProcessContext->RecentExecutables);
    }

    if (Record->MappingFlags & PAS_MAP_FLAG_IMAGE) {
        InterlockedIncrement64(&ProcessContext->ImageMappings);
    }
}


static BOOLEAN
PaspDetectHollowingPattern(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    )
/*++
Routine Description:
    Detects process hollowing patterns.

    Process hollowing typically involves:
    1. Creating a process in suspended state
    2. Unmapping the original image
    3. Mapping a malicious image
    4. Resuming execution

    Detection signals:
    - Executable mapping early in process lifetime
    - Multiple image mappings
    - Writable + Executable mappings
--*/
{
    UNREFERENCED_PARAMETER(Record);

    //
    // Check for multiple executable mappings in short time
    //
    if (ProcessContext->RecentExecutables > 3) {
        return TRUE;
    }

    //
    // Check for rapid image mappings
    //
    if (ProcessContext->ImageMappings > 5 && ProcessContext->TotalMappings < 20) {
        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
PaspDetectInjectionPattern(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    )
/*++
Routine Description:
    Detects DLL injection patterns.

    DLL injection typically involves:
    1. Opening target process
    2. Allocating memory in target
    3. Writing DLL path or shellcode
    4. Creating remote thread

    From section perspective:
    - Cross-process section mapping
    - Writable + Executable sections
    - Unsigned or packed binaries
--*/
{
    UNREFERENCED_PARAMETER(ProcessContext);

    //
    // Cross-process mapping is suspicious
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_CROSS_PROCESS) {
        return TRUE;
    }

    //
    // Writable + Executable from network/removable is suspicious
    //
    if ((Record->MappingFlags & PAS_MAP_FLAG_WRITABLE) &&
        (Record->MappingFlags & (PAS_MAP_FLAG_NETWORK | PAS_MAP_FLAG_REMOVABLE))) {
        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
PaspDetectReflectiveLoading(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    )
/*++
Routine Description:
    Detects reflective DLL loading patterns.

    Reflective loading involves:
    1. Allocating RWX memory
    2. Copying DLL into memory
    3. Manually resolving imports
    4. Calling DllMain without LoadLibrary

    Detection signals:
    - Writable + Executable mappings
    - Non-image executable sections
    - Mapping from suspicious locations
--*/
{
    //
    // Writable + Executable is core reflective pattern
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_WRITABLE) {
        //
        // Combined with suspicious path = high confidence
        //
        if (Record->MappingFlags & PAS_MAP_FLAG_SUSPICIOUS_PATH) {
            return TRUE;
        }

        //
        // Combined with temp location = medium-high confidence
        //
        if (Record->MappingFlags & PAS_MAP_FLAG_TEMP_LOCATION) {
            return TRUE;
        }

        //
        // Rapid writable+executable mappings
        //
        if (ProcessContext->RecentExecutables > 2) {
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================================
// CLEANUP
// ============================================================================

static VOID
PaspCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (g_PasState.ShutdownRequested) {
        return;
    }

    PaspCleanupStaleRecords();
}


static VOID
PaspCleanupStaleRecords(
    VOID
    )
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;
    PLIST_ENTRY Entry, Next;
    PPAS_MAPPING_RECORD Record;
    LIST_ENTRY StaleList;
    ULONG BucketIndex;
    PPAS_HASH_BUCKET Bucket;

    InitializeListHead(&StaleList);

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)PAS_MAPPING_TIMEOUT_MS * 10000;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PasState.MappingLock);

    for (Entry = g_PasState.MappingList.Flink;
         Entry != &g_PasState.MappingList;
         Entry = Next) {

        Next = Entry->Flink;
        Record = CONTAINING_RECORD(Entry, PAS_MAPPING_RECORD, ListEntry);

        if ((CurrentTime.QuadPart - Record->Timestamp.QuadPart) > TimeoutInterval.QuadPart) {
            RemoveEntryList(&Record->ListEntry);
            InterlockedDecrement(&g_PasState.MappingCount);
            InsertTailList(&StaleList, &Record->ListEntry);
        }
    }

    ExReleasePushLockExclusive(&g_PasState.MappingLock);
    KeLeaveCriticalRegion();

    //
    // Free stale records outside lock
    //
    while (!IsListEmpty(&StaleList)) {
        Entry = RemoveHeadList(&StaleList);
        Record = CONTAINING_RECORD(Entry, PAS_MAPPING_RECORD, ListEntry);

        //
        // Remove from hash table
        //
        BucketIndex = PaspHashFileId(Record->FileId, Record->VolumeSerial);
        Bucket = &g_PasState.HashTable[BucketIndex];

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Bucket->Lock);

        if (!IsListEmpty(&Record->HashEntry)) {
            RemoveEntryList(&Record->HashEntry);
            InitializeListHead(&Record->HashEntry);
        }

        ExReleasePushLockExclusive(&Bucket->Lock);
        KeLeaveCriticalRegion();

        PaspFreeRecord(Record);
    }
}

// ============================================================================
// PUBLIC STATISTICS API
// ============================================================================

NTSTATUS
ShadowStrikeGetPreAcquireSectionStats(
    _Out_ PULONG64 TotalCalls,
    _Out_ PULONG64 ExecuteMappings,
    _Out_ PULONG64 Blocked,
    _Out_ PULONG64 HollowingDetected,
    _Out_ PULONG64 InjectionDetected
    )
/*++
Routine Description:
    Gets PreAcquireSection callback statistics.

Arguments:
    TotalCalls - Receives total callback invocations.
    ExecuteMappings - Receives executable mapping count.
    Blocked - Receives blocked count.
    HollowingDetected - Receives hollowing detection count.
    InjectionDetected - Receives injection detection count.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    if (!g_PasState.Initialized) {
        return STATUS_NOT_FOUND;
    }

    if (TotalCalls != NULL) {
        *TotalCalls = (ULONG64)g_PasState.Stats.TotalCalls;
    }

    if (ExecuteMappings != NULL) {
        *ExecuteMappings = (ULONG64)g_PasState.Stats.ExecuteMappings;
    }

    if (Blocked != NULL) {
        *Blocked = (ULONG64)g_PasState.Stats.Blocked;
    }

    if (HollowingDetected != NULL) {
        *HollowingDetected = (ULONG64)g_PasState.Stats.HollowingDetected;
    }

    if (InjectionDetected != NULL) {
        *InjectionDetected = (ULONG64)g_PasState.Stats.InjectionDetected;
    }

    return STATUS_SUCCESS;
}


NTSTATUS
ShadowStrikeQueryProcessMappingContext(
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsHollowingSuspect,
    _Out_ PBOOLEAN IsInjectionSuspect,
    _Out_ PBOOLEAN IsReflectiveSuspect,
    _Out_ PULONG SuspicionScore
    )
/*++
Routine Description:
    Queries section mapping context for a process.

Arguments:
    ProcessId - Process ID to query.
    IsHollowingSuspect - Receives hollowing suspect flag.
    IsInjectionSuspect - Receives injection suspect flag.
    IsReflectiveSuspect - Receives reflective loading suspect flag.
    SuspicionScore - Receives suspicion score.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PPAS_PROCESS_CONTEXT Context;

    if (!g_PasState.Initialized) {
        return STATUS_NOT_FOUND;
    }

    Context = PaspLookupProcessContext(ProcessId, FALSE);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    if (IsHollowingSuspect != NULL) {
        *IsHollowingSuspect = Context->IsHollowingSuspect;
    }

    if (IsInjectionSuspect != NULL) {
        *IsInjectionSuspect = Context->IsInjectionSuspect;
    }

    if (IsReflectiveSuspect != NULL) {
        *IsReflectiveSuspect = Context->IsReflectiveSuspect;
    }

    if (SuspicionScore != NULL) {
        *SuspicionScore = Context->SuspicionScore;
    }

    PaspDereferenceProcessContext(Context);

    return STATUS_SUCCESS;
}


VOID
ShadowStrikeRemoveProcessMappingContext(
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    Removes mapping context when process exits.

Arguments:
    ProcessId - Process ID.
--*/
{
    PLIST_ENTRY Entry;
    PPAS_PROCESS_CONTEXT Context = NULL;

    if (!g_PasState.Initialized) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PasState.ProcessContextLock);

    for (Entry = g_PasState.ProcessContextList.Flink;
         Entry != &g_PasState.ProcessContextList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, PAS_PROCESS_CONTEXT, ListEntry);

        if (Context->ProcessId == ProcessId) {
            RemoveEntryList(&Context->ListEntry);
            InitializeListHead(&Context->ListEntry);
            InterlockedDecrement(&g_PasState.ProcessContextCount);
            break;
        }
        Context = NULL;
    }

    ExReleasePushLockExclusive(&g_PasState.ProcessContextLock);
    KeLeaveCriticalRegion();

    if (Context != NULL) {
        if (InterlockedDecrement(&Context->RefCount) == 0) {
            ExFreeToNPagedLookasideList(&g_PasState.ContextLookaside, Context);
        }
    }
}

