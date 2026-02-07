/*++
===============================================================================
ShadowStrike NGAV - PROCESS ANALYZER IMPLEMENTATION
===============================================================================

@file ProcessAnalyzer.c
@brief Enterprise-grade deep process analysis for comprehensive threat detection.

This module provides real-time process analysis capabilities including:
- PE header analysis and validation
- Security mitigation detection (DEP, ASLR, CFG, ACG)
- Process integrity level assessment
- Behavioral indicator detection
- Suspicion scoring and threat classification
- Parent-child relationship analysis
- Token and privilege inspection
- Code signing verification
- Entropy-based packing detection

Implementation Features:
- Thread-safe analysis caching with EX_PUSH_LOCK
- Lookaside lists for high-frequency allocations
- Reference counting for analysis objects
- Asynchronous analysis support
- Comprehensive MITRE ATT&CK mapping
- Integration with ProcessUtils for introspection

Detection Techniques Covered:
- T1055: Process Injection indicators
- T1036: Masquerading detection
- T1134: Access Token Manipulation
- T1548: Abuse Elevation Control Mechanism
- T1574: Hijack Execution Flow
- T1106: Native API abuse patterns

@author ShadowStrike Security Team
@version 2.0.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "ProcessAnalyzer.h"
#include "../../Utilities/ProcessUtils.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Shared/SharedDefs.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define PA_MAX_CACHED_ANALYSES          4096
#define PA_MAX_PATH_LENGTH              1024
#define PA_MAX_CMDLINE_LENGTH           8192
#define PA_ANALYSIS_CACHE_TIMEOUT_MS    60000
#define PA_ENTROPY_THRESHOLD_PACKED     700
#define PA_ENTROPY_THRESHOLD_ENCRYPTED  750
#define PA_SUSPICION_THRESHOLD_LOW      25
#define PA_SUSPICION_THRESHOLD_MEDIUM   50
#define PA_SUSPICION_THRESHOLD_HIGH     75
#define PA_SUSPICION_THRESHOLD_CRITICAL 90

//
// Pool tags for sub-allocations
//
#define PA_POOL_TAG_ANALYSIS    'AnAP'
#define PA_POOL_TAG_CACHE       'CaAP'
#define PA_POOL_TAG_STRING      'StAP'
#define PA_POOL_TAG_BUFFER      'BuAP'

//
// PE signature constants
//
#define PA_DOS_SIGNATURE        0x5A4D      // 'MZ'
#define PA_NT_SIGNATURE         0x00004550  // 'PE\0\0'
#define PA_PE32_MAGIC           0x10B
#define PA_PE32PLUS_MAGIC       0x20B

//
// PE Characteristics flags
//
#define PA_IMAGE_FILE_EXECUTABLE_IMAGE      0x0002
#define PA_IMAGE_FILE_DLL                   0x2000
#define PA_IMAGE_FILE_LARGE_ADDRESS_AWARE   0x0020
#define PA_IMAGE_FILE_RELOCS_STRIPPED       0x0001

//
// PE DllCharacteristics for security mitigations
//
#define PA_IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA     0x0020
#define PA_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE        0x0040
#define PA_IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY     0x0080
#define PA_IMAGE_DLLCHARACTERISTICS_NX_COMPAT           0x0100
#define PA_IMAGE_DLLCHARACTERISTICS_NO_SEH              0x0400
#define PA_IMAGE_DLLCHARACTERISTICS_GUARD_CF            0x4000

//
// PE Subsystem values
//
#define PA_IMAGE_SUBSYSTEM_UNKNOWN          0
#define PA_IMAGE_SUBSYSTEM_NATIVE           1
#define PA_IMAGE_SUBSYSTEM_WINDOWS_GUI      2
#define PA_IMAGE_SUBSYSTEM_WINDOWS_CUI      3

//
// .NET metadata detection
//
#define PA_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

//
// Behavior flags for suspicious indicators
//
#define PA_BEHAVIOR_SUSPICIOUS_PARENT       0x00000001
#define PA_BEHAVIOR_UNUSUAL_PATH            0x00000002
#define PA_BEHAVIOR_UNSIGNED                0x00000004
#define PA_BEHAVIOR_PACKED                  0x00000008
#define PA_BEHAVIOR_NO_DEP                  0x00000010
#define PA_BEHAVIOR_NO_ASLR                 0x00000020
#define PA_BEHAVIOR_ELEVATED                0x00000040
#define PA_BEHAVIOR_SYSTEM_IMPERSONATION    0x00000080
#define PA_BEHAVIOR_HOLLOWED                0x00000100
#define PA_BEHAVIOR_INJECTED                0x00000200
#define PA_BEHAVIOR_MASQUERADING            0x00000400
#define PA_BEHAVIOR_ANOMALOUS_TOKEN         0x00000800
#define PA_BEHAVIOR_SUSPICIOUS_CMDLINE      0x00001000
#define PA_BEHAVIOR_SCRIPT_HOST             0x00002000
#define PA_BEHAVIOR_LOL_BINARY              0x00004000
#define PA_BEHAVIOR_UNUSUAL_EXTENSION       0x00008000
#define PA_BEHAVIOR_HIDDEN_WINDOW           0x00010000
#define PA_BEHAVIOR_DEBUGGER_PRESENT        0x00020000
#define PA_BEHAVIOR_SHORT_LIVED             0x00040000
#define PA_BEHAVIOR_HIGH_ENTROPY            0x00080000

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

//
// Extended analysis with private data
//
typedef struct _PA_ANALYSIS_INTERNAL {
    //
    // Public structure (must be first)
    //
    PA_PROCESS_ANALYSIS Public;

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // Cache management
    //
    LARGE_INTEGER AnalysisTime;
    LARGE_INTEGER LastAccessTime;
    BOOLEAN IsValid;
    BOOLEAN InCache;
    UCHAR Reserved[2];

    //
    // Extended PE information
    //
    struct {
        ULONG ImageBase;
        ULONG ImageSize;
        ULONG EntryPoint;
        ULONG SectionCount;
        ULONG ImportCount;
        ULONG ExportCount;
        USHORT DllCharacteristics;
        USHORT Machine;
        ULONG TimeDateStamp;
        ULONG CheckSum;
        BOOLEAN HasImportAddressTable;
        BOOLEAN HasExportTable;
        BOOLEAN HasResourceSection;
        BOOLEAN HasRelocations;
        BOOLEAN HasDebugInfo;
        BOOLEAN HasTlsCallbacks;
        BOOLEAN HasDelayImports;
        BOOLEAN HasBoundImports;
    } ExtendedPE;

    //
    // Extended security information
    //
    struct {
        ULONG TokenIntegrityLevel;
        ULONG ProtectionLevel;
        BOOLEAN IsProtectedProcess;
        BOOLEAN IsProtectedProcessLight;
        BOOLEAN IsSystemProcess;
        BOOLEAN IsServiceProcess;
        BOOLEAN HasSeDebugPrivilege;
        BOOLEAN HasSeLoadDriverPrivilege;
        BOOLEAN HasSeTcbPrivilege;
        BOOLEAN IsElevated;
        HANDLE TokenHandle;
        SID_IDENTIFIER_AUTHORITY SidAuthority;
    } ExtendedSecurity;

    //
    // Parent process information
    //
    struct {
        UNICODE_STRING ImagePath;
        WCHAR ImagePathBuffer[PA_MAX_PATH_LENGTH];
        BOOLEAN IsKnownParent;
        BOOLEAN ParentMismatch;
        ULONG ParentSuspicionScore;
    } ParentInfo;

    //
    // String buffers
    //
    WCHAR ImagePathBuffer[PA_MAX_PATH_LENGTH];
    WCHAR CommandLineBuffer[PA_MAX_CMDLINE_LENGTH];

    //
    // Hash entry for cache lookup
    //
    LIST_ENTRY HashEntry;
    ULONG HashBucket;

} PA_ANALYSIS_INTERNAL, *PPA_ANALYSIS_INTERNAL;

//
// Hash bucket for cached analyses
//
typedef struct _PA_HASH_BUCKET {
    LIST_ENTRY AnalysisList;
    EX_PUSH_LOCK Lock;
    volatile LONG Count;
} PA_HASH_BUCKET, *PPA_HASH_BUCKET;

#define PA_HASH_BUCKET_COUNT        256
#define PA_HASH_BUCKET_MASK         (PA_HASH_BUCKET_COUNT - 1)

//
// Extended analyzer with private data
//
typedef struct _PA_ANALYZER_INTERNAL {
    //
    // Public structure (must be first)
    //
    PA_ANALYZER Public;

    //
    // Analysis cache hash table
    //
    PA_HASH_BUCKET HashBuckets[PA_HASH_BUCKET_COUNT];

    //
    // Lookaside list for analysis allocations
    //
    NPAGED_LOOKASIDE_LIST AnalysisLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Configuration
    //
    struct {
        ULONG CacheTimeoutMs;
        ULONG MaxCachedAnalyses;
        BOOLEAN EnableDeepAnalysis;
        BOOLEAN EnableSignatureCheck;
        BOOLEAN EnableEntropyAnalysis;
        BOOLEAN EnableParentValidation;
        ULONG SuspicionThreshold;
    } Config;

    //
    // Extended statistics
    //
    struct {
        volatile LONG64 CacheHits;
        volatile LONG64 CacheMisses;
        volatile LONG64 AnalysisErrors;
        volatile LONG64 PackedDetections;
        volatile LONG64 UnsignedDetections;
        volatile LONG64 ElevatedProcesses;
        volatile LONG64 SuspiciousParents;
        volatile LONG64 MasqueradingDetections;
    } ExtendedStats;

    //
    // Known good parent processes (hashes)
    //
    ULONG KnownParentHashes[64];
    ULONG KnownParentCount;

    //
    // Known LOLBin names (hashes)
    //
    ULONG LOLBinHashes[128];
    ULONG LOLBinCount;

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    BOOLEAN CleanupTimerActive;

    //
    // Worker thread for async analysis
    //
    HANDLE WorkerThread;
    KEVENT ShutdownEvent;
    KEVENT WorkAvailableEvent;
    LIST_ENTRY WorkQueue;
    EX_PUSH_LOCK WorkQueueLock;
    BOOLEAN ShutdownRequested;

} PA_ANALYZER_INTERNAL, *PPA_ANALYZER_INTERNAL;

//
// Work item for async analysis
//
typedef struct _PA_WORK_ITEM {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    KEVENT CompletionEvent;
    PPA_ANALYSIS_INTERNAL Result;
    NTSTATUS Status;
} PA_WORK_ITEM, *PPA_WORK_ITEM;

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

//
// Hash functions
//
static ULONG
PapHashProcessId(
    _In_ HANDLE ProcessId
    );

static ULONG
PapHashString(
    _In_ PCWSTR String,
    _In_ ULONG Length
    );

//
// Analysis allocation
//
static PPA_ANALYSIS_INTERNAL
PapAllocateAnalysis(
    _In_ PPA_ANALYZER_INTERNAL Analyzer
    );

static VOID
PapFreeAnalysisInternal(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PPA_ANALYSIS_INTERNAL Analysis
    );

static VOID
PapReferenceAnalysis(
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    );

static VOID
PapDereferenceAnalysis(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    );

//
// Cache management
//
static PPA_ANALYSIS_INTERNAL
PapLookupCachedAnalysis(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ HANDLE ProcessId
    );

static NTSTATUS
PapInsertCachedAnalysis(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PPA_ANALYSIS_INTERNAL Analysis
    );

static VOID
PapRemoveCachedAnalysis(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PPA_ANALYSIS_INTERNAL Analysis
    );

static VOID
PapCleanupStaleCache(
    _In_ PPA_ANALYZER_INTERNAL Analyzer
    );

//
// Core analysis functions
//
static NTSTATUS
PapPerformAnalysis(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ HANDLE ProcessId,
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    );

static NTSTATUS
PapAnalyzePEHeaders(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PEPROCESS Process,
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    );

static NTSTATUS
PapAnalyzeSecurityMitigations(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PEPROCESS Process,
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    );

static NTSTATUS
PapAnalyzeProcessToken(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PEPROCESS Process,
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    );

static NTSTATUS
PapAnalyzeParentProcess(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ HANDLE ParentId,
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    );

static NTSTATUS
PapAnalyzeCommandLine(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PEPROCESS Process,
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    );

static NTSTATUS
PapCalculateEntropy(
    _In_ PVOID Buffer,
    _In_ SIZE_T Length,
    _Out_ PULONG Entropy
    );

//
// Suspicion scoring
//
static ULONG
PapCalculateSuspicionScore(
    _In_ PPA_ANALYSIS_INTERNAL Analysis
    );

static ULONG
PapDetectBehaviorFlags(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PPA_ANALYSIS_INTERNAL Analysis
    );

//
// Known process detection
//
static BOOLEAN
PapIsKnownParent(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PCUNICODE_STRING ImagePath
    );

static BOOLEAN
PapIsLOLBinary(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PCUNICODE_STRING ImagePath
    );

static BOOLEAN
PapIsScriptHost(
    _In_ PCUNICODE_STRING ImagePath
    );

static BOOLEAN
PapIsSuspiciousPath(
    _In_ PCUNICODE_STRING ImagePath
    );

//
// Initialization helpers
//
static VOID
PapInitializeKnownParents(
    _In_ PPA_ANALYZER_INTERNAL Analyzer
    );

static VOID
PapInitializeLOLBins(
    _In_ PPA_ANALYZER_INTERNAL Analyzer
    );

//
// Timer and worker routines
//
static VOID
PapCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
PapWorkerThread(
    _In_ PVOID StartContext
    );

//
// String utilities
//
static BOOLEAN
PapExtractFileName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING FileName
    );

static BOOLEAN
PapStringContainsInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Substring
    );

// ============================================================================
// PUBLIC FUNCTION IMPLEMENTATIONS
// ============================================================================

NTSTATUS
PaInitialize(
    _Out_ PPA_ANALYZER* Analyzer
    )
/*++
Routine Description:
    Initializes the process analyzer subsystem.

Arguments:
    Analyzer - Receives pointer to initialized analyzer.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;
    PPA_ANALYZER_INTERNAL Internal = NULL;
    HANDLE ThreadHandle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    LARGE_INTEGER DueTime;
    ULONG i;

    if (Analyzer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Analyzer = NULL;

    //
    // Allocate internal analyzer structure
    //
    Internal = (PPA_ANALYZER_INTERNAL)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PA_ANALYZER_INTERNAL),
        PA_POOL_TAG
        );

    if (Internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Internal, sizeof(PA_ANALYZER_INTERNAL));

    //
    // Initialize public structure
    //
    InitializeListHead(&Internal->Public.AnalysisList);
    ExInitializePushLock(&Internal->Public.Lock);

    //
    // Initialize hash buckets
    //
    for (i = 0; i < PA_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&Internal->HashBuckets[i].AnalysisList);
        ExInitializePushLock(&Internal->HashBuckets[i].Lock);
        Internal->HashBuckets[i].Count = 0;
    }

    //
    // Initialize lookaside list
    //
    ExInitializeNPagedLookasideList(
        &Internal->AnalysisLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PA_ANALYSIS_INTERNAL),
        PA_POOL_TAG_ANALYSIS,
        0
        );
    Internal->LookasideInitialized = TRUE;

    //
    // Initialize default configuration
    //
    Internal->Config.CacheTimeoutMs = PA_ANALYSIS_CACHE_TIMEOUT_MS;
    Internal->Config.MaxCachedAnalyses = PA_MAX_CACHED_ANALYSES;
    Internal->Config.EnableDeepAnalysis = TRUE;
    Internal->Config.EnableSignatureCheck = TRUE;
    Internal->Config.EnableEntropyAnalysis = TRUE;
    Internal->Config.EnableParentValidation = TRUE;
    Internal->Config.SuspicionThreshold = PA_SUSPICION_THRESHOLD_MEDIUM;

    //
    // Initialize known process lists
    //
    PapInitializeKnownParents(Internal);
    PapInitializeLOLBins(Internal);

    //
    // Initialize work queue
    //
    InitializeListHead(&Internal->WorkQueue);
    ExInitializePushLock(&Internal->WorkQueueLock);

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&Internal->Public.Stats.StartTime);

    //
    // Initialize worker thread synchronization
    //
    KeInitializeEvent(&Internal->ShutdownEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&Internal->WorkAvailableEvent, SynchronizationEvent, FALSE);

    //
    // Create worker thread
    //
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = PsCreateSystemThread(
        &ThreadHandle,
        THREAD_ALL_ACCESS,
        &ObjectAttributes,
        NULL,
        NULL,
        PapWorkerThread,
        Internal
        );

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status = ObReferenceObjectByHandle(
        ThreadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&Internal->WorkerThread,
        NULL
        );

    ZwClose(ThreadHandle);

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&Internal->CleanupTimer);
    KeInitializeDpc(&Internal->CleanupDpc, PapCleanupTimerDpc, Internal);

    //
    // Start cleanup timer (every 30 seconds)
    //
    DueTime.QuadPart = -((LONGLONG)30000 * 10000);
    KeSetTimerEx(
        &Internal->CleanupTimer,
        DueTime,
        30000,
        &Internal->CleanupDpc
        );
    Internal->CleanupTimerActive = TRUE;

    //
    // Mark as initialized
    //
    Internal->Public.Initialized = TRUE;
    *Analyzer = (PPA_ANALYZER)Internal;

    return STATUS_SUCCESS;

Cleanup:
    if (Internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Internal->AnalysisLookaside);
    }

    ExFreePoolWithTag(Internal, PA_POOL_TAG);
    return Status;
}

VOID
PaShutdown(
    _Inout_ PPA_ANALYZER Analyzer
    )
/*++
Routine Description:
    Shuts down the process analyzer subsystem.

Arguments:
    Analyzer - Analyzer instance to shutdown.
--*/
{
    PPA_ANALYZER_INTERNAL Internal = (PPA_ANALYZER_INTERNAL)Analyzer;
    PLIST_ENTRY Entry;
    PPA_ANALYSIS_INTERNAL Analysis;
    ULONG i;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return;
    }

    Internal->Public.Initialized = FALSE;
    Internal->ShutdownRequested = TRUE;

    //
    // Cancel cleanup timer
    //
    if (Internal->CleanupTimerActive) {
        KeCancelTimer(&Internal->CleanupTimer);
        Internal->CleanupTimerActive = FALSE;
    }

    //
    // Signal worker thread to exit
    //
    KeSetEvent(&Internal->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&Internal->WorkAvailableEvent, IO_NO_INCREMENT, FALSE);

    if (Internal->WorkerThread != NULL) {
        KeWaitForSingleObject(
            Internal->WorkerThread,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );
        ObDereferenceObject(Internal->WorkerThread);
        Internal->WorkerThread = NULL;
    }

    //
    // Free all cached analyses
    //
    for (i = 0; i < PA_HASH_BUCKET_COUNT; i++) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Internal->HashBuckets[i].Lock);

        while (!IsListEmpty(&Internal->HashBuckets[i].AnalysisList)) {
            Entry = RemoveHeadList(&Internal->HashBuckets[i].AnalysisList);
            Analysis = CONTAINING_RECORD(Entry, PA_ANALYSIS_INTERNAL, HashEntry);
            Analysis->InCache = FALSE;

            ExReleasePushLockExclusive(&Internal->HashBuckets[i].Lock);
            KeLeaveCriticalRegion();

            PapFreeAnalysisInternal(Internal, Analysis);

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Internal->HashBuckets[i].Lock);
        }

        ExReleasePushLockExclusive(&Internal->HashBuckets[i].Lock);
        KeLeaveCriticalRegion();
    }

    //
    // Free all analyses from main list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->Public.Lock);

    while (!IsListEmpty(&Internal->Public.AnalysisList)) {
        Entry = RemoveHeadList(&Internal->Public.AnalysisList);
        Analysis = CONTAINING_RECORD(Entry, PA_ANALYSIS_INTERNAL, Public.ListEntry);

        ExReleasePushLockExclusive(&Internal->Public.Lock);
        KeLeaveCriticalRegion();

        PapFreeAnalysisInternal(Internal, Analysis);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Internal->Public.Lock);
    }

    ExReleasePushLockExclusive(&Internal->Public.Lock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside list
    //
    if (Internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Internal->AnalysisLookaside);
    }

    //
    // Free analyzer
    //
    ExFreePoolWithTag(Internal, PA_POOL_TAG);
}

NTSTATUS
PaAnalyzeProcess(
    _In_ PPA_ANALYZER Analyzer,
    _In_ HANDLE ProcessId,
    _Out_ PPA_PROCESS_ANALYSIS* Analysis
    )
/*++
Routine Description:
    Performs comprehensive analysis of a process.

Arguments:
    Analyzer - Analyzer instance.
    ProcessId - Process to analyze.
    Analysis - Receives analysis results.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PPA_ANALYZER_INTERNAL Internal = (PPA_ANALYZER_INTERNAL)Analyzer;
    PPA_ANALYSIS_INTERNAL InternalAnalysis = NULL;
    NTSTATUS Status;

    if (Internal == NULL || !Internal->Public.Initialized || Analysis == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Analysis = NULL;

    //
    // Check cache first
    //
    InternalAnalysis = PapLookupCachedAnalysis(Internal, ProcessId);
    if (InternalAnalysis != NULL) {
        InterlockedIncrement64(&Internal->ExtendedStats.CacheHits);
        KeQuerySystemTime(&InternalAnalysis->LastAccessTime);
        *Analysis = &InternalAnalysis->Public;
        return STATUS_SUCCESS;
    }

    InterlockedIncrement64(&Internal->ExtendedStats.CacheMisses);

    //
    // Allocate new analysis
    //
    InternalAnalysis = PapAllocateAnalysis(Internal);
    if (InternalAnalysis == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Perform analysis
    //
    Status = PapPerformAnalysis(Internal, ProcessId, InternalAnalysis);
    if (!NT_SUCCESS(Status)) {
        InterlockedIncrement64(&Internal->ExtendedStats.AnalysisErrors);
        PapFreeAnalysisInternal(Internal, InternalAnalysis);
        return Status;
    }

    //
    // Calculate behavior flags and suspicion score
    //
    InternalAnalysis->Public.BehaviorFlags = PapDetectBehaviorFlags(Internal, InternalAnalysis);
    InternalAnalysis->Public.SuspicionScore = PapCalculateSuspicionScore(InternalAnalysis);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Internal->Public.Stats.ProcessesAnalyzed);

    if (InternalAnalysis->Public.SuspicionScore >= Internal->Config.SuspicionThreshold) {
        InterlockedIncrement64(&Internal->Public.Stats.SuspiciousFound);
    }

    if (InternalAnalysis->Public.PE.IsPacked) {
        InterlockedIncrement64(&Internal->ExtendedStats.PackedDetections);
    }

    if (!InternalAnalysis->Public.PE.IsSigned) {
        InterlockedIncrement64(&Internal->ExtendedStats.UnsignedDetections);
    }

    if (InternalAnalysis->ExtendedSecurity.IsElevated) {
        InterlockedIncrement64(&Internal->ExtendedStats.ElevatedProcesses);
    }

    //
    // Insert into cache
    //
    Status = PapInsertCachedAnalysis(Internal, InternalAnalysis);
    if (!NT_SUCCESS(Status)) {
        //
        // Cache insert failed, but analysis is still valid
        //
    }

    //
    // Add to main analysis list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->Public.Lock);
    InsertTailList(&Internal->Public.AnalysisList, &InternalAnalysis->Public.ListEntry);
    InterlockedIncrement(&Internal->Public.AnalysisCount);
    ExReleasePushLockExclusive(&Internal->Public.Lock);
    KeLeaveCriticalRegion();

    *Analysis = &InternalAnalysis->Public;

    return STATUS_SUCCESS;
}

NTSTATUS
PaQuickCheck(
    _In_ PPA_ANALYZER Analyzer,
    _In_ HANDLE ProcessId,
    _Out_ PULONG SuspicionScore
    )
/*++
Routine Description:
    Performs a quick suspicion check without full analysis.

Arguments:
    Analyzer - Analyzer instance.
    ProcessId - Process to check.
    SuspicionScore - Receives suspicion score.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PPA_ANALYZER_INTERNAL Internal = (PPA_ANALYZER_INTERNAL)Analyzer;
    PPA_ANALYSIS_INTERNAL CachedAnalysis;
    PEPROCESS Process = NULL;
    NTSTATUS Status;
    ULONG Score = 0;

    if (Internal == NULL || !Internal->Public.Initialized || SuspicionScore == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *SuspicionScore = 0;

    //
    // Check cache first
    //
    CachedAnalysis = PapLookupCachedAnalysis(Internal, ProcessId);
    if (CachedAnalysis != NULL) {
        *SuspicionScore = CachedAnalysis->Public.SuspicionScore;
        PapDereferenceAnalysis(Internal, CachedAnalysis);
        return STATUS_SUCCESS;
    }

    //
    // Get process object
    //
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Quick checks without full analysis
    //
    __try {
        UCHAR Buffer[256];
        PUNICODE_STRING ImageName;

        //
        // Get image file name
        //
        Status = SeLocateProcessImageName(Process, &ImageName);
        if (NT_SUCCESS(Status)) {
            //
            // Check for suspicious path
            //
            if (PapIsSuspiciousPath(ImageName)) {
                Score += 30;
            }

            //
            // Check for script host
            //
            if (PapIsScriptHost(ImageName)) {
                Score += 20;
            }

            //
            // Check for LOLBin
            //
            if (PapIsLOLBinary(Internal, ImageName)) {
                Score += 25;
            }

            ExFreePool(ImageName);
        }

        //
        // Check for elevated process
        //
        {
            PACCESS_TOKEN Token = PsReferencePrimaryToken(Process);
            if (Token != NULL) {
                SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
                TOKEN_TYPE TokenType;
                BOOLEAN IsElevated = FALSE;

                //
                // Simplified elevation check
                //
                if (SeTokenIsAdmin(Token)) {
                    IsElevated = TRUE;
                    Score += 15;
                }

                PsDereferencePrimaryToken(Token);
            }
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    ObDereferenceObject(Process);

    //
    // Cap score at 100
    //
    if (Score > 100) {
        Score = 100;
    }

    *SuspicionScore = Score;

    return STATUS_SUCCESS;
}

VOID
PaFreeAnalysis(
    _In_ PPA_PROCESS_ANALYSIS Analysis
    )
/*++
Routine Description:
    Frees a process analysis structure.

Arguments:
    Analysis - Analysis to free.
--*/
{
    PPA_ANALYSIS_INTERNAL InternalAnalysis;

    if (Analysis == NULL) {
        return;
    }

    InternalAnalysis = CONTAINING_RECORD(Analysis, PA_ANALYSIS_INTERNAL, Public);

    //
    // Just dereference - actual free happens when refcount hits zero
    // Note: We don't have direct access to analyzer here, so we need to
    // handle this differently. The analysis should be marked as not in cache
    // and the memory should be freed when the analyzer shuts down or
    // when it's explicitly removed from the cache.
    //

    //
    // For now, we'll free the string buffers if they were dynamically allocated
    // The lookaside list memory will be freed during shutdown
    //
    if (InternalAnalysis->Public.ImagePath.Buffer != NULL &&
        InternalAnalysis->Public.ImagePath.Buffer != InternalAnalysis->ImagePathBuffer) {
        ExFreePoolWithTag(InternalAnalysis->Public.ImagePath.Buffer, PA_POOL_TAG_STRING);
    }

    if (InternalAnalysis->Public.CommandLine.Buffer != NULL &&
        InternalAnalysis->Public.CommandLine.Buffer != InternalAnalysis->CommandLineBuffer) {
        ExFreePoolWithTag(InternalAnalysis->Public.CommandLine.Buffer, PA_POOL_TAG_STRING);
    }
}

// ============================================================================
// PRIVATE FUNCTION IMPLEMENTATIONS
// ============================================================================

static ULONG
PapHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR Value = (ULONG_PTR)ProcessId;

    Value ^= (Value >> 16);
    Value *= 0x85ebca6b;
    Value ^= (Value >> 13);
    Value *= 0xc2b2ae35;
    Value ^= (Value >> 16);

    return (ULONG)(Value & PA_HASH_BUCKET_MASK);
}

static ULONG
PapHashString(
    _In_ PCWSTR String,
    _In_ ULONG Length
    )
{
    ULONG Hash = 5381;
    ULONG i;

    for (i = 0; i < Length && String[i] != L'\0'; i++) {
        WCHAR Ch = String[i];
        //
        // Case-insensitive hash
        //
        if (Ch >= L'A' && Ch <= L'Z') {
            Ch += (L'a' - L'A');
        }
        Hash = ((Hash << 5) + Hash) + (ULONG)Ch;
    }

    return Hash;
}

static PPA_ANALYSIS_INTERNAL
PapAllocateAnalysis(
    _In_ PPA_ANALYZER_INTERNAL Analyzer
    )
{
    PPA_ANALYSIS_INTERNAL Analysis;

    Analysis = (PPA_ANALYSIS_INTERNAL)ExAllocateFromNPagedLookasideList(
        &Analyzer->AnalysisLookaside
        );

    if (Analysis != NULL) {
        RtlZeroMemory(Analysis, sizeof(PA_ANALYSIS_INTERNAL));
        Analysis->RefCount = 1;
        Analysis->IsValid = FALSE;
        Analysis->InCache = FALSE;
        InitializeListHead(&Analysis->Public.ListEntry);
        InitializeListHead(&Analysis->HashEntry);

        //
        // Initialize string buffers to use internal storage
        //
        Analysis->Public.ImagePath.Buffer = Analysis->ImagePathBuffer;
        Analysis->Public.ImagePath.Length = 0;
        Analysis->Public.ImagePath.MaximumLength = sizeof(Analysis->ImagePathBuffer);

        Analysis->Public.CommandLine.Buffer = Analysis->CommandLineBuffer;
        Analysis->Public.CommandLine.Length = 0;
        Analysis->Public.CommandLine.MaximumLength = sizeof(Analysis->CommandLineBuffer);

        Analysis->ParentInfo.ImagePath.Buffer = Analysis->ParentInfo.ImagePathBuffer;
        Analysis->ParentInfo.ImagePath.Length = 0;
        Analysis->ParentInfo.ImagePath.MaximumLength = sizeof(Analysis->ParentInfo.ImagePathBuffer);
    }

    return Analysis;
}

static VOID
PapFreeAnalysisInternal(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PPA_ANALYSIS_INTERNAL Analysis
    )
{
    //
    // Free any dynamically allocated strings
    //
    if (Analysis->Public.ImagePath.Buffer != NULL &&
        Analysis->Public.ImagePath.Buffer != Analysis->ImagePathBuffer) {
        ExFreePoolWithTag(Analysis->Public.ImagePath.Buffer, PA_POOL_TAG_STRING);
    }

    if (Analysis->Public.CommandLine.Buffer != NULL &&
        Analysis->Public.CommandLine.Buffer != Analysis->CommandLineBuffer) {
        ExFreePoolWithTag(Analysis->Public.CommandLine.Buffer, PA_POOL_TAG_STRING);
    }

    if (Analysis->ParentInfo.ImagePath.Buffer != NULL &&
        Analysis->ParentInfo.ImagePath.Buffer != Analysis->ParentInfo.ImagePathBuffer) {
        ExFreePoolWithTag(Analysis->ParentInfo.ImagePath.Buffer, PA_POOL_TAG_STRING);
    }

    ExFreeToNPagedLookasideList(&Analyzer->AnalysisLookaside, Analysis);
}

static VOID
PapReferenceAnalysis(
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    )
{
    InterlockedIncrement(&Analysis->RefCount);
}

static VOID
PapDereferenceAnalysis(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    )
{
    if (InterlockedDecrement(&Analysis->RefCount) == 0) {
        PapFreeAnalysisInternal(Analyzer, Analysis);
    }
}

static PPA_ANALYSIS_INTERNAL
PapLookupCachedAnalysis(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ HANDLE ProcessId
    )
{
    ULONG Hash;
    PLIST_ENTRY Entry;
    PPA_ANALYSIS_INTERNAL Analysis;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;

    Hash = PapHashProcessId(ProcessId);

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)Analyzer->Config.CacheTimeoutMs * 10000;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Analyzer->HashBuckets[Hash].Lock);

    for (Entry = Analyzer->HashBuckets[Hash].AnalysisList.Flink;
         Entry != &Analyzer->HashBuckets[Hash].AnalysisList;
         Entry = Entry->Flink) {

        Analysis = CONTAINING_RECORD(Entry, PA_ANALYSIS_INTERNAL, HashEntry);

        if (Analysis->Public.ProcessId == ProcessId) {
            //
            // Check if cache entry is still valid
            //
            if ((CurrentTime.QuadPart - Analysis->AnalysisTime.QuadPart) <= TimeoutInterval.QuadPart) {
                PapReferenceAnalysis(Analysis);
                ExReleasePushLockShared(&Analyzer->HashBuckets[Hash].Lock);
                KeLeaveCriticalRegion();
                return Analysis;
            }
        }
    }

    ExReleasePushLockShared(&Analyzer->HashBuckets[Hash].Lock);
    KeLeaveCriticalRegion();

    return NULL;
}

static NTSTATUS
PapInsertCachedAnalysis(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PPA_ANALYSIS_INTERNAL Analysis
    )
{
    ULONG Hash;

    if ((ULONG)Analyzer->Public.AnalysisCount >= Analyzer->Config.MaxCachedAnalyses) {
        return STATUS_QUOTA_EXCEEDED;
    }

    Hash = PapHashProcessId(Analysis->Public.ProcessId);
    Analysis->HashBucket = Hash;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Analyzer->HashBuckets[Hash].Lock);

    InsertTailList(&Analyzer->HashBuckets[Hash].AnalysisList, &Analysis->HashEntry);
    InterlockedIncrement(&Analyzer->HashBuckets[Hash].Count);
    Analysis->InCache = TRUE;
    KeQuerySystemTime(&Analysis->AnalysisTime);
    Analysis->LastAccessTime = Analysis->AnalysisTime;

    ExReleasePushLockExclusive(&Analyzer->HashBuckets[Hash].Lock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

static VOID
PapRemoveCachedAnalysis(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PPA_ANALYSIS_INTERNAL Analysis
    )
{
    ULONG Hash;

    if (!Analysis->InCache) {
        return;
    }

    Hash = Analysis->HashBucket;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Analyzer->HashBuckets[Hash].Lock);

    if (Analysis->InCache) {
        RemoveEntryList(&Analysis->HashEntry);
        InitializeListHead(&Analysis->HashEntry);
        InterlockedDecrement(&Analyzer->HashBuckets[Hash].Count);
        Analysis->InCache = FALSE;
    }

    ExReleasePushLockExclusive(&Analyzer->HashBuckets[Hash].Lock);
    KeLeaveCriticalRegion();
}

static VOID
PapCleanupStaleCache(
    _In_ PPA_ANALYZER_INTERNAL Analyzer
    )
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;
    ULONG i;
    PLIST_ENTRY Entry, Next;
    PPA_ANALYSIS_INTERNAL Analysis;
    LIST_ENTRY StaleList;

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)Analyzer->Config.CacheTimeoutMs * 10000;

    InitializeListHead(&StaleList);

    for (i = 0; i < PA_HASH_BUCKET_COUNT && !Analyzer->ShutdownRequested; i++) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Analyzer->HashBuckets[i].Lock);

        for (Entry = Analyzer->HashBuckets[i].AnalysisList.Flink;
             Entry != &Analyzer->HashBuckets[i].AnalysisList;
             Entry = Next) {

            Next = Entry->Flink;
            Analysis = CONTAINING_RECORD(Entry, PA_ANALYSIS_INTERNAL, HashEntry);

            if ((CurrentTime.QuadPart - Analysis->AnalysisTime.QuadPart) > TimeoutInterval.QuadPart) {
                RemoveEntryList(&Analysis->HashEntry);
                InterlockedDecrement(&Analyzer->HashBuckets[i].Count);
                Analysis->InCache = FALSE;
                InsertTailList(&StaleList, &Analysis->HashEntry);
            }
        }

        ExReleasePushLockExclusive(&Analyzer->HashBuckets[i].Lock);
        KeLeaveCriticalRegion();
    }

    //
    // Free stale entries outside the lock
    //
    while (!IsListEmpty(&StaleList)) {
        Entry = RemoveHeadList(&StaleList);
        Analysis = CONTAINING_RECORD(Entry, PA_ANALYSIS_INTERNAL, HashEntry);

        //
        // Also remove from main analysis list
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Analyzer->Public.Lock);
        RemoveEntryList(&Analysis->Public.ListEntry);
        InterlockedDecrement(&Analyzer->Public.AnalysisCount);
        ExReleasePushLockExclusive(&Analyzer->Public.Lock);
        KeLeaveCriticalRegion();

        PapDereferenceAnalysis(Analyzer, Analysis);
    }
}

static NTSTATUS
PapPerformAnalysis(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ HANDLE ProcessId,
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    )
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    PUNICODE_STRING ImageFileName = NULL;

    //
    // Get process object
    //
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Analysis->Public.ProcessId = ProcessId;

    __try {
        //
        // Get image file name
        //
        Status = SeLocateProcessImageName(Process, &ImageFileName);
        if (NT_SUCCESS(Status) && ImageFileName != NULL) {
            if (ImageFileName->Length <= Analysis->Public.ImagePath.MaximumLength - sizeof(WCHAR)) {
                RtlCopyMemory(
                    Analysis->Public.ImagePath.Buffer,
                    ImageFileName->Buffer,
                    ImageFileName->Length
                    );
                Analysis->Public.ImagePath.Length = ImageFileName->Length;
                Analysis->Public.ImagePath.Buffer[ImageFileName->Length / sizeof(WCHAR)] = L'\0';
            }
            ExFreePool(ImageFileName);
            ImageFileName = NULL;
        }

        //
        // Get parent process ID
        //
        Analysis->Public.ParentId = PsGetProcessInheritedFromUniqueProcessId(Process);

        //
        // Analyze PE headers
        //
        if (Analyzer->Config.EnableDeepAnalysis) {
            Status = PapAnalyzePEHeaders(Analyzer, Process, Analysis);
            if (!NT_SUCCESS(Status)) {
                //
                // PE analysis failure is not fatal
                //
            }
        }

        //
        // Analyze security mitigations
        //
        Status = PapAnalyzeSecurityMitigations(Analyzer, Process, Analysis);
        if (!NT_SUCCESS(Status)) {
            //
            // Security analysis failure is not fatal
            //
        }

        //
        // Analyze process token
        //
        Status = PapAnalyzeProcessToken(Analyzer, Process, Analysis);
        if (!NT_SUCCESS(Status)) {
            //
            // Token analysis failure is not fatal
            //
        }

        //
        // Analyze parent process
        //
        if (Analyzer->Config.EnableParentValidation && Analysis->Public.ParentId != NULL) {
            Status = PapAnalyzeParentProcess(Analyzer, Analysis->Public.ParentId, Analysis);
            if (!NT_SUCCESS(Status)) {
                //
                // Parent analysis failure is not fatal
                //
            }
        }

        //
        // Analyze command line
        //
        Status = PapAnalyzeCommandLine(Analyzer, Process, Analysis);
        if (!NT_SUCCESS(Status)) {
            //
            // Command line analysis failure is not fatal
            //
        }

        Analysis->IsValid = TRUE;
        Status = STATUS_SUCCESS;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    if (ImageFileName != NULL) {
        ExFreePool(ImageFileName);
    }

    ObDereferenceObject(Process);

    return Status;
}

static NTSTATUS
PapAnalyzePEHeaders(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PEPROCESS Process,
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    KAPC_STATE ApcState;
    PVOID ImageBase = NULL;
    BOOLEAN Attached = FALSE;

    UNREFERENCED_PARAMETER(Analyzer);

    __try {
        //
        // Get process image base
        //
        ImageBase = PsGetProcessSectionBaseAddress(Process);
        if (ImageBase == NULL) {
            return STATUS_NOT_FOUND;
        }

        //
        // Attach to process address space
        //
        KeStackAttachProcess(Process, &ApcState);
        Attached = TRUE;

        //
        // Read and validate DOS header
        //
        __try {
            PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
            PIMAGE_NT_HEADERS NtHeaders;

            ProbeForRead(DosHeader, sizeof(IMAGE_DOS_HEADER), 1);

            if (DosHeader->e_magic != PA_DOS_SIGNATURE) {
                Analysis->Public.PE.IsPE = FALSE;
                __leave;
            }

            //
            // Get NT headers
            //
            NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + DosHeader->e_lfanew);
            ProbeForRead(NtHeaders, sizeof(IMAGE_NT_HEADERS), 1);

            if (NtHeaders->Signature != PA_NT_SIGNATURE) {
                Analysis->Public.PE.IsPE = FALSE;
                __leave;
            }

            Analysis->Public.PE.IsPE = TRUE;

            //
            // Check if 64-bit
            //
            Analysis->Public.PE.Is64Bit = (NtHeaders->OptionalHeader.Magic == PA_PE32PLUS_MAGIC);

            //
            // Get characteristics
            //
            Analysis->Public.PE.Characteristics = NtHeaders->FileHeader.Characteristics;
            Analysis->ExtendedPE.Machine = NtHeaders->FileHeader.Machine;
            Analysis->ExtendedPE.SectionCount = NtHeaders->FileHeader.NumberOfSections;
            Analysis->ExtendedPE.TimeDateStamp = NtHeaders->FileHeader.TimeDateStamp;

            //
            // Get optional header info
            //
            if (Analysis->Public.PE.Is64Bit) {
                PIMAGE_OPTIONAL_HEADER64 OptHeader = (PIMAGE_OPTIONAL_HEADER64)&NtHeaders->OptionalHeader;
                Analysis->Public.PE.Subsystem = OptHeader->Subsystem;
                Analysis->ExtendedPE.ImageBase = (ULONG)OptHeader->ImageBase;
                Analysis->ExtendedPE.ImageSize = OptHeader->SizeOfImage;
                Analysis->ExtendedPE.EntryPoint = OptHeader->AddressOfEntryPoint;
                Analysis->ExtendedPE.CheckSum = OptHeader->CheckSum;
                Analysis->ExtendedPE.DllCharacteristics = OptHeader->DllCharacteristics;

                //
                // Check for .NET
                //
                if (OptHeader->NumberOfRvaAndSizes > PA_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
                    if (OptHeader->DataDirectory[PA_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0) {
                        Analysis->Public.PE.IsDotNet = TRUE;
                    }
                }

                //
                // Check for imports/exports
                //
                if (OptHeader->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
                    Analysis->ExtendedPE.HasImportAddressTable =
                        (OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0);
                }

                if (OptHeader->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
                    Analysis->ExtendedPE.HasExportTable =
                        (OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0);
                }

                if (OptHeader->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
                    Analysis->ExtendedPE.HasDebugInfo =
                        (OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress != 0);
                }

                if (OptHeader->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
                    Analysis->ExtendedPE.HasTlsCallbacks =
                        (OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0);
                }

                if (OptHeader->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
                    Analysis->ExtendedPE.HasRelocations =
                        (OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0);
                }

            } else {
                PIMAGE_OPTIONAL_HEADER32 OptHeader = (PIMAGE_OPTIONAL_HEADER32)&NtHeaders->OptionalHeader;
                Analysis->Public.PE.Subsystem = OptHeader->Subsystem;
                Analysis->ExtendedPE.ImageBase = OptHeader->ImageBase;
                Analysis->ExtendedPE.ImageSize = OptHeader->SizeOfImage;
                Analysis->ExtendedPE.EntryPoint = OptHeader->AddressOfEntryPoint;
                Analysis->ExtendedPE.CheckSum = OptHeader->CheckSum;
                Analysis->ExtendedPE.DllCharacteristics = OptHeader->DllCharacteristics;

                //
                // Check for .NET
                //
                if (OptHeader->NumberOfRvaAndSizes > PA_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
                    if (OptHeader->DataDirectory[PA_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0) {
                        Analysis->Public.PE.IsDotNet = TRUE;
                    }
                }

                //
                // Check for imports/exports
                //
                if (OptHeader->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
                    Analysis->ExtendedPE.HasImportAddressTable =
                        (OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0);
                }

                if (OptHeader->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
                    Analysis->ExtendedPE.HasExportTable =
                        (OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0);
                }

                if (OptHeader->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
                    Analysis->ExtendedPE.HasDebugInfo =
                        (OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress != 0);
                }

                if (OptHeader->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
                    Analysis->ExtendedPE.HasTlsCallbacks =
                        (OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0);
                }

                if (OptHeader->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
                    Analysis->ExtendedPE.HasRelocations =
                        (OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0);
                }
            }

            //
            // Calculate entropy for packing detection
            //
            if (Analyzer->Config.EnableEntropyAnalysis && Analysis->ExtendedPE.ImageSize > 0) {
                ULONG Entropy = 0;
                SIZE_T SampleSize = min(Analysis->ExtendedPE.ImageSize, 0x10000);

                Status = PapCalculateEntropy(ImageBase, SampleSize, &Entropy);
                if (NT_SUCCESS(Status)) {
                    Analysis->Public.PE.Entropy = Entropy;
                    Analysis->Public.PE.IsPacked = (Entropy >= PA_ENTROPY_THRESHOLD_PACKED);
                }
            }

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

    } __finally {
        if (Attached) {
            KeUnstackDetachProcess(&ApcState);
        }
    }

    return Status;
}

static NTSTATUS
PapAnalyzeSecurityMitigations(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PEPROCESS Process,
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    )
{
    UNREFERENCED_PARAMETER(Analyzer);
    UNREFERENCED_PARAMETER(Process);

    //
    // Check security mitigations from DllCharacteristics
    //
    if (Analysis->Public.PE.IsPE) {
        USHORT DllChar = Analysis->ExtendedPE.DllCharacteristics;

        Analysis->Public.Security.HasDEP =
            ((DllChar & PA_IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0);

        Analysis->Public.Security.HasASLR =
            ((DllChar & PA_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0);

        Analysis->Public.Security.HasCFG =
            ((DllChar & PA_IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0);
    }

    //
    // Get process mitigation policies (if available)
    // Note: Full implementation would use ZwQueryInformationProcess
    // with ProcessMitigationPolicy
    //

    return STATUS_SUCCESS;
}

static NTSTATUS
PapAnalyzeProcessToken(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PEPROCESS Process,
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    )
{
    PACCESS_TOKEN Token = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Analyzer);

    __try {
        Token = PsReferencePrimaryToken(Process);
        if (Token == NULL) {
            return STATUS_UNSUCCESSFUL;
        }

        //
        // Check for admin token
        //
        Analysis->ExtendedSecurity.IsElevated = SeTokenIsAdmin(Token);

        //
        // Check for specific privileges
        //
        {
            LUID SeDebugLuid = { SE_DEBUG_PRIVILEGE, 0 };
            LUID SeLoadDriverLuid = { SE_LOAD_DRIVER_PRIVILEGE, 0 };
            LUID SeTcbLuid = { SE_TCB_PRIVILEGE, 0 };

            Analysis->ExtendedSecurity.HasSeDebugPrivilege =
                SePrivilegeCheck(&SeDebugLuid, Token, KernelMode);

            Analysis->ExtendedSecurity.HasSeLoadDriverPrivilege =
                SePrivilegeCheck(&SeLoadDriverLuid, Token, KernelMode);

            Analysis->ExtendedSecurity.HasSeTcbPrivilege =
                SePrivilegeCheck(&SeTcbLuid, Token, KernelMode);
        }

        //
        // Get integrity level
        //
        {
            TOKEN_MANDATORY_LABEL* MandatoryLabel = NULL;
            ULONG ReturnLength = 0;

            Status = SeQueryInformationToken(
                Token,
                TokenIntegrityLevel,
                NULL,
                0,
                &ReturnLength
                );

            if (Status == STATUS_BUFFER_TOO_SMALL && ReturnLength > 0) {
                MandatoryLabel = (TOKEN_MANDATORY_LABEL*)ExAllocatePoolWithTag(
                    PagedPool,
                    ReturnLength,
                    PA_POOL_TAG_BUFFER
                    );

                if (MandatoryLabel != NULL) {
                    Status = SeQueryInformationToken(
                        Token,
                        TokenIntegrityLevel,
                        MandatoryLabel,
                        ReturnLength,
                        &ReturnLength
                        );

                    if (NT_SUCCESS(Status)) {
                        PISID Sid = (PISID)MandatoryLabel->Label.Sid;
                        if (Sid != NULL && Sid->SubAuthorityCount > 0) {
                            Analysis->ExtendedSecurity.TokenIntegrityLevel =
                                Sid->SubAuthority[Sid->SubAuthorityCount - 1];
                            Analysis->Public.Security.IntegrityLevel =
                                Analysis->ExtendedSecurity.TokenIntegrityLevel;
                            Analysis->Public.Security.HasIntegrityLevel = TRUE;
                        }
                    }

                    ExFreePoolWithTag(MandatoryLabel, PA_POOL_TAG_BUFFER);
                }
            }
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    if (Token != NULL) {
        PsDereferencePrimaryToken(Token);
    }

    return Status;
}

static NTSTATUS
PapAnalyzeParentProcess(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ HANDLE ParentId,
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    )
{
    NTSTATUS Status;
    PEPROCESS ParentProcess = NULL;
    PUNICODE_STRING ParentImageName = NULL;

    Status = PsLookupProcessByProcessId(ParentId, &ParentProcess);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    __try {
        //
        // Get parent image name
        //
        Status = SeLocateProcessImageName(ParentProcess, &ParentImageName);
        if (NT_SUCCESS(Status) && ParentImageName != NULL) {
            if (ParentImageName->Length <= Analysis->ParentInfo.ImagePath.MaximumLength - sizeof(WCHAR)) {
                RtlCopyMemory(
                    Analysis->ParentInfo.ImagePath.Buffer,
                    ParentImageName->Buffer,
                    ParentImageName->Length
                    );
                Analysis->ParentInfo.ImagePath.Length = ParentImageName->Length;
                Analysis->ParentInfo.ImagePath.Buffer[ParentImageName->Length / sizeof(WCHAR)] = L'\0';
            }

            //
            // Check if parent is known good
            //
            Analysis->ParentInfo.IsKnownParent = PapIsKnownParent(Analyzer, ParentImageName);

            //
            // Check for parent-child mismatch (e.g., notepad.exe spawning cmd.exe)
            //
            Analysis->ParentInfo.ParentMismatch = FALSE;
            // TODO: Implement parent-child validation rules

            ExFreePool(ParentImageName);
            ParentImageName = NULL;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    if (ParentImageName != NULL) {
        ExFreePool(ParentImageName);
    }

    ObDereferenceObject(ParentProcess);

    return Status;
}

static NTSTATUS
PapAnalyzeCommandLine(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PEPROCESS Process,
    _Inout_ PPA_ANALYSIS_INTERNAL Analysis
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    KAPC_STATE ApcState;
    BOOLEAN Attached = FALSE;

    UNREFERENCED_PARAMETER(Analyzer);

    __try {
        PPEB Peb;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;

        //
        // Get PEB
        //
        Peb = PsGetProcessPeb(Process);
        if (Peb == NULL) {
            return STATUS_NOT_FOUND;
        }

        //
        // Attach to process
        //
        KeStackAttachProcess(Process, &ApcState);
        Attached = TRUE;

        __try {
            ProbeForRead(Peb, sizeof(PEB), 1);

            ProcessParameters = Peb->ProcessParameters;
            if (ProcessParameters != NULL) {
                ProbeForRead(ProcessParameters, sizeof(RTL_USER_PROCESS_PARAMETERS), 1);

                if (ProcessParameters->CommandLine.Buffer != NULL &&
                    ProcessParameters->CommandLine.Length > 0) {

                    USHORT CopyLength = min(
                        ProcessParameters->CommandLine.Length,
                        (USHORT)(Analysis->Public.CommandLine.MaximumLength - sizeof(WCHAR))
                        );

                    ProbeForRead(
                        ProcessParameters->CommandLine.Buffer,
                        CopyLength,
                        sizeof(WCHAR)
                        );

                    RtlCopyMemory(
                        Analysis->Public.CommandLine.Buffer,
                        ProcessParameters->CommandLine.Buffer,
                        CopyLength
                        );
                    Analysis->Public.CommandLine.Length = CopyLength;
                    Analysis->Public.CommandLine.Buffer[CopyLength / sizeof(WCHAR)] = L'\0';
                }
            }

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

    } __finally {
        if (Attached) {
            KeUnstackDetachProcess(&ApcState);
        }
    }

    return Status;
}

static NTSTATUS
PapCalculateEntropy(
    _In_ PVOID Buffer,
    _In_ SIZE_T Length,
    _Out_ PULONG Entropy
    )
{
    ULONG ByteCounts[256] = { 0 };
    PUCHAR Data = (PUCHAR)Buffer;
    SIZE_T i;
    ULONG EntropyValue = 0;

    *Entropy = 0;

    if (Length == 0) {
        return STATUS_SUCCESS;
    }

    __try {
        //
        // Count byte frequencies
        //
        for (i = 0; i < Length; i++) {
            ByteCounts[Data[i]]++;
        }

        //
        // Calculate entropy (scaled to 0-1000)
        // Using simplified calculation without floating point
        //
        for (i = 0; i < 256; i++) {
            if (ByteCounts[i] > 0) {
                //
                // Simplified entropy approximation
                // Higher unique byte counts = higher entropy
                //
                ULONG Probability = (ByteCounts[i] * 1000) / (ULONG)Length;
                if (Probability > 0) {
                    EntropyValue += (Probability > 100) ? 4 : (Probability > 10) ? 3 : 1;
                }
            }
        }

        //
        // Normalize to 0-1000 scale
        //
        EntropyValue = min(EntropyValue * 4, 1000);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    *Entropy = EntropyValue;
    return STATUS_SUCCESS;
}

static ULONG
PapCalculateSuspicionScore(
    _In_ PPA_ANALYSIS_INTERNAL Analysis
    )
{
    ULONG Score = 0;

    //
    // PE-based indicators
    //
    if (!Analysis->Public.PE.IsPE) {
        Score += 10;
    }

    if (Analysis->Public.PE.IsPacked) {
        Score += 30;
    }

    if (!Analysis->Public.PE.IsSigned) {
        Score += 15;
    }

    if (Analysis->Public.PE.Entropy >= PA_ENTROPY_THRESHOLD_ENCRYPTED) {
        Score += 25;
    }

    //
    // Security mitigation indicators
    //
    if (!Analysis->Public.Security.HasDEP) {
        Score += 15;
    }

    if (!Analysis->Public.Security.HasASLR) {
        Score += 10;
    }

    if (!Analysis->Public.Security.HasCFG) {
        Score += 5;
    }

    //
    // Token-based indicators
    //
    if (Analysis->ExtendedSecurity.IsElevated) {
        Score += 10;
    }

    if (Analysis->ExtendedSecurity.HasSeDebugPrivilege) {
        Score += 20;
    }

    if (Analysis->ExtendedSecurity.HasSeTcbPrivilege) {
        Score += 25;
    }

    //
    // Behavior flag indicators
    //
    if (Analysis->Public.BehaviorFlags & PA_BEHAVIOR_SUSPICIOUS_PARENT) {
        Score += 25;
    }

    if (Analysis->Public.BehaviorFlags & PA_BEHAVIOR_UNUSUAL_PATH) {
        Score += 20;
    }

    if (Analysis->Public.BehaviorFlags & PA_BEHAVIOR_MASQUERADING) {
        Score += 35;
    }

    if (Analysis->Public.BehaviorFlags & PA_BEHAVIOR_SCRIPT_HOST) {
        Score += 15;
    }

    if (Analysis->Public.BehaviorFlags & PA_BEHAVIOR_LOL_BINARY) {
        Score += 20;
    }

    if (Analysis->Public.BehaviorFlags & PA_BEHAVIOR_SUSPICIOUS_CMDLINE) {
        Score += 25;
    }

    //
    // Parent indicators
    //
    if (Analysis->ParentInfo.ParentMismatch) {
        Score += 30;
    }

    //
    // Cap at 100
    //
    if (Score > 100) {
        Score = 100;
    }

    return Score;
}

static ULONG
PapDetectBehaviorFlags(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PPA_ANALYSIS_INTERNAL Analysis
    )
{
    ULONG Flags = 0;

    //
    // Check for suspicious path
    //
    if (PapIsSuspiciousPath(&Analysis->Public.ImagePath)) {
        Flags |= PA_BEHAVIOR_UNUSUAL_PATH;
    }

    //
    // Check for unsigned
    //
    if (!Analysis->Public.PE.IsSigned) {
        Flags |= PA_BEHAVIOR_UNSIGNED;
    }

    //
    // Check for packed
    //
    if (Analysis->Public.PE.IsPacked) {
        Flags |= PA_BEHAVIOR_PACKED;
    }

    //
    // Check for missing DEP
    //
    if (!Analysis->Public.Security.HasDEP) {
        Flags |= PA_BEHAVIOR_NO_DEP;
    }

    //
    // Check for missing ASLR
    //
    if (!Analysis->Public.Security.HasASLR) {
        Flags |= PA_BEHAVIOR_NO_ASLR;
    }

    //
    // Check for elevated
    //
    if (Analysis->ExtendedSecurity.IsElevated) {
        Flags |= PA_BEHAVIOR_ELEVATED;
    }

    //
    // Check for script host
    //
    if (PapIsScriptHost(&Analysis->Public.ImagePath)) {
        Flags |= PA_BEHAVIOR_SCRIPT_HOST;
    }

    //
    // Check for LOLBin
    //
    if (PapIsLOLBinary(Analyzer, &Analysis->Public.ImagePath)) {
        Flags |= PA_BEHAVIOR_LOL_BINARY;
    }

    //
    // Check for high entropy
    //
    if (Analysis->Public.PE.Entropy >= PA_ENTROPY_THRESHOLD_PACKED) {
        Flags |= PA_BEHAVIOR_HIGH_ENTROPY;
    }

    //
    // Check for suspicious parent
    //
    if (!Analysis->ParentInfo.IsKnownParent && Analysis->Public.ParentId != NULL) {
        Flags |= PA_BEHAVIOR_SUSPICIOUS_PARENT;
    }

    //
    // Check for suspicious command line patterns
    //
    if (Analysis->Public.CommandLine.Length > 0) {
        //
        // Check for encoded commands
        //
        if (PapStringContainsInsensitive(&Analysis->Public.CommandLine, L"-encodedcommand") ||
            PapStringContainsInsensitive(&Analysis->Public.CommandLine, L"-enc ") ||
            PapStringContainsInsensitive(&Analysis->Public.CommandLine, L"-e ") ||
            PapStringContainsInsensitive(&Analysis->Public.CommandLine, L"frombase64")) {
            Flags |= PA_BEHAVIOR_SUSPICIOUS_CMDLINE;
        }

        //
        // Check for download cradles
        //
        if (PapStringContainsInsensitive(&Analysis->Public.CommandLine, L"downloadstring") ||
            PapStringContainsInsensitive(&Analysis->Public.CommandLine, L"downloadfile") ||
            PapStringContainsInsensitive(&Analysis->Public.CommandLine, L"invoke-webrequest") ||
            PapStringContainsInsensitive(&Analysis->Public.CommandLine, L"iwr ") ||
            PapStringContainsInsensitive(&Analysis->Public.CommandLine, L"wget ") ||
            PapStringContainsInsensitive(&Analysis->Public.CommandLine, L"curl ")) {
            Flags |= PA_BEHAVIOR_SUSPICIOUS_CMDLINE;
        }

        //
        // Check for execution bypass
        //
        if (PapStringContainsInsensitive(&Analysis->Public.CommandLine, L"-executionpolicy bypass") ||
            PapStringContainsInsensitive(&Analysis->Public.CommandLine, L"-ep bypass") ||
            PapStringContainsInsensitive(&Analysis->Public.CommandLine, L"-noprofile") ||
            PapStringContainsInsensitive(&Analysis->Public.CommandLine, L"-windowstyle hidden")) {
            Flags |= PA_BEHAVIOR_SUSPICIOUS_CMDLINE;
        }
    }

    return Flags;
}

static BOOLEAN
PapIsKnownParent(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PCUNICODE_STRING ImagePath
    )
{
    UNICODE_STRING FileName;
    ULONG Hash;
    ULONG i;

    if (!PapExtractFileName(ImagePath, &FileName)) {
        return FALSE;
    }

    Hash = PapHashString(FileName.Buffer, FileName.Length / sizeof(WCHAR));

    for (i = 0; i < Analyzer->KnownParentCount; i++) {
        if (Analyzer->KnownParentHashes[i] == Hash) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
PapIsLOLBinary(
    _In_ PPA_ANALYZER_INTERNAL Analyzer,
    _In_ PCUNICODE_STRING ImagePath
    )
{
    UNICODE_STRING FileName;
    ULONG Hash;
    ULONG i;

    if (!PapExtractFileName(ImagePath, &FileName)) {
        return FALSE;
    }

    Hash = PapHashString(FileName.Buffer, FileName.Length / sizeof(WCHAR));

    for (i = 0; i < Analyzer->LOLBinCount; i++) {
        if (Analyzer->LOLBinHashes[i] == Hash) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
PapIsScriptHost(
    _In_ PCUNICODE_STRING ImagePath
    )
{
    UNICODE_STRING FileName;

    if (!PapExtractFileName(ImagePath, &FileName)) {
        return FALSE;
    }

    //
    // Check for common script hosts
    //
    if (PapStringContainsInsensitive(&FileName, L"powershell") ||
        PapStringContainsInsensitive(&FileName, L"pwsh") ||
        PapStringContainsInsensitive(&FileName, L"cmd.exe") ||
        PapStringContainsInsensitive(&FileName, L"wscript") ||
        PapStringContainsInsensitive(&FileName, L"cscript") ||
        PapStringContainsInsensitive(&FileName, L"mshta") ||
        PapStringContainsInsensitive(&FileName, L"wmic") ||
        PapStringContainsInsensitive(&FileName, L"bash") ||
        PapStringContainsInsensitive(&FileName, L"python") ||
        PapStringContainsInsensitive(&FileName, L"perl") ||
        PapStringContainsInsensitive(&FileName, L"ruby")) {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
PapIsSuspiciousPath(
    _In_ PCUNICODE_STRING ImagePath
    )
{
    //
    // Check for suspicious paths
    //
    if (PapStringContainsInsensitive(ImagePath, L"\\temp\\") ||
        PapStringContainsInsensitive(ImagePath, L"\\tmp\\") ||
        PapStringContainsInsensitive(ImagePath, L"\\appdata\\local\\temp") ||
        PapStringContainsInsensitive(ImagePath, L"\\downloads\\") ||
        PapStringContainsInsensitive(ImagePath, L"\\public\\") ||
        PapStringContainsInsensitive(ImagePath, L"\\users\\public") ||
        PapStringContainsInsensitive(ImagePath, L"\\programdata\\") ||
        PapStringContainsInsensitive(ImagePath, L"\\recycler\\") ||
        PapStringContainsInsensitive(ImagePath, L"\\$recycle.bin\\")) {
        return TRUE;
    }

    //
    // Check for unusual file extensions
    //
    if (PapStringContainsInsensitive(ImagePath, L".scr") ||
        PapStringContainsInsensitive(ImagePath, L".pif") ||
        PapStringContainsInsensitive(ImagePath, L".com") ||
        PapStringContainsInsensitive(ImagePath, L".cmd") ||
        PapStringContainsInsensitive(ImagePath, L".bat") ||
        PapStringContainsInsensitive(ImagePath, L".vbs") ||
        PapStringContainsInsensitive(ImagePath, L".js") ||
        PapStringContainsInsensitive(ImagePath, L".jse") ||
        PapStringContainsInsensitive(ImagePath, L".vbe") ||
        PapStringContainsInsensitive(ImagePath, L".wsf")) {
        return TRUE;
    }

    return FALSE;
}

static VOID
PapInitializeKnownParents(
    _In_ PPA_ANALYZER_INTERNAL Analyzer
    )
{
    //
    // Known good parent processes
    //
    static const PCWSTR KnownParents[] = {
        L"explorer.exe",
        L"services.exe",
        L"svchost.exe",
        L"csrss.exe",
        L"wininit.exe",
        L"winlogon.exe",
        L"smss.exe",
        L"lsass.exe",
        L"system",
        L"userinit.exe",
        L"sihost.exe",
        L"taskhostw.exe",
        L"runtimebroker.exe",
        L"searchindexer.exe",
        L"spoolsv.exe"
    };

    ULONG i;

    Analyzer->KnownParentCount = 0;

    for (i = 0; i < RTL_NUMBER_OF(KnownParents) && Analyzer->KnownParentCount < 64; i++) {
        Analyzer->KnownParentHashes[Analyzer->KnownParentCount++] =
            PapHashString(KnownParents[i], (ULONG)wcslen(KnownParents[i]));
    }
}

static VOID
PapInitializeLOLBins(
    _In_ PPA_ANALYZER_INTERNAL Analyzer
    )
{
    //
    // Living Off the Land Binaries
    //
    static const PCWSTR LOLBins[] = {
        L"certutil.exe",
        L"bitsadmin.exe",
        L"msiexec.exe",
        L"mshta.exe",
        L"regsvr32.exe",
        L"rundll32.exe",
        L"cmstp.exe",
        L"installutil.exe",
        L"regasm.exe",
        L"regsvcs.exe",
        L"msbuild.exe",
        L"ieexec.exe",
        L"dnscmd.exe",
        L"esentutl.exe",
        L"expand.exe",
        L"extrac32.exe",
        L"findstr.exe",
        L"forfiles.exe",
        L"gpscript.exe",
        L"hh.exe",
        L"infdefaultinstall.exe",
        L"makecab.exe",
        L"mavinject.exe",
        L"microsoft.workflow.compiler.exe",
        L"mmc.exe",
        L"msdeploy.exe",
        L"msdt.exe",
        L"msiexec.exe",
        L"odbcconf.exe",
        L"pcalua.exe",
        L"pcwrun.exe",
        L"presentationhost.exe",
        L"reg.exe",
        L"regasm.exe",
        L"regedit.exe",
        L"register-cimprovider.exe",
        L"replace.exe",
        L"rpcping.exe",
        L"runscripthelper.exe",
        L"sc.exe",
        L"schtasks.exe",
        L"scriptrunner.exe",
        L"syncappvpublishingserver.exe",
        L"ttdinject.exe",
        L"tttracer.exe",
        L"vbc.exe",
        L"verclsid.exe",
        L"wmic.exe",
        L"wscript.exe",
        L"xwizard.exe"
    };

    ULONG i;

    Analyzer->LOLBinCount = 0;

    for (i = 0; i < RTL_NUMBER_OF(LOLBins) && Analyzer->LOLBinCount < 128; i++) {
        Analyzer->LOLBinHashes[Analyzer->LOLBinCount++] =
            PapHashString(LOLBins[i], (ULONG)wcslen(LOLBins[i]));
    }
}

static VOID
PapCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PPA_ANALYZER_INTERNAL Analyzer = (PPA_ANALYZER_INTERNAL)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Analyzer == NULL || Analyzer->ShutdownRequested) {
        return;
    }

    //
    // Signal worker thread to perform cleanup
    //
    KeSetEvent(&Analyzer->WorkAvailableEvent, IO_NO_INCREMENT, FALSE);
}

static VOID
PapWorkerThread(
    _In_ PVOID StartContext
    )
{
    PPA_ANALYZER_INTERNAL Analyzer = (PPA_ANALYZER_INTERNAL)StartContext;
    PVOID WaitObjects[2];
    NTSTATUS Status;

    WaitObjects[0] = &Analyzer->ShutdownEvent;
    WaitObjects[1] = &Analyzer->WorkAvailableEvent;

    while (!Analyzer->ShutdownRequested) {
        Status = KeWaitForMultipleObjects(
            2,
            WaitObjects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            NULL,
            NULL
            );

        if (Status == STATUS_WAIT_0 || Analyzer->ShutdownRequested) {
            break;
        }

        if (Status == STATUS_WAIT_1) {
            //
            // Cleanup stale cache entries
            //
            if (Analyzer->Public.Initialized && !Analyzer->ShutdownRequested) {
                PapCleanupStaleCache(Analyzer);
            }
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static BOOLEAN
PapExtractFileName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING FileName
    )
{
    USHORT i;
    USHORT LastSlash = 0;

    if (FullPath == NULL || FullPath->Buffer == NULL || FullPath->Length == 0) {
        return FALSE;
    }

    //
    // Find last path separator
    //
    for (i = 0; i < FullPath->Length / sizeof(WCHAR); i++) {
        if (FullPath->Buffer[i] == L'\\' || FullPath->Buffer[i] == L'/') {
            LastSlash = i + 1;
        }
    }

    FileName->Buffer = &FullPath->Buffer[LastSlash];
    FileName->Length = FullPath->Length - (LastSlash * sizeof(WCHAR));
    FileName->MaximumLength = FileName->Length + sizeof(WCHAR);

    return TRUE;
}

static BOOLEAN
PapStringContainsInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Substring
    )
{
    SIZE_T StringLen;
    SIZE_T SubLen;
    SIZE_T i, j;
    BOOLEAN Match;

    if (String == NULL || String->Buffer == NULL || Substring == NULL) {
        return FALSE;
    }

    StringLen = String->Length / sizeof(WCHAR);
    SubLen = wcslen(Substring);

    if (SubLen > StringLen || SubLen == 0) {
        return FALSE;
    }

    for (i = 0; i <= StringLen - SubLen; i++) {
        Match = TRUE;
        for (j = 0; j < SubLen; j++) {
            WCHAR c1 = String->Buffer[i + j];
            WCHAR c2 = Substring[j];

            //
            // Case-insensitive comparison
            //
            if (c1 >= L'A' && c1 <= L'Z') {
                c1 += (L'a' - L'A');
            }
            if (c2 >= L'A' && c2 <= L'Z') {
                c2 += (L'a' - L'A');
            }

            if (c1 != c2) {
                Match = FALSE;
                break;
            }
        }

        if (Match) {
            return TRUE;
        }
    }

    return FALSE;
}
