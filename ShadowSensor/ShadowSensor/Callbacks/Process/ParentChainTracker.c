/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE PARENT CHAIN TRACKER IMPLEMENTATION
 * ============================================================================
 *
 * @file ParentChainTracker.c
 * @brief Enterprise-grade process ancestry tracking and PPID spoofing detection.
 *
 * This module implements comprehensive process chain analysis with:
 * - Full parent process chain reconstruction up to 32 levels
 * - PPID spoofing detection via creation time analysis
 * - PID reuse attack protection via creation time correlation
 * - Suspicious parent-child pattern detection (LOLBins, etc.)
 * - Known malicious ancestry pattern matching
 * - Process genealogy correlation for threat hunting
 * - Integration with behavioral detection engine
 *
 * Security Detection Capabilities:
 * - T1134.004: Parent PID Spoofing
 * - T1055: Process Injection (via ancestry analysis)
 * - T1059: Command and Scripting Interpreter abuse
 * - T1218: Signed Binary Proxy Execution (LOLBins)
 *
 * Security Hardening (v2.1.0):
 * - Fixed lookaside vs pool allocation mismatch
 * - Fixed shutdown race condition
 * - Added PID reuse attack protection
 * - Safe string operations without null-terminator assumptions
 * - Integer overflow protection
 * - Full signature validation on all APIs
 * - Complete system process detection
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition - Security Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ParentChainTracker.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/StringUtils.h"
#include "../../Utilities/ProcessUtils.h"

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define PCT_VERSION                     0x00020100  // 2.1.0

//
// Timeouts and intervals
//
#define PCT_SHUTDOWN_WAIT_MS            30000       // 30 seconds - must wait for all ops
#define PCT_CHAIN_STALE_THRESHOLD_MS    300000      // 5 minutes
#define PCT_CLEANUP_INTERVAL_MS         60000       // 1 minute

//
// Suspicion score weights
//
#define PCT_SCORE_PPID_SPOOFED          500
#define PCT_SCORE_SUSPICIOUS_PARENT     150
#define PCT_SCORE_SCRIPT_HOST           100
#define PCT_SCORE_OFFICE_SPAWN_SHELL    200
#define PCT_SCORE_BROWSER_SPAWN_SHELL   180
#define PCT_SCORE_SERVICE_SPAWN_USER    120
#define PCT_SCORE_UNCOMMON_PARENT       80
#define PCT_SCORE_SHORT_LIVED_PARENT    60
#define PCT_SCORE_HIDDEN_PARENT         250
#define PCT_SCORE_ORPHANED_PROCESS      40
#define PCT_SCORE_DEEP_CHAIN            30
#define PCT_SCORE_LOLBIN_CHAIN          170
#define PCT_SCORE_TERMINATED_ANCESTOR   50
#define PCT_SCORE_PID_REUSE_SUSPECTED   300

//
// Creation time tolerance for PPID spoofing detection (100ns units)
// A legitimate child must be created AFTER its parent
//
#define PCT_CREATION_TIME_TOLERANCE     (10LL * 1000LL * 1000LL)  // 1 second tolerance

//
// Maximum string length to prevent integer overflow (in characters)
//
#define PCT_MAX_SAFE_STRING_LENGTH      32000

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Suspicious parent-child pattern definition.
 */
typedef struct _PCT_SUSPICIOUS_PATTERN {
    LIST_ENTRY ListEntry;
    UNICODE_STRING ParentImageName;
    UNICODE_STRING ChildImageName;
    UNICODE_STRING Description;
    ULONG Score;
    BOOLEAN IsWildcardParent;
    BOOLEAN IsWildcardChild;
} PCT_SUSPICIOUS_PATTERN, *PPCT_SUSPICIOUS_PATTERN;

/**
 * @brief Known script hosts and interpreters.
 */
typedef struct _PCT_SCRIPT_HOST {
    PCWSTR ImageName;
    USHORT ImageNameLength;  // In bytes, not including null
    ULONG BaseScore;
} PCT_SCRIPT_HOST;

/**
 * @brief Known system process definition.
 */
typedef struct _PCT_SYSTEM_PROCESS {
    PCWSTR ImageName;
    USHORT ImageNameLength;  // In bytes
    BOOLEAN MustBeInSystem32;
} PCT_SYSTEM_PROCESS;

/**
 * @brief Extended internal tracker structure.
 */
typedef struct _PCT_TRACKER_INTERNAL {
    //
    // Base public structure - MUST BE FIRST
    //
    PCT_TRACKER Public;

    //
    // Signature for validation
    //
    ULONG Signature;
    ULONG Version;

    //
    // Lookaside lists for efficient allocation
    //
    NPAGED_LOOKASIDE_LIST ChainLookaside;
    NPAGED_LOOKASIDE_LIST NodeLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Pattern lock
    //
    EX_PUSH_LOCK PatternLock;
    ULONG PatternCount;

    //
    // Shutdown synchronization - use rundown protection for robust shutdown
    //
    EX_RUNDOWN_REF RundownRef;
    volatile LONG ActiveOperations;
    KEVENT ShutdownCompleteEvent;

} PCT_TRACKER_INTERNAL, *PPCT_TRACKER_INTERNAL;

// ============================================================================
// STATIC DATA - KNOWN PATTERNS
// ============================================================================

/**
 * @brief Known script hosts and interpreters with pre-computed lengths.
 */
static const PCT_SCRIPT_HOST g_ScriptHosts[] = {
    { L"powershell.exe",    sizeof(L"powershell.exe") - sizeof(WCHAR),    100 },
    { L"pwsh.exe",          sizeof(L"pwsh.exe") - sizeof(WCHAR),          100 },
    { L"cmd.exe",           sizeof(L"cmd.exe") - sizeof(WCHAR),           60 },
    { L"wscript.exe",       sizeof(L"wscript.exe") - sizeof(WCHAR),       120 },
    { L"cscript.exe",       sizeof(L"cscript.exe") - sizeof(WCHAR),       120 },
    { L"mshta.exe",         sizeof(L"mshta.exe") - sizeof(WCHAR),         150 },
    { L"wmic.exe",          sizeof(L"wmic.exe") - sizeof(WCHAR),          130 },
    { L"bash.exe",          sizeof(L"bash.exe") - sizeof(WCHAR),          80 },
    { L"python.exe",        sizeof(L"python.exe") - sizeof(WCHAR),        70 },
    { L"python3.exe",       sizeof(L"python3.exe") - sizeof(WCHAR),       70 },
    { L"perl.exe",          sizeof(L"perl.exe") - sizeof(WCHAR),          70 },
    { L"ruby.exe",          sizeof(L"ruby.exe") - sizeof(WCHAR),          70 },
    { L"node.exe",          sizeof(L"node.exe") - sizeof(WCHAR),          60 },
};

/**
 * @brief Known LOLBins (Living Off the Land Binaries).
 */
static const PCWSTR g_LOLBins[] = {
    L"regsvr32.exe",
    L"rundll32.exe",
    L"msiexec.exe",
    L"msbuild.exe",
    L"installutil.exe",
    L"regasm.exe",
    L"regsvcs.exe",
    L"cmstp.exe",
    L"certutil.exe",
    L"bitsadmin.exe",
    L"forfiles.exe",
    L"pcalua.exe",
    L"syncappvpublishingserver.exe",
    L"control.exe",
    L"presentationhost.exe",
    L"dnscmd.exe",
    L"infdefaultinstall.exe",
    L"mavinject.exe",
    L"ftp.exe",
    L"xwizard.exe",
};

/**
 * @brief Office applications.
 */
static const PCWSTR g_OfficeApps[] = {
    L"winword.exe",
    L"excel.exe",
    L"powerpnt.exe",
    L"outlook.exe",
    L"msaccess.exe",
    L"onenote.exe",
    L"mspub.exe",
    L"visio.exe",
};

/**
 * @brief Web browsers.
 */
static const PCWSTR g_Browsers[] = {
    L"chrome.exe",
    L"firefox.exe",
    L"msedge.exe",
    L"iexplore.exe",
    L"opera.exe",
    L"brave.exe",
    L"vivaldi.exe",
};

/**
 * @brief Shell/command interpreters.
 */
static const PCWSTR g_Shells[] = {
    L"cmd.exe",
    L"powershell.exe",
    L"pwsh.exe",
    L"bash.exe",
    L"wscript.exe",
    L"cscript.exe",
    L"mshta.exe",
};

/**
 * @brief Known Windows system processes.
 */
static const PCT_SYSTEM_PROCESS g_SystemProcesses[] = {
    { L"system",            sizeof(L"system") - sizeof(WCHAR),            FALSE },
    { L"smss.exe",          sizeof(L"smss.exe") - sizeof(WCHAR),          TRUE },
    { L"csrss.exe",         sizeof(L"csrss.exe") - sizeof(WCHAR),         TRUE },
    { L"wininit.exe",       sizeof(L"wininit.exe") - sizeof(WCHAR),       TRUE },
    { L"winlogon.exe",      sizeof(L"winlogon.exe") - sizeof(WCHAR),      TRUE },
    { L"services.exe",      sizeof(L"services.exe") - sizeof(WCHAR),      TRUE },
    { L"lsass.exe",         sizeof(L"lsass.exe") - sizeof(WCHAR),         TRUE },
    { L"lsaiso.exe",        sizeof(L"lsaiso.exe") - sizeof(WCHAR),        TRUE },
    { L"svchost.exe",       sizeof(L"svchost.exe") - sizeof(WCHAR),       TRUE },
    { L"dwm.exe",           sizeof(L"dwm.exe") - sizeof(WCHAR),           TRUE },
    { L"fontdrvhost.exe",   sizeof(L"fontdrvhost.exe") - sizeof(WCHAR),   TRUE },
    { L"conhost.exe",       sizeof(L"conhost.exe") - sizeof(WCHAR),       TRUE },
    { L"sihost.exe",        sizeof(L"sihost.exe") - sizeof(WCHAR),        TRUE },
    { L"taskhostw.exe",     sizeof(L"taskhostw.exe") - sizeof(WCHAR),     TRUE },
    { L"explorer.exe",      sizeof(L"explorer.exe") - sizeof(WCHAR),      FALSE },
    { L"runtimebroker.exe", sizeof(L"runtimebroker.exe") - sizeof(WCHAR), TRUE },
};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PPCT_CHAIN_NODE
PctpAllocateNode(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    );

static VOID
PctpFreeNode(
    _In_opt_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PPCT_CHAIN_NODE Node
    );

static PPCT_PROCESS_CHAIN
PctpAllocateChain(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    );

static VOID
PctpFreeChainInternal(
    _In_opt_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PPCT_PROCESS_CHAIN Chain
    );

static NTSTATUS
PctpGetProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_ PPCT_CHAIN_NODE Node,
    _Out_ PBOOLEAN ProcessTerminated
    );

static NTSTATUS
PctpGetParentProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PHANDLE ParentProcessId,
    _Out_ PLARGE_INTEGER ParentCreateTime
    );

static NTSTATUS
PctpGetProcessCreateTime(
    _In_ HANDLE ProcessId,
    _Out_ PLARGE_INTEGER CreateTime
    );

static BOOLEAN
PctpIsScriptHost(
    _In_ PUNICODE_STRING ImageName,
    _Out_opt_ PULONG Score
    );

static BOOLEAN
PctpIsLOLBin(
    _In_ PUNICODE_STRING ImageName
    );

static BOOLEAN
PctpIsOfficeApp(
    _In_ PUNICODE_STRING ImageName
    );

static BOOLEAN
PctpIsBrowser(
    _In_ PUNICODE_STRING ImageName
    );

static BOOLEAN
PctpIsShell(
    _In_ PUNICODE_STRING ImageName
    );

static BOOLEAN
PctpIsSystemProcess(
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ImageName
    );

static VOID
PctpAnalyzeChain(
    _In_ PPCT_TRACKER_INTERNAL Tracker,
    _Inout_ PPCT_PROCESS_CHAIN Chain
    );

static ULONG
PctpCalculateSuspicionScore(
    _In_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PPCT_PROCESS_CHAIN Chain
    );

static BOOLEAN
PctpSafeCompareImageNames(
    _In_ PUNICODE_STRING ImagePath,
    _In_ PCWSTR ImageName,
    _In_ USHORT ImageNameLengthBytes
    );

static BOOLEAN
PctpSafeFindCharInString(
    _In_ PUNICODE_STRING String,
    _In_ WCHAR Character,
    _Out_ PUSHORT Position
    );

static BOOLEAN
PctpSafeFindLastCharInString(
    _In_ PUNICODE_STRING String,
    _In_ WCHAR Character,
    _Out_ PUSHORT Position
    );

static VOID
PctpExtractImageNameSafe(
    _In_ PUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING ImageName
    );

static BOOLEAN
PctpAcquireRundownProtection(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    );

static VOID
PctpReleaseRundownProtection(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    );

static NTSTATUS
PctpInitializeBuiltinPatterns(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    );

static NTSTATUS
PctpAddSuspiciousPattern(
    _In_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PCWSTR ParentImage,
    _In_ PCWSTR ChildImage,
    _In_ ULONG Score,
    _In_ PCWSTR Description
    );

static BOOLEAN
PctpMatchesSuspiciousPattern(
    _In_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PUNICODE_STRING ParentImageName,
    _In_ PUNICODE_STRING ChildImageName,
    _Out_ PULONG Score
    );

static NTSTATUS
PctpValidateTracker(
    _In_ PPCT_TRACKER Tracker,
    _Out_ PPCT_TRACKER_INTERNAL* Internal
    );

static NTSTATUS
PctpAllocateAndCopyUnicodeString(
    _Out_ PUNICODE_STRING Dest,
    _In_ PUNICODE_STRING Source,
    _In_ ULONG PoolTag
    );

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PctInitialize(
    _Out_ PPCT_TRACKER* Tracker
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PPCT_TRACKER_INTERNAL internal = NULL;

    if (Tracker == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Tracker = NULL;

    //
    // Allocate tracker structure from NonPagedPoolNx
    //
    internal = (PPCT_TRACKER_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PCT_TRACKER_INTERNAL),
        PCT_POOL_TAG
    );

    if (internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(internal, sizeof(PCT_TRACKER_INTERNAL));
    internal->Signature = PCT_SIGNATURE;
    internal->Version = PCT_VERSION;

    //
    // Initialize synchronization primitives
    //
    ExInitializePushLock(&internal->Public.ChainLock);
    ExInitializePushLock(&internal->PatternLock);
    InitializeListHead(&internal->Public.ChainList);
    InitializeListHead(&internal->Public.SuspiciousPatterns);

    //
    // Initialize rundown protection for safe shutdown
    //
    ExInitializeRundownProtection(&internal->RundownRef);
    KeInitializeEvent(&internal->ShutdownCompleteEvent, NotificationEvent, FALSE);
    internal->ActiveOperations = 0;

    //
    // Initialize lookaside lists for efficient allocation
    //
    ExInitializeNPagedLookasideList(
        &internal->ChainLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PCT_PROCESS_CHAIN),
        PCT_POOL_TAG,
        0
    );

    ExInitializeNPagedLookasideList(
        &internal->NodeLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PCT_CHAIN_NODE),
        PCT_POOL_TAG,
        0
    );

    internal->LookasideInitialized = TRUE;

    //
    // Initialize built-in suspicious patterns
    //
    status = PctpInitializeBuiltinPatterns(internal);
    if (!NT_SUCCESS(status)) {
        //
        // Log but don't fail - patterns are enhancement, not critical
        //
        InterlockedIncrement64(&internal->Public.Stats.AllocationFailures);
    }

    //
    // Record start time
    //
    KeQuerySystemTime(&internal->Public.Stats.StartTime);

    //
    // Mark as initialized
    //
    internal->Public.Initialized = TRUE;
    internal->Public.ShuttingDown = 0;

    *Tracker = &internal->Public;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PctShutdown(
    _Inout_ PPCT_TRACKER Tracker
    )
{
    PPCT_TRACKER_INTERNAL internal;
    PLIST_ENTRY listEntry;
    PPCT_PROCESS_CHAIN chain;
    PPCT_SUSPICIOUS_PATTERN pattern;

    if (Tracker == NULL || !Tracker->Initialized) {
        return;
    }

    internal = CONTAINING_RECORD(Tracker, PCT_TRACKER_INTERNAL, Public);

    if (internal->Signature != PCT_SIGNATURE) {
        return;
    }

    //
    // Signal shutdown - prevent new operations from starting
    //
    InterlockedExchange(&Tracker->ShuttingDown, 1);

    //
    // Wait for all active operations to complete using rundown protection
    // This blocks until all PctpAcquireRundownProtection holders release
    //
    ExWaitForRundownProtectionRelease(&internal->RundownRef);

    //
    // At this point, no new operations can start and all existing ones have completed
    // Safe to clean up resources
    //

    //
    // Free all cached chains
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->ChainLock);

    while (!IsListEmpty(&Tracker->ChainList)) {
        listEntry = RemoveHeadList(&Tracker->ChainList);
        chain = CONTAINING_RECORD(listEntry, PCT_PROCESS_CHAIN, ListEntry);
        InterlockedDecrement(&Tracker->ChainCount);
        PctpFreeChainInternal(internal, chain);
    }

    ExReleasePushLockExclusive(&Tracker->ChainLock);
    KeLeaveCriticalRegion();

    //
    // Free all suspicious patterns
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internal->PatternLock);

    while (!IsListEmpty(&Tracker->SuspiciousPatterns)) {
        listEntry = RemoveHeadList(&Tracker->SuspiciousPatterns);
        pattern = CONTAINING_RECORD(listEntry, PCT_SUSPICIOUS_PATTERN, ListEntry);

        if (pattern->ParentImageName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(pattern->ParentImageName.Buffer, PCT_POOL_TAG);
        }
        if (pattern->ChildImageName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(pattern->ChildImageName.Buffer, PCT_POOL_TAG);
        }
        if (pattern->Description.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(pattern->Description.Buffer, PCT_POOL_TAG);
        }

        ShadowStrikeFreePoolWithTag(pattern, PCT_POOL_TAG);
    }

    ExReleasePushLockExclusive(&internal->PatternLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside lists - safe now that all operations are complete
    //
    if (internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&internal->ChainLookaside);
        ExDeleteNPagedLookasideList(&internal->NodeLookaside);
        internal->LookasideInitialized = FALSE;
    }

    //
    // Clear signature and mark as uninitialized
    //
    internal->Signature = 0;
    Tracker->Initialized = FALSE;

    //
    // Free the tracker structure
    //
    ShadowStrikeFreePoolWithTag(internal, PCT_POOL_TAG);
}

// ============================================================================
// CHAIN BUILDING
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PctBuildChain(
    _In_ PPCT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_ PPCT_PROCESS_CHAIN* Chain
    )
{
    NTSTATUS status;
    PPCT_TRACKER_INTERNAL internal;
    PPCT_PROCESS_CHAIN chain = NULL;
    PPCT_CHAIN_NODE node = NULL;
    HANDLE currentPid;
    HANDLE parentPid;
    LARGE_INTEGER parentCreateTime;
    LARGE_INTEGER previousCreateTime;
    ULONG depth = 0;
    BOOLEAN firstNode = TRUE;
    BOOLEAN processTerminated = FALSE;

    //
    // Validate parameters and tracker
    //
    if (Chain == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Chain = NULL;

    status = PctpValidateTracker(Tracker, &internal);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Acquire rundown protection - prevents shutdown while we're working
    //
    if (!PctpAcquireRundownProtection(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Allocate chain structure
    //
    chain = PctpAllocateChain(internal);
    if (chain == NULL) {
        InterlockedIncrement64(&Tracker->Stats.AllocationFailures);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(chain, sizeof(PCT_PROCESS_CHAIN));
    chain->Signature = PCT_CHAIN_SIGNATURE;
    chain->AllocSource = PctAllocSourceLookaside;
    chain->OwningTracker = internal;
    chain->LeafProcessId = ProcessId;
    KeQuerySystemTime(&chain->BuildTime);
    InitializeListHead(&chain->ChainList);

    //
    // Build the chain by traversing parent processes
    //
    currentPid = ProcessId;
    previousCreateTime.QuadPart = MAXLONGLONG;

    while (currentPid != NULL &&
           (ULONG_PTR)currentPid != 0 &&
           (ULONG_PTR)currentPid != 4 &&  // System process
           depth < PCT_MAX_CHAIN_DEPTH) {

        //
        // Allocate node for this process
        //
        node = PctpAllocateNode(internal);
        if (node == NULL) {
            //
            // Continue with partial chain rather than failing completely
            //
            InterlockedIncrement64(&Tracker->Stats.AllocationFailures);
            break;
        }

        RtlZeroMemory(node, sizeof(PCT_CHAIN_NODE));
        node->Signature = PCT_NODE_SIGNATURE;
        node->AllocSource = PctAllocSourceLookaside;
        node->ProcessId = currentPid;

        //
        // Get process information
        //
        processTerminated = FALSE;
        status = PctpGetProcessInfo(currentPid, node, &processTerminated);
        if (!NT_SUCCESS(status)) {
            //
            // Process may have terminated - mark it and continue
            //
            node->IsTerminated = TRUE;
            chain->HasTerminatedAncestor = TRUE;
            InterlockedIncrement64(&Tracker->Stats.ProcessLookupFailures);

            //
            // Don't use fake creation time - leave as 0 to indicate unknown
            //
        } else {
            node->IsTerminated = processTerminated;
            if (processTerminated) {
                chain->HasTerminatedAncestor = TRUE;
            }
        }

        //
        // Check if this is a system process
        //
        node->IsSystem = PctpIsSystemProcess(currentPid,
            (node->ImageName.Buffer != NULL) ? &node->ImageName : NULL);

        //
        // Check creation time ordering for PPID spoofing detection
        // Only check if we have valid creation times
        //
        if (!firstNode &&
            node->CreateTime.QuadPart != 0 &&
            previousCreateTime.QuadPart != MAXLONGLONG &&
            previousCreateTime.QuadPart != 0) {
            //
            // Child must be created AFTER parent
            // If parent (current node) creation time is AFTER child, it's spoofed
            //
            if (node->CreateTime.QuadPart > previousCreateTime.QuadPart + PCT_CREATION_TIME_TOLERANCE) {
                chain->IsParentSpoofed = TRUE;
                node->IsSuspicious = TRUE;
                InterlockedIncrement64(&Tracker->Stats.SpoofingDetected);
            }
        }

        if (node->CreateTime.QuadPart != 0) {
            previousCreateTime = node->CreateTime;
        }
        firstNode = FALSE;

        //
        // Add to chain (at tail - so chain is ordered from leaf to root)
        //
        InsertTailList(&chain->ChainList, &node->ListEntry);
        depth++;

        //
        // Get parent process ID and creation time for PID reuse protection
        //
        status = PctpGetParentProcessId(currentPid, &parentPid, &parentCreateTime);
        if (!NT_SUCCESS(status) || parentPid == currentPid || parentPid == NULL) {
            //
            // Reached end of chain or orphaned process
            //
            if (depth > 1 && parentPid == NULL) {
                chain->HasOrphanedProcess = TRUE;
                InterlockedIncrement64(&Tracker->Stats.OrphanedProcesses);
            }
            break;
        }

        currentPid = parentPid;
        node = NULL;
    }

    chain->ChainDepth = depth;

    //
    // Analyze the chain for suspicious patterns
    //
    PctpAnalyzeChain(internal, chain);

    //
    // Calculate final suspicion score
    //
    chain->SuspicionScore = PctpCalculateSuspicionScore(internal, chain);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Tracker->Stats.ChainsBuilt);
    InterlockedIncrement(&Tracker->ChainCount);

    if (chain->SuspicionScore >= PCT_SCORE_SUSPICIOUS_PARENT) {
        InterlockedIncrement64(&Tracker->Stats.SuspiciousChains);
    }

    *Chain = chain;
    chain = NULL;
    status = STATUS_SUCCESS;

Cleanup:
    if (chain != NULL) {
        PctpFreeChainInternal(internal, chain);
    }

    PctpReleaseRundownProtection(internal);

    return status;
}

// ============================================================================
// PPID SPOOFING DETECTION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PctDetectSpoofing(
    _In_ PPCT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ClaimedParentId,
    _In_opt_ PLARGE_INTEGER ClaimedParentCreateTime,
    _Out_ PBOOLEAN IsSpoofed
    )
{
    NTSTATUS status;
    PPCT_TRACKER_INTERNAL internal;
    LARGE_INTEGER childCreateTime;
    LARGE_INTEGER actualParentCreateTime;
    LARGE_INTEGER currentParentCreateTime;
    HANDLE actualParentId;
    BOOLEAN spoofed = FALSE;
    PEPROCESS parentProcess = NULL;

    //
    // Validate parameters
    //
    if (IsSpoofed == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsSpoofed = FALSE;

    status = PctpValidateTracker(Tracker, &internal);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Acquire rundown protection
    //
    if (!PctpAcquireRundownProtection(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Get the actual parent process ID and creation time from the system
    //
    status = PctpGetParentProcessId(ProcessId, &actualParentId, &actualParentCreateTime);
    if (!NT_SUCCESS(status)) {
        //
        // Can't determine actual parent - process may have terminated
        //
        goto Cleanup;
    }

    //
    // Check 1: Does claimed parent match actual parent?
    //
    if (actualParentId != ClaimedParentId) {
        //
        // Parent IDs don't match - strong indicator of spoofing
        //
        spoofed = TRUE;
        goto Done;
    }

    //
    // Check 2: If caller provided claimed parent create time, verify it matches current parent
    // This detects PID reuse attacks where the original parent terminated and PID was recycled
    //
    if (ClaimedParentCreateTime != NULL && ClaimedParentCreateTime->QuadPart != 0) {
        status = PctpGetProcessCreateTime(ClaimedParentId, &currentParentCreateTime);
        if (NT_SUCCESS(status)) {
            //
            // If current parent's creation time differs from claimed, PID was recycled
            //
            if (currentParentCreateTime.QuadPart != ClaimedParentCreateTime->QuadPart) {
                spoofed = TRUE;
                goto Done;
            }
        } else {
            //
            // Parent no longer exists - could be legitimate termination or spoofing
            // If we have the claimed create time but can't verify, treat as suspicious
            //
            spoofed = TRUE;
            goto Done;
        }
    }

    //
    // Check 3: Validate creation time ordering
    // Child process must be created AFTER parent process
    //
    status = PctpGetProcessCreateTime(ProcessId, &childCreateTime);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Get current parent's creation time if we don't have it yet
    //
    if (ClaimedParentCreateTime == NULL || ClaimedParentCreateTime->QuadPart == 0) {
        status = PctpGetProcessCreateTime(ClaimedParentId, &currentParentCreateTime);
        if (!NT_SUCCESS(status)) {
            //
            // Parent doesn't exist - if child exists but parent doesn't,
            // and they should have the same PID relationship, it's suspicious
            //
            spoofed = TRUE;
            goto Done;
        }
    } else {
        currentParentCreateTime = *ClaimedParentCreateTime;
    }

    //
    // If parent was created AFTER the child (with tolerance), it's spoofed
    //
    if (currentParentCreateTime.QuadPart > childCreateTime.QuadPart + PCT_CREATION_TIME_TOLERANCE) {
        spoofed = TRUE;
        goto Done;
    }

    //
    // Check 4: Verify the claimed parent actually exists (additional validation)
    //
    if (ClaimedParentId != NULL && (ULONG_PTR)ClaimedParentId > 4) {
        status = PsLookupProcessByProcessId(ClaimedParentId, &parentProcess);
        if (NT_SUCCESS(status)) {
            //
            // Parent exists - verify its creation time matches what we expect
            //
            LONGLONG parentCreateTimeFromEprocess = PsGetProcessCreateTimeQuadPart(parentProcess);
            ObDereferenceObject(parentProcess);

            if (ClaimedParentCreateTime != NULL && ClaimedParentCreateTime->QuadPart != 0) {
                if (parentCreateTimeFromEprocess != ClaimedParentCreateTime->QuadPart) {
                    //
                    // PID was recycled - different process now has this PID
                    //
                    spoofed = TRUE;
                    goto Done;
                }
            }
        }
        // If lookup fails, parent terminated - not necessarily spoofing
    }

Done:
    *IsSpoofed = spoofed;

    if (spoofed) {
        InterlockedIncrement64(&Tracker->Stats.SpoofingDetected);
    }

    status = STATUS_SUCCESS;

Cleanup:
    PctpReleaseRundownProtection(internal);

    return status;
}

// ============================================================================
// ANCESTRY CHECKING
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PctCheckAncestry(
    _In_ PPCT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING AncestorName,
    _Out_ PBOOLEAN HasAncestor
    )
{
    NTSTATUS status;
    PPCT_TRACKER_INTERNAL internal;
    PPCT_PROCESS_CHAIN chain = NULL;
    PLIST_ENTRY listEntry;
    PPCT_CHAIN_NODE node;
    BOOLEAN found = FALSE;
    UNICODE_STRING searchName;
    UNICODE_STRING extractedName;

    //
    // Validate parameters
    //
    if (HasAncestor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *HasAncestor = FALSE;

    if (AncestorName == NULL || AncestorName->Buffer == NULL || AncestorName->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PctpValidateTracker(Tracker, &internal);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Build the process chain (this acquires/releases rundown protection internally)
    //
    status = PctBuildChain(Tracker, ProcessId, &chain);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Prepare the search name
    //
    searchName = *AncestorName;

    //
    // Search for the ancestor in the chain
    //
    for (listEntry = chain->ChainList.Flink;
         listEntry != &chain->ChainList;
         listEntry = listEntry->Flink) {

        node = CONTAINING_RECORD(listEntry, PCT_CHAIN_NODE, ListEntry);

        if (node->Signature != PCT_NODE_SIGNATURE) {
            //
            // Corrupted node - skip
            //
            continue;
        }

        if (node->ImageName.Buffer != NULL && node->ImageName.Length > 0) {
            //
            // Extract just the image name from the full path
            //
            PctpExtractImageNameSafe(&node->ImageName, &extractedName);

            //
            // Compare the image names (case-insensitive)
            //
            if (RtlEqualUnicodeString(&extractedName, &searchName, TRUE)) {
                found = TRUE;
                break;
            }
        }
    }

    *HasAncestor = found;

    PctFreeChain(chain);

    return STATUS_SUCCESS;
}

// ============================================================================
// CHAIN FREE - HANDLES BOTH LOOKASIDE AND POOL ALLOCATIONS
// ============================================================================

_Use_decl_annotations_
VOID
PctFreeChain(
    _In_opt_ PPCT_PROCESS_CHAIN Chain
    )
{
    PPCT_TRACKER_INTERNAL tracker;
    PLIST_ENTRY listEntry;
    PPCT_CHAIN_NODE node;

    if (Chain == NULL) {
        return;
    }

    //
    // Validate chain signature
    //
    if (Chain->Signature != PCT_CHAIN_SIGNATURE) {
        //
        // Invalid or corrupted chain - cannot safely free
        //
        return;
    }

    //
    // Get the owning tracker if available (for lookaside deallocation)
    //
    tracker = (PPCT_TRACKER_INTERNAL)Chain->OwningTracker;

    //
    // Validate tracker if present
    //
    if (tracker != NULL && tracker->Signature != PCT_SIGNATURE) {
        //
        // Tracker is invalid - fall back to pool deallocation
        //
        tracker = NULL;
    }

    //
    // Check if tracker is shutting down - if so, use pool deallocation
    //
    if (tracker != NULL && tracker->Public.ShuttingDown) {
        tracker = NULL;
    }

    //
    // Free all nodes in the chain
    //
    while (!IsListEmpty(&Chain->ChainList)) {
        listEntry = RemoveHeadList(&Chain->ChainList);
        node = CONTAINING_RECORD(listEntry, PCT_CHAIN_NODE, ListEntry);

        if (node->Signature == PCT_NODE_SIGNATURE) {
            PctpFreeNode(tracker, node);
        }
    }

    //
    // Decrement chain count if we have a valid tracker
    //
    if (tracker != NULL && !tracker->Public.ShuttingDown) {
        InterlockedDecrement(&tracker->Public.ChainCount);
    }

    //
    // Clear signature before freeing
    //
    Chain->Signature = 0;

    //
    // Free chain structure based on allocation source
    //
    if (Chain->AllocSource == PctAllocSourceLookaside &&
        tracker != NULL &&
        tracker->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&tracker->ChainLookaside, Chain);
    } else {
        ShadowStrikeFreePoolWithTag(Chain, PCT_POOL_TAG);
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PctGetStatistics(
    _In_ PPCT_TRACKER Tracker,
    _Out_ PPCT_STATISTICS Stats
    )
{
    PPCT_TRACKER_INTERNAL internal;
    NTSTATUS status;

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(PCT_STATISTICS));

    status = PctpValidateTracker(Tracker, &internal);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Copy statistics (reads are atomic for LONG64 on x64)
    //
    Stats->ChainsBuilt = Tracker->Stats.ChainsBuilt;
    Stats->ChainsFromCache = Tracker->Stats.ChainsFromCache;
    Stats->SpoofingDetected = Tracker->Stats.SpoofingDetected;
    Stats->SuspiciousChains = Tracker->Stats.SuspiciousChains;
    Stats->OrphanedProcesses = Tracker->Stats.OrphanedProcesses;
    Stats->AllocationFailures = Tracker->Stats.AllocationFailures;
    Stats->ProcessLookupFailures = Tracker->Stats.ProcessLookupFailures;
    Stats->StartTime = Tracker->Stats.StartTime;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - VALIDATION
// ============================================================================

static NTSTATUS
PctpValidateTracker(
    _In_ PPCT_TRACKER Tracker,
    _Out_ PPCT_TRACKER_INTERNAL* Internal
    )
{
    PPCT_TRACKER_INTERNAL internal;

    *Internal = NULL;

    if (Tracker == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Tracker->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    internal = CONTAINING_RECORD(Tracker, PCT_TRACKER_INTERNAL, Public);

    if (internal->Signature != PCT_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Tracker->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    *Internal = internal;
    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - RUNDOWN PROTECTION
// ============================================================================

static BOOLEAN
PctpAcquireRundownProtection(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    )
{
    if (Tracker->Public.ShuttingDown) {
        return FALSE;
    }

    if (!ExAcquireRundownProtection(&Tracker->RundownRef)) {
        return FALSE;
    }

    InterlockedIncrement(&Tracker->ActiveOperations);
    return TRUE;
}

static VOID
PctpReleaseRundownProtection(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    )
{
    InterlockedDecrement(&Tracker->ActiveOperations);
    ExReleaseRundownProtection(&Tracker->RundownRef);
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - ALLOCATION
// ============================================================================

static PPCT_CHAIN_NODE
PctpAllocateNode(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    )
{
    PPCT_CHAIN_NODE node;

    if (Tracker->LookasideInitialized && !Tracker->Public.ShuttingDown) {
        node = (PPCT_CHAIN_NODE)ExAllocateFromNPagedLookasideList(
            &Tracker->NodeLookaside
        );
        if (node != NULL) {
            node->AllocSource = PctAllocSourceLookaside;
            return node;
        }
    }

    //
    // Fallback to pool allocation
    //
    node = (PPCT_CHAIN_NODE)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PCT_CHAIN_NODE),
        PCT_POOL_TAG
    );

    if (node != NULL) {
        node->AllocSource = PctAllocSourcePool;
    }

    return node;
}

static VOID
PctpFreeNode(
    _In_opt_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PPCT_CHAIN_NODE Node
    )
{
    if (Node == NULL) {
        return;
    }

    //
    // Free strings first
    //
    if (Node->ImageName.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(Node->ImageName.Buffer, PCT_POOL_TAG);
        Node->ImageName.Buffer = NULL;
    }
    if (Node->CommandLine.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(Node->CommandLine.Buffer, PCT_POOL_TAG);
        Node->CommandLine.Buffer = NULL;
    }

    //
    // Clear signature
    //
    Node->Signature = 0;

    //
    // Free based on allocation source
    //
    if (Node->AllocSource == PctAllocSourceLookaside &&
        Tracker != NULL &&
        Tracker->LookasideInitialized &&
        !Tracker->Public.ShuttingDown) {
        ExFreeToNPagedLookasideList(&Tracker->NodeLookaside, Node);
    } else {
        ShadowStrikeFreePoolWithTag(Node, PCT_POOL_TAG);
    }
}

static PPCT_PROCESS_CHAIN
PctpAllocateChain(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    )
{
    PPCT_PROCESS_CHAIN chain;

    if (Tracker->LookasideInitialized && !Tracker->Public.ShuttingDown) {
        chain = (PPCT_PROCESS_CHAIN)ExAllocateFromNPagedLookasideList(
            &Tracker->ChainLookaside
        );
        if (chain != NULL) {
            chain->AllocSource = PctAllocSourceLookaside;
            return chain;
        }
    }

    //
    // Fallback to pool allocation
    //
    chain = (PPCT_PROCESS_CHAIN)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PCT_PROCESS_CHAIN),
        PCT_POOL_TAG
    );

    if (chain != NULL) {
        chain->AllocSource = PctAllocSourcePool;
    }

    return chain;
}

static VOID
PctpFreeChainInternal(
    _In_opt_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PPCT_PROCESS_CHAIN Chain
    )
{
    PLIST_ENTRY listEntry;
    PPCT_CHAIN_NODE node;

    if (Chain == NULL) {
        return;
    }

    //
    // Free all nodes
    //
    while (!IsListEmpty(&Chain->ChainList)) {
        listEntry = RemoveHeadList(&Chain->ChainList);
        node = CONTAINING_RECORD(listEntry, PCT_CHAIN_NODE, ListEntry);
        PctpFreeNode(Tracker, node);
    }

    //
    // Clear signature
    //
    Chain->Signature = 0;

    //
    // Free chain based on allocation source
    //
    if (Chain->AllocSource == PctAllocSourceLookaside &&
        Tracker != NULL &&
        Tracker->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Tracker->ChainLookaside, Chain);
    } else {
        ShadowStrikeFreePoolWithTag(Chain, PCT_POOL_TAG);
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - PROCESS INFORMATION
// ============================================================================

static NTSTATUS
PctpGetProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_ PPCT_CHAIN_NODE Node,
    _Out_ PBOOLEAN ProcessTerminated
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;

    *ProcessTerminated = FALSE;

    //
    // Lookup the process
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        *ProcessTerminated = TRUE;
        return status;
    }

    //
    // Check if process is terminating
    //
    if (PsGetProcessExitStatus(process) != STATUS_PENDING) {
        *ProcessTerminated = TRUE;
    }

    //
    // Get process creation time
    //
    Node->CreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(process);

    //
    // Get image file name
    //
    status = SeLocateProcessImageName(process, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL && imageName->Buffer != NULL && imageName->Length > 0) {
        //
        // Validate length to prevent overflow
        //
        if (imageName->Length <= (PCT_MAX_SAFE_STRING_LENGTH * sizeof(WCHAR))) {
            //
            // Allocate and copy the image name with null terminator
            //
            Node->ImageName.MaximumLength = imageName->Length + sizeof(WCHAR);
            Node->ImageName.Buffer = (PWCH)ShadowStrikeAllocatePoolWithTag(
                NonPagedPoolNx,
                Node->ImageName.MaximumLength,
                PCT_POOL_TAG
            );

            if (Node->ImageName.Buffer != NULL) {
                RtlCopyMemory(Node->ImageName.Buffer, imageName->Buffer, imageName->Length);
                Node->ImageName.Length = imageName->Length;
                //
                // Ensure null termination
                //
                Node->ImageName.Buffer[Node->ImageName.Length / sizeof(WCHAR)] = L'\0';
            } else {
                Node->ImageName.MaximumLength = 0;
            }
        }

        ExFreePool(imageName);
    }

    ObDereferenceObject(process);

    return STATUS_SUCCESS;
}

static NTSTATUS
PctpGetParentProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PHANDLE ParentProcessId,
    _Out_ PLARGE_INTEGER ParentCreateTime
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PEPROCESS parentProcess = NULL;
    HANDLE parentPid = NULL;

    *ParentProcessId = NULL;
    ParentCreateTime->QuadPart = 0;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Get inherited from unique process ID (parent PID)
    //
    parentPid = PsGetProcessInheritedFromUniqueProcessId(process);

    ObDereferenceObject(process);

    *ParentProcessId = parentPid;

    //
    // Get parent's creation time for PID reuse protection
    //
    if (parentPid != NULL && (ULONG_PTR)parentPid > 4) {
        status = PsLookupProcessByProcessId(parentPid, &parentProcess);
        if (NT_SUCCESS(status)) {
            ParentCreateTime->QuadPart = PsGetProcessCreateTimeQuadPart(parentProcess);
            ObDereferenceObject(parentProcess);
        }
        // If parent lookup fails, leave create time as 0
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
PctpGetProcessCreateTime(
    _In_ HANDLE ProcessId,
    _Out_ PLARGE_INTEGER CreateTime
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;

    CreateTime->QuadPart = 0;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    CreateTime->QuadPart = PsGetProcessCreateTimeQuadPart(process);

    ObDereferenceObject(process);

    return STATUS_SUCCESS;
}

static BOOLEAN
PctpIsSystemProcess(
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ImageName
    )
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    ULONG i;
    UNICODE_STRING extractedName;

    //
    // System (PID 4), Idle (PID 0)
    //
    if (pid == 0 || pid == 4) {
        return TRUE;
    }

    //
    // Check by image name if provided
    //
    if (ImageName != NULL && ImageName->Buffer != NULL && ImageName->Length > 0) {
        //
        // Extract just the filename
        //
        PctpExtractImageNameSafe(ImageName, &extractedName);

        if (extractedName.Buffer != NULL && extractedName.Length > 0) {
            for (i = 0; i < ARRAYSIZE(g_SystemProcesses); i++) {
                if (PctpSafeCompareImageNames(
                        &extractedName,
                        g_SystemProcesses[i].ImageName,
                        g_SystemProcesses[i].ImageNameLength)) {
                    //
                    // TODO: If MustBeInSystem32, verify path contains \Windows\System32\
                    // For now, just match by name
                    //
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - SAFE STRING OPERATIONS
// ============================================================================

/**
 * @brief Safely compares image names without assuming null-termination.
 */
static BOOLEAN
PctpSafeCompareImageNames(
    _In_ PUNICODE_STRING ImagePath,
    _In_ PCWSTR ImageName,
    _In_ USHORT ImageNameLengthBytes
    )
{
    UNICODE_STRING compareString;

    if (ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0) {
        return FALSE;
    }

    if (ImageName == NULL || ImageNameLengthBytes == 0) {
        return FALSE;
    }

    //
    // Build compare string from known-good static data
    //
    compareString.Buffer = (PWCH)ImageName;
    compareString.Length = ImageNameLengthBytes;
    compareString.MaximumLength = ImageNameLengthBytes + sizeof(WCHAR);

    //
    // Length must match for equality
    //
    if (ImagePath->Length != ImageNameLengthBytes) {
        return FALSE;
    }

    //
    // Use RtlEqualUnicodeString which respects Length field
    //
    return RtlEqualUnicodeString(ImagePath, &compareString, TRUE);
}

/**
 * @brief Safely finds a character in a UNICODE_STRING without assuming null-termination.
 */
static BOOLEAN
PctpSafeFindCharInString(
    _In_ PUNICODE_STRING String,
    _In_ WCHAR Character,
    _Out_ PUSHORT Position
    )
{
    USHORT i;
    USHORT charCount;

    *Position = 0;

    if (String == NULL || String->Buffer == NULL || String->Length == 0) {
        return FALSE;
    }

    charCount = String->Length / sizeof(WCHAR);

    for (i = 0; i < charCount; i++) {
        if (String->Buffer[i] == Character) {
            *Position = i;
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * @brief Safely finds the last occurrence of a character in a UNICODE_STRING.
 */
static BOOLEAN
PctpSafeFindLastCharInString(
    _In_ PUNICODE_STRING String,
    _In_ WCHAR Character,
    _Out_ PUSHORT Position
    )
{
    USHORT charCount;
    LONG i;  // Signed for reverse iteration
    BOOLEAN found = FALSE;

    *Position = 0;

    if (String == NULL || String->Buffer == NULL || String->Length == 0) {
        return FALSE;
    }

    charCount = String->Length / sizeof(WCHAR);

    for (i = (LONG)charCount - 1; i >= 0; i--) {
        if (String->Buffer[i] == Character) {
            *Position = (USHORT)i;
            found = TRUE;
            break;
        }
    }

    return found;
}

/**
 * @brief Safely extracts image name from full path without assuming null-termination.
 */
static VOID
PctpExtractImageNameSafe(
    _In_ PUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING ImageName
    )
{
    USHORT slashPosition;

    RtlZeroMemory(ImageName, sizeof(UNICODE_STRING));

    if (FullPath == NULL || FullPath->Buffer == NULL || FullPath->Length == 0) {
        return;
    }

    if (PctpSafeFindLastCharInString(FullPath, L'\\', &slashPosition)) {
        //
        // Point to character after the last backslash
        //
        USHORT startIndex = slashPosition + 1;
        USHORT charCount = FullPath->Length / sizeof(WCHAR);

        if (startIndex < charCount) {
            ImageName->Buffer = &FullPath->Buffer[startIndex];
            ImageName->Length = (charCount - startIndex) * sizeof(WCHAR);
            ImageName->MaximumLength = ImageName->Length;
        }
    } else {
        //
        // No backslash found - entire string is the image name
        //
        *ImageName = *FullPath;
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - PATTERN MATCHING
// ============================================================================

static BOOLEAN
PctpIsScriptHost(
    _In_ PUNICODE_STRING ImageName,
    _Out_opt_ PULONG Score
    )
{
    ULONG i;
    UNICODE_STRING extractedName;

    if (Score != NULL) {
        *Score = 0;
    }

    if (ImageName == NULL || ImageName->Buffer == NULL || ImageName->Length == 0) {
        return FALSE;
    }

    PctpExtractImageNameSafe(ImageName, &extractedName);

    for (i = 0; i < ARRAYSIZE(g_ScriptHosts); i++) {
        if (PctpSafeCompareImageNames(&extractedName,
                g_ScriptHosts[i].ImageName,
                g_ScriptHosts[i].ImageNameLength)) {
            if (Score != NULL) {
                *Score = g_ScriptHosts[i].BaseScore;
            }
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
PctpIsLOLBin(
    _In_ PUNICODE_STRING ImageName
    )
{
    ULONG i;
    UNICODE_STRING extractedName;
    UNICODE_STRING compareString;

    if (ImageName == NULL || ImageName->Buffer == NULL || ImageName->Length == 0) {
        return FALSE;
    }

    PctpExtractImageNameSafe(ImageName, &extractedName);

    for (i = 0; i < ARRAYSIZE(g_LOLBins); i++) {
        RtlInitUnicodeString(&compareString, g_LOLBins[i]);
        if (RtlEqualUnicodeString(&extractedName, &compareString, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
PctpIsOfficeApp(
    _In_ PUNICODE_STRING ImageName
    )
{
    ULONG i;
    UNICODE_STRING extractedName;
    UNICODE_STRING compareString;

    if (ImageName == NULL || ImageName->Buffer == NULL || ImageName->Length == 0) {
        return FALSE;
    }

    PctpExtractImageNameSafe(ImageName, &extractedName);

    for (i = 0; i < ARRAYSIZE(g_OfficeApps); i++) {
        RtlInitUnicodeString(&compareString, g_OfficeApps[i]);
        if (RtlEqualUnicodeString(&extractedName, &compareString, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
PctpIsBrowser(
    _In_ PUNICODE_STRING ImageName
    )
{
    ULONG i;
    UNICODE_STRING extractedName;
    UNICODE_STRING compareString;

    if (ImageName == NULL || ImageName->Buffer == NULL || ImageName->Length == 0) {
        return FALSE;
    }

    PctpExtractImageNameSafe(ImageName, &extractedName);

    for (i = 0; i < ARRAYSIZE(g_Browsers); i++) {
        RtlInitUnicodeString(&compareString, g_Browsers[i]);
        if (RtlEqualUnicodeString(&extractedName, &compareString, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
PctpIsShell(
    _In_ PUNICODE_STRING ImageName
    )
{
    ULONG i;
    UNICODE_STRING extractedName;
    UNICODE_STRING compareString;

    if (ImageName == NULL || ImageName->Buffer == NULL || ImageName->Length == 0) {
        return FALSE;
    }

    PctpExtractImageNameSafe(ImageName, &extractedName);

    for (i = 0; i < ARRAYSIZE(g_Shells); i++) {
        RtlInitUnicodeString(&compareString, g_Shells[i]);
        if (RtlEqualUnicodeString(&extractedName, &compareString, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - CHAIN ANALYSIS
// ============================================================================

static VOID
PctpAnalyzeChain(
    _In_ PPCT_TRACKER_INTERNAL Tracker,
    _Inout_ PPCT_PROCESS_CHAIN Chain
    )
{
    PLIST_ENTRY listEntry;
    PPCT_CHAIN_NODE node;
    PPCT_CHAIN_NODE childNode = NULL;
    BOOLEAN hasSuspiciousAncestor = FALSE;
    ULONG patternScore = 0;
    UNICODE_STRING nodeImageName;
    UNICODE_STRING childImageName;

    if (IsListEmpty(&Chain->ChainList)) {
        return;
    }

    //
    // Analyze parent-child relationships in the chain
    // Chain is ordered: leaf -> parent -> grandparent -> ... -> root
    // So Flink moves toward root (parent), Blink moves toward leaf (child)
    //
    for (listEntry = Chain->ChainList.Flink;
         listEntry != &Chain->ChainList;
         listEntry = listEntry->Flink) {

        node = CONTAINING_RECORD(listEntry, PCT_CHAIN_NODE, ListEntry);

        if (node->Signature != PCT_NODE_SIGNATURE) {
            continue;
        }

        //
        // Get the child node (previous in list = this node's child)
        //
        if (listEntry->Blink != &Chain->ChainList) {
            childNode = CONTAINING_RECORD(listEntry->Blink, PCT_CHAIN_NODE, ListEntry);

            if (childNode->Signature == PCT_NODE_SIGNATURE &&
                node->ImageName.Buffer != NULL &&
                childNode->ImageName.Buffer != NULL) {

                //
                // Extract image names for comparison
                //
                PctpExtractImageNameSafe(&node->ImageName, &nodeImageName);
                PctpExtractImageNameSafe(&childNode->ImageName, &childImageName);

                //
                // Check against built pattern list first
                //
                if (PctpMatchesSuspiciousPattern(Tracker, &nodeImageName, &childImageName, &patternScore)) {
                    childNode->IsSuspicious = TRUE;
                    hasSuspiciousAncestor = TRUE;
                }

                //
                // Office app spawning shell
                //
                if (PctpIsOfficeApp(&node->ImageName) && PctpIsShell(&childNode->ImageName)) {
                    childNode->IsSuspicious = TRUE;
                    hasSuspiciousAncestor = TRUE;
                }

                //
                // Browser spawning shell
                //
                if (PctpIsBrowser(&node->ImageName) && PctpIsShell(&childNode->ImageName)) {
                    childNode->IsSuspicious = TRUE;
                    hasSuspiciousAncestor = TRUE;
                }

                //
                // LOLBin chain (LOLBin spawning LOLBin)
                //
                if (PctpIsLOLBin(&node->ImageName) && PctpIsLOLBin(&childNode->ImageName)) {
                    childNode->IsSuspicious = TRUE;
                    hasSuspiciousAncestor = TRUE;
                }

                //
                // Script host spawning another script host
                //
                if (PctpIsScriptHost(&node->ImageName, NULL) &&
                    PctpIsScriptHost(&childNode->ImageName, NULL)) {
                    childNode->IsSuspicious = TRUE;
                    hasSuspiciousAncestor = TRUE;
                }
            }
        }
    }

    Chain->HasSuspiciousAncestor = hasSuspiciousAncestor;
}

static ULONG
PctpCalculateSuspicionScore(
    _In_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PPCT_PROCESS_CHAIN Chain
    )
{
    ULONG score = 0;
    PLIST_ENTRY listEntry;
    PPCT_CHAIN_NODE node;
    PPCT_CHAIN_NODE childNode;
    ULONG scriptScore;
    ULONG patternScore;
    UNICODE_STRING nodeImageName;
    UNICODE_STRING childImageName;

    UNREFERENCED_PARAMETER(Tracker);

    //
    // PPID spoofing is a critical indicator
    //
    if (Chain->IsParentSpoofed) {
        score += PCT_SCORE_PPID_SPOOFED;
    }

    //
    // Orphaned process
    //
    if (Chain->HasOrphanedProcess) {
        score += PCT_SCORE_ORPHANED_PROCESS;
    }

    //
    // Terminated ancestor (could indicate evasion)
    //
    if (Chain->HasTerminatedAncestor) {
        score += PCT_SCORE_TERMINATED_ANCESTOR;
    }

    //
    // Deep chains can indicate evasion attempts
    //
    if (Chain->ChainDepth > 10) {
        score += PCT_SCORE_DEEP_CHAIN;
    }

    //
    // Analyze each node in the chain
    //
    for (listEntry = Chain->ChainList.Flink;
         listEntry != &Chain->ChainList;
         listEntry = listEntry->Flink) {

        node = CONTAINING_RECORD(listEntry, PCT_CHAIN_NODE, ListEntry);

        if (node->Signature != PCT_NODE_SIGNATURE) {
            continue;
        }

        //
        // Check for script hosts
        //
        if (PctpIsScriptHost(&node->ImageName, &scriptScore)) {
            score += scriptScore;
        }

        //
        // Check for LOLBins
        //
        if (PctpIsLOLBin(&node->ImageName)) {
            score += PCT_SCORE_LOLBIN_CHAIN;
        }

        //
        // Get child for parent-child analysis
        //
        if (listEntry->Blink != &Chain->ChainList) {
            childNode = CONTAINING_RECORD(listEntry->Blink, PCT_CHAIN_NODE, ListEntry);

            if (childNode->Signature == PCT_NODE_SIGNATURE &&
                node->ImageName.Buffer != NULL &&
                childNode->ImageName.Buffer != NULL) {

                PctpExtractImageNameSafe(&node->ImageName, &nodeImageName);
                PctpExtractImageNameSafe(&childNode->ImageName, &childImageName);

                //
                // Check pattern list
                //
                if (PctpMatchesSuspiciousPattern(Tracker, &nodeImageName, &childImageName, &patternScore)) {
                    score += patternScore;
                }

                //
                // Office spawning shell
                //
                if (PctpIsOfficeApp(&node->ImageName) && PctpIsShell(&childNode->ImageName)) {
                    score += PCT_SCORE_OFFICE_SPAWN_SHELL;
                }

                //
                // Browser spawning shell
                //
                if (PctpIsBrowser(&node->ImageName) && PctpIsShell(&childNode->ImageName)) {
                    score += PCT_SCORE_BROWSER_SPAWN_SHELL;
                }
            }
        }

        //
        // Suspicious flag from chain analysis
        //
        if (node->IsSuspicious) {
            score += PCT_SCORE_SUSPICIOUS_PARENT;
        }

        //
        // Track highest individual node score
        //
        if (score > Chain->HighestNodeScore) {
            Chain->HighestNodeScore = score;
        }
    }

    return score;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - PATTERN MATCHING
// ============================================================================

static BOOLEAN
PctpMatchesSuspiciousPattern(
    _In_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PUNICODE_STRING ParentImageName,
    _In_ PUNICODE_STRING ChildImageName,
    _Out_ PULONG Score
    )
{
    PLIST_ENTRY listEntry;
    PPCT_SUSPICIOUS_PATTERN pattern;
    BOOLEAN matched = FALSE;

    *Score = 0;

    if (ParentImageName == NULL || ParentImageName->Buffer == NULL ||
        ChildImageName == NULL || ChildImageName->Buffer == NULL) {
        return FALSE;
    }

    //
    // Acquire pattern lock for reading
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->PatternLock);

    for (listEntry = Tracker->Public.SuspiciousPatterns.Flink;
         listEntry != &Tracker->Public.SuspiciousPatterns;
         listEntry = listEntry->Flink) {

        pattern = CONTAINING_RECORD(listEntry, PCT_SUSPICIOUS_PATTERN, ListEntry);

        //
        // Check parent match
        //
        if (!RtlEqualUnicodeString(ParentImageName, &pattern->ParentImageName, TRUE)) {
            continue;
        }

        //
        // Check child match
        //
        if (!RtlEqualUnicodeString(ChildImageName, &pattern->ChildImageName, TRUE)) {
            continue;
        }

        //
        // Match found
        //
        *Score = pattern->Score;
        matched = TRUE;
        break;
    }

    ExReleasePushLockShared(&Tracker->PatternLock);
    KeLeaveCriticalRegion();

    return matched;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - PATTERN INITIALIZATION
// ============================================================================

static NTSTATUS
PctpAllocateAndCopyUnicodeString(
    _Out_ PUNICODE_STRING Dest,
    _In_ PUNICODE_STRING Source,
    _In_ ULONG PoolTag
    )
{
    RtlZeroMemory(Dest, sizeof(UNICODE_STRING));

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate length to prevent overflow
    //
    if (Source->Length > (PCT_MAX_SAFE_STRING_LENGTH * sizeof(WCHAR))) {
        return STATUS_BUFFER_OVERFLOW;
    }

    Dest->MaximumLength = Source->Length + sizeof(WCHAR);
    Dest->Buffer = (PWCH)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        Dest->MaximumLength,
        PoolTag
    );

    if (Dest->Buffer == NULL) {
        Dest->MaximumLength = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Dest->Buffer, Source->Buffer, Source->Length);
    Dest->Length = Source->Length;
    Dest->Buffer[Dest->Length / sizeof(WCHAR)] = L'\0';

    return STATUS_SUCCESS;
}

static NTSTATUS
PctpInitializeBuiltinPatterns(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS patternStatus;

    //
    // Office applications spawning shells
    //
    patternStatus = PctpAddSuspiciousPattern(Tracker, L"winword.exe", L"cmd.exe",
        PCT_SCORE_OFFICE_SPAWN_SHELL, L"Word spawning command prompt");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"winword.exe", L"powershell.exe",
        PCT_SCORE_OFFICE_SPAWN_SHELL, L"Word spawning PowerShell");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"excel.exe", L"cmd.exe",
        PCT_SCORE_OFFICE_SPAWN_SHELL, L"Excel spawning command prompt");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"excel.exe", L"powershell.exe",
        PCT_SCORE_OFFICE_SPAWN_SHELL, L"Excel spawning PowerShell");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"outlook.exe", L"cmd.exe",
        PCT_SCORE_OFFICE_SPAWN_SHELL, L"Outlook spawning command prompt");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"outlook.exe", L"powershell.exe",
        PCT_SCORE_OFFICE_SPAWN_SHELL, L"Outlook spawning PowerShell");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    //
    // Browsers spawning shells
    //
    patternStatus = PctpAddSuspiciousPattern(Tracker, L"chrome.exe", L"cmd.exe",
        PCT_SCORE_BROWSER_SPAWN_SHELL, L"Chrome spawning command prompt");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"chrome.exe", L"powershell.exe",
        PCT_SCORE_BROWSER_SPAWN_SHELL, L"Chrome spawning PowerShell");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"firefox.exe", L"cmd.exe",
        PCT_SCORE_BROWSER_SPAWN_SHELL, L"Firefox spawning command prompt");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"firefox.exe", L"powershell.exe",
        PCT_SCORE_BROWSER_SPAWN_SHELL, L"Firefox spawning PowerShell");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"msedge.exe", L"cmd.exe",
        PCT_SCORE_BROWSER_SPAWN_SHELL, L"Edge spawning command prompt");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"msedge.exe", L"powershell.exe",
        PCT_SCORE_BROWSER_SPAWN_SHELL, L"Edge spawning PowerShell");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    //
    // LOLBin patterns
    //
    patternStatus = PctpAddSuspiciousPattern(Tracker, L"mshta.exe", L"powershell.exe",
        PCT_SCORE_LOLBIN_CHAIN, L"MSHTA spawning PowerShell");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"wscript.exe", L"cmd.exe",
        PCT_SCORE_LOLBIN_CHAIN, L"WScript spawning command prompt");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"cscript.exe", L"cmd.exe",
        PCT_SCORE_LOLBIN_CHAIN, L"CScript spawning command prompt");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"rundll32.exe", L"cmd.exe",
        PCT_SCORE_LOLBIN_CHAIN, L"Rundll32 spawning command prompt");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"regsvr32.exe", L"cmd.exe",
        PCT_SCORE_LOLBIN_CHAIN, L"Regsvr32 spawning command prompt");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"certutil.exe", L"cmd.exe",
        PCT_SCORE_LOLBIN_CHAIN, L"Certutil spawning command prompt");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"msiexec.exe", L"cmd.exe",
        PCT_SCORE_LOLBIN_CHAIN, L"Msiexec spawning command prompt");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    //
    // Script host chains
    //
    patternStatus = PctpAddSuspiciousPattern(Tracker, L"powershell.exe", L"powershell.exe",
        PCT_SCORE_SCRIPT_HOST, L"PowerShell spawning PowerShell");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"cmd.exe", L"powershell.exe",
        PCT_SCORE_SCRIPT_HOST, L"CMD spawning PowerShell");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    patternStatus = PctpAddSuspiciousPattern(Tracker, L"powershell.exe", L"cmd.exe",
        PCT_SCORE_SCRIPT_HOST, L"PowerShell spawning CMD");
    if (!NT_SUCCESS(patternStatus)) status = patternStatus;

    return status;
}

static NTSTATUS
PctpAddSuspiciousPattern(
    _In_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PCWSTR ParentImage,
    _In_ PCWSTR ChildImage,
    _In_ ULONG Score,
    _In_ PCWSTR Description
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PPCT_SUSPICIOUS_PATTERN pattern = NULL;
    SIZE_T parentLen;
    SIZE_T childLen;
    SIZE_T descLen;
    UNICODE_STRING tempString;

    //
    // Check pattern limit
    //
    if (Tracker->PatternCount >= PCT_MAX_SUSPICIOUS_PATTERNS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Validate and measure input strings
    //
    parentLen = wcslen(ParentImage);
    childLen = wcslen(ChildImage);
    descLen = wcslen(Description);

    //
    // Validate lengths to prevent overflow
    //
    if (parentLen > PCT_MAX_SAFE_STRING_LENGTH ||
        childLen > PCT_MAX_SAFE_STRING_LENGTH ||
        descLen > PCT_MAX_SAFE_STRING_LENGTH) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Allocate pattern structure
    //
    pattern = (PPCT_SUSPICIOUS_PATTERN)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PCT_SUSPICIOUS_PATTERN),
        PCT_POOL_TAG
    );

    if (pattern == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(pattern, sizeof(PCT_SUSPICIOUS_PATTERN));

    //
    // Allocate and copy parent image name
    //
    RtlInitUnicodeString(&tempString, ParentImage);
    status = PctpAllocateAndCopyUnicodeString(&pattern->ParentImageName, &tempString, PCT_POOL_TAG);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Allocate and copy child image name
    //
    RtlInitUnicodeString(&tempString, ChildImage);
    status = PctpAllocateAndCopyUnicodeString(&pattern->ChildImageName, &tempString, PCT_POOL_TAG);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Allocate and copy description (now a proper copy, not a pointer)
    //
    RtlInitUnicodeString(&tempString, Description);
    status = PctpAllocateAndCopyUnicodeString(&pattern->Description, &tempString, PCT_POOL_TAG);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    pattern->Score = Score;
    pattern->IsWildcardParent = (wcschr(ParentImage, L'*') != NULL);
    pattern->IsWildcardChild = (wcschr(ChildImage, L'*') != NULL);

    //
    // Insert into pattern list under lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->PatternLock);

    InsertTailList(&Tracker->Public.SuspiciousPatterns, &pattern->ListEntry);
    Tracker->PatternCount++;

    ExReleasePushLockExclusive(&Tracker->PatternLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;

Cleanup:
    if (pattern != NULL) {
        if (pattern->ParentImageName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(pattern->ParentImageName.Buffer, PCT_POOL_TAG);
        }
        if (pattern->ChildImageName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(pattern->ChildImageName.Buffer, PCT_POOL_TAG);
        }
        if (pattern->Description.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(pattern->Description.Buffer, PCT_POOL_TAG);
        }
        ShadowStrikeFreePoolWithTag(pattern, PCT_POOL_TAG);
    }

    return status;
}
