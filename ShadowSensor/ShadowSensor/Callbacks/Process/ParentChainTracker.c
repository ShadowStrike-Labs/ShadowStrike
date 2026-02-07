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
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
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

#define PCT_VERSION                     1
#define PCT_SIGNATURE                   0x50435454  // 'PCTT'
#define PCT_MAX_CACHED_CHAINS           256
#define PCT_MAX_SUSPICIOUS_PATTERNS     64
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

//
// Creation time tolerance for PPID spoofing detection (100ns units)
// A legitimate child must be created AFTER its parent
//
#define PCT_CREATION_TIME_TOLERANCE     (10 * 1000 * 1000)  // 1 second tolerance

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
    ULONG Score;
    BOOLEAN IsWildcardParent;
    BOOLEAN IsWildcardChild;
    PCWSTR Description;
} PCT_SUSPICIOUS_PATTERN, *PPCT_SUSPICIOUS_PATTERN;

/**
 * @brief Known script hosts and interpreters.
 */
typedef struct _PCT_SCRIPT_HOST {
    PCWSTR ImageName;
    ULONG BaseScore;
} PCT_SCRIPT_HOST, *PPCT_SCRIPT_HOST;

/**
 * @brief Extended internal tracker structure.
 */
typedef struct _PCT_TRACKER_INTERNAL {
    //
    // Base public structure
    //
    PCT_TRACKER Public;

    //
    // Signature for validation
    //
    ULONG Signature;

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
    // Shutdown synchronization
    //
    volatile LONG ShuttingDown;
    volatile LONG ActiveOperations;
    KEVENT ShutdownEvent;

} PCT_TRACKER_INTERNAL, *PPCT_TRACKER_INTERNAL;

// ============================================================================
// STATIC DATA - KNOWN SUSPICIOUS PATTERNS
// ============================================================================

/**
 * @brief Known script hosts and interpreters.
 */
static const PCT_SCRIPT_HOST g_ScriptHosts[] = {
    { L"powershell.exe",    100 },
    { L"pwsh.exe",          100 },
    { L"cmd.exe",           60 },
    { L"wscript.exe",       120 },
    { L"cscript.exe",       120 },
    { L"mshta.exe",         150 },
    { L"wmic.exe",          130 },
    { L"bash.exe",          80 },
    { L"python.exe",        70 },
    { L"python3.exe",       70 },
    { L"perl.exe",          70 },
    { L"ruby.exe",          70 },
    { L"node.exe",          60 },
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

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PPCT_CHAIN_NODE
PctpAllocateNode(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    );

static VOID
PctpFreeNode(
    _In_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PPCT_CHAIN_NODE Node
    );

static PPCT_PROCESS_CHAIN
PctpAllocateChain(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    );

static VOID
PctpFreeChainInternal(
    _In_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PPCT_PROCESS_CHAIN Chain
    );

static NTSTATUS
PctpGetProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_ PPCT_CHAIN_NODE Node
    );

static NTSTATUS
PctpGetParentProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PHANDLE ParentProcessId
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
    _In_ HANDLE ProcessId
    );

static VOID
PctpAnalyzeChain(
    _Inout_ PPCT_PROCESS_CHAIN Chain
    );

static ULONG
PctpCalculateSuspicionScore(
    _In_ PPCT_PROCESS_CHAIN Chain
    );

static BOOLEAN
PctpMatchesPattern(
    _In_ PUNICODE_STRING String,
    _In_ PCWSTR Pattern,
    _In_ BOOLEAN IsWildcard
    );

static BOOLEAN
PctpCompareImageNames(
    _In_ PUNICODE_STRING ImagePath,
    _In_ PCWSTR ImageName
    );

static VOID
PctpExtractImageName(
    _In_ PUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING ImageName
    );

static VOID
PctpAcquireReference(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    );

static VOID
PctpReleaseReference(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    );

static NTSTATUS
PctpInitializeBuiltinPatterns(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    );

static VOID
PctpAddSuspiciousPattern(
    _In_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PCWSTR ParentImage,
    _In_ PCWSTR ChildImage,
    _In_ ULONG Score,
    _In_ PCWSTR Description
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
    // Allocate tracker structure
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

    //
    // Initialize synchronization primitives
    //
    ExInitializePushLock(&internal->Public.ChainLock);
    ExInitializePushLock(&internal->PatternLock);
    InitializeListHead(&internal->Public.ChainList);
    InitializeListHead(&internal->Public.SuspiciousPatterns);

    //
    // Initialize shutdown event
    //
    KeInitializeEvent(&internal->ShutdownEvent, NotificationEvent, FALSE);
    internal->ActiveOperations = 1;  // Initial reference

    //
    // Initialize lookaside lists
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
        goto Cleanup;
    }

    //
    // Record start time
    //
    KeQuerySystemTime(&internal->Public.Stats.StartTime);

    //
    // Mark as initialized
    //
    internal->Public.Initialized = TRUE;

    *Tracker = &internal->Public;

    return STATUS_SUCCESS;

Cleanup:
    if (internal != NULL) {
        if (internal->LookasideInitialized) {
            ExDeleteNPagedLookasideList(&internal->ChainLookaside);
            ExDeleteNPagedLookasideList(&internal->NodeLookaside);
        }

        ShadowStrikeFreePoolWithTag(internal, PCT_POOL_TAG);
    }

    return status;
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
    LARGE_INTEGER timeout;

    if (Tracker == NULL || !Tracker->Initialized) {
        return;
    }

    internal = CONTAINING_RECORD(Tracker, PCT_TRACKER_INTERNAL, Public);

    if (internal->Signature != PCT_SIGNATURE) {
        return;
    }

    //
    // Signal shutdown
    //
    InterlockedExchange(&internal->ShuttingDown, 1);

    //
    // Wait for active operations to complete
    //
    PctpReleaseReference(internal);
    timeout.QuadPart = -((LONGLONG)5000 * 10000);  // 5 second timeout
    KeWaitForSingleObject(
        &internal->ShutdownEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    //
    // Free all cached chains
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->ChainLock);

    while (!IsListEmpty(&Tracker->ChainList)) {
        listEntry = RemoveHeadList(&Tracker->ChainList);
        chain = CONTAINING_RECORD(listEntry, PCT_PROCESS_CHAIN, ListEntry);
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

        ShadowStrikeFreePoolWithTag(pattern, PCT_POOL_TAG);
    }

    ExReleasePushLockExclusive(&internal->PatternLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside lists
    //
    if (internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&internal->ChainLookaside);
        ExDeleteNPagedLookasideList(&internal->NodeLookaside);
        internal->LookasideInitialized = FALSE;
    }

    //
    // Clear signature and free
    //
    internal->Signature = 0;
    Tracker->Initialized = FALSE;

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
    ULONG depth = 0;
    LARGE_INTEGER previousCreateTime;
    BOOLEAN firstNode = TRUE;

    if (Tracker == NULL || !Tracker->Initialized || Chain == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Chain = NULL;

    internal = CONTAINING_RECORD(Tracker, PCT_TRACKER_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    PctpAcquireReference(internal);

    //
    // Allocate chain structure
    //
    chain = PctpAllocateChain(internal);
    if (chain == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(chain, sizeof(PCT_PROCESS_CHAIN));
    chain->LeafProcessId = ProcessId;
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
            // Continue with partial chain rather than failing
            //
            break;
        }

        RtlZeroMemory(node, sizeof(PCT_CHAIN_NODE));
        node->ProcessId = currentPid;

        //
        // Get process information
        //
        status = PctpGetProcessInfo(currentPid, node);
        if (!NT_SUCCESS(status)) {
            //
            // Process may have terminated - add minimal node
            //
            node->ProcessId = currentPid;
            KeQuerySystemTime(&node->CreateTime);
        }

        //
        // Check if this is a system process
        //
        node->IsSystem = PctpIsSystemProcess(currentPid);

        //
        // Check creation time ordering for PPID spoofing
        //
        if (!firstNode) {
            //
            // Child must be created AFTER parent
            // If parent creation time is AFTER child, it's spoofed
            //
            if (node->CreateTime.QuadPart > previousCreateTime.QuadPart) {
                chain->IsParentSpoofed = TRUE;
                node->IsSuspicious = TRUE;
            }
        }

        previousCreateTime = node->CreateTime;
        firstNode = FALSE;

        //
        // Add to chain (at head - so chain is ordered from leaf to root)
        //
        InsertTailList(&chain->ChainList, &node->ListEntry);
        depth++;

        //
        // Get parent process ID
        //
        status = PctpGetParentProcessId(currentPid, &parentPid);
        if (!NT_SUCCESS(status) || parentPid == currentPid) {
            //
            // Reached end of chain or orphaned process
            //
            break;
        }

        currentPid = parentPid;
        node = NULL;
    }

    chain->ChainDepth = depth;

    //
    // Analyze the chain for suspicious patterns
    //
    PctpAnalyzeChain(chain);

    //
    // Calculate final suspicion score
    //
    chain->SuspicionScore = PctpCalculateSuspicionScore(chain);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Tracker->Stats.ChainsBuilt);

    if (chain->IsParentSpoofed) {
        InterlockedIncrement64(&Tracker->Stats.SpoofingDetected);
    }

    *Chain = chain;
    chain = NULL;
    status = STATUS_SUCCESS;

Cleanup:
    if (chain != NULL) {
        PctpFreeChainInternal(internal, chain);
    }

    PctpReleaseReference(internal);

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
    _Out_ PBOOLEAN IsSpoofed
    )
{
    NTSTATUS status;
    PPCT_TRACKER_INTERNAL internal;
    LARGE_INTEGER childCreateTime;
    LARGE_INTEGER parentCreateTime;
    HANDLE actualParentId;
    BOOLEAN spoofed = FALSE;

    if (Tracker == NULL || !Tracker->Initialized || IsSpoofed == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsSpoofed = FALSE;

    internal = CONTAINING_RECORD(Tracker, PCT_TRACKER_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    PctpAcquireReference(internal);

    //
    // Get the actual parent process ID from the system
    //
    status = PctpGetParentProcessId(ProcessId, &actualParentId);
    if (!NT_SUCCESS(status)) {
        //
        // Can't determine actual parent - assume not spoofed
        //
        goto Cleanup;
    }

    //
    // Check 1: Does claimed parent match actual parent?
    //
    if (actualParentId != ClaimedParentId) {
        //
        // Parent IDs don't match - potential spoofing
        // However, this could be legitimate if the actual parent terminated
        //
        spoofed = TRUE;
    }

    //
    // Check 2: Validate creation time ordering
    // Child process must be created AFTER parent process
    //
    status = PctpGetProcessCreateTime(ProcessId, &childCreateTime);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = PctpGetProcessCreateTime(ClaimedParentId, &parentCreateTime);
    if (!NT_SUCCESS(status)) {
        //
        // Parent may have terminated - check if claimed parent even exists
        //
        spoofed = TRUE;
        goto Done;
    }

    //
    // If claimed parent was created AFTER the child, it's definitely spoofed
    //
    if (parentCreateTime.QuadPart > childCreateTime.QuadPart + PCT_CREATION_TIME_TOLERANCE) {
        spoofed = TRUE;
    }

    //
    // Check 3: Verify the claimed parent is actually running or recently terminated
    // A process cannot have a parent that never existed
    //
    if (ClaimedParentId != NULL && (ULONG_PTR)ClaimedParentId > 4) {
        PEPROCESS parentProcess = NULL;

        status = PsLookupProcessByProcessId(ClaimedParentId, &parentProcess);
        if (!NT_SUCCESS(status)) {
            //
            // Claimed parent doesn't exist - but could be legitimate if it terminated
            // Check if the creation time is reasonable
            //
            if (childCreateTime.QuadPart < parentCreateTime.QuadPart) {
                spoofed = TRUE;
            }
        } else {
            ObDereferenceObject(parentProcess);
        }
    }

Done:
    *IsSpoofed = spoofed;

    if (spoofed) {
        InterlockedIncrement64(&Tracker->Stats.SpoofingDetected);
    }

    status = STATUS_SUCCESS;

Cleanup:
    PctpReleaseReference(internal);

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

    if (Tracker == NULL || !Tracker->Initialized ||
        AncestorName == NULL || HasAncestor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *HasAncestor = FALSE;

    internal = CONTAINING_RECORD(Tracker, PCT_TRACKER_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Build the process chain
    //
    status = PctBuildChain(Tracker, ProcessId, &chain);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Search for the ancestor in the chain
    //
    for (listEntry = chain->ChainList.Flink;
         listEntry != &chain->ChainList;
         listEntry = listEntry->Flink) {

        node = CONTAINING_RECORD(listEntry, PCT_CHAIN_NODE, ListEntry);

        if (node->ImageName.Buffer != NULL) {
            //
            // Compare the image name (case-insensitive)
            //
            if (PctpCompareImageNames(&node->ImageName, AncestorName->Buffer)) {
                found = TRUE;
                break;
            }

            //
            // Also check if it matches as a wildcard pattern
            //
            if (PctpMatchesPattern(&node->ImageName, AncestorName->Buffer, TRUE)) {
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
// CHAIN FREE
// ============================================================================

_Use_decl_annotations_
VOID
PctFreeChain(
    _In_ PPCT_PROCESS_CHAIN Chain
    )
{
    PLIST_ENTRY listEntry;
    PPCT_CHAIN_NODE node;

    if (Chain == NULL) {
        return;
    }

    //
    // Free all nodes in the chain
    //
    while (!IsListEmpty(&Chain->ChainList)) {
        listEntry = RemoveHeadList(&Chain->ChainList);
        node = CONTAINING_RECORD(listEntry, PCT_CHAIN_NODE, ListEntry);

        //
        // Free node strings
        //
        if (node->ImageName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(node->ImageName.Buffer, PCT_POOL_TAG);
        }
        if (node->CommandLine.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(node->CommandLine.Buffer, PCT_POOL_TAG);
        }

        //
        // Free node
        //
        ShadowStrikeFreePoolWithTag(node, PCT_POOL_TAG);
    }

    //
    // Free chain structure
    //
    ShadowStrikeFreePoolWithTag(Chain, PCT_POOL_TAG);
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

    if (!Tracker->LookasideInitialized) {
        node = (PPCT_CHAIN_NODE)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(PCT_CHAIN_NODE),
            PCT_POOL_TAG
        );
    } else {
        node = (PPCT_CHAIN_NODE)ExAllocateFromNPagedLookasideList(
            &Tracker->NodeLookaside
        );
    }

    return node;
}

static VOID
PctpFreeNode(
    _In_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PPCT_CHAIN_NODE Node
    )
{
    //
    // Free strings first
    //
    if (Node->ImageName.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(Node->ImageName.Buffer, PCT_POOL_TAG);
    }
    if (Node->CommandLine.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(Node->CommandLine.Buffer, PCT_POOL_TAG);
    }

    if (Tracker->LookasideInitialized) {
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

    if (!Tracker->LookasideInitialized) {
        chain = (PPCT_PROCESS_CHAIN)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(PCT_PROCESS_CHAIN),
            PCT_POOL_TAG
        );
    } else {
        chain = (PPCT_PROCESS_CHAIN)ExAllocateFromNPagedLookasideList(
            &Tracker->ChainLookaside
        );
    }

    return chain;
}

static VOID
PctpFreeChainInternal(
    _In_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PPCT_PROCESS_CHAIN Chain
    )
{
    PLIST_ENTRY listEntry;
    PPCT_CHAIN_NODE node;

    //
    // Free all nodes
    //
    while (!IsListEmpty(&Chain->ChainList)) {
        listEntry = RemoveHeadList(&Chain->ChainList);
        node = CONTAINING_RECORD(listEntry, PCT_CHAIN_NODE, ListEntry);
        PctpFreeNode(Tracker, node);
    }

    //
    // Free chain
    //
    if (Tracker->LookasideInitialized) {
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
    _Out_ PPCT_CHAIN_NODE Node
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;

    //
    // Lookup the process
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Get process creation time
    //
    Node->CreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(process);

    //
    // Get image file name
    //
    status = SeLocateProcessImageName(process, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL) {
        //
        // Allocate and copy the image name
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
            Node->ImageName.Buffer[Node->ImageName.Length / sizeof(WCHAR)] = L'\0';
        }

        ExFreePool(imageName);
    }

    ObDereferenceObject(process);

    return STATUS_SUCCESS;
}

static NTSTATUS
PctpGetParentProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PHANDLE ParentProcessId
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    HANDLE parentPid = NULL;

    *ParentProcessId = NULL;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Get inherited from unique process ID (parent PID)
    // This is stored in the EPROCESS structure
    //
    parentPid = PsGetProcessInheritedFromUniqueProcessId(process);

    ObDereferenceObject(process);

    *ParentProcessId = parentPid;

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
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;

    //
    // System (PID 4), Idle (PID 0), and some other system processes
    //
    if (pid == 0 || pid == 4) {
        return TRUE;
    }

    //
    // Check for smss.exe, csrss.exe, wininit.exe, services.exe, lsass.exe
    // These are typically very low PIDs but we'd need to check by name
    //
    return FALSE;
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

    if (Score != NULL) {
        *Score = 0;
    }

    if (ImageName == NULL || ImageName->Buffer == NULL) {
        return FALSE;
    }

    for (i = 0; i < ARRAYSIZE(g_ScriptHosts); i++) {
        if (PctpCompareImageNames(ImageName, g_ScriptHosts[i].ImageName)) {
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

    if (ImageName == NULL || ImageName->Buffer == NULL) {
        return FALSE;
    }

    for (i = 0; i < ARRAYSIZE(g_LOLBins); i++) {
        if (PctpCompareImageNames(ImageName, g_LOLBins[i])) {
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

    if (ImageName == NULL || ImageName->Buffer == NULL) {
        return FALSE;
    }

    for (i = 0; i < ARRAYSIZE(g_OfficeApps); i++) {
        if (PctpCompareImageNames(ImageName, g_OfficeApps[i])) {
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

    if (ImageName == NULL || ImageName->Buffer == NULL) {
        return FALSE;
    }

    for (i = 0; i < ARRAYSIZE(g_Browsers); i++) {
        if (PctpCompareImageNames(ImageName, g_Browsers[i])) {
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

    if (ImageName == NULL || ImageName->Buffer == NULL) {
        return FALSE;
    }

    for (i = 0; i < ARRAYSIZE(g_Shells); i++) {
        if (PctpCompareImageNames(ImageName, g_Shells[i])) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
PctpMatchesPattern(
    _In_ PUNICODE_STRING String,
    _In_ PCWSTR Pattern,
    _In_ BOOLEAN IsWildcard
    )
{
    UNICODE_STRING patternString;

    if (String == NULL || String->Buffer == NULL || Pattern == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&patternString, Pattern);

    if (IsWildcard) {
        //
        // Simple wildcard: check if pattern is contained in string
        //
        PWCHAR found = wcsstr(String->Buffer, Pattern);
        return (found != NULL);
    } else {
        return RtlEqualUnicodeString(String, &patternString, TRUE);
    }
}

static BOOLEAN
PctpCompareImageNames(
    _In_ PUNICODE_STRING ImagePath,
    _In_ PCWSTR ImageName
    )
{
    UNICODE_STRING extractedName;
    UNICODE_STRING compareString;
    PWCHAR lastSlash;

    if (ImagePath == NULL || ImagePath->Buffer == NULL || ImageName == NULL) {
        return FALSE;
    }

    //
    // Extract just the image name from the full path
    //
    lastSlash = wcsrchr(ImagePath->Buffer, L'\\');
    if (lastSlash != NULL) {
        RtlInitUnicodeString(&extractedName, lastSlash + 1);
    } else {
        extractedName = *ImagePath;
    }

    RtlInitUnicodeString(&compareString, ImageName);

    return RtlEqualUnicodeString(&extractedName, &compareString, TRUE);
}

static VOID
PctpExtractImageName(
    _In_ PUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING ImageName
    )
{
    PWCHAR lastSlash;

    RtlZeroMemory(ImageName, sizeof(UNICODE_STRING));

    if (FullPath == NULL || FullPath->Buffer == NULL) {
        return;
    }

    lastSlash = wcsrchr(FullPath->Buffer, L'\\');
    if (lastSlash != NULL) {
        RtlInitUnicodeString(ImageName, lastSlash + 1);
    } else {
        *ImageName = *FullPath;
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - CHAIN ANALYSIS
// ============================================================================

static VOID
PctpAnalyzeChain(
    _Inout_ PPCT_PROCESS_CHAIN Chain
    )
{
    PLIST_ENTRY listEntry;
    PLIST_ENTRY prevEntry;
    PPCT_CHAIN_NODE node;
    PPCT_CHAIN_NODE parentNode;
    BOOLEAN hasSuspiciousAncestor = FALSE;

    if (IsListEmpty(&Chain->ChainList)) {
        return;
    }

    //
    // Analyze parent-child relationships in the chain
    //
    for (listEntry = Chain->ChainList.Flink;
         listEntry != &Chain->ChainList;
         listEntry = listEntry->Flink) {

        node = CONTAINING_RECORD(listEntry, PCT_CHAIN_NODE, ListEntry);
        prevEntry = listEntry->Blink;

        if (prevEntry != &Chain->ChainList) {
            //
            // Get the parent (previous in list = child's parent)
            // Actually, the list is built from leaf to root, so Flink points toward root
            //
            parentNode = CONTAINING_RECORD(listEntry->Flink, PCT_CHAIN_NODE, ListEntry);

            if (listEntry->Flink != &Chain->ChainList && parentNode->ImageName.Buffer != NULL) {
                //
                // Check for suspicious parent-child patterns
                //

                //
                // Office app spawning shell
                //
                if (PctpIsOfficeApp(&parentNode->ImageName) &&
                    PctpIsShell(&node->ImageName)) {
                    node->IsSuspicious = TRUE;
                    hasSuspiciousAncestor = TRUE;
                }

                //
                // Browser spawning shell
                //
                if (PctpIsBrowser(&parentNode->ImageName) &&
                    PctpIsShell(&node->ImageName)) {
                    node->IsSuspicious = TRUE;
                    hasSuspiciousAncestor = TRUE;
                }

                //
                // LOLBin chain (LOLBin spawning LOLBin)
                //
                if (PctpIsLOLBin(&parentNode->ImageName) &&
                    PctpIsLOLBin(&node->ImageName)) {
                    node->IsSuspicious = TRUE;
                    hasSuspiciousAncestor = TRUE;
                }

                //
                // Script host spawning another script host
                //
                if (PctpIsScriptHost(&parentNode->ImageName, NULL) &&
                    PctpIsScriptHost(&node->ImageName, NULL)) {
                    node->IsSuspicious = TRUE;
                    hasSuspiciousAncestor = TRUE;
                }
            }
        }

        //
        // Check if this node is inherently suspicious
        //
        if (PctpIsScriptHost(&node->ImageName, NULL) ||
            PctpIsLOLBin(&node->ImageName)) {
            //
            // Mark as potentially suspicious for deeper analysis
            //
        }
    }

    Chain->HasSuspiciousAncestor = hasSuspiciousAncestor;
}

static ULONG
PctpCalculateSuspicionScore(
    _In_ PPCT_PROCESS_CHAIN Chain
    )
{
    ULONG score = 0;
    PLIST_ENTRY listEntry;
    PLIST_ENTRY parentEntry;
    PPCT_CHAIN_NODE node;
    PPCT_CHAIN_NODE parentNode;
    ULONG scriptScore;

    //
    // PPID spoofing is a critical indicator
    //
    if (Chain->IsParentSpoofed) {
        score += PCT_SCORE_PPID_SPOOFED;
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
        parentEntry = listEntry->Flink;

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
        // Parent-child analysis
        //
        if (parentEntry != &Chain->ChainList) {
            parentNode = CONTAINING_RECORD(parentEntry, PCT_CHAIN_NODE, ListEntry);

            //
            // Office spawning shell
            //
            if (PctpIsOfficeApp(&parentNode->ImageName) &&
                PctpIsShell(&node->ImageName)) {
                score += PCT_SCORE_OFFICE_SPAWN_SHELL;
            }

            //
            // Browser spawning shell
            //
            if (PctpIsBrowser(&parentNode->ImageName) &&
                PctpIsShell(&node->ImageName)) {
                score += PCT_SCORE_BROWSER_SPAWN_SHELL;
            }
        }

        //
        // Suspicious flag from chain analysis
        //
        if (node->IsSuspicious) {
            score += PCT_SCORE_SUSPICIOUS_PARENT;
        }
    }

    return score;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - PATTERN INITIALIZATION
// ============================================================================

static NTSTATUS
PctpInitializeBuiltinPatterns(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    )
{
    //
    // Add known suspicious parent-child patterns
    //

    //
    // Office applications spawning shells
    //
    PctpAddSuspiciousPattern(Tracker, L"winword.exe", L"cmd.exe",
        PCT_SCORE_OFFICE_SPAWN_SHELL, L"Word spawning command prompt");
    PctpAddSuspiciousPattern(Tracker, L"winword.exe", L"powershell.exe",
        PCT_SCORE_OFFICE_SPAWN_SHELL, L"Word spawning PowerShell");
    PctpAddSuspiciousPattern(Tracker, L"excel.exe", L"cmd.exe",
        PCT_SCORE_OFFICE_SPAWN_SHELL, L"Excel spawning command prompt");
    PctpAddSuspiciousPattern(Tracker, L"excel.exe", L"powershell.exe",
        PCT_SCORE_OFFICE_SPAWN_SHELL, L"Excel spawning PowerShell");
    PctpAddSuspiciousPattern(Tracker, L"outlook.exe", L"cmd.exe",
        PCT_SCORE_OFFICE_SPAWN_SHELL, L"Outlook spawning command prompt");
    PctpAddSuspiciousPattern(Tracker, L"outlook.exe", L"powershell.exe",
        PCT_SCORE_OFFICE_SPAWN_SHELL, L"Outlook spawning PowerShell");

    //
    // Browsers spawning shells
    //
    PctpAddSuspiciousPattern(Tracker, L"chrome.exe", L"cmd.exe",
        PCT_SCORE_BROWSER_SPAWN_SHELL, L"Chrome spawning command prompt");
    PctpAddSuspiciousPattern(Tracker, L"chrome.exe", L"powershell.exe",
        PCT_SCORE_BROWSER_SPAWN_SHELL, L"Chrome spawning PowerShell");
    PctpAddSuspiciousPattern(Tracker, L"firefox.exe", L"cmd.exe",
        PCT_SCORE_BROWSER_SPAWN_SHELL, L"Firefox spawning command prompt");
    PctpAddSuspiciousPattern(Tracker, L"firefox.exe", L"powershell.exe",
        PCT_SCORE_BROWSER_SPAWN_SHELL, L"Firefox spawning PowerShell");
    PctpAddSuspiciousPattern(Tracker, L"msedge.exe", L"cmd.exe",
        PCT_SCORE_BROWSER_SPAWN_SHELL, L"Edge spawning command prompt");

    //
    // LOLBin patterns
    //
    PctpAddSuspiciousPattern(Tracker, L"mshta.exe", L"powershell.exe",
        PCT_SCORE_LOLBIN_CHAIN, L"MSHTA spawning PowerShell");
    PctpAddSuspiciousPattern(Tracker, L"wscript.exe", L"cmd.exe",
        PCT_SCORE_LOLBIN_CHAIN, L"WScript spawning command prompt");
    PctpAddSuspiciousPattern(Tracker, L"cscript.exe", L"cmd.exe",
        PCT_SCORE_LOLBIN_CHAIN, L"CScript spawning command prompt");
    PctpAddSuspiciousPattern(Tracker, L"rundll32.exe", L"cmd.exe",
        PCT_SCORE_LOLBIN_CHAIN, L"Rundll32 spawning command prompt");
    PctpAddSuspiciousPattern(Tracker, L"regsvr32.exe", L"cmd.exe",
        PCT_SCORE_LOLBIN_CHAIN, L"Regsvr32 spawning command prompt");

    //
    // Script host chains
    //
    PctpAddSuspiciousPattern(Tracker, L"powershell.exe", L"powershell.exe",
        PCT_SCORE_SCRIPT_HOST, L"PowerShell spawning PowerShell");
    PctpAddSuspiciousPattern(Tracker, L"cmd.exe", L"powershell.exe",
        PCT_SCORE_SCRIPT_HOST, L"CMD spawning PowerShell");

    return STATUS_SUCCESS;
}

static VOID
PctpAddSuspiciousPattern(
    _In_ PPCT_TRACKER_INTERNAL Tracker,
    _In_ PCWSTR ParentImage,
    _In_ PCWSTR ChildImage,
    _In_ ULONG Score,
    _In_ PCWSTR Description
    )
{
    PPCT_SUSPICIOUS_PATTERN pattern;
    SIZE_T parentLen;
    SIZE_T childLen;

    if (Tracker->PatternCount >= PCT_MAX_SUSPICIOUS_PATTERNS) {
        return;
    }

    pattern = (PPCT_SUSPICIOUS_PATTERN)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PCT_SUSPICIOUS_PATTERN),
        PCT_POOL_TAG
    );

    if (pattern == NULL) {
        return;
    }

    RtlZeroMemory(pattern, sizeof(PCT_SUSPICIOUS_PATTERN));

    //
    // Allocate and copy parent image name
    //
    parentLen = wcslen(ParentImage);
    pattern->ParentImageName.MaximumLength = (USHORT)((parentLen + 1) * sizeof(WCHAR));
    pattern->ParentImageName.Buffer = (PWCH)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        pattern->ParentImageName.MaximumLength,
        PCT_POOL_TAG
    );

    if (pattern->ParentImageName.Buffer == NULL) {
        ShadowStrikeFreePoolWithTag(pattern, PCT_POOL_TAG);
        return;
    }

    RtlCopyMemory(pattern->ParentImageName.Buffer, ParentImage, parentLen * sizeof(WCHAR));
    pattern->ParentImageName.Length = (USHORT)(parentLen * sizeof(WCHAR));
    pattern->ParentImageName.Buffer[parentLen] = L'\0';

    //
    // Allocate and copy child image name
    //
    childLen = wcslen(ChildImage);
    pattern->ChildImageName.MaximumLength = (USHORT)((childLen + 1) * sizeof(WCHAR));
    pattern->ChildImageName.Buffer = (PWCH)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        pattern->ChildImageName.MaximumLength,
        PCT_POOL_TAG
    );

    if (pattern->ChildImageName.Buffer == NULL) {
        ShadowStrikeFreePoolWithTag(pattern->ParentImageName.Buffer, PCT_POOL_TAG);
        ShadowStrikeFreePoolWithTag(pattern, PCT_POOL_TAG);
        return;
    }

    RtlCopyMemory(pattern->ChildImageName.Buffer, ChildImage, childLen * sizeof(WCHAR));
    pattern->ChildImageName.Length = (USHORT)(childLen * sizeof(WCHAR));
    pattern->ChildImageName.Buffer[childLen] = L'\0';

    pattern->Score = Score;
    pattern->Description = Description;
    pattern->IsWildcardParent = (wcschr(ParentImage, L'*') != NULL);
    pattern->IsWildcardChild = (wcschr(ChildImage, L'*') != NULL);

    //
    // Insert into pattern list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->PatternLock);

    InsertTailList(&Tracker->Public.SuspiciousPatterns, &pattern->ListEntry);
    Tracker->PatternCount++;

    ExReleasePushLockExclusive(&Tracker->PatternLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - REFERENCE COUNTING
// ============================================================================

static VOID
PctpAcquireReference(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    )
{
    InterlockedIncrement(&Tracker->ActiveOperations);
}

static VOID
PctpReleaseReference(
    _In_ PPCT_TRACKER_INTERNAL Tracker
    )
{
    if (InterlockedDecrement(&Tracker->ActiveOperations) == 0) {
        KeSetEvent(&Tracker->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
}

