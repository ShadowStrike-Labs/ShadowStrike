/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE ENVIRONMENT VARIABLE MONITOR
 * ============================================================================
 *
 * @file EnvironmentMonitor.c
 * @brief Enterprise-grade environment variable tracking and analysis engine.
 *
 * Implements CrowdStrike Falcon-class environment variable security analysis:
 * - Process environment block (PEB) extraction and parsing
 * - Malicious PATH modification detection (DLL search order hijacking)
 * - Proxy settings manipulation detection (credential theft)
 * - TEMP/TMP override attacks (malware staging detection)
 * - Hidden/obfuscated environment variable detection
 * - Base64/encoded value detection in environment variables
 * - Per-process environment baseline caching
 * - Real-time environment change monitoring
 * - Comprehensive environment forensics
 *
 * Detection Techniques:
 * - PATH variable parsing for suspicious directories
 * - Known DLL hijack path detection
 * - Proxy environment variables (HTTP_PROXY, HTTPS_PROXY, etc.)
 * - Encoded payload detection via entropy analysis
 * - Environment variable injection detection
 * - System vs user variable comparison
 * - Writable directory in PATH detection
 *
 * MITRE ATT&CK Coverage:
 * - T1574.007: Path Interception by PATH Environment Variable
 * - T1574.008: Path Interception by Search Order Hijacking
 * - T1090.001: Proxy (via environment variable manipulation)
 * - T1027: Obfuscated Files or Information (encoded env vars)
 * - T1059: Command and Scripting Interpreter (env var abuse)
 * - T1564: Hide Artifacts (hidden environment variables)
 *
 * Security Hardened v2.0.0:
 * - All input parameters validated before use
 * - Safe PEB access with proper memory validation
 * - Exception handling for invalid process access
 * - Reference counting for thread safety
 * - Proper cleanup on all error paths
 * - Memory-efficient environment caching
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "EnvironmentMonitor.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/StringUtils.h"
#include "../../Utilities/ProcessUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Maximum cached environment entries per monitor
 */
#define EM_MAX_CACHE_ENTRIES                2048

/**
 * @brief Maximum environment variables per process
 */
#define EM_MAX_VARIABLES_PER_PROCESS        1024

/**
 * @brief Maximum PATH entries to analyze
 */
#define EM_MAX_PATH_ENTRIES                 256

/**
 * @brief Lookaside list depth for env variable allocations
 */
#define EM_ENV_VAR_LOOKASIDE_DEPTH          128

/**
 * @brief Monitor magic for validation
 */
#define EM_MONITOR_MAGIC                    0x454E564D  // 'ENVM'

/**
 * @brief Environment entry magic for validation
 */
#define EM_ENV_ENTRY_MAGIC                  0x454E5645  // 'ENVE'

/**
 * @brief Pool tag for environment variable entries
 */
#define EM_ENV_VAR_TAG                      'VENE'

/**
 * @brief Pool tag for PATH analysis
 */
#define EM_PATH_TAG                         'PTNE'

/**
 * @brief Pool tag for environment string buffers
 */
#define EM_STRING_TAG                       'STNE'

/**
 * @brief Cache entry expiry time (10 minutes in 100ns units)
 */
#define EM_CACHE_EXPIRY_TIME                (10 * 60 * 10000000LL)

/**
 * @brief Minimum entropy threshold for encoded value detection
 */
#define EM_ENTROPY_THRESHOLD                4.5f

/**
 * @brief Maximum environment block size to capture (64 KB)
 */
#define EM_MAX_ENV_BLOCK_SIZE               (64 * 1024)

/**
 * @brief High suspicion score threshold
 */
#define EM_HIGH_SUSPICION_THRESHOLD         80

/**
 * @brief Medium suspicion score threshold
 */
#define EM_MEDIUM_SUSPICION_THRESHOLD       50

// ============================================================================
// WELL-KNOWN SUSPICIOUS ENVIRONMENT VARIABLES
// ============================================================================

/**
 * @brief Proxy-related environment variables
 */
static const PCWSTR g_ProxyVariables[] = {
    L"HTTP_PROXY",
    L"HTTPS_PROXY",
    L"FTP_PROXY",
    L"ALL_PROXY",
    L"NO_PROXY",
    L"http_proxy",
    L"https_proxy",
    L"ftp_proxy",
    L"all_proxy"
};

/**
 * @brief Temp directory environment variables
 */
static const PCWSTR g_TempVariables[] = {
    L"TEMP",
    L"TMP",
    L"TMPDIR",
    L"USERPROFILE"
};

/**
 * @brief DLL loading related variables
 */
static const PCWSTR g_DllVariables[] = {
    L"PATH",
    L"PATHEXT",
    L"COMSPEC",
    L"SYSTEMROOT",
    L"WINDIR"
};

/**
 * @brief Security-sensitive variables
 */
static const PCWSTR g_SecurityVariables[] = {
    L"USERNAME",
    L"USERDOMAIN",
    L"LOGONSERVER",
    L"COMPUTERNAME",
    L"SESSIONNAME"
};

/**
 * @brief Suspicious writable directories in PATH
 */
static const PCWSTR g_SuspiciousPathDirs[] = {
    L"\\Users\\",
    L"\\Temp\\",
    L"\\AppData\\",
    L"\\Downloads\\",
    L"\\Desktop\\",
    L"\\Documents\\",
    L"\\Public\\"
};

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Internal monitor context with extended fields
 */
typedef struct _EM_MONITOR_INTERNAL {
    //
    // Base structure (must be first)
    //
    EM_MONITOR Base;

    //
    // Magic for validation
    //
    ULONG Magic;

    //
    // Lookaside list for environment variable allocations
    //
    NPAGED_LOOKASIDE_LIST EnvVarLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Reference counting
    //
    volatile LONG ReferenceCount;
    volatile LONG ShuttingDown;
    KEVENT ShutdownEvent;

    //
    // System baseline cache
    //
    LIST_ENTRY SystemBaseline;
    EX_PUSH_LOCK BaselineLock;
    BOOLEAN BaselineInitialized;

} EM_MONITOR_INTERNAL, *PEM_MONITOR_INTERNAL;

/**
 * @brief Internal process environment with extended fields
 */
typedef struct _EM_PROCESS_ENV_INTERNAL {
    //
    // Base structure (must be first)
    //
    EM_PROCESS_ENV Base;

    //
    // Magic for validation
    //
    ULONG Magic;

    //
    // PATH analysis results
    //
    ULONG PathEntryCount;
    BOOLEAN HasWritablePathEntry;
    BOOLEAN HasUserPathEntry;
    BOOLEAN HasSuspiciousPathEntry;

    //
    // Proxy analysis results
    //
    BOOLEAN HasProxySettings;
    BOOLEAN ProxyIsLocalhost;
    BOOLEAN ProxyIsSuspicious;

    //
    // Encoding analysis
    //
    ULONG EncodedValueCount;
    ULONG HighEntropyCount;

    //
    // Temp override analysis
    //
    BOOLEAN HasTempOverride;
    BOOLEAN TempPointsToWritable;

    //
    // Detection results
    //
    BOOLEAN AnalysisComplete;
    ULONG SuspicionScore;
    LARGE_INTEGER AnalysisTime;

    //
    // Back reference
    //
    PEM_MONITOR_INTERNAL Monitor;
    volatile LONG ReferenceCount;

    //
    // Cache linkage
    //
    LIST_ENTRY CacheEntry;
    LARGE_INTEGER CacheTime;

} EM_PROCESS_ENV_INTERNAL, *PEM_PROCESS_ENV_INTERNAL;

/**
 * @brief PATH entry analysis structure
 */
typedef struct _EM_PATH_ENTRY {
    WCHAR Path[MAX_PATH];
    USHORT PathLength;
    BOOLEAN IsWritable;
    BOOLEAN IsUserDirectory;
    BOOLEAN IsSuspicious;
    BOOLEAN IsSystemDirectory;
    ULONG Priority;
} EM_PATH_ENTRY, *PEM_PATH_ENTRY;

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static VOID
EmpAcquireReference(
    _Inout_ PEM_MONITOR_INTERNAL Monitor
);

static VOID
EmpReleaseReference(
    _Inout_ PEM_MONITOR_INTERNAL Monitor
);

static NTSTATUS
EmpAllocateEnvVariable(
    _In_ PEM_MONITOR_INTERNAL Monitor,
    _Out_ PEM_ENV_VARIABLE* Variable
);

static VOID
EmpFreeEnvVariable(
    _In_ PEM_MONITOR_INTERNAL Monitor,
    _In_ PEM_ENV_VARIABLE Variable
);

static NTSTATUS
EmpAllocateProcessEnv(
    _In_ PEM_MONITOR_INTERNAL Monitor,
    _Out_ PEM_PROCESS_ENV_INTERNAL* ProcessEnv
);

static VOID
EmpFreeProcessEnvInternal(
    _In_ PEM_MONITOR_INTERNAL Monitor,
    _In_ PEM_PROCESS_ENV_INTERNAL ProcessEnv
);

static NTSTATUS
EmpCaptureEnvironmentBlock(
    _In_ HANDLE ProcessId,
    _Out_ PVOID* EnvironmentBlock,
    _Out_ PSIZE_T BlockSize
);

static NTSTATUS
EmpParseEnvironmentBlock(
    _In_ PEM_MONITOR_INTERNAL Monitor,
    _In_ PVOID EnvironmentBlock,
    _In_ SIZE_T BlockSize,
    _Inout_ PEM_PROCESS_ENV_INTERNAL ProcessEnv
);

static NTSTATUS
EmpAnalyzePathVariable(
    _In_ PEM_PROCESS_ENV_INTERNAL ProcessEnv,
    _In_ PCSTR PathValue
);

static NTSTATUS
EmpAnalyzeProxySettings(
    _In_ PEM_PROCESS_ENV_INTERNAL ProcessEnv
);

static NTSTATUS
EmpAnalyzeTempOverrides(
    _In_ PEM_PROCESS_ENV_INTERNAL ProcessEnv
);

static BOOLEAN
EmpIsEncodedValue(
    _In_ PCSTR Value,
    _In_ SIZE_T ValueLength
);

static float
EmpCalculateEntropy(
    _In_ PCSTR Data,
    _In_ SIZE_T Length
);

static BOOLEAN
EmpIsBase64Encoded(
    _In_ PCSTR Value,
    _In_ SIZE_T ValueLength
);

static BOOLEAN
EmpIsHexEncoded(
    _In_ PCSTR Value,
    _In_ SIZE_T ValueLength
);

static BOOLEAN
EmpIsWritablePath(
    _In_ PCWSTR Path
);

static BOOLEAN
EmpIsUserPath(
    _In_ PCWSTR Path
);

static BOOLEAN
EmpIsSuspiciousPath(
    _In_ PCWSTR Path
);

static BOOLEAN
EmpIsSystemPath(
    _In_ PCWSTR Path
);

static EM_SUSPICION
EmpDetectSuspiciousConditions(
    _In_ PEM_PROCESS_ENV_INTERNAL ProcessEnv
);

static ULONG
EmpCalculateSuspicionScore(
    _In_ PEM_PROCESS_ENV_INTERNAL ProcessEnv,
    _In_ EM_SUSPICION Flags
);

static VOID
EmpCleanupExpiredCacheEntries(
    _Inout_ PEM_MONITOR_INTERNAL Monitor
);

static BOOLEAN
EmpCompareEnvironmentVariable(
    _In_ PCSTR Name,
    _In_ PCWSTR Target
);

// ============================================================================
// PAGE ALLOCATION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, EmInitialize)
#pragma alloc_text(PAGE, EmShutdown)
#pragma alloc_text(PAGE, EmCaptureEnvironment)
#pragma alloc_text(PAGE, EmAnalyzeEnvironment)
#pragma alloc_text(PAGE, EmGetVariable)
#pragma alloc_text(PAGE, EmFreeEnvironment)
#endif

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EmInitialize(
    _Out_ PEM_MONITOR* Monitor
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEM_MONITOR_INTERNAL monitor = NULL;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Monitor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Monitor = NULL;

    //
    // Allocate monitor structure from non-paged pool
    //
    monitor = (PEM_MONITOR_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(EM_MONITOR_INTERNAL),
        EM_POOL_TAG
    );

    if (monitor == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(monitor, sizeof(EM_MONITOR_INTERNAL));

    //
    // Set magic for validation
    //
    monitor->Magic = EM_MONITOR_MAGIC;

    //
    // Initialize process environment cache
    //
    InitializeListHead(&monitor->Base.ProcessList);
    ExInitializePushLock(&monitor->Base.ProcessLock);

    //
    // Initialize system baseline cache
    //
    InitializeListHead(&monitor->SystemBaseline);
    ExInitializePushLock(&monitor->BaselineLock);

    //
    // Initialize lookaside list for environment variable allocations
    //
    ExInitializeNPagedLookasideList(
        &monitor->EnvVarLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(EM_ENV_VARIABLE),
        EM_ENV_VAR_TAG,
        EM_ENV_VAR_LOOKASIDE_DEPTH
    );
    monitor->LookasideInitialized = TRUE;

    //
    // Initialize reference counting
    //
    monitor->ReferenceCount = 1;
    monitor->ShuttingDown = FALSE;
    KeInitializeEvent(&monitor->ShutdownEvent, NotificationEvent, FALSE);

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&monitor->Base.Stats.StartTime);

    //
    // Mark as initialized
    //
    monitor->Base.Initialized = TRUE;

    *Monitor = (PEM_MONITOR)monitor;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
EmShutdown(
    _Inout_ PEM_MONITOR Monitor
)
{
    PEM_MONITOR_INTERNAL monitor = (PEM_MONITOR_INTERNAL)Monitor;
    PLIST_ENTRY entry;
    PEM_PROCESS_ENV_INTERNAL processEnv;
    PEM_ENV_VARIABLE envVar;
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (Monitor == NULL || !Monitor->Initialized) {
        return;
    }

    if (monitor->Magic != EM_MONITOR_MAGIC) {
        return;
    }

    //
    // Signal shutdown
    //
    InterlockedExchange(&monitor->ShuttingDown, 1);

    //
    // Wait for references to drain
    //
    timeout.QuadPart = -10000;  // 1ms
    while (monitor->ReferenceCount > 1) {
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    }

    //
    // Free all cached process environments
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&monitor->Base.ProcessLock);

    while (!IsListEmpty(&monitor->Base.ProcessList)) {
        entry = RemoveHeadList(&monitor->Base.ProcessList);
        processEnv = CONTAINING_RECORD(entry, EM_PROCESS_ENV_INTERNAL, Base.ListEntry);
        EmpFreeProcessEnvInternal(monitor, processEnv);
    }

    ExReleasePushLockExclusive(&monitor->Base.ProcessLock);
    KeLeaveCriticalRegion();

    //
    // Free system baseline cache
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&monitor->BaselineLock);

    while (!IsListEmpty(&monitor->SystemBaseline)) {
        entry = RemoveHeadList(&monitor->SystemBaseline);
        envVar = CONTAINING_RECORD(entry, EM_ENV_VARIABLE, ListEntry);
        EmpFreeEnvVariable(monitor, envVar);
    }

    ExReleasePushLockExclusive(&monitor->BaselineLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside list
    //
    if (monitor->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&monitor->EnvVarLookaside);
        monitor->LookasideInitialized = FALSE;
    }

    //
    // Clear state
    //
    monitor->Magic = 0;
    monitor->Base.Initialized = FALSE;

    ShadowStrikeFreePoolWithTag(monitor, EM_POOL_TAG);
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EmCaptureEnvironment(
    _In_ PEM_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _Out_ PEM_PROCESS_ENV* Env
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEM_MONITOR_INTERNAL monitor = (PEM_MONITOR_INTERNAL)Monitor;
    PEM_PROCESS_ENV_INTERNAL processEnv = NULL;
    PVOID environmentBlock = NULL;
    SIZE_T blockSize = 0;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Monitor == NULL || !Monitor->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (monitor->Magic != EM_MONITOR_MAGIC) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Env == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    *Env = NULL;

    //
    // Check shutdown
    //
    if (monitor->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    EmpAcquireReference(monitor);

    //
    // Update statistics
    //
    InterlockedIncrement64(&monitor->Base.Stats.ProcessesMonitored);

    //
    // Allocate process environment structure
    //
    status = EmpAllocateProcessEnv(monitor, &processEnv);
    if (!NT_SUCCESS(status)) {
        EmpReleaseReference(monitor);
        return status;
    }

    //
    // Initialize basic fields
    //
    processEnv->Base.ProcessId = ProcessId;
    KeQuerySystemTime(&processEnv->AnalysisTime);

    //
    // Capture environment block from target process
    //
    status = EmpCaptureEnvironmentBlock(ProcessId, &environmentBlock, &blockSize);
    if (!NT_SUCCESS(status)) {
        EmpFreeProcessEnvInternal(monitor, processEnv);
        EmpReleaseReference(monitor);
        return status;
    }

    //
    // Parse environment block into variable list
    //
    status = EmpParseEnvironmentBlock(monitor, environmentBlock, blockSize, processEnv);

    //
    // Free the captured block - we've copied what we need
    //
    if (environmentBlock != NULL) {
        ShadowStrikeFreePoolWithTag(environmentBlock, EM_STRING_TAG);
    }

    if (!NT_SUCCESS(status)) {
        EmpFreeProcessEnvInternal(monitor, processEnv);
        EmpReleaseReference(monitor);
        return status;
    }

    //
    // Add to cache
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&monitor->Base.ProcessLock);

    //
    // Enforce cache limit
    //
    if ((ULONG)monitor->Base.ProcessCount >= EM_MAX_CACHE_ENTRIES) {
        EmpCleanupExpiredCacheEntries(monitor);

        //
        // If still at limit, remove oldest
        //
        if ((ULONG)monitor->Base.ProcessCount >= EM_MAX_CACHE_ENTRIES) {
            if (!IsListEmpty(&monitor->Base.ProcessList)) {
                PLIST_ENTRY oldEntry = RemoveHeadList(&monitor->Base.ProcessList);
                PEM_PROCESS_ENV_INTERNAL oldEnv = CONTAINING_RECORD(
                    oldEntry, EM_PROCESS_ENV_INTERNAL, Base.ListEntry
                );
                EmpFreeProcessEnvInternal(monitor, oldEnv);
                InterlockedDecrement(&monitor->Base.ProcessCount);
            }
        }
    }

    KeQuerySystemTime(&processEnv->CacheTime);
    InsertTailList(&monitor->Base.ProcessList, &processEnv->Base.ListEntry);
    InterlockedIncrement(&monitor->Base.ProcessCount);

    ExReleasePushLockExclusive(&monitor->Base.ProcessLock);
    KeLeaveCriticalRegion();

    *Env = &processEnv->Base;

    EmpReleaseReference(monitor);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EmAnalyzeEnvironment(
    _In_ PEM_MONITOR Monitor,
    _In_ PEM_PROCESS_ENV Env,
    _Out_ PEM_SUSPICION* Flags
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEM_MONITOR_INTERNAL monitor = (PEM_MONITOR_INTERNAL)Monitor;
    PEM_PROCESS_ENV_INTERNAL processEnv;
    EM_SUSPICION suspicionFlags = EmSuspicion_None;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Monitor == NULL || !Monitor->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (monitor->Magic != EM_MONITOR_MAGIC) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Env == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Flags == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    *Flags = EmSuspicion_None;

    if (monitor->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    EmpAcquireReference(monitor);

    processEnv = CONTAINING_RECORD(Env, EM_PROCESS_ENV_INTERNAL, Base);

    //
    // Validate magic
    //
    if (processEnv->Magic != EM_ENV_ENTRY_MAGIC) {
        EmpReleaseReference(monitor);
        return STATUS_INVALID_PARAMETER_2;
    }

    //
    // Check if already analyzed
    //
    if (processEnv->AnalysisComplete) {
        *Flags = processEnv->Base.SuspicionFlags;
        EmpReleaseReference(monitor);
        return STATUS_SUCCESS;
    }

    //
    // Analyze PATH variable for DLL search order hijacking
    //
    status = EmpAnalyzeProxySettings(processEnv);
    if (!NT_SUCCESS(status)) {
        // Continue with analysis despite error
        status = STATUS_SUCCESS;
    }

    //
    // Analyze TEMP/TMP overrides
    //
    status = EmpAnalyzeTempOverrides(processEnv);
    if (!NT_SUCCESS(status)) {
        status = STATUS_SUCCESS;
    }

    //
    // Detect all suspicious conditions
    //
    suspicionFlags = EmpDetectSuspiciousConditions(processEnv);

    //
    // Calculate suspicion score
    //
    processEnv->SuspicionScore = EmpCalculateSuspicionScore(processEnv, suspicionFlags);
    processEnv->Base.SuspicionFlags = suspicionFlags;
    processEnv->AnalysisComplete = TRUE;

    //
    // Update statistics if suspicious
    //
    if (suspicionFlags != EmSuspicion_None) {
        InterlockedIncrement64(&monitor->Base.Stats.SuspiciousEnvFound);
    }

    *Flags = suspicionFlags;

    EmpReleaseReference(monitor);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EmGetVariable(
    _In_ PEM_PROCESS_ENV Env,
    _In_ PCSTR Name,
    _Out_ PEM_ENV_VARIABLE* Variable
)
{
    PEM_PROCESS_ENV_INTERNAL processEnv;
    PLIST_ENTRY entry;
    PEM_ENV_VARIABLE envVar;
    SIZE_T nameLength;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Env == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Name == NULL || Name[0] == '\0') {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Variable == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    *Variable = NULL;

    processEnv = CONTAINING_RECORD(Env, EM_PROCESS_ENV_INTERNAL, Base);

    if (processEnv->Magic != EM_ENV_ENTRY_MAGIC) {
        return STATUS_INVALID_PARAMETER_1;
    }

    nameLength = strlen(Name);
    if (nameLength >= EM_MAX_ENV_NAME) {
        return STATUS_INVALID_PARAMETER_2;
    }

    //
    // Search for the variable in the list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&processEnv->Base.Lock);

    for (entry = processEnv->Base.VariableList.Flink;
         entry != &processEnv->Base.VariableList;
         entry = entry->Flink) {

        envVar = CONTAINING_RECORD(entry, EM_ENV_VARIABLE, ListEntry);

        //
        // Case-insensitive comparison
        //
        if (_stricmp(envVar->Name, Name) == 0) {
            *Variable = envVar;
            break;
        }
    }

    ExReleasePushLockShared(&processEnv->Base.Lock);
    KeLeaveCriticalRegion();

    if (*Variable == NULL) {
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
EmFreeEnvironment(
    _In_ PEM_PROCESS_ENV Env
)
{
    PEM_PROCESS_ENV_INTERNAL processEnv;
    PEM_MONITOR_INTERNAL monitor;

    PAGED_CODE();

    if (Env == NULL) {
        return;
    }

    processEnv = CONTAINING_RECORD(Env, EM_PROCESS_ENV_INTERNAL, Base);

    if (processEnv->Magic != EM_ENV_ENTRY_MAGIC) {
        return;
    }

    monitor = processEnv->Monitor;

    if (monitor == NULL || monitor->Magic != EM_MONITOR_MAGIC) {
        //
        // No valid monitor - just free with pool tag
        //
        ShadowStrikeFreePoolWithTag(processEnv, EM_POOL_TAG);
        return;
    }

    //
    // Remove from cache if linked
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&monitor->Base.ProcessLock);

    if (!IsListEmpty(&processEnv->Base.ListEntry)) {
        RemoveEntryList(&processEnv->Base.ListEntry);
        InterlockedDecrement(&monitor->Base.ProcessCount);
    }

    ExReleasePushLockExclusive(&monitor->Base.ProcessLock);
    KeLeaveCriticalRegion();

    EmpFreeProcessEnvInternal(monitor, processEnv);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - REFERENCE COUNTING
// ============================================================================

static VOID
EmpAcquireReference(
    _Inout_ PEM_MONITOR_INTERNAL Monitor
)
{
    InterlockedIncrement(&Monitor->ReferenceCount);
}

static VOID
EmpReleaseReference(
    _Inout_ PEM_MONITOR_INTERNAL Monitor
)
{
    LONG newCount = InterlockedDecrement(&Monitor->ReferenceCount);

    if (newCount == 0 && Monitor->ShuttingDown) {
        KeSetEvent(&Monitor->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - ALLOCATION
// ============================================================================

static NTSTATUS
EmpAllocateEnvVariable(
    _In_ PEM_MONITOR_INTERNAL Monitor,
    _Out_ PEM_ENV_VARIABLE* Variable
)
{
    PEM_ENV_VARIABLE envVar = NULL;

    *Variable = NULL;

    if (Monitor->LookasideInitialized) {
        envVar = (PEM_ENV_VARIABLE)ExAllocateFromNPagedLookasideList(
            &Monitor->EnvVarLookaside
        );
    }

    if (envVar == NULL) {
        envVar = (PEM_ENV_VARIABLE)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(EM_ENV_VARIABLE),
            EM_ENV_VAR_TAG
        );
    }

    if (envVar == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(envVar, sizeof(EM_ENV_VARIABLE));
    InitializeListHead(&envVar->ListEntry);

    *Variable = envVar;

    return STATUS_SUCCESS;
}

static VOID
EmpFreeEnvVariable(
    _In_ PEM_MONITOR_INTERNAL Monitor,
    _In_ PEM_ENV_VARIABLE Variable
)
{
    if (Variable == NULL) {
        return;
    }

    if (Monitor != NULL && Monitor->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Monitor->EnvVarLookaside, Variable);
    } else {
        ShadowStrikeFreePoolWithTag(Variable, EM_ENV_VAR_TAG);
    }
}

static NTSTATUS
EmpAllocateProcessEnv(
    _In_ PEM_MONITOR_INTERNAL Monitor,
    _Out_ PEM_PROCESS_ENV_INTERNAL* ProcessEnv
)
{
    PEM_PROCESS_ENV_INTERNAL processEnv = NULL;

    *ProcessEnv = NULL;

    processEnv = (PEM_PROCESS_ENV_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(EM_PROCESS_ENV_INTERNAL),
        EM_POOL_TAG
    );

    if (processEnv == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(processEnv, sizeof(EM_PROCESS_ENV_INTERNAL));

    processEnv->Magic = EM_ENV_ENTRY_MAGIC;
    processEnv->Monitor = Monitor;
    processEnv->ReferenceCount = 1;

    InitializeListHead(&processEnv->Base.VariableList);
    KeInitializeSpinLock(&processEnv->Base.Lock);
    InitializeListHead(&processEnv->Base.ListEntry);
    InitializeListHead(&processEnv->CacheEntry);

    *ProcessEnv = processEnv;

    return STATUS_SUCCESS;
}

static VOID
EmpFreeProcessEnvInternal(
    _In_ PEM_MONITOR_INTERNAL Monitor,
    _In_ PEM_PROCESS_ENV_INTERNAL ProcessEnv
)
{
    PLIST_ENTRY entry;
    PEM_ENV_VARIABLE envVar;

    if (ProcessEnv == NULL) {
        return;
    }

    //
    // Free all environment variables
    //
    while (!IsListEmpty(&ProcessEnv->Base.VariableList)) {
        entry = RemoveHeadList(&ProcessEnv->Base.VariableList);
        envVar = CONTAINING_RECORD(entry, EM_ENV_VARIABLE, ListEntry);
        EmpFreeEnvVariable(Monitor, envVar);
    }

    ProcessEnv->Magic = 0;

    ShadowStrikeFreePoolWithTag(ProcessEnv, EM_POOL_TAG);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - ENVIRONMENT CAPTURE
// ============================================================================

static NTSTATUS
EmpCaptureEnvironmentBlock(
    _In_ HANDLE ProcessId,
    _Out_ PVOID* EnvironmentBlock,
    _Out_ PSIZE_T BlockSize
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    PPEB peb = NULL;
    PRTL_USER_PROCESS_PARAMETERS processParams = NULL;
    PVOID envBlock = NULL;
    SIZE_T envSize = 0;
    PVOID capturedBlock = NULL;
    BOOLEAN attached = FALSE;

    *EnvironmentBlock = NULL;
    *BlockSize = 0;

    //
    // Get process object
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Check if process is terminating
    //
    if (PsGetProcessExitStatus(process) != STATUS_PENDING) {
        ObDereferenceObject(process);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    __try {
        //
        // Attach to target process address space
        //
        KeStackAttachProcess(process, &apcState);
        attached = TRUE;

        //
        // Get PEB
        //
        peb = PsGetProcessPeb(process);
        if (peb == NULL) {
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        //
        // Probe PEB address
        //
        ProbeForRead(peb, sizeof(PEB), sizeof(ULONG));

        //
        // Get process parameters
        //
        processParams = peb->ProcessParameters;
        if (processParams == NULL) {
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        //
        // Probe process parameters
        //
        ProbeForRead(processParams, sizeof(RTL_USER_PROCESS_PARAMETERS), sizeof(ULONG));

        //
        // Get environment block
        //
        envBlock = processParams->Environment;
        if (envBlock == NULL) {
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        //
        // Calculate environment block size
        // Environment block is a series of null-terminated strings, ending with double null
        //
        envSize = 0;
        PWCHAR envPtr = (PWCHAR)envBlock;

        while (envSize < EM_MAX_ENV_BLOCK_SIZE) {
            ProbeForRead(envPtr, sizeof(WCHAR), sizeof(WCHAR));

            if (*envPtr == L'\0') {
                //
                // Check for double null (end of block)
                //
                envSize += sizeof(WCHAR);
                if (envSize >= EM_MAX_ENV_BLOCK_SIZE) {
                    break;
                }

                ProbeForRead(envPtr + 1, sizeof(WCHAR), sizeof(WCHAR));
                if (*(envPtr + 1) == L'\0') {
                    envSize += sizeof(WCHAR);
                    break;
                }
            }

            envSize += sizeof(WCHAR);
            envPtr++;

            //
            // Safety check
            //
            if (envSize >= EM_MAX_ENV_BLOCK_SIZE) {
                break;
            }
        }

        if (envSize == 0 || envSize > EM_MAX_ENV_BLOCK_SIZE) {
            status = STATUS_BUFFER_TOO_SMALL;
            __leave;
        }

        //
        // Allocate kernel buffer for environment block
        //
        capturedBlock = ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            envSize,
            EM_STRING_TAG
        );

        if (capturedBlock == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        //
        // Copy environment block to kernel memory
        //
        ProbeForRead(envBlock, envSize, sizeof(WCHAR));
        RtlCopyMemory(capturedBlock, envBlock, envSize);

        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();

        if (capturedBlock != NULL) {
            ShadowStrikeFreePoolWithTag(capturedBlock, EM_STRING_TAG);
            capturedBlock = NULL;
        }
    }

    if (attached) {
        KeUnstackDetachProcess(&apcState);
    }

    ObDereferenceObject(process);

    if (NT_SUCCESS(status)) {
        *EnvironmentBlock = capturedBlock;
        *BlockSize = envSize;
    }

    return status;
}

static NTSTATUS
EmpParseEnvironmentBlock(
    _In_ PEM_MONITOR_INTERNAL Monitor,
    _In_ PVOID EnvironmentBlock,
    _In_ SIZE_T BlockSize,
    _Inout_ PEM_PROCESS_ENV_INTERNAL ProcessEnv
)
{
    NTSTATUS status;
    PWCHAR envPtr = (PWCHAR)EnvironmentBlock;
    PWCHAR endPtr = (PWCHAR)((PUCHAR)EnvironmentBlock + BlockSize);
    PEM_ENV_VARIABLE envVar = NULL;
    ULONG variableCount = 0;
    PWCHAR equalSign;
    SIZE_T nameLength;
    SIZE_T valueLength;
    ANSI_STRING ansiName;
    ANSI_STRING ansiValue;
    UNICODE_STRING unicodeName;
    UNICODE_STRING unicodeValue;

    while (envPtr < endPtr && *envPtr != L'\0' && variableCount < EM_MAX_VARIABLES_PER_PROCESS) {
        //
        // Find the end of this environment string
        //
        PWCHAR stringEnd = envPtr;
        while (stringEnd < endPtr && *stringEnd != L'\0') {
            stringEnd++;
        }

        SIZE_T stringLength = (SIZE_T)(stringEnd - envPtr);

        if (stringLength == 0) {
            break;
        }

        //
        // Find the '=' separator
        //
        equalSign = NULL;
        for (PWCHAR p = envPtr; p < stringEnd; p++) {
            if (*p == L'=') {
                //
                // Skip if '=' is first character (special variables like =C:)
                //
                if (p != envPtr) {
                    equalSign = p;
                }
                break;
            }
        }

        if (equalSign == NULL) {
            //
            // Invalid format or special variable, skip
            //
            envPtr = stringEnd + 1;
            continue;
        }

        //
        // Calculate name and value lengths
        //
        nameLength = (SIZE_T)(equalSign - envPtr);
        valueLength = (SIZE_T)(stringEnd - equalSign - 1);

        if (nameLength == 0 || nameLength >= EM_MAX_ENV_NAME) {
            envPtr = stringEnd + 1;
            continue;
        }

        if (valueLength >= EM_MAX_ENV_VALUE) {
            valueLength = EM_MAX_ENV_VALUE - 1;
        }

        //
        // Allocate environment variable entry
        //
        status = EmpAllocateEnvVariable(Monitor, &envVar);
        if (!NT_SUCCESS(status)) {
            break;
        }

        //
        // Convert name from Unicode to ANSI
        //
        unicodeName.Buffer = envPtr;
        unicodeName.Length = (USHORT)(nameLength * sizeof(WCHAR));
        unicodeName.MaximumLength = unicodeName.Length;

        ansiName.Buffer = envVar->Name;
        ansiName.Length = 0;
        ansiName.MaximumLength = EM_MAX_ENV_NAME - 1;

        status = RtlUnicodeStringToAnsiString(&ansiName, &unicodeName, FALSE);
        if (!NT_SUCCESS(status)) {
            EmpFreeEnvVariable(Monitor, envVar);
            envPtr = stringEnd + 1;
            continue;
        }
        envVar->Name[ansiName.Length] = '\0';

        //
        // Convert value from Unicode to ANSI
        //
        unicodeValue.Buffer = equalSign + 1;
        unicodeValue.Length = (USHORT)(valueLength * sizeof(WCHAR));
        unicodeValue.MaximumLength = unicodeValue.Length;

        ansiValue.Buffer = envVar->Value;
        ansiValue.Length = 0;
        ansiValue.MaximumLength = EM_MAX_ENV_VALUE - 1;

        status = RtlUnicodeStringToAnsiString(&ansiValue, &unicodeValue, FALSE);
        if (!NT_SUCCESS(status)) {
            EmpFreeEnvVariable(Monitor, envVar);
            envPtr = stringEnd + 1;
            continue;
        }
        envVar->Value[ansiValue.Length] = '\0';

        //
        // Set timestamp
        //
        KeQuerySystemTime(&envVar->LastModified);

        //
        // Determine if this is a system variable
        //
        envVar->IsSystemVariable = FALSE;
        for (ULONG i = 0; i < ARRAYSIZE(g_DllVariables); i++) {
            if (EmpCompareEnvironmentVariable(envVar->Name, g_DllVariables[i])) {
                envVar->IsSystemVariable = TRUE;
                break;
            }
        }

        //
        // Check for PATH variable and analyze it
        //
        if (_stricmp(envVar->Name, "PATH") == 0) {
            EmpAnalyzePathVariable(ProcessEnv, envVar->Value);
        }

        //
        // Check for encoded values
        //
        if (EmpIsEncodedValue(envVar->Value, strlen(envVar->Value))) {
            ProcessEnv->EncodedValueCount++;
        }

        //
        // Check entropy
        //
        float entropy = EmpCalculateEntropy(envVar->Value, strlen(envVar->Value));
        if (entropy > EM_ENTROPY_THRESHOLD) {
            ProcessEnv->HighEntropyCount++;
        }

        //
        // Add to variable list
        //
        InsertTailList(&ProcessEnv->Base.VariableList, &envVar->ListEntry);
        variableCount++;

        //
        // Move to next environment string
        //
        envPtr = stringEnd + 1;
    }

    ProcessEnv->Base.VariableCount = variableCount;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - PATH ANALYSIS
// ============================================================================

static NTSTATUS
EmpAnalyzePathVariable(
    _In_ PEM_PROCESS_ENV_INTERNAL ProcessEnv,
    _In_ PCSTR PathValue
)
{
    PCHAR pathCopy = NULL;
    PCHAR token;
    PCHAR nextToken;
    SIZE_T pathLength;
    ULONG entryCount = 0;
    WCHAR widePath[MAX_PATH];
    ANSI_STRING ansiPath;
    UNICODE_STRING unicodePath;
    NTSTATUS status;

    if (PathValue == NULL || PathValue[0] == '\0') {
        return STATUS_SUCCESS;
    }

    pathLength = strlen(PathValue);
    if (pathLength >= EM_MAX_ENV_VALUE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Make a copy of PATH for tokenization
    //
    pathCopy = (PCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        pathLength + 1,
        EM_PATH_TAG
    );

    if (pathCopy == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(pathCopy, PathValue, pathLength + 1);

    //
    // Parse PATH entries (semicolon-separated)
    //
    token = pathCopy;
    while (token != NULL && entryCount < EM_MAX_PATH_ENTRIES) {
        //
        // Find next semicolon
        //
        nextToken = strchr(token, ';');
        if (nextToken != NULL) {
            *nextToken = '\0';
            nextToken++;
        }

        //
        // Skip empty entries
        //
        if (token[0] == '\0') {
            token = nextToken;
            continue;
        }

        //
        // Convert to wide string for analysis
        //
        RtlInitAnsiString(&ansiPath, token);
        unicodePath.Buffer = widePath;
        unicodePath.Length = 0;
        unicodePath.MaximumLength = sizeof(widePath) - sizeof(WCHAR);

        status = RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, FALSE);
        if (NT_SUCCESS(status)) {
            widePath[unicodePath.Length / sizeof(WCHAR)] = L'\0';

            //
            // Analyze this path entry
            //
            if (EmpIsWritablePath(widePath)) {
                ProcessEnv->HasWritablePathEntry = TRUE;
            }

            if (EmpIsUserPath(widePath)) {
                ProcessEnv->HasUserPathEntry = TRUE;
            }

            if (EmpIsSuspiciousPath(widePath)) {
                ProcessEnv->HasSuspiciousPathEntry = TRUE;
            }

            entryCount++;
        }

        token = nextToken;
    }

    ProcessEnv->PathEntryCount = entryCount;

    ShadowStrikeFreePoolWithTag(pathCopy, EM_PATH_TAG);

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - PROXY ANALYSIS
// ============================================================================

static NTSTATUS
EmpAnalyzeProxySettings(
    _In_ PEM_PROCESS_ENV_INTERNAL ProcessEnv
)
{
    PLIST_ENTRY entry;
    PEM_ENV_VARIABLE envVar;
    BOOLEAN foundProxy = FALSE;

    for (entry = ProcessEnv->Base.VariableList.Flink;
         entry != &ProcessEnv->Base.VariableList;
         entry = entry->Flink) {

        envVar = CONTAINING_RECORD(entry, EM_ENV_VARIABLE, ListEntry);

        for (ULONG i = 0; i < ARRAYSIZE(g_ProxyVariables); i++) {
            if (EmpCompareEnvironmentVariable(envVar->Name, g_ProxyVariables[i])) {
                foundProxy = TRUE;
                ProcessEnv->HasProxySettings = TRUE;

                //
                // Check if proxy points to localhost (potential credential interception)
                //
                if (strstr(envVar->Value, "127.0.0.1") != NULL ||
                    strstr(envVar->Value, "localhost") != NULL ||
                    strstr(envVar->Value, "::1") != NULL) {
                    ProcessEnv->ProxyIsLocalhost = TRUE;
                    ProcessEnv->ProxyIsSuspicious = TRUE;
                }

                //
                // Check for unusual ports
                //
                PCHAR colonPos = strrchr(envVar->Value, ':');
                if (colonPos != NULL) {
                    int port = atoi(colonPos + 1);
                    if (port != 80 && port != 443 && port != 8080 && port != 3128) {
                        ProcessEnv->ProxyIsSuspicious = TRUE;
                    }
                }

                break;
            }
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - TEMP ANALYSIS
// ============================================================================

static NTSTATUS
EmpAnalyzeTempOverrides(
    _In_ PEM_PROCESS_ENV_INTERNAL ProcessEnv
)
{
    PLIST_ENTRY entry;
    PEM_ENV_VARIABLE envVar;
    WCHAR widePath[MAX_PATH];
    ANSI_STRING ansiPath;
    UNICODE_STRING unicodePath;
    NTSTATUS status;

    for (entry = ProcessEnv->Base.VariableList.Flink;
         entry != &ProcessEnv->Base.VariableList;
         entry = entry->Flink) {

        envVar = CONTAINING_RECORD(entry, EM_ENV_VARIABLE, ListEntry);

        for (ULONG i = 0; i < ARRAYSIZE(g_TempVariables); i++) {
            if (EmpCompareEnvironmentVariable(envVar->Name, g_TempVariables[i])) {
                //
                // Convert value to wide string for path analysis
                //
                RtlInitAnsiString(&ansiPath, envVar->Value);
                unicodePath.Buffer = widePath;
                unicodePath.Length = 0;
                unicodePath.MaximumLength = sizeof(widePath) - sizeof(WCHAR);

                status = RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, FALSE);
                if (NT_SUCCESS(status)) {
                    widePath[unicodePath.Length / sizeof(WCHAR)] = L'\0';

                    //
                    // Check if TEMP points to unexpected location
                    //
                    if (!EmpIsSystemPath(widePath)) {
                        ProcessEnv->HasTempOverride = TRUE;

                        if (EmpIsWritablePath(widePath)) {
                            ProcessEnv->TempPointsToWritable = TRUE;
                        }
                    }
                }

                break;
            }
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - ENCODING DETECTION
// ============================================================================

static BOOLEAN
EmpIsEncodedValue(
    _In_ PCSTR Value,
    _In_ SIZE_T ValueLength
)
{
    if (ValueLength < 8) {
        return FALSE;
    }

    //
    // Check for Base64 encoding
    //
    if (EmpIsBase64Encoded(Value, ValueLength)) {
        return TRUE;
    }

    //
    // Check for hex encoding
    //
    if (EmpIsHexEncoded(Value, ValueLength)) {
        return TRUE;
    }

    return FALSE;
}

static float
EmpCalculateEntropy(
    _In_ PCSTR Data,
    _In_ SIZE_T Length
)
{
    ULONG frequency[256] = { 0 };
    float entropy = 0.0f;
    ULONG i;

    if (Length == 0) {
        return 0.0f;
    }

    //
    // Count byte frequencies
    //
    for (i = 0; i < Length; i++) {
        frequency[(UCHAR)Data[i]]++;
    }

    //
    // Calculate Shannon entropy
    //
    for (i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            float probability = (float)frequency[i] / (float)Length;
            //
            // entropy -= p * log2(p)
            // Using natural log and converting: log2(x) = ln(x) / ln(2)
            //
            float logVal = 0.0f;

            //
            // Approximate log2(probability) using integer math
            // For kernel mode, avoid floating point log functions
            // Use a lookup table approximation
            //
            ULONG invP = (ULONG)(1.0f / probability);
            ULONG log2Approx = 0;
            while (invP > 1) {
                invP >>= 1;
                log2Approx++;
            }

            entropy += probability * (float)log2Approx;
        }
    }

    return entropy;
}

static BOOLEAN
EmpIsBase64Encoded(
    _In_ PCSTR Value,
    _In_ SIZE_T ValueLength
)
{
    ULONG validChars = 0;
    ULONG paddingCount = 0;
    BOOLEAN hasInvalidChar = FALSE;

    if (ValueLength < 4) {
        return FALSE;
    }

    //
    // Check if value looks like Base64
    //
    for (SIZE_T i = 0; i < ValueLength; i++) {
        CHAR c = Value[i];

        if ((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '+' || c == '/') {
            validChars++;
        } else if (c == '=') {
            paddingCount++;
        } else if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            // Whitespace is allowed
        } else {
            hasInvalidChar = TRUE;
            break;
        }
    }

    if (hasInvalidChar) {
        return FALSE;
    }

    //
    // Base64 should be mostly valid chars with 0-2 padding at end
    //
    if (paddingCount > 2) {
        return FALSE;
    }

    //
    // At least 80% valid Base64 chars and length divisible by 4
    //
    if ((validChars + paddingCount) >= (ValueLength * 8 / 10) &&
        ((validChars + paddingCount) % 4) == 0 &&
        validChars >= 16) {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
EmpIsHexEncoded(
    _In_ PCSTR Value,
    _In_ SIZE_T ValueLength
)
{
    ULONG hexChars = 0;

    if (ValueLength < 8) {
        return FALSE;
    }

    //
    // Check if value is all hex digits
    //
    for (SIZE_T i = 0; i < ValueLength; i++) {
        CHAR c = Value[i];

        if ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'F') ||
            (c >= 'a' && c <= 'f')) {
            hexChars++;
        } else if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            // Whitespace is allowed
        } else {
            return FALSE;
        }
    }

    //
    // Must be even number of hex chars (complete bytes) and at least 16 chars
    //
    if (hexChars >= 16 && (hexChars % 2) == 0) {
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - PATH ANALYSIS HELPERS
// ============================================================================

static BOOLEAN
EmpIsWritablePath(
    _In_ PCWSTR Path
)
{
    //
    // Check for user-writable directories in PATH
    //
    for (ULONG i = 0; i < ARRAYSIZE(g_SuspiciousPathDirs); i++) {
        if (wcsstr(Path, g_SuspiciousPathDirs[i]) != NULL) {
            return TRUE;
        }
    }

    //
    // Check for current directory placeholder
    //
    if (Path[0] == L'.' && (Path[1] == L'\0' || Path[1] == L'\\' || Path[1] == L';')) {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
EmpIsUserPath(
    _In_ PCWSTR Path
)
{
    //
    // Check if path is under user profile
    //
    if (wcsstr(Path, L"\\Users\\") != NULL) {
        return TRUE;
    }

    if (wcsstr(Path, L"\\AppData\\") != NULL) {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
EmpIsSuspiciousPath(
    _In_ PCWSTR Path
)
{
    //
    // Check for paths that are commonly abused for DLL hijacking
    //

    //
    // Network paths at start of PATH are suspicious
    //
    if (Path[0] == L'\\' && Path[1] == L'\\') {
        return TRUE;
    }

    //
    // Relative paths are suspicious
    //
    if (Path[0] != L'\\' && (Path[1] != L':' || Path[2] != L'\\')) {
        return TRUE;
    }

    //
    // Known malware staging directories
    //
    if (wcsstr(Path, L"\\ProgramData\\") != NULL) {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
EmpIsSystemPath(
    _In_ PCWSTR Path
)
{
    //
    // Check if path is a system directory
    //
    if (wcsstr(Path, L"\\Windows\\") != NULL) {
        return TRUE;
    }

    if (wcsstr(Path, L"\\System32\\") != NULL) {
        return TRUE;
    }

    if (wcsstr(Path, L"\\SysWOW64\\") != NULL) {
        return TRUE;
    }

    if (wcsstr(Path, L"\\Program Files\\") != NULL) {
        return TRUE;
    }

    if (wcsstr(Path, L"\\Program Files (x86)\\") != NULL) {
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - SUSPICION DETECTION
// ============================================================================

static EM_SUSPICION
EmpDetectSuspiciousConditions(
    _In_ PEM_PROCESS_ENV_INTERNAL ProcessEnv
)
{
    EM_SUSPICION flags = EmSuspicion_None;

    //
    // Check PATH modifications
    //
    if (ProcessEnv->HasWritablePathEntry || ProcessEnv->HasUserPathEntry) {
        flags |= EmSuspicion_ModifiedPath;
    }

    if (ProcessEnv->HasSuspiciousPathEntry) {
        flags |= EmSuspicion_DLLSearchOrder;
    }

    //
    // Check proxy settings
    //
    if (ProcessEnv->HasProxySettings && ProcessEnv->ProxyIsSuspicious) {
        flags |= EmSuspicion_ProxySettings;
    }

    //
    // Check TEMP overrides
    //
    if (ProcessEnv->HasTempOverride) {
        flags |= EmSuspicion_TempOverride;
    }

    //
    // Check for encoded values
    //
    if (ProcessEnv->EncodedValueCount > 0 || ProcessEnv->HighEntropyCount > 2) {
        flags |= EmSuspicion_EncodedValue;
    }

    //
    // Check variable count (unusually high might indicate injection)
    //
    if (ProcessEnv->Base.VariableCount > 500) {
        flags |= EmSuspicion_HiddenVariable;
    }

    return flags;
}

static ULONG
EmpCalculateSuspicionScore(
    _In_ PEM_PROCESS_ENV_INTERNAL ProcessEnv,
    _In_ EM_SUSPICION Flags
)
{
    ULONG score = 0;

    //
    // Score based on suspicion flags
    //
    if (Flags & EmSuspicion_ModifiedPath) {
        score += 25;
    }

    if (Flags & EmSuspicion_DLLSearchOrder) {
        score += 40;
    }

    if (Flags & EmSuspicion_ProxySettings) {
        score += 35;
    }

    if (Flags & EmSuspicion_TempOverride) {
        score += 20;
    }

    if (Flags & EmSuspicion_HiddenVariable) {
        score += 15;
    }

    if (Flags & EmSuspicion_EncodedValue) {
        score += 30;
    }

    //
    // Additional scoring based on detailed analysis
    //
    if (ProcessEnv->ProxyIsLocalhost) {
        score += 20;
    }

    if (ProcessEnv->EncodedValueCount > 3) {
        score += 15;
    }

    if (ProcessEnv->HighEntropyCount > 5) {
        score += 15;
    }

    if (ProcessEnv->TempPointsToWritable) {
        score += 10;
    }

    //
    // Cap at 100
    //
    if (score > 100) {
        score = 100;
    }

    return score;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - CACHE MANAGEMENT
// ============================================================================

static VOID
EmpCleanupExpiredCacheEntries(
    _Inout_ PEM_MONITOR_INTERNAL Monitor
)
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PEM_PROCESS_ENV_INTERNAL processEnv;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER expiryThreshold;

    KeQuerySystemTime(&currentTime);
    expiryThreshold.QuadPart = currentTime.QuadPart - EM_CACHE_EXPIRY_TIME;

    //
    // Lock should already be held by caller
    //

    for (entry = Monitor->Base.ProcessList.Flink;
         entry != &Monitor->Base.ProcessList;
         entry = nextEntry) {

        nextEntry = entry->Flink;

        processEnv = CONTAINING_RECORD(entry, EM_PROCESS_ENV_INTERNAL, Base.ListEntry);

        if (processEnv->CacheTime.QuadPart < expiryThreshold.QuadPart) {
            RemoveEntryList(&processEnv->Base.ListEntry);
            InitializeListHead(&processEnv->Base.ListEntry);
            EmpFreeProcessEnvInternal(Monitor, processEnv);
            InterlockedDecrement(&Monitor->Base.ProcessCount);
        }
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - UTILITY FUNCTIONS
// ============================================================================

static BOOLEAN
EmpCompareEnvironmentVariable(
    _In_ PCSTR Name,
    _In_ PCWSTR Target
)
{
    WCHAR wideName[EM_MAX_ENV_NAME];
    ANSI_STRING ansiName;
    UNICODE_STRING unicodeName;
    UNICODE_STRING unicodeTarget;
    NTSTATUS status;

    RtlInitAnsiString(&ansiName, Name);
    unicodeName.Buffer = wideName;
    unicodeName.Length = 0;
    unicodeName.MaximumLength = sizeof(wideName) - sizeof(WCHAR);

    status = RtlAnsiStringToUnicodeString(&unicodeName, &ansiName, FALSE);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    RtlInitUnicodeString(&unicodeTarget, Target);

    return RtlEqualUnicodeString(&unicodeName, &unicodeTarget, TRUE);
}
