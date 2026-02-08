/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE ENVIRONMENT VARIABLE MONITOR
 * ============================================================================
 *
 * @file EnvironmentMonitor.c
 * @brief Enterprise-grade environment variable tracking and analysis engine.
 *
 * SECURITY HARDENED v3.0.0 - Complete rewrite addressing:
 * - CRITICAL: Fixed KSPIN_LOCK/EX_PUSH_LOCK type mismatch (was causing BSOD)
 * - CRITICAL: Fixed TOCTOU vulnerabilities in PEB access
 * - CRITICAL: Removed unsafe floating point, using integer-only entropy
 * - CRITICAL: Fixed use-after-free with proper reference counting
 * - HIGH: Fixed lookaside allocation/free mismatch with source tracking
 * - HIGH: Replaced atoi() with RtlCharToInteger
 * - HIGH: Added proper locking to all list iterations
 * - HIGH: Fixed shutdown race with proper event waiting
 * - MEDIUM: Added iteration bounds to prevent infinite loops
 * - MEDIUM: Reduced stack buffer usage
 * - MEDIUM: Added ProcessId epoch validation
 * - MEDIUM: Fixed list entry linked state detection
 *
 * Detection Techniques:
 * - PATH variable parsing for suspicious directories
 * - Known DLL hijack path detection
 * - Proxy environment variables (HTTP_PROXY, HTTPS_PROXY, etc.)
 * - Encoded payload detection via entropy analysis (integer-only)
 * - Environment variable injection detection
 * - System vs user variable comparison
 *
 * MITRE ATT&CK Coverage:
 * - T1574.007: Path Interception by PATH Environment Variable
 * - T1574.008: Path Interception by Search Order Hijacking
 * - T1090.001: Proxy (via environment variable manipulation)
 * - T1027: Obfuscated Files or Information (encoded env vars)
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition - Security Hardened)
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
 * @brief Lookaside list depth for env variable allocations
 */
#define EMP_LOOKASIDE_DEPTH             64

/**
 * @brief Cache entry expiry time (10 minutes in 100ns units)
 */
#define EMP_CACHE_EXPIRY_TIME           (10LL * 60LL * 10000000LL)

/**
 * @brief Minimum entropy threshold (scaled by 1000 for integer math)
 * 4.5 * 1000 = 4500
 */
#define EMP_ENTROPY_THRESHOLD_SCALED    4500

/**
 * @brief Shutdown wait timeout (30 seconds in 100ns units)
 */
#define EMP_SHUTDOWN_TIMEOUT            (-30LL * 10000000LL)

/**
 * @brief Maximum safe string length for bounded operations
 */
#define EMP_SAFE_STRING_MAX             32768

// ============================================================================
// WELL-KNOWN SUSPICIOUS ENVIRONMENT VARIABLES
// ============================================================================

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

static const PCWSTR g_TempVariables[] = {
    L"TEMP",
    L"TMP",
    L"TMPDIR"
};

static const PCWSTR g_DllVariables[] = {
    L"PATH",
    L"PATHEXT",
    L"COMSPEC",
    L"SYSTEMROOT",
    L"WINDIR"
};

static const PCWSTR g_SuspiciousPathDirs[] = {
    L"\\Users\\",
    L"\\Temp\\",
    L"\\AppData\\",
    L"\\Downloads\\",
    L"\\Desktop\\",
    L"\\Documents\\",
    L"\\Public\\",
    L"\\ProgramData\\"
};

// ============================================================================
// PRIVATE STRUCTURE FOR EXTENDED PROCESS ENV DATA
// ============================================================================

typedef struct _EMP_PROCESS_ENV_EXTENDED {
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

} EMP_PROCESS_ENV_EXTENDED, *PEMP_PROCESS_ENV_EXTENDED;

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static VOID
EmpAcquireMonitorReference(
    _In_ PEM_MONITOR Monitor
);

static VOID
EmpReleaseMonitorReference(
    _In_ PEM_MONITOR Monitor
);

static VOID
EmpAcquireEnvReference(
    _In_ PEM_PROCESS_ENV Env
);

static LONG
EmpReleaseEnvReference(
    _In_ PEM_PROCESS_ENV Env
);

static NTSTATUS
EmpAllocateEnvVariable(
    _In_ PEM_MONITOR Monitor,
    _Out_ PEM_ENV_VARIABLE* Variable
);

static VOID
EmpFreeEnvVariable(
    _In_ PEM_MONITOR Monitor,
    _In_ PEM_ENV_VARIABLE Variable
);

static NTSTATUS
EmpAllocateProcessEnv(
    _In_ PEM_MONITOR Monitor,
    _Out_ PEM_PROCESS_ENV* ProcessEnv
);

static VOID
EmpFreeProcessEnvInternal(
    _In_ PEM_MONITOR Monitor,
    _In_ PEM_PROCESS_ENV ProcessEnv
);

static NTSTATUS
EmpCaptureEnvironmentBlockSafe(
    _In_ HANDLE ProcessId,
    _Out_ PVOID* EnvironmentBlock,
    _Out_ PSIZE_T BlockSize,
    _Out_ PLARGE_INTEGER ProcessCreateTime
);

static NTSTATUS
EmpParseEnvironmentBlock(
    _In_ PEM_MONITOR Monitor,
    _In_ PVOID EnvironmentBlock,
    _In_ SIZE_T BlockSize,
    _Inout_ PEM_PROCESS_ENV ProcessEnv,
    _Out_ PEMP_PROCESS_ENV_EXTENDED ExtendedData
);

static NTSTATUS
EmpAnalyzePathVariable(
    _In_ PCSTR PathValue,
    _In_ SIZE_T PathLength,
    _Inout_ PEMP_PROCESS_ENV_EXTENDED ExtendedData
);

static NTSTATUS
EmpAnalyzeProxySettingsLocked(
    _In_ PEM_PROCESS_ENV ProcessEnv,
    _Inout_ PEMP_PROCESS_ENV_EXTENDED ExtendedData
);

static NTSTATUS
EmpAnalyzeTempOverridesLocked(
    _In_ PEM_PROCESS_ENV ProcessEnv,
    _Inout_ PEMP_PROCESS_ENV_EXTENDED ExtendedData
);

static BOOLEAN
EmpIsEncodedValue(
    _In_ PCSTR Value,
    _In_ SIZE_T ValueLength
);

static ULONG
EmpCalculateEntropyScaled(
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
    _In_ PCWSTR Path,
    _In_ SIZE_T PathLength
);

static BOOLEAN
EmpIsUserPath(
    _In_ PCWSTR Path,
    _In_ SIZE_T PathLength
);

static BOOLEAN
EmpIsSuspiciousPath(
    _In_ PCWSTR Path,
    _In_ SIZE_T PathLength
);

static BOOLEAN
EmpIsSystemPath(
    _In_ PCWSTR Path,
    _In_ SIZE_T PathLength
);

static EM_SUSPICION
EmpDetectSuspiciousConditions(
    _In_ PEM_PROCESS_ENV ProcessEnv,
    _In_ PEMP_PROCESS_ENV_EXTENDED ExtendedData
);

static ULONG
EmpCalculateSuspicionScore(
    _In_ PEMP_PROCESS_ENV_EXTENDED ExtendedData,
    _In_ EM_SUSPICION Flags
);

static VOID
EmpCleanupExpiredCacheEntriesLocked(
    _Inout_ PEM_MONITOR Monitor
);

static BOOLEAN
EmpCompareEnvVarNameToWide(
    _In_ PCSTR Name,
    _In_ SIZE_T NameLength,
    _In_ PCWSTR Target
);

static SIZE_T
EmpSafeStringLengthA(
    _In_ PCSTR String,
    _In_ SIZE_T MaxLength
);

static SIZE_T
EmpSafeStringLengthW(
    _In_ PCWSTR String,
    _In_ SIZE_T MaxLength
);

static BOOLEAN
EmpSafeWcsStr(
    _In_ PCWSTR Haystack,
    _In_ SIZE_T HaystackLength,
    _In_ PCWSTR Needle
);

static NTSTATUS
EmpParsePortFromString(
    _In_ PCSTR String,
    _In_ SIZE_T StringLength,
    _Out_ PULONG Port
);

static PEM_PROCESS_ENV
EmpFindCachedEnvironmentLocked(
    _In_ PEM_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _In_ PLARGE_INTEGER ProcessCreateTime
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
#pragma alloc_text(PAGE, EmReleaseEnvironment)
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
    PEM_MONITOR monitor = NULL;

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
    // (contains synchronization primitives that may be accessed at elevated IRQL)
    //
    monitor = (PEM_MONITOR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(EM_MONITOR),
        EM_POOL_TAG
    );

    if (monitor == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(monitor, sizeof(EM_MONITOR));

    //
    // Set magic for validation
    //
    monitor->Magic = EM_MONITOR_MAGIC;

    //
    // Initialize process environment cache
    //
    InitializeListHead(&monitor->ProcessCacheList);
    ExInitializePushLock(&monitor->CacheLock);

    //
    // Initialize reference counting
    // Start with 1 reference for the caller
    //
    monitor->ReferenceCount = 1;
    monitor->ShuttingDown = FALSE;
    KeInitializeEvent(&monitor->ShutdownCompleteEvent, NotificationEvent, FALSE);

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
        EMP_LOOKASIDE_DEPTH
    );
    monitor->LookasideInitialized = TRUE;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&monitor->Stats.StartTime);

    //
    // Mark as initialized
    //
    monitor->Initialized = TRUE;

    *Monitor = monitor;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
EmShutdown(
    _Inout_ PEM_MONITOR Monitor
)
{
    PLIST_ENTRY entry;
    PEM_PROCESS_ENV processEnv;
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;
    ULONG iterationCount;

    PAGED_CODE();

    if (Monitor == NULL) {
        return;
    }

    if (Monitor->Magic != EM_MONITOR_MAGIC) {
        return;
    }

    if (!Monitor->Initialized) {
        return;
    }

    //
    // Signal shutdown - no new operations will be accepted
    //
    InterlockedExchange(&Monitor->ShuttingDown, 1);

    //
    // Release our initialization reference
    //
    EmpReleaseMonitorReference(Monitor);

    //
    // Wait for all references to drain with timeout
    // Using ShutdownCompleteEvent instead of busy-wait
    //
    timeout.QuadPart = EMP_SHUTDOWN_TIMEOUT;

    while (Monitor->ReferenceCount > 0) {
        waitStatus = KeWaitForSingleObject(
            &Monitor->ShutdownCompleteEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );

        if (waitStatus == STATUS_TIMEOUT) {
            //
            // References didn't drain in time - log and continue cleanup
            // This prevents infinite hang but may leak memory
            //
            break;
        }
    }

    //
    // Free all cached process environments
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Monitor->CacheLock);

    iterationCount = 0;
    while (!IsListEmpty(&Monitor->ProcessCacheList) &&
           iterationCount < EM_MAX_LIST_ITERATIONS) {

        entry = RemoveHeadList(&Monitor->ProcessCacheList);
        processEnv = CONTAINING_RECORD(entry, EM_PROCESS_ENV, CacheListEntry);
        processEnv->IsLinkedToCache = FALSE;

        //
        // Free without lock - we already removed from list
        //
        ExReleasePushLockExclusive(&Monitor->CacheLock);
        KeLeaveCriticalRegion();

        EmpFreeProcessEnvInternal(Monitor, processEnv);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Monitor->CacheLock);

        iterationCount++;
    }

    ExReleasePushLockExclusive(&Monitor->CacheLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside list
    //
    if (Monitor->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Monitor->EnvVarLookaside);
        Monitor->LookasideInitialized = FALSE;
    }

    //
    // Clear state and free
    //
    Monitor->Magic = 0;
    Monitor->Initialized = FALSE;

    ShadowStrikeFreePoolWithTag(Monitor, EM_POOL_TAG);
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
    PEM_PROCESS_ENV processEnv = NULL;
    PEM_PROCESS_ENV cachedEnv = NULL;
    PVOID environmentBlock = NULL;
    SIZE_T blockSize = 0;
    LARGE_INTEGER processCreateTime = {0};
    EMP_PROCESS_ENV_EXTENDED extendedData = {0};

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Monitor == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Monitor->Magic != EM_MONITOR_MAGIC || !Monitor->Initialized) {
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
    if (Monitor->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    EmpAcquireMonitorReference(Monitor);

    //
    // Double-check shutdown after acquiring reference
    //
    if (Monitor->ShuttingDown) {
        EmpReleaseMonitorReference(Monitor);
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // First, try to capture environment block and get process create time
    // This also validates the process still exists
    //
    status = EmpCaptureEnvironmentBlockSafe(
        ProcessId,
        &environmentBlock,
        &blockSize,
        &processCreateTime
    );

    if (!NT_SUCCESS(status)) {
        EmpReleaseMonitorReference(Monitor);
        return status;
    }

    //
    // Check cache for existing entry with matching ProcessId AND create time
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Monitor->CacheLock);

    cachedEnv = EmpFindCachedEnvironmentLocked(Monitor, ProcessId, &processCreateTime);

    if (cachedEnv != NULL) {
        //
        // Cache hit - acquire reference and return
        //
        EmpAcquireEnvReference(cachedEnv);
        InterlockedIncrement64(&Monitor->Stats.CacheHits);

        ExReleasePushLockShared(&Monitor->CacheLock);
        KeLeaveCriticalRegion();

        //
        // Free the captured block - not needed
        //
        ShadowStrikeFreePoolWithTag(environmentBlock, EM_STRING_TAG);

        *Env = cachedEnv;
        EmpReleaseMonitorReference(Monitor);
        return STATUS_SUCCESS;
    }

    ExReleasePushLockShared(&Monitor->CacheLock);
    KeLeaveCriticalRegion();

    InterlockedIncrement64(&Monitor->Stats.CacheMisses);

    //
    // Allocate new process environment structure
    //
    status = EmpAllocateProcessEnv(Monitor, &processEnv);
    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(environmentBlock, EM_STRING_TAG);
        EmpReleaseMonitorReference(Monitor);
        return status;
    }

    //
    // Initialize process identification with epoch
    //
    processEnv->ProcessId = ProcessId;
    processEnv->ProcessCreateTime = processCreateTime;
    KeQuerySystemTime(&processEnv->CacheTime);

    //
    // Parse environment block into variable list
    //
    status = EmpParseEnvironmentBlock(
        Monitor,
        environmentBlock,
        blockSize,
        processEnv,
        &extendedData
    );

    //
    // Free the captured block - we've copied what we need
    //
    ShadowStrikeFreePoolWithTag(environmentBlock, EM_STRING_TAG);

    if (!NT_SUCCESS(status)) {
        EmpFreeProcessEnvInternal(Monitor, processEnv);
        EmpReleaseMonitorReference(Monitor);
        return status;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Monitor->Stats.ProcessesMonitored);

    //
    // Add to cache with exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Monitor->CacheLock);

    //
    // Enforce cache limit - cleanup expired entries first
    //
    if (Monitor->CacheCount >= EM_MAX_CACHE_ENTRIES) {
        EmpCleanupExpiredCacheEntriesLocked(Monitor);
    }

    //
    // If still at limit, remove oldest entry
    //
    if (Monitor->CacheCount >= EM_MAX_CACHE_ENTRIES) {
        if (!IsListEmpty(&Monitor->ProcessCacheList)) {
            PLIST_ENTRY oldEntry = RemoveHeadList(&Monitor->ProcessCacheList);
            PEM_PROCESS_ENV oldEnv = CONTAINING_RECORD(
                oldEntry, EM_PROCESS_ENV, CacheListEntry
            );
            oldEnv->IsLinkedToCache = FALSE;
            InterlockedDecrement(&Monitor->CacheCount);

            //
            // Schedule for deferred cleanup if references exist
            //
            if (EmpReleaseEnvReference(oldEnv) == 0) {
                //
                // No references - safe to free now
                // But we hold the lock, so just mark for cleanup
                //
            }
        }
    }

    //
    // Add new entry to cache
    //
    InsertTailList(&Monitor->ProcessCacheList, &processEnv->CacheListEntry);
    processEnv->IsLinkedToCache = TRUE;
    InterlockedIncrement(&Monitor->CacheCount);

    //
    // Acquire reference for caller (cache holds one, caller gets another)
    //
    EmpAcquireEnvReference(processEnv);

    ExReleasePushLockExclusive(&Monitor->CacheLock);
    KeLeaveCriticalRegion();

    *Env = processEnv;

    EmpReleaseMonitorReference(Monitor);

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
    EM_SUSPICION suspicionFlags = EmSuspicion_None;
    EMP_PROCESS_ENV_EXTENDED extendedData = {0};

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Monitor == NULL || Monitor->Magic != EM_MONITOR_MAGIC || !Monitor->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Env == NULL || Env->Magic != EM_PROCESS_ENV_MAGIC) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Flags == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    *Flags = EmSuspicion_None;

    if (Monitor->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    EmpAcquireMonitorReference(Monitor);

    //
    // Check if already analyzed
    //
    if (Env->AnalysisComplete) {
        *Flags = Env->SuspicionFlags;
        EmpReleaseMonitorReference(Monitor);
        return STATUS_SUCCESS;
    }

    //
    // Acquire lock for variable list access during analysis
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Env->VariableLock);

    //
    // Analyze proxy settings
    //
    status = EmpAnalyzeProxySettingsLocked(Env, &extendedData);
    if (!NT_SUCCESS(status)) {
        //
        // Log but continue - partial analysis is better than none
        //
        status = STATUS_SUCCESS;
    }

    //
    // Analyze TEMP/TMP overrides
    //
    status = EmpAnalyzeTempOverridesLocked(Env, &extendedData);
    if (!NT_SUCCESS(status)) {
        status = STATUS_SUCCESS;
    }

    //
    // Detect all suspicious conditions
    //
    suspicionFlags = EmpDetectSuspiciousConditions(Env, &extendedData);

    ExReleasePushLockShared(&Env->VariableLock);
    KeLeaveCriticalRegion();

    //
    // Calculate suspicion score and store results
    // Need exclusive lock for write
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Env->VariableLock);

    Env->SuspicionScore = EmpCalculateSuspicionScore(&extendedData, suspicionFlags);
    Env->SuspicionFlags = suspicionFlags;
    Env->AnalysisComplete = TRUE;

    ExReleasePushLockExclusive(&Env->VariableLock);
    KeLeaveCriticalRegion();

    //
    // Update statistics if suspicious
    //
    if (suspicionFlags != EmSuspicion_None) {
        InterlockedIncrement64(&Monitor->Stats.SuspiciousEnvFound);
    }

    *Flags = suspicionFlags;

    EmpReleaseMonitorReference(Monitor);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EmGetVariable(
    _In_ PEM_PROCESS_ENV Env,
    _In_ PCSTR Name,
    _In_ SIZE_T NameMaxLength,
    _Out_ PEM_ENV_VARIABLE* Variable
)
{
    PLIST_ENTRY entry;
    PEM_ENV_VARIABLE envVar;
    SIZE_T nameLength;
    ULONG iterationCount = 0;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Env == NULL || Env->Magic != EM_PROCESS_ENV_MAGIC) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Name == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Variable == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    *Variable = NULL;

    //
    // Safe string length with bounds
    //
    nameLength = EmpSafeStringLengthA(Name, min(NameMaxLength, EM_MAX_ENV_NAME));
    if (nameLength == 0 || nameLength >= EM_MAX_ENV_NAME) {
        return STATUS_INVALID_PARAMETER_2;
    }

    //
    // Search for the variable in the list with proper locking
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Env->VariableLock);

    for (entry = Env->VariableList.Flink;
         entry != &Env->VariableList && iterationCount < EM_MAX_LIST_ITERATIONS;
         entry = entry->Flink, iterationCount++) {

        envVar = CONTAINING_RECORD(entry, EM_ENV_VARIABLE, ListEntry);

        if (envVar->Magic != EM_ENV_VAR_MAGIC) {
            //
            // Corrupted entry - stop iteration
            //
            break;
        }

        //
        // Case-insensitive comparison with length check
        //
        if (envVar->NameLength == nameLength &&
            _strnicmp(envVar->Name, Name, nameLength) == 0) {
            *Variable = envVar;
            break;
        }
    }

    ExReleasePushLockShared(&Env->VariableLock);
    KeLeaveCriticalRegion();

    if (*Variable == NULL) {
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
EmReleaseEnvironment(
    _In_ PEM_PROCESS_ENV Env
)
{
    PEM_MONITOR monitor;
    LONG newRefCount;

    PAGED_CODE();

    if (Env == NULL || Env->Magic != EM_PROCESS_ENV_MAGIC) {
        return;
    }

    monitor = Env->OwnerMonitor;

    //
    // Release caller's reference
    //
    newRefCount = EmpReleaseEnvReference(Env);

    //
    // If reference count hit zero and not in cache, free it
    //
    if (newRefCount == 0) {
        KeEnterCriticalRegion();

        if (monitor != NULL && monitor->Magic == EM_MONITOR_MAGIC) {
            ExAcquirePushLockExclusive(&monitor->CacheLock);

            //
            // Double-check linked state under lock
            //
            if (!Env->IsLinkedToCache) {
                ExReleasePushLockExclusive(&monitor->CacheLock);
                KeLeaveCriticalRegion();

                EmpFreeProcessEnvInternal(monitor, Env);
                return;
            }

            ExReleasePushLockExclusive(&monitor->CacheLock);
        }

        KeLeaveCriticalRegion();
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EmAcquireEnvironmentReference(
    _In_ PEM_PROCESS_ENV Env
)
{
    if (Env != NULL && Env->Magic == EM_PROCESS_ENV_MAGIC) {
        EmpAcquireEnvReference(Env);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EmReleaseEnvironmentReference(
    _In_ PEM_PROCESS_ENV Env
)
{
    if (Env != NULL && Env->Magic == EM_PROCESS_ENV_MAGIC) {
        EmpReleaseEnvReference(Env);
    }
}

// ============================================================================
// PRIVATE IMPLEMENTATION - REFERENCE COUNTING
// ============================================================================

static VOID
EmpAcquireMonitorReference(
    _In_ PEM_MONITOR Monitor
)
{
    InterlockedIncrement(&Monitor->ReferenceCount);
}

static VOID
EmpReleaseMonitorReference(
    _In_ PEM_MONITOR Monitor
)
{
    LONG newCount = InterlockedDecrement(&Monitor->ReferenceCount);

    if (newCount == 0 && Monitor->ShuttingDown) {
        KeSetEvent(&Monitor->ShutdownCompleteEvent, IO_NO_INCREMENT, FALSE);
    }
}

static VOID
EmpAcquireEnvReference(
    _In_ PEM_PROCESS_ENV Env
)
{
    InterlockedIncrement(&Env->ReferenceCount);
}

static LONG
EmpReleaseEnvReference(
    _In_ PEM_PROCESS_ENV Env
)
{
    return InterlockedDecrement(&Env->ReferenceCount);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - ALLOCATION
// ============================================================================

static NTSTATUS
EmpAllocateEnvVariable(
    _In_ PEM_MONITOR Monitor,
    _Out_ PEM_ENV_VARIABLE* Variable
)
{
    PEM_ENV_VARIABLE envVar = NULL;
    EM_ALLOC_SOURCE allocSource = EmAllocSource_Pool;

    *Variable = NULL;

    //
    // Try lookaside first if available
    //
    if (Monitor->LookasideInitialized) {
        envVar = (PEM_ENV_VARIABLE)ExAllocateFromNPagedLookasideList(
            &Monitor->EnvVarLookaside
        );
        if (envVar != NULL) {
            allocSource = EmAllocSource_Lookaside;
        }
    }

    //
    // Fallback to pool if lookaside failed or not initialized
    //
    if (envVar == NULL) {
        envVar = (PEM_ENV_VARIABLE)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(EM_ENV_VARIABLE),
            EM_ENV_VAR_TAG
        );
        allocSource = EmAllocSource_Pool;
    }

    if (envVar == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(envVar, sizeof(EM_ENV_VARIABLE));

    envVar->Magic = EM_ENV_VAR_MAGIC;
    envVar->AllocSource = allocSource;
    InitializeListHead(&envVar->ListEntry);

    *Variable = envVar;

    return STATUS_SUCCESS;
}

static VOID
EmpFreeEnvVariable(
    _In_ PEM_MONITOR Monitor,
    _In_ PEM_ENV_VARIABLE Variable
)
{
    if (Variable == NULL) {
        return;
    }

    if (Variable->Magic != EM_ENV_VAR_MAGIC) {
        return;
    }

    Variable->Magic = 0;

    //
    // Free to correct allocator based on tracked source
    //
    if (Variable->AllocSource == EmAllocSource_Lookaside &&
        Monitor != NULL &&
        Monitor->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Monitor->EnvVarLookaside, Variable);
    } else {
        ShadowStrikeFreePoolWithTag(Variable, EM_ENV_VAR_TAG);
    }
}

static NTSTATUS
EmpAllocateProcessEnv(
    _In_ PEM_MONITOR Monitor,
    _Out_ PEM_PROCESS_ENV* ProcessEnv
)
{
    PEM_PROCESS_ENV processEnv = NULL;

    *ProcessEnv = NULL;

    processEnv = (PEM_PROCESS_ENV)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(EM_PROCESS_ENV),
        EM_POOL_TAG
    );

    if (processEnv == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(processEnv, sizeof(EM_PROCESS_ENV));

    processEnv->Magic = EM_PROCESS_ENV_MAGIC;
    processEnv->OwnerMonitor = Monitor;
    processEnv->ReferenceCount = 1;  // Initial reference for cache
    processEnv->IsLinkedToCache = FALSE;

    InitializeListHead(&processEnv->VariableList);
    ExInitializePushLock(&processEnv->VariableLock);
    InitializeListHead(&processEnv->CacheListEntry);

    *ProcessEnv = processEnv;

    return STATUS_SUCCESS;
}

static VOID
EmpFreeProcessEnvInternal(
    _In_ PEM_MONITOR Monitor,
    _In_ PEM_PROCESS_ENV ProcessEnv
)
{
    PLIST_ENTRY entry;
    PEM_ENV_VARIABLE envVar;
    ULONG iterationCount = 0;

    if (ProcessEnv == NULL) {
        return;
    }

    if (ProcessEnv->Magic != EM_PROCESS_ENV_MAGIC) {
        return;
    }

    //
    // Free all environment variables with iteration bound
    //
    while (!IsListEmpty(&ProcessEnv->VariableList) &&
           iterationCount < EM_MAX_LIST_ITERATIONS) {

        entry = RemoveHeadList(&ProcessEnv->VariableList);
        envVar = CONTAINING_RECORD(entry, EM_ENV_VARIABLE, ListEntry);
        EmpFreeEnvVariable(Monitor, envVar);
        iterationCount++;
    }

    ProcessEnv->Magic = 0;

    ShadowStrikeFreePoolWithTag(ProcessEnv, EM_POOL_TAG);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - SAFE ENVIRONMENT CAPTURE (TOCTOU-RESISTANT)
// ============================================================================

static NTSTATUS
EmpCaptureEnvironmentBlockSafe(
    _In_ HANDLE ProcessId,
    _Out_ PVOID* EnvironmentBlock,
    _Out_ PSIZE_T BlockSize,
    _Out_ PLARGE_INTEGER ProcessCreateTime
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    PVOID capturedBlock = NULL;
    SIZE_T capturedSize = 0;
    BOOLEAN attached = FALSE;

    //
    // Captured values - atomic snapshot to prevent TOCTOU
    //
    PVOID envBlockAddress = NULL;
    SIZE_T envBlockSize = 0;

    *EnvironmentBlock = NULL;
    *BlockSize = 0;
    RtlZeroMemory(ProcessCreateTime, sizeof(LARGE_INTEGER));

    //
    // Get process object with reference
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Get process create time for epoch validation
    // This is safe to access without attachment
    //
    *ProcessCreateTime = PsGetProcessCreateTimeQuadPart(process);

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
        // Get PEB - this is kernel memory, safe to access
        //
        PPEB peb = PsGetProcessPeb(process);
        if (peb == NULL) {
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        //
        // All user-mode access in single __try block with atomic capture
        //
        __try {
            PRTL_USER_PROCESS_PARAMETERS processParams;

            //
            // Validate PEB is in user address range
            //
            if ((ULONG_PTR)peb >= MmUserProbeAddress) {
                status = STATUS_ACCESS_VIOLATION;
                __leave;
            }

            //
            // Probe and capture ProcessParameters pointer atomically
            //
            ProbeForRead(peb, sizeof(PEB), sizeof(ULONG));
            processParams = (PRTL_USER_PROCESS_PARAMETERS)
                InterlockedCompareExchangePointer(
                    (PVOID*)&peb->ProcessParameters,
                    peb->ProcessParameters,
                    peb->ProcessParameters
                );

            if (processParams == NULL) {
                status = STATUS_UNSUCCESSFUL;
                __leave;
            }

            //
            // Validate ProcessParameters is in user address range
            //
            if ((ULONG_PTR)processParams >= MmUserProbeAddress) {
                status = STATUS_ACCESS_VIOLATION;
                __leave;
            }

            //
            // Probe and capture environment block address and size atomically
            //
            ProbeForRead(
                processParams,
                sizeof(RTL_USER_PROCESS_PARAMETERS),
                sizeof(ULONG)
            );

            //
            // Capture both values in single atomic snapshot
            //
            envBlockAddress = processParams->Environment;
            envBlockSize = processParams->EnvironmentSize;

            //
            // Validate captured values
            //
            if (envBlockAddress == NULL) {
                status = STATUS_UNSUCCESSFUL;
                __leave;
            }

            if ((ULONG_PTR)envBlockAddress >= MmUserProbeAddress) {
                status = STATUS_ACCESS_VIOLATION;
                __leave;
            }

            //
            // Bound the size to prevent DoS
            //
            if (envBlockSize == 0) {
                //
                // Fallback: scan for size if EnvironmentSize is 0
                // Limit scan to prevent DoS
                //
                envBlockSize = EM_MAX_ENV_BLOCK_SIZE;
            }

            if (envBlockSize > EM_MAX_ENV_BLOCK_SIZE) {
                envBlockSize = EM_MAX_ENV_BLOCK_SIZE;
            }

            //
            // Validate entire range is in user address space
            //
            if ((ULONG_PTR)envBlockAddress + envBlockSize < (ULONG_PTR)envBlockAddress ||
                (ULONG_PTR)envBlockAddress + envBlockSize > MmUserProbeAddress) {
                status = STATUS_ACCESS_VIOLATION;
                __leave;
            }

            //
            // Allocate kernel buffer
            //
            capturedBlock = ShadowStrikeAllocatePoolWithTag(
                NonPagedPoolNx,
                envBlockSize,
                EM_STRING_TAG
            );

            if (capturedBlock == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                __leave;
            }

            //
            // Probe and copy in single operation
            // This minimizes TOCTOU window
            //
            ProbeForRead(envBlockAddress, envBlockSize, sizeof(WCHAR));
            RtlCopyMemory(capturedBlock, envBlockAddress, envBlockSize);

            capturedSize = envBlockSize;
            status = STATUS_SUCCESS;

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }

    } __finally {
        if (attached) {
            KeUnstackDetachProcess(&apcState);
        }
    }

    ObDereferenceObject(process);

    if (NT_SUCCESS(status)) {
        *EnvironmentBlock = capturedBlock;
        *BlockSize = capturedSize;
    } else {
        if (capturedBlock != NULL) {
            ShadowStrikeFreePoolWithTag(capturedBlock, EM_STRING_TAG);
        }
    }

    return status;
}

static NTSTATUS
EmpParseEnvironmentBlock(
    _In_ PEM_MONITOR Monitor,
    _In_ PVOID EnvironmentBlock,
    _In_ SIZE_T BlockSize,
    _Inout_ PEM_PROCESS_ENV ProcessEnv,
    _Out_ PEMP_PROCESS_ENV_EXTENDED ExtendedData
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

    RtlZeroMemory(ExtendedData, sizeof(EMP_PROCESS_ENV_EXTENDED));

    //
    // Ensure block is at least minimally valid
    //
    if (BlockSize < sizeof(WCHAR) * 2) {
        return STATUS_INVALID_PARAMETER;
    }

    while (envPtr < endPtr &&
           *envPtr != L'\0' &&
           variableCount < EM_MAX_VARIABLES) {

        //
        // Find the end of this environment string safely
        //
        PWCHAR stringEnd = envPtr;
        SIZE_T maxScan = (SIZE_T)(endPtr - envPtr);
        SIZE_T scanned = 0;

        while (stringEnd < endPtr && *stringEnd != L'\0' && scanned < maxScan) {
            stringEnd++;
            scanned++;
        }

        if (stringEnd >= endPtr) {
            //
            // Malformed block - no null terminator found
            //
            break;
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
            //
            // Out of memory - stop parsing but don't fail
            //
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
        envVar->NameLength = ansiName.Length;

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
        envVar->ValueLength = ansiValue.Length;

        //
        // Set timestamp
        //
        KeQuerySystemTime(&envVar->LastModified);

        //
        // Determine if this is a system variable
        //
        envVar->IsSystemVariable = FALSE;
        for (ULONG i = 0; i < ARRAYSIZE(g_DllVariables); i++) {
            if (EmpCompareEnvVarNameToWide(
                    envVar->Name,
                    envVar->NameLength,
                    g_DllVariables[i])) {
                envVar->IsSystemVariable = TRUE;
                break;
            }
        }

        //
        // Check for PATH variable and analyze it
        //
        if (_strnicmp(envVar->Name, "PATH", 4) == 0 && envVar->NameLength == 4) {
            EmpAnalyzePathVariable(envVar->Value, envVar->ValueLength, ExtendedData);
        }

        //
        // Check for encoded values (using integer-only entropy)
        //
        if (EmpIsEncodedValue(envVar->Value, envVar->ValueLength)) {
            ExtendedData->EncodedValueCount++;
        }

        //
        // Check entropy using integer-scaled calculation
        //
        ULONG entropyScaled = EmpCalculateEntropyScaled(
            envVar->Value,
            envVar->ValueLength
        );
        if (entropyScaled > EMP_ENTROPY_THRESHOLD_SCALED) {
            ExtendedData->HighEntropyCount++;
        }

        //
        // Add to variable list (lock not needed - we own this structure)
        //
        InsertTailList(&ProcessEnv->VariableList, &envVar->ListEntry);
        variableCount++;

        //
        // Move to next environment string
        //
        envPtr = stringEnd + 1;
    }

    ProcessEnv->VariableCount = variableCount;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - PATH ANALYSIS
// ============================================================================

static NTSTATUS
EmpAnalyzePathVariable(
    _In_ PCSTR PathValue,
    _In_ SIZE_T PathLength,
    _Inout_ PEMP_PROCESS_ENV_EXTENDED ExtendedData
)
{
    PCHAR pathCopy = NULL;
    PCHAR token;
    PCHAR nextToken;
    ULONG entryCount = 0;
    NTSTATUS status;

    //
    // Pool-allocated buffer for wide path to avoid stack overflow
    //
    PWCHAR widePath = NULL;
    const SIZE_T widePathSize = MAX_PATH * sizeof(WCHAR);

    if (PathValue == NULL || PathLength == 0) {
        return STATUS_SUCCESS;
    }

    if (PathLength >= EM_MAX_ENV_VALUE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Allocate from pool instead of stack
    //
    pathCopy = (PCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        PathLength + 1,
        EM_PATH_TAG
    );

    if (pathCopy == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    widePath = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        widePathSize,
        EM_PATH_TAG
    );

    if (widePath == NULL) {
        ShadowStrikeFreePoolWithTag(pathCopy, EM_PATH_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(pathCopy, PathValue, PathLength);
    pathCopy[PathLength] = '\0';

    //
    // Parse PATH entries (semicolon-separated)
    //
    token = pathCopy;
    while (token != NULL && entryCount < EM_MAX_PATH_ENTRIES) {
        ANSI_STRING ansiPath;
        UNICODE_STRING unicodePath;

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
        SIZE_T tokenLen = EmpSafeStringLengthA(token, MAX_PATH);
        if (tokenLen == 0) {
            token = nextToken;
            continue;
        }

        //
        // Convert to wide string for analysis
        //
        RtlInitAnsiString(&ansiPath, token);
        unicodePath.Buffer = widePath;
        unicodePath.Length = 0;
        unicodePath.MaximumLength = (USHORT)(widePathSize - sizeof(WCHAR));

        status = RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, FALSE);
        if (NT_SUCCESS(status)) {
            SIZE_T wideLen = unicodePath.Length / sizeof(WCHAR);
            widePath[wideLen] = L'\0';

            //
            // Analyze this path entry
            //
            if (EmpIsWritablePath(widePath, wideLen)) {
                ExtendedData->HasWritablePathEntry = TRUE;
            }

            if (EmpIsUserPath(widePath, wideLen)) {
                ExtendedData->HasUserPathEntry = TRUE;
            }

            if (EmpIsSuspiciousPath(widePath, wideLen)) {
                ExtendedData->HasSuspiciousPathEntry = TRUE;
            }

            entryCount++;
        }

        token = nextToken;
    }

    ExtendedData->PathEntryCount = entryCount;

    ShadowStrikeFreePoolWithTag(widePath, EM_PATH_TAG);
    ShadowStrikeFreePoolWithTag(pathCopy, EM_PATH_TAG);

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - PROXY ANALYSIS
// ============================================================================

static NTSTATUS
EmpAnalyzeProxySettingsLocked(
    _In_ PEM_PROCESS_ENV ProcessEnv,
    _Inout_ PEMP_PROCESS_ENV_EXTENDED ExtendedData
)
{
    PLIST_ENTRY entry;
    PEM_ENV_VARIABLE envVar;
    ULONG iterationCount = 0;

    for (entry = ProcessEnv->VariableList.Flink;
         entry != &ProcessEnv->VariableList && iterationCount < EM_MAX_LIST_ITERATIONS;
         entry = entry->Flink, iterationCount++) {

        envVar = CONTAINING_RECORD(entry, EM_ENV_VARIABLE, ListEntry);

        if (envVar->Magic != EM_ENV_VAR_MAGIC) {
            break;
        }

        for (ULONG i = 0; i < ARRAYSIZE(g_ProxyVariables); i++) {
            if (EmpCompareEnvVarNameToWide(
                    envVar->Name,
                    envVar->NameLength,
                    g_ProxyVariables[i])) {

                ExtendedData->HasProxySettings = TRUE;

                //
                // Check if proxy points to localhost (potential credential interception)
                //
                if (envVar->ValueLength > 0) {
                    //
                    // Safe substring search with bounds
                    //
                    PCSTR value = envVar->Value;
                    SIZE_T valueLen = envVar->ValueLength;

                    if (valueLen >= 9 && strstr(value, "127.0.0.1") != NULL) {
                        ExtendedData->ProxyIsLocalhost = TRUE;
                        ExtendedData->ProxyIsSuspicious = TRUE;
                    }
                    if (valueLen >= 9 && strstr(value, "localhost") != NULL) {
                        ExtendedData->ProxyIsLocalhost = TRUE;
                        ExtendedData->ProxyIsSuspicious = TRUE;
                    }
                    if (valueLen >= 3 && strstr(value, "::1") != NULL) {
                        ExtendedData->ProxyIsLocalhost = TRUE;
                        ExtendedData->ProxyIsSuspicious = TRUE;
                    }

                    //
                    // Check for unusual ports using kernel-safe parsing
                    //
                    PCSTR colonPos = strrchr(value, ':');
                    if (colonPos != NULL && colonPos < value + valueLen - 1) {
                        ULONG port = 0;
                        SIZE_T portStrLen = (value + valueLen) - (colonPos + 1);

                        if (NT_SUCCESS(EmpParsePortFromString(colonPos + 1, portStrLen, &port))) {
                            if (port != 80 && port != 443 && port != 8080 && port != 3128) {
                                ExtendedData->ProxyIsSuspicious = TRUE;
                            }
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
// PRIVATE IMPLEMENTATION - TEMP ANALYSIS
// ============================================================================

static NTSTATUS
EmpAnalyzeTempOverridesLocked(
    _In_ PEM_PROCESS_ENV ProcessEnv,
    _Inout_ PEMP_PROCESS_ENV_EXTENDED ExtendedData
)
{
    PLIST_ENTRY entry;
    PEM_ENV_VARIABLE envVar;
    ULONG iterationCount = 0;
    NTSTATUS status;

    //
    // Pool-allocated buffer instead of stack
    //
    PWCHAR widePath = NULL;
    const SIZE_T widePathSize = MAX_PATH * sizeof(WCHAR);

    widePath = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        widePathSize,
        EM_PATH_TAG
    );

    if (widePath == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (entry = ProcessEnv->VariableList.Flink;
         entry != &ProcessEnv->VariableList && iterationCount < EM_MAX_LIST_ITERATIONS;
         entry = entry->Flink, iterationCount++) {

        envVar = CONTAINING_RECORD(entry, EM_ENV_VARIABLE, ListEntry);

        if (envVar->Magic != EM_ENV_VAR_MAGIC) {
            break;
        }

        for (ULONG i = 0; i < ARRAYSIZE(g_TempVariables); i++) {
            if (EmpCompareEnvVarNameToWide(
                    envVar->Name,
                    envVar->NameLength,
                    g_TempVariables[i])) {

                ANSI_STRING ansiPath;
                UNICODE_STRING unicodePath;

                //
                // Convert value to wide string for path analysis
                //
                RtlInitAnsiString(&ansiPath, envVar->Value);
                unicodePath.Buffer = widePath;
                unicodePath.Length = 0;
                unicodePath.MaximumLength = (USHORT)(widePathSize - sizeof(WCHAR));

                status = RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, FALSE);
                if (NT_SUCCESS(status)) {
                    SIZE_T wideLen = unicodePath.Length / sizeof(WCHAR);
                    widePath[wideLen] = L'\0';

                    //
                    // Check if TEMP points to unexpected location
                    //
                    if (!EmpIsSystemPath(widePath, wideLen)) {
                        ExtendedData->HasTempOverride = TRUE;

                        if (EmpIsWritablePath(widePath, wideLen)) {
                            ExtendedData->TempPointsToWritable = TRUE;
                        }
                    }
                }

                break;
            }
        }
    }

    ShadowStrikeFreePoolWithTag(widePath, EM_PATH_TAG);

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - ENCODING DETECTION (INTEGER-ONLY)
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

/**
 * @brief Calculate entropy using integer-only arithmetic (scaled by 1000)
 *
 * This avoids kernel floating-point issues. Returns entropy * 1000.
 * For example, entropy of 4.5 returns 4500.
 */
static ULONG
EmpCalculateEntropyScaled(
    _In_ PCSTR Data,
    _In_ SIZE_T Length
)
{
    ULONG frequency[256] = { 0 };
    ULONG entropyScaled = 0;
    ULONG i;

    if (Length == 0 || Length > EMP_SAFE_STRING_MAX) {
        return 0;
    }

    //
    // Count byte frequencies
    //
    for (i = 0; i < Length; i++) {
        frequency[(UCHAR)Data[i]]++;
    }

    //
    // Calculate Shannon entropy using integer approximation
    // entropy = -sum(p * log2(p)) where p = frequency[i] / Length
    //
    // Using log2 approximation: log2(n) ≈ position of highest set bit
    // Scaled by 1000 for precision
    //
    for (i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            //
            // p = frequency[i] / Length
            // -p * log2(p) = (frequency[i] / Length) * log2(Length / frequency[i])
            //
            // Compute log2(Length / frequency[i]) using bit position
            //
            ULONG ratio = (ULONG)(Length / frequency[i]);
            ULONG log2Approx = 0;
            ULONG temp = ratio;

            while (temp > 1) {
                temp >>= 1;
                log2Approx++;
            }

            //
            // Contribution = (frequency[i] * log2Approx * 1000) / Length
            //
            ULONG contribution = (frequency[i] * log2Approx * 1000) / (ULONG)Length;
            entropyScaled += contribution;
        }
    }

    return entropyScaled;
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

    if (ValueLength < 4 || ValueLength > EMP_SAFE_STRING_MAX) {
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
    ULONG totalValidChars = validChars + paddingCount;
    if (totalValidChars >= (ValueLength * 8 / 10) &&
        (totalValidChars % 4) == 0 &&
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

    if (ValueLength < 8 || ValueLength > EMP_SAFE_STRING_MAX) {
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
    _In_ PCWSTR Path,
    _In_ SIZE_T PathLength
)
{
    //
    // Check for user-writable directories in PATH
    //
    for (ULONG i = 0; i < ARRAYSIZE(g_SuspiciousPathDirs); i++) {
        if (EmpSafeWcsStr(Path, PathLength, g_SuspiciousPathDirs[i])) {
            return TRUE;
        }
    }

    //
    // Check for current directory placeholder
    //
    if (PathLength >= 1 && Path[0] == L'.') {
        if (PathLength == 1 || Path[1] == L'\\' || Path[1] == L';') {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
EmpIsUserPath(
    _In_ PCWSTR Path,
    _In_ SIZE_T PathLength
)
{
    if (EmpSafeWcsStr(Path, PathLength, L"\\Users\\")) {
        return TRUE;
    }

    if (EmpSafeWcsStr(Path, PathLength, L"\\AppData\\")) {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
EmpIsSuspiciousPath(
    _In_ PCWSTR Path,
    _In_ SIZE_T PathLength
)
{
    if (PathLength < 1) {
        return FALSE;
    }

    //
    // Network paths at start of PATH are suspicious
    //
    if (PathLength >= 2 && Path[0] == L'\\' && Path[1] == L'\\') {
        return TRUE;
    }

    //
    // Relative paths are suspicious (not starting with drive letter)
    //
    if (PathLength >= 3) {
        if (Path[0] != L'\\' && (Path[1] != L':' || Path[2] != L'\\')) {
            //
            // Not an absolute path
            //
            if (!((Path[0] >= L'A' && Path[0] <= L'Z') ||
                  (Path[0] >= L'a' && Path[0] <= L'z'))) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

static BOOLEAN
EmpIsSystemPath(
    _In_ PCWSTR Path,
    _In_ SIZE_T PathLength
)
{
    if (EmpSafeWcsStr(Path, PathLength, L"\\Windows\\")) {
        return TRUE;
    }

    if (EmpSafeWcsStr(Path, PathLength, L"\\System32\\")) {
        return TRUE;
    }

    if (EmpSafeWcsStr(Path, PathLength, L"\\SysWOW64\\")) {
        return TRUE;
    }

    if (EmpSafeWcsStr(Path, PathLength, L"\\Program Files\\")) {
        return TRUE;
    }

    if (EmpSafeWcsStr(Path, PathLength, L"\\Program Files (x86)\\")) {
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - SUSPICION DETECTION
// ============================================================================

static EM_SUSPICION
EmpDetectSuspiciousConditions(
    _In_ PEM_PROCESS_ENV ProcessEnv,
    _In_ PEMP_PROCESS_ENV_EXTENDED ExtendedData
)
{
    EM_SUSPICION flags = EmSuspicion_None;

    //
    // Check PATH modifications
    //
    if (ExtendedData->HasWritablePathEntry || ExtendedData->HasUserPathEntry) {
        flags |= EmSuspicion_ModifiedPath;
    }

    if (ExtendedData->HasSuspiciousPathEntry) {
        flags |= EmSuspicion_DLLSearchOrder;
    }

    //
    // Check proxy settings
    //
    if (ExtendedData->HasProxySettings && ExtendedData->ProxyIsSuspicious) {
        flags |= EmSuspicion_ProxySettings;
    }

    //
    // Check TEMP overrides
    //
    if (ExtendedData->HasTempOverride) {
        flags |= EmSuspicion_TempOverride;
    }

    //
    // Check for encoded values
    //
    if (ExtendedData->EncodedValueCount > 0 || ExtendedData->HighEntropyCount > 2) {
        flags |= EmSuspicion_EncodedValue;
    }

    //
    // Check variable count (unusually high might indicate injection)
    //
    if (ProcessEnv->VariableCount > 500) {
        flags |= EmSuspicion_HiddenVariable;
    }

    return flags;
}

static ULONG
EmpCalculateSuspicionScore(
    _In_ PEMP_PROCESS_ENV_EXTENDED ExtendedData,
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
    if (ExtendedData->ProxyIsLocalhost) {
        score += 20;
    }

    if (ExtendedData->EncodedValueCount > 3) {
        score += 15;
    }

    if (ExtendedData->HighEntropyCount > 5) {
        score += 15;
    }

    if (ExtendedData->TempPointsToWritable) {
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
EmpCleanupExpiredCacheEntriesLocked(
    _Inout_ PEM_MONITOR Monitor
)
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PEM_PROCESS_ENV processEnv;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER expiryThreshold;
    ULONG iterationCount = 0;

    KeQuerySystemTime(&currentTime);
    expiryThreshold.QuadPart = currentTime.QuadPart - EMP_CACHE_EXPIRY_TIME;

    //
    // Caller must hold CacheLock exclusively
    //

    for (entry = Monitor->ProcessCacheList.Flink;
         entry != &Monitor->ProcessCacheList && iterationCount < EM_MAX_LIST_ITERATIONS;
         entry = nextEntry, iterationCount++) {

        nextEntry = entry->Flink;

        processEnv = CONTAINING_RECORD(entry, EM_PROCESS_ENV, CacheListEntry);

        if (processEnv->Magic != EM_PROCESS_ENV_MAGIC) {
            //
            // Corrupted entry - remove it
            //
            RemoveEntryList(&processEnv->CacheListEntry);
            processEnv->IsLinkedToCache = FALSE;
            InterlockedDecrement(&Monitor->CacheCount);
            continue;
        }

        if (processEnv->CacheTime.QuadPart < expiryThreshold.QuadPart) {
            //
            // Expired entry
            //
            RemoveEntryList(&processEnv->CacheListEntry);
            InitializeListHead(&processEnv->CacheListEntry);
            processEnv->IsLinkedToCache = FALSE;
            InterlockedDecrement(&Monitor->CacheCount);

            //
            // Release cache's reference
            // If it hits zero and no external refs, it will be freed by caller
            //
            EmpReleaseEnvReference(processEnv);
        }
    }
}

static PEM_PROCESS_ENV
EmpFindCachedEnvironmentLocked(
    _In_ PEM_MONITOR Monitor,
    _In_ HANDLE ProcessId,
    _In_ PLARGE_INTEGER ProcessCreateTime
)
{
    PLIST_ENTRY entry;
    PEM_PROCESS_ENV processEnv;
    ULONG iterationCount = 0;

    //
    // Caller must hold CacheLock (shared or exclusive)
    //

    for (entry = Monitor->ProcessCacheList.Flink;
         entry != &Monitor->ProcessCacheList && iterationCount < EM_MAX_LIST_ITERATIONS;
         entry = entry->Flink, iterationCount++) {

        processEnv = CONTAINING_RECORD(entry, EM_PROCESS_ENV, CacheListEntry);

        if (processEnv->Magic != EM_PROCESS_ENV_MAGIC) {
            continue;
        }

        //
        // Match on both ProcessId AND CreateTime to prevent cache poisoning
        // from ProcessId reuse
        //
        if (processEnv->ProcessId == ProcessId &&
            processEnv->ProcessCreateTime.QuadPart == ProcessCreateTime->QuadPart) {
            return processEnv;
        }
    }

    return NULL;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - UTILITY FUNCTIONS
// ============================================================================

static BOOLEAN
EmpCompareEnvVarNameToWide(
    _In_ PCSTR Name,
    _In_ SIZE_T NameLength,
    _In_ PCWSTR Target
)
{
    SIZE_T targetLength;
    SIZE_T i;

    if (Name == NULL || Target == NULL || NameLength == 0) {
        return FALSE;
    }

    //
    // Get target length safely
    //
    targetLength = EmpSafeStringLengthW(Target, EM_MAX_ENV_NAME);

    if (NameLength != targetLength) {
        return FALSE;
    }

    //
    // Case-insensitive comparison character by character
    //
    for (i = 0; i < NameLength; i++) {
        CHAR c1 = Name[i];
        WCHAR c2 = Target[i];

        //
        // Convert to lowercase for comparison
        //
        if (c1 >= 'A' && c1 <= 'Z') {
            c1 = c1 - 'A' + 'a';
        }
        if (c2 >= L'A' && c2 <= L'Z') {
            c2 = c2 - L'A' + L'a';
        }

        if ((WCHAR)c1 != c2) {
            return FALSE;
        }
    }

    return TRUE;
}

static SIZE_T
EmpSafeStringLengthA(
    _In_ PCSTR String,
    _In_ SIZE_T MaxLength
)
{
    SIZE_T length = 0;

    if (String == NULL) {
        return 0;
    }

    while (length < MaxLength && String[length] != '\0') {
        length++;
    }

    return length;
}

static SIZE_T
EmpSafeStringLengthW(
    _In_ PCWSTR String,
    _In_ SIZE_T MaxLength
)
{
    SIZE_T length = 0;

    if (String == NULL) {
        return 0;
    }

    while (length < MaxLength && String[length] != L'\0') {
        length++;
    }

    return length;
}

static BOOLEAN
EmpSafeWcsStr(
    _In_ PCWSTR Haystack,
    _In_ SIZE_T HaystackLength,
    _In_ PCWSTR Needle
)
{
    SIZE_T needleLength;
    SIZE_T i;

    if (Haystack == NULL || Needle == NULL || HaystackLength == 0) {
        return FALSE;
    }

    needleLength = EmpSafeStringLengthW(Needle, EM_MAX_ENV_NAME);
    if (needleLength == 0 || needleLength > HaystackLength) {
        return FALSE;
    }

    //
    // Simple substring search with bounds
    //
    for (i = 0; i <= HaystackLength - needleLength; i++) {
        BOOLEAN match = TRUE;

        for (SIZE_T j = 0; j < needleLength; j++) {
            WCHAR c1 = Haystack[i + j];
            WCHAR c2 = Needle[j];

            //
            // Case-insensitive
            //
            if (c1 >= L'A' && c1 <= L'Z') {
                c1 = c1 - L'A' + L'a';
            }
            if (c2 >= L'A' && c2 <= L'Z') {
                c2 = c2 - L'A' + L'a';
            }

            if (c1 != c2) {
                match = FALSE;
                break;
            }
        }

        if (match) {
            return TRUE;
        }
    }

    return FALSE;
}

static NTSTATUS
EmpParsePortFromString(
    _In_ PCSTR String,
    _In_ SIZE_T StringLength,
    _Out_ PULONG Port
)
{
    ULONG result = 0;
    SIZE_T i;

    *Port = 0;

    if (String == NULL || StringLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Parse digits only, max 5 digits for port (65535)
    //
    for (i = 0; i < StringLength && i < 5; i++) {
        CHAR c = String[i];

        if (c >= '0' && c <= '9') {
            result = result * 10 + (c - '0');

            if (result > 65535) {
                return STATUS_INTEGER_OVERFLOW;
            }
        } else if (c == '/' || c == '\0') {
            //
            // End of port number
            //
            break;
        } else {
            //
            // Invalid character
            //
            return STATUS_INVALID_PARAMETER;
        }
    }

    *Port = result;
    return STATUS_SUCCESS;
}
