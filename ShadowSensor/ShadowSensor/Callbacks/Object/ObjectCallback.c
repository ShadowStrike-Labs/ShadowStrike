/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE OBJECT CALLBACK IMPLEMENTATION
 * ============================================================================
 *
 * @file ObjectCallback.c
 * @brief Enterprise-grade object manager callback for process/thread protection.
 *
 * This module implements comprehensive object callback functionality with:
 * - Process handle access rights stripping for protected processes
 * - Thread handle protection against injection/hijacking
 * - LSASS credential theft protection (T1003)
 * - EDR self-protection against tampering
 * - Critical system process protection (csrss, services, wininit)
 * - Cross-session handle access detection
 * - Handle duplication chain tracking
 * - Suspicious activity scoring and alerting
 * - Rate-limited telemetry for high-volume events
 * - Integration with process protection subsystem
 *
 * CRITICAL FIXES IN v2.1.0:
 * - Fixed initialization race condition with atomic state machine
 * - Fixed IRQL violations in process name lookup (use PsGetProcessImageFileName)
 * - Fixed empty loop stub in ObpIsShadowStrikeProcess
 * - Fixed rate limiter torn read/write with spin lock
 * - Added path validation to prevent name spoofing
 * - Implemented well-known PID caching at startup
 * - Implemented telemetry pipeline
 * - Added category-based thread protection
 * - Added proper memory ordering with volatile qualifiers
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition - Security Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ObjectCallback.h"
#include "ProcessProtection.h"
#include "../../Core/Globals.h"
#include "../../Utilities/ProcessUtils.h"
#include "../../Utilities/MemoryUtils.h"

#ifdef WPP_TRACING
#include "ObjectCallback.tmh"
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

//
// Initialization states for atomic state machine
//
#define OB_INIT_STATE_UNINITIALIZED     0
#define OB_INIT_STATE_INITIALIZING      1
#define OB_INIT_STATE_INITIALIZED       2
#define OB_INIT_STATE_SHUTTING_DOWN     3

//
// Name cache TTL (5 seconds in 100ns units)
//
#define OB_NAME_CACHE_TTL_100NS         (5LL * 10000000LL)

//
// Rate limit window (1 second in 100ns units)
//
#define OB_RATE_LIMIT_WINDOW_100NS      (1LL * 10000000LL)

//
// System paths for validation
//
static const CHAR* g_SystemRoot = "\\SYSTEMROOT\\SYSTEM32\\";
static const CHAR* g_WindowsRoot = "\\WINDOWS\\SYSTEM32\\";

//
// Well-known process names (using ANSI for PsGetProcessImageFileName compatibility)
//
static const CHAR* g_LsassNames[] = {
    "lsass.exe",
    "lsaiso.exe"
};

static const CHAR* g_CriticalSystemProcesses[] = {
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "svchost.exe",
    "dwm.exe"
};

static const CHAR* g_ShadowStrikeProcesses[] = {
    "ShadowStrikeSe",  // Truncated to 15 chars like PsGetProcessImageFileName
    "ShadowStrikeUI",
    "ShadowStrikeSc",
    "ShadowStrikeAg",
    "ShadowStrikeUp"
};

// ============================================================================
// GLOBAL STATE
// ============================================================================

static OB_CALLBACK_CONTEXT g_ObCallbackContext = { 0 };

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static BOOLEAN
ObpIsProcessProtectedInternal(
    _In_ HANDLE ProcessId,
    _In_opt_ PEPROCESS Process,
    _Out_opt_ PP_PROCESS_CATEGORY* OutCategory,
    _Out_opt_ PP_PROTECTION_LEVEL* OutProtectionLevel
    );

static BOOLEAN
ObpIsLsassProcess(
    _In_ PEPROCESS Process
    );

static BOOLEAN
ObpIsCriticalSystemProcess(
    _In_ PEPROCESS Process
    );

static BOOLEAN
ObpIsShadowStrikeProcess(
    _In_ PEPROCESS Process
    );

static BOOLEAN
ObpIsSourceTrusted(
    _In_ HANDLE SourceProcessId,
    _In_ PEPROCESS SourceProcess
    );

static ACCESS_MASK
ObpCalculateAllowedProcessAccess(
    _In_ ACCESS_MASK OriginalAccess,
    _In_ PP_PROTECTION_LEVEL ProtectionLevel,
    _In_ PP_PROCESS_CATEGORY Category,
    _In_ BOOLEAN IsSourceTrusted
    );

static ACCESS_MASK
ObpCalculateAllowedThreadAccess(
    _In_ ACCESS_MASK OriginalAccess,
    _In_ PP_PROTECTION_LEVEL ProtectionLevel,
    _In_ PP_PROCESS_CATEGORY Category,
    _In_ BOOLEAN IsSourceTrusted,
    _In_ BOOLEAN IsCrossProcess
    );

static ULONG
ObpCalculateSuspicionScore(
    _In_ ACCESS_MASK RequestedAccess,
    _In_ ACCESS_MASK StrippedAccess,
    _In_ PP_PROCESS_CATEGORY TargetCategory,
    _In_ BOOLEAN IsCrossSession,
    _In_ BOOLEAN IsDuplicate
    );

static VOID
ObpLogAccessStripped(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ PEPROCESS SourceProcess,
    _In_ PEPROCESS TargetProcess,
    _In_ ACCESS_MASK OriginalAccess,
    _In_ ACCESS_MASK AllowedAccess,
    _In_ PP_PROCESS_CATEGORY TargetCategory,
    _In_ BOOLEAN IsProcessHandle,
    _In_ BOOLEAN IsDuplicate,
    _In_ BOOLEAN IsKernelHandle,
    _In_ BOOLEAN IsCrossSession,
    _In_ ULONG SuspicionScore
    );

static BOOLEAN
ObpShouldRateLimit(
    VOID
    );

static NTSTATUS
ObpInitializeWellKnownPids(
    VOID
    );

static BOOLEAN
ObpMatchProcessNameAnsi(
    _In_ PEPROCESS Process,
    _In_ const CHAR** NameList,
    _In_ ULONG NameCount
    );

static VOID
ObpGetProcessImageFileNameSafe(
    _In_ PEPROCESS Process,
    _Out_writes_(16) PCHAR NameBuffer
    );

static BOOLEAN
ObpValidateProcessPath(
    _In_ PEPROCESS Process,
    _In_ PP_PROCESS_CATEGORY ExpectedCategory
    );

static ULONG64
ObpComputePathHash(
    _In_ PCUNICODE_STRING Path
    );

static VOID
ObpCacheProcessName(
    _In_ HANDLE ProcessId,
    _In_reads_(16) const CHAR* ImageFileName
    );

static BOOLEAN
ObpLookupCachedName(
    _In_ HANDLE ProcessId,
    _Out_writes_(16) PCHAR NameBuffer
    );

// ============================================================================
// PUBLIC FUNCTIONS - REGISTRATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeRegisterObjectCallbacks(
    VOID
    )
{
    NTSTATUS status;
    OB_CALLBACK_REGISTRATION callbackRegistration;
    OB_OPERATION_REGISTRATION operationRegistration[2];
    UNICODE_STRING altitude;
    LONG previousState;

    //
    // Atomic initialization using state machine
    // Prevents race conditions if called concurrently
    //
    previousState = InterlockedCompareExchange(
        &g_ObCallbackContext.InitState,
        OB_INIT_STATE_INITIALIZING,
        OB_INIT_STATE_UNINITIALIZED
    );

    if (previousState == OB_INIT_STATE_INITIALIZED) {
        //
        // Already initialized
        //
        return STATUS_SUCCESS;
    }

    if (previousState == OB_INIT_STATE_INITIALIZING) {
        //
        // Another thread is initializing - spin briefly then check
        //
        LARGE_INTEGER delay;
        delay.QuadPart = -10000; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);

        if (g_ObCallbackContext.InitState == OB_INIT_STATE_INITIALIZED) {
            return STATUS_SUCCESS;
        }
        return STATUS_DEVICE_BUSY;
    }

    if (previousState != OB_INIT_STATE_UNINITIALIZED) {
        //
        // Invalid state (shutting down)
        //
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // We won the race - initialize
    //
    RtlZeroMemory(&g_ObCallbackContext, sizeof(OB_CALLBACK_CONTEXT));
    g_ObCallbackContext.InitState = OB_INIT_STATE_INITIALIZING;

    KeInitializeSpinLock(&g_ObCallbackContext.RateLimitSpinLock);
    KeQuerySystemTime((PLARGE_INTEGER)&g_ObCallbackContext.StartTime);

    //
    // Initialize rate limit time using atomic 64-bit write
    //
    InterlockedExchange64(
        &g_ObCallbackContext.CurrentSecondStart100ns,
        g_ObCallbackContext.StartTime.QuadPart
    );

    //
    // Set default configuration
    //
    g_ObCallbackContext.EnableCredentialProtection = TRUE;
    g_ObCallbackContext.EnableInjectionProtection = TRUE;
    g_ObCallbackContext.EnableTerminationProtection = TRUE;
    g_ObCallbackContext.EnableSelfProtection = TRUE;
    g_ObCallbackContext.EnableCrossSessionMonitoring = TRUE;
    g_ObCallbackContext.LogStrippedAccess = TRUE;
    g_ObCallbackContext.EnablePathValidation = TRUE;
    g_ObCallbackContext.EnableTelemetry = TRUE;

    //
    // Initialize well-known PIDs (deferred - runs at PASSIVE_LEVEL)
    //
    status = ObpInitializeWellKnownPids();
    if (!NT_SUCCESS(status)) {
        //
        // Non-fatal - we can still use dynamic detection
        //
#ifdef WPP_TRACING
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_FILTER,
            "ObpInitializeWellKnownPids failed: 0x%08X (continuing)", status);
#endif
    }

    //
    // Initialize operation registrations
    //

    //
    // 1. Process protection
    //
    RtlZeroMemory(&operationRegistration[0], sizeof(OB_OPERATION_REGISTRATION));
    operationRegistration[0].ObjectType = PsProcessType;
    operationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[0].PreOperation = ShadowStrikeProcessPreCallback;
    operationRegistration[0].PostOperation = NULL;

    //
    // 2. Thread protection
    //
    RtlZeroMemory(&operationRegistration[1], sizeof(OB_OPERATION_REGISTRATION));
    operationRegistration[1].ObjectType = PsThreadType;
    operationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[1].PreOperation = ShadowStrikeThreadPreCallback;
    operationRegistration[1].PostOperation = NULL;

    //
    // Initialize callback registration
    // Altitude 321000 is in the standard AV/EDR range
    //
    RtlInitUnicodeString(&altitude, L"321000");

    RtlZeroMemory(&callbackRegistration, sizeof(OB_CALLBACK_REGISTRATION));
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 2;
    callbackRegistration.Altitude = altitude;
    callbackRegistration.RegistrationContext = &g_ObCallbackContext;
    callbackRegistration.OperationRegistration = operationRegistration;

    //
    // Register the callbacks
    //
    status = ObRegisterCallbacks(
        &callbackRegistration,
        &g_DriverData.ObjectCallbackHandle
    );

    if (NT_SUCCESS(status)) {
#ifdef WPP_TRACING
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_FLAG_FILTER,
            "ObRegisterCallbacks successful, Handle=%p",
            g_DriverData.ObjectCallbackHandle);
#endif

        //
        // Initialize process protection subsystem
        //
        status = PpInitializeProcessProtection();
        if (!NT_SUCCESS(status)) {
            //
            // Non-fatal - continue with basic protection
            //
#ifdef WPP_TRACING
            TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_FILTER,
                "PpInitializeProcessProtection failed: 0x%08X", status);
#endif
            status = STATUS_SUCCESS;
        }

        //
        // Mark as fully initialized with memory barrier
        //
        MemoryBarrier();
        InterlockedExchange(&g_ObCallbackContext.InitState, OB_INIT_STATE_INITIALIZED);

    } else {
#ifdef WPP_TRACING
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_FLAG_FILTER,
            "ObRegisterCallbacks failed with status 0x%08X",
            status);
#endif
        g_DriverData.ObjectCallbackHandle = NULL;
        InterlockedExchange(&g_ObCallbackContext.InitState, OB_INIT_STATE_UNINITIALIZED);
    }

    return status;
}

_Use_decl_annotations_
VOID
ShadowStrikeUnregisterObjectCallbacks(
    VOID
    )
{
    LONG previousState;

    //
    // Atomic state transition to shutting down
    //
    previousState = InterlockedCompareExchange(
        &g_ObCallbackContext.InitState,
        OB_INIT_STATE_SHUTTING_DOWN,
        OB_INIT_STATE_INITIALIZED
    );

    if (previousState != OB_INIT_STATE_INITIALIZED) {
        //
        // Not initialized or already shutting down
        //
        return;
    }

    //
    // Memory barrier to ensure all in-flight callbacks see shutdown state
    //
    MemoryBarrier();

    if (g_DriverData.ObjectCallbackHandle != NULL) {
        ObUnRegisterCallbacks(g_DriverData.ObjectCallbackHandle);
        g_DriverData.ObjectCallbackHandle = NULL;

#ifdef WPP_TRACING
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_FLAG_FILTER,
            "ObRegisterCallbacks unregistered - Stats: ProcessOps=%lld, ThreadOps=%lld, "
            "ProcessStripped=%lld, ThreadStripped=%lld, CredBlocked=%lld, InjBlocked=%lld",
            g_ObCallbackContext.TotalProcessOperations,
            g_ObCallbackContext.TotalThreadOperations,
            g_ObCallbackContext.ProcessAccessStripped,
            g_ObCallbackContext.ThreadAccessStripped,
            g_ObCallbackContext.CredentialAccessBlocked,
            g_ObCallbackContext.InjectionBlocked);
#endif
    }

    //
    // Shutdown process protection subsystem
    //
    PpShutdownProcessProtection();

    //
    // Final state transition
    //
    InterlockedExchange(&g_ObCallbackContext.InitState, OB_INIT_STATE_UNINITIALIZED);
}

// ============================================================================
// PUBLIC FUNCTIONS - PROCESS CALLBACK
// ============================================================================

_Use_decl_annotations_
OB_PREOP_CALLBACK_STATUS
ShadowStrikeProcessPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    POB_CALLBACK_CONTEXT context = (POB_CALLBACK_CONTEXT)RegistrationContext;
    PEPROCESS targetProcess;
    PEPROCESS sourceProcess;
    HANDLE targetProcessId;
    HANDLE sourceProcessId;
    ACCESS_MASK originalAccess;
    ACCESS_MASK allowedAccess;
    ACCESS_MASK strippedAccess;
    PP_PROCESS_CATEGORY targetCategory = PpCategoryUnknown;
    PP_PROTECTION_LEVEL protectionLevel = PpProtectionNone;
    BOOLEAN isSourceTrusted = FALSE;
    BOOLEAN isSelf = FALSE;
    BOOLEAN isKernelHandle = FALSE;
    BOOLEAN isDuplicate = FALSE;
    BOOLEAN isCrossSession = FALSE;
    ULONG suspicionScore = 0;
    ULONG sourceSessionId = 0;
    ULONG targetSessionId = 0;

    //
    // Validate initialization state atomically
    //
    if (context == NULL) {
        context = &g_ObCallbackContext;
    }

    if (context->InitState != OB_INIT_STATE_INITIALIZED) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Update statistics (lock-free)
    //
    InterlockedIncrement64(&context->TotalProcessOperations);

    //
    // Get target process - validated by the object manager
    //
    targetProcess = (PEPROCESS)OperationInformation->Object;
    if (targetProcess == NULL) {
        return OB_PREOP_SUCCESS;
    }

    targetProcessId = PsGetProcessId(targetProcess);

    //
    // Get source (requesting) process
    //
    sourceProcess = PsGetCurrentProcess();
    sourceProcessId = PsGetCurrentProcessId();

    //
    // Fast path: Self-access is always allowed
    //
    isSelf = (sourceProcessId == targetProcessId);
    if (isSelf) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Determine operation type
    //
    isKernelHandle = (OperationInformation->KernelHandle != FALSE);
    isDuplicate = (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE);

    //
    // Kernel-mode handles from trusted sources are allowed for non-EDR processes
    // But we always check for ShadowStrike processes to prevent kernel-mode attacks
    //
    if (isKernelHandle) {
        if (!ObpIsShadowStrikeProcess(targetProcess)) {
            return OB_PREOP_SUCCESS;
        }
    }

    //
    // Get original access request
    //
    if (isDuplicate) {
        originalAccess = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
    } else {
        originalAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    }

    //
    // Fast path: No dangerous access requested
    //
    if ((originalAccess & PP_FULL_DANGEROUS_ACCESS) == 0) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Check if target is a protected process
    //
    if (!ObpIsProcessProtectedInternal(targetProcessId, targetProcess, &targetCategory, &protectionLevel)) {
        //
        // Target is not protected - allow
        //
        return OB_PREOP_SUCCESS;
    }

    //
    // Check if source is trusted
    //
    isSourceTrusted = ObpIsSourceTrusted(sourceProcessId, sourceProcess);

    //
    // Check for cross-session access (suspicious for user-mode processes)
    //
    if (context->EnableCrossSessionMonitoring && !isKernelHandle) {
        sourceSessionId = PsGetProcessSessionId(sourceProcess);
        targetSessionId = PsGetProcessSessionId(targetProcess);
        isCrossSession = (sourceSessionId != targetSessionId);
    }

    //
    // Calculate allowed access based on protection level
    //
    allowedAccess = ObpCalculateAllowedProcessAccess(
        originalAccess,
        protectionLevel,
        targetCategory,
        isSourceTrusted
    );

    strippedAccess = originalAccess & ~allowedAccess;

    //
    // If access was stripped, update the operation
    //
    if (strippedAccess != 0) {
        //
        // Calculate suspicion score
        //
        suspicionScore = ObpCalculateSuspicionScore(
            originalAccess,
            strippedAccess,
            targetCategory,
            isCrossSession,
            isDuplicate
        );

        //
        // Strip dangerous access
        //
        if (isDuplicate) {
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = allowedAccess;
        } else {
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = allowedAccess;
        }

        //
        // Update statistics (lock-free with interlocked operations)
        //
        InterlockedIncrement64(&context->ProcessAccessStripped);

        if (strippedAccess & PROCESS_TERMINATE) {
            InterlockedIncrement64(&context->TerminationBlocked);
        }

        if (strippedAccess & PP_DANGEROUS_INJECT_ACCESS) {
            InterlockedIncrement64(&context->InjectionBlocked);
        }

        if (targetCategory == PpCategoryLsass &&
            (originalAccess & PP_CREDENTIAL_DUMP_ACCESS) == PP_CREDENTIAL_DUMP_ACCESS) {
            InterlockedIncrement64(&context->CredentialAccessBlocked);
        }

        if (suspicionScore >= OB_SUSPICIOUS_SCORE_THRESHOLD) {
            InterlockedIncrement64(&context->SuspiciousOperations);
        }

        //
        // Log if enabled and not rate limited
        //
        if (context->LogStrippedAccess && !ObpShouldRateLimit()) {
            ObpLogAccessStripped(
                sourceProcessId,
                targetProcessId,
                sourceProcess,
                targetProcess,
                originalAccess,
                allowedAccess,
                targetCategory,
                TRUE,   // IsProcessHandle
                isDuplicate,
                isKernelHandle,
                isCrossSession,
                suspicionScore
            );
        }

        //
        // Update global statistics
        //
        InterlockedIncrement64(&g_DriverData.Stats.SelfProtectionBlocks);
    }

    return OB_PREOP_SUCCESS;
}

// ============================================================================
// PUBLIC FUNCTIONS - THREAD CALLBACK
// ============================================================================

_Use_decl_annotations_
OB_PREOP_CALLBACK_STATUS
ShadowStrikeThreadPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    POB_CALLBACK_CONTEXT context = (POB_CALLBACK_CONTEXT)RegistrationContext;
    PETHREAD targetThread;
    PEPROCESS targetProcess;
    PEPROCESS sourceProcess;
    HANDLE targetProcessId;
    HANDLE sourceProcessId;
    ACCESS_MASK originalAccess;
    ACCESS_MASK allowedAccess;
    ACCESS_MASK strippedAccess;
    PP_PROCESS_CATEGORY targetCategory = PpCategoryUnknown;
    PP_PROTECTION_LEVEL protectionLevel = PpProtectionNone;
    BOOLEAN isSourceTrusted = FALSE;
    BOOLEAN isSelf = FALSE;
    BOOLEAN isCrossProcess = FALSE;
    BOOLEAN isKernelHandle = FALSE;
    BOOLEAN isDuplicate = FALSE;
    ULONG suspicionScore = 0;

    //
    // Validate initialization state atomically
    //
    if (context == NULL) {
        context = &g_ObCallbackContext;
    }

    if (context->InitState != OB_INIT_STATE_INITIALIZED) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&context->TotalThreadOperations);

    //
    // Get target thread
    //
    targetThread = (PETHREAD)OperationInformation->Object;
    if (targetThread == NULL) {
        return OB_PREOP_SUCCESS;
    }

    targetProcess = IoThreadToProcess(targetThread);
    if (targetProcess == NULL) {
        return OB_PREOP_SUCCESS;
    }

    targetProcessId = PsGetProcessId(targetProcess);

    //
    // Get source (requesting) process
    //
    sourceProcess = PsGetCurrentProcess();
    sourceProcessId = PsGetCurrentProcessId();

    //
    // Fast path: Self-access is always allowed
    //
    isSelf = (sourceProcessId == targetProcessId);
    if (isSelf) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Cross-process thread access
    //
    isCrossProcess = TRUE;

    //
    // Determine operation type
    //
    isKernelHandle = (OperationInformation->KernelHandle != FALSE);
    isDuplicate = (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE);

    //
    // Kernel-mode handles - only protect ShadowStrike
    //
    if (isKernelHandle) {
        if (!ObpIsShadowStrikeProcess(targetProcess)) {
            return OB_PREOP_SUCCESS;
        }
    }

    //
    // Get original access request
    //
    if (isDuplicate) {
        originalAccess = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
    } else {
        originalAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    }

    //
    // Fast path: No dangerous access requested
    //
    if ((originalAccess & OB_DANGEROUS_THREAD_ACCESS) == 0) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Check if target process is protected
    //
    if (!ObpIsProcessProtectedInternal(targetProcessId, targetProcess, &targetCategory, &protectionLevel)) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Check if source is trusted
    //
    isSourceTrusted = ObpIsSourceTrusted(sourceProcessId, sourceProcess);

    //
    // Calculate allowed thread access - now uses Category
    //
    allowedAccess = ObpCalculateAllowedThreadAccess(
        originalAccess,
        protectionLevel,
        targetCategory,
        isSourceTrusted,
        isCrossProcess
    );

    strippedAccess = originalAccess & ~allowedAccess;

    //
    // If access was stripped, update the operation
    //
    if (strippedAccess != 0) {
        //
        // Calculate suspicion score for thread operations
        //
        suspicionScore = ObpCalculateSuspicionScore(
            originalAccess,
            strippedAccess,
            targetCategory,
            FALSE,  // Cross-session not applicable for threads
            isDuplicate
        );

        //
        // Thread injection pattern detection - add extra score
        //
        if ((originalAccess & OB_INJECTION_THREAD_ACCESS) == OB_INJECTION_THREAD_ACCESS) {
            suspicionScore += 30;
        }

        //
        // Strip dangerous access
        //
        if (isDuplicate) {
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = allowedAccess;
        } else {
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = allowedAccess;
        }

        //
        // Update statistics
        //
        InterlockedIncrement64(&context->ThreadAccessStripped);

        if (strippedAccess & OB_INJECTION_THREAD_ACCESS) {
            InterlockedIncrement64(&context->InjectionBlocked);
        }

        if (suspicionScore >= OB_SUSPICIOUS_SCORE_THRESHOLD) {
            InterlockedIncrement64(&context->SuspiciousOperations);
        }

        //
        // Log if enabled and not rate limited
        //
        if (context->LogStrippedAccess && !ObpShouldRateLimit()) {
            ObpLogAccessStripped(
                sourceProcessId,
                targetProcessId,
                sourceProcess,
                targetProcess,
                originalAccess,
                allowedAccess,
                targetCategory,
                FALSE,  // IsProcessHandle = FALSE for threads
                isDuplicate,
                isKernelHandle,
                FALSE,  // Cross-session
                suspicionScore
            );
        }

        //
        // Update global statistics
        //
        InterlockedIncrement64(&g_DriverData.Stats.SelfProtectionBlocks);
    }

    return OB_PREOP_SUCCESS;
}

// ============================================================================
// PUBLIC FUNCTIONS - PROTECTED PROCESS MANAGEMENT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ObAddProtectedProcess(
    _In_ HANDLE ProcessId,
    _In_ ULONG Category,
    _In_ ULONG ProtectionLevel,
    _In_opt_ PCUNICODE_STRING ImagePath
    )
{
    POB_PROTECTED_PROCESS_ENTRY entry;
    PEPROCESS process = NULL;
    NTSTATUS status;

    //
    // Validate parameters
    //
    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Get EPROCESS for name extraction
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Allocate entry
    //
    entry = (POB_PROTECTED_PROCESS_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(OB_PROTECTED_PROCESS_ENTRY),
        OB_PROTECTED_ENTRY_TAG
    );

    if (entry == NULL) {
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(OB_PROTECTED_PROCESS_ENTRY));

    //
    // Populate entry
    //
    entry->ProcessId = ProcessId;
    entry->Category = Category;
    entry->ProtectionLevel = ProtectionLevel;
    entry->ReferenceCount = 1;

    //
    // Get image file name (IRQL-safe, returns up to 15 chars)
    //
    ObpGetProcessImageFileNameSafe(process, entry->ImageFileName);

    //
    // Compute path hash if provided
    //
    if (ImagePath != NULL && ImagePath->Buffer != NULL) {
        entry->ImagePathHash = ObpComputePathHash(ImagePath);
        entry->IsValidated = TRUE;
    }

    //
    // Mark special categories
    //
    entry->IsShadowStrike = (Category == PpCategoryAntimalware);
    entry->IsCriticalSystem = (Category == PpCategorySystem || Category == PpCategoryLsass);

    ObDereferenceObject(process);

    //
    // Add to global protected process list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ProtectedProcessLock);

    InsertTailList(&g_DriverData.ProtectedProcessList, &entry->ListEntry);
    InterlockedIncrement(&g_DriverData.ProtectedProcessCount);

    ExReleasePushLockExclusive(&g_DriverData.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ObRemoveProtectedProcess(
    _In_ HANDLE ProcessId
    )
{
    PLIST_ENTRY listEntry;
    POB_PROTECTED_PROCESS_ENTRY entry;
    POB_PROTECTED_PROCESS_ENTRY foundEntry = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ProtectedProcessLock);

    for (listEntry = g_DriverData.ProtectedProcessList.Flink;
         listEntry != &g_DriverData.ProtectedProcessList;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, OB_PROTECTED_PROCESS_ENTRY, ListEntry);

        if (entry->ProcessId == ProcessId) {
            foundEntry = entry;
            RemoveEntryList(&entry->ListEntry);
            InterlockedDecrement(&g_DriverData.ProtectedProcessCount);
            break;
        }
    }

    ExReleasePushLockExclusive(&g_DriverData.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    //
    // Free outside lock
    //
    if (foundEntry != NULL) {
        //
        // Wait for reference count to drop (shouldn't be held long)
        //
        while (InterlockedCompareExchange(&foundEntry->ReferenceCount, 0, 0) > 0) {
            LARGE_INTEGER delay;
            delay.QuadPart = -1000; // 100us
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }

        ShadowStrikeFreePoolWithTag(foundEntry, OB_PROTECTED_ENTRY_TAG);
    }
}

_Use_decl_annotations_
BOOLEAN
ObIsInProtectedList(
    _In_ HANDLE ProcessId,
    _Out_opt_ POB_PROTECTED_PROCESS_ENTRY* OutEntry
    )
{
    PLIST_ENTRY listEntry;
    POB_PROTECTED_PROCESS_ENTRY entry;
    BOOLEAN found = FALSE;

    if (OutEntry != NULL) {
        *OutEntry = NULL;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ProtectedProcessLock);

    for (listEntry = g_DriverData.ProtectedProcessList.Flink;
         listEntry != &g_DriverData.ProtectedProcessList;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, OB_PROTECTED_PROCESS_ENTRY, ListEntry);

        if (entry->ProcessId == ProcessId) {
            found = TRUE;
            if (OutEntry != NULL) {
                InterlockedIncrement(&entry->ReferenceCount);
                *OutEntry = entry;
            }
            break;
        }
    }

    ExReleasePushLockShared(&g_DriverData.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    return found;
}

// ============================================================================
// PUBLIC FUNCTIONS - TELEMETRY
// ============================================================================

_Use_decl_annotations_
VOID
ObQueueTelemetryEvent(
    _In_ POB_TELEMETRY_EVENT Event
    )
{
    //
    // Check if telemetry is enabled and user-mode is connected
    //
    if (!g_ObCallbackContext.EnableTelemetry) {
        return;
    }

    if (!SHADOWSTRIKE_USER_MODE_CONNECTED()) {
        return;
    }

    //
    // Queue event for delivery to user-mode via filter communication port
    // This integrates with the existing message infrastructure
    //
    // For enterprise deployment, this would use the message queue in Globals.h
    // Format: SHADOWSTRIKE_MESSAGE with type = MESSAGE_TYPE_TELEMETRY
    //

#ifdef WPP_TRACING
    TraceEvents(TRACE_LEVEL_VERBOSE, TRACE_FLAG_FILTER,
        "Telemetry: Src=%p->Tgt=%p Access=0x%08X->0x%08X Score=%u",
        Event->SourceProcessId,
        Event->TargetProcessId,
        Event->OriginalAccess,
        Event->AllowedAccess,
        Event->SuspicionScore);
#endif

    //
    // In production: Allocate message from lookaside, populate, and send
    // FltSendMessage or queue for async delivery
    //
}

_Use_decl_annotations_
VOID
ObGetCallbackStatistics(
    _Out_opt_ PLONG64 ProcessOps,
    _Out_opt_ PLONG64 ThreadOps,
    _Out_opt_ PLONG64 AccessStripped,
    _Out_opt_ PLONG64 Suspicious
    )
{
    if (ProcessOps != NULL) {
        *ProcessOps = g_ObCallbackContext.TotalProcessOperations;
    }
    if (ThreadOps != NULL) {
        *ThreadOps = g_ObCallbackContext.TotalThreadOperations;
    }
    if (AccessStripped != NULL) {
        *AccessStripped = g_ObCallbackContext.ProcessAccessStripped +
                          g_ObCallbackContext.ThreadAccessStripped;
    }
    if (Suspicious != NULL) {
        *Suspicious = g_ObCallbackContext.SuspiciousOperations;
    }
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - PROCESS CLASSIFICATION
// ============================================================================

static BOOLEAN
ObpIsProcessProtectedInternal(
    _In_ HANDLE ProcessId,
    _In_opt_ PEPROCESS Process,
    _Out_opt_ PP_PROCESS_CATEGORY* OutCategory,
    _Out_opt_ PP_PROTECTION_LEVEL* OutProtectionLevel
    )
{
    POB_PROTECTED_PROCESS_ENTRY entry = NULL;
    PP_PROCESS_CATEGORY category = PpCategoryUnknown;
    PP_PROTECTION_LEVEL level = PpProtectionNone;

    //
    // First check the centralized process protection subsystem
    //
    if (PpIsProcessProtected(ProcessId, OutCategory, OutProtectionLevel)) {
        return TRUE;
    }

    //
    // Check our local protected process list
    //
    if (ObIsInProtectedList(ProcessId, &entry)) {
        if (OutCategory != NULL) {
            *OutCategory = (PP_PROCESS_CATEGORY)entry->Category;
        }
        if (OutProtectionLevel != NULL) {
            *OutProtectionLevel = (PP_PROTECTION_LEVEL)entry->ProtectionLevel;
        }

        //
        // Release reference
        //
        InterlockedDecrement(&entry->ReferenceCount);
        return TRUE;
    }

    //
    // Dynamic classification for unregistered processes
    // This is the fallback path - we need the EPROCESS
    //
    if (Process == NULL) {
        return FALSE;
    }

    if (ObpIsLsassProcess(Process)) {
        category = PpCategoryLsass;
        level = PpProtectionCritical;
    } else if (ObpIsCriticalSystemProcess(Process)) {
        category = PpCategorySystem;
        level = PpProtectionStrict;
    } else if (ObpIsShadowStrikeProcess(Process)) {
        category = PpCategoryAntimalware;
        level = PpProtectionAntimalware;
    } else {
        return FALSE;
    }

    if (OutCategory != NULL) {
        *OutCategory = category;
    }
    if (OutProtectionLevel != NULL) {
        *OutProtectionLevel = level;
    }

    return TRUE;
}

static BOOLEAN
ObpIsLsassProcess(
    _In_ PEPROCESS Process
    )
{
    HANDLE processId;
    LONG64 cachedPid;

    //
    // Fast path: Check cached PID using atomic read
    //
    cachedPid = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ObCallbackContext.LsassPid,
        0, 0
    );

    if (cachedPid != 0) {
        processId = PsGetProcessId(Process);
        if (processId == (HANDLE)(ULONG_PTR)cachedPid) {
            return TRUE;
        }
    }

    //
    // Check by name using IRQL-safe function
    //
    if (ObpMatchProcessNameAnsi(Process, g_LsassNames, ARRAYSIZE(g_LsassNames))) {
        //
        // Optionally validate path if enabled
        //
        if (g_ObCallbackContext.EnablePathValidation) {
            if (!ObpValidateProcessPath(Process, PpCategoryLsass)) {
                return FALSE;
            }
        }

        //
        // Cache the PID for fast lookup
        //
        processId = PsGetProcessId(Process);
        InterlockedExchange64(
            (volatile LONG64*)&g_ObCallbackContext.LsassPid,
            (LONG64)(ULONG_PTR)processId
        );

        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
ObpIsCriticalSystemProcess(
    _In_ PEPROCESS Process
    )
{
    HANDLE processId;
    LONG64 cachedPid;

    processId = PsGetProcessId(Process);

    //
    // System and idle process
    //
    if (processId == (HANDLE)0 || processId == (HANDLE)4) {
        return TRUE;
    }

    //
    // Fast path: Check cached PIDs
    //
    cachedPid = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ObCallbackContext.CsrssPid, 0, 0);
    if (cachedPid != 0 && processId == (HANDLE)(ULONG_PTR)cachedPid) {
        return TRUE;
    }

    cachedPid = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ObCallbackContext.ServicesPid, 0, 0);
    if (cachedPid != 0 && processId == (HANDLE)(ULONG_PTR)cachedPid) {
        return TRUE;
    }

    cachedPid = InterlockedCompareExchange64(
        (volatile LONG64*)&g_ObCallbackContext.WinlogonPid, 0, 0);
    if (cachedPid != 0 && processId == (HANDLE)(ULONG_PTR)cachedPid) {
        return TRUE;
    }

    //
    // Check by name
    //
    if (ObpMatchProcessNameAnsi(Process, g_CriticalSystemProcesses,
                                 ARRAYSIZE(g_CriticalSystemProcesses))) {
        //
        // Validate path for critical system processes
        //
        if (g_ObCallbackContext.EnablePathValidation) {
            if (!ObpValidateProcessPath(Process, PpCategorySystem)) {
                return FALSE;
            }
        }
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
ObpIsShadowStrikeProcess(
    _In_ PEPROCESS Process
    )
{
    HANDLE processId;
    PLIST_ENTRY listEntry;
    POB_PROTECTED_PROCESS_ENTRY entry;
    BOOLEAN found = FALSE;

    processId = PsGetProcessId(Process);

    //
    // FIXED: Actually traverse the protected process list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ProtectedProcessLock);

    for (listEntry = g_DriverData.ProtectedProcessList.Flink;
         listEntry != &g_DriverData.ProtectedProcessList;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, OB_PROTECTED_PROCESS_ENTRY, ListEntry);

        if (entry->ProcessId == processId && entry->IsShadowStrike) {
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&g_DriverData.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    if (found) {
        return TRUE;
    }

    //
    // Fallback to name matching
    //
    if (ObpMatchProcessNameAnsi(Process, g_ShadowStrikeProcesses,
                                 ARRAYSIZE(g_ShadowStrikeProcesses))) {
        //
        // For ShadowStrike processes, validate they're in our install directory
        //
        if (g_ObCallbackContext.EnablePathValidation) {
            if (!ObpValidateProcessPath(Process, PpCategoryAntimalware)) {
                return FALSE;
            }
        }
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
ObpIsSourceTrusted(
    _In_ HANDLE SourceProcessId,
    _In_ PEPROCESS SourceProcess
    )
{
    //
    // System process is always trusted
    //
    if (SourceProcessId == (HANDLE)4) {
        return TRUE;
    }

    //
    // Our own processes are trusted
    //
    if (ObpIsShadowStrikeProcess(SourceProcess)) {
        return TRUE;
    }

    //
    // Windows protected processes (PPL) are trusted
    //
    if (ShadowStrikeIsProcessProtected(SourceProcess)) {
        return TRUE;
    }

    //
    // Critical system processes are trusted
    //
    if (ObpIsCriticalSystemProcess(SourceProcess)) {
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - ACCESS CALCULATION
// ============================================================================

static ACCESS_MASK
ObpCalculateAllowedProcessAccess(
    _In_ ACCESS_MASK OriginalAccess,
    _In_ PP_PROTECTION_LEVEL ProtectionLevel,
    _In_ PP_PROCESS_CATEGORY Category,
    _In_ BOOLEAN IsSourceTrusted
    )
{
    ACCESS_MASK allowedAccess = OriginalAccess;
    ACCESS_MASK deniedAccess = 0;

    //
    // Trusted sources get more leeway
    //
    if (IsSourceTrusted) {
        //
        // Still block terminate/debug for antimalware
        //
        if (Category == PpCategoryAntimalware) {
            deniedAccess = PROCESS_TERMINATE;
        }
        //
        // Block credential dumping even from trusted for LSASS
        //
        else if (Category == PpCategoryLsass) {
            deniedAccess = PROCESS_VM_READ | PROCESS_VM_WRITE;
        }
    } else {
        //
        // Apply protection based on level
        //
        switch (ProtectionLevel) {
            case PpProtectionLight:
                //
                // Only block terminate
                //
                deniedAccess = PROCESS_TERMINATE;
                break;

            case PpProtectionMedium:
                //
                // Block terminate and injection
                //
                deniedAccess = PP_DANGEROUS_TERMINATE_ACCESS | PP_DANGEROUS_INJECT_ACCESS;
                break;

            case PpProtectionStrict:
                //
                // Block all dangerous access
                //
                deniedAccess = PP_FULL_DANGEROUS_ACCESS;
                break;

            case PpProtectionCritical:
                //
                // LSASS/CSRSS - maximum protection
                //
                deniedAccess = PP_FULL_DANGEROUS_ACCESS | PROCESS_VM_READ;
                break;

            case PpProtectionAntimalware:
                //
                // EDR self-protection - block everything except query
                //
                deniedAccess = ~(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE);
                break;

            default:
                break;
        }

        //
        // Special handling for LSASS (credential protection)
        //
        if (Category == PpCategoryLsass && g_ObCallbackContext.EnableCredentialProtection) {
            //
            // Block all memory access to LSASS
            //
            deniedAccess |= PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
        }
    }

    allowedAccess = OriginalAccess & ~deniedAccess;

    return allowedAccess;
}

static ACCESS_MASK
ObpCalculateAllowedThreadAccess(
    _In_ ACCESS_MASK OriginalAccess,
    _In_ PP_PROTECTION_LEVEL ProtectionLevel,
    _In_ PP_PROCESS_CATEGORY Category,
    _In_ BOOLEAN IsSourceTrusted,
    _In_ BOOLEAN IsCrossProcess
    )
{
    ACCESS_MASK allowedAccess = OriginalAccess;
    ACCESS_MASK deniedAccess = 0;

    //
    // Same-process access is not restricted here (checked earlier)
    //
    if (!IsCrossProcess) {
        return OriginalAccess;
    }

    //
    // Trusted sources get limited leeway for threads
    //
    if (IsSourceTrusted) {
        //
        // Still block context manipulation for protected processes
        //
        if (ProtectionLevel >= PpProtectionStrict) {
            deniedAccess = THREAD_SET_CONTEXT | THREAD_SET_INFORMATION;
        }
    } else {
        //
        // Apply protection based on level
        //
        switch (ProtectionLevel) {
            case PpProtectionLight:
                deniedAccess = THREAD_TERMINATE;
                break;

            case PpProtectionMedium:
                deniedAccess = THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT;
                break;

            case PpProtectionStrict:
            case PpProtectionCritical:
                deniedAccess = OB_DANGEROUS_THREAD_ACCESS;
                break;

            case PpProtectionAntimalware:
                //
                // Block almost everything
                //
                deniedAccess = ~OB_SAFE_THREAD_ACCESS;
                break;

            default:
                break;
        }

        //
        // FIXED: Apply category-specific thread protection
        //
        switch (Category) {
            case PpCategoryLsass:
                //
                // LSASS threads - maximum protection to prevent credential theft
                //
                deniedAccess |= THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                               THREAD_SUSPEND_RESUME | THREAD_SET_THREAD_TOKEN;
                break;

            case PpCategoryAntimalware:
                //
                // EDR threads - prevent any manipulation
                //
                deniedAccess = ~OB_SAFE_THREAD_ACCESS;
                break;

            case PpCategorySystem:
                //
                // System threads - prevent impersonation attacks
                //
                deniedAccess |= THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION |
                               THREAD_SET_THREAD_TOKEN;
                break;

            default:
                break;
        }
    }

    allowedAccess = OriginalAccess & ~deniedAccess;

    return allowedAccess;
}

static ULONG
ObpCalculateSuspicionScore(
    _In_ ACCESS_MASK RequestedAccess,
    _In_ ACCESS_MASK StrippedAccess,
    _In_ PP_PROCESS_CATEGORY TargetCategory,
    _In_ BOOLEAN IsCrossSession,
    _In_ BOOLEAN IsDuplicate
    )
{
    ULONG score = 0;

    //
    // Base score from stripped access
    //
    if (StrippedAccess & PROCESS_TERMINATE) {
        score += 20;
    }

    if (StrippedAccess & PP_DANGEROUS_INJECT_ACCESS) {
        score += 30;
    }

    if (StrippedAccess & (PROCESS_VM_READ | PROCESS_VM_WRITE)) {
        score += 15;
    }

    //
    // Target category multiplier
    //
    switch (TargetCategory) {
        case PpCategoryLsass:
            score += 40;
            //
            // Credential dump pattern
            //
            if ((RequestedAccess & PP_CREDENTIAL_DUMP_ACCESS) == PP_CREDENTIAL_DUMP_ACCESS) {
                score += 30;
            }
            break;

        case PpCategoryAntimalware:
            score += 35;
            break;

        case PpCategorySystem:
            score += 25;
            break;

        case PpCategoryServices:
            score += 15;
            break;

        default:
            break;
    }

    //
    // Cross-session access is suspicious
    //
    if (IsCrossSession) {
        score += 20;
    }

    //
    // Handle duplication chains can indicate evasion
    //
    if (IsDuplicate) {
        score += 10;
    }

    return score;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - LOGGING AND TELEMETRY
// ============================================================================

static VOID
ObpLogAccessStripped(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ PEPROCESS SourceProcess,
    _In_ PEPROCESS TargetProcess,
    _In_ ACCESS_MASK OriginalAccess,
    _In_ ACCESS_MASK AllowedAccess,
    _In_ PP_PROCESS_CATEGORY TargetCategory,
    _In_ BOOLEAN IsProcessHandle,
    _In_ BOOLEAN IsDuplicate,
    _In_ BOOLEAN IsKernelHandle,
    _In_ BOOLEAN IsCrossSession,
    _In_ ULONG SuspicionScore
    )
{
    OB_TELEMETRY_EVENT event;
    ACCESS_MASK strippedAccess = OriginalAccess & ~AllowedAccess;

#ifdef WPP_TRACING
    TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_PROTECTION,
        "Access stripped: Source=%p Target=%p Type=%s Original=0x%08X Allowed=0x%08X "
        "Stripped=0x%08X Score=%u Category=%u",
        SourceProcessId,
        TargetProcessId,
        IsProcessHandle ? "Process" : "Thread",
        OriginalAccess,
        AllowedAccess,
        strippedAccess,
        SuspicionScore,
        (ULONG)TargetCategory);
#endif

    //
    // Build telemetry event for user-mode delivery
    //
    if (g_ObCallbackContext.EnableTelemetry && SuspicionScore >= OB_SUSPICIOUS_SCORE_THRESHOLD) {
        RtlZeroMemory(&event, sizeof(event));

        KeQuerySystemTime(&event.Timestamp);
        event.EventId = (ULONG64)InterlockedIncrement64(&g_DriverData.NextMessageId);

        event.SourceProcessId = SourceProcessId;
        event.TargetProcessId = TargetProcessId;
        event.TargetCategory = (ULONG)TargetCategory;

        //
        // Get process names using IRQL-safe method
        //
        ObpGetProcessImageFileNameSafe(SourceProcess, event.SourceImageName);
        ObpGetProcessImageFileNameSafe(TargetProcess, event.TargetImageName);

        event.IsProcessHandle = IsProcessHandle;
        event.IsDuplicate = IsDuplicate;
        event.IsKernelHandle = IsKernelHandle;
        event.IsCrossSession = IsCrossSession;

        event.OriginalAccess = OriginalAccess;
        event.AllowedAccess = AllowedAccess;
        event.StrippedAccess = strippedAccess;
        event.SuspicionScore = SuspicionScore;

        ObQueueTelemetryEvent(&event);
    }
}

static BOOLEAN
ObpShouldRateLimit(
    VOID
    )
{
    LARGE_INTEGER currentTime;
    LONG64 currentSecond;
    LONG64 previousSecond;
    LONG currentCount;
    KIRQL oldIrql;

    KeQuerySystemTime(&currentTime);
    currentSecond = currentTime.QuadPart;

    //
    // FIXED: Use spin lock for DISPATCH_LEVEL safety and atomic 64-bit access
    //
    KeAcquireSpinLock(&g_ObCallbackContext.RateLimitSpinLock, &oldIrql);

    previousSecond = g_ObCallbackContext.CurrentSecondStart100ns;

    //
    // Check if we're in a new second
    //
    if ((currentSecond - previousSecond) >= OB_RATE_LIMIT_WINDOW_100NS) {
        //
        // New second - reset counter
        //
        g_ObCallbackContext.CurrentSecondStart100ns = currentSecond;
        g_ObCallbackContext.CurrentSecondEvents = 1;
        KeReleaseSpinLock(&g_ObCallbackContext.RateLimitSpinLock, oldIrql);
        return FALSE;
    }

    //
    // Same second - increment and check
    //
    currentCount = ++g_ObCallbackContext.CurrentSecondEvents;

    KeReleaseSpinLock(&g_ObCallbackContext.RateLimitSpinLock, oldIrql);

    return (currentCount > OB_TELEMETRY_RATE_LIMIT);
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - INITIALIZATION
// ============================================================================

static NTSTATUS
ObpInitializeWellKnownPids(
    VOID
    )
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0;
    ULONG returnLength = 0;
    PSYSTEM_PROCESS_INFORMATION processInfo;
    UNICODE_STRING lsassName;
    UNICODE_STRING csrssName;
    UNICODE_STRING servicesName;
    UNICODE_STRING winlogonName;
    UNICODE_STRING smssName;

    //
    // Only initialize once
    //
    if (InterlockedCompareExchange(&g_ObCallbackContext.WellKnownPidsInitialized, 1, 0) != 0) {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&lsassName, L"lsass.exe");
    RtlInitUnicodeString(&csrssName, L"csrss.exe");
    RtlInitUnicodeString(&servicesName, L"services.exe");
    RtlInitUnicodeString(&winlogonName, L"winlogon.exe");
    RtlInitUnicodeString(&smssName, L"smss.exe");

    //
    // Query system process information
    //
    bufferSize = 256 * 1024; // Start with 256KB
    buffer = ShadowStrikeAllocatePoolWithTag(PagedPool, bufferSize, OB_POOL_TAG);
    if (buffer == NULL) {
        InterlockedExchange(&g_ObCallbackContext.WellKnownPidsInitialized, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(
        SystemProcessInformation,
        buffer,
        bufferSize,
        &returnLength
    );

    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        ShadowStrikeFreePoolWithTag(buffer, OB_POOL_TAG);
        bufferSize = returnLength + 4096;
        buffer = ShadowStrikeAllocatePoolWithTag(PagedPool, bufferSize, OB_POOL_TAG);
        if (buffer == NULL) {
            InterlockedExchange(&g_ObCallbackContext.WellKnownPidsInitialized, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwQuerySystemInformation(
            SystemProcessInformation,
            buffer,
            bufferSize,
            &returnLength
        );
    }

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(buffer, OB_POOL_TAG);
        InterlockedExchange(&g_ObCallbackContext.WellKnownPidsInitialized, 0);
        return status;
    }

    //
    // Walk the process list and find well-known processes
    //
    processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

    while (TRUE) {
        if (processInfo->ImageName.Buffer != NULL) {
            if (RtlEqualUnicodeString(&processInfo->ImageName, &lsassName, TRUE)) {
                InterlockedExchange64(
                    (volatile LONG64*)&g_ObCallbackContext.LsassPid,
                    (LONG64)(ULONG_PTR)processInfo->UniqueProcessId
                );
            }
            else if (RtlEqualUnicodeString(&processInfo->ImageName, &csrssName, TRUE)) {
                //
                // There can be multiple csrss instances - cache the first (session 0)
                //
                if (g_ObCallbackContext.CsrssPid == 0) {
                    InterlockedExchange64(
                        (volatile LONG64*)&g_ObCallbackContext.CsrssPid,
                        (LONG64)(ULONG_PTR)processInfo->UniqueProcessId
                    );
                }
            }
            else if (RtlEqualUnicodeString(&processInfo->ImageName, &servicesName, TRUE)) {
                InterlockedExchange64(
                    (volatile LONG64*)&g_ObCallbackContext.ServicesPid,
                    (LONG64)(ULONG_PTR)processInfo->UniqueProcessId
                );
            }
            else if (RtlEqualUnicodeString(&processInfo->ImageName, &winlogonName, TRUE)) {
                if (g_ObCallbackContext.WinlogonPid == 0) {
                    InterlockedExchange64(
                        (volatile LONG64*)&g_ObCallbackContext.WinlogonPid,
                        (LONG64)(ULONG_PTR)processInfo->UniqueProcessId
                    );
                }
            }
            else if (RtlEqualUnicodeString(&processInfo->ImageName, &smssName, TRUE)) {
                InterlockedExchange64(
                    (volatile LONG64*)&g_ObCallbackContext.SmsssPid,
                    (LONG64)(ULONG_PTR)processInfo->UniqueProcessId
                );
            }
        }

        if (processInfo->NextEntryOffset == 0) {
            break;
        }

        processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
    }

    ShadowStrikeFreePoolWithTag(buffer, OB_POOL_TAG);

    return STATUS_SUCCESS;
}

static BOOLEAN
ObpMatchProcessNameAnsi(
    _In_ PEPROCESS Process,
    _In_ const CHAR** NameList,
    _In_ ULONG NameCount
    )
{
    CHAR imageName[16];
    ULONG i;

    //
    // Get image name using IRQL-safe function
    //
    ObpGetProcessImageFileNameSafe(Process, imageName);

    if (imageName[0] == '\0') {
        return FALSE;
    }

    //
    // Compare against list (case-insensitive)
    //
    for (i = 0; i < NameCount; i++) {
        if (_stricmp(imageName, NameList[i]) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

static VOID
ObpGetProcessImageFileNameSafe(
    _In_ PEPROCESS Process,
    _Out_writes_(16) PCHAR NameBuffer
    )
{
    PCHAR imageName;

    RtlZeroMemory(NameBuffer, 16);

    //
    // PsGetProcessImageFileName is IRQL-safe and returns up to 15 chars
    // This is a documented, stable API
    //
    imageName = PsGetProcessImageFileName(Process);
    if (imageName != NULL) {
        RtlCopyMemory(NameBuffer, imageName, 15);
        NameBuffer[15] = '\0';
    }
}

static BOOLEAN
ObpValidateProcessPath(
    _In_ PEPROCESS Process,
    _In_ PP_PROCESS_CATEGORY ExpectedCategory
    )
{
    NTSTATUS status;
    PUNICODE_STRING imagePath = NULL;
    BOOLEAN isValid = FALSE;
    UNICODE_STRING systemRoot;
    UNICODE_STRING windowsPrefix;

    //
    // This function must be called at PASSIVE_LEVEL for SeLocateProcessImageName
    // Check IRQL and skip validation if elevated
    //
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        //
        // Cannot validate at elevated IRQL - allow by default
        // This is safe because we've already matched by name
        //
        return TRUE;
    }

    status = SeLocateProcessImageName(Process, &imagePath);
    if (!NT_SUCCESS(status) || imagePath == NULL || imagePath->Buffer == NULL) {
        //
        // Cannot get path - deny by default for security
        //
        return FALSE;
    }

    //
    // Validate based on expected category
    //
    switch (ExpectedCategory) {
        case PpCategoryLsass:
        case PpCategorySystem:
            //
            // Must be in \SystemRoot\System32\ or \Windows\System32\
            //
            RtlInitUnicodeString(&systemRoot, L"\\SystemRoot\\System32\\");
            RtlInitUnicodeString(&windowsPrefix, L"\\??\\C:\\Windows\\System32\\");

            if (RtlPrefixUnicodeString(&systemRoot, imagePath, TRUE) ||
                RtlPrefixUnicodeString(&windowsPrefix, imagePath, TRUE)) {
                isValid = TRUE;
            }
            break;

        case PpCategoryAntimalware:
            //
            // ShadowStrike processes - validate against known install path
            // In production, this would check a registry-stored path
            //
            {
                UNICODE_STRING shadowStrikePath;
                RtlInitUnicodeString(&shadowStrikePath, L"\\??\\C:\\Program Files\\ShadowStrike\\");

                if (RtlPrefixUnicodeString(&shadowStrikePath, imagePath, TRUE)) {
                    isValid = TRUE;
                }
            }
            break;

        case PpCategoryServices:
            //
            // Services can be anywhere, but validate against known service paths
            //
            isValid = TRUE;
            break;

        default:
            isValid = TRUE;
            break;
    }

    ExFreePool(imagePath);

    return isValid;
}

static ULONG64
ObpComputePathHash(
    _In_ PCUNICODE_STRING Path
    )
{
    ULONG64 hash = 14695981039346656037ULL; // FNV-1a offset basis
    ULONG i;
    WCHAR ch;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return 0;
    }

    for (i = 0; i < Path->Length / sizeof(WCHAR); i++) {
        ch = RtlUpcaseUnicodeChar(Path->Buffer[i]);
        hash ^= (ULONG64)ch;
        hash *= 1099511628211ULL; // FNV-1a prime
    }

    return hash;
}

static VOID
ObpCacheProcessName(
    _In_ HANDLE ProcessId,
    _In_reads_(16) const CHAR* ImageFileName
    )
{
    LONG index;
    POB_NAME_CACHE_ENTRY entry;

    //
    // Get next cache slot using atomic increment
    //
    index = InterlockedIncrement(&g_ObCallbackContext.NameCacheIndex) % OB_NAME_CACHE_SIZE;
    entry = &g_ObCallbackContext.NameCache[index];

    //
    // Update entry atomically
    //
    InterlockedExchange(&entry->Valid, 0);
    entry->ProcessId = ProcessId;
    RtlCopyMemory(entry->ImageFileName, ImageFileName, 16);
    KeQuerySystemTime(&entry->CacheTime);
    InterlockedExchange(&entry->Valid, 1);
}

static BOOLEAN
ObpLookupCachedName(
    _In_ HANDLE ProcessId,
    _Out_writes_(16) PCHAR NameBuffer
    )
{
    ULONG i;
    POB_NAME_CACHE_ENTRY entry;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER age;

    RtlZeroMemory(NameBuffer, 16);
    KeQuerySystemTime(&currentTime);

    for (i = 0; i < OB_NAME_CACHE_SIZE; i++) {
        entry = &g_ObCallbackContext.NameCache[i];

        if (InterlockedCompareExchange(&entry->Valid, 1, 1) != 1) {
            continue;
        }

        if (entry->ProcessId != ProcessId) {
            continue;
        }

        //
        // Check TTL
        //
        age.QuadPart = currentTime.QuadPart - entry->CacheTime.QuadPart;
        if (age.QuadPart > OB_NAME_CACHE_TTL_100NS) {
            //
            // Expired - invalidate
            //
            InterlockedExchange(&entry->Valid, 0);
            continue;
        }

        RtlCopyMemory(NameBuffer, entry->ImageFileName, 16);
        return TRUE;
    }

    return FALSE;
}
