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
 * Security Detection Capabilities:
 * - T1003: OS Credential Dumping (LSASS protection)
 * - T1055: Process Injection (VM_WRITE/CREATE_THREAD blocking)
 * - T1489: Service Stop (service process protection)
 * - T1562: Impair Defenses (EDR self-protection)
 * - T1106: Native API abuse detection
 * - T1134: Access Token Manipulation
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ObjectCallback.h"
#include "ProcessProtection.h"
#include "../../Core/Globals.h"
#include "../../Utilities/ProcessUtils.h"
#include "../../Utilities/MemoryUtils.h"

//
// WPP Tracing - conditionally include if available
//
#ifdef WPP_TRACING
#include "ObjectCallback.tmh"
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define OB_CALLBACK_VERSION                 0x100
#define OB_POOL_TAG                         'bOSS'
#define OB_MAX_CALLBACK_CONTEXTS            16
#define OB_TELEMETRY_RATE_LIMIT             100     // Max events per second
#define OB_SUSPICIOUS_SCORE_THRESHOLD       50      // Score to trigger alert

//
// Thread access masks for protection
//
#define OB_DANGEROUS_THREAD_ACCESS          \
    (THREAD_TERMINATE |                     \
     THREAD_SUSPEND_RESUME |                \
     THREAD_SET_CONTEXT |                   \
     THREAD_SET_INFORMATION |               \
     THREAD_SET_THREAD_TOKEN |              \
     THREAD_IMPERSONATE |                   \
     THREAD_DIRECT_IMPERSONATION)

#define OB_INJECTION_THREAD_ACCESS          \
    (THREAD_SET_CONTEXT |                   \
     THREAD_GET_CONTEXT |                   \
     THREAD_SUSPEND_RESUME)

#define OB_SAFE_THREAD_ACCESS               \
    (THREAD_QUERY_LIMITED_INFORMATION |     \
     SYNCHRONIZE)

//
// Well-known process names for classification
//
static const WCHAR* g_LsassNames[] = {
    L"lsass.exe",
    L"lsaiso.exe"
};

static const WCHAR* g_CriticalSystemProcesses[] = {
    L"csrss.exe",
    L"smss.exe",
    L"wininit.exe",
    L"winlogon.exe",
    L"services.exe",
    L"svchost.exe",
    L"spoolsv.exe",
    L"dwm.exe"
};

static const WCHAR* g_ShadowStrikeProcesses[] = {
    L"ShadowStrikeService.exe",
    L"ShadowStrikeUI.exe",
    L"ShadowStrikeScanner.exe",
    L"ShadowStrikeAgent.exe",
    L"ShadowStrikeUpdater.exe"
};

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Extended callback context for telemetry and state
 */
typedef struct _OB_CALLBACK_CONTEXT {
    //
    // Statistics
    //
    volatile LONG64 TotalProcessOperations;
    volatile LONG64 TotalThreadOperations;
    volatile LONG64 ProcessAccessStripped;
    volatile LONG64 ThreadAccessStripped;
    volatile LONG64 CredentialAccessBlocked;
    volatile LONG64 InjectionBlocked;
    volatile LONG64 TerminationBlocked;
    volatile LONG64 SuspiciousOperations;

    //
    // Rate limiting
    //
    volatile LONG CurrentSecondEvents;
    LARGE_INTEGER CurrentSecondStart;
    EX_PUSH_LOCK RateLimitLock;

    //
    // Cached well-known PIDs
    //
    HANDLE LsassPid;
    HANDLE CsrssPid;
    HANDLE ServicesPid;
    HANDLE WinlogonPid;
    volatile LONG WellKnownPidsInitialized;

    //
    // Configuration
    //
    BOOLEAN EnableCredentialProtection;
    BOOLEAN EnableInjectionProtection;
    BOOLEAN EnableTerminationProtection;
    BOOLEAN EnableSelfProtection;
    BOOLEAN EnableCrossSessionMonitoring;
    BOOLEAN LogStrippedAccess;

    //
    // Initialization state
    //
    BOOLEAN Initialized;
    LARGE_INTEGER StartTime;

} OB_CALLBACK_CONTEXT, *POB_CALLBACK_CONTEXT;

/**
 * @brief Thread operation analysis context
 */
typedef struct _OB_THREAD_ANALYSIS {
    HANDLE SourceProcessId;
    HANDLE TargetProcessId;
    HANDLE TargetThreadId;
    ACCESS_MASK OriginalAccess;
    ACCESS_MASK ModifiedAccess;
    BOOLEAN IsKernelHandle;
    BOOLEAN TargetIsProtected;
    BOOLEAN SourceIsSelf;
    BOOLEAN IsCrossProcess;
    ULONG SuspicionScore;
    ULONG Flags;
} OB_THREAD_ANALYSIS, *POB_THREAD_ANALYSIS;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static OB_CALLBACK_CONTEXT g_ObCallbackContext = { 0 };

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static BOOLEAN
ObpIsProcessProtected(
    _In_ HANDLE ProcessId,
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
    _In_ ACCESS_MASK OriginalAccess,
    _In_ ACCESS_MASK AllowedAccess,
    _In_ BOOLEAN IsProcessHandle,
    _In_ ULONG SuspicionScore
    );

static BOOLEAN
ObpShouldRateLimit(
    VOID
    );

static VOID
ObpInitializeWellKnownPids(
    VOID
    );

static BOOLEAN
ObpMatchProcessName(
    _In_ PEPROCESS Process,
    _In_ const WCHAR** NameList,
    _In_ ULONG NameCount
    );

static NTSTATUS
ObpGetProcessImageName(
    _In_ PEPROCESS Process,
    _Out_ PUNICODE_STRING ImageName
    );

static VOID
ObpFreeImageName(
    _Inout_ PUNICODE_STRING ImageName
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

    //
    // Initialize callback context if not already done
    //
    if (!g_ObCallbackContext.Initialized) {
        RtlZeroMemory(&g_ObCallbackContext, sizeof(OB_CALLBACK_CONTEXT));

        ExInitializePushLock(&g_ObCallbackContext.RateLimitLock);
        KeQuerySystemTime(&g_ObCallbackContext.StartTime);
        KeQuerySystemTime(&g_ObCallbackContext.CurrentSecondStart);

        //
        // Set default configuration
        //
        g_ObCallbackContext.EnableCredentialProtection = TRUE;
        g_ObCallbackContext.EnableInjectionProtection = TRUE;
        g_ObCallbackContext.EnableTerminationProtection = TRUE;
        g_ObCallbackContext.EnableSelfProtection = TRUE;
        g_ObCallbackContext.EnableCrossSessionMonitoring = TRUE;
        g_ObCallbackContext.LogStrippedAccess = TRUE;

        g_ObCallbackContext.Initialized = TRUE;
    }

    //
    // Initialize well-known PIDs (deferred)
    //
    ObpInitializeWellKnownPids();

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
    callbackRegistration.Version = OB_CALLBACK_VERSION;
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

    } else {
#ifdef WPP_TRACING
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_FLAG_FILTER,
            "ObRegisterCallbacks failed with status 0x%08X",
            status);
#endif
        g_DriverData.ObjectCallbackHandle = NULL;
    }

    return status;
}

_Use_decl_annotations_
VOID
ShadowStrikeUnregisterObjectCallbacks(
    VOID
    )
{
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

    g_ObCallbackContext.Initialized = FALSE;
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
    // Validate callback context
    //
    if (context == NULL || !context->Initialized) {
        context = &g_ObCallbackContext;
        if (!context->Initialized) {
            return OB_PREOP_SUCCESS;
        }
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&context->TotalProcessOperations);

    //
    // Get target process
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
    // Kernel-mode handles from trusted sources are allowed
    // But we still check for critical processes
    //
    if (isKernelHandle) {
        //
        // Only protect against kernel handles for antimalware processes
        // to prevent kernel-mode attacks on EDR
        //
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
    if (!ObpIsProcessProtected(targetProcessId, &targetCategory, &protectionLevel)) {
        //
        // Dynamic classification for unregistered processes
        //
        if (ObpIsLsassProcess(targetProcess)) {
            targetCategory = PpCategoryLsass;
            protectionLevel = PpProtectionCritical;
        } else if (ObpIsCriticalSystemProcess(targetProcess)) {
            targetCategory = PpCategorySystem;
            protectionLevel = PpProtectionStrict;
        } else if (ObpIsShadowStrikeProcess(targetProcess)) {
            targetCategory = PpCategoryAntimalware;
            protectionLevel = PpProtectionAntimalware;
        } else {
            //
            // Target is not protected - allow
            //
            return OB_PREOP_SUCCESS;
        }
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
        // Update statistics
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
                originalAccess,
                allowedAccess,
                TRUE,
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
    HANDLE targetThreadId;
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
    // Validate callback context
    //
    if (context == NULL || !context->Initialized) {
        context = &g_ObCallbackContext;
        if (!context->Initialized) {
            return OB_PREOP_SUCCESS;
        }
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

    targetThreadId = PsGetThreadId(targetThread);
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
    // Cross-process thread access is always notable
    //
    isCrossProcess = TRUE;

    //
    // Determine operation type
    //
    isKernelHandle = (OperationInformation->KernelHandle != FALSE);
    isDuplicate = (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE);

    //
    // Kernel-mode handles from trusted sources
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
    if (!ObpIsProcessProtected(targetProcessId, &targetCategory, &protectionLevel)) {
        //
        // Dynamic classification
        //
        if (ObpIsLsassProcess(targetProcess)) {
            targetCategory = PpCategoryLsass;
            protectionLevel = PpProtectionCritical;
        } else if (ObpIsCriticalSystemProcess(targetProcess)) {
            targetCategory = PpCategorySystem;
            protectionLevel = PpProtectionStrict;
        } else if (ObpIsShadowStrikeProcess(targetProcess)) {
            targetCategory = PpCategoryAntimalware;
            protectionLevel = PpProtectionAntimalware;
        } else {
            //
            // Target is not protected - allow
            //
            return OB_PREOP_SUCCESS;
        }
    }

    //
    // Check if source is trusted
    //
    isSourceTrusted = ObpIsSourceTrusted(sourceProcessId, sourceProcess);

    //
    // Calculate allowed thread access
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
        // Cross-process thread access is inherently more suspicious
        //
        suspicionScore = ObpCalculateSuspicionScore(
            originalAccess,
            strippedAccess,
            targetCategory,
            FALSE,
            isDuplicate
        );

        //
        // Thread injection pattern detection
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
                originalAccess,
                allowedAccess,
                FALSE,
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
// PRIVATE HELPER FUNCTIONS - PROCESS CLASSIFICATION
// ============================================================================

static BOOLEAN
ObpIsProcessProtected(
    _In_ HANDLE ProcessId,
    _Out_opt_ PP_PROCESS_CATEGORY* OutCategory,
    _Out_opt_ PP_PROTECTION_LEVEL* OutProtectionLevel
    )
{
    //
    // Check against process protection subsystem
    //
    return PpIsProcessProtected(ProcessId, OutCategory, OutProtectionLevel);
}

static BOOLEAN
ObpIsLsassProcess(
    _In_ PEPROCESS Process
    )
{
    HANDLE processId;

    //
    // Fast path: Check cached PID
    //
    if (g_ObCallbackContext.LsassPid != NULL) {
        processId = PsGetProcessId(Process);
        if (processId == g_ObCallbackContext.LsassPid) {
            return TRUE;
        }
    }

    //
    // Check by name
    //
    return ObpMatchProcessName(
        Process,
        g_LsassNames,
        ARRAYSIZE(g_LsassNames)
    );
}

static BOOLEAN
ObpIsCriticalSystemProcess(
    _In_ PEPROCESS Process
    )
{
    HANDLE processId;

    //
    // Fast path: Check cached PIDs
    //
    processId = PsGetProcessId(Process);

    if (g_ObCallbackContext.CsrssPid != NULL &&
        processId == g_ObCallbackContext.CsrssPid) {
        return TRUE;
    }

    if (g_ObCallbackContext.ServicesPid != NULL &&
        processId == g_ObCallbackContext.ServicesPid) {
        return TRUE;
    }

    if (g_ObCallbackContext.WinlogonPid != NULL &&
        processId == g_ObCallbackContext.WinlogonPid) {
        return TRUE;
    }

    //
    // System and idle process
    //
    if (processId == (HANDLE)0 || processId == (HANDLE)4) {
        return TRUE;
    }

    //
    // Check by name
    //
    return ObpMatchProcessName(
        Process,
        g_CriticalSystemProcesses,
        ARRAYSIZE(g_CriticalSystemProcesses)
    );
}

static BOOLEAN
ObpIsShadowStrikeProcess(
    _In_ PEPROCESS Process
    )
{
    HANDLE processId;

    //
    // Check against our protected process list
    //
    processId = PsGetProcessId(Process);

    //
    // Check global protected process list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ProtectedProcessLock);

    PLIST_ENTRY listEntry;
    BOOLEAN found = FALSE;

    for (listEntry = g_DriverData.ProtectedProcessList.Flink;
         listEntry != &g_DriverData.ProtectedProcessList;
         listEntry = listEntry->Flink) {

        //
        // The protected process list structure depends on implementation
        // For now, check by name
        //
        break;
    }

    ExReleasePushLockShared(&g_DriverData.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    if (found) {
        return TRUE;
    }

    //
    // Fallback to name matching
    //
    return ObpMatchProcessName(
        Process,
        g_ShadowStrikeProcesses,
        ARRAYSIZE(g_ShadowStrikeProcesses)
    );
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
    // Windows protected processes are trusted
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

    UNREFERENCED_PARAMETER(Category);

    //
    // Cross-process thread access is always suspicious
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
    _In_ ACCESS_MASK OriginalAccess,
    _In_ ACCESS_MASK AllowedAccess,
    _In_ BOOLEAN IsProcessHandle,
    _In_ ULONG SuspicionScore
    )
{
    ACCESS_MASK strippedAccess = OriginalAccess & ~AllowedAccess;

#ifdef WPP_TRACING
    TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_PROTECTION,
        "Access stripped: Source=%p Target=%p Type=%s Original=0x%08X Allowed=0x%08X "
        "Stripped=0x%08X Score=%u",
        SourceProcessId,
        TargetProcessId,
        IsProcessHandle ? "Process" : "Thread",
        OriginalAccess,
        AllowedAccess,
        strippedAccess,
        SuspicionScore);
#else
    UNREFERENCED_PARAMETER(SourceProcessId);
    UNREFERENCED_PARAMETER(TargetProcessId);
    UNREFERENCED_PARAMETER(OriginalAccess);
    UNREFERENCED_PARAMETER(AllowedAccess);
    UNREFERENCED_PARAMETER(IsProcessHandle);
    UNREFERENCED_PARAMETER(SuspicionScore);
    UNREFERENCED_PARAMETER(strippedAccess);
#endif

    //
    // TODO: Send telemetry event to user-mode for high-score operations
    //
}

static BOOLEAN
ObpShouldRateLimit(
    VOID
    )
{
    LARGE_INTEGER currentTime;
    LARGE_INTEGER secondsDiff;
    LONG currentCount;

    KeQuerySystemTime(&currentTime);

    //
    // Check if we're in a new second
    //
    secondsDiff.QuadPart = (currentTime.QuadPart - g_ObCallbackContext.CurrentSecondStart.QuadPart) / 10000000;

    if (secondsDiff.QuadPart >= 1) {
        //
        // New second - reset counter
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_ObCallbackContext.RateLimitLock);

        if ((currentTime.QuadPart - g_ObCallbackContext.CurrentSecondStart.QuadPart) / 10000000 >= 1) {
            g_ObCallbackContext.CurrentSecondStart = currentTime;
            g_ObCallbackContext.CurrentSecondEvents = 0;
        }

        ExReleasePushLockExclusive(&g_ObCallbackContext.RateLimitLock);
        KeLeaveCriticalRegion();
    }

    currentCount = InterlockedIncrement(&g_ObCallbackContext.CurrentSecondEvents);

    return (currentCount > OB_TELEMETRY_RATE_LIMIT);
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS - INITIALIZATION
// ============================================================================

static VOID
ObpInitializeWellKnownPids(
    VOID
    )
{
    //
    // Only initialize once
    //
    if (InterlockedCompareExchange(&g_ObCallbackContext.WellKnownPidsInitialized, 1, 0) != 0) {
        return;
    }

    //
    // LSASS, CSRSS, etc. PIDs are typically discovered by enumerating processes
    // For now, we rely on dynamic detection in the callback
    // A full implementation would enumerate processes at startup
    //

    //
    // Detect well-known system processes through PpDetectCriticalProcesses
    // which is called during process protection initialization
    //
}

static BOOLEAN
ObpMatchProcessName(
    _In_ PEPROCESS Process,
    _In_ const WCHAR** NameList,
    _In_ ULONG NameCount
    )
{
    UNICODE_STRING imageName = { 0 };
    NTSTATUS status;
    ULONG i;
    BOOLEAN match = FALSE;
    PWCHAR lastSlash;
    UNICODE_STRING fileName;

    status = ObpGetProcessImageName(Process, &imageName);
    if (!NT_SUCCESS(status) || imageName.Buffer == NULL) {
        return FALSE;
    }

    //
    // Extract just the filename from the path
    //
    lastSlash = wcsrchr(imageName.Buffer, L'\\');
    if (lastSlash != NULL) {
        RtlInitUnicodeString(&fileName, lastSlash + 1);
    } else {
        fileName = imageName;
    }

    //
    // Compare against list
    //
    for (i = 0; i < NameCount; i++) {
        UNICODE_STRING compareName;
        RtlInitUnicodeString(&compareName, NameList[i]);

        if (RtlEqualUnicodeString(&fileName, &compareName, TRUE)) {
            match = TRUE;
            break;
        }
    }

    ObpFreeImageName(&imageName);

    return match;
}

static NTSTATUS
ObpGetProcessImageName(
    _In_ PEPROCESS Process,
    _Out_ PUNICODE_STRING ImageName
    )
{
    NTSTATUS status;
    PUNICODE_STRING processImageName = NULL;

    RtlZeroMemory(ImageName, sizeof(UNICODE_STRING));

    status = SeLocateProcessImageName(Process, &processImageName);
    if (!NT_SUCCESS(status) || processImageName == NULL) {
        return status;
    }

    //
    // Allocate and copy the string
    //
    ImageName->MaximumLength = processImageName->Length + sizeof(WCHAR);
    ImageName->Buffer = (PWCH)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        ImageName->MaximumLength,
        OB_POOL_TAG
    );

    if (ImageName->Buffer == NULL) {
        ExFreePool(processImageName);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(ImageName->Buffer, processImageName->Buffer, processImageName->Length);
    ImageName->Length = processImageName->Length;
    ImageName->Buffer[ImageName->Length / sizeof(WCHAR)] = L'\0';

    ExFreePool(processImageName);

    return STATUS_SUCCESS;
}

static VOID
ObpFreeImageName(
    _Inout_ PUNICODE_STRING ImageName
    )
{
    if (ImageName->Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(ImageName->Buffer, OB_POOL_TAG);
        ImageName->Buffer = NULL;
        ImageName->Length = 0;
        ImageName->MaximumLength = 0;
    }
}
