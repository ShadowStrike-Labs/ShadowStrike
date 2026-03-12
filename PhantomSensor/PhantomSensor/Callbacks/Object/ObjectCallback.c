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
#include "../../SelfProtection/SelfProtect.h"
#include "../../Utilities/ProcessUtils.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Communication/CommPort.h"
#include "../../Behavioral/BehaviorEngine.h"
#include "../../Exclusions/ExclusionManager.h"

#ifdef WPP_TRACING
#include "ObjectCallback.tmh"
#endif

// ============================================================================
// KERNEL API FORWARD DECLARATIONS
// ============================================================================

//
// PsGetProcessSessionId — returns session ID for a given EPROCESS
//
NTKERNELAPI
ULONG
PsGetProcessSessionId(
    _In_ PEPROCESS Process
    );

//
// PsGetProcessImageFileName — returns up to 15-char image name, IRQL-safe
//
NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

// ============================================================================
// SYSTEM STRUCTURES (for ZwQuerySystemInformation process enumeration)
// ============================================================================

#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

#ifndef _OB_SYSTEM_PROCESS_INFORMATION_DEFINED
#define _OB_SYSTEM_PROCESS_INFORMATION_DEFINED

typedef struct _OB_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} OB_SYSTEM_PROCESS_INFORMATION, *POB_SYSTEM_PROCESS_INFORMATION;

#endif // _OB_SYSTEM_PROCESS_INFORMATION_DEFINED

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

static VOID
ObpInitializeInstallPath(
    VOID
    );

static VOID
ObpInitializeSystem32Path(
    VOID
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
    // We won the race - reinitialize fields individually
    // (do NOT RtlZeroMemory the whole struct — it clobbers InitState,
    //  creating a window where another CPU sees 0 and CAS succeeds)
    //
    g_ObCallbackContext.TotalProcessOperations = 0;
    g_ObCallbackContext.TotalThreadOperations = 0;
    g_ObCallbackContext.ProcessAccessStripped = 0;
    g_ObCallbackContext.ThreadAccessStripped = 0;
    g_ObCallbackContext.CredentialAccessBlocked = 0;
    g_ObCallbackContext.InjectionBlocked = 0;
    g_ObCallbackContext.TerminationBlocked = 0;
    g_ObCallbackContext.SuspiciousOperations = 0;
    g_ObCallbackContext.CurrentSecondEvents = 0;
    g_ObCallbackContext.LsassPid = 0;
    g_ObCallbackContext.CsrssPid = 0;
    g_ObCallbackContext.ServicesPid = 0;
    g_ObCallbackContext.WinlogonPid = 0;
    g_ObCallbackContext.SmsssPid = 0;
    g_ObCallbackContext.WellKnownPidsInitialized = 0;
    g_ObCallbackContext.NameCacheIndex = 0;
    RtlZeroMemory(g_ObCallbackContext.NameCache, sizeof(g_ObCallbackContext.NameCache));

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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[ShadowStrike] ObpInitializeWellKnownPids failed: 0x%08X (continuing)\n", status);
    }

    //
    // Cache install path and System32 device path for validation
    //
    ObpInitializeInstallPath();
    ObpInitializeSystem32Path();

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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[ShadowStrike] ObRegisterCallbacks successful, Handle=%p\n",
            g_DriverData.ObjectCallbackHandle);

        //
        // Initialize process protection subsystem
        //
        status = PpInitializeProcessProtection();
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[ShadowStrike] PpInitializeProcessProtection failed: 0x%08X\n", status);
            status = STATUS_SUCCESS;
        }

        //
        // Mark as fully initialized with memory barrier
        //
        MemoryBarrier();
        InterlockedExchange(&g_ObCallbackContext.InitState, OB_INIT_STATE_INITIALIZED);

    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike] ObRegisterCallbacks failed: 0x%08X\n", status);
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

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[ShadowStrike] ObjectCallbacks unregistered - ProcessOps=%lld ThreadOps=%lld "
            "ProcStripped=%lld ThreadStripped=%lld CredBlocked=%lld InjBlocked=%lld\n",
            ReadNoFence64((volatile LONG64*)&g_ObCallbackContext.TotalProcessOperations),
            ReadNoFence64((volatile LONG64*)&g_ObCallbackContext.TotalThreadOperations),
            ReadNoFence64((volatile LONG64*)&g_ObCallbackContext.ProcessAccessStripped),
            ReadNoFence64((volatile LONG64*)&g_ObCallbackContext.ThreadAccessStripped),
            ReadNoFence64((volatile LONG64*)&g_ObCallbackContext.CredentialAccessBlocked),
            ReadNoFence64((volatile LONG64*)&g_ObCallbackContext.InjectionBlocked));
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
    // Skip analysis if the requesting process is excluded
    //
    if (ShadowStrikeIsProcessExcluded(sourceProcessId, NULL)) {
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

            //
            // Submit handle manipulation events to BehaviorEngine for kill-chain
            // correlation. LSASS credential access (T1003), injection (T1055),
            // process termination attacks all manifest through handle requests.
            //
            {
                BEHAVIOR_EVENT_TYPE beType = BehaviorEvent_CrossProcessWrite;
                BEHAVIOR_EVENT_CATEGORY beCat = BehaviorCategory_CodeInjection;

                if (targetCategory == PpCategoryLsass) {
                    beType = BehaviorEvent_LSASSAccess;
                    beCat = BehaviorCategory_CredentialAccess;
                } else if (strippedAccess & PROCESS_TERMINATE) {
                    beType = BehaviorEvent_ProcessTerminate;
                    beCat = BehaviorCategory_Impact;
                }

                BeEngineSubmitEvent(
                    beType,
                    beCat,
                    HandleToULong(sourceProcessId),
                    NULL, 0,
                    (UINT32)suspicionScore,
                    FALSE,
                    NULL
                    );
            }
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

            //
            // Thread handle injection pattern → BehaviorEngine (T1055)
            //
            BeEngineSubmitEvent(
                BehaviorEvent_ThreadExecutionHijack,
                BehaviorCategory_CodeInjection,
                HandleToULong(sourceProcessId),
                NULL, 0,
                (UINT32)suspicionScore,
                FALSE,
                NULL
                );
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
    ULONG walkCount = 0;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ProtectedProcessLock);

    for (listEntry = g_DriverData.ProtectedProcessList.Flink;
         listEntry != &g_DriverData.ProtectedProcessList;
         listEntry = listEntry->Flink) {

        if (++walkCount > OB_MAX_LIST_WALK) {
            break;
        }

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
        // Wait for reference count to drop with bounded iteration
        //
        ULONG spinCount = 0;
        while (InterlockedCompareExchange(&foundEntry->ReferenceCount, 0, 0) > 0) {
            if (++spinCount > OB_MAX_REFCOUNT_SPINS) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[ShadowStrike] ObRemoveProtectedProcess: refcount drain timeout PID=%p\n",
                    foundEntry->ProcessId);
                break;
            }
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
    ULONG walkCount = 0;

    if (OutEntry != NULL) {
        *OutEntry = NULL;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ProtectedProcessLock);

    for (listEntry = g_DriverData.ProtectedProcessList.Flink;
         listEntry != &g_DriverData.ProtectedProcessList;
         listEntry = listEntry->Flink) {

        if (++walkCount > OB_MAX_LIST_WALK) {
            break;
        }

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
    NTSTATUS status;
    struct {
        SHADOWSTRIKE_MESSAGE_HEADER Header;
        SHADOWSTRIKE_HANDLE_ALERT_NOTIFICATION Alert;
    } Message;

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
    // Build handle alert notification for user-mode delivery
    //
    RtlZeroMemory(&Message, sizeof(Message));

    Message.Header.Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
    Message.Header.Version = SHADOWSTRIKE_PROTOCOL_VERSION;
    Message.Header.MessageType = (UINT16)SHADOWSTRIKE_MSG_PROCESS_HANDLE_ALERT;
    Message.Header.MessageId = (UINT64)InterlockedIncrement64(&g_DriverData.NextMessageId);
    Message.Header.TotalSize = sizeof(Message);
    Message.Header.DataSize = sizeof(SHADOWSTRIKE_HANDLE_ALERT_NOTIFICATION);
    {
        LARGE_INTEGER Now;
        KeQuerySystemTime(&Now);
        Message.Header.Timestamp = (UINT64)Now.QuadPart;
    }

    Message.Alert.SourceProcessId = (UINT32)(ULONG_PTR)Event->SourceProcessId;
    Message.Alert.TargetProcessId = (UINT32)(ULONG_PTR)Event->TargetProcessId;
    Message.Alert.RequestedAccess = Event->OriginalAccess;
    Message.Alert.GrantedAccess = Event->AllowedAccess;
    Message.Alert.SuspicionScore = Event->SuspicionScore;
    Message.Alert.SuspiciousFlags = Event->SuspiciousFlags;
    Message.Alert.TargetCategory = Event->TargetCategory;
    Message.Alert.OperationType = Event->IsProcessHandle ? 1 : 2;
    Message.Alert.Verdict = (Event->StrippedAccess != 0) ? 1 : 0;

    status = ShadowStrikeSendNotification(
        &Message.Header,
        sizeof(Message)
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[ShadowStrike] ObQueueTelemetryEvent: send failed 0x%08X (Src=%p Tgt=%p)\n",
            status, Event->SourceProcessId, Event->TargetProcessId);
    }
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
        *ProcessOps = ReadNoFence64((volatile LONG64*)&g_ObCallbackContext.TotalProcessOperations);
    }
    if (ThreadOps != NULL) {
        *ThreadOps = ReadNoFence64((volatile LONG64*)&g_ObCallbackContext.TotalThreadOperations);
    }
    if (AccessStripped != NULL) {
        *AccessStripped = ReadNoFence64((volatile LONG64*)&g_ObCallbackContext.ProcessAccessStripped) +
                          ReadNoFence64((volatile LONG64*)&g_ObCallbackContext.ThreadAccessStripped);
    }
    if (Suspicious != NULL) {
        *Suspicious = ReadNoFence64((volatile LONG64*)&g_ObCallbackContext.SuspiciousOperations);
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

        //
        // Cache the PID for fast future lookups
        //
        {
            CHAR imageName[16];
            ObpGetProcessImageFileNameSafe(Process, imageName);

            if (_stricmp(imageName, "csrss.exe") == 0 &&
                g_ObCallbackContext.CsrssPid == 0) {
                InterlockedExchange64(
                    (volatile LONG64*)&g_ObCallbackContext.CsrssPid,
                    (LONG64)(ULONG_PTR)processId);
            } else if (_stricmp(imageName, "services.exe") == 0) {
                InterlockedExchange64(
                    (volatile LONG64*)&g_ObCallbackContext.ServicesPid,
                    (LONG64)(ULONG_PTR)processId);
            } else if (_stricmp(imageName, "winlogon.exe") == 0 &&
                       g_ObCallbackContext.WinlogonPid == 0) {
                InterlockedExchange64(
                    (volatile LONG64*)&g_ObCallbackContext.WinlogonPid,
                    (LONG64)(ULONG_PTR)processId);
            } else if (_stricmp(imageName, "smss.exe") == 0) {
                InterlockedExchange64(
                    (volatile LONG64*)&g_ObCallbackContext.SmsssPid,
                    (LONG64)(ULONG_PTR)processId);
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
    ULONG walkCount = 0;

    processId = PsGetProcessId(Process);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ProtectedProcessLock);

    for (listEntry = g_DriverData.ProtectedProcessList.Flink;
         listEntry != &g_DriverData.ProtectedProcessList;
         listEntry = listEntry->Flink) {

        if (++walkCount > OB_MAX_LIST_WALK) {
            break;
        }

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
    if (ShadowStrikeIsProcessProtected(SourceProcessId, NULL)) {
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
                deniedAccess = (ACCESS_MASK)~(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE);
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
                deniedAccess = (ACCESS_MASK)~OB_SAFE_THREAD_ACCESS;
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
                deniedAccess = (ACCESS_MASK)~OB_SAFE_THREAD_ACCESS;
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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[ShadowStrike] Access stripped: Src=%p Tgt=%p Type=%s Orig=0x%08X Allowed=0x%08X "
        "Stripped=0x%08X Score=%u Cat=%u\n",
        SourceProcessId, TargetProcessId,
        IsProcessHandle ? "Process" : "Thread",
        OriginalAccess, AllowedAccess, strippedAccess,
        SuspicionScore, (ULONG)TargetCategory);

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

        if (returnLength > (MAXULONG - 8192)) {
            InterlockedExchange(&g_ObCallbackContext.WellKnownPidsInitialized, 0);
            return STATUS_INTEGER_OVERFLOW;
        }

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
    // with full buffer bounds checking and iteration cap
    //
    {
        POB_SYSTEM_PROCESS_INFORMATION currentProcess;
        PUCHAR bufferEnd = (PUCHAR)buffer + bufferSize;
        ULONG iterationCount = 0;

        currentProcess = (POB_SYSTEM_PROCESS_INFORMATION)buffer;

        do {
            //
            // Buffer bounds validation
            //
            if ((PUCHAR)currentProcess < (PUCHAR)buffer ||
                (PUCHAR)currentProcess + sizeof(OB_SYSTEM_PROCESS_INFORMATION) > bufferEnd) {
                break;
            }

            if (++iterationCount > OB_MAX_PROCESS_WALK) {
                break;
            }

            if (currentProcess->ImageName.Buffer != NULL) {
                //
                // Validate ImageName buffer range
                //
                if ((PUCHAR)currentProcess->ImageName.Buffer >= (PUCHAR)buffer &&
                    (PUCHAR)currentProcess->ImageName.Buffer + currentProcess->ImageName.Length <= bufferEnd) {

                    if (RtlEqualUnicodeString(&currentProcess->ImageName, &lsassName, TRUE)) {
                        InterlockedExchange64(
                            (volatile LONG64*)&g_ObCallbackContext.LsassPid,
                            (LONG64)(ULONG_PTR)currentProcess->UniqueProcessId
                        );
                    }
                    else if (RtlEqualUnicodeString(&currentProcess->ImageName, &csrssName, TRUE)) {
                        if (g_ObCallbackContext.CsrssPid == 0) {
                            InterlockedExchange64(
                                (volatile LONG64*)&g_ObCallbackContext.CsrssPid,
                                (LONG64)(ULONG_PTR)currentProcess->UniqueProcessId
                            );
                        }
                    }
                    else if (RtlEqualUnicodeString(&currentProcess->ImageName, &servicesName, TRUE)) {
                        InterlockedExchange64(
                            (volatile LONG64*)&g_ObCallbackContext.ServicesPid,
                            (LONG64)(ULONG_PTR)currentProcess->UniqueProcessId
                        );
                    }
                    else if (RtlEqualUnicodeString(&currentProcess->ImageName, &winlogonName, TRUE)) {
                        if (g_ObCallbackContext.WinlogonPid == 0) {
                            InterlockedExchange64(
                                (volatile LONG64*)&g_ObCallbackContext.WinlogonPid,
                                (LONG64)(ULONG_PTR)currentProcess->UniqueProcessId
                            );
                        }
                    }
                    else if (RtlEqualUnicodeString(&currentProcess->ImageName, &smssName, TRUE)) {
                        InterlockedExchange64(
                            (volatile LONG64*)&g_ObCallbackContext.SmsssPid,
                            (LONG64)(ULONG_PTR)currentProcess->UniqueProcessId
                        );
                    }
                }
            }

            if (currentProcess->NextEntryOffset == 0) {
                break;
            }

            //
            // Validate NextEntryOffset doesn't point backwards
            //
            if (currentProcess->NextEntryOffset < sizeof(OB_SYSTEM_PROCESS_INFORMATION)) {
                break;
            }

            currentProcess = (POB_SYSTEM_PROCESS_INFORMATION)(
                (PUCHAR)currentProcess + currentProcess->NextEntryOffset
            );
        } while (TRUE);
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
    HANDLE processId;

    processId = PsGetProcessId(Process);

    //
    // Try the name cache first for performance
    //
    if (ObpLookupCachedName(processId, imageName)) {
        if (imageName[0] != '\0') {
            for (i = 0; i < NameCount; i++) {
                if (_stricmp(imageName, NameList[i]) == 0) {
                    return TRUE;
                }
            }
            return FALSE;
        }
    }

    //
    // Cache miss — get image name using IRQL-safe function
    //
    ObpGetProcessImageFileNameSafe(Process, imageName);

    if (imageName[0] == '\0') {
        return FALSE;
    }

    //
    // Cache the result for future lookups
    //
    ObpCacheProcessName(processId, imageName);

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
    UNICODE_STRING systemRootPrefix;
    UNICODE_STRING system32Suffix;

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
            // Must be under a known System32 path.
            // Check multiple possible path formats:
            //   1. \SystemRoot\System32\  (NT symbolic link)
            //   2. Cached device path from init (e.g. \Device\HarddiskVolume2\Windows\System32\)
            //   3. DOS path with \??\<drive>:\Windows\System32\ for any drive letter
            //
            RtlInitUnicodeString(&systemRootPrefix, L"\\SystemRoot\\System32\\");

            if (RtlPrefixUnicodeString(&systemRootPrefix, imagePath, TRUE)) {
                isValid = TRUE;
            }

            //
            // Check cached device path (resolved at init from \SystemRoot symlink)
            //
            if (!isValid && g_ObCallbackContext.System32PathInitialized &&
                g_ObCallbackContext.System32DevicePath.Length > 0) {
                if (RtlPrefixUnicodeString(&g_ObCallbackContext.System32DevicePath, imagePath, TRUE)) {
                    isValid = TRUE;
                }
            }

            //
            // Check DOS path format for any drive letter (\??\X:\Windows\System32\)
            //
            if (!isValid && imagePath->Length >= 28 * sizeof(WCHAR)) {
                RtlInitUnicodeString(&system32Suffix, L"\\Windows\\System32\\");

                if (imagePath->Buffer[0] == L'\\' &&
                    imagePath->Buffer[1] == L'?' &&
                    imagePath->Buffer[2] == L'?' &&
                    imagePath->Buffer[3] == L'\\' &&
                    imagePath->Buffer[5] == L':' &&
                    imagePath->Buffer[6] == L'\\') {
                    //
                    // Looks like \??\X:\... — check the rest matches \Windows\System32\
                    //
                    UNICODE_STRING pathAfterDrive;
                    pathAfterDrive.Buffer = &imagePath->Buffer[6];
                    pathAfterDrive.Length = imagePath->Length - (6 * sizeof(WCHAR));
                    pathAfterDrive.MaximumLength = pathAfterDrive.Length;

                    if (RtlPrefixUnicodeString(&system32Suffix, &pathAfterDrive, TRUE)) {
                        isValid = TRUE;
                    }
                }
            }
            break;

        case PpCategoryAntimalware:
            //
            // ShadowStrike processes — validate against cached install directory.
            // Install path is read from registry at initialization:
            //   HKLM\SOFTWARE\ShadowStrike\InstallPath
            // Falls back to default path if registry key is not present.
            //
            if (g_ObCallbackContext.InstallPathInitialized &&
                g_ObCallbackContext.InstallPath.Length > 0) {
                if (RtlPrefixUnicodeString(&g_ObCallbackContext.InstallPath, imagePath, TRUE)) {
                    isValid = TRUE;
                }
            } else {
                //
                // Fallback: default install location for any drive letter
                //
                UNICODE_STRING defaultSuffix;
                RtlInitUnicodeString(&defaultSuffix, L"\\Program Files\\ShadowStrike\\");

                if (imagePath->Length >= 30 * sizeof(WCHAR) &&
                    imagePath->Buffer[0] == L'\\' &&
                    imagePath->Buffer[1] == L'?' &&
                    imagePath->Buffer[2] == L'?' &&
                    imagePath->Buffer[3] == L'\\' &&
                    imagePath->Buffer[5] == L':' &&
                    imagePath->Buffer[6] == L'\\') {
                    UNICODE_STRING pathAfterDrive;
                    pathAfterDrive.Buffer = &imagePath->Buffer[6];
                    pathAfterDrive.Length = imagePath->Length - (6 * sizeof(WCHAR));
                    pathAfterDrive.MaximumLength = pathAfterDrive.Length;

                    if (RtlPrefixUnicodeString(&defaultSuffix, &pathAfterDrive, TRUE)) {
                        isValid = TRUE;
                    }
                }
            }
            break;

        case PpCategoryServices:
        default:
            //
            // Services and unknown categories: require the binary to be located
            // within a known system path. This prevents spoofed service names
            // from arbitrary directories gaining trusted status.
            //
            {
                UNICODE_STRING sys32Suffix;
                UNICODE_STRING progFilesSuffix;
                RtlInitUnicodeString(&sys32Suffix, L"\\Windows\\System32\\");
                RtlInitUnicodeString(&progFilesSuffix, L"\\Program Files\\");

                if (imagePath->Length >= 14 * sizeof(WCHAR) &&
                    imagePath->Buffer[0] == L'\\' &&
                    imagePath->Buffer[1] == L'?' &&
                    imagePath->Buffer[2] == L'?' &&
                    imagePath->Buffer[3] == L'\\' &&
                    imagePath->Buffer[5] == L':' &&
                    imagePath->Buffer[6] == L'\\') {
                    UNICODE_STRING pathAfterDrive;
                    pathAfterDrive.Buffer = &imagePath->Buffer[6];
                    pathAfterDrive.Length = imagePath->Length - (6 * sizeof(WCHAR));
                    pathAfterDrive.MaximumLength = pathAfterDrive.Length;

                    if (RtlPrefixUnicodeString(&sys32Suffix, &pathAfterDrive, TRUE) ||
                        RtlPrefixUnicodeString(&progFilesSuffix, &pathAfterDrive, TRUE)) {
                        isValid = TRUE;
                    }
                }

                //
                // Also accept SystemRoot prefix
                //
                if (!isValid) {
                    RtlInitUnicodeString(&sys32Suffix, L"\\SystemRoot\\");
                    if (RtlPrefixUnicodeString(&sys32Suffix, imagePath, TRUE)) {
                        isValid = TRUE;
                    }
                }
            }
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
    LONG rawIndex;
    LONG index;
    POB_NAME_CACHE_ENTRY entry;

    //
    // Get next cache slot using atomic increment
    // Use bitwise AND to avoid negative modulo after INT32 overflow
    //
    rawIndex = InterlockedIncrement(&g_ObCallbackContext.NameCacheIndex);
    index = (rawIndex & 0x7FFFFFFF) % OB_NAME_CACHE_SIZE;
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

// ============================================================================
// Install Path Initialization
// ============================================================================

static VOID
ObpInitializeInstallPath(
    VOID
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING keyPath;
    UNICODE_STRING valueName;
    HANDLE keyHandle = NULL;
    UCHAR valueBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 520];
    PKEY_VALUE_PARTIAL_INFORMATION valueInfo;
    ULONG resultLength = 0;
    ULONG copyLength;

    //
    // Attempt to read install path from:
    //   HKLM\SOFTWARE\ShadowStrike\InstallPath
    //
    RtlInitUnicodeString(&keyPath,
        L"\\Registry\\Machine\\SOFTWARE\\ShadowStrike");
    RtlInitUnicodeString(&valueName, L"InstallPath");

    InitializeObjectAttributes(&objAttr, &keyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);

    status = ZwOpenKey(&keyHandle, KEY_READ, &objAttr);
    if (!NT_SUCCESS(status)) {
        goto UseDefault;
    }

    valueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)valueBuffer;

    status = ZwQueryValueKey(
        keyHandle,
        &valueName,
        KeyValuePartialInformation,
        valueInfo,
        sizeof(valueBuffer),
        &resultLength
        );

    ZwClose(keyHandle);
    keyHandle = NULL;

    if (!NT_SUCCESS(status) || valueInfo->Type != REG_SZ ||
        valueInfo->DataLength < sizeof(WCHAR) * 2) {
        goto UseDefault;
    }

    //
    // Validate and copy the registry value.
    // Cap at buffer size - 2 chars for trailing backslash + null.
    //
    copyLength = valueInfo->DataLength;
    if (copyLength > (sizeof(g_ObCallbackContext.InstallPathBuffer) - 2 * sizeof(WCHAR))) {
        copyLength = sizeof(g_ObCallbackContext.InstallPathBuffer) - 2 * sizeof(WCHAR);
    }

    RtlZeroMemory(g_ObCallbackContext.InstallPathBuffer,
                   sizeof(g_ObCallbackContext.InstallPathBuffer));
    RtlCopyMemory(g_ObCallbackContext.InstallPathBuffer,
                   valueInfo->Data, copyLength);

    //
    // Ensure trailing backslash for prefix matching
    //
    {
        ULONG charCount = copyLength / sizeof(WCHAR);
        while (charCount > 0 && g_ObCallbackContext.InstallPathBuffer[charCount - 1] == L'\0') {
            charCount--;
        }
        if (charCount > 0 && g_ObCallbackContext.InstallPathBuffer[charCount - 1] != L'\\') {
            if (charCount < ARRAYSIZE(g_ObCallbackContext.InstallPathBuffer) - 1) {
                g_ObCallbackContext.InstallPathBuffer[charCount] = L'\\';
                charCount++;
            }
        }
        g_ObCallbackContext.InstallPath.Buffer = g_ObCallbackContext.InstallPathBuffer;
        g_ObCallbackContext.InstallPath.Length = (USHORT)(charCount * sizeof(WCHAR));
        g_ObCallbackContext.InstallPath.MaximumLength = sizeof(g_ObCallbackContext.InstallPathBuffer);
    }

    InterlockedExchange(&g_ObCallbackContext.InstallPathInitialized, 1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[ShadowStrike] ObCallback: Install path from registry: %wZ\n",
        &g_ObCallbackContext.InstallPath);
    return;

UseDefault:
    if (keyHandle != NULL) {
        ZwClose(keyHandle);
    }

    //
    // Default: use standard install location with NT path prefix.
    // Use \??\ prefix for DOS-path format matching.
    //
    {
        UNICODE_STRING defaultPath;
        RtlInitUnicodeString(&defaultPath,
            L"\\??\\C:\\Program Files\\ShadowStrike\\");

        RtlZeroMemory(g_ObCallbackContext.InstallPathBuffer,
                       sizeof(g_ObCallbackContext.InstallPathBuffer));
        RtlCopyMemory(g_ObCallbackContext.InstallPathBuffer,
                       defaultPath.Buffer, defaultPath.Length);

        g_ObCallbackContext.InstallPath.Buffer = g_ObCallbackContext.InstallPathBuffer;
        g_ObCallbackContext.InstallPath.Length = defaultPath.Length;
        g_ObCallbackContext.InstallPath.MaximumLength = sizeof(g_ObCallbackContext.InstallPathBuffer);
    }

    InterlockedExchange(&g_ObCallbackContext.InstallPathInitialized, 1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[ShadowStrike] ObCallback: Using default install path: %wZ\n",
        &g_ObCallbackContext.InstallPath);
}

// ============================================================================
// System32 Device Path Initialization
// ============================================================================

static VOID
ObpInitializeSystem32Path(
    VOID
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING symlinkName;
    HANDLE linkHandle = NULL;
    UNICODE_STRING targetPath;
    ULONG pathChars;

    //
    // Resolve \SystemRoot symbolic link to get the device path of the
    // Windows directory (e.g. \Device\HarddiskVolume2\Windows).
    // Then append \System32\ for System32 prefix matching.
    //

    RtlZeroMemory(g_ObCallbackContext.System32DevicePathBuffer,
                   sizeof(g_ObCallbackContext.System32DevicePathBuffer));

    RtlInitUnicodeString(&symlinkName, L"\\SystemRoot");
    InitializeObjectAttributes(&objAttr, &symlinkName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);

    status = ZwOpenSymbolicLinkObject(&linkHandle, GENERIC_READ, &objAttr);
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }

    targetPath.Buffer = g_ObCallbackContext.System32DevicePathBuffer;
    targetPath.Length = 0;
    targetPath.MaximumLength = (USHORT)(sizeof(g_ObCallbackContext.System32DevicePathBuffer)
                                        - 20 * sizeof(WCHAR));

    status = ZwQuerySymbolicLinkObject(linkHandle, &targetPath, NULL);
    ZwClose(linkHandle);
    linkHandle = NULL;

    if (!NT_SUCCESS(status) || targetPath.Length == 0) {
        goto Fail;
    }

    //
    // targetPath is something like \Device\HarddiskVolume2\Windows
    // Append \System32\ for prefix matching
    //
    pathChars = targetPath.Length / sizeof(WCHAR);

    //
    // Ensure trailing backslash before appending System32
    //
    if (pathChars > 0 && g_ObCallbackContext.System32DevicePathBuffer[pathChars - 1] != L'\\') {
        if (pathChars < ARRAYSIZE(g_ObCallbackContext.System32DevicePathBuffer) - 10) {
            g_ObCallbackContext.System32DevicePathBuffer[pathChars++] = L'\\';
        }
    }

    //
    // Append "System32\"
    //
    if (pathChars + 9 < ARRAYSIZE(g_ObCallbackContext.System32DevicePathBuffer)) {
        g_ObCallbackContext.System32DevicePathBuffer[pathChars++] = L'S';
        g_ObCallbackContext.System32DevicePathBuffer[pathChars++] = L'y';
        g_ObCallbackContext.System32DevicePathBuffer[pathChars++] = L's';
        g_ObCallbackContext.System32DevicePathBuffer[pathChars++] = L't';
        g_ObCallbackContext.System32DevicePathBuffer[pathChars++] = L'e';
        g_ObCallbackContext.System32DevicePathBuffer[pathChars++] = L'm';
        g_ObCallbackContext.System32DevicePathBuffer[pathChars++] = L'3';
        g_ObCallbackContext.System32DevicePathBuffer[pathChars++] = L'2';
        g_ObCallbackContext.System32DevicePathBuffer[pathChars++] = L'\\';
        g_ObCallbackContext.System32DevicePathBuffer[pathChars] = L'\0';
    }

    g_ObCallbackContext.System32DevicePath.Buffer = g_ObCallbackContext.System32DevicePathBuffer;
    g_ObCallbackContext.System32DevicePath.Length = (USHORT)(pathChars * sizeof(WCHAR));
    g_ObCallbackContext.System32DevicePath.MaximumLength =
        sizeof(g_ObCallbackContext.System32DevicePathBuffer);

    InterlockedExchange(&g_ObCallbackContext.System32PathInitialized, 1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[ShadowStrike] ObCallback: System32 device path resolved: %wZ\n",
        &g_ObCallbackContext.System32DevicePath);
    return;

Fail:
    if (linkHandle != NULL) {
        ZwClose(linkHandle);
    }

    //
    // Failed to resolve — the function will still work via
    // \SystemRoot\System32\ prefix and \??\X:\Windows\System32\ DOS path checks
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[ShadowStrike] ObCallback: Could not resolve \\SystemRoot symlink (0x%08X), "
        "using fallback path validation\n", status);
}
