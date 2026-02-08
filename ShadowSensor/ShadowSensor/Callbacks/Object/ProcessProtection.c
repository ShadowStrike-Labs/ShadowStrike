/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE PROCESS PROTECTION IMPLEMENTATION
===============================================================================

@file ProcessProtection.c
@brief Enterprise-grade process handle protection for kernel-mode EDR.

This module provides comprehensive process handle monitoring and protection:
- Handle access rights stripping for protected processes
- Malicious handle operation detection (credential theft, injection)
- Per-process access policy enforcement
- Handle duplication monitoring across process boundaries
- LSASS, CSRSS, and critical system process protection
- Anti-debugging protection for EDR processes
- Handle enumeration defense
- Cross-session handle access monitoring

Detection Techniques Covered (MITRE ATT&CK):
- T1003: OS Credential Dumping (LSASS protection)
- T1055: Process Injection (VM_WRITE/CREATE_THREAD blocking)
- T1489: Service Stop (service process protection)
- T1562: Impair Defenses (EDR self-protection)
- T1106: Native API (handle duplication monitoring)
- T1134: Access Token Manipulation (token access monitoring)

Performance Characteristics:
- O(1) protected process lookup via cache
- Lock-free statistics using InterlockedXxx
- Per-second rate limiting for logging
- Early exit for kernel handles and unprotected targets
- Reference-counted activity trackers for safe concurrent access

Thread Safety:
- Uses EX_RUNDOWN_REF for safe shutdown
- Lock ordering: RundownRef -> CacheLock -> PolicyLock -> ActivityLock
- Activity trackers use reference counting to prevent use-after-free

@author ShadowStrike Security Team
@version 2.1.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "ProcessProtection.h"
#include "ObjectCallback.h"
#include "../../Core/Globals.h"
#include "../../SelfProtection/SelfProtect.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/ProcessUtils.h"
#include "../../Communication/CommPort.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, PpInitializeProcessProtection)
#pragma alloc_text(PAGE, PpShutdownProcessProtection)
#pragma alloc_text(PAGE, PpDetectCriticalProcesses)
#pragma alloc_text(PAGE, PpClassifyProcess)
#pragma alloc_text(PAGE, PpAddAccessPolicy)
#pragma alloc_text(PAGE, PpRemovePoliciesForCategory)
#pragma alloc_text(PAGE, PpValidateCachedProcess)
#pragma alloc_text(PAGE, PpCleanupActivityTrackerForProcess)
#endif

// ============================================================================
// GLOBAL STATE
// ============================================================================

static PP_PROTECTION_STATE g_ProcessProtection = {0};

//
// Well-known process name constants (UNICODE_STRING compatible)
//
static const WCHAR g_LsassName[] = L"\\lsass.exe";
static const WCHAR g_CsrssName[] = L"\\csrss.exe";
static const WCHAR g_ServicesName[] = L"\\services.exe";
static const WCHAR g_SvchostName[] = L"\\svchost.exe";
static const WCHAR g_SmssName[] = L"\\smss.exe";
static const WCHAR g_WininitName[] = L"\\wininit.exe";
static const WCHAR g_WinlogonName[] = L"\\winlogon.exe";
static const WCHAR g_ShadowStrikeName[] = L"ShadowStrike";

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID
PppInitializeDefaultConfig(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
PppRegisterProcessNotifyCallback(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
PppUnregisterProcessNotifyCallback(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PppProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

_IRQL_requires_max_(APC_LEVEL)
static VOID
PppCleanupActivityTrackers(
    VOID
    );

_IRQL_requires_max_(APC_LEVEL)
static VOID
PppCleanupPolicies(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static PPP_ACTIVITY_TRACKER
PppFindActivityTrackerLocked(
    _In_ HANDLE SourceProcessId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static PPP_ACTIVITY_TRACKER
PppFindOrCreateActivityTracker(
    _In_ HANDLE SourceProcessId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
PppReferenceTracker(
    _In_ PPP_ACTIVITY_TRACKER Tracker
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
PppDereferenceTracker(
    _In_ PPP_ACTIVITY_TRACKER Tracker
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
PppUpdateActivityTracker(
    _Inout_ PPP_ACTIVITY_TRACKER Tracker,
    _In_ HANDLE TargetProcessId,
    _In_ BOOLEAN IsSuspicious
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
PppHashProcessId(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
PppIsSystemProcess(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
PppIsTrustedSource(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId
    );

_IRQL_requires_max_(APC_LEVEL)
static PP_PROCESS_CATEGORY
PppCategorizeByImageName(
    _In_ PCUNICODE_STRING ImageName
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
PppLogSuspiciousOperation(
    _In_ PPP_OPERATION_CONTEXT Context
    );

_IRQL_requires_max_(APC_LEVEL)
static VOID
PppSendNotification(
    _In_ PPP_OPERATION_CONTEXT Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
PppFindProcessesByName(
    _In_ PCWSTR ProcessName,
    _Out_writes_(MaxPids) PHANDLE ProcessIds,
    _In_ ULONG MaxPids,
    _Out_ PULONG FoundCount
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
PppShouldLogOperation(
    VOID
    );

_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN
PppMatchImageNameSuffix(
    _In_ PCUNICODE_STRING FullPath,
    _In_ PCWSTR Suffix
    );

_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN
PppImageNameContains(
    _In_ PCUNICODE_STRING FullPath,
    _In_ PCWSTR Substring
    );

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PpInitializeProcessProtection(
    VOID
    )
/*++
Routine Description:
    Initializes the process protection subsystem.

    Thread Safety:
    - Must be called at PASSIVE_LEVEL
    - Must be called before ObRegisterCallbacks
    - Not thread-safe for concurrent initialization

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG i;

    PAGED_CODE();

    if (g_ProcessProtection.Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_ProcessProtection, sizeof(PP_PROTECTION_STATE));

    //
    // Initialize rundown protection for safe shutdown
    //
    ExInitializeRundownProtection(&g_ProcessProtection.RundownRef);

    //
    // Initialize synchronization primitives
    //
    ExInitializePushLock(&g_ProcessProtection.CacheLock);
    ExInitializePushLock(&g_ProcessProtection.PolicyLock);
    ExInitializePushLock(&g_ProcessProtection.ActivityLock);

    //
    // Initialize lists
    //
    InitializeListHead(&g_ProcessProtection.PolicyList);
    InitializeListHead(&g_ProcessProtection.ActivityList);

    //
    // Initialize activity hash table
    //
    for (i = 0; i < PP_ACTIVITY_HASH_SIZE; i++) {
        InitializeListHead(&g_ProcessProtection.ActivityHashTable[i]);
    }

    //
    // Initialize default configuration
    //
    PppInitializeDefaultConfig();

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&g_ProcessProtection.Stats.StartTime);
    InterlockedExchange64(
        &g_ProcessProtection.RateLimiter.CurrentSecondStart,
        g_ProcessProtection.Stats.StartTime.QuadPart
        );

    //
    // Register process notify callback for cleanup
    //
    Status = PppRegisterProcessNotifyCallback();
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/PP] Failed to register process notify: 0x%08X\n",
            Status
            );
        //
        // Non-fatal: activity trackers will leak but protection still works
        //
    }

    //
    // Detect and cache critical system processes
    //
    Status = PpDetectCriticalProcesses();
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/PP] Failed to detect critical processes: 0x%08X\n",
            Status
            );
        //
        // Non-fatal: continue without pre-cached critical processes
        //
    }

    g_ProcessProtection.Initialized = TRUE;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/PP] Process protection initialized. "
        "Cached %ld critical processes, %ld CSRSS instances\n",
        g_ProcessProtection.CriticalProcessCount,
        g_ProcessProtection.CsrssCount
        );

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
PpShutdownProcessProtection(
    VOID
    )
/*++
Routine Description:
    Shuts down the process protection subsystem.

    Uses rundown protection to ensure all in-flight operations
    complete before freeing resources.

    Thread Safety:
    - Must be called at PASSIVE_LEVEL
    - Must be called after unregistering object callbacks
    - Waits for all in-flight operations to complete
--*/
{
    PAGED_CODE();

    if (!g_ProcessProtection.Initialized) {
        return;
    }

    //
    // Mark as not initialized to stop new operations
    //
    g_ProcessProtection.Initialized = FALSE;

    //
    // Wait for all in-flight operations to complete
    // This blocks until all ExAcquireRundownProtection calls are balanced
    //
    ExWaitForRundownProtectionRelease(&g_ProcessProtection.RundownRef);

    //
    // Unregister process notify callback
    //
    PppUnregisterProcessNotifyCallback();

    //
    // Cleanup activity trackers (safe now, no in-flight operations)
    //
    PppCleanupActivityTrackers();

    //
    // Cleanup policies
    //
    PppCleanupPolicies();

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/PP] Process protection shutdown. "
        "Stats: Total=%lld, Stripped=%lld, Blocked=%lld, Notifications=%lld\n",
        g_ProcessProtection.Stats.TotalOperations,
        g_ProcessProtection.Stats.AccessStripped,
        g_ProcessProtection.Stats.OperationsBlocked,
        g_ProcessProtection.Stats.NotificationsSent
        );
}


static VOID
PppInitializeDefaultConfig(
    VOID
    )
{
    g_ProcessProtection.Config.EnableCredentialProtection = TRUE;
    g_ProcessProtection.Config.EnableInjectionProtection = TRUE;
    g_ProcessProtection.Config.EnableTerminationProtection = TRUE;
    g_ProcessProtection.Config.EnableCrossSessionMonitoring = TRUE;
    g_ProcessProtection.Config.EnableActivityTracking = TRUE;
    g_ProcessProtection.Config.EnableRateLimiting = TRUE;
    g_ProcessProtection.Config.EnableKernelHandleFiltering = FALSE;  // Default off for compat
    g_ProcessProtection.Config.EnablePolicyEnforcement = TRUE;
    g_ProcessProtection.Config.LogStrippedAccess = TRUE;
    g_ProcessProtection.Config.NotifyUserMode = TRUE;
    g_ProcessProtection.Config.StrictLsassProtection = TRUE;  // Block VM_READ on LSASS
    g_ProcessProtection.Config.SuspicionScoreThreshold = 50;
}


// ============================================================================
// PROCESS NOTIFY CALLBACK FOR CLEANUP
// ============================================================================

_Use_decl_annotations_
static NTSTATUS
PppRegisterProcessNotifyCallback(
    VOID
    )
{
    NTSTATUS Status;

    PAGED_CODE();

    Status = PsSetCreateProcessNotifyRoutineEx(
        PppProcessNotifyCallback,
        FALSE  // Register
        );

    if (NT_SUCCESS(Status)) {
        g_ProcessProtection.ProcessNotifyRegistered = TRUE;
    }

    return Status;
}


_Use_decl_annotations_
static VOID
PppUnregisterProcessNotifyCallback(
    VOID
    )
{
    PAGED_CODE();

    if (g_ProcessProtection.ProcessNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(
            PppProcessNotifyCallback,
            TRUE  // Remove
            );
        g_ProcessProtection.ProcessNotifyRegistered = FALSE;
    }
}


_Use_decl_annotations_
static VOID
PppProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
/*++
Routine Description:
    Process creation/termination callback.

    Used to:
    1. Clean up activity trackers when processes terminate
    2. Update critical process cache if a protected process restarts

Arguments:
    Process     - EPROCESS pointer
    ProcessId   - Process ID
    CreateInfo  - NULL for termination, non-NULL for creation
--*/
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL) {
        //
        // Process is terminating - clean up its activity tracker
        //
        PpCleanupActivityTrackerForProcess(ProcessId);

        //
        // Also remove from protected process cache if present
        //
        PpRemoveProtectedProcess(ProcessId);
    }
}


// ============================================================================
// MAIN CALLBACK IMPLEMENTATION
// ============================================================================

_Use_decl_annotations_
OB_PREOP_CALLBACK_STATUS
PpProcessHandlePreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
/*++
Routine Description:
    Enterprise-grade process handle pre-operation callback.

    This is the core of our process protection. Called by ObRegisterCallbacks
    before any handle is created or duplicated to a process.

    Thread Safety:
    - Uses rundown protection for safe shutdown
    - All accessed data structures are properly synchronized
    - Activity trackers use reference counting

Arguments:
    RegistrationContext     - Registration context (unused).
    OperationInformation    - Handle operation details.

Return Value:
    OB_PREOP_SUCCESS always (we strip access, never block the call).
--*/
{
    PP_OPERATION_CONTEXT Context;
    PEPROCESS TargetProcess;
    ACCESS_MASK OriginalAccess;
    ACCESS_MASK NewAccess;
    PP_VERDICT Verdict;
    PP_ACCESS_POLICY MatchedPolicy;
    ULONG ProtectionFlags = 0;
    BOOLEAN IsProtectedTarget = FALSE;
    BOOLEAN HasPolicy = FALSE;
    BOOLEAN RundownAcquired = FALSE;

    UNREFERENCED_PARAMETER(RegistrationContext);

    //
    // Quick validation - check pointers before any access
    //
    if (OperationInformation == NULL) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->Object == NULL) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->Parameters == NULL) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Check if we're initialized and not shutting down
    //
    if (!g_ProcessProtection.Initialized) {
        return OB_PREOP_SUCCESS;
    }

    if (!SHADOWSTRIKE_IS_READY()) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Acquire rundown protection - prevents shutdown during our operation
    //
    if (!ExAcquireRundownProtection(&g_ProcessProtection.RundownRef)) {
        //
        // Shutdown in progress, allow the operation
        //
        return OB_PREOP_SUCCESS;
    }
    RundownAcquired = TRUE;

    //
    // Increment operation counter
    //
    InterlockedIncrement64(&g_ProcessProtection.Stats.TotalOperations);

    //
    // Handle kernel-mode handles based on configuration
    //
    if (OperationInformation->KernelHandle) {
        if (!g_ProcessProtection.Config.EnableKernelHandleFiltering) {
            goto Cleanup;
        }
        //
        // If kernel handle filtering is enabled, continue processing
        //
    }

    //
    // Get target process
    //
    TargetProcess = (PEPROCESS)OperationInformation->Object;

    //
    // Initialize operation context
    //
    RtlZeroMemory(&Context, sizeof(PP_OPERATION_CONTEXT));
    KeQuerySystemTime(&Context.Timestamp);

    Context.TargetProcess = TargetProcess;
    Context.TargetProcessId = PsGetProcessId(TargetProcess);
    Context.IsKernelHandle = OperationInformation->KernelHandle;

    //
    // Determine operation type and get original access
    //
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        Context.OperationType = PpOperationCreate;
        OriginalAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        Context.OperationType = PpOperationDuplicate;
        OriginalAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        goto Cleanup;
    }

    Context.OriginalDesiredAccess = OriginalAccess;

    //
    // Get source process information
    //
    Context.SourceProcessId = PsGetCurrentProcessId();
    Context.SourceProcess = PsGetCurrentProcess();

    //
    // Fast path: Check if source and target are the same process
    // (Processes can access themselves freely)
    //
    if (Context.SourceProcessId == Context.TargetProcessId) {
        goto Cleanup;
    }

    //
    // Check if target is a protected process (fast path via cache)
    //
    IsProtectedTarget = PpIsProcessProtected(
        Context.TargetProcessId,
        &Context.TargetCategory,
        &Context.TargetProtectionLevel
        );

    //
    // Also check SelfProtection module for EDR processes
    //
    if (!IsProtectedTarget) {
        if (ShadowStrikeIsProcessProtected(Context.TargetProcessId, &ProtectionFlags)) {
            IsProtectedTarget = TRUE;
            Context.TargetCategory = PpCategoryAntimalware;
            Context.TargetProtectionLevel = PpProtectionAntimalware;
        }
    }

    //
    // If target is not protected, allow full access
    // (But still track activity if enabled)
    //
    if (!IsProtectedTarget) {
        //
        // Optional: Track activity for non-protected targets
        // to detect enumeration behavior
        //
        if (g_ProcessProtection.Config.EnableActivityTracking) {
            //
            // Only track if access is suspicious (not just query)
            //
            if (PpAccessAllowsInjection(OriginalAccess) ||
                PpAccessAllowsTermination(OriginalAccess)) {
                PpTrackActivity(
                    Context.SourceProcessId,
                    Context.TargetProcessId,
                    FALSE
                    );
            }
        }
        goto Cleanup;
    }

    //
    // Increment protected target counter
    //
    InterlockedIncrement64(&g_ProcessProtection.Stats.ProtectedTargetOperations);

    //
    // Check if source is trusted (allow our own processes full access)
    //
    if (PppIsTrustedSource(Context.SourceProcessId, Context.TargetProcessId)) {
        goto Cleanup;
    }

    //
    // Check if source is also protected (EDR-to-EDR communication)
    //
    if (ShadowStrikeIsProcessProtected(Context.SourceProcessId, NULL)) {
        Context.SourceIsProtected = TRUE;
        goto Cleanup;
    }

    //
    // Get session information for cross-session detection
    // Token operations can fail for exiting processes - handle gracefully
    //
    {
        PACCESS_TOKEN SourceToken = NULL;
        PACCESS_TOKEN TargetToken = NULL;
        ULONG SourceSession = 0;
        ULONG TargetSession = 0;

        __try {
            SourceToken = PsReferencePrimaryToken(Context.SourceProcess);
            if (SourceToken != NULL) {
                SeQuerySessionIdToken(SourceToken, &SourceSession);
                Context.SourceSessionId = SourceSession;
                PsDereferencePrimaryToken(SourceToken);
            }

            TargetToken = PsReferencePrimaryToken(TargetProcess);
            if (TargetToken != NULL) {
                SeQuerySessionIdToken(TargetToken, &TargetSession);
                Context.TargetSessionId = TargetSession;
                PsDereferencePrimaryToken(TargetToken);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            //
            // Token access failed - process may be exiting
            // Continue with default session values (0)
            //
        }
    }

    //
    // Check for matching policy if enabled
    //
    if (g_ProcessProtection.Config.EnablePolicyEnforcement) {
        RtlZeroMemory(&MatchedPolicy, sizeof(PP_ACCESS_POLICY));
        HasPolicy = PpFindMatchingPolicy(&Context, &MatchedPolicy);
        if (HasPolicy) {
            InterlockedIncrement64(&g_ProcessProtection.Stats.PolicyMatches);
        }
    }

    //
    // Perform full operation analysis
    //
    PpAnalyzeOperation(&Context);

    //
    // Determine verdict based on analysis
    //
    Verdict = PpDetermineVerdict(&Context);
    Context.Verdict = Verdict;

    //
    // Apply verdict
    //
    switch (Verdict) {
        case PpVerdictAllow:
            //
            // No modification needed
            //
            break;

        case PpVerdictStrip:
            //
            // Calculate allowed access
            //
            NewAccess = PpCalculateAllowedAccess(
                OriginalAccess,
                Context.TargetProtectionLevel,
                Context.TargetCategory
                );

            //
            // If we have a policy, also apply policy-specific denials
            //
            if (HasPolicy && MatchedPolicy.DeniedAccess != 0) {
                NewAccess &= ~MatchedPolicy.DeniedAccess;
            }

            Context.ModifiedDesiredAccess = NewAccess;
            Context.StrippedAccess = OriginalAccess & ~NewAccess;

            //
            // Apply the stripped access
            //
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = NewAccess;
            } else {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = NewAccess;
            }

            //
            // Update statistics
            //
            InterlockedIncrement64(&g_ProcessProtection.Stats.AccessStripped);

            if (Context.StrippedAccess & PROCESS_TERMINATE) {
                InterlockedIncrement64(&g_ProcessProtection.Stats.TerminationAttempts);
            }
            if (Context.StrippedAccess & PP_DANGEROUS_INJECT_ACCESS) {
                InterlockedIncrement64(&g_ProcessProtection.Stats.InjectionAttempts);
            }

            //
            // Log if enabled
            //
            if (g_ProcessProtection.Config.LogStrippedAccess && PppShouldLogOperation()) {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID,
                    DPFLTR_WARNING_LEVEL,
                    "[ShadowStrike/PP] Stripped access: PID %lu -> PID %lu, "
                    "Original: 0x%08X, New: 0x%08X, Stripped: 0x%08X\n",
                    HandleToULong(Context.SourceProcessId),
                    HandleToULong(Context.TargetProcessId),
                    OriginalAccess,
                    NewAccess,
                    Context.StrippedAccess
                    );
            }
            break;

        case PpVerdictMonitor:
            //
            // Allow but log/alert
            //
            PppLogSuspiciousOperation(&Context);
            break;

        case PpVerdictBlock:
            //
            // Strip all access (effectively blocking useful handle)
            //
            NewAccess = SYNCHRONIZE;  // Minimal access
            Context.ModifiedDesiredAccess = NewAccess;

            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = NewAccess;
            } else {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = NewAccess;
            }

            InterlockedIncrement64(&g_ProcessProtection.Stats.OperationsBlocked);

            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/PP] BLOCKED handle operation: PID %lu -> PID %lu, "
                "Requested: 0x%08X, Score: %lu, Flags: 0x%08X\n",
                HandleToULong(Context.SourceProcessId),
                HandleToULong(Context.TargetProcessId),
                OriginalAccess,
                Context.SuspicionScore,
                Context.SuspiciousFlags
                );
            break;
    }

    //
    // Track activity for this source
    //
    if (g_ProcessProtection.Config.EnableActivityTracking) {
        PpTrackActivity(
            Context.SourceProcessId,
            Context.TargetProcessId,
            Context.SuspicionScore > 0
            );
    }

    //
    // Send notification to user-mode if significant
    //
    if (g_ProcessProtection.Config.NotifyUserMode &&
        Context.SuspicionScore >= g_ProcessProtection.Config.SuspicionScoreThreshold) {
        PppSendNotification(&Context);
    }

Cleanup:
    if (RundownAcquired) {
        ExReleaseRundownProtection(&g_ProcessProtection.RundownRef);
    }

    return OB_PREOP_SUCCESS;
}


// ============================================================================
// PROTECTION MANAGEMENT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PpAddProtectedProcess(
    _In_ HANDLE ProcessId,
    _In_ PP_PROCESS_CATEGORY Category,
    _In_ PP_PROTECTION_LEVEL ProtectionLevel
    )
{
    LONG Index;
    LONG Count;
    LARGE_INTEGER CurrentTime;

    if (!g_ProcessProtection.Initialized) {
        return STATUS_NOT_FOUND;
    }

    KeQuerySystemTime(&CurrentTime);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessProtection.CacheLock);

    Count = g_ProcessProtection.CriticalProcessCount;

    //
    // Check if already in cache
    //
    for (Index = 0; Index < Count; Index++) {
        if (g_ProcessProtection.CriticalProcessCache[Index].ProcessId == ProcessId) {
            //
            // Update existing entry
            //
            g_ProcessProtection.CriticalProcessCache[Index].Category = Category;
            g_ProcessProtection.CriticalProcessCache[Index].ProtectionLevel = ProtectionLevel;
            g_ProcessProtection.CriticalProcessCache[Index].CacheTime = CurrentTime;

            ExReleasePushLockExclusive(&g_ProcessProtection.CacheLock);
            KeLeaveCriticalRegion();
            return STATUS_SUCCESS;
        }
    }

    //
    // Add new entry if space available
    //
    if (Count >= PP_MAX_CACHED_PROTECTED) {
        ExReleasePushLockExclusive(&g_ProcessProtection.CacheLock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_ProcessProtection.CriticalProcessCache[Count].ProcessId = ProcessId;
    g_ProcessProtection.CriticalProcessCache[Count].Category = Category;
    g_ProcessProtection.CriticalProcessCache[Count].ProtectionLevel = ProtectionLevel;
    g_ProcessProtection.CriticalProcessCache[Count].Flags = 0;
    g_ProcessProtection.CriticalProcessCache[Count].CacheTime = CurrentTime;

    InterlockedIncrement(&g_ProcessProtection.CriticalProcessCount);

    ExReleasePushLockExclusive(&g_ProcessProtection.CacheLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
PpRemoveProtectedProcess(
    _In_ HANDLE ProcessId
    )
{
    LONG Index;
    LONG Count;
    LONG LastIndex;

    if (!g_ProcessProtection.Initialized) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessProtection.CacheLock);

    Count = g_ProcessProtection.CriticalProcessCount;

    for (Index = 0; Index < Count; Index++) {
        if (g_ProcessProtection.CriticalProcessCache[Index].ProcessId == ProcessId) {
            //
            // Remove by swapping with last entry
            //
            LastIndex = Count - 1;
            if (Index != LastIndex) {
                g_ProcessProtection.CriticalProcessCache[Index] =
                    g_ProcessProtection.CriticalProcessCache[LastIndex];
            }

            RtlZeroMemory(
                &g_ProcessProtection.CriticalProcessCache[LastIndex],
                sizeof(PP_CRITICAL_PROCESS_ENTRY)
                );

            InterlockedDecrement(&g_ProcessProtection.CriticalProcessCount);
            break;
        }
    }

    ExReleasePushLockExclusive(&g_ProcessProtection.CacheLock);
    KeLeaveCriticalRegion();
}


_Use_decl_annotations_
BOOLEAN
PpIsProcessProtected(
    _In_ HANDLE ProcessId,
    _Out_opt_ PP_PROCESS_CATEGORY* OutCategory,
    _Out_opt_ PP_PROTECTION_LEVEL* OutProtectionLevel
    )
{
    LONG Index;
    LONG Count;
    BOOLEAN Found = FALSE;

    if (!g_ProcessProtection.Initialized) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ProcessProtection.CacheLock);

    Count = g_ProcessProtection.CriticalProcessCount;

    for (Index = 0; Index < Count; Index++) {
        if (g_ProcessProtection.CriticalProcessCache[Index].ProcessId == ProcessId) {
            Found = TRUE;

            if (OutCategory != NULL) {
                *OutCategory = g_ProcessProtection.CriticalProcessCache[Index].Category;
            }
            if (OutProtectionLevel != NULL) {
                *OutProtectionLevel = g_ProcessProtection.CriticalProcessCache[Index].ProtectionLevel;
            }
            break;
        }
    }

    ExReleasePushLockShared(&g_ProcessProtection.CacheLock);
    KeLeaveCriticalRegion();

    return Found;
}


_Use_decl_annotations_
BOOLEAN
PpValidateCachedProcess(
    _In_ HANDLE ProcessId,
    _In_ PCWSTR ExpectedName
    )
/*++
Routine Description:
    Validates that a cached PID still corresponds to the expected process.

    This prevents attacks where an attacker causes a critical process to
    restart and the new process gets a different PID.
--*/
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    PUNICODE_STRING ImageFileName = NULL;
    BOOLEAN IsValid = FALSE;
    UNICODE_STRING ExpectedSuffix;

    PAGED_CODE();

    if (ProcessId == NULL || ExpectedName == NULL) {
        return FALSE;
    }

    //
    // Look up the process
    //
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status) || Process == NULL) {
        return FALSE;
    }

    //
    // Get the image name
    //
    Status = SeLocateProcessImageName(Process, &ImageFileName);
    if (!NT_SUCCESS(Status) || ImageFileName == NULL) {
        ObDereferenceObject(Process);
        return FALSE;
    }

    //
    // Check if the image name ends with the expected name
    //
    RtlInitUnicodeString(&ExpectedSuffix, ExpectedName);
    IsValid = PpSafeStringEndsWith(ImageFileName, &ExpectedSuffix, TRUE);

    ExFreePool(ImageFileName);
    ObDereferenceObject(Process);

    return IsValid;
}


// ============================================================================
// CRITICAL PROCESS DETECTION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PpDetectCriticalProcesses(
    VOID
    )
/*++
Routine Description:
    Detects and caches well-known critical system processes.

    This version properly handles multiple instances of processes
    like CSRSS (one per session).
--*/
{
    NTSTATUS Status;
    HANDLE Pids[PP_MAX_CSRSS_INSTANCES];
    ULONG FoundCount = 0;
    ULONG i;

    PAGED_CODE();

    //
    // System process (PID 4) - always present
    //
    g_ProcessProtection.SystemPid = (HANDLE)(ULONG_PTR)4;
    PpAddProtectedProcess(
        g_ProcessProtection.SystemPid,
        PpCategorySystem,
        PpProtectionCritical
        );

    //
    // Find LSASS - should be exactly one instance
    //
    Status = PppFindProcessesByName(L"lsass.exe", Pids, 1, &FoundCount);
    if (NT_SUCCESS(Status) && FoundCount > 0 && Pids[0] != NULL) {
        g_ProcessProtection.LsassPid = Pids[0];
        PpAddProtectedProcess(Pids[0], PpCategoryLsass, PpProtectionCritical);

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "[ShadowStrike/PP] Protected LSASS: PID %lu\n",
            HandleToULong(Pids[0])
            );
    }

    //
    // Find ALL CSRSS instances (one per session)
    //
    RtlZeroMemory(Pids, sizeof(Pids));
    Status = PppFindProcessesByName(L"csrss.exe", Pids, PP_MAX_CSRSS_INSTANCES, &FoundCount);
    if (NT_SUCCESS(Status) && FoundCount > 0) {
        for (i = 0; i < FoundCount && i < PP_MAX_CSRSS_INSTANCES; i++) {
            if (Pids[i] != NULL) {
                g_ProcessProtection.CsrssPids[i] = Pids[i];
                PpAddProtectedProcess(Pids[i], PpCategorySystem, PpProtectionCritical);
            }
        }
        InterlockedExchange(&g_ProcessProtection.CsrssCount, (LONG)FoundCount);

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "[ShadowStrike/PP] Protected %lu CSRSS instances\n",
            FoundCount
            );
    }

    //
    // Find services.exe
    //
    RtlZeroMemory(Pids, sizeof(Pids));
    Status = PppFindProcessesByName(L"services.exe", Pids, 1, &FoundCount);
    if (NT_SUCCESS(Status) && FoundCount > 0 && Pids[0] != NULL) {
        g_ProcessProtection.ServicesPid = Pids[0];
        PpAddProtectedProcess(Pids[0], PpCategoryServices, PpProtectionStrict);
    }

    //
    // Find winlogon.exe (may be multiple - one per session)
    //
    RtlZeroMemory(Pids, sizeof(Pids));
    Status = PppFindProcessesByName(L"winlogon.exe", Pids, PP_MAX_CSRSS_INSTANCES, &FoundCount);
    if (NT_SUCCESS(Status) && FoundCount > 0) {
        g_ProcessProtection.WinlogonPid = Pids[0];  // Store first one
        for (i = 0; i < FoundCount; i++) {
            if (Pids[i] != NULL) {
                PpAddProtectedProcess(Pids[i], PpCategorySystem, PpProtectionStrict);
            }
        }
    }

    //
    // Find smss.exe
    //
    RtlZeroMemory(Pids, sizeof(Pids));
    Status = PppFindProcessesByName(L"smss.exe", Pids, 1, &FoundCount);
    if (NT_SUCCESS(Status) && FoundCount > 0 && Pids[0] != NULL) {
        PpAddProtectedProcess(Pids[0], PpCategorySystem, PpProtectionCritical);
    }

    //
    // Find wininit.exe
    //
    RtlZeroMemory(Pids, sizeof(Pids));
    Status = PppFindProcessesByName(L"wininit.exe", Pids, 1, &FoundCount);
    if (NT_SUCCESS(Status) && FoundCount > 0 && Pids[0] != NULL) {
        PpAddProtectedProcess(Pids[0], PpCategorySystem, PpProtectionStrict);
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
PpClassifyProcess(
    _In_ PEPROCESS Process,
    _Out_ PP_PROCESS_CATEGORY* OutCategory,
    _Out_ PP_PROTECTION_LEVEL* OutProtectionLevel
    )
{
    NTSTATUS Status;
    PUNICODE_STRING ImageFileName = NULL;
    PP_PROCESS_CATEGORY Category = PpCategoryUnknown;
    PP_PROTECTION_LEVEL Level = PpProtectionNone;

    PAGED_CODE();

    if (Process == NULL || OutCategory == NULL || OutProtectionLevel == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutCategory = PpCategoryUnknown;
    *OutProtectionLevel = PpProtectionNone;

    //
    // Get process image file name
    //
    Status = SeLocateProcessImageName(Process, &ImageFileName);
    if (!NT_SUCCESS(Status) || ImageFileName == NULL) {
        return Status;
    }

    //
    // Categorize by image name (using length-aware comparison)
    //
    Category = PppCategorizeByImageName(ImageFileName);

    //
    // Determine protection level based on category
    //
    switch (Category) {
        case PpCategorySystem:
            Level = PpProtectionCritical;
            break;
        case PpCategoryLsass:
            Level = PpProtectionCritical;
            break;
        case PpCategoryServices:
            Level = PpProtectionStrict;
            break;
        case PpCategoryAntimalware:
            Level = PpProtectionAntimalware;
            break;
        default:
            Level = PpProtectionNone;
            break;
    }

    *OutCategory = Category;
    *OutProtectionLevel = Level;

    //
    // Free the image name (allocated by SeLocateProcessImageName)
    //
    ExFreePool(ImageFileName);

    return STATUS_SUCCESS;
}


// ============================================================================
// POLICY MANAGEMENT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PpAddAccessPolicy(
    _In_ PPP_ACCESS_POLICY Policy
    )
{
    PPP_ACCESS_POLICY NewPolicy = NULL;

    PAGED_CODE();

    if (Policy == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    NewPolicy = (PPP_ACCESS_POLICY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PP_ACCESS_POLICY),
        PP_POLICY_TAG
        );

    if (NewPolicy == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(NewPolicy, Policy, sizeof(PP_ACCESS_POLICY));
    InitializeListHead(&NewPolicy->ListEntry);

    //
    // Clone image name if provided
    //
    if (Policy->ImageName.Buffer != NULL && Policy->ImageName.Length > 0) {
        //
        // Validate length to prevent integer overflow
        //
        if (Policy->ImageName.MaximumLength < Policy->ImageName.Length ||
            Policy->ImageName.MaximumLength > 32768) {  // Reasonable max
            ShadowStrikeFreePoolWithTag(NewPolicy, PP_POLICY_TAG);
            return STATUS_INVALID_PARAMETER;
        }

        NewPolicy->ImageName.Buffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            Policy->ImageName.MaximumLength,
            PP_STRING_TAG
            );

        if (NewPolicy->ImageName.Buffer == NULL) {
            ShadowStrikeFreePoolWithTag(NewPolicy, PP_POLICY_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(
            NewPolicy->ImageName.Buffer,
            Policy->ImageName.Buffer,
            Policy->ImageName.Length
            );
        NewPolicy->ImageName.Length = Policy->ImageName.Length;
        NewPolicy->ImageName.MaximumLength = Policy->ImageName.MaximumLength;
    } else {
        RtlZeroMemory(&NewPolicy->ImageName, sizeof(UNICODE_STRING));
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessProtection.PolicyLock);

    InsertTailList(&g_ProcessProtection.PolicyList, &NewPolicy->ListEntry);
    InterlockedIncrement(&g_ProcessProtection.PolicyCount);

    ExReleasePushLockExclusive(&g_ProcessProtection.PolicyLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
PpRemovePoliciesForCategory(
    _In_ PP_PROCESS_CATEGORY Category
    )
{
    PLIST_ENTRY Entry;
    PLIST_ENTRY Next;
    PPP_ACCESS_POLICY Policy;
    LIST_ENTRY RemoveList;

    PAGED_CODE();

    InitializeListHead(&RemoveList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessProtection.PolicyLock);

    for (Entry = g_ProcessProtection.PolicyList.Flink;
         Entry != &g_ProcessProtection.PolicyList;
         Entry = Next) {

        Next = Entry->Flink;
        Policy = CONTAINING_RECORD(Entry, PP_ACCESS_POLICY, ListEntry);

        if (Policy->Category == Category) {
            RemoveEntryList(Entry);
            InsertTailList(&RemoveList, Entry);
            InterlockedDecrement(&g_ProcessProtection.PolicyCount);
        }
    }

    ExReleasePushLockExclusive(&g_ProcessProtection.PolicyLock);
    KeLeaveCriticalRegion();

    //
    // Free removed policies outside the lock
    //
    while (!IsListEmpty(&RemoveList)) {
        Entry = RemoveHeadList(&RemoveList);
        Policy = CONTAINING_RECORD(Entry, PP_ACCESS_POLICY, ListEntry);

        if (Policy->ImageName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(Policy->ImageName.Buffer, PP_STRING_TAG);
        }
        ShadowStrikeFreePoolWithTag(Policy, PP_POLICY_TAG);
    }
}


_Use_decl_annotations_
BOOLEAN
PpFindMatchingPolicy(
    _In_ PPP_OPERATION_CONTEXT Context,
    _Out_ PPP_ACCESS_POLICY OutPolicy
    )
/*++
Routine Description:
    Finds a matching access policy for the given operation context.

    Policy matching order:
    1. Exact PID match (highest priority)
    2. Category match
    3. Image name match

    Returns a COPY of the policy to avoid holding locks.
--*/
{
    PLIST_ENTRY Entry;
    PPP_ACCESS_POLICY Policy;
    PPP_ACCESS_POLICY BestMatch = NULL;
    ULONG BestMatchScore = 0;
    ULONG CurrentScore;
    ULONG i;
    BOOLEAN IsExempt;

    if (Context == NULL || OutPolicy == NULL) {
        return FALSE;
    }

    RtlZeroMemory(OutPolicy, sizeof(PP_ACCESS_POLICY));

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ProcessProtection.PolicyLock);

    for (Entry = g_ProcessProtection.PolicyList.Flink;
         Entry != &g_ProcessProtection.PolicyList;
         Entry = Entry->Flink) {

        Policy = CONTAINING_RECORD(Entry, PP_ACCESS_POLICY, ListEntry);
        CurrentScore = 0;

        //
        // Check exemptions first
        //
        IsExempt = FALSE;
        for (i = 0; i < Policy->ExemptCount && i < 8; i++) {
            if (Policy->ExemptProcessIds[i] == Context->SourceProcessId) {
                IsExempt = TRUE;
                break;
            }
        }
        if (IsExempt) {
            continue;
        }

        //
        // Score the match
        //
        if (Policy->TargetProcessId != NULL) {
            if (Policy->TargetProcessId == Context->TargetProcessId) {
                CurrentScore = 100;  // Exact PID match
            } else {
                continue;  // PID specified but doesn't match
            }
        } else if (Policy->Category != PpCategoryUnknown) {
            if (Policy->Category == Context->TargetCategory) {
                CurrentScore = 50;  // Category match
            } else {
                continue;  // Category specified but doesn't match
            }
        }

        //
        // Keep best match
        //
        if (CurrentScore > BestMatchScore) {
            BestMatchScore = CurrentScore;
            BestMatch = Policy;
        }
    }

    if (BestMatch != NULL) {
        //
        // Copy the policy (excluding pointers that need special handling)
        //
        OutPolicy->TargetProcessId = BestMatch->TargetProcessId;
        OutPolicy->Category = BestMatch->Category;
        OutPolicy->ProtectionLevel = BestMatch->ProtectionLevel;
        OutPolicy->DeniedAccess = BestMatch->DeniedAccess;
        OutPolicy->AllowedAccess = BestMatch->AllowedAccess;
        OutPolicy->BlockKernelHandles = BestMatch->BlockKernelHandles;
        OutPolicy->LogOnly = BestMatch->LogOnly;
        OutPolicy->RequireSignedExemption = BestMatch->RequireSignedExemption;
        RtlZeroMemory(&OutPolicy->ImageName, sizeof(UNICODE_STRING));  // Don't copy string
        RtlCopyMemory(OutPolicy->ExemptProcessIds, BestMatch->ExemptProcessIds,
                      sizeof(OutPolicy->ExemptProcessIds));
        OutPolicy->ExemptCount = BestMatch->ExemptCount;

        InterlockedIncrement64(&BestMatch->TimesApplied);
    }

    ExReleasePushLockShared(&g_ProcessProtection.PolicyLock);
    KeLeaveCriticalRegion();

    return (BestMatch != NULL);
}


// ============================================================================
// OPERATION ANALYSIS
// ============================================================================

_Use_decl_annotations_
VOID
PpAnalyzeOperation(
    _Inout_ PPP_OPERATION_CONTEXT Context
    )
/*++
Routine Description:
    Analyzes a handle operation for suspicious indicators.
--*/
{
    ULONG Score = 0;
    ACCESS_MASK Access = Context->OriginalDesiredAccess;

    Context->SuspiciousFlags = PpSuspiciousNone;
    Context->SuspicionScore = 0;

    //
    // Check for credential dumping pattern (LSASS access)
    //
    if (Context->TargetCategory == PpCategoryLsass) {
        if (PpAccessMatchesCredentialDump(Access)) {
            Context->SuspiciousFlags |= PpSuspiciousCredentialAccess;
            Score += 40;
            InterlockedIncrement64(&g_ProcessProtection.Stats.CredentialAccessAttempts);
        }

        //
        // Any memory access to LSASS is highly suspicious
        //
        if (Access & PROCESS_VM_READ) {
            Score += 20;
        }
    }

    //
    // Check for injection attempt
    //
    if (PpAccessAllowsInjection(Access)) {
        Context->SuspiciousFlags |= PpSuspiciousInjectionAttempt;
        Score += 30;
    }

    //
    // Check for termination attempt
    //
    if (PpAccessAllowsTermination(Access)) {
        Context->SuspiciousFlags |= PpSuspiciousTerminationAttempt;
        Score += 25;
    }

    //
    // Check for debug access (PROCESS_ALL_ACCESS)
    //
    if ((Access & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS) {
        Context->SuspiciousFlags |= PpSuspiciousDebugAttempt;
        Score += 35;
        InterlockedIncrement64(&g_ProcessProtection.Stats.DebugAttempts);
    }

    //
    // Check for cross-session access
    //
    if (Context->SourceSessionId != Context->TargetSessionId) {
        //
        // Session 0 to user session is normal (services)
        // User session to session 0 is suspicious
        //
        if (Context->SourceSessionId != 0 && Context->TargetSessionId == 0) {
            Context->SuspiciousFlags |= PpSuspiciousCrossSectionAccess;
            Score += 15;
            InterlockedIncrement64(&g_ProcessProtection.Stats.CrossSessionAccess);
        }
    }

    //
    // Check for handle duplication chains
    //
    if (Context->OperationType == PpOperationDuplicate) {
        Context->SuspiciousFlags |= PpSuspiciousDuplicationChain;
        Score += 10;
    }

    //
    // Check if source is rate limited (potential enumeration)
    //
    if (PpIsSourceRateLimited(Context->SourceProcessId)) {
        Context->SuspiciousFlags |= PpSuspiciousRapidEnumeration;
        Score += 20;
    }

    //
    // Increase score for EDR self-protection bypass attempts
    //
    if (Context->TargetCategory == PpCategoryAntimalware) {
        Context->SuspiciousFlags |= PpSuspiciousSelfProtectBypass;
        Score += 25;
    }

    //
    // Cap score at 100
    //
    if (Score > 100) {
        Score = 100;
    }

    Context->SuspicionScore = Score;

    if (Score > 0) {
        InterlockedIncrement64(&g_ProcessProtection.Stats.SuspiciousOperations);
    }
}


_Use_decl_annotations_
PP_VERDICT
PpDetermineVerdict(
    _In_ PPP_OPERATION_CONTEXT Context
    )
{
    //
    // If safe read-only access, always allow
    //
    if (PpAccessIsSafeReadOnly(Context->OriginalDesiredAccess)) {
        return PpVerdictAllow;
    }

    //
    // High suspicion score = strip
    //
    if (Context->SuspicionScore >= 80) {
        return PpVerdictStrip;
    }

    //
    // Medium suspicion = strip based on protection level
    //
    if (Context->SuspicionScore >= 40) {
        switch (Context->TargetProtectionLevel) {
            case PpProtectionCritical:
            case PpProtectionAntimalware:
            case PpProtectionStrict:
                return PpVerdictStrip;
            case PpProtectionMedium:
            case PpProtectionLight:
                return PpVerdictMonitor;
            default:
                return PpVerdictMonitor;
        }
    }

    //
    // Low suspicion: Apply protection based on level
    //
    switch (Context->TargetProtectionLevel) {
        case PpProtectionCritical:
        case PpProtectionAntimalware:
            //
            // Always strip dangerous access for critical processes
            //
            if ((Context->OriginalDesiredAccess & PP_FULL_DANGEROUS_ACCESS) != 0) {
                return PpVerdictStrip;
            }
            break;

        case PpProtectionStrict:
            //
            // Strip terminate and inject rights
            //
            if ((Context->OriginalDesiredAccess &
                (PP_DANGEROUS_TERMINATE_ACCESS | PP_DANGEROUS_INJECT_ACCESS)) != 0) {
                return PpVerdictStrip;
            }
            break;

        case PpProtectionMedium:
            //
            // Strip terminate and inject rights
            //
            if ((Context->OriginalDesiredAccess &
                (PP_DANGEROUS_TERMINATE_ACCESS | PP_DANGEROUS_INJECT_ACCESS)) != 0) {
                return PpVerdictStrip;
            }
            break;

        case PpProtectionLight:
            //
            // Strip only terminate rights
            //
            if ((Context->OriginalDesiredAccess & PROCESS_TERMINATE) != 0) {
                return PpVerdictStrip;
            }
            break;

        default:
            break;
    }

    return PpVerdictAllow;
}


_Use_decl_annotations_
ACCESS_MASK
PpCalculateAllowedAccess(
    _In_ ACCESS_MASK OriginalAccess,
    _In_ PP_PROTECTION_LEVEL ProtectionLevel,
    _In_ PP_PROCESS_CATEGORY Category
    )
{
    ACCESS_MASK DeniedMask = 0;

    //
    // Determine what to deny based on protection level
    //
    switch (ProtectionLevel) {
        case PpProtectionCritical:
        case PpProtectionAntimalware:
            DeniedMask = PP_FULL_DANGEROUS_ACCESS;
            break;

        case PpProtectionStrict:
            DeniedMask = PP_DANGEROUS_TERMINATE_ACCESS |
                         PP_DANGEROUS_INJECT_ACCESS |
                         PP_DANGEROUS_CONTROL_ACCESS;
            break;

        case PpProtectionMedium:
            DeniedMask = PP_DANGEROUS_TERMINATE_ACCESS |
                         PP_DANGEROUS_INJECT_ACCESS;
            break;

        case PpProtectionLight:
            DeniedMask = PP_DANGEROUS_TERMINATE_ACCESS;
            break;

        default:
            DeniedMask = 0;
            break;
    }

    //
    // Special handling for LSASS: Block VM_READ if strict protection enabled
    // This is the key defense against credential dumping (T1003)
    //
    if (Category == PpCategoryLsass &&
        g_ProcessProtection.Config.StrictLsassProtection) {
        DeniedMask |= PP_LSASS_BLOCKED_ACCESS;
    }

    return OriginalAccess & ~DeniedMask;
}


// ============================================================================
// ACTIVITY TRACKING (WITH REFERENCE COUNTING)
// ============================================================================

_Use_decl_annotations_
static VOID
PppReferenceTracker(
    _In_ PPP_ACTIVITY_TRACKER Tracker
    )
/*++
Routine Description:
    Adds a reference to an activity tracker.
--*/
{
    if (Tracker != NULL) {
        InterlockedIncrement(&Tracker->ReferenceCount);
    }
}


_Use_decl_annotations_
static VOID
PppDereferenceTracker(
    _In_ PPP_ACTIVITY_TRACKER Tracker
    )
/*++
Routine Description:
    Releases a reference to an activity tracker.
    Frees the tracker when the last reference is released.
--*/
{
    LONG NewCount;

    if (Tracker == NULL) {
        return;
    }

    NewCount = InterlockedDecrement(&Tracker->ReferenceCount);

    if (NewCount == 0) {
        //
        // Mark as freed to help detect use-after-free in debug
        //
        InterlockedExchange(&Tracker->State, PpTrackerStateFreed);

        ShadowStrikeFreePoolWithTag(Tracker, PP_TRACKER_TAG);
    }
}


_Use_decl_annotations_
static PPP_ACTIVITY_TRACKER
PppFindActivityTrackerLocked(
    _In_ HANDLE SourceProcessId
    )
/*++
Routine Description:
    Finds an activity tracker under the lock.

    CALLER MUST HOLD ActivityLock (shared or exclusive).
    Does NOT add a reference - caller must do so if needed.
--*/
{
    ULONG HashIndex;
    PLIST_ENTRY Entry;
    PPP_ACTIVITY_TRACKER Tracker;

    HashIndex = PppHashProcessId(SourceProcessId) % PP_ACTIVITY_HASH_SIZE;

    for (Entry = g_ProcessProtection.ActivityHashTable[HashIndex].Flink;
         Entry != &g_ProcessProtection.ActivityHashTable[HashIndex];
         Entry = Entry->Flink) {

        Tracker = CONTAINING_RECORD(Entry, PP_ACTIVITY_TRACKER, HashEntry);

        //
        // Check state to skip trackers being removed
        //
        if (InterlockedCompareExchange(&Tracker->State, PpTrackerStateActive, PpTrackerStateActive)
            == PpTrackerStateActive) {

            if (Tracker->SourceProcessId == SourceProcessId) {
                return Tracker;
            }
        }
    }

    return NULL;
}


_Use_decl_annotations_
static PPP_ACTIVITY_TRACKER
PppFindOrCreateActivityTracker(
    _In_ HANDLE SourceProcessId
    )
/*++
Routine Description:
    Finds or creates an activity tracker for a source process.

    Returns a REFERENCED tracker that must be dereferenced by the caller.

    Thread Safety:
    - Uses double-checked locking pattern
    - Returns with reference count incremented
--*/
{
    ULONG HashIndex;
    PPP_ACTIVITY_TRACKER Tracker = NULL;
    PPP_ACTIVITY_TRACKER NewTracker = NULL;
    PPP_ACTIVITY_TRACKER ExistingTracker = NULL;

    HashIndex = PppHashProcessId(SourceProcessId) % PP_ACTIVITY_HASH_SIZE;

    //
    // First try to find existing tracker with shared lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ProcessProtection.ActivityLock);

    Tracker = PppFindActivityTrackerLocked(SourceProcessId);
    if (Tracker != NULL) {
        //
        // Found - add reference while still holding lock
        //
        PppReferenceTracker(Tracker);
        ExReleasePushLockShared(&g_ProcessProtection.ActivityLock);
        KeLeaveCriticalRegion();
        return Tracker;
    }

    ExReleasePushLockShared(&g_ProcessProtection.ActivityLock);
    KeLeaveCriticalRegion();

    //
    // Not found - allocate new tracker
    //
    NewTracker = (PPP_ACTIVITY_TRACKER)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PP_ACTIVITY_TRACKER),
        PP_TRACKER_TAG
        );

    if (NewTracker == NULL) {
        return NULL;
    }

    RtlZeroMemory(NewTracker, sizeof(PP_ACTIVITY_TRACKER));
    NewTracker->SourceProcessId = SourceProcessId;
    NewTracker->ReferenceCount = 2;  // One for hash table, one for caller
    NewTracker->State = PpTrackerStateActive;
    KeQuerySystemTime(&NewTracker->FirstActivity);
    KeInitializeSpinLock(&NewTracker->TargetLock);
    InitializeListHead(&NewTracker->ListEntry);
    InitializeListHead(&NewTracker->HashEntry);

    //
    // Insert with exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessProtection.ActivityLock);

    //
    // Double-check it wasn't added while we allocated
    //
    ExistingTracker = PppFindActivityTrackerLocked(SourceProcessId);
    if (ExistingTracker != NULL) {
        //
        // Someone else added it - use that one
        //
        PppReferenceTracker(ExistingTracker);
        ExReleasePushLockExclusive(&g_ProcessProtection.ActivityLock);
        KeLeaveCriticalRegion();

        //
        // Free our unused allocation
        //
        ShadowStrikeFreePoolWithTag(NewTracker, PP_TRACKER_TAG);
        return ExistingTracker;
    }

    //
    // Insert new tracker
    //
    InsertTailList(&g_ProcessProtection.ActivityList, &NewTracker->ListEntry);
    InsertTailList(&g_ProcessProtection.ActivityHashTable[HashIndex], &NewTracker->HashEntry);
    InterlockedIncrement(&g_ProcessProtection.ActiveTrackers);

    ExReleasePushLockExclusive(&g_ProcessProtection.ActivityLock);
    KeLeaveCriticalRegion();

    return NewTracker;
}


_Use_decl_annotations_
static VOID
PppUpdateActivityTracker(
    _Inout_ PPP_ACTIVITY_TRACKER Tracker,
    _In_ HANDLE TargetProcessId,
    _In_ BOOLEAN IsSuspicious
    )
/*++
Routine Description:
    Updates activity tracker state.

    Thread Safety:
    - Uses atomic operations for counters
    - Uses spinlock for target array
    - Safe for concurrent calls
--*/
{
    LARGE_INTEGER CurrentTime;
    LONGLONG FirstActivityTime;
    LONGLONG TimeDiff;
    KIRQL OldIrql;
    BOOLEAN AlreadyTracked;
    ULONG i;

    KeQuerySystemTime(&CurrentTime);

    //
    // Update last activity atomically (use InterlockedExchange64 for 64-bit values)
    //
    InterlockedExchange64(&Tracker->LastActivity.QuadPart, CurrentTime.QuadPart);

    InterlockedIncrement(&Tracker->HandleOperationCount);

    if (IsSuspicious) {
        InterlockedIncrement(&Tracker->SuspiciousOperationCount);
    }

    //
    // Check for rate limiting using atomic operations
    //
    FirstActivityTime = InterlockedCompareExchange64(
        &Tracker->FirstActivity.QuadPart,
        0,
        0  // Read current value
        );

    TimeDiff = CurrentTime.QuadPart - FirstActivityTime;

    if (TimeDiff < PP_ACTIVITY_WINDOW_100NS) {
        //
        // Within time window - check threshold
        //
        if (Tracker->HandleOperationCount > PP_SUSPICIOUS_HANDLE_THRESHOLD) {
            if (InterlockedExchange(&Tracker->IsRateLimited, TRUE) == FALSE) {
                InterlockedIncrement64(&g_ProcessProtection.Stats.RateLimitedOperations);
            }
        }
    } else {
        //
        // Reset window atomically
        //
        InterlockedExchange64(&Tracker->FirstActivity.QuadPart, CurrentTime.QuadPart);
        InterlockedExchange(&Tracker->HandleOperationCount, 1);
        InterlockedExchange(&Tracker->SuspiciousOperationCount, IsSuspicious ? 1 : 0);
        InterlockedExchange(&Tracker->IsRateLimited, FALSE);
    }

    //
    // Track unique targets (protected by spinlock)
    //
    KeAcquireSpinLock(&Tracker->TargetLock, &OldIrql);

    if (Tracker->UniqueTargetCount < PP_MAX_TRACKED_TARGETS) {
        AlreadyTracked = FALSE;
        for (i = 0; i < Tracker->UniqueTargetCount; i++) {
            if (Tracker->RecentTargets[i] == TargetProcessId) {
                AlreadyTracked = TRUE;
                break;
            }
        }
        if (!AlreadyTracked) {
            Tracker->RecentTargets[Tracker->UniqueTargetCount++] = TargetProcessId;
        }
    }

    KeReleaseSpinLock(&Tracker->TargetLock, OldIrql);
}


_Use_decl_annotations_
VOID
PpTrackActivity(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ BOOLEAN IsSuspicious
    )
{
    PPP_ACTIVITY_TRACKER Tracker;

    if (!g_ProcessProtection.Config.EnableActivityTracking) {
        return;
    }

    Tracker = PppFindOrCreateActivityTracker(SourceProcessId);
    if (Tracker != NULL) {
        PppUpdateActivityTracker(Tracker, TargetProcessId, IsSuspicious);

        //
        // Release our reference
        //
        PppDereferenceTracker(Tracker);
    }
}


_Use_decl_annotations_
BOOLEAN
PpIsSourceRateLimited(
    _In_ HANDLE SourceProcessId
    )
{
    ULONG HashIndex;
    PLIST_ENTRY Entry;
    PPP_ACTIVITY_TRACKER Tracker;
    BOOLEAN IsLimited = FALSE;

    if (!g_ProcessProtection.Config.EnableRateLimiting) {
        return FALSE;
    }

    HashIndex = PppHashProcessId(SourceProcessId) % PP_ACTIVITY_HASH_SIZE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ProcessProtection.ActivityLock);

    for (Entry = g_ProcessProtection.ActivityHashTable[HashIndex].Flink;
         Entry != &g_ProcessProtection.ActivityHashTable[HashIndex];
         Entry = Entry->Flink) {

        Tracker = CONTAINING_RECORD(Entry, PP_ACTIVITY_TRACKER, HashEntry);
        if (Tracker->SourceProcessId == SourceProcessId) {
            //
            // Read atomically
            //
            IsLimited = (InterlockedCompareExchange(&Tracker->IsRateLimited, 0, 0) != 0);
            break;
        }
    }

    ExReleasePushLockShared(&g_ProcessProtection.ActivityLock);
    KeLeaveCriticalRegion();

    return IsLimited;
}


_Use_decl_annotations_
VOID
PpCleanupActivityTrackerForProcess(
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    Cleans up the activity tracker for a terminated process.

    Called from process notify callback when a process exits.
    This prevents memory leaks from accumulated trackers.

    Thread Safety:
    - Removes tracker from lists under lock
    - Uses reference counting for safe deallocation
--*/
{
    ULONG HashIndex;
    PPP_ACTIVITY_TRACKER Tracker = NULL;

    HashIndex = PppHashProcessId(ProcessId) % PP_ACTIVITY_HASH_SIZE;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessProtection.ActivityLock);

    Tracker = PppFindActivityTrackerLocked(ProcessId);
    if (Tracker != NULL) {
        //
        // Mark as removing to prevent new references
        //
        InterlockedExchange(&Tracker->State, PpTrackerStateRemoving);

        //
        // Remove from lists
        //
        RemoveEntryList(&Tracker->ListEntry);
        RemoveEntryList(&Tracker->HashEntry);
        InterlockedDecrement(&g_ProcessProtection.ActiveTrackers);

        //
        // Reinitialize list entries to prevent double-remove issues
        //
        InitializeListHead(&Tracker->ListEntry);
        InitializeListHead(&Tracker->HashEntry);
    }

    ExReleasePushLockExclusive(&g_ProcessProtection.ActivityLock);
    KeLeaveCriticalRegion();

    //
    // Release the hash table's reference (outside lock)
    //
    if (Tracker != NULL) {
        PppDereferenceTracker(Tracker);
    }
}


// ============================================================================
// STATISTICS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PpGetStatistics(
    _Out_opt_ PULONG64 TotalOperations,
    _Out_opt_ PULONG64 AccessStripped,
    _Out_opt_ PULONG64 CredentialAccessAttempts,
    _Out_opt_ PULONG64 InjectionAttempts
    )
{
    if (!g_ProcessProtection.Initialized) {
        return STATUS_NOT_FOUND;
    }

    if (TotalOperations != NULL) {
        *TotalOperations = (ULONG64)g_ProcessProtection.Stats.TotalOperations;
    }
    if (AccessStripped != NULL) {
        *AccessStripped = (ULONG64)g_ProcessProtection.Stats.AccessStripped;
    }
    if (CredentialAccessAttempts != NULL) {
        *CredentialAccessAttempts = (ULONG64)g_ProcessProtection.Stats.CredentialAccessAttempts;
    }
    if (InjectionAttempts != NULL) {
        *InjectionAttempts = (ULONG64)g_ProcessProtection.Stats.InjectionAttempts;
    }

    return STATUS_SUCCESS;
}


// ============================================================================
// INTERNAL HELPERS
// ============================================================================

_Use_decl_annotations_
static ULONG
PppHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR Value = (ULONG_PTR)ProcessId;
    Value = Value ^ (Value >> 16);
    Value = Value * 0x85EBCA6B;
    return (ULONG)(Value & 0xFFFFFFFF);
}


_Use_decl_annotations_
static BOOLEAN
PppIsSystemProcess(
    _In_ HANDLE ProcessId
    )
{
    //
    // Only PID 4 (System) is implicitly trusted
    // PID 0 is the Idle process - not a real process
    //
    return (HandleToULong(ProcessId) == 4);
}


_Use_decl_annotations_
static BOOLEAN
PppIsTrustedSource(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId
    )
{
    //
    // System process (PID 4) is trusted
    //
    if (PppIsSystemProcess(SourceProcessId)) {
        return TRUE;
    }

    //
    // Same process is trusted (self-access)
    //
    if (SourceProcessId == TargetProcessId) {
        return TRUE;
    }

    //
    // Check if source is in our protected list (EDR component)
    //
    if (ShadowStrikeIsProcessProtected(SourceProcessId, NULL)) {
        return TRUE;
    }

    return FALSE;
}


_Use_decl_annotations_
static BOOLEAN
PppMatchImageNameSuffix(
    _In_ PCUNICODE_STRING FullPath,
    _In_ PCWSTR Suffix
    )
/*++
Routine Description:
    Safely checks if a UNICODE_STRING ends with a suffix.

    Unlike wcsrchr/wcsicmp, this respects the Length field and
    does NOT rely on NULL termination.
--*/
{
    UNICODE_STRING SuffixString;

    if (FullPath == NULL || FullPath->Buffer == NULL || Suffix == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&SuffixString, Suffix);

    return PpSafeStringEndsWith(FullPath, &SuffixString, TRUE);
}


_Use_decl_annotations_
static BOOLEAN
PppImageNameContains(
    _In_ PCUNICODE_STRING FullPath,
    _In_ PCWSTR Substring
    )
/*++
Routine Description:
    Safely checks if a UNICODE_STRING contains a substring.

    Uses length-aware comparison, NOT wcsstr which requires NULL termination.
--*/
{
    UNICODE_STRING SubString;
    USHORT i;
    USHORT MaxStart;
    USHORT PathChars;
    USHORT SubChars;
    BOOLEAN Match;
    USHORT j;
    WCHAR PathChar;
    WCHAR SubChar;

    if (FullPath == NULL || FullPath->Buffer == NULL || Substring == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&SubString, Substring);

    if (SubString.Length == 0 || FullPath->Length < SubString.Length) {
        return FALSE;
    }

    PathChars = FullPath->Length / sizeof(WCHAR);
    SubChars = SubString.Length / sizeof(WCHAR);
    MaxStart = PathChars - SubChars;

    for (i = 0; i <= MaxStart; i++) {
        Match = TRUE;

        for (j = 0; j < SubChars; j++) {
            PathChar = FullPath->Buffer[i + j];
            SubChar = SubString.Buffer[j];

            //
            // Case-insensitive comparison
            //
            if (PathChar >= L'A' && PathChar <= L'Z') {
                PathChar = PathChar - L'A' + L'a';
            }
            if (SubChar >= L'A' && SubChar <= L'Z') {
                SubChar = SubChar - L'A' + L'a';
            }

            if (PathChar != SubChar) {
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


_Use_decl_annotations_
static PP_PROCESS_CATEGORY
PppCategorizeByImageName(
    _In_ PCUNICODE_STRING ImageName
    )
/*++
Routine Description:
    Categorizes a process by its image name.

    Uses length-aware string comparisons to avoid buffer overreads.
--*/
{
    if (ImageName == NULL || ImageName->Buffer == NULL || ImageName->Length == 0) {
        return PpCategoryUnknown;
    }

    //
    // Check for LSASS
    //
    if (PppMatchImageNameSuffix(ImageName, g_LsassName)) {
        return PpCategoryLsass;
    }

    //
    // Check for system processes
    //
    if (PppMatchImageNameSuffix(ImageName, g_CsrssName) ||
        PppMatchImageNameSuffix(ImageName, g_SmssName) ||
        PppMatchImageNameSuffix(ImageName, g_WininitName) ||
        PppMatchImageNameSuffix(ImageName, g_WinlogonName)) {
        return PpCategorySystem;
    }

    //
    // Check for service processes
    //
    if (PppMatchImageNameSuffix(ImageName, g_ServicesName) ||
        PppMatchImageNameSuffix(ImageName, g_SvchostName)) {
        return PpCategoryServices;
    }

    //
    // Check for ShadowStrike (our EDR) - contains check is sufficient
    // NOTE: This is weak protection. In production, use code signing verification.
    //
    if (PppImageNameContains(ImageName, g_ShadowStrikeName)) {
        return PpCategoryAntimalware;
    }

    return PpCategoryUnknown;
}


_Use_decl_annotations_
static VOID
PppCleanupActivityTrackers(
    VOID
    )
/*++
Routine Description:
    Cleans up all activity trackers during shutdown.

    Called AFTER rundown protection has drained all in-flight operations.
--*/
{
    PLIST_ENTRY Entry;
    PPP_ACTIVITY_TRACKER Tracker;
    LIST_ENTRY FreeList;

    InitializeListHead(&FreeList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessProtection.ActivityLock);

    while (!IsListEmpty(&g_ProcessProtection.ActivityList)) {
        Entry = RemoveHeadList(&g_ProcessProtection.ActivityList);
        Tracker = CONTAINING_RECORD(Entry, PP_ACTIVITY_TRACKER, ListEntry);

        //
        // Remove from hash table
        //
        if (!IsListEmpty(&Tracker->HashEntry)) {
            RemoveEntryList(&Tracker->HashEntry);
            InitializeListHead(&Tracker->HashEntry);
        }

        //
        // Add to free list (to free outside lock)
        //
        InsertTailList(&FreeList, &Tracker->ListEntry);
    }

    g_ProcessProtection.ActiveTrackers = 0;

    ExReleasePushLockExclusive(&g_ProcessProtection.ActivityLock);
    KeLeaveCriticalRegion();

    //
    // Free all trackers outside the lock
    //
    while (!IsListEmpty(&FreeList)) {
        Entry = RemoveHeadList(&FreeList);
        Tracker = CONTAINING_RECORD(Entry, PP_ACTIVITY_TRACKER, ListEntry);

        //
        // Release the hash table's reference
        //
        PppDereferenceTracker(Tracker);
    }
}


_Use_decl_annotations_
static VOID
PppCleanupPolicies(
    VOID
    )
{
    PLIST_ENTRY Entry;
    PPP_ACCESS_POLICY Policy;
    LIST_ENTRY FreeList;

    InitializeListHead(&FreeList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessProtection.PolicyLock);

    while (!IsListEmpty(&g_ProcessProtection.PolicyList)) {
        Entry = RemoveHeadList(&g_ProcessProtection.PolicyList);
        InsertTailList(&FreeList, Entry);
    }

    g_ProcessProtection.PolicyCount = 0;

    ExReleasePushLockExclusive(&g_ProcessProtection.PolicyLock);
    KeLeaveCriticalRegion();

    //
    // Free outside lock
    //
    while (!IsListEmpty(&FreeList)) {
        Entry = RemoveHeadList(&FreeList);
        Policy = CONTAINING_RECORD(Entry, PP_ACCESS_POLICY, ListEntry);

        if (Policy->ImageName.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(Policy->ImageName.Buffer, PP_STRING_TAG);
        }
        ShadowStrikeFreePoolWithTag(Policy, PP_POLICY_TAG);
    }
}


_Use_decl_annotations_
static VOID
PppLogSuspiciousOperation(
    _In_ PPP_OPERATION_CONTEXT Context
    )
{
    if (!PppShouldLogOperation()) {
        return;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_WARNING_LEVEL,
        "[ShadowStrike/PP] SUSPICIOUS: PID %lu -> PID %lu (Cat:%d), "
        "Access: 0x%08X, Score: %lu, Flags: 0x%08X\n",
        HandleToULong(Context->SourceProcessId),
        HandleToULong(Context->TargetProcessId),
        Context->TargetCategory,
        Context->OriginalDesiredAccess,
        Context->SuspicionScore,
        Context->SuspiciousFlags
        );
}


_Use_decl_annotations_
static VOID
PppSendNotification(
    _In_ PPP_OPERATION_CONTEXT Context
    )
/*++
Routine Description:
    Sends a notification to user-mode about a suspicious handle operation.

    Uses the ShadowStrike communication port infrastructure.
--*/
{
    NTSTATUS Status;
    SHADOWSTRIKE_PROCESS_NOTIFICATION Notification;

    //
    // Check if CommPort is available
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        return;
    }

    //
    // Build notification message
    //
    RtlZeroMemory(&Notification, sizeof(Notification));

    Notification.Header.Size = sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION);
    Notification.Header.MessageType = SHADOWSTRIKE_MSG_PROCESS_HANDLE_ALERT;

    Notification.SourceProcessId = Context->SourceProcessId;
    Notification.TargetProcessId = Context->TargetProcessId;
    Notification.RequestedAccess = Context->OriginalDesiredAccess;
    Notification.GrantedAccess = Context->ModifiedDesiredAccess;
    Notification.SuspicionScore = Context->SuspicionScore;
    Notification.SuspiciousFlags = Context->SuspiciousFlags;
    Notification.TargetCategory = (ULONG)Context->TargetCategory;
    Notification.OperationType = (ULONG)Context->OperationType;
    Notification.Verdict = (ULONG)Context->Verdict;

    //
    // Send notification (non-blocking, no reply needed)
    //
    Status = ShadowStrikeSendProcessNotification(
        &Notification,
        sizeof(Notification),
        FALSE,      // Don't require reply
        NULL,
        NULL
        );

    if (NT_SUCCESS(Status)) {
        InterlockedIncrement64(&g_ProcessProtection.Stats.NotificationsSent);
    }
}


_Use_decl_annotations_
static BOOLEAN
PppShouldLogOperation(
    VOID
    )
/*++
Routine Description:
    Rate-limits logging operations to prevent log flooding.

    Uses lock-free atomic operations for thread safety.
--*/
{
    LARGE_INTEGER CurrentTime;
    LONGLONG CurrentSecond;
    LONGLONG StoredSecond;
    LONG CurrentLogs;

    if (!g_ProcessProtection.Config.EnableRateLimiting) {
        return TRUE;
    }

    KeQuerySystemTime(&CurrentTime);

    //
    // Get current stored second start (atomic read)
    //
    StoredSecond = InterlockedCompareExchange64(
        &g_ProcessProtection.RateLimiter.CurrentSecondStart,
        0,
        0
        );

    CurrentSecond = CurrentTime.QuadPart;

    //
    // Check if we're in a new second (1 second = 10,000,000 100ns units)
    //
    if ((CurrentSecond - StoredSecond) >= 10000000LL) {
        //
        // Try to reset the counter for new second
        // Use compare-exchange to handle race conditions
        //
        if (InterlockedCompareExchange64(
                &g_ProcessProtection.RateLimiter.CurrentSecondStart,
                CurrentSecond,
                StoredSecond
                ) == StoredSecond) {
            //
            // We won the race - reset counter
            //
            InterlockedExchange(&g_ProcessProtection.RateLimiter.CurrentSecondLogs, 0);
        }
    }

    //
    // Check if under rate limit and increment atomically
    //
    CurrentLogs = InterlockedIncrement(&g_ProcessProtection.RateLimiter.CurrentSecondLogs);

    if (CurrentLogs > PP_MAX_LOG_RATE_PER_SEC) {
        //
        // Over limit - decrement back and return FALSE
        //
        InterlockedDecrement(&g_ProcessProtection.RateLimiter.CurrentSecondLogs);
        return FALSE;
    }

    return TRUE;
}


_Use_decl_annotations_
static NTSTATUS
PppFindProcessesByName(
    _In_ PCWSTR ProcessName,
    _Out_writes_(MaxPids) PHANDLE ProcessIds,
    _In_ ULONG MaxPids,
    _Out_ PULONG FoundCount
    )
/*++
Routine Description:
    Finds ALL processes matching a given name.

    Unlike the previous implementation, this returns multiple PIDs
    to handle processes with multiple instances (e.g., CSRSS, winlogon).
--*/
{
    NTSTATUS Status;
    PSYSTEM_PROCESS_INFORMATION ProcessInfo = NULL;
    PSYSTEM_PROCESS_INFORMATION CurrentProcess;
    PVOID Buffer = NULL;
    ULONG BufferSize = 256 * 1024;  // Start with 256KB
    ULONG ReturnLength = 0;
    UNICODE_STRING TargetName;
    ULONG Count = 0;

    *FoundCount = 0;
    RtlZeroMemory(ProcessIds, MaxPids * sizeof(HANDLE));

    RtlInitUnicodeString(&TargetName, ProcessName);

    //
    // Allocate buffer for process information
    //
    Buffer = ShadowStrikeAllocatePoolWithTag(PagedPool, BufferSize, PP_POOL_TAG);
    if (Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Query system process information
    //
    Status = ZwQuerySystemInformation(
        SystemProcessInformation,
        Buffer,
        BufferSize,
        &ReturnLength
        );

    if (Status == STATUS_INFO_LENGTH_MISMATCH) {
        ShadowStrikeFreePoolWithTag(Buffer, PP_POOL_TAG);

        //
        // Check for integer overflow
        //
        if (ReturnLength > (ULONG_MAX - 8192)) {
            return STATUS_INTEGER_OVERFLOW;
        }

        BufferSize = ReturnLength + 4096;
        Buffer = ShadowStrikeAllocatePoolWithTag(PagedPool, BufferSize, PP_POOL_TAG);
        if (Buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = ZwQuerySystemInformation(
            SystemProcessInformation,
            Buffer,
            BufferSize,
            &ReturnLength
            );
    }

    if (!NT_SUCCESS(Status)) {
        ShadowStrikeFreePoolWithTag(Buffer, PP_POOL_TAG);
        return Status;
    }

    //
    // Search for ALL matching processes
    //
    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer;
    CurrentProcess = ProcessInfo;

    do {
        if (CurrentProcess->ImageName.Buffer != NULL) {
            if (RtlEqualUnicodeString(&CurrentProcess->ImageName, &TargetName, TRUE)) {
                if (Count < MaxPids) {
                    ProcessIds[Count] = CurrentProcess->UniqueProcessId;
                    Count++;
                }
            }
        }

        if (CurrentProcess->NextEntryOffset == 0) {
            break;
        }

        CurrentProcess = (PSYSTEM_PROCESS_INFORMATION)(
            (PUCHAR)CurrentProcess + CurrentProcess->NextEntryOffset
            );

    } while (TRUE);

    ShadowStrikeFreePoolWithTag(Buffer, PP_POOL_TAG);

    *FoundCount = Count;

    return (Count > 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}


// ============================================================================
// LEGACY COMPATIBILITY
// ============================================================================

/*
 * The existing ObjectCallback.c calls ShadowStrikeProcessPreCallback.
 * We provide this as a wrapper that delegates to our enterprise implementation.
 */
OB_PREOP_CALLBACK_STATUS
ShadowStrikeProcessPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    return PpProcessHandlePreCallback(RegistrationContext, OperationInformation);
}
