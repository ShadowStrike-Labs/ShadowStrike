/**
 * ============================================================================
 * ShadowStrike NGAV - THREAD PROTECTION
 * ============================================================================
 *
 * @file ThreadProtection.c
 * @brief Object callback logic for thread protection.
 *
 * Implements the pre-operation callback to strip dangerous access rights
 * (THREAD_TERMINATE, THREAD_SUSPEND_RESUME, etc.) from handles opened to
 * threads belonging to protected processes.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ObjectCallback.h"
#include "../../Core/Globals.h"
#include "../../SelfProtection/SelfProtect.h"
#include "ThreadProtection.tmh"

// ============================================================================
// CALLBACK IMPLEMENTATION
// ============================================================================

OB_PREOP_CALLBACK_STATUS
ShadowStrikeThreadPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    PETHREAD targetThread;
    HANDLE targetPid;
    HANDLE sourcePid;
    ULONG protectionFlags = 0;
    ACCESS_MASK originalAccess;
    ACCESS_MASK strippedAccess;

    UNREFERENCED_PARAMETER(RegistrationContext);

    //
    // Safety check
    //
    if (OperationInformation == NULL || OperationInformation->Object == NULL) {
        return OB_PREOP_SUCCESS;
    }

    //
    // We only care about user-mode handle creation/duplication
    //
    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Get target thread object and its process ID
    //
    targetThread = (PETHREAD)OperationInformation->Object;
    targetPid = PsGetThreadProcessId(targetThread);

    //
    // Check if the thread belongs to a protected process
    //
    if (!ShadowStrikeIsProcessProtected(targetPid, &protectionFlags)) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Check if the source is trusted
    //
    sourcePid = PsGetCurrentProcessId();
    if (ShadowStrikeIsProcessProtected(sourcePid, NULL)) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Determine access rights
    //
    originalAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    
    //
    // Calculate new access mask by stripping dangerous rights
    //
    strippedAccess = originalAccess & ~SHADOWSTRIKE_DANGEROUS_THREAD_ACCESS;

    //
    // If access was modified, update the operation info
    //
    if (originalAccess != strippedAccess) {
        
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = strippedAccess;
        
        // Update statistics
        SHADOWSTRIKE_INC_STAT(SelfProtectionBlocks);
        
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_FILTER,
            "SelfProtection: Stripped THREAD access from PID %p to target PID %p. Orig: 0x%X, New: 0x%X",
            sourcePid, targetPid, originalAccess, strippedAccess);
            
        //
        // Specific stats
        //
        // Note: Reusing ProcessTerminateBlocks or maybe we should have ThreadTerminateBlocks
        // But the struct has ThreadInjectBlocks. Using generic blocks for now or mapping best effort.
        
        if (originalAccess & (THREAD_SET_CONTEXT | THREAD_SET_INFORMATION)) {
             InterlockedIncrement64(&g_DriverData.Stats.ThreadInjectBlocks);
        }
    }

    return OB_PREOP_SUCCESS;
}
