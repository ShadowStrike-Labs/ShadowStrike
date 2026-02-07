/**
 * ============================================================================
 * ShadowStrike NGAV - PROCESS PROTECTION
 * ============================================================================
 *
 * @file ProcessProtection.c
 * @brief Object callback logic for process protection.
 *
 * Implements the pre-operation callback to strip dangerous access rights
 * (PROCESS_TERMINATE, PROCESS_VM_WRITE, etc.) from handles opened to
 * protected processes.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ObjectCallback.h"
#include "../../Core/Globals.h"
#include "../../SelfProtection/SelfProtect.h"
#include "ProcessProtection.tmh"

// ============================================================================
// CALLBACK IMPLEMENTATION
// ============================================================================

OB_PREOP_CALLBACK_STATUS
ShadowStrikeProcessPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    PEPROCESS targetProcess;
    HANDLE targetPid;
    HANDLE sourcePid;
    ULONG protectionFlags = 0;
    ACCESS_MASK originalAccess;
    ACCESS_MASK strippedAccess;

    UNREFERENCED_PARAMETER(RegistrationContext);

    //
    // Safety check: Ensure we have operation info
    //
    if (OperationInformation == NULL || OperationInformation->Object == NULL) {
        return OB_PREOP_SUCCESS;
    }

    //
    // We only care about user-mode handle creation/duplication
    // Kernel-mode operations are generally trusted
    //
    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Get target process object and ID
    //
    targetProcess = (PEPROCESS)OperationInformation->Object;
    targetPid = PsGetProcessId(targetProcess);

    //
    // Check if the target process is protected
    //
    if (!ShadowStrikeIsProcessProtected(targetPid, &protectionFlags)) {
        return OB_PREOP_SUCCESS;
    }

    //
    // If we're here, the target is one of our protected processes.
    // Check if the source is also us (we allow our own processes to manage themselves).
    //
    sourcePid = PsGetCurrentProcessId();
    if (ShadowStrikeIsProcessProtected(sourcePid, NULL)) {
        // Allow our own components full access
        return OB_PREOP_SUCCESS;
    }

    //
    // Determine which access rights to modify
    //
    originalAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    
    //
    // Calculate new access mask by stripping dangerous rights
    //
    strippedAccess = originalAccess & ~SHADOWSTRIKE_DANGEROUS_PROCESS_ACCESS;

    //
    // If access was modified, update the operation info and log it
    //
    if (originalAccess != strippedAccess) {
        
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = strippedAccess;
        
        // Update statistics
        SHADOWSTRIKE_INC_STAT(SelfProtectionBlocks);
        
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_FLAG_FILTER,
            "SelfProtection: Stripped PROCESS access from PID %p to PID %p. Orig: 0x%X, New: 0x%X",
            sourcePid, targetPid, originalAccess, strippedAccess);
            
        //
        // If specific flags are blocked, we can increment specific stats
        // (Assuming helper function exists or doing it manually)
        //
        if (originalAccess & PROCESS_TERMINATE) {
             // We can access g_DriverData.Stats.ProcessTerminateBlocks via InterlockedIncrement
             InterlockedIncrement64(&g_DriverData.Stats.ProcessTerminateBlocks);
        }
        if (originalAccess & PROCESS_VM_WRITE) {
             InterlockedIncrement64(&g_DriverData.Stats.VMWriteBlocks);
        }
    }

    return OB_PREOP_SUCCESS;
}
