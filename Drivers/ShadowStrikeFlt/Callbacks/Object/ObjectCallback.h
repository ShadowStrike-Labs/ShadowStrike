/**
 * ============================================================================
 * ShadowStrike NGAV - OBJECT CALLBACK HEADER
 * ============================================================================
 *
 * @file ObjectCallback.h
 * @brief Object manager callback definitions for self-protection.
 *
 * Handles ObRegisterCallbacks logic to strip dangerous access rights
 * from handles opened to our protected processes and threads.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#include <ntifs.h>
#include <wdm.h>

// ============================================================================
// FUNCTION PROTOTYPES
// ============================================================================

/**
 * @brief Register object manager callbacks.
 * 
 * Registers callbacks for PsProcessType and PsThreadType to protect
 * critical services from termination and injection.
 * 
 * @return STATUS_SUCCESS or error code.
 */
NTSTATUS
ShadowStrikeRegisterObjectCallbacks(
    VOID
    );

/**
 * @brief Unregister object manager callbacks.
 */
VOID
ShadowStrikeUnregisterObjectCallbacks(
    VOID
    );

/**
 * @brief Pre-operation callback for process handles.
 * 
 * Called before a handle to a process is created or duplicated.
 * Checks if the target is a protected process and strips dangerous rights.
 * 
 * @param RegistrationContext Context passed during registration.
 * @param OperationInformation Operation details.
 * @return OB_PREOP_SUCCESS.
 */
OB_PREOP_CALLBACK_STATUS
ShadowStrikeProcessPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

/**
 * @brief Pre-operation callback for thread handles.
 * 
 * Called before a handle to a thread is created or duplicated.
 * Checks if the target thread belongs to a protected process.
 * 
 * @param RegistrationContext Context passed during registration.
 * @param OperationInformation Operation details.
 * @return OB_PREOP_SUCCESS.
 */
OB_PREOP_CALLBACK_STATUS
ShadowStrikeThreadPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );
