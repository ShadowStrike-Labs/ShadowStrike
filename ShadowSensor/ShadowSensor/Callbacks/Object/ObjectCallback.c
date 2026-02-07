/**
 * ============================================================================
 * ShadowStrike NGAV - OBJECT CALLBACK REGISTRATION
 * ============================================================================
 *
 * @file ObjectCallback.c
 * @brief Implementation of object callback registration.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ObjectCallback.h"
#include "../../Core/Globals.h"
#include "ObjectCallback.tmh"

//
// Define the callback registration structure
//

#define SHADOWSTRIKE_OB_CALLBACK_VERSION_LATEST 0x100

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

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
    // Initialize operation registrations
    //
    
    // 1. Process protection
    RtlZeroMemory(&operationRegistration[0], sizeof(OB_OPERATION_REGISTRATION));
    operationRegistration[0].ObjectType = PsProcessType;
    operationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[0].PreOperation = ShadowStrikeProcessPreCallback;
    operationRegistration[0].PostOperation = NULL; // We don't need post-op

    // 2. Thread protection
    RtlZeroMemory(&operationRegistration[1], sizeof(OB_OPERATION_REGISTRATION));
    operationRegistration[1].ObjectType = PsThreadType;
    operationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[1].PreOperation = ShadowStrikeThreadPreCallback;
    operationRegistration[1].PostOperation = NULL;

    //
    // Initialize callback registration
    //
    RtlInitUnicodeString(&altitude, L"321000"); // Standard AV altitude range

    RtlZeroMemory(&callbackRegistration, sizeof(OB_CALLBACK_REGISTRATION));
    callbackRegistration.Version = SHADOWSTRIKE_OB_CALLBACK_VERSION_LATEST;
    callbackRegistration.OperationRegistrationCount = 2;
    callbackRegistration.Altitude = altitude;
    callbackRegistration.RegistrationContext = NULL;
    callbackRegistration.OperationRegistration = operationRegistration;

    //
    // Register the callbacks
    //
    status = ObRegisterCallbacks(
        &callbackRegistration,
        &g_DriverData.ObjectCallbackHandle
        );

    if (NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_FLAG_FILTER,
            "ObRegisterCallbacks successful, Handle=%p", 
            g_DriverData.ObjectCallbackHandle);
    } else {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_FLAG_FILTER,
            "ObRegisterCallbacks failed with status 0x%08X", 
            status);
        g_DriverData.ObjectCallbackHandle = NULL;
    }

    return status;
}

VOID
ShadowStrikeUnregisterObjectCallbacks(
    VOID
    )
{
    if (g_DriverData.ObjectCallbackHandle != NULL) {
        ObUnRegisterCallbacks(g_DriverData.ObjectCallbackHandle);
        g_DriverData.ObjectCallbackHandle = NULL;
        
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_FLAG_FILTER,
            "ObRegisterCallbacks unregistered");
    }
}
