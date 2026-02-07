#pragma once
#include <ntddk.h>

//
// Routine Description:
//    Registers the image load notification callback.
//
// Arguments:
//    None
//
// Return Value:
//    STATUS_SUCCESS if successful, otherwise an NTSTATUS error code.
//
NTSTATUS
RegisterImageNotify(
    VOID
    );

//
// Routine Description:
//    Unregisters the image load notification callback.
//
// Arguments:
//    None
//
// Return Value:
//    STATUS_SUCCESS if successful, otherwise an NTSTATUS error code.
//
NTSTATUS
UnregisterImageNotify(
    VOID
    );
