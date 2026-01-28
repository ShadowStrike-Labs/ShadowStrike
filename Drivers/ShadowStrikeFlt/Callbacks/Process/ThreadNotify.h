#pragma once
#include <ntddk.h>

//
// Routine Description:
//    Registers the thread creation notification callback.
//
// Arguments:
//    None
//
// Return Value:
//    STATUS_SUCCESS if successful, otherwise an NTSTATUS error code.
//
NTSTATUS
RegisterThreadNotify(
    VOID
    );

//
// Routine Description:
//    Unregisters the thread creation notification callback.
//
// Arguments:
//    None
//
// Return Value:
//    STATUS_SUCCESS if successful, otherwise an NTSTATUS error code.
//
NTSTATUS
UnregisterThreadNotify(
    VOID
    );
