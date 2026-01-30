#include "ThreadNotify.h"
#include "../../Core/Globals.h"
#include "../../Communication/ScanBridge.h"

//
// Global flag to track if the callback is registered
//
static BOOLEAN g_ThreadNotifyRegistered = FALSE;

//
// Forward declaration
//
VOID
ThreadCreateNotifyRoutine(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    );

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, RegisterThreadNotify)
#pragma alloc_text(PAGE, UnregisterThreadNotify)
#pragma alloc_text(PAGE, ThreadCreateNotifyRoutine)
#endif

_Use_decl_annotations_
NTSTATUS
RegisterThreadNotify(
    VOID
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (g_ThreadNotifyRegistered) {
        return STATUS_SUCCESS;
    }

    status = PsSetCreateThreadNotifyRoutine(ThreadCreateNotifyRoutine);

    if (NT_SUCCESS(status)) {
        g_ThreadNotifyRegistered = TRUE;
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS
UnregisterThreadNotify(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    if (g_ThreadNotifyRegistered) {
        status = PsRemoveCreateThreadNotifyRoutine(ThreadCreateNotifyRoutine);
        if (NT_SUCCESS(status)) {
            g_ThreadNotifyRegistered = FALSE;
        }
    }

    return status;
}

//
// Routine Description:
//    Callback routine invoked when a thread is created or deleted.
//
// Arguments:
//    ProcessId - The process ID of the process where the thread is created/deleted.
//    ThreadId - The thread ID of the thread.
//    Create - TRUE if the thread is being created, FALSE if deleted.
//
// Return Value:
//    None
//
VOID
ThreadCreateNotifyRoutine(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    )
{
    HANDLE CurrentProcessId;
    BOOLEAN IsRemote = FALSE;

    PAGED_CODE();

    //
    // Check if driver is ready to process requests
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        return;
    }

    if (!Create) {
        return; // We only care about creation for injection detection
    }

    CurrentProcessId = PsGetCurrentProcessId();

    //
    // Detection Logic: Remote Thread Injection
    // If the process creating the thread is NOT the process owning the thread,
    // and it's not the System process (PID 4), it's a remote thread.
    //
    if (CurrentProcessId != ProcessId && CurrentProcessId != (HANDLE)4) {
        IsRemote = TRUE;

        // Log or Notify User Mode
        // We send this to user mode to correlate with known good behavior or malicious patterns.
        // For example, Debuggers do this, but so does Malware.

        ShadowStrikeSendThreadNotification(
            ProcessId,
            ThreadId,
            Create,
            IsRemote
        );
    }
}
