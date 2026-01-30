#include "ImageNotify.h"
#include "../../Core/Globals.h"
#include "../../Communication/ScanBridge.h"

//
// Global flag to track if the callback is registered
//
static BOOLEAN g_ImageNotifyRegistered = FALSE;

//
// Forward declaration
//
VOID
ImageLoadNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    );

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, RegisterImageNotify)
#pragma alloc_text(PAGE, UnregisterImageNotify)
#pragma alloc_text(PAGE, ImageLoadNotifyRoutine)
#endif

_Use_decl_annotations_
NTSTATUS
RegisterImageNotify(
    VOID
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (g_ImageNotifyRegistered) {
        return STATUS_SUCCESS;
    }

    status = PsSetLoadImageNotifyRoutine(ImageLoadNotifyRoutine);

    if (NT_SUCCESS(status)) {
        g_ImageNotifyRegistered = TRUE;
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS
UnregisterImageNotify(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    if (g_ImageNotifyRegistered) {
        status = PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyRoutine);
        if (NT_SUCCESS(status)) {
            g_ImageNotifyRegistered = FALSE;
        }
    }

    return status;
}

//
// Routine Description:
//    Callback routine invoked when an image is loaded.
//
// Arguments:
//    FullImageName - The name of the image being loaded.
//    ProcessId - The process ID where the image is loaded.
//    ImageInfo - Information about the image.
//
// Return Value:
//    None
//
VOID
ImageLoadNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    PAGED_CODE();

    //
    // Check if driver is ready to process requests
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        return;
    }

    //
    // Filter out minimal events to reduce noise if needed.
    // For now, we forward everything to user mode for visibility.
    //
    // Note: FullImageName can be NULL.
    // ProcessId is 0 for driver loads.
    //

    // We are interested in:
    // 1. Unsigned drivers (ProcessId == 0)
    // 2. Unsigned DLLs loaded into critical processes
    // 3. DLLs loaded from suspicious locations (Temp, etc.) - User mode can decide this based on path.

    if (ImageInfo) {
        // Send notification to user mode
        ShadowStrikeSendImageNotification(
            ProcessId,
            FullImageName,
            ImageInfo
        );
    }
}
