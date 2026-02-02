/**
 * ============================================================================
 * ShadowStrike NGAV - STREAM CONTEXT IMPLEMENTATION
 * ============================================================================
 */

#include "StreamContext.h"
#include "../../Core/Globals.h"

NTSTATUS
ShadowCreateStreamContext(
    _In_ PFLT_FILTER Filter,
    _Out_ PSHADOW_STREAM_CONTEXT *Context
    )
{
    NTSTATUS status;
    PSHADOW_STREAM_CONTEXT ctx = NULL;

    //
    // Allocate context from Filter Manager
    //
    status = FltAllocateContext(
        Filter,
        FLT_STREAM_CONTEXT,
        sizeof(SHADOW_STREAM_CONTEXT),
        PagedPool,
        (PFLT_CONTEXT*)&ctx
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Initialize structure
    //
    RtlZeroMemory(ctx, sizeof(SHADOW_STREAM_CONTEXT));
    ExInitializeResourceLite(&ctx->Resource);

    *Context = ctx;
    return STATUS_SUCCESS;
}

NTSTATUS
ShadowGetStreamContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PSHADOW_STREAM_CONTEXT *Context
    )
{
    // Stub: Get context from FM
    return STATUS_NOT_IMPLEMENTED;
}

VOID
ShadowCleanupStreamContext(
    _In_ PSHADOW_STREAM_CONTEXT Context
    )
{
    if (Context) {
        ExDeleteResourceLite(&Context->Resource);
        // String cleanup would go here
    }
}
