/**
 * ============================================================================
 * ShadowStrike NGAV - STREAM CONTEXT MANAGER
 * ============================================================================
 *
 * @file StreamContext.h
 * @brief Per-file context management for the Minifilter.
 *
 * This context is attached to the File Stream. It persists as long as there
 * is at least one open handle to the file object. It is used to cache
 * scan verdicts, prevent re-scanning, and track file modification state.
 *
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_STREAM_CONTEXT_H
#define SHADOWSTRIKE_STREAM_CONTEXT_H

#include <fltKernel.h>

//
// Context structure layout
//
typedef struct _SHADOW_STREAM_CONTEXT {
    //
    // Synchronization
    //
    ERESOURCE Resource;

    //
    // File Identity
    //
    UNICODE_STRING FileName;
    LARGE_INTEGER FileId;

    //
    // Scan State
    //
    BOOLEAN Scanned;
    BOOLEAN IsMalware;
    NTSTATUS ScanStatus;
    LARGE_INTEGER LastScanTime;
    
    //
    // Modification State
    //
    BOOLEAN Modified;
    ULONG WriteCount;

} SHADOW_STREAM_CONTEXT, *PSHADOW_STREAM_CONTEXT;

//
// Function Prototypes
//

NTSTATUS
ShadowCreateStreamContext(
    _In_ PFLT_FILTER Filter,
    _Out_ PSHADOW_STREAM_CONTEXT *Context
    );

NTSTATUS
ShadowGetStreamContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PSHADOW_STREAM_CONTEXT *Context
    );

VOID
ShadowCleanupStreamContext(
    _In_ PSHADOW_STREAM_CONTEXT Context
    );

#endif // SHADOWSTRIKE_STREAM_CONTEXT_H
