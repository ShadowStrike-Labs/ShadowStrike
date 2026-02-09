/**
 * ============================================================================
 * ShadowStrike NGAV - FILTER REGISTRATION
 * ============================================================================
 *
 * @file FilterRegistration.h
 * @brief Minifilter registration structures and callback declarations.
 *
 * Defines the FLT_REGISTRATION structure and all callback function prototypes
 * for file system filtering operations.
 *
 * THREAD SAFETY:
 * - All callbacks are inherently thread-safe (called by Filter Manager)
 * - Global state access is synchronized via g_DriverData locks
 * - Context access uses ERESOURCE locks from StreamContext module
 *
 * IRQL REQUIREMENTS:
 * - Instance callbacks: PASSIVE_LEVEL (pageable)
 * - Pre-operation callbacks: <= APC_LEVEL
 * - Post-operation callbacks: <= APC_LEVEL (may be DISPATCH for draining)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_FILTER_REGISTRATION_H
#define SHADOWSTRIKE_FILTER_REGISTRATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include "../Context/StreamContext.h"

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for deferred work items: 'xSWk' = ShadowStrike Work
 */
#define SHADOW_WORK_ITEM_TAG        'kWSx'

/**
 * @brief Pool tag for context allocations: 'xSCx' = ShadowStrike Context
 */
#define SHADOW_CONTEXT_TAG          'xCSx'

// ============================================================================
// DEFERRED WORK CONTEXT
// ============================================================================

/**
 * @brief Context for deferred post-operation processing.
 *
 * Used when post-operation callbacks need to perform work at PASSIVE_LEVEL
 * but were called at elevated IRQL or during draining.
 */
typedef struct _SHADOW_DEFERRED_SCAN_CONTEXT {
    /**
     * @brief Work item for deferred processing.
     */
    PFLT_DEFERRED_IO_WORKITEM WorkItem;

    /**
     * @brief Filter instance handle.
     */
    PFLT_INSTANCE Instance;

    /**
     * @brief File object for the operation.
     */
    PFILE_OBJECT FileObject;

    /**
     * @brief Cached file name (allocated copy).
     */
    UNICODE_STRING FileName;

    /**
     * @brief File size for scan decision.
     */
    LARGE_INTEGER FileSize;

    /**
     * @brief Access type for scan request.
     */
    ULONG AccessType;

    /**
     * @brief Process ID of requestor.
     */
    HANDLE ProcessId;

    /**
     * @brief TRUE if this is an execute access.
     */
    BOOLEAN IsExecute;

    /**
     * @brief Reserved for alignment.
     */
    BOOLEAN Reserved[7];

} SHADOW_DEFERRED_SCAN_CONTEXT, *PSHADOW_DEFERRED_SCAN_CONTEXT;

// ============================================================================
// SCANNABLE EXTENSION TABLE
// ============================================================================

/**
 * @brief Maximum extension length we check (in characters).
 */
#define SHADOW_MAX_EXTENSION_LENGTH     8

/**
 * @brief Entry in scannable extensions table.
 */
typedef struct _SHADOW_EXTENSION_ENTRY {
    PCWSTR Extension;
    USHORT Length;          // In bytes, not including null
    BOOLEAN IsExecutable;   // TRUE if this can be directly executed
    BOOLEAN IsScript;       // TRUE if this is a script file
} SHADOW_EXTENSION_ENTRY, *PSHADOW_EXTENSION_ENTRY;

// ============================================================================
// FILTER REGISTRATION STRUCTURE
// ============================================================================

/**
 * @brief Get the filter registration structure.
 *
 * @return Pointer to the global FLT_REGISTRATION structure.
 *
 * @irql Any
 */
CONST PFLT_REGISTRATION
ShadowStrikeGetFilterRegistration(
    VOID
    );

// ============================================================================
// INSTANCE CALLBACKS
// ============================================================================

/**
 * @brief Instance setup callback.
 *
 * Called when the filter is being attached to a volume. Determines whether
 * to attach based on volume type and characteristics.
 *
 * @param FltObjects       Filter objects for this instance.
 * @param Flags            Reason for the setup call.
 * @param VolumeDeviceType Device type of the volume.
 * @param VolumeFilesystemType Filesystem type.
 * @return STATUS_SUCCESS to attach, STATUS_FLT_DO_NOT_ATTACH to skip.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

/**
 * @brief Instance query teardown callback.
 *
 * Called when a volume is about to be detached. Allows the filter
 * to prevent detachment if operations are in progress.
 *
 * @param FltObjects  Filter objects for this instance.
 * @param Flags       Reason for the teardown query.
 * @return STATUS_SUCCESS to allow detachment, STATUS_FLT_DO_NOT_DETACH to deny.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

/**
 * @brief Instance teardown start callback.
 *
 * Called when instance teardown begins. Should stop accepting new work.
 *
 * @param FltObjects  Filter objects for this instance.
 * @param Flags       Reason for the teardown.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

/**
 * @brief Instance teardown complete callback.
 *
 * Called when instance teardown is complete. Final cleanup opportunity.
 *
 * @param FltObjects  Filter objects for this instance.
 * @param Flags       Reason for the teardown.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

// ============================================================================
// IRP_MJ_CREATE CALLBACKS
// ============================================================================

/**
 * @brief Pre-create callback.
 *
 * Called before a file is opened. Primary trigger for self-protection checks.
 * Must complete quickly or defer to post-create.
 *
 * @param Data        Callback data for this operation.
 * @param FltObjects  Filter objects for this operation.
 * @param CompletionContext  Context passed to post-operation callback.
 * @return FLT_PREOP_SUCCESS_WITH_CALLBACK to receive post-create,
 *         FLT_PREOP_SUCCESS_NO_CALLBACK to skip post-create,
 *         FLT_PREOP_COMPLETE to complete the operation immediately.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

/**
 * @brief Post-create callback.
 *
 * Called after a file is opened. Has access to file size, attributes,
 * and can initiate scanning with full file access.
 *
 * NOTE: If called at elevated IRQL, work is deferred via work item.
 *
 * @param Data        Callback data for this operation.
 * @param FltObjects  Filter objects for this operation.
 * @param CompletionContext  Context from pre-operation callback.
 * @param Flags       Post-operation flags.
 * @return FLT_POSTOP_FINISHED_PROCESSING or FLT_POSTOP_MORE_PROCESSING_REQUIRED.
 *
 * @irql <= APC_LEVEL (may be DISPATCH_LEVEL if draining)
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

// ============================================================================
// IRP_MJ_WRITE CALLBACKS
// ============================================================================

/**
 * @brief Pre-write callback.
 *
 * Called before a write operation. Used for self-protection enforcement
 * and monitoring file modifications.
 *
 * @param Data        Callback data for this operation.
 * @param FltObjects  Filter objects for this operation.
 * @param CompletionContext  Context passed to post-operation callback.
 * @return FLT_PREOP_SUCCESS_WITH_CALLBACK to receive post-write,
 *         FLT_PREOP_COMPLETE to block the write.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

/**
 * @brief Post-write callback.
 *
 * Called after a write completes. Marks file as modified for rescan.
 *
 * @param Data        Callback data for this operation.
 * @param FltObjects  Filter objects for this operation.
 * @param CompletionContext  Context from pre-operation callback.
 * @param Flags       Post-operation flags.
 * @return FLT_POSTOP_FINISHED_PROCESSING.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

// ============================================================================
// IRP_MJ_SET_INFORMATION CALLBACKS
// ============================================================================

/**
 * @brief Pre-set-information callback.
 *
 * Called before file information is changed. Intercepts rename and delete
 * operations for self-protection and monitoring.
 *
 * @param Data        Callback data for this operation.
 * @param FltObjects  Filter objects for this operation.
 * @param CompletionContext  Context passed to post-operation callback.
 * @return FLT_PREOP_SUCCESS_WITH_CALLBACK or FLT_PREOP_COMPLETE.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

/**
 * @brief Post-set-information callback.
 *
 * Called after file information is changed. Sends notifications for
 * rename/delete operations.
 *
 * @param Data        Callback data for this operation.
 * @param FltObjects  Filter objects for this operation.
 * @param CompletionContext  Context from pre-operation callback.
 * @param Flags       Post-operation flags.
 * @return FLT_POSTOP_FINISHED_PROCESSING.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

// ============================================================================
// IRP_MJ_CLEANUP CALLBACKS
// ============================================================================

/**
 * @brief Pre-cleanup callback.
 *
 * Called when the last handle to a file is closed. Used to trigger
 * rescan of modified files.
 *
 * @param Data        Callback data for this operation.
 * @param FltObjects  Filter objects for this operation.
 * @param CompletionContext  Context passed to post-operation callback.
 * @return FLT_PREOP_SUCCESS_NO_CALLBACK.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

// ============================================================================
// SECTION SYNCHRONIZATION CALLBACKS
// ============================================================================

/**
 * @brief Pre-acquire-for-section-synchronization callback.
 *
 * Called when a file is being mapped for execution. Critical trigger
 * for scanning before code execution.
 *
 * NOTE: This callback uses cached verdicts only to avoid blocking.
 * New scans are queued asynchronously.
 *
 * @param Data        Callback data for this operation.
 * @param FltObjects  Filter objects for this operation.
 * @param CompletionContext  Context passed to post-operation callback.
 * @return FLT_PREOP_SUCCESS_NO_CALLBACK or FLT_PREOP_COMPLETE.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreAcquireForSectionSync(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Check if file extension is scannable.
 *
 * @param Extension  File extension to check (without dot).
 * @param IsExecutable  Receives TRUE if extension is directly executable.
 *
 * @return TRUE if file should be scanned.
 *
 * @irql Any
 */
BOOLEAN
ShadowStrikeIsScannable(
    _In_ PCUNICODE_STRING Extension,
    _Out_opt_ PBOOLEAN IsExecutable
    );

/**
 * @brief Queue file for asynchronous rescan.
 *
 * Used when a modified file needs rescanning but we cannot block.
 *
 * @param Instance    Filter instance.
 * @param FileObject  File object.
 * @param FileName    File name for logging.
 *
 * @return STATUS_SUCCESS if queued, error otherwise.
 *
 * @irql <= APC_LEVEL
 */
NTSTATUS
ShadowStrikeQueueRescan(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ PCUNICODE_STRING FileName
    );

/**
 * @brief Deferred scan worker function.
 *
 * Called from work item to perform scan at PASSIVE_LEVEL.
 *
 * @param WorkItem    Work item.
 * @param Context     SHADOW_DEFERRED_SCAN_CONTEXT.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeDeferredScanWorker(
    _In_ PFLT_DEFERRED_IO_WORKITEM WorkItem,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PVOID Context
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_FILTER_REGISTRATION_H
