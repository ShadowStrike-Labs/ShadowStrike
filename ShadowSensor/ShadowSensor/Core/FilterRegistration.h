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
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_FILTER_REGISTRATION_H
#define SHADOWSTRIKE_FILTER_REGISTRATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include "../Shared/SharedDefs.h"
#include "StreamContext.h"

// ============================================================================
// FILTER REGISTRATION STRUCTURE
// ============================================================================

/**
 * @brief Get the filter registration structure.
 *
 * @return Pointer to the global FLT_REGISTRATION structure.
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
 */
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
 * @return STATUS_SUCCESS to allow detachment.
 */
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
 */
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
 */
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
 * Called before a file is opened. Primary trigger for file scanning.
 * Must complete quickly or defer to post-create.
 *
 * @param Data        Callback data for this operation.
 * @param FltObjects  Filter objects for this operation.
 * @param CompletionContext  Context passed to post-operation callback.
 * @return FLT_PREOP_SUCCESS_WITH_CALLBACK to receive post-create,
 *         FLT_PREOP_SUCCESS_NO_CALLBACK to skip post-create,
 *         FLT_PREOP_COMPLETE to complete the operation immediately.
 */
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
 * @param Data        Callback data for this operation.
 * @param FltObjects  Filter objects for this operation.
 * @param CompletionContext  Context from pre-operation callback.
 * @param Flags       Post-operation flags.
 * @return FLT_POSTOP_FINISHED_PROCESSING.
 */
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
 * Called before a write operation. Used for monitoring file modifications.
 *
 * @param Data        Callback data for this operation.
 * @param FltObjects  Filter objects for this operation.
 * @param CompletionContext  Context passed to post-operation callback.
 * @return FLT_PREOP_SUCCESS_WITH_CALLBACK to receive post-write.
 */
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

/**
 * @brief Post-write callback.
 *
 * Called after a write completes. Triggers rescan if file content changed.
 *
 * @param Data        Callback data for this operation.
 * @param FltObjects  Filter objects for this operation.
 * @param CompletionContext  Context from pre-operation callback.
 * @param Flags       Post-operation flags.
 * @return FLT_POSTOP_FINISHED_PROCESSING.
 */
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
 */
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

/**
 * @brief Post-set-information callback.
 *
 * Called after file information is changed.
 *
 * @param Data        Callback data for this operation.
 * @param FltObjects  Filter objects for this operation.
 * @param CompletionContext  Context from pre-operation callback.
 * @param Flags       Post-operation flags.
 * @return FLT_POSTOP_FINISHED_PROCESSING.
 */
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
 */
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
 * @param Data        Callback data for this operation.
 * @param FltObjects  Filter objects for this operation.
 * @param CompletionContext  Context passed to post-operation callback.
 * @return FLT_PREOP_SUCCESS_WITH_CALLBACK or FLT_PREOP_COMPLETE.
 */
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreAcquireForSectionSync(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_FILTER_REGISTRATION_H
