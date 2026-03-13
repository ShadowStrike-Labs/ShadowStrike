/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - FILE SYSTEM CALLBACKS HEADER
 * ============================================================================
 *
 * @file FileSystemCallbacks.h
 * @brief Prototypes for Minifilter file system callbacks.
 *
 * Handles:
 * - IRP_MJ_CREATE (File open/create) - MAIN SCAN TRIGGER
 * - IRP_MJ_WRITE (File write) - Change detection
 * - IRP_MJ_SET_INFORMATION (Delete/Rename) - Self-protection
 * - IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION (Execute)
 * - IRP_MJ_CREATE_NAMED_PIPE (Named pipe monitoring)
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_FS_CALLBACKS_H
#define SHADOWSTRIKE_FS_CALLBACKS_H

#pragma warning(push)
#pragma warning(disable:4324)  // structure padded due to alignment specifier
#include <fltKernel.h>
#pragma warning(pop)

// ============================================================================
// LIFECYCLE
// ============================================================================

/**
 * @brief Initialize the filesystem callback subsystem.
 * @return STATUS_SUCCESS on success, STATUS_ALREADY_REGISTERED if already initialized.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeInitializeFileSystemCallbacks(
    VOID
    );

/**
 * @brief Shutdown and cleanup the filesystem callback subsystem.
 *        Waits for all in-flight operations via rundown protection.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeCleanupFileSystemCallbacks(
    VOID
    );

// ============================================================================
// INSTANCE CALLBACKS
// ============================================================================

/**
 * @brief Instance setup callback — decides whether to attach to a volume.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

/**
 * @brief Instance query teardown callback — allows manual detachment.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

/**
 * @brief Instance teardown start callback — marks volume as detaching.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
    );

/**
 * @brief Instance teardown complete callback — final cleanup for volume.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
    );

// ============================================================================
// CONTEXT CLEANUP CALLBACKS
// ============================================================================

/**
 * @brief Cleanup callback for stream contexts.
 */
VOID
ShadowStrikeStreamContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    );

/**
 * @brief Cleanup callback for stream handle contexts.
 */
VOID
ShadowStrikeStreamHandleContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    );

/**
 * @brief Cleanup callback for volume contexts.
 */
VOID
ShadowStrikeVolumeContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    );

// ============================================================================
// CALLBACK PROTOTYPES
// ============================================================================

/**
 * @brief Pre-operation callback for IRP_MJ_CREATE.
 *        This is the primary entry point for on-access scanning.
 */
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

/**
 * @brief Post-operation callback for IRP_MJ_CREATE.
 *        Used to track successful opens and attach contexts.
 */
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

/**
 * @brief Pre-operation callback for IRP_MJ_WRITE.
 *        Detects modification of files to invalidate cache/re-scan.
 */
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

/**
 * @brief Post-operation callback for IRP_MJ_WRITE.
 *        Handles cache invalidation, ransomware detection, and telemetry.
 */
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

/**
 * @brief Pre-operation callback for IRP_MJ_SET_INFORMATION.
 *        Handles file deletion and renaming (Self-Protection).
 */
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

/**
 * @brief Pre-operation callback for Section Synchronization.
 *        Detects execution (memory mapping as image).
 */
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreAcquireSection(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

/**
 * @brief Initialize PreAcquireSection subsystem (lookaside, hash table, timers).
 */
NTSTATUS
ShadowStrikePreAcquireSectionInitialize(VOID);

/**
 * @brief Shutdown PreAcquireSection subsystem (drain resources, cancel timers).
 */
VOID
ShadowStrikePreAcquireSectionShutdown(VOID);

/**
 * @brief Remove mapping context on process exit (call from ProcessNotify).
 */
VOID
ShadowStrikeRemoveProcessMappingContext(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Pre-operation callback for IRP_MJ_CREATE_NAMED_PIPE.
 *        Detects C2 channel and lateral movement pipe creation.
 */
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreCreateNamedPipe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

/**
 * @brief Post-operation callback for IRP_MJ_CREATE_NAMED_PIPE.
 *        Records successfully created pipes for tracking.
 */
FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostCreateNamedPipe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

// ============================================================================
// PUBLIC STATISTICS / QUERY API
// ============================================================================

/**
 * @brief Retrieves filesystem callback statistics.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeGetFileSystemStats(
    _Out_opt_ PULONG64 PreCreateCalls,
    _Out_opt_ PULONG64 FilesBlocked,
    _Out_opt_ PULONG64 RansomwareDetections,
    _Out_opt_ PULONG VolumeCount
    );

/**
 * @brief Queries file operation context for a process.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ShadowStrikeQueryProcessFileContext(
    _In_ HANDLE ProcessId,
    _Out_opt_ PBOOLEAN IsRansomwareSuspect,
    _Out_opt_ PULONG SuspicionScore,
    _Out_opt_ PULONG BehaviorFlags
    );

/**
 * @brief External API to notify of file operations (cross-module integration).
 */
VOID
ShadowStrikeNotifyProcessFileOperation(
    _In_ HANDLE ProcessId,
    _In_ ULONG OperationType,
    _In_opt_ PCUNICODE_STRING FileName
    );

#endif // SHADOWSTRIKE_FS_CALLBACKS_H
