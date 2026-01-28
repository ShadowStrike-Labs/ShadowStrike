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
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_FS_CALLBACKS_H
#define SHADOWSTRIKE_FS_CALLBACKS_H

#include <fltKernel.h>

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

#endif // SHADOWSTRIKE_FS_CALLBACKS_H
