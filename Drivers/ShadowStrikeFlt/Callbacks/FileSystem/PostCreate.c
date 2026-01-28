/**
 * ============================================================================
 * ShadowStrike NGAV - POST-CREATE CALLBACK
 * ============================================================================
 *
 * @file PostCreate.c
 * @brief Handles post-creation logic (context attachment).
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "FileSystemCallbacks.h"
#include "../../Core/Globals.h"

FLT_POSTOP_CALLBACK_STATUS
ShadowStrikePostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    //
    // If the create succeeded, we might want to attach a Stream Context
    // to track this file handle for future operations (like Writes).
    //

    return FLT_POSTOP_FINISHED_PROCESSING;
}
