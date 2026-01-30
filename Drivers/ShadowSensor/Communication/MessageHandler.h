/**
 * ============================================================================
 * ShadowStrike NGAV - MESSAGE HANDLER HEADER
 * ============================================================================
 *
 * @file MessageHandler.h
 * @brief Dispatch logic for user-mode messages.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_MESSAGE_HANDLER_H_
#define _SHADOWSTRIKE_MESSAGE_HANDLER_H_

#include <fltKernel.h>
#include "../Core/Globals.h"

//
// Function Prototypes
//

NTSTATUS
ShadowStrikeProcessUserMessage(
    _In_ PSHADOWSTRIKE_CLIENT_PORT ClientContext,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );

#endif // _SHADOWSTRIKE_MESSAGE_HANDLER_H_
