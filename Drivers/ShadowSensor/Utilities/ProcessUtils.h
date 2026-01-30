/**
 * ============================================================================
 * ShadowStrike NGAV - PROCESS UTILITIES
 * ============================================================================
 *
 * @file ProcessUtils.h
 * @brief Helper functions for process information retrieval.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_PROCESS_UTILS_H_
#define _SHADOWSTRIKE_PROCESS_UTILS_H_

#include <fltKernel.h>

//
// Function Prototypes
//

NTSTATUS
ShadowStrikeGetProcessImageName(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING ProcessName
    );

NTSTATUS
ShadowStrikeGetProcessIdFromHandle(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE ProcessId
    );

BOOLEAN
ShadowStrikeIsProcessTerminating(
    _In_ PEPROCESS Process
    );

#endif // _SHADOWSTRIKE_PROCESS_UTILS_H_
