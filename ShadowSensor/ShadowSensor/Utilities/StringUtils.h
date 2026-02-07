/**
 * ============================================================================
 * ShadowStrike NGAV - STRING UTILITIES
 * ============================================================================
 *
 * @file StringUtils.h
 * @brief Safe string manipulation wrappers.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_STRING_UTILS_H_
#define _SHADOWSTRIKE_STRING_UTILS_H_

#include <fltKernel.h>

//
// Function Prototypes
//

NTSTATUS
ShadowStrikeCopyUnicodeString(
    _Inout_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    );

NTSTATUS
ShadowStrikeAppendUnicodeString(
    _Inout_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    );

NTSTATUS
ShadowStrikeCloneUnicodeString(
    _Out_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    );

VOID
ShadowStrikeFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
    );

BOOLEAN
ShadowStrikeIsStringMatch(
    _In_ PCUNICODE_STRING String1,
    _In_ PCUNICODE_STRING String2,
    _In_ BOOLEAN CaseInSensitive
    );

#endif // _SHADOWSTRIKE_STRING_UTILS_H_
