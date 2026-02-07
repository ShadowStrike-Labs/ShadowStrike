/**
 * ============================================================================
 * ShadowStrike NGAV - STRING UTILITIES
 * ============================================================================
 *
 * @file StringUtils.c
 * @brief Implementation of safe string manipulation wrappers.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "StringUtils.h"
#include "MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeCopyUnicodeString)
#pragma alloc_text(PAGE, ShadowStrikeCloneUnicodeString)
#pragma alloc_text(PAGE, ShadowStrikeFreeUnicodeString)
#pragma alloc_text(PAGE, ShadowStrikeIsStringMatch)
#endif

NTSTATUS
ShadowStrikeCopyUnicodeString(
    _Inout_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    )
{
    PAGED_CODE();

    if (Destination->MaximumLength < Source->Length) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyUnicodeString(Destination, Source);
    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeAppendUnicodeString(
    _Inout_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    )
{
    // Can be called at dispatch level if buffers are non-paged
    return RtlAppendUnicodeStringToString(Destination, Source);
}

NTSTATUS
ShadowStrikeCloneUnicodeString(
    _Out_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    )
{
    PAGED_CODE();

    Destination->Buffer = NULL;
    Destination->Length = 0;
    Destination->MaximumLength = 0;

    if (Source == NULL || Source->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate buffer
    Destination->Buffer = ShadowStrikeAllocatePaged(Source->Length + sizeof(WCHAR));
    if (Destination->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Destination->MaximumLength = Source->Length + sizeof(WCHAR);
    RtlCopyUnicodeString(Destination, Source);

    // Ensure null termination just in case
    Destination->Buffer[Destination->Length / sizeof(WCHAR)] = L'\0';

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
    )
{
    PAGED_CODE();

    if (String->Buffer) {
        ShadowStrikeFreePool(String->Buffer);
        String->Buffer = NULL;
    }
    String->Length = 0;
    String->MaximumLength = 0;
}

BOOLEAN
ShadowStrikeIsStringMatch(
    _In_ PCUNICODE_STRING String1,
    _In_ PCUNICODE_STRING String2,
    _In_ BOOLEAN CaseInSensitive
    )
{
    PAGED_CODE();

    if (String1 == NULL || String2 == NULL) {
        return FALSE;
    }

    return RtlEqualUnicodeString(String1, String2, CaseInSensitive);
}
