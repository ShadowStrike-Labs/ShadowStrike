/**
 * ============================================================================
 * ShadowStrike NGAV - KERNEL HASHING UTILITIES
 * ============================================================================
 *
 * @file HashUtils.h
 * @brief CNG (Cryptography API: Next Generation) wrappers for kernel mode.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_HASH_UTILS_H_
#define _SHADOWSTRIKE_HASH_UTILS_H_

#include <fltKernel.h>
#include <bcrypt.h>

#define SHA256_HASH_SIZE 32

//
// Function Prototypes
//

NTSTATUS
ShadowStrikeComputeSha256(
    _In_ PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_(SHA256_HASH_SIZE) PUCHAR Hash
    );

#endif // _SHADOWSTRIKE_HASH_UTILS_H_
