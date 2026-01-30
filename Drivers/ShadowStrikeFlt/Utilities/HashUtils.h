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

/**
 * @brief Initialize the hashing subsystem.
 *
 * Opens the CNG SHA-256 algorithm provider. Must be called before
 * any hashing operations.
 *
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeInitializeHashUtils(
    VOID
    );

/**
 * @brief Cleanup the hashing subsystem.
 *
 * Closes the CNG algorithm provider. Call during driver unload.
 */
VOID
ShadowStrikeCleanupHashUtils(
    VOID
    );

/**
 * @brief Compute SHA-256 hash of a buffer.
 *
 * @param Buffer Pointer to data to hash.
 * @param Length Size of data in bytes.
 * @param Hash   Receives the 32-byte hash.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeComputeSha256(
    _In_ PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_(SHA256_HASH_SIZE) PUCHAR Hash
    );

/**
 * @brief Compute SHA-256 hash of a file.
 *
 * Reads the file in chunks and computes a streaming hash.
 * Suitable for large files without loading entire content into memory.
 *
 * @param Instance     Filter instance.
 * @param FileObject   File object to hash.
 * @param Hash         Receives the 32-byte hash.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeComputeFileHash(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_writes_(SHA256_HASH_SIZE) PUCHAR Hash
    );

#endif // _SHADOWSTRIKE_HASH_UTILS_H_
