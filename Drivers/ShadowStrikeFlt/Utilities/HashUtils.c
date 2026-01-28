/**
 * ============================================================================
 * ShadowStrike NGAV - KERNEL HASHING UTILITIES
 * ============================================================================
 *
 * @file HashUtils.c
 * @brief Implementation of CNG wrappers for SHA-256.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "HashUtils.h"
#include "MemoryUtils.h"

//
// Handle to the algorithm provider
//
static BCRYPT_ALG_HANDLE g_hAlgSha256 = NULL;
static ULONG g_cbHashObject = 0;

NTSTATUS
ShadowStrikeInitializeHashUtils(
    VOID
    )
{
    NTSTATUS Status;
    ULONG ResultLength = 0;

    if (g_hAlgSha256 != NULL) {
        return STATUS_SUCCESS;
    }

    Status = BCryptOpenAlgorithmProvider(&g_hAlgSha256,
                                       BCRYPT_SHA256_ALGORITHM,
                                       NULL,
                                       BCRYPT_PROV_DISPATCH);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = BCryptGetProperty(g_hAlgSha256,
                             BCRYPT_OBJECT_LENGTH,
                             (PUCHAR)&g_cbHashObject,
                             sizeof(ULONG),
                             &ResultLength,
                             0);

    if (!NT_SUCCESS(Status)) {
        BCryptCloseAlgorithmProvider(g_hAlgSha256, 0);
        g_hAlgSha256 = NULL;
    }

    return Status;
}

VOID
ShadowStrikeCleanupHashUtils(
    VOID
    )
{
    if (g_hAlgSha256) {
        BCryptCloseAlgorithmProvider(g_hAlgSha256, 0);
        g_hAlgSha256 = NULL;
    }
}

NTSTATUS
ShadowStrikeComputeSha256(
    _In_ PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_(SHA256_HASH_SIZE) PUCHAR Hash
    )
{
    NTSTATUS Status;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PUCHAR pbHashObject = NULL;

    if (g_hAlgSha256 == NULL) {
        Status = ShadowStrikeInitializeHashUtils();
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    pbHashObject = ShadowStrikeAllocate(g_cbHashObject);
    if (pbHashObject == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = BCryptCreateHash(g_hAlgSha256,
                            &hHash,
                            pbHashObject,
                            g_cbHashObject,
                            NULL,
                            0,
                            0);

    if (NT_SUCCESS(Status)) {
        Status = BCryptHashData(hHash,
                              (PUCHAR)Buffer,
                              Length,
                              0);
    }

    if (NT_SUCCESS(Status)) {
        Status = BCryptFinishHash(hHash,
                                Hash,
                                SHA256_HASH_SIZE,
                                0);
    }

    if (hHash) {
        BCryptDestroyHash(hHash);
    }

    if (pbHashObject) {
        ShadowStrikeFreePool(pbHashObject);
    }

    return Status;
}
