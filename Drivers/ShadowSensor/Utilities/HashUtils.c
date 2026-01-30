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

/**
 * @brief Compute SHA-256 hash of a file using streaming.
 *
 * Reads the file in 64KB chunks to avoid large memory allocations.
 * Handles files of any size efficiently.
 */
#define HASH_READ_CHUNK_SIZE (64 * 1024)

NTSTATUS
ShadowStrikeComputeFileHash(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_writes_(SHA256_HASH_SIZE) PUCHAR Hash
    )
{
    NTSTATUS Status;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PUCHAR pbHashObject = NULL;
    PUCHAR pbReadBuffer = NULL;
    LARGE_INTEGER ByteOffset;
    ULONG BytesRead;
    FILE_STANDARD_INFORMATION FileInfo;

    if (g_hAlgSha256 == NULL) {
        Status = ShadowStrikeInitializeHashUtils();
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    //
    // Get file size to validate and set reasonable limits
    //
    Status = FltQueryInformationFile(
        Instance,
        FileObject,
        &FileInfo,
        sizeof(FileInfo),
        FileStandardInformation,
        NULL
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Cap file size at 100MB for hashing to prevent DoS
    //
    if (FileInfo.EndOfFile.QuadPart > (100 * 1024 * 1024)) {
        return STATUS_FILE_TOO_LARGE;
    }

    //
    // Allocate hash object
    //
    pbHashObject = ShadowStrikeAllocate(g_cbHashObject);
    if (pbHashObject == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Allocate read buffer
    //
    pbReadBuffer = ShadowStrikeAllocate(HASH_READ_CHUNK_SIZE);
    if (pbReadBuffer == NULL) {
        ShadowStrikeFreePool(pbHashObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Create hash object
    //
    Status = BCryptCreateHash(
        g_hAlgSha256,
        &hHash,
        pbHashObject,
        g_cbHashObject,
        NULL,
        0,
        0
    );

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Read file in chunks and hash
    //
    ByteOffset.QuadPart = 0;

    while (ByteOffset.QuadPart < FileInfo.EndOfFile.QuadPart) {
        Status = FltReadFile(
            Instance,
            FileObject,
            &ByteOffset,
            HASH_READ_CHUNK_SIZE,
            pbReadBuffer,
            FLTFL_IO_OPERATION_NON_CACHED |
            FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
            &BytesRead,
            NULL,
            NULL
        );

        if (!NT_SUCCESS(Status)) {
            //
            // End of file is not an error
            //
            if (Status == STATUS_END_OF_FILE) {
                Status = STATUS_SUCCESS;
                break;
            }
            goto Cleanup;
        }

        if (BytesRead == 0) {
            break;
        }

        Status = BCryptHashData(hHash, pbReadBuffer, BytesRead, 0);
        if (!NT_SUCCESS(Status)) {
            goto Cleanup;
        }

        ByteOffset.QuadPart += BytesRead;
    }

    //
    // Finalize hash
    //
    Status = BCryptFinishHash(hHash, Hash, SHA256_HASH_SIZE, 0);

Cleanup:
    if (hHash) {
        BCryptDestroyHash(hHash);
    }
    if (pbReadBuffer) {
        ShadowStrikeFreePool(pbReadBuffer);
    }
    if (pbHashObject) {
        ShadowStrikeFreePool(pbHashObject);
    }

    return Status;
}
