/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE KERNEL HASHING UTILITIES
 * ============================================================================
 *
 * @file HashUtils.c
 * @brief Implementation of enterprise-grade cryptographic hashing for kernel-mode.
 *
 * This implementation provides:
 * - Thread-safe CNG algorithm provider management
 * - Streaming hash computation for memory-efficient large file hashing
 * - Constant-time hash comparison to prevent timing attacks
 * - Comprehensive statistics tracking for monitoring
 * - HMAC support for message authentication
 * - Multi-algorithm parallel hashing for threat intelligence
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "HashUtils.h"
#include "MemoryUtils.h"
#include "StringUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, ShadowStrikeInitializeHashUtils)
#pragma alloc_text(PAGE, ShadowStrikeCleanupHashUtils)
#pragma alloc_text(PAGE, ShadowStrikeComputeFileHash)
#pragma alloc_text(PAGE, ShadowStrikeComputeFileHashEx)
#pragma alloc_text(PAGE, ShadowStrikeComputeFileMultiHash)
#pragma alloc_text(PAGE, ShadowStrikeComputeFileHashByPath)
#pragma alloc_text(PAGE, ShadowStrikeSha256ToString)
#endif

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

/**
 * @brief Internal algorithm provider state
 */
typedef struct _SHADOWSTRIKE_HASH_PROVIDER {
    /// CNG algorithm handle
    BCRYPT_ALG_HANDLE AlgorithmHandle;

    /// Hash object size for this algorithm
    ULONG HashObjectSize;

    /// Hash output size for this algorithm
    ULONG HashSize;

    /// Is this provider initialized
    BOOLEAN Initialized;

    /// Reserved for alignment
    UCHAR Reserved[3];

} SHADOWSTRIKE_HASH_PROVIDER, *PSHADOWSTRIKE_HASH_PROVIDER;

/**
 * @brief Global hash subsystem state
 */
typedef struct _SHADOWSTRIKE_HASH_GLOBALS {
    /// Algorithm providers
    SHADOWSTRIKE_HASH_PROVIDER Providers[ShadowHashAlgorithmCount];

    /// HMAC-SHA256 provider
    BCRYPT_ALG_HANDLE HmacSha256Handle;
    ULONG HmacSha256ObjectSize;

    /// Subsystem initialization state
    volatile LONG InitializationCount;
    BOOLEAN Initialized;

    /// Synchronization
    EX_PUSH_LOCK InitLock;

    /// Statistics
    SHADOWSTRIKE_HASH_STATISTICS Statistics;

    /// Reserved
    UCHAR Reserved[4];

} SHADOWSTRIKE_HASH_GLOBALS, *PSHADOWSTRIKE_HASH_GLOBALS;

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief Global hash subsystem state (Meyers' singleton pattern)
 */
static SHADOWSTRIKE_HASH_GLOBALS g_HashGlobals = { 0 };

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Get CNG algorithm string for our algorithm enum
 */
static
PCWSTR
HashiGetCngAlgorithmString(
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm
    )
{
    switch (Algorithm) {
        case ShadowHashAlgorithmSha256:
            return BCRYPT_SHA256_ALGORITHM;
        case ShadowHashAlgorithmSha1:
            return BCRYPT_SHA1_ALGORITHM;
        case ShadowHashAlgorithmMd5:
            return BCRYPT_MD5_ALGORITHM;
        case ShadowHashAlgorithmSha512:
            return BCRYPT_SHA512_ALGORITHM;
        default:
            return NULL;
    }
}

/**
 * @brief Get algorithm provider handle
 */
static
BCRYPT_ALG_HANDLE
HashiGetAlgorithmHandle(
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm
    )
{
    if (Algorithm <= ShadowHashAlgorithmNone || Algorithm >= ShadowHashAlgorithmCount) {
        return NULL;
    }

    if (!g_HashGlobals.Providers[Algorithm].Initialized) {
        return NULL;
    }

    return g_HashGlobals.Providers[Algorithm].AlgorithmHandle;
}

/**
 * @brief Get hash object size for algorithm
 */
static
ULONG
HashiGetHashObjectSize(
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm
    )
{
    if (Algorithm <= ShadowHashAlgorithmNone || Algorithm >= ShadowHashAlgorithmCount) {
        return 0;
    }

    return g_HashGlobals.Providers[Algorithm].HashObjectSize;
}

/**
 * @brief Update statistics for operation start
 */
static
VOID
HashiEnterOperation(
    VOID
    )
{
    LONG Current;
    LONG Peak;

    InterlockedIncrement64(&g_HashGlobals.Statistics.TotalOperations);
    Current = InterlockedIncrement(&g_HashGlobals.Statistics.CurrentOperations);

    //
    // Update peak if current exceeds it (lock-free)
    //
    do {
        Peak = g_HashGlobals.Statistics.PeakOperations;
        if (Current <= Peak) {
            break;
        }
    } while (InterlockedCompareExchange(
        &g_HashGlobals.Statistics.PeakOperations,
        Current,
        Peak) != Peak);
}

/**
 * @brief Update statistics for operation completion
 */
static
VOID
HashiLeaveOperation(
    _In_ BOOLEAN Success,
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm,
    _In_ ULONG64 BytesHashed,
    _In_ BOOLEAN IsFileOperation
    )
{
    InterlockedDecrement(&g_HashGlobals.Statistics.CurrentOperations);

    if (Success) {
        InterlockedIncrement64(&g_HashGlobals.Statistics.SuccessfulOperations);
        InterlockedAdd64(&g_HashGlobals.Statistics.TotalBytesHashed, (LONG64)BytesHashed);
    } else {
        InterlockedIncrement64(&g_HashGlobals.Statistics.FailedOperations);
    }

    if (IsFileOperation) {
        InterlockedIncrement64(&g_HashGlobals.Statistics.FileHashOperations);
    } else {
        InterlockedIncrement64(&g_HashGlobals.Statistics.BufferHashOperations);
    }

    switch (Algorithm) {
        case ShadowHashAlgorithmSha256:
            InterlockedIncrement64(&g_HashGlobals.Statistics.Sha256Operations);
            break;
        case ShadowHashAlgorithmSha1:
            InterlockedIncrement64(&g_HashGlobals.Statistics.Sha1Operations);
            break;
        case ShadowHashAlgorithmMd5:
            InterlockedIncrement64(&g_HashGlobals.Statistics.Md5Operations);
            break;
        case ShadowHashAlgorithmSha512:
            InterlockedIncrement64(&g_HashGlobals.Statistics.Sha512Operations);
            break;
        default:
            break;
    }
}

/**
 * @brief Internal buffer hash implementation
 */
static
NTSTATUS
HashiComputeBufferHashInternal(
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(HashSize) PUCHAR Hash,
    _In_ ULONG HashSize
    )
{
    NTSTATUS Status;
    BCRYPT_ALG_HANDLE hAlgorithm;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PUCHAR pbHashObject = NULL;
    ULONG cbHashObject;
    ULONG ExpectedHashSize;

    //
    // Validate subsystem is initialized
    //
    if (!g_HashGlobals.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // Get algorithm handle
    //
    hAlgorithm = HashiGetAlgorithmHandle(Algorithm);
    if (hAlgorithm == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate hash size
    //
    ExpectedHashSize = ShadowStrikeGetHashSize(Algorithm);
    if (HashSize < ExpectedHashSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Get hash object size
    //
    cbHashObject = HashiGetHashObjectSize(Algorithm);
    if (cbHashObject == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // Allocate hash object from non-paged pool
    //
    pbHashObject = (PUCHAR)ShadowStrikeAllocateWithTag(cbHashObject, SHADOWSTRIKE_HASH_OBJ_TAG);
    if (pbHashObject == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Create hash object
    //
    Status = BCryptCreateHash(
        hAlgorithm,
        &hHash,
        pbHashObject,
        cbHashObject,
        NULL,
        0,
        0
    );

    if (!NT_SUCCESS(Status)) {
        InterlockedIncrement64(&g_HashGlobals.Statistics.CngErrors);
        goto Cleanup;
    }

    //
    // Hash the data
    //
    Status = BCryptHashData(
        hHash,
        (PUCHAR)Buffer,
        Length,
        0
    );

    if (!NT_SUCCESS(Status)) {
        InterlockedIncrement64(&g_HashGlobals.Statistics.CngErrors);
        goto Cleanup;
    }

    //
    // Finalize hash
    //
    Status = BCryptFinishHash(
        hHash,
        Hash,
        ExpectedHashSize,
        0
    );

    if (!NT_SUCCESS(Status)) {
        InterlockedIncrement64(&g_HashGlobals.Statistics.CngErrors);
    }

Cleanup:
    if (hHash != NULL) {
        BCryptDestroyHash(hHash);
    }

    if (pbHashObject != NULL) {
        //
        // Securely wipe hash object before freeing
        //
        ShadowStrikeSecureZeroMemory(pbHashObject, cbHashObject);
        ShadowStrikeFreePoolWithTag(pbHashObject, SHADOWSTRIKE_HASH_OBJ_TAG);
    }

    return Status;
}

/**
 * @brief Get current timestamp in microseconds
 */
static
ULONG64
HashiGetTimestampMicroseconds(
    VOID
    )
{
    LARGE_INTEGER PerformanceCounter;
    LARGE_INTEGER Frequency;

    PerformanceCounter = KeQueryPerformanceCounter(&Frequency);

    if (Frequency.QuadPart == 0) {
        return 0;
    }

    return (ULONG64)((PerformanceCounter.QuadPart * 1000000) / Frequency.QuadPart);
}

// ============================================================================
// SUBSYSTEM INITIALIZATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeInitializeHashUtils(
    VOID
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    NTSTATUS ProviderStatus;
    ULONG ResultLength = 0;
    SHADOWSTRIKE_HASH_ALGORITHM Algorithm;
    PCWSTR CngAlgorithmString;
    BOOLEAN AnyProviderInitialized = FALSE;

    PAGED_CODE();

    //
    // Use push lock for thread-safe initialization
    //
    ExAcquirePushLockExclusive(&g_HashGlobals.InitLock);

    //
    // Check if already initialized (reference counting)
    //
    if (InterlockedIncrement(&g_HashGlobals.InitializationCount) > 1) {
        ExReleasePushLockExclusive(&g_HashGlobals.InitLock);
        return STATUS_SUCCESS;
    }

    //
    // Zero out statistics
    //
    RtlZeroMemory(&g_HashGlobals.Statistics, sizeof(g_HashGlobals.Statistics));

    //
    // Initialize all algorithm providers
    //
    for (Algorithm = ShadowHashAlgorithmSha256;
         Algorithm < ShadowHashAlgorithmCount;
         Algorithm++) {

        CngAlgorithmString = HashiGetCngAlgorithmString(Algorithm);
        if (CngAlgorithmString == NULL) {
            continue;
        }

        //
        // Open algorithm provider with DISPATCH flag for kernel-mode use
        //
        ProviderStatus = BCryptOpenAlgorithmProvider(
            &g_HashGlobals.Providers[Algorithm].AlgorithmHandle,
            CngAlgorithmString,
            NULL,
            BCRYPT_PROV_DISPATCH
        );

        if (!NT_SUCCESS(ProviderStatus)) {
            g_HashGlobals.Providers[Algorithm].Initialized = FALSE;
            continue;
        }

        //
        // Get hash object size
        //
        ProviderStatus = BCryptGetProperty(
            g_HashGlobals.Providers[Algorithm].AlgorithmHandle,
            BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&g_HashGlobals.Providers[Algorithm].HashObjectSize,
            sizeof(ULONG),
            &ResultLength,
            0
        );

        if (!NT_SUCCESS(ProviderStatus)) {
            BCryptCloseAlgorithmProvider(
                g_HashGlobals.Providers[Algorithm].AlgorithmHandle,
                0
            );
            g_HashGlobals.Providers[Algorithm].AlgorithmHandle = NULL;
            g_HashGlobals.Providers[Algorithm].Initialized = FALSE;
            continue;
        }

        //
        // Get hash output size
        //
        ProviderStatus = BCryptGetProperty(
            g_HashGlobals.Providers[Algorithm].AlgorithmHandle,
            BCRYPT_HASH_LENGTH,
            (PUCHAR)&g_HashGlobals.Providers[Algorithm].HashSize,
            sizeof(ULONG),
            &ResultLength,
            0
        );

        if (!NT_SUCCESS(ProviderStatus)) {
            BCryptCloseAlgorithmProvider(
                g_HashGlobals.Providers[Algorithm].AlgorithmHandle,
                0
            );
            g_HashGlobals.Providers[Algorithm].AlgorithmHandle = NULL;
            g_HashGlobals.Providers[Algorithm].Initialized = FALSE;
            continue;
        }

        g_HashGlobals.Providers[Algorithm].Initialized = TRUE;
        AnyProviderInitialized = TRUE;
    }

    //
    // Initialize HMAC-SHA256 provider
    //
    ProviderStatus = BCryptOpenAlgorithmProvider(
        &g_HashGlobals.HmacSha256Handle,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_PROV_DISPATCH
    );

    if (NT_SUCCESS(ProviderStatus)) {
        BCryptGetProperty(
            g_HashGlobals.HmacSha256Handle,
            BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&g_HashGlobals.HmacSha256ObjectSize,
            sizeof(ULONG),
            &ResultLength,
            0
        );
    }

    //
    // Require at least SHA-256 to be available
    //
    if (!g_HashGlobals.Providers[ShadowHashAlgorithmSha256].Initialized) {
        Status = STATUS_UNSUCCESSFUL;
        goto CleanupOnFailure;
    }

    g_HashGlobals.Initialized = TRUE;
    ExReleasePushLockExclusive(&g_HashGlobals.InitLock);
    return STATUS_SUCCESS;

CleanupOnFailure:
    //
    // Cleanup on failure
    //
    for (Algorithm = ShadowHashAlgorithmSha256;
         Algorithm < ShadowHashAlgorithmCount;
         Algorithm++) {
        if (g_HashGlobals.Providers[Algorithm].AlgorithmHandle != NULL) {
            BCryptCloseAlgorithmProvider(
                g_HashGlobals.Providers[Algorithm].AlgorithmHandle,
                0
            );
            g_HashGlobals.Providers[Algorithm].AlgorithmHandle = NULL;
        }
        g_HashGlobals.Providers[Algorithm].Initialized = FALSE;
    }

    if (g_HashGlobals.HmacSha256Handle != NULL) {
        BCryptCloseAlgorithmProvider(g_HashGlobals.HmacSha256Handle, 0);
        g_HashGlobals.HmacSha256Handle = NULL;
    }

    InterlockedDecrement(&g_HashGlobals.InitializationCount);
    ExReleasePushLockExclusive(&g_HashGlobals.InitLock);
    return Status;
}

_Use_decl_annotations_
VOID
ShadowStrikeCleanupHashUtils(
    VOID
    )
{
    SHADOWSTRIKE_HASH_ALGORITHM Algorithm;

    PAGED_CODE();

    ExAcquirePushLockExclusive(&g_HashGlobals.InitLock);

    //
    // Reference counting - only cleanup when last reference released
    //
    if (InterlockedDecrement(&g_HashGlobals.InitializationCount) > 0) {
        ExReleasePushLockExclusive(&g_HashGlobals.InitLock);
        return;
    }

    //
    // Wait for outstanding operations to complete
    //
    while (g_HashGlobals.Statistics.CurrentOperations > 0) {
        LARGE_INTEGER Delay;
        Delay.QuadPart = -10000; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }

    //
    // Close all algorithm providers
    //
    for (Algorithm = ShadowHashAlgorithmSha256;
         Algorithm < ShadowHashAlgorithmCount;
         Algorithm++) {
        if (g_HashGlobals.Providers[Algorithm].AlgorithmHandle != NULL) {
            BCryptCloseAlgorithmProvider(
                g_HashGlobals.Providers[Algorithm].AlgorithmHandle,
                0
            );
            g_HashGlobals.Providers[Algorithm].AlgorithmHandle = NULL;
        }
        g_HashGlobals.Providers[Algorithm].Initialized = FALSE;
    }

    //
    // Close HMAC provider
    //
    if (g_HashGlobals.HmacSha256Handle != NULL) {
        BCryptCloseAlgorithmProvider(g_HashGlobals.HmacSha256Handle, 0);
        g_HashGlobals.HmacSha256Handle = NULL;
    }

    g_HashGlobals.Initialized = FALSE;

    ExReleasePushLockExclusive(&g_HashGlobals.InitLock);
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeIsHashUtilsInitialized(
    VOID
    )
{
    return g_HashGlobals.Initialized;
}

_Use_decl_annotations_
VOID
ShadowStrikeGetHashStatistics(
    _Out_ PSHADOWSTRIKE_HASH_STATISTICS Statistics
    )
{
    if (Statistics == NULL) {
        return;
    }

    RtlCopyMemory(Statistics, &g_HashGlobals.Statistics, sizeof(SHADOWSTRIKE_HASH_STATISTICS));
}

_Use_decl_annotations_
VOID
ShadowStrikeResetHashStatistics(
    VOID
    )
{
    LONG CurrentOps = g_HashGlobals.Statistics.CurrentOperations;
    LONG PeakOps = g_HashGlobals.Statistics.PeakOperations;

    RtlZeroMemory(&g_HashGlobals.Statistics, sizeof(SHADOWSTRIKE_HASH_STATISTICS));

    //
    // Preserve current/peak as they're still relevant
    //
    g_HashGlobals.Statistics.CurrentOperations = CurrentOps;
    g_HashGlobals.Statistics.PeakOperations = PeakOps;
}

// ============================================================================
// BUFFER HASHING
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeComputeSha256(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(SHA256_HASH_SIZE) PUCHAR Hash
    )
{
    NTSTATUS Status;

    if (Buffer == NULL || Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Length == 0) {
        //
        // Hash of empty input - compute it properly
        //
    }

    HashiEnterOperation();

    Status = HashiComputeBufferHashInternal(
        ShadowHashAlgorithmSha256,
        Buffer,
        Length,
        Hash,
        SHA256_HASH_SIZE
    );

    HashiLeaveOperation(NT_SUCCESS(Status), ShadowHashAlgorithmSha256, Length, FALSE);

    return Status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeComputeSha1(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(SHA1_HASH_SIZE) PUCHAR Hash
    )
{
    NTSTATUS Status;

    if (Buffer == NULL || Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    HashiEnterOperation();

    Status = HashiComputeBufferHashInternal(
        ShadowHashAlgorithmSha1,
        Buffer,
        Length,
        Hash,
        SHA1_HASH_SIZE
    );

    HashiLeaveOperation(NT_SUCCESS(Status), ShadowHashAlgorithmSha1, Length, FALSE);

    return Status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeComputeMd5(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(MD5_HASH_SIZE) PUCHAR Hash
    )
{
    NTSTATUS Status;

    if (Buffer == NULL || Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    HashiEnterOperation();

    Status = HashiComputeBufferHashInternal(
        ShadowHashAlgorithmMd5,
        Buffer,
        Length,
        Hash,
        MD5_HASH_SIZE
    );

    HashiLeaveOperation(NT_SUCCESS(Status), ShadowHashAlgorithmMd5, Length, FALSE);

    return Status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeComputeSha512(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(SHA512_HASH_SIZE) PUCHAR Hash
    )
{
    NTSTATUS Status;

    if (Buffer == NULL || Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    HashiEnterOperation();

    Status = HashiComputeBufferHashInternal(
        ShadowHashAlgorithmSha512,
        Buffer,
        Length,
        Hash,
        SHA512_HASH_SIZE
    );

    HashiLeaveOperation(NT_SUCCESS(Status), ShadowHashAlgorithmSha512, Length, FALSE);

    return Status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeComputeBufferHash(
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PSHADOWSTRIKE_HASH_RESULT Result
    )
{
    NTSTATUS Status;
    ULONG64 StartTime;
    ULONG64 EndTime;
    ULONG HashSize;

    if (Buffer == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Algorithm <= ShadowHashAlgorithmNone || Algorithm >= ShadowHashAlgorithmCount) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Initialize result structure
    //
    RtlZeroMemory(Result, sizeof(SHADOWSTRIKE_HASH_RESULT));
    Result->Algorithm = Algorithm;
    Result->TotalFileSize = Length;

    HashSize = ShadowStrikeGetHashSize(Algorithm);
    Result->HashSize = HashSize;

    StartTime = HashiGetTimestampMicroseconds();
    HashiEnterOperation();

    Status = HashiComputeBufferHashInternal(
        Algorithm,
        Buffer,
        Length,
        Result->Hash,
        HashSize
    );

    EndTime = HashiGetTimestampMicroseconds();
    HashiLeaveOperation(NT_SUCCESS(Status), Algorithm, Length, FALSE);

    Result->NtStatus = Status;
    Result->ElapsedMicroseconds = EndTime - StartTime;

    if (NT_SUCCESS(Status)) {
        Result->Status = ShadowHashStatusSuccess;
        Result->BytesHashed = Length;
    } else {
        Result->Status = ShadowHashStatusAlgorithmError;
    }

    return Status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeComputeMultiHash(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PSHADOWSTRIKE_MULTI_HASH_RESULT Result
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    NTSTATUS Sha256Status;
    NTSTATUS Sha1Status;
    NTSTATUS Md5Status;

    if (Buffer == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Result, sizeof(SHADOWSTRIKE_MULTI_HASH_RESULT));

    HashiEnterOperation();

    //
    // Compute all three hashes
    // In a more optimized implementation, we could process data once
    // and feed it to all three hash contexts. For now, we compute separately.
    //

    Sha256Status = HashiComputeBufferHashInternal(
        ShadowHashAlgorithmSha256,
        Buffer,
        Length,
        Result->Sha256,
        SHA256_HASH_SIZE
    );

    if (NT_SUCCESS(Sha256Status)) {
        Result->AlgorithmsComputed |= (1 << ShadowHashAlgorithmSha256);
    }

    Sha1Status = HashiComputeBufferHashInternal(
        ShadowHashAlgorithmSha1,
        Buffer,
        Length,
        Result->Sha1,
        SHA1_HASH_SIZE
    );

    if (NT_SUCCESS(Sha1Status)) {
        Result->AlgorithmsComputed |= (1 << ShadowHashAlgorithmSha1);
    }

    Md5Status = HashiComputeBufferHashInternal(
        ShadowHashAlgorithmMd5,
        Buffer,
        Length,
        Result->Md5,
        MD5_HASH_SIZE
    );

    if (NT_SUCCESS(Md5Status)) {
        Result->AlgorithmsComputed |= (1 << ShadowHashAlgorithmMd5);
    }

    //
    // Determine overall status
    //
    if (NT_SUCCESS(Sha256Status) && NT_SUCCESS(Sha1Status) && NT_SUCCESS(Md5Status)) {
        Result->Status = ShadowHashStatusSuccess;
        Result->NtStatus = STATUS_SUCCESS;
    } else if (Result->AlgorithmsComputed != 0) {
        Result->Status = ShadowHashStatusPartial;
        Result->NtStatus = Sha256Status; // Primary algorithm status
    } else {
        Result->Status = ShadowHashStatusAlgorithmError;
        Result->NtStatus = Sha256Status;
        Status = Sha256Status;
    }

    Result->BytesHashed = Length;

    HashiLeaveOperation(
        Result->AlgorithmsComputed != 0,
        ShadowHashAlgorithmSha256,
        Length,
        FALSE
    );

    return Status;
}

// ============================================================================
// FILE HASHING
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeComputeFileHash(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_writes_bytes_(SHA256_HASH_SIZE) PUCHAR Hash
    )
{
    SHADOWSTRIKE_HASH_RESULT Result;
    NTSTATUS Status;

    PAGED_CODE();

    if (Instance == NULL || FileObject == NULL || Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = ShadowStrikeComputeFileHashEx(
        Instance,
        FileObject,
        ShadowHashAlgorithmSha256,
        NULL,
        &Result
    );

    if (NT_SUCCESS(Status)) {
        RtlCopyMemory(Hash, Result.Hash, SHA256_HASH_SIZE);
    }

    //
    // Securely wipe result
    //
    ShadowStrikeSecureZeroMemory(&Result, sizeof(Result));

    return Status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeComputeFileHashEx(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm,
    _In_opt_ PSHADOWSTRIKE_HASH_CONFIG Config,
    _Out_ PSHADOWSTRIKE_HASH_RESULT Result
    )
{
    NTSTATUS Status;
    BCRYPT_ALG_HANDLE hAlgorithm;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PUCHAR pbHashObject = NULL;
    PUCHAR pbReadBuffer = NULL;
    ULONG cbHashObject;
    ULONG cbChunkSize;
    ULONG64 MaxFileSize;
    LARGE_INTEGER ByteOffset;
    ULONG BytesRead;
    FILE_STANDARD_INFORMATION FileInfo;
    ULONG64 StartTime;
    ULONG64 EndTime;
    ULONG HashSize;
    ULONG Flags;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Instance == NULL || FileObject == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Algorithm <= ShadowHashAlgorithmNone || Algorithm >= ShadowHashAlgorithmCount) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Initialize result
    //
    RtlZeroMemory(Result, sizeof(SHADOWSTRIKE_HASH_RESULT));
    Result->Algorithm = Algorithm;

    //
    // Apply configuration or defaults
    //
    if (Config != NULL) {
        MaxFileSize = Config->MaxFileSize;
        cbChunkSize = Config->ChunkSize;
        Flags = Config->Flags;
    } else {
        MaxFileSize = 0;
        cbChunkSize = 0;
        Flags = ShadowHashFlagNonCached;
    }

    if (MaxFileSize == 0) {
        MaxFileSize = HASH_MAX_FILE_SIZE_DEFAULT;
    }
    if (MaxFileSize > HASH_MAX_FILE_SIZE_LIMIT) {
        MaxFileSize = HASH_MAX_FILE_SIZE_LIMIT;
    }

    if (cbChunkSize == 0) {
        cbChunkSize = HASH_DEFAULT_CHUNK_SIZE;
    }
    if (cbChunkSize < HASH_MIN_CHUNK_SIZE) {
        cbChunkSize = HASH_MIN_CHUNK_SIZE;
    }
    if (cbChunkSize > HASH_MAX_CHUNK_SIZE) {
        cbChunkSize = HASH_MAX_CHUNK_SIZE;
    }

    //
    // Validate subsystem
    //
    if (!g_HashGlobals.Initialized) {
        Result->Status = ShadowHashStatusNotInitialized;
        Result->NtStatus = STATUS_UNSUCCESSFUL;
        return STATUS_UNSUCCESSFUL;
    }

    StartTime = HashiGetTimestampMicroseconds();
    HashiEnterOperation();

    //
    // Get file size
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
        Result->Status = ShadowHashStatusAccessDenied;
        Result->NtStatus = Status;
        goto Cleanup;
    }

    Result->TotalFileSize = FileInfo.EndOfFile.QuadPart;

    //
    // Check file size limit
    //
    if ((ULONG64)FileInfo.EndOfFile.QuadPart > MaxFileSize) {
        InterlockedIncrement64(&g_HashGlobals.Statistics.SizeLimitExceeded);
        Result->Status = ShadowHashStatusFileTooLarge;
        Result->NtStatus = STATUS_FILE_TOO_LARGE;
        Status = STATUS_FILE_TOO_LARGE;
        goto Cleanup;
    }

    //
    // Get algorithm handle and sizes
    //
    hAlgorithm = HashiGetAlgorithmHandle(Algorithm);
    if (hAlgorithm == NULL) {
        Result->Status = ShadowHashStatusAlgorithmError;
        Result->NtStatus = STATUS_UNSUCCESSFUL;
        Status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    cbHashObject = HashiGetHashObjectSize(Algorithm);
    HashSize = ShadowStrikeGetHashSize(Algorithm);
    Result->HashSize = HashSize;

    //
    // Allocate hash object
    //
    pbHashObject = (PUCHAR)ShadowStrikeAllocateWithTag(cbHashObject, SHADOWSTRIKE_HASH_OBJ_TAG);
    if (pbHashObject == NULL) {
        Result->Status = ShadowHashStatusMemoryError;
        Result->NtStatus = STATUS_INSUFFICIENT_RESOURCES;
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    //
    // Allocate read buffer
    //
    if (Flags & ShadowHashFlagPagedBuffer) {
        pbReadBuffer = (PUCHAR)ShadowStrikeAllocatePagedWithTag(cbChunkSize, SHADOWSTRIKE_HASH_BUF_TAG);
    } else {
        pbReadBuffer = (PUCHAR)ShadowStrikeAllocateWithTag(cbChunkSize, SHADOWSTRIKE_HASH_BUF_TAG);
    }

    if (pbReadBuffer == NULL) {
        Result->Status = ShadowHashStatusMemoryError;
        Result->NtStatus = STATUS_INSUFFICIENT_RESOURCES;
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    //
    // Create hash object
    //
    Status = BCryptCreateHash(
        hAlgorithm,
        &hHash,
        pbHashObject,
        cbHashObject,
        NULL,
        0,
        0
    );

    if (!NT_SUCCESS(Status)) {
        InterlockedIncrement64(&g_HashGlobals.Statistics.CngErrors);
        Result->Status = ShadowHashStatusAlgorithmError;
        Result->NtStatus = Status;
        goto Cleanup;
    }

    //
    // Read file in chunks and hash
    //
    ByteOffset.QuadPart = 0;

    while (ByteOffset.QuadPart < FileInfo.EndOfFile.QuadPart) {
        ULONG ReadFlags = FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET;

        if (Flags & ShadowHashFlagNonCached) {
            ReadFlags |= FLTFL_IO_OPERATION_NON_CACHED;
        }

        Status = FltReadFile(
            Instance,
            FileObject,
            &ByteOffset,
            cbChunkSize,
            pbReadBuffer,
            ReadFlags,
            &BytesRead,
            NULL,
            NULL
        );

        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_END_OF_FILE) {
                Status = STATUS_SUCCESS;
                break;
            }

            //
            // Handle partial hash if configured
            //
            if (Flags & ShadowHashFlagAllowPartial) {
                Result->IsPartial = TRUE;
                Status = STATUS_SUCCESS;
                break;
            }

            Result->Status = ShadowHashStatusAccessDenied;
            Result->NtStatus = Status;
            goto Cleanup;
        }

        if (BytesRead == 0) {
            break;
        }

        //
        // Hash this chunk
        //
        Status = BCryptHashData(hHash, pbReadBuffer, BytesRead, 0);
        if (!NT_SUCCESS(Status)) {
            InterlockedIncrement64(&g_HashGlobals.Statistics.CngErrors);
            Result->Status = ShadowHashStatusAlgorithmError;
            Result->NtStatus = Status;
            goto Cleanup;
        }

        Result->BytesHashed += BytesRead;
        ByteOffset.QuadPart += BytesRead;
    }

    //
    // Finalize hash
    //
    Status = BCryptFinishHash(hHash, Result->Hash, HashSize, 0);
    if (!NT_SUCCESS(Status)) {
        InterlockedIncrement64(&g_HashGlobals.Statistics.CngErrors);
        Result->Status = ShadowHashStatusAlgorithmError;
        Result->NtStatus = Status;
        goto Cleanup;
    }

    Result->Status = Result->IsPartial ? ShadowHashStatusPartial : ShadowHashStatusSuccess;
    Result->NtStatus = STATUS_SUCCESS;
    Status = STATUS_SUCCESS;

Cleanup:
    EndTime = HashiGetTimestampMicroseconds();
    Result->ElapsedMicroseconds = EndTime - StartTime;

    if (hHash != NULL) {
        BCryptDestroyHash(hHash);
    }

    if (pbHashObject != NULL) {
        ShadowStrikeSecureZeroMemory(pbHashObject, cbHashObject);
        ShadowStrikeFreePoolWithTag(pbHashObject, SHADOWSTRIKE_HASH_OBJ_TAG);
    }

    if (pbReadBuffer != NULL) {
        if (Flags & ShadowHashFlagSecureWipe) {
            ShadowStrikeSecureZeroMemory(pbReadBuffer, cbChunkSize);
        }
        ShadowStrikeFreePoolWithTag(pbReadBuffer, SHADOWSTRIKE_HASH_BUF_TAG);
    }

    HashiLeaveOperation(
        Result->Status == ShadowHashStatusSuccess || Result->Status == ShadowHashStatusPartial,
        Algorithm,
        Result->BytesHashed,
        TRUE
    );

    return Status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeComputeFileMultiHash(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ PSHADOWSTRIKE_HASH_CONFIG Config,
    _Out_ PSHADOWSTRIKE_MULTI_HASH_RESULT Result
    )
{
    NTSTATUS Status;
    BCRYPT_HASH_HANDLE hHashSha256 = NULL;
    BCRYPT_HASH_HANDLE hHashSha1 = NULL;
    BCRYPT_HASH_HANDLE hHashMd5 = NULL;
    PUCHAR pbHashObjSha256 = NULL;
    PUCHAR pbHashObjSha1 = NULL;
    PUCHAR pbHashObjMd5 = NULL;
    PUCHAR pbReadBuffer = NULL;
    ULONG cbChunkSize;
    ULONG64 MaxFileSize;
    LARGE_INTEGER ByteOffset;
    ULONG BytesRead;
    FILE_STANDARD_INFORMATION FileInfo;
    ULONG Flags;

    PAGED_CODE();

    if (Instance == NULL || FileObject == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Result, sizeof(SHADOWSTRIKE_MULTI_HASH_RESULT));

    //
    // Apply configuration
    //
    if (Config != NULL) {
        MaxFileSize = Config->MaxFileSize;
        cbChunkSize = Config->ChunkSize;
        Flags = Config->Flags;
    } else {
        MaxFileSize = HASH_MAX_FILE_SIZE_DEFAULT;
        cbChunkSize = HASH_DEFAULT_CHUNK_SIZE;
        Flags = ShadowHashFlagNonCached;
    }

    if (MaxFileSize == 0) MaxFileSize = HASH_MAX_FILE_SIZE_DEFAULT;
    if (cbChunkSize == 0) cbChunkSize = HASH_DEFAULT_CHUNK_SIZE;

    if (!g_HashGlobals.Initialized) {
        Result->Status = ShadowHashStatusNotInitialized;
        return STATUS_UNSUCCESSFUL;
    }

    HashiEnterOperation();

    //
    // Get file size
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
        Result->Status = ShadowHashStatusAccessDenied;
        Result->NtStatus = Status;
        goto Cleanup;
    }

    if ((ULONG64)FileInfo.EndOfFile.QuadPart > MaxFileSize) {
        Result->Status = ShadowHashStatusFileTooLarge;
        Result->NtStatus = STATUS_FILE_TOO_LARGE;
        Status = STATUS_FILE_TOO_LARGE;
        goto Cleanup;
    }

    //
    // Allocate hash objects
    //
    pbHashObjSha256 = (PUCHAR)ShadowStrikeAllocateWithTag(
        g_HashGlobals.Providers[ShadowHashAlgorithmSha256].HashObjectSize,
        SHADOWSTRIKE_HASH_OBJ_TAG
    );

    pbHashObjSha1 = (PUCHAR)ShadowStrikeAllocateWithTag(
        g_HashGlobals.Providers[ShadowHashAlgorithmSha1].HashObjectSize,
        SHADOWSTRIKE_HASH_OBJ_TAG
    );

    pbHashObjMd5 = (PUCHAR)ShadowStrikeAllocateWithTag(
        g_HashGlobals.Providers[ShadowHashAlgorithmMd5].HashObjectSize,
        SHADOWSTRIKE_HASH_OBJ_TAG
    );

    pbReadBuffer = (PUCHAR)ShadowStrikeAllocateWithTag(cbChunkSize, SHADOWSTRIKE_HASH_BUF_TAG);

    if (pbHashObjSha256 == NULL || pbHashObjSha1 == NULL ||
        pbHashObjMd5 == NULL || pbReadBuffer == NULL) {
        Result->Status = ShadowHashStatusMemoryError;
        Result->NtStatus = STATUS_INSUFFICIENT_RESOURCES;
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    //
    // Create hash objects
    //
    Status = BCryptCreateHash(
        g_HashGlobals.Providers[ShadowHashAlgorithmSha256].AlgorithmHandle,
        &hHashSha256,
        pbHashObjSha256,
        g_HashGlobals.Providers[ShadowHashAlgorithmSha256].HashObjectSize,
        NULL, 0, 0
    );
    if (!NT_SUCCESS(Status)) goto Cleanup;

    Status = BCryptCreateHash(
        g_HashGlobals.Providers[ShadowHashAlgorithmSha1].AlgorithmHandle,
        &hHashSha1,
        pbHashObjSha1,
        g_HashGlobals.Providers[ShadowHashAlgorithmSha1].HashObjectSize,
        NULL, 0, 0
    );
    if (!NT_SUCCESS(Status)) goto Cleanup;

    Status = BCryptCreateHash(
        g_HashGlobals.Providers[ShadowHashAlgorithmMd5].AlgorithmHandle,
        &hHashMd5,
        pbHashObjMd5,
        g_HashGlobals.Providers[ShadowHashAlgorithmMd5].HashObjectSize,
        NULL, 0, 0
    );
    if (!NT_SUCCESS(Status)) goto Cleanup;

    //
    // Read and hash file
    //
    ByteOffset.QuadPart = 0;

    while (ByteOffset.QuadPart < FileInfo.EndOfFile.QuadPart) {
        Status = FltReadFile(
            Instance,
            FileObject,
            &ByteOffset,
            cbChunkSize,
            pbReadBuffer,
            FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
            &BytesRead,
            NULL,
            NULL
        );

        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_END_OF_FILE) {
                Status = STATUS_SUCCESS;
                break;
            }
            goto Cleanup;
        }

        if (BytesRead == 0) break;

        //
        // Feed data to all three hash contexts
        //
        BCryptHashData(hHashSha256, pbReadBuffer, BytesRead, 0);
        BCryptHashData(hHashSha1, pbReadBuffer, BytesRead, 0);
        BCryptHashData(hHashMd5, pbReadBuffer, BytesRead, 0);

        Result->BytesHashed += BytesRead;
        ByteOffset.QuadPart += BytesRead;
    }

    //
    // Finalize all hashes
    //
    Status = BCryptFinishHash(hHashSha256, Result->Sha256, SHA256_HASH_SIZE, 0);
    if (NT_SUCCESS(Status)) {
        Result->AlgorithmsComputed |= (1 << ShadowHashAlgorithmSha256);
    }

    Status = BCryptFinishHash(hHashSha1, Result->Sha1, SHA1_HASH_SIZE, 0);
    if (NT_SUCCESS(Status)) {
        Result->AlgorithmsComputed |= (1 << ShadowHashAlgorithmSha1);
    }

    Status = BCryptFinishHash(hHashMd5, Result->Md5, MD5_HASH_SIZE, 0);
    if (NT_SUCCESS(Status)) {
        Result->AlgorithmsComputed |= (1 << ShadowHashAlgorithmMd5);
    }

    Result->Status = ShadowHashStatusSuccess;
    Result->NtStatus = STATUS_SUCCESS;
    Status = STATUS_SUCCESS;

Cleanup:
    if (hHashSha256) BCryptDestroyHash(hHashSha256);
    if (hHashSha1) BCryptDestroyHash(hHashSha1);
    if (hHashMd5) BCryptDestroyHash(hHashMd5);

    if (pbHashObjSha256) {
        ShadowStrikeSecureZeroMemory(pbHashObjSha256,
            g_HashGlobals.Providers[ShadowHashAlgorithmSha256].HashObjectSize);
        ShadowStrikeFreePoolWithTag(pbHashObjSha256, SHADOWSTRIKE_HASH_OBJ_TAG);
    }
    if (pbHashObjSha1) {
        ShadowStrikeSecureZeroMemory(pbHashObjSha1,
            g_HashGlobals.Providers[ShadowHashAlgorithmSha1].HashObjectSize);
        ShadowStrikeFreePoolWithTag(pbHashObjSha1, SHADOWSTRIKE_HASH_OBJ_TAG);
    }
    if (pbHashObjMd5) {
        ShadowStrikeSecureZeroMemory(pbHashObjMd5,
            g_HashGlobals.Providers[ShadowHashAlgorithmMd5].HashObjectSize);
        ShadowStrikeFreePoolWithTag(pbHashObjMd5, SHADOWSTRIKE_HASH_OBJ_TAG);
    }
    if (pbReadBuffer) {
        ShadowStrikeFreePoolWithTag(pbReadBuffer, SHADOWSTRIKE_HASH_BUF_TAG);
    }

    HashiLeaveOperation(
        Result->AlgorithmsComputed != 0,
        ShadowHashAlgorithmSha256,
        Result->BytesHashed,
        TRUE
    );

    return Status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeComputeFileHashByPath(
    _In_ PCUNICODE_STRING FilePath,
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm,
    _Out_ PSHADOWSTRIKE_HASH_RESULT Result
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE FileHandle = NULL;
    PFILE_OBJECT FileObject = NULL;

    PAGED_CODE();

    if (FilePath == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ShadowStrikeIsValidUnicodeString(FilePath)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Result, sizeof(SHADOWSTRIKE_HASH_RESULT));
    Result->Algorithm = Algorithm;

    InitializeObjectAttributes(
        &ObjectAttributes,
        (PUNICODE_STRING)FilePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    Status = ZwCreateFile(
        &FileHandle,
        FILE_READ_DATA | SYNCHRONIZE,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(Status)) {
        Result->Status = ShadowHashStatusAccessDenied;
        Result->NtStatus = Status;
        return Status;
    }

    Status = ObReferenceObjectByHandle(
        FileHandle,
        FILE_READ_DATA,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&FileObject,
        NULL
    );

    if (!NT_SUCCESS(Status)) {
        ZwClose(FileHandle);
        Result->Status = ShadowHashStatusAccessDenied;
        Result->NtStatus = Status;
        return Status;
    }

    //
    // Note: This path-based function cannot use FltReadFile without a filter instance.
    // For full implementation, we would need to use ZwReadFile or have access to a filter instance.
    // This is a simplified implementation that reads the file directly.
    //

    //
    // For now, we'll implement a ZwReadFile-based approach
    //
    {
        FILE_STANDARD_INFORMATION FileInfo;
        PUCHAR pbBuffer = NULL;
        PUCHAR pbHashObject = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        BCRYPT_ALG_HANDLE hAlgorithm;
        ULONG cbHashObject;
        ULONG HashSize;
        LARGE_INTEGER ByteOffset;
        ULONG ChunkSize = HASH_DEFAULT_CHUNK_SIZE;

        //
        // Get file size
        //
        Status = ZwQueryInformationFile(
            FileHandle,
            &IoStatusBlock,
            &FileInfo,
            sizeof(FileInfo),
            FileStandardInformation
        );

        if (!NT_SUCCESS(Status)) {
            Result->Status = ShadowHashStatusAccessDenied;
            Result->NtStatus = Status;
            goto PathCleanup;
        }

        Result->TotalFileSize = FileInfo.EndOfFile.QuadPart;

        if ((ULONG64)FileInfo.EndOfFile.QuadPart > HASH_MAX_FILE_SIZE_DEFAULT) {
            Result->Status = ShadowHashStatusFileTooLarge;
            Result->NtStatus = STATUS_FILE_TOO_LARGE;
            Status = STATUS_FILE_TOO_LARGE;
            goto PathCleanup;
        }

        hAlgorithm = HashiGetAlgorithmHandle(Algorithm);
        cbHashObject = HashiGetHashObjectSize(Algorithm);
        HashSize = ShadowStrikeGetHashSize(Algorithm);
        Result->HashSize = HashSize;

        pbHashObject = (PUCHAR)ShadowStrikeAllocateWithTag(cbHashObject, SHADOWSTRIKE_HASH_OBJ_TAG);
        pbBuffer = (PUCHAR)ShadowStrikeAllocateWithTag(ChunkSize, SHADOWSTRIKE_HASH_BUF_TAG);

        if (pbHashObject == NULL || pbBuffer == NULL) {
            Result->Status = ShadowHashStatusMemoryError;
            Result->NtStatus = STATUS_INSUFFICIENT_RESOURCES;
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto PathCleanup;
        }

        Status = BCryptCreateHash(hAlgorithm, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
        if (!NT_SUCCESS(Status)) {
            Result->Status = ShadowHashStatusAlgorithmError;
            Result->NtStatus = Status;
            goto PathCleanup;
        }

        ByteOffset.QuadPart = 0;

        while (ByteOffset.QuadPart < FileInfo.EndOfFile.QuadPart) {
            Status = ZwReadFile(
                FileHandle,
                NULL,
                NULL,
                NULL,
                &IoStatusBlock,
                pbBuffer,
                ChunkSize,
                &ByteOffset,
                NULL
            );

            if (!NT_SUCCESS(Status)) {
                if (Status == STATUS_END_OF_FILE) {
                    Status = STATUS_SUCCESS;
                    break;
                }
                Result->Status = ShadowHashStatusAccessDenied;
                Result->NtStatus = Status;
                goto PathCleanup;
            }

            if (IoStatusBlock.Information == 0) break;

            BCryptHashData(hHash, pbBuffer, (ULONG)IoStatusBlock.Information, 0);
            Result->BytesHashed += IoStatusBlock.Information;
            ByteOffset.QuadPart += IoStatusBlock.Information;
        }

        Status = BCryptFinishHash(hHash, Result->Hash, HashSize, 0);
        if (NT_SUCCESS(Status)) {
            Result->Status = ShadowHashStatusSuccess;
            Result->NtStatus = STATUS_SUCCESS;
        } else {
            Result->Status = ShadowHashStatusAlgorithmError;
            Result->NtStatus = Status;
        }

PathCleanup:
        if (hHash) BCryptDestroyHash(hHash);
        if (pbHashObject) {
            ShadowStrikeSecureZeroMemory(pbHashObject, cbHashObject);
            ShadowStrikeFreePoolWithTag(pbHashObject, SHADOWSTRIKE_HASH_OBJ_TAG);
        }
        if (pbBuffer) {
            ShadowStrikeFreePoolWithTag(pbBuffer, SHADOWSTRIKE_HASH_BUF_TAG);
        }
    }

    ObDereferenceObject(FileObject);
    ZwClose(FileHandle);

    return Status;
}

// ============================================================================
// STREAMING HASH CONTEXT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeHashContextInit(
    _Out_ PSHADOWSTRIKE_HASH_CONTEXT Context,
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm
    )
{
    NTSTATUS Status;
    BCRYPT_ALG_HANDLE hAlgorithm;
    ULONG cbHashObject;

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Context, sizeof(SHADOWSTRIKE_HASH_CONTEXT));

    if (Algorithm <= ShadowHashAlgorithmNone || Algorithm >= ShadowHashAlgorithmCount) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_HashGlobals.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    hAlgorithm = HashiGetAlgorithmHandle(Algorithm);
    if (hAlgorithm == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    cbHashObject = HashiGetHashObjectSize(Algorithm);

    Context->HashObject = (PUCHAR)ShadowStrikeAllocateWithTag(cbHashObject, SHADOWSTRIKE_HASH_OBJ_TAG);
    if (Context->HashObject == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = BCryptCreateHash(
        hAlgorithm,
        &Context->HashHandle,
        Context->HashObject,
        cbHashObject,
        NULL,
        0,
        0
    );

    if (!NT_SUCCESS(Status)) {
        ShadowStrikeFreePoolWithTag(Context->HashObject, SHADOWSTRIKE_HASH_OBJ_TAG);
        Context->HashObject = NULL;
        return Status;
    }

    Context->Algorithm = Algorithm;
    Context->HashObjectSize = cbHashObject;
    Context->ExpectedHashSize = ShadowStrikeGetHashSize(Algorithm);
    Context->TotalBytesHashed = 0;
    Context->IsValid = TRUE;
    Context->IsFinalized = FALSE;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeHashContextUpdate(
    _Inout_ PSHADOWSTRIKE_HASH_CONTEXT Context,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length
    )
{
    NTSTATUS Status;

    if (Context == NULL || Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Context->IsValid || Context->IsFinalized) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (Length == 0) {
        return STATUS_SUCCESS;
    }

    Status = BCryptHashData(Context->HashHandle, (PUCHAR)Buffer, Length, 0);

    if (NT_SUCCESS(Status)) {
        Context->TotalBytesHashed += Length;
    } else {
        Context->IsValid = FALSE;
    }

    return Status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeHashContextFinalize(
    _Inout_ PSHADOWSTRIKE_HASH_CONTEXT Context,
    _Out_writes_bytes_(HashSize) PUCHAR Hash,
    _In_ ULONG HashSize
    )
{
    NTSTATUS Status;

    if (Context == NULL || Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Context->IsValid) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (Context->IsFinalized) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (HashSize < Context->ExpectedHashSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Status = BCryptFinishHash(Context->HashHandle, Hash, Context->ExpectedHashSize, 0);

    Context->IsFinalized = TRUE;

    return Status;
}

_Use_decl_annotations_
VOID
ShadowStrikeHashContextCleanup(
    _Inout_ PSHADOWSTRIKE_HASH_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    if (Context->HashHandle != NULL) {
        BCryptDestroyHash(Context->HashHandle);
        Context->HashHandle = NULL;
    }

    if (Context->HashObject != NULL) {
        ShadowStrikeSecureZeroMemory(Context->HashObject, Context->HashObjectSize);
        ShadowStrikeFreePoolWithTag(Context->HashObject, SHADOWSTRIKE_HASH_OBJ_TAG);
        Context->HashObject = NULL;
    }

    Context->IsValid = FALSE;
    Context->IsFinalized = TRUE;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeHashContextClone(
    _In_ PSHADOWSTRIKE_HASH_CONTEXT Source,
    _Out_ PSHADOWSTRIKE_HASH_CONTEXT Destination
    )
{
    NTSTATUS Status;
    BCRYPT_ALG_HANDLE hAlgorithm;

    if (Source == NULL || Destination == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Source->IsValid || Source->IsFinalized) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(Destination, sizeof(SHADOWSTRIKE_HASH_CONTEXT));

    Destination->HashObject = (PUCHAR)ShadowStrikeAllocateWithTag(
        Source->HashObjectSize,
        SHADOWSTRIKE_HASH_OBJ_TAG
    );

    if (Destination->HashObject == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = BCryptDuplicateHash(
        Source->HashHandle,
        &Destination->HashHandle,
        Destination->HashObject,
        Source->HashObjectSize,
        0
    );

    if (!NT_SUCCESS(Status)) {
        ShadowStrikeFreePoolWithTag(Destination->HashObject, SHADOWSTRIKE_HASH_OBJ_TAG);
        Destination->HashObject = NULL;
        return Status;
    }

    Destination->Algorithm = Source->Algorithm;
    Destination->HashObjectSize = Source->HashObjectSize;
    Destination->ExpectedHashSize = Source->ExpectedHashSize;
    Destination->TotalBytesHashed = Source->TotalBytesHashed;
    Destination->IsValid = TRUE;
    Destination->IsFinalized = FALSE;

    return STATUS_SUCCESS;
}

// ============================================================================
// HASH COMPARISON
// ============================================================================

_Use_decl_annotations_
BOOLEAN
ShadowStrikeCompareHash(
    _In_reads_bytes_(HashSize) const UCHAR* Hash1,
    _In_reads_bytes_(HashSize) const UCHAR* Hash2,
    _In_ ULONG HashSize
    )
{
    ULONG i;
    volatile UCHAR Diff = 0;

    if (Hash1 == NULL || Hash2 == NULL || HashSize == 0) {
        return FALSE;
    }

    //
    // Constant-time comparison to prevent timing attacks
    //
    for (i = 0; i < HashSize; i++) {
        Diff |= Hash1[i] ^ Hash2[i];
    }

    return (Diff == 0);
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeCompareSha256(
    _In_reads_bytes_(SHA256_HASH_SIZE) const UCHAR* Hash1,
    _In_reads_bytes_(SHA256_HASH_SIZE) const UCHAR* Hash2
    )
{
    return ShadowStrikeCompareHash(Hash1, Hash2, SHA256_HASH_SIZE);
}

// ============================================================================
// HASH STRING CONVERSION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeHashToString(
    _In_reads_bytes_(HashSize) const UCHAR* Hash,
    _In_ ULONG HashSize,
    _Out_writes_z_(StringSize) PWCHAR String,
    _In_ ULONG StringSize,
    _In_ BOOLEAN Uppercase
    )
{
    ULONG i;
    ULONG RequiredSize;
    PCWSTR HexChars;

    if (Hash == NULL || String == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RequiredSize = (HashSize * 2 + 1) * sizeof(WCHAR);
    if (StringSize < RequiredSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    HexChars = Uppercase ? L"0123456789ABCDEF" : L"0123456789abcdef";

    for (i = 0; i < HashSize; i++) {
        String[i * 2] = HexChars[(Hash[i] >> 4) & 0x0F];
        String[i * 2 + 1] = HexChars[Hash[i] & 0x0F];
    }

    String[HashSize * 2] = L'\0';

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeStringToHash(
    _In_z_ PCWSTR String,
    _Out_writes_bytes_(HashSize) PUCHAR Hash,
    _In_ ULONG HashSize,
    _Out_opt_ PULONG BytesWritten
    )
{
    ULONG i;
    SIZE_T StringLength;
    ULONG BytesToWrite;
    WCHAR c1, c2;
    UCHAR b1, b2;

    if (String == NULL || Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    StringLength = wcslen(String);
    if (StringLength % 2 != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    BytesToWrite = (ULONG)(StringLength / 2);
    if (BytesToWrite > HashSize) {
        BytesToWrite = HashSize;
    }

    for (i = 0; i < BytesToWrite; i++) {
        c1 = String[i * 2];
        c2 = String[i * 2 + 1];

        //
        // Convert hex char to nibble
        //
        if (c1 >= L'0' && c1 <= L'9') b1 = (UCHAR)(c1 - L'0');
        else if (c1 >= L'a' && c1 <= L'f') b1 = (UCHAR)(c1 - L'a' + 10);
        else if (c1 >= L'A' && c1 <= L'F') b1 = (UCHAR)(c1 - L'A' + 10);
        else return STATUS_INVALID_PARAMETER;

        if (c2 >= L'0' && c2 <= L'9') b2 = (UCHAR)(c2 - L'0');
        else if (c2 >= L'a' && c2 <= L'f') b2 = (UCHAR)(c2 - L'a' + 10);
        else if (c2 >= L'A' && c2 <= L'F') b2 = (UCHAR)(c2 - L'A' + 10);
        else return STATUS_INVALID_PARAMETER;

        Hash[i] = (b1 << 4) | b2;
    }

    if (BytesWritten != NULL) {
        *BytesWritten = BytesToWrite;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeSha256ToString(
    _In_reads_bytes_(SHA256_HASH_SIZE) const UCHAR* Hash,
    _Out_ PUNICODE_STRING String
    )
{
    NTSTATUS Status;
    PWCHAR Buffer;
    ULONG BufferSize;

    PAGED_CODE();

    if (Hash == NULL || String == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    BufferSize = SHA256_STRING_SIZE * sizeof(WCHAR);

    Buffer = (PWCHAR)ShadowStrikeAllocatePagedWithTag(BufferSize, SHADOW_STRING_TAG);
    if (Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ShadowStrikeHashToString(
        Hash,
        SHA256_HASH_SIZE,
        Buffer,
        BufferSize,
        FALSE  // lowercase
    );

    if (!NT_SUCCESS(Status)) {
        ShadowStrikeFreePoolWithTag(Buffer, SHADOW_STRING_TAG);
        return Status;
    }

    String->Buffer = Buffer;
    String->Length = SHA256_HASH_SIZE * 2 * sizeof(WCHAR);
    String->MaximumLength = (USHORT)BufferSize;

    return STATUS_SUCCESS;
}

// ============================================================================
// HMAC OPERATIONS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeComputeHmacSha256(
    _In_reads_bytes_(KeyLength) const UCHAR* Key,
    _In_ ULONG KeyLength,
    _In_reads_bytes_(DataLength) const UCHAR* Data,
    _In_ ULONG DataLength,
    _Out_writes_bytes_(SHA256_HASH_SIZE) PUCHAR Mac
    )
{
    NTSTATUS Status;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PUCHAR pbHashObject = NULL;

    if (Key == NULL || Data == NULL || Mac == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_HashGlobals.Initialized || g_HashGlobals.HmacSha256Handle == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    pbHashObject = (PUCHAR)ShadowStrikeAllocateWithTag(
        g_HashGlobals.HmacSha256ObjectSize,
        SHADOWSTRIKE_HASH_OBJ_TAG
    );

    if (pbHashObject == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = BCryptCreateHash(
        g_HashGlobals.HmacSha256Handle,
        &hHash,
        pbHashObject,
        g_HashGlobals.HmacSha256ObjectSize,
        (PUCHAR)Key,
        KeyLength,
        0
    );

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status = BCryptHashData(hHash, (PUCHAR)Data, DataLength, 0);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status = BCryptFinishHash(hHash, Mac, SHA256_HASH_SIZE, 0);

Cleanup:
    if (hHash != NULL) {
        BCryptDestroyHash(hHash);
    }

    if (pbHashObject != NULL) {
        ShadowStrikeSecureZeroMemory(pbHashObject, g_HashGlobals.HmacSha256ObjectSize);
        ShadowStrikeFreePoolWithTag(pbHashObject, SHADOWSTRIKE_HASH_OBJ_TAG);
    }

    return Status;
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeVerifyHmacSha256(
    _In_reads_bytes_(KeyLength) const UCHAR* Key,
    _In_ ULONG KeyLength,
    _In_reads_bytes_(DataLength) const UCHAR* Data,
    _In_ ULONG DataLength,
    _In_reads_bytes_(SHA256_HASH_SIZE) const UCHAR* ExpectedMac
    )
{
    NTSTATUS Status;
    UCHAR ComputedMac[SHA256_HASH_SIZE];

    Status = ShadowStrikeComputeHmacSha256(Key, KeyLength, Data, DataLength, ComputedMac);

    if (!NT_SUCCESS(Status)) {
        ShadowStrikeSecureZeroMemory(ComputedMac, sizeof(ComputedMac));
        return FALSE;
    }

    BOOLEAN Result = ShadowStrikeCompareSha256(ComputedMac, ExpectedMac);

    ShadowStrikeSecureZeroMemory(ComputedMac, sizeof(ComputedMac));

    return Result;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

_Use_decl_annotations_
ULONG
ShadowStrikeGetHashSize(
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm
    )
{
    switch (Algorithm) {
        case ShadowHashAlgorithmSha256:
            return SHA256_HASH_SIZE;
        case ShadowHashAlgorithmSha1:
            return SHA1_HASH_SIZE;
        case ShadowHashAlgorithmMd5:
            return MD5_HASH_SIZE;
        case ShadowHashAlgorithmSha512:
            return SHA512_HASH_SIZE;
        default:
            return 0;
    }
}

_Use_decl_annotations_
PCWSTR
ShadowStrikeGetHashAlgorithmName(
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm
    )
{
    switch (Algorithm) {
        case ShadowHashAlgorithmSha256:
            return L"SHA-256";
        case ShadowHashAlgorithmSha1:
            return L"SHA-1";
        case ShadowHashAlgorithmMd5:
            return L"MD5";
        case ShadowHashAlgorithmSha512:
            return L"SHA-512";
        default:
            return L"Unknown";
    }
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeIsHashResultValid(
    _In_ PSHADOWSTRIKE_HASH_RESULT Result
    )
{
    if (Result == NULL) {
        return FALSE;
    }

    if (Result->Status != ShadowHashStatusSuccess &&
        Result->Status != ShadowHashStatusPartial) {
        return FALSE;
    }

    if (Result->HashSize == 0 || Result->HashSize > MAX_HASH_SIZE) {
        return FALSE;
    }

    if (ShadowStrikeIsHashEmpty(Result->Hash, Result->HashSize)) {
        return FALSE;
    }

    return TRUE;
}

_Use_decl_annotations_
VOID
ShadowStrikeInitDefaultHashConfig(
    _Out_ PSHADOWSTRIKE_HASH_CONFIG Config
    )
{
    if (Config == NULL) {
        return;
    }

    RtlZeroMemory(Config, sizeof(SHADOWSTRIKE_HASH_CONFIG));

    Config->MaxFileSize = HASH_MAX_FILE_SIZE_DEFAULT;
    Config->ChunkSize = HASH_DEFAULT_CHUNK_SIZE;
    Config->Flags = ShadowHashFlagNonCached;
    Config->TimeoutMs = 0;  // No timeout by default
}

_Use_decl_annotations_
VOID
ShadowStrikeClearHashResult(
    _Inout_ PSHADOWSTRIKE_HASH_RESULT Result
    )
{
    if (Result != NULL) {
        ShadowStrikeSecureZeroMemory(Result, sizeof(SHADOWSTRIKE_HASH_RESULT));
    }
}
