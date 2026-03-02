/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/*++
    ShadowStrike Next-Generation Antivirus
    Module: Encryption.c

    Purpose: Enterprise-grade AES-GCM encryption for sensitive telemetry data
             and secure kernel-to-user communication channels.

    Architecture:
    - AES-256-GCM authenticated encryption via BCrypt
    - HKDF key derivation (RFC 5869)
    - Monotonic nonce counter (never reused)
    - Secure key storage in non-paged pool with obfuscation
    - Automatic key rotation with configurable intervals

    Security Properties:
    - Authenticated encryption (confidentiality + integrity)
    - Nonce uniqueness guaranteed via atomic counter
    - Keys zeroed on destruction
    - Constant-time comparisons to prevent timing attacks
    - No key material in pageable memory
    - All BCrypt operations at PASSIVE_LEVEL

    Copyright (c) ShadowStrike Team
--*/

#include "Encryption.h"
#include "../Utilities/MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, EncInitialize)
#pragma alloc_text(PAGE, EncShutdown)
#pragma alloc_text(PAGE, EncSetMasterKey)
#pragma alloc_text(PAGE, EncGenerateKey)
#pragma alloc_text(PAGE, EncDeriveKey)
#pragma alloc_text(PAGE, EncImportKey)
#pragma alloc_text(PAGE, EncExportKey)
#pragma alloc_text(PAGE, EncDestroyKey)
#pragma alloc_text(PAGE, EncCreateContext)
#pragma alloc_text(PAGE, EncDestroyContext)
#pragma alloc_text(PAGE, EncSetAAD)
#pragma alloc_text(PAGE, EncEncrypt)
#pragma alloc_text(PAGE, EncDecrypt)
#pragma alloc_text(PAGE, EncEncryptWithContext)
#pragma alloc_text(PAGE, EncDecryptWithContext)
#pragma alloc_text(PAGE, EncRotateKey)
#pragma alloc_text(PAGE, EncRotateAllKeys)
#pragma alloc_text(PAGE, EncSetAutoRotation)
#pragma alloc_text(PAGE, EncRandomBytes)
#pragma alloc_text(PAGE, EncHmacSha256)
#pragma alloc_text(PAGE, EncHkdfDerive)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

#define ENC_SIGNATURE               'CNEZ'  // 'ZENC' reversed
#define ENC_HMAC_SHA256_SIZE        32
#define ENC_HKDF_HASH_SIZE          32      // SHA-256
#define ENC_OBFUSCATION_ROUNDS      3
#define ENC_CRC32_POLYNOMIAL        0xEDB88320UL

//=============================================================================
// Internal Structures
//=============================================================================

typedef struct _ENC_KEY_INTERNAL {
    ULONG Signature;
    ENC_KEY Key;
    PENC_MANAGER Manager;
    volatile BOOLEAN Destroying;
} ENC_KEY_INTERNAL, *PENC_KEY_INTERNAL;

typedef struct _ENC_ROTATION_CONTEXT {
    PENC_MANAGER Manager;
    WORK_QUEUE_ITEM WorkItem;
} ENC_ROTATION_CONTEXT, *PENC_ROTATION_CONTEXT;

//=============================================================================
// Forward Declarations
//=============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS
EncpGenerateNonce(
    _Inout_ PENC_KEY Key,
    _Out_writes_bytes_(ENC_GCM_NONCE_SIZE) PUCHAR Nonce
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
EncpGetDeobfuscatedKeyMaterial(
    _In_ PENC_KEY Key,
    _Out_writes_bytes_(ENC_AES_KEY_SIZE_256) PUCHAR KeyBuffer
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
EncpInitializeBCryptKey(
    _In_ PENC_MANAGER Manager,
    _Inout_ PENC_KEY Key
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
EncpCleanupBCryptKey(
    _Inout_ PENC_KEY Key
    );

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
EncpIsKeyExpired(
    _In_ PENC_KEY Key
    );

static ULONG
EncpCalculateCrc32(
    _In_reads_bytes_(Size) PVOID Data,
    _In_ ULONG Size
    );

IO_WORKITEM_ROUTINE EncpRotationWorkItemRoutine;
KDEFERRED_ROUTINE EncpRotationDpcRoutine;

//=============================================================================
// CRC32 Table (for header integrity)
//=============================================================================

static ULONG g_Crc32Table[256];
static BOOLEAN g_Crc32TableInitialized = FALSE;

static VOID
EncpInitializeCrc32Table(
    VOID
    )
{
    ULONG i, j, crc;

    if (g_Crc32TableInitialized) {
        return;
    }

    for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ ENC_CRC32_POLYNOMIAL;
            } else {
                crc >>= 1;
            }
        }
        g_Crc32Table[i] = crc;
    }

    g_Crc32TableInitialized = TRUE;
}

static ULONG
EncpCalculateCrc32(
    _In_reads_bytes_(Size) PVOID Data,
    _In_ ULONG Size
    )
{
    PUCHAR bytes = (PUCHAR)Data;
    ULONG crc = 0xFFFFFFFF;
    ULONG i;

    for (i = 0; i < Size; i++) {
        crc = (crc >> 8) ^ g_Crc32Table[(crc ^ bytes[i]) & 0xFF];
    }

    return crc ^ 0xFFFFFFFF;
}

//=============================================================================
// Initialization / Shutdown
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EncInitialize(
    _Out_ PENC_MANAGER Manager,
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    Initializes the encryption manager. Opens BCrypt algorithm providers
    and prepares key management infrastructure.

Arguments:

    Manager - Encryption manager to initialize.
    DeviceObject - Device object for work item allocation (optional).

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    NTSTATUS status;

    PAGED_CODE();

    if (Manager == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Manager, sizeof(ENC_MANAGER));

    //
    // Initialize CRC32 table
    //
    EncpInitializeCrc32Table();

    //
    // Open AES-GCM algorithm provider
    //
    status = BCryptOpenAlgorithmProvider(
        &Manager->AesGcmAlgHandle,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Set chaining mode to GCM
    //
    status = BCryptSetProperty(
        Manager->AesGcmAlgHandle,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Open HMAC-SHA256 algorithm provider
    //
    status = BCryptOpenAlgorithmProvider(
        &Manager->HmacAlgHandle,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Open RNG provider
    //
    status = BCryptOpenAlgorithmProvider(
        &Manager->RngAlgHandle,
        BCRYPT_RNG_ALGORITHM,
        NULL,
        0
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Initialize key list with ERESOURCE for reader/writer access
    //
    InitializeListHead(&Manager->KeyList);
    status = ExInitializeResourceLite(&Manager->KeyListLock);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    Manager->KeyCount = 0;
    Manager->NextKeyId = 1;

    //
    // Initialize active keys lock
    //
    KeInitializeSpinLock(&Manager->ActiveKeysLock);
    RtlZeroMemory(Manager->ActiveKeys, sizeof(Manager->ActiveKeys));

    //
    // Initialize rotation timer and DPC
    //
    KeInitializeTimer(&Manager->RotationTimer);
    KeInitializeDpc(&Manager->RotationDpc, EncpRotationDpcRoutine, Manager);
    Manager->RotationIntervalSeconds = ENC_KEY_ROTATION_INTERVAL;
    Manager->AutoRotationEnabled = FALSE;
    Manager->RotationInProgress = FALSE;

    //
    // Store device object and allocate work item if provided
    //
    Manager->DeviceObject = DeviceObject;
    if (DeviceObject != NULL) {
        Manager->RotationWorkItem = IoAllocateWorkItem(DeviceObject);
        if (Manager->RotationWorkItem == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
    }

    //
    // Initialize master key mutex
    //
    ExInitializeFastMutex(&Manager->MasterKeyMutex);
    Manager->MasterKeySet = FALSE;
    Manager->MasterKeyObfuscation = NULL;

    //
    // Set default configuration
    //
    Manager->Config.DefaultAlgorithm = EncAlgorithm_AES_256_GCM;
    Manager->Config.DefaultTagSize = ENC_GCM_TAG_SIZE;
    Manager->Config.RequireNonPagedKeys = TRUE;
    Manager->Config.EnableAutoRotation = FALSE;
    Manager->Config.KeyExpirationSeconds = ENC_KEY_ROTATION_INTERVAL;

    //
    // Initialize statistics
    //
    Manager->TotalEncryptions = 0;
    Manager->TotalDecryptions = 0;
    Manager->BytesEncrypted = 0;
    Manager->BytesDecrypted = 0;
    Manager->AuthFailures = 0;
    Manager->KeyRotations = 0;

    Manager->Initialized = TRUE;

    return STATUS_SUCCESS;

Cleanup:
    if (Manager->RotationWorkItem != NULL) {
        IoFreeWorkItem(Manager->RotationWorkItem);
        Manager->RotationWorkItem = NULL;
    }
    if (Manager->RngAlgHandle != NULL) {
        BCryptCloseAlgorithmProvider(Manager->RngAlgHandle, 0);
        Manager->RngAlgHandle = NULL;
    }
    if (Manager->HmacAlgHandle != NULL) {
        BCryptCloseAlgorithmProvider(Manager->HmacAlgHandle, 0);
        Manager->HmacAlgHandle = NULL;
    }
    if (Manager->AesGcmAlgHandle != NULL) {
        BCryptCloseAlgorithmProvider(Manager->AesGcmAlgHandle, 0);
        Manager->AesGcmAlgHandle = NULL;
    }

    return status;
}


_Use_decl_annotations_
VOID
EncShutdown(
    _Inout_ PENC_MANAGER Manager
    )
/*++

Routine Description:

    Shuts down the encryption manager. Destroys all keys and closes
    algorithm providers.

--*/
{
    PLIST_ENTRY entry;
    PENC_KEY key;
    LIST_ENTRY keysToFree;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized) {
        return;
    }

    Manager->Initialized = FALSE;

    //
    // Cancel rotation timer and wait for DPC to complete
    //
    KeCancelTimer(&Manager->RotationTimer);
    KeFlushQueuedDpcs();

    //
    // Free work item
    //
    if (Manager->RotationWorkItem != NULL) {
        IoFreeWorkItem(Manager->RotationWorkItem);
        Manager->RotationWorkItem = NULL;
    }

    //
    // Collect all keys under exclusive lock
    //
    InitializeListHead(&keysToFree);

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Manager->KeyListLock, TRUE);

    while (!IsListEmpty(&Manager->KeyList)) {
        entry = RemoveHeadList(&Manager->KeyList);
        key = CONTAINING_RECORD(entry, ENC_KEY, ListEntry);
        key->RemovedFromList = TRUE;
        InsertTailList(&keysToFree, entry);
    }

    Manager->KeyCount = 0;
    RtlZeroMemory(Manager->ActiveKeys, sizeof(Manager->ActiveKeys));

    ExReleaseResourceLite(&Manager->KeyListLock);
    KeLeaveCriticalRegion();

    //
    // Destroy all keys outside of lock
    //
    while (!IsListEmpty(&keysToFree)) {
        entry = RemoveHeadList(&keysToFree);
        key = CONTAINING_RECORD(entry, ENC_KEY, ListEntry);

        //
        // Direct cleanup since key is already removed from list
        //
        EncpCleanupBCryptKey(key);

        EncSecureClear(key->KeyMaterial, sizeof(key->KeyMaterial));

        if (key->ObfuscationKey != NULL) {
            EncSecureClear(key->ObfuscationKey, ENC_AES_KEY_SIZE_256);
            ShadowStrikeFreePoolWithTag(key->ObfuscationKey, ENC_POOL_TAG_OBFUSK);
        }

        PENC_KEY_INTERNAL keyInternal = CONTAINING_RECORD(key, ENC_KEY_INTERNAL, Key);
        keyInternal->Signature = 0;
        ShadowStrikeFreePoolWithTag(keyInternal, ENC_POOL_TAG_KEY);
    }

    //
    // Clear master key
    //
    ExAcquireFastMutex(&Manager->MasterKeyMutex);
    EncSecureClear(Manager->MasterKey, sizeof(Manager->MasterKey));
    if (Manager->MasterKeyObfuscation != NULL) {
        EncSecureClear(Manager->MasterKeyObfuscation, ENC_AES_KEY_SIZE_256);
        ShadowStrikeFreePoolWithTag(Manager->MasterKeyObfuscation, ENC_POOL_TAG_OBFUSK);
        Manager->MasterKeyObfuscation = NULL;
    }
    Manager->MasterKeySet = FALSE;
    ExReleaseFastMutex(&Manager->MasterKeyMutex);

    //
    // Delete ERESOURCE
    //
    ExDeleteResourceLite(&Manager->KeyListLock);

    //
    // Close algorithm providers
    //
    if (Manager->RngAlgHandle != NULL) {
        BCryptCloseAlgorithmProvider(Manager->RngAlgHandle, 0);
        Manager->RngAlgHandle = NULL;
    }

    if (Manager->HmacAlgHandle != NULL) {
        BCryptCloseAlgorithmProvider(Manager->HmacAlgHandle, 0);
        Manager->HmacAlgHandle = NULL;
    }

    if (Manager->AesGcmAlgHandle != NULL) {
        BCryptCloseAlgorithmProvider(Manager->AesGcmAlgHandle, 0);
        Manager->AesGcmAlgHandle = NULL;
    }
}


_Use_decl_annotations_
NTSTATUS
EncSetMasterKey(
    _Inout_ PENC_MANAGER Manager,
    _In_reads_bytes_(KeySize) PUCHAR Key,
    _In_ ULONG KeySize
    )
/*++

Routine Description:

    Sets the master key used for key derivation. The master key
    is stored obfuscated in memory.

--*/
{
    NTSTATUS status;
    PUCHAR obfuscation = NULL;
    ULONG i;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Key == NULL || KeySize == 0 || KeySize > ENC_AES_KEY_SIZE_256) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate obfuscation key in separate allocation
    //
    obfuscation = (PUCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        ENC_AES_KEY_SIZE_256,
        ENC_POOL_TAG_OBFUSK
        );

    if (obfuscation == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Generate random obfuscation key
    //
    status = BCryptGenRandom(
        Manager->RngAlgHandle,
        obfuscation,
        ENC_AES_KEY_SIZE_256,
        0
        );

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(obfuscation, ENC_POOL_TAG_OBFUSK);
        return status;
    }

    ExAcquireFastMutex(&Manager->MasterKeyMutex);

    //
    // Clear existing master key
    //
    EncSecureClear(Manager->MasterKey, sizeof(Manager->MasterKey));
    if (Manager->MasterKeyObfuscation != NULL) {
        EncSecureClear(Manager->MasterKeyObfuscation, ENC_AES_KEY_SIZE_256);
        ShadowStrikeFreePoolWithTag(Manager->MasterKeyObfuscation, ENC_POOL_TAG_OBFUSK);
    }

    //
    // Copy and obfuscate new master key
    //
    RtlCopyMemory(Manager->MasterKey, Key, KeySize);
    if (KeySize < ENC_AES_KEY_SIZE_256) {
        RtlZeroMemory(Manager->MasterKey + KeySize, ENC_AES_KEY_SIZE_256 - KeySize);
    }

    //
    // XOR with obfuscation key
    //
    for (i = 0; i < ENC_AES_KEY_SIZE_256; i++) {
        Manager->MasterKey[i] ^= obfuscation[i];
    }

    Manager->MasterKeyObfuscation = obfuscation;
    Manager->MasterKeySet = TRUE;

    ExReleaseFastMutex(&Manager->MasterKeyMutex);

    return STATUS_SUCCESS;
}


//=============================================================================
// Key Management
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EncGenerateKey(
    _In_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType,
    _In_ ENC_ALGORITHM Algorithm,
    _Out_ PENC_KEY* Key
    )
/*++

Routine Description:

    Generates a new cryptographically random encryption key.

--*/
{
    PENC_KEY_INTERNAL keyInternal = NULL;
    PENC_KEY key = NULL;
    NTSTATUS status;
    ULONG keySize;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized || Key == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ENC_VALID_KEY_TYPE(KeyType)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ENC_VALID_ALGORITHM(Algorithm)) {
        return STATUS_INVALID_PARAMETER;
    }

    *Key = NULL;

    //
    // Check key limit
    //
    if (Manager->KeyCount >= ENC_MAX_KEYS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Determine key size based on algorithm
    //
    switch (Algorithm) {
        case EncAlgorithm_AES_128_GCM:
            keySize = ENC_AES_KEY_SIZE_128;
            break;

        case EncAlgorithm_AES_256_GCM:
            keySize = ENC_AES_KEY_SIZE_256;
            break;

        default:
            return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate key structure from non-paged pool
    //
    keyInternal = (PENC_KEY_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ENC_KEY_INTERNAL),
        ENC_POOL_TAG_KEY
        );

    if (keyInternal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(keyInternal, sizeof(ENC_KEY_INTERNAL));

    keyInternal->Signature = ENC_SIGNATURE;
    keyInternal->Manager = Manager;
    keyInternal->Destroying = FALSE;

    key = &keyInternal->Key;

    //
    // Initialize mutex for obfuscation
    //
    ExInitializeFastMutex(&key->ObfuscationMutex);

    //
    // Allocate obfuscation key in separate allocation
    //
    key->ObfuscationKey = (PUCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        ENC_AES_KEY_SIZE_256,
        ENC_POOL_TAG_OBFUSK
        );

    if (key->ObfuscationKey == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    //
    // Generate key ID (64-bit, no overflow concern)
    //
    key->KeyId = (ULONG64)InterlockedIncrement64(&Manager->NextKeyId);
    key->KeyType = KeyType;
    key->Algorithm = Algorithm;
    key->KeySize = keySize;

    //
    // Generate random key material
    //
    status = BCryptGenRandom(
        Manager->RngAlgHandle,
        key->KeyMaterial,
        keySize,
        0
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Generate obfuscation key
    //
    status = BCryptGenRandom(
        Manager->RngAlgHandle,
        key->ObfuscationKey,
        keySize,
        0
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Generate nonce prefix (first 4 bytes)
    //
    status = BCryptGenRandom(
        Manager->RngAlgHandle,
        key->NoncePrefix,
        sizeof(key->NoncePrefix),
        0
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Initialize nonce counter and lock
    //
    key->NonceCounter = 0;
    KeInitializeSpinLock(&key->NonceLock);

    //
    // Store algorithm handle reference for temp key creation in encrypt/decrypt.
    // We deliberately do NOT create a persistent BCrypt key handle here:
    // the key material is about to be obfuscated, and a persistent handle
    // would retain the unobfuscated key in BCrypt internal buffers, defeating
    // the obfuscation scheme. Encrypt/decrypt create ephemeral handles.
    //
    key->AlgHandle = Manager->AesGcmAlgHandle;

    //
    // Set key lifecycle
    //
    KeQuerySystemTimePrecise(&key->CreationTime);
    key->ExpirationTime.QuadPart = key->CreationTime.QuadPart +
        ((LONGLONG)Manager->Config.KeyExpirationSeconds * 10000000LL);
    key->UseCount = 0;
    key->IsActive = TRUE;
    key->IsExpired = FALSE;

    //
    // Initialize reference count and state
    //
    key->RefCount = 1;
    key->IsBeingDestroyed = FALSE;
    key->RemovedFromList = FALSE;

    //
    // Obfuscate key material in memory
    //
    ExAcquireFastMutex(&key->ObfuscationMutex);
    for (ULONG i = 0; i < key->KeySize; i++) {
        key->KeyMaterial[i] ^= key->ObfuscationKey[i];
    }
    key->IsObfuscated = TRUE;
    ExReleaseFastMutex(&key->ObfuscationMutex);

    //
    // Add to key list under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Manager->KeyListLock, TRUE);
    InsertTailList(&Manager->KeyList, &key->ListEntry);
    Manager->KeyCount++;
    ExReleaseResourceLite(&Manager->KeyListLock);
    KeLeaveCriticalRegion();

    *Key = key;

    return STATUS_SUCCESS;

Cleanup:
    if (keyInternal != NULL) {
        if (key->ObfuscationKey != NULL) {
            EncSecureClear(key->ObfuscationKey, ENC_AES_KEY_SIZE_256);
            ShadowStrikeFreePoolWithTag(key->ObfuscationKey, ENC_POOL_TAG_OBFUSK);
        }
        EncSecureClear(keyInternal, sizeof(ENC_KEY_INTERNAL));
        ShadowStrikeFreePoolWithTag(keyInternal, ENC_POOL_TAG_KEY);
    }

    return status;
}


_Use_decl_annotations_
NTSTATUS
EncDeriveKey(
    _In_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType,
    _In_ ENC_ALGORITHM Algorithm,
    _In_reads_bytes_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _Out_ PENC_KEY* Key
    )
/*++

Routine Description:

    Derives a key from the master key using HKDF.

--*/
{
    PENC_KEY_INTERNAL keyInternal = NULL;
    PENC_KEY key = NULL;
    NTSTATUS status;
    ULONG keySize;
    UCHAR salt[ENC_HKDF_SALT_SIZE];
    UCHAR deobfuscatedMasterKey[ENC_AES_KEY_SIZE_256];
    ULONG i;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized || Key == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Manager->MasterKeySet) {
        return STATUS_ENCRYPTION_FAILED;
    }

    if (Context == NULL || ContextSize == 0 || ContextSize > ENC_HKDF_INFO_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ENC_VALID_KEY_TYPE(KeyType) || !ENC_VALID_ALGORITHM(Algorithm)) {
        return STATUS_INVALID_PARAMETER;
    }

    *Key = NULL;

    //
    // Determine key size
    //
    switch (Algorithm) {
        case EncAlgorithm_AES_128_GCM:
            keySize = ENC_AES_KEY_SIZE_128;
            break;

        case EncAlgorithm_AES_256_GCM:
            keySize = ENC_AES_KEY_SIZE_256;
            break;

        default:
            return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate key structure
    //
    keyInternal = (PENC_KEY_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ENC_KEY_INTERNAL),
        ENC_POOL_TAG_KEY
        );

    if (keyInternal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(keyInternal, sizeof(ENC_KEY_INTERNAL));

    keyInternal->Signature = ENC_SIGNATURE;
    keyInternal->Manager = Manager;

    key = &keyInternal->Key;
    ExInitializeFastMutex(&key->ObfuscationMutex);

    //
    // Allocate obfuscation key
    //
    key->ObfuscationKey = (PUCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        ENC_AES_KEY_SIZE_256,
        ENC_POOL_TAG_OBFUSK
        );

    if (key->ObfuscationKey == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    //
    // Generate random salt
    //
    status = BCryptGenRandom(
        Manager->RngAlgHandle,
        salt,
        sizeof(salt),
        0
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Get deobfuscated master key
    //
    ExAcquireFastMutex(&Manager->MasterKeyMutex);
    RtlCopyMemory(deobfuscatedMasterKey, Manager->MasterKey, ENC_AES_KEY_SIZE_256);
    if (Manager->MasterKeyObfuscation != NULL) {
        for (i = 0; i < ENC_AES_KEY_SIZE_256; i++) {
            deobfuscatedMasterKey[i] ^= Manager->MasterKeyObfuscation[i];
        }
    }
    ExReleaseFastMutex(&Manager->MasterKeyMutex);

    //
    // Derive key using HKDF
    //
    status = EncHkdfDerive(
        Manager->HmacAlgHandle,
        deobfuscatedMasterKey,
        ENC_AES_KEY_SIZE_256,
        salt,
        sizeof(salt),
        Context,
        ContextSize,
        key->KeyMaterial,
        keySize
        );

    //
    // Clear deobfuscated master key immediately
    //
    EncSecureClear(deobfuscatedMasterKey, sizeof(deobfuscatedMasterKey));

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    key->KeyId = (ULONG64)InterlockedIncrement64(&Manager->NextKeyId);
    key->KeyType = KeyType;
    key->Algorithm = Algorithm;
    key->KeySize = keySize;

    //
    // Generate obfuscation key
    //
    status = BCryptGenRandom(
        Manager->RngAlgHandle,
        key->ObfuscationKey,
        keySize,
        0
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Generate nonce prefix
    //
    status = BCryptGenRandom(
        Manager->RngAlgHandle,
        key->NoncePrefix,
        sizeof(key->NoncePrefix),
        0
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    key->NonceCounter = 0;
    KeInitializeSpinLock(&key->NonceLock);

    //
    // Store algorithm handle — no persistent BCrypt key handle (see EncGenerateKey)
    //
    key->AlgHandle = Manager->AesGcmAlgHandle;

    //
    // Set lifecycle
    //
    KeQuerySystemTimePrecise(&key->CreationTime);
    key->ExpirationTime.QuadPart = key->CreationTime.QuadPart +
        ((LONGLONG)Manager->Config.KeyExpirationSeconds * 10000000LL);
    key->UseCount = 0;
    key->IsActive = TRUE;
    key->IsExpired = FALSE;
    key->RefCount = 1;
    key->IsBeingDestroyed = FALSE;
    key->RemovedFromList = FALSE;

    //
    // Obfuscate key
    //
    ExAcquireFastMutex(&key->ObfuscationMutex);
    for (i = 0; i < key->KeySize; i++) {
        key->KeyMaterial[i] ^= key->ObfuscationKey[i];
    }
    key->IsObfuscated = TRUE;
    ExReleaseFastMutex(&key->ObfuscationMutex);

    //
    // Add to key list
    //
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Manager->KeyListLock, TRUE);
    InsertTailList(&Manager->KeyList, &key->ListEntry);
    Manager->KeyCount++;
    ExReleaseResourceLite(&Manager->KeyListLock);
    KeLeaveCriticalRegion();

    //
    // Clear salt
    //
    EncSecureClear(salt, sizeof(salt));

    *Key = key;

    return STATUS_SUCCESS;

Cleanup:
    EncSecureClear(salt, sizeof(salt));
    EncSecureClear(deobfuscatedMasterKey, sizeof(deobfuscatedMasterKey));

    if (keyInternal != NULL) {
        if (key->ObfuscationKey != NULL) {
            EncSecureClear(key->ObfuscationKey, ENC_AES_KEY_SIZE_256);
            ShadowStrikeFreePoolWithTag(key->ObfuscationKey, ENC_POOL_TAG_OBFUSK);
        }
        EncSecureClear(keyInternal, sizeof(ENC_KEY_INTERNAL));
        ShadowStrikeFreePoolWithTag(keyInternal, ENC_POOL_TAG_KEY);
    }

    return status;
}


_Use_decl_annotations_
NTSTATUS
EncImportKey(
    _In_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType,
    _In_ ENC_ALGORITHM Algorithm,
    _In_reads_bytes_(KeySize) PUCHAR KeyMaterial,
    _In_ ULONG KeySize,
    _Out_ PENC_KEY* Key
    )
/*++

Routine Description:

    Imports an existing key from raw material.

--*/
{
    PENC_KEY_INTERNAL keyInternal = NULL;
    PENC_KEY key = NULL;
    NTSTATUS status;
    ULONG expectedKeySize;
    ULONG i;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized || Key == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeyMaterial == NULL || KeySize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ENC_VALID_KEY_TYPE(KeyType) || !ENC_VALID_ALGORITHM(Algorithm)) {
        return STATUS_INVALID_PARAMETER;
    }

    *Key = NULL;

    //
    // Validate key size for algorithm
    //
    switch (Algorithm) {
        case EncAlgorithm_AES_128_GCM:
            expectedKeySize = ENC_AES_KEY_SIZE_128;
            break;

        case EncAlgorithm_AES_256_GCM:
            expectedKeySize = ENC_AES_KEY_SIZE_256;
            break;

        default:
            return STATUS_INVALID_PARAMETER;
    }

    if (KeySize != expectedKeySize) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate key structure
    //
    keyInternal = (PENC_KEY_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ENC_KEY_INTERNAL),
        ENC_POOL_TAG_KEY
        );

    if (keyInternal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(keyInternal, sizeof(ENC_KEY_INTERNAL));

    keyInternal->Signature = ENC_SIGNATURE;
    keyInternal->Manager = Manager;

    key = &keyInternal->Key;
    ExInitializeFastMutex(&key->ObfuscationMutex);

    //
    // Allocate obfuscation key
    //
    key->ObfuscationKey = (PUCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        ENC_AES_KEY_SIZE_256,
        ENC_POOL_TAG_OBFUSK
        );

    if (key->ObfuscationKey == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    //
    // Copy key material
    //
    RtlCopyMemory(key->KeyMaterial, KeyMaterial, KeySize);

    key->KeyId = (ULONG64)InterlockedIncrement64(&Manager->NextKeyId);
    key->KeyType = KeyType;
    key->Algorithm = Algorithm;
    key->KeySize = KeySize;

    //
    // Generate obfuscation key
    //
    status = BCryptGenRandom(
        Manager->RngAlgHandle,
        key->ObfuscationKey,
        KeySize,
        0
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Generate nonce prefix
    //
    status = BCryptGenRandom(
        Manager->RngAlgHandle,
        key->NoncePrefix,
        sizeof(key->NoncePrefix),
        0
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    key->NonceCounter = 0;
    KeInitializeSpinLock(&key->NonceLock);

    //
    // Store algorithm handle — no persistent BCrypt key handle (see EncGenerateKey)
    //
    key->AlgHandle = Manager->AesGcmAlgHandle;

    //
    // Set lifecycle
    //
    KeQuerySystemTimePrecise(&key->CreationTime);
    key->ExpirationTime.QuadPart = key->CreationTime.QuadPart +
        ((LONGLONG)Manager->Config.KeyExpirationSeconds * 10000000LL);
    key->UseCount = 0;
    key->IsActive = TRUE;
    key->IsExpired = FALSE;
    key->RefCount = 1;
    key->IsBeingDestroyed = FALSE;
    key->RemovedFromList = FALSE;

    //
    // Obfuscate key
    //
    ExAcquireFastMutex(&key->ObfuscationMutex);
    for (i = 0; i < key->KeySize; i++) {
        key->KeyMaterial[i] ^= key->ObfuscationKey[i];
    }
    key->IsObfuscated = TRUE;
    ExReleaseFastMutex(&key->ObfuscationMutex);

    //
    // Add to key list
    //
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Manager->KeyListLock, TRUE);
    InsertTailList(&Manager->KeyList, &key->ListEntry);
    Manager->KeyCount++;
    ExReleaseResourceLite(&Manager->KeyListLock);
    KeLeaveCriticalRegion();

    *Key = key;

    return STATUS_SUCCESS;

Cleanup:
    if (keyInternal != NULL) {
        if (key->ObfuscationKey != NULL) {
            EncSecureClear(key->ObfuscationKey, ENC_AES_KEY_SIZE_256);
            ShadowStrikeFreePoolWithTag(key->ObfuscationKey, ENC_POOL_TAG_OBFUSK);
        }
        EncSecureClear(keyInternal, sizeof(ENC_KEY_INTERNAL));
        ShadowStrikeFreePoolWithTag(keyInternal, ENC_POOL_TAG_KEY);
    }

    return status;
}


_Use_decl_annotations_
NTSTATUS
EncExportKey(
    _In_ PENC_KEY Key,
    _Out_writes_bytes_to_(BufferSize, *ExportedSize) PUCHAR Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG ExportedSize
    )
/*++

Routine Description:

    Exports key material for backup/transfer.
    Uses mutex to safely access obfuscated key.

--*/
{
    NTSTATUS status;
    UCHAR deobfuscatedKey[ENC_AES_KEY_SIZE_256];

    PAGED_CODE();

    if (Key == NULL || Buffer == NULL || ExportedSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ExportedSize = 0;

    if (BufferSize < Key->KeySize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Get deobfuscated key material safely
    //
    status = EncpGetDeobfuscatedKeyMaterial(Key, deobfuscatedKey);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Copy to output buffer
    //
    RtlCopyMemory(Buffer, deobfuscatedKey, Key->KeySize);
    *ExportedSize = Key->KeySize;

    //
    // Clear temporary buffer
    //
    EncSecureClear(deobfuscatedKey, sizeof(deobfuscatedKey));

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
EncDestroyKey(
    _In_ PENC_MANAGER Manager,
    _Inout_ PENC_KEY Key
    )
/*++

Routine Description:

    Securely destroys a key, zeroing all sensitive material.
    Removes from list before freeing to prevent use-after-free.

--*/
{
    PENC_KEY_INTERNAL keyInternal;
    BOOLEAN wasInList = FALSE;
    KIRQL oldIrql;
    LARGE_INTEGER drainDelay;
    ULONG drainWaitCount;

    PAGED_CODE();

    if (Key == NULL || Manager == NULL) {
        return;
    }

    keyInternal = CONTAINING_RECORD(Key, ENC_KEY_INTERNAL, Key);

    if (keyInternal->Signature != ENC_SIGNATURE) {
        return;
    }

    //
    // Mark as being destroyed to prevent concurrent access
    //
    if (InterlockedCompareExchange((LONG*)&keyInternal->Destroying, TRUE, FALSE) == TRUE) {
        // Already being destroyed by another thread
        return;
    }

    Key->IsActive = FALSE;
    Key->IsBeingDestroyed = TRUE;

    //
    // Remove from list under exclusive lock BEFORE freeing
    //
    if (!Key->RemovedFromList) {
        KeEnterCriticalRegion();
        ExAcquireResourceExclusiveLite(&Manager->KeyListLock, TRUE);

        if (!Key->RemovedFromList) {
            RemoveEntryList(&Key->ListEntry);
            Key->RemovedFromList = TRUE;
            Manager->KeyCount--;
            wasInList = TRUE;
        }

        ExReleaseResourceLite(&Manager->KeyListLock);
        KeLeaveCriticalRegion();
    }

    //
    // Clear from active keys if present
    //
    KeAcquireSpinLock(&Manager->ActiveKeysLock, &oldIrql);
    for (ULONG i = 0; i < EncKeyType_Max; i++) {
        if (Manager->ActiveKeys[i] == Key) {
            Manager->ActiveKeys[i] = NULL;
        }
    }
    KeReleaseSpinLock(&Manager->ActiveKeysLock, oldIrql);

    //
    // Drain in-flight references before freeing.
    // After marking IsBeingDestroyed and removing from all lists,
    // no new AddRefs can succeed. Wait for existing holders to release.
    //
    drainDelay.QuadPart = -10000LL;  // 1ms
    drainWaitCount = 0;

    while (ReadNoFence(&Key->RefCount) > 0) {
        if (++drainWaitCount > 5000) {
            //
            // 5 second timeout — break to avoid driver hang.
            // Remaining refs are leaked encrypt/decrypt operations.
            //
            break;
        }
        KeDelayExecutionThread(KernelMode, FALSE, &drainDelay);
    }

    //
    // Cleanup BCrypt handles
    //
    EncpCleanupBCryptKey(Key);

    //
    // Securely clear key material
    //
    ExAcquireFastMutex(&Key->ObfuscationMutex);
    EncSecureClear(Key->KeyMaterial, sizeof(Key->KeyMaterial));
    ExReleaseFastMutex(&Key->ObfuscationMutex);

    //
    // Free obfuscation key
    //
    if (Key->ObfuscationKey != NULL) {
        EncSecureClear(Key->ObfuscationKey, ENC_AES_KEY_SIZE_256);
        ShadowStrikeFreePoolWithTag(Key->ObfuscationKey, ENC_POOL_TAG_OBFUSK);
        Key->ObfuscationKey = NULL;
    }

    EncSecureClear(Key->NoncePrefix, sizeof(Key->NoncePrefix));

    //
    // Clear signature and free
    //
    keyInternal->Signature = 0;

    ShadowStrikeFreePoolWithTag(keyInternal, ENC_POOL_TAG_KEY);
}


_Use_decl_annotations_
PENC_KEY
EncGetActiveKey(
    _In_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType
    )
{
    PENC_KEY key;
    KIRQL oldIrql;

    if (Manager == NULL || !Manager->Initialized) {
        return NULL;
    }

    if (!ENC_VALID_KEY_TYPE(KeyType)) {
        return NULL;
    }

    KeAcquireSpinLock(&Manager->ActiveKeysLock, &oldIrql);
    key = Manager->ActiveKeys[KeyType];
    if (key != NULL && !EncKeyAddRef(key)) {
        key = NULL;
    }
    KeReleaseSpinLock(&Manager->ActiveKeysLock, oldIrql);

    return key;
}


_Use_decl_annotations_
NTSTATUS
EncSetActiveKey(
    _Inout_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType,
    _In_ PENC_KEY Key
    )
{
    KIRQL oldIrql;
    PENC_KEY oldKey;

    if (Manager == NULL || !Manager->Initialized || Key == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ENC_VALID_KEY_TYPE(KeyType)) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Manager->ActiveKeysLock, &oldIrql);

    oldKey = Manager->ActiveKeys[KeyType];
    Manager->ActiveKeys[KeyType] = Key;
    if (!EncKeyAddRef(Key)) {
        //
        // Key is being destroyed — cannot set as active
        //
        Manager->ActiveKeys[KeyType] = oldKey;
        KeReleaseSpinLock(&Manager->ActiveKeysLock, oldIrql);
        return STATUS_UNSUCCESSFUL;
    }

    KeReleaseSpinLock(&Manager->ActiveKeysLock, oldIrql);

    //
    // Release old key reference outside lock
    //
    if (oldKey != NULL) {
        EncKeyRelease(oldKey);
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
BOOLEAN
EncKeyAddRef(
    _In_ PENC_KEY Key
    )
{
    LONG oldRef;
    LONG newRef;

    if (Key == NULL) {
        return FALSE;
    }

    //
    // CAS loop: atomically check IsBeingDestroyed and increment RefCount.
    // This eliminates the TOCTOU window between checking the flag and
    // modifying the counter.
    //
    do {
        oldRef = ReadNoFence(&Key->RefCount);

        if (oldRef <= 0 || Key->IsBeingDestroyed) {
            return FALSE;
        }

        newRef = oldRef + 1;

    } while (InterlockedCompareExchange(&Key->RefCount, newRef, oldRef) != oldRef);

    return TRUE;
}


_Use_decl_annotations_
LONG
EncKeyRelease(
    _In_ PENC_KEY Key
    )
{
    LONG newCount;

    if (Key == NULL) {
        return 0;
    }

    newCount = InterlockedDecrement(&Key->RefCount);

    //
    // Note: Caller must explicitly call EncDestroyKey when ready
    // to destroy the key. We don't auto-destroy here to avoid
    // issues with circular references and shutdown ordering.
    //

    return newCount;
}


//=============================================================================
// Simple Encryption / Decryption
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EncEncrypt(
    _In_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType,
    _In_reads_bytes_(PlaintextSize) PVOID Plaintext,
    _In_ ULONG PlaintextSize,
    _Out_writes_bytes_to_(OutputSize, *CiphertextSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG CiphertextSize,
    _In_opt_ PENC_OPTIONS Options
    )
/*++

Routine Description:

    Encrypts data using AES-256-GCM with automatic nonce generation.
    All operations at PASSIVE_LEVEL as required by BCrypt.

--*/
{
    NTSTATUS status;
    PENC_KEY key = NULL;
    PENC_HEADER header;
    PUCHAR ciphertext;
    ULONG requiredSize;
    UCHAR nonce[ENC_GCM_NONCE_SIZE];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    ULONG cbResult;
    UCHAR localKeyMaterial[ENC_AES_KEY_SIZE_256];
    BCRYPT_KEY_HANDLE tempKeyHandle = NULL;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Plaintext == NULL || PlaintextSize == 0 || Output == NULL || CiphertextSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ENC_VALID_SIZE(PlaintextSize)) {
        return STATUS_INVALID_PARAMETER;
    }

    *CiphertextSize = 0;

    //
    // Calculate required output size with overflow check
    //
    status = EncGetEncryptedSize(PlaintextSize, TRUE, &requiredSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (OutputSize < requiredSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Get key
    //
    if (Options != NULL && Options->Key != NULL) {
        key = Options->Key;
        if (!EncKeyAddRef(key)) {
            return STATUS_ENCRYPTION_FAILED;
        }
    } else {
        key = EncGetActiveKey(Manager, KeyType);
        if (key == NULL) {
            return STATUS_ENCRYPTION_FAILED;
        }
    }

    //
    // Check if key is expired
    //
    if (EncpIsKeyExpired(key)) {
        EncKeyRelease(key);
        return STATUS_ENCRYPTION_FAILED;
    }

    //
    // Generate unique nonce
    //
    status = EncpGenerateNonce(key, nonce);
    if (!NT_SUCCESS(status)) {
        EncKeyRelease(key);
        return status;
    }

    //
    // Get deobfuscated key material into local buffer
    //
    status = EncpGetDeobfuscatedKeyMaterial(key, localKeyMaterial);
    if (!NT_SUCCESS(status)) {
        EncKeyRelease(key);
        return status;
    }

    //
    // Create temporary key handle for this operation
    //
    status = BCryptGenerateSymmetricKey(
        Manager->AesGcmAlgHandle,
        &tempKeyHandle,
        NULL,
        0,
        localKeyMaterial,
        key->KeySize,
        0
        );

    //
    // Clear local key material immediately after creating handle
    //
    EncSecureClear(localKeyMaterial, sizeof(localKeyMaterial));

    if (!NT_SUCCESS(status)) {
        EncKeyRelease(key);
        return status;
    }

    //
    // Setup header - copy to local first to avoid TOCTOU
    //
    header = (PENC_HEADER)Output;
    RtlZeroMemory(header, sizeof(ENC_HEADER));
    header->Magic = ENC_MAGIC;
    header->Version = ENC_VERSION;
    header->Algorithm = (USHORT)key->Algorithm;
    header->Flags = (Options != NULL) ? Options->Flags : 0;
    header->PlaintextSize = PlaintextSize;
    header->CiphertextSize = PlaintextSize;  // GCM doesn't pad
    RtlCopyMemory(header->Nonce, nonce, ENC_GCM_NONCE_SIZE);
    header->KeyId = key->KeyId;
    header->AADSize = (Options != NULL) ? Options->AADSize : 0;
    {
        LARGE_INTEGER encTimestamp;
        KeQuerySystemTimePrecise(&encTimestamp);
        RtlCopyMemory(&header->Timestamp, &encTimestamp, sizeof(LARGE_INTEGER));
    }

    ciphertext = (PUCHAR)Output + sizeof(ENC_HEADER);

    //
    // Setup authenticated cipher mode info
    //
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = ENC_GCM_NONCE_SIZE;
    authInfo.pbTag = header->Tag;
    authInfo.cbTag = ENC_GCM_TAG_SIZE;

    if (Options != NULL && Options->AAD != NULL && Options->AADSize > 0) {
        if (Options->AADSize > ENC_MAX_AAD_SIZE) {
            BCryptDestroyKey(tempKeyHandle);
            EncKeyRelease(key);
            return STATUS_INVALID_PARAMETER;
        }
        authInfo.pbAuthData = (PUCHAR)Options->AAD;
        authInfo.cbAuthData = Options->AADSize;
    }

    //
    // Perform encryption
    //
    status = BCryptEncrypt(
        tempKeyHandle,
        (PUCHAR)Plaintext,
        PlaintextSize,
        &authInfo,
        NULL,
        0,
        ciphertext,
        PlaintextSize,
        &cbResult,
        0
        );

    //
    // Destroy temporary key handle
    //
    BCryptDestroyKey(tempKeyHandle);

    if (!NT_SUCCESS(status)) {
        EncKeyRelease(key);
        EncSecureClear(Output, requiredSize);
        return status;
    }

    //
    // Calculate and store header CRC (excluding CRC field itself)
    //
    header->HeaderCrc32 = EncpCalculateCrc32(header, sizeof(ENC_HEADER) - sizeof(ULONG));

    //
    // Update statistics
    //
    InterlockedIncrement64(&Manager->TotalEncryptions);
    InterlockedAdd64(&Manager->BytesEncrypted, PlaintextSize);
    InterlockedIncrement(&key->UseCount);

    *CiphertextSize = requiredSize;

    EncKeyRelease(key);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
EncDecrypt(
    _In_ PENC_MANAGER Manager,
    _In_reads_bytes_(CiphertextSize) PVOID Ciphertext,
    _In_ ULONG CiphertextSize,
    _Out_writes_bytes_to_(OutputSize, *PlaintextSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG PlaintextSize,
    _In_opt_ PENC_OPTIONS Options
    )
/*++

Routine Description:

    Decrypts data and verifies authentication tag.
    Copies header to local variable to prevent TOCTOU attacks.

--*/
{
    NTSTATUS status;
    ENC_HEADER localHeader;  // Local copy to prevent TOCTOU
    PENC_KEY key = NULL;
    PUCHAR encryptedData;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    ULONG cbResult;
    PLIST_ENTRY entry;
    UCHAR localKeyMaterial[ENC_AES_KEY_SIZE_256];
    BCRYPT_KEY_HANDLE tempKeyHandle = NULL;
    ULONG expectedCrc;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Ciphertext == NULL || CiphertextSize < sizeof(ENC_HEADER) ||
        Output == NULL || PlaintextSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *PlaintextSize = 0;

    //
    // Copy header to local variable IMMEDIATELY to prevent TOCTOU
    //
    RtlCopyMemory(&localHeader, Ciphertext, sizeof(ENC_HEADER));

    //
    // Validate header magic and version
    //
    if (localHeader.Magic != ENC_MAGIC) {
        return STATUS_DECRYPTION_FAILED;
    }

    if (localHeader.Version != ENC_VERSION) {
        return STATUS_DECRYPTION_FAILED;
    }

    //
    // Validate header CRC
    //
    expectedCrc = EncpCalculateCrc32(&localHeader, sizeof(ENC_HEADER) - sizeof(ULONG));
    if (localHeader.HeaderCrc32 != expectedCrc) {
        return STATUS_DECRYPTION_FAILED;
    }

    //
    // Validate algorithm
    //
    if (!ENC_VALID_ALGORITHM((ENC_ALGORITHM)localHeader.Algorithm)) {
        return STATUS_DECRYPTION_FAILED;
    }

    //
    // For GCM, plaintext size MUST equal ciphertext size (no padding)
    //
    if (localHeader.PlaintextSize != localHeader.CiphertextSize) {
        return STATUS_DECRYPTION_FAILED;
    }

    //
    // Validate sizes
    //
    if (!ENC_VALID_SIZE(localHeader.PlaintextSize)) {
        return STATUS_DECRYPTION_FAILED;
    }

    if (CiphertextSize < sizeof(ENC_HEADER) + localHeader.CiphertextSize) {
        return STATUS_DECRYPTION_FAILED;
    }

    if (OutputSize < localHeader.PlaintextSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (localHeader.AADSize > ENC_MAX_AAD_SIZE) {
        return STATUS_DECRYPTION_FAILED;
    }

    //
    // Find key by ID
    //
    if (Options != NULL && Options->Key != NULL) {
        key = Options->Key;
        if (!EncKeyAddRef(key)) {
            return STATUS_DECRYPTION_FAILED;
        }
    } else {
        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&Manager->KeyListLock, TRUE);

        for (entry = Manager->KeyList.Flink;
             entry != &Manager->KeyList;
             entry = entry->Flink) {

            PENC_KEY candidate = CONTAINING_RECORD(entry, ENC_KEY, ListEntry);
            if (candidate->KeyId == localHeader.KeyId && EncKeyAddRef(candidate)) {
                key = candidate;
                break;
            }
        }

        ExReleaseResourceLite(&Manager->KeyListLock);
        KeLeaveCriticalRegion();

        if (key == NULL) {
            return STATUS_DECRYPTION_FAILED;
        }
    }

    encryptedData = (PUCHAR)Ciphertext + sizeof(ENC_HEADER);

    //
    // Get deobfuscated key material
    //
    status = EncpGetDeobfuscatedKeyMaterial(key, localKeyMaterial);
    if (!NT_SUCCESS(status)) {
        EncKeyRelease(key);
        return status;
    }

    //
    // Create temporary key handle
    //
    status = BCryptGenerateSymmetricKey(
        Manager->AesGcmAlgHandle,
        &tempKeyHandle,
        NULL,
        0,
        localKeyMaterial,
        key->KeySize,
        0
        );

    EncSecureClear(localKeyMaterial, sizeof(localKeyMaterial));

    if (!NT_SUCCESS(status)) {
        EncKeyRelease(key);
        return status;
    }

    //
    // Setup authenticated cipher mode info using LOCAL header copy
    //
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)localHeader.Nonce;
    authInfo.cbNonce = ENC_GCM_NONCE_SIZE;
    authInfo.pbTag = (PUCHAR)localHeader.Tag;
    authInfo.cbTag = ENC_GCM_TAG_SIZE;

    if (Options != NULL && Options->AAD != NULL && Options->AADSize > 0) {
        authInfo.pbAuthData = (PUCHAR)Options->AAD;
        authInfo.cbAuthData = Options->AADSize;
    }

    //
    // Perform decryption
    //
    status = BCryptDecrypt(
        tempKeyHandle,
        encryptedData,
        localHeader.CiphertextSize,
        &authInfo,
        NULL,
        0,
        (PUCHAR)Output,
        OutputSize,
        &cbResult,
        0
        );

    BCryptDestroyKey(tempKeyHandle);

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&Manager->AuthFailures);
        EncKeyRelease(key);
        EncSecureClear(Output, OutputSize);
        return STATUS_AUTH_TAG_MISMATCH;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Manager->TotalDecryptions);
    InterlockedAdd64(&Manager->BytesDecrypted, localHeader.PlaintextSize);

    *PlaintextSize = localHeader.PlaintextSize;

    EncKeyRelease(key);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
EncGetEncryptedSize(
    _In_ ULONG PlaintextSize,
    _In_ BOOLEAN IncludeHeader,
    _Out_ PULONG RequiredSize
    )
/*++

Routine Description:

    Calculates required output buffer size with overflow protection.

--*/
{
    NTSTATUS status;
    ULONG size;

    if (RequiredSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *RequiredSize = 0;

    //
    // Start with plaintext size (GCM doesn't pad)
    //
    size = PlaintextSize;

    if (IncludeHeader) {
        //
        // Safe add: size + sizeof(ENC_HEADER)
        //
        status = RtlULongAdd(size, sizeof(ENC_HEADER), &size);
        if (!NT_SUCCESS(status)) {
            return STATUS_INTEGER_OVERFLOW;
        }
    }

    *RequiredSize = size;
    return STATUS_SUCCESS;
}


//=============================================================================
// Context-Based Encryption
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EncCreateContext(
    _Out_ PENC_CONTEXT* Context,
    _In_ PENC_KEY Key,
    _In_ ENC_FLAGS Flags
    )
{
    PENC_CONTEXT ctx;

    PAGED_CODE();

    if (Context == NULL || Key == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Context = NULL;

    ctx = (PENC_CONTEXT)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ENC_CONTEXT),
        ENC_POOL_TAG_CONTEXT
        );

    if (ctx == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ctx, sizeof(ENC_CONTEXT));

    ctx->CurrentKey = Key;
    if (!EncKeyAddRef(Key)) {
        ShadowStrikeFreePoolWithTag(ctx, ENC_POOL_TAG_CONTEXT);
        return STATUS_UNSUCCESSFUL;
    }

    ctx->Algorithm = Key->Algorithm;
    ctx->Flags = Flags;
    ctx->TagSize = ENC_GCM_TAG_SIZE;

    ExInitializeFastMutex(&ctx->ContextMutex);

    *Context = ctx;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
EncDestroyContext(
    _Inout_ PENC_CONTEXT Context
    )
{
    PAGED_CODE();

    if (Context == NULL) {
        return;
    }

    ExAcquireFastMutex(&Context->ContextMutex);

    //
    // Release key reference
    //
    if (Context->CurrentKey != NULL) {
        EncKeyRelease(Context->CurrentKey);
        Context->CurrentKey = NULL;
    }

    //
    // Free AAD buffer
    //
    if (Context->AADBuffer != NULL) {
        EncSecureClear(Context->AADBuffer, Context->AADSize);
        ShadowStrikeFreePoolWithTag(Context->AADBuffer, ENC_POOL_TAG_BUFFER);
        Context->AADBuffer = NULL;
    }

    ExReleaseFastMutex(&Context->ContextMutex);

    ShadowStrikeFreePoolWithTag(Context, ENC_POOL_TAG_CONTEXT);
}


_Use_decl_annotations_
NTSTATUS
EncSetAAD(
    _Inout_ PENC_CONTEXT Context,
    _In_reads_bytes_(AADSize) PVOID AAD,
    _In_ ULONG AADSize
    )
/*++

Routine Description:

    Sets AAD for context with proper synchronization.

--*/
{
    PVOID newBuffer;
    PVOID oldBuffer = NULL;
    ULONG oldSize = 0;

    PAGED_CODE();

    if (Context == NULL || AAD == NULL || AADSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (AADSize > ENC_MAX_AAD_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate new AAD buffer
    //
    newBuffer = ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        AADSize,
        ENC_POOL_TAG_BUFFER
        );

    if (newBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newBuffer, AAD, AADSize);

    //
    // Swap buffers under mutex
    //
    ExAcquireFastMutex(&Context->ContextMutex);

    oldBuffer = Context->AADBuffer;
    oldSize = Context->AADSize;

    Context->AADBuffer = newBuffer;
    Context->AADSize = AADSize;

    ExReleaseFastMutex(&Context->ContextMutex);

    //
    // Free old buffer outside lock
    //
    if (oldBuffer != NULL) {
        EncSecureClear(oldBuffer, oldSize);
        ShadowStrikeFreePoolWithTag(oldBuffer, ENC_POOL_TAG_BUFFER);
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
EncEncryptWithContext(
    _In_ PENC_CONTEXT Context,
    _In_ PENC_MANAGER Manager,
    _In_reads_bytes_(PlaintextSize) PVOID Plaintext,
    _In_ ULONG PlaintextSize,
    _Out_writes_bytes_to_(OutputSize, *CiphertextSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG CiphertextSize
    )
{
    ENC_OPTIONS options;

    PAGED_CODE();

    if (Context == NULL || Context->CurrentKey == NULL || Manager == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&Context->ContextMutex);

    RtlZeroMemory(&options, sizeof(options));
    options.Flags = Context->Flags;
    options.Key = Context->CurrentKey;
    options.AAD = Context->AADBuffer;
    options.AADSize = Context->AADSize;
    options.TagSize = Context->TagSize;

    ExReleaseFastMutex(&Context->ContextMutex);

    return EncEncrypt(
        Manager,
        Context->CurrentKey->KeyType,
        Plaintext,
        PlaintextSize,
        Output,
        OutputSize,
        CiphertextSize,
        &options
        );
}


_Use_decl_annotations_
NTSTATUS
EncDecryptWithContext(
    _In_ PENC_CONTEXT Context,
    _In_ PENC_MANAGER Manager,
    _In_reads_bytes_(CiphertextSize) PVOID Ciphertext,
    _In_ ULONG CiphertextSize,
    _Out_writes_bytes_to_(OutputSize, *PlaintextSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG PlaintextSize
    )
{
    ENC_OPTIONS options;

    PAGED_CODE();

    if (Context == NULL || Context->CurrentKey == NULL || Manager == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&Context->ContextMutex);

    RtlZeroMemory(&options, sizeof(options));
    options.Flags = Context->Flags;
    options.Key = Context->CurrentKey;
    options.AAD = Context->AADBuffer;
    options.AADSize = Context->AADSize;
    options.TagSize = Context->TagSize;

    ExReleaseFastMutex(&Context->ContextMutex);

    return EncDecrypt(
        Manager,
        Ciphertext,
        CiphertextSize,
        Output,
        OutputSize,
        PlaintextSize,
        &options
        );
}


//=============================================================================
// Key Rotation
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EncRotateKey(
    _Inout_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType
    )
{
    NTSTATUS status;
    PENC_KEY oldKey;
    PENC_KEY newKey = NULL;
    ENC_ALGORITHM algorithm;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ENC_VALID_KEY_TYPE(KeyType)) {
        return STATUS_INVALID_PARAMETER;
    }

    oldKey = EncGetActiveKey(Manager, KeyType);
    algorithm = (oldKey != NULL) ? oldKey->Algorithm : Manager->Config.DefaultAlgorithm;

    //
    // Generate new key
    //
    status = EncGenerateKey(Manager, KeyType, algorithm, &newKey);
    if (!NT_SUCCESS(status)) {
        if (oldKey != NULL) {
            EncKeyRelease(oldKey);
        }
        return status;
    }

    //
    // Set as active
    //
    status = EncSetActiveKey(Manager, KeyType, newKey);
    if (!NT_SUCCESS(status)) {
        EncKeyRelease(newKey);
        if (oldKey != NULL) {
            EncKeyRelease(oldKey);
        }
        return status;
    }

    //
    // Mark old key as inactive (but keep it for decryption of existing data)
    //
    if (oldKey != NULL) {
        oldKey->IsActive = FALSE;
        EncKeyRelease(oldKey);
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Manager->KeyRotations);

    //
    // Release our reference to new key (active key holds reference)
    //
    EncKeyRelease(newKey);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
EncRotateAllKeys(
    _Inout_ PENC_MANAGER Manager
    )
{
    NTSTATUS status;
    ULONG i;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = EncKeyType_Invalid + 1; i < EncKeyType_Max; i++) {
        KIRQL oldIrql;
        PENC_KEY activeKey;

        KeAcquireSpinLock(&Manager->ActiveKeysLock, &oldIrql);
        activeKey = Manager->ActiveKeys[i];
        KeReleaseSpinLock(&Manager->ActiveKeysLock, oldIrql);

        if (activeKey != NULL) {
            status = EncRotateKey(Manager, (ENC_KEY_TYPE)i);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
EncSetAutoRotation(
    _Inout_ PENC_MANAGER Manager,
    _In_ BOOLEAN Enable,
    _In_ ULONG IntervalSeconds
    )
{
    LARGE_INTEGER dueTime;

    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Enable && Manager->RotationWorkItem == NULL) {
        //
        // Cannot enable auto rotation without work item
        //
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // Validate IntervalSeconds to prevent overflow in ms conversion
    // KeSetTimerEx period is LONG (max 2147483647 ms ≈ 24.8 days)
    //
    if (Enable && IntervalSeconds > 2147483) {
        return STATUS_INTEGER_OVERFLOW;
    }

    Manager->RotationIntervalSeconds = IntervalSeconds;
    Manager->Config.KeyExpirationSeconds = IntervalSeconds;

    if (Enable && !Manager->AutoRotationEnabled) {
        //
        // Start rotation timer
        //
        dueTime.QuadPart = -((LONGLONG)IntervalSeconds * 10000000LL);
        KeSetTimerEx(
            &Manager->RotationTimer,
            dueTime,
            IntervalSeconds * 1000,  // Period in ms (validated above)
            &Manager->RotationDpc
            );
        Manager->AutoRotationEnabled = TRUE;
    } else if (!Enable && Manager->AutoRotationEnabled) {
        //
        // Cancel rotation timer
        //
        KeCancelTimer(&Manager->RotationTimer);
        Manager->AutoRotationEnabled = FALSE;
    }

    return STATUS_SUCCESS;
}


//=============================================================================
// Rotation DPC and Work Item
//=============================================================================

VOID
EncpRotationDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/*++

Routine Description:

    DPC routine for automatic key rotation timer.
    Queues a work item to perform actual rotation at PASSIVE_LEVEL.

--*/
{
    PENC_MANAGER manager;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    manager = (PENC_MANAGER)DeferredContext;

    if (manager == NULL || !manager->Initialized) {
        return;
    }

    //
    // Only queue if not already rotating
    //
    if (InterlockedCompareExchange((LONG*)&manager->RotationInProgress, TRUE, FALSE) == FALSE) {
        if (manager->RotationWorkItem != NULL && manager->DeviceObject != NULL) {
            IoQueueWorkItem(
                manager->RotationWorkItem,
                EncpRotationWorkItemRoutine,
                DelayedWorkQueue,
                manager
                );
        } else {
            manager->RotationInProgress = FALSE;
        }
    }
}


VOID
EncpRotationWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
/*++

Routine Description:

    Work item routine that performs actual key rotation at PASSIVE_LEVEL.

--*/
{
    PENC_MANAGER manager = (PENC_MANAGER)Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    if (manager == NULL || !manager->Initialized) {
        return;
    }

    //
    // Perform rotation of all active keys
    //
    EncRotateAllKeys(manager);

    //
    // Clear rotation in progress flag
    //
    InterlockedExchange((LONG*)&manager->RotationInProgress, FALSE);
}


//=============================================================================
// Utility Functions
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EncRandomBytes(
    _In_ PENC_MANAGER Manager,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ ULONG Size
    )
{
    PAGED_CODE();

    if (Manager == NULL || !Manager->Initialized || Buffer == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    return BCryptGenRandom(
        Manager->RngAlgHandle,
        (PUCHAR)Buffer,
        Size,
        0
        );
}


_Use_decl_annotations_
VOID
EncSecureClear(
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ ULONG Size
    )
{
    if (Buffer == NULL || Size == 0) {
        return;
    }

    //
    // Use RtlSecureZeroMemory which is guaranteed not to be optimized away
    //
    RtlSecureZeroMemory(Buffer, Size);
}


_Use_decl_annotations_
BOOLEAN
EncConstantTimeCompare(
    _In_reads_bytes_(Size) PVOID A,
    _In_reads_bytes_(Size) PVOID B,
    _In_ ULONG Size
    )
{
    volatile UCHAR result = 0;
    PUCHAR pA = (PUCHAR)A;
    PUCHAR pB = (PUCHAR)B;
    ULONG i;

    if (A == NULL || B == NULL || Size == 0) {
        return FALSE;
    }

    //
    // XOR all bytes and accumulate differences
    //
    for (i = 0; i < Size; i++) {
        result |= pA[i] ^ pB[i];
    }

    return (result == 0);
}


_Use_decl_annotations_
NTSTATUS
EncHmacSha256(
    _In_opt_ BCRYPT_ALG_HANDLE HmacAlgHandle,
    _In_reads_bytes_(KeySize) PVOID Key,
    _In_ ULONG KeySize,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_writes_bytes_(32) PUCHAR Hmac
    )
{
    NTSTATUS status;
    BCRYPT_ALG_HANDLE localAlgHandle = NULL;
    BCRYPT_ALG_HANDLE algToUse;
    BCRYPT_HASH_HANDLE hashHandle = NULL;
    ULONG hashLength;
    ULONG resultLength;

    PAGED_CODE();

    if (Key == NULL || KeySize == 0 || Data == NULL || DataSize == 0 || Hmac == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Use pre-opened handle if available, otherwise open a new one (slow path)
    //
    if (HmacAlgHandle != NULL) {
        algToUse = HmacAlgHandle;
    } else {
        status = BCryptOpenAlgorithmProvider(
            &localAlgHandle,
            BCRYPT_SHA256_ALGORITHM,
            NULL,
            BCRYPT_ALG_HANDLE_HMAC_FLAG
            );

        if (!NT_SUCCESS(status)) {
            return status;
        }

        algToUse = localAlgHandle;
    }

    //
    // Create hash object
    //
    status = BCryptCreateHash(
        algToUse,
        &hashHandle,
        NULL,
        0,
        (PUCHAR)Key,
        KeySize,
        0
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Hash data
    //
    status = BCryptHashData(hashHandle, (PUCHAR)Data, DataSize, 0);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Get hash length
    //
    status = BCryptGetProperty(
        algToUse,
        BCRYPT_HASH_LENGTH,
        (PUCHAR)&hashLength,
        sizeof(hashLength),
        &resultLength,
        0
        );

    if (!NT_SUCCESS(status) || hashLength != 32) {
        status = STATUS_INTERNAL_ERROR;
        goto Cleanup;
    }

    //
    // Finalize hash
    //
    status = BCryptFinishHash(hashHandle, Hmac, 32, 0);

Cleanup:
    if (hashHandle != NULL) {
        BCryptDestroyHash(hashHandle);
    }

    if (localAlgHandle != NULL) {
        BCryptCloseAlgorithmProvider(localAlgHandle, 0);
    }

    return status;
}


_Use_decl_annotations_
NTSTATUS
EncHkdfDerive(
    _In_opt_ BCRYPT_ALG_HANDLE HmacAlgHandle,
    _In_reads_bytes_(IKMSize) PVOID IKM,
    _In_ ULONG IKMSize,
    _In_reads_bytes_opt_(SaltSize) PVOID Salt,
    _In_ ULONG SaltSize,
    _In_reads_bytes_opt_(InfoSize) PVOID Info,
    _In_ ULONG InfoSize,
    _Out_writes_bytes_(OKMSize) PVOID OKM,
    _In_ ULONG OKMSize
    )
/*++

Routine Description:

    HKDF key derivation per RFC 5869.

--*/
{
    NTSTATUS status;
    UCHAR prk[ENC_HMAC_SHA256_SIZE];
    UCHAR t[ENC_HMAC_SHA256_SIZE];
    UCHAR counter;
    ULONG offset = 0;
    ULONG copyLen;
    UCHAR hmacInput[ENC_HMAC_SHA256_SIZE + ENC_HKDF_INFO_SIZE + 1];
    ULONG hmacInputLen;
    UCHAR defaultSalt[ENC_HMAC_SHA256_SIZE] = {0};

    PAGED_CODE();

    if (IKM == NULL || IKMSize == 0 || OKM == NULL || OKMSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (OKMSize > 255 * ENC_HMAC_SHA256_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    //
    status = EncHmacSha256(
        HmacAlgHandle,
        (Salt != NULL && SaltSize > 0) ? Salt : defaultSalt,
        (Salt != NULL && SaltSize > 0) ? SaltSize : sizeof(defaultSalt),
        IKM,
        IKMSize,
        prk
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // HKDF-Expand: OKM = T(1) | T(2) | T(3) | ...
    // T(0) = empty string
    // T(N) = HMAC-Hash(PRK, T(N-1) | info | N)
    //
    RtlZeroMemory(t, sizeof(t));
    counter = 0;

    while (offset < OKMSize) {
        counter++;
        hmacInputLen = 0;

        //
        // Build HMAC input: T(N-1) | info | counter
        //
        if (counter > 1) {
            RtlCopyMemory(hmacInput, t, ENC_HMAC_SHA256_SIZE);
            hmacInputLen = ENC_HMAC_SHA256_SIZE;
        }

        if (Info != NULL && InfoSize > 0) {
            RtlCopyMemory(hmacInput + hmacInputLen, Info, InfoSize);
            hmacInputLen += InfoSize;
        }

        hmacInput[hmacInputLen] = counter;
        hmacInputLen++;

        //
        // T(N) = HMAC(PRK, input)
        //
        status = EncHmacSha256(HmacAlgHandle, prk, sizeof(prk), hmacInput, hmacInputLen, t);
        if (!NT_SUCCESS(status)) {
            EncSecureClear(prk, sizeof(prk));
            EncSecureClear(t, sizeof(t));
            return status;
        }

        //
        // Copy to output
        //
        copyLen = min(ENC_HMAC_SHA256_SIZE, OKMSize - offset);
        RtlCopyMemory((PUCHAR)OKM + offset, t, copyLen);
        offset += copyLen;
    }

    //
    // Clear sensitive data
    //
    EncSecureClear(prk, sizeof(prk));
    EncSecureClear(t, sizeof(t));
    EncSecureClear(hmacInput, sizeof(hmacInput));

    return STATUS_SUCCESS;
}


//=============================================================================
// Statistics
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EncGetStatistics(
    _In_ PENC_MANAGER Manager,
    _Out_ PENC_STATISTICS Stats
    )
{
    if (Manager == NULL || !Manager->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(ENC_STATISTICS));

    //
    // Use interlocked reads for consistency
    //
    Stats->TotalEncryptions = InterlockedCompareExchange64(&Manager->TotalEncryptions, 0, 0);
    Stats->TotalDecryptions = InterlockedCompareExchange64(&Manager->TotalDecryptions, 0, 0);
    Stats->BytesEncrypted = InterlockedCompareExchange64(&Manager->BytesEncrypted, 0, 0);
    Stats->BytesDecrypted = InterlockedCompareExchange64(&Manager->BytesDecrypted, 0, 0);
    Stats->AuthenticationFailures = InterlockedCompareExchange64(&Manager->AuthFailures, 0, 0);
    Stats->KeyRotations = InterlockedCompareExchange64(&Manager->KeyRotations, 0, 0);
    Stats->ActiveKeyCount = Manager->KeyCount;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
EncResetStatistics(
    _Inout_ PENC_MANAGER Manager
    )
{
    if (Manager == NULL || !Manager->Initialized) {
        return;
    }

    InterlockedExchange64(&Manager->TotalEncryptions, 0);
    InterlockedExchange64(&Manager->TotalDecryptions, 0);
    InterlockedExchange64(&Manager->BytesEncrypted, 0);
    InterlockedExchange64(&Manager->BytesDecrypted, 0);
    InterlockedExchange64(&Manager->AuthFailures, 0);
}


//=============================================================================
// Validation
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EncValidateHeader(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PENC_HEADER Header
    )
{
    PENC_HEADER srcHeader;
    ULONG expectedCrc;

    if (Data == NULL || Header == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (DataSize < sizeof(ENC_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Copy to output first
    //
    srcHeader = (PENC_HEADER)Data;
    RtlCopyMemory(Header, srcHeader, sizeof(ENC_HEADER));

    //
    // Validate on the copy
    //
    if (Header->Magic != ENC_MAGIC) {
        return STATUS_DECRYPTION_FAILED;
    }

    if (Header->Version != ENC_VERSION) {
        return STATUS_DECRYPTION_FAILED;
    }

    //
    // Validate CRC
    //
    expectedCrc = EncpCalculateCrc32(Header, sizeof(ENC_HEADER) - sizeof(ULONG));
    if (Header->HeaderCrc32 != expectedCrc) {
        return STATUS_DECRYPTION_FAILED;
    }

    //
    // Validate algorithm
    //
    if (!ENC_VALID_ALGORITHM((ENC_ALGORITHM)Header->Algorithm)) {
        return STATUS_DECRYPTION_FAILED;
    }

    //
    // Validate GCM constraint
    //
    if (Header->PlaintextSize != Header->CiphertextSize) {
        return STATUS_DECRYPTION_FAILED;
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
BOOLEAN
EncIsEncrypted(
    _In_reads_bytes_(Size) PVOID Data,
    _In_ ULONG Size
    )
{
    ENC_HEADER localHeader;

    if (Data == NULL || Size < sizeof(ENC_HEADER)) {
        return FALSE;
    }

    //
    // Copy header to local variable for validation
    //
    RtlCopyMemory(&localHeader, Data, sizeof(ENC_HEADER));

    if (localHeader.Magic != ENC_MAGIC) {
        return FALSE;
    }

    if (localHeader.Version != ENC_VERSION) {
        return FALSE;
    }

    //
    // Validate CRC for additional confidence
    //
    ULONG expectedCrc = EncpCalculateCrc32(&localHeader, sizeof(ENC_HEADER) - sizeof(ULONG));
    if (localHeader.HeaderCrc32 != expectedCrc) {
        return FALSE;
    }

    return TRUE;
}


//=============================================================================
// Internal Functions
//=============================================================================

static
_Use_decl_annotations_
NTSTATUS
EncpGenerateNonce(
    _Inout_ PENC_KEY Key,
    _Out_writes_bytes_(ENC_GCM_NONCE_SIZE) PUCHAR Nonce
    )
/*++

Routine Description:

    Generates a unique nonce using prefix + monotonic counter.
    Guarantees nonce uniqueness across the key's lifetime.

--*/
{
    LONG64 counter;
    KIRQL oldIrql;

    //
    // Get next counter value atomically
    //
    KeAcquireSpinLock(&Key->NonceLock, &oldIrql);

    if (Key->NonceCounter >= ENC_NONCE_COUNTER_MAX) {
        KeReleaseSpinLock(&Key->NonceLock, oldIrql);
        //
        // Counter exhausted - key should be rotated
        //
        Key->IsExpired = TRUE;
        return STATUS_INTEGER_OVERFLOW;
    }

    counter = ++Key->NonceCounter;
    KeReleaseSpinLock(&Key->NonceLock, oldIrql);

    //
    // Build nonce: 4 bytes prefix + 8 bytes counter
    //
    RtlCopyMemory(Nonce, Key->NoncePrefix, 4);
    RtlCopyMemory(Nonce + 4, &counter, 8);

    return STATUS_SUCCESS;
}


static
_Use_decl_annotations_
NTSTATUS
EncpGetDeobfuscatedKeyMaterial(
    _In_ PENC_KEY Key,
    _Out_writes_bytes_(ENC_AES_KEY_SIZE_256) PUCHAR KeyBuffer
    )
/*++

Routine Description:

    Safely retrieves deobfuscated key material into a caller-provided buffer.
    The caller is responsible for clearing the buffer after use.

--*/
{
    ULONG i;

    PAGED_CODE();

    if (Key == NULL || KeyBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Key->ObfuscationKey == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    ExAcquireFastMutex(&Key->ObfuscationMutex);

    //
    // Copy key material
    //
    RtlCopyMemory(KeyBuffer, Key->KeyMaterial, Key->KeySize);

    //
    // Deobfuscate if necessary
    //
    if (Key->IsObfuscated) {
        for (i = 0; i < Key->KeySize; i++) {
            KeyBuffer[i] ^= Key->ObfuscationKey[i];
        }
    }

    //
    // Zero out any remaining bytes
    //
    if (Key->KeySize < ENC_AES_KEY_SIZE_256) {
        RtlZeroMemory(KeyBuffer + Key->KeySize, ENC_AES_KEY_SIZE_256 - Key->KeySize);
    }

    ExReleaseFastMutex(&Key->ObfuscationMutex);

    return STATUS_SUCCESS;
}


static
_Use_decl_annotations_
NTSTATUS
EncpInitializeBCryptKey(
    _In_ PENC_MANAGER Manager,
    _Inout_ PENC_KEY Key
    )
/*++

Routine Description:

    Initializes BCrypt key handle for the encryption key.

--*/
{
    NTSTATUS status;

    PAGED_CODE();

    Key->AlgHandle = Manager->AesGcmAlgHandle;

    //
    // Generate key object using raw key material (not yet obfuscated at this point)
    //
    status = BCryptGenerateSymmetricKey(
        Manager->AesGcmAlgHandle,
        &Key->KeyHandle,
        NULL,
        0,
        Key->KeyMaterial,
        Key->KeySize,
        0
        );

    if (NT_SUCCESS(status)) {
        Key->HandlesInitialized = TRUE;
    }

    return status;
}


static
_Use_decl_annotations_
VOID
EncpCleanupBCryptKey(
    _Inout_ PENC_KEY Key
    )
{
    PAGED_CODE();

    if (Key->HandlesInitialized && Key->KeyHandle != NULL) {
        BCryptDestroyKey(Key->KeyHandle);
        Key->KeyHandle = NULL;
        Key->HandlesInitialized = FALSE;
    }
}


static
_Use_decl_annotations_
BOOLEAN
EncpIsKeyExpired(
    _In_ PENC_KEY Key
    )
/*++

Routine Description:

    Checks if a key has expired based on its expiration time.

--*/
{
    LARGE_INTEGER currentTime;

    if (Key->IsExpired) {
        return TRUE;
    }

    KeQuerySystemTimePrecise(&currentTime);

    if (currentTime.QuadPart >= Key->ExpirationTime.QuadPart) {
        Key->IsExpired = TRUE;
        return TRUE;
    }

    return FALSE;
}
