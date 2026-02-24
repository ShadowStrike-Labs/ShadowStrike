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
    Module: Encryption.h

    Purpose: AES-GCM encryption for sensitive telemetry data and
             secure kernel-to-user communication channels.

    Architecture:
    - AES-256-GCM authenticated encryption
    - Key derivation using HKDF
    - Nonce management with counter mode
    - Secure key storage with obfuscation

    Security Notes:
    - Keys never stored in pageable memory
    - Nonces never reused (monotonic counter)
    - Sensitive data cleared after use
    - All BCrypt operations require PASSIVE_LEVEL

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>
#include <ntintsafe.h>
#include <bcrypt.h>
#include <ntstrsafe.h>

//=============================================================================
// Pool Tags
//=============================================================================

#define ENC_POOL_TAG_KEY        'YKNE'  // Encryption - Key
#define ENC_POOL_TAG_CONTEXT    'CXNE'  // Encryption - Context
#define ENC_POOL_TAG_BUFFER     'FBNE'  // Encryption - Buffer
#define ENC_POOL_TAG_NONCE      'NNNE'  // Encryption - Nonce
#define ENC_POOL_TAG_OBFUSK     'OKNE'  // Encryption - Obfuscation Key
#define ENC_POOL_TAG_WORKITEM   'WINE'  // Encryption - Work Item

//=============================================================================
// Configuration Constants
//=============================================================================

// AES parameters
#define ENC_AES_KEY_SIZE_128        16
#define ENC_AES_KEY_SIZE_192        24
#define ENC_AES_KEY_SIZE_256        32
#define ENC_AES_BLOCK_SIZE          16
#define ENC_AES_DEFAULT_KEY_SIZE    ENC_AES_KEY_SIZE_256

// GCM parameters
#define ENC_GCM_NONCE_SIZE          12      // 96 bits (recommended)
#define ENC_GCM_TAG_SIZE            16      // 128 bits (full)
#define ENC_GCM_TAG_SIZE_MIN        12      // 96 bits (minimum secure)
#define ENC_GCM_AAD_MAX_SIZE        (64 * 1024)  // Max additional auth data

// Key derivation
#define ENC_HKDF_SALT_SIZE          32
#define ENC_HKDF_INFO_SIZE          64
#define ENC_KEY_ROTATION_INTERVAL   (24 * 60 * 60)  // 24 hours in seconds

// Limits
#define ENC_MAX_PLAINTEXT_SIZE      (16 * 1024 * 1024)  // 16 MB (reduced for safety)
#define ENC_MIN_PLAINTEXT_SIZE      1
#define ENC_MAX_AAD_SIZE            (64 * 1024)
#define ENC_NONCE_COUNTER_MAX       0x7FFFFFFFFFFFFFFFLL  // Signed max for safe increment
#define ENC_MAX_KEYS                64

//=============================================================================
// Algorithm Types
//=============================================================================

typedef enum _ENC_ALGORITHM {
    EncAlgorithm_None = 0,
    EncAlgorithm_AES_128_GCM,           // AES-128-GCM
    EncAlgorithm_AES_256_GCM,           // AES-256-GCM (default)
    EncAlgorithm_Max
} ENC_ALGORITHM;

//=============================================================================
// Key Types
//=============================================================================

typedef enum _ENC_KEY_TYPE {
    EncKeyType_Invalid = 0,
    EncKeyType_Telemetry,               // Telemetry encryption
    EncKeyType_Communication,           // Kernel-user channel
    EncKeyType_Storage,                 // At-rest encryption
    EncKeyType_Ephemeral,               // Session keys
    EncKeyType_Max
} ENC_KEY_TYPE;

//=============================================================================
// Encryption Flags
//=============================================================================

typedef enum _ENC_FLAGS {
    EncFlag_None                = 0x00000000,
    EncFlag_IncludeHeader       = 0x00000001,   // Prepend header to output
    EncFlag_UseAAD              = 0x00000002,   // Use additional auth data
    EncFlag_InPlace             = 0x00000004,   // Encrypt in-place
    EncFlag_ZeroOnFree          = 0x00000020,   // Zero memory on free
    EncFlag_NonPagedKey         = 0x00000040,   // Key in non-paged pool
} ENC_FLAGS;

//=============================================================================
// Encrypted Data Header
//=============================================================================

#pragma pack(push, 1)

typedef struct _ENC_HEADER {
    ULONG Magic;                        // 'ENCR' magic
    USHORT Version;                     // Header version
    USHORT Algorithm;                   // ENC_ALGORITHM
    ULONG Flags;                        // ENC_FLAGS
    ULONG PlaintextSize;                // Original plaintext size
    ULONG CiphertextSize;               // Ciphertext size (without header/tag)
    UCHAR Nonce[ENC_GCM_NONCE_SIZE];    // Nonce/IV
    UCHAR Tag[ENC_GCM_TAG_SIZE];        // Authentication tag
    ULONG64 KeyId;                      // Key identifier (64-bit for no overflow)
    ULONG AADSize;                      // Additional auth data size
    LARGE_INTEGER Timestamp;            // Encryption timestamp
    ULONG HeaderCrc32;                  // CRC32 of header fields (excluding this)
} ENC_HEADER, *PENC_HEADER;

#define ENC_MAGIC           'RCNE'      // 'ENCR' reversed
#define ENC_VERSION         2           // Version 2 with 64-bit KeyId

C_ASSERT(sizeof(ENC_HEADER) == 72);

#pragma pack(pop)

//=============================================================================
// Key Structure
//=============================================================================

typedef struct _ENC_KEY {
    //
    // Key identification
    //
    ULONG64 KeyId;
    ENC_KEY_TYPE KeyType;
    ENC_ALGORITHM Algorithm;

    //
    // Key material (in non-paged memory)
    // Stored obfuscated - use EncpGetKeyMaterial for access
    //
    UCHAR KeyMaterial[ENC_AES_KEY_SIZE_256];
    ULONG KeySize;

    //
    // Key obfuscation (stored in separate allocation for security)
    //
    PUCHAR ObfuscationKey;              // Separate allocation
    BOOLEAN IsObfuscated;
    FAST_MUTEX ObfuscationMutex;        // Protects obfuscation state

    //
    // Nonce counter (monotonic, never reused)
    //
    volatile LONG64 NonceCounter;
    UCHAR NoncePrefix[4];               // First 4 bytes of nonce
    KSPIN_LOCK NonceLock;

    //
    // BCrypt handles
    //
    BCRYPT_ALG_HANDLE AlgHandle;
    BCRYPT_KEY_HANDLE KeyHandle;
    BOOLEAN HandlesInitialized;

    //
    // Key lifecycle
    //
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER ExpirationTime;
    volatile LONG UseCount;
    BOOLEAN IsActive;
    volatile BOOLEAN IsExpired;

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // Flags for cleanup state
    //
    volatile BOOLEAN IsBeingDestroyed;
    volatile BOOLEAN RemovedFromList;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;

} ENC_KEY, *PENC_KEY;

//=============================================================================
// Encryption Context
//=============================================================================

typedef struct _ENC_CONTEXT {
    //
    // Current key
    //
    PENC_KEY CurrentKey;

    //
    // Algorithm settings
    //
    ENC_ALGORITHM Algorithm;
    ENC_FLAGS Flags;
    ULONG TagSize;                      // Authentication tag size

    //
    // AAD for this operation
    //
    PVOID AADBuffer;
    ULONG AADSize;

    //
    // Statistics
    //
    ULONG64 TotalBytesEncrypted;
    ULONG64 TotalBytesDecrypted;
    ULONG64 OperationCount;

    //
    // Synchronization
    //
    FAST_MUTEX ContextMutex;

} ENC_CONTEXT, *PENC_CONTEXT;

//=============================================================================
// Encryption Manager
//=============================================================================

typedef struct _ENC_MANAGER {
    //
    // Initialization state
    //
    BOOLEAN Initialized;

    //
    // BCrypt algorithm providers
    //
    BCRYPT_ALG_HANDLE AesGcmAlgHandle;
    BCRYPT_ALG_HANDLE HmacAlgHandle;
    BCRYPT_ALG_HANDLE RngAlgHandle;

    //
    // Key management
    //
    LIST_ENTRY KeyList;
    ERESOURCE KeyListLock;              // Use ERESOURCE for reader/writer
    ULONG KeyCount;
    volatile LONG64 NextKeyId;

    //
    // Active keys by type
    //
    PENC_KEY ActiveKeys[EncKeyType_Max];
    KSPIN_LOCK ActiveKeysLock;

    //
    // Key rotation
    //
    KTIMER RotationTimer;
    KDPC RotationDpc;
    PIO_WORKITEM RotationWorkItem;
    PDEVICE_OBJECT DeviceObject;
    ULONG RotationIntervalSeconds;
    BOOLEAN AutoRotationEnabled;
    volatile BOOLEAN RotationInProgress;

    //
    // Master key (derived from boot key or TPM)
    //
    UCHAR MasterKey[ENC_AES_KEY_SIZE_256];
    PUCHAR MasterKeyObfuscation;        // Separate allocation
    BOOLEAN MasterKeySet;
    FAST_MUTEX MasterKeyMutex;

    //
    // Statistics (use interlocked access)
    //
    volatile LONG64 TotalEncryptions;
    volatile LONG64 TotalDecryptions;
    volatile LONG64 BytesEncrypted;
    volatile LONG64 BytesDecrypted;
    volatile LONG64 AuthFailures;
    volatile LONG64 KeyRotations;

    //
    // Configuration
    //
    struct {
        ENC_ALGORITHM DefaultAlgorithm;
        ULONG DefaultTagSize;
        BOOLEAN RequireNonPagedKeys;
        BOOLEAN EnableAutoRotation;
        ULONG KeyExpirationSeconds;
    } Config;

} ENC_MANAGER, *PENC_MANAGER;

//=============================================================================
// Encryption Options
//=============================================================================

typedef struct _ENC_OPTIONS {
    ENC_FLAGS Flags;                    // Encryption flags
    PENC_KEY Key;                       // Specific key (NULL = use active)
    PVOID AAD;                          // Additional authenticated data
    ULONG AADSize;                      // AAD size
    ULONG TagSize;                      // Auth tag size (default: 16)
} ENC_OPTIONS, *PENC_OPTIONS;

//=============================================================================
// Public API - Initialization
//=============================================================================

//
// Initialize the encryption manager
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncInitialize(
    _Out_ PENC_MANAGER Manager,
    _In_opt_ PDEVICE_OBJECT DeviceObject
    );

//
// Shutdown the encryption manager
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
EncShutdown(
    _Inout_ PENC_MANAGER Manager
    );

//
// Set the master key (from TPM or secure storage)
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncSetMasterKey(
    _Inout_ PENC_MANAGER Manager,
    _In_reads_bytes_(KeySize) PUCHAR Key,
    _In_ ULONG KeySize
    );

//=============================================================================
// Public API - Key Management
//=============================================================================

//
// Generate a new encryption key
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncGenerateKey(
    _In_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType,
    _In_ ENC_ALGORITHM Algorithm,
    _Out_ PENC_KEY* Key
    );

//
// Derive a key from master key and context
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncDeriveKey(
    _In_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType,
    _In_ ENC_ALGORITHM Algorithm,
    _In_reads_bytes_(ContextSize) PVOID Context,
    _In_ ULONG ContextSize,
    _Out_ PENC_KEY* Key
    );

//
// Import an existing key
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncImportKey(
    _In_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType,
    _In_ ENC_ALGORITHM Algorithm,
    _In_reads_bytes_(KeySize) PUCHAR KeyMaterial,
    _In_ ULONG KeySize,
    _Out_ PENC_KEY* Key
    );

//
// Export a key (for backup/transfer)
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncExportKey(
    _In_ PENC_KEY Key,
    _Out_writes_bytes_to_(BufferSize, *ExportedSize) PUCHAR Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG ExportedSize
    );

//
// Destroy a key
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
EncDestroyKey(
    _In_ PENC_MANAGER Manager,
    _Inout_ PENC_KEY Key
    );

//
// Get active key for a type
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
PENC_KEY
EncGetActiveKey(
    _In_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType
    );

//
// Set active key for a type
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
EncSetActiveKey(
    _Inout_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType,
    _In_ PENC_KEY Key
    );

//
// Add/release key reference
// EncKeyAddRef returns TRUE if reference was acquired, FALSE if key is being destroyed
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
EncKeyAddRef(
    _In_ PENC_KEY Key
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
LONG
EncKeyRelease(
    _In_ PENC_KEY Key
    );

//=============================================================================
// Public API - Simple Encryption/Decryption
//=============================================================================

//
// Encrypt data with default key
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
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
    );

//
// Decrypt data
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncDecrypt(
    _In_ PENC_MANAGER Manager,
    _In_reads_bytes_(CiphertextSize) PVOID Ciphertext,
    _In_ ULONG CiphertextSize,
    _Out_writes_bytes_to_(OutputSize, *PlaintextSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG PlaintextSize,
    _In_opt_ PENC_OPTIONS Options
    );

//
// Calculate required output buffer size (with overflow protection)
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
EncGetEncryptedSize(
    _In_ ULONG PlaintextSize,
    _In_ BOOLEAN IncludeHeader,
    _Out_ PULONG RequiredSize
    );

//=============================================================================
// Public API - Context-Based Encryption
//=============================================================================

//
// Create encryption context
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncCreateContext(
    _Out_ PENC_CONTEXT* Context,
    _In_ PENC_KEY Key,
    _In_ ENC_FLAGS Flags
    );

//
// Destroy encryption context
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
EncDestroyContext(
    _Inout_ PENC_CONTEXT Context
    );

//
// Encrypt with context
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncEncryptWithContext(
    _In_ PENC_CONTEXT Context,
    _In_ PENC_MANAGER Manager,
    _In_reads_bytes_(PlaintextSize) PVOID Plaintext,
    _In_ ULONG PlaintextSize,
    _Out_writes_bytes_to_(OutputSize, *CiphertextSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG CiphertextSize
    );

//
// Decrypt with context
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncDecryptWithContext(
    _In_ PENC_CONTEXT Context,
    _In_ PENC_MANAGER Manager,
    _In_reads_bytes_(CiphertextSize) PVOID Ciphertext,
    _In_ ULONG CiphertextSize,
    _Out_writes_bytes_to_(OutputSize, *PlaintextSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG PlaintextSize
    );

//
// Set AAD for context
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncSetAAD(
    _Inout_ PENC_CONTEXT Context,
    _In_reads_bytes_(AADSize) PVOID AAD,
    _In_ ULONG AADSize
    );

//=============================================================================
// Public API - Key Rotation
//=============================================================================

//
// Rotate key for a specific type
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncRotateKey(
    _Inout_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType
    );

//
// Rotate all keys
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncRotateAllKeys(
    _Inout_ PENC_MANAGER Manager
    );

//
// Enable/disable automatic key rotation
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncSetAutoRotation(
    _Inout_ PENC_MANAGER Manager,
    _In_ BOOLEAN Enable,
    _In_ ULONG IntervalSeconds
    );

//=============================================================================
// Public API - Utility Functions
//=============================================================================

//
// Generate cryptographically secure random bytes
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncRandomBytes(
    _In_ PENC_MANAGER Manager,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ ULONG Size
    );

//
// Secure memory clear (not optimized away)
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EncSecureClear(
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ ULONG Size
    );

//
// Constant-time comparison
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
BOOLEAN
EncConstantTimeCompare(
    _In_reads_bytes_(Size) PVOID A,
    _In_reads_bytes_(Size) PVOID B,
    _In_ ULONG Size
    );

//
// Calculate HMAC-SHA256
// Pass a pre-opened HmacAlgHandle to avoid per-call BCryptOpenAlgorithmProvider overhead.
// If HmacAlgHandle is NULL, opens and closes a provider internally (slow path).
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EncHmacSha256(
    _In_opt_ BCRYPT_ALG_HANDLE HmacAlgHandle,
    _In_reads_bytes_(KeySize) PVOID Key,
    _In_ ULONG KeySize,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_writes_bytes_(32) PUCHAR Hmac
    );

//
// HKDF key derivation
// Pass a pre-opened HmacAlgHandle for efficient HMAC operations.
// If HmacAlgHandle is NULL, each HMAC call opens a new provider (slow path).
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
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
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _ENC_STATISTICS {
    LONG64 TotalEncryptions;
    LONG64 TotalDecryptions;
    LONG64 BytesEncrypted;
    LONG64 BytesDecrypted;
    LONG64 AuthenticationFailures;
    LONG64 KeyRotations;
    ULONG ActiveKeyCount;
    LARGE_INTEGER LastKeyRotation;
} ENC_STATISTICS, *PENC_STATISTICS;

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
EncGetStatistics(
    _In_ PENC_MANAGER Manager,
    _Out_ PENC_STATISTICS Stats
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EncResetStatistics(
    _Inout_ PENC_MANAGER Manager
    );

//=============================================================================
// Public API - Validation
//=============================================================================

//
// Validate encrypted data header
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
EncValidateHeader(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PENC_HEADER Header
    );

//
// Check if data appears encrypted
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
BOOLEAN
EncIsEncrypted(
    _In_reads_bytes_(Size) PVOID Data,
    _In_ ULONG Size
    );

//=============================================================================
// Helper Macros
//=============================================================================

//
// Check if size is valid for encryption
//
#define ENC_VALID_SIZE(size) \
    ((size) >= ENC_MIN_PLAINTEXT_SIZE && (size) <= ENC_MAX_PLAINTEXT_SIZE)

//
// Check if algorithm is valid
//
#define ENC_VALID_ALGORITHM(alg) \
    ((alg) > EncAlgorithm_None && (alg) < EncAlgorithm_Max)

//
// Check if key type is valid
//
#define ENC_VALID_KEY_TYPE(type) \
    ((type) > EncKeyType_Invalid && (type) < EncKeyType_Max)

#ifdef __cplusplus
}
#endif
