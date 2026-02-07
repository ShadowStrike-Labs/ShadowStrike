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
    
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <bcrypt.h>

//=============================================================================
// Pool Tags
//=============================================================================

#define ENC_POOL_TAG_KEY        'YKNE'  // Encryption - Key
#define ENC_POOL_TAG_CONTEXT    'CXNE'  // Encryption - Context
#define ENC_POOL_TAG_BUFFER     'FBNE'  // Encryption - Buffer
#define ENC_POOL_TAG_NONCE      'NNNE'  // Encryption - Nonce

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
#define ENC_MAX_PLAINTEXT_SIZE      (64 * 1024 * 1024)  // 64 MB
#define ENC_MIN_PLAINTEXT_SIZE      1
#define ENC_MAX_AAD_SIZE            (64 * 1024)
#define ENC_NONCE_COUNTER_MAX       0xFFFFFFFFFFFFFFFFULL

//=============================================================================
// Algorithm Types
//=============================================================================

typedef enum _ENC_ALGORITHM {
    EncAlgorithm_None = 0,
    EncAlgorithm_AES_128_GCM,           // AES-128-GCM
    EncAlgorithm_AES_256_GCM,           // AES-256-GCM (default)
    EncAlgorithm_AES_128_CBC_HMAC,      // AES-128-CBC + HMAC-SHA256
    EncAlgorithm_AES_256_CBC_HMAC,      // AES-256-CBC + HMAC-SHA256
    EncAlgorithm_ChaCha20_Poly1305,     // ChaCha20-Poly1305 (if available)
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
    EncFlag_Streaming           = 0x00000008,   // Multi-call encryption
    EncFlag_FinalBlock          = 0x00000010,   // Final block in stream
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
    ULONG KeyId;                        // Key identifier (for rotation)
    ULONG AADSize;                      // Additional auth data size
    LARGE_INTEGER Timestamp;            // Encryption timestamp
    ULONG Reserved;
} ENC_HEADER, *PENC_HEADER;

#define ENC_MAGIC           'RCNE'      // 'ENCR' reversed
#define ENC_VERSION         1

C_ASSERT(sizeof(ENC_HEADER) == 64);

#pragma pack(pop)

//=============================================================================
// Key Structure
//=============================================================================

typedef struct _ENC_KEY {
    //
    // Key identification
    //
    ULONG KeyId;
    ENC_KEY_TYPE KeyType;
    ENC_ALGORITHM Algorithm;
    
    //
    // Key material (in non-paged memory)
    //
    UCHAR KeyMaterial[ENC_AES_KEY_SIZE_256];
    ULONG KeySize;
    
    //
    // Key obfuscation (XOR with random value)
    //
    UCHAR ObfuscationKey[ENC_AES_KEY_SIZE_256];
    BOOLEAN IsObfuscated;
    
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
    
    //
    // Reference counting
    //
    volatile LONG RefCount;
    
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
    // Streaming state
    //
    BOOLEAN StreamMode;
    BOOLEAN StreamInitialized;
    PVOID StreamState;
    ULONG StreamStateSize;
    ULONG StreamBytesProcessed;
    
    //
    // Statistics
    //
    ULONG64 TotalBytesEncrypted;
    ULONG64 TotalBytesDecrypted;
    ULONG64 OperationCount;
    
    //
    // Synchronization
    //
    KSPIN_LOCK Lock;
    
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
    BCRYPT_ALG_HANDLE AesCbcAlgHandle;
    BCRYPT_ALG_HANDLE HmacAlgHandle;
    BCRYPT_ALG_HANDLE RngAlgHandle;
    
    //
    // Key management
    //
    LIST_ENTRY KeyList;
    KSPIN_LOCK KeyListLock;
    ULONG KeyCount;
    ULONG NextKeyId;
    
    //
    // Active keys by type
    //
    PENC_KEY ActiveKeys[EncKeyType_Max];
    
    //
    // Key rotation
    //
    KTIMER RotationTimer;
    KDPC RotationDpc;
    ULONG RotationIntervalSeconds;
    BOOLEAN AutoRotationEnabled;
    
    //
    // Master key (derived from boot key or TPM)
    //
    UCHAR MasterKey[ENC_AES_KEY_SIZE_256];
    BOOLEAN MasterKeySet;
    
    //
    // Statistics
    //
    struct {
        ULONG64 TotalEncryptions;
        ULONG64 TotalDecryptions;
        ULONG64 BytesEncrypted;
        ULONG64 BytesDecrypted;
        ULONG64 AuthFailures;
        ULONG64 KeyRotations;
    } Stats;
    
    //
    // Configuration
    //
    struct {
        ENC_ALGORITHM DefaultAlgorithm;
        ULONG DefaultTagSize;
        BOOLEAN RequireNonPagedKeys;
        BOOLEAN EnableAutoRotation;
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
NTSTATUS
EncInitialize(
    _Out_ PENC_MANAGER Manager
    );

//
// Shutdown the encryption manager
//
VOID
EncShutdown(
    _Inout_ PENC_MANAGER Manager
    );

//
// Set the master key (from TPM or secure storage)
//
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
VOID
EncDestroyKey(
    _Inout_ PENC_KEY Key
    );

//
// Get active key for a type
//
PENC_KEY
EncGetActiveKey(
    _In_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType
    );

//
// Set active key for a type
//
NTSTATUS
EncSetActiveKey(
    _Inout_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType,
    _In_ PENC_KEY Key
    );

//
// Add/release key reference
//
VOID
EncKeyAddRef(
    _In_ PENC_KEY Key
    );

VOID
EncKeyRelease(
    _In_ PENC_KEY Key
    );

//=============================================================================
// Public API - Simple Encryption/Decryption
//=============================================================================

//
// Encrypt data with default key
//
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
// Calculate required output buffer size
//
ULONG
EncGetEncryptedSize(
    _In_ ULONG PlaintextSize,
    _In_ BOOLEAN IncludeHeader
    );

//=============================================================================
// Public API - Context-Based Encryption
//=============================================================================

//
// Create encryption context
//
NTSTATUS
EncCreateContext(
    _Out_ PENC_CONTEXT* Context,
    _In_ PENC_KEY Key,
    _In_ ENC_FLAGS Flags
    );

//
// Destroy encryption context
//
VOID
EncDestroyContext(
    _Inout_ PENC_CONTEXT Context
    );

//
// Encrypt with context
//
NTSTATUS
EncEncryptWithContext(
    _In_ PENC_CONTEXT Context,
    _In_reads_bytes_(PlaintextSize) PVOID Plaintext,
    _In_ ULONG PlaintextSize,
    _Out_writes_bytes_to_(OutputSize, *CiphertextSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG CiphertextSize
    );

//
// Decrypt with context
//
NTSTATUS
EncDecryptWithContext(
    _In_ PENC_CONTEXT Context,
    _In_reads_bytes_(CiphertextSize) PVOID Ciphertext,
    _In_ ULONG CiphertextSize,
    _Out_writes_bytes_to_(OutputSize, *PlaintextSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG PlaintextSize
    );

//
// Set AAD for context
//
NTSTATUS
EncSetAAD(
    _Inout_ PENC_CONTEXT Context,
    _In_reads_bytes_(AADSize) PVOID AAD,
    _In_ ULONG AADSize
    );

//=============================================================================
// Public API - Streaming Encryption
//=============================================================================

//
// Begin streaming encryption
//
NTSTATUS
EncStreamBegin(
    _Inout_ PENC_CONTEXT Context,
    _Out_writes_bytes_(ENC_GCM_NONCE_SIZE) PUCHAR NonceOut
    );

//
// Process streaming data
//
NTSTATUS
EncStreamProcess(
    _Inout_ PENC_CONTEXT Context,
    _In_reads_bytes_(InputSize) PVOID Input,
    _In_ ULONG InputSize,
    _Out_writes_bytes_(OutputSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG OutputWritten,
    _In_ BOOLEAN IsFinal
    );

//
// Finalize streaming encryption
//
NTSTATUS
EncStreamFinalize(
    _Inout_ PENC_CONTEXT Context,
    _Out_writes_bytes_(TagSize) PUCHAR TagOut,
    _In_ ULONG TagSize
    );

//
// Begin streaming decryption
//
NTSTATUS
EncStreamDecryptBegin(
    _Inout_ PENC_CONTEXT Context,
    _In_reads_bytes_(ENC_GCM_NONCE_SIZE) PUCHAR Nonce
    );

//
// Finalize streaming decryption (verify tag)
//
NTSTATUS
EncStreamDecryptFinalize(
    _Inout_ PENC_CONTEXT Context,
    _In_reads_bytes_(TagSize) PUCHAR Tag,
    _In_ ULONG TagSize
    );

//=============================================================================
// Public API - Key Rotation
//=============================================================================

//
// Rotate key for a specific type
//
NTSTATUS
EncRotateKey(
    _Inout_ PENC_MANAGER Manager,
    _In_ ENC_KEY_TYPE KeyType
    );

//
// Rotate all keys
//
NTSTATUS
EncRotateAllKeys(
    _Inout_ PENC_MANAGER Manager
    );

//
// Enable/disable automatic key rotation
//
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
NTSTATUS
EncRandomBytes(
    _In_ PENC_MANAGER Manager,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ ULONG Size
    );

//
// Secure memory clear
//
VOID
EncSecureClear(
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ ULONG Size
    );

//
// Constant-time comparison
//
BOOLEAN
EncConstantTimeCompare(
    _In_reads_bytes_(Size) PVOID A,
    _In_reads_bytes_(Size) PVOID B,
    _In_ ULONG Size
    );

//
// Calculate HMAC-SHA256
//
NTSTATUS
EncHmacSha256(
    _In_reads_bytes_(KeySize) PVOID Key,
    _In_ ULONG KeySize,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_writes_bytes_(32) PUCHAR Hmac
    );

//
// HKDF key derivation
//
NTSTATUS
EncHkdfDerive(
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
    ULONG64 TotalEncryptions;
    ULONG64 TotalDecryptions;
    ULONG64 BytesEncrypted;
    ULONG64 BytesDecrypted;
    ULONG64 AuthenticationFailures;
    ULONG64 KeyRotations;
    ULONG ActiveKeyCount;
    LARGE_INTEGER LastKeyRotation;
} ENC_STATISTICS, *PENC_STATISTICS;

NTSTATUS
EncGetStatistics(
    _In_ PENC_MANAGER Manager,
    _Out_ PENC_STATISTICS Stats
    );

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
NTSTATUS
EncValidateHeader(
    _In_reads_bytes_(HeaderSize) PVOID Data,
    _In_ ULONG HeaderSize,
    _Out_ PENC_HEADER Header
    );

//
// Check if data appears encrypted
//
BOOLEAN
EncIsEncrypted(
    _In_reads_bytes_(Size) PVOID Data,
    _In_ ULONG Size
    );

//=============================================================================
// Helper Macros
//=============================================================================

//
// Calculate encrypted output size (with header)
//
#define ENC_ENCRYPTED_SIZE(plaintextSize) \
    (sizeof(ENC_HEADER) + (plaintextSize) + ENC_GCM_TAG_SIZE)

//
// Calculate plaintext size from encrypted size (with header)
//
#define ENC_PLAINTEXT_SIZE(encryptedSize) \
    ((encryptedSize) - sizeof(ENC_HEADER) - ENC_GCM_TAG_SIZE)

//
// Check if size is valid for encryption
//
#define ENC_VALID_SIZE(size) \
    ((size) >= ENC_MIN_PLAINTEXT_SIZE && (size) <= ENC_MAX_PLAINTEXT_SIZE)

#ifdef __cplusplus
}
#endif
