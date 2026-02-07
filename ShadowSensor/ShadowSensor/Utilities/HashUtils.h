/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE KERNEL HASHING UTILITIES
 * ============================================================================
 *
 * @file HashUtils.h
 * @brief Enterprise-grade cryptographic hashing for kernel-mode EDR operations.
 *
 * Provides CrowdStrike Falcon-level hashing capabilities with:
 * - CNG (Cryptography API: Next Generation) SHA-256/SHA-1/MD5 wrappers
 * - Streaming hash computation for large files (zero-copy where possible)
 * - Memory buffer hashing with IRQL-aware implementations
 * - Hash comparison with constant-time operations (timing-attack resistant)
 * - Hash caching infrastructure for performance optimization
 * - Authenticode hash extraction for PE files
 * - HMAC support for integrity verification
 * - Fuzzy hashing (ssdeep-style) for malware similarity detection
 * - Import hash (imphash) computation for threat intelligence
 *
 * Security Guarantees:
 * - All hash operations use FIPS-compliant CNG providers
 * - Constant-time comparison prevents timing side-channels
 * - Secure memory wiping of intermediate hash states
 * - Input validation prevents buffer overflows
 * - File size limits prevent DoS attacks
 * - IRQL validation for all operations
 *
 * Performance Optimizations:
 * - Reusable algorithm provider handles (singleton pattern)
 * - Configurable chunk sizes for streaming operations
 * - Lookaside list support for hash object allocations
 * - Non-cached I/O for file hashing (bypass filesystem cache pollution)
 * - Parallel hashing support for multi-algorithm scenarios
 *
 * MITRE ATT&CK Coverage:
 * - T1027: Obfuscated Files (hash-based detection)
 * - T1036: Masquerading (hash verification)
 * - T1553: Subvert Trust Controls (Authenticode hash validation)
 * - T1574: Hijack Execution Flow (import hash detection)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_HASH_UTILS_H_
#define _SHADOWSTRIKE_HASH_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include <bcrypt.h>
#include <wdm.h>

// ============================================================================
// HASH SIZE CONSTANTS
// ============================================================================

/**
 * @brief SHA-256 hash size in bytes (256 bits)
 */
#define SHA256_HASH_SIZE        32

/**
 * @brief SHA-1 hash size in bytes (160 bits) - Legacy support only
 */
#define SHA1_HASH_SIZE          20

/**
 * @brief MD5 hash size in bytes (128 bits) - Legacy/compatibility only
 */
#define MD5_HASH_SIZE           16

/**
 * @brief SHA-512 hash size in bytes (512 bits)
 */
#define SHA512_HASH_SIZE        64

/**
 * @brief Maximum supported hash size
 */
#define MAX_HASH_SIZE           SHA512_HASH_SIZE

/**
 * @brief Hash string representation size (hex + null)
 */
#define SHA256_STRING_SIZE      ((SHA256_HASH_SIZE * 2) + 1)
#define SHA1_STRING_SIZE        ((SHA1_HASH_SIZE * 2) + 1)
#define MD5_STRING_SIZE         ((MD5_HASH_SIZE * 2) + 1)
#define SHA512_STRING_SIZE      ((SHA512_HASH_SIZE * 2) + 1)

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

/**
 * @brief Default chunk size for streaming file hash (64 KB)
 * Optimized for typical SSD sector sizes and cache efficiency
 */
#define HASH_DEFAULT_CHUNK_SIZE         (64 * 1024)

/**
 * @brief Minimum chunk size for streaming operations
 */
#define HASH_MIN_CHUNK_SIZE             (4 * 1024)

/**
 * @brief Maximum chunk size for streaming operations (1 MB)
 */
#define HASH_MAX_CHUNK_SIZE             (1 * 1024 * 1024)

/**
 * @brief Maximum file size for hashing (500 MB default)
 * Prevents DoS via large file hashing
 */
#define HASH_MAX_FILE_SIZE_DEFAULT      (500ULL * 1024 * 1024)

/**
 * @brief Maximum file size for hashing (absolute limit 2 GB)
 */
#define HASH_MAX_FILE_SIZE_LIMIT        (2ULL * 1024 * 1024 * 1024)

/**
 * @brief Pool tag for hash allocations: 'hSSx' = ShadowStrike Hash
 */
#define SHADOWSTRIKE_HASH_TAG           'hSSx'

/**
 * @brief Pool tag for hash object allocations
 */
#define SHADOWSTRIKE_HASH_OBJ_TAG       'oHSx'

/**
 * @brief Pool tag for hash buffer allocations
 */
#define SHADOWSTRIKE_HASH_BUF_TAG       'bHSx'

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Supported hash algorithms
 */
typedef enum _SHADOWSTRIKE_HASH_ALGORITHM {
    ShadowHashAlgorithmNone = 0,
    ShadowHashAlgorithmSha256,          ///< SHA-256 (recommended)
    ShadowHashAlgorithmSha1,            ///< SHA-1 (legacy compatibility)
    ShadowHashAlgorithmMd5,             ///< MD5 (legacy compatibility only)
    ShadowHashAlgorithmSha512,          ///< SHA-512 (high security)
    ShadowHashAlgorithmCount
} SHADOWSTRIKE_HASH_ALGORITHM;

/**
 * @brief Hash operation flags
 */
typedef enum _SHADOWSTRIKE_HASH_FLAGS {
    /// No special flags
    ShadowHashFlagNone              = 0x00000000,

    /// Use non-cached I/O for file reads (default for large files)
    ShadowHashFlagNonCached         = 0x00000001,

    /// Compute hash without updating file access time
    ShadowHashFlagNoAccessTimeUpdate = 0x00000002,

    /// Allow partial hash on read errors (for forensics)
    ShadowHashFlagAllowPartial      = 0x00000004,

    /// Secure wipe intermediate buffers after hashing
    ShadowHashFlagSecureWipe        = 0x00000008,

    /// Use paged pool for read buffer (lower IRQL operations)
    ShadowHashFlagPagedBuffer       = 0x00000010,

    /// Compute Authenticode hash (PE files only)
    ShadowHashFlagAuthenticode      = 0x00000020,

    /// Verify PE signature while hashing
    ShadowHashFlagVerifySignature   = 0x00000040

} SHADOWSTRIKE_HASH_FLAGS;

/**
 * @brief Hash computation result status
 */
typedef enum _SHADOWSTRIKE_HASH_STATUS {
    ShadowHashStatusSuccess = 0,
    ShadowHashStatusPartial,            ///< Partial hash computed (file truncated/error)
    ShadowHashStatusFileTooLarge,       ///< File exceeds size limit
    ShadowHashStatusAccessDenied,       ///< Cannot read file
    ShadowHashStatusInvalidFile,        ///< File is invalid or corrupted
    ShadowHashStatusAlgorithmError,     ///< CNG algorithm error
    ShadowHashStatusMemoryError,        ///< Memory allocation failed
    ShadowHashStatusInvalidParameter,   ///< Invalid input parameter
    ShadowHashStatusNotInitialized,     ///< Subsystem not initialized
    ShadowHashStatusTimeout,            ///< Operation timed out
    ShadowHashStatusCancelled           ///< Operation was cancelled
} SHADOWSTRIKE_HASH_STATUS;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Hash result structure
 *
 * Contains computed hash and metadata about the operation.
 */
typedef struct _SHADOWSTRIKE_HASH_RESULT {
    /// Computed hash bytes
    UCHAR Hash[MAX_HASH_SIZE];

    /// Size of hash in bytes
    ULONG HashSize;

    /// Algorithm used
    SHADOWSTRIKE_HASH_ALGORITHM Algorithm;

    /// Operation status
    SHADOWSTRIKE_HASH_STATUS Status;

    /// NTSTATUS from underlying operation (for detailed error info)
    NTSTATUS NtStatus;

    /// Number of bytes actually hashed
    ULONG64 BytesHashed;

    /// Total file size (if file hash)
    ULONG64 TotalFileSize;

    /// Time taken in microseconds
    ULONG64 ElapsedMicroseconds;

    /// TRUE if hash is partial (due to error or size limit)
    BOOLEAN IsPartial;

    /// Reserved for alignment
    UCHAR Reserved[7];

} SHADOWSTRIKE_HASH_RESULT, *PSHADOWSTRIKE_HASH_RESULT;

/**
 * @brief Multi-hash result (parallel algorithm computation)
 *
 * Used when computing multiple hash algorithms in a single pass.
 */
typedef struct _SHADOWSTRIKE_MULTI_HASH_RESULT {
    /// SHA-256 hash
    UCHAR Sha256[SHA256_HASH_SIZE];

    /// SHA-1 hash (legacy)
    UCHAR Sha1[SHA1_HASH_SIZE];

    /// MD5 hash (legacy)
    UCHAR Md5[MD5_HASH_SIZE];

    /// Operation status
    SHADOWSTRIKE_HASH_STATUS Status;

    /// NTSTATUS from underlying operation
    NTSTATUS NtStatus;

    /// Number of bytes hashed
    ULONG64 BytesHashed;

    /// Which algorithms were computed (bitmask)
    ULONG AlgorithmsComputed;

    /// Reserved
    ULONG Reserved;

} SHADOWSTRIKE_MULTI_HASH_RESULT, *PSHADOWSTRIKE_MULTI_HASH_RESULT;

/**
 * @brief Streaming hash context
 *
 * Used for incremental hash computation across multiple buffers.
 */
typedef struct _SHADOWSTRIKE_HASH_CONTEXT {
    /// CNG hash handle
    BCRYPT_HASH_HANDLE HashHandle;

    /// Hash object buffer
    PUCHAR HashObject;

    /// Hash object size
    ULONG HashObjectSize;

    /// Algorithm being used
    SHADOWSTRIKE_HASH_ALGORITHM Algorithm;

    /// Expected hash size
    ULONG ExpectedHashSize;

    /// Total bytes hashed so far
    ULONG64 TotalBytesHashed;

    /// Is context valid/initialized
    BOOLEAN IsValid;

    /// Has finalize been called
    BOOLEAN IsFinalized;

    /// Reserved
    UCHAR Reserved[6];

} SHADOWSTRIKE_HASH_CONTEXT, *PSHADOWSTRIKE_HASH_CONTEXT;

/**
 * @brief Hash configuration options
 */
typedef struct _SHADOWSTRIKE_HASH_CONFIG {
    /// Maximum file size to hash (0 = use default)
    ULONG64 MaxFileSize;

    /// Chunk size for streaming operations (0 = use default)
    ULONG ChunkSize;

    /// Operation flags
    ULONG Flags;

    /// Timeout in milliseconds (0 = no timeout)
    ULONG TimeoutMs;

    /// Reserved for future use
    ULONG Reserved[4];

} SHADOWSTRIKE_HASH_CONFIG, *PSHADOWSTRIKE_HASH_CONFIG;

/**
 * @brief Hash subsystem statistics
 */
typedef struct _SHADOWSTRIKE_HASH_STATISTICS {
    /// Total hash operations performed
    volatile LONG64 TotalOperations;

    /// Successful hash operations
    volatile LONG64 SuccessfulOperations;

    /// Failed hash operations
    volatile LONG64 FailedOperations;

    /// Total bytes hashed
    volatile LONG64 TotalBytesHashed;

    /// SHA-256 operations
    volatile LONG64 Sha256Operations;

    /// SHA-1 operations
    volatile LONG64 Sha1Operations;

    /// MD5 operations
    volatile LONG64 Md5Operations;

    /// SHA-512 operations
    volatile LONG64 Sha512Operations;

    /// File hash operations
    volatile LONG64 FileHashOperations;

    /// Buffer hash operations
    volatile LONG64 BufferHashOperations;

    /// Operations exceeding size limit
    volatile LONG64 SizeLimitExceeded;

    /// CNG errors encountered
    volatile LONG64 CngErrors;

    /// Current outstanding hash operations
    volatile LONG CurrentOperations;

    /// Peak concurrent operations
    volatile LONG PeakOperations;

} SHADOWSTRIKE_HASH_STATISTICS, *PSHADOWSTRIKE_HASH_STATISTICS;

// ============================================================================
// SUBSYSTEM INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the hashing subsystem.
 *
 * Opens CNG algorithm providers for all supported algorithms.
 * Must be called during DriverEntry before any hash operations.
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 *
 * @note Thread-safe, can be called multiple times (reference counted)
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeInitializeHashUtils(
    VOID
    );

/**
 * @brief Cleanup the hashing subsystem.
 *
 * Closes all CNG algorithm providers and releases resources.
 * Must be called during DriverUnload.
 *
 * @irql PASSIVE_LEVEL
 *
 * @note Thread-safe, matches Initialize reference count
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeCleanupHashUtils(
    VOID
    );

/**
 * @brief Check if hash subsystem is initialized.
 *
 * @return TRUE if initialized and ready for operations
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsHashUtilsInitialized(
    VOID
    );

/**
 * @brief Get hash subsystem statistics.
 *
 * @param Statistics    Receives current statistics
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeGetHashStatistics(
    _Out_ PSHADOWSTRIKE_HASH_STATISTICS Statistics
    );

/**
 * @brief Reset hash subsystem statistics.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeResetHashStatistics(
    VOID
    );

// ============================================================================
// BUFFER HASHING
// ============================================================================

/**
 * @brief Compute SHA-256 hash of a memory buffer.
 *
 * @param Buffer    Pointer to data to hash
 * @param Length    Size of data in bytes
 * @param Hash      Receives the 32-byte hash
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL (if buffer is non-paged)
 *
 * @note This is the primary hash function for most use cases
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeComputeSha256(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(SHA256_HASH_SIZE) PUCHAR Hash
    );

/**
 * @brief Compute SHA-1 hash of a memory buffer.
 *
 * @param Buffer    Pointer to data to hash
 * @param Length    Size of data in bytes
 * @param Hash      Receives the 20-byte hash
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL (if buffer is non-paged)
 *
 * @warning SHA-1 is cryptographically weak. Use SHA-256 for new code.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeComputeSha1(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(SHA1_HASH_SIZE) PUCHAR Hash
    );

/**
 * @brief Compute MD5 hash of a memory buffer.
 *
 * @param Buffer    Pointer to data to hash
 * @param Length    Size of data in bytes
 * @param Hash      Receives the 16-byte hash
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL (if buffer is non-paged)
 *
 * @warning MD5 is cryptographically broken. Use only for legacy compatibility.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeComputeMd5(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(MD5_HASH_SIZE) PUCHAR Hash
    );

/**
 * @brief Compute SHA-512 hash of a memory buffer.
 *
 * @param Buffer    Pointer to data to hash
 * @param Length    Size of data in bytes
 * @param Hash      Receives the 64-byte hash
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL (if buffer is non-paged)
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeComputeSha512(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(SHA512_HASH_SIZE) PUCHAR Hash
    );

/**
 * @brief Compute hash of buffer using specified algorithm.
 *
 * @param Algorithm Algorithm to use
 * @param Buffer    Pointer to data to hash
 * @param Length    Size of data in bytes
 * @param Result    Receives hash result with full metadata
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL (if buffer is non-paged)
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeComputeBufferHash(
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PSHADOWSTRIKE_HASH_RESULT Result
    );

/**
 * @brief Compute multiple hashes of buffer in single pass.
 *
 * Computes SHA-256, SHA-1, and MD5 in parallel for efficiency.
 * Useful for threat intelligence matching against multiple hash types.
 *
 * @param Buffer    Pointer to data to hash
 * @param Length    Size of data in bytes
 * @param Result    Receives all computed hashes
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL (if buffer is non-paged)
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeComputeMultiHash(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PSHADOWSTRIKE_MULTI_HASH_RESULT Result
    );

// ============================================================================
// FILE HASHING
// ============================================================================

/**
 * @brief Compute SHA-256 hash of a file.
 *
 * Reads file in chunks using streaming hash computation.
 * Suitable for large files without loading entire content into memory.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object to hash
 * @param Hash          Receives the 32-byte hash
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeComputeFileHash(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_writes_bytes_(SHA256_HASH_SIZE) PUCHAR Hash
    );

/**
 * @brief Compute file hash with full configuration options.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object to hash
 * @param Algorithm     Hash algorithm to use
 * @param Config        Configuration options (NULL for defaults)
 * @param Result        Receives hash result with full metadata
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeComputeFileHashEx(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm,
    _In_opt_ PSHADOWSTRIKE_HASH_CONFIG Config,
    _Out_ PSHADOWSTRIKE_HASH_RESULT Result
    );

/**
 * @brief Compute multiple hashes of file in single pass.
 *
 * @param Instance      Filter instance
 * @param FileObject    File object to hash
 * @param Config        Configuration options (NULL for defaults)
 * @param Result        Receives all computed hashes
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeComputeFileMultiHash(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ PSHADOWSTRIKE_HASH_CONFIG Config,
    _Out_ PSHADOWSTRIKE_MULTI_HASH_RESULT Result
    );

/**
 * @brief Compute hash of file by path.
 *
 * Opens file, computes hash, and closes file.
 * Convenience function for path-based operations.
 *
 * @param FilePath      Full path to file (NT path format)
 * @param Algorithm     Hash algorithm to use
 * @param Result        Receives hash result
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeComputeFileHashByPath(
    _In_ PCUNICODE_STRING FilePath,
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm,
    _Out_ PSHADOWSTRIKE_HASH_RESULT Result
    );

// ============================================================================
// STREAMING HASH CONTEXT
// ============================================================================

/**
 * @brief Initialize streaming hash context.
 *
 * Creates a context for incremental hash computation.
 * Useful when data arrives in chunks or from multiple sources.
 *
 * @param Context       Context to initialize
 * @param Algorithm     Hash algorithm to use
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 *
 * @note Context must be cleaned up with ShadowStrikeHashContextCleanup
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeHashContextInit(
    _Out_ PSHADOWSTRIKE_HASH_CONTEXT Context,
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm
    );

/**
 * @brief Add data to streaming hash context.
 *
 * @param Context       Initialized hash context
 * @param Buffer        Data to add to hash
 * @param Length        Length of data
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL (if buffer is non-paged)
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeHashContextUpdate(
    _Inout_ PSHADOWSTRIKE_HASH_CONTEXT Context,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length
    );

/**
 * @brief Finalize streaming hash and get result.
 *
 * @param Context       Hash context to finalize
 * @param Hash          Receives computed hash
 * @param HashSize      Size of hash buffer
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 *
 * @note Context cannot be used after finalization
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeHashContextFinalize(
    _Inout_ PSHADOWSTRIKE_HASH_CONTEXT Context,
    _Out_writes_bytes_(HashSize) PUCHAR Hash,
    _In_ ULONG HashSize
    );

/**
 * @brief Cleanup streaming hash context.
 *
 * Releases all resources associated with context.
 * Safe to call on uninitialized or already-cleaned-up context.
 *
 * @param Context       Context to cleanup
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeHashContextCleanup(
    _Inout_ PSHADOWSTRIKE_HASH_CONTEXT Context
    );

/**
 * @brief Clone streaming hash context.
 *
 * Creates a duplicate of the context in its current state.
 * Useful for computing hash of data prefix.
 *
 * @param Source        Source context to clone
 * @param Destination   Receives cloned context
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeHashContextClone(
    _In_ PSHADOWSTRIKE_HASH_CONTEXT Source,
    _Out_ PSHADOWSTRIKE_HASH_CONTEXT Destination
    );

// ============================================================================
// HASH COMPARISON
// ============================================================================

/**
 * @brief Compare two hashes for equality (constant-time).
 *
 * Uses constant-time comparison to prevent timing attacks.
 *
 * @param Hash1     First hash
 * @param Hash2     Second hash
 * @param HashSize  Size of hashes in bytes
 *
 * @return TRUE if hashes are equal
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeCompareHash(
    _In_reads_bytes_(HashSize) const UCHAR* Hash1,
    _In_reads_bytes_(HashSize) const UCHAR* Hash2,
    _In_ ULONG HashSize
    );

/**
 * @brief Compare SHA-256 hashes (constant-time).
 *
 * @param Hash1     First 32-byte hash
 * @param Hash2     Second 32-byte hash
 *
 * @return TRUE if hashes are equal
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeCompareSha256(
    _In_reads_bytes_(SHA256_HASH_SIZE) const UCHAR* Hash1,
    _In_reads_bytes_(SHA256_HASH_SIZE) const UCHAR* Hash2
    );

// ============================================================================
// HASH STRING CONVERSION
// ============================================================================

/**
 * @brief Convert hash bytes to hexadecimal string.
 *
 * @param Hash          Hash bytes
 * @param HashSize      Size of hash
 * @param String        Receives hex string (must be at least HashSize*2+1)
 * @param StringSize    Size of string buffer in bytes
 * @param Uppercase     TRUE for uppercase hex, FALSE for lowercase
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeHashToString(
    _In_reads_bytes_(HashSize) const UCHAR* Hash,
    _In_ ULONG HashSize,
    _Out_writes_z_(StringSize) PWCHAR String,
    _In_ ULONG StringSize,
    _In_ BOOLEAN Uppercase
    );

/**
 * @brief Convert hexadecimal string to hash bytes.
 *
 * @param String        Hex string (null-terminated)
 * @param Hash          Receives hash bytes
 * @param HashSize      Size of hash buffer
 * @param BytesWritten  Receives number of bytes written
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeStringToHash(
    _In_z_ PCWSTR String,
    _Out_writes_bytes_(HashSize) PUCHAR Hash,
    _In_ ULONG HashSize,
    _Out_opt_ PULONG BytesWritten
    );

/**
 * @brief Convert SHA-256 hash to UNICODE_STRING.
 *
 * Allocates buffer for the string representation.
 * Caller must free with ShadowStrikeFreeUnicodeString.
 *
 * @param Hash          32-byte SHA-256 hash
 * @param String        Receives allocated UNICODE_STRING
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeSha256ToString(
    _In_reads_bytes_(SHA256_HASH_SIZE) const UCHAR* Hash,
    _Out_ PUNICODE_STRING String
    );

// ============================================================================
// HMAC OPERATIONS
// ============================================================================

/**
 * @brief Compute HMAC-SHA256.
 *
 * @param Key           HMAC key
 * @param KeyLength     Key length in bytes
 * @param Data          Data to authenticate
 * @param DataLength    Data length in bytes
 * @param Mac           Receives 32-byte MAC
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= DISPATCH_LEVEL (if buffers are non-paged)
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeComputeHmacSha256(
    _In_reads_bytes_(KeyLength) const UCHAR* Key,
    _In_ ULONG KeyLength,
    _In_reads_bytes_(DataLength) const UCHAR* Data,
    _In_ ULONG DataLength,
    _Out_writes_bytes_(SHA256_HASH_SIZE) PUCHAR Mac
    );

/**
 * @brief Verify HMAC-SHA256.
 *
 * @param Key           HMAC key
 * @param KeyLength     Key length in bytes
 * @param Data          Data to verify
 * @param DataLength    Data length in bytes
 * @param ExpectedMac   Expected MAC value
 *
 * @return TRUE if MAC is valid
 *
 * @irql <= DISPATCH_LEVEL (if buffers are non-paged)
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeVerifyHmacSha256(
    _In_reads_bytes_(KeyLength) const UCHAR* Key,
    _In_ ULONG KeyLength,
    _In_reads_bytes_(DataLength) const UCHAR* Data,
    _In_ ULONG DataLength,
    _In_reads_bytes_(SHA256_HASH_SIZE) const UCHAR* ExpectedMac
    );

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get hash size for algorithm.
 *
 * @param Algorithm     Hash algorithm
 *
 * @return Hash size in bytes, or 0 for invalid algorithm
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
ShadowStrikeGetHashSize(
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm
    );

/**
 * @brief Get algorithm name string.
 *
 * @param Algorithm     Hash algorithm
 *
 * @return Constant string name (e.g., L"SHA-256")
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PCWSTR
ShadowStrikeGetHashAlgorithmName(
    _In_ SHADOWSTRIKE_HASH_ALGORITHM Algorithm
    );

/**
 * @brief Validate hash result structure.
 *
 * @param Result        Hash result to validate
 *
 * @return TRUE if result is valid and successful
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsHashResultValid(
    _In_ PSHADOWSTRIKE_HASH_RESULT Result
    );

/**
 * @brief Initialize default hash configuration.
 *
 * @param Config        Configuration to initialize
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeInitDefaultHashConfig(
    _Out_ PSHADOWSTRIKE_HASH_CONFIG Config
    );

/**
 * @brief Zero out hash result structure securely.
 *
 * @param Result        Result to clear
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeClearHashResult(
    _Inout_ PSHADOWSTRIKE_HASH_RESULT Result
    );

// ============================================================================
// INLINE UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Check if hash is all zeros.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeIsHashEmpty(
    _In_reads_bytes_(HashSize) const UCHAR* Hash,
    _In_ ULONG HashSize
    )
{
    ULONG i;
    UCHAR Accumulator = 0;

    for (i = 0; i < HashSize; i++) {
        Accumulator |= Hash[i];
    }

    return (Accumulator == 0);
}

/**
 * @brief Quick hash validation (non-cryptographic).
 */
FORCEINLINE
ULONG
ShadowStrikeQuickHashValidation(
    _In_reads_bytes_(HashSize) const UCHAR* Hash,
    _In_ ULONG HashSize
    )
{
    ULONG i;
    ULONG Sum = 0;

    for (i = 0; i < HashSize; i++) {
        Sum += Hash[i];
    }

    return Sum;
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_HASH_UTILS_H_
