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
    Module: Compression.h
    
    Purpose: High-performance LZ4 compression for telemetry and message
             data to reduce bandwidth and improve transfer efficiency.
             
    Architecture:
    - LZ4 fast compression (optimized for speed)
    - LZ4 HC high compression (optimized for ratio)
    - Stream compression for large data
    - Dictionary support for repeated patterns
    
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>

//=============================================================================
// Pool Tags
//=============================================================================

#define COMP_POOL_TAG_BUFFER    'FBOC'  // Compression - Buffer
#define COMP_POOL_TAG_DICT      'DBOC'  // Compression - Dictionary
#define COMP_POOL_TAG_STREAM    'SBOC'  // Compression - Stream
#define COMP_POOL_TAG_CONTEXT   'CBOC'  // Compression - Context

//=============================================================================
// Configuration Constants
//=============================================================================

// Buffer limits
#define COMP_MIN_INPUT_SIZE             64          // Below this, don't compress
#define COMP_MAX_INPUT_SIZE             (64 * 1024 * 1024)  // 64 MB max
#define COMP_DEFAULT_BUFFER_SIZE        (64 * 1024) // 64 KB default
#define COMP_MAX_DICT_SIZE              (64 * 1024) // 64 KB dictionary

// LZ4 constants (from LZ4 specification)
#define LZ4_MAX_INPUT_SIZE              0x7E000000  // ~2 GB
#define LZ4_COMPRESSBOUND(isize)        ((unsigned)(isize) + ((isize)/255) + 16)
#define LZ4_ACCELERATION_DEFAULT        1
#define LZ4_ACCELERATION_MAX            65535

// Compression levels
#define COMP_LEVEL_FASTEST              0
#define COMP_LEVEL_FAST                 1
#define COMP_LEVEL_DEFAULT              4
#define COMP_LEVEL_BETTER               9
#define COMP_LEVEL_BEST                 12
#define COMP_LEVEL_MAX                  16

//=============================================================================
// Compression Algorithm Types
//=============================================================================

typedef enum _COMP_ALGORITHM {
    CompAlgorithm_None = 0,             // No compression
    CompAlgorithm_LZ4_Fast,             // LZ4 fast (default)
    CompAlgorithm_LZ4_HC,               // LZ4 high compression
    CompAlgorithm_RLE,                  // Run-length encoding (simple)
    CompAlgorithm_Delta,                // Delta encoding (for timestamps)
    CompAlgorithm_Max
} COMP_ALGORITHM;

//=============================================================================
// Compression Flags
//=============================================================================

typedef enum _COMP_FLAGS {
    CompFlag_None               = 0x00000000,
    CompFlag_UseDictionary      = 0x00000001,   // Use dictionary
    CompFlag_StreamMode         = 0x00000002,   // Stream compression
    CompFlag_VerifyChecksum     = 0x00000004,   // Verify on decompress
    CompFlag_IndependentBlocks  = 0x00000008,   // Each block independent
    CompFlag_ContentSize        = 0x00000010,   // Store original size
    CompFlag_Checksum           = 0x00000020,   // Add checksum
    CompFlag_DictId             = 0x00000040,   // Include dictionary ID
} COMP_FLAGS;

//=============================================================================
// Compression Header
//=============================================================================

#pragma pack(push, 1)

typedef struct _COMP_HEADER {
    ULONG Magic;                        // 'COMP' or 'LZ4C'
    ULONG Version;                      // Header version
    COMP_ALGORITHM Algorithm;           // Compression algorithm
    COMP_FLAGS Flags;                   // Compression flags
    ULONG OriginalSize;                 // Original uncompressed size
    ULONG CompressedSize;               // Compressed size (without header)
    ULONG Checksum;                     // CRC32 of original data
    ULONG DictionaryId;                 // Dictionary ID (if used)
    ULONG Reserved[2];                  // Future use
} COMP_HEADER, *PCOMP_HEADER;

#define COMP_MAGIC          'PMOC'      // 'COMP' reversed
#define COMP_MAGIC_LZ4      'C4ZL'      // 'LZ4C' reversed
#define COMP_VERSION        1

C_ASSERT(sizeof(COMP_HEADER) == 40);

#pragma pack(pop)

//=============================================================================
// Compression Context
//=============================================================================

//
// Forward declaration for dictionary
//
typedef struct _COMP_DICTIONARY *PCOMP_DICTIONARY_REF;

typedef struct _COMP_CONTEXT {
    //
    // Algorithm settings
    //
    COMP_ALGORITHM Algorithm;
    COMP_FLAGS Flags;
    ULONG CompressionLevel;
    ULONG Acceleration;

    //
    // Dictionary support - stores actual PCOMP_DICTIONARY reference
    //
    PCOMP_DICTIONARY_REF DictionaryRef;
    PVOID DictionaryData;
    ULONG DictionarySize;
    ULONG DictionaryId;

    //
    // Internal state (for stream mode)
    //
    PVOID InternalState;
    ULONG InternalStateSize;
    BOOLEAN StreamInitialized;

    //
    // Work buffers
    //
    PVOID WorkBuffer;
    ULONG WorkBufferSize;

    //
    // Statistics (must be accessed atomically)
    //
    volatile LONG64 TotalBytesIn;
    volatile LONG64 TotalBytesOut;
    volatile LONG64 TotalOperations;

    //
    // Synchronization - protects dictionary changes
    //
    EX_SPIN_LOCK Lock;

    //
    // Indicates context is valid and initialized
    //
    volatile LONG Initialized;

} COMP_CONTEXT, *PCOMP_CONTEXT;

//=============================================================================
// Stream Context (for multi-block compression)
//=============================================================================

typedef struct _COMP_STREAM {
    //
    // Stream identification
    //
    ULONG StreamId;
    COMP_ALGORITHM Algorithm;
    
    //
    // Block tracking
    //
    ULONG BlockSize;
    ULONG BlockCount;
    ULONG CurrentBlock;
    
    //
    // Cumulative data
    //
    ULONG64 TotalOriginalSize;
    ULONG64 TotalCompressedSize;
    
    //
    // Dictionary context
    //
    PVOID DictContext;
    BOOLEAN UseDictionary;
    
    //
    // Internal LZ4 stream state
    //
    PVOID LZ4StreamState;
    ULONG LZ4StateSize;
    
    //
    // Ring buffer for inter-block references
    //
    PVOID RingBuffer;
    ULONG RingBufferSize;
    ULONG RingBufferPos;
    
    //
    // Statistics
    //
    LARGE_INTEGER StartTime;
    ULONG64 BytesProcessed;
    
} COMP_STREAM, *PCOMP_STREAM;

//=============================================================================
// Dictionary
//=============================================================================

typedef struct _COMP_DICTIONARY {
    //
    // Dictionary identification
    //
    ULONG DictionaryId;
    ULONG Version;
    
    //
    // Dictionary data
    //
    PVOID Data;
    ULONG Size;
    ULONG UsageCount;
    
    //
    // Precomputed state for LZ4
    //
    PVOID LZ4DictState;
    BOOLEAN LZ4StateReady;
    
    //
    // Reference counting
    //
    volatile LONG RefCount;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} COMP_DICTIONARY, *PCOMP_DICTIONARY;

//=============================================================================
// Compression Manager
//=============================================================================

typedef struct _COMP_MANAGER {
    //
    // Initialization state - use interlocked access
    //
    volatile LONG Initialized;

    //
    // Reference count for safe shutdown
    //
    volatile LONG RefCount;

    //
    // Default context for quick operations
    //
    COMP_CONTEXT DefaultContext;

    //
    // Dictionary cache
    //
    LIST_ENTRY DictionaryList;
    EX_SPIN_LOCK DictionaryLock;
    volatile LONG DictionaryCount;
    ULONG MaxDictionaries;

    //
    // Statistics - all must be accessed atomically
    //
    struct {
        volatile LONG64 TotalCompressed;
        volatile LONG64 TotalDecompressed;
        volatile LONG64 BytesSaved;
        volatile LONG64 Errors;
        volatile LONG PeakRatio;        // Peak compression ratio (percentage)
    } Stats;

    //
    // Configuration
    //
    struct {
        COMP_ALGORITHM DefaultAlgorithm;
        ULONG DefaultLevel;
        ULONG MinSizeToCompress;
        BOOLEAN AlwaysVerify;
    } Config;

} COMP_MANAGER, *PCOMP_MANAGER;

//=============================================================================
// Compression Options
//=============================================================================

typedef struct _COMP_OPTIONS {
    COMP_ALGORITHM Algorithm;           // Algorithm to use
    ULONG CompressionLevel;             // 0-16 (0=fastest, 16=best)
    COMP_FLAGS Flags;                   // Compression flags
    PCOMP_DICTIONARY Dictionary;        // Optional dictionary
    ULONG Acceleration;                 // LZ4 acceleration (1=default)
} COMP_OPTIONS, *PCOMP_OPTIONS;

//=============================================================================
// Public API - Initialization
//=============================================================================

//
// Initialize the compression manager
//
NTSTATUS
CompInitialize(
    _Out_ PCOMP_MANAGER Manager
    );

//
// Shutdown the compression manager
//
VOID
CompShutdown(
    _Inout_ PCOMP_MANAGER Manager
    );

//=============================================================================
// Public API - Simple Compression/Decompression
//=============================================================================

//
// Compress data in a single call
//
NTSTATUS
CompCompress(
    _In_reads_bytes_(InputSize) PVOID Input,
    _In_ ULONG InputSize,
    _Out_writes_bytes_to_(OutputSize, *CompressedSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG CompressedSize,
    _In_opt_ PCOMP_OPTIONS Options
    );

//
// Decompress data in a single call
//
NTSTATUS
CompDecompress(
    _In_reads_bytes_(CompressedSize) PVOID Compressed,
    _In_ ULONG CompressedSize,
    _Out_writes_bytes_to_(OutputSize, *DecompressedSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG DecompressedSize,
    _In_opt_ PCOMP_OPTIONS Options
    );

//
// Calculate worst-case compressed size
//
ULONG
CompGetBound(
    _In_ ULONG InputSize,
    _In_ COMP_ALGORITHM Algorithm
    );

//
// Get original size from compressed data
//
NTSTATUS
CompGetOriginalSize(
    _In_reads_bytes_(HeaderSize) PVOID CompressedData,
    _In_ ULONG HeaderSize,
    _Out_ PULONG OriginalSize
    );

//=============================================================================
// Public API - Context-Based Compression
//=============================================================================

//
// Create a compression context
//
NTSTATUS
CompCreateContext(
    _Out_ PCOMP_CONTEXT* Context,
    _In_ COMP_ALGORITHM Algorithm,
    _In_ ULONG CompressionLevel
    );

//
// Destroy a compression context
//
VOID
CompDestroyContext(
    _Inout_ PCOMP_CONTEXT Context
    );

//
// Compress using context (more efficient for repeated use)
//
NTSTATUS
CompCompressWithContext(
    _In_ PCOMP_CONTEXT Context,
    _In_reads_bytes_(InputSize) PVOID Input,
    _In_ ULONG InputSize,
    _Out_writes_bytes_to_(OutputSize, *CompressedSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG CompressedSize
    );

//
// Decompress using context
//
NTSTATUS
CompDecompressWithContext(
    _In_ PCOMP_CONTEXT Context,
    _In_reads_bytes_(CompressedSize) PVOID Compressed,
    _In_ ULONG CompressedSize,
    _Out_writes_bytes_to_(OutputSize, *DecompressedSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG DecompressedSize
    );

//=============================================================================
// Public API - Stream Compression
//=============================================================================

//
// Begin stream compression
//
NTSTATUS
CompStreamBegin(
    _Out_ PCOMP_STREAM* Stream,
    _In_ COMP_ALGORITHM Algorithm,
    _In_ ULONG BlockSize,
    _In_opt_ PCOMP_OPTIONS Options
    );

//
// Compress a block in stream mode
//
NTSTATUS
CompStreamCompress(
    _Inout_ PCOMP_STREAM Stream,
    _In_reads_bytes_(InputSize) PVOID Input,
    _In_ ULONG InputSize,
    _Out_writes_bytes_to_(OutputSize, *CompressedSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG CompressedSize
    );

//
// End stream compression
//
NTSTATUS
CompStreamEnd(
    _Inout_ PCOMP_STREAM Stream,
    _Out_opt_ PULONG64 TotalOriginal,
    _Out_opt_ PULONG64 TotalCompressed
    );

//
// Begin stream decompression
//
NTSTATUS
CompStreamDecompressBegin(
    _Out_ PCOMP_STREAM* Stream,
    _In_ COMP_ALGORITHM Algorithm,
    _In_opt_ PCOMP_OPTIONS Options
    );

//
// Decompress a block in stream mode
//
NTSTATUS
CompStreamDecompress(
    _Inout_ PCOMP_STREAM Stream,
    _In_reads_bytes_(CompressedSize) PVOID Compressed,
    _In_ ULONG CompressedSize,
    _Out_writes_bytes_to_(OutputSize, *DecompressedSize) PVOID Output,
    _In_ ULONG OutputSize,
    _Out_ PULONG DecompressedSize
    );

//
// End stream decompression
//
VOID
CompStreamDecompressEnd(
    _Inout_ PCOMP_STREAM Stream
    );

//=============================================================================
// Public API - Dictionary Management
//=============================================================================

//
// Create a compression dictionary from sample data
//
NTSTATUS
CompCreateDictionary(
    _Out_ PCOMP_DICTIONARY* Dictionary,
    _In_reads_bytes_(SampleSize) PVOID SampleData,
    _In_ ULONG SampleSize,
    _In_ ULONG MaxDictSize
    );

//
// Load a pre-built dictionary
//
NTSTATUS
CompLoadDictionary(
    _Out_ PCOMP_DICTIONARY* Dictionary,
    _In_reads_bytes_(DictSize) PVOID DictData,
    _In_ ULONG DictSize,
    _In_ ULONG DictionaryId
    );

//
// Destroy a dictionary
//
VOID
CompDestroyDictionary(
    _Inout_ PCOMP_DICTIONARY Dictionary
    );

//
// Add reference to dictionary
//
VOID
CompDictionaryAddRef(
    _In_ PCOMP_DICTIONARY Dictionary
    );

//
// Release dictionary reference
//
VOID
CompDictionaryRelease(
    _In_ PCOMP_DICTIONARY Dictionary
    );

//
// Set context dictionary
//
NTSTATUS
CompSetDictionary(
    _Inout_ PCOMP_CONTEXT Context,
    _In_ PCOMP_DICTIONARY Dictionary
    );

//=============================================================================
// Public API - In-Place Operations
//=============================================================================

//
// Compress in-place (requires extra buffer space at end)
//
NTSTATUS
CompCompressInPlace(
    _Inout_updates_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG DataSize,
    _In_ ULONG BufferSize,
    _Out_ PULONG CompressedSize,
    _In_opt_ PCOMP_OPTIONS Options
    );

//
// Decompress in-place (requires data at end of buffer)
//
NTSTATUS
CompDecompressInPlace(
    _Inout_updates_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG CompressedSize,
    _In_ ULONG BufferSize,
    _Out_ PULONG DecompressedSize
    );

//=============================================================================
// Public API - Verification
//=============================================================================

//
// Verify compressed data integrity
//
NTSTATUS
CompVerify(
    _In_reads_bytes_(CompressedSize) PVOID CompressedData,
    _In_ ULONG CompressedSize
    );

//
// Verify and get metadata
//
NTSTATUS
CompVerifyEx(
    _In_reads_bytes_(CompressedSize) PVOID CompressedData,
    _In_ ULONG CompressedSize,
    _Out_ PCOMP_HEADER Header
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _COMP_STATISTICS {
    ULONG64 TotalCompressed;
    ULONG64 TotalDecompressed;
    ULONG64 BytesIn;
    ULONG64 BytesOut;
    ULONG64 BytesSaved;
    ULONG64 Errors;
    ULONG AverageRatio;                 // Percentage (e.g., 35 = 35% of original)
    ULONG PeakRatio;
} COMP_STATISTICS, *PCOMP_STATISTICS;

NTSTATUS
CompGetStatistics(
    _In_ PCOMP_MANAGER Manager,
    _Out_ PCOMP_STATISTICS Stats
    );

VOID
CompResetStatistics(
    _Inout_ PCOMP_MANAGER Manager
    );

//=============================================================================
// LZ4 Core Functions (Internal Implementation)
//=============================================================================

//
// These functions implement the LZ4 algorithm directly for kernel use
// (no dependency on external LZ4 library)
//

INT
LZ4_compress_default(
    _In_reads_bytes_(srcSize) const CHAR* src,
    _Out_writes_bytes_(dstCapacity) CHAR* dst,
    _In_ INT srcSize,
    _In_ INT dstCapacity
    );

INT
LZ4_compress_fast(
    _In_reads_bytes_(srcSize) const CHAR* src,
    _Out_writes_bytes_(dstCapacity) CHAR* dst,
    _In_ INT srcSize,
    _In_ INT dstCapacity,
    _In_ INT acceleration
    );

INT
LZ4_compress_HC(
    _In_reads_bytes_(srcSize) const CHAR* src,
    _Out_writes_bytes_(dstCapacity) CHAR* dst,
    _In_ INT srcSize,
    _In_ INT dstCapacity,
    _In_ INT compressionLevel
    );

INT
LZ4_decompress_safe(
    _In_reads_bytes_(compressedSize) const CHAR* src,
    _Out_writes_bytes_(dstCapacity) CHAR* dst,
    _In_ INT compressedSize,
    _In_ INT dstCapacity
    );

//
// LZ4_decompress_fast is DEPRECATED and REMOVED for security reasons.
// This function cannot safely validate input bounds without knowing
// the compressed size. Use LZ4_decompress_safe instead.
//
// INT LZ4_decompress_fast(...) - REMOVED - DO NOT USE
//

//
// Dictionary variants
//
INT
LZ4_compress_fast_usingDict(
    _In_ PVOID state,
    _In_reads_bytes_(srcSize) const CHAR* src,
    _Out_writes_bytes_(dstCapacity) CHAR* dst,
    _In_ INT srcSize,
    _In_ INT dstCapacity,
    _In_reads_bytes_(dictSize) const CHAR* dictBuffer,
    _In_ INT dictSize
    );

INT
LZ4_decompress_safe_usingDict(
    _In_reads_bytes_(compressedSize) const CHAR* src,
    _Out_writes_bytes_(dstCapacity) CHAR* dst,
    _In_ INT compressedSize,
    _In_ INT dstCapacity,
    _In_reads_bytes_(dictSize) const CHAR* dictBuffer,
    _In_ INT dictSize
    );

//=============================================================================
// Helper Macros
//=============================================================================

//
// Calculate compression ratio percentage
//
#define COMP_RATIO(original, compressed) \
    ((original) > 0 ? (((compressed) * 100) / (original)) : 100)

//
// Check if compression would be beneficial
//
#define COMP_SHOULD_COMPRESS(size) \
    ((size) >= COMP_MIN_INPUT_SIZE)

//
// Calculate required output buffer size
//
#define COMP_OUTPUT_SIZE(inputSize) \
    (sizeof(COMP_HEADER) + LZ4_COMPRESSBOUND(inputSize))

#ifdef __cplusplus
}
#endif
