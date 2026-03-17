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
    Module: BootDriverVerify.c - ELAM boot driver verification implementation

    This module provides cryptographic verification of boot-start drivers including:
    - SHA-256 hash calculation of driver images
    - Authenticode hash computation (excludes signature section)
    - Certificate extraction and validation
    - Bloom filter for rapid known-hash lookups
    - Known-good/known-bad hash database management

    Copyright (c) ShadowStrike Team
--*/

#include "BootDriverVerify.h"
#pragma warning(push)
#pragma warning(disable:4324)
#include "../PhantomSensor/Utilities/HashUtils.h"
#pragma warning(pop)
#include <ntimage.h>
#include <ntstrsafe.h>

// ============================================================================
// CONSTANTS AND CONFIGURATION
// ============================================================================

#define BDV_BLOOM_FILTER_SIZE_BITS      (1024 * 1024)   // 128KB = 1M bits (~1.4% FPR at 100K entries)
#define BDV_BLOOM_FILTER_SIZE_BYTES     (BDV_BLOOM_FILTER_SIZE_BITS / 8)
#define BDV_BLOOM_HASH_COUNT            7               // Number of hash functions
#define BDV_MAX_KNOWN_HASHES            100000          // Maximum hash entries
#define BDV_MAX_VERIFIED_DRIVERS        10000           // Maximum verified driver cache entries

#define BDV_HASH_SIZE                   32              // SHA-256

#define BDV_PE_DOS_SIGNATURE            0x5A4D          // 'MZ'
#define BDV_PE_NT_SIGNATURE             0x00004550      // 'PE\0\0'
#define BDV_MAX_IMAGE_SIZE              (100ULL * 1024 * 1024)  // 100MB max driver
#define BDV_MAX_PE_SECTIONS             96              // Stack-safe section sort limit

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

/**
 * @brief Hash entry for known good/bad lists
 */
typedef struct _BDV_HASH_ENTRY {
    UCHAR Hash[BDV_HASH_SIZE];
    BDV_CLASSIFICATION Classification;
    CHAR Description[64];
    LIST_ENTRY ListEntry;
} BDV_HASH_ENTRY, *PBDV_HASH_ENTRY;

/**
 * @brief Bloom filter for rapid hash lookups
 */
typedef struct _BDV_BLOOM_FILTER {
    PUCHAR BitArray;
    ULONG SizeBits;
    ULONG HashCount;
    volatile LONG EntryCount;
} BDV_BLOOM_FILTER, *PBDV_BLOOM_FILTER;

/**
 * @brief Internal verifier context
 */
typedef struct _BDV_VERIFIER_INTERNAL {
    BDV_VERIFIER Public;

    // Bloom filters for rapid lookup
    BDV_BLOOM_FILTER GoodBloomFilter;
    BDV_BLOOM_FILTER BadBloomFilter;

    // Hash entry counts
    volatile LONG KnownGoodCount;
    volatile LONG KnownBadCount;

    // Lookaside list for driver info allocations
    NPAGED_LOOKASIDE_LIST DriverInfoLookaside;
    BOOLEAN LookasideInitialized;

} BDV_VERIFIER_INTERNAL, *PBDV_VERIFIER_INTERNAL;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static NTSTATUS
BdvpInitializeBloomFilter(
    _Out_ PBDV_BLOOM_FILTER Filter,
    _In_ ULONG SizeBits,
    _In_ ULONG HashCount
    );

static VOID
BdvpDestroyBloomFilter(
    _Inout_ PBDV_BLOOM_FILTER Filter
    );

static VOID
BdvpBloomFilterAdd(
    _Inout_ PBDV_BLOOM_FILTER Filter,
    _In_reads_(BDV_HASH_SIZE) const UCHAR* Hash
    );

static BOOLEAN
BdvpBloomFilterMayContain(
    _In_ PBDV_BLOOM_FILTER Filter,
    _In_reads_(BDV_HASH_SIZE) const UCHAR* Hash
    );

static NTSTATUS
BdvpCalculateImageHash(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _Out_writes_(BDV_HASH_SIZE) PUCHAR Hash
    );

static NTSTATUS
BdvpCalculateAuthenticodeHash(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _Out_writes_(BDV_HASH_SIZE) PUCHAR Hash
    );

static NTSTATUS
BdvpExtractCertificateInfo(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _Inout_ PBDV_DRIVER_INFO Info
    );

static BOOLEAN
BdvpIsHashInList(
    _In_ PLIST_ENTRY ListHead,
    _In_ PEX_PUSH_LOCK Lock,
    _In_reads_(BDV_HASH_SIZE) const UCHAR* Hash
    );

static ULONG
BdvpMurmurHash3(
    _In_reads_(Length) const UCHAR* Data,
    _In_ ULONG Length,
    _In_ ULONG Seed
    );

static NTSTATUS
BdvpDeepCopyDriverPath(
    _In_ PUNICODE_STRING SourcePath,
    _Out_ PUNICODE_STRING DestPath,
    _Out_ PUNICODE_STRING DestName
    );

static VOID
BdvpFreeDriverInfoPaths(
    _Inout_ PBDV_DRIVER_INFO Info
    );

// ============================================================================
// BLOOM FILTER IMPLEMENTATION
// ============================================================================

/**
 * @brief Initialize a bloom filter
 */
static NTSTATUS
BdvpInitializeBloomFilter(
    _Out_ PBDV_BLOOM_FILTER Filter,
    _In_ ULONG SizeBits,
    _In_ ULONG HashCount
    )
{
    ULONG sizeBytes;

    if (Filter == NULL || SizeBits == 0 || HashCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Filter, sizeof(BDV_BLOOM_FILTER));

    sizeBytes = SizeBits / 8;

    Filter->BitArray = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeBytes,
        BDV_POOL_TAG
        );

    if (Filter->BitArray == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Filter->BitArray, sizeBytes);
    Filter->SizeBits = SizeBits;
    Filter->HashCount = HashCount;
    Filter->EntryCount = 0;

    return STATUS_SUCCESS;
}

/**
 * @brief Destroy a bloom filter
 */
static VOID
BdvpDestroyBloomFilter(
    _Inout_ PBDV_BLOOM_FILTER Filter
    )
{
    if (Filter == NULL) {
        return;
    }

    if (Filter->BitArray != NULL) {
        ExFreePoolWithTag(Filter->BitArray, BDV_POOL_TAG);
        Filter->BitArray = NULL;
    }

    Filter->SizeBits = 0;
    Filter->HashCount = 0;
    Filter->EntryCount = 0;
}

/**
 * @brief MurmurHash3 for bloom filter bit positions
 */
static ULONG
BdvpMurmurHash3(
    _In_reads_(Length) const UCHAR* Data,
    _In_ ULONG Length,
    _In_ ULONG Seed
    )
{
    const ULONG c1 = 0xcc9e2d51;
    const ULONG c2 = 0x1b873593;
    const ULONG r1 = 15;
    const ULONG r2 = 13;
    const ULONG m = 5;
    const ULONG n = 0xe6546b64;

    ULONG hash = Seed;
    ULONG k;
    ULONG i;
    const ULONG numBlocks = Length / 4;
    const UCHAR* tail = Data + (numBlocks * 4);

    // Body — use RtlCopyMemory to avoid unaligned ULONG access (ARM64 safe)
    for (i = 0; i < numBlocks; i++) {
        RtlCopyMemory(&k, Data + (i * 4), sizeof(ULONG));
        k *= c1;
        k = (k << r1) | (k >> (32 - r1));
        k *= c2;

        hash ^= k;
        hash = ((hash << r2) | (hash >> (32 - r2))) * m + n;
    }

    // Tail
    k = 0;
    switch (Length & 3) {
        case 3:
            k ^= (ULONG)tail[2] << 16;
            // Fall through
        case 2:
            k ^= (ULONG)tail[1] << 8;
            // Fall through
        case 1:
            k ^= (ULONG)tail[0];
            k *= c1;
            k = (k << r1) | (k >> (32 - r1));
            k *= c2;
            hash ^= k;
            break;
    }

    // Finalization
    hash ^= Length;
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;

    return hash;
}

/**
 * @brief Add a hash to the bloom filter
 */
static VOID
BdvpBloomFilterAdd(
    _Inout_ PBDV_BLOOM_FILTER Filter,
    _In_reads_(BDV_HASH_SIZE) const UCHAR* Hash
    )
{
    ULONG i;
    ULONG bitIndex;
    ULONG byteIndex;
    ULONG bitMask;

    if (Filter == NULL || Filter->BitArray == NULL || Hash == NULL) {
        return;
    }

    for (i = 0; i < Filter->HashCount; i++) {
        bitIndex = BdvpMurmurHash3(Hash, BDV_HASH_SIZE, i) % Filter->SizeBits;
        byteIndex = bitIndex / 8;
        bitMask = 1 << (bitIndex % 8);

        InterlockedOr8((volatile CHAR*)&Filter->BitArray[byteIndex], (CHAR)bitMask);
    }

    InterlockedIncrement(&Filter->EntryCount);
}

/**
 * @brief Check if a hash may be in the bloom filter
 */
static BOOLEAN
BdvpBloomFilterMayContain(
    _In_ PBDV_BLOOM_FILTER Filter,
    _In_reads_(BDV_HASH_SIZE) const UCHAR* Hash
    )
{
    ULONG i;
    ULONG bitIndex;
    ULONG byteIndex;
    ULONG bitMask;

    if (Filter == NULL || Filter->BitArray == NULL || Hash == NULL) {
        return FALSE;
    }

    for (i = 0; i < Filter->HashCount; i++) {
        bitIndex = BdvpMurmurHash3(Hash, BDV_HASH_SIZE, i) % Filter->SizeBits;
        byteIndex = bitIndex / 8;
        bitMask = 1 << (bitIndex % 8);

        if ((Filter->BitArray[byteIndex] & bitMask) == 0) {
            return FALSE;
        }
    }

    return TRUE;
}

// ============================================================================
// HASH CALCULATION
// ============================================================================

/**
 * @brief Calculate SHA-256 hash of entire driver image
 */
static NTSTATUS
BdvpCalculateImageHash(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _Out_writes_(BDV_HASH_SIZE) PUCHAR Hash
    )
{
    NTSTATUS status;

    if (ImageBase == NULL || ImageSize == 0 || Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate image size is reasonable
    if (ImageSize > BDV_MAX_IMAGE_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    // Use existing HashUtils infrastructure
    status = ShadowStrikeComputeSha256(ImageBase, (ULONG)ImageSize, Hash);

    return status;
}

/**
 * @brief Calculate Authenticode hash (excludes signature section)
 *
 * The Authenticode hash specifically excludes:
 * - The checksum field in the optional header
 * - The certificate table entry in the data directory
 * - The certificate table itself
 */
static NTSTATUS
BdvpCalculateAuthenticodeHash(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _Out_writes_(BDV_HASH_SIZE) PUCHAR Hash
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeader;
    PIMAGE_DATA_DIRECTORY securityDir;
    SHADOWSTRIKE_HASH_CONTEXT hashContext;
    ULONG checksumOffset;
    ULONG securityDirOffset;
    ULONG securityDirSize;
    ULONG securityDirEnd;
    ULONG sectionTableOffset;
    ULONG headerSize;
    ULONG currentOffset;
    ULONG bytesToHash;
    BOOLEAN contextInitialized = FALSE;

    if (ImageBase == NULL || ImageSize < sizeof(IMAGE_DOS_HEADER) || Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Hash, BDV_HASH_SIZE);

    // Validate DOS header
    dosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    if (dosHeader->e_magic != BDV_PE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Validate NT headers offset (overflow-safe)
    if (dosHeader->e_lfanew < 0 ||
        (SIZE_T)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > ImageSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != BDV_PE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Initialize streaming hash context
    status = ShadowStrikeHashContextInit(&hashContext, ShadowHashAlgorithmSha256);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    contextInitialized = TRUE;

    // Calculate offsets for fields to exclude
    checksumOffset = (ULONG)((PUCHAR)&ntHeaders->OptionalHeader.CheckSum - (PUCHAR)ImageBase);

    // Get security directory info
    if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        PIMAGE_NT_HEADERS64 ntHeaders64 = (PIMAGE_NT_HEADERS64)ntHeaders;
        if (ntHeaders64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            securityDir = &ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            securityDirOffset = (ULONG)((PUCHAR)securityDir - (PUCHAR)ImageBase);
        } else {
            securityDir = NULL;
            securityDirOffset = 0;
        }
        headerSize = ntHeaders64->OptionalHeader.SizeOfHeaders;
    } else {
        // 32-bit PE: must cast to IMAGE_NT_HEADERS32 for correct field offsets
        // (IMAGE_NT_HEADERS on x64 builds is IMAGE_NT_HEADERS64 — DataDirectory
        // and NumberOfRvaAndSizes are at different offsets in 32-bit layout)
        PIMAGE_NT_HEADERS32 ntHeaders32 = (PIMAGE_NT_HEADERS32)ntHeaders;
        if (ntHeaders32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            securityDir = &ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            securityDirOffset = (ULONG)((PUCHAR)securityDir - (PUCHAR)ImageBase);
        } else {
            securityDir = NULL;
            securityDirOffset = 0;
        }
        headerSize = ntHeaders32->OptionalHeader.SizeOfHeaders;
    }

    // Validate headerSize against actual image bounds
    if (headerSize > (ULONG)ImageSize) {
        headerSize = (ULONG)ImageSize;
    }

    // Get security table location (overflow-safe)
    if (securityDir != NULL && securityDir->VirtualAddress != 0) {
        securityDirSize = securityDir->Size;
        if (securityDir->VirtualAddress > (ULONG)ImageSize ||
            securityDirSize > (ULONG)ImageSize - securityDir->VirtualAddress) {
            securityDirSize = 0;
            securityDirEnd = 0;
        } else {
            securityDirEnd = securityDir->VirtualAddress + securityDirSize;
        }
    } else {
        securityDirSize = 0;
        securityDirEnd = 0;
    }

    // Hash headers up to checksum
    currentOffset = 0;
    bytesToHash = checksumOffset;
    status = ShadowStrikeHashContextUpdate(
        &hashContext,
        (PUCHAR)ImageBase + currentOffset,
        bytesToHash
        );
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    currentOffset = checksumOffset + sizeof(ULONG); // Skip checksum

    // Hash from after checksum to security directory entry
    if (securityDirOffset > currentOffset) {
        bytesToHash = securityDirOffset - currentOffset;
        status = ShadowStrikeHashContextUpdate(
            &hashContext,
            (PUCHAR)ImageBase + currentOffset,
            bytesToHash
            );
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
        currentOffset = securityDirOffset + sizeof(IMAGE_DATA_DIRECTORY);
    }

    // Hash rest of headers
    if (headerSize > currentOffset) {
        bytesToHash = headerSize - currentOffset;
        status = ShadowStrikeHashContextUpdate(
            &hashContext,
            (PUCHAR)ImageBase + currentOffset,
            bytesToHash
            );
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
    }

    // Hash sections sorted by PointerToRawData (Authenticode spec requirement)
    sectionTableOffset = dosHeader->e_lfanew + sizeof(ULONG) +
                         sizeof(IMAGE_FILE_HEADER) +
                         ntHeaders->FileHeader.SizeOfOptionalHeader;

    // Validate section table fits within image
    {
        USHORT numSections = ntHeaders->FileHeader.NumberOfSections;
        SIZE_T tableEnd = (SIZE_T)sectionTableOffset +
                          (SIZE_T)numSections * sizeof(IMAGE_SECTION_HEADER);
        if (sectionTableOffset > ImageSize || tableEnd > ImageSize) {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto Cleanup;
        }
    }

    sectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)ImageBase + sectionTableOffset);

    // Sort sections by ascending PointerToRawData (insertion sort, stack-safe)
    {
        typedef struct { USHORT Index; ULONG Offset; } SECTION_SORT;
        SECTION_SORT sorted[BDV_MAX_PE_SECTIONS];
        USHORT sectionCount = min(ntHeaders->FileHeader.NumberOfSections,
                                  BDV_MAX_PE_SECTIONS);
        USHORT j, k;
        SECTION_SORT key;
        ULONG lastSectionEnd = 0;

        for (j = 0; j < sectionCount; j++) {
            sorted[j].Index = j;
            sorted[j].Offset = sectionHeader[j].PointerToRawData;
        }

        for (j = 1; j < sectionCount; j++) {
            key = sorted[j];
            k = j;
            while (k > 0 && sorted[k - 1].Offset > key.Offset) {
                sorted[k] = sorted[k - 1];
                k--;
            }
            sorted[k] = key;
        }

        for (j = 0; j < sectionCount; j++) {
            USHORT idx = sorted[j].Index;
            ULONG sectionStart = sectionHeader[idx].PointerToRawData;
            ULONG sectionSize = sectionHeader[idx].SizeOfRawData;

            if (sectionStart > (ULONG)ImageSize ||
                sectionSize > (ULONG)ImageSize - sectionStart) {
                continue;
            }

            if (securityDir != NULL && securityDir->VirtualAddress != 0 && securityDirEnd != 0) {
                ULONG sectionEnd = sectionStart + sectionSize;
                if (sectionStart < securityDirEnd && sectionEnd > securityDir->VirtualAddress) {
                    continue;
                }
            }

            if (sectionSize > 0) {
                status = ShadowStrikeHashContextUpdate(
                    &hashContext,
                    (PUCHAR)ImageBase + sectionStart,
                    sectionSize
                    );
                if (!NT_SUCCESS(status)) {
                    goto Cleanup;
                }

                // Track highest section end for trailing data calculation
                if (sectionStart + sectionSize > lastSectionEnd) {
                    lastSectionEnd = sectionStart + sectionSize;
                }
            }
        }

        //
        // Authenticode spec step 5: Hash trailing data between last section
        // end and the certificate table (or end of file if no cert table).
        // This covers overlay data, debug directory data outside sections, etc.
        //
        {
            ULONG trailingStart = lastSectionEnd;
            ULONG trailingEnd;

            if (securityDir != NULL && securityDir->VirtualAddress != 0 &&
                securityDir->VirtualAddress <= (ULONG)ImageSize) {
                trailingEnd = securityDir->VirtualAddress;
            } else {
                trailingEnd = (ULONG)ImageSize;
            }

            if (trailingEnd > trailingStart && trailingStart <= (ULONG)ImageSize) {
                ULONG trailingSize = trailingEnd - trailingStart;
                if (trailingSize <= (ULONG)ImageSize - trailingStart) {
                    status = ShadowStrikeHashContextUpdate(
                        &hashContext,
                        (PUCHAR)ImageBase + trailingStart,
                        trailingSize
                        );
                    if (!NT_SUCCESS(status)) {
                        goto Cleanup;
                    }
                }
            }
        }
    }

    // Finalize hash
    status = ShadowStrikeHashContextFinalize(&hashContext, Hash, BDV_HASH_SIZE);

Cleanup:
    if (contextInitialized) {
        ShadowStrikeHashContextCleanup(&hashContext);
    }

    return status;
}

/**
 * @brief Extract certificate information from PE file
 *
 * Determines if the PE has an Authenticode signature by checking the
 * IMAGE_DIRECTORY_ENTRY_SECURITY data directory. If present, computes
 * a SHA-1 hash of the raw certificate bytes as a thumbprint proxy.
 *
 * @note This is a heuristic — presence of a certificate table does NOT
 *       guarantee a valid signature. Full Authenticode verification
 *       requires user-mode WinVerifyTrust or undocumented CiCheckSignedFile.
 *       The thumbprint is SHA-1 of the raw PKCS#7 blob, NOT the standard
 *       certificate thumbprint (SHA-1 of the DER-encoded certificate).
 */
static NTSTATUS
BdvpExtractCertificateInfo(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _Inout_ PBDV_DRIVER_INFO Info
    )
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_DATA_DIRECTORY securityDir;
    PUCHAR certTable;

    if (ImageBase == NULL || ImageSize < sizeof(IMAGE_DOS_HEADER) || Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Info->IsSigned = FALSE;
    Info->IsWhqlSigned = FALSE;
    RtlZeroMemory(Info->ThumbPrint, sizeof(Info->ThumbPrint));

    dosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    if (dosHeader->e_magic != BDV_PE_DOS_SIGNATURE) {
        return STATUS_SUCCESS;
    }

    // Overflow-safe NT headers offset validation
    if (dosHeader->e_lfanew < 0 ||
        (SIZE_T)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > ImageSize) {
        return STATUS_SUCCESS;
    }

    ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != BDV_PE_NT_SIGNATURE) {
        return STATUS_SUCCESS;
    }

    if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        PIMAGE_NT_HEADERS64 ntHeaders64 = (PIMAGE_NT_HEADERS64)ntHeaders;
        if (ntHeaders64->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
            return STATUS_SUCCESS;
        }
        securityDir = &ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    } else {
        // 32-bit PE: use IMAGE_NT_HEADERS32 for correct DataDirectory offset
        PIMAGE_NT_HEADERS32 ntHeaders32 = (PIMAGE_NT_HEADERS32)ntHeaders;
        if (ntHeaders32->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
            return STATUS_SUCCESS;
        }
        securityDir = &ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    }

    if (securityDir->VirtualAddress == 0 || securityDir->Size == 0) {
        return STATUS_SUCCESS;
    }

    // Overflow-safe certificate table bounds check
    if (securityDir->VirtualAddress > (ULONG)ImageSize ||
        securityDir->Size > (ULONG)ImageSize - securityDir->VirtualAddress) {
        return STATUS_SUCCESS;
    }

    Info->IsSigned = TRUE;

    // Compute SHA-1 of raw PKCS#7 certificate blob (skip WIN_CERTIFICATE header)
    certTable = (PUCHAR)ImageBase + securityDir->VirtualAddress;
    if (securityDir->Size >= 8) {
        ShadowStrikeComputeSha1(
            certTable + 8,
            min(securityDir->Size - 8, 4096),
            Info->ThumbPrint
            );
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Check if hash exists in a linked list
 */
static BOOLEAN
BdvpIsHashInList(
    _In_ PLIST_ENTRY ListHead,
    _In_ PEX_PUSH_LOCK Lock,
    _In_reads_(BDV_HASH_SIZE) const UCHAR* Hash
    )
{
    PLIST_ENTRY entry;
    PBDV_HASH_ENTRY hashEntry;
    BOOLEAN found = FALSE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(Lock);

    for (entry = ListHead->Flink; entry != ListHead; entry = entry->Flink) {
        hashEntry = CONTAINING_RECORD(entry, BDV_HASH_ENTRY, ListEntry);

        if (ShadowStrikeCompareSha256(hashEntry->Hash, Hash)) {
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(Lock);
    KeLeaveCriticalRegion();

    return found;
}

/**
 * @brief Deep-copy a UNICODE_STRING driver path and derive the short name
 *
 * Allocates a new buffer, copies the full path, and sets DestName
 * to point at the last path component within DestPath's buffer.
 */
static NTSTATUS
BdvpDeepCopyDriverPath(
    _In_ PUNICODE_STRING SourcePath,
    _Out_ PUNICODE_STRING DestPath,
    _Out_ PUNICODE_STRING DestName
    )
{
    PWCH newBuffer;
    USHORT lastSlashOffset = 0;
    USHORT i;

    RtlZeroMemory(DestPath, sizeof(UNICODE_STRING));
    RtlZeroMemory(DestName, sizeof(UNICODE_STRING));

    if (SourcePath == NULL || SourcePath->Buffer == NULL || SourcePath->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    newBuffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, SourcePath->Length, 'PvdB');
    if (newBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newBuffer, SourcePath->Buffer, SourcePath->Length);

    DestPath->Buffer = newBuffer;
    DestPath->Length = SourcePath->Length;
    DestPath->MaximumLength = SourcePath->Length;

    // Find last backslash to derive short name
    for (i = 0; i < SourcePath->Length / sizeof(WCHAR); i++) {
        if (newBuffer[i] == L'\\') {
            lastSlashOffset = (USHORT)((i + 1) * sizeof(WCHAR));
        }
    }

    if (lastSlashOffset < SourcePath->Length) {
        DestName->Buffer = (PWCH)((PUCHAR)newBuffer + lastSlashOffset);
        DestName->Length = SourcePath->Length - lastSlashOffset;
        DestName->MaximumLength = DestName->Length;
    } else {
        DestName->Buffer = newBuffer;
        DestName->Length = SourcePath->Length;
        DestName->MaximumLength = DestName->Length;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Free deep-copied path buffers from a driver info entry
 *
 * Only frees DriverPath.Buffer (DriverName shares the same allocation).
 */
static VOID
BdvpFreeDriverInfoPaths(
    _Inout_ PBDV_DRIVER_INFO Info
    )
{
    if (Info->DriverPath.Buffer != NULL) {
        ExFreePoolWithTag(Info->DriverPath.Buffer, 'PvdB');
        Info->DriverPath.Buffer = NULL;
        Info->DriverPath.Length = 0;
        Info->DriverPath.MaximumLength = 0;
        Info->DriverName.Buffer = NULL;
        Info->DriverName.Length = 0;
        Info->DriverName.MaximumLength = 0;
    }
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

/**
 * @brief Initialize the boot driver verifier
 */
_Use_decl_annotations_
NTSTATUS
BdvInitialize(
    PBDV_VERIFIER* Verifier
    )
{
    NTSTATUS status;
    PBDV_VERIFIER_INTERNAL internal = NULL;

    if (Verifier == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Verifier = NULL;

    // Allocate internal structure
    internal = (PBDV_VERIFIER_INTERNAL)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(BDV_VERIFIER_INTERNAL),
        BDV_POOL_TAG
        );

    if (internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(internal, sizeof(BDV_VERIFIER_INTERNAL));

    // Initialize lists
    InitializeListHead(&internal->Public.KnownGoodList);
    InitializeListHead(&internal->Public.KnownBadList);
    InitializeListHead(&internal->Public.VerifiedList);

    // Initialize locks
    ExInitializePushLock(&internal->Public.ListLock);
    KeInitializeSpinLock(&internal->Public.VerifiedLock);

    // Initialize bloom filters
    status = BdvpInitializeBloomFilter(
        &internal->GoodBloomFilter,
        BDV_BLOOM_FILTER_SIZE_BITS,
        BDV_BLOOM_HASH_COUNT
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = BdvpInitializeBloomFilter(
        &internal->BadBloomFilter,
        BDV_BLOOM_FILTER_SIZE_BITS,
        BDV_BLOOM_HASH_COUNT
        );

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // Initialize lookaside list for driver info structures
    ExInitializeNPagedLookasideList(
        &internal->DriverInfoLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(BDV_DRIVER_INFO),
        BDV_POOL_TAG,
        0
        );
    internal->LookasideInitialized = TRUE;

    // Record start time
    KeQuerySystemTimePrecise(&internal->Public.Stats.StartTime);

    InterlockedExchange(&internal->Public.Initialized, 1);
    *Verifier = &internal->Public;

    return STATUS_SUCCESS;

Cleanup:
    if (internal != NULL) {
        BdvpDestroyBloomFilter(&internal->GoodBloomFilter);
        BdvpDestroyBloomFilter(&internal->BadBloomFilter);

        if (internal->LookasideInitialized) {
            ExDeleteNPagedLookasideList(&internal->DriverInfoLookaside);
        }

        ExFreePoolWithTag(internal, BDV_POOL_TAG);
    }

    return status;
}

/**
 * @brief Shutdown the boot driver verifier
 */
_Use_decl_annotations_
VOID
BdvShutdown(
    PBDV_VERIFIER Verifier
    )
{
    PBDV_VERIFIER_INTERNAL internal;
    PLIST_ENTRY entry;
    PBDV_HASH_ENTRY hashEntry;
    PBDV_DRIVER_INFO driverInfo;
    KIRQL oldIrql;

    if (Verifier == NULL) {
        return;
    }

    // Atomically clear Initialized: returns previous value.
    // If it was already 0, another shutdown raced us — bail.
    if (!InterlockedCompareExchange(&Verifier->Initialized, 0, 1)) {
        return;
    }

    internal = CONTAINING_RECORD(Verifier, BDV_VERIFIER_INTERNAL, Public);

    // Free known good list
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Verifier->ListLock);
    while (!IsListEmpty(&Verifier->KnownGoodList)) {
        entry = RemoveHeadList(&Verifier->KnownGoodList);
        hashEntry = CONTAINING_RECORD(entry, BDV_HASH_ENTRY, ListEntry);
        ExFreePoolWithTag(hashEntry, BDV_POOL_TAG);
    }

    // Free known bad list
    while (!IsListEmpty(&Verifier->KnownBadList)) {
        entry = RemoveHeadList(&Verifier->KnownBadList);
        hashEntry = CONTAINING_RECORD(entry, BDV_HASH_ENTRY, ListEntry);
        ExFreePoolWithTag(hashEntry, BDV_POOL_TAG);
    }
    ExReleasePushLockExclusive(&Verifier->ListLock);
    KeLeaveCriticalRegion();

    // Free verified driver list (including deep-copied paths)
    KeAcquireSpinLock(&Verifier->VerifiedLock, &oldIrql);
    while (!IsListEmpty(&Verifier->VerifiedList)) {
        entry = RemoveHeadList(&Verifier->VerifiedList);
        driverInfo = CONTAINING_RECORD(entry, BDV_DRIVER_INFO, ListEntry);
        BdvpFreeDriverInfoPaths(driverInfo);
        ExFreeToNPagedLookasideList(&internal->DriverInfoLookaside, driverInfo);
    }
    KeReleaseSpinLock(&Verifier->VerifiedLock, oldIrql);

    // Destroy bloom filters
    BdvpDestroyBloomFilter(&internal->GoodBloomFilter);
    BdvpDestroyBloomFilter(&internal->BadBloomFilter);

    // Delete lookaside list
    if (internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&internal->DriverInfoLookaside);
        internal->LookasideInitialized = FALSE;
    }

    // Free ELAM config if present
    if (Verifier->ELAMConfig != NULL) {
        ExFreePoolWithTag(Verifier->ELAMConfig, BDV_POOL_TAG);
        Verifier->ELAMConfig = NULL;
    }

    // Free the structure
    ExFreePoolWithTag(internal, BDV_POOL_TAG);
}

/**
 * @brief Load configuration data for the verifier
 */
_Use_decl_annotations_
NTSTATUS
BdvLoadConfiguration(
    PBDV_VERIFIER Verifier,
    PVOID ConfigData,
    SIZE_T ConfigSize
    )
{
    if (Verifier == NULL || !InterlockedCompareExchange(&Verifier->Initialized, 1, 1)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ConfigData == NULL || ConfigSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate size limits
    if (ConfigSize > 10 * 1024 * 1024) { // 10MB max
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate new config before taking lock (paged — accessed only at < DISPATCH)
    PVOID newConfig = ExAllocatePool2(
        POOL_FLAG_PAGED,
        ConfigSize,
        BDV_POOL_TAG
        );

    if (newConfig == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newConfig, ConfigData, ConfigSize);

    // Swap under push lock for synchronization with readers
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Verifier->ListLock);

    PVOID oldConfig = Verifier->ELAMConfig;
    Verifier->ELAMConfig = newConfig;
    Verifier->ELAMConfigSize = ConfigSize;

    ExReleasePushLockExclusive(&Verifier->ListLock);
    KeLeaveCriticalRegion();

    if (oldConfig != NULL) {
        ExFreePoolWithTag(oldConfig, BDV_POOL_TAG);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Verify a boot driver
 *
 * Allocates a driver info entry from lookaside, deep-copies the driver path,
 * computes SHA-256 full image hash and Authenticode hash, extracts certificate
 * info, classifies the driver, and adds to verified cache.
 *
 * All image access is wrapped in __try/__except to handle corrupted or
 * partially-mapped images without crashing the system.
 */
_Use_decl_annotations_
NTSTATUS
BdvVerifyDriver(
    PBDV_VERIFIER Verifier,
    PUNICODE_STRING DriverPath,
    PVOID ImageBase,
    SIZE_T ImageSize,
    PBDV_DRIVER_INFO* Info
    )
{
    NTSTATUS status;
    PBDV_VERIFIER_INTERNAL internal;
    PBDV_DRIVER_INFO driverInfo = NULL;
    KIRQL oldIrql;

    if (Verifier == NULL || !InterlockedCompareExchange(&Verifier->Initialized, 1, 1) || Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ImageBase == NULL || ImageSize == 0 || ImageSize > BDV_MAX_IMAGE_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Verifier, BDV_VERIFIER_INTERNAL, Public);
    *Info = NULL;

    // Enforce verified list cap to prevent unbounded memory growth
    if ((ULONG)InterlockedCompareExchange(&Verifier->VerifiedCount, 0, 0) >= BDV_MAX_VERIFIED_DRIVERS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    // Allocate driver info from lookaside
    driverInfo = (PBDV_DRIVER_INFO)ExAllocateFromNPagedLookasideList(
        &internal->DriverInfoLookaside
        );

    if (driverInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(driverInfo, sizeof(BDV_DRIVER_INFO));

    // Deep-copy driver path (caller's buffer may be freed after return)
    if (DriverPath != NULL && DriverPath->Length > 0 && DriverPath->Buffer != NULL) {
        status = BdvpDeepCopyDriverPath(
            DriverPath,
            &driverInfo->DriverPath,
            &driverInfo->DriverName
            );
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
    }

    // All image access is wrapped in SEH to handle corrupted/unmapped images
    __try {
        // Calculate image hash (full file hash)
        status = BdvpCalculateImageHash(ImageBase, ImageSize, driverInfo->ImageHash);
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }

        // Calculate Authenticode hash
        status = BdvpCalculateAuthenticodeHash(ImageBase, ImageSize, driverInfo->AuthentiCodeHash);
        if (!NT_SUCCESS(status)) {
            // Non-fatal — some drivers may not have valid Authenticode
            RtlZeroMemory(driverInfo->AuthentiCodeHash, sizeof(driverInfo->AuthentiCodeHash));
        }

        // Extract certificate information
        status = BdvpExtractCertificateInfo(ImageBase, ImageSize, driverInfo);
        if (!NT_SUCCESS(status)) {
            driverInfo->IsSigned = FALSE;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        goto Cleanup;
    }

    // Store file size
    driverInfo->FileSize.QuadPart = (LONGLONG)ImageSize;

    // Perform classification
    status = BdvClassifyDriver(Verifier, driverInfo, &driverInfo->Classification);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // Add to verified list
    KeAcquireSpinLock(&Verifier->VerifiedLock, &oldIrql);
    InsertTailList(&Verifier->VerifiedList, &driverInfo->ListEntry);
    InterlockedIncrement(&Verifier->VerifiedCount);
    KeReleaseSpinLock(&Verifier->VerifiedLock, oldIrql);

    // Update statistics
    InterlockedIncrement64(&Verifier->Stats.DriversVerified);

    *Info = driverInfo;
    return STATUS_SUCCESS;

Cleanup:
    if (driverInfo != NULL) {
        BdvpFreeDriverInfoPaths(driverInfo);
        ExFreeToNPagedLookasideList(&internal->DriverInfoLookaside, driverInfo);
    }

    return status;
}

/**
 * @brief Classify a driver based on verification results
 */
_Use_decl_annotations_
NTSTATUS
BdvClassifyDriver(
    PBDV_VERIFIER Verifier,
    PBDV_DRIVER_INFO Info,
    PBDV_CLASSIFICATION Classification
    )
{
    PBDV_VERIFIER_INTERNAL internal;
    BOOLEAN mayBeGood;
    BOOLEAN mayBeBad;

    if (Verifier == NULL ||
        !InterlockedCompareExchange(&Verifier->Initialized, 1, 1) ||
        Info == NULL || Classification == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Verifier, BDV_VERIFIER_INTERNAL, Public);
    *Classification = BdvClass_Unknown;

    // Fast bloom filter check first (< 1 microsecond)
    mayBeBad = BdvpBloomFilterMayContain(&internal->BadBloomFilter, Info->ImageHash);
    if (mayBeBad) {
        // Confirm with full list check
        if (BdvpIsHashInList(&Verifier->KnownBadList, &Verifier->ListLock, Info->ImageHash)) {
            *Classification = BdvClass_KnownBad;
            RtlStringCbCopyA(Info->ClassificationReason, sizeof(Info->ClassificationReason),
                           "Hash matches known malicious driver");
            InterlockedIncrement64(&Verifier->Stats.KnownBad);
            return STATUS_SUCCESS;
        }
    }

    mayBeGood = BdvpBloomFilterMayContain(&internal->GoodBloomFilter, Info->ImageHash);
    if (mayBeGood) {
        // Confirm with full list check
        if (BdvpIsHashInList(&Verifier->KnownGoodList, &Verifier->ListLock, Info->ImageHash)) {
            *Classification = BdvClass_KnownGood;
            RtlStringCbCopyA(Info->ClassificationReason, sizeof(Info->ClassificationReason),
                           "Hash matches known good driver");
            InterlockedIncrement64(&Verifier->Stats.KnownGood);
            return STATUS_SUCCESS;
        }
    }

    // Unknown driver - apply heuristics
    if (Info->IsSigned) {
        if (Info->IsWhqlSigned) {
            *Classification = BdvClass_Unknown_Good;
            RtlStringCbCopyA(Info->ClassificationReason, sizeof(Info->ClassificationReason),
                           "Unknown driver with WHQL signature");
            InterlockedIncrement64(&Verifier->Stats.UnknownAllowed);
        } else {
            *Classification = BdvClass_Unknown_Good;
            RtlStringCbCopyA(Info->ClassificationReason, sizeof(Info->ClassificationReason),
                           "Unknown driver with valid signature");
            InterlockedIncrement64(&Verifier->Stats.UnknownAllowed);
        }
    } else {
        // Unsigned unknown driver - suspicious
        *Classification = BdvClass_Unknown_Bad;
        RtlStringCbCopyA(Info->ClassificationReason, sizeof(Info->ClassificationReason),
                       "Unknown unsigned driver");
        InterlockedIncrement64(&Verifier->Stats.UnknownBlocked);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Add a known hash to the database
 */
_Use_decl_annotations_
NTSTATUS
BdvAddKnownHash(
    PBDV_VERIFIER Verifier,
    PUCHAR Hash,
    SIZE_T HashLength,
    BOOLEAN IsGood
    )
{
    PBDV_VERIFIER_INTERNAL internal;
    PBDV_HASH_ENTRY entry;

    if (Verifier == NULL ||
        !InterlockedCompareExchange(&Verifier->Initialized, 1, 1)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Hash == NULL || HashLength != BDV_HASH_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Verifier, BDV_VERIFIER_INTERNAL, Public);

    // Allocate entry before lock (allocation may block)
    entry = (PBDV_HASH_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(BDV_HASH_ENTRY),
        BDV_POOL_TAG
        );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(entry->Hash, Hash, BDV_HASH_SIZE);
    entry->Classification = IsGood ? BdvClass_KnownGood : BdvClass_KnownBad;
    entry->Description[0] = '\0';

    // All quota checks and insertion under exclusive lock to prevent races
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Verifier->ListLock);

    // Re-check quota under lock to prevent concurrent overcommit
    if (IsGood && internal->KnownGoodCount >= BDV_MAX_KNOWN_HASHES) {
        ExReleasePushLockExclusive(&Verifier->ListLock);
        KeLeaveCriticalRegion();
        ExFreePoolWithTag(entry, BDV_POOL_TAG);
        return STATUS_QUOTA_EXCEEDED;
    }
    if (!IsGood && internal->KnownBadCount >= BDV_MAX_KNOWN_HASHES) {
        ExReleasePushLockExclusive(&Verifier->ListLock);
        KeLeaveCriticalRegion();
        ExFreePoolWithTag(entry, BDV_POOL_TAG);
        return STATUS_QUOTA_EXCEEDED;
    }

    // Check for duplicate before inserting
    {
        PLIST_ENTRY listHead = IsGood ? &Verifier->KnownGoodList : &Verifier->KnownBadList;
        PLIST_ENTRY cur;
        for (cur = listHead->Flink; cur != listHead; cur = cur->Flink) {
            PBDV_HASH_ENTRY existing = CONTAINING_RECORD(cur, BDV_HASH_ENTRY, ListEntry);
            if (ShadowStrikeCompareSha256(existing->Hash, Hash)) {
                ExReleasePushLockExclusive(&Verifier->ListLock);
                KeLeaveCriticalRegion();
                ExFreePoolWithTag(entry, BDV_POOL_TAG);
                return STATUS_DUPLICATE_OBJECTID;
            }
        }
    }

    if (IsGood) {
        InsertTailList(&Verifier->KnownGoodList, &entry->ListEntry);
        BdvpBloomFilterAdd(&internal->GoodBloomFilter, Hash);
        InterlockedIncrement(&internal->KnownGoodCount);
    } else {
        InsertTailList(&Verifier->KnownBadList, &entry->ListEntry);
        BdvpBloomFilterAdd(&internal->BadBloomFilter, Hash);
        InterlockedIncrement(&internal->KnownBadCount);
    }

    ExReleasePushLockExclusive(&Verifier->ListLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/**
 * @brief Free a driver info structure
 *
 * Removes the entry from the VerifiedList under spinlock, frees the
 * deep-copied path buffer, decrements the verified count, and returns
 * the BDV_DRIVER_INFO to the lookaside list.
 */
_Use_decl_annotations_
VOID
BdvFreeDriverInfo(
    PBDV_VERIFIER Verifier,
    PBDV_DRIVER_INFO Info
    )
{
    PBDV_VERIFIER_INTERNAL internal;
    KIRQL oldIrql;

    if (Verifier == NULL || Info == NULL) {
        return;
    }

    internal = CONTAINING_RECORD(Verifier, BDV_VERIFIER_INTERNAL, Public);

    // Remove from verified list under spinlock (guard against double-free)
    KeAcquireSpinLock(&Verifier->VerifiedLock, &oldIrql);
    if (Info->ListEntry.Flink != NULL &&
        Info->ListEntry.Flink != &Info->ListEntry) {
        RemoveEntryList(&Info->ListEntry);
        InitializeListHead(&Info->ListEntry);
        InterlockedDecrement(&Verifier->VerifiedCount);
    }
    KeReleaseSpinLock(&Verifier->VerifiedLock, oldIrql);

    // Free deep-copied path buffer
    BdvpFreeDriverInfoPaths(Info);

    // Return to lookaside
    ExFreeToNPagedLookasideList(&internal->DriverInfoLookaside, Info);
}
