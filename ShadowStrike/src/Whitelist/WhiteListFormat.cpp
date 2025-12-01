/*
 * ============================================================================
 * ShadowStrike WhitelistFormat - IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Binary format validation and utility functions
 * RAII-based resource management for exception safety
 * Enterprise-grade implementation - zero tolerance for errors
 *
 * ============================================================================
 */

#include "WhiteListFormat.hpp"
#include "../Utils/Logger.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cwctype>
#include <cwchar>
#include <charconv>
#include <locale>

// Windows API headers
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

namespace ShadowStrike {
namespace Whitelist {

// ============================================================================
// RAII HELPER CLASSES (Internal)
// ============================================================================

namespace {

/// @brief RAII wrapper for Windows HANDLE (file/mapping handles)
class HandleGuard {
public:
    explicit HandleGuard(HANDLE h = INVALID_HANDLE_VALUE) noexcept : m_handle(h) {}
    
    ~HandleGuard() noexcept { 
        Close(); 
    }
    
    // Disable copy
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    
    // Enable move
    HandleGuard(HandleGuard&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = INVALID_HANDLE_VALUE;
    }
    
    HandleGuard& operator=(HandleGuard&& other) noexcept {
        if (this != &other) {
            Close();
            m_handle = other.m_handle;
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    
    void Close() noexcept {
        if (m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr) {
            CloseHandle(m_handle);
            m_handle = INVALID_HANDLE_VALUE;
        }
    }
    
    [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
    
    [[nodiscard]] bool IsValid() const noexcept {
        return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr;
    }
    
    [[nodiscard]] HANDLE Release() noexcept {
        HANDLE h = m_handle;
        m_handle = INVALID_HANDLE_VALUE;
        return h;
    }

private:
    HANDLE m_handle;
};

/// @brief RAII wrapper for MapViewOfFile (memory-mapped view)
class MappedViewGuard {
public:
    explicit MappedViewGuard(void* addr = nullptr) noexcept : m_address(addr) {}
    
    ~MappedViewGuard() noexcept { 
        Unmap(); 
    }
    
    // Disable copy
    MappedViewGuard(const MappedViewGuard&) = delete;
    MappedViewGuard& operator=(const MappedViewGuard&) = delete;
    
    // Enable move
    MappedViewGuard(MappedViewGuard&& other) noexcept : m_address(other.m_address) {
        other.m_address = nullptr;
    }
    
    MappedViewGuard& operator=(MappedViewGuard&& other) noexcept {
        if (this != &other) {
            Unmap();
            m_address = other.m_address;
            other.m_address = nullptr;
        }
        return *this;
    }
    
    void Unmap() noexcept {
        if (m_address != nullptr) {
            UnmapViewOfFile(m_address);
            m_address = nullptr;
        }
    }
    
    [[nodiscard]] void* Get() noexcept { return m_address; }
    [[nodiscard]] const void* Get() const noexcept { return m_address; }
    [[nodiscard]] bool IsValid() const noexcept { return m_address != nullptr; }
    
    [[nodiscard]] void* Release() noexcept {
        void* addr = m_address;
        m_address = nullptr;
        return addr;
    }

private:
    void* m_address;
};

/// @brief RAII wrapper for HCRYPTPROV crypto context
class CryptoContextGuard {
public:
    explicit CryptoContextGuard(HCRYPTPROV prov = 0) noexcept : m_provider(prov) {}
    
    ~CryptoContextGuard() noexcept {
        Release();
    }
    
    CryptoContextGuard(const CryptoContextGuard&) = delete;
    CryptoContextGuard& operator=(const CryptoContextGuard&) = delete;
    
    void Release() noexcept {
        if (m_provider != 0) {
            CryptReleaseContext(m_provider, 0);
            m_provider = 0;
        }
    }
    
    [[nodiscard]] HCRYPTPROV Get() const noexcept { return m_provider; }
    [[nodiscard]] HCRYPTPROV* Ptr() noexcept { return &m_provider; }
    [[nodiscard]] bool IsValid() const noexcept { return m_provider != 0; }

private:
    HCRYPTPROV m_provider;
};

/// @brief RAII wrapper for HCRYPTHASH crypto hash
class CryptoHashGuard {
public:
    explicit CryptoHashGuard(HCRYPTHASH hash = 0) noexcept : m_hash(hash) {}
    
    ~CryptoHashGuard() noexcept {
        Destroy();
    }
    
    CryptoHashGuard(const CryptoHashGuard&) = delete;
    CryptoHashGuard& operator=(const CryptoHashGuard&) = delete;
    
    void Destroy() noexcept {
        if (m_hash != 0) {
            CryptDestroyHash(m_hash);
            m_hash = 0;
        }
    }
    
    [[nodiscard]] HCRYPTHASH Get() const noexcept { return m_hash; }
    [[nodiscard]] HCRYPTHASH* Ptr() noexcept { return &m_hash; }
    [[nodiscard]] bool IsValid() const noexcept { return m_hash != 0; }

private:
    HCRYPTHASH m_hash;
};

// ============================================================================
// CRC32 TABLE (Pre-computed for performance)
// ============================================================================

/// @brief CRC32 lookup table (IEEE 802.3 polynomial)
constexpr std::array<uint32_t, 256> GenerateCRC32Table() noexcept {
    std::array<uint32_t, 256> table{};
    constexpr uint32_t polynomial = 0xEDB88320;
    
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ polynomial;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
    return table;
}

static constexpr auto CRC32_TABLE = GenerateCRC32Table();

/// @brief Compute CRC32 checksum
[[nodiscard]] uint32_t ComputeCRC32(const void* data, size_t length) noexcept {
    if (!data || length == 0) {
        return 0;
    }
    
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < length; ++i) {
        crc = (crc >> 8) ^ CRC32_TABLE[(crc ^ bytes[i]) & 0xFF];
    }
    
    return crc ^ 0xFFFFFFFF;
}

// ============================================================================
// HEX STRING HELPERS
// ============================================================================

/// @brief Convert hex character to value
[[nodiscard]] inline uint8_t HexCharToValue(char c) noexcept {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0xFF; // Invalid
}

/// @brief Check if character is valid hex
[[nodiscard]] inline bool IsHexChar(char c) noexcept {
    return (c >= '0' && c <= '9') || 
           (c >= 'a' && c <= 'f') || 
           (c >= 'A' && c <= 'F');
}

} // anonymous namespace

// ============================================================================
// FORMAT UTILITY IMPLEMENTATIONS
// ============================================================================

namespace Format {

bool ValidateHeader(const WhitelistDatabaseHeader* header) noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE HEADER VALIDATION
     * ========================================================================
     *
     * Validates all aspects of the database header:
     * 1. Magic number and version
     * 2. Page alignment of all section offsets
     * 3. Size limits and overflow protection
     * 4. Section overlap detection
     * 5. Timestamp sanity checks
     * 6. CRC32 integrity verification
     *
     * ========================================================================
     */
    
    if (!header) {
        SS_LOG_ERROR(L"Whitelist", L"ValidateHeader: null header pointer");
        return false;
    }
    
    // ========================================================================
    // STEP 1: MAGIC NUMBER & VERSION CHECK
    // ========================================================================
    
    if (header->magic != WHITELIST_DB_MAGIC) {
        SS_LOG_ERROR(L"Whitelist",
            L"Invalid magic number: expected 0x%08X, got 0x%08X",
            WHITELIST_DB_MAGIC, header->magic);
        return false;
    }
    
    if (header->versionMajor != WHITELIST_DB_VERSION_MAJOR) {
        SS_LOG_ERROR(L"Whitelist",
            L"Version mismatch: expected %u.x, got %u.%u",
            WHITELIST_DB_VERSION_MAJOR,
            header->versionMajor,
            header->versionMinor);
        return false;
    }
    
    // ========================================================================
    // STEP 2: CRC32 QUICK VALIDATION (Before extensive checks)
    // ========================================================================
    
    // Compute CRC32 of header excluding the checksum fields
    // CRC32 is stored at offset of sha256Checksum + 32 bytes
    constexpr size_t crcOffset = offsetof(WhitelistDatabaseHeader, headerCrc32);
    uint32_t computedCrc = ComputeCRC32(header, crcOffset);
    
    if (header->headerCrc32 != 0 && header->headerCrc32 != computedCrc) {
        SS_LOG_ERROR(L"Whitelist",
            L"Header CRC32 mismatch: expected 0x%08X, got 0x%08X",
            header->headerCrc32, computedCrc);
        return false;
    }
    
    // ========================================================================
    // STEP 3: PAGE ALIGNMENT VALIDATION
    // ========================================================================
    
    auto checkPageAlignment = [](uint64_t offset, const wchar_t* name) -> bool {
        if (offset != 0 && (offset % PAGE_SIZE != 0)) {
            SS_LOG_ERROR(L"Whitelist",
                L"%s offset 0x%llX not page-aligned (PAGE_SIZE=%zu)",
                name, offset, PAGE_SIZE);
            return false;
        }
        return true;
    };
    
    if (!checkPageAlignment(header->hashIndexOffset, L"Hash index")) return false;
    if (!checkPageAlignment(header->pathIndexOffset, L"Path index")) return false;
    if (!checkPageAlignment(header->certIndexOffset, L"Certificate index")) return false;
    if (!checkPageAlignment(header->publisherIndexOffset, L"Publisher index")) return false;
    if (!checkPageAlignment(header->entryDataOffset, L"Entry data")) return false;
    if (!checkPageAlignment(header->extendedHashOffset, L"Extended hash")) return false;
    if (!checkPageAlignment(header->stringPoolOffset, L"String pool")) return false;
    if (!checkPageAlignment(header->bloomFilterOffset, L"Bloom filter")) return false;
    if (!checkPageAlignment(header->metadataOffset, L"Metadata")) return false;
    if (!checkPageAlignment(header->pathBloomOffset, L"Path bloom")) return false;
    
    // ========================================================================
    // STEP 4: SIZE LIMITS VALIDATION
    // ========================================================================
    
    auto checkSizeLimit = [](uint64_t size, const wchar_t* name) -> bool {
        if (size > MAX_DATABASE_SIZE) {
            SS_LOG_ERROR(L"Whitelist",
                L"%s size %llu exceeds maximum %llu",
                name, size, MAX_DATABASE_SIZE);
            return false;
        }
        return true;
    };
    
    if (!checkSizeLimit(header->hashIndexSize, L"Hash index")) return false;
    if (!checkSizeLimit(header->pathIndexSize, L"Path index")) return false;
    if (!checkSizeLimit(header->certIndexSize, L"Certificate index")) return false;
    if (!checkSizeLimit(header->publisherIndexSize, L"Publisher index")) return false;
    if (!checkSizeLimit(header->entryDataSize, L"Entry data")) return false;
    if (!checkSizeLimit(header->stringPoolSize, L"String pool")) return false;
    if (!checkSizeLimit(header->bloomFilterSize, L"Bloom filter")) return false;
    if (!checkSizeLimit(header->metadataSize, L"Metadata")) return false;
    
    // ========================================================================
    // STEP 5: OVERFLOW PROTECTION (offset + size)
    // ========================================================================
    
    auto checkNoOverflow = [](uint64_t offset, uint64_t size, const wchar_t* name) -> bool {
        if (offset > 0 && size > 0) {
            if (offset > UINT64_MAX - size) {
                SS_LOG_ERROR(L"Whitelist",
                    L"%s offset+size overflow: 0x%llX + 0x%llX",
                    name, offset, size);
                return false;
            }
        }
        return true;
    };
    
    if (!checkNoOverflow(header->hashIndexOffset, header->hashIndexSize, L"Hash index")) return false;
    if (!checkNoOverflow(header->pathIndexOffset, header->pathIndexSize, L"Path index")) return false;
    if (!checkNoOverflow(header->certIndexOffset, header->certIndexSize, L"Cert index")) return false;
    if (!checkNoOverflow(header->publisherIndexOffset, header->publisherIndexSize, L"Publisher")) return false;
    if (!checkNoOverflow(header->entryDataOffset, header->entryDataSize, L"Entry data")) return false;
    if (!checkNoOverflow(header->stringPoolOffset, header->stringPoolSize, L"String pool")) return false;
    if (!checkNoOverflow(header->bloomFilterOffset, header->bloomFilterSize, L"Bloom filter")) return false;
    if (!checkNoOverflow(header->metadataOffset, header->metadataSize, L"Metadata")) return false;
    
    // ========================================================================
    // STEP 6: SECTION OVERLAP DETECTION
    // ========================================================================
    
    struct SectionInfo {
        uint64_t offset;
        uint64_t size;
        const wchar_t* name;
    };
    
    std::array<SectionInfo, 10> sections = {{
        { header->hashIndexOffset, header->hashIndexSize, L"HashIndex" },
        { header->pathIndexOffset, header->pathIndexSize, L"PathIndex" },
        { header->certIndexOffset, header->certIndexSize, L"CertIndex" },
        { header->publisherIndexOffset, header->publisherIndexSize, L"PublisherIndex" },
        { header->entryDataOffset, header->entryDataSize, L"EntryData" },
        { header->extendedHashOffset, header->extendedHashSize, L"ExtendedHash" },
        { header->stringPoolOffset, header->stringPoolSize, L"StringPool" },
        { header->bloomFilterOffset, header->bloomFilterSize, L"BloomFilter" },
        { header->metadataOffset, header->metadataSize, L"Metadata" },
        { header->pathBloomOffset, header->pathBloomSize, L"PathBloom" }
    }};
    
    // Check each pair for overlap
    for (size_t i = 0; i < sections.size(); ++i) {
        if (sections[i].offset == 0 || sections[i].size == 0) continue;
        
        uint64_t endI = sections[i].offset + sections[i].size;
        
        for (size_t j = i + 1; j < sections.size(); ++j) {
            if (sections[j].offset == 0 || sections[j].size == 0) continue;
            
            uint64_t endJ = sections[j].offset + sections[j].size;
            
            // Check overlap: [start_i, end_i) overlaps [start_j, end_j)
            bool overlaps = (sections[i].offset < endJ) && (sections[j].offset < endI);
            
            if (overlaps) {
                SS_LOG_ERROR(L"Whitelist",
                    L"Section overlap: %s [0x%llX-0x%llX) overlaps %s [0x%llX-0x%llX)",
                    sections[i].name, sections[i].offset, endI,
                    sections[j].name, sections[j].offset, endJ);
                return false;
            }
        }
    }
    
    // ========================================================================
    // STEP 7: TIMESTAMP SANITY CHECKS
    // ========================================================================
    
    if (header->creationTime > 0 && header->lastUpdateTime > 0) {
        if (header->creationTime > header->lastUpdateTime) {
            SS_LOG_WARN(L"Whitelist",
                L"Creation time (%llu) > last update time (%llu) - possible corruption",
                header->creationTime, header->lastUpdateTime);
        }
    }
    
    // Reasonable timestamp range: 2020-2100
    constexpr uint64_t MIN_TIMESTAMP = 1577836800ULL;  // 2020-01-01
    constexpr uint64_t MAX_TIMESTAMP = 4102444800ULL;  // 2100-01-01
    
    if (header->creationTime > 0 &&
        (header->creationTime < MIN_TIMESTAMP || header->creationTime > MAX_TIMESTAMP)) {
        SS_LOG_WARN(L"Whitelist",
            L"Creation timestamp %llu outside expected range [2020-2100]",
            header->creationTime);
    }
    
    // ========================================================================
    // STEP 8: STATISTICS SANITY CHECKS (Warnings only)
    // ========================================================================
    
    uint64_t totalEntries = header->totalHashEntries + header->totalPathEntries +
                            header->totalCertEntries + header->totalPublisherEntries +
                            header->totalOtherEntries;
    
    if (totalEntries > MAX_ENTRIES) {
        SS_LOG_WARN(L"Whitelist",
            L"Total entries (%llu) exceeds expected maximum (%llu)",
            totalEntries, MAX_ENTRIES);
    }
    
    SS_LOG_DEBUG(L"Whitelist", L"Header validation passed");
    return true;
}

uint32_t ComputeHeaderCRC32(const WhitelistDatabaseHeader* header) noexcept {
    if (!header) {
        return 0;
    }
    
    // Compute CRC32 of header up to (but not including) headerCrc32 field
    constexpr size_t crcOffset = offsetof(WhitelistDatabaseHeader, headerCrc32);
    return ComputeCRC32(header, crcOffset);
}

bool ComputeDatabaseChecksum(
    const MemoryMappedView& view,
    std::array<uint8_t, 32>& outChecksum
) noexcept {
    /*
     * ========================================================================
     * SHA-256 DATABASE CHECKSUM COMPUTATION
     * ========================================================================
     *
     * Computes SHA-256 of entire database excluding the checksum field.
     * Uses Windows CryptoAPI for FIPS-compliant implementation.
     *
     * ========================================================================
     */
    
    if (!view.IsValid()) {
        SS_LOG_ERROR(L"Whitelist", L"ComputeDatabaseChecksum: invalid view");
        return false;
    }
    
    outChecksum.fill(0);
    
    // Acquire crypto context
    CryptoContextGuard cryptProv;
    if (!CryptAcquireContextW(cryptProv.Ptr(), nullptr, nullptr, 
                               PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        SS_LOG_LAST_ERROR(L"Whitelist", L"CryptAcquireContext failed");
        return false;
    }
    
    // Create hash object
    CryptoHashGuard cryptHash;
    if (!CryptCreateHash(cryptProv.Get(), CALG_SHA_256, 0, 0, cryptHash.Ptr())) {
        SS_LOG_LAST_ERROR(L"Whitelist", L"CryptCreateHash failed");
        return false;
    }
    
    // Hash in chunks for large files
    constexpr size_t CHUNK_SIZE = 1024 * 1024; // 1MB chunks
    const auto* data = static_cast<const uint8_t*>(view.baseAddress);
    
    // Hash everything before the checksum field
    constexpr size_t checksumOffset = offsetof(WhitelistDatabaseHeader, sha256Checksum);
    
    // Hash header up to checksum
    if (!CryptHashData(cryptHash.Get(), data, static_cast<DWORD>(checksumOffset), 0)) {
        SS_LOG_LAST_ERROR(L"Whitelist", L"CryptHashData (header) failed");
        return false;
    }
    
    // Skip the checksum field (32 bytes)
    constexpr size_t postChecksumOffset = checksumOffset + 32;
    
    // Hash remaining header
    constexpr size_t remainingHeader = sizeof(WhitelistDatabaseHeader) - postChecksumOffset;
    if (!CryptHashData(cryptHash.Get(), data + postChecksumOffset, 
                       static_cast<DWORD>(remainingHeader), 0)) {
        SS_LOG_LAST_ERROR(L"Whitelist", L"CryptHashData (header remainder) failed");
        return false;
    }
    
    // Hash rest of file in chunks
    size_t offset = sizeof(WhitelistDatabaseHeader);
    while (offset < view.fileSize) {
        size_t remaining = view.fileSize - offset;
        size_t chunkSize = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
        
        if (!CryptHashData(cryptHash.Get(), data + offset, 
                           static_cast<DWORD>(chunkSize), 0)) {
            SS_LOG_LAST_ERROR(L"Whitelist", L"CryptHashData (data chunk) failed");
            return false;
        }
        
        offset += chunkSize;
    }
    
    // Get hash value
    DWORD hashLen = 32;
    if (!CryptGetHashParam(cryptHash.Get(), HP_HASHVAL, outChecksum.data(), &hashLen, 0)) {
        SS_LOG_LAST_ERROR(L"Whitelist", L"CryptGetHashParam failed");
        return false;
    }
    
    return true;
}

bool VerifyIntegrity(const MemoryMappedView& view, StoreError& error) noexcept {
    /*
     * ========================================================================
     * FULL DATABASE INTEGRITY VERIFICATION
     * ========================================================================
     *
     * Performs complete integrity check:
     * 1. Header validation
     * 2. CRC32 quick check
     * 3. SHA-256 full checksum verification
     *
     * ========================================================================
     */
    
    if (!view.IsValid()) {
        error = StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Invalid memory-mapped view"
        );
        return false;
    }
    
    // Get header
    const auto* header = view.GetAt<WhitelistDatabaseHeader>(0);
    if (!header) {
        error = StoreError::WithMessage(
            WhitelistStoreError::InvalidHeader,
            "Failed to read database header"
        );
        return false;
    }
    
    // Validate header structure
    if (!ValidateHeader(header)) {
        error = StoreError::WithMessage(
            WhitelistStoreError::InvalidHeader,
            "Header validation failed"
        );
        return false;
    }
    
    // Verify SHA-256 checksum (skip if all zeros - new database)
    bool hasChecksum = false;
    for (uint8_t b : header->sha256Checksum) {
        if (b != 0) {
            hasChecksum = true;
            break;
        }
    }
    
    if (hasChecksum) {
        std::array<uint8_t, 32> computedChecksum;
        if (!ComputeDatabaseChecksum(view, computedChecksum)) {
            error = StoreError::WithMessage(
                WhitelistStoreError::InvalidChecksum,
                "Failed to compute checksum"
            );
            return false;
        }
        
        if (computedChecksum != header->sha256Checksum) {
            error = StoreError::WithMessage(
                WhitelistStoreError::InvalidChecksum,
                "Database checksum mismatch - possible corruption"
            );
            return false;
        }
    }
    
    error = StoreError::Success();
    return true;
}

const char* HashAlgorithmToString(HashAlgorithm algo) noexcept {
    switch (algo) {
        case HashAlgorithm::MD5:          return "MD5";
        case HashAlgorithm::SHA1:         return "SHA1";
        case HashAlgorithm::SHA256:       return "SHA256";
        case HashAlgorithm::SHA512:       return "SHA512";
        case HashAlgorithm::ImpHash:      return "IMPHASH";
        case HashAlgorithm::Authenticode: return "AUTHENTICODE";
        default:                          return "UNKNOWN";
    }
}

const char* EntryTypeToString(WhitelistEntryType type) noexcept {
    switch (type) {
        case WhitelistEntryType::FileHash:     return "FileHash";
        case WhitelistEntryType::FilePath:     return "FilePath";
        case WhitelistEntryType::ProcessPath:  return "ProcessPath";
        case WhitelistEntryType::Certificate:  return "Certificate";
        case WhitelistEntryType::Publisher:    return "Publisher";
        case WhitelistEntryType::ProductName:  return "ProductName";
        case WhitelistEntryType::CommandLine:  return "CommandLine";
        case WhitelistEntryType::ImportHash:   return "ImportHash";
        case WhitelistEntryType::CombinedRule: return "CombinedRule";
        default:                               return "Unknown";
    }
}

const char* ReasonToString(WhitelistReason reason) noexcept {
    switch (reason) {
        case WhitelistReason::SystemFile:      return "SystemFile";
        case WhitelistReason::TrustedVendor:   return "TrustedVendor";
        case WhitelistReason::UserApproved:    return "UserApproved";
        case WhitelistReason::PolicyBased:     return "PolicyBased";
        case WhitelistReason::TemporaryBypass: return "TemporaryBypass";
        case WhitelistReason::MLClassified:    return "MLClassified";
        case WhitelistReason::ReputationBased: return "ReputationBased";
        case WhitelistReason::Compatibility:   return "Compatibility";
        case WhitelistReason::Development:     return "Development";
        case WhitelistReason::Custom:          return "Custom";
        default:                               return "Unknown";
    }
}

std::optional<HashValue> ParseHashString(
    const std::string& hashStr,
    HashAlgorithm algo
) noexcept {
    /*
     * ========================================================================
     * EXCEPTION-SAFE HASH STRING PARSING
     * ========================================================================
     *
     * Parses hex-encoded hash strings with full validation.
     * Stack-based processing to avoid heap allocation failures.
     *
     * ========================================================================
     */
    
    if (hashStr.empty()) {
        SS_LOG_ERROR(L"Whitelist", L"ParseHashString: empty hash string");
        return std::nullopt;
    }
    
    // Maximum reasonable length
    constexpr size_t MAX_HASH_STRING_LEN = 256;
    if (hashStr.length() > MAX_HASH_STRING_LEN) {
        SS_LOG_ERROR(L"Whitelist", L"ParseHashString: string too long (%zu)", 
            hashStr.length());
        return std::nullopt;
    }
    
    // Get expected length for algorithm
    uint8_t expectedLen = HashValue::GetLengthForAlgorithm(algo);
    if (expectedLen == 0) {
        SS_LOG_ERROR(L"Whitelist", L"ParseHashString: invalid algorithm %u",
            static_cast<uint8_t>(algo));
        return std::nullopt;
    }
    
    // Stack-based cleaning (remove whitespace)
    char cleaned[MAX_HASH_STRING_LEN + 1];
    size_t cleanedLen = 0;
    
    for (size_t i = 0; i < hashStr.length() && cleanedLen < MAX_HASH_STRING_LEN; ++i) {
        char c = hashStr[i];
        if (!std::isspace(static_cast<unsigned char>(c))) {
            cleaned[cleanedLen++] = c;
        }
    }
    cleaned[cleanedLen] = '\0';
    
    // Validate hex string
    if (cleanedLen != static_cast<size_t>(expectedLen) * 2) {
        SS_LOG_ERROR(L"Whitelist",
            L"ParseHashString: invalid length %zu for %S (expected %u hex chars)",
            cleanedLen, HashAlgorithmToString(algo), expectedLen * 2);
        return std::nullopt;
    }
    
    // Parse hex to bytes
    HashValue hash{};
    hash.algorithm = algo;
    hash.length = expectedLen;
    
    for (size_t i = 0; i < expectedLen; ++i) {
        uint8_t high = HexCharToValue(cleaned[i * 2]);
        uint8_t low = HexCharToValue(cleaned[i * 2 + 1]);
        
        if (high == 0xFF || low == 0xFF) {
            SS_LOG_ERROR(L"Whitelist",
                L"ParseHashString: invalid hex character at position %zu", i * 2);
            return std::nullopt;
        }
        
        hash.data[i] = static_cast<uint8_t>((high << 4) | low);
    }
    
    return hash;
}

std::string FormatHashString(const HashValue& hash) {
    /*
     * ========================================================================
     * HIGH-PERFORMANCE HASH FORMATTING
     * ========================================================================
     *
     * Converts binary hash to lowercase hex string.
     * Lookup table for optimal performance.
     *
     * ========================================================================
     */
    
    if (hash.length == 0 || hash.length > hash.data.size()) {
        return {};
    }
    
    static constexpr char hexChars[] = "0123456789abcdef";
    
    std::string result;
    result.reserve(static_cast<size_t>(hash.length) * 2);
    
    for (size_t i = 0; i < hash.length; ++i) {
        uint8_t byte = hash.data[i];
        result.push_back(hexChars[(byte >> 4) & 0x0F]);
        result.push_back(hexChars[byte & 0x0F]);
    }
    
    return result;
}

uint32_t CalculateOptimalCacheSize(uint64_t dbSizeBytes) noexcept {
    /*
     * ========================================================================
     * CACHE SIZE CALCULATION
     * ========================================================================
     *
     * Strategy: 5% of database size, clamped to [16MB, 512MB]
     * This provides good cache hit rates while limiting memory usage.
     *
     * ========================================================================
     */
    
    constexpr uint64_t MIN_CACHE_MB = 16;
    constexpr uint64_t MAX_CACHE_MB = 512;
    constexpr double CACHE_RATIO = 0.05;
    
    uint64_t cacheSizeMB = static_cast<uint64_t>(
        (static_cast<double>(dbSizeBytes) / (1024.0 * 1024.0)) * CACHE_RATIO
    );
    
    if (cacheSizeMB < MIN_CACHE_MB) {
        cacheSizeMB = MIN_CACHE_MB;
    } else if (cacheSizeMB > MAX_CACHE_MB) {
        cacheSizeMB = MAX_CACHE_MB;
    }
    
    return static_cast<uint32_t>(cacheSizeMB);
}

std::wstring NormalizePath(std::wstring_view path) {
    /*
     * ========================================================================
     * PATH NORMALIZATION FOR CONSISTENT COMPARISON
     * ========================================================================
     *
     * - Converts to lowercase (Windows is case-insensitive)
     * - Converts backslashes to forward slashes
     * - Removes trailing slashes
     * - Expands environment variables (optional)
     *
     * ========================================================================
     */
    
    if (path.empty()) {
        return {};
    }
    
    std::wstring normalized;
    normalized.reserve(path.length());
    
    for (wchar_t c : path) {
        // Convert to lowercase
        wchar_t lower = static_cast<wchar_t>(std::towlower(c));
        
        // Normalize path separators to backslash (Windows standard)
        if (lower == L'/') {
            lower = L'\\';
        }
        
        normalized.push_back(lower);
    }
    
    // Remove trailing backslashes (except for root paths like "C:\")
    while (normalized.length() > 3 && normalized.back() == L'\\') {
        normalized.pop_back();
    }
    
    return normalized;
}

bool PathMatchesPattern(
    std::wstring_view path,
    std::wstring_view pattern,
    PathMatchMode mode,
    bool caseSensitive
) noexcept {
    /*
     * ========================================================================
     * PATH PATTERN MATCHING
     * ========================================================================
     *
     * Supports multiple matching modes:
     * - Exact: Full string match
     * - Prefix: Starts with pattern
     * - Suffix: Ends with pattern
     * - Contains: Pattern appears anywhere
     * - Glob: Wildcard matching (*, ?)
     *
     * ========================================================================
     */
    
    if (path.empty()) {
        return pattern.empty();
    }
    
    // Normalize for comparison
    auto normPath = NormalizePath(path);
    auto normPattern = NormalizePath(pattern);
    
    switch (mode) {
        case PathMatchMode::Exact:
            return normPath == normPattern;
            
        case PathMatchMode::Prefix:
            return normPath.starts_with(normPattern);
            
        case PathMatchMode::Suffix:
            return normPath.ends_with(normPattern);
            
        case PathMatchMode::Contains:
            return normPath.find(normPattern) != std::wstring::npos;
            
        case PathMatchMode::Glob: {
            // Simple glob matching with * and ?
            size_t pathIdx = 0;
            size_t patIdx = 0;
            size_t starPathIdx = std::wstring::npos;
            size_t starPatIdx = std::wstring::npos;
            
            while (pathIdx < normPath.length()) {
                if (patIdx < normPattern.length()) {
                    wchar_t patChar = normPattern[patIdx];
                    
                    if (patChar == L'*') {
                        // Star: remember position and try to match empty string
                        starPatIdx = patIdx++;
                        starPathIdx = pathIdx;
                        continue;
                    }
                    
                    if (patChar == L'?' || patChar == normPath[pathIdx]) {
                        ++pathIdx;
                        ++patIdx;
                        continue;
                    }
                }
                
                // Mismatch - backtrack to last star if possible
                if (starPatIdx != std::wstring::npos) {
                    patIdx = starPatIdx + 1;
                    pathIdx = ++starPathIdx;
                    continue;
                }
                
                return false;
            }
            
            // Skip trailing stars
            while (patIdx < normPattern.length() && normPattern[patIdx] == L'*') {
                ++patIdx;
            }
            
            return patIdx == normPattern.length();
        }
            
        case PathMatchMode::Regex:
            // TODO: Implement regex matching (expensive, use sparingly)
            SS_LOG_WARN(L"Whitelist", L"Regex path matching not yet implemented");
            return false;
            
        default:
            return false;
    }
}

} // namespace Format

// ============================================================================
// MEMORY MAPPING IMPLEMENTATIONS
// ============================================================================

namespace MemoryMapping {

namespace {

// Helper: Open file for memory mapping
HANDLE OpenFileForMapping(const std::wstring& path, bool readOnly, DWORD& outError) noexcept {
    DWORD desiredAccess = readOnly ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
    DWORD shareMode = readOnly ? FILE_SHARE_READ : 0;
    DWORD flagsAndAttributes = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS;
    
    HANDLE hFile = CreateFileW(
        path.c_str(),
        desiredAccess,
        shareMode,
        nullptr,
        OPEN_EXISTING,
        flagsAndAttributes,
        nullptr
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        outError = GetLastError();
        SS_LOG_LAST_ERROR(L"Whitelist", L"Failed to open file: %s", path.c_str());
    }
    
    return hFile;
}

// Helper: Create new file for database
HANDLE CreateFileForDatabase(const std::wstring& path, DWORD& outError) noexcept {
    HANDLE hFile = CreateFileW(
        path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, // Exclusive access during creation
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
        nullptr
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        outError = GetLastError();
        SS_LOG_LAST_ERROR(L"Whitelist", L"Failed to create file: %s", path.c_str());
    }
    
    return hFile;
}

// Helper: Get file size
bool GetFileSizeHelper(HANDLE hFile, uint64_t& outSize, DWORD& outError) noexcept {
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(hFile, &size)) {
        outError = GetLastError();
        SS_LOG_LAST_ERROR(L"Whitelist", L"Failed to get file size");
        return false;
    }
    outSize = static_cast<uint64_t>(size.QuadPart);
    return true;
}

// Helper: Set file size
bool SetFileSizeHelper(HANDLE hFile, uint64_t size, DWORD& outError) noexcept {
    LARGE_INTEGER pos{};
    pos.QuadPart = static_cast<LONGLONG>(size);
    
    if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN)) {
        outError = GetLastError();
        SS_LOG_LAST_ERROR(L"Whitelist", L"Failed to set file pointer");
        return false;
    }
    
    if (!SetEndOfFile(hFile)) {
        outError = GetLastError();
        SS_LOG_LAST_ERROR(L"Whitelist", L"Failed to set end of file");
        return false;
    }
    
    return true;
}

// Helper: Create file mapping
HANDLE CreateFileMappingHelper(HANDLE hFile, bool readOnly, uint64_t size, DWORD& outError) noexcept {
    DWORD protect = readOnly ? PAGE_READONLY : PAGE_READWRITE;
    DWORD maxSizeHigh = static_cast<DWORD>(size >> 32);
    DWORD maxSizeLow = static_cast<DWORD>(size & 0xFFFFFFFF);
    
    HANDLE hMapping = CreateFileMappingW(
        hFile,
        nullptr,
        protect,
        maxSizeHigh,
        maxSizeLow,
        nullptr
    );
    
    if (hMapping == nullptr) {
        outError = GetLastError();
        SS_LOG_LAST_ERROR(L"Whitelist", L"Failed to create file mapping");
    }
    
    return hMapping;
}

// Helper: Map view of file
void* MapViewHelper(HANDLE hMapping, bool readOnly, uint64_t size, DWORD& outError) noexcept {
    DWORD desiredAccess = readOnly ? FILE_MAP_READ : FILE_MAP_WRITE;
    
    void* baseAddress = MapViewOfFile(
        hMapping,
        desiredAccess,
        0, // offset high
        0, // offset low
        static_cast<SIZE_T>(size)
    );
    
    if (baseAddress == nullptr) {
        outError = GetLastError();
        SS_LOG_LAST_ERROR(L"Whitelist", L"Failed to map view of file");
    }
    
    return baseAddress;
}

} // anonymous namespace

bool OpenView(
    const std::wstring& path,
    bool readOnly,
    MemoryMappedView& view,
    StoreError& error
) noexcept {
    /*
     * ========================================================================
     * RAII-BASED MEMORY-MAPPED FILE OPENING
     * ========================================================================
     *
     * Opens existing database file with full validation.
     * Uses RAII guards for exception-safe resource management.
     *
     * ========================================================================
     */
    
    // Close any existing view
    CloseView(view);
    
    // Input validation
    if (path.empty()) {
        error = StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Empty file path"
        );
        return false;
    }
    
    if (path.length() > MAX_PATH_LENGTH) {
        error = StoreError::WithMessage(
            WhitelistStoreError::PathTooLong,
            "File path too long"
        );
        return false;
    }
    
    // Open file
    DWORD win32Error = 0;
    HandleGuard fileGuard(OpenFileForMapping(path, readOnly, win32Error));
    
    if (!fileGuard.IsValid()) {
        error = StoreError::FromWin32(WhitelistStoreError::FileNotFound, win32Error);
        error.message = "Failed to open database file";
        return false;
    }
    
    // Get file size
    uint64_t fileSize = 0;
    if (!GetFileSizeHelper(fileGuard.Get(), fileSize, win32Error)) {
        error = StoreError::FromWin32(WhitelistStoreError::InvalidSection, win32Error);
        error.message = "Failed to get file size";
        return false;
    }
    
    // Validate minimum size
    if (fileSize < sizeof(WhitelistDatabaseHeader)) {
        error = StoreError::WithMessage(
            WhitelistStoreError::InvalidHeader,
            "File too small for valid header"
        );
        return false;
    }
    
    // Validate maximum size
    if (fileSize > MAX_DATABASE_SIZE) {
        error = StoreError::WithMessage(
            WhitelistStoreError::DatabaseTooLarge,
            "Database exceeds maximum size"
        );
        return false;
    }
    
    // Create file mapping
    HandleGuard mappingGuard(CreateFileMappingHelper(fileGuard.Get(), readOnly, fileSize, win32Error));
    
    if (!mappingGuard.IsValid()) {
        error = StoreError::FromWin32(WhitelistStoreError::MappingFailed, win32Error);
        error.message = "Failed to create file mapping";
        return false;
    }
    
    // Map view
    MappedViewGuard viewGuard(MapViewHelper(mappingGuard.Get(), readOnly, fileSize, win32Error));
    
    if (!viewGuard.IsValid()) {
        error = StoreError::FromWin32(WhitelistStoreError::MappingFailed, win32Error);
        error.message = "Failed to map view of file";
        return false;
    }
    
    // Validate header before committing
    const auto* header = reinterpret_cast<const WhitelistDatabaseHeader*>(viewGuard.Get());
    if (!Format::ValidateHeader(header)) {
        error = StoreError::WithMessage(
            WhitelistStoreError::InvalidHeader,
            "Invalid database header"
        );
        return false;
    }
    
    // Success - transfer ownership
    view.fileHandle = fileGuard.Release();
    view.mappingHandle = mappingGuard.Release();
    view.baseAddress = viewGuard.Release();
    view.fileSize = fileSize;
    view.readOnly = readOnly;
    
    SS_LOG_INFO(L"Whitelist",
        L"Opened whitelist database: %s (%llu bytes, %s)",
        path.c_str(), fileSize, readOnly ? L"read-only" : L"read-write");
    
    error = StoreError::Success();
    return true;
}

bool CreateDatabase(
    const std::wstring& path,
    uint64_t initialSize,
    MemoryMappedView& view,
    StoreError& error
) noexcept {
    /*
     * ========================================================================
     * CREATE NEW DATABASE FILE
     * ========================================================================
     *
     * Creates a new whitelist database with initialized header.
     * Allocates space for indices and data sections.
     *
     * ========================================================================
     */
    
    // Close any existing view
    CloseView(view);
    
    // Validate parameters
    if (path.empty()) {
        error = StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Empty file path"
        );
        return false;
    }
    
    // Minimum size: header + at least one page for each section
    constexpr uint64_t MIN_DB_SIZE = PAGE_SIZE * 16; // 64KB minimum
    if (initialSize < MIN_DB_SIZE) {
        initialSize = MIN_DB_SIZE;
    }
    
    // Align to page size
    initialSize = Format::AlignToPage(initialSize);
    
    if (initialSize > MAX_DATABASE_SIZE) {
        error = StoreError::WithMessage(
            WhitelistStoreError::DatabaseTooLarge,
            "Requested size exceeds maximum"
        );
        return false;
    }
    
    // Create file
    DWORD win32Error = 0;
    HandleGuard fileGuard(CreateFileForDatabase(path, win32Error));
    
    if (!fileGuard.IsValid()) {
        error = StoreError::FromWin32(WhitelistStoreError::FileAccessDenied, win32Error);
        error.message = "Failed to create database file";
        return false;
    }
    
    // Set file size
    if (!SetFileSizeHelper(fileGuard.Get(), initialSize, win32Error)) {
        error = StoreError::FromWin32(WhitelistStoreError::InvalidSection, win32Error);
        error.message = "Failed to set file size";
        return false;
    }
    
    // Create file mapping
    HandleGuard mappingGuard(CreateFileMappingHelper(fileGuard.Get(), false, initialSize, win32Error));
    
    if (!mappingGuard.IsValid()) {
        error = StoreError::FromWin32(WhitelistStoreError::MappingFailed, win32Error);
        error.message = "Failed to create file mapping";
        return false;
    }
    
    // Map view (read-write for initialization)
    MappedViewGuard viewGuard(MapViewHelper(mappingGuard.Get(), false, initialSize, win32Error));
    
    if (!viewGuard.IsValid()) {
        error = StoreError::FromWin32(WhitelistStoreError::MappingFailed, win32Error);
        error.message = "Failed to map view";
        return false;
    }
    
    // Initialize header
    auto* header = reinterpret_cast<WhitelistDatabaseHeader*>(viewGuard.Get());
    std::memset(header, 0, sizeof(WhitelistDatabaseHeader));
    
    // Set magic and version
    header->magic = WHITELIST_DB_MAGIC;
    header->versionMajor = WHITELIST_DB_VERSION_MAJOR;
    header->versionMinor = WHITELIST_DB_VERSION_MINOR;
    
    // Generate UUID
    if (FAILED(CoCreateGuid(reinterpret_cast<GUID*>(header->databaseUuid.data())))) {
        // Fallback: use random bytes from crypto API
        CryptoContextGuard cryptProv;
        if (CryptAcquireContextW(cryptProv.Ptr(), nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(cryptProv.Get(), 16, header->databaseUuid.data());
        }
    }
    
    // Set timestamps
    auto now = std::chrono::system_clock::now();
    auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()
    ).count();
    header->creationTime = static_cast<uint64_t>(epoch);
    header->lastUpdateTime = static_cast<uint64_t>(epoch);
    header->buildNumber = 1;
    
    // Calculate section layout
    uint64_t offset = PAGE_SIZE; // Start after header
    
    // Bloom filter section (1MB default)
    header->bloomFilterOffset = offset;
    header->bloomFilterSize = 1024 * 1024;
    offset += Format::AlignToPage(header->bloomFilterSize);
    
    // Path bloom filter (512KB)
    header->pathBloomOffset = offset;
    header->pathBloomSize = 512 * 1024;
    offset += Format::AlignToPage(header->pathBloomSize);
    
    // Hash index section (reserve 25% of remaining space)
    uint64_t remaining = initialSize - offset;
    header->hashIndexOffset = offset;
    header->hashIndexSize = remaining / 4;
    offset += Format::AlignToPage(header->hashIndexSize);
    
    // Path index section (15% of remaining)
    remaining = initialSize - offset;
    header->pathIndexOffset = offset;
    header->pathIndexSize = remaining / 4;
    offset += Format::AlignToPage(header->pathIndexSize);
    
    // Certificate index (5%)
    remaining = initialSize - offset;
    header->certIndexOffset = offset;
    header->certIndexSize = remaining / 8;
    offset += Format::AlignToPage(header->certIndexSize);
    
    // Publisher index (5%)
    remaining = initialSize - offset;
    header->publisherIndexOffset = offset;
    header->publisherIndexSize = remaining / 8;
    offset += Format::AlignToPage(header->publisherIndexSize);
    
    // Entry data section (40% of remaining)
    remaining = initialSize - offset;
    header->entryDataOffset = offset;
    header->entryDataSize = remaining / 2;
    offset += Format::AlignToPage(header->entryDataSize);
    
    // String pool (rest)
    remaining = initialSize - offset;
    header->stringPoolOffset = offset;
    header->stringPoolSize = remaining - PAGE_SIZE; // Leave room for metadata
    offset += Format::AlignToPage(header->stringPoolSize);
    
    // Metadata section
    header->metadataOffset = offset;
    header->metadataSize = initialSize - offset;
    
    // Performance hints
    header->recommendedCacheSize = Format::CalculateOptimalCacheSize(initialSize);
    header->bloomExpectedElements = 1000000; // 1M elements
    header->bloomFalsePositiveRate = 100;    // 0.0001 (0.01%)
    
    // Compute CRC32
    header->headerCrc32 = Format::ComputeHeaderCRC32(header);
    
    // Transfer ownership
    view.fileHandle = fileGuard.Release();
    view.mappingHandle = mappingGuard.Release();
    view.baseAddress = viewGuard.Release();
    view.fileSize = initialSize;
    view.readOnly = false;
    
    SS_LOG_INFO(L"Whitelist",
        L"Created new whitelist database: %s (%llu bytes)",
        path.c_str(), initialSize);
    
    error = StoreError::Success();
    return true;
}

void CloseView(MemoryMappedView& view) noexcept {
    if (view.baseAddress != nullptr) {
        UnmapViewOfFile(view.baseAddress);
        view.baseAddress = nullptr;
    }
    
    if (view.mappingHandle != nullptr && view.mappingHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(view.mappingHandle);
        view.mappingHandle = nullptr;
    }
    
    if (view.fileHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(view.fileHandle);
        view.fileHandle = INVALID_HANDLE_VALUE;
    }
    
    view.fileSize = 0;
    view.readOnly = true;
}

bool FlushView(MemoryMappedView& view, StoreError& error) noexcept {
    if (!view.IsValid()) {
        error = StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Invalid memory-mapped view"
        );
        return false;
    }
    
    if (view.readOnly) {
        error = StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot flush read-only view"
        );
        return false;
    }
    
    // Flush memory-mapped region
    if (!FlushViewOfFile(view.baseAddress, static_cast<SIZE_T>(view.fileSize))) {
        DWORD win32Error = GetLastError();
        error = StoreError::FromWin32(WhitelistStoreError::Unknown, win32Error);
        error.message = "Failed to flush view to disk";
        SS_LOG_LAST_ERROR(L"Whitelist", L"FlushViewOfFile failed");
        return false;
    }
    
    // Flush file buffers
    if (!FlushFileBuffers(view.fileHandle)) {
        DWORD win32Error = GetLastError();
        error = StoreError::FromWin32(WhitelistStoreError::Unknown, win32Error);
        error.message = "Failed to flush file buffers";
        SS_LOG_LAST_ERROR(L"Whitelist", L"FlushFileBuffers failed");
        return false;
    }
    
    error = StoreError::Success();
    return true;
}

bool ExtendDatabase(
    MemoryMappedView& view,
    uint64_t newSize,
    StoreError& error
) noexcept {
    /*
     * ========================================================================
     * EXTEND DATABASE SIZE
     * ========================================================================
     *
     * Grows the database file and remaps it.
     * This is an expensive operation - use sparingly.
     *
     * ========================================================================
     */
    
    if (!view.IsValid()) {
        error = StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Invalid memory-mapped view"
        );
        return false;
    }
    
    if (view.readOnly) {
        error = StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot extend read-only database"
        );
        return false;
    }
    
    if (newSize <= view.fileSize) {
        error = StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "New size must be larger than current size"
        );
        return false;
    }
    
    if (newSize > MAX_DATABASE_SIZE) {
        error = StoreError::WithMessage(
            WhitelistStoreError::DatabaseTooLarge,
            "New size exceeds maximum"
        );
        return false;
    }
    
    // Align to page size
    newSize = Format::AlignToPage(newSize);
    
    // Flush current view
    if (!FlushView(view, error)) {
        return false;
    }
    
    // Save file handle, close mapping
    HANDLE hFile = view.fileHandle;
    
    if (view.baseAddress) {
        UnmapViewOfFile(view.baseAddress);
        view.baseAddress = nullptr;
    }
    
    if (view.mappingHandle) {
        CloseHandle(view.mappingHandle);
        view.mappingHandle = nullptr;
    }
    
    // Extend file
    DWORD win32Error = 0;
    if (!SetFileSizeHelper(hFile, newSize, win32Error)) {
        error = StoreError::FromWin32(WhitelistStoreError::Unknown, win32Error);
        error.message = "Failed to extend file";
        return false;
    }
    
    // Recreate mapping
    HandleGuard mappingGuard(CreateFileMappingHelper(hFile, false, newSize, win32Error));
    
    if (!mappingGuard.IsValid()) {
        error = StoreError::FromWin32(WhitelistStoreError::MappingFailed, win32Error);
        error.message = "Failed to recreate file mapping";
        return false;
    }
    
    // Remap view
    MappedViewGuard viewGuard(MapViewHelper(mappingGuard.Get(), false, newSize, win32Error));
    
    if (!viewGuard.IsValid()) {
        error = StoreError::FromWin32(WhitelistStoreError::MappingFailed, win32Error);
        error.message = "Failed to remap view";
        return false;
    }
    
    // Update view structure
    view.mappingHandle = mappingGuard.Release();
    view.baseAddress = viewGuard.Release();
    view.fileSize = newSize;
    
    SS_LOG_INFO(L"Whitelist", L"Extended database to %llu bytes", newSize);
    
    error = StoreError::Success();
    return true;
}

} // namespace MemoryMapping

} // namespace Whitelist
} // namespace ShadowStrike
