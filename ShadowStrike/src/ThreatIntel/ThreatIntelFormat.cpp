/*
 * ============================================================================
 * ShadowStrike ThreatIntelFormat - IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * This file implements the utility functions declared in ThreatIntelFormat.hpp
 * for threat intelligence binary format operations.
 *
 * Implementation includes:
 * - Header validation and CRC32/SHA256 checksum computation
 * - IPv4/IPv6 address parsing and formatting
 * - Hash value parsing and formatting
 * - Domain/URL/Email validation and normalization
 * - Memory-mapped file operations
 * - STIX timestamp handling
 * - UUID generation and parsing
 * - Bloom filter size calculations
 *
 * Performance Standards: CrowdStrike Falcon / Microsoft Defender ATP quality
 *
 * ============================================================================
 */

#include "ThreatIntelFormat.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <ctime>
#include <iomanip>
#include <random>
#include <regex>
#include <sstream>

// Windows CryptoAPI for SHA256
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// ANONYMOUS NAMESPACE FOR INTERNAL HELPERS
// ============================================================================

namespace {

/// @brief Thread-local random engine for UUID generation
thread_local std::mt19937_64 g_randomEngine{std::random_device{}()};

/// @brief Convert hex character to nibble value
/// @param c Hex character ('0'-'9', 'a'-'f', 'A'-'F')
/// @return Nibble value (0-15) or -1 on error
[[nodiscard]] constexpr int HexCharToNibble(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

/// @brief Convert nibble value to hex character
/// @param nibble Value 0-15
/// @param uppercase Use uppercase letters
/// @return Hex character
[[nodiscard]] constexpr char NibbleToHexChar(int nibble, bool uppercase = false) noexcept {
    if (nibble < 10) return static_cast<char>('0' + nibble);
    return static_cast<char>((uppercase ? 'A' : 'a') + (nibble - 10));
}

/// @brief Check if character is valid hex digit
[[nodiscard]] constexpr bool IsHexDigit(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/// @brief Check if character is valid domain character
[[nodiscard]] constexpr bool IsDomainChar(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '.';
}

/// @brief Parse hex string to bytes
/// @param hexStr Hex string (must be even length)
/// @param outBytes Output buffer
/// @param maxBytes Maximum bytes to parse
/// @return Number of bytes parsed, or 0 on error
[[nodiscard]] size_t ParseHexString(
    std::string_view hexStr,
    uint8_t* outBytes,
    size_t maxBytes
) noexcept {
    if (hexStr.empty() || (hexStr.length() % 2) != 0) {
        return 0;
    }
    
    size_t byteCount = hexStr.length() / 2;
    if (byteCount > maxBytes) {
        byteCount = maxBytes;
    }
    
    for (size_t i = 0; i < byteCount; ++i) {
        int high = HexCharToNibble(hexStr[i * 2]);
        int low = HexCharToNibble(hexStr[i * 2 + 1]);
        
        if (high < 0 || low < 0) {
            return 0;
        }
        
        outBytes[i] = static_cast<uint8_t>((high << 4) | low);
    }
    
    return byteCount;
}

/// @brief Format bytes to hex string
/// @param bytes Input bytes
/// @param length Number of bytes
/// @param uppercase Use uppercase letters
/// @return Hex string
[[nodiscard]] std::string FormatHexString(
    const uint8_t* bytes,
    size_t length,
    bool uppercase = false
) {
    std::string result;
    result.reserve(length * 2);
    
    for (size_t i = 0; i < length; ++i) {
        result += NibbleToHexChar((bytes[i] >> 4) & 0x0F, uppercase);
        result += NibbleToHexChar(bytes[i] & 0x0F, uppercase);
    }
    
    return result;
}

/// @brief Trim whitespace from string view
[[nodiscard]] std::string_view TrimWhitespace(std::string_view str) noexcept {
    while (!str.empty() && std::isspace(static_cast<unsigned char>(str.front()))) {
        str.remove_prefix(1);
    }
    while (!str.empty() && std::isspace(static_cast<unsigned char>(str.back()))) {
        str.remove_suffix(1);
    }
    return str;
}

/// @brief Convert string to lowercase
[[nodiscard]] std::string ToLowerCase(std::string_view str) {
    std::string result;
    result.reserve(str.length());
    for (char c : str) {
        result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return result;
}

/// @brief Split string by delimiter
[[nodiscard]] std::vector<std::string_view> SplitString(
    std::string_view str,
    char delimiter
) {
    std::vector<std::string_view> result;
    size_t start = 0;
    
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == delimiter) {
            if (i > start) {
                result.push_back(str.substr(start, i - start));
            }
            start = i + 1;
        }
    }
    
    if (start < str.length()) {
        result.push_back(str.substr(start));
    }
    
    return result;
}

} // anonymous namespace

// ============================================================================
// FORMAT NAMESPACE IMPLEMENTATION
// ============================================================================

namespace Format {

// ----------------------------------------------------------------------------
// HEADER VALIDATION
// ----------------------------------------------------------------------------

bool ValidateHeader(const ThreatIntelDatabaseHeader* header) noexcept {
    // Null check
    if (!header) {
        return false;
    }
    
    // Magic number validation
    if (header->magic != THREATINTEL_DB_MAGIC) {
        return false;
    }
    
    // Version check (accept current major version)
    if (header->versionMajor != THREATINTEL_DB_VERSION_MAJOR) {
        return false;
    }
    
    // Minor version can be higher (forward compatible) but not too high
    if (header->versionMinor > 99) {
        return false;
    }
    
    // Validate creation time is reasonable (after 2020, before 2100)
    constexpr uint64_t MIN_TIMESTAMP = 1577836800;  // 2020-01-01 00:00:00 UTC
    constexpr uint64_t MAX_TIMESTAMP = 4102444800;  // 2100-01-01 00:00:00 UTC
    
    if (header->creationTime < MIN_TIMESTAMP || header->creationTime > MAX_TIMESTAMP) {
        return false;
    }
    
    // Last update should be >= creation time
    if (header->lastUpdateTime < header->creationTime) {
        return false;
    }
    
    // Validate section offsets are page-aligned
    auto isPageAligned = [](uint64_t offset) -> bool {
        return offset == 0 || (offset % PAGE_SIZE) == 0;
    };
    
    if (!isPageAligned(header->ipv4IndexOffset) ||
        !isPageAligned(header->ipv6IndexOffset) ||
        !isPageAligned(header->domainIndexOffset) ||
        !isPageAligned(header->urlIndexOffset) ||
        !isPageAligned(header->hashIndexOffset) ||
        !isPageAligned(header->emailIndexOffset) ||
        !isPageAligned(header->certIndexOffset) ||
        !isPageAligned(header->ja3IndexOffset) ||
        !isPageAligned(header->entryDataOffset) ||
        !isPageAligned(header->compactEntryOffset) ||
        !isPageAligned(header->stringPoolOffset) ||
        !isPageAligned(header->bloomFilterOffset) ||
        !isPageAligned(header->stixBundleOffset) ||
        !isPageAligned(header->feedConfigOffset) ||
        !isPageAligned(header->metadataOffset) ||
        !isPageAligned(header->relationGraphOffset)) {
        return false;
    }
    
    // Validate file size limits
    if (header->totalFileSize > MAX_DATABASE_SIZE) {
        return false;
    }
    
    // Validate entry counts don't exceed maximum
    uint64_t totalEntries = header->totalIPv4Entries + header->totalIPv6Entries +
                            header->totalDomainEntries + header->totalURLEntries +
                            header->totalHashEntries + header->totalEmailEntries +
                            header->totalCertEntries + header->totalOtherEntries;
    
    if (totalEntries > MAX_IOC_ENTRIES) {
        return false;
    }
    
    // Validate active entries <= total entries
    if (header->totalActiveEntries > totalEntries) {
        return false;
    }
    
    // Quick CRC32 validation of header (excluding checksum fields)
    uint32_t expectedCrc = ComputeHeaderCRC32(header);
    if (header->headerCrc32 != 0 && header->headerCrc32 != expectedCrc) {
        return false;
    }
    
    return true;
}

// ----------------------------------------------------------------------------
// CRC32 COMPUTATION
// ----------------------------------------------------------------------------

uint32_t ComputeHeaderCRC32(const ThreatIntelDatabaseHeader* header) noexcept {
    if (!header) {
        return 0;
    }
    
    // Compute CRC32 of header, excluding the checksum fields themselves
    // We need to zero out the checksum fields during computation
    
    // Copy header to temporary buffer
    ThreatIntelDatabaseHeader tempHeader;
    std::memcpy(&tempHeader, header, sizeof(ThreatIntelDatabaseHeader));
    
    // Zero out integrity fields
    tempHeader.sha256Checksum.fill(0);
    tempHeader.headerCrc32 = 0;
    
    // Compute CRC32
    return Detail::ComputeCRC32(&tempHeader, sizeof(ThreatIntelDatabaseHeader));
}

// ----------------------------------------------------------------------------
// SHA256 CHECKSUM COMPUTATION
// ----------------------------------------------------------------------------

bool ComputeDatabaseChecksum(
    const MemoryMappedView& view,
    std::array<uint8_t, 32>& outChecksum
) noexcept {
    if (!view.IsValid()) {
        return false;
    }
    
    // Use Windows BCrypt for SHA256
    BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status;
    
    // Open algorithm provider
    status = BCryptOpenAlgorithmProvider(
        &hAlgorithm,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        0
    );
    
    if (!BCRYPT_SUCCESS(status)) {
        return false;
    }
    
    // Create hash object
    status = BCryptCreateHash(
        hAlgorithm,
        &hHash,
        nullptr,
        0,
        nullptr,
        0,
        0
    );
    
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return false;
    }
    
    // Hash the data in chunks (skip the checksum field in header)
    const auto* data = static_cast<const uint8_t*>(view.baseAddress);
    uint64_t remaining = view.fileSize;
    uint64_t offset = 0;
    
    // Location of sha256Checksum field in header
    constexpr uint64_t CHECKSUM_OFFSET = offsetof(ThreatIntelDatabaseHeader, sha256Checksum);
    constexpr uint64_t CHECKSUM_SIZE = 32;
    
    // Process in 1MB chunks for efficiency
    constexpr size_t CHUNK_SIZE = 1024 * 1024;
    
    while (remaining > 0) {
        size_t chunkSize = static_cast<size_t>(std::min<uint64_t>(remaining, CHUNK_SIZE));
        
        // Check if this chunk contains the checksum field
        if (offset < CHECKSUM_OFFSET + CHECKSUM_SIZE && offset + chunkSize > CHECKSUM_OFFSET) {
            // Need to hash around the checksum field
            
            // Hash bytes before checksum field
            if (offset < CHECKSUM_OFFSET) {
                size_t beforeSize = static_cast<size_t>(CHECKSUM_OFFSET - offset);
                status = BCryptHashData(hHash, const_cast<PUCHAR>(data + offset), 
                                        static_cast<ULONG>(beforeSize), 0);
                if (!BCRYPT_SUCCESS(status)) {
                    BCryptDestroyHash(hHash);
                    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
                    return false;
                }
            }
            
            // Skip the checksum bytes (hash zeros instead to maintain consistent size)
            uint8_t zeros[32] = {0};
            status = BCryptHashData(hHash, zeros, CHECKSUM_SIZE, 0);
            if (!BCRYPT_SUCCESS(status)) {
                BCryptDestroyHash(hHash);
                BCryptCloseAlgorithmProvider(hAlgorithm, 0);
                return false;
            }
            
            // Hash bytes after checksum field
            uint64_t afterStart = CHECKSUM_OFFSET + CHECKSUM_SIZE;
            if (offset + chunkSize > afterStart) {
                size_t afterSize = static_cast<size_t>((offset + chunkSize) - afterStart);
                status = BCryptHashData(hHash, const_cast<PUCHAR>(data + afterStart),
                                        static_cast<ULONG>(afterSize), 0);
                if (!BCRYPT_SUCCESS(status)) {
                    BCryptDestroyHash(hHash);
                    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
                    return false;
                }
            }
        } else {
            // Normal chunk - no checksum field overlap
            status = BCryptHashData(hHash, const_cast<PUCHAR>(data + offset),
                                    static_cast<ULONG>(chunkSize), 0);
            if (!BCRYPT_SUCCESS(status)) {
                BCryptDestroyHash(hHash);
                BCryptCloseAlgorithmProvider(hAlgorithm, 0);
                return false;
            }
        }
        
        offset += chunkSize;
        remaining -= chunkSize;
    }
    
    // Finalize hash
    status = BCryptFinishHash(hHash, outChecksum.data(), 32, 0);
    
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    
    return BCRYPT_SUCCESS(status);
}

// ----------------------------------------------------------------------------
// DATABASE INTEGRITY VERIFICATION
// ----------------------------------------------------------------------------

bool VerifyIntegrity(
    const MemoryMappedView& view,
    StoreError& error
) noexcept {
    if (!view.IsValid()) {
        error = StoreError::WithMessage(ThreatIntelError::InvalidHeader, 
                                        "Invalid memory-mapped view");
        return false;
    }
    
    // Check minimum size for header
    if (view.fileSize < sizeof(ThreatIntelDatabaseHeader)) {
        error = StoreError::WithMessage(ThreatIntelError::InvalidHeader,
                                        "File too small for header");
        return false;
    }
    
    // Get and validate header
    const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
    if (!header) {
        error = StoreError::WithMessage(ThreatIntelError::InvalidHeader,
                                        "Failed to read header");
        return false;
    }
    
    // Validate magic number
    if (header->magic != THREATINTEL_DB_MAGIC) {
        error = StoreError::WithMessage(ThreatIntelError::InvalidMagic,
                                        "Invalid magic number");
        return false;
    }
    
    // Validate version
    if (header->versionMajor != THREATINTEL_DB_VERSION_MAJOR) {
        error = StoreError::WithMessage(ThreatIntelError::InvalidVersion,
                                        "Unsupported database version");
        return false;
    }
    
    // Validate header CRC32
    uint32_t computedCrc = ComputeHeaderCRC32(header);
    if (header->headerCrc32 != 0 && header->headerCrc32 != computedCrc) {
        error = StoreError::WithMessage(ThreatIntelError::InvalidChecksum,
                                        "Header CRC32 mismatch");
        return false;
    }
    
    // Validate file size matches header
    if (header->totalFileSize != 0 && header->totalFileSize != view.fileSize) {
        error = StoreError::WithMessage(ThreatIntelError::FileCorrupted,
                                        "File size mismatch");
        return false;
    }
    
    // Full header validation
    if (!ValidateHeader(header)) {
        error = StoreError::WithMessage(ThreatIntelError::InvalidHeader,
                                        "Header validation failed");
        return false;
    }
    
    // Optionally verify SHA256 checksum (expensive operation)
    // Only do this if checksum is non-zero
    bool hasChecksum = false;
    for (const auto& byte : header->sha256Checksum) {
        if (byte != 0) {
            hasChecksum = true;
            break;
        }
    }
    
    if (hasChecksum) {
        std::array<uint8_t, 32> computedChecksum;
        if (!ComputeDatabaseChecksum(view, computedChecksum)) {
            error = StoreError::WithMessage(ThreatIntelError::InvalidChecksum,
                                            "Failed to compute database checksum");
            return false;
        }
        
        if (computedChecksum != header->sha256Checksum) {
            error = StoreError::WithMessage(ThreatIntelError::InvalidChecksum,
                                            "Database SHA256 checksum mismatch");
            return false;
        }
    }
    
    error = StoreError::Success();
    return true;
}

// ----------------------------------------------------------------------------
// IPV4 ADDRESS PARSING
// ----------------------------------------------------------------------------

std::optional<IPv4Address> ParseIPv4(std::string_view str) noexcept {
    str = TrimWhitespace(str);
    
    if (str.empty() || str.length() > 18) {  // Max: "255.255.255.255/32"
        return std::nullopt;
    }
    
    // Check for CIDR notation
    uint8_t prefixLength = 32;
    size_t slashPos = str.find('/');
    std::string_view addrPart = str;
    
    if (slashPos != std::string_view::npos) {
        addrPart = str.substr(0, slashPos);
        std::string_view prefixPart = str.substr(slashPos + 1);
        
        if (prefixPart.empty() || prefixPart.length() > 2) {
            return std::nullopt;
        }
        
        // Parse prefix length
        int prefix = 0;
        auto result = std::from_chars(prefixPart.data(), 
                                      prefixPart.data() + prefixPart.length(),
                                      prefix);
        
        if (result.ec != std::errc() || result.ptr != prefixPart.data() + prefixPart.length()) {
            return std::nullopt;
        }
        
        if (prefix < 0 || prefix > 32) {
            return std::nullopt;
        }
        
        prefixLength = static_cast<uint8_t>(prefix);
    }
    
    // Parse IPv4 address octets
    uint8_t octets[4] = {0};
    size_t octetIndex = 0;
    size_t start = 0;
    
    for (size_t i = 0; i <= addrPart.length(); ++i) {
        if (i == addrPart.length() || addrPart[i] == '.') {
            if (octetIndex >= 4) {
                return std::nullopt;
            }
            
            std::string_view octetStr = addrPart.substr(start, i - start);
            if (octetStr.empty() || octetStr.length() > 3) {
                return std::nullopt;
            }
            
            // Check for leading zeros (not allowed except for "0")
            if (octetStr.length() > 1 && octetStr[0] == '0') {
                return std::nullopt;
            }
            
            int value = 0;
            auto result = std::from_chars(octetStr.data(),
                                          octetStr.data() + octetStr.length(),
                                          value);
            
            if (result.ec != std::errc() || result.ptr != octetStr.data() + octetStr.length()) {
                return std::nullopt;
            }
            
            if (value < 0 || value > 255) {
                return std::nullopt;
            }
            
            octets[octetIndex++] = static_cast<uint8_t>(value);
            start = i + 1;
        }
    }
    
    if (octetIndex != 4) {
        return std::nullopt;
    }
    
    return IPv4Address(octets[0], octets[1], octets[2], octets[3], prefixLength);
}

// ----------------------------------------------------------------------------
// IPV4 ADDRESS FORMATTING
// ----------------------------------------------------------------------------

std::string FormatIPv4(const IPv4Address& addr) {
    std::string result;
    result.reserve(18);  // Max: "255.255.255.255/32"
    
    // Format octets
    result += std::to_string((addr.address >> 24) & 0xFF);
    result += '.';
    result += std::to_string((addr.address >> 16) & 0xFF);
    result += '.';
    result += std::to_string((addr.address >> 8) & 0xFF);
    result += '.';
    result += std::to_string(addr.address & 0xFF);
    
    // Add CIDR notation if not /32
    if (addr.prefixLength != 32) {
        result += '/';
        result += std::to_string(addr.prefixLength);
    }
    
    return result;
}

// ----------------------------------------------------------------------------
// IPV6 ADDRESS PARSING
// ----------------------------------------------------------------------------

std::optional<IPv6Address> ParseIPv6(std::string_view str) noexcept {
    str = TrimWhitespace(str);
    
    if (str.empty() || str.length() > 43) {  // Max with CIDR
        return std::nullopt;
    }
    
    // Check for CIDR notation
    uint8_t prefixLength = 128;
    size_t slashPos = str.find('/');
    std::string_view addrPart = str;
    
    if (slashPos != std::string_view::npos) {
        addrPart = str.substr(0, slashPos);
        std::string_view prefixPart = str.substr(slashPos + 1);
        
        if (prefixPart.empty() || prefixPart.length() > 3) {
            return std::nullopt;
        }
        
        int prefix = 0;
        auto result = std::from_chars(prefixPart.data(),
                                      prefixPart.data() + prefixPart.length(),
                                      prefix);
        
        if (result.ec != std::errc() || result.ptr != prefixPart.data() + prefixPart.length()) {
            return std::nullopt;
        }
        
        if (prefix < 0 || prefix > 128) {
            return std::nullopt;
        }
        
        prefixLength = static_cast<uint8_t>(prefix);
    }
    
    // Use Windows API for IPv6 parsing (handles all edge cases)
    IN6_ADDR addr6{};
    std::string addrStr(addrPart);
    
    // Try parsing with inet_pton
    int result = inet_pton(AF_INET6, addrStr.c_str(), &addr6);
    if (result != 1) {
        return std::nullopt;
    }
    
    // Create IPv6Address from parsed bytes
    IPv6Address ipv6;
    std::memcpy(ipv6.address.data(), addr6.s6_addr, 16);
    ipv6.prefixLength = prefixLength;
    
    return ipv6;
}

// ----------------------------------------------------------------------------
// IPV6 ADDRESS FORMATTING
// ----------------------------------------------------------------------------

std::string FormatIPv6(const IPv6Address& addr) {
    // Use Windows API for formatting (handles zero compression)
    char buffer[INET6_ADDRSTRLEN + 4] = {0};  // +4 for /128
    
    IN6_ADDR addr6;
    std::memcpy(addr6.s6_addr, addr.address.data(), 16);
    
    const char* result = inet_ntop(AF_INET6, &addr6, buffer, INET6_ADDRSTRLEN);
    if (!result) {
        // Fallback to manual formatting
        std::string str;
        str.reserve(45);
        
        for (size_t i = 0; i < 16; i += 2) {
            if (i > 0) str += ':';
            uint16_t group = (static_cast<uint16_t>(addr.address[i]) << 8) | 
                             addr.address[i + 1];
            
            char hex[5];
            snprintf(hex, sizeof(hex), "%x", group);
            str += hex;
        }
        
        if (addr.prefixLength != 128) {
            str += '/';
            str += std::to_string(addr.prefixLength);
        }
        
        return str;
    }
    
    std::string formatted = buffer;
    
    // Add CIDR notation if not /128
    if (addr.prefixLength != 128) {
        formatted += '/';
        formatted += std::to_string(addr.prefixLength);
    }
    
    return formatted;
}

// ----------------------------------------------------------------------------
// HASH VALUE PARSING
// ----------------------------------------------------------------------------

std::optional<HashValue> ParseHashString(
    std::string_view hashStr,
    HashAlgorithm algo
) noexcept {
    hashStr = TrimWhitespace(hashStr);
    
    if (hashStr.empty()) {
        return std::nullopt;
    }
    
    // Get expected length for algorithm
    uint8_t expectedLength = GetHashLength(algo);
    if (expectedLength == 0) {
        return std::nullopt;
    }
    
    // For SSDEEP and TLSH, the string IS the hash (not hex encoded)
    if (algo == HashAlgorithm::SSDEEP || algo == HashAlgorithm::TLSH) {
        if (hashStr.length() > 72) {
            return std::nullopt;
        }
        
        HashValue hash;
        hash.algorithm = algo;
        hash.length = static_cast<uint8_t>(hashStr.length());
        std::memcpy(hash.data.data(), hashStr.data(), hashStr.length());
        
        return hash;
    }
    
    // For other algorithms, parse as hex string
    size_t expectedHexLength = static_cast<size_t>(expectedLength) * 2;
    
    // Handle "0x" prefix
    if (hashStr.length() >= 2 && hashStr[0] == '0' && 
        (hashStr[1] == 'x' || hashStr[1] == 'X')) {
        hashStr.remove_prefix(2);
    }
    
    if (hashStr.length() != expectedHexLength) {
        return std::nullopt;
    }
    
    // Validate all characters are hex
    for (char c : hashStr) {
        if (!IsHexDigit(c)) {
            return std::nullopt;
        }
    }
    
    // Parse hex string
    HashValue hash;
    hash.algorithm = algo;
    hash.length = expectedLength;
    
    size_t parsed = ParseHexString(hashStr, hash.data.data(), hash.data.size());
    if (parsed != expectedLength) {
        return std::nullopt;
    }
    
    return hash;
}

// ----------------------------------------------------------------------------
// HASH VALUE FORMATTING
// ----------------------------------------------------------------------------

std::string FormatHashString(const HashValue& hash) {
    if (hash.IsEmpty()) {
        return {};
    }
    
    // For SSDEEP and TLSH, return as-is (not hex encoded)
    if (hash.algorithm == HashAlgorithm::SSDEEP || 
        hash.algorithm == HashAlgorithm::TLSH) {
        return std::string(
            reinterpret_cast<const char*>(hash.data.data()),
            hash.length
        );
    }
    
    // For other algorithms, format as lowercase hex
    return FormatHexString(hash.data.data(), hash.length, false);
}

// ----------------------------------------------------------------------------
// DOMAIN NORMALIZATION
// ----------------------------------------------------------------------------

std::string NormalizeDomain(std::string_view domain) {
    domain = TrimWhitespace(domain);
    
    if (domain.empty()) {
        return {};
    }
    
    // Convert to lowercase
    std::string normalized = ToLowerCase(domain);
    
    // Remove trailing dot if present (FQDN notation)
    if (!normalized.empty() && normalized.back() == '.') {
        normalized.pop_back();
    }
    
    // Remove leading dot if present
    if (!normalized.empty() && normalized.front() == '.') {
        normalized.erase(0, 1);
    }
    
    // Remove any whitespace
    normalized.erase(
        std::remove_if(normalized.begin(), normalized.end(),
                       [](char c) { return std::isspace(static_cast<unsigned char>(c)); }),
        normalized.end()
    );
    
    return normalized;
}

// ----------------------------------------------------------------------------
// DOMAIN VALIDATION
// ----------------------------------------------------------------------------

bool IsValidDomain(std::string_view domain) noexcept {
    domain = TrimWhitespace(domain);
    
    // Check length limits
    if (domain.empty() || domain.length() > MAX_DOMAIN_LENGTH) {
        return false;
    }
    
    // Remove trailing dot if present
    if (domain.back() == '.') {
        domain.remove_suffix(1);
    }
    
    if (domain.empty()) {
        return false;
    }
    
    // Split into labels
    size_t labelStart = 0;
    size_t labelCount = 0;
    bool hasAlpha = false;
    
    for (size_t i = 0; i <= domain.length(); ++i) {
        if (i == domain.length() || domain[i] == '.') {
            std::string_view label = domain.substr(labelStart, i - labelStart);
            
            // Label length check (1-63 characters)
            if (label.empty() || label.length() > 63) {
                return false;
            }
            
            // Label cannot start or end with hyphen
            if (label.front() == '-' || label.back() == '-') {
                return false;
            }
            
            // Check valid characters in label
            for (char c : label) {
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '-')) {
                    // Allow underscore for some DNS records (e.g., DKIM)
                    if (c != '_') {
                        return false;
                    }
                }
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
                    hasAlpha = true;
                }
            }
            
            labelCount++;
            labelStart = i + 1;
        }
    }
    
    // Must have at least one label (though typically 2+ for valid domain)
    if (labelCount < 1) {
        return false;
    }
    
    // TLD should contain at least one letter (not all-numeric)
    // This helps reject IP addresses parsed as domains
    // Note: We already checked hasAlpha above
    
    return true;
}

// ----------------------------------------------------------------------------
// URL NORMALIZATION
// ----------------------------------------------------------------------------

std::string NormalizeURL(std::string_view url) {
    url = TrimWhitespace(url);
    
    if (url.empty()) {
        return {};
    }
    
    std::string normalized;
    normalized.reserve(url.length());
    
    // Find scheme
    size_t schemeEnd = url.find("://");
    std::string_view scheme;
    std::string_view rest;
    
    if (schemeEnd != std::string_view::npos) {
        scheme = url.substr(0, schemeEnd);
        rest = url.substr(schemeEnd + 3);
    } else {
        // No scheme, assume http
        scheme = "http";
        rest = url;
    }
    
    // Normalize scheme to lowercase
    for (char c : scheme) {
        normalized += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    normalized += "://";
    
    // Find host end (before path, query, or fragment)
    size_t hostEnd = rest.find_first_of("/?#");
    std::string_view host;
    std::string_view pathAndQuery;
    
    if (hostEnd != std::string_view::npos) {
        host = rest.substr(0, hostEnd);
        pathAndQuery = rest.substr(hostEnd);
    } else {
        host = rest;
    }
    
    // Handle userinfo (user:pass@)
    size_t atPos = host.find('@');
    std::string_view userinfo;
    std::string_view hostPort;
    
    if (atPos != std::string_view::npos) {
        userinfo = host.substr(0, atPos + 1);
        hostPort = host.substr(atPos + 1);
    } else {
        hostPort = host;
    }
    
    // Add userinfo as-is
    normalized += userinfo;
    
    // Find port
    size_t portPos = hostPort.rfind(':');
    std::string_view hostname;
    std::string_view port;
    
    // Handle IPv6 in brackets
    size_t bracketPos = hostPort.find(']');
    if (bracketPos != std::string_view::npos) {
        // IPv6 address in brackets
        if (portPos > bracketPos) {
            hostname = hostPort.substr(0, portPos);
            port = hostPort.substr(portPos);
        } else {
            hostname = hostPort;
        }
    } else if (portPos != std::string_view::npos) {
        hostname = hostPort.substr(0, portPos);
        port = hostPort.substr(portPos);
    } else {
        hostname = hostPort;
    }
    
    // Normalize hostname to lowercase
    for (char c : hostname) {
        normalized += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    
    // Remove default ports
    if (!port.empty()) {
        std::string_view portNum = port.substr(1);  // Skip ':'
        bool isDefaultPort = false;
        
        if ((scheme == "http" || scheme == "HTTP") && portNum == "80") {
            isDefaultPort = true;
        } else if ((scheme == "https" || scheme == "HTTPS") && portNum == "443") {
            isDefaultPort = true;
        } else if ((scheme == "ftp" || scheme == "FTP") && portNum == "21") {
            isDefaultPort = true;
        }
        
        if (!isDefaultPort) {
            normalized += port;
        }
    }
    
    // Add path and query as-is (case-sensitive)
    normalized += pathAndQuery;
    
    // Ensure path starts with /
    if (!pathAndQuery.empty() && pathAndQuery[0] != '/' && 
        pathAndQuery[0] != '?' && pathAndQuery[0] != '#') {
        // This shouldn't happen with valid URLs, but handle it
    }
    
    // If no path, add trailing slash for consistency (optional)
    // Some systems prefer this, others don't - leaving as-is
    
    return normalized;
}

// ----------------------------------------------------------------------------
// URL VALIDATION
// ----------------------------------------------------------------------------

bool IsValidURL(std::string_view url) noexcept {
    url = TrimWhitespace(url);
    
    if (url.empty() || url.length() > MAX_URL_LENGTH) {
        return false;
    }
    
    // Find scheme
    size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string_view::npos || schemeEnd == 0) {
        return false;
    }
    
    std::string_view scheme = url.substr(0, schemeEnd);
    
    // Validate scheme (must be alphanumeric, start with letter)
    if (scheme.empty()) {
        return false;
    }
    
    if (!std::isalpha(static_cast<unsigned char>(scheme[0]))) {
        return false;
    }
    
    for (char c : scheme) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '+' && c != '-' && c != '.') {
            return false;
        }
    }
    
    // Check for host after ://
    std::string_view rest = url.substr(schemeEnd + 3);
    if (rest.empty()) {
        return false;
    }
    
    // Find host end
    size_t hostEnd = rest.find_first_of("/?#");
    std::string_view host = (hostEnd != std::string_view::npos) 
                            ? rest.substr(0, hostEnd) 
                            : rest;
    
    // Remove userinfo
    size_t atPos = host.find('@');
    if (atPos != std::string_view::npos) {
        host = host.substr(atPos + 1);
    }
    
    // Remove port
    size_t bracketPos = host.find(']');
    size_t portPos = host.rfind(':');
    
    if (bracketPos == std::string_view::npos || portPos > bracketPos) {
        if (portPos != std::string_view::npos) {
            // Validate port is numeric
            std::string_view portStr = host.substr(portPos + 1);
            for (char c : portStr) {
                if (!std::isdigit(static_cast<unsigned char>(c))) {
                    return false;
                }
            }
            host = host.substr(0, portPos);
        }
    }
    
    // Host must not be empty
    if (host.empty()) {
        return false;
    }
    
    // Check if host is IPv6 (in brackets)
    if (host.front() == '[') {
        if (host.back() != ']' || host.length() < 4) {
            return false;
        }
        // Could add IPv6 validation here
        return true;
    }
    
    // Check if host is IPv4
    bool isIPv4 = true;
    int dotCount = 0;
    for (char c : host) {
        if (c == '.') {
            dotCount++;
        } else if (!std::isdigit(static_cast<unsigned char>(c))) {
            isIPv4 = false;
            break;
        }
    }
    
    if (isIPv4 && dotCount == 3) {
        // Validate as IPv4
        auto ipv4 = ParseIPv4(host);
        return ipv4.has_value();
    }
    
    // Validate as domain
    return IsValidDomain(host);
}

// ----------------------------------------------------------------------------
// EMAIL VALIDATION
// ----------------------------------------------------------------------------

bool IsValidEmail(std::string_view email) noexcept {
    email = TrimWhitespace(email);
    
    if (email.empty() || email.length() > MAX_EMAIL_LENGTH) {
        return false;
    }
    
    // Find @ symbol
    size_t atPos = email.find('@');
    if (atPos == std::string_view::npos || atPos == 0) {
        return false;
    }
    
    std::string_view localPart = email.substr(0, atPos);
    std::string_view domainPart = email.substr(atPos + 1);
    
    // Local part validation (simplified - RFC 5321)
    if (localPart.empty() || localPart.length() > 64) {
        return false;
    }
    
    // Check for consecutive dots
    bool prevDot = true;  // Treat start as dot for first char check
    for (char c : localPart) {
        if (c == '.') {
            if (prevDot) {
                return false;  // Consecutive dots or starts with dot
            }
            prevDot = true;
        } else {
            prevDot = false;
            // Allow alphanumeric and some special chars
            if (!std::isalnum(static_cast<unsigned char>(c)) &&
                c != '.' && c != '_' && c != '-' && c != '+' && c != '!' &&
                c != '#' && c != '$' && c != '%' && c != '&' && c != '\'' &&
                c != '*' && c != '/' && c != '=' && c != '?' && c != '^' &&
                c != '`' && c != '{' && c != '|' && c != '}' && c != '~') {
                return false;
            }
        }
    }
    
    // Cannot end with dot
    if (prevDot) {
        return false;
    }
    
    // Domain part validation
    if (domainPart.empty() || domainPart.length() > 255) {
        return false;
    }
    
    // Check if domain is IPv4 in brackets [1.2.3.4]
    if (domainPart.front() == '[' && domainPart.back() == ']') {
        std::string_view ip = domainPart.substr(1, domainPart.length() - 2);
        auto ipv4 = ParseIPv4(ip);
        return ipv4.has_value();
    }
    
    // Validate as domain
    return IsValidDomain(domainPart);
}

// ----------------------------------------------------------------------------
// BLOOM FILTER SIZE CALCULATION
// ----------------------------------------------------------------------------

size_t CalculateBloomFilterSize(
    size_t expectedElements,
    double falsePositiveRate
) noexcept {
    if (expectedElements == 0 || falsePositiveRate <= 0.0 || falsePositiveRate >= 1.0) {
        return 0;
    }
    
    // Optimal size formula: m = -n * ln(p) / (ln(2)^2)
    // Where:
    //   m = number of bits
    //   n = expected number of elements
    //   p = desired false positive rate
    
    constexpr double LN2_SQUARED = 0.480453013918201;  // ln(2)^2
    
    double m = -static_cast<double>(expectedElements) * std::log(falsePositiveRate) / LN2_SQUARED;
    
    // Round up to multiple of 64 (for cache-line alignment and atomic operations)
    size_t bits = static_cast<size_t>(std::ceil(m));
    bits = (bits + 63) & ~static_cast<size_t>(63);
    
    // Sanity check - don't exceed 4GB
    constexpr size_t MAX_BLOOM_BITS = 32ULL * 1024 * 1024 * 1024;
    if (bits > MAX_BLOOM_BITS) {
        bits = MAX_BLOOM_BITS;
    }
    
    return bits;
}

// ----------------------------------------------------------------------------
// BLOOM FILTER HASH FUNCTIONS CALCULATION
// ----------------------------------------------------------------------------

size_t CalculateBloomHashFunctions(
    size_t filterSize,
    size_t expectedElements
) noexcept {
    if (filterSize == 0 || expectedElements == 0) {
        return 0;
    }
    
    // Optimal number of hash functions: k = (m/n) * ln(2)
    // Where:
    //   k = number of hash functions
    //   m = number of bits
    //   n = expected number of elements
    
    constexpr double LN2 = 0.693147180559945;
    
    double k = (static_cast<double>(filterSize) / static_cast<double>(expectedElements)) * LN2;
    
    // Round to nearest integer, minimum 1
    size_t hashFunctions = static_cast<size_t>(std::round(k));
    if (hashFunctions < 1) {
        hashFunctions = 1;
    }
    
    // Practical limit - diminishing returns beyond 20
    if (hashFunctions > 20) {
        hashFunctions = 20;
    }
    
    return hashFunctions;
}

// ----------------------------------------------------------------------------
// OPTIMAL CACHE SIZE CALCULATION
// ----------------------------------------------------------------------------

uint32_t CalculateOptimalCacheSize(uint64_t dbSizeBytes) noexcept {
    // Heuristic: cache should be roughly 1-5% of database size
    // Minimum: 16MB, Maximum: 4GB
    
    constexpr uint64_t MIN_CACHE_MB = 16;
    constexpr uint64_t MAX_CACHE_MB = 4096;
    constexpr double CACHE_RATIO = 0.02;  // 2%
    
    uint64_t cacheMB = static_cast<uint64_t>(
        static_cast<double>(dbSizeBytes) * CACHE_RATIO / (1024 * 1024)
    );
    
    if (cacheMB < MIN_CACHE_MB) {
        cacheMB = MIN_CACHE_MB;
    }
    if (cacheMB > MAX_CACHE_MB) {
        cacheMB = MAX_CACHE_MB;
    }
    
    return static_cast<uint32_t>(cacheMB);
}

// ----------------------------------------------------------------------------
// STIX TIMESTAMP PARSING
// ----------------------------------------------------------------------------

std::optional<uint64_t> ParseSTIXTimestamp(std::string_view timestamp) noexcept {
    timestamp = TrimWhitespace(timestamp);
    
    // STIX 2.1 timestamp format: YYYY-MM-DDTHH:MM:SS.sssZ
    // Also accept: YYYY-MM-DDTHH:MM:SSZ
    //              YYYY-MM-DD HH:MM:SS
    //              YYYY-MM-DDTHH:MM:SS+00:00
    
    if (timestamp.length() < 19) {
        return std::nullopt;
    }
    
    // Parse year
    int year = 0;
    auto result = std::from_chars(timestamp.data(), timestamp.data() + 4, year);
    if (result.ec != std::errc() || result.ptr != timestamp.data() + 4) {
        return std::nullopt;
    }
    
    if (timestamp[4] != '-') return std::nullopt;
    
    // Parse month
    int month = 0;
    result = std::from_chars(timestamp.data() + 5, timestamp.data() + 7, month);
    if (result.ec != std::errc() || result.ptr != timestamp.data() + 7) {
        return std::nullopt;
    }
    
    if (timestamp[7] != '-') return std::nullopt;
    
    // Parse day
    int day = 0;
    result = std::from_chars(timestamp.data() + 8, timestamp.data() + 10, day);
    if (result.ec != std::errc() || result.ptr != timestamp.data() + 10) {
        return std::nullopt;
    }
    
    // Accept 'T' or space as date/time separator
    if (timestamp[10] != 'T' && timestamp[10] != ' ') return std::nullopt;
    
    // Parse hour
    int hour = 0;
    result = std::from_chars(timestamp.data() + 11, timestamp.data() + 13, hour);
    if (result.ec != std::errc() || result.ptr != timestamp.data() + 13) {
        return std::nullopt;
    }
    
    if (timestamp[13] != ':') return std::nullopt;
    
    // Parse minute
    int minute = 0;
    result = std::from_chars(timestamp.data() + 14, timestamp.data() + 16, minute);
    if (result.ec != std::errc() || result.ptr != timestamp.data() + 16) {
        return std::nullopt;
    }
    
    if (timestamp[16] != ':') return std::nullopt;
    
    // Parse second
    int second = 0;
    result = std::from_chars(timestamp.data() + 17, timestamp.data() + 19, second);
    if (result.ec != std::errc() || result.ptr != timestamp.data() + 19) {
        return std::nullopt;
    }
    
    // Validate ranges
    if (year < 1970 || year > 2100) return std::nullopt;
    if (month < 1 || month > 12) return std::nullopt;
    if (day < 1 || day > 31) return std::nullopt;
    if (hour < 0 || hour > 23) return std::nullopt;
    if (minute < 0 || minute > 59) return std::nullopt;
    if (second < 0 || second > 60) return std::nullopt;  // 60 for leap seconds
    
    // Convert to Unix epoch
    std::tm tm{};
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;
    tm.tm_isdst = 0;
    
    // Use _mkgmtime on Windows for UTC
#ifdef _WIN32
    time_t epoch = _mkgmtime(&tm);
#else
    time_t epoch = timegm(&tm);
#endif
    
    if (epoch == -1) {
        return std::nullopt;
    }
    
    return static_cast<uint64_t>(epoch);
}

// ----------------------------------------------------------------------------
// STIX TIMESTAMP FORMATTING
// ----------------------------------------------------------------------------

std::string FormatSTIXTimestamp(uint64_t epoch) {
    time_t time = static_cast<time_t>(epoch);
    std::tm tm{};
    
#ifdef _WIN32
    gmtime_s(&tm, &time);
#else
    gmtime_r(&time, &tm);
#endif
    
    // Format: YYYY-MM-DDTHH:MM:SS.000Z
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer),
                  "%04d-%02d-%02dT%02d:%02d:%02d.000Z",
                  tm.tm_year + 1900,
                  tm.tm_mon + 1,
                  tm.tm_mday,
                  tm.tm_hour,
                  tm.tm_min,
                  tm.tm_sec);
    
    return buffer;
}

// ----------------------------------------------------------------------------
// UUID GENERATION (Version 4 - Random)
// ----------------------------------------------------------------------------

std::array<uint8_t, 16> GenerateUUID() noexcept {
    std::array<uint8_t, 16> uuid;
    
    // Generate random bytes
    std::uniform_int_distribution<uint32_t> dist(0, 255);
    
    for (size_t i = 0; i < 16; ++i) {
        uuid[i] = static_cast<uint8_t>(dist(g_randomEngine));
    }
    
    // Set version (4 = random)
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    
    // Set variant (RFC 4122)
    uuid[8] = (uuid[8] & 0x3F) | 0x80;
    
    return uuid;
}

// ----------------------------------------------------------------------------
// UUID FORMATTING
// ----------------------------------------------------------------------------

std::string FormatUUID(const std::array<uint8_t, 16>& uuid) {
    // Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    char buffer[37];
    
    std::snprintf(buffer, sizeof(buffer),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  uuid[0], uuid[1], uuid[2], uuid[3],
                  uuid[4], uuid[5],
                  uuid[6], uuid[7],
                  uuid[8], uuid[9],
                  uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
    
    return buffer;
}

// ----------------------------------------------------------------------------
// UUID PARSING
// ----------------------------------------------------------------------------

std::optional<std::array<uint8_t, 16>> ParseUUID(std::string_view str) noexcept {
    str = TrimWhitespace(str);
    
    // Accept both with and without hyphens
    // With hyphens: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
    // Without: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (32 chars)
    
    std::array<uint8_t, 16> uuid;
    size_t byteIndex = 0;
    size_t charIndex = 0;
    
    while (byteIndex < 16 && charIndex < str.length()) {
        // Skip hyphens
        if (str[charIndex] == '-') {
            charIndex++;
            continue;
        }
        
        // Need at least 2 characters for a byte
        if (charIndex + 1 >= str.length()) {
            return std::nullopt;
        }
        
        int high = HexCharToNibble(str[charIndex]);
        int low = HexCharToNibble(str[charIndex + 1]);
        
        if (high < 0 || low < 0) {
            return std::nullopt;
        }
        
        uuid[byteIndex++] = static_cast<uint8_t>((high << 4) | low);
        charIndex += 2;
    }
    
    // Must have parsed exactly 16 bytes
    if (byteIndex != 16) {
        return std::nullopt;
    }
    
    // Must have consumed all non-hyphen characters
    while (charIndex < str.length()) {
        if (str[charIndex] != '-') {
            return std::nullopt;
        }
        charIndex++;
    }
    
    return uuid;
}

// ============================================================================
// PART 2/3 COMPLETE - Domain/URL/Email validation, STIX, UUID, Bloom calculations
// ============================================================================

} // namespace Format

// ============================================================================
// MEMORY MAPPING NAMESPACE IMPLEMENTATION
// ============================================================================

namespace MemoryMapping {

// ----------------------------------------------------------------------------
// OPEN MEMORY-MAPPED VIEW
// ----------------------------------------------------------------------------

bool OpenView(
    const std::wstring& path,
    bool readOnly,
    MemoryMappedView& view,
    StoreError& error
) noexcept {
    // Close any existing mapping first
    CloseView(view);
    
    // Validate path
    if (path.empty()) {
        error = StoreError::WithMessage(ThreatIntelError::FileNotFound,
                                        "Empty file path");
        return false;
    }
    
    // Open file with appropriate access
    DWORD desiredAccess = readOnly ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
    DWORD shareMode = readOnly ? FILE_SHARE_READ : 0;
    DWORD creationDisposition = OPEN_EXISTING;
    
    HANDLE fileHandle = CreateFileW(
        path.c_str(),
        desiredAccess,
        shareMode,
        nullptr,  // Security attributes
        creationDisposition,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
        nullptr   // Template file
    );
    
    if (fileHandle == INVALID_HANDLE_VALUE) {
        DWORD win32Error = GetLastError();
        
        if (win32Error == ERROR_FILE_NOT_FOUND || win32Error == ERROR_PATH_NOT_FOUND) {
            error = StoreError::FromWin32(ThreatIntelError::FileNotFound, win32Error);
        } else if (win32Error == ERROR_ACCESS_DENIED) {
            error = StoreError::FromWin32(ThreatIntelError::FileAccessDenied, win32Error);
        } else if (win32Error == ERROR_SHARING_VIOLATION) {
            error = StoreError::FromWin32(ThreatIntelError::FileLocked, win32Error);
        } else {
            error = StoreError::FromWin32(ThreatIntelError::FileReadError, win32Error);
        }
        error.context = "CreateFileW failed";
        return false;
    }
    
    // Get file size
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(fileHandle, &fileSize)) {
        DWORD win32Error = GetLastError();
        CloseHandle(fileHandle);
        error = StoreError::FromWin32(ThreatIntelError::FileReadError, win32Error);
        error.context = "GetFileSizeEx failed";
        return false;
    }
    
    // Validate minimum size (must contain at least header)
    if (fileSize.QuadPart < static_cast<LONGLONG>(sizeof(ThreatIntelDatabaseHeader))) {
        CloseHandle(fileHandle);
        error = StoreError::WithMessage(ThreatIntelError::InvalidHeader,
                                        "File too small for header");
        return false;
    }
    
    // Create file mapping
    DWORD protect = readOnly ? PAGE_READONLY : PAGE_READWRITE;
    
    HANDLE mappingHandle = CreateFileMappingW(
        fileHandle,
        nullptr,  // Security attributes
        protect,
        0,        // Maximum size high (0 = use file size)
        0,        // Maximum size low (0 = use file size)
        nullptr   // Mapping name (anonymous)
    );
    
    if (mappingHandle == nullptr) {
        DWORD win32Error = GetLastError();
        CloseHandle(fileHandle);
        error = StoreError::FromWin32(ThreatIntelError::MappingFailed, win32Error);
        error.context = "CreateFileMappingW failed";
        return false;
    }
    
    // Map view of file
    DWORD mapAccess = readOnly ? FILE_MAP_READ : FILE_MAP_ALL_ACCESS;
    
    void* baseAddress = MapViewOfFile(
        mappingHandle,
        mapAccess,
        0,        // Offset high
        0,        // Offset low
        0         // Size (0 = entire file)
    );
    
    if (baseAddress == nullptr) {
        DWORD win32Error = GetLastError();
        CloseHandle(mappingHandle);
        CloseHandle(fileHandle);
        
        if (win32Error == ERROR_NOT_ENOUGH_MEMORY) {
            error = StoreError::FromWin32(ThreatIntelError::OutOfMemory, win32Error);
        } else {
            error = StoreError::FromWin32(ThreatIntelError::MappingFailed, win32Error);
        }
        error.context = "MapViewOfFile failed";
        return false;
    }
    
    // Lock critical pages in memory for performance (optional, ignore failure)
    // This helps prevent page faults during critical lookups
    VirtualLock(baseAddress, std::min<SIZE_T>(
        static_cast<SIZE_T>(fileSize.QuadPart),
        64 * 1024 * 1024  // Lock up to 64MB
    ));
    
    // Populate view structure
    view.fileHandle = fileHandle;
    view.mappingHandle = mappingHandle;
    view.baseAddress = baseAddress;
    view.fileSize = static_cast<uint64_t>(fileSize.QuadPart);
    view.readOnly = readOnly;
    
    error = StoreError::Success();
    return true;
}

// ----------------------------------------------------------------------------
// CREATE NEW DATABASE FILE
// ----------------------------------------------------------------------------

bool CreateDatabase(
    const std::wstring& path,
    uint64_t initialSize,
    MemoryMappedView& view,
    StoreError& error
) noexcept {
    // Close any existing mapping first
    CloseView(view);
    
    // Validate path
    if (path.empty()) {
        error = StoreError::WithMessage(ThreatIntelError::FileNotFound,
                                        "Empty file path");
        return false;
    }
    
    // Validate initial size
    if (initialSize < sizeof(ThreatIntelDatabaseHeader)) {
        initialSize = sizeof(ThreatIntelDatabaseHeader);
    }
    
    // Align to page boundary
    initialSize = Format::AlignToPage(initialSize);
    
    // Ensure minimum reasonable size (at least 1MB)
    if (initialSize < 1024 * 1024) {
        initialSize = 1024 * 1024;
    }
    
    // Check maximum size
    if (initialSize > MAX_DATABASE_SIZE) {
        error = StoreError::WithMessage(ThreatIntelError::DatabaseTooLarge,
                                        "Initial size exceeds maximum");
        return false;
    }
    
    // Create file (fail if exists)
    HANDLE fileHandle = CreateFileW(
        path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,        // No sharing
        nullptr,  // Security attributes
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_WRITE_THROUGH,
        nullptr   // Template file
    );
    
    if (fileHandle == INVALID_HANDLE_VALUE) {
        DWORD win32Error = GetLastError();
        
        if (win32Error == ERROR_FILE_EXISTS || win32Error == ERROR_ALREADY_EXISTS) {
            error = StoreError::WithMessage(ThreatIntelError::DuplicateEntry,
                                            "Database file already exists");
        } else if (win32Error == ERROR_ACCESS_DENIED) {
            error = StoreError::FromWin32(ThreatIntelError::FileAccessDenied, win32Error);
        } else if (win32Error == ERROR_PATH_NOT_FOUND) {
            error = StoreError::FromWin32(ThreatIntelError::FileNotFound, win32Error);
            error.message = "Directory does not exist";
        } else {
            error = StoreError::FromWin32(ThreatIntelError::FileWriteError, win32Error);
        }
        error.context = "CreateFileW failed";
        return false;
    }
    
    // Set file size
    LARGE_INTEGER newSize;
    newSize.QuadPart = static_cast<LONGLONG>(initialSize);
    
    if (!SetFilePointerEx(fileHandle, newSize, nullptr, FILE_BEGIN)) {
        DWORD win32Error = GetLastError();
        CloseHandle(fileHandle);
        DeleteFileW(path.c_str());  // Clean up
        error = StoreError::FromWin32(ThreatIntelError::FileWriteError, win32Error);
        error.context = "SetFilePointerEx failed";
        return false;
    }
    
    if (!SetEndOfFile(fileHandle)) {
        DWORD win32Error = GetLastError();
        CloseHandle(fileHandle);
        DeleteFileW(path.c_str());  // Clean up
        
        if (win32Error == ERROR_DISK_FULL) {
            error = StoreError::FromWin32(ThreatIntelError::DiskFull, win32Error);
        } else {
            error = StoreError::FromWin32(ThreatIntelError::FileWriteError, win32Error);
        }
        error.context = "SetEndOfFile failed";
        return false;
    }
    
    // Create file mapping
    HANDLE mappingHandle = CreateFileMappingW(
        fileHandle,
        nullptr,
        PAGE_READWRITE,
        static_cast<DWORD>(initialSize >> 32),
        static_cast<DWORD>(initialSize & 0xFFFFFFFF),
        nullptr
    );
    
    if (mappingHandle == nullptr) {
        DWORD win32Error = GetLastError();
        CloseHandle(fileHandle);
        DeleteFileW(path.c_str());  // Clean up
        error = StoreError::FromWin32(ThreatIntelError::MappingFailed, win32Error);
        error.context = "CreateFileMappingW failed";
        return false;
    }
    
    // Map view
    void* baseAddress = MapViewOfFile(
        mappingHandle,
        FILE_MAP_ALL_ACCESS,
        0, 0, 0
    );
    
    if (baseAddress == nullptr) {
        DWORD win32Error = GetLastError();
        CloseHandle(mappingHandle);
        CloseHandle(fileHandle);
        DeleteFileW(path.c_str());  // Clean up
        error = StoreError::FromWin32(ThreatIntelError::MappingFailed, win32Error);
        error.context = "MapViewOfFile failed";
        return false;
    }
    
    // Zero-initialize the mapped memory
    SecureZeroMemory(baseAddress, static_cast<SIZE_T>(initialSize));
    
    // Initialize header
    auto* header = static_cast<ThreatIntelDatabaseHeader*>(baseAddress);
    
    header->magic = THREATINTEL_DB_MAGIC;
    header->versionMajor = THREATINTEL_DB_VERSION_MAJOR;
    header->versionMinor = THREATINTEL_DB_VERSION_MINOR;
    
    // Generate database UUID
    header->databaseUuid = Format::GenerateUUID();
    
    // Set timestamps
    auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
    header->creationTime = now;
    header->lastUpdateTime = now;
    header->buildNumber = 1;
    
    // Set file size
    header->totalFileSize = initialSize;
    
    // Initialize section offsets (all start after header)
    // For a new empty database, we just allocate minimal space for each section
    uint64_t currentOffset = PAGE_SIZE;  // After header
    
    // IPv4 index - allocate 1 page initially
    header->ipv4IndexOffset = currentOffset;
    header->ipv4IndexSize = PAGE_SIZE;
    currentOffset += PAGE_SIZE;
    
    // IPv6 index
    header->ipv6IndexOffset = currentOffset;
    header->ipv6IndexSize = PAGE_SIZE;
    currentOffset += PAGE_SIZE;
    
    // Domain index
    header->domainIndexOffset = currentOffset;
    header->domainIndexSize = PAGE_SIZE;
    currentOffset += PAGE_SIZE;
    
    // URL index
    header->urlIndexOffset = currentOffset;
    header->urlIndexSize = PAGE_SIZE;
    currentOffset += PAGE_SIZE;
    
    // Hash index
    header->hashIndexOffset = currentOffset;
    header->hashIndexSize = PAGE_SIZE;
    currentOffset += PAGE_SIZE;
    
    // Email index
    header->emailIndexOffset = currentOffset;
    header->emailIndexSize = PAGE_SIZE;
    currentOffset += PAGE_SIZE;
    
    // Certificate index
    header->certIndexOffset = currentOffset;
    header->certIndexSize = PAGE_SIZE;
    currentOffset += PAGE_SIZE;
    
    // JA3 index
    header->ja3IndexOffset = currentOffset;
    header->ja3IndexSize = PAGE_SIZE;
    currentOffset += PAGE_SIZE;
    
    // Entry data section (bulk of the file)
    header->entryDataOffset = currentOffset;
    header->entryDataSize = (initialSize - currentOffset) / 2;
    header->entryDataSize = Format::AlignToPage(header->entryDataSize);
    currentOffset += header->entryDataSize;
    
    // Compact entry section
    header->compactEntryOffset = currentOffset;
    header->compactEntrySize = PAGE_SIZE * 16;  // 64KB
    currentOffset += header->compactEntrySize;
    
    // String pool
    header->stringPoolOffset = currentOffset;
    header->stringPoolSize = PAGE_SIZE * 64;  // 256KB
    currentOffset += header->stringPoolSize;
    
    // Bloom filter
    header->bloomFilterOffset = currentOffset;
    header->bloomFilterSize = PAGE_SIZE * 256;  // 1MB
    currentOffset += header->bloomFilterSize;
    
    // STIX bundle
    header->stixBundleOffset = currentOffset;
    header->stixBundleSize = PAGE_SIZE * 16;  // 64KB
    currentOffset += header->stixBundleSize;
    
    // Feed config
    header->feedConfigOffset = currentOffset;
    header->feedConfigSize = PAGE_SIZE * 4;  // 16KB
    currentOffset += header->feedConfigSize;
    
    // Metadata
    header->metadataOffset = currentOffset;
    header->metadataSize = PAGE_SIZE * 4;  // 16KB
    currentOffset += header->metadataSize;
    
    // Relation graph
    header->relationGraphOffset = currentOffset;
    header->relationGraphSize = initialSize - currentOffset;  // Rest of file
    
    // Performance hints
    header->recommendedCacheSize = 64;  // 64MB
    header->bloomExpectedElements = 100000;
    header->bloomFalsePositiveRate = 1000;  // 0.1% (scaled by 1M = 1000)
    header->defaultTimeoutMs = 1000;
    header->memoryBudgetMB = 256;
    
    // Compute and store header CRC32
    header->headerCrc32 = Format::ComputeHeaderCRC32(header);
    
    // Flush header to disk
    if (!FlushViewOfFile(baseAddress, sizeof(ThreatIntelDatabaseHeader))) {
        DWORD win32Error = GetLastError();
        UnmapViewOfFile(baseAddress);
        CloseHandle(mappingHandle);
        CloseHandle(fileHandle);
        DeleteFileW(path.c_str());
        error = StoreError::FromWin32(ThreatIntelError::FileWriteError, win32Error);
        error.context = "FlushViewOfFile failed";
        return false;
    }
    
    // Populate view structure
    view.fileHandle = fileHandle;
    view.mappingHandle = mappingHandle;
    view.baseAddress = baseAddress;
    view.fileSize = initialSize;
    view.readOnly = false;
    
    error = StoreError::Success();
    return true;
}

// ----------------------------------------------------------------------------
// CLOSE MEMORY-MAPPED VIEW
// ----------------------------------------------------------------------------

void CloseView(MemoryMappedView& view) noexcept {
    // Unmap view
    if (view.baseAddress != nullptr) {
        // Unlock memory (ignore errors)
        VirtualUnlock(view.baseAddress, static_cast<SIZE_T>(
            std::min<uint64_t>(view.fileSize, 64 * 1024 * 1024)
        ));
        
        // Flush if writable
        if (!view.readOnly) {
            FlushViewOfFile(view.baseAddress, 0);
        }
        
        UnmapViewOfFile(view.baseAddress);
        view.baseAddress = nullptr;
    }
    
    // Close mapping handle
    if (view.mappingHandle != nullptr && view.mappingHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(view.mappingHandle);
        view.mappingHandle = nullptr;
    }
    
    // Close file handle
    if (view.fileHandle != INVALID_HANDLE_VALUE) {
        // Flush file buffers before closing
        if (!view.readOnly) {
            FlushFileBuffers(view.fileHandle);
        }
        CloseHandle(view.fileHandle);
        view.fileHandle = INVALID_HANDLE_VALUE;
    }
    
    // Reset other fields
    view.fileSize = 0;
    view.readOnly = true;
}

// ----------------------------------------------------------------------------
// FLUSH VIEW TO DISK
// ----------------------------------------------------------------------------

bool FlushView(
    MemoryMappedView& view,
    StoreError& error
) noexcept {
    if (!view.IsValid()) {
        error = StoreError::WithMessage(ThreatIntelError::NotInitialized,
                                        "View not initialized");
        return false;
    }
    
    if (view.readOnly) {
        // Nothing to flush for read-only view
        error = StoreError::Success();
        return true;
    }
    
    // Flush memory-mapped view
    if (!FlushViewOfFile(view.baseAddress, 0)) {
        DWORD win32Error = GetLastError();
        error = StoreError::FromWin32(ThreatIntelError::FileWriteError, win32Error);
        error.context = "FlushViewOfFile failed";
        return false;
    }
    
    // Flush file buffers to ensure data hits disk
    if (!FlushFileBuffers(view.fileHandle)) {
        DWORD win32Error = GetLastError();
        error = StoreError::FromWin32(ThreatIntelError::FileWriteError, win32Error);
        error.context = "FlushFileBuffers failed";
        return false;
    }
    
    error = StoreError::Success();
    return true;
}

// ----------------------------------------------------------------------------
// EXTEND DATABASE FILE SIZE
// ----------------------------------------------------------------------------

bool ExtendDatabase(
    MemoryMappedView& view,
    uint64_t newSize,
    StoreError& error
) noexcept {
    if (!view.IsValid()) {
        error = StoreError::WithMessage(ThreatIntelError::NotInitialized,
                                        "View not initialized");
        return false;
    }
    
    if (view.readOnly) {
        error = StoreError::WithMessage(ThreatIntelError::ReadOnlyDatabase,
                                        "Cannot extend read-only database");
        return false;
    }
    
    // Validate new size
    if (newSize <= view.fileSize) {
        error = StoreError::WithMessage(ThreatIntelError::InvalidEntry,
                                        "New size must be larger than current size");
        return false;
    }
    
    // Align to page boundary
    newSize = Format::AlignToPage(newSize);
    
    // Check maximum size
    if (newSize > MAX_DATABASE_SIZE) {
        error = StoreError::WithMessage(ThreatIntelError::DatabaseTooLarge,
                                        "New size exceeds maximum");
        return false;
    }
    
    // Flush current view before remapping
    if (!FlushViewOfFile(view.baseAddress, 0)) {
        DWORD win32Error = GetLastError();
        error = StoreError::FromWin32(ThreatIntelError::FileWriteError, win32Error);
        error.context = "FlushViewOfFile before extend failed";
        return false;
    }
    
    // Unmap current view
    VirtualUnlock(view.baseAddress, static_cast<SIZE_T>(
        std::min<uint64_t>(view.fileSize, 64 * 1024 * 1024)
    ));
    
    if (!UnmapViewOfFile(view.baseAddress)) {
        DWORD win32Error = GetLastError();
        error = StoreError::FromWin32(ThreatIntelError::MappingFailed, win32Error);
        error.context = "UnmapViewOfFile failed";
        return false;
    }
    view.baseAddress = nullptr;
    
    // Close current mapping
    if (view.mappingHandle != nullptr) {
        CloseHandle(view.mappingHandle);
        view.mappingHandle = nullptr;
    }
    
    // Extend file
    LARGE_INTEGER newFileSize;
    newFileSize.QuadPart = static_cast<LONGLONG>(newSize);
    
    if (!SetFilePointerEx(view.fileHandle, newFileSize, nullptr, FILE_BEGIN)) {
        DWORD win32Error = GetLastError();
        error = StoreError::FromWin32(ThreatIntelError::FileWriteError, win32Error);
        error.context = "SetFilePointerEx failed";
        // Try to recover by remapping original size
        RemapView(view, error);
        return false;
    }
    
    if (!SetEndOfFile(view.fileHandle)) {
        DWORD win32Error = GetLastError();
        
        if (win32Error == ERROR_DISK_FULL) {
            error = StoreError::FromWin32(ThreatIntelError::DiskFull, win32Error);
        } else {
            error = StoreError::FromWin32(ThreatIntelError::FileWriteError, win32Error);
        }
        error.context = "SetEndOfFile failed";
        
        // Try to recover by remapping original size
        RemapView(view, error);
        return false;
    }
    
    // Update file size in view
    uint64_t oldSize = view.fileSize;
    view.fileSize = newSize;
    
    // Remap with new size
    if (!RemapView(view, error)) {
        // Failed to remap - view is in invalid state
        view.fileSize = oldSize;  // Restore old size for potential recovery
        return false;
    }
    
    // Zero-initialize new space
    if (view.baseAddress != nullptr && newSize > oldSize) {
        void* newSpace = static_cast<uint8_t*>(view.baseAddress) + oldSize;
        SIZE_T newSpaceSize = static_cast<SIZE_T>(newSize - oldSize);
        SecureZeroMemory(newSpace, newSpaceSize);
    }
    
    // Update header with new file size
    auto* header = static_cast<ThreatIntelDatabaseHeader*>(view.baseAddress);
    if (header != nullptr) {
        header->totalFileSize = newSize;
        header->lastUpdateTime = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
        header->headerCrc32 = Format::ComputeHeaderCRC32(header);
    }
    
    error = StoreError::Success();
    return true;
}

// ----------------------------------------------------------------------------
// REMAP VIEW (After extension or recovery)
// ----------------------------------------------------------------------------

bool RemapView(
    MemoryMappedView& view,
    StoreError& error
) noexcept {
    if (view.fileHandle == INVALID_HANDLE_VALUE) {
        error = StoreError::WithMessage(ThreatIntelError::NotInitialized,
                                        "File handle is invalid");
        return false;
    }
    
    // Close existing mapping if any
    if (view.baseAddress != nullptr) {
        UnmapViewOfFile(view.baseAddress);
        view.baseAddress = nullptr;
    }
    
    if (view.mappingHandle != nullptr) {
        CloseHandle(view.mappingHandle);
        view.mappingHandle = nullptr;
    }
    
    // Get current file size if not set
    if (view.fileSize == 0) {
        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(view.fileHandle, &fileSize)) {
            DWORD win32Error = GetLastError();
            error = StoreError::FromWin32(ThreatIntelError::FileReadError, win32Error);
            error.context = "GetFileSizeEx failed";
            return false;
        }
        view.fileSize = static_cast<uint64_t>(fileSize.QuadPart);
    }
    
    // Create new mapping
    DWORD protect = view.readOnly ? PAGE_READONLY : PAGE_READWRITE;
    
    view.mappingHandle = CreateFileMappingW(
        view.fileHandle,
        nullptr,
        protect,
        static_cast<DWORD>(view.fileSize >> 32),
        static_cast<DWORD>(view.fileSize & 0xFFFFFFFF),
        nullptr
    );
    
    if (view.mappingHandle == nullptr) {
        DWORD win32Error = GetLastError();
        error = StoreError::FromWin32(ThreatIntelError::MappingFailed, win32Error);
        error.context = "CreateFileMappingW in RemapView failed";
        return false;
    }
    
    // Map view
    DWORD mapAccess = view.readOnly ? FILE_MAP_READ : FILE_MAP_ALL_ACCESS;
    
    view.baseAddress = MapViewOfFile(
        view.mappingHandle,
        mapAccess,
        0, 0, 0
    );
    
    if (view.baseAddress == nullptr) {
        DWORD win32Error = GetLastError();
        CloseHandle(view.mappingHandle);
        view.mappingHandle = nullptr;
        
        if (win32Error == ERROR_NOT_ENOUGH_MEMORY) {
            error = StoreError::FromWin32(ThreatIntelError::OutOfMemory, win32Error);
        } else {
            error = StoreError::FromWin32(ThreatIntelError::MappingFailed, win32Error);
        }
        error.context = "MapViewOfFile in RemapView failed";
        return false;
    }
    
    // Lock critical pages
    VirtualLock(view.baseAddress, std::min<SIZE_T>(
        static_cast<SIZE_T>(view.fileSize),
        64 * 1024 * 1024
    ));
    
    error = StoreError::Success();
    return true;
}

} // namespace MemoryMapping

// ============================================================================
// PART 3/3 COMPLETE - Memory-mapped file operations
// ============================================================================

} // namespace ThreatIntel
} // namespace ShadowStrike
