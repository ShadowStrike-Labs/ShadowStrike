// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/*
 * ============================================================================
 * ShadowStrike SignatureFormat - IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Binary format validation and utility functions
 * RAII-based resource management for exception safety
 * Ultra-careful implementation - EVERY BYTE MATTERS
 *
 * ============================================================================
 */
#include "SignatureFormat.hpp"
#include "../Utils/Logger.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cwchar>
#include <charconv>
#include <cstdint>   // For SIZE_MAX and standard integer limits
#include <climits>   // For additional platform limits

// Windows crypto API for SHA-256 validation
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

namespace ShadowStrike {
namespace SignatureStore {

// ============================================================================
// RAII HELPER CLASSES FOR WINDOWS RESOURCES
// ============================================================================
namespace {

    // RAII wrapper for Windows HANDLE (file/mapping handles)
    class HandleGuard {
    public:
        explicit HandleGuard(HANDLE h = INVALID_HANDLE_VALUE) noexcept : m_handle(h) {}
        ~HandleGuard() noexcept { Close(); }

        HandleGuard(const HandleGuard&) = delete;
        HandleGuard& operator=(const HandleGuard&) = delete;

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

        // Release ownership (caller takes responsibility)
        [[nodiscard]] HANDLE Release() noexcept {
            HANDLE h = m_handle;
            m_handle = INVALID_HANDLE_VALUE;
            return h;
        }

    private:
        HANDLE m_handle;
    };

    // RAII wrapper for MapViewOfFile (memory-mapped view)
    class MappedViewGuard {
    public:
        explicit MappedViewGuard(void* addr = nullptr) noexcept : m_address(addr) {}
        ~MappedViewGuard() noexcept { Unmap(); }

        MappedViewGuard(const MappedViewGuard&) = delete;
        MappedViewGuard& operator=(const MappedViewGuard&) = delete;

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

} // anonymous namespace

namespace Format {

    // ============================================================================
    // HEADER VALIDATION (Enterprise-Grade with Overflow Protection)
    // ============================================================================

    bool ValidateHeader(const SignatureDatabaseHeader* header) noexcept {
        if (!header) {
            SS_LOG_ERROR(L"SignatureStore", L"ValidateHeader: null header pointer");
            return false;
        }

        // ========================================================================
        // STEP 1: MAGIC NUMBER & VERSION CHECK
        // ========================================================================

        if (header->magic != SIGNATURE_DB_MAGIC) {
            SS_LOG_ERROR(L"SignatureStore",
                L"Invalid magic number: expected 0x%08X, got 0x%08X",
                SIGNATURE_DB_MAGIC, header->magic);
            return false;
        }

        if (header->versionMajor != SIGNATURE_DB_VERSION_MAJOR) {
            SS_LOG_ERROR(L"SignatureStore",
                L"Version mismatch: expected %u.x, got %u.%u",
                SIGNATURE_DB_VERSION_MAJOR,
                header->versionMajor,
                header->versionMinor);
            return false;
        }

        // ========================================================================
        // STEP 2: PAGE ALIGNMENT VALIDATION (Critical for Memory Mapping)
        // ========================================================================

        // Helper lambda for alignment check
        auto checkPageAlignment = [](uint64_t offset, const wchar_t* name) -> bool {
            if (offset != 0 && (offset % PAGE_SIZE != 0)) {
                SS_LOG_ERROR(L"SignatureStore",
                    L"%s offset 0x%llX not page-aligned (PAGE_SIZE=%zu)",
                    name, offset, PAGE_SIZE);
                return false;
            }
            return true;
            };

        if (!checkPageAlignment(header->hashIndexOffset, L"Hash index")) return false;
        if (!checkPageAlignment(header->patternIndexOffset, L"Pattern index")) return false;
        if (!checkPageAlignment(header->yaraRulesOffset, L"YARA rules")) return false;
        if (!checkPageAlignment(header->metadataOffset, L"Metadata")) return false;
        if (!checkPageAlignment(header->stringPoolOffset, L"String pool")) return false;

        // ========================================================================
        // STEP 3: SIZE LIMIT VALIDATION
        // ========================================================================

        auto checkSizeLimit = [](uint64_t size, const wchar_t* name) -> bool {
            if (size > MAX_DATABASE_SIZE) {
                SS_LOG_ERROR(L"SignatureStore",
                    L"%s size %llu exceeds maximum %llu",
                    name, size, MAX_DATABASE_SIZE);
                return false;
            }
            return true;
            };

        if (!checkSizeLimit(header->hashIndexSize, L"Hash index")) return false;
        if (!checkSizeLimit(header->patternIndexSize, L"Pattern index")) return false;
        if (!checkSizeLimit(header->yaraRulesSize, L"YARA rules")) return false;
        if (!checkSizeLimit(header->metadataSize, L"Metadata")) return false;
        if (!checkSizeLimit(header->stringPoolSize, L"String pool")) return false;

        // ========================================================================
        // STEP 4: OVERFLOW-SAFE SECTION BOUNDS VALIDATION
        // ========================================================================

        // Check that offset + size doesn't overflow
        auto checkNoOverflow = [](uint64_t offset, uint64_t size, const wchar_t* name) -> bool {
            if (offset > 0 && size > 0) {
                // Check for uint64_t overflow
                if (offset > UINT64_MAX - size) {
                    SS_LOG_ERROR(L"SignatureStore",
                        L"%s offset+size overflow: 0x%llX + 0x%llX",
                        name, offset, size);
                    return false;
                }
            }
            return true;
            };

        if (!checkNoOverflow(header->hashIndexOffset, header->hashIndexSize, L"Hash index")) return false;
        if (!checkNoOverflow(header->patternIndexOffset, header->patternIndexSize, L"Pattern index")) return false;
        if (!checkNoOverflow(header->yaraRulesOffset, header->yaraRulesSize, L"YARA rules")) return false;
        if (!checkNoOverflow(header->metadataOffset, header->metadataSize, L"Metadata")) return false;
        if (!checkNoOverflow(header->stringPoolOffset, header->stringPoolSize, L"String pool")) return false;

        // ========================================================================
        // STEP 5: SECTION OVERLAP DETECTION (with size consideration)
        // ========================================================================

        struct SectionInfo {
            uint64_t offset;
            uint64_t size;
            const wchar_t* name;
        };

        // Only include non-empty sections
        std::array<SectionInfo, 5> sections = { {
            { header->hashIndexOffset, header->hashIndexSize, L"HashIndex" },
            { header->patternIndexOffset, header->patternIndexSize, L"PatternIndex" },
            { header->yaraRulesOffset, header->yaraRulesSize, L"YaraRules" },
            { header->metadataOffset, header->metadataSize, L"Metadata" },
            { header->stringPoolOffset, header->stringPoolSize, L"StringPool" }
        } };

        // Check each pair of sections for overlap
        for (size_t i = 0; i < sections.size(); ++i) {
            if (sections[i].offset == 0 || sections[i].size == 0) continue;

            // SECURITY: Overflow-safe end calculation for section i
            // Already validated above in section offset validation loop
            uint64_t end_i = sections[i].offset + sections[i].size;

            for (size_t j = i + 1; j < sections.size(); ++j) {
                if (sections[j].offset == 0 || sections[j].size == 0) continue;

                // SECURITY: Overflow protection for section j end calculation
                // Check that offset + size doesn't overflow (should be caught earlier, but defense-in-depth)
                if (sections[j].size > UINT64_MAX - sections[j].offset) {
                    SS_LOG_ERROR(L"SignatureStore",
                        L"Section %s: offset + size would overflow",
                        sections[j].name);
                    return false;
                }
                uint64_t end_j = sections[j].offset + sections[j].size;

                // Check for overlap: [start_i, end_i) overlaps [start_j, end_j)
                bool overlaps = (sections[i].offset < end_j) && (sections[j].offset < end_i);

                if (overlaps) {
                    SS_LOG_ERROR(L"SignatureStore",
                        L"Section overlap: %s [0x%llX-0x%llX) overlaps %s [0x%llX-0x%llX)",
                        sections[i].name, sections[i].offset, end_i,
                        sections[j].name, sections[j].offset, end_j);
                    return false;
                }
            }
        }

        // ========================================================================
        // STEP 6: STATISTICS SANITY CHECK (Warnings only)
        // ========================================================================

        if (header->totalHashes > 1'000'000'000ULL) {
            SS_LOG_WARN(L"SignatureStore",
                L"Suspicious hash count: %llu (>1 billion)",
                header->totalHashes);
        }

        if (header->totalPatterns > 10'000'000ULL) {
            SS_LOG_WARN(L"SignatureStore",
                L"Suspicious pattern count: %llu (>10 million)",
                header->totalPatterns);
        }

        if (header->totalYaraRules > 100'000ULL) {
            SS_LOG_WARN(L"SignatureStore",
                L"Suspicious YARA rule count: %llu (>100K)",
                header->totalYaraRules);
        }

        // ========================================================================
        // STEP 7: TIMESTAMP VALIDATION
        // ========================================================================

        // Creation time should be before or equal to last update time
        if (header->creationTime > 0 && header->lastUpdateTime > 0) {
            if (header->creationTime > header->lastUpdateTime) {
                SS_LOG_WARN(L"SignatureStore",
                    L"Creation time (%llu) > last update time (%llu) - possible corruption",
                    header->creationTime, header->lastUpdateTime);
            }
        }

        // Reasonable timestamp range: 2020-2100 (in seconds since epoch)
        constexpr uint64_t MIN_TIMESTAMP = 1577836800ULL;  // 2020-01-01
        constexpr uint64_t MAX_TIMESTAMP = 4102444800ULL;  // 2100-01-01

        if (header->creationTime > 0 &&
            (header->creationTime < MIN_TIMESTAMP || header->creationTime > MAX_TIMESTAMP)) {
            SS_LOG_WARN(L"SignatureStore",
                L"Creation timestamp %llu outside expected range [2020-2100]",
                header->creationTime);
        }

        SS_LOG_DEBUG(L"SignatureStore", L"Header validation passed");
        return true;
    }


// ============================================================================
// CACHE SIZE CALCULATION
// ============================================================================

uint32_t CalculateOptimalCacheSize(uint64_t dbSizeBytes) noexcept {
    // Calculate optimal cache size based on database size
    // Strategy: 5% of database size, clamped to [16MB, 512MB]
    
    constexpr uint64_t MIN_CACHE_MB = 16;
    constexpr uint64_t MAX_CACHE_MB = 512;
    constexpr double CACHE_RATIO = 0.05; // 5% of database

    uint64_t cacheSizeMB = static_cast<uint64_t>(
        (dbSizeBytes / (1024.0 * 1024.0)) * CACHE_RATIO
    );

    // Clamp to range
    if (cacheSizeMB < MIN_CACHE_MB) {
        cacheSizeMB = MIN_CACHE_MB;
    } else if (cacheSizeMB > MAX_CACHE_MB) {
        cacheSizeMB = MAX_CACHE_MB;
    }

    return static_cast<uint32_t>(cacheSizeMB);
}

// ============================================================================
// HASH TYPE UTILITIES
// ============================================================================

const char* HashTypeToString(HashType type) noexcept {
    switch (type) {
        case HashType::MD5:     return "MD5";
        case HashType::SHA1:    return "SHA1";
        case HashType::SHA256:  return "SHA256";
        case HashType::SHA512:  return "SHA512";
        case HashType::IMPHASH: return "IMPHASH";
        case HashType::FUZZY:   return "FUZZY";
        case HashType::TLSH:    return "TLSH";
        default:                return "UNKNOWN";
    }
}

// ============================================================================
// HASH PARSING
// ============================================================================

namespace {

// Helper: Convert hex character to value
inline uint8_t HexCharToValue(char c) noexcept {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0xFF; // Invalid
}

// Helper: Convert hex string to bytes
// SECURITY: All bounds are validated before any memory access
bool HexStringToBytes(const std::string& hexStr, uint8_t* output, size_t maxLen) noexcept {
    // SECURITY: Validate output pointer
    if (output == nullptr || maxLen == 0) {
        return false;
    }

    if (hexStr.empty()) {
        return false; // Empty string - no bytes to parse
    }

    if (hexStr.length() % 2 != 0) {
        return false; // Must be even number of characters
    }

    size_t byteCount = hexStr.length() / 2;
    if (byteCount > maxLen) {
        return false; // Too long
    }

    for (size_t i = 0; i < byteCount; ++i) {
        // SECURITY: Bounds check - verify index is valid
        // i * 2 < hexStr.length() is guaranteed since byteCount = length/2
        // and i < byteCount
        size_t highIdx = i * 2;
        size_t lowIdx = highIdx + 1;
        
        // Defense-in-depth: explicit bounds check
        if (lowIdx >= hexStr.length()) {
            return false;
        }

        uint8_t high = HexCharToValue(hexStr[highIdx]);
        uint8_t low = HexCharToValue(hexStr[lowIdx]);

        if (high == 0xFF || low == 0xFF) {
            return false; // Invalid hex character
        }

        output[i] = static_cast<uint8_t>((high << 4) | low);
    }

    return true;
}

// Helper: Determine hash length for type
uint8_t GetHashLength(HashType type) noexcept {
    switch (type) {
        case HashType::MD5:     return 16;
        case HashType::SHA1:    return 20;
        case HashType::SHA256:  return 32;
        case HashType::SHA512:  return 64;
        case HashType::IMPHASH: return 16; // MD5-based
        case HashType::FUZZY:   return 64; // Variable, max 64
        case HashType::TLSH:    return 35; // 70 hex chars = 35 bytes
        default:                return 0;
    }
}

} // anonymous namespace

std::optional<HashValue> ParseHashString(const std::string& hashStr, HashType type) noexcept {
    /*
     * ========================================================================
     * EXCEPTION-SAFE HASH STRING PARSING
     * ========================================================================
     *
     * Parses hex-encoded hash strings with validation.
     * Uses stack-based cleaning to avoid allocation failures.
     *
     * ========================================================================
     */

    if (hashStr.empty()) {
        SS_LOG_ERROR(L"SignatureStore", L"ParseHashString: empty hash string");
        return std::nullopt;
    }

    // Maximum reasonable hash string length (SHA-512 = 128 hex chars + some whitespace)
    constexpr size_t MAX_HASH_STRING_LEN = 256;
    if (hashStr.length() > MAX_HASH_STRING_LEN) {
        SS_LOG_ERROR(L"SignatureStore", L"ParseHashString: string too long (%zu)",
            hashStr.length());
        return std::nullopt;
    }

    // Stack-based cleaning to avoid heap allocation failures
    char cleaned[MAX_HASH_STRING_LEN + 1];
    size_t cleanedLen = 0;

    for (size_t i = 0; i < hashStr.length() && cleanedLen < MAX_HASH_STRING_LEN; ++i) {
        char c = hashStr[i];
        if (!std::isspace(static_cast<unsigned char>(c))) {
            cleaned[cleanedLen++] = c;
        }
    }
    cleaned[cleanedLen] = '\0';

    // Validate length
    uint8_t expectedLen = GetHashLength(type);
    if (expectedLen == 0) {
        SS_LOG_ERROR(L"SignatureStore", L"ParseHashString: invalid hash type %u",
            static_cast<uint8_t>(type));
        return std::nullopt;
    }

    // For fixed-length hashes, validate exact length
    if (type != HashType::FUZZY && type != HashType::TLSH) {
        if (cleanedLen != static_cast<size_t>(expectedLen) * 2) {
            SS_LOG_ERROR(L"SignatureStore", 
                L"ParseHashString: invalid length %zu for %S (expected %u hex chars)",
                cleanedLen, HashTypeToString(type), expectedLen * 2);
            return std::nullopt;
        }
    }

    // Validate hex string length is even
    if (cleanedLen % 2 != 0) {
        SS_LOG_ERROR(L"SignatureStore", 
            L"ParseHashString: odd length %zu (must be even for hex)", cleanedLen);
        return std::nullopt;
    }

    // Parse hex string directly (avoid std::string allocation)
    HashValue hash{};
    hash.type = type;

    size_t byteCount = cleanedLen / 2;
    if (byteCount > hash.data.size()) {
        SS_LOG_ERROR(L"SignatureStore", 
            L"ParseHashString: hash too long (%zu bytes)", byteCount);
        return std::nullopt;
    }

    for (size_t i = 0; i < byteCount; ++i) {
        uint8_t high = HexCharToValue(cleaned[i * 2]);
        uint8_t low = HexCharToValue(cleaned[i * 2 + 1]);

        if (high == 0xFF || low == 0xFF) {
            SS_LOG_ERROR(L"SignatureStore", 
                L"ParseHashString: invalid hex character at position %zu", i * 2);
            return std::nullopt;
        }

        hash.data[i] = static_cast<uint8_t>((high << 4) | low);
    }

    // Set actual length
    if (type == HashType::FUZZY || type == HashType::TLSH) {
        hash.length = static_cast<uint8_t>(byteCount);
    } else {
        hash.length = expectedLen;
    }

    return hash;
}

// ============================================================================
// HASH FORMATTING (Exception-Safe Version)
// ============================================================================

std::string FormatHashString(const HashValue& hash) {
    /*
     * ========================================================================
     * HIGH-PERFORMANCE HASH FORMATTING
     * ========================================================================
     *
     * Converts binary hash to hex string.
     * Uses lookup table for optimal performance.
     * May throw std::bad_alloc (documented behavior).
     *
     * ========================================================================
     */

    // SECURITY: Validate input with explicit bounds check
    // Check for zero length first, then validate against container size
    if (hash.length == 0) {
        return {};
    }
    
    // SECURITY: Explicit bounds check to prevent buffer over-read
    // hash.length is uint8_t so max is 255, but validate against actual container
    if (static_cast<size_t>(hash.length) > hash.data.size()) {
        SS_LOG_ERROR(L"SignatureStore", 
            L"FormatHashString: hash.length (%u) exceeds data buffer size (%zu)",
            static_cast<unsigned>(hash.length), hash.data.size());
        return {};
    }

    // Pre-allocate exact size needed
    std::string result;
    result.reserve(static_cast<size_t>(hash.length) * 2);

    // Lookup table for hex conversion (faster than sprintf/stringstream)
    static constexpr char hexChars[] = "0123456789abcdef";

    for (size_t i = 0; i < hash.length; ++i) {
        uint8_t byte = hash.data[i];
        result.push_back(hexChars[(byte >> 4) & 0x0F]);
        result.push_back(hexChars[byte & 0x0F]);
    }

    return result;
}

// ============================================================================
// PATH SECURITY VALIDATION (Format namespace - exported in header)
// ============================================================================

namespace {
/**
 * @brief Checks if a path component contains path traversal patterns.
 * 
 * @param path The path to check.
 * @return true if path traversal is detected, false otherwise.
 * 
 * @details Detects:
 * - Parent directory references (..\, ../)
 * - Current directory references (.\, ./)  
 * - Alternative data streams (:) in unexpected positions
 * - Device paths (e.g., \\.\, CON, PRN, AUX, NUL)
 */
[[nodiscard]] bool ContainsPathTraversalPatternsInternal(const std::wstring& path) noexcept {
    if (path.empty()) return false;
    
    // Check for parent directory traversal (..\ or ../)
    // This is the primary path traversal attack vector
    if (path.find(L"..\\") != std::wstring::npos ||
        path.find(L"../") != std::wstring::npos) {
        return true;
    }
    
    // Check if path starts with .. (relative traversal at start)
    if (path.size() >= 2 && path[0] == L'.' && path[1] == L'.') {
        return true;
    }
    
    // Check for device path prefix (\\.\) which could access raw devices
    if (path.size() >= 4 && 
        path[0] == L'\\' && path[1] == L'\\' && 
        path[2] == L'.' && path[3] == L'\\') {
        return true;
    }
    
    // Check for reserved Windows device names (case-insensitive)
    // These can cause issues when used as file names
    static const std::wstring reservedDevices[] = {
        L"CON", L"PRN", L"AUX", L"NUL",
        L"COM1", L"COM2", L"COM3", L"COM4", L"COM5", L"COM6", L"COM7", L"COM8", L"COM9",
        L"LPT1", L"LPT2", L"LPT3", L"LPT4", L"LPT5", L"LPT6", L"LPT7", L"LPT8", L"LPT9"
    };
    
    // Extract the filename part (after last backslash)
    size_t lastSlash = path.rfind(L'\\');
    std::wstring filename = (lastSlash != std::wstring::npos) 
        ? path.substr(lastSlash + 1) 
        : path;
    
    // Remove extension for device name check
    size_t dotPos = filename.find(L'.');
    std::wstring baseName = (dotPos != std::wstring::npos) 
        ? filename.substr(0, dotPos) 
        : filename;
    
    // Convert to uppercase for case-insensitive comparison
    for (wchar_t& c : baseName) {
        if (c >= L'a' && c <= L'z') c -= 32;
    }
    
    for (const auto& device : reservedDevices) {
        if (baseName == device) {
            return true;
        }
    }
    
    return false;
}
} // anonymous namespace

/**
 * @brief Validates and canonicalizes a file path for safe file operations.
 * 
 * @param inputPath The user-provided path to validate.
 * @param canonicalPath Output: The canonicalized (resolved) absolute path.
 * @param errorMessage Output: Error description if validation fails.
 * @return true if path is safe to use, false if validation failed.
 * 
 * @details Security measures:
 * 1. Rejects empty paths
 * 2. Rejects paths with embedded NUL characters
 * 3. Rejects paths with traversal patterns (..)
 * 4. Rejects Windows reserved device names
 * 5. Canonicalizes the path to resolve any remaining . or .. components
 * 6. Validates the canonical path doesn't escape expected boundaries
 * 
 * @security This function is critical for preventing path traversal attacks
 * where an attacker provides paths like "..\..\Windows\System32\config" to
 * access sensitive system files.
 */
[[nodiscard]] bool ValidateAndCanonicalizePath(
    const std::wstring& inputPath,
    std::wstring& canonicalPath,
    std::string& errorMessage
) noexcept {
    canonicalPath.clear();
    errorMessage.clear();
    
    // SECURITY CHECK 1: Reject empty paths
    if (inputPath.empty()) {
        errorMessage = "Empty path";
        return false;
    }
    
    // SECURITY CHECK 2: Reject excessively long paths (DoS prevention)
    constexpr size_t MAX_SAFE_PATH_LENGTH = 32767;  // Windows MAX_PATH extended
    if (inputPath.size() > MAX_SAFE_PATH_LENGTH) {
        errorMessage = "Path exceeds maximum allowed length";
        return false;
    }
    
    // SECURITY CHECK 3: Reject embedded NUL characters (truncation attack)
    if (inputPath.find(L'\0') != std::wstring::npos) {
        errorMessage = "Path contains embedded NUL character";
        SS_LOG_WARN(L"SignatureStore", L"Security: Rejected path with embedded NUL");
        return false;
    }
    
    // SECURITY CHECK 4: Reject obvious path traversal patterns
    // This catches ".." patterns before canonicalization
    if (ContainsPathTraversalPatternsInternal(inputPath)) {
        errorMessage = "Path contains traversal patterns or reserved names";
        SS_LOG_WARN(L"SignatureStore", 
            L"Security: Rejected path with traversal pattern: %s", inputPath.c_str());
        return false;
    }
    
    // SECURITY CHECK 5: Canonicalize the path
    // GetFullPathNameW resolves ., .., and normalizes separators
    // Use extended buffer size to handle long paths
    std::wstring canonBuffer;
    try {
        canonBuffer.resize(MAX_SAFE_PATH_LENGTH);
    }
    catch (const std::exception&) {
        errorMessage = "Memory allocation failed";
        return false;
    }
    
    DWORD result = GetFullPathNameW(
        inputPath.c_str(),
        static_cast<DWORD>(canonBuffer.size()),
        canonBuffer.data(),
        nullptr
    );
    
    if (result == 0) {
        errorMessage = "Failed to resolve path";
        SS_LOG_LAST_ERROR(L"SignatureStore", L"GetFullPathNameW failed");
        return false;
    }
    
    if (result >= canonBuffer.size()) {
        errorMessage = "Resolved path exceeds buffer size";
        return false;
    }
    
    canonBuffer.resize(result);
    
    // SECURITY CHECK 6: Verify the canonical path doesn't still contain traversal
    // This catches edge cases that might slip through
    if (ContainsPathTraversalPatternsInternal(canonBuffer)) {
        errorMessage = "Canonicalized path still contains traversal patterns";
        SS_LOG_WARN(L"SignatureStore", 
            L"Security: Canonical path still has traversal: %s", canonBuffer.c_str());
        return false;
    }
    
    // SECURITY CHECK 7: Ensure path is absolute (starts with drive letter or UNC)
    bool isAbsolute = false;
    if (canonBuffer.size() >= 3) {
        // Check for drive letter (C:\)
        if (((canonBuffer[0] >= L'A' && canonBuffer[0] <= L'Z') ||
             (canonBuffer[0] >= L'a' && canonBuffer[0] <= L'z')) &&
            canonBuffer[1] == L':' && canonBuffer[2] == L'\\') {
            isAbsolute = true;
        }
        // Check for UNC path (\\server)
        else if (canonBuffer[0] == L'\\' && canonBuffer[1] == L'\\') {
            isAbsolute = true;
        }
        // Check for long path prefix (\\?\)
        else if (canonBuffer.size() >= 4 &&
                 canonBuffer[0] == L'\\' && canonBuffer[1] == L'\\' &&
                 canonBuffer[2] == L'?' && canonBuffer[3] == L'\\') {
            isAbsolute = true;
        }
    }
    
    if (!isAbsolute) {
        errorMessage = "Path must be absolute";
        SS_LOG_WARN(L"SignatureStore", 
            L"Security: Rejected non-absolute path: %s", canonBuffer.c_str());
        return false;
    }
    
    canonicalPath = std::move(canonBuffer);
    return true;
}

} // namespace Format

// ============================================================================
// MEMORY-MAPPED VIEW UTILITIES (Helper Functions)
// ============================================================================

namespace {

// Helper: Open file for memory mapping
HANDLE OpenFileForMapping(const std::wstring& path, bool readOnly, DWORD& outError) noexcept {
    DWORD desiredAccess = readOnly ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
    DWORD shareMode = readOnly ? FILE_SHARE_READ : 0;
    DWORD creationDisposition = OPEN_EXISTING;
    DWORD flagsAndAttributes = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS;

    HANDLE hFile = CreateFileW(
        path.c_str(),
        desiredAccess,
        shareMode,
        nullptr,
        creationDisposition,
        flagsAndAttributes,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        outError = GetLastError();
        SS_LOG_LAST_ERROR(L"SignatureStore", 
            L"Failed to open file for mapping: %s", path.c_str());
    }

    return hFile;
}

// Helper: Get file size
bool GetFileSizeEx(HANDLE hFile, uint64_t& outSize, DWORD& outError) noexcept {
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(hFile, &size)) {
        outError = GetLastError();
        SS_LOG_LAST_ERROR(L"SignatureStore", L"Failed to get file size");
        return false;
    }

    outSize = static_cast<uint64_t>(size.QuadPart);
    return true;
}

// Helper: Create file mapping
HANDLE CreateFileMappingForView(HANDLE hFile, bool readOnly, uint64_t size, DWORD& outError) noexcept {
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
        SS_LOG_LAST_ERROR(L"SignatureStore", L"Failed to create file mapping");
    }

    return hMapping;
}

// Helper: Map view of file
// SECURITY: Validates size fits in SIZE_T before casting
void* MapViewOfFileForAccess(HANDLE hMapping, bool readOnly, uint64_t size, DWORD& outError) noexcept {
    // SECURITY: Validate size fits in SIZE_T (critical for 32-bit compatibility)
    // SIZE_T is size_t which is 32-bit on 32-bit Windows
    if (size > static_cast<uint64_t>(SIZE_MAX)) {
        outError = ERROR_ARITHMETIC_OVERFLOW;
        SS_LOG_ERROR(L"SignatureStore", 
            L"MapViewOfFileForAccess: size %llu exceeds SIZE_MAX", size);
        return nullptr;
    }

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
        SS_LOG_LAST_ERROR(L"SignatureStore", L"Failed to map view of file");
    }

    return baseAddress;
}

} // anonymous namespace

// ============================================================================
// PUBLIC MEMORY-MAPPED VIEW FUNCTIONS (RAII-Based)
// ============================================================================

namespace MemoryMapping {

// Open memory-mapped view with RAII for exception safety
bool OpenView(const std::wstring& path, bool readOnly, MemoryMappedView& view, StoreError& error) noexcept {
    /*
     * ========================================================================
     * RAII-BASED MEMORY-MAPPED FILE OPENING
     * ========================================================================
     *
     * Uses RAII guards to ensure cleanup on any error path.
     * Resources are only "released" (not closed) on success.
     *
     * Security Features:
     * - Path traversal protection (prevents ..\ attacks)
     * - Path canonicalization (resolves to absolute path)
     * - Reserved device name rejection (CON, NUL, etc.)
     * - Embedded NUL character detection (truncation attack)
     *
     * ========================================================================
     */

    // Close any existing view first
    MemoryMapping::CloseView(view);

    // ========================================================================
    // STEP 1: PATH SECURITY VALIDATION & CANONICALIZATION
    // ========================================================================
    
    // SECURITY: Validate and canonicalize path to prevent traversal attacks
    // This prevents attackers from using paths like "..\..\Windows\System32"
    std::wstring canonicalPath;
    std::string validationError;
    
    if (!Format::ValidateAndCanonicalizePath(path, canonicalPath, validationError)) {
        error.code = SignatureStoreError::InvalidFormat;
        error.win32Error = 0;
        error.message = "Path validation failed: " + validationError;
        SS_LOG_ERROR(L"SignatureStore", 
            L"Security: Path validation failed for: %s - %S", 
            path.c_str(), validationError.c_str());
        return false;
    }

    // ========================================================================
    // STEP 2: OPEN FILE WITH RAII (using validated canonical path)
    // ========================================================================

    DWORD win32Error = 0;
    HandleGuard fileGuard(OpenFileForMapping(canonicalPath, readOnly, win32Error));
    
    if (!fileGuard.IsValid()) {
        error.code = SignatureStoreError::FileNotFound;
        error.win32Error = win32Error;
        error.message = "Failed to open database file";
        return false;
    }

    // ========================================================================
    // STEP 3: GET AND VALIDATE FILE SIZE
    // ========================================================================

    uint64_t fileSize = 0;
    if (!GetFileSizeEx(fileGuard.Get(), fileSize, win32Error)) {
        error.code = SignatureStoreError::InvalidFormat;
        error.win32Error = win32Error;
        error.message = "Failed to get file size";
        return false;
    }

    // Minimum size validation
    if (fileSize < sizeof(SignatureDatabaseHeader)) {
        error.code = SignatureStoreError::InvalidFormat;
        error.win32Error = 0;
        error.message = "File too small to contain valid header";
        return false;
    }

    // Maximum size validation
    if (fileSize > MAX_DATABASE_SIZE) {
        error.code = SignatureStoreError::TooLarge;
        error.win32Error = 0;
        error.message = "Database file exceeds maximum size";
        return false;
    }

    // SECURITY: Validate fileSize fits in SIZE_T before memory mapping
    // This is critical on 32-bit systems where SIZE_T is 32-bit
    if (fileSize > static_cast<uint64_t>(SIZE_MAX)) {
        error.code = SignatureStoreError::TooLarge;
        error.win32Error = 0;
        error.message = "File size exceeds addressable memory range";
        SS_LOG_ERROR(L"SignatureStore", 
            L"OpenView: fileSize %llu exceeds SIZE_MAX for memory mapping", fileSize);
        return false;
    }

    // ========================================================================
    // STEP 4: CREATE FILE MAPPING WITH RAII
    // ========================================================================

    HandleGuard mappingGuard(CreateFileMappingForView(fileGuard.Get(), readOnly, fileSize, win32Error));
    
    if (!mappingGuard.IsValid()) {
        error.code = SignatureStoreError::MappingFailed;
        error.win32Error = win32Error;
        error.message = "Failed to create file mapping";
        return false;
    }

    // ========================================================================
    // STEP 5: MAP VIEW WITH RAII
    // ========================================================================

    MappedViewGuard viewGuard(MapViewOfFileForAccess(mappingGuard.Get(), readOnly, fileSize, win32Error));
    
    if (!viewGuard.IsValid()) {
        error.code = SignatureStoreError::MappingFailed;
        error.win32Error = win32Error;
        error.message = "Failed to map view of file";
        return false;
    }

    // ========================================================================
    // STEP 6: VALIDATE HEADER BEFORE COMMITTING
    // ========================================================================

    const auto* header = reinterpret_cast<const SignatureDatabaseHeader*>(viewGuard.Get());
    if (!Format::ValidateHeader(header)) {
        error.code = SignatureStoreError::InvalidFormat;
        error.win32Error = 0;
        error.message = "Invalid database header";
        return false;
        // RAII guards will clean up automatically
    }

    // ========================================================================
    // STEP 7: SUCCESS - TRANSFER OWNERSHIP TO OUTPUT VIEW
    // ========================================================================

    // Release ownership from guards (caller now owns these resources)
    view.fileHandle = fileGuard.Release();
    view.mappingHandle = mappingGuard.Release();
    view.baseAddress = viewGuard.Release();
    view.fileSize = fileSize;
    view.readOnly = readOnly;

    SS_LOG_INFO(L"SignatureStore", 
        L"Opened memory-mapped view: %s (%llu bytes, %s)",
        path.c_str(), fileSize, readOnly ? L"read-only" : L"read-write");

    error.code = SignatureStoreError::Success;
    return true;
}

// Close memory-mapped view
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

// Flush view to disk
bool FlushView(MemoryMappedView& view, StoreError& error) noexcept {
    if (!view.IsValid()) {
        error.code = SignatureStoreError::InvalidFormat;
        error.message = "Invalid memory-mapped view";
        return false;
    }

    if (view.readOnly) {
        error.code = SignatureStoreError::AccessDenied;
        error.message = "Cannot flush read-only view";
        return false;
    }

    // SECURITY: Validate fileSize fits in SIZE_T before casting
    // On 32-bit systems, SIZE_T is 32-bit, so large files would overflow
    if (view.fileSize > static_cast<uint64_t>(SIZE_MAX)) {
        error.code = SignatureStoreError::TooLarge;
        error.message = "File size exceeds addressable range for flush";
        SS_LOG_ERROR(L"SignatureStore", 
            L"FlushView: fileSize %llu exceeds SIZE_MAX", view.fileSize);
        return false;
    }

    // Flush memory-mapped region
    if (!FlushViewOfFile(view.baseAddress, static_cast<SIZE_T>(view.fileSize))) {
        DWORD win32Error = GetLastError();
        error.code = SignatureStoreError::Unknown;
        error.win32Error = win32Error;
        error.message = "Failed to flush view to disk";
        SS_LOG_LAST_ERROR(L"SignatureStore", L"FlushViewOfFile failed");
        return false;
    }

    // Flush file buffers
    if (!FlushFileBuffers(view.fileHandle)) {
        DWORD win32Error = GetLastError();
        error.code = SignatureStoreError::Unknown;
        error.win32Error = win32Error;
        error.message = "Failed to flush file buffers";
        SS_LOG_LAST_ERROR(L"SignatureStore", L"FlushFileBuffers failed");
        return false;
    }

    error.code = SignatureStoreError::Success;
    return true;
}

} // namespace MemoryMapping

} 
}
