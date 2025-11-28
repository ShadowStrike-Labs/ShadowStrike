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

// Windows crypto API for SHA-256 validation
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

namespace ShadowStrike {
namespace SignatureStore {
namespace Format {

// ============================================================================
// HEADER VALIDATION
// ============================================================================

bool ValidateHeader(const SignatureDatabaseHeader* header) noexcept {
    if (!header) {
        SS_LOG_ERROR(L"SignatureStore", L"ValidateHeader: null header pointer");
        return false;
    }

    // Check magic number
    if (header->magic != SIGNATURE_DB_MAGIC) {
        SS_LOG_ERROR(L"SignatureStore", 
            L"Invalid magic number: expected 0x%08X, got 0x%08X", 
            SIGNATURE_DB_MAGIC, header->magic);
        return false;
    }

    // Check version
    if (header->versionMajor != SIGNATURE_DB_VERSION_MAJOR) {
        SS_LOG_ERROR(L"SignatureStore", 
            L"Version mismatch: expected %u.x, got %u.%u",
            SIGNATURE_DB_VERSION_MAJOR, 
            header->versionMajor, 
            header->versionMinor);
        return false;
    }

    // Validate section alignment (CRITICAL for memory mapping)
    if (header->hashIndexOffset % PAGE_SIZE != 0) {
        SS_LOG_ERROR(L"SignatureStore", 
            L"Hash index offset 0x%llX not page-aligned (PAGE_SIZE=%zu)",
            header->hashIndexOffset, PAGE_SIZE);
        return false;
    }

    if (header->patternIndexOffset % PAGE_SIZE != 0) {
        SS_LOG_ERROR(L"SignatureStore", 
            L"Pattern index offset 0x%llX not page-aligned",
            header->patternIndexOffset);
        return false;
    }

    if (header->yaraRulesOffset % PAGE_SIZE != 0) {
        SS_LOG_ERROR(L"SignatureStore", 
            L"YARA rules offset 0x%llX not page-aligned",
            header->yaraRulesOffset);
        return false;
    }

    if (header->metadataOffset % PAGE_SIZE != 0) {
        SS_LOG_ERROR(L"SignatureStore", 
            L"Metadata offset 0x%llX not page-aligned",
            header->metadataOffset);
        return false;
    }

    if (header->stringPoolOffset % PAGE_SIZE != 0) {
        SS_LOG_ERROR(L"SignatureStore", 
            L"String pool offset 0x%llX not page-aligned",
            header->stringPoolOffset);
        return false;
    }

    // Validate section ordering (sections must not overlap)
    uint64_t offsets[] = {
        header->hashIndexOffset,
        header->patternIndexOffset,
        header->yaraRulesOffset,
        header->metadataOffset,
        header->stringPoolOffset
    };

    for (size_t i = 0; i < 4; ++i) {
        if (offsets[i] != 0 && offsets[i + 1] != 0) {
            if (offsets[i] >= offsets[i + 1]) {
                SS_LOG_ERROR(L"SignatureStore", 
                    L"Section overlap detected: offset[%zu]=0x%llX >= offset[%zu]=0x%llX",
                    i, offsets[i], i + 1, offsets[i + 1]);
                return false;
            }
        }
    }

    // Validate sizes are reasonable
    if (header->hashIndexSize > MAX_DATABASE_SIZE) {
        SS_LOG_ERROR(L"SignatureStore", 
            L"Hash index size %llu exceeds maximum %llu",
            header->hashIndexSize, MAX_DATABASE_SIZE);
        return false;
    }

    if (header->patternIndexSize > MAX_DATABASE_SIZE) {
        SS_LOG_ERROR(L"SignatureStore", 
            L"Pattern index size %llu exceeds maximum %llu",
            header->patternIndexSize, MAX_DATABASE_SIZE);
        return false;
    }

    if (header->yaraRulesSize > MAX_DATABASE_SIZE) {
        SS_LOG_ERROR(L"SignatureStore", 
            L"YARA rules size %llu exceeds maximum %llu",
            header->yaraRulesSize, MAX_DATABASE_SIZE);
        return false;
    }

    // Validate statistics (sanity check)
    if (header->totalHashes > 1'000'000'000ULL) { // 1 billion signatures max
        SS_LOG_WARN(L"SignatureStore", 
            L"Suspicious hash count: %llu (very large)", 
            header->totalHashes);
    }

    if (header->totalPatterns > 10'000'000ULL) { // 10 million patterns max
        SS_LOG_WARN(L"SignatureStore", 
            L"Suspicious pattern count: %llu (very large)", 
            header->totalPatterns);
    }

    if (header->totalYaraRules > 100'000ULL) { // 100K YARA rules max
        SS_LOG_WARN(L"SignatureStore", 
            L"Suspicious YARA rule count: %llu (very large)", 
            header->totalYaraRules);
    }

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
        case HashType::SSDEEP:  return "SSDEEP";
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
bool HexStringToBytes(const std::string& hexStr, uint8_t* output, size_t maxLen) noexcept {
    if (hexStr.length() % 2 != 0) {
        return false; // Must be even number of characters
    }

    size_t byteCount = hexStr.length() / 2;
    if (byteCount > maxLen) {
        return false; // Too long
    }

    for (size_t i = 0; i < byteCount; ++i) {
        uint8_t high = HexCharToValue(hexStr[i * 2]);
        uint8_t low = HexCharToValue(hexStr[i * 2 + 1]);

        if (high == 0xFF || low == 0xFF) {
            return false; // Invalid hex character
        }

        output[i] = (high << 4) | low;
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
        case HashType::SSDEEP:  return 64; // Variable, max 64
        case HashType::TLSH:    return 35; // 70 hex chars = 35 bytes
        default:                return 0;
    }
}

} // anonymous namespace

std::optional<HashValue> ParseHashString(const std::string& hashStr, HashType type) noexcept {
    if (hashStr.empty()) {
        SS_LOG_ERROR(L"SignatureStore", L"ParseHashString: empty hash string");
        return std::nullopt;
    }

    // Remove any whitespace
    std::string cleaned;
    cleaned.reserve(hashStr.length());
    for (char c : hashStr) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            cleaned += c;
        }
    }

    // Validate length
    uint8_t expectedLen = GetHashLength(type);
    if (expectedLen == 0) {
        SS_LOG_ERROR(L"SignatureStore", L"ParseHashString: invalid hash type %u",
            static_cast<uint8_t>(type));
        return std::nullopt;
    }

    // For SSDEEP and TLSH, length can vary
    if (type != HashType::SSDEEP && type != HashType::TLSH) {
        if (cleaned.length() != expectedLen * 2) {
            SS_LOG_ERROR(L"SignatureStore", 
                L"ParseHashString: invalid length %zu for %S (expected %u bytes)",
                cleaned.length(), HashTypeToString(type), expectedLen);
            return std::nullopt;
        }
    }

    // Parse hex string
    HashValue hash{};
    hash.type = type;
    hash.length = expectedLen;

    if (!HexStringToBytes(cleaned, hash.data.data(), hash.data.size())) {
        SS_LOG_ERROR(L"SignatureStore", L"ParseHashString: invalid hex string");
        return std::nullopt;
    }

    // For variable-length hashes, update actual length
    if (type == HashType::SSDEEP || type == HashType::TLSH) {
        hash.length = static_cast<uint8_t>(cleaned.length() / 2);
    }

    return hash;
}

// ============================================================================
// HASH FORMATTING
// ============================================================================

std::string FormatHashString(const HashValue& hash) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (size_t i = 0; i < hash.length; ++i) {
        oss << std::setw(2) << static_cast<unsigned>(hash.data[i]);
    }

    return oss.str();
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
void* MapViewOfFileForAccess(HANDLE hMapping, bool readOnly, uint64_t size, DWORD& outError) noexcept {
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
// PUBLIC MEMORY-MAPPED VIEW FUNCTIONS
// ============================================================================

namespace MemoryMapping {

// Open memory-mapped view
bool OpenView(const std::wstring& path, bool readOnly, MemoryMappedView& view, StoreError& error) noexcept {
    // Close any existing view
    CloseView(view);

    // Open file
    DWORD win32Error = 0;
    view.fileHandle = OpenFileForMapping(path, readOnly, win32Error);
    if (view.fileHandle == INVALID_HANDLE_VALUE) {
        error.code = SignatureStoreError::FileNotFound;
        error.win32Error = win32Error;
        error.message = "Failed to open database file";
        return false;
    }

    // Get file size
    if (!GetFileSizeEx(view.fileHandle, view.fileSize, win32Error)) {
        error.code = SignatureStoreError::InvalidFormat;
        error.win32Error = win32Error;
        error.message = "Failed to get file size";
        CloseHandle(view.fileHandle);
        view.fileHandle = INVALID_HANDLE_VALUE;
        return false;
    }

    // Validate minimum size (must fit header)
    if (view.fileSize < sizeof(SignatureDatabaseHeader)) {
        error.code = SignatureStoreError::InvalidFormat;
        error.win32Error = 0;
        error.message = "File too small to contain valid header";
        CloseHandle(view.fileHandle);
        view.fileHandle = INVALID_HANDLE_VALUE;
        return false;
    }

    // Create file mapping
    view.mappingHandle = CreateFileMappingForView(view.fileHandle, readOnly, view.fileSize, win32Error);
    if (view.mappingHandle == nullptr) {
        error.code = SignatureStoreError::MappingFailed;
        error.win32Error = win32Error;
        error.message = "Failed to create file mapping";
        CloseHandle(view.fileHandle);
        view.fileHandle = INVALID_HANDLE_VALUE;
        return false;
    }

    // Map view
    view.baseAddress = MapViewOfFileForAccess(view.mappingHandle, readOnly, view.fileSize, win32Error);
    if (view.baseAddress == nullptr) {
        error.code = SignatureStoreError::MappingFailed;
        error.win32Error = win32Error;
        error.message = "Failed to map view of file";
        CloseHandle(view.mappingHandle);
        CloseHandle(view.fileHandle);
        view.mappingHandle = nullptr;
        view.fileHandle = INVALID_HANDLE_VALUE;
        return false;
    }

    view.readOnly = readOnly;

    // Validate header
    const auto* header = view.GetAt<SignatureDatabaseHeader>(0);
    if (!header || !Format::ValidateHeader(header)) {
        error.code = SignatureStoreError::InvalidFormat;
        error.win32Error = 0;
        error.message = "Invalid database header";
        CloseView(view);
        return false;
    }

    SS_LOG_INFO(L"SignatureStore", 
        L"Opened memory-mapped view: %s (%llu bytes, %s)",
        path.c_str(), view.fileSize, readOnly ? L"read-only" : L"read-write");

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

} // namespace SignatureStore
} // namespace ShadowStrike
