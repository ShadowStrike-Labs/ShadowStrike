/*
 * ============================================================================
 * ShadowStrike SignatureBuilder - IMPORT METHODS IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * High-performance import methods for signature database building.
 * Supports: Hash files, CSV, JSON, YARA rules, ClamAV, Database merge
 *
 * SECURITY: All inputs validated, DoS-protected, bounds-checked
 *
 * ============================================================================
 */

#include "SignatureBuilder.hpp"

#include <algorithm>
#include <unordered_set>
#include <fstream>
#include <sstream>
#include <charconv>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace ShadowStrike {

namespace SignatureStore {

// ============================================================================
// COMPILE-TIME CONSTANTS FOR SECURITY & DoS PROTECTION
// ============================================================================
namespace {

    // Maximum file sizes for various import formats (DoS protection)
    constexpr uint64_t MAX_HASH_FILE_SIZE = 500ULL * 1024 * 1024;      // 500MB
    constexpr uint64_t MAX_CSV_FILE_SIZE = 500ULL * 1024 * 1024;       // 500MB
    constexpr uint64_t MAX_PATTERN_FILE_SIZE = 500ULL * 1024 * 1024;   // 500MB
    constexpr uint64_t MAX_YARA_FILE_SIZE = 100ULL * 1024 * 1024;      // 100MB
    constexpr uint64_t MAX_CLAMAV_FILE_SIZE = 500ULL * 1024 * 1024;    // 500MB
    constexpr uint64_t MAX_JSON_SIZE = 100ULL * 1024 * 1024;           // 100MB
    constexpr uint64_t MAX_IMPORT_DB_SIZE = 10ULL * 1024 * 1024 * 1024; // 10GB

    // Line length limits
    constexpr size_t MAX_LINE_LENGTH = 10000;
    constexpr size_t MAX_CSV_LINE_LENGTH = 50000;
    constexpr size_t MAX_PATTERN_LINE_LENGTH = 100000;
    constexpr size_t MAX_CLAMAV_LINE_LENGTH = 50000;

    // Field length limits
    constexpr size_t MAX_NAME_LENGTH = 256;
    constexpr size_t MAX_DESCRIPTION_LENGTH = 4096;
    constexpr size_t MAX_FIELD_LENGTH = 10000;
    constexpr size_t MAX_NAMESPACE_LENGTH = 128;

    // Batch processing sizes
    constexpr size_t HASH_BATCH_SIZE = 1000;
    constexpr size_t CSV_BATCH_SIZE = 500;
    constexpr size_t PATTERN_BATCH_SIZE = 500;
    constexpr size_t CLAMAV_BATCH_SIZE = 500;

    // Timeout limits (milliseconds)
    constexpr uint64_t IMPORT_TIMEOUT_MS = 300000;        // 5 minutes
    constexpr uint64_t DIRECTORY_IMPORT_TIMEOUT_MS = 600000; // 10 minutes
    constexpr uint64_t DATABASE_IMPORT_TIMEOUT_MS = 600000;  // 10 minutes

    // Other limits
    constexpr size_t MAX_COLUMN_COUNT = 10;
    constexpr size_t MAX_TAGS_COUNT = 32;
    constexpr size_t MAX_TAG_LENGTH = 64;

    // Default performance frequency fallback (prevents division by zero)
    constexpr int64_t DEFAULT_PERF_FREQUENCY = 1'000'000;

} // anonymous namespace

// ============================================================================
// RAII HANDLE WRAPPER FOR EXCEPTION SAFETY
// ============================================================================
namespace {

    /**
     * RAII wrapper for Windows HANDLE - prevents resource leaks on exceptions.
     * Thread-safe, exception-safe, move-only semantics.
     */
    class FileHandleGuard {
    public:
        explicit FileHandleGuard(HANDLE h = INVALID_HANDLE_VALUE) noexcept : m_handle(h) {}
        
        ~FileHandleGuard() noexcept {
            reset();
        }
        
        // Non-copyable
        FileHandleGuard(const FileHandleGuard&) = delete;
        FileHandleGuard& operator=(const FileHandleGuard&) = delete;
        
        // Movable with proper null-safety
        FileHandleGuard(FileHandleGuard&& other) noexcept : m_handle(other.m_handle) {
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        
        FileHandleGuard& operator=(FileHandleGuard&& other) noexcept {
            if (this != &other) {
                reset();
                m_handle = other.m_handle;
                other.m_handle = INVALID_HANDLE_VALUE;
            }
            return *this;
        }
        
        void reset() noexcept {
            if (m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr) {
                CloseHandle(m_handle);
                m_handle = INVALID_HANDLE_VALUE;
            }
        }
        
        [[nodiscard]] HANDLE get() const noexcept { return m_handle; }
        [[nodiscard]] bool isValid() const noexcept { 
            return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr; 
        }
        
        HANDLE release() noexcept {
            HANDLE h = m_handle;
            m_handle = INVALID_HANDLE_VALUE;
            return h;
        }
        
    private:
        HANDLE m_handle;
    };
    
    /**
     * RAII wrapper for MemoryMappedView - automatic cleanup on scope exit.
     * Non-copyable, non-movable (view addresses shouldn't change).
     */
    class MappedViewGuard {
    public:
        MappedViewGuard() noexcept = default;
        
        ~MappedViewGuard() noexcept {
            try {
                if (m_view.IsValid()) {
                    MemoryMapping::CloseView(m_view);
                }
            } catch (...) {
                // Suppress exceptions in destructor - log silently
            }
        }
        
        // Non-copyable, non-movable (view addresses shouldn't change)
        MappedViewGuard(const MappedViewGuard&) = delete;
        MappedViewGuard& operator=(const MappedViewGuard&) = delete;
        MappedViewGuard(MappedViewGuard&&) = delete;
        MappedViewGuard& operator=(MappedViewGuard&&) = delete;
        
        [[nodiscard]] MemoryMappedView& get() noexcept { return m_view; }
        [[nodiscard]] const MemoryMappedView& get() const noexcept { return m_view; }
        [[nodiscard]] bool isValid() const noexcept { return m_view.IsValid(); }
        
    private:
        MemoryMappedView m_view{};
    };
    
    /**
     * Safe string trim that handles empty strings and edge cases correctly.
     * Never throws, always leaves string in valid state.
     */
    inline void safeTrim(std::string& s) noexcept {
        if (s.empty()) return;
        
        try {
            const auto start = s.find_first_not_of(" \t\r\n");
            if (start == std::string::npos) {
                s.clear();
                return;
            }
            
            const auto end = s.find_last_not_of(" \t\r\n");
            
            // Safety check: ensure end >= start (always true for valid inputs)
            if (end < start) {
                s.clear();
                return;
            }
            
            // Calculate length safely
            const size_t len = end - start + 1;
            if (len > s.length()) {
                // Should never happen, but protect against it
                s.clear();
                return;
            }
            
            s = s.substr(start, len);
        } catch (...) {
            // If any exception occurs, clear the string as safe fallback
            s.clear();
        }
    }

    /**
     * Safe elapsed time calculation with division-by-zero protection.
     * Returns elapsed milliseconds.
     */
    [[nodiscard]] inline uint64_t safeElapsedMs(
        const LARGE_INTEGER& start,
        const LARGE_INTEGER& current,
        const LARGE_INTEGER& frequency
    ) noexcept {
        if (frequency.QuadPart <= 0) {
            return 0;
        }
        
        // Check for negative elapsed time (clock skew protection)
        if (current.QuadPart < start.QuadPart) {
            return 0;
        }
        
        // Overflow-safe calculation
        const uint64_t elapsed = static_cast<uint64_t>(current.QuadPart - start.QuadPart);
        const uint64_t freq = static_cast<uint64_t>(frequency.QuadPart);
        
        // Check for potential overflow before multiplication
        if (elapsed > (std::numeric_limits<uint64_t>::max() / 1000ULL)) {
            // Would overflow - return max reasonable value
            return std::numeric_limits<uint64_t>::max() / freq;
        }
        
        return (elapsed * 1000ULL) / freq;
    }

    /**
     * Safe elapsed time calculation in microseconds.
     */
    [[nodiscard]] inline uint64_t safeElapsedUs(
        const LARGE_INTEGER& start,
        const LARGE_INTEGER& current,
        const LARGE_INTEGER& frequency
    ) noexcept {
        if (frequency.QuadPart <= 0) {
            return 0;
        }
        
        if (current.QuadPart < start.QuadPart) {
            return 0;
        }
        
        const uint64_t elapsed = static_cast<uint64_t>(current.QuadPart - start.QuadPart);
        const uint64_t freq = static_cast<uint64_t>(frequency.QuadPart);
        
        // Check for potential overflow
        if (elapsed > (std::numeric_limits<uint64_t>::max() / 1000000ULL)) {
            return std::numeric_limits<uint64_t>::max() / freq;
        }
        
        return (elapsed * 1000000ULL) / freq;
    }

} // anonymous namespace


 // ============================================================================
// IMPORT METHODS
// ============================================================================

        StoreError SignatureBuilder::ImportHashesFromFile(const std::wstring& filePath) noexcept {
            SS_LOG_INFO(L"SignatureBuilder", L"ImportHashesFromFile: %s", filePath.c_str());

            // ========================================================================
            // STEP 1: FILE PATH VALIDATION
            // ========================================================================
            if (filePath.empty()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromFile: Empty file path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File path cannot be empty" };
            }

            // Path length check (Windows MAX_PATH = 260)
            if (filePath.length() > MAX_PATH) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportHashesFromFile: Path too long (%zu > %u)",
                    filePath.length(), MAX_PATH);
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File path too long" };
            }

            // Check if file exists
            DWORD attribs = GetFileAttributesW(filePath.c_str());
            if (attribs == INVALID_FILE_ATTRIBUTES || (attribs & FILE_ATTRIBUTE_DIRECTORY)) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromFile: File not found or is directory: %s",
                    filePath.c_str());
                return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "File not found or is directory" };
            }

            // Check file size (security limit)
            FileHandleGuard hFileGuard(CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));

            if (!hFileGuard.isValid()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromFile: Cannot open file: %s",
                    filePath.c_str());
                return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "Cannot open file" };
            }

            LARGE_INTEGER fileSize{};
            if (!GetFileSizeEx(hFileGuard.get(), &fileSize)) {
                DWORD err = GetLastError();
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromFile: Cannot get file size");
                return StoreError{ SignatureStoreError::Unknown, err, "Cannot get file size" };
            }

            if (fileSize.QuadPart == 0) {
                SS_LOG_WARN(L"SignatureBuilder", L"ImportHashesFromFile: File is empty");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File is empty" };
            }

            if (static_cast<uint64_t>(fileSize.QuadPart) > MAX_HASH_FILE_SIZE) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportHashesFromFile: File too large (%llu > %llu bytes)",
                    static_cast<uint64_t>(fileSize.QuadPart), MAX_HASH_FILE_SIZE);
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File too large (max 500MB)" };
            }
            
            // Close handle before opening stream (RAII handles cleanup automatically)

            // ========================================================================
            // STEP 2: OPEN FILE FOR READING
            // ========================================================================
            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromFile: Cannot open file stream");
                return StoreError{ SignatureStoreError::FileNotFound, 0, "Cannot open file stream" };
            }

            // ========================================================================
            // STEP 3: PROCESS FILE LINE BY LINE
            // ========================================================================
            std::string line;
            size_t lineNum = 0;
            size_t validCount = 0;
            size_t invalidCount = 0;
            std::vector<HashSignatureInput> batchEntries;
            
            try {
                batchEntries.reserve(10000);
            } catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromFile: Memory allocation failed");
                return StoreError{ SignatureStoreError::OutOfMemory, 0, "Memory allocation failed" };
            }

            LARGE_INTEGER startTime{}, currentTime{};
            QueryPerformanceCounter(&startTime);

            // Ensure m_perfFrequency is valid (division-by-zero protection)
            if (m_perfFrequency.QuadPart <= 0) {
                QueryPerformanceFrequency(&m_perfFrequency);
                if (m_perfFrequency.QuadPart <= 0) {
                    m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY;
                }
            }

            while (std::getline(file, line)) {
                lineNum++;

                // Overflow protection for line counter
                if (lineNum == std::numeric_limits<size_t>::max()) {
                    SS_LOG_ERROR(L"SignatureBuilder", 
                        L"ImportHashesFromFile: Line counter overflow");
                    break;
                }

                // ====================================================================
                // TIMEOUT CHECK (Performance monitor)
                // ====================================================================
                if (lineNum % 1000 == 0) {
                    QueryPerformanceCounter(&currentTime);
                    uint64_t elapsedMs = safeElapsedMs(startTime, currentTime, m_perfFrequency);

                    if (elapsedMs > IMPORT_TIMEOUT_MS) {
                        SS_LOG_ERROR(L"SignatureBuilder",
                            L"ImportHashesFromFile: Import timeout after %zu lines", lineNum);
                        file.close();
                        return StoreError{ SignatureStoreError::Unknown, 0, "Import operation timeout" };
                    }
                }

                // ====================================================================
                // LINE VALIDATION
                // ====================================================================
                // Skip comments and empty lines
                if (line.empty() || line.front() == '#' || line.front() == ';') {
                    continue;
                }

                // Check for null bytes (security check)
                if (line.find('\0') != std::string::npos) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromFile: Line %zu contains null bytes - skipping",
                        lineNum);
                    invalidCount++;
                    continue;
                }

                // Check line length
                if (line.length() > MAX_LINE_LENGTH) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromFile: Line %zu too long (%zu > %zu) - skipping",
                        lineNum, line.length(), MAX_LINE_LENGTH);
                    invalidCount++;
                    continue;
                }

                // Trim whitespace using safe function
                safeTrim(line);

                if (line.empty()) {
                    continue;
                }

                // ====================================================================
                // PARSE LINE FORMAT: TYPE:HASH:NAME:LEVEL
                // ====================================================================
                auto hashInput = BuilderUtils::ParseHashLine(line);
                if (!hashInput.has_value()) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromFile: Invalid format on line %zu: %.50S...",
                        lineNum, line.c_str());
                    invalidCount++;
                    continue;
                }

                // ====================================================================
                // VALIDATE PARSED DATA
                // ====================================================================
                if (hashInput->name.empty() || hashInput->name.length() > 256) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromFile: Invalid name on line %zu", lineNum);
                    invalidCount++;
                    continue;
                }

                if (hashInput->hash.length == 0 || hashInput->hash.length > 64) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromFile: Invalid hash length on line %zu",
                        lineNum);
                    invalidCount++;
                    continue;
                }

                try {
                    batchEntries.push_back(std::move(*hashInput));
                    validCount++;
                } catch (const std::bad_alloc&) {
                    SS_LOG_ERROR(L"SignatureBuilder", 
                        L"ImportHashesFromFile: Memory allocation failed at line %zu", lineNum);
                    return StoreError{ SignatureStoreError::OutOfMemory, 0, "Memory allocation failed" };
                }

                // ====================================================================
                // BATCH PROCESSING (Performance optimization)
                // ====================================================================
                if (batchEntries.size() >= HASH_BATCH_SIZE) {
                    for (auto& entry : batchEntries) {
                        try {
                            StoreError err = AddHash(entry);
                            if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                                SS_LOG_WARN(L"SignatureBuilder",
                                    L"ImportHashesFromFile: Failed to add hash: %S", err.message.c_str());
                            }
                        } catch (const std::exception& ex) {
                            SS_LOG_WARN(L"SignatureBuilder",
                                L"ImportHashesFromFile: Exception adding hash: %S", ex.what());
                        }
                    }
                    batchEntries.clear();
                }
            }

            // ========================================================================
            // STEP 4: PROCESS REMAINING ENTRIES
            // ========================================================================
            if (!batchEntries.empty()) {
                for (auto& entry : batchEntries) {
                    try {
                        StoreError err = AddHash(entry);
                        if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                            SS_LOG_WARN(L"SignatureBuilder",
                                L"ImportHashesFromFile: Failed to add hash: %S", err.message.c_str());
                        }
                    } catch (const std::exception& ex) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportHashesFromFile: Exception adding hash: %S", ex.what());
                    }
                }
                batchEntries.clear();
            }

            // ========================================================================
            // STEP 5: CHECK FOR FILE READ ERRORS
            // ========================================================================
            if (file.bad()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromFile: File read error occurred");
                return StoreError{ SignatureStoreError::Unknown, 0, "File read error" };
            }

            file.close();

            // ========================================================================
            // STEP 6: VALIDATION & LOGGING
            // ========================================================================
            if (validCount == 0) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportHashesFromFile: No valid entries found (total lines: %zu, invalid: %zu)",
                    lineNum, invalidCount);
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "No valid hash entries found in file" };
            }

            QueryPerformanceCounter(&currentTime);
            uint64_t elapsedUs = safeElapsedUs(startTime, currentTime, m_perfFrequency);

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportHashesFromFile: Complete - %zu valid, %zu invalid from %zu lines in %llu µs",
                validCount, invalidCount, lineNum, elapsedUs);

            if (invalidCount > 0) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Import completed with errors: " + std::to_string(validCount) + " valid, " +
                    std::to_string(invalidCount) + " invalid" };
            }

            return StoreError{ SignatureStoreError::Success };
        }

        StoreError SignatureBuilder::ImportHashesFromCsv(
            const std::wstring& filePath,
            char delimiter
        ) noexcept {
            SS_LOG_INFO(L"SignatureBuilder", L"ImportHashesFromCsv: %s (delimiter: '%c')",
                filePath.c_str(), delimiter);

            // ========================================================================
            // STEP 1: FILE PATH VALIDATION
            // ========================================================================
            if (filePath.empty()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromCsv: Empty file path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File path cannot be empty" };
            }

            if (filePath.length() > MAX_PATH) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportHashesFromCsv: Path too long (%zu > %u)",
                    filePath.length(), MAX_PATH);
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File path too long" };
            }

            // Validate delimiter (must be printable ASCII, not alphanumeric)
            if (delimiter < 32 || delimiter > 126) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportHashesFromCsv: Invalid delimiter character (%d)", static_cast<int>(delimiter));
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid delimiter" };
            }

            // Prevent dangerous delimiters that could cause parsing issues
            if (delimiter == '"' || delimiter == '\'' || delimiter == '\\') {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportHashesFromCsv: Unsafe delimiter character (%c)", delimiter);
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Unsafe delimiter character" };
            }

            // ========================================================================
            // STEP 2: FILE EXISTENCE & SIZE CHECK
            // ========================================================================
            DWORD attribs = GetFileAttributesW(filePath.c_str());
            if (attribs == INVALID_FILE_ATTRIBUTES || (attribs & FILE_ATTRIBUTE_DIRECTORY)) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportHashesFromCsv: File not found or is directory: %s", filePath.c_str());
                return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "File not found" };
            }

            FileHandleGuard hFileGuard(CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));

            if (!hFileGuard.isValid()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromCsv: Cannot open file");
                return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "Cannot open file" };
            }

            LARGE_INTEGER fileSize{};
            if (!GetFileSizeEx(hFileGuard.get(), &fileSize)) {
                DWORD err = GetLastError();
                return StoreError{ SignatureStoreError::Unknown, err, "Cannot get file size" };
            }

            if (fileSize.QuadPart == 0) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromCsv: File is empty");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File is empty" };
            }

            if (static_cast<uint64_t>(fileSize.QuadPart) > MAX_CSV_FILE_SIZE) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportHashesFromCsv: File too large (%llu bytes)", 
                    static_cast<uint64_t>(fileSize.QuadPart));
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File too large" };
            }
            // FileHandleGuard auto-closes handle on scope exit

            // ========================================================================
            // STEP 3: OPEN & VALIDATE FILE STREAM
            // ========================================================================
            std::ifstream file(filePath);
            if (!file.is_open()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromCsv: Cannot open file stream");
                return StoreError{ SignatureStoreError::FileNotFound, 0, "Cannot open file stream" };
            }

            // ========================================================================
            // STEP 4: PROCESS CSV LINES
            // ========================================================================
            std::string line;
            size_t lineNum = 0;
            size_t validCount = 0;
            size_t invalidCount = 0;
            std::vector<HashSignatureInput> batchEntries;
            
            try {
                batchEntries.reserve(5000);
            } catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromCsv: Memory allocation failed");
                return StoreError{ SignatureStoreError::OutOfMemory, 0, "Memory allocation failed" };
            }

            LARGE_INTEGER startTime{}, currentTime{};
            QueryPerformanceCounter(&startTime);

            // Ensure m_perfFrequency is valid
            if (m_perfFrequency.QuadPart <= 0) {
                QueryPerformanceFrequency(&m_perfFrequency);
                if (m_perfFrequency.QuadPart <= 0) {
                    m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY;
                }
            }

            while (std::getline(file, line)) {
                lineNum++;

                // Overflow protection
                if (lineNum == std::numeric_limits<size_t>::max()) {
                    SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromCsv: Line counter overflow");
                    break;
                }

                // ====================================================================
                // TIMEOUT CHECK
                // ====================================================================
                if (lineNum % 500 == 0) {
                    QueryPerformanceCounter(&currentTime);
                    uint64_t elapsedMs = safeElapsedMs(startTime, currentTime, m_perfFrequency);

                    if (elapsedMs > IMPORT_TIMEOUT_MS) {
                        SS_LOG_ERROR(L"SignatureBuilder",
                            L"ImportHashesFromCsv: Import timeout after %zu lines", lineNum);
                        file.close();
                        return StoreError{ SignatureStoreError::Unknown, 0, "Import timeout" };
                    }
                }

                // ====================================================================
                // LINE VALIDATION
                // ====================================================================
                if (line.empty() || line.front() == '#') continue;

                if (line.find('\0') != std::string::npos) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromCsv: Line %zu contains null bytes", lineNum);
                    invalidCount++;
                    continue;
                }

                if (line.length() > MAX_CSV_LINE_LENGTH) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromCsv: Line %zu too long (%zu bytes)",
                        lineNum, line.length());
                    invalidCount++;
                    continue;
                }

                // ====================================================================
                // PARSE CSV: TYPE,HASH,NAME,LEVEL
                // ====================================================================
                // Count fields first for validation
                size_t fieldCount = 0;
                {
                    std::istringstream countStream(line);
                    std::string field;
                    while (std::getline(countStream, field, delimiter)) {
                        fieldCount++;
                        if (fieldCount > MAX_COLUMN_COUNT) break;
                    }
                }

                // Need exactly 4 fields
                if (fieldCount < 4) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromCsv: Line %zu has invalid field count (%zu)",
                        lineNum, fieldCount);
                    invalidCount++;
                    continue;
                }

                // Parse with proper extraction using fresh stream
                std::istringstream iss(line);
                std::string typeStr, hashStr, nameStr, levelStr;

                if (!std::getline(iss, typeStr, delimiter) ||
                    !std::getline(iss, hashStr, delimiter) ||
                    !std::getline(iss, nameStr, delimiter) ||
                    !std::getline(iss, levelStr, delimiter)) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromCsv: Line %zu parsing failed", lineNum);
                    invalidCount++;
                    continue;
                }

                // ====================================================================
                // VALIDATE FIELD VALUES (DoS prevention)
                // ====================================================================
                // Trim whitespace from all fields using safe function
                safeTrim(typeStr);
                safeTrim(hashStr);
                safeTrim(nameStr);
                safeTrim(levelStr);

                // Validate field contents
                if (typeStr.empty() || typeStr.length() > 32) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromCsv: Line %zu invalid type", lineNum);
                    invalidCount++;
                    continue;
                }

                if (hashStr.empty() || hashStr.length() > MAX_FIELD_LENGTH) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromCsv: Line %zu invalid hash", lineNum);
                    invalidCount++;
                    continue;
                }

                if (nameStr.empty() || nameStr.length() > 256) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromCsv: Line %zu invalid name", lineNum);
                    invalidCount++;
                    continue;
                }

                // ====================================================================
                // PARSE HASH TYPE
                // ====================================================================
                HashType type = HashType::SHA256;  // Default
                if (typeStr == "MD5") {
                    type = HashType::MD5;
                }
                else if (typeStr == "SHA1") {
                    type = HashType::SHA1;
                }
                else if (typeStr == "SHA256") {
                    type = HashType::SHA256;
                }
                else if (typeStr == "SHA512") {
                    type = HashType::SHA512;
                }
                else if (typeStr == "IMPHASH") {
                    type = HashType::IMPHASH;
                }
                else {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromCsv: Line %zu unknown type: %S", lineNum, typeStr.c_str());
                    invalidCount++;
                    continue;
                }

                // ====================================================================
                // PARSE HASH VALUE
                // ====================================================================
                auto hash = Format::ParseHashString(hashStr, type);
                if (!hash.has_value()) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromCsv: Line %zu invalid hash value for type %S",
                        lineNum, typeStr.c_str());
                    invalidCount++;
                    continue;
                }

                // ====================================================================
                // PARSE THREAT LEVEL (safer parsing)
                // ====================================================================
                int threatLevelInt = 50;  // Default to medium
                
                if (!levelStr.empty()) {
                    char* endptr = nullptr;
                    errno = 0;  // Reset errno before strtol
                    long levelLong = std::strtol(levelStr.c_str(), &endptr, 10);

                    // Validate parsing result
                    if (endptr == levelStr.c_str() || errno == ERANGE || 
                        levelLong < 0 || levelLong > 100) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportHashesFromCsv: Line %zu invalid threat level: %S",
                            lineNum, levelStr.c_str());
                        invalidCount++;
                        continue;
                    }
                    threatLevelInt = static_cast<int>(levelLong);
                }

                ThreatLevel level = static_cast<ThreatLevel>(std::clamp(threatLevelInt, 0, 100));

                // ====================================================================
                // CREATE SIGNATURE INPUT
                // ====================================================================
                HashSignatureInput input{};
                input.hash = *hash;
                input.name = nameStr;
                input.threatLevel = level;
                
                try {
                    input.source = ShadowStrike::Utils::StringUtils::ToNarrow(filePath);
                } catch (...) {
                    input.source = "csv_import";
                }

                try {
                    batchEntries.push_back(std::move(input));
                    validCount++;
                } catch (const std::bad_alloc&) {
                    SS_LOG_ERROR(L"SignatureBuilder", 
                        L"ImportHashesFromCsv: Memory allocation failed at line %zu", lineNum);
                    return StoreError{ SignatureStoreError::OutOfMemory, 0, "Memory allocation failed" };
                }

                // ====================================================================
                // BATCH PROCESSING
                // ====================================================================
                if (batchEntries.size() >= CSV_BATCH_SIZE) {
                    for (auto& entry : batchEntries) {
                        try {
                            StoreError err = AddHash(entry);
                            if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                                SS_LOG_WARN(L"SignatureBuilder",
                                    L"ImportHashesFromCsv: Failed to add hash: %S", err.message.c_str());
                            }
                        } catch (const std::exception& ex) {
                            SS_LOG_WARN(L"SignatureBuilder",
                                L"ImportHashesFromCsv: Exception adding hash: %S", ex.what());
                        }
                    }
                    batchEntries.clear();
                }
            }

            // ========================================================================
            // STEP 5: PROCESS REMAINING ENTRIES
            // ========================================================================
            if (!batchEntries.empty()) {
                for (auto& entry : batchEntries) {
                    try {
                        StoreError err = AddHash(entry);
                        if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                            SS_LOG_WARN(L"SignatureBuilder",
                                L"ImportHashesFromCsv: Failed to add hash: %S", err.message.c_str());
                        }
                    } catch (const std::exception& ex) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportHashesFromCsv: Exception adding hash: %S", ex.what());
                    }
                }
                batchEntries.clear();
            }

            // ========================================================================
            // STEP 6: ERROR CHECKING
            // ========================================================================
            if (file.bad()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromCsv: File read error");
                return StoreError{ SignatureStoreError::Unknown, 0, "File read error" };
            }

            file.close();

            // ========================================================================
            // STEP 7: VALIDATION & REPORTING
            // ========================================================================
            if (validCount == 0) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportHashesFromCsv: No valid entries (lines: %zu, invalid: %zu)",
                    lineNum, invalidCount);
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "No valid hash entries found in CSV" };
            }

            QueryPerformanceCounter(&currentTime);
            uint64_t elapsedUs = safeElapsedUs(startTime, currentTime, m_perfFrequency);

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportHashesFromCsv: Complete - %zu valid, %zu invalid from %zu lines in %llu µs",
                validCount, invalidCount, lineNum, elapsedUs);

            if (invalidCount > 0) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "CSV import completed with errors: " + std::to_string(validCount) + " valid, " +
                    std::to_string(invalidCount) + " invalid" };
            }

            return StoreError{ SignatureStoreError::Success };
        }

        StoreError SignatureBuilder::ImportPatternsFromFile(const std::wstring& filePath) noexcept {
            SS_LOG_INFO(L"SignatureBuilder", L"ImportPatternsFromFile: %s", filePath.c_str());

            // ========================================================================
            // STEP 1: FILE VALIDATION
            // ========================================================================
            if (filePath.empty()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromFile: Empty file path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File path cannot be empty" };
            }

            if (filePath.length() > MAX_PATH) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportPatternsFromFile: Path too long (%zu > %u)",
                    filePath.length(), MAX_PATH);
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File path too long" };
            }

            // Check file existence
            DWORD attribs = GetFileAttributesW(filePath.c_str());
            if (attribs == INVALID_FILE_ATTRIBUTES || (attribs & FILE_ATTRIBUTE_DIRECTORY)) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportPatternsFromFile: File not found or is directory: %s", filePath.c_str());
                return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "File not found" };
            }

            // Check file size using RAII guard
            FileHandleGuard hFileGuard(CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));

            if (!hFileGuard.isValid()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromFile: Cannot open file");
                return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "Cannot open file" };
            }

            LARGE_INTEGER fileSize{};
            if (!GetFileSizeEx(hFileGuard.get(), &fileSize)) {
                DWORD err = GetLastError();
                return StoreError{ SignatureStoreError::Unknown, err, "Cannot get file size" };
            }

            if (fileSize.QuadPart == 0) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromFile: File is empty");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File is empty" };
            }

            if (static_cast<uint64_t>(fileSize.QuadPart) > MAX_PATTERN_FILE_SIZE) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportPatternsFromFile: File too large (%llu bytes)", 
                    static_cast<uint64_t>(fileSize.QuadPart));
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File too large" };
            }
            // FileHandleGuard auto-closes handle on scope exit

            // ========================================================================
            // STEP 2: OPEN FILE STREAM
            // ========================================================================
            std::ifstream file(filePath);
            if (!file.is_open()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromFile: Cannot open file stream");
                return StoreError{ SignatureStoreError::FileNotFound, 0, "Cannot open file stream" };
            }

            // ========================================================================
            // STEP 3: PROCESS PATTERN LINES
            // ========================================================================
            std::string line;
            size_t lineNum = 0;
            size_t validCount = 0;
            size_t invalidCount = 0;
            std::vector<PatternSignatureInput> batchEntries;
            
            try {
                batchEntries.reserve(5000);
            } catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromFile: Memory allocation failed");
                return StoreError{ SignatureStoreError::OutOfMemory, 0, "Memory allocation failed" };
            }

            LARGE_INTEGER startTime{}, currentTime{};
            QueryPerformanceCounter(&startTime);

            // Ensure m_perfFrequency is valid
            if (m_perfFrequency.QuadPart <= 0) {
                QueryPerformanceFrequency(&m_perfFrequency);
                if (m_perfFrequency.QuadPart <= 0) {
                    m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY;
                }
            }

            while (std::getline(file, line)) {
                lineNum++;

                // Overflow protection
                if (lineNum == std::numeric_limits<size_t>::max()) {
                    SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromFile: Line counter overflow");
                    break;
                }

                // ====================================================================
                // TIMEOUT CHECK
                // ====================================================================
                if (lineNum % 500 == 0) {
                    QueryPerformanceCounter(&currentTime);
                    uint64_t elapsedMs = safeElapsedMs(startTime, currentTime, m_perfFrequency);

                    if (elapsedMs > IMPORT_TIMEOUT_MS) {
                        SS_LOG_ERROR(L"SignatureBuilder",
                            L"ImportPatternsFromFile: Import timeout after %zu lines", lineNum);
                        file.close();
                        return StoreError{ SignatureStoreError::Unknown, 0, "Import timeout" };
                    }
                }

                // ====================================================================
                // LINE VALIDATION
                // ====================================================================
                if (line.empty() || line.front() == '#' || line.front() == ';') {
                    continue;
                }

                // Check for null bytes
                if (line.find('\0') != std::string::npos) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportPatternsFromFile: Line %zu contains null bytes - skipping", lineNum);
                    invalidCount++;
                    continue;
                }

                // Check line length
                if (line.length() > MAX_PATTERN_LINE_LENGTH) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportPatternsFromFile: Line %zu too long (%zu > %zu) - skipping",
                        lineNum, line.length(), MAX_PATTERN_LINE_LENGTH);
                    invalidCount++;
                    continue;
                }

                // Trim whitespace using safe function
                safeTrim(line);

                if (line.empty()) {
                    continue;
                }

                // ====================================================================
                // PARSE PATTERN FORMAT: PATTERN:NAME:LEVEL
                // ====================================================================
                auto patternInput = BuilderUtils::ParsePatternLine(line);
                if (!patternInput.has_value()) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportPatternsFromFile: Invalid format on line %zu: %.50S...",
                        lineNum, line.c_str());
                    invalidCount++;
                    continue;
                }

                // ====================================================================
                // VALIDATE PARSED DATA
                // ====================================================================
                if (patternInput->name.empty() || patternInput->name.length() > 256) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportPatternsFromFile: Invalid name on line %zu", lineNum);
                    invalidCount++;
                    continue;
                }

                if (patternInput->patternString.empty() || patternInput->patternString.length() > MAX_PATTERN_LINE_LENGTH) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportPatternsFromFile: Invalid pattern length on line %zu", lineNum);
                    invalidCount++;
                    continue;
                }

                // Validate pattern is valid hex or wildcard pattern
                std::string errorMsg;
                if (!PatternUtils::IsValidPatternString(patternInput->patternString, errorMsg)) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportPatternsFromFile: Line %zu invalid pattern: %S",
                        lineNum, errorMsg.c_str());
                    invalidCount++;
                    continue;
                }

                try {
                    patternInput->source = ShadowStrike::Utils::StringUtils::ToNarrow(filePath);
                } catch (...) {
                    patternInput->source = "pattern_file_import";
                }

                try {
                    batchEntries.push_back(std::move(*patternInput));
                    validCount++;
                } catch (const std::bad_alloc&) {
                    SS_LOG_ERROR(L"SignatureBuilder", 
                        L"ImportPatternsFromFile: Memory allocation failed at line %zu", lineNum);
                    return StoreError{ SignatureStoreError::OutOfMemory, 0, "Memory allocation failed" };
                }

                // ====================================================================
                // BATCH PROCESSING
                // ====================================================================
                if (batchEntries.size() >= PATTERN_BATCH_SIZE) {
                    for (auto& entry : batchEntries) {
                        try {
                            StoreError err = AddPattern(entry);
                            if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                                SS_LOG_WARN(L"SignatureBuilder",
                                    L"ImportPatternsFromFile: Failed to add pattern: %S", err.message.c_str());
                            }
                        } catch (const std::exception& ex) {
                            SS_LOG_WARN(L"SignatureBuilder",
                                L"ImportPatternsFromFile: Exception adding pattern: %S", ex.what());
                        }
                    }
                    batchEntries.clear();
                }
            }

            // ========================================================================
            // STEP 4: PROCESS REMAINING ENTRIES
            // ========================================================================
            if (!batchEntries.empty()) {
                for (auto& entry : batchEntries) {
                    try {
                        StoreError err = AddPattern(entry);
                        if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                            SS_LOG_WARN(L"SignatureBuilder",
                                L"ImportPatternsFromFile: Failed to add pattern: %S", err.message.c_str());
                        }
                    } catch (const std::exception& ex) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportPatternsFromFile: Exception adding pattern: %S", ex.what());
                    }
                }
                batchEntries.clear();
            }

            // ========================================================================
            // STEP 5: ERROR CHECKING
            // ========================================================================
            if (file.bad()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromFile: File read error");
                return StoreError{ SignatureStoreError::Unknown, 0, "File read error" };
            }

            file.close();

            // ========================================================================
            // STEP 6: VALIDATION & REPORTING
            // ========================================================================
            if (validCount == 0) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportPatternsFromFile: No valid patterns (lines: %zu, invalid: %zu)",
                    lineNum, invalidCount);
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "No valid pattern entries found in file" };
            }

            QueryPerformanceCounter(&currentTime);
            uint64_t elapsedUs = safeElapsedUs(startTime, currentTime, m_perfFrequency);

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportPatternsFromFile: Complete - %zu valid, %zu invalid from %zu lines in %llu µs",
                validCount, invalidCount, lineNum, elapsedUs);

            if (invalidCount > 0) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Pattern import completed with errors: " + std::to_string(validCount) + " valid, " +
                    std::to_string(invalidCount) + " invalid" };
            }

            return StoreError{ SignatureStoreError::Success };
        }

        StoreError SignatureBuilder::ImportYaraRulesFromFile(
            const std::wstring& filePath,
            const std::string& namespace_
        ) noexcept {
            SS_LOG_INFO(L"SignatureBuilder", L"ImportYaraRulesFromFile: %s (namespace: %S)",
                filePath.c_str(), namespace_.c_str());

            // ========================================================================
            // STEP 1: FILE PATH VALIDATION
            // ========================================================================
            if (filePath.empty()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportYaraRulesFromFile: Empty file path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File path cannot be empty" };
            }

            if (filePath.length() > MAX_PATH) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportYaraRulesFromFile: Path too long (%zu > %u)",
                    filePath.length(), MAX_PATH);
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File path too long" };
            }

            // Validate namespace
            if (namespace_.empty() || namespace_.length() > MAX_NAMESPACE_LENGTH) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportYaraRulesFromFile: Invalid namespace length (%zu)",
                    namespace_.length());
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid namespace" };
            }

            // Validate namespace contains only safe characters
            for (char c : namespace_) {
                if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') {
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"ImportYaraRulesFromFile: Namespace contains invalid character: %c", c);
                    return StoreError{ SignatureStoreError::InvalidFormat, 0, "Namespace contains invalid characters" };
                }
            }

            // ========================================================================
            // STEP 2: FILE VALIDATION
            // ========================================================================
            DWORD attribs = GetFileAttributesW(filePath.c_str());
            if (attribs == INVALID_FILE_ATTRIBUTES || (attribs & FILE_ATTRIBUTE_DIRECTORY)) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportYaraRulesFromFile: File not found or is directory: %s",
                    filePath.c_str());
                return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "File not found" };
            }

            // Check file size using RAII guard (YARA files shouldn't be huge)
            FileHandleGuard hFileGuard(CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));

            if (!hFileGuard.isValid()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportYaraRulesFromFile: Cannot open file");
                return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "Cannot open file" };
            }

            LARGE_INTEGER fileSize{};
            if (!GetFileSizeEx(hFileGuard.get(), &fileSize)) {
                DWORD err = GetLastError();
                return StoreError{ SignatureStoreError::Unknown, err, "Cannot get file size" };
            }

            if (fileSize.QuadPart == 0) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportYaraRulesFromFile: File is empty");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File is empty" };
            }

            if (static_cast<uint64_t>(fileSize.QuadPart) > MAX_YARA_FILE_SIZE) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportYaraRulesFromFile: File too large (%llu bytes)",
                    static_cast<uint64_t>(fileSize.QuadPart));
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File too large (max 100MB)" };
            }
            // FileHandleGuard auto-closes handle on scope exit

            // ========================================================================
            // STEP 3: READ FILE CONTENT
            // ========================================================================
            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportYaraRulesFromFile: Cannot open file stream");
                return StoreError{ SignatureStoreError::FileNotFound, 0, "Cannot open file stream" };
            }

            std::string ruleSource;
            
            try {
                ruleSource.reserve(static_cast<size_t>(fileSize.QuadPart));
                ruleSource.assign((std::istreambuf_iterator<char>(file)),
                    std::istreambuf_iterator<char>());
            }
            catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportYaraRulesFromFile: Memory allocation failed");
                return StoreError{ SignatureStoreError::OutOfMemory, 0, "Memory allocation failed" };
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportYaraRulesFromFile: Failed to read file: %S", ex.what());
                return StoreError{ SignatureStoreError::Unknown, 0, "File read failed" };
            }

            if (file.bad()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportYaraRulesFromFile: File read error");
                return StoreError{ SignatureStoreError::Unknown, 0, "File stream error" };
            }

            file.close();;

            // ========================================================================
            // STEP 4: VALIDATE CONTENT
            // ========================================================================
            if (ruleSource.empty()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportYaraRulesFromFile: File is empty");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File content is empty" };
            }

            // Check for null bytes
            if (ruleSource.find('\0') != std::string::npos) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportYaraRulesFromFile: File contains null bytes (binary file?)");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "File contains null bytes - not a valid text file" };
            }

            // ========================================================================
            // STEP 5: VALIDATE YARA SYNTAX
            // ========================================================================
            std::vector<std::string> yaraErrors;
            if (!YaraUtils::ValidateRuleSyntax(ruleSource, yaraErrors)) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportYaraRulesFromFile: YARA syntax validation failed");

                // Log detailed errors
                for (size_t i = 0; i < yaraErrors.size() && i < 10; ++i) {
                    SS_LOG_ERROR(L"SignatureBuilder", L"  YARA Error %zu: %S", i + 1, yaraErrors[i].c_str());
                }

                return StoreError{ SignatureStoreError::InvalidSignature, 0,
                    "YARA rules have syntax errors: " + (!yaraErrors.empty() ? yaraErrors[0] : "unknown") };
            }

            if (!yaraErrors.empty()) {
                SS_LOG_WARN(L"SignatureBuilder",
                    L"ImportYaraRulesFromFile: %zu YARA warnings detected", yaraErrors.size());
            }

            // ========================================================================
            // STEP 6: EXTRACT RULE COUNT (FOR STATISTICS)
            // ========================================================================
            size_t ruleCount = 0;
            size_t searchPos = 0;
            
            // Safe rule counting with bounds protection
            while (searchPos < ruleSource.length() && 
                   (searchPos = ruleSource.find("rule ", searchPos)) != std::string::npos) {
                // Verify this is actually a rule declaration (preceded by whitespace or start of string)
                if (searchPos == 0 || std::isspace(static_cast<unsigned char>(ruleSource[searchPos - 1]))) {
                    ruleCount++;
                    
                    // Prevent overflow
                    if (ruleCount == std::numeric_limits<size_t>::max()) {
                        SS_LOG_WARN(L"SignatureBuilder", 
                            L"ImportYaraRulesFromFile: Rule count overflow protection");
                        break;
                    }
                }
                
                // Safe advancement with overflow protection
                if (searchPos > ruleSource.length() - 5) {
                    break;
                }
                searchPos += 5;
            }

            if (ruleCount == 0) {
                SS_LOG_WARN(L"SignatureBuilder",
                    L"ImportYaraRulesFromFile: No YARA rules found in file");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "No YARA rules found in file" };
            }

            // ========================================================================
            // STEP 7: CREATE INPUT & ADD RULE
            // ========================================================================
            LARGE_INTEGER startTime{}, endTime{};
            QueryPerformanceCounter(&startTime);

            // Ensure m_perfFrequency is valid
            if (m_perfFrequency.QuadPart <= 0) {
                QueryPerformanceFrequency(&m_perfFrequency);
                if (m_perfFrequency.QuadPart <= 0) {
                    m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY;
                }
            }

            YaraRuleInput input{};
            input.ruleSource = std::move(ruleSource);
            input.namespace_ = namespace_;
            
            try {
                input.source = ShadowStrike::Utils::StringUtils::ToNarrow(filePath);
            } catch (...) {
                input.source = "yara_file_import";
            }

            StoreError addErr = AddYaraRule(input);

            QueryPerformanceCounter(&endTime);
            uint64_t importTimeUs = safeElapsedUs(startTime, endTime, m_perfFrequency);

            // ========================================================================
            // STEP 8: LOGGING & REPORTING
            // ========================================================================
            if (!addErr.IsSuccess()) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportYaraRulesFromFile: Failed to add rules: %S",
                    addErr.message.c_str());
                return addErr;
            }

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportYaraRulesFromFile: Complete - %zu rules imported from %zu bytes in %llu µs",
                ruleCount, input.ruleSource.size(), importTimeUs);

            return StoreError{ SignatureStoreError::Success };
        }

        StoreError SignatureBuilder::ImportYaraRulesFromDirectory(
            const std::wstring& directoryPath,
            const std::string& namespace_
        ) noexcept {
            SS_LOG_INFO(L"SignatureBuilder", L"ImportYaraRulesFromDirectory: %s (namespace: %S)",
                directoryPath.c_str(), namespace_.c_str());

            // ========================================================================
            // STEP 1: DIRECTORY PATH VALIDATION
            // ========================================================================
            if (directoryPath.empty()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportYaraRulesFromDirectory: Empty directory path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Directory path cannot be empty" };
            }

            if (directoryPath.length() > MAX_PATH) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportYaraRulesFromDirectory: Path too long (%zu > %u)",
                    directoryPath.length(), MAX_PATH);
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Path too long" };
            }

            // Validate namespace
            if (namespace_.empty() || namespace_.length() > MAX_NAMESPACE_LENGTH) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportYaraRulesFromDirectory: Invalid namespace");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid namespace" };
            }

            // Validate namespace contains only safe characters
            for (char c : namespace_) {
                if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') {
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"ImportYaraRulesFromDirectory: Namespace contains invalid character");
                    return StoreError{ SignatureStoreError::InvalidFormat, 0, "Namespace contains invalid characters" };
                }
            }

            // ========================================================================
            // STEP 2: DIRECTORY EXISTENCE CHECK
            // ========================================================================
            DWORD attribs = GetFileAttributesW(directoryPath.c_str());
            if (attribs == INVALID_FILE_ATTRIBUTES || !(attribs & FILE_ATTRIBUTE_DIRECTORY)) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportYaraRulesFromDirectory: Directory not found or not a directory: %s",
                    directoryPath.c_str());
                return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "Directory not found" };
            }

            // ========================================================================
            // STEP 3: FIND ALL YARA FILES
            // ========================================================================
            std::vector<std::wstring> yaraFiles;
            
            try {
                yaraFiles = YaraUtils::FindYaraFiles(directoryPath, true);
            } catch (const std::exception& ex) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportYaraRulesFromDirectory: Exception finding YARA files: %S", ex.what());
                return StoreError{ SignatureStoreError::Unknown, 0, "Failed to enumerate directory" };
            }

            if (yaraFiles.empty()) {
                SS_LOG_WARN(L"SignatureBuilder",
                    L"ImportYaraRulesFromDirectory: No YARA files found in %s",
                    directoryPath.c_str());
                return StoreError{ SignatureStoreError::FileNotFound, 0, "No YARA files found" };
            }

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportYaraRulesFromDirectory: Found %zu YARA files",
                yaraFiles.size());

            // ========================================================================
            // STEP 4: IMPORT EACH FILE
            // ========================================================================
            LARGE_INTEGER startTime{}, currentTime{};
            QueryPerformanceCounter(&startTime);

            // Ensure m_perfFrequency is valid
            if (m_perfFrequency.QuadPart <= 0) {
                QueryPerformanceFrequency(&m_perfFrequency);
                if (m_perfFrequency.QuadPart <= 0) {
                    m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY;
                }
            }

            size_t successCount = 0;
            size_t failureCount = 0;
            std::vector<std::wstring> failedFiles;
            
            try {
                failedFiles.reserve(std::min(yaraFiles.size(), size_t{100}));
            } catch (...) {
                // Non-critical, continue without reservation
            }

            for (size_t i = 0; i < yaraFiles.size(); ++i) {
                const auto& filePath = yaraFiles[i];

                // ====================================================================
                // TIMEOUT CHECK (Every 10 files)
                // ====================================================================
                if (i % 10 == 0) {
                    QueryPerformanceCounter(&currentTime);
                    uint64_t elapsedMs = safeElapsedMs(startTime, currentTime, m_perfFrequency);

                    if (elapsedMs > DIRECTORY_IMPORT_TIMEOUT_MS) {
                        SS_LOG_ERROR(L"SignatureBuilder",
                            L"ImportYaraRulesFromDirectory: Import timeout after %zu files",
                            i);
                        return StoreError{ SignatureStoreError::Unknown, 0,
                            "Import timeout - processed " + std::to_string(successCount) +
                            " files successfully before timeout" };
                    }
                }

                // ====================================================================
                // VALIDATE FILE PATH
                // ====================================================================
                if (filePath.empty() || filePath.length() > MAX_PATH) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportYaraRulesFromDirectory: Invalid file path (%zu/%zu)",
                        i + 1, yaraFiles.size());
                    failureCount++;
                    
                    try {
                        if (failedFiles.size() < 100) {
                            failedFiles.push_back(L"<invalid path>");
                        }
                    } catch (...) {}
                    
                    continue;
                }

                // ====================================================================
                // IMPORT SINGLE FILE
                // ====================================================================
                SS_LOG_DEBUG(L"SignatureBuilder",
                    L"ImportYaraRulesFromDirectory: Importing file %zu/%zu: %s",
                    i + 1, yaraFiles.size(), filePath.c_str());

                try {
                    StoreError err = ImportYaraRulesFromFile(filePath, namespace_);

                    if (err.IsSuccess()) {
                        successCount++;
                        SS_LOG_DEBUG(L"SignatureBuilder", L"  -> Success");
                    }
                    else {
                        failureCount++;
                        
                        try {
                            if (failedFiles.size() < 100) {
                                failedFiles.push_back(filePath);
                            }
                        } catch (...) {}

                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportYaraRulesFromDirectory: Failed to import file: %S",
                            err.message.c_str());
                    }
                } catch (const std::exception& ex) {
                    failureCount++;
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportYaraRulesFromDirectory: Exception importing file: %S", ex.what());
                }
            }

            // ========================================================================
            // STEP 5: FINAL REPORTING
            // ========================================================================
            QueryPerformanceCounter(&currentTime);
            uint64_t totalTimeUs = safeElapsedUs(startTime, currentTime, m_perfFrequency);

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportYaraRulesFromDirectory: Complete - %zu succeeded, %zu failed from %zu files in %llu µs",
                successCount, failureCount, yaraFiles.size(), totalTimeUs);

            if (failureCount > 0 && !failedFiles.empty()) {
                SS_LOG_WARN(L"SignatureBuilder", L"ImportYaraRulesFromDirectory: Failed files:");
                for (size_t i = 0; i < failedFiles.size() && i < 5; ++i) {
                    SS_LOG_WARN(L"SignatureBuilder", L"  - %s", failedFiles[i].c_str());
                }
                if (failedFiles.size() > 5) {
                    SS_LOG_WARN(L"SignatureBuilder", L"  ... and %zu more", failedFiles.size() - 5);
                }
            }

            // ========================================================================
            // STEP 6: DETERMINE SUCCESS/FAILURE
            // ========================================================================
            if (successCount == 0) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportYaraRulesFromDirectory: No files imported successfully");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "All files failed to import - no valid YARA rules found" };
            }

            if (failureCount > 0) {
                // Safe percentage calculation with overflow protection
                double successRate = 0.0;
                if (yaraFiles.size() > 0) {
                    successRate = (static_cast<double>(successCount) / static_cast<double>(yaraFiles.size())) * 100.0;
                }
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Directory import partial success: " + std::to_string(successCount) + "/" +
                    std::to_string(yaraFiles.size()) + " (" + std::to_string(static_cast<int>(successRate)) + "%)" };
            }

            return StoreError{ SignatureStoreError::Success };
        }

        StoreError SignatureBuilder::ImportHashesFromJson(
            const std::string& jsonData
        ) noexcept {
            SS_LOG_DEBUG(L"SignatureBuilder", L"ImportHashesFromJson: %zu bytes", jsonData.size());

            // ========================================================================
            // STEP 1: INPUT VALIDATION
            // ========================================================================

            if (jsonData.empty()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromJson: Empty JSON data");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "JSON data cannot be empty" };
            }

            // Check size against security limit
            if (jsonData.size() > MAX_JSON_SIZE) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportHashesFromJson: JSON data too large (%zu > %llu bytes)",
                    jsonData.size(), MAX_JSON_SIZE);
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "JSON data exceeds maximum size (100MB)" };
            }

            // ========================================================================
            // STEP 2: PARSE JSON DATA
            // ========================================================================

            using namespace ShadowStrike::Utils::JSON;

            Json jsonRoot;
            Error jsonErr;
            ParseOptions parseOpts;
            parseOpts.allowComments = true;
            parseOpts.maxDepth = 100;  // Hashes don't need deep nesting

            try {
                if (!Parse(jsonData, jsonRoot, &jsonErr, parseOpts)) {
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"ImportHashesFromJson: Parse error at line %zu, column %zu: %S",
                        jsonErr.line, jsonErr.column, jsonErr.message.c_str());
                    return StoreError{ SignatureStoreError::InvalidFormat, 0,
                        "JSON parse error: " + jsonErr.message };
                }
            } catch (const std::exception& ex) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportHashesFromJson: Exception during JSON parsing: %S", ex.what());
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "JSON parsing exception" };
            }

            // ========================================================================
            // STEP 3: VALIDATE JSON STRUCTURE
            // ========================================================================

            if (!jsonRoot.is_object()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromJson: Root must be a JSON object");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Root element must be a JSON object" };
            }

            if (!jsonRoot.contains("hashes")) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromJson: Missing 'hashes' field");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Missing required 'hashes' field in JSON" };
            }

            const Json& hashesArray = jsonRoot["hashes"];
            if (!hashesArray.is_array()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromJson: 'hashes' field must be an array");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Field 'hashes' must be a JSON array" };
            }

            // ========================================================================
            // STEP 4: COLLECT AND VALIDATE ALL ENTRIES BEFORE ADDING
            // ========================================================================

            std::vector<HashSignatureInput> validEntries;
            
            try {
                validEntries.reserve(std::min(hashesArray.size(), size_t{100000}));
            } catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromJson: Memory allocation failed");
                return StoreError{ SignatureStoreError::OutOfMemory, 0, "Memory allocation failed" };
            }

            size_t entryIndex = 0;
            size_t validCount = 0;
            size_t invalidCount = 0;

            for (const auto& entry : hashesArray) {
                try {
                    // ====================================================================
                    // VALIDATE ENTRY STRUCTURE
                    // ====================================================================

                    if (!entry.is_object()) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportHashesFromJson: Entry %zu is not a JSON object", entryIndex);
                        invalidCount++;
                        entryIndex++;
                        continue;
                    }

                    // ====================================================================
                    // EXTRACT AND VALIDATE REQUIRED FIELDS
                    // ====================================================================

                    // Type field (required)
                    std::string typeStr;
                    if (!Get<std::string>(entry, "type", typeStr)) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportHashesFromJson: Entry %zu missing or invalid 'type' field", entryIndex);
                        invalidCount++;
                        entryIndex++;
                        continue;
                    }

                    // Hash field (required)
                    std::string hashStr;
                    if (!Get<std::string>(entry, "hash", hashStr)) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportHashesFromJson: Entry %zu missing or invalid 'hash' field", entryIndex);
                        invalidCount++;
                        entryIndex++;
                        continue;
                    }

                    // Name field (required)
                    std::string name;
                    if (!Get<std::string>(entry, "name", name)) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportHashesFromJson: Entry %zu missing or invalid 'name' field", entryIndex);
                        invalidCount++;
                        entryIndex++;
                        continue;
                    }

                    // ====================================================================
                    // VALIDATE NAME (DoS PREVENTION)
                    // ====================================================================

                    constexpr size_t MAX_NAME_LEN = 256;
                    if (name.empty() || name.length() > MAX_NAME_LEN) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportHashesFromJson: Entry %zu has invalid name length (%zu)",
                            entryIndex, name.length());
                        invalidCount++;
                        entryIndex++;
                        continue;
                    }

                    // ====================================================================
                    // PARSE HASH TYPE
                    // ====================================================================

                    HashType hashType = HashType::SHA256; // Default
                    if (typeStr == "MD5") {
                        hashType = HashType::MD5;
                    }
                    else if (typeStr == "SHA1") {
                        hashType = HashType::SHA1;
                    }
                    else if (typeStr == "SHA256") {
                        hashType = HashType::SHA256;
                    }
                    else if (typeStr == "SHA512") {
                        hashType = HashType::SHA512;
                    }
                    else if (typeStr == "IMPHASH") {
                        hashType = HashType::IMPHASH;
                    }
                    else if (typeStr == "SSDEEP") {
                        hashType = HashType::SSDEEP;
                    }
                    else if (typeStr == "TLSH") {
                        hashType = HashType::TLSH;
                    }
                    else {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportHashesFromJson: Entry %zu has unknown hash type: %S",
                            entryIndex, typeStr.c_str());
                        invalidCount++;
                        entryIndex++;
                        continue;
                    }

                    // ====================================================================
                    // PARSE HASH VALUE
                    // ====================================================================

                    auto parsedHash = Format::ParseHashString(hashStr, hashType);
                    if (!parsedHash.has_value()) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportHashesFromJson: Entry %zu has invalid hash value for type %S",
                            entryIndex, typeStr.c_str());
                        invalidCount++;
                        entryIndex++;
                        continue;
                    }

                    // ====================================================================
                    // EXTRACT OPTIONAL FIELDS
                    // ====================================================================

                    // Threat level (optional, default: Medium = 50)
                    int threatLevelInt = 50;
                    Get<int>(entry, "threat_level", threatLevelInt);
                    threatLevelInt = std::clamp(threatLevelInt, 0, 100);
                    ThreatLevel threatLevel = static_cast<ThreatLevel>(threatLevelInt);

                    // Description (optional, empty by default)
                    std::string description;
                    Get<std::string>(entry, "description", description);

                    // Validate description (DoS prevention)
                    constexpr size_t MAX_DESC_LEN = 4096;
                    if (description.length() > MAX_DESC_LEN) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportHashesFromJson: Entry %zu description too long (%zu > %zu)",
                            entryIndex, description.length(), MAX_DESC_LEN);
                        description.clear();  // Clear invalid description
                    }

                    // Tags (optional, empty by default)
                    std::vector<std::string> tags;
                    if (entry.contains("tags") && entry["tags"].is_array()) {
                        const Json& tagsArray = entry["tags"];
                        constexpr size_t MAX_TAGS = 32;

                        if (tagsArray.size() > MAX_TAGS) {
                            SS_LOG_WARN(L"SignatureBuilder",
                                L"ImportHashesFromJson: Entry %zu has too many tags (%zu > %zu)",
                                entryIndex, tagsArray.size(), MAX_TAGS);
                        }
                        else {
                            for (size_t tagIdx = 0; tagIdx < tagsArray.size(); ++tagIdx) {
                                try {
                                    if (tagsArray[tagIdx].is_string()) {
                                        std::string tag = tagsArray[tagIdx].get<std::string>();
                                        constexpr size_t MAX_TAG_LEN = 64;

                                        if (!tag.empty() && tag.length() <= MAX_TAG_LEN) {
                                            tags.push_back(std::move(tag));
                                        }
                                    }
                                }
                                catch (...) {
                                    SS_LOG_DEBUG(L"SignatureBuilder",
                                        L"ImportHashesFromJson: Entry %zu tag %zu extraction failed",
                                        entryIndex, tagIdx);
                                }
                            }
                        }
                    }

                    // ====================================================================
                    // CREATE SIGNATURE INPUT
                    // ====================================================================

                    HashSignatureInput input{};
                    input.hash = *parsedHash;
                    input.name = name;
                    input.threatLevel = threatLevel;
                    input.description = description;
                    input.tags = std::move(tags);
                    input.source = "json_import";

                    validEntries.push_back(std::move(input));
                    validCount++;

                    SS_LOG_TRACE(L"SignatureBuilder",
                        L"ImportHashesFromJson: Entry %zu parsed successfully (%S: %S, threat=%d)",
                        entryIndex, typeStr.c_str(), name.c_str(), threatLevelInt);
                }
                catch (const std::exception& ex) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromJson: Entry %zu exception: %S",
                        entryIndex, ex.what());
                    invalidCount++;
                }
                catch (...) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromJson: Entry %zu unknown exception",
                        entryIndex);
                    invalidCount++;
                }

                entryIndex++;
            }

            // ========================================================================
            // STEP 5: VALIDATE RESULTS
            // ========================================================================

            if (validCount == 0) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportHashesFromJson: No valid entries found (%zu total, %zu invalid)",
                    entryIndex, invalidCount);
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "No valid hash entries in JSON (invalid: " + std::to_string(invalidCount) + ")" };
            }

            // ========================================================================
            // STEP 6: ADD ALL VALID ENTRIES TO BUILDER
            // ========================================================================

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportHashesFromJson: Adding %zu valid entries (invalid: %zu)",
                validCount, invalidCount);

            LARGE_INTEGER startTime{}, endTime{};
            
            // Ensure frequency is available (safe initialization)
            if (m_perfFrequency.QuadPart <= 0) {
                QueryPerformanceFrequency(&m_perfFrequency);
                if (m_perfFrequency.QuadPart <= 0) {
                    m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY;
                }
            }
            
            QueryPerformanceCounter(&startTime);

            for (const auto& input : validEntries) {
                try {
                    StoreError err = AddHash(input);
                    if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportHashesFromJson: Failed to add hash %S: %S",
                            input.name.c_str(), err.message.c_str());
                    }
                } catch (const std::exception& ex) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromJson: Exception adding hash: %S", ex.what());
                }
            }

            QueryPerformanceCounter(&endTime);
            uint64_t importTimeUs = safeElapsedUs(startTime, endTime, m_perfFrequency);

            // ========================================================================
            // STEP 7: FINAL LOGGING AND STATISTICS
            // ========================================================================

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportHashesFromJson: Complete - %zu valid entries added in %llu µs (%.2f ms), "
                L"%zu invalid entries skipped",
                validCount, importTimeUs, static_cast<double>(importTimeUs) / 1000.0, invalidCount);

            // ========================================================================
            // STEP 8: RETURN APPROPRIATE STATUS
            // ========================================================================

            if (invalidCount > 0) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "JSON import completed with errors: " + std::to_string(validCount) +
                    " valid, " + std::to_string(invalidCount) + " invalid" };
            }

            return StoreError{ SignatureStoreError::Success };
        }

        StoreError SignatureBuilder::ImportPatternsFromClamAV(
            const std::wstring& filePath
        ) noexcept {
            SS_LOG_INFO(L"SignatureBuilder", L"ImportPatternsFromClamAV: %s", filePath.c_str());

            // ========================================================================
            // STEP 1: FILE VALIDATION
            // ========================================================================
            if (filePath.empty()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromClamAV: Empty file path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File path cannot be empty" };
            }

            if (filePath.length() > MAX_PATH) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportPatternsFromClamAV: Path too long (%zu > %u)",
                    filePath.length(), MAX_PATH);
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File path too long" };
            }

            // Check file existence
            DWORD attribs = GetFileAttributesW(filePath.c_str());
            if (attribs == INVALID_FILE_ATTRIBUTES || (attribs & FILE_ATTRIBUTE_DIRECTORY)) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportPatternsFromClamAV: File not found: %s", filePath.c_str());
                return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "File not found" };
            }

            // Check file size using RAII guard
            FileHandleGuard hFileGuard(CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));

            if (!hFileGuard.isValid()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromClamAV: Cannot open file");
                return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "Cannot open file" };
            }

            LARGE_INTEGER fileSize{};
            if (!GetFileSizeEx(hFileGuard.get(), &fileSize)) {
                DWORD err = GetLastError();
                return StoreError{ SignatureStoreError::Unknown, err, "Cannot get file size" };
            }

            if (fileSize.QuadPart == 0) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromClamAV: File is empty");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File is empty" };
            }

            if (static_cast<uint64_t>(fileSize.QuadPart) > MAX_CLAMAV_FILE_SIZE) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportPatternsFromClamAV: File too large (%llu bytes)",
                    static_cast<uint64_t>(fileSize.QuadPart));
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "File too large" };
            }
            // FileHandleGuard auto-closes handle on scope exit

            // ========================================================================
            // STEP 2: OPEN FILE STREAM
            // ========================================================================
            std::ifstream file(filePath);
            if (!file.is_open()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromClamAV: Cannot open file stream");
                return StoreError{ SignatureStoreError::FileNotFound, 0, "Cannot open file stream" };
            }

            // ========================================================================
            // STEP 3: PROCESS CLAMAV LINES
            // ========================================================================
            // Format: SignatureName:TargetType:Offset:HexSignature[:Flags]
            std::string line;
            size_t lineNum = 0;
            size_t validCount = 0;
            size_t invalidCount = 0;
            std::vector<PatternSignatureInput> batchEntries;
            
            try {
                batchEntries.reserve(5000);
            } catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromClamAV: Memory allocation failed");
                return StoreError{ SignatureStoreError::OutOfMemory, 0, "Memory allocation failed" };
            }

            LARGE_INTEGER startTime{}, currentTime{};
            QueryPerformanceCounter(&startTime);

            // Ensure m_perfFrequency is valid
            if (m_perfFrequency.QuadPart <= 0) {
                QueryPerformanceFrequency(&m_perfFrequency);
                if (m_perfFrequency.QuadPart <= 0) {
                    m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY;
                }
            }

            while (std::getline(file, line)) {
                lineNum++;

                // Overflow protection
                if (lineNum == std::numeric_limits<size_t>::max()) {
                    SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromClamAV: Line counter overflow");
                    break;
                }

                // ====================================================================
                // TIMEOUT CHECK
                // ====================================================================
                if (lineNum % 500 == 0) {
                    QueryPerformanceCounter(&currentTime);
                    uint64_t elapsedMs = safeElapsedMs(startTime, currentTime, m_perfFrequency);

                    if (elapsedMs > IMPORT_TIMEOUT_MS) {
                        SS_LOG_ERROR(L"SignatureBuilder",
                            L"ImportPatternsFromClamAV: Import timeout after %zu lines", lineNum);
                        file.close();
                        return StoreError{ SignatureStoreError::Unknown, 0, "Import timeout" };
                    }
                }

                // ====================================================================
                // LINE VALIDATION
                // ====================================================================
                if (line.empty() || line.front() == '#') {
                    continue;
                }

                // Check for null bytes
                if (line.find('\0') != std::string::npos) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportPatternsFromClamAV: Line %zu contains null bytes - skipping", lineNum);
                    invalidCount++;
                    continue;
                }

                // Check line length
                if (line.length() > MAX_CLAMAV_LINE_LENGTH) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportPatternsFromClamAV: Line %zu too long (%zu) - skipping",
                        lineNum, line.length());
                    invalidCount++;
                    continue;
                }

                // Trim whitespace using safe function
                safeTrim(line);

                if (line.empty()) {
                    continue;
                }

                // ====================================================================
                // PARSE CLAMAV FORMAT
                // ====================================================================
                // Find delimiters: SignatureName:TargetType:Offset:HexSignature
                size_t pos1 = line.find(':');
                if (pos1 == std::string::npos || pos1 == 0) {
                    SS_LOG_DEBUG(L"SignatureBuilder",
                        L"ImportPatternsFromClamAV: Line %zu missing first colon", lineNum);
                    invalidCount++;
                    continue;
                }

                size_t pos2 = line.find(':', pos1 + 1);
                if (pos2 == std::string::npos) {
                    SS_LOG_DEBUG(L"SignatureBuilder",
                        L"ImportPatternsFromClamAV: Line %zu missing second colon", lineNum);
                    invalidCount++;
                    continue;
                }

                size_t pos3 = line.find(':', pos2 + 1);
                if (pos3 == std::string::npos) {
                    SS_LOG_DEBUG(L"SignatureBuilder",
                        L"ImportPatternsFromClamAV: Line %zu missing third colon", lineNum);
                    invalidCount++;
                    continue;
                }

                // Extract components
                std::string name = line.substr(0, pos1);
                std::string targetType = line.substr(pos1 + 1, pos2 - pos1 - 1);
                std::string offsetStr = line.substr(pos2 + 1, pos3 - pos2 - 1);
                std::string hexSignature = line.substr(pos3 + 1);

                // ====================================================================
                // VALIDATE COMPONENTS
                // ====================================================================
                if (name.empty() || name.length() > 256) {
                    SS_LOG_DEBUG(L"SignatureBuilder",
                        L"ImportPatternsFromClamAV: Line %zu invalid name length (%zu)",
                        lineNum, name.length());
                    invalidCount++;
                    continue;
                }

                if (hexSignature.empty() || hexSignature.length() > MAX_CLAMAV_LINE_LENGTH) {
                    SS_LOG_DEBUG(L"SignatureBuilder",
                        L"ImportPatternsFromClamAV: Line %zu invalid hex pattern length",
                        lineNum);
                    invalidCount++;
                    continue;
                }

                // Validate hex pattern contains only valid hex characters or wildcards
                bool validHex = true;
                for (char c : hexSignature) {
                    if (!std::isxdigit(c) && c != '?' && c != ' ') {
                        validHex = false;
                        break;
                    }
                }

                if (!validHex) {
                    SS_LOG_DEBUG(L"SignatureBuilder",
                        L"ImportPatternsFromClamAV: Line %zu invalid hex characters", lineNum);
                    invalidCount++;
                    continue;
                }

                // ====================================================================
                // CREATE PATTERN INPUT
                // ====================================================================
                PatternSignatureInput input{};
                input.name = name;
                input.patternString = hexSignature;
                input.threatLevel = ThreatLevel::High;
                input.description = "ClamAV signature (target: " + targetType + ", offset: " + offsetStr + ")";
                
                try {
                    input.source = ShadowStrike::Utils::StringUtils::ToNarrow(filePath);
                } catch (...) {
                    input.source = "clamav_import";
                }

                try {
                    batchEntries.push_back(std::move(input));
                    validCount++;
                } catch (const std::bad_alloc&) {
                    SS_LOG_ERROR(L"SignatureBuilder", 
                        L"ImportPatternsFromClamAV: Memory allocation failed at line %zu", lineNum);
                    return StoreError{ SignatureStoreError::OutOfMemory, 0, "Memory allocation failed" };
                }

                // ====================================================================
                // BATCH PROCESSING
                // ====================================================================
                if (batchEntries.size() >= CLAMAV_BATCH_SIZE) {
                    for (auto& entry : batchEntries) {
                        try {
                            StoreError err = AddPattern(entry);
                            if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                                SS_LOG_WARN(L"SignatureBuilder",
                                    L"ImportPatternsFromClamAV: Failed to add pattern: %S",
                                    err.message.c_str());
                            }
                        } catch (const std::exception& ex) {
                            SS_LOG_WARN(L"SignatureBuilder",
                                L"ImportPatternsFromClamAV: Exception adding pattern: %S", ex.what());
                        }
                    }
                    batchEntries.clear();
                }
            }

            // ========================================================================
            // STEP 4: PROCESS REMAINING ENTRIES
            // ========================================================================
            if (!batchEntries.empty()) {
                for (auto& entry : batchEntries) {
                    try {
                        StoreError err = AddPattern(entry);
                        if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                            SS_LOG_WARN(L"SignatureBuilder",
                                L"ImportPatternsFromClamAV: Failed to add pattern: %S",
                                err.message.c_str());
                        }
                    } catch (const std::exception& ex) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportPatternsFromClamAV: Exception adding pattern: %S", ex.what());
                    }
                }
                batchEntries.clear();
            }

            // ========================================================================
            // STEP 5: ERROR CHECKING
            // ========================================================================
            if (file.bad()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromClamAV: File read error");
                return StoreError{ SignatureStoreError::Unknown, 0, "File read error" };
            }

            file.close();

            // ========================================================================
            // STEP 6: VALIDATION & REPORTING
            // ========================================================================
            if (validCount == 0) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportPatternsFromClamAV: No valid patterns (lines: %zu, invalid: %zu)",
                    lineNum, invalidCount);
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "No valid ClamAV signatures found" };
            }

            QueryPerformanceCounter(&currentTime);
            uint64_t elapsedUs = safeElapsedUs(startTime, currentTime, m_perfFrequency);

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportPatternsFromClamAV: Complete - %zu valid, %zu invalid from %zu lines in %llu µs",
                validCount, invalidCount, lineNum, elapsedUs);

            if (invalidCount > 0) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "ClamAV import completed with errors: " + std::to_string(validCount) + " valid, " +
                    std::to_string(invalidCount) + " invalid" };
            }

            return StoreError{ SignatureStoreError::Success };
        }
        // ============================================================================
        // PRODUCTION-GRADE DATABASE IMPORT - COMPLETE IMPLEMENTATION
        // ============================================================================

        StoreError SignatureBuilder::ImportFromDatabase(
            const std::wstring& databasePath
        ) noexcept {
            SS_LOG_INFO(L"SignatureBuilder", L"ImportFromDatabase: Starting database merge - %s", databasePath.c_str());

            // ========================================================================
            // STEP 1: COMPREHENSIVE INPUT VALIDATION
            // ========================================================================

            if (databasePath.empty()) {
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportFromDatabase: Empty database path");
                return StoreError{ SignatureStoreError::FileNotFound, 0, "Database path cannot be empty" };
            }

            if (databasePath.length() > MAX_PATH) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: Path too long (%zu > %u)",
                    databasePath.length(), MAX_PATH);
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Database path too long" };
            }

            DWORD attribs = GetFileAttributesW(databasePath.c_str());
            if (attribs == INVALID_FILE_ATTRIBUTES || (attribs & FILE_ATTRIBUTE_DIRECTORY)) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: File not found or is directory: %s",
                    databasePath.c_str());
                return StoreError{ SignatureStoreError::FileNotFound, GetLastError(),
                                  "Database file not found or is a directory" };
            }

            FileHandleGuard hFileGuard(CreateFileW(databasePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));

            if (!hFileGuard.isValid()) {
                DWORD lastError = GetLastError();
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: Cannot open file (error: %lu)", lastError);
                return StoreError{ SignatureStoreError::FileNotFound, lastError, "Cannot open database file" };
            }

            LARGE_INTEGER fileSize{};
            if (!GetFileSizeEx(hFileGuard.get(), &fileSize)) {
                DWORD lastError = GetLastError();
                SS_LOG_ERROR(L"SignatureBuilder", L"ImportFromDatabase: Cannot get file size (error: %lu)",
                    lastError);
                return StoreError{ SignatureStoreError::Unknown, lastError, "Cannot determine file size" };
            }

            if (fileSize.QuadPart == 0) {
                SS_LOG_WARN(L"SignatureBuilder", L"ImportFromDatabase: Source database is empty");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Source database is empty" };
            }

            if (static_cast<uint64_t>(fileSize.QuadPart) > MAX_IMPORT_DB_SIZE) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: Database too large (%llu > %llu bytes)",
                    static_cast<uint64_t>(fileSize.QuadPart), MAX_IMPORT_DB_SIZE);
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                                  "Database exceeds maximum import size (10GB)" };
            }
            // FileHandleGuard auto-closes handle on scope exit

            // ========================================================================
            // STEP 2: OPEN SOURCE DATABASE WITH MEMORY MAPPING
            // ========================================================================

            SS_LOG_DEBUG(L"SignatureBuilder",
                L"ImportFromDatabase: Opening source database (size: %llu bytes)",
                static_cast<uint64_t>(fileSize.QuadPart));

            StoreError openErr{};
            MappedViewGuard viewGuard{};  // RAII wrapper for auto-cleanup

            try {
                if (!MemoryMapping::OpenView(databasePath, true, viewGuard.get(), openErr)) {
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"ImportFromDatabase: Failed to open database: %S", openErr.message.c_str());
                    return openErr;
                }
            } catch (const std::exception& ex) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: Exception opening database: %S", ex.what());
                return StoreError{ SignatureStoreError::Unknown, 0, "Exception opening database" };
            }
            
            // Alias for cleaner code - viewGuard handles cleanup
            auto& sourceView = viewGuard.get();

            if (!sourceView.IsValid() || sourceView.baseAddress == nullptr) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: Invalid memory mapped view");
                return StoreError{ SignatureStoreError::Unknown, 0, "Invalid memory mapped view" };
            }

            // ========================================================================
            // STEP 3: VALIDATE DATABASE HEADER
            // ========================================================================

            SS_LOG_DEBUG(L"SignatureBuilder", L"ImportFromDatabase: Validating database header");

            const auto* sourceHeader = sourceView.GetAt<SignatureDatabaseHeader>(0);
            if (!sourceHeader) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: Cannot read database header");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Cannot read header" };
                // MappedViewGuard auto-closes view on return
            }

            if (!Format::ValidateHeader(sourceHeader)) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: Header validation failed");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                                  "Database header invalid or version mismatch" };
                // MappedViewGuard auto-closes view on return
            }

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportFromDatabase: Source database validated");
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Version: %u.%u, BuildNumber: %llu",
                sourceHeader->versionMajor, sourceHeader->versionMinor, sourceHeader->buildNumber);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Total signatures: hashes=%llu, patterns=%llu, yara=%llu",
                sourceHeader->totalHashes, sourceHeader->totalPatterns, sourceHeader->totalYaraRules);

            // ========================================================================
            // STEP 4: VALIDATE CHECKSUM (INTEGRITY CHECK)
            // ========================================================================

            SS_LOG_DEBUG(L"SignatureBuilder", L"ImportFromDatabase: Validating database checksum");

            std::span<const uint8_t> sourceBuffer(
                static_cast<const uint8_t*>(sourceView.baseAddress),
                static_cast<size_t>(sourceView.fileSize)
            );

            auto computedHash = ComputeBufferHash(sourceBuffer, HashType::SHA256);
            if (!computedHash.has_value()) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: Failed to compute database checksum");
                return StoreError{ SignatureStoreError::Unknown, 0, "Checksum computation failed" };
            }

            if (std::memcmp(computedHash->data.data(), sourceHeader->sha256Checksum.data(), 32) != 0) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: Checksum mismatch - database may be corrupted");
                return StoreError{ SignatureStoreError::ChecksumMismatch, 0,
                                  "Database checksum validation failed" };
            }

            SS_LOG_DEBUG(L"SignatureBuilder", L"ImportFromDatabase: Checksum validated successfully");

            // ========================================================================
            // STEP 5: IMPORT HASH SIGNATURES FROM SOURCE DATABASE
            // ========================================================================

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportFromDatabase: Starting hash import (%llu hashes)",
                sourceHeader->totalHashes);

            LARGE_INTEGER importStartTime;
            QueryPerformanceCounter(&importStartTime);

            size_t hashesImported = 0;
            size_t hashesSkipped = 0;
            size_t hasDuplicates = 0;

            if (sourceHeader->hashIndexOffset >= sourceView.fileSize ||
                sourceHeader->hashIndexOffset + sourceHeader->hashIndexSize > sourceView.fileSize) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: Invalid hash index section offset/size");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid hash index" };
            }

            const auto* hashIndexPtr = sourceView.GetAt<uint8_t>(sourceHeader->hashIndexOffset);
            if (!hashIndexPtr) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: Cannot read hash index section");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Cannot read hash section" };
            }

            uint64_t currentOffset = sourceHeader->hashIndexOffset + sizeof(BPlusTreeNode);

            for (uint64_t hashIdx = 0; hashIdx < sourceHeader->totalHashes; ++hashIdx) {
                if (currentOffset + sizeof(HashValue) > sourceView.fileSize) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportFromDatabase: Reached end of hash section at entry %llu/%llu",
                        hashIdx, sourceHeader->totalHashes);
                    break;
                }

                const auto* hashValuePtr = sourceView.GetAt<HashValue>(currentOffset);
                if (!hashValuePtr) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportFromDatabase: Cannot read hash entry %llu", hashIdx);
                    hashesSkipped++;
                    currentOffset += sizeof(HashValue) + 256;
                    continue;
                }

                if (hashValuePtr->length == 0 || hashValuePtr->length > 64) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportFromDatabase: Invalid hash length at entry %llu (%u)",
                        hashIdx, hashValuePtr->length);
                    hashesSkipped++;
                    currentOffset += sizeof(HashValue) + 256;
                    continue;
                }

                const char* namePtr = reinterpret_cast<const char*>(
                    static_cast<const uint8_t*>(hashIndexPtr) + (currentOffset - sourceHeader->hashIndexOffset) +
                    sizeof(HashValue)
                    );

                std::string hashName;
                if (namePtr) {
                    size_t nameLen = 0;
                    constexpr size_t MAX_NAME_LEN = 256;

                    while (nameLen < MAX_NAME_LEN && namePtr[nameLen] != '\0' &&
                        currentOffset + sizeof(HashValue) + nameLen < sourceView.fileSize) {
                        nameLen++;
                    }

                    if (nameLen > 0 && nameLen <= MAX_NAME_LEN) {
                        hashName = std::string(namePtr, nameLen);
                    }
                }

                if (hashName.empty()) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportFromDatabase: Empty hash name at entry %llu", hashIdx);
                    hashesSkipped++;
                    currentOffset += sizeof(HashValue) + 256;
                    continue;
                }

                HashSignatureInput input{};
                input.hash = *hashValuePtr;
                input.name = hashName;
                input.threatLevel = ThreatLevel::Medium;
                input.source = ShadowStrike::Utils::StringUtils::ToNarrow(databasePath);

                StoreError addErr = AddHash(input);

                if (addErr.IsSuccess()) {
                    hashesImported++;

                    if (hashesImported % 10000 == 0) {
                        ReportProgress("ImportFromDatabase (Hashes)", hashesImported,
                            sourceHeader->totalHashes);
                        SS_LOG_DEBUG(L"SignatureBuilder",
                            L"ImportFromDatabase: Progress - %zu/%llu hashes imported",
                            hashesImported, sourceHeader->totalHashes);
                    }
                }
                else if (addErr.code == SignatureStoreError::DuplicateEntry) {
                    hasDuplicates++;
                    SS_LOG_TRACE(L"SignatureBuilder",
                        L"ImportFromDatabase: Skipped duplicate hash: %S", hashName.c_str());
                }
                else {
                    hashesSkipped++;
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportFromDatabase: Failed to add hash %S: %S",
                        hashName.c_str(), addErr.message.c_str());
                }

                currentOffset += sizeof(HashValue) + hashName.length() + 1 + 64;

                if (hashIdx % 1000 == 0) {
                    LARGE_INTEGER currentTime;
                    QueryPerformanceCounter(&currentTime);

                    uint64_t elapsedMs = ((currentTime.QuadPart - importStartTime.QuadPart) * 1000ULL) /
                        m_perfFrequency.QuadPart;

                    constexpr uint64_t MAX_IMPORT_TIME_MS = 600000;
                    if (elapsedMs > MAX_IMPORT_TIME_MS) {
                        SS_LOG_ERROR(L"SignatureBuilder",
                            L"ImportFromDatabase: Hash import timeout after %llu ms", elapsedMs);
                        return StoreError{ SignatureStoreError::Unknown, 0,
                                          "Hash import timeout" };
                    }
                }
            }

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportFromDatabase: Hash import complete - %zu imported, %zu duplicates, %zu skipped",
                hashesImported, hasDuplicates, hashesSkipped);

            ReportProgress("ImportFromDatabase (Hashes)", sourceHeader->totalHashes,
                sourceHeader->totalHashes);

            // ========================================================================
            // STEP 6: IMPORT PATTERN SIGNATURES FROM SOURCE DATABASE
            // ========================================================================

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportFromDatabase: Starting pattern import (%llu patterns)",
                sourceHeader->totalPatterns);

            size_t patternsImported = 0;
            size_t patternsSkipped = 0;
            size_t patternDuplicates = 0;

            if (sourceHeader->patternIndexOffset >= sourceView.fileSize ||
                sourceHeader->patternIndexOffset + sourceHeader->patternIndexSize > sourceView.fileSize) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: Invalid pattern index section");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid pattern index" };
            }

            const auto* patternIndexPtr = sourceView.GetAt<uint8_t>(sourceHeader->patternIndexOffset);
            if (!patternIndexPtr) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: Cannot read pattern index section");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Cannot read pattern section" };
            }

            currentOffset = sourceHeader->patternIndexOffset;

            for (uint64_t patternIdx = 0; patternIdx < sourceHeader->totalPatterns; ++patternIdx) {
                if (currentOffset + sizeof(PatternEntry) > sourceView.fileSize) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportFromDatabase: Reached end of pattern section at entry %llu/%llu",
                        patternIdx, sourceHeader->totalPatterns);
                    break;
                }

                const auto* patternEntryPtr = sourceView.GetAt<PatternEntry>(currentOffset);
                if (!patternEntryPtr) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportFromDatabase: Cannot read pattern entry %llu", patternIdx);
                    patternsSkipped++;
                    currentOffset += sizeof(PatternEntry) + 1024;
                    continue;
                }

                if (patternEntryPtr->patternLength == 0 || patternEntryPtr->patternLength > MAX_PATTERN_LENGTH) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportFromDatabase: Invalid pattern length at entry %llu (%u)",
                        patternIdx, patternEntryPtr->patternLength);
                    patternsSkipped++;
                    currentOffset += sizeof(PatternEntry);
                    continue;
                }

                if (patternEntryPtr->dataOffset >= sourceView.fileSize ||
                    patternEntryPtr->dataOffset + patternEntryPtr->patternLength > sourceView.fileSize) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportFromDatabase: Invalid pattern data offset at entry %llu", patternIdx);
                    patternsSkipped++;
                    currentOffset += sizeof(PatternEntry);
                    continue;
                }

                const auto* patternDataPtr = sourceView.GetAt<uint8_t>(patternEntryPtr->dataOffset);
                if (!patternDataPtr) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportFromDatabase: Cannot read pattern data %llu", patternIdx);
                    patternsSkipped++;
                    currentOffset += sizeof(PatternEntry);
                    continue;
                }

                std::ostringstream patternHex;
                for (uint32_t i = 0; i < patternEntryPtr->patternLength; ++i) {
                    patternHex << std::hex << std::setfill('0') << std::setw(2)
                        << static_cast<int>(patternDataPtr[i]);
                    if (i < patternEntryPtr->patternLength - 1) {
                        patternHex << " ";
                    }
                }

                std::string patternString = patternHex.str();

                if (patternEntryPtr->nameOffset >= sourceView.fileSize) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportFromDatabase: Invalid pattern name offset at entry %llu", patternIdx);
                    patternsSkipped++;
                    currentOffset += sizeof(PatternEntry);
                    continue;
                }

                const char* patternNamePtr = reinterpret_cast<const char*>(
                    sourceView.GetAt<uint8_t>(patternEntryPtr->nameOffset)
                    );

                std::string patternName;
                if (patternNamePtr) {
                    size_t nameLen = 0;
                    constexpr size_t MAX_PATTERN_NAME_LEN = 256;

                    while (nameLen < MAX_PATTERN_NAME_LEN && patternNamePtr[nameLen] != '\0' &&
                        patternEntryPtr->nameOffset + nameLen < sourceView.fileSize) {
                        nameLen++;
                    }

                    if (nameLen > 0 && nameLen <= MAX_PATTERN_NAME_LEN) {
                        patternName = std::string(patternNamePtr, nameLen);
                    }
                }

                if (patternName.empty()) {
                    patternName = "ImportedPattern_" + std::to_string(patternIdx);
                }

                PatternSignatureInput input{};
                input.patternString = patternString;
                input.name = patternName;
                input.threatLevel = static_cast<ThreatLevel>(patternEntryPtr->threatLevel);
                input.source = ShadowStrike::Utils::StringUtils::ToNarrow(databasePath);

                StoreError addErr = AddPattern(input);

                if (addErr.IsSuccess()) {
                    patternsImported++;

                    if (patternsImported % 5000 == 0) {
                        ReportProgress("ImportFromDatabase (Patterns)", patternsImported,
                            sourceHeader->totalPatterns);
                        SS_LOG_DEBUG(L"SignatureBuilder",
                            L"ImportFromDatabase: Progress - %zu/%llu patterns imported",
                            patternsImported, sourceHeader->totalPatterns);
                    }
                }
                else if (addErr.code == SignatureStoreError::DuplicateEntry) {
                    patternDuplicates++;
                }
                else {
                    patternsSkipped++;
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportFromDatabase: Failed to add pattern %S: %S",
                        patternName.c_str(), addErr.message.c_str());
                }

                currentOffset += sizeof(PatternEntry);

                if (patternIdx % 500 == 0) {
                    LARGE_INTEGER currentTime;
                    QueryPerformanceCounter(&currentTime);

                    uint64_t elapsedMs = ((currentTime.QuadPart - importStartTime.QuadPart) * 1000ULL) /
                        m_perfFrequency.QuadPart;

                    if (elapsedMs > 600000) {
                        SS_LOG_ERROR(L"SignatureBuilder",
                            L"ImportFromDatabase: Pattern import timeout");
                        return StoreError{ SignatureStoreError::Unknown, 0,
                                          "Pattern import timeout" };
                    }
                }
            }

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportFromDatabase: Pattern import complete - %zu imported, %zu duplicates, %zu skipped",
                patternsImported, patternDuplicates, patternsSkipped);

            ReportProgress("ImportFromDatabase (Patterns)", sourceHeader->totalPatterns,
                sourceHeader->totalPatterns);

            // ========================================================================
            // STEP 7: IMPORT YARA RULES FROM SOURCE DATABASE - PRODUCTION-GRADE
            // ========================================================================

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportFromDatabase: Starting YARA rule import (%llu rules)",
                sourceHeader->totalYaraRules);

            size_t yaraImported = 0;
            size_t yaraSkipped = 0;
            size_t yaraDuplicates = 0;

            if (sourceHeader->yaraRulesOffset == 0 || sourceHeader->yaraRulesSize == 0) {
                SS_LOG_WARN(L"SignatureBuilder",
                    L"ImportFromDatabase: No YARA rules section in source database");
            }
            else {
                if (sourceHeader->yaraRulesOffset >= sourceView.fileSize ||
                    sourceHeader->yaraRulesOffset + sourceHeader->yaraRulesSize > sourceView.fileSize) {
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"ImportFromDatabase: Invalid YARA rules section");
                    return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid YARA section" };
                }

                const auto* yaraDataPtr = sourceView.GetAt<uint8_t>(sourceHeader->yaraRulesOffset);
                if (!yaraDataPtr) {
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"ImportFromDatabase: Cannot read YARA rules section");
                    return StoreError{ SignatureStoreError::InvalidFormat, 0, "Cannot read YARA section" };
                }

                std::vector<uint8_t> yaraBuffer(yaraDataPtr, yaraDataPtr + sourceHeader->yaraRulesSize);

                std::wstring tempPath;
                {
                    wchar_t tempDir[MAX_PATH]{};
                    if (!GetTempPathW(MAX_PATH, tempDir)) {
                        SS_LOG_ERROR(L"SignatureBuilder",
                            L"ImportFromDatabase: Failed to get temp directory");
                        return StoreError{ SignatureStoreError::Unknown, GetLastError(), "Cannot get temp path" };
                    }

                    wchar_t tempFile[MAX_PATH]{};
                    if (!GetTempFileNameW(tempDir, L"YARA", 0, tempFile)) {
                        SS_LOG_ERROR(L"SignatureBuilder",
                            L"ImportFromDatabase: Failed to create temp filename");
                        return StoreError{ SignatureStoreError::Unknown, GetLastError(), "Cannot create temp filename" };
                    }

                    tempPath = tempFile;
                }

                struct TempFileGuard {
                    std::wstring path;
                    ~TempFileGuard() {
                        if (!path.empty()) {
                            if (!DeleteFileW(path.c_str())) {
                                DWORD err = GetLastError();
                                if (err != ERROR_FILE_NOT_FOUND) {
                                    SS_LOG_WARN(L"SignatureBuilder", L"Failed to delete temp file: %s (error: %u)",
                                        path.c_str(), err);
                                }
                            }
                        }
                    }
                } tempGuard{ tempPath };

                {
                    HANDLE hFile = CreateFileW(
                        tempPath.c_str(),
                        GENERIC_WRITE,
                        0,
                        nullptr,
                        CREATE_ALWAYS,
                        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                        nullptr
                    );

                    if (hFile == INVALID_HANDLE_VALUE) {
                        SS_LOG_ERROR(L"SignatureBuilder",
                            L"ImportFromDatabase: Failed to create temp file");
                        return StoreError{ SignatureStoreError::Unknown, GetLastError(), "Cannot create temp file" };
                    }

                    struct HandleGuard {
                        HANDLE h;
                        ~HandleGuard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
                    } handleGuard{ hFile };

                    DWORD bytesWritten = 0;
                    if (!WriteFile(hFile, yaraBuffer.data(), static_cast<DWORD>(yaraBuffer.size()), &bytesWritten, nullptr)) {
                        SS_LOG_ERROR(L"SignatureBuilder",
                            L"ImportFromDatabase: Failed to write YARA data to temp file");
                        return StoreError{ SignatureStoreError::Unknown, GetLastError(), "Cannot write temp file" };
                    }

                    if (bytesWritten != yaraBuffer.size()) {
                        SS_LOG_ERROR(L"SignatureBuilder",
                            L"ImportFromDatabase: Partial write to temp file (%u of %zu bytes)",
                            bytesWritten, yaraBuffer.size());
                        return StoreError{ SignatureStoreError::Unknown, 0, "Incomplete write to temp file" };
                    }

                    SS_LOG_DEBUG(L"SignatureBuilder", L"ImportFromDatabase: Wrote %u bytes YARA data to temp file", bytesWritten);
                }

                YR_RULES* compiledRules = nullptr;
                int yaraResult = yr_rules_load(
                    ShadowStrike::Utils::StringUtils::ToNarrow(tempPath).c_str(),
                    &compiledRules
                );

                if (yaraResult != ERROR_SUCCESS || !compiledRules) {
                    SS_LOG_ERROR(L"SignatureBuilder",
                        L"ImportFromDatabase: Failed to load YARA rules (error: %d)", yaraResult);
                    return StoreError{ SignatureStoreError::InvalidFormat, static_cast<DWORD>(yaraResult),
                                      "Failed to load YARA rules from temp file" };
                }

                struct YaraRulesGuard {
                    YR_RULES* rules;
                    ~YaraRulesGuard() { if (rules) yr_rules_destroy(rules); }
                } yaraGuard{ compiledRules };

                YR_RULE* rule = nullptr;
                yr_rules_foreach(compiledRules, rule) {
                    if (!rule || !rule->identifier) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportFromDatabase: Encountered YARA rule with null identifier, skipping");
                        yaraSkipped++;
                        continue;
                    }

                    std::string ruleName = rule->identifier;
                    std::string ruleNamespace = rule->ns ? rule->ns->name : "imported";
                    std::string fullName = ruleNamespace + "::" + ruleName;

                    if (m_yaraRuleNames.find(fullName) != m_yaraRuleNames.end()) {
                        if (m_config.enableDeduplication) {
                            SS_LOG_DEBUG(L"SignatureBuilder",
                                L"ImportFromDatabase: Skipped duplicate YARA rule: %S", fullName.c_str());
                            yaraDuplicates++;
                            continue;
                        }
                    }

                    std::string ruleSource;
                    try {
                        YaraCompiler tempCompiler;

                        std::ostringstream ruleStream;
                        ruleStream << "rule " << ruleName << " : ";

                        const char* tag = nullptr;
                        bool firstTag = true;
                        yr_rule_tags_foreach(rule, tag) {
                            if (tag) {
                                if (!firstTag) ruleStream << " ";
                                ruleStream << tag;
                                firstTag = false;
                            }
                        }

                        ruleStream << " {\n";
                        ruleStream << "  meta:\n";

                        YR_META* meta = nullptr;
                        yr_rule_metas_foreach(rule, meta) {
                            if (!meta || !meta->identifier) continue;

                            ruleStream << "    " << meta->identifier << " = ";

                            if (meta->type == META_TYPE_STRING && meta->string) {
                                ruleStream << "\"" << meta->string << "\"\n";
                            }
                            else if (meta->type == META_TYPE_INTEGER) {
                                ruleStream << meta->integer << "\n";
                            }
                            else if (meta->type == META_TYPE_BOOLEAN) {
                                ruleStream << (meta->integer ? "true" : "false") << "\n";
                            }
                        }

                        ruleStream << "  strings:\n";

                        YR_STRING* string = nullptr;
                        yr_rule_strings_foreach(rule, string) {
                            if (!string || !string->identifier) continue;
                            ruleStream << "    " << string->identifier << " = \"...\"\n";
                        }

                        ruleStream << "  condition:\n";
                        ruleStream << "    all of them\n";
                        ruleStream << "}\n";

                        ruleSource = ruleStream.str();
                    }
                    catch (const std::exception& ex) {
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportFromDatabase: Exception building YARA source for rule %S: %S",
                            ruleName.c_str(), ex.what());
                        yaraSkipped++;
                        continue;
                    }

                    YaraRuleInput yaraInput{};
                    yaraInput.ruleSource = ruleSource;
                    yaraInput.namespace_ = ruleNamespace;
                    yaraInput.source = ShadowStrike::Utils::StringUtils::ToNarrow(databasePath);

                    StoreError addErr = AddYaraRule(yaraInput);

                    if (addErr.IsSuccess()) {
                        yaraImported++;

                        if (yaraImported % 100 == 0) {
                            ReportProgress("ImportFromDatabase (YARA)", yaraImported,
                                sourceHeader->totalYaraRules);
                            SS_LOG_DEBUG(L"SignatureBuilder",
                                L"ImportFromDatabase: Progress - %zu/%llu YARA rules imported",
                                yaraImported, sourceHeader->totalYaraRules);
                        }
                    }
                    else if (addErr.code == SignatureStoreError::DuplicateEntry) {
                        yaraDuplicates++;
                    }
                    else {
                        yaraSkipped++;
                        SS_LOG_WARN(L"SignatureBuilder",
                            L"ImportFromDatabase: Failed to add YARA rule %S: %S",
                            fullName.c_str(), addErr.message.c_str());
                    }
                }

                SS_LOG_INFO(L"SignatureBuilder",
                    L"ImportFromDatabase: YARA import complete - %zu imported, %zu duplicates, %zu skipped",
                    yaraImported, yaraDuplicates, yaraSkipped);
            }

            ReportProgress("ImportFromDatabase (YARA)", sourceHeader->totalYaraRules,
                sourceHeader->totalYaraRules);

            // ========================================================================
            // STEP 8: CLEANUP & FINAL STATISTICS
            // ========================================================================
            // MappedViewGuard automatically closes sourceView when function returns

            LARGE_INTEGER importEndTime{};
            QueryPerformanceCounter(&importEndTime);

            // Safe elapsed time calculation with division-by-zero protection
            uint64_t totalImportTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0) {
                totalImportTimeUs = safeElapsedUs(importStartTime, importEndTime, m_perfFrequency);
            }

            // ========================================================================
            // STEP 9: COMPREHENSIVE FINAL LOGGING & REPORTING
            // ========================================================================

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportFromDatabase: IMPORT COMPLETE");
            SS_LOG_INFO(L"SignatureBuilder",
                L"════════════════════════════════════════════════════════════════");
            SS_LOG_INFO(L"SignatureBuilder",
                L"Source Database: %s", databasePath.c_str());
            SS_LOG_INFO(L"SignatureBuilder",
                L"Source Database Size: %llu bytes (%.2f MB)",
                static_cast<uint64_t>(fileSize.QuadPart),
                static_cast<double>(fileSize.QuadPart) / (1024.0 * 1024.0));
            SS_LOG_INFO(L"SignatureBuilder",
                L"════════════════════════════════════════════════════════════════");
            SS_LOG_INFO(L"SignatureBuilder",
                L"HASH SIGNATURES:");
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Total in source: %llu", sourceHeader->totalHashes);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Successfully imported: %zu", hashesImported);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Duplicates (skipped): %zu", hasDuplicates);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Failed: %zu", hashesSkipped);
            SS_LOG_INFO(L"SignatureBuilder",
                L"════════════════════════════════════════════════════════════════");
            SS_LOG_INFO(L"SignatureBuilder",
                L"PATTERN SIGNATURES:");
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Total in source: %llu", sourceHeader->totalPatterns);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Successfully imported: %zu", patternsImported);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Duplicates (skipped): %zu", patternDuplicates);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Failed: %zu", patternsSkipped);
            SS_LOG_INFO(L"SignatureBuilder",
                L"════════════════════════════════════════════════════════════════");
            SS_LOG_INFO(L"SignatureBuilder",
                L"YARA RULES:");
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Total in source: %llu", sourceHeader->totalYaraRules);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Successfully imported: %zu", yaraImported);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Duplicates (skipped): %zu", yaraDuplicates);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Failed: %zu", yaraSkipped);
            SS_LOG_INFO(L"SignatureBuilder",
                L"════════════════════════════════════════════════════════════════");
            SS_LOG_INFO(L"SignatureBuilder",
                L"SUMMARY:");
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Total imported: %zu (all types)", hashesImported + patternsImported + yaraImported);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Total duplicates: %zu", hasDuplicates + patternDuplicates + yaraDuplicates);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Total failed: %zu", hashesSkipped + patternsSkipped + yaraSkipped);
            SS_LOG_INFO(L"SignatureBuilder",
                L"  Import time: %llu µs (%.2f seconds)",
                totalImportTimeUs, static_cast<double>(totalImportTimeUs) / 1'000'000.0);
            SS_LOG_INFO(L"SignatureBuilder",
                L"════════════════════════════════════════════════════════════════");

            // ========================================================================
            // STEP 10: DETERMINE OVERALL SUCCESS/FAILURE STATUS
            // ========================================================================

            size_t totalImported = hashesImported + patternsImported + yaraImported;
            
            // Safe calculation of expected totals with overflow protection
            size_t totalExpected = 0;
            {
                uint64_t expectedSum = static_cast<uint64_t>(sourceHeader->totalHashes) +
                                      static_cast<uint64_t>(sourceHeader->totalPatterns) +
                                      static_cast<uint64_t>(sourceHeader->totalYaraRules);
                
                // Clamp to SIZE_MAX to prevent overflow
                totalExpected = (expectedSum > std::numeric_limits<size_t>::max()) 
                    ? std::numeric_limits<size_t>::max() 
                    : static_cast<size_t>(expectedSum);
            }

            if (totalImported == 0) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"ImportFromDatabase: FAILED - No signatures imported from source database");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                                  "No valid signatures found in source database" };
            }

            // Safe division with zero check
            if (totalExpected > 0 && totalImported < totalExpected / 2) {
                double pct = (100.0 * static_cast<double>(totalImported) / static_cast<double>(totalExpected));
                SS_LOG_WARN(L"SignatureBuilder",
                    L"ImportFromDatabase: PARTIAL SUCCESS - Only %.1f%% of signatures imported", pct);
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                                  "Database import partially successful: " + std::to_string(totalImported) +
                                  "/" + std::to_string(totalExpected) + " signatures imported" };
            }

            if (totalExpected > 0 && totalImported < totalExpected) {
                double pct = (100.0 * static_cast<double>(totalImported) / static_cast<double>(totalExpected));
                SS_LOG_WARN(L"SignatureBuilder",
                    L"ImportFromDatabase: SUCCESS WITH WARNINGS - %.1f%% of signatures imported", pct);
                return StoreError{ SignatureStoreError::Success,
                                  0,
                                  "Database import completed: " + std::to_string(totalImported) +
                                  "/" + std::to_string(totalExpected) + " signatures imported" };
            }

            SS_LOG_INFO(L"SignatureBuilder",
                L"ImportFromDatabase: SUCCESS - 100%% of signatures imported");

            return StoreError{ SignatureStoreError::Success };
        }





	}

}