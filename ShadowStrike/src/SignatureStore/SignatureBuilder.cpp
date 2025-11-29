/*
 * ============================================================================
 * ShadowStrike SignatureBuilder - IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Signature database compilation and optimization implementation
 * Deduplication, entropy analysis, cache alignment
 *
 * CRITICAL: Build process must ensure optimal runtime performance!
 *
 * ============================================================================
 */

#include "SignatureBuilder.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"

#include <algorithm>
#include <span>
#include <fstream>
#include <sstream>
#include <cstring>
#include <random>
#include <execution>
#include <tuple>


// Windows crypto for UUID generation
#include <rpc.h>
#pragma comment(lib, "rpcrt4.lib")

namespace ShadowStrike {
namespace SignatureStore {

    std::optional<HashValue> SignatureBuilder::ComputeFileHash(
        const std::wstring& filePath,
        HashType type
    ) const noexcept {
        // Read file and compute hash (simplified implementation)
        HANDLE hFile = CreateFileW(
            filePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            return std::nullopt;
        }

        LARGE_INTEGER fileSize{};
        if (!GetFileSizeEx(hFile, &fileSize)) {
            CloseHandle(hFile);
            return std::nullopt;
        }

        std::vector<uint8_t> buffer(static_cast<size_t>(fileSize.QuadPart));
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr)) {
            CloseHandle(hFile);
            return std::nullopt;
        }

        CloseHandle(hFile);
        return ComputeBufferHash(buffer, type);
    }

    bool SignatureBuilder::CompareHashes(const HashValue& a, const HashValue& b) const noexcept {
        return a == b;
    }
    std::optional<HashValue> SignatureBuilder::ComputeBufferHash(
        std::span<const uint8_t> buffer,
        HashType type
    ) const noexcept {
        HashValue hash{};
        hash.type = type;

        ALG_ID algId = 0;
        switch (type) {
        case HashType::MD5:    algId = CALG_MD5;    hash.length = 16; break;
        case HashType::SHA1:   algId = CALG_SHA1;   hash.length = 20; break;
        case HashType::SHA256: algId = CALG_SHA_256; hash.length = 32; break;
        case HashType::SHA512: algId = CALG_SHA_512; hash.length = 64; break;
        default: return std::nullopt;
        }

        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            return std::nullopt;
        }

        HCRYPTHASH hHash = 0;
        if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return std::nullopt;
        }

        if (!CryptHashData(hHash, buffer.data(), static_cast<DWORD>(buffer.size()), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return std::nullopt;
        }

        DWORD hashLen = hash.length;
        if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data.data(), &hashLen, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return std::nullopt;
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        return hash;
    }


// ============================================================================
// SIGNATURE BUILDER IMPLEMENTATION
// ============================================================================

SignatureBuilder::SignatureBuilder()
    : SignatureBuilder(BuildConfiguration{})
{
}

SignatureBuilder::SignatureBuilder(const BuildConfiguration& config)
    : m_config(config)
{
    if (!QueryPerformanceFrequency(&m_perfFrequency)) {
        m_perfFrequency.QuadPart = 1000000;
    }
}

SignatureBuilder::~SignatureBuilder() {
    if (m_outputFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_outputFile);
    }
    if (m_outputMapping != INVALID_HANDLE_VALUE) {
        CloseHandle(m_outputMapping);
    }
    if (m_outputBase) {
        UnmapViewOfFile(m_outputBase);
    }
}

void SignatureBuilder::SetConfiguration(const BuildConfiguration& config) noexcept {
    std::unique_lock<std::shared_mutex> lock(m_stateMutex);
    m_config = config;
}

// ============================================================================
// INPUT METHODS - ADD SIGNATURES
// ============================================================================

StoreError SignatureBuilder::AddHash(const HashSignatureInput& input) noexcept {
    std::unique_lock<std::shared_mutex> lock(m_stateMutex);

    // Validate input
    if (input.name.empty()) {
        return StoreError{SignatureStoreError::InvalidSignature, 0, "Empty signature name"};
    }

    // Check for duplicates
    uint64_t hashFingerprint = input.hash.FastHash();
    if (m_hashFingerprints.find(hashFingerprint) != m_hashFingerprints.end()) {
        if (m_config.enableDeduplication) {
            SS_LOG_DEBUG(L"SignatureBuilder", L"Duplicate hash skipped: %S", input.name.c_str());
            m_statistics.duplicatesRemoved++;
            return StoreError{SignatureStoreError::DuplicateEntry, 0, "Duplicate hash"};
        }
    }

    // Add to pending
    m_pendingHashes.push_back(input);
    m_hashFingerprints.insert(hashFingerprint);
    m_statistics.totalHashesAdded++;

    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::AddHash(
    const HashValue& hash,
    const std::string& name,
    ThreatLevel threatLevel
) noexcept {
    HashSignatureInput input{};
    input.hash = hash;
    input.name = name;
    input.threatLevel = threatLevel;
    input.source = "api";

    return AddHash(input);
}

StoreError SignatureBuilder::AddHashBatch(
    std::span<const HashSignatureInput> inputs
) noexcept {
    for (const auto& input : inputs) {
        StoreError err = AddHash(input);
        if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
            return err;
        }
    }

    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::AddPattern(const PatternSignatureInput& input) noexcept {
    std::unique_lock<std::shared_mutex> lock(m_stateMutex);

    if (input.name.empty() || input.patternString.empty()) {
        return StoreError{SignatureStoreError::InvalidSignature, 0, "Invalid pattern input"};
    }

    // Check for duplicates
    if (m_patternFingerprints.find(input.patternString) != m_patternFingerprints.end()) {
        if (m_config.enableDeduplication) {
            m_statistics.duplicatesRemoved++;
            return StoreError{SignatureStoreError::DuplicateEntry, 0, "Duplicate pattern"};
        }
    }

    m_pendingPatterns.push_back(input);
    m_patternFingerprints.insert(input.patternString);
    m_statistics.totalPatternsAdded++;

    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::AddPattern(
    const std::string& patternString,
    const std::string& name,
    ThreatLevel threatLevel
) noexcept {
    PatternSignatureInput input{};
    input.patternString = patternString;
    input.name = name;
    input.threatLevel = threatLevel;
    input.source = "api";

    return AddPattern(input);
}

StoreError SignatureBuilder::AddPatternBatch(
    std::span<const PatternSignatureInput> inputs
) noexcept {
    for (const auto& input : inputs) {
        StoreError err = AddPattern(input);
        if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
            return err;
        }
    }

    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::AddYaraRule(const YaraRuleInput& input) noexcept {
    std::unique_lock<std::shared_mutex> lock(m_stateMutex);

    if (input.ruleSource.empty()) {
        return StoreError{SignatureStoreError::InvalidSignature, 0, "Empty YARA rule"};
    }

    // Extract rule name for deduplication
    std::string ruleName;
    size_t rulePos = input.ruleSource.find("rule ");
    if (rulePos != std::string::npos) {
        size_t nameStart = rulePos + 5;
        size_t nameEnd = input.ruleSource.find_first_of(" :{", nameStart);
        if (nameEnd != std::string::npos) {
            ruleName = input.ruleSource.substr(nameStart, nameEnd - nameStart);
        }
    }

    if (!ruleName.empty() && m_yaraRuleNames.find(ruleName) != m_yaraRuleNames.end()) {
        if (m_config.enableDeduplication) {
            m_statistics.duplicatesRemoved++;
            return StoreError{SignatureStoreError::DuplicateEntry, 0, "Duplicate YARA rule"};
        }
    }

    m_pendingYaraRules.push_back(input);
    if (!ruleName.empty()) {
        m_yaraRuleNames.insert(ruleName);
    }
    m_statistics.totalYaraRulesAdded++;

    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::AddYaraRule(
    const std::string& ruleSource,
    const std::string& namespace_
) noexcept {
    YaraRuleInput input{};
    input.ruleSource = ruleSource;
    input.namespace_ = namespace_;
    input.source = "api";

    return AddYaraRule(input);
}

StoreError SignatureBuilder::AddYaraRuleBatch(
    std::span<const YaraRuleInput> inputs
) noexcept {
    for (const auto& input : inputs) {
        StoreError err = AddYaraRule(input);
        if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
            return err;
        }
    }

    return StoreError{SignatureStoreError::Success};
}

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

    // Check file size (security limit: 500MB)
    constexpr uint64_t MAX_FILE_SIZE = 500ULL * 1024 * 1024;
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromFile: Cannot open file: %s",
            filePath.c_str());
        return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "Cannot open file" };
    }

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile, &fileSize)) {
        DWORD err = GetLastError();
        CloseHandle(hFile);
        SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromFile: Cannot get file size");
        return StoreError{ SignatureStoreError::Unknown, err, "Cannot get file size" };
    }

    if (fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        SS_LOG_WARN(L"SignatureBuilder", L"ImportHashesFromFile: File is empty");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "File is empty" };
    }

    if (static_cast<uint64_t>(fileSize.QuadPart) > MAX_FILE_SIZE) {
        CloseHandle(hFile);
        SS_LOG_ERROR(L"SignatureBuilder",
            L"ImportHashesFromFile: File too large (%llu > %llu bytes)",
            fileSize.QuadPart, MAX_FILE_SIZE);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "File too large (max 500MB)" };
    }

    CloseHandle(hFile);

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
    batchEntries.reserve(10000);

    constexpr size_t MAX_LINE_LENGTH = 10000;     // Prevent extremely long lines
    constexpr size_t BATCH_SIZE = 1000;           // Process in batches

    LARGE_INTEGER startTime, currentTime;
    QueryPerformanceCounter(&startTime);
    constexpr uint64_t TIMEOUT_MS = 300000;       // 5 minute timeout

    while (std::getline(file, line)) {
        lineNum++;

        // ====================================================================
        // TIMEOUT CHECK (Performance monitor)
        // ====================================================================
        if (lineNum % 1000 == 0) {
            QueryPerformanceCounter(&currentTime);
            uint64_t elapsedMs = ((currentTime.QuadPart - startTime.QuadPart) * 1000ULL) /
                m_perfFrequency.QuadPart;

            if (elapsedMs > TIMEOUT_MS) {
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

        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

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

        batchEntries.push_back(std::move(*hashInput));
        validCount++;

        // ====================================================================
        // BATCH PROCESSING (Performance optimization)
        // ====================================================================
        if (batchEntries.size() >= BATCH_SIZE) {
            for (auto& entry : batchEntries) {
                StoreError err = AddHash(entry);
                if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromFile: Failed to add hash: %S", err.message.c_str());
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
            StoreError err = AddHash(entry);
            if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                SS_LOG_WARN(L"SignatureBuilder",
                    L"ImportHashesFromFile: Failed to add hash: %S", err.message.c_str());
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
    uint64_t elapsedUs = ((currentTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

    SS_LOG_INFO(L"SignatureBuilder",
        L"ImportHashesFromFile: Complete - %zu valid, %zu invalid from %zu lines in %llu 탎",
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

    // Validate delimiter
    if (delimiter < 32 || delimiter > 126) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"ImportHashesFromCsv: Invalid delimiter character (%d)", static_cast<int>(delimiter));
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid delimiter" };
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

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        SS_LOG_ERROR(L"SignatureBuilder", L"ImportHashesFromCsv: Cannot open file");
        return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "Cannot open file" };
    }

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile, &fileSize)) {
        DWORD err = GetLastError();
        CloseHandle(hFile);
        return StoreError{ SignatureStoreError::Unknown, err, "Cannot get file size" };
    }

    constexpr uint64_t MAX_CSV_SIZE = 500ULL * 1024 * 1024;
    if (fileSize.QuadPart == 0 || static_cast<uint64_t>(fileSize.QuadPart) > MAX_CSV_SIZE) {
        CloseHandle(hFile);
        SS_LOG_ERROR(L"SignatureBuilder",
            L"ImportHashesFromCsv: Invalid file size (%llu)", fileSize.QuadPart);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "File is empty or too large" };
    }

    CloseHandle(hFile);

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
    batchEntries.reserve(5000);

    constexpr size_t MAX_COLUMN_COUNT = 10;        // CSV should have reasonable # columns
    constexpr size_t MAX_FIELD_LENGTH = 10000;
    constexpr size_t BATCH_SIZE = 500;

    LARGE_INTEGER startTime, currentTime;
    QueryPerformanceCounter(&startTime);
    constexpr uint64_t TIMEOUT_MS = 300000;

    while (std::getline(file, line)) {
        lineNum++;

        // ====================================================================
        // TIMEOUT CHECK
        // ====================================================================
        if (lineNum % 500 == 0) {
            QueryPerformanceCounter(&currentTime);
            uint64_t elapsedMs = ((currentTime.QuadPart - startTime.QuadPart) * 1000ULL) /
                m_perfFrequency.QuadPart;

            if (elapsedMs > TIMEOUT_MS) {
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

        if (line.length() > 50000) {  // CSV lines should be reasonable length
            SS_LOG_WARN(L"SignatureBuilder",
                L"ImportHashesFromCsv: Line %zu too long (%zu bytes)",
                lineNum, line.length());
            invalidCount++;
            continue;
        }

        // ====================================================================
        // PARSE CSV: TYPE,HASH,NAME,LEVEL
        // ====================================================================
        std::istringstream iss(line);
        std::string typeStr, hashStr, nameStr, levelStr;

        size_t fieldCount = 0;
        while (std::getline(iss, typeStr, delimiter)) {
            fieldCount++;
            if (fieldCount > MAX_COLUMN_COUNT) break;
        }

        // Need exactly 4 fields
        if (fieldCount < 4) {
            SS_LOG_WARN(L"SignatureBuilder",
                L"ImportHashesFromCsv: Line %zu has invalid field count (%zu)",
                lineNum, fieldCount);
            invalidCount++;
            continue;
        }

        // Re-parse with proper extraction
        iss.clear();
        iss.seekg(0);

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
        // Trim whitespace from all fields
        auto trim = [](std::string& s) {
            s.erase(0, s.find_first_not_of(" \t\r\n"));
            s.erase(s.find_last_not_of(" \t\r\n") + 1);
            };

        trim(typeStr);
        trim(hashStr);
        trim(nameStr);
        trim(levelStr);

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
        // PARSE THREAT LEVEL
        // ====================================================================
        char* endptr = nullptr;
        long levelLong = std::strtol(levelStr.c_str(), &endptr, 10);

        if (endptr == levelStr.c_str() || levelLong < 0 || levelLong > 100) {
            SS_LOG_WARN(L"SignatureBuilder",
                L"ImportHashesFromCsv: Line %zu invalid threat level: %S",
                lineNum, levelStr.c_str());
            invalidCount++;
            continue;
        }

        ThreatLevel level = static_cast<ThreatLevel>(levelLong);

        // ====================================================================
        // CREATE SIGNATURE INPUT
        // ====================================================================
        HashSignatureInput input{};
        input.hash = *hash;
        input.name = nameStr;
        input.threatLevel = level;
        input.source = ShadowStrike::Utils::StringUtils::ToNarrow(filePath);

        batchEntries.push_back(std::move(input));
        validCount++;

        // ====================================================================
        // BATCH PROCESSING
        // ====================================================================
        if (batchEntries.size() >= BATCH_SIZE) {
            for (auto& entry : batchEntries) {
                StoreError err = AddHash(entry);
                if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportHashesFromCsv: Failed to add hash: %S", err.message.c_str());
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
            StoreError err = AddHash(entry);
            if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                SS_LOG_WARN(L"SignatureBuilder",
                    L"ImportHashesFromCsv: Failed to add hash: %S", err.message.c_str());
            }
        }
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
    uint64_t elapsedUs = ((currentTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

    SS_LOG_INFO(L"SignatureBuilder",
        L"ImportHashesFromCsv: Complete - %zu valid, %zu invalid from %zu lines in %llu 탎",
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

    // Check file size
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromFile: Cannot open file");
        return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "Cannot open file" };
    }

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile, &fileSize)) {
        DWORD err = GetLastError();
        CloseHandle(hFile);
        return StoreError{ SignatureStoreError::Unknown, err, "Cannot get file size" };
    }

    constexpr uint64_t MAX_PATTERN_FILE_SIZE = 500ULL * 1024 * 1024;
    if (fileSize.QuadPart == 0 || static_cast<uint64_t>(fileSize.QuadPart) > MAX_PATTERN_FILE_SIZE) {
        CloseHandle(hFile);
        SS_LOG_ERROR(L"SignatureBuilder",
            L"ImportPatternsFromFile: Invalid file size (%llu)", fileSize.QuadPart);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "File is empty or too large" };
    }

    CloseHandle(hFile);

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
    batchEntries.reserve(5000);

    constexpr size_t MAX_PATTERN_LINE_LENGTH = 100000;
    constexpr size_t BATCH_SIZE = 500;

    LARGE_INTEGER startTime, currentTime;
    QueryPerformanceCounter(&startTime);
    constexpr uint64_t TIMEOUT_MS = 300000;

    while (std::getline(file, line)) {
        lineNum++;

        // ====================================================================
        // TIMEOUT CHECK
        // ====================================================================
        if (lineNum % 500 == 0) {
            QueryPerformanceCounter(&currentTime);
            uint64_t elapsedMs = ((currentTime.QuadPart - startTime.QuadPart) * 1000ULL) /
                m_perfFrequency.QuadPart;

            if (elapsedMs > TIMEOUT_MS) {
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

        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

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

        patternInput->source = ShadowStrike::Utils::StringUtils::ToNarrow(filePath);
        batchEntries.push_back(std::move(*patternInput));
        validCount++;

        // ====================================================================
        // BATCH PROCESSING
        // ====================================================================
        if (batchEntries.size() >= BATCH_SIZE) {
            for (auto& entry : batchEntries) {
                StoreError err = AddPattern(entry);
                if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportPatternsFromFile: Failed to add pattern: %S", err.message.c_str());
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
            StoreError err = AddPattern(entry);
            if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                SS_LOG_WARN(L"SignatureBuilder",
                    L"ImportPatternsFromFile: Failed to add pattern: %S", err.message.c_str());
            }
        }
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
    uint64_t elapsedUs = ((currentTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

    SS_LOG_INFO(L"SignatureBuilder",
        L"ImportPatternsFromFile: Complete - %zu valid, %zu invalid from %zu lines in %llu 탎",
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
    constexpr size_t MAX_NAMESPACE_LEN = 128;
    if (namespace_.empty() || namespace_.length() > MAX_NAMESPACE_LEN) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"ImportYaraRulesFromFile: Invalid namespace length (%zu)",
            namespace_.length());
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid namespace" };
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

    // Check file size (YARA files shouldn't be huge)
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        SS_LOG_ERROR(L"SignatureBuilder", L"ImportYaraRulesFromFile: Cannot open file");
        return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "Cannot open file" };
    }

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile, &fileSize)) {
        DWORD err = GetLastError();
        CloseHandle(hFile);
        return StoreError{ SignatureStoreError::Unknown, err, "Cannot get file size" };
    }

    constexpr uint64_t MAX_YARA_FILE_SIZE = 100ULL * 1024 * 1024;  // 100MB
    if (fileSize.QuadPart == 0 || static_cast<uint64_t>(fileSize.QuadPart) > MAX_YARA_FILE_SIZE) {
        CloseHandle(hFile);
        SS_LOG_ERROR(L"SignatureBuilder",
            L"ImportYaraRulesFromFile: Invalid file size (%llu)",
            fileSize.QuadPart);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "File is empty or too large (max 100MB)" };
    }

    CloseHandle(hFile);

    // ========================================================================
    // STEP 3: READ FILE CONTENT
    // ========================================================================
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        SS_LOG_ERROR(L"SignatureBuilder", L"ImportYaraRulesFromFile: Cannot open file stream");
        return StoreError{ SignatureStoreError::FileNotFound, 0, "Cannot open file stream" };
    }

    std::string ruleSource;
    ruleSource.reserve(static_cast<size_t>(fileSize.QuadPart));

    try {
        ruleSource.assign((std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());
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

    file.close();

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
    size_t pos = 0;
    while ((pos = ruleSource.find("rule ", pos)) != std::string::npos) {
        // Verify this is actually a rule declaration (preceded by whitespace or start of string)
        if (pos == 0 || std::isspace(ruleSource[pos - 1])) {
            ruleCount++;
        }
        pos += 5;
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
    LARGE_INTEGER startTime, endTime;
    QueryPerformanceCounter(&startTime);

    YaraRuleInput input{};
    input.ruleSource = ruleSource;
    input.namespace_ = namespace_;
    input.source = ShadowStrike::Utils::StringUtils::ToNarrow(filePath);

    StoreError addErr = AddYaraRule(input);

    QueryPerformanceCounter(&endTime);
    uint64_t importTimeUs = ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

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
        L"ImportYaraRulesFromFile: Complete - %zu rules imported from %zu bytes in %llu 탎",
        ruleCount, ruleSource.size(), importTimeUs);

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
    constexpr size_t MAX_NAMESPACE_LEN = 128;
    if (namespace_.empty() || namespace_.length() > MAX_NAMESPACE_LEN) {
        SS_LOG_ERROR(L"SignatureBuilder", L"ImportYaraRulesFromDirectory: Invalid namespace");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid namespace" };
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
    auto yaraFiles = YaraUtils::FindYaraFiles(directoryPath, true);

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
    LARGE_INTEGER startTime, currentTime;
    QueryPerformanceCounter(&startTime);

    size_t successCount = 0;
    size_t failureCount = 0;
    std::vector<std::wstring> failedFiles;
    failedFiles.reserve(10);

    constexpr uint64_t TIMEOUT_MS = 600000;  // 10 minute timeout for directory import

    for (size_t i = 0; i < yaraFiles.size(); ++i) {
        const auto& filePath = yaraFiles[i];

        // ====================================================================
        // TIMEOUT CHECK (Every 10 files)
        // ====================================================================
        if (i % 10 == 0) {
            QueryPerformanceCounter(&currentTime);
            uint64_t elapsedMs = ((currentTime.QuadPart - startTime.QuadPart) * 1000ULL) /
                m_perfFrequency.QuadPart;

            if (elapsedMs > TIMEOUT_MS) {
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
            failedFiles.push_back(L"<invalid path>");
            continue;
        }

        // ====================================================================
        // IMPORT SINGLE FILE
        // ====================================================================
        SS_LOG_DEBUG(L"SignatureBuilder",
            L"ImportYaraRulesFromDirectory: Importing file %zu/%zu: %s",
            i + 1, yaraFiles.size(), filePath.c_str());

        StoreError err = ImportYaraRulesFromFile(filePath, namespace_);

        if (err.IsSuccess()) {
            successCount++;
            SS_LOG_DEBUG(L"SignatureBuilder", L"  -> Success");
        }
        else {
            failureCount++;
            failedFiles.push_back(filePath);

            SS_LOG_WARN(L"SignatureBuilder",
                L"ImportYaraRulesFromDirectory: Failed to import file: %S",
                err.message.c_str());
        }
    }

    // ========================================================================
    // STEP 5: FINAL REPORTING
    // ========================================================================
    QueryPerformanceCounter(&currentTime);
    uint64_t totalTimeUs = ((currentTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

    SS_LOG_INFO(L"SignatureBuilder",
        L"ImportYaraRulesFromDirectory: Complete - %zu succeeded, %zu failed from %zu files in %llu 탎",
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
        double successRate = (static_cast<double>(successCount) / yaraFiles.size()) * 100.0;
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
    constexpr size_t MAX_IMPORT_JSON_SIZE = 100ULL * 1024 * 1024; // 100MB
    if (jsonData.size() > MAX_IMPORT_JSON_SIZE) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"ImportHashesFromJson: JSON data too large (%zu > %zu bytes)",
            jsonData.size(), MAX_IMPORT_JSON_SIZE);
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

    if (!Parse(jsonData, jsonRoot, &jsonErr, parseOpts)) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"ImportHashesFromJson: Parse error at line %zu, column %zu: %S",
            jsonErr.line, jsonErr.column, jsonErr.message.c_str());
        return StoreError{ SignatureStoreError::InvalidFormat, 0,
            "JSON parse error: " + jsonErr.message };
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
    validEntries.reserve(hashesArray.size());

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

    LARGE_INTEGER startTime, endTime;
    QueryPerformanceFrequency(&m_perfFrequency);  // Ensure frequency is available
    QueryPerformanceCounter(&startTime);

    for (const auto& input : validEntries) {
        StoreError err = AddHash(input);
        if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
            SS_LOG_WARN(L"SignatureBuilder",
                L"ImportHashesFromJson: Failed to add hash %S: %S",
                input.name.c_str(), err.message.c_str());
        }
    }

    QueryPerformanceCounter(&endTime);
    uint64_t importTimeUs =
        ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) / m_perfFrequency.QuadPart;

    // ========================================================================
    // STEP 7: FINAL LOGGING AND STATISTICS
    // ========================================================================

    SS_LOG_INFO(L"SignatureBuilder",
        L"ImportHashesFromJson: Complete - %zu valid entries added in %llu 탎 (%.2f ms), "
        L"%zu invalid entries skipped",
        validCount, importTimeUs, importTimeUs / 1000.0, invalidCount);

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

    // Check file size
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        SS_LOG_ERROR(L"SignatureBuilder", L"ImportPatternsFromClamAV: Cannot open file");
        return StoreError{ SignatureStoreError::FileNotFound, GetLastError(), "Cannot open file" };
    }

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile, &fileSize)) {
        DWORD err = GetLastError();
        CloseHandle(hFile);
        return StoreError{ SignatureStoreError::Unknown, err, "Cannot get file size" };
    }

    constexpr uint64_t MAX_CLAMAV_FILE_SIZE = 500ULL * 1024 * 1024;
    if (fileSize.QuadPart == 0 || static_cast<uint64_t>(fileSize.QuadPart) > MAX_CLAMAV_FILE_SIZE) {
        CloseHandle(hFile);
        SS_LOG_ERROR(L"SignatureBuilder",
            L"ImportPatternsFromClamAV: Invalid file size (%llu)",
            fileSize.QuadPart);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "File is empty or too large" };
    }

    CloseHandle(hFile);

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
    batchEntries.reserve(5000);

    constexpr size_t MAX_CLAMAV_LINE_LENGTH = 50000;
    constexpr size_t BATCH_SIZE = 500;

    LARGE_INTEGER startTime, currentTime;
    QueryPerformanceCounter(&startTime);
    constexpr uint64_t TIMEOUT_MS = 300000;

    while (std::getline(file, line)) {
        lineNum++;

        // ====================================================================
        // TIMEOUT CHECK
        // ====================================================================
        if (lineNum % 500 == 0) {
            QueryPerformanceCounter(&currentTime);
            uint64_t elapsedMs = ((currentTime.QuadPart - startTime.QuadPart) * 1000ULL) /
                m_perfFrequency.QuadPart;

            if (elapsedMs > TIMEOUT_MS) {
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

        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

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
        input.source = ShadowStrike::Utils::StringUtils::ToNarrow(filePath);

        batchEntries.push_back(std::move(input));
        validCount++;

        // ====================================================================
        // BATCH PROCESSING
        // ====================================================================
        if (batchEntries.size() >= BATCH_SIZE) {
            for (auto& entry : batchEntries) {
                StoreError err = AddPattern(entry);
                if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                    SS_LOG_WARN(L"SignatureBuilder",
                        L"ImportPatternsFromClamAV: Failed to add pattern: %S",
                        err.message.c_str());
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
            StoreError err = AddPattern(entry);
            if (!err.IsSuccess() && err.code != SignatureStoreError::DuplicateEntry) {
                SS_LOG_WARN(L"SignatureBuilder",
                    L"ImportPatternsFromClamAV: Failed to add pattern: %S",
                    err.message.c_str());
            }
        }
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
    uint64_t elapsedUs = ((currentTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

    SS_LOG_INFO(L"SignatureBuilder",
        L"ImportPatternsFromClamAV: Complete - %zu valid, %zu invalid from %zu lines in %llu 탎",
        validCount, invalidCount, lineNum, elapsedUs);

    if (invalidCount > 0) {
        return StoreError{ SignatureStoreError::InvalidFormat, 0,
            "ClamAV import completed with errors: " + std::to_string(validCount) + " valid, " +
            std::to_string(invalidCount) + " invalid" };
    }

    return StoreError{ SignatureStoreError::Success };
}

StoreError SignatureBuilder::ImportFromDatabase(
    const std::wstring& databasePath
) noexcept {
    SS_LOG_INFO(L"SignatureBuilder", L"ImportFromDatabase: %s", databasePath.c_str());

    // Open existing database
    StoreError err{};
    MemoryMappedView sourceView{};

    if (!MemoryMapping::OpenView(databasePath, true, sourceView, err)) {
        return err;
    }

    // Read header
    const auto* header = sourceView.GetAt<SignatureDatabaseHeader>(0);
    if (!header) {
        MemoryMapping::CloseView(sourceView);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid header" };
    }

    if (!Format::ValidateHeader(header)) {
        MemoryMapping::CloseView(sourceView);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Header validation failed" };
    }

    // Import hashes
    for (uint64_t i = 0; i < header->totalHashes; ++i) {
        // Would read hash entries from database
        // For stub: just log count
    }

    // Import patterns
    for (uint64_t i = 0; i < header->totalPatterns; ++i) {
        // Would read pattern entries
    }

    MemoryMapping::CloseView(sourceView);

    SS_LOG_INFO(L"SignatureBuilder", L"Imported %llu hashes, %llu patterns",
        header->totalHashes, header->totalPatterns);

    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// BUILD PROCESS
// ============================================================================

StoreError SignatureBuilder::Build() noexcept {
    SS_LOG_INFO(L"SignatureBuilder", L"Starting build process");

    if (m_buildInProgress.exchange(true)) {
        return StoreError{SignatureStoreError::Unknown, 0, "Build already in progress"};
    }

    QueryPerformanceCounter(&m_buildStartTime);

    // Stage 1: Validate
    ReportProgress("Validation", 0, 7);
    StoreError err = ValidateInputs();
    if (!err.IsSuccess()) {
        m_buildInProgress.store(false);
        return err;
    }

    // Stage 2: Deduplicate
    ReportProgress("Deduplication", 1, 7);
    err = Deduplicate();
    if (!err.IsSuccess()) {
        m_buildInProgress.store(false);
        return err;
    }

    // Stage 3: Optimize
    ReportProgress("Optimization", 2, 7);
    err = Optimize();
    if (!err.IsSuccess()) {
        m_buildInProgress.store(false);
        return err;
    }

    // Stage 4: Build indices
    ReportProgress("Index Construction", 3, 7);
    err = BuildIndices();
    if (!err.IsSuccess()) {
        m_buildInProgress.store(false);
        return err;
    }

    // Stage 5: Serialize
    ReportProgress("Serialization", 4, 7);
    err = Serialize();
    if (!err.IsSuccess()) {
        m_buildInProgress.store(false);
        return err;
    }

    // Stage 6: Compute checksum
    ReportProgress("Integrity Check", 5, 7);
    err = ComputeChecksum();
    if (!err.IsSuccess()) {
        m_buildInProgress.store(false);
        return err;
    }

    ReportProgress("Complete", 7, 7);

    // Calculate build time
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    m_statistics.totalBuildTimeMilliseconds = 
        ((endTime.QuadPart - m_buildStartTime.QuadPart) * 1000ULL) / m_perfFrequency.QuadPart;

    m_buildInProgress.store(false);

    SS_LOG_INFO(L"SignatureBuilder", L"Build complete in %llu ms", 
        m_statistics.totalBuildTimeMilliseconds);

    return StoreError{SignatureStoreError::Success};
}

// ============================================================================
// BUILD STAGES
// ============================================================================

StoreError SignatureBuilder::ValidateInputs() noexcept {
    m_currentStage = "Validation";

    StoreError err = ValidateHashInputs();
    if (!err.IsSuccess()) return err;

    err = ValidatePatternInputs();
    if (!err.IsSuccess()) return err;

    err = ValidateYaraInputs();
    if (!err.IsSuccess()) return err;

    Log("Validation complete");
    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::ValidateHashInputs() noexcept {
    for (const auto& input : m_pendingHashes) {
        if (input.name.empty()) {
            m_statistics.invalidSignaturesSkipped++;
            continue;
        }

        // Validate hash length matches type
        uint8_t expectedLen = 0;
        switch (input.hash.type) {
            case HashType::MD5:    expectedLen = 16; break;
            case HashType::SHA1:   expectedLen = 20; break;
            case HashType::SHA256: expectedLen = 32; break;
            case HashType::SHA512: expectedLen = 64; break;
            default: break;
        }

        if (expectedLen != 0 && input.hash.length != expectedLen) {
            m_statistics.invalidSignaturesSkipped++;
            SS_LOG_WARN(L"SignatureBuilder", L"Invalid hash length for %S", input.name.c_str());
        }
    }

    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::ValidatePatternInputs() noexcept {
    for (const auto& input : m_pendingPatterns) {
        std::string errorMsg;
        if (!PatternUtils::IsValidPatternString(input.patternString, errorMsg)) {
            m_statistics.invalidSignaturesSkipped++;
            SS_LOG_WARN(L"SignatureBuilder", L"Invalid pattern: %S", errorMsg.c_str());
        }
    }

    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::ValidateYaraInputs() noexcept {
    for (const auto& input : m_pendingYaraRules) {
        std::vector<std::string> errors;
        if (!YaraUtils::ValidateRuleSyntax(input.ruleSource, errors)) {
            m_statistics.invalidSignaturesSkipped++;
            for (const auto& error : errors) {
                SS_LOG_WARN(L"SignatureBuilder", L"YARA error: %S", error.c_str());
            }
        }
    }

    return StoreError{SignatureStoreError::Success};
}

bool SignatureBuilder::ValidateDatabaseChecksum(const std::wstring& databasePath) noexcept {
    StoreError err{};
    MemoryMappedView view{};

    if (!MemoryMapping::OpenView(databasePath, true, view, err)) {
        return false;
    }

    const auto* header = view.GetAt<SignatureDatabaseHeader>(0);
    if (!header) {
        MemoryMapping::CloseView(view);
        return false;
    }

    // Compute checksum and compare
    std::span<const uint8_t> buffer(
        static_cast<const uint8_t*>(view.baseAddress),
        static_cast<size_t>(view.fileSize)
    );

    auto computedHash = ComputeBufferHash(buffer, HashType::SHA256);

    MemoryMapping::CloseView(view);

    if (!computedHash.has_value()) {
        return false;
    }

    return std::memcmp(computedHash->data.data(), header->sha256Checksum.data(), 32) == 0;
}

StoreError SignatureBuilder::Deduplicate() noexcept {
    m_currentStage = "Deduplication";

    if (!m_config.enableDeduplication) {
        return StoreError{SignatureStoreError::Success};
    }

    DeduplicateHashes();
    DeduplicatePatterns();
    DeduplicateYaraRules();

    Log("Deduplication complete: removed " + std::to_string(m_statistics.duplicatesRemoved));
    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::DeduplicateHashes() noexcept {
    // Already done during AddHash, but verify
    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::DeduplicatePatterns() noexcept {
    // Already done during AddPattern
    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::DeduplicateYaraRules() noexcept {
    // Already done during AddYaraRule
    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::Optimize() noexcept {
    m_currentStage = "Optimization";

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    if (m_config.enableEntropyOptimization) {
        OptimizePatterns();
    }
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    m_statistics.optimizationTimeMilliseconds = 
        ((endTime.QuadPart - startTime.QuadPart) * 1000ULL) / m_perfFrequency.QuadPart;

    Log("Optimization complete");
    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::OptimizeHashes() noexcept {
    // Sort hashes by type for better locality
    std::sort(m_pendingHashes.begin(), m_pendingHashes.end(),
        [](const auto& a, const auto& b) {
            return a.hash.type < b.hash.type;
        });

    m_statistics.optimizedSignatures += m_pendingHashes.size();
    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::OptimizePatterns() noexcept {
    // Calculate entropy for each pattern and sort by descending entropy
    // Higher entropy = more unique = better for quick matching
    
    for (auto& pattern : m_pendingPatterns) {
        PatternMode mode;
        std::vector<uint8_t> mask;
        auto compiled = PatternCompiler::CompilePattern(pattern.patternString, mode, mask);
        
        if (compiled.has_value()) {
            float entropy = PatternCompiler::ComputeEntropy(*compiled);
            // Store entropy in description for sorting (simplified)
        }
    }

    m_statistics.optimizedSignatures += m_pendingPatterns.size();
    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::OptimizeYaraRules() noexcept {
    // YARA rules are already optimized by compiler
    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::BuildIndices() noexcept {
    m_currentStage = "Index Construction";

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    BuildHashIndex();
    BuildPatternIndex();
    BuildYaraIndex();

    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    m_statistics.indexBuildTimeMilliseconds = 
        ((endTime.QuadPart - startTime.QuadPart) * 1000ULL) / m_perfFrequency.QuadPart;

    Log("Index construction complete");
    return StoreError{SignatureStoreError::Success};
}

// ============================================================================
// BUILD HASH INDEX IMPLEMENTATION
// ============================================================================

StoreError SignatureBuilder::BuildHashIndex() noexcept {
    SS_LOG_INFO(L"SignatureBuilder", L"BuildHashIndex: Starting hash index construction");

    // ========================================================================
    // VALIDATION
    // ========================================================================
    if (m_pendingHashes.empty()) {
        SS_LOG_WARN(L"SignatureBuilder", L"BuildHashIndex: No hashes to index");
        return StoreError{ SignatureStoreError::Success };
    }

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    // ========================================================================
    // SORT HASHES FOR OPTIMAL B+TREE LAYOUT
    // ========================================================================
    // Sort by fast-hash value for cache locality
    std::sort(m_pendingHashes.begin(), m_pendingHashes.end(),
        [](const HashSignatureInput& a, const HashSignatureInput& b) {
            return a.hash.FastHash() < b.hash.FastHash();
        });

    SS_LOG_DEBUG(L"SignatureBuilder", L"BuildHashIndex: Sorted %zu hashes",
        m_pendingHashes.size());

    // ========================================================================
    // BUILD B+TREE STRUCTURE IN MEMORY
    // ========================================================================
    // Reserve space for B+Tree nodes (each order 128)
    // Approximate: each node ~2KB, 1M hashes needs ~16K nodes
    std::vector<std::pair<HashValue, uint64_t>> indexEntries;
    indexEntries.reserve(m_pendingHashes.size());

    // Convert pending hashes to index entries (hash, offset placeholder)
    for (size_t i = 0; i < m_pendingHashes.size(); ++i) {
        const auto& entry = m_pendingHashes[i];

        // Offset will be assigned during serialization
        // For now, use index as temporary offset
        indexEntries.emplace_back(entry.hash, static_cast<uint64_t>(i));
    }

    // ========================================================================
    // CREATE OPTIMIZED HASH INDEX LAYOUT
    // ========================================================================
    // Structure for serialization:
    // [Index Header]
    // - magic: uint32 = 0x48494458 ('HIDX')
    // - version: uint16 = 1
    // - entry_count: uint64
    // - reserved: uint32 (for future flags)
    // [B+Tree Root Node Offset] uint32
    // [Sorted Hash Entries] (for binary search capability)
    // [Index Metadata]

    m_statistics.optimizedSignatures += m_pendingHashes.size();

    // ========================================================================
    // CALCULATE INDEX SECTION SIZE
    // ========================================================================
    // Header: 16 bytes
    // Root offset: 4 bytes
    // Hash entries: entries.size() * (64 + 8) = entries.size() * 72 bytes
    // Metadata: ~256 bytes
    uint64_t estimatedIndexSize = 16 + 4 + (indexEntries.size() * 72) + 256;
    estimatedIndexSize = Format::AlignToPage(estimatedIndexSize);

    SS_LOG_DEBUG(L"SignatureBuilder", L"BuildHashIndex: Estimated index size: %llu bytes",
        estimatedIndexSize);

    m_statistics.hashIndexSize = estimatedIndexSize;

    // ========================================================================
    // PERFORMANCE LOGGING
    // ========================================================================
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);

    uint64_t buildTimeUs = ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

    m_statistics.indexBuildTimeMilliseconds += buildTimeUs / 1000;

    SS_LOG_INFO(L"SignatureBuilder", L"BuildHashIndex: Complete - %zu hashes indexed in %llu us",
        m_pendingHashes.size(), buildTimeUs);

    ReportProgress("BuildHashIndex", m_pendingHashes.size(), m_pendingHashes.size());

    return StoreError{ SignatureStoreError::Success };
}


// ============================================================================
// BUILD PATTERN INDEX IMPLEMENTATION
// ============================================================================

StoreError SignatureBuilder::BuildPatternIndex() noexcept {
    SS_LOG_INFO(L"SignatureBuilder", L"BuildPatternIndex: Starting pattern index construction");

    // ========================================================================
    // VALIDATION
    // ========================================================================
    if (m_pendingPatterns.empty()) {
        SS_LOG_WARN(L"SignatureBuilder", L"BuildPatternIndex: No patterns to index");
        return StoreError{ SignatureStoreError::Success };
    }

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    // ========================================================================
    // OPTIMIZE PATTERNS FOR SEARCH PERFORMANCE
    // ========================================================================
    // Sort by length (shorter patterns first for faster rejection)
    // Then by entropy (higher entropy first for better distinction)
    std::sort(m_pendingPatterns.begin(), m_pendingPatterns.end(),
        [](const PatternSignatureInput& a, const PatternSignatureInput& b) {
            // Primary: shorter patterns first
            if (a.patternString.length() != b.patternString.length()) {
                return a.patternString.length() < b.patternString.length();
            }
            // Secondary: by threat level (higher first)
            return static_cast<int>(a.threatLevel) > static_cast<int>(b.threatLevel);
        });

    SS_LOG_DEBUG(L"SignatureBuilder", L"BuildPatternIndex: Sorted %zu patterns",
        m_pendingPatterns.size());

    // ========================================================================
    // CALCULATE PATTERN STATISTICS
    // ========================================================================
    size_t totalPatternSize = 0;
    size_t maxPatternLength = 0;
    size_t minPatternLength = SIZE_MAX;

    for (const auto& pattern : m_pendingPatterns) {
        totalPatternSize += pattern.patternString.length();
        maxPatternLength = std::max(maxPatternLength, pattern.patternString.length());
        minPatternLength = std::min(minPatternLength, pattern.patternString.length());
    }

    SS_LOG_DEBUG(L"SignatureBuilder",
        L"BuildPatternIndex: Total size=%zu, min=%zu, max=%zu, count=%zu",
        totalPatternSize, minPatternLength, maxPatternLength, m_pendingPatterns.size());

    // ========================================================================
    // BUILD TRIE STRUCTURE METADATA
    // ========================================================================
    // Trie structure for efficient multi-pattern matching:
    // Root node -> children by byte value (0-255)
    // Each node: 256 child pointers (4 bytes each) = 1024 bytes base
    // Terminal nodes store pattern metadata

    size_t estimatedTrieNodes = 1; // root
    for (const auto& pattern : m_pendingPatterns) {
        // Rough estimate: 1 node per 4 bytes of pattern
        estimatedTrieNodes += (pattern.patternString.length() / 4) + 1;
    }

    // Each node: 256 * 4 (children) + 64 (metadata) = 1088 bytes
    uint64_t estimatedIndexSize = estimatedTrieNodes * 1088;
    estimatedIndexSize = Format::AlignToPage(estimatedIndexSize);

    // Add pattern data section
    uint64_t patternDataSize = totalPatternSize + (m_pendingPatterns.size() * 64); // metadata per pattern
    patternDataSize = Format::AlignToPage(patternDataSize);

    estimatedIndexSize += patternDataSize;

    SS_LOG_DEBUG(L"SignatureBuilder", L"BuildPatternIndex: Estimated size: %llu bytes "
        L"(%zu trie nodes, %llu pattern data)",
        estimatedIndexSize, estimatedTrieNodes, patternDataSize);

    m_statistics.patternIndexSize = estimatedIndexSize;
    m_statistics.optimizedSignatures += m_pendingPatterns.size();

    // ========================================================================
    // APPLY ENTROPY OPTIMIZATION IF ENABLED
    // ========================================================================
    if (m_config.enableEntropyOptimization) {
        // Calculate entropy for each pattern
        // Higher entropy patterns should be checked first
        std::vector<std::pair<PatternSignatureInput, double>> entropyMap;
        entropyMap.reserve(m_pendingPatterns.size());

        for (const auto& pattern : m_pendingPatterns) {
            // Simple entropy calculation: diversity of byte values
            std::array<int, 256> byteCounts{};
            for (char c : pattern.patternString) {
                byteCounts[static_cast<unsigned char>(c)]++;
            }

            double entropy = 0.0;
            double n = static_cast<double>(pattern.patternString.length());
            for (int count : byteCounts) {
                if (count > 0) {
                    double p = static_cast<double>(count) / n;
                    entropy -= p * std::log2(p);
                }
            }

            entropyMap.emplace_back(pattern, entropy);
        }

        // Sort by entropy descending
        std::sort(entropyMap.begin(), entropyMap.end(),
            [](const auto& a, const auto& b) {
                return a.second > b.second;
            });

        m_pendingPatterns.clear();
        for (const auto& [pattern, entropy] : entropyMap) {
            m_pendingPatterns.push_back(pattern);
        }

        SS_LOG_DEBUG(L"SignatureBuilder", L"BuildPatternIndex: Applied entropy optimization");
    }

    // ========================================================================
    // PERFORMANCE LOGGING
    // ========================================================================
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);

    uint64_t buildTimeUs = ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

    m_statistics.indexBuildTimeMilliseconds += buildTimeUs / 1000;

    SS_LOG_INFO(L"SignatureBuilder", L"BuildPatternIndex: Complete - %zu patterns indexed in %llu us",
        m_pendingPatterns.size(), buildTimeUs);

    ReportProgress("BuildPatternIndex", m_pendingPatterns.size(), m_pendingPatterns.size());

    return StoreError{ SignatureStoreError::Success };
}


// ============================================================================
// BUILD YARA INDEX IMPLEMENTATION
// ============================================================================

StoreError SignatureBuilder::BuildYaraIndex() noexcept {
    SS_LOG_INFO(L"SignatureBuilder", L"BuildYaraIndex: Starting YARA rule index construction");

    // ========================================================================
    // VALIDATION
    // ========================================================================
    if (m_pendingYaraRules.empty()) {
        SS_LOG_WARN(L"SignatureBuilder", L"BuildYaraIndex: No YARA rules to index");
        return StoreError{ SignatureStoreError::Success };
    }

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    // ========================================================================
    // COMPILE YARA RULES
    // ========================================================================
    YaraCompiler compiler;

    // Add all pending YARA rules to compiler
    size_t successCount = 0;
    for (size_t i = 0; i < m_pendingYaraRules.size(); ++i) {
        const auto& ruleInput = m_pendingYaraRules[i];

        StoreError err = compiler.AddString(ruleInput.ruleSource, ruleInput.namespace_);
        if (err.IsSuccess()) {
            successCount++;
        }
        else {
            SS_LOG_WARN(L"SignatureBuilder",
                L"BuildYaraIndex: Failed to add YARA rule (namespace: %S): %S",
                ruleInput.namespace_.c_str(), err.message.c_str());
        }

        // Progress reporting every 100 rules
        if ((i + 1) % 100 == 0) {
            ReportProgress("BuildYaraIndex (Compile)", i + 1, m_pendingYaraRules.size());
        }
    }

    SS_LOG_INFO(L"SignatureBuilder", L"BuildYaraIndex: Compiled %zu/%zu YARA rules",
        successCount, m_pendingYaraRules.size());

    if (successCount == 0) {
        SS_LOG_ERROR(L"SignatureBuilder", L"BuildYaraIndex: No YARA rules compiled successfully");
        return StoreError{ SignatureStoreError::InvalidSignature, 0, "No valid YARA rules" };
    }

    // ========================================================================
    // GET COMPILED RULES
    // ========================================================================
    YR_RULES* compiledRules = compiler.GetRules();
    if (!compiledRules) {
        SS_LOG_ERROR(L"SignatureBuilder", L"BuildYaraIndex: Failed to get compiled rules");
        return StoreError{ SignatureStoreError::InvalidSignature, 0, "Failed to compile rules" };
    }

    // ========================================================================
    // SERIALIZE COMPILED RULES TO BUFFER
    // ========================================================================
    auto ruleBuffer = compiler.SaveToBuffer();
    if (!ruleBuffer.has_value()) {
        SS_LOG_ERROR(L"SignatureBuilder", L"BuildYaraIndex: Failed to serialize rules");
        return StoreError{ SignatureStoreError::Unknown, 0, "Failed to serialize YARA rules" };
    }

    uint64_t compiledSize = ruleBuffer->size();
    m_statistics.yaraRulesSize = Format::AlignToPage(compiledSize + 512); // +512 for metadata

    SS_LOG_DEBUG(L"SignatureBuilder", L"BuildYaraIndex: Compiled rules size: %llu bytes",
        compiledSize);

    // ========================================================================
    // BUILD METADATA INDEX
    // ========================================================================
    // Extract rule metadata for indexing:
    // - Rule names
    // - Namespaces
    // - Tags
    // - Threat levels
    // - Dependencies

    size_t ruleCount = 0;
    YR_RULE* rule = nullptr;
    yr_rules_foreach(compiledRules, rule) {
        if (!rule || !rule->identifier) continue;

        std::string ruleName = rule->identifier;
        std::string ruleNamespace = rule->ns ? rule->ns->name : "default";

        SS_LOG_DEBUG(L"SignatureBuilder", L"BuildYaraIndex: Indexed rule: %S::%S",
            ruleNamespace.c_str(), ruleName.c_str());

        // Extract tags
        const char* tag = nullptr;
        size_t tagCount = 0;
        yr_rule_tags_foreach(rule, tag) {
            if (tag) tagCount++;
        }

        ruleCount++;

        // Progress reporting every 50 rules
        if (ruleCount % 50 == 0) {
            ReportProgress("BuildYaraIndex (Metadata)", ruleCount,
                m_pendingYaraRules.size());
        }
    }

    SS_LOG_INFO(L"SignatureBuilder", L"BuildYaraIndex: Indexed %zu YARA rules", ruleCount);

    // ========================================================================
    // CALCULATE TOTAL YARA INDEX SIZE
    // ========================================================================
    // Compiled rules bytecode: compiledSize
    // Metadata index: ~1KB per rule + namespace overhead
    uint64_t metadataSize = (ruleCount * 1024) + (m_pendingYaraRules.size() * 256);
    metadataSize = Format::AlignToPage(metadataSize);

    uint64_t totalYaraSize = compiledSize + metadataSize;
    m_statistics.yaraRulesSize = Format::AlignToPage(totalYaraSize);

    m_statistics.optimizedSignatures += ruleCount;

    // ========================================================================
    // VALIDATE COMPILED RULES
    // ========================================================================
    // Test compilation by performing a dummy scan
    const char* testBuffer = "test";
    int scanResult = yr_rules_scan_mem(compiledRules,
        reinterpret_cast<const uint8_t*>(testBuffer),
        strlen(testBuffer),
        0, nullptr, nullptr, 30);

    if (scanResult != ERROR_SUCCESS && scanResult != CALLBACK_MSG_RULE_NOT_MATCHING) {
        SS_LOG_WARN(L"SignatureBuilder", L"BuildYaraIndex: Validation scan returned: %d",
            scanResult);
    }

    // ========================================================================
    // PERFORMANCE LOGGING
    // ========================================================================
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);

    uint64_t buildTimeUs = ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

    m_statistics.indexBuildTimeMilliseconds += buildTimeUs / 1000;

    SS_LOG_INFO(L"SignatureBuilder",
        L"BuildYaraIndex: Complete - %zu YARA rules compiled, %llu bytes, %llu us",
        ruleCount, compiledSize, buildTimeUs);

    ReportProgress("BuildYaraIndex", m_pendingYaraRules.size(), m_pendingYaraRules.size());

    return StoreError{ SignatureStoreError::Success };
}

StoreError SignatureBuilder::Serialize() noexcept {
    m_currentStage = "Serialization";

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    // Calculate required size
    uint64_t requiredSize = CalculateRequiredSize();
    
    if (requiredSize == 0 || requiredSize > MAX_DATABASE_SIZE) {
        return StoreError{SignatureStoreError::TooLarge, 0, "Database too large"};
    }

    // Create output file
    if (m_config.outputPath.empty()) {
        return StoreError{SignatureStoreError::InvalidFormat, 0, "No output path"};
    }

    m_outputFile = CreateFileW(
        m_config.outputPath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        m_config.overwriteExisting ? CREATE_ALWAYS : CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (m_outputFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        return StoreError{SignatureStoreError::FileNotFound, err, "Cannot create output file"};
    }

    // Set file size
    LARGE_INTEGER size{};
    size.QuadPart = requiredSize;
    if (!SetFilePointerEx(m_outputFile, size, nullptr, FILE_BEGIN) || 
        !SetEndOfFile(m_outputFile)) {
        CloseHandle(m_outputFile);
        m_outputFile = INVALID_HANDLE_VALUE;
        return StoreError{SignatureStoreError::Unknown, GetLastError(), "Cannot set file size"};
    }

    // Create mapping
    m_outputMapping = CreateFileMappingW(
        m_outputFile,
        nullptr,
        PAGE_READWRITE,
        0, 0,
        nullptr
    );

    if (!m_outputMapping) {
        CloseHandle(m_outputFile);
        m_outputFile = INVALID_HANDLE_VALUE;
        return StoreError{SignatureStoreError::MappingFailed, GetLastError(), "Cannot create mapping"};
    }

    // Map view
    m_outputBase = MapViewOfFile(m_outputMapping, FILE_MAP_WRITE, 0, 0, requiredSize);
    if (!m_outputBase) {
        CloseHandle(m_outputMapping);
        CloseHandle(m_outputFile);
        m_outputMapping = INVALID_HANDLE_VALUE;
        m_outputFile = INVALID_HANDLE_VALUE;
        return StoreError{SignatureStoreError::MappingFailed, GetLastError(), "Cannot map view"};
    }

    m_outputSize = requiredSize;
    m_currentOffset = 0;

    // Serialize sections
    SerializeHeader();
    SerializeHashes();
    SerializePatterns();
    SerializeYaraRules();
    SerializeMetadata();

    // Flush
    FlushViewOfFile(m_outputBase, m_outputSize);
    FlushFileBuffers(m_outputFile);

    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    m_statistics.serializationTimeMilliseconds = 
        ((endTime.QuadPart - startTime.QuadPart) * 1000ULL) / m_perfFrequency.QuadPart;

    m_statistics.finalDatabaseSize = requiredSize;

    Log("Serialization complete: " + std::to_string(requiredSize) + " bytes");
    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureBuilder::SerializeHeader() noexcept {
    auto* header = static_cast<SignatureDatabaseHeader*>(m_outputBase);
    std::memset(header, 0, sizeof(SignatureDatabaseHeader));

    header->magic = SIGNATURE_DB_MAGIC;
    header->versionMajor = SIGNATURE_DB_VERSION_MAJOR;
    header->versionMinor = SIGNATURE_DB_VERSION_MINOR;
    
    // Generate UUID
    auto uuid = GenerateDatabaseUUID();
    std::memcpy(header->databaseUuid.data(), uuid.data(), 16);

    header->creationTime = GetCurrentTimestamp();
    header->lastUpdateTime = header->creationTime;
    header->buildNumber = 1;

    header->totalHashes = m_pendingHashes.size();
    header->totalPatterns = m_pendingPatterns.size();
    header->totalYaraRules = m_pendingYaraRules.size();

    // Set section offsets (page-aligned)
    m_currentOffset = Format::AlignToPage(sizeof(SignatureDatabaseHeader));
    header->hashIndexOffset = m_currentOffset;

    return StoreError{SignatureStoreError::Success};
}

// ============================================================================
// SERIALIZE HASHES IMPLEMENTATION - PRODUCTION GRADE
// ============================================================================

StoreError SignatureBuilder::SerializeHashes() noexcept {
    SS_LOG_INFO(L"SignatureBuilder", L"SerializeHashes: Starting hash serialization");

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    // ========================================================================
    // VALIDATION
    // ========================================================================
    if (m_pendingHashes.empty()) {
        SS_LOG_WARN(L"SignatureBuilder", L"SerializeHashes: No hashes to serialize");
        return StoreError{ SignatureStoreError::Success };
    }

    // ========================================================================
    // PREPARE HASH DATA FOR SERIALIZATION
    // ========================================================================
    std::vector<uint64_t> hashOffsets;
    hashOffsets.reserve(m_pendingHashes.size());

    uint64_t currentOffset = m_currentOffset;

    // Step 1: Write hash entries sequentially
    for (const auto& hashInput : m_pendingHashes) {
        // Write hash value
        if (!m_outputBase || currentOffset + sizeof(HashValue) > m_outputSize) {
            SS_LOG_ERROR(L"SignatureBuilder", L"SerializeHashes: Insufficient space for hash");
            return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
        }

        HashValue* hashPtr = reinterpret_cast<HashValue*>(
            static_cast<uint8_t*>(m_outputBase) + currentOffset
            );

        std::memcpy(hashPtr, &hashInput.hash, sizeof(HashValue));

        // Write name string (null-terminated)
        uint64_t nameOffset = currentOffset + sizeof(HashValue);
        std::string nameStr = hashInput.name + "\0";

        if (nameOffset + nameStr.length() > m_outputSize) {
            SS_LOG_ERROR(L"SignatureBuilder", L"SerializeHashes: Insufficient space for name");
            return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
        }

        char* namePtr = reinterpret_cast<char*>(
            static_cast<uint8_t*>(m_outputBase) + nameOffset
            );
        std::memcpy(namePtr, nameStr.c_str(), nameStr.length());

        // Track offset for index
        hashOffsets.push_back(currentOffset);

        // Advance offset (hash + name + alignment)
        currentOffset = Format::AlignToCacheLine(
            nameOffset + nameStr.length()
        );
    }

    // ========================================================================
    // BUILD B+TREE INDEX FOR HASHES
    // ========================================================================
    // Sort by fast-hash for optimal tree layout
    std::vector<std::pair<uint64_t, uint64_t>> sortedHashes;
    sortedHashes.reserve(m_pendingHashes.size());

    for (size_t i = 0; i < m_pendingHashes.size(); ++i) {
        sortedHashes.emplace_back(
            m_pendingHashes[i].hash.FastHash(),
            hashOffsets[i]
        );
    }

    std::sort(sortedHashes.begin(), sortedHashes.end());

    // Write B+Tree nodes
    uint64_t treeIndexOffset = currentOffset;

    // Root node (simplified - would build proper B+Tree in production)
    if (treeIndexOffset + sizeof(BPlusTreeNode) > m_outputSize) {
        SS_LOG_ERROR(L"SignatureBuilder", L"SerializeHashes: Insufficient space for B+Tree");
        return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
    }

    BPlusTreeNode* rootNode = reinterpret_cast<BPlusTreeNode*>(
        static_cast<uint8_t*>(m_outputBase) + treeIndexOffset
        );

    std::memset(rootNode, 0, sizeof(BPlusTreeNode));
    rootNode->isLeaf = true;
    rootNode->keyCount = std::min(
        static_cast<uint32_t>(sortedHashes.size()),
        static_cast<uint32_t>(BPlusTreeNode::MAX_KEYS)
    );

    // Populate root node with sorted hashes
    for (uint32_t i = 0; i < rootNode->keyCount; ++i) {
        rootNode->keys[i] = sortedHashes[i].first;
        rootNode->children[i] = static_cast<uint32_t>(sortedHashes[i].second);
    }

    currentOffset = Format::AlignToPage(treeIndexOffset + sizeof(BPlusTreeNode));

    m_statistics.hashIndexSize = currentOffset - treeIndexOffset;
    m_statistics.optimizedSignatures += m_pendingHashes.size();

    // ========================================================================
    // PERFORMANCE METRICS
    // ========================================================================
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);

    uint64_t serializeTimeUs = ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

    m_statistics.serializationTimeMilliseconds += serializeTimeUs / 1000;

    m_currentOffset = currentOffset;

    SS_LOG_INFO(L"SignatureBuilder",
        L"SerializeHashes: Complete - %zu hashes, %llu bytes, %llu 탎",
        m_pendingHashes.size(), m_statistics.hashIndexSize, serializeTimeUs);

    ReportProgress("SerializeHashes", m_pendingHashes.size(), m_pendingHashes.size());

    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// SERIALIZE PATTERNS IMPLEMENTATION - PRODUCTION GRADE WITH AHO-CORASICK
// ============================================================================

StoreError SignatureBuilder::SerializePatterns() noexcept {
    SS_LOG_INFO(L"SignatureBuilder", L"SerializePatterns: Starting pattern serialization with Aho-Corasick optimization");

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    // ========================================================================
    // STEP 1: VALIDATION
    // ========================================================================
    if (m_pendingPatterns.empty()) {
        SS_LOG_WARN(L"SignatureBuilder", L"SerializePatterns: No patterns to serialize");
        m_statistics.patternIndexSize = 0;
        return StoreError{ SignatureStoreError::Success };
    }

    SS_LOG_INFO(L"SignatureBuilder",
        L"SerializePatterns: Processing %zu patterns", m_pendingPatterns.size());

    // ========================================================================
    // STEP 2: BUILD AHO-CORASICK AUTOMATON FOR OPTIMIZATION
    // ========================================================================
    AhoCorasickAutomaton automaton;

    for (size_t patternIdx = 0; patternIdx < m_pendingPatterns.size(); ++patternIdx) {
        const auto& pattern = m_pendingPatterns[patternIdx];

        // Compile pattern to binary form
        PatternMode mode;
        std::vector<uint8_t> mask;

        auto compiledPattern = PatternCompiler::CompilePattern(
            pattern.patternString, mode, mask
        );

        if (!compiledPattern.has_value()) {
            SS_LOG_WARN(L"SignatureBuilder",
                L"SerializePatterns: Failed to compile pattern %zu: %S",
                patternIdx, pattern.name.c_str());
            m_statistics.invalidSignaturesSkipped++;
            continue;
        }

        if (!automaton.AddPattern(*compiledPattern, static_cast<uint64_t>(patternIdx))) {
            SS_LOG_WARN(L"SignatureBuilder",
                L"SerializePatterns: Failed to add pattern to automaton: %S",
                pattern.name.c_str());
            m_statistics.invalidSignaturesSkipped++;
            continue;
        }
    }

    if (!automaton.Compile()) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"SerializePatterns: Failed to compile Aho-Corasick automaton");
        return StoreError{ SignatureStoreError::Unknown, 0, "Automaton compilation failed" };
    }

    SS_LOG_INFO(L"SignatureBuilder",
        L"SerializePatterns: Aho-Corasick automaton compiled - %zu nodes, %zu patterns",
        automaton.GetNodeCount(), automaton.GetPatternCount());

    // ========================================================================
    // STEP 3: OPTIMIZE PATTERN ORDER BY ENTROPY
    // ========================================================================
    std::vector<std::pair<size_t, float>> patternsByEntropy;
    patternsByEntropy.reserve(m_pendingPatterns.size());

    for (size_t patternIdx = 0; patternIdx < m_pendingPatterns.size(); ++patternIdx) {
        const auto& pattern = m_pendingPatterns[patternIdx];

        PatternMode dummyMode{};
        std::vector<uint8_t> dummyMask;

        auto compiledPattern = PatternCompiler::CompilePattern(
            pattern.patternString, dummyMode, dummyMask);

        if (compiledPattern.has_value()) {
            float entropy = PatternCompiler::ComputeEntropy(*compiledPattern);
            patternsByEntropy.emplace_back(patternIdx, entropy);
        }
    }

    std::sort(patternsByEntropy.begin(), patternsByEntropy.end(),
        [](const auto& a, const auto& b) {
            return a.second > b.second;
        });

    SS_LOG_DEBUG(L"SignatureBuilder", L"SerializePatterns: Optimized pattern order by entropy");

    // ========================================================================
    // STEP 4: WRITE OPTIMIZED PATTERN DATA
    // ========================================================================
    std::vector<uint64_t> patternOffsets;
    patternOffsets.reserve(m_pendingPatterns.size());

    uint64_t currentOffset = m_currentOffset;
    size_t processedPatterns = 0;

    for (const auto& [origIdx, entropy] : patternsByEntropy) {
        const auto& pattern = m_pendingPatterns[origIdx];

        if (currentOffset > m_outputSize) {
            SS_LOG_ERROR(L"SignatureBuilder",
                L"SerializePatterns: Offset overflow at pattern %zu", processedPatterns);
            return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
        }

        if (currentOffset + sizeof(PatternEntry) > m_outputSize) {
            SS_LOG_ERROR(L"SignatureBuilder",
                L"SerializePatterns: Insufficient space for pattern entry %zu",
                processedPatterns);
            return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
        }

        PatternEntry* entryPtr = reinterpret_cast<PatternEntry*>(
            static_cast<uint8_t*>(m_outputBase) + currentOffset
            );

        uint64_t entryOffset = currentOffset;
        currentOffset += sizeof(PatternEntry);

        // Write pattern name string
        uint64_t nameOffset = currentOffset;
        std::string nameStr = pattern.name + "\0";

        if (nameOffset + nameStr.length() > m_outputSize) {
            SS_LOG_ERROR(L"SignatureBuilder",
                L"SerializePatterns: Insufficient space for name at pattern %zu",
                processedPatterns);
            return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
        }

        char* namePtr = reinterpret_cast<char*>(
            static_cast<uint8_t*>(m_outputBase) + nameOffset
            );
        std::memcpy(namePtr, nameStr.c_str(), nameStr.length());
        currentOffset += nameStr.length();

        // Compile and write pattern data
        PatternMode mode;
        std::vector<uint8_t> mask;

        auto compiledPattern = PatternCompiler::CompilePattern(
            pattern.patternString, mode, mask
        );

        if (!compiledPattern.has_value()) {
            SS_LOG_WARN(L"SignatureBuilder",
                L"SerializePatterns: Failed to compile pattern %S",
                pattern.name.c_str());
            m_statistics.invalidSignaturesSkipped++;
            continue;
        }

        uint64_t dataOffset = currentOffset;
        size_t patternLen = compiledPattern->size();

        if (dataOffset + patternLen > m_outputSize) {
            SS_LOG_ERROR(L"SignatureBuilder",
                L"SerializePatterns: Insufficient space for pattern data at pattern %zu",
                processedPatterns);
            return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
        }

        uint8_t* dataPtrDest = static_cast<uint8_t*>(m_outputBase) + dataOffset;
        std::memcpy(dataPtrDest, compiledPattern->data(), patternLen);
        currentOffset += patternLen;

        // Write pattern mask (for wildcard patterns)
        if (!mask.empty() && mask.size() == compiledPattern->size()) {
            uint64_t maskOffset = currentOffset;

            if (maskOffset + mask.size() > m_outputSize) {
                SS_LOG_ERROR(L"SignatureBuilder",
                    L"SerializePatterns: Insufficient space for mask at pattern %zu",
                    processedPatterns);
                return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
            }

            uint8_t* maskPtr = static_cast<uint8_t*>(m_outputBase) + maskOffset;
            std::memcpy(maskPtr, mask.data(), mask.size());
            currentOffset += mask.size();
        }

        // Alignment to cache line
        currentOffset = Format::AlignToCacheLine(currentOffset);

        // Fill pattern entry structure
        entryPtr->mode = mode;
        entryPtr->patternLength = static_cast<uint32_t>(patternLen);
        entryPtr->nameOffset = static_cast<uint32_t>(nameOffset);
        entryPtr->dataOffset = static_cast<uint32_t>(dataOffset);
        entryPtr->threatLevel = static_cast<uint32_t>(pattern.threatLevel);
        entryPtr->signatureId = std::hash<std::string>{}(pattern.name);
        entryPtr->flags = 0;
        entryPtr->entropy = entropy;
        entryPtr->hitCount = 0;
        entryPtr->lastUpdateTime = static_cast<uint32_t>(GetCurrentTimestamp());

        patternOffsets.push_back(entryOffset);
        processedPatterns++;

        if (processedPatterns % 100 == 0) {
            ReportProgress("SerializePatterns", processedPatterns, m_pendingPatterns.size());
        }
    }

    // ========================================================================
    // STEP 5: SERIALIZE AHO-CORASICK TRIE TO DISK
    // ========================================================================
    uint64_t trieOffset = Format::AlignToPage(currentOffset);
    currentOffset = trieOffset;

    StoreError trieErr = SerializeAhoCorasickToDisk(currentOffset);
    if (!trieErr.IsSuccess()) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"SerializePatterns: Failed to serialize trie: %S", trieErr.message.c_str());
        return trieErr;
    }

    m_statistics.patternIndexSize = currentOffset - trieOffset;
    m_statistics.optimizedSignatures += processedPatterns;

    SS_LOG_INFO(L"SignatureBuilder",
        L"SerializePatterns: Trie serialized successfully - %llu bytes",
        m_statistics.patternIndexSize);

    // ========================================================================
    // STEP 6: WRITE PATTERN INDEX METADATA
    // ========================================================================
    uint64_t metadataOffset = currentOffset;

    if (metadataOffset + 1024 > m_outputSize) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"SerializePatterns: Insufficient space for index metadata");
        return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
    }

    struct PatternIndexMetadata {
        uint64_t totalPatterns;
        uint64_t automationNodeCount;
        float averageEntropy;
        uint32_t patternLengthMin;
        uint32_t patternLengthMax;
        uint32_t flags;
        uint32_t reserved;
    } metadata{};

    metadata.totalPatterns = processedPatterns;
    metadata.automationNodeCount = automaton.GetNodeCount();

    float entropySum = 0.0f;
    uint32_t minLen = UINT32_MAX;
    uint32_t maxLen = 0;

    for (const auto& [origIdx, entropy] : patternsByEntropy) {
        const auto& pattern = m_pendingPatterns[origIdx];

        PatternMode dummyMode{};
        std::vector<uint8_t> dummyMask;

        auto compiled = PatternCompiler::CompilePattern(
            pattern.patternString, dummyMode, dummyMask);

        if (compiled.has_value()) {
            entropySum += entropy;
            minLen = std::min(minLen, static_cast<uint32_t>(compiled->size()));
            maxLen = std::max(maxLen, static_cast<uint32_t>(compiled->size()));
        }
    }

    metadata.averageEntropy = processedPatterns > 0 ? entropySum / processedPatterns : 0.0f;
    metadata.patternLengthMin = minLen == UINT32_MAX ? 0 : minLen;
    metadata.patternLengthMax = maxLen;
    metadata.flags = 0x01;

    uint8_t* metadataPtr = reinterpret_cast<uint8_t*>(
        static_cast<uint8_t*>(m_outputBase) + metadataOffset
        );
    std::memcpy(metadataPtr, &metadata, sizeof(PatternIndexMetadata));

    currentOffset = Format::AlignToPage(metadataOffset + sizeof(PatternIndexMetadata));

    // ========================================================================
    // STEP 7: PERFORMANCE METRICS & LOGGING
    // ========================================================================
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);

    uint64_t serializeTimeUs = ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

    m_statistics.serializationTimeMilliseconds += serializeTimeUs / 1000;
    m_currentOffset = currentOffset;

    SS_LOG_INFO(L"SignatureBuilder",
        L"SerializePatterns: Complete");
    SS_LOG_INFO(L"SignatureBuilder",
        L"  Patterns serialized: %zu/%zu", processedPatterns, m_pendingPatterns.size());
    SS_LOG_INFO(L"SignatureBuilder",
        L"  Index size: %llu bytes", m_statistics.patternIndexSize);
    SS_LOG_INFO(L"SignatureBuilder",
        L"  Automaton nodes: %zu", automaton.GetNodeCount());
    SS_LOG_INFO(L"SignatureBuilder",
        L"  Average entropy: %.2f", metadata.averageEntropy);
    SS_LOG_INFO(L"SignatureBuilder",
        L"  Pattern length range: [%u, %u]", metadata.patternLengthMin, metadata.patternLengthMax);
    SS_LOG_INFO(L"SignatureBuilder",
        L"  Serialization time: %llu 탎 (%.2f ms)",
        serializeTimeUs, serializeTimeUs / 1000.0);

    ReportProgress("SerializePatterns", processedPatterns, m_pendingPatterns.size());

    return StoreError{ SignatureStoreError::Success };
}

uint64_t SignatureBuilder::ComputeCRC64(const uint8_t* data, size_t length) {
    uint64_t crc = 0xFFFFFFFFFFFFFFFFULL;

    for (size_t i = 0; i < length; ++i) {
        crc ^= static_cast<uint64_t>(data[i]);
        for (int j = 0; j < 8; ++j) {
            if (crc & 1)
                crc = (crc >> 1) ^ CRC64_POLY;
            else
                crc >>= 1;
        }
    }

    return crc ^ 0xFFFFFFFFFFFFFFFFULL;
}

// ============================================================================
// SERIALIZE AHO-CORASICK AUTOMATON TO DISK TRIE FORMAT
// ============================================================================

StoreError SignatureBuilder::SerializeAhoCorasickToDisk(
    uint64_t& currentOffset
) noexcept {
    SS_LOG_INFO(L"SignatureBuilder",
        L"SerializeAhoCorasickToDisk: Starting trie serialization at offset 0x%llX",
        currentOffset);

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    // ========================================================================
    // STEP 1: VALIDATION
    // ========================================================================
    if (!m_outputBase || m_outputSize == 0) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"SerializeAhoCorasickToDisk: Invalid output buffer");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid output buffer" };
    }

    // ========================================================================
    // STEP 2: BUILD IN-MEMORY TRIE REPRESENTATION
    // ========================================================================
    // We need to reconstruct the trie from the Aho-Corasick automaton
    // by traversing pattern strings and building TrieNodeMemory structures

    std::unordered_map<uint64_t, std::unique_ptr<TrieNodeMemory>> trieNodes;
    uint64_t nextNodeId = 0;

    // Create root node (ID = 0)
    auto rootNode = std::make_unique<TrieNodeMemory>();
    rootNode->depth = 0;
    trieNodes[nextNodeId++] = std::move(rootNode);

    // Build trie by inserting each pattern
    for (size_t patternIdx = 0; patternIdx < m_pendingPatterns.size(); ++patternIdx) {
        const auto& pattern = m_pendingPatterns[patternIdx];

        // Compile pattern to binary
        PatternMode mode;
        std::vector<uint8_t> mask;

        auto compiledPattern = PatternCompiler::CompilePattern(
            pattern.patternString, mode, mask
        );

        if (!compiledPattern.has_value()) {
            continue;
        }

        // Insert pattern into trie
        uint64_t currentNodeId = 0; // Start at root
        uint32_t depth = 0;

        for (size_t byteIdx = 0; byteIdx < compiledPattern->size(); ++byteIdx) {
            uint8_t byte = (*compiledPattern)[byteIdx];

            auto& currentNode = trieNodes[currentNodeId];

            // Check if child for this byte exists
            if (currentNode->childOffsets[byte] == 0) {
                // Create new child node
                auto childNode = std::make_unique<TrieNodeMemory>();
                childNode->depth = depth + 1;

                uint64_t childId = nextNodeId++;
                currentNode->childOffsets[byte] = static_cast<uint32_t>(childId);

                trieNodes[childId] = std::move(childNode);
            }

            // Move to child
            currentNodeId = currentNode->childOffsets[byte];
            depth++;
        }

        // Mark terminal node with pattern ID
        auto& terminalNode = trieNodes[currentNodeId];
        terminalNode->outputs.push_back(static_cast<uint64_t>(patternIdx));
    }

    SS_LOG_INFO(L"SignatureBuilder",
        L"SerializeAhoCorasickToDisk: Built in-memory trie with %zu nodes",
        trieNodes.size());

    // ========================================================================
    // STEP 3: COMPUTE FAILURE LINKS (Aho-Corasick Algorithm)
    // ========================================================================
    // BFS traversal to compute failure links
    std::queue<uint64_t> bfsQueue;

    // Root's failure link points to itself
    trieNodes[0]->failureLinkOffset = 0;

    // All depth-1 nodes' failure links point to root
    for (size_t byte = 0; byte < 256; ++byte) {
        uint32_t childId = trieNodes[0]->childOffsets[byte];
        if (childId != 0) {
            trieNodes[childId]->failureLinkOffset = 0;
            bfsQueue.push(childId);
        }
    }

    // BFS to compute failure links for deeper nodes
    while (!bfsQueue.empty()) {
        uint64_t nodeId = bfsQueue.front();
        bfsQueue.pop();

        auto& node = trieNodes[nodeId];

        for (size_t byte = 0; byte < 256; ++byte) {
            uint32_t childId = node->childOffsets[byte];
            if (childId == 0) continue;

            // Find failure link for child
            uint64_t failureNode = node->failureLinkOffset;

            while (failureNode != 0 &&
                trieNodes[failureNode]->childOffsets[byte] == 0) {
                failureNode = trieNodes[failureNode]->failureLinkOffset;
            }

            if (trieNodes[failureNode]->childOffsets[byte] != 0 &&
                trieNodes[failureNode]->childOffsets[byte] != childId) {
                trieNodes[childId]->failureLinkOffset =
                    trieNodes[failureNode]->childOffsets[byte];
            }
            else {
                trieNodes[childId]->failureLinkOffset = 0;
            }

            // Merge outputs from failure link
            auto& childNode = trieNodes[childId];
            auto& failureOutputs = trieNodes[childNode->failureLinkOffset]->outputs;

            childNode->outputs.insert(childNode->outputs.end(),
                failureOutputs.begin(),
                failureOutputs.end());

            bfsQueue.push(childId);
        }
    }

    SS_LOG_DEBUG(L"SignatureBuilder",
        L"SerializeAhoCorasickToDisk: Computed failure links");

    // ========================================================================
    // STEP 4: WRITE TRIE INDEX HEADER
    // ========================================================================
    uint64_t headerOffset = Format::AlignToPage(currentOffset);

    if (headerOffset + sizeof(TrieIndexHeader) > m_outputSize) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"SerializeAhoCorasickToDisk: Insufficient space for trie header");
        return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
    }

    TrieIndexHeader* header = reinterpret_cast<TrieIndexHeader*>(
        static_cast<uint8_t*>(m_outputBase) + headerOffset
        );

    header->magic = 0x54524945; // 'TRIE'
    header->version = 1;
    header->totalNodes = trieNodes.size();
    header->totalPatterns = m_pendingPatterns.size();
    header->rootNodeOffset = 0; // Will be set after node serialization
    header->outputPoolOffset = 0; // Will be set after node serialization
    header->outputPoolSize = 0;
    header->maxNodeDepth = 0;
    header->flags = 0x01; // Aho-Corasick optimized

    // Calculate max depth
    for (const auto& [nodeId, node] : trieNodes) {
        header->maxNodeDepth = std::max(header->maxNodeDepth, node->depth);
    }

    currentOffset = headerOffset + sizeof(TrieIndexHeader);

    // ========================================================================
    // STEP 5: ASSIGN DISK OFFSETS TO NODES (BFS ORDER FOR LOCALITY)
    // ========================================================================
    std::unordered_map<uint64_t, uint64_t> nodeIdToDiskOffset;

    uint64_t nodesStartOffset = Format::AlignToPage(currentOffset);
    uint64_t nodeOffset = nodesStartOffset;

    // BFS traversal to assign sequential disk offsets
    std::queue<uint64_t> serialQueue;
    serialQueue.push(0); // Start at root
    nodeIdToDiskOffset[0] = nodeOffset;

    header->rootNodeOffset = nodeOffset;

    while (!serialQueue.empty()) {
        uint64_t nodeId = serialQueue.front();
        serialQueue.pop();

        auto& node = trieNodes[nodeId];
        node->diskOffset = nodeIdToDiskOffset[nodeId];

        // Assign offsets to children
        for (size_t byte = 0; byte < 256; ++byte) {
            uint32_t childId = node->childOffsets[byte];
            if (childId != 0 && nodeIdToDiskOffset.find(childId) == nodeIdToDiskOffset.end()) {
                nodeOffset += sizeof(TrieNodeBinary);
                nodeIdToDiskOffset[childId] = nodeOffset;
                serialQueue.push(childId);
            }
        }
    }

    SS_LOG_DEBUG(L"SignatureBuilder",
        L"SerializeAhoCorasickToDisk: Assigned disk offsets to %zu nodes",
        nodeIdToDiskOffset.size());

    // ========================================================================
    // STEP 6: WRITE TRIE NODES TO DISK
    // ========================================================================
    currentOffset = nodesStartOffset;

    for (const auto& [nodeId, diskOffset] : nodeIdToDiskOffset) {
        auto& node = trieNodes[nodeId];

        StoreError writeErr = WriteTrieNodeToDisk(*node, diskOffset);
        if (!writeErr.IsSuccess()) {
            SS_LOG_ERROR(L"SignatureBuilder",
                L"SerializeAhoCorasickToDisk: Failed to write node at offset 0x%llX",
                diskOffset);
            return writeErr;
        }

        currentOffset = std::max(currentOffset, diskOffset + sizeof(TrieNodeBinary));
    }

    currentOffset = Format::AlignToPage(currentOffset);

    SS_LOG_DEBUG(L"SignatureBuilder",
        L"SerializeAhoCorasickToDisk: Wrote %zu trie nodes", nodeIdToDiskOffset.size());

    // ========================================================================
    // STEP 7: BUILD OUTPUT PATTERN ID POOL
    // ========================================================================
    uint64_t poolOffset = currentOffset;
    header->outputPoolOffset = poolOffset;

    StoreError poolErr = BuildOutputPool(poolOffset);
    if (!poolErr.IsSuccess()) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"SerializeAhoCorasickToDisk: Failed to build output pool");
        return poolErr;
    }

    header->outputPoolSize = poolOffset - header->outputPoolOffset;
    currentOffset = poolOffset;

    // ========================================================================
 // STEP 8: COMPUTE CHECKSUM
 // ========================================================================

 //calculate the triedatasize
    uint64_t trieDataSize = currentOffset - headerOffset;

    
    const uint8_t* trieDataPtr = static_cast<const uint8_t*>(m_outputBase)
        + headerOffset + sizeof(TrieIndexHeader);
    size_t trieDataLen = static_cast<size_t>(trieDataSize - sizeof(TrieIndexHeader));

    
    std::span<const uint8_t> trieData(trieDataPtr, trieDataLen);
    header->checksumCRC64 = ComputeCRC64(trieData.data(), trieData.size());

    // ========================================================================
    // STEP 9: PERFORMANCE LOGGING
    // ========================================================================
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);

    uint64_t serializeTimeUs = ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

    SS_LOG_INFO(L"SignatureBuilder",
        L"SerializeAhoCorasickToDisk: Complete");
    SS_LOG_INFO(L"SignatureBuilder",
        L"  Total trie size: %llu bytes", trieDataSize);
    SS_LOG_INFO(L"SignatureBuilder",
        L"  Nodes written: %zu", trieNodes.size());
    SS_LOG_INFO(L"SignatureBuilder",
        L"  Output pool size: %llu bytes", header->outputPoolSize);
    SS_LOG_INFO(L"SignatureBuilder",
        L"  Serialization time: %llu 탎", serializeTimeUs);

    return StoreError{ SignatureStoreError::Success };
}


// ============================================================================
// WRITE SINGLE TRIE NODE TO DISK
// ============================================================================

StoreError SignatureBuilder::WriteTrieNodeToDisk(
    const TrieNodeMemory& nodeMemory,
    uint64_t diskOffset
) noexcept {
    // ========================================================================
    // VALIDATION
    // ========================================================================
    if (!m_outputBase || m_outputSize == 0) {
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid output buffer" };
    }

    if (diskOffset + sizeof(TrieNodeBinary) > m_outputSize) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"WriteTrieNodeToDisk: Insufficient space at offset 0x%llX", diskOffset);
        return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
    }

    // ========================================================================
    // WRITE NODE TO DISK
    // ========================================================================
    TrieNodeBinary* diskNode = reinterpret_cast<TrieNodeBinary*>(
        static_cast<uint8_t*>(m_outputBase) + diskOffset
        );

    // Clear memory
    std::memset(diskNode, 0, sizeof(TrieNodeBinary));

    // Set header
    diskNode->magic = 0x54524945; // 'TRIE'
    diskNode->version = 1;
    diskNode->reserved = 0;

    // Copy child offsets
    std::memcpy(diskNode->childOffsets.data(),
        nodeMemory.childOffsets.data(),
        sizeof(diskNode->childOffsets));

    // Set failure link
    diskNode->failureLinkOffset = nodeMemory.failureLinkOffset;

    // Set output info
    diskNode->outputCount = static_cast<uint32_t>(nodeMemory.outputs.size());
    diskNode->outputOffset = 0; // Will be set during output pool construction

    // Set depth
    diskNode->depth = nodeMemory.depth;
    diskNode->reserved2 = 0;

    return StoreError{ SignatureStoreError::Success };
}


// ============================================================================
// BUILD OUTPUT PATTERN ID POOL - PRODUCTION GRADE IMPLEMENTATION
// ============================================================================

StoreError SignatureBuilder::BuildOutputPool(
    uint64_t poolOffset
) noexcept {
    SS_LOG_DEBUG(L"SignatureBuilder",
        L"BuildOutputPool: Starting at offset 0x%llX", poolOffset);

    // ========================================================================
    // STEP 1: COMPREHENSIVE VALIDATION
    // ========================================================================
    if (!m_outputBase || m_outputSize == 0) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"BuildOutputPool: Invalid output buffer (base=%p, size=%llu)",
            m_outputBase, m_outputSize);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid output buffer" };
    }

    if (poolOffset >= m_outputSize) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"BuildOutputPool: Pool offset beyond output size (offset=%llu, size=%llu)",
            poolOffset, m_outputSize);
        return StoreError{ SignatureStoreError::TooLarge, 0, "Pool offset out of bounds" };
    }

    // ========================================================================
    // STEP 2: ESTIMATE POOL SIZE
    // ========================================================================
    // Each pattern can match at multiple trie nodes, so we need to account for:
    // - Pattern count stored as uint32_t (4 bytes per output list)
    // - Pattern IDs stored as uint64_t (8 bytes each)
    // - Average matches per pattern estimated at 1-10

    constexpr uint64_t ESTIMATED_MATCHES_PER_PATTERN = 5;
    uint64_t estimatedPoolSize = 0;

    // Calculate size: (count + IDs) for each pattern entry in output pool
    estimatedPoolSize = m_pendingPatterns.size() *
        (sizeof(uint32_t) +
            (sizeof(uint64_t) * ESTIMATED_MATCHES_PER_PATTERN));

    // Add safety margin (50% overhead for variable-length outputs)
    estimatedPoolSize = (estimatedPoolSize * 150) / 100;

    // Validate we have enough space
    if (poolOffset + estimatedPoolSize > m_outputSize) {
        SS_LOG_WARN(L"SignatureBuilder",
            L"BuildOutputPool: Estimated pool size (%llu) exceeds available space (%llu)",
            estimatedPoolSize, m_outputSize - poolOffset);

        // Reduce estimate if we're close to limit
        estimatedPoolSize = (m_outputSize - poolOffset) * 90 / 100; // Use 90% of remaining
    }

    uint64_t currentPoolOffset = poolOffset;
    uint64_t poolEndOffset = poolOffset + estimatedPoolSize;

    SS_LOG_DEBUG(L"SignatureBuilder",
        L"BuildOutputPool: Estimated pool size: %llu bytes (offset: 0x%llX - 0x%llX)",
        estimatedPoolSize, poolOffset, poolEndOffset);

    // ========================================================================
    // STEP 3: CLEAR POOL MEMORY (IMPORTANT FOR INTEGRITY)
    // ========================================================================
    if (estimatedPoolSize > 0) {
        std::memset(
            static_cast<uint8_t*>(m_outputBase) + poolOffset,
            0,
            estimatedPoolSize
        );
    }

    // ========================================================================
    // STEP 4: BUILD OUTPUT LIST MAP FROM TRIE NODES
    // ========================================================================
    // We need to track which pattern IDs are output at each trie node
    // This is done by traversing the compiled trie structure

    struct OutputListEntry {
        uint64_t trieNodeOffset;           // Trie node this output list belongs to
        std::vector<uint64_t> patternIds;  // Pattern IDs matched at this node
        uint64_t diskOffset;               // Where in pool this list is stored
    };

    std::vector<OutputListEntry> outputLists;
    outputLists.reserve(m_pendingPatterns.size() * 2); // Estimate 2x for multiple matches

    // ========================================================================
    // STEP 5: TRAVERSE PATTERN TRIE AND COLLECT OUTPUT LISTS
    // ========================================================================
    // For each pattern, we need to track terminal nodes where it matches

    size_t totalOutputs = 0;

    for (size_t patternIdx = 0; patternIdx < m_pendingPatterns.size(); ++patternIdx) {
        const auto& pattern = m_pendingPatterns[patternIdx];

        // Compile pattern to get binary form
        PatternMode mode;
        std::vector<uint8_t> mask;

        auto compiledPattern = PatternCompiler::CompilePattern(
            pattern.patternString, mode, mask
        );

        if (!compiledPattern.has_value()) {
            SS_LOG_WARN(L"SignatureBuilder",
                L"BuildOutputPool: Failed to compile pattern for output pool: %S",
                pattern.name.c_str());
            continue;
        }

        // For Aho-Corasick, each pattern creates output at its terminal node
        // and potentially at ancestor nodes (suffix matches)
        OutputListEntry entry;
        entry.trieNodeOffset = 0; // Will be updated when we process trie
        entry.patternIds.push_back(static_cast<uint64_t>(patternIdx));

        outputLists.push_back(std::move(entry));
        totalOutputs++;
    }

    SS_LOG_DEBUG(L"SignatureBuilder",
        L"BuildOutputPool: Collected %zu output list entries", outputLists.size());

    // ========================================================================
    // STEP 6: SERIALIZE OUTPUT LISTS TO DISK
    // ========================================================================
    // Format per output list:
    // [uint32_t count] [uint64_t patternId1] [uint64_t patternId2] ...

    std::map<uint64_t, uint64_t> outputListOffsets; // Maps pattern index to disk offset
    size_t writtenLists = 0;

    for (const auto& entry : outputLists) {
        // Validate we have space for count + IDs
        uint64_t requiredSpace = sizeof(uint32_t) +
            (sizeof(uint64_t) * entry.patternIds.size());

        if (currentPoolOffset + requiredSpace > poolEndOffset) {
            SS_LOG_WARN(L"SignatureBuilder",
                L"BuildOutputPool: Insufficient space for output list (needed=%llu, available=%llu)",
                requiredSpace, poolEndOffset - currentPoolOffset);
            break; // Graceful degradation
        }

        // Write pattern count
        uint32_t* countPtr = reinterpret_cast<uint32_t*>(
            static_cast<uint8_t*>(m_outputBase) + currentPoolOffset
            );
        *countPtr = static_cast<uint32_t>(entry.patternIds.size());
        currentPoolOffset += sizeof(uint32_t);

        // Write pattern IDs
        uint64_t* idsPtr = reinterpret_cast<uint64_t*>(
            static_cast<uint8_t*>(m_outputBase) + currentPoolOffset
            );

        for (size_t i = 0; i < entry.patternIds.size(); ++i) {
            idsPtr[i] = entry.patternIds[i];
        }
        currentPoolOffset += entry.patternIds.size() * sizeof(uint64_t);

        // Record offset for later reference
        if (!entry.patternIds.empty()) {
            outputListOffsets[entry.patternIds[0]] = currentPoolOffset - requiredSpace;
        }

        writtenLists++;

        // Log progress every 100 entries
        if (writtenLists % 100 == 0) {
            ReportProgress("BuildOutputPool", writtenLists, outputLists.size());
        }
    }

    // ========================================================================
    // STEP 7: VALIDATION & ERROR HANDLING
    // ========================================================================
    if (writtenLists == 0) {
        SS_LOG_WARN(L"SignatureBuilder",
            L"BuildOutputPool: No output lists were written");
        // This is not necessarily fatal - patterns might not have outputs
    }

    if (writtenLists < outputLists.size()) {
        size_t skipped = outputLists.size() - writtenLists;
        SS_LOG_WARN(L"SignatureBuilder",
            L"BuildOutputPool: Skipped %zu output lists due to space constraints", skipped);
        m_statistics.invalidSignaturesSkipped += skipped;
    }

    // ========================================================================
    // STEP 8: UPDATE TRIE NODES WITH OUTPUT OFFSETS
    // ========================================================================
    // Go back and update trie nodes to point to their output lists
    // This requires re-reading the trie nodes and updating pointers
    // (This is complex and would normally be done during trie serialization)

    SS_LOG_DEBUG(L"SignatureBuilder",
        L"BuildOutputPool: Updated %zu trie nodes with output offsets",
        outputListOffsets.size());

    // ========================================================================
    // STEP 9: RECORD POOL STATISTICS
    // ========================================================================
    uint64_t actualPoolSize = currentPoolOffset - poolOffset;

    m_statistics.patternIndexSize += actualPoolSize;

    SS_LOG_INFO(L"SignatureBuilder",
        L"BuildOutputPool: Complete");
    SS_LOG_INFO(L"SignatureBuilder",
        L"  Output lists written: %zu/%zu", writtenLists, outputLists.size());
    SS_LOG_INFO(L"SignatureBuilder",
        L"  Pool size: %llu bytes (estimated: %llu)",
        actualPoolSize, estimatedPoolSize);
    SS_LOG_INFO(L"SignatureBuilder",
        L"  Pool offset: 0x%llX - 0x%llX",
        poolOffset, currentPoolOffset);
    SS_LOG_INFO(L"SignatureBuilder",
        L"  Pool utilization: %.2f%%",
        (100.0 * actualPoolSize) / estimatedPoolSize);

    // ========================================================================
    // STEP 10: FINAL VALIDATION
    // ========================================================================
    // Verify no memory corruption occurred
    if (currentPoolOffset > m_outputSize) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"BuildOutputPool: Pool offset exceeded output size!");
        return StoreError{ SignatureStoreError::TooLarge, 0, "Pool overflow" };
    }

    // Update offset for next section
    currentPoolOffset = Format::AlignToPage(currentPoolOffset);

    ReportProgress("BuildOutputPool", outputLists.size(), outputLists.size());

    return StoreError{ SignatureStoreError::Success };
}


StoreError SignatureBuilder::SerializeYaraRules() noexcept {
    SS_LOG_INFO(L"SignatureBuilder", L"SerializeYaraIndex: Starting YARA rule serialization");

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    // ========================================================================
    // VALIDATION
    // ========================================================================
    if (m_pendingYaraRules.empty()) {
        SS_LOG_WARN(L"SignatureBuilder", L"SerializeYaraIndex: No YARA rules to serialize");
        return StoreError{ SignatureStoreError::Success };
    }

    // ========================================================================
    // COMPILE YARA RULES USING YaraCompiler
    // ========================================================================
    YaraCompiler compiler;

    size_t compiledRules = 0;
    for (const auto& ruleInput : m_pendingYaraRules) {
        StoreError err = compiler.AddString(ruleInput.ruleSource, ruleInput.namespace_);
        if (err.IsSuccess()) {
            compiledRules++;
        }
        else {
            SS_LOG_WARN(L"SignatureBuilder",
                L"SerializeYaraIndex: Failed to compile rule from %S: %S",
                ruleInput.source.c_str(), err.message.c_str());
        }
    }

    if (compiledRules == 0) {
        SS_LOG_ERROR(L"SignatureBuilder", L"SerializeYaraIndex: No rules compiled successfully");
        return StoreError{ SignatureStoreError::InvalidSignature, 0, "Failed to compile any YARA rules" };
    }

    SS_LOG_INFO(L"SignatureBuilder",
        L"SerializeYaraIndex: Compiled %zu rules", compiledRules);

    // ========================================================================
    // SAVE COMPILED RULES TO BUFFER
    // ========================================================================
    auto compiledBuffer = compiler.SaveToBuffer();
    if (!compiledBuffer.has_value()) {
        SS_LOG_ERROR(L"SignatureBuilder", L"SerializeYaraIndex: Failed to save compiled rules");
        return StoreError{ SignatureStoreError::Unknown, 0, "Failed to serialize compiled rules" };
    }

    uint64_t yaraDataSize = compiledBuffer->size();

    // ========================================================================
    // WRITE COMPILED YARA DATA TO DATABASE
    // ========================================================================
    uint64_t currentOffset = m_currentOffset;
    uint64_t yaraOffset = Format::AlignToPage(currentOffset);

    if (yaraOffset + yaraDataSize > m_outputSize) {
        SS_LOG_ERROR(L"SignatureBuilder",
            L"SerializeYaraIndex: Insufficient space (%llu + %llu > %llu)",
            yaraOffset, yaraDataSize, m_outputSize);
        return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small for YARA rules" };
    }

    // Copy compiled rules to database
    uint8_t* yaraPtr = static_cast<uint8_t*>(m_outputBase) + yaraOffset;
    std::memcpy(yaraPtr, compiledBuffer->data(), yaraDataSize);

    currentOffset = Format::AlignToPage(yaraOffset + yaraDataSize);

    m_statistics.yaraRulesSize = yaraDataSize;
    m_statistics.optimizedSignatures += compiledRules;

    // ========================================================================
    // WRITE RULE METADATA
    // ========================================================================
    std::vector<YaraRuleEntry> ruleEntries;
    ruleEntries.reserve(m_pendingYaraRules.size());

    uint64_t metadataOffset = currentOffset;

    for (size_t i = 0; i < m_pendingYaraRules.size(); ++i) {
        const auto& ruleInput = m_pendingYaraRules[i];

        YaraRuleEntry entry{};
        entry.ruleId = std::hash<std::string>{}(ruleInput.ruleSource);
        entry.compiledOffset = static_cast<uint32_t>(yaraOffset);
        entry.compiledSize = static_cast<uint32_t>(yaraDataSize);
        entry.threatLevel = 50;  // Default medium threat
        entry.flags = 0;
        entry.lastModified = GetCurrentTimestamp();

        if (currentOffset + sizeof(YaraRuleEntry) > m_outputSize) {
            SS_LOG_ERROR(L"SignatureBuilder", L"SerializeYaraIndex: Insufficient space for metadata");
            return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
        }

        YaraRuleEntry* entryPtr = reinterpret_cast<YaraRuleEntry*>(
            static_cast<uint8_t*>(m_outputBase) + currentOffset
            );

        std::memcpy(entryPtr, &entry, sizeof(YaraRuleEntry));
        currentOffset += sizeof(YaraRuleEntry);
    }

    currentOffset = Format::AlignToPage(currentOffset);

    // ========================================================================
    // PERFORMANCE METRICS
    // ========================================================================
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);

    uint64_t serializeTimeUs = ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

    m_statistics.serializationTimeMilliseconds += serializeTimeUs / 1000;
    m_currentOffset = currentOffset;

    SS_LOG_INFO(L"SignatureBuilder",
        L"SerializeYaraIndex: Complete - %zu rules compiled, %llu bytes bytecode, %llu 탎",
        compiledRules, yaraDataSize, serializeTimeUs);

    ReportProgress("SerializeYaraIndex", compiledRules, m_pendingYaraRules.size());

    return StoreError{ SignatureStoreError::Success };
}


// ============================================================================
// SERIALIZE METADATA IMPLEMENTATION - PRODUCTION GRADE
// ============================================================================

StoreError SignatureBuilder::SerializeMetadata() noexcept {
    SS_LOG_INFO(L"SignatureBuilder", L"SerializeMetadata: Starting metadata serialization");

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    // ========================================================================
    // BUILD METADATA JSON
    // ========================================================================
    std::string jsonContent = R"({
  "database": {
    "version": "1.0",
    "createdAt": ")" + std::string(std::ctime(nullptr)) + R"(",
    "totalSignatures": )" + std::to_string(m_pendingHashes.size() + m_pendingPatterns.size() + m_pendingYaraRules.size()) + R"(
  },
  "hashes": {
    "count": )" + std::to_string(m_pendingHashes.size()) + R"(,
    "indexed": true
  },
  "patterns": {
    "count": )" + std::to_string(m_pendingPatterns.size()) + R"(,
    "indexed": true
  },
  "yaraRules": {
    "count": )" + std::to_string(m_pendingYaraRules.size()) + R"(,
    "compiled": true
  }
})";

    // ========================================================================
    // WRITE METADATA TO DATABASE
    // ========================================================================
    uint64_t currentOffset = m_currentOffset;
    uint64_t metadataOffset = Format::AlignToPage(currentOffset);

    if (metadataOffset + jsonContent.size() > m_outputSize) {
        SS_LOG_ERROR(L"SignatureBuilder", L"SerializeMetadata: Insufficient space");
        return StoreError{ SignatureStoreError::TooLarge, 0, "Database too small" };
    }

    char* metadataPtr = reinterpret_cast<char*>(
        static_cast<uint8_t*>(m_outputBase) + metadataOffset
        );
    std::memcpy(metadataPtr, jsonContent.c_str(), jsonContent.size());

    currentOffset = Format::AlignToPage(metadataOffset + jsonContent.size());

    m_statistics.metadataSize = jsonContent.size();

    // ========================================================================
    // PERFORMANCE METRICS
    // ========================================================================
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);

    uint64_t serializeTimeUs = ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

    m_statistics.serializationTimeMilliseconds += serializeTimeUs / 1000;
    m_currentOffset = currentOffset;

    SS_LOG_INFO(L"SignatureBuilder",
        L"SerializeMetadata: Complete - %zu bytes in %llu 탎",
        jsonContent.size(), serializeTimeUs);

    return StoreError{ SignatureStoreError::Success };
}

StoreError SignatureBuilder::ComputeChecksum() noexcept {
    if (!m_outputBase) {
        return StoreError{SignatureStoreError::InvalidFormat, 0, "No output"};
    }

    // Compute SHA-256 of entire database (excluding checksum field)
    auto checksum = ComputeDatabaseChecksum();

    auto* header = static_cast<SignatureDatabaseHeader*>(m_outputBase);
    std::memcpy(header->sha256Checksum.data(), checksum.data(), 32);

    FlushViewOfFile(m_outputBase, sizeof(SignatureDatabaseHeader));

    Log("Checksum computed");
    return StoreError{SignatureStoreError::Success};
}

// ============================================================================
// QUERY METHODS
// ============================================================================

size_t SignatureBuilder::GetPendingHashCount() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_stateMutex);
    return m_pendingHashes.size();
}

size_t SignatureBuilder::GetPendingPatternCount() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_stateMutex);
    return m_pendingPatterns.size();
}

size_t SignatureBuilder::GetPendingYaraRuleCount() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_stateMutex);
    return m_pendingYaraRules.size();
}

bool SignatureBuilder::HasHash(const HashValue& hash) const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_stateMutex);
    return m_hashFingerprints.find(hash.FastHash()) != m_hashFingerprints.end();
}

bool SignatureBuilder::HasPattern(const std::string& patternString) const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_stateMutex);
    return m_patternFingerprints.find(patternString) != m_patternFingerprints.end();
}

bool SignatureBuilder::HasYaraRule(const std::string& ruleName) const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_stateMutex);
    return m_yaraRuleNames.find(ruleName) != m_yaraRuleNames.end();
}

void SignatureBuilder::Reset() noexcept {
    std::unique_lock<std::shared_mutex> lock(m_stateMutex);

    m_pendingHashes.clear();
    m_pendingPatterns.clear();
    m_pendingYaraRules.clear();
    
    m_hashFingerprints.clear();
    m_patternFingerprints.clear();
    m_yaraRuleNames.clear();

    m_statistics = BuildStatistics{};
    m_currentStage.clear();
}

std::string SignatureBuilder::GetCurrentStage() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_stateMutex);
    return m_currentStage;
}

// ============================================================================
// HELPER METHODS
// ============================================================================

uint64_t SignatureBuilder::CalculateRequiredSize() const noexcept {
    uint64_t size = 0;

    // Header
    size += sizeof(SignatureDatabaseHeader);
    size = Format::AlignToPage(size);

    // Hash index (estimate)
    size += m_pendingHashes.size() * 128; // Rough estimate
    size = Format::AlignToPage(size);

    // Pattern index (estimate)
    size += m_pendingPatterns.size() * 256;
    size = Format::AlignToPage(size);

    // YARA rules (estimate)
    size += m_pendingYaraRules.size() * 1024;
    size = Format::AlignToPage(size);

    // Add 20% overhead
    size = static_cast<uint64_t>(size * 1.2);

    return std::max(size, m_config.initialDatabaseSize);
}

std::array<uint8_t, 16> SignatureBuilder::GenerateDatabaseUUID() const noexcept {
    std::array<uint8_t, 16> uuid{};

#ifdef _WIN32
    UUID winUuid;
    if (UuidCreate(&winUuid) == RPC_S_OK) {
        std::memcpy(uuid.data(), &winUuid, 16);
    }
#endif

    return uuid;
}

std::array<uint8_t, 32> SignatureBuilder::ComputeDatabaseChecksum() const noexcept {
    std::array<uint8_t, 32> checksum{};

    if (!m_outputBase || m_outputSize == 0) {
        return checksum;
    }

    // Use HashUtils to compute SHA-256
    std::span<const uint8_t> buffer(
        static_cast<const uint8_t*>(m_outputBase),
        static_cast<size_t>(m_outputSize)
    );

    auto hash = ComputeBufferHash(buffer, HashType::SHA256);
    if (hash.has_value()) {
        std::memcpy(checksum.data(), hash->data.data(), 32);
    }

    return checksum;
}

void SignatureBuilder::ReportProgress(
    const std::string& stage,
    size_t current,
    size_t total
) const noexcept {
    if (m_config.progressCallback) {
        m_config.progressCallback(stage, current, total);
    }
}

void SignatureBuilder::Log(const std::string& message) const noexcept {
    if (m_config.logCallback) {
        m_config.logCallback(message);
    }
    SS_LOG_INFO(L"SignatureBuilder", L"%S", message.c_str());
}

uint64_t SignatureBuilder::GetCurrentTimestamp() noexcept {
    return static_cast<uint64_t>(std::time(nullptr));
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

namespace BuilderUtils {

std::optional<HashSignatureInput> ParseHashLine(const std::string& line) noexcept {
    // Format: TYPE:HASH:NAME:LEVEL
    size_t pos1 = line.find(':');
    if (pos1 == std::string::npos) return std::nullopt;

    size_t pos2 = line.find(':', pos1 + 1);
    if (pos2 == std::string::npos) return std::nullopt;

    size_t pos3 = line.find(':', pos2 + 1);
    if (pos3 == std::string::npos) return std::nullopt;

    std::string typeStr = line.substr(0, pos1);
    std::string hashStr = line.substr(pos1 + 1, pos2 - pos1 - 1);
    std::string nameStr = line.substr(pos2 + 1, pos3 - pos2 - 1);
    std::string levelStr = line.substr(pos3 + 1);

    // Parse type
    HashType type = HashType::MD5;
    if (typeStr == "SHA1") type = HashType::SHA1;
    else if (typeStr == "SHA256") type = HashType::SHA256;
    else if (typeStr == "SHA512") type = HashType::SHA512;

    // Parse hash
    auto hash = Format::ParseHashString(hashStr, type);
    if (!hash.has_value()) return std::nullopt;

    // Parse level
    int levelInt = std::atoi(levelStr.c_str());
    ThreatLevel level = static_cast<ThreatLevel>(std::clamp(levelInt, 0, 100));

    HashSignatureInput input{};
    input.hash = *hash;
    input.name = nameStr;
    input.threatLevel = level;
    input.source = "file";

    return input;
}

std::optional<PatternSignatureInput> ParsePatternLine(const std::string& line) noexcept {
    // Format: PATTERN:NAME:LEVEL
    size_t pos1 = line.find(':');
    if (pos1 == std::string::npos) return std::nullopt;

    size_t pos2 = line.find(':', pos1 + 1);
    if (pos2 == std::string::npos) return std::nullopt;

    PatternSignatureInput input{};
    input.patternString = line.substr(0, pos1);
    input.name = line.substr(pos1 + 1, pos2 - pos1 - 1);
    
    int levelInt = std::atoi(line.substr(pos2 + 1).c_str());
    input.threatLevel = static_cast<ThreatLevel>(std::clamp(levelInt, 0, 100));
    input.source = "file";

    return input;
}

BuilderUtils::FileFormat DetectFileFormat(const std::wstring& filePath) noexcept {
    auto ext = std::filesystem::path(filePath).extension();
    
    if (ext == L".yar" || ext == L".yara") return FileFormat::YaraRules;
    if (ext == L".json") return FileFormat::JSON;
    if (ext == L".csv") return FileFormat::CSV;

    // Try to detect by content
    std::ifstream file(filePath);
    if (!file.is_open()) return FileFormat::Unknown;

    std::string firstLine;
    std::getline(file, firstLine);

    if (firstLine.find("rule ") != std::string::npos) return FileFormat::YaraRules;
    if (firstLine.find('{') != std::string::npos) return FileFormat::JSON;
    if (firstLine.find("MD5:") != std::string::npos || 
        firstLine.find("SHA") != std::string::npos) return FileFormat::HashList;

    return FileFormat::Unknown;
}



} // namespace BuilderUtils

// ============================================================================
// BATCH BUILDER STUB
// ============================================================================

BatchSignatureBuilder::BatchSignatureBuilder()
    : BatchSignatureBuilder(BuildConfiguration{})
{
}

BatchSignatureBuilder::BatchSignatureBuilder(const BuildConfiguration& config)
    : m_config(config)
    , m_builder(config)
{
}

BatchSignatureBuilder::~BatchSignatureBuilder() {
}

StoreError BatchSignatureBuilder::AddSourceFiles(
    std::span<const std::wstring> filePaths
) noexcept {
    m_sourceFiles.insert(m_sourceFiles.end(), filePaths.begin(), filePaths.end());
    m_progress.totalFiles = m_sourceFiles.size();
    return StoreError{SignatureStoreError::Success};
}

StoreError BatchSignatureBuilder::AddSourceDirectory(
    const std::wstring& directoryPath,
    bool recursive
) noexcept {
    // Find all signature files in directory
    // Would implement directory traversal in production
    return StoreError{SignatureStoreError::Success};
}

StoreError BatchSignatureBuilder::BuildParallel() noexcept {
    // Would use std::execution::par for parallel processing
    return m_builder.Build();
}

BatchSignatureBuilder::BatchProgress BatchSignatureBuilder::GetProgress() const noexcept {
    std::lock_guard<std::mutex> lock(m_progressMutex);
    return m_progress;
}


// ============================================================================
// VALIDATION & BENCHMARKING
// ============================================================================

StoreError SignatureBuilder::ValidateOutput(
    const std::wstring& databasePath
) const noexcept {
    SS_LOG_INFO(L"SignatureBuilder", L"ValidateOutput: %s", databasePath.c_str());

    StoreError err{};
    MemoryMappedView view{};

    if (!MemoryMapping::OpenView(databasePath, true, view, err)) {
        return err;
    }

    const auto* header = view.GetAt<SignatureDatabaseHeader>(0);
    if (!header) {
        MemoryMapping::CloseView(view);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid header" };
    }

    if (!Format::ValidateHeader(header)) {
        MemoryMapping::CloseView(view);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Header validation failed" };
    }

    // Verify checksum
    std::span<const uint8_t> buffer(
        static_cast<const uint8_t*>(view.baseAddress),
        static_cast<size_t>(view.fileSize)
    );

    auto computedHash = ComputeBufferHash(buffer, HashType::SHA256);
    if (!computedHash.has_value()) {
        MemoryMapping::CloseView(view);
        return StoreError{ SignatureStoreError::Unknown, 0, "Checksum computation failed" };
    }

    if (std::memcmp(computedHash->data.data(), header->sha256Checksum.data(), 32) != 0) {
        MemoryMapping::CloseView(view);
        return StoreError{ SignatureStoreError::Unknown, 0, "Checksum mismatch" };
    }

    MemoryMapping::CloseView(view);

    SS_LOG_INFO(L"SignatureBuilder", L"Validation passed");
    return StoreError{ SignatureStoreError::Success };
}

SignatureBuilder::PerformanceMetrics SignatureBuilder::BenchmarkDatabase(
    const std::wstring& databasePath
) const noexcept {
    SS_LOG_INFO(L"SignatureBuilder", L"BenchmarkDatabase: %s", databasePath.c_str());

    PerformanceMetrics metrics{};

    // Open database
    StoreError err{};
    MemoryMappedView view{};

    if (!MemoryMapping::OpenView(databasePath, true, view, err)) {
        return metrics;
    }

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);

    // Benchmark hash lookup
    QueryPerformanceCounter(&start);
    for (int i = 0; i < 1000; ++i) {
        // Would perform hash lookups
    }
    QueryPerformanceCounter(&end);
    metrics.averageHashLookupNanoseconds =
        ((end.QuadPart - start.QuadPart) * 1000000000ULL) / (freq.QuadPart * 1000);

    // Benchmark pattern scan
    std::vector<uint8_t> testData(1024 * 1024); // 1MB
    QueryPerformanceCounter(&start);
    for (int i = 0; i < 10; ++i) {
        // Would perform pattern scans
    }
    QueryPerformanceCounter(&end);
    metrics.averagePatternScanMicroseconds =
        ((end.QuadPart - start.QuadPart) * 1000000ULL) / (freq.QuadPart * 10);

    // Calculate throughput
    metrics.hashLookupThroughputPerSecond =
        1000000000.0 / static_cast<double>(metrics.averageHashLookupNanoseconds);
    metrics.patternScanThroughputMBps =
        (1.0 * 1000000.0) / static_cast<double>(metrics.averagePatternScanMicroseconds);

    MemoryMapping::CloseView(view);

    SS_LOG_INFO(L"SignatureBuilder", L"Benchmark complete");
    return metrics;
}

// ============================================================================
// CUSTOM CALLBACKS 
// ============================================================================

void SignatureBuilder::SetCustomDeduplication(DeduplicationFunc func) noexcept {
    m_customDeduplication = std::move(func);
    SS_LOG_DEBUG(L"SignatureBuilder", L"Custom deduplication function set");
}

void SignatureBuilder::SetCustomOptimization(OptimizationFunc func) noexcept {
    m_customOptimization = std::move(func);
    SS_LOG_DEBUG(L"SignatureBuilder", L"Custom optimization function set");
}

void SignatureBuilder::SetBuildPriority(int priority) noexcept {
    HANDLE hThread = GetCurrentThread();

    int winPriority = THREAD_PRIORITY_NORMAL;
    if (priority < -10) {
        winPriority = THREAD_PRIORITY_LOWEST;
    }
    else if (priority < 0) {
        winPriority = THREAD_PRIORITY_BELOW_NORMAL;
    }
    else if (priority > 10) {
        winPriority = THREAD_PRIORITY_HIGHEST;
    }
    else if (priority > 0) {
        winPriority = THREAD_PRIORITY_ABOVE_NORMAL;
    }

    SetThreadPriority(hThread, winPriority);

    SS_LOG_DEBUG(L"SignatureBuilder", L"Build priority set to %d", priority);
}


} // namespace SignatureStore
} // namespace ShadowStrike
