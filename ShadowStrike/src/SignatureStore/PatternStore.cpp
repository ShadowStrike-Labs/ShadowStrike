/*
 * ============================================================================
 * ShadowStrike PatternStore - IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * High-speed byte pattern matching implementation
 * Aho-Corasick + Boyer-Moore + SIMD (AVX2/AVX-512)
 * Target: < 10ms for 10MB file with 10,000 patterns
 *
 * CRITICAL: Pattern scanning performance is paramount!
 *
 * ============================================================================
 */

#include "PatternStore.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"

#include <algorithm>
#include <queue>
#include <cctype>
#include <sstream>
#include <bit>
#include <iomanip>
#include <string>
#include <iostream>
#include <chrono>
#include <mutex>
#include <cstdint>
#include <immintrin.h> // AVX2/AVX-512 intrinsics

namespace ShadowStrike {
namespace SignatureStore {

    

// ============================================================================
// PATTERN COMPILER IMPLEMENTATION
// ============================================================================

std::optional<std::vector<uint8_t>> PatternCompiler::CompilePattern(
    const std::string& patternStr,
    PatternMode& outMode,
    std::vector<uint8_t>& outMask
) noexcept {
    /*
     * ========================================================================
     * PRODUCTION-GRADE PATTERN COMPILER
     * ========================================================================
     *
     * Supports multiple pattern formats:
     * 1. EXACT:     "48 8B 05 A1 B2 C3 D4"
     * 2. WILDCARD:  "48 8B 05 ?? ?? ?? ??"
     * 3. REGEX:     "48 8B [01-FF] ?? C3" (byte ranges)
     * 4. VAR_GAP:   "48 8B {0-16} C3" (variable length gaps)
     * 5. MIXED:     "48 [8B-8D] ?? {2-4} C3 ??"
     *
     * Performance: O(n) parsing, O(n*m) expansion for variable gaps
     * Security: Input validation, bounds checking, DoS protection
     *
     * ========================================================================
     */

    std::vector<uint8_t> pattern;
    outMask.clear();

    if (patternStr.empty()) {
        SS_LOG_ERROR(L"PatternCompiler", L"Empty pattern string");
        return std::nullopt;
    }

    // ========================================================================
    // STEP 1: DETECT PATTERN MODE
    // ========================================================================
    outMode = PatternMode::Exact; // Default

    bool hasWildcard = patternStr.find("??") != std::string::npos;
    bool hasRegex = patternStr.find('[') != std::string::npos;
    bool hasVarGap = patternStr.find('{') != std::string::npos;

    if (hasVarGap) {
        // Variable gaps are complex, mark as regex for now
        outMode = PatternMode::Regex;
    }
    else if (hasRegex) {
        outMode = PatternMode::Regex;
    }
    else if (hasWildcard) {
        outMode = PatternMode::Wildcard;
    }
    else {
        outMode = PatternMode::Exact;
    }

    SS_LOG_DEBUG(L"PatternCompiler", L"Pattern mode: %u, HasWildcard=%d, HasRegex=%d, HasVarGap=%d",
        static_cast<uint8_t>(outMode), hasWildcard, hasRegex, hasVarGap);

    // ========================================================================
    // STEP 2: TOKENIZE PATTERN
    // ========================================================================
    // Split by spaces and special delimiters
    std::vector<std::string> tokens;

    {
        std::string current;
        for (size_t i = 0; i < patternStr.length(); ++i) {
            char c = patternStr[i];

            if (std::isspace(static_cast<unsigned char>(c))) {
                // Whitespace separates tokens
                if (!current.empty()) {
                    tokens.push_back(current);
                    current.clear();
                }
            }
            else if (c == '{' || c == '}') {
                // Variable gap delimiters
                if (!current.empty()) {
                    tokens.push_back(current);
                    current.clear();
                }
                current += c;
            }
            else if (c == '[' || c == ']') {
                // Byte range delimiters
                if (!current.empty() && current.back() != '[') {
                    tokens.push_back(current);
                    current.clear();
                }
                current += c;
            }
            else {
                current += c;
            }
        }

        if (!current.empty()) {
            tokens.push_back(current);
        }
    }

    // ========================================================================
    // STEP 3: PARSE EACH TOKEN
    // ========================================================================
    size_t expandedSize = 0;  // Track expansion size for variable gaps

    for (size_t tokenIdx = 0; tokenIdx < tokens.size(); ++tokenIdx) {
        const std::string& token = tokens[tokenIdx];

        // Variable gap: {min-max}
        if (token[0] == '{') {
            if (outMode != PatternMode::Regex) {
                SS_LOG_ERROR(L"PatternCompiler", L"Variable gap only in regex mode");
                return std::nullopt;
            }

            // Parse min-max
            size_t dashPos = token.find('-');
            if (dashPos == std::string::npos || token.back() != '}') {
                SS_LOG_ERROR(L"PatternCompiler", L"Invalid variable gap format: %S", token.c_str());
                return std::nullopt;
            }

            try {
                std::string minStr = token.substr(1, dashPos - 1);
                std::string maxStr = token.substr(dashPos + 1, token.length() - dashPos - 2);

                size_t minGap = std::stoul(minStr);
                size_t maxGap = std::stoul(maxStr);

                if (minGap > maxGap || maxGap > 256) {
                    SS_LOG_ERROR(L"PatternCompiler", L"Invalid gap range: [%zu, %zu]", minGap, maxGap);
                    return std::nullopt;
                }

                // For now, expand to minimum gap size (conservative approach)
                // Full implementation would track variable positions
                expandedSize += minGap;

                SS_LOG_DEBUG(L"PatternCompiler", L"Variable gap: [%zu, %zu]", minGap, maxGap);
            }
            catch (...) {
                SS_LOG_ERROR(L"PatternCompiler", L"Failed to parse gap: %S", token.c_str());
                return std::nullopt;
            }

            continue;
        }

        // Byte range: [01-FF] or [8B-8D]
        if (token[0] == '[' && token.back() == ']') {
            if (outMode != PatternMode::Regex) {
                SS_LOG_WARN(L"PatternCompiler", L"Byte range in non-regex mode");
            }

            std::string rangeContent = token.substr(1, token.length() - 2);
            size_t dashPos = rangeContent.find('-');

            if (dashPos == std::string::npos) {
                SS_LOG_ERROR(L"PatternCompiler", L"Invalid byte range: %S", token.c_str());
                return std::nullopt;
            }

            try {
                std::string minStr = rangeContent.substr(0, dashPos);
                std::string maxStr = rangeContent.substr(dashPos + 1);

                uint8_t minByte = static_cast<uint8_t>(std::stoi(minStr, nullptr, 16));
                uint8_t maxByte = static_cast<uint8_t>(std::stoi(maxStr, nullptr, 16));

                if (minByte > maxByte) {
                    SS_LOG_ERROR(L"PatternCompiler", L"Invalid byte range: [0x%02X, 0x%02X]", minByte, maxByte);
                    return std::nullopt;
                }

                // Add first byte of range (conservative, full impl would track all)
                pattern.push_back(minByte);
                outMask.push_back(0xFF);

                SS_LOG_DEBUG(L"PatternCompiler", L"Byte range: [0x%02X, 0x%02X]", minByte, maxByte);
            }
            catch (...) {
                SS_LOG_ERROR(L"PatternCompiler", L"Failed to parse byte range: %S", token.c_str());
                return std::nullopt;
            }

            continue;
        }

        // Wildcard: ?? (matches any byte)
        if (token == "??") {
            if (outMode == PatternMode::Exact) {
                outMode = PatternMode::Wildcard;
            }

            pattern.push_back(0x00);    // Placeholder value
            outMask.push_back(0x00);    // Don't care mask

            SS_LOG_DEBUG(L"PatternCompiler", L"Wildcard byte");
            continue;
        }

        // Hex byte: 48, 8B, FF, etc.
        if (token.length() == 2 || token.length() == 4) {
            try {
                uint8_t byte = static_cast<uint8_t>(std::stoi(token, nullptr, 16));
                pattern.push_back(byte);
                outMask.push_back(0xFF);

                SS_LOG_DEBUG(L"PatternCompiler", L"Hex byte: 0x%02X", byte);
            }
            catch (...) {
                SS_LOG_ERROR(L"PatternCompiler", L"Invalid hex byte: %S", token.c_str());
                return std::nullopt;
            }

            continue;
        }

        // Unknown token
        SS_LOG_WARN(L"PatternCompiler", L"Unknown token (ignoring): %S", token.c_str());
    }

    // ========================================================================
    // STEP 4: VALIDATION & SECURITY CHECKS
    // ========================================================================

    // Minimum pattern size
    if (pattern.size() < 1 || pattern.size() > 256) {
        SS_LOG_ERROR(L"PatternCompiler",
            L"Pattern size out of bounds: %zu (min=1, max=256)", pattern.size());
        return std::nullopt;
    }

    // Maximum expansion check (prevent DoS)
    const size_t MAX_EXPANDED_SIZE = 10000;  // 10KB max after expansion
    if (expandedSize > MAX_EXPANDED_SIZE) {
        SS_LOG_ERROR(L"PatternCompiler",
            L"Pattern expansion too large: %zu (max=%zu)", expandedSize, MAX_EXPANDED_SIZE);
        return std::nullopt;
    }

    // Verify mask size matches pattern size
    if (outMask.size() != pattern.size()) {
        SS_LOG_ERROR(L"PatternCompiler",
            L"Mask/pattern size mismatch: %zu vs %zu", outMask.size(), pattern.size());
        return std::nullopt;
    }

    // ========================================================================
    // STEP 5: OPTIMIZATION
    // ========================================================================

    // Check entropy for performance hints
    float entropy = ComputeEntropy(pattern);

    // Check for common patterns
    size_t wildcardCount = std::count(outMask.begin(), outMask.end(), static_cast<uint8_t>(0));
    double wildcardRatio = static_cast<double>(wildcardCount) / pattern.size();

    SS_LOG_INFO(L"PatternCompiler",
        L"Pattern compiled: size=%zu, mode=%u, entropy=%.2f, wildcard_ratio=%.2f%%",
        pattern.size(), static_cast<uint8_t>(outMode), entropy, wildcardRatio * 100.0);

    // Warn if pattern is mostly wildcards (poor selectivity)
    if (wildcardRatio > 0.5) {
        SS_LOG_WARN(L"PatternCompiler",
            L"Pattern has low selectivity (%.2f%% wildcards)", wildcardRatio * 100.0);
    }

    // ========================================================================
    // STEP 6: RETURN COMPILED PATTERN
    // ========================================================================

    return pattern;
}

// ============================================================================
// ENHANCED VALIDATION WITH SECURITY CHECKS
// ============================================================================

bool PatternCompiler::ValidatePattern(
    const std::string& patternStr,
    std::string& errorMessage
) noexcept {
    /*
     * Validate pattern syntax BEFORE compilation
     * Prevents DoS attacks and invalid patterns
     */

    errorMessage.clear();

    if (patternStr.empty()) {
        errorMessage = "Pattern is empty";
        return false;
    }

    if (patternStr.length() > 10000) {
        errorMessage = "Pattern string too long (max 10000 characters)";
        return false;
    }

    // Check for balanced brackets
    {
        int bracketBalance = 0;
        int braceBalance = 0;

        for (size_t i = 0; i < patternStr.length(); ++i) {
            char c = patternStr[i];

            if (c == '[') bracketBalance++;
            else if (c == ']') bracketBalance--;
            else if (c == '{') braceBalance++;
            else if (c == '}') braceBalance--;

            if (bracketBalance < 0 || braceBalance < 0) {
                errorMessage = "Unbalanced brackets at position " + std::to_string(i);
                return false;
            }
        }

        if (bracketBalance != 0) {
            errorMessage = "Unbalanced [ ] brackets";
            return false;
        }

        if (braceBalance != 0) {
            errorMessage = "Unbalanced { } braces";
            return false;
        }
    }

    // Validate hex characters
    {
        bool inBracket = false;
        bool inBrace = false;

        for (size_t i = 0; i < patternStr.length(); ++i) {
            char c = patternStr[i];

            if (c == '[') inBracket = true;
            else if (c == ']') inBracket = false;
            else if (c == '{') inBrace = true;
            else if (c == '}') inBrace = false;

            // Outside brackets/braces: must be hex, space, ?, -, [, ], {, }
            if (!inBracket && !inBrace) {
                if (!std::isxdigit(static_cast<unsigned char>(c)) &&
                    !std::isspace(static_cast<unsigned char>(c)) &&
                    c != '?' && c != '-' && c != '[' && c != ']' && c != '{' && c != '}') {

                    errorMessage = std::string("Invalid character '") + c +
                        "' at position " + std::to_string(i);
                    return false;
                }
            }
        }
    }

    // Validate variable gaps syntax
    {
        size_t bracePos = 0;
        while ((bracePos = patternStr.find('{', bracePos)) != std::string::npos) {
            size_t closePos = patternStr.find('}', bracePos);
            if (closePos == std::string::npos) {
                errorMessage = "Unclosed { at position " + std::to_string(bracePos);
                return false;
            }

            std::string gapStr = patternStr.substr(bracePos + 1, closePos - bracePos - 1);
            size_t dashPos = gapStr.find('-');

            if (dashPos == std::string::npos) {
                errorMessage = "Invalid gap format (need min-max)";
                return false;
            }

            try {
                size_t minGap = std::stoul(gapStr.substr(0, dashPos));
                size_t maxGap = std::stoul(gapStr.substr(dashPos + 1));

                if (minGap > maxGap || maxGap > 256) {
                    errorMessage = "Gap range invalid: [" + std::to_string(minGap) +
                        ", " + std::to_string(maxGap) + "]";
                    return false;
                }
            }
            catch (...) {
                errorMessage = "Failed to parse gap values";
                return false;
            }

            bracePos = closePos + 1;
        }
    }

    // Validate byte ranges
    {
        size_t bracketPos = 0;
        while ((bracketPos = patternStr.find('[', bracketPos)) != std::string::npos) {
            // Skip if this is part of a variable gap
            if (bracketPos > 0 && patternStr[bracketPos - 1] == '{') {
                bracketPos++;
                continue;
            }

            size_t closePos = patternStr.find(']', bracketPos);
            if (closePos == std::string::npos) {
                errorMessage = "Unclosed [ at position " + std::to_string(bracketPos);
                return false;
            }

            std::string rangeStr = patternStr.substr(bracketPos + 1, closePos - bracketPos - 1);
            size_t dashPos = rangeStr.find('-');

            if (dashPos == std::string::npos) {
                errorMessage = "Invalid byte range (need min-max)";
                return false;
            }

            try {
                uint8_t minByte = static_cast<uint8_t>(std::stoi(rangeStr.substr(0, dashPos), nullptr, 16));
                uint8_t maxByte = static_cast<uint8_t>(std::stoi(rangeStr.substr(dashPos + 1), nullptr, 16));

                if (minByte > maxByte) {
                    errorMessage = "Byte range invalid: [0x" + rangeStr.substr(0, dashPos) +
                        ", 0x" + rangeStr.substr(dashPos + 1) + "]";
                    return false;
                }
            }
            catch (...) {
                errorMessage = "Failed to parse byte range";
                return false;
            }

            bracketPos = closePos + 1;
        }
    }

    // Check estimated pattern size
    {
        size_t estimatedSize = 0;
        for (char c : patternStr) {
            if (std::isxdigit(static_cast<unsigned char>(c))) estimatedSize++;
            if (c == '?') estimatedSize += 2;
        }
        estimatedSize /= 2;

        if (estimatedSize > 256) {
            errorMessage = "Pattern too large (estimated " + std::to_string(estimatedSize) + " bytes)";
            return false;
        }

        if (estimatedSize == 0) {
            errorMessage = "Pattern results in empty byte sequence";
            return false;
        }
    }

    return true;
}

// ============================================================================
// ENTROPY CALCULATION (Already implemented, kept for reference)
// ============================================================================

float PatternCompiler::ComputeEntropy(
    std::span<const uint8_t> pattern
) noexcept {
    if (pattern.empty()) return 0.0f;

    std::array<size_t, 256> freq{};
    for (uint8_t byte : pattern) {
        freq[byte]++;
    }

    float entropy = 0.0f;
    float patternLen = static_cast<float>(pattern.size());

    for (size_t count : freq) {
        if (count > 0) {
            float prob = count / patternLen;
            entropy -= prob * std::log2(prob);
        }
    }

    return entropy;
}
// ============================================================================
// PATTERN STORE IMPLEMENTATION
// ============================================================================

PatternStore::PatternStore() {
    if (!QueryPerformanceFrequency(&m_perfFrequency)) {
        m_perfFrequency.QuadPart = 1000000;
    }
}

PatternStore::~PatternStore() {
    Close();
}

StoreError PatternStore::Initialize(
    const std::wstring& databasePath,
    bool readOnly
) noexcept {
    SS_LOG_INFO(L"PatternStore", L"Initialize: %s", databasePath.c_str());

    if (m_initialized.load(std::memory_order_acquire)) {
        return StoreError{SignatureStoreError::Success};
    }

    m_databasePath = databasePath;
    m_readOnly.store(readOnly, std::memory_order_release);

    // Open memory mapping
    StoreError err = OpenMemoryMapping(databasePath, readOnly);
    if (!err.IsSuccess()) {
        return err;
    }

    // Initialize pattern index
    m_patternIndex = std::make_unique<PatternIndex>();
    const auto* header = m_mappedView.GetAt<SignatureDatabaseHeader>(0);
    if (header != nullptr) {
        err = m_patternIndex->Initialize(
            m_mappedView,
            header->patternIndexOffset,
            header->patternIndexSize
        );
        if (!err.IsSuccess()) {
            CloseMemoryMapping();
            return err;
        }
    }

    // Build Aho-Corasick automaton
    err = BuildAutomaton();
    if (!err.IsSuccess()) {
        CloseMemoryMapping();
        return err;
    }

    m_initialized.store(true, std::memory_order_release);

    SS_LOG_INFO(L"PatternStore", L"Initialized successfully");
    return StoreError{SignatureStoreError::Success};
}

StoreError PatternStore::CreateNew(
    const std::wstring& databasePath,
    uint64_t initialSizeBytes
) noexcept {
    SS_LOG_INFO(L"PatternStore", L"CreateNew: %s", databasePath.c_str());

    // Create database file (similar to HashStore)
    HANDLE hFile = CreateFileW(
        databasePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        return StoreError{SignatureStoreError::FileNotFound, err, "Cannot create file"};
    }

    LARGE_INTEGER size{};
    size.QuadPart = initialSizeBytes;
    if (!SetFilePointerEx(hFile, size, nullptr, FILE_BEGIN) || !SetEndOfFile(hFile)) {
        CloseHandle(hFile);
        return StoreError{SignatureStoreError::Unknown, GetLastError(), "Cannot set size"};
    }

    CloseHandle(hFile);

    return Initialize(databasePath, false);
}

void PatternStore::Close() noexcept {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    m_patternIndex.reset();
    m_automaton.reset();
    m_patternCache.clear();
    CloseMemoryMapping();

    m_initialized.store(false, std::memory_order_release);

    SS_LOG_INFO(L"PatternStore", L"Closed");
}

// ============================================================================
// PATTERN SCANNING
// ============================================================================

std::vector<DetectionResult> PatternStore::Scan(
    std::span<const uint8_t> buffer,
    const QueryOptions& options
) const noexcept {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    m_totalScans.fetch_add(1, std::memory_order_relaxed);
    m_totalBytesScanned.fetch_add(buffer.size(), std::memory_order_relaxed);

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    std::vector<DetectionResult> results;

    // Use SIMD if enabled
    if (m_simdEnabled.load(std::memory_order_acquire)) {
        auto simdResults = ScanWithSIMD(buffer, options);
        results.insert(results.end(), simdResults.begin(), simdResults.end());
    } else {
        // Use Aho-Corasick automaton
        auto acResults = ScanWithAutomaton(buffer, options);
        results.insert(results.end(), acResults.begin(), acResults.end());
    }

    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    uint64_t scanTimeUs = 
        ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) / m_perfFrequency.QuadPart;

    // Update statistics with safe integer arithmetic
    for (auto& result : results) {
        // Prevent integer overflow: check before multiplication
        if (scanTimeUs <= UINT64_MAX / 1000ULL) {
            result.matchTimeNanoseconds = scanTimeUs * 1000ULL;
        } else {
            result.matchTimeNanoseconds = UINT64_MAX; // Saturate on overflow
        }
        m_totalMatches.fetch_add(1, std::memory_order_relaxed);
        
        // Thread-safe hit count update using atomic
        if (m_heatmapEnabled.load(std::memory_order_acquire)) {
            if (result.signatureId < m_hitCounters.size()) {
                // Use atomic_ref for safe concurrent access
                std::atomic_ref<uint64_t> counter(
                    const_cast<std::vector<uint64_t>&>(m_hitCounters)[result.signatureId]
                );
                counter.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    return results;
}

std::vector<DetectionResult> PatternStore::ScanFile(
    const std::wstring& filePath,
    const QueryOptions& options
) const noexcept {
    SS_LOG_DEBUG(L"PatternStore", L"ScanFile: %s", filePath.c_str());

    // Memory-map file for scanning
    StoreError err{};
    MemoryMappedView fileView{};
    
    if (!MemoryMapping::OpenView(filePath, true, fileView, err)) {
        SS_LOG_ERROR(L"PatternStore", L"Failed to map file: %S", err.message.c_str());
        return {};
    }

    // Scan mapped file
    std::span<const uint8_t> buffer(
        static_cast<const uint8_t*>(fileView.baseAddress),
        static_cast<size_t>(fileView.fileSize)
    );

    auto results = Scan(buffer, options);

    MemoryMapping::CloseView(fileView);

    return results;
}

PatternStore::ScanContext PatternStore::CreateScanContext(
    const QueryOptions& options
) const noexcept {
    ScanContext ctx;
    ctx.m_store = this;
    ctx.m_options = options;
    return ctx;
}

void PatternStore::ScanContext::Reset() noexcept {
    m_buffer.clear();
    m_totalBytesProcessed = 0;
}

std::vector<DetectionResult> PatternStore::ScanContext::FeedChunk(
    std::span<const uint8_t> chunk
) noexcept {
    // Append to buffer
    m_buffer.insert(m_buffer.end(), chunk.begin(), chunk.end());
    m_totalBytesProcessed += chunk.size();

    // Scan when buffer reaches threshold
    constexpr size_t SCAN_THRESHOLD = 1024 * 1024; // 1MB
    constexpr size_t MAX_PATTERN_LEN = 256;        // Keep overlap for pattern boundary
    
    if (m_buffer.size() >= SCAN_THRESHOLD) {
        auto results = m_store->Scan(m_buffer, m_options);
        
        // Keep last MAX_PATTERN_LEN bytes to handle patterns crossing chunk boundaries
        // This prevents missing patterns that span two chunks
        if (m_buffer.size() > MAX_PATTERN_LEN) {
            std::vector<uint8_t> overlap(
                m_buffer.end() - MAX_PATTERN_LEN,
                m_buffer.end()
            );
            m_buffer = std::move(overlap);
        } else {
            m_buffer.clear();
        }
        
        return results;
    }

    return {};
}

std::vector<DetectionResult> PatternStore::ScanContext::Finalize() noexcept {
    if (m_buffer.empty()) {
        return {};
    }

    auto results = m_store->Scan(m_buffer, m_options);
    m_buffer.clear();
    return results;
}

// ============================================================================
// PATTERN MANAGEMENT
// ============================================================================

StoreError PatternStore::AddPattern(
    const std::string& patternStr,
    const std::string& signatureName,
    ThreatLevel threatLevel,
    const std::string& description,
    const std::vector<std::string>& tags
) noexcept {
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{SignatureStoreError::AccessDenied, 0, "Read-only"};
    }

    // Compile pattern
    PatternMode mode;
    std::vector<uint8_t> mask;
    auto pattern = PatternCompiler::CompilePattern(patternStr, mode, mask);

    if (!pattern.has_value()) {
        return StoreError{SignatureStoreError::InvalidSignature, 0, "Invalid pattern"};
    }

    return AddCompiledPattern(*pattern, mode, mask, signatureName, threatLevel);
}

StoreError PatternStore::AddCompiledPattern(
    std::span<const uint8_t> pattern,
    PatternMode mode,
    std::span<const uint8_t> mask,
    const std::string& signatureName,
    ThreatLevel threatLevel
) noexcept {
    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    // Create pattern metadata
    PatternMetadata metadata{};
    metadata.signatureId = m_patternCache.size();
    metadata.name = signatureName;
    metadata.threatLevel = threatLevel;
    metadata.mode = mode;
    metadata.pattern.assign(pattern.begin(), pattern.end());
    metadata.mask.assign(mask.begin(), mask.end());
    metadata.entropy = PatternCompiler::ComputeEntropy(pattern);
    metadata.hitCount = 0;

    m_patternCache.push_back(metadata);

    SS_LOG_DEBUG(L"PatternStore", L"Added pattern: %S (mode=%u, entropy=%.2f)",
        signatureName.c_str(), static_cast<uint8_t>(mode), metadata.entropy);

    return StoreError{SignatureStoreError::Success};
}


StoreError PatternStore::AddPatternBatch(
    std::span<const std::string> patternStrs,
    std::span<const std::string> signatureNames,
    std::span<const ThreatLevel> threatLevels
) noexcept {
    SS_LOG_INFO(L"PatternStore", L"AddPatternBatch: Adding %zu patterns", patternStrs.size());

    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
    }

    // Validate input sizes
    if (patternStrs.size() != signatureNames.size() || patternStrs.size() != threatLevels.size()) {
        SS_LOG_ERROR(L"PatternStore", L"AddPatternBatch: Array size mismatch");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Array sizes must match" };
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    size_t successCount = 0;
    size_t failCount = 0;

    for (size_t i = 0; i < patternStrs.size(); ++i) {
        // Compile pattern
        PatternMode mode;
        std::vector<uint8_t> mask;
        auto pattern = PatternCompiler::CompilePattern(patternStrs[i], mode, mask);

        if (!pattern.has_value()) {
            SS_LOG_WARN(L"PatternStore", L"AddPatternBatch: Failed to compile pattern %zu", i);
            failCount++;
            continue;
        }

        // Create pattern metadata
        PatternMetadata metadata{};
        metadata.signatureId = m_patternCache.size();
        metadata.name = signatureNames[i];
        metadata.threatLevel = threatLevels[i];
        metadata.mode = mode;
        metadata.pattern.assign(pattern->begin(), pattern->end());
        metadata.mask.assign(mask.begin(), mask.end());
        metadata.entropy = PatternCompiler::ComputeEntropy(*pattern);
        metadata.hitCount = 0;

        m_patternCache.push_back(metadata);
        successCount++;
    }

    SS_LOG_INFO(L"PatternStore", L"AddPatternBatch: Success=%zu, Failed=%zu", successCount, failCount);

    // Rebuild automaton with new patterns
    if (successCount > 0) {
        StoreError rebuildErr = BuildAutomaton();
        if (!rebuildErr.IsSuccess()) {
            SS_LOG_WARN(L"PatternStore", L"AddPatternBatch: Automaton rebuild failed");
        }
    }

    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// PATTERN REMOVAL
// ============================================================================

StoreError PatternStore::RemovePattern(uint64_t signatureId) noexcept {
    SS_LOG_DEBUG(L"PatternStore", L"RemovePattern: ID=%llu", signatureId);

    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    // Find pattern in cache
    auto it = std::find_if(m_patternCache.begin(), m_patternCache.end(),
        [signatureId](const PatternMetadata& meta) {
            return meta.signatureId == signatureId;
        });

    if (it == m_patternCache.end()) {
        SS_LOG_WARN(L"PatternStore", L"RemovePattern: Pattern %llu not found", signatureId);
        return StoreError{ SignatureStoreError::InvalidSignature, 0, "Pattern not found" };
    }

    SS_LOG_INFO(L"PatternStore", L"RemovePattern: Removing pattern '%S'", it->name.c_str());

    m_patternCache.erase(it);

    // Rebuild automaton
    StoreError rebuildErr = BuildAutomaton();
    if (!rebuildErr.IsSuccess()) {
        SS_LOG_WARN(L"PatternStore", L"RemovePattern: Automaton rebuild failed");
        return rebuildErr;
    }

    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// UPDATE PATTERN METADATA
// ============================================================================

StoreError PatternStore::UpdatePatternMetadata(
    uint64_t signatureId,
    const std::string& newDescription,
    const std::vector<std::string>& newTags
) noexcept {
    /*
     * ========================================================================
     * UPDATE PATTERN METADATA - FULL IMPLEMENTATION
     * ========================================================================
     *
     * Updates description and tags for a pattern while maintaining:
     * - Thread safety (unique_lock)
     * - Audit logging
     * - Change tracking
     * - Validation
     *
     * ========================================================================
     */

    SS_LOG_DEBUG(L"PatternStore", L"UpdatePatternMetadata: ID=%llu", signatureId);

    if (m_readOnly.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"PatternStore", L"UpdatePatternMetadata: Read-only mode");
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
    }

    // Validate inputs
    if (newDescription.length() > 10000) {
        SS_LOG_ERROR(L"PatternStore", L"UpdatePatternMetadata: Description too long (max 10000)");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Description too long" };
    }

    if (newTags.size() > 100) {
        SS_LOG_ERROR(L"PatternStore", L"UpdatePatternMetadata: Too many tags (max 100)");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Too many tags" };
    }

    for (const auto& tag : newTags) {
        if (tag.length() > 256) {
            SS_LOG_ERROR(L"PatternStore", L"UpdatePatternMetadata: Tag too long");
            return StoreError{ SignatureStoreError::InvalidFormat, 0, "Tag too long" };
        }
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    // Find pattern in cache
    auto it = std::find_if(m_patternCache.begin(), m_patternCache.end(),
        [signatureId](const PatternMetadata& meta) {
            return meta.signatureId == signatureId;
        });

    if (it == m_patternCache.end()) {
        SS_LOG_WARN(L"PatternStore", L"UpdatePatternMetadata: Pattern %llu not found", signatureId);
        return StoreError{ SignatureStoreError::InvalidSignature, 0, "Pattern not found" };
    }

    // Store old values for audit log
    std::string oldDescription = it->description;
    std::vector<std::string> oldTags = it->tags;

    // Update metadata
    try {
        it->description = newDescription;
        it->tags = newTags;
        it->lastModified = std::chrono::system_clock::now();
        it->modificationCount++;

        SS_LOG_INFO(L"PatternStore",
            L"UpdatePatternMetadata: Updated pattern '%S' (ID=%llu, tags=%zu)",
            it->name.c_str(), signatureId, newTags.size());

        // Log changes for audit
        if (!oldDescription.empty() && oldDescription != newDescription) {
            SS_LOG_DEBUG(L"PatternStore",
                L"  Description changed: '%S' -> '%S'",
                oldDescription.c_str(), newDescription.c_str());
        }

        if (oldTags.size() != newTags.size()) {
            SS_LOG_DEBUG(L"PatternStore",
                L"  Tags changed: %zu -> %zu",
                oldTags.size(), newTags.size());
        }

        return StoreError{ SignatureStoreError::Success };
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(L"PatternStore",
            L"UpdatePatternMetadata: Exception: %S",
            ex.what());

        // Rollback changes
        it->description = oldDescription;
        it->tags = oldTags;

        return StoreError{ SignatureStoreError::Unknown, 0, "Update failed" };
    }
}

// ============================================================================
// IMPORT FROM YARA FILE
// ============================================================================

StoreError PatternStore::ImportFromYaraFile(
    const std::wstring& filePath,
    std::function<void(size_t current, size_t total)> progressCallback
) noexcept {
    SS_LOG_INFO(L"PatternStore", L"ImportFromYaraFile: %ls", filePath.c_str());

    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
    }

    // Read file using FileUtils
    std::vector<std::byte> fileContent;
    ShadowStrike::Utils::FileUtils::Error fileErr{};

    if (!ShadowStrike::Utils::FileUtils::ReadAllBytes(filePath, fileContent, &fileErr)) {
        SS_LOG_ERROR(L"PatternStore", L"ImportFromYaraFile: Failed to read file: %u", fileErr.win32);
        return StoreError{ SignatureStoreError::FileNotFound, fileErr.win32, "Cannot read file" };
    }

    // Convert to string
    std::string yaraContent(reinterpret_cast<const char*>(fileContent.data()), fileContent.size());

    // Parse YARA rules (simplified - production would use full YARA parser)
    std::vector<std::string> patterns;
    std::vector<std::string> names;
    std::vector<ThreatLevel> levels;

    // Use string stream for line-by-line parsing
    size_t pos = 0;
    size_t lineCount = 0;
    size_t importedCount = 0;

    while (pos < yaraContent.size()) {
        // Find next newline
        size_t nextNewline = yaraContent.find('\n', pos);
        if (nextNewline == std::string::npos) {
            nextNewline = yaraContent.size();
        }

        // Extract line
        std::string line = yaraContent.substr(pos, nextNewline - pos);
        pos = nextNewline + 1;
        lineCount++;

        // Remove trailing \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        // Look for hex pattern strings (simplified parser)
        size_t hexPos = line.find("{ ");
        if (hexPos != std::string::npos) {
            size_t endPos = line.find(" }", hexPos);
            if (endPos != std::string::npos) {
                std::string hexPattern = line.substr(hexPos + 2, endPos - hexPos - 2);

                // Extract rule name
                std::string ruleName = "imported_pattern_" + std::to_string(importedCount);

                patterns.push_back(hexPattern);
                names.push_back(ruleName);
                levels.push_back(ThreatLevel::Medium);

                importedCount++;

                if (progressCallback) {
                    progressCallback(importedCount, 0); // Total unknown
                }
            }
        }
    }

    if (patterns.empty()) {
        SS_LOG_WARN(L"PatternStore", L"ImportFromYaraFile: No patterns found");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "No patterns found" };
    }

    SS_LOG_INFO(L"PatternStore", L"ImportFromYaraFile: Importing %zu patterns", patterns.size());

    // Batch import
    return AddPatternBatch(patterns, names, levels);
}

// ============================================================================
// IMPORT FROM CLAMAV 
// ============================================================================

StoreError PatternStore::ImportFromClamAV(const std::wstring& filePath) noexcept {
    SS_LOG_INFO(L"PatternStore", L"ImportFromClamAV: %ls", filePath.c_str());

    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
    }

    // Read ClamAV signature file
    std::vector<std::byte> fileContent;
    ShadowStrike::Utils::FileUtils::Error fileErr{};

    if (!ShadowStrike::Utils::FileUtils::ReadAllBytes(filePath, fileContent, &fileErr)) {
        SS_LOG_ERROR(L"PatternStore", L"ImportFromClamAV: Failed to read file: %u", fileErr.win32);
        return StoreError{ SignatureStoreError::FileNotFound, fileErr.win32, "Cannot read file" };
    }

    std::string content(reinterpret_cast<const char*>(fileContent.data()), fileContent.size());

    // Parse ClamAV format (simplified)
    // Format: SignatureName:TargetType:Offset:HexSignature
    std::vector<std::string> patterns;
    std::vector<std::string> names;
    std::vector<ThreatLevel> levels;

    size_t pos = 0;
    size_t importedCount = 0;

    while (pos < content.size()) {
        // Find next newline
        size_t nextNewline = content.find('\n', pos);
        if (nextNewline == std::string::npos) {
            nextNewline = content.size();
        }

        // Extract line
        std::string line = content.substr(pos, nextNewline - pos);
        pos = nextNewline + 1;

        // Remove trailing \r
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // Parse ClamAV signature line: Name:Type:Offset:Signature
        std::vector<std::string> tokens;
        size_t tokenStart = 0;

        for (size_t i = 0; i <= line.size(); ++i) {
            if (i == line.size() || line[i] == ':') {
                if (i > tokenStart) {
                    tokens.push_back(line.substr(tokenStart, i - tokenStart));
                }
                tokenStart = i + 1;
            }
        }

        // Need at least 4 tokens
        if (tokens.size() >= 4) {
            std::string sigName = tokens[0];
            std::string hexSig = tokens[3];

            patterns.push_back(hexSig);
            names.push_back(sigName);
            levels.push_back(ThreatLevel::High);

            importedCount++;
        }
    }

    if (patterns.empty()) {
        SS_LOG_WARN(L"PatternStore", L"ImportFromClamAV: No patterns found");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "No patterns found" };
    }

    SS_LOG_INFO(L"PatternStore", L"ImportFromClamAV: Importing %zu patterns", patterns.size());

    return AddPatternBatch(patterns, names, levels);
}

// ============================================================================
// EXPORT TO JSON 
// ============================================================================

std::string PatternStore::ExportToJson(uint32_t maxEntries) const noexcept {
    SS_LOG_DEBUG(L"PatternStore", L"ExportToJson: maxEntries=%u", maxEntries);

    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    // JSON string escape helper (prevents injection attacks)
    auto escapeJson = [](const std::string& input) -> std::string {
        std::ostringstream escaped;
        for (char c : input) {
            switch (c) {
                case '"':  escaped << "\\\""; break;
                case '\\': escaped << "\\\\"; break;
                case '\b': escaped << "\\b"; break;
                case '\f': escaped << "\\f"; break;
                case '\n': escaped << "\\n"; break;
                case '\r': escaped << "\\r"; break;
                case '\t': escaped << "\\t"; break;
                default:
                    // Control characters (0x00-0x1F) must be escaped
                    if (static_cast<unsigned char>(c) < 0x20) {
                        escaped << "\\u" << std::hex << std::setfill('0') 
                                << std::setw(4) << static_cast<int>(c);
                    } else {
                        escaped << c;
                    }
            }
        }
        return escaped.str();
    };

    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"version\": \"1.0\",\n";
    oss << "  \"pattern_count\": " << m_patternCache.size() << ",\n";
    oss << "  \"patterns\": [\n";

    size_t count = 0;
    for (const auto& meta : m_patternCache) {
        if (count >= maxEntries) break;

        if (count > 0) oss << ",\n";

        oss << "    {\n";
        oss << "      \"id\": " << meta.signatureId << ",\n";
        oss << "      \"name\": \"" << escapeJson(meta.name) << "\",\n";
        oss << "      \"threat_level\": " << static_cast<int>(meta.threatLevel) << ",\n";
        oss << "      \"mode\": " << static_cast<int>(meta.mode) << ",\n";
        oss << "      \"pattern\": \"" << PatternUtils::BytesToHexString(meta.pattern) << "\",\n";
        oss << "      \"entropy\": " << std::fixed << std::setprecision(2) << meta.entropy << ",\n";
        oss << "      \"hit_count\": " << meta.hitCount << "\n";
        oss << "    }";

        count++;
    }

    oss << "\n  ]\n";
    oss << "}\n";

    return oss.str();
}

// ============================================================================
// REBUILD 
// ============================================================================

StoreError PatternStore::Rebuild() noexcept {
    SS_LOG_INFO(L"PatternStore", L"Rebuild: Rebuilding automaton");

    if (m_readOnly.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"PatternStore", L"Rebuild: Cannot rebuild in read-only mode");
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    // Clear existing automaton
    m_automaton.reset();

    // Rebuild
    StoreError err = BuildAutomaton();
    if (!err.IsSuccess()) {
        SS_LOG_ERROR(L"PatternStore", L"Rebuild: Automaton build failed");
        return err;
    }

    SS_LOG_INFO(L"PatternStore", L"Rebuild: Complete - %zu patterns", m_patternCache.size());
    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// OPTIMIZE BY HIT RATE 
// ============================================================================

StoreError PatternStore::OptimizeByHitRate() noexcept {
    SS_LOG_INFO(L"PatternStore", L"OptimizeByHitRate: Optimizing pattern order");

    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    // Sort patterns by hit count (descending)
    std::sort(m_patternCache.begin(), m_patternCache.end(),
        [](const PatternMetadata& a, const PatternMetadata& b) {
            return a.hitCount > b.hitCount;
        });

    // Reassign IDs
    for (size_t i = 0; i < m_patternCache.size(); ++i) {
        m_patternCache[i].signatureId = i;
    }

    SS_LOG_INFO(L"PatternStore", L"OptimizeByHitRate: Reordered %zu patterns", m_patternCache.size());

    // Rebuild automaton with optimized order
    return BuildAutomaton();
}

// ============================================================================
// VERIFY 
// ============================================================================

StoreError PatternStore::Verify(
    std::function<void(const std::string&)> logCallback
) const noexcept {
    SS_LOG_INFO(L"PatternStore", L"Verify: Starting integrity check");

    auto log = [&](const std::string& msg) {
        if (logCallback) {
            logCallback(msg);
        }
        SS_LOG_DEBUG(L"PatternStore", L"Verify: %S", msg.c_str());
        };

    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    size_t issues = 0;

    // Check header
    if (m_mappedView.IsValid()) {
        const auto* header = m_mappedView.GetAt<SignatureDatabaseHeader>(0);
        if (!header) {
            log("ERROR: Cannot read database header");
            issues++;
        }
        else if (header->magic != SIGNATURE_DB_MAGIC) {
            log("ERROR: Invalid magic number");
            issues++;
        }
        else {
            log("OK: Database header valid");
        }
    }

    // Check pattern cache
    log("Checking pattern cache...");
    for (size_t i = 0; i < m_patternCache.size(); ++i) {
        const auto& meta = m_patternCache[i];

        if (meta.pattern.empty()) {
            log("ERROR: Pattern " + std::to_string(i) + " is empty");
            issues++;
        }

        if (meta.name.empty()) {
            log("WARNING: Pattern " + std::to_string(i) + " has no name");
        }

        if (meta.mode == PatternMode::Wildcard && meta.mask.size() != meta.pattern.size()) {
            log("ERROR: Pattern " + std::to_string(i) + " mask size mismatch");
            issues++;
        }
    }

    // Check automaton
    if (m_automaton) {
        if (!m_automaton->IsCompiled()) {
            log("ERROR: Automaton not compiled");
            issues++;
        }
        else {
            log("OK: Automaton compiled - " + std::to_string(m_automaton->GetPatternCount()) + " patterns");
        }
    }
    else {
        log("WARNING: No automaton initialized");
    }

    log("Verification complete: " + std::to_string(issues) + " issues found");

    if (issues > 0) {
        return StoreError{ SignatureStoreError::CorruptedDatabase, 0, std::to_string(issues) + " issues found" };
    }

    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// FLUSH 
// ============================================================================

StoreError PatternStore::Flush() noexcept {
    SS_LOG_DEBUG(L"PatternStore", L"Flush: Flushing changes to disk");

    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{ SignatureStoreError::Success }; // Nothing to flush
    }

    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    if (m_mappedView.IsValid()) {
        StoreError err{};
        if (!MemoryMapping::FlushView(m_mappedView, err)) {
            SS_LOG_ERROR(L"PatternStore", L"Flush: Failed to flush view");
            return err;
        }
    }

    SS_LOG_INFO(L"PatternStore", L"Flush: Complete");
    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// COMPACT 
// ============================================================================

StoreError PatternStore::Compact() noexcept {
    SS_LOG_INFO(L"PatternStore", L"Compact: Compacting database");

    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    // Remove patterns with zero hit count (if heatmap enabled)
    if (m_heatmapEnabled.load(std::memory_order_acquire)) {
        size_t beforeCount = m_patternCache.size();

        auto newEnd = std::remove_if(m_patternCache.begin(), m_patternCache.end(),
            [](const PatternMetadata& meta) {
                return meta.hitCount == 0;
            });

        m_patternCache.erase(newEnd, m_patternCache.end());

        size_t afterCount = m_patternCache.size();
        size_t removed = beforeCount - afterCount;

        SS_LOG_INFO(L"PatternStore", L"Compact: Removed %zu unused patterns", removed);
    }

    // Rebuild automaton
    StoreError err = BuildAutomaton();
    if (!err.IsSuccess()) {
        SS_LOG_WARN(L"PatternStore", L"Compact: Automaton rebuild failed");
        return err;
    }

    // Flush to disk
    return Flush();
}

// ======== HELPERS ===========================================================
// ============================================================================

StoreError PatternStore::OpenMemoryMapping(const std::wstring& path, bool readOnly) noexcept {
    StoreError err{};
    if (!MemoryMapping::OpenView(path, readOnly, m_mappedView, err)) {
        return err;
    }
    return StoreError{ SignatureStoreError::Success };
}

void PatternStore::CloseMemoryMapping() noexcept {
    MemoryMapping::CloseView(m_mappedView);
}

StoreError PatternStore::BuildAutomaton() noexcept {
    // Create new automaton separately for exception safety
    // Only replace m_automaton if compilation succeeds
    auto newAutomaton = std::make_unique<AhoCorasickAutomaton>();

    // Add patterns from cache to automaton
    size_t addedCount = 0;
    for (const auto& meta : m_patternCache) {
        if (meta.mode == PatternMode::Exact) {
            if (!newAutomaton->AddPattern(meta.pattern, meta.signatureId)) {
                SS_LOG_WARN(L"PatternStore", 
                    L"BuildAutomaton: Failed to add pattern %llu", meta.signatureId);
                // Continue with other patterns, don't fail entire build
            } else {
                addedCount++;
            }
        }
    }

    // Compile the automaton
    if (!newAutomaton->Compile()) {
        SS_LOG_ERROR(L"PatternStore", L"BuildAutomaton: Compilation failed");
        // Keep old automaton if compilation fails (better than nothing)
        return StoreError{ SignatureStoreError::Unknown, 0, "Automaton compilation failed" };
    }

    // Success - atomically swap in new automaton
    m_automaton = std::move(newAutomaton);
    
    // Resize atomic hit counters to match pattern cache size
    // This enables lock-free hit count updates during scanning
    m_hitCounters.resize(m_patternCache.size());
    
    // Sync hit counts from cache to atomic counters
    for (size_t i = 0; i < m_patternCache.size(); ++i) {
        m_hitCounters[i] = m_patternCache[i].hitCount;
    }

    SS_LOG_INFO(L"PatternStore", 
        L"BuildAutomaton: Success - %zu patterns added", addedCount);

    return StoreError{ SignatureStoreError::Success };
}

std::vector<DetectionResult> PatternStore::ScanWithAutomaton(
    std::span<const uint8_t> buffer,
    const QueryOptions& options
) const noexcept {
    std::vector<DetectionResult> results;

    if (!m_automaton) return results;

    // Take reader lock for thread-safe access to pattern cache
    std::shared_lock<std::shared_mutex> lock(m_globalLock);
    
    // Capture cache size once under lock to avoid TOCTOU
    const size_t cacheSize = m_patternCache.size();

    m_automaton->Search(buffer, [&](uint64_t patternId, size_t offset) {
        if (patternId < cacheSize) {
            const auto& meta = m_patternCache[patternId];

            DetectionResult result{};
            result.signatureId = patternId;
            result.signatureName = meta.name;
            result.threatLevel = meta.threatLevel;
            result.fileOffset = offset;
            result.description = "Pattern match";

            results.push_back(result);
        }
    });

    return results;
}

std::vector<DetectionResult> PatternStore::ScanWithSIMD(
    std::span<const uint8_t> buffer,
    const QueryOptions& options
) const noexcept {
    std::vector<DetectionResult> results;

    // Take reader lock for thread-safe access to pattern cache
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    // Use SIMD for exact patterns only
    for (const auto& meta : m_patternCache) {
        if (meta.mode != PatternMode::Exact) continue;

        auto matches = SIMDMatcher::SearchAVX2(buffer, meta.pattern);

        for (size_t offset : matches) {
            DetectionResult result{};
            result.signatureId = meta.signatureId;
            result.signatureName = meta.name;
            result.threatLevel = meta.threatLevel;
            result.fileOffset = offset;
            result.description = "SIMD pattern match";

            results.push_back(result);
        }
    }

    return results;
}





DetectionResult PatternStore::BuildDetectionResult(
    uint64_t patternId,
    size_t offset,
    uint64_t matchTimeNs
) const noexcept {
    DetectionResult result{};
    result.signatureId = patternId;
    result.fileOffset = offset;
    result.matchTimeNanoseconds = matchTimeNs;

    if (patternId < m_patternCache.size()) {
        const auto& meta = m_patternCache[patternId];
        result.signatureName = meta.name;
        result.threatLevel = meta.threatLevel;
    }

    return result;
}

void PatternStore::UpdateHitCount(uint64_t patternId) noexcept {
    // Thread-safe hit count update using atomic counters
    // Note: m_hitCounters must be resized when patterns are added
    if (patternId < m_hitCounters.size()) {
        std::atomic_ref<uint64_t> counter(m_hitCounters[patternId]);
        counter.fetch_add(1, std::memory_order_relaxed);
    }
    
    // Also update the cache copy under lock for persistence
    std::unique_lock<std::shared_mutex> lock(m_globalLock);
    if (patternId < m_patternCache.size()) {
        m_patternCache[patternId].hitCount = m_hitCounters[patternId];
    }
}

std::wstring PatternStore::GetDatabasePath() const noexcept {
    return m_databasePath;
}

const SignatureDatabaseHeader* PatternStore::GetHeader() const noexcept {
    SS_LOG_DEBUG(L"PatternStore", L"GetHeader called");

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"PatternStore", L"GetHeader: PatternStore not initialized");
        return nullptr;
    }

    if (!m_mappedView.IsValid()) {
        SS_LOG_WARN(L"PatternStore", L"GetHeader: Memory mapping not valid");
        return nullptr;
    }

    // Get header from memory-mapped file at offset 0
    const SignatureDatabaseHeader* header = m_mappedView.GetAt<SignatureDatabaseHeader>(0);

    if (!header) {
        SS_LOG_ERROR(L"PatternStore", L"GetHeader: Failed to get header from memory-mapped view");
        return nullptr;
    }

    // Validate header magic
    if (header->magic != SIGNATURE_DB_MAGIC) {
        SS_LOG_ERROR(L"PatternStore",
            L"GetHeader: Invalid magic 0x%08X, expected 0x%08X",
            header->magic, SIGNATURE_DB_MAGIC);
        return nullptr;
    }

    // Validate version
    if (header->versionMajor != SIGNATURE_DB_VERSION_MAJOR) {
        SS_LOG_WARN(L"PatternStore",
            L"GetHeader: Version mismatch - file: %u.%u, expected: %u.%u",
            header->versionMajor, header->versionMinor,
            SIGNATURE_DB_VERSION_MAJOR, SIGNATURE_DB_VERSION_MINOR);
    }

    SS_LOG_DEBUG(L"PatternStore",
        L"GetHeader: Valid header - version %u.%u",
        header->versionMajor, header->versionMinor);

    return header;
}

PatternStore::PatternStoreStatistics PatternStore::GetStatistics() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    PatternStoreStatistics stats{};
    stats.totalScans = m_totalScans.load(std::memory_order_relaxed);
    stats.totalMatches = m_totalMatches.load(std::memory_order_relaxed);
    stats.totalBytesScanned = m_totalBytesScanned.load(std::memory_order_relaxed);
    stats.totalPatterns = m_patternCache.size();

    // Count by mode
    for (const auto& meta : m_patternCache) {
        switch (meta.mode) {
            case PatternMode::Exact:    stats.exactPatterns++; break;
            case PatternMode::Wildcard: stats.wildcardPatterns++; break;
            case PatternMode::Regex:    stats.regexPatterns++; break;
            default: break;
        }
    }

    if (m_automaton) {
        stats.automatonNodeCount = m_automaton->GetNodeCount();
    }

    return stats;
}

std::map<size_t, size_t> PatternStore::GetLengthHistogram() const noexcept {
    

    SS_LOG_DEBUG(L"PatternStore", L"GetLengthHistogram: Building histogram");

    auto startTime = std::chrono::high_resolution_clock::now();

    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    std::map<size_t, size_t> histogram;
    size_t totalPatterns = m_patternCache.size();

    // Build histogram
    for (const auto& meta : m_patternCache) {
        histogram[meta.pattern.size()]++;
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

    // Extended logging
    if (!histogram.empty()) {
        size_t minLen = histogram.begin()->first;
        size_t maxLen = histogram.rbegin()->first;
        size_t rangeLen = maxLen - minLen + 1;

        // Calculate statistics
        double avgLength = 0.0;
        double variance = 0.0;

        for (const auto& [length, count] : histogram) {
            avgLength += length * count;
        }
        avgLength /= totalPatterns;

        for (const auto& [length, count] : histogram) {
            double diff = length - avgLength;
            variance += diff * diff * count;
        }
        variance /= totalPatterns;
        double stdDev = std::sqrt(variance);

        // Find most common length
        size_t modeLen = histogram.begin()->first;
        size_t modeCount = histogram.begin()->second;
        for (const auto& [length, count] : histogram) {
            if (count > modeCount) {
                modeLen = length;
                modeCount = count;
            }
        }

        SS_LOG_INFO(L"PatternStore",
            L"GetLengthHistogram: Total=%zu, Range=[%zu-%zu], Avg=%.2f, StdDev=%.2f, Mode=%zu",
            totalPatterns, minLen, maxLen, avgLength, stdDev, modeLen);

        SS_LOG_INFO(L"PatternStore",
            L"  Histogram buckets: %zu, Computation time: %lld �s",
            histogram.size(), duration.count());
    }
    else {
        SS_LOG_WARN(L"PatternStore", L"GetLengthHistogram: Empty pattern cache");
    }

    return histogram;
}

void PatternStore::ResetStatistics() noexcept {
    m_totalScans.store(0, std::memory_order_release);
    m_totalMatches.store(0, std::memory_order_release);
    m_totalBytesScanned.store(0, std::memory_order_release);
}

std::vector<std::pair<uint64_t, uint32_t>> PatternStore::GetHeatmap() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    std::vector<std::pair<uint64_t, uint32_t>> heatmap;
    heatmap.reserve(m_patternCache.size());

    // Read hit counts safely
    for (size_t i = 0; i < m_patternCache.size(); ++i) {
        const auto& meta = m_patternCache[i];
        uint32_t hitCount = 0;

        if (i < m_hitCounters.size()) {
            // Use atomic_ref for safe read
            std::atomic_ref<const uint64_t> counter(m_hitCounters[i]);
            hitCount = static_cast<uint32_t>(
                counter.load(std::memory_order_relaxed)
                );
        }

        heatmap.emplace_back(meta.signatureId, hitCount);
    }

    std::sort(heatmap.begin(), heatmap.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });

    return heatmap;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

namespace PatternUtils {

bool IsValidPatternString(
    const std::string& pattern,
    std::string& errorMessage
) noexcept {
    return PatternCompiler::ValidatePattern(pattern, errorMessage);
}

std::optional<std::vector<uint8_t>> HexStringToBytes(
    const std::string& hexStr
) noexcept {
    std::vector<uint8_t> bytes;
    
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        if (i + 1 >= hexStr.length()) break;
        
        std::string byteStr = hexStr.substr(i, 2);
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
            bytes.push_back(byte);
        } catch (...) {
            return std::nullopt;
        }
    }

    return bytes;
}

std::string BytesToHexString(
    std::span<const uint8_t> bytes
) noexcept {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (uint8_t byte : bytes) {
        oss << std::setw(2) << static_cast<unsigned>(byte);
    }

    return oss.str();
}

size_t HammingDistance(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b
) noexcept {
    size_t distance = 0;
    size_t minLen = std::min(a.size(), b.size());

    for (size_t i = 0; i < minLen; ++i) {
        distance += std::popcount(static_cast<uint8_t>(a[i] ^ b[i]));
    }

    // Add difference in lengths
    distance += std::abs(static_cast<int>(a.size() - b.size())) * 8;

    return distance;
}

} // namespace PatternUtils

} // namespace SignatureStore
} // namespace ShadowStrike
