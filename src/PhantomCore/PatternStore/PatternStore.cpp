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
/*
 * ============================================================================
 * ShadowStrike PatternStore - IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 *
 * High-speed byte pattern matching implementation
 * Aho-Corasick + Boyer-Moore + SIMD (AVX2/AVX-512)
 * Target: < 10ms for 10MB file with 10,000 patterns
 *
 * CRITICAL: Pattern scanning performance is paramount!
 *
 * ============================================================================
 */

#include"pch.h"
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
#include <cmath>
#include <limits>
#include <immintrin.h> // AVX2/AVX-512 intrinsics

namespace ShadowStrike {
namespace PatternStore {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace {

    // Maximum pattern string length (DoS protection)
    constexpr size_t MAX_PATTERN_STRING_LENGTH = 10'000;
    
    // Maximum compiled pattern size
    constexpr size_t MAX_COMPILED_PATTERN_SIZE = 256;
    
    // Minimum compiled pattern size
    constexpr size_t MIN_COMPILED_PATTERN_SIZE = 1;
    
    // Maximum expansion size for variable gaps (DoS protection)
    constexpr size_t MAX_EXPANDED_SIZE = 10'000;
    
    // Maximum variable gap range
    constexpr size_t MAX_VAR_GAP_RANGE = 256;
    
    // Wildcard ratio warning threshold
    constexpr double WILDCARD_RATIO_WARN_THRESHOLD = 0.5;
    
    // Scan threshold for incremental scanning
    constexpr size_t SCAN_THRESHOLD = 1024 * 1024; // 1MB
    
    // Maximum pattern overlap for chunk boundary handling
    constexpr size_t MAX_PATTERN_OVERLAP = 256;
    
    // Maximum description length
    constexpr size_t MAX_DESCRIPTION_LENGTH = 10'000;
    
    // Maximum number of tags per pattern
    constexpr size_t MAX_TAGS_PER_PATTERN = 100;
    
    // Maximum tag length
    constexpr size_t MAX_TAG_LENGTH = 256;
    
    // Default performance frequency fallback
    constexpr int64_t DEFAULT_PERF_FREQUENCY = 1'000'000;
    
    // Maximum buffer size for feed chunk (DoS protection)
    constexpr size_t MAX_FEED_BUFFER_SIZE = 128ULL * 1024ULL * 1024ULL; // 128MB

} // anonymous namespace

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
    outMode = PatternMode::Exact; // Safe default

    // ========================================================================
    // INPUT VALIDATION
    // ========================================================================

    if (patternStr.empty()) {
        SS_LOG_ERROR(L"PatternCompiler", L"Empty pattern string");
        return std::nullopt;
    }

    if (patternStr.length() > MAX_PATTERN_STRING_LENGTH) {
        SS_LOG_ERROR(L"PatternCompiler", 
            L"Pattern string too long: %zu (max %zu)", 
            patternStr.length(), MAX_PATTERN_STRING_LENGTH);
        return std::nullopt;
    }

    // Reserve reasonable initial capacity
    try {
        pattern.reserve(patternStr.length() / 2);
        outMask.reserve(patternStr.length() / 2);
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"PatternCompiler", L"Memory allocation failed");
        return std::nullopt;
    }

    // ========================================================================
    // STEP 1: DETECT PATTERN MODE
    // ========================================================================

    // REFUSE WHAT THIS COMPILER CANNOT REPRESENT, BEFORE PARSING ANYTHING.
    //
    // Byte ranges and variable gaps used to be accepted here and compiled into a
    // DIFFERENT pattern, successfully. Measured on the real implementation:
    //
    //   '[8B-8D]'  emitted its LOWER BOUND with a 0xFF (exact) mask, so the range
    //              became "the byte 0x8B". '[00-FF]', which means any byte, became
    //              "exactly 0x00" - the narrowest possible reading of the widest
    //              possible expression.
    //   '{0-16}'   was parsed, added to a local expansion counter used only for a
    //              size check, and then DROPPED. "48 8B {0-16} C3" compiled to the
    //              three CONTIGUOUS bytes 48 8B C3.
    //
    // Both returned a valid pattern and reported success, so an author had no way to
    // learn that the stored bytes were not the bytes they wrote. Only PatternMode
    // being Regex - which nothing in the product matches - kept the wrong pattern
    // from producing wrong detections.
    //
    // Neither construct is expressible in this store's model, which is a fixed-length
    // byte sequence plus a per-position AND-mask: a range admits a SET of values that
    // no single mask describes, and a gap changes the LENGTH of a match. Supporting
    // them needs a different matcher and a format that can carry per-position sets,
    // not a wider mask. Until that exists, refusing is the only honest answer - a
    // compiler that emits a pattern meaning something other than its input is worse
    // than one that fails, because the failure is visible and the wrong pattern is not.
    if (patternStr.find('[') != std::string::npos ||
        patternStr.find(']') != std::string::npos) {
        SS_LOG_ERROR(L"PatternCompiler",
            L"Byte ranges are not supported: this store matches a fixed byte sequence "
            L"plus an AND-mask, which cannot express a set of admissible values. Use "
            L"'??' for any byte.");
        return std::nullopt;
    }

    if (patternStr.find('{') != std::string::npos ||
        patternStr.find('}') != std::string::npos) {
        SS_LOG_ERROR(L"PatternCompiler",
            L"Variable gaps are not supported: a gap changes the length of a match and "
            L"every matcher here is fixed-length. Use a fixed number of '??' wildcards.");
        return std::nullopt;
    }

    // A '?' must always be part of a '??' pair. The tokeniser below treats an
    // unrecognised token as one to skip with a warning, so a lone '?' would silently
    // shorten the pattern by one byte and still compile.
    for (size_t i = 0; i < patternStr.length(); ++i) {
        if (patternStr[i] != '?') {
            continue;
        }
        const bool pairedWithNext = (i + 1 < patternStr.length() && patternStr[i + 1] == '?');
        const bool pairedWithPrev = (i > 0 && patternStr[i - 1] == '?');
        if (!pairedWithNext && !pairedWithPrev) {
            SS_LOG_ERROR(L"PatternCompiler",
                L"A wildcard must be written as '??' (one whole byte); a single '?' "
                L"would be dropped and silently shorten the pattern");
            return std::nullopt;
        }
    }

    const bool hasWildcard = patternStr.find("??") != std::string::npos;

    outMode = hasWildcard ? PatternMode::Wildcard : PatternMode::Exact;

    SS_LOG_DEBUG(L"PatternCompiler", L"Pattern mode: %u, HasWildcard=%d",
        static_cast<uint8_t>(outMode), hasWildcard ? 1 : 0);

    // ========================================================================
    // STEP 2: TOKENIZE PATTERN
    // ========================================================================

    std::vector<std::string> tokens;

    try {
        std::string current;
        current.reserve(16); // Typical token size
        bool inBracket = false;   // Track if we're inside [...]
        bool inBrace = false;     // Track if we're inside {...}

        for (size_t i = 0; i < patternStr.length(); ++i) {
            const char c = patternStr[i];

            if (std::isspace(static_cast<unsigned char>(c))) {
                // Only split on whitespace if not inside brackets or braces
                if (!inBracket && !inBrace) {
                    if (!current.empty()) {
                        tokens.push_back(current);
                        current.clear();
                    }
                }
                else {
                    current += c; // Preserve whitespace inside brackets/braces
                }
            }
            else if (c == '{') {
                if (!current.empty()) {
                    tokens.push_back(current);
                    current.clear();
                }
                inBrace = true;
                current += c;
            }
            else if (c == '}') {
                current += c;
                if (inBrace) {
                    tokens.push_back(current);
                    current.clear();
                    inBrace = false;
                }
            }
            else if (c == '[') {
                if (!current.empty()) {
                    tokens.push_back(current);
                    current.clear();
                }
                inBracket = true;
                current += c;
            }
            else if (c == ']') {
                current += c;
                if (inBracket) {
                    tokens.push_back(current);
                    current.clear();
                    inBracket = false;
                }
            }
            else {
                current += c;
            }
        }

        if (!current.empty()) {
            tokens.push_back(current);
        }
    } catch (const std::exception&) {
        SS_LOG_ERROR(L"PatternCompiler", L"Tokenization failed: exception");
        return std::nullopt;
    }

    // ========================================================================
    // STEP 3: PARSE EACH TOKEN
    // ========================================================================

    for (size_t tokenIdx = 0; tokenIdx < tokens.size(); ++tokenIdx) {
        const std::string& token = tokens[tokenIdx];

        if (token.empty()) {
            continue;
        }

        // Wildcard: ?? (matches any byte)
        if (token == "??") {
            if (outMode == PatternMode::Exact) {
                outMode = PatternMode::Wildcard;
            }

            pattern.push_back(0x00);
            outMask.push_back(0x00);

            SS_LOG_DEBUG(L"PatternCompiler", L"Wildcard byte");
            continue;
        }

        // Hex byte: 48, 8B, FF, etc.
        if (token.length() == 2) {
            // Validate all characters are hex digits
            if (!std::isxdigit(static_cast<unsigned char>(token[0])) ||
                !std::isxdigit(static_cast<unsigned char>(token[1]))) {
                SS_LOG_WARN(L"PatternCompiler", L"Invalid hex byte (non-hex chars): %S", token.c_str());
                continue;
            }

            try {
                const int val = std::stoi(token, nullptr, 16);
                if (val < 0 || val > 255) {
                    SS_LOG_ERROR(L"PatternCompiler", L"Hex byte out of range: %S", token.c_str());
                    return std::nullopt;
                }

                pattern.push_back(static_cast<uint8_t>(val));
                outMask.push_back(0xFF);

                SS_LOG_DEBUG(L"PatternCompiler", L"Hex byte: 0x%02X", val);
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"PatternCompiler", L"Invalid hex byte '%S': %S",
                    token.c_str(), ex.what());
                return std::nullopt;
            }

            continue;
        }

        // 4-character token (some patterns use XXXX format)
        if (token.length() == 4) {
            bool allHex = true;
            for (char c : token) {
                if (!std::isxdigit(static_cast<unsigned char>(c))) {
                    allHex = false;
                    break;
                }
            }

            if (allHex) {
                try {
                    // Parse as two bytes
                    const int val1 = std::stoi(token.substr(0, 2), nullptr, 16);
                    const int val2 = std::stoi(token.substr(2, 2), nullptr, 16);

                    if (val1 >= 0 && val1 <= 255 && val2 >= 0 && val2 <= 255) {
                        pattern.push_back(static_cast<uint8_t>(val1));
                        outMask.push_back(0xFF);
                        pattern.push_back(static_cast<uint8_t>(val2));
                        outMask.push_back(0xFF);

                        SS_LOG_DEBUG(L"PatternCompiler", L"Hex bytes: 0x%02X 0x%02X", val1, val2);
                        continue;
                    }
                }
                catch (const std::exception& ex) {
                    SS_LOG_DEBUG(L"PatternCompiler",
                        L"Failed to parse compact hex token '%S': %S",
                        token.c_str(), ex.what());
                }
            }
        }

        SS_LOG_WARN(L"PatternCompiler", L"Unknown token (ignoring): %S", token.c_str());
    }

    // ========================================================================
    // STEP 4: VALIDATION & SECURITY CHECKS
    // ========================================================================

    if (pattern.empty()) {
        SS_LOG_ERROR(L"PatternCompiler", L"Pattern compiled to empty sequence");
        return std::nullopt;
    }

    if (pattern.size() < MIN_COMPILED_PATTERN_SIZE || pattern.size() > MAX_COMPILED_PATTERN_SIZE) {
        SS_LOG_ERROR(L"PatternCompiler",
            L"Pattern size out of bounds: %zu (min=%zu, max=%zu)", 
            pattern.size(), MIN_COMPILED_PATTERN_SIZE, MAX_COMPILED_PATTERN_SIZE);
        return std::nullopt;
    }


    if (outMask.size() != pattern.size()) {
        SS_LOG_ERROR(L"PatternCompiler",
            L"Mask/pattern size mismatch: %zu vs %zu", outMask.size(), pattern.size());
        return std::nullopt;
    }

    // ========================================================================
    // STEP 5: OPTIMIZATION & METRICS
    // ========================================================================

    const float entropy = ComputeEntropy(pattern);

    const size_t wildcardCount = std::count(outMask.begin(), outMask.end(), static_cast<uint8_t>(0));
    const double wildcardRatio = pattern.empty() ? 0.0 : 
        static_cast<double>(wildcardCount) / static_cast<double>(pattern.size());

    SS_LOG_INFO(L"PatternCompiler",
        L"Pattern compiled: size=%zu, mode=%u, entropy=%.2f, wildcard_ratio=%.2f%%",
        pattern.size(), static_cast<uint8_t>(outMode), entropy, wildcardRatio * 100.0);

    if (wildcardRatio > WILDCARD_RATIO_WARN_THRESHOLD) {
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

    // Refuse exactly what CompilePattern refuses, for exactly the same reasons.
    //
    // These two functions are a matched pair - the Fuzzer harness calls ValidatePattern
    // and then CompilePattern on the same input and expects them to agree - so a
    // construct accepted here and rejected there (or worse, MIS-COMPILED there) is a
    // contradiction inside one module. This block used to validate the syntax of byte
    // ranges and variable gaps in detail: balanced brackets, well-formed min-max pairs,
    // ranges in ascending order. All of it carefully checked the shape of constructs the
    // compiler then turned into a different pattern.
    if (patternStr.find('[') != std::string::npos ||
        patternStr.find(']') != std::string::npos) {
        errorMessage = "Byte ranges ('[8B-8D]') are not supported: a fixed byte sequence "
                       "plus an AND-mask cannot express a set of admissible values. "
                       "Use '??' for any byte.";
        return false;
    }

    if (patternStr.find('{') != std::string::npos ||
        patternStr.find('}') != std::string::npos) {
        errorMessage = "Variable gaps ('{0-16}') are not supported: a gap changes the "
                       "length of a match and every matcher here is fixed-length. "
                       "Use a fixed number of '??' wildcards.";
        return false;
    }

    // Character set: hex digits, whitespace, and '?' for wildcards. Nothing else.
    for (size_t i = 0; i < patternStr.length(); ++i) {
        const char c = patternStr[i];
        if (std::isxdigit(static_cast<unsigned char>(c)) != 0 ||
            std::isspace(static_cast<unsigned char>(c)) != 0 ||
            c == '?') {
            continue;
        }
        errorMessage = std::string("Invalid character '") + c +
            "' at position " + std::to_string(i);
        return false;
    }

    // A '?' must be part of a '??' pair: the tokeniser skips an unrecognised token with
    // a warning, so a lone '?' would silently shorten the pattern by one byte.
    for (size_t i = 0; i < patternStr.length(); ++i) {
        if (patternStr[i] != '?') {
            continue;
        }
        const bool pairedWithNext = (i + 1 < patternStr.length() && patternStr[i + 1] == '?');
        const bool pairedWithPrev = (i > 0 && patternStr[i - 1] == '?');
        if (!pairedWithNext && !pairedWithPrev) {
            errorMessage = "A wildcard must be written as '??' (one whole byte) at "
                           "position " + std::to_string(i);
            return false;
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
    // Initialize performance frequency with safe fallback
    m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY;
    if (!QueryPerformanceFrequency(&m_perfFrequency) || m_perfFrequency.QuadPart <= 0) {
        SS_LOG_WARN(L"PatternStore", L"QueryPerformanceFrequency failed, using fallback");
        m_perfFrequency.QuadPart = DEFAULT_PERF_FREQUENCY;
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

    // Prevent double initialization
    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_DEBUG(L"PatternStore", L"Already initialized");
        return StoreError{SignatureStoreError::Success};
    }

    // Validate path is not empty
    if (databasePath.empty()) {
        SS_LOG_ERROR(L"PatternStore", L"Initialize: Empty database path");
        return StoreError{SignatureStoreError::FileNotFound, 0, "Empty database path"};
    }

    m_databasePath = databasePath;
    m_readOnly.store(readOnly, std::memory_order_release);

    // Open memory mapping
    StoreError err = OpenMemoryMapping(databasePath, readOnly);
    if (!err.IsSuccess()) {
        SS_LOG_ERROR(L"PatternStore", L"Initialize: Failed to open memory mapping");
        return err;
    }

    // Initialize pattern index
    try {
        m_patternIndex = std::make_unique<PatternIndex>();
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"PatternStore", L"Initialize: Failed to allocate PatternIndex");
        CloseMemoryMapping();
        return StoreError{SignatureStoreError::OutOfMemory, 0, "Failed to allocate PatternIndex"};
    }

    // Read and validate header
    const auto* header = m_mappedView.GetAt<SignatureDatabaseHeader>(0);
    if (header != nullptr) {
        // Validate header before using
        if (header->magic != SIGNATURE_DB_MAGIC) {
            SS_LOG_ERROR(L"PatternStore", L"Initialize: Invalid database magic");
            CloseMemoryMapping();
            return StoreError{SignatureStoreError::InvalidFormat, 0, "Invalid database magic"};
        }

        // Check pattern index bounds
        if (header->patternIndexOffset > 0 && header->patternIndexSize > 0) {
            // Validate offset doesn't exceed file size
            if (header->patternIndexOffset >= m_mappedView.fileSize ||
                header->patternIndexOffset + header->patternIndexSize > m_mappedView.fileSize) {
                SS_LOG_ERROR(L"PatternStore", 
                    L"Initialize: Pattern index bounds exceed file size");
                CloseMemoryMapping();
                return StoreError{SignatureStoreError::InvalidFormat, 0, "Invalid pattern index bounds"};
            }

            err = m_patternIndex->Initialize(
                m_mappedView,
                header->patternIndexOffset,
                header->patternIndexSize
            );
            if (!err.IsSuccess()) {
                SS_LOG_ERROR(L"PatternStore", L"Initialize: Failed to initialize pattern index");
                CloseMemoryMapping();
                return err;
            }
        }
    }

    // Load the persisted patterns BEFORE building the automaton. BuildAutomaton
    // compiles from m_patternCache, so without this it compiled an empty set and
    // the store reported itself ready while matching nothing.
    //
    // A load failure is not fatal to the store: the mapping is valid, the other
    // components work, and refusing to open would take hash and YARA detection
    // down with it. But it is an ERROR, because pattern detection is off.
    err = LoadPatternsFromDatabase();
    if (!err.IsSuccess()) {
        SS_LOG_ERROR(L"PatternStore",
            L"Initialize: the patterns in this database could not be loaded (%S); "
            L"pattern matching will report no matches until this is resolved",
            err.message.c_str());
    }

    // Build Aho-Corasick automaton
    err = BuildAutomaton();
    if (!err.IsSuccess()) {
        // An empty pattern set no longer reaches here - BuildAutomaton reports that
        // as a success with an explanatory line - so this genuinely means a rebuild
        // failed while patterns were present, and pattern matching is running with
        // whatever automaton preceded it.
        SS_LOG_WARN(L"PatternStore",
            L"Initialize: the pattern automaton could not be built even though "
            L"patterns are present; pattern matching may be incomplete until a "
            L"rebuild succeeds");
        // Don't fail - the store still serves its other functions and the automaton
        // can be rebuilt later.
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

    // Ensure minimum size for header
    if (initialSizeBytes < sizeof(SignatureDatabaseHeader)) {
        initialSizeBytes = sizeof(SignatureDatabaseHeader) + (1024 * 1024); // At least 1MB + header
    }

    // Create database file
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
        SS_LOG_ERROR(L"PatternStore", L"CreateNew: Cannot create file, error=%lu", err);
        return StoreError{SignatureStoreError::FileNotFound, err, "Cannot create file"};
    }

    // Set file size
    LARGE_INTEGER size{};
    size.QuadPart = static_cast<LONGLONG>(initialSizeBytes);
    if (!SetFilePointerEx(hFile, size, nullptr, FILE_BEGIN) || !SetEndOfFile(hFile)) {
        DWORD err = GetLastError();
        CloseHandle(hFile);
        SS_LOG_ERROR(L"PatternStore", L"CreateNew: Cannot set size, error=%lu", err);
        return StoreError{SignatureStoreError::Unknown, err, "Cannot set file size"};
    }

    // Create file mapping for writing header
    HANDLE hMapping = CreateFileMappingW(
        hFile,
        nullptr,
        PAGE_READWRITE,
        0,
        0,
        nullptr
    );

    if (hMapping == nullptr) {
        DWORD err = GetLastError();
        CloseHandle(hFile);
        SS_LOG_ERROR(L"PatternStore", L"CreateNew: Cannot create mapping, error=%lu", err);
        return StoreError{SignatureStoreError::MappingFailed, err, "Cannot create file mapping"};
    }

    // Map view for writing
    void* pView = MapViewOfFile(
        hMapping,
        FILE_MAP_WRITE,
        0,
        0,
        0
    );

    if (pView == nullptr) {
        DWORD err = GetLastError();
        CloseHandle(hMapping);
        CloseHandle(hFile);
        SS_LOG_ERROR(L"PatternStore", L"CreateNew: Cannot map view, error=%lu", err);
        return StoreError{SignatureStoreError::MappingFailed, err, "Cannot map view of file"};
    }

    // Initialize header with valid magic number and structure
    auto* header = reinterpret_cast<SignatureDatabaseHeader*>(pView);
    std::memset(header, 0, sizeof(SignatureDatabaseHeader));

    header->magic = SIGNATURE_DB_MAGIC;
    header->versionMajor = SIGNATURE_DB_VERSION_MAJOR;
    header->versionMinor = SIGNATURE_DB_VERSION_MINOR;

    // Set creation timestamp
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    header->creationTime = static_cast<uint64_t>(timestamp);
    header->lastUpdateTime = static_cast<uint64_t>(timestamp);
    header->buildNumber = 1;

    // Generate UUID for database
    GUID guid;
    if (CoCreateGuid(&guid) == S_OK) {
        std::memcpy(header->databaseUuid.data(), &guid, sizeof(GUID));
    }

    // Initialize section offsets (pattern index starts after header)
    header->patternIndexOffset = Format::AlignToPage(sizeof(SignatureDatabaseHeader));
    header->patternIndexSize = 0;  // Will be updated when patterns are added
    header->hashIndexOffset = 0;
    header->hashIndexSize = 0;
    header->yaraRulesOffset = 0;
    header->yaraRulesSize = 0;
    header->metadataOffset = 0;
    header->metadataSize = 0;
    header->stringPoolOffset = 0;
    header->stringPoolSize = 0;

    // Initialize statistics
    header->totalPatterns = 0;
    header->totalHashes = 0;
    header->totalYaraRules = 0;
    header->totalDetections = 0;

    // Performance hints
    header->recommendedCacheSize = Format::CalculateOptimalCacheSize(initialSizeBytes);
    header->compressionFlags = 0;

    // Flush to disk
    if (!FlushViewOfFile(pView, sizeof(SignatureDatabaseHeader))) {
        DWORD err = GetLastError();
        SS_LOG_WARN(L"PatternStore", L"CreateNew: FlushViewOfFile failed, error=%lu", err);
    }

    // Cleanup mapping resources
    UnmapViewOfFile(pView);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    SS_LOG_INFO(L"PatternStore", L"CreateNew: Database created with magic=0x%08X", SIGNATURE_DB_MAGIC);

    // Now initialize from the created file
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
    std::vector<DetectionResult> results;

    // Early validation
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"PatternStore", L"Scan: Not initialized");
        return results;
    }

    if (buffer.empty()) {
        SS_LOG_DEBUG(L"PatternStore", L"Scan: Empty buffer");
        return results;
    }

    // Update statistics (atomic, safe)
    m_totalScans.fetch_add(1, std::memory_order_relaxed);
    m_totalBytesScanned.fetch_add(buffer.size(), std::memory_order_relaxed);

    // Get start time and compute scan deadline for timeout enforcement
    LARGE_INTEGER startTime{};
    if (!QueryPerformanceCounter(&startTime)) {
        startTime.QuadPart = 0;
    }

    LARGE_INTEGER deadline{};
    if (options.timeoutMilliseconds > 0 && startTime.QuadPart != 0) {
        LARGE_INTEGER freq{};
        if (QueryPerformanceFrequency(&freq) && freq.QuadPart > 0) {
            deadline.QuadPart = startTime.QuadPart +
                (static_cast<int64_t>(options.timeoutMilliseconds) * freq.QuadPart / 1000LL);
        } else {
            deadline.QuadPart = LLONG_MAX;
        }
    } else {
        deadline.QuadPart = LLONG_MAX; // no timeout
    }

    // Reserve reasonable capacity for results
    try {
        const size_t reserveCapacity = (std::min)(
            static_cast<size_t>(options.maxResults > 0 ? options.maxResults : 1000u),
            static_cast<size_t>(256)
        );
        results.reserve(reserveCapacity);
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"PatternStore", L"Scan: Failed to reserve results vector");
        return results;
    }

    // ========================================================================
    // DISPATCH: cheapest matcher that can answer, then the ones it cannot
    // ========================================================================
    //
    // The order here used to be inverted, and the cost of that fell hardest on
    // exactly the common case. ScanWithSIMD ran FIRST and unconditionally, doing a
    // full AVX2 pass over the buffer for EVERY pattern - O(patterns x bytes) - and
    // the O(bytes) automaton ran only `if (results.empty())`. So a clean file, which
    // is almost every file, paid the entire per-pattern sweep AND then the automaton
    // sweep, while a file that matched early paid the sweep and skipped the cheap
    // pass. With one shipped pattern that is invisible; the pattern section is meant
    // to hold thousands, and at that size the default was the expensive one.
    //
    // Aho-Corasick finds every exact pattern in ONE pass whose cost is independent of
    // how many patterns are loaded, so it is strictly the better default and there is
    // no coverage argument for the old order: both matchers consider precisely the
    // PatternMode::Exact set.
    //
    // The three passes cover disjoint pattern sets and are not alternatives:
    //   automaton  -> every exact pattern, O(bytes)
    //   SIMD       -> the same exact patterns, ONLY when no automaton is available
    //                 (compilation failed and a previous automaton was not retained)
    //   masked     -> wildcard/byte-mask patterns, which the automaton cannot express
    bool automatonServedExactPatterns = false;

    {
        auto acResults = ScanWithAutomaton(buffer, options, deadline,
            automatonServedExactPatterns);
        try {
            results.insert(results.end(),
                std::make_move_iterator(acResults.begin()),
                std::make_move_iterator(acResults.end()));
        } catch (const std::bad_alloc&) {
            SS_LOG_ERROR(L"PatternStore", L"Scan: out of memory collecting automaton matches");
        }
    }

    // Fallback for the exact patterns, NOT a supplement: reached only when the
    // automaton could not run. Skipping it there would silently drop every exact
    // pattern for as long as the automaton stays unavailable.
    if (!automatonServedExactPatterns) {
        if (m_simdEnabled.load(std::memory_order_acquire) && SIMDMatcher::IsAVX2Available()) {
            auto simdResults = ScanWithSIMD(buffer, options, deadline);
            try {
                results.insert(results.end(),
                    std::make_move_iterator(simdResults.begin()),
                    std::make_move_iterator(simdResults.end()));
            } catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"PatternStore", L"Scan: out of memory collecting SIMD matches");
            }
        } else {
            // Reported rather than passed over: with no automaton and no SIMD, the
            // exact patterns in this store are not being scanned at all, and that
            // must not look like a clean result.
            SS_LOG_ERROR(L"PatternStore",
                L"Scan: no automaton is available and the SIMD fallback is unavailable "
                L"(simdEnabled=%d avx2=%d) - exact patterns were NOT scanned for this buffer",
                m_simdEnabled.load(std::memory_order_acquire) ? 1 : 0,
                SIMDMatcher::IsAVX2Available() ? 1 : 0);
        }
    }

    // Masked patterns, always, in addition to the above. Returns immediately when the
    // store holds none, which is the case for all shipped content today.
    {
        auto maskedResults = ScanWithMaskedPatterns(buffer, options, deadline);
        try {
            results.insert(results.end(),
                std::make_move_iterator(maskedResults.begin()),
                std::make_move_iterator(maskedResults.end()));
        } catch (const std::bad_alloc&) {
            SS_LOG_ERROR(L"PatternStore", L"Scan: out of memory collecting masked matches");
        }
    }

    // Calculate scan time safely
    LARGE_INTEGER endTime{};
    uint64_t scanTimeUs = 0;
    
    if (QueryPerformanceCounter(&endTime) && startTime.QuadPart > 0) {
        const int64_t perfFreq = m_perfFrequency.QuadPart;
        if (perfFreq > 0) {
            const int64_t elapsed = endTime.QuadPart - startTime.QuadPart;
            if (elapsed > 0) {
                // Check for overflow before multiplication
                if (elapsed <= (std::numeric_limits<int64_t>::max)() / 1'000'000LL) {
                    scanTimeUs = static_cast<uint64_t>((elapsed * 1'000'000LL) / perfFreq);
                } else {
                    // Divide first to prevent overflow
                    scanTimeUs = static_cast<uint64_t>((elapsed / perfFreq) * 1'000'000LL);
                }
            }
        }
    }

    // Update result metadata and statistics.
    //
    // The hit counters are deliberately NOT touched here. They are updated inside
    // ScanWithAutomaton and ScanWithSIMD, under the shared lock those functions
    // hold and indexed by the cache position. Doing it here was wrong twice over:
    // the lock is already released by this point, so it raced with the resize in
    // BuildAutomaton; and it indexed m_hitCounters with result.signatureId, which
    // only works while that value happens to be an array position.
    for (auto& result : results) {
        // Safe conversion to nanoseconds
        if (scanTimeUs <= (std::numeric_limits<uint64_t>::max)() / 1'000ULL) {
            result.matchTimeNanoseconds = scanTimeUs * 1'000ULL;
        } else {
            result.matchTimeNanoseconds = (std::numeric_limits<uint64_t>::max)();
        }

        m_totalMatches.fetch_add(1, std::memory_order_relaxed);
    }

    SS_LOG_DEBUG(L"PatternStore", L"Scan: Found %zu matches in %llu µs", 
        results.size(), scanTimeUs);

    return results;
}

std::vector<DetectionResult> PatternStore::ScanFile(
    const std::wstring& filePath,
    const QueryOptions& options
) const noexcept {
    SS_LOG_DEBUG(L"PatternStore", L"ScanFile: %s", filePath.c_str());

    std::vector<DetectionResult> results;

    // Validate initialization
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"PatternStore", L"ScanFile: Not initialized");
        return results;
    }

    // Validate path
    if (filePath.empty()) {
        SS_LOG_ERROR(L"PatternStore", L"ScanFile: Empty file path");
        return results;
    }

    // Memory-map file for scanning
    StoreError err{};
    MemoryMappedView fileView{};
    
    if (!MemoryMapping::OpenView(filePath, true, fileView, err)) {
        SS_LOG_ERROR(L"PatternStore", L"ScanFile: Failed to map file: %S", err.message.c_str());
        return results;
    }

    // Validate mapped view
    if (!fileView.IsValid() || fileView.baseAddress == nullptr) {
        SS_LOG_ERROR(L"PatternStore", L"ScanFile: Invalid memory map");
        MemoryMapping::CloseView(fileView);
        return results;
    }

    // Validate file size is within reasonable limits
    if (fileView.fileSize == 0) {
        SS_LOG_DEBUG(L"PatternStore", L"ScanFile: Empty file");
        MemoryMapping::CloseView(fileView);
        return results;
    }

    // Check for size overflow when casting to size_t
    if (fileView.fileSize > static_cast<uint64_t>((std::numeric_limits<size_t>::max)())) {
        SS_LOG_ERROR(L"PatternStore", 
            L"ScanFile: File too large for memory-mapped scan: %llu bytes", fileView.fileSize);
        MemoryMapping::CloseView(fileView);
        return results;
    }

    // Create buffer span safely
    std::span<const uint8_t> buffer(
        static_cast<const uint8_t*>(fileView.baseAddress),
        static_cast<size_t>(fileView.fileSize)
    );

    // Scan the mapped file
    results = Scan(buffer, options);

    // Close memory mapping
    MemoryMapping::CloseView(fileView);

    SS_LOG_DEBUG(L"PatternStore", L"ScanFile: Found %zu matches in %llu bytes", 
        results.size(), fileView.fileSize);

    return results;
}

PatternStore::ScanContext PatternStore::CreateScanContext(
    const QueryOptions& options
) const noexcept {
    ScanContext ctx;
    ctx.m_store = this;
    ctx.m_options = options;
    ctx.m_buffer.clear();
    ctx.m_totalBytesProcessed = 0;
    return ctx;
}

void PatternStore::ScanContext::Reset() noexcept {
    m_buffer.clear();
    m_buffer.shrink_to_fit(); // Release memory
    m_totalBytesProcessed = 0;
}

std::vector<DetectionResult> PatternStore::ScanContext::FeedChunk(
    std::span<const uint8_t> chunk
) noexcept {
    std::vector<DetectionResult> results;

    // Validate store pointer
    if (!m_store) {
        SS_LOG_ERROR(L"PatternStore::ScanContext", L"FeedChunk: Store pointer is null");
        return results;
    }

    // Validate chunk
    if (chunk.empty()) {
        return results;
    }

    // Check for buffer overflow protection
    if (m_buffer.size() > MAX_FEED_BUFFER_SIZE - chunk.size()) {
        SS_LOG_WARN(L"PatternStore::ScanContext", 
            L"FeedChunk: Buffer would exceed maximum size, scanning now");
        
        // Force scan of current buffer
        if (!m_buffer.empty()) {
            results = m_store->Scan(m_buffer, m_options);
            m_buffer.clear();
        }
    }

    // Append chunk to buffer with exception handling
    try {
        m_buffer.insert(m_buffer.end(), chunk.begin(), chunk.end());
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"PatternStore::ScanContext", L"FeedChunk: Memory allocation failed");
        return results;
    }

    // Update processed bytes counter with overflow protection
    if (m_totalBytesProcessed <= (std::numeric_limits<size_t>::max)() - chunk.size()) {
        m_totalBytesProcessed += chunk.size();
    } else {
        m_totalBytesProcessed = (std::numeric_limits<size_t>::max)();
    }

    // Scan when buffer reaches threshold
    if (m_buffer.size() >= SCAN_THRESHOLD) {
        results = m_store->Scan(m_buffer, m_options);
        
        // Keep last MAX_PATTERN_OVERLAP bytes for pattern boundary handling
        if (m_buffer.size() > MAX_PATTERN_OVERLAP) {
            try {
                std::vector<uint8_t> overlap(
                    m_buffer.end() - static_cast<ptrdiff_t>(MAX_PATTERN_OVERLAP),
                    m_buffer.end()
                );
                m_buffer = std::move(overlap);
            } catch (const std::bad_alloc&) {
                SS_LOG_WARN(L"PatternStore::ScanContext", 
                    L"FeedChunk: Failed to preserve overlap, clearing buffer");
                m_buffer.clear();
            }
        } else {
            m_buffer.clear();
        }
    }

    return results;
}

std::vector<DetectionResult> PatternStore::ScanContext::Finalize() noexcept {
    std::vector<DetectionResult> results;

    if (!m_store) {
        SS_LOG_ERROR(L"PatternStore::ScanContext", L"Finalize: Store pointer is null");
        return results;
    }

    if (m_buffer.empty()) {
        return results;
    }

    results = m_store->Scan(m_buffer, m_options);
    m_buffer.clear();
    m_buffer.shrink_to_fit(); // Release memory
    
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
    // Validate inputs
    if (pattern.empty()) {
        SS_LOG_ERROR(L"PatternStore", L"AddCompiledPattern: Empty pattern");
        return StoreError{SignatureStoreError::InvalidSignature, 0, "Empty pattern"};
    }

    if (pattern.size() > MAX_COMPILED_PATTERN_SIZE) {
        SS_LOG_ERROR(L"PatternStore", L"AddCompiledPattern: Pattern too large (%zu bytes)", pattern.size());
        return StoreError{SignatureStoreError::TooLarge, 0, "Pattern too large"};
    }

    if (signatureName.empty()) {
        SS_LOG_WARN(L"PatternStore", L"AddCompiledPattern: Empty signature name");
    }

    // Validate mask size if provided
    if (!mask.empty() && mask.size() != pattern.size()) {
        SS_LOG_ERROR(L"PatternStore", L"AddCompiledPattern: Mask size mismatch");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Mask size mismatch"};
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    // Check for duplicate signature names (optional, for uniqueness)
    for (const auto& existing : m_patternCache) {
        if (existing.name == signatureName && !signatureName.empty()) {
            SS_LOG_WARN(L"PatternStore", 
                L"AddCompiledPattern: Duplicate name '%S', assigning new ID", 
                signatureName.c_str());
            break;
        }
    }

    // Create pattern metadata with exception handling
    try {
        PatternMetadata metadata{};
        metadata.signatureId = m_patternCache.size();
        metadata.name = signatureName;
        metadata.threatLevel = threatLevel;
        metadata.mode = mode;
        metadata.pattern.assign(pattern.begin(), pattern.end());
        
        if (!mask.empty()) {
            metadata.mask.assign(mask.begin(), mask.end());
        } else {
            // Default mask: all 0xFF (exact match)
            metadata.mask.assign(pattern.size(), 0xFF);
        }
        
        metadata.entropy = PatternCompiler::ComputeEntropy(pattern);
        metadata.hitCount = 0;
        metadata.created = std::chrono::system_clock::now();
        metadata.lastModified = metadata.created;
        metadata.modificationCount = 0;
        metadata.isDeprecated = false;

        m_patternCache.push_back(std::move(metadata));

        SS_LOG_DEBUG(L"PatternStore", L"AddCompiledPattern: Added '%S' (mode=%u, entropy=%.2f, id=%zu)",
            signatureName.c_str(), static_cast<uint8_t>(mode), 
            m_patternCache.back().entropy, m_patternCache.back().signatureId);

    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"PatternStore", L"AddCompiledPattern: Memory allocation failed");
        return StoreError{SignatureStoreError::OutOfMemory, 0, "Memory allocation failed"};
    } catch (const std::exception&) {
        SS_LOG_ERROR(L"PatternStore", L"AddCompiledPattern: Exception occurred");
        return StoreError{SignatureStoreError::Unknown, 0, "Exception during pattern addition"};
    }

    return StoreError{SignatureStoreError::Success};
}


StoreError PatternStore::AddPatternBatch(
    std::span<const std::string> patternStrs,
    std::span<const std::string> signatureNames,
    std::span<const ThreatLevel> threatLevels
) noexcept {
    SS_LOG_INFO(L"PatternStore", L"AddPatternBatch: Adding %zu patterns", patternStrs.size());

    if (m_readOnly.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"PatternStore", L"AddPatternBatch: Read-only mode");
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
    }

    // Validate input sizes
    if (patternStrs.size() != signatureNames.size() || patternStrs.size() != threatLevels.size()) {
        SS_LOG_ERROR(L"PatternStore", L"AddPatternBatch: Array size mismatch (%zu, %zu, %zu)",
            patternStrs.size(), signatureNames.size(), threatLevels.size());
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Array sizes must match" };
    }

    // Empty batch is not an error
    if (patternStrs.empty()) {
        SS_LOG_DEBUG(L"PatternStore", L"AddPatternBatch: Empty batch");
        return StoreError{ SignatureStoreError::Success };
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    size_t successCount = 0;
    size_t failCount = 0;

    // Pre-reserve capacity for better performance
    try {
        m_patternCache.reserve(m_patternCache.size() + patternStrs.size());
    } catch (const std::bad_alloc&) {
        SS_LOG_WARN(L"PatternStore", L"AddPatternBatch: Failed to reserve capacity");
        // Continue anyway - push_back will handle allocation
    }

    for (size_t i = 0; i < patternStrs.size(); ++i) {
        // Compile pattern
        PatternMode mode = PatternMode::Exact;
        std::vector<uint8_t> mask;
        
        auto pattern = PatternCompiler::CompilePattern(patternStrs[i], mode, mask);

        if (!pattern.has_value()) {
            SS_LOG_WARN(L"PatternStore", L"AddPatternBatch: Failed to compile pattern %zu", i);
            failCount++;
            continue;
        }

        // Validate compiled pattern
        if (pattern->empty() || pattern->size() > MAX_COMPILED_PATTERN_SIZE) {
            SS_LOG_WARN(L"PatternStore", 
                L"AddPatternBatch: Invalid compiled pattern size at index %zu", i);
            failCount++;
            continue;
        }

        // Create pattern metadata
        try {
            PatternMetadata metadata{};
            metadata.signatureId = m_patternCache.size();
            metadata.name = signatureNames[i];
            metadata.threatLevel = threatLevels[i];
            metadata.mode = mode;
            metadata.pattern = std::move(*pattern);
            metadata.mask = std::move(mask);
            metadata.entropy = PatternCompiler::ComputeEntropy(metadata.pattern);
            metadata.hitCount = 0;
            metadata.created = std::chrono::system_clock::now();
            metadata.lastModified = metadata.created;

            m_patternCache.push_back(std::move(metadata));
            successCount++;
        } catch (const std::bad_alloc&) {
            SS_LOG_ERROR(L"PatternStore", L"AddPatternBatch: Memory allocation failed at index %zu", i);
            failCount++;
            // Don't break - try to continue with remaining patterns
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(L"PatternStore", L"AddPatternBatch: Exception at index %zu: %S",
                i, ex.what());
            failCount++;
        }
    }

    SS_LOG_INFO(L"PatternStore", L"AddPatternBatch: Success=%zu, Failed=%zu", successCount, failCount);

    // Rebuild automaton with new patterns
    if (successCount > 0) {
        StoreError rebuildErr = BuildAutomaton();
        if (!rebuildErr.IsSuccess()) {
            SS_LOG_WARN(L"PatternStore", L"AddPatternBatch: Automaton rebuild failed (non-fatal)");
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

    // RENUMBER. PatternMetadata::signatureId is POSITIONAL - the header states that it
    // always equals the entry's index - and erase() shifts every element after the one
    // removed, so without this the cache [A:0, B:1, C:2] minus B leaves index 1 holding
    // signatureId 2 and the invariant is broken for the rest of the store's life.
    //
    // Rebuild, Compact and OptimizeByHitRate all renumber after reordering; this was the
    // one mutator that did not. It did not break matching, because task 59 keyed the
    // automaton by cache index rather than by this field - but it broke the id reported
    // in every DetectionResult produced afterwards, and it left a documented invariant
    // false for any future consumer that trusts it.
    for (size_t i = 0; i < m_patternCache.size(); ++i) {
        m_patternCache[i].signatureId = i;
    }

    // Rebuild unconditionally, including when the cache is now empty.
    //
    // The empty case used to call m_automaton->Clear() directly instead, which left
    // m_hitCounters and (once masked matchers existed) m_maskedMatchers holding entries
    // for patterns the store no longer has - so a masked pattern could keep matching
    // after being removed. BuildAutomaton already handles an empty cache correctly: it
    // releases the automaton, clears the counters and rebuilds the masked matchers from
    // the now-empty cache, reporting the state plainly rather than as a failure.
    const StoreError rebuildErr = BuildAutomaton();
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

    // Cap file size to prevent abuse (64 MB max for rule files)
    constexpr size_t MAX_YARA_FILE_SIZE = 64 * 1024 * 1024;
    if (fileContent.size() > MAX_YARA_FILE_SIZE) {
        SS_LOG_ERROR(L"PatternStore",
            L"ImportFromYaraFile: File exceeds 64 MB limit: %zu bytes", fileContent.size());
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "YARA file exceeds 64 MB limit" };
    }

    std::string yaraContent(reinterpret_cast<const char*>(fileContent.data()), fileContent.size());

    // Collected patterns from all rules
    std::vector<std::string> patterns;
    std::vector<std::string> names;
    std::vector<ThreatLevel> levels;

    // ---- Full YARA Rule Parser ----
    // Parses: rule RuleName [: tag1 tag2] { meta: ... strings: ... condition: ... }
    // Extracts hex patterns ($var = { hex }) and string patterns ($var = "text")
    // Reads meta: threat_level/severity for severity classification

    size_t pos = 0;
    size_t ruleCount = 0;
    size_t importedCount = 0;
    constexpr size_t MAX_RULES_PER_FILE = 100000;

    // Helper: skip whitespace and comments
    auto skipWS = [&]() {
        while (pos < yaraContent.size()) {
            if (std::isspace(static_cast<unsigned char>(yaraContent[pos]))) {
                ++pos;
                continue;
            }
            // Single-line comment: //
            if (pos + 1 < yaraContent.size() &&
                yaraContent[pos] == '/' && yaraContent[pos + 1] == '/') {
                pos = yaraContent.find('\n', pos);
                if (pos == std::string::npos) pos = yaraContent.size();
                else ++pos;
                continue;
            }
            // Multi-line comment: /* ... */
            if (pos + 1 < yaraContent.size() &&
                yaraContent[pos] == '/' && yaraContent[pos + 1] == '*') {
                size_t endComment = yaraContent.find("*/", pos + 2);
                pos = (endComment == std::string::npos) ? yaraContent.size() : endComment + 2;
                continue;
            }
            break;
        }
    };

    // Helper: read identifier (alphanumeric + underscore)
    auto readIdent = [&]() -> std::string {
        size_t start = pos;
        while (pos < yaraContent.size() &&
               (std::isalnum(static_cast<unsigned char>(yaraContent[pos])) ||
                yaraContent[pos] == '_')) {
            ++pos;
        }
        return yaraContent.substr(start, pos - start);
    };

    // Helper: find matching closing brace, respecting nesting/strings/comments
    auto findClosingBrace = [&](size_t startPos) -> size_t {
        int depth = 0;
        size_t i = startPos;
        bool inStr = false;
        bool inLineComment = false;
        bool inBlockComment = false;

        while (i < yaraContent.size()) {
            char c = yaraContent[i];

            if (inLineComment) {
                if (c == '\n') inLineComment = false;
                ++i; continue;
            }
            if (inBlockComment) {
                if (c == '*' && i + 1 < yaraContent.size() && yaraContent[i + 1] == '/') {
                    inBlockComment = false; i += 2; continue;
                }
                ++i; continue;
            }
            if (c == '/' && i + 1 < yaraContent.size()) {
                if (yaraContent[i + 1] == '/') { inLineComment = true; i += 2; continue; }
                if (yaraContent[i + 1] == '*') { inBlockComment = true; i += 2; continue; }
            }
            if (c == '"' && !inStr) { inStr = true; ++i; continue; }
            if (inStr) {
                if (c == '\\' && i + 1 < yaraContent.size()) { i += 2; continue; }
                if (c == '"') inStr = false;
                ++i; continue;
            }
            if (c == '{') ++depth;
            if (c == '}') { --depth; if (depth == 0) return i; }
            ++i;
        }
        return std::string::npos;
    };

    // Helper: extract hex pattern from raw content between { and }
    auto extractHex = [](const std::string& raw) -> std::string {
        std::string result;
        result.reserve(raw.size());
        for (char c : raw) {
            if (std::isxdigit(static_cast<unsigned char>(c)) ||
                c == '?' || c == '[' || c == ']' || c == '-' ||
                c == '(' || c == ')' || c == '|') {
                result += c;
            } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                if (!result.empty() && result.back() != ' ') result += ' ';
            }
        }
        while (!result.empty() && result.back() == ' ') result.pop_back();
        return result;
    };

    // Helper: convert quoted string literal to hex pattern
    auto strToHex = [](const std::string& str) -> std::string {
        std::ostringstream hex;
        hex << std::uppercase << std::hex << std::setfill('0');
        for (size_t i = 0; i < str.size(); ++i) {
            if (str[i] == '\\' && i + 1 < str.size()) {
                ++i;
                switch (str[i]) {
                    case 'n': hex << "0A "; break;
                    case 'r': hex << "0D "; break;
                    case 't': hex << "09 "; break;
                    case '\\': hex << "5C "; break;
                    case '"': hex << "22 "; break;
                    case '0': hex << "00 "; break;
                    case 'x':
                        if (i + 2 < str.size()) {
                            hex << str[i + 1] << str[i + 2] << ' ';
                            i += 2;
                        }
                        break;
                    default:
                        hex << std::setw(2) << static_cast<int>(
                            static_cast<unsigned char>(str[i])) << ' ';
                        break;
                }
            } else {
                hex << std::setw(2) << static_cast<int>(
                    static_cast<unsigned char>(str[i])) << ' ';
            }
        }
        std::string result = hex.str();
        while (!result.empty() && result.back() == ' ') result.pop_back();
        return result;
    };

    while (pos < yaraContent.size() && ruleCount < MAX_RULES_PER_FILE) {
        skipWS();
        if (pos >= yaraContent.size()) break;

        // Skip 'import' and 'include' directives
        if (yaraContent.compare(pos, 7, "import ") == 0 ||
            yaraContent.compare(pos, 8, "include ") == 0) {
            pos = yaraContent.find('\n', pos);
            if (pos == std::string::npos) pos = yaraContent.size();
            else ++pos;
            continue;
        }

        // Handle 'private' and 'global' modifiers before 'rule'
        if (yaraContent.compare(pos, 8, "private ") == 0) {
            pos += 8; skipWS();
        }
        if (yaraContent.compare(pos, 7, "global ") == 0) {
            pos += 7; skipWS();
        }

        if (yaraContent.compare(pos, 5, "rule ") != 0) {
            pos = yaraContent.find('\n', pos);
            if (pos == std::string::npos) pos = yaraContent.size();
            else ++pos;
            continue;
        }
        pos += 5;
        skipWS();

        std::string ruleName = readIdent();
        if (ruleName.empty()) {
            SS_LOG_WARN(L"PatternStore",
                L"ImportFromYaraFile: Empty rule name at offset %zu", pos);
            pos = yaraContent.find('\n', pos);
            if (pos == std::string::npos) pos = yaraContent.size();
            else ++pos;
            continue;
        }
        if (ruleName.size() > 256) ruleName = ruleName.substr(0, 256);

        skipWS();

        // Optional tags: rule Name : tag1 tag2 {
        if (pos < yaraContent.size() && yaraContent[pos] == ':') {
            ++pos; skipWS();
            while (pos < yaraContent.size() && yaraContent[pos] != '{') {
                readIdent(); // consume tag, not stored
                skipWS();
            }
        }

        skipWS();

        // Expect opening brace
        if (pos >= yaraContent.size() || yaraContent[pos] != '{') {
            SS_LOG_WARN(L"PatternStore",
                L"ImportFromYaraFile: Expected '{' for rule '%hs' at offset %zu",
                ruleName.c_str(), pos);
            continue;
        }

        size_t closingBrace = findClosingBrace(pos);
        if (closingBrace == std::string::npos) {
            SS_LOG_WARN(L"PatternStore",
                L"ImportFromYaraFile: Unmatched brace for rule '%hs'", ruleName.c_str());
            break;
        }

        std::string ruleBody = yaraContent.substr(pos + 1, closingBrace - pos - 1);
        pos = closingBrace + 1;
        ruleCount++;

        // --- Parse meta: section for threat level ---
        ThreatLevel ruleThreatLevel = ThreatLevel::Medium;

        size_t metaPos = ruleBody.find("meta:");
        size_t stringsPos = ruleBody.find("strings:");
        size_t conditionPos = ruleBody.find("condition:");

        if (metaPos != std::string::npos) {
            size_t metaEnd = std::string::npos;
            if (stringsPos != std::string::npos && stringsPos > metaPos)
                metaEnd = stringsPos;
            else if (conditionPos != std::string::npos && conditionPos > metaPos)
                metaEnd = conditionPos;

            std::string metaSection = (metaEnd != std::string::npos)
                ? ruleBody.substr(metaPos + 5, metaEnd - metaPos - 5)
                : ruleBody.substr(metaPos + 5);

            // Extract a meta key's value
            auto getMetaVal = [&](const std::string& key) -> std::string {
                size_t kpos = metaSection.find(key);
                if (kpos == std::string::npos) return {};
                kpos += key.size();
                while (kpos < metaSection.size() && metaSection[kpos] != '=') ++kpos;
                if (kpos >= metaSection.size()) return {};
                ++kpos;
                while (kpos < metaSection.size() &&
                       std::isspace(static_cast<unsigned char>(metaSection[kpos]))) ++kpos;

                if (kpos < metaSection.size() && metaSection[kpos] == '"') {
                    ++kpos;
                    size_t eq = metaSection.find('"', kpos);
                    if (eq != std::string::npos)
                        return metaSection.substr(kpos, eq - kpos);
                }
                size_t vs = kpos;
                while (kpos < metaSection.size() &&
                       !std::isspace(static_cast<unsigned char>(metaSection[kpos])) &&
                       metaSection[kpos] != '\n') ++kpos;
                return metaSection.substr(vs, kpos - vs);
            };

            std::string sev = getMetaVal("threat_level");
            if (sev.empty()) sev = getMetaVal("severity");
            if (sev.empty()) sev = getMetaVal("level");

            if (!sev.empty()) {
                std::string ls;
                ls.reserve(sev.size());
                for (char c : sev)
                    ls += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

                if (ls == "critical" || ls == "100")
                    ruleThreatLevel = ThreatLevel::Critical;
                else if (ls == "high" || ls == "75")
                    ruleThreatLevel = ThreatLevel::High;
                else if (ls == "medium" || ls == "50")
                    ruleThreatLevel = ThreatLevel::Medium;
                else if (ls == "low" || ls == "25")
                    ruleThreatLevel = ThreatLevel::Low;
                else if (ls == "info" || ls == "0" || ls == "informational")
                    ruleThreatLevel = ThreatLevel::Info;
            }
        }

        // --- Parse strings: section ---
        if (stringsPos == std::string::npos) {
            // No strings section (condition-only rule like filesize checks)
            SS_LOG_DEBUG(L"PatternStore",
                L"ImportFromYaraFile: Rule '%hs' has no strings section, skipping",
                ruleName.c_str());
            continue;
        }

        size_t strEnd = (conditionPos != std::string::npos && conditionPos > stringsPos)
            ? conditionPos : ruleBody.size();
        std::string strSection = ruleBody.substr(stringsPos + 8, strEnd - stringsPos - 8);

        size_t sp = 0;
        size_t pIdx = 0;
        constexpr size_t MAX_PATTERNS_PER_RULE = 1000;

        while (sp < strSection.size() && pIdx < MAX_PATTERNS_PER_RULE) {
            size_t dollarPos = strSection.find('$', sp);
            if (dollarPos == std::string::npos) break;
            sp = dollarPos + 1;

            // Read variable name
            size_t vs = sp;
            while (sp < strSection.size() &&
                   (std::isalnum(static_cast<unsigned char>(strSection[sp])) ||
                    strSection[sp] == '_')) ++sp;
            std::string varName = strSection.substr(vs, sp - vs);

            // Skip to '='
            while (sp < strSection.size() &&
                   std::isspace(static_cast<unsigned char>(strSection[sp]))) ++sp;
            if (sp >= strSection.size() || strSection[sp] != '=') continue;
            ++sp;
            while (sp < strSection.size() &&
                   std::isspace(static_cast<unsigned char>(strSection[sp]))) ++sp;
            if (sp >= strSection.size()) break;

            std::string patHex;

            if (strSection[sp] == '{') {
                // Hex pattern: $var = { AB CD ?? EF }
                size_t hexEnd = strSection.find('}', sp);
                if (hexEnd == std::string::npos) break;
                patHex = extractHex(strSection.substr(sp + 1, hexEnd - sp - 1));
                sp = hexEnd + 1;
            } else if (strSection[sp] == '"') {
                // String pattern: $var = "text"
                ++sp;
                std::string literal;
                while (sp < strSection.size() && strSection[sp] != '"') {
                    if (strSection[sp] == '\\' && sp + 1 < strSection.size()) {
                        literal += strSection[sp];
                        literal += strSection[sp + 1];
                        sp += 2;
                    } else {
                        literal += strSection[sp];
                        ++sp;
                    }
                }
                if (sp < strSection.size()) ++sp;
                patHex = strToHex(literal);
            } else if (strSection[sp] == '/') {
                // Regex: not importable as byte pattern
                size_t regEnd = strSection.find('/', sp + 1);
                if (regEnd != std::string::npos) {
                    sp = regEnd + 1;
                    while (sp < strSection.size() &&
                           std::isalpha(static_cast<unsigned char>(strSection[sp]))) ++sp;
                }
                SS_LOG_DEBUG(L"PatternStore",
                    L"ImportFromYaraFile: Skipping regex pattern $%hs in rule '%hs'",
                    varName.c_str(), ruleName.c_str());
                continue;
            } else {
                continue;
            }

            // Validate minimum pattern length (at least 2 hex bytes)
            if (patHex.size() < 4) continue;

            // Cap individual pattern size (16 KB hex = ~8 KB binary)
            if (patHex.size() > 16384) {
                SS_LOG_WARN(L"PatternStore",
                    L"ImportFromYaraFile: Pattern $%hs exceeds 16 KB in rule '%hs', truncating",
                    varName.c_str(), ruleName.c_str());
                patHex = patHex.substr(0, 16384);
            }

            // Build signature name: ruleName.$varName
            std::string sigName = ruleName;
            if (!varName.empty()) sigName += ".$" + varName;

            patterns.push_back(std::move(patHex));
            names.push_back(std::move(sigName));
            levels.push_back(ruleThreatLevel);
            importedCount++;
            pIdx++;

            if (progressCallback) progressCallback(importedCount, 0);
        }
    }

    if (ruleCount == 0) {
        SS_LOG_WARN(L"PatternStore", L"ImportFromYaraFile: No YARA rules found in '%ls'",
            filePath.c_str());
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "No YARA rules found" };
    }

    if (patterns.empty()) {
        SS_LOG_WARN(L"PatternStore",
            L"ImportFromYaraFile: Parsed %zu rules, 0 patterns from '%ls'",
            ruleCount, filePath.c_str());
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "No scannable patterns in rules" };
    }

    SS_LOG_INFO(L"PatternStore",
        L"ImportFromYaraFile: Parsed %zu rules, importing %zu patterns",
        ruleCount, patterns.size());

    return AddPatternBatch(patterns, names, levels);
}

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
        return StoreError{ SignatureStoreError::Success };
    }

    std::shared_lock<std::shared_mutex> lock(m_globalLock);
    return FlushInternal();
}

StoreError PatternStore::FlushInternal() noexcept {
    // Caller must hold at least a shared lock on m_globalLock
    if (m_mappedView.IsValid()) {
        StoreError err{};
        if (!MemoryMapping::FlushView(m_mappedView, err)) {
            SS_LOG_ERROR(L"PatternStore", L"FlushInternal: Failed to flush view");
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

    // Remove only explicitly deprecated patterns (NEVER remove based on hit count —
    // that would silently disable detection of new or rare malware signatures)
    size_t beforeCount = m_patternCache.size();

    auto newEnd = std::remove_if(m_patternCache.begin(), m_patternCache.end(),
        [](const PatternMetadata& meta) {
            return meta.isDeprecated;
        });

    m_patternCache.erase(newEnd, m_patternCache.end());

    size_t afterCount = m_patternCache.size();
    size_t removed = beforeCount - afterCount;

    if (removed > 0) {
        SS_LOG_INFO(L"PatternStore", L"Compact: Removed %zu deprecated patterns", removed);

        for (size_t i = 0; i < m_patternCache.size(); ++i) {
            m_patternCache[i].signatureId = i;
        }
    }

    // Rebuild automaton
    StoreError err = BuildAutomaton();
    if (!err.IsSuccess()) {
        SS_LOG_WARN(L"PatternStore", L"Compact: Automaton rebuild failed");
        return err;
    }

    // Flush to disk (use internal variant — we already hold exclusive lock)
    return FlushInternal();
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

// ============================================================================
// LOAD PATTERNS FROM THE DATABASE
// ============================================================================
// This is the path that did not exist. PatternStore::Initialize opened the
// mapping, initialised PatternIndex over the pattern section, and went straight
// to BuildAutomaton - which compiles from m_patternCache, and m_patternCache was
// only ever populated by runtime AddPattern calls. So a database full of
// patterns produced a store that reported every component ready, compiled an
// automaton of zero patterns, and matched nothing. Measured, not inferred:
// building a database with one verified EICAR pattern and scanning content that
// contains it reported 0 of 1 matched.
//
// Everything here is read out of a memory-mapped file that lives in a directory
// the product does not yet lock down, so every offset and length is treated as
// untrusted: bounds are checked against the SECTION (not just the file), and a
// field that fails validation rejects THAT ENTRY loudly instead of being
// clamped into something plausible. A pattern quietly coerced into a different
// threat level or a truncated length is a detection defect that looks like
// working detection.
StoreError PatternStore::LoadPatternsFromDatabase() noexcept {
    if (!m_mappedView.IsValid() || m_mappedView.baseAddress == nullptr) {
        SS_LOG_ERROR(L"PatternStore", L"LoadPatterns: mapping is not valid");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Mapping not valid" };
    }

    const auto* dbHeader = m_mappedView.GetAt<SignatureDatabaseHeader>(0);
    if (dbHeader == nullptr) {
        SS_LOG_ERROR(L"PatternStore", L"LoadPatterns: cannot read database header");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Cannot read database header" };
    }

    const uint64_t sectionOffset = dbHeader->patternIndexOffset;
    const uint64_t sectionSize = dbHeader->patternIndexSize;

    if (sectionOffset == 0 || sectionSize == 0) {
        SS_LOG_INFO(L"PatternStore",
            L"LoadPatterns: this database carries no pattern section, so no patterns "
            L"are loaded and pattern scanning will report no matches");
        return StoreError{ SignatureStoreError::Success };
    }

    // Re-validate the section bounds rather than trusting the caller to have done
    // it. Every offset below is resolved relative to this window.
    if (sectionOffset > m_mappedView.fileSize ||
        sectionSize > m_mappedView.fileSize - sectionOffset) {
        SS_LOG_ERROR(L"PatternStore",
            L"LoadPatterns: pattern section 0x%llX+0x%llX exceeds the %llu byte file",
            sectionOffset, sectionSize, m_mappedView.fileSize);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Pattern section out of bounds" };
    }

    const auto* trie = m_mappedView.GetAt<TrieIndexHeader>(sectionOffset);
    if (trie == nullptr || sectionSize < sizeof(TrieIndexHeader)) {
        SS_LOG_ERROR(L"PatternStore",
            L"LoadPatterns: pattern section is too small to hold its own header");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Pattern section truncated" };
    }

    if (trie->magic != TRIE_INDEX_MAGIC) {
        SS_LOG_ERROR(L"PatternStore",
            L"LoadPatterns: pattern section magic is 0x%08X, expected 0x%08X",
            trie->magic, TRIE_INDEX_MAGIC);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Bad pattern section magic" };
    }

    // Version 1 has no patternEntryOffset/patternEntryCount - those bytes were
    // "reserved" and carry no meaning, so they must not be interpreted. Refusing
    // is correct rather than best-effort: reading a reserved field as an offset is
    // how a loader ends up walking arbitrary bytes.
    if (trie->version != TRIE_INDEX_VERSION) {
        SS_LOG_ERROR(L"PatternStore",
            L"LoadPatterns: pattern section version %u is not the supported version %u; "
            L"no patterns loaded (a version 1 section does not record where its pattern "
            L"entries are, so they cannot be found)",
            trie->version, TRIE_INDEX_VERSION);
        return StoreError{ SignatureStoreError::VersionMismatch, 0,
                          "Unsupported pattern section version" };
    }

    const uint64_t entryCount = trie->patternEntryCount;
    const uint64_t entryOffset = trie->patternEntryOffset;

    if (entryCount == 0 || entryOffset == 0) {
        SS_LOG_INFO(L"PatternStore",
            L"LoadPatterns: the pattern section records no pattern entries, so no "
            L"patterns are loaded and pattern scanning will report no matches");
        return StoreError{ SignatureStoreError::Success };
    }

    if (entryOffset < sizeof(TrieIndexHeader)) {
        SS_LOG_ERROR(L"PatternStore",
            L"LoadPatterns: pattern entry offset 0x%llX overlaps the section header",
            entryOffset);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Entry offset overlaps header" };
    }

    // Overflow-safe: never form entryOffset + count * sizeof(PatternEntry) directly.
    if (entryOffset >= sectionSize ||
        entryCount > (sectionSize - entryOffset) / sizeof(PatternEntry)) {
        SS_LOG_ERROR(L"PatternStore",
            L"LoadPatterns: %llu pattern entries at section offset 0x%llX do not fit "
            L"in a 0x%llX byte section",
            entryCount, entryOffset, sectionSize);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Entry array out of bounds" };
    }

    const uint64_t sectionEnd = sectionOffset + sectionSize;
    const uint64_t entryArrayAbs = sectionOffset + entryOffset;

    // A blob must lie inside the section. Checked as a closed range with no
    // addition that can wrap.
    const auto blobInSection = [&](uint64_t at, uint64_t len) noexcept -> bool {
        if (at < sectionOffset || at > sectionEnd) return false;
        return len <= sectionEnd - at;
    };

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    size_t loaded = 0;
    size_t rejected = 0;
    size_t unmatchable = 0;
    size_t maskedLoaded = 0;

    for (uint64_t i = 0; i < entryCount; ++i) {
        const auto* entry = m_mappedView.GetAt<PatternEntry>(
            entryArrayAbs + i * sizeof(PatternEntry));
        if (entry == nullptr) {
            SS_LOG_ERROR(L"PatternStore",
                L"LoadPatterns: entry %llu is not readable; stopping", i);
            ++rejected;
            break;
        }

        const uint32_t patternLen = entry->patternLength;

        // The three size limits in this codebase disagree: the builder validates
        // against MAX_PATTERN_SIZE (8192), the automaton accepts up to
        // AC_MAX_PATTERN_LENGTH (4096), and this store rejects anything over
        // MAX_COMPILED_PATTERN_SIZE (256). A pattern between those bounds builds
        // into the database and cannot be loaded. Report it with the actual number
        // so the disagreement is visible instead of appearing as a missing pattern.
        if (patternLen < MIN_COMPILED_PATTERN_SIZE || patternLen > MAX_COMPILED_PATTERN_SIZE) {
            SS_LOG_ERROR(L"PatternStore",
                L"LoadPatterns: entry %llu has length %u, outside this store's accepted "
                L"range [%zu, %zu]; the pattern is in the database and will NOT be "
                L"matched at runtime",
                i, patternLen, MIN_COMPILED_PATTERN_SIZE, MAX_COMPILED_PATTERN_SIZE);
            ++rejected;
            continue;
        }

        if (!blobInSection(entry->dataOffset, patternLen)) {
            SS_LOG_ERROR(L"PatternStore",
                L"LoadPatterns: entry %llu pattern data 0x%X+%u lies outside the pattern "
                L"section; rejected",
                i, entry->dataOffset, patternLen);
            ++rejected;
            continue;
        }

        // Mode must name a real matching mode before it is cast to the enum.
        const auto modeRaw = static_cast<uint8_t>(entry->mode);
        if (modeRaw > static_cast<uint8_t>(PatternMode::ByteMask)) {
            SS_LOG_ERROR(L"PatternStore",
                L"LoadPatterns: entry %llu has unknown pattern mode %u; rejected",
                i, modeRaw);
            ++rejected;
            continue;
        }

        // Threat level must be one of the defined severities. Deliberately NOT
        // clamped: coercing an unrecognised value down would silently weaken a
        // detection and coercing it up would manufacture a conviction.
        ThreatLevel level{};
        switch (entry->threatLevel) {
            case static_cast<uint32_t>(ThreatLevel::Info):     level = ThreatLevel::Info; break;
            case static_cast<uint32_t>(ThreatLevel::Low):      level = ThreatLevel::Low; break;
            case static_cast<uint32_t>(ThreatLevel::Medium):   level = ThreatLevel::Medium; break;
            case static_cast<uint32_t>(ThreatLevel::High):     level = ThreatLevel::High; break;
            case static_cast<uint32_t>(ThreatLevel::Critical): level = ThreatLevel::Critical; break;
            default:
                SS_LOG_ERROR(L"PatternStore",
                    L"LoadPatterns: entry %llu has threat level %u, which is not a defined "
                    L"severity; rejected rather than coerced",
                    i, entry->threatLevel);
                ++rejected;
                continue;
        }

        if ((entry->flags & ~PatternEntryFlags::AllKnown) != 0) {
            SS_LOG_WARN(L"PatternStore",
                L"LoadPatterns: entry %llu carries flag bits 0x%llX this build does not "
                L"know; the pattern is loaded but any behaviour those bits describe is "
                L"not applied",
                i, entry->flags & ~PatternEntryFlags::AllKnown);
        }

        // Name: NUL-terminated inside the section. The length is not stored, so the
        // scan is bounded by the section end AND by a sane maximum - an unterminated
        // string must not turn into a section-length read.
        std::string name;
        {
            constexpr uint32_t kMaxNameLength = 512;
            const auto* nameBytes = m_mappedView.GetAt<char>(entry->nameOffset);
            uint64_t available = 0;
            if (nameBytes != nullptr && entry->nameOffset >= sectionOffset &&
                entry->nameOffset <= sectionEnd) {
                available = (std::min)(static_cast<uint64_t>(kMaxNameLength),
                                       sectionEnd - entry->nameOffset);
            }

            uint64_t len = 0;
            while (len < available && nameBytes[len] != '\0') {
                ++len;
            }

            if (available == 0 || len == available) {
                // Unnamed or unterminated. The pattern is still usable, but a
                // detection with no name is not actionable, so say so.
                SS_LOG_WARN(L"PatternStore",
                    L"LoadPatterns: entry %llu has no readable NUL-terminated name at "
                    L"0x%X; it is loaded with a generated name",
                    i, entry->nameOffset);
                name = "UnnamedPattern_" + std::to_string(i);
            } else {
                name.assign(nameBytes, static_cast<size_t>(len));
            }
        }

        const uint8_t* dataPtr = m_mappedView.GetAt<uint8_t>(entry->dataOffset);
        if (dataPtr == nullptr) {
            SS_LOG_ERROR(L"PatternStore",
                L"LoadPatterns: entry %llu pattern data is not readable; rejected", i);
            ++rejected;
            continue;
        }

        // Mask, only where the writer said it is present. mode alone is not proof:
        // the writer skips the mask when its length disagrees with the pattern.
        const uint8_t* maskPtr = nullptr;
        if ((entry->flags & PatternEntryFlags::MaskFollowsData) != 0) {
            const uint64_t maskAt = static_cast<uint64_t>(entry->dataOffset) + patternLen;
            if (!blobInSection(maskAt, patternLen)) {
                SS_LOG_ERROR(L"PatternStore",
                    L"LoadPatterns: entry %llu claims a mask at 0x%llX+%u, outside the "
                    L"pattern section; rejected rather than matched without its mask",
                    i, maskAt, patternLen);
                ++rejected;
                continue;
            }
            maskPtr = m_mappedView.GetAt<uint8_t>(maskAt);
            if (maskPtr == nullptr) {
                SS_LOG_ERROR(L"PatternStore",
                    L"LoadPatterns: entry %llu mask is not readable; rejected", i);
                ++rejected;
                continue;
            }
        }

        try {
            PatternMetadata meta{};

            // POSITIONAL identity - see PatternMetadata in the header. The automaton
            // is keyed by this index and every consumer indexes m_patternCache with
            // it, so it must be the position and not the database's signatureId
            // (which is a hash of the name and would fail every bounds check).
            meta.signatureId = m_patternCache.size();
            meta.name = std::move(name);
            meta.threatLevel = level;
            meta.mode = static_cast<PatternMode>(modeRaw);
            meta.pattern.assign(dataPtr, dataPtr + patternLen);

            if (maskPtr != nullptr) {
                meta.mask.assign(maskPtr, maskPtr + patternLen);
            } else {
                // Same convention as AddCompiledPattern: absent mask means exact.
                meta.mask.assign(patternLen, 0xFF);
            }

            meta.entropy = entry->entropy;
            meta.hitCount = entry->hitCount;
            meta.description = "Loaded from signature database";
            meta.created = std::chrono::system_clock::now();
            meta.lastModified = meta.created;
            meta.modificationCount = 0;
            meta.isDeprecated = false;

            // Counted by what can actually scan the pattern, not by whether it is
            // exact. Wildcard and ByteMask entries are scanned by the Boyer-Moore pass;
            // Regex mode - byte ranges and variable gaps - is matched by nothing,
            // because neither is expressible as a fixed-length pattern plus an AND-mask.
            if (meta.mode == PatternMode::Regex) {
                ++unmatchable;
            } else if (meta.mode != PatternMode::Exact) {
                ++maskedLoaded;
            }

            m_patternCache.push_back(std::move(meta));
            ++loaded;
        } catch (const std::bad_alloc&) {
            SS_LOG_ERROR(L"PatternStore",
                L"LoadPatterns: out of memory after loading %zu pattern(s)", loaded);
            return StoreError{ SignatureStoreError::OutOfMemory, 0, "Out of memory loading patterns" };
        } catch (const std::exception&) {
            SS_LOG_ERROR(L"PatternStore", L"LoadPatterns: exception on entry %llu", i);
            ++rejected;
        }
    }

    if (rejected > 0) {
        SS_LOG_ERROR(L"PatternStore",
            L"LoadPatterns: %zu of %llu pattern entrie(s) were REJECTED and will never "
            L"match; the database claims detection this build cannot perform",
            rejected, entryCount);
    }

    // Masked patterns ARE scanned now, by the Boyer-Moore pass that BuildMaskedMatchers
    // compiles and ScanWithMaskedPatterns runs. This line used to say that nothing in
    // the product matched them, which was true when it was written and would now be a
    // false statement in the log.
    if (maskedLoaded > 0) {
        SS_LOG_INFO(L"PatternStore",
            L"LoadPatterns: %zu loaded pattern(s) carry a wildcard mask and are scanned "
            L"by the masked pass rather than the automaton",
            maskedLoaded);
    }

    // Regex mode remains matched by NOTHING, and that is a property of the construct
    // rather than a missing implementation: a byte range is not a bitmask and a variable
    // gap changes the length of a match, so neither the automaton nor a fixed-length
    // masked matcher can express one. phantom-sigbuild refuses both at build time.
    if (unmatchable > 0) {
        SS_LOG_ERROR(L"PatternStore",
            L"LoadPatterns: %zu loaded pattern(s) are Regex mode (byte range or variable "
            L"gap) and NO matcher in this build scans those - they are held in the store "
            L"and will never produce a detection",
            unmatchable);
    }

    SS_LOG_INFO(L"PatternStore",
        L"LoadPatterns: loaded %zu of %llu pattern entrie(s) from the database",
        loaded, entryCount);

    return StoreError{ SignatureStoreError::Success };
}

void PatternStore::BuildMaskedMatchers() noexcept {
    m_maskedMatchers.clear();

    size_t withWildcards = 0;
    size_t maskIsFullyExact = 0;
    size_t refusedMaskShape = 0;
    size_t refusedRegex = 0;
    size_t refusedBuild = 0;

    for (size_t cacheIndex = 0; cacheIndex < m_patternCache.size(); ++cacheIndex) {
        const auto& meta = m_patternCache[cacheIndex];

        // Exact patterns belong to the automaton. Building a Boyer-Moore matcher for
        // them as well would double every match.
        if (meta.mode == PatternMode::Exact) {
            continue;
        }

        if (meta.pattern.empty()) {
            continue;
        }

        // Regex mode covers byte ranges ([01-FF]) and variable gaps ({0-16}). Neither
        // is expressible as a fixed-length pattern plus an AND-mask: a range is not a
        // bitmask, and a variable gap changes the LENGTH of a match. Boyer-Moore is a
        // fixed-length matcher, so it cannot be made to serve these by configuration.
        //
        // Reported at ERROR because the pattern is in the store and will never fire.
        // phantom-sigbuild refuses both constructs at build time, so a Regex-mode entry
        // can only arrive through the runtime AddPattern API, which bypasses that
        // check - and see the compiler defect that makes such an entry wrong as well as
        // unmatched: '[01-FF]' compiles to an exact match on 0x01 and '{0-16}' is
        // dropped entirely, so the stored bytes are not what the author wrote.
        if (meta.mode == PatternMode::Regex) {
            ++refusedRegex;
            SS_LOG_ERROR(L"PatternStore",
                L"BuildMaskedMatchers: pattern '%S' (index %zu) is Regex mode - no "
                L"matcher in this build can scan a byte range or a variable gap, so it "
                L"will never produce a detection",
                meta.name.c_str(), cacheIndex);
            continue;
        }

        // A masked pattern whose mask does not describe its bytes cannot be scanned
        // correctly. BoyerMooreMatcher would silently reconcile the two by padding with
        // 0xFF or truncating, which changes which bytes are wildcards - so the entry is
        // refused here instead, where the disagreement can be named.
        if (meta.mask.size() != meta.pattern.size()) {
            ++refusedMaskShape;
            SS_LOG_ERROR(L"PatternStore",
                L"BuildMaskedMatchers: pattern '%S' (index %zu) declares mode %u but its "
                L"mask is %zu byte(s) for %zu pattern byte(s) - refused rather than "
                L"padded, because padding would change which positions are wildcards",
                meta.name.c_str(), cacheIndex, static_cast<unsigned>(meta.mode),
                meta.mask.size(), meta.pattern.size());
            continue;
        }

        const bool hasWildcardPosition = std::any_of(meta.mask.begin(), meta.mask.end(),
            [](uint8_t maskByte) { return maskByte != 0xFFu; });

        // A mask of all 0xFF still gets a matcher. It is equivalent to an exact pattern,
        // but the automaton only accepts mode == Exact, so declining to build one here
        // would leave the pattern owned by neither pass - scanned by nothing while
        // looking loaded. Cheap to keep correct, and Boyer-Moore keeps its full
        // good-suffix shifts in this case because no mask position is degraded.
        if (hasWildcardPosition) {
            ++withWildcards;
        } else {
            ++maskIsFullyExact;
        }

        try {
            auto matcher = std::make_unique<BoyerMooreMatcher>(
                std::span<const uint8_t>(meta.pattern),
                std::span<const uint8_t>(meta.mask));

            if (!matcher->IsValid()) {
                ++refusedBuild;
                SS_LOG_ERROR(L"PatternStore",
                    L"BuildMaskedMatchers: matcher for pattern '%S' (index %zu, %zu byte(s)) "
                    L"did not build a usable state and is DISCARDED - it would have "
                    L"reported no matches for every buffer",
                    meta.name.c_str(), cacheIndex, meta.pattern.size());
                continue;
            }

            m_maskedMatchers.push_back(MaskedMatcher{ cacheIndex, std::move(matcher) });
        } catch (const std::bad_alloc&) {
            ++refusedBuild;
            SS_LOG_ERROR(L"PatternStore",
                L"BuildMaskedMatchers: out of memory building a matcher for pattern '%S' "
                L"(index %zu); it will not be scanned",
                meta.name.c_str(), cacheIndex);
        }
    }

    const size_t unscannable = refusedRegex + refusedMaskShape + refusedBuild;

    if (unscannable > 0) {
        SS_LOG_ERROR(L"PatternStore",
            L"BuildMaskedMatchers: %zu non-exact pattern(s) CANNOT be scanned by this "
            L"build (%zu regex, %zu mask/pattern size disagreement, %zu failed to build) "
            L"- the store holds them and they will never produce a detection",
            unscannable, refusedRegex, refusedMaskShape, refusedBuild);
    }

    if (!m_maskedMatchers.empty()) {
        SS_LOG_INFO(L"PatternStore",
            L"BuildMaskedMatchers: %zu masked pattern(s) ready to scan (%zu with wildcard "
            L"positions, %zu whose mask is fully exact)",
            m_maskedMatchers.size(), withWildcards, maskIsFullyExact);
    }
}

StoreError PatternStore::BuildAutomaton() noexcept {
    // Rebuild the masked matchers FIRST, and unconditionally.
    //
    // This must happen before any early return below. A store holding only masked
    // patterns produces addedCount == 0, which returns Success early - so building the
    // matchers after that point would leave a store full of wildcard patterns with no
    // matchers at all, reporting success. That is the same shape as the empty automaton
    // this function already had to learn to distinguish from a failure.
    //
    // Both callers of this function hold m_globalLock exclusively, which is what makes
    // clearing and repopulating m_maskedMatchers safe against the shared_lock the scan
    // passes take.
    BuildMaskedMatchers();

    // Create new automaton separately for exception safety
    // Only replace m_automaton if compilation succeeds
    auto newAutomaton = std::make_unique<AhoCorasickAutomaton>();

    // Add patterns from cache to automaton.
    //
    // THE KEY IS THE CACHE INDEX, not meta.signatureId. Every consumer of a match
    // treats the value the automaton hands back as an index into m_patternCache -
    // ScanWithAutomaton bounds-checks it with `patternId >= cacheSize` and then does
    // m_patternCache[patternId], and the hit counters are indexed the same way.
    //
    // The two are equal today because PatternMetadata::signatureId is positional,
    // but passing signatureId made that a coincidence rather than a contract, and
    // the coincidence was one change away from breaking silently: the database's
    // PatternEntry::signatureId is a hash of the pattern name, so the first loader
    // to carry it through would have had every single match discarded by that bounds
    // check, with a warning calling the id invalid. Store ready, automaton compiled,
    // matches found, results thrown away.
    //
    // Only PatternMode::Exact is added, because Aho-Corasick keys its transitions on
    // exact byte values and has no edge to follow for a "match any byte" position.
    // Masked patterns are therefore not a gap here - they are owned by the separate
    // Boyer-Moore pass that BuildMaskedMatchers compiled above.
    size_t addedCount = 0;
    for (size_t cacheIndex = 0; cacheIndex < m_patternCache.size(); ++cacheIndex) {
        const auto& meta = m_patternCache[cacheIndex];
        if (meta.mode == PatternMode::Exact) {
            if (!newAutomaton->AddPattern(meta.pattern, static_cast<uint64_t>(cacheIndex))) {
                SS_LOG_WARN(L"PatternStore", 
                    L"BuildAutomaton: Failed to add pattern '%S' at index %zu",
                    meta.name.c_str(), cacheIndex);
                // Continue with other patterns, don't fail entire build
            } else {
                addedCount++;
            }
        }
    }

    // Nothing to compile is not a failure.
    //
    // AhoCorasickAutomaton::Compile() returns false for an empty automaton, so with
    // no patterns loaded this reported "BuildAutomaton: Compilation failed" as an
    // ERROR and the caller followed it with "Failed to build automaton" on every
    // single service start. There is no pattern content shipped yet, so that pair of
    // lines was pure noise - and noise on an error channel is not harmless: it
    // trains whoever reads the log to skip exactly the line that will matter when
    // the automaton genuinely fails to build.
    //
    // The two states are now distinguished. An empty pattern set is reported plainly
    // and succeeds, with the automaton released so that it reflects reality: no
    // patterns means no pattern matches, and ScanWithAutomaton already returns an
    // empty result set when no automaton is present. Releasing it also matters for
    // correctness in the other direction - if patterns were removed, keeping the
    // previous automaton would go on matching content the store no longer holds.
    if (addedCount == 0) {
        m_automaton.reset();

        // The hit counters are sized to the CACHE, not to the automaton. A store with
        // no exact patterns can still hold masked ones that the Boyer-Moore pass scans
        // and counts, and clearing the counters unconditionally would silently disable
        // the heatmap for exactly that store.
        if (m_maskedMatchers.empty()) {
            m_hitCounters.clear();
            SS_LOG_INFO(L"PatternStore",
                L"BuildAutomaton: no exact patterns are loaded, so there is nothing to "
                L"compile; pattern scanning will report no matches until pattern content "
                L"is added to the database");
        } else {
            m_hitCounters.assign(m_patternCache.size(), 0);
            for (size_t i = 0; i < m_patternCache.size(); ++i) {
                m_hitCounters[i] = m_patternCache[i].hitCount;
            }
            SS_LOG_INFO(L"PatternStore",
                L"BuildAutomaton: no exact patterns to compile, but %zu masked pattern(s) "
                L"are loaded and will be scanned by the Boyer-Moore pass",
                m_maskedMatchers.size());
        }

        return StoreError{ SignatureStoreError::Success };
    }

    // Compile the automaton
    if (!newAutomaton->Compile()) {
        SS_LOG_ERROR(L"PatternStore",
            L"BuildAutomaton: compilation failed with %zu pattern(s) present - the "
            L"previous automaton is kept, so pattern coverage is whatever it was "
            L"before this rebuild",
            addedCount);
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
    const QueryOptions& options,
    const LARGE_INTEGER& deadline,
    bool& outServedExactPatterns
) const noexcept {
    std::vector<DetectionResult> results;

    outServedExactPatterns = false;

    if (buffer.empty()) {
        return results;
    }

    // Take reader lock for thread-safe access to pattern cache
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    // The automaton is checked HERE, under the lock, and not before it.
    //
    // This test used to sit above the lock acquisition while m_automaton->Search()
    // below runs inside it. BuildAutomaton both resets that unique_ptr (when no exact
    // patterns remain) and move-assigns it (destroying the previous automaton), under
    // the exclusive lock - so between an unlocked check and the locked dereference the
    // pointer could become null or refer to a destroyed object. Task 61 fixed the hit
    // counters in this same function and left the pointer they are reached through
    // unsynchronised, which is the more serious half.
    if (!m_automaton) {
        SS_LOG_DEBUG(L"PatternStore", L"ScanWithAutomaton: No automaton available");
        return results;
    }

    // Reaching this point means the automaton is present and will be searched, so the
    // exact patterns are covered and the caller must not run the fallback. Set before
    // the search rather than after: a search that finds nothing, times out, or stops
    // at maxResults has still covered them, and re-running a per-pattern sweep after a
    // timeout would spend more of a budget that has already expired.
    outServedExactPatterns = true;

    // Capture cache size once under lock to avoid TOCTOU
    const size_t cacheSize = m_patternCache.size();

    // Reserve reasonable capacity
    try {
        const size_t reserveCapacity = (std::min)(
            static_cast<size_t>(options.maxResults > 0 ? options.maxResults : 256u),
            static_cast<size_t>(256)
        );
        results.reserve(reserveCapacity);
    } catch (const std::bad_alloc&) {
        SS_LOG_WARN(L"PatternStore", L"ScanWithAutomaton: Failed to reserve results capacity");
    }

    // Track match count for maxResults limit
    size_t matchCount = 0;
    const size_t maxResults = options.maxResults > 0 ? options.maxResults : SIZE_MAX;
    bool timedOut = false;

    try {
        m_automaton->Search(buffer, [&](uint64_t patternId, size_t offset) {
            if (matchCount >= maxResults || timedOut) {
                return;
            }

            // Periodic timeout check (every 64 matches to amortize syscall cost)
            if ((matchCount & 63) == 0 && IsDeadlineExceeded(deadline)) {
                timedOut = true;
                SS_LOG_WARN(L"PatternStore", L"ScanWithAutomaton: Timeout exceeded");
                return;
            }

            // Validate pattern ID bounds
            if (patternId >= cacheSize) {
                SS_LOG_WARN(L"PatternStore", 
                    L"ScanWithAutomaton: Invalid pattern ID %llu (cache size %zu)", 
                    patternId, cacheSize);
                return;
            }

            const auto& meta = m_patternCache[patternId];

            try {
                DetectionResult result{};
                result.signatureId = meta.signatureId;
                result.signatureName = meta.name;
                result.threatLevel = meta.threatLevel;
                result.fileOffset = offset;
                result.description = "Pattern match";

                results.push_back(std::move(result));
                matchCount++;

                // Hit counter updated HERE, under the shared lock this function
                // already holds, indexed by the cache index. It used to be done by
                // the caller after both scan helpers had returned and released their
                // locks - an unsynchronised read of m_hitCounters.size() followed by
                // taking a reference into a vector that BuildAutomaton resizes under
                // the exclusive lock. Rebuild, Compact or OptimizeByHitRate running
                // concurrently with a scan could therefore reallocate the storage
                // under that reference.
                if (m_heatmapEnabled.load(std::memory_order_acquire) &&
                    patternId < m_hitCounters.size()) {
                    std::atomic_ref<uint64_t> counter(
                        const_cast<std::vector<uint64_t>&>(m_hitCounters)[patternId]);
                    counter.fetch_add(1, std::memory_order_relaxed);
                }
            } catch (const std::bad_alloc&) {
                SS_LOG_WARN(L"PatternStore", L"ScanWithAutomaton: Memory allocation failed for result");
            }
        });
    } catch (const std::exception&) {
        SS_LOG_ERROR(L"PatternStore", L"ScanWithAutomaton: Exception during search");
    }

    SS_LOG_DEBUG(L"PatternStore", L"ScanWithAutomaton: Found %zu matches", results.size());

    return results;
}

std::vector<DetectionResult> PatternStore::ScanWithSIMD(
    std::span<const uint8_t> buffer,
    const QueryOptions& options,
    const LARGE_INTEGER& deadline
) const noexcept {
    std::vector<DetectionResult> results;

    if (buffer.empty()) {
        return results;
    }

    // Take reader lock for thread-safe access to pattern cache
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    // Check if AVX2 is available
    if (!SIMDMatcher::IsAVX2Available()) {
        SS_LOG_DEBUG(L"PatternStore", L"ScanWithSIMD: AVX2 not available");
        return results;
    }

    // Track match count for maxResults limit
    size_t matchCount = 0;
    const size_t maxResults = options.maxResults > 0 ? options.maxResults : SIZE_MAX;

    // Reserve reasonable capacity
    try {
        const size_t reserveCapacity = (std::min)(static_cast<size_t>(256), 
            static_cast<size_t>(maxResults));
        results.reserve(reserveCapacity);
    } catch (const std::bad_alloc&) {
        SS_LOG_WARN(L"PatternStore", L"ScanWithSIMD: Failed to reserve results capacity");
    }

    // Use SIMD for exact patterns only.
    // cacheIndex is the position in m_patternCache and is what the hit counters are
    // indexed by. It is a separate variable from the deadline stride counter on
    // purpose: that one was incremented inside the condition expression, so the
    // value visible in the body was already one past the entry being scanned.
    size_t checkStride = 0;
    for (size_t cacheIndex = 0; cacheIndex < m_patternCache.size(); ++cacheIndex) {
        const auto& meta = m_patternCache[cacheIndex];

        if (matchCount >= maxResults) {
            break;
        }

        // Periodic timeout check (every 32 patterns to amortize syscall cost)
        if ((checkStride++ & 31) == 0 && IsDeadlineExceeded(deadline)) {
            SS_LOG_WARN(L"PatternStore", L"ScanWithSIMD: Timeout exceeded");
            break;
        }

        if (meta.mode != PatternMode::Exact) {
            continue;
        }

        // Skip empty patterns
        if (meta.pattern.empty()) {
            continue;
        }

        // Skip patterns longer than buffer
        if (meta.pattern.size() > buffer.size()) {
            continue;
        }

        try {
            auto matches = SIMDMatcher::SearchAVX2(buffer, meta.pattern);

            for (size_t offset : matches) {
                if (matchCount >= maxResults) {
                    break;
                }

                DetectionResult result{};
                result.signatureId = meta.signatureId;
                result.signatureName = meta.name;
                result.threatLevel = meta.threatLevel;
                result.fileOffset = offset;
                result.description = "SIMD pattern match";

                results.push_back(std::move(result));
                matchCount++;

                // Under the shared lock held by this function - see the equivalent
                // comment in ScanWithAutomaton for why the caller must not do this.
                if (m_heatmapEnabled.load(std::memory_order_acquire) &&
                    cacheIndex < m_hitCounters.size()) {
                    std::atomic_ref<uint64_t> counter(
                        const_cast<std::vector<uint64_t>&>(m_hitCounters)[cacheIndex]);
                    counter.fetch_add(1, std::memory_order_relaxed);
                }
            }
        } catch (const std::exception&) {
            SS_LOG_WARN(L"PatternStore", 
                L"ScanWithSIMD: Exception searching pattern '%S'", meta.name.c_str());
        }
    }

    SS_LOG_DEBUG(L"PatternStore", L"ScanWithSIMD: Found %zu matches", results.size());

    return results;
}

std::vector<DetectionResult> PatternStore::ScanWithMaskedPatterns(
    std::span<const uint8_t> buffer,
    const QueryOptions& options,
    const LARGE_INTEGER& deadline
) const noexcept {
    std::vector<DetectionResult> results;

    if (buffer.empty()) {
        return results;
    }

    // Reader lock, held for the whole pass: it guards both m_maskedMatchers (which
    // BuildMaskedMatchers clears and repopulates under the exclusive lock) and the
    // cache entries the results are built from.
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    // Checked under the lock for the same reason the automaton pointer is - the vector
    // this reads is replaced wholesale by a rebuild.
    if (m_maskedMatchers.empty()) {
        return results;
    }

    const size_t cacheSize = m_patternCache.size();

    size_t matchCount = 0;
    const size_t maxResults = options.maxResults > 0 ? options.maxResults : SIZE_MAX;

    try {
        const size_t reserveCapacity = (std::min)(static_cast<size_t>(256),
            static_cast<size_t>(maxResults));
        results.reserve(reserveCapacity);
    } catch (const std::bad_alloc&) {
        SS_LOG_WARN(L"PatternStore", L"ScanWithMaskedPatterns: Failed to reserve results capacity");
    }

    size_t scannedPatterns = 0;

    for (const auto& entry : m_maskedMatchers) {
        if (matchCount >= maxResults) {
            break;
        }

        // The deadline is tested on EVERY iteration, not on a stride like the SIMD pass.
        // One iteration here is a full traversal of the buffer, and a masked pattern
        // degrades Boyer-Moore's good-suffix shifts to 1, so a single iteration is the
        // most expensive unit of work in the whole scan path. Amortising the clock read
        // across 32 of them, which is right for cheap iterations, would allow a 32-pass
        // overrun of a budget that exists to bound the kernel's wait.
        //
        // HONEST LIMIT: this bounds the pass BETWEEN patterns, not within one. A single
        // masked pattern against a large buffer runs to completion regardless of the
        // deadline, because BoyerMooreMatcher::Search has no interruption point. Its own
        // iteration cap is the only bound inside a call.
        if (IsDeadlineExceeded(deadline)) {
            SS_LOG_WARN(L"PatternStore",
                L"ScanWithMaskedPatterns: deadline exceeded after %zu of %zu masked "
                L"pattern(s); the remainder were NOT scanned for this buffer",
                scannedPatterns, m_maskedMatchers.size());
            break;
        }

        // Both guards are structural rather than defensive: the matcher is only ever
        // stored non-null and valid, and cacheIndex is only ever set from a live cache
        // position under the exclusive lock. They are here because this vector and the
        // cache are two structures that must agree, and if a future change breaks that
        // agreement the correct outcome is to skip and say so, not to index out of range.
        if (!entry.matcher) {
            SS_LOG_ERROR(L"PatternStore",
                L"ScanWithMaskedPatterns: null matcher at cache index %zu - skipped",
                entry.cacheIndex);
            continue;
        }

        if (entry.cacheIndex >= cacheSize) {
            SS_LOG_ERROR(L"PatternStore",
                L"ScanWithMaskedPatterns: matcher references cache index %zu but the cache "
                L"holds %zu entrie(s) - skipped; the matchers are out of step with the cache",
                entry.cacheIndex, cacheSize);
            continue;
        }

        const auto& meta = m_patternCache[entry.cacheIndex];

        if (meta.pattern.size() > buffer.size()) {
            continue;
        }

        ++scannedPatterns;

        const std::vector<size_t> offsets = entry.matcher->Search(buffer);

        for (const size_t offset : offsets) {
            if (matchCount >= maxResults) {
                break;
            }

            try {
                DetectionResult result{};
                result.signatureId = meta.signatureId;
                result.signatureName = meta.name;
                result.threatLevel = meta.threatLevel;
                result.fileOffset = offset;
                result.description = "Masked pattern match";

                results.push_back(std::move(result));
                matchCount++;

                // Under the shared lock held by this function - see the equivalent
                // comment in ScanWithAutomaton for why the caller must not do this.
                if (m_heatmapEnabled.load(std::memory_order_acquire) &&
                    entry.cacheIndex < m_hitCounters.size()) {
                    std::atomic_ref<uint64_t> counter(
                        const_cast<std::vector<uint64_t>&>(m_hitCounters)[entry.cacheIndex]);
                    counter.fetch_add(1, std::memory_order_relaxed);
                }
            } catch (const std::bad_alloc&) {
                SS_LOG_WARN(L"PatternStore",
                    L"ScanWithMaskedPatterns: Memory allocation failed for result");
            }
        }
    }

    SS_LOG_DEBUG(L"PatternStore",
        L"ScanWithMaskedPatterns: Found %zu matches across %zu masked pattern(s)",
        results.size(), scannedPatterns);

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
    result.threatLevel = ThreatLevel::Info; // Safe default (lowest severity)

    // Thread-safe read with shared lock
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    if (patternId < m_patternCache.size()) {
        const auto& meta = m_patternCache[patternId];
        result.signatureName = meta.name;
        result.threatLevel = meta.threatLevel;
        result.description = meta.description;
    } else {
        result.signatureName = "Unknown_" + std::to_string(patternId);
        SS_LOG_WARN(L"PatternStore", 
            L"BuildDetectionResult: Pattern ID %llu out of range", patternId);
    }

    return result;
}

// UpdateHitCount was removed. It had ZERO callers while the live hit-counter
// update sat inline in Scan without any lock - the correct implementation was dead
// code and the racy copy was the one that ran. It cannot simply be called from the
// scan helpers either: they already hold a shared_lock, and re-acquiring a
// std::shared_mutex in shared mode from inside that region can deadlock when a
// writer is queued between the two acquisitions. The update now happens where the
// lock is already held and the cache index is already known.

bool PatternStore::IsDeadlineExceeded(const LARGE_INTEGER& deadline) const noexcept {
    if (deadline.QuadPart == 0) {
        return false;
    }
    LARGE_INTEGER now{};
    if (!QueryPerformanceCounter(&now)) {
        return false;
    }
    return now.QuadPart >= deadline.QuadPart;
}

std::wstring PatternStore::GetDatabasePath() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_globalLock);
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

    if (m_mappedView.baseAddress == nullptr) {
        SS_LOG_WARN(L"PatternStore", L"GetHeader: Base address is null");
        return nullptr;
    }

    // Validate file size can accommodate header
    if (m_mappedView.fileSize < sizeof(SignatureDatabaseHeader)) {
        SS_LOG_ERROR(L"PatternStore", L"GetHeader: File too small for header");
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

    // Validate version (warning only for minor version mismatch)
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
    
    // Initialize all fields to safe defaults
    stats.totalScans = 0;
    stats.totalMatches = 0;
    stats.totalBytesScanned = 0;
    stats.totalPatterns = 0;
    stats.exactPatterns = 0;
    stats.wildcardPatterns = 0;
    stats.regexPatterns = 0;
    stats.averageScanTimeMicroseconds = 0;
    stats.peakScanTimeMicroseconds = 0;
    stats.averageThroughputMBps = 0.0;
    stats.automatonNodeCount = 0;

    // Read atomic statistics safely
    stats.totalScans = m_totalScans.load(std::memory_order_relaxed);
    stats.totalMatches = m_totalMatches.load(std::memory_order_relaxed);
    stats.totalBytesScanned = m_totalBytesScanned.load(std::memory_order_relaxed);
    stats.totalPatterns = m_patternCache.size();

    // Count patterns by mode
    for (const auto& meta : m_patternCache) {
        switch (meta.mode) {
            case PatternMode::Exact:    stats.exactPatterns++; break;
            case PatternMode::Wildcard: stats.wildcardPatterns++; break;
            case PatternMode::Regex:    stats.regexPatterns++; break;
            default: break;
        }
    }

    // Get automaton statistics safely
    if (m_automaton) {
        stats.automatonNodeCount = m_automaton->GetNodeCount();
    }

    return stats;
}

std::map<size_t, size_t> PatternStore::GetLengthHistogram() const noexcept {
    SS_LOG_DEBUG(L"PatternStore", L"GetLengthHistogram: Building histogram");

    std::map<size_t, size_t> histogram;

    auto startTime = std::chrono::high_resolution_clock::now();

    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    const size_t totalPatterns = m_patternCache.size();

    if (totalPatterns == 0) {
        SS_LOG_WARN(L"PatternStore", L"GetLengthHistogram: Empty pattern cache");
        return histogram;
    }

    // Build histogram
    for (const auto& meta : m_patternCache) {
        if (!meta.pattern.empty()) {
            histogram[meta.pattern.size()]++;
        }
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

    // Extended logging with statistics
    if (!histogram.empty()) {
        const size_t minLen = histogram.begin()->first;
        const size_t maxLen = histogram.rbegin()->first;

        // Calculate statistics safely
        double avgLength = 0.0;
        double variance = 0.0;

        for (const auto& [length, count] : histogram) {
            avgLength += static_cast<double>(length) * static_cast<double>(count);
        }
        
        if (totalPatterns > 0) {
            avgLength /= static_cast<double>(totalPatterns);
        }

        for (const auto& [length, count] : histogram) {
            const double diff = static_cast<double>(length) - avgLength;
            variance += diff * diff * static_cast<double>(count);
        }
        
        if (totalPatterns > 0) {
            variance /= static_cast<double>(totalPatterns);
        }
        
        const double stdDev = std::sqrt(variance);

        // Find most common length (mode)
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
            L"  Histogram buckets: %zu, Computation time: %lld us",
            histogram.size(), static_cast<long long>(duration.count()));
    }

    return histogram;
}

void PatternStore::ResetStatistics() noexcept {
    m_totalScans.store(0, std::memory_order_release);
    m_totalMatches.store(0, std::memory_order_release);
    m_totalBytesScanned.store(0, std::memory_order_release);

    // Clear hit counters under exclusive lock (prevents concurrent atomic_ref access)
    std::unique_lock<std::shared_mutex> lock(m_globalLock);
    for (size_t i = 0; i < m_hitCounters.size(); ++i) {
        m_hitCounters[i] = 0;
    }
    for (auto& meta : m_patternCache) {
        meta.hitCount = 0;
    }
    
    SS_LOG_DEBUG(L"PatternStore", L"ResetStatistics: Statistics and hit counters cleared");
}

std::vector<std::pair<uint64_t, uint32_t>> PatternStore::GetHeatmap() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    std::vector<std::pair<uint64_t, uint32_t>> heatmap;
    
    // Reserve capacity
    try {
        heatmap.reserve(m_patternCache.size());
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"PatternStore", L"GetHeatmap: Failed to reserve capacity");
        return heatmap;
    }

    // Read hit counts safely (shared lock held — vector won't be resized)
    for (size_t i = 0; i < m_patternCache.size(); ++i) {
        const auto& meta = m_patternCache[i];
        uint32_t hitCount = 0;

        if (i < m_hitCounters.size()) {
            std::atomic_ref<uint64_t> counter(m_hitCounters[i]);
            const uint64_t rawCount = counter.load(std::memory_order_relaxed);
            hitCount = static_cast<uint32_t>(
                (std::min)(rawCount, static_cast<uint64_t>((std::numeric_limits<uint32_t>::max)()))
            );
        } else {
            hitCount = meta.hitCount;
        }

        try {
            heatmap.emplace_back(meta.signatureId, hitCount);
        } catch (const std::bad_alloc&) {
            SS_LOG_WARN(L"PatternStore", L"GetHeatmap: Memory allocation failed at index %zu", i);
            break;
        }
    }

    // Sort by hit count (descending)
    std::sort(heatmap.begin(), heatmap.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });

    SS_LOG_DEBUG(L"PatternStore", L"GetHeatmap: Returned %zu entries", heatmap.size());

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
    
    // Empty string returns empty vector
    if (hexStr.empty()) {
        return bytes;
    }

    // Reserve capacity for better performance
    try {
        bytes.reserve(hexStr.length() / 2);
    } catch (const std::bad_alloc&) {
        return std::nullopt;
    }
    
    // Process pairs of hex characters
    for (size_t i = 0; i + 1 < hexStr.length(); i += 2) {
        // Skip whitespace
        while (i < hexStr.length() && std::isspace(static_cast<unsigned char>(hexStr[i]))) {
            i++;
        }
        
        if (i + 1 >= hexStr.length()) {
            break;
        }
        
        // Validate both characters are hex digits
        if (!std::isxdigit(static_cast<unsigned char>(hexStr[i])) ||
            !std::isxdigit(static_cast<unsigned char>(hexStr[i + 1]))) {
            return std::nullopt;
        }
        
        const std::string byteStr = hexStr.substr(i, 2);
        try {
            const int val = std::stoi(byteStr, nullptr, 16);
            if (val < 0 || val > 255) {
                return std::nullopt;
            }
            bytes.push_back(static_cast<uint8_t>(val));
        } catch (const std::out_of_range&) {
            return std::nullopt;
        } catch (const std::invalid_argument&) {
            return std::nullopt;
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

    return bytes;
}

std::string BytesToHexString(
    std::span<const uint8_t> bytes
) noexcept {
    if (bytes.empty()) {
        return std::string{};
    }

    try {
        std::ostringstream oss;
        oss << std::hex << std::uppercase << std::setfill('0');
        
        for (size_t i = 0; i < bytes.size(); ++i) {
            if (i > 0) {
                oss << ' '; // Add space between bytes
            }
            oss << std::setw(2) << static_cast<unsigned>(bytes[i]);
        }

        return oss.str();
    } catch (const std::exception&) {
        return std::string{};
    }
}

size_t HammingDistance(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b
) noexcept {
    size_t distance = 0;
    const size_t minLen = (std::min)(a.size(), b.size());

    // Count bit differences in overlapping region
    for (size_t i = 0; i < minLen; ++i) {
        distance += static_cast<size_t>(std::popcount(static_cast<uint8_t>(a[i] ^ b[i])));
    }

    // Add difference in lengths (each byte difference = 8 bits)
    const size_t lenDiff = (a.size() > b.size()) ? (a.size() - b.size()) : (b.size() - a.size());
    
    // Check for overflow before multiplication
    if (lenDiff <= (std::numeric_limits<size_t>::max)() / 8) {
        distance += lenDiff * 8;
    } else {
        distance = (std::numeric_limits<size_t>::max)();
    }

    return distance;
}

} // namespace PatternUtils

} // namespace PatternStore
} // namespace ShadowStrike
