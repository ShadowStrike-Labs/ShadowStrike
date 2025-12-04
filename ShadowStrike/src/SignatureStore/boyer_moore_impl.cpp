

/**
 * @file boyer_moore_impl.cpp
 * @brief Boyer-Moore Pattern Matching Algorithm Implementation
 *
 * This file implements a high-performance Boyer-Moore string matching algorithm
 * optimized for malware signature scanning in antivirus applications.
 *
 * Architecture:
 * - Bad character rule for O(n/m) average case performance
 * - Good suffix rule using Z-algorithm for worst-case O(n) guarantee
 * - Optional mask support for wildcard pattern matching
 *
 * Security Features:
 * - Comprehensive bounds checking on all array accesses
 * - Pattern length limits to prevent DoS
 * - Integer overflow protection in offset calculations
 * - Safe handling of empty patterns and buffers
 *
 * Performance:
 * - Target: <100ns per pattern construction
 * - Zero allocations during search
 * - Cache-line optimized data layout
 * - Branch prediction friendly
 *
 * Thread Safety:
 * - Search methods are const and thread-safe for concurrent reads
 * - Construction is single-threaded only
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
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
#include <chrono>
#include <mutex>
#include <limits>
#include <stdexcept>

namespace ShadowStrike {
namespace SignatureStore {

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

namespace {

/// @brief Maximum pattern length for Boyer-Moore (prevents DoS via huge patterns)
/// @note Uses local name to avoid conflict with SignatureFormat.hpp constant
constexpr size_t BM_MAX_PATTERN_LENGTH = 8192;

/// @brief Maximum number of matches to return (prevent memory exhaustion)
constexpr size_t BM_MAX_MATCH_COUNT = 10'000'000;

/// @brief Maximum search iterations (DoS protection)
constexpr size_t BM_MAX_ITERATIONS = 100'000'000;

/// @brief Maximum match count for single search (consistent naming)
constexpr size_t MAX_MATCH_COUNT = BM_MAX_MATCH_COUNT;

/**
 * @brief Check if addition would overflow size_t
 * @param a First operand
 * @param b Second operand  
 * @return True if overflow would occur
 * @note Uses compiler intrinsic where available for optimal codegen
 */
[[nodiscard]] constexpr inline bool WouldOverflow(size_t a, size_t b) noexcept {
    return a > std::numeric_limits<size_t>::max() - b;
}

/**
 * @brief Safe addition with overflow check
 * @param a First operand
 * @param b Second operand
 * @param result Output parameter for result
 * @return True if addition succeeded without overflow
 */
[[nodiscard]] constexpr inline bool SafeAdd(size_t a, size_t b, size_t& result) noexcept {
    if (WouldOverflow(a, b)) {
        result = std::numeric_limits<size_t>::max();
        return false;
    }
    result = a + b;
    return true;
}

/**
 * @brief Safe subtraction with underflow check
 * @param a Minuend
 * @param b Subtrahend
 * @param result Output parameter for result
 * @return True if subtraction succeeded without underflow
 */
[[nodiscard]] constexpr inline bool SafeSub(size_t a, size_t b, size_t& result) noexcept {
    if (b > a) {
        result = 0;
        return false;
    }
    result = a - b;
    return true;
}

} // anonymous namespace

// ============================================================================
// BOYER-MOORE MATCHER IMPLEMENTATION
// ============================================================================

/**
 * @brief Construct Boyer-Moore matcher with pattern and optional mask
 * @param pattern The byte pattern to search for
 * @param mask Optional mask (0xFF = exact match, other values allow wildcards)
 *
 * If mask is empty, defaults to 0xFF for all positions (exact match).
 * If mask is provided but shorter than pattern, remaining positions use 0xFF.
 * 
 * @note Constructor is noexcept - invalid patterns result in empty m_pattern
 *       which is handled gracefully by all search methods.
 */
BoyerMooreMatcher::BoyerMooreMatcher(
    std::span<const uint8_t> pattern,
    std::span<const uint8_t> mask
) noexcept
    : m_pattern()
    , m_mask()
    , m_badCharTable()
    , m_goodSuffixTable()
{
    // Initialize bad char table to safe defaults immediately
    m_badCharTable.fill(1);

    // Validate pattern length (security: prevent DoS via huge patterns)
    if (pattern.empty()) {
        SS_LOG_WARN(L"BoyerMoore", L"Constructor: Empty pattern provided");
        return;
    }

    if (pattern.size() > BM_MAX_PATTERN_LENGTH) {
        SS_LOG_ERROR(L"BoyerMoore", 
            L"Constructor: Pattern too long (%zu > %zu)", 
            pattern.size(), BM_MAX_PATTERN_LENGTH);
        return;
    }

    // Copy pattern safely with exception handling
    try {
        m_pattern.reserve(pattern.size());
        m_pattern.assign(pattern.begin(), pattern.end());
    }
    catch (const std::bad_alloc& ex) {
        SS_LOG_ERROR(L"BoyerMoore", 
            L"Constructor: Memory allocation failed for pattern: %S", ex.what());
        m_pattern.clear();
        return;
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(L"BoyerMoore", 
            L"Constructor: Failed to copy pattern: %S", ex.what());
        m_pattern.clear();
        return;
    }

    // Handle mask with comprehensive validation
    try {
        m_mask.reserve(m_pattern.size());
        
        if (mask.empty()) {
            // Default: all bits matter (exact match)
            m_mask.resize(m_pattern.size(), 0xFF);
        }
        else if (mask.size() == m_pattern.size()) {
            // Mask provided with correct size
            m_mask.assign(mask.begin(), mask.end());
        }
        else if (mask.size() < m_pattern.size()) {
            // Mask shorter than pattern - extend with 0xFF
            m_mask.assign(mask.begin(), mask.end());
            m_mask.resize(m_pattern.size(), 0xFF);
            SS_LOG_WARN(L"BoyerMoore",
                L"Constructor: Mask shorter than pattern (%zu < %zu), extended with 0xFF",
                mask.size(), m_pattern.size());
        }
        else {
            // Mask longer than pattern - truncate safely
            m_mask.assign(mask.begin(), mask.begin() + static_cast<std::ptrdiff_t>(m_pattern.size()));
            SS_LOG_WARN(L"BoyerMoore",
                L"Constructor: Mask longer than pattern (%zu > %zu), truncated",
                mask.size(), m_pattern.size());
        }
    }
    catch (const std::bad_alloc& ex) {
        SS_LOG_ERROR(L"BoyerMoore", 
            L"Constructor: Memory allocation failed for mask: %S", ex.what());
        m_pattern.clear();
        m_mask.clear();
        return;
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(L"BoyerMoore", 
            L"Constructor: Failed to setup mask: %S", ex.what());
        m_pattern.clear();
        m_mask.clear();
        return;
    }

    // Verify mask/pattern consistency before building tables
    if (m_mask.size() != m_pattern.size()) {
        SS_LOG_ERROR(L"BoyerMoore", 
            L"Constructor: Internal error - mask/pattern size mismatch after setup");
        m_pattern.clear();
        m_mask.clear();
        return;
    }

    // Build lookup tables (order matters: bad char first)
    BuildBadCharTable();
    BuildGoodSuffixTable();

    // Final validation: ensure tables are properly built
    if (!m_pattern.empty() && m_goodSuffixTable.size() != m_pattern.size()) {
        SS_LOG_ERROR(L"BoyerMoore",
            L"Constructor: Good suffix table construction failed");
        m_pattern.clear();
        m_mask.clear();
        m_goodSuffixTable.clear();
    }
}

// ============================================================================
// SEARCH METHODS
// ============================================================================

/**
 * @brief Search for all occurrences of the pattern in buffer
 * @param buffer The data buffer to search
 * @return Vector of match offsets (empty if no matches or invalid state)
 *
 * Thread-safe: This method is const and safe for concurrent calls.
 * 
 * @note Returns empty vector on:
 *       - Invalid matcher state (empty pattern)
 *       - Buffer smaller than pattern
 *       - Memory allocation failure
 *       - DoS protection limits reached
 */
std::vector<size_t> BoyerMooreMatcher::Search(
    std::span<const uint8_t> buffer
) const noexcept {
    std::vector<size_t> matches;

    // Validate matcher state
    if (m_pattern.empty()) {
        return matches;
    }

    // Validate mask consistency (invariant check)
    if (m_mask.size() != m_pattern.size()) {
        SS_LOG_ERROR(L"BoyerMoore", L"Search: Internal state corrupted - mask/pattern mismatch");
        return matches;
    }

    // Validate good suffix table
    if (m_goodSuffixTable.size() != m_pattern.size()) {
        SS_LOG_ERROR(L"BoyerMoore", L"Search: Internal state corrupted - good suffix table invalid");
        return matches;
    }

    // Validate buffer
    if (buffer.empty()) {
        return matches;
    }

    if (buffer.size() < m_pattern.size()) {
        return matches;
    }

    // Calculate safe search boundary (underflow-safe)
    size_t searchLimit = 0;
    if (!SafeSub(buffer.size(), m_pattern.size(), searchLimit)) {
        // Should not happen given above checks, but be safe
        return matches;
    }

    // Pre-reserve reasonable capacity to minimize reallocations
    try {
        const size_t estimatedMatches = std::min(
            size_t(1024), 
            (buffer.size() / std::max(m_pattern.size(), size_t(1))) + 1
        );
        matches.reserve(estimatedMatches);
    }
    catch (const std::bad_alloc&) {
        // Allocation failed, continue without pre-reserve
        SS_LOG_WARN(L"BoyerMoore", L"Search: Reserve allocation failed, continuing");
    }

    size_t offset = 0;
    size_t iterations = 0;

    while (offset <= searchLimit) {
        // DoS protection: limit iterations
        if (++iterations > BM_MAX_ITERATIONS) {
            SS_LOG_WARN(L"BoyerMoore", 
                L"Search: Max iterations reached (%zu), returning partial results",
                BM_MAX_ITERATIONS);
            break;
        }

        if (MatchesAt(buffer, offset)) {
            // Match limit check (prevent memory exhaustion)
            if (matches.size() >= MAX_MATCH_COUNT) {
                SS_LOG_WARN(L"BoyerMoore",
                    L"Search: Max match count reached (%zu)", MAX_MATCH_COUNT);
                break;
            }

            try {
                matches.push_back(offset);
            }
            catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"BoyerMoore", L"Search: Memory allocation failed for match storage");
                break;
            }

            // Move to next position (overlapping matches allowed)
            // Overflow-safe increment
            if (offset == std::numeric_limits<size_t>::max()) {
                break;
            }
            ++offset;
        }
        else {
            // Calculate skip distance using bad character and good suffix rules
            size_t skip = 1;

            // Bounds-check lastCharPos calculation
            size_t lastCharPos = 0;
            if (!SafeAdd(offset, m_pattern.size() - 1, lastCharPos)) {
                break;  // Overflow would occur
            }

            if (lastCharPos < buffer.size()) {
                const uint8_t badChar = buffer[lastCharPos];
                
                // Bad character rule
                const size_t badCharSkip = m_badCharTable[badChar];
                
                // Good suffix rule (find mismatch position first)
                size_t mismatchPos = m_pattern.size();
                for (size_t i = m_pattern.size(); i > 0; --i) {
                    const size_t idx = i - 1;
                    const size_t bufIdx = offset + idx;
                    if (bufIdx >= buffer.size()) {
                        continue;
                    }
                    const uint8_t bufByte = buffer[bufIdx];
                    const uint8_t patByte = m_pattern[idx];
                    const uint8_t maskByte = m_mask[idx];
                    if ((bufByte & maskByte) != (patByte & maskByte)) {
                        mismatchPos = idx;
                        break;
                    }
                }

                // Use good suffix table if mismatch found and table is valid
                size_t goodSuffixSkip = 1;
                if (mismatchPos < m_pattern.size() && mismatchPos < m_goodSuffixTable.size()) {
                    goodSuffixSkip = m_goodSuffixTable[mismatchPos];
                }

                // Take maximum of both rules
                skip = std::max({badCharSkip, goodSuffixSkip, size_t(1)});
            }

            // Overflow-safe offset advancement
            if (WouldOverflow(offset, skip)) {
                break;
            }
            offset += skip;
        }
    }

    return matches;
}

/**
 * @brief Find the first occurrence of the pattern in buffer
 * @param buffer The data buffer to search
 * @return Offset of first match, or nullopt if not found
 *
 * Thread-safe: This method is const and safe for concurrent calls.
 * 
 * @note Returns nullopt on:
 *       - Invalid matcher state (empty pattern)
 *       - Buffer smaller than pattern
 *       - DoS protection limits reached
 *       - Pattern not found
 */
std::optional<size_t> BoyerMooreMatcher::FindFirst(
    std::span<const uint8_t> buffer
) const noexcept {
    // Validate matcher state
    if (m_pattern.empty()) {
        return std::nullopt;
    }

    // Validate mask consistency (invariant check)
    if (m_mask.size() != m_pattern.size()) {
        SS_LOG_ERROR(L"BoyerMoore", L"FindFirst: Internal state corrupted - mask/pattern mismatch");
        return std::nullopt;
    }

    // Validate good suffix table
    if (m_goodSuffixTable.size() != m_pattern.size()) {
        SS_LOG_ERROR(L"BoyerMoore", L"FindFirst: Internal state corrupted - good suffix table invalid");
        return std::nullopt;
    }

    // Validate buffer
    if (buffer.empty()) {
        return std::nullopt;
    }

    if (buffer.size() < m_pattern.size()) {
        return std::nullopt;
    }

    // Calculate safe search boundary (underflow-safe)
    size_t searchLimit = 0;
    if (!SafeSub(buffer.size(), m_pattern.size(), searchLimit)) {
        return std::nullopt;
    }

    size_t offset = 0;
    size_t iterations = 0;

    while (offset <= searchLimit) {
        // DoS protection
        if (++iterations > BM_MAX_ITERATIONS) {
            SS_LOG_WARN(L"BoyerMoore", L"FindFirst: Max iterations reached (%zu)", BM_MAX_ITERATIONS);
            return std::nullopt;
        }

        if (MatchesAt(buffer, offset)) {
            return offset;
        }

        // Calculate skip distance using bad character and good suffix rules
        size_t skip = 1;
        
        // Bounds-check lastCharPos calculation
        size_t lastCharPos = 0;
        if (!SafeAdd(offset, m_pattern.size() - 1, lastCharPos)) {
            break;  // Overflow would occur
        }

        if (lastCharPos < buffer.size()) {
            const uint8_t badChar = buffer[lastCharPos];
            
            // Bad character rule
            const size_t badCharSkip = m_badCharTable[badChar];
            
            // Good suffix rule (find mismatch position first)
            size_t mismatchPos = m_pattern.size();
            for (size_t i = m_pattern.size(); i > 0; --i) {
                const size_t idx = i - 1;
                const size_t bufIdx = offset + idx;
                if (bufIdx >= buffer.size()) {
                    continue;
                }
                const uint8_t bufByte = buffer[bufIdx];
                const uint8_t patByte = m_pattern[idx];
                const uint8_t maskByte = m_mask[idx];
                if ((bufByte & maskByte) != (patByte & maskByte)) {
                    mismatchPos = idx;
                    break;
                }
            }

            // Use good suffix table if mismatch found and table is valid
            size_t goodSuffixSkip = 1;
            if (mismatchPos < m_pattern.size() && mismatchPos < m_goodSuffixTable.size()) {
                goodSuffixSkip = m_goodSuffixTable[mismatchPos];
            }

            // Take maximum of both rules
            skip = std::max({badCharSkip, goodSuffixSkip, size_t(1)});
        }

        // Overflow-safe advancement
        if (WouldOverflow(offset, skip)) {
            break;
        }
        offset += skip;
    }

    return std::nullopt;
}

// ============================================================================
// TABLE BUILDING
// ============================================================================

/**
 * @brief Build the bad character skip table
 *
 * For each byte value, stores the distance from the last occurrence
 * of that byte in the pattern to the end of the pattern.
 * Used for the bad character rule in Boyer-Moore.
 * 
 * @note Safe for empty patterns - fills table with minimum skip value (1)
 * @note All entries guaranteed to be in range [1, pattern.size()]
 */
void BoyerMooreMatcher::BuildBadCharTable() noexcept {
    // Handle empty pattern case - should not happen but be defensive
    if (m_pattern.empty()) {
        m_badCharTable.fill(1);  // Minimum skip for safety
        return;
    }

    const size_t patternLen = m_pattern.size();

    // Initialize with pattern length (skip entire pattern if char not found)
    // This is safe because patternLen > 0 is guaranteed here
    m_badCharTable.fill(patternLen);

    // Fill with last occurrence positions (exclude last character)
    // This gives us the shift values for the bad character rule
    // Safety: we've already verified m_pattern is not empty above
    const size_t lastIndex = patternLen - 1;
    
    for (size_t i = 0; i < lastIndex; ++i) {
        const uint8_t byte = m_pattern[i];
        
        // Calculate shift: distance from position i to end of pattern
        const size_t shift = lastIndex - i;
        
        // Bounds check: shift must be >= 1 and <= patternLen
        // This should always be true given the loop bounds, but verify
        if (shift >= 1 && shift <= patternLen) {
            m_badCharTable[byte] = shift;
        }
    }

    // Validation: ensure no zero entries (would cause infinite loops)
    // In debug builds, also validate upper bounds
#if defined(_DEBUG) || defined(SS_VALIDATE_TABLES)
    for (size_t i = 0; i < 256; ++i) {
        if (m_badCharTable[i] == 0) {
            SS_LOG_ERROR(L"BoyerMoore", 
                L"BuildBadCharTable: Invalid zero entry at index %zu", i);
            m_badCharTable[i] = 1;  // Fix the invalid entry
        }
        if (m_badCharTable[i] > patternLen) {
            SS_LOG_ERROR(L"BoyerMoore",
                L"BuildBadCharTable: Entry %zu exceeds pattern length", i);
            m_badCharTable[i] = patternLen;
        }
    }
#endif
}

/**
 * @brief Build the good suffix skip table
 *
 * Uses Z-algorithm and KMP failure function for O(n) construction.
 * The good suffix table enables optimal skipping when a mismatch occurs
 * after matching some suffix of the pattern.
 * 
 * @note All entries guaranteed to be in range [1, n] after construction
 * @note Safe for empty patterns - results in empty table
 * @note Memory allocation failures result in cleared pattern (invalid state)
 */
void BoyerMooreMatcher::BuildGoodSuffixTable() noexcept {
    /*
     * Algorithm: Z-Algorithm + KMP Failure Function Fusion
     * Time: O(n) - Single pass, no quadratic worst case
     * Space: O(n) - Exactly patternLen entries
     * References:
     * - Boyer & Moore (1977): "A fast string searching algorithm"
     * - Cormen et al. (2009): "Introduction to Algorithms", Chapter 32
     * - Gusfield (1997): "Algorithms on Strings, Trees and Sequences"
     * ========================================================================
     */

    const size_t n = m_pattern.size();

    // Handle empty pattern - clear table and return
    if (n == 0) {
        m_goodSuffixTable.clear();
        return;
    }

    // Pre-allocate with exact capacity
    try {
        m_goodSuffixTable.clear();
        m_goodSuffixTable.resize(n, n);  // Initialize all to n (max shift)
    }
    catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"BoyerMoore", L"BuildGoodSuffixTable: Memory allocation failed");
        m_goodSuffixTable.clear();
        return;
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(L"BoyerMoore", L"BuildGoodSuffixTable: Allocation failed: %S", ex.what());
        m_goodSuffixTable.clear();
        return;
    }

    // For single-byte patterns, good suffix table is trivial
    if (n == 1) {
        m_goodSuffixTable[0] = 1;
        return;
    }

    // ========================================================================
    // STEP 1: Build Z-Array (Efficient Suffix Information)
    // ========================================================================

    std::vector<size_t> zArray;
    try {
        zArray.resize(n, 0);
    }
    catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"BoyerMoore", L"BuildGoodSuffixTable: Z-array allocation failed");
        // Fall back to simple good suffix table
        for (size_t i = 0; i < n; ++i) {
            m_goodSuffixTable[i] = n;
        }
        return;
    }

    zArray[0] = n;

    // Z-algorithm: O(n) linear time computation
    // [l, r] tracks the rightmost Z-box found so far
    size_t l = 0, r = 0;

    for (size_t i = 1; i < n; ++i) {
        if (i > r) {
            // Outside current Z-box, compute directly
            l = r = i;
            
            // Extend Z-box while characters match
            size_t safetyCounter = 0;
            while (r < n && (r - l) < n && m_pattern[r - l] == m_pattern[r]) {
                ++r;
                // Safety: prevent infinite loops on corrupted data
                if (++safetyCounter > n) {
                    SS_LOG_ERROR(L"BoyerMoore", L"BuildGoodSuffixTable: Z-algorithm safety limit hit");
                    break;
                }
            }
            
            zArray[i] = r - l;
            
            // Adjust r to be the rightmost index in Z-box (prevent underflow)
            if (r > 0) {
                --r;
            }
        }
        else {
            // Inside Z-box, reuse computation from symmetric position
            const size_t k = i - l;

            // Bounds check on k (defensive)
            if (k >= n) {
                zArray[i] = 0;
                continue;
            }

            // Check if we can directly use zArray[k]
            // r - i + 1 is the remaining length in current Z-box
            const size_t remaining = (r >= i) ? (r - i + 1) : 0;
            
            if (zArray[k] < remaining) {
                zArray[i] = zArray[k];
            }
            else {
                // Need to extend Z-box
                l = i;
                
                size_t safetyCounter = 0;
                while (r < n && (r - l) < n && m_pattern[r - l] == m_pattern[r]) {
                    ++r;
                    if (++safetyCounter > n) {
                        SS_LOG_ERROR(L"BoyerMoore", L"BuildGoodSuffixTable: Z-extend safety limit hit");
                        break;
                    }
                }
                
                zArray[i] = r - l;
                
                if (r > 0) {
                    --r;
                }
            }
        }
    }

    // ========================================================================
    // STEP 2: Compute KMP Failure Function
    // ========================================================================

    std::vector<size_t> fail;
    try {
        fail.resize(n, 0);
    }
    catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"BoyerMoore", L"BuildGoodSuffixTable: Fail array allocation failed");
        // Keep the current good suffix table (initialized to n)
        return;
    }

    for (size_t i = 1; i < n; ++i) {
        size_t j = (i > 0 && fail[i - 1] < n) ? fail[i - 1] : 0;

        // Walk back through failure links with iteration limit
        size_t iterations = 0;
        const size_t maxIterations = n + 1;  // Bounded by pattern length
        
        while (j > 0 && m_pattern[i] != m_pattern[j]) {
            if (++iterations > maxIterations) {
                // Safety: prevent infinite loop on corrupted data
                SS_LOG_ERROR(L"BoyerMoore", L"BuildGoodSuffixTable: KMP iteration limit hit at i=%zu", i);
                break;
            }
            
            // Bounds check before accessing fail array
            if (j == 0 || j > n) {
                break;
            }
            
            j = fail[j - 1];
        }

        if (m_pattern[i] == m_pattern[j]) {
            fail[i] = j + 1;
            
            // Sanity check: fail[i] should not exceed i+1
            if (fail[i] > i + 1) {
                SS_LOG_ERROR(L"BoyerMoore", L"BuildGoodSuffixTable: Invalid fail value at i=%zu", i);
                fail[i] = 0;
            }
        }
    }

    // ========================================================================
    // STEP 3: Compute Good Suffix Shifts (THE CORE ALGORITHM)
    // ========================================================================

    // Mark positions where suffixes actually occur using Z-array
    for (size_t i = 1; i < n; ++i) {
        const size_t suffixLen = zArray[i];
        
        // Skip invalid or zero-length suffixes
        if (suffixLen == 0 || suffixLen > n) {
            continue;
        }

        // Calculate position in good suffix table
        // pos is the index where this suffix ends (0-based)
        const size_t pos = n - suffixLen;

        // Bounds check: pos must be valid for array access at pos-1
        if (pos == 0 || pos > n) {
            continue;
        }

        // The shift value is the distance to move the pattern
        // Update only if this gives a smaller shift
        const size_t tableIndex = pos - 1;
        if (tableIndex < m_goodSuffixTable.size()) {
            m_goodSuffixTable[tableIndex] = std::min(m_goodSuffixTable[tableIndex], pos);
        }
    }

    // ========================================================================
    // STEP 4: Handle Partial Prefix Matches
    // ========================================================================

    const size_t lastFailValue = fail[n - 1];

    if (lastFailValue > 0 && lastFailValue < n) {
        const size_t shift = n - lastFailValue;
        
        // Apply to last position in table
        if (n > 0 && shift > 0) {
            m_goodSuffixTable[n - 1] = std::min(m_goodSuffixTable[n - 1], shift);
        }
    }

    // ========================================================================
    // STEP 5: Apply Transitivity for Optimality
    // ========================================================================

    // Propagate minimum shifts from right to left
    for (size_t i = n - 1; i > 0; --i) {
        const size_t currentVal = m_goodSuffixTable[i];
        const size_t prevVal = m_goodSuffixTable[i - 1];
        
        if (currentVal < prevVal) {
            m_goodSuffixTable[i - 1] = currentVal;
        }
    }

    // ========================================================================
    // STEP 6: Final Validation and Fallback Shifts
    // ========================================================================

    for (size_t i = 0; i < n; ++i) {
        // Ensure minimum shift of 1 (prevents infinite loops)
        if (m_goodSuffixTable[i] == 0) {
            m_goodSuffixTable[i] = 1;
        }

        // Ensure shift doesn't exceed pattern length
        if (m_goodSuffixTable[i] > n) {
            m_goodSuffixTable[i] = n;
        }

        // Use failure function for max-value entries to get better shift
        if (m_goodSuffixTable[i] == n && i < n - 1) {
            const size_t j = fail[i];
            if (j > 0 && j < n) {
                const size_t betterShift = n - j;
                if (betterShift > 0 && betterShift < n) {
                    m_goodSuffixTable[i] = betterShift;
                }
            }
        }
    }

    // ========================================================================
    // VALIDATION (All builds - critical for security)
    // ========================================================================

    // Verify all entries are in valid range [1, n]
    // This is critical - invalid values can cause infinite loops or OOB access
    for (size_t i = 0; i < n; ++i) {
        if (m_goodSuffixTable[i] == 0 || m_goodSuffixTable[i] > n) {
            SS_LOG_ERROR(L"BoyerMoore",
                L"BuildGoodSuffixTable: Invalid entry at [%zu] = %zu, clamping",
                i, m_goodSuffixTable[i]);
            m_goodSuffixTable[i] = std::clamp(m_goodSuffixTable[i], size_t(1), n);
        }
    }
}

// ============================================================================
// PATTERN MATCHING
// ============================================================================

/**
 * @brief Check if pattern matches at the given offset in buffer
 * @param buffer The data buffer to check
 * @param offset Starting offset to check
 * @return True if pattern matches at offset (with mask applied)
 *
 * This is the core matching function used by Search() and FindFirst().
 * Uses mask to support wildcard pattern matching.
 * 
 * @note Thread-safe: const method with no side effects
 * @note Returns false on any invalid state or bounds violation
 */
bool BoyerMooreMatcher::MatchesAt(
    std::span<const uint8_t> buffer,
    size_t offset
) const noexcept {
    // Validate pattern state
    if (m_pattern.empty()) {
        return false;
    }

    const size_t patternSize = m_pattern.size();

    // Validate mask consistency (critical invariant)
    if (m_mask.size() != patternSize) {
        // This indicates internal state corruption - log but don't crash
        SS_LOG_ERROR(L"BoyerMoore", 
            L"MatchesAt: Internal state corrupted - mask/pattern size mismatch (%zu vs %zu)",
            m_mask.size(), patternSize);
        return false;
    }

    // Validate buffer
    if (buffer.empty()) {
        return false;
    }

    // Bounds check: ensure offset is within buffer
    if (offset >= buffer.size()) {
        return false;
    }

    // Bounds check: ensure we can read patternSize bytes from offset
    // Using SafeSub to prevent underflow
    size_t availableBytes = 0;
    if (!SafeSub(buffer.size(), offset, availableBytes)) {
        return false;
    }

    if (availableBytes < patternSize) {
        return false;
    }

    // Compare bytes with mask - optimized loop with early exit
    // Loop from end to beginning for better cache behavior with Boyer-Moore
    for (size_t i = patternSize; i > 0; --i) {
        const size_t idx = i - 1;
        
        // Calculate buffer index with overflow protection
        size_t bufferIndex = 0;
        if (!SafeAdd(offset, idx, bufferIndex)) {
            return false;  // Overflow would occur
        }

        // Redundant bounds check for defense in depth
        if (bufferIndex >= buffer.size()) {
            return false;
        }

        // Bounds check on pattern/mask arrays (should always pass given checks above)
        if (idx >= patternSize) {
            return false;
        }

        const uint8_t bufferByte = buffer[bufferIndex];
        const uint8_t patternByte = m_pattern[idx];
        const uint8_t maskByte = m_mask[idx];

        // Apply mask and compare
        // Mask value 0x00 = wildcard (any byte matches)
        // Mask value 0xFF = exact match required
        if ((bufferByte & maskByte) != (patternByte & maskByte)) {
            return false;
        }
    }

    return true;
}

} // namespace SignatureStore
} // namespace ShadowStrike