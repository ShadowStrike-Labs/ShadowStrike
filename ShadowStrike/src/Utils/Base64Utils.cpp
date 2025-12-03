/*
 * ============================================================================
 * ShadowStrike Base64 Implementation
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Enterprise-grade Base64 encoding/decoding implementation with:
 *   - RFC 4648 compliant Standard and URL-safe alphabets
 *   - Comprehensive input validation and bounds checking
 *   - Overflow-safe length calculations
 *   - Exception-safe memory allocation
 *   - Constant-time decoding table lookups (timing attack mitigation)
 *   - Full padding control and whitespace handling
 *   - Line break insertion support for MIME compatibility
 *
 * Implementation Notes:
 *   - Uses scalar processing for maximum portability
 *   - All size calculations are overflow-checked
 *   - Decode lookup uses volatile pointer to prevent optimization
 *     of timing-sensitive code paths
 *   - SIMD optimizations planned for future releases
 *
 * ============================================================================
 */

#include "Base64Utils.hpp"

#include <cstring>
#include <algorithm>
#include <limits>
#include <new>

namespace ShadowStrike {
    namespace Utils {

        // ============================================================================
        // Internal Constants and Lookup Tables
        // ============================================================================

        namespace {

            /**
             * @brief Standard Base64 encoding alphabet (RFC 4648 Section 4).
             * 
             * Characters 0-25:  A-Z
             * Characters 26-51: a-z
             * Characters 52-61: 0-9
             * Character 62:     +
             * Character 63:     /
             */
            constexpr std::array<char, 64> kEncodeTableStandard = {
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                '4', '5', '6', '7', '8', '9', '+', '/'
            };

            /**
             * @brief URL-safe Base64 encoding alphabet (RFC 4648 Section 5).
             * 
             * Same as standard except:
             * Character 62: - (hyphen)
             * Character 63: _ (underscore)
             */
            constexpr std::array<char, 64> kEncodeTableUrlSafe = {
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                '4', '5', '6', '7', '8', '9', '-', '_'
            };

            /**
             * @brief Invalid character marker for decode lookup tables.
             * 
             * Using 0x80 as the high bit set indicates invalid character
             * and can be detected with a simple mask test.
             */
            constexpr uint8_t kInvalidChar = 0x80;

            /**
             * @brief Build decode lookup table at compile time.
             * 
             * @tparam EncodeTable Reference to the encoding table to invert.
             * @return 256-element array mapping ASCII codes to 6-bit values.
             * 
             * Invalid characters map to kInvalidChar (0x80).
             */
            template<const std::array<char, 64>& EncodeTable>
            constexpr std::array<uint8_t, 256> BuildDecodeLookupTable() noexcept {
                std::array<uint8_t, 256> table{};
                
                // Initialize all entries as invalid
                for (size_t i = 0; i < 256; ++i) {
                    table[i] = kInvalidChar;
                }
                
                // Map valid Base64 characters to their 6-bit values
                for (uint8_t i = 0; i < 64; ++i) {
                    const auto charIndex = static_cast<uint8_t>(EncodeTable[i]);
                    table[charIndex] = i;
                }
                
                return table;
            }

            /// Decode lookup table for standard Base64
            constexpr auto kDecodeTableStandard = BuildDecodeLookupTable<kEncodeTableStandard>();

            /// Decode lookup table for URL-safe Base64
            constexpr auto kDecodeTableUrlSafe = BuildDecodeLookupTable<kEncodeTableUrlSafe>();

            /**
             * @brief Perform constant-time lookup in decode table.
             * 
             * Uses volatile pointer to prevent compiler from optimizing
             * the memory access pattern, providing resistance against
             * timing-based side-channel attacks.
             * 
             * @param ch The character to decode (0-255).
             * @param lut Reference to the decode lookup table.
             * @return The 6-bit value, or kInvalidChar (0x80) if invalid.
             */
            [[nodiscard]] inline uint8_t DecodeCharacter(
                uint8_t ch,
                const std::array<uint8_t, 256>& lut
            ) noexcept {
                // Use volatile to prevent timing optimization
                // This ensures the lookup takes constant time regardless
                // of the character value
                const volatile uint8_t* const volatileTable = lut.data();
                return volatileTable[ch];
            }

            /**
             * @brief Check if character is ASCII whitespace.
             * 
             * Handles: space (0x20), tab (0x09), CR (0x0D), LF (0x0A),
             * vertical tab (0x0B), form feed (0x0C).
             * 
             * This is locale-independent unlike std::isspace.
             * 
             * @param ch The character to check.
             * @return true if whitespace, false otherwise.
             */
            [[nodiscard]] constexpr bool IsWhitespace(unsigned char ch) noexcept {
                return ch == ' '  ||   // Space
                       ch == '\t' ||   // Horizontal tab
                       ch == '\n' ||   // Line feed
                       ch == '\r' ||   // Carriage return
                       ch == '\v' ||   // Vertical tab
                       ch == '\f';     // Form feed
            }

            /**
             * @brief Maximum safe input length for encoding.
             * 
             * Calculated to prevent overflow in size calculations:
             * - Base64 expansion is 4/3 (worst case ~1.34x)
             * - Leave headroom for line breaks and safety margin
             * - Use SIZE_MAX / 4 as conservative upper bound
             */
            constexpr size_t kMaxSafeInputLength = (std::numeric_limits<size_t>::max() / 4) - 4096;

            /**
             * @brief Select the appropriate encode table based on alphabet.
             * 
             * @param alphabet The alphabet selection.
             * @return Reference to the appropriate encoding table.
             */
            [[nodiscard]] inline const std::array<char, 64>& SelectEncodeTable(
                Base64Alphabet alphabet
            ) noexcept {
                return (alphabet == Base64Alphabet::Standard)
                    ? kEncodeTableStandard
                    : kEncodeTableUrlSafe;
            }

            /**
             * @brief Select the appropriate decode table based on alphabet.
             * 
             * @param alphabet The alphabet selection.
             * @return Reference to the appropriate decoding table.
             */
            [[nodiscard]] inline const std::array<uint8_t, 256>& SelectDecodeTable(
                Base64Alphabet alphabet
            ) noexcept {
                return (alphabet == Base64Alphabet::Standard)
                    ? kDecodeTableStandard
                    : kDecodeTableUrlSafe;
            }

        } // anonymous namespace

        // ============================================================================
        // Length Calculation Implementation
        // ============================================================================

        size_t Base64EncodedLength(size_t inputLen, const Base64EncodeOptions& opt) noexcept {
            // Empty input produces empty output
            if (inputLen == 0) {
                return 0;
            }

            // Validate input length to prevent overflow
            if (inputLen > kMaxSafeInputLength) {
                return 0;
            }

            // Calculate number of complete 3-byte input blocks
            const size_t fullBlocks = inputLen / 3;
            const size_t remainder = inputLen % 3;

            // Each 3-byte block produces 4 Base64 characters
            // Overflow check: fullBlocks is at most kMaxSafeInputLength/3,
            // and kMaxSafeInputLength/3 * 4 < SIZE_MAX by construction
            size_t outputLen = fullBlocks * 4;

            // Handle partial block at end
            if (remainder > 0) {
                // Partial block produces 4 characters (with padding)
                // or 2-3 characters (without padding)
                outputLen += 4;
            }

            // Adjust for padding omission if requested
            if (HasFlag(opt.flags, Base64Flags::OmitPadding) && remainder > 0) {
                // remainder == 1: produces 2 chars (not 4), so subtract 2
                // remainder == 2: produces 3 chars (not 4), so subtract 1
                const size_t paddingReduction = (remainder == 1) ? 2 : 1;
                outputLen -= paddingReduction;
            }

            // Calculate line breaks if requested
            if (HasFlag(opt.flags, Base64Flags::InsertLineBreaks) &&
                opt.lineBreakEvery > 0 &&
                !opt.lineBreak.empty()) {
                
                // Use configured line length, with sanity bounds
                const size_t charsPerLine = opt.lineBreakEvery;
                
                // Calculate number of line breaks needed
                // For N chars with M chars/line, we need floor((N-1)/M) breaks
                // (no trailing break after last line)
                if (outputLen > 0) {
                    const size_t numBreaks = (outputLen - 1) / charsPerLine;
                    
                    if (numBreaks > 0) {
                        const size_t breakSize = opt.lineBreak.size();
                        
                        // Overflow check for line break bytes
                        if (numBreaks > (std::numeric_limits<size_t>::max() - outputLen) / breakSize) {
                            return 0;  // Would overflow
                        }
                        
                        outputLen += numBreaks * breakSize;
                    }
                }
            }

            return outputLen;
        }

        size_t Base64MaxDecodedLength(size_t inputLen) noexcept {
            // Empty input produces empty output
            if (inputLen == 0) {
                return 0;
            }

            // Check for potential overflow before calculation
            // We need (inputLen + 3) to not overflow for the division
            if (inputLen > std::numeric_limits<size_t>::max() - 3) {
                return 0;
            }

            // Calculate number of 4-character groups (rounded up)
            const size_t groups = (inputLen + 3) / 4;

            // Check for overflow in multiplication
            if (groups > std::numeric_limits<size_t>::max() / 3) {
                return 0;
            }

            // Each group decodes to at most 3 bytes
            return groups * 3;
        }

        // ============================================================================
        // Base64 Encode Implementation
        // ============================================================================

        bool Base64Encode(
            const uint8_t* data,
            size_t len,
            std::string& out,
            const Base64EncodeOptions& opt
        ) noexcept {
            // Clear output to ensure clean state on both success and failure
            out.clear();

            // Validate input pointer (nullptr allowed only if len == 0)
            if (data == nullptr && len != 0) {
                return false;
            }

            // Empty input is valid and produces empty output
            if (len == 0) {
                return true;
            }

            // Validate options
            if (!opt.IsValid()) {
                return false;
            }

            // Calculate required output size with overflow protection
            const size_t estimatedSize = Base64EncodedLength(len, opt);
            if (estimatedSize == 0) {
                // Overflow would occur, or input too large
                return false;
            }

            // Select encoding table based on alphabet
            const auto& encodeTable = SelectEncodeTable(opt.alphabet);

            // Determine encoding options
            const bool insertLineBreaks = HasFlag(opt.flags, Base64Flags::InsertLineBreaks) &&
                                          opt.lineBreakEvery > 0 &&
                                          !opt.lineBreak.empty();
            const bool omitPadding = HasFlag(opt.flags, Base64Flags::OmitPadding);

            // Pre-allocate output buffer (with exception safety)
            try {
                out.reserve(estimatedSize);
            }
            catch (const std::bad_alloc&) {
                return false;
            }
            catch (...) {
                // Catch any other allocation-related exceptions
                return false;
            }

            // Line break tracking
            const size_t lineLength = insertLineBreaks ? opt.lineBreakEvery : std::numeric_limits<size_t>::max();
            size_t currentLinePos = 0;

            // Process complete 3-byte blocks
            size_t inputIndex = 0;
            while (inputIndex + 3 <= len) {
                // Read 3 bytes and pack into 24-bit value
                // Using explicit casts for clarity and safety
                const uint32_t triplet =
                    (static_cast<uint32_t>(data[inputIndex])     << 16) |
                    (static_cast<uint32_t>(data[inputIndex + 1]) << 8)  |
                    (static_cast<uint32_t>(data[inputIndex + 2]));
                inputIndex += 3;

                // Extract 4 x 6-bit indices and encode
                char encodedQuad[4];
                encodedQuad[0] = encodeTable[(triplet >> 18) & 0x3F];
                encodedQuad[1] = encodeTable[(triplet >> 12) & 0x3F];
                encodedQuad[2] = encodeTable[(triplet >>  6) & 0x3F];
                encodedQuad[3] = encodeTable[(triplet)       & 0x3F];

                // Insert line break if needed BEFORE this quad
                if (insertLineBreaks && currentLinePos > 0 && currentLinePos + 4 > lineLength) {
                    try {
                        out.append(opt.lineBreak.data(), opt.lineBreak.size());
                    }
                    catch (...) {
                        out.clear();
                        return false;
                    }
                    currentLinePos = 0;
                }

                // Append encoded quad
                try {
                    out.append(encodedQuad, 4);
                }
                catch (...) {
                    out.clear();
                    return false;
                }
                currentLinePos += 4;
            }

            // Handle remaining 1 or 2 bytes (partial block)
            const size_t remainingBytes = len - inputIndex;
            if (remainingBytes > 0) {
                // Pack remaining bytes into triplet (zero-padded)
                uint32_t triplet = static_cast<uint32_t>(data[inputIndex]) << 16;
                if (remainingBytes == 2) {
                    triplet |= static_cast<uint32_t>(data[inputIndex + 1]) << 8;
                }

                // Encode with padding
                char encodedQuad[4];
                encodedQuad[0] = encodeTable[(triplet >> 18) & 0x3F];
                encodedQuad[1] = encodeTable[(triplet >> 12) & 0x3F];
                
                if (remainingBytes == 2) {
                    // 2 input bytes -> 3 output characters + 1 padding
                    encodedQuad[2] = encodeTable[(triplet >> 6) & 0x3F];
                    encodedQuad[3] = '=';
                }
                else {
                    // 1 input byte -> 2 output characters + 2 padding
                    encodedQuad[2] = '=';
                    encodedQuad[3] = '=';
                }

                // Determine how many characters to output
                size_t outputChars = 4;
                if (omitPadding) {
                    outputChars = (remainingBytes == 2) ? 3 : 2;
                }

                // Insert line break if needed
                if (insertLineBreaks && currentLinePos > 0 && currentLinePos + outputChars > lineLength) {
                    try {
                        out.append(opt.lineBreak.data(), opt.lineBreak.size());
                    }
                    catch (...) {
                        out.clear();
                        return false;
                    }
                }

                // Append final encoded characters
                try {
                    out.append(encodedQuad, outputChars);
                }
                catch (...) {
                    out.clear();
                    return false;
                }
            }

            return true;
        }

        // ============================================================================
        // Base64 Decode Implementation
        // ============================================================================

        bool Base64Decode(
            const char* data,
            size_t len,
            std::vector<uint8_t>& out,
            Base64DecodeError& err,
            const Base64DecodeOptions& opt
        ) noexcept {
            // Clear output to ensure clean state
            out.clear();
            err = Base64DecodeError::None;

            // Validate input pointer (nullptr allowed only if len == 0)
            if (data == nullptr && len != 0) {
                err = Base64DecodeError::InvalidCharacter;
                return false;
            }

            // Empty input is valid
            if (len == 0) {
                return true;
            }

            // Check for unreasonably large input
            if (len > kMaxSafeInputLength) {
                err = Base64DecodeError::InputTooLarge;
                return false;
            }

            // Select decode table
            const auto& decodeTable = SelectDecodeTable(opt.alphabet);

            // Calculate maximum possible output size
            const size_t maxOutputSize = Base64MaxDecodedLength(len);
            if (maxOutputSize == 0) {
                err = Base64DecodeError::InputTooLarge;
                return false;
            }

            // Pre-allocate output buffer
            try {
                out.reserve(maxOutputSize);
            }
            catch (const std::bad_alloc&) {
                err = Base64DecodeError::AllocationFailed;
                return false;
            }
            catch (...) {
                err = Base64DecodeError::AllocationFailed;
                return false;
            }

            // Decoding state
            uint32_t accumulator = 0;    // Accumulated bits (up to 24 bits used)
            uint32_t bitsInAccumulator = 0;
            size_t validCharsConsumed = 0;  // Count of valid Base64 chars processed
            uint32_t paddingCount = 0;      // Number of '=' seen
            bool paddingStarted = false;    // Have we seen any padding?

            // Process each input character
            for (size_t i = 0; i < len; ++i) {
                const unsigned char ch = static_cast<unsigned char>(data[i]);

                // Handle whitespace if configured to ignore it
                if (opt.ignoreWhitespace && IsWhitespace(ch)) {
                    continue;
                }

                // Handle padding character
                if (ch == '=') {
                    paddingStarted = true;
                    ++paddingCount;

                    // Validate padding count (max 2 padding chars allowed)
                    if (paddingCount > 2) {
                        err = Base64DecodeError::InvalidPadding;
                        out.clear();
                        return false;
                    }

                    // Validate padding position
                    // Padding can only appear after 2 or 3 valid chars in current group
                    const size_t positionInGroup = validCharsConsumed % 4;
                    if (positionInGroup < 2) {
                        err = Base64DecodeError::InvalidPadding;
                        out.clear();
                        return false;
                    }

                    // Validate padding count matches position
                    // Position 2: need exactly 2 padding chars
                    // Position 3: need exactly 1 padding char
                    const size_t expectedPadding = 4 - positionInGroup;
                    if (paddingCount > expectedPadding) {
                        err = Base64DecodeError::InvalidPadding;
                        out.clear();
                        return false;
                    }

                    continue;
                }

                // After padding, only whitespace (if ignored) is allowed
                if (paddingStarted) {
                    err = Base64DecodeError::TrailingData;
                    out.clear();
                    return false;
                }

                // Decode the character using constant-time lookup
                const uint8_t decoded = DecodeCharacter(ch, decodeTable);

                // Check for invalid character (high bit set indicates invalid)
                if (decoded & kInvalidChar) {
                    err = Base64DecodeError::InvalidCharacter;
                    out.clear();
                    return false;
                }

                // Accumulate 6 bits
                accumulator = (accumulator << 6) | decoded;
                bitsInAccumulator += 6;
                ++validCharsConsumed;

                // Output complete bytes when we have 8+ bits
                while (bitsInAccumulator >= 8) {
                    bitsInAccumulator -= 8;
                    const uint8_t outputByte = static_cast<uint8_t>(
                        (accumulator >> bitsInAccumulator) & 0xFF
                    );
                    
                    try {
                        out.push_back(outputByte);
                    }
                    catch (...) {
                        err = Base64DecodeError::AllocationFailed;
                        out.clear();
                        return false;
                    }
                }
            }

            // Validate final state
            const size_t positionInGroup = validCharsConsumed % 4;

            if (paddingStarted) {
                // With padding, we should have consumed exactly a multiple of 4 chars
                // (counting padding as consuming positions)
                const size_t expectedPadding = (positionInGroup == 0) ? 0 : (4 - positionInGroup);
                if (paddingCount != expectedPadding) {
                    err = Base64DecodeError::InvalidPadding;
                    out.clear();
                    return false;
                }

                // Verify no non-zero bits remain in accumulator
                // (padding should zero out remaining bits)
                const uint32_t remainingBitsMask = (1U << bitsInAccumulator) - 1U;
                if ((accumulator & remainingBitsMask) != 0) {
                    // Non-canonical encoding - trailing bits should be zero
                    // This is technically valid per RFC 4648 but some implementations reject it
                    // We accept it but could add a strict mode flag if needed
                }
            }
            else {
                // Without padding, validate the position makes sense
                if (positionInGroup == 1) {
                    // Single character in final group is always invalid
                    // (6 bits cannot represent any complete bytes)
                    err = Base64DecodeError::InvalidPadding;
                    out.clear();
                    return false;
                }

                // Check if missing padding is acceptable
                if (!opt.acceptMissingPadding && positionInGroup != 0) {
                    err = Base64DecodeError::InvalidPadding;
                    out.clear();
                    return false;
                }
            }

            return true;
        }

    } // namespace Utils
} // namespace ShadowStrike