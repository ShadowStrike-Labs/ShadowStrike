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
 * Security Considerations:
 *   - All buffer operations are bounds-checked
 *   - Integer overflow protection on all size calculations
 *   - No undefined behavior paths
 *   - Memory allocation failures handled gracefully
 *
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <limits>
#include <type_traits>

namespace ShadowStrike {
    namespace Utils {

        // ============================================================================
        // Base64 Alphabet Selection
        // ============================================================================

        /**
         * @brief Specifies the Base64 alphabet variant to use.
         * 
         * Standard: Uses '+' and '/' as the 62nd and 63rd characters (RFC 4648 Section 4)
         * UrlSafe:  Uses '-' and '_' as the 62nd and 63rd characters (RFC 4648 Section 5)
         */
        enum class Base64Alphabet : uint8_t {
            Standard = 0,  ///< RFC 4648 standard alphabet (+/)
            UrlSafe  = 1   ///< RFC 4648 URL-safe alphabet (-_)
        };

        // ============================================================================
        // Encoding Flags
        // ============================================================================

        /**
         * @brief Bit flags controlling Base64 encoding behavior.
         */
        enum class Base64Flags : uint32_t {
            None            = 0,        ///< Default encoding behavior
            InsertLineBreaks = 1U << 0, ///< Insert line breaks for MIME compatibility
            OmitPadding     = 1U << 1   ///< Omit trailing '=' padding characters
        };

        /**
         * @brief Bitwise OR operator for combining Base64Flags.
         */
        [[nodiscard]] constexpr Base64Flags operator|(Base64Flags a, Base64Flags b) noexcept {
            return static_cast<Base64Flags>(
                static_cast<std::underlying_type_t<Base64Flags>>(a) |
                static_cast<std::underlying_type_t<Base64Flags>>(b)
            );
        }

        /**
         * @brief Bitwise OR assignment operator for Base64Flags.
         */
        constexpr Base64Flags& operator|=(Base64Flags& a, Base64Flags b) noexcept {
            a = a | b;
            return a;
        }

        /**
         * @brief Bitwise AND operator for Base64Flags.
         */
        [[nodiscard]] constexpr Base64Flags operator&(Base64Flags a, Base64Flags b) noexcept {
            return static_cast<Base64Flags>(
                static_cast<std::underlying_type_t<Base64Flags>>(a) &
                static_cast<std::underlying_type_t<Base64Flags>>(b)
            );
        }

        /**
         * @brief Check if a specific flag bit is set.
         * @param flags The flags value to check.
         * @param bit The specific flag bit to test for.
         * @return true if the bit is set, false otherwise.
         */
        [[nodiscard]] constexpr bool HasFlag(Base64Flags flags, Base64Flags bit) noexcept {
            return (static_cast<std::underlying_type_t<Base64Flags>>(flags) &
                    static_cast<std::underlying_type_t<Base64Flags>>(bit)) != 0;
        }

        // ============================================================================
        // Options Structures
        // ============================================================================

        /**
         * @brief Configuration options for Base64 encoding operations.
         * 
         * Thread Safety: This structure is safe for concurrent read access.
         *                Each encoding operation should use its own instance.
         */
        struct Base64EncodeOptions final {
            Base64Alphabet alphabet = Base64Alphabet::Standard; ///< Alphabet variant
            Base64Flags flags = Base64Flags::None;              ///< Encoding flags
            size_t lineBreakEvery = 76;                         ///< Characters per line (MIME default)
            std::string_view lineBreak = "\r\n";                ///< Line break sequence

            // Validation constants
            static constexpr size_t kMinLineBreakInterval = 4;   ///< Minimum sensible line length
            static constexpr size_t kMaxLineBreakInterval = 8192; ///< Maximum practical line length

            /**
             * @brief Validate the options structure.
             * @return true if all options are valid, false otherwise.
             */
            [[nodiscard]] constexpr bool IsValid() const noexcept {
                // lineBreakEvery must be reasonable if line breaks are enabled
                if (HasFlag(flags, Base64Flags::InsertLineBreaks)) {
                    if (lineBreakEvery < kMinLineBreakInterval ||
                        lineBreakEvery > kMaxLineBreakInterval) {
                        return false;
                    }
                    if (lineBreak.empty()) {
                        return false;
                    }
                }
                return true;
            }
        };

        /**
         * @brief Configuration options for Base64 decoding operations.
         * 
         * Thread Safety: This structure is safe for concurrent read access.
         *                Each decoding operation should use its own instance.
         */
        struct Base64DecodeOptions final {
            Base64Alphabet alphabet = Base64Alphabet::Standard; ///< Alphabet variant
            bool ignoreWhitespace = true;                       ///< Skip whitespace characters
            bool acceptMissingPadding = true;                   ///< Allow input without '=' padding
        };

        // ============================================================================
        // Error Codes
        // ============================================================================

        /**
         * @brief Error codes returned by Base64 decoding operations.
         */
        enum class Base64DecodeError : uint8_t {
            None = 0,              ///< No error - operation succeeded
            InvalidCharacter = 1,  ///< Input contains invalid Base64 character
            InvalidPadding = 2,    ///< Padding characters are malformed
            TrailingData = 3,      ///< Non-whitespace data after padding
            AllocationFailed = 4,  ///< Memory allocation failed
            InputTooLarge = 5      ///< Input exceeds safe processing limits
        };

        /**
         * @brief Convert Base64DecodeError to human-readable string.
         * @param err The error code to convert.
         * @return A null-terminated string describing the error.
         */
        [[nodiscard]] constexpr const char* Base64DecodeErrorToString(Base64DecodeError err) noexcept {
            switch (err) {
                case Base64DecodeError::None:             return "No error";
                case Base64DecodeError::InvalidCharacter: return "Invalid Base64 character";
                case Base64DecodeError::InvalidPadding:   return "Invalid padding";
                case Base64DecodeError::TrailingData:     return "Trailing data after padding";
                case Base64DecodeError::AllocationFailed: return "Memory allocation failed";
                case Base64DecodeError::InputTooLarge:    return "Input exceeds safe size limits";
                default:                                  return "Unknown error";
            }
        }

        // ============================================================================
        // Length Calculation Functions
        // ============================================================================

        /**
         * @brief Calculate the exact output length for Base64 encoding.
         * 
         * This function performs overflow-safe calculations and accounts for:
         *   - Padding characters (optional)
         *   - Line break insertions (optional)
         * 
         * @param inputLen The length of the input data in bytes.
         * @param opt Encoding options that affect output length.
         * @return The required output buffer size, or 0 if overflow would occur.
         * 
         * Thread Safety: This function is thread-safe.
         */
        [[nodiscard]] size_t Base64EncodedLength(size_t inputLen, const Base64EncodeOptions& opt = {}) noexcept;

        /**
         * @brief Calculate the maximum possible decoded length.
         * 
         * The actual decoded length may be less due to padding characters.
         * This provides an upper bound for buffer allocation.
         * 
         * @param inputLen The length of the Base64 input string.
         * @return The maximum possible decoded size, or 0 if overflow would occur.
         * 
         * Thread Safety: This function is thread-safe.
         */
        [[nodiscard]] size_t Base64MaxDecodedLength(size_t inputLen) noexcept;

        // ============================================================================
        // Core Encode Functions
        // ============================================================================

        /**
         * @brief Encode binary data to Base64 string.
         * 
         * @param data Pointer to input binary data (may be nullptr if len == 0).
         * @param len Length of input data in bytes.
         * @param out Output string (cleared and populated on success).
         * @param opt Encoding options.
         * @return true on success, false on failure (overflow, allocation failure, etc.).
         * 
         * Thread Safety: This function is thread-safe when different output buffers are used.
         * Exception Safety: Strong guarantee - output is unchanged on failure.
         */
        [[nodiscard]] bool Base64Encode(
            const uint8_t* data,
            size_t len,
            std::string& out,
            const Base64EncodeOptions& opt = {}
        ) noexcept;

        /**
         * @brief Encode a string_view to Base64.
         * 
         * Convenience overload for encoding string data.
         * 
         * @param bytes Input data as string_view.
         * @param out Output string (cleared and populated on success).
         * @param opt Encoding options.
         * @return true on success, false on failure.
         */
        [[nodiscard]] inline bool Base64Encode(
            std::string_view bytes,
            std::string& out,
            const Base64EncodeOptions& opt = {}
        ) noexcept {
            // Handle empty input explicitly for clarity
            if (bytes.empty()) {
                out.clear();
                return true;
            }
            // Safe cast: string_view guarantees valid data pointer for non-empty views
            return Base64Encode(
                reinterpret_cast<const uint8_t*>(bytes.data()),
                bytes.size(),
                out,
                opt
            );
        }

        /**
         * @brief Encode a byte vector to Base64.
         * 
         * Convenience overload for encoding vector<uint8_t> data.
         * 
         * @param bytes Input data as byte vector.
         * @param out Output string (cleared and populated on success).
         * @param opt Encoding options.
         * @return true on success, false on failure.
         */
        [[nodiscard]] inline bool Base64Encode(
            const std::vector<uint8_t>& bytes,
            std::string& out,
            const Base64EncodeOptions& opt = {}
        ) noexcept {
            // Handle empty input explicitly
            if (bytes.empty()) {
                out.clear();
                return true;
            }
            // Vector guarantees valid data() pointer when non-empty
            return Base64Encode(bytes.data(), bytes.size(), out, opt);
        }

        // ============================================================================
        // Core Decode Functions
        // ============================================================================

        /**
         * @brief Decode a Base64 string to binary data.
         * 
         * @param data Pointer to Base64 input string (may be nullptr if len == 0).
         * @param len Length of input string.
         * @param out Output byte vector (cleared and populated on success).
         * @param err Error code set on failure (unchanged on success).
         * @param opt Decoding options.
         * @return true on success, false on failure (check err for details).
         * 
         * Thread Safety: This function is thread-safe when different output buffers are used.
         * Exception Safety: Strong guarantee - output is unchanged on failure.
         */
        [[nodiscard]] bool Base64Decode(
            const char* data,
            size_t len,
            std::vector<uint8_t>& out,
            Base64DecodeError& err,
            const Base64DecodeOptions& opt = {}
        ) noexcept;

        /**
         * @brief Decode a Base64 string_view to binary data.
         * 
         * Convenience overload for decoding string_view input.
         * 
         * @param text Input Base64 text.
         * @param out Output byte vector (cleared and populated on success).
         * @param err Error code set on failure.
         * @param opt Decoding options.
         * @return true on success, false on failure.
         */
        [[nodiscard]] inline bool Base64Decode(
            std::string_view text,
            std::vector<uint8_t>& out,
            Base64DecodeError& err,
            const Base64DecodeOptions& opt = {}
        ) noexcept {
            // Handle empty input
            if (text.empty()) {
                out.clear();
                err = Base64DecodeError::None;
                return true;
            }
            // string_view guarantees valid data() for non-empty views
            return Base64Decode(text.data(), text.size(), out, err, opt);
        }

        /**
         * @brief Decode Base64 string to binary with simplified error handling.
         * 
         * @param text Input Base64 text.
         * @param out Output byte vector.
         * @param opt Decoding options.
         * @return true on success, false on any error.
         */
        [[nodiscard]] inline bool Base64Decode(
            std::string_view text,
            std::vector<uint8_t>& out,
            const Base64DecodeOptions& opt = {}
        ) noexcept {
            Base64DecodeError err = Base64DecodeError::None;
            return Base64Decode(text, out, err, opt);
        }

    } // namespace Utils
} // namespace ShadowStrike
