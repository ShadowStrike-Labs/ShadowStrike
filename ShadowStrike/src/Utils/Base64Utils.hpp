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
 * This is a clean, scalar-only Base64 implementation for maximum compatibility
 * and reliability. SIMD optimizations may be added in future releases.
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

namespace ShadowStrike {
    namespace Utils {

        enum class Base64Alphabet : uint8_t {
            Standard,
            UrlSafe
        };

        enum class Base64Flags : uint32_t {
            None = 0,
            InsertLineBreaks = 1 << 0,
            OmitPadding = 1 << 1   // '=' padding characters
        };

        constexpr Base64Flags operator|(Base64Flags a, Base64Flags b) noexcept {
            return static_cast<Base64Flags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
        }
        constexpr Base64Flags& operator|=(Base64Flags& a, Base64Flags b) noexcept {
            a = a | b; return a;
        }
        constexpr bool HasFlag(Base64Flags f, Base64Flags bit) noexcept {
            return (static_cast<uint32_t>(f) & static_cast<uint32_t>(bit)) != 0;
        }

        struct Base64EncodeOptions {
            Base64Alphabet alphabet = Base64Alphabet::Standard;
            Base64Flags flags = Base64Flags::None;
            size_t lineBreakEvery = 76;         // break at every N chars if InsertLineBreaks is set
            std::string_view lineBreak = "\r\n";// line break string
        };

        struct Base64DecodeOptions {
            Base64Alphabet alphabet = Base64Alphabet::Standard;
            bool ignoreWhitespace = true;       // ignore ' ', '\t', '\r', '\n'
            bool acceptMissingPadding = true;
        };

        enum class Base64DecodeError : uint8_t {
            None = 0,
            InvalidCharacter,
            InvalidPadding,
            TrailingData
        };

        // ============================================================================
        // Helper Functions
        // ============================================================================

        size_t Base64EncodedLength(size_t inputLen, const Base64EncodeOptions& opt = {});
        size_t Base64MaxDecodedLength(size_t inputLen) noexcept;

        // ============================================================================
        // Core Encode Functions
        // ============================================================================

        bool Base64Encode(const uint8_t* data, size_t len, std::string& out, const Base64EncodeOptions& opt = {});
        
        inline bool Base64Encode(std::string_view bytes, std::string& out, const Base64EncodeOptions& opt = {}) {
            if (bytes.empty()) {
                out.clear();
                return true;
            }
            return Base64Encode(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(), out, opt);
        }
        
        inline bool Base64Encode(const std::vector<uint8_t>& bytes, std::string& out, const Base64EncodeOptions& opt = {}) {
            if (bytes.empty()) {
                out.clear();
                return true;
            }
            return Base64Encode(bytes.data(), bytes.size(), out, opt);
        }

        // ============================================================================
        // Core Decode Functions
        // ============================================================================

        bool Base64Decode(const char* data, size_t len, std::vector<uint8_t>& out, Base64DecodeError& err, const Base64DecodeOptions& opt = {});
        
        inline bool Base64Decode(std::string_view text, std::vector<uint8_t>& out, Base64DecodeError& err, const Base64DecodeOptions& opt = {}) {
            return Base64Decode(text.data(), text.size(), out, err, opt);
        }

    } // namespace Utils
} // namespace ShadowStrike
