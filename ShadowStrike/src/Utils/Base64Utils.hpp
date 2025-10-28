
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
 * This implementation is entirely original work, written from scratch using
 * only publicly available Intel Intrinsics Guide documentation (Volume 2).
 *
 * No code has been copied, adapted, or derived from:
 * - Chromium/Chrome project
 * - libc++/LLVM
 * - libbase64
 * - Any other open-source or closed-source Base64 implementations
 *
 * Algorithm Design(For SIMD system):
 * - Custom chunk sizes (18/12 bytes for encoding, 24/16 chars for decoding)
 * - Original parallel processing strategies
 * - Independent validation logic
 *
 * Legal Status: This code is the intellectual property of ShadowStrike
 * and may be used for commercial purposes without licensing concerns.
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
#include <type_traits>

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
            size_t lineBreakEvery = 76;         //break at every N chars if InsertLineBreaks is set
            std::string_view lineBreak = "\r\n";// line break string
        };

        struct Base64DecodeOptions {
            Base64Alphabet alphabet = Base64Alphabet::Standard;
            bool ignoreWhitespace = true;       //ignore ' ', '\t', '\r', '\n'
            bool acceptMissingPadding = true;
        };

        enum class Base64DecodeError : uint8_t {
            None = 0,
            InvalidCharacter,
            InvalidPadding,
            TrailingData
        };

        // ============================================================================
       // CPU Feature Detection
       // ============================================================================

       /// @brief CPU SIMD capabilities detection
        struct CpuFeatures {
            bool hasSSE2 = false;
            bool hasSSSE3 = false;
            bool hasAVX = false;
            bool hasAVX2 = false;

            /// @brief Detect CPU features at runtime (cached)
            static const CpuFeatures& Detect() noexcept;
        };
        //HELPERS
        size_t Base64EncodedLength(size_t inputLen, const Base64EncodeOptions& opt = {});
        size_t Base64MaxDecodedLength(size_t inputLen) noexcept;

        // Encode
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

        // Decode
        bool Base64Decode(const char* data, size_t len, std::vector<uint8_t>& out, Base64DecodeError& err, const Base64DecodeOptions& opt = {});
        inline bool Base64Decode(std::string_view text, std::vector<uint8_t>& out, Base64DecodeError& err, const Base64DecodeOptions& opt = {}) {
            return Base64Decode(text.data(), text.size(), out, err, opt);
        }


        // Scalar implementations (fallback)
        bool Base64EncodeScalar(const uint8_t* data, size_t len, std::string& out, const Base64EncodeOptions& opt);
        bool Base64DecodeScalar(const char* data, size_t len, std::vector<uint8_t>& out, Base64DecodeError& err, const Base64DecodeOptions& opt);

        // SIMD implementation
        
#if defined(_M_X64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__)
       bool Base64EncodeAVX2(const uint8_t* data, size_t len, std::string& out, const Base64EncodeOptions& opt);
         bool Base64EncodeSSSE3(const uint8_t* data, size_t len, std::string& out, const Base64EncodeOptions& opt);

         bool Base64DecodeAVX2(const char* data, size_t len, std::vector<uint8_t>& out, Base64DecodeError& err, const Base64DecodeOptions& opt);
         bool Base64DecodeSSSE3(const char* data, size_t len, std::vector<uint8_t>& out, Base64DecodeError& err, const Base64DecodeOptions& opt);
#endif
      

    } // namespace Utils
} // namespace ShadowStrike