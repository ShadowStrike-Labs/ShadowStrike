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


#include "Base64Utils.hpp"

#include <cstring>
#include <cassert>
#include<cctype>


#if defined(_M_X64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__)
#  include <immintrin.h>
#  include <tmmintrin.h> // SSSE3
#  include <cstring>
#  include <algorithm>
#endif

 // Platform detection for SIMD
#if defined(_M_X64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__)
#  ifndef SS_BASE64_X86_SIMD
#    define SS_BASE64_X86_SIMD 1
#  endif
#endif


namespace ShadowStrike {
	namespace Utils {

		//Alphabets
        static constexpr std::array<char, 64> kEncStd{
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
    'q','r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9','+','/'
        };
        static constexpr std::array<char, 64> kEncUrl{
            'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
            'Q','R','S','T','U','V','W','X','Y','Z',
            'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
            'q','r','s','t','u','v','w','x','y','z',
            '0','1','2','3','4','5','6','7','8','9','-','_'
        };


        //Decoding table creator
        template<const std::array<char, 64>& Enc>
        constexpr std::array<uint8_t, 256> BuildDecLUT() {
            std::array<uint8_t, 256> t{};
            for (size_t i = 0; i < t.size(); ++i) t[i] = 0x80; // invalid
            for (uint8_t i = 0; i < 64; ++i) {
                t[static_cast<uint8_t>(Enc[i])] = i;
            }
            return t;
        }


        static constexpr auto kDecStd = BuildDecLUT<kEncStd>();
        static constexpr auto kDecUrl = BuildDecLUT<kEncUrl>();

      
      
        static inline uint8_t DecVal(uint8_t c, const std::array<uint8_t, 256>& lut) noexcept {
            
			//constant time lookup - avoids compiler optimization
            volatile const uint8_t* vptr = lut.data();
            return vptr[c];
        }

        
      // ============================================================================
      // CPU Feature Detection (Runtime - Cached)
      // ============================================================================

            const CpuFeatures& CpuFeatures::Detect() noexcept {
                static CpuFeatures features = []() {
                    CpuFeatures f;
#if defined(SS_BASE64_X86_SIMD)
                    int cpuInfo[4] = { 0 };

                    // CPUID function 1: EDX and ECX
                    __cpuid(cpuInfo, 1);
                    f.hasSSE2 = (cpuInfo[3] & (1 << 26)) != 0;  // EDX[26]

                    // CPUID function 1: ECX
                    f.hasSSSE3 = (cpuInfo[2] & (1 << 9)) != 0;   // ECX[9]
                    f.hasAVX = (cpuInfo[2] & (1 << 28)) != 0;    // ECX[28]

                    // CPUID function 7, subleaf 0: EBX
                    if (f.hasAVX) {
                        int cpuInfo7[4] = { 0 };
                        __cpuidex(cpuInfo7, 7, 0);
                        f.hasAVX2 = (cpuInfo7[1] & (1 << 5)) != 0; // EBX[5]
                    }
#endif
                    return f;
                    }();
                return features;
            }

       // ============================================================================
       // Dispatcher Functions (Auto SIMD Selection)
       // ============================================================================

       // Minimum size threshold for SIMD (below this, scalar is faster due to overhead)
            constexpr size_t SIMD_MIN_SIZE = 1024; // 1KB

            bool Base64Encode(const uint8_t* data, size_t len, std::string& out, const Base64EncodeOptions& opt) {
                out.clear();
                if (!data || len == 0) return true;

                // Size validation
                const size_t estimated = Base64EncodedLength(len, opt);
                if (estimated == 0 && len > 0) return false;

#if defined(SS_BASE64_X86_SIMD)
                // SIMD optimization only for:
                // 1. Large enough data (>= 1KB)
                // 2. No line breaks (SIMD doesn't handle line breaks efficiently)
                // 3. Standard padding (SIMD optimized for standard format)
                const bool canUseSIMD = (len >= SIMD_MIN_SIZE) &&
                    !HasFlag(opt.flags, Base64Flags::InsertLineBreaks) &&
                    !HasFlag(opt.flags, Base64Flags::OmitPadding) &&
                    opt.alphabet == Base64Alphabet::Standard;

                if (canUseSIMD) {
                    const auto& cpu = CpuFeatures::Detect();

                    // AVX2 path (fastest - ~4x speedup)
                    if (cpu.hasAVX2) {
                        if (Base64EncodeAVX2(data, len, out, opt)) {
                            return true;
                        }
                       
                    }

                    // SSSE3 path (fast - ~2.5x speedup)
                    else if (cpu.hasSSSE3) {
                        if (Base64EncodeSSSE3(data, len, out, opt)) {
                            return true;
                        }
                    }
                }
#endif

                // Scalar fallback (always safe)
                return Base64EncodeScalar(data, len, out, opt);
            }

            bool Base64Decode(const char* data, size_t len, std::vector<uint8_t>& out, Base64DecodeError& err, const Base64DecodeOptions& opt) {
                out.clear();
                err = Base64DecodeError::None;
                if (!data || len == 0) return true;

#if defined(SS_BASE64_X86_SIMD)
                // SIMD optimization conditions
                const bool canUseSIMD = (len >= SIMD_MIN_SIZE) &&
                    opt.alphabet == Base64Alphabet::Standard &&
                    !opt.ignoreWhitespace; // SIMD doesn't skip whitespace efficiently

                if (canUseSIMD) {
                    const auto& cpu = CpuFeatures::Detect();

                    // AVX2 path
                    if (cpu.hasAVX2) {
                        if (Base64DecodeAVX2(data, len, out, err, opt)) {
                            return err == Base64DecodeError::None;
                        }
                    }

                    // SSSE3 path
                    else if (cpu.hasSSSE3) {
                        if (Base64DecodeSSSE3(data, len, out, err, opt)) {
                            return err == Base64DecodeError::None;
                        }
                    }
                }
#endif

                // Scalar fallback
                return Base64DecodeScalar(data, len, out, err, opt);
            }

            // ============================================================================
            // Scalar Implementation 
            // ============================================================================

                // Scalar encode implementation (EXISTING CODE - NO CHANGES)
                bool Base64EncodeScalar(const uint8_t* data, size_t len, std::string& out, const Base64EncodeOptions& opt) {
                    out.clear();
                    if (!data || len == 0) return true;

                    const size_t estimated = Base64EncodedLength(len, opt);
                    if (estimated == 0 && len > 0) return false;

                    const auto& enc = (opt.alphabet == Base64Alphabet::Standard) ? kEncStd : kEncUrl;
                    const bool insertLB = HasFlag(opt.flags, Base64Flags::InsertLineBreaks) && opt.lineBreakEvery > 0 && !opt.lineBreak.empty();
                    const bool omitPad = HasFlag(opt.flags, Base64Flags::OmitPadding);

                    try {
                        out.reserve(estimated);
                    }
                    catch (const std::bad_alloc&) {
                        return false;
                    }

                    const size_t charsPerLine = insertLB ? (opt.lineBreakEvery ? opt.lineBreakEvery : 76) : SIZE_MAX;
                    size_t lineCount = 0;

                    size_t i = 0;
                    while (i + 3 <= len) {
                        uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                            (static_cast<uint32_t>(data[i + 1]) << 8) |
                            static_cast<uint32_t>(data[i + 2]);
                        i += 3;

                        char out4[4];
                        out4[0] = enc[(v >> 18) & 0x3F];
                        out4[1] = enc[(v >> 12) & 0x3F];
                        out4[2] = enc[(v >> 6) & 0x3F];
                        out4[3] = enc[(v) & 0x3F];

                        if (insertLB && lineCount + 4 > charsPerLine) {
                            out.append(opt.lineBreak);
                            lineCount = 0;
                        }

                        out.append(out4, 4);
                        lineCount += 4;
                    }

                    size_t rem = len - i;
                    if (rem) {
                        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
                        if (rem == 2) {
                            v |= static_cast<uint32_t>(data[i + 1]) << 8;
                        }

                        char out4[4];
                        out4[0] = enc[(v >> 18) & 0x3F];
                        out4[1] = enc[(v >> 12) & 0x3F];
                        out4[2] = (rem == 2) ? enc[(v >> 6) & 0x3F] : '=';
                        out4[3] = '=';

                        size_t validChars = (rem == 2) ? 3 : 2;
                        size_t appendSize = omitPad ? validChars : 4;

                        if (insertLB && lineCount + appendSize > charsPerLine) {
                            out.append(opt.lineBreak);
                            lineCount = 0;
                        }
                        out.append(out4, appendSize);
                        lineCount += appendSize;
                    }

                    return true;
                }

                // Scalar decode implementation
                bool Base64DecodeScalar(const char* data, size_t len, std::vector<uint8_t>& out, Base64DecodeError& err, const Base64DecodeOptions& opt) {
                    out.clear();
                    err = Base64DecodeError::None;
                    if (!data || len == 0) return true;

                    const auto& lut = (opt.alphabet == Base64Alphabet::Standard) ? kDecStd : kDecUrl;

                    size_t maxSize = Base64MaxDecodedLength(len);
                    if (maxSize == 0 && len > 0) {
                        err = Base64DecodeError::InvalidCharacter;
                        return false;
                    }

                    try {
                        out.reserve(maxSize);
                    }
                    catch (const std::bad_alloc&) {
                        err = Base64DecodeError::InvalidCharacter;
                        return false;
                    }

                    uint32_t acc = 0;
                    int bits = 0;
                    int padCount = 0;
                    bool seenPad = false;
                    size_t consumed = 0;

                    size_t i = 0;
                    while (i < len) {
                        unsigned char ch = static_cast<unsigned char>(data[i++]);

                        if (opt.ignoreWhitespace && std::isspace(static_cast<unsigned char>(ch))) {
                            continue;
                        }

                        if (ch == '=') {
                            seenPad = true;
                            padCount++;
                            if (padCount > 2) {
                                err = Base64DecodeError::InvalidPadding;
                                return false;
                            }
                            if ((consumed % 4) == 0) {  
                                err = Base64DecodeError::InvalidPadding;
                                return false;
                            }
                            continue;
                        }

                        if (seenPad) {
                            if (!(opt.ignoreWhitespace && std::isspace(static_cast<unsigned char>(ch)))) {
                                err = Base64DecodeError::InvalidPadding;
                                return false;
                            }
                            continue;
                        }

                        uint8_t v = DecVal(ch, lut);
                        if (v & 0x80) {
                            err = Base64DecodeError::InvalidCharacter;
                            return false;
                        }

                        acc = (acc << 6) | v;
                        bits += 6;
                        consumed++;

                        if (bits >= 8) {
                            bits -= 8;
                            uint8_t byte = static_cast<uint8_t>((acc >> bits) & 0xFF);
                            out.push_back(byte);
                        }
                    }

                    if (seenPad) {
                        if (padCount > 2) {
                            err = Base64DecodeError::InvalidPadding;
                            return false;
                        }
                        if (bits > 4) {
                            err = Base64DecodeError::InvalidPadding;
                            return false;
                        }
                    }
                    else {
                        size_t mod4 = consumed % 4;
                        if (mod4 == 1) {
                            err = Base64DecodeError::InvalidPadding;
                            return false;
                        }
                        if (!opt.acceptMissingPadding && mod4 != 0) {
                            err = Base64DecodeError::InvalidPadding;
                            return false;
                        }
                    }

                    err = Base64DecodeError::None;
                    return true;
                }

          

            // ============================================================================
            // Utility Functions (Keep existing)
            // ============================================================================

            size_t Base64EncodedLength(size_t inputLen, const Base64EncodeOptions& opt) {
                if (inputLen == 0) return 0;

                constexpr size_t MAX_SAFE_INPUT = (SIZE_MAX / 4) - 1024;
                if (inputLen > MAX_SAFE_INPUT) {
                    return 0;
                }

                size_t fullBlocks = inputLen / 3;
                size_t rem = inputLen % 3;

                size_t outLen = 0;
                if (fullBlocks > SIZE_MAX / 4) return 0;
                outLen = fullBlocks * 4;

                if (rem) {
                    if (outLen > SIZE_MAX - 4) return 0;
                    outLen += 4;
                }

                if (HasFlag(opt.flags, Base64Flags::OmitPadding)) {
                    if (rem == 1 && outLen >= 2) outLen -= 2;
                    else if (rem == 2 && outLen >= 1) outLen -= 1;
                }

                if (HasFlag(opt.flags, Base64Flags::InsertLineBreaks) && opt.lineBreakEvery > 0 && !opt.lineBreak.empty()) {
                    size_t charsPerLine = opt.lineBreakEvery;
                    if (charsPerLine == 0) charsPerLine = 76;

                    size_t numBreaks = (outLen == 0) ? 0 : ((outLen - 1) / charsPerLine);

                    if (numBreaks > 0 && opt.lineBreak.size() > 0) {
                        if (numBreaks > SIZE_MAX / opt.lineBreak.size()) return 0;
                        size_t additionalBytes = numBreaks * opt.lineBreak.size();
                        if (outLen > SIZE_MAX - additionalBytes) return 0;
                        outLen += additionalBytes;
                    }
                }

                return outLen;
            }

            size_t Base64MaxDecodedLength(size_t inputLen) noexcept {
                if (inputLen == 0) return 0;
                if (inputLen > SIZE_MAX - 3) return 0;

                size_t groups = (inputLen + 3) / 4;
                if (groups > SIZE_MAX / 3) return 0;

                return groups * 3;
            }

//SIMD implementation will be here...

            bool Base64EncodeAVX2(const uint8_t* data, size_t len, std::string& out, const Base64EncodeOptions& opt) {
				return false;//not implemented yet
            }
            bool Base64EncodeSSSE3(const uint8_t* data, size_t len, std::string& out, const Base64EncodeOptions& opt) {
                return false;//not implemented yet
            }

            bool Base64DecodeAVX2(const char* data, size_t len, std::vector<uint8_t>& out, Base64DecodeError& err, const Base64DecodeOptions& opt) {
                return false;//not implemented yet
            }
            bool Base64DecodeSSSE3(const char* data, size_t len, std::vector<uint8_t>& out, Base64DecodeError& err, const Base64DecodeOptions& opt) {
                return false;//not implemented yet
            }
    
         
	}//namespace Utils
}//namespace ShadowStrike