#include "Base64Utils.hpp"

#include <cstring>
#include <cassert>
#include<cctype>

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

        //Guessing code length
        size_t Base64EncodedLength(size_t inputLen, const Base64EncodeOptions& opt) {
            if (inputLen == 0) return 0;

            //Base output length(with padding)
            size_t fullBlocks = inputLen / 3;
            size_t rem = inputLen % 3;

            size_t outLen = fullBlocks * 4;
            if (rem) {
                outLen += 4;
            }

        
            if (HasFlag(opt.flags, Base64Flags::OmitPadding)) {
                if (rem == 1) outLen -= 2;
                else if (rem == 2) outLen -= 1;
            }

            if (HasFlag(opt.flags, Base64Flags::InsertLineBreaks) && opt.lineBreakEvery > 0 && !opt.lineBreak.empty()) {
      
                size_t charsPerLine = opt.lineBreakEvery;
                if (charsPerLine == 0) charsPerLine = 76;
                size_t numBreaks = (outLen == 0) ? 0 : ((outLen - 1) / charsPerLine);
                outLen += numBreaks * opt.lineBreak.size();
            }

            return outLen;
        }

        size_t Base64MaxDecodedLength(size_t inputLen) noexcept {
         
            if (inputLen == 0) return 0;
            size_t groups = (inputLen + 3) / 4;
            return groups * 3;
        }


        bool Base64Encode(const uint8_t* data, size_t len, std::string& out, const Base64EncodeOptions& opt) {
            out.clear();
            if (!data || len == 0) return true;

            const auto& enc = (opt.alphabet == Base64Alphabet::Standard) ? kEncStd : kEncUrl;

            const bool insertLB = HasFlag(opt.flags, Base64Flags::InsertLineBreaks) && opt.lineBreakEvery > 0 && !opt.lineBreak.empty();
            const bool omitPad = HasFlag(opt.flags, Base64Flags::OmitPadding);

            const size_t estimated = Base64EncodedLength(len, opt);
            out.reserve(estimated);

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

                // Line end check
                if (lineCount + 4 > charsPerLine) {
                    out.append(opt.lineBreak);
                    lineCount = 0;
                }
                out.append(out4, 4);
                lineCount += 4;
            }

            size_t rem = len - i;
            if (rem) {
                uint32_t v = static_cast<uint32_t>(data[i]) << 16;
                char out4[4];
                if (rem == 2) {
                    v |= static_cast<uint32_t>(data[i + 1]) << 8;
                    out4[0] = enc[(v >> 18) & 0x3F];
                    out4[1] = enc[(v >> 12) & 0x3F];
                    out4[2] = enc[(v >> 6) & 0x3F];
                    out4[3] = '=';
                    if (omitPad) {
                        // satýr kesimi
                        if (lineCount + 3 > charsPerLine && insertLB) { out.append(opt.lineBreak); lineCount = 0; }
                        out.append(out4, 3);
                        lineCount += 3;
                    }
                    else {
                        if (lineCount + 4 > charsPerLine && insertLB) { out.append(opt.lineBreak); lineCount = 0; }
                        out.append(out4, 4);
                        lineCount += 4;
                    }
                }
                else { // rem == 1
                    out4[0] = enc[(v >> 18) & 0x3F];
                    out4[1] = enc[(v >> 12) & 0x3F];
                    out4[2] = '=';
                    out4[3] = '=';
                    if (omitPad) {
                        if (lineCount + 2 > charsPerLine && insertLB) { out.append(opt.lineBreak); lineCount = 0; }
                        out.append(out4, 2);
                        lineCount += 2;
                    }
                    else {
                        if (lineCount + 4 > charsPerLine && insertLB) { out.append(opt.lineBreak); lineCount = 0; }
                        out.append(out4, 4);
                        lineCount += 4;
                    }
                }
            }

            
            return true;
        }

        static inline uint8_t DecVal(uint8_t c, const std::array<uint8_t, 256>& lut) noexcept {
            return lut[c];
        }

        bool Base64Decode(const char* data, size_t len, std::vector<uint8_t>& out, Base64DecodeError& err, const Base64DecodeOptions& opt) {
            out.clear();
            err = Base64DecodeError::None;
            if (!data || len == 0) return true;

            const auto& lut = (opt.alphabet == Base64Alphabet::Standard) ? kDecStd : kDecUrl;

            // Reserve maximum required byte count
            out.reserve(Base64MaxDecodedLength(len));

            uint32_t acc = 0;   // 24-bit accumulator
            int bits = 0;       // number of accumulated bits
            int padCount = 0;   // number of '=' characters seen
            bool seenPad = false;

            size_t i = 0;
            size_t consumed = 0;

            while (i < len) {
                unsigned char ch = static_cast<unsigned char>(data[i++]);

                if (opt.ignoreWhitespace && std::isspace(static_cast<char>(ch))) {
                    continue;
                }

                if (ch == '=') {
                    // '=' can only appear in the final block
                    seenPad = true;
                    padCount++;
                    // After padding, all remaining characters must be '=' or whitespace
                    // We'll validate this at the end instead of consuming them now
                    continue;
                }

                if (seenPad) {
                    // No valid base64 characters allowed after padding
                    if (!(opt.ignoreWhitespace && std::isspace(static_cast<char>(ch)))) {
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

            // Padding check and partial block handling:
            // Base64 quartet: 4 x 6-bit -> 24-bit -> 3 bytes
            // Without padding, depending on quartet count, 1 or 2 bytes may have been produced
            if (seenPad) {
                // Valid padding rules:
                // - '==' -> only first 2 base64 characters carry data -> 1 byte
                // - '='  -> first 3 base64 characters carry data -> 2 bytes
                if (padCount > 2) {
                    err = Base64DecodeError::InvalidPadding;
                    return false;
                }
                // When padding is seen, bits % 8 must be aligned (already handled during push)
                // No extra checks needed; stream-based decoding already produced bytes
            }
            else {
                // If padding is missing and acceptMissingPadding=true, validate based on remaining bits:
                // base64 character count % 4 == 0 -> valid
                // % 4 == 2 -> should have produced 1 byte
                // % 4 == 3 -> should have produced 2 bytes
                // % 4 == 1 -> invalid
                size_t mod4 = consumed % 4;
                if (mod4 == 1) {
                    err = Base64DecodeError::InvalidPadding;
                    return false;
                }
                if (!opt.acceptMissingPadding) {
                    if (mod4 != 0 && mod4 != 2 && mod4 != 3) {
                        err = Base64DecodeError::InvalidPadding;
                        return false;
                    }
                }
            }

            // Remaining characters must have been whitespace, otherwise they'd have been caught earlier
            err = Base64DecodeError::None;
            return true;
        }
     

	}//namespace Utils
}//namespace ShadowStrike