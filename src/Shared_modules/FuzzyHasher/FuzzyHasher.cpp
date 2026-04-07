#include "pch.h"
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
/**
 * ============================================================================
 * ShadowStrike NGAV — FuzzyHasher Public API Implementation
 * ============================================================================
 *
 * @file FuzzyHasher.cpp
 * @brief Public API facade for the CTPH fuzzy hashing engine
 *
 * Responsibilities:
 *   - Input validation and size capping (BUG-3)
 *   - Delegation to DigestGenerator / DigestComparer
 *   - Per-session salt generation via BCryptGenRandom (BUG-8)
 *   - APT-hardening extensions: normalized hashing, salted hashing,
 *     suspicious-digest detection, and batch comparison
 *
 * @copyright Copyright (c) ShadowStrike Contributors
 * @license AGPL-3.0-only
 * ============================================================================
 */

#include "FuzzyHasher.hpp"
#include "DigestGenerator.hpp"
#include "DigestComparer.hpp"

// PEParser: required for HashBufferNormalized PE-section extraction
#include "../PEParser/PEParser.hpp"

// Logger: required for explicit, traceable error reporting
#include "../Utils/Logger.hpp"

// HashUtils: required for SHA-256/SHA-3 cryptographic confirmation
#include "../Utils/HashUtils.hpp"

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt.lib")
#endif

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace ShadowStrike::FuzzyHasher {

    namespace {

        // =====================================================================
        // Per-session salt (BCryptGenRandom, initialized once at first use)
        // =====================================================================

        /**
         * @brief Retrieve the module-level per-session random salt.
         *
         * Initialized exactly once (C++ static-local guarantee) using
         * BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG, which does
         * not require an open provider handle and is FIPS-compliant.
         *
         * Falls back to QPC XOR PID if BCryptGenRandom fails (should never
         * happen on a healthy Windows install, but must not crash silently).
         *
         * The salt is 64 bits so that after XOR-folding into the 32-bit FNV
         * offset basis the attacker needs to guess a 64-bit secret to
         * pre-compute any chunk hash.
         */
        [[nodiscard]] uint64_t SessionSalt() noexcept {
            static const uint64_t kSalt = []() noexcept -> uint64_t {
                uint64_t s = 0;
#ifdef _WIN32
                const NTSTATUS st = BCryptGenRandom(
                    nullptr,
                    reinterpret_cast<PUCHAR>(&s),
                    static_cast<ULONG>(sizeof(s)),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG
                );
                if (st != 0 || s == 0) {
                    // BCryptGenRandom failed or returned zero — use QPC + PID fallback.
                    LARGE_INTEGER qpc{};
                    QueryPerformanceCounter(&qpc);
                    s = static_cast<uint64_t>(qpc.QuadPart)
                      ^ (static_cast<uint64_t>(GetCurrentProcessId()) << 32);
                    if (s == 0) {
                        // Absolute last resort: a non-zero compile-time constant.
                        s = 0xDEADBEEFCAFEBABEULL;
                    }
                    SS_LOG_WARN(L"FuzzyHasher",
                        L"BCryptGenRandom failed (NTSTATUS=0x%08X); "
                        L"session salt derived from QPC+PID",
                        static_cast<unsigned>(st));
                }
#else
                // Non-Windows stub: use a non-zero compile-time constant.
                s = 0xABCDEF0123456789ULL;
#endif
                return s;
            }();
            return kSalt;
        }

        // =====================================================================
        // PE section extraction helpers for HashBufferNormalized
        // =====================================================================

        /**
         * @brief Extract and concatenate the raw bytes of all executable/code
         *        sections from a PE image buffer.
         *
         * Iterates over PEInfo::sections and collects every section where
         * isExecutable || hasCode is true.  Raw section data is copied from
         * the original buffer using rawAddress and rawSize (both bounds-checked
         * against the buffer size).
         *
         * @param data     Original PE buffer
         * @param info     Parsed PEInfo from PEParser::PEParser::ParseBuffer
         * @return Vector containing concatenated code section bytes, or empty
         *         on failure (no code sections, all sections out of bounds).
         */
        [[nodiscard]] std::vector<uint8_t> ExtractCodeSections(
            std::span<const uint8_t>            data,
            const ShadowStrike::PEParser::PEInfo& info
        ) noexcept {
            try {
                std::vector<uint8_t> extracted;
                extracted.reserve(data.size() / 2); // Pre-allocate ~half the file

                for (const auto& sec : info.sections) {
                    if (!sec.isExecutable && !sec.hasCode) {
                        continue;
                    }
                    if (sec.rawAddress == 0 || sec.rawSize == 0) {
                        continue;
                    }

                    // Bounds-check: never read beyond the mapped buffer.
                    const uint64_t secEnd =
                        static_cast<uint64_t>(sec.rawAddress) + sec.rawSize;
                    if (secEnd > data.size()) {
                        SS_LOG_WARN(L"FuzzyHasher",
                            L"HashBufferNormalized: section '%S' extends beyond "
                            L"buffer (rawAddr=%u, rawSize=%u, bufSize=%zu) — skipped",
                            sec.name.c_str(), sec.rawAddress, sec.rawSize, data.size());
                        continue;
                    }

                    const uint8_t* start = data.data() + sec.rawAddress;
                    extracted.insert(extracted.end(), start, start + sec.rawSize);
                }

                return extracted;
            } catch (...) {
                return {};
            }
        }

        /**
         * @brief Find the effective end of a buffer after stripping trailing
         *        zero-padding of at least kMinZeroPad consecutive zero bytes.
         *
         * Preserves at least one byte so we never return a zero-length span
         * for a buffer that is all zeros.
         *
         * @return Number of meaningful bytes (trimmed length).
         */
        [[nodiscard]] size_t EffectiveLengthAfterZeroStrip(
            std::span<const uint8_t> data
        ) noexcept {
            constexpr size_t kMinZeroPad = 512;

            if (data.size() < kMinZeroPad) {
                return data.size();
            }

            // Count trailing zeros from the end.
            size_t zeroCount = 0;
            for (size_t i = data.size(); i > 0; --i) {
                if (data[i - 1] == 0) {
                    ++zeroCount;
                } else {
                    break;
                }
            }

            if (zeroCount < kMinZeroPad) {
                return data.size(); // Not enough trailing zeros to strip
            }

            const size_t trimmed = data.size() - zeroCount;
            return (trimmed == 0) ? 1 : trimmed; // Keep at least 1 byte
        }

        // =====================================================================
        // Cryptographic confirmation helpers
        // =====================================================================

        /**
         * @brief Determine the best cryptographic algorithm available at runtime.
         *
         * Tries SHA-3-256 first (Windows 10 1903+); falls back to SHA-256.
         * Result is cached after the first call (C++ static-local guarantee).
         *
         * @return CryptoAlgorithm::SHA3_256 when BCrypt can open it;
         *         CryptoAlgorithm::SHA256   otherwise.
         */
        [[nodiscard]] CryptoAlgorithm PickCryptoAlgorithm() noexcept {
            static const CryptoAlgorithm kAvailable = []() noexcept -> CryptoAlgorithm {
                // Probe by attempting Init(). If it succeeds, SHA-3 is available.
                ShadowStrike::Utils::HashUtils::Hasher probe(
                    ShadowStrike::Utils::HashUtils::Algorithm::SHA3_256);
                if (probe.Init()) {
                    SS_LOG_DEBUG(L"FuzzyHasher",
                        L"CryptoConfirm: SHA-3-256 is available on this system");
                    return CryptoAlgorithm::SHA3_256;
                }
                SS_LOG_DEBUG(L"FuzzyHasher",
                    L"CryptoConfirm: SHA-3-256 unavailable — using SHA-256 fallback");
                return CryptoAlgorithm::SHA256;
            }();
            return kAvailable;
        }

        /**
         * @brief Map our CryptoAlgorithm enum to HashUtils::Algorithm.
         */
        [[nodiscard]] ShadowStrike::Utils::HashUtils::Algorithm ToHashUtilsAlg(
            CryptoAlgorithm ca
        ) noexcept {
            switch (ca) {
            case CryptoAlgorithm::SHA3_256:
                return ShadowStrike::Utils::HashUtils::Algorithm::SHA3_256;
            case CryptoAlgorithm::SHA256:
            default:
                return ShadowStrike::Utils::HashUtils::Algorithm::SHA256;
            }
        }

        /**
         * @brief Compute a cryptographic hash of a byte buffer, returned as
         *        a lowercase hex string.
         *
         * @param data    Input bytes
         * @param alg     HashUtils algorithm to use
         * @return Lowercase hex string, or std::nullopt on failure.
         */
        [[nodiscard]] std::optional<std::string> ComputeCryptoHashHex(
            std::span<const uint8_t>                     data,
            ShadowStrike::Utils::HashUtils::Algorithm    alg
        ) noexcept {
            if (data.empty()) {
                return std::nullopt;
            }
            std::string hexOut;
            ShadowStrike::Utils::HashUtils::Error err{};
            const bool ok = ShadowStrike::Utils::HashUtils::ComputeHex(
                alg,
                data.data(),
                data.size(),
                hexOut,
                /*upper=*/false,
                &err
            );
            if (!ok) {
                SS_LOG_WARN(L"FuzzyHasher",
                    L"ComputeCryptoHashHex failed (nt=0x%08X, win32=%lu)",
                    static_cast<unsigned>(err.ntstatus),
                    static_cast<unsigned long>(err.win32));
                return std::nullopt;
            }
            return hexOut;
        }

        /**
         * @brief Normalize a buffer (PE section extraction or zero-strip) and
         *        return the raw normalized bytes for cryptographic hashing.
         *
         * This mirrors the normalization in HashBufferNormalized() but returns
         * the raw bytes rather than a CTPH digest, so that CompareWithCryptoConfirmation
         * can hash those bytes with SHA-256/SHA-3.
         *
         * @param data   Input buffer
         * @return Normalized bytes.  Falls back to the original data on parse failure.
         *         Returns empty span only when input is empty.
         */
        [[nodiscard]] std::vector<uint8_t> NormalizeForCrypto(
            std::span<const uint8_t> data
        ) noexcept {
            if (data.empty()) {
                return {};
            }

            try {
                // Auto-detect PE
                const bool looksLikePE =
                    (data.size() >= 2 && data[0] == 0x4D && data[1] == 0x5A);

                if (looksLikePE) {
                    ShadowStrike::PEParser::PEParser parser;
                    ShadowStrike::PEParser::PEInfo   info{};
                    ShadowStrike::PEParser::PEError  peErr{};

                    if (parser.ParseBuffer(data, info, &peErr)) {
                        std::vector<uint8_t> codeBytes = ExtractCodeSections(data, info);
                        if (!codeBytes.empty()) {
                            return codeBytes;
                        }
                    }
                    // PE parse failed or no code sections — use full buffer.
                    return std::vector<uint8_t>(data.begin(), data.end());
                }

                // Non-PE: strip trailing zero-padding.
                const size_t effectiveLen = EffectiveLengthAfterZeroStrip(data);
                return std::vector<uint8_t>(data.begin(), data.begin() + effectiveLen);

            } catch (...) {
                SS_LOG_ERROR(L"FuzzyHasher",
                    L"NormalizeForCrypto: unexpected exception — returning full buffer");
                return std::vector<uint8_t>(data.begin(), data.end());
            }
        }

    } // anonymous namespace

    // =========================================================================
    // Core API
    // =========================================================================

    std::optional<std::string> HashBuffer(std::span<const uint8_t> data) noexcept {
        // BUG-3 FIX: enforce a maximum input size to prevent CPU/memory DoS.
        if (data.empty()) {
            SS_LOG_WARN(L"FuzzyHasher", L"HashBuffer called with empty input");
            return std::nullopt;
        }
        if (data.size() > kMaxHashableSize) {
            SS_LOG_WARN(L"FuzzyHasher",
                L"HashBuffer input too large (%zu bytes, max %zu) — rejected",
                data.size(), kMaxHashableSize);
            return std::nullopt;
        }
        return GenerateDigest(data);
    }

    int HashBufferRaw(
        const uint8_t* buf,
        uint32_t       buf_len,
        char*          result
    ) noexcept {
        if (!buf || buf_len == 0 || !result) {
            return -1;
        }
        // BUG-3 FIX: buf_len is uint32_t (max ~4 GB) but kMaxHashableSize is 200 MB.
        if (static_cast<size_t>(buf_len) > kMaxHashableSize) {
            SS_LOG_WARN(L"FuzzyHasher",
                L"HashBufferRaw input too large (%u bytes, max %zu) — rejected",
                buf_len, kMaxHashableSize);
            return -1;
        }
        return GenerateDigestRaw(buf, buf_len, result);
    }

    int Compare(const char* digest1, const char* digest2) noexcept {
        if (!digest1 || !digest2) {
            return -1;
        }
        // BUG-3 FIX: strnlen-bound before any further scanning.
        // CompareDigests also applies this check, but we guard here at the
        // public boundary for defence-in-depth.
        if (strnlen(digest1, kMaxDigestStringLength + 1) > kMaxDigestStringLength ||
            strnlen(digest2, kMaxDigestStringLength + 1) > kMaxDigestStringLength) {
            SS_LOG_WARN(L"FuzzyHasher",
                L"Compare: digest string exceeds kMaxDigestStringLength (%zu) — rejected",
                kMaxDigestStringLength);
            return -1;
        }
        return CompareDigests(digest1, digest2);
    }

    int Compare(const std::string& digest1, const std::string& digest2) noexcept {
        if (digest1.empty() || digest2.empty()) {
            return -1;
        }
        if (digest1.size() > kMaxDigestStringLength ||
            digest2.size() > kMaxDigestStringLength) {
            SS_LOG_WARN(L"FuzzyHasher",
                L"Compare: digest string exceeds kMaxDigestStringLength (%zu) — rejected",
                kMaxDigestStringLength);
            return -1;
        }
        return CompareDigests(digest1.c_str(), digest2.c_str());
    }

    // =========================================================================
    // APT-Hardening Extensions
    // =========================================================================

    NormalizedHashResult HashBufferNormalized(
        std::span<const uint8_t> data,
        bool                     isPE
    ) noexcept {
        NormalizedHashResult out;

        if (data.empty() || data.size() > kMaxHashableSize) {
            SS_LOG_WARN(L"FuzzyHasher",
                L"HashBufferNormalized: invalid input size (%zu bytes)", data.size());
            return out;
        }

        try {
            // Auto-detect PE via MZ magic (0x4D 0x5A = 'MZ') if hint not given.
            const bool looksLikePE = isPE ||
                (data.size() >= 2 && data[0] == 0x4D && data[1] == 0x5A);

            if (looksLikePE) {
                // Compute full-file hash as a secondary reference.
                out.fullFileDigest = GenerateDigest(data);

                // Attempt PE parsing to extract code sections.
                ShadowStrike::PEParser::PEParser parser;
                ShadowStrike::PEParser::PEInfo   info{};
                ShadowStrike::PEParser::PEError  peErr{};

                if (parser.ParseBuffer(data, info, &peErr)) {
                    std::vector<uint8_t> codeBytes = ExtractCodeSections(data, info);

                    if (!codeBytes.empty()) {
                        out.normalizedDigest = GenerateDigest(
                            std::span<const uint8_t>(codeBytes)
                        );
                        out.sha256Hex = ComputeCryptoHashHex(
                            std::span<const uint8_t>(codeBytes),
                            ShadowStrike::Utils::HashUtils::Algorithm::SHA256
                        );
                        out.wasNormalized = true;
                        SS_LOG_DEBUG(L"FuzzyHasher",
                            L"HashBufferNormalized: PE code-section extraction "
                            L"succeeded (%zu bytes from %zu sections)",
                            codeBytes.size(), info.sections.size());
                        return out;
                    }

                    SS_LOG_DEBUG(L"FuzzyHasher",
                        L"HashBufferNormalized: PE parsed but no executable sections "
                        L"found — falling back to full-file hash");
                } else {
                    SS_LOG_DEBUG(L"FuzzyHasher",
                        L"HashBufferNormalized: PE parse failed (%ls) — "
                        L"falling back to full-file hash",
                        peErr.message.c_str());
                }

                // PE normalization failed — use full-file hash as normalizedDigest.
                out.normalizedDigest = out.fullFileDigest;
                out.sha256Hex = ComputeCryptoHashHex(
                    data,
                    ShadowStrike::Utils::HashUtils::Algorithm::SHA256
                );
                return out;
            }

            // Non-PE path: strip trailing zero-padding.
            const size_t effectiveLen = EffectiveLengthAfterZeroStrip(data);
            if (effectiveLen < data.size()) {
                const auto trimmed = data.subspan(0, effectiveLen);
                out.normalizedDigest = GenerateDigest(trimmed);
                out.sha256Hex = ComputeCryptoHashHex(
                    trimmed,
                    ShadowStrike::Utils::HashUtils::Algorithm::SHA256
                );
                out.wasNormalized = true;
                SS_LOG_DEBUG(L"FuzzyHasher",
                    L"HashBufferNormalized: stripped %zu trailing zero bytes "
                    L"(original=%zu, effective=%zu)",
                    data.size() - effectiveLen, data.size(), effectiveLen);
            } else {
                out.normalizedDigest = GenerateDigest(data);
                out.sha256Hex = ComputeCryptoHashHex(
                    data,
                    ShadowStrike::Utils::HashUtils::Algorithm::SHA256
                );
            }

        } catch (...) {
            SS_LOG_ERROR(L"FuzzyHasher",
                L"HashBufferNormalized: unexpected exception during normalization");
        }

        return out;
    }

    std::optional<std::string> HashWithSalt(
        std::span<const uint8_t> data,
        uint64_t                 salt
    ) noexcept {
        if (data.empty() || data.size() > kMaxHashableSize) {
            SS_LOG_WARN(L"FuzzyHasher",
                L"HashWithSalt: invalid input size (%zu bytes)", data.size());
            return std::nullopt;
        }

        // Callers that pass salt == 0 get the module-level session salt.
        const uint64_t effectiveSalt = (salt != 0) ? salt : SessionSalt();

        return GenerateDigestWithSalt(data, effectiveSalt);
    }

    bool IsSuspiciousDigest(const std::string& digest) noexcept {
        try {
            if (digest.empty() || digest.size() > kMaxDigestStringLength) {
                return true; // Empty or oversized is always suspicious
            }

            // Parse the digest to extract its components.
            const char* raw = digest.c_str();

            // Locate first colon
            const char* colon1 = std::strchr(raw, ':');
            if (!colon1 || colon1 == raw) return true;

            // Parse blocksize
            char* endPtr = nullptr;
            const unsigned long long bsLong = std::strtoull(raw, &endPtr, 10);
            if (endPtr != colon1 || bsLong == 0 || bsLong > 0xFFFFFFFFULL) return true;
            const uint32_t blockSize = static_cast<uint32_t>(bsLong);

            // Locate second colon
            const char* hash1Start = colon1 + 1;
            const char* colon2 = std::strchr(hash1Start, ':');
            if (!colon2) return true;

            const std::string_view sig1(hash1Start,
                                        static_cast<size_t>(colon2 - hash1Start));
            const std::string_view sig2(colon2 + 1);

            // CHECK 1: blocksize must be 3 * 2^n (i.e., a power-of-2 multiple of
            // kMinBlockSize).  Legitimate CTPH always selects blocksize by doubling
            // from 3.  A blocksize that is not of this form indicates a crafted digest.
            {
                uint32_t bs = blockSize;
                if (bs % 3 != 0) return true; // Not a multiple of 3
                bs /= 3;
                // bs must now be a power of two (or 1)
                if (bs == 0 || (bs & (bs - 1)) != 0) return true;
            }

            // CHECK 2: signature component lengths must be >= kRollingWindowSize (7).
            // Signatures shorter than the rolling window can never satisfy
            // HasCommonSubstring and will always score 0, yet a crafted digest
            // with length just at this boundary might trigger edge-case behaviour.
            constexpr size_t kMinSigLen = 7; // kRollingWindowSize from RollingHash.hpp
            if (sig1.size() < kMinSigLen || sig2.size() < kMinSigLen) {
                return true;
            }

            // CHECK 3: all-identical-character signature — score inflation attack.
            // A signature like "AAAAAAAAAAAAAAAAAA" scores 100 against any file
            // that contains a run of bytes mapping to the same Base64 character.
            auto allSameChar = [](std::string_view s) noexcept -> bool {
                if (s.empty()) return false;
                const char first = s[0];
                for (char c : s) {
                    if (c != first) return false;
                }
                return true;
            };

            if (allSameChar(sig1) || allSameChar(sig2)) {
                return true;
            }

            return false;

        } catch (...) {
            return true; // Treat exceptions as suspicious
        }
    }

    std::vector<BatchCompareEntry> BatchCompare(
        std::span<const std::string> candidates,
        const std::string&           target
    ) noexcept {
        std::vector<BatchCompareEntry> results;

        if (candidates.empty() || target.empty()) {
            return results;
        }
        if (target.size() > kMaxDigestStringLength) {
            SS_LOG_WARN(L"FuzzyHasher",
                L"BatchCompare: target digest exceeds kMaxDigestStringLength — rejected");
            return results;
        }

        try {
            results.reserve(candidates.size());

            for (size_t i = 0; i < candidates.size(); ++i) {
                const std::string& cand = candidates[i];
                if (cand.empty() || cand.size() > kMaxDigestStringLength) {
                    continue;
                }

                const int score = CompareDigests(target.c_str(), cand.c_str());
                if (score > 0) {
                    results.push_back(BatchCompareEntry{ i, score });
                }
            }

            // Sort by score descending so callers get the best matches first.
            std::sort(results.begin(), results.end(),
                [](const BatchCompareEntry& a, const BatchCompareEntry& b) noexcept {
                    return a.score > b.score;
                });

        } catch (...) {
            SS_LOG_ERROR(L"FuzzyHasher",
                L"BatchCompare: unexpected exception during batch comparison");
        }

        return results;
    }

    CryptoConfirmResult CompareWithCryptoConfirmation(
        std::span<const uint8_t> buf1,
        std::span<const uint8_t> buf2,
        int                      threshold
    ) noexcept {
        CryptoConfirmResult result;

        // Validate inputs — reuse the same size cap as HashBuffer.
        if (buf1.empty() || buf2.empty()) {
            SS_LOG_WARN(L"FuzzyHasher",
                L"CompareWithCryptoConfirmation: one or both input buffers are empty");
            return result; // fuzzyScore == -1
        }
        if (buf1.size() > kMaxHashableSize || buf2.size() > kMaxHashableSize) {
            SS_LOG_WARN(L"FuzzyHasher",
                L"CompareWithCryptoConfirmation: input exceeds kMaxHashableSize "
                L"(buf1=%zu, buf2=%zu, max=%zu)",
                buf1.size(), buf2.size(), kMaxHashableSize);
            return result;
        }

        try {
            // ----------------------------------------------------------------
            // Step 1: Normalize both buffers independently.
            //         NormalizeForCrypto() applies the same PE section
            //         extraction / zero-strip as HashBufferNormalized(), and
            //         returns the raw bytes so we can both fuzzy-hash and
            //         crypto-hash them from the same normalized representation.
            // ----------------------------------------------------------------
            const std::vector<uint8_t> norm1 = NormalizeForCrypto(buf1);
            const std::vector<uint8_t> norm2 = NormalizeForCrypto(buf2);

            if (norm1.empty() || norm2.empty()) {
                SS_LOG_ERROR(L"FuzzyHasher",
                    L"CompareWithCryptoConfirmation: normalization returned empty buffer");
                return result;
            }

            // ----------------------------------------------------------------
            // Step 2: Fuzzy comparison on normalized content.
            // ----------------------------------------------------------------
            const auto dig1 = GenerateDigest(std::span<const uint8_t>(norm1));
            const auto dig2 = GenerateDigest(std::span<const uint8_t>(norm2));

            if (!dig1.has_value() || !dig2.has_value()) {
                SS_LOG_ERROR(L"FuzzyHasher",
                    L"CompareWithCryptoConfirmation: digest generation failed");
                return result;
            }

            result.fuzzyScore = CompareDigests(dig1->c_str(), dig2->c_str());
            if (result.fuzzyScore < 0) {
                SS_LOG_WARN(L"FuzzyHasher",
                    L"CompareWithCryptoConfirmation: CompareDigests returned error");
                result.fuzzyScore = -1;
                return result;
            }

            // ----------------------------------------------------------------
            // Step 3: Cryptographic confirmation — only when fuzzy score meets
            //         threshold.  Skip on low-confidence matches for performance.
            // ----------------------------------------------------------------
            if (result.fuzzyScore < threshold) {
                SS_LOG_DEBUG(L"FuzzyHasher",
                    L"CompareWithCryptoConfirmation: fuzzyScore=%d < threshold=%d, "
                    L"skipping crypto pass",
                    result.fuzzyScore, threshold);
                return result; // cryptoRan stays false
            }

            // Determine best available algorithm (SHA-3-256 or SHA-256 fallback),
            // probed once at process start and cached.
            result.algorithm = PickCryptoAlgorithm();
            const auto huAlg = ToHashUtilsAlg(result.algorithm);

            result.hash1Hex = ComputeCryptoHashHex(
                std::span<const uint8_t>(norm1), huAlg);
            result.hash2Hex = ComputeCryptoHashHex(
                std::span<const uint8_t>(norm2), huAlg);

            if (!result.hash1Hex.has_value() || !result.hash2Hex.has_value()) {
                SS_LOG_ERROR(L"FuzzyHasher",
                    L"CompareWithCryptoConfirmation: cryptographic hash computation "
                    L"failed (alg=%u)", static_cast<unsigned>(result.algorithm));
                // Fuzzy score is still valid; crypto result is indeterminate.
                result.cryptoRan = false;
                return result;
            }

            result.cryptoRan = true;

            // Constant-time comparison via HashUtils::Equal to prevent timing
            // side-channels when the hashes differ by only a few bytes.
            // Both hashes are hex strings of equal length (64 hex chars for 32-byte
            // digests); length equality is verified first.
            if (result.hash1Hex->size() == result.hash2Hex->size()) {
                result.exactMatch = ShadowStrike::Utils::HashUtils::Equal(
                    reinterpret_cast<const uint8_t*>(result.hash1Hex->data()),
                    reinterpret_cast<const uint8_t*>(result.hash2Hex->data()),
                    result.hash1Hex->size()
                );
            } else {
                // Digest length mismatch — hash computation error; treat as no match.
                result.exactMatch = false;
                SS_LOG_ERROR(L"FuzzyHasher",
                    L"CompareWithCryptoConfirmation: hash hex length mismatch "
                    L"(%zu vs %zu) — exactMatch forced false",
                    result.hash1Hex->size(), result.hash2Hex->size());
            }

            SS_LOG_DEBUG(L"FuzzyHasher",
                L"CompareWithCryptoConfirmation: fuzzy=%d, exact=%s, alg=%s",
                result.fuzzyScore,
                result.exactMatch ? L"true" : L"false",
                result.algorithm == CryptoAlgorithm::SHA3_256 ? L"SHA3-256" : L"SHA-256");

        } catch (...) {
            SS_LOG_ERROR(L"FuzzyHasher",
                L"CompareWithCryptoConfirmation: unexpected exception");
        }

        return result;
    }

} // namespace ShadowStrike::FuzzyHasher
