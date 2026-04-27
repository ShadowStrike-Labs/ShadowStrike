/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SIMDEngine — Host-CPU SIMD-accelerated primitives for emulation analysis
 *
 * Provides AVX2/SSE4.2/SSE2 optimized routines for entropy calculation,
 * pattern matching, CRC checksumming, and memory analysis. All functions
 * include scalar fallbacks for compatibility.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "SIMDEngine.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>

#if defined(_MSC_VER)
#include <intrin.h>
#include <nmmintrin.h>   // SSE4.2
#include <immintrin.h>   // AVX2
#endif

namespace Phantom {

// ============================================================================
// CRC32C Software Lookup Table (Castagnoli polynomial 0x1EDC6F41)
// ============================================================================

namespace {

constexpr std::array<uint32_t, 256> BuildCRC32CTable() noexcept {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1u) {
                crc = (crc >> 1) ^ 0x82F63B78u;
            } else {
                crc >>= 1;
            }
        }
        table.at(i) = crc;
    }
    return table;
}

constexpr auto kCRC32CTable = BuildCRC32CTable();

// Minimum data length to consider for single-byte XOR detection
constexpr size_t kMinXORDetectLength    = 16;
// Minimum printable ASCII ratio to accept a candidate key
constexpr double kMinPrintableRatio     = 0.70;
// Minimum ratio advantage over the next-best key
constexpr double kMinKeyAdvantage       = 0.05;
constexpr size_t kMaxDirectScanBytes    = 64ULL * 1024ULL * 1024ULL;
constexpr size_t kMaxXORDetectBytes     = 1ULL * 1024ULL * 1024ULL;
constexpr size_t kMaxPatternCount       = 65536;
constexpr size_t kMaxPatternMatches     = 65536;

[[nodiscard]] bool IsValidSpan(ByteSpan data) noexcept {
    return data.empty() || data.data() != nullptr;
}

[[nodiscard]] ByteSpan CappedSpan(ByteSpan data) noexcept {
    return ByteSpan(data.data(), std::min(data.size(), kMaxDirectScanBytes));
}

} // anonymous namespace

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct SIMDEngine::Impl {
    CPUFeatures features{};

    // -----------------------------------------------------------------------
    // CPUID Detection
    // -----------------------------------------------------------------------
    void DetectFeatures() noexcept {
#if defined(_MSC_VER)
        int cpuInfo[4]{};

        __cpuid(cpuInfo, 0);
        const int maxLeaf = cpuInfo[0];

        if (maxLeaf >= 1) {
            __cpuid(cpuInfo, 1);
            const uint32_t ecx = static_cast<uint32_t>(cpuInfo[2]);
            const uint32_t edx = static_cast<uint32_t>(cpuInfo[3]);

            features.sse2       = (edx & (1u << 26)) != 0;
            features.sse41      = (ecx & (1u << 19)) != 0;
            features.sse42      = (ecx & (1u << 20)) != 0;
            features.avx        = (ecx & (1u << 28)) != 0;
            features.aesni      = (ecx & (1u << 25)) != 0;
            features.pclmulqdq  = (ecx & (1u <<  1)) != 0;

            // AVX requires OS XSAVE support (bit 27) + AVX (bit 28)
            if (features.avx) {
                const bool osxsave = (ecx & (1u << 27)) != 0;
                if (osxsave) {
                    // Verify OS has enabled AVX state saving via XGETBV
                    const uint64_t xcr0 = _xgetbv(0);
                    const bool avxOsEnabled = ((xcr0 & 0x6) == 0x6);
                    if (!avxOsEnabled) {
                        features.avx = false;
                    }
                } else {
                    features.avx = false;
                }
            }
        }

        if (maxLeaf >= 7) {
            __cpuidex(cpuInfo, 7, 0);
            const uint32_t ebx = static_cast<uint32_t>(cpuInfo[1]);

            features.avx2  = features.avx && ((ebx & (1u <<  5)) != 0);
            features.bmi1  = (ebx & (1u <<  3)) != 0;
            features.bmi2  = (ebx & (1u <<  8)) != 0;
            features.shani = (ebx & (1u << 29)) != 0;
        }
#else
        // Minimal fallback — no SIMD features detected on non-MSVC
        features = CPUFeatures{};
        features.sse2 = true; // x86-64 guarantees SSE2
#endif
    }

    // -----------------------------------------------------------------------
    // Histogram — scalar (clean and fast enough; vectorised histogram adds
    // complexity with marginal gain for typical malware sample sizes)
    // -----------------------------------------------------------------------
    void BuildHistogramScalar(ByteSpan data,
                              std::array<uint32_t, 256>& histogram) const noexcept {
        histogram.fill(0);

        const uint8_t* ptr = data.data();
        size_t remaining = data.size();

        // Unroll 4× to reduce loop overhead
        while (remaining >= 4) {
            ++histogram[ptr[0]];
            ++histogram[ptr[1]];
            ++histogram[ptr[2]];
            ++histogram[ptr[3]];
            ptr += 4;
            remaining -= 4;
        }
        while (remaining > 0) {
            ++histogram[*ptr++];
            --remaining;
        }
    }

    // -----------------------------------------------------------------------
    // Entropy from histogram
    // -----------------------------------------------------------------------
    [[nodiscard]] double EntropyFromHistogram(
        const std::array<uint32_t, 256>& histogram,
        size_t totalBytes) const noexcept {

        if (totalBytes == 0) return 0.0;

        const double invTotal = 1.0 / static_cast<double>(totalBytes);
        double entropy = 0.0;

        for (uint32_t count : histogram) {
            if (count == 0) continue;
            const double p = static_cast<double>(count) * invTotal;
            entropy -= p * std::log2(p);
        }
        return entropy;
    }

    // -----------------------------------------------------------------------
    // CRC32C — hardware (SSE4.2)
    // -----------------------------------------------------------------------
    [[nodiscard]] uint32_t CRC32CHardware(ByteSpan data) const noexcept {
#if defined(_MSC_VER)
        uint32_t crc = 0xFFFFFFFFu;
        const uint8_t* ptr = data.data();
        size_t remaining = data.size();

        // Process 8 bytes at a time using 64-bit CRC32C instruction
        while (remaining >= 8) {
            uint64_t val;
            std::memcpy(&val, ptr, 8);
            crc = static_cast<uint32_t>(_mm_crc32_u64(crc, val));
            ptr += 8;
            remaining -= 8;
        }

        // Process remaining bytes one at a time
        while (remaining > 0) {
            crc = _mm_crc32_u8(crc, *ptr);
            ++ptr;
            --remaining;
        }

        return crc ^ 0xFFFFFFFFu;
#else
        return CRC32CSoftware(data);
#endif
    }

    // -----------------------------------------------------------------------
    // CRC32C — software LUT
    // -----------------------------------------------------------------------
    [[nodiscard]] uint32_t CRC32CSoftware(ByteSpan data) const noexcept {
        uint32_t crc = 0xFFFFFFFFu;
        const uint8_t* ptr = data.data();
        size_t remaining = data.size();

        while (remaining > 0) {
            crc = kCRC32CTable[static_cast<uint8_t>(crc ^ *ptr)] ^ (crc >> 8);
            ++ptr;
            --remaining;
        }

        return crc ^ 0xFFFFFFFFu;
    }

    // -----------------------------------------------------------------------
    // Pattern Search — AVX2
    // -----------------------------------------------------------------------
    [[nodiscard]] std::optional<size_t> FindPatternAVX2(
        ByteSpan haystack, ByteSpan needle) const noexcept {
#if defined(_MSC_VER)
        if (needle.empty()) return 0;
        if (haystack.size() < needle.size()) return std::nullopt;

        const uint8_t firstByte = needle[0];
        const size_t needleLen = needle.size();
        const size_t searchLimit = haystack.size() - needleLen + 1;

        const __m256i first = _mm256_set1_epi8(static_cast<char>(firstByte));
        size_t i = 0;

        // AVX2: scan 32 bytes at a time for first-byte candidates
        for (; i + 32 <= haystack.size() && i < searchLimit; i += 32) {
            const __m256i chunk = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(&haystack[i]));
            const __m256i cmp = _mm256_cmpeq_epi8(chunk, first);
            uint32_t mask = static_cast<uint32_t>(_mm256_movemask_epi8(cmp));

            while (mask != 0) {
                unsigned long bitPos = 0;
                _BitScanForward(&bitPos, mask);
                const uint32_t bit = static_cast<uint32_t>(bitPos);
                const size_t candidatePos = i + bit;

                if (candidatePos + needleLen <= haystack.size()) {
                    if (std::memcmp(&haystack[candidatePos], needle.data(),
                                    needleLen) == 0) {
                        return candidatePos;
                    }
                }

                mask &= mask - 1; // clear lowest set bit
            }
        }

        // Scalar tail
        for (; i < searchLimit; ++i) {
            if (haystack[i] == firstByte &&
                std::memcmp(&haystack[i], needle.data(), needleLen) == 0) {
                return i;
            }
        }

        return std::nullopt;
#else
        return FindPatternScalar(haystack, needle);
#endif
    }

    // -----------------------------------------------------------------------
    // Pattern Search — SSE2
    // -----------------------------------------------------------------------
    [[nodiscard]] std::optional<size_t> FindPatternSSE2(
        ByteSpan haystack, ByteSpan needle) const noexcept {
#if defined(_MSC_VER)
        if (needle.empty()) return 0;
        if (haystack.size() < needle.size()) return std::nullopt;

        const uint8_t firstByte = needle[0];
        const size_t needleLen = needle.size();
        const size_t searchLimit = haystack.size() - needleLen + 1;

        const __m128i first = _mm_set1_epi8(static_cast<char>(firstByte));
        size_t i = 0;

        for (; i + 16 <= haystack.size() && i < searchLimit; i += 16) {
            const __m128i chunk = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(&haystack[i]));
            const __m128i cmp = _mm_cmpeq_epi8(chunk, first);
            uint32_t mask = static_cast<uint32_t>(_mm_movemask_epi8(cmp));

            while (mask != 0) {
                unsigned long bit;
                _BitScanForward(&bit, mask);
                const size_t candidatePos = i + bit;

                if (candidatePos + needleLen <= haystack.size()) {
                    if (std::memcmp(&haystack[candidatePos], needle.data(),
                                    needleLen) == 0) {
                        return candidatePos;
                    }
                }

                mask &= mask - 1;
            }
        }

        for (; i < searchLimit; ++i) {
            if (haystack[i] == firstByte &&
                std::memcmp(&haystack[i], needle.data(), needleLen) == 0) {
                return i;
            }
        }

        return std::nullopt;
#else
        return FindPatternScalar(haystack, needle);
#endif
    }

    // -----------------------------------------------------------------------
    // Pattern Search — scalar
    // -----------------------------------------------------------------------
    [[nodiscard]] std::optional<size_t> FindPatternScalar(
        ByteSpan haystack, ByteSpan needle) const noexcept {
        if (needle.empty()) return 0;
        if (haystack.size() < needle.size()) return std::nullopt;

        const size_t searchLimit = haystack.size() - needle.size() + 1;
        const uint8_t firstByte = needle[0];
        const size_t needleLen = needle.size();

        for (size_t i = 0; i < searchLimit; ++i) {
            if (haystack[i] == firstByte &&
                std::memcmp(&haystack[i], needle.data(), needleLen) == 0) {
                return i;
            }
        }
        return std::nullopt;
    }

    // -----------------------------------------------------------------------
    // Memory Compare — AVX2
    // -----------------------------------------------------------------------
    [[nodiscard]] bool MemoryEqualAVX2(ByteSpan a, ByteSpan b) const noexcept {
#if defined(_MSC_VER)
        if (a.size() != b.size()) return false;
        if (a.size() == 0) return true;
        if (a.data() == b.data()) return true;

        const uint8_t* pa = a.data();
        const uint8_t* pb = b.data();
        size_t remaining = a.size();

        while (remaining >= 32) {
            const __m256i va = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(pa));
            const __m256i vb = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(pb));
            const __m256i cmp = _mm256_cmpeq_epi8(va, vb);
            if (_mm256_movemask_epi8(cmp) != -1) {
                return false;
            }
            pa += 32;
            pb += 32;
            remaining -= 32;
        }

        // SSE2 tail (16 bytes)
        while (remaining >= 16) {
            const __m128i va = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(pa));
            const __m128i vb = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(pb));
            const __m128i cmp = _mm_cmpeq_epi8(va, vb);
            if (_mm_movemask_epi8(cmp) != 0xFFFF) {
                return false;
            }
            pa += 16;
            pb += 16;
            remaining -= 16;
        }

        // Scalar tail
        return std::memcmp(pa, pb, remaining) == 0;
#else
        return MemoryEqualScalar(a, b);
#endif
    }

    // -----------------------------------------------------------------------
    // Memory Compare — SSE2
    // -----------------------------------------------------------------------
    [[nodiscard]] bool MemoryEqualSSE2(ByteSpan a, ByteSpan b) const noexcept {
#if defined(_MSC_VER)
        if (a.size() != b.size()) return false;
        if (a.size() == 0) return true;
        if (a.data() == b.data()) return true;

        const uint8_t* pa = a.data();
        const uint8_t* pb = b.data();
        size_t remaining = a.size();

        while (remaining >= 16) {
            const __m128i va = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(pa));
            const __m128i vb = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(pb));
            const __m128i cmp = _mm_cmpeq_epi8(va, vb);
            if (_mm_movemask_epi8(cmp) != 0xFFFF) {
                return false;
            }
            pa += 16;
            pb += 16;
            remaining -= 16;
        }

        return std::memcmp(pa, pb, remaining) == 0;
#else
        return MemoryEqualScalar(a, b);
#endif
    }

    // -----------------------------------------------------------------------
    // Memory Compare — scalar
    // -----------------------------------------------------------------------
    [[nodiscard]] bool MemoryEqualScalar(ByteSpan a, ByteSpan b) const noexcept {
        if (a.size() != b.size()) return false;
        if (a.size() == 0) return true;
        if (a.data() == b.data()) return true;
        return std::memcmp(a.data(), b.data(), a.size()) == 0;
    }

    // -----------------------------------------------------------------------
    // XOR Detection — AVX2 (vectorised printable ASCII check)
    // -----------------------------------------------------------------------
    [[nodiscard]] uint32_t CountPrintableAVX2(ByteSpan data,
                                              uint8_t key) const noexcept {
#if defined(_MSC_VER)
        uint32_t printableCount = 0;
        const uint8_t* ptr = data.data();
        size_t remaining = data.size();

        const __m256i vkey     = _mm256_set1_epi8(static_cast<char>(key));
        // Printable ASCII: 0x20..0x7E
        const __m256i lo_bound = _mm256_set1_epi8(0x1F);   // < 0x20
        const __m256i hi_bound = _mm256_set1_epi8(0x7E);

        while (remaining >= 32) {
            const __m256i chunk = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(ptr));
            const __m256i decoded = _mm256_xor_si256(chunk, vkey);

            // decoded > 0x1F  → cmpgt(decoded, lo_bound) gives 0xFF where true
            // decoded <= 0x7E → cmpgt(hi_bound, decoded) | cmpeq(decoded, hi_bound)
            //                   but simpler: NOT cmpgt(decoded, hi_bound)
            const __m256i above_lo = _mm256_cmpgt_epi8(decoded, lo_bound);
            const __m256i above_hi = _mm256_cmpgt_epi8(decoded, hi_bound);
            // Printable = above_lo AND NOT above_hi
            const __m256i printable = _mm256_andnot_si256(above_hi, above_lo);

            const uint32_t mask = static_cast<uint32_t>(
                _mm256_movemask_epi8(printable));
            printableCount += PHANTOM_POPCOUNT32(mask);

            ptr += 32;
            remaining -= 32;
        }

        // Scalar tail
        while (remaining > 0) {
            const uint8_t decoded = *ptr ^ key;
            if (decoded >= 0x20 && decoded <= 0x7E) {
                ++printableCount;
            }
            ++ptr;
            --remaining;
        }

        return printableCount;
#else
        return CountPrintableScalar(data, key);
#endif
    }

    // -----------------------------------------------------------------------
    // XOR Detection — scalar printable count
    // -----------------------------------------------------------------------
    [[nodiscard]] uint32_t CountPrintableScalar(ByteSpan data,
                                                uint8_t key) const noexcept {
        uint32_t count = 0;
        for (size_t i = 0; i < data.size(); ++i) {
            const uint8_t decoded = data[i] ^ key;
            if (decoded >= 0x20 && decoded <= 0x7E) {
                ++count;
            }
        }
        return count;
    }
};

// ============================================================================
// SIMDEngine — Public API Implementation
// ============================================================================

SIMDEngine::SIMDEngine() noexcept
{
    try {
        m_impl = std::make_unique<Impl>();
        m_impl->DetectFeatures();
    } catch (const std::bad_alloc&) {
        m_impl.reset();
    } catch (const std::length_error&) {
        m_impl.reset();
    }
}

SIMDEngine::~SIMDEngine() noexcept = default;

SIMDEngine::SIMDEngine(SIMDEngine&&) noexcept = default;
SIMDEngine& SIMDEngine::operator=(SIMDEngine&&) noexcept = default;

// ----------------------------------------------------------------------------
// Feature queries
// ----------------------------------------------------------------------------

bool SIMDEngine::HasSSE2()      const noexcept { return m_impl && m_impl->features.sse2; }
bool SIMDEngine::HasSSE41()     const noexcept { return m_impl && m_impl->features.sse41; }
bool SIMDEngine::HasSSE42()     const noexcept { return m_impl && m_impl->features.sse42; }
bool SIMDEngine::HasAVX()       const noexcept { return m_impl && m_impl->features.avx; }
bool SIMDEngine::HasAVX2()      const noexcept { return m_impl && m_impl->features.avx2; }
bool SIMDEngine::HasAESNI()     const noexcept { return m_impl && m_impl->features.aesni; }
bool SIMDEngine::HasSHANI()     const noexcept { return m_impl && m_impl->features.shani; }
bool SIMDEngine::HasPCLMULQDQ() const noexcept { return m_impl && m_impl->features.pclmulqdq; }
bool SIMDEngine::HasBMI1()      const noexcept { return m_impl && m_impl->features.bmi1; }
bool SIMDEngine::HasBMI2()      const noexcept { return m_impl && m_impl->features.bmi2; }

const CPUFeatures& SIMDEngine::GetFeatures() const noexcept {
    static constexpr CPUFeatures kNoFeatures{};
    return m_impl ? m_impl->features : kNoFeatures;
}

// ----------------------------------------------------------------------------
// Entropy Calculation
// ----------------------------------------------------------------------------

double SIMDEngine::CalculateEntropy(ByteSpan data) const noexcept {
    if (data.empty()) return 0.0;
    if (!m_impl || !IsValidSpan(data)) return 0.0;
    data = CappedSpan(data);

    std::array<uint32_t, 256> histogram{};
    BuildHistogram(data, histogram);
    return m_impl->EntropyFromHistogram(histogram, data.size());
}

// ----------------------------------------------------------------------------
// Byte Frequency Histogram
// ----------------------------------------------------------------------------

void SIMDEngine::BuildHistogram(ByteSpan data,
                                std::array<uint32_t, 256>& histogram) const noexcept {
    if (!m_impl || !IsValidSpan(data)) {
        histogram.fill(0);
        return;
    }
    data = CappedSpan(data);
    m_impl->BuildHistogramScalar(data, histogram);
}

// ----------------------------------------------------------------------------
// CRC32C
// ----------------------------------------------------------------------------

uint32_t SIMDEngine::CRC32C(ByteSpan data) const noexcept {
    if (data.empty()) return 0u;
    if (!m_impl || !IsValidSpan(data)) return 0u;

    if (m_impl->features.sse42) {
        return m_impl->CRC32CHardware(data);
    }
    return m_impl->CRC32CSoftware(data);
}

// ----------------------------------------------------------------------------
// Pattern Search (single)
// ----------------------------------------------------------------------------

std::optional<size_t> SIMDEngine::FindPattern(ByteSpan haystack,
                                               ByteSpan needle) const noexcept {
    if (needle.empty()) return 0;
    if (!m_impl || !IsValidSpan(haystack) || !IsValidSpan(needle)) return std::nullopt;
    haystack = CappedSpan(haystack);
    if (haystack.size() < needle.size()) return std::nullopt;

    if (m_impl->features.avx2) {
        return m_impl->FindPatternAVX2(haystack, needle);
    }
    if (m_impl->features.sse2) {
        return m_impl->FindPatternSSE2(haystack, needle);
    }
    return m_impl->FindPatternScalar(haystack, needle);
}

// ----------------------------------------------------------------------------
// Multi-Pattern Search
// ----------------------------------------------------------------------------

std::vector<std::pair<size_t, uint32_t>> SIMDEngine::FindPatterns(
    ByteSpan data,
    std::span<const ByteSpan> patterns) const noexcept {

    std::vector<std::pair<size_t, uint32_t>> results;

    if (data.empty() || patterns.empty()) return results;
    if (!m_impl || !IsValidSpan(data) || patterns.data() == nullptr) return results;
    data = CappedSpan(data);
    try {
        results.reserve(kMaxPatternMatches);
    } catch (const std::bad_alloc&) {
        return results;
    } catch (const std::length_error&) {
        return results;
    }

    // Guard against pathological inputs
    const size_t patternCount = (std::min)(patterns.size(),
                                           kMaxPatternCount);

    // Build first-byte lookup: for each possible byte value, which patterns
    // start with it? This avoids O(patterns × data) first-byte checks.
    std::array<std::vector<uint32_t>, 256> firstByteBuckets{};
    try {
        for (size_t pi = 0; pi < patternCount; ++pi) {
            if (patterns[pi].empty() || !IsValidSpan(patterns[pi])) continue;
            if (patterns[pi].size() > data.size()) continue;
            firstByteBuckets[patterns[pi][0]].push_back(static_cast<uint32_t>(pi));
        }
    } catch (const std::bad_alloc&) {
        return results;
    } catch (const std::length_error&) {
        return results;
    }

    // Determine minimum pattern length for SIMD scanning
    size_t minPatternLen = (std::numeric_limits<size_t>::max)();
    for (size_t pi = 0; pi < patternCount; ++pi) {
        if (!patterns[pi].empty() && IsValidSpan(patterns[pi]) && patterns[pi].size() <= data.size()) {
            minPatternLen = (std::min)(minPatternLen, patterns[pi].size());
        }
    }
    if (minPatternLen == (std::numeric_limits<size_t>::max)()) return results;

#if defined(_MSC_VER)
    if (m_impl->features.avx2) {
        // AVX2 path: scan 32 bytes at a time, check each first-byte hit
        size_t i = 0;
        for (; i + 32 <= data.size(); i += 32) {
            const __m256i chunk = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(&data[i]));

            // For each unique first byte that at least one pattern starts with,
            // do a SIMD compare. To avoid 256 compares, iterate only occupied buckets.
            for (uint32_t fb = 0; fb < 256; ++fb) {
                if (firstByteBuckets[fb].empty()) continue;

                const __m256i target = _mm256_set1_epi8(
                    static_cast<char>(static_cast<uint8_t>(fb)));
                const __m256i cmp = _mm256_cmpeq_epi8(chunk, target);
                uint32_t mask = static_cast<uint32_t>(
                    _mm256_movemask_epi8(cmp));

                while (mask != 0) {
                    unsigned long bitPos = 0;
                    _BitScanForward(&bitPos, mask);
                    const uint32_t bit = static_cast<uint32_t>(bitPos);
                    const size_t pos = i + bit;

                    for (uint32_t pi : firstByteBuckets[fb]) {
                        const ByteSpan& pat = patterns[pi];
                        if (pos + pat.size() <= data.size() &&
                            std::memcmp(&data[pos], pat.data(),
                                        pat.size()) == 0) {
                            results.emplace_back(pos, pi);
                            if (results.size() >= kMaxPatternMatches) return results;
                        }
                    }

                    mask &= mask - 1;
                }
            }
        }

        // Scalar tail
        for (; i < data.size(); ++i) {
            const auto& bucket = firstByteBuckets[data[i]];
            for (uint32_t pi : bucket) {
                const ByteSpan& pat = patterns[pi];
                if (i + pat.size() <= data.size() &&
                    std::memcmp(&data[i], pat.data(), pat.size()) == 0) {
                    results.emplace_back(i, pi);
                    if (results.size() >= kMaxPatternMatches) return results;
                }
            }
        }

        return results;
    }
#endif

    // Scalar fallback
    for (size_t i = 0; i < data.size(); ++i) {
        const auto& bucket = firstByteBuckets[data[i]];
        for (uint32_t pi : bucket) {
            const ByteSpan& pat = patterns[pi];
            if (i + pat.size() <= data.size() &&
                std::memcmp(&data[i], pat.data(), pat.size()) == 0) {
                results.emplace_back(i, pi);
                if (results.size() >= kMaxPatternMatches) return results;
            }
        }
    }

    return results;
}

// ----------------------------------------------------------------------------
// Memory Compare
// ----------------------------------------------------------------------------

bool SIMDEngine::MemoryEqual(ByteSpan a, ByteSpan b) const noexcept {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    if (!m_impl || !IsValidSpan(a) || !IsValidSpan(b)) return false;

    if (m_impl->features.avx2) {
        return m_impl->MemoryEqualAVX2(a, b);
    }
    if (m_impl->features.sse2) {
        return m_impl->MemoryEqualSSE2(a, b);
    }
    return m_impl->MemoryEqualScalar(a, b);
}

// ----------------------------------------------------------------------------
// Single-Byte XOR Detection
// ----------------------------------------------------------------------------

std::optional<uint8_t> SIMDEngine::DetectSingleByteXOR(
    ByteSpan data) const noexcept {

    if (data.size() < kMinXORDetectLength) return std::nullopt;
    if (!m_impl || !IsValidSpan(data)) return std::nullopt;
    data = CappedSpan(data);
    data = ByteSpan(data.data(), std::min(data.size(), kMaxXORDetectBytes));

    uint8_t  bestKey       = 0;
    uint32_t bestCount     = 0;
    uint32_t secondBest    = 0;
    double   bestScore     = -std::numeric_limits<double>::infinity();
    double   secondScore   = -std::numeric_limits<double>::infinity();

    const auto scoreDecoded = [](uint8_t ch) noexcept -> double {
        if (ch >= 'a' && ch <= 'z') {
            switch (ch) {
            case 'e': case 't': case 'a': case 'o': case 'i': case 'n':
            case 's': case 'h': case 'r':
                return 1.55;
            default:
                return 1.25;
            }
        }
        if (ch >= 'A' && ch <= 'Z') return 1.15;
        if (ch >= '0' && ch <= '9') return 0.95;
        if (ch == ' ') return 1.75;
        if (ch == '.' || ch == ',' || ch == '-' || ch == '_' || ch == ':' ||
            ch == ';' || ch == '/' || ch == '\\' || ch == '\'' || ch == '"') {
            return 0.75;
        }
        if (ch == '\r' || ch == '\n' || ch == '\t') return 0.35;
        if (ch >= 0x20 && ch <= 0x7E) return 0.25;
        return -2.5;
    };

    // Key 0x00 is identity XOR — skip it (no encoding)
    for (uint32_t key = 1; key < 256; ++key) {
        uint32_t count = 0;
        double score = 0.0;
        for (uint8_t byte : data) {
            const uint8_t decoded = static_cast<uint8_t>(byte ^ static_cast<uint8_t>(key));
            if ((decoded >= 0x20 && decoded <= 0x7E) ||
                decoded == '\r' || decoded == '\n' || decoded == '\t') {
                ++count;
            }
            score += scoreDecoded(decoded);
        }

        if (score > bestScore) {
            secondBest = bestCount;
            secondScore = bestScore;
            bestCount  = count;
            bestKey    = static_cast<uint8_t>(key);
            bestScore  = score;
        } else if (score > secondScore) {
            secondBest = count;
            secondScore = score;
        }
    }

    // Validate: the best key must yield enough printable bytes
    const double bestRatio = static_cast<double>(bestCount) /
                             static_cast<double>(data.size());

    if (bestRatio < kMinPrintableRatio) return std::nullopt;

    // Require meaningful separation from the second-best key
    const double secondRatio = static_cast<double>(secondBest) /
                               static_cast<double>(data.size());

    const double scoreAdvantage =
        (bestScore - secondScore) / static_cast<double>(data.size());

    if ((bestRatio - secondRatio < kMinKeyAdvantage) &&
        scoreAdvantage < kMinKeyAdvantage) {
        return std::nullopt;
    }

    return bestKey;
}

} // namespace Phantom
