/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MemoryScanAccel — SIMD-accelerated memory analysis for emulation
 *
 * Provides high-speed page entropy scanning, shellcode pattern detection,
 * ROP gadget discovery, and packed region identification. Uses AVX2/SSE4.2
 * intrinsics for pattern matching with scalar fallbacks.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "MemoryScanAccel.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"
#include "../Memory/VirtualMemory.hpp"

#include <intrin.h>
#include <immintrin.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>

namespace Phantom {

// ============================================================================
// CPUID Feature Detection
// ============================================================================

struct SIMDCapabilities {
    bool hasSSE2  = false;
    bool hasSSE42 = false;
    bool hasAVX2  = false;

    SIMDCapabilities() noexcept {
        std::array<int, 4> cpuInfo{};

        __cpuid(cpuInfo.data(), 0);
        const int maxLeaf = cpuInfo[0];

        if (maxLeaf >= 1) {
            __cpuid(cpuInfo.data(), 1);
            hasSSE2  = (cpuInfo[3] & (1 << 26)) != 0;
            hasSSE42 = (cpuInfo[2] & (1 << 20)) != 0;
        }

        if (maxLeaf >= 7) {
            __cpuidex(cpuInfo.data(), 7, 0);
            hasAVX2 = (cpuInfo[1] & (1 << 5)) != 0;
        }

        // AVX2 requires OS XSAVE support — verify via XGETBV
        if (hasAVX2) {
            std::array<int, 4> leaf1{};
            __cpuid(leaf1.data(), 1);
            const bool osxsave = (leaf1[2] & (1 << 27)) != 0;
            if (osxsave) {
                const unsigned long long xcr0 = _xgetbv(0);
                // Both XMM (bit 1) and YMM (bit 2) state must be enabled
                if ((xcr0 & 0x6) != 0x6) {
                    hasAVX2 = false;
                }
            } else {
                hasAVX2 = false;
            }
        }
    }
};

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct MemoryScanAccel::Impl {
    SIMDCapabilities simd;

    // Caps to prevent unbounded allocations in result vectors
    static constexpr uint32_t kMaxEntropyEntries   = 131072; // 512 MB / 4 KB
    static constexpr uint32_t kMaxShellcodeMatches  = 4096;
    static constexpr uint32_t kMaxROPGadgets        = 16384;
    static constexpr uint32_t kMaxPackedRegions     = 1024;

    // ========================================================================
    // Shannon Entropy — scalar (sufficient for 4 KB pages)
    // ========================================================================

    [[nodiscard]] static double ComputeEntropy(const uint8_t* data, size_t len) noexcept {
        if (len == 0) return 0.0;

        std::array<uint32_t, 256> histogram{};
        for (size_t i = 0; i < len; ++i) {
            ++histogram[data[i]];
        }

        const double invLen = 1.0 / static_cast<double>(len);
        double entropy = 0.0;
        for (uint32_t count : histogram) {
            if (count == 0) continue;
            const double p = static_cast<double>(count) * invLen;
            entropy -= p * std::log2(p);
        }
        return entropy;
    }

    // ========================================================================
    // SIMD Pattern Search — AVX2 first-byte filter + scalar verify
    // ========================================================================

    [[nodiscard]] std::vector<size_t> FindPatternAVX2(
        const uint8_t* data, size_t dataLen,
        const uint8_t* pat, size_t patLen) const noexcept
    {
        std::vector<size_t> results;
        if (patLen == 0 || dataLen < patLen) return results;

        const size_t searchLen = dataLen - patLen + 1;
        const __m256i firstByte = _mm256_set1_epi8(static_cast<char>(pat[0]));
        size_t i = 0;

        for (; i + 32 <= searchLen; i += 32) {
            const __m256i block = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(data + i));
            const __m256i cmp = _mm256_cmpeq_epi8(block, firstByte);
            uint32_t mask = static_cast<uint32_t>(_mm256_movemask_epi8(cmp));

            while (mask != 0) {
                unsigned long bitPos = 0;
                _BitScanForward(&bitPos, mask);
                const size_t candidateIdx = i + bitPos;
                if (candidateIdx + patLen <= dataLen) {
                    if (std::memcmp(data + candidateIdx, pat, patLen) == 0) {
                        results.push_back(candidateIdx);
                        if (results.size() >= kMaxShellcodeMatches) return results;
                    }
                }
                mask &= mask - 1; // clear lowest set bit
            }
        }

        // Scalar tail
        for (; i < searchLen; ++i) {
            if (data[i] == pat[0] && i + patLen <= dataLen) {
                if (std::memcmp(data + i, pat, patLen) == 0) {
                    results.push_back(i);
                    if (results.size() >= kMaxShellcodeMatches) return results;
                }
            }
        }
        return results;
    }

    [[nodiscard]] static std::vector<size_t> FindPatternScalar(
        const uint8_t* data, size_t dataLen,
        const uint8_t* pat, size_t patLen) noexcept
    {
        std::vector<size_t> results;
        if (patLen == 0 || dataLen < patLen) return results;

        const size_t searchLen = dataLen - patLen + 1;
        for (size_t i = 0; i < searchLen; ++i) {
            if (data[i] == pat[0]) {
                if (std::memcmp(data + i, pat, patLen) == 0) {
                    results.push_back(i);
                    if (results.size() >= kMaxShellcodeMatches) return results;
                }
            }
        }
        return results;
    }

    [[nodiscard]] std::vector<size_t> FindPattern(
        const uint8_t* data, size_t dataLen,
        const uint8_t* pat, size_t patLen) const noexcept
    {
        if (simd.hasAVX2) {
            return FindPatternAVX2(data, dataLen, pat, patLen);
        }
        return FindPatternScalar(data, dataLen, pat, patLen);
    }

    // ========================================================================
    // AVX2-accelerated byte scan (find all positions of a single byte value)
    // ========================================================================

    [[nodiscard]] std::vector<size_t> FindByteAVX2(
        const uint8_t* data, size_t dataLen, uint8_t value) const noexcept
    {
        std::vector<size_t> results;
        const __m256i target = _mm256_set1_epi8(static_cast<char>(value));
        size_t i = 0;

        for (; i + 32 <= dataLen; i += 32) {
            const __m256i block = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(data + i));
            const __m256i cmp = _mm256_cmpeq_epi8(block, target);
            uint32_t mask = static_cast<uint32_t>(_mm256_movemask_epi8(cmp));

            while (mask != 0) {
                unsigned long bitPos = 0;
                _BitScanForward(&bitPos, mask);
                results.push_back(i + bitPos);
                if (results.size() >= kMaxROPGadgets) return results;
                mask &= mask - 1;
            }
        }

        for (; i < dataLen; ++i) {
            if (data[i] == value) {
                results.push_back(i);
                if (results.size() >= kMaxROPGadgets) return results;
            }
        }
        return results;
    }

    [[nodiscard]] static std::vector<size_t> FindByteScalar(
        const uint8_t* data, size_t dataLen, uint8_t value) noexcept
    {
        std::vector<size_t> results;
        for (size_t i = 0; i < dataLen; ++i) {
            if (data[i] == value) {
                results.push_back(i);
                if (results.size() >= kMaxROPGadgets) return results;
            }
        }
        return results;
    }

    [[nodiscard]] std::vector<size_t> FindByte(
        const uint8_t* data, size_t dataLen, uint8_t value) const noexcept
    {
        if (simd.hasAVX2) {
            return FindByteAVX2(data, dataLen, value);
        }
        return FindByteScalar(data, dataLen, value);
    }

    // ========================================================================
    // Page Enumeration Helper
    // ========================================================================

    [[nodiscard]] static std::vector<PageEntropyEntry> EnumeratePages(
        VirtualMemory& memory, const SIMDCapabilities& /*simd*/) noexcept
    {
        std::vector<PageEntropyEntry> entries;

        const GuestSize allocBytes = memory.GetAllocatedBytes();
        if (allocBytes == 0) return entries;

        // Iterate page-by-page up to the memory ceiling
        const GuestSize maxAddr = std::min(allocBytes + kMaxGuestMemory, kMaxGuestMemory);

        for (GuestAddress addr = 0; addr < maxAddr; addr += kPageSize) {
            // Overflow guard
            if (addr + kPageSize < addr) break;

            const auto prot = memory.GetProtection(addr);
            if (!prot.has_value()) continue; // unmapped page

            const uint8_t* hostPtr = memory.GetHostReadPtr(addr);
            if (!hostPtr) continue;

            PageEntropyEntry entry;
            entry.pageAddress = addr;
            entry.protection = prot.value();

            const double ent = ComputeEntropy(hostPtr, kPageSize);
            entry.entropy = ent;
            entry.isHighEntropy = (ent > 7.0);
            entry.isEncrypted = (ent > 7.5);
            entry.wasWritten = memory.WasWrittenThenExecuted(addr);

            entries.push_back(entry);
            if (entries.size() >= kMaxEntropyEntries) break;
        }

        return entries;
    }

    // ========================================================================
    // Shellcode Detection Helpers
    // ========================================================================

    void DetectNopSled(ByteSpan data, GuestAddress base,
                       std::vector<ShellcodeMatch>& matches) const noexcept
    {
        if (data.size() < 16) return;
        const uint8_t* ptr = data.data();
        const size_t len = data.size();

        size_t runStart = 0;
        size_t i = 0;

        while (i < len && matches.size() < kMaxShellcodeMatches) {
            // Single-byte NOP (0x90)
            if (ptr[i] == 0x90) {
                runStart = i;
                while (i < len && ptr[i] == 0x90) ++i;
                const size_t runLen = i - runStart;
                if (runLen >= 16) {
                    ShellcodeMatch m;
                    m.pattern = ShellcodePattern::NopSled;
                    m.address = base + runStart;
                    m.size = runLen;
                    m.confidence = std::min(1.0f, static_cast<float>(runLen) / 64.0f);
                    m.description = "NOP sled (0x90)";
                    matches.push_back(m);
                }
                continue;
            }
            // Multi-byte NOP: 0F 1F xx...
            if (i + 2 < len && ptr[i] == 0x0F && ptr[i + 1] == 0x1F) {
                runStart = i;
                while (i + 2 < len && ptr[i] == 0x0F && ptr[i + 1] == 0x1F) {
                    // Multi-byte NOPs vary from 2 to 9+ bytes; skip based on ModR/M
                    const uint8_t modrm = ptr[i + 2];
                    const uint8_t mod = (modrm >> 6) & 0x03;
                    // Approximate sizes for Intel multi-byte NOP encodings
                    uint32_t nopLen = 3; // base: 0F 1F + modrm
                    if (mod == 0x01) nopLen = 4;
                    else if (mod == 0x02) nopLen = 7;
                    else if (mod == 0x00 && (modrm & 0x07) == 0x04) nopLen = 4; // SIB
                    if (i + nopLen > len) break;
                    i += nopLen;
                }
                const size_t runLen = i - runStart;
                if (runLen >= 16) {
                    ShellcodeMatch m;
                    m.pattern = ShellcodePattern::NopSled;
                    m.address = base + runStart;
                    m.size = runLen;
                    m.confidence = std::min(1.0f, static_cast<float>(runLen) / 64.0f);
                    m.description = "Multi-byte NOP sled (0x0F 0x1F)";
                    matches.push_back(m);
                }
                continue;
            }
            ++i;
        }
    }

    void DetectGetPCStubs(ByteSpan data, GuestAddress base,
                          std::vector<ShellcodeMatch>& matches) const noexcept
    {
        if (data.size() < 6) return;

        // Pattern: E8 00 00 00 00 [58-5F] (call $+5; pop r32)
        // or E8 00 00 00 00 [41 58 - 41 5F] (call $+5; pop r64 via REX.B)
        static constexpr uint8_t kCallNext[] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };

        auto positions = FindPattern(data.data(), data.size(), kCallNext, sizeof(kCallNext));

        for (const size_t pos : positions) {
            if (matches.size() >= kMaxShellcodeMatches) break;
            const size_t afterCall = pos + 5;
            if (afterCall >= data.size()) continue;

            bool matched = false;
            GuestSize matchSize = 6;

            const uint8_t next = data[afterCall];
            // pop rax..pop rdi (58-5F)
            if (next >= 0x58 && next <= 0x5F) {
                matched = true;
                matchSize = 6;
            }
            // REX.B pop r8..r15 (41 58 - 41 5F)
            else if (next == 0x41 && afterCall + 1 < data.size()) {
                const uint8_t ext = data[afterCall + 1];
                if (ext >= 0x58 && ext <= 0x5F) {
                    matched = true;
                    matchSize = 7;
                }
            }

            if (matched) {
                ShellcodeMatch m;
                m.pattern = ShellcodePattern::GetPCStub;
                m.address = base + pos;
                m.size = matchSize;
                m.confidence = 0.95f;
                m.description = "GetPC stub: CALL $+5; POP reg";
                matches.push_back(m);
            }
        }
    }

    void DetectEggHunter(ByteSpan data, GuestAddress base,
                         std::vector<ShellcodeMatch>& matches) const noexcept
    {
        if (data.size() < 18) return;

        // NtAccessCheckAndAuditAlarm egg hunter signature (common 32-bit variant)
        // 66 81 CA FF 0F  (OR DX, 0x0FFF)
        // 42              (INC EDX)
        // 52              (PUSH EDX)
        // 6A 02           (PUSH 2)
        // 58              (POP EAX  — NtAccessCheckAndAuditAlarm syscall number)
        // CD 2E           (INT 0x2E)
        // 3C 05           (CMP AL, 5)
        // 5A              (POP EDX)
        // 74 EF           (JZ short back)
        // B8              (MOV EAX, <tag>)
        static constexpr uint8_t kEggHunterHead[] = {
            0x66, 0x81, 0xCA, 0xFF, 0x0F
        };

        auto positions = FindPattern(data.data(), data.size(),
                                     kEggHunterHead, sizeof(kEggHunterHead));

        for (const size_t pos : positions) {
            if (matches.size() >= kMaxShellcodeMatches) break;
            // Verify subsequent bytes loosely (the full pattern may vary)
            if (pos + 18 > data.size()) continue;
            const uint8_t* p = data.data() + pos + 5;
            if (p[0] == 0x42 && p[1] == 0x52 && p[2] == 0x6A && p[3] == 0x02 &&
                p[4] == 0x58 && p[5] == 0xCD && p[6] == 0x2E) {
                ShellcodeMatch m;
                m.pattern = ShellcodePattern::EggHunter;
                m.address = base + pos;
                m.size = 18;
                m.confidence = 0.90f;
                m.description = "Egg hunter (NtAccessCheckAndAuditAlarm)";
                matches.push_back(m);
            }
        }
    }

    void DetectStackPivot(ByteSpan data, GuestAddress base,
                          std::vector<ShellcodeMatch>& matches) const noexcept
    {
        if (data.size() < 1) return;
        const uint8_t* ptr = data.data();
        const size_t len = data.size();

        for (size_t i = 0; i < len && matches.size() < kMaxShellcodeMatches; ++i) {
            bool matched = false;
            GuestSize matchSize = 0;
            const char* desc = nullptr;

            // XCHG EAX, ESP — opcode 0x94
            if (ptr[i] == 0x94) {
                matched = true;
                matchSize = 1;
                desc = "Stack pivot: XCHG EAX, ESP";
            }
            // XCHG ESP, reg — 0x87 E4 or 0x87 with r/m == ESP
            else if (i + 1 < len && ptr[i] == 0x87) {
                const uint8_t modrm = ptr[i + 1];
                const uint8_t reg = (modrm >> 3) & 0x07;
                const uint8_t rm  = modrm & 0x07;
                // ModR/M mod==11 (register), one operand must be ESP (4)
                if ((modrm >> 6) == 0x03 && (reg == 4 || rm == 4)) {
                    matched = true;
                    matchSize = 2;
                    desc = "Stack pivot: XCHG ESP, reg";
                }
            }
            // MOV ESP, reg — 0x89 with modrm mod=11, rm=4 (ESP destination)
            else if (i + 1 < len && ptr[i] == 0x89) {
                const uint8_t modrm = ptr[i + 1];
                const uint8_t rm  = modrm & 0x07;
                if ((modrm >> 6) == 0x03 && rm == 4) {
                    matched = true;
                    matchSize = 2;
                    desc = "Stack pivot: MOV ESP, reg";
                }
            }

            if (matched) {
                ShellcodeMatch m;
                m.pattern = ShellcodePattern::StackPivot;
                m.address = base + i;
                m.size = matchSize;
                m.confidence = 0.85f;
                m.description = desc;
                matches.push_back(m);
            }
        }
    }

    void DetectPEBWalk(ByteSpan data, GuestAddress base,
                       std::vector<ShellcodeMatch>& matches) const noexcept
    {
        // 32-bit: MOV EAX, FS:[0x30]  → 64 A1 30 00 00 00
        static constexpr uint8_t kPEB32[] = { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00 };
        // 64-bit: MOV RAX, GS:[0x60]  → 65 48 8B 04 25 60 00 00 00
        static constexpr uint8_t kPEB64[] = { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 };

        auto hits32 = FindPattern(data.data(), data.size(), kPEB32, sizeof(kPEB32));
        for (const size_t pos : hits32) {
            if (matches.size() >= kMaxShellcodeMatches) break;
            ShellcodeMatch m;
            m.pattern = ShellcodePattern::PEBWalk;
            m.address = base + pos;
            m.size = sizeof(kPEB32);
            m.confidence = 0.90f;
            m.description = "PEB access: MOV EAX, FS:[0x30]";
            matches.push_back(m);
        }

        auto hits64 = FindPattern(data.data(), data.size(), kPEB64, sizeof(kPEB64));
        for (const size_t pos : hits64) {
            if (matches.size() >= kMaxShellcodeMatches) break;
            ShellcodeMatch m;
            m.pattern = ShellcodePattern::PEBWalk;
            m.address = base + pos;
            m.size = sizeof(kPEB64);
            m.confidence = 0.92f;
            m.description = "PEB access: MOV RAX, GS:[0x60]";
            matches.push_back(m);
        }
    }

    void DetectAPIHashLoop(ByteSpan data, GuestAddress base,
                           std::vector<ShellcodeMatch>& matches) const noexcept
    {
        if (data.size() < 6) return;
        const uint8_t* ptr = data.data();
        const size_t len = data.size();

        // Look for ROR reg, 13 (0xC1 Cx 0D where x: C0-C7 for reg=0..7)
        // near ADD reg, reg (0x03 Cx where mod=11)
        for (size_t i = 0; i + 2 < len && matches.size() < kMaxShellcodeMatches; ++i) {
            if (ptr[i] != 0xC1) continue;
            const uint8_t modrm = ptr[i + 1];
            // ROR: /1 group — reg field = 1, but with 0xC8-0xCF encoding
            // C1 C8+r 0D means ROR r32, 13
            if (modrm < 0xC8 || modrm > 0xCF) continue;
            if (ptr[i + 2] != 0x0D) continue;

            // Search nearby (within 16 bytes) for ADD reg, reg (03 Cx)
            const size_t searchEnd = std::min(len, i + 20);
            for (size_t j = (i >= 16 ? i - 16 : 0); j + 1 < searchEnd; ++j) {
                if (ptr[j] == 0x03 && (ptr[j + 1] & 0xC0) == 0xC0) {
                    ShellcodeMatch m;
                    m.pattern = ShellcodePattern::APIHashLookup;
                    m.address = base + std::min(i, j);
                    m.size = static_cast<GuestSize>(std::max(i + 3, j + 2) - std::min(i, j));
                    m.confidence = 0.88f;
                    m.description = "API hash loop: ROR reg, 13 + ADD";
                    matches.push_back(m);
                    break;
                }
            }
        }
    }

    void DetectSyscallStub(ByteSpan data, GuestAddress base,
                           std::vector<ShellcodeMatch>& matches) const noexcept
    {
        if (data.size() < 2) return;
        const uint8_t* ptr = data.data();
        const size_t len = data.size();

        for (size_t i = 0; i < len && matches.size() < kMaxShellcodeMatches; ++i) {
            // SYSCALL: 0F 05
            if (i + 1 < len && ptr[i] == 0x0F && ptr[i + 1] == 0x05) {
                ShellcodeMatch m;
                m.pattern = ShellcodePattern::SyscallStub;
                m.address = base + i;
                m.size = 2;
                m.confidence = 0.80f;
                m.description = "Direct SYSCALL instruction";
                matches.push_back(m);
                ++i; // skip second byte
            }
            // INT 0x2E: CD 2E
            else if (i + 1 < len && ptr[i] == 0xCD && ptr[i + 1] == 0x2E) {
                ShellcodeMatch m;
                m.pattern = ShellcodePattern::SyscallStub;
                m.address = base + i;
                m.size = 2;
                m.confidence = 0.85f;
                m.description = "INT 0x2E (legacy syscall)";
                matches.push_back(m);
                ++i;
            }
        }
    }

    void DetectEncoderStub(ByteSpan data, GuestAddress base,
                           std::vector<ShellcodeMatch>& matches) const noexcept
    {
        // Look for small loops containing XOR/SUB/ADD with memory operands
        // A typical encoder: XOR [reg+offset], imm; INC/ADD reg; CMP; JNZ back
        // We detect backward short jumps (EB xx / 75 xx with negative offset)
        // preceded by XOR (0x80/0x30/0x31) within the loop body
        if (data.size() < 6) return;
        const uint8_t* ptr = data.data();
        const size_t len = data.size();

        for (size_t i = 2; i < len && matches.size() < kMaxShellcodeMatches; ++i) {
            // Short backward conditional jump: 75 xx (JNZ) or 79/7x backward
            bool isLoopBack = false;
            uint32_t loopSize = 0;

            if (i + 1 < len && (ptr[i] == 0x75 || ptr[i] == 0xE2 || ptr[i] == 0x74)) {
                const auto disp = static_cast<int8_t>(ptr[i + 1]);
                if (disp < 0 && static_cast<uint32_t>(-disp) <= 32) {
                    isLoopBack = true;
                    loopSize = static_cast<uint32_t>(-disp);
                }
            }

            if (!isLoopBack || loopSize < 4) continue;

            // Check loop body for XOR/SUB/ADD with memory operand
            const size_t loopStart = (i >= loopSize) ? (i - loopSize) : 0;
            bool hasXOR = false;
            for (size_t j = loopStart; j < i; ++j) {
                // XOR [reg], imm8  (0x80 /6)
                // XOR [reg], reg   (0x30, 0x31)
                // SUB [reg], imm8  (0x80 /5)
                // ADD [reg], imm8  (0x80 /0)
                if (ptr[j] == 0x30 || ptr[j] == 0x31 || ptr[j] == 0x32 || ptr[j] == 0x33) {
                    hasXOR = true;
                    break;
                }
                if (ptr[j] == 0x80 && j + 1 < i) {
                    const uint8_t regField = (ptr[j + 1] >> 3) & 0x07;
                    if (regField == 6 || regField == 5 || regField == 0 || regField == 4) {
                        hasXOR = true;
                        break;
                    }
                }
            }

            if (hasXOR) {
                ShellcodeMatch m;
                m.pattern = ShellcodePattern::EncoderStub;
                m.address = base + loopStart;
                m.size = static_cast<GuestSize>(i + 2 - loopStart);
                m.confidence = 0.82f;
                m.description = "Encoder/decoder loop (XOR/SUB loop)";
                matches.push_back(m);
            }
        }
    }

    void DetectHeapSpray(ByteSpan data, GuestAddress base,
                         std::vector<ShellcodeMatch>& matches) const noexcept
    {
        // Detect repeated 4-byte patterns over a large region (> 256 bytes)
        if (data.size() < 256) return;
        const uint8_t* ptr = data.data();
        const size_t len = data.size();

        // Sample the first 4 bytes as a candidate repeated dword
        uint32_t candidate = 0;
        std::memcpy(&candidate, ptr, sizeof(candidate));

        uint32_t repeatCount = 0;
        for (size_t i = 0; i + 4 <= len; i += 4) {
            uint32_t dword = 0;
            std::memcpy(&dword, ptr + i, sizeof(dword));
            if (dword == candidate) {
                ++repeatCount;
            }
        }

        // If > 75% of dwords match the same pattern, it's a heap spray
        const uint32_t totalDwords = static_cast<uint32_t>(len / 4);
        if (totalDwords > 0 && repeatCount > (totalDwords * 3 / 4) && repeatCount > 64) {
            ShellcodeMatch m;
            m.pattern = ShellcodePattern::HeapSpray;
            m.address = base;
            m.size = len;
            m.confidence = static_cast<float>(repeatCount) / static_cast<float>(totalDwords);
            m.description = "Heap spray (repeated dword pattern)";
            matches.push_back(m);
        }
    }

    void DetectRetSled(ByteSpan data, GuestAddress base,
                       std::vector<ShellcodeMatch>& matches) const noexcept
    {
        if (data.size() < 8) return;
        const uint8_t* ptr = data.data();
        const size_t len = data.size();

        size_t i = 0;
        while (i < len && matches.size() < kMaxShellcodeMatches) {
            if (ptr[i] == 0xC3) {
                const size_t start = i;
                while (i < len && ptr[i] == 0xC3) ++i;
                const size_t runLen = i - start;
                if (runLen >= 8) {
                    ShellcodeMatch m;
                    m.pattern = ShellcodePattern::RetSled;
                    m.address = base + start;
                    m.size = runLen;
                    m.confidence = std::min(1.0f, static_cast<float>(runLen) / 32.0f);
                    m.description = "RET sled (consecutive RET instructions)";
                    matches.push_back(m);
                }
                continue;
            }
            ++i;
        }
    }

    void DetectHeavensGate(ByteSpan data, GuestAddress base,
                           std::vector<ShellcodeMatch>& matches) const noexcept
    {
        if (data.size() < 7) return;
        const uint8_t* ptr = data.data();
        const size_t len = data.size();

        for (size_t i = 0; i + 6 < len && matches.size() < kMaxShellcodeMatches; ++i) {
            // Far JMP with segment selector 0x33 (switch to 64-bit mode)
            // Encoding: EA xx xx xx xx 33 00 (far JMP ptr16:32)
            if (ptr[i] == 0xEA && i + 6 < len) {
                if (ptr[i + 5] == 0x33 && ptr[i + 6] == 0x00) {
                    ShellcodeMatch m;
                    m.pattern = ShellcodePattern::WoW64Gate;
                    m.address = base + i;
                    m.size = 7;
                    m.confidence = 0.92f;
                    m.description = "Heaven's Gate: far JMP to 0x33 segment";
                    matches.push_back(m);
                }
            }

            // Alternative: JMP FAR [mem] with 0x33 selector may also appear via
            // CALL FAR or RETF with 0x33 on the stack; detect the 6A 33 CB pattern
            // (PUSH 0x33; RETF)
            if (i + 2 < len && ptr[i] == 0x6A && ptr[i + 1] == 0x33 && ptr[i + 2] == 0xCB) {
                ShellcodeMatch m;
                m.pattern = ShellcodePattern::WoW64Gate;
                m.address = base + i;
                m.size = 3;
                m.confidence = 0.90f;
                m.description = "Heaven's Gate: PUSH 0x33; RETF";
                matches.push_back(m);
            }
        }
    }

    void DetectJmpTrampoline(ByteSpan data, GuestAddress base,
                             std::vector<ShellcodeMatch>& matches) const noexcept
    {
        if (data.size() < 2) return;
        const uint8_t* ptr = data.data();
        const size_t len = data.size();

        for (size_t i = 0; i < len && matches.size() < kMaxShellcodeMatches; ++i) {
            // JMP reg (FF /4 with mod=11 — FF E0..FF E7)
            if (i + 1 < len && ptr[i] == 0xFF) {
                const uint8_t modrm = ptr[i + 1];
                if ((modrm & 0xF8) == 0xE0) { // mod=11, reg=4, rm=0..7
                    ShellcodeMatch m;
                    m.pattern = ShellcodePattern::JmpTrampoline;
                    m.address = base + i;
                    m.size = 2;
                    m.confidence = 0.70f;
                    m.description = "JMP reg (computed jump trampoline)";
                    matches.push_back(m);
                    ++i;
                }
            }
        }
    }

    // ========================================================================
    // ROP Gadget Classification
    // ========================================================================

    struct GadgetInfo {
        const char* description = nullptr;
        bool useful = false;
    };

    [[nodiscard]] static GadgetInfo ClassifyGadget(
        const uint8_t* gadgetBytes, uint32_t gadgetLen) noexcept
    {
        // We examine the bytes *before* the trailing C3 (RET)
        // gadgetBytes points to the start, gadgetLen includes the RET
        if (gadgetLen < 2) return { "ret", false };

        const uint32_t preRetLen = gadgetLen - 1; // bytes before RET

        // Single instruction gadgets
        if (preRetLen == 1) {
            const uint8_t b = gadgetBytes[0];
            // POP r32/r64: 58-5F
            if (b >= 0x58 && b <= 0x5F) {
                static constexpr const char* kPopNames[] = {
                    "pop rax; ret", "pop rcx; ret", "pop rdx; ret", "pop rbx; ret",
                    "pop rsp; ret", "pop rbp; ret", "pop rsi; ret", "pop rdi; ret"
                };
                return { kPopNames[b - 0x58], true };
            }
            // NOP; ret
            if (b == 0x90) return { "nop; ret", false };
            // RET (double ret) — not useful but noted
            if (b == 0xC3) return { "ret; ret", false };
        }

        if (preRetLen == 2) {
            const uint8_t b0 = gadgetBytes[0];
            const uint8_t b1 = gadgetBytes[1];

            // REX.B + POP r8..r15: 41 58-5F
            if (b0 == 0x41 && b1 >= 0x58 && b1 <= 0x5F) {
                static constexpr const char* kPopExtNames[] = {
                    "pop r8; ret",  "pop r9; ret",  "pop r10; ret", "pop r11; ret",
                    "pop r12; ret", "pop r13; ret", "pop r14; ret", "pop r15; ret"
                };
                return { kPopExtNames[b1 - 0x58], true };
            }

            // XCHG reg, reg: 87 modrm (mod=11)
            if (b0 == 0x87 && (b1 & 0xC0) == 0xC0) {
                return { "xchg reg, reg; ret", true };
            }

            // MOV [reg], reg patterns: 89 modrm (mod=00)
            if (b0 == 0x89 && (b1 & 0xC0) == 0x00) {
                return { "mov [reg], reg; ret", true };
            }

            // MOV reg, [reg]: 8B modrm (mod=00)
            if (b0 == 0x8B && (b1 & 0xC0) == 0x00) {
                return { "mov reg, [reg]; ret", true };
            }

            // INC/DEC: FF /0 or FF /1 with mod=11
            if (b0 == 0xFF && (b1 & 0xC0) == 0xC0) {
                const uint8_t regField = (b1 >> 3) & 0x07;
                if (regField == 0) return { "inc reg; ret", true };
                if (regField == 1) return { "dec reg; ret", true };
            }
        }

        // Two POP instructions: pop reg1; pop reg2; ret
        if (preRetLen >= 2) {
            if (gadgetBytes[0] >= 0x58 && gadgetBytes[0] <= 0x5F &&
                gadgetBytes[1] >= 0x58 && gadgetBytes[1] <= 0x5F) {
                return { "pop reg; pop reg; ret", true };
            }
        }

        // Default: generic gadget
        return { "gadget; ret", false };
    }

    // ========================================================================
    // Decoder Loop Detection for Packed Region Analysis
    // ========================================================================

    [[nodiscard]] static bool HasDecoderLoop(const uint8_t* data, size_t len) noexcept {
        if (len < 6) return false;

        // Scan for backward short jumps near XOR/SUB/ADD memory operations
        for (size_t i = 4; i < len; ++i) {
            bool isBackJump = false;
            uint32_t loopLen = 0;

            if (i + 1 < len && (data[i] == 0x75 || data[i] == 0xE2)) {
                const auto disp = static_cast<int8_t>(data[i + 1]);
                if (disp < 0 && static_cast<uint32_t>(-disp) <= 32) {
                    isBackJump = true;
                    loopLen = static_cast<uint32_t>(-disp);
                }
            }
            if (!isBackJump || loopLen < 4) continue;

            const size_t loopStart = (i >= loopLen) ? (i - loopLen) : 0;
            for (size_t j = loopStart; j < i; ++j) {
                if (data[j] == 0x30 || data[j] == 0x31 || data[j] == 0x32 || data[j] == 0x33) {
                    return true;
                }
                if (data[j] == 0x80 && j + 1 < i) {
                    const uint8_t regField = (data[j + 1] >> 3) & 0x07;
                    if (regField == 6 || regField == 4 || regField == 5 || regField == 0) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // ========================================================================
    // Packer Signature Detection
    // ========================================================================

    [[nodiscard]] static const char* MatchPackerSignature(
        const uint8_t* regionData, size_t regionLen) noexcept
    {
        if (regionLen < 4) return nullptr;

        // UPX magic: "UPX!" (0x55 0x50 0x58 0x21)
        static constexpr uint8_t kUPXMagic[] = { 0x55, 0x50, 0x58, 0x21 };
        for (size_t i = 0; i + 4 <= regionLen && i < 1024; ++i) {
            if (std::memcmp(regionData + i, kUPXMagic, 4) == 0) {
                return "UPX";
            }
        }

        // Section name markers (typically in PE headers, scan first 1 KB)
        const size_t scanEnd = std::min(regionLen, static_cast<size_t>(1024));

        // ".themida" section
        static constexpr uint8_t kThemida[] = { '.', 't', 'h', 'e', 'm', 'i', 'd', 'a' };
        for (size_t i = 0; i + sizeof(kThemida) <= scanEnd; ++i) {
            if (std::memcmp(regionData + i, kThemida, sizeof(kThemida)) == 0) {
                return "Themida";
            }
        }

        // ".aspack" section
        static constexpr uint8_t kASPack[] = { '.', 'a', 's', 'p', 'a', 'c', 'k' };
        for (size_t i = 0; i + sizeof(kASPack) <= scanEnd; ++i) {
            if (std::memcmp(regionData + i, kASPack, sizeof(kASPack)) == 0) {
                return "ASPack";
            }
        }

        // UPX section names: "UPX0", "UPX1"
        static constexpr uint8_t kUPX0[] = { 'U', 'P', 'X', '0' };
        static constexpr uint8_t kUPX1[] = { 'U', 'P', 'X', '1' };
        for (size_t i = 0; i + 4 <= scanEnd; ++i) {
            if (std::memcmp(regionData + i, kUPX0, 4) == 0 ||
                std::memcmp(regionData + i, kUPX1, 4) == 0) {
                return "UPX";
            }
        }

        return nullptr;
    }
};

// ============================================================================
// MemoryScanAccel — Public API Implementation
// ============================================================================

MemoryScanAccel::MemoryScanAccel() noexcept
    : m_impl(std::make_unique<Impl>())
{
}

MemoryScanAccel::~MemoryScanAccel() noexcept = default;

MemoryScanAccel::MemoryScanAccel(MemoryScanAccel&&) noexcept = default;
MemoryScanAccel& MemoryScanAccel::operator=(MemoryScanAccel&&) noexcept = default;

// ============================================================================
// ScanAll — Full Memory Scan
// ============================================================================

MemoryScanResult MemoryScanAccel::ScanAll(VirtualMemory& memory) const noexcept {
    MemoryScanResult result;

    // 1. Entropy scan of all pages
    result.entropyMap = ScanPageEntropy(memory);
    result.totalPagesScanned = static_cast<uint32_t>(result.entropyMap.size());

    double entropySum = 0.0;
    for (const auto& entry : result.entropyMap) {
        entropySum += entry.entropy;

        if (entry.isHighEntropy) ++result.highEntropyPages;
        if (HasProt(entry.protection, MemProt::Execute)) ++result.executablePages;
        if (HasProt(entry.protection, MemProt::Read) &&
            HasProt(entry.protection, MemProt::Write) &&
            HasProt(entry.protection, MemProt::Execute)) {
            ++result.rwxPages;
        }
    }

    if (result.totalPagesScanned > 0) {
        result.overallEntropy = entropySum / static_cast<double>(result.totalPagesScanned);
    }

    // 2. Shellcode + ROP detection on executable pages
    for (const auto& entry : result.entropyMap) {
        if (!HasProt(entry.protection, MemProt::Execute) &&
            !HasProt(entry.protection, MemProt::Read)) {
            continue;
        }

        const uint8_t* hostPtr = memory.GetHostReadPtr(entry.pageAddress);
        if (!hostPtr) continue;

        const ByteSpan pageData(hostPtr, kPageSize);

        // Shellcode detection
        auto shellcode = DetectShellcode(pageData, entry.pageAddress);
        for (auto& match : shellcode) {
            if (result.shellcodeMatches.size() >= Impl::kMaxShellcodeMatches) break;
            result.shellcodeMatches.push_back(std::move(match));
        }

        // ROP gadgets in executable pages
        if (HasProt(entry.protection, MemProt::Execute)) {
            auto gadgets = FindROPGadgets(pageData, entry.pageAddress);
            for (auto& g : gadgets) {
                if (result.ropGadgets.size() >= Impl::kMaxROPGadgets) break;
                result.ropGadgets.push_back(std::move(g));
            }
        }
    }

    // 3. Packed region detection
    result.packedRegions = DetectPackedRegions(memory);

    // Aggregate flags
    result.hasShellcode = !result.shellcodeMatches.empty();
    result.hasPacking = !result.packedRegions.empty();

    // Heuristic: > 10 useful ROP gadgets in non-standard regions is suspicious
    uint32_t usefulGadgets = 0;
    for (const auto& g : result.ropGadgets) {
        if (g.isUseful) ++usefulGadgets;
    }
    result.hasROPChain = (usefulGadgets >= 10);

    return result;
}

// ============================================================================
// ScanPageEntropy
// ============================================================================

std::vector<PageEntropyEntry> MemoryScanAccel::ScanPageEntropy(
    VirtualMemory& memory) const noexcept
{
    return Impl::EnumeratePages(memory, m_impl->simd);
}

// ============================================================================
// DetectShellcode
// ============================================================================

std::vector<ShellcodeMatch> MemoryScanAccel::DetectShellcode(
    ByteSpan data, GuestAddress baseAddr) const noexcept
{
    std::vector<ShellcodeMatch> matches;
    if (data.empty()) return matches;

    m_impl->DetectNopSled(data, baseAddr, matches);
    m_impl->DetectGetPCStubs(data, baseAddr, matches);
    m_impl->DetectEggHunter(data, baseAddr, matches);
    m_impl->DetectStackPivot(data, baseAddr, matches);
    m_impl->DetectPEBWalk(data, baseAddr, matches);
    m_impl->DetectAPIHashLoop(data, baseAddr, matches);
    m_impl->DetectSyscallStub(data, baseAddr, matches);
    m_impl->DetectEncoderStub(data, baseAddr, matches);
    m_impl->DetectHeapSpray(data, baseAddr, matches);
    m_impl->DetectRetSled(data, baseAddr, matches);
    m_impl->DetectJmpTrampoline(data, baseAddr, matches);
    m_impl->DetectHeavensGate(data, baseAddr, matches);

    return matches;
}

// ============================================================================
// FindROPGadgets
// ============================================================================

std::vector<ROPGadget> MemoryScanAccel::FindROPGadgets(
    ByteSpan execRegion, GuestAddress baseAddr,
    uint32_t maxGadgetLength) const noexcept
{
    std::vector<ROPGadget> gadgets;
    if (execRegion.empty() || maxGadgetLength == 0) return gadgets;

    // Cap gadget length to prevent excessive backward scans
    const uint32_t maxLen = std::min(maxGadgetLength, 15u);

    // Find all RET (0xC3) bytes using SIMD
    auto retPositions = m_impl->FindByte(execRegion.data(), execRegion.size(), 0xC3);

    for (const size_t retPos : retPositions) {
        if (gadgets.size() >= Impl::kMaxROPGadgets) break;

        // Scan backward from RET to find gadgets of varying lengths
        for (uint32_t gadgetLen = 2; gadgetLen <= maxLen + 1; ++gadgetLen) {
            if (retPos + 1 < gadgetLen) continue; // not enough room

            const size_t gadgetStart = retPos + 1 - gadgetLen;
            const uint8_t* gadgetBytes = execRegion.data() + gadgetStart;

            const auto info = Impl::ClassifyGadget(gadgetBytes, gadgetLen);

            ROPGadget g;
            g.address = baseAddr + gadgetStart;
            g.length = static_cast<uint8_t>(gadgetLen);
            g.description = info.description;
            g.isUseful = info.useful;

            // Estimate instruction count: each useful gadget has ~1 instruction + ret
            g.instructionCount = static_cast<uint8_t>(gadgetLen <= 2 ? 2 : (gadgetLen <= 4 ? 2 : 3));

            if (info.useful) {
                gadgets.push_back(g);
            }
        }
    }

    return gadgets;
}

// ============================================================================
// DetectPackedRegions
// ============================================================================

std::vector<PackedRegion> MemoryScanAccel::DetectPackedRegions(
    VirtualMemory& memory,
    double entropyThreshold) const noexcept
{
    std::vector<PackedRegion> regions;

    auto entropyMap = ScanPageEntropy(memory);
    if (entropyMap.empty()) return regions;

    // Sort by page address to group consecutive high-entropy pages
    std::sort(entropyMap.begin(), entropyMap.end(),
              [](const PageEntropyEntry& a, const PageEntropyEntry& b) {
                  return a.pageAddress < b.pageAddress;
              });

    // Group consecutive high-entropy pages into packed regions
    size_t i = 0;
    while (i < entropyMap.size() && regions.size() < Impl::kMaxPackedRegions) {
        if (entropyMap[i].entropy < entropyThreshold) {
            ++i;
            continue;
        }

        // Start of a high-entropy region
        const size_t regionStart = i;
        double entropySum = 0.0;
        bool anyWX = false;

        while (i < entropyMap.size() && entropyMap[i].entropy >= entropyThreshold) {
            entropySum += entropyMap[i].entropy;
            if (entropyMap[i].wasWritten) anyWX = true;

            // Check for consecutive pages (allow small gaps of 1 page for interleaved headers)
            if (i + 1 < entropyMap.size()) {
                const GuestAddress gap = entropyMap[i + 1].pageAddress - entropyMap[i].pageAddress;
                if (gap > kPageSize * 2) break; // gap too large, end this region
            }
            ++i;
        }

        const size_t pageCount = i - regionStart;
        if (pageCount < 2) continue; // require at least 2 contiguous high-entropy pages

        PackedRegion region;
        region.base = entropyMap[regionStart].pageAddress;
        region.size = static_cast<GuestSize>(pageCount) * kPageSize;
        region.avgEntropy = entropySum / static_cast<double>(pageCount);
        region.hasWriteExecute = anyWX;

        // Check for decoder loops in the region's first few pages
        const uint8_t* hostPtr = memory.GetHostReadPtr(region.base);
        if (hostPtr) {
            const size_t checkLen = std::min(static_cast<size_t>(region.size),
                                             static_cast<size_t>(kPageSize * 4));
            region.hasDecoderLoop = Impl::HasDecoderLoop(hostPtr, checkLen);
        }

        // Check for packer signatures in the region
        if (hostPtr) {
            const size_t sigCheckLen = std::min(static_cast<size_t>(region.size),
                                                static_cast<size_t>(kPageSize * 2));
            region.likelyPacker = Impl::MatchPackerSignature(hostPtr, sigCheckLen);
        }

        regions.push_back(region);
    }

    return regions;
}

// ============================================================================
// PageEntropy — Single Page
// ============================================================================

double MemoryScanAccel::PageEntropy(ByteSpan page) const noexcept {
    return Impl::ComputeEntropy(page.data(), page.size());
}

// ============================================================================
// FindNopSled
// ============================================================================

std::optional<GuestAddress> MemoryScanAccel::FindNopSled(
    ByteSpan data, GuestAddress base, uint32_t minLength) const noexcept
{
    if (data.size() < minLength || minLength == 0) return std::nullopt;

    const uint8_t* ptr = data.data();
    const size_t len = data.size();
    size_t i = 0;

    while (i < len) {
        // Single-byte NOP
        if (ptr[i] == 0x90) {
            const size_t start = i;
            while (i < len && ptr[i] == 0x90) ++i;
            if (i - start >= minLength) {
                return base + start;
            }
            continue;
        }

        // Multi-byte NOP: 0F 1F
        if (i + 2 < len && ptr[i] == 0x0F && ptr[i + 1] == 0x1F) {
            const size_t start = i;
            while (i + 2 < len && ptr[i] == 0x0F && ptr[i + 1] == 0x1F) {
                const uint8_t modrm = ptr[i + 2];
                const uint8_t mod = (modrm >> 6) & 0x03;
                uint32_t nopLen = 3;
                if (mod == 0x01) nopLen = 4;
                else if (mod == 0x02) nopLen = 7;
                else if (mod == 0x00 && (modrm & 0x07) == 0x04) nopLen = 4;
                if (i + nopLen > len) break;
                i += nopLen;
            }
            if (i - start >= minLength) {
                return base + start;
            }
            continue;
        }
        ++i;
    }

    return std::nullopt;
}

// ============================================================================
// FindGetPCStubs
// ============================================================================

std::vector<GuestAddress> MemoryScanAccel::FindGetPCStubs(
    ByteSpan data, GuestAddress base) const noexcept
{
    std::vector<GuestAddress> results;
    if (data.size() < 6) return results;

    static constexpr uint8_t kCallNext[] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
    auto positions = m_impl->FindPattern(data.data(), data.size(), kCallNext, sizeof(kCallNext));

    for (const size_t pos : positions) {
        const size_t afterCall = pos + 5;
        if (afterCall >= data.size()) continue;

        const uint8_t next = data[afterCall];
        // pop rax..rdi
        if (next >= 0x58 && next <= 0x5F) {
            results.push_back(base + pos);
        }
        // REX.B + pop r8..r15
        else if (next == 0x41 && afterCall + 1 < data.size()) {
            if (data[afterCall + 1] >= 0x58 && data[afterCall + 1] <= 0x5F) {
                results.push_back(base + pos);
            }
        }

        if (results.size() >= Impl::kMaxShellcodeMatches) break;
    }

    return results;
}

// ============================================================================
// FindAllOccurrences — Generic SIMD Pattern Search
// ============================================================================

std::vector<size_t> MemoryScanAccel::FindAllOccurrences(
    ByteSpan data, ByteSpan pattern) const noexcept
{
    if (data.empty() || pattern.empty() || pattern.size() > data.size()) {
        return {};
    }
    return m_impl->FindPattern(data.data(), data.size(), pattern.data(), pattern.size());
}

// ============================================================================
// FindPEBAccess
// ============================================================================

std::vector<GuestAddress> MemoryScanAccel::FindPEBAccess(
    ByteSpan data, GuestAddress base, bool is64Bit) const noexcept
{
    std::vector<GuestAddress> results;
    if (data.empty()) return results;

    if (is64Bit) {
        // 64-bit PEB: MOV RAX, GS:[0x60] → 65 48 8B 04 25 60 00 00 00
        static constexpr uint8_t kPEB64[] = {
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00
        };
        auto hits = m_impl->FindPattern(data.data(), data.size(), kPEB64, sizeof(kPEB64));
        for (const size_t pos : hits) {
            results.push_back(base + pos);
            if (results.size() >= Impl::kMaxShellcodeMatches) return results;
        }

        // Also detect other GS:[0x60] access patterns:
        // MOV reg, GS:[0x60] — 65 48 8B 0C 25 60 00 00 00 (RCX variant)
        // and other register variants with different ModR/M bytes
        static constexpr uint8_t kGSPrefix[] = { 0x65, 0x48, 0x8B };
        auto gsHits = m_impl->FindPattern(data.data(), data.size(), kGSPrefix, sizeof(kGSPrefix));
        for (const size_t pos : gsHits) {
            if (pos + 9 > data.size()) continue;
            // Check for disp32 encoding with 0x60 displacement
            if (data[pos + 4] == 0x25 &&
                data[pos + 5] == 0x60 &&
                data[pos + 6] == 0x00 &&
                data[pos + 7] == 0x00 &&
                data[pos + 8] == 0x00) {
                // Avoid duplicate with the primary pattern
                const GuestAddress addr = base + pos;
                bool duplicate = false;
                for (const auto& existing : results) {
                    if (existing == addr) { duplicate = true; break; }
                }
                if (!duplicate) {
                    results.push_back(addr);
                    if (results.size() >= Impl::kMaxShellcodeMatches) return results;
                }
            }
        }
    } else {
        // 32-bit PEB: MOV EAX, FS:[0x30] → 64 A1 30 00 00 00
        static constexpr uint8_t kPEB32[] = {
            0x64, 0xA1, 0x30, 0x00, 0x00, 0x00
        };
        auto hits = m_impl->FindPattern(data.data(), data.size(), kPEB32, sizeof(kPEB32));
        for (const size_t pos : hits) {
            results.push_back(base + pos);
            if (results.size() >= Impl::kMaxShellcodeMatches) return results;
        }

        // FS:[0x30] with MOV reg, [segment:disp]
        // 64 8B xx 30 00 00 00 patterns
        for (size_t i = 0; i + 6 < data.size(); ++i) {
            if (data[i] == 0x64 && i != 0) { // FS: prefix (skip already-found A1)
                // MOV r32, FS:[0x30] with different encodings
                if (data[i + 1] == 0x8B && i + 7 <= data.size()) {
                    const uint8_t modrm = data[i + 2];
                    const uint8_t mod = (modrm >> 6) & 0x03;
                    // mod=00 with disp32 for [0x30]
                    if (mod == 0x00 && (modrm & 0x07) == 0x05) {
                        if (data[i + 3] == 0x30 && data[i + 4] == 0x00 &&
                            data[i + 5] == 0x00 && data[i + 6] == 0x00) {
                            results.push_back(base + i);
                            if (results.size() >= Impl::kMaxShellcodeMatches) return results;
                        }
                    }
                }
            }
        }
    }

    return results;
}

} // namespace Phantom
