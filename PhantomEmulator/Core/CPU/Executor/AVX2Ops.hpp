/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * AVX2Ops.hpp — AVX2 (256-bit) instruction executor declarations
 *
 * Provides the CPU::ExecuteAVX2 handler for VEX-encoded 256-bit
 * integer and logical instructions. Critical for emulating modern
 * malware that uses AVX2 for:
 *   - Fast XOR encryption (VPXOR on 32 bytes)
 *   - Obfuscated string operations (VPSHUFB byte rearrangement)
 *   - Hash computation (VPADDD chains)
 *   - Anti-emulation detection (AVX2 instruction probes)
 *
 * Supported instruction families:
 *   - Packed integer arithmetic (VPADD/VPSUB/VPMULL/VPMADD)
 *   - Packed compare (VPCMPEQ/VPCMPGT)
 *   - Bitwise logical (VPAND/VPOR/VPXOR/VPANDN, VANDPS/VORPS/VXORPS/VANDNPS)
 *   - Shift (VPSRL/VPSLL/VPSRA — immediate and variable)
 *   - Shuffle / Permute (VPSHUFB/VPSHUFD/VPERMQ/VPERMD/VPERM2I128)
 *   - Unpack (VPUNPCKL/VPUNPCKH — byte/word/dword/qword)
 *   - Sign extension (VPMOVSXBW/WD/DQ, VPMOVZXBW/WD/DQ)
 *   - Min/Max (VPMINS/VPMINU/VPMAXS/VPMAXU — byte/word/dword)
 *   - Broadcast (VPBROADCASTB/W/D)
 *   - Blend (VPBLENDW/VPBLENDD)
 *   - Move (VMOVDQA/VMOVUPS — load/store)
 *   - Gather (VPGATHERDD)
 *   - Masked move (VPMASKMOVD load/store)
 *   - Lane insert/extract (VINSERTI128/VEXTRACTI128)
 *   - Absolute value (VPABSB/VPABSW/VPABSD)
 *   - Horizontal add (VPHADDW)
 *   - Packed sign (VPSIGNB)
 *   - Packed multiply high round-scale (VPMULHRSW)
 *   - Multiply high (VPMULHUW/VPMULHW)
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../CPU.hpp"

namespace Phantom {

// YMM register represented as a 32-byte aligned buffer for executor logic.
// This avoids repeated GetYMM/SetYMM calls when multiple element-wise ops
// need access to the same register values.
struct alignas(32) YMMValue {
    union {
        uint8_t  u8[32];
        uint16_t u16[16];
        uint32_t u32[8];
        uint64_t u64[4];
        int8_t   i8[32];
        int16_t  i16[16];
        int32_t  i32[8];
        int64_t  i64[4];
        float    f32[8];
        double   f64[4];
    };

    void Clear() noexcept { std::memset(this, 0, sizeof(*this)); }
};

static_assert(sizeof(YMMValue) == 32, "YMMValue must be 32 bytes");

// ZMM register represented as a 64-byte aligned buffer for AVX-512 executor.
struct alignas(64) ZMMValue {
    union {
        uint8_t  u8[64];
        uint16_t u16[32];
        uint32_t u32[16];
        uint64_t u64[8];
        int8_t   i8[64];
        int16_t  i16[32];
        int32_t  i32[16];
        int64_t  i64[8];
        float    f32[16];
        double   f64[8];
    };

    void Clear() noexcept { std::memset(this, 0, sizeof(*this)); }
};

static_assert(sizeof(ZMMValue) == 64, "ZMMValue must be 64 bytes");

} // namespace Phantom
