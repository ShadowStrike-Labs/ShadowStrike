/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * AMXOps.cpp — Intel AMX (Advanced Matrix Extensions) tile instruction
 *              emulation for anti-evasion fidelity.
 *
 * Covers:
 *   Config:    LDTILECFG, STTILECFG, TILERELEASE
 *   Data:      TILELOADD, TILESTORED, TILEZERO
 *   Compute:   TDPBSSD, TDPBSUD, TDPBUSD, TDPBUUD (INT8 dot-product)
 *              TDPBF16PS, TDPFP16PS (BFloat16/FP16 dot-product)
 *
 * AMX provides 8 tile registers (tmm0-7), each up to 1024 bytes (16×64).
 * TILECFG controls dimensions; dot-product ops accumulate into FP32/INT32.
 *
 * For malware EDR context: AMX is server-only (Sapphire Rapids+) but we
 * implement it for completeness and to prevent CPUID probe discrepancies.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"
#include <array>
#include <algorithm>
#include <cstring>
#include <cmath>
#include <limits>

namespace Phantom {

// ============================================================================
// Helpers
// ============================================================================

static constexpr uint8_t kAMXTileCount = 8;
static constexpr uint32_t kTileCfgBytes = 64;

[[nodiscard]] static inline bool ValidateTileIndex(uint8_t idx) noexcept {
    return idx < kAMXTileCount;
}

[[nodiscard]] bool CanAddGuestOffset(GuestAddress base, uint64_t offset, GuestAddress& out) noexcept {
    if (base > (std::numeric_limits<GuestAddress>::max)() - offset) {
        return false;
    }
    out = base + offset;
    return true;
}

[[nodiscard]] bool ValidateTileShape(
    const CPUState::TileConfig::TileDim& dim) noexcept
{
    return dim.rows <= CPUState::kMaxTileRows &&
           dim.colsb <= CPUState::kMaxTileCols &&
           static_cast<uint32_t>(dim.rows) * dim.colsb <= CPUState::kTileBytes;
}

[[nodiscard]] bool ValidateTileMemoryOperand(const DecodedInstruction& inst) noexcept {
    return inst.operandCount >= 1 && inst.Op(0).IsMemory();
}

[[nodiscard]] bool ValidateTileRegisterOperand(const DecodedInstruction& inst) noexcept {
    return inst.operandCount >= 1 && inst.Op(0).IsRegister() &&
           ValidateTileIndex(inst.Op(0).reg.regIndex);
}

[[nodiscard]] float FP16ToFloat(uint16_t h) noexcept {
    const uint32_t sign = (static_cast<uint32_t>(h & 0x8000U)) << 16;
    uint32_t exp = (h >> 10) & 0x1FU;
    uint32_t mant = h & 0x03FFU;

    uint32_t bits = 0;
    if (exp == 0) {
        if (mant == 0) {
            bits = sign;
        } else {
            int32_t e = -14;
            while ((mant & 0x0400U) == 0) {
                mant <<= 1;
                --e;
            }
            mant &= 0x03FFU;
            bits = sign |
                   (static_cast<uint32_t>(e + 127) << 23) |
                   (mant << 13);
        }
    } else if (exp == 0x1FU) {
        bits = sign | 0x7F800000U | (mant << 13);
    } else {
        bits = sign | ((exp + 112U) << 23) | (mant << 13);
    }

    float result = 0.0f;
    std::memcpy(&result, &bits, sizeof(result));
    return result;
}

void AddWrapI32(CPUState::TileData& dst, uint32_t row, uint32_t col, int32_t product) noexcept {
    const uint32_t off = row * CPUState::kMaxTileCols + col * sizeof(int32_t);
    uint32_t accBits = 0;
    std::memcpy(&accBits, dst.data + off, sizeof(accBits));
    accBits += static_cast<uint32_t>(product);
    std::memcpy(dst.data + off, &accBits, sizeof(accBits));
}

// TILECFG layout (64 bytes, per Intel AMX spec):
//   Byte 0: palette_id
//   Byte 1: start_row
//   Bytes 2-15: reserved
//   Bytes 16-17: tile[0].colsb  (uint16_t)
//   Bytes 18-19: tile[1].colsb  ... up to tile[7] at bytes 30-31
//   Bytes 32-47: reserved
//   Byte 48: tile[0].rows  ... Byte 55: tile[7].rows
//   Bytes 56-63: reserved

ErrorCode CPU::ExecuteAMX(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    uint8_t op = inst.opcode;
    uint8_t pp = inst.prefixes.vexPP;
    auto& tc = m_state.tileConfig;

    // ========================================================================
    // TILERELEASE: VEX.NP.0F38 49 C0 — release all tile state
    // ========================================================================
    if (op == 0x49 && pp == 0 && inst.modrm == 0xC0) {
        tc.Reset();
        for (auto& tile : m_state.tiles) tile.Clear();
        return ErrorCode::Success;
    }

    // ========================================================================
    // LDTILECFG: VEX.NP.0F38.W0 49 /0 (memory) — load tile configuration
    // ========================================================================
    if (op == 0x49 && pp == 0 && (inst.modrm >> 6) != 3) {
        if (!ValidateTileMemoryOperand(inst)) return ErrorCode::InvalidOperandSize;
        GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);

        std::array<uint8_t, kTileCfgBytes> cfgBuf{};
        auto err = mem.Read(addr, cfgBuf.data(), static_cast<uint32_t>(cfgBuf.size()));
        if (err != ErrorCode::Success) return err;

        const bool reservedZero =
            std::all_of(cfgBuf.begin() + 2, cfgBuf.begin() + 16, [](uint8_t b) { return b == 0; }) &&
            std::all_of(cfgBuf.begin() + 32, cfgBuf.begin() + 48, [](uint8_t b) { return b == 0; }) &&
            std::all_of(cfgBuf.begin() + 56, cfgBuf.end(), [](uint8_t b) { return b == 0; });
        if (!reservedZero) {
            tc.Reset();
            return ErrorCode::InvalidOperandSize;
        }

        // Parse TILECFG
        tc.paletteId = cfgBuf[0];
        tc.startRow  = cfgBuf[1];

        // Validate palette (must be 1 for AMX-INT8/BF16)
        if (tc.paletteId != 1 || tc.startRow >= CPUState::kMaxTileRows) {
            tc.Reset();
            return ErrorCode::InvalidOperandSize;
        }

        for (uint32_t i = 0; i < kAMXTileCount; ++i) {
            uint16_t colsb = 0;
            std::memcpy(&colsb, cfgBuf.data() + 16 + i * 2, sizeof(uint16_t));
            uint8_t rows = cfgBuf[48 + i];

            // Validate dimensions
            CPUState::TileConfig::TileDim candidate{colsb, rows};
            if (!ValidateTileShape(candidate)) {
                tc.Reset();
                return ErrorCode::InvalidOperandSize;
            }
            tc.tiles[i].colsb = colsb;
            tc.tiles[i].rows  = rows;
        }
        tc.configured = true;
        // Clear tile data on reconfiguration
        for (auto& tile : m_state.tiles) tile.Clear();
        return ErrorCode::Success;
    }

    // ========================================================================
    // STTILECFG: VEX.66.0F38.W0 49 /0 (memory) — store tile configuration
    // ========================================================================
    if (op == 0x49 && pp == 1 && (inst.modrm >> 6) != 3) {
        if (!ValidateTileMemoryOperand(inst)) return ErrorCode::InvalidOperandSize;
        GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);

        std::array<uint8_t, kTileCfgBytes> cfgBuf{};
        cfgBuf[0] = tc.paletteId;
        cfgBuf[1] = tc.startRow;
        for (uint32_t i = 0; i < kAMXTileCount; ++i) {
            std::memcpy(cfgBuf.data() + 16 + i * 2, &tc.tiles[i].colsb, sizeof(uint16_t));
            cfgBuf[48 + i] = tc.tiles[i].rows;
        }
        return mem.Write(addr, cfgBuf.data(), static_cast<uint32_t>(cfgBuf.size()));
    }

    // ========================================================================
    // TILEZERO: VEX.F2.0F38.W0 49 /r (mod=3) — zero a tile register
    // ========================================================================
    if (op == 0x49 && pp == 3 && (inst.modrm >> 6) == 3) {
        if (!tc.configured) return ErrorCode::InvalidOperandSize;
        uint8_t tileIdx = inst.opcodeExt;  // reg field from modrm
        if (!ValidateTileIndex(tileIdx)) return ErrorCode::InvalidOperandSize;
        m_state.tiles[tileIdx].Clear();
        return ErrorCode::Success;
    }

    // ========================================================================
    // TILELOADD: VEX.F2.0F38.W0 4B /r (memory) — load tile from memory
    // ========================================================================
    if (op == 0x4B && pp == 3) {
        if (!tc.configured) return ErrorCode::InvalidOperandSize;
        uint8_t tileIdx = inst.opcodeExt;
        if (!ValidateTileIndex(tileIdx)) return ErrorCode::InvalidOperandSize;
        if (!ValidateTileMemoryOperand(inst)) return ErrorCode::InvalidOperandSize;

        auto& dim = tc.tiles[tileIdx];
        if (dim.rows == 0 || dim.colsb == 0 || !ValidateTileShape(dim)) return ErrorCode::InvalidOperandSize;

        GuestAddress baseAddr = CalculateEffectiveAddress(inst.Op(0), inst);
        // The stride comes from the SIB index register × scale.
        // For our emulation, stride = colsb (row-major, packed).
        uint32_t stride = dim.colsb;

        m_state.tiles[tileIdx].Clear();
        for (uint8_t row = 0; row < dim.rows; ++row) {
            GuestAddress rowAddr = 0;
            if (!CanAddGuestOffset(baseAddr, static_cast<uint64_t>(row) * stride, rowAddr)) {
                return ErrorCode::AddressOverflow;
            }
            auto err = mem.Read(rowAddr, m_state.tiles[tileIdx].data +
                                row * CPUState::kMaxTileCols, dim.colsb);
            if (err != ErrorCode::Success) return err;
        }
        return ErrorCode::Success;
    }

    // ========================================================================
    // TILESTORED: VEX.F3.0F38.W0 4B /r (memory) — store tile to memory
    // ========================================================================
    if (op == 0x4B && pp == 2) {
        if (!tc.configured) return ErrorCode::InvalidOperandSize;
        uint8_t tileIdx = inst.opcodeExt;
        if (!ValidateTileIndex(tileIdx)) return ErrorCode::InvalidOperandSize;
        if (!ValidateTileMemoryOperand(inst)) return ErrorCode::InvalidOperandSize;

        auto& dim = tc.tiles[tileIdx];
        if (dim.rows == 0 || dim.colsb == 0 || !ValidateTileShape(dim)) return ErrorCode::InvalidOperandSize;

        GuestAddress baseAddr = CalculateEffectiveAddress(inst.Op(0), inst);
        uint32_t stride = dim.colsb;

        for (uint8_t row = 0; row < dim.rows; ++row) {
            GuestAddress rowAddr = 0;
            if (!CanAddGuestOffset(baseAddr, static_cast<uint64_t>(row) * stride, rowAddr)) {
                return ErrorCode::AddressOverflow;
            }
            auto err = mem.Write(rowAddr, m_state.tiles[tileIdx].data +
                                 row * CPUState::kMaxTileCols, dim.colsb);
            if (err != ErrorCode::Success) return err;
        }
        return ErrorCode::Success;
    }

    // ========================================================================
    // AMX-INT8 Dot Product Instructions
    //   TDPBSSD: F2 — signed × signed → int32  accumulate
    //   TDPBSUD: F3 — signed × unsigned → int32
    //   TDPBUSD: 66 — unsigned × signed → int32
    //   TDPBUUD: NP — unsigned × unsigned → int32
    //   All: VEX.0F38.W0 5E /r
    // ========================================================================
    if (op == 0x5E) {
        if (!tc.configured) return ErrorCode::InvalidOperandSize;

        // Operand encoding: dst=reg, src1=vvvv, src2=r/m (all tile registers)
        uint8_t dstIdx = inst.opcodeExt;
        uint8_t src1Idx = static_cast<uint8_t>(15 - inst.prefixes.vexVVVV);
        if (!ValidateTileRegisterOperand(inst)) return ErrorCode::InvalidOperandSize;
        uint8_t src2Idx = inst.Op(0).reg.regIndex;

        if (!ValidateTileIndex(dstIdx) || !ValidateTileIndex(src1Idx) ||
            !ValidateTileIndex(src2Idx))
            return ErrorCode::InvalidOperandSize;

        auto& dstDim  = tc.tiles[dstIdx];
        auto& src1Dim = tc.tiles[src1Idx];
        auto& src2Dim = tc.tiles[src2Idx];

        // Dimension validation: dst.rows=src1.rows, dst.colsb=src2.colsb,
        // src1.colsb=src2.rows*4 (for INT8 4-element dot product)
        uint8_t M = dstDim.rows;
        uint16_t N_bytes = dstDim.colsb;
        uint16_t K_bytes = src1Dim.colsb;

        if (M == 0 || N_bytes == 0 || K_bytes == 0 ||
            !ValidateTileShape(dstDim) || !ValidateTileShape(src1Dim) || !ValidateTileShape(src2Dim) ||
            (N_bytes % sizeof(int32_t)) != 0 || (K_bytes % sizeof(int32_t)) != 0 ||
            src1Dim.rows != M || src2Dim.rows != (K_bytes / sizeof(int32_t)) ||
            src2Dim.colsb != N_bytes)
            return ErrorCode::InvalidOperandSize;

        uint32_t N = N_bytes / sizeof(int32_t);  // Number of int32 columns in dst
        uint32_t K = K_bytes / sizeof(int32_t);  // Number of 4-byte groups

        auto& dst  = m_state.tiles[dstIdx];
        auto& src1 = m_state.tiles[src1Idx];
        auto& src2 = m_state.tiles[src2Idx];

        for (uint32_t m = 0; m < M; ++m) {
            for (uint32_t n = 0; n < N; ++n) {
                for (uint32_t k = 0; k < K; ++k) {
                    // Each k-group: 4 byte-pairs dot-product
                    for (uint32_t b = 0; b < 4; ++b) {
                        uint32_t s2Off = n * CPUState::kMaxTileCols + k * 4 + b;
                        // Careful: s2 is accessed with n as row for column-major
                        // Actually: src2[k_row][n_col], so off = k*maxCols + n*4 + b
                        // Wait — AMX INT8: src1[m][k*4+b], src2[k][n*4+b]
                        // src2 rows = K, cols = N_bytes
                        s2Off = k * CPUState::kMaxTileCols + n * 4 + b;

                        int32_t a_val = 0;
                        int32_t b_val = 0;

                        uint8_t a_byte = src1.data[m * CPUState::kMaxTileCols + k * 4 + b];
                        uint8_t b_byte = src2.data[s2Off];

                        switch (pp) {
                        case 3: // TDPBSSD — signed × signed
                            a_val = static_cast<int8_t>(a_byte);
                            b_val = static_cast<int8_t>(b_byte);
                            break;
                        case 2: // TDPBSUD — signed × unsigned
                            a_val = static_cast<int8_t>(a_byte);
                            b_val = static_cast<uint8_t>(b_byte);
                            break;
                        case 1: // TDPBUSD — unsigned × signed
                            a_val = static_cast<uint8_t>(a_byte);
                            b_val = static_cast<int8_t>(b_byte);
                            break;
                        case 0: // TDPBUUD — unsigned × unsigned
                            a_val = static_cast<uint8_t>(a_byte);
                            b_val = static_cast<uint8_t>(b_byte);
                            break;
                        }
                        AddWrapI32(dst, m, n, a_val * b_val);
                    }
                }
            }
        }
        return ErrorCode::Success;
    }

    // ========================================================================
    // AMX-BF16/FP16 Dot Product
    //   TDPBF16PS: F3 — BFloat16 pairs → FP32 accumulate
    //   TDPFP16PS: F2 — FP16 pairs → FP32 accumulate
    //   VEX.0F38.W0 5C /r
    // ========================================================================
    if (op == 0x5C) {
        if (!tc.configured) return ErrorCode::InvalidOperandSize;

        uint8_t dstIdx = inst.opcodeExt;
        uint8_t src1Idx = static_cast<uint8_t>(15 - inst.prefixes.vexVVVV);
        if (!ValidateTileRegisterOperand(inst)) return ErrorCode::InvalidOperandSize;
        uint8_t src2Idx = inst.Op(0).reg.regIndex;

        if (!ValidateTileIndex(dstIdx) || !ValidateTileIndex(src1Idx) ||
            !ValidateTileIndex(src2Idx))
            return ErrorCode::InvalidOperandSize;

        auto& dstDim = tc.tiles[dstIdx];
        auto& src1Dim = tc.tiles[src1Idx];
        auto& src2Dim = tc.tiles[src2Idx];
        uint8_t M = dstDim.rows;
        uint16_t N_bytes = dstDim.colsb;
        uint16_t K_bytes = src1Dim.colsb;

        if (M == 0 || N_bytes == 0 || K_bytes == 0 ||
            !ValidateTileShape(dstDim) || !ValidateTileShape(src1Dim) || !ValidateTileShape(src2Dim) ||
            (N_bytes % sizeof(float)) != 0 || (K_bytes % sizeof(uint32_t)) != 0 ||
            src1Dim.rows != M || src2Dim.rows != (K_bytes / sizeof(uint32_t)) ||
            src2Dim.colsb != N_bytes)
            return ErrorCode::InvalidOperandSize;

        uint32_t N = N_bytes / sizeof(float);     // FP32 columns in dst
        uint32_t K = K_bytes / sizeof(uint32_t);  // Pairs of BF16/FP16

        auto& dst  = m_state.tiles[dstIdx];
        auto& src1 = m_state.tiles[src1Idx];
        auto& src2 = m_state.tiles[src2Idx];

        for (uint32_t m = 0; m < M; ++m) {
            for (uint32_t n = 0; n < N; ++n) {
                // Read accumulator as float
                float acc = 0.0f;
                uint32_t dstOff = m * CPUState::kMaxTileCols + n * sizeof(float);
                std::memcpy(&acc, dst.data + dstOff, sizeof(float));

                for (uint32_t k = 0; k < K; ++k) {
                    // Each k-group: 2 pairs of BF16/FP16 values
                    for (uint32_t p = 0; p < 2; ++p) {
                        uint32_t s1Off = m * CPUState::kMaxTileCols + k * 4 + p * 2;
                        uint32_t s2Off = k * CPUState::kMaxTileCols + n * 4 + p * 2;

                        uint16_t a_raw = 0, b_raw = 0;
                        std::memcpy(&a_raw, src1.data + s1Off, sizeof(uint16_t));
                        std::memcpy(&b_raw, src2.data + s2Off, sizeof(uint16_t));

                        float a_f = 0.0f, b_f = 0.0f;
                        if (pp == 2) {
                            // TDPBF16PS: BFloat16 → float (shift left 16)
                            uint32_t a32 = static_cast<uint32_t>(a_raw) << 16;
                            uint32_t b32 = static_cast<uint32_t>(b_raw) << 16;
                            std::memcpy(&a_f, &a32, sizeof(float));
                            std::memcpy(&b_f, &b32, sizeof(float));
                        } else {
                            // TDPFP16PS: IEEE FP16 -> float.
                            a_f = FP16ToFloat(a_raw);
                            b_f = FP16ToFloat(b_raw);
                        }
                        acc += a_f * b_f;
                    }
                }
                std::memcpy(dst.data + dstOff, &acc, sizeof(float));
            }
        }
        return ErrorCode::Success;
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
