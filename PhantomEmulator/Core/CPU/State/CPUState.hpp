/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "EFLAGS.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Constants.hpp"
#include <array>
#include <cstdint>
#include <cstring>

namespace Phantom {

// ============================================================================
// Segment Descriptor (lightweight — just what the emulator needs)
// ============================================================================

struct SegmentDescriptor {
    uint64_t base   = 0;
    uint32_t limit  = 0xFFFFFFFF;
    uint16_t selector = 0;
    uint8_t  type   = 0;
    uint8_t  dpl    = 3;       // Ring 3 (user mode)
    bool     present = true;
    bool     is32bit = true;
    bool     is64bit = false;
};

// ============================================================================
// x87 FPU Register
// ============================================================================

struct FPUReg {
    long double value = 0.0L;   // 80-bit extended precision
};

// ============================================================================
// XMM Register (128-bit SSE)
// ============================================================================

struct alignas(16) XMMReg {
    union {
        uint8_t   u8[16];
        uint16_t  u16[8];
        uint32_t  u32[4];
        uint64_t  u64[2];
        int8_t    i8[16];
        int16_t   i16[8];
        int32_t   i32[4];
        int64_t   i64[2];
        float     f32[4];
        double    f64[2];
    };

    XMMReg() noexcept { std::memset(this, 0, sizeof(*this)); }

    void Clear() noexcept { std::memset(this, 0, sizeof(*this)); }
};

static_assert(sizeof(XMMReg) == 16, "XMMReg must be 16 bytes");

// ============================================================================
// CPU State — Complete x86/x64 Register File
// ============================================================================
// This is the heart of the emulator. Every instruction reads from and writes
// to this structure. It must be:
// 1. Cache-friendly (hot fields at the top)
// 2. Complete (every register malware might touch)
// 3. Correct (exact bit widths, sign extension rules)

class CPUState {
public:
    CPUState() noexcept { Reset(); }

    void Reset() noexcept;
    void Reset32() noexcept;
    void Reset64() noexcept;

    // === Snapshot/Restore for analysis ===
    struct Snapshot {
        std::array<uint64_t, 16> gpr;
        uint64_t rip;
        uint64_t rflags;
        CPUMode mode;
        uint64_t instructionCount;
    };

    [[nodiscard]] Snapshot TakeSnapshot() const noexcept;
    void RestoreSnapshot(const Snapshot& snap) noexcept;

    // ========================================================================
    // General Purpose Registers (GPR)
    // ========================================================================
    // Stored as full 64-bit. 32-bit writes zero-extend to 64-bit.
    // 16-bit and 8-bit writes preserve upper bits.
    std::array<uint64_t, 16> gpr{};

    // Full 64-bit access
    [[nodiscard]] uint64_t GetReg64(GPR reg) const noexcept {
        return gpr[static_cast<uint8_t>(reg)];
    }
    void SetReg64(GPR reg, uint64_t value) noexcept {
        gpr[static_cast<uint8_t>(reg)] = value;
    }

    // 32-bit access (read: truncate; write: zero-extend to 64)
    [[nodiscard]] uint32_t GetReg32(GPR reg) const noexcept {
        return static_cast<uint32_t>(gpr[static_cast<uint8_t>(reg)]);
    }
    void SetReg32(GPR reg, uint32_t value) noexcept {
        gpr[static_cast<uint8_t>(reg)] = value; // zero-extends in 64-bit mode
    }

    // 16-bit access (read: truncate; write: preserve upper bits)
    [[nodiscard]] uint16_t GetReg16(GPR reg) const noexcept {
        return static_cast<uint16_t>(gpr[static_cast<uint8_t>(reg)]);
    }
    void SetReg16(GPR reg, uint16_t value) noexcept {
        auto& r = gpr[static_cast<uint8_t>(reg)];
        r = (r & ~0xFFFFULL) | value;
    }

    // 8-bit low access (AL, CL, DL, BL, SPL, BPL, SIL, DIL, R8B-R15B)
    [[nodiscard]] uint8_t GetReg8(GPR reg) const noexcept {
        return static_cast<uint8_t>(gpr[static_cast<uint8_t>(reg)]);
    }
    void SetReg8(GPR reg, uint8_t value) noexcept {
        auto& r = gpr[static_cast<uint8_t>(reg)];
        r = (r & ~0xFFULL) | value;
    }

    // 8-bit high access (AH=4, CH=5, DH=6, BH=7) — legacy, no REX prefix
    [[nodiscard]] uint8_t GetReg8High(uint8_t hiReg) const noexcept {
        if (hiReg < 4 || hiReg > 7) return 0;
        return static_cast<uint8_t>(gpr[hiReg - 4] >> 8);
    }
    void SetReg8High(uint8_t hiReg, uint8_t value) noexcept {
        if (hiReg < 4 || hiReg > 7) return;
        auto& r = gpr[hiReg - 4];
        r = (r & ~0xFF00ULL) | (static_cast<uint64_t>(value) << 8);
    }

    // Operand-size-aware register read/write
    [[nodiscard]] uint64_t GetRegBySize(GPR reg, OperandSize size) const noexcept {
        switch (size) {
            case OperandSize::Size8:  return GetReg8(reg);
            case OperandSize::Size16: return GetReg16(reg);
            case OperandSize::Size32: return GetReg32(reg);
            case OperandSize::Size64: return GetReg64(reg);
        }
        return 0;
    }

    void SetRegBySize(GPR reg, uint64_t value, OperandSize size) noexcept {
        switch (size) {
            case OperandSize::Size8:  SetReg8(reg, static_cast<uint8_t>(value)); break;
            case OperandSize::Size16: SetReg16(reg, static_cast<uint16_t>(value)); break;
            case OperandSize::Size32: SetReg32(reg, static_cast<uint32_t>(value)); break;
            case OperandSize::Size64: SetReg64(reg, value); break;
        }
    }

    // Named register shortcuts (hot path optimization)
    [[nodiscard]] uint64_t RAX() const noexcept { return gpr[0]; }
    [[nodiscard]] uint64_t RCX() const noexcept { return gpr[1]; }
    [[nodiscard]] uint64_t RDX() const noexcept { return gpr[2]; }
    [[nodiscard]] uint64_t RBX() const noexcept { return gpr[3]; }
    [[nodiscard]] uint64_t RSP() const noexcept { return gpr[4]; }
    [[nodiscard]] uint64_t RBP() const noexcept { return gpr[5]; }
    [[nodiscard]] uint64_t RSI() const noexcept { return gpr[6]; }
    [[nodiscard]] uint64_t RDI() const noexcept { return gpr[7]; }

    // ========================================================================
    // Instruction Pointer
    // ========================================================================
    uint64_t rip = 0;

    [[nodiscard]] GuestAddress GetRIP() const noexcept { return rip; }
    void SetRIP(GuestAddress addr) noexcept { rip = addr; }
    void AdvanceRIP(uint32_t bytes) noexcept { rip += bytes; }

    // ========================================================================
    // EFLAGS / RFLAGS
    // ========================================================================
    EFlags eflags;

    // ========================================================================
    // Segment Registers
    // ========================================================================
    std::array<SegmentDescriptor, 6> segments{};

    [[nodiscard]] const SegmentDescriptor& GetSegment(SegReg seg) const noexcept {
        return segments[static_cast<uint8_t>(seg)];
    }
    void SetSegmentSelector(SegReg seg, uint16_t selector) noexcept {
        segments[static_cast<uint8_t>(seg)].selector = selector;
    }
    void SetSegmentBase(SegReg seg, uint64_t base) noexcept {
        segments[static_cast<uint8_t>(seg)].base = base;
    }

    // ========================================================================
    // Control Registers
    // ========================================================================
    uint64_t cr0 = 0x80050033;   // PE, ET, NE, WP, AM, PG
    uint64_t cr2 = 0;             // Page fault linear address
    uint64_t cr3 = 0;             // Page directory base
    uint64_t cr4 = 0x000406F8;   // PAE, PGE, OSFXSR, OSXMMEXCPT, OSXSAVE

    // Extended Control Register (for XGETBV support — bits: x87=1, SSE=2, AVX=4)
    uint64_t xcr0 = 0x7;

    // ========================================================================
    // Debug Registers (for anti-evasion: malware checks DR0-DR3)
    // ========================================================================
    std::array<uint64_t, 4> dr{};    // DR0-DR3: breakpoint addresses
    uint64_t dr6 = 0xFFFF0FF0;       // DR6: debug status
    uint64_t dr7 = 0x00000400;       // DR7: debug control

    // ========================================================================
    // x87 FPU State
    // ========================================================================
    std::array<FPUReg, 8> fpuStack{};
    uint16_t fpuControl  = 0x037F;   // Default: all exceptions masked, precision=64-bit
    uint16_t fpuStatus   = 0;
    uint16_t fpuTag      = 0xFFFF;   // All registers empty
    uint16_t fpuOpcode   = 0;
    uint64_t fpuIP       = 0;         // Last FPU instruction pointer
    uint64_t fpuDP       = 0;         // Last FPU data pointer
    int8_t   fpuTop      = 0;         // Stack top pointer (0-7)

    [[nodiscard]] int8_t FPUStackTop() const noexcept { return fpuTop; }

    [[nodiscard]] FPUReg& FPU_ST(int offset) noexcept {
        return fpuStack[(fpuTop + offset) & 7];
    }
    [[nodiscard]] const FPUReg& FPU_ST(int offset) const noexcept {
        return fpuStack[(fpuTop + offset) & 7];
    }

    void FPUPush(long double value) noexcept {
        uint8_t newTop = (fpuTop - 1) & 7;
        // Check for stack overflow (register not empty → C1=1, IE=1 in status)
        if (((fpuTag >> (newTop * 2)) & 3) != 3) {
            fpuStatus |= (1 << 9);   // C1 = 1 (stack overflow)
            fpuStatus |= (1 << 6);   // Stack Fault
            fpuStatus |= (1 << 0);   // Invalid Exception
        }
        fpuTop = newTop;
        fpuStack[fpuTop].value = value;
        fpuTag &= ~(3 << (fpuTop * 2));
    }

    [[nodiscard]] long double FPUPop() noexcept {
        // Check for stack underflow (register empty → C1=0, IE=1)
        if (((fpuTag >> (fpuTop * 2)) & 3) == 3) {
            fpuStatus &= ~(1 << 9);  // C1 = 0 (stack underflow)
            fpuStatus |= (1 << 6);   // Stack Fault
            fpuStatus |= (1 << 0);   // Invalid Exception
        }
        long double val = fpuStack[fpuTop].value;
        fpuTag |= (3 << (fpuTop * 2));
        fpuTop = (fpuTop + 1) & 7;
        return val;
    }

    // ========================================================================
    // SSE State (XMM registers + MXCSR)
    // ========================================================================
    std::array<XMMReg, 16> xmm{};
    uint32_t mxcsr = 0x1F80;   // Default: all exceptions masked

    [[nodiscard]] XMMReg& XMM(uint8_t index) noexcept {
        return xmm[index & 0x0F];
    }
    [[nodiscard]] const XMMReg& XMM(uint8_t index) const noexcept {
        return xmm[index & 0x0F];
    }

    // ========================================================================
    // AVX State (YMM registers — upper 128 bits)
    // ========================================================================
    // YMM registers extend XMM: YMM[i] = { XMM[i] (low 128) | ymmHigh[i] (high 128) }
    // The low 128 bits are stored in xmm[], the high 128 bits here.
    std::array<XMMReg, 16> ymmHigh{};  // Upper halves of YMM0-YMM15

    // Get pointer to full 256-bit YMM value (caller provides 32-byte aligned buffer)
    void GetYMM(uint8_t index, void* dst32) const noexcept {
        auto idx = index & 0x0F;
        std::memcpy(dst32, xmm[idx].u8, 16);
        std::memcpy(static_cast<uint8_t*>(dst32) + 16, ymmHigh[idx].u8, 16);
    }
    void SetYMM(uint8_t index, const void* src32) noexcept {
        auto idx = index & 0x0F;
        std::memcpy(xmm[idx].u8, src32, 16);
        std::memcpy(ymmHigh[idx].u8, static_cast<const uint8_t*>(src32) + 16, 16);
    }

    // Clear upper halves (VEX-encoded 128-bit ops zero the upper YMM bits)
    void ClearYMMHigh(uint8_t index) noexcept {
        ymmHigh[index & 0x0F].Clear();
    }

    // ========================================================================
    // Execution Mode
    // ========================================================================
    CPUMode mode = CPUMode::Long64;

    [[nodiscard]] bool Is64Bit() const noexcept { return mode == CPUMode::Long64; }
    [[nodiscard]] bool Is32Bit() const noexcept { return mode == CPUMode::Protected32; }
    [[nodiscard]] bool Is16Bit() const noexcept { return mode == CPUMode::Real16; }

    [[nodiscard]] OperandSize DefaultOperandSize() const noexcept {
        switch (mode) {
            case CPUMode::Long64:      return OperandSize::Size32; // Default in long mode is 32!
            case CPUMode::Protected32: return OperandSize::Size32;
            case CPUMode::Real16:      return OperandSize::Size16;
        }
        return OperandSize::Size32;
    }

    [[nodiscard]] AddressSize DefaultAddressSize() const noexcept {
        switch (mode) {
            case CPUMode::Long64:      return AddressSize::Addr64;
            case CPUMode::Protected32: return AddressSize::Addr32;
            case CPUMode::Real16:      return AddressSize::Addr16;
        }
        return AddressSize::Addr64;
    }

    // ========================================================================
    // Instruction Counter (for analysis + limits)
    // ========================================================================
    uint64_t instructionCount = 0;

    // ========================================================================
    // TSC (Time Stamp Counter — fake, for anti-evasion)
    // ========================================================================
    uint64_t tsc = 0;
    uint64_t tscIncrement = 25;   // ~25 cycles per instruction at 3.8 GHz
};

} // namespace Phantom
