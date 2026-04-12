/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Constants.hpp"
#include "../../Common/Platform.hpp"
#include <cstdint>
#include <array>

namespace Phantom {

// ============================================================================
// EFLAGS Register Manipulation
// ============================================================================
// Every arithmetic/logic instruction must update flags correctly.
// A single wrong flag bit can cause conditional branches to go the wrong way,
// which means malware executes the wrong code path → missed detection.
// This class must be PERFECT.

class EFlags {
public:
    EFlags() noexcept : m_flags(0x202) {} // IF=1, reserved bit 1 always set
    explicit EFlags(uint64_t raw) noexcept : m_flags(raw | 0x2) {} // bit 1 always set

    [[nodiscard]] uint64_t Raw() const noexcept { return m_flags; }
    void SetRaw(uint64_t val) noexcept { m_flags = (val & kWritableMask) | 0x2; }

    // === Individual flag accessors ===
    [[nodiscard]] bool CF() const noexcept { return (m_flags & Flags::CF) != 0; }
    [[nodiscard]] bool PF() const noexcept { return (m_flags & Flags::PF) != 0; }
    [[nodiscard]] bool AF() const noexcept { return (m_flags & Flags::AF) != 0; }
    [[nodiscard]] bool ZF() const noexcept { return (m_flags & Flags::ZF) != 0; }
    [[nodiscard]] bool SF() const noexcept { return (m_flags & Flags::SF) != 0; }
    [[nodiscard]] bool TF() const noexcept { return (m_flags & Flags::TF) != 0; }
    [[nodiscard]] bool IF() const noexcept { return (m_flags & Flags::IF) != 0; }
    [[nodiscard]] bool DF() const noexcept { return (m_flags & Flags::DF) != 0; }
    [[nodiscard]] bool OF() const noexcept { return (m_flags & Flags::OF) != 0; }

    void SetCF(bool v) noexcept { SetBit(Flags::CF, v); }
    void SetPF(bool v) noexcept { SetBit(Flags::PF, v); }
    void SetAF(bool v) noexcept { SetBit(Flags::AF, v); }
    void SetZF(bool v) noexcept { SetBit(Flags::ZF, v); }
    void SetSF(bool v) noexcept { SetBit(Flags::SF, v); }
    void SetTF(bool v) noexcept { SetBit(Flags::TF, v); }
    void SetIF(bool v) noexcept { SetBit(Flags::IF, v); }
    void SetDF(bool v) noexcept { SetBit(Flags::DF, v); }
    void SetOF(bool v) noexcept { SetBit(Flags::OF, v); }

    // === Bulk flag manipulation (bitmask-style) ===
    // Used by SSE/SSE4 comparison instructions (COMISS, COMISD, PCMPESTRI, etc.)
    // that need to set/clear multiple flags atomically based on comparison results.
    void Set(uint64_t mask) noexcept { m_flags |= (mask & kWritableMask); }
    void Clear(uint64_t mask) noexcept { m_flags &= ~(mask & kWritableMask); m_flags |= 0x2; }

    // === Parity flag computation ===
    // PF is based on the low 8 bits of the result only
    void UpdatePF(uint64_t result) noexcept {
        SetPF(Flags::ComputeParity(static_cast<uint8_t>(result)));
    }

    // === Zero flag computation ===
    void UpdateZF8(uint8_t result) noexcept { SetZF(result == 0); }
    void UpdateZF16(uint16_t result) noexcept { SetZF(result == 0); }
    void UpdateZF32(uint32_t result) noexcept { SetZF(result == 0); }
    void UpdateZF64(uint64_t result) noexcept { SetZF(result == 0); }

    // === Sign flag computation ===
    void UpdateSF8(uint8_t result) noexcept { SetSF((result & 0x80) != 0); }
    void UpdateSF16(uint16_t result) noexcept { SetSF((result & 0x8000) != 0); }
    void UpdateSF32(uint32_t result) noexcept { SetSF((result & 0x80000000) != 0); }
    void UpdateSF64(uint64_t result) noexcept { SetSF((result & 0x8000000000000000ULL) != 0); }

    // === Combined flag updates for common operations ===

    // Update SF, ZF, PF based on result (used by most ALU ops)
    void UpdateSZP8(uint8_t result) noexcept {
        UpdateSF8(result); UpdateZF8(result); UpdatePF(result);
    }
    void UpdateSZP16(uint16_t result) noexcept {
        UpdateSF16(result); UpdateZF16(result); UpdatePF(result);
    }
    void UpdateSZP32(uint32_t result) noexcept {
        UpdateSF32(result); UpdateZF32(result); UpdatePF(result);
    }
    void UpdateSZP64(uint64_t result) noexcept {
        UpdateSF64(result); UpdateZF64(result); UpdatePF(result);
    }

    // === Full ADD flag update (all 6 arithmetic flags) ===
    void UpdateFlagsAdd8(uint8_t a, uint8_t b, uint8_t result) noexcept {
        UpdateSZP8(result);
        SetCF(result < a);
        SetOF(((a ^ result) & (b ^ result) & 0x80) != 0);
        SetAF(((a ^ b ^ result) & 0x10) != 0);
    }
    void UpdateFlagsAdd16(uint16_t a, uint16_t b, uint16_t result) noexcept {
        UpdateSZP16(result);
        SetCF(result < a);
        SetOF(((a ^ result) & (b ^ result) & 0x8000) != 0);
        SetAF(((a ^ b ^ result) & 0x10) != 0);
    }
    void UpdateFlagsAdd32(uint32_t a, uint32_t b, uint32_t result) noexcept {
        UpdateSZP32(result);
        SetCF(result < a);
        SetOF(((a ^ result) & (b ^ result) & 0x80000000) != 0);
        SetAF(((a ^ b ^ result) & 0x10) != 0);
    }
    void UpdateFlagsAdd64(uint64_t a, uint64_t b, uint64_t result) noexcept {
        UpdateSZP64(result);
        SetCF(result < a);
        SetOF(((a ^ result) & (b ^ result) & 0x8000000000000000ULL) != 0);
        SetAF(((a ^ b ^ result) & 0x10) != 0);
    }

    // === Full SUB flag update (all 6 arithmetic flags) ===
    void UpdateFlagsSub8(uint8_t a, uint8_t b, uint8_t result) noexcept {
        UpdateSZP8(result);
        SetCF(a < b);
        SetOF(((a ^ b) & (a ^ result) & 0x80) != 0);
        SetAF(((a ^ b ^ result) & 0x10) != 0);
    }
    void UpdateFlagsSub16(uint16_t a, uint16_t b, uint16_t result) noexcept {
        UpdateSZP16(result);
        SetCF(a < b);
        SetOF(((a ^ b) & (a ^ result) & 0x8000) != 0);
        SetAF(((a ^ b ^ result) & 0x10) != 0);
    }
    void UpdateFlagsSub32(uint32_t a, uint32_t b, uint32_t result) noexcept {
        UpdateSZP32(result);
        SetCF(a < b);
        SetOF(((a ^ b) & (a ^ result) & 0x80000000) != 0);
        SetAF(((a ^ b ^ result) & 0x10) != 0);
    }
    void UpdateFlagsSub64(uint64_t a, uint64_t b, uint64_t result) noexcept {
        UpdateSZP64(result);
        SetCF(a < b);
        SetOF(((a ^ b) & (a ^ result) & 0x8000000000000000ULL) != 0);
        SetAF(((a ^ b ^ result) & 0x10) != 0);
    }

    // === Logic operation flags (AND, OR, XOR, TEST) ===
    // CF=0, OF=0, AF undefined (we clear it)
    void UpdateFlagsLogic8(uint8_t result) noexcept {
        UpdateSZP8(result); SetCF(false); SetOF(false); SetAF(false);
    }
    void UpdateFlagsLogic16(uint16_t result) noexcept {
        UpdateSZP16(result); SetCF(false); SetOF(false); SetAF(false);
    }
    void UpdateFlagsLogic32(uint32_t result) noexcept {
        UpdateSZP32(result); SetCF(false); SetOF(false); SetAF(false);
    }
    void UpdateFlagsLogic64(uint64_t result) noexcept {
        UpdateSZP64(result); SetCF(false); SetOF(false); SetAF(false);
    }

    // === INC/DEC flags (all except CF — CF is preserved) ===
    void UpdateFlagsInc8(uint8_t a, uint8_t result) noexcept {
        UpdateSZP8(result);
        SetOF(a == 0x7F);
        SetAF(((a ^ 1 ^ result) & 0x10) != 0);
    }
    void UpdateFlagsInc16(uint16_t a, uint16_t result) noexcept {
        UpdateSZP16(result);
        SetOF(a == 0x7FFF);
        SetAF(((a ^ 1 ^ result) & 0x10) != 0);
    }
    void UpdateFlagsInc32(uint32_t a, uint32_t result) noexcept {
        UpdateSZP32(result);
        SetOF(a == 0x7FFFFFFF);
        SetAF(((a ^ 1 ^ result) & 0x10) != 0);
    }
    void UpdateFlagsInc64(uint64_t a, uint64_t result) noexcept {
        UpdateSZP64(result);
        SetOF(a == 0x7FFFFFFFFFFFFFFFULL);
        SetAF(((a ^ 1 ^ result) & 0x10) != 0);
    }

    void UpdateFlagsDec8(uint8_t a, uint8_t result) noexcept {
        UpdateSZP8(result);
        SetOF(a == 0x80);
        SetAF(((a ^ 1 ^ result) & 0x10) != 0);
    }
    void UpdateFlagsDec16(uint16_t a, uint16_t result) noexcept {
        UpdateSZP16(result);
        SetOF(a == 0x8000);
        SetAF(((a ^ 1 ^ result) & 0x10) != 0);
    }
    void UpdateFlagsDec32(uint32_t a, uint32_t result) noexcept {
        UpdateSZP32(result);
        SetOF(a == 0x80000000);
        SetAF(((a ^ 1 ^ result) & 0x10) != 0);
    }
    void UpdateFlagsDec64(uint64_t a, uint64_t result) noexcept {
        UpdateSZP64(result);
        SetOF(a == 0x8000000000000000ULL);
        SetAF(((a ^ 1 ^ result) & 0x10) != 0);
    }

    // === Condition code evaluation (Jcc, CMOVcc, SETcc) ===
    [[nodiscard]] bool EvaluateCondition(uint8_t cc) const noexcept {
        switch (cc & 0x0F) {
            case 0x0: return OF();                          // O:   OF=1
            case 0x1: return !OF();                         // NO:  OF=0
            case 0x2: return CF();                          // B:   CF=1
            case 0x3: return !CF();                         // NB:  CF=0
            case 0x4: return ZF();                          // Z:   ZF=1
            case 0x5: return !ZF();                         // NZ:  ZF=0
            case 0x6: return CF() || ZF();                  // BE:  CF=1 or ZF=1
            case 0x7: return !CF() && !ZF();                // NBE: CF=0 and ZF=0
            case 0x8: return SF();                          // S:   SF=1
            case 0x9: return !SF();                         // NS:  SF=0
            case 0xA: return PF();                          // P:   PF=1
            case 0xB: return !PF();                         // NP:  PF=0
            case 0xC: return SF() != OF();                  // L:   SF≠OF
            case 0xD: return SF() == OF();                  // NL:  SF=OF
            case 0xE: return ZF() || (SF() != OF());        // LE:  ZF=1 or SF≠OF
            case 0xF: return !ZF() && (SF() == OF());       // NLE: ZF=0 and SF=OF
            default:  return false;
        }
    }

private:
    uint64_t m_flags;

    // Bits that can be modified by user code
    static constexpr uint64_t kWritableMask =
        Flags::CF | Flags::PF | Flags::AF | Flags::ZF | Flags::SF |
        Flags::TF | Flags::IF | Flags::DF | Flags::OF | Flags::AC | Flags::ID;

    void SetBit(uint64_t mask, bool value) noexcept {
        if (value) m_flags |= mask;
        else       m_flags &= ~mask;
    }
};

} // namespace Phantom
