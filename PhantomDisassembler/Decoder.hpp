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
 * PhantomDisassembler - x86-64 INSTRUCTION DECODER
 * ============================================================================
 *
 * @file Decoder.hpp
 * @brief Standalone x86-64 instruction decoder for the ShadowStrike platform.
 *
 * Provides complete decode of x86-64 instructions from raw byte buffers into
 * structured DecodedInstruction/DecodedOperand representations. Designed for
 * use in static analysis, emulation, and real-time threat detection paths.
 *
 * DESIGN PRINCIPLES:
 * ==================
 *
 * 1. STATELESS PER-DECODE
 *    - The Decoder stores only its configured MachineMode.
 *    - All per-decode state lives in a stack-allocated DecodeContext that
 *      never escapes DecodeFull().
 *    - Init once, decode many — matches Zydis-style usage patterns.
 *
 * 2. ALLOCATION-FREE
 *    - Zero heap allocations in any decode path.
 *    - All scratch state is stack-local.
 *    - Safe for hot-path integration in scan engines.
 *
 * 3. THREAD-SAFE
 *    - Multiple threads may call DecodeFull() concurrently on the same
 *      Decoder instance with no synchronization required.
 *    - All const methods, no mutable shared state.
 *
 * 4. NOEXCEPT THROUGHOUT
 *    - Every public and private method is noexcept.
 *    - No exceptions, no undefined behavior on malformed input.
 *    - Error conditions are reported through the Status return type.
 *
 * DECODE PIPELINE:
 * ================
 *
 *   DecodeFull()
 *     |-- DecodePrefixes()        Legacy prefixes (groups 1-4)
 *     |-- DecodeVEX() / EVEX()    VEX/EVEX prefix detection
 *     |-- DecodeOpcode()          Primary/escape opcode bytes
 *     |-- DecodeModRM() / SIB()   Addressing mode resolution
 *     |-- DecodeDisplacement()    Memory displacement bytes
 *     |-- DecodeImmediate()       Immediate operand bytes
 *     |-- Operand building        Register/Memory/Immediate operands
 *     `-- Mnemonic resolution     Opcode -> mnemonic mapping
 *
 * USAGE:
 * ======
 *
 *   Phantom::Disasm::Decoder decoder;
 *   auto status = decoder.Init(Phantom::Disasm::MachineMode::Long64);
 *   if (Phantom::Disasm::IsFailed(status)) { ... }
 *
 *   Phantom::Disasm::DecodedInstruction inst{};
 *   Phantom::Disasm::DecodedOperand operands[MAX_OPERANDS]{};
 *
 *   status = decoder.DecodeFull(buffer, length, inst, operands);
 *   if (Phantom::Disasm::IsSuccess(status)) {
 *       // inst.length contains the byte length consumed
 *       // inst.mnemonic contains the resolved mnemonic
 *       // operands[0..inst.operandCount-1] contain decoded operands
 *   }
 *
 * @see Types.hpp       Enumerations: MachineMode, Register, Mnemonic, etc.
 * @see Instruction.hpp Structures: DecodedInstruction, DecodedOperand
 */
#pragma once

#include "Types.hpp"
#include "Instruction.hpp"

#include <cstdint>
#include <cstddef>

namespace Phantom::Disasm {

// ============================================================================
// Status codes for decoder operations
// ============================================================================

/// Result codes returned by all fallible decoder operations.
/// Every decode call returns a Status; callers must check before using output.
enum class Status : uint32_t {
    Success             = 0,    ///< Decode completed successfully
    InvalidInput        = 1,    ///< Null buffer or zero length supplied
    InvalidOpcode       = 2,    ///< Unrecognized or undefined opcode encoding
    InvalidPrefix       = 3,    ///< Contradictory or malformed prefix sequence
    InvalidModRM        = 4,    ///< Invalid ModR/M or SIB encoding
    InstructionTooLong  = 5,    ///< Instruction exceeds 15-byte x86 maximum
    TruncatedInput      = 6,    ///< Buffer ended before instruction was complete
    UnsupportedEncoding = 7,    ///< Valid but unsupported encoding (e.g., XOP, 3DNow!)
    InternalError       = 8,    ///< Logic error — should never occur in production
};

/// @brief Check if a decode status represents success.
[[nodiscard]] constexpr bool IsSuccess(Status s) noexcept
{
    return s == Status::Success;
}

/// @brief Check if a decode status represents a failure.
[[nodiscard]] constexpr bool IsFailed(Status s) noexcept
{
    return s != Status::Success;
}

// ============================================================================
// Decoder — Main x86-64 instruction decoder
// ============================================================================

/// @brief Stateless, allocation-free, thread-safe x86-64 instruction decoder.
///
/// Stores only the target machine mode. All per-decode state is stack-local.
/// Safe for concurrent use from multiple threads without synchronization.
class Decoder {
public:
    Decoder() noexcept = default;
    ~Decoder() noexcept = default;

    Decoder(const Decoder&) noexcept = default;
    Decoder& operator=(const Decoder&) noexcept = default;
    Decoder(Decoder&&) noexcept = default;
    Decoder& operator=(Decoder&&) noexcept = default;

    // === Initialization =====

    /// @brief Initialize the decoder for a specific machine mode.
    ///
    /// Must be called exactly once before any DecodeFull() calls.
    /// Subsequent calls reinitialize the decoder for a different mode.
    ///
    /// @param mode  Target machine mode (Long64, CompatProtected32, Real16)
    /// @return Status::Success on valid mode, Status::InvalidInput otherwise
    [[nodiscard]] Status Init(MachineMode mode) noexcept;

    // === Primary decode API =====

    /// @brief Decode a single x86-64 instruction from a raw byte buffer.
    ///
    /// This is the main entry point. It runs the full decode pipeline:
    /// prefixes → VEX/EVEX → opcode → ModRM/SIB → displacement → immediate
    /// → operand building → mnemonic resolution.
    ///
    /// @param buffer       Pointer to instruction bytes (must not be null)
    /// @param length       Number of available bytes (>= 15 recommended)
    /// @param instruction  Output: fully populated on success
    /// @param operands     Output: array of at least MAX_OPERANDS elements
    /// @return Status::Success on successful decode; error code otherwise
    ///
    /// @pre  Init() must have been called and returned Success.
    /// @pre  buffer != nullptr && length > 0
    /// @pre  operands points to an array of at least MAX_OPERANDS elements.
    /// @post On success, instruction.length bytes have been consumed from buffer.
    /// @post On failure, instruction and operands contents are undefined.
    [[nodiscard]] Status DecodeFull(
        const uint8_t* buffer,
        size_t length,
        DecodedInstruction& instruction,
        DecodedOperand* operands) const noexcept;

    // === Accessors =====

    /// @brief Get the machine mode this decoder was initialized for.
    [[nodiscard]] MachineMode GetMode() const noexcept { return m_mode; }

    /// @brief Check if Init() has been called successfully.
    [[nodiscard]] bool IsInitialized() const noexcept { return m_initialized; }

private:
    // ========================================================================
    // Instance state — only mode; everything else is per-decode
    // ========================================================================

    MachineMode m_mode = MachineMode::Long64;
    bool m_initialized = false;

    // ========================================================================
    // DecodeContext — stack-allocated scratch pad for a single DecodeFull call
    // ========================================================================

    /// @brief Per-decode scratch state.  Stack-allocated, never escapes DecodeFull().
    ///
    /// Captures all transient decoding state: prefix flags, REX/VEX/EVEX fields,
    /// opcode map position, ModRM/SIB bytes, and effective operand/address widths.
    struct DecodeContext {
        // --- Input buffer ---
        const uint8_t* buffer       = nullptr;
        size_t         bufferLength = 0;
        uint32_t       offset       = 0;       ///< Current read position in buffer
        uint64_t       rip          = 0;       ///< Virtual address of instruction start

        // --- Legacy prefix state (groups 1–4) ---
        bool     hasLock            = false;
        bool     hasRep             = false;    ///< F3 prefix (REP / REPE)
        bool     hasRepNE           = false;    ///< F2 prefix (REPNE / BND)
        bool     hasSegOverride     = false;
        Register segOverride        = Register::NONE;
        bool     hasOpSizeOverride  = false;    ///< 66h operand-size override
        bool     hasAddrSizeOverride = false;   ///< 67h address-size override

        // --- REX prefix (40h–4Fh, Long64 only) ---
        bool hasREX = false;
        bool rexW   = false;    ///< 64-bit operand size
        bool rexR   = false;    ///< ModRM reg extension
        bool rexX   = false;    ///< SIB index extension
        bool rexB   = false;    ///< ModRM r/m or SIB base extension

        // --- REX2 prefix (D5h, APX future extension) ---
        bool hasREX2 = false;
        bool rex2R4  = false;   ///< 5th bit for ModRM reg (r16-r31)
        bool rex2X4  = false;   ///< 5th bit for SIB index (r16-r31)
        bool rex2B4  = false;   ///< 5th bit for ModRM r/m / SIB base (r16-r31)

        // --- VEX prefix (C4h 3-byte / C5h 2-byte) ---
        bool    hasVEX   = false;
        uint8_t vexL     = 0;       ///< Vector length (0=128, 1=256)
        uint8_t vexPP    = 0;       ///< Implied mandatory prefix
        uint8_t vexMMMMM = 1;       ///< Implied opcode map
        uint8_t vexVVVV  = 0;       ///< Additional register specifier (inverted)
        bool    vexW     = false;   ///< Operand size promotion / opcode extension

        // --- EVEX prefix (62h, 4-byte) ---
        bool    hasEVEX  = false;
        uint8_t evexZ    = 0;       ///< Zeroing-masking
        uint8_t evexLL   = 0;       ///< Vector length / rounding control
        uint8_t evexB    = 0;       ///< Broadcast / rounding / SAE
        uint8_t evexAAA  = 0;       ///< Opmask register k1–k7
        uint8_t evexV2   = 0;       ///< High-16 register extension for VVVV
        uint8_t evexR2   = 0;       ///< High-16 register extension for ModRM.reg

        uint8_t prefixCount = 0;    ///< Total legacy prefix byte count

        // --- Opcode identification ---
        uint8_t opcodeMap = 0;      ///< 0=one-byte, 1=0F, 2=0F38, 3=0F3A
        uint8_t opcode    = 0;      ///< Primary opcode byte
        uint8_t opcodeExt = 0;      ///< ModRM reg field used as opcode extension

        // --- ModRM / SIB ---
        uint8_t modrm    = 0;
        uint8_t sib      = 0;
        bool    hasModRM = false;
        bool    hasSIB   = false;

        // --- Effective sizes (resolved after prefix decode) ---
        uint16_t effectiveOperandWidth = 32;
        uint16_t effectiveAddressWidth = 64;

        /// @brief Reset all fields to default state for a new decode.
        void Reset() noexcept;
    };

    // ========================================================================
    // Decode phases — called sequentially by DecodeFull()
    // ========================================================================

    /// @brief Decode legacy prefix bytes (groups 1–4, REX).
    Status DecodePrefixes(DecodeContext& ctx) const noexcept;

    /// @brief Decode 2-byte (C5h) or 3-byte (C4h) VEX prefix.
    Status DecodeVEX(DecodeContext& ctx) const noexcept;

    /// @brief Decode 4-byte EVEX prefix (62h).
    Status DecodeEVEX(DecodeContext& ctx) const noexcept;

    /// @brief Decode primary opcode byte and escape sequences (0Fh, 0F38h, 0F3Ah).
    Status DecodeOpcode(DecodeContext& ctx) const noexcept;

    /// @brief Decode ModR/M byte and extract mod, reg, rm fields.
    Status DecodeModRM(DecodeContext& ctx) const noexcept;

    /// @brief Decode SIB byte (scale-index-base addressing).
    Status DecodeSIB(DecodeContext& ctx) const noexcept;

    /// @brief Read and sign-extend a displacement of the given byte size.
    /// @param dispSize  Displacement size in bytes (0, 1, 2, or 4)
    /// @param disp      Output: sign-extended displacement value
    Status DecodeDisplacement(DecodeContext& ctx, uint8_t dispSize, int64_t& disp) const noexcept;

    /// @brief Read and optionally sign-extend an immediate of the given byte size.
    /// @param immSize   Immediate size in bytes (1, 2, 4, or 8)
    /// @param imm       Output: sign-extended immediate value
    Status DecodeImmediate(DecodeContext& ctx, uint8_t immSize, int64_t& imm) const noexcept;

    // ========================================================================
    // Operand building — populate DecodedOperand from decode context
    // ========================================================================

    /// @brief Build a register operand.
    void BuildRegOperand(DecodedOperand& op, Register reg,
                         uint16_t sizeBits) const noexcept;

    /// @brief Build a memory operand from ModRM/SIB decode state.
    void BuildMemOperand(DecodedOperand& op, const DecodeContext& ctx,
                         int64_t displacement, uint16_t sizeBits) const noexcept;

    /// @brief Build an immediate operand.
    /// @param isRelative  True for RIP-relative branch targets
    void BuildImmOperand(DecodedOperand& op, int64_t value, uint16_t sizeBits,
                         bool isSigned, bool isRelative = false) const noexcept;

    // ========================================================================
    // Resolution helpers — opcode tables and mnemonic lookup
    // ========================================================================

    /// @brief Determine whether an opcode requires a ModR/M byte.
    [[nodiscard]] bool OpcodeRequiresModRM(uint8_t map, uint8_t opcode) const noexcept;

    /// @brief Determine the immediate operand size for an opcode.
    /// @return Immediate size in bytes (0 if none)
    [[nodiscard]] uint8_t OpcodeImmediateSize(uint8_t map, uint8_t opcode,
                                              uint16_t opWidth) const noexcept;

    /// @brief Resolve the mnemonic from the current opcode + prefix state.
    [[nodiscard]] Mnemonic ResolveMnemonic(const DecodeContext& ctx) const noexcept;

    /// @brief Resolve VEX-encoded mnemonic (AVX/AVX2/FMA/BMI).
    [[nodiscard]] Mnemonic ResolveVEXMnemonic(const DecodeContext& ctx) const noexcept;

    /// @brief Resolve EVEX-encoded mnemonic (AVX-512).
    [[nodiscard]] Mnemonic ResolveEVEXMnemonic(const DecodeContext& ctx) const noexcept;

    /// @brief Map a mnemonic to its instruction category.
    [[nodiscard]] InstructionCategory ResolveCategory(Mnemonic mnem) const noexcept;

    /// @brief Determine the ISA extension required by the current encoding.
    [[nodiscard]] ISAExtension ResolveISAExtension(const DecodeContext& ctx) const noexcept;

    // ========================================================================
    // Register resolution — index + width → Register enum
    // ========================================================================

    /// @brief Resolve a general-purpose register from encoding index and width.
    /// @param index    Register index (0–15, accounting for REX extensions)
    /// @param sizeBits Operand size in bits (8, 16, 32, 64)
    /// @param hasRex   True if REX prefix was present (affects high-byte regs)
    [[nodiscard]] Register ResolveGPR(uint8_t index, uint16_t sizeBits,
                                      bool hasRex) const noexcept;

    /// @brief Resolve a segment register from its 3-bit encoding.
    [[nodiscard]] Register ResolveSegment(uint8_t index) const noexcept;

    /// @brief Resolve an XMM/YMM/ZMM register from index and vector length.
    [[nodiscard]] Register ResolveSIMD(uint8_t index,
                                       uint8_t vectorLength) const noexcept;

    /// @brief Determine the default segment register for a given base register.
    /// @return Register::SS for RSP/RBP-based addressing, Register::DS otherwise.
    [[nodiscard]] Register DefaultSegment(uint8_t baseReg) const noexcept;

    // ========================================================================
    // Composite operand decode for common encoding forms
    // ========================================================================

    /// @brief Decode operands for a ModRM-based instruction (reg, r/m).
    /// @param regSize   Size of the reg operand in bits
    /// @param rmSize    Size of the r/m operand in bits
    /// @param regIsDst  True if reg field is the destination operand
    void DecodeModRMOperands(DecodeContext& ctx, DecodedInstruction& inst,
                             DecodedOperand* operands, uint16_t regSize,
                             uint16_t rmSize, bool regIsDst) const noexcept;

    /// @brief Decode accumulator + immediate form (e.g., ADD AL, imm8).
    void DecodeAccumImm(DecodeContext& ctx, DecodedInstruction& inst,
                        DecodedOperand* operands, uint16_t size) const noexcept;

    /// @brief Decode opcode-embedded register form (e.g., PUSH r64, MOV r32, imm32).
    void DecodeOpcodeReg(DecodeContext& ctx, DecodedInstruction& inst,
                         DecodedOperand* operands, uint16_t size) const noexcept;

    // ========================================================================
    // Bounds-checked byte reading from decode buffer
    // ========================================================================

    /// @brief Read a single byte from the buffer at the given offset.
    [[nodiscard]] bool ReadByte(const DecodeContext& ctx, uint32_t offset,
                                uint8_t& out) const noexcept;

    /// @brief Read a little-endian 16-bit word from the buffer.
    [[nodiscard]] bool ReadWord(const DecodeContext& ctx, uint32_t offset,
                                uint16_t& out) const noexcept;

    /// @brief Read a little-endian 32-bit dword from the buffer.
    [[nodiscard]] bool ReadDword(const DecodeContext& ctx, uint32_t offset,
                                 uint32_t& out) const noexcept;

    /// @brief Read a little-endian 64-bit qword from the buffer.
    [[nodiscard]] bool ReadQword(const DecodeContext& ctx, uint32_t offset,
                                 uint64_t& out) const noexcept;

    // ========================================================================
    // Sign extension utilities
    // ========================================================================

    /// @brief Sign-extend an 8-bit value to 64 bits.
    [[nodiscard]] static int64_t SignExtend8(uint8_t v) noexcept;

    /// @brief Sign-extend a 16-bit value to 64 bits.
    [[nodiscard]] static int64_t SignExtend16(uint16_t v) noexcept;

    /// @brief Sign-extend a 32-bit value to 64 bits.
    [[nodiscard]] static int64_t SignExtend32(uint32_t v) noexcept;

    // ========================================================================
    // Effective size computation
    // ========================================================================

    /// @brief Resolve effective operand and address widths from mode + prefixes.
    ///
    /// Must be called after prefix decoding and before operand building.
    /// Takes into account: machine mode, REX.W, 66h override, 67h override,
    /// VEX.W, and default operand/address sizes for the current mode.
    void ResolveEffectiveSizes(DecodeContext& ctx) const noexcept;
};

} // namespace Phantom::Disasm
