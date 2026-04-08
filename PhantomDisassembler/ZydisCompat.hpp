/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomDisassembler - Standalone x86-64 Instruction Disassembler
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

/**
 * ============================================================================
 * PhantomDisassembler — ZYDIS API COMPATIBILITY LAYER
 * ============================================================================
 *
 * @file ZydisCompat.hpp
 * @brief Drop-in replacement for <Zydis/Zydis.h>.
 *
 * This header provides type aliases, macro constants, and inline wrapper
 * functions that map the Zydis disassembler API surface to the native
 * PhantomDisassembler engine.
 *
 * MIGRATION GUIDE:
 * ================
 *
 * To migrate a translation unit from Zydis to PhantomDisassembler:
 *
 *   1. Replace:
 *        #include <Zydis/Zydis.h>
 *      with:
 *        #include <PhantomDisassembler/ZydisCompat.hpp>
 *
 *   2. Remove:
 *        #pragma comment(lib, "Zydis.lib")
 *
 *   3. Recompile. No other source changes should be required.
 *
 * COMPATIBILITY SCOPE:
 * ====================
 * This layer covers the exact Zydis API surface used by ShadowStrike's
 * AntiEvasion analysis modules. It is NOT a complete Zydis reimplementation.
 * Symbols not used by ShadowStrike are intentionally omitted to avoid
 * maintenance burden on dead code.
 */
#pragma once

#include "PhantomDisasm.hpp"

#include <cstdint>
#include <cstddef>
#include <type_traits>

// ============================================================================
// Section 1 — Zycore scalar type aliases
// ============================================================================

using ZyanStatus = Phantom::Disasm::Status;
using ZyanU8     = uint8_t;
using ZyanU16    = uint16_t;
using ZyanU32    = uint32_t;
using ZyanU64    = uint64_t;
using ZyanI8     = int8_t;
using ZyanI16    = int16_t;
using ZyanI32    = int32_t;
using ZyanI64    = int64_t;
using ZyanBool   = bool;
using ZyanUSize  = size_t;

#define ZYAN_NULL nullptr

// ============================================================================
// Section 2 — Status-checking macros
// ============================================================================

#define ZYAN_SUCCESS(status) (Phantom::Disasm::IsSuccess(status))
#define ZYAN_FAILED(status)  (Phantom::Disasm::IsFailed(status))

// ============================================================================
// Section 3 — Primary type aliases
// ============================================================================

using ZydisDecoder             = Phantom::Disasm::Decoder;
using ZydisDecodedInstruction  = Phantom::Disasm::DecodedInstruction;
using ZydisDecodedOperand      = Phantom::Disasm::DecodedOperand;
using ZydisFormatter           = Phantom::Disasm::Formatter;
using ZydisMnemonic            = Phantom::Disasm::Mnemonic;
using ZydisRegister            = Phantom::Disasm::Register;
using ZydisMachineMode         = Phantom::Disasm::MachineMode;
using ZydisStackWidth          = uint8_t;
using ZydisFormatterStyle      = Phantom::Disasm::FormatterStyle;
using ZydisOperandType         = Phantom::Disasm::OperandType;

// Nested struct aliases for field-access compatibility
using ZydisDecodedOperandReg = Phantom::Disasm::DecodedOperandReg;
using ZydisDecodedOperandMem = Phantom::Disasm::DecodedOperandMem;
using ZydisDecodedOperandImm = Phantom::Disasm::DecodedOperandImm;
using ZydisDecodedOperandPtr = Phantom::Disasm::DecodedOperandPtr;

// ============================================================================
// Section 4 — Machine mode constants
// ============================================================================

#define ZYDIS_MACHINE_MODE_LONG_64        Phantom::Disasm::MachineMode::Long64
#define ZYDIS_MACHINE_MODE_LEGACY_32      Phantom::Disasm::MachineMode::Legacy32
#define ZYDIS_MACHINE_MODE_LONG_COMPAT_32 Phantom::Disasm::MachineMode::LongCompat32
#define ZYDIS_MACHINE_MODE_LONG_COMPAT_16 Phantom::Disasm::MachineMode::Real16
#define ZYDIS_MACHINE_MODE_LEGACY_16      Phantom::Disasm::MachineMode::Real16
#define ZYDIS_MACHINE_MODE_REAL_16        Phantom::Disasm::MachineMode::Real16

// ============================================================================
// Section 5 — Stack width constants (ignored by PhantomDisassembler;
//             the machine mode alone determines default widths)
// ============================================================================

#define ZYDIS_STACK_WIDTH_16  static_cast<ZydisStackWidth>(2)
#define ZYDIS_STACK_WIDTH_32  static_cast<ZydisStackWidth>(4)
#define ZYDIS_STACK_WIDTH_64  static_cast<ZydisStackWidth>(8)

// ============================================================================
// Section 6 — Operand type constants
// ============================================================================

#define ZYDIS_OPERAND_TYPE_UNUSED    Phantom::Disasm::OperandType::NONE
#define ZYDIS_OPERAND_TYPE_REGISTER  Phantom::Disasm::OperandType::REGISTER
#define ZYDIS_OPERAND_TYPE_MEMORY    Phantom::Disasm::OperandType::MEMORY
#define ZYDIS_OPERAND_TYPE_POINTER   Phantom::Disasm::OperandType::POINTER
#define ZYDIS_OPERAND_TYPE_IMMEDIATE Phantom::Disasm::OperandType::IMMEDIATE

// ============================================================================
// Section 7 — Instruction attribute constants
// ============================================================================

#define ZYDIS_ATTRIB_HAS_LOCK        Phantom::Disasm::ATTRIB_HAS_LOCK
#define ZYDIS_ATTRIB_HAS_REP         Phantom::Disasm::ATTRIB_HAS_REP
#define ZYDIS_ATTRIB_HAS_REPE        Phantom::Disasm::ATTRIB_HAS_REPE
#define ZYDIS_ATTRIB_HAS_REPNE       Phantom::Disasm::ATTRIB_HAS_REPNE
#define ZYDIS_ATTRIB_IS_RELATIVE     Phantom::Disasm::ATTRIB_IS_RELATIVE
#define ZYDIS_ATTRIB_IS_PRIVILEGED   Phantom::Disasm::ATTRIB_IS_PRIVILEGED
#define ZYDIS_ATTRIB_HAS_REX         Phantom::Disasm::ATTRIB_HAS_REX
#define ZYDIS_ATTRIB_HAS_VEX         Phantom::Disasm::ATTRIB_HAS_VEX
#define ZYDIS_ATTRIB_HAS_EVEX        Phantom::Disasm::ATTRIB_HAS_EVEX
#define ZYDIS_ATTRIB_HAS_MODRM       Phantom::Disasm::ATTRIB_HAS_MODRM
#define ZYDIS_ATTRIB_HAS_SIB         Phantom::Disasm::ATTRIB_HAS_SIB

// ============================================================================
// Section 8 — Formatter style constants
// ============================================================================

#define ZYDIS_FORMATTER_STYLE_INTEL Phantom::Disasm::FormatterStyle::Intel
#define ZYDIS_FORMATTER_STYLE_ATT   Phantom::Disasm::FormatterStyle::ATT

// ============================================================================
// Section 9 — Max operand count
// ============================================================================

#define ZYDIS_MAX_OPERAND_COUNT         Phantom::Disasm::MAX_OPERANDS
#define ZYDIS_MAX_OPERAND_COUNT_VISIBLE Phantom::Disasm::MAX_OPERANDS

// ============================================================================
// Section 10 — Mnemonic constants
//
// Maps every ZYDIS_MNEMONIC_* used by ShadowStrike AntiEvasion modules to
// the corresponding Phantom::Disasm::Mnemonic enumerator.
// ============================================================================

// Arithmetic / logic
#define ZYDIS_MNEMONIC_ADD        Phantom::Disasm::Mnemonic::ADD
#define ZYDIS_MNEMONIC_SUB        Phantom::Disasm::Mnemonic::SUB
#define ZYDIS_MNEMONIC_AND        Phantom::Disasm::Mnemonic::AND
#define ZYDIS_MNEMONIC_OR         Phantom::Disasm::Mnemonic::OR
#define ZYDIS_MNEMONIC_XOR        Phantom::Disasm::Mnemonic::XOR
#define ZYDIS_MNEMONIC_NOT        Phantom::Disasm::Mnemonic::NOT
#define ZYDIS_MNEMONIC_CMP        Phantom::Disasm::Mnemonic::CMP
#define ZYDIS_MNEMONIC_TEST       Phantom::Disasm::Mnemonic::TEST
#define ZYDIS_MNEMONIC_INC        Phantom::Disasm::Mnemonic::INC
#define ZYDIS_MNEMONIC_DEC        Phantom::Disasm::Mnemonic::DEC
#define ZYDIS_MNEMONIC_DIV        Phantom::Disasm::Mnemonic::DIV
#define ZYDIS_MNEMONIC_IDIV       Phantom::Disasm::Mnemonic::IDIV
#define ZYDIS_MNEMONIC_MUL        Phantom::Disasm::Mnemonic::MUL
#define ZYDIS_MNEMONIC_IMUL       Phantom::Disasm::Mnemonic::IMUL
#define ZYDIS_MNEMONIC_NEG        Phantom::Disasm::Mnemonic::NEG
#define ZYDIS_MNEMONIC_SHL        Phantom::Disasm::Mnemonic::SHL
#define ZYDIS_MNEMONIC_SHR        Phantom::Disasm::Mnemonic::SHR
#define ZYDIS_MNEMONIC_ROL        Phantom::Disasm::Mnemonic::ROL
#define ZYDIS_MNEMONIC_ROR        Phantom::Disasm::Mnemonic::ROR

// Data transfer
#define ZYDIS_MNEMONIC_MOV        Phantom::Disasm::Mnemonic::MOV
#define ZYDIS_MNEMONIC_MOVZX      Phantom::Disasm::Mnemonic::MOVZX
#define ZYDIS_MNEMONIC_LEA        Phantom::Disasm::Mnemonic::LEA
#define ZYDIS_MNEMONIC_XCHG       Phantom::Disasm::Mnemonic::XCHG
#define ZYDIS_MNEMONIC_CMPXCHG    Phantom::Disasm::Mnemonic::CMPXCHG

// Stack
#define ZYDIS_MNEMONIC_PUSH       Phantom::Disasm::Mnemonic::PUSH
#define ZYDIS_MNEMONIC_POP        Phantom::Disasm::Mnemonic::POP
#define ZYDIS_MNEMONIC_PUSHA      Phantom::Disasm::Mnemonic::PUSHA
#define ZYDIS_MNEMONIC_PUSHAD     Phantom::Disasm::Mnemonic::PUSHAD
#define ZYDIS_MNEMONIC_POPA       Phantom::Disasm::Mnemonic::POPA
#define ZYDIS_MNEMONIC_POPAD      Phantom::Disasm::Mnemonic::POPAD
#define ZYDIS_MNEMONIC_PUSHF      Phantom::Disasm::Mnemonic::PUSHF
#define ZYDIS_MNEMONIC_PUSHFD     Phantom::Disasm::Mnemonic::PUSHFD
#define ZYDIS_MNEMONIC_PUSHFQ     Phantom::Disasm::Mnemonic::PUSHFQ
#define ZYDIS_MNEMONIC_POPF       Phantom::Disasm::Mnemonic::POPF
#define ZYDIS_MNEMONIC_POPFQ      Phantom::Disasm::Mnemonic::POPFQ

// Control flow — unconditional
#define ZYDIS_MNEMONIC_CALL       Phantom::Disasm::Mnemonic::CALL
#define ZYDIS_MNEMONIC_RET        Phantom::Disasm::Mnemonic::RET
#define ZYDIS_MNEMONIC_JMP        Phantom::Disasm::Mnemonic::JMP

// Control flow — conditional jumps
#define ZYDIS_MNEMONIC_JO         Phantom::Disasm::Mnemonic::JO
#define ZYDIS_MNEMONIC_JNO        Phantom::Disasm::Mnemonic::JNO
#define ZYDIS_MNEMONIC_JB         Phantom::Disasm::Mnemonic::JB
#define ZYDIS_MNEMONIC_JNB        Phantom::Disasm::Mnemonic::JNB
#define ZYDIS_MNEMONIC_JZ         Phantom::Disasm::Mnemonic::JZ
#define ZYDIS_MNEMONIC_JNZ        Phantom::Disasm::Mnemonic::JNZ
#define ZYDIS_MNEMONIC_JBE        Phantom::Disasm::Mnemonic::JBE
#define ZYDIS_MNEMONIC_JNBE       Phantom::Disasm::Mnemonic::JNBE
#define ZYDIS_MNEMONIC_JS         Phantom::Disasm::Mnemonic::JS
#define ZYDIS_MNEMONIC_JNS        Phantom::Disasm::Mnemonic::JNS
#define ZYDIS_MNEMONIC_JP         Phantom::Disasm::Mnemonic::JP
#define ZYDIS_MNEMONIC_JNP        Phantom::Disasm::Mnemonic::JNP
#define ZYDIS_MNEMONIC_JL         Phantom::Disasm::Mnemonic::JL
#define ZYDIS_MNEMONIC_JNL        Phantom::Disasm::Mnemonic::JNL
#define ZYDIS_MNEMONIC_JLE        Phantom::Disasm::Mnemonic::JLE
#define ZYDIS_MNEMONIC_JNLE       Phantom::Disasm::Mnemonic::JNLE
#define ZYDIS_MNEMONIC_JCXZ       Phantom::Disasm::Mnemonic::JCXZ
#define ZYDIS_MNEMONIC_JECXZ      Phantom::Disasm::Mnemonic::JECXZ
#define ZYDIS_MNEMONIC_JRCXZ      Phantom::Disasm::Mnemonic::JRCXZ

// Loops
#define ZYDIS_MNEMONIC_LOOP       Phantom::Disasm::Mnemonic::LOOP
#define ZYDIS_MNEMONIC_LOOPE      Phantom::Disasm::Mnemonic::LOOPE
#define ZYDIS_MNEMONIC_LOOPNE     Phantom::Disasm::Mnemonic::LOOPNE

// String operations
#define ZYDIS_MNEMONIC_MOVSB      Phantom::Disasm::Mnemonic::MOVSB
#define ZYDIS_MNEMONIC_MOVSW      Phantom::Disasm::Mnemonic::MOVSW
#define ZYDIS_MNEMONIC_MOVSD      Phantom::Disasm::Mnemonic::MOVSD_STR
#define ZYDIS_MNEMONIC_MOVSQ      Phantom::Disasm::Mnemonic::MOVSQ
#define ZYDIS_MNEMONIC_STOSB      Phantom::Disasm::Mnemonic::STOSB
#define ZYDIS_MNEMONIC_STOSW      Phantom::Disasm::Mnemonic::STOSW
#define ZYDIS_MNEMONIC_STOSD      Phantom::Disasm::Mnemonic::STOSD
#define ZYDIS_MNEMONIC_STOSQ      Phantom::Disasm::Mnemonic::STOSQ
#define ZYDIS_MNEMONIC_LODSB      Phantom::Disasm::Mnemonic::LODSB
#define ZYDIS_MNEMONIC_LODSW      Phantom::Disasm::Mnemonic::LODSW
#define ZYDIS_MNEMONIC_SCASB      Phantom::Disasm::Mnemonic::SCASB
#define ZYDIS_MNEMONIC_SCASD      Phantom::Disasm::Mnemonic::SCASD

// Interrupt / exception
#define ZYDIS_MNEMONIC_INT        Phantom::Disasm::Mnemonic::INT
#define ZYDIS_MNEMONIC_INT1       Phantom::Disasm::Mnemonic::INT1
#define ZYDIS_MNEMONIC_INT3       Phantom::Disasm::Mnemonic::INT3
#define ZYDIS_MNEMONIC_INTO       Phantom::Disasm::Mnemonic::INTO
#define ZYDIS_MNEMONIC_UD0        Phantom::Disasm::Mnemonic::UD0
#define ZYDIS_MNEMONIC_UD1        Phantom::Disasm::Mnemonic::UD1
#define ZYDIS_MNEMONIC_UD2        Phantom::Disasm::Mnemonic::UD2
#define ZYDIS_MNEMONIC_HLT        Phantom::Disasm::Mnemonic::HLT

// System call
#define ZYDIS_MNEMONIC_SYSCALL    Phantom::Disasm::Mnemonic::SYSCALL
#define ZYDIS_MNEMONIC_SYSRET     Phantom::Disasm::Mnemonic::SYSRET
#define ZYDIS_MNEMONIC_SYSENTER   Phantom::Disasm::Mnemonic::SYSENTER
#define ZYDIS_MNEMONIC_SYSEXIT    Phantom::Disasm::Mnemonic::SYSEXIT

// System / privileged
#define ZYDIS_MNEMONIC_IN         Phantom::Disasm::Mnemonic::IN
#define ZYDIS_MNEMONIC_OUT        Phantom::Disasm::Mnemonic::OUT
#define ZYDIS_MNEMONIC_RDTSC      Phantom::Disasm::Mnemonic::RDTSC
#define ZYDIS_MNEMONIC_RDTSCP     Phantom::Disasm::Mnemonic::RDTSCP
#define ZYDIS_MNEMONIC_RDPMC      Phantom::Disasm::Mnemonic::RDPMC
#define ZYDIS_MNEMONIC_CPUID      Phantom::Disasm::Mnemonic::CPUID
#define ZYDIS_MNEMONIC_SGDT       Phantom::Disasm::Mnemonic::SGDT
#define ZYDIS_MNEMONIC_SIDT       Phantom::Disasm::Mnemonic::SIDT
#define ZYDIS_MNEMONIC_SLDT       Phantom::Disasm::Mnemonic::SLDT
#define ZYDIS_MNEMONIC_STR        Phantom::Disasm::Mnemonic::STR

// NOP
#define ZYDIS_MNEMONIC_NOP        Phantom::Disasm::Mnemonic::NOP

// ============================================================================
// Section 11 — Register constants
// ============================================================================

#define ZYDIS_REGISTER_NONE  Phantom::Disasm::Register::NONE

// 64-bit GPR
#define ZYDIS_REGISTER_RAX   Phantom::Disasm::Register::RAX
#define ZYDIS_REGISTER_RCX   Phantom::Disasm::Register::RCX
#define ZYDIS_REGISTER_RDX   Phantom::Disasm::Register::RDX
#define ZYDIS_REGISTER_RBX   Phantom::Disasm::Register::RBX
#define ZYDIS_REGISTER_RSP   Phantom::Disasm::Register::RSP
#define ZYDIS_REGISTER_RBP   Phantom::Disasm::Register::RBP
#define ZYDIS_REGISTER_RSI   Phantom::Disasm::Register::RSI
#define ZYDIS_REGISTER_RDI   Phantom::Disasm::Register::RDI
#define ZYDIS_REGISTER_R8    Phantom::Disasm::Register::R8
#define ZYDIS_REGISTER_R9    Phantom::Disasm::Register::R9
#define ZYDIS_REGISTER_R10   Phantom::Disasm::Register::R10
#define ZYDIS_REGISTER_R11   Phantom::Disasm::Register::R11
#define ZYDIS_REGISTER_R12   Phantom::Disasm::Register::R12
#define ZYDIS_REGISTER_R13   Phantom::Disasm::Register::R13
#define ZYDIS_REGISTER_R14   Phantom::Disasm::Register::R14
#define ZYDIS_REGISTER_R15   Phantom::Disasm::Register::R15

// 32-bit GPR
#define ZYDIS_REGISTER_EAX   Phantom::Disasm::Register::EAX
#define ZYDIS_REGISTER_ECX   Phantom::Disasm::Register::ECX
#define ZYDIS_REGISTER_EDX   Phantom::Disasm::Register::EDX
#define ZYDIS_REGISTER_EBX   Phantom::Disasm::Register::EBX
#define ZYDIS_REGISTER_ESP   Phantom::Disasm::Register::ESP
#define ZYDIS_REGISTER_EBP   Phantom::Disasm::Register::EBP
#define ZYDIS_REGISTER_ESI   Phantom::Disasm::Register::ESI
#define ZYDIS_REGISTER_EDI   Phantom::Disasm::Register::EDI
#define ZYDIS_REGISTER_R8D   Phantom::Disasm::Register::R8D
#define ZYDIS_REGISTER_R9D   Phantom::Disasm::Register::R9D
#define ZYDIS_REGISTER_R10D  Phantom::Disasm::Register::R10D
#define ZYDIS_REGISTER_R11D  Phantom::Disasm::Register::R11D
#define ZYDIS_REGISTER_R12D  Phantom::Disasm::Register::R12D
#define ZYDIS_REGISTER_R13D  Phantom::Disasm::Register::R13D
#define ZYDIS_REGISTER_R14D  Phantom::Disasm::Register::R14D
#define ZYDIS_REGISTER_R15D  Phantom::Disasm::Register::R15D

// 16-bit GPR
#define ZYDIS_REGISTER_AX    Phantom::Disasm::Register::AX
#define ZYDIS_REGISTER_CX    Phantom::Disasm::Register::CX
#define ZYDIS_REGISTER_DX    Phantom::Disasm::Register::DX
#define ZYDIS_REGISTER_BX    Phantom::Disasm::Register::BX
#define ZYDIS_REGISTER_SP    Phantom::Disasm::Register::SP
#define ZYDIS_REGISTER_BP    Phantom::Disasm::Register::BP
#define ZYDIS_REGISTER_SI    Phantom::Disasm::Register::SI
#define ZYDIS_REGISTER_DI    Phantom::Disasm::Register::DI
#define ZYDIS_REGISTER_R8W   Phantom::Disasm::Register::R8W
#define ZYDIS_REGISTER_R9W   Phantom::Disasm::Register::R9W
#define ZYDIS_REGISTER_R10W  Phantom::Disasm::Register::R10W
#define ZYDIS_REGISTER_R11W  Phantom::Disasm::Register::R11W
#define ZYDIS_REGISTER_R12W  Phantom::Disasm::Register::R12W
#define ZYDIS_REGISTER_R13W  Phantom::Disasm::Register::R13W
#define ZYDIS_REGISTER_R14W  Phantom::Disasm::Register::R14W
#define ZYDIS_REGISTER_R15W  Phantom::Disasm::Register::R15W

// 8-bit GPR
#define ZYDIS_REGISTER_AL    Phantom::Disasm::Register::AL
#define ZYDIS_REGISTER_CL    Phantom::Disasm::Register::CL
#define ZYDIS_REGISTER_DL    Phantom::Disasm::Register::DL
#define ZYDIS_REGISTER_BL    Phantom::Disasm::Register::BL
#define ZYDIS_REGISTER_AH    Phantom::Disasm::Register::AH
#define ZYDIS_REGISTER_CH    Phantom::Disasm::Register::CH
#define ZYDIS_REGISTER_DH    Phantom::Disasm::Register::DH
#define ZYDIS_REGISTER_BH    Phantom::Disasm::Register::BH
#define ZYDIS_REGISTER_SPL   Phantom::Disasm::Register::SPL
#define ZYDIS_REGISTER_BPL   Phantom::Disasm::Register::BPL
#define ZYDIS_REGISTER_SIL   Phantom::Disasm::Register::SIL
#define ZYDIS_REGISTER_DIL   Phantom::Disasm::Register::DIL
#define ZYDIS_REGISTER_R8B   Phantom::Disasm::Register::R8B
#define ZYDIS_REGISTER_R9B   Phantom::Disasm::Register::R9B
#define ZYDIS_REGISTER_R10B  Phantom::Disasm::Register::R10B
#define ZYDIS_REGISTER_R11B  Phantom::Disasm::Register::R11B
#define ZYDIS_REGISTER_R12B  Phantom::Disasm::Register::R12B
#define ZYDIS_REGISTER_R13B  Phantom::Disasm::Register::R13B
#define ZYDIS_REGISTER_R14B  Phantom::Disasm::Register::R14B
#define ZYDIS_REGISTER_R15B  Phantom::Disasm::Register::R15B

// Segment registers
#define ZYDIS_REGISTER_ES    Phantom::Disasm::Register::ES
#define ZYDIS_REGISTER_CS    Phantom::Disasm::Register::CS
#define ZYDIS_REGISTER_SS    Phantom::Disasm::Register::SS
#define ZYDIS_REGISTER_DS    Phantom::Disasm::Register::DS
#define ZYDIS_REGISTER_FS    Phantom::Disasm::Register::FS
#define ZYDIS_REGISTER_GS    Phantom::Disasm::Register::GS

// Instruction pointer (EIP mapped to RIP — unified instruction pointer
// representation; semantically equivalent for detection logic)
#define ZYDIS_REGISTER_IP    Phantom::Disasm::Register::RIP
#define ZYDIS_REGISTER_EIP   Phantom::Disasm::Register::RIP
#define ZYDIS_REGISTER_RIP   Phantom::Disasm::Register::RIP

// Flags
#define ZYDIS_REGISTER_RFLAGS Phantom::Disasm::Register::RFLAGS

// ============================================================================
// Section 12 — API function wrappers
//
// All wrappers are inline free functions with the same signature as the
// original Zydis C API, adapted for C++ types.
// ============================================================================

/// @brief Initialize a decoder for the given machine mode.
///
/// @param decoder      Pointer to a Decoder instance (must not be null).
/// @param machineMode  Target machine mode (Long64, LongCompat32, Legacy32).
///                     Accepts MachineMode enum values directly from the
///                     ZYDIS_MACHINE_MODE_* macros.
/// @param stackWidth   Ignored — machine mode determines all widths.
/// @return Status::Success on valid initialisation.
inline ZyanStatus ZydisDecoderInit(
    ZydisDecoder* decoder,
    auto machineMode,
    auto /*stackWidth*/) noexcept
{
    if (!decoder) return Phantom::Disasm::Status::InvalidInput;

    Phantom::Disasm::MachineMode mode;
    if constexpr (std::is_same_v<decltype(machineMode), Phantom::Disasm::MachineMode>) {
        mode = machineMode;
    } else {
        mode = static_cast<Phantom::Disasm::MachineMode>(machineMode);
    }
    return decoder->Init(mode);
}

/// @brief Decode a complete instruction from a byte buffer.
///
/// @param decoder      Pointer to an initialised Decoder.
/// @param buffer       Raw instruction bytes (cast from const void*).
/// @param length       Available byte count.
/// @param instruction  Output: populated on success.
/// @param operands     Output: array of at least ZYDIS_MAX_OPERAND_COUNT elements.
/// @return Status::Success on successful decode.
inline ZyanStatus ZydisDecoderDecodeFull(
    const ZydisDecoder* decoder,
    const void* buffer,
    ZyanUSize length,
    ZydisDecodedInstruction* instruction,
    ZydisDecodedOperand* operands) noexcept
{
    if (!decoder || !buffer || !instruction || !operands)
        return Phantom::Disasm::Status::InvalidInput;

    // DecodeFull is thread-safe (all state is stack-local); const_cast is
    // safe here because the method does not mutate any Decoder member.
    auto* mutableDecoder = const_cast<ZydisDecoder*>(decoder);
    return mutableDecoder->DecodeFull(
        static_cast<const uint8_t*>(buffer),
        length,
        *instruction,
        operands);
}

/// @brief Initialize a text formatter.
///
/// @param formatter  Pointer to a Formatter instance.
/// @param style      Formatting style (Intel or ATT).
/// @return Status::Success on valid initialisation.
inline ZyanStatus ZydisFormatterInit(
    ZydisFormatter* formatter,
    auto style) noexcept
{
    if (!formatter) return Phantom::Disasm::Status::InvalidInput;

    Phantom::Disasm::FormatterStyle fmtStyle;
    if constexpr (std::is_same_v<decltype(style), Phantom::Disasm::FormatterStyle>) {
        fmtStyle = style;
    } else {
        fmtStyle = static_cast<Phantom::Disasm::FormatterStyle>(style);
    }
    return formatter->Init(fmtStyle);
}

/// @brief Format a decoded instruction into a human-readable text buffer.
///
/// @param formatter      Pointer to an initialised Formatter.
/// @param instruction    The decoded instruction to format.
/// @param operands       The decoded operand array.
/// @param operandCount   Number of operands to format.
/// @param buffer         Output character buffer.
/// @param bufferSize     Size of buffer in bytes.
/// @param runtimeAddress Runtime virtual address (for RIP-relative display).
/// @param userData       Reserved — pass ZYAN_NULL.
/// @return Status::Success on successful formatting.
inline ZyanStatus ZydisFormatterFormatInstruction(
    const ZydisFormatter* formatter,
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands,
    ZyanU8 operandCount,
    char* buffer,
    ZyanUSize bufferSize,
    ZyanU64 runtimeAddress = 0,
    void* userData = nullptr) noexcept
{
    if (!formatter || !instruction || !operands || !buffer)
        return Phantom::Disasm::Status::InvalidInput;

    // FormatInstruction is safe to const_cast — it reads the Formatter's
    // style setting but does not modify persistent state.
    auto* mutableFormatter = const_cast<ZydisFormatter*>(formatter);
    return mutableFormatter->FormatInstruction(
        *instruction,
        operands,
        operandCount,
        buffer,
        bufferSize,
        runtimeAddress,
        userData);
}

/// @brief Get a human-readable string for a mnemonic enum value.
///
/// @param mnemonic  The mnemonic to convert.
/// @return Pointer to a static null-terminated string.
///         Valid for the lifetime of the program.
inline const char* ZydisMnemonicGetString(ZydisMnemonic mnemonic) noexcept
{
    // MnemonicToString returns a std::string_view constructed from a string
    // literal, so .data() yields a valid null-terminated const char*.
    return Phantom::Disasm::MnemonicToString(mnemonic).data();
}

/// @brief Get a human-readable string for a register enum value.
///
/// @param reg  The register to convert.
/// @return Pointer to a static null-terminated string.
inline const char* ZydisRegisterGetString(ZydisRegister reg) noexcept
{
    return Phantom::Disasm::RegisterToString(reg).data();
}
