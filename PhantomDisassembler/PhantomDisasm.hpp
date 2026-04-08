/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomDisassembler - Standalone x86-64 Instruction Disassembler
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

/**
 * @file PhantomDisasm.hpp
 * @brief Master include header for the PhantomDisassembler engine.
 *
 * Include this single header to pull in the complete PhantomDisassembler API:
 * type definitions, decoded instruction/operand structures, the decoder, and
 * the text formatter. Built entirely from scratch for the ShadowStrike platform.
 */
#pragma once

#include "Types.hpp"
#include "Instruction.hpp"
#include "Decoder.hpp"
#include "Formatter.hpp"

namespace Phantom::Disasm {

// ============================================================================
// Version information
// ============================================================================

constexpr uint32_t PHANTOM_DISASM_VERSION_MAJOR = 1;
constexpr uint32_t PHANTOM_DISASM_VERSION_MINOR = 0;
constexpr uint32_t PHANTOM_DISASM_VERSION_PATCH = 0;

// ============================================================================
// Quick single-instruction disassemble helper
// ============================================================================

/// @brief Decode and optionally format a single instruction in one call.
///
/// Convenience wrapper that creates a temporary Decoder (and optionally a
/// Formatter), decodes one instruction, and fills in the runtime address.
/// Suitable for one-off use; callers that decode many instructions should
/// create their own Decoder/Formatter and reuse them.
///
/// @param mode            Target machine mode (Long64, LongCompat32, Legacy32)
/// @param buffer          Raw instruction bytes
/// @param length          Number of available bytes in buffer
/// @param runtimeAddress  Virtual address of the first byte of buffer
/// @param instruction     Output: populated on success
/// @param operands        Output: array of at least MAX_OPERANDS elements
/// @param textBuffer      Optional: buffer for Intel-syntax text output
/// @param textBufferSize  Size of textBuffer in bytes (0 to skip formatting)
/// @return Status::Success on successful decode; error code otherwise
[[nodiscard]] inline Status Disassemble(
    MachineMode mode,
    const uint8_t* buffer,
    size_t length,
    uint64_t runtimeAddress,
    DecodedInstruction& instruction,
    DecodedOperand* operands,
    char* textBuffer = nullptr,
    size_t textBufferSize = 0)
{
    Decoder decoder;
    Status status = decoder.Init(mode);
    if (IsFailed(status)) return status;

    status = decoder.DecodeFull(buffer, length, instruction, operands);
    if (IsFailed(status)) return status;

    instruction.address = runtimeAddress;

    if (textBuffer && textBufferSize > 0) {
        Formatter fmt;
        status = fmt.Init(FormatterStyle::Intel);
        if (IsFailed(status)) return status;

        status = fmt.FormatInstruction(
            instruction, operands, instruction.operand_count,
            textBuffer, textBufferSize, runtimeAddress);
    }

    return Status::Success;
}

} // namespace Phantom::Disasm
