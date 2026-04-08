/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomDisassembler - Standalone x86-64 Instruction Disassembler
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "Types.hpp"
#include "Instruction.hpp"
#include "Decoder.hpp"          // Status enum
#include <cstdint>
#include <cstddef>

namespace Phantom::Disasm {

enum class FormatterStyle : uint8_t {
    Intel,        // Intel syntax (default): mov rax, [rbx+8]
    ATT,          // AT&T syntax: movq 8(%rbx), %rax
};

class Formatter {
public:
    [[nodiscard]] Status Init(FormatterStyle style = FormatterStyle::Intel) noexcept;

    // Format a decoded instruction + operands into a text buffer
    // @param instruction  The decoded instruction
    // @param operands     The operand array (from DecodeFull)
    // @param operandCount Number of operands to format
    // @param buffer       Output character buffer
    // @param bufferSize   Size of output buffer in bytes
    // @param runtimeAddress  Runtime address for RIP-relative display (optional, 0 = use instruction.address)
    // @param userData     Reserved for future use (pass nullptr)
    // @return Status::Success if formatted successfully
    [[nodiscard]] Status FormatInstruction(
        const DecodedInstruction& instruction,
        const DecodedOperand* operands,
        uint8_t operandCount,
        char* buffer,
        size_t bufferSize,
        uint64_t runtimeAddress = 0,
        void* userData = nullptr) const noexcept;

    [[nodiscard]] bool IsInitialized() const noexcept { return m_initialized; }
    [[nodiscard]] FormatterStyle GetStyle() const noexcept { return m_style; }

private:
    FormatterStyle m_style = FormatterStyle::Intel;
    bool m_initialized = false;

    // Internal formatting helpers
    size_t FormatMnemonic(const DecodedInstruction& inst, char* buf, size_t remaining) noexcept;
    size_t FormatOperand(const DecodedOperand& op, const DecodedInstruction& inst,
                         char* buf, size_t remaining, uint64_t runtimeAddr) noexcept;
    size_t FormatRegister(Register reg, char* buf, size_t remaining) noexcept;
    size_t FormatMemory(const DecodedOperandMem& mem, const DecodedInstruction& inst,
                        uint16_t opSize, char* buf, size_t remaining) noexcept;
    size_t FormatImmediate(const DecodedOperandImm& imm, uint16_t opSize,
                           bool isRelative, uint64_t instrAddr, uint8_t instrLen,
                           char* buf, size_t remaining) noexcept;

    // Size prefix helper (byte ptr, word ptr, dword ptr, qword ptr, etc.)
    size_t FormatSizePrefix(uint16_t sizeBits, char* buf, size_t remaining) noexcept;

    // Safe string append
    static size_t SafeAppend(char* dst, size_t dstRemaining, const char* src) noexcept;
    static size_t SafeAppendChar(char* dst, size_t dstRemaining, char c) noexcept;
    static size_t SafeAppendHex(char* dst, size_t dstRemaining, uint64_t value, bool prefix0x = true) noexcept;
    static size_t SafeAppendSignedHex(char* dst, size_t dstRemaining, int64_t value) noexcept;
};

} // namespace Phantom::Disasm
