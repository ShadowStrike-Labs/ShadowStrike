/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomDisassembler - Standalone x86-64 Instruction Disassembler
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 *
 * Formatter.cpp — Converts decoded x86-64 instructions into human-readable
 * Intel-syntax assembly text.  Zero heap allocation, fully noexcept,
 * thread-safe after Init().
 *
 * All type definitions live in Types.hpp and Instruction.hpp.
 * The Status enum is defined in Decoder.hpp.
 */

#include "Formatter.hpp"
#include "Decoder.hpp"      // Status enum full definition

#include <algorithm>        // std::min
#include <cctype>
#include <cstring>
#include <string_view>

namespace Phantom::Disasm {

// ============================================================================
// Anonymous-namespace helpers (internal linkage)
// ============================================================================

namespace {

/// Append the contents of @p sv to @p dst, converting each character to
/// lowercase.  Returns the number of characters written (no terminator).
/// Handles non-null-terminated string_view safely.
size_t AppendLowercase(char* dst, size_t remaining,
                       std::string_view sv) noexcept
{
    if (!dst || remaining <= 1 || sv.empty()) return 0;

    const size_t maxWrite = std::min(sv.size(), remaining - 1);
    for (size_t i = 0; i < maxWrite; ++i) {
        dst[i] = static_cast<char>(
            std::tolower(static_cast<unsigned char>(sv[i])));
    }
    return maxWrite;
}

/// Append the contents of @p sv verbatim (no case conversion).
size_t AppendView(char* dst, size_t remaining,
                  std::string_view sv) noexcept
{
    if (!dst || remaining <= 1 || sv.empty()) return 0;

    const size_t maxWrite = std::min(sv.size(), remaining - 1);
    std::memcpy(dst, sv.data(), maxWrite);
    return maxWrite;
}

} // anonymous namespace

// ============================================================================
// Safe string primitives — every append returns chars written, never touches
// memory beyond [dst, dst + dstRemaining).  Callers track position; the main
// entry point null-terminates at the end.
// ============================================================================

size_t Formatter::SafeAppend(char* dst, size_t dstRemaining,
                             const char* src) noexcept
{
    if (!dst || !src || dstRemaining <= 1) return 0;

    size_t written = 0;
    while (src[written] != '\0' && written < dstRemaining - 1) {
        dst[written] = src[written];
        ++written;
    }
    return written;
}

size_t Formatter::SafeAppendChar(char* dst, size_t dstRemaining,
                                 char c) noexcept
{
    if (!dst || dstRemaining <= 1) return 0;
    dst[0] = c;
    return 1;
}

size_t Formatter::SafeAppendHex(char* dst, size_t dstRemaining,
                                uint64_t value, bool prefix0x) noexcept
{
    if (!dst || dstRemaining <= 1) return 0;

    // Worst case: "0x" (2) + 16 hex digits = 18 chars + NUL
    static constexpr char kHex[] = "0123456789ABCDEF";
    char temp[20];
    int len = 0;

    if (prefix0x) {
        temp[len++] = '0';
        temp[len++] = 'x';
    }

    if (value == 0) {
        temp[len++] = '0';
    } else {
        char digits[16];
        int ndig = 0;
        uint64_t v = value;
        while (v != 0) {
            digits[ndig++] = kHex[v & 0xFu];
            v >>= 4;
        }
        for (int i = ndig - 1; i >= 0; --i) {
            temp[len++] = digits[i];
        }
    }
    temp[len] = '\0';

    return SafeAppend(dst, dstRemaining, temp);
}

size_t Formatter::SafeAppendSignedHex(char* dst, size_t dstRemaining,
                                      int64_t value) noexcept
{
    if (!dst || dstRemaining <= 1) return 0;

    if (value < 0) {
        size_t pos = SafeAppendChar(dst, dstRemaining, '-');
        pos += SafeAppendHex(dst + pos, dstRemaining - pos,
                             static_cast<uint64_t>(-value), /*prefix0x=*/true);
        return pos;
    }
    return SafeAppendHex(dst, dstRemaining,
                         static_cast<uint64_t>(value), /*prefix0x=*/true);
}

// ============================================================================
// Init
// ============================================================================

Status Formatter::Init(FormatterStyle style) noexcept
{
    if (style != FormatterStyle::Intel && style != FormatterStyle::ATT) {
        return Status::InvalidInput;
    }
    m_style = style;
    m_initialized = true;
    return Status::Success;
}

// ============================================================================
// FormatInstruction — main public entry point
// ============================================================================

Status Formatter::FormatInstruction(
    const DecodedInstruction& instruction,
    const DecodedOperand*     operands,
    uint8_t                   operandCount,
    char*                     buffer,
    size_t                    bufferSize,
    uint64_t                  runtimeAddress,
    void*                     /*userData*/) noexcept
{
    // ---- validation ----
    if (!m_initialized)                        return Status::InternalError;
    if (!buffer || bufferSize == 0)            return Status::InvalidInput;
    if (operandCount > 0 && !operands)         return Status::InvalidInput;

    // Hard cap — x86-64 visible operands never exceed MAX_OPERANDS.
    if (operandCount > MAX_OPERANDS) {
        operandCount = MAX_OPERANDS;
    }

    buffer[0] = '\0';
    size_t pos       = 0;
    size_t remaining = bufferSize;

    // Use caller-supplied runtime address, falling back to the encoded address.
    const uint64_t effectiveAddr =
        (runtimeAddress != 0) ? runtimeAddress : instruction.address;

    // ---- mnemonic (with lock / rep / repe / repne prefix) ----
    size_t w = FormatMnemonic(instruction, buffer + pos, remaining);
    pos       += w;
    remaining -= w;

    // ---- operands, separated by ", " ----
    for (uint8_t i = 0; i < operandCount && remaining > 1; ++i) {
        if (operands[i].type == OperandType::NONE) {
            break;
        }

        // Separator
        w = (i == 0)
            ? SafeAppend(buffer + pos, remaining, " ")
            : SafeAppend(buffer + pos, remaining, ", ");
        pos       += w;
        remaining -= w;

        // Operand body
        w = FormatOperand(operands[i], instruction,
                          buffer + pos, remaining, effectiveAddr);
        pos       += w;
        remaining -= w;
    }

    // ---- null-terminate ----
    if (pos < bufferSize) {
        buffer[pos] = '\0';
    } else {
        buffer[bufferSize - 1] = '\0';
        return Status::TruncatedInput;
    }

    return Status::Success;
}

// ============================================================================
// FormatMnemonic — prefix strings + mnemonic in lowercase
// ============================================================================

size_t Formatter::FormatMnemonic(const DecodedInstruction& inst,
                                 char* buf, size_t remaining) noexcept
{
    size_t pos = 0;

    // Legacy prefixes rendered before the mnemonic.
    // REP (F3) and REPE (F3 on CMPS/SCAS) are mutually exclusive with REPNE (F2).
    if (inst.attributes & ATTRIB_HAS_LOCK) {
        pos += SafeAppend(buf + pos, remaining - pos, "lock ");
    }
    if (inst.attributes & ATTRIB_HAS_REPE) {
        pos += SafeAppend(buf + pos, remaining - pos, "repe ");
    } else if (inst.attributes & ATTRIB_HAS_REP) {
        pos += SafeAppend(buf + pos, remaining - pos, "rep ");
    }
    if (inst.attributes & ATTRIB_HAS_REPNE) {
        pos += SafeAppend(buf + pos, remaining - pos, "repne ");
    }

    // Mnemonic text.  MnemonicToString() already returns lowercase
    // string_view literals, but we lowercase defensively for robustness.
    const std::string_view name = MnemonicToString(inst.mnemonic);
    if (!name.empty()) {
        pos += AppendLowercase(buf + pos, remaining - pos, name);
    }

    return pos;
}

// ============================================================================
// FormatOperand — dispatch by OperandType
// ============================================================================

size_t Formatter::FormatOperand(const DecodedOperand& op,
                                const DecodedInstruction& inst,
                                char* buf, size_t remaining,
                                uint64_t runtimeAddr) noexcept
{
    switch (op.type) {

    case OperandType::REGISTER:
        return FormatRegister(op.reg.value, buf, remaining);

    case OperandType::MEMORY:
        return FormatMemory(op.mem, inst, op.size, buf, remaining);

    case OperandType::IMMEDIATE:
        return FormatImmediate(op.imm, op.size,
                               /*isRelative=*/false,
                               inst.address, inst.length,
                               buf, remaining);

    case OperandType::RELATIVE:
        return FormatImmediate(op.imm, op.size,
                               /*isRelative=*/true,
                               runtimeAddr, inst.length,
                               buf, remaining);

    case OperandType::FAR_PTR: {
        // Far pointer: seg:offset   e.g.  0x33:0x401000
        size_t pos = 0;
        pos += SafeAppendHex(buf + pos, remaining - pos,
                             op.ptr.segment, /*prefix0x=*/true);
        pos += SafeAppendChar(buf + pos, remaining - pos, ':');
        pos += SafeAppendHex(buf + pos, remaining - pos,
                             op.ptr.offset, /*prefix0x=*/true);
        return pos;
    }

    case OperandType::NONE:
    default:
        return 0;
    }
}

// ============================================================================
// FormatRegister — lowercase register name via RegisterToString()
// ============================================================================

size_t Formatter::FormatRegister(Register reg, char* buf,
                                 size_t remaining) noexcept
{
    if (reg == Register::NONE) return 0;

    const std::string_view name = RegisterToString(reg);
    if (name.empty()) return 0;

    // RegisterToString() returns lowercase literals, but we lowercase
    // defensively so the formatter is correct even if the lookup changes.
    return AppendLowercase(buf, remaining, name);
}

// ============================================================================
// FormatSizePrefix — memory-operand size qualifier
// ============================================================================

size_t Formatter::FormatSizePrefix(uint16_t sizeBits, char* buf,
                                   size_t remaining) noexcept
{
    const char* prefix = nullptr;

    switch (sizeBits) {
    case 8:   prefix = "byte ptr ";    break;
    case 16:  prefix = "word ptr ";    break;
    case 32:  prefix = "dword ptr ";   break;
    case 48:  prefix = "fword ptr ";   break;
    case 64:  prefix = "qword ptr ";   break;
    case 80:  prefix = "tbyte ptr ";   break;
    case 128: prefix = "xmmword ptr "; break;
    case 256: prefix = "ymmword ptr "; break;
    case 512: prefix = "zmmword ptr "; break;
    default:  return 0;                // Unknown size — omit qualifier
    }

    return SafeAppend(buf, remaining, prefix);
}

// ============================================================================
// FormatMemory — Intel-syntax memory operand
//
//   Full form:  qword ptr fs:[rbx+rcx*4-0x8]
//
//   Components:
//     1. Size qualifier       "qword ptr "
//     2. Segment override     "fs:"
//     3. Opening bracket      "["
//     4. Base register        "rbx"
//     5. Index * scale        "+rcx*4"
//     6. Displacement         "+0x10"  or  "-0x8"
//     7. Closing bracket      "]"
// ============================================================================

size_t Formatter::FormatMemory(const DecodedOperandMem& mem,
                               const DecodedInstruction& /*inst*/,
                               uint16_t opSize,
                               char* buf, size_t remaining) noexcept
{
    size_t pos = 0;

    // 1) Size qualifier (always emitted when known)
    pos += FormatSizePrefix(opSize, buf + pos, remaining - pos);

    // 2) Segment override — only printed when the decoder explicitly sets one.
    //    Register::NONE means "use the default segment" (DS or SS); we omit it.
    if (mem.segment != Register::NONE) {
        pos += FormatRegister(mem.segment, buf + pos, remaining - pos);
        pos += SafeAppendChar(buf + pos, remaining - pos, ':');
    }

    // 3) Opening bracket
    pos += SafeAppendChar(buf + pos, remaining - pos, '[');

    bool hasComponent = false;

    // 4) Base register
    if (mem.base != Register::NONE) {
        pos += FormatRegister(mem.base, buf + pos, remaining - pos);
        hasComponent = true;
    }

    // 5) Index register * scale
    if (mem.index != Register::NONE) {
        if (hasComponent) {
            pos += SafeAppendChar(buf + pos, remaining - pos, '+');
        }
        pos += FormatRegister(mem.index, buf + pos, remaining - pos);
        pos += SafeAppendChar(buf + pos, remaining - pos, '*');

        // Scale is 1, 2, 4, or 8 — all single ASCII digits.
        // Sanitize a zero scale to 1 defensively.
        const uint8_t scale = (mem.scale == 0) ? uint8_t{1} : mem.scale;
        pos += SafeAppendChar(buf + pos, remaining - pos,
                              static_cast<char>('0' + scale));
        hasComponent = true;
    }

    // 6) Displacement
    //    Skip a zero displacement when base/index already provide content
    //    (matches Zydis default behaviour).
    const bool showDisp =
        mem.disp.has_displacement &&
        (mem.disp.value != 0 || !hasComponent);

    if (showDisp) {
        const int64_t d = mem.disp.value;

        if (hasComponent) {
            // Relative form: "+0x10" or "-0x8"
            if (d >= 0) {
                pos += SafeAppendChar(buf + pos, remaining - pos, '+');
                pos += SafeAppendHex(buf + pos, remaining - pos,
                                     static_cast<uint64_t>(d), true);
            } else {
                pos += SafeAppendChar(buf + pos, remaining - pos, '-');
                pos += SafeAppendHex(buf + pos, remaining - pos,
                                     static_cast<uint64_t>(-d), true);
            }
        } else {
            // Displacement-only (absolute address): show as unsigned
            pos += SafeAppendHex(buf + pos, remaining - pos,
                                 static_cast<uint64_t>(d), true);
        }
    } else if (!hasComponent) {
        // No base, index, or displacement — should not happen on valid input.
        // Emit 0x0 so the brackets are never empty.
        pos += SafeAppendHex(buf + pos, remaining - pos, 0, true);
    }

    // 7) Closing bracket
    pos += SafeAppendChar(buf + pos, remaining - pos, ']');

    return pos;
}

// ============================================================================
// FormatImmediate — immediate values and resolved branch targets
//
//   • Relative operands: compute absolute target = addr + length + offset.
//   • Small unsigned values (0-9): decimal.
//   • All others: "0x" + uppercase hex digits.
//   • Signed negatives displayed as -0xN.
// ============================================================================

size_t Formatter::FormatImmediate(const DecodedOperandImm& imm,
                                  uint16_t                 /*opSize*/,
                                  bool                     isRelative,
                                  uint64_t                 instrAddr,
                                  uint8_t                  instrLen,
                                  char* buf, size_t remaining) noexcept
{
    // ---- branch / call target: resolve to absolute address ----
    if (isRelative) {
        // target = instrAddr + instrLen + signed_offset
        // Two's complement arithmetic handles negative offsets correctly.
        const uint64_t target =
            instrAddr
            + static_cast<uint64_t>(instrLen)
            + static_cast<uint64_t>(imm.value.s);

        return SafeAppendHex(buf, remaining, target, /*prefix0x=*/true);
    }

    // ---- signed negative immediate ----
    if (imm.is_signed && imm.value.s < 0) {
        const uint64_t absVal = static_cast<uint64_t>(-imm.value.s);
        size_t pos = 0;
        pos += SafeAppendChar(buf + pos, remaining - pos, '-');
        if (absVal <= 9) {
            pos += SafeAppendChar(buf + pos, remaining - pos,
                                  static_cast<char>('0' + absVal));
        } else {
            pos += SafeAppendHex(buf + pos, remaining - pos,
                                 absVal, /*prefix0x=*/true);
        }
        return pos;
    }

    // ---- unsigned / positive immediate ----
    const uint64_t val = imm.value.u;

    // Small values rendered in decimal for readability
    if (val <= 9) {
        return SafeAppendChar(buf, remaining,
                              static_cast<char>('0' + val));
    }

    return SafeAppendHex(buf, remaining, val, /*prefix0x=*/true);
}

} // namespace Phantom::Disasm
