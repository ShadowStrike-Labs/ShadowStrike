/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MSILDisassembler.cpp — MSIL/CIL bytecode disassembler implementation
 *
 * Full opcode table covering every ECMA-335 §III opcode.
 * Decodes single-byte (0x00-0xFE) and two-byte (0xFE xx) MSIL opcodes,
 * parses tiny/fat method headers, and extracts exception handling clauses.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "MSILDisassembler.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace Phantom::CLR {

// ============================================================================
// Opcode Metadata Tables
// ============================================================================

// Internal opcode table entry — file-local to the translation unit.
struct OpcodeInfo {
    const char*     name;
    MSILOperandType operandType;
    int8_t          stackDelta;   // push - pop; 0 for variable-stack opcodes
};

// Sentinel entry returned for unknown / invalid opcodes.
static constexpr OpcodeInfo kInvalidOpcodeInfo{
    "INVALID", MSILOperandType::None, 0
};

// Single-byte opcodes indexed 0x00 .. 0xFF.
// Gaps in the ECMA-335 encoding (e.g., 0x24) are filled with kInvalidOpcodeInfo.
static constexpr std::array<OpcodeInfo, 256> kSingleByteTable = []() {
    std::array<OpcodeInfo, 256> t{};
    for (auto& e : t) e = kInvalidOpcodeInfo;

    //  Byte   Name                    OperandType                 Delta
    t[0x00] = {"nop",                  MSILOperandType::None,           0};
    t[0x01] = {"break",                MSILOperandType::None,           0};
    t[0x02] = {"ldarg.0",              MSILOperandType::None,           1};
    t[0x03] = {"ldarg.1",              MSILOperandType::None,           1};
    t[0x04] = {"ldarg.2",              MSILOperandType::None,           1};
    t[0x05] = {"ldarg.3",              MSILOperandType::None,           1};
    t[0x06] = {"ldloc.0",              MSILOperandType::None,           1};
    t[0x07] = {"ldloc.1",              MSILOperandType::None,           1};
    t[0x08] = {"ldloc.2",              MSILOperandType::None,           1};
    t[0x09] = {"ldloc.3",              MSILOperandType::None,           1};
    t[0x0A] = {"stloc.0",              MSILOperandType::None,          -1};
    t[0x0B] = {"stloc.1",              MSILOperandType::None,          -1};
    t[0x0C] = {"stloc.2",              MSILOperandType::None,          -1};
    t[0x0D] = {"stloc.3",              MSILOperandType::None,          -1};
    t[0x0E] = {"ldarg.s",              MSILOperandType::ShortInlineVar, 1};
    t[0x0F] = {"ldarga.s",             MSILOperandType::ShortInlineVar, 1};
    t[0x10] = {"starg.s",              MSILOperandType::ShortInlineVar,-1};
    t[0x11] = {"ldloc.s",              MSILOperandType::ShortInlineVar, 1};
    t[0x12] = {"ldloca.s",             MSILOperandType::ShortInlineVar, 1};
    t[0x13] = {"stloc.s",              MSILOperandType::ShortInlineVar,-1};
    t[0x14] = {"ldnull",               MSILOperandType::None,           1};
    t[0x15] = {"ldc.i4.m1",            MSILOperandType::None,           1};
    t[0x16] = {"ldc.i4.0",             MSILOperandType::None,           1};
    t[0x17] = {"ldc.i4.1",             MSILOperandType::None,           1};
    t[0x18] = {"ldc.i4.2",             MSILOperandType::None,           1};
    t[0x19] = {"ldc.i4.3",             MSILOperandType::None,           1};
    t[0x1A] = {"ldc.i4.4",             MSILOperandType::None,           1};
    t[0x1B] = {"ldc.i4.5",             MSILOperandType::None,           1};
    t[0x1C] = {"ldc.i4.6",             MSILOperandType::None,           1};
    t[0x1D] = {"ldc.i4.7",             MSILOperandType::None,           1};
    t[0x1E] = {"ldc.i4.8",             MSILOperandType::None,           1};
    t[0x1F] = {"ldc.i4.s",             MSILOperandType::ShortInlineI,   1};
    t[0x20] = {"ldc.i4",               MSILOperandType::InlineI,        1};
    t[0x21] = {"ldc.i8",               MSILOperandType::InlineI8,       1};
    t[0x22] = {"ldc.r4",               MSILOperandType::ShortInlineR,   1};
    t[0x23] = {"ldc.r8",               MSILOperandType::InlineR,        1};
    // 0x24 unused
    t[0x25] = {"dup",                  MSILOperandType::None,           1};
    t[0x26] = {"pop",                  MSILOperandType::None,          -1};
    t[0x27] = {"jmp",                  MSILOperandType::InlineMethod,   0};
    t[0x28] = {"call",                 MSILOperandType::InlineMethod,   0}; // variable
    t[0x29] = {"calli",                MSILOperandType::InlineSig,      0}; // variable
    t[0x2A] = {"ret",                  MSILOperandType::None,           0};
    t[0x2B] = {"br.s",                 MSILOperandType::ShortInlineBr,  0};
    t[0x2C] = {"brfalse.s",            MSILOperandType::ShortInlineBr, -1};
    t[0x2D] = {"brtrue.s",             MSILOperandType::ShortInlineBr, -1};
    t[0x2E] = {"beq.s",                MSILOperandType::ShortInlineBr, -2};
    t[0x2F] = {"bge.s",                MSILOperandType::ShortInlineBr, -2};
    t[0x30] = {"bgt.s",                MSILOperandType::ShortInlineBr, -2};
    t[0x31] = {"ble.s",                MSILOperandType::ShortInlineBr, -2};
    t[0x32] = {"blt.s",                MSILOperandType::ShortInlineBr, -2};
    t[0x33] = {"bne.un.s",             MSILOperandType::ShortInlineBr, -2};
    t[0x34] = {"bge.un.s",             MSILOperandType::ShortInlineBr, -2};
    t[0x35] = {"bgt.un.s",             MSILOperandType::ShortInlineBr, -2};
    t[0x36] = {"ble.un.s",             MSILOperandType::ShortInlineBr, -2};
    t[0x37] = {"blt.un.s",             MSILOperandType::ShortInlineBr, -2};
    t[0x38] = {"br",                   MSILOperandType::InlineBr,       0};
    t[0x39] = {"brfalse",              MSILOperandType::InlineBr,      -1};
    t[0x3A] = {"brtrue",               MSILOperandType::InlineBr,      -1};
    t[0x3B] = {"beq",                  MSILOperandType::InlineBr,      -2};
    t[0x3C] = {"bge",                  MSILOperandType::InlineBr,      -2};
    t[0x3D] = {"bgt",                  MSILOperandType::InlineBr,      -2};
    t[0x3E] = {"ble",                  MSILOperandType::InlineBr,      -2};
    t[0x3F] = {"blt",                  MSILOperandType::InlineBr,      -2};
    t[0x40] = {"bne.un",               MSILOperandType::InlineBr,      -2};
    t[0x41] = {"bge.un",               MSILOperandType::InlineBr,      -2};
    t[0x42] = {"bgt.un",               MSILOperandType::InlineBr,      -2};
    t[0x43] = {"ble.un",               MSILOperandType::InlineBr,      -2};
    t[0x44] = {"blt.un",               MSILOperandType::InlineBr,      -2};
    t[0x45] = {"switch",               MSILOperandType::InlineSwitch,  -1};
    t[0x46] = {"ldind.i1",             MSILOperandType::None,           0};
    t[0x47] = {"ldind.u1",             MSILOperandType::None,           0};
    t[0x48] = {"ldind.i2",             MSILOperandType::None,           0};
    t[0x49] = {"ldind.u2",             MSILOperandType::None,           0};
    t[0x4A] = {"ldind.i4",             MSILOperandType::None,           0};
    t[0x4B] = {"ldind.u4",             MSILOperandType::None,           0};
    t[0x4C] = {"ldind.i8",             MSILOperandType::None,           0};
    t[0x4D] = {"ldind.i",              MSILOperandType::None,           0};
    t[0x4E] = {"ldind.r4",             MSILOperandType::None,           0};
    t[0x4F] = {"ldind.r8",             MSILOperandType::None,           0};
    t[0x50] = {"ldind.ref",            MSILOperandType::None,           0};
    t[0x51] = {"stind.ref",            MSILOperandType::None,          -2};
    t[0x52] = {"stind.i1",             MSILOperandType::None,          -2};
    t[0x53] = {"stind.i2",             MSILOperandType::None,          -2};
    t[0x54] = {"stind.i4",             MSILOperandType::None,          -2};
    t[0x55] = {"stind.i8",             MSILOperandType::None,          -2};
    t[0x56] = {"stind.r4",             MSILOperandType::None,          -2};
    t[0x57] = {"stind.r8",             MSILOperandType::None,          -2};
    t[0x58] = {"add",                  MSILOperandType::None,          -1};
    t[0x59] = {"sub",                  MSILOperandType::None,          -1};
    t[0x5A] = {"mul",                  MSILOperandType::None,          -1};
    t[0x5B] = {"div",                  MSILOperandType::None,          -1};
    t[0x5C] = {"div.un",               MSILOperandType::None,          -1};
    t[0x5D] = {"rem",                  MSILOperandType::None,          -1};
    t[0x5E] = {"rem.un",               MSILOperandType::None,          -1};
    t[0x5F] = {"and",                  MSILOperandType::None,          -1};
    t[0x60] = {"or",                   MSILOperandType::None,          -1};
    t[0x61] = {"xor",                  MSILOperandType::None,          -1};
    t[0x62] = {"shl",                  MSILOperandType::None,          -1};
    t[0x63] = {"shr",                  MSILOperandType::None,          -1};
    t[0x64] = {"shr.un",               MSILOperandType::None,          -1};
    t[0x65] = {"neg",                  MSILOperandType::None,           0};
    t[0x66] = {"not",                  MSILOperandType::None,           0};
    t[0x67] = {"conv.i1",              MSILOperandType::None,           0};
    t[0x68] = {"conv.i2",              MSILOperandType::None,           0};
    t[0x69] = {"conv.i4",              MSILOperandType::None,           0};
    t[0x6A] = {"conv.i8",              MSILOperandType::None,           0};
    t[0x6B] = {"conv.r4",              MSILOperandType::None,           0};
    t[0x6C] = {"conv.r8",              MSILOperandType::None,           0};
    t[0x6D] = {"conv.u4",              MSILOperandType::None,           0};
    t[0x6E] = {"conv.u8",              MSILOperandType::None,           0};
    t[0x6F] = {"callvirt",             MSILOperandType::InlineMethod,   0}; // variable
    t[0x70] = {"cpobj",                MSILOperandType::InlineType,    -2};
    t[0x71] = {"ldobj",                MSILOperandType::InlineType,     0};
    t[0x72] = {"ldstr",                MSILOperandType::InlineString,   1};
    t[0x73] = {"newobj",               MSILOperandType::InlineMethod,   0}; // variable
    t[0x74] = {"castclass",            MSILOperandType::InlineType,     0};
    t[0x75] = {"isinst",               MSILOperandType::InlineType,     0};
    t[0x76] = {"conv.r.un",            MSILOperandType::None,           0};
    // 0x77, 0x78 unused
    t[0x79] = {"unbox",                MSILOperandType::InlineType,     0};
    t[0x7A] = {"throw",                MSILOperandType::None,          -1};
    t[0x7B] = {"ldfld",                MSILOperandType::InlineField,    0};
    t[0x7C] = {"ldflda",               MSILOperandType::InlineField,    0};
    t[0x7D] = {"stfld",                MSILOperandType::InlineField,   -2};
    t[0x7E] = {"ldsfld",               MSILOperandType::InlineField,    1};
    t[0x7F] = {"ldsflda",              MSILOperandType::InlineField,    1};
    t[0x80] = {"stsfld",               MSILOperandType::InlineField,   -1};
    t[0x81] = {"stobj",                MSILOperandType::InlineType,    -2};
    t[0x82] = {"conv.ovf.i1.un",       MSILOperandType::None,           0};
    t[0x83] = {"conv.ovf.i2.un",       MSILOperandType::None,           0};
    t[0x84] = {"conv.ovf.i4.un",       MSILOperandType::None,           0};
    t[0x85] = {"conv.ovf.i8.un",       MSILOperandType::None,           0};
    t[0x86] = {"conv.ovf.u1.un",       MSILOperandType::None,           0};
    t[0x87] = {"conv.ovf.u2.un",       MSILOperandType::None,           0};
    t[0x88] = {"conv.ovf.u4.un",       MSILOperandType::None,           0};
    t[0x89] = {"conv.ovf.u8.un",       MSILOperandType::None,           0};
    t[0x8A] = {"conv.ovf.i.un",        MSILOperandType::None,           0};
    t[0x8B] = {"conv.ovf.u.un",        MSILOperandType::None,           0};
    t[0x8C] = {"box",                  MSILOperandType::InlineType,     0};
    t[0x8D] = {"newarr",               MSILOperandType::InlineType,     0};
    t[0x8E] = {"ldlen",                MSILOperandType::None,           0};
    t[0x8F] = {"ldelema",              MSILOperandType::InlineType,    -1};
    t[0x90] = {"ldelem.i1",            MSILOperandType::None,          -1};
    t[0x91] = {"ldelem.u1",            MSILOperandType::None,          -1};
    t[0x92] = {"ldelem.i2",            MSILOperandType::None,          -1};
    t[0x93] = {"ldelem.u2",            MSILOperandType::None,          -1};
    t[0x94] = {"ldelem.i4",            MSILOperandType::None,          -1};
    t[0x95] = {"ldelem.u4",            MSILOperandType::None,          -1};
    t[0x96] = {"ldelem.i8",            MSILOperandType::None,          -1};
    t[0x97] = {"ldelem.i",             MSILOperandType::None,          -1};
    t[0x98] = {"ldelem.r4",            MSILOperandType::None,          -1};
    t[0x99] = {"ldelem.r8",            MSILOperandType::None,          -1};
    t[0x9A] = {"ldelem.ref",           MSILOperandType::None,          -1};
    t[0x9B] = {"stelem.i",             MSILOperandType::None,          -3};
    t[0x9C] = {"stelem.i1",            MSILOperandType::None,          -3};
    t[0x9D] = {"stelem.i2",            MSILOperandType::None,          -3};
    t[0x9E] = {"stelem.i4",            MSILOperandType::None,          -3};
    t[0x9F] = {"stelem.i8",            MSILOperandType::None,          -3};
    t[0xA0] = {"stelem.r4",            MSILOperandType::None,          -3};
    t[0xA1] = {"stelem.r8",            MSILOperandType::None,          -3};
    t[0xA2] = {"stelem.ref",           MSILOperandType::None,          -3};
    t[0xA3] = {"ldelem",               MSILOperandType::InlineType,    -1};
    t[0xA4] = {"stelem",               MSILOperandType::InlineType,    -3};
    t[0xA5] = {"unbox.any",            MSILOperandType::InlineType,     0};
    // 0xA6..0xB2 unused
    t[0xB3] = {"conv.ovf.i1",          MSILOperandType::None,           0};
    t[0xB4] = {"conv.ovf.u1",          MSILOperandType::None,           0};
    t[0xB5] = {"conv.ovf.i2",          MSILOperandType::None,           0};
    t[0xB6] = {"conv.ovf.u2",          MSILOperandType::None,           0};
    t[0xB7] = {"conv.ovf.i4",          MSILOperandType::None,           0};
    t[0xB8] = {"conv.ovf.u4",          MSILOperandType::None,           0};
    t[0xB9] = {"conv.ovf.i8",          MSILOperandType::None,           0};
    t[0xBA] = {"conv.ovf.u8",          MSILOperandType::None,           0};
    // 0xBB..0xC1 unused
    t[0xC2] = {"refanyval",            MSILOperandType::InlineType,     0};
    t[0xC3] = {"ckfinite",             MSILOperandType::None,           0};
    // 0xC4, 0xC5 unused
    t[0xC6] = {"mkrefany",             MSILOperandType::InlineType,     0};
    // 0xC7..0xCF unused
    t[0xD0] = {"ldtoken",              MSILOperandType::InlineTok,      1};
    t[0xD1] = {"conv.u2",              MSILOperandType::None,           0};
    t[0xD2] = {"conv.u1",              MSILOperandType::None,           0};
    t[0xD3] = {"conv.i",               MSILOperandType::None,           0};
    t[0xD4] = {"conv.ovf.i",           MSILOperandType::None,           0};
    t[0xD5] = {"conv.ovf.u",           MSILOperandType::None,           0};
    t[0xD6] = {"add.ovf",              MSILOperandType::None,          -1};
    t[0xD7] = {"add.ovf.un",           MSILOperandType::None,          -1};
    t[0xD8] = {"mul.ovf",              MSILOperandType::None,          -1};
    t[0xD9] = {"mul.ovf.un",           MSILOperandType::None,          -1};
    t[0xDA] = {"sub.ovf",              MSILOperandType::None,          -1};
    t[0xDB] = {"sub.ovf.un",           MSILOperandType::None,          -1};
    t[0xDC] = {"endfinally",           MSILOperandType::None,           0};
    t[0xDD] = {"leave",                MSILOperandType::InlineBr,       0};
    t[0xDE] = {"leave.s",              MSILOperandType::ShortInlineBr,  0};
    t[0xDF] = {"stind.i",              MSILOperandType::None,          -2};
    t[0xE0] = {"conv.u",               MSILOperandType::None,           0};
    // 0xE1..0xF7 unused
    t[0xF8] = {"prefix7",              MSILOperandType::None,           0};
    t[0xF9] = {"prefix6",              MSILOperandType::None,           0};
    t[0xFA] = {"prefix5",              MSILOperandType::None,           0};
    t[0xFB] = {"prefix4",              MSILOperandType::None,           0};
    t[0xFC] = {"prefix3",              MSILOperandType::None,           0};
    t[0xFD] = {"prefix2",              MSILOperandType::None,           0};
    t[0xFE] = {"prefix1",              MSILOperandType::None,           0}; // two-byte prefix
    t[0xFF] = {"prefixref",            MSILOperandType::None,           0};

    return t;
}();

// Two-byte opcodes indexed by the second byte (0xFE xx), range 0x00..0x1E.
static constexpr uint32_t kTwoByteTableSize = 0x1F;

static constexpr std::array<OpcodeInfo, kTwoByteTableSize> kTwoByteTable = []() {
    std::array<OpcodeInfo, kTwoByteTableSize> t{};
    for (auto& e : t) e = kInvalidOpcodeInfo;

    t[0x00] = {"arglist",              MSILOperandType::None,           1};
    t[0x01] = {"ceq",                  MSILOperandType::None,          -1};
    t[0x02] = {"cgt",                  MSILOperandType::None,          -1};
    t[0x03] = {"cgt.un",               MSILOperandType::None,          -1};
    t[0x04] = {"clt",                  MSILOperandType::None,          -1};
    t[0x05] = {"clt.un",               MSILOperandType::None,          -1};
    t[0x06] = {"ldftn",                MSILOperandType::InlineMethod,   1};
    t[0x07] = {"ldvirtftn",            MSILOperandType::InlineMethod,   0};
    // 0x08 unused
    t[0x09] = {"ldarg",                MSILOperandType::InlineVar,      1};
    t[0x0A] = {"ldarga",               MSILOperandType::InlineVar,      1};
    t[0x0B] = {"starg",                MSILOperandType::InlineVar,     -1};
    t[0x0C] = {"ldloc",                MSILOperandType::InlineVar,      1};
    t[0x0D] = {"ldloca",               MSILOperandType::InlineVar,      1};
    t[0x0E] = {"stloc",                MSILOperandType::InlineVar,     -1};
    t[0x0F] = {"localloc",             MSILOperandType::None,           0};
    // 0x10 unused
    t[0x11] = {"endfilter",            MSILOperandType::None,          -1};
    t[0x12] = {"unaligned.",           MSILOperandType::ShortInlineI,   0};
    t[0x13] = {"volatile.",            MSILOperandType::None,           0};
    t[0x14] = {"tail.",                MSILOperandType::None,           0};
    t[0x15] = {"initobj",              MSILOperandType::InlineType,    -1};
    t[0x16] = {"constrained.",         MSILOperandType::InlineType,     0};
    t[0x17] = {"cpblk",                MSILOperandType::None,          -3};
    t[0x18] = {"initblk",              MSILOperandType::None,          -3};
    // 0x19 unused (no.)
    t[0x1A] = {"rethrow",              MSILOperandType::None,           0};
    // 0x1B unused
    t[0x1C] = {"sizeof",               MSILOperandType::InlineType,     1};
    t[0x1D] = {"refanytype",           MSILOperandType::None,           0};
    t[0x1E] = {"readonly.",            MSILOperandType::None,           0};

    return t;
}();

// ============================================================================
// OpcodeInfo Lookup
// ============================================================================

static const OpcodeInfo& LookupOpcode(MSILOpcode opcode) noexcept {
    const uint16_t raw = static_cast<uint16_t>(opcode);

    if (raw <= 0xFF) {
        return kSingleByteTable[raw];
    }

    if ((raw & 0xFF00) == 0xFE00) {
        const uint16_t idx = raw & 0x00FF;
        if (idx < kTwoByteTableSize) {
            return kTwoByteTable[idx];
        }
    }

    return kInvalidOpcodeInfo;
}

// ============================================================================
// Public Opcode Metadata Accessors
// ============================================================================

const char* MSILDisassembler::GetOpcodeName(MSILOpcode opcode) noexcept {
    return LookupOpcode(opcode).name;
}

MSILOperandType MSILDisassembler::GetOperandType(MSILOpcode opcode) noexcept {
    return LookupOpcode(opcode).operandType;
}

int MSILDisassembler::GetStackDelta(MSILOpcode opcode) noexcept {
    return LookupOpcode(opcode).stackDelta;
}

bool MSILDisassembler::IsBranch(MSILOpcode opcode) noexcept {
    const auto ot = GetOperandType(opcode);
    return ot == MSILOperandType::ShortInlineBr
        || ot == MSILOperandType::InlineBr
        || ot == MSILOperandType::InlineSwitch;
}

bool MSILDisassembler::IsCall(MSILOpcode opcode) noexcept {
    return opcode == MSILOpcode::Call
        || opcode == MSILOpcode::Callvirt
        || opcode == MSILOpcode::Calli
        || opcode == MSILOpcode::Newobj;
}

// ============================================================================
// Safe Little-Endian Read Helpers
// ============================================================================

namespace {

template <typename T>
[[nodiscard]] bool SafeRead(const uint8_t* buf, uint32_t bufSize, uint32_t offset, T& out) noexcept {
    if (offset + sizeof(T) > bufSize) return false;
    std::memcpy(&out, buf + offset, sizeof(T));
    return true;
}

[[nodiscard]] bool SafeReadU8(const uint8_t* buf, uint32_t bufSize, uint32_t offset, uint8_t& out) noexcept {
    if (offset >= bufSize) return false;
    out = buf[offset];
    return true;
}

} // anonymous namespace

// ============================================================================
// Method Header Parsing (ECMA-335 §II.25.4)
// ============================================================================

std::optional<MSILDisassembler::MethodBodyInfo> MSILDisassembler::ParseMethodHeader(
    const uint8_t* body, uint32_t bodySize) noexcept
{
    if (!body || bodySize == 0) return std::nullopt;

    const uint8_t firstByte = body[0];
    const uint8_t formatBits = firstByte & 0x03;

    if (formatBits == static_cast<uint8_t>(MethodHeaderType::TinyFormat)) {
        // Tiny format: single byte header, code size in upper 6 bits
        MethodBodyInfo info{};
        info.headerType       = MethodHeaderType::TinyFormat;
        info.codeSize         = (firstByte >> 2) & 0x3F;
        info.maxStack         = 8;
        info.localVarSigToken = 0;
        info.codeOffset       = 1;
        info.hasMoreSections  = false;
        info.initLocals       = false;

        if (info.codeOffset + info.codeSize > bodySize) return std::nullopt;
        return info;
    }

    if (formatBits == static_cast<uint8_t>(MethodHeaderType::FatFormat)) {
        // Fat format: 12-byte header
        if (bodySize < 12) return std::nullopt;

        uint16_t flagsAndSize = 0;
        std::memcpy(&flagsAndSize, body, sizeof(uint16_t));

        const uint8_t headerSizeDwords = static_cast<uint8_t>((flagsAndSize >> 12) & 0x0F);
        const uint32_t headerSizeBytes = static_cast<uint32_t>(headerSizeDwords) * 4;
        if (headerSizeBytes < 12 || headerSizeBytes > bodySize) return std::nullopt;

        MethodBodyInfo info{};
        info.headerType = MethodHeaderType::FatFormat;
        info.hasMoreSections = (flagsAndSize & kMoreSectionsFlag) != 0;
        info.initLocals      = (flagsAndSize & kInitLocalsFlag) != 0;

        std::memcpy(&info.maxStack, body + 2, sizeof(uint16_t));
        std::memcpy(&info.codeSize, body + 4, sizeof(uint32_t));
        std::memcpy(&info.localVarSigToken, body + 8, sizeof(uint32_t));

        info.codeOffset = headerSizeBytes;

        if (info.codeSize > kMaxILMethodBodySize) return std::nullopt;
        if (static_cast<uint64_t>(info.codeOffset) + info.codeSize > bodySize) return std::nullopt;

        return info;
    }

    return std::nullopt;
}

// ============================================================================
// Exception Clause Parsing (ECMA-335 §II.25.4.5 / §II.25.4.6)
// ============================================================================

static constexpr uint8_t kSectFatFormat     = 0x40;
static constexpr uint8_t kSectMoreSections  = 0x80;
static constexpr uint32_t kMaxExceptionClauses = 4096;

std::vector<ExceptionClause> MSILDisassembler::ParseExceptionClauses(
    const uint8_t* body, uint32_t bodySize,
    uint32_t codeOffset, uint32_t codeSize) noexcept
{
    std::vector<ExceptionClause> clauses;

    // Exception sections start after IL code, aligned to 4-byte boundary.
    uint32_t pos = codeOffset + codeSize;
    pos = (pos + 3) & ~3u;

    bool moreSections = true;
    while (moreSections && pos < bodySize && clauses.size() < kMaxExceptionClauses) {
        if (pos + 4 > bodySize) break;

        const uint8_t kind = body[pos];
        moreSections = (kind & kSectMoreSections) != 0;

        // We only care about exception handling sections (kind & 0x01).
        const bool isExceptionSection = (kind & 0x01) != 0;
        const bool isFat = (kind & kSectFatFormat) != 0;

        if (isFat) {
            // Fat section: 4-byte header (kind:1 + dataSize:3)
            if (pos + 4 > bodySize) break;

            uint32_t dataSize = 0;
            std::memcpy(&dataSize, body + pos, sizeof(uint32_t));
            dataSize = (dataSize >> 8) & 0x00FFFFFF;

            pos += 4;
            if (dataSize < 4) break;
            const uint32_t payloadSize = dataSize - 4;

            if (!isExceptionSection) {
                pos += payloadSize;
                continue;
            }

            // Each fat clause is 24 bytes.
            const uint32_t clauseCount = payloadSize / 24;
            for (uint32_t i = 0; i < clauseCount && clauses.size() < kMaxExceptionClauses; ++i) {
                const uint32_t clauseStart = pos + i * 24;
                if (clauseStart + 24 > bodySize) break;

                ExceptionClause c{};
                uint32_t rawFlags = 0;
                std::memcpy(&rawFlags,              body + clauseStart +  0, sizeof(uint32_t));
                std::memcpy(&c.tryOffset,           body + clauseStart +  4, sizeof(uint32_t));
                std::memcpy(&c.tryLength,           body + clauseStart +  8, sizeof(uint32_t));
                std::memcpy(&c.handlerOffset,       body + clauseStart + 12, sizeof(uint32_t));
                std::memcpy(&c.handlerLength,       body + clauseStart + 16, sizeof(uint32_t));
                std::memcpy(&c.classTokenOrFilterOffset, body + clauseStart + 20, sizeof(uint32_t));

                c.flags = static_cast<ExceptionClauseType>(rawFlags);

                // Validate offsets are within IL bounds.
                if (c.tryOffset + c.tryLength <= codeSize &&
                    c.handlerOffset + c.handlerLength <= codeSize) {
                    clauses.push_back(c);
                }
            }
            pos += payloadSize;
        } else {
            // Small section: 4-byte header (kind:1 + dataSize:1 + padding:2)
            if (pos + 4 > bodySize) break;

            const uint32_t dataSize = body[pos + 1];
            pos += 4;
            if (dataSize < 4) break;
            const uint32_t payloadSize = dataSize - 4;

            if (!isExceptionSection) {
                pos += payloadSize;
                continue;
            }

            // Each small clause is 12 bytes.
            const uint32_t clauseCount = payloadSize / 12;
            for (uint32_t i = 0; i < clauseCount && clauses.size() < kMaxExceptionClauses; ++i) {
                const uint32_t clauseStart = pos + i * 12;
                if (clauseStart + 12 > bodySize) break;

                ExceptionClause c{};
                uint16_t smallFlags = 0, tryOff16 = 0, handlerOff16 = 0;
                uint8_t  tryLen8 = 0, handlerLen8 = 0;

                std::memcpy(&smallFlags,     body + clauseStart + 0, sizeof(uint16_t));
                std::memcpy(&tryOff16,       body + clauseStart + 2, sizeof(uint16_t));
                tryLen8 = body[clauseStart + 4];
                std::memcpy(&handlerOff16,   body + clauseStart + 5, sizeof(uint16_t));
                handlerLen8 = body[clauseStart + 7];
                std::memcpy(&c.classTokenOrFilterOffset, body + clauseStart + 8, sizeof(uint32_t));

                c.flags         = static_cast<ExceptionClauseType>(static_cast<uint32_t>(smallFlags));
                c.tryOffset     = tryOff16;
                c.tryLength     = tryLen8;
                c.handlerOffset = handlerOff16;
                c.handlerLength = handlerLen8;

                if (c.tryOffset + c.tryLength <= codeSize &&
                    c.handlerOffset + c.handlerLength <= codeSize) {
                    clauses.push_back(c);
                }
            }
            pos += payloadSize;
        }
    }

    return clauses;
}

// ============================================================================
// Operand Size Helper
// ============================================================================

namespace {

[[nodiscard]] uint32_t OperandFixedSize(MSILOperandType ot) noexcept {
    switch (ot) {
        case MSILOperandType::None:           return 0;
        case MSILOperandType::ShortInlineI:   return 1;
        case MSILOperandType::ShortInlineVar: return 1;
        case MSILOperandType::ShortInlineBr:  return 1;
        case MSILOperandType::InlineVar:      return 2;
        case MSILOperandType::InlineI:        return 4;
        case MSILOperandType::InlineMethod:   return 4;
        case MSILOperandType::InlineField:    return 4;
        case MSILOperandType::InlineType:     return 4;
        case MSILOperandType::InlineString:   return 4;
        case MSILOperandType::InlineSig:      return 4;
        case MSILOperandType::InlineTok:      return 4;
        case MSILOperandType::InlineBr:       return 4;
        case MSILOperandType::ShortInlineR:   return 4;
        case MSILOperandType::InlineI8:       return 8;
        case MSILOperandType::InlineR:        return 8;
        case MSILOperandType::InlineSwitch:   return 0; // variable length
    }
    return 0;
}

} // anonymous namespace

// ============================================================================
// Instruction Disassembly
// ============================================================================

std::vector<MSILInstruction> MSILDisassembler::Disassemble(
    const uint8_t* ilBytes, uint32_t ilSize) noexcept
{
    std::vector<MSILInstruction> instructions;
    if (!ilBytes || ilSize == 0) return instructions;

    instructions.reserve(std::min<uint32_t>(ilSize, 8192));

    uint32_t offset = 0;

    while (offset < ilSize && instructions.size() < kMaxDecodedInstructions) {
        MSILInstruction instr{};
        instr.offset = offset;

        // -- Decode opcode --
        const uint8_t firstByte = ilBytes[offset];
        uint32_t opcodeSize = 1;
        MSILOpcode opcode;

        if (firstByte == 0xFE) {
            // Two-byte opcode
            if (offset + 1 >= ilSize) {
                // Truncated: prefix with no second byte
                instr.opcode = MSILOpcode::INVALID;
                instr.operandType = MSILOperandType::None;
                instr.size = 1;
                instructions.push_back(std::move(instr));
                break;
            }
            const uint8_t secondByte = ilBytes[offset + 1];
            opcodeSize = 2;
            opcode = static_cast<MSILOpcode>(0xFE00 | static_cast<uint16_t>(secondByte));
        } else {
            opcode = static_cast<MSILOpcode>(firstByte);
        }

        const auto& info = LookupOpcode(opcode);
        const bool isKnown = (info.name[0] != 'I'); // "INVALID" starts with 'I', all real opcodes are lowercase

        if (!isKnown) {
            // Unknown opcode — emit as invalid, advance one byte.
            instr.opcode = MSILOpcode::INVALID;
            instr.operandType = MSILOperandType::None;
            instr.size = 1;
            instructions.push_back(std::move(instr));
            offset += 1;
            continue;
        }

        instr.opcode = opcode;
        instr.operandType = info.operandType;

        uint32_t operandOffset = offset + opcodeSize;

        // -- Decode operand --
        if (info.operandType == MSILOperandType::InlineSwitch) {
            // switch: 4-byte count + count * 4-byte offsets
            uint32_t targetCount = 0;
            if (!SafeRead(ilBytes, ilSize, operandOffset, targetCount)) {
                instr.opcode = MSILOpcode::INVALID;
                instr.size = opcodeSize;
                instructions.push_back(std::move(instr));
                break;
            }

            if (targetCount > kMaxSwitchTargets) {
                instr.opcode = MSILOpcode::INVALID;
                instr.size = opcodeSize + 4;
                instructions.push_back(std::move(instr));
                break;
            }

            const uint32_t switchPayloadSize = 4 + targetCount * 4;
            if (operandOffset + switchPayloadSize > ilSize) {
                instr.opcode = MSILOpcode::INVALID;
                instr.size = opcodeSize + 4;
                instructions.push_back(std::move(instr));
                break;
            }

            instr.switchTargets.reserve(targetCount);
            for (uint32_t i = 0; i < targetCount; ++i) {
                int32_t target = 0;
                (void)SafeRead(ilBytes, ilSize, operandOffset + 4 + i * 4, target);
                instr.switchTargets.push_back(target);
            }

            instr.size = opcodeSize + switchPayloadSize;
        } else {
            const uint32_t operandSize = OperandFixedSize(info.operandType);

            if (operandOffset + operandSize > ilSize) {
                // Truncated operand
                instr.opcode = MSILOpcode::INVALID;
                instr.size = opcodeSize;
                instructions.push_back(std::move(instr));
                break;
            }

            // Read the operand value into the union.
            switch (info.operandType) {
                case MSILOperandType::None:
                    break;

                case MSILOperandType::ShortInlineI:
                    (void)SafeRead(ilBytes, ilSize, operandOffset, instr.operand.shortI);
                    break;

                case MSILOperandType::ShortInlineVar:
                    (void)SafeReadU8(ilBytes, ilSize, operandOffset, instr.operand.varIndex8);
                    break;

                case MSILOperandType::ShortInlineBr:
                {
                    int8_t rel = 0;
                    (void)SafeRead(ilBytes, ilSize, operandOffset, rel);
                    instr.operand.branchOffset = static_cast<int32_t>(rel);
                    break;
                }

                case MSILOperandType::InlineVar:
                    (void)SafeRead(ilBytes, ilSize, operandOffset, instr.operand.varIndex16);
                    break;

                case MSILOperandType::InlineI:
                    (void)SafeRead(ilBytes, ilSize, operandOffset, instr.operand.i32);
                    break;

                case MSILOperandType::InlineMethod:
                case MSILOperandType::InlineField:
                case MSILOperandType::InlineType:
                case MSILOperandType::InlineString:
                case MSILOperandType::InlineSig:
                case MSILOperandType::InlineTok:
                    (void)SafeRead(ilBytes, ilSize, operandOffset, instr.operand.token);
                    break;

                case MSILOperandType::InlineBr:
                    (void)SafeRead(ilBytes, ilSize, operandOffset, instr.operand.branchOffset);
                    break;

                case MSILOperandType::ShortInlineR:
                    (void)SafeRead(ilBytes, ilSize, operandOffset, instr.operand.f32);
                    break;

                case MSILOperandType::InlineI8:
                    (void)SafeRead(ilBytes, ilSize, operandOffset, instr.operand.i64);
                    break;

                case MSILOperandType::InlineR:
                    (void)SafeRead(ilBytes, ilSize, operandOffset, instr.operand.f64);
                    break;

                case MSILOperandType::InlineSwitch:
                    break; // handled above
            }

            instr.size = opcodeSize + operandSize;
        }

        offset += instr.size;
        instructions.push_back(std::move(instr));
    }

    return instructions;
}

// ============================================================================
// Full Method Disassembly (header + IL + exceptions)
// ============================================================================

MSILDisassembler::DisassemblyResult MSILDisassembler::DisassembleMethod(
    const uint8_t* body, uint32_t bodySize) noexcept
{
    DisassemblyResult result{};

    auto headerOpt = ParseMethodHeader(body, bodySize);
    if (!headerOpt.has_value()) return result;

    result.header = *headerOpt;

    const uint8_t* ilStart = body + result.header.codeOffset;
    result.instructions = Disassemble(ilStart, result.header.codeSize);

    if (result.header.headerType == MethodHeaderType::FatFormat && result.header.hasMoreSections) {
        result.exceptionClauses = ParseExceptionClauses(
            body, bodySize, result.header.codeOffset, result.header.codeSize);
    }

    result.valid = true;
    return result;
}

} // namespace Phantom::CLR
