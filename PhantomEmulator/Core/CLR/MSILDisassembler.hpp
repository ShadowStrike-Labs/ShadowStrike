/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MSILDisassembler.hpp — MSIL/CIL bytecode disassembler
 *
 * Decodes .NET Intermediate Language from method bodies into structured
 * MSILInstruction objects. Handles all ECMA-335 opcodes, both tiny and
 * fat method headers, and exception handling clause sections.
 *
 * References:
 *   ECMA-335 (6th Edition) §III — CIL Instruction Set
 *   ECMA-335 (6th Edition) §II.25.4 — Method Body Format
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "CLRTypes.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace Phantom::CLR {

// ============================================================================
// Exception Handling Clause Types (ECMA-335 §II.25.4.6)
// ============================================================================

enum class ExceptionClauseType : uint32_t {
    Exception = 0x0000,
    Filter    = 0x0001,
    Finally   = 0x0002,
    Fault     = 0x0004,
};

struct ExceptionClause {
    ExceptionClauseType flags;
    uint32_t tryOffset;
    uint32_t tryLength;
    uint32_t handlerOffset;
    uint32_t handlerLength;
    uint32_t classTokenOrFilterOffset;
};

// ============================================================================
// MSILDisassembler — Stateless MSIL bytecode decoder
// ============================================================================

class MSILDisassembler {
public:
    // Maximum decoded instructions per method body
    static constexpr uint32_t kMaxDecodedInstructions = 1'000'000;

    // ---- Method Header Parsing ----

    struct MethodBodyInfo {
        MethodHeaderType headerType;  // Defined in CLRTypes.hpp
        uint32_t         codeSize;
        uint16_t         maxStack;
        uint32_t         localVarSigToken;
        uint32_t         codeOffset;
        bool             hasMoreSections;
        bool             initLocals;
    };

    [[nodiscard]] static std::optional<MethodBodyInfo> ParseMethodHeader(
        const uint8_t* body, uint32_t bodySize) noexcept;

    // ---- Disassembly ----

    [[nodiscard]] static std::vector<MSILInstruction> Disassemble(
        const uint8_t* ilBytes, uint32_t ilSize) noexcept;

    struct DisassemblyResult {
        MethodBodyInfo                   header;
        std::vector<MSILInstruction>     instructions;
        std::vector<ExceptionClause>     exceptionClauses;
        bool                             valid = false;
    };

    [[nodiscard]] static DisassemblyResult DisassembleMethod(
        const uint8_t* body, uint32_t bodySize) noexcept;

    // ---- Opcode Metadata Queries ----

    [[nodiscard]] static const char* GetOpcodeName(MSILOpcode opcode) noexcept;
    [[nodiscard]] static MSILOperandType GetOperandType(MSILOpcode opcode) noexcept;
    [[nodiscard]] static int GetStackDelta(MSILOpcode opcode) noexcept;
    [[nodiscard]] static bool IsBranch(MSILOpcode opcode) noexcept;
    [[nodiscard]] static bool IsCall(MSILOpcode opcode) noexcept;

private:
    static std::vector<ExceptionClause> ParseExceptionClauses(
        const uint8_t* body, uint32_t bodySize,
        uint32_t codeOffset, uint32_t codeSize) noexcept;
};

} // namespace Phantom::CLR
