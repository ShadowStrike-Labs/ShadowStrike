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

/**
 * @brief ECMA-335 exception handling clause decoded from a method body.
 *
 * Offsets and lengths are relative to the IL code stream and are validated to
 * remain within the decoded method body. Thread safety: immutable value type.
 */
struct ExceptionClause {
    ExceptionClauseType flags = ExceptionClauseType::Exception;
    uint32_t tryOffset = 0;
    uint32_t tryLength = 0;
    uint32_t handlerOffset = 0;
    uint32_t handlerLength = 0;
    uint32_t classTokenOrFilterOffset = 0;
};

// ============================================================================
// MSILDisassembler — Stateless MSIL bytecode decoder
// ============================================================================

/**
 * @brief Stateless defensive decoder for ECMA-335 CIL/MSIL method bodies.
 *
 * All public functions accept caller-owned byte buffers and validate every
 * offset, operand size, switch target array, and exception section before
 * reading. Failure contract: malformed/truncated input returns nullopt, invalid
 * placeholder instructions, or a result with valid=false; public APIs never
 * throw. Thread safety: all methods are static and reentrant. IRQL: user-mode.
 */
class MSILDisassembler {
public:
    // Maximum decoded instructions per method body
    static constexpr uint32_t kMaxDecodedInstructions = 1'000'000;

    // ---- Method Header Parsing ----

    struct MethodBodyInfo {
        MethodHeaderType headerType = MethodHeaderType::TinyFormat;
        uint32_t         codeSize = 0;
        uint16_t         maxStack = 0;
        uint32_t         localVarSigToken = 0;
        uint32_t         codeOffset = 0;
        bool             hasMoreSections = false;
        bool             initLocals = false;
    };

    /**
     * @brief Parses tiny/fat method body headers.
     * @return Header info when the body is complete and code bounds are valid.
     */
    [[nodiscard]] static std::optional<MethodBodyInfo> ParseMethodHeader(
        const uint8_t* body, uint32_t bodySize) noexcept;

    // ---- Disassembly ----

    /**
     * @brief Decodes a raw IL byte stream into bounded MSILInstruction records.
     * @return Partial decoded stream with invalid sentinel on truncation.
     */
    [[nodiscard]] static std::vector<MSILInstruction> Disassemble(
        const uint8_t* ilBytes, uint32_t ilSize) noexcept;

    /**
     * @brief Complete method body disassembly result.
     */
    struct DisassemblyResult {
        MethodBodyInfo                   header;
        std::vector<MSILInstruction>     instructions;
        std::vector<ExceptionClause>     exceptionClauses;
        bool                             valid = false;
    };

    /**
     * @brief Parses a method header, disassembles IL, and extracts EH clauses.
     * @return valid=false on malformed input or allocation failure.
     */
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
