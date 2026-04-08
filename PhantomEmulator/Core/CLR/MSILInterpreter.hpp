/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MSILInterpreter.hpp — Stack-based CIL/MSIL virtual machine
 *
 * Interprets .NET method bodies to extract decrypted strings, API call
 * sequences, byte-array payloads, and obfuscation behaviour without
 * requiring a full CLR implementation.
 *
 * References:
 *   ECMA-335 (6th Edition) — Common Language Infrastructure §III
 *   Microsoft .NET metadata specification
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "CLRTypes.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Phantom::CLR {

// Forward declaration — MetadataParser is built by a sibling module.
class MetadataParser;

// ============================================================================
// Evaluation Stack Value Representation
// ============================================================================

enum class ILValueType : uint8_t {
    Null,
    Int32,
    Int64,
    Float64,
    String,
    ObjectRef,
    ArrayRef,
};

struct ILValue {
    ILValueType type = ILValueType::Null;
    union {
        int32_t  i32;
        int64_t  i64;
        double   f64;
        uint32_t ref;   // Index into string / array / object tables
    };

    ILValue() noexcept : type(ILValueType::Null), i64(0) {}

    static ILValue MakeNull() noexcept {
        ILValue v;
        return v;
    }
    static ILValue MakeI32(int32_t val) noexcept {
        ILValue v;
        v.type = ILValueType::Int32;
        v.i32  = val;
        return v;
    }
    static ILValue MakeI64(int64_t val) noexcept {
        ILValue v;
        v.type = ILValueType::Int64;
        v.i64  = val;
        return v;
    }
    static ILValue MakeF64(double val) noexcept {
        ILValue v;
        v.type = ILValueType::Float64;
        v.f64  = val;
        return v;
    }
    static ILValue MakeString(uint32_t idx) noexcept {
        ILValue v;
        v.type = ILValueType::String;
        v.ref  = idx;
        return v;
    }
    static ILValue MakeObjectRef(uint32_t idx) noexcept {
        ILValue v;
        v.type = ILValueType::ObjectRef;
        v.ref  = idx;
        return v;
    }
    static ILValue MakeArrayRef(uint32_t idx) noexcept {
        ILValue v;
        v.type = ILValueType::ArrayRef;
        v.ref  = idx;
        return v;
    }

    [[nodiscard]] int64_t AsInteger() const noexcept {
        switch (type) {
            case ILValueType::Int32: return static_cast<int64_t>(i32);
            case ILValueType::Int64: return i64;
            default: return 0;
        }
    }

    [[nodiscard]] bool IsZero() const noexcept {
        switch (type) {
            case ILValueType::Null:    return true;
            case ILValueType::Int32:   return i32 == 0;
            case ILValueType::Int64:   return i64 == 0;
            case ILValueType::Float64: return f64 == 0.0;
            default: return false;
        }
    }
};

// ============================================================================
// Callback & Result Types
// ============================================================================

/// Returns (pointer-to-IL-bytes, size) for a method body given its token.
/// Returns (nullptr, 0) when the body is unavailable.
using MethodBodyProvider =
    std::function<std::pair<const uint8_t*, uint32_t>(uint32_t methodToken)>;

struct InterpretationResult {
    std::vector<std::u16string>          decryptedStrings;
    std::vector<DotNetAPICall>           apiCalls;
    std::vector<std::vector<uint8_t>>    extractedArrays;

    uint64_t instructionsExecuted  = 0;
    uint32_t maxStackDepthReached  = 0;
    uint32_t callDepthReached      = 0;

    bool hitInstructionLimit  = false;
    bool hitStackLimit        = false;
    bool hitCallDepthLimit    = false;
    bool threwException       = false;
};

// ============================================================================
// MSILInterpreter — Stack-based IL Virtual Machine
// ============================================================================

class MSILInterpreter {
public:
    explicit MSILInterpreter(const MetadataParser& metadata) noexcept;
    ~MSILInterpreter() noexcept;

    // Non-copyable, movable
    MSILInterpreter(const MSILInterpreter&)            = delete;
    MSILInterpreter& operator=(const MSILInterpreter&) = delete;
    MSILInterpreter(MSILInterpreter&&) noexcept;
    MSILInterpreter& operator=(MSILInterpreter&&) noexcept;

    /// Provide a callback that fetches IL bytes for a MethodDef token.
    void SetMethodBodyProvider(MethodBodyProvider provider) noexcept;

    /// Execute a single method body from pre-disassembled instructions.
    [[nodiscard]] InterpretationResult Execute(
        const std::vector<MSILInstruction>& instructions,
        MetadataToken                       methodToken,
        const std::vector<ILValue>&         args = {}) noexcept;

    /// Execute every .cctor in the assembly (primary use case: string decryption).
    [[nodiscard]] InterpretationResult ExecuteStaticConstructors(
        MethodBodyProvider bodyProvider) noexcept;

    // --- Configuration (safe defaults from CLRTypes.hpp) ---
    void SetMaxInstructions(uint64_t max) noexcept;
    void SetMaxStackDepth(uint32_t max) noexcept;
    void SetMaxCallDepth(uint32_t max) noexcept;
    void SetMaxArraySize(uint32_t max) noexcept;

    // --- Query ---
    [[nodiscard]] const std::vector<std::u16string>& GetDecryptedStrings() const noexcept;
    [[nodiscard]] const std::vector<DotNetAPICall>&  GetAPICalls() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom::CLR
