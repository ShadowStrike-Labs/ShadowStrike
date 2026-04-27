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

/// Runtime type tag for values stored on the bounded MSIL evaluation stack.
enum class ILValueType : uint8_t {
    Null,
    Int32,
    Int64,
    Float64,
    String,
    ObjectRef,
    ArrayRef,
};

/// Lightweight value used by the interpreter for stack, local, and argument slots.
///
/// The active union member is selected by `type`. Factory helpers initialize the
/// correct member and all query helpers are noexcept so malformed IL cannot
/// propagate exceptions across the emulator boundary.
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

    /// Return the signed integer representation used by arithmetic opcodes.
    /// Non-integer values intentionally coerce to zero for resilient best-effort
    /// extraction from hostile or incomplete IL.
    [[nodiscard]] int64_t AsInteger() const noexcept {
        switch (type) {
            case ILValueType::Int32: return static_cast<int64_t>(i32);
            case ILValueType::Int64: return i64;
            default: return 0;
        }
    }

    /// Return whether the value is false/null for conditional branch opcodes.
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

/// Returns `(pointer-to-IL-bytes, size)` for a method body token.
///
/// Implementations may be backed by an in-memory PE image, cache, or test
/// fixture. Throwing providers are treated as untrusted plugin boundaries by
/// the interpreter and abort the current run without escaping noexcept APIs.
using MethodBodyProvider =
    std::function<std::pair<const uint8_t*, uint32_t>(uint32_t methodToken)>;

/// Result of a bounded interpreter run.
///
/// Vectors are best-effort: under memory pressure they may be empty while the
/// counters and limit flags still describe the execution. All data is derived
/// from emulated IL and must be treated as attacker-controlled by callers.
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
    /// Construct an interpreter bound to immutable metadata.
    ///
    /// Allocation failure leaves the object in an inert state; subsequent calls
    /// return empty results rather than throwing. The referenced MetadataParser
    /// must outlive the interpreter. Not thread-safe; create one interpreter per
    /// concurrent analysis task.
    explicit MSILInterpreter(const MetadataParser& metadata) noexcept;
    ~MSILInterpreter() noexcept;

    // Non-copyable, movable
    MSILInterpreter(const MSILInterpreter&)            = delete;
    MSILInterpreter& operator=(const MSILInterpreter&) = delete;
    MSILInterpreter(MSILInterpreter&&) noexcept;
    MSILInterpreter& operator=(MSILInterpreter&&) noexcept;

    /// Provide a callback that fetches IL bytes for a MethodDef token.
    ///
    /// The callback is stored by value and may be cleared if allocation fails.
    /// Callback exceptions are contained at the interpreter boundary.
    void SetMethodBodyProvider(MethodBodyProvider provider) noexcept;

    /// Execute a single method body from pre-disassembled instructions.
    ///
    /// Preconditions: `instructions` must come from `MSILDisassembler` for the
    /// same module metadata. Execution is bounded by instruction, stack, call,
    /// string, array, and API-call caps. On malformed IL or resource pressure,
    /// the returned limit flags/counters indicate the best-effort outcome.
    [[nodiscard]] InterpretationResult Execute(
        const std::vector<MSILInstruction>& instructions,
        MetadataToken                       methodToken,
        const std::vector<ILValue>&         args = {}) noexcept;

    /// Execute every static constructor discovered in metadata.
    ///
    /// This helper is intentionally conservative: body-provider failures or
    /// unavailable raw IL bodies are skipped, and partial aggregate results are
    /// returned without throwing.
    [[nodiscard]] InterpretationResult ExecuteStaticConstructors(
        MethodBodyProvider bodyProvider) noexcept;

    // --- Configuration (safe defaults and hard caps from CLRTypes.hpp) ---
    /// Set the maximum number of IL instructions executed per call. Values are clamped.
    void SetMaxInstructions(uint64_t max) noexcept;
    /// Set the maximum evaluation-stack depth. Values are clamped.
    void SetMaxStackDepth(uint32_t max) noexcept;
    /// Set the maximum recursive method-call depth. Values are clamped.
    void SetMaxCallDepth(uint32_t max) noexcept;
    /// Set the maximum tracked array allocation size. Values are clamped.
    void SetMaxArraySize(uint32_t max) noexcept;

    // --- Query ---
    /// Return the cumulative decrypted-string table owned by this interpreter.
    [[nodiscard]] const std::vector<std::u16string>& GetDecryptedStrings() const noexcept;
    /// Return the cumulative API-call table owned by this interpreter.
    [[nodiscard]] const std::vector<DotNetAPICall>&  GetAPICalls() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom::CLR
