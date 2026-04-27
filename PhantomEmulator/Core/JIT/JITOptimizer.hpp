/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * JITOptimizer — Advanced optimization passes for JIT compilation
 *
 * Provides trace building, IR generation, constant folding, dead store
 * elimination, register allocation, and self-modifying code detection
 * for the JIT compilation subsystem.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../CPU/Executor/Decoder/Instruction.hpp"
#include "../../Common/Types.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

namespace Phantom {

// ============================================================================
// Trace Structures
// ============================================================================

struct TraceBlock {
    GuestAddress startAddress = 0;
    GuestAddress endAddress = 0;
    uint32_t instructionCount = 0;
    GuestAddress fallthroughTarget = 0;
    GuestAddress branchTarget = 0;
    bool isBranchTaken = false;
    float branchTakenRate = 0.0f;
};

struct TraceInfo {
    std::vector<TraceBlock> blocks;
    GuestAddress entryAddress = 0;
    uint32_t totalInstructions = 0;
    uint64_t executionCount = 0;
    bool isLoop = false;
};

// ============================================================================
// Register Allocation
// ============================================================================

struct RegisterMapping {
    uint8_t guestGPR = 0xFF;
    uint8_t hostReg = 0xFF;
    bool isDirty = false;
    bool isLive = false;
};

// ============================================================================
// Optimization Statistics
// ============================================================================

struct OptimizationStats {
    uint32_t tracesBuilt = 0;
    uint32_t tracesCompiled = 0;
    uint32_t constantsFolded = 0;
    uint32_t deadStoresEliminated = 0;
    uint32_t registersAllocated = 0;
    uint32_t smcDetections = 0;
    uint32_t cacheInvalidations = 0;
    uint64_t interpretedInstructions = 0;
    uint64_t compiledInstructions = 0;
    double jitSpeedup = 0.0;
};

// ============================================================================
// Intermediate Representation
// ============================================================================

struct IRInstruction {
    enum class Op : uint8_t {
        Nop,
        MovImm,
        MovReg,
        Load,
        Store,
        Add, Sub, And, Or, Xor, Not, Neg,
        Shl, Shr, Sar, Rol, Ror,
        Mul, Div,
        Cmp, Test,
        Jcc,
        Jmp,
        Call,
        Ret,
        FlagUpdate,
        SideEffect,
    };

    Op op = Op::Nop;
    uint8_t dst = 0xFF;
    uint8_t src1 = 0xFF;
    uint8_t src2 = 0xFF;
    uint64_t immediate = 0;
    GuestAddress guestAddress = 0;
    OperandSize size = OperandSize::Size64;
    bool hasSideEffects = false;
    bool isDeadStore = false;
    bool isFolded = false;
};

// ============================================================================
// JITOptimizer
// ============================================================================

class JITOptimizer {
public:
    explicit JITOptimizer() noexcept;
    ~JITOptimizer() noexcept;

    JITOptimizer(const JITOptimizer&) = delete;
    JITOptimizer& operator=(const JITOptimizer&) = delete;
    JITOptimizer(JITOptimizer&&) noexcept;
    JITOptimizer& operator=(JITOptimizer&&) noexcept;

    // === Trace Building ===

    [[nodiscard]] std::optional<TraceInfo> BuildTrace(
        GuestAddress entryPoint,
        const std::unordered_map<GuestAddress, uint32_t>& blockProfile,
        const DecodedInstruction* instructions,
        uint32_t instrCount,
        uint32_t maxTraceLength = 256) const noexcept;

    // === IR Generation ===

    [[nodiscard]] std::vector<IRInstruction> GenerateIR(
        const DecodedInstruction* instructions,
        uint32_t count) const noexcept;

    // === Optimization Passes ===

    void ConstantFold(std::vector<IRInstruction>& ir) noexcept;
    void EliminateDeadStores(std::vector<IRInstruction>& ir) noexcept;
    void PropagateConstants(std::vector<IRInstruction>& ir) noexcept;
    void ReduceStrength(std::vector<IRInstruction>& ir) noexcept;

    // === Register Allocation ===

    [[nodiscard]] std::vector<RegisterMapping> AllocateRegisters(
        const std::vector<IRInstruction>& ir,
        uint32_t availableHostRegs = 6) const noexcept;

    // === Self-Modifying Code Detection ===

    void TrackCompiledBlock(GuestAddress start, GuestSize size) noexcept;
    void ForgetCompiledBlock(GuestAddress start) noexcept;
    void OnMemoryWrite(GuestAddress addr, GuestSize size) noexcept;

    [[nodiscard]] std::vector<GuestAddress> GetInvalidatedBlocks() const noexcept;

    void ClearWriteTracking() noexcept;

    // === JIT Profiling ===

    [[nodiscard]] bool ShouldCompile(
        GuestAddress addr,
        uint32_t executionCount,
        uint32_t hotThreshold) const noexcept;

    [[nodiscard]] OptimizationStats GetStats() const noexcept;
    void ResetStats() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
