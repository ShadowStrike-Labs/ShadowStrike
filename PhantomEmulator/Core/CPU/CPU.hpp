/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "State/CPUState.hpp"
#include "Executor/Decoder/InstructionDecoder.hpp"
#include "Executor/Decoder/Instruction.hpp"
#include "../Memory/VirtualMemory.hpp"
#include "../Memory/MemoryTracker.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"
#include "../../Common/Config.hpp"
#include <cstdint>
#include <functional>
#include <optional>
#include <atomic>

namespace Phantom {

// ============================================================================
// CPU Execution Callbacks
// ============================================================================

// Called before each instruction is executed. Return false to stop execution.
using PreInstructionCallback = std::function<bool(const CPUState&, const DecodedInstruction&)>;

// Called after each instruction is executed.
using PostInstructionCallback = std::function<void(const CPUState&, const DecodedInstruction&)>;

// Called when an API hook address is hit.
// Returns: true = API was handled (continue execution), false = stop
using APICallCallback = std::function<bool(CPUState&, VirtualMemory&, GuestAddress apiAddr)>;

// Called when SYSCALL/SYSENTER/INT 0x2E is executed.
using SyscallCallback = std::function<bool(CPUState&, VirtualMemory&)>;

// Called when an interrupt is triggered.
using InterruptCallback = std::function<bool(CPUState&, VirtualMemory&, uint8_t vector)>;

// ============================================================================
// CPU Execution Result
// ============================================================================

struct ExecutionResult {
    StopReason     reason         = StopReason::None;
    ErrorCode      errorCode      = ErrorCode::Success;
    uint64_t       instructionsExecuted = 0;
    GuestAddress   faultAddress   = 0;        // For access violations
    GuestAddress   lastRIP        = 0;        // RIP of last executed instruction
    uint64_t       apiCallCount   = 0;
};

// ============================================================================
// CPU — Fetch-Decode-Execute Engine
// ============================================================================
// The central emulation loop. Owns a CPUState and operates on a VirtualMemory.
//
// Design:
// - Single-threaded per CPU instance (thread scheduling is above this level)
// - No heap allocation in the hot path
// - Callbacks for API hooks, breakpoints, tracing
// - Configurable instruction/time limits
// - Clean abort on any error (no silent corruption)

class CPU {
public:
    CPU() noexcept;
    ~CPU() noexcept = default;

    // Non-copyable (owns state)
    CPU(const CPU&) = delete;
    CPU& operator=(const CPU&) = delete;

    // === Configuration ===

    void SetPreInstructionCallback(PreInstructionCallback cb) noexcept;
    void SetPostInstructionCallback(PostInstructionCallback cb) noexcept;
    void SetAPICallCallback(APICallCallback cb) noexcept;
    void SetSyscallCallback(SyscallCallback cb) noexcept;
    void SetInterruptCallback(InterruptCallback cb) noexcept;

    // Add a breakpoint at a guest address
    void AddBreakpoint(GuestAddress addr) noexcept;
    void RemoveBreakpoint(GuestAddress addr) noexcept;
    void ClearBreakpoints() noexcept;

    // Set the API hook address range (addresses that trigger API call callback)
    void SetAPIHookRange(GuestAddress base, GuestSize size) noexcept;

    // === Execution ===

    // Execute instructions until a stop condition.
    [[nodiscard]] ExecutionResult Execute(
        VirtualMemory& memory,
        MemoryTracker* tracker,
        const EmulationConfig& config) noexcept;

    // Execute exactly one instruction.
    [[nodiscard]] ErrorCode ExecuteSingle(
        VirtualMemory& memory,
        MemoryTracker* tracker) noexcept;

    // Request abort (can be called from another thread)
    void RequestAbort() noexcept;

    // === State Access ===

    [[nodiscard]] CPUState& State() noexcept { return m_state; }
    [[nodiscard]] const CPUState& State() const noexcept { return m_state; }

    void Reset() noexcept;
    void Reset32() noexcept;
    void Reset64() noexcept;

private:
    CPUState m_state;
    InstructionDecoder m_decoder;

    // Callbacks
    PreInstructionCallback  m_preCallback;
    PostInstructionCallback m_postCallback;
    APICallCallback         m_apiCallback;
    SyscallCallback         m_syscallCallback;
    InterruptCallback       m_interruptCallback;

    // Breakpoints
    std::unordered_set<GuestAddress> m_breakpoints;

    // API hook address range
    GuestAddress m_apiHookBase = 0;
    GuestSize    m_apiHookSize = 0;

    // Abort flag (cross-thread safe)
    std::atomic<bool> m_abortRequested{ false };

    // Instruction fetch buffer (avoid repeated memory reads)
    alignas(16) uint8_t m_fetchBuffer[Encoding::kMaxInstructionLength]{};

    // === Execution internals ===

    // Execute a single decoded instruction (THE BIG SWITCH)
    [[nodiscard]] ErrorCode DispatchInstruction(
        const DecodedInstruction& inst,
        VirtualMemory& memory,
        MemoryTracker* tracker) noexcept;

    // Check if address is in API hook range
    [[nodiscard]] bool IsAPIHookAddress(GuestAddress addr) const noexcept;

    // === Instruction handler groups ===
    // Each returns ErrorCode::Success on success, or an error.

    ErrorCode ExecuteALU(const DecodedInstruction& inst, VirtualMemory& mem) noexcept;
    ErrorCode ExecuteDataTransfer(const DecodedInstruction& inst, VirtualMemory& mem) noexcept;
    ErrorCode ExecuteControlFlow(const DecodedInstruction& inst, VirtualMemory& mem) noexcept;
    ErrorCode ExecuteLogic(const DecodedInstruction& inst, VirtualMemory& mem) noexcept;
    ErrorCode ExecuteShiftRotate(const DecodedInstruction& inst, VirtualMemory& mem) noexcept;
    ErrorCode ExecuteString(const DecodedInstruction& inst, VirtualMemory& mem) noexcept;
    ErrorCode ExecuteBitManip(const DecodedInstruction& inst, VirtualMemory& mem) noexcept;
    ErrorCode ExecuteFlag(const DecodedInstruction& inst) noexcept;
    ErrorCode ExecuteStack(const DecodedInstruction& inst, VirtualMemory& mem) noexcept;
    ErrorCode ExecuteSystem(const DecodedInstruction& inst, VirtualMemory& mem) noexcept;
    ErrorCode ExecuteSSE2(const DecodedInstruction& inst, VirtualMemory& mem) noexcept;
    ErrorCode ExecuteSSE4(const DecodedInstruction& inst, VirtualMemory& mem) noexcept;
    ErrorCode ExecuteAESNI(const DecodedInstruction& inst, VirtualMemory& mem) noexcept;
    ErrorCode ExecuteAVX2(const DecodedInstruction& inst, VirtualMemory& mem) noexcept;
    ErrorCode ExecuteFPU(const DecodedInstruction& inst, VirtualMemory& mem) noexcept;

    // === Operand read/write helpers ===

    // Read the value of an operand (register, memory, or immediate)
    [[nodiscard]] ErrorCode ReadOperand(
        const DecodedOperand& op,
        const DecodedInstruction& inst,
        VirtualMemory& mem,
        uint64_t& value) noexcept;

    // Write a value to an operand (register or memory)
    [[nodiscard]] ErrorCode WriteOperand(
        const DecodedOperand& op,
        const DecodedInstruction& inst,
        VirtualMemory& mem,
        uint64_t value) noexcept;

    // Calculate effective address for a memory operand
    [[nodiscard]] GuestAddress CalculateEffectiveAddress(
        const DecodedOperand& op,
        const DecodedInstruction& inst) const noexcept;

    // Push/Pop stack helpers
    [[nodiscard]] ErrorCode StackPush(VirtualMemory& mem, uint64_t value, OperandSize size) noexcept;
    [[nodiscard]] ErrorCode StackPop(VirtualMemory& mem, uint64_t& value, OperandSize size) noexcept;

    // Mask value to operand size
    [[nodiscard]] static uint64_t MaskToSize(uint64_t value, OperandSize size) noexcept;
    [[nodiscard]] static uint64_t SignExtendToSize(uint64_t value, OperandSize fromSize, OperandSize toSize) noexcept;
};

} // namespace Phantom
