/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "CPU.hpp"
#include "../../Common/Constants.hpp"
#include "../../Common/Platform.hpp"
#include <chrono>
#include <cstring>

namespace Phantom {

// ============================================================================
// Constructor / Reset
// ============================================================================

CPU::CPU() noexcept {
    m_state.Reset64();
}

void CPU::Reset() noexcept    { m_state.Reset(); m_abortRequested.store(false, std::memory_order_relaxed); }
void CPU::Reset32() noexcept  { m_state.Reset32(); m_abortRequested.store(false, std::memory_order_relaxed); }
void CPU::Reset64() noexcept  { m_state.Reset64(); m_abortRequested.store(false, std::memory_order_relaxed); }

// ============================================================================
// Configuration
// ============================================================================

void CPU::SetPreInstructionCallback(PreInstructionCallback cb) noexcept   { m_preCallback = std::move(cb); }
void CPU::SetPostInstructionCallback(PostInstructionCallback cb) noexcept { m_postCallback = std::move(cb); }
void CPU::SetAPICallCallback(APICallCallback cb) noexcept                { m_apiCallback = std::move(cb); }
void CPU::SetSyscallCallback(SyscallCallback cb) noexcept                { m_syscallCallback = std::move(cb); }
void CPU::SetInterruptCallback(InterruptCallback cb) noexcept            { m_interruptCallback = std::move(cb); }

void CPU::AddBreakpoint(GuestAddress addr) noexcept    { m_breakpoints.insert(addr); }
void CPU::RemoveBreakpoint(GuestAddress addr) noexcept  { m_breakpoints.erase(addr); }
void CPU::ClearBreakpoints() noexcept                   { m_breakpoints.clear(); }

void CPU::SetAPIHookRange(GuestAddress base, GuestSize size) noexcept {
    m_apiHookBase = base;
    m_apiHookSize = size;
}

void CPU::RequestAbort() noexcept {
    m_abortRequested.store(true, std::memory_order_release);
}

// ============================================================================
// Main Execution Loop
// ============================================================================

ExecutionResult CPU::Execute(
    VirtualMemory& memory,
    MemoryTracker* tracker,
    const EmulationConfig& config) noexcept
{
    ExecutionResult result{};
    m_abortRequested.store(false, std::memory_order_relaxed);

    auto startTime = std::chrono::steady_clock::now();
    uint64_t maxInstr = config.maxInstructions;
    uint64_t maxAPI   = config.maxAPIcalls;

    while (true) {
        // === Check abort ===
        if (PHANTOM_UNLIKELY(m_abortRequested.load(std::memory_order_acquire))) {
            result.reason = StopReason::UserAborted;
            break;
        }

        // === Check instruction limit ===
        if (PHANTOM_UNLIKELY(m_state.instructionCount >= maxInstr)) {
            result.reason = StopReason::InstructionLimit;
            break;
        }

        // === Check time limit (every 4096 instructions to amortize cost) ===
        if (PHANTOM_UNLIKELY((m_state.instructionCount & 0xFFF) == 0)) {
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            if (elapsed >= config.maxWallTime) {
                result.reason = StopReason::TimeLimit;
                break;
            }

            // Check memory limit
            if (memory.GetAllocatedBytes() > config.maxGuestMemory) {
                result.reason = StopReason::MemoryLimit;
                break;
            }
        }

        // === Check breakpoint ===
        if (PHANTOM_UNLIKELY(!m_breakpoints.empty() && m_breakpoints.contains(m_state.rip))) {
            result.reason = StopReason::Breakpoint;
            break;
        }

        // === Check API hook ===
        if (PHANTOM_UNLIKELY(IsAPIHookAddress(m_state.rip))) {
            result.apiCallCount++;
            if (result.apiCallCount >= maxAPI) {
                result.reason = StopReason::APICallTrap;
                break;
            }
            if (m_apiCallback) {
                if (!m_apiCallback(m_state, memory, m_state.rip)) {
                    result.reason = StopReason::APICallTrap;
                    break;
                }
                // API callback handles RIP update (via RET emulation)
                continue;
            }
            // No API callback — treat as unknown API, return 0
            result.reason = StopReason::APICallTrap;
            break;
        }

        // === Fetch instruction bytes ===
        uint32_t bytesRead = 0;
        auto fetchErr = memory.FetchInstruction(
            m_state.rip, m_fetchBuffer, Encoding::kMaxInstructionLength, bytesRead);

        if (fetchErr != ErrorCode::Success) {
            result.reason = StopReason::AccessViolation;
            result.errorCode = fetchErr;
            result.faultAddress = m_state.rip;
            break;
        }

        // Track instruction fetch for W→X detection
        if (tracker) {
            tracker->RecordExecute(m_state.rip);
        }

        // === Decode ===
        DecodedInstruction inst;
        auto decodeErr = m_decoder.Decode(
            std::span<const uint8_t>(m_fetchBuffer, bytesRead),
            m_state.rip, m_state.mode, inst);

        if (decodeErr != ErrorCode::Success) {
            result.reason = StopReason::InvalidInstruction;
            result.errorCode = decodeErr;
            result.faultAddress = m_state.rip;
            break;
        }

        // === Pre-instruction callback ===
        if (m_preCallback) {
            if (!m_preCallback(m_state, inst)) {
                result.reason = StopReason::UserAborted;
                break;
            }
        }

        // === Execute ===
        result.lastRIP = m_state.rip;

        auto execErr = DispatchInstruction(inst, memory, tracker);
        if (execErr != ErrorCode::Success) {
            // Map error to stop reason
            switch (execErr) {
                case ErrorCode::DivideByZero:
                    result.reason = StopReason::DivideByZero;
                    break;
                case ErrorCode::StackOverflow:
                    result.reason = StopReason::StackOverflow;
                    break;
                case ErrorCode::AccessViolationRead:
                case ErrorCode::AccessViolationWrite:
                case ErrorCode::AccessViolationExec:
                case ErrorCode::PageNotPresent:
                    result.reason = StopReason::AccessViolation;
                    break;
                case ErrorCode::InvalidSystemCall:
                    result.reason = StopReason::Syscall;
                    break;
                default:
                    result.reason = StopReason::Crashed;
                    break;
            }
            result.errorCode = execErr;
            result.faultAddress = m_state.rip;
            break;
        }

        // === Post-instruction callback ===
        if (m_postCallback) {
            m_postCallback(m_state, inst);
        }

        // === Update counters ===
        m_state.instructionCount++;
        m_state.tsc += m_state.tscIncrement;
    }

    result.instructionsExecuted = m_state.instructionCount;
    return result;
}

// ============================================================================
// Single Instruction Execution
// ============================================================================

ErrorCode CPU::ExecuteSingle(VirtualMemory& memory, MemoryTracker* tracker) noexcept {
    uint32_t bytesRead = 0;
    auto fetchErr = memory.FetchInstruction(
        m_state.rip, m_fetchBuffer, Encoding::kMaxInstructionLength, bytesRead);
    if (fetchErr != ErrorCode::Success) return fetchErr;

    if (tracker) tracker->RecordExecute(m_state.rip);

    DecodedInstruction inst;
    auto decodeErr = m_decoder.Decode(
        std::span<const uint8_t>(m_fetchBuffer, bytesRead),
        m_state.rip, m_state.mode, inst);
    if (decodeErr != ErrorCode::Success) return decodeErr;

    auto execErr = DispatchInstruction(inst, memory, tracker);
    if (execErr == ErrorCode::Success) {
        m_state.instructionCount++;
        m_state.tsc += m_state.tscIncrement;
    }
    return execErr;
}

// ============================================================================
// Instruction Dispatch
// ============================================================================

ErrorCode CPU::DispatchInstruction(
    const DecodedInstruction& inst,
    VirtualMemory& memory,
    MemoryTracker* tracker) noexcept
{
    // Track memory writes for W→X
    // (individual instruction handlers call WriteOperand which calls memory.Write)

    const bool isEVEX = inst.prefixes.hasEVEX;

    if (inst.opcodeMap == OpcodeMap::OneByte) {
        uint8_t op = inst.opcode;

        // === NOP family ===
        if (op == 0x90) {
            m_state.AdvanceRIP(inst.length);
            return ErrorCode::Success;
        }

        // === ALU operations (ADD, OR, ADC, SBB, AND, SUB, XOR, CMP) ===
        // Opcodes 0x00-0x3F: groups of 8 opcodes each
        if (op <= 0x3F) {
            auto err = ExecuteALU(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === INC/DEC (32-bit mode: 0x40-0x4F) ===
        if (!m_state.Is64Bit() && op >= 0x40 && op <= 0x4F) {
            auto err = ExecuteALU(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === PUSH/POP register ===
        if ((op >= 0x50 && op <= 0x57) || (op >= 0x58 && op <= 0x5F)) {
            auto err = ExecuteStack(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === PUSH imm ===
        if (op == 0x68 || op == 0x6A) {
            auto err = ExecuteStack(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === Jcc short (0x70-0x7F) ===
        if (op >= 0x70 && op <= 0x7F) {
            return ExecuteControlFlow(inst, memory);
        }

        // === ALU group (0x80-0x83) ===
        if (op >= 0x80 && op <= 0x83) {
            auto err = ExecuteALU(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === TEST (0x84, 0x85) ===
        if (op == 0x84 || op == 0x85) {
            auto err = ExecuteLogic(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === XCHG (0x86, 0x87) ===
        if (op == 0x86 || op == 0x87) {
            auto err = ExecuteDataTransfer(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === MOV (0x88-0x8B, 0x8C, 0x8E, 0xA0-0xA3, 0xB0-0xBF, 0xC6, 0xC7) ===
        if ((op >= 0x88 && op <= 0x8B) || op == 0x8C || op == 0x8E ||
            (op >= 0xA0 && op <= 0xA3) || (op >= 0xB0 && op <= 0xBF) ||
            op == 0xC6 || op == 0xC7) {
            auto err = ExecuteDataTransfer(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === LEA (0x8D) ===
        if (op == 0x8D) {
            auto err = ExecuteDataTransfer(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === NOP/XCHG eAX (0x90-0x97) ===
        if (op >= 0x91 && op <= 0x97) {
            auto err = ExecuteDataTransfer(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === CBW/CWDE/CDQE (0x98), CWD/CDQ/CQO (0x99) ===
        if (op == 0x98 || op == 0x99) {
            auto err = ExecuteDataTransfer(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === PUSHF (0x9C) ===
        if (op == 0x9C) {
            OperandSize pushSz = m_state.Is64Bit() ? OperandSize::Size64 : inst.operandSize;
            uint64_t flags = m_state.eflags.Raw();
            flags &= ~(3ULL << 12); // Clear IOPL
            flags &= ~(1ULL << 17); // Clear VM
            auto err = StackPush(memory, flags, pushSz);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === POPF (0x9D) ===
        if (op == 0x9D) {
            OperandSize popSz = m_state.Is64Bit() ? OperandSize::Size64 : inst.operandSize;
            uint64_t flags = 0;
            auto err = StackPop(memory, flags, popSz);
            if (err != ErrorCode::Success) return err;
            m_state.eflags.SetRaw(flags);
            m_state.AdvanceRIP(inst.length);
            return ErrorCode::Success;
        }

        // === SAHF/LAHF (0x9E, 0x9F) ===
        if (op == 0x9E || op == 0x9F) {
            auto err = ExecuteFlag(inst);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === TEST AL/eAX, imm (0xA8, 0xA9) ===
        if (op == 0xA8 || op == 0xA9) {
            auto err = ExecuteLogic(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === String ops (0xA4-0xA7, 0xAA-0xAF) ===
        if ((op >= 0xA4 && op <= 0xA7) || (op >= 0xAA && op <= 0xAF)) {
            auto err = ExecuteString(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === Shift/Rotate group (0xC0, 0xC1, 0xD0-0xD3) ===
        if (op == 0xC0 || op == 0xC1 || (op >= 0xD0 && op <= 0xD3)) {
            auto err = ExecuteShiftRotate(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === RET (0xC2, 0xC3) ===
        if (op == 0xC2 || op == 0xC3) {
            return ExecuteControlFlow(inst, memory);
        }

        // === ENTER/LEAVE (0xC8, 0xC9) ===
        if (op == 0xC8 || op == 0xC9) {
            auto err = ExecuteStack(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === INT3 (0xCC) ===
        if (op == 0xCC) {
            if (m_interruptCallback && m_interruptCallback(m_state, memory, 3)) {
                m_state.AdvanceRIP(inst.length);
                return ErrorCode::Success;
            }
            return ErrorCode::InvalidSystemCall;
        }

        // === INT imm8 (0xCD) ===
        if (op == 0xCD) {
            uint8_t vector = static_cast<uint8_t>(inst.immediate & 0xFF);
            if (m_interruptCallback && m_interruptCallback(m_state, memory, vector)) {
                m_state.AdvanceRIP(inst.length);
                return ErrorCode::Success;
            }
            return ErrorCode::InvalidSystemCall;
        }

        // === CALL rel32 (0xE8) ===
        if (op == 0xE8) {
            return ExecuteControlFlow(inst, memory);
        }

        // === JMP rel32 (0xE9), JMP rel8 (0xEB) ===
        if (op == 0xE9 || op == 0xEB) {
            return ExecuteControlFlow(inst, memory);
        }

        // === LOOPcc / JCXZ (0xE0-0xE3) ===
        if (op >= 0xE0 && op <= 0xE3) {
            return ExecuteControlFlow(inst, memory);
        }

        // === Flag ops (0xF5 CMC, 0xF8 CLC, 0xF9 STC, 0xFA CLI, 0xFB STI, 0xFC CLD, 0xFD STD) ===
        if (op == 0xF5 || (op >= 0xF8 && op <= 0xFD)) {
            auto err = ExecuteFlag(inst);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === Unary group (0xF6, 0xF7): TEST/NOT/NEG/MUL/IMUL/DIV/IDIV ===
        if (op == 0xF6 || op == 0xF7) {
            auto err = ExecuteALU(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === INC/DEC/CALL/JMP/PUSH group (0xFE, 0xFF) ===
        if (op == 0xFE || op == 0xFF) {
            uint8_t ext = inst.opcodeExt;
            if (ext <= 1) {
                // INC/DEC
                auto err = ExecuteALU(inst, memory);
                if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
                return err;
            }
            if (ext == 2 || ext == 4) {
                // CALL/JMP r/m
                return ExecuteControlFlow(inst, memory);
            }
            if (ext == 6) {
                // PUSH r/m
                auto err = ExecuteStack(inst, memory);
                if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
                return err;
            }
            return ErrorCode::UnsupportedOpcode;
        }

        // === HLT (0xF4) ===
        if (op == 0xF4) {
            return ErrorCode::PrivilegedInstruction;
        }

        // === IMUL (0x69, 0x6B) ===
        if (op == 0x69 || op == 0x6B) {
            auto err = ExecuteALU(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === MOVSXD (0x63 in 64-bit) ===
        if (op == 0x63 && m_state.Is64Bit()) {
            auto err = ExecuteDataTransfer(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

    } else if (inst.opcodeMap == OpcodeMap::TwoByte) {
        uint8_t op = inst.opcode;

        if (isEVEX) {
            auto err = ExecuteSSE2(inst, memory);
            if (err == ErrorCode::Success) {
                m_state.AdvanceRIP(inst.length);
            }
            return err;
        }

        // === Jcc near (0x80-0x8F) ===
        if (op >= 0x80 && op <= 0x8F) {
            return ExecuteControlFlow(inst, memory);
        }

        // === SETcc (0x90-0x9F) ===
        if (op >= 0x90 && op <= 0x9F) {
            return ExecuteControlFlow(inst, memory);
        }

        // === MOVZX (0xB6, 0xB7), MOVSX (0xBE, 0xBF) ===
        if (op == 0xB6 || op == 0xB7 || op == 0xBE || op == 0xBF) {
            auto err = ExecuteDataTransfer(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === BSF (0xBC), BSR (0xBD) ===
        if (op == 0xBC || op == 0xBD) {
            auto err = ExecuteBitManip(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === BT/BTS/BTR/BTC (0xA3, 0xAB, 0xB3, 0xBB, 0xBA) ===
        if (op == 0xA3 || op == 0xAB || op == 0xB3 || op == 0xBB || op == 0xBA) {
            auto err = ExecuteBitManip(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === IMUL r, r/m (0xAF) ===
        if (op == 0xAF) {
            auto err = ExecuteALU(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === XADD (0xC0, 0xC1) ===
        if (op == 0xC0 || op == 0xC1) {
            auto err = ExecuteALU(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === BSWAP (0xC8-0xCF) ===
        if (op >= 0xC8 && op <= 0xCF) {
            auto err = ExecuteDataTransfer(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === CMOVcc (0x40-0x4F) ===
        if (op >= 0x40 && op <= 0x4F) {
            auto err = ExecuteDataTransfer(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === SYSCALL (0x05) ===
        if (op == 0x05) {
            if (m_syscallCallback && m_syscallCallback(m_state, memory)) {
                m_state.AdvanceRIP(inst.length);
                return ErrorCode::Success;
            }
            return ErrorCode::InvalidSystemCall;
        }

        // === CPUID (0xA2) ===
        if (op == 0xA2) {
            auto err = ExecuteSystem(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === RDTSC (0x31) ===
        if (op == 0x31) {
            auto err = ExecuteSystem(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === UD2 (0x0B) ===
        if (op == 0x0B) {
            return ErrorCode::InvalidOpcode;
        }

        // === SHLD/SHRD (0xA4, 0xA5, 0xAC, 0xAD) ===
        if (op == 0xA4 || op == 0xA5 || op == 0xAC || op == 0xAD) {
            auto err = ExecuteShiftRotate(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === NOP variants (0x1F) ===
        if (op == 0x1F) {
            m_state.AdvanceRIP(inst.length);
            return ErrorCode::Success;
        }

        // === CMPXCHG (0xB0, 0xB1) ===
        if (op == 0xB0 || op == 0xB1) {
            auto err = ExecuteALU(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === POPCNT (F3 0F B8) ===
        if (op == 0xB8 && inst.prefixes.hasRep) {
            auto err = ExecuteBitManip(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === SYSENTER (0F 34) — 32-bit syscall entry ===
        if (op == 0x34) {
            if (m_syscallCallback && m_syscallCallback(m_state, memory)) {
                m_state.AdvanceRIP(inst.length);
                return ErrorCode::Success;
            }
            return ErrorCode::InvalidSystemCall;
        }

        // === SSE/SSE2 (TwoByte map fallthrough) ===
        // Covers: MOVUPS/MOVAPS/MOVSS/MOVSD, XORPS/PXOR, packed arithmetic,
        // compares, shuffles, conversions, and all other 0F-prefixed SSE ops.
        // EVEX reuses the 0F opcode map as VEX. Full AVX-512 execution still
        // requires a 512-bit ZMM/opmask register file; for now we route EVEX
        // forms through the existing vector handlers so the decoder can surface
        // AVX-512 usage to higher-level anti-analysis heuristics.
        {
            auto err = ExecuteSSE2(inst, memory);
            if (err == ErrorCode::Success) {
                m_state.AdvanceRIP(inst.length);
                return ErrorCode::Success;
            }
            // If SSE2 doesn't handle it, fall through to UnsupportedOpcode
        }
    }

    // ====================================================================
    // ThreeByte38 map (0F 38 xx) — SSE4.1/4.2 + AES-NI
    // ====================================================================

    if (inst.opcodeMap == OpcodeMap::ThreeByte38) {
        uint8_t op = inst.opcode;

        if (isEVEX) {
            auto err = ExecuteSSE4(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // AES-NI instructions: 0xDB-0xDF with 66 prefix
        if (op >= 0xDB && op <= 0xDF && inst.prefixes.hasOpSizeOverride) {
            auto err = ExecuteAESNI(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // SSE4 handles everything else in this map, including EVEX forms
        // that share the 0F 38 opcode map with VEX encodings.
        auto err = ExecuteSSE4(inst, memory);
        if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
        return err;
    }

    // ====================================================================
    // ThreeByte3A map (0F 3A xx) — SSE4.1/4.2 + PCLMULQDQ + AESKEYGENASSIST
    // ====================================================================

    if (inst.opcodeMap == OpcodeMap::ThreeByte3A) {
        uint8_t op = inst.opcode;

        if (isEVEX) {
            auto err = ExecuteSSE4(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // AES-NI: PCLMULQDQ (0x44) and AESKEYGENASSIST (0xDF) with 66 prefix
        if ((op == 0x44 || op == 0xDF) && inst.prefixes.hasOpSizeOverride) {
            auto err = ExecuteAESNI(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // SSE4 handles everything else in this map, including EVEX forms
        // that share the 0F 3A opcode map with VEX encodings.
        auto err = ExecuteSSE4(inst, memory);
        if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
        return err;
    }

    // FPU (0xD8-0xDF)
    if (inst.opcodeMap == OpcodeMap::OneByte && inst.opcode >= 0xD8 && inst.opcode <= 0xDF) {
        auto err = ExecuteFPU(inst, memory);
        if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
        return err;
    }

    // If we reach here, the opcode is not implemented
    return ErrorCode::UnsupportedOpcode;
}

// ============================================================================
// API Hook Check
// ============================================================================

bool CPU::IsAPIHookAddress(GuestAddress addr) const noexcept {
    if (m_apiHookSize == 0) return false;
    // Overflow-safe range check: avoid (base + size) wrapping
    return addr >= m_apiHookBase && (addr - m_apiHookBase) < m_apiHookSize;
}

// ============================================================================
// Operand Helpers
// ============================================================================

ErrorCode CPU::ReadOperand(
    const DecodedOperand& op,
    const DecodedInstruction& inst,
    VirtualMemory& mem,
    uint64_t& value) noexcept
{
    switch (op.type) {
        case OperandType::Register: {
            if (op.reg.regType == RegType::GPR) {
                if (op.reg.isHighByte) {
                    value = m_state.GetReg8High(op.reg.regIndex);
                } else {
                    value = m_state.GetRegBySize(
                        static_cast<GPR>(op.reg.regIndex), op.size);
                }
            } else if (op.reg.regType == RegType::Segment) {
                value = m_state.GetSegment(static_cast<SegReg>(op.reg.regIndex)).selector;
            }
            return ErrorCode::Success;
        }

        case OperandType::Memory: {
            GuestAddress addr = CalculateEffectiveAddress(op, inst);
            uint32_t size = static_cast<uint32_t>(op.size);
            return mem.Read(addr, &value, size);
        }

        case OperandType::Immediate: {
            value = op.imm.value;
            return ErrorCode::Success;
        }

        case OperandType::RelativeOffset: {
            value = static_cast<uint64_t>(op.rel.offset);
            return ErrorCode::Success;
        }

        default:
            return ErrorCode::InvalidOperandSize;
    }
}

ErrorCode CPU::WriteOperand(
    const DecodedOperand& op,
    const DecodedInstruction& inst,
    VirtualMemory& mem,
    uint64_t value) noexcept
{
    switch (op.type) {
        case OperandType::Register: {
            if (op.reg.regType == RegType::GPR) {
                if (op.reg.isHighByte) {
                    m_state.SetReg8High(op.reg.regIndex, static_cast<uint8_t>(value));
                } else {
                    m_state.SetRegBySize(
                        static_cast<GPR>(op.reg.regIndex), value, op.size);
                }
            } else if (op.reg.regType == RegType::Segment) {
                m_state.SetSegmentSelector(static_cast<SegReg>(op.reg.regIndex),
                                           static_cast<uint16_t>(value));
            }
            return ErrorCode::Success;
        }

        case OperandType::Memory: {
            GuestAddress addr = CalculateEffectiveAddress(op, inst);
            uint32_t size = static_cast<uint32_t>(op.size);
            return mem.Write(addr, &value, size);
        }

        default:
            return ErrorCode::InvalidOperandSize;
    }
}

GuestAddress CPU::CalculateEffectiveAddress(
    const DecodedOperand& op,
    const DecodedInstruction& inst) const noexcept
{
    if (op.type != OperandType::Memory) return kGuestInvalid;

    uint64_t addr = 0;

    if (op.mem.ripRelative) {
        // RIP-relative: addr = RIP_next + displacement
        addr = inst.NextRIP() + static_cast<uint64_t>(op.mem.displacement);
    } else {
        // base + index*scale + displacement
        if (op.mem.hasBase) {
            addr = m_state.GetReg64(static_cast<GPR>(op.mem.baseReg));
        }
        if (op.mem.hasIndex) {
            addr += m_state.GetReg64(static_cast<GPR>(op.mem.indexReg)) * op.mem.scale;
        }
        addr += static_cast<uint64_t>(op.mem.displacement);
    }

    // In 32-bit mode, truncate to 32 bits
    if (inst.addressSize == AddressSize::Addr32) {
        addr &= 0xFFFFFFFF;
    }

    // Add segment base (significant for FS/GS in user mode)
    if (op.mem.segment == SegReg::FS || op.mem.segment == SegReg::GS) {
        addr += m_state.GetSegment(op.mem.segment).base;
    }

    return addr;
}

// ============================================================================
// Stack Helpers
// ============================================================================

ErrorCode CPU::StackPush(VirtualMemory& mem, uint64_t value, OperandSize size) noexcept {
    uint32_t bytes = static_cast<uint32_t>(size);
    uint64_t rsp = m_state.RSP() - bytes;
    m_state.SetReg64(GPR::RSP, rsp);
    return mem.Write(rsp, &value, bytes);
}

ErrorCode CPU::StackPop(VirtualMemory& mem, uint64_t& value, OperandSize size) noexcept {
    uint32_t bytes = static_cast<uint32_t>(size);
    value = 0;
    auto err = mem.Read(m_state.RSP(), &value, bytes);
    if (err != ErrorCode::Success) return err;
    m_state.SetReg64(GPR::RSP, m_state.RSP() + bytes);
    return ErrorCode::Success;
}

uint64_t CPU::MaskToSize(uint64_t value, OperandSize size) noexcept {
    switch (size) {
        case OperandSize::Size8:  return value & 0xFF;
        case OperandSize::Size16: return value & 0xFFFF;
        case OperandSize::Size32: return value & 0xFFFFFFFF;
        case OperandSize::Size64: return value;
    }
    return value;
}

uint64_t CPU::SignExtendToSize(uint64_t value, OperandSize fromSize, OperandSize toSize) noexcept {
    // First, sign-extend to 64-bit
    int64_t signedVal;
    switch (fromSize) {
        case OperandSize::Size8:  signedVal = static_cast<int64_t>(static_cast<int8_t>(value)); break;
        case OperandSize::Size16: signedVal = static_cast<int64_t>(static_cast<int16_t>(value)); break;
        case OperandSize::Size32: signedVal = static_cast<int64_t>(static_cast<int32_t>(value)); break;
        case OperandSize::Size64: signedVal = static_cast<int64_t>(value); break;
        default: signedVal = static_cast<int64_t>(value); break;
    }
    // Then mask to target size
    return MaskToSize(static_cast<uint64_t>(signedVal), toSize);
}

// ============================================================================
// Handlers implemented in Executor/ translation units:
// - Executor/ArithmeticOps.cpp → ExecuteALU
// - Executor/LogicOps.cpp      → ExecuteLogic
// - Executor/DataTransfer.cpp  → ExecuteDataTransfer
// - Executor/ControlFlow.cpp   → ExecuteControlFlow
// - Executor/ShiftRotate.cpp   → ExecuteShiftRotate
// - Executor/StringOps.cpp     → ExecuteString
// - Executor/BitManip.cpp      → ExecuteBitManip
// - Executor/StackOps.cpp      → ExecuteStack
// - Executor/FlagOps.cpp       → ExecuteFlag
// - Executor/SystemOps.cpp     → ExecuteSystem
// - Executor/SSE2Ops.cpp       → ExecuteSSE2
// - Executor/SSE4Ops.cpp       → ExecuteSSE4
// - Executor/AESNIOps.cpp      → ExecuteAESNI
// - Executor/FPUOps.cpp        → ExecuteFPU
// ============================================================================

} // namespace Phantom
