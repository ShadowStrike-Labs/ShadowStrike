/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "CPU.hpp"
#include "ExceptionDispatcher.hpp"
#include "HardwareBreakpoints.hpp"
#include "../../Common/Constants.hpp"
#include "../../Common/Platform.hpp"
#include <chrono>
#include <cstring>
#include <limits>
#include <new>

namespace Phantom {

namespace {

[[nodiscard]] bool IsSupportedOperandSize(OperandSize size) noexcept {
    switch (size) {
        case OperandSize::Size8:
        case OperandSize::Size16:
        case OperandSize::Size32:
        case OperandSize::Size64:
            return true;
    }
    return false;
}

[[nodiscard]] uint32_t OperandByteWidth(OperandSize size) noexcept {
    switch (size) {
        case OperandSize::Size8:  return 1;
        case OperandSize::Size16: return 2;
        case OperandSize::Size32: return 4;
        case OperandSize::Size64: return 8;
    }
    return 0;
}

[[nodiscard]] bool IsValidGprIndex(uint8_t index) noexcept {
    return index < static_cast<uint8_t>(GPR::Count);
}

[[nodiscard]] bool IsValidSegmentIndex(uint8_t index) noexcept {
    return index < static_cast<uint8_t>(SegReg::Count);
}

[[nodiscard]] bool AddUnsigned(uint64_t lhs, uint64_t rhs, uint64_t& result) noexcept {
    if ((std::numeric_limits<uint64_t>::max)() - lhs < rhs) {
        return false;
    }
    result = lhs + rhs;
    return true;
}

[[nodiscard]] bool AddSigned(uint64_t lhs, int64_t rhs, uint64_t& result) noexcept {
    if (rhs >= 0) {
        return AddUnsigned(lhs, static_cast<uint64_t>(rhs), result);
    }

    const uint64_t magnitude = static_cast<uint64_t>(-(rhs + 1)) + 1;
    if (lhs < magnitude) {
        return false;
    }
    result = lhs - magnitude;
    return true;
}

[[nodiscard]] bool ScaleIndex(uint64_t value, uint8_t scale, uint64_t& result) noexcept {
    if (scale != 1 && scale != 2 && scale != 4 && scale != 8) {
        return false;
    }
    if (value > (std::numeric_limits<uint64_t>::max)() / scale) {
        return false;
    }
    result = value * scale;
    return true;
}

void AddSaturating(uint64_t& target, uint64_t increment) noexcept {
    if ((std::numeric_limits<uint64_t>::max)() - target < increment) {
        target = (std::numeric_limits<uint64_t>::max)();
        return;
    }
    target += increment;
}

[[nodiscard]] uint64_t MulSaturating(uint64_t lhs, uint64_t rhs) noexcept {
    if (lhs != 0 && rhs > (std::numeric_limits<uint64_t>::max)() / lhs) {
        return (std::numeric_limits<uint64_t>::max)();
    }
    return lhs * rhs;
}

} // namespace

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
void CPU::SetExceptionDispatcher(ExceptionDispatcher* dispatcher) noexcept { m_exceptionDispatcher = dispatcher; }
void CPU::SetHardwareBreakpoints(HardwareBreakpoints* hwbp) noexcept { m_hwBreakpoints = hwbp; }

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
// JIT Control
// ============================================================================

void CPU::EnableJIT(JITStrategy strategy, uint32_t cacheSize, uint32_t hotThreshold) noexcept {
    if (m_jit.Initialize(cacheSize)) {
        m_jit.SetStrategy(strategy);
        m_jitHotThreshold = hotThreshold;
        m_jitEnabled = true;
    }
}

void CPU::DisableJIT() noexcept {
    m_jitEnabled = false;
    m_jit.Shutdown();
    m_blockProfile.clear();
}

const JITCompiler& CPU::GetJIT() const noexcept {
    return m_jit;
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

    // === JIT initialization from config ===
    if (config.enableJIT && !m_jitEnabled) {
        EnableJIT(config.jitStrategy, config.jitCodeCacheSize, config.jitHotThreshold);
    } else if (!config.enableJIT && m_jitEnabled) {
        DisableJIT();
    }

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

        // === Check software breakpoint ===
        if (PHANTOM_UNLIKELY(!m_breakpoints.empty() && m_breakpoints.contains(m_state.rip))) {
            result.reason = StopReason::Breakpoint;
            break;
        }

        // === Check hardware breakpoints (DR0-DR3 execute breakpoints) ===
        // This is the hot path for anti-debug detection — malware that sets
        // hardware breakpoints to detect analysis tools triggers DR6/INT1.
        if (PHANTOM_UNLIKELY(m_hwBreakpoints && m_hwBreakpoints->HasActiveBreakpoints())) {
            if (m_hwBreakpoints->CheckExecuteBreakpoint(m_state.rip)) {
                // Hardware execute breakpoint fired — generate INT1 (#DB).
                // Route through the interrupt callback so the ExceptionDispatcher
                // can dispatch to VEH/SEH handlers if registered by the sample.
                if (m_interruptCallback) {
                    if (!m_interruptCallback(m_state, memory, 1)) {
                        result.reason = StopReason::Breakpoint;
                        break;
                    }
                    continue;
                }
                result.reason = StopReason::Breakpoint;
                break;
            }
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

        // === JIT Fast Path ===
        // If JIT is enabled, try the code cache first. On cache hit,
        // execute the compiled native block and skip the interpreter for
        // all instructions in that block. Breakpoints, API hooks, and
        // abort checks above are always evaluated first — compiled blocks
        // are only reachable for addresses that passed all those guards.
        if (m_jitEnabled) {
            bool profileCurrentRip = true;
            CompiledBlock* block = m_jit.Lookup(m_state.rip);
            if (block && block->isValid) {
                uint32_t instrExecuted = m_jit.Execute(*block, m_state, memory);
                if (instrExecuted == 0) {
                    // Failed-closed JIT blocks are invalidated by JITCompiler;
                    // interpret the same RIP in this iteration to preserve
                    // precise fault reporting and avoid zero-progress loops.
                    profileCurrentRip = false;
                } else {
                    AddSaturating(m_state.instructionCount, instrExecuted);
                    AddSaturating(m_state.tsc, MulSaturating(instrExecuted, m_state.tscIncrement));
                    result.instructionsExecuted = m_state.instructionCount;
                    result.lastRIP = m_state.rip;

                    if (PHANTOM_UNLIKELY(m_state.instructionCount >= maxInstr)) {
                        result.reason = StopReason::InstructionLimit;
                        break;
                    }

                    continue; // Skip interpreter for this block
                }
            }

            // Track block execution count for profiling.
            // Only allocate a new entry if the map hasn't hit the cap —
            // this prevents unbounded growth from polymorphic code.
            if (profileCurrentRip) {
                auto profileIt = m_blockProfile.find(m_state.rip);
                if (profileIt != m_blockProfile.end()) {
                    if (profileIt->second < (std::numeric_limits<uint32_t>::max)()) {
                        ++profileIt->second;
                    }
                } else if (m_blockProfile.size() < kMaxBlockProfileEntries) {
                    try {
                        m_blockProfile.emplace(m_state.rip, 1u);
                    } catch (const std::bad_alloc&) {
                        DisableJIT();
                    }
                }
            }
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
        if (bytesRead == 0) {
            result.reason = StopReason::InvalidInstruction;
            result.errorCode = ErrorCode::TruncatedInstruction;
            result.faultAddress = m_state.rip;
            break;
        }

        // Track instruction fetch for W→X detection
        if (tracker) {
            tracker->RecordExecute(m_state.rip);

            // Invalidate JIT cache for self-modifying code.
            // If this page was previously written and is now being executed,
            // any compiled blocks covering it are stale.
            if (m_jitEnabled && tracker->IsWriteExecuteTransition(PageBase(m_state.rip))) {
                m_jit.Invalidate(PageBase(m_state.rip), kPageSize);
            }
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
            // Attempt exception dispatch through SEH/VEH if available.
            // This models the Windows exception dispatch mechanism —
            // malware that uses VEH for anti-debug or SEH for control flow
            // will have its handlers analyzed before we decide to stop.
            if (m_exceptionDispatcher) {
                bool handled = m_exceptionDispatcher->DispatchFromError(
                    m_state, memory, execErr, m_state.rip);
                if (handled) {
                    // Exception was handled — continue execution.
                    // The dispatcher may have modified RIP to resume at
                    // a handler, or the heuristic indicates continuation.
                    m_state.instructionCount++;
                    m_state.tsc += m_state.tscIncrement;
                    continue;
                }
            }

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

        // === Hardware single-step (Trap Flag) processing ===
        // If the Trap Flag is set in EFLAGS, generate a #DB exception after
        // the instruction completes. This models x86 single-step behaviour
        // used by debuggers — and exploited by malware for anti-debug checks.
        if (PHANTOM_UNLIKELY(m_hwBreakpoints &&
                             m_hwBreakpoints->IsSingleStepActive(m_state.eflags))) {
            if (m_hwBreakpoints->ProcessSingleStep(m_state)) {
                if (m_interruptCallback) {
                    if (!m_interruptCallback(m_state, memory, 1)) {
                        result.reason = StopReason::Breakpoint;
                        break;
                    }
                }
            }
        }

        // === Update counters ===
        m_state.instructionCount++;
        m_state.tsc += m_state.tscIncrement;

        // === JIT Compilation Check ===
        // After successful interpretation, check if the basic block at the
        // starting RIP has been interpreted enough times to warrant compilation.
        // We only compile after jitHotThreshold interpretations to avoid
        // wasting cycles compiling cold or one-shot code.
        if (m_jitEnabled) {
            auto profIt = m_blockProfile.find(result.lastRIP);
            if (profIt != m_blockProfile.end() && profIt->second == m_jitHotThreshold) {
                (void)m_jit.CompileBlock(result.lastRIP, &inst, 1);
            }
        }
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
    (void)tracker;
    // Track memory writes for W→X
    // (individual instruction handlers call WriteOperand which calls memory.Write)
    if (inst.length == 0 || inst.NextRIP() == kGuestInvalid) {
        return ErrorCode::TruncatedInstruction;
    }

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
            auto err = ExecuteAVX512(inst, memory);
            if (err == ErrorCode::Success) {
                m_state.AdvanceRIP(inst.length);
            }
            return err;
        }

        // === VEX-encoded AVX/AVX2 instructions ===
        // Route VEX-prefixed instructions to the AVX2 executor before
        // falling through to legacy SSE. ExecuteAVX2 handles both
        // VEX.L=1 (256-bit) and VEX.L=0 (128-bit with upper zeroing).
        if (inst.prefixes.hasVEX) {
            auto err = ExecuteAVX2(inst, memory);
            if (err == ErrorCode::Success) {
                m_state.AdvanceRIP(inst.length);
                return ErrorCode::Success;
            }
            // If AVX2 didn't handle it (UnimplementedOpcode), fall through
            // to SSE2 which may handle VEX.L=0 forms for legacy SSE ops
            if (err != ErrorCode::UnimplementedOpcode &&
                err != ErrorCode::UnsupportedOpcode) {
                return err;
            }
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

        // === RDRAND/RDSEED (0xC7 /6, /7 mod=3) ===
        if (op == 0xC7) {
            uint8_t ext = inst.opcodeExt;
            uint8_t mod = (inst.modrm >> 6) & 3;
            if ((ext == 6 || ext == 7) && mod == 3) {
                auto err = ExecuteRdRandSeed(inst, memory);
                if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
                return err;
            }
            // /1 = CMPXCHG8B/16B — route to ALU
            if (ext == 1) {
                auto err = ExecuteALU(inst, memory);
                if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
                return err;
            }
            return ErrorCode::UnsupportedOpcode;
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

        // === CET: ENDBR32/ENDBR64, RDSSPD/Q (F3 0F 1E) ===
        if (op == 0x1E) {
            auto err = ExecuteCET(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
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

        // === FENCE / CLFLUSH / XSAVE / XRSTOR (0F AE) ===
        // CET: INCSSPD/Q (F3 0F AE /5 mod=3), CLRSSBSY (F3 0F AE /6 mod!=3)
        if (op == 0xAE) {
            if (inst.prefixes.hasRep &&
                (inst.opcodeExt == 5 || inst.opcodeExt == 6)) {
                auto err = ExecuteCET(inst, memory);
                if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
                return err;
            }
            auto err = ExecuteSystem(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === System instructions: RDTSCP/XGETBV (0F 01), WRMSR (0F 30),
        //     RDMSR (0F 32), PREFETCH (0F 18) ===
        // CET: RSTORSSP (F3 0F 01 /5 mem), SETSSBSY (F3 0F 01 E8),
        //      SAVEPREVSSP (F3 0F 01 EA)
        if (op == 0x01 || op == 0x30 || op == 0x32 || op == 0x18) {
            if (op == 0x01 && inst.prefixes.hasRep) {
                auto err = ExecuteCET(inst, memory);
                if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
                return err;
            }
            auto err = ExecuteSystem(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
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
            auto err = ExecuteAVX512(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === VEX-encoded instructions in 0F 38 map ===
        if (inst.prefixes.hasVEX) {
            // AMX tile instructions (VEX.0F38 49/4B/5C/5E)
            if (op == 0x49 || op == 0x4B ||
                ((op == 0x5C || op == 0x5E) && !inst.prefixes.vexW)) {
                auto err = ExecuteAMX(inst, memory);
                if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
                return err;
            }

            // FMA3 (VEX.66.0F38 W0/W1, opcodes 96-9F, A6-AF, B6-BF)
            if (inst.prefixes.vexPP == 1 && op >= 0x96 && op <= 0xBF
                && (op & 0x0F) >= 6) {
                auto err = ExecuteFMA(inst, memory);
                if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
                return err;
            }

            // BMI1/BMI2 (VEX.0F38 F2-F7, various pp values)
            if (op >= 0xF2 && op <= 0xF7) {
                auto err = ExecuteBitManip(inst, memory);
                if (err == ErrorCode::Success) {
                    m_state.AdvanceRIP(inst.length);
                    return ErrorCode::Success;
                }
                if (err != ErrorCode::UnimplementedOpcode &&
                    err != ErrorCode::UnsupportedOpcode) {
                    return err;
                }
                // Fall through to AVX2 if BitManip doesn't handle it
            }

            // General AVX2 handler (VPSHUFB, VPMOVSXBW, VPERMD, etc.)
            auto err = ExecuteAVX2(inst, memory);
            if (err == ErrorCode::Success) {
                m_state.AdvanceRIP(inst.length);
                return ErrorCode::Success;
            }
            if (err != ErrorCode::UnimplementedOpcode &&
                err != ErrorCode::UnsupportedOpcode) {
                return err;
            }
        }

        // === Non-VEX: MOVBE (0F 38 F0/F1) — NOT F2-prefixed (that's CRC32) ===
        if ((op == 0xF0 || op == 0xF1) && !inst.prefixes.hasRepNE) {
            auto err = ExecuteDataTransfer(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === Non-VEX: SHA-NI (0F 38 C8-CD) ===
        if (op >= 0xC8 && op <= 0xCD && !inst.prefixes.hasOpSizeOverride) {
            auto err = ExecuteSHA(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === Non-VEX: ADX — ADCX (66 0F38 F6) / ADOX (F3 0F38 F6) ===
        if (op == 0xF6 && (inst.prefixes.hasOpSizeOverride || inst.prefixes.hasRep)) {
            auto err = ExecuteALU(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === CET: WRSSD/Q (NP 0F 38 F6), WRUSSD/Q (66 0F 38 F5) ===
        if ((op == 0xF6 && !inst.prefixes.hasOpSizeOverride && !inst.prefixes.hasRep &&
             !inst.prefixes.hasVEX) ||
            (op == 0xF5 && inst.prefixes.hasOpSizeOverride && !inst.prefixes.hasVEX)) {
            auto err = ExecuteCET(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // AES-NI instructions: 0xDB-0xDF with 66 prefix
        if (op >= 0xDB && op <= 0xDF && inst.prefixes.hasOpSizeOverride) {
            auto err = ExecuteAESNI(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // SSE4 handles everything else in this map
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
            auto err = ExecuteAVX512(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // === VEX-encoded instructions in 0F 3A map ===
        if (inst.prefixes.hasVEX) {
            // RORX (VEX.LZ.F2.0F3A F0, pp=3) — BMI2
            if (op == 0xF0 && inst.prefixes.vexPP == 3) {
                auto err = ExecuteBitManip(inst, memory);
                if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
                return err;
            }

            // F16C: VCVTPS2PH (VEX.66.0F3A.W0 1D) — Float16 conversion
            if (op == 0x1D && inst.prefixes.vexPP == 1) {
                auto err = ExecuteAVX2(inst, memory);
                if (err == ErrorCode::Success) {
                    m_state.AdvanceRIP(inst.length);
                    return ErrorCode::Success;
                }
                if (err != ErrorCode::UnimplementedOpcode &&
                    err != ErrorCode::UnsupportedOpcode) {
                    return err;
                }
            }

            // General AVX2 handler (VPERM2I128, VINSERTI128, etc.)
            auto err = ExecuteAVX2(inst, memory);
            if (err == ErrorCode::Success) {
                m_state.AdvanceRIP(inst.length);
                return ErrorCode::Success;
            }
            if (err != ErrorCode::UnimplementedOpcode &&
                err != ErrorCode::UnsupportedOpcode) {
                return err;
            }
        }

        // AES-NI: PCLMULQDQ (0x44) and AESKEYGENASSIST (0xDF) with 66 prefix
        if ((op == 0x44 || op == 0xDF) && inst.prefixes.hasOpSizeOverride) {
            auto err = ExecuteAESNI(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // SHA1RNDS4 (NP 0F 3A CC) — non-VEX, no 66 prefix
        if (op == 0xCC && !inst.prefixes.hasOpSizeOverride && !inst.prefixes.hasVEX) {
            auto err = ExecuteSHA(inst, memory);
            if (err == ErrorCode::Success) m_state.AdvanceRIP(inst.length);
            return err;
        }

        // SSE4 handles everything else in this map
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
    value = 0;
    if (!IsSupportedOperandSize(op.size)) {
        return ErrorCode::InvalidOperandSize;
    }

    switch (op.type) {
        case OperandType::Register: {
            if (op.reg.regType == RegType::GPR) {
                if (op.reg.isHighByte) {
                    if (op.size != OperandSize::Size8 || op.reg.regIndex < 4 || op.reg.regIndex > 7) {
                        return ErrorCode::InvalidOperandSize;
                    }
                    value = m_state.GetReg8High(op.reg.regIndex);
                } else {
                    if (!IsValidGprIndex(op.reg.regIndex)) {
                        return ErrorCode::InvalidOperandSize;
                    }
                    value = m_state.GetRegBySize(
                        static_cast<GPR>(op.reg.regIndex), op.size);
                }
            } else if (op.reg.regType == RegType::Segment) {
                if (!IsValidSegmentIndex(op.reg.regIndex)) {
                    return ErrorCode::InvalidOperandSize;
                }
                value = m_state.GetSegment(static_cast<SegReg>(op.reg.regIndex)).selector;
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            return ErrorCode::Success;
        }

        case OperandType::Memory: {
            GuestAddress addr = CalculateEffectiveAddress(op, inst);
            if (addr == kGuestInvalid) {
                return ErrorCode::InvalidAddress;
            }
            uint32_t size = OperandByteWidth(op.size);
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
    if (!IsSupportedOperandSize(op.size)) {
        return ErrorCode::InvalidOperandSize;
    }

    switch (op.type) {
        case OperandType::Register: {
            if (op.reg.regType == RegType::GPR) {
                if (op.reg.isHighByte) {
                    if (op.size != OperandSize::Size8 || op.reg.regIndex < 4 || op.reg.regIndex > 7) {
                        return ErrorCode::InvalidOperandSize;
                    }
                    m_state.SetReg8High(op.reg.regIndex, static_cast<uint8_t>(value));
                } else {
                    if (!IsValidGprIndex(op.reg.regIndex)) {
                        return ErrorCode::InvalidOperandSize;
                    }
                    m_state.SetRegBySize(
                        static_cast<GPR>(op.reg.regIndex), value, op.size);
                }
            } else if (op.reg.regType == RegType::Segment) {
                if (!IsValidSegmentIndex(op.reg.regIndex)) {
                    return ErrorCode::InvalidOperandSize;
                }
                m_state.SetSegmentSelector(static_cast<SegReg>(op.reg.regIndex),
                                           static_cast<uint16_t>(value));
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            return ErrorCode::Success;
        }

        case OperandType::Memory: {
            GuestAddress addr = CalculateEffectiveAddress(op, inst);
            if (addr == kGuestInvalid) {
                return ErrorCode::InvalidAddress;
            }
            uint32_t size = OperandByteWidth(op.size);
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
        const GuestAddress nextRip = inst.NextRIP();
        if (nextRip == kGuestInvalid || !AddSigned(nextRip, op.mem.displacement, addr)) {
            return kGuestInvalid;
        }
    } else {
        // base + index*scale + displacement
        if (op.mem.hasBase) {
            if (!IsValidGprIndex(op.mem.baseReg)) {
                return kGuestInvalid;
            }
            addr = m_state.GetReg64(static_cast<GPR>(op.mem.baseReg));
        }
        if (op.mem.hasIndex) {
            if (!IsValidGprIndex(op.mem.indexReg)) {
                return kGuestInvalid;
            }
            uint64_t scaledIndex = 0;
            if (!ScaleIndex(m_state.GetReg64(static_cast<GPR>(op.mem.indexReg)), op.mem.scale, scaledIndex)
                || !AddUnsigned(addr, scaledIndex, addr)) {
                return kGuestInvalid;
            }
        }
        if (!AddSigned(addr, op.mem.displacement, addr)) {
            return kGuestInvalid;
        }
    }

    if (inst.addressSize == AddressSize::Addr32) {
        addr &= 0xFFFFFFFF;
    } else if (inst.addressSize == AddressSize::Addr16) {
        addr &= 0xFFFF;
    } else if (inst.addressSize != AddressSize::Addr64) {
        return kGuestInvalid;
    }

    // Add segment base (significant for FS/GS in user mode)
    if (op.mem.segment == SegReg::FS || op.mem.segment == SegReg::GS) {
        if (!AddUnsigned(addr, m_state.GetSegment(op.mem.segment).base, addr)) {
            return kGuestInvalid;
        }
    } else if (!CPUState::IsValidSegment(op.mem.segment)) {
        return kGuestInvalid;
    }

    return addr;
}

// ============================================================================
// Stack Helpers
// ============================================================================

ErrorCode CPU::StackPush(VirtualMemory& mem, uint64_t value, OperandSize size) noexcept {
    if (!IsSupportedOperandSize(size)) {
        return ErrorCode::InvalidOperandSize;
    }
    uint32_t bytes = OperandByteWidth(size);
    if (m_state.RSP() < bytes) {
        return ErrorCode::StackOverflow;
    }
    uint64_t rsp = m_state.RSP() - bytes;
    const auto err = mem.Write(rsp, &value, bytes);
    if (err != ErrorCode::Success) {
        return err;
    }
    m_state.SetReg64(GPR::RSP, rsp);
    return ErrorCode::Success;
}

ErrorCode CPU::StackPop(VirtualMemory& mem, uint64_t& value, OperandSize size) noexcept {
    if (!IsSupportedOperandSize(size)) {
        return ErrorCode::InvalidOperandSize;
    }
    uint32_t bytes = OperandByteWidth(size);
    value = 0;
    auto err = mem.Read(m_state.RSP(), &value, bytes);
    if (err != ErrorCode::Success) return err;
    uint64_t nextRsp = 0;
    if (!AddUnsigned(m_state.RSP(), bytes, nextRsp)) {
        return ErrorCode::StackUnderflow;
    }
    m_state.SetReg64(GPR::RSP, nextRsp);
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
// - Executor/AVX2Ops.cpp       → ExecuteAVX2
// - Executor/FPUOps.cpp        → ExecuteFPU
// ============================================================================

} // namespace Phantom
