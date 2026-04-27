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

#include "JITOptimizer.hpp"
#include "../../Common/Constants.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <shared_mutex>
#include <unordered_set>

namespace Phantom {

// ============================================================================
// Internal Constants
// ============================================================================

namespace {

static constexpr uint32_t kMaxTraceBlocks       = 64;
static constexpr uint32_t kMaxWriteTrackEntries  = 4096;
static constexpr uint32_t kMaxIRInstructions     = 2048;
static constexpr float    kColdBranchThreshold   = 0.20f;
static constexpr uint32_t kMaxGuestGPR           = 16;
static constexpr uint32_t kMaxCompiledRangeEntries = 4096;

// Host callee-saved registers available for allocation: R12, R13, R14, R15, RBX, RBP
static constexpr std::array<uint8_t, 6> kHostAllocRegs = {
    12, 13, 14, 15, 3, 5
};

// ============================================================================
// Opcode Classification Helpers
// ============================================================================

[[nodiscard]] bool IsConditionalBranch(const DecodedInstruction& inst) noexcept {
    if (inst.opcodeMap == OpcodeMap::OneByte && inst.opcode >= 0x70 && inst.opcode <= 0x7F) {
        return true;
    }
    if (inst.opcodeMap == OpcodeMap::TwoByte && inst.opcode >= 0x80 && inst.opcode <= 0x8F) {
        return true;
    }
    if (inst.opcodeMap == OpcodeMap::OneByte && inst.opcode >= 0xE0 && inst.opcode <= 0xE3) {
        return true;
    }
    return false;
}

[[nodiscard]] bool IsUnconditionalJmp(const DecodedInstruction& inst) noexcept {
    if (inst.opcodeMap != OpcodeMap::OneByte) {
        return false;
    }
    return inst.opcode == 0xE9 || inst.opcode == 0xEB;
}

[[nodiscard]] bool IsIndirectBranch(const DecodedInstruction& inst) noexcept {
    if (inst.opcodeMap != OpcodeMap::OneByte || inst.opcode != 0xFF) {
        return false;
    }
    // ModRM.reg == 4 (JMP r/m) or 5 (JMP FAR m)
    return inst.opcodeExt == 4 || inst.opcodeExt == 5;
}

[[nodiscard]] bool IsCallInstruction(const DecodedInstruction& inst) noexcept {
    if (inst.opcodeMap != OpcodeMap::OneByte) {
        return false;
    }
    if (inst.opcode == 0xE8) {
        return true;
    }
    // CALL r/m64: FF /2
    if (inst.opcode == 0xFF && inst.opcodeExt == 2) {
        return true;
    }
    return false;
}

[[nodiscard]] bool IsRetInstruction(const DecodedInstruction& inst) noexcept {
    if (inst.opcodeMap != OpcodeMap::OneByte) {
        return false;
    }
    return inst.opcode == 0xC3 || inst.opcode == 0xC2 ||
           inst.opcode == 0xCB || inst.opcode == 0xCA;
}

[[nodiscard]] bool IsSyscallOrInterrupt(const DecodedInstruction& inst) noexcept {
    if (inst.opcodeMap == OpcodeMap::OneByte) {
        // INT, INT3, INTO
        if (inst.opcode == 0xCC || inst.opcode == 0xCD || inst.opcode == 0xCE) {
            return true;
        }
    }
    if (inst.opcodeMap == OpcodeMap::TwoByte) {
        // SYSCALL (0F 05), SYSENTER (0F 34)
        if (inst.opcode == 0x05 || inst.opcode == 0x34) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool IsBlockTerminator(const DecodedInstruction& inst) noexcept {
    return IsConditionalBranch(inst) || IsUnconditionalJmp(inst) ||
           IsIndirectBranch(inst) || IsCallInstruction(inst) ||
           IsRetInstruction(inst) || IsSyscallOrInterrupt(inst);
}

[[nodiscard]] bool AddUnsigned(GuestAddress lhs, GuestSize rhs, GuestAddress& result) noexcept {
    if ((std::numeric_limits<GuestAddress>::max)() - lhs < rhs) {
        return false;
    }
    result = lhs + rhs;
    return true;
}

[[nodiscard]] bool AddSigned(GuestAddress lhs, int64_t rhs, GuestAddress& result) noexcept {
    if (rhs >= 0) {
        return AddUnsigned(lhs, static_cast<GuestSize>(rhs), result);
    }

    const auto magnitude = static_cast<GuestSize>(-(rhs + 1)) + 1;
    if (lhs < magnitude) {
        return false;
    }
    result = lhs - magnitude;
    return true;
}

[[nodiscard]] bool RangeEnd(GuestAddress start, GuestSize size, GuestAddress& end) noexcept {
    return size != 0 && AddUnsigned(start, size, end);
}

[[nodiscard]] bool RangesOverlap(
    GuestAddress firstStart,
    GuestSize firstSize,
    GuestAddress secondStart,
    GuestSize secondSize) noexcept
{
    GuestAddress firstEnd = 0;
    GuestAddress secondEnd = 0;
    if (!RangeEnd(firstStart, firstSize, firstEnd) || !RangeEnd(secondStart, secondSize, secondEnd)) {
        return false;
    }
    return firstStart < secondEnd && secondStart < firstEnd;
}

[[nodiscard]] GuestAddress ComputeBranchTarget(const DecodedInstruction& inst) noexcept {
    if (inst.operandCount == 0) {
        return 0;
    }
    const GuestAddress nextRip = inst.NextRIP();
    if (nextRip == kGuestInvalid) {
        return 0;
    }
    const auto& op0 = inst.operands[0];
    if (op0.type == OperandType::RelativeOffset) {
        GuestAddress target = 0;
        return AddSigned(nextRip, op0.rel.offset, target) ? target : 0;
    }
    if (op0.type == OperandType::Immediate) {
        GuestAddress target = 0;
        return AddUnsigned(nextRip, op0.imm.value, target) ? target : 0;
    }
    return 0;
}

// ============================================================================
// IR Generation Helpers
// ============================================================================

[[nodiscard]] uint8_t ExtractGPRIndex(const DecodedOperand& op) noexcept {
    if (op.type == OperandType::Register
        && op.reg.regType == RegType::GPR
        && op.reg.regIndex < static_cast<uint8_t>(GPR::Count)) {
        return op.reg.regIndex;
    }
    return 0xFF;
}

[[nodiscard]] bool OperandIsGPR(const DecodedOperand& op) noexcept {
    return ExtractGPRIndex(op) != 0xFF;
}

[[nodiscard]] bool OperandIsImmediate(const DecodedOperand& op) noexcept {
    return op.type == OperandType::Immediate;
}

[[nodiscard]] bool OperandIsMemory(const DecodedOperand& op) noexcept {
    return op.type == OperandType::Memory;
}

// Compute an ALU result for constant folding
[[nodiscard]] uint32_t OperandBitWidth(OperandSize size) noexcept {
    switch (size) {
        case OperandSize::Size8:  return 8;
        case OperandSize::Size16: return 16;
        case OperandSize::Size32: return 32;
        case OperandSize::Size64: return 64;
    }
    return 64;
}

[[nodiscard]] uint64_t OperandMask(OperandSize size) noexcept {
    switch (size) {
        case OperandSize::Size8:  return 0xFFULL;
        case OperandSize::Size16: return 0xFFFFULL;
        case OperandSize::Size32: return 0xFFFFFFFFULL;
        case OperandSize::Size64: return (std::numeric_limits<uint64_t>::max)();
    }
    return (std::numeric_limits<uint64_t>::max)();
}

[[nodiscard]] uint64_t MaskToOperand(uint64_t value, OperandSize size) noexcept {
    return value & OperandMask(size);
}

[[nodiscard]] uint64_t ArithmeticShiftRight(uint64_t value, uint64_t count, OperandSize size) noexcept {
    const uint32_t width = OperandBitWidth(size);
    const uint64_t masked = MaskToOperand(value, size);
    if (count >= width) {
        return (masked & (1ULL << (width - 1))) != 0 ? OperandMask(size) : 0;
    }
    if (count == 0) {
        return masked;
    }

    const uint64_t shifted = masked >> count;
    if ((masked & (1ULL << (width - 1))) == 0) {
        return shifted;
    }
    const uint64_t signFill = OperandMask(size) << (width - count);
    return MaskToOperand(shifted | signFill, size);
}

[[nodiscard]] uint64_t EvaluateALU(IRInstruction::Op op, uint64_t a, uint64_t b, OperandSize sz) noexcept {
    uint64_t result = 0;
    const uint32_t width = OperandBitWidth(sz);
    const uint64_t shiftCount = b;
    const uint64_t lhs = MaskToOperand(a, sz);
    const uint64_t rhs = MaskToOperand(b, sz);

    switch (op) {
        case IRInstruction::Op::Add: result = lhs + rhs; break;
        case IRInstruction::Op::Sub: result = lhs - rhs; break;
        case IRInstruction::Op::And: result = lhs & rhs; break;
        case IRInstruction::Op::Or:  result = lhs | rhs; break;
        case IRInstruction::Op::Xor: result = lhs ^ rhs; break;
        case IRInstruction::Op::Shl:
            result = (shiftCount < width) ? (lhs << shiftCount) : 0;
            break;
        case IRInstruction::Op::Shr:
            result = (shiftCount < width) ? (lhs >> shiftCount) : 0;
            break;
        case IRInstruction::Op::Sar:
            result = ArithmeticShiftRight(lhs, shiftCount, sz);
            break;
        case IRInstruction::Op::Not: result = ~lhs; break;
        case IRInstruction::Op::Neg: result = 0ULL - lhs; break;
        default: result = 0; break;
    }

    return MaskToOperand(result, sz);
}

[[nodiscard]] bool IsALUOp(IRInstruction::Op op) noexcept {
    switch (op) {
        case IRInstruction::Op::Add:
        case IRInstruction::Op::Sub:
        case IRInstruction::Op::And:
        case IRInstruction::Op::Or:
        case IRInstruction::Op::Xor:
        case IRInstruction::Op::Shl:
        case IRInstruction::Op::Shr:
        case IRInstruction::Op::Sar:
        case IRInstruction::Op::Rol:
        case IRInstruction::Op::Ror:
        case IRInstruction::Op::Not:
        case IRInstruction::Op::Neg:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] bool WritesRegister(const IRInstruction& ir) noexcept {
    if (ir.dst == 0xFF) {
        return false;
    }
    switch (ir.op) {
        case IRInstruction::Op::MovImm:
        case IRInstruction::Op::MovReg:
        case IRInstruction::Op::Load:
        case IRInstruction::Op::Add:
        case IRInstruction::Op::Sub:
        case IRInstruction::Op::And:
        case IRInstruction::Op::Or:
        case IRInstruction::Op::Xor:
        case IRInstruction::Op::Not:
        case IRInstruction::Op::Neg:
        case IRInstruction::Op::Shl:
        case IRInstruction::Op::Shr:
        case IRInstruction::Op::Sar:
        case IRInstruction::Op::Rol:
        case IRInstruction::Op::Ror:
        case IRInstruction::Op::Mul:
        case IRInstruction::Op::Div:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] bool ReadsRegister(const IRInstruction& ir, uint8_t reg) noexcept {
    if (reg == 0xFF) {
        return false;
    }
    if (ir.src1 == reg || ir.src2 == reg) {
        return true;
    }
    // Store uses dst as source value
    if (ir.op == IRInstruction::Op::Store && ir.dst == reg) {
        return true;
    }
    return false;
}

[[nodiscard]] bool IsValidGuestGpr(uint8_t reg) noexcept {
    return reg < kMaxGuestGPR;
}

void ConvertToSideEffect(IRInstruction& ir) noexcept {
    ir.op = IRInstruction::Op::SideEffect;
    ir.dst = 0xFF;
    ir.src1 = 0xFF;
    ir.src2 = 0xFF;
    ir.immediate = 0;
    ir.hasSideEffects = true;
    ir.isDeadStore = false;
    ir.isFolded = false;
}

void SanitizeIR(std::vector<IRInstruction>& ir) noexcept {
    for (auto& inst : ir) {
        switch (inst.op) {
            case IRInstruction::Op::Nop:
            case IRInstruction::Op::SideEffect:
            case IRInstruction::Op::FlagUpdate:
            case IRInstruction::Op::Jcc:
            case IRInstruction::Op::Jmp:
            case IRInstruction::Op::Call:
            case IRInstruction::Op::Ret:
                break;

            case IRInstruction::Op::MovImm:
                if (!IsValidGuestGpr(inst.dst)) { ConvertToSideEffect(inst); }
                break;

            case IRInstruction::Op::MovReg:
                if (!IsValidGuestGpr(inst.dst) || !IsValidGuestGpr(inst.src1)) { ConvertToSideEffect(inst); }
                break;

            case IRInstruction::Op::Load:
                if (!IsValidGuestGpr(inst.dst)) { ConvertToSideEffect(inst); }
                break;

            case IRInstruction::Op::Store:
                if (!IsValidGuestGpr(inst.dst)) { ConvertToSideEffect(inst); }
                break;

            case IRInstruction::Op::Add:
            case IRInstruction::Op::Sub:
            case IRInstruction::Op::And:
            case IRInstruction::Op::Or:
            case IRInstruction::Op::Xor:
            case IRInstruction::Op::Shl:
            case IRInstruction::Op::Shr:
            case IRInstruction::Op::Sar:
            case IRInstruction::Op::Rol:
            case IRInstruction::Op::Ror:
            case IRInstruction::Op::Mul:
            case IRInstruction::Op::Div:
                if (!IsValidGuestGpr(inst.dst)
                    || !IsValidGuestGpr(inst.src1)
                    || (inst.src2 != 0xFF && !IsValidGuestGpr(inst.src2))) {
                    ConvertToSideEffect(inst);
                }
                break;

            case IRInstruction::Op::Not:
            case IRInstruction::Op::Neg:
                if (!IsValidGuestGpr(inst.dst) || !IsValidGuestGpr(inst.src1)) { ConvertToSideEffect(inst); }
                break;

            case IRInstruction::Op::Cmp:
            case IRInstruction::Op::Test:
                if (!IsValidGuestGpr(inst.src1)
                    || (inst.src2 != 0xFF && !IsValidGuestGpr(inst.src2))) {
                    ConvertToSideEffect(inst);
                }
                break;
        }
    }
}

} // anonymous namespace

// ============================================================================
// Write Range for SMC detection
// ============================================================================

struct WriteRange {
    GuestAddress start = 0;
    GuestSize    size  = 0;
};

// ============================================================================
// Compiled Block Range for SMC invalidation
// ============================================================================

struct BlockRange {
    GuestAddress start = 0;
    GuestSize    size  = 0;
};

// ============================================================================
// Impl
// ============================================================================

struct JITOptimizer::Impl {
    mutable std::shared_mutex mutex;

    // SMC tracking: sorted by start address for efficient overlap queries
    std::vector<WriteRange> writeRanges;

    // Known compiled block ranges for overlap testing
    std::vector<BlockRange> compiledRanges;

    // Statistics
    OptimizationStats stats{};

    Impl() {
        writeRanges.reserve(kMaxWriteTrackEntries);
        compiledRanges.reserve(kMaxCompiledRangeEntries);
    }
};

// ============================================================================
// Construction / Destruction
// ============================================================================

JITOptimizer::JITOptimizer() noexcept {
    try {
        m_impl = std::make_unique<Impl>();
    } catch (...) {
        m_impl.reset();
    }
}

JITOptimizer::~JITOptimizer() noexcept = default;

JITOptimizer::JITOptimizer(JITOptimizer&&) noexcept = default;
JITOptimizer& JITOptimizer::operator=(JITOptimizer&&) noexcept = default;

// ============================================================================
// Trace Building
// ============================================================================

std::optional<TraceInfo> JITOptimizer::BuildTrace(
    GuestAddress entryPoint,
    const std::unordered_map<GuestAddress, uint32_t>& blockProfile,
    const DecodedInstruction* instructions,
    uint32_t instrCount,
    uint32_t maxTraceLength) const noexcept
{
    if (!m_impl || instructions == nullptr || instrCount == 0 || entryPoint == 0) {
        return std::nullopt;
    }

    try {
    // Cap trace length to prevent unbounded growth
    const uint32_t effectiveMaxLength = std::min(maxTraceLength, kMaxIRInstructions);
    if (effectiveMaxLength == 0) {
        return std::nullopt;
    }
    const uint32_t cappedInstrCount = std::min(instrCount, kMaxIRInstructions);

    // Build an index from guest address to instruction array position for O(1) lookup
    std::unordered_map<GuestAddress, uint32_t> addrToIndex;
    addrToIndex.reserve(cappedInstrCount);
    for (uint32_t i = 0; i < cappedInstrCount; ++i) {
        addrToIndex.emplace(instructions[i].address, i);
    }

    // Find the entry instruction
    auto entryIt = addrToIndex.find(entryPoint);
    if (entryIt == addrToIndex.end()) {
        return std::nullopt;
    }

    TraceInfo trace{};
    trace.entryAddress = entryPoint;

    // Track visited block starts to detect loops
    std::unordered_set<GuestAddress> visitedStarts;
    uint32_t totalInstr = 0;
    GuestAddress currentBlockStart = entryPoint;

    while (totalInstr < effectiveMaxLength && trace.blocks.size() < kMaxTraceBlocks) {
        auto blockStartIt = addrToIndex.find(currentBlockStart);
        if (blockStartIt == addrToIndex.end()) {
            break;
        }

        // Loop detection
        if (visitedStarts.count(currentBlockStart) > 0) {
            if (currentBlockStart == entryPoint) {
                trace.isLoop = true;
            }
            break;
        }
        visitedStarts.insert(currentBlockStart);

        TraceBlock block{};
        block.startAddress = currentBlockStart;

        uint32_t blockInstrCount = 0;
        uint32_t idx = blockStartIt->second;
        GuestAddress lastAddr = currentBlockStart;
        bool terminated = false;

        while (idx < cappedInstrCount && totalInstr + blockInstrCount < effectiveMaxLength) {
            const auto& inst = instructions[idx];
            if (inst.address != lastAddr && blockInstrCount > 0) {
                // Instructions are not contiguous — end of this block's coverage
                if (inst.address != instructions[idx - 1].NextRIP()) {
                    break;
                }
            }

            lastAddr = inst.address;
            ++blockInstrCount;

            if (IsBlockTerminator(inst)) {
                block.endAddress = inst.NextRIP();
                if (block.endAddress == kGuestInvalid) {
                    terminated = true;
                    break;
                }

                if (IsSyscallOrInterrupt(inst) || IsIndirectBranch(inst) || IsRetInstruction(inst)) {
                    // Hard terminator — cannot continue trace
                    terminated = true;
                    break;
                }

                if (IsConditionalBranch(inst)) {
                    const GuestAddress target = ComputeBranchTarget(inst);
                    const GuestAddress fallthrough = inst.NextRIP();

                    block.branchTarget = target;
                    block.fallthroughTarget = fallthrough;

                    // Use profiling data to determine branch direction
                    auto targetIt = blockProfile.find(target);
                    auto fallIt   = blockProfile.find(fallthrough);

                    const uint64_t targetCount = (targetIt != blockProfile.end()) ? targetIt->second : 0;
                    const uint64_t fallCount   = (fallIt != blockProfile.end())   ? fallIt->second   : 0;
                    const uint64_t totalCount  = targetCount + fallCount;

                    if (totalCount > 0) {
                        block.branchTakenRate = static_cast<float>(targetCount) /
                                                static_cast<float>(totalCount);
                    } else {
                        block.branchTakenRate = 0.5f;
                    }

                    block.isBranchTaken = (block.branchTakenRate >= 0.5f);

                    terminated = true;
                    break;
                }

                if (IsUnconditionalJmp(inst)) {
                    const GuestAddress target = ComputeBranchTarget(inst);
                    block.branchTarget = target;
                    block.fallthroughTarget = 0;
                    block.isBranchTaken = true;
                    block.branchTakenRate = 1.0f;
                    terminated = true;
                    break;
                }

                if (IsCallInstruction(inst)) {
                    // Treat CALL as a block boundary; trace continues at return address
                    block.fallthroughTarget = inst.NextRIP();
                    block.branchTarget = 0;
                    block.isBranchTaken = false;
                    block.branchTakenRate = 0.0f;
                    terminated = true;
                    break;
                }

                break;
            }

            ++idx;
        }

        if (blockInstrCount == 0) {
            break;
        }

        if (block.endAddress == 0) {
            // Block didn't hit a terminator — ended naturally
            if (idx > 0 && idx <= cappedInstrCount) {
                const auto& lastInst = instructions[idx - 1];
                block.endAddress = lastInst.NextRIP();
                if (block.endAddress == kGuestInvalid) {
                    break;
                }
                block.fallthroughTarget = block.endAddress;
            } else {
                block.endAddress = lastAddr;
            }
        }

        block.instructionCount = blockInstrCount;
        totalInstr += blockInstrCount;
        trace.blocks.push_back(block);

        if (!terminated) {
            break;
        }

        // Determine next block to follow
        GuestAddress nextAddr = 0;
        if (block.isBranchTaken && block.branchTarget != 0) {
            // Follow taken branch if hot enough
            if (block.branchTakenRate >= kColdBranchThreshold) {
                nextAddr = block.branchTarget;
            }
        } else if (block.fallthroughTarget != 0) {
            if ((1.0f - block.branchTakenRate) >= kColdBranchThreshold) {
                nextAddr = block.fallthroughTarget;
            }
        }

        if (nextAddr == 0) {
            break;
        }

        currentBlockStart = nextAddr;
    }

    if (trace.blocks.empty()) {
        return std::nullopt;
    }

    trace.totalInstructions = totalInstr;

    // Sum execution counts from profile for the entry
    auto profileIt = blockProfile.find(entryPoint);
    if (profileIt != blockProfile.end()) {
        trace.executionCount = profileIt->second;
    }

    // Update stats under lock
    {
        std::unique_lock lock(m_impl->mutex);
        ++m_impl->stats.tracesBuilt;
    }

    return trace;
    } catch (const std::bad_alloc&) {
        return std::nullopt;
    }
}

// ============================================================================
// IR Generation
// ============================================================================

std::vector<IRInstruction> JITOptimizer::GenerateIR(
    const DecodedInstruction* instructions,
    uint32_t count) const noexcept
{
    std::vector<IRInstruction> ir;
    if (!m_impl || instructions == nullptr || count == 0) {
        return ir;
    }

    try {
    const uint32_t cappedCount = std::min(count, kMaxIRInstructions);
    ir.reserve(cappedCount * 2); // Some instructions expand to multiple IR ops

    for (uint32_t i = 0; i < cappedCount; ++i) {
        const auto& inst = instructions[i];

        // Handle syscall/interrupt as side effects
        if (IsSyscallOrInterrupt(inst)) {
            IRInstruction side{};
            side.op = IRInstruction::Op::SideEffect;
            side.guestAddress = inst.address;
            side.size = inst.operandSize;
            side.hasSideEffects = true;
            ir.push_back(side);
            continue;
        }

        // Handle CALL
        if (IsCallInstruction(inst)) {
            IRInstruction call{};
            call.op = IRInstruction::Op::Call;
            call.guestAddress = inst.address;
            call.size = inst.operandSize;
            call.hasSideEffects = true;
            if (inst.operandCount > 0 && inst.operands[0].type == OperandType::RelativeOffset) {
                call.immediate = ComputeBranchTarget(inst);
            }
            ir.push_back(call);
            continue;
        }

        // Handle RET
        if (IsRetInstruction(inst)) {
            IRInstruction ret{};
            ret.op = IRInstruction::Op::Ret;
            ret.guestAddress = inst.address;
            ret.size = inst.operandSize;
            ret.hasSideEffects = true;
            ir.push_back(ret);
            continue;
        }

        // Handle conditional branches
        if (IsConditionalBranch(inst)) {
            IRInstruction jcc{};
            jcc.op = IRInstruction::Op::Jcc;
            jcc.guestAddress = inst.address;
            jcc.size = inst.operandSize;
            jcc.hasSideEffects = true;
            jcc.immediate = ComputeBranchTarget(inst);
            ir.push_back(jcc);
            continue;
        }

        // Handle unconditional jumps
        if (IsUnconditionalJmp(inst)) {
            IRInstruction jmp{};
            jmp.op = IRInstruction::Op::Jmp;
            jmp.guestAddress = inst.address;
            jmp.size = inst.operandSize;
            jmp.hasSideEffects = true;
            jmp.immediate = ComputeBranchTarget(inst);
            ir.push_back(jmp);
            continue;
        }

        // Indirect branch via FF /4, FF /5
        if (IsIndirectBranch(inst)) {
            IRInstruction jmp{};
            jmp.op = IRInstruction::Op::Jmp;
            jmp.guestAddress = inst.address;
            jmp.size = inst.operandSize;
            jmp.hasSideEffects = true;
            ir.push_back(jmp);
            continue;
        }

        if (inst.opcodeMap != OpcodeMap::OneByte && inst.opcodeMap != OpcodeMap::TwoByte) {
            // Unsupported map — emit as side effect to preserve correctness
            IRInstruction side{};
            side.op = IRInstruction::Op::SideEffect;
            side.guestAddress = inst.address;
            side.size = inst.operandSize;
            side.hasSideEffects = true;
            ir.push_back(side);
            continue;
        }

        // === One-byte opcode map ===
        if (inst.opcodeMap == OpcodeMap::OneByte) {
            const uint8_t op = inst.opcode;

            // NOP (0x90)
            if (op == 0x90) {
                IRInstruction nop{};
                nop.op = IRInstruction::Op::Nop;
                nop.guestAddress = inst.address;
                nop.size = inst.operandSize;
                ir.push_back(nop);
                continue;
            }

            // MOV reg, imm (0xB0-0xBF)
            if (op >= 0xB0 && op <= 0xBF) {
                IRInstruction mov{};
                mov.op = IRInstruction::Op::MovImm;
                mov.guestAddress = inst.address;
                mov.size = inst.operandSize;
                if (inst.operandCount >= 1) {
                    mov.dst = ExtractGPRIndex(inst.operands[0]);
                }
                if (inst.operandCount >= 2 && OperandIsImmediate(inst.operands[1])) {
                    mov.immediate = inst.operands[1].imm.value;
                }
                ir.push_back(mov);
                continue;
            }

            // MOV r/m, r (0x88, 0x89) and MOV r, r/m (0x8A, 0x8B)
            if (op == 0x88 || op == 0x89 || op == 0x8A || op == 0x8B) {
                if (inst.operandCount < 2) {
                    IRInstruction side{};
                    side.op = IRInstruction::Op::SideEffect;
                    side.guestAddress = inst.address;
                    side.hasSideEffects = true;
                    ir.push_back(side);
                    continue;
                }

                const auto& dst = inst.operands[0];
                const auto& src = inst.operands[1];

                if (OperandIsGPR(dst) && OperandIsGPR(src)) {
                    IRInstruction mov{};
                    mov.op = IRInstruction::Op::MovReg;
                    mov.dst = ExtractGPRIndex(dst);
                    mov.src1 = ExtractGPRIndex(src);
                    mov.guestAddress = inst.address;
                    mov.size = inst.operandSize;
                    ir.push_back(mov);
                } else if (OperandIsGPR(dst) && OperandIsMemory(src)) {
                    IRInstruction load{};
                    load.op = IRInstruction::Op::Load;
                    load.dst = ExtractGPRIndex(dst);
                    load.guestAddress = inst.address;
                    load.size = inst.operandSize;
                    load.hasSideEffects = true; // Memory reads may have side effects (MMIO)
                    if (src.mem.hasBase) {
                        load.src1 = src.mem.baseReg;
                    }
                    ir.push_back(load);
                } else if (OperandIsMemory(dst) && OperandIsGPR(src)) {
                    IRInstruction store{};
                    store.op = IRInstruction::Op::Store;
                    store.dst = ExtractGPRIndex(src);
                    store.guestAddress = inst.address;
                    store.size = inst.operandSize;
                    store.hasSideEffects = true;
                    if (dst.mem.hasBase) {
                        store.src1 = dst.mem.baseReg;
                    }
                    ir.push_back(store);
                } else if (OperandIsGPR(dst) && OperandIsImmediate(src)) {
                    IRInstruction mov{};
                    mov.op = IRInstruction::Op::MovImm;
                    mov.dst = ExtractGPRIndex(dst);
                    mov.immediate = src.imm.value;
                    mov.guestAddress = inst.address;
                    mov.size = inst.operandSize;
                    ir.push_back(mov);
                } else {
                    IRInstruction side{};
                    side.op = IRInstruction::Op::SideEffect;
                    side.guestAddress = inst.address;
                    side.hasSideEffects = true;
                    ir.push_back(side);
                }
                continue;
            }

            // MOV r/m, imm (0xC6, 0xC7)
            if (op == 0xC6 || op == 0xC7) {
                if (inst.operandCount >= 2) {
                    const auto& dstOp = inst.operands[0];
                    const auto& srcOp = inst.operands[1];
                    if (OperandIsGPR(dstOp) && OperandIsImmediate(srcOp)) {
                        IRInstruction mov{};
                        mov.op = IRInstruction::Op::MovImm;
                        mov.dst = ExtractGPRIndex(dstOp);
                        mov.immediate = srcOp.imm.value;
                        mov.guestAddress = inst.address;
                        mov.size = inst.operandSize;
                        ir.push_back(mov);
                    } else if (OperandIsMemory(dstOp)) {
                        IRInstruction store{};
                        store.op = IRInstruction::Op::Store;
                        store.guestAddress = inst.address;
                        store.size = inst.operandSize;
                        store.hasSideEffects = true;
                        if (OperandIsImmediate(srcOp)) {
                            store.immediate = srcOp.imm.value;
                        }
                        ir.push_back(store);
                    } else {
                        IRInstruction side{};
                        side.op = IRInstruction::Op::SideEffect;
                        side.guestAddress = inst.address;
                        side.hasSideEffects = true;
                        ir.push_back(side);
                    }
                }
                continue;
            }

            // LEA r, m (0x8D) — no memory access, compute address into register
            if (op == 0x8D) {
                if (inst.operandCount >= 2 && OperandIsGPR(inst.operands[0]) &&
                    OperandIsMemory(inst.operands[1])) {
                    // LEA is effectively a complex add/shift — model as MovImm or Add
                    // If the displacement is the only component, it's a constant load
                    const auto& mem = inst.operands[1].mem;
                    if (!mem.hasBase && !mem.hasIndex) {
                        IRInstruction mov{};
                        mov.op = IRInstruction::Op::MovImm;
                        mov.dst = ExtractGPRIndex(inst.operands[0]);
                        mov.immediate = static_cast<uint64_t>(mem.displacement);
                        mov.guestAddress = inst.address;
                        mov.size = inst.operandSize;
                        ir.push_back(mov);
                    } else {
                        // Generic LEA: side-effect-free address computation
                        IRInstruction lea{};
                        lea.op = IRInstruction::Op::Add;
                        lea.dst = ExtractGPRIndex(inst.operands[0]);
                        if (mem.hasBase) {
                            lea.src1 = mem.baseReg;
                        }
                        if (mem.hasIndex) {
                            lea.src2 = mem.indexReg;
                        }
                        lea.immediate = static_cast<uint64_t>(mem.displacement);
                        lea.guestAddress = inst.address;
                        lea.size = inst.operandSize;
                        ir.push_back(lea);
                    }
                } else {
                    IRInstruction side{};
                    side.op = IRInstruction::Op::SideEffect;
                    side.guestAddress = inst.address;
                    side.hasSideEffects = true;
                    ir.push_back(side);
                }
                continue;
            }

            // ADD (0x01, 0x03, 0x05), SUB (0x29, 0x2B, 0x2D), XOR (0x31, 0x33, 0x35),
            // AND (0x21, 0x23, 0x25), OR (0x09, 0x0B, 0x0D)
            // Group opcodes: 0x81 /ext, 0x83 /ext
            {
                IRInstruction::Op irOp = IRInstruction::Op::Nop;
                bool isAlu = false;

                if (op == 0x01 || op == 0x03 || op == 0x05) { irOp = IRInstruction::Op::Add; isAlu = true; }
                else if (op == 0x29 || op == 0x2B || op == 0x2D) { irOp = IRInstruction::Op::Sub; isAlu = true; }
                else if (op == 0x31 || op == 0x33 || op == 0x35) { irOp = IRInstruction::Op::Xor; isAlu = true; }
                else if (op == 0x21 || op == 0x23 || op == 0x25) { irOp = IRInstruction::Op::And; isAlu = true; }
                else if (op == 0x09 || op == 0x0B || op == 0x0D) { irOp = IRInstruction::Op::Or;  isAlu = true; }
                else if (op == 0x81 || op == 0x83) {
                    isAlu = true;
                    switch (inst.opcodeExt) {
                        case 0: irOp = IRInstruction::Op::Add; break;
                        case 1: irOp = IRInstruction::Op::Or;  break;
                        case 4: irOp = IRInstruction::Op::And; break;
                        case 5: irOp = IRInstruction::Op::Sub; break;
                        case 6: irOp = IRInstruction::Op::Xor; break;
                        case 7: // CMP
                            irOp = IRInstruction::Op::Cmp;
                            break;
                        default:
                            isAlu = false;
                            break;
                    }
                }

                if (isAlu && inst.operandCount >= 2) {
                    const auto& dstOp = inst.operands[0];
                    const auto& srcOp = inst.operands[1];

                    IRInstruction aluInst{};
                    aluInst.op = irOp;
                    aluInst.guestAddress = inst.address;
                    aluInst.size = inst.operandSize;

                    if (OperandIsGPR(dstOp)) {
                        aluInst.dst = ExtractGPRIndex(dstOp);
                        aluInst.src1 = aluInst.dst;
                    } else if (OperandIsMemory(dstOp)) {
                        aluInst.hasSideEffects = true;
                    }

                    if (OperandIsGPR(srcOp)) {
                        aluInst.src2 = ExtractGPRIndex(srcOp);
                    } else if (OperandIsImmediate(srcOp)) {
                        aluInst.immediate = srcOp.imm.value;
                        aluInst.src2 = 0xFF; // No register source — immediate
                    } else if (OperandIsMemory(srcOp)) {
                        aluInst.hasSideEffects = true;
                    }

                    ir.push_back(aluInst);

                    // ALU instructions update flags
                    IRInstruction flagUpd{};
                    flagUpd.op = IRInstruction::Op::FlagUpdate;
                    flagUpd.guestAddress = inst.address;
                    flagUpd.size = inst.operandSize;
                    flagUpd.hasSideEffects = true;
                    ir.push_back(flagUpd);
                    continue;
                }
            }

            // CMP (0x39, 0x3B, 0x3D)
            if (op == 0x39 || op == 0x3B || op == 0x3D) {
                if (inst.operandCount >= 2) {
                    IRInstruction cmp{};
                    cmp.op = IRInstruction::Op::Cmp;
                    cmp.guestAddress = inst.address;
                    cmp.size = inst.operandSize;
                    if (OperandIsGPR(inst.operands[0])) {
                        cmp.src1 = ExtractGPRIndex(inst.operands[0]);
                    }
                    if (OperandIsGPR(inst.operands[1])) {
                        cmp.src2 = ExtractGPRIndex(inst.operands[1]);
                    } else if (OperandIsImmediate(inst.operands[1])) {
                        cmp.immediate = inst.operands[1].imm.value;
                    }
                    cmp.hasSideEffects = true; // Flags are a side effect
                    ir.push_back(cmp);

                    IRInstruction flagUpd{};
                    flagUpd.op = IRInstruction::Op::FlagUpdate;
                    flagUpd.guestAddress = inst.address;
                    flagUpd.size = inst.operandSize;
                    flagUpd.hasSideEffects = true;
                    ir.push_back(flagUpd);
                }
                continue;
            }

            // TEST (0x85, 0xA9, 0xF7 /0)
            if (op == 0x85 || op == 0xA9 || (op == 0xF7 && inst.opcodeExt == 0)) {
                if (inst.operandCount >= 2) {
                    IRInstruction test{};
                    test.op = IRInstruction::Op::Test;
                    test.guestAddress = inst.address;
                    test.size = inst.operandSize;
                    if (OperandIsGPR(inst.operands[0])) {
                        test.src1 = ExtractGPRIndex(inst.operands[0]);
                    }
                    if (OperandIsGPR(inst.operands[1])) {
                        test.src2 = ExtractGPRIndex(inst.operands[1]);
                    } else if (OperandIsImmediate(inst.operands[1])) {
                        test.immediate = inst.operands[1].imm.value;
                    }
                    test.hasSideEffects = true;
                    ir.push_back(test);

                    IRInstruction flagUpd{};
                    flagUpd.op = IRInstruction::Op::FlagUpdate;
                    flagUpd.guestAddress = inst.address;
                    flagUpd.size = inst.operandSize;
                    flagUpd.hasSideEffects = true;
                    ir.push_back(flagUpd);
                }
                continue;
            }

            // Shift/Rotate: SHL(0xD1/0xC1 ext0, 0xD3 ext4), SHR(ext5), SAR(ext7), ROL(ext0), ROR(ext1)
            if (op == 0xD0 || op == 0xD1 || op == 0xD2 || op == 0xD3 || op == 0xC0 || op == 0xC1) {
                if (inst.operandCount >= 1) {
                    IRInstruction::Op shOp = IRInstruction::Op::Nop;
                    switch (inst.opcodeExt) {
                        case 0: shOp = IRInstruction::Op::Rol; break;
                        case 1: shOp = IRInstruction::Op::Ror; break;
                        case 4: shOp = IRInstruction::Op::Shl; break;
                        case 5: shOp = IRInstruction::Op::Shr; break;
                        case 7: shOp = IRInstruction::Op::Sar; break;
                        default:
                            break;
                    }

                    if (shOp != IRInstruction::Op::Nop) {
                        IRInstruction shift{};
                        shift.op = shOp;
                        shift.guestAddress = inst.address;
                        shift.size = inst.operandSize;
                        if (OperandIsGPR(inst.operands[0])) {
                            shift.dst = ExtractGPRIndex(inst.operands[0]);
                            shift.src1 = shift.dst;
                        } else {
                            shift.hasSideEffects = true;
                        }

                        if (inst.operandCount >= 2 && OperandIsImmediate(inst.operands[1])) {
                            shift.immediate = inst.operands[1].imm.value;
                        } else if (op == 0xD0 || op == 0xD1) {
                            shift.immediate = 1; // Shift by 1
                        } else {
                            // Shift by CL — src2 = RCX index
                            shift.src2 = static_cast<uint8_t>(GPR::RCX);
                        }

                        ir.push_back(shift);

                        IRInstruction flagUpd{};
                        flagUpd.op = IRInstruction::Op::FlagUpdate;
                        flagUpd.guestAddress = inst.address;
                        flagUpd.size = inst.operandSize;
                        flagUpd.hasSideEffects = true;
                        ir.push_back(flagUpd);
                        continue;
                    }
                }
            }

            // NOT (0xF7 /2), NEG (0xF7 /3)
            if (op == 0xF6 || op == 0xF7) {
                if (inst.opcodeExt == 2) {
                    // NOT
                    IRInstruction notInst{};
                    notInst.op = IRInstruction::Op::Not;
                    notInst.guestAddress = inst.address;
                    notInst.size = inst.operandSize;
                    if (inst.operandCount >= 1 && OperandIsGPR(inst.operands[0])) {
                        notInst.dst = ExtractGPRIndex(inst.operands[0]);
                        notInst.src1 = notInst.dst;
                    } else {
                        notInst.hasSideEffects = true;
                    }
                    ir.push_back(notInst);
                    continue;
                }
                if (inst.opcodeExt == 3) {
                    // NEG
                    IRInstruction negInst{};
                    negInst.op = IRInstruction::Op::Neg;
                    negInst.guestAddress = inst.address;
                    negInst.size = inst.operandSize;
                    if (inst.operandCount >= 1 && OperandIsGPR(inst.operands[0])) {
                        negInst.dst = ExtractGPRIndex(inst.operands[0]);
                        negInst.src1 = negInst.dst;
                    } else {
                        negInst.hasSideEffects = true;
                    }
                    ir.push_back(negInst);

                    IRInstruction flagUpd{};
                    flagUpd.op = IRInstruction::Op::FlagUpdate;
                    flagUpd.guestAddress = inst.address;
                    flagUpd.size = inst.operandSize;
                    flagUpd.hasSideEffects = true;
                    ir.push_back(flagUpd);
                    continue;
                }
                if (inst.opcodeExt == 4 || inst.opcodeExt == 5) {
                    // MUL/IMUL
                    IRInstruction mul{};
                    mul.op = IRInstruction::Op::Mul;
                    mul.guestAddress = inst.address;
                    mul.size = inst.operandSize;
                    mul.hasSideEffects = true; // Writes RAX:RDX
                    mul.dst = static_cast<uint8_t>(GPR::RAX);
                    if (inst.operandCount >= 1 && OperandIsGPR(inst.operands[0])) {
                        mul.src1 = ExtractGPRIndex(inst.operands[0]);
                    }
                    ir.push_back(mul);

                    IRInstruction flagUpd{};
                    flagUpd.op = IRInstruction::Op::FlagUpdate;
                    flagUpd.guestAddress = inst.address;
                    flagUpd.size = inst.operandSize;
                    flagUpd.hasSideEffects = true;
                    ir.push_back(flagUpd);
                    continue;
                }
                if (inst.opcodeExt == 6 || inst.opcodeExt == 7) {
                    // DIV/IDIV
                    IRInstruction divInst{};
                    divInst.op = IRInstruction::Op::Div;
                    divInst.guestAddress = inst.address;
                    divInst.size = inst.operandSize;
                    divInst.hasSideEffects = true;
                    divInst.dst = static_cast<uint8_t>(GPR::RAX);
                    if (inst.operandCount >= 1 && OperandIsGPR(inst.operands[0])) {
                        divInst.src1 = ExtractGPRIndex(inst.operands[0]);
                    }
                    ir.push_back(divInst);

                    IRInstruction flagUpd{};
                    flagUpd.op = IRInstruction::Op::FlagUpdate;
                    flagUpd.guestAddress = inst.address;
                    flagUpd.size = inst.operandSize;
                    flagUpd.hasSideEffects = true;
                    ir.push_back(flagUpd);
                    continue;
                }
            }

            // IMUL two/three-operand forms (0F AF, 69, 6B)
            if (op == 0x69 || op == 0x6B) {
                IRInstruction mul{};
                mul.op = IRInstruction::Op::Mul;
                mul.guestAddress = inst.address;
                mul.size = inst.operandSize;
                mul.hasSideEffects = true;
                if (inst.operandCount >= 1 && OperandIsGPR(inst.operands[0])) {
                    mul.dst = ExtractGPRIndex(inst.operands[0]);
                }
                if (inst.operandCount >= 2 && OperandIsGPR(inst.operands[1])) {
                    mul.src1 = ExtractGPRIndex(inst.operands[1]);
                }
                if (inst.operandCount >= 3 && OperandIsImmediate(inst.operands[2])) {
                    mul.immediate = inst.operands[2].imm.value;
                } else if (inst.operandCount >= 2 && OperandIsImmediate(inst.operands[1])) {
                    mul.immediate = inst.operands[1].imm.value;
                }
                ir.push_back(mul);

                IRInstruction flagUpd{};
                flagUpd.op = IRInstruction::Op::FlagUpdate;
                flagUpd.guestAddress = inst.address;
                flagUpd.size = inst.operandSize;
                flagUpd.hasSideEffects = true;
                ir.push_back(flagUpd);
                continue;
            }
        }

        // === Two-byte opcode map (0F xx) ===
        if (inst.opcodeMap == OpcodeMap::TwoByte) {
            // MOVZX (0F B6, 0F B7), MOVSX (0F BE, 0F BF)
            if (inst.opcode == 0xB6 || inst.opcode == 0xB7 ||
                inst.opcode == 0xBE || inst.opcode == 0xBF) {
                if (inst.operandCount >= 2) {
                    const auto& dstOp = inst.operands[0];
                    const auto& srcOp = inst.operands[1];
                    if (OperandIsGPR(dstOp) && OperandIsGPR(srcOp)) {
                        IRInstruction mov{};
                        mov.op = IRInstruction::Op::MovReg;
                        mov.dst = ExtractGPRIndex(dstOp);
                        mov.src1 = ExtractGPRIndex(srcOp);
                        mov.guestAddress = inst.address;
                        mov.size = inst.operandSize;
                        ir.push_back(mov);
                    } else if (OperandIsGPR(dstOp) && OperandIsMemory(srcOp)) {
                        IRInstruction load{};
                        load.op = IRInstruction::Op::Load;
                        load.dst = ExtractGPRIndex(dstOp);
                        load.guestAddress = inst.address;
                        load.size = inst.operandSize;
                        load.hasSideEffects = true;
                        ir.push_back(load);
                    } else {
                        IRInstruction side{};
                        side.op = IRInstruction::Op::SideEffect;
                        side.guestAddress = inst.address;
                        side.hasSideEffects = true;
                        ir.push_back(side);
                    }
                }
                continue;
            }

            // IMUL r, r/m (0F AF)
            if (inst.opcode == 0xAF) {
                IRInstruction mul{};
                mul.op = IRInstruction::Op::Mul;
                mul.guestAddress = inst.address;
                mul.size = inst.operandSize;
                mul.hasSideEffects = true;
                if (inst.operandCount >= 1 && OperandIsGPR(inst.operands[0])) {
                    mul.dst = ExtractGPRIndex(inst.operands[0]);
                    mul.src1 = mul.dst;
                }
                if (inst.operandCount >= 2 && OperandIsGPR(inst.operands[1])) {
                    mul.src2 = ExtractGPRIndex(inst.operands[1]);
                }
                ir.push_back(mul);

                IRInstruction flagUpd{};
                flagUpd.op = IRInstruction::Op::FlagUpdate;
                flagUpd.guestAddress = inst.address;
                flagUpd.size = inst.operandSize;
                flagUpd.hasSideEffects = true;
                ir.push_back(flagUpd);
                continue;
            }

            // Jcc near (0F 80 - 0F 8F) — already handled by IsConditionalBranch above
            // Fall through to generic side effect
        }

        // If we didn't match any known pattern, emit as a generic side effect
        // to preserve soundness — never silently drop instructions
        IRInstruction side{};
        side.op = IRInstruction::Op::SideEffect;
        side.guestAddress = inst.address;
        side.size = inst.operandSize;
        side.hasSideEffects = true;
        ir.push_back(side);
    }

    SanitizeIR(ir);
    return ir;
    } catch (const std::bad_alloc&) {
        return {};
    }
}

// ============================================================================
// Constant Folding
// ============================================================================

void JITOptimizer::ConstantFold(std::vector<IRInstruction>& ir) noexcept {
    if (!m_impl || ir.empty()) {
        return;
    }

    // Track which registers currently hold known constant values
    struct RegConst {
        bool isConst = false;
        uint64_t value = 0;
    };
    std::array<RegConst, kMaxGuestGPR> known{};

    uint32_t foldCount = 0;

    for (auto& inst : ir) {
        // Instructions with side effects or targeting memory invalidate our knowledge
        if (inst.hasSideEffects && inst.op != IRInstruction::Op::FlagUpdate) {
            // Side effects may clobber any register; conservatively invalidate all
            // Exception: FlagUpdate doesn't clobber GPRs
            if (inst.op == IRInstruction::Op::SideEffect ||
                inst.op == IRInstruction::Op::Call) {
                known.fill(RegConst{});
            }
            continue;
        }

        if (inst.isDeadStore || inst.isFolded) {
            continue;
        }

        // MovImm: register gets a known constant
        if (inst.op == IRInstruction::Op::MovImm && inst.dst < kMaxGuestGPR) {
            known[inst.dst] = { true, inst.immediate };
            continue;
        }

        // MovReg: if source is constant, propagate
        if (inst.op == IRInstruction::Op::MovReg && inst.dst < kMaxGuestGPR && inst.src1 < kMaxGuestGPR) {
            if (known[inst.src1].isConst) {
                inst.op = IRInstruction::Op::MovImm;
                inst.immediate = known[inst.src1].value;
                inst.isFolded = true;
                known[inst.dst] = { true, inst.immediate };
                ++foldCount;
            } else {
                known[inst.dst] = { false, 0 };
            }
            continue;
        }

        // ALU operations: if both operands are constant, fold
        if (IsALUOp(inst.op) && inst.dst < kMaxGuestGPR) {
            bool src1Const = (inst.src1 < kMaxGuestGPR && known[inst.src1].isConst);
            bool src2Const = (inst.src2 == 0xFF) ? true : // immediate operand
                             (inst.src2 < kMaxGuestGPR && known[inst.src2].isConst);

            uint64_t val1 = src1Const ? known[inst.src1].value : 0;
            uint64_t val2 = (inst.src2 == 0xFF) ? inst.immediate :
                            (src2Const ? known[inst.src2].value : 0);

            // Unary ops: NOT, NEG — only need src1
            bool isUnary = (inst.op == IRInstruction::Op::Not || inst.op == IRInstruction::Op::Neg);

            if (isUnary && src1Const) {
                uint64_t result = EvaluateALU(inst.op, val1, 0, inst.size);
                inst.op = IRInstruction::Op::MovImm;
                inst.immediate = result;
                inst.src1 = 0xFF;
                inst.src2 = 0xFF;
                inst.isFolded = true;
                known[inst.dst] = { true, result };
                ++foldCount;
            } else if (!isUnary && src1Const && src2Const) {
                uint64_t result = EvaluateALU(inst.op, val1, val2, inst.size);
                inst.op = IRInstruction::Op::MovImm;
                inst.immediate = result;
                inst.src1 = 0xFF;
                inst.src2 = 0xFF;
                inst.isFolded = true;
                known[inst.dst] = { true, result };
                ++foldCount;
            } else {
                // Result is not a known constant
                known[inst.dst] = { false, 0 };
            }
            continue;
        }

        // Load from memory: result is unknown
        if (inst.op == IRInstruction::Op::Load && inst.dst < kMaxGuestGPR) {
            known[inst.dst] = { false, 0 };
            continue;
        }

        // Any other write to a register: invalidate
        if (WritesRegister(inst) && inst.dst < kMaxGuestGPR) {
            known[inst.dst] = { false, 0 };
        }
    }

    std::unique_lock lock(m_impl->mutex);
    m_impl->stats.constantsFolded += foldCount;
}

// ============================================================================
// Dead Store Elimination
// ============================================================================

void JITOptimizer::EliminateDeadStores(std::vector<IRInstruction>& ir) noexcept {
    if (!m_impl || ir.size() < 2) {
        return;
    }

    // Backward pass: track which registers are read before being written
    // A write to a register that is overwritten before any read is a dead store.
    //
    // NEVER eliminate:
    //   - Memory stores
    //   - Instructions with side effects
    //   - FlagUpdate (flags may be read by later conditional branches)

    std::array<bool, kMaxGuestGPR> isRead{};   // true if register is read before next write
    isRead.fill(true); // Conservatively assume all live at trace exit

    uint32_t eliminatedCount = 0;

    for (auto it = ir.rbegin(); it != ir.rend(); ++it) {
        auto& inst = *it;

        if (inst.isDeadStore || inst.isFolded) {
            continue;
        }

        // Side-effect instructions are never dead
        if (inst.hasSideEffects) {
            // Mark all source registers as read
            if (inst.src1 < kMaxGuestGPR) { isRead[inst.src1] = true; }
            if (inst.src2 < kMaxGuestGPR) { isRead[inst.src2] = true; }
            // Store also reads dst (value being stored)
            if (inst.op == IRInstruction::Op::Store && inst.dst < kMaxGuestGPR) {
                isRead[inst.dst] = true;
            }
            continue;
        }

        // Memory ops: never eliminate
        if (inst.op == IRInstruction::Op::Store || inst.op == IRInstruction::Op::Load) {
            if (inst.src1 < kMaxGuestGPR) { isRead[inst.src1] = true; }
            if (inst.src2 < kMaxGuestGPR) { isRead[inst.src2] = true; }
            if (inst.op == IRInstruction::Op::Load && inst.dst < kMaxGuestGPR) {
                // Load writes dst — if not read, it could be dead, but loads
                // may have side effects so we keep them
                isRead[inst.dst] = true;
            }
            continue;
        }

        // Check if this instruction writes a register
        if (WritesRegister(inst) && inst.dst < kMaxGuestGPR) {
            if (!isRead[inst.dst]) {
                // Register is written but never read before next write — dead store
                inst.isDeadStore = true;
                ++eliminatedCount;
                continue;
            }
            // Mark dst as not read (we just defined it)
            isRead[inst.dst] = false;
        }

        // Mark source registers as read
        if (inst.src1 < kMaxGuestGPR) { isRead[inst.src1] = true; }
        if (inst.src2 < kMaxGuestGPR) { isRead[inst.src2] = true; }
    }

    std::unique_lock lock(m_impl->mutex);
    m_impl->stats.deadStoresEliminated += eliminatedCount;
}

// ============================================================================
// Constant Propagation
// ============================================================================

void JITOptimizer::PropagateConstants(std::vector<IRInstruction>& ir) noexcept {
    if (!m_impl || ir.empty()) {
        return;
    }

    // Forward pass: when a register is known to hold a constant, replace
    // uses of that register with the constant value (convert to immediate form).
    struct RegConst {
        bool isConst = false;
        uint64_t value = 0;
    };
    std::array<RegConst, kMaxGuestGPR> known{};

    for (auto& inst : ir) {
        if (inst.isDeadStore || inst.isFolded) {
            continue;
        }

        // Track MovImm as constant definitions
        if (inst.op == IRInstruction::Op::MovImm && inst.dst < kMaxGuestGPR) {
            known[inst.dst] = { true, inst.immediate };
            continue;
        }

        // If src1 is a known constant and the op can accept an immediate form
        if (inst.src1 < kMaxGuestGPR && known[inst.src1].isConst) {
            // For ALU ops where src1 == dst, we can't easily convert to immediate-only
            // because x86 ALU ops are typically dst = dst op src. But we propagate
            // knowledge for the constant folding pass.
        }

        // For ALU ops with src2 as a register holding a known constant,
        // convert to immediate form
        if (IsALUOp(inst.op) && inst.src2 < kMaxGuestGPR && known[inst.src2].isConst) {
            inst.immediate = known[inst.src2].value;
            inst.src2 = 0xFF; // Mark as immediate
        }

        // Side effects / calls invalidate all constants
        if (inst.op == IRInstruction::Op::SideEffect || inst.op == IRInstruction::Op::Call) {
            known.fill(RegConst{});
            continue;
        }

        // Any write to a register: update knowledge
        if (WritesRegister(inst) && inst.dst < kMaxGuestGPR) {
            if (inst.op != IRInstruction::Op::MovImm) {
                known[inst.dst] = { false, 0 };
            }
        }
    }
}

// ============================================================================
// Strength Reduction
// ============================================================================

void JITOptimizer::ReduceStrength(std::vector<IRInstruction>& ir) noexcept {
    if (!m_impl || ir.empty()) {
        return;
    }

    for (auto& inst : ir) {
        if (inst.isDeadStore || inst.isFolded || inst.hasSideEffects) {
            continue;
        }

        // Multiply by power of 2 → shift left
        if (inst.op == IRInstruction::Op::Mul && inst.src2 == 0xFF && inst.immediate != 0) {
            uint64_t imm = inst.immediate;
            if ((imm & (imm - 1)) == 0) {
                // Power of 2
                uint32_t shift = 0;
                uint64_t tmp = imm;
                while (tmp > 1) { tmp >>= 1; ++shift; }
                inst.op = IRInstruction::Op::Shl;
                inst.immediate = shift;
            }
        }

        // Add 0 → Nop (but preserve flag updates that follow)
        if (inst.op == IRInstruction::Op::Add && inst.src2 == 0xFF && inst.immediate == 0) {
            inst.op = IRInstruction::Op::Nop;
            inst.isDeadStore = true;
        }

        // Sub 0 → Nop
        if (inst.op == IRInstruction::Op::Sub && inst.src2 == 0xFF && inst.immediate == 0) {
            inst.op = IRInstruction::Op::Nop;
            inst.isDeadStore = true;
        }

        // XOR reg, reg → MovImm 0 (common zeroing idiom)
        if (inst.op == IRInstruction::Op::Xor && inst.dst < kMaxGuestGPR &&
            inst.src1 == inst.dst && inst.src2 == inst.dst) {
            inst.op = IRInstruction::Op::MovImm;
            inst.immediate = 0;
            inst.src1 = 0xFF;
            inst.src2 = 0xFF;
        }

        // Shift by 0 → Nop
        if ((inst.op == IRInstruction::Op::Shl || inst.op == IRInstruction::Op::Shr ||
             inst.op == IRInstruction::Op::Sar || inst.op == IRInstruction::Op::Rol ||
             inst.op == IRInstruction::Op::Ror) &&
            inst.src2 == 0xFF && inst.immediate == 0) {
            inst.op = IRInstruction::Op::Nop;
            inst.isDeadStore = true;
        }

        // AND with all-ones mask for operand size → Nop
        if (inst.op == IRInstruction::Op::And && inst.src2 == 0xFF) {
            uint64_t mask = 0;
            switch (inst.size) {
                case OperandSize::Size8:  mask = 0xFFULL; break;
                case OperandSize::Size16: mask = 0xFFFFULL; break;
                case OperandSize::Size32: mask = 0xFFFFFFFFULL; break;
                case OperandSize::Size64: mask = 0xFFFFFFFFFFFFFFFFULL; break;
            }
            if (inst.immediate == mask) {
                inst.op = IRInstruction::Op::Nop;
                inst.isDeadStore = true;
            }
        }

        // OR with 0 → Nop
        if (inst.op == IRInstruction::Op::Or && inst.src2 == 0xFF && inst.immediate == 0) {
            inst.op = IRInstruction::Op::Nop;
            inst.isDeadStore = true;
        }
    }
}

// ============================================================================
// Register Allocation
// ============================================================================

std::vector<RegisterMapping> JITOptimizer::AllocateRegisters(
    const std::vector<IRInstruction>& ir,
    uint32_t availableHostRegs) const noexcept
{
    std::vector<RegisterMapping> mappings;
    if (!m_impl || ir.empty() || availableHostRegs == 0) {
        return mappings;
    }

    try {
    const uint32_t maxAlloc = std::min(availableHostRegs, static_cast<uint32_t>(kHostAllocRegs.size()));
    mappings.reserve(maxAlloc);

    // Count register usage frequency across the trace
    std::array<uint32_t, kMaxGuestGPR> useCount{};
    std::array<bool, kMaxGuestGPR> hasWrite{};

    for (const auto& inst : ir) {
        if (inst.isDeadStore) {
            continue;
        }
        if (inst.src1 < kMaxGuestGPR) { ++useCount[inst.src1]; }
        if (inst.src2 < kMaxGuestGPR) { ++useCount[inst.src2]; }
        if (inst.dst < kMaxGuestGPR) {
            ++useCount[inst.dst];
            if (WritesRegister(inst)) {
                hasWrite[inst.dst] = true;
            }
        }
        // Store reads dst as value
        if (inst.op == IRInstruction::Op::Store && inst.dst < kMaxGuestGPR) {
            ++useCount[inst.dst];
        }
    }

    // Sort guest GPRs by usage count (descending) — skip RSP (index 4) as it's
    // managed specially by the emulator and should not be allocated to a host reg
    struct GPRUsage {
        uint8_t gprIndex;
        uint32_t count;
    };

    std::array<GPRUsage, kMaxGuestGPR> sorted{};
    for (uint8_t i = 0; i < kMaxGuestGPR; ++i) {
        sorted[i] = { i, useCount[i] };
    }

    std::sort(sorted.begin(), sorted.end(),
        [](const GPRUsage& a, const GPRUsage& b) { return a.count > b.count; });

    uint32_t allocated = 0;
    for (uint32_t i = 0; i < kMaxGuestGPR && allocated < maxAlloc; ++i) {
        const auto& entry = sorted[i];
        if (entry.count == 0) {
            break;
        }

        // Skip RSP — stack pointer is not allocatable
        if (entry.gprIndex == static_cast<uint8_t>(GPR::RSP)) {
            continue;
        }

        RegisterMapping mapping{};
        mapping.guestGPR = entry.gprIndex;
        mapping.hostReg = kHostAllocRegs[allocated];
        mapping.isDirty = hasWrite[entry.gprIndex];
        mapping.isLive = true;
        mappings.push_back(mapping);
        ++allocated;
    }

    // Update stats
    {
        std::unique_lock lock(m_impl->mutex);
        m_impl->stats.registersAllocated += allocated;
    }

    return mappings;
    } catch (const std::bad_alloc&) {
        return {};
    }
}

// ============================================================================
// Self-Modifying Code Detection
// ============================================================================

void JITOptimizer::TrackCompiledBlock(GuestAddress start, GuestSize size) noexcept {
    GuestAddress ignoredEnd = 0;
    if (!m_impl || !RangeEnd(start, size, ignoredEnd)) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);

    for (auto& range : m_impl->compiledRanges) {
        if (range.start == start) {
            range.size = size;
            return;
        }
    }

    if (m_impl->compiledRanges.size() >= kMaxCompiledRangeEntries) {
        const size_t halfSize = m_impl->compiledRanges.size() / 2;
        m_impl->compiledRanges.erase(
            m_impl->compiledRanges.begin(),
            m_impl->compiledRanges.begin() + static_cast<ptrdiff_t>(halfSize));
    }

    m_impl->compiledRanges.push_back({ start, size });
}

void JITOptimizer::ForgetCompiledBlock(GuestAddress start) noexcept {
    if (!m_impl || start == 0) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    const auto removeBegin = std::remove_if(
        m_impl->compiledRanges.begin(),
        m_impl->compiledRanges.end(),
        [start](const BlockRange& range) noexcept {
            return range.start == start;
        });
    m_impl->compiledRanges.erase(removeBegin, m_impl->compiledRanges.end());
}

void JITOptimizer::OnMemoryWrite(GuestAddress addr, GuestSize size) noexcept {
    GuestAddress writeEnd = 0;
    if (!m_impl || !RangeEnd(addr, size, writeEnd)) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);

    // Cap tracking entries to prevent unbounded memory growth
    if (m_impl->writeRanges.size() >= kMaxWriteTrackEntries) {
        // Evict oldest half to make room — amortized O(1)
        const size_t halfSize = m_impl->writeRanges.size() / 2;
        m_impl->writeRanges.erase(
            m_impl->writeRanges.begin(),
            m_impl->writeRanges.begin() + static_cast<ptrdiff_t>(halfSize));
    }

    // Coalesce with last entry if adjacent or overlapping
    if (!m_impl->writeRanges.empty()) {
        auto& last = m_impl->writeRanges.back();
        GuestAddress lastEnd = 0;
        if (RangeEnd(last.start, last.size, lastEnd) && addr >= last.start && addr <= lastEnd) {
            // Overlapping or adjacent — extend
            const GuestAddress newEnd = std::max(lastEnd, writeEnd);
            last.size = newEnd - last.start;
            return;
        }
    }

    m_impl->writeRanges.push_back({ addr, size });
}

std::vector<GuestAddress> JITOptimizer::GetInvalidatedBlocks() const noexcept {
    std::vector<GuestAddress> result;
    if (!m_impl) {
        return result;
    }

    std::shared_lock lock(m_impl->mutex);

    if (m_impl->writeRanges.empty() || m_impl->compiledRanges.empty()) {
        return result;
    }

    try {
    result.reserve(std::min(m_impl->compiledRanges.size(), m_impl->writeRanges.size()));

    // Check each compiled block against all write ranges
    for (const auto& block : m_impl->compiledRanges) {
        for (const auto& wr : m_impl->writeRanges) {
            // Overlap check: two ranges [a, a+sa) and [b, b+sb) overlap iff
            // a < b+sb && b < a+sa
            if (RangesOverlap(block.start, block.size, wr.start, wr.size)) {
                result.push_back(block.start);
                break; // No need to check more write ranges for this block
            }
        }
    }
    } catch (const std::bad_alloc&) {
        result.clear();
    }

    return result;
}

void JITOptimizer::ClearWriteTracking() noexcept {
    if (!m_impl) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    m_impl->writeRanges.clear();
}

// ============================================================================
// JIT Profiling
// ============================================================================

bool JITOptimizer::ShouldCompile(
    GuestAddress addr,
    uint32_t executionCount,
    uint32_t hotThreshold) const noexcept
{
    if (!m_impl || addr == 0 || hotThreshold == 0) {
        return false;
    }

    return executionCount >= hotThreshold;
}

// ============================================================================
// Statistics
// ============================================================================

OptimizationStats JITOptimizer::GetStats() const noexcept {
    if (!m_impl) {
        return OptimizationStats{};
    }

    std::shared_lock lock(m_impl->mutex);
    return m_impl->stats;
}

void JITOptimizer::ResetStats() noexcept {
    if (!m_impl) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    m_impl->stats = OptimizationStats{};
}

} // namespace Phantom
