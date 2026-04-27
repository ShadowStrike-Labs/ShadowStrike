/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * JITCompiler.cpp — Just-In-Time compilation framework for hot paths
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "JITCompiler.hpp"

#include "../../Common/Constants.hpp"

#include <array>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <shared_mutex>

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace Phantom {

namespace {

static constexpr uint32_t kLookupTableSize = 8192;
static constexpr uint32_t kLookupMask = kLookupTableSize - 1;
static constexpr uint32_t kMaxCompiledInstrPerBlock = 64;
static constexpr uint32_t kMinJitSlotSize = 128;
static constexpr uint32_t kMaxJitCodeCacheSize = 64u * 1024u * 1024u;

[[nodiscard]] uint64_t MaskToSize(uint64_t value, OperandSize size) noexcept {
    switch (size) {
        case OperandSize::Size8:  return value & 0xFFULL;
        case OperandSize::Size16: return value & 0xFFFFULL;
        case OperandSize::Size32: return value & 0xFFFFFFFFULL;
        case OperandSize::Size64: return value;
    }
    return value;
}

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

[[nodiscard]] bool IsValidSegmentRegister(SegReg segment) noexcept {
    return CPUState::IsValidSegment(segment);
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

void UpdateAddFlags(EFlags& flags, uint64_t lhs, uint64_t rhs, uint64_t result, OperandSize size) noexcept {
    switch (size) {
        case OperandSize::Size8:
            flags.UpdateFlagsAdd8(static_cast<uint8_t>(lhs), static_cast<uint8_t>(rhs), static_cast<uint8_t>(result));
            break;
        case OperandSize::Size16:
            flags.UpdateFlagsAdd16(static_cast<uint16_t>(lhs), static_cast<uint16_t>(rhs), static_cast<uint16_t>(result));
            break;
        case OperandSize::Size32:
            flags.UpdateFlagsAdd32(static_cast<uint32_t>(lhs), static_cast<uint32_t>(rhs), static_cast<uint32_t>(result));
            break;
        case OperandSize::Size64:
            flags.UpdateFlagsAdd64(lhs, rhs, result);
            break;
    }
}

void UpdateSubFlags(EFlags& flags, uint64_t lhs, uint64_t rhs, uint64_t result, OperandSize size) noexcept {
    switch (size) {
        case OperandSize::Size8:
            flags.UpdateFlagsSub8(static_cast<uint8_t>(lhs), static_cast<uint8_t>(rhs), static_cast<uint8_t>(result));
            break;
        case OperandSize::Size16:
            flags.UpdateFlagsSub16(static_cast<uint16_t>(lhs), static_cast<uint16_t>(rhs), static_cast<uint16_t>(result));
            break;
        case OperandSize::Size32:
            flags.UpdateFlagsSub32(static_cast<uint32_t>(lhs), static_cast<uint32_t>(rhs), static_cast<uint32_t>(result));
            break;
        case OperandSize::Size64:
            flags.UpdateFlagsSub64(lhs, rhs, result);
            break;
    }
}

void UpdateLogicFlags(EFlags& flags, uint64_t result, OperandSize size) noexcept {
    switch (size) {
        case OperandSize::Size8:
            flags.UpdateFlagsLogic8(static_cast<uint8_t>(result));
            break;
        case OperandSize::Size16:
            flags.UpdateFlagsLogic16(static_cast<uint16_t>(result));
            break;
        case OperandSize::Size32:
            flags.UpdateFlagsLogic32(static_cast<uint32_t>(result));
            break;
        case OperandSize::Size64:
            flags.UpdateFlagsLogic64(result);
            break;
    }
}

[[nodiscard]] GuestAddress CalculateEffectiveAddress(
    CPUState& cpu,
    const DecodedOperand& op,
    const DecodedInstruction& inst) noexcept
{
    if (op.type != OperandType::Memory) {
        return kGuestInvalid;
    }

    uint64_t addr = 0;
    if (op.mem.ripRelative) {
        const GuestAddress nextRip = inst.NextRIP();
        if (nextRip == kGuestInvalid || !AddSigned(nextRip, op.mem.displacement, addr)) {
            return kGuestInvalid;
        }
    } else {
        if (op.mem.hasBase) {
            if (!IsValidGprIndex(op.mem.baseReg)) {
                return kGuestInvalid;
            }
            addr = cpu.GetReg64(static_cast<GPR>(op.mem.baseReg));
        }
        if (op.mem.hasIndex) {
            if (!IsValidGprIndex(op.mem.indexReg)) {
                return kGuestInvalid;
            }
            uint64_t scaledIndex = 0;
            if (!ScaleIndex(cpu.GetReg64(static_cast<GPR>(op.mem.indexReg)), op.mem.scale, scaledIndex)
                || !AddUnsigned(addr, scaledIndex, addr)) {
                return kGuestInvalid;
            }
        }
        if (!AddSigned(addr, op.mem.displacement, addr)) {
            return kGuestInvalid;
        }
    }

    if (inst.addressSize == AddressSize::Addr32) {
        addr &= 0xFFFFFFFFULL;
    } else if (inst.addressSize == AddressSize::Addr16) {
        addr &= 0xFFFFULL;
    } else if (inst.addressSize != AddressSize::Addr64) {
        return kGuestInvalid;
    }

    if (op.mem.segment == SegReg::FS || op.mem.segment == SegReg::GS) {
        if (!AddUnsigned(addr, cpu.GetSegment(op.mem.segment).base, addr)) {
            return kGuestInvalid;
        }
    } else if (!IsValidSegmentRegister(op.mem.segment)) {
        return kGuestInvalid;
    }

    return addr;
}

[[nodiscard]] bool IsValidRegisterOperand(const DecodedOperand& op) noexcept {
    if (op.type != OperandType::Register || op.reg.regType != RegType::GPR || !IsSupportedOperandSize(op.size)) {
        return false;
    }
    if (op.reg.isHighByte) {
        return op.size == OperandSize::Size8 && op.reg.regIndex >= 4 && op.reg.regIndex <= 7;
    }
    return IsValidGprIndex(op.reg.regIndex);
}

[[nodiscard]] bool IsReadableCompiledOperand(const DecodedOperand& op) noexcept {
    if (!IsSupportedOperandSize(op.size)) {
        return false;
    }
    if (op.type == OperandType::Register) {
        return IsValidRegisterOperand(op);
    }
    return op.type == OperandType::Immediate || op.type == OperandType::RelativeOffset;
}

[[nodiscard]] bool IsWritableCompiledOperand(const DecodedOperand& op) noexcept {
    return IsValidRegisterOperand(op);
}

[[nodiscard]] ErrorCode ReadOperandValue(
    CPUState& cpu,
    VirtualMemory& memory,
    const DecodedOperand& op,
    const DecodedInstruction& inst,
    uint64_t& value) noexcept
{
    value = 0;
    if (!IsSupportedOperandSize(op.size)) {
        return ErrorCode::InvalidOperandSize;
    }

    switch (op.type) {
        case OperandType::Register:
            if (!IsValidRegisterOperand(op)) {
                return ErrorCode::InvalidOperandSize;
            }
            if (op.reg.isHighByte) {
                value = cpu.GetReg8High(op.reg.regIndex);
            } else {
                value = cpu.GetRegBySize(static_cast<GPR>(op.reg.regIndex), op.size);
            }
            return ErrorCode::Success;

        case OperandType::Memory: {
            const auto address = CalculateEffectiveAddress(cpu, op, inst);
            if (address == kGuestInvalid) {
                return ErrorCode::InvalidAddress;
            }
            return memory.Read(address, &value, OperandByteWidth(op.size));
        }

        case OperandType::Immediate:
            value = op.imm.value;
            return ErrorCode::Success;

        case OperandType::RelativeOffset:
            value = static_cast<uint64_t>(op.rel.offset);
            return ErrorCode::Success;

        default:
            return ErrorCode::UnsupportedOpcode;
    }
}

[[nodiscard]] ErrorCode WriteOperandValue(
    CPUState& cpu,
    VirtualMemory& memory,
    const DecodedOperand& op,
    const DecodedInstruction& inst,
    uint64_t value) noexcept
{
    if (!IsSupportedOperandSize(op.size)) {
        return ErrorCode::InvalidOperandSize;
    }

    value = MaskToSize(value, op.size);

    switch (op.type) {
        case OperandType::Register:
            if (!IsValidRegisterOperand(op)) {
                return ErrorCode::InvalidOperandSize;
            }
            if (op.reg.isHighByte) {
                cpu.SetReg8High(op.reg.regIndex, static_cast<uint8_t>(value));
            } else {
                cpu.SetRegBySize(static_cast<GPR>(op.reg.regIndex), value, op.size);
            }
            return ErrorCode::Success;

        case OperandType::Memory: {
            const auto address = CalculateEffectiveAddress(cpu, op, inst);
            if (address == kGuestInvalid) {
                return ErrorCode::InvalidAddress;
            }
            return memory.Write(address, &value, OperandByteWidth(op.size));
        }

        default:
            return ErrorCode::UnsupportedOpcode;
    }
}

[[nodiscard]] bool IsControlFlowInstruction(const DecodedInstruction& inst) noexcept {
    if (inst.opcodeMap == OpcodeMap::OneByte) {
        const uint8_t op = inst.opcode;
        if ((op >= 0x70 && op <= 0x7F)
            || op == 0xC2 || op == 0xC3 || op == 0xCA || op == 0xCB
            || op == 0xE8 || op == 0xE9 || op == 0xEA
            || op == 0xEB || (op >= 0xE0 && op <= 0xE3)
            || op == 0xCC || op == 0xCD || op == 0xCE || op == 0xCF
            || op == 0x9A || op == 0xFF) {
            return true;
        }
    }

    if (inst.opcodeMap == OpcodeMap::TwoByte && inst.opcode >= 0x80 && inst.opcode <= 0x8F) {
        return true;
    }

    return false;
}

[[nodiscard]] bool SupportsCompiledInstruction(const DecodedInstruction& inst) noexcept {
    if (inst.length == 0 || inst.NextRIP() == kGuestInvalid || inst.prefixes.hasLock) {
        return false;
    }

    if (IsControlFlowInstruction(inst)) {
        return false;
    }

    if (inst.opcodeMap == OpcodeMap::TwoByte) {
        return inst.operandCount == 2
            && (inst.opcode == 0xB6 || inst.opcode == 0xB7)
            && inst.HasOperand(0)
            && inst.HasOperand(1)
            && IsWritableCompiledOperand(inst.operands[0])
            && IsValidRegisterOperand(inst.operands[1])
            && ((inst.opcode == 0xB6 && inst.operands[1].size == OperandSize::Size8)
                || (inst.opcode == 0xB7 && inst.operands[1].size == OperandSize::Size16));
    }

    if (inst.opcodeMap != OpcodeMap::OneByte) {
        return false;
    }

    const uint8_t op = inst.opcode;
    if (op == 0x90 || op == 0x9B) {
        return inst.operandCount == 0;
    }

    if ((op >= 0xB0 && op <= 0xBF) || op == 0x88 || op == 0x89 || op == 0x8A || op == 0x8B
        || op == 0xC6 || op == 0xC7
        || op == 0x01 || op == 0x03 || op == 0x05 || op == 0x29 || op == 0x2B
        || op == 0x2D || op == 0x31 || op == 0x33 || op == 0x35) {
        return inst.operandCount == 2
            && inst.HasOperand(0)
            && inst.HasOperand(1)
            && IsWritableCompiledOperand(inst.operands[0])
            && IsReadableCompiledOperand(inst.operands[1]);
    }

    if ((op == 0x81 || op == 0x83) && inst.operandCount == 2) {
        return inst.opcodeExt == 0
            && inst.HasOperand(0)
            && inst.HasOperand(1)
            && IsWritableCompiledOperand(inst.operands[0])
            && IsReadableCompiledOperand(inst.operands[1]);
    }

    return false;
}

[[nodiscard]] ErrorCode ExecuteCompiledInstruction(
    CPUState& cpu,
    VirtualMemory& memory,
    const DecodedInstruction& inst) noexcept
{
    uint64_t lhs = 0;
    uint64_t rhs = 0;

    if (inst.opcodeMap != OpcodeMap::OneByte) {
        if (inst.opcodeMap == OpcodeMap::TwoByte && inst.opcode == 0xB6 && inst.operandCount == 2) {
            if (ReadOperandValue(cpu, memory, inst.operands[1], inst, rhs) != ErrorCode::Success) {
                return ErrorCode::UnsupportedOpcode;
            }
            if (WriteOperandValue(cpu, memory, inst.operands[0], inst, rhs & 0xFFULL) != ErrorCode::Success) {
                return ErrorCode::UnsupportedOpcode;
            }
            cpu.SetRIP(inst.NextRIP());
            return ErrorCode::Success;
        }

        if (inst.opcodeMap == OpcodeMap::TwoByte && inst.opcode == 0xB7 && inst.operandCount == 2) {
            if (ReadOperandValue(cpu, memory, inst.operands[1], inst, rhs) != ErrorCode::Success) {
                return ErrorCode::UnsupportedOpcode;
            }
            if (WriteOperandValue(cpu, memory, inst.operands[0], inst, rhs & 0xFFFFULL) != ErrorCode::Success) {
                return ErrorCode::UnsupportedOpcode;
            }
            cpu.SetRIP(inst.NextRIP());
            return ErrorCode::Success;
        }

        return ErrorCode::UnsupportedOpcode;
    }

    const uint8_t op = inst.opcode;

    if (op == 0x90 || op == 0x9B) {
        cpu.SetRIP(inst.NextRIP());
        return ErrorCode::Success;
    }

    if ((op >= 0xB0 && op <= 0xBF) || op == 0x88 || op == 0x89 || op == 0x8A || op == 0x8B
        || op == 0x8D || op == 0xC6 || op == 0xC7) {
        if (op == 0x8D && inst.operandCount == 2 && inst.operands[1].type == OperandType::Memory) {
            const auto address = CalculateEffectiveAddress(cpu, inst.operands[1], inst);
            if (WriteOperandValue(cpu, memory, inst.operands[0], inst, address) != ErrorCode::Success) {
                return ErrorCode::UnsupportedOpcode;
            }
            cpu.SetRIP(inst.NextRIP());
            return ErrorCode::Success;
        }

        if (inst.operandCount < 2) {
            return ErrorCode::UnsupportedOpcode;
        }

        if (ReadOperandValue(cpu, memory, inst.operands[1], inst, rhs) != ErrorCode::Success) {
            return ErrorCode::UnsupportedOpcode;
        }
        if (WriteOperandValue(cpu, memory, inst.operands[0], inst, rhs) != ErrorCode::Success) {
            return ErrorCode::UnsupportedOpcode;
        }

        cpu.SetRIP(inst.NextRIP());
        return ErrorCode::Success;
    }

    if (op == 0x01 || op == 0x03 || op == 0x05 || op == 0x81 || op == 0x83) {
        if (inst.operandCount < 2) {
            return ErrorCode::UnsupportedOpcode;
        }
        if (op == 0x81 || op == 0x83) {
            if (inst.opcodeExt != 0) {
                return ErrorCode::UnsupportedOpcode;
            }
        }

        if (ReadOperandValue(cpu, memory, inst.operands[0], inst, lhs) != ErrorCode::Success
            || ReadOperandValue(cpu, memory, inst.operands[1], inst, rhs) != ErrorCode::Success) {
            return ErrorCode::UnsupportedOpcode;
        }

        const uint64_t result = MaskToSize(lhs + rhs, inst.operands[0].size);
        UpdateAddFlags(cpu.eflags, lhs, rhs, result, inst.operands[0].size);
        if (WriteOperandValue(cpu, memory, inst.operands[0], inst, result) != ErrorCode::Success) {
            return ErrorCode::UnsupportedOpcode;
        }
        cpu.SetRIP(inst.NextRIP());
        return ErrorCode::Success;
    }

    if (op == 0x29 || op == 0x2B || op == 0x2D) {
        if (inst.operandCount < 2) {
            return ErrorCode::UnsupportedOpcode;
        }
        if (ReadOperandValue(cpu, memory, inst.operands[0], inst, lhs) != ErrorCode::Success
            || ReadOperandValue(cpu, memory, inst.operands[1], inst, rhs) != ErrorCode::Success) {
            return ErrorCode::UnsupportedOpcode;
        }

        const uint64_t result = MaskToSize(lhs - rhs, inst.operands[0].size);
        UpdateSubFlags(cpu.eflags, lhs, rhs, result, inst.operands[0].size);
        if (WriteOperandValue(cpu, memory, inst.operands[0], inst, result) != ErrorCode::Success) {
            return ErrorCode::UnsupportedOpcode;
        }
        cpu.SetRIP(inst.NextRIP());
        return ErrorCode::Success;
    }

    if (op == 0x31 || op == 0x33 || op == 0x35) {
        if (inst.operandCount < 2) {
            return ErrorCode::UnsupportedOpcode;
        }
        if (ReadOperandValue(cpu, memory, inst.operands[0], inst, lhs) != ErrorCode::Success
            || ReadOperandValue(cpu, memory, inst.operands[1], inst, rhs) != ErrorCode::Success) {
            return ErrorCode::UnsupportedOpcode;
        }

        const uint64_t result = MaskToSize(lhs ^ rhs, inst.operands[0].size);
        UpdateLogicFlags(cpu.eflags, result, inst.operands[0].size);
        if (WriteOperandValue(cpu, memory, inst.operands[0], inst, result) != ErrorCode::Success) {
            return ErrorCode::UnsupportedOpcode;
        }
        cpu.SetRIP(inst.NextRIP());
        return ErrorCode::Success;
    }

    return ErrorCode::UnsupportedOpcode;
}

} // namespace

X64Emitter::X64Emitter(uint8_t* buffer, uint32_t capacity) noexcept
    : m_buffer(buffer)
    , m_capacity(capacity)
{}

bool X64Emitter::CanEmit(uint32_t bytes) const noexcept {
    return m_buffer != nullptr && m_offset <= m_capacity && bytes <= (m_capacity - m_offset);
}

void X64Emitter::EmitRex(bool w, uint8_t r, uint8_t x, uint8_t b) noexcept {
    uint8_t rex = 0x40;
    if (w) rex |= 0x08;
    if ((r & 0x08) != 0) rex |= 0x04;
    if ((x & 0x08) != 0) rex |= 0x02;
    if ((b & 0x08) != 0) rex |= 0x01;
    if (rex != 0x40) {
        EmitByte(rex);
    }
}

void X64Emitter::EmitByte(uint8_t b) noexcept {
    if (!CanEmit(1)) {
        m_failed = true;
        return;
    }
    m_buffer[m_offset++] = b;
}

void X64Emitter::EmitDword(uint32_t v) noexcept {
    if (!CanEmit(4)) {
        m_failed = true;
        return;
    }
    std::memcpy(m_buffer + m_offset, &v, sizeof(v));
    m_offset += sizeof(v);
}

void X64Emitter::EmitQword(uint64_t v) noexcept {
    if (!CanEmit(8)) {
        m_failed = true;
        return;
    }
    std::memcpy(m_buffer + m_offset, &v, sizeof(v));
    m_offset += sizeof(v);
}

void X64Emitter::EmitPush(uint8_t reg) noexcept {
    if ((reg & 0x08) != 0) {
        EmitByte(0x41);
    }
    EmitByte(static_cast<uint8_t>(0x50 + (reg & 0x07)));
}

void X64Emitter::EmitPop(uint8_t reg) noexcept {
    if ((reg & 0x08) != 0) {
        EmitByte(0x41);
    }
    EmitByte(static_cast<uint8_t>(0x58 + (reg & 0x07)));
}

void X64Emitter::EmitMovRegImm64(uint8_t reg, uint64_t imm) noexcept {
    EmitRex(true, 0, 0, reg);
    EmitByte(static_cast<uint8_t>(0xB8 + (reg & 0x07)));
    EmitQword(imm);
}

void X64Emitter::EmitMovRegReg(uint8_t dst, uint8_t src) noexcept {
    EmitRex(true, src, 0, dst);
    EmitByte(0x89);
    EmitByte(static_cast<uint8_t>(0xC0 | ((src & 0x07) << 3) | (dst & 0x07)));
}

void X64Emitter::EmitMovRegMem(uint8_t dst, uint8_t base, int32_t disp) noexcept {
    EmitRex(true, dst, 0, base);
    EmitByte(0x8B);
    EmitByte(static_cast<uint8_t>(0x80 | ((dst & 0x07) << 3) | (base & 0x07)));
    EmitDword(static_cast<uint32_t>(disp));
}

void X64Emitter::EmitMovMemReg(uint8_t base, int32_t disp, uint8_t src) noexcept {
    EmitRex(true, src, 0, base);
    EmitByte(0x89);
    EmitByte(static_cast<uint8_t>(0x80 | ((src & 0x07) << 3) | (base & 0x07)));
    EmitDword(static_cast<uint32_t>(disp));
}

void X64Emitter::EmitAddRegImm32(uint8_t reg, int32_t imm) noexcept {
    EmitRex(true, 0, 0, reg);
    EmitByte(0x81);
    EmitByte(static_cast<uint8_t>(0xC0 | (reg & 0x07)));
    EmitDword(static_cast<uint32_t>(imm));
}

void X64Emitter::EmitSubRegImm32(uint8_t reg, int32_t imm) noexcept {
    EmitRex(true, 0, 0, reg);
    EmitByte(0x81);
    EmitByte(static_cast<uint8_t>(0xE8 | (reg & 0x07)));
    EmitDword(static_cast<uint32_t>(imm));
}

void X64Emitter::EmitCall(void* target) noexcept {
    EmitMovRegImm64(0, reinterpret_cast<uint64_t>(target));
    EmitByte(0xFF);
    EmitByte(0xD0);
}

void X64Emitter::EmitRet() noexcept {
    EmitByte(0xC3);
}

void X64Emitter::EmitJmp(int32_t offset) noexcept {
    EmitByte(0xE9);
    EmitDword(static_cast<uint32_t>(offset));
}

void X64Emitter::EmitNop(uint32_t count) noexcept {
    for (uint32_t i = 0; i < count; ++i) {
        EmitByte(0x90);
    }
}

uint32_t X64Emitter::GetOffset() const noexcept {
    return m_offset;
}

uint8_t* X64Emitter::GetBuffer() const noexcept {
    return m_buffer;
}

bool X64Emitter::Failed() const noexcept {
    return m_failed;
}

struct JITCompiler::Impl {
    struct RuntimeBlock {
        CompiledBlock compiled{};
        uint32_t slotIndex = 0;
        uint32_t compiledInstrCount = 0;
        std::array<DecodedInstruction, kMaxCompiledInstrPerBlock> instructions{};
    };

    mutable std::shared_mutex mutex;
    JITStrategy strategy = JITStrategy::Disabled;

    uint8_t* codeCache = nullptr;
    uint32_t codeCacheSize = 0;
    uint32_t slotSize = 0;
    uint32_t compiledBlockCount = 0;
    uint32_t codeCacheUsed = 0;
    uint64_t usageClock = 1;
    uint64_t lookupHits = 0;
    uint64_t lookupMisses = 0;

    std::array<int32_t, kLookupTableSize> lookupTable{};
    std::array<RuntimeBlock, kMaxCompiledBlocks> runtimeBlocks{};

    Impl() noexcept {
        lookupTable.fill(-1);
    }

    [[nodiscard]] static bool IsValidBlockIndex(int32_t blockIndex) noexcept {
        return blockIndex >= 0 && static_cast<uint32_t>(blockIndex) < kMaxCompiledBlocks;
    }

#if defined(_WIN32) || defined(_WIN64)
    [[nodiscard]] static bool ProtectNativeCode(void* address, size_t size, DWORD protection) noexcept {
        if (address == nullptr || size == 0) {
            return false;
        }
        DWORD previousProtection = 0;
        return ::VirtualProtect(address, size, protection, &previousProtection) != 0;
    }
#endif

    void ResetRuntimeSlot(uint32_t slot) noexcept {
        if (slot >= kMaxCompiledBlocks) {
            return;
        }
        runtimeBlocks[slot] = RuntimeBlock{};
        runtimeBlocks[slot].slotIndex = slot;
    }

    [[nodiscard]] int32_t FindLookupIndex(GuestAddress address) const noexcept {
        if (address == 0) {
            return -1;
        }

        uint32_t index = static_cast<uint32_t>((address >> 2) & kLookupMask);
        for (uint32_t probe = 0; probe < kLookupTableSize; ++probe) {
            const int32_t blockIndex = lookupTable[(index + probe) & kLookupMask];
            if (blockIndex < 0) {
                return -1;
            }
            if (!IsValidBlockIndex(blockIndex)) {
                return -1;
            }
            const auto blockSlot = static_cast<size_t>(blockIndex);
            if (runtimeBlocks[blockSlot].compiled.isValid
                && runtimeBlocks[blockSlot].compiled.guestAddress == address) {
                return blockIndex;
            }
        }

        return -1;
    }

    void RemoveLookup(GuestAddress address) noexcept {
        if (address == 0) {
            return;
        }

        uint32_t index = static_cast<uint32_t>((address >> 2) & kLookupMask);
        for (uint32_t probe = 0; probe < kLookupTableSize; ++probe) {
            auto& slot = lookupTable[(index + probe) & kLookupMask];
            if (slot < 0) {
                return;
            }

            const auto blockIndex = static_cast<size_t>(slot);
            if (blockIndex >= runtimeBlocks.size()) {
                slot = -1;
                return;
            }
            if (runtimeBlocks[blockIndex].compiled.guestAddress == address) {
                slot = -1;
                uint32_t next = (index + probe + 1) & kLookupMask;
                while (lookupTable[next] >= 0) {
                    const int32_t displaced = lookupTable[next];
                    lookupTable[next] = -1;
                    if (IsValidBlockIndex(displaced)) {
                        InsertLookup(
                            runtimeBlocks[static_cast<size_t>(displaced)].compiled.guestAddress,
                            displaced);
                    }
                    next = (next + 1) & kLookupMask;
                }
                return;
            }
        }
    }

    void InsertLookup(GuestAddress address, int32_t blockIndex) noexcept {
        if (address == 0 || !IsValidBlockIndex(blockIndex)) {
            return;
        }
        uint32_t index = static_cast<uint32_t>((address >> 2) & kLookupMask);
        for (uint32_t probe = 0; probe < kLookupTableSize; ++probe) {
            auto& slot = lookupTable[(index + probe) & kLookupMask];
            if (slot < 0
                || !IsValidBlockIndex(slot)
                || runtimeBlocks[static_cast<size_t>(slot)].compiled.guestAddress == address) {
                slot = blockIndex;
                return;
            }
        }
    }

    [[nodiscard]] RuntimeBlock* FindRuntimeBlock(GuestAddress address) noexcept {
        const int32_t index = FindLookupIndex(address);
        return IsValidBlockIndex(index) ? &runtimeBlocks[static_cast<size_t>(index)] : nullptr;
    }

    [[nodiscard]] const RuntimeBlock* FindRuntimeBlock(GuestAddress address) const noexcept {
        return const_cast<Impl*>(this)->FindRuntimeBlock(address);
    }

    [[nodiscard]] uint32_t SelectVictimSlot() noexcept {
        for (uint32_t i = 0; i < kMaxCompiledBlocks; ++i) {
            if (!runtimeBlocks[i].compiled.isValid) {
                return i;
            }
        }

        uint32_t victim = 0;
        RuntimeBlock* victimBlock = &runtimeBlocks[0];
        uint64_t oldest = std::numeric_limits<uint64_t>::max();
        for (uint32_t i = 0; i < kMaxCompiledBlocks; ++i) {
            if (runtimeBlocks[i].compiled.lastUsed < oldest) {
                oldest = runtimeBlocks[i].compiled.lastUsed;
                victim = i;
                victimBlock = &runtimeBlocks[i];
            }
        }

        RemoveLookup(victimBlock->compiled.guestAddress);
        if (compiledBlockCount > 0) {
            --compiledBlockCount;
        }
        if (codeCacheUsed >= victimBlock->compiled.nativeSize) {
            codeCacheUsed -= victimBlock->compiled.nativeSize;
        }
        ResetRuntimeSlot(victim);
        return victim;
    }

    [[nodiscard]] GuestAddress RuntimeBlockEnd(const RuntimeBlock& runtime) const noexcept {
        if (!runtime.compiled.isValid || runtime.compiledInstrCount == 0) {
            return runtime.compiled.guestAddress;
        }
        const GuestAddress blockStart = runtime.compiled.guestAddress;
        const GuestAddress nextRip = runtime.instructions[runtime.compiledInstrCount - 1].NextRIP();
        if (nextRip == kGuestInvalid || nextRip < blockStart) {
            return blockStart;
        }
        return nextRip;
    }

    void InvalidateRuntimeBlock(RuntimeBlock& runtime) noexcept {
        if (!runtime.compiled.isValid) {
            return;
        }
        RemoveLookup(runtime.compiled.guestAddress);
        if (compiledBlockCount > 0) {
            --compiledBlockCount;
        }
        if (codeCacheUsed >= runtime.compiled.nativeSize) {
            codeCacheUsed -= runtime.compiled.nativeSize;
        }
        const uint32_t slot = runtime.slotIndex;
        ResetRuntimeSlot(slot);
    }

    [[nodiscard]] static uint32_t ExecuteRuntimeBlock(
        CPUState* cpu,
        VirtualMemory* memory,
        RuntimeBlock* block) noexcept
    {
        if (cpu == nullptr || memory == nullptr || block == nullptr || !block->compiled.isValid) {
            return 0;
        }

        uint32_t executed = 0;
        for (; executed < block->compiledInstrCount; ++executed) {
            const auto err = ExecuteCompiledInstruction(*cpu, *memory, block->instructions[executed]);
            if (err != ErrorCode::Success) {
                break;
            }
        }

        return executed;
    }
};

JITCompiler::JITCompiler(JITStrategy strategy) noexcept {
    try {
        m_impl = std::make_unique<Impl>();
        m_impl->strategy = strategy;
    } catch (...) {
        m_impl.reset();
    }
}

JITCompiler::~JITCompiler() noexcept {
    Shutdown();
}

JITCompiler::JITCompiler(JITCompiler&&) noexcept = default;
JITCompiler& JITCompiler::operator=(JITCompiler&&) noexcept = default;

bool JITCompiler::Initialize(uint32_t cacheSizeBytes) noexcept {
    if (!m_impl || cacheSizeBytes == 0 || cacheSizeBytes > kMaxJitCodeCacheSize) {
        return false;
    }

    std::unique_lock lock(m_impl->mutex);

    if (m_impl->codeCache != nullptr) {
        return true;
    }

    const uint32_t slotCount = kMaxCompiledBlocks;
    const uint32_t roundedSize = std::max(cacheSizeBytes, slotCount * 256u);
    const uint32_t slotSize = roundedSize / slotCount;
    if (slotSize < kMinJitSlotSize) {
        return false;
    }

#if defined(_WIN32) || defined(_WIN64)
    auto* cache = static_cast<uint8_t*>(
        ::VirtualAlloc(nullptr, roundedSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (cache == nullptr) {
        return false;
    }
#else
    auto* cache = static_cast<uint8_t*>(std::malloc(roundedSize));
    if (cache == nullptr) {
        return false;
    }
#endif

    m_impl->codeCache = cache;
    m_impl->codeCacheSize = roundedSize;
    m_impl->slotSize = slotSize;
    m_impl->compiledBlockCount = 0;
    m_impl->codeCacheUsed = 0;
    m_impl->usageClock = 1;
    m_impl->lookupHits = 0;
    m_impl->lookupMisses = 0;
    m_impl->lookupTable.fill(-1);
    for (uint32_t i = 0; i < kMaxCompiledBlocks; ++i) {
        m_impl->runtimeBlocks[i] = Impl::RuntimeBlock{};
        m_impl->runtimeBlocks[i].slotIndex = i;
    }

    return true;
}

void JITCompiler::Shutdown() noexcept {
    if (!m_impl) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    if (m_impl->codeCache != nullptr) {
#if defined(_WIN32) || defined(_WIN64)
        ::VirtualFree(m_impl->codeCache, 0, MEM_RELEASE);
#else
        std::free(m_impl->codeCache);
#endif
        m_impl->codeCache = nullptr;
    }

    m_impl->codeCacheSize = 0;
    m_impl->slotSize = 0;
    m_impl->compiledBlockCount = 0;
    m_impl->codeCacheUsed = 0;
    m_impl->usageClock = 1;
    m_impl->lookupHits = 0;
    m_impl->lookupMisses = 0;
    m_impl->lookupTable.fill(-1);
    for (uint32_t i = 0; i < kMaxCompiledBlocks; ++i) {
        m_impl->runtimeBlocks[i] = Impl::RuntimeBlock{};
        m_impl->runtimeBlocks[i].slotIndex = i;
    }
}

CompiledBlock* JITCompiler::Lookup(GuestAddress address) noexcept {
    if (!m_impl || address == 0) {
        return nullptr;
    }

    std::unique_lock lock(m_impl->mutex);
    if (auto* runtime = m_impl->FindRuntimeBlock(address); runtime != nullptr) {
        runtime->compiled.lastUsed = m_impl->usageClock++;
        ++m_impl->lookupHits;
        return &runtime->compiled;
    }

    ++m_impl->lookupMisses;
    return nullptr;
}

bool JITCompiler::CompileBlock(
    GuestAddress address,
    const DecodedInstruction* instructions,
    uint32_t instrCount) noexcept
{
    if (!m_impl || address == 0 || instructions == nullptr || instrCount == 0) {
        return false;
    }

    if (m_impl->strategy == JITStrategy::Disabled) {
        return false;
    }

    std::unique_lock lock(m_impl->mutex);
    if (m_impl->codeCache == nullptr || m_impl->slotSize == 0) {
        return false;
    }

    const uint32_t cappedCount = std::min(instrCount, kMaxCompiledInstrPerBlock);
    uint32_t compiledInstrCount = 0;
    for (; compiledInstrCount < cappedCount; ++compiledInstrCount) {
        const auto& inst = instructions[compiledInstrCount];
        if (!SupportsCompiledInstruction(inst)) {
            break;
        }
    }

    if (compiledInstrCount == 0) {
        return false;
    }

    int32_t existingIndex = m_impl->FindLookupIndex(address);
    uint32_t slot = existingIndex >= 0
        ? static_cast<uint32_t>(existingIndex)
        : m_impl->SelectVictimSlot();

    if (existingIndex >= 0) {
        auto& existing = m_impl->runtimeBlocks[slot];
        m_impl->RemoveLookup(address);
        if (m_impl->codeCacheUsed >= existing.compiled.nativeSize) {
            m_impl->codeCacheUsed -= existing.compiled.nativeSize;
        }
        if (m_impl->compiledBlockCount > 0) {
            --m_impl->compiledBlockCount;
        }
    }

    auto& runtime = m_impl->runtimeBlocks[slot];
    m_impl->ResetRuntimeSlot(slot);
    auto* buffer = m_impl->codeCache + (static_cast<size_t>(slot) * m_impl->slotSize);
#if defined(_WIN32) || defined(_WIN64)
    if (!Impl::ProtectNativeCode(buffer, m_impl->slotSize, PAGE_READWRITE)) {
        return false;
    }
#endif

    runtime.compiledInstrCount = compiledInstrCount;
    runtime.compiled.guestAddress = address;
    runtime.compiled.guestInstrCount = instrCount;
    runtime.compiled.lastUsed = m_impl->usageClock++;
    runtime.compiled.executionCount = 0;
    runtime.compiled.isValid = true;
    std::memcpy(
        runtime.instructions.data(),
        instructions,
        static_cast<size_t>(compiledInstrCount) * sizeof(DecodedInstruction));

    X64Emitter emitter(buffer, m_impl->slotSize);
    emitter.EmitSubRegImm32(4, 0x28);
    emitter.EmitMovRegImm64(8, reinterpret_cast<uint64_t>(&runtime));
    emitter.EmitCall(reinterpret_cast<void*>(&Impl::ExecuteRuntimeBlock));
    emitter.EmitAddRegImm32(4, 0x28);
    emitter.EmitRet();

    runtime.compiled.nativeCode = buffer;
    runtime.compiled.nativeSize = emitter.GetOffset();
    if (emitter.Failed() || runtime.compiled.nativeSize == 0 || runtime.compiled.nativeSize > m_impl->slotSize) {
        m_impl->ResetRuntimeSlot(slot);
#if defined(_WIN32) || defined(_WIN64)
        (void)Impl::ProtectNativeCode(buffer, m_impl->slotSize, PAGE_EXECUTE_READ);
#endif
        return false;
    }

    m_impl->InsertLookup(address, static_cast<int32_t>(slot));
    ++m_impl->compiledBlockCount;
    if ((std::numeric_limits<uint32_t>::max)() - m_impl->codeCacheUsed < runtime.compiled.nativeSize) {
        m_impl->InvalidateRuntimeBlock(runtime);
#if defined(_WIN32) || defined(_WIN64)
        (void)Impl::ProtectNativeCode(buffer, m_impl->slotSize, PAGE_EXECUTE_READ);
#endif
        return false;
    }
    m_impl->codeCacheUsed += runtime.compiled.nativeSize;

#if defined(_WIN32) || defined(_WIN64)
    if (::FlushInstructionCache(::GetCurrentProcess(), buffer, runtime.compiled.nativeSize) == 0
        || !Impl::ProtectNativeCode(buffer, m_impl->slotSize, PAGE_EXECUTE_READ)) {
        m_impl->InvalidateRuntimeBlock(runtime);
        (void)Impl::ProtectNativeCode(buffer, m_impl->slotSize, PAGE_EXECUTE_READ);
        return false;
    }
#endif

    return true;
}

void JITCompiler::Invalidate(GuestAddress start, GuestSize size) noexcept {
    if (!m_impl || size == 0) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    const GuestAddress end =
        (std::numeric_limits<GuestAddress>::max() - start < size)
        ? std::numeric_limits<GuestAddress>::max()
        : start + size;

    for (auto& runtime : m_impl->runtimeBlocks) {
        if (!runtime.compiled.isValid) {
            continue;
        }

        const GuestAddress blockStart = runtime.compiled.guestAddress;
        const GuestAddress blockEnd = m_impl->RuntimeBlockEnd(runtime);

        if (blockStart < end && start < blockEnd) {
            m_impl->InvalidateRuntimeBlock(runtime);
        }
    }
}

uint32_t JITCompiler::Execute(
    CompiledBlock& block,
    CPUState& cpu,
    VirtualMemory& memory) noexcept
{
    if (!m_impl || !block.isValid || block.nativeCode == nullptr) {
        return 0;
    }

    using CompiledEntry = uint32_t(__fastcall*)(CPUState*, VirtualMemory*);
    auto entry = reinterpret_cast<CompiledEntry>(block.nativeCode);
    const uint32_t executed = entry(&cpu, &memory);

    std::unique_lock lock(m_impl->mutex);
    if (auto* runtime = m_impl->FindRuntimeBlock(block.guestAddress); runtime != nullptr) {
        if (executed == 0) {
            m_impl->InvalidateRuntimeBlock(*runtime);
        } else {
            runtime->compiled.lastUsed = m_impl->usageClock++;
            runtime->compiled.executionCount += executed;
            block = runtime->compiled;
        }
    }

    return executed;
}

uint32_t JITCompiler::GetCompiledBlockCount() const noexcept {
    if (!m_impl) {
        return 0;
    }

    std::shared_lock lock(m_impl->mutex);
    return m_impl->compiledBlockCount;
}

uint32_t JITCompiler::GetCodeCacheUsed() const noexcept {
    if (!m_impl) {
        return 0;
    }

    std::shared_lock lock(m_impl->mutex);
    return m_impl->codeCacheUsed;
}

double JITCompiler::GetCacheHitRate() const noexcept {
    if (!m_impl) {
        return 0.0;
    }

    std::shared_lock lock(m_impl->mutex);
    const uint64_t lookups = m_impl->lookupHits + m_impl->lookupMisses;
    if (lookups == 0) {
        return 0.0;
    }

    return static_cast<double>(m_impl->lookupHits) / static_cast<double>(lookups);
}

void JITCompiler::SetStrategy(JITStrategy strategy) noexcept {
    if (!m_impl) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    m_impl->strategy = strategy;
}

JITStrategy JITCompiler::GetStrategy() const noexcept {
    if (!m_impl) {
        return JITStrategy::Disabled;
    }

    std::shared_lock lock(m_impl->mutex);
    return m_impl->strategy;
}

} // namespace Phantom
