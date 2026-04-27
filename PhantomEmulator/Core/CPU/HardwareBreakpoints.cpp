/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "HardwareBreakpoints.hpp"
#include <algorithm>
#include <limits>
#include <new>

namespace Phantom {

// ============================================================================
// DR6 / DR7 Bit Constants
// ============================================================================
// These follow the Intel SDM Vol. 3A, Chapter 17 (Debug, Branch Profile,
// TSC, and Intel® Resource Director Technology).

namespace DR7Bits {
    // Local/Global enable bits for DR0-DR3.
    // Layout: L0(0), G0(1), L1(2), G1(3), L2(4), G2(5), L3(6), G3(7)
    static constexpr uint64_t kLocalEnable[4]  = { 1ULL << 0, 1ULL << 2, 1ULL << 4, 1ULL << 6 };
    static constexpr uint64_t kGlobalEnable[4] = { 1ULL << 1, 1ULL << 3, 1ULL << 5, 1ULL << 7 };

    // Exact breakpoint enable
    static constexpr uint64_t kLE = 1ULL << 8;   // Local Exact
    static constexpr uint64_t kGE = 1ULL << 9;   // Global Exact

    // General Detect enable — triggers #DB on any MOV DR access
    static constexpr uint64_t kGD = 1ULL << 13;

    // Condition and Length field bit offsets per slot.
    // DR0: bits 16-17 (cond), 18-19 (len)
    // DR1: bits 20-21 (cond), 22-23 (len)
    // DR2: bits 24-25 (cond), 26-27 (len)
    // DR3: bits 28-29 (cond), 30-31 (len)
    static constexpr uint32_t kCondShift[4] = { 16, 20, 24, 28 };
    static constexpr uint32_t kLenShift[4]  = { 18, 22, 26, 30 };

    // Reserved bits that must be set to 1 (bit 10 = 1 on Intel)
    static constexpr uint64_t kReservedOne = 1ULL << 10;

    // Mask for all enable bits (bits 0-7)
    static constexpr uint64_t kEnableMask = 0xFF;

    // Writable mask: bits 0-7 (enables), 8-9 (LE/GE), 13 (GD), 16-31 (cond/len)
    static constexpr uint64_t kWritableMask =
        0xFFFF'0000ULL | kGD | kGE | kLE | kEnableMask;
}

namespace DR6Bits {
    static constexpr uint64_t kB0 = 1ULL << 0;    // DR0 triggered
    static constexpr uint64_t kB1 = 1ULL << 1;    // DR1 triggered
    static constexpr uint64_t kB2 = 1ULL << 2;    // DR2 triggered
    static constexpr uint64_t kB3 = 1ULL << 3;    // DR3 triggered
    static constexpr uint64_t kB[4] = { kB0, kB1, kB2, kB3 };

    static constexpr uint64_t kBD = 1ULL << 13;   // Debug register access detected
    static constexpr uint64_t kBS = 1ULL << 14;   // Single step (TF)
    static constexpr uint64_t kBT = 1ULL << 15;   // Task switch

    // DR6 power-on/reset value: upper bits 16-63 set, bits 4-11 set
    // Intel SDM: bits 16-31 are 1, bits 4-11 are 1 → 0xFFFF0FF0
    static constexpr uint64_t kResetValue = 0xFFFF0FF0ULL;

    // Mask of bits the CPU clears on write: B0-B3, BD, BS, BT (bits 0-3, 13-15)
    static constexpr uint64_t kClearableMask = kB0 | kB1 | kB2 | kB3 | kBD | kBS | kBT;
}

namespace {

[[nodiscard]] bool IsValidCondition(HWBPCondition condition) noexcept {
    switch (condition) {
        case HWBPCondition::Execute:
        case HWBPCondition::WriteOnly:
        case HWBPCondition::IOReadWrite:
        case HWBPCondition::ReadWrite:
            return true;
    }
    return false;
}

[[nodiscard]] bool IsValidLength(HWBPLength length) noexcept {
    switch (length) {
        case HWBPLength::Byte:
        case HWBPLength::Word:
        case HWBPLength::Dword:
        case HWBPLength::Qword:
            return true;
    }
    return false;
}

[[nodiscard]] bool AddRangeEnd(GuestAddress start, uint32_t size, GuestAddress& end) noexcept {
    if (size == 0 || (std::numeric_limits<GuestAddress>::max)() - start < size) {
        return false;
    }
    end = start + size;
    return true;
}

} // namespace

// ============================================================================
// Static sentinel for out-of-range GetSlot() calls
// ============================================================================

const HWBreakpoint HardwareBreakpoints::s_nullSlot{};

// ============================================================================
// Construction / Destruction
// ============================================================================

HardwareBreakpoints::HardwareBreakpoints() noexcept {
    try {
        m_detections.reserve(kMaxDetections);
    } catch (const std::bad_alloc&) {
        m_detections.clear();
    }
}

HardwareBreakpoints::~HardwareBreakpoints() noexcept = default;

// ============================================================================
// DR0-DR3 Configuration
// ============================================================================

bool HardwareBreakpoints::SetBreakpoint(uint8_t slot, GuestAddress address,
                                         HWBPCondition condition,
                                         HWBPLength length) noexcept {
    if (slot >= kMaxSlots) {
        return false;
    }
    if (!IsValidCondition(condition) || !IsValidLength(length)) {
        return false;
    }
    if (condition == HWBPCondition::Execute) {
        length = HWBPLength::Byte;
    } else {
        const uint64_t alignMask = ~LengthToAlignMask(length);
        if ((address & alignMask) != 0) {
            return false;
        }
    }

    auto& bp = m_slots[slot];
    bp.address   = address;
    bp.condition  = condition;
    bp.length     = length;
    bp.enabled    = true;
    bp.triggered  = false;

    return true;
}

void HardwareBreakpoints::ClearBreakpoint(uint8_t slot) noexcept {
    if (slot >= kMaxSlots) {
        return;
    }

    m_slots[slot] = HWBreakpoint{};
}

void HardwareBreakpoints::ClearAll() noexcept {
    for (auto& bp : m_slots) {
        bp = HWBreakpoint{};
    }
    m_triggeredCount = 0;
}

const HWBreakpoint& HardwareBreakpoints::GetSlot(uint8_t slot) const noexcept {
    if (slot >= kMaxSlots) {
        return s_nullSlot;
    }
    return m_slots[slot];
}

// ============================================================================
// Execution Checks — HOT PATH
// ============================================================================
// These are called on every instruction / memory access when breakpoints are
// active. Zero heap allocation. Minimal branching.

bool HardwareBreakpoints::CheckExecuteBreakpoint(GuestAddress rip) const noexcept {
    for (uint8_t i = 0; i < kMaxSlots; ++i) {
        const auto& bp = m_slots[i];
        if (bp.enabled &&
            bp.condition == HWBPCondition::Execute &&
            bp.address == rip) {
            return true;
        }
    }
    return false;
}

bool HardwareBreakpoints::CheckDataBreakpoint(GuestAddress addr, uint32_t size,
                                               bool isWrite) const noexcept {
    for (uint8_t i = 0; i < kMaxSlots; ++i) {
        const auto& bp = m_slots[i];
        if (!bp.enabled) {
            continue;
        }

        // Execute breakpoints don't match data accesses
        if (bp.condition == HWBPCondition::Execute) {
            continue;
        }

        // WriteOnly breakpoints only fire on writes
        if (bp.condition == HWBPCondition::WriteOnly && !isWrite) {
            continue;
        }

        // ReadWrite matches both reads and writes; IOReadWrite treated as ReadWrite
        // in user-mode emulation.

        const uint32_t bpLen = LengthToBytes(bp.length);
        if (RangesOverlap(bp.address, bpLen, addr, size)) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Trap Flag (TF) / Single-Step Support
// ============================================================================

bool HardwareBreakpoints::IsSingleStepActive(const EFlags& eflags) const noexcept {
    return eflags.TF();
}

bool HardwareBreakpoints::ProcessSingleStep(CPUState& cpu) noexcept {
    // Clear TF so the debug exception handler runs without immediately re-trapping
    cpu.eflags.SetTF(false);

    // Set DR6.BS to indicate the #DB was caused by single-step
    cpu.dr6 = (cpu.dr6 & ~DR6Bits::kClearableMask) | DR6Bits::kBS;

    return true;
}

// ============================================================================
// DR6/DR7 Register Access (MOV DR instructions)
// ============================================================================

uint64_t HardwareBreakpoints::ReadDR(const CPUState& cpu, uint8_t drIndex) const noexcept {
    switch (drIndex) {
        case 0: case 1: case 2: case 3:
            return cpu.dr[drIndex];

        case 4:
            // DR4 aliases to DR6 (when CR4.DE=0, which we assume)
            return cpu.dr6;

        case 5:
            // DR5 aliases to DR7
            return cpu.dr7;

        case 6:
            return cpu.dr6;

        case 7:
            return cpu.dr7;

        default:
            return 0;
    }
}

void HardwareBreakpoints::WriteDR(CPUState& cpu, uint8_t drIndex, uint64_t value) noexcept {
    switch (drIndex) {
        case 0: case 1: case 2: case 3:
            cpu.dr[drIndex] = value;
            m_slots[drIndex].address = value;
            DecodeDR7(cpu.dr7);
            break;

        case 4:
            // DR4 aliases to DR6
            // DR6 write: only the clearable bits can be explicitly written;
            // the reserved-one bits are preserved.
            cpu.dr6 = (value & DR6Bits::kClearableMask) |
                       (DR6Bits::kResetValue & ~DR6Bits::kClearableMask);
            break;

        case 5:
            // DR5 aliases to DR7
            cpu.dr7 = (value & DR7Bits::kWritableMask) | DR7Bits::kReservedOne;
            DecodeDR7(cpu.dr7);
            break;

        case 6:
            cpu.dr6 = (value & DR6Bits::kClearableMask) |
                       (DR6Bits::kResetValue & ~DR6Bits::kClearableMask);
            break;

        case 7:
            cpu.dr7 = (value & DR7Bits::kWritableMask) | DR7Bits::kReservedOne;
            DecodeDR7(cpu.dr7);
            break;

        default:
            break;
    }
}

void HardwareBreakpoints::SyncFromCPUState(const CPUState& cpu) noexcept {
    // Load addresses from DR0-DR3
    for (uint8_t i = 0; i < kMaxSlots; ++i) {
        m_slots[i].address = cpu.dr[i];
    }

    // Decode DR7 to populate condition, length, and enable for each slot
    DecodeDR7(cpu.dr7);

    // Reset triggered state from DR6
    m_triggeredCount = 0;
    for (uint8_t i = 0; i < kMaxSlots; ++i) {
        m_slots[i].triggered = (cpu.dr6 & DR6Bits::kB[i]) != 0;
        if (m_slots[i].triggered) {
            ++m_triggeredCount;
        }
    }
}

void HardwareBreakpoints::SyncToCPUState(CPUState& cpu) const noexcept {
    // Write addresses back to DR0-DR3
    for (uint8_t i = 0; i < kMaxSlots; ++i) {
        cpu.dr[i] = m_slots[i].address;
    }

    // Encode DR7 from current slot configuration
    cpu.dr7 = EncodeDR7();

    // Write triggered bits into DR6 (preserve other DR6 bits)
    uint64_t dr6 = cpu.dr6 & ~(DR6Bits::kB0 | DR6Bits::kB1 | DR6Bits::kB2 | DR6Bits::kB3);
    for (uint8_t i = 0; i < kMaxSlots; ++i) {
        if (m_slots[i].triggered) {
            dr6 |= DR6Bits::kB[i];
        }
    }
    cpu.dr6 = dr6;
}

// ============================================================================
// Anti-Debug Detection
// ============================================================================

void HardwareBreakpoints::OnDRAccess(GuestAddress rip, uint8_t drIndex,
                                      bool isWrite, uint64_t value) noexcept {
    if (isWrite) {
        if (drIndex <= 3) {
            // Malware writing to DR0-DR3 — potentially setting anti-debug trap addresses
            if (value != 0) {
                AddDetection(DebugDetectionEvent::Type::WriteDR0_DR3_Set, rip, drIndex);
            }
        } else if (drIndex == 7 || drIndex == 5) {
            // Writing to DR7/DR5 — check if clearing all enables (anti-debug)
            if ((value & DR7Bits::kEnableMask) == 0) {
                AddDetection(DebugDetectionEvent::Type::WriteDR7_Clear, rip, drIndex);
            }
        }
    } else {
        // Read access
        if (drIndex <= 3) {
            AddDetection(DebugDetectionEvent::Type::ReadDR0_DR3, rip, drIndex);
        } else if (drIndex == 6 || drIndex == 4) {
            AddDetection(DebugDetectionEvent::Type::ReadDR6, rip, drIndex);
        } else if (drIndex == 7 || drIndex == 5) {
            AddDetection(DebugDetectionEvent::Type::ReadDR7, rip, drIndex);
        }
    }
}

void HardwareBreakpoints::OnPushFlags(GuestAddress rip) noexcept {
    AddDetection(DebugDetectionEvent::Type::CheckTrapFlag, rip, 0);
}

const std::vector<DebugDetectionEvent>& HardwareBreakpoints::GetDetections() const noexcept {
    return m_detections;
}

void HardwareBreakpoints::ClearDetections() noexcept {
    m_detections.clear();
}

// ============================================================================
// Querying
// ============================================================================

bool HardwareBreakpoints::HasActiveBreakpoints() const noexcept {
    for (const auto& bp : m_slots) {
        if (bp.enabled) {
            return true;
        }
    }
    return false;
}

uint32_t HardwareBreakpoints::GetTriggeredCount() const noexcept {
    return m_triggeredCount;
}

uint32_t HardwareBreakpoints::GetDetectionCount() const noexcept {
    return static_cast<uint32_t>(m_detections.size());
}

// ============================================================================
// Internal Helpers
// ============================================================================

uint32_t HardwareBreakpoints::LengthToBytes(HWBPLength len) noexcept {
    switch (len) {
        case HWBPLength::Byte:  return 1;
        case HWBPLength::Word:  return 2;
        case HWBPLength::Dword: return 4;
        case HWBPLength::Qword: return 8;
    }
    return 1;
}

uint64_t HardwareBreakpoints::LengthToAlignMask(HWBPLength len) noexcept {
    switch (len) {
        case HWBPLength::Byte:  return ~0ULL;        // No alignment
        case HWBPLength::Word:  return ~1ULL;         // 2-byte aligned
        case HWBPLength::Dword: return ~3ULL;         // 4-byte aligned
        case HWBPLength::Qword: return ~7ULL;         // 8-byte aligned
    }
    return ~0ULL;
}

bool HardwareBreakpoints::RangesOverlap(GuestAddress bpAddr, uint32_t bpLen,
                                         GuestAddress accessAddr, uint32_t accessSize) noexcept {
    // Guard against zero-length access (shouldn't happen, but be defensive)
    if (accessSize == 0 || bpLen == 0) {
        return false;
    }

    // Overflow-safe overlap check:
    // [bpAddr, bpAddr + bpLen) overlaps [accessAddr, accessAddr + accessSize)
    // iff bpAddr < accessAddr + accessSize AND accessAddr < bpAddr + bpLen
    GuestAddress bpEnd = 0;
    GuestAddress accessEnd = 0;
    if (!AddRangeEnd(bpAddr, bpLen, bpEnd) || !AddRangeEnd(accessAddr, accessSize, accessEnd)) {
        return false;
    }

    return (bpAddr < accessEnd) && (accessAddr < bpEnd);
}

void HardwareBreakpoints::DecodeDR7(uint64_t dr7) noexcept {
    for (uint8_t i = 0; i < kMaxSlots; ++i) {
        // A slot is enabled if either its local or global enable bit is set
        const bool localEnabled  = (dr7 & DR7Bits::kLocalEnable[i]) != 0;
        const bool globalEnabled = (dr7 & DR7Bits::kGlobalEnable[i]) != 0;
        m_slots[i].enabled = localEnabled || globalEnabled;

        // Extract condition (R/W) field: 2 bits
        const uint8_t cond = static_cast<uint8_t>(
            (dr7 >> DR7Bits::kCondShift[i]) & 0x3);
        m_slots[i].condition = static_cast<HWBPCondition>(cond);

        // Extract length field: 2 bits
        const uint8_t len = static_cast<uint8_t>(
            (dr7 >> DR7Bits::kLenShift[i]) & 0x3);
        m_slots[i].length = static_cast<HWBPLength>(len);

        if (m_slots[i].condition == HWBPCondition::Execute) {
            m_slots[i].length = HWBPLength::Byte;
        } else {
            const uint64_t alignMask = ~LengthToAlignMask(m_slots[i].length);
            if ((m_slots[i].address & alignMask) != 0) {
                m_slots[i].enabled = false;
            }
        }
    }
}

uint64_t HardwareBreakpoints::EncodeDR7() const noexcept {
    uint64_t dr7 = DR7Bits::kReservedOne;  // Bit 10 always set

    for (uint8_t i = 0; i < kMaxSlots; ++i) {
        if (m_slots[i].enabled) {
            dr7 |= DR7Bits::kLocalEnable[i];
        }

        // Encode condition (R/W) field
        dr7 |= (static_cast<uint64_t>(m_slots[i].condition) & 0x3)
                << DR7Bits::kCondShift[i];

        // Encode length field
        dr7 |= (static_cast<uint64_t>(m_slots[i].length) & 0x3)
                << DR7Bits::kLenShift[i];
    }

    return dr7;
}

void HardwareBreakpoints::AddDetection(DebugDetectionEvent::Type type,
                                        GuestAddress rip,
                                        uint64_t details) noexcept {
    if (m_detections.size() >= kMaxDetections) {
        return;
    }

    try {
        m_detections.push_back(DebugDetectionEvent{
            .type    = type,
            .rip     = rip,
            .details = details,
        });
    } catch (const std::bad_alloc&) {
        return;
    }
}

} // namespace Phantom
