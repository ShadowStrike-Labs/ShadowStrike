/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "State/CPUState.hpp"
#include "State/EFLAGS.hpp"
#include "../../Common/Types.hpp"
#include <array>
#include <cstdint>
#include <vector>

namespace Phantom {

// ============================================================================
// DR7 Breakpoint Condition Types
// ============================================================================

enum class HWBPCondition : uint8_t {
    Execute     = 0b00,   // Break on instruction execution
    WriteOnly   = 0b01,   // Break on data write only
    IOReadWrite = 0b10,   // Break on I/O read/write (not used in user mode)
    ReadWrite   = 0b11,   // Break on data read or write
};

// ============================================================================
// DR7 Breakpoint Length Encoding
// ============================================================================

enum class HWBPLength : uint8_t {
    Byte  = 0b00,  // 1 byte
    Word  = 0b01,  // 2 bytes
    Qword = 0b10,  // 8 bytes (64-bit mode only)
    Dword = 0b11,  // 4 bytes
};

// ============================================================================
// Hardware Breakpoint Slot Descriptor (DR0-DR3)
// ============================================================================

struct HWBreakpoint {
    GuestAddress  address   = 0;
    HWBPCondition condition = HWBPCondition::Execute;
    HWBPLength    length    = HWBPLength::Byte;
    bool          enabled   = false;
    bool          triggered = false;
};

// ============================================================================
// Anti-Debug Detection Event
// ============================================================================
// Accumulated when the guest attempts debug-register-based anti-analysis.

struct DebugDetectionEvent {
    enum class Type : uint8_t {
        ReadDR0_DR3,          // Malware reading DR0-DR3 (checking for debugger)
        ReadDR6,              // Malware reading DR6 (checking breakpoint status)
        ReadDR7,              // Malware reading DR7 (checking breakpoint control)
        WriteDR7_Clear,       // Malware clearing DR7 (disabling breakpoints)
        WriteDR0_DR3_Set,     // Malware setting DR0-DR3 (anti-debug trap)
        CheckTrapFlag,        // Malware checking TF via PUSHF/POPF
        TimingCheck,          // Malware using RDTSC around INT1 to detect stepping
        ExceptionBasedDetect, // Malware using hardware BP exception as anti-debug
    };

    Type         type;
    GuestAddress rip     = 0;
    uint64_t     details = 0;   // DR index or other context
};

// ============================================================================
// HardwareBreakpoints — x86/x64 Debug Register Engine
// ============================================================================
// Models DR0-DR7 faithfully for the emulator. Provides:
//   - Execute breakpoints (instruction-level)
//   - Data breakpoints (read/write watchpoints)
//   - Trap Flag (TF) single-step support via DR6.BS
//   - Anti-debug detection for malware analysis
//
// Thread safety: NOT thread-safe. One instance per CPU, used only from the
// CPU execution loop on its owning thread.

class HardwareBreakpoints {
public:
    HardwareBreakpoints() noexcept;
    ~HardwareBreakpoints() noexcept;

    // Non-copyable, movable
    HardwareBreakpoints(const HardwareBreakpoints&) = delete;
    HardwareBreakpoints& operator=(const HardwareBreakpoints&) = delete;
    HardwareBreakpoints(HardwareBreakpoints&&) noexcept = default;
    HardwareBreakpoints& operator=(HardwareBreakpoints&&) noexcept = default;

    // ========================================================================
    // DR0-DR3 Configuration
    // ========================================================================

    /// Set a hardware breakpoint in slot 0-3.
    /// Returns false if slot is out of range.
    [[nodiscard]] bool SetBreakpoint(uint8_t slot, GuestAddress address,
                                      HWBPCondition condition,
                                      HWBPLength length) noexcept;

    /// Clear a specific hardware breakpoint slot (0-3).
    void ClearBreakpoint(uint8_t slot) noexcept;

    /// Clear all four hardware breakpoint slots.
    void ClearAll() noexcept;

    /// Get read-only reference to a breakpoint slot.
    /// Returns a disabled sentinel for out-of-range indices.
    [[nodiscard]] const HWBreakpoint& GetSlot(uint8_t slot) const noexcept;

    // ========================================================================
    // Execution Checks (called from CPU loop — HOT PATH, no allocations)
    // ========================================================================

    /// Check if the current RIP matches any enabled Execute breakpoint.
    /// Returns true if a breakpoint fired (caller should generate INT1).
    [[nodiscard]] bool CheckExecuteBreakpoint(GuestAddress rip) const noexcept;

    /// Check if a memory access matches any enabled Read/Write breakpoint.
    /// Called for every memory read/write when hardware breakpoints are active.
    [[nodiscard]] bool CheckDataBreakpoint(GuestAddress addr, uint32_t size,
                                           bool isWrite) const noexcept;

    // ========================================================================
    // Trap Flag (TF) / Single-Step Support
    // ========================================================================

    /// Check if the Trap Flag is set in EFLAGS (called after each instruction).
    [[nodiscard]] bool IsSingleStepActive(const EFlags& eflags) const noexcept;

    /// Process single-step: clears TF in EFLAGS, sets DR6.BS, returns true
    /// to indicate a #DB should be delivered.
    [[nodiscard]] bool ProcessSingleStep(CPUState& cpu) noexcept;

    // ========================================================================
    // DR6/DR7 Register Access (for MOV DR instructions)
    // ========================================================================

    /// Read a DR register as the guest would see it (DR0-DR7).
    /// DR4/DR5 alias to DR6/DR7 per Intel spec.
    [[nodiscard]] uint64_t ReadDR(const CPUState& cpu, uint8_t drIndex) const noexcept;

    /// Write a DR register (from a MOV-to-DR instruction).
    void WriteDR(CPUState& cpu, uint8_t drIndex, uint64_t value) noexcept;

    /// Synchronize internal slot state from CPU's DR registers (DR0-DR3, DR6, DR7).
    void SyncFromCPUState(const CPUState& cpu) noexcept;

    /// Write internal state back to CPU's DR registers.
    void SyncToCPUState(CPUState& cpu) const noexcept;

    // ========================================================================
    // Anti-Debug Detection
    // ========================================================================

    /// Record a debug register access for anti-debug tracking.
    void OnDRAccess(GuestAddress rip, uint8_t drIndex, bool isWrite,
                    uint64_t value = 0) noexcept;

    /// Record a PUSHF instruction (malware may check TF).
    void OnPushFlags(GuestAddress rip) noexcept;

    /// Get accumulated anti-debug detection events.
    [[nodiscard]] const std::vector<DebugDetectionEvent>& GetDetections() const noexcept;

    /// Clear detection log.
    void ClearDetections() noexcept;

    // ========================================================================
    // Querying
    // ========================================================================

    [[nodiscard]] bool HasActiveBreakpoints() const noexcept;
    [[nodiscard]] uint32_t GetTriggeredCount() const noexcept;
    [[nodiscard]] uint32_t GetDetectionCount() const noexcept;

private:
    static constexpr uint8_t  kMaxSlots       = 4;
    static constexpr uint32_t kMaxDetections   = 1024;

    // The four hardware breakpoint slots (mirrors DR0-DR3 + DR7 config)
    std::array<HWBreakpoint, kMaxSlots> m_slots{};

    // Anti-debug detection accumulator (bounded)
    std::vector<DebugDetectionEvent> m_detections;

    // Cached counts for fast querying
    uint32_t m_triggeredCount = 0;

    // Sentinel returned for out-of-range GetSlot() calls
    static const HWBreakpoint s_nullSlot;

    // === Internal helpers ===

    /// Decode the byte length from a HWBPLength encoding.
    [[nodiscard]] static uint32_t LengthToBytes(HWBPLength len) noexcept;

    /// Compute the alignment mask for a given breakpoint length.
    [[nodiscard]] static uint64_t LengthToAlignMask(HWBPLength len) noexcept;

    /// Check whether access range [addr, addr+size) overlaps breakpoint range.
    [[nodiscard]] static bool RangesOverlap(GuestAddress bpAddr, uint32_t bpLen,
                                            GuestAddress accessAddr, uint32_t accessSize) noexcept;

    /// Parse DR7 to update m_slots condition/length/enabled fields.
    void DecodeDR7(uint64_t dr7) noexcept;

    /// Encode m_slots state back into a DR7 value.
    [[nodiscard]] uint64_t EncodeDR7() const noexcept;

    /// Append a detection event (respecting the bound).
    void AddDetection(DebugDetectionEvent::Type type, GuestAddress rip,
                      uint64_t details = 0) noexcept;
};

} // namespace Phantom
