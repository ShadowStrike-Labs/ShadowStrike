/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "CPUState.hpp"
#include "../../Common/Constants.hpp"
#include <cstring>

namespace Phantom {

// ============================================================================
// Reset — Initialize to a clean state
// ============================================================================

void CPUState::Reset() noexcept {
    if (mode == CPUMode::Long64 || mode == CPUMode::Protected32) {
        Reset64();
    } else {
        Reset32();
    }
}

void CPUState::Reset32() noexcept {
    mode = CPUMode::Protected32;

    // Zero all GPRs
    gpr.fill(0);

    // Stack pointer at top of 1MB stack
    gpr[static_cast<uint8_t>(GPR::RSP)] = WinConst::kStackTop64;
    gpr[static_cast<uint8_t>(GPR::RBP)] = WinConst::kStackTop64;

    rip = 0;

    // EFLAGS: IF=1, reserved bit 1 set
    eflags = EFlags(0x202);

    // Segment registers: flat model, ring 3
    for (auto& seg : segments) {
        seg = SegmentDescriptor{};
        seg.base = 0;
        seg.limit = 0xFFFFFFFF;
        seg.dpl = 3;
        seg.present = true;
        seg.is32bit = true;
        seg.is64bit = false;
    }
    segments[static_cast<uint8_t>(SegReg::CS)].selector = 0x1B;
    segments[static_cast<uint8_t>(SegReg::DS)].selector = 0x23;
    segments[static_cast<uint8_t>(SegReg::SS)].selector = 0x23;
    segments[static_cast<uint8_t>(SegReg::ES)].selector = 0x23;
    segments[static_cast<uint8_t>(SegReg::FS)].selector = 0x3B;
    segments[static_cast<uint8_t>(SegReg::GS)].selector = 0x43;

    // FS.base points to TEB in 32-bit mode
    segments[static_cast<uint8_t>(SegReg::FS)].base = WinConst::kTEBAddress64;

    // Control registers
    cr0 = 0x80050033;
    cr2 = 0;
    cr3 = 0;
    cr4 = 0x000406F8;

    // Debug registers: clean (malware checks these for debugger detection)
    dr.fill(0);
    dr6 = 0xFFFF0FF0;
    dr7 = 0x00000400;

    // FPU: reset to default state
    for (auto& fpr : fpuStack) { fpr.value = 0.0L; }
    fpuControl = 0x037F;
    fpuStatus = 0;
    fpuTag = 0xFFFF;
    fpuOpcode = 0;
    fpuIP = 0;
    fpuDP = 0;
    fpuTop = 0;

    // SSE: clear all XMM registers
    for (auto& x : xmm) { x.Clear(); }
    mxcsr = 0x1F80;

    instructionCount = 0;
    tsc = 0x00000389A7C21E40ULL;  // ~3.9 trillion — realistic for a system booted ~17 minutes ago at 3.8GHz
    tscIncrement = 25;
}

void CPUState::Reset64() noexcept {
    Reset32(); // Start with 32-bit defaults

    mode = CPUMode::Long64;

    // In 64-bit mode, segments are mostly flat
    for (auto& seg : segments) {
        seg.is64bit = true;
        seg.is32bit = false;
    }

    // CS selector for 64-bit user mode
    segments[static_cast<uint8_t>(SegReg::CS)].selector = 0x33;
    segments[static_cast<uint8_t>(SegReg::CS)].is64bit = true;

    // GS.base points to TEB in 64-bit mode (not FS)
    segments[static_cast<uint8_t>(SegReg::FS)].base = 0;
    segments[static_cast<uint8_t>(SegReg::GS)].base = WinConst::kTEBAddress64;
}

// ============================================================================
// Snapshot/Restore
// ============================================================================

CPUState::Snapshot CPUState::TakeSnapshot() const noexcept {
    Snapshot snap{};
    snap.gpr = gpr;
    snap.rip = rip;
    snap.rflags = eflags.Raw();
    snap.mode = mode;
    snap.instructionCount = instructionCount;
    return snap;
}

void CPUState::RestoreSnapshot(const Snapshot& snap) noexcept {
    gpr = snap.gpr;
    rip = snap.rip;
    eflags.SetRaw(snap.rflags);
    mode = snap.mode;
    instructionCount = snap.instructionCount;
}

} // namespace Phantom
