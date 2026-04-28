/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * RingTransition — CPU privilege level tracking and transition handling
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "RingTransition.hpp"
#include "MSREmulation.hpp"
#include "../CPU/State/CPUState.hpp"
#include "../Memory/VirtualMemory.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Constants.hpp"
#include "KernelAddressSpace.hpp"

#include <algorithm>
#include <atomic>
#include <limits>
#include <mutex>
#include <new>
#include <shared_mutex>
#include <unordered_map>

namespace Phantom {

// ============================================================================
// Canonical Address Validation
// ============================================================================

static bool RingIsCanonicalAddress(uint64_t addr) noexcept {
    // In x86-64, bits [63:48] must be all-zero or all-one (sign-extension of bit 47)
    uint64_t top17 = addr >> 47;
    return top17 == 0 || top17 == 0x1FFFF;
}

static bool RingAddGuest(GuestAddress base, uint64_t offset, GuestAddress& result) noexcept {
    if ((std::numeric_limits<GuestAddress>::max)() - base < offset) {
        return false;
    }
    result = base + offset;
    return true;
}

static void RingSaturatingIncrement(std::atomic<uint32_t>& counter) noexcept {
    uint32_t current = counter.load(std::memory_order_relaxed);
    while (current != (std::numeric_limits<uint32_t>::max)()) {
        if (counter.compare_exchange_weak(current, current + 1,
                                          std::memory_order_relaxed,
                                          std::memory_order_relaxed)) {
            return;
        }
    }
}

static bool RingAddSelectorOffset(uint16_t selector, uint16_t offset, uint16_t& result) noexcept {
    if (selector > (std::numeric_limits<uint16_t>::max)() - offset) {
        return false;
    }
    result = static_cast<uint16_t>(selector + offset);
    return true;
}

// ============================================================================
// Capacity Limits
// ============================================================================

static constexpr uint32_t kMaxTransitionHistory   = 65536;
static constexpr uint32_t kMaxSyscallNumber       = 0x2000;   // Upper bound for Windows syscall numbers
static constexpr uint64_t kStackPivotThreshold     = 0x100000; // 1 MB — RSP shift beyond this is suspicious

// ============================================================================
// RFLAGS Masks
// ============================================================================

static constexpr uint64_t kRFLAGSReservedBit1     = 0x2;
static constexpr uint64_t kSysretRFLAGSMask       = 0x3C7FD7;  // Bits SYSRET restores from R11

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct RingTransition::Impl {
    CPUState*      cpu = nullptr;
    MSREmulation*  msr = nullptr;

    uint8_t        currentCPL = 3;   // Start in user mode

    // Transition event log
    std::vector<RingTransitionEvent> history;

    // Syscall histogram: syscall number → count
    std::unordered_map<uint32_t, uint32_t> syscallCounts;

    // Counters
    std::atomic<uint32_t> syscallCount{0};
    std::atomic<uint32_t> transitionCount{0};

    mutable std::shared_mutex mutex;

    bool RecordEvent(const RingTransitionEvent& event) {
        if (history.size() < kMaxTransitionHistory) {
            try {
                history.push_back(event);
            } catch (const std::bad_alloc&) {
                return false;
            }
        }
        RingSaturatingIncrement(transitionCount);
        return true;
    }

    bool RecordSyscall(uint32_t syscallNumber) {
        try {
            auto& count = syscallCounts[syscallNumber];
            if (count < (std::numeric_limits<uint32_t>::max)()) {
                ++count;
            }
        } catch (const std::bad_alloc&) {
            return false;
        }
        RingSaturatingIncrement(syscallCount);
        return true;
    }
};

// ============================================================================
// Singleton
// ============================================================================

RingTransition& RingTransition::Instance() {
    static RingTransition instance;
    return instance;
}

RingTransition::RingTransition()
    : m_impl(std::make_unique<Impl>()) {}

RingTransition::~RingTransition() = default;

// ============================================================================
// Reset
// ============================================================================

void RingTransition::Reset() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->cpu = nullptr;
    m_impl->msr = nullptr;
    m_impl->currentCPL = 3;
    m_impl->history.clear();
    m_impl->syscallCounts.clear();
    m_impl->syscallCount.store(0, std::memory_order_relaxed);
    m_impl->transitionCount.store(0, std::memory_order_relaxed);
}

// ============================================================================
// Initialize
// ============================================================================

void RingTransition::Initialize(CPUState& cpu, MSREmulation& msr) {
    std::unique_lock lock(m_impl->mutex);
    m_impl->cpu = &cpu;
    m_impl->msr = &msr;
    m_impl->currentCPL = 3;
}

// ============================================================================
// SYSCALL Handler (AMD64 ABI)
// ============================================================================

bool RingTransition::HandleSyscall(CPUState& cpu) {
    std::unique_lock lock(m_impl->mutex);

    auto* msr = m_impl->msr;
    if (!msr) {
        return false;
    }

    // Verify EFER.SCE is enabled
    uint64_t efer = 0;
    if (!msr->ReadMSR(MSRIndex::EFER, efer)) {
        return false;
    }
    if ((efer & EFERBits::SCE) == 0) {
        return false;
    }

    GuestAddress fromRIP = cpu.GetRIP();
    uint64_t     fromRSP = cpu.RSP();
    uint32_t     syscallNum = static_cast<uint32_t>(cpu.RAX());
    GuestAddress lstar = msr->GetLSTAR();
    if (!RingIsCanonicalAddress(lstar)) {
        return false;
    }

    uint64_t star = msr->GetSTAR();
    uint16_t syscallCS = static_cast<uint16_t>((star >> 32) & 0xFFFF);
    uint16_t syscallSS = 0;
    if (syscallCS == 0 || !RingAddSelectorOffset(syscallCS, 8, syscallSS)) {
        return false;
    }

    // Step 1: Save RIP to RCX
    cpu.SetReg64(GPR::RCX, fromRIP);

    // Step 2: Save RFLAGS to R11
    uint64_t rflags = cpu.eflags.Raw();
    cpu.SetReg64(GPR::R11, rflags);

    // Step 3: RFLAGS &= ~SFMASK
    uint64_t sfmask = msr->GetSFMASK();
    cpu.eflags.SetRaw(rflags & ~sfmask);

    // Step 4: Load CS from STAR[47:32], SS from STAR[47:32]+8
    cpu.SetSegmentSelector(SegReg::CS, syscallCS);
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].base   = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].dpl    = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is64bit = true;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is32bit = false;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].present = true;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].type   = 0x0B; // Execute/Read, Accessed

    cpu.SetSegmentSelector(SegReg::SS, syscallSS);
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].base   = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].dpl    = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].present = true;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].type   = 0x03; // Read/Write, Accessed

    // Step 5: Set CPL = 0
    uint8_t prevCPL = m_impl->currentCPL;
    m_impl->currentCPL = 0;

    // Step 6: Load RIP from LSTAR
    cpu.SetRIP(lstar);

    // Record event
    RingTransitionEvent event{};
    event.type          = TransitionType::Syscall;
    event.fromRing      = prevCPL;
    event.toRing        = 0;
    event.fromRIP       = fromRIP;
    event.toRIP         = lstar;
    event.rflags        = rflags;
    event.rsp           = fromRSP;
    event.syscallNumber = syscallNum;
    event.timestamp     = cpu.instructionCount;
    (void)m_impl->RecordEvent(event);

    // Track syscall number
    (void)m_impl->RecordSyscall(syscallNum);

    return true;
}

// ============================================================================
// SYSRET Handler (AMD64 ABI)
// ============================================================================

bool RingTransition::HandleSysret(CPUState& cpu) {
    std::unique_lock lock(m_impl->mutex);

    auto* msr = m_impl->msr;
    if (!msr) {
        return false;
    }

    // SYSRET must execute from Ring 0
    if (m_impl->currentCPL != 0) {
        return false;
    }

    GuestAddress fromRIP = cpu.GetRIP();

    // Step 1: Load RIP from RCX
    GuestAddress targetRIP = cpu.RCX();

    // Validate canonical address — Intel SDM: SYSRET #GP if non-canonical
    if (!RingIsCanonicalAddress(targetRIP)) {
        return false;
    }

    uint64_t star = msr->GetSTAR();
    uint16_t sysretCSBase = static_cast<uint16_t>((star >> 48) & 0xFFFF);
    uint16_t userCS = 0;
    uint16_t userSS = 0;
    if (!RingAddSelectorOffset(sysretCSBase, 16, userCS) ||
        !RingAddSelectorOffset(sysretCSBase, 8, userSS)) {
        return false;
    }

    cpu.SetRIP(targetRIP);

    // Step 2: Load RFLAGS from R11 (with mask)
    uint64_t newFlags = cpu.GetReg64(GPR::R11);
    newFlags = (newFlags & kSysretRFLAGSMask) | kRFLAGSReservedBit1;
    cpu.eflags.SetRaw(newFlags);

    // Step 3: Load CS from STAR[63:48]+16, SS from STAR[63:48]+8
    cpu.SetSegmentSelector(SegReg::CS, userCS);
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].base   = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].dpl    = 3;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is64bit = true;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is32bit = false;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].present = true;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].type   = 0x0B;

    cpu.SetSegmentSelector(SegReg::SS, userSS);
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].base   = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].dpl    = 3;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].present = true;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].type   = 0x03;

    // Step 4: Set CPL = 3
    m_impl->currentCPL = 3;

    // Record event
    RingTransitionEvent event{};
    event.type          = TransitionType::Sysret;
    event.fromRing      = 0;
    event.toRing        = 3;
    event.fromRIP       = fromRIP;
    event.toRIP         = targetRIP;
    event.rflags        = newFlags;
    event.rsp           = cpu.RSP();
    event.syscallNumber = 0;
    event.timestamp     = cpu.instructionCount;
    (void)m_impl->RecordEvent(event);

    return true;
}

// ============================================================================
// SYSENTER Handler (Intel fast syscall — 32-bit compat path)
// ============================================================================

bool RingTransition::HandleSysenter(CPUState& cpu) {
    std::unique_lock lock(m_impl->mutex);

    auto* msr = m_impl->msr;
    if (!msr) {
        return false;
    }

    // Read SYSENTER MSRs
    uint64_t sysenterCS = 0, sysenterESP = 0, sysenterEIP = 0;
    if (!msr->ReadMSR(MSRIndex::SYSENTER_CS, sysenterCS)) return false;
    if (!msr->ReadMSR(MSRIndex::SYSENTER_ESP, sysenterESP)) return false;
    if (!msr->ReadMSR(MSRIndex::SYSENTER_EIP, sysenterEIP)) return false;

    // SYSENTER requires SYSENTER_CS != 0
    if (sysenterCS == 0) {
        return false;
    }

    GuestAddress fromRIP = cpu.GetRIP();
    uint64_t     fromRSP = cpu.RSP();
    uint32_t     syscallNum = static_cast<uint32_t>(cpu.RAX());
    uint8_t      prevCPL = m_impl->currentCPL;

    // Load CS = SYSENTER_CS, SS = SYSENTER_CS + 8
    uint16_t cs = static_cast<uint16_t>(sysenterCS & 0xFFFF);
    uint16_t ss = 0;
    if (!RingAddSelectorOffset(cs, 8, ss) || !RingIsCanonicalAddress(sysenterESP) ||
        !RingIsCanonicalAddress(sysenterEIP)) {
        return false;
    }

    cpu.SetSegmentSelector(SegReg::CS, cs);
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].base   = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].dpl    = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is64bit = true;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is32bit = false;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].present = true;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].type   = 0x0B;

    cpu.SetSegmentSelector(SegReg::SS, ss);
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].base   = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].dpl    = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].present = true;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].type   = 0x03;

    // Load RSP and RIP from MSRs
    cpu.SetReg64(GPR::RSP, sysenterESP);
    cpu.SetRIP(static_cast<GuestAddress>(sysenterEIP));

    // Clear IF in EFLAGS
    cpu.eflags.SetIF(false);

    // Set CPL = 0
    m_impl->currentCPL = 0;

    // Record event
    RingTransitionEvent event{};
    event.type          = TransitionType::Sysenter;
    event.fromRing      = prevCPL;
    event.toRing        = 0;
    event.fromRIP       = fromRIP;
    event.toRIP         = static_cast<GuestAddress>(sysenterEIP);
    event.rflags        = cpu.eflags.Raw();
    event.rsp           = fromRSP;
    event.syscallNumber = syscallNum;
    event.timestamp     = cpu.instructionCount;
    (void)m_impl->RecordEvent(event);

    (void)m_impl->RecordSyscall(syscallNum);

    return true;
}

// ============================================================================
// SYSEXIT Handler
// ============================================================================

bool RingTransition::HandleSysexit(CPUState& cpu) {
    std::unique_lock lock(m_impl->mutex);

    auto* msr = m_impl->msr;
    if (!msr) {
        return false;
    }

    // SYSEXIT must execute from Ring 0
    if (m_impl->currentCPL != 0) {
        return false;
    }

    uint64_t sysenterCS = 0;
    if (!msr->ReadMSR(MSRIndex::SYSENTER_CS, sysenterCS)) return false;
    if (sysenterCS == 0) return false;

    GuestAddress fromRIP = cpu.GetRIP();

    // In 64-bit mode: CS = SYSENTER_CS + 32, SS = SYSENTER_CS + 40
    uint16_t userCS = 0;
    uint16_t userSS = 0;
    const uint16_t sysenterSelector = static_cast<uint16_t>(sysenterCS & 0xFFFF);
    if (!RingAddSelectorOffset(sysenterSelector, 32, userCS) ||
        !RingAddSelectorOffset(sysenterSelector, 40, userSS)) {
        return false;
    }

    // RIP <- RDX, RSP <- RCX (Intel SDM SYSEXIT specification)
    GuestAddress targetRIP = cpu.RDX();
    uint64_t targetRSP     = cpu.RCX();
    if (!RingIsCanonicalAddress(targetRIP) || !RingIsCanonicalAddress(targetRSP)) {
        return false;
    }

    cpu.SetSegmentSelector(SegReg::CS, userCS);
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].base   = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].dpl    = 3;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is64bit = true;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is32bit = false;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].present = true;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].type   = 0x0B;

    cpu.SetSegmentSelector(SegReg::SS, userSS);
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].base   = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].dpl    = 3;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].present = true;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].type   = 0x03;

    cpu.SetRIP(targetRIP);
    cpu.SetReg64(GPR::RSP, targetRSP);

    // Set CPL = 3
    m_impl->currentCPL = 3;

    // Record event
    RingTransitionEvent event{};
    event.type          = TransitionType::Sysexit;
    event.fromRing      = 0;
    event.toRing        = 3;
    event.fromRIP       = fromRIP;
    event.toRIP         = targetRIP;
    event.rflags        = cpu.eflags.Raw();
    event.rsp           = targetRSP;
    event.syscallNumber = 0;
    event.timestamp     = cpu.instructionCount;
    (void)m_impl->RecordEvent(event);

    return true;
}

// ============================================================================
// INT 0x2E Handler (Legacy Windows syscall path)
// ============================================================================

bool RingTransition::HandleInt2E(CPUState& cpu) {
    std::unique_lock lock(m_impl->mutex);

    auto* msr = m_impl->msr;
    if (!msr) {
        return false;
    }

    GuestAddress fromRIP = cpu.GetRIP();
    uint64_t     fromRSP = cpu.RSP();
    uint32_t     syscallNum = static_cast<uint32_t>(cpu.RAX());
    uint8_t      prevCPL = m_impl->currentCPL;

    // INT 0x2E transitions to kernel: use SYSENTER_EIP as handler
    // (on modern Windows, INT 0x2E is typically redirected to KiSystemService)
    uint64_t sysenterEIP = 0;
    if (!msr->ReadMSR(MSRIndex::SYSENTER_EIP, sysenterEIP)) {
        return false;
    }

    // Read SYSENTER CS for the kernel CS selector
    uint64_t sysenterCS = 0;
    if (!msr->ReadMSR(MSRIndex::SYSENTER_CS, sysenterCS)) {
        return false;
    }

    // Set kernel-mode segments
    uint16_t cs = static_cast<uint16_t>(sysenterCS & 0xFFFF);
    if (cs == 0) cs = 0x10; // Fallback to standard kernel CS
    uint16_t ss = 0;
    if (!RingAddSelectorOffset(cs, 8, ss) || !RingIsCanonicalAddress(sysenterEIP)) {
        return false;
    }

    cpu.SetSegmentSelector(SegReg::CS, cs);
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].base   = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].dpl    = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is64bit = true;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is32bit = false;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].present = true;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].type   = 0x0B;

    cpu.SetSegmentSelector(SegReg::SS, ss);
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].base   = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].dpl    = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].present = true;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].type   = 0x03;

    // Clear IF, TF
    cpu.eflags.SetIF(false);
    cpu.eflags.SetTF(false);

    // Set RIP to handler
    cpu.SetRIP(static_cast<GuestAddress>(sysenterEIP));

    // Set CPL = 0
    m_impl->currentCPL = 0;

    // Record event
    RingTransitionEvent event{};
    event.type          = TransitionType::Int2E;
    event.fromRing      = prevCPL;
    event.toRing        = 0;
    event.fromRIP       = fromRIP;
    event.toRIP         = static_cast<GuestAddress>(sysenterEIP);
    event.rflags        = cpu.eflags.Raw();
    event.rsp           = fromRSP;
    event.syscallNumber = syscallNum;
    event.timestamp     = cpu.instructionCount;
    (void)m_impl->RecordEvent(event);

    (void)m_impl->RecordSyscall(syscallNum);

    return true;
}

// ============================================================================
// IRETQ Handler
// ============================================================================

bool RingTransition::HandleIret(CPUState& cpu, VirtualMemory& memory) {
    std::unique_lock lock(m_impl->mutex);

    GuestAddress fromRIP = cpu.GetRIP();
    uint64_t     rsp     = cpu.RSP();

    // IRETQ pops: RIP, CS, RFLAGS, RSP, SS (each 8 bytes in 64-bit mode)
    uint64_t newRIP = 0, newCS = 0, newRFLAGS = 0, newRSP = 0, newSS = 0;
    GuestAddress ripSlot = 0, csSlot = 0, flagsSlot = 0, rspSlot = 0, ssSlot = 0;

    if (!RingAddGuest(rsp, 0, ripSlot) ||
        !RingAddGuest(rsp, 8, csSlot) ||
        !RingAddGuest(rsp, 16, flagsSlot) ||
        !RingAddGuest(rsp, 24, rspSlot) ||
        !RingAddGuest(rsp, 32, ssSlot)) {
        return false;
    }

    if (memory.ReadU64(ripSlot,   newRIP)    != ErrorCode::Success) return false;
    if (memory.ReadU64(csSlot,    newCS)     != ErrorCode::Success) return false;
    if (memory.ReadU64(flagsSlot, newRFLAGS) != ErrorCode::Success) return false;
    if (memory.ReadU64(rspSlot,   newRSP)    != ErrorCode::Success) return false;
    if (memory.ReadU64(ssSlot,    newSS)     != ErrorCode::Success) return false;

    // Validate canonical RIP
    if (!RingIsCanonicalAddress(newRIP) || !RingIsCanonicalAddress(newRSP) ||
        newCS > (std::numeric_limits<uint16_t>::max)() ||
        newSS > (std::numeric_limits<uint16_t>::max)()) {
        return false;
    }

    // Determine target CPL from CS DPL (low 2 bits of selector)
    uint8_t targetCPL = static_cast<uint8_t>(newCS & 0x03);
    uint8_t prevCPL   = m_impl->currentCPL;

    cpu.SetRIP(static_cast<GuestAddress>(newRIP));
    cpu.SetSegmentSelector(SegReg::CS, static_cast<uint16_t>(newCS));
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].dpl    = targetCPL;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is64bit = true;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is32bit = false;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].present = true;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].base   = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].type   = 0x0B;

    cpu.eflags.SetRaw(newRFLAGS);

    cpu.SetReg64(GPR::RSP, newRSP);

    cpu.SetSegmentSelector(SegReg::SS, static_cast<uint16_t>(newSS));
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].dpl    = targetCPL;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].present = true;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].base   = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].type   = 0x03;

    m_impl->currentCPL = targetCPL;

    // Record event
    RingTransitionEvent event{};
    event.type          = TransitionType::Iret;
    event.fromRing      = prevCPL;
    event.toRing        = targetCPL;
    event.fromRIP       = fromRIP;
    event.toRIP         = static_cast<GuestAddress>(newRIP);
    event.rflags        = newRFLAGS;
    event.rsp           = newRSP;
    event.syscallNumber = 0;
    event.timestamp     = cpu.instructionCount;
    (void)m_impl->RecordEvent(event);

    return true;
}

// ============================================================================
// CPL Accessors
// ============================================================================

uint8_t RingTransition::GetCPL() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->currentCPL;
}

void RingTransition::SetCPL(uint8_t cpl) {
    std::unique_lock lock(m_impl->mutex);
    m_impl->currentCPL = (cpl <= 3) ? cpl : 3;
}

bool RingTransition::IsKernelMode() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->currentCPL == 0;
}

bool RingTransition::IsUserMode() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->currentCPL == 3;
}

// ============================================================================
// Transition History
// ============================================================================

std::vector<RingTransitionEvent> RingTransition::GetHistory() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->history;
}

uint32_t RingTransition::GetSyscallCount() const {
    return m_impl->syscallCount.load(std::memory_order_relaxed);
}

uint32_t RingTransition::GetTransitionCount() const {
    return m_impl->transitionCount.load(std::memory_order_relaxed);
}

// ============================================================================
// Anomaly Detection
// ============================================================================

std::vector<RingTransitionAnomaly> RingTransition::DetectAnomalies() const {
    std::shared_lock lock(m_impl->mutex);
    std::vector<RingTransitionAnomaly> anomalies;

    for (const auto& event : m_impl->history) {
        // Check: User-space RIP executing at Ring 0
        if (event.toRing == 0 && KernelAddressSpace::IsUserAddress(event.toRIP)) {
            RingTransitionAnomaly anomaly;
            anomaly.type        = RingTransitionAnomaly::Type::UserCodeAtRing0;
            anomaly.description = "User-space RIP 0x" + std::to_string(event.toRIP) +
                                  " executing at CPL=0 — possible exploitation";
            anomaly.event       = event;
            anomalies.push_back(std::move(anomaly));
        }

        // Check: Kernel RIP at Ring 3
        if (event.toRing == 3 && KernelAddressSpace::IsKernelAddress(event.toRIP)) {
            RingTransitionAnomaly anomaly;
            anomaly.type        = RingTransitionAnomaly::Type::KernelCodeAtRing3;
            anomaly.description = "Kernel-space RIP 0x" + std::to_string(event.toRIP) +
                                  " at CPL=3 — possible SYSRET exploit";
            anomaly.event       = event;
            anomalies.push_back(std::move(anomaly));
        }

        // Check: SYSCALL when already in Ring 0
        if (event.type == TransitionType::Syscall && event.fromRing == 0) {
            RingTransitionAnomaly anomaly;
            anomaly.type        = RingTransitionAnomaly::Type::SyscallFromKernel;
            anomaly.description = "SYSCALL executed from Ring 0 — abnormal kernel behavior";
            anomaly.event       = event;
            anomalies.push_back(std::move(anomaly));
        }

        // Check: SYSRET to kernel address
        if (event.type == TransitionType::Sysret &&
            KernelAddressSpace::IsKernelAddress(event.toRIP)) {
            RingTransitionAnomaly anomaly;
            anomaly.type        = RingTransitionAnomaly::Type::SysretToKernel;
            anomaly.description = "SYSRET targeting kernel address 0x" +
                                  std::to_string(event.toRIP);
            anomaly.event       = event;
            anomalies.push_back(std::move(anomaly));
        }

        // Check: Invalid syscall number
        if ((event.type == TransitionType::Syscall ||
             event.type == TransitionType::Sysenter ||
             event.type == TransitionType::Int2E) &&
            event.syscallNumber > kMaxSyscallNumber) {
            RingTransitionAnomaly anomaly;
            anomaly.type        = RingTransitionAnomaly::Type::InvalidSyscallNumber;
            anomaly.description = "Syscall number " + std::to_string(event.syscallNumber) +
                                  " exceeds maximum " + std::to_string(kMaxSyscallNumber);
            anomaly.event       = event;
            anomalies.push_back(std::move(anomaly));
        }

        // Check: Non-canonical return address on SYSRET/IRET
        if ((event.type == TransitionType::Sysret || event.type == TransitionType::Iret) &&
            !RingIsCanonicalAddress(event.toRIP)) {
            RingTransitionAnomaly anomaly;
            anomaly.type        = RingTransitionAnomaly::Type::NonCanonicalReturn;
            anomaly.description = "Return to non-canonical address 0x" +
                                  std::to_string(event.toRIP);
            anomaly.event       = event;
            anomalies.push_back(std::move(anomaly));
        }
    }

    // Check for stack pivots: compare RSP between consecutive events
    for (size_t i = 1; i < m_impl->history.size(); ++i) {
        const auto& prev = m_impl->history[i - 1];
        const auto& curr = m_impl->history[i];

        // Only flag if the transition pair is to/from the same ring and RSP changed dramatically
        if (curr.type == TransitionType::Syscall || curr.type == TransitionType::Sysenter) {
            uint64_t rspDiff = (curr.rsp > prev.rsp)
                                   ? (curr.rsp - prev.rsp)
                                   : (prev.rsp - curr.rsp);
            if (rspDiff > kStackPivotThreshold) {
                RingTransitionAnomaly anomaly;
                anomaly.type        = RingTransitionAnomaly::Type::StackPivot;
                anomaly.description = "RSP shifted by 0x" + std::to_string(rspDiff) +
                                      " bytes between transitions — possible stack pivot";
                anomaly.event       = curr;
                anomalies.push_back(std::move(anomaly));
            }
        }
    }

    return anomalies;
}

// ============================================================================
// Syscall Histogram
// ============================================================================

std::vector<std::pair<uint32_t, uint32_t>> RingTransition::GetSyscallHistogram() const {
    std::shared_lock lock(m_impl->mutex);

    std::vector<std::pair<uint32_t, uint32_t>> histogram(
        m_impl->syscallCounts.begin(), m_impl->syscallCounts.end());

    // Sort by count descending
    std::sort(histogram.begin(), histogram.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    return histogram;
}

} // namespace Phantom
