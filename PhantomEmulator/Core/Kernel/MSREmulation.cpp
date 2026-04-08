/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MSREmulation — Model-Specific Register emulation implementation
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "MSREmulation.hpp"
#include "../../Common/Types.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

namespace Phantom {

// ============================================================================
// MSR Name Lookup (for diagnostics and hook-detection reports)
// ============================================================================

static const char* GetMSRName(uint32_t index) noexcept {
    switch (index) {
        case MSRIndex::APIC_BASE:       return "IA32_APIC_BASE";
        case MSRIndex::SYSENTER_CS:     return "IA32_SYSENTER_CS";
        case MSRIndex::SYSENTER_ESP:    return "IA32_SYSENTER_ESP";
        case MSRIndex::SYSENTER_EIP:    return "IA32_SYSENTER_EIP";
        case MSRIndex::DEBUGCTL:        return "IA32_DEBUGCTL";
        case MSRIndex::PAT:             return "IA32_PAT";
        case MSRIndex::MTRR_DEF_TYPE:   return "IA32_MTRR_DEF_TYPE";
        case MSRIndex::EFER:            return "IA32_EFER";
        case MSRIndex::STAR:            return "IA64_STAR";
        case MSRIndex::LSTAR:           return "IA64_LSTAR";
        case MSRIndex::CSTAR:           return "IA64_CSTAR";
        case MSRIndex::SFMASK:          return "IA64_SFMASK";
        case MSRIndex::FS_BASE:         return "IA64_FS_BASE";
        case MSRIndex::GS_BASE:         return "IA64_GS_BASE";
        case MSRIndex::KERNEL_GS_BASE:  return "IA64_KERNEL_GS_BASE";
        case MSRIndex::TSC_AUX:         return "IA32_TSC_AUX";
        default:                        return "UNKNOWN_MSR";
    }
}

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct MSREmulation::Impl {
    // MSR register store: index → current value
    std::unordered_map<uint32_t, uint64_t> registers;

    // Original values snapshot (taken after InitializeDefaults)
    std::unordered_map<uint32_t, uint64_t> originalValues;

    // Access counters
    std::atomic<uint32_t> readCount{0};
    std::atomic<uint32_t> writeCount{0};

    mutable std::shared_mutex mutex;

    // Set of valid MSR indices this emulator supports
    bool IsSupportedMSR(uint32_t index) const noexcept {
        switch (index) {
            case MSRIndex::APIC_BASE:
            case MSRIndex::SYSENTER_CS:
            case MSRIndex::SYSENTER_ESP:
            case MSRIndex::SYSENTER_EIP:
            case MSRIndex::DEBUGCTL:
            case MSRIndex::PAT:
            case MSRIndex::MTRR_DEF_TYPE:
            case MSRIndex::EFER:
            case MSRIndex::STAR:
            case MSRIndex::LSTAR:
            case MSRIndex::CSTAR:
            case MSRIndex::SFMASK:
            case MSRIndex::FS_BASE:
            case MSRIndex::GS_BASE:
            case MSRIndex::KERNEL_GS_BASE:
            case MSRIndex::TSC_AUX:
                return true;
            default:
                return false;
        }
    }
};

// ============================================================================
// Singleton
// ============================================================================

MSREmulation& MSREmulation::Instance() {
    static MSREmulation instance;
    return instance;
}

MSREmulation::MSREmulation()
    : m_impl(std::make_unique<Impl>())
{
    InitializeDefaults();
}

MSREmulation::~MSREmulation() = default;

// ============================================================================
// Reset
// ============================================================================

void MSREmulation::Reset() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->registers.clear();
    m_impl->originalValues.clear();
    m_impl->readCount.store(0, std::memory_order_relaxed);
    m_impl->writeCount.store(0, std::memory_order_relaxed);
    lock.unlock();
    InitializeDefaults();
}

// ============================================================================
// Initialize with Windows 10/11 x64 Default Values
// ============================================================================

void MSREmulation::InitializeDefaults() {
    std::unique_lock lock(m_impl->mutex);

    auto& regs = m_impl->registers;

    // EFER: SYSCALL enable + Long Mode Enable + Long Mode Active + NX Enable
    regs[MSRIndex::EFER] = EFERBits::SCE | EFERBits::LME | EFERBits::LMA | EFERBits::NXE;

    // STAR: Ring 0 CS=0x0010, Ring 3 CS=0x0033 (STAR[47:32]=0x0010, STAR[63:48]=0x0023)
    // STAR layout: [63:48] = SYSRET CS base, [47:32] = SYSCALL CS, [31:0] = target EIP (32-bit, unused in 64)
    // Windows: SYSCALL CS=0x10, SS=0x18; SYSRET CS=0x33, SS=0x2B
    // Encoded: (0x0023ULL << 48) | (0x0010ULL << 32)
    regs[MSRIndex::STAR] = (0x0023ULL << 48) | (0x0010ULL << 32);

    // LSTAR: Typical Windows ntoskrnl KiSystemCall64 address
    regs[MSRIndex::LSTAR] = 0xFFFFF80000200000ULL;

    // CSTAR: Compatibility mode SYSCALL target (rarely used on Win64)
    regs[MSRIndex::CSTAR] = 0xFFFFF80000200100ULL;

    // SFMASK: Mask TF, IF, DF, AC, NT during SYSCALL
    // TF=0x100, IF=0x200, DF=0x400, AC=0x40000, NT=0x4000
    regs[MSRIndex::SFMASK] = 0x00000000000047700ULL;

    // FS_BASE: User-mode TEB address (typical)
    regs[MSRIndex::FS_BASE] = 0x0000000000000000ULL;

    // GS_BASE: In kernel mode, points to KPCR
    regs[MSRIndex::GS_BASE] = 0xFFFFF78000000000ULL;

    // KERNEL_GS_BASE: The user-mode GS value saved by SWAPGS
    regs[MSRIndex::KERNEL_GS_BASE] = 0x000000007FFE0000ULL;

    // TSC_AUX: Processor ID for RDTSCP (processor 0)
    regs[MSRIndex::TSC_AUX] = 0;

    // SYSENTER MSRs (used by 32-bit compat path)
    regs[MSRIndex::SYSENTER_CS]  = 0x0010;
    regs[MSRIndex::SYSENTER_ESP] = 0xFFFFF80000201000ULL;
    regs[MSRIndex::SYSENTER_EIP] = 0xFFFFF80000200200ULL;

    // APIC_BASE: Default APIC base with BSP flag and enable bit
    // Bit 8 = BSP, Bit 11 = APIC Global Enable, Bits [35:12] = base address
    regs[MSRIndex::APIC_BASE] = 0xFEE00900ULL;

    // PAT: Default Page Attribute Table
    // PA0=WB(06), PA1=WT(04), PA2=UC-(07), PA3=UC(00), PA4=WB, PA5=WT, PA6=UC-, PA7=UC
    regs[MSRIndex::PAT] = 0x0007040600070406ULL;

    // DEBUGCTL: All debug features disabled by default
    regs[MSRIndex::DEBUGCTL] = 0;

    // MTRR_DEF_TYPE: Default type = WB (06), MTRR enabled (bit 11), fixed-range enabled (bit 10)
    regs[MSRIndex::MTRR_DEF_TYPE] = 0x0C06ULL;

    // Snapshot all values as originals for hook detection
    m_impl->originalValues = regs;
}

// ============================================================================
// RDMSR
// ============================================================================

bool MSREmulation::ReadMSR(uint32_t msrIndex, uint64_t& value) const {
    std::shared_lock lock(m_impl->mutex);

    if (!m_impl->IsSupportedMSR(msrIndex)) {
        return false;
    }

    auto it = m_impl->registers.find(msrIndex);
    if (it != m_impl->registers.end()) {
        value = it->second;
    } else {
        value = 0;
    }

    m_impl->readCount.fetch_add(1, std::memory_order_relaxed);
    return true;
}

// ============================================================================
// WRMSR
// ============================================================================

bool MSREmulation::WriteMSR(uint32_t msrIndex, uint64_t value) {
    std::unique_lock lock(m_impl->mutex);

    if (!m_impl->IsSupportedMSR(msrIndex)) {
        return false;
    }

    // Enforce write masks on certain MSRs to prevent invalid states
    switch (msrIndex) {
        case MSRIndex::EFER: {
            // Only SCE, LME, LMA, NXE bits are writable
            constexpr uint64_t kEFERWriteMask = EFERBits::SCE | EFERBits::LME |
                                                 EFERBits::LMA | EFERBits::NXE;
            value &= kEFERWriteMask;
            break;
        }
        case MSRIndex::DEBUGCTL: {
            // Only low 16 bits are defined
            value &= 0xFFFF;
            break;
        }
        case MSRIndex::MTRR_DEF_TYPE: {
            // Bits [7:0] = type, bit 10 = FE, bit 11 = E
            value &= 0x0CFF;
            break;
        }
        case MSRIndex::APIC_BASE: {
            // Preserve BSP flag (bit 8), allow enable (bit 11) and base address [35:12]
            constexpr uint64_t kAPICWriteMask = 0x0000000FFFFFF900ULL;
            value &= kAPICWriteMask;
            break;
        }
        case MSRIndex::TSC_AUX: {
            // Only low 32 bits are architecturally defined
            value &= 0xFFFFFFFF;
            break;
        }
        case MSRIndex::SYSENTER_CS: {
            // Only low 16 bits meaningful
            value &= 0xFFFF;
            break;
        }
        default:
            break;
    }

    m_impl->registers[msrIndex] = value;
    m_impl->writeCount.fetch_add(1, std::memory_order_relaxed);
    return true;
}

// ============================================================================
// Hot-Path Accessors
// ============================================================================

GuestAddress MSREmulation::GetLSTAR() const {
    std::shared_lock lock(m_impl->mutex);
    auto it = m_impl->registers.find(MSRIndex::LSTAR);
    return (it != m_impl->registers.end()) ? it->second : 0;
}

uint64_t MSREmulation::GetSTAR() const {
    std::shared_lock lock(m_impl->mutex);
    auto it = m_impl->registers.find(MSRIndex::STAR);
    return (it != m_impl->registers.end()) ? it->second : 0;
}

uint64_t MSREmulation::GetSFMASK() const {
    std::shared_lock lock(m_impl->mutex);
    auto it = m_impl->registers.find(MSRIndex::SFMASK);
    return (it != m_impl->registers.end()) ? it->second : 0;
}

GuestAddress MSREmulation::GetGSBase() const {
    std::shared_lock lock(m_impl->mutex);
    auto it = m_impl->registers.find(MSRIndex::GS_BASE);
    return (it != m_impl->registers.end()) ? it->second : 0;
}

GuestAddress MSREmulation::GetKernelGSBase() const {
    std::shared_lock lock(m_impl->mutex);
    auto it = m_impl->registers.find(MSRIndex::KERNEL_GS_BASE);
    return (it != m_impl->registers.end()) ? it->second : 0;
}

GuestAddress MSREmulation::GetFSBase() const {
    std::shared_lock lock(m_impl->mutex);
    auto it = m_impl->registers.find(MSRIndex::FS_BASE);
    return (it != m_impl->registers.end()) ? it->second : 0;
}

// ============================================================================
// SWAPGS Emulation
// ============================================================================

void MSREmulation::SwapGS() {
    std::unique_lock lock(m_impl->mutex);
    auto& regs = m_impl->registers;
    uint64_t gsBase       = regs[MSRIndex::GS_BASE];
    uint64_t kernelGSBase = regs[MSRIndex::KERNEL_GS_BASE];
    regs[MSRIndex::GS_BASE]        = kernelGSBase;
    regs[MSRIndex::KERNEL_GS_BASE] = gsBase;
}

// ============================================================================
// Hook Detection
// ============================================================================

std::vector<MSRModification> MSREmulation::DetectModifications() const {
    std::shared_lock lock(m_impl->mutex);
    std::vector<MSRModification> results;

    // Security-critical MSRs to monitor
    static constexpr uint32_t kMonitoredMSRs[] = {
        MSRIndex::LSTAR,
        MSRIndex::CSTAR,
        MSRIndex::STAR,
        MSRIndex::SFMASK,
        MSRIndex::EFER,
        MSRIndex::SYSENTER_EIP,
        MSRIndex::SYSENTER_ESP,
        MSRIndex::SYSENTER_CS,
        MSRIndex::DEBUGCTL,
        MSRIndex::GS_BASE,
        MSRIndex::KERNEL_GS_BASE,
    };

    for (uint32_t idx : kMonitoredMSRs) {
        auto origIt = m_impl->originalValues.find(idx);
        auto currIt = m_impl->registers.find(idx);
        if (origIt == m_impl->originalValues.end() || currIt == m_impl->registers.end()) {
            continue;
        }
        if (origIt->second != currIt->second) {
            MSRModification mod;
            mod.msrIndex      = idx;
            mod.originalValue = origIt->second;
            mod.currentValue  = currIt->second;
            mod.msrName       = GetMSRName(idx);
            results.push_back(std::move(mod));
        }
    }

    return results;
}

// ============================================================================
// Statistics
// ============================================================================

uint32_t MSREmulation::GetReadCount() const {
    return m_impl->readCount.load(std::memory_order_relaxed);
}

uint32_t MSREmulation::GetWriteCount() const {
    return m_impl->writeCount.load(std::memory_order_relaxed);
}

} // namespace Phantom
