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
#include <limits>
#include <mutex>
#include <new>
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
        case MSRIndex::STAR:            return "IA32_STAR";
        case MSRIndex::LSTAR:           return "IA32_LSTAR";
        case MSRIndex::CSTAR:           return "IA32_CSTAR";
        case MSRIndex::SFMASK:          return "IA32_SFMASK";
        case MSRIndex::FS_BASE:         return "IA32_FS_BASE";
        case MSRIndex::GS_BASE:         return "IA32_GS_BASE";
        case MSRIndex::KERNEL_GS_BASE:  return "IA32_KERNEL_GS_BASE";
        case MSRIndex::TSC_AUX:         return "IA32_TSC_AUX";
        default:                        return "UNKNOWN_MSR";
    }
}

[[nodiscard]] bool IsCanonicalAddress(uint64_t value) noexcept {
    const uint64_t top17 = value >> 47;
    return top17 == 0 || top17 == 0x1FFFFULL;
}

[[nodiscard]] bool IsValidMemoryType(uint8_t type) noexcept {
    switch (type) {
        case 0x00: // UC
        case 0x01: // WC
        case 0x04: // WT
        case 0x05: // WP
        case 0x06: // WB
        case 0x07: // UC-
            return true;
        default:
            return false;
    }
}

[[nodiscard]] bool IsValidPAT(uint64_t pat) noexcept {
    for (uint32_t i = 0; i < 8; ++i) {
        const auto type = static_cast<uint8_t>((pat >> (i * 8)) & 0xFFU);
        if (!IsValidMemoryType(type)) {
            return false;
        }
    }
    return true;
}

void SaturatingIncrement(std::atomic<uint32_t>& counter) noexcept {
    uint32_t current = counter.load(std::memory_order_relaxed);
    while (current != (std::numeric_limits<uint32_t>::max)()) {
        if (counter.compare_exchange_weak(current, current + 1,
                                          std::memory_order_relaxed,
                                          std::memory_order_relaxed)) {
            return;
        }
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
    regs.clear();
    m_impl->originalValues.clear();
    try {
        regs.reserve(16);
        m_impl->originalValues.reserve(16);
    } catch (const std::bad_alloc&) {
        regs.clear();
        m_impl->originalValues.clear();
        return;
    }

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

    SaturatingIncrement(m_impl->readCount);
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
    const uint64_t previousValue = [this, msrIndex]() noexcept {
        auto it = m_impl->registers.find(msrIndex);
        return (it != m_impl->registers.end()) ? it->second : 0ULL;
    }();

    // Enforce write masks on certain MSRs to prevent invalid states
    switch (msrIndex) {
        case MSRIndex::EFER: {
            // LMA is CPU-derived/read-only; guest WRMSR may alter SCE/LME/NXE only.
            constexpr uint64_t kEFERWritableMask = EFERBits::SCE | EFERBits::LME | EFERBits::NXE;
            value = (previousValue & EFERBits::LMA) | (value & kEFERWritableMask);
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
            if (!IsValidMemoryType(static_cast<uint8_t>(value & 0xFFU))) {
                return false;
            }
            break;
        }
        case MSRIndex::APIC_BASE: {
            // Preserve BSP flag (bit 8), allow enable (bit 11) and base address [35:12]
            constexpr uint64_t kAPICWriteMask = 0x0000000FFFFFF900ULL;
            constexpr uint64_t kBspMask = 1ULL << 8;
            value = (value & (kAPICWriteMask & ~kBspMask)) | (previousValue & kBspMask);
            break;
        }
        case MSRIndex::PAT: {
            if (!IsValidPAT(value)) {
                return false;
            }
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
        case MSRIndex::LSTAR:
        case MSRIndex::CSTAR:
        case MSRIndex::FS_BASE:
        case MSRIndex::GS_BASE:
        case MSRIndex::KERNEL_GS_BASE:
        case MSRIndex::SYSENTER_ESP:
        case MSRIndex::SYSENTER_EIP:
            if (!IsCanonicalAddress(value)) {
                return false;
            }
            break;
        default:
            break;
    }

    try {
        m_impl->registers[msrIndex] = value;
    } catch (const std::bad_alloc&) {
        return false;
    }
    SaturatingIncrement(m_impl->writeCount);
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
    auto gsIt = regs.find(MSRIndex::GS_BASE);
    auto kernelGsIt = regs.find(MSRIndex::KERNEL_GS_BASE);
    if (gsIt == regs.end() || kernelGsIt == regs.end()) {
        return;
    }
    std::swap(gsIt->second, kernelGsIt->second);
}

// ============================================================================
// Hook Detection
// ============================================================================

std::vector<MSRModification> MSREmulation::DetectModifications() const {
    std::shared_lock lock(m_impl->mutex);
    std::vector<MSRModification> results;
    try {
        results.reserve(16);
    } catch (const std::bad_alloc&) {
        return results;
    }

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
