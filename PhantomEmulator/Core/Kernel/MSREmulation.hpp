/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MSREmulation — Model-Specific Register emulation for kernel-mode analysis
 *
 * Rootkits and kernel-mode malware read/write MSRs to:
 *   - Hook SYSCALL entry (LSTAR)
 *   - Modify GS_BASE for thread-local storage manipulation
 *   - Read/write debug control MSRs
 *   - Detect and evade virtualization
 *
 * This module emulates RDMSR/WRMSR with a full MSR register map,
 * tracks modifications to security-critical MSRs for hook detection,
 * and provides SWAPGS instruction emulation.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Phantom {

// ============================================================================
// MSR Index Constants
// ============================================================================

namespace MSRIndex {
    static constexpr uint32_t APIC_BASE       = 0x0000001B;
    static constexpr uint32_t SYSENTER_CS     = 0x00000174;
    static constexpr uint32_t SYSENTER_ESP    = 0x00000175;
    static constexpr uint32_t SYSENTER_EIP    = 0x00000176;
    static constexpr uint32_t DEBUGCTL        = 0x000001D9;
    static constexpr uint32_t PAT             = 0x00000277;
    static constexpr uint32_t MTRR_DEF_TYPE   = 0x000002FF;
    static constexpr uint32_t EFER            = 0xC0000080;
    static constexpr uint32_t STAR            = 0xC0000081;
    static constexpr uint32_t LSTAR           = 0xC0000082;
    static constexpr uint32_t CSTAR           = 0xC0000083;
    static constexpr uint32_t SFMASK          = 0xC0000084;
    static constexpr uint32_t FS_BASE         = 0xC0000100;
    static constexpr uint32_t GS_BASE         = 0xC0000101;
    static constexpr uint32_t KERNEL_GS_BASE  = 0xC0000102;
    static constexpr uint32_t TSC_AUX         = 0xC0000103;
} // namespace MSRIndex

// ============================================================================
// EFER Bit Definitions
// ============================================================================

namespace EFERBits {
    static constexpr uint64_t SCE  = 1ULL << 0;   // SYSCALL Enable
    static constexpr uint64_t LME  = 1ULL << 8;   // Long Mode Enable
    static constexpr uint64_t LMA  = 1ULL << 10;  // Long Mode Active
    static constexpr uint64_t NXE  = 1ULL << 11;  // No-Execute Enable
} // namespace EFERBits

// ============================================================================
// MSR Modification Record (for hook detection)
// ============================================================================

struct MSRModification {
    uint32_t    msrIndex;
    uint64_t    originalValue;
    uint64_t    currentValue;
    std::string msrName;
};

// ============================================================================
// MSR Emulation Engine
// ============================================================================

class MSREmulation {
public:
    static MSREmulation& Instance();
    void Reset();

    // Core RDMSR/WRMSR — return false on invalid/unsupported MSR index
    [[nodiscard]] bool ReadMSR(uint32_t msrIndex, uint64_t& value) const;
    [[nodiscard]] bool WriteMSR(uint32_t msrIndex, uint64_t value);

    // Quick accessors for hot-path MSRs
    [[nodiscard]] GuestAddress GetLSTAR() const;
    [[nodiscard]] uint64_t GetSTAR() const;
    [[nodiscard]] uint64_t GetSFMASK() const;
    [[nodiscard]] GuestAddress GetGSBase() const;
    [[nodiscard]] GuestAddress GetKernelGSBase() const;
    [[nodiscard]] GuestAddress GetFSBase() const;

    // SWAPGS instruction emulation (swaps GS_BASE ↔ KERNEL_GS_BASE)
    void SwapGS();

    // Initialize with default Windows 10/11 x64 values
    void InitializeDefaults();

    // Hook detection: compare current values against initial snapshot
    [[nodiscard]] std::vector<MSRModification> DetectModifications() const;

    // Statistics
    [[nodiscard]] uint32_t GetReadCount() const;
    [[nodiscard]] uint32_t GetWriteCount() const;

private:
    MSREmulation();
    ~MSREmulation();

    MSREmulation(const MSREmulation&) = delete;
    MSREmulation& operator=(const MSREmulation&) = delete;
    MSREmulation(MSREmulation&&) = delete;
    MSREmulation& operator=(MSREmulation&&) = delete;

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
