/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace Phantom {

class VirtualMemory;

// ============================================================================
// Kernel Address Space Constants (Windows x64)
// ============================================================================

static constexpr GuestAddress kKernelBase       = 0xFFFFF80000000000ULL;
static constexpr GuestAddress kKernelEnd        = 0xFFFFFFFFFFFFFFFFULL;
static constexpr GuestAddress kUserSharedData   = 0x7FFE0000ULL;
static constexpr GuestAddress kKernelSharedData = 0xFFFFF78000000000ULL;
static constexpr GuestAddress kNonPagedPoolBase = 0xFFFFF80100000000ULL;
static constexpr GuestAddress kPagedPoolBase    = 0xFFFFF80200000000ULL;
static constexpr GuestAddress kSystemPteBase    = 0xFFFFF80300000000ULL;
static constexpr GuestAddress kDriverBase       = 0xFFFFF80400000000ULL;

// ============================================================================
// Pool Types
// ============================================================================

enum class PoolType : uint8_t {
    NonPagedPool,
    NonPagedPoolNx,
    PagedPool
};

// ============================================================================
// Kernel Allocation Descriptor
// ============================================================================

struct KernelAllocation {
    GuestAddress base;
    GuestSize    size;
    PoolType     poolType;
    uint32_t     tag;           // 4-char pool tag (e.g., 'SdSt')
    bool         freed = false;
};

// ============================================================================
// Kernel Region Descriptor
// ============================================================================

struct KernelRegionInfo {
    GuestAddress base;
    GuestSize    size;
    std::string  name;
    bool         isSupervisor;
    uint32_t     protection;
};

// ============================================================================
// Kernel Address Space Manager
// ============================================================================
// Manages dual-mode address space for kernel-mode emulation:
// - Kernel memory mapping and region tracking
// - Address classification (user vs. kernel canonical ranges)
// - CPL-based supervisor page access enforcement
// - KUSER_SHARED_DATA population with Windows 10/11 values
// - NonPagedPool / PagedPool emulation with pool tag tracking
// - Guard-byte pool integrity validation for overflow detection
//
// Thread-safe: shared_mutex protects all mutable state.
// Singleton: Meyers' singleton — one kernel address space per process.

class KernelAddressSpace {
public:
    static KernelAddressSpace& Instance();

    // Initialize kernel address space with reference to guest memory
    bool Initialize(VirtualMemory& memory);
    void Reset();

    // === Address Classification ===

    [[nodiscard]] static bool IsKernelAddress(GuestAddress addr);
    [[nodiscard]] static bool IsUserAddress(GuestAddress addr);
    [[nodiscard]] static bool IsCanonicalAddress(GuestAddress addr);

    // CPL-based access check — returns true if access is allowed
    [[nodiscard]] bool CheckAccess(GuestAddress addr, uint8_t cpl, bool write);

    // === Kernel Pool Allocation (ExAllocatePoolWithTag emulation) ===

    [[nodiscard]] std::optional<GuestAddress> AllocatePool(PoolType type, GuestSize size, uint32_t tag);
    void FreePool(GuestAddress addr);

    // === Kernel Region Mapping ===

    [[nodiscard]] bool MapKernelRegion(GuestAddress base, GuestSize size,
                                       const std::string& name, uint32_t protection,
                                       const void* data = nullptr, uint32_t dataSize = 0);

    // === Region Queries ===

    [[nodiscard]] std::optional<KernelRegionInfo> FindRegion(GuestAddress addr) const;
    [[nodiscard]] std::vector<KernelRegionInfo> GetAllRegions() const;
    [[nodiscard]] std::vector<KernelAllocation> GetPoolAllocations() const;

    // === KUSER_SHARED_DATA Setup ===

    void InitializeSharedUserData();

    // === Pool Statistics ===

    [[nodiscard]] GuestSize GetNonPagedPoolUsed() const;
    [[nodiscard]] GuestSize GetPagedPoolUsed() const;
    [[nodiscard]] uint32_t GetAllocationCount() const;

    // === Pool Tag Tracking (leak detection) ===

    struct PoolTagStats {
        uint32_t  tag;
        uint32_t  allocCount;
        uint32_t  freeCount;
        GuestSize totalBytes;
    };

    [[nodiscard]] std::vector<PoolTagStats> GetPoolTagStatistics() const;

    // Detect pool corruption/overflow via guard bytes
    [[nodiscard]] bool ValidatePoolIntegrity() const;

private:
    KernelAddressSpace();
    ~KernelAddressSpace();

    KernelAddressSpace(const KernelAddressSpace&) = delete;
    KernelAddressSpace& operator=(const KernelAddressSpace&) = delete;
    KernelAddressSpace(KernelAddressSpace&&) = delete;
    KernelAddressSpace& operator=(KernelAddressSpace&&) = delete;

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
