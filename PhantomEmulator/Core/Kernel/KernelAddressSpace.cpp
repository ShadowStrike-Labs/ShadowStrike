/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "KernelAddressSpace.hpp"
#include "../Memory/VirtualMemory.hpp"
#include "../../Common/Platform.hpp"
#include <algorithm>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace Phantom {

// ============================================================================
// Pool Limits
// ============================================================================

static constexpr GuestSize kMaxNonPagedPool = 64ULL * 1024 * 1024;    // 64 MB
static constexpr GuestSize kMaxPagedPool    = 128ULL * 1024 * 1024;   // 128 MB
static constexpr uint32_t  kMaxPoolAllocs   = 8192;

// Guard pattern written before and after each pool allocation
static constexpr uint32_t  kGuardPattern    = 0xDEADBEEF;
static constexpr uint32_t  kGuardSize       = 16;  // bytes of guard on each side
static constexpr uint32_t  kPoolAlignment   = 16;  // NonPagedPool minimum alignment

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct KernelAddressSpace::Impl {
    VirtualMemory*                          memory = nullptr;
    bool                                    initialized = false;

    // Kernel region registry
    std::vector<KernelRegionInfo>           regions;

    // Pool allocations indexed by base address
    std::unordered_map<GuestAddress, KernelAllocation> poolAllocations;

    // Pool cursors — next free address in each pool
    GuestAddress                            nonPagedPoolCursor = kNonPagedPoolBase;
    GuestAddress                            pagedPoolCursor    = kPagedPoolBase;

    // Pool usage counters
    GuestSize                               nonPagedPoolUsed = 0;
    GuestSize                               pagedPoolUsed    = 0;
    uint32_t                                allocationCount  = 0;

    // Pool tag statistics
    std::unordered_map<uint32_t, PoolTagStats> tagStats;

    mutable std::shared_mutex               mutex;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    [[nodiscard]] GuestSize TotalAllocationSize(GuestSize requestedSize) const noexcept {
        // guard_front + aligned_payload + guard_back, page-aligned for large allocs
        GuestSize aligned = AlignUp(requestedSize, kPoolAlignment);
        return kGuardSize + aligned + kGuardSize;
    }

    void WriteGuardBytes(GuestAddress allocationBase, GuestSize totalSize) noexcept {
        if (!memory) return;

        // Front guard: kGuardSize bytes of kGuardPattern at allocationBase
        for (uint32_t i = 0; i < kGuardSize; i += sizeof(uint32_t)) {
            (void)memory->WriteU32(allocationBase + i, kGuardPattern);
        }

        // Back guard: kGuardSize bytes of kGuardPattern at end
        GuestAddress backGuard = allocationBase + totalSize - kGuardSize;
        for (uint32_t i = 0; i < kGuardSize; i += sizeof(uint32_t)) {
            (void)memory->WriteU32(backGuard + i, kGuardPattern);
        }
    }

    [[nodiscard]] bool VerifyGuardBytes(GuestAddress allocationBase, GuestSize totalSize) const noexcept {
        if (!memory) return false;

        // Verify front guard
        for (uint32_t i = 0; i < kGuardSize; i += sizeof(uint32_t)) {
            uint32_t val = 0;
            if (memory->ReadU32(allocationBase + i, val) != ErrorCode::Success) return false;
            if (val != kGuardPattern) return false;
        }

        // Verify back guard
        GuestAddress backGuard = allocationBase + totalSize - kGuardSize;
        for (uint32_t i = 0; i < kGuardSize; i += sizeof(uint32_t)) {
            uint32_t val = 0;
            if (memory->ReadU32(backGuard + i, val) != ErrorCode::Success) return false;
            if (val != kGuardPattern) return false;
        }

        return true;
    }

    void UpdateTagStats(uint32_t tag, GuestSize size, bool isAlloc) noexcept {
        auto& stats = tagStats[tag];
        stats.tag = tag;
        if (isAlloc) {
            stats.allocCount++;
            stats.totalBytes += size;
        } else {
            stats.freeCount++;
            if (stats.totalBytes >= size) {
                stats.totalBytes -= size;
            } else {
                stats.totalBytes = 0;
            }
        }
    }
};

// ============================================================================
// Singleton
// ============================================================================

KernelAddressSpace& KernelAddressSpace::Instance() {
    static KernelAddressSpace instance;
    return instance;
}

KernelAddressSpace::KernelAddressSpace()
    : m_impl(std::make_unique<Impl>()) {}

KernelAddressSpace::~KernelAddressSpace() = default;

// ============================================================================
// Initialization / Reset
// ============================================================================

bool KernelAddressSpace::Initialize(VirtualMemory& memory) {
    std::unique_lock lock(m_impl->mutex);

    if (m_impl->initialized) return false;

    m_impl->memory             = &memory;
    m_impl->nonPagedPoolCursor = kNonPagedPoolBase;
    m_impl->pagedPoolCursor    = kPagedPoolBase;
    m_impl->nonPagedPoolUsed   = 0;
    m_impl->pagedPoolUsed      = 0;
    m_impl->allocationCount    = 0;
    m_impl->regions.clear();
    m_impl->poolAllocations.clear();
    m_impl->tagStats.clear();
    m_impl->initialized        = true;

    return true;
}

void KernelAddressSpace::Reset() {
    std::unique_lock lock(m_impl->mutex);

    m_impl->memory             = nullptr;
    m_impl->nonPagedPoolCursor = kNonPagedPoolBase;
    m_impl->pagedPoolCursor    = kPagedPoolBase;
    m_impl->nonPagedPoolUsed   = 0;
    m_impl->pagedPoolUsed      = 0;
    m_impl->allocationCount    = 0;
    m_impl->regions.clear();
    m_impl->poolAllocations.clear();
    m_impl->tagStats.clear();
    m_impl->initialized        = false;
}

// ============================================================================
// Address Classification
// ============================================================================

bool KernelAddressSpace::IsKernelAddress(GuestAddress addr) {
    // Windows x64 kernel space: 0xFFFF800000000000 and above
    // Also include the KUSER_SHARED_DATA kernel mapping
    return addr >= 0xFFFF800000000000ULL;
}

bool KernelAddressSpace::IsUserAddress(GuestAddress addr) {
    // Windows x64 user space: 0 through 0x00007FFFFFFFFFFF
    return addr <= 0x00007FFFFFFFFFFFULL;
}

bool KernelAddressSpace::IsCanonicalAddress(GuestAddress addr) {
    // On x64, bits [63:48] must be all-zero or all-one (sign extension of bit 47)
    uint64_t top17 = addr >> 47;
    return top17 == 0 || top17 == 0x1FFFF;
}

// ============================================================================
// CPL-Based Access Control
// ============================================================================

bool KernelAddressSpace::CheckAccess(GuestAddress addr, uint8_t cpl, bool write) {
    std::shared_lock lock(m_impl->mutex);

    if (!m_impl->initialized) return false;

    // Non-canonical addresses are always invalid
    if (!IsCanonicalAddress(addr)) return false;

    // Ring 0 (kernel mode) can access everything
    if (cpl == 0) {
        // For kernel addresses, verify the region exists and check write protection
        if (IsKernelAddress(addr)) {
            for (const auto& region : m_impl->regions) {
                if (addr >= region.base && (addr - region.base) < region.size) {
                    if (write) {
                        return (region.protection & static_cast<uint32_t>(MemProt::Write)) != 0;
                    }
                    return true;
                }
            }
            // Check pool allocations — pool memory is always RW from ring 0
            for (const auto& [base, alloc] : m_impl->poolAllocations) {
                if (!alloc.freed && addr >= alloc.base &&
                    (addr - alloc.base) < alloc.size) {
                    return true;
                }
            }
            // Unmapped kernel address
            return false;
        }
        // Ring 0 accessing user-space is always allowed
        return true;
    }

    // Ring 3 (user mode): kernel pages are inaccessible
    if (IsKernelAddress(addr)) return false;

    // User-space KUSER_SHARED_DATA is readable from ring 3, but not writable
    if (addr >= kUserSharedData && addr < kUserSharedData + kPageSize) {
        return !write;
    }

    // All other user-space access is allowed (VirtualMemory handles per-page prot)
    return true;
}

// ============================================================================
// Kernel Pool Allocation
// ============================================================================

std::optional<GuestAddress> KernelAddressSpace::AllocatePool(
    PoolType type, GuestSize size, uint32_t tag)
{
    if (size == 0) return std::nullopt;

    std::unique_lock lock(m_impl->mutex);

    if (!m_impl->initialized || !m_impl->memory) return std::nullopt;
    if (m_impl->allocationCount >= kMaxPoolAllocs) return std::nullopt;

    // Cap individual allocation size to prevent abuse
    static constexpr GuestSize kMaxSingleAlloc = 16ULL * 1024 * 1024; // 16 MB
    if (size > kMaxSingleAlloc) return std::nullopt;

    GuestSize totalSize = m_impl->TotalAllocationSize(size);

    // Large allocations get page-aligned for realistic behavior
    bool isLargeAlloc = (size >= kPageSize);
    if (isLargeAlloc) {
        totalSize = AlignUp(totalSize, kPageSize);
    }

    GuestAddress allocBase = 0;
    MemProt prot = MemProt::RW;

    switch (type) {
        case PoolType::NonPagedPool:
        case PoolType::NonPagedPoolNx: {
            if (m_impl->nonPagedPoolUsed + totalSize > kMaxNonPagedPool) return std::nullopt;

            allocBase = AlignUp(m_impl->nonPagedPoolCursor, isLargeAlloc ? kPageSize : kPoolAlignment);
            m_impl->nonPagedPoolCursor = allocBase + totalSize;
            m_impl->nonPagedPoolUsed  += totalSize;

            // NonPagedPoolNx is RW only (no execute); NonPagedPool is RWX for legacy compat
            prot = (type == PoolType::NonPagedPoolNx) ? MemProt::RW : MemProt::RWX;
            break;
        }
        case PoolType::PagedPool: {
            if (m_impl->pagedPoolUsed + totalSize > kMaxPagedPool) return std::nullopt;

            allocBase = AlignUp(m_impl->pagedPoolCursor, isLargeAlloc ? kPageSize : kPoolAlignment);
            m_impl->pagedPoolCursor = allocBase + totalSize;
            m_impl->pagedPoolUsed  += totalSize;
            prot = MemProt::RW;
            break;
        }
    }

    // Map the region in VirtualMemory
    GuestSize virtualSize = AlignUp(totalSize, kPageSize);
    auto result = m_impl->memory->Allocate(allocBase, virtualSize, prot);
    if (!result.has_value()) return std::nullopt;

    // Write guard bytes
    m_impl->WriteGuardBytes(allocBase, totalSize);

    // Zero the payload area (between guard regions)
    GuestAddress payloadBase = allocBase + kGuardSize;
    GuestSize payloadSize = AlignUp(size, kPoolAlignment);
    std::vector<uint8_t> zeroBuf(static_cast<size_t>(std::min(payloadSize, static_cast<GuestSize>(4096))), 0);
    GuestSize remaining = payloadSize;
    GuestAddress writeAddr = payloadBase;
    while (remaining > 0) {
        uint32_t chunk = static_cast<uint32_t>(std::min(remaining, static_cast<GuestSize>(zeroBuf.size())));
        (void)m_impl->memory->Write(writeAddr, zeroBuf.data(), chunk);
        writeAddr += chunk;
        remaining -= chunk;
    }

    // Record allocation
    KernelAllocation alloc{};
    alloc.base     = payloadBase;
    alloc.size     = size;
    alloc.poolType = type;
    alloc.tag      = tag;
    alloc.freed    = false;

    m_impl->poolAllocations[payloadBase] = alloc;
    m_impl->allocationCount++;
    m_impl->UpdateTagStats(tag, size, true);

    // Register as kernel region
    KernelRegionInfo regionInfo{};
    regionInfo.base         = allocBase;
    regionInfo.size         = virtualSize;
    regionInfo.name         = "PoolAlloc_" + std::to_string(m_impl->allocationCount);
    regionInfo.isSupervisor = true;
    regionInfo.protection   = static_cast<uint32_t>(prot);
    m_impl->regions.push_back(std::move(regionInfo));

    return payloadBase;
}

void KernelAddressSpace::FreePool(GuestAddress addr) {
    std::unique_lock lock(m_impl->mutex);

    if (!m_impl->initialized) return;

    auto it = m_impl->poolAllocations.find(addr);
    if (it == m_impl->poolAllocations.end()) return;

    auto& alloc = it->second;
    if (alloc.freed) return; // Double-free protection

    alloc.freed = true;
    m_impl->UpdateTagStats(alloc.tag, alloc.size, false);

    // Reclaim pool usage accounting
    GuestSize totalSize = m_impl->TotalAllocationSize(alloc.size);
    if (alloc.size >= kPageSize) {
        totalSize = AlignUp(totalSize, kPageSize);
    }

    switch (alloc.poolType) {
        case PoolType::NonPagedPool:
        case PoolType::NonPagedPoolNx:
            if (m_impl->nonPagedPoolUsed >= totalSize) {
                m_impl->nonPagedPoolUsed -= totalSize;
            } else {
                m_impl->nonPagedPoolUsed = 0;
            }
            break;
        case PoolType::PagedPool:
            if (m_impl->pagedPoolUsed >= totalSize) {
                m_impl->pagedPoolUsed -= totalSize;
            } else {
                m_impl->pagedPoolUsed = 0;
            }
            break;
    }

    // Poison freed memory with 0xDD pattern (Windows debug behavior)
    if (m_impl->memory) {
        GuestSize payloadAligned = AlignUp(alloc.size, kPoolAlignment);
        std::vector<uint8_t> poison(static_cast<size_t>(std::min(payloadAligned, static_cast<GuestSize>(4096))), 0xDD);
        GuestSize remaining = payloadAligned;
        GuestAddress writeAddr = addr;
        while (remaining > 0) {
            uint32_t chunk = static_cast<uint32_t>(std::min(remaining, static_cast<GuestSize>(poison.size())));
            (void)m_impl->memory->Write(writeAddr, poison.data(), chunk);
            writeAddr += chunk;
            remaining -= chunk;
        }
    }
}

// ============================================================================
// Kernel Region Mapping
// ============================================================================

bool KernelAddressSpace::MapKernelRegion(
    GuestAddress base, GuestSize size,
    const std::string& name, uint32_t protection,
    const void* data, uint32_t dataSize)
{
    if (size == 0) return false;

    std::unique_lock lock(m_impl->mutex);

    if (!m_impl->initialized || !m_impl->memory) return false;

    // Validate the base address is in kernel space (or user-shared-data)
    if (!IsKernelAddress(base) && base != kUserSharedData) return false;

    // Check for overlap with existing regions
    for (const auto& region : m_impl->regions) {
        // Overflow-safe overlap check
        if (base < region.base) {
            if (base + size > region.base) return false;
        } else {
            if (region.base + region.size > base) return false;
        }
    }

    GuestSize virtualSize = AlignUp(size, kPageSize);
    MemProt prot = static_cast<MemProt>(protection);

    // Map into VirtualMemory
    if (data && dataSize > 0) {
        uint32_t writeSize = static_cast<uint32_t>(std::min(static_cast<GuestSize>(dataSize), virtualSize));
        auto err = m_impl->memory->MapRegion(base, static_cast<const uint8_t*>(data),
                                              writeSize, virtualSize, prot);
        if (err != ErrorCode::Success) return false;
    } else {
        auto result = m_impl->memory->Allocate(base, virtualSize, prot);
        if (!result.has_value()) return false;
    }

    KernelRegionInfo info{};
    info.base         = base;
    info.size         = virtualSize;
    info.name         = name;
    info.isSupervisor = IsKernelAddress(base);
    info.protection   = protection;
    m_impl->regions.push_back(std::move(info));

    return true;
}

// ============================================================================
// Region Queries
// ============================================================================

std::optional<KernelRegionInfo> KernelAddressSpace::FindRegion(GuestAddress addr) const {
    std::shared_lock lock(m_impl->mutex);

    for (const auto& region : m_impl->regions) {
        if (addr >= region.base && (addr - region.base) < region.size) {
            return region;
        }
    }
    return std::nullopt;
}

std::vector<KernelRegionInfo> KernelAddressSpace::GetAllRegions() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->regions;
}

std::vector<KernelAllocation> KernelAddressSpace::GetPoolAllocations() const {
    std::shared_lock lock(m_impl->mutex);

    std::vector<KernelAllocation> result;
    result.reserve(m_impl->poolAllocations.size());
    for (const auto& [base, alloc] : m_impl->poolAllocations) {
        result.push_back(alloc);
    }
    return result;
}

// ============================================================================
// KUSER_SHARED_DATA Initialization
// ============================================================================

void KernelAddressSpace::InitializeSharedUserData() {
    std::unique_lock lock(m_impl->mutex);

    if (!m_impl->initialized || !m_impl->memory) return;

    // Map the user-mode KUSER_SHARED_DATA page at 0x7FFE0000 (read-only from ring 3)
    auto userResult = m_impl->memory->Allocate(kUserSharedData, kPageSize, MemProt::RW);
    if (!userResult.has_value()) return;

    // Map the kernel-mode alias at 0xFFFFF78000000000 (read-write from ring 0)
    auto kernelResult = m_impl->memory->Allocate(kKernelSharedData, kPageSize, MemProt::RW);
    if (!kernelResult.has_value()) return;

    // Populate KUSER_SHARED_DATA fields with realistic Windows 10 21H1 values
    // Reference: ntddk.h KUSER_SHARED_DATA structure

    // +0x000: TickCountLowDeprecated (ULONG)
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x000, 0x001A0000);

    // +0x004: TickCountMultiplier (ULONG)
    // Standard value: 0x0FA00000 (multiply by this, shift right 24 to get ms)
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x004, 0x0FA00000);

    // +0x008: InterruptTime (KSYSTEM_TIME) - 100ns units since boot
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x008, 0x00500000); // LowPart
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x00C, 0x00000002); // High1Time
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x010, 0x00000002); // High2Time

    // +0x014: SystemTime (KSYSTEM_TIME) - 100ns units since 1601-01-01
    // Realistic value: ~132800000000000000 (0x01D7F5D000000000) ≈ mid-2022
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x014, 0x00000000); // LowPart
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x018, 0x01D7F5D0); // High1Time
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x01C, 0x01D7F5D0); // High2Time

    // +0x020: TimeZoneBias (KSYSTEM_TIME)
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x020, 0x00000000);
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x024, 0x00000000);
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x028, 0x00000000);

    // +0x02C: ImageNumberLow (USHORT) — x64 PE magic
    (void)m_impl->memory->WriteU16(kUserSharedData + 0x02C, 0x8664);

    // +0x02E: ImageNumberHigh (USHORT)
    (void)m_impl->memory->WriteU16(kUserSharedData + 0x02E, 0x8664);

    // +0x030: NtSystemRoot (WCHAR[260]) — "C:\WINDOWS"
    const wchar_t systemRoot[] = L"C:\\WINDOWS";
    for (size_t i = 0; i < sizeof(systemRoot) / sizeof(wchar_t); ++i) {
        (void)m_impl->memory->WriteU16(
            kUserSharedData + 0x030 + static_cast<GuestAddress>(i * 2),
            static_cast<uint16_t>(systemRoot[i]));
    }

    // +0x238: MaxStackTraceDepth (ULONG)
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x238, 0x00000020);

    // +0x260: NtMajorVersion (ULONG) — Windows 10
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x260, 10);

    // +0x264: NtMinorVersion (ULONG)
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x264, 0);

    // +0x268: AvailableProcessorFeatures (32 bits) — SSE2, etc.
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x268, 0x00003FFF);

    // +0x26C: NtBuildNumber (ULONG) — 19041 (Windows 10 2004)
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x26C, 19041);

    // +0x270: NtProductType (ULONG) — 1 = NtProductWinNt (Workstation)
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x270, 1);

    // +0x274: ProductTypeIsValid (BOOLEAN)
    (void)m_impl->memory->WriteU8(kUserSharedData + 0x274, 1);

    // +0x278: NativeMajorVersion (ULONG)
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x278, 10);

    // +0x27C: NativeBuildNumber (ULONG)
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x27C, 19041);

    // +0x2D0: KdDebuggerEnabled (UCHAR) — 0 = no debugger attached
    (void)m_impl->memory->WriteU8(kUserSharedData + 0x2D0, 0);

    // +0x2D4: MitigationPolicies (UCHAR) — enable CFG
    (void)m_impl->memory->WriteU8(kUserSharedData + 0x2D4, 0x01);

    // +0x2D8: CyclesPerYield (USHORT)
    (void)m_impl->memory->WriteU16(kUserSharedData + 0x2D8, 100);

    // +0x2EC: ActiveProcessorCount (ULONG) — 4 cores
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x2EC, 4);

    // +0x320: TickCount (KSYSTEM_TIME — volatile, used by GetTickCount)
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x320, 0x001A0000); // LowPart
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x324, 0x00000000); // High1Time
    (void)m_impl->memory->WriteU32(kUserSharedData + 0x328, 0x00000000); // High2Time

    // Now make the user-mode page read-only (ring 3 can only read)
    (void)m_impl->memory->Protect(kUserSharedData, kPageSize, MemProt::Read);

    // Mirror the same data to the kernel-mode alias
    // Read from user page, write to kernel page
    std::vector<uint8_t> pageData(kPageSize, 0);
    (void)m_impl->memory->Read(kUserSharedData, pageData.data(), static_cast<uint32_t>(kPageSize));
    (void)m_impl->memory->Write(kKernelSharedData, pageData.data(), static_cast<uint32_t>(kPageSize));

    // Register both regions
    KernelRegionInfo userInfo{};
    userInfo.base         = kUserSharedData;
    userInfo.size         = kPageSize;
    userInfo.name         = "KUSER_SHARED_DATA (user)";
    userInfo.isSupervisor = false;
    userInfo.protection   = static_cast<uint32_t>(MemProt::Read);
    m_impl->regions.push_back(std::move(userInfo));

    KernelRegionInfo kernelInfo{};
    kernelInfo.base         = kKernelSharedData;
    kernelInfo.size         = kPageSize;
    kernelInfo.name         = "KUSER_SHARED_DATA (kernel)";
    kernelInfo.isSupervisor = true;
    kernelInfo.protection   = static_cast<uint32_t>(MemProt::RW);
    m_impl->regions.push_back(std::move(kernelInfo));
}

// ============================================================================
// Pool Statistics
// ============================================================================

GuestSize KernelAddressSpace::GetNonPagedPoolUsed() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->nonPagedPoolUsed;
}

GuestSize KernelAddressSpace::GetPagedPoolUsed() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->pagedPoolUsed;
}

uint32_t KernelAddressSpace::GetAllocationCount() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->allocationCount;
}

std::vector<KernelAddressSpace::PoolTagStats> KernelAddressSpace::GetPoolTagStatistics() const {
    std::shared_lock lock(m_impl->mutex);

    std::vector<PoolTagStats> result;
    result.reserve(m_impl->tagStats.size());
    for (const auto& [tag, stats] : m_impl->tagStats) {
        result.push_back(stats);
    }
    return result;
}

// ============================================================================
// Pool Integrity Validation
// ============================================================================

bool KernelAddressSpace::ValidatePoolIntegrity() const {
    std::shared_lock lock(m_impl->mutex);

    if (!m_impl->initialized || !m_impl->memory) return false;

    for (const auto& [payloadBase, alloc] : m_impl->poolAllocations) {
        if (alloc.freed) continue;

        // Reconstruct the outer allocation base (payload is offset by kGuardSize)
        GuestAddress outerBase = payloadBase - kGuardSize;
        GuestSize totalSize = kGuardSize + AlignUp(alloc.size, kPoolAlignment) + kGuardSize;

        if (!m_impl->VerifyGuardBytes(outerBase, totalSize)) {
            return false;
        }
    }

    return true;
}

} // namespace Phantom
