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
#include <limits>
#include <mutex>
#include <new>
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

namespace {

[[nodiscard]] bool AddGuest(GuestAddress a, GuestSize b, GuestAddress& result) noexcept {
    if ((std::numeric_limits<GuestAddress>::max)() - a < b) {
        return false;
    }
    result = a + b;
    return true;
}

[[nodiscard]] bool AlignUpGuest(GuestAddress value, GuestSize alignment, GuestAddress& result) noexcept {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        return false;
    }
    if ((std::numeric_limits<GuestAddress>::max)() - value < alignment - 1) {
        return false;
    }
    result = AlignUp(value, alignment);
    return true;
}

[[nodiscard]] bool RangesOverlap(GuestAddress aBase, GuestSize aSize,
                                 GuestAddress bBase, GuestSize bSize) noexcept {
    if (aSize == 0 || bSize == 0) {
        return false;
    }
    GuestAddress aEnd = 0;
    GuestAddress bEnd = 0;
    if (!AddGuest(aBase, aSize, aEnd) || !AddGuest(bBase, bSize, bEnd)) {
        return true;
    }
    return aBase < bEnd && bBase < aEnd;
}

} // namespace

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
        if ((std::numeric_limits<GuestSize>::max)() - requestedSize < kPoolAlignment - 1) {
            return 0;
        }
        GuestSize aligned = AlignUp(requestedSize, kPoolAlignment);
        if ((std::numeric_limits<GuestSize>::max)() - aligned < (kGuardSize * 2ULL)) {
            return 0;
        }
        return kGuardSize + aligned + kGuardSize;
    }

    [[nodiscard]] bool WriteGuardBytes(GuestAddress allocationBase, GuestSize totalSize) noexcept {
        if (!memory || totalSize < (kGuardSize * 2ULL)) return false;

        // Front guard: kGuardSize bytes of kGuardPattern at allocationBase
        for (uint32_t i = 0; i < kGuardSize; i += sizeof(uint32_t)) {
            GuestAddress guardAddr = 0;
            if (!AddGuest(allocationBase, i, guardAddr) ||
                memory->WriteU32(guardAddr, kGuardPattern) != ErrorCode::Success) {
                return false;
            }
        }

        // Back guard: kGuardSize bytes of kGuardPattern at end
        GuestAddress backGuard = 0;
        if (!AddGuest(allocationBase, totalSize - kGuardSize, backGuard)) return false;
        for (uint32_t i = 0; i < kGuardSize; i += sizeof(uint32_t)) {
            GuestAddress guardAddr = 0;
            if (!AddGuest(backGuard, i, guardAddr) ||
                memory->WriteU32(guardAddr, kGuardPattern) != ErrorCode::Success) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool VerifyGuardBytes(GuestAddress allocationBase, GuestSize totalSize) const noexcept {
        if (!memory || totalSize < (kGuardSize * 2ULL)) return false;

        // Verify front guard
        for (uint32_t i = 0; i < kGuardSize; i += sizeof(uint32_t)) {
            uint32_t val = 0;
            GuestAddress guardAddr = 0;
            if (!AddGuest(allocationBase, i, guardAddr)) return false;
            if (memory->ReadU32(guardAddr, val) != ErrorCode::Success) return false;
            if (val != kGuardPattern) return false;
        }

        // Verify back guard
        GuestAddress backGuard = 0;
        if (!AddGuest(allocationBase, totalSize - kGuardSize, backGuard)) return false;
        for (uint32_t i = 0; i < kGuardSize; i += sizeof(uint32_t)) {
            uint32_t val = 0;
            GuestAddress guardAddr = 0;
            if (!AddGuest(backGuard, i, guardAddr)) return false;
            if (memory->ReadU32(guardAddr, val) != ErrorCode::Success) return false;
            if (val != kGuardPattern) return false;
        }

        return true;
    }

    void UpdateTagStats(uint32_t tag, GuestSize size, bool isAlloc) noexcept {
        auto& stats = tagStats[tag];
        stats.tag = tag;
        if (isAlloc) {
            if (stats.allocCount < (std::numeric_limits<uint32_t>::max)()) {
                ++stats.allocCount;
            }
            stats.totalBytes = ((std::numeric_limits<GuestSize>::max)() - stats.totalBytes < size)
                                   ? (std::numeric_limits<GuestSize>::max)()
                                   : stats.totalBytes + size;
        } else {
            if (stats.freeCount < (std::numeric_limits<uint32_t>::max)()) {
                ++stats.freeCount;
            }
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
    if (totalSize == 0) return std::nullopt;

    // Large allocations get page-aligned for realistic behavior
    bool isLargeAlloc = (size >= kPageSize);
    if (isLargeAlloc) {
        if ((std::numeric_limits<GuestSize>::max)() - totalSize < kPageSize - 1) {
            return std::nullopt;
        }
        totalSize = AlignUp(totalSize, kPageSize);
    }

    GuestAddress allocBase = 0;
    GuestAddress nextCursor = 0;
    MemProt prot = MemProt::RW;

    switch (type) {
        case PoolType::NonPagedPool:
        case PoolType::NonPagedPoolNx: {
            if (totalSize > kMaxNonPagedPool ||
                m_impl->nonPagedPoolUsed > kMaxNonPagedPool - totalSize) {
                return std::nullopt;
            }

            if (!AlignUpGuest(m_impl->nonPagedPoolCursor,
                              isLargeAlloc ? kPageSize : kPoolAlignment,
                              allocBase) ||
                !AddGuest(allocBase, totalSize, nextCursor)) {
                return std::nullopt;
            }

            // NonPagedPoolNx is RW only (no execute); NonPagedPool is RWX for legacy compat
            prot = (type == PoolType::NonPagedPoolNx) ? MemProt::RW : MemProt::RWX;
            break;
        }
        case PoolType::PagedPool: {
            if (totalSize > kMaxPagedPool ||
                m_impl->pagedPoolUsed > kMaxPagedPool - totalSize) {
                return std::nullopt;
            }

            if (!AlignUpGuest(m_impl->pagedPoolCursor,
                              isLargeAlloc ? kPageSize : kPoolAlignment,
                              allocBase) ||
                !AddGuest(allocBase, totalSize, nextCursor)) {
                return std::nullopt;
            }
            prot = MemProt::RW;
            break;
        }
    }

    // Map the region in VirtualMemory
    if ((std::numeric_limits<GuestSize>::max)() - totalSize < kPageSize - 1) {
        return std::nullopt;
    }
    GuestSize virtualSize = AlignUp(totalSize, kPageSize);
    auto result = m_impl->memory->Allocate(allocBase, virtualSize, prot);
    if (!result.has_value()) return std::nullopt;

    // Write guard bytes
    if (!m_impl->WriteGuardBytes(allocBase, totalSize)) {
        (void)m_impl->memory->Free(allocBase, virtualSize);
        return std::nullopt;
    }

    // Zero the payload area (between guard regions)
    GuestAddress payloadBase = 0;
    if (!AddGuest(allocBase, kGuardSize, payloadBase)) {
        (void)m_impl->memory->Free(allocBase, virtualSize);
        return std::nullopt;
    }
    GuestSize payloadSize = AlignUp(size, kPoolAlignment);
    std::vector<uint8_t> zeroBuf;
    try {
        zeroBuf.assign(static_cast<size_t>(std::min(payloadSize, static_cast<GuestSize>(4096))), 0);
    } catch (const std::bad_alloc&) {
        (void)m_impl->memory->Free(allocBase, virtualSize);
        return std::nullopt;
    }
    GuestSize remaining = payloadSize;
    GuestAddress writeAddr = payloadBase;
    while (remaining > 0) {
        uint32_t chunk = static_cast<uint32_t>(std::min(remaining, static_cast<GuestSize>(zeroBuf.size())));
        if (m_impl->memory->Write(writeAddr, zeroBuf.data(), chunk) != ErrorCode::Success ||
            !AddGuest(writeAddr, chunk, writeAddr)) {
            (void)m_impl->memory->Free(allocBase, virtualSize);
            return std::nullopt;
        }
        remaining -= chunk;
    }

    // Record allocation
    KernelAllocation alloc{};
    alloc.base     = payloadBase;
    alloc.size     = size;
    alloc.poolType = type;
    alloc.tag      = tag;
    alloc.freed    = false;

    KernelRegionInfo regionInfo{};
    regionInfo.base         = allocBase;
    regionInfo.size         = virtualSize;
    regionInfo.isSupervisor = true;
    regionInfo.protection   = static_cast<uint32_t>(prot);
    try {
        regionInfo.name = "PoolAlloc_" + std::to_string(m_impl->allocationCount + 1);
        m_impl->poolAllocations.emplace(payloadBase, alloc);
        m_impl->regions.push_back(std::move(regionInfo));
    } catch (const std::bad_alloc&) {
        m_impl->poolAllocations.erase(payloadBase);
        (void)m_impl->memory->Free(allocBase, virtualSize);
        return std::nullopt;
    }

    switch (type) {
        case PoolType::NonPagedPool:
        case PoolType::NonPagedPoolNx:
            m_impl->nonPagedPoolCursor = nextCursor;
            m_impl->nonPagedPoolUsed  += totalSize;
            break;
        case PoolType::PagedPool:
            m_impl->pagedPoolCursor = nextCursor;
            m_impl->pagedPoolUsed  += totalSize;
            break;
    }
    ++m_impl->allocationCount;
    m_impl->UpdateTagStats(tag, size, true);

    return payloadBase;
}

void KernelAddressSpace::FreePool(GuestAddress addr) {
    std::unique_lock lock(m_impl->mutex);

    if (!m_impl->initialized) return;

    auto it = m_impl->poolAllocations.find(addr);
    if (it == m_impl->poolAllocations.end()) return;

    auto& alloc = it->second;
    if (alloc.freed) return; // Double-free protection

    // Reclaim pool usage accounting
    GuestSize totalSize = m_impl->TotalAllocationSize(alloc.size);
    if (totalSize == 0) return;
    if (alloc.size >= kPageSize) {
        if ((std::numeric_limits<GuestSize>::max)() - totalSize < kPageSize - 1) {
            return;
        }
        totalSize = AlignUp(totalSize, kPageSize);
    }
    GuestSize virtualSize = AlignUp(totalSize, kPageSize);
    if (addr < kGuardSize) return;
    const GuestAddress outerBase = addr - kGuardSize;

    // Poison freed memory with 0xDD pattern (Windows debug behavior)
    if (m_impl->memory) {
        GuestSize payloadAligned = AlignUp(alloc.size, kPoolAlignment);
        std::vector<uint8_t> poison;
        try {
            poison.assign(static_cast<size_t>(std::min(payloadAligned, static_cast<GuestSize>(4096))), 0xDD);
        } catch (const std::bad_alloc&) {
            return;
        }
        GuestSize remaining = payloadAligned;
        GuestAddress writeAddr = addr;
        while (remaining > 0) {
            uint32_t chunk = static_cast<uint32_t>(std::min(remaining, static_cast<GuestSize>(poison.size())));
            if (m_impl->memory->Write(writeAddr, poison.data(), chunk) != ErrorCode::Success ||
                !AddGuest(writeAddr, chunk, writeAddr)) {
                return;
            }
            remaining -= chunk;
        }
        (void)m_impl->memory->Free(outerBase, virtualSize);
    }

    alloc.freed = true;
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
    if (m_impl->allocationCount > 0) {
        --m_impl->allocationCount;
    }
    m_impl->UpdateTagStats(alloc.tag, alloc.size, false);
    m_impl->regions.erase(
        std::remove_if(m_impl->regions.begin(), m_impl->regions.end(),
                       [outerBase](const KernelRegionInfo& region) {
                           return region.base == outerBase;
                       }),
        m_impl->regions.end());
}

// ============================================================================
// Kernel Region Mapping
// ============================================================================

bool KernelAddressSpace::MapKernelRegion(
    GuestAddress base, GuestSize size,
    const std::string& name, uint32_t protection,
    const void* data, uint32_t dataSize)
{
    if (size == 0 || name.empty() || name.size() > 128) return false;
    if (data == nullptr && dataSize != 0) return false;
    if (dataSize > size) return false;

    std::unique_lock lock(m_impl->mutex);

    if (!m_impl->initialized || !m_impl->memory) return false;
    GuestAddress checkedEnd = 0;
    if (!AddGuest(base, size, checkedEnd)) return false;
    if (!IsCanonicalAddress(base) || !IsCanonicalAddress(checkedEnd - 1)) return false;

    // Validate the base address is in kernel space (or user-shared-data)
    if (!IsKernelAddress(base) && base != kUserSharedData) return false;

    // Check for overlap with existing regions
    for (const auto& region : m_impl->regions) {
        if (RangesOverlap(base, size, region.base, region.size)) return false;
    }

    if ((std::numeric_limits<GuestSize>::max)() - size < kPageSize - 1) return false;
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
    try {
        m_impl->regions.push_back(std::move(info));
    } catch (const std::bad_alloc&) {
        (void)m_impl->memory->Free(base, virtualSize);
        return false;
    }

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
    if (!kernelResult.has_value()) {
        (void)m_impl->memory->Free(kUserSharedData, kPageSize);
        return;
    }

    auto failSharedDataInit = [&]() noexcept {
        (void)m_impl->memory->Free(kUserSharedData, kPageSize);
        (void)m_impl->memory->Free(kKernelSharedData, kPageSize);
    };

    bool ok = true;

    // Populate KUSER_SHARED_DATA fields with realistic Windows 10 21H1 values
    // Reference: ntddk.h KUSER_SHARED_DATA structure

    // +0x000: TickCountLowDeprecated (ULONG)
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x000, 0x001A0000) == ErrorCode::Success;

    // +0x004: TickCountMultiplier (ULONG)
    // Standard value: 0x0FA00000 (multiply by this, shift right 24 to get ms)
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x004, 0x0FA00000) == ErrorCode::Success;

    // +0x008: InterruptTime (KSYSTEM_TIME) - 100ns units since boot
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x008, 0x00500000) == ErrorCode::Success; // LowPart
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x00C, 0x00000002) == ErrorCode::Success; // High1Time
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x010, 0x00000002) == ErrorCode::Success; // High2Time

    // +0x014: SystemTime (KSYSTEM_TIME) - 100ns units since 1601-01-01
    // Realistic value: ~132800000000000000 (0x01D7F5D000000000) ≈ mid-2022
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x014, 0x00000000) == ErrorCode::Success; // LowPart
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x018, 0x01D7F5D0) == ErrorCode::Success; // High1Time
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x01C, 0x01D7F5D0) == ErrorCode::Success; // High2Time

    // +0x020: TimeZoneBias (KSYSTEM_TIME)
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x020, 0x00000000) == ErrorCode::Success;
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x024, 0x00000000) == ErrorCode::Success;
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x028, 0x00000000) == ErrorCode::Success;

    // +0x02C: ImageNumberLow (USHORT) — x64 PE magic
    ok = ok && m_impl->memory->WriteU16(kUserSharedData + 0x02C, 0x8664) == ErrorCode::Success;

    // +0x02E: ImageNumberHigh (USHORT)
    ok = ok && m_impl->memory->WriteU16(kUserSharedData + 0x02E, 0x8664) == ErrorCode::Success;

    // +0x030: NtSystemRoot (WCHAR[260]) — "C:\WINDOWS"
    const wchar_t systemRoot[] = L"C:\\WINDOWS";
    for (size_t i = 0; i < sizeof(systemRoot) / sizeof(wchar_t); ++i) {
        ok = ok && m_impl->memory->WriteU16(
            kUserSharedData + 0x030 + static_cast<GuestAddress>(i * 2),
            static_cast<uint16_t>(systemRoot[i])) == ErrorCode::Success;
    }

    // +0x238: MaxStackTraceDepth (ULONG)
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x238, 0x00000020) == ErrorCode::Success;

    // +0x260: NtMajorVersion (ULONG) — Windows 10
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x260, 10) == ErrorCode::Success;

    // +0x264: NtMinorVersion (ULONG)
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x264, 0) == ErrorCode::Success;

    // +0x268: AvailableProcessorFeatures (32 bits) — SSE2, etc.
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x268, 0x00003FFF) == ErrorCode::Success;

    // +0x26C: NtBuildNumber (ULONG) — 19041 (Windows 10 2004)
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x26C, 19041) == ErrorCode::Success;

    // +0x270: NtProductType (ULONG) — 1 = NtProductWinNt (Workstation)
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x270, 1) == ErrorCode::Success;

    // +0x274: ProductTypeIsValid (BOOLEAN)
    ok = ok && m_impl->memory->WriteU8(kUserSharedData + 0x274, 1) == ErrorCode::Success;

    // +0x278: NativeMajorVersion (ULONG)
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x278, 10) == ErrorCode::Success;

    // +0x27C: NativeBuildNumber (ULONG)
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x27C, 19041) == ErrorCode::Success;

    // +0x2D0: KdDebuggerEnabled (UCHAR) — 0 = no debugger attached
    ok = ok && m_impl->memory->WriteU8(kUserSharedData + 0x2D0, 0) == ErrorCode::Success;

    // +0x2D4: MitigationPolicies (UCHAR) — enable CFG
    ok = ok && m_impl->memory->WriteU8(kUserSharedData + 0x2D4, 0x01) == ErrorCode::Success;

    // +0x2D8: CyclesPerYield (USHORT)
    ok = ok && m_impl->memory->WriteU16(kUserSharedData + 0x2D8, 100) == ErrorCode::Success;

    // +0x2EC: ActiveProcessorCount (ULONG) — 4 cores
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x2EC, 4) == ErrorCode::Success;

    // +0x320: TickCount (KSYSTEM_TIME — volatile, used by GetTickCount)
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x320, 0x001A0000) == ErrorCode::Success; // LowPart
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x324, 0x00000000) == ErrorCode::Success; // High1Time
    ok = ok && m_impl->memory->WriteU32(kUserSharedData + 0x328, 0x00000000) == ErrorCode::Success; // High2Time

    if (!ok) {
        failSharedDataInit();
        return;
    }

    // Now make the user-mode page read-only (ring 3 can only read)
    if (!m_impl->memory->Protect(kUserSharedData, kPageSize, MemProt::Read)) {
        failSharedDataInit();
        return;
    }

    // Mirror the same data to the kernel-mode alias
    // Read from user page, write to kernel page
    std::vector<uint8_t> pageData;
    try {
        pageData.assign(kPageSize, 0);
    } catch (const std::bad_alloc&) {
        failSharedDataInit();
        return;
    }
    if (m_impl->memory->Read(kUserSharedData, pageData.data(), static_cast<uint32_t>(kPageSize)) != ErrorCode::Success ||
        m_impl->memory->Write(kKernelSharedData, pageData.data(), static_cast<uint32_t>(kPageSize)) != ErrorCode::Success) {
        failSharedDataInit();
        return;
    }

    // Register both regions
    KernelRegionInfo userInfo{};
    userInfo.base         = kUserSharedData;
    userInfo.size         = kPageSize;
    userInfo.name         = "KUSER_SHARED_DATA (user)";
    userInfo.isSupervisor = false;
    userInfo.protection   = static_cast<uint32_t>(MemProt::Read);
    KernelRegionInfo kernelInfo{};
    kernelInfo.base         = kKernelSharedData;
    kernelInfo.size         = kPageSize;
    kernelInfo.name         = "KUSER_SHARED_DATA (kernel)";
    kernelInfo.isSupervisor = true;
    kernelInfo.protection   = static_cast<uint32_t>(MemProt::RW);
    try {
        m_impl->regions.push_back(std::move(userInfo));
        m_impl->regions.push_back(std::move(kernelInfo));
    } catch (const std::bad_alloc&) {
        m_impl->regions.erase(
            std::remove_if(m_impl->regions.begin(), m_impl->regions.end(),
                           [](const KernelRegionInfo& region) {
                               return region.base == kUserSharedData ||
                                      region.base == kKernelSharedData;
                           }),
            m_impl->regions.end());
        failSharedDataInit();
    }
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
