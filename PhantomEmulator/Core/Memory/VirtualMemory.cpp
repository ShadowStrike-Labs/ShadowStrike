/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "VirtualMemory.hpp"
#include "../../Common/Platform.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>

namespace Phantom {

namespace {

[[nodiscard]] bool AlignUpChecked(GuestSize value, GuestSize alignment, GuestSize& out) noexcept {
    if (alignment == 0 || value > (std::numeric_limits<GuestSize>::max)() - (alignment - 1)) {
        return false;
    }
    out = AlignUp(value, alignment);
    return out >= value;
}

[[nodiscard]] bool PageIndexFits(GuestAddress addr) noexcept {
    return (addr >> kPageShift) <= (std::numeric_limits<uint32_t>::max)();
}

[[nodiscard]] bool IsValidAddressRange(GuestAddress addr, GuestSize size) noexcept {
    if (size == 0 || size > (std::numeric_limits<GuestAddress>::max)() - addr) {
        return false;
    }
    const GuestAddress last = addr + size - 1;
    return PageIndexFits(addr) && PageIndexFits(last);
}

[[nodiscard]] bool GetPageRange(
    GuestAddress addr,
    GuestSize size,
    GuestAddress& alignedBase,
    GuestSize& alignedSize,
    uint32_t& startPage,
    uint32_t& pageCount) noexcept
{
    if (!IsValidAddressRange(addr, size)) {
        return false;
    }

    const GuestAddress end = addr + size;
    GuestAddress alignedEnd = 0;
    if (!AlignUpChecked(end, kPageSize, alignedEnd)) {
        return false;
    }

    alignedBase = AlignDown(addr, kPageSize);
    if (alignedEnd <= alignedBase) {
        return false;
    }

    const uint64_t firstPage = alignedBase >> kPageShift;
    const uint64_t lastPage = (alignedEnd - 1) >> kPageShift;
    if (firstPage > (std::numeric_limits<uint32_t>::max)() ||
        lastPage > (std::numeric_limits<uint32_t>::max)() ||
        lastPage < firstPage) {
        return false;
    }

    const uint64_t count = lastPage - firstPage + 1;
    if (count > (std::numeric_limits<uint32_t>::max)()) {
        return false;
    }

    alignedSize = alignedEnd - alignedBase;
    startPage = static_cast<uint32_t>(firstPage);
    pageCount = static_cast<uint32_t>(count);
    return true;
}

[[nodiscard]] bool AddPageIndex(uint32_t startPage, uint32_t offset, uint32_t& out) noexcept {
    if (offset > (std::numeric_limits<uint32_t>::max)() - startPage) {
        return false;
    }
    out = startPage + offset;
    return true;
}

} // namespace

// ============================================================================
// Constructor / Destructor
// ============================================================================

VirtualMemory::VirtualMemory(GuestSize maxMemory) noexcept
    : m_maxMemory(std::min(maxMemory, kMaxGuestMemory))
{
    try {
        m_pages.reserve(1024); // Pre-size for typical use
    } catch (const std::bad_alloc&) {
        // Lazy growth remains safe; reserve is only a performance optimization.
    }
}

VirtualMemory::~VirtualMemory() noexcept {
    // Free all backing memory
    for (auto& [idx, page] : m_pages) {
        if (page.hostPtr) {
            Platform::SecureZero(page.hostPtr, kPageSize);
            Platform::FreePage(page.hostPtr);
            page.hostPtr = nullptr;
        }
    }
    m_pages.clear();
    m_allocatedBytes = 0;
    m_allocatedPages = 0;
}

// ============================================================================
// Allocation
// ============================================================================

std::optional<GuestAddress> VirtualMemory::Allocate(
    GuestAddress preferredBase,
    GuestSize size,
    MemProt protection) noexcept
{
    if (size == 0) return std::nullopt;

    std::unique_lock lock(m_mutex);

    GuestSize requestSize = 0;
    if (!AlignUpChecked(size, kPageSize, requestSize)) {
        return std::nullopt;
    }

    if (requestSize > m_maxMemory || requestSize > m_maxMemory - m_allocatedBytes) {
        return std::nullopt;
    }

    // If no preferred base, find a free region
    GuestAddress base = preferredBase;
    if (base == 0) {
        base = FindFreeRegion(requestSize);
        if (base == kGuestNull) return std::nullopt;
    }

    GuestAddress alignedBase = 0;
    GuestSize alignedSize = 0;
    uint32_t pageCount = 0;
    uint32_t startPage = 0;
    if (!GetPageRange(base, size, alignedBase, alignedSize, startPage, pageCount)) {
        return std::nullopt;
    }

    if (alignedSize > m_maxMemory || alignedSize > m_maxMemory - m_allocatedBytes) {
        return std::nullopt;
    }

    // Verify no overlap with existing allocations
    for (uint32_t i = 0; i < pageCount; ++i) {
        uint32_t idx = 0;
        if (!AddPageIndex(startPage, i, idx)) return std::nullopt;
        auto it = m_pages.find(idx);
        if (it != m_pages.end() && it->second.present) {
            return std::nullopt; // Already allocated
        }
    }

    // Allocate pages (lazy: just create metadata, host backing on first access)
    uint32_t created = 0;
    for (uint32_t i = 0; i < pageCount; ++i) {
        uint32_t idx = 0;
        if (!AddPageIndex(startPage, i, idx)) {
            break;
        }

        try {
            auto [it, inserted] = m_pages.emplace(idx, PageEntry{});
            if (!inserted) {
                for (uint32_t rollback = 0; rollback < created; ++rollback) {
                    uint32_t rollbackIdx = 0;
                    if (AddPageIndex(startPage, rollback, rollbackIdx)) {
                        m_pages.erase(rollbackIdx);
                    }
                }
                return std::nullopt;
            }
            auto& page = it->second;
            page.protection = protection;
            page.present = true;
            page.dirty = false;
            page.accessed = false;
            page.guardPage = HasProt(protection, MemProt::Guard);
            ++created;
        } catch (const std::bad_alloc&) {
            for (uint32_t rollback = 0; rollback < created; ++rollback) {
                uint32_t rollbackIdx = 0;
                if (AddPageIndex(startPage, rollback, rollbackIdx)) {
                    m_pages.erase(rollbackIdx);
                }
            }
            return std::nullopt;
        }
    }
    if (created != pageCount) {
        for (uint32_t rollback = 0; rollback < created; ++rollback) {
            uint32_t rollbackIdx = 0;
            if (AddPageIndex(startPage, rollback, rollbackIdx)) {
                m_pages.erase(rollbackIdx);
            }
        }
        return std::nullopt;
    }

    m_allocatedBytes += alignedSize;
    m_allocatedPages += pageCount;

    return alignedBase;
}

bool VirtualMemory::Free(GuestAddress base, GuestSize size) noexcept {
    if (size == 0) return false;

    std::unique_lock lock(m_mutex);

    GuestAddress alignedBase = 0;
    GuestSize alignedSize = 0;
    uint32_t pageCount = 0;
    uint32_t startPage = 0;
    if (!GetPageRange(base, size, alignedBase, alignedSize, startPage, pageCount)) {
        return false;
    }

    uint32_t freedCount = 0;
    for (uint32_t i = 0; i < pageCount; ++i) {
        uint32_t idx = 0;
        if (!AddPageIndex(startPage, i, idx)) break;
        auto it = m_pages.find(idx);
        if (it != m_pages.end() && it->second.present) {
            if (it->second.hostPtr) {
                Platform::SecureZero(it->second.hostPtr, kPageSize);
                Platform::FreePage(it->second.hostPtr);
            }
            m_pages.erase(it);
            freedCount++;
        }
    }

    GuestSize freedBytes = static_cast<GuestSize>(freedCount) * kPageSize;
    m_allocatedBytes = (m_allocatedBytes >= freedBytes) ? m_allocatedBytes - freedBytes : 0;
    m_allocatedPages = (m_allocatedPages >= freedCount) ? m_allocatedPages - freedCount : 0;

    return freedCount > 0;
}

bool VirtualMemory::Protect(GuestAddress base, GuestSize size, MemProt newProt) noexcept {
    if (size == 0) return false;

    std::unique_lock lock(m_mutex);

    GuestAddress alignedBase = 0;
    GuestSize alignedSize = 0;
    uint32_t pageCount = 0;
    uint32_t startPage = 0;
    if (!GetPageRange(base, size, alignedBase, alignedSize, startPage, pageCount)) {
        return false;
    }

    for (uint32_t i = 0; i < pageCount; ++i) {
        uint32_t idx = 0;
        if (!AddPageIndex(startPage, i, idx)) return false;
        auto* page = FindPage(idx);
        if (!page || !page->present) return false;
    }

    for (uint32_t i = 0; i < pageCount; ++i) {
        uint32_t idx = 0;
        if (!AddPageIndex(startPage, i, idx)) return false;
        auto* page = FindPage(idx);
        if (!page) return false;
        page->protection = newProt;
        page->guardPage = HasProt(newProt, MemProt::Guard);
    }

    return true;
}

// ============================================================================
// Memory Access (Hot Path)
// ============================================================================

ErrorCode VirtualMemory::Read(GuestAddress addr, void* dst, uint32_t count) const noexcept {
    if (!dst || count == 0) return ErrorCode::InvalidAddress;
    if (!IsValidAddressRange(addr, count)) return ErrorCode::InvalidAddress;

    std::shared_lock lock(m_mutex);

    uint8_t* dstPtr = static_cast<uint8_t*>(dst);
    uint32_t remaining = count;
    GuestAddress current = addr;

    while (remaining > 0) {
        uint32_t pageIdx = PageIndex(current);
        uint32_t pageOff = PageOffset(current);
        uint32_t bytesInPage = std::min(remaining, static_cast<uint32_t>(kPageSize - pageOff));

        const auto* page = FindPage(pageIdx);
        auto accessErr = CheckAccess(page, current, MemProt::Read);
        if (accessErr != ErrorCode::Success) return accessErr;

        if (page->hostPtr) {
            std::memcpy(dstPtr, page->hostPtr + pageOff, bytesInPage);
        } else {
            // Page present but not yet backed → reads as zero
            std::memset(dstPtr, 0, bytesInPage);
        }

        dstPtr += bytesInPage;
        current += bytesInPage;
        remaining -= bytesInPage;
    }

    return ErrorCode::Success;
}

ErrorCode VirtualMemory::Write(GuestAddress addr, const void* src, uint32_t count) noexcept {
    if (!src || count == 0) return ErrorCode::InvalidAddress;
    if (!IsValidAddressRange(addr, count)) return ErrorCode::InvalidAddress;

    // Write needs exclusive lock because we may allocate backing pages
    std::unique_lock lock(m_mutex);

    const uint8_t* srcPtr = static_cast<const uint8_t*>(src);
    uint32_t remaining = count;
    GuestAddress current = addr;

    while (remaining > 0) {
        uint32_t pageIdx = PageIndex(current);
        uint32_t pageOff = PageOffset(current);
        uint32_t bytesInPage = std::min(remaining, static_cast<uint32_t>(kPageSize - pageOff));

        auto* page = FindPage(pageIdx);
        auto accessErr = CheckAccess(page, current, MemProt::Write);
        if (accessErr != ErrorCode::Success) return accessErr;

        // Lazy allocation: allocate backing on first write
        if (!page->hostPtr) {
            page->hostPtr = Platform::AllocatePage();
            if (!page->hostPtr) return ErrorCode::OutOfMemory;
        }

        std::memcpy(page->hostPtr + pageOff, srcPtr, bytesInPage);
        page->dirty = true;
        page->accessed = true;

        srcPtr += bytesInPage;
        current += bytesInPage;
        remaining -= bytesInPage;
    }

    return ErrorCode::Success;
}

ErrorCode VirtualMemory::FetchInstruction(
    GuestAddress addr, uint8_t* dst, uint32_t maxBytes, uint32_t& bytesRead) const noexcept
{
    if (!dst || maxBytes == 0) return ErrorCode::InvalidAddress;
    if (!IsValidAddressRange(addr, maxBytes)) return ErrorCode::InvalidAddress;

    std::unique_lock lock(m_mutex);

    bytesRead = 0;
    GuestAddress current = addr;
    uint32_t remaining = maxBytes;

    while (remaining > 0) {
        uint32_t pageIdx = PageIndex(current);
        uint32_t pageOff = PageOffset(current);
        uint32_t bytesInPage = std::min(remaining, static_cast<uint32_t>(kPageSize - pageOff));

        const auto* page = FindPage(pageIdx);
        auto accessErr = CheckAccess(page, current, MemProt::Execute);
        if (accessErr != ErrorCode::Success) {
            // If we already read some bytes, return what we have
            if (bytesRead > 0) return ErrorCode::Success;
            return accessErr;
        }

        if (page->hostPtr) {
            std::memcpy(dst + bytesRead, page->hostPtr + pageOff, bytesInPage);
        } else {
            // Uninitialized executable page reads as zeros (would decode as ADD [RAX], AL)
            std::memset(dst + bytesRead, 0, bytesInPage);
        }

        page->accessed = true;

        bytesRead += bytesInPage;
        current += bytesInPage;
        remaining -= bytesInPage;
    }

    return ErrorCode::Success;
}

// ============================================================================
// Query
// ============================================================================

bool VirtualMemory::IsAccessible(GuestAddress addr, MemProt requiredProt) const noexcept {
    if (!PageIndexFits(addr)) return false;
    std::shared_lock lock(m_mutex);
    const auto* page = FindPage(PageIndex(addr));
    return CheckAccess(page, addr, requiredProt) == ErrorCode::Success;
}

std::optional<MemProt> VirtualMemory::GetProtection(GuestAddress addr) const noexcept {
    if (!PageIndexFits(addr)) return std::nullopt;
    std::shared_lock lock(m_mutex);
    const auto* page = FindPage(PageIndex(addr));
    if (!page || !page->present) return std::nullopt;
    return page->protection;
}

bool VirtualMemory::WasWrittenThenExecuted(GuestAddress pageAddr) const noexcept {
    if (!PageIndexFits(pageAddr)) return false;
    std::shared_lock lock(m_mutex);
    const auto* page = FindPage(PageIndex(pageAddr));
    if (!page) return false;
    return page->dirty && page->accessed && HasProt(page->protection, MemProt::Execute);
}

GuestSize VirtualMemory::GetAllocatedBytes() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_allocatedBytes;
}

uint32_t VirtualMemory::GetAllocatedPages() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_allocatedPages;
}

GuestSize VirtualMemory::GetMaxMemory() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_maxMemory;
}

// ============================================================================
// Snapshot/Restore
// ============================================================================

VirtualMemory::MemorySnapshot VirtualMemory::TakeSnapshot() const {
    std::shared_lock lock(m_mutex);
    MemorySnapshot snap;
    for (const auto& [idx, page] : m_pages) {
        snap.metadata[idx] = page;
        snap.metadata[idx].hostPtr = nullptr;
        if (page.hostPtr) {
            snap.pages[idx].resize(kPageSize);
            std::memcpy(snap.pages[idx].data(), page.hostPtr, kPageSize);
        }
    }
    return snap;
}

void VirtualMemory::RestoreSnapshot(const MemorySnapshot& snap) {
    // Validate snapshot won't exceed memory limit
    GuestSize snapshotBytes = static_cast<GuestSize>(snap.metadata.size()) * kPageSize;
    if (snapshotBytes > m_maxMemory) return;

    std::unordered_map<uint32_t, PageEntry> newPages;
    try {
        newPages.reserve(snap.metadata.size());
    } catch (const std::bad_alloc&) {
        return;
    }

    for (const auto& [idx, meta] : snap.metadata) {
        PageEntry restored = meta;
        restored.hostPtr = nullptr;

        auto dataIt = snap.pages.find(idx);
        if (dataIt != snap.pages.end()) {
            if (dataIt->second.size() != kPageSize) {
                for (auto& [_, page] : newPages) {
                    if (page.hostPtr) {
                        Platform::SecureZero(page.hostPtr, kPageSize);
                        Platform::FreePage(page.hostPtr);
                    }
                }
                return;
            }

            restored.hostPtr = Platform::AllocatePage();
            if (!restored.hostPtr) {
                for (auto& [_, page] : newPages) {
                    if (page.hostPtr) {
                        Platform::SecureZero(page.hostPtr, kPageSize);
                        Platform::FreePage(page.hostPtr);
                    }
                }
                return;
            }
            std::memcpy(restored.hostPtr, dataIt->second.data(), kPageSize);
        }

        try {
            newPages.emplace(idx, restored);
        } catch (const std::bad_alloc&) {
            if (restored.hostPtr) {
                Platform::SecureZero(restored.hostPtr, kPageSize);
                Platform::FreePage(restored.hostPtr);
            }
            for (auto& [_, page] : newPages) {
                if (page.hostPtr) {
                    Platform::SecureZero(page.hostPtr, kPageSize);
                    Platform::FreePage(page.hostPtr);
                }
            }
            return;
        }
    }

    std::unique_lock lock(m_mutex);

    // Free current pages
    for (auto& [idx, page] : m_pages) {
        if (page.hostPtr) {
            Platform::SecureZero(page.hostPtr, kPageSize);
            Platform::FreePage(page.hostPtr);
            page.hostPtr = nullptr;
        }
    }
    m_pages = std::move(newPages);

    m_allocatedPages = static_cast<uint32_t>(m_pages.size());
    m_allocatedBytes = static_cast<GuestSize>(m_allocatedPages) * kPageSize;
}

// ============================================================================
// Bulk Operations
// ============================================================================

ErrorCode VirtualMemory::MapRegion(
    GuestAddress base,
    const uint8_t* data,
    uint32_t dataSize,
    GuestSize virtualSize,
    MemProt protection) noexcept
{
    if (virtualSize == 0) return ErrorCode::InvalidAddress;
    if (dataSize > virtualSize) return ErrorCode::BufferOverflow;

    // Allocate as RW so we can populate the region with data.
    // The final protection is applied after the copy completes.
    auto result = Allocate(base, virtualSize, MemProt::RW);
    if (!result.has_value()) return ErrorCode::OutOfMemory;

    if (data && dataSize > 0) {
        uint32_t writeSize = std::min(dataSize, static_cast<uint32_t>(virtualSize));
        auto err = Write(base, data, writeSize);
        if (err != ErrorCode::Success) {
            static_cast<void>(Free(base, virtualSize));
            return err;
        }
    }

    // Apply the requested protection now that data is written
    if (protection != MemProt::RW) {
        if (!Protect(base, virtualSize, protection)) {
            static_cast<void>(Free(base, virtualSize));
            return ErrorCode::AccessViolationWrite;
        }
    }

    return ErrorCode::Success;
}

const uint8_t* VirtualMemory::GetHostReadPtr(GuestAddress addr) const noexcept {
    // Caller must hold shared lock
    if (!PageIndexFits(addr)) return nullptr;
    const auto* page = FindPage(PageIndex(addr));
    if (!page || !page->present || !page->hostPtr) return nullptr;
    return page->hostPtr + PageOffset(addr);
}

uint8_t* VirtualMemory::GetHostWritePtr(GuestAddress addr) noexcept {
    // Caller must hold exclusive lock
    if (!PageIndexFits(addr)) return nullptr;
    auto* page = FindPage(PageIndex(addr));
    if (!page || !page->present) return nullptr;
    if (!page->hostPtr) {
        page->hostPtr = Platform::AllocatePage();
        if (!page->hostPtr) return nullptr;
    }
    page->dirty = true;
    return page->hostPtr + PageOffset(addr);
}

// ============================================================================
// Internal Helpers
// ============================================================================

PageEntry* VirtualMemory::EnsurePage(uint32_t pageIndex) noexcept {
    auto it = m_pages.find(pageIndex);
    if (it == m_pages.end()) return nullptr;
    if (!it->second.present) return nullptr;

    // Lazy allocation of backing memory
    if (!it->second.hostPtr) {
        it->second.hostPtr = Platform::AllocatePage();
        if (!it->second.hostPtr) return nullptr;
    }

    return &it->second;
}

PageEntry* VirtualMemory::FindPage(uint32_t pageIndex) noexcept {
    auto it = m_pages.find(pageIndex);
    if (it == m_pages.end()) return nullptr;
    return &it->second;
}

const PageEntry* VirtualMemory::FindPage(uint32_t pageIndex) const noexcept {
    auto it = m_pages.find(pageIndex);
    if (it == m_pages.end()) return nullptr;
    return &it->second;
}

ErrorCode VirtualMemory::CheckAccess(
    const PageEntry* page,
    [[maybe_unused]] GuestAddress addr,
    MemProt requiredProt) const noexcept
{
    if (!page || !page->present) {
        return ErrorCode::PageNotPresent;
    }

    // Guard page: trigger exception on first access
    if (page->guardPage) {
        return ErrorCode::GuardPageViolation;
    }

    // Check protection
    if (!HasProt(page->protection, requiredProt)) {
        switch (requiredProt) {
            case MemProt::Read:    return ErrorCode::AccessViolationRead;
            case MemProt::Write:   return ErrorCode::AccessViolationWrite;
            case MemProt::Execute: return ErrorCode::AccessViolationExec;
            default:               return ErrorCode::AccessViolationRead;
        }
    }

    return ErrorCode::Success;
}

GuestAddress VirtualMemory::FindFreeRegion(GuestSize size) const noexcept {
    // Start searching from a high address to avoid conflicts with PE image base
    constexpr GuestAddress kSearchStart = 0x0000000010000000ULL;
    constexpr GuestAddress kSearchEnd   = 0x0000000080000000ULL;

    if (size == 0 || size > kSearchEnd - kSearchStart) {
        return kGuestNull;
    }

    uint32_t pagesNeeded = PagesNeeded(size);

    for (GuestAddress addr = kSearchStart; addr <= kSearchEnd - size; addr += kPageSize) {
        uint32_t startPage = PageIndex(addr);
        bool conflict = false;

        for (uint32_t i = 0; i < pagesNeeded && !conflict; ++i) {
            uint32_t idx = 0;
            if (!AddPageIndex(startPage, i, idx)) {
                conflict = true;
                break;
            }
            auto it = m_pages.find(idx);
            if (it != m_pages.end() && it->second.present) {
                conflict = true;
                addr = (static_cast<GuestAddress>(idx) * kPageSize);
            }
        }

        if (!conflict) return addr;
    }

    return kGuestNull;
}

void VirtualMemory::FreePage(uint32_t pageIndex) noexcept {
    auto it = m_pages.find(pageIndex);
    if (it == m_pages.end()) return;

    if (it->second.hostPtr) {
        Platform::SecureZero(it->second.hostPtr, kPageSize);
        Platform::FreePage(it->second.hostPtr);
    }
    m_pages.erase(it);
}

} // namespace Phantom
