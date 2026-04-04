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

namespace Phantom {

// ============================================================================
// Constructor / Destructor
// ============================================================================

VirtualMemory::VirtualMemory(GuestSize maxMemory) noexcept
    : m_maxMemory(std::min(maxMemory, kMaxGuestMemory))
{
    m_pages.reserve(1024); // Pre-size for typical use
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

    // Check memory limit
    GuestSize alignedSize = AlignUp(size, kPageSize);
    if (m_allocatedBytes + alignedSize > m_maxMemory) {
        return std::nullopt;
    }

    // If no preferred base, find a free region
    GuestAddress base = preferredBase;
    if (base == 0) {
        base = FindFreeRegion(alignedSize);
        if (base == kGuestNull) return std::nullopt;
    }

    base = AlignDown(base, kPageSize);
    uint32_t pageCount = PagesNeeded(size);
    uint32_t startPage = PageIndex(base);

    // Verify no overlap with existing allocations
    for (uint32_t i = 0; i < pageCount; ++i) {
        if (m_pages.contains(startPage + i) && m_pages[startPage + i].present) {
            return std::nullopt; // Already allocated
        }
    }

    // Allocate pages (lazy: just create metadata, host backing on first access)
    for (uint32_t i = 0; i < pageCount; ++i) {
        auto& page = m_pages[startPage + i];
        page.protection = protection;
        page.present = true;
        page.dirty = false;
        page.accessed = false;
        page.guardPage = HasProt(protection, MemProt::Guard);
        // hostPtr stays null until first access (lazy allocation)
    }

    m_allocatedBytes += alignedSize;
    m_allocatedPages += pageCount;

    return base;
}

bool VirtualMemory::Free(GuestAddress base, GuestSize size) noexcept {
    if (size == 0) return false;

    std::unique_lock lock(m_mutex);

    base = AlignDown(base, kPageSize);
    uint32_t pageCount = PagesNeeded(size);
    uint32_t startPage = PageIndex(base);

    uint32_t freedCount = 0;
    for (uint32_t i = 0; i < pageCount; ++i) {
        uint32_t idx = startPage + i;
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

    base = AlignDown(base, kPageSize);
    uint32_t pageCount = PagesNeeded(size);
    uint32_t startPage = PageIndex(base);

    for (uint32_t i = 0; i < pageCount; ++i) {
        auto* page = FindPage(startPage + i);
        if (!page || !page->present) return false;
        page->protection = newProt;
        page->guardPage = HasProt(newProt, MemProt::Guard);
    }

    return true;
}

// ============================================================================
// Memory Access (Hot Path)
// ============================================================================

ErrorCode VirtualMemory::Read(GuestAddress addr, void* dst, uint32_t count) noexcept {
    if (!dst || count == 0) return ErrorCode::InvalidAddress;

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

        // Track access
        const_cast<PageEntry*>(page)->accessed = true;

        dstPtr += bytesInPage;
        current += bytesInPage;
        remaining -= bytesInPage;
    }

    return ErrorCode::Success;
}

ErrorCode VirtualMemory::Write(GuestAddress addr, const void* src, uint32_t count) noexcept {
    if (!src || count == 0) return ErrorCode::InvalidAddress;

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
    GuestAddress addr, uint8_t* dst, uint32_t maxBytes, uint32_t& bytesRead) noexcept
{
    if (!dst || maxBytes == 0) return ErrorCode::InvalidAddress;

    std::shared_lock lock(m_mutex);

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

        const_cast<PageEntry*>(page)->accessed = true;

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
    std::shared_lock lock(m_mutex);
    const auto* page = FindPage(PageIndex(addr));
    return CheckAccess(page, addr, requiredProt) == ErrorCode::Success;
}

std::optional<MemProt> VirtualMemory::GetProtection(GuestAddress addr) const noexcept {
    std::shared_lock lock(m_mutex);
    const auto* page = FindPage(PageIndex(addr));
    if (!page || !page->present) return std::nullopt;
    return page->protection;
}

bool VirtualMemory::WasWrittenThenExecuted(GuestAddress pageAddr) const noexcept {
    std::shared_lock lock(m_mutex);
    const auto* page = FindPage(PageIndex(pageAddr));
    if (!page) return false;
    return page->dirty && page->accessed && HasProt(page->protection, MemProt::Execute);
}

// ============================================================================
// Snapshot/Restore
// ============================================================================

VirtualMemory::MemorySnapshot VirtualMemory::TakeSnapshot() const {
    std::shared_lock lock(m_mutex);
    MemorySnapshot snap;
    for (const auto& [idx, page] : m_pages) {
        snap.metadata[idx] = page;
        if (page.hostPtr) {
            snap.pages[idx].resize(kPageSize);
            std::memcpy(snap.pages[idx].data(), page.hostPtr, kPageSize);
        }
    }
    return snap;
}

void VirtualMemory::RestoreSnapshot(const MemorySnapshot& snap) {
    std::unique_lock lock(m_mutex);

    // Free current pages
    for (auto& [idx, page] : m_pages) {
        if (page.hostPtr) {
            Platform::SecureZero(page.hostPtr, kPageSize);
            Platform::FreePage(page.hostPtr);
        }
    }
    m_pages.clear();

    // Restore
    for (const auto& [idx, meta] : snap.metadata) {
        m_pages[idx] = meta;
        m_pages[idx].hostPtr = nullptr;

        auto it = snap.pages.find(idx);
        if (it != snap.pages.end()) {
            m_pages[idx].hostPtr = Platform::AllocatePage();
            if (m_pages[idx].hostPtr) {
                std::memcpy(m_pages[idx].hostPtr, it->second.data(), kPageSize);
            }
        }
    }

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

    // Allocate the region first
    auto result = Allocate(base, virtualSize, protection);
    if (!result.has_value()) return ErrorCode::OutOfMemory;

    // Write data into it
    if (data && dataSize > 0) {
        uint32_t writeSize = std::min(dataSize, static_cast<uint32_t>(virtualSize));
        auto err = Write(base, data, writeSize);
        if (err != ErrorCode::Success) return err;
    }

    return ErrorCode::Success;
}

const uint8_t* VirtualMemory::GetHostReadPtr(GuestAddress addr) const noexcept {
    // Caller must hold shared lock
    const auto* page = FindPage(PageIndex(addr));
    if (!page || !page->present || !page->hostPtr) return nullptr;
    return page->hostPtr + PageOffset(addr);
}

uint8_t* VirtualMemory::GetHostWritePtr(GuestAddress addr) noexcept {
    // Caller must hold exclusive lock
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
    GuestAddress addr,
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

    uint32_t pagesNeeded = PagesNeeded(size);

    for (GuestAddress addr = kSearchStart; addr + size <= kSearchEnd; addr += kPageSize) {
        uint32_t startPage = PageIndex(addr);
        bool conflict = false;

        for (uint32_t i = 0; i < pagesNeeded && !conflict; ++i) {
            auto it = m_pages.find(startPage + i);
            if (it != m_pages.end() && it->second.present) {
                conflict = true;
                addr = static_cast<GuestAddress>(startPage + i + 1) * kPageSize - kPageSize;
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
