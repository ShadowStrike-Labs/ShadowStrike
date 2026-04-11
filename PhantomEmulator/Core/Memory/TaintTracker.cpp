/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "TaintTracker.hpp"
#include <algorithm>
#include <cstring>

namespace Phantom {

// ============================================================================
// Reset
// ============================================================================

void TaintTracker::Reset() noexcept {
    std::unique_lock lock(m_mutex);
    m_shadowPages.clear();
    m_events.clear();
}

// ============================================================================
// Shadow Page Management
// ============================================================================

TaintTracker::ShadowPage* TaintTracker::GetOrCreatePage(
    GuestAddress pageBase) noexcept
{
    // Caller must hold exclusive lock
    auto it = m_shadowPages.find(pageBase);
    if (it != m_shadowPages.end()) return it->second.get();

    if (m_shadowPages.size() >= kMaxShadowPages) return nullptr;

    auto page = std::make_unique<ShadowPage>();
    auto* raw = page.get();
    m_shadowPages.emplace(pageBase, std::move(page));
    return raw;
}

const TaintTracker::ShadowPage* TaintTracker::GetPage(
    GuestAddress pageBase) const noexcept
{
    // Caller must hold at least shared lock
    auto it = m_shadowPages.find(pageBase);
    return (it != m_shadowPages.end()) ? it->second.get() : nullptr;
}

bool TaintTracker::IsPageClean(const ShadowPage& page) noexcept {
    // Fast check: scan 8 bytes at a time
    const auto* ptr = reinterpret_cast<const uint64_t*>(page.bytes);
    constexpr size_t count = kPageSize / sizeof(uint64_t);
    for (size_t i = 0; i < count; ++i) {
        if (ptr[i] != 0) return false;
    }
    return true;
}

// ============================================================================
// MarkTainted — Apply taint source tag to a guest memory range
// ============================================================================

void TaintTracker::MarkTainted(
    GuestAddress addr,
    GuestSize size,
    TaintSource source) noexcept
{
    if (size == 0 || source == TaintSource::None) return;
    if (size > kMaxTaintMarkSize) return; // Reject unreasonably large marks

    std::unique_lock lock(m_mutex);

    GuestAddress end = addr + size;
    // Overflow check
    if (end < addr) end = ~GuestAddress(0);

    GuestAddress current = addr;
    while (current < end) {
        GuestAddress pageBase = PageBase(current);
        uint32_t offset = PageOffset(current);
        uint32_t remaining = static_cast<uint32_t>(
            std::min<GuestSize>(kPageSize - offset, end - current));

        ShadowPage* page = GetOrCreatePage(pageBase);
        if (!page) return; // Hit shadow page cap

        for (uint32_t i = 0; i < remaining; ++i) {
            page->bytes[offset + i] |= source;
        }

        current = pageBase + kPageSize;
    }
}

// ============================================================================
// ClearRange — Remove all taint from a guest memory range
// ============================================================================

void TaintTracker::ClearRange(GuestAddress addr, GuestSize size) noexcept {
    if (size == 0) return;

    std::unique_lock lock(m_mutex);

    GuestAddress end = addr + size;
    if (end < addr) end = ~GuestAddress(0);

    GuestAddress current = addr;
    while (current < end) {
        GuestAddress pageBase = PageBase(current);
        uint32_t offset = PageOffset(current);
        uint32_t remaining = static_cast<uint32_t>(
            std::min<GuestSize>(kPageSize - offset, end - current));

        auto it = m_shadowPages.find(pageBase);
        if (it != m_shadowPages.end()) {
            std::memset(&it->second->bytes[offset], 0, remaining);

            // If the page is now entirely clean, reclaim it
            if (IsPageClean(*it->second)) {
                m_shadowPages.erase(it);
            }
        }

        current = pageBase + kPageSize;
    }
}

// ============================================================================
// IsTainted — Check if any byte in a range carries taint
// ============================================================================

bool TaintTracker::IsTainted(GuestAddress addr, GuestSize size) const noexcept {
    if (size == 0) return false;

    std::shared_lock lock(m_mutex);

    GuestAddress end = addr + size;
    if (end < addr) end = ~GuestAddress(0);

    GuestAddress current = addr;
    while (current < end) {
        GuestAddress pageBase = PageBase(current);
        uint32_t offset = PageOffset(current);
        uint32_t remaining = static_cast<uint32_t>(
            std::min<GuestSize>(kPageSize - offset, end - current));

        const ShadowPage* page = GetPage(pageBase);
        if (page) {
            for (uint32_t i = 0; i < remaining; ++i) {
                if (page->bytes[offset + i] != TaintSource::None) return true;
            }
        }

        current = pageBase + kPageSize;
    }
    return false;
}

// ============================================================================
// GetTaint — OR-union of all taint tags in a range
// ============================================================================

TaintSource TaintTracker::GetTaint(
    GuestAddress addr, GuestSize size) const noexcept
{
    if (size == 0) return TaintSource::None;

    std::shared_lock lock(m_mutex);

    TaintSource result = TaintSource::None;
    GuestAddress end = addr + size;
    if (end < addr) end = ~GuestAddress(0);

    GuestAddress current = addr;
    while (current < end) {
        GuestAddress pageBase = PageBase(current);
        uint32_t offset = PageOffset(current);
        uint32_t remaining = static_cast<uint32_t>(
            std::min<GuestSize>(kPageSize - offset, end - current));

        const ShadowPage* page = GetPage(pageBase);
        if (page) {
            for (uint32_t i = 0; i < remaining; ++i) {
                result |= page->bytes[offset + i];
            }
            // Early exit if we've seen all possible taint sources
            if (static_cast<uint8_t>(result) == 0x7F) return result;
        }

        current = pageBase + kPageSize;
    }
    return result;
}

// ============================================================================
// GetTaintMap — Per-byte taint tags for a range
// ============================================================================

std::vector<TaintSource> TaintTracker::GetTaintMap(
    GuestAddress addr, GuestSize size) const noexcept
{
    if (size == 0 || size > kMaxTaintMarkSize) return {};

    std::shared_lock lock(m_mutex);

    std::vector<TaintSource> map;
    try {
        map.resize(static_cast<size_t>(size), TaintSource::None);
    } catch (...) {
        return {};
    }

    GuestAddress end = addr + size;
    if (end < addr) return {};

    size_t mapIndex = 0;
    GuestAddress current = addr;
    while (current < end) {
        GuestAddress pageBase = PageBase(current);
        uint32_t offset = PageOffset(current);
        uint32_t remaining = static_cast<uint32_t>(
            std::min<GuestSize>(kPageSize - offset, end - current));

        const ShadowPage* page = GetPage(pageBase);
        if (page) {
            std::memcpy(&map[mapIndex], &page->bytes[offset],
                        remaining * sizeof(TaintSource));
        }
        // else: already TaintSource::None from resize

        mapIndex += remaining;
        current = pageBase + kPageSize;
    }
    return map;
}

// ============================================================================
// PropagateWrite — Copy taint from source to destination
// ============================================================================

void TaintTracker::PropagateWrite(
    GuestAddress dst,
    GuestAddress src,
    GuestSize size) noexcept
{
    if (size == 0 || size > kMaxTaintMarkSize) return;

    std::unique_lock lock(m_mutex);

    // First check if source has any taint at all (fast bail-out)
    bool anyTaint = false;
    {
        GuestAddress end = src + size;
        if (end < src) return;
        GuestAddress current = src;
        while (current < end && !anyTaint) {
            GuestAddress pageBase = PageBase(current);
            const ShadowPage* page = GetPage(pageBase);
            if (page) anyTaint = true;
            current = pageBase + kPageSize;
        }
    }
    if (!anyTaint) return;

    // Copy taint byte-by-byte across page boundaries
    GuestAddress srcEnd = src + size;
    GuestSize offset = 0;

    while (offset < size) {
        GuestAddress srcAddr = src + offset;
        GuestAddress dstAddr = dst + offset;

        GuestAddress srcPageBase = PageBase(srcAddr);
        GuestAddress dstPageBase = PageBase(dstAddr);
        uint32_t srcOff = PageOffset(srcAddr);
        uint32_t dstOff = PageOffset(dstAddr);

        // How many bytes we can process before hitting a page boundary
        uint32_t srcRemain = static_cast<uint32_t>(kPageSize - srcOff);
        uint32_t dstRemain = static_cast<uint32_t>(kPageSize - dstOff);
        uint32_t chunk = std::min({srcRemain, dstRemain,
                                   static_cast<uint32_t>(size - offset)});

        const ShadowPage* srcPage = GetPage(srcPageBase);
        if (srcPage) {
            // Check if this chunk has any taint
            bool chunkHasTaint = false;
            for (uint32_t i = 0; i < chunk; ++i) {
                if (srcPage->bytes[srcOff + i] != TaintSource::None) {
                    chunkHasTaint = true;
                    break;
                }
            }

            if (chunkHasTaint) {
                ShadowPage* dstPage = GetOrCreatePage(dstPageBase);
                if (dstPage) {
                    for (uint32_t i = 0; i < chunk; ++i) {
                        dstPage->bytes[dstOff + i] |= srcPage->bytes[srcOff + i];
                    }
                }
            }
        }

        offset += chunk;
    }
}

// ============================================================================
// PropagateTag — Apply a uniform taint tag to a destination range
// ============================================================================

void TaintTracker::PropagateTag(
    GuestAddress dst,
    GuestSize size,
    TaintSource tag) noexcept
{
    // Delegates to MarkTainted which handles page creation and caps
    if (tag == TaintSource::None || size == 0) return;
    // Note: lock is taken inside MarkTainted — but we're calling without
    // holding the lock here, so we must release and re-acquire.
    // Since this is just a convenience wrapper, call MarkTainted directly.
    MarkTainted(dst, size, tag);
}

// ============================================================================
// CheckSink — Test taint at a sink point, record event if tainted
// ============================================================================

bool TaintTracker::CheckSink(
    GuestAddress dataAddr,
    GuestSize dataSize,
    GuestAddress ripAddr,
    TaintEvent::SinkType sinkType,
    uint64_t instrCount,
    uint16_t threadId) noexcept
{
    if (dataSize == 0) return false;

    std::unique_lock lock(m_mutex);

    // Check taint without going through the public API (already locked)
    TaintSource sources = TaintSource::None;
    GuestAddress end = dataAddr + dataSize;
    if (end < dataAddr) end = ~GuestAddress(0);

    GuestAddress current = dataAddr;
    while (current < end) {
        GuestAddress pageBase = PageBase(current);
        uint32_t offset = PageOffset(current);
        uint32_t remaining = static_cast<uint32_t>(
            std::min<GuestSize>(kPageSize - offset, end - current));

        const ShadowPage* page = GetPage(pageBase);
        if (page) {
            for (uint32_t i = 0; i < remaining; ++i) {
                sources |= page->bytes[offset + i];
            }
        }

        current = pageBase + kPageSize;
    }

    if (sources == TaintSource::None) return false;

    // Record the event
    if (m_events.size() < kMaxTaintEvents) {
        TaintEvent event;
        event.sinkAddress      = ripAddr;
        event.dataAddress      = dataAddr;
        event.sources          = sources;
        event.instructionCount = instrCount;
        event.threadId         = threadId;
        event.sinkType         = sinkType;
        m_events.push_back(event);
    }

    return true;
}

// ============================================================================
// Event Retrieval
// ============================================================================

std::vector<TaintEvent> TaintTracker::GetTaintEvents() const {
    std::shared_lock lock(m_mutex);
    return m_events;
}

uint32_t TaintTracker::GetTaintEventCount() const noexcept {
    std::shared_lock lock(m_mutex);
    return static_cast<uint32_t>(m_events.size());
}

// ============================================================================
// Statistics
// ============================================================================

uint32_t TaintTracker::GetTaintedPageCount() const noexcept {
    std::shared_lock lock(m_mutex);
    return static_cast<uint32_t>(m_shadowPages.size());
}

uint64_t TaintTracker::GetTotalTaintedBytes() const noexcept {
    std::shared_lock lock(m_mutex);

    uint64_t total = 0;
    for (const auto& [_, page] : m_shadowPages) {
        for (size_t i = 0; i < kPageSize; ++i) {
            if (page->bytes[i] != TaintSource::None) ++total;
        }
    }
    return total;
}

} // namespace Phantom
