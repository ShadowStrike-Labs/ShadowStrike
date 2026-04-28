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
#include <limits>
#include <mutex>
#include <new>

namespace Phantom {

namespace {

[[nodiscard]] bool CheckedEnd(GuestAddress addr, GuestSize size, GuestAddress& end) noexcept {
    if (size == 0 || size > (std::numeric_limits<GuestAddress>::max)() - addr) {
        return false;
    }
    end = addr + size;
    return true;
}

void AdvanceToNextPage(GuestAddress& current, GuestAddress pageBase, GuestAddress end) noexcept {
    GuestAddress next = 0;
    if (kPageSize > (std::numeric_limits<GuestAddress>::max)() - pageBase) {
        current = end;
        return;
    }
    next = pageBase + kPageSize;
    current = (next > current && next < end) ? next : end;
}

[[nodiscard]] bool IsValidTaintMask(TaintSource source) noexcept {
    constexpr uint8_t kAllTaintBits =
        static_cast<uint8_t>(TaintSource::FileContent) |
        static_cast<uint8_t>(TaintSource::NetworkData) |
        static_cast<uint8_t>(TaintSource::UserInput) |
        static_cast<uint8_t>(TaintSource::RegistryValue) |
        static_cast<uint8_t>(TaintSource::EnvironmentVar) |
        static_cast<uint8_t>(TaintSource::ProcessMemory) |
        static_cast<uint8_t>(TaintSource::CryptoOutput);

    const uint8_t value = static_cast<uint8_t>(source);
    return value != 0 && (value & ~kAllTaintBits) == 0;
}

} // namespace

// ============================================================================
// Reset
// ============================================================================

void TaintTracker::RecordDropLocked() noexcept {
    if (m_droppedEvents < (std::numeric_limits<uint64_t>::max)()) {
        ++m_droppedEvents;
    }
}

void TaintTracker::Reset() noexcept {
    std::unique_lock lock(m_mutex);
    m_shadowPages.clear();
    m_events.clear();
    m_droppedEvents = 0;
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

    try {
        auto page = std::make_unique<ShadowPage>();
        auto* raw = page.get();
        m_shadowPages.emplace(pageBase, std::move(page));
        return raw;
    } catch (const std::bad_alloc&) {
        RecordDropLocked();
        return nullptr;
    }
}

const TaintTracker::ShadowPage* TaintTracker::GetPage(
    GuestAddress pageBase) const noexcept
{
    // Caller must hold at least shared lock
    auto it = m_shadowPages.find(pageBase);
    return (it != m_shadowPages.end()) ? it->second.get() : nullptr;
}

bool TaintTracker::IsPageClean(const ShadowPage& page) noexcept {
    for (const TaintSource source : page.bytes) {
        if (source != TaintSource::None) return false;
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
    if (size == 0 || !IsValidTaintMask(source)) return;
    if (size > kMaxTaintMarkSize) return; // Reject unreasonably large marks

    std::unique_lock lock(m_mutex);

    GuestAddress end = 0;
    if (!CheckedEnd(addr, size, end)) {
        RecordDropLocked();
        return;
    }

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

        AdvanceToNextPage(current, pageBase, end);
    }
}

// ============================================================================
// ClearRange — Remove all taint from a guest memory range
// ============================================================================

void TaintTracker::ClearRange(GuestAddress addr, GuestSize size) noexcept {
    if (size == 0) return;

    std::unique_lock lock(m_mutex);

    GuestAddress end = 0;
    if (!CheckedEnd(addr, size, end)) {
        RecordDropLocked();
        return;
    }

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

        AdvanceToNextPage(current, pageBase, end);
    }
}

// ============================================================================
// IsTainted — Check if any byte in a range carries taint
// ============================================================================

bool TaintTracker::IsTainted(GuestAddress addr, GuestSize size) const noexcept {
    if (size == 0) return false;

    std::shared_lock lock(m_mutex);

    GuestAddress end = 0;
    if (!CheckedEnd(addr, size, end)) return false;

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

        AdvanceToNextPage(current, pageBase, end);
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
    GuestAddress end = 0;
    if (!CheckedEnd(addr, size, end)) return TaintSource::None;

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

        AdvanceToNextPage(current, pageBase, end);
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
    } catch (const std::bad_alloc&) {
        return {};
    }

    GuestAddress end = 0;
    if (!CheckedEnd(addr, size, end)) return {};

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
        AdvanceToNextPage(current, pageBase, end);
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
    GuestAddress srcEnd = 0;
    GuestAddress dstEnd = 0;
    if (!CheckedEnd(src, size, srcEnd) || !CheckedEnd(dst, size, dstEnd)) {
        std::unique_lock lock(m_mutex);
        RecordDropLocked();
        return;
    }

    std::unique_lock lock(m_mutex);

    // First check if source has any taint at all (fast bail-out)
    bool anyTaint = false;
    {
        GuestAddress current = src;
        while (current < srcEnd && !anyTaint) {
            GuestAddress pageBase = PageBase(current);
            const ShadowPage* page = GetPage(pageBase);
            if (page) anyTaint = true;
            AdvanceToNextPage(current, pageBase, srcEnd);
        }
    }
    if (!anyTaint) return;

    // Copy taint byte-by-byte across page boundaries
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
    if (!IsValidTaintMask(tag) || size == 0) return;
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
    if (dataSize == 0 || dataSize > kMaxTaintMarkSize) return false;

    std::unique_lock lock(m_mutex);

    // Check taint without going through the public API (already locked)
    TaintSource sources = TaintSource::None;
    GuestAddress end = 0;
    if (!CheckedEnd(dataAddr, dataSize, end)) {
        RecordDropLocked();
        return false;
    }

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

        AdvanceToNextPage(current, pageBase, end);
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
        try {
            m_events.push_back(event);
        } catch (const std::bad_alloc&) {
            RecordDropLocked();
            return false;
        }
    } else {
        RecordDropLocked();
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

uint64_t TaintTracker::GetDroppedEventCount() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_droppedEvents;
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
