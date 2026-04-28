/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "MemoryTracker.hpp"
#include "../../Common/Types.hpp"

#include <limits>
#include <mutex>
#include <new>

namespace Phantom {

void MemoryTracker::RecordDropLocked() noexcept {
    if (m_droppedEvents < (std::numeric_limits<uint64_t>::max)()) {
        ++m_droppedEvents;
    }
}

void MemoryTracker::Reset() noexcept {
    std::unique_lock lock(m_mutex);
    m_writtenPages.clear();
    m_executedPages.clear();
    m_wxPages.clear();
    m_rwxAllocations.clear();
    m_accessLog.clear();
    m_fullTracing = false;
    m_droppedEvents = 0;
}

void MemoryTracker::RecordWrite(GuestAddress pageBase) noexcept {
    pageBase = PageBase(pageBase);
    std::unique_lock lock(m_mutex);
    if (!m_writtenPages.contains(pageBase) && m_writtenPages.size() >= kMaxTrackedPages) {
        RecordDropLocked();
        return;
    }

    try {
        m_writtenPages.insert(pageBase);
    } catch (const std::bad_alloc&) {
        RecordDropLocked();
    }
}

void MemoryTracker::RecordExecute(GuestAddress pageBase) noexcept {
    pageBase = PageBase(pageBase);
    std::unique_lock lock(m_mutex);

    if (!m_executedPages.contains(pageBase) && m_executedPages.size() >= kMaxTrackedPages) {
        RecordDropLocked();
    } else {
        try {
            m_executedPages.insert(pageBase);
        } catch (const std::bad_alloc&) {
            RecordDropLocked();
        }
    }

    // Detect W→X transition
    if (m_writtenPages.contains(pageBase)) {
        if (m_wxPages.contains(pageBase) || m_wxPages.size() < kMaxWXPages) {
            try {
                m_wxPages.insert(pageBase);
            } catch (const std::bad_alloc&) {
                RecordDropLocked();
            }
        } else {
            RecordDropLocked();
        }
    }
}

void MemoryTracker::SetFullTracing(bool enable) noexcept {
    std::unique_lock lock(m_mutex);
    m_fullTracing = enable;
    if (!enable) {
        try {
            m_accessLog.clear();
            m_accessLog.shrink_to_fit();
        } catch (const std::bad_alloc&) {
            RecordDropLocked();
        }
    } else {
        try {
            m_accessLog.reserve(4096);
        } catch (const std::bad_alloc&) {
            m_fullTracing = false;
            RecordDropLocked();
        }
    }
}

uint64_t MemoryTracker::GetDroppedEventCount() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_droppedEvents;
}

bool MemoryTracker::IsWriteExecuteTransition(GuestAddress pageBase) const noexcept {
    pageBase = PageBase(pageBase);
    std::shared_lock lock(m_mutex);
    return m_wxPages.contains(pageBase);
}

std::vector<GuestAddress> MemoryTracker::GetWriteExecutePages() const {
    std::shared_lock lock(m_mutex);
    return std::vector<GuestAddress>(m_wxPages.begin(), m_wxPages.end());
}

uint32_t MemoryTracker::GetWriteExecuteCount() const noexcept {
    std::shared_lock lock(m_mutex);
    return static_cast<uint32_t>(m_wxPages.size());
}

void MemoryTracker::RecordRWXAllocation(GuestAddress base, GuestSize size) noexcept {
    if (size == 0 || size > (std::numeric_limits<GuestAddress>::max)() - base) {
        std::unique_lock lock(m_mutex);
        RecordDropLocked();
        return;
    }

    std::unique_lock lock(m_mutex);
    if (m_rwxAllocations.size() < kMaxRWXAllocations) {
        try {
            m_rwxAllocations.emplace_back(base, size);
        } catch (const std::bad_alloc&) {
            RecordDropLocked();
        }
    } else {
        RecordDropLocked();
    }
}

std::vector<std::pair<GuestAddress, GuestSize>> MemoryTracker::GetRWXAllocations() const {
    std::shared_lock lock(m_mutex);
    return m_rwxAllocations;
}

uint32_t MemoryTracker::GetUniqueWrittenPages() const noexcept {
    std::shared_lock lock(m_mutex);
    return static_cast<uint32_t>(m_writtenPages.size());
}

void MemoryTracker::RecordAccess(const MemoryAccessRecord& record) noexcept {
    if (record.size == 0) {
        std::unique_lock lock(m_mutex);
        RecordDropLocked();
        return;
    }

    std::unique_lock lock(m_mutex);
    if (!m_fullTracing) {
        return;
    }

    if (m_accessLog.size() < kMaxAccessLogSize) {
        try {
            m_accessLog.push_back(record);
        } catch (const std::bad_alloc&) {
            m_fullTracing = false;
            RecordDropLocked();
        }
    } else {
        RecordDropLocked();
    }
}

std::vector<MemoryAccessRecord> MemoryTracker::GetAccessLog() const {
    std::shared_lock lock(m_mutex);
    return m_accessLog;
}

} // namespace Phantom
