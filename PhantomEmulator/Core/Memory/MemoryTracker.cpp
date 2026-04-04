/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "MemoryTracker.hpp"
#include "../../Common/Types.hpp"

namespace Phantom {

void MemoryTracker::Reset() noexcept {
    std::unique_lock lock(m_mutex);
    m_writtenPages.clear();
    m_executedPages.clear();
    m_wxPages.clear();
    m_rwxAllocations.clear();
    m_accessLog.clear();
}

void MemoryTracker::RecordWrite(GuestAddress pageBase) noexcept {
    pageBase = PageBase(pageBase);
    std::unique_lock lock(m_mutex);
    m_writtenPages.insert(pageBase);
}

void MemoryTracker::RecordExecute(GuestAddress pageBase) noexcept {
    pageBase = PageBase(pageBase);
    std::unique_lock lock(m_mutex);
    m_executedPages.insert(pageBase);

    // Detect W→X transition
    if (m_writtenPages.contains(pageBase)) {
        if (m_wxPages.size() < kMaxWXPages) {
            m_wxPages.insert(pageBase);
        }
    }
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
    std::unique_lock lock(m_mutex);
    if (m_rwxAllocations.size() < 10000) {
        m_rwxAllocations.emplace_back(base, size);
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

void MemoryTracker::RecordAccess(const MemoryAccessRecord& record) {
    if (!m_fullTracing) return;

    std::unique_lock lock(m_mutex);
    if (m_accessLog.size() < kMaxAccessLogSize) {
        m_accessLog.push_back(record);
    }
}

std::vector<MemoryAccessRecord> MemoryTracker::GetAccessLog() const {
    std::shared_lock lock(m_mutex);
    return m_accessLog;
}

} // namespace Phantom
