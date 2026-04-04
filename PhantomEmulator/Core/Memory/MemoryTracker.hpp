/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include <cstdint>
#include <vector>
#include <unordered_set>
#include <shared_mutex>

namespace Phantom {

// ============================================================================
// Memory Access Record (for analysis)
// ============================================================================

struct MemoryAccessRecord {
    GuestAddress address;
    uint32_t     size;
    uint64_t     instructionCount;
    GuestAddress rip;
    enum class Type : uint8_t { Read, Write, Execute } type;
};

// ============================================================================
// Memory Tracker
// ============================================================================
// Tracks memory access patterns for behavioral analysis:
// - W→X transitions (the #1 indicator of unpacking/shellcode)
// - Heap spray patterns (repeated identical allocations)
// - RWX page creation (common in injection)
// - Code modification (self-modifying code detection)

class MemoryTracker {
public:
    MemoryTracker() noexcept = default;

    void Reset() noexcept;

    // Record a write to a page
    void RecordWrite(GuestAddress pageBase) noexcept;

    // Record an execution from a page
    void RecordExecute(GuestAddress pageBase) noexcept;

    // Check if a page was written then executed
    [[nodiscard]] bool IsWriteExecuteTransition(GuestAddress pageBase) const noexcept;

    // Get all W→X pages (for unpacking analysis)
    [[nodiscard]] std::vector<GuestAddress> GetWriteExecutePages() const;

    // Get count of W→X transitions
    [[nodiscard]] uint32_t GetWriteExecuteCount() const noexcept;

    // Record an RWX allocation (always suspicious)
    void RecordRWXAllocation(GuestAddress base, GuestSize size) noexcept;

    // Get all RWX allocations (returns copy under lock for thread safety)
    [[nodiscard]] std::vector<std::pair<GuestAddress, GuestSize>> GetRWXAllocations() const;

    // Track unique pages written (for heap spray detection)
    [[nodiscard]] uint32_t GetUniqueWrittenPages() const noexcept;

    // === Full access log (optional, expensive) ===
    void SetFullTracing(bool enable) noexcept { m_fullTracing = enable; }
    void RecordAccess(const MemoryAccessRecord& record);
    [[nodiscard]] std::vector<MemoryAccessRecord> GetAccessLog() const;

private:
    std::unordered_set<GuestAddress> m_writtenPages;
    std::unordered_set<GuestAddress> m_executedPages;
    std::unordered_set<GuestAddress> m_wxPages;  // Pages that were both written AND executed
    std::vector<std::pair<GuestAddress, GuestSize>> m_rwxAllocations;
    std::vector<MemoryAccessRecord> m_accessLog;
    mutable std::shared_mutex m_mutex;
    bool m_fullTracing = false;

    static constexpr uint32_t kMaxAccessLogSize = 10'000'000; // Cap to prevent OOM
    static constexpr uint32_t kMaxWXPages = 100'000;
};

} // namespace Phantom
