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
#include "../../Common/Platform.hpp"
#include <cstdint>
#include <vector>
#include <memory>
#include <shared_mutex>
#include <unordered_map>
#include <optional>

namespace Phantom {

// ============================================================================
// Page Entry
// ============================================================================

struct PageEntry {
    uint8_t*  hostPtr    = nullptr;    // Host-allocated backing memory (4KB)
    MemProt   protection = MemProt::None;
    bool      dirty      = false;       // Has been written
    mutable bool accessed = false;      // Has been read or executed (mutable: set under shared lock)
    bool      present    = false;       // Is allocated
    bool      guardPage  = false;       // Guard page (one-shot exception)
};

// ============================================================================
// Virtual Memory Manager
// ============================================================================
// Manages the guest virtual address space:
// - Lazy page allocation (allocate host backing on first access)
// - Per-page R/W/X protection
// - Guard pages for stack overflow detection
// - Memory access tracking for behavioral analysis
// - Capped total allocation to prevent resource exhaustion
//
// Thread-safe: Multiple emulated threads may access memory concurrently.
// The real-world lock ordering: Read operations use shared lock,
// write operations and allocations use exclusive lock.

class VirtualMemory {
public:
    explicit VirtualMemory(GuestSize maxMemory = 256ULL * 1024 * 1024) noexcept;
    ~VirtualMemory() noexcept;

    // Non-copyable, non-movable (owns host allocations)
    VirtualMemory(const VirtualMemory&) = delete;
    VirtualMemory& operator=(const VirtualMemory&) = delete;
    VirtualMemory(VirtualMemory&&) = delete;
    VirtualMemory& operator=(VirtualMemory&&) = delete;

    // === Allocation ===

    // Allocate a region of virtual memory.
    // Returns the base address of the allocated region, or nullopt on failure.
    [[nodiscard]] std::optional<GuestAddress> Allocate(
        GuestAddress preferredBase,
        GuestSize size,
        MemProt protection) noexcept;

    // Free a previously allocated region.
    [[nodiscard]] bool Free(GuestAddress base, GuestSize size) noexcept;

    // Change protection of a region.
    [[nodiscard]] bool Protect(GuestAddress base, GuestSize size, MemProt newProt) noexcept;

    // === Memory Access (Hot Path) ===

    // Read `count` bytes from guest address into host buffer.
    // Returns ErrorCode::Success or an access violation error.
    [[nodiscard]] ErrorCode Read(GuestAddress addr, void* dst, uint32_t count) noexcept;

    // Write `count` bytes from host buffer to guest address.
    [[nodiscard]] ErrorCode Write(GuestAddress addr, const void* src, uint32_t count) noexcept;

    // Fetch instruction bytes (requires Execute permission).
    [[nodiscard]] ErrorCode FetchInstruction(
        GuestAddress addr, uint8_t* dst, uint32_t maxBytes, uint32_t& bytesRead) noexcept;

    // === Typed access helpers (hot path) ===

    template <typename T>
    [[nodiscard]] ErrorCode ReadValue(GuestAddress addr, T& value) noexcept {
        return Read(addr, &value, sizeof(T));
    }

    template <typename T>
    [[nodiscard]] ErrorCode WriteValue(GuestAddress addr, const T& value) noexcept {
        return Write(addr, &value, sizeof(T));
    }

    [[nodiscard]] ErrorCode ReadU8(GuestAddress addr, uint8_t& val) noexcept { return ReadValue(addr, val); }
    [[nodiscard]] ErrorCode ReadU16(GuestAddress addr, uint16_t& val) noexcept { return ReadValue(addr, val); }
    [[nodiscard]] ErrorCode ReadU32(GuestAddress addr, uint32_t& val) noexcept { return ReadValue(addr, val); }
    [[nodiscard]] ErrorCode ReadU64(GuestAddress addr, uint64_t& val) noexcept { return ReadValue(addr, val); }

    [[nodiscard]] ErrorCode WriteU8(GuestAddress addr, uint8_t val) noexcept { return WriteValue(addr, val); }
    [[nodiscard]] ErrorCode WriteU16(GuestAddress addr, uint16_t val) noexcept { return WriteValue(addr, val); }
    [[nodiscard]] ErrorCode WriteU32(GuestAddress addr, uint32_t val) noexcept { return WriteValue(addr, val); }
    [[nodiscard]] ErrorCode WriteU64(GuestAddress addr, uint64_t val) noexcept { return WriteValue(addr, val); }

    // === Query ===

    // Check if an address is mapped and has the given protection.
    [[nodiscard]] bool IsAccessible(GuestAddress addr, MemProt requiredProt) const noexcept;

    // Get the protection of a specific address.
    [[nodiscard]] std::optional<MemProt> GetProtection(GuestAddress addr) const noexcept;

    // Check for W→X transition (critical for unpacking detection)
    [[nodiscard]] bool WasWrittenThenExecuted(GuestAddress pageAddr) const noexcept;

    // === Statistics ===

    [[nodiscard]] GuestSize GetAllocatedBytes() const noexcept { return m_allocatedBytes; }
    [[nodiscard]] uint32_t GetAllocatedPages() const noexcept { return m_allocatedPages; }
    [[nodiscard]] GuestSize GetMaxMemory() const noexcept { return m_maxMemory; }

    // === Snapshot/Restore ===
    // Used for unpacking: snapshot before suspected unpack, restore if false positive

    struct MemorySnapshot {
        std::unordered_map<uint32_t, std::vector<uint8_t>> pages;
        std::unordered_map<uint32_t, PageEntry> metadata;
    };

    [[nodiscard]] MemorySnapshot TakeSnapshot() const;
    void RestoreSnapshot(const MemorySnapshot& snap);

    // === Bulk operations ===

    // Map a PE section into guest memory (used by PELoader)
    [[nodiscard]] ErrorCode MapRegion(
        GuestAddress base,
        const uint8_t* data,
        uint32_t dataSize,
        GuestSize virtualSize,
        MemProt protection) noexcept;

    // Get direct host pointer for a guest address (for bulk operations).
    // WARNING: Only valid while holding the read lock. Do not store this pointer.
    [[nodiscard]] const uint8_t* GetHostReadPtr(GuestAddress addr) const noexcept;
    [[nodiscard]] uint8_t* GetHostWritePtr(GuestAddress addr) noexcept;

private:
    // Page table: maps page index → PageEntry
    std::unordered_map<uint32_t, PageEntry> m_pages;
    mutable std::shared_mutex m_mutex;

    GuestSize m_maxMemory;
    GuestSize m_allocatedBytes = 0;
    uint32_t  m_allocatedPages = 0;

    // === Internal helpers ===

    // Ensure a page is present (allocate backing if needed)
    [[nodiscard]] PageEntry* EnsurePage(uint32_t pageIndex) noexcept;

    // Find a page (returns nullptr if not present)
    [[nodiscard]] PageEntry* FindPage(uint32_t pageIndex) noexcept;
    [[nodiscard]] const PageEntry* FindPage(uint32_t pageIndex) const noexcept;

    // Check access permission for a single page
    [[nodiscard]] ErrorCode CheckAccess(
        const PageEntry* page,
        GuestAddress addr,
        MemProt requiredProt) const noexcept;

    // Find a free region of the given size (for VirtualAlloc with addr=0)
    [[nodiscard]] GuestAddress FindFreeRegion(GuestSize size) const noexcept;

    // Free a single page's backing memory
    void FreePage(uint32_t pageIndex) noexcept;
};

} // namespace Phantom
