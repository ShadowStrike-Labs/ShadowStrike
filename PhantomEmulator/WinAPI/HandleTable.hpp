/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * HandleTable.hpp — Centralized guest handle management
 *
 * Maps guest HANDLE values to typed internal resource descriptors.
 * Provides thread-safe handle allocation, lookup, and deallocation
 * with strict type checking and leak detection.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "APITypes.hpp"
#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace Phantom {

// ============================================================================
// HandleEntry — A single entry in the handle table
// ============================================================================

struct HandleEntry {
    GuestHandle handle   = kNullHandle;
    HandleType  type     = HandleType::Invalid;
    HandleData  data;
    uint32_t    refCount = 1;
    bool        inheritable = false;
};

// ============================================================================
// HandleTable — Thread-safe guest handle management
// ============================================================================
// Allocates HANDLE values that look realistic to the emulated process:
// - Multiples of 4, starting at 0x04 (Windows convention)
// - Never reuses a handle value within the same session
// - Supports DuplicateHandle semantics (refcounting)
//
// Thread-safe: handles may be created/closed from different emulated threads.

class HandleTable {
public:
    HandleTable() noexcept;
    ~HandleTable() noexcept = default;

    HandleTable(const HandleTable&) = delete;
    HandleTable& operator=(const HandleTable&) = delete;

    // Allocate a new handle of the given type with associated data.
    // Returns the guest-visible HANDLE value.
    [[nodiscard]] GuestHandle Create(HandleType type, HandleData data,
                                     bool inheritable = false) noexcept;

    // Look up a handle. Returns nullopt if not found or type mismatch.
    [[nodiscard]] std::optional<HandleEntry> Lookup(GuestHandle handle) const noexcept;

    // Look up with type check — returns nullopt if handle exists but wrong type
    [[nodiscard]] std::optional<HandleEntry> Lookup(GuestHandle handle,
                                                    HandleType expectedType) const noexcept;

    // Get a mutable reference to handle data (for updating file position, etc.)
    // Caller must NOT hold the lock — this acquires exclusive lock internally.
    // Returns false if handle not found.
    template <typename T>
    [[nodiscard]] bool Modify(GuestHandle handle, std::function<void(T&)> modifier) noexcept {
        std::unique_lock lock(m_mutex);
        auto it = m_entries.find(handle);
        if (it == m_entries.end()) return false;
        auto* p = std::get_if<T>(&it->second.data);
        if (!p) return false;
        modifier(*p);
        return true;
    }

    // Close a handle. Decrements refcount; entry removed when refcount hits 0.
    // Returns true if the handle existed and was closed.
    [[nodiscard]] bool Close(GuestHandle handle) noexcept;

    // Duplicate a handle (increment refcount, return new HANDLE value).
    [[nodiscard]] std::optional<GuestHandle> Duplicate(GuestHandle source) noexcept;

    // Check if a handle is valid.
    [[nodiscard]] bool IsValid(GuestHandle handle) const noexcept;

    // Get the type of a handle (returns HandleType::Invalid if not found).
    [[nodiscard]] HandleType GetType(GuestHandle handle) const noexcept;

    // Get all open handles of a specific type.
    [[nodiscard]] std::vector<GuestHandle> GetHandlesByType(HandleType type) const;

    // Get total number of open handles (for leak detection).
    [[nodiscard]] uint32_t GetOpenCount() const noexcept;

    // Cap on total open handles (resource exhaustion defense)
    static constexpr uint32_t kMaxHandles = 65536;

    // Dump all open handles (for diagnostics / leaked handle detection)
    [[nodiscard]] std::vector<HandleEntry> GetAllEntries() const;

    // Reset the table (session cleanup)
    void Reset() noexcept;

private:
    mutable std::shared_mutex m_mutex;
    std::unordered_map<GuestHandle, HandleEntry> m_entries;
    GuestHandle m_nextHandle = 0x04;  // Windows starts handle values at 0x4

    [[nodiscard]] GuestHandle AllocateValue() noexcept;
};

} // namespace Phantom
