/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "HandleTable.hpp"
#include <algorithm>

namespace Phantom {

// ============================================================================
// Special pseudo-handle helpers
// ============================================================================

// Returns true for pseudo-handles that are always valid and never stored
// in the table (Windows GetCurrentProcess / GetCurrentThread semantics).
static constexpr bool IsPseudoHandle(GuestHandle handle) noexcept {
    return handle == kCurrentProcess || handle == kCurrentThread;
}

// Build a synthetic HandleEntry for GetCurrentProcess().
// These are never stored — they are manufactured on every lookup.
static HandleEntry MakeCurrentProcessEntry() noexcept {
    HandleEntry entry;
    entry.handle      = kCurrentProcess;
    entry.type        = HandleType::Process;
    entry.refCount    = 1;
    entry.inheritable = false;

    ProcessHandleData pd;
    pd.pid        = 0;
    pd.accessMask = 0x001FFFFF; // PROCESS_ALL_ACCESS
    pd.isSelf     = true;
    pd.imageBase  = 0;
    entry.data = std::move(pd);

    return entry;
}

// Build a synthetic HandleEntry for GetCurrentThread().
static HandleEntry MakeCurrentThreadEntry() noexcept {
    HandleEntry entry;
    entry.handle      = kCurrentThread;
    entry.type        = HandleType::Thread;
    entry.refCount    = 1;
    entry.inheritable = false;

    ThreadHandleData td;
    td.tid        = 0;
    td.ownerPid   = 0;
    td.accessMask = 0x001FFFFF; // THREAD_ALL_ACCESS
    td.suspended  = false;
    entry.data = std::move(td);

    return entry;
}

// ============================================================================
// Constructor
// ============================================================================

HandleTable::HandleTable() noexcept
    : m_nextHandle(0x04)
{
}

// ============================================================================
// Create — allocate a new guest handle
// ============================================================================

GuestHandle HandleTable::Create(HandleType type, HandleData data,
                                bool inheritable) noexcept
{
    std::unique_lock lock(m_mutex);

    if (m_entries.size() >= kMaxHandles) {
        return kNullHandle;
    }

    const GuestHandle value = AllocateValue();

    HandleEntry entry;
    entry.handle      = value;
    entry.type        = type;
    entry.data        = std::move(data);
    entry.refCount    = 1;
    entry.inheritable = inheritable;

    m_entries.emplace(value, std::move(entry));
    return value;
}

// ============================================================================
// Lookup — untyped
// ============================================================================

std::optional<HandleEntry> HandleTable::Lookup(GuestHandle handle) const noexcept
{
    // Pseudo-handles are synthesized, never stored.
    if (handle == kCurrentProcess) {
        return MakeCurrentProcessEntry();
    }
    if (handle == kCurrentThread) {
        return MakeCurrentThreadEntry();
    }

    std::shared_lock lock(m_mutex);

    auto it = m_entries.find(handle);
    if (it == m_entries.end()) {
        return std::nullopt;
    }
    return it->second; // return copy — caller never sees internal state
}

// ============================================================================
// Lookup — with type check
// ============================================================================

std::optional<HandleEntry> HandleTable::Lookup(GuestHandle handle,
                                               HandleType expectedType) const noexcept
{
    auto entry = Lookup(handle);
    if (!entry.has_value()) {
        return std::nullopt;
    }
    if (entry->type != expectedType) {
        return std::nullopt;
    }
    return entry;
}

// ============================================================================
// Close — decrement refcount, erase at zero
// ============================================================================

bool HandleTable::Close(GuestHandle handle) noexcept
{
    // Pseudo-handles cannot be closed, but callers should not get an error.
    if (IsPseudoHandle(handle)) {
        return true;
    }

    std::unique_lock lock(m_mutex);

    auto it = m_entries.find(handle);
    if (it == m_entries.end()) {
        return false;
    }

    if (it->second.refCount <= 1) {
        m_entries.erase(it);
    } else {
        --it->second.refCount;
    }

    return true;
}

// ============================================================================
// Duplicate — clone an entry under a new handle value
// ============================================================================

std::optional<GuestHandle> HandleTable::Duplicate(GuestHandle source) noexcept
{
    // Pseudo-handles can be duplicated — result is a real table entry.
    std::unique_lock lock(m_mutex);

    HandleEntry srcEntry;

    if (source == kCurrentProcess) {
        srcEntry = MakeCurrentProcessEntry();
    } else if (source == kCurrentThread) {
        srcEntry = MakeCurrentThreadEntry();
    } else {
        auto it = m_entries.find(source);
        if (it == m_entries.end()) {
            return std::nullopt;
        }
        srcEntry = it->second;
    }

    if (m_entries.size() >= kMaxHandles) {
        return std::nullopt;
    }

    const GuestHandle newValue = AllocateValue();

    HandleEntry newEntry;
    newEntry.handle      = newValue;
    newEntry.type        = srcEntry.type;
    newEntry.data        = srcEntry.data;
    newEntry.refCount    = 1;
    newEntry.inheritable = srcEntry.inheritable;

    m_entries.emplace(newValue, std::move(newEntry));
    return newValue;
}

// ============================================================================
// IsValid
// ============================================================================

bool HandleTable::IsValid(GuestHandle handle) const noexcept
{
    if (IsPseudoHandle(handle)) {
        return true;
    }

    std::shared_lock lock(m_mutex);
    return m_entries.find(handle) != m_entries.end();
}

// ============================================================================
// GetType
// ============================================================================

HandleType HandleTable::GetType(GuestHandle handle) const noexcept
{
    if (handle == kCurrentProcess) {
        return HandleType::Process;
    }
    if (handle == kCurrentThread) {
        return HandleType::Thread;
    }

    std::shared_lock lock(m_mutex);

    auto it = m_entries.find(handle);
    if (it == m_entries.end()) {
        return HandleType::Invalid;
    }
    return it->second.type;
}

// ============================================================================
// GetHandlesByType — collect all handles matching a given type
// ============================================================================

std::vector<GuestHandle> HandleTable::GetHandlesByType(HandleType type) const
{
    std::shared_lock lock(m_mutex);

    std::vector<GuestHandle> result;
    result.reserve(m_entries.size()); // Upper-bound pre-alloc

    for (const auto& [handle, entry] : m_entries) {
        if (entry.type == type) {
            result.push_back(handle);
        }
    }

    return result;
}

// ============================================================================
// GetOpenCount
// ============================================================================

uint32_t HandleTable::GetOpenCount() const noexcept
{
    std::shared_lock lock(m_mutex);
    return static_cast<uint32_t>(m_entries.size());
}

// ============================================================================
// GetAllEntries — snapshot of the full table (diagnostics / leak detection)
// ============================================================================

std::vector<HandleEntry> HandleTable::GetAllEntries() const
{
    std::shared_lock lock(m_mutex);

    std::vector<HandleEntry> result;
    result.reserve(m_entries.size());

    for (const auto& [handle, entry] : m_entries) {
        result.push_back(entry);
    }

    return result;
}

// ============================================================================
// Reset — tear down the entire table (session cleanup)
// ============================================================================

void HandleTable::Reset() noexcept
{
    std::unique_lock lock(m_mutex);
    m_entries.clear();
    m_nextHandle = 0x04;
}

// ============================================================================
// AllocateValue — produce next handle value (caller holds exclusive lock)
// ============================================================================

GuestHandle HandleTable::AllocateValue() noexcept
{
    const GuestHandle current = m_nextHandle;
    m_nextHandle += 4; // Windows handle granularity
    return current;
}

} // namespace Phantom
