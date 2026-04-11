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
#include <memory>
#include <vector>
#include <unordered_map>
#include <shared_mutex>

namespace Phantom {

// ============================================================================
// Taint Event — recorded when tainted data reaches a security-relevant sink
// ============================================================================

struct TaintEvent {
    GuestAddress sinkAddress;     // RIP of the instruction that consumed tainted data
    GuestAddress dataAddress;     // Guest address of the tainted operand
    TaintSource  sources;         // Union of all taint tags on the consumed data
    uint64_t     instructionCount;
    uint16_t     threadId;

    enum class SinkType : uint8_t {
        CodeExecution,            // Tainted data used as RIP target (code injection)
        APIArgument,              // Tainted data passed as API argument
        RegistryWrite,            // Tainted data written to registry
        FileWrite,                // Tainted data written to file
        NetworkSend,              // Tainted data sent over network
        ProcessInject,            // Tainted data written to another process
        CryptoKey,                // Tainted data used as crypto key/material
    } sinkType;
};

// ============================================================================
// Taint Tracker — per-byte shadow memory with source tagging
// ============================================================================
//
// Design:
//   - Shadow memory is a sparse page table: only pages that actually carry
//     taint get allocated (one byte per guest byte, holding TaintSource bits).
//   - Propagation: on every guest memory copy/move the emulator calls
//     PropagateWrite() which OR-merges source tags into the destination.
//   - Sources: API handlers call MarkTainted() when external data enters
//     guest memory (file reads, network recv, registry queries, etc.).
//   - Sinks: before security-relevant operations (indirect calls, API
//     arguments, file/registry writes), the emulator calls CheckSink()
//     which records a TaintEvent if the operand carries taint.
//
// Resource caps:
//   - Maximum 128K shadow pages (512 MB shadow for 512 MB guest)
//   - Maximum 100K recorded taint events
//
// Thread safety:
//   - All public methods are protected by a shared_mutex.
//   - Reads (IsTainted, GetTaint) take shared locks.
//   - Writes (MarkTainted, PropagateWrite, ClearRange) take exclusive locks.
//
// Performance:
//   - This is an analysis feature — NOT on the hot instruction decode path.
//   - Enabled only via EmulationConfig::enableTaintAnalysis.
//   - Shadow page allocation is lazy: untouched pages are nullptr (clean).

class TaintTracker {
public:
    TaintTracker() noexcept = default;
    ~TaintTracker() noexcept = default;

    TaintTracker(const TaintTracker&) = delete;
    TaintTracker& operator=(const TaintTracker&) = delete;
    TaintTracker(TaintTracker&&) noexcept = default;
    TaintTracker& operator=(TaintTracker&&) noexcept = default;

    void Reset() noexcept;

    // === Source Marking ===
    // Mark a guest memory range as tainted with the given source tag.
    // Called by API handlers when external data enters guest address space.
    void MarkTainted(GuestAddress addr, GuestSize size, TaintSource source) noexcept;

    // Clear taint from a range (e.g., on VirtualFree/HeapFree).
    void ClearRange(GuestAddress addr, GuestSize size) noexcept;

    // === Taint Queries ===
    // Check if any byte in [addr, addr+size) carries taint.
    [[nodiscard]] bool IsTainted(GuestAddress addr, GuestSize size) const noexcept;

    // Get the OR-union of all taint tags in [addr, addr+size).
    [[nodiscard]] TaintSource GetTaint(GuestAddress addr, GuestSize size) const noexcept;

    // Get per-byte taint for a range (returns empty on cap exceeded or unmapped).
    [[nodiscard]] std::vector<TaintSource> GetTaintMap(
        GuestAddress addr, GuestSize size) const noexcept;

    // === Taint Propagation ===
    // Propagate taint from source range to destination range (memory copy/move).
    // Destination bytes get OR-merged with source taint tags.
    void PropagateWrite(GuestAddress dst, GuestAddress src, GuestSize size) noexcept;

    // Propagate a uniform taint tag to a destination range (e.g., API return
    // writing a buffer where the source is an external input, not guest memory).
    void PropagateTag(GuestAddress dst, GuestSize size, TaintSource tag) noexcept;

    // === Sink Checking ===
    // Check if data at an address is tainted before a security-relevant sink.
    // If tainted, records a TaintEvent and returns true.
    [[nodiscard]] bool CheckSink(
        GuestAddress dataAddr,
        GuestSize dataSize,
        GuestAddress ripAddr,
        TaintEvent::SinkType sinkType,
        uint64_t instrCount,
        uint16_t threadId) noexcept;

    // === Event Retrieval ===
    [[nodiscard]] std::vector<TaintEvent> GetTaintEvents() const;
    [[nodiscard]] uint32_t GetTaintEventCount() const noexcept;

    // Statistics
    [[nodiscard]] uint32_t GetTaintedPageCount() const noexcept;
    [[nodiscard]] uint64_t GetTotalTaintedBytes() const noexcept;

private:
    // Shadow page = kPageSize bytes of TaintSource tags
    // nullptr means the page is entirely clean (no taint)
    struct ShadowPage {
        TaintSource bytes[kPageSize]{};
    };

    // Get or create a shadow page for a guest page base address
    [[nodiscard]] ShadowPage* GetOrCreatePage(GuestAddress pageBase) noexcept;

    // Get a shadow page (read-only, returns nullptr if clean)
    [[nodiscard]] const ShadowPage* GetPage(GuestAddress pageBase) const noexcept;

    // Check if a shadow page is entirely clean (all bytes None)
    [[nodiscard]] static bool IsPageClean(const ShadowPage& page) noexcept;

    // Sparse shadow page table: maps page-base → shadow page
    // Using unique_ptr for RAII and to keep the map value small
    std::unordered_map<GuestAddress, std::unique_ptr<ShadowPage>> m_shadowPages;

    // Recorded taint events (when tainted data reaches sinks)
    std::vector<TaintEvent> m_events;

    mutable std::shared_mutex m_mutex;

    // Resource caps
    static constexpr uint32_t kMaxShadowPages   = 131'072;  // 128K pages = 512 MB
    static constexpr uint32_t kMaxTaintEvents    = 100'000;
    static constexpr GuestSize kMaxTaintMarkSize = 64ULL * 1024 * 1024; // 64 MB single mark
};

} // namespace Phantom
