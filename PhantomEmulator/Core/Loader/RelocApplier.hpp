/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * RelocApplier.hpp — PE base relocation application engine
 *
 * Applies base relocations when a PE image is loaded at an address different
 * from its preferred ImageBase. Supports all x86/x64 relocation types per the
 * PE/COFF specification. Operates exclusively through VirtualMemory to respect
 * guest address space isolation and page protection semantics.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "PEStructures.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"
#include "../Memory/VirtualMemory.hpp"

#include <cstdint>

namespace Phantom {

// ============================================================================
// Relocation Result
// ============================================================================

struct RelocResult {
    uint32_t  relocationsApplied = 0;
    uint32_t  blocksProcessed    = 0;
    uint32_t  skippedAbsolute    = 0;
    ErrorCode error              = ErrorCode::Success;

    [[nodiscard]] bool Ok() const noexcept { return error == ErrorCode::Success; }
};

// ============================================================================
// RelocApplier — Static relocation application engine
// ============================================================================

class RelocApplier {
public:
    /// Apply base relocations to a loaded PE image in guest memory.
    /// @param actualBase     Guest address where the image was actually loaded.
    /// @param preferredBase  ImageBase from the PE optional header.
    /// @param relocDirRVA    RVA of the base relocation directory.
    /// @param relocDirSize   Size of the base relocation directory in bytes.
    /// @param memory         Guest virtual memory containing the mapped image.
    /// @return RelocResult with counts and error status.
    [[nodiscard]] static RelocResult Apply(
        GuestAddress   actualBase,
        uint64_t       preferredBase,
        uint32_t       relocDirRVA,
        uint32_t       relocDirSize,
        VirtualMemory& memory) noexcept;

private:
    /// Apply a single relocation entry.
    [[nodiscard]] static ErrorCode ApplyEntry(
        VirtualMemory& memory,
        GuestAddress   pageBase,
        uint16_t       type,
        uint16_t       offset,
        uint64_t       delta) noexcept;
};

} // namespace Phantom
