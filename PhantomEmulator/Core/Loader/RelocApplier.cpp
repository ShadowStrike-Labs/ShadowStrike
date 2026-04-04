/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * RelocApplier.cpp — PE base relocation application engine
 *
 * Walks the PE base relocation directory and patches absolute addresses in the
 * loaded image to account for the difference between the actual load address
 * and the preferred ImageBase. All memory access is performed through the
 * VirtualMemory abstraction to honor guest page protections and isolation.
 *
 * Supports:
 *   - IMAGE_REL_BASED_ABSOLUTE  (0)  — padding / no-op
 *   - IMAGE_REL_BASED_HIGH      (1)  — high 16 bits of a 32-bit address
 *   - IMAGE_REL_BASED_LOW       (2)  — low  16 bits of a 32-bit address
 *   - IMAGE_REL_BASED_HIGHLOW   (3)  — full 32-bit address (PE32)
 *   - IMAGE_REL_BASED_HIGHADJ   (4)  — high 16 bits with adjustment
 *   - IMAGE_REL_BASED_DIR64    (10)  — full 64-bit address (PE64)
 *
 * Anti-evasion: malware may craft pathological relocation directories with
 * excessive block counts, oversized blocks, or out-of-range offsets. Every
 * iteration is capped against PE::kMax* limits and every address is validated
 * through VirtualMemory before read/write.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "RelocApplier.hpp"

#include <cstdint>
#include <cstring>

namespace Phantom {

// ============================================================================
// Constants
// ============================================================================

// Maximum reasonable block size: 8-byte header + kMaxRelocsPerBlock * 2 bytes
static constexpr uint32_t kMaxBlockSize =
    sizeof(PE::BaseRelocation) +
    static_cast<uint32_t>(PE::kMaxRelocsPerBlock) * sizeof(uint16_t);

// Minimum valid block size: header only (no entries — degenerate but legal)
static constexpr uint32_t kMinBlockSize = sizeof(PE::BaseRelocation);

// ============================================================================
// Apply — Walk relocation directory, patch all entries
// ============================================================================

RelocResult RelocApplier::Apply(
    GuestAddress   actualBase,
    uint64_t       preferredBase,
    uint32_t       relocDirRVA,
    uint32_t       relocDirSize,
    VirtualMemory& memory) noexcept
{
    RelocResult result{};

    // -----------------------------------------------------------------------
    // 1. Compute delta — if the image loaded at its preferred base, nothing to do
    // -----------------------------------------------------------------------
    const auto delta = static_cast<int64_t>(actualBase) -
                       static_cast<int64_t>(preferredBase);
    if (delta == 0) {
        return result; // No relocations needed
    }

    // -----------------------------------------------------------------------
    // 2. Validate directory parameters
    // -----------------------------------------------------------------------
    if (relocDirRVA == 0 || relocDirSize < kMinBlockSize) {
        // No relocation directory present or impossibly small — not necessarily
        // an error; some PEs have no relocations (stripped or position-independent).
        return result;
    }

    // Guard against a directory that claims to be absurdly large
    if (relocDirSize > PE::kMaxRelocBlocks * kMaxBlockSize) {
        result.error = ErrorCode::MalformedPE;
        return result;
    }

    // -----------------------------------------------------------------------
    // 3. Walk relocation blocks
    // -----------------------------------------------------------------------
    const GuestAddress dirBase = actualBase + relocDirRVA;
    uint32_t offset = 0;

    while (offset + kMinBlockSize <= relocDirSize &&
           result.blocksProcessed < PE::kMaxRelocBlocks)
    {
        // -------------------------------------------------------------------
        // 3a. Read the BaseRelocation header for this block
        // -------------------------------------------------------------------
        PE::BaseRelocation block{};
        const GuestAddress blockAddr = dirBase + offset;

        ErrorCode err = memory.ReadValue(blockAddr, block);
        if (err != ErrorCode::Success) {
            result.error = ErrorCode::RelocApplyFail;
            return result;
        }

        // -------------------------------------------------------------------
        // 3b. Validate block fields
        // -------------------------------------------------------------------
        if (block.SizeOfBlock == 0) {
            // Sentinel: zero-sized block terminates the directory
            break;
        }

        if (block.SizeOfBlock < kMinBlockSize) {
            result.error = ErrorCode::MalformedPE;
            return result;
        }

        if (block.SizeOfBlock > kMaxBlockSize) {
            result.error = ErrorCode::MalformedPE;
            return result;
        }

        // Ensure this block does not extend past the directory
        if (block.SizeOfBlock > relocDirSize - offset) {
            result.error = ErrorCode::MalformedPE;
            return result;
        }

        // -------------------------------------------------------------------
        // 3c. Calculate entry count and page base
        // -------------------------------------------------------------------
        const uint32_t entryBytes = block.SizeOfBlock - kMinBlockSize;
        uint32_t entryCount = entryBytes / sizeof(uint16_t);

        if (entryCount > PE::kMaxRelocsPerBlock) {
            entryCount = PE::kMaxRelocsPerBlock;
        }

        const GuestAddress pageBase = actualBase + block.VirtualAddress;

        // -------------------------------------------------------------------
        // 3d. Process each 16-bit relocation entry in this block
        // -------------------------------------------------------------------
        const GuestAddress entriesAddr = blockAddr + kMinBlockSize;

        for (uint32_t i = 0; i < entryCount; ++i) {
            uint16_t entry = 0;
            err = memory.ReadU16(entriesAddr + i * sizeof(uint16_t), entry);
            if (err != ErrorCode::Success) {
                result.error = ErrorCode::RelocApplyFail;
                return result;
            }

            const uint16_t type   = entry >> 12;
            const uint16_t relOff = entry & 0x0FFF;

            if (type == PE::kRelocAbsolute) {
                ++result.skippedAbsolute;
                continue;
            }

            // Handle kRelocHighAdj: it consumes the next entry as parameter
            if (type == PE::kRelocHighAdj) {
                // Read the adjustment value from the next entry
                uint16_t adjustment = 0;
                if (i + 1 < entryCount) {
                    err = memory.ReadU16(entriesAddr + (i + 1) * sizeof(uint16_t), adjustment);
                    if (err != ErrorCode::Success) {
                        result.error = ErrorCode::RelocApplyFail;
                        return result;
                    }
                }

                const GuestAddress targetAddr = pageBase + relOff;
                uint16_t highWord = 0;
                err = memory.ReadU16(targetAddr, highWord);
                if (err != ErrorCode::Success) {
                    result.error = ErrorCode::RelocApplyFail;
                    return result;
                }

                // HIGHADJ: (highWord << 16) + adjustment + delta, take high 16 bits
                const int32_t combined =
                    (static_cast<int32_t>(highWord) << 16) +
                    static_cast<int32_t>(adjustment) +
                    static_cast<int32_t>(delta);
                highWord = static_cast<uint16_t>(
                    static_cast<uint32_t>(combined) >> 16);

                err = memory.WriteU16(targetAddr, highWord);
                if (err != ErrorCode::Success) {
                    result.error = ErrorCode::RelocApplyFail;
                    return result;
                }

                ++result.relocationsApplied;
                ++i; // Skip the consumed adjustment entry
                continue;
            }

            err = ApplyEntry(memory, pageBase, type, relOff, delta);
            if (err != ErrorCode::Success) {
                result.error = err;
                return result;
            }

            ++result.relocationsApplied;
        }

        ++result.blocksProcessed;
        offset += block.SizeOfBlock;
    }

    return result;
}

// ============================================================================
// ApplyEntry — Patch a single relocation site
// ============================================================================

ErrorCode RelocApplier::ApplyEntry(
    VirtualMemory& memory,
    GuestAddress   pageBase,
    uint16_t       type,
    uint16_t       offset,
    int64_t        delta) noexcept
{
    const GuestAddress targetAddr = pageBase + offset;

    switch (type) {

    case PE::kRelocHighLow: {
        // Full 32-bit fixup (common in PE32)
        uint32_t value = 0;
        ErrorCode err = memory.ReadU32(targetAddr, value);
        if (err != ErrorCode::Success) return ErrorCode::RelocApplyFail;

        const auto adjusted = static_cast<uint32_t>(
            static_cast<int64_t>(value) + delta);

        err = memory.WriteU32(targetAddr, adjusted);
        if (err != ErrorCode::Success) return ErrorCode::RelocApplyFail;
        return ErrorCode::Success;
    }

    case PE::kRelocDir64: {
        // Full 64-bit fixup (common in PE64)
        uint64_t value = 0;
        ErrorCode err = memory.ReadU64(targetAddr, value);
        if (err != ErrorCode::Success) return ErrorCode::RelocApplyFail;

        const auto adjusted = static_cast<uint64_t>(
            static_cast<int64_t>(value) + delta);

        err = memory.WriteU64(targetAddr, adjusted);
        if (err != ErrorCode::Success) return ErrorCode::RelocApplyFail;
        return ErrorCode::Success;
    }

    case PE::kRelocHigh: {
        // Adjust the high 16 bits of a 32-bit address at the target
        uint16_t value = 0;
        ErrorCode err = memory.ReadU16(targetAddr, value);
        if (err != ErrorCode::Success) return ErrorCode::RelocApplyFail;

        const auto adjusted = static_cast<uint16_t>(
            value + static_cast<uint16_t>(
                (static_cast<uint32_t>(delta) >> 16) & 0xFFFF));

        err = memory.WriteU16(targetAddr, adjusted);
        if (err != ErrorCode::Success) return ErrorCode::RelocApplyFail;
        return ErrorCode::Success;
    }

    case PE::kRelocLow: {
        // Adjust the low 16 bits of a 32-bit address at the target
        uint16_t value = 0;
        ErrorCode err = memory.ReadU16(targetAddr, value);
        if (err != ErrorCode::Success) return ErrorCode::RelocApplyFail;

        const auto adjusted = static_cast<uint16_t>(
            value + static_cast<uint16_t>(delta & 0xFFFF));

        err = memory.WriteU16(targetAddr, adjusted);
        if (err != ErrorCode::Success) return ErrorCode::RelocApplyFail;
        return ErrorCode::Success;
    }

    default:
        // Unknown relocation type — possible malformation or unsupported arch
        return ErrorCode::RelocApplyFail;
    }
}

} // namespace Phantom
