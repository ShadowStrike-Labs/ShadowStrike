/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * PELoader.hpp — PE32/PE64 image loader orchestrator
 *
 * Coordinates the full PE loading pipeline: parse, allocate, map sections,
 * apply relocations, resolve imports, handle TLS, and set up the execution
 * environment (stack, heap, PEB, TEB). Every step assumes hostile input.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "PEParser.hpp"
#include "PEStructures.hpp"
#include "ExportResolver.hpp"
#include "ImportResolver.hpp"
#include "RelocApplier.hpp"
#include "TLSHandler.hpp"
#include "../Memory/VirtualMemory.hpp"
#include "../CPU/CPU.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"
#include "../../Common/Config.hpp"
#include "../../Common/Constants.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace Phantom {

// ============================================================================
// LoadedImage — Result of loading a PE into guest memory
// ============================================================================

struct LoadedImage {
    GuestAddress imageBase  = 0;
    GuestAddress entryPoint = 0;
    GuestAddress stackBase  = 0;
    GuestAddress stackTop   = 0;
    GuestAddress heapBase   = 0;
    GuestAddress pebAddress = 0;
    GuestAddress tebAddress = 0;

    ParsedPE         parsedPE;
    TLSInfo          tlsInfo;
    ImportResolution imports;

    bool            is64Bit = false;
    bool            isDLL   = false;
    EmulationTarget target  = EmulationTarget::PE64;

    GuestSize totalMapped    = 0;
    uint32_t  sectionsLoaded = 0;
};

// ============================================================================
// PELoader — Orchestrates PE loading into guest memory
// ============================================================================

class PELoader {
public:
    PELoader(VirtualMemory& memory,
             ExportResolver& exports,
             ImportResolver& imports) noexcept;

    struct LoadResult {
        LoadedImage image;
        ErrorCode   error = ErrorCode::Success;
        std::string errorDetail;
        [[nodiscard]] bool Ok() const noexcept { return error == ErrorCode::Success; }
    };

    [[nodiscard]] LoadResult Load(ByteSpan peData,
                                  const EmulationConfig& config) noexcept;

    [[nodiscard]] LoadResult LoadDLL(ByteSpan peData,
                                     std::string_view dllName) noexcept;

    void PrepareCPUState(CPU& cpu,
                         const LoadedImage& image,
                         const EmulationConfig& config) noexcept;

    [[nodiscard]] GuestAddress GetNextDLLBase() const noexcept { return m_nextDLLBase; }

private:
    VirtualMemory&  m_memory;
    ExportResolver& m_exports;
    ImportResolver& m_imports;
    GuestAddress    m_nextDLLBase = 0;

    [[nodiscard]] ErrorCode AllocateImageMemory(
        const ParsedPE& pe, GuestAddress& actualBase) noexcept;
    [[nodiscard]] ErrorCode MapSections(
        const ParsedPE& pe, ByteSpan peData, GuestAddress actualBase) noexcept;
    [[nodiscard]] ErrorCode MapHeaders(
        const ParsedPE& pe, ByteSpan peData, GuestAddress actualBase) noexcept;
    [[nodiscard]] ErrorCode ApplySectionProtections(
        const ParsedPE& pe, GuestAddress imageBase) noexcept;
    [[nodiscard]] ErrorCode SetupStack(
        LoadedImage& image, const EmulationConfig& config) noexcept;
    [[nodiscard]] ErrorCode SetupHeap(
        LoadedImage& image, const EmulationConfig& config) noexcept;
    [[nodiscard]] ErrorCode CreatePEB(
        LoadedImage& image, const EmulationConfig& config) noexcept;
    [[nodiscard]] ErrorCode CreateTEB(
        LoadedImage& image, const EmulationConfig& config) noexcept;
};

} // namespace Phantom
