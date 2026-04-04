/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ShellcodeLoader.hpp — Raw shellcode loader for emulation
 *
 * Loads raw x86/x64 shellcode buffers into the guest address space with a
 * minimal execution environment: RWX code region, stack, heap, and fake
 * PEB/TEB structures. The PEB/TEB are critical because sophisticated
 * shellcode reads TEB→PEB→Ldr→InLoadOrderModuleList to locate kernel32.dll.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Memory/VirtualMemory.hpp"
#include "../CPU/CPU.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"
#include "../../Common/Config.hpp"
#include "../../Common/Constants.hpp"

#include <cstdint>

namespace Phantom {

// ============================================================================
// LoadedShellcode — Result of loading shellcode into guest memory
// ============================================================================

struct LoadedShellcode {
    GuestAddress codeBase   = 0;
    GuestAddress entryPoint = 0;
    GuestAddress stackBase  = 0;
    GuestAddress stackTop   = 0;
    GuestAddress heapBase   = 0;
    GuestAddress pebAddress = 0;
    GuestAddress tebAddress = 0;
    GuestSize    codeSize   = 0;
    bool         is64Bit    = false;
};

// ============================================================================
// ShellcodeLoader — Loads raw shellcode into an emulation environment
// ============================================================================

class ShellcodeLoader {
public:
    explicit ShellcodeLoader(VirtualMemory& memory) noexcept;

    struct LoadResult {
        LoadedShellcode shellcode;
        ErrorCode       error = ErrorCode::Success;
        [[nodiscard]] bool Ok() const noexcept { return error == ErrorCode::Success; }
    };

    [[nodiscard]] LoadResult Load(
        ByteSpan shellcodeData,
        const EmulationConfig& config) noexcept;

    void PrepareCPUState(
        CPU& cpu,
        const LoadedShellcode& sc,
        const EmulationConfig& config) noexcept;

private:
    VirtualMemory& m_memory;

    [[nodiscard]] ErrorCode CreateMinimalPEB(
        LoadedShellcode& sc,
        const EmulationConfig& config) noexcept;
    [[nodiscard]] ErrorCode CreateMinimalTEB(
        LoadedShellcode& sc,
        const EmulationConfig& config) noexcept;
};

} // namespace Phantom
