/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtMemory.hpp — Nt* virtual-memory and section syscall handlers
 *
 * Covers NtAllocateVirtualMemory, NtProtectVirtualMemory,
 * NtFreeVirtualMemory, NtRead/WriteVirtualMemory,
 * NtQueryVirtualMemory, NtCreateSection, NtMapViewOfSection,
 * and NtUnmapViewOfSection.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ntdll {

// Register all Nt* memory and section handlers with the dispatcher.
void RegisterNtMemory(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop
bool HandleNtAllocateVirtualMemory(APIContext& ctx);
bool HandleNtProtectVirtualMemory(APIContext& ctx);
bool HandleNtFreeVirtualMemory(APIContext& ctx);
bool HandleNtReadVirtualMemory(APIContext& ctx);
bool HandleNtWriteVirtualMemory(APIContext& ctx);
bool HandleNtQueryVirtualMemory(APIContext& ctx);
bool HandleNtCreateSection(APIContext& ctx);
bool HandleNtMapViewOfSection(APIContext& ctx);
bool HandleNtUnmapViewOfSection(APIContext& ctx);

} // namespace WinAPI::Ntdll
} // namespace Phantom
