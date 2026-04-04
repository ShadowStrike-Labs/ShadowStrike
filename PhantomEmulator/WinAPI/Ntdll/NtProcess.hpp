/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtProcess.hpp — Nt* process management syscall handlers
 *
 * Covers NtOpenProcess, NtTerminateProcess, and
 * NtQueryInformationProcess (including anti-debug info classes:
 * ProcessDebugPort, ProcessDebugObjectHandle, ProcessDebugFlags).
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ntdll {

// Register all Nt* process handlers with the dispatcher.
void RegisterNtProcess(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop (e.g., NtTerminateProcess on self)
bool HandleNtOpenProcess(APIContext& ctx);
bool HandleNtTerminateProcess(APIContext& ctx);
bool HandleNtQueryInformationProcess(APIContext& ctx);

} // namespace WinAPI::Ntdll
} // namespace Phantom
