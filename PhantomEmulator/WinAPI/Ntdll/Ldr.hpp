/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * Ldr.hpp — Ntdll Loader (Ldr) function handler declarations
 *
 * Emulates the NT module loader functions used by malware for
 * dynamic API resolution. Maps known DLL names to fake base
 * addresses and resolves function names to hook addresses via
 * the APIDispatcher, enabling interception of dynamically
 * resolved calls (GetProcAddress → LdrGetProcedureAddress).
 *
 * Registered handlers:
 *   LdrLoadDll, LdrGetProcedureAddress,
 *   LdrGetDllHandle, LdrUnloadDll
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ntdll {

/// Register all Ldr function handlers with the API dispatcher.
/// Stores a back-pointer to the dispatcher for hook address resolution.
/// Called by APIDispatcher::RegisterNtdll() during initialization.
void RegisterLdrHandlers(APIDispatcher& dispatcher) noexcept;

/// Reset internal Ldr state (loaded module tracking).
/// Must be called between emulation sessions to prevent state leakage.
void ResetLdrState() noexcept;

} // namespace WinAPI::Ntdll
} // namespace Phantom
