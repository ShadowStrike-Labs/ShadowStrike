/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MemoryAPI.hpp — Kernel32 memory management API handlers
 *
 * Covers VirtualAlloc/Free/Protect/Query, ReadProcessMemory,
 * WriteProcessMemory, Heap*, GlobalAlloc/Free, LocalAlloc/Free.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel32 {

// Register all Kernel32 memory management handlers with the dispatcher.
void RegisterMemoryAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop

bool HandleVirtualAlloc(APIContext& ctx);
bool HandleVirtualAllocEx(APIContext& ctx);
bool HandleVirtualFree(APIContext& ctx);
bool HandleVirtualFreeEx(APIContext& ctx);
bool HandleVirtualProtect(APIContext& ctx);
bool HandleVirtualProtectEx(APIContext& ctx);
bool HandleVirtualQuery(APIContext& ctx);
bool HandleVirtualQueryEx(APIContext& ctx);
bool HandleReadProcessMemory(APIContext& ctx);
bool HandleWriteProcessMemory(APIContext& ctx);
bool HandleHeapCreate(APIContext& ctx);
bool HandleHeapDestroy(APIContext& ctx);
bool HandleHeapAlloc(APIContext& ctx);
bool HandleHeapFree(APIContext& ctx);
bool HandleHeapReAlloc(APIContext& ctx);
bool HandleHeapSize(APIContext& ctx);
bool HandleGetProcessHeap(APIContext& ctx);
bool HandleGlobalAlloc(APIContext& ctx);
bool HandleGlobalFree(APIContext& ctx);
bool HandleLocalAlloc(APIContext& ctx);
bool HandleLocalFree(APIContext& ctx);

} // namespace WinAPI::Kernel32
} // namespace Phantom
