/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * FileMappingAPI.hpp — Kernel32 memory-mapped file API handlers
 *
 * Covers CreateFileMappingA/W, OpenFileMappingA/W, MapViewOfFile,
 * MapViewOfFileEx, UnmapViewOfFile, FlushViewOfFile.
 *
 * ENTERPRISE CRITICAL:
 *   - File mappings with SEC_IMAGE are the foundation of process
 *     hollowing (MITRE ATT&CK T1055.012) and transacted hollowing.
 *   - Named shared-memory sections enable stealthy C2 data channels
 *     between injected components.
 *   - Executable mappings (PAGE_EXECUTE_*) indicate code loading
 *     outside the normal module loader path.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel32 {

// Register all file mapping handlers with the dispatcher.
void RegisterFileMappingAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop

bool HandleCreateFileMappingA(APIContext& ctx);
bool HandleCreateFileMappingW(APIContext& ctx);
bool HandleOpenFileMappingA(APIContext& ctx);
bool HandleOpenFileMappingW(APIContext& ctx);
bool HandleMapViewOfFile(APIContext& ctx);
bool HandleMapViewOfFileEx(APIContext& ctx);
bool HandleUnmapViewOfFile(APIContext& ctx);
bool HandleFlushViewOfFile(APIContext& ctx);

} // namespace WinAPI::Kernel32
} // namespace Phantom
