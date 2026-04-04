/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ShellAPI.hpp — Shell32 shell execution and folder path API handlers
 *
 * Covers ShellExecuteA/W, ShellExecuteExA/W, SHGetFolderPathA/W,
 * SHGetSpecialFolderPathA/W, CommandLineToArgvW.
 *
 * ENTERPRISE CRITICAL:
 *   - ShellExecute is a major process creation vector used by malware
 *   - "runas" verb indicates privilege escalation attempts
 *   - SHGetFolderPath for Startup folders indicates persistence mechanisms
 *   - All file/path operations logged for IOC extraction
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Shell32 {

// Register all Shell32 handlers with the dispatcher.
void RegisterShellAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop

bool HandleShellExecuteA(APIContext& ctx);
bool HandleShellExecuteW(APIContext& ctx);
bool HandleShellExecuteExA(APIContext& ctx);
bool HandleShellExecuteExW(APIContext& ctx);
bool HandleSHGetFolderPathA(APIContext& ctx);
bool HandleSHGetFolderPathW(APIContext& ctx);
bool HandleSHGetSpecialFolderPathA(APIContext& ctx);
bool HandleSHGetSpecialFolderPathW(APIContext& ctx);
bool HandleCommandLineToArgvW(APIContext& ctx);

} // namespace WinAPI::Shell32
} // namespace Phantom
