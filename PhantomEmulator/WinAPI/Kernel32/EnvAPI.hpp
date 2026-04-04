/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * EnvAPI.hpp — Kernel32 environment and system information API handlers
 *
 * Covers GetComputerNameA/W, GetUserNameA/W, GetSystemDirectoryA/W,
 * GetWindowsDirectoryA/W, GetEnvironmentVariableA/W, GetVersionExA/W,
 * GetVersion, GetSystemInfo, GetNativeSystemInfo,
 * IsProcessorFeaturePresent, GetDiskFreeSpaceExA.
 *
 * Anti-evasion critical: environment must appear as a real enterprise
 * workstation — not a sandbox, VM, or analysis host.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel32 {

// Register all Kernel32 environment/system info handlers with the dispatcher.
void RegisterEnvAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract.
bool HandleGetComputerNameA(APIContext& ctx);
bool HandleGetComputerNameW(APIContext& ctx);
bool HandleGetUserNameA(APIContext& ctx);
bool HandleGetUserNameW(APIContext& ctx);
bool HandleGetSystemDirectoryA(APIContext& ctx);
bool HandleGetSystemDirectoryW(APIContext& ctx);
bool HandleGetWindowsDirectoryA(APIContext& ctx);
bool HandleGetWindowsDirectoryW(APIContext& ctx);
bool HandleGetEnvironmentVariableA(APIContext& ctx);
bool HandleGetEnvironmentVariableW(APIContext& ctx);
bool HandleGetVersionExA(APIContext& ctx);
bool HandleGetVersionExW(APIContext& ctx);
bool HandleGetVersion(APIContext& ctx);
bool HandleGetSystemInfo(APIContext& ctx);
bool HandleGetNativeSystemInfo(APIContext& ctx);
bool HandleIsProcessorFeaturePresent(APIContext& ctx);
bool HandleGetDiskFreeSpaceExA(APIContext& ctx);

} // namespace WinAPI::Kernel32
} // namespace Phantom
