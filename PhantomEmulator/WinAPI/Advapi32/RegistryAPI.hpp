/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * RegistryAPI.hpp — Advapi32 registry API handlers
 *
 * Covers RegOpenKeyExA/W, RegCreateKeyExA/W, RegSetValueExA/W,
 * RegQueryValueExA/W, RegDeleteKeyA/W, RegDeleteValueA/W,
 * RegCloseKey, RegEnumKeyExA/W, RegEnumValueA/W.
 *
 * Operates against a virtual registry tree pre-populated with realistic
 * Windows 10 Pro entries for anti-evasion during malware analysis.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Advapi32 {

void RegisterRegistryAPI(APIDispatcher& dispatcher) noexcept;

bool HandleRegOpenKeyExA(APIContext& ctx);
bool HandleRegOpenKeyExW(APIContext& ctx);
bool HandleRegCreateKeyExA(APIContext& ctx);
bool HandleRegCreateKeyExW(APIContext& ctx);
bool HandleRegSetValueExA(APIContext& ctx);
bool HandleRegSetValueExW(APIContext& ctx);
bool HandleRegQueryValueExA(APIContext& ctx);
bool HandleRegQueryValueExW(APIContext& ctx);
bool HandleRegDeleteKeyA(APIContext& ctx);
bool HandleRegDeleteKeyW(APIContext& ctx);
bool HandleRegDeleteValueA(APIContext& ctx);
bool HandleRegDeleteValueW(APIContext& ctx);
bool HandleRegCloseKey(APIContext& ctx);
bool HandleRegEnumKeyExA(APIContext& ctx);
bool HandleRegEnumKeyExW(APIContext& ctx);
bool HandleRegEnumValueA(APIContext& ctx);
bool HandleRegEnumValueW(APIContext& ctx);

} // namespace WinAPI::Advapi32
} // namespace Phantom
