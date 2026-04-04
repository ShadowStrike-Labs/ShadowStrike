/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * RegistryExtAPI.hpp — Advapi32 advanced registry API handlers
 *
 * Covers RegQueryInfoKeyA/W, RegSaveKeyA/W, RegLoadKeyA/W,
 * RegUnLoadKeyA/W, RegNotifyChangeKeyValue, RegRestoreKeyA/W,
 * RegOpenKeyA/W, RegConnectRegistryA/W, RegGetValueA/W,
 * RegCopyTreeA/W, RegDeleteTreeA/W, RegDeleteKeyValueA/W.
 *
 * Credential dumping via registry hive export (T1003.002),
 * lateral movement via remote registry (T1021), and large-scale
 * registry manipulation are high-value IOCs flagged here.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Advapi32 {

void RegisterRegistryExtAPI(APIDispatcher& dispatcher) noexcept;

bool HandleRegQueryInfoKeyA(APIContext& ctx);
bool HandleRegQueryInfoKeyW(APIContext& ctx);
bool HandleRegSaveKeyA(APIContext& ctx);
bool HandleRegSaveKeyW(APIContext& ctx);
bool HandleRegLoadKeyA(APIContext& ctx);
bool HandleRegLoadKeyW(APIContext& ctx);
bool HandleRegUnLoadKeyA(APIContext& ctx);
bool HandleRegUnLoadKeyW(APIContext& ctx);
bool HandleRegNotifyChangeKeyValue(APIContext& ctx);
bool HandleRegRestoreKeyA(APIContext& ctx);
bool HandleRegRestoreKeyW(APIContext& ctx);
bool HandleRegOpenKeyA(APIContext& ctx);
bool HandleRegOpenKeyW(APIContext& ctx);
bool HandleRegConnectRegistryA(APIContext& ctx);
bool HandleRegConnectRegistryW(APIContext& ctx);
bool HandleRegGetValueA(APIContext& ctx);
bool HandleRegGetValueW(APIContext& ctx);
bool HandleRegCopyTreeA(APIContext& ctx);
bool HandleRegCopyTreeW(APIContext& ctx);
bool HandleRegDeleteTreeA(APIContext& ctx);
bool HandleRegDeleteTreeW(APIContext& ctx);
bool HandleRegDeleteKeyValueA(APIContext& ctx);
bool HandleRegDeleteKeyValueW(APIContext& ctx);

} // namespace WinAPI::Advapi32
} // namespace Phantom
