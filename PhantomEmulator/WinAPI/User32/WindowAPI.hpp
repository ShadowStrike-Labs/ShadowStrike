/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * WindowAPI.hpp — User32 window management API handlers
 *
 * Covers MessageBox, FindWindow, GetDesktopWindow, GetForegroundWindow,
 * GetShellWindow, ShowWindow, PostMessage, SendMessage, GetSystemMetrics,
 * SystemParametersInfo, GetCursorPos, SetCursorPos, EnumWindows,
 * GetWindowText, GetClassName.
 *
 * ANTI-EVASION CRITICAL:
 *   - FindWindow returns NULL for ALL analysis tool queries (OllyDbg, IDA, etc.)
 *   - FindWindow returns fake HWND only for Shell_TrayWnd (realistic environment)
 *   - GetSystemMetrics(SM_REMOTESESSION) returns 0 (not RDP — sandbox evasion)
 *   - Screen resolution: 1920x1080 (VMs often use 1024x768 — detectable)
 *   - MessageBox logs text for ransomware note detection
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::User32 {

// Register all User32 window management handlers with the dispatcher.
void RegisterWindowAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop

bool HandleMessageBoxA(APIContext& ctx);
bool HandleMessageBoxW(APIContext& ctx);
bool HandleFindWindowA(APIContext& ctx);
bool HandleFindWindowW(APIContext& ctx);
bool HandleGetForegroundWindow(APIContext& ctx);
bool HandleGetDesktopWindow(APIContext& ctx);
bool HandleGetShellWindow(APIContext& ctx);
bool HandleShowWindow(APIContext& ctx);
bool HandlePostMessageA(APIContext& ctx);
bool HandlePostMessageW(APIContext& ctx);
bool HandleSendMessageA(APIContext& ctx);
bool HandleSendMessageW(APIContext& ctx);
bool HandleGetSystemMetrics(APIContext& ctx);
bool HandleSystemParametersInfoA(APIContext& ctx);
bool HandleSystemParametersInfoW(APIContext& ctx);
bool HandleGetCursorPos(APIContext& ctx);
bool HandleSetCursorPos(APIContext& ctx);
bool HandleEnumWindows(APIContext& ctx);
bool HandleGetWindowTextA(APIContext& ctx);
bool HandleGetWindowTextW(APIContext& ctx);
bool HandleGetClassNameA(APIContext& ctx);
bool HandleGetClassNameW(APIContext& ctx);

} // namespace WinAPI::User32
} // namespace Phantom
