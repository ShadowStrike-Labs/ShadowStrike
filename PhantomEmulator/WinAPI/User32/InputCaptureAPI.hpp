/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * InputCaptureAPI.hpp — User32 input capture, keylogging, and
 *                       screen capture API handlers
 *
 * Covers GetAsyncKeyState, GetKeyState, GetKeyboardState,
 * SetWindowsHookExA/W, UnhookWindowsHookEx, GetWindowDC, ReleaseDC,
 * BitBlt, StretchBlt, CreateDIBSection, GetDIBits,
 * CreateCompatibleDC, CreateCompatibleBitmap, SelectObject,
 * DeleteDC, DeleteObject.
 *
 * ENTERPRISE CRITICAL:
 *   - SetWindowsHookEx with WH_KEYBOARD_LL is MITRE ATT&CK T1056.001
 *     (Input Capture: Keylogging). This is the #1 keylogging technique.
 *   - BitBlt/StretchBlt from screen DC is MITRE ATT&CK T1113 (Screen
 *     Capture). RATs and spyware capture screenshots for exfiltration.
 *   - Repeated GetAsyncKeyState polling is a polling-style keylogger
 *     pattern used when hooks are not feasible.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::User32 {

// Register all input capture / screen capture handlers with the dispatcher.
void RegisterInputCaptureAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop

// Key state polling — keylogger detection
bool HandleGetAsyncKeyState(APIContext& ctx);
bool HandleGetKeyState(APIContext& ctx);
bool HandleGetKeyboardState(APIContext& ctx);

// Windows hooks — keylogger / mouse capture
bool HandleSetWindowsHookExA(APIContext& ctx);
bool HandleSetWindowsHookExW(APIContext& ctx);
bool HandleUnhookWindowsHookEx(APIContext& ctx);

// Device context acquisition — screen capture chain
bool HandleGetWindowDC(APIContext& ctx);
bool HandleReleaseDC(APIContext& ctx);
bool HandleCreateCompatibleDC(APIContext& ctx);
bool HandleDeleteDC(APIContext& ctx);

// Bitmap / blit operations — screen capture
bool HandleBitBlt(APIContext& ctx);
bool HandleStretchBlt(APIContext& ctx);
bool HandleCreateCompatibleBitmap(APIContext& ctx);
bool HandleCreateDIBSection(APIContext& ctx);
bool HandleGetDIBits(APIContext& ctx);
bool HandleSelectObject(APIContext& ctx);
bool HandleDeleteObject(APIContext& ctx);

} // namespace WinAPI::User32
} // namespace Phantom
