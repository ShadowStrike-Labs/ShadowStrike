/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * COMAPI.hpp — Ole32 COM infrastructure API handlers
 *
 * Covers CoInitialize, CoInitializeEx, CoUninitialize, CoCreateInstance,
 * CoGetClassObject, CLSIDFromProgID, StringFromGUID2, CoTaskMemAlloc,
 * CoTaskMemFree.
 *
 * ENTERPRISE CRITICAL:
 *   - CoCreateInstance with known-bad CLSIDs detects COM-based attacks:
 *     ShellLink (LNK abuse), InternetExplorer (COM hijack),
 *     WScript.Shell, MSXML2.XMLHTTP (C2 comms)
 *   - WbemLocator CLSID returns a fake vtable (S_OK) to enable WMI
 *     code path execution and query capture
 *   - All other COM object creation is blocked (E_NOINTERFACE) to prevent
 *     malware from progressing through COM chains
 *   - CLSID logging provides IOC for behavioral analysis
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ole32 {

// Register all Ole32 COM handlers with the dispatcher.
void RegisterCOMAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop

bool HandleCoInitialize(APIContext& ctx);
bool HandleCoInitializeEx(APIContext& ctx);
bool HandleCoUninitialize(APIContext& ctx);
bool HandleCoCreateInstance(APIContext& ctx);
bool HandleCoGetClassObject(APIContext& ctx);
bool HandleCLSIDFromProgID(APIContext& ctx);
bool HandleStringFromGUID2(APIContext& ctx);
bool HandleCoTaskMemAlloc(APIContext& ctx);
bool HandleCoTaskMemFree(APIContext& ctx);

} // namespace WinAPI::Ole32
} // namespace Phantom
