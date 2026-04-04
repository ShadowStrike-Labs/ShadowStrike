/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * UrlmonAPI.hpp — Urlmon URL download and validation API handlers
 *
 * Covers URLDownloadToFileA/W, URLDownloadToCacheFileA/W,
 * IsValidURL, CoInternetIsFeatureEnabled.
 *
 * ENTERPRISE CRITICAL:
 *   - URLDownloadToFile is one of the most common payload download methods
 *   - URL + destination filename are critical IOCs (drive-by download, staging)
 *   - All downloads simulated as success to reveal full attack chain
 *   - No actual file writes — emulation only
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Urlmon {

// Register all Urlmon handlers with the dispatcher.
void RegisterUrlmonAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop

bool HandleURLDownloadToFileA(APIContext& ctx);
bool HandleURLDownloadToFileW(APIContext& ctx);
bool HandleURLDownloadToCacheFileA(APIContext& ctx);
bool HandleURLDownloadToCacheFileW(APIContext& ctx);
bool HandleIsValidURL(APIContext& ctx);
bool HandleCoInternetIsFeatureEnabled(APIContext& ctx);

} // namespace WinAPI::Urlmon
} // namespace Phantom
