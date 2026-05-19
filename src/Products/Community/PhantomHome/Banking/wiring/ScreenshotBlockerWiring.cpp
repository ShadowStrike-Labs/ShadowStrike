/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - SCREENSHOT BLOCKER MODULE WIRING
 * ============================================================================
 *
 * @file ScreenshotBlockerWiring.cpp
 * @brief Registers the ScreenshotBlocker module with the
 *        HomeProductOrchestrator.
 *
 * ScreenshotBlocker monitors and blocks unauthorized invocations of Win32
 * screen-capture APIs (BitBlt, PrintWindow, IDXGIOutputDuplication, etc.) when
 * a financial session is active.  Initialize() configures the allowlist and
 * prepares the API hooks; Start() activates the real-time blocking callbacks;
 * Shutdown() deregisters those callbacks and restores original API dispatch.
 *
 * The module is placed in the CoreProtections phase (phase 1) and gated by
 * "Home/Banking/Enabled".
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "pch.h"

#include "../../HomeProductOrchestrator.hpp"
#include "../ScreenshotBlocker.hpp"
#include "../../ModeThresholds.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"ScreenshotBlockerWiring";

struct ScreenshotBlockerRegistrar final {
    ScreenshotBlockerRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Banking::ScreenshotBlocker;
            using ::ShadowStrike::Products::Home::ProtectionMode;
            using ::ShadowStrike::Products::Home::ProtectionModeMask;
            using ::ShadowStrike::Products::Home::ApplyModeThresholds;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "ScreenshotBlocker",
                .enabledConfigKey = "Home/Banking/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        if (!ScreenshotBlocker::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"ScreenshotBlocker: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"ScreenshotBlocker: Initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"ScreenshotBlocker: Initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        if (!ScreenshotBlocker::Instance().Start()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"ScreenshotBlocker: Start() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"ScreenshotBlocker: Start() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"ScreenshotBlocker: Start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        ScreenshotBlocker::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"ScreenshotBlocker: Shutdown() threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"ScreenshotBlocker: Shutdown() threw unknown exception");
                    }
                },

                .setMode = [](ProtectionMode mode) -> bool {
                    auto& blocker = ScreenshotBlocker::Instance();
                    auto config = blocker.GetConfiguration();

                    switch (mode) {
                        case ProtectionMode::Passive:
                            config.enableDisplayAffinity        = true;
                            config.enableGDIHooks               = true;
                            config.enableDirectXHooks           = false;
                            config.enableClipboardFiltering     = false;
                            config.enablePrintScreenBlocking    = false;
                            config.enableOverlayObfuscation     = false;
                            config.autoSanitizeClipboard        = false;
                            config.autoProtectPasswordFields    = false;
                            config.useEnhancedAffinity          = true;
                            config.allowAccessibilityTools      = true;
                            break;
                        case ProtectionMode::Balanced:
                            config.enableDisplayAffinity        = true;
                            config.enableGDIHooks               = true;
                            config.enableDirectXHooks           = true;
                            config.enableClipboardFiltering     = true;
                            config.enablePrintScreenBlocking    = true;
                            config.enableOverlayObfuscation     = false;
                            config.autoSanitizeClipboard        = true;
                            config.autoProtectPasswordFields    = true;
                            config.useEnhancedAffinity          = true;
                            config.allowAccessibilityTools      = true;
                            break;
                        case ProtectionMode::Aggressive:
                            config.enableDisplayAffinity        = true;
                            config.enableGDIHooks               = true;
                            config.enableDirectXHooks           = true;
                            config.enableClipboardFiltering     = true;
                            config.enablePrintScreenBlocking    = true;
                            config.enableOverlayObfuscation     = true;
                            config.autoSanitizeClipboard        = true;
                            config.autoProtectPasswordFields    = true;
                            config.useEnhancedAffinity          = true;
                            config.allowAccessibilityTools      = false;
                            break;
                        case ProtectionMode::Off:
                            SS_LOG_ERROR(kLogCategory,
                                L"ScreenshotBlocker: setMode(Off) must be routed through orchestrator disable");
                            return false;
                    }

                    if (!blocker.UpdateConfiguration(config)) {
                        SS_LOG_ERROR(kLogCategory,
                            L"ScreenshotBlocker: UpdateConfiguration rejected mode=%u",
                            static_cast<unsigned>(mode));
                        return false;
                    }
                    return ApplyModeThresholds("ScreenshotBlocker", mode);
                },

                .supportedModesMask =
                    ProtectionModeMask(ProtectionMode::Off)        |
                    ProtectionModeMask(ProtectionMode::Passive)    |
                    ProtectionModeMask(ProtectionMode::Balanced)   |
                    ProtectionModeMask(ProtectionMode::Aggressive)
            });
        } catch (...) {
            ::OutputDebugStringW(
                L"ScreenshotBlockerWiring: static registration failed\n");
        }
    }
};

const ScreenshotBlockerRegistrar g_screenshotBlockerRegistrar{};

}  // namespace

// ---------------------------------------------------------------------------
// Keep-alive anchor — prevents MSVC /OPT:REF + LTCG from dropping this TU in
// Release builds. The global registrar has internal linkage, so without an
// external-linkage symbol referenced from another TU the linker can elide the
// whole object. WiringAnchor.cpp takes the address of this function.
// ---------------------------------------------------------------------------
extern "C" void PhantomHome_KeepAlive_ScreenshotBlocker() noexcept {}
