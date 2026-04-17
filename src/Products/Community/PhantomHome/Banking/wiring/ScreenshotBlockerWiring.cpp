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
                }
            });
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

const ScreenshotBlockerRegistrar g_screenshotBlockerRegistrar{};

}  // namespace
