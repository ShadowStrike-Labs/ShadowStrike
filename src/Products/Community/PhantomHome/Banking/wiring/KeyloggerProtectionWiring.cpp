/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - KEYLOGGER PROTECTION MODULE WIRING
 * ============================================================================
 *
 * @file KeyloggerProtectionWiring.cpp
 * @brief Registers the KeyloggerProtection module with the
 *        HomeProductOrchestrator.
 *
 * KeyloggerProtection intercepts and blocks unauthorized kernel-level keystroke
 * capture hooks that banking trojans and spyware use to harvest credentials.
 * Initialize() loads the hook filter configuration; Start() installs the
 * kernel callbacks that intercept SetWindowsHookEx and raw-input device
 * interception chains; Shutdown() removes those callbacks.
 *
 * The module is placed in the CoreProtections phase (phase 1) and gated by
 * "Home/Banking/Enabled".
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "../../HomeProductOrchestrator.hpp"
#include "../KeyloggerProtection.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"KeyloggerProtectionWiring";

struct KeyloggerProtectionRegistrar final {
    KeyloggerProtectionRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Banking::KeyloggerProtection;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "KeyloggerProtection",
                .enabledConfigKey = "Home/Banking/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        if (!KeyloggerProtection::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"KeyloggerProtection: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"KeyloggerProtection: Initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"KeyloggerProtection: Initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        if (!KeyloggerProtection::Instance().Start()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"KeyloggerProtection: Start() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"KeyloggerProtection: Start() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"KeyloggerProtection: Start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        KeyloggerProtection::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"KeyloggerProtection: Shutdown() threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"KeyloggerProtection: Shutdown() threw unknown exception");
                    }
                }
            });
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

const KeyloggerProtectionRegistrar g_keyloggerProtectionRegistrar{};

}  // namespace
