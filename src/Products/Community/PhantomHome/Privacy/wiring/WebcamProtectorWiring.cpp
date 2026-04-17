/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - WEBCAM PROTECTOR MODULE WIRING
 * ============================================================================
 *
 * @file WebcamProtectorWiring.cpp
 * @brief Registers the WebcamProtector module with the HomeProductOrchestrator
 *        via a static initializer, before main() runs.
 *
 * WebcamProtector intercepts camera access attempts by processes and enforces
 * allow/deny policy. Initialize() sets up the device enumeration and policy
 * engine; StartMonitoring() arms the kernel-notification callbacks that
 * intercept live camera access. StopMonitoring() quiesces those callbacks
 * cleanly before Shutdown() tears down device handles.
 *
 * Phase      : ModulePhase::OnDemand
 * Config key : "Home/Privacy/Enabled"
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "../../HomeProductOrchestrator.hpp"
#include "../WebcamProtector.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"WebcamProtectorWiring";

struct WebcamProtectorRegistrar final {
    WebcamProtectorRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Privacy::WebcamProtector;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "WebcamProtector",
                .enabledConfigKey = "Home/Privacy/Enabled",
                .phase            = ModulePhase::OnDemand,

                .initialize = []() -> bool {
                    try {
                        if (!WebcamProtector::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"WebcamProtector: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"WebcamProtector: initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"WebcamProtector: initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        if (!WebcamProtector::Instance().StartMonitoring()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"WebcamProtector: StartMonitoring() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"WebcamProtector: start() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"WebcamProtector: start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        WebcamProtector::Instance().StopMonitoring();
                        WebcamProtector::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"WebcamProtector: shutdown threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"WebcamProtector: shutdown threw unknown exception");
                    }
                }
            });
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

const WebcamProtectorRegistrar g_webcamProtectorRegistrar{};

}  // namespace
