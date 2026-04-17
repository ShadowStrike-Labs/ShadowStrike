/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - LOCATION PRIVACY MODULE WIRING
 * ============================================================================
 *
 * @file LocationPrivacyWiring.cpp
 * @brief Registers the LocationPrivacy module with the HomeProductOrchestrator
 *        via a static initializer, before main() runs.
 *
 * LocationPrivacy enforces location access control and geofence policy. It
 * becomes fully operational after Initialize() returns; StartRoute() /
 * StopRoute() are on-demand simulation APIs that callers invoke explicitly
 * and are not part of the module lifecycle.
 *
 * Phase      : ModulePhase::OnDemand
 * Config key : "Home/Privacy/Enabled"
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "pch.h"

#include "../../HomeProductOrchestrator.hpp"
#include "../LocationPrivacy.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"LocationPrivacyWiring";

struct LocationPrivacyRegistrar final {
    LocationPrivacyRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Privacy::LocationPrivacy;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "LocationPrivacy",
                .enabledConfigKey = "Home/Privacy/Enabled",
                .phase            = ModulePhase::OnDemand,

                .initialize = []() -> bool {
                    try {
                        if (!LocationPrivacy::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"LocationPrivacy: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"LocationPrivacy: initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"LocationPrivacy: initialize() threw unknown exception");
                        return false;
                    }
                },

                // LocationPrivacy is fully operational after Initialize();
                // StartRoute/StopRoute are caller-driven simulation APIs, not
                // part of the module's background-thread lifecycle.
                .start = []() -> bool {
                    return true;
                },

                .shutdown = []() noexcept {
                    try {
                        LocationPrivacy::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"LocationPrivacy: Shutdown() threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"LocationPrivacy: Shutdown() threw unknown exception");
                    }
                }
            });
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

const LocationPrivacyRegistrar g_locationPrivacyRegistrar{};

}  // namespace
