/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - PRIVACY CLEANER MODULE WIRING
 * ============================================================================
 *
 * @file PrivacyCleanerWiring.cpp
 * @brief Registers the PrivacyCleaner module with the HomeProductOrchestrator
 *        via a static initializer, before main() runs.
 *
 * PrivacyCleaner performs scheduled and on-demand erasure of browser history,
 * cached credentials, and system artefacts. It becomes fully operational after
 * Initialize() returns; cleaning operations are triggered on-demand or on
 * the schedule baked into the configuration — there is no persistent background
 * monitoring loop to arm via a Start() call.
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
#include "../PrivacyCleaner.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"PrivacyCleanerWiring";

struct PrivacyCleanerRegistrar final {
    PrivacyCleanerRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Privacy::PrivacyCleaner;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "PrivacyCleaner",
                .enabledConfigKey = "Home/Privacy/Enabled",
                .phase            = ModulePhase::OnDemand,

                .initialize = []() -> bool {
                    try {
                        if (!PrivacyCleaner::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"PrivacyCleaner: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PrivacyCleaner: initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PrivacyCleaner: initialize() threw unknown exception");
                        return false;
                    }
                },

                // PrivacyCleaner operates on-demand and on a schedule embedded
                // in its configuration; there is no persistent monitoring loop
                // to arm at Start() time.
                .start = []() -> bool {
                    return true;
                },

                .shutdown = []() noexcept {
                    try {
                        PrivacyCleaner::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PrivacyCleaner: Shutdown() threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PrivacyCleaner: Shutdown() threw unknown exception");
                    }
                }
            });
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

const PrivacyCleanerRegistrar g_privacyCleanerRegistrar{};

}  // namespace
