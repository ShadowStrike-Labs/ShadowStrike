/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - COOKIE MANAGER MODULE WIRING
 * ============================================================================
 *
 * @file CookieManagerWiring.cpp
 * @brief Registers the CookieManager module with the HomeProductOrchestrator
 *        via a static initializer, before main() runs.
 *
 * CookieManager handles browser cookie enumeration, tracker purge, and
 * supercookie detection. It becomes fully operational after Initialize()
 * returns; there is no separate Start() method.
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
#include "../CookieManager.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"CookieManagerWiring";

struct CookieManagerRegistrar final {
    CookieManagerRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Privacy::CookieManager;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "CookieManager",
                .enabledConfigKey = "Home/Privacy/Enabled",
                .phase            = ModulePhase::OnDemand,

                .initialize = []() -> bool {
                    try {
                        if (!CookieManager::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"CookieManager: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CookieManager: initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CookieManager: initialize() threw unknown exception");
                        return false;
                    }
                },

                // CookieManager is fully operational after Initialize(); no
                // separate background thread or event loop requires arming.
                .start = []() -> bool {
                    return true;
                },

                .shutdown = []() noexcept {
                    try {
                        CookieManager::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CookieManager: Shutdown() threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CookieManager: Shutdown() threw unknown exception");
                    }
                }
            });
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

const CookieManagerRegistrar g_cookieManagerRegistrar{};

}  // namespace
