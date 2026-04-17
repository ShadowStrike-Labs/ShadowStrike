/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - PRIVACY PROTECTION MODULE WIRING
 * ============================================================================
 *
 * @file PrivacyWiring.cpp
 * @brief Registers Privacy protection modules with HomeProductOrchestrator
 *        via static initialization, before main() runs.
 *
 * MODULES REGISTERED
 * ==================
 *   CookieManager    — browser cookie enumeration, tracker purge, supercookie
 *                      detection; uses Common.hpp (ModuleStatus shared);
 *                      unique callback types: no name conflicts
 *   LocationPrivacy  — location access control and geofence enforcement;
 *                      uses Common.hpp (ModuleStatus shared);
 *                      unique: AccessEventCallback, GeofenceCallback,
 *                              LocationCallback (no conflicts with Cookie/Mic)
 *   MicrophoneGuard  — microphone access arbitration and global mute control;
 *                      uses Common.hpp (ModuleStatus shared);
 *                      unique: AudioAccessCallback, DecisionCallback,
 *                              DeviceChangeCallback, StreamCallback
 *                      (no conflicts with Cookie/Location)
 *
 * MODULES EXCLUDED FROM THIS TU — TYPE ALIAS CONFLICTS OR MIGRATION PENDING
 * ===========================================================================
 *   WebcamProtector:
 *     Defines AccessEventCallback (conflicts with LocationPrivacy's alias of
 *     the same name but different underlying type), DeviceChangeCallback and
 *     DecisionCallback (both conflict with MicrophoneGuard's aliases of the
 *     same names but different underlying types).  Including this header
 *     together with LocationPrivacy or MicrophoneGuard causes C2371
 *     "redefinition; different basic types" errors.  Wire WebcamProtector in
 *     a separate translation unit (WebcamProtectorWiring.cpp).
 *
 *   DataLeakProtection, DNSLeakProtection, Privacy::IPLeakProtection,
 *   PrivacyCleaner:
 *     Each defines its own ShadowStrike::Privacy::ModuleStatus enumeration
 *     with distinct enumerators and values.  Including any of these with the
 *     modules above — which pull in Common.hpp's authoritative ModuleStatus —
 *     causes C2011 "type redefinition" errors.  The migration from per-module
 *     enumerations to the Common.hpp shared enum (as documented in Common.hpp:
 *     "Previously each module defined its own identical enum, causing ODR
 *     violations") is incomplete for these four modules.  Wire them in
 *     dedicated translation units once migration is complete.
 *
 * None of the registered modules expose a Start() method; they become fully
 * operational once Initialize() returns true.  The start() callbacks
 * therefore return true immediately, consistent with the EmailWiring
 * and SecureBrowser precedents.
 *
 * PHASE / CONFIG KEY
 * ==================
 *   Phase      : ModulePhase::OnDemand
 *   Config key : "Home/Privacy/Enabled"
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "../HomeProductOrchestrator.hpp"
#include "CookieManager.hpp"
#include "LocationPrivacy.hpp"
#include "MicrophoneGuard.hpp"

#include "../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"PrivacyWiring";

struct PrivacyModulesRegistrar final {
    PrivacyModulesRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Privacy::CookieManager;
            using ::ShadowStrike::Privacy::LocationPrivacy;
            using ::ShadowStrike::Privacy::MicrophoneGuard;

            auto& orch = HomeProductOrchestrator::Instance();

            // ----------------------------------------------------------------
            // CookieManager
            // ----------------------------------------------------------------
            orch.RegisterModule(ModuleDescriptor{
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
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CookieManager: initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CookieManager: initialize() threw unknown exception");
                        return false;
                    }
                },

                // CookieManager becomes fully operational after Initialize().
                .start = []() -> bool {
                    return true;
                },

                .shutdown = []() noexcept {
                    try {
                        CookieManager::Instance().Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CookieManager: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CookieManager: Shutdown() threw unknown exception");
                    }
                }
            });

            // ----------------------------------------------------------------
            // LocationPrivacy
            // ----------------------------------------------------------------
            orch.RegisterModule(ModuleDescriptor{
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
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"LocationPrivacy: initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"LocationPrivacy: initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    return true;
                },

                .shutdown = []() noexcept {
                    try {
                        LocationPrivacy::Instance().Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"LocationPrivacy: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"LocationPrivacy: Shutdown() threw unknown exception");
                    }
                }
            });

            // ----------------------------------------------------------------
            // MicrophoneGuard
            // ----------------------------------------------------------------
            orch.RegisterModule(ModuleDescriptor{
                .name             = "MicrophoneGuard",
                .enabledConfigKey = "Home/Privacy/Enabled",
                .phase            = ModulePhase::OnDemand,

                .initialize = []() -> bool {
                    try {
                        if (!MicrophoneGuard::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"MicrophoneGuard: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"MicrophoneGuard: initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"MicrophoneGuard: initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    return true;
                },

                .shutdown = []() noexcept {
                    try {
                        MicrophoneGuard::Instance().Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"MicrophoneGuard: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"MicrophoneGuard: Shutdown() threw unknown exception");
                    }
                }
            });

        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

// Namespace-scope object — constructed before main(), exactly once per
// PhantomHome binary (unnamed namespace prevents ODR issues in other TUs).
const PrivacyModulesRegistrar g_privacyModulesRegistrar{};

}  // namespace
