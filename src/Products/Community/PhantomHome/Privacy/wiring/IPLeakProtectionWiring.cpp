/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - IP LEAK PROTECTION MODULE WIRING
 * ============================================================================
 *
 * @file IPLeakProtectionWiring.cpp
 * @brief Registers the Privacy IPLeakProtection module with the
 *        HomeProductOrchestrator via a static initializer, before main() runs.
 *
 * IPLeakProtection detects real-IP disclosure through WebRTC, IPv6, and VPN
 * kill-switch bypass channels. The module is registered under the name
 * "PrivacyIPLeakProtection" to disambiguate it from any IoT-layer adapter
 * that may register a module with a similar name.
 *
 * Initialize() configures WebRTC blocking, IPv6 protection mode, and
 * adapter enumeration; StartVPNMonitoring() arms the real-time VPN-state
 * watcher. StopVPNMonitoring() quiesces the watcher before Shutdown()
 * releases network handles.
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
#include "../IPLeakProtection.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"IPLeakProtectionWiring";

struct IPLeakProtectionRegistrar final {
    IPLeakProtectionRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Privacy::IPLeakProtection;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                // "PrivacyIPLeakProtection" avoids name collision with any IoT
                // or network layer module that might register "IPLeakProtection".
                .name             = "PrivacyIPLeakProtection",
                .enabledConfigKey = "Home/Privacy/Enabled",
                .phase            = ModulePhase::OnDemand,

                .initialize = []() -> bool {
                    try {
                        if (!IPLeakProtection::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"IPLeakProtection: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"IPLeakProtection: initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"IPLeakProtection: initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        if (!IPLeakProtection::Instance().StartVPNMonitoring()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"IPLeakProtection: StartVPNMonitoring() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"IPLeakProtection: start() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"IPLeakProtection: start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        IPLeakProtection::Instance().StopVPNMonitoring();
                        IPLeakProtection::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"IPLeakProtection: shutdown threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"IPLeakProtection: shutdown threw unknown exception");
                    }
                }
            });
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

const IPLeakProtectionRegistrar g_ipLeakProtectionRegistrar{};

}  // namespace
