/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - DNS LEAK PROTECTION MODULE WIRING
 * ============================================================================
 *
 * @file DNSLeakProtectionWiring.cpp
 * @brief Registers the DNSLeakProtection module with the HomeProductOrchestrator
 *        via a static initializer, before main() runs.
 *
 * DNSLeakProtection intercepts DNS queries to detect resolver leaks that
 * expose a user's network activity outside a VPN tunnel. Initialize() loads
 * resolver configuration and baseline policy; MonitorDnsActivity() arms the
 * real-time DNS interception hook. StopMonitoring() quiesces that hook before
 * Shutdown() releases resolver state and OS handles.
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
#include "../DNSLeakProtection.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"DNSLeakProtectionWiring";

struct DNSLeakProtectionRegistrar final {
    DNSLeakProtectionRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Privacy::DNSLeakProtection;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "DNSLeakProtection",
                .enabledConfigKey = "Home/Privacy/Enabled",
                .phase            = ModulePhase::OnDemand,

                .initialize = []() -> bool {
                    try {
                        if (!DNSLeakProtection::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"DNSLeakProtection: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"DNSLeakProtection: initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"DNSLeakProtection: initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        if (!DNSLeakProtection::Instance().MonitorDnsActivity()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"DNSLeakProtection: MonitorDnsActivity() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"DNSLeakProtection: start() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"DNSLeakProtection: start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        DNSLeakProtection::Instance().StopMonitoring();
                        DNSLeakProtection::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"DNSLeakProtection: shutdown threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"DNSLeakProtection: shutdown threw unknown exception");
                    }
                }
            });
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

const DNSLeakProtectionRegistrar g_dnsLeakProtectionRegistrar{};

}  // namespace
