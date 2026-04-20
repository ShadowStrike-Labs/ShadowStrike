/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - IoT PROTECTION MODULE WIRING
 * ============================================================================
 *
 * Registers each IoT subsystem independently so HomeProductOrchestrator can
 * initialize, start, and tear down the stack in deterministic order.
 */

#include "pch.h"

#include "../HomeProductOrchestrator.hpp"
#include "IoTDeviceScanner.hpp"
#include "RouterSecurityChecker.hpp"
#include "SmartHomeProtection.hpp"
#include "WiFiSecurityAnalyzer.hpp"
#include "IPLeakProtection.hpp"

#include "../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"IoTWiring";

using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
using ::ShadowStrike::Products::Home::ModuleDescriptor;
using ::ShadowStrike::Products::Home::ModulePhase;

struct IoTModulesRegistrar final {
    IoTModulesRegistrar() noexcept {
        try {
            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name = "IoTDeviceScanner",
                .enabledConfigKey = "Home/IoT/Enabled",
                .phase = ModulePhase::OnDemand,
                .initialize = []() -> bool {
                    ShadowStrike::IoT::IoTScannerConfiguration config;
                    config.autoDiscoveryOnStartup = false;
                    config.continuousMonitoring = false;
                    config.defaultScanConfig.checkDefaultCredentials = false;
                    return ShadowStrike::IoT::IoTDeviceScanner::Instance().Initialize(config);
                },
                .start = []() -> bool {
                    return ShadowStrike::IoT::IoTDeviceScanner::Instance().IsInitialized();
                },
                .shutdown = []() {
                    ShadowStrike::IoT::IoTDeviceScanner::Instance().StopScan();
                    ShadowStrike::IoT::IoTDeviceScanner::Instance().Shutdown();
                }
            });

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name = "WiFiSecurityAnalyzer",
                .enabledConfigKey = "Home/IoT/Enabled",
                .phase = ModulePhase::OnDemand,
                .initialize = []() -> bool {
                    ShadowStrike::IoT::WiFiAnalyzerConfiguration config;
                    config.continuousMonitoring = true;
                    config.allowNearbyNetworkEnumeration = false;
                    return ShadowStrike::IoT::WiFiSecurityAnalyzer::Instance().Initialize(config);
                },
                .start = []() -> bool {
                    auto& analyzer = ShadowStrike::IoT::WiFiSecurityAnalyzer::Instance();
                    if (!analyzer.IsInitialized()) {
                        return false;
                    }
                    return analyzer.StartMonitoring();
                },
                .shutdown = []() {
                    ShadowStrike::IoT::WiFiSecurityAnalyzer::Instance().StopMonitoring();
                    ShadowStrike::IoT::WiFiSecurityAnalyzer::Instance().Shutdown();
                }
            });

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name = "RouterSecurityChecker",
                .enabledConfigKey = "Home/IoT/Enabled",
                .phase = ModulePhase::OnDemand,
                .initialize = []() -> bool {
                    ShadowStrike::IoT::RouterCheckerConfiguration config;
                    config.autoAssessOnStartup = false;
                    config.defaultAssessmentConfig.checkDefaultCredentials = false;
                    config.defaultAssessmentConfig.allowCredentialProbe = false;
                    return ShadowStrike::IoT::RouterSecurityChecker::Instance().Initialize(config);
                },
                .start = []() -> bool {
                    return ShadowStrike::IoT::RouterSecurityChecker::Instance().IsInitialized();
                },
                .shutdown = []() {
                    ShadowStrike::IoT::RouterSecurityChecker::Instance().Shutdown();
                }
            });

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name = "SmartHomeProtection",
                .enabledConfigKey = "Home/IoT/Enabled",
                .phase = ModulePhase::OnDemand,
                .initialize = []() -> bool {
                    ShadowStrike::IoT::SmartHomeConfiguration config;
                    return ShadowStrike::IoT::SmartHomeProtection::Instance().Initialize(config);
                },
                .start = []() -> bool {
                    auto& protection = ShadowStrike::IoT::SmartHomeProtection::Instance();
                    if (!protection.IsInitialized()) {
                        return false;
                    }
                    return protection.StartProtection();
                },
                .shutdown = []() {
                    ShadowStrike::IoT::SmartHomeProtection::Instance().StopProtection();
                    ShadowStrike::IoT::SmartHomeProtection::Instance().Shutdown();
                }
            });

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name = "IoTIPLeakProtection",
                .enabledConfigKey = "Home/IoT/Enabled",
                .phase = ModulePhase::OnDemand,
                .initialize = []() -> bool {
                    ShadowStrike::IoT::IPLeakProtectionConfiguration config;
                    config.allowExternalEndpointProbes = false;
                    return ShadowStrike::IoT::IPLeakProtection::Instance().Initialize(config);
                },
                .start = []() -> bool {
                    auto& protection = ShadowStrike::IoT::IPLeakProtection::Instance();
                    if (!protection.IsInitialized()) {
                        return false;
                    }
                    if (!protection.StartMonitoring()) {
                        return false;
                    }
                    if (!protection.StartVPNMonitoring()) {
                        protection.StopMonitoring();
                        return false;
                    }
                    return true;
                },
                .shutdown = []() {
                    auto& protection = ShadowStrike::IoT::IPLeakProtection::Instance();
                    protection.StopVPNMonitoring();
                    protection.StopMonitoring();
                    protection.Shutdown();
                }
            });

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(kLogCategory, L"IoT wiring registration failed: %hs", ex.what());
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"IoT wiring registration failed with unknown exception");
        }
    }
};

const IoTModulesRegistrar g_iotModulesRegistrar{};

}  // namespace
