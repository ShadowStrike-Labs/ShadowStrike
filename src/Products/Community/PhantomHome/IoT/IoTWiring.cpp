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
 * @file IoTWiring.cpp
 * @brief Registers the IoT protection subsystem with HomeProductOrchestrator
 *        via IPLeakProtection, which serves as the IoT integration facade.
 *
 * DESIGN RATIONALE
 * ================
 * The IoT folder contains five individual modules:
 *   - IoTDeviceScanner
 *   - IPLeakProtection  (IoT namespace)
 *   - RouterSecurityChecker
 *   - SmartHomeProtection
 *   - WiFiSecurityAnalyzer
 *
 * Each module header defines its own `ShadowStrike::IoT::ModuleStatus` enum
 * with distinct enumerators and values.  Because the five headers share a
 * namespace but define incompatible enumerations, including more than one of
 * them in the same translation unit causes a C2011 type-redefinition error.
 *
 * `IPLeakProtection` is explicitly documented as "an integration point for
 * IoT security subsystems" and exposes:
 *   - StartIoTModules()  — initializes and starts the full IoT stack
 *   - StopIoTModules()   — stops and tears down the full IoT stack
 *   - RunIoTSecurityScan() / GetIoTStatus()
 *
 * Registering `IPLeakProtection` as the sole wiring entry therefore drives
 * the complete IoT lifecycle through a single, well-defined integration point,
 * matching the "register facade if it exists" contract in the wiring spec.
 *
 * The module is registered as "IoTIPLeakProtection" to disambiguate from the
 * identically-named class in the Privacy folder (ShadowStrike::Privacy).
 *
 * LIFECYCLE MAPPING
 * =================
 *   initialize() → IPLeakProtection::Instance().Initialize()
 *   start()      → IPLeakProtection::Instance().StartIoTModules()
 *   shutdown()   → IPLeakProtection::Instance().StopIoTModules()
 *                  IPLeakProtection::Instance().Shutdown()
 *
 * PHASE / CONFIG KEY
 * ==================
 *   Phase      : ModulePhase::OnDemand
 *   Config key : "Home/IoT/Enabled"
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "../HomeProductOrchestrator.hpp"
#include "IPLeakProtection.hpp"

#include "../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"IoTWiring";

struct IoTModulesRegistrar final {
    IoTModulesRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::IoT::IPLeakProtection;

            // ----------------------------------------------------------------
            // IoTIPLeakProtection — IoT integration facade
            //
            // IPLeakProtection is the designated integration point for all IoT
            // subsystems.  Its Initialize() prepares IP-leak detection; its
            // StartIoTModules() brings up the full IoT stack
            // (IoTDeviceScanner, RouterSecurityChecker, SmartHomeProtection,
            //  WiFiSecurityAnalyzer).  StopIoTModules() tears them all down
            // before Shutdown() releases IPLeakProtection's own resources.
            // ----------------------------------------------------------------
            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "IoTIPLeakProtection",
                .enabledConfigKey = "Home/IoT/Enabled",
                .phase            = ModulePhase::OnDemand,

                .initialize = []() -> bool {
                    try {
                        if (!IPLeakProtection::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"IoTIPLeakProtection: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"IoTIPLeakProtection: initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"IoTIPLeakProtection: initialize() threw unknown exception");
                        return false;
                    }
                },

                // start() activates the full IoT stack via the integration facade.
                .start = []() -> bool {
                    try {
                        if (!IPLeakProtection::Instance().StartIoTModules()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"IoTIPLeakProtection: StartIoTModules() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"IoTIPLeakProtection: start() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"IoTIPLeakProtection: start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        IPLeakProtection::Instance().StopIoTModules();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"IoTIPLeakProtection: StopIoTModules() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"IoTIPLeakProtection: StopIoTModules() threw unknown exception");
                    }
                    try {
                        IPLeakProtection::Instance().Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"IoTIPLeakProtection: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"IoTIPLeakProtection: Shutdown() threw unknown exception");
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
const IoTModulesRegistrar g_iotModulesRegistrar{};

}  // namespace
