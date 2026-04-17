/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - DATA LEAK PROTECTION MODULE WIRING
 * ============================================================================
 *
 * @file DataLeakProtectionWiring.cpp
 * @brief Registers the DataLeakProtection module with the HomeProductOrchestrator
 *        via a static initializer, before main() runs.
 *
 * DataLeakProtection (DLP) scans egress channels for sensitive data patterns.
 * Initialize() loads policy definitions and pattern rules; StartClipboardMonitoring()
 * arms the real-time clipboard interception hook that requires a running
 * message loop. StopClipboardMonitoring() quiesces the hook before Shutdown()
 * releases OS handles and policy state.
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
#include "../DataLeakProtection.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"DataLeakProtectionWiring";

struct DataLeakProtectionRegistrar final {
    DataLeakProtectionRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Privacy::DataLeakProtection;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "DataLeakProtection",
                .enabledConfigKey = "Home/Privacy/Enabled",
                .phase            = ModulePhase::OnDemand,

                .initialize = []() -> bool {
                    try {
                        if (!DataLeakProtection::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"DataLeakProtection: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"DataLeakProtection: initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"DataLeakProtection: initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        if (!DataLeakProtection::Instance().StartClipboardMonitoring()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"DataLeakProtection: StartClipboardMonitoring() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"DataLeakProtection: start() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"DataLeakProtection: start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        DataLeakProtection::Instance().StopClipboardMonitoring();
                        DataLeakProtection::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"DataLeakProtection: shutdown threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"DataLeakProtection: shutdown threw unknown exception");
                    }
                }
            });
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

const DataLeakProtectionRegistrar g_dataLeakProtectionRegistrar{};

}  // namespace
