/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - BANKING TROJAN DETECTOR MODULE WIRING
 * ============================================================================
 *
 * @file BankingTrojanDetectorWiring.cpp
 * @brief Registers the BankingTrojanDetector module with the
 *        HomeProductOrchestrator.
 *
 * BankingTrojanDetector performs real-time scanning of process memory and
 * loaded modules to identify banker trojans, form-grabbers, and memory-resident
 * financial malware.  Its lifecycle follows the standard three-phase contract:
 * Initialize() loads configuration and prepares detection state; Start() arms
 * the real-time memory-scanning callbacks; Shutdown() quiesces those callbacks
 * and releases OS handles.
 *
 * The module is placed in the CoreProtections phase (phase 1) so it starts
 * after the Foundation config bootstrap but before on-demand and background
 * modules.  It is gated by "Home/Banking/Enabled".
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "../../HomeProductOrchestrator.hpp"
#include "../BankingTrojanDetector.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"BankingTrojanDetectorWiring";

struct BankingTrojanDetectorRegistrar final {
    BankingTrojanDetectorRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Banking::BankingTrojanDetector;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "BankingTrojanDetector",
                .enabledConfigKey = "Home/Banking/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        if (!BankingTrojanDetector::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"BankingTrojanDetector: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BankingTrojanDetector: Initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BankingTrojanDetector: Initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        if (!BankingTrojanDetector::Instance().Start()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"BankingTrojanDetector: Start() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BankingTrojanDetector: Start() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BankingTrojanDetector: Start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        BankingTrojanDetector::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BankingTrojanDetector: Shutdown() threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BankingTrojanDetector: Shutdown() threw unknown exception");
                    }
                }
            });
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

const BankingTrojanDetectorRegistrar g_bankingTrojanDetectorRegistrar{};

}  // namespace
