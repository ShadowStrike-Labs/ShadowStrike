/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - TRANSACTION MONITOR MODULE WIRING
 * ============================================================================
 *
 * @file TransactionMonitorWiring.cpp
 * @brief Registers the TransactionMonitor module with the
 *        HomeProductOrchestrator.
 *
 * TransactionMonitor performs behavioral analysis of active financial sessions,
 * correlating browser network traffic, DOM mutations, and clipboard access
 * patterns to detect in-session Man-in-the-Browser (MitB) attacks and
 * transaction-manipulation attempts.  Initialize() loads the behavioral
 * ruleset and allocates session-state buffers; Start() begins the real-time
 * monitoring loop; Shutdown() drains the event queue and releases resources.
 *
 * The module is placed in the CoreProtections phase (phase 1) and gated by
 * "Home/Banking/Enabled".
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "../../HomeProductOrchestrator.hpp"
#include "../TransactionMonitor.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"TransactionMonitorWiring";

struct TransactionMonitorRegistrar final {
    TransactionMonitorRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Banking::TransactionMonitor;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "TransactionMonitor",
                .enabledConfigKey = "Home/Banking/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        if (!TransactionMonitor::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"TransactionMonitor: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"TransactionMonitor: Initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"TransactionMonitor: Initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        if (!TransactionMonitor::Instance().Start()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"TransactionMonitor: Start() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"TransactionMonitor: Start() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"TransactionMonitor: Start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        TransactionMonitor::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"TransactionMonitor: Shutdown() threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"TransactionMonitor: Shutdown() threw unknown exception");
                    }
                }
            });
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

const TransactionMonitorRegistrar g_transactionMonitorRegistrar{};

}  // namespace
