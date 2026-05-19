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

#include "pch.h"

#include "../../HomeProductOrchestrator.hpp"
#include "../TransactionMonitor.hpp"
#include "../../ModeThresholds.hpp"

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
            using ::ShadowStrike::Products::Home::ProtectionMode;
            using ::ShadowStrike::Products::Home::ProtectionModeMask;
            using ::ShadowStrike::Products::Home::ApplyModeThresholds;

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
                },

                .setMode = [](ProtectionMode mode) -> bool {
                    auto& monitor = TransactionMonitor::Instance();
                    auto config = monitor.GetConfiguration();

                    switch (mode) {
                        case ProtectionMode::Passive:
                            config.enableDOMMonitoring               = true;
                            config.enableNetworkValidation           = true;
                            config.enableUIPayloadVerification       = true;
                            config.enableVelocityAnalysis            = true;
                            config.enableBeneficiaryTracking         = true;
                            config.enableGeographicAnalysis          = true;
                            config.blockSuspiciousTransactions       = false;
                            config.requireNewBeneficiaryConfirmation = false;
                            config.anomalyConfidenceThreshold        = 0.85;
                            break;
                        case ProtectionMode::Balanced:
                            config.enableDOMMonitoring               = true;
                            config.enableNetworkValidation           = true;
                            config.enableUIPayloadVerification       = true;
                            config.enableVelocityAnalysis            = true;
                            config.enableBeneficiaryTracking         = true;
                            config.enableGeographicAnalysis          = true;
                            config.blockSuspiciousTransactions       = true;
                            config.requireNewBeneficiaryConfirmation = true;
                            config.anomalyConfidenceThreshold        = 0.70;
                            break;
                        case ProtectionMode::Aggressive:
                            config.enableDOMMonitoring               = true;
                            config.enableNetworkValidation           = true;
                            config.enableUIPayloadVerification       = true;
                            config.enableVelocityAnalysis            = true;
                            config.enableBeneficiaryTracking         = true;
                            config.enableGeographicAnalysis          = true;
                            config.blockSuspiciousTransactions       = true;
                            config.requireNewBeneficiaryConfirmation = true;
                            config.anomalyConfidenceThreshold        = 0.55;
                            break;
                        case ProtectionMode::Off:
                            SS_LOG_ERROR(kLogCategory,
                                L"TransactionMonitor: setMode(Off) must be routed through orchestrator disable");
                            return false;
                    }

                    if (!monitor.UpdateConfiguration(config)) {
                        SS_LOG_ERROR(kLogCategory,
                            L"TransactionMonitor: UpdateConfiguration rejected mode=%u",
                            static_cast<unsigned>(mode));
                        return false;
                    }
                    return ApplyModeThresholds("TransactionMonitor", mode);
                },

                .supportedModesMask =
                    ProtectionModeMask(ProtectionMode::Off)        |
                    ProtectionModeMask(ProtectionMode::Passive)    |
                    ProtectionModeMask(ProtectionMode::Balanced)   |
                    ProtectionModeMask(ProtectionMode::Aggressive)
            });
        } catch (...) {
            ::OutputDebugStringW(
                L"TransactionMonitorWiring: static registration failed\n");
        }
    }
};

const TransactionMonitorRegistrar g_transactionMonitorRegistrar{};

}  // namespace

// ---------------------------------------------------------------------------
// Keep-alive anchor — prevents MSVC /OPT:REF + LTCG from dropping this TU in
// Release builds. The global registrar has internal linkage, so without an
// external-linkage symbol referenced from another TU the linker can elide the
// whole object. WiringAnchor.cpp takes the address of this function.
// ---------------------------------------------------------------------------
extern "C" void PhantomHome_KeepAlive_TransactionMonitor() noexcept {}
