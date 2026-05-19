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

#include "pch.h"

#include "../../HomeProductOrchestrator.hpp"
#include "../BankingTrojanDetector.hpp"
#include "../../ModeThresholds.hpp"

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
            using ::ShadowStrike::Products::Home::ProtectionMode;
            using ::ShadowStrike::Products::Home::ProtectionModeMask;
            using ::ShadowStrike::Products::Home::ApplyModeThresholds;

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
                            L"BankingTrojanDetector: Initialize() threw: %S", e.what());
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
                            L"BankingTrojanDetector: Start() threw: %S", e.what());
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
                            L"BankingTrojanDetector: Shutdown() threw: %S", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BankingTrojanDetector: Shutdown() threw unknown exception");
                    }
                },

                .setMode = [](ProtectionMode mode) -> bool {
                    auto& detector = BankingTrojanDetector::Instance();
                    auto config = detector.GetConfiguration();

                    switch (mode) {
                        case ProtectionMode::Passive:
                            config.enableRealTimeProtection = true;
                            config.autoQuarantine = false;
                            config.autoTerminate = false;
                            config.blockC2 = false;
                            config.threatScoreThreshold = 75.0;
                            config.confidenceThreshold = 0.85;
                            break;
                        case ProtectionMode::Balanced:
                            config.enableRealTimeProtection = true;
                            config.autoQuarantine = true;
                            config.autoTerminate = false;
                            config.blockC2 = true;
                            config.threatScoreThreshold = 60.0;
                            config.confidenceThreshold = 0.70;
                            break;
                        case ProtectionMode::Aggressive:
                            config.enableRealTimeProtection = true;
                            config.autoQuarantine = true;
                            config.autoTerminate = true;
                            config.blockC2 = true;
                            config.threatScoreThreshold = 45.0;
                            config.confidenceThreshold = 0.55;
                            break;
                        case ProtectionMode::Off:
                            SS_LOG_ERROR(kLogCategory,
                                L"BankingTrojanDetector: setMode(Off) must be routed through orchestrator disable");
                            return false;
                    }

                    if (!detector.UpdateConfiguration(config)) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BankingTrojanDetector: UpdateConfiguration rejected mode=%u",
                            static_cast<unsigned>(mode));
                        return false;
                    }
                    return ApplyModeThresholds("BankingTrojanDetector", mode);
                },

                .supportedModesMask =
                    ProtectionModeMask(ProtectionMode::Off)        |
                    ProtectionModeMask(ProtectionMode::Passive)    |
                    ProtectionModeMask(ProtectionMode::Balanced)   |
                    ProtectionModeMask(ProtectionMode::Aggressive)
            });
        } catch (...) {
            ::OutputDebugStringW(
                L"BankingTrojanDetectorWiring: static registration failed\n");
        }
    }
};

const BankingTrojanDetectorRegistrar g_bankingTrojanDetectorRegistrar{};

}  // namespace

// ---------------------------------------------------------------------------
// Keep-alive anchor — prevents MSVC /OPT:REF + LTCG from dropping this TU in
// Release builds. The global registrar has internal linkage, so without an
// external-linkage symbol referenced from another TU the linker can elide the
// whole object. WiringAnchor.cpp takes the address of this function.
// ---------------------------------------------------------------------------
extern "C" void PhantomHome_KeepAlive_BankingTrojanDetector() noexcept {}
