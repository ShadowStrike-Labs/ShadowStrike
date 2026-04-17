/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - CRYPTO MINERS PROTECTION MODULE WIRING
 * ============================================================================
 *
 * @file CryptoMinersWiring.cpp
 * @brief Registers every CryptoMinersProtection subsystem module with
 *        HomeProductOrchestrator.
 *
 * Modules registered (CoreProtections phase, all gated by "Home/CryptoMiner/Enabled"):
 *   - CryptoMinerDetector    : process-level cryptominer binary detection
 *   - BrowserMinerDetector   : in-browser JavaScript mining detection
 *   - CPUUsageAnalyzer       : sustained high-CPU pattern attribution
 *   - GPUMiningDetector      : GPU API monitoring for mining workloads
 *   - PoolConnectionDetector : stratum/mining-pool network traffic detection
 *
 * Registration is performed by a namespace-scope static object so that
 * RegisterModule() is called before main() runs, matching the pattern
 * established in HomeProductEntry.cpp and ConfigWiring.cpp.
 *
 * BrowserMinerDetector exposes only Initialize/Shutdown (no Start); its start
 * callback returns true immediately, which is correct per the ModuleDescriptor
 * contract.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "pch.h"

#include "../HomeProductOrchestrator.hpp"

#include "BrowserMinerDetector.hpp"
#include "CPUUsageAnalyzer.hpp"
#include "CryptoMinerDetector.hpp"
#include "GPUMiningDetector.hpp"
#include "PoolConnectionDetector.hpp"

#include "../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"CryptoMinersWiring";

struct CryptoMinersModuleRegistrar final {
    CryptoMinersModuleRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;

            auto& orch = HomeProductOrchestrator::Instance();

            // ----------------------------------------------------------------
            // CryptoMinerDetector
            // ----------------------------------------------------------------
            orch.RegisterModule(ModuleDescriptor{
                .name             = "CryptoMinerDetector",
                .enabledConfigKey = "Home/CryptoMiner/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        return ShadowStrike::CryptoMiners::CryptoMinerDetector::Instance()
                            .Initialize();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CryptoMinerDetector: Initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CryptoMinerDetector: Initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        return ShadowStrike::CryptoMiners::CryptoMinerDetector::Instance()
                            .Start();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CryptoMinerDetector: Start() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CryptoMinerDetector: Start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        ShadowStrike::CryptoMiners::CryptoMinerDetector::Instance()
                            .Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CryptoMinerDetector: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CryptoMinerDetector: Shutdown() threw unknown exception");
                    }
                }
            });

            // ----------------------------------------------------------------
            // BrowserMinerDetector  (Initialize / Shutdown only — no Start)
            // ----------------------------------------------------------------
            orch.RegisterModule(ModuleDescriptor{
                .name             = "BrowserMinerDetector",
                .enabledConfigKey = "Home/CryptoMiner/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        return ShadowStrike::CryptoMiners::BrowserMinerDetector::Instance()
                            .Initialize();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BrowserMinerDetector: Initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BrowserMinerDetector: Initialize() threw unknown exception");
                        return false;
                    }
                },

                // BrowserMinerDetector installs its browser extension bridge and
                // network hooks inside Initialize(); no separate start needed.
                .start = []() -> bool {
                    return true;
                },

                .shutdown = []() noexcept {
                    try {
                        ShadowStrike::CryptoMiners::BrowserMinerDetector::Instance()
                            .Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BrowserMinerDetector: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BrowserMinerDetector: Shutdown() threw unknown exception");
                    }
                }
            });

            // ----------------------------------------------------------------
            // CPUUsageAnalyzer
            // ----------------------------------------------------------------
            orch.RegisterModule(ModuleDescriptor{
                .name             = "CPUUsageAnalyzer",
                .enabledConfigKey = "Home/CryptoMiner/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        return ShadowStrike::CryptoMiners::CPUUsageAnalyzer::Instance()
                            .Initialize();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CPUUsageAnalyzer: Initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CPUUsageAnalyzer: Initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        return ShadowStrike::CryptoMiners::CPUUsageAnalyzer::Instance()
                            .Start();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CPUUsageAnalyzer: Start() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CPUUsageAnalyzer: Start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        ShadowStrike::CryptoMiners::CPUUsageAnalyzer::Instance()
                            .Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CPUUsageAnalyzer: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CPUUsageAnalyzer: Shutdown() threw unknown exception");
                    }
                }
            });

            // ----------------------------------------------------------------
            // GPUMiningDetector
            // ----------------------------------------------------------------
            orch.RegisterModule(ModuleDescriptor{
                .name             = "GPUMiningDetector",
                .enabledConfigKey = "Home/CryptoMiner/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        return ShadowStrike::CryptoMiners::GPUMiningDetector::Instance()
                            .Initialize();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GPUMiningDetector: Initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GPUMiningDetector: Initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        return ShadowStrike::CryptoMiners::GPUMiningDetector::Instance()
                            .Start();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GPUMiningDetector: Start() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GPUMiningDetector: Start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        ShadowStrike::CryptoMiners::GPUMiningDetector::Instance()
                            .Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GPUMiningDetector: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GPUMiningDetector: Shutdown() threw unknown exception");
                    }
                }
            });

            // ----------------------------------------------------------------
            // PoolConnectionDetector
            // ----------------------------------------------------------------
            orch.RegisterModule(ModuleDescriptor{
                .name             = "PoolConnectionDetector",
                .enabledConfigKey = "Home/CryptoMiner/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        return ShadowStrike::CryptoMiners::PoolConnectionDetector::Instance()
                            .Initialize();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PoolConnectionDetector: Initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PoolConnectionDetector: Initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        return ShadowStrike::CryptoMiners::PoolConnectionDetector::Instance()
                            .Start();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PoolConnectionDetector: Start() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PoolConnectionDetector: Start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        ShadowStrike::CryptoMiners::PoolConnectionDetector::Instance()
                            .Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PoolConnectionDetector: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PoolConnectionDetector: Shutdown() threw unknown exception");
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
const CryptoMinersModuleRegistrar g_cryptoMinersModuleRegistrar{};

}  // namespace
