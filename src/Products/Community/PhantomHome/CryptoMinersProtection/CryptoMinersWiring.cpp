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

#include "../ModeThresholds.hpp"

#include "../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"CryptoMinersWiring";

struct CryptoMinersModuleRegistrar final {
    CryptoMinersModuleRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Products::Home::ProtectionMode;
            using ::ShadowStrike::Products::Home::ProtectionModeMask;
            using ::ShadowStrike::Products::Home::ApplyModeThresholds;

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
                        if (!ShadowStrike::CryptoMiners::CryptoMinerDetector::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"CryptoMinerDetector: Initialize() returned false");
                            return false;
                        }
                        return true;
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
                        if (!ShadowStrike::CryptoMiners::CryptoMinerDetector::Instance().Start()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"CryptoMinerDetector: Start() returned false");
                            return false;
                        }
                        return true;
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
                },

                .setMode = [](ProtectionMode mode) -> bool {
                    if (mode == ProtectionMode::Off) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CryptoMinerDetector: setMode(Off) must be routed through orchestrator disable");
                        return false;
                    }
                    try {
                        auto& detector = ShadowStrike::CryptoMiners::CryptoMinerDetector::Instance();
                        auto config = detector.GetConfiguration();
                        switch (mode) {
                            case ProtectionMode::Passive:
                                config.terminateOnDetection = false;
                                config.blockStratumProtocol = false;
                                config.alertOnDetection     = true;
                                break;
                            case ProtectionMode::Balanced:
                                config.terminateOnDetection = false;
                                config.blockStratumProtocol = true;
                                config.alertOnDetection     = true;
                                break;
                            case ProtectionMode::Aggressive:
                                config.terminateOnDetection = true;
                                config.blockStratumProtocol = true;
                                config.alertOnDetection     = true;
                                break;
                            case ProtectionMode::Off:
                                return false;  // unreachable; guarded above
                        }
                        if (!detector.UpdateConfiguration(config)) {
                            SS_LOG_ERROR(kLogCategory,
                                L"CryptoMinerDetector: UpdateConfiguration rejected mode=%u",
                                static_cast<unsigned>(mode));
                            return false;
                        }
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CryptoMinerDetector: setMode threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CryptoMinerDetector: setMode threw unknown exception");
                        return false;
                    }
                    return ApplyModeThresholds("CryptoMinerDetector", mode);
                },

                .supportedModesMask =
                    ProtectionModeMask(ProtectionMode::Off)        |
                    ProtectionModeMask(ProtectionMode::Passive)    |
                    ProtectionModeMask(ProtectionMode::Balanced)   |
                    ProtectionModeMask(ProtectionMode::Aggressive)
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
                        if (!ShadowStrike::CryptoMiners::BrowserMinerDetector::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"BrowserMinerDetector: Initialize() returned false");
                            return false;
                        }
                        return true;
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
                },

                .setMode = [](ProtectionMode mode) -> bool {
                    if (mode == ProtectionMode::Off) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BrowserMinerDetector: setMode(Off) must be routed through orchestrator disable");
                        return false;
                    }
                    try {
                        auto& detector = ShadowStrike::CryptoMiners::BrowserMinerDetector::Instance();
                        auto config = detector.GetConfiguration();
                        switch (mode) {
                            case ProtectionMode::Passive:
                                config.enableDomainBlocking = false;
                                config.blockKnownDomains    = false;
                                config.confidenceThreshold  = 0.85;
                                break;
                            case ProtectionMode::Balanced:
                                config.enableDomainBlocking = true;
                                config.blockKnownDomains    = true;
                                config.confidenceThreshold  = 0.70;
                                break;
                            case ProtectionMode::Aggressive:
                                config.enableDomainBlocking = true;
                                config.blockKnownDomains    = true;
                                config.confidenceThreshold  = 0.55;
                                break;
                            case ProtectionMode::Off:
                                return false;  // unreachable; guarded above
                        }
                        if (!detector.UpdateConfiguration(config)) {
                            SS_LOG_ERROR(kLogCategory,
                                L"BrowserMinerDetector: UpdateConfiguration rejected mode=%u",
                                static_cast<unsigned>(mode));
                            return false;
                        }
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BrowserMinerDetector: setMode threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BrowserMinerDetector: setMode threw unknown exception");
                        return false;
                    }
                    return ApplyModeThresholds("BrowserMinerDetector", mode);
                },

                .supportedModesMask =
                    ProtectionModeMask(ProtectionMode::Off)        |
                    ProtectionModeMask(ProtectionMode::Passive)    |
                    ProtectionModeMask(ProtectionMode::Balanced)   |
                    ProtectionModeMask(ProtectionMode::Aggressive)
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
                        if (!ShadowStrike::CryptoMiners::CPUUsageAnalyzer::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"CPUUsageAnalyzer: Initialize() returned false");
                            return false;
                        }
                        return true;
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
                        if (!ShadowStrike::CryptoMiners::CPUUsageAnalyzer::Instance().Start()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"CPUUsageAnalyzer: Start() returned false");
                            return false;
                        }
                        return true;
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
                },

                .setMode = [](ProtectionMode mode) -> bool {
                    if (mode == ProtectionMode::Off) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CPUUsageAnalyzer: setMode(Off) must be routed through orchestrator disable");
                        return false;
                    }
                    try {
                        auto& analyzer = ShadowStrike::CryptoMiners::CPUUsageAnalyzer::Instance();
                        auto config = analyzer.GetConfiguration();
                        switch (mode) {
                            case ProtectionMode::Passive:
                                config.miningThreshold               = 90.0;
                                config.enableAlgorithmFingerprinting = false;
                                config.monitorBackgroundOnly         = true;
                                break;
                            case ProtectionMode::Balanced:
                                config.miningThreshold               = 75.0;
                                config.enableAlgorithmFingerprinting = true;
                                config.monitorBackgroundOnly         = false;
                                break;
                            case ProtectionMode::Aggressive:
                                config.miningThreshold               = 60.0;
                                config.enableAlgorithmFingerprinting = true;
                                config.monitorBackgroundOnly         = false;
                                break;
                            case ProtectionMode::Off:
                                return false;  // unreachable; guarded above
                        }
                        if (!analyzer.UpdateConfiguration(config)) {
                            SS_LOG_ERROR(kLogCategory,
                                L"CPUUsageAnalyzer: UpdateConfiguration rejected mode=%u",
                                static_cast<unsigned>(mode));
                            return false;
                        }
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CPUUsageAnalyzer: setMode threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CPUUsageAnalyzer: setMode threw unknown exception");
                        return false;
                    }
                    return ApplyModeThresholds("CPUUsageAnalyzer", mode);
                },

                .supportedModesMask =
                    ProtectionModeMask(ProtectionMode::Off)        |
                    ProtectionModeMask(ProtectionMode::Passive)    |
                    ProtectionModeMask(ProtectionMode::Balanced)   |
                    ProtectionModeMask(ProtectionMode::Aggressive)
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
                        if (!ShadowStrike::CryptoMiners::GPUMiningDetector::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"GPUMiningDetector: Initialize() returned false");
                            return false;
                        }
                        return true;
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
                        if (!ShadowStrike::CryptoMiners::GPUMiningDetector::Instance().Start()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"GPUMiningDetector: Start() returned false");
                            return false;
                        }
                        return true;
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
                },

                .setMode = [](ProtectionMode mode) -> bool {
                    if (mode == ProtectionMode::Off) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GPUMiningDetector: setMode(Off) must be routed through orchestrator disable");
                        return false;
                    }
                    try {
                        auto& detector = ShadowStrike::CryptoMiners::GPUMiningDetector::Instance();
                        auto config = detector.GetConfiguration();
                        switch (mode) {
                            case ProtectionMode::Passive:
                                config.terminateMiningProcesses = false;
                                config.detectDAGAllocation      = true;
                                config.gpuLoadThreshold         = 95.0;
                                break;
                            case ProtectionMode::Balanced:
                                config.terminateMiningProcesses = false;
                                config.detectDAGAllocation      = true;
                                config.gpuLoadThreshold         = 80.0;
                                break;
                            case ProtectionMode::Aggressive:
                                config.terminateMiningProcesses = true;
                                config.detectDAGAllocation      = true;
                                config.gpuLoadThreshold         = 65.0;
                                break;
                            case ProtectionMode::Off:
                                return false;  // unreachable; guarded above
                        }
                        if (!detector.UpdateConfiguration(config)) {
                            SS_LOG_ERROR(kLogCategory,
                                L"GPUMiningDetector: UpdateConfiguration rejected mode=%u",
                                static_cast<unsigned>(mode));
                            return false;
                        }
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GPUMiningDetector: setMode threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GPUMiningDetector: setMode threw unknown exception");
                        return false;
                    }
                    return ApplyModeThresholds("GPUMiningDetector", mode);
                },

                .supportedModesMask =
                    ProtectionModeMask(ProtectionMode::Off)        |
                    ProtectionModeMask(ProtectionMode::Passive)    |
                    ProtectionModeMask(ProtectionMode::Balanced)   |
                    ProtectionModeMask(ProtectionMode::Aggressive)
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
                        if (!ShadowStrike::CryptoMiners::PoolConnectionDetector::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"PoolConnectionDetector: Initialize() returned false");
                            return false;
                        }
                        return true;
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
                        if (!ShadowStrike::CryptoMiners::PoolConnectionDetector::Instance().Start()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"PoolConnectionDetector: Start() returned false");
                            return false;
                        }
                        return true;
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
                },

                .setMode = [](ProtectionMode mode) -> bool {
                    if (mode == ProtectionMode::Off) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PoolConnectionDetector: setMode(Off) must be routed through orchestrator disable");
                        return false;
                    }
                    try {
                        auto& detector = ShadowStrike::CryptoMiners::PoolConnectionDetector::Instance();
                        auto config = detector.GetConfiguration();
                        switch (mode) {
                            case ProtectionMode::Passive:
                                config.blockStratumTraffic        = false;
                                config.blockMaliciousPools        = false;
                                config.enableDeepPacketInspection = false;
                                config.extractWalletAddresses     = false;
                                break;
                            case ProtectionMode::Balanced:
                                config.blockStratumTraffic        = true;
                                config.blockMaliciousPools        = true;
                                config.enableDeepPacketInspection = true;
                                config.extractWalletAddresses     = true;
                                break;
                            case ProtectionMode::Aggressive:
                                config.blockStratumTraffic        = true;
                                config.blockMaliciousPools        = true;
                                config.enableDeepPacketInspection = true;
                                config.extractWalletAddresses     = true;
                                break;
                            case ProtectionMode::Off:
                                return false;  // unreachable; guarded above
                        }
                        if (!detector.UpdateConfiguration(config)) {
                            SS_LOG_ERROR(kLogCategory,
                                L"PoolConnectionDetector: UpdateConfiguration rejected mode=%u",
                                static_cast<unsigned>(mode));
                            return false;
                        }
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PoolConnectionDetector: setMode threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PoolConnectionDetector: setMode threw unknown exception");
                        return false;
                    }
                    return ApplyModeThresholds("PoolConnectionDetector", mode);
                },

                .supportedModesMask =
                    ProtectionModeMask(ProtectionMode::Off)        |
                    ProtectionModeMask(ProtectionMode::Passive)    |
                    ProtectionModeMask(ProtectionMode::Balanced)   |
                    ProtectionModeMask(ProtectionMode::Aggressive)
            });

        } catch (...) {
            ::OutputDebugStringW(
                L"CryptoMinersWiring: static registration failed\n");
        }
    }
};

// Namespace-scope object — constructed before main(), exactly once per
// PhantomHome binary (unnamed namespace prevents ODR issues in other TUs).
const CryptoMinersModuleRegistrar g_cryptoMinersModuleRegistrar{};

}  // namespace

// ---------------------------------------------------------------------------
// Keep-alive anchor — prevents MSVC /OPT:REF + LTCG from dropping this TU in
// Release builds. The global registrar has internal linkage, so without an
// external-linkage symbol referenced from another TU the linker can elide the
// whole object. WiringAnchor.cpp takes the address of this function.
// ---------------------------------------------------------------------------
extern "C" void PhantomHome_KeepAlive_CryptoMiners() noexcept {}
