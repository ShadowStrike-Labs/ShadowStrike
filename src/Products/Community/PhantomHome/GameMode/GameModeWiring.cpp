/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - GAME MODE MODULE WIRING
 * ============================================================================
 *
 * @file GameModeWiring.cpp
 * @brief Registers all GameMode subsystem modules with the
 *        HomeProductOrchestrator via a static initializer. Four separate
 *        descriptors are used to preserve per-module fault isolation:
 *
 *   1. GameProcessDetector  - Process + fullscreen + launcher + VR detection.
 *   2. PerformanceOptimizer - Process priority adjustment and resource
 *                             monitoring; owns its own monitoring thread.
 *   3. OverlayProtection    - Secure overlay windows and integrity checking.
 *   4. GameModeManager      - Facade: coordinates all three above, manages
 *                             profiles, and exposes the canonical IsActive()
 *                             predicate consumed by other subsystems.
 *
 * All four share the "Home/Gaming/Enabled" config gate and run in
 * ModulePhase::UserExperience.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "pch.h"

#include "GameModeManager.hpp"
#include "GameProcessDetector.hpp"
#include "OverlayProtection.hpp"
#include "PerformanceOptimizer.hpp"

#include "../HomeProductOrchestrator.hpp"
#include "../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"GameMode";

struct GameModeWiringRegistrar final {
    GameModeWiringRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;

            // ----------------------------------------------------------------
            // GameProcessDetector - game/launcher/VR process and fullscreen
            // detection. Must be up before the manager activates game mode.
            // ----------------------------------------------------------------
            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "GameProcessDetector",
                .enabledConfigKey = "Home/Gaming/Enabled",
                .phase            = ModulePhase::UserExperience,
                .initialize       = []() -> bool {
                    try {
                        return ::ShadowStrike::GameMode::GameProcessDetector::Instance()
                            .Initialize();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GameProcessDetector::Initialize threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GameProcessDetector::Initialize threw unknown exception");
                        return false;
                    }
                },
                .start            = []() -> bool {
                    try {
                        return ::ShadowStrike::GameMode::GameProcessDetector::Instance()
                            .IsInitialized();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GameProcessDetector start-check threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GameProcessDetector start-check threw unknown exception");
                        return false;
                    }
                },
                .shutdown         = []() {
                    try {
                        ::ShadowStrike::GameMode::GameProcessDetector::Instance()
                            .Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GameProcessDetector::Shutdown threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GameProcessDetector::Shutdown threw unknown exception");
                    }
                }
            });

            // ----------------------------------------------------------------
            // PerformanceOptimizer - process priority and resource monitoring.
            // StartResourceMonitoring() launches its internal polling thread;
            // StopResourceMonitoring() quiesces it before Shutdown().
            // ----------------------------------------------------------------
            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "PerformanceOptimizer",
                .enabledConfigKey = "Home/Gaming/Enabled",
                .phase            = ModulePhase::UserExperience,
                .initialize       = []() -> bool {
                    try {
                        return ::ShadowStrike::GameMode::PerformanceOptimizer::Instance()
                            .Initialize();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PerformanceOptimizer::Initialize threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PerformanceOptimizer::Initialize threw unknown exception");
                        return false;
                    }
                },
                .start            = []() -> bool {
                    try {
                        ::ShadowStrike::GameMode::PerformanceOptimizer::Instance()
                            .StartResourceMonitoring();
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PerformanceOptimizer::StartResourceMonitoring threw: %hs",
                            e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PerformanceOptimizer::StartResourceMonitoring threw "
                            L"unknown exception");
                        return false;
                    }
                },
                .shutdown         = []() {
                    try {
                        auto& opt =
                            ::ShadowStrike::GameMode::PerformanceOptimizer::Instance();
                        opt.StopResourceMonitoring();
                        opt.Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PerformanceOptimizer shutdown threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PerformanceOptimizer shutdown threw unknown exception");
                    }
                }
            });

            // ----------------------------------------------------------------
            // OverlayProtection - secure overlay window management and hook
            // integrity checking. No background thread of its own; integrity
            // checks are driven by GameModeManager callbacks.
            // ----------------------------------------------------------------
            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "OverlayProtection",
                .enabledConfigKey = "Home/Gaming/Enabled",
                .phase            = ModulePhase::UserExperience,
                .initialize       = []() -> bool {
                    try {
                        return ::ShadowStrike::GameMode::OverlayProtection::Instance()
                            .Initialize();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"OverlayProtection::Initialize threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"OverlayProtection::Initialize threw unknown exception");
                        return false;
                    }
                },
                .start            = []() -> bool {
                    try {
                        return ::ShadowStrike::GameMode::OverlayProtection::Instance()
                            .IsInitialized();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"OverlayProtection start-check threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"OverlayProtection start-check threw unknown exception");
                        return false;
                    }
                },
                .shutdown         = []() {
                    try {
                        ::ShadowStrike::GameMode::OverlayProtection::Instance()
                            .Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"OverlayProtection::Shutdown threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"OverlayProtection::Shutdown threw unknown exception");
                    }
                }
            });

            // ----------------------------------------------------------------
            // GameModeManager - facade that coordinates detection, optimizer,
            // and overlay subsystems. Registered last so it initializes after
            // its dependencies and shuts down first during teardown.
            // ----------------------------------------------------------------
            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "GameModeManager",
                .enabledConfigKey = "Home/Gaming/Enabled",
                .phase            = ModulePhase::UserExperience,
                .initialize       = []() -> bool {
                    try {
                        return ::ShadowStrike::GameMode::GameModeManager::Instance()
                            .Initialize();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GameModeManager::Initialize threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GameModeManager::Initialize threw unknown exception");
                        return false;
                    }
                },
                .start            = []() -> bool {
                    try {
                        return ::ShadowStrike::GameMode::GameModeManager::Instance()
                            .IsInitialized();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GameModeManager start-check threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GameModeManager start-check threw unknown exception");
                        return false;
                    }
                },
                .shutdown         = []() {
                    try {
                        ::ShadowStrike::GameMode::GameModeManager::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GameModeManager::Shutdown threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"GameModeManager::Shutdown threw unknown exception");
                    }
                }
            });

        } catch (...) {
            // Static-init-time: logger may not be up yet. Swallow.
        }
    }
};

// Namespace-scope object performs registration before main() runs.
const GameModeWiringRegistrar g_gameModeWiringRegistrar{};

}  // namespace

// ---------------------------------------------------------------------------
// Keep-alive anchor — prevents MSVC /OPT:REF + LTCG from dropping this TU in
// Release builds. The global registrar has internal linkage, so without an
// external-linkage symbol referenced from another TU the linker can elide the
// whole object. WiringAnchor.cpp takes the address of this function.
// ---------------------------------------------------------------------------
extern "C" void PhantomHome_KeepAlive_GameMode() noexcept {}
