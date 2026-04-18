/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - CONFIG MODULE WIRING
 * ============================================================================
 *
 * @file ConfigWiring.cpp
 * @brief Registers the HomeConfig module with the HomeProductOrchestrator.
 *
 * The HomeConfig module is placed in the Foundation phase so that all
 * configuration keys and profile presets are registered before any other
 * module (email, banking, web, etc.) attempts to read them.  It has no
 * enabledConfigKey ("" = always enabled) because the config subsystem is a
 * prerequisite for every feature gate.
 *
 * Registration is performed by a namespace-scope static object (unnamed
 * namespace) so the RegisterModule() call reaches the orchestrator before
 * main() runs, matching the pattern established in HomeProductEntry.cpp.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "pch.h"

#include "../HomeProductOrchestrator.hpp"
#include "HomeConfigRegistration.hpp"

#include "../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"ConfigWiring";

struct HomeConfigRegistrar final {
    HomeConfigRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "HomeConfig",
                .enabledConfigKey = "",   // Always enabled — this is the bootstrap itself.
                .phase            = ModulePhase::Foundation,

                .initialize = []() -> bool {
                    try {
                        namespace Cfg = ShadowStrike::Products::PhantomHome::Config;

                        if (!Cfg::RegisterProductDefaults()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"HomeConfig: RegisterProductDefaults() returned false");
                            return false;
                        }

                        if (!Cfg::RegisterProfilePresets()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"HomeConfig: RegisterProfilePresets() returned false");
                            return false;
                        }

                        return true;
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"HomeConfig: initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"HomeConfig: initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    // Config registration completed in Initialize(). Now
                    // validate the assembled configuration before feature
                    // modules begin reading it during their Start() calls.
                    try {
                        namespace Cfg = ShadowStrike::Products::PhantomHome::Config;
                        if (!Cfg::ValidateConfiguration()) {
                            SS_LOG_WARN(kLogCategory,
                                L"HomeConfig: ValidateConfiguration() found issues — "
                                L"continuing with best-effort defaults");
                            // Non-fatal: validation warnings should not block
                            // the entire product. Issues are already logged
                            // individually by ValidateConfiguration().
                        }
                        return true;
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"HomeConfig: start() threw: %hs", ex.what());
                        return true; // Non-fatal — validation is advisory
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"HomeConfig: start() threw unknown exception");
                        return true;
                    }
                },

                .shutdown = []() noexcept {
                    // Nothing to tear down — config keys remain valid for the
                    // lifetime of the process and are cleaned up by the
                    // ConfigManager singleton itself.
                }
            });
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

// Namespace-scope object — constructed before main(), exactly once per
// PhantomHome binary (unnamed namespace prevents ODR issues in other TUs).
const HomeConfigRegistrar g_homeConfigRegistrar{};

}  // namespace
