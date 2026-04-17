/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - PRODUCT ENTRY POINT
 * ============================================================================
 *
 * @file HomeProductEntry.cpp
 * @brief Glue between PhantomCore's ProductExtensions hook and the Home
 *        orchestrator. Present only in the PhantomHome binary; EDR/XDR binaries
 *        compile a no-op ProductExtensions into a dormant singleton and never
 *        reference any Home symbol.
 *
 * Mechanism:
 *   A static initializer in this translation unit registers two lambdas with
 *   ShadowStrike::Service::ProductExtensions. When the main service reaches
 *   its late-init hook, the engine calls InitializeProduct() which runs the
 *   registered lambda, which in turn drives HomeProductOrchestrator.
 *
 *   Because the registration happens before main() (dynamic initialization of
 *   a namespace-scope object), the hook is guaranteed to be in place when the
 *   SCM invokes AntivirusService::OnStart().
 *
 * This file is intentionally thin: it owns no state, makes no protection
 * decisions, and could be replaced by a completely different product entry
 * (e.g. HomeOEMProductEntry.cpp) without touching the orchestrator or engine.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "pch.h"

#include "HomeProductOrchestrator.hpp"

#include "../../../PhantomCore/Service/ProductExtensions.hpp"
#include "../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"HomeProductEntry";

struct HomeProductRegistrar final {
    HomeProductRegistrar() noexcept {
        try {
            using ::ShadowStrike::Service::ProductExtensions;
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;

            ProductExtensions::Instance().SetProductEntry(
                "PhantomHome",
                /*initializeAndStart=*/[]() -> bool {
                    try {
                        auto& orch = HomeProductOrchestrator::Instance();

                        // Initialize must come before Start. We treat Initialize
                        // failure as fatal (the user expects the product up).
                        // Individual module failures are already isolated
                        // inside the orchestrator; a false return here means
                        // the config bootstrap itself blew up.
                        if (!orch.Initialize()) {
                            SS_LOG_WARN(kLogCategory,
                                L"HomeProductOrchestrator::Initialize() reported partial failure");
                            // Continue anyway - per-module failures are
                            // isolated; we still want the surviving modules
                            // to Start. Return true because "some modules
                            // running" is better than "whole product down".
                        }

                        if (!orch.Start()) {
                            SS_LOG_WARN(kLogCategory,
                                L"HomeProductOrchestrator::Start() reported partial failure");
                            // Same rationale as above.
                        }

                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_FATAL(kLogCategory,
                            L"PhantomHome startup threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_FATAL(kLogCategory,
                            L"PhantomHome startup threw unknown exception");
                        return false;
                    }
                },
                /*shutdown=*/[]() {
                    try {
                        HomeProductOrchestrator::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PhantomHome shutdown threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PhantomHome shutdown threw unknown exception");
                    }
                });
        } catch (...) {
            // Static-init-time: logger may not be up. Swallow.
        }
    }
};

// Namespace-scope object performs the registration before main() runs.
// Using an unnamed namespace means exactly one instance per PhantomHome binary;
// other product binaries don't link this TU so they never construct it.
const HomeProductRegistrar g_homeProductRegistrar{};

}  // namespace
