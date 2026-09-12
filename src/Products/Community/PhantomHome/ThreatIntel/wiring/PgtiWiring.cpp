/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file PgtiWiring.cpp
 * @brief Registers the PGTI feed manager with HomeProductOrchestrator.
 *
 * PgtiFeedManager was fully implemented and never started. Start() spawns the
 * jthread that watches every configured feed and marks one Degraded when it has
 * not reported a pull in more than twice its interval; Stop() requests the stop
 * token. Without a lifecycle nothing ever called either, so the feed-health view
 * in the UI - PgtiViewModel, PgtiDetailPage, SecurityPage - could never report a
 * stalled feed, because the only code that detects one never ran.
 *
 * This registration does NOT make feeds pull. WorkerLoop is a watchdog; the
 * PhantomCore ThreatIntelFeedManager owns the HTTP client and the pulling, and is
 * started separately by RealTimeProtection. Registering here without saying so
 * would invite the conclusion that an empty IOC store is now explained.
 *
 * Phase is Background deliberately. The watchdog reports on feeds owned by
 * ThreatIntelStore, which comes up during CoreProtections, so starting earlier
 * would observe a subsystem that does not exist yet - the start-ordering
 * inversion recorded as task 235.
 */

// -- Windows prerequisites (no PCH) -----------------------------------------
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

// -- Standard library before Logger.hpp -------------------------------------
#include <format>
#include <stdexcept>

// -- PhantomHome infrastructure ---------------------------------------------
#include "Products/Community/PhantomHome/HomeProductOrchestrator.hpp"
#include "Products/Community/PhantomHome/ModeThresholds.hpp"
#include "Products/Community/PhantomHome/ThreatIntel/PgtiFeedManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"PgtiWiring";

struct PgtiRegistrar final {
    PgtiRegistrar() noexcept {
        using namespace ShadowStrike::Products::Home;
        try {
            auto& orch = HomeProductOrchestrator::Instance();

            orch.RegisterModule(ModuleDescriptor{
                .name             = "PgtiFeeds",
                .displayName      = "Global Threat Intelligence",
                .group            = "Network",
                .enabledConfigKey = "Home/Pgti/Enabled",
                .phase            = ModulePhase::Background,

                .initialize = []() -> bool {
                    try {
                        // Constructs the Meyers singleton and builds the feed
                        // descriptor table. No thread is spawned here, which the
                        // ModuleDescriptor contract requires of initialize.
                        (void)ThreatIntel::PgtiFeedManager::Instance();
                        return true;
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PgtiFeeds: Instance() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PgtiFeeds: Instance() threw unknown");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        // Start() returns void and is idempotent: it exchanges an
                        // atomic running flag and returns early if already set.
                        ThreatIntel::PgtiFeedManager::Instance().Start();
                        return true;
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PgtiFeeds: Start() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PgtiFeeds: Start() threw unknown");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        ThreatIntel::PgtiFeedManager::Instance().Stop();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PgtiFeeds: Stop() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"PgtiFeeds: Stop() threw unknown");
                    }
                },

                // .setMode is deliberately null. The watchdog observes feeds and
                // changes no detection behaviour, so it has nothing to vary by
                // protection mode; the orchestrator falls back to
                // ApplyModeThresholds, which writes the generic per-module keys.
            });

        } catch (...) {
            // Static-init-time: logger may not be ready - silently swallow.
        }
    }
};

const PgtiRegistrar g_pgtiRegistrar{};

}  // namespace

extern "C" void PhantomHome_KeepAlive_Pgti() noexcept {}
