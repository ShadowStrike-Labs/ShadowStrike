/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

// ── Windows prerequisites (no PCH) ───────────────────────────────────────────
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

// ── Standard library before Logger.hpp ───────────────────────────────────────
#include <format>
#include <stdexcept>

// ── PhantomHome infrastructure ────────────────────────────────────────────────
#include "Products/Community/PhantomHome/HomeProductOrchestrator.hpp"
#include "Products/Community/PhantomHome/ModeThresholds.hpp"
#include "Products/Community/PhantomHome/NetworkAttackBlocker/NetworkAttackBlocker.hpp"
#include "PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"NabWiring";

struct NetworkAttackBlockerRegistrar final {
    NetworkAttackBlockerRegistrar() noexcept {
        using namespace ShadowStrike::Products::Home;
        try {
            auto& orch = HomeProductOrchestrator::Instance();

            orch.RegisterModule(ModuleDescriptor{
                .name             = "NetworkAttackBlocker",
                .displayName      = "Network Attack Blocker",
                .group            = "Network",
                .enabledConfigKey = "Home/NetworkAttackBlocker/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        return NetworkAttackBlocker::Instance().Initialize();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"NetworkAttackBlocker: Initialize() threw: %hs",
                            ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"NetworkAttackBlocker: Initialize() threw unknown");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        return NetworkAttackBlocker::Instance().Start();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"NetworkAttackBlocker: Start() threw: %hs",
                            ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"NetworkAttackBlocker: Start() threw unknown");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        NetworkAttackBlocker::Instance().Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"NetworkAttackBlocker: Shutdown() threw: %hs",
                            ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"NetworkAttackBlocker: Shutdown() threw unknown");
                    }
                },

                .setMode = [](ProtectionMode m) -> bool {
                    try {
                        NetworkAttackBlocker::Instance().SetMode(m);
                        if (m == ProtectionMode::Off) {
                            // ApplyModeThresholds refuses Off; the SetMode call
                            // above already drives the runtime into Off state.
                            return true;
                        }
                        return ApplyModeThresholds("NetworkAttackBlocker", m);
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"NetworkAttackBlocker: setMode() threw: %hs",
                            ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"NetworkAttackBlocker: setMode() threw unknown");
                        return false;
                    }
                },

                .supportedModesMask =
                    ProtectionModeMask(ProtectionMode::Off)        |
                    ProtectionModeMask(ProtectionMode::Passive)    |
                    ProtectionModeMask(ProtectionMode::Balanced)   |
                    ProtectionModeMask(ProtectionMode::Aggressive),
            });

        } catch (...) {
            // Static-init-time: logger may not be ready — silently swallow.
        }
    }
};

const NetworkAttackBlockerRegistrar g_nabRegistrar{};

}  // namespace

extern "C" void PhantomHome_KeepAlive_NetworkAttackBlocker() noexcept {}
