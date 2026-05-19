/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file AmsiWiring.cpp
 * @brief Registers the AmsiProvider module with HomeProductOrchestrator.
 */

// ── Windows prerequisites (no PCH) ───────────────────────────────────────────
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <amsi.h>

// ── Standard library before Logger.hpp ───────────────────────────────────────
#include <format>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

// ── PhantomHome infrastructure ────────────────────────────────────────────────
#include "Products/Community/PhantomHome/HomeProductOrchestrator.hpp"
#include "Products/Community/PhantomHome/ModeThresholds.hpp"
#include "Products/Community/PhantomHome/AmsiProvider/AmsiProvider.hpp"
#include "Products/Community/PhantomHome/AmsiProvider/AmsiProviderRegistration.hpp"
#include "PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"AmsiWiring";

// One provider instance for this process. The mutex serializes orchestrator
// mode/shutdown callbacks; the provider itself handles concurrent AMSI scans.
std::mutex g_providerMutex;
std::unique_ptr<ShadowStrike::Products::Home::AmsiProvider> g_provider;

// ─────────────────────────────────────────────────────────────────────────────

struct AmsiProviderRegistrar final {
    AmsiProviderRegistrar() noexcept {
        using namespace ShadowStrike::Products::Home;
        try {
            auto& orch = HomeProductOrchestrator::Instance();

            orch.RegisterModule(ModuleDescriptor{
                .name             = "AmsiProvider",
                .displayName      = "Script & Memory Scan (AMSI)",
                .group            = "Realtime",
                .enabledConfigKey = "Home/AmsiProvider/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        std::lock_guard lock(g_providerMutex);
                        if (g_provider) return true;

                        auto provider =
                            std::make_unique<ShadowStrike::Products::Home::AmsiProvider>();
                        if (!provider->Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"AmsiProvider::Initialize() returned false");
                            return false;
                        }

                        // Best-effort COM registration; non-fatal if it fails
                        if (!RegisterAmsiProvider()) {
                            SS_LOG_WARN(kLogCategory,
                                L"AMSI COM registration failed; provider will "
                                L"still scan in-process but may not intercept "
                                 L"third-party AMSI clients");
                        }
                        g_provider = std::move(provider);
                        SS_LOG_INFO(kLogCategory,
                            L"AmsiProvider module initialised");
                        return true;
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"Initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"Initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    // No background threads needed; provider is purely on-demand.
                    SS_LOG_INFO(kLogCategory, L"AmsiProvider started");
                    return true;
                },

                .shutdown = []() noexcept {
                    try {
                        if (!UnregisterAmsiProvider()) {
                            SS_LOG_WARN(kLogCategory,
                                L"AMSI COM unregistration reported a non-fatal failure");
                        }
                        std::lock_guard lock(g_providerMutex);
                        if (g_provider) {
                            g_provider->Shutdown();
                            g_provider.reset();
                        }
                        SS_LOG_INFO(kLogCategory, L"AmsiProvider shut down");
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"Shutdown() threw unknown exception");
                    }
                },

                .setMode = [](ShadowStrike::Products::Home::ProtectionMode m)
                    -> bool {
                    try {
                        const bool thresholdsApplied =
                            ShadowStrike::Products::Home::ApplyModeThresholds(
                            "AmsiProvider", m);
                        if (!thresholdsApplied) {
                            return false;
                        }

                        std::lock_guard lock(g_providerMutex);
                        if (g_provider) g_provider->SetMode(m);
                        return true;
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"setMode() threw: %hs", ex.what());
                        return false;
                    }
                },

                .supportedModesMask =
                    ShadowStrike::Products::Home::ProtectionModeMask(
                        ShadowStrike::Products::Home::ProtectionMode::Off)        |
                    ShadowStrike::Products::Home::ProtectionModeMask(
                        ShadowStrike::Products::Home::ProtectionMode::Passive)    |
                    ShadowStrike::Products::Home::ProtectionModeMask(
                        ShadowStrike::Products::Home::ProtectionMode::Balanced)   |
                    ShadowStrike::Products::Home::ProtectionModeMask(
                        ShadowStrike::Products::Home::ProtectionMode::Aggressive),
            });

        } catch (const std::exception& ex) {
            const std::string message =
                std::string("AmsiProviderRegistrar failed during static initialization: ") +
                ex.what() + "\n";
            OutputDebugStringA(message.c_str());
        } catch (...) {
            OutputDebugStringW(
                L"AmsiProviderRegistrar failed during static initialization: unknown exception\n");
        }
    }
};

const AmsiProviderRegistrar g_amsiProviderRegistrar{};

}  // namespace

extern "C" void PhantomHome_KeepAlive_AmsiProvider() noexcept {}
