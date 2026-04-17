/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - MICROPHONE GUARD MODULE WIRING
 * ============================================================================
 *
 * @file MicrophoneGuardWiring.cpp
 * @brief Registers the MicrophoneGuard module with the HomeProductOrchestrator
 *        via a static initializer, before main() runs.
 *
 * MicrophoneGuard arbitrates microphone access and enforces global mute
 * policy. Initialize() prepares the access-control engine; MonitorAudioStreams()
 * arms the real-time stream interception loop that must run while the service
 * is active. StopMonitoring() quiesces stream interception cleanly before
 * Shutdown() releases the COM/WASAPI handles.
 *
 * Phase      : ModulePhase::OnDemand
 * Config key : "Home/Privacy/Enabled"
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "../../HomeProductOrchestrator.hpp"
#include "../MicrophoneGuard.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"MicrophoneGuardWiring";

struct MicrophoneGuardRegistrar final {
    MicrophoneGuardRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Privacy::MicrophoneGuard;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "MicrophoneGuard",
                .enabledConfigKey = "Home/Privacy/Enabled",
                .phase            = ModulePhase::OnDemand,

                .initialize = []() -> bool {
                    try {
                        if (!MicrophoneGuard::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"MicrophoneGuard: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"MicrophoneGuard: initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"MicrophoneGuard: initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        if (!MicrophoneGuard::Instance().MonitorAudioStreams()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"MicrophoneGuard: MonitorAudioStreams() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"MicrophoneGuard: start() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"MicrophoneGuard: start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        MicrophoneGuard::Instance().StopMonitoring();
                        MicrophoneGuard::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"MicrophoneGuard: shutdown threw: %hs", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"MicrophoneGuard: shutdown threw unknown exception");
                    }
                }
            });
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

const MicrophoneGuardRegistrar g_microphoneGuardRegistrar{};

}  // namespace
