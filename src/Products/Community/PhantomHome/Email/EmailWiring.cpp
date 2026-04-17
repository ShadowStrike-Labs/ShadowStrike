/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - EMAIL PROTECTION MODULE WIRING
 * ============================================================================
 *
 * @file EmailWiring.cpp
 * @brief Registers the EmailProtection module with the HomeProductOrchestrator.
 *
 * EmailProtection is the single facade orchestrator that internally owns and
 * coordinates AttachmentScanner, PhishingEmailDetector, SpamDetector,
 * OutlookScanner, and ThunderbirdScanner.  A single RegisterModule() call is
 * therefore correct: wiring the sub-components separately would bypass
 * EmailProtection's internal sequencing and duplicate lifecycle management.
 *
 * The module is placed in the CoreProtections phase (phase 1) so it starts
 * after the Foundation config bootstrap (phase 0) but before on-demand and
 * background modules.  It is gated by "Home/Email/Enabled" so users who
 * disable email protection never pay the Initialize() cost.
 *
 * EmailProtection::Initialize() brings all sub-engines to a ready state.
 * There is no separate Start() method on the facade; the module is fully
 * operational after Initialize() succeeds.  The wiring start() callback
 * therefore returns true immediately.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "../HomeProductOrchestrator.hpp"
#include "EmailProtection.hpp"

#include "../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"EmailWiring";

struct EmailProtectionRegistrar final {
    EmailProtectionRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Email::EmailProtection;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "EmailProtection",
                .enabledConfigKey = "Home/Email/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        // EmailProtection is the facade; its Initialize() brings
                        // AttachmentScanner, PhishingEmailDetector, SpamDetector,
                        // OutlookScanner, and ThunderbirdScanner up in order.
                        if (!EmailProtection::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"EmailProtection: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"EmailProtection: initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"EmailProtection: initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    // EmailProtection has no separate Start() method; the module
                    // is fully operational once Initialize() returns true.
                    // Real-time hooks and client adapters are armed inside
                    // Initialize() itself.
                    return true;
                },

                .shutdown = []() noexcept {
                    try {
                        EmailProtection::Instance().Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"EmailProtection: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"EmailProtection: Shutdown() threw unknown exception");
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
const EmailProtectionRegistrar g_emailProtectionRegistrar{};

}  // namespace
