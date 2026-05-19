/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - CERTIFICATE PINNING MODULE WIRING
 * ============================================================================
 *
 * @file CertificatePinningWiring.cpp
 * @brief Registers the CertificatePinning module with the
 *        HomeProductOrchestrator.
 *
 * CertificatePinning enforces TLS certificate pinning for a curated set of
 * financial domains by intercepting WinHTTP and WinInet certificate-validation
 * callbacks.  All hooks are installed during Initialize(); there is no separate
 * Start() method on this class.  The wiring start() callback therefore returns
 * true immediately, consistent with the SecureBrowser facade pattern.
 *
 * The module is placed in the CoreProtections phase (phase 1) and gated by
 * "Home/Banking/Enabled".
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "pch.h"

#include "../../HomeProductOrchestrator.hpp"
#include "../CertificatePinning.hpp"
#include "../../ModeThresholds.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"CertificatePinningWiring";

struct CertificatePinningRegistrar final {
    CertificatePinningRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Banking::CertificatePinning;
            using ::ShadowStrike::Products::Home::ProtectionMode;
            using ::ShadowStrike::Products::Home::ProtectionModeMask;
            using ::ShadowStrike::Products::Home::ApplyModeThresholds;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "CertificatePinning",
                .enabledConfigKey = "Home/Banking/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        if (!CertificatePinning::Instance().Initialize()) {
                            SS_LOG_ERROR(kLogCategory,
                                L"CertificatePinning: Initialize() returned false");
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CertificatePinning: Initialize() threw: %S", e.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CertificatePinning: Initialize() threw unknown exception");
                        return false;
                    }
                },

                // CertificatePinning installs its WinHTTP/WinInet hooks inside
                // Initialize(); no background work to start separately.
                .start = []() -> bool {
                    return true;
                },

                .shutdown = []() noexcept {
                    try {
                        CertificatePinning::Instance().Shutdown();
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CertificatePinning: Shutdown() threw: %S", e.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CertificatePinning: Shutdown() threw unknown exception");
                    }
                },

                .setMode = [](ProtectionMode mode) -> bool {
                    using ::ShadowStrike::Banking::PinningMode;
                    PinningMode pinMode = PinningMode::Enforce;
                    switch (mode) {
                        case ProtectionMode::Passive:
                            pinMode = PinningMode::ReportOnly;
                            break;
                        case ProtectionMode::Balanced:
                            pinMode = PinningMode::Enforce;
                            break;
                        case ProtectionMode::Aggressive:
                            pinMode = PinningMode::Strict;
                            break;
                        case ProtectionMode::Off:
                            SS_LOG_ERROR(kLogCategory,
                                L"CertificatePinning: setMode(Off) must be routed through orchestrator disable");
                            return false;
                    }
                    auto& pinning = CertificatePinning::Instance();
                    auto config = pinning.GetConfiguration();
                    config.mode = pinMode;
                    config.enableCTChecking = true;
                    config.enableRevocationChecking = true;
                    config.allowRevocationSoftFail = (mode == ProtectionMode::Passive);
                    config.blockWeakSignatures = (mode != ProtectionMode::Passive);

                    if (!pinning.UpdateConfiguration(config)) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CertificatePinning: UpdateConfiguration rejected mode=%u",
                            static_cast<unsigned>(mode));
                        return false;
                    }
                    return ApplyModeThresholds("CertificatePinning", mode);
                },

                .supportedModesMask =
                    ProtectionModeMask(ProtectionMode::Off)        |
                    ProtectionModeMask(ProtectionMode::Passive)    |
                    ProtectionModeMask(ProtectionMode::Balanced)   |
                    ProtectionModeMask(ProtectionMode::Aggressive)
            });
        } catch (...) {
            ::OutputDebugStringW(
                L"CertificatePinningWiring: static registration failed\n");
        }
    }
};

const CertificatePinningRegistrar g_certificatePinningRegistrar{};

}  // namespace

// ---------------------------------------------------------------------------
// Keep-alive anchor — prevents MSVC /OPT:REF + LTCG from dropping this TU in
// Release builds. The global registrar has internal linkage, so without an
// external-linkage symbol referenced from another TU the linker can elide the
// whole object. WiringAnchor.cpp takes the address of this function.
// ---------------------------------------------------------------------------
extern "C" void PhantomHome_KeepAlive_CertificatePinning() noexcept {}
