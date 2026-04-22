/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ZeroTrustWiring.cpp
 * @brief Registers the Zero-Trust Execution Guard with HomeProductOrchestrator.
 *
 * Registration pattern:
 *   A namespace-scope static object (ZeroTrustModuleRegistrar) is constructed
 *   before main(), triggering RegisterModule() on the orchestrator singleton.
 *   An extern "C" keep-alive function (PhantomHome_KeepAlive_ZeroTrust) is
 *   referenced from WiringAnchor.cpp so the linker cannot prune this TU under
 *   /OPT:REF + LTCG.
 *
 * Also provides:
 *   - Implementation of CreateZeroTrustModuleDescriptor() declared in
 *     PhantomCore/RealTime/ZeroTrust/ZeroTrustWiring.hpp, used internally by
 *     the PhantomCore engine if it needs to self-register.
 *   - InstallDefaults(): explicit startup hook for deterministic initialization
 *     ordering when ConfigManager is already live.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#include "ZeroTrustWiring.hpp"

#include "../ZeroTrustGuard.hpp"
#include "../ZeroTrustPromptQueue.hpp"

#include "../../HomeProductOrchestrator.hpp"
#include "../../ModeThresholds.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"
#include "../../../../../PhantomCore/Config/ConfigManager.hpp"
#include "../../../../../PhantomCore/RealTime/ZeroTrust/ZeroTrustWiring.hpp"
#include "../../../../../PhantomCore/RealTime/ZeroTrust/ZeroTrustGuard.hpp"

#include <atomic>
#include <exception>
#include <stdexcept>

namespace {

constexpr const wchar_t* kLogCategory   = L"ZeroTrustWiring";
constexpr const char*    kModuleName    = "ZeroTrustGuard";
constexpr const char*    kDisplayName   = "Zero-Trust Execution Guard";
constexpr const char*    kEnabledKey    = "Home/ZeroTrust/Enabled";
constexpr const char*    kModuleGroup   = "Realtime";

// Tracks whether InstallDefaults() has already run.
std::atomic<bool> g_defaultsInstalled{false};

} // anonymous namespace

// ============================================================================
// CreateZeroTrustModuleDescriptor
// (implements the declaration in PhantomCore/RealTime/ZeroTrust/ZeroTrustWiring.hpp)
// ============================================================================

namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust {

[[nodiscard]] ::ShadowStrike::Products::Home::ModuleDescriptor
CreateZeroTrustModuleDescriptor()
{
    using ::ShadowStrike::Products::Home::ModuleDescriptor;
    using ::ShadowStrike::Products::Home::ModulePhase;
    using ::ShadowStrike::Products::Home::ProtectionMode;
    using ::ShadowStrike::Products::Home::ProtectionModeMask;
    using ::ShadowStrike::Products::Home::ApplyModeThresholds;
    using HomeGuard = ::ShadowStrike::Products::Home::ZeroTrust::ZeroTrustGuard;

    ModuleDescriptor desc;
    desc.name             = kModuleName;
    desc.displayName      = kDisplayName;
    desc.group            = kModuleGroup;
    desc.enabledConfigKey = kEnabledKey;
    desc.phase            = ModulePhase::CoreProtections;
    desc.supportedModesMask =
        ProtectionModeMask(ProtectionMode::Off)        |
        ProtectionModeMask(ProtectionMode::Passive)    |
        ProtectionModeMask(ProtectionMode::Balanced)   |
        ProtectionModeMask(ProtectionMode::Aggressive);

    desc.initialize = []() -> bool {
        try {
            return HomeGuard::Instance().Initialize();
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(kLogCategory,
                L"ZeroTrustGuard: Initialize() threw: %hs", ex.what());
            return false;
        } catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"ZeroTrustGuard: Initialize() threw unknown exception");
            return false;
        }
    };

    desc.start = []() -> bool {
        try {
            return HomeGuard::Instance().Start();
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(kLogCategory,
                L"ZeroTrustGuard: Start() threw: %hs", ex.what());
            return false;
        } catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"ZeroTrustGuard: Start() threw unknown exception");
            return false;
        }
    };

    desc.shutdown = []() noexcept {
        try {
            HomeGuard::Instance().Shutdown();
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(kLogCategory,
                L"ZeroTrustGuard: Shutdown() threw: %hs", ex.what());
        } catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"ZeroTrustGuard: Shutdown() threw unknown exception");
        }
    };

    desc.setMode = [](ProtectionMode mode) -> bool {
        try {
            // Apply canonical ModeThresholds keys to ConfigManager so other
            // subscribers (IPC, telemetry) see consistent values.
            if (mode != ProtectionMode::Off) {
                if (!ApplyModeThresholds("ZeroTrust", mode)) {
                    SS_LOG_WARN(kLogCategory,
                        L"ZeroTrustGuard: ApplyModeThresholds() failed for mode %hhu; "
                        L"continuing with in-memory update",
                        static_cast<std::uint8_t>(mode));
                    // Non-fatal: in-memory transition still applies.
                }
            }
            HomeGuard::Instance().SetMode(mode);
            return true;
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(kLogCategory,
                L"ZeroTrustGuard: SetMode() threw: %hs", ex.what());
            return false;
        } catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"ZeroTrustGuard: SetMode() threw unknown exception");
            return false;
        }
    };

    return desc;
}

} // namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust

// ============================================================================
// PhantomHome wiring functions
// ============================================================================

namespace ShadowStrike::Products::Home::ZeroTrust {

void RegisterZeroTrustGuard(HomeProductOrchestrator& orch) {
    if (!orch.RegisterModule(
            ::ShadowStrike::PhantomCore::RealTime::ZeroTrust::
                CreateZeroTrustModuleDescriptor())) {
        SS_LOG_ERROR(kLogCategory,
            L"ZeroTrustWiring: RegisterModule(ZeroTrustGuard) failed — "
            L"duplicate registration or null callbacks");
    }
}

void InstallDefaults() {
    bool expected = false;
    if (!g_defaultsInstalled.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        return; // Already installed.
    }

    SS_LOG_INFO(kLogCategory, L"ZeroTrustWiring: Installing defaults");

    if (!::ShadowStrike::Config::ConfigManager::HasInstance()) {
        SS_LOG_WARN(kLogCategory,
            L"ZeroTrustWiring: ConfigManager unavailable — "
            L"skipping persisted config load; Balanced defaults apply");
        return;
    }

    auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
    using Layer = ::ShadowStrike::Config::ConfigLayer;

    // Only set keys that don't already have a user-layer value, so we don't
    // clobber existing user configuration on service restart.
    auto setDefault = [&](const char* key, auto defaultVal) {
        const auto existing = cfg.GetValueFromLayer<decltype(defaultVal)>(key, Layer::User);
        if (!existing.has_value()) {
            if (!cfg.SetValue(key, defaultVal, Layer::User)) {
                SS_LOG_WARN(kLogCategory,
                    L"ZeroTrustWiring: Failed to write default for key '%hs'", key);
            }
        }
    };

    setDefault("Home/ZeroTrust/Enabled",                true);
    setDefault("Home/ZeroTrust/Threshold",              0.70);
    setDefault("Home/ZeroTrust/UncertainBand",          0.05);
    setDefault("Home/ZeroTrust/ZeroTrustMode",          false);
    setDefault("Home/ZeroTrust/UncertainBehavior",      static_cast<int32_t>(2)); // Prompt
    setDefault("Home/ZeroTrust/RequirePublisherSigned", false);
    setDefault("Home/ZeroTrust/RequireWhitelist",       false);
    setDefault("Home/ZeroTrust/MinReputation",          0.0);
    setDefault("Home/ZeroTrust/MinStaticBenign",        0.0);

    SS_LOG_INFO(kLogCategory,
        L"ZeroTrustWiring: Balanced defaults installed (threshold=0.70, behavior=Prompt)");
}

} // namespace ShadowStrike::Products::Home::ZeroTrust

// ============================================================================
// Namespace-scope registrar (runs before main())
// ============================================================================

namespace {

struct ZeroTrustModuleRegistrar final {
    ZeroTrustModuleRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ZeroTrust::RegisterZeroTrustGuard;

            RegisterZeroTrustGuard(HomeProductOrchestrator::Instance());
        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

const ZeroTrustModuleRegistrar g_zeroTrustModuleRegistrar{};

} // anonymous namespace

// ============================================================================
// Keep-alive anchor — prevents MSVC /OPT:REF + LTCG from dropping this TU.
// Referenced from WiringAnchor.cpp.
// ============================================================================
extern "C" void PhantomHome_KeepAlive_ZeroTrust() noexcept {}
