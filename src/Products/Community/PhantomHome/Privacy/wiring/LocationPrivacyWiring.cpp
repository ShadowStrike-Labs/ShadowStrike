/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "pch.h"

#include "../../HomeProductOrchestrator.hpp"
#include "../LocationPrivacy.hpp"
#include "../../ModeThresholds.hpp"
#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"LocationPrivacyWiring";
using Module = ::ShadowStrike::Privacy::LocationPrivacy;

[[nodiscard]] bool ValidateInitialized(const wchar_t* operation) {
    if (!Module::HasInstance()) {
        SS_LOG_ERROR(kLogCategory, L"LocationPrivacy: %ls called before instance creation", operation);
        return false;
    }

    auto& module = Module::Instance();
    if (!module.IsInitialized()) {
        SS_LOG_ERROR(kLogCategory, L"LocationPrivacy: %ls called while module is not initialized", operation);
        return false;
    }

    return true;
}

void SafeShutdown() noexcept {
    if (!Module::HasInstance()) {
        return;
    }

    try {
        auto& module = Module::Instance();
            if (module.IsInitialized()) {
                module.Shutdown();
            }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCategory, L"LocationPrivacy: shutdown cleanup threw: %hs", e.what());
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"LocationPrivacy: shutdown cleanup threw unknown exception");
    }
}

struct Registrar final {
    Registrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;
            using ::ShadowStrike::Products::Home::ProtectionMode;
            using ::ShadowStrike::Products::Home::ProtectionModeMask;
            using ::ShadowStrike::Products::Home::ApplyModeThresholds;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "LocationPrivacy",
                .enabledConfigKey = "Home/Privacy/Enabled",
                .phase            = ModulePhase::OnDemand,

                .initialize = []() -> bool {
                    try {
                        if (Module::HasInstance()) {
                            auto& existingModule = Module::Instance();
                            if (existingModule.IsInitialized()) {
                                return true;
                            }
                            const auto status = existingModule.GetStatus();
                            if (status != ::ShadowStrike::Privacy::ModuleStatus::Uninitialized &&
                                status != ::ShadowStrike::Privacy::ModuleStatus::Stopped) {
                                SS_LOG_ERROR(kLogCategory,
                                    L"LocationPrivacy: initialize() rejected while status is %hs",
                                    ::ShadowStrike::Privacy::GetModuleStatusName(status).data());
                                return false;
                            }
                        }
                        auto& module = Module::Instance();
                        if (!module.Initialize()) {
                            SS_LOG_ERROR(kLogCategory, L"LocationPrivacy: Initialize() returned false");
                            SafeShutdown();
                            return false;
                        }
                        if (!module.IsInitialized()) {
                            SS_LOG_ERROR(kLogCategory, L"LocationPrivacy: Initialize() completed without entering initialized state");
                            SafeShutdown();
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SafeShutdown();
                        SS_LOG_ERROR(kLogCategory, L"LocationPrivacy: initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SafeShutdown();
                        SS_LOG_ERROR(kLogCategory, L"LocationPrivacy: initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    return ValidateInitialized(L"start");
                },
                .shutdown = []() noexcept {
                    SafeShutdown();
                },

                .setMode = [](ProtectionMode mode) -> bool {
                    using MMode = ::ShadowStrike::Privacy::LocationProtectionMode;
                    MMode mapped = MMode::WhitelistOnly;
                    switch (mode) {
                        case ProtectionMode::Passive:    mapped = MMode::Monitor;       break;
                        case ProtectionMode::Balanced:   mapped = MMode::WhitelistOnly; break;
                        case ProtectionMode::Aggressive: mapped = MMode::BlockAll;      break;
                        default: break;
                    }
                    if (Module::HasInstance()) {
                        Module::Instance().SetProtectionMode(mapped);
                    }
                    return ApplyModeThresholds("LocationPrivacy", mode);
                },

                .supportedModesMask =
                    ProtectionModeMask(ProtectionMode::Off)        |
                    ProtectionModeMask(ProtectionMode::Passive)    |
                    ProtectionModeMask(ProtectionMode::Balanced)   |
                    ProtectionModeMask(ProtectionMode::Aggressive)
            });
        } catch (...) {
            // Static initializer path: logger may not yet be available.
        }
    }
};

const Registrar g_registrar{};

}  // namespace

// ---------------------------------------------------------------------------
// Keep-alive anchor — prevents MSVC /OPT:REF + LTCG from dropping this TU in
// Release builds. The global registrar has internal linkage, so without an
// external-linkage symbol referenced from another TU the linker can elide the
// whole object. WiringAnchor.cpp takes the address of this function.
// ---------------------------------------------------------------------------
extern "C" void PhantomHome_KeepAlive_LocationPrivacy() noexcept {}