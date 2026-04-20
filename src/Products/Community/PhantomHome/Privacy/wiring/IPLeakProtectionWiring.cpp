/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "pch.h"

#include "../../HomeProductOrchestrator.hpp"
#include "../IPLeakProtection.hpp"
#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"IPLeakProtectionWiring";
using Module = ::ShadowStrike::Privacy::IPLeakProtection;

[[nodiscard]] bool ValidateInitialized(const wchar_t* operation) {
    if (!Module::HasInstance()) {
        SS_LOG_ERROR(kLogCategory, L"IPLeakProtection: %ls called before instance creation", operation);
        return false;
    }

    auto& module = Module::Instance();
    if (!module.IsInitialized()) {
        SS_LOG_ERROR(kLogCategory, L"IPLeakProtection: %ls called while module is not initialized", operation);
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
                module.StopVPNMonitoring();
                module.Shutdown();
            }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCategory, L"IPLeakProtection: shutdown cleanup threw: %hs", e.what());
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"IPLeakProtection: shutdown cleanup threw unknown exception");
    }
}

struct Registrar final {
    Registrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "PrivacyIPLeakProtection",
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
                                    L"IPLeakProtection: initialize() rejected while status is %hs",
                                    ::ShadowStrike::Privacy::GetModuleStatusName(status).data());
                                return false;
                            }
                        }
                        auto& module = Module::Instance();
                        if (!module.Initialize()) {
                            SS_LOG_ERROR(kLogCategory, L"IPLeakProtection: Initialize() returned false");
                            SafeShutdown();
                            return false;
                        }
                        if (!module.IsInitialized()) {
                            SS_LOG_ERROR(kLogCategory, L"IPLeakProtection: Initialize() completed without entering initialized state");
                            SafeShutdown();
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SafeShutdown();
                        SS_LOG_ERROR(kLogCategory, L"IPLeakProtection: initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SafeShutdown();
                        SS_LOG_ERROR(kLogCategory, L"IPLeakProtection: initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    if (!ValidateInitialized(L"start")) {
                        return false;
                    }
                    try {
                        auto& module = Module::Instance();
                        if (!module.StartVPNMonitoring()) {
                            SS_LOG_ERROR(kLogCategory, L"IPLeakProtection: StartVPNMonitoring() returned false");
                            SafeShutdown();
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SafeShutdown();
                        SS_LOG_ERROR(kLogCategory, L"IPLeakProtection: start() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SafeShutdown();
                        SS_LOG_ERROR(kLogCategory, L"IPLeakProtection: start() threw unknown exception");
                        return false;
                    }
                },
                .shutdown = []() noexcept {
                    SafeShutdown();
                }
            });
        } catch (...) {
            // Static initializer path: logger may not yet be available.
        }
    }
};

const Registrar g_registrar{};

}  // namespace
