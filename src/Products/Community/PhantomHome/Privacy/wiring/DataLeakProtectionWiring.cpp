/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "pch.h"

#include "../../HomeProductOrchestrator.hpp"
#include "../DataLeakProtection.hpp"
#include "../../../../../PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogCategory = L"DataLeakProtectionWiring";
using Module = ::ShadowStrike::Privacy::DataLeakProtection;

[[nodiscard]] bool ValidateInitialized(const wchar_t* operation) {
    if (!Module::HasInstance()) {
        SS_LOG_ERROR(kLogCategory, L"DataLeakProtection: %ls called before instance creation", operation);
        return false;
    }

    auto& module = Module::Instance();
    if (!module.IsInitialized()) {
        SS_LOG_ERROR(kLogCategory, L"DataLeakProtection: %ls called while module is not initialized", operation);
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
                module.StopClipboardMonitoring();
                module.Shutdown();
            }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCategory, L"DataLeakProtection: shutdown cleanup threw: %hs", e.what());
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"DataLeakProtection: shutdown cleanup threw unknown exception");
    }
}

struct Registrar final {
    Registrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;

            HomeProductOrchestrator::Instance().RegisterModule(ModuleDescriptor{
                .name             = "DataLeakProtection",
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
                                    L"DataLeakProtection: initialize() rejected while status is %hs",
                                    ::ShadowStrike::Privacy::GetModuleStatusName(status).data());
                                return false;
                            }
                        }
                        auto& module = Module::Instance();
                        if (!module.Initialize()) {
                            SS_LOG_ERROR(kLogCategory, L"DataLeakProtection: Initialize() returned false");
                            SafeShutdown();
                            return false;
                        }
                        if (!module.IsInitialized()) {
                            SS_LOG_ERROR(kLogCategory, L"DataLeakProtection: Initialize() completed without entering initialized state");
                            SafeShutdown();
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SafeShutdown();
                        SS_LOG_ERROR(kLogCategory, L"DataLeakProtection: initialize() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SafeShutdown();
                        SS_LOG_ERROR(kLogCategory, L"DataLeakProtection: initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    if (!ValidateInitialized(L"start")) {
                        return false;
                    }
                    try {
                        auto& module = Module::Instance();
                        if (!module.StartClipboardMonitoring()) {
                            SS_LOG_ERROR(kLogCategory, L"DataLeakProtection: StartClipboardMonitoring() returned false");
                            SafeShutdown();
                            return false;
                        }
                        return true;
                    } catch (const std::exception& e) {
                        SafeShutdown();
                        SS_LOG_ERROR(kLogCategory, L"DataLeakProtection: start() threw: %hs", e.what());
                        return false;
                    } catch (...) {
                        SafeShutdown();
                        SS_LOG_ERROR(kLogCategory, L"DataLeakProtection: start() threw unknown exception");
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

// ---------------------------------------------------------------------------
// Keep-alive anchor — prevents MSVC /OPT:REF + LTCG from dropping this TU in
// Release builds. The global registrar has internal linkage, so without an
// external-linkage symbol referenced from another TU the linker can elide the
// whole object. WiringAnchor.cpp takes the address of this function.
// ---------------------------------------------------------------------------
extern "C" void PhantomHome_KeepAlive_DataLeakProtection() noexcept {}