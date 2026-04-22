/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - USB PROTECTION WIRING
 * ============================================================================
 *
 * @file USBWiring.cpp
 * @brief Registers every USB_Protection sub-module with HomeProductOrchestrator
 *        via static initialization, before main() runs.
 *
 * Modules registered (phase CoreProtections, gate "Home/USB/Enabled"):
 *   1. DeviceControlManager - policy evaluation and device access control
 *   2. BadUSBDetector        - HID/firmware attack detection
 *   3. USBAutorunBlocker     - autorun.inf and LNK attack suppression
 *   4. USBDeviceMonitor      - real-time device attach/detach surveillance
 *   5. USBScanner            - on-insert malware scan of drive contents
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "pch.h"

#include "../HomeProductOrchestrator.hpp"
#include "../../../../PhantomCore/Utils/Logger.hpp"

#include "DeviceControlManager.hpp"
#include "BadUSBDetector.hpp"
#include "USBAutorunBlocker.hpp"
#include "USBDeviceMonitor.hpp"
#include "USBScanner.hpp"

namespace {

constexpr const wchar_t* kCat = L"USBWiring";
constexpr const char*    kConfigKey = "Home/USB/Enabled";

// ---------------------------------------------------------------------------
// Helper: register one descriptor, absorb any exception so static init
// never propagates through the C++ runtime.
// ---------------------------------------------------------------------------
void SafeRegister(
    ::ShadowStrike::Products::Home::ModuleDescriptor desc) noexcept
{
    try {
        if (!::ShadowStrike::Products::Home::HomeProductOrchestrator::Instance()
                .RegisterModule(std::move(desc)))
        {
            SS_LOG_ERROR(kCat,
                L"RegisterModule rejected a USB_Protection descriptor "
                L"(duplicate name or null callback)");
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kCat,
            L"RegisterModule threw during USB wiring: %hs", e.what());
    } catch (...) {
        SS_LOG_ERROR(kCat,
            L"RegisterModule threw unknown exception during USB wiring");
    }
}

// ---------------------------------------------------------------------------
// Static registrar
// ---------------------------------------------------------------------------
struct USBRegistrar final {
    USBRegistrar() noexcept {
        using ::ShadowStrike::Products::Home::ModuleDescriptor;
        using ::ShadowStrike::Products::Home::ModulePhase;
        using namespace ::ShadowStrike::USB;

        // ------------------------------------------------------------------
        // 1. DeviceControlManager
        //    Evaluates allow/block policy before the OS mounts a device.
        //    Must be initialized before the monitor and scanner so that
        //    policy is in effect when the first attach event fires.
        // ------------------------------------------------------------------
        SafeRegister(ModuleDescriptor{
            .name            = "DeviceControlManager",
            .enabledConfigKey = kConfigKey,
            .phase           = ModulePhase::CoreProtections,
            .initialize      = []() noexcept -> bool {
                try {
                    return DeviceControlManager::Instance().Initialize();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"DeviceControlManager::Initialize threw: %hs", e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"DeviceControlManager::Initialize threw unknown exception");
                    return false;
                }
            },
            .start           = []() noexcept -> bool {
                return true;
            },
            .shutdown        = []() noexcept {
                try {
                    DeviceControlManager::Instance().Shutdown();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"DeviceControlManager::Shutdown threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"DeviceControlManager::Shutdown threw unknown exception");
                }
            }
        });

        // ------------------------------------------------------------------
        // 2. BadUSBDetector
        //    Analyzes USB device descriptors for HID/rubber-ducky patterns.
        // ------------------------------------------------------------------
        SafeRegister(ModuleDescriptor{
            .name            = "BadUSBDetector",
            .enabledConfigKey = kConfigKey,
            .phase           = ModulePhase::CoreProtections,
            .initialize      = []() noexcept -> bool {
                try {
                    return BadUSBDetector::Instance().Initialize();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"BadUSBDetector::Initialize threw: %hs", e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"BadUSBDetector::Initialize threw unknown exception");
                    return false;
                }
            },
            .start           = []() noexcept -> bool {
                return true;
            },
            .shutdown        = []() noexcept {
                try {
                    BadUSBDetector::Instance().Shutdown();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"BadUSBDetector::Shutdown threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"BadUSBDetector::Shutdown threw unknown exception");
                }
            }
        });

        // ------------------------------------------------------------------
        // 3. USBAutorunBlocker
        //    Suppresses autorun.inf execution and weaponized LNK files.
        // ------------------------------------------------------------------
        SafeRegister(ModuleDescriptor{
            .name            = "USBAutorunBlocker",
            .enabledConfigKey = kConfigKey,
            .phase           = ModulePhase::CoreProtections,
            .initialize      = []() noexcept -> bool {
                try {
                    return USBAutorunBlocker::Instance().Initialize();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"USBAutorunBlocker::Initialize threw: %hs", e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"USBAutorunBlocker::Initialize threw unknown exception");
                    return false;
                }
            },
            .start           = []() noexcept -> bool {
                return true;
            },
            .shutdown        = []() noexcept {
                try {
                    USBAutorunBlocker::Instance().Shutdown();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"USBAutorunBlocker::Shutdown threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"USBAutorunBlocker::Shutdown threw unknown exception");
                }
            }
        });

        // ------------------------------------------------------------------
        // 4. USBDeviceMonitor
        //    start  → StartMonitoring() (registers WM_DEVICECHANGE hook)
        //    shutdown → StopMonitoring() then Shutdown()
        // ------------------------------------------------------------------
        SafeRegister(ModuleDescriptor{
            .name            = "USBDeviceMonitor",
            .enabledConfigKey = kConfigKey,
            .phase           = ModulePhase::CoreProtections,
            .initialize      = []() noexcept -> bool {
                try {
                    return USBDeviceMonitor::Instance().Initialize();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"USBDeviceMonitor::Initialize threw: %hs", e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"USBDeviceMonitor::Initialize threw unknown exception");
                    return false;
                }
            },
            .start           = []() noexcept -> bool {
                try {
                    return USBDeviceMonitor::Instance().StartMonitoring();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"USBDeviceMonitor::StartMonitoring threw: %hs", e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"USBDeviceMonitor::StartMonitoring threw unknown exception");
                    return false;
                }
            },
            .shutdown        = []() noexcept {
                try {
                    USBDeviceMonitor::Instance().StopMonitoring();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"USBDeviceMonitor::StopMonitoring threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"USBDeviceMonitor::StopMonitoring threw unknown exception");
                }
                try {
                    USBDeviceMonitor::Instance().Shutdown();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"USBDeviceMonitor::Shutdown threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"USBDeviceMonitor::Shutdown threw unknown exception");
                }
            }
        });

        // ------------------------------------------------------------------
        // 5. USBScanner
        //    Performs on-insert deep scan of drive contents.
        // ------------------------------------------------------------------
        SafeRegister(ModuleDescriptor{
            .name            = "USBScanner",
            .enabledConfigKey = kConfigKey,
            .phase           = ModulePhase::CoreProtections,
            .initialize      = []() noexcept -> bool {
                try {
                    return USBScanner::Instance().Initialize();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"USBScanner::Initialize threw: %hs", e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"USBScanner::Initialize threw unknown exception");
                    return false;
                }
            },
            .start           = []() noexcept -> bool {
                return true;
            },
            .shutdown        = []() noexcept {
                try {
                    USBScanner::Instance().Shutdown();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"USBScanner::Shutdown threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"USBScanner::Shutdown threw unknown exception");
                }
            }
        });
    }
};

// Namespace-scope object drives static initialization before main().
const USBRegistrar g_usbRegistrar{};

}  // namespace

// ---------------------------------------------------------------------------
// Keep-alive anchor — prevents MSVC /OPT:REF + LTCG from dropping this TU in
// Release builds. The global registrar has internal linkage, so without an
// external-linkage symbol referenced from another TU the linker can elide the
// whole object. WiringAnchor.cpp takes the address of this function.
// ---------------------------------------------------------------------------
extern "C" void PhantomHome_KeepAlive_USBProtection() noexcept {}
