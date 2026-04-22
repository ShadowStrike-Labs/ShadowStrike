/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - WEB PROTECTION WIRING
 * ============================================================================
 *
 * @file WebProtectionWiring.cpp
 * @brief Registers every WebProtection sub-module with HomeProductOrchestrator
 *        via static initialization, before main() runs.
 *
 * Modules registered (phase CoreProtections, gate "Home/Web/Enabled"):
 *   1. SafeBrowsingAPI          - cloud-backed URL/hash reputation
 *   2. PhishingDetector         - heuristic + ML phishing analysis
 *   3. AdBlocker                - network-level ad/tracker filter
 *   4. TrackerBlocker           - cross-site tracker enforcement
 *   5. BrowserProtection        - in-browser navigation/download control
 *   6. MaliciousDownloadBlocker - download-dir scanning & monitoring
 *   7. ChromeExtensionScanner   - Chromium-based extension auditing
 *   8. FirefoxAddonScanner      - Firefox/Gecko addon auditing
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "pch.h"

#include "../HomeProductOrchestrator.hpp"
#include "../../../../PhantomCore/Utils/Logger.hpp"

#include "SafeBrowsingAPI.hpp"
#include "PhishingDetector.hpp"
#include "AdBlocker.hpp"
#include "TrackerBlocker.hpp"
#include "BrowserProtection.hpp"
#include "MaliciousDownloadBlocker.hpp"
#include "ChromeExtensionScanner.hpp"
#include "FirefoxAddonScanner.hpp"

namespace {

constexpr const wchar_t* kCat = L"WebProtectionWiring";
constexpr const char*    kConfigKey = "Home/Web/Enabled";

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
                L"RegisterModule rejected a WebProtection descriptor "
                L"(duplicate name or null callback)");
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kCat,
            L"RegisterModule threw during WebProtection wiring: %hs", e.what());
    } catch (...) {
        SS_LOG_ERROR(kCat,
            L"RegisterModule threw unknown exception during WebProtection wiring");
    }
}

// ---------------------------------------------------------------------------
// Static registrar
// ---------------------------------------------------------------------------
struct WebProtectionRegistrar final {
    WebProtectionRegistrar() noexcept {
        using ::ShadowStrike::Products::Home::ModuleDescriptor;
        using ::ShadowStrike::Products::Home::ModulePhase;
        using namespace ::ShadowStrike::WebBrowser;

        // ------------------------------------------------------------------
        // 1. SafeBrowsingAPI
        //    Initialize(): loads local bloom filter & opens HTTP client.
        //    No separate start thread – URL lookups are driven by callers.
        // ------------------------------------------------------------------
        SafeRegister(ModuleDescriptor{
            .name            = "SafeBrowsingAPI",
            .enabledConfigKey = kConfigKey,
            .phase           = ModulePhase::CoreProtections,
            .initialize      = []() noexcept -> bool {
                try {
                    SafeBrowsingConfig config{};
                    config.enableCloudLookups = false;
                    config.enableTelemetry = false;
                    return SafeBrowsingAPI::Instance().Initialize(config);
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"SafeBrowsingAPI::Initialize threw: %hs", e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"SafeBrowsingAPI::Initialize threw unknown exception");
                    return false;
                }
            },
            .start           = []() noexcept -> bool {
                return SafeBrowsingAPI::Instance().IsInitialized();
            },
            .shutdown        = []() noexcept {
                try {
                    SafeBrowsingAPI::Instance().Shutdown();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"SafeBrowsingAPI::Shutdown threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"SafeBrowsingAPI::Shutdown threw unknown exception");
                }
            }
        });

        // ------------------------------------------------------------------
        // 2. PhishingDetector
        // ------------------------------------------------------------------
        SafeRegister(ModuleDescriptor{
            .name            = "PhishingDetector",
            .enabledConfigKey = kConfigKey,
            .phase           = ModulePhase::CoreProtections,
            .initialize      = []() noexcept -> bool {
                try {
                    return PhishingDetector::Instance().Initialize();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"PhishingDetector::Initialize threw: %hs", e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"PhishingDetector::Initialize threw unknown exception");
                    return false;
                }
            },
            .start           = []() noexcept -> bool {
                return PhishingDetector::Instance().IsInitialized();
            },
            .shutdown        = []() noexcept {
                try {
                    PhishingDetector::Instance().Shutdown();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"PhishingDetector::Shutdown threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"PhishingDetector::Shutdown threw unknown exception");
                }
            }
        });

        // ------------------------------------------------------------------
        // 3. AdBlocker
        // ------------------------------------------------------------------
        SafeRegister(ModuleDescriptor{
            .name            = "AdBlocker",
            .enabledConfigKey = kConfigKey,
            .phase           = ModulePhase::CoreProtections,
            .initialize      = []() noexcept -> bool {
                try {
                    return AdBlocker::Instance().Initialize();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"AdBlocker::Initialize threw: %hs", e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"AdBlocker::Initialize threw unknown exception");
                    return false;
                }
            },
            .start           = []() noexcept -> bool {
                return AdBlocker::Instance().IsInitialized();
            },
            .shutdown        = []() noexcept {
                try {
                    AdBlocker::Instance().Shutdown();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"AdBlocker::Shutdown threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"AdBlocker::Shutdown threw unknown exception");
                }
            }
        });

        // ------------------------------------------------------------------
        // 4. TrackerBlocker
        // ------------------------------------------------------------------
        SafeRegister(ModuleDescriptor{
            .name            = "TrackerBlocker",
            .enabledConfigKey = kConfigKey,
            .phase           = ModulePhase::CoreProtections,
            .initialize      = []() noexcept -> bool {
                try {
                    return TrackerBlocker::Instance().Initialize();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"TrackerBlocker::Initialize threw: %hs", e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"TrackerBlocker::Initialize threw unknown exception");
                    return false;
                }
            },
            .start           = []() noexcept -> bool {
                return TrackerBlocker::Instance().IsInitialized();
            },
            .shutdown        = []() noexcept {
                try {
                    TrackerBlocker::Instance().Shutdown();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"TrackerBlocker::Shutdown threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"TrackerBlocker::Shutdown threw unknown exception");
                }
            }
        });

        // ------------------------------------------------------------------
        // 5. BrowserProtection
        //    start  → StartNativeMessaging() (spawns messaging host thread)
        //    shutdown → StopNativeMessaging() then Shutdown()
        // ------------------------------------------------------------------
        SafeRegister(ModuleDescriptor{
            .name            = "BrowserProtection",
            .enabledConfigKey = kConfigKey,
            .phase           = ModulePhase::CoreProtections,
            .initialize      = []() noexcept -> bool {
                try {
                    return BrowserProtection::Instance().Initialize();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"BrowserProtection::Initialize threw: %hs", e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"BrowserProtection::Initialize threw unknown exception");
                    return false;
                }
            },
            .start           = []() noexcept -> bool {
                try {
                    return BrowserProtection::Instance().StartNativeMessaging();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"BrowserProtection::StartNativeMessaging threw: %hs",
                        e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"BrowserProtection::StartNativeMessaging threw unknown exception");
                    return false;
                }
            },
            .shutdown        = []() noexcept {
                try {
                    BrowserProtection::Instance().StopNativeMessaging();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"BrowserProtection::StopNativeMessaging threw: %hs",
                        e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"BrowserProtection::StopNativeMessaging threw unknown exception");
                }
                try {
                    BrowserProtection::Instance().Shutdown();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"BrowserProtection::Shutdown threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"BrowserProtection::Shutdown threw unknown exception");
                }
            }
        });

        // ------------------------------------------------------------------
        // 6. MaliciousDownloadBlocker
        //    start  → StartMonitoring() (watches download directories)
        //    shutdown → StopMonitoring() then Shutdown()
        // ------------------------------------------------------------------
        SafeRegister(ModuleDescriptor{
            .name            = "MaliciousDownloadBlocker",
            .enabledConfigKey = kConfigKey,
            .phase           = ModulePhase::CoreProtections,
            .initialize      = []() noexcept -> bool {
                try {
                    return MaliciousDownloadBlocker::Instance().Initialize();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"MaliciousDownloadBlocker::Initialize threw: %hs",
                        e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"MaliciousDownloadBlocker::Initialize threw unknown exception");
                    return false;
                }
            },
            .start           = []() noexcept -> bool {
                try {
                    return MaliciousDownloadBlocker::Instance().StartMonitoring();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"MaliciousDownloadBlocker::StartMonitoring threw: %hs",
                        e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"MaliciousDownloadBlocker::StartMonitoring threw unknown exception");
                    return false;
                }
            },
            .shutdown        = []() noexcept {
                try {
                    MaliciousDownloadBlocker::Instance().StopMonitoring();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"MaliciousDownloadBlocker::StopMonitoring threw: %hs",
                        e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"MaliciousDownloadBlocker::StopMonitoring threw unknown exception");
                }
                try {
                    MaliciousDownloadBlocker::Instance().Shutdown();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"MaliciousDownloadBlocker::Shutdown threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"MaliciousDownloadBlocker::Shutdown threw unknown exception");
                }
            }
        });

        // ------------------------------------------------------------------
        // 7. ChromeExtensionScanner
        // ------------------------------------------------------------------
        SafeRegister(ModuleDescriptor{
            .name            = "ChromeExtensionScanner",
            .enabledConfigKey = kConfigKey,
            .phase           = ModulePhase::CoreProtections,
            .initialize      = []() noexcept -> bool {
                try {
                    return ChromeExtensionScanner::Instance().Initialize();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"ChromeExtensionScanner::Initialize threw: %hs", e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"ChromeExtensionScanner::Initialize threw unknown exception");
                    return false;
                }
            },
            .start           = []() noexcept -> bool {
                return ChromeExtensionScanner::Instance().IsInitialized();
            },
            .shutdown        = []() noexcept {
                try {
                    ChromeExtensionScanner::Instance().Shutdown();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"ChromeExtensionScanner::Shutdown threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"ChromeExtensionScanner::Shutdown threw unknown exception");
                }
            }
        });

        // ------------------------------------------------------------------
        // 8. FirefoxAddonScanner
        // ------------------------------------------------------------------
        SafeRegister(ModuleDescriptor{
            .name            = "FirefoxAddonScanner",
            .enabledConfigKey = kConfigKey,
            .phase           = ModulePhase::CoreProtections,
            .initialize      = []() noexcept -> bool {
                try {
                    return FirefoxAddonScanner::Instance().Initialize();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"FirefoxAddonScanner::Initialize threw: %hs", e.what());
                    return false;
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"FirefoxAddonScanner::Initialize threw unknown exception");
                    return false;
                }
            },
            .start           = []() noexcept -> bool {
                return FirefoxAddonScanner::Instance().IsInitialized();
            },
            .shutdown        = []() noexcept {
                try {
                    FirefoxAddonScanner::Instance().Shutdown();
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(kCat,
                        L"FirefoxAddonScanner::Shutdown threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kCat,
                        L"FirefoxAddonScanner::Shutdown threw unknown exception");
                }
            }
        });
    }
};

// Namespace-scope object drives static initialization before main().
const WebProtectionRegistrar g_webProtectionRegistrar{};

}  // namespace

// ---------------------------------------------------------------------------
// Keep-alive anchor — prevents MSVC /OPT:REF + LTCG from dropping this TU in
// Release builds. The global registrar has internal linkage, so without an
// external-linkage symbol referenced from another TU the linker can elide the
// whole object. WiringAnchor.cpp takes the address of this function.
// ---------------------------------------------------------------------------
extern "C" void PhantomHome_KeepAlive_WebProtection() noexcept {}
