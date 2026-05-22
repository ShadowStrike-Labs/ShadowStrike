/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ModuleCatalog.cpp
 * @brief Implementation of the PhantomHome UI module catalog.
 *
 * Module id strings MUST match the .name field passed to RegisterModule() in
 * the corresponding *Wiring.cpp file.  Any mismatch breaks the
 * orchestrator<->catalog mapping and will surface as an "unknown module"
 * warning in UI logs.
 *
 * supportedModesMask bit encoding (matches ProtectionModeMask in orchestrator):
 *   bit 0 = Off (1), bit 1 = Passive (2), bit 2 = Balanced (4), bit 3 = Aggressive (8)
 *
 * Common preset masks used below:
 *   kMaskOffBalanced   = 0x05  Off | Balanced             (default wiring default)
 *   kMaskFullSpectrum  = 0x0F  Off | Passive | Balanced | Aggressive
 *   kMaskNoPassive     = 0x0D  Off | Balanced | Aggressive (skip Passive)
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#include "ModuleCatalog.hpp"

#include "../../HomeProductOrchestrator.hpp"

#include "../../../../../PhantomCore/Utils/Logger.hpp"

#include <algorithm>

namespace ShadowStrike::Products::Home::UI {

// ============================================================================
// Internal constants
// ============================================================================

namespace {

constexpr const wchar_t* kLog = L"ModuleCatalog";

// supportedModesMask shorthand — must match HomeProductOrchestrator ProtectionModeMask().
constexpr std::uint8_t kMaskOffBalanced  = 0x05u;  // Off | Balanced
constexpr std::uint8_t kMaskFullSpectrum = 0x0Fu;  // Off | Passive | Balanced | Aggressive
constexpr std::uint8_t kMaskNoPassive    = 0x0Du;  // Off | Balanced | Aggressive

} // anonymous namespace

// ============================================================================
// ModuleCatalog construction — one entry per wiring file registration
// ============================================================================

ModuleCatalog::ModuleCatalog()
{
    // ---- RealtimeProtection -------------------------------------------------

    // AmsiProvider (src/Products/Community/PhantomHome/AmsiProvider/wiring/AmsiWiring.cpp)
    m_entries.push_back({
        .id              = "AmsiProvider",
        .displayNameKey  = "module.amsi.name",
        .descriptionKey  = "module.amsi.description",
        .iconId          = "Shield",
        .category        = ModuleCategory::RealtimeProtection,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // SafeBrowsingAPI (src/.../WebProtection/WebProtectionWiring.cpp)
    m_entries.push_back({
        .id              = "SafeBrowsingAPI",
        .displayNameKey  = "module.safebrowsing.name",
        .descriptionKey  = "module.safebrowsing.description",
        .iconId          = "Shield",
        .category        = ModuleCategory::RealtimeProtection,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // PhishingDetector (WebProtectionWiring.cpp)
    m_entries.push_back({
        .id              = "PhishingDetector",
        .displayNameKey  = "module.phishingdetector.name",
        .descriptionKey  = "module.phishingdetector.description",
        .iconId          = "Shield",
        .category        = ModuleCategory::RealtimeProtection,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // MaliciousDownloadBlocker (WebProtectionWiring.cpp)
    m_entries.push_back({
        .id              = "MaliciousDownloadBlocker",
        .displayNameKey  = "module.maldownloadblocker.name",
        .descriptionKey  = "module.maldownloadblocker.description",
        .iconId          = "Shield",
        .category        = ModuleCategory::RealtimeProtection,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // ---- BehavioralSecurity -------------------------------------------------

    // ZeroTrustGuard (src/.../ZeroTrustGuard/wiring/ZeroTrustWiring.cpp)
    m_entries.push_back({
        .id              = "ZeroTrustGuard",
        .displayNameKey  = "module.zerotrust.name",
        .descriptionKey  = "module.zerotrust.description",
        .iconId          = "Eye",
        .category        = ModuleCategory::BehavioralSecurity,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ZeroTrustDetailPage.qml",
        .premium         = false,
    });

    // NOTE: No BehaviorBlocker / BehaviorMonitor / PhantomSentry module was
    // found in any wiring file at the time of catalog population. If a future
    // wiring file registers such a module, add an entry here with:
    //   displayNameKey = "module.phantomsentry.name"
    //   descriptionKey = "module.phantomsentry.description"
    // (The backend id should remain whatever the wiring file uses; only the
    //  display keys must match the "PhantomSentry" branding requirement.)

    // ---- NetworkSecurity ----------------------------------------------------

    // NetworkAttackBlocker (src/.../NetworkAttackBlocker/wiring/NabWiring.cpp)
    m_entries.push_back({
        .id              = "NetworkAttackBlocker",
        .displayNameKey  = "module.nab.name",
        .descriptionKey  = "module.nab.description",
        .iconId          = "Lock",
        .category        = ModuleCategory::NetworkSecurity,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // DNSLeakProtection (Privacy/wiring/DNSLeakProtectionWiring.cpp)
    m_entries.push_back({
        .id              = "DNSLeakProtection",
        .displayNameKey  = "module.dnsleakprotection.name",
        .descriptionKey  = "module.dnsleakprotection.description",
        .iconId          = "Lock",
        .category        = ModuleCategory::NetworkSecurity,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // PrivacyIPLeakProtection (Privacy/wiring/IPLeakProtectionWiring.cpp)
    m_entries.push_back({
        .id              = "PrivacyIPLeakProtection",
        .displayNameKey  = "module.ipleakprotection.name",
        .descriptionKey  = "module.ipleakprotection.description",
        .iconId          = "Lock",
        .category        = ModuleCategory::NetworkSecurity,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // IoTIPLeakProtection (IoT/IoTWiring.cpp)
    m_entries.push_back({
        .id              = "IoTIPLeakProtection",
        .displayNameKey  = "module.iotipleak.name",
        .descriptionKey  = "module.iotipleak.description",
        .iconId          = "Lock",
        .category        = ModuleCategory::NetworkSecurity,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // WiFiSecurityAnalyzer (IoT/IoTWiring.cpp)
    m_entries.push_back({
        .id              = "WiFiSecurityAnalyzer",
        .displayNameKey  = "module.wifisecurity.name",
        .descriptionKey  = "module.wifisecurity.description",
        .iconId          = "Lock",
        .category        = ModuleCategory::NetworkSecurity,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // RouterSecurityChecker (IoT/IoTWiring.cpp)
    m_entries.push_back({
        .id              = "RouterSecurityChecker",
        .displayNameKey  = "module.routersecurity.name",
        .descriptionKey  = "module.routersecurity.description",
        .iconId          = "Lock",
        .category        = ModuleCategory::NetworkSecurity,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // PoolConnectionDetector (CryptoMiners/CryptoMinersWiring.cpp)
    // Positioned in Network because it monitors network-level mining pool traffic.
    m_entries.push_back({
        .id              = "PoolConnectionDetector",
        .displayNameKey  = "module.poolconnection.name",
        .descriptionKey  = "module.poolconnection.description",
        .iconId          = "Lock",
        .category        = ModuleCategory::NetworkSecurity,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // ---- WebAndEmail --------------------------------------------------------

    // AdBlocker (WebProtectionWiring.cpp)
    m_entries.push_back({
        .id              = "AdBlocker",
        .displayNameKey  = "module.adblocker.name",
        .descriptionKey  = "module.adblocker.description",
        .iconId          = "Globe",
        .category        = ModuleCategory::WebAndEmail,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // TrackerBlocker (WebProtectionWiring.cpp)
    m_entries.push_back({
        .id              = "TrackerBlocker",
        .displayNameKey  = "module.trackerblocker.name",
        .descriptionKey  = "module.trackerblocker.description",
        .iconId          = "Globe",
        .category        = ModuleCategory::WebAndEmail,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // BrowserProtection (WebProtectionWiring.cpp)
    m_entries.push_back({
        .id              = "BrowserProtection",
        .displayNameKey  = "module.browserprotection.name",
        .descriptionKey  = "module.browserprotection.description",
        .iconId          = "Globe",
        .category        = ModuleCategory::WebAndEmail,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // ChromeExtensionScanner (WebProtectionWiring.cpp)
    m_entries.push_back({
        .id              = "ChromeExtensionScanner",
        .displayNameKey  = "module.chromeextscanner.name",
        .descriptionKey  = "module.chromeextscanner.description",
        .iconId          = "Globe",
        .category        = ModuleCategory::WebAndEmail,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // FirefoxAddonScanner (WebProtectionWiring.cpp)
    m_entries.push_back({
        .id              = "FirefoxAddonScanner",
        .displayNameKey  = "module.firefoxaddonscanner.name",
        .descriptionKey  = "module.firefoxaddonscanner.description",
        .iconId          = "Globe",
        .category        = ModuleCategory::WebAndEmail,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // EmailProtection (Email/EmailWiring.cpp)
    m_entries.push_back({
        .id              = "EmailProtection",
        .displayNameKey  = "module.emailprotection.name",
        .descriptionKey  = "module.emailprotection.description",
        .iconId          = "Globe",
        .category        = ModuleCategory::WebAndEmail,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // ---- PrivacyProtection --------------------------------------------------

    // WebcamProtector (Privacy/wiring/WebcamProtectorWiring.cpp)
    m_entries.push_back({
        .id              = "WebcamProtector",
        .displayNameKey  = "module.webcamprotector.name",
        .descriptionKey  = "module.webcamprotector.description",
        .iconId          = "Eye",
        .category        = ModuleCategory::PrivacyProtection,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // MicrophoneGuard (Privacy/wiring/MicrophoneGuardWiring.cpp)
    m_entries.push_back({
        .id              = "MicrophoneGuard",
        .displayNameKey  = "module.microphoneguard.name",
        .descriptionKey  = "module.microphoneguard.description",
        .iconId          = "Eye",
        .category        = ModuleCategory::PrivacyProtection,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // LocationPrivacy (Privacy/wiring/LocationPrivacyWiring.cpp)
    m_entries.push_back({
        .id              = "LocationPrivacy",
        .displayNameKey  = "module.locationprivacy.name",
        .descriptionKey  = "module.locationprivacy.description",
        .iconId          = "Eye",
        .category        = ModuleCategory::PrivacyProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // CookieManager (Privacy/wiring/CookieManagerWiring.cpp)
    m_entries.push_back({
        .id              = "CookieManager",
        .displayNameKey  = "module.cookiemanager.name",
        .descriptionKey  = "module.cookiemanager.description",
        .iconId          = "Eye",
        .category        = ModuleCategory::PrivacyProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // PrivacyCleaner (Privacy/wiring/PrivacyCleanerWiring.cpp)
    m_entries.push_back({
        .id              = "PrivacyCleaner",
        .displayNameKey  = "module.privacycleaner.name",
        .descriptionKey  = "module.privacycleaner.description",
        .iconId          = "Eye",
        .category        = ModuleCategory::PrivacyProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = true,   // schedule-driven on/off; no graduated intensity
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // ---- DataAndBackup ------------------------------------------------------

    // DataLeakProtection (Privacy/wiring/DataLeakProtectionWiring.cpp)
    m_entries.push_back({
        .id              = "DataLeakProtection",
        .displayNameKey  = "module.dataleakprotection.name",
        .descriptionKey  = "module.dataleakprotection.description",
        .iconId          = "Archive",
        .category        = ModuleCategory::DataAndBackup,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // BackupManager (Backup/BackupWiring.cpp)
    m_entries.push_back({
        .id              = "BackupManager",
        .displayNameKey  = "module.backupmanager.name",
        .descriptionKey  = "module.backupmanager.description",
        .iconId          = "Archive",
        .category        = ModuleCategory::DataAndBackup,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = true,   // on/off; no graduated intensity
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // ---- SpecializedProtection ----------------------------------------------

    // -- Banking suite (Banking/wiring/*)

    // BankingTrojanDetector (Banking/wiring/BankingTrojanDetectorWiring.cpp)
    m_entries.push_back({
        .id              = "BankingTrojanDetector",
        .displayNameKey  = "module.bankingtrojan.name",
        .descriptionKey  = "module.bankingtrojan.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // CertificatePinning (Banking/wiring/CertificatePinningWiring.cpp)
    m_entries.push_back({
        .id              = "CertificatePinning",
        .displayNameKey  = "module.certpinning.name",
        .descriptionKey  = "module.certpinning.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // KeyloggerProtection (Banking/wiring/KeyloggerProtectionWiring.cpp)
    m_entries.push_back({
        .id              = "KeyloggerProtection",
        .displayNameKey  = "module.keyloggerprotection.name",
        .descriptionKey  = "module.keyloggerprotection.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // ScreenshotBlocker (Banking/wiring/ScreenshotBlockerWiring.cpp)
    m_entries.push_back({
        .id              = "ScreenshotBlocker",
        .displayNameKey  = "module.screenshotblocker.name",
        .descriptionKey  = "module.screenshotblocker.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // SecureBrowser (Banking/wiring/SecureBrowserWiring.cpp)
    m_entries.push_back({
        .id              = "SecureBrowser",
        .displayNameKey  = "module.securebrowser.name",
        .descriptionKey  = "module.securebrowser.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // TransactionMonitor (Banking/wiring/TransactionMonitorWiring.cpp)
    m_entries.push_back({
        .id              = "TransactionMonitor",
        .displayNameKey  = "module.transactionmonitor.name",
        .descriptionKey  = "module.transactionmonitor.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // -- Crypto miners suite (CryptoMinersProtection/CryptoMinersWiring.cpp)

    // CryptoMinerDetector
    m_entries.push_back({
        .id              = "CryptoMinerDetector",
        .displayNameKey  = "module.cryptominerdetector.name",
        .descriptionKey  = "module.cryptominerdetector.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // BrowserMinerDetector
    m_entries.push_back({
        .id              = "BrowserMinerDetector",
        .displayNameKey  = "module.browserminerdetector.name",
        .descriptionKey  = "module.browserminerdetector.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // CPUUsageAnalyzer
    m_entries.push_back({
        .id              = "CPUUsageAnalyzer",
        .displayNameKey  = "module.cpuusageanalyzer.name",
        .descriptionKey  = "module.cpuusageanalyzer.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // GPUMiningDetector
    m_entries.push_back({
        .id              = "GPUMiningDetector",
        .displayNameKey  = "module.gpuminingdetector.name",
        .descriptionKey  = "module.gpuminingdetector.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // -- IoT suite (IoT/IoTWiring.cpp)

    // IoTDeviceScanner
    m_entries.push_back({
        .id              = "IoTDeviceScanner",
        .displayNameKey  = "module.iotdevicescanner.name",
        .descriptionKey  = "module.iotdevicescanner.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // SmartHomeProtection
    m_entries.push_back({
        .id              = "SmartHomeProtection",
        .displayNameKey  = "module.smarthomeprotection.name",
        .descriptionKey  = "module.smarthomeprotection.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // -- USB suite (USB_Protection/USBWiring.cpp)

    // DeviceControlManager
    m_entries.push_back({
        .id              = "DeviceControlManager",
        .displayNameKey  = "module.devicecontrol.name",
        .descriptionKey  = "module.devicecontrol.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // BadUSBDetector
    m_entries.push_back({
        .id              = "BadUSBDetector",
        .displayNameKey  = "module.badusb.name",
        .descriptionKey  = "module.badusb.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskFullSpectrum,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // USBAutorunBlocker
    m_entries.push_back({
        .id              = "USBAutorunBlocker",
        .displayNameKey  = "module.usbautorun.name",
        .descriptionKey  = "module.usbautorun.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // USBDeviceMonitor
    m_entries.push_back({
        .id              = "USBDeviceMonitor",
        .displayNameKey  = "module.usbmonitor.name",
        .descriptionKey  = "module.usbmonitor.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // USBScanner
    m_entries.push_back({
        .id              = "USBScanner",
        .displayNameKey  = "module.usbscanner.name",
        .descriptionKey  = "module.usbscanner.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // -- Game mode suite (GameMode/GameModeWiring.cpp)

    // GameProcessDetector
    m_entries.push_back({
        .id              = "GameProcessDetector",
        .displayNameKey  = "module.gameprocessdetector.name",
        .descriptionKey  = "module.gameprocessdetector.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // PerformanceOptimizer
    m_entries.push_back({
        .id              = "PerformanceOptimizer",
        .displayNameKey  = "module.performanceoptimizer.name",
        .descriptionKey  = "module.performanceoptimizer.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // OverlayProtection
    m_entries.push_back({
        .id              = "OverlayProtection",
        .displayNameKey  = "module.overlayprotection.name",
        .descriptionKey  = "module.overlayprotection.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = false,
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // GameModeManager
    m_entries.push_back({
        .id              = "GameModeManager",
        .displayNameKey  = "module.gamemodemanager.name",
        .descriptionKey  = "module.gamemodemanager.description",
        .iconId          = "Star",
        .category        = ModuleCategory::SpecializedProtection,
        .supportedModesMask = kMaskOffBalanced,
        .binary          = true,  // on/off switch; performance mode has no graduated intensity
        .detailPage      = "ModuleDetailPage.qml",
        .premium         = false,
    });

    // NOTE: "HomeConfig" is a Foundation-phase internal module that the user
    // never interacts with directly. It is deliberately omitted from the catalog.

    SS_LOG_INFO(kLog, L"ModuleCatalog populated with %zu entries.",
                m_entries.size());
}

// ============================================================================
// Singleton
// ============================================================================

const ModuleCatalog& ModuleCatalog::Instance()
{
    static ModuleCatalog s_instance;
    return s_instance;
}

// ============================================================================
// Accessors
// ============================================================================

std::span<const CatalogEntry> ModuleCatalog::All() const noexcept
{
    return std::span<const CatalogEntry>(m_entries.data(), m_entries.size());
}

const CatalogEntry* ModuleCatalog::FindById(std::string_view id) const noexcept
{
    for (const auto& e : m_entries) {
        if (e.id == id) {
            return &e;
        }
    }
    return nullptr;
}

std::vector<const CatalogEntry*> ModuleCatalog::ByCategory(ModuleCategory cat) const
{
    std::vector<const CatalogEntry*> result;
    result.reserve(8);
    for (const auto& e : m_entries) {
        if (e.category == cat) {
            result.push_back(&e);
        }
    }
    return result;
}

// ============================================================================
// GetSupportedModesForId — catalog then orchestrator fallback
// ============================================================================

std::uint8_t GetSupportedModesForId(std::string_view id) noexcept
{
    // 1. Try the catalog first (fast linear scan over ~46 entries).
    const CatalogEntry* entry = ModuleCatalog::Instance().FindById(id);
    if (entry != nullptr) {
        return entry->supportedModesMask;
    }

    // 2. Fall back to the orchestrator's registered descriptor.
    //    GetModuleMode() exists; supportedModesMask is in the private record.
    //    Closest public proxy: if the module exists, return the default mask.
    //    A richer path requires GetModuleStatus() and ModuleDescriptor exposure.
    const auto status =
        ::ShadowStrike::Products::Home::HomeProductOrchestrator::Instance()
            .GetModuleStatus(id);
    if (status.has_value()) {
        // Module is registered but not in catalog; return the wiring default.
        // Off | Balanced = 0x05 is the ModuleDescriptor::supportedModesMask default.
        SS_LOG_DEBUG(kLog,
            L"GetSupportedModesForId: '%hs' not in catalog; returning wiring default 0x05.",
            std::string(id).c_str());
        return 0x05u;
    }

    SS_LOG_WARN(kLog,
        L"GetSupportedModesForId: '%hs' not found in catalog or orchestrator.",
        std::string(id).c_str());
    return 0u;
}

}  // namespace ShadowStrike::Products::Home::UI
