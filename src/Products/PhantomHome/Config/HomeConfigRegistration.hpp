// ===========================================================================
// ShadowStrike – PhantomHome Configuration Registration
// Copyright (c) ShadowStrike-Labs. All rights reserved.
//
// Registers Home-specific configuration keys, simplified policies, and
// consumer-oriented profiles with the shared Config infrastructure.
//
// PhantomHome is a consumer product with a local UI. Configuration is
// managed by the end-user through the HomeUI, not an enterprise console.
// Policies are simplified and user-friendly. Profiles emphasize usability
// (Gaming, Silent) over enterprise roles (Server, DomainController).
// ===========================================================================
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace ShadowStrike::Products::PhantomHome::Config {

// ============================================================================
// CONFIG KEY CONSTANTS
// Keys are hierarchical: "Home/<Category>/<Setting>"
// ============================================================================

namespace Keys {

    // --- Protection Level (simplified for consumers) ---
    inline constexpr std::string_view ProtectionLevel             = "Home/Protection/Level";
    inline constexpr std::string_view RealTimeProtection          = "Home/Protection/RealTime";
    inline constexpr std::string_view CloudLookup                 = "Home/Protection/CloudLookup";
    inline constexpr std::string_view AutoQuarantine              = "Home/Protection/AutoQuarantine";
    inline constexpr std::string_view PUPDetection                = "Home/Protection/PUPDetection";
    inline constexpr std::string_view RansomwareShield            = "Home/Protection/RansomwareShield";

    // --- Scan Settings ---
    inline constexpr std::string_view QuickScanOnStartup          = "Home/Scan/QuickScanOnStartup";
    inline constexpr std::string_view ScheduledScanEnabled        = "Home/Scan/ScheduledScan";
    inline constexpr std::string_view ScheduledScanDay            = "Home/Scan/ScheduledDay";
    inline constexpr std::string_view ScheduledScanHour           = "Home/Scan/ScheduledHour";
    inline constexpr std::string_view ScanRemovableMedia          = "Home/Scan/RemovableMedia";
    inline constexpr std::string_view ScanArchives                = "Home/Scan/Archives";
    inline constexpr std::string_view ScanMaxFileSizeMB           = "Home/Scan/MaxFileSizeMB";
    inline constexpr std::string_view ScanExcludedPaths           = "Home/Scan/ExcludedPaths";
    inline constexpr std::string_view ScanExcludedExtensions      = "Home/Scan/ExcludedExtensions";

    // --- Banking & Financial Protection ---
    inline constexpr std::string_view BankingProtection           = "Home/Banking/Enabled";
    inline constexpr std::string_view SecureBrowser               = "Home/Banking/SecureBrowser";
    inline constexpr std::string_view ScreenshotBlocker           = "Home/Banking/ScreenshotBlocker";
    inline constexpr std::string_view KeyloggerProtection         = "Home/Banking/KeyloggerProtection";
    inline constexpr std::string_view CertificatePinning          = "Home/Banking/CertificatePinning";
    inline constexpr std::string_view BankingTrojanDetection      = "Home/Banking/TrojanDetection";
    inline constexpr std::string_view TrustedBankingSites         = "Home/Banking/TrustedSites";

    // --- Web Protection ---
    inline constexpr std::string_view WebProtection               = "Home/Web/Enabled";
    inline constexpr std::string_view PhishingDetection           = "Home/Web/PhishingDetection";
    inline constexpr std::string_view MaliciousURLBlocking        = "Home/Web/MaliciousURLBlocking";
    inline constexpr std::string_view SafeSearch                  = "Home/Web/SafeSearch";
    inline constexpr std::string_view DownloadScanning            = "Home/Web/DownloadScanning";
    inline constexpr std::string_view BrowserExtProtection        = "Home/Web/BrowserExtProtection";
    inline constexpr std::string_view WebFilterCategories         = "Home/Web/FilterCategories";

    // --- Email Protection ---
    inline constexpr std::string_view EmailProtection             = "Home/Email/Enabled";
    inline constexpr std::string_view EmailAttachmentScan         = "Home/Email/AttachmentScan";
    inline constexpr std::string_view EmailPhishingDetection      = "Home/Email/PhishingDetection";
    inline constexpr std::string_view EmailLinkRewriting          = "Home/Email/LinkRewriting";
    inline constexpr std::string_view EmailSpamFilter             = "Home/Email/SpamFilter";

    // --- USB & Device Protection ---
    inline constexpr std::string_view USBProtection               = "Home/USB/Enabled";
    inline constexpr std::string_view USBAutoScan                 = "Home/USB/AutoScan";
    inline constexpr std::string_view USBBlockUnknown             = "Home/USB/BlockUnknown";
    inline constexpr std::string_view USBAllowList                = "Home/USB/AllowList";
    inline constexpr std::string_view USBAutoRunBlock             = "Home/USB/AutoRunBlock";

    // --- Privacy ---
    inline constexpr std::string_view PrivacyProtection           = "Home/Privacy/Enabled";
    inline constexpr std::string_view WebcamProtection            = "Home/Privacy/WebcamProtection";
    inline constexpr std::string_view MicrophoneProtection        = "Home/Privacy/MicrophoneProtection";
    inline constexpr std::string_view TrackerBlocking             = "Home/Privacy/TrackerBlocking";
    inline constexpr std::string_view DataLeakPrevention          = "Home/Privacy/DataLeakPrevention";
    inline constexpr std::string_view CookieManager               = "Home/Privacy/CookieManager";
    inline constexpr std::string_view DigitalFingerprint           = "Home/Privacy/FingerprintProtection";

    // --- IoT Protection ---
    inline constexpr std::string_view IoTProtection               = "Home/IoT/Enabled";
    inline constexpr std::string_view IoTNetworkScan              = "Home/IoT/NetworkScan";
    inline constexpr std::string_view IoTVulnerabilityCheck       = "Home/IoT/VulnerabilityCheck";
    inline constexpr std::string_view IoTScanIntervalMin          = "Home/IoT/ScanIntervalMin";
    inline constexpr std::string_view IoTAlertOnNewDevice         = "Home/IoT/AlertOnNewDevice";
    inline constexpr std::string_view IoTTrustedDevices           = "Home/IoT/TrustedDevices";

    // --- Crypto Miner Protection ---
    inline constexpr std::string_view CryptoMinerProtection       = "Home/CryptoMiner/Enabled";
    inline constexpr std::string_view CryptoMinerGPUMonitoring    = "Home/CryptoMiner/GPUMonitoring";
    inline constexpr std::string_view CryptoMinerCPUThreshold     = "Home/CryptoMiner/CPUThreshold";
    inline constexpr std::string_view CryptoMinerBrowserProtection = "Home/CryptoMiner/BrowserProtection";

    // --- Gaming Mode ---
    inline constexpr std::string_view GamingModeEnabled           = "Home/Gaming/Enabled";
    inline constexpr std::string_view GamingAutoDetect            = "Home/Gaming/AutoDetect";
    inline constexpr std::string_view GamingSuppressNotifications = "Home/Gaming/SuppressNotifications";
    inline constexpr std::string_view GamingReduceCPU             = "Home/Gaming/ReduceCPU";
    inline constexpr std::string_view GamingPostponeScans         = "Home/Gaming/PostponeScans";
    inline constexpr std::string_view GamingPostponeUpdates       = "Home/Gaming/PostponeUpdates";
    inline constexpr std::string_view GamingKnownGames            = "Home/Gaming/KnownGames";

    // --- Backup & Recovery ---
    inline constexpr std::string_view BackupEnabled               = "Home/Backup/Enabled";
    inline constexpr std::string_view BackupSchedule              = "Home/Backup/Schedule";
    inline constexpr std::string_view BackupProtectedFolders      = "Home/Backup/ProtectedFolders";
    inline constexpr std::string_view BackupMaxStorageGB          = "Home/Backup/MaxStorageGB";
    inline constexpr std::string_view BackupRetentionDays         = "Home/Backup/RetentionDays";
    inline constexpr std::string_view BackupIncrementalEnabled    = "Home/Backup/IncrementalEnabled";

    // --- Notifications & UX ---
    inline constexpr std::string_view ShowThreatPopup             = "Home/UX/ShowThreatPopup";
    inline constexpr std::string_view ShowScanProgress            = "Home/UX/ShowScanProgress";
    inline constexpr std::string_view ShowTrayIcon                = "Home/UX/ShowTrayIcon";
    inline constexpr std::string_view NotificationSound           = "Home/UX/NotificationSound";
    inline constexpr std::string_view QuietHoursEnabled           = "Home/UX/QuietHoursEnabled";
    inline constexpr std::string_view QuietHoursStart             = "Home/UX/QuietHoursStart";
    inline constexpr std::string_view QuietHoursEnd               = "Home/UX/QuietHoursEnd";

    // --- Update ---
    inline constexpr std::string_view AutoUpdate                  = "Home/Update/AutoUpdate";
    inline constexpr std::string_view NotifyBeforeRestart         = "Home/Update/NotifyBeforeRestart";
    inline constexpr std::string_view UpdateCheckIntervalHours    = "Home/Update/CheckIntervalHours";

    // --- Telemetry (consumer-grade, privacy-conscious) ---
    inline constexpr std::string_view TelemetryOptIn              = "Home/Telemetry/OptIn";
    inline constexpr std::string_view AnonymousUsageStats         = "Home/Telemetry/AnonymousUsageStats";
    inline constexpr std::string_view CrashReporting              = "Home/Telemetry/CrashReporting";

} // namespace Keys

// ============================================================================
// ENUMS FOR TYPED CONFIG VALUES
// ============================================================================

enum class ProtectionLevel : uint32_t {
    Essential   = 0,    // Core antivirus only — minimal resource usage
    Recommended = 1,    // Balanced — AV + web + email + banking
    Maximum     = 2     // Full suite — all modules enabled
};

enum class ScanScheduleDay : uint32_t {
    Daily       = 0,
    Monday      = 1,
    Tuesday     = 2,
    Wednesday   = 3,
    Thursday    = 4,
    Friday      = 5,
    Saturday    = 6,
    Sunday      = 7
};

enum class BackupSchedule : uint32_t {
    Hourly      = 0,
    Daily       = 1,
    Weekly      = 2,
    Manual      = 3
};

// ============================================================================
// REGISTRATION API
// ============================================================================

/// @brief Registers all Home configuration keys with consumer-friendly
///        defaults, validation rules, and simplified profiles.
///        Must be called once during PhantomHome startup.
/// @return true if all registrations succeeded
[[nodiscard]] bool RegisterProductDefaults();

/// @brief Registers consumer-appropriate system profiles
///        (Standard, Gaming, Silent, LowResource).
/// @return true if all profiles configured
[[nodiscard]] bool RegisterProfilePresets();

/// @brief Validates the current Home configuration.
/// @return true if configuration is valid
[[nodiscard]] bool ValidateConfiguration();

/// @brief Returns the product identifier string for config namespacing.
[[nodiscard]] constexpr std::string_view GetProductIdentifier() noexcept {
    return "PhantomHome";
}

/// @brief Returns the product version for config compatibility checks.
[[nodiscard]] constexpr uint32_t GetProductVersion() noexcept {
    return 0x03000000; // 3.0.0
}

} // namespace ShadowStrike::Products::PhantomHome::Config
