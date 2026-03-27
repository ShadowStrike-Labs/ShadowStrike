// ===========================================================================
// ShadowStrike – PhantomHome Configuration Registration (Implementation)
// Copyright (c) ShadowStrike-Labs. All rights reserved.
// ===========================================================================
#include "pch.h"
#include "HomeConfigRegistration.hpp"
#include "../../Shared_modules/Config/ConfigManager.hpp"
#include "../../Shared_modules/Config/ProfileManager.hpp"
#include "../../Shared_modules/Config/SettingsManager.hpp"

namespace ShadowStrike::Products::PhantomHome::Config {

using CM = ShadowStrike::Config::ConfigManager;
using ProfM = ShadowStrike::Config::ProfileManager;
using SM = ShadowStrike::Config::SettingsManager;
using Meta = ShadowStrike::Config::ConfigKeyMetadata;

// ============================================================================
// HELPER
// ============================================================================

namespace {

template<typename T>
bool RegKey(const std::string& key, const std::string& category,
            const std::string& displayName, const T& defaultValue,
            bool sensitive = false) {
    Meta meta{};
    meta.key = key;
    meta.category = category;
    meta.displayName = displayName;
    meta.defaultValue = ShadowStrike::Config::ConfigValue(defaultValue);
    meta.isSensitive = sensitive;
    return CM::Instance().RegisterKeyMetadata(meta);
}

template<typename T>
bool RegKeyRange(const std::string& key, const std::string& category,
                 const std::string& displayName, const T& defaultValue,
                 const T& minVal, const T& maxVal) {
    Meta meta{};
    meta.key = key;
    meta.category = category;
    meta.displayName = displayName;
    meta.defaultValue = ShadowStrike::Config::ConfigValue(defaultValue);
    meta.minValue = ShadowStrike::Config::ConfigValue(minVal);
    meta.maxValue = ShadowStrike::Config::ConfigValue(maxVal);
    return CM::Instance().RegisterKeyMetadata(meta);
}

} // anonymous namespace

// ============================================================================
// RegisterProductDefaults
// ============================================================================

[[nodiscard]] bool RegisterProductDefaults() {
    bool ok = true;

    // ---- Protection Level ----
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ProtectionLevel),
        "Protection", "Protection Level",
        static_cast<uint32_t>(ProtectionLevel::Recommended), 0, 2);
    ok &= RegKey<bool>(std::string(Keys::RealTimeProtection),
        "Protection", "Real-time file protection", true);
    ok &= RegKey<bool>(std::string(Keys::CloudLookup),
        "Protection", "Cloud-based file reputation", true);
    ok &= RegKey<bool>(std::string(Keys::AutoQuarantine),
        "Protection", "Automatically quarantine threats", true);
    ok &= RegKey<bool>(std::string(Keys::PUPDetection),
        "Protection", "Detect potentially unwanted programs", true);
    ok &= RegKey<bool>(std::string(Keys::RansomwareShield),
        "Protection", "Ransomware behavior shield", true);

    // ---- Scan Settings ----
    ok &= RegKey<bool>(std::string(Keys::QuickScanOnStartup),
        "Scan", "Quick scan when Windows starts", false);
    ok &= RegKey<bool>(std::string(Keys::ScheduledScanEnabled),
        "Scan", "Enable scheduled scans", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ScheduledScanDay),
        "Scan", "Scheduled scan day",
        static_cast<uint32_t>(ScanScheduleDay::Sunday), 0, 7);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ScheduledScanHour),
        "Scan", "Scheduled scan hour (0-23)", 2, 0, 23);
    ok &= RegKey<bool>(std::string(Keys::ScanRemovableMedia),
        "Scan", "Scan removable media on insert", true);
    ok &= RegKey<bool>(std::string(Keys::ScanArchives),
        "Scan", "Scan inside archive files", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::ScanMaxFileSizeMB),
        "Scan", "Maximum file size to scan (MB)", 128, 1, 2048);

    // ---- Banking & Financial Protection ----
    ok &= RegKey<bool>(std::string(Keys::BankingProtection),
        "Banking", "Banking protection suite", true);
    ok &= RegKey<bool>(std::string(Keys::SecureBrowser),
        "Banking", "Secure browser for banking", true);
    ok &= RegKey<bool>(std::string(Keys::ScreenshotBlocker),
        "Banking", "Block screenshots during banking", true);
    ok &= RegKey<bool>(std::string(Keys::KeyloggerProtection),
        "Banking", "Keylogger protection", true);
    ok &= RegKey<bool>(std::string(Keys::CertificatePinning),
        "Banking", "Certificate pinning for banking sites", true);
    ok &= RegKey<bool>(std::string(Keys::BankingTrojanDetection),
        "Banking", "Banking trojan detection", true);

    // ---- Web Protection ----
    ok &= RegKey<bool>(std::string(Keys::WebProtection),
        "Web", "Web protection", true);
    ok &= RegKey<bool>(std::string(Keys::PhishingDetection),
        "Web", "Phishing website detection", true);
    ok &= RegKey<bool>(std::string(Keys::MaliciousURLBlocking),
        "Web", "Block malicious URLs", true);
    ok &= RegKey<bool>(std::string(Keys::SafeSearch),
        "Web", "Safe search enforcement", false);
    ok &= RegKey<bool>(std::string(Keys::DownloadScanning),
        "Web", "Scan downloaded files", true);
    ok &= RegKey<bool>(std::string(Keys::BrowserExtProtection),
        "Web", "Browser extension monitoring", true);

    // ---- Email Protection ----
    ok &= RegKey<bool>(std::string(Keys::EmailProtection),
        "Email", "Email protection", true);
    ok &= RegKey<bool>(std::string(Keys::EmailAttachmentScan),
        "Email", "Scan email attachments", true);
    ok &= RegKey<bool>(std::string(Keys::EmailPhishingDetection),
        "Email", "Email phishing detection", true);
    ok &= RegKey<bool>(std::string(Keys::EmailLinkRewriting),
        "Email", "Rewrite suspicious email links", false);
    ok &= RegKey<bool>(std::string(Keys::EmailSpamFilter),
        "Email", "Email spam filter", true);

    // ---- USB & Device Protection ----
    ok &= RegKey<bool>(std::string(Keys::USBProtection),
        "USB", "USB device protection", true);
    ok &= RegKey<bool>(std::string(Keys::USBAutoScan),
        "USB", "Auto-scan USB on connect", true);
    ok &= RegKey<bool>(std::string(Keys::USBBlockUnknown),
        "USB", "Block unrecognized USB devices", false);
    ok &= RegKey<bool>(std::string(Keys::USBAutoRunBlock),
        "USB", "Block USB autorun", true);

    // ---- Privacy ----
    ok &= RegKey<bool>(std::string(Keys::PrivacyProtection),
        "Privacy", "Privacy protection suite", true);
    ok &= RegKey<bool>(std::string(Keys::WebcamProtection),
        "Privacy", "Webcam access protection", true);
    ok &= RegKey<bool>(std::string(Keys::MicrophoneProtection),
        "Privacy", "Microphone access protection", true);
    ok &= RegKey<bool>(std::string(Keys::TrackerBlocking),
        "Privacy", "Online tracker blocking", true);
    ok &= RegKey<bool>(std::string(Keys::DataLeakPrevention),
        "Privacy", "Personal data leak prevention", false);
    ok &= RegKey<bool>(std::string(Keys::CookieManager),
        "Privacy", "Cookie manager", false);
    ok &= RegKey<bool>(std::string(Keys::DigitalFingerprint),
        "Privacy", "Digital fingerprint protection", false);

    // ---- IoT Protection ----
    ok &= RegKey<bool>(std::string(Keys::IoTProtection),
        "IoT", "IoT device protection", false);
    ok &= RegKey<bool>(std::string(Keys::IoTNetworkScan),
        "IoT", "Scan network for IoT devices", false);
    ok &= RegKey<bool>(std::string(Keys::IoTVulnerabilityCheck),
        "IoT", "Check IoT devices for vulnerabilities", false);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::IoTScanIntervalMin),
        "IoT", "IoT network scan interval (minutes)", 60, 5, 1440);
    ok &= RegKey<bool>(std::string(Keys::IoTAlertOnNewDevice),
        "IoT", "Alert when new device joins network", true);

    // ---- Crypto Miner Protection ----
    ok &= RegKey<bool>(std::string(Keys::CryptoMinerProtection),
        "CryptoMiner", "Cryptocurrency miner detection", true);
    ok &= RegKey<bool>(std::string(Keys::CryptoMinerGPUMonitoring),
        "CryptoMiner", "GPU usage monitoring for miners", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::CryptoMinerCPUThreshold),
        "CryptoMiner", "CPU threshold for miner detection (%)", 80, 30, 100);
    ok &= RegKey<bool>(std::string(Keys::CryptoMinerBrowserProtection),
        "CryptoMiner", "Block browser-based miners", true);

    // ---- Gaming Mode ----
    ok &= RegKey<bool>(std::string(Keys::GamingModeEnabled),
        "Gaming", "Gaming mode", true);
    ok &= RegKey<bool>(std::string(Keys::GamingAutoDetect),
        "Gaming", "Auto-detect fullscreen games", true);
    ok &= RegKey<bool>(std::string(Keys::GamingSuppressNotifications),
        "Gaming", "Suppress notifications during gaming", true);
    ok &= RegKey<bool>(std::string(Keys::GamingReduceCPU),
        "Gaming", "Reduce scan CPU usage during gaming", true);
    ok &= RegKey<bool>(std::string(Keys::GamingPostponeScans),
        "Gaming", "Postpone scheduled scans during gaming", true);
    ok &= RegKey<bool>(std::string(Keys::GamingPostponeUpdates),
        "Gaming", "Postpone updates during gaming", true);

    // ---- Backup ----
    ok &= RegKey<bool>(std::string(Keys::BackupEnabled),
        "Backup", "Backup protection", false);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::BackupSchedule),
        "Backup", "Backup schedule",
        static_cast<uint32_t>(BackupSchedule::Daily), 0, 3);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::BackupMaxStorageGB),
        "Backup", "Maximum backup storage (GB)", 50, 1, 1000);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::BackupRetentionDays),
        "Backup", "Backup retention (days)", 30, 1, 365);
    ok &= RegKey<bool>(std::string(Keys::BackupIncrementalEnabled),
        "Backup", "Incremental backup", true);

    // ---- Notifications & UX ----
    ok &= RegKey<bool>(std::string(Keys::ShowThreatPopup),
        "UX", "Show threat detection popup", true);
    ok &= RegKey<bool>(std::string(Keys::ShowScanProgress),
        "UX", "Show scan progress in tray", true);
    ok &= RegKey<bool>(std::string(Keys::ShowTrayIcon),
        "UX", "Show system tray icon", true);
    ok &= RegKey<bool>(std::string(Keys::NotificationSound),
        "UX", "Play notification sounds", true);
    ok &= RegKey<bool>(std::string(Keys::QuietHoursEnabled),
        "UX", "Quiet hours (no notifications)", false);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::QuietHoursStart),
        "UX", "Quiet hours start (0-23)", 22, 0, 23);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::QuietHoursEnd),
        "UX", "Quiet hours end (0-23)", 7, 0, 23);

    // ---- Update ----
    ok &= RegKey<bool>(std::string(Keys::AutoUpdate),
        "Update", "Automatic updates", true);
    ok &= RegKey<bool>(std::string(Keys::NotifyBeforeRestart),
        "Update", "Notify before restart for updates", true);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::UpdateCheckIntervalHours),
        "Update", "Update check interval (hours)", 4, 1, 48);

    // ---- Telemetry (privacy-conscious defaults) ----
    ok &= RegKey<bool>(std::string(Keys::TelemetryOptIn),
        "Telemetry", "Opt-in to telemetry", false);
    ok &= RegKey<bool>(std::string(Keys::AnonymousUsageStats),
        "Telemetry", "Share anonymous usage statistics", false);
    ok &= RegKey<bool>(std::string(Keys::CrashReporting),
        "Telemetry", "Automatic crash reporting", true);

    if (!ok) {
        Utils::Logger::Error("[Home Config] One or more key registrations failed");
    }
    return ok;
}

// ============================================================================
// RegisterProfilePresets
// ============================================================================

[[nodiscard]] bool RegisterProfilePresets() {
    using SystemProfile = ShadowStrike::Config::SystemProfile;
    using ProfileDef = ShadowStrike::Config::ProfileDefinition;

    bool ok = true;

    // Standard Profile — balanced for everyday use
    {
        ProfileDef standard{};
        standard.type = SystemProfile::Standard;
        standard.name = "Balanced";
        standard.description = "Balanced protection for everyday computing";

        standard.resources.maxCpuPercent = 25;
        standard.resources.maxMemoryMB = 384;
        standard.resources.ioPriority = 1;
        standard.resources.maxConcurrentScans = 2;
        standard.resources.threadPriority = 0;

        standard.scanSettings.realTimeProtection = true;
        standard.scanSettings.behaviorMonitoring = true;
        standard.scanSettings.archiveScanning = true;
        standard.scanSettings.scanNetworkFiles = false;
        standard.scanSettings.heuristicLevel = 2;
        standard.scanSettings.cloudLookup = true;

        ok &= ProfM::Instance().CreateCustomProfile(standard);
    }

    // Gaming Profile — minimal disruption during games
    {
        ProfileDef gaming{};
        gaming.type = SystemProfile::Gaming;
        gaming.name = "Gaming";
        gaming.description = "Minimal CPU/IO usage during gaming sessions";

        gaming.resources.maxCpuPercent = 5;
        gaming.resources.maxMemoryMB = 128;
        gaming.resources.ioPriority = 0; // Lowest
        gaming.resources.maxConcurrentScans = 1;
        gaming.resources.threadPriority = -2; // Idle priority

        gaming.scanSettings.realTimeProtection = true;
        gaming.scanSettings.behaviorMonitoring = true;
        gaming.scanSettings.archiveScanning = false;
        gaming.scanSettings.scanNetworkFiles = false;
        gaming.scanSettings.heuristicLevel = 1;
        gaming.scanSettings.cloudLookup = true;

        gaming.notificationSettings.enabled = false;
        gaming.notificationSettings.sound = false;
        gaming.notificationSettings.showScanProgress = false;

        ok &= ProfM::Instance().CreateCustomProfile(gaming);
    }

    // Silent Profile — no user disruption at all
    {
        ProfileDef silent{};
        silent.type = SystemProfile::Silent;
        silent.name = "Silent";
        silent.description = "No notifications, minimal resource usage";

        silent.resources.maxCpuPercent = 10;
        silent.resources.maxMemoryMB = 192;
        silent.resources.ioPriority = 0;
        silent.resources.maxConcurrentScans = 1;
        silent.resources.threadPriority = -1;

        silent.scanSettings.realTimeProtection = true;
        silent.scanSettings.behaviorMonitoring = true;
        silent.scanSettings.archiveScanning = false;
        silent.scanSettings.scanNetworkFiles = false;
        silent.scanSettings.heuristicLevel = 1;
        silent.scanSettings.cloudLookup = true;

        silent.notificationSettings.enabled = false;
        silent.notificationSettings.sound = false;
        silent.notificationSettings.showScanProgress = false;

        ok &= ProfM::Instance().CreateCustomProfile(silent);
    }

    // Low Resource Profile — for older/weaker machines
    {
        ProfileDef lowRes{};
        lowRes.type = SystemProfile::LowResource;
        lowRes.name = "Low Resource";
        lowRes.description = "Minimal footprint for older hardware";

        lowRes.resources.maxCpuPercent = 5;
        lowRes.resources.maxMemoryMB = 96;
        lowRes.resources.ioPriority = 0;
        lowRes.resources.maxConcurrentScans = 1;
        lowRes.resources.threadPriority = -2;

        lowRes.scanSettings.realTimeProtection = true;
        lowRes.scanSettings.behaviorMonitoring = false; // Too resource-heavy
        lowRes.scanSettings.archiveScanning = false;
        lowRes.scanSettings.scanNetworkFiles = false;
        lowRes.scanSettings.heuristicLevel = 0; // Signatures only
        lowRes.scanSettings.cloudLookup = true;

        ok &= ProfM::Instance().CreateCustomProfile(lowRes);
    }

    if (!ok) {
        Utils::Logger::Error("[Home Config] One or more profile preset registrations failed");
    }
    return ok;
}

// ============================================================================
// ValidateConfiguration
// ============================================================================

[[nodiscard]] bool ValidateConfiguration() {
    auto& cm = CM::Instance();
    bool valid = true;

    // Protection level sanity
    auto level = cm.GetValue<uint32_t>(std::string(Keys::ProtectionLevel),
        static_cast<uint32_t>(ProtectionLevel::Recommended));
    if (level > static_cast<uint32_t>(ProtectionLevel::Maximum)) {
        Utils::Logger::Error("[Home Config] Invalid protection level: {}", level);
        valid = false;
    }

    // If banking protection enabled, ensure required sub-features are on
    bool bankingEnabled = cm.GetValue<bool>(std::string(Keys::BankingProtection), true);
    if (bankingEnabled) {
        bool keylogger = cm.GetValue<bool>(std::string(Keys::KeyloggerProtection), true);
        bool certPin = cm.GetValue<bool>(std::string(Keys::CertificatePinning), true);
        if (!keylogger || !certPin) {
            Utils::Logger::Warn("[Home Config] Banking protection enabled but keylogger "
                                "protection or certificate pinning disabled — reduced security");
        }
    }

    // Quiet hours range sanity
    bool quietEnabled = cm.GetValue<bool>(std::string(Keys::QuietHoursEnabled), false);
    if (quietEnabled) {
        auto start = cm.GetValue<uint32_t>(std::string(Keys::QuietHoursStart), 22);
        auto end = cm.GetValue<uint32_t>(std::string(Keys::QuietHoursEnd), 7);
        if (start == end) {
            Utils::Logger::Warn("[Home Config] Quiet hours start == end — quiet hours effectively disabled");
        }
    }

    // IoT scan interval sanity
    bool iotEnabled = cm.GetValue<bool>(std::string(Keys::IoTProtection), false);
    if (iotEnabled) {
        auto interval = cm.GetValue<uint32_t>(std::string(Keys::IoTScanIntervalMin), 60);
        if (interval < 10) {
            Utils::Logger::Warn("[Home Config] IoT scan interval {}min is very aggressive — "
                                "may cause network congestion", interval);
        }
    }

    auto errors = cm.ValidateAll();
    for (const auto& err : errors) {
        Utils::Logger::Warn("[Home Config] Validation error for '{}': {}", err.key, err.message);
    }

    if (valid && errors.empty()) {
        Utils::Logger::Info("[Home Config] Configuration validation passed");
    } else {
        Utils::Logger::Error("[Home Config] Configuration validation found issues");
        valid = false;
    }

    return valid;
}

} // namespace ShadowStrike::Products::PhantomHome::Config
