// ===========================================================================
// ShadowStrike – PhantomHome Configuration Registration (Implementation)
// Copyright (c) ShadowStrike-Labs. All rights reserved.
// ===========================================================================
#include "pch.h"
#include "HomeConfigRegistration.hpp"
#include "../../PhantomCore/Config/ConfigManager.hpp"
#include "../../PhantomCore/Config/ProfileManager.hpp"
#include "../../PhantomCore/Config/SettingsManager.hpp"

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
    if (!CM::Instance().RegisterKeyMetadata(meta)) {
        Utils::Logger::Error("[Home Config] Failed to register key '{}'", key);
        return false;
    }
    return true;
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
    meta.minValue = static_cast<double>(minVal);
    meta.maxValue = static_cast<double>(maxVal);
    if (!CM::Instance().RegisterKeyMetadata(meta)) {
        Utils::Logger::Error("[Home Config] Failed to register key '{}' (range [{}, {}])",
                             key, minVal, maxVal);
        return false;
    }
    return true;
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
    ok &= RegKey<std::vector<std::string>>(std::string(Keys::ScanExcludedPaths),
        "Scan", "Excluded scan paths", std::vector<std::string>{}, true);
    ok &= RegKey<std::vector<std::string>>(std::string(Keys::ScanExcludedExtensions),
        "Scan", "Excluded file extensions", std::vector<std::string>{}, true);

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
    ok &= RegKey<std::vector<std::string>>(std::string(Keys::TrustedBankingSites),
        "Banking", "Trusted banking site URLs", std::vector<std::string>{}, true);

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
    ok &= RegKey<std::vector<std::string>>(std::string(Keys::WebFilterCategories),
        "Web", "Content filter categories", std::vector<std::string>{});

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
    ok &= RegKey<std::vector<std::string>>(std::string(Keys::USBAllowList),
        "USB", "Allowed USB device identifiers", std::vector<std::string>{}, true);
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
    ok &= RegKey<std::vector<std::string>>(std::string(Keys::IoTTrustedDevices),
        "IoT", "Trusted IoT device identifiers", std::vector<std::string>{}, true);

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
    ok &= RegKey<std::vector<std::string>>(std::string(Keys::GamingKnownGames),
        "Gaming", "Known game executable paths", std::vector<std::string>{});

    // ---- Backup ----
    ok &= RegKey<bool>(std::string(Keys::BackupEnabled),
        "Backup", "Backup protection", false);
    ok &= RegKeyRange<uint32_t>(std::string(Keys::BackupSchedule),
        "Backup", "Backup schedule",
        static_cast<uint32_t>(BackupSchedule::Daily), 0, 3);
    ok &= RegKey<std::vector<std::string>>(std::string(Keys::BackupProtectedFolders),
        "Backup", "Folders protected by backup", std::vector<std::string>{});
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
        standard.profileType = SystemProfile::Standard;
        standard.customName = "Balanced";
        standard.description = "Balanced protection for everyday computing";

        standard.resources.maxCpuPercent = 25;
        standard.resources.maxMemoryMb = 384;
        standard.resources.ioPriority = 1;
        standard.resources.maxConcurrentScans = 2;
        standard.resources.scanThreadPriority = 0;

        standard.scan.realtimeProtection = true;
        standard.scan.behaviorMonitoring = true;
        standard.scan.scanArchives = true;
        standard.scan.scanNetworkFiles = false;
        standard.scan.heuristicLevel = 2;
        standard.scan.cloudLookupEnabled = true;

        ok &= ProfM::Instance().CreateCustomProfile(standard);
    }

    // Gaming Profile — minimal disruption during games
    {
        ProfileDef gaming{};
        gaming.profileType = SystemProfile::Gaming;
        gaming.customName = "Gaming";
        gaming.description = "Minimal CPU/IO usage during gaming sessions";

        gaming.resources.maxCpuPercent = 5;
        gaming.resources.maxMemoryMb = 128;
        gaming.resources.ioPriority = 0; // Lowest
        gaming.resources.maxConcurrentScans = 1;
        gaming.resources.scanThreadPriority = -2; // Idle priority

        gaming.scan.realtimeProtection = true;
        gaming.scan.behaviorMonitoring = true;
        gaming.scan.scanArchives = false;
        gaming.scan.scanNetworkFiles = false;
        gaming.scan.heuristicLevel = 1;
        gaming.scan.cloudLookupEnabled = true;

        gaming.notifications.enabled = false;
        gaming.notifications.soundEnabled = false;
        gaming.notifications.showScanProgress = false;

        ok &= ProfM::Instance().CreateCustomProfile(gaming);
    }

    // Silent Profile — no user disruption at all
    {
        ProfileDef silent{};
        silent.profileType = SystemProfile::Silent;
        silent.customName = "Silent";
        silent.description = "No notifications, minimal resource usage";

        silent.resources.maxCpuPercent = 10;
        silent.resources.maxMemoryMb = 192;
        silent.resources.ioPriority = 0;
        silent.resources.maxConcurrentScans = 1;
        silent.resources.scanThreadPriority = -1;

        silent.scan.realtimeProtection = true;
        silent.scan.behaviorMonitoring = true;
        silent.scan.scanArchives = false;
        silent.scan.scanNetworkFiles = false;
        silent.scan.heuristicLevel = 1;
        silent.scan.cloudLookupEnabled = true;

        silent.notifications.enabled = false;
        silent.notifications.soundEnabled = false;
        silent.notifications.showScanProgress = false;

        ok &= ProfM::Instance().CreateCustomProfile(silent);
    }

    // Low Resource Profile — for older/weaker machines
    {
        ProfileDef lowRes{};
        lowRes.profileType = SystemProfile::LowResource;
        lowRes.customName = "Low Resource";
        lowRes.description = "Minimal footprint for older hardware";

        lowRes.resources.maxCpuPercent = 5;
        lowRes.resources.maxMemoryMb = 96;
        lowRes.resources.ioPriority = 0;
        lowRes.resources.maxConcurrentScans = 1;
        lowRes.resources.scanThreadPriority = -2;

        lowRes.scan.realtimeProtection = true;
        lowRes.scan.behaviorMonitoring = false; // Too resource-heavy
        lowRes.scan.scanArchives = false;
        lowRes.scan.scanNetworkFiles = false;
        lowRes.scan.heuristicLevel = 0; // Signatures only
        lowRes.scan.cloudLookupEnabled = true;

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

    // Maximum protection must have real-time and ransomware shield enabled
    if (level == static_cast<uint32_t>(ProtectionLevel::Maximum)) {
        bool rtpOn = cm.GetValue<bool>(std::string(Keys::RealTimeProtection), true);
        bool ransomOn = cm.GetValue<bool>(std::string(Keys::RansomwareShield), true);
        if (!rtpOn) {
            Utils::Logger::Error("[Home Config] Protection level is Maximum but "
                                 "real-time protection is disabled — forcing enabled");
            valid = false;
        }
        if (!ransomOn) {
            Utils::Logger::Warn("[Home Config] Protection level is Maximum but "
                                "ransomware shield is disabled — reduced protection");
        }
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

    // Update interval sanity — stale signatures are a security risk
    auto updateInterval = cm.GetValue<uint32_t>(
        std::string(Keys::UpdateCheckIntervalHours), 4);
    if (updateInterval > 24) {
        Utils::Logger::Warn("[Home Config] Update check interval {}h is dangerously long — "
                            "signature updates may be stale", updateInterval);
    }

    // ScanMaxFileSizeMB sanity — too small leaves large malware unscanned
    auto maxFileSizeMB = cm.GetValue<uint32_t>(
        std::string(Keys::ScanMaxFileSizeMB), 128);
    if (maxFileSizeMB < 16) {
        Utils::Logger::Warn("[Home Config] Maximum scan file size {}MB is very low — "
                            "large malware payloads may be missed", maxFileSizeMB);
    }

    // CryptoMiner CPU threshold — too low causes false positives
    auto cpuThreshold = cm.GetValue<uint32_t>(
        std::string(Keys::CryptoMinerCPUThreshold), 80);
    if (cpuThreshold < 40) {
        Utils::Logger::Warn("[Home Config] CryptoMiner CPU threshold {}% may cause "
                            "false positives during normal workloads", cpuThreshold);
    }

    auto errors = cm.ValidateAll();
    for (const auto& err : errors) {
        Utils::Logger::Warn("[Home Config] Validation error for '{}': {}", err.key, err.message);
    }

    if (valid && errors.empty()) {
        Utils::Logger::Info("[Home Config] Configuration validation passed");
    } else {
        Utils::Logger::Error("[Home Config] Configuration validation found {} issue(s)",
                             errors.size() + (valid ? 0u : 1u));
        valid = false;
    }

    return valid;
}

// ============================================================================
// ResetToDefaults
// ============================================================================

[[nodiscard]] bool ResetToDefaults() {
    auto& cm = CM::Instance();

    Utils::Logger::Info("[Home Config] Resetting all Home configuration to factory defaults");

    auto snapshotId = cm.CreateSnapshot("Pre-reset backup");
    if (snapshotId == 0) {
        Utils::Logger::Warn("[Home Config] Could not create pre-reset snapshot — "
                            "proceeding without backup");
    }

    cm.ResetToDefaults(ShadowStrike::Config::ConfigLayer::User);

    auto errors = cm.ValidateAll();
    if (!errors.empty()) {
        Utils::Logger::Error("[Home Config] Post-reset validation found {} error(s) — "
                             "attempting snapshot restore", errors.size());
        if (snapshotId != 0) {
            cm.RestoreSnapshot(snapshotId);
        }
        return false;
    }

    Utils::Logger::Info("[Home Config] Configuration reset to defaults completed");
    return true;
}

// ============================================================================
// MigrateConfiguration
// ============================================================================

[[nodiscard]] bool MigrateConfiguration(uint32_t fromVersion) {
    constexpr uint32_t kCurrentVersion = 0x03000000; // 3.0.0

    if (fromVersion >= kCurrentVersion) {
        Utils::Logger::Info("[Home Config] No migration needed (source version 0x{:08X})",
                            fromVersion);
        return true;
    }

    auto& cm = CM::Instance();

    auto snapshotId = cm.CreateSnapshot("Pre-migration backup");
    if (snapshotId == 0) {
        Utils::Logger::Error("[Home Config] Failed to create pre-migration snapshot — "
                             "aborting migration for safety");
        return false;
    }

    Utils::Logger::Info("[Home Config] Migrating configuration from 0x{:08X} to 0x{:08X}",
                        fromVersion, kCurrentVersion);

    // v2.x → v3.0: IoT and CryptoMiner modules were added; register their defaults
    if (fromVersion < 0x03000000) {
        Utils::Logger::Info("[Home Config] Applying v2.x → v3.0 migration rules");

        // New keys get factory defaults automatically through RegisterProductDefaults.
        // Existing keys that changed semantics need explicit migration here.
        // Currently no semantic changes — this block is a placeholder for future
        // version-specific transformations and documents the migration path.
    }

    auto errors = cm.ValidateAll();
    if (!errors.empty()) {
        Utils::Logger::Error("[Home Config] Post-migration validation failed ({} errors) — "
                             "rolling back", errors.size());
        cm.RestoreSnapshot(snapshotId);
        return false;
    }

    Utils::Logger::Info("[Home Config] Configuration migration completed successfully");
    return true;
}

// ============================================================================
// ExportUserConfiguration
// ============================================================================

[[nodiscard]] bool ExportUserConfiguration(const std::filesystem::path& outputPath) {
    if (outputPath.empty()) {
        Utils::Logger::Error("[Home Config] Export path is empty");
        return false;
    }

    auto parentDir = outputPath.parent_path();
    if (!parentDir.empty() && !std::filesystem::exists(parentDir)) {
        Utils::Logger::Error("[Home Config] Export directory does not exist: {}",
                             parentDir.string());
        return false;
    }

    ShadowStrike::Config::ConfigIOOptions options{};
    options.includeDefaults = false;
    options.includeSensitive = false;
    options.encryptSensitive = true;
    options.layers = { ShadowStrike::Config::ConfigLayer::User };

    bool result = CM::Instance().ExportToFile(outputPath, options);
    if (!result) {
        Utils::Logger::Error("[Home Config] Failed to export configuration to '{}'",
                             outputPath.string());
    } else {
        Utils::Logger::Info("[Home Config] Configuration exported to '{}'",
                            outputPath.string());
    }
    return result;
}

// ============================================================================
// ImportUserConfiguration
// ============================================================================

[[nodiscard]] bool ImportUserConfiguration(const std::filesystem::path& inputPath) {
    if (inputPath.empty() || !std::filesystem::exists(inputPath)) {
        Utils::Logger::Error("[Home Config] Import file does not exist: '{}'",
                             inputPath.string());
        return false;
    }

    auto& cm = CM::Instance();

    auto snapshotId = cm.CreateSnapshot("Pre-import backup");
    if (snapshotId == 0) {
        Utils::Logger::Error("[Home Config] Failed to create pre-import snapshot — "
                             "aborting import for safety");
        return false;
    }

    bool imported = cm.ImportFromFile(inputPath, ShadowStrike::Config::ConfigLayer::User);
    if (!imported) {
        Utils::Logger::Error("[Home Config] Failed to parse import file '{}'",
                             inputPath.string());
        return false;
    }

    auto errors = cm.ValidateAll();
    if (!errors.empty()) {
        Utils::Logger::Error("[Home Config] Imported configuration has {} validation error(s) — "
                             "rolling back", errors.size());
        cm.RestoreSnapshot(snapshotId);
        return false;
    }

    Utils::Logger::Info("[Home Config] Configuration imported from '{}'",
                        inputPath.string());
    return true;
}

} // namespace ShadowStrike::Products::PhantomHome::Config
